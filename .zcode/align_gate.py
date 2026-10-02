#!/usr/bin/env python3
"""
align_gate.py — PreToolUse gate enforcing AGENTS.md 铁律 1.2 / 机制 E:
"修改一个函数的代码前,必须重新先看对应的 Ghidra 函数代码".

Mechanism (two cooperating hooks, see HOOK_GUIDE.md):
  - PostToolUse on Read:  records every read of a Ghidra cpp source file into
                           .alignment_receipts.json  (record_receipt.py)
  - THIS FILE (PreToolUse on Edit|Write|MultiEdit):
      For each src/*.rs function touched by the edit, find its `// Ghidra:
      <file>:<line> <ghidraFn>` annotation, and require a receipt proving the
      named Ghidra file was read in the current session AFTER the function's
      last edit. No receipt -> BLOCK the edit with a precise message telling
      the agent which Ghidra file/function to read first.

Input:  JSON on stdin (ZCode PreToolUse payload):
          { "tool_name": "Edit", "tool_input": { "file_path",
            "old_string", "new_string" } }
Output: JSON on stdout with {"hookSpecificOutput":{"hookEventName":"PreToolUse",
          "permissionDecision":"deny"|"allow",
          "permissionDecisionReason":"..."}}
        Exit 0 = allow, 2 = block (Claude-Code convention).

Bypass rules (do NOT block):
  - file not under src/*.rs          (only Rust source gated)
  - test fns (#[test] / cfg(test))   (no Ghidra counterpart)
  - fns with NO // Ghidra: annotation but a // RUDRA-GLUE: marker
  - edits that don't fall inside any fn body (e.g. top-level use/docs)
  - first-time creation of a fn whose annotation is being added in THIS edit
  - ZCODE_ALIGN_GATE=0 in env (escape hatch, log it)

Cross-root edits (GATE-WORKTREE-ROOTMISMATCH-0001): when the edited file lives
outside the hook's ROOT (e.g. a main-repo hook dispatching for a worktree
file), the gate re-resolves the file's own `git rev-parse --show-toplevel`
(GIT_* hijack vars scrubbed, same list as tools/check_gate_health.py) and, for
`toplevel/src/*.rs` files, re-anchors receipts/session/ghidra paths onto that
toplevel so the edit is gated by the file's own repo state. Paths that look
like gated Rust source ('/src/' + '.rs') but resolve to NO git root are denied
(fail-closed) instead of silently allowed.

Receipt freshness: a receipt for ghidra file F counts if its read timestamp is
>= the mtime-stamp of the receipt entry recording the *previous* successful
gate for that (rs_fn, F) pair — i.e. "re-read after each edit cycle". Concretely
we require: last_read_ts(F) >= last_gated_edit_ts(rs_fn). For the very first
edit of a fn in a session we only require last_read_ts(F) to exist (>= the
session's start, tracked by a session_start marker).
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]          # .../rudra
sys.path.insert(0, str(ROOT / "tools"))

from rust_fn_scanner import RustFunction, functions_overlapping
from rust_fn_scanner import run_self_test as run_scanner_self_test
from rust_fn_scanner import scan_rust_functions

SRC = ROOT / "src"
GHIDRA_CPP = ROOT / "ghidra" / "Ghidra" / "Features" / "Decompiler" / "src" / "decompile" / "cpp"
RECEIPTS = ROOT / ".alignment_receipts.json"
SESSION_START = ROOT / ".alignment_session_start"
LOG = ROOT / ".zcode" / "align_gate.log"

ENV_OFF = os.environ.get("ZCODE_ALIGN_GATE", "").strip() == "0"

# Canonical above-block annotation: `// Ghidra: <file>:<line> <rest...>`
GHIDRA_RE = re.compile(r"//\s*Ghidra:\s*([A-Za-z0-9_./-]+\.(?:cc|hh|h|c))\s*:(\d+)\s*(.*)")
# Inline reference: any `// ... <file>.<ext>:<digits> ...` inside a comment,
# covering `(coreaction.cc:4886)`, `coreaction.cc:4886`, `(varnode.hh:235)` etc.
GHIDRA_INLINE_RE = re.compile(r"([A-Za-z0-9_]+\.(?:cc|hh|h|c))\s*[:#]\s*(\d+)")
GLUE_RE = re.compile(r"//\s*RUDRA-GLUE:")
def log(msg: str) -> None:
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.time():.0f}] {msg}\n")
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Receipt store
# ----------------------------------------------------------------------------
def _load_json(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
    except Exception:
        return default


def _save_json(p: Path, data) -> None:
    try:
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def session_start_ts() -> float:
    try:
        return float(SESSION_START.read_text(encoding="utf-8").strip()) if SESSION_START.exists() else 0.0
    except Exception:
        return 0.0


def receipts() -> dict:
    return _load_json(RECEIPTS, {"reads": {}, "gated_edits": {}})


def touch_session_start() -> None:
    """Stamp session start on first gate invocation if not yet stamped.
    The authoritative stamper is the SessionStart hook, but this is a fallback
    so the gate works even without that hook registered."""
    if not SESSION_START.exists():
        _save_json(SESSION_START, {})  # create file presence
        try:
            SESSION_START.write_text(str(time.time()), encoding="utf-8")
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Locating Rust fns affected by an edit
# ----------------------------------------------------------------------------
def find_fn_for_line(lines: list[str], target: int) -> tuple[int, str, bool] | None:
    """Return a function only when ``target`` is inside its exact range."""

    records = scan_rust_functions("\n".join(lines))
    candidates = [
        record for record in records
        if record.start_line <= target <= record.end_line
    ]
    if not candidates:
        return None
    record = min(candidates, key=lambda item: item.end - item.start)
    return (record.start_line, record.name, record.is_test)


def _fn_annotation(
    lines: list[str], record: RustFunction, *, allow_above_marker: bool = True
) -> tuple[str, int, str] | None:
    """Find the Ghidra source location this Rust fn corresponds to.

    Search order:
      1. The comment/attribute block immediately ABOVE fn_idx, for an explicit
         `// Ghidra: <file>:<line> ...` annotation (canonical form).
      2. The fn BODY, for the first `// ... Ghidra: ... (<file>:<line>)` or
         `// Ghidra: ... <file>:<line> ...` reference — covers the common
         inline-comment style used across this codebase (302 distinct refs).
      3. An explicit `// RUDRA-GLUE:` marker above -> None (exempt).

    Returns (ghidra_file, ghidra_line, rest) or None.
    """
    # --- (1) above-block explicit annotation ---
    if allow_above_marker:
        j = record.start_line - 1
        while j >= 0:
            s = lines[j].rstrip()
            stripped = s.strip()
            if stripped == "":
                j -= 1
                continue
            if stripped.startswith("#["):
                j -= 1
                continue
            if stripped.startswith("//"):
                m = GHIDRA_RE.search(stripped)
                if m:
                    return (m.group(1), int(m.group(2)), m.group(3))
                if GLUE_RE.search(stripped):
                    return None  # explicit glue exemption
                j -= 1
                continue
            break

    # --- (2) inline references in the fn body ---
    for k in range(record.start_line, record.end_line + 1):
        s = lines[k].strip() if k < len(lines) else ""
        if not s.startswith("//"):
            continue
        if GLUE_RE.search(s):
            return None
        m = GHIDRA_INLINE_RE.search(s)
        if m:
            return (m.group(1), int(m.group(2)), s)
    return None


def fn_annotation(lines: list[str], fn_idx: int) -> tuple[str, int, str] | None:
    """Compatibility wrapper locating a record by its zero-based start line."""

    records = scan_rust_functions("\n".join(lines))
    record = next((item for item in records if item.start_line == fn_idx), None)
    return _fn_annotation(lines, record) if record is not None else None


def line_range_of_fn(lines: list[str], fn_idx: int) -> tuple[int, int]:
    """Return the shared scanner's exact zero-based line range."""

    records = scan_rust_functions("\n".join(lines))
    record = next((item for item in records if item.start_line == fn_idx), None)
    return (record.start_line, record.end_line) if record is not None else (fn_idx, fn_idx)


# ----------------------------------------------------------------------------
# Edits → affected fns
# ----------------------------------------------------------------------------
def _selected_records(
    text: str,
    records: list[RustFunction],
    edits: list[dict],
    whole_file: bool,
) -> list[RustFunction]:
    if whole_file:
        return records
    if not edits or any(not (edit.get("old_string") or "") for edit in edits):
        # An edit with no resolvable anchor is indistinguishable from a whole
        # file mutation at PreToolUse time.  Fail safe by gating every item.
        return records
    selected: dict[tuple[int, str], RustFunction] = {}
    for edit in edits:
        old_string = edit.get("old_string") or ""
        search_from = 0
        while search_from <= len(text) - len(old_string):
            start = text.find(old_string, search_from)
            if start < 0:
                break
            for record in functions_overlapping(records, start, start + len(old_string)):
                selected[(record.start, record.name)] = record
            # Include overlapping occurrences and ``replace_all`` targets.
            search_from = start + 1
    return sorted(selected.values(), key=lambda item: item.start)


def affected_fns(
    file_path: Path,
    old_string: str | None,
    new_string: str | None,
    edits: list[dict] | None = None,
    whole_file: bool = False,
) -> list[dict]:
    """Determine which fns an Edit touches. Returns list of dicts:
       {fn_name, ghidra_file, ghidra_line, ghidra_rest, is_test, has_annotation}.
    """
    try:
        text = file_path.read_text(encoding="utf-8")
    except Exception:
        return []
    lines = text.split("\n")
    records = scan_rust_functions(text)
    edit_specs = edits if edits is not None else [
        {"old_string": old_string, "new_string": new_string}
    ]
    targets = _selected_records(text, records, edit_specs, whole_file)

    out = []
    first_item_on_line: dict[int, int] = {}
    for record in records:
        first_item_on_line.setdefault(record.start_line, record.start)
    for record in targets:
        ann = _fn_annotation(
            lines,
            record,
            allow_above_marker=first_item_on_line[record.start_line] == record.start,
        )
        out.append({
            "name": record.name,
            "fn_line": record.start_line + 1,
            "is_test": record.is_test,
            "has_annotation": ann is not None,
            "ghidra_file": ann[0] if ann else None,
            "ghidra_line": ann[1] if ann else None,
            "ghidra_rest": ann[2] if ann else None,
            "body_end": record.end_line + 1,
        })
    return out


# ----------------------------------------------------------------------------
# Decision
# ----------------------------------------------------------------------------
def decide(file_rel: str, affected: list[dict], rec: dict, sess_ts: float) -> tuple[bool, str]:
    """Return (allow, reason)."""
    # Only gate src/*.rs
    if not file_rel.replace("\\", "/").startswith("src/") or not file_rel.endswith(".rs"):
        return (True, "non-src-rust file")

    # Filter out test fns
    real = [f for f in affected if not f["is_test"]]
    if not real:
        return (True, "only test fns / no fn affected")

    # Require a read after both this session started and the previous
    # successful gate for this exact Rust function.  Every edit cycle therefore
    # requires a fresh oracle read, as required by AGENTS.md 铁律 1.2.
    reads = rec.get("reads", {})
    gated = rec.get("gated_edits", {})
    now = time.time()
    missing = []
    passed_gate_keys: list[str] = []
    for f in real:
        if not f["has_annotation"]:
            # No annotation: don't block here (check_ghidra_annotations.py
            # already enforces annotations at commit time). Allow.
            continue
        gfile = f["ghidra_file"]
        key = f"{gfile}"
        last_read = reads.get(key, {}).get("ts", 0.0)
        gate_key = _gate_key(file_rel, f, gfile)
        last_gated = gated.get(gate_key, 0.0)
        fresh = _receipt_is_fresh(last_read, sess_ts, last_gated)
        if not fresh:
            missing.append({
                "fn": f["name"],
                "ghidra_file": gfile,
                "ghidra_line": f["ghidra_line"],
                "ghidra_rest": f["ghidra_rest"],
                "last_read_ts": last_read,
                "sess_ts": sess_ts,
            })
        else:
            passed_gate_keys.append(gate_key)

    if missing:
        lines = ["BLOCKED by align_gate (AGENTS.md 铁律 1.2 / 机制 E): edit would modify "
                 "Rust fn(s) whose corresponding Ghidra function was not re-read "
                 "in this session. Re-read FIRST, then retry the edit:"]
        for m in missing:
            lines.append(
                f"  - fn `{m['fn']}` ({file_rel}) -> Ghidra "
                f"{m['ghidra_file']}:{m['ghidra_line']}  {m['ghidra_rest'] or ''}".rstrip()
            )
        lines.append(f"Read each listed Ghidra source (the file:line above), "
                     f"then re-issue the edit. Receipt file: {RECEIPTS.name}")
        return (False, "\n".join(lines))

    # Stamp only a wholly successful gate.  A denied multi-function edit did
    # not mutate Rust and therefore must not consume otherwise-fresh receipts.
    for gate_key in passed_gate_keys:
        gated[gate_key] = now
    rec["gated_edits"] = gated
    _save_json(RECEIPTS, rec)
    return (True, "all annotated fns have a fresh Ghidra-read receipt")


def _receipt_is_fresh(last_read: float, sess_ts: float, last_gated: float) -> bool:
    return last_read >= max(sess_ts, last_gated)


def _gate_key(file_rel: str, affected_fn: dict, gfile: str) -> str:
    """Stable identity: Rust line movement must not reset freshness."""

    return (
        f"{file_rel}::{affected_fn['name']}::"
        f"{gfile}:{affected_fn['ghidra_line']}"
    )


# ----------------------------------------------------------------------------
# Cross-root dispatch (GATE-WORKTREE-ROOTMISMATCH-0001)
# ----------------------------------------------------------------------------
def _scrubbed_git_env() -> dict[str, str]:
    """GATE-WORKTREE-GITDIR-0001 (same scrub list as tools/check_gate_health.py):
    git exports GIT_DIR/GIT_WORK_TREE (and friends) when hooks run from linked
    worktrees; those env vars would override per-cwd repo discovery and hijack
    the toplevel query below, so strip them for every git subprocess."""
    return {
        key: value
        for key, value in os.environ.items()
        if key
        not in (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
        )
    }


def _nearest_existing_dir(start: Path) -> Path | None:
    """First existing ancestor directory of ``start`` (the file being written
    may not exist yet, and neither may its parent)."""
    probe = start
    while not probe.is_dir():
        if probe.parent == probe:
            return None
        probe = probe.parent
    return probe


def _git_toplevel(file_path: Path) -> Path | None:
    """Resolve the git toplevel governing ``file_path`` (works from inside
    linked worktrees too: --show-toplevel returns the worktree root)."""
    probe = _nearest_existing_dir(file_path.parent)
    if probe is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(probe),
            text=True,
            capture_output=True,
            check=False,
            env=_scrubbed_git_env(),
            timeout=10,
        )
    except Exception:
        return None
    top = result.stdout.strip() if result.returncode == 0 else ""
    return Path(top) if top else None


def _rebase_onto_file_root(file_path: Path) -> tuple[Path, str] | None:
    """GATE-WORKTREE-ROOTMISMATCH-0001: when the edited file lives outside the
    hook's ROOT (main-repo hook / worktree file), re-anchor gating onto the
    file's own git toplevel. Returns (toplevel, file_rel) when the file is
    ``<toplevel>/src/*.rs``, else None (not gated content for any root)."""
    toplevel = _git_toplevel(file_path)
    if toplevel is None:
        return None
    try:
        rel = str(file_path.resolve().relative_to(toplevel.resolve())).replace("\\", "/")
    except Exception:
        return None
    if rel.startswith("src/") and rel.endswith(".rs"):
        return (toplevel, rel)
    return None


def _is_suspicious_external_src(file_rel: str) -> bool:
    """A path that looks like gated Rust source (a '/src/' component plus a
    '.rs' suffix) that no resolvable git root claims. Receipts cannot be
    located for it, so it must fail closed rather than pass silently."""
    return f"/{file_rel}".count("/src/") > 0 and file_rel.endswith(".rs")


def _rebase_gate_paths(gate_root: Path) -> None:
    """GATE-WORKTREE-ROOTMISMATCH-0001: anchor the gate's state files onto the
    edited file's repo root. Receipts and the session-start marker are
    gitignored per-worktree session state, so they must be read/written in the
    file's own repo. Only invoked on the cross-root path; the same-root flow
    keeps the module-level anchors derived from the script's own location."""
    global SRC, GHIDRA_CPP, RECEIPTS, SESSION_START
    SRC = gate_root / "src"
    GHIDRA_CPP = (
        gate_root
        / "ghidra"
        / "Ghidra"
        / "Features"
        / "Decompiler"
        / "src"
        / "decompile"
        / "cpp"
    )
    RECEIPTS = gate_root / ".alignment_receipts.json"
    SESSION_START = gate_root / ".alignment_session_start"


def _cross_root_deny_reason(file_path_str: str) -> str:
    return (
        "BLOCKED by align_gate (GATE-WORKTREE-ROOTMISMATCH-0001): "
        "hook 根与文件根不一致且无法解析 toplevel — the hook's root "
        f"{ROOT} does not contain '{file_path_str}', no git toplevel could be "
        "resolved from the file's directory, and the path looks like gated "
        "Rust source ('/src/' + '.rs'), so read-receipts cannot be located "
        "for it (fail-closed). Fix: edit via a session whose project dir is "
        "the file's own repo/worktree (its .zcode hooks gate it there), or "
        "record a receipt in that repo first. ZCODE_ALIGN_GATE=0 remains the "
        "documented escape hatch for registered gate repairs."
    )


# ----------------------------------------------------------------------------
# SessionStart handling
# ----------------------------------------------------------------------------
def handle_session_start() -> int:
    """Stamp the session-start marker. Reads of Ghidra files after this ts
    count as fresh receipts. Invoked by the SessionStart hook so the gate has
    a correct baseline even on the first edit of a new session."""
    try:
        SESSION_START.write_text(f"{time.time():.0f}", encoding="utf-8")
    except Exception as e:
        log(f"session-start stamp FAILED: {e}")
    log(f"session-start stamped")
    return 0


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def read_payload() -> dict:
    """Read the ZCode hook JSON from stdin without blocking when no stdin is
    attached (the hook is always invoked with a piped stdin per the contract,
    but be defensive)."""
    try:
        if sys.stdin.isatty():
            return {}
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def emit_decision(allow: bool, reason: str) -> int:
    """Emit the decision both as structured JSON (preferred) and via the
    exit-code-2 + stderr fallback (most reliable deny path, per the reverse-
    engineered contract: Gcn() in zcode.cjs derives the deny reason from
    stderr/stdout text on exit != 0)."""
    decision = "allow" if allow else "deny"
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }
    try:
        sys.stdout.write(json.dumps(out))
        sys.stdout.flush()
    except Exception:
        pass
    if not allow:
        # Belt-and-suspenders: also write reason to stderr so even if the JSON
        # path isn't honored, exit 2 + stderr still blocks with the message.
        sys.stderr.write(reason + "\n")
        return 2
    return 0


def _run_script(script: Path, payload: dict) -> subprocess.CompletedProcess:
    """Run the gate end-to-end as a real hook subprocess (stdin JSON), with
    GIT_* hijack vars scrubbed and the ZCODE_ALIGN_GATE hatch force-disabled so
    the caller's environment cannot skew the self-test."""
    env = {
        key: value
        for key, value in _scrubbed_git_env().items()
        if key != "ZCODE_ALIGN_GATE"
    }
    return subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=env,
        timeout=60,
    )


def _self_test_cross_root(script: Path) -> None:
    """GATE-WORKTREE-ROOTMISMATCH-0001: a hook whose ROOT differs from the
    edited file's repo must gate correctly instead of silently allowing.
    Simulated with throwaway temp git repos; real worktrees are never
    touched."""
    def edit_payload(target: Path, old: str, new: str) -> dict:
        return {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": str(target),
                "old_string": old,
                "new_string": new,
            },
        }

    with TemporaryDirectory(prefix="align_gate_xroot_") as tmp:
        base = Path(tmp)

        # (1) cross-root src/*.rs in its own temp git repo, no receipts ->
        #     standard BLOCKED deny naming the annotated Ghidra file.
        repo = base / "wt" / "repo"
        (repo / "src").mkdir(parents=True)
        subprocess.run(
            ["git", "init", "-q"],
            cwd=str(repo),
            check=True,
            capture_output=True,
            env=_scrubbed_git_env(),
        )
        sample = repo / "src" / "sample.rs"
        sample.write_text(
            "// Ghidra: action.cc:100 target_fn\n"
            "fn target_fn() { let _ = 1; }\n",
            encoding="utf-8",
        )
        result = _run_script(script, edit_payload(sample, "fn target_fn", "fn renamed"))
        assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
        combined = result.stdout + result.stderr
        assert "action.cc" in combined, combined

        # (2) same file with fresh receipts in ITS repo -> allowed (exit 0).
        (repo / ".alignment_session_start").write_text(
            str(time.time() - 60), encoding="utf-8"
        )
        (repo / ".alignment_receipts.json").write_text(
            json.dumps(
                {"reads": {"action.cc": {"ts": time.time(), "ranges": [[100, 100]]}},
                 "gated_edits": {}}
            ),
            encoding="utf-8",
        )
        result = _run_script(script, edit_payload(sample, "fn target_fn", "fn renamed"))
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)

        # (3) suspicious /src/*.rs path inside NO git repo -> fail-closed deny.
        orphan = base / "orphan" / "src" / "orphan.rs"
        orphan.parent.mkdir(parents=True)
        orphan.write_text("fn lone() {}\n", encoding="utf-8")
        result = _run_script(script, edit_payload(orphan, "fn lone", "fn alone"))
        assert result.returncode == 2, (result.returncode, result.stdout, result.stderr)
        combined = result.stdout + result.stderr
        assert "toplevel" in combined, combined

        # (4) cross-root NON-src file in the temp repo -> not gated (exit 0).
        note = repo / "docs" / "note.md"
        note.parent.mkdir(parents=True, exist_ok=True)
        note.write_text("note\n", encoding="utf-8")
        result = _run_script(script, edit_payload(note, "note", "notes"))
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)


def run_self_test() -> None:
    run_scanner_self_test()
    fixture = '''// Ghidra: action.cc:1 declared
trait T { fn declared(&self); }
const TOP_LEVEL: u8 = 1;
// Ghidra: action.cc:2 production
pub(crate) fn production() { let text = "}"; }
#[cfg(test)]
mod checks { mod nested { fn test_only() {} } }
// Ghidra: action.cc:3 after_tests
pub unsafe extern "C" fn after_tests() {}
// Ghidra: action.cc:4 first_on_line
impl Pair { fn first_on_line() {} fn second_on_line() {} }
// Ghidra: action.cc:5 repeated_a
fn repeated_a() { shared_call(); }
// Ghidra: action.cc:6 repeated_b
fn repeated_b() { shared_call(); }
'''
    lines = fixture.split("\n")
    declaration_line = next(
        record.start_line for record in scan_rust_functions(fixture)
        if record.name == "declared"
    )
    assert line_range_of_fn(lines, declaration_line) == (declaration_line, declaration_line)
    assert find_fn_for_line(lines, declaration_line + 1) is None

    with NamedTemporaryFile("w", suffix=".rs", encoding="utf-8") as handle:
        handle.write(fixture)
        handle.flush()
        affected = affected_fns(
            Path(handle.name),
            "pub(crate) fn production",
            None,
        )
        assert [item["name"] for item in affected] == ["production"], affected
        affected = affected_fns(
            Path(handle.name),
            None,
            None,
            edits=[
                {"old_string": "fn test_only", "new_string": "fn changed_test"},
                {"old_string": 'pub unsafe extern "C" fn after_tests'},
            ],
        )
        assert [item["name"] for item in affected] == ["test_only", "after_tests"]
        assert affected[0]["is_test"] and not affected[1]["is_test"]
        second = affected_fns(Path(handle.name), "fn second_on_line", None)
        assert [item["name"] for item in second] == ["second_on_line"]
        assert not second[0]["has_annotation"]
        repeated = affected_fns(Path(handle.name), "shared_call();", None)
        assert [item["name"] for item in repeated] == ["repeated_a", "repeated_b"]
        fail_safe = affected_fns(Path(handle.name), "", "replacement")
        assert len(fail_safe) == len(scan_rust_functions(fixture))

    assert _receipt_is_fresh(20.0, 10.0, 15.0)
    assert not _receipt_is_fresh(14.0, 10.0, 15.0)
    assert not _receipt_is_fresh(9.0, 10.0, 0.0)
    identity = {
        "name": "same", "fn_line": 10, "ghidra_line": 77,
    }
    before_move = _gate_key("src/sample.rs", identity, "action.cc")
    identity["fn_line"] = 999
    assert _gate_key("src/sample.rs", identity, "action.cc") == before_move

    assert _is_suspicious_external_src("/tmp/wt/src/a.rs")
    assert not _is_suspicious_external_src("/tmp/wt/docs/a.rs")
    assert not _is_suspicious_external_src("/tmp/wt/src.rs")
    _self_test_cross_root(Path(__file__).resolve())


def main() -> int:
    args = sys.argv[1:]
    if "--session-start" in args:
        return handle_session_start()
    if "--self-test" in args:
        run_self_test()
        print("✅ align_gate self-test passed")
        return 0

    payload = read_payload()
    tool = payload.get("tool_name", "?")
    ti = payload.get("tool_input", {}) or {}
    file_path_str = ti.get("file_path") or ti.get("path") or ""
    file_path = Path(file_path_str)
    try:
        file_rel = str(file_path.relative_to(ROOT)).replace("\\", "/")
        cross_root = False
    except Exception:
        file_rel = file_path_str.replace("\\", "/")
        cross_root = True

    if ENV_OFF:
        log(f"SKIP (ZCODE_ALIGN_GATE=0) tool={tool} file={file_rel}")
        return 0

    # Only care about src/*.rs
    if not (file_rel.startswith("src/") and file_rel.endswith(".rs")):
        if not cross_root:
            return 0
        # GATE-WORKTREE-ROOTMISMATCH-0001: hook ROOT != edited file's root
        # (main-repo hook dispatching for a worktree file). The pre-fix code
        # reached this `return 0` for absolute worktree paths and silently
        # allowed the edit (fail-open, see B7 audit §7). Instead: re-anchor
        # onto the file's own git toplevel and gate there; deny (fail-closed)
        # when a suspicious /src/*.rs path resolves to no root at all.
        if not file_path.is_absolute():
            return 0
        rebased = _rebase_onto_file_root(file_path)
        if rebased is None:
            if _is_suspicious_external_src(file_rel):
                log(f"DENY cross-root-unresolved tool={tool} file={file_rel}")
                return emit_decision(False, _cross_root_deny_reason(file_path_str))
            return 0
        gate_root, file_rel = rebased
        _rebase_gate_paths(gate_root)
        log(
            f"CROSS-ROOT rebase tool={tool} hook_root={ROOT} "
            f"gate_root={gate_root} file={file_rel}"
        )

    touch_session_start()
    sess_ts = session_start_ts()
    rec = receipts()
    affected = affected_fns(
        file_path,
        ti.get("old_string"),
        ti.get("new_string"),
        edits=ti.get("edits"),
        whole_file=tool == "Write",
    )
    allow, reason = decide(file_rel, affected, rec, sess_ts)
    log(f"tool={tool} file={file_rel} affected={len(affected)} allow={allow} :: {reason[:120]}")
    return emit_decision(allow, reason)


if __name__ == "__main__":
    sys.exit(main())
