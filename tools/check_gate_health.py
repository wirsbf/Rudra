#!/usr/bin/env python3
"""Verify the repository's versioned alignment-gate installation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GHIDRA = ROOT / "ghidra"
LOCKED_ORACLE = "e40ed13014025f82488b1f8f7bca566894ac376b"
CPP = GHIDRA / "Ghidra/Features/Decompiler/src/decompile/cpp"


def git_output(*args: str, cwd: Path = ROOT) -> str:
    # GATE-WORKTREE-GITDIR-0001: git exports GIT_DIR/GIT_WORK_TREE (and friends)
    # to hooks when invoked from a linked worktree; those env vars override
    # per-cwd repo discovery and hijack the embedded ghidra HEAD query.
    env = {
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
    result = subprocess.run(
        ["git", *args], cwd=cwd, text=True, capture_output=True, check=False, env=env
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def main() -> int:
    failures: list[str] = []

    oracle_head = git_output("rev-parse", "HEAD", cwd=GHIDRA)
    if oracle_head != LOCKED_ORACLE:
        failures.append(
            f"ghidra HEAD={oracle_head or '<missing>'}; expected {LOCKED_ORACLE}"
        )
    cc_count = len(list(CPP.glob("*.cc"))) if CPP.is_dir() else 0
    if cc_count != 114:
        failures.append(f"locked oracle has {cc_count} .cc files; expected 114")

    hooks_path = git_output("config", "--get", "core.hooksPath")
    if hooks_path != ".githooks":
        failures.append(
            f"core.hooksPath={hooks_path or '<unset>'}; expected .githooks"
        )

    hook_text: dict[str, str] = {}
    for relative in (".githooks/pre-commit", ".githooks/commit-msg"):
        hook = ROOT / relative
        if not hook.is_file():
            failures.append(f"missing versioned hook: {relative}")
            continue
        if not (hook.stat().st_mode & stat.S_IXUSR):
            failures.append(f"hook is not executable: {relative}")
        text = hook.read_text(encoding="utf-8", errors="replace")
        if "python3" not in text:
            failures.append(f"hook does not invoke python3: {relative}")
        if '$REPO_ROOT/rudra/' in text or '$REPO_ROOT/rugra/' in text:
            failures.append(f"hook contains stale nested-repo path: {relative}")
        hook_text[relative] = text

    scanner = ROOT / "tools/rust_fn_scanner.py"
    if not scanner.is_file():
        failures.append("missing shared Rust function scanner")

    # GATE-WORKTREE-ROOTMISMATCH-0001: cross-root edits (hook root != edited
    # file's root, e.g. a main-repo hook dispatching for a worktree file) must
    # be re-gated against the file's own git toplevel, and suspicious
    # /src/*.rs paths resolving to no root must fail closed — never silently
    # allowed. Static assertions keep those branches from regressing.
    gate_script = ROOT / ".zcode/align_gate.py"
    try:
        gate_text = gate_script.read_text(encoding="utf-8")
    except OSError as exc:
        failures.append(f"cannot read .zcode/align_gate.py: {exc}")
    else:
        for required in (
            "rev-parse",                       # toplevel rebase lookup
            "--show-toplevel",
            "GATE-WORKTREE-ROOTMISMATCH-0001", # tracked defect marker
            "_rebase_gate_paths",              # receipts/session re-anchor
            "fail-closed",                     # unresolved-root deny branch
            "_self_test_cross_root",           # runtime self-test coverage
        ):
            if required not in gate_text:
                failures.append(
                    f"align_gate.py lost cross-root gate handling: {required}"
                )

    pre_commit = hook_text.get(".githooks/pre-commit", "")
    for command in (
        "tools/check_gate_health.py",
        "tools/check_doc_sync.py\" --staged",
        "tools/check_ghidra_annotations.py\" --all",
        "tools/check_ghidra_refs.py\" --all --strict",
    ):
        if command not in pre_commit:
            failures.append(f"pre-commit is missing required command: {command}")
    commit_msg = hook_text.get(".githooks/commit-msg", "")
    if "tools/check_alignment_evidence.py" not in commit_msg or '"$1"' not in commit_msg:
        failures.append("commit-msg must validate the supplied message file")

    config_path = ROOT / ".zcode/config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if config.get("hooks", {}).get("enabled") is not True:
            failures.append(".zcode hooks.enabled must be true")
        events = config["hooks"]["events"]
        expected = {
            "PreToolUse": ["${ZCODE_PROJECT_DIR}/.zcode/align_gate.py"],
            "PostToolUse": ["${ZCODE_PROJECT_DIR}/.zcode/record_receipt.py"],
            "SessionStart": [
                "${ZCODE_PROJECT_DIR}/.zcode/align_gate.py",
                "--session-start",
            ],
        }
        expected_matchers = {
            "PreToolUse": "Edit|Write|MultiEdit",
            "PostToolUse": "Read",
            "SessionStart": "startup|resume",
        }
        for event, expected_args in expected.items():
            event_config = events[event][0]
            if event_config.get("matcher") != expected_matchers[event]:
                failures.append(
                    f"{event} matcher={event_config.get('matcher')!r}; "
                    f"expected {expected_matchers[event]!r}"
                )
            hook = event_config["hooks"][0]
            if hook.get("type") != "process" or hook.get("command") != "python3":
                failures.append(f"{event} must use process command=python3")
            args = hook.get("args")
            if args != expected_args:
                failures.append(
                    f"{event} args={args!r}; expected project-relative {expected_args!r}"
                )
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        failures.append(f"invalid .zcode/config.json: {exc}")

    workflow_path = ROOT / ".github/workflows/alignment-gates.yml"
    try:
        workflow = workflow_path.read_text(encoding="utf-8")
        for required in (
            LOCKED_ORACLE,
            "tools/check_gate_health.py",
            "tools/rust_fn_scanner.py",
            "tools/check_ghidra_annotations.py --self-test",
            ".zcode/align_gate.py --self-test",
            "tools/check_ghidra_annotations.py --all",
            "tools/check_ghidra_refs.py --all --strict",
            "tools/check_alignment_evidence.py --self-test",
        ):
            if required not in workflow:
                failures.append(f"alignment CI is missing: {required}")
    except OSError as exc:
        failures.append(f"missing alignment CI workflow: {exc}")

    if failures:
        print("gate health: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        "gate health: OK "
        f"(oracle={LOCKED_ORACLE[:8]}, cc=114, hooks=.githooks, zcode=project-relative)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
