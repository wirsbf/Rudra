#!/usr/bin/env python3
"""Corpus-marker gate for Rudra library production code (AUDIT-CORPUS-MARKERS-GATE-0001).

Rudra's library (src/) must contain ZERO per-corpus special-casing: no
function-name arity/type tables keyed on curl/httpd-internal symbols, no
binary-name branches, no corpus hex addresses. The 2026-06-23 bootstrap
tables (known_param_count / known_param_types in coreaction.rs, expelled
2026-09-25 by EXPEL-CORPUS-TABLES-0001) proved how easily such tables leak
in; this gate makes any recurrence a hard commit failure.

Scope per file (src/**/*.rs, including src/bin/):
  - the PRODUCTION region only: everything before the first top-level
    ``#[cfg(test)]`` attribute (test fixtures legitimately name corpus
    functions; the whole file is production when no test region exists);
  - COMMENTS ARE STRIPPED before matching (alignment notes and deletion
    tombstones legitimately cite corpus history; the gate targets code
    and the string literals that feed logic, e.g. ``match name { ... }``
    arms);
  - identifiers are matched with identifier boundaries, so look-alike
    words such as ``curlast``/``curly`` do NOT trip the ``curl`` marker
    (the "curlast-class false positive" whitelist concern); any genuine
    edge case is handled by the explicit allowlist below, which requires
    a TODO-ID-bound justification.

Marker classes:
  - FUNCTION_NAMES: curl/httpd-internal symbols (hugehelp, getparameter,
    match_url, SetHTTPrequest, glob_*, ap_*, curl_easy_*, my_*, ...).
    A trailing ``_`` is tolerated on the right boundary so GCC clone
    suffixes (``getparameter_constprop_0``) are still caught.
  - BINARY_NAMES: standalone ``curl`` / ``httpd`` tokens in code.
  - CORPUS_ADDRESSES: corpus-specific hex constants observed in fixture
    lanes (DWARF globals, fixture entry addresses).

Usage:
  python3 tools/check_corpus_markers.py            # whole library (gate form)
  python3 tools/check_corpus_markers.py --staged   # only staged src files
  python3 tools/check_corpus_markers.py -v         # list allowlisted hits too

Exit codes: 0 clean / 1 violations / 2 usage.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Marker data (data plane of this gate, not library production code)
# ---------------------------------------------------------------------------

# curl/src/tool_*.c + httpd internal symbols from the expelled tables and the
# corpus lanes' fixture sets. Suffix-tolerant boundary: right side rejects
# [A-Za-z0-9] but allows '_', so ``parseconfig_constprop_0`` matches
# ``parseconfig``.
FUNCTION_NAMES = [
    # curl tool internals
    "hugehelp", "getparameter", "match_url", "SetHTTPrequest", "glob_url",
    "glob_set", "glob_range", "glob_word", "next_url", "my_fwrite",
    "myprogress", "my_get_token", "my_get_line", "parseconfig",
    "file2string", "progressbarinit", "maprintf", "GetStr", "strequal",
    "strnequal", "helpf", "main_init", "main_free",
    # libcurl public API as observed in the corpus driver tables
    "curl_easy_init", "curl_easy_cleanup", "curl_easy_perform",
    "curl_easy_setopt", "curl_global_init", "curl_global_cleanup",
    "curl_getenv", "curl_free", "curl_slist_append",
    "curl_slist_free_all", "curl_version",
    # httpd internals
    "ap_ht_time", "ap_strcmp_match", "ap_strcasecmp_match",
    "ap_fini_vhost_config", "ap_parse_vhost_addrs", "ap_init_vhost_config",
    "ap_set_name_virtual_host", "ap_matches_request_vhost",
    "ap_update_vhost_given_ip", "ap_make_dirstr_prefix", "ap_no2slash",
    "ap_getparents", "ap_pregsub", "ap_log_error",
    "ap_exists_config_define",
]

BINARY_NAMES = ["curl", "httpd"]

# Corpus hex constants: curl DWARF globals / fixture entry addresses seen in
# lane evidence (0x17520 config global; 0x3ff2 GetStr call site; httpd
# fixture addresses). Library code has no legitimate reason to name any of
# them; fixture drivers live in examples/, not src/.
CORPUS_ADDRESSES = [
    "0x17520", "0x3ff2", "0x2b820", "0x41430", "0x2c520", "0x12c520",
    "0x1a0828", "0x2cf02",
]

# Allowlist: (file, marker, justification-with-TODO). Every entry MUST cite
# a TODO_BOARD ID that tracks its removal. An allowlisted marker still
# prints (with -v or on hits) so the ledger stays visible.
ALLOWLIST = [
    (
        "src/printc.rs",
        "0x17520",
        "legacy [FOUND-0x17520] stderr debug probe keyed to the curl corpus "
        "DWARF config global; stderr-only, no output effect — removal tracked "
        "by PRINTC-CORPUS-PROBE-0001 (printc.rs outside EXPEL lane write-set)",
    ),
]

# ---------------------------------------------------------------------------
# Rust comment stripper (keeps string literals — the tables were string-keyed)
# ---------------------------------------------------------------------------


def strip_rust_comments(source: str) -> str:
    """Remove // and /* */ comments while preserving string/char literals.

    A conservative state machine: handles escaped quotes, raw strings
    (r#..#), and char literals vs lifetimes. False negatives (missing a
    strip) only weaken comment immunity; the marker scan itself stays
    code-anchored.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    state = "code"  # code | line_comment | block_comment | str | raw_str | char
    raw_hashes = 0
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                state = "str"
                out.append(ch)
                i += 1
                continue
            if ch == "r" and nxt in "#\"" and _raw_string_ahead(source, i):
                raw_hashes = _raw_string_hashes(source, i)
                state = "raw_str"
                out.append(source[i : i + raw_hashes + 2])
                i += raw_hashes + 2
                continue
            if ch == "'":
                # char literal vs lifetime: a char literal closes within 3-4 chars
                if _is_char_literal(source, i):
                    state = "char"
                    out.append(ch)
                    i += 1
                    continue
            out.append(ch)
            i += 1
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
                out.append(ch)
            i += 1
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                if ch == "\n":
                    out.append(ch)  # keep line structure
                i += 1
        elif state == "str":
            out.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    out.append(nxt)
                i += 2
                continue
            if ch == '"':
                state = "code"
            i += 1
        elif state == "raw_str":
            out.append(ch)
            if ch == '"' and _raw_close(source, i + 1, raw_hashes):
                for k in range(raw_hashes):
                    out.append("#")
                i += 1 + raw_hashes
                state = "code"
                continue
            i += 1
        elif state == "char":
            out.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    out.append(nxt)
                i += 2
                continue
            if ch == "'":
                state = "code"
            i += 1
    return "".join(out)


def _raw_string_ahead(source: str, i: int) -> bool:
    j = i + 1
    if j < len(source) and source[j] != "#":
        return source[j] == '"'
    while j < len(source) and source[j] == "#":
        j += 1
    return j < len(source) and source[j] == '"'


def _raw_string_hashes(source: str, i: int) -> int:
    j = i + 1
    hashes = 0
    while j < len(source) and source[j] == "#":
        hashes += 1
        j += 1
    return hashes


def _raw_close(source: str, i: int, hashes: int) -> bool:
    j = i
    k = 0
    while j < len(source) and k < hashes and source[j] == "#":
        j += 1
        k += 1
    return k == hashes


def _is_char_literal(source: str, i: int) -> bool:
    # 'x' / '\n' / '\u{1}' forms: next chars reach a closing ' quickly
    j = i + 1
    if j >= len(source):
        return False
    if source[j] == "\\":
        j += 2
    else:
        j += 1
    return j < len(source) and source[j] == "'"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

TEST_REGION_RE = re.compile(r"^[ \t]*#\[cfg\(test\)\]", re.MULTILINE)


def production_region(source: str) -> str:
    match = TEST_REGION_RE.search(source)
    return source if match is None else source[: match.start()]


def iter_hits(code: str):
    """Yield (marker_class, marker, line_no) over comment-stripped code."""
    stripped = strip_rust_comments(code)
    for name in FUNCTION_NAMES:
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9])"
        )
        for match in pattern.finditer(stripped):
            yield "function", name, stripped.count("\n", 0, match.start()) + 1
    for name in BINARY_NAMES:
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])"
        )
        for match in pattern.finditer(stripped):
            yield "binary", name, stripped.count("\n", 0, match.start()) + 1
    for address in CORPUS_ADDRESSES:
        pattern = re.compile(re.escape(address) + r"(?![0-9a-fA-F])")
        for match in pattern.finditer(stripped):
            yield "address", address, stripped.count("\n", 0, match.start()) + 1


def scan_file(path: Path, root: Path, verbose: bool) -> tuple[int, int]:
    source = path.read_text(encoding="utf-8", errors="replace")
    region = production_region(source)
    violations = 0
    allowed = 0
    try:
        relative = path.resolve().relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    for marker_class, marker, line_no in iter_hits(region):
        entry = next(
            (
                allow
                for allow in ALLOWLIST
                if allow[0] == relative and allow[1] == marker
            ),
            None,
        )
        if entry is None:
            violations += 1
            print(
                f"VIOLATION {relative}:{line_no} [{marker_class}] {marker}"
            )
        else:
            allowed += 1
            if verbose:
                print(
                    f"ALLOWED   {relative}:{line_no} [{marker_class}] {marker}"
                    f" — {entry[2]}"
                )
    return violations, allowed


def staged_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    files = [
        root / line
        for line in result.stdout.decode(errors="replace").splitlines()
        if line.startswith("src/") and line.endswith(".rs")
    ]
    return [path for path in files if path.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="scan all src/**/*.rs")
    mode.add_argument(
        "--staged", action="store_true", help="scan only staged src/*.rs files"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    if args.staged:
        files = staged_files(root)
    else:
        files = sorted((root / "src").rglob("*.rs"))

    total_violations = 0
    total_allowed = 0
    for path in files:
        violations, allowed = scan_file(path, root, args.verbose)
        total_violations += violations
        total_allowed += allowed

    print(
        f"corpus markers: {total_violations} violation(s), "
        f"{total_allowed} allowlisted, {len(files)} file(s) scanned"
    )
    if total_violations:
        print(
            "Production library code must not special-case corpus symbols, "
            "binary names, or corpus addresses. Route the knowledge through "
            "a data-driven channel (e.g. debugproto::LibcSignatureTable / "
            "DWARF / callee FuncProto locks) or register + justify an "
            "allowlist entry with a TODO ID."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
