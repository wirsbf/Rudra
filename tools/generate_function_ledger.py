#!/usr/bin/env python3
"""Generate Rudra's locked-Ghidra function ledger and dependency inventories.

The generated files are observations, not alignment claims.  In particular,
an exact source annotation proves provenance only; behavior remains UNTESTED
until a locked oracle fixture records a complete MATCH.

Function IDs (id scheme 2) are position-independent and ordinal-free:

* Ghidra ``GH12-F-...`` = sha256 over (locked path, entry_kind, complete
  qualified signature) plus, only for otherwise indistinguishable duplicates
  (conditionally compiled macro variants), the preprocessor guard context of
  the definition.  Line numbers and same-name ordinals never enter the ID.
* Rust ``RG-F-...`` = sha256 over (module, owner context, normalized
  signature).  The owner context renders trait impls as ``Type as Trait``,
  records ``macro_rules!`` template scopes by macro name, and qualifies
  nested functions by their parent signature.  ``name_ordinal`` is recorded
  as an observation for legacy consumers but never participates in the ID.

``--migrate`` performs the one-time scheme-1 to scheme-2 rewrite and emits
``FUNCTION_ID_MIGRATION.json``.  ``--reconcile-migration`` is deliberately a
separate operation: it replays the pinned first-parent Rust history from that
immutable source table to the pinned current ledger.  Keeping these two
operations separate prevents a later ledger refresh from silently replacing
the migration's historical origin.  ``--reconcile-continuity`` extends that
immutable baseline through a later pinned source checkpoint without changing
the raw scheme-2 hash or rewriting the baseline migration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence

try:
    from .rust_fn_scanner import RustFunction, mask_non_code, scan_rust_functions
except ImportError:
    from rust_fn_scanner import RustFunction, mask_non_code, scan_rust_functions


ORACLE_COMMIT = "e40ed13014025f82488b1f8f7bca566894ac376b"
EXPECTED_COUNTS = {
    "cc_definition": 5691,
    "cc_prototype": 101,
    "hh_definition": 3803,
    "hh_prototype": 6216,
}
GHIDRA_MARKER_RE = re.compile(
    r"//\s*Ghidra:\s*(?P<file>[A-Za-z0-9_.-]+\.(?:cc|hh)):(?P<line>\d+)(?:\s+(?P<label>.*?))?\s*$"
)
GLUE_MARKER_RE = re.compile(r"//\s*RUDRA-GLUE:\s*(?P<reason>.*?)\s*$")
CPP_ASSIGN_RE = re.compile(r"(?<![A-Za-z0-9_])(?P<name>[A-Z][A-Z0-9_]{2,})\s*=\s*(?P<value>[^,;/}]+)")
CPP_ID_RE = re.compile(
    r"\b(?P<kind>AttributeId|ElementId)\s+(?P<name>[A-Z][A-Z0-9_]+)\s*\([^,]+,\s*(?P<value>[^)]+)\)"
)
RUST_CONST_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?const\s+(?P<name>[A-Z][A-Z0-9_]{2,})\s*:[^=;]+\s*=\s*(?P<value>[^;]+);"
)
RUST_CRATE_REF_RE = re.compile(r"\bcrate::(?P<path>[A-Za-z_][A-Za-z0-9_:]*)")
CPP_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"(?P<name>[A-Za-z0-9_.-]+\.hh)"', re.MULTILINE)
# A TODO identifier must contain at least one hyphen-separated component.
# This deliberately excludes evidence/status literals such as `MATCH`,
# `MISMATCH`, `NO_ORACLE`, and `UNTESTED` from the dependency graph.
TODO_ID_RE = re.compile(r"`(?P<id>[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+)`")
MARKDOWN_SEPARATOR_RE = re.compile(r"^:?-{3,}:?$")
DEPENDENCY_LABEL_RE = re.compile(
    r"(?:^|[；;])\s*(?:依赖|dependency|dependencies)\s*(?:=|:|：)?\s*"
    r"(?P<body>.*?)(?=[；;]|$)",
    re.IGNORECASE,
)

# Preprocessor conditionals, used only to derive a stable, content-based
# disambiguator for duplicate Ghidra definitions (``#ifdef`` variants).
CPP_CONDITIONAL_RE = re.compile(
    r"^\s*#\s*(?P<kw>if|ifdef|ifndef|elif|else|endif)\b\s*(?P<expr>.*)$"
)

# Rust scope classification for the owner context of a function item.
RUST_MACRO_RULES_RE = re.compile(r"^macro_rules\s*!\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
RUST_ITEM_KW_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:unsafe\s+|default\s+|auto\s+)*"
    r"(?P<kw>impl|trait|mod|fn|extern)\b"
)
RUST_VIS_PREFIX_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+")

ID_SCHEME = {
    "schema": 2,
    "ghidra": (
        "GH12-F = stable_id(prefix, locked_path, entry_kind, complete_qualified_signature"
        "[, preprocessor_guard_disambiguator])"
    ),
    "rust": (
        "RG-F = stable_id(prefix, module, owner_context, normalized_signature); "
        "owner_context renders trait impls as 'Type as Trait', macro_rules! template "
        "scopes as 'macro:NAME', nested functions as 'fn:<parent signature>'; "
        "name_ordinal and line numbers never participate"
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, parts: Iterable[object]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return f"{prefix}-{digest.hexdigest()[:20]}"


def command_output(command: list[str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def verify_oracle(root: Path) -> Path:
    ghidra = root / "ghidra"
    commit = command_output(["git", "rev-parse", "HEAD"], ghidra).strip()
    if commit != ORACLE_COMMIT:
        raise RuntimeError(f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {commit}")
    dirty = command_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], ghidra
    ).strip()
    if dirty:
        raise RuntimeError(f"locked Ghidra worktree has tracked changes:\n{dirty}")
    cpp = ghidra / "Ghidra/Features/Decompiler/src/decompile/cpp"
    cc_count = len(list(cpp.glob("*.cc")))
    if cc_count != 114:
        raise RuntimeError(f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}")
    return cpp


def preprocessor_guard_context(lines: Sequence[str], target_index: int) -> str:
    """Render the active preprocessor conditional chain at a source line.

    The value is derived from file content only (macro guard expressions),
    never from the line number itself, so it stays stable across unrelated
    insertions, deletions, and moves elsewhere in the file.
    """

    stack: list[list[str | None]] = []
    for index in range(target_index):
        match = CPP_CONDITIONAL_RE.match(lines[index])
        if not match:
            continue
        keyword = match.group("kw")
        expression = match.group("expr").strip()
        if keyword in ("if", "ifdef", "ifndef"):
            if keyword == "ifdef":
                condition = f"defined({expression})"
            elif keyword == "ifndef":
                condition = f"!defined({expression})"
            else:
                condition = f"({expression})"
            stack.append([condition])
        elif keyword == "elif" and stack:
            stack[-1].append(f"({expression})")
        elif keyword == "else" and stack:
            stack[-1].append(None)
        elif keyword == "endif" and stack:
            stack.pop()
    parts: list[str] = []
    for frame in stack:
        if len(frame) == 1:
            parts.append(str(frame[0]))
        elif frame[-1] is None:
            parts.append("!(" + " || ".join(str(item) for item in frame[:-1]) + ")")
        else:
            parts.append(str(frame[-1]))
    return " && ".join(parts)


def assign_ghidra_locked_ids(
    entries: list[dict[str, object]], cpp: Path
) -> list[dict[str, object]]:
    """Assign position-independent Ghidra IDs.

    Collisions (same path + signature + category, e.g. conditionally compiled
    macro variants) are disambiguated by preprocessor guard context; if that
    cannot separate them the assignment fails closed rather than falling back
    to ordinals or line numbers.
    """

    for entry in entries:
        entry["id_disambiguator"] = None
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        base = stable_id(
            "GH12-F",
            (entry.get("path", ""), entry.get("entry_kind", ""), entry.get("signature", "")),
        )
        entry["id"] = base
        groups[base].append(entry)
    disambiguated: list[dict[str, object]] = []
    for base, group in groups.items():
        if len(group) == 1:
            continue
        lines_cache: dict[str, list[str]] = {}

        def guard_for(entry: dict[str, object]) -> str:
            file_name = str(entry["file"])
            if file_name not in lines_cache:
                lines_cache[file_name] = (cpp / file_name).read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            return preprocessor_guard_context(lines_cache[file_name], int(entry["line"]) - 1)

        contexts = [guard_for(entry) for entry in group]
        # An empty context ("unconditional") is itself a distinct value; only
        # genuinely indistinguishable members fail closed.
        if len(set(contexts)) == len(contexts):
            for entry, context in zip(group, contexts):
                entry["id"] = stable_id(
                    "GH12-F",
                    (
                        entry.get("path", ""),
                        entry.get("entry_kind", ""),
                        entry.get("signature", ""),
                        context,
                    ),
                )
                entry["id_disambiguator"] = {
                    "kind": "preprocessor_guard",
                    "value": context,
                }
                disambiguated.append(entry)
            continue
        raise RuntimeError(
            "indistinguishable Ghidra function records share one ID key and their "
            "preprocessor guard contexts do not separate them; refusing to guess an "
            "ordinal-free disambiguator:\n"
            + "\n".join(
                f"  {item['path']}:{item['line']} {item['signature']} guard={context!r}"
                for item, context in zip(group, contexts)
            )
        )
    return disambiguated


def ctags_entries(root: Path, cpp: Path) -> tuple[list[dict[str, object]], str]:
    ctags = shutil.which("ctags")
    if ctags is None:
        raise RuntimeError("Universal Ctags is required")
    version = command_output([ctags, "--version"], root).splitlines()[0]
    if "Universal Ctags" not in version:
        raise RuntimeError(f"unsupported ctags implementation: {version}")
    files = sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh"))
    command = [
        ctags,
        "--output-format=json",
        "--fields=+neKStz",
        "--extras=+F",
        "--kinds-C++=+p",
        "-o",
        "-",
        *[str(path.relative_to(root)) for path in files],
    ]
    raw = command_output(command, root)
    entries: list[dict[str, object]] = []
    for line in raw.splitlines():
        item = json.loads(line)
        if item.get("_type") != "tag" or item.get("kind") not in ("function", "prototype"):
            continue
        path = str(item["path"])
        line_number = int(item["line"])
        end = int(item.get("end", line_number))
        kind = "definition" if item["kind"] == "function" else "prototype"
        suffix = Path(path).suffix[1:]
        scope = str(item.get("scope", ""))
        name = str(item["name"])
        arguments = str(item.get("signature", ""))
        typeref = str(item.get("typeref", ""))
        return_type = typeref.removeprefix("typename:")
        qualified_name = f"{scope}::{name}" if scope else name
        complete_signature = f"{qualified_name}{arguments}"
        if return_type:
            complete_signature = f"{return_type} {complete_signature}"
        entries.append(
            {
                "path": path,
                "file": Path(path).name,
                "source_kind": suffix,
                "entry_kind": kind,
                "line": line_number,
                "end_line": max(line_number, end),
                "name": name,
                "scope": scope,
                "qualified_name": qualified_name,
                "arguments": arguments,
                "return_type": return_type,
                "signature": complete_signature,
                "file_scope": bool(item.get("file")),
                "rust_mappings": [],
                "behavior_status": "UNTESTED" if kind == "definition" else "DECLARATION",
            }
        )
    entries.sort(
        key=lambda entry: (
            entry["path"],
            entry["line"],
            entry["entry_kind"],
            entry["scope"],
            entry["name"],
            entry["arguments"],
        )
    )
    assign_ghidra_locked_ids(entries, cpp)
    return entries, version


def validate_ctags_counts(entries: list[dict[str, object]]) -> dict[str, int]:
    counts = Counter(
        f"{entry['source_kind']}_{entry['entry_kind']}" for entry in entries
    )
    actual = {key: counts.get(key, 0) for key in EXPECTED_COUNTS}
    if actual != EXPECTED_COUNTS:
        raise RuntimeError(f"ctags denominator drift: expected {EXPECTED_COUNTS}, got {actual}")
    return actual


# FMAPRECON cross-corroboration pins (FUNCTION_MAP_RECONCILE_2026-09-26 §1.3/
# §3.4, measured on the locked oracle with Universal Ctags 6.2.0): the REFSDEF
# line-form parser is a .cc-side cross-check of the ctags enumeration, never
# the denominator enumerator (it systematically over-counts .hh because doxygen
# tail comments defeat the `;` guard).  Name-grain residuals (operator
# spellings, nested-class ctors, class-body inline free keys) are classified
# and stable on the locked tree; any drift here means a tool behavior change
# that must be re-adjudicated before the ledger can be regenerated.
PARSER_CROSS_CHECK_COUNTS = {
    "refsdef_parser_cc_unique_names": 5_549,
    "ctags_cc_unique_names_stripped": 5_530,
    "parser_only_names": 122,
    "ctags_only_names": 103,
}


def parser_cross_check(cpp: Path, ghidra: list[dict[str, object]]) -> dict[str, int]:
    """Corroborate the ctags .cc enumeration with the REFSDEF line parser.

    Metric grain (FMAPRECON delta_characterize.py): per-file name sets summed
    over the 114 .cc files, residuals likewise per (file, name) pairs.
    """
    import check_ghidra_refs  # noqa: PLC0415 - tools-dir sibling module

    parser_by_file: dict[str, set[str]] = {}
    for cc in sorted(cpp.glob("*.cc")):
        parser_by_file[cc.name] = set(check_ghidra_refs.parse_cc_definitions(cc.name))
    ctags_by_file: dict[str, set[str]] = {}
    for entry in ghidra:
        if entry.get("source_kind") != "cc" or entry.get("entry_kind") != "definition":
            continue
        qualified = str(entry.get("qualified_name") or "")
        if qualified.startswith("ghidra::"):
            qualified = qualified[len("ghidra::"):]
        ctags_by_file.setdefault(str(entry["file"]), set()).add(qualified)
    parser_only = sum(
        len(parser_by_file.get(name, set()) - ctags_by_file.get(name, set()))
        for name in set(parser_by_file) | set(ctags_by_file)
    )
    ctags_only = sum(
        len(ctags_by_file.get(name, set()) - parser_by_file.get(name, set()))
        for name in set(parser_by_file) | set(ctags_by_file)
    )
    actual = {
        "refsdef_parser_cc_unique_names": sum(map(len, parser_by_file.values())),
        "ctags_cc_unique_names_stripped": sum(map(len, ctags_by_file.values())),
        "parser_only_names": parser_only,
        "ctags_only_names": ctags_only,
    }
    if actual != PARSER_CROSS_CHECK_COUNTS:
        raise RuntimeError(
            "parser cross-check drift (FMAPRECON pinned "
            f"{PARSER_CROSS_CHECK_COUNTS}, got {actual}); re-adjudicate before "
            "regenerating the ledger"
        )
    return actual


# --- Unmapped dispositions: bison translation units -----------------------
#
# GENERATOR_ABSORBED_2026-09-27.md (lane PARSEADJ ticket
# WORKPKG-UNMAP-PARSEADJ-0015; integrated into this classifier by lane
# REGENABSORB, see also REBASE-0000 item 3): grammar.cc / pcodeparse.cc are
# bison-generated translation units.  Their yy* definitions are the LALR(1)
# table driver plus its debug/error print skeleton expanded from the
# grammar.y / pcodeparse.y templates, with no hand-written action semantics;
# Rudra replaces the whole face with hand-written recursive-descent drivers,
# so the equivalence unit is a whole-parser fixture, never a per-function
# claim.  The pinned (file, line) whitelist below dispositions every unmapped
# definition in the four bison files; no name matching is performed.  When a
# whitelisted entry later gains a real Rust mapping (for example the parseadj
# per-variant twins for grammar.cc:2403/2412/2419, or the pcodeparse.y
# re-anchoring owned by the PCODEFACE lane), generation fails closed and the
# entry must be trimmed from the whitelist together with the expected counts
# -- that is the documented pool-exit gate, not an error to paper over.
GENERATOR_ABSORBED_DOC = "docs/alignment_audit/GENERATOR_ABSORBED_2026-09-27.md"
UNMAPPED_DISPOSITION_FILES = ("grammar.cc", "grammar.hh", "pcodeparse.cc", "pcodeparse.hh")
UNMAPPED_DISPOSITION_TICKET = "WORKPKG-UNMAP-PARSEADJ-0015"
GRAMMAR_FACE_EVIDENCE = {
    "fixture": "tests/oracle/grammar_parse_face_1204",
    "face_result": "BILATERAL_MATCH",
    "records": 83,
    "records_sha256": "d63130daf9c6ce1087dfe156208337e6ecd488d010043f0761f4dcbfa1d65c49",
    "oracle_commit": ORACLE_COMMIT,
    "note": (
        "whole-face equivalence unit (GENERATOR_ABSORBED section 3); the fixture "
        "files land with the parseadj branch merge, and behavior_status stays "
        "UNTESTED until then -- generator provenance alone never promotes a match"
    ),
}
PCODE_FACE_PENDING = {
    "ticket": "PARSEADJ-PARSEFACE-PCODE-0001",
    "note": (
        "p-code parse-face fixture not built yet; members stay UNTESTED and must "
        "not cite the grammar face (GENERATOR_ABSORBED section 3)"
    ),
}
UNMAPPED_DISPOSITION_CLASS_NOTES = {
    "generator_absorbed": (
        "bison LALR driver + debug/error print skeleton (GENERATOR_ABSORBED "
        "sections 1-2); replaced whole-face by the recursive-descent driver"
    ),
    "generator_shim": (
        "yylex/yyerror bridge of the bison driver; absorbed with the same "
        "replacement unit (GENERATOR_ABSORBED section 2)"
    ),
    "glue_absorbed": (
        "DECOMP section 4 glue absorption: .hh inline <=2 lines, accessor "
        "shape, owning class with >=3 mapped members (GENERATOR_ABSORBED section 4)"
    ),
    "inline_absorbed": (
        "hand-written lexer core absorbed into GrammarLexer::get_next_token's "
        "state machine (GENERATOR_ABSORBED section 4; grammar_audit.md design note 4)"
    ),
    "drop_absorbed": (
        "destructor absorbed by Rust ownership (Arc + Vec drop); no separate "
        "Rudra function is expected (GENERATOR_ABSORBED section 4)"
    ),
    "unlinked_relink": (
        "implemented in Rust but not linked by a // Ghidra annotation yet "
        "(GENERATOR_ABSORBED section 4)"
    ),
    "residual_relink": (
        "per-variant twin verified equivalent in place by PARSEADJ; twin "
        "annotations take over the mapping at the parseadj merge and this "
        "entry then exits the pool (GENERATOR_ABSORBED section 4)"
    ),
}
UNMAPPED_DISPOSITIONS: dict[tuple[str, int], dict[str, object]] = {
    # generator_absorbed -- yy* skeleton (grammar.cc, 10 defs / 1003 LOC)
    ("grammar.cc", 827): {"class": "generator_absorbed"},
    ("grammar.cc", 848): {"class": "generator_absorbed"},
    ("grammar.cc", 863): {"class": "generator_absorbed"},
    ("grammar.cc", 886): {"class": "generator_absorbed"},
    ("grammar.cc", 947): {"class": "generator_absorbed"},
    ("grammar.cc", 964): {"class": "generator_absorbed"},
    ("grammar.cc", 986): {"class": "generator_absorbed"},
    ("grammar.cc", 1037): {"class": "generator_absorbed"},
    ("grammar.cc", 1176): {"class": "generator_absorbed"},
    ("grammar.cc", 1205): {"class": "generator_absorbed"},
    # generator_absorbed -- yy* skeleton (pcodeparse.cc, 10 defs / 1231 LOC)
    ("pcodeparse.cc", 1365): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1386): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1401): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1424): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1485): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1502): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1524): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1575): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1714): {"class": "generator_absorbed"},
    ("pcodeparse.cc", 1791): {"class": "generator_absorbed"},
    # generator_shim -- lex/error bridges of the bison driver
    ("grammar.cc", 3100): {"class": "generator_shim"},
    ("grammar.cc", 3106): {"class": "generator_shim"},
    ("pcodeparse.cc", 3292): {"class": "generator_shim"},
    ("pcodeparse.cc", 3296): {"class": "generator_shim"},
    # glue_absorbed -- grammar.hh one-line inline accessors/setters (19 defs)
    ("grammar.hh", 58): {"class": "glue_absorbed"},
    ("grammar.hh", 61): {"class": "glue_absorbed"},
    ("grammar.hh", 62): {"class": "glue_absorbed"},
    ("grammar.hh", 63): {"class": "glue_absorbed"},
    ("grammar.hh", 64): {"class": "glue_absorbed"},
    ("grammar.hh", 65): {"class": "glue_absorbed"},
    ("grammar.hh", 66): {"class": "glue_absorbed"},
    ("grammar.hh", 102): {"class": "glue_absorbed"},
    ("grammar.hh", 113): {"class": "glue_absorbed"},
    ("grammar.hh", 127): {"class": "glue_absorbed"},
    ("grammar.hh", 137): {"class": "glue_absorbed"},
    ("grammar.hh", 138): {"class": "glue_absorbed"},
    ("grammar.hh", 147): {"class": "glue_absorbed"},
    ("grammar.hh", 148): {"class": "glue_absorbed"},
    ("grammar.hh", 159): {"class": "glue_absorbed"},
    ("grammar.hh", 160): {"class": "glue_absorbed"},
    ("grammar.hh", 277): {"class": "glue_absorbed"},
    ("grammar.hh", 278): {"class": "glue_absorbed"},
    ("grammar.hh", 279): {"class": "glue_absorbed"},
    # inline_absorbed -- GrammarLexer core folded into get_next_token
    ("grammar.cc", 2048): {"class": "inline_absorbed"},
    ("grammar.cc", 2062): {"class": "inline_absorbed"},
    ("grammar.cc", 2294): {"class": "inline_absorbed"},
    # drop_absorbed -- destructors absorbed by Rust ownership
    ("grammar.cc", 2486): {"class": "drop_absorbed"},
    ("grammar.cc", 2608): {"class": "drop_absorbed"},
    # unlinked_relink -- mergeSpecDec(TypeSpecifiers*) single-parameter overload,
    # behavior covered by merge_spec_dec; registered in the REBASE-0000 batch-2
    # candidate list (GENERATOR_ABSORBED section 4)
    ("grammar.cc", 2633): {
        "class": "unlinked_relink",
        "target": ("src/grammar.rs", "merge_spec_dec", "impl:CParse"),
        "ticket": "WORKPKG-UNMAP-REBASE-0000",
    },
    # unlinked_relink -- pcodeparse members implemented in Rust but annotated
    # at their true pcodeparse.y source lines, which the ledger does not accept;
    # re-anchoring to these .cc definition starts (option a) is owned by the
    # PCODEFACE lane (src/pcodeparse.rs write domain)
    ("pcodeparse.cc", 2795): {"class": "unlinked_relink", "y_anchor": 297},
    ("pcodeparse.cc", 3058): {"class": "unlinked_relink", "y_anchor": 560},
    ("pcodeparse.cc", 3106): {"class": "unlinked_relink", "y_anchor": 608},
    ("pcodeparse.cc", 3130): {"class": "unlinked_relink", "y_anchor": 632},
    ("pcodeparse.cc", 3138): {"class": "unlinked_relink", "y_anchor": 640},
    ("pcodeparse.cc", 3150): {"class": "unlinked_relink", "y_anchor": 652},
    ("pcodeparse.cc", 3174): {"class": "unlinked_relink", "y_anchor": 676},
    ("pcodeparse.cc", 3195): {"class": "unlinked_relink"},
    ("pcodeparse.cc", 3207): {"class": "unlinked_relink", "y_anchor": 709},
    ("pcodeparse.cc", 3268): {"class": "unlinked_relink", "y_anchor": 770},
    ("pcodeparse.cc", 3285): {"class": "unlinked_relink", "y_anchor": 787},
    # residual_relink -- true residuals; PARSEADJ extracted per-variant twins
    # (parseadj commit 5b4a6b26) that carry the exact behavior; in this tree
    # the behavior lives inside the mod_type / new_func monoliths until the
    # parseadj branch merges
    ("grammar.cc", 2403): {
        "class": "residual_relink",
        "twin": ("src/grammar.rs", "pointer_mod_type"),
        "holder": ("src/grammar.rs", "mod_type", "free"),
    },
    ("grammar.cc", 2412): {
        "class": "residual_relink",
        "twin": ("src/grammar.rs", "array_mod_type"),
        "holder": ("src/grammar.rs", "mod_type", "free"),
    },
    ("grammar.cc", 2419): {
        "class": "residual_relink",
        "twin": ("src/grammar.rs", "function_modifier_ctor"),
        "holder": ("src/grammar.rs", "new_func", "impl:CParse"),
    },
}
# Pinned class totals (definitions, LOC) on the locked oracle; GENERATOR
# ABSORBED_2026-09-27 TL;DR / section 4: pool 63 defs / 2997 LOC = family 24
# (yy 20/2234 + shim 4/19) + remaining 39 (residual 3/28 + other 36/716 =
# glue 19/19 + grammar.cc rest 6/264 + pcodeparse rest 11/433).
UNMAPPED_DISPOSITION_EXPECTED_CLASSES = {
    "generator_absorbed": (20, 2234),
    "generator_shim": (4, 19),
    "glue_absorbed": (19, 19),
    "inline_absorbed": (3, 246),
    "drop_absorbed": (2, 11),
    "unlinked_relink": (12, 440),
    "residual_relink": (3, 28),
}
UNMAPPED_DISPOSITION_EXPECTED_POOL = (63, 2997)


def _resolve_unique_rust_record(
    rust: list[dict[str, object]], path: str, name: str, owner: str
) -> dict[str, object]:
    """Resolve exactly one production Rust record by identity pins."""

    matches = [
        entry
        for entry in rust
        if entry["path"] == path
        and entry["name"] == name
        and entry["owner"] == owner
        and not entry["is_test"]
    ]
    if len(matches) != 1:
        found = [
            f"{entry['path']}:{entry['line']} owner={entry['owner']}"
            for entry in matches
        ]
        raise RuntimeError(
            "unmapped-disposition target resolution failed: expected exactly one "
            f"production record for {path}::{name} owner={owner}, got "
            f"{len(matches)} ({'; '.join(found) or 'none'}); the pinned "
            "disposition table must be updated alongside the src change"
        )
    return {
        "path": path,
        "name": name,
        "owner": owner,
        "rust_id": matches[0]["id"],
    }


def classify_unmapped_dispositions(
    ghidra: list[dict[str, object]], rust: list[dict[str, object]]
) -> dict[str, object]:
    """Disposition every unmapped definition in the bison translation units.

    Fails closed on any drift between the pinned whitelist and the observed
    pool: a new unmapped entry needs a disposition ruling, and a whitelisted
    entry that gained a real Rust mapping (the parseadj twins, the PCODEFACE
    re-anchoring) must be trimmed from the whitelist with its expected counts
    -- the documented pool-exit gate of GENERATOR_ABSORBED section 5.
    """

    pool: dict[tuple[str, int], dict[str, object]] = {}
    for entry in ghidra:
        if str(entry["file"]) not in UNMAPPED_DISPOSITION_FILES:
            continue
        if entry["entry_kind"] != "definition" or entry["rust_mappings"]:
            continue
        key = (str(entry["file"]), int(entry["line"]))
        if key in pool:
            raise RuntimeError(f"duplicate unmapped record at {key[0]}:{key[1]}")
        pool[key] = entry
    undispositioned = sorted(set(pool) - set(UNMAPPED_DISPOSITIONS))
    if undispositioned:
        raise RuntimeError(
            "unmapped definitions in the bison translation units without a "
            "pinned disposition (GENERATOR_ABSORBED drift; rule on them before "
            "regenerating): "
            + ", ".join(f"{file}:{line}" for file, line in undispositioned)
        )
    exited = sorted(set(UNMAPPED_DISPOSITIONS) - set(pool))
    if exited:
        raise RuntimeError(
            "whitelisted dispositions whose entries left the unmapped pool "
            "(a real Rust mapping now covers them; trim the whitelist entry "
            "and the expected counts -- GENERATOR_ABSORBED section 5 exit "
            "gate): "
            + ", ".join(f"{file}:{line}" for file, line in exited)
        )

    counters: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for key in sorted(pool):
        entry = pool[key]
        record = dict(UNMAPPED_DISPOSITIONS[key])
        disposition = str(record["class"])
        record["evidence"] = UNMAPPED_DISPOSITION_CLASS_NOTES[disposition]
        if disposition in ("generator_absorbed", "generator_shim"):
            record["face"] = (
                GRAMMAR_FACE_EVIDENCE if key[0] == "grammar.cc" else PCODE_FACE_PENDING
            )
        elif disposition == "inline_absorbed":
            record["absorber"] = _resolve_unique_rust_record(
                rust, "src/grammar.rs", "get_next_token", "impl:GrammarLexer"
            )
        elif disposition == "residual_relink":
            path, name = record["twin"]  # type: ignore[misc]
            record["twin"] = {
                "path": path,
                "name": name,
                "status": "extracted_on_parseadj_5b4a6b26_pending_merge",
            }
            holder_path, holder_name, holder_owner = record["holder"]  # type: ignore[misc]
            record["holder"] = _resolve_unique_rust_record(
                rust, holder_path, holder_name, holder_owner
            )
        elif disposition == "unlinked_relink" and "target" in record:
            target_path, target_name, target_owner = record["target"]  # type: ignore[misc]
            record["target"] = _resolve_unique_rust_record(
                rust, target_path, target_name, target_owner
            )
        entry["unmapped_disposition"] = record
        counters[disposition][0] += 1
        counters[disposition][1] += int(entry["end_line"]) - int(entry["line"]) + 1

    observed = {name: (values[0], values[1]) for name, values in counters.items()}
    if observed != UNMAPPED_DISPOSITION_EXPECTED_CLASSES:
        raise RuntimeError(
            "unmapped-disposition class drift (GENERATOR_ABSORBED pinned "
            f"{UNMAPPED_DISPOSITION_EXPECTED_CLASSES}, got {observed}); "
            "re-adjudicate before regenerating the ledger"
        )
    pool_defs = len(pool)
    pool_loc = sum(values[1] for values in counters.values())
    if (pool_defs, pool_loc) != UNMAPPED_DISPOSITION_EXPECTED_POOL:
        raise RuntimeError(
            "unmapped-disposition pool drift (GENERATOR_ABSORBED pinned "
            f"{UNMAPPED_DISPOSITION_EXPECTED_POOL}, got "
            f"({pool_defs}, {pool_loc}))"
        )
    family = {
        "definitions": counters["generator_absorbed"][0] + counters["generator_shim"][0],
        "loc": counters["generator_absorbed"][1] + counters["generator_shim"][1],
        "yy_skeleton": {
            "definitions": counters["generator_absorbed"][0],
            "loc": counters["generator_absorbed"][1],
        },
        "lex_error_shim": {
            "definitions": counters["generator_shim"][0],
            "loc": counters["generator_shim"][1],
        },
    }
    return {
        "source": "GENERATOR_ABSORBED_2026-09-27",
        "document": GENERATOR_ABSORBED_DOC,
        "ticket": UNMAPPED_DISPOSITION_TICKET,
        "files": list(UNMAPPED_DISPOSITION_FILES),
        "pool": {"definitions": pool_defs, "loc": pool_loc},
        "generator_absorbed_family": family,
        "remaining_pool": {
            "definitions": pool_defs - family["definitions"],
            "loc": pool_loc - family["loc"],
        },
        "classes": {
            name: {"definitions": values[0], "loc": values[1]}
            for name, values in sorted(counters.items())
        },
    }


def marker_above(lines: list[str], start_line: int) -> tuple[str, dict[str, object]]:
    """Find the provenance marker above a function starting at ``start_line``.

    ``start_line`` is the zero-based index of the function's first line, as
    produced by the scanner.
    """

    position = start_line - 1
    while position >= 0:
        stripped = lines[position].strip()
        if not stripped or stripped.startswith("#[") or stripped.startswith("#!["):
            position -= 1
            continue
        if stripped.startswith("//"):
            ghidra = GHIDRA_MARKER_RE.search(stripped)
            if ghidra:
                return (
                    "ghidra",
                    {
                        "file": ghidra.group("file"),
                        "line": int(ghidra.group("line")),
                        "label": (ghidra.group("label") or "").strip(),
                    },
                )
            glue = GLUE_MARKER_RE.search(stripped)
            if glue:
                return "glue", {"reason": glue.group("reason").strip()}
            position -= 1
            continue
        break
    return "missing", {}


# --- Rust identity extraction (module, owner context, normalized signature) ---


def rust_brace_pairs(code: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for pos, ch in enumerate(code):
        if ch == "{":
            stack.append(pos)
        elif ch == "}" and stack:
            pairs[stack.pop()] = pos
    return pairs


def rust_skip_attributes(code: str, start: int) -> int:
    pos = start
    while True:
        while pos < len(code) and code[pos].isspace():
            pos += 1
        if pos >= len(code) or code[pos] != "#":
            return pos
        opening = pos + 1
        while opening < len(code) and code[opening].isspace():
            opening += 1
        if opening >= len(code) or code[opening] != "[":
            return pos
        depth = 1
        pos = opening + 1
        while pos < len(code) and depth:
            if code[pos] == "[":
                depth += 1
            elif code[pos] == "]":
                depth -= 1
            pos += 1


def rust_signature_end(code: str, pairs: dict[int, int], search_from: int) -> int:
    """Offset where a function item's signature ends (body ``{`` or ``;``)."""

    paren = 0
    bracket = 0
    angle = 0
    pos = search_from
    while pos < len(code):
        ch = code[pos]
        if ch == "(":
            paren += 1
        elif ch == ")" and paren:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket:
            bracket -= 1
        elif ch == "<" and paren == 0 and bracket == 0:
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        elif ch == ";" and paren == 0 and bracket == 0 and angle == 0:
            return pos
        elif ch == "{" and paren == 0 and bracket == 0 and angle == 0:
            previous = pos - 1
            while previous >= search_from and code[previous].isspace():
                previous -= 1
            # A macro in a return type can use braces before the body.
            if previous >= search_from and code[previous] == "!" and pairs.get(pos) is not None:
                pos = pairs[pos] + 1
                continue
            return pos
        pos += 1
    return len(code)


def _top_level_index(text: str, separator: str) -> int | None:
    paren = 0
    bracket = 0
    angle = 0
    for index, ch in enumerate(text):
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "<" and paren == 0 and bracket == 0:
            angle += 1
        elif ch == ">" and angle:
            angle -= 1
        if paren == 0 and bracket == 0 and angle == 0 and text.startswith(separator, index):
            return index
    return None


def rust_cut_top_level(text: str, keyword: str) -> str:
    index = _top_level_index(text, keyword)
    return text if index is None else text[:index]


def rust_render_scope_header(header: str) -> tuple[str, str] | None:
    """Classify one enclosing block header as an owner-context segment."""

    header = " ".join(header.strip().split())
    if not header:
        return None
    macro = RUST_MACRO_RULES_RE.match(header)
    if macro:
        return ("macro", macro.group("name"))
    pos = rust_skip_attributes(header, 0)
    match = RUST_ITEM_KW_RE.match(header, pos)
    if not match:
        return None
    keyword = match.group("kw")
    rest = header[match.end("kw"):]
    if keyword == "mod":
        name = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", rest)
        return ("mod", name.group(1) if name else "?")
    if keyword == "trait":
        return ("trait", rust_cut_top_level(rest, " where").strip())
    if keyword == "fn":
        return ("fn", " ".join(header[match.start("kw"):].split()))
    if keyword == "extern":
        return ("extern", rest.strip())
    if keyword == "impl":
        rest = rest.strip()
        if rest.startswith("<"):
            depth = 0
            end = 0
            for end, ch in enumerate(rest):
                if ch == "<":
                    depth += 1
                elif ch == ">":
                    depth -= 1
                    if depth == 0:
                        break
            rest = rest[end + 1:].strip()
        rest = rust_cut_top_level(rest, " where")
        split = _top_level_index(rest, " for ")
        if split is not None:
            trait_part = rest[:split].strip()
            type_part = rest[split + len(" for "):].strip()
            return ("impl", f"{type_part} as {trait_part}")
        return ("impl", rest.strip())
    return None


def rust_scope_chain(code: str, pairs: dict[int, int], item_start: int) -> list[tuple[str, str]]:
    chain: list[tuple[str, str]] = []
    for open_pos in sorted(pos for pos, close in pairs.items() if pos < item_start < close):
        boundary = max(
            code.rfind("{", 0, open_pos),
            code.rfind("}", 0, open_pos),
            code.rfind(";", 0, open_pos),
        )
        segment = rust_render_scope_header(code[boundary + 1:open_pos])
        if segment:
            chain.append(segment)
    return chain


def collect_rust_identities(relative: str, text: str, module: str) -> list[dict[str, object]]:
    """Scan one Rust file and derive identity fields for every function item.

    The returned records carry the scanner observations plus the new-scheme
    ID parts; the ID itself is assigned later by ``assign_rust_locked_ids``
    so collisions can be handled globally across files.
    """

    code = mask_non_code(text)
    pairs = rust_brace_pairs(code)
    records: list[dict[str, object]] = []
    ordinals: Counter[str] = Counter()
    for record in scan_rust_functions(text):
        ordinals[record.name] += 1
        signature_end = rust_signature_end(code, pairs, record.start)
        signature = RUST_VIS_PREFIX_RE.sub(
            "", " ".join(code[record.start:signature_end].split())
        ).strip()
        chain = rust_scope_chain(code, pairs, record.start)
        inner_mods = [name for kind, name in chain if kind == "mod"]
        full_module = "::".join([module, *inner_mods])
        scopes = [f"{kind}:{name}" for kind, name in chain if kind != "mod"]
        owner = "/".join(scopes) if scopes else "free"
        enclosing = [pos for pos, close in pairs.items() if pos < record.start < close]
        if enclosing:
            innermost = max(enclosing)
            boundary = max(
                code.rfind("{", 0, innermost),
                code.rfind("}", 0, innermost),
                code.rfind(";", 0, innermost),
            )
            # Raw header of the nearest enclosing item, attributes included.
            # ``rust_render_scope_header`` deliberately drops attribute-decorated
            # headers (``#[test]``/``#[cfg(test)]``) from the owner chain, so this
            # raw segment is the only content-derived context that separates
            # identically named helpers nested inside two different attributed
            # scopes.  Whitespace-normalized and position-independent.
            scope_context = " ".join(code[boundary + 1:innermost].split())
        else:
            scope_context = ""
        records.append(
            {
                "path": relative,
                "name": record.name,
                "name_ordinal": ordinals[record.name],
                "line": record.start_line + 1,
                "end_line": record.end_line + 1,
                "is_test": record.is_test,
                "is_declaration": record.is_declaration,
                "start": record.start,
                "end": record.end,
                "module": full_module,
                "owner": owner,
                "signature": signature,
                "scope_context": scope_context,
            }
        )
    return records


def assign_rust_locked_ids(records: list[dict[str, object]]) -> None:
    """Assign new-scheme RG-F IDs; colliding identities fail closed."""

    for record in records:
        record["id"] = stable_id(
            "RG-F", (record["module"], record["owner"], record["signature"])
        )
        record["id_disambiguator"] = None
    collisions: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        collisions[str(record["id"])].append(record)
    unresolved: list[list[dict[str, object]]] = []
    for group in collisions.values():
        if len(group) < 2:
            continue
        # Content-derived fallback in the spirit of the Ghidra preprocessor
        # guard disambiguator: attribute-decorated scope headers are dropped
        # from the owner chain by design, so identically named helpers nested
        # inside two different attributed scopes (e.g. two #[test] functions)
        # collide on (module, owner, signature) alone.  The raw nearest
        # enclosing item header separates them by content; if it cannot, the
        # assignment fails closed rather than guessing an ordinal.
        contexts = [str(record.get("scope_context") or "") for record in group]
        if len(set(contexts)) == len(contexts):
            for record, context in zip(group, contexts):
                record["id"] = stable_id(
                    "RG-F",
                    (
                        record["module"],
                        record["owner"],
                        record["signature"],
                        context,
                    ),
                )
                record["id_disambiguator"] = {
                    "kind": "enclosing_scope_header",
                    "value": context,
                }
            continue
        unresolved.append(group)
    if unresolved:
        details = []
        for group in unresolved:
            for record in group:
                details.append(
                    f"  {record['path']}:{record['line']} {record['name']} "
                    f"module={record['module']} owner={record['owner']} "
                    f"signature={record['signature']} "
                    f"scope_context={record.get('scope_context')!r}"
                )
        raise RuntimeError(
            "indistinguishable Rust function items share one ID key (module + owner "
            "+ signature + enclosing scope header); refusing to guess an "
            "ordinal-free disambiguator:\n" + "\n".join(details)
        )


def module_from_relative(relative: str) -> str:
    parts = relative.split("/")
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return ""
    parts[-1] = parts[-1].removesuffix(".rs")
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts)


def rust_entries(root: Path, ghidra_entries: list[dict[str, object]]) -> list[dict[str, object]]:
    exact_index: dict[tuple[str, int], list[dict[str, object]]] = defaultdict(list)
    span_index: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in ghidra_entries:
        exact_index[(str(entry["file"]), int(entry["line"]))].append(entry)
        span_index[str(entry["file"])].append(entry)

    rust: list[dict[str, object]] = []
    identities: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        relative = path.relative_to(root).as_posix()
        module = module_from_relative(relative)
        for identity in collect_rust_identities(relative, text, module):
            annotation_kind, annotation = marker_above(lines, int(identity["line"]) - 1)
            rust_entry: dict[str, object] = {
                "path": relative,
                "name": identity["name"],
                "name_ordinal": identity["name_ordinal"],
                "line": identity["line"],
                "end_line": identity["end_line"],
                "is_test": identity["is_test"],
                "is_declaration": identity["is_declaration"],
                "module": identity["module"],
                "owner": identity["owner"],
                "signature": identity["signature"],
                "annotation_kind": "test" if identity["is_test"] else annotation_kind,
                "annotation": annotation,
                "ghidra_mappings": [],
                "behavior_status": "TEST" if identity["is_test"] else "UNTESTED",
            }
            if not identity["is_test"] and annotation_kind == "ghidra":
                file_name = str(annotation["file"])
                line_number = int(annotation["line"])
                candidates = exact_index.get((file_name, line_number), [])
                exact = bool(candidates)
                mapping_kind = "exact_source_start"
                if not candidates:
                    containing = [
                        entry
                        for entry in span_index.get(file_name, [])
                        if int(entry["line"]) <= line_number <= int(entry["end_line"])
                    ]
                    if containing:
                        smallest = min(int(item["end_line"]) - int(item["line"]) for item in containing)
                        candidates = [
                            item
                            for item in containing
                            if int(item["end_line"]) - int(item["line"]) == smallest
                        ]
                        mapping_kind = "inside_function_body"
                    else:
                        mapping_kind = "unresolved_reference"
                for candidate in candidates:
                    candidate_mapping_kind = mapping_kind
                    if exact:
                        candidate_mapping_kind = (
                            "exact_definition_start"
                            if candidate["entry_kind"] == "definition"
                            else "exact_declaration_start"
                        )
                    rust_entry["ghidra_mappings"].append(
                        {"ghidra_id": candidate["id"], "kind": candidate_mapping_kind}
                    )
                if mapping_kind == "unresolved_reference":
                    rust_entry["behavior_status"] = "NO_ORACLE"
            elif not identity["is_test"] and annotation_kind == "missing":
                rust_entry["behavior_status"] = "NO_ORACLE"
            rust.append(rust_entry)
            identities.append(identity)
    sort_key = lambda entry: (entry["path"], entry["line"], entry["name"])  # noqa: E731
    rust.sort(key=sort_key)
    identities.sort(key=sort_key)
    # IDs are assigned globally (module strings can repeat across a `foo.rs`
    # and a nested `mod foo`), so mapping edges are stitched afterwards.
    assign_rust_locked_ids(identities)
    for entry, identity in zip(rust, identities):
        entry["id"] = identity["id"]
        entry["id_disambiguator"] = identity["id_disambiguator"]
    ghidra_by_id = {str(entry["id"]): entry for entry in ghidra_entries}
    for entry in ghidra_entries:
        entry["rust_mappings"] = []
    for entry in rust:
        for mapping in entry["ghidra_mappings"]:
            ghidra_entry = ghidra_by_id[str(mapping["ghidra_id"])]
            ghidra_entry["rust_mappings"].append(
                {"rust_id": entry["id"], "kind": mapping["kind"]}
            )
    return rust


def clean_value(value: str) -> str:
    return " ".join(value.strip().split())


def protocol_entries(root: Path, cpp: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(mask_non_code(source).splitlines(), 1):
            for match in CPP_ID_RE.finditer(line):
                entries.append(
                    {
                        "language": "cpp",
                        "kind": match.group("kind"),
                        "name": match.group("name"),
                        "value": clean_value(match.group("value")),
                        "path": relative,
                        "line": line_number,
                    }
                )
            for match in CPP_ASSIGN_RE.finditer(line):
                value = clean_value(match.group("value"))
                if value and len(value) <= 120:
                    entries.append(
                        {
                            "language": "cpp",
                            "kind": "constant_assignment",
                            "name": match.group("name"),
                            "value": value,
                            "path": relative,
                            "line": line_number,
                        }
                    )
    for path in sorted((root / "src").rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(mask_non_code(source).splitlines(), 1):
            for match in RUST_CONST_RE.finditer(line):
                value = clean_value(match.group("value"))
                if value and len(value) <= 120:
                    entries.append(
                        {
                            "language": "rust",
                            "kind": "const",
                            "name": match.group("name"),
                            "value": value,
                            "path": relative,
                            "line": line_number,
                        }
                    )
    deduplicated: dict[tuple[object, ...], dict[str, object]] = {}
    for entry in entries:
        key = tuple(entry[field] for field in ("language", "kind", "name", "value", "path", "line"))
        deduplicated[key] = entry
    result = sorted(
        deduplicated.values(),
        key=lambda entry: (entry["name"], entry["language"], entry["path"], entry["line"]),
    )
    for entry in result:
        entry["id"] = stable_id(
            "PROTO", (entry["language"], entry["kind"], entry["name"], entry["path"], entry["line"])
        )
    return result


def protocol_document(entries: list[dict[str, object]]) -> dict[str, object]:
    by_name: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        by_name[str(entry["name"])].append(entry)
    candidates = []
    for name, group in sorted(by_name.items()):
        languages = {str(entry["language"]) for entry in group}
        if languages != {"cpp", "rust"}:
            continue
        candidates.append(
            {
                "name": name,
                "status": "CANDIDATE_ONLY",
                "cpp_values": sorted({str(entry["value"]) for entry in group if entry["language"] == "cpp"}),
                "rust_values": sorted({str(entry["value"]) for entry in group if entry["language"] == "rust"}),
            }
        )
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "semantics": "Raw protocol-sensitive observations; equal names are candidates, not equivalence claims.",
        "entries": entries,
        "cross_language_candidates": candidates,
    }


def rust_module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts)


def markdown_table_cells(line: str) -> list[str]:
    """Split one Markdown table row without splitting pipes in code spans."""

    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    escaped = False
    for character in stripped[1:]:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            continue
        if character == "`":
            in_code = not in_code
            current.append(character)
            continue
        if character == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    if current or not stripped.endswith("|"):
        cells.append("".join(current).strip())
    if cells and not cells[-1]:
        cells.pop()
    return cells


def dependency_fragments(header: str, cell: str) -> list[str]:
    """Return only dependency clauses from a TODO table cell.

    Some board tables dedicate a whole column to dependencies, while newer
    tables combine dependencies, acceptance, evidence, and timestamps.  The
    combined form must be narrowed to explicit ``依赖=...`` clauses so status
    and evidence tokens cannot become graph edges.
    """

    normalized = header.strip().lower()
    mixed = any(
        marker in normalized
        for marker in ("/", "验收", "证据", "evidence", "更新", "acceptance")
    )
    if not mixed:
        return [cell]
    return [match.group("body").strip() for match in DEPENDENCY_LABEL_RE.finditer(cell)]


def todo_dependency_inventory(text: str) -> tuple[set[str], set[tuple[str, str]]]:
    """Extract TODO nodes and true dependency edges from Markdown tables."""

    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()
    headers: list[str] | None = None
    for line in text.splitlines():
        cells = markdown_table_cells(line)
        if not cells:
            headers = None
            continue
        if all(MARKDOWN_SEPARATOR_RE.fullmatch(cell) for cell in cells):
            continue
        first = cells[0].strip().lower()
        if first in {"id", "todo id", "任务 id", "任务id"}:
            headers = cells
            continue
        # Historical rows sometimes append a state note after the leading
        # stable ID.  The ID must still be the first complete code span.
        source_match = TODO_ID_RE.match(cells[0])
        if source_match is None:
            continue
        source = source_match.group("id")
        nodes.add(source)
        if headers is None:
            continue
        for index, header in enumerate(headers):
            if index >= len(cells):
                continue
            normalized = header.lower()
            if "依赖" not in header and "dependenc" not in normalized:
                continue
            for fragment in dependency_fragments(header, cells[index]):
                for match in TODO_ID_RE.finditer(fragment):
                    target = match.group("id")
                    edges.add((source, target))
    unknown = sorted({target for _, target in edges} - nodes)
    if unknown:
        raise ValueError(
            "TODO dependency targets have no stable row (refusing implicit nodes): "
            + ", ".join(unknown)
        )

    adjacency: dict[str, list[str]] = {node: [] for node in nodes}
    for source, target in sorted(edges):
        adjacency[source].append(target)
    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            start = path.index(node)
            cycle = path[start:] + [node]
            raise ValueError("TODO dependency cycle: " + " -> ".join(cycle))
        visiting.add(node)
        path.append(node)
        for target in adjacency[node]:
            visit(target)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(nodes):
        visit(node)
    return nodes, edges


def dependency_dag(root: Path, cpp: Path) -> dict[str, object]:
    rust_paths = sorted((root / "src").rglob("*.rs"))
    module_by_path = {path: rust_module_name(root, path) for path in rust_paths}
    modules = set(module_by_path.values())
    rust_edges: set[tuple[str, str]] = set()
    for path, source in module_by_path.items():
        text = mask_non_code(path.read_text(encoding="utf-8"))
        for match in RUST_CRATE_REF_RE.finditer(text):
            parts = match.group("path").split("::")
            targets = ["::".join(parts[:size]) for size in range(len(parts), 0, -1)]
            target = next((candidate for candidate in targets if candidate in modules), None)
            if target and target != source:
                rust_edges.add((source, target))

    ghidra_edges: set[tuple[str, str]] = set()
    ghidra_nodes = {path.name for path in cpp.glob("*.cc")} | {path.name for path in cpp.glob("*.hh")}
    for path in sorted(cpp.glob("*.cc")) + sorted(cpp.glob("*.hh")):
        for match in CPP_INCLUDE_RE.finditer(path.read_text(encoding="utf-8", errors="replace")):
            target = match.group("name")
            if target in ghidra_nodes and target != path.name:
                ghidra_edges.add((path.name, target))

    todo_nodes, todo_edges = todo_dependency_inventory(
        (root / "docs/TODO_BOARD.md").read_text(encoding="utf-8")
    )
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "rust_modules": sorted(modules),
        "rust_edges": [{"from": source, "to": target} for source, target in sorted(rust_edges)],
        "ghidra_files": sorted(ghidra_nodes),
        "ghidra_include_edges": [
            {"from": source, "to": target} for source, target in sorted(ghidra_edges)
        ],
        "todo_nodes": sorted(todo_nodes),
        "todo_dependency_edges": [
            {"from": source, "to": target} for source, target in sorted(todo_edges)
        ],
    }


def ledger_document(
    root: Path,
    ghidra: list[dict[str, object]],
    rust: list[dict[str, object]],
    ctags_version: str,
    counts: dict[str, int],
    dispositions: dict[str, object] | None = None,
) -> dict[str, object]:
    exact = sum(
        1
        for entry in ghidra
        if any(mapping["kind"] == "exact_definition_start" for mapping in entry["rust_mappings"])
    )
    body = sum(
        1
        for entry in ghidra
        if any(mapping["kind"] == "inside_function_body" for mapping in entry["rust_mappings"])
    )
    definitions = counts["cc_definition"] + counts["hh_definition"]
    declarations = counts["cc_prototype"] + counts["hh_prototype"]
    production = [entry for entry in rust if not entry["is_test"]]
    return {
        "schema": 1,
        "id_scheme": ID_SCHEME,
        "oracle": {
            "tag": "Ghidra_12.0.4_build",
            "commit": ORACLE_COMMIT,
            "cc_file_count": 114,
            "ctags": ctags_version,
        },
        "semantics": {
            "annotation_is_provenance_only": True,
            "default_behavior_status": "UNTESTED",
            "completion_rule": "Only a complete locked-oracle MATCH may change a definition to MATCH.",
        },
        "summary": {
            **counts,
            "behavior_definition_denominator": definitions,
            "declaration_reference_count": declarations,
            "raw_function_records": len(ghidra),
            "ghidra_records_with_exact_rust_mapping": exact,
            "ghidra_records_with_body_reference": body,
            "ghidra_ids_with_guard_disambiguator": sum(
                1 for entry in ghidra if entry.get("id_disambiguator")
            ),
            "rudra_function_records": len(rust),
            "rudra_production_functions": len(production),
            "rudra_test_functions": len(rust) - len(production),
            "rudra_declarations": sum(bool(entry["is_declaration"]) for entry in rust),
            "rudra_glue_functions": sum(entry["annotation_kind"] == "glue" for entry in production),
            "rudra_unresolved_or_missing": sum(
                entry["behavior_status"] == "NO_ORACLE" for entry in production
            ),
        },
        "unmapped_dispositions": dispositions,
        "inputs": {
            "generator_sha256": sha256_file(Path(__file__).resolve()),
            "rust_scanner_sha256": sha256_file(root / "tools/rust_fn_scanner.py"),
        },
        "ghidra_functions": ghidra,
        "rugra_functions": rust,
    }


def markdown_summary(ledger: dict[str, object]) -> str:
    summary = ledger["summary"]
    rows: dict[str, Counter[str]] = defaultdict(Counter)
    for entry in ledger["ghidra_functions"]:
        if entry["entry_kind"] != "definition":
            continue
        mappings = entry["rust_mappings"]
        status = "unmapped"
        if any(mapping["kind"] == "exact_definition_start" for mapping in mappings):
            status = "exact"
        elif any(mapping["kind"] == "inside_function_body" for mapping in mappings):
            status = "body-ref"
        rows[entry["file"]][status] += 1
        rows[entry["file"]]["definitions"] += 1
    lines = [
        "# Generated Ghidra 12.0.4 Function Map",
        "",
        "> Generated by `tools/generate_function_ledger.py`; do not edit by hand.",
        "> An annotation is provenance only. Every behavior status defaults to `UNTESTED`.",
        "",
        f"- Oracle commit: `{ORACLE_COMMIT}`",
        f"- Behavior definition denominator: **{summary['behavior_definition_denominator']}**",
        f"  ({summary['cc_definition']} `.cc` + {summary['hh_definition']} inline `.hh` definitions)",
        f"- Declaration references: {summary['declaration_reference_count']}",
        f"- Raw Ctags function records: {summary['raw_function_records']}",
        f"- Ghidra IDs carrying a guard disambiguator: {summary['ghidra_ids_with_guard_disambiguator']}",
        f"- Rudra functions: {summary['rudra_function_records']}",
        f"  ({summary['rudra_production_functions']} production + {summary['rudra_test_functions']} test)",
        f"- Exact definition-start mappings: {summary['ghidra_records_with_exact_rust_mapping']}",
        f"- Body-line references requiring audit: {summary['ghidra_records_with_body_reference']}",
        "",
        "The old hand-maintained `~2055` denominator is not a completion metric. The generated",
        "9494-definition denominator remains entirely `UNTESTED` unless a locked behavior fixture",
        "records complete same-input/same-output evidence.",
        "",
        "## Definition coverage by oracle file",
        "",
        "| File | Definitions | Exact marker | Body-line marker | Unmapped |",
        "|---|---:|---:|---:|---:|",
    ]
    for file_name in sorted(rows):
        counter = rows[file_name]
        lines.append(
            f"| `{file_name}` | {counter['definitions']} | {counter['exact']} | "
            f"{counter['body-ref']} | {counter['unmapped']} |"
        )
    dispositions = ledger.get("unmapped_dispositions")
    if dispositions:
        family = dispositions["generator_absorbed_family"]
        remaining = dispositions["remaining_pool"]
        classes = dispositions["classes"]
        lines.extend(
            [
                "",
                "## Unmapped dispositions — bison translation units",
                "",
                "Every unmapped definition in `grammar.cc`, `grammar.hh`, `pcodeparse.cc`, and",
                f"`pcodeparse.hh` carries a pinned `unmapped_disposition` "
                f"({dispositions['pool']['definitions']} definitions / "
                f"{dispositions['pool']['loc']} LOC; "
                f"`{Path(str(dispositions['document'])).name}`, ticket "
                f"`{dispositions['ticket']}`). The bison generator family absorbs "
                f"{family['definitions']} definitions "
                f"(yy skeleton {family['yy_skeleton']['definitions']} / "
                f"{family['yy_skeleton']['loc']} LOC + lex-error shim "
                f"{family['lex_error_shim']['definitions']} / "
                f"{family['lex_error_shim']['loc']} LOC); the remaining pool is "
                f"{remaining['definitions']} definitions / {remaining['loc']} LOC. "
                "Disposition is an accounting caliber, never a behavior claim: statuses stay",
                "`UNTESTED`, the grammar face cites the `grammar_parse_face_1204` fixture, and",
                "the p-code face carries `PARSEADJ-PARSEFACE-PCODE-0001`.",
                "",
                "| Disposition class | Definitions | LOC |",
                "|---|---:|---:|",
            ]
        )
        for class_name in sorted(classes):
            entry = classes[class_name]
            lines.append(
                f"| `{class_name}` | {entry['definitions']} | {entry['loc']} |"
            )
    lines.extend(
        [
            "",
            "Machine-readable records, stable IDs, signatures, spans, mapping kinds, and statuses",
            "are in `FUNCTION_LEDGER.json`. Protocol constants and dependency edges are emitted",
            "separately so fixture selection never has to scrape this Markdown table.",
            "",
        ]
    )
    return "\n".join(lines)


# --- Migration: rewrite an existing ledger's ID space into scheme 2 ---


OLD_RUST_ID_PREFIX = "RG-F"
ORDINAL_SUFFIX_RE = re.compile(r"-\d{2}$")


class MigrationHarnessError(RuntimeError):
    """A pinned migration input is unusable (CLI exit 2, never a traceback)."""


# FUNCTION-ID-MIGRATE-REKEY-0001 immutable replay boundary.  These pins name
# git objects rather than mutable paths.  The reconciler additionally checks
# the current worktree's src tree and ledger bytes against the target objects.
REKEY_SOURCE_COMMIT = "235b91bb552261fb3f94b7974926ef6db9b21515"
REKEY_SOURCE_COMMIT_TREE = "6f49b977e46af96c0934114836d457f680caa057"
REKEY_SOURCE_SRC_TREE = "7a9746660c9c569edf1ea922618bcad2ac9860ae"
REKEY_SOURCE_LEDGER_BLOB = "4d06b6c71f84c6bc5f05489b809754fe2b263cbf"
REKEY_TARGET_COMMIT = "8d129628c84eb87f4094b5012833b8970ff21ae9"
REKEY_TARGET_COMMIT_TREE = "5d46f835125307cf7ff83d41274373ec8bb19f45"
REKEY_TARGET_SRC_TREE = "004b20c8ed6da74cf6457a4386570bae4801bc78"
REKEY_TARGET_LEDGER_BLOB = "840bac842767797f62ddf598a6e93574be47d282"
REKEY_SOURCE_MIGRATION_BLOB = "4deb7ee4f17582c508f248b060cf13f7090b475b"
REKEY_FIRST_PARENT_COMMIT_COUNT = 332
REKEY_ORIGIN_COUNT = 24_370
REKEY_LIVE_ORIGIN_COUNT = 24_323
REKEY_GAP_COUNT = 193
REKEY_AUTO_EVENT_COUNT = 135
REKEY_AUTO_LINEAGE_COUNT = 132
REKEY_REVIEWED_SAME_NAME_COUNT = 6
REKEY_REVIEWED_SUCCESSOR_COUNT = 8
REKEY_LIVE_REKEY_LINEAGE_COUNT = 146
REKEY_ALIAS_TOKEN_COUNT = 149
REKEY_TOMBSTONE_COUNT = 47

# Post-baseline scheme-2 continuity boundary.  This is intentionally separate
# from FUNCTION_ID_MIGRATION.json: the latter remains the immutable scheme-1
# origin closure, while this checkpoint records later raw scheme-2 ID changes.
# Checkpoint advanced 2026-08-29 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) from
# 1f3aea4a (10058 Rust records) to the reviewed src tree of 3fb97c11; every
# extension-window transition/tombstone/ephemeral decision below is pinned to
# exact commit/path/blob evidence.  Advanced again the same day to the merge
# commit that folded master's switchcast/varnode-symbol-tail window
# (3fb97c11..05a8bafa src delta replayed through first-parent 65422a62).
# Advanced again 2026-08-30 (REGISTRY-CHECKPOINT-ADVANCE-0001) to the merge
# commit that folded master's nodejoin-F1/anondecl window (10ea407d..e3a9c421
# src delta replayed through first-parent ed3fed6a; merge 0c5091f5): the net
# window effect is exactly three introduced records — action.rs
# nodejoin_join_block_forces_heritage_restructure (96e8e1a8) and debugproto.rs
# ptr_drill_base_name trait+impl pair (e331a5c5) — with zero transitions,
# tombstones, or unproved removals (the 46412358 revert nets out inside the
# window).  Evidence: zero-drift probe + git log -S origin pinning per token.
#
# Fifth extension window, 2026-08-30 (REGISTRY-CHECKPOINT-ADVANCE): branch-line
# anchor merge 42017443 folds master 884208b8 (nodejoin F2-F5 fixes, printc
# INT_NEGATE OpToken order, BlockGoto wrapped-component port, GLOBWORD-C5
# DWARF seed, heritage lattice/INDIRECT endpoint order, x86_lift RIP/EIP
# offsets; 15 src-touching commits).  Window effect at the single merge replay
# step: 31 introduced records (two of them the first-ever enclosing-scope
# disambiguations: coreaction.rs const_vn inside test_nodejoin_execute_runs_
# all_four_steps / test_nodejoin_finddups_gates), one reviewed transition
# (mark_unstructured_target &self -> &mut self with the cc:2859 wrapped
# recursion, a2c5ce26) and one reviewed tombstone (mark_front_leaf_dyn retired;
# its markCopyBlock call site now routes through the pre-existing general
# mark_front_leaf / FlowBlock::getFrontLeaf block.cc:340, a2c5ce26).  The
# tombstone's lineage is post-baseline introduced (RG-F-34c3b946, pinned at
# earlier checkpoints), which schema 1 could not encode: this window bumps the
# continuity document to schema 2 (introduced-origin tombstones carry an
# inline origin block).  Evidence: zero-drift probe (ambiguous=0, collisions=0,
# all rules consumed exactly) + per-token git log -S origin pinning.
# Sixth extension window, 2026-08-30 (REGISTRY-CHECKPOINT-ADVANCE, w-registry7):
# branch-line anchor merge 6fcec613 (first parent 52f5321e) folds 1288e9d4,
# which carries the rc3 printc/prettyprint bundle (db090828..edee039c: whiledo
# body gates, carry-family opFunc CARRY1/SCARRY/SBORROW, oracle-compact
# while( true ) overflow header) plus the httpd determinedbranch lineage
# (484f752c/863c0741/ac03a64c).  Master then advanced past the anchor with
# 48bbdaf1 (artifact regen to the anchor tree), 739aada4 (funcdata synthetic
# block boundaries at no-op jump targets, the FUNCDATA-ZOMBIE-DECISION-ORIGIN
# root-cause fix) and 45cf2962 (docs).  The checkpoint is pinned to 45cf2962
# rather than the anchor itself because the HEAD:src invariant requires the
# pinned checkpoint src tree to equal the worktree src tree, and the mandated
# final tree (merge of master 45cf2962) already contains the zombie fix.
# Window effect across 42017443..45cf2962 (first-parent replay, 9 commits,
# count 415 -> 424): exactly nine introduced records and nothing else —
# six appearing at the 6fcec613 merge replay step (printc.rs
# rpn_operator_name_carry [origin 6b9fc9d8], prettyprint.rs
# pretty_print_overflow_whiledo_header_spaces [origin 8aba975c], coreaction.rs
# test_determinedbranch_removes_not_taken_edge_and_counts and
# test_determinedbranch_skips_malformed_decision_block [origin 863c0741],
# coreaction.rs take_count_delta [origin 484f752c], blockaction.rs
# bs_trace_cfg_sig [origin ac03a64c]) and three at 739aada4 (funcdata.rs
# test_branch_remove_internal_destroys_cbranch_at_two_out,
# test_build_blocks_synthetic_target_creates_block_no_zombie,
# test_build_blocks_external_target_edge_still_dropped).  Zero transitions,
# zero tombstones, zero unproved removals; the 1232 (rc3 fold) + 151 (zombie
# fix) same-ID line shifts are ledger line-field-only because the raw ID
# identity projection excludes line numbers.  Evidence: zero-drift probe
# (ambiguous=0, collisions=0, all reviewed rules consumed exactly) with
# per-token git log -S origin pinning; EXPECTED_INTRODUCED 912 -> 921.
# Seventh extension window, 2026-08-30 (REGISTRY-CHECKPOINT-ADVANCE, w-registry8):
# branch-line anchor merge 2c5bdb30 (first parent 6a45a349) folds master
# 647543ab, which carries the iced-lift flag-pcode overhaul (0c80ad5c,
# 0c2fd80c, 18f88702, a8c56d17, 56f77d1b: add/sub/neg/not flags, logic/cmp/
# test + jcc cc table, sbb/adc carry chains, cmovcc/setcc, pop/movx/cdq
# zero-op arms), the PendingBrace port 642e6156 with its while-break fold
# regression 9d419f3a, the flow overlap-hlt seam (a87d2dbe, c5d6f6d1,
# d8928b41), the merge crossreview diagnostics (8f4ebc29 boundtype cc: line
# drift, 6d7b32a8 MERGE-FAIL/MERGE-PAIR/UNIFY/H-GRET TAGs, afdfcdde direct
# marked= count), the switchb pair (fa6ba1ec aCover/range op-based entries,
# fd589fdd snip_reads INPUT branch pc = block-0 getStart) and the minis
# batch (dd543e5a Rule2Comp2Sub oracle form, 8b2b0f32 get_use_point
# free-leg sentinel fd base - 1, 3a10c583 opUndoPtradd finalize, d251532e
# ActionSetCasts PTRADD/PTRSUB preflight, ad65b957 arithmeticOutputStandard
# family tokens, 13884cc7 castOutput/castInput arms, c6cd3630 setcasts
# tests, 32f44c30 addlflags RUDRA-GLUE annotations).  Unlike the sixth
# window the checkpoint is pinned to the anchor itself: the branch tip was
# already contained in master, so the mandated --no-ff merge tree equals
# master tip and no later commit carries the window src; the HEAD:src
# invariant therefore lands on 2c5bdb30:src directly.  Window effect
# collapsed at the single merge replay step (first-parent 424 -> 428,
# records 10_505 -> 10_574): 69 introduced records, two reviewed
# transitions (varnode.rs get_use_point `_fd` -> `fd` binding re-key with
# the free-leg sentinel change, origin 8b2b0f32; merge.rs
# eliminate_intersect gains `-> usize` marked= count, origin afdfcdde),
# zero tombstones, zero unproved removals.  Three intra-window ephemeral
# IDs (x86_lift.rs emit_addflags/emit_subflags/resolve_alu first forms,
# introduced 0c80ad5c, re-keyed 0c2fd80c) net out inside the window and are
# invisible to the collapsed replay (no rules required).
# EXPECTED_INTRODUCED 921 -> 990; EXPECTED_TRANSITIONS 489 -> 491.
# Evidence: zero-drift probe (ambiguous=0, collisions=0, all reviewed rules
# consumed exactly) with per-token spine scan and git log -S origin pinning
# (69/69 agree at short-hash width; the three re-keyed finals pin their
# name text to 0c80ad5c and their final signatures to 0c2fd80c).
# Eighth extension window, 2026-08-30 (REGISTRY-CHECKPOINT-ADVANCE,
# w-registry9): branch-line anchor merge ac7a3526 (first parent c07e2345)
# folds master 38c3338a, a multi-window batch: the dowhile absorb chain
# (6a7a4609 newBlockList forceOutputNum/forceFalseEdge in try_rule_cat,
# f4c2d017/4d0dcabb fixtures), push88 (6b9d62d3 ia.sinc :PUSH constructors
# + push88 macro in the iced path: lift_push/push_source_val/
# compute_push_src_addr/get_register_64), the stackslot fold root cause
# (3f1883df canonical Architecture attach so spacebase STORE/LOAD reindex),
# the hdefects pair (09b367f5 ActionDoNothing faithful removal chain with
# block_remove_internal/remove_do_nothing_block re-keys and
# block_is_do_nothing/block_unblocked_multi; d4fd9f87 printc emitBlockDoWhile
# body + emitBlockGoto wrapped structural dispatch re-key), canonical arch
# (14be736d Funcdata::new bind + canonical_arch accessor), f23 fixes
# (a986dce4 isOpIdentical typedef-chain strip re-key, 7b99f234 castInput
# two-level double-cast guard) and the W0 postfix-retirement dead-code
# purge (92160892 reconcile_pointer_arith, 68e3ebdc recover_struct_fields_
# anon, f8fe3cb3 struct-deref trio try_convert_ptr_add/rewrite_struct_deref/
# canonicalize_struct_deref, 16e4d8ff brace scaffold, d630ba7b forged
# annotation fixes).  As in the seventh window the checkpoint is pinned to
# the anchor itself: the branch tip c07e2345 was already contained in
# master, so the mandated --no-ff merge tree equals master tip and the
# HEAD:src invariant lands on ac7a3526:src directly.  Window effect
# collapsed at the single merge replay step (first-parent 428 -> 432,
# records 10_574 -> 10_581): 12 introduced records (x86_lift push family
# 6b9d62d3, blockaction force pair 6a7a4609, coreaction donothing pair +
# three tests 09b367f5/a986dce4/7b99f234, funcdata canonical_arch
# 14be736d), four reviewed transitions (coreaction is_op_identical
# typedef-chain re-key 0b58bd56 -> 67f66f09, printc emit_block_goto
# wrapped-dispatch re-key 35f0c0ff -> fd44b0e0, funcdata
# block_remove_internal 680b7aec -> 27e5c680 and remove_do_nothing_block
# dcefd033 -> 259bd077, both re-keyed inside 09b367f5), five reviewed
# tombstones (the W0 prettyprint dead-code purge above), zero unproved
# removals.  Two lineage pairs retire because is_op_identical and
# emit_block_goto already carried trailing-comma aliases from 3fb97c11:
# EXPECTED_TRANSITIONS stores (base, current) so their pairs advance
# (33c86fd1 -> 0b58bd56) => (33c86fd1 -> 67f66f09) and (8fcaf961 ->
# 35f0c0ff) => (8fcaf961 -> fd44b0e0).
# EXPECTED_INTRODUCED 990 -> 1002; EXPECTED_TRANSITIONS 491 -> 493;
# EXPECTED_TOMBSTONES 56 -> 61.
# Evidence: zero-drift probe (ambiguous=0, collisions=0, all reviewed rules
# consumed exactly) with per-token spine scan and git log -S origin pinning
# (12/12 agree at short-hash width; 9/9 removal origins death-pinned by
# spine scan: 09b367f5/a986dce4/d4fd9f87 for the re-keys, 92160892/
# 68e3ebdc/f8fe3cb3 for the tombstones).
# Ninth extension window, 2026-09-26 (REGISTRY-CHECKPOINT-ADVANCE, REGEN lane /
# FMAPRECON-REGEN-0001): branch-line anchor merge 80ffb7d1 (first parent
# b382a54f) folds master e486fb18, the 2026-09 development month between the
# eighth-window fold (38c3338a) and the MERGEBATCH3 wave ledger note: the
# post-interruption salvage, SubfloatFlow (5317299b), the unionresolve package
# waves (dbd06779/c05c1290/a2d81171/83213b78/18b0209b/e94c3640), the
# POSTFIX-RETIRE-0001 W1 stats counters + W2 nine knife cuts, RuleStringStore
# HeapSequence (01879607), varmap NameRecommend recover chain (09bc75fb),
# RETREC ordinal-19 (c1e67b23), BlockMultiGoto/multigoto plumbing (4be34425/
# 91ae3f83/0639babe/cb912769), jumptable matchModel/recoverLabels family
# (c9b4b2cf/e27e9857/05da54b9/b4d73400), value-set solver wiring
# (d626a117/dbd5d89b/99f023f4/0b996bed), FS/GS + shift/mul/div flag lifts
# (f377acda/ea5010e9/53b4e456/0abe6ddb/7fe22b99), drill formatter modules
# (636d2cc4), the ELF PLT thunk symbolize (ec5e3167), the MERGEBATCH lanes
# (VZEXT/CURLE/DIVCHAIN/F8FOR/JTDEST) and the SCOPEBREAK goto-label fix
# (0b067de5).  This window supersedes the unmerged w-registry10 advance
# (7c955a78 folding af678926: 26 introduced, 2 transitions, 4 tombstones)
# whose anchor never reached master; its characterized content is contained
# here (same four POSTFIX-RETIRE W2 cut tombstones, same find_exit/emit_flow_
# basic re-keys) and its commit 7c955a78 stays outside the first-parent chain.
# As in the sixth/seventh/eighth windows the checkpoint is pinned to the
# anchor itself: the branch tip b382a54f is already contained in master, so
# the anchor merge tree equals master tip and the HEAD:src invariant lands on
# 80ffb7d1:src directly.  Window effect collapsed at the single anchor replay
# step (first-parent 432 -> 437 across the four registry-lane housekeeping
# commits plus the anchor, records 10_581 -> 11_007): 119 reviewed
# transitions (117 same-4-key re-keys plus two historical-token reverts that
# close lineage loops by restoring baseline-era raw IDs: debugproto
# void_signature_dwarf_prototype_pins_unknown_model RG-F-407c79f6 reverts the
# 26eee4ad keeps_bound_model rename, printc emit_flow_basic RG-F-a176e923
# reverts the 0b067de5 rustfmt separator), 66 reviewed tombstones (largest
# families: STRNCPY HeapSequence rework 01879607 x10, EXPEL-CORPUS-TABLES
# 430ddb3c x5, typeop fd-aware a2d81171 x5, switch default join cb912769 x5,
# PendingBrace identity e1ee7de6 x5, POSTFIX-RETIRE W2 cuts dc086b58/8b4f2c66/
# 2173be28/f8cae893), 492 introduced-live records across 131 origin commits
# (top: BlockMultiGoto 4be34425 x27, drill modules 636d2cc4 x24, varmap
# NameRecommend 09bc75fb x15, RETREC c1e67b23 x15, ScopeLocal adsorption
# 26ffb3c2 x14, SubfloatFlow 5317299b x14, PLT thunk ec5e3167 x12,
# markLabelBumpUp 03210101 x11, findExit container arm 07678863 x11), 11
# introduced-live deaths, zero unproved removals, zero intra-window ephemeral
# re-keys needing rules.  EXPECTED_INTRODUCED 1002 -> 1483;
# EXPECTED_TRANSITIONS 493 -> 588 (24 pairs advance because their old
# terminals re-key again inside this window); EXPECTED_TOMBSTONES 61 -> 127;
# reviewed transition rules 244 -> 363, tombstone rules 61 -> 127.
# Evidence: zero-drift probe (ambiguous=0, collisions=0, every reviewed rule
# consumed exactly) with per-token git log -S/-G origin pinning plus a
# 430-commit first-parent spine scan for the six separator/reflow re-keys
# invisible to pickaxe (492/492 introduced, 119/119 transitions, 66/66
# tombstones pinned; the unmerged w-registry10 characterization cross-agrees
# on every overlapping item).
CONTINUITY_CHECKPOINT_COMMIT = "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"
CONTINUITY_CHECKPOINT_COMMIT_TREE = "7bcda539b26d06d682f4678686b1de67820cf767"
CONTINUITY_CHECKPOINT_SRC_TREE = "4d47cf92b618eac87975dfa707bd6a20c13fc76d"
CONTINUITY_CHECKPOINT_PARENT = "b382a54f340186665cb3c97d3af01ec3d770d814"
CONTINUITY_BASELINE_MIGRATION_BLOB = "8ecab1e6160b7d4d28a15aba0cad89c2fe8fc171"
CONTINUITY_BASELINE_MIGRATION_SHA256 = (
    "16236201f0b4920d2a3e33a848df05d3d601ee60998f7f7c51464d4eeb7739e9"
)
CONTINUITY_FIRST_PARENT_COMMIT_COUNT = 437
CONTINUITY_FIRST_COMMIT = "7ae30f5bcfba5e1adce2a4e8cdeebc23d96964cb"
CONTINUITY_BASELINE_RUST_RECORDS = 9_639
CONTINUITY_CHECKPOINT_RUST_RECORDS = 11_007
CONTINUITY_EXPECTED_TRANSITIONS = {
    ("RG-F-003416535aaee2f83d44", "RG-F-81062ccc03179475b483"),
    ("RG-F-00572f8089ee0282e3c8", "RG-F-6916029914151d2db6eb"),
    ("RG-F-008eae3b0ba4d12666a2", "RG-F-0eb47d4f14a0f355f3e8"),
    ("RG-F-014e421b9237134489e2", "RG-F-a0058e4a4e7ff0e25ce6"),
    ("RG-F-025f5fca8290ce0dd217", "RG-F-d21dc52d46b8f7c84e9a"),
    ("RG-F-02af378dcb9608ea64b2", "RG-F-33e95afa7889a0820812"),
    ("RG-F-02b973adc674e2dafcca", "RG-F-818e9e9dd2f555e6186c"),
    ("RG-F-02e4be08c92e34abfe47", "RG-F-22ed1eb12bc5abac17fe"),
    ("RG-F-03d5a60e3d01149041f7", "RG-F-9433b41c58ad43fdc6d4"),
    ("RG-F-04719b658523b82375be", "RG-F-9ae05b2bec51d673d26f"),
    ("RG-F-04ce7405b808e773488d", "RG-F-01394a9c89d7021557c4"),
    ("RG-F-04f44a232e7a634ff9e2", "RG-F-7a062e2cfb1b7594aec8"),
    ("RG-F-0566330cb210c4865002", "RG-F-fe107f6bac1013c9e1cd"),
    ("RG-F-06f245fe0aa91d078cad", "RG-F-d37d33eb864bbbb07f51"),
    ("RG-F-0746077b8faf709f4115", "RG-F-1e70a0af95480224f97e"),
    ("RG-F-07af6068109e9df13299", "RG-F-703d8e7abf31c32580a1"),
    ("RG-F-07c891e8ebed22a614bf", "RG-F-073da449723cb9f5d314"),
    ("RG-F-085c02d6f39c4639fb36", "RG-F-6fd5b910459f46619697"),
    ("RG-F-092e589b0fcbeef86f82", "RG-F-0d3c66e5656471ce3631"),
    ("RG-F-096cf82d192f9fb97a26", "RG-F-4c52a144995488a034b3"),
    ("RG-F-098edc738e5a43908809", "RG-F-b6bfd7d98562fbfd99d7"),
    ("RG-F-09d0ffc3ccbb554e789c", "RG-F-cd924c7bc3e50d8e6a9b"),
    ("RG-F-0a8a5f4c9320af37114a", "RG-F-2cf6bd977285eb0e278e"),
    ("RG-F-0ab856c8630502fa90bd", "RG-F-4be434b812b72af0df30"),
    ("RG-F-0b4cdff982c9cdb86c11", "RG-F-24ee661dbc4a83cadbdf"),
    ("RG-F-0b65260ce004a84337c9", "RG-F-98082c2ff9434b0485d1"),
    ("RG-F-0c9b722a5e2a1f5950bb", "RG-F-1e3090fe8bc992c441dc"),
    ("RG-F-0d8b13a396b10708badb", "RG-F-0c02c845fb562e683bf6"),
    ("RG-F-0dae6323773b6d73f891", "RG-F-35ffd25821dd403c0ce0"),
    ("RG-F-0dbef8d4c630c37f0f20", "RG-F-10bd03523f37860dd01b"),
    ("RG-F-0df2d06c62d030e3aee1", "RG-F-f61cd3727162105b42cf"),
    ("RG-F-0e57c9f536067337d286", "RG-F-5d4cb90317ed3e77a0b1"),
    ("RG-F-0e84d5343bedbed4f403", "RG-F-a6aab626acbdf0773375"),
    ("RG-F-0f1e2055dd75ad3ab3a3", "RG-F-fddd3775df982bee7359"),
    ("RG-F-0f440fb28a621f11a2e5", "RG-F-506fcb9f9b16958229e0"),
    ("RG-F-0facc525130f063a1867", "RG-F-01f9f559bd7edc377058"),
    ("RG-F-104e7177e37c491be519", "RG-F-4fcc20c778fd1c00a6e5"),
    ("RG-F-10d4a7460bde7271db1f", "RG-F-06691be42e207b9291d4"),
    ("RG-F-11a5ff425fc4c01b4da8", "RG-F-bfadcbc9981a3a281fff"),
    ("RG-F-11e62348309dc8b5f729", "RG-F-abecc777f3b9071054ea"),
    ("RG-F-12a1ac7520a2936215cc", "RG-F-dc31cc79ae927e192ee1"),
    ("RG-F-12d6470ee45b74a19780", "RG-F-3bcea05e49a9bcd80cc5"),
    ("RG-F-13b326553ae8f9898f77", "RG-F-c43098d7d6918b6b28b5"),
    ("RG-F-13da39415f2306101dce", "RG-F-9517435a8e95934f7bbd"),
    ("RG-F-140645eda9c6178626bb", "RG-F-d336771e87bc3eea28e2"),
    ("RG-F-1422cc4b4789d56e3b74", "RG-F-373190ebec7e0e9285a4"),
    ("RG-F-1500b403d31dc09fa484", "RG-F-77e3f1c39c224a8fb08d"),
    ("RG-F-1696a469c1e4f234a381", "RG-F-0725ce4eafd7506761ce"),
    ("RG-F-16aa2a5efa10c7458c99", "RG-F-d55f52db76766c496c96"),
    ("RG-F-17bb69ec3f3581840c9f", "RG-F-8d0b0408847a76fc710a"),
    ("RG-F-17ef2d9d23d6d220f407", "RG-F-343f5a5b111fa2a66a95"),
    ("RG-F-1819687d557b4ed9c7e6", "RG-F-bb4190ff2d34e3ba0401"),
    ("RG-F-183a83727d39b25f669d", "RG-F-0f8fe610df74d4044b50"),
    ("RG-F-1847710578ba36f41a2c", "RG-F-fdec08b5119c673abb6c"),
    ("RG-F-18770556d1ec3727b61f", "RG-F-063a91bacb8e9ce82632"),
    ("RG-F-18ba40084ce92497ea12", "RG-F-8f738757220bf0bf6a41"),
    ("RG-F-190434e2b136253e7cf8", "RG-F-f937b633d5a6319d9b19"),
    ("RG-F-1a0435a14acc3aa3522b", "RG-F-f2222bbb6aa727fbb4d8"),
    ("RG-F-1a0de177364519004226", "RG-F-d217c0a3cdc7581a6a87"),
    ("RG-F-1a31e6c2b34252958c71", "RG-F-051d6dc01af5e493d722"),
    ("RG-F-1a6ab365231163a9d855", "RG-F-99af3a4c99a40a29079c"),
    ("RG-F-1aa360a6b042f0ba1e34", "RG-F-815fafdb87ad801e093a"),
    ("RG-F-1ab6f35e176e1adb2059", "RG-F-591a6de44d0bf0b8937a"),
    ("RG-F-1abb54f08c25ca5d0b2d", "RG-F-37b3c7f9009da2eac5dd"),
    ("RG-F-1b1d42d39302829f8e72", "RG-F-dc54176d68b572318a13"),
    ("RG-F-1b84fa71d5415f6c65e0", "RG-F-a36d0f21c07b134850b6"),
    ("RG-F-1e379133c5e93eb237e8", "RG-F-3cbd3b212adf5233023c"),
    ("RG-F-1f2b2566bda5b027ace1", "RG-F-a55f5e4d885019044dea"),
    ("RG-F-1f849ee11eb26abd452d", "RG-F-4f3e7eb760d8b1679217"),
    ("RG-F-1f9c977e2c885a2fcd1c", "RG-F-9e8d3ad4aa0167ab2793"),
    ("RG-F-2030541ea9b02a722a22", "RG-F-6fe47f3146f53627e732"),
    ("RG-F-208f18dc3bc2543b44b9", "RG-F-bdbde6f78df46af9dd05"),
    ("RG-F-217fc3a00aafa7219757", "RG-F-b71eb3c75f98f34d6804"),
    ("RG-F-21b48af872dd34850d90", "RG-F-c3aa409fa748b4da709a"),
    ("RG-F-21f9a0c8b5fd1e81b17f", "RG-F-677b01d48051e870bbd4"),
    ("RG-F-224286367b10e73e2221", "RG-F-d13be972489a12b30e0d"),
    ("RG-F-2282417c93d08f203cd9", "RG-F-5c1a94676a8a8172bfdd"),
    ("RG-F-22aafcc017427cf69c66", "RG-F-fd6c2f138f07d6a434c2"),
    ("RG-F-22c46fc05bddb2d4345b", "RG-F-766b5e4ed8fc866214d8"),
    ("RG-F-23a895ea5f61f952f461", "RG-F-e6b3127a82181285b431"),
    ("RG-F-23cf63793beda221308d", "RG-F-1816889143e3beb44458"),
    ("RG-F-24364fbcca97705e6585", "RG-F-1dd7a348a0462e68228e"),
    ("RG-F-2475c99307254aa5a543", "RG-F-db506a6e32389d44cf8d"),
    ("RG-F-24db94981a0293b2e2b5", "RG-F-25ed035b36f7473c2032"),
    ("RG-F-24f186531946104c862a", "RG-F-bbda0b7433deea952b24"),
    ("RG-F-2642a89b925f1de36e09", "RG-F-af8092285f474721e59d"),
    ("RG-F-2646dcd008a8290bb207", "RG-F-977e74c702d9c9d318ba"),
    ("RG-F-2723244b1664e2c12a1c", "RG-F-ba30411e7974455ce7c2"),
    ("RG-F-273e39542f5211caf365", "RG-F-7b9617242d96a3bd3335"),
    ("RG-F-2835c96bb378a92f97e6", "RG-F-534675b041b9cad59baa"),
    ("RG-F-2837daddc938af793d3c", "RG-F-8015705770472a5fdead"),
    ("RG-F-2860cbdf7b0a4edd4844", "RG-F-165e0b2552156a96c8fd"),
    ("RG-F-2889a92a8025b2977238", "RG-F-967f9662a16ef15dd43b"),
    ("RG-F-293a5a0812a002b4c7c0", "RG-F-1fb8be36fc1e2b1b5b00"),
    ("RG-F-29b64f515e2cc6b8a2d7", "RG-F-55f51939bbaf977e476c"),
    ("RG-F-29e4041fe2b6394c6713", "RG-F-0ea3959fe7dcd6358737"),
    ("RG-F-29f1bd831bde716de5c4", "RG-F-813b027ebcd5353c4236"),
    ("RG-F-2b4ab74cff7d2f97b18b", "RG-F-d5cd0c131fdd09cf6d6c"),
    ("RG-F-2c8bc5541245d8b6fec5", "RG-F-3bb2edeafbf9ec2e3fef"),
    ("RG-F-2c988c04aca0f061a836", "RG-F-8ba6690d9b3d452c451e"),
    ("RG-F-2cae510ca54daac7111b", "RG-F-c411e51718b87c2f2bd5"),
    ("RG-F-2d1a5cee1611f71e97b7", "RG-F-ea94c3487a8e7c4d2e3d"),
    ("RG-F-2d4e177f5009fc1d464d", "RG-F-ef5b143c7b8bd3efb3a6"),
    ("RG-F-2de92d72d9fdbccc7507", "RG-F-630ddcebbfe93b0e818c"),
    ("RG-F-2e96dea7b92ff0ef2a96", "RG-F-4275c5418379b85fb462"),
    ("RG-F-2ff0c0b1db0b04d9f173", "RG-F-b3290e09e1924693811b"),
    ("RG-F-2ffe7f84827bd91a7a70", "RG-F-bd915990f843b42dcec3"),
    ("RG-F-30425150c9566c0704d7", "RG-F-3cdc78584c04aa4c8506"),
    ("RG-F-3156a5367272b2a9b2b5", "RG-F-24b44d69ff0ec854f19c"),
    ("RG-F-3175e312a1638de63b65", "RG-F-cc2efb8ee4aead475a92"),
    ("RG-F-324512e30e8186d490fa", "RG-F-965186488164bcc5ab4f"),
    ("RG-F-32b69c55e48850549780", "RG-F-914ebd32697eb67d4df6"),
    ("RG-F-332dc229f8ca31752d6f", "RG-F-88e669e7fc3b4d59eec8"),
    ("RG-F-33c86fd1b415d82ce820", "RG-F-67f66f09decf8c2d0193"),
    ("RG-F-348bcf1129d00810889e", "RG-F-878f03cc15c53f8e9887"),
    ("RG-F-350bfd7ce36aafc87bc5", "RG-F-df24ec62e96f58098106"),
    ("RG-F-353d179342f1b8c88e5b", "RG-F-4fc23f9164942392a358"),
    ("RG-F-35baebabf6c4256404cd", "RG-F-0a4de5fd7646c766b94b"),
    ("RG-F-35caa9e455d7c3452c64", "RG-F-00bc5c5c59d8e247f17e"),
    ("RG-F-368f07c936246d7f38ca", "RG-F-cc4e217c1badd4960228"),
    ("RG-F-36ca824e6db9a673db96", "RG-F-1c297303ec4b0839dc87"),
    ("RG-F-371e85ad2b3c3d326dc0", "RG-F-522719ade416e1e6b521"),
    ("RG-F-373b5a01aeab84ff971b", "RG-F-b4b5399e2a9ff2e26129"),
    ("RG-F-37f3180c79895c67390c", "RG-F-f1aebd4d5e1c7b8f7825"),
    ("RG-F-3814aca9f7db808e8d20", "RG-F-f65ccde3fa36e11c55c7"),
    ("RG-F-3840b2aa55741a564b42", "RG-F-b8ad1086fc47b0b0e8f8"),
    ("RG-F-397f3a04435071b934e3", "RG-F-1177cbf9d9ec8b6b4878"),
    ("RG-F-39e123daf5f57401f23b", "RG-F-e2da956f10d8f38b8bfd"),
    ("RG-F-39fe2822c979b62f2ff8", "RG-F-bf27faa8da20efb7b41c"),
    ("RG-F-3a923bfee6882417fc96", "RG-F-2a34c9f6095ee64fb93b"),
    ("RG-F-3aae0be2241ef765314f", "RG-F-2160ffb27d9d6b5a7f8d"),
    ("RG-F-3ba0a78d6820c7784fb0", "RG-F-586cf6bb5285be51173c"),
    ("RG-F-3d75e8fa19d4a99c7495", "RG-F-3ace5a7777a4d45ac533"),
    ("RG-F-3d7c8b325c1bd4b86a95", "RG-F-435eff3576c30dbe684c"),
    ("RG-F-3d8642a6bd61e196fae6", "RG-F-18743618f85614374e05"),
    ("RG-F-3dc7c42e2821d00cea8a", "RG-F-a02dabc4695772d39068"),
    ("RG-F-3dd8a09502c79e668db5", "RG-F-6366ebc7c4d1ef5e164b"),
    ("RG-F-3dde2c94bf8d902d5057", "RG-F-bc69c26bf6c937ea608a"),
    ("RG-F-3ded1b49dfe4d85957dc", "RG-F-632a961a57699fdc0fec"),
    ("RG-F-3e66d67cb11e74edd45a", "RG-F-67932873029bfd4f49e9"),
    ("RG-F-3f0ed0181172cb6adba5", "RG-F-4962edf42e1a26835b05"),
    ("RG-F-3f54231b0de2609dc1e5", "RG-F-3f316f0a983f0169c0f8"),
    ("RG-F-3f8506cdc116cdbcd4af", "RG-F-a8f4359f807b44837726"),
    ("RG-F-4027c78009584d7abc4e", "RG-F-fc60561a535493ba5d27"),
    ("RG-F-403c62b545e4c4c6862a", "RG-F-d767ef0840705c775605"),
    ("RG-F-407c79f6fb505c89bd8b", "RG-F-407c79f6fb505c89bd8b"),
    ("RG-F-4095c525bd79c6a1e9d5", "RG-F-5e4a2aed945a92a3544f"),
    ("RG-F-413c169efcdfd7e18940", "RG-F-b30adb3ed2e6f7a8e928"),
    ("RG-F-418f3036e9876a352e13", "RG-F-e2bffedfda38a0041452"),
    ("RG-F-41e0b9eeff3dd39c08a9", "RG-F-ebf5e55e9e9e90c6fdce"),
    ("RG-F-41f64260f48f0ecc9ce1", "RG-F-0ae09e97f158088ac2d3"),
    ("RG-F-420b7f1781eaae99bb0c", "RG-F-da6d2d3c6a3a39b28deb"),
    ("RG-F-4269e256e1890ee9c4fd", "RG-F-d529f1aba80316f7645c"),
    ("RG-F-427fb6d649f3e79ceb1d", "RG-F-100a0ebc98f73bdc511e"),
    ("RG-F-432ce7cf0610470a7b2c", "RG-F-851579adad728df7237c"),
    ("RG-F-43b327826f8b7d1a8a5f", "RG-F-4bcb3564a2d811b04567"),
    ("RG-F-4419c7711d1b266e00dd", "RG-F-80e27db92dcee96864bf"),
    ("RG-F-44fcf9a5c35080fabaf4", "RG-F-d14405de53b00443943d"),
    ("RG-F-4519b750d13bed433120", "RG-F-7ab0b03534ee5b2ef25c"),
    ("RG-F-45324feb85f0fe2be5a9", "RG-F-d6766501e16b7fea4fc8"),
    ("RG-F-45d25c0eb3e56e0ece17", "RG-F-940c93f88545d0a9a335"),
    ("RG-F-4616eac5c78178841108", "RG-F-f41724e55935a7f3da26"),
    ("RG-F-46320ffdcfa9ca2fd7a0", "RG-F-2c4bd41eee303832ea34"),
    ("RG-F-464977f6d3fb106a54b4", "RG-F-d91e1a7f53283fc2d9a9"),
    ("RG-F-46555960b50ff8a7af36", "RG-F-677424a69f8543c266ce"),
    ("RG-F-46f2bdbe22d5abfead52", "RG-F-72f1c0a89849a4fd2a65"),
    ("RG-F-471897415751e5d275d8", "RG-F-dde1a3ccdb9db5f6d490"),
    ("RG-F-47b1ea6105135f403568", "RG-F-274fc5bff7d3dfd55610"),
    ("RG-F-47d6a10f1254fe28ce2b", "RG-F-521003ba33641ecfd0f4"),
    ("RG-F-47f2bc0adc94feb28032", "RG-F-47d286a975ef1afcb494"),
    ("RG-F-484ed51a1834115a3a27", "RG-F-c5d4b0a7203f6792e696"),
    ("RG-F-48cac975d49aaa45fbc4", "RG-F-8fdef7ef5f62224b9392"),
    ("RG-F-48cebeae7b1f1b743e6f", "RG-F-328f0cee2b4153e006ab"),
    ("RG-F-48d8c1f6b4ebb4c1b052", "RG-F-0cf75b414e5cc24cc605"),
    ("RG-F-48fe6c8f93b446cab259", "RG-F-a77b988ff57bb863572b"),
    ("RG-F-49047a901b0905807ad4", "RG-F-e24c59a91e3095bd3774"),
    ("RG-F-4954fcae08dcd39b8e0a", "RG-F-52ba298f3f784d2078a5"),
    ("RG-F-4985b73f8e9c7a934f29", "RG-F-417a59ddbd5d1fc6c5dd"),
    ("RG-F-49a45b403b54963f863b", "RG-F-f29006cf772e07b95741"),
    ("RG-F-4ac684c61c5ad61c28da", "RG-F-42670b35e88c1e5832f8"),
    ("RG-F-4bed19d4a1d8e9c57367", "RG-F-3ee35d5df418351c987a"),
    ("RG-F-4c8cb470054a31b803d9", "RG-F-69d80ecebe6b9daee3ca"),
    ("RG-F-4cdd5bd19c95d3404ef9", "RG-F-e2b08074d7ef80d46a19"),
    ("RG-F-4cebbe80d33d76389015", "RG-F-b8398d937fc990bf2792"),
    ("RG-F-4dbfce48ee7489688bdf", "RG-F-40118e533e4151c718aa"),
    ("RG-F-4dffb2ed510f8cb9b14b", "RG-F-b011bf03cc992c741479"),
    ("RG-F-4e99381ad31c66523ecd", "RG-F-1423a948a3f514db88d2"),
    ("RG-F-4e9f597e3cbe737fd971", "RG-F-7145804dcf3c378fbd8d"),
    ("RG-F-4f1a95506fbd0a64ce1b", "RG-F-56d64d9193b7a4a3ff6c"),
    ("RG-F-4f5c3734d8040f27a454", "RG-F-b31db2dd8ac3344bd391"),
    ("RG-F-4f99310a1c165683a602", "RG-F-5d6711661d9a6faf6856"),
    ("RG-F-4fb1c4fb4918bd11f593", "RG-F-d04d21815f77968bea7d"),
    ("RG-F-503a03cb217c238099fb", "RG-F-a7d1311516103ceec64f"),
    ("RG-F-50e19643061ea49964e1", "RG-F-3f297b3c5df156cf268a"),
    ("RG-F-5127056353d49f4f310b", "RG-F-63f3f21a402497b4e638"),
    ("RG-F-51aa66bc4efbef5ce41c", "RG-F-68b7284fc2778ca40e41"),
    ("RG-F-51ab5a52438e17af10e4", "RG-F-46ea1d992f354714f304"),
    ("RG-F-520116e1c5cf96491238", "RG-F-2e5da275cf751c87ed56"),
    ("RG-F-5227b5f226119b369a5b", "RG-F-dc674a02bc57fbe9a94a"),
    ("RG-F-530b119efe0002da1433", "RG-F-453b9a3802470f457c69"),
    ("RG-F-53c7b72564db22db08d3", "RG-F-f1d085b75606d91b2c03"),
    ("RG-F-53d171f3bfd9713df232", "RG-F-3104bf41dea30e902230"),
    ("RG-F-5475712bde2bf73eaa25", "RG-F-528ac70644e0158b6017"),
    ("RG-F-54c2084809079c0db1b4", "RG-F-cec50911a394b1916765"),
    ("RG-F-54e1fd06697d149e306b", "RG-F-c06352489dc706be65ab"),
    ("RG-F-54eb3f3a336984773dcd", "RG-F-88d169a5e0e90393f739"),
    ("RG-F-554763b0033e681da0d2", "RG-F-4220d57440c20d97e93b"),
    ("RG-F-559415c4abcda31d7dcf", "RG-F-6480e326b0fc7be84b3c"),
    ("RG-F-55e8785cf6c756440521", "RG-F-c1d047496cda7d91d86b"),
    ("RG-F-56aa5a2cb39adcdaa0e7", "RG-F-665caf5de788197a7ddb"),
    ("RG-F-56e2c07586c6362bfa42", "RG-F-da4d300bfe1bb0faec44"),
    ("RG-F-5769dd71cbf54d6f40dc", "RG-F-993a5e957e53c20ab7aa"),
    ("RG-F-5832a5a5ba7c6b24413e", "RG-F-03c634cfdc51443226c2"),
    ("RG-F-5833ec87d885664efa5f", "RG-F-85943640e89de9a361c8"),
    ("RG-F-5923eb2467cb55ffa55f", "RG-F-7f644254abac1693b1ff"),
    ("RG-F-599925663bf4d9151f1b", "RG-F-c40817108c16ed8cd523"),
    ("RG-F-59a3a5731573081b334f", "RG-F-e10b314f1c23d10fa36f"),
    ("RG-F-5a6f72a011a7067ff257", "RG-F-23a1e820b90c22cdc8e3"),
    ("RG-F-5acc1fe44524378a2993", "RG-F-a2248f3edeaad9a38159"),
    ("RG-F-5b842bec1b80d6108a87", "RG-F-560b3902b8696bea6cf0"),
    ("RG-F-5b884c90f4650cb85895", "RG-F-59926f42e76a1316cad6"),
    ("RG-F-5be66959a615062d55ad", "RG-F-45b71e75539b0f882800"),
    ("RG-F-5c2e14141945d5333422", "RG-F-3c0cf7164ca1fbaa4a53"),
    ("RG-F-5c67bfa2b4dafad127e9", "RG-F-55b083f921edad907204"),
    ("RG-F-5c6e179e4c791a950842", "RG-F-c78c8d04310be0774374"),
    ("RG-F-5c7416bdda895a05a58d", "RG-F-934782810e98ad817d27"),
    ("RG-F-5da2232cfccfbc48236b", "RG-F-147b2914b0460c3b7e89"),
    ("RG-F-5e80c406760f953c226e", "RG-F-41da9fc52fbb9f9e34cd"),
    ("RG-F-5fe9abb973fdb2e82999", "RG-F-8f2c902693e85f979324"),
    ("RG-F-60ed08ef419968c52ca7", "RG-F-9f116c4d0c2f40e47057"),
    ("RG-F-614df5b0ab663eee9561", "RG-F-943c9ffce54566a72c11"),
    ("RG-F-61c59823904724004cc7", "RG-F-9b7b70521d92ab540492"),
    ("RG-F-61ecbd977af055b28e95", "RG-F-4ef3e2cd56f01e5b84c3"),
    ("RG-F-62c0cf8ffb3794618287", "RG-F-9b1995ef16a44eef814f"),
    ("RG-F-62f8a8c73f70a420aa11", "RG-F-292e381983ba98dfd9c0"),
    ("RG-F-631999f3a57799cd3ce3", "RG-F-2a1c4c6151d8d8414480"),
    ("RG-F-6321663d15099e9cdffc", "RG-F-7521f4be200a2a2a5ba1"),
    ("RG-F-636713cd718416eda469", "RG-F-3f1bd88d4b4e89d8f38f"),
    ("RG-F-63d638ee9488d59148eb", "RG-F-4485e36f3c842c19985a"),
    ("RG-F-642475c83941e8195622", "RG-F-b806aaff7510b1daade8"),
    ("RG-F-64f5c422e9b306ad0486", "RG-F-4e73bb88f947f5cbd811"),
    ("RG-F-657993bd9ae7c40f453c", "RG-F-bc367e56a6c33dd53e16"),
    ("RG-F-65e60494e6abb3224e3a", "RG-F-8775a30a0efcbe76c4bb"),
    ("RG-F-660098de7b5be80202a6", "RG-F-382d3324bcde3d89f736"),
    ("RG-F-664cdbe7f00113f64327", "RG-F-23ff4924c25b1bbdf96d"),
    ("RG-F-665e889efe29adc78c07", "RG-F-08f7654728d229dc7238"),
    ("RG-F-6665054cc12a39bea8a7", "RG-F-85a2695399c05e09116d"),
    ("RG-F-677d167932e38cfd8059", "RG-F-6b77b0a1166c681a2da7"),
    ("RG-F-67827efc2b3b4d4016b9", "RG-F-3cd23de12de85f61b589"),
    ("RG-F-680b7aec490d30d27e54", "RG-F-27e5c680f9d99fdeadee"),
    ("RG-F-681b63f29b27de3a4123", "RG-F-b0bd0fd9650c8dc041d9"),
    ("RG-F-6875a1df88043187e59d", "RG-F-aeed1ce92fc04c5aaf17"),
    ("RG-F-69077eff0f6c6d312b89", "RG-F-63703e43769647a36512"),
    ("RG-F-69082e1a1446056c0929", "RG-F-2e0f624c8f20e1cad172"),
    ("RG-F-692f60ebcfc4f7c2b57f", "RG-F-b2e6d53a6de0b5590d13"),
    ("RG-F-69e8d03507ac3b1ebe30", "RG-F-486673c37eac41c29160"),
    ("RG-F-6a422bdc9f26aad48fad", "RG-F-d548b0dad163f4e73bb7"),
    ("RG-F-6aa2e7432f77cda70d02", "RG-F-ecbc4c18cf6c99ce34cc"),
    ("RG-F-6b40dae6130206b79953", "RG-F-1fab32158a172b256fad"),
    ("RG-F-6b8e37da55f6ecc8eb92", "RG-F-fa40cb3136b396e182a8"),
    ("RG-F-6bc453b29b6e1f28d16b", "RG-F-94cae4a0681c4444a3eb"),
    ("RG-F-6c631a0b96eb8cfbf084", "RG-F-e43755a77bd2c83617aa"),
    ("RG-F-6c712f998590fc4f4ea4", "RG-F-81f070e989979d3d4ead"),
    ("RG-F-6cda2f7c91a4cf0724af", "RG-F-b1b189aa63cb14f8e1c1"),
    ("RG-F-6d89816a873eebe5ad7c", "RG-F-1db06938d3ac9874cf91"),
    ("RG-F-6d8be805614592440f51", "RG-F-9da23290d55207396763"),
    ("RG-F-6dfcaab8801850cd610e", "RG-F-0e6b6cd02690de61c6ba"),
    ("RG-F-6e051e8535ea7b93c378", "RG-F-6b9c714aa4edbd3bd260"),
    ("RG-F-6e9e5fc5dff33182265c", "RG-F-60ce0f7505bfbf56fd42"),
    ("RG-F-6ee3ee8b5557dec99e2c", "RG-F-d5aeb202ea5d4c9c70be"),
    ("RG-F-6f12e6842f728524255d", "RG-F-b58fc8ff4f266ffbf162"),
    ("RG-F-6f4859390b5a5e828d0e", "RG-F-34705a0e8846212e03e0"),
    ("RG-F-6f57a74143457c1e6f5d", "RG-F-c0396163cb5428d9eb7d"),
    ("RG-F-6f6a818a4e632357b615", "RG-F-0345c93508ad882e10c3"),
    ("RG-F-6faca00e16168f0d41ef", "RG-F-e9a648e8c1f60e0e96fa"),
    ("RG-F-7073a637b916fa4ad621", "RG-F-fdb464888cf52ff37017"),
    ("RG-F-707607c0ca8d05f5df1c", "RG-F-a5f90e34e3533781488b"),
    ("RG-F-71aaf4c2c8a8f3873677", "RG-F-e00b5a6860924846eeb8"),
    ("RG-F-720419b442383baf0802", "RG-F-7f2c84d23dd5d3df2828"),
    ("RG-F-72110be65453cf3d1587", "RG-F-49837dd5483eee6ce607"),
    ("RG-F-735b0cbbed34f53e7b56", "RG-F-94e982a429b78d3256c0"),
    ("RG-F-73f78dcee4467e087cd2", "RG-F-1eb0987634d9064bb18a"),
    ("RG-F-74239bf8f5f8e8e31fc7", "RG-F-079b0a68815cef04e6b9"),
    ("RG-F-7472347f6d20c447c6ef", "RG-F-4eb112e335ddc8f1c3b5"),
    ("RG-F-74b857e527c0bb3a964c", "RG-F-054c4ff7718a72e1fe10"),
    ("RG-F-74cbc539f032efd2cb86", "RG-F-dc35c1cce8a2425d4747"),
    ("RG-F-74fb94456502ba673e4e", "RG-F-9b888a53e7004d1c5065"),
    ("RG-F-758670c73687373915f3", "RG-F-9b8a3c53c53b21af7164"),
    ("RG-F-7622630fcd5425152c42", "RG-F-87ecf60944cd017f0272"),
    ("RG-F-762a4c4caa2013c3835a", "RG-F-78b3f4e9819b44d98587"),
    ("RG-F-76437d6700295a7f2295", "RG-F-93421285b1d5b2a0fadb"),
    ("RG-F-76c63196d7e6b6395e4b", "RG-F-2052a82c109bea8a5b43"),
    ("RG-F-76cb2507806aee1865ff", "RG-F-6ed05bdd14b09896f864"),
    ("RG-F-77adb336f064e67308a6", "RG-F-e659f766cf51c63bdac0"),
    ("RG-F-782b5bf849af80f65d5c", "RG-F-5923943cda2aaa09d13d"),
    ("RG-F-78ccc92c113f69e92c6c", "RG-F-64582aa32b11c8400313"),
    ("RG-F-78d6138fc67e2a7b6cb2", "RG-F-6e765bdbf79a52255fc0"),
    ("RG-F-78f6c10072ae947b9b26", "RG-F-29239adf25ac56679a79"),
    ("RG-F-79d038a2d96aed2ff6fa", "RG-F-fb8802bcf98b8c9cf182"),
    ("RG-F-7a9724a583fb0aad16fa", "RG-F-da013bcda528bcaacdcd"),
    ("RG-F-7ae28678d2befca75e98", "RG-F-931203dadda55196eaaf"),
    ("RG-F-7b42a19d25b9c808f4c1", "RG-F-27773d602fa8cb0dbbef"),
    ("RG-F-7bb0e8877a320e3beb77", "RG-F-caabc4f584b95b2912ea"),
    ("RG-F-7bb1826a9a24ff75f90d", "RG-F-135975b0c3b697afb894"),
    ("RG-F-7beafac2b7964f1a7a69", "RG-F-117e8317c74b88097687"),
    ("RG-F-7c1d546d131826f1a24e", "RG-F-3dfefc81f282efb451a4"),
    ("RG-F-7c2c3c44b0d8066003c1", "RG-F-22fa5e957ee993f7e93e"),
    ("RG-F-7c5932644e877daca86f", "RG-F-687e0eee77e05580bac1"),
    ("RG-F-7cb40678e03e0199f4bf", "RG-F-80050f314d2fe50522bc"),
    ("RG-F-7d0daadf4cad7c7129f9", "RG-F-d5debe25be69298d4889"),
    ("RG-F-7d3ec36cb92d748b7de3", "RG-F-13f03568eb3480914790"),
    ("RG-F-7d556024abe5b7ab9390", "RG-F-eeb68e078ec542ada31c"),
    ("RG-F-7d56bab7c0eede6b219e", "RG-F-493eb3dfad4a42d40802"),
    ("RG-F-7dc71841a3c1f18ff861", "RG-F-b078b0c026dfdc3ee4d2"),
    ("RG-F-7e4b009ae1d8d5f62495", "RG-F-8ae418e1953a52a1525c"),
    ("RG-F-7ec066f342456017fdad", "RG-F-8375efb34dfc3db9e22b"),
    ("RG-F-7f42ec8f8d04719e520b", "RG-F-ef758395e1c6fa784751"),
    ("RG-F-7f4499a24e9d5f6e00f6", "RG-F-46da1927bc8f8bbed9e9"),
    ("RG-F-7fa8e7ac0c0c9868e5e7", "RG-F-74a151ae48279e5ae396"),
    ("RG-F-8026e53037a53df12cd6", "RG-F-79857dc37346a3ede1e1"),
    ("RG-F-80a6b0895e4ac21c15b1", "RG-F-c7788e3df880d2ac4c88"),
    ("RG-F-80efb246c1c6cef502b9", "RG-F-49f913eb36de6f0eb01a"),
    ("RG-F-815e1275a0974c35cfa6", "RG-F-b77697a383103414ce26"),
    ("RG-F-81608c6faa73271f21d5", "RG-F-eb46e519adb49cd1a0b4"),
    ("RG-F-81748a75f8538c62a9f7", "RG-F-ffc6810a059dd112231b"),
    ("RG-F-81f4ae9753655126716c", "RG-F-9555f089ef1a40cbf80e"),
    ("RG-F-827b6af889449cdfa621", "RG-F-2c0a2a0c34601ce91936"),
    ("RG-F-827fe3112766f8b1f36b", "RG-F-82751c6aba1c2d0b685a"),
    ("RG-F-82e05319e99b38439c65", "RG-F-2cfdd4953973ec93aaa6"),
    ("RG-F-8392c4fca5e455eb3cda", "RG-F-cbadccf7edbe802a508e"),
    ("RG-F-83f03eae691bb0f57956", "RG-F-5722d20b8628b430605b"),
    ("RG-F-842ae1fa8dfa0b9daf76", "RG-F-fc454bde9c77551f1734"),
    ("RG-F-8441d3a636ed52928e6b", "RG-F-ab8ae51b79cf1320f9b3"),
    ("RG-F-84e5a83d96412926ea75", "RG-F-01b35158d6b2436983ee"),
    ("RG-F-84eeae3ebcc64e90781a", "RG-F-90dfb8d3abb28ba347a1"),
    ("RG-F-85317e7aebd33b457844", "RG-F-0f04069b9e821a168708"),
    ("RG-F-856e53a8550be68cc92e", "RG-F-bf6865da3e03b11eafae"),
    ("RG-F-85bdc46a384c692a66c3", "RG-F-a5c06a03ffec24675436"),
    ("RG-F-86967e6e29d35596db8a", "RG-F-aeaa09c0100e95e146b0"),
    ("RG-F-86c1af68dfdcac804331", "RG-F-c950bf3a26e57a4fcc11"),
    ("RG-F-86d314b4ea2f2daa5539", "RG-F-a9451aaa578b6edd89ab"),
    ("RG-F-8783f7e0987e14dd74d6", "RG-F-fc31690efe18d4711078"),
    ("RG-F-883875d77da546381df0", "RG-F-e08fbe93d2668bef6133"),
    ("RG-F-885b524a8f76bbb842bd", "RG-F-fb859141aef85785ef0f"),
    ("RG-F-88cf9964c4fb75e6e29f", "RG-F-da085a167322a6ca3af9"),
    ("RG-F-89d1a3bc65108b92a474", "RG-F-02aff009ce146122520e"),
    ("RG-F-89e016fe2736366562e6", "RG-F-ece9814ead84b2737728"),
    ("RG-F-8afa232b7531c9dbdfd3", "RG-F-ea42b78a0f4dad50a82f"),
    ("RG-F-8bc8ed67fe6405b5b418", "RG-F-5813677334aa93cf4f03"),
    ("RG-F-8c08bb34df9cd180b7cb", "RG-F-dce82be491b111bcc4a1"),
    ("RG-F-8c82c2f0d0f6cd7708b8", "RG-F-81d47be012470e8e535c"),
    ("RG-F-8c9e208aeb94f353de11", "RG-F-34b986e9ccb55b770590"),
    ("RG-F-8d0c27bf0ef286bbf8b4", "RG-F-b970909461534a9c9b3e"),
    ("RG-F-8d5b3ab8036d6e8ab747", "RG-F-41f2a0737e311b10f1fb"),
    ("RG-F-8d7818eecf4c25ea2fdc", "RG-F-e2019417ba9532fd82ab"),
    ("RG-F-8dd367f8f6d2e6b25a9f", "RG-F-4179788f33f6e4b9f744"),
    ("RG-F-8dd379352be47c4b7e63", "RG-F-b39aabab5b7695bb28fb"),
    ("RG-F-8e78d5ae4a28fef032c3", "RG-F-2127ca21d3815659a53a"),
    ("RG-F-8e9709511e9ac7f7b9c7", "RG-F-acfc386205484a8311d4"),
    ("RG-F-8ecb43535a426d40a019", "RG-F-74b33e705f2209041e2c"),
    ("RG-F-8f4e504512ee200863f5", "RG-F-944cdbc7e4979c473263"),
    ("RG-F-8fbf2f389d0c6c824c78", "RG-F-2303c505805d68842c9a"),
    ("RG-F-8fcaf9612ef6a752403d", "RG-F-fd44b0e0bd93649279b9"),
    ("RG-F-903e4bede9d3b38af7ac", "RG-F-3d84fca029aa0db125c4"),
    ("RG-F-912fef162cc89fe0bf88", "RG-F-13e779331bc0e4e025d1"),
    ("RG-F-917836855667b06a8be5", "RG-F-037e3def62b3322c0cc8"),
    ("RG-F-92954b482e0b849281e7", "RG-F-b8b11f1c573097bc7ce6"),
    ("RG-F-92e9416a4310840d58b7", "RG-F-76cebbc18633352e965f"),
    ("RG-F-932e3457c2d208fa6cbd", "RG-F-f9f9d5b00f03d853b047"),
    ("RG-F-944ce9ba0db019417ecc", "RG-F-f37cb83185100090045d"),
    ("RG-F-955a3451fb0ff43a0e7d", "RG-F-3025cfb61fb588b0b2e3"),
    ("RG-F-959f407b5d68573d1229", "RG-F-ad0f5edfae77eb1ce2c7"),
    ("RG-F-96eb0ac5065e1587ce77", "RG-F-d2b2ca69f2bf9a8120b1"),
    ("RG-F-994778d198289ded4a86", "RG-F-48864c28d6e3ff960af3"),
    ("RG-F-9a298db1ebc4744c4d81", "RG-F-28f9624a43ed879fda4a"),
    ("RG-F-9a532c938b1d72c03c1d", "RG-F-1692e4d449f0e322a223"),
    ("RG-F-9a5919c0f999202c5bcd", "RG-F-c8428447225801049db6"),
    ("RG-F-9a6f1212b70164463eab", "RG-F-628f09332338f299ec89"),
    ("RG-F-9a81adb6d00ac21cfb47", "RG-F-d4922f3dbfb37b66e235"),
    ("RG-F-9b9931881b1b3c044009", "RG-F-dcdbfeefb263f3c27d3a"),
    ("RG-F-9b9f309fc6f60e4b3272", "RG-F-b53e1c5710796608a0b3"),
    ("RG-F-9bc90d81a5b23d53a9f8", "RG-F-2a845dc07da7597798b6"),
    ("RG-F-9d29607e52f9a3e6de05", "RG-F-c4ad63f98048d0486a69"),
    ("RG-F-9e35fb6c959b18a5a1ba", "RG-F-9e79bde7c5d1fb8f92c3"),
    ("RG-F-9e895a3a0250ae83b691", "RG-F-56e4e3f45e08c5c2f01d"),
    ("RG-F-9eb8a316387fb8b4eda7", "RG-F-b420b653f54f7c18598b"),
    ("RG-F-9f084ffd4f7bca8a8785", "RG-F-ecbbaedaac3eea1407e1"),
    ("RG-F-9f45a266fb8458156812", "RG-F-8da24b5ec162432b2e21"),
    ("RG-F-a04285735b5eace092c8", "RG-F-611bc55ef8f94d1de02f"),
    ("RG-F-a06896e1911b510d41e1", "RG-F-7a91a8340e6d1dafe471"),
    ("RG-F-a0778ccb56479e37c576", "RG-F-269df9ee5cb7d55a01e7"),
    ("RG-F-a0fa97e4da60b58ff89c", "RG-F-ceca69f0d45ed10fca87"),
    ("RG-F-a10d860ce8bc8dd86327", "RG-F-23956b20a1c593a174b0"),
    ("RG-F-a134cd8378f1b1bea740", "RG-F-3c9dec833bbcaa4f4e66"),
    ("RG-F-a176e923c63403710964", "RG-F-a176e923c63403710964"),
    ("RG-F-a17b6b8e305291daff59", "RG-F-18434fc2854cdfff8473"),
    ("RG-F-a23ffa80c4cf415d47bc", "RG-F-d82f555f894e694b2bfc"),
    ("RG-F-a27d48811a96d0201aa6", "RG-F-2760e336ab5d6ab10f1f"),
    ("RG-F-a33c0fce3605345a648e", "RG-F-591ad2963b9ceb809480"),
    ("RG-F-a464a95d8c6a6833c6d2", "RG-F-eed549dc563c28236353"),
    ("RG-F-a4975d81a52ad28d1341", "RG-F-eefe380d7a7142f35827"),
    ("RG-F-a579c006e0aba9709bc6", "RG-F-a3f39e93d5b9660d6899"),
    ("RG-F-a5ca3ef9fea141425097", "RG-F-40fe694b4de7e44dda8a"),
    ("RG-F-a609af621c4f7aa229af", "RG-F-f188179f04ce5e71dfee"),
    ("RG-F-a7c613aedf13259c0b0f", "RG-F-b1b28afdc0d96c99bac2"),
    ("RG-F-a7ec54f387c92994e719", "RG-F-f731551ae9854f335652"),
    ("RG-F-a952489a1e2a692af4c1", "RG-F-19772f7e6c72893d19e5"),
    ("RG-F-a9957536cc9af854bb5e", "RG-F-3842d1fd59aaf1efbc55"),
    ("RG-F-a99abc66852a3dff734e", "RG-F-1ce28154f6b860b85d1e"),
    ("RG-F-a9b11ca1a705fba9c44a", "RG-F-c09a0eec54678ad3475a"),
    ("RG-F-aa8fd9e00030cf9ce2b6", "RG-F-393d63210c286a7210e6"),
    ("RG-F-ab88782630ba7ee4c7b1", "RG-F-ff0e0d8fd96611a11ae6"),
    ("RG-F-abb3bf756fd20450f68c", "RG-F-ca618a5a3392bc3c59c3"),
    ("RG-F-abf77d064f1ec656081b", "RG-F-abf77d064f1ec656081b"),
    ("RG-F-ad4ab40cb6a9b0d5f2a9", "RG-F-a00048815b18b27aff2d"),
    ("RG-F-ad4cafa74f583abfbe4f", "RG-F-425cd5352ccd5db995c9"),
    ("RG-F-ad8d53f73b8595fb38d1", "RG-F-a9d1cbbe68258bced033"),
    ("RG-F-ad9083c45ed7997566cd", "RG-F-6f8ed569097d86c2d371"),
    ("RG-F-ae05f2c79003ff6ec9a9", "RG-F-0e245e7a29cace90cd81"),
    ("RG-F-aeb8d423e0f3a9bcc9cd", "RG-F-49dfda3363343e0433d9"),
    ("RG-F-afcc95cc17357bffe136", "RG-F-25034d16aceabddf9230"),
    ("RG-F-afed274d95795398acbb", "RG-F-2935aaa8714aad428418"),
    ("RG-F-b08c817301eefaaf4011", "RG-F-b987304cb5f7158efc91"),
    ("RG-F-b1c59d7c1ce83f3fc877", "RG-F-bdbeb8a17dfc1773937a"),
    ("RG-F-b1d9aa1845cfec1804e7", "RG-F-8b08836d46d2f18623fd"),
    ("RG-F-b3157b943066d8e74d4f", "RG-F-131206e2dc76ecaa0ea8"),
    ("RG-F-b447d242a143e3ff0006", "RG-F-59286f41a83f786200b2"),
    ("RG-F-b45a4aaf0ba46f015ebf", "RG-F-4a2d7b2f308abdd4878d"),
    ("RG-F-b4b72e04dd90228ef3bb", "RG-F-d4425392f6e84096fc7a"),
    ("RG-F-b519d3336f9e5464a216", "RG-F-72f14c47bb45e0145a42"),
    ("RG-F-b598f75669c803e9e3d1", "RG-F-9d065c969e343a2c172e"),
    ("RG-F-b59e032e8c04bc03622e", "RG-F-de82ccf5cb3ab7d05a15"),
    ("RG-F-b5ab805b4b3320aeb1fa", "RG-F-32dc11b88842073b5fec"),
    ("RG-F-b6563b02f21bb001353d", "RG-F-5702dd3779ca70860cbb"),
    ("RG-F-b7664d16289b71c456ae", "RG-F-3286a2439cb53c6c76ad"),
    ("RG-F-b7b473477f7a70c35483", "RG-F-12e5d41fb77844c41884"),
    ("RG-F-b87e3846e27e434b4bfd", "RG-F-3e91241d56bd40490b28"),
    ("RG-F-b963ca1fc0328358033f", "RG-F-333df7b03f2b23fe523c"),
    ("RG-F-b9dc9947cf63b842e5d9", "RG-F-3a18532285d86cae6790"),
    ("RG-F-b9ddcaca12d17fea3c91", "RG-F-85d52ed81248fcadcd31"),
    ("RG-F-ba5f8ef92122364caff2", "RG-F-9abcbe19cd51f069dcce"),
    ("RG-F-baa0434992c1363b8d95", "RG-F-6ad94d26468d36295c26"),
    ("RG-F-bb20c591cf86c2a9f868", "RG-F-c9feebcf8cdadccd5d46"),
    ("RG-F-bbbb84898a6050a471c2", "RG-F-cb9755f81567fc7a4482"),
    ("RG-F-bbc4672a43e4d19ea710", "RG-F-3fb10cc1b8dfba18a557"),
    ("RG-F-bbd8e4d05192bc9c2e93", "RG-F-08a1b796e1c02e6be764"),
    ("RG-F-bc74f0d9039600d1864e", "RG-F-90f730e9c1bbca2fc102"),
    ("RG-F-bcec90a45f20c425e217", "RG-F-16ee7fda412a0a96b79c"),
    ("RG-F-bd60554faf89984f30be", "RG-F-c97d899146f0bbc23a15"),
    ("RG-F-be167ca2e23afd8c5956", "RG-F-8671d6c7e58b410b2e68"),
    ("RG-F-be4fb6bac4aa0d1906a6", "RG-F-b51b2deb8da29696dc52"),
    ("RG-F-bfc8d20242b45bc15e41", "RG-F-1847f64e5306599bb1f7"),
    ("RG-F-c07f97463d7249eed59e", "RG-F-edd4713c9bdadd7ab3e4"),
    ("RG-F-c0beda04f2e6bc96f20f", "RG-F-c410a7bf715f02b791bf"),
    ("RG-F-c0d432026d80a6803402", "RG-F-f3ad82fa5257af315995"),
    ("RG-F-c0ee2922e77c9119c79f", "RG-F-f69d8955656e7dadd499"),
    ("RG-F-c1d3abc347842d2810ce", "RG-F-44857baf6cb5bb613def"),
    ("RG-F-c1ee72b6e2546281e74f", "RG-F-0eb65941d5d8f3ff01fc"),
    ("RG-F-c1f21ae5ca7ac7e7aa3c", "RG-F-3a3073abf02fbff97aca"),
    ("RG-F-c292ca37d2c29dfc9361", "RG-F-ff7130f442132a11fd55"),
    ("RG-F-c299d7fecc95460c1a0e", "RG-F-4b19f498aa16c391513a"),
    ("RG-F-c385cd66a20c157f5332", "RG-F-9fcd346dc88678c0690c"),
    ("RG-F-c3c55a413d67209a2012", "RG-F-802fc82b2697d77d7175"),
    ("RG-F-c3eb10dd19ac33346cb4", "RG-F-fd605804efab72dd7f61"),
    ("RG-F-c4081c3d98b373cceaea", "RG-F-1d3d27fe9a186deff7a6"),
    ("RG-F-c58bd5e5d630cc315643", "RG-F-cc05e9e6d69e72d76759"),
    ("RG-F-c677af856e21301a1be7", "RG-F-944b96880e55bb88cc25"),
    ("RG-F-c71fdf0ebdad0fef5258", "RG-F-c748cdbeb770415ad70f"),
    ("RG-F-c76e93f7b514cc307344", "RG-F-30f67e8116795adbb6b2"),
    ("RG-F-c7d3359e93081883b23e", "RG-F-e5567279d4d848c68284"),
    ("RG-F-c9339617d6f5796079fc", "RG-F-3bab7231ccc5d61b950d"),
    ("RG-F-c9811edb9fb50bdcbb02", "RG-F-3e640a9b136c4a824063"),
    ("RG-F-caaba4c4451663e8192a", "RG-F-f520a43dcd8762748705"),
    ("RG-F-cb1453367426bab70b42", "RG-F-14308901657e8b225fe7"),
    ("RG-F-cbd102e6173cd8cf0653", "RG-F-5701b1ca48b5f80a7e9f"),
    ("RG-F-cc2d27eec015d9dc0b91", "RG-F-94576517ee1372639e64"),
    ("RG-F-cc32cb3caeaee660aa33", "RG-F-0cd5548a65347108ceb2"),
    ("RG-F-ccf9df140af6ac428e51", "RG-F-b1bf4d29c31ccb227943"),
    ("RG-F-cd4bc385cfa9e01d47eb", "RG-F-809fcdf999a8f630f4ad"),
    ("RG-F-cd9fb6ded582fdb4a253", "RG-F-c9c94fa204bef1d0f6a7"),
    ("RG-F-cf52e890ee8a36a0f5d2", "RG-F-695928e52bc3d1243201"),
    ("RG-F-cf9c7ee152384ba37e38", "RG-F-873b743824356fbc98b7"),
    ("RG-F-cffb162ddc3991a0c693", "RG-F-b98549747f90bdc02553"),
    ("RG-F-d084af6d55490fcb2f03", "RG-F-6060d4628884d9c7b934"),
    ("RG-F-d0a3c5e35185cb718fcf", "RG-F-2e7e417fdc2bb71a9c73"),
    ("RG-F-d0b0d9affa336a02666d", "RG-F-e3a4e090f3da475f6305"),
    ("RG-F-d0c6ed811bdd75fca718", "RG-F-6cc79925c1152ad3d51e"),
    ("RG-F-d0f85a86bc40ee471542", "RG-F-ed97c13f822938c9cd89"),
    ("RG-F-d21d7ad7d37f851c09ed", "RG-F-73c5c36f5fc7758afb22"),
    ("RG-F-d2a6efd33943f99876b9", "RG-F-372d591b6a8a3aca4941"),
    ("RG-F-d309f2cb1e0521649c3e", "RG-F-a11fffb2014479dd4a7a"),
    ("RG-F-d3b57f6a0c99257a308b", "RG-F-2b59fa1c3b1a73362ba7"),
    ("RG-F-d3cbdd1c0f4c699102a4", "RG-F-cd90d3c35bf841317557"),
    ("RG-F-d3f036ca49b1857fe77d", "RG-F-e6157b745bd25cbd77c7"),
    ("RG-F-d421f5a0561e50936f18", "RG-F-144b2303dbaaaa3c0906"),
    ("RG-F-d4793f1f2dc45770289c", "RG-F-5351aec1c6466b1b9859"),
    ("RG-F-d4aa907eac43960edeec", "RG-F-b9f1117373f2f06d7396"),
    ("RG-F-d5d39e79e997301dbbbc", "RG-F-b652978fb99ef75eaa35"),
    ("RG-F-d746d5fe277c46b2549e", "RG-F-6e1acc5c079520db7a15"),
    ("RG-F-d7badb03d82a13df560d", "RG-F-7a7fa43baa543aa45f24"),
    ("RG-F-d7bbd57335d62c42df4f", "RG-F-99f929268ea42c2d5675"),
    ("RG-F-d85013c4d85b6ef00ce3", "RG-F-562df5f00ebcbf38872a"),
    ("RG-F-d8e0a50ea15b7f15c23f", "RG-F-d03ae0650e666c500a8e"),
    ("RG-F-d9bbc5bf257eba661cde", "RG-F-a87f5098b9cb3d94a709"),
    ("RG-F-daa603fd8f42abcfe2fb", "RG-F-b28ed8113612c1d70101"),
    ("RG-F-dae04c9c907df09546fa", "RG-F-e9d1d51845e6a8b2af36"),
    ("RG-F-db63a0620cae7f35a1e5", "RG-F-58043a6f46ae1c9b28c7"),
    ("RG-F-dbcf028e82133b9565c3", "RG-F-b41f1c06100a7f440c36"),
    ("RG-F-dc8dd0e36487b3b2fb4a", "RG-F-6d463d2e267d5753352c"),
    ("RG-F-dce23f8a1501c96a1a84", "RG-F-e8403781f3b10897f1ff"),
    ("RG-F-dcefd033d937f2b339bd", "RG-F-259bd0774148eb5c8ab2"),
    ("RG-F-dd1379a84ce1f896ce22", "RG-F-0b56e116e3afefd18da3"),
    ("RG-F-ddcc1f330d0332f912ae", "RG-F-6a8ca348f696a0ccc27a"),
    ("RG-F-ddcca3e697279ebe7c54", "RG-F-ce80229a438c9635fbe9"),
    ("RG-F-de86f142eac0c451b496", "RG-F-4b68743471f19aa81df9"),
    ("RG-F-debbaec13ded4d28d1ed", "RG-F-4fe9e16efa2a6b2ffced"),
    ("RG-F-df138e1608414f13f855", "RG-F-97e2e72a7bad8ffb35cc"),
    ("RG-F-df8aed776091cdabd260", "RG-F-de4503d9225d9713c77c"),
    ("RG-F-dfc7d3bfa1c1d97086b3", "RG-F-5d59c2f260f92a5d1e58"),
    ("RG-F-e03451a738bd548e1f31", "RG-F-d6fe7b4d2a2591f3f51c"),
    ("RG-F-e168755a3d3ef1e682d7", "RG-F-2fb18593bd567569c47b"),
    ("RG-F-e1c8120aff0b2b2ab02d", "RG-F-92442e738d9250d093f2"),
    ("RG-F-e1d51dd246fa1fa37c37", "RG-F-11bcc506bd95b58ddc74"),
    ("RG-F-e1ee4372589486b36d70", "RG-F-211fba91cd3ce658fac7"),
    ("RG-F-e2f8fd9656b544eb364c", "RG-F-bee721d4d0c8d4474c66"),
    ("RG-F-e32609c6e6aa96eb3250", "RG-F-dc9b38102ff7f83438ee"),
    ("RG-F-e3c7f85da0796b6253c4", "RG-F-9a9ed4cf8bf43083e3ff"),
    ("RG-F-e4e3f26824bc65a83baf", "RG-F-150fcf46b07d4de67214"),
    ("RG-F-e5118215bbe2945b9480", "RG-F-67c7a43469ad14fb90af"),
    ("RG-F-e5323a85b3b72311c6b9", "RG-F-21c6c1067a89ef093ce7"),
    ("RG-F-e5c3f2b033d412a9ff3c", "RG-F-a3c894580ae5233ca84f"),
    ("RG-F-e6d44fe6157734ea6fa8", "RG-F-66a413c393915c485061"),
    ("RG-F-e72fa333323b4a4184b7", "RG-F-cb1242df3cf7ff451804"),
    ("RG-F-e738a6a6904c1fbbb1cf", "RG-F-5546153a513e93e74238"),
    ("RG-F-e74efd0e7cd7b12c51d9", "RG-F-165d45a203c4b7b0a40d"),
    ("RG-F-e7700e3314cd8bda7097", "RG-F-7c1d3d4135d705d2ffcb"),
    ("RG-F-e7ba51c17a135fa5e918", "RG-F-746a8b9fa443b0ba04a6"),
    ("RG-F-e80d4c879a2f526486ce", "RG-F-40549d264fd9c758c752"),
    ("RG-F-e8414cb0b3d76abecbe6", "RG-F-6f65439227ead95686eb"),
    ("RG-F-e878fd4581e333b2901f", "RG-F-f6d4c6dd7f9ae71405a9"),
    ("RG-F-e987d5886ea390ea16df", "RG-F-bbccaf0df208080ff787"),
    ("RG-F-e9e5daa17d4e432ad7df", "RG-F-9295bdfef8776521b3c7"),
    ("RG-F-ea9543a172a0f65beea0", "RG-F-f084574e3e9118b71d23"),
    ("RG-F-eb3426c01ce39d7eb5e4", "RG-F-922c621e9666b98875ff"),
    ("RG-F-ec2d50c00923e0d5796d", "RG-F-0706966789d474fb68e6"),
    ("RG-F-ecb07ecfbc33e6ed366d", "RG-F-c6f2b9c34e68bbcee2ed"),
    ("RG-F-ed16c7848d79ac742b4e", "RG-F-d0b22a501b5d17eeb9dd"),
    ("RG-F-edb7fd6800521806fa82", "RG-F-be869cfeb9e8fd5a610b"),
    ("RG-F-eef41041ac8e520895ee", "RG-F-833fb812c4b36c827a42"),
    ("RG-F-ef4d045b60b3b49ac842", "RG-F-c97ac8849c87e461c1ae"),
    ("RG-F-ef67f0f933f00d59516d", "RG-F-601eb1ab580c9774525d"),
    ("RG-F-ef9802b1e78c6b85d7eb", "RG-F-0ec433144b996e971af4"),
    ("RG-F-efa850e5e1703eb01886", "RG-F-6f7d48f6d6fd21368c90"),
    ("RG-F-efcf794f8358682dd6e9", "RG-F-94a2b6bd1410db433619"),
    ("RG-F-effd3684359ae297f230", "RG-F-c8f3dbd5f36d5397aaa7"),
    ("RG-F-f094bb239e3cfa774b1d", "RG-F-2632a5958240233737f3"),
    ("RG-F-f0c872a033d6ed8d2afc", "RG-F-46888848014d136d6b50"),
    ("RG-F-f1437432d5a7e58d9d21", "RG-F-da3d195ba322cfdad90a"),
    ("RG-F-f1c07fdfb00e5862b60a", "RG-F-c88411b5ae073a7a72b1"),
    ("RG-F-f1cb88a0ee1c3b981bc5", "RG-F-6e6088a51898cb19de36"),
    ("RG-F-f1d9c2162cced50a9f1a", "RG-F-61c15ec0ca08d6e5f9e7"),
    ("RG-F-f23c84cf58035a9ebe14", "RG-F-1dc9c2147f40511a7a8b"),
    ("RG-F-f2badfebbd89a2ed2bc6", "RG-F-21e0ac28551f044dca6e"),
    ("RG-F-f2c4534fa006dfacfb4d", "RG-F-ed98f5099b53ffc8032f"),
    ("RG-F-f369df8fef61e2ae0151", "RG-F-712b6b68b1c2b02ea626"),
    ("RG-F-f38d5881cc3a460135ff", "RG-F-e8ce8c77c3620a5ab966"),
    ("RG-F-f3dc32d6d453637b39c1", "RG-F-d2f30b300aa03e80ba0a"),
    ("RG-F-f4aa72ee02bdf111fcd3", "RG-F-b7b702b2308146f88e35"),
    ("RG-F-f50a838960c2cc4b2803", "RG-F-e210f36f5ecda32d81c9"),
    ("RG-F-f64771d7c6cdb9599854", "RG-F-bcee4c5acad4b0d3d723"),
    ("RG-F-f6aa634dbca27f180284", "RG-F-50955cbe6a5317194dda"),
    ("RG-F-f77c9c81fdfbee8c4397", "RG-F-c72b1f17c80fe192ae20"),
    ("RG-F-f7d034b180f778c0b7a4", "RG-F-003a096c5edc6c456ded"),
    ("RG-F-f828f9d8a2f59aebb57b", "RG-F-9e79ed98d1092ec72737"),
    ("RG-F-f83534827af595642dff", "RG-F-62677f02a16f1130b552"),
    ("RG-F-f8cd03202039eae9efae", "RG-F-029dbb5de6766b075389"),
    ("RG-F-f9711768905eb5bf056c", "RG-F-f873313f735f02cf3937"),
    ("RG-F-fbb344d0a6765f84f294", "RG-F-55e1e0c41b7b89a5db6b"),
    ("RG-F-fbfe7f51233fbd8fd42a", "RG-F-eb3c36fa409cf4b98773"),
    ("RG-F-fc7fd2788de77ca38565", "RG-F-e2393ac56e6f7cb7936c"),
    ("RG-F-fd655d6b3856412c7d46", "RG-F-e45cf642507c156f4831"),
    ("RG-F-fd82c9d5598cf4e2837b", "RG-F-4d35f2595074be762e86"),
    ("RG-F-fe8f47856b4f6df506ff", "RG-F-fba8b8b1904fa47ba493"),
    ("RG-F-fe9dc3722a3f03fda7a6", "RG-F-e8eb49cd41fcc683818a"),
    ("RG-F-fec5ede5b348f8c683da", "RG-F-7cadc7ac3096a5dd59da"),
    ("RG-F-fefdb48c92ee9155d8c7", "RG-F-aee8d565c0bd52e44f5c"),
    ("RG-F-ff9e56b34d4facda44b5", "RG-F-ddbc2a4da7caf5c794ea"),
    ("RG-F-ffc9c39bf41866161a52", "RG-F-188bbf4a5725ad8c3d30"),
}
CONTINUITY_EXPECTED_TOMBSTONES = {
    ("RG-F-002a9ec13d8e062540b9", "RG-F-002a9ec13d8e062540b9", "874e81f7b9877b519c8ab55b57cbac24de0918f0"),
    ("RG-F-069b0702a18335d9be0c", "RG-F-069b0702a18335d9be0c", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-080a097af2330629ba3f", "RG-F-080a097af2330629ba3f", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-0956a3c1a45b988e2264", "RG-F-0956a3c1a45b988e2264", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-0d2289bfdcab7b4448fa", "RG-F-0d2289bfdcab7b4448fa", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-0ed2474deb7fd50b1810", "RG-F-0ed2474deb7fd50b1810", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-11fe8713d50574890a0d", "RG-F-11fe8713d50574890a0d", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-122e53031d85d983b3c5", "RG-F-122e53031d85d983b3c5", "ac7a35266cf5612ac6d8bb340f53a4a946418d14"),
    ("RG-F-15a6b977326f7c0a9e15", "RG-F-15a6b977326f7c0a9e15", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-16c31deda08795ad3093", "RG-F-16c31deda08795ad3093", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-19f611a02beef2ac0b9b", "RG-F-19f611a02beef2ac0b9b", "3fb97c113e3128c78b5856099d0bffe5deeda496"),
    ("RG-F-1c73f35250d2f790089b", "RG-F-1c73f35250d2f790089b", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-1db18bd849feb0c1a2ff", "RG-F-1db18bd849feb0c1a2ff", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-1e84c830545d01637f72", "RG-F-1e84c830545d01637f72", "a5362afcfcccc25d87e4853552440d4fad619d1b"),
    ("RG-F-1f5b317e9c9d4e92a42c", "RG-F-1f5b317e9c9d4e92a42c", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-1fa229bcb4933c3aa865", "RG-F-1fa229bcb4933c3aa865", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-207970b57ae89033f8ef", "RG-F-207970b57ae89033f8ef", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-23e0cdef45d8a01764a7", "RG-F-23e0cdef45d8a01764a7", "1644180de42b58cd0155f62c9b3ad82efc820a57"),
    ("RG-F-255edda2318d460e2e4b", "RG-F-255edda2318d460e2e4b", "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-2a30e8b9fb9513652359", "RG-F-2a30e8b9fb9513652359", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-2f5becc12de85429ab6e", "RG-F-2f5becc12de85429ab6e", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-2f5c843a5f5bb2d862e9", "RG-F-2f5c843a5f5bb2d862e9", "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-30101d742841018ea6b2", "RG-F-30101d742841018ea6b2", "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-34ac6f9501dab285e4c2", "RG-F-34ac6f9501dab285e4c2", "3fb97c113e3128c78b5856099d0bffe5deeda496"),
    ("RG-F-34b7e7a5eccad1c230cc", "RG-F-34b7e7a5eccad1c230cc", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-34c3b946a9961b60b651", "RG-F-fe174638708e62b5cdaf", "420174438fdf3ae4f7e09b483af14cc04215316d"),
    ("RG-F-3524f2b85a89317f48c9", "RG-F-3524f2b85a89317f48c9", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-39e5459fa425a2e12584", "RG-F-39e5459fa425a2e12584", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-3d0d2effbe43a91462ce", "RG-F-3d0d2effbe43a91462ce", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-3d82ffd9aa8f8d3850b6", "RG-F-3d82ffd9aa8f8d3850b6", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-444114638e85929a8a7c", "RG-F-444114638e85929a8a7c", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-482acb248a628653592d", "RG-F-482acb248a628653592d", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-4888aa18f6c00f918567", "RG-F-4888aa18f6c00f918567", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-4991980ba6d7be445656", "RG-F-4991980ba6d7be445656", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-4a37bb3ab1d3734f0c77", "RG-F-4a37bb3ab1d3734f0c77", "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-4e37a3628b4770e851f8", "RG-F-4e37a3628b4770e851f8", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-53ed24ee2a9a1e691b6b", "RG-F-53ed24ee2a9a1e691b6b", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-548dbddabf2cb58f43e3", "RG-F-548dbddabf2cb58f43e3", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-56411d1c69a8e636a9cc", "RG-F-56411d1c69a8e636a9cc", "bdc7f341d3a588045832a670f02cf384d3b12e1a"),
    ("RG-F-59bb7728de73efb30458", "RG-F-59bb7728de73efb30458", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-5b1e839e8d308d43aaf3", "RG-F-5b1e839e8d308d43aaf3", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-5cf088ee67b09c27078b", "RG-F-5cf088ee67b09c27078b", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-5d999c09619be29bf43c", "RG-F-5d999c09619be29bf43c", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-5dad7059d66628fd9da9", "RG-F-5dad7059d66628fd9da9", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-5ec71c480ba4438dca3a", "RG-F-5ec71c480ba4438dca3a", "92daed300bcce3c4d855b311cf9667ba21eb475a"),
    ("RG-F-616567dbc34f5558543c", "RG-F-616567dbc34f5558543c", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-620248dd286ea7551a37", "RG-F-620248dd286ea7551a37", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-629cf67761b687a8c26d", "RG-F-629cf67761b687a8c26d", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-67dc7962c61bc5688142", "RG-F-67dc7962c61bc5688142", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-69a24b4aa7a5774bcbbc", "RG-F-69a24b4aa7a5774bcbbc", "4d1bcf29bf527f542141adef5774980d4831b0ce"),
    ("RG-F-6d0b423a6eb30f204ebc", "RG-F-6d0b423a6eb30f204ebc", "10ea407df05d4f92cbd71ffe4df20aac70b5afb8"),
    ("RG-F-8544a0e173d594065ca7", "RG-F-8544a0e173d594065ca7", "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-8761367cefe917fac99f", "RG-F-8761367cefe917fac99f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-88d87eaf0e792af4c255", "RG-F-88d87eaf0e792af4c255", "4495eb601d22f959bad64a6c085f516431195b42"),
    ("RG-F-89654e80cbde5e7d3ea3", "RG-F-89654e80cbde5e7d3ea3", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-8e4485d9f15252be0689", "RG-F-8e4485d9f15252be0689", "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-8e6f7437052ad650c6c7", "RG-F-8e6f7437052ad650c6c7", "8e5944cad072ae10595214016a5f70e64fcae015"),
    ("RG-F-90968956e438c405eacd", "RG-F-90968956e438c405eacd", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-90e506c7ea693e6b9770", "RG-F-90e506c7ea693e6b9770", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-91b02db0f11bf77a4794", "RG-F-91b02db0f11bf77a4794", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-927b775bff6275603c45", "RG-F-927b775bff6275603c45", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-935389e7c53de5c13756", "RG-F-935389e7c53de5c13756", "4d1bcf29bf527f542141adef5774980d4831b0ce"),
    ("RG-F-93890c76dc270880c224", "RG-F-93890c76dc270880c224", "f87e4d802652244e1b5792097d53a746d164dc07"),
    ("RG-F-95a861f4477ffddc9d35", "RG-F-95a861f4477ffddc9d35", "bdc7f341d3a588045832a670f02cf384d3b12e1a"),
    ("RG-F-96f8a3e95e70159bece0", "RG-F-96f8a3e95e70159bece0", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-9712364a6d3cf8e6a6a9", "RG-F-9712364a6d3cf8e6a6a9", "8e5944cad072ae10595214016a5f70e64fcae015"),
    ("RG-F-98eb48688773519607ba", "RG-F-98eb48688773519607ba", "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-9a28c4e392ee5121fb7f", "RG-F-9a28c4e392ee5121fb7f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-9b222eeba49a70df3b79", "RG-F-9b222eeba49a70df3b79", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-9e46078d26f5ecc6cd37", "RG-F-9e46078d26f5ecc6cd37", "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-9f52bbaae4d239936a07", "RG-F-9f52bbaae4d239936a07", "e956e963b167ed1d57a7a4daed2a3566f2425999"),
    ("RG-F-9f7e83ffb52973d9aec4", "RG-F-9f7e83ffb52973d9aec4", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-a339a27f5ce4ccf3f7a8", "RG-F-a339a27f5ce4ccf3f7a8", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-a5a4a606dbe7165a08de", "RG-F-a5a4a606dbe7165a08de", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-a92016e1f7d5546f5f4a", "RG-F-a92016e1f7d5546f5f4a", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-abbb15fe53c1fe59162d", "RG-F-abbb15fe53c1fe59162d", "3fb97c113e3128c78b5856099d0bffe5deeda496"),
    ("RG-F-ad6cc85c2c3eaa3a8cdf", "RG-F-ad6cc85c2c3eaa3a8cdf", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-addd45c134e9c47b4617", "RG-F-addd45c134e9c47b4617", "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-aeb06d1101df113fd3b2", "RG-F-aeb06d1101df113fd3b2", "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-b04bd21a5d624e1fc06f", "RG-F-b04bd21a5d624e1fc06f", "26d675e7f6131ed17e8de6a689b5b3d85ec21470"),
    ("RG-F-b08ab6d33575c1274bd2", "RG-F-b08ab6d33575c1274bd2", "2d78b5afc4333180187c1c764b9b23fd71289487"),
    ("RG-F-b17f9f9f43aed18da23f", "RG-F-b17f9f9f43aed18da23f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-b2cb4f664723372b7400", "RG-F-b2cb4f664723372b7400", "11371d512e9b374ec73d5a7e7181e6ed52eba296"),
    ("RG-F-b40b937681743f6e2665", "RG-F-b40b937681743f6e2665", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-b8da745f71c85226ca7e", "RG-F-b8da745f71c85226ca7e", "26eee4ad27fc36a132c948876c9e0fbbb79051e2"),
    ("RG-F-ba26cfc768c51f9d5d5e", "RG-F-ba26cfc768c51f9d5d5e", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-bb8e1fa85a210f58bc8f", "RG-F-bb8e1fa85a210f58bc8f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-bc8a763172eb63d51968", "RG-F-bc8a763172eb63d51968", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-bd201b6f89048574b546", "RG-F-bd201b6f89048574b546", "1644180de42b58cd0155f62c9b3ad82efc820a57"),
    ("RG-F-bd7035998b3fcfcf09fd", "RG-F-bd7035998b3fcfcf09fd", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-bd9141cd6ae9f5a4ddad", "RG-F-bd9141cd6ae9f5a4ddad", "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db"),
    ("RG-F-be28b0ba758951601dda", "RG-F-be28b0ba758951601dda", "8dae10d3c2b02df7424beaba2abf9fdf72bbdb66"),
    ("RG-F-bf779565541f339a5b98", "RG-F-bf779565541f339a5b98", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-c261bf862e86c3ae27dd", "RG-F-c261bf862e86c3ae27dd", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-c38867803d56c02e64a5", "RG-F-c38867803d56c02e64a5", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-c469c5afb8c5eaa6944e", "RG-F-c469c5afb8c5eaa6944e", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-c5250352efdcc2e7c776", "RG-F-c5250352efdcc2e7c776", "ac7a35266cf5612ac6d8bb340f53a4a946418d14"),
    ("RG-F-c856c136a6c476dafc73", "RG-F-c856c136a6c476dafc73", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-ca1da07e9a917ec01ce4", "RG-F-ca1da07e9a917ec01ce4", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-ca8e5e48082eb933ed01", "RG-F-ca8e5e48082eb933ed01", "4d1bcf29bf527f542141adef5774980d4831b0ce"),
    ("RG-F-cac945ca8266a08b1dfa", "RG-F-cac945ca8266a08b1dfa", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-cb2c742a239b918218ca", "RG-F-cb2c742a239b918218ca", "cddcefd88006dd68ed69284ed31562a08fda3107"),
    ("RG-F-cd3e481e567525eef117", "RG-F-cd3e481e567525eef117", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-cf22821ce96008ff0c7e", "RG-F-cf22821ce96008ff0c7e", "10ea407df05d4f92cbd71ffe4df20aac70b5afb8"),
    ("RG-F-d5b104b5737433f9258f", "RG-F-d5b104b5737433f9258f", "3b6e3139f3f6e9ba3d8d999b046fe7d30310c224"),
    ("RG-F-d7fe24b5271831c9c4e1", "RG-F-d7fe24b5271831c9c4e1", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-dc6c8c08206a5ce51b17", "RG-F-dc6c8c08206a5ce51b17", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-dda630121a5380c159b1", "RG-F-dda630121a5380c159b1", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-ded5b6e2aef38fd29e5a", "RG-F-ded5b6e2aef38fd29e5a", "f87e4d802652244e1b5792097d53a746d164dc07"),
    ("RG-F-deed2231a6bf3a9a609f", "RG-F-deed2231a6bf3a9a609f", "b8da22a86f28cb2750fe85e1a7c69391c900a1fc"),
    ("RG-F-df1ebb5b6896001240d2", "RG-F-df1ebb5b6896001240d2", "ac7a35266cf5612ac6d8bb340f53a4a946418d14"),
    ("RG-F-df518a6031bf229b56b9", "RG-F-df518a6031bf229b56b9", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-dfecd395bd04ac2f614e", "RG-F-dfecd395bd04ac2f614e", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-e1f620e7a5aeaa73902b", "RG-F-e1f620e7a5aeaa73902b", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-e39dc55a8fc070a1517f", "RG-F-e39dc55a8fc070a1517f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-e43c2d78ba8a0472a781", "RG-F-e43c2d78ba8a0472a781", "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db"),
    ("RG-F-e4e0c8f016826161ad18", "RG-F-e4e0c8f016826161ad18", "ac7a35266cf5612ac6d8bb340f53a4a946418d14"),
    ("RG-F-e6a5ca59c7df4b468e28", "RG-F-e6a5ca59c7df4b468e28", "73b5ef26453372a2b562051f113f9b299bcebeef"),
    ("RG-F-ebef02582ed9f5c4ff7f", "RG-F-ebef02582ed9f5c4ff7f", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-ef02d5e77634269ac883", "RG-F-ef02d5e77634269ac883", "4495eb601d22f959bad64a6c085f516431195b42"),
    ("RG-F-f1ff5fa89d5ad21d7426", "RG-F-f1ff5fa89d5ad21d7426", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-f24c99cca197427aca2e", "RG-F-f24c99cca197427aca2e", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-f38dac80fb60e63f7d37", "RG-F-f38dac80fb60e63f7d37", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-f563848b18adbc2e5c71", "RG-F-f563848b18adbc2e5c71", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-f6de4e0f5185cd7b9aef", "RG-F-f6de4e0f5185cd7b9aef", "ac7a35266cf5612ac6d8bb340f53a4a946418d14"),
    ("RG-F-f9bbf97d97898f798acb", "RG-F-f9bbf97d97898f798acb", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
    ("RG-F-fdd3859cc4666533f82b", "RG-F-fdd3859cc4666533f82b", "80ffb7d138dd6825990a4986ed77f0ae7d2355ee"),
}
CONTINUITY_EXPECTED_INTRODUCED = {
    "RG-F-00043d119eb89495e0bc",
    "RG-F-003416535aaee2f83d44",
    "RG-F-00572f8089ee0282e3c8",
    "RG-F-008926b22d962c23a872",
    "RG-F-008d766323a9ccffd8bf",
    "RG-F-008eae3b0ba4d12666a2",
    "RG-F-00cf455c02e51953b267",
    "RG-F-00dab665b85c27184c35",
    "RG-F-00e3706bab0467521374",
    "RG-F-0107d69c97706422234d",
    "RG-F-0181aa98a1fbd83c89b0",
    "RG-F-0181df66ac27c905e488",
    "RG-F-0192719a66c357950145",
    "RG-F-01a8d0c683cbeb72e170",
    "RG-F-01c806223029835bfb7c",
    "RG-F-01d0399e28360197800b",
    "RG-F-01e927f155ea7ad3b212",
    "RG-F-01ee2728c466ae69b5d6",
    "RG-F-01feb5284b6491e5fe0f",
    "RG-F-0255ec262e1f7e9417c8",
    "RG-F-026213b8286dfd642972",
    "RG-F-02a0c5119c38e473ff38",
    "RG-F-02b973adc674e2dafcca",
    "RG-F-02d22322d9306d6a1957",
    "RG-F-02d9ed2945784e08fd09",
    "RG-F-02e4be08c92e34abfe47",
    "RG-F-02e699d2b96d435be309",
    "RG-F-037c0d67474b950b1947",
    "RG-F-0380ee661ebfe004db50",
    "RG-F-03c2e475c288ae37c5ee",
    "RG-F-040dd6a4963caea0f64f",
    "RG-F-042aad4a869ec81de7fa",
    "RG-F-0451f810ac168b6965c8",
    "RG-F-0461c8f711b87d95788a",
    "RG-F-0491ed80d1944df4ee44",
    "RG-F-04bb5a04ed0c5e38341a",
    "RG-F-04c911902b5296c41929",
    "RG-F-0516366c1da03ff42bea",
    "RG-F-05691556ecb6120cfa82",
    "RG-F-0584c8aaef39e842a75d",
    "RG-F-059e23279b9da0115610",
    "RG-F-05acefb94c19229397b1",
    "RG-F-05b7edb1beaf4beabe97",
    "RG-F-05f0a4639ffe477dfe29",
    "RG-F-063d075d779cdcec91b5",
    "RG-F-064534368e4fa9d14c73",
    "RG-F-065555eea9ebf23bec7b",
    "RG-F-068ec0b94ed7ac817c85",
    "RG-F-06c0169bc0459ca42c01",
    "RG-F-06ceabd489805db0990f",
    "RG-F-06f245fe0aa91d078cad",
    "RG-F-07c891e8ebed22a614bf",
    "RG-F-07fe7f5793b3dcb84d52",
    "RG-F-0836e32076174659d198",
    "RG-F-085c02d6f39c4639fb36",
    "RG-F-085ee1eaf9a331ab5cfa",
    "RG-F-08a39029bfe0f0be87ef",
    "RG-F-08bc4cf55d55916e44ee",
    "RG-F-08ccb6b5ae6cdabaf989",
    "RG-F-08dac8072bdc637b124d",
    "RG-F-092e589b0fcbeef86f82",
    "RG-F-0949e302d2d49a3efee5",
    "RG-F-09989c7d05b509be1f6b",
    "RG-F-09ca9f6693c3c6512ec6",
    "RG-F-09ce5f5892df757ee779",
    "RG-F-09e9f71b1c6b4394d17d",
    "RG-F-09f455ed64251d83c705",
    "RG-F-0a00fc7dc24e2fd1aeca",
    "RG-F-0a04aff901a1f8a0c981",
    "RG-F-0a3a5d04dd187b4c9643",
    "RG-F-0a5ab09c4660c57659ce",
    "RG-F-0a95ba0e6234251b69a3",
    "RG-F-0acaaa228de47803d624",
    "RG-F-0acecfe59a00b24053c1",
    "RG-F-0b384cc598e59212d178",
    "RG-F-0b68cb89eb26a5eda7f3",
    "RG-F-0b92a896aa73cc3725f7",
    "RG-F-0ba727b4d4764976fafc",
    "RG-F-0bb902ae9804cb180414",
    "RG-F-0bd73e389622c5d4e2e8",
    "RG-F-0c16fca82d2e2e00a92e",
    "RG-F-0c1812dc79f9771a0122",
    "RG-F-0c4532797b20fa773a40",
    "RG-F-0c5a78a58a9084c68bad",
    "RG-F-0c9b722a5e2a1f5950bb",
    "RG-F-0cc500a14a162b8ade17",
    "RG-F-0ce0e6d56fb0ac31d166",
    "RG-F-0cecf0aca3dd73da1a6a",
    "RG-F-0dc1ec134f52889b4c7f",
    "RG-F-0df196b8a20551c7fd08",
    "RG-F-0e15bb6d7c13b1b596c9",
    "RG-F-0e2100fe343f32904900",
    "RG-F-0e33ad7119bc35c6d94b",
    "RG-F-0e8ed93409d11e65e670",
    "RG-F-0ea64a6087c7f3bdb86f",
    "RG-F-0f2ffa34cfa8d8fa03d4",
    "RG-F-0f4e466fad6c33ba3618",
    "RG-F-0f5415b3d4f3168a6781",
    "RG-F-0f7d1111989c0dcb880e",
    "RG-F-0f83f70cb3576f250ad3",
    "RG-F-0f9521055fb85327ff0a",
    "RG-F-0fbe5cf21ba1816b1abd",
    "RG-F-0fc26a780e6ae233a84c",
    "RG-F-0fdfc157feeb473451db",
    "RG-F-0ff73bc84055f7007361",
    "RG-F-100a612aa7212bc23cbf",
    "RG-F-1032be3fd4ff172cc745",
    "RG-F-104e7177e37c491be519",
    "RG-F-104ea5cc2fcc8b0d8a7e",
    "RG-F-10821d77db3ea7d39567",
    "RG-F-108665bf8e8db980f54f",
    "RG-F-10e53934244421ea0176",
    "RG-F-110d014b3b0e579592a2",
    "RG-F-111441559a33ff4862ca",
    "RG-F-11384ccdf5f27645dce0",
    "RG-F-1144eed0e375b0ec7cfe",
    "RG-F-1149be944c98f817e88f",
    "RG-F-114d6190a80e5e9307af",
    "RG-F-1187eefd1d74587d27e4",
    "RG-F-118a32c68dd9ab577f9b",
    "RG-F-11d2d434ee5673b2f522",
    "RG-F-11e62348309dc8b5f729",
    "RG-F-12179e9c6f95b87170d6",
    "RG-F-1219325c4812c1dd23f2",
    "RG-F-123221b0d9971eb1ff21",
    "RG-F-124cd34d55249816790d",
    "RG-F-1277c8a2b5a31d093c26",
    "RG-F-127afe7d95fd856b3311",
    "RG-F-127b366a00aafc2c6619",
    "RG-F-12c4d303663de55dfbce",
    "RG-F-12f506606145bce1a4e0",
    "RG-F-131701c4a9ad3e4a5002",
    "RG-F-1338e567f56c180e99ee",
    "RG-F-1351f06a2748de7f0508",
    "RG-F-13714dd5d4dfbd7e1421",
    "RG-F-1383b2dc9fd67a304b91",
    "RG-F-13cb1616b8dc5a4b3237",
    "RG-F-13ffa94daa2221be7810",
    "RG-F-14211684d20ec57bc170",
    "RG-F-146ca46957e23e82feb1",
    "RG-F-1500bd995c855ce6895c",
    "RG-F-1515aec57757e43c0b4d",
    "RG-F-1525650de5bcfd435631",
    "RG-F-1548dbf86c773e571bf5",
    "RG-F-157253d5eb6087e664d2",
    "RG-F-1575e8b8dd6563a8cb24",
    "RG-F-1598e1dce980eeacc77a",
    "RG-F-15fb7edd798a685a3808",
    "RG-F-162be04d1ee0cee22ad3",
    "RG-F-16631043521a9cd28528",
    "RG-F-168586405b4a5f13f031",
    "RG-F-16ad5a0f0071f13bc5b6",
    "RG-F-171a26cc2773b0933269",
    "RG-F-176965f2d197861d4701",
    "RG-F-17ada37befe3da0c72a5",
    "RG-F-17dee0662e238eba3dbe",
    "RG-F-17e1b0fea82a8cbd4f16",
    "RG-F-17fefe80512bbd3c0d38",
    "RG-F-1816b9129452b10d63d5",
    "RG-F-181d5bf28272c632dc3e",
    "RG-F-183a5020c9c4df2954fd",
    "RG-F-183ed2ab29bff6cf9fd3",
    "RG-F-1858875b41476176edc8",
    "RG-F-1883b4ec4602f5197e64",
    "RG-F-18d24fefcc04b721bc75",
    "RG-F-1903a5098cb972086397",
    "RG-F-192b5a713145450ef08e",
    "RG-F-192c52f2c4dbbd140bf0",
    "RG-F-1935062c7057d9514b15",
    "RG-F-193774d891bb395d9cf0",
    "RG-F-19447bb36d2f795e7478",
    "RG-F-195a8e77db98cbe5cd59",
    "RG-F-19bc94396f8adc303d6a",
    "RG-F-19c2c30698c70e22fcdb",
    "RG-F-19cbcfb43b2ad638307e",
    "RG-F-19dde5f8d302ddf77cc4",
    "RG-F-19f5afa199e2f612b42f",
    "RG-F-1a229c31e9b9fac4d9ea",
    "RG-F-1a31e6c2b34252958c71",
    "RG-F-1a86052463fe45257a78",
    "RG-F-1b285a9f7036553830fd",
    "RG-F-1b44a6ec6e600aecdbc1",
    "RG-F-1b8e6f1436147bc4091b",
    "RG-F-1b9d2bfe545242131544",
    "RG-F-1bb64040676f2c2c548d",
    "RG-F-1bbf210cfec8aa6ba25e",
    "RG-F-1bc0ac24d1e44e2c92c9",
    "RG-F-1be2ad78a91bf112bfa3",
    "RG-F-1bed76286e1ff90524c5",
    "RG-F-1c09a7343ad499f449c5",
    "RG-F-1c2bd6a9011ade40c5bc",
    "RG-F-1c31d7d267cf2c44f523",
    "RG-F-1c813b6e5463520770f8",
    "RG-F-1cb8ebd9a889597c65f0",
    "RG-F-1d03fdb2b0725f928d1d",
    "RG-F-1d72435db46d5ae730d6",
    "RG-F-1d7e1e836c5e2422f97d",
    "RG-F-1dfdfcf477b746124c4e",
    "RG-F-1e16dfd27039b6c1d6d0",
    "RG-F-1e379133c5e93eb237e8",
    "RG-F-1e577d68f23d8afa8b60",
    "RG-F-1e82270e64ae136e1ff1",
    "RG-F-1e82b450779a7fd97bc1",
    "RG-F-1ea8324e8ade917bc498",
    "RG-F-1f22a873b53c9605f9f5",
    "RG-F-1f3866bdca3f1386b405",
    "RG-F-1fcc10e325a7fac374ec",
    "RG-F-1fdec6ae394eb2ecbfa2",
    "RG-F-1fe6c2b52eccdd39b452",
    "RG-F-1ff19328137f773a122a",
    "RG-F-200daf94837b60d90e9c",
    "RG-F-202372b8209f4c235b2d",
    "RG-F-20b6906d1d1ee9b0cd76",
    "RG-F-20b73ffb7717bb1106e6",
    "RG-F-20e0a57c2d54b0b1c67d",
    "RG-F-212ddea625b7443d63cb",
    "RG-F-21349bc241c63414c350",
    "RG-F-21540a6f1bd93a1bfc14",
    "RG-F-216c139e84414e8ffbf9",
    "RG-F-21cdb06e4507f4f4c691",
    "RG-F-2213bfc450c0564f0a01",
    "RG-F-2241579b5b56f4c6e6ea",
    "RG-F-2276fcd1de5322e7604d",
    "RG-F-22c46fc05bddb2d4345b",
    "RG-F-22d0cde64c40f412081a",
    "RG-F-22e16272b2b579d020d2",
    "RG-F-22eccc1e1851814ffe6d",
    "RG-F-22f277857f36e9c5aae4",
    "RG-F-22fdfbf8278ece1348bc",
    "RG-F-232929dbd0b337e2c222",
    "RG-F-23c659f1017deafb1dc6",
    "RG-F-241da80d29a09365b21c",
    "RG-F-243665bc9f7a02f6d02c",
    "RG-F-244ea859034937d36257",
    "RG-F-245ec46f5966d1227505",
    "RG-F-24758d9c4cdfb2c0f18b",
    "RG-F-247f395d88b998db5284",
    "RG-F-2494f3e409b6f64df0e4",
    "RG-F-24db94981a0293b2e2b5",
    "RG-F-25067204f5b3e34f9798",
    "RG-F-254288b4414ecbf564f7",
    "RG-F-25564c7df65e290568df",
    "RG-F-255c1493a10ab3495460",
    "RG-F-25896af002d768c087df",
    "RG-F-259a9c49bba099f03b24",
    "RG-F-25ac3c5580b8bef2e105",
    "RG-F-25b5a88855b12eec4e4b",
    "RG-F-25cad4695abc87d04370",
    "RG-F-2646dcd008a8290bb207",
    "RG-F-264acf75a501ce87dedd",
    "RG-F-266843c8ac33a1a59b21",
    "RG-F-2691568ac3a23b372685",
    "RG-F-2712f2145ebb3e4de196",
    "RG-F-272f314cf619f4e3574f",
    "RG-F-273eb3cf20c70885bab9",
    "RG-F-2742e831c45e0582f311",
    "RG-F-27430607a20acf228b93",
    "RG-F-275171c8bfbbe7c5c360",
    "RG-F-27b427b38ad2b76de539",
    "RG-F-27bb7523e29958e6558b",
    "RG-F-27f807b8573d302b02d7",
    "RG-F-280545c5aee718dfbb72",
    "RG-F-284a84451afcf57c7972",
    "RG-F-285578f9c31678643187",
    "RG-F-28a09579aa1e40998b98",
    "RG-F-28e4a783fb75dcdf2f04",
    "RG-F-291817f8baaf83e11472",
    "RG-F-296043d82a41ee18ae3b",
    "RG-F-29cbee7248ef3411c05b",
    "RG-F-29dc4b50b4e765955d48",
    "RG-F-29dd30a286d080d5a21a",
    "RG-F-29f85471e683fa65142b",
    "RG-F-2a2388a99f562160cf0b",
    "RG-F-2a2d8b272db8d55177f9",
    "RG-F-2aa6f21723a0fd910906",
    "RG-F-2abc0abb279c6e994743",
    "RG-F-2afae441e2967ec9902b",
    "RG-F-2b15c8cc63a6cc45d95c",
    "RG-F-2ba4ec98a4a3ef35e7ba",
    "RG-F-2c1c46e7eb41d9d0fba1",
    "RG-F-2c614e4f0fe5fd220752",
    "RG-F-2c621f46e3c7b77f1f59",
    "RG-F-2cae510ca54daac7111b",
    "RG-F-2cb78c66eccd2f47258b",
    "RG-F-2d396aa34969d8131811",
    "RG-F-2de92d72d9fdbccc7507",
    "RG-F-2e44940743d67802045a",
    "RG-F-2e6a8e25a8f51169f0aa",
    "RG-F-2e6b131a1e863477a76f",
    "RG-F-2e700fb34b6245ff8d27",
    "RG-F-2e96dea7b92ff0ef2a96",
    "RG-F-2eae62fef9e6cd3c648f",
    "RG-F-2edf01e5a42ad034105a",
    "RG-F-2f14eb91e22dd031c2f9",
    "RG-F-2f56051b70c745c691d6",
    "RG-F-2f863cbd4783c59ddcdb",
    "RG-F-2f933d5a214cba4925e5",
    "RG-F-2ffcd1413b8322f0a043",
    "RG-F-30bb9f76b19c56515ae1",
    "RG-F-3117bf70a0a131115a0d",
    "RG-F-312b2c7055621e1bf498",
    "RG-F-31652cc59b9dc91dbbb0",
    "RG-F-31c4257a3b82b40ad242",
    "RG-F-31d6967fc8ada4cb91eb",
    "RG-F-31e5a475900bf139cda5",
    "RG-F-31f38bae5f34dbe01257",
    "RG-F-324dc7e55c75bc7ef877",
    "RG-F-32502ab56cddd0190910",
    "RG-F-32695f03c6864b0f1fe0",
    "RG-F-32de656f55dfeabcf796",
    "RG-F-32ed6404e734a3756d32",
    "RG-F-334734e6707b98e65537",
    "RG-F-3364b2b484f2fafba596",
    "RG-F-341bb1c0dfdc97575206",
    "RG-F-341f551528f5db7d7224",
    "RG-F-348572e48805a57c238a",
    "RG-F-34c7d933dc71fc515a58",
    "RG-F-34d00aa7b73b80b7e06b",
    "RG-F-34d2579fcfa737263708",
    "RG-F-34ed2b8e73d2a065cdd3",
    "RG-F-3502c0529d42243bba57",
    "RG-F-352875e26c6bad57310a",
    "RG-F-355de159045fc5a3fb40",
    "RG-F-35e0489b93b9cb206606",
    "RG-F-35e9f3f59cad7c897df1",
    "RG-F-364043d58cd57a6c2af5",
    "RG-F-365a01380774696bb891",
    "RG-F-366f5f5ff89810017f5a",
    "RG-F-368f07c936246d7f38ca",
    "RG-F-36ae6a0a421f7db68ddf",
    "RG-F-3736a66da91fbf0bf7bc",
    "RG-F-377d2765e85223c4a653",
    "RG-F-37fe618e1633b505056f",
    "RG-F-3814aca9f7db808e8d20",
    "RG-F-38225f1cc6d4472a0df6",
    "RG-F-385fc5a3f59720c4cea6",
    "RG-F-3865499be614e5334fa8",
    "RG-F-386f697ff55eadbd2270",
    "RG-F-3871f27f5e5e5a66bf35",
    "RG-F-388ae1a628488af9f3fb",
    "RG-F-390e2a8e8305fff18992",
    "RG-F-396cc91a9b2d3fda9d27",
    "RG-F-39766216966330a8e38f",
    "RG-F-397dbed441e7d806e74b",
    "RG-F-39b5ffc412339124b5f7",
    "RG-F-39d56ebd4bb216a6200d",
    "RG-F-39ef8a715e72c7d8cdae",
    "RG-F-39fe2822c979b62f2ff8",
    "RG-F-3a067446bbdcfa1d3701",
    "RG-F-3a4c2cb6610ed696ff72",
    "RG-F-3a91f053d1feb935ac22",
    "RG-F-3ab3e7c341eff7a06dc3",
    "RG-F-3ae4f3955581989a9dd0",
    "RG-F-3af69af0c791124cf2e7",
    "RG-F-3b710a409ce34f951cbd",
    "RG-F-3bb0f0a39065da5c5344",
    "RG-F-3bcb1bfe1842193c65cc",
    "RG-F-3bd6cdd2997cc3f4dd19",
    "RG-F-3be4beb6411d6b4d8a2b",
    "RG-F-3c0b620503d7ecc03ee5",
    "RG-F-3c38099b51c44841765f",
    "RG-F-3ce54e6ad0d15b9e87a6",
    "RG-F-3cedd88530c11c3f3cf7",
    "RG-F-3d20b9690dc42d1b52ec",
    "RG-F-3d63b40e127937e7e9b5",
    "RG-F-3d8d8b770de39c70625e",
    "RG-F-3db8ed9183b3d123ecd4",
    "RG-F-3dc78accde9de57c71dc",
    "RG-F-3dcfb496c884945bb027",
    "RG-F-3e09c3afa10e851b1219",
    "RG-F-3e1e68cf861d0ee729b9",
    "RG-F-3e24593e62a142567720",
    "RG-F-3e46061a7878caf18c05",
    "RG-F-3e4ee50c3bbc358ad164",
    "RG-F-3e5cfea6823d6bd34974",
    "RG-F-3e66d67cb11e74edd45a",
    "RG-F-3e716eaf9d48d91f2bf3",
    "RG-F-3e801db332ef78d1e469",
    "RG-F-3e946fd54fe20f6f8f01",
    "RG-F-3e9d8167cb9ed1aa4dcb",
    "RG-F-3ea17351735f97af1eb6",
    "RG-F-3ea726c76a58c7dd4800",
    "RG-F-3f02c3348e79ed0c243c",
    "RG-F-3f6d55fa37ffc9f13029",
    "RG-F-3f8506cdc116cdbcd4af",
    "RG-F-3f934fcc0af020d37335",
    "RG-F-3f951f6d1bbf106138ec",
    "RG-F-3faad93fc8e5ed321ddf",
    "RG-F-3ffe3220f383027c50cb",
    "RG-F-40058bf3fe9e9af73c04",
    "RG-F-400aa9c03e695df1d4dc",
    "RG-F-40376c49380eeeaafe87",
    "RG-F-40481fea8e066944e9b4",
    "RG-F-4050375907e571194b90",
    "RG-F-406d6efebce8192e1ef9",
    "RG-F-408cd50aaf435efc6fbe",
    "RG-F-40cee6350d3d57b7786f",
    "RG-F-4109d5d724eba7dbc14c",
    "RG-F-418f664310446b269914",
    "RG-F-41f64260f48f0ecc9ce1",
    "RG-F-42478ba04ed7e7b30232",
    "RG-F-425ee43dd96fc3faa32f",
    "RG-F-4269e256e1890ee9c4fd",
    "RG-F-4285eeed77503f4cb85e",
    "RG-F-428eff40e78b1400b16f",
    "RG-F-439be28c753d959db436",
    "RG-F-43cd730f33f0693305f6",
    "RG-F-440e7f86651bdb352597",
    "RG-F-445256a1fc831affd166",
    "RG-F-44aaa849ab3789113a8d",
    "RG-F-44fcf9a5c35080fabaf4",
    "RG-F-4505d8d72764cdfab19a",
    "RG-F-4562f1242824b48b15df",
    "RG-F-456463060527a73a63e7",
    "RG-F-457da052b0c6e2e7dff4",
    "RG-F-4616eac5c78178841108",
    "RG-F-46555960b50ff8a7af36",
    "RG-F-4655dc12b17bbd1c9327",
    "RG-F-4694bf767d94c8465a6e",
    "RG-F-46bca3423f8a0c445045",
    "RG-F-47aae7a3a360d04d1ded",
    "RG-F-47b0abacb8c8d893905d",
    "RG-F-47cfe058e966a6231980",
    "RG-F-47f1ac1e4f13a8573ee7",
    "RG-F-48049a17cc5f1a31cede",
    "RG-F-480b4ba306002994ab1a",
    "RG-F-481d5cfb4aa791714a25",
    "RG-F-4840d5f092db75abe499",
    "RG-F-484ed51a1834115a3a27",
    "RG-F-48a56f7995926edcd9b1",
    "RG-F-48aac8c78cb933c4176b",
    "RG-F-4927d068a53e3ea3c34b",
    "RG-F-49a8a8820a93d8c302f3",
    "RG-F-49b59976ba308a34c7d1",
    "RG-F-4a0e1b3e1c57a6dccdaf",
    "RG-F-4a138a78091d4292b3ed",
    "RG-F-4a5a1db6c2619e3ae4ee",
    "RG-F-4a74084a8eb51f1cb9e0",
    "RG-F-4a7726c0d1b089f59ff8",
    "RG-F-4ad10191d1a7872cb53b",
    "RG-F-4ae07a419afaed9fbbb9",
    "RG-F-4afaf6bdf6aa7ff87223",
    "RG-F-4b518f1576fc2b643fc7",
    "RG-F-4b890dfe1c63bb81ad5c",
    "RG-F-4bb1e1cc11a7ebbde6b9",
    "RG-F-4be82fedb54a135be9ca",
    "RG-F-4bfae72cb67783eace93",
    "RG-F-4bfcd0fa777a78f7c8c8",
    "RG-F-4cb95f3cc114edafa456",
    "RG-F-4ce3843c5a38edebfed0",
    "RG-F-4cf84fae6ac448305b37",
    "RG-F-4d07b1536a85260f618f",
    "RG-F-4d0d944ef8c3713a9359",
    "RG-F-4d325ddbb71b6f91116e",
    "RG-F-4d37ff30d6d890378621",
    "RG-F-4d4627dace046260c244",
    "RG-F-4d5b069e7b5b1b6dc654",
    "RG-F-4d5e9af28f7111bc731f",
    "RG-F-4d8a7817de76229c59cc",
    "RG-F-4d8c1521cc6856f70e53",
    "RG-F-4dbc7d98ed0b7fdafe36",
    "RG-F-4de51ce227b408d7773d",
    "RG-F-4e1430dcb618565edaac",
    "RG-F-4e6712f8e73ebad664ba",
    "RG-F-4e9f597e3cbe737fd971",
    "RG-F-4eb231db0ce3dbc0e317",
    "RG-F-4f06c84392fb6a92c4c7",
    "RG-F-4f24b91261d816418d21",
    "RG-F-4f30f43e1b156f2b3801",
    "RG-F-4f588705471f3a013d19",
    "RG-F-4f7b3bd59e0e8f713ca9",
    "RG-F-4f8ee16cf1a61b4b0fd8",
    "RG-F-5012f5b1447e3445b75c",
    "RG-F-503a03cb217c238099fb",
    "RG-F-50de6131310f5b88da75",
    "RG-F-5127056353d49f4f310b",
    "RG-F-514124441de603c9f459",
    "RG-F-5162171a14116caec8bf",
    "RG-F-516f819c538656e7f1ee",
    "RG-F-523449ebeae7fd01dc0e",
    "RG-F-525ffc83e802014b19a7",
    "RG-F-527c6d488d343864c630",
    "RG-F-53155036c2a5d8040fbf",
    "RG-F-533a1caf5ebd8375cca0",
    "RG-F-534803143f7406228719",
    "RG-F-53988f8b76d85c9de969",
    "RG-F-53ca36c23ece63eead64",
    "RG-F-5467ca6ccbfc5d1e0067",
    "RG-F-549bf8604d3554dc7e17",
    "RG-F-54beaf76ae263bbffb72",
    "RG-F-54de666ebe8df7ac17e3",
    "RG-F-55086c2ff081a72ded2b",
    "RG-F-550f975b4cfbd7f3bdf7",
    "RG-F-55a062c76c9a718780ba",
    "RG-F-560d456a098aa701eab0",
    "RG-F-5632337a8cde056439c9",
    "RG-F-56d3aaa705ffa0f500a3",
    "RG-F-56da048f5a828d55a296",
    "RG-F-56e570a8b6bb4de29de4",
    "RG-F-56edae331542672fea78",
    "RG-F-57cd91545cb9a99bf507",
    "RG-F-57e3bb9bb87773938b62",
    "RG-F-58041394b6d37447ccfa",
    "RG-F-58060d9146bc920f12b0",
    "RG-F-58305d699a1d71bcd4ce",
    "RG-F-5840c92b94183fda5078",
    "RG-F-58423e675d1c5c2e4ae7",
    "RG-F-58671daf0cf269ceff9e",
    "RG-F-5889d352de12bc64a91e",
    "RG-F-58a733e89770d0232ea5",
    "RG-F-58d02faae81c322574ca",
    "RG-F-58db8f196f01fbb5c334",
    "RG-F-58e00bf983965e129379",
    "RG-F-5954ddef465e441c7f32",
    "RG-F-598f7fd49db8a0469f2f",
    "RG-F-599925663bf4d9151f1b",
    "RG-F-59af58e52ae7d88cbcc6",
    "RG-F-59c782a851bb95fa70ef",
    "RG-F-59eb223f5cd10b89be89",
    "RG-F-5a1cb70a11ae5fa77bc0",
    "RG-F-5a26c0a40802f968d297",
    "RG-F-5a36f8f997d3d89c4b49",
    "RG-F-5a54e368bfdddb229af5",
    "RG-F-5aa3a0cd3b68eeab4eab",
    "RG-F-5aea7bf717efb0009640",
    "RG-F-5b479c2059d687138b32",
    "RG-F-5b59d6e3bd2ff1fa2d80",
    "RG-F-5ba5643fd697173de6ac",
    "RG-F-5bb8de9d0bb377367f86",
    "RG-F-5c1c47d1da97bfa24019",
    "RG-F-5c43cb17756ba919e0cd",
    "RG-F-5c56fd8c342438530acb",
    "RG-F-5d277b8a02e32a875ff6",
    "RG-F-5d34a11fd820a7e53206",
    "RG-F-5d6bbe8bd95dd66461dc",
    "RG-F-5d80d5b2606d7ca76715",
    "RG-F-5da4b6af6663748e71d4",
    "RG-F-5dab412b6695470dfa91",
    "RG-F-5dc1f02ffa0a44a2745a",
    "RG-F-5df78bf86ba2a1677eb4",
    "RG-F-5e0d2590b4c77d1d01e6",
    "RG-F-5e2a9b97305993b92177",
    "RG-F-5e32bb70681f7068331b",
    "RG-F-5e7e439bbb35a8cbbd80",
    "RG-F-5ec52468e51c339dfd37",
    "RG-F-5f487e3d424c1de665d0",
    "RG-F-5f4be06231abdc1b7e3c",
    "RG-F-5f6b775ce05e2aa3a3a1",
    "RG-F-5fc0ac34992e747a365b",
    "RG-F-601eb6f2e436904d662a",
    "RG-F-605cccf75283f3057463",
    "RG-F-609498502ab6e9d82b15",
    "RG-F-609c87590aa8224e5db4",
    "RG-F-60c8e02b13caa1a887e7",
    "RG-F-610aeeebcfc9dd961da3",
    "RG-F-613002f79d3dd2d26aaf",
    "RG-F-6140eb4da25391919c18",
    "RG-F-6159293fccdff9939225",
    "RG-F-61659f5a98e9b24e0927",
    "RG-F-6166e62bb9eb436d6585",
    "RG-F-617d45c1dd4eaca81c67",
    "RG-F-61941c71ce036632c7a7",
    "RG-F-6203ce67d3e9a017c330",
    "RG-F-62415db52a7de09d6668",
    "RG-F-625efd3ab530393b8738",
    "RG-F-62a55372c4fd4fadf642",
    "RG-F-6349804f2fbc18beca5e",
    "RG-F-63649e8fd9baee58868f",
    "RG-F-639c68417a0a043ecc8f",
    "RG-F-63eb2e852641a54b43bb",
    "RG-F-63f3d30e197c8a1dd04d",
    "RG-F-64059e0f20c8611d48e3",
    "RG-F-649e02799a1b63388a00",
    "RG-F-6509151ec7e3d149923a",
    "RG-F-656d43e5c242a377f3a3",
    "RG-F-65c2ac64dc0d2e7c73e0",
    "RG-F-65fcb5472255e00b0c8d",
    "RG-F-65fdaba54f6bec9299b7",
    "RG-F-660098de7b5be80202a6",
    "RG-F-660ad807e1893a47f43f",
    "RG-F-66962b1adf5fce2aa39e",
    "RG-F-669c87153eeca2260979",
    "RG-F-66cf355b52e2e8d2fa18",
    "RG-F-673ad79cd3ddee674eb2",
    "RG-F-67456bc4cb66cc92ba27",
    "RG-F-675749acbb9cdce56b3c",
    "RG-F-67620561238e32eac404",
    "RG-F-677d167932e38cfd8059",
    "RG-F-67ca390476519fd99ec9",
    "RG-F-67e7d0f2aaad08dd5a9d",
    "RG-F-6801c1cf2e5e395a80ca",
    "RG-F-680cf0808c206119d7f4",
    "RG-F-68180042ebf658d3fcdc",
    "RG-F-682e5586723e322580ec",
    "RG-F-68e40e7d11f5272feaf9",
    "RG-F-6900b26937be092cb1ae",
    "RG-F-694605d4eecfaa91f85c",
    "RG-F-697e3cdbd608a51d4f2e",
    "RG-F-698b18bd69c98a8674af",
    "RG-F-69f6d0d40a08a23d66a8",
    "RG-F-6a06fcc4b93cc09ba795",
    "RG-F-6a6339cc2bfa77c6f794",
    "RG-F-6a89f66ce270fe816a93",
    "RG-F-6ac6f45740286b3a48c5",
    "RG-F-6ae93072db274bd7f8f6",
    "RG-F-6afebac8a424ec5586a0",
    "RG-F-6b8e37da55f6ecc8eb92",
    "RG-F-6bc4470db49d0278f22f",
    "RG-F-6be9645b3c8142df8a33",
    "RG-F-6c0c820d8037569de122",
    "RG-F-6c3437711cb053146335",
    "RG-F-6c6bdb1858f0dfae7305",
    "RG-F-6c9cbc9d5528a236c309",
    "RG-F-6cc551ee1fd7a7467895",
    "RG-F-6cebfe241a9ddcf8432a",
    "RG-F-6d0e068e363521799425",
    "RG-F-6d72c6dd6b163aefba91",
    "RG-F-6d8be805614592440f51",
    "RG-F-6e0463d70306112395a2",
    "RG-F-6e116b115a2c22372a63",
    "RG-F-6e1871d56adcb2e298de",
    "RG-F-6e2eddf5972b0c1dc5d0",
    "RG-F-6e50afac0f0003d639dc",
    "RG-F-6e98648b4fff08725466",
    "RG-F-6e99e4ac1d0bf06a43c2",
    "RG-F-6ed189c4cf051831e5f1",
    "RG-F-6ed4b9872da1e1262936",
    "RG-F-6f3483fcb562a345f033",
    "RG-F-6f670e8ba30ea9978e5f",
    "RG-F-6f6f937f8d97de2bc51a",
    "RG-F-6f7f59e3cda2fc6eb79b",
    "RG-F-6f81ff4d1ca421b38c3e",
    "RG-F-6f83ce5c135bfd13e648",
    "RG-F-6f8ba9a952f948f7a707",
    "RG-F-6faa653b5d8213bd5a34",
    "RG-F-6faca00e16168f0d41ef",
    "RG-F-6fc6d4a71ef6637ac545",
    "RG-F-6fd877ebe33c4959701e",
    "RG-F-6fde951fa416a91fd617",
    "RG-F-703f0f2722ff56c4a6bb",
    "RG-F-709d36c8a0a4e5852e56",
    "RG-F-70c79b3f4414d50bc975",
    "RG-F-70ed64c0d98fb1fb8d2e",
    "RG-F-70ef11178981ecccf2df",
    "RG-F-70f0eedccca9fb13d7d1",
    "RG-F-7124d84b3ecc262815ec",
    "RG-F-71aaf4c2c8a8f3873677",
    "RG-F-71bdefedf127b6689235",
    "RG-F-71c6279ce9517f29cdc0",
    "RG-F-71df3cccf2d9bfc2e467",
    "RG-F-71faed99507a39d3bb09",
    "RG-F-71fbef1a57926ccfb925",
    "RG-F-72160c629d357567dbbe",
    "RG-F-722f46ccf95f5da5211a",
    "RG-F-7273958eb0ddc7a00724",
    "RG-F-72d324a426688135fff9",
    "RG-F-7311b30501e17b2d1be5",
    "RG-F-73294745c8e1ba6cbe0c",
    "RG-F-7330cea4820f52e7fcee",
    "RG-F-7332c270de4e0e54f939",
    "RG-F-7336aaebd198e98b8e5c",
    "RG-F-73421a679308837f71ce",
    "RG-F-73550a6421596c5f5a38",
    "RG-F-737889481a3284ff5eaf",
    "RG-F-73972757717189967d4d",
    "RG-F-741cd63b1cd97b9be937",
    "RG-F-7429dfc5e1e42597dbe0",
    "RG-F-74735a22c84e153c4321",
    "RG-F-747987b7456e5577b083",
    "RG-F-74a11a42c908394545b9",
    "RG-F-750a373f3861de31322a",
    "RG-F-7516577594830fc0d141",
    "RG-F-75227e188d4e057c0056",
    "RG-F-755d1e9149216cb7e86b",
    "RG-F-75a7ceddf65ab6560bc3",
    "RG-F-75b04f104053c7be3c4c",
    "RG-F-75c0102fddc24e93a53a",
    "RG-F-760656550daae6c4b5c4",
    "RG-F-761e0935fde69ba1a2ed",
    "RG-F-761ff7e2ac19702ffc0c",
    "RG-F-7626c610ce9c3f6b8db2",
    "RG-F-7643d54c86c72af40d4d",
    "RG-F-768f646bdc051192b889",
    "RG-F-769776db0caf758a7fac",
    "RG-F-777aeae0f3f078555f0f",
    "RG-F-7788601902d755d5dd67",
    "RG-F-7795ec675c08d08fadc1",
    "RG-F-779f4becf09eb82055fa",
    "RG-F-77cdc302e554312d20a7",
    "RG-F-77d7e1929d84d8a9308a",
    "RG-F-78f87617e0afc9bc8e20",
    "RG-F-78fb64b5091e43313636",
    "RG-F-7909a29462b00fbbdb9c",
    "RG-F-79123f1b829342ee6c79",
    "RG-F-79190312ff91ce810f3a",
    "RG-F-7956dcf231ce5f01e9fd",
    "RG-F-7992af31f20c424f1c26",
    "RG-F-7997a6cc7b1fbbc8ef3e",
    "RG-F-79a328c9773747e00c6b",
    "RG-F-79a77e88f92a5d2280a0",
    "RG-F-79ee519c42cab941368a",
    "RG-F-7a3b472134bccd5a97f6",
    "RG-F-7be175134af266d24a85",
    "RG-F-7be2e1aded9403138e2c",
    "RG-F-7c17950c834ea9504242",
    "RG-F-7c79e5490d051ae0608d",
    "RG-F-7c9be11d61453260cff9",
    "RG-F-7ca5bff81674db184bb7",
    "RG-F-7cb6625ae84bc31cae67",
    "RG-F-7d0d68df2338f194eced",
    "RG-F-7d13038a8fa7f7b654d8",
    "RG-F-7d16faddb640f830df37",
    "RG-F-7d22c5b6d380c46be69e",
    "RG-F-7d4bd7950f4297ec32b6",
    "RG-F-7d949a2dc82972bb9f60",
    "RG-F-7d98f24d26ddc207dccb",
    "RG-F-7da7064b9e988bfc9a9a",
    "RG-F-7dd08045097ad54e0ddd",
    "RG-F-7de827d003e76d6c30e5",
    "RG-F-7e31ad5922751fb790cb",
    "RG-F-7e71e31324297f001c9d",
    "RG-F-7e73ad7e651aaf595505",
    "RG-F-7e741a8c504bcc4752ad",
    "RG-F-7e82eb7f0c441de1704f",
    "RG-F-7ec7d8e3acf6434eb376",
    "RG-F-7ed78f16069a0f084e9b",
    "RG-F-7f11b51548c81dde1997",
    "RG-F-7f26061ab9a7abb64ed7",
    "RG-F-7f3ca6e8ede84e9dc429",
    "RG-F-7f3cac9c1d28c3d69c6b",
    "RG-F-7f4499a24e9d5f6e00f6",
    "RG-F-7f4c48378d23c1a5e5ea",
    "RG-F-7f72074e5a3b2f30b2f3",
    "RG-F-7f7d46407bed96bd6757",
    "RG-F-7fa59b5bcf8603857252",
    "RG-F-7fc25f0ba8f3590f8ce5",
    "RG-F-7fd3b572f66f1fb31c5a",
    "RG-F-8000e4daa42f3f3c8e45",
    "RG-F-80b9954cc6245e2a1ae7",
    "RG-F-80be11223c7b4a4b7bbc",
    "RG-F-8103478fa5632787566b",
    "RG-F-811f256e0c355602aba9",
    "RG-F-816e09d0281b3262a658",
    "RG-F-818eb71aaab9e28c0124",
    "RG-F-81a6e185f6e75fa2bba2",
    "RG-F-81afe358ba9923ea7a37",
    "RG-F-81babf287a2265577061",
    "RG-F-81d7915d513231a017b3",
    "RG-F-822fae0d17f3b9ab5d5b",
    "RG-F-826b449b376d040fa113",
    "RG-F-826cc415aa5961285bb2",
    "RG-F-82ed5ecaeb15a4ea56b7",
    "RG-F-82f08ff8f803b2ee3aa0",
    "RG-F-836f64d548ebdf5f7622",
    "RG-F-83817fe0866b1803be05",
    "RG-F-83b05c1fe00356048c26",
    "RG-F-83d9c0e78ccb3713cda7",
    "RG-F-83e853484f56821c1812",
    "RG-F-8438bf2f8da15594e9c7",
    "RG-F-84749c9d1107aad23889",
    "RG-F-8475bca3010e57cf12c0",
    "RG-F-84ac1f8e44214a6e7dd4",
    "RG-F-84b9c2374fd31d45ad7d",
    "RG-F-84cd82d5ddca70d81772",
    "RG-F-854abd426f8d906293fc",
    "RG-F-856104de7b4b35b3b196",
    "RG-F-8571ca4cb763915cffeb",
    "RG-F-859a7ac315865f6b8760",
    "RG-F-85a9a9cb05cba5cd73c7",
    "RG-F-85ce0eb54798067006cd",
    "RG-F-85f37911e4cc908d94be",
    "RG-F-8644167dba914511af35",
    "RG-F-8669410a9972d6085bad",
    "RG-F-86769bd63577238c68e6",
    "RG-F-869a6e6d9c1c6e346dcb",
    "RG-F-86f399f00416ec6e471e",
    "RG-F-87173d6e5ef99c5289ec",
    "RG-F-872e0420b1f365b847b9",
    "RG-F-873ff48e658242435de8",
    "RG-F-8749f746dfd02373363d",
    "RG-F-87903122aa615f9a30bb",
    "RG-F-87c6821a687f43ed3cca",
    "RG-F-87c82bad314b75737658",
    "RG-F-880eb0ffbe6138519833",
    "RG-F-881211834fd817dbfd37",
    "RG-F-881dc1c5a28ba9848707",
    "RG-F-88537f11604ee37c97b8",
    "RG-F-8889f6d8b8e759d8dba4",
    "RG-F-88afc95ae2cd730cbcbc",
    "RG-F-88bb8c20631231472f93",
    "RG-F-88e0290b444504b3758a",
    "RG-F-89391e141ab1dc241643",
    "RG-F-895dc60b19d893033b8f",
    "RG-F-89a3e541d0076fa04da1",
    "RG-F-89be050a0d634f84dd79",
    "RG-F-89d7582f789cb52e5dc0",
    "RG-F-89e7f2f4105b0d16bd06",
    "RG-F-8a21652789ccd6ead05e",
    "RG-F-8a7993e2ea925d23366f",
    "RG-F-8aa5dc00a1f81698124d",
    "RG-F-8aee319041fc15885aa0",
    "RG-F-8b5d5c8e67eea3d005f7",
    "RG-F-8b80a404cabb1f263730",
    "RG-F-8c0ddbdb92bbb01c6e0f",
    "RG-F-8c9e208aeb94f353de11",
    "RG-F-8cb88cfa51a59cf0a96f",
    "RG-F-8cc64cee333b9835f736",
    "RG-F-8ce898b35f4b96fb3028",
    "RG-F-8d0f69692399436cc2b0",
    "RG-F-8d41afa5702311004b3f",
    "RG-F-8d5656235b795f8ebb31",
    "RG-F-8d5c2627bc57c261813a",
    "RG-F-8d622e878f47dfb5761e",
    "RG-F-8d7818eecf4c25ea2fdc",
    "RG-F-8dad27cd32cd1e3eed3c",
    "RG-F-8db0133064b2ee94ab03",
    "RG-F-8e553bd6c64dac2af697",
    "RG-F-8ea52cc8ddc107cb5bd4",
    "RG-F-8eb776b3fa088a50b624",
    "RG-F-8ebc5a9ee110db0da52d",
    "RG-F-8ebed3fdf1b95247ed33",
    "RG-F-8ee0e817a068fbd9f977",
    "RG-F-8f5e58d1a1c044f076cd",
    "RG-F-8f79157fd38de8c5c8a3",
    "RG-F-8f93bbbcb14a6ebc2fc3",
    "RG-F-8fbc5699101b3f510a1c",
    "RG-F-8fbf2f389d0c6c824c78",
    "RG-F-8fd7cc62c810fb242a5a",
    "RG-F-8ff967384a2fc5f96d85",
    "RG-F-902acc84754ee2c2cbe5",
    "RG-F-9062453f0961f46006b4",
    "RG-F-9065e79950510f8deebc",
    "RG-F-90662db55e741859bdb9",
    "RG-F-907ffa0504904b889d3a",
    "RG-F-9097510e3c88af28a026",
    "RG-F-90dadaca4359f714778c",
    "RG-F-90f2e325176921f26d08",
    "RG-F-9107c106059d1f85c322",
    "RG-F-91178bf829fdfc5675a8",
    "RG-F-9141ca5f4bdce44388a0",
    "RG-F-914a13726dfd0b09b621",
    "RG-F-914a4c2787820475d450",
    "RG-F-918ae76454d613b674a3",
    "RG-F-91a81937da48aea15702",
    "RG-F-91b17d759f4c4509c185",
    "RG-F-91b8fbbf0b62f18f97f6",
    "RG-F-91c0b321491c2cf648d3",
    "RG-F-91c1ee30572b68352ee7",
    "RG-F-91e7c34c894253fec8a8",
    "RG-F-921022109ee94dd57a3c",
    "RG-F-922b6bc020ee1c31087b",
    "RG-F-92484cc621f01015c275",
    "RG-F-927c5b68b7157411e3fa",
    "RG-F-928afe49ba6eef3c242e",
    "RG-F-92ad84047e3bac2f3830",
    "RG-F-92d191da91187a29e7f5",
    "RG-F-934308b0b1731db22b6e",
    "RG-F-9382f4598eb174593d93",
    "RG-F-9396874c90d04b9b724a",
    "RG-F-93998f44bde4d69ed502",
    "RG-F-93d4ce0a4a37056809a1",
    "RG-F-9407bd4708cf63508f77",
    "RG-F-940b3e62538fa6ea99b6",
    "RG-F-943f335bfae60678587b",
    "RG-F-949799a34501700c4178",
    "RG-F-94b6b3fb5c6254fee1bf",
    "RG-F-94e0427c0fe68c4fdda2",
    "RG-F-94f2502fa3cf379178d7",
    "RG-F-9547fc0a1a9f78d90fff",
    "RG-F-954c2327aea9b661f9b4",
    "RG-F-95646c7c0446cb4ff942",
    "RG-F-9599a106d8883aa65815",
    "RG-F-959f407b5d68573d1229",
    "RG-F-95afb6d7d6abc288df62",
    "RG-F-95d1a6f481d56bd88dc9",
    "RG-F-95dfff513f38d7e862f5",
    "RG-F-96021001201c82258935",
    "RG-F-961a5e125d9979437452",
    "RG-F-9626432e7f016be31db9",
    "RG-F-96a977d695fc779448c3",
    "RG-F-96bc01a1e64206e70c4c",
    "RG-F-96f3f3838cb786826475",
    "RG-F-975050a3e74f78d9d3a3",
    "RG-F-97c9803f668508561135",
    "RG-F-98334cd7a16d5c30e303",
    "RG-F-98604abc3a26a5861917",
    "RG-F-98706fdd7195c6dd8763",
    "RG-F-987c0c4685c579ad3ef3",
    "RG-F-98831c615b3f85621d7c",
    "RG-F-98bb691f88357760ab57",
    "RG-F-98eeabc61c2227d324ad",
    "RG-F-9924d4b159c4b6b68d36",
    "RG-F-995f2cbbe32f8835fbf3",
    "RG-F-997976ecaa74c228fd83",
    "RG-F-9995fc4165c1cb485085",
    "RG-F-99cc1d691c8875e1c5c2",
    "RG-F-99d5f88fded3a33f33d8",
    "RG-F-99f0f3972bcdff75685b",
    "RG-F-9a228a854efe2682b7f4",
    "RG-F-9a298db1ebc4744c4d81",
    "RG-F-9a39ad97bd6afdeed2b9",
    "RG-F-9a5919c0f999202c5bcd",
    "RG-F-9a99b1b3bb17d4b1e862",
    "RG-F-9b25272766ad22c1893b",
    "RG-F-9b5baba65cd5c883caaa",
    "RG-F-9b7ab326f7ce2943c4fc",
    "RG-F-9b82e56c78598ec8d3cb",
    "RG-F-9ba091eacf52bf03ea4c",
    "RG-F-9bc90d81a5b23d53a9f8",
    "RG-F-9c5128e0eaafa8259771",
    "RG-F-9c5682c5bf6902470cad",
    "RG-F-9ca2df063f21ff5c1ff9",
    "RG-F-9d218b8a48d25e3143c8",
    "RG-F-9dae51657d938d888b36",
    "RG-F-9dcc3492039b01a007b8",
    "RG-F-9de0e0da5b0a23312241",
    "RG-F-9de168de7406c59884f3",
    "RG-F-9e25ba491c2ebdd3f0f0",
    "RG-F-9e36c0fb5daa89f6e75b",
    "RG-F-9efd056431f8364d0be8",
    "RG-F-9f1935e81471cf88494a",
    "RG-F-9f411e55f3dd548b1f5d",
    "RG-F-a0525457da1e800c39b2",
    "RG-F-a053bab0eb89a5e76def",
    "RG-F-a056bf8a072b01959b6d",
    "RG-F-a063637ec7ae9cf2e53f",
    "RG-F-a087d0230d65eb1e87ca",
    "RG-F-a0bc186db4d1b16a5a2c",
    "RG-F-a0d564af318c54be62c0",
    "RG-F-a10d860ce8bc8dd86327",
    "RG-F-a11a156c6318c2df9ed2",
    "RG-F-a11cec0bc00c94f37a70",
    "RG-F-a1284b983985a442d8d1",
    "RG-F-a176e923c63403710964",
    "RG-F-a17aa78c11cf76e74c62",
    "RG-F-a17b3f8d238b2b582d4b",
    "RG-F-a1d8dd79fcfa15352068",
    "RG-F-a20e889267b9f177f1bc",
    "RG-F-a217cd18fd4614f8d658",
    "RG-F-a23181f8846012d8bdc9",
    "RG-F-a28286265c7b51b20c1e",
    "RG-F-a2a0c63c3c7dc2a0cdcf",
    "RG-F-a37a1bb21ebde3d2f37c",
    "RG-F-a3c30e842f3c880c894b",
    "RG-F-a3e7a255e1a701689133",
    "RG-F-a3ecf63fc9578af84b83",
    "RG-F-a410efaafb2a01ba8376",
    "RG-F-a439db5fc11bea7f9d30",
    "RG-F-a43b43b4851399cb487b",
    "RG-F-a44a128249f3eb815765",
    "RG-F-a44fdd592fe99cf1e0ae",
    "RG-F-a47bba9a2f71f1a03ef2",
    "RG-F-a49c806fa9b0aceeedd2",
    "RG-F-a4d0240c14057607786f",
    "RG-F-a4d17900cc35d67a27d1",
    "RG-F-a4dfb8c5132426e884db",
    "RG-F-a4e74e09f6b0ac7e095c",
    "RG-F-a4e9d75bce199463a831",
    "RG-F-a4f1da12634c92e6753c",
    "RG-F-a5092800e14156e24458",
    "RG-F-a51da3d51090399e334a",
    "RG-F-a550a105e102203f7469",
    "RG-F-a5b69ac71c7042021efd",
    "RG-F-a5f8448af3e1739ac5e1",
    "RG-F-a605092ee2d5dee977af",
    "RG-F-a64f3d3e4e7bf3e8c40e",
    "RG-F-a66d90609d169ea01db2",
    "RG-F-a6a4a8e1b2e3566d2893",
    "RG-F-a6b5349e89166706e042",
    "RG-F-a6bd125935c53df33d0a",
    "RG-F-a6dc49d8a82baf22bfb7",
    "RG-F-a6de64906aef1236f7f7",
    "RG-F-a6e0a49a2ee23cbd31aa",
    "RG-F-a7154dfaa3ef8c59cada",
    "RG-F-a727b986e7f2ed89a93e",
    "RG-F-a774ad6c6504a5e131b0",
    "RG-F-a79c0ffaca8d37ac2720",
    "RG-F-a7ab5922150f4f7f47f1",
    "RG-F-a7abb12e6c2c90645ad9",
    "RG-F-a7b190a9cc6699355ab8",
    "RG-F-a7be7c6bbc22947ee915",
    "RG-F-a7e2ad1aa5969100e3ef",
    "RG-F-a7f678a9f1d3c48ba8e1",
    "RG-F-a817d4d9a259152b9e00",
    "RG-F-a81cd9a45c4dab5a0710",
    "RG-F-a83580fcdc51b33aef49",
    "RG-F-a83b1168e338003b703e",
    "RG-F-a89ee9a4c7cb592ddd30",
    "RG-F-a8ad618fb8ab0a87d030",
    "RG-F-a90a8498ecb52ff4ac8c",
    "RG-F-a925bfc61a96482d1122",
    "RG-F-a9520a718c2bdf58a5f4",
    "RG-F-aa0a2cbe229a6f291d54",
    "RG-F-aa2027dd1ad6789cb3ec",
    "RG-F-aa3422ce65da9a1f89cd",
    "RG-F-aa76ee351792ed513e3e",
    "RG-F-aa8e430d8b38a8f2a140",
    "RG-F-aa9136995b0e2b2c2d4a",
    "RG-F-aac3e8659132fb196a16",
    "RG-F-aad4662f2d4def75a3fd",
    "RG-F-abd70ae0f0a63378c816",
    "RG-F-ac11090f8a4f4419f255",
    "RG-F-ac385b3896fbc69af1ad",
    "RG-F-ac69b64441781fc5ee72",
    "RG-F-ac79e4e5034f906bd3c9",
    "RG-F-ac7f4ffeac8f8ef49e9d",
    "RG-F-ac9fd9012e6ee802132b",
    "RG-F-aca2efe1658e0339ca93",
    "RG-F-acb02327690f56609032",
    "RG-F-acc9ba278bd344dff61a",
    "RG-F-accde14462652e255ad8",
    "RG-F-ad0c37b2124e8c259487",
    "RG-F-ad7ccd8f5de3b21d800e",
    "RG-F-ad983834a4ef86502760",
    "RG-F-ada8b71bab89cd3b8c6d",
    "RG-F-adad8cb2382e55250e96",
    "RG-F-adba82208d7b6be78431",
    "RG-F-ae033fdaa9b8f29b0870",
    "RG-F-ae472dbd8da4c6e05ccf",
    "RG-F-ae86cb627afedcf93157",
    "RG-F-ae975f5c15f5bea65bd1",
    "RG-F-af1e44fa513e12f2bb5a",
    "RG-F-af1fad6c42c639175c6f",
    "RG-F-af80018ee474fe10259f",
    "RG-F-af844086a72c72c05543",
    "RG-F-b012142bdb3f9e54adeb",
    "RG-F-b094363a81d24891573b",
    "RG-F-b0ea87f1b544cf77eed5",
    "RG-F-b0f297ffd0622fb16d72",
    "RG-F-b1b574faa2f9b9f7d9f5",
    "RG-F-b1f27ed489d87d8ab2b9",
    "RG-F-b2097cd02eaddc7cf422",
    "RG-F-b21a399a5783e8e1c3de",
    "RG-F-b26561ea983223f81dcf",
    "RG-F-b26e123db8244b36e3f8",
    "RG-F-b3180c27d03aeb110e90",
    "RG-F-b31a57d06ed367f433f5",
    "RG-F-b320803858fa9bd39cd7",
    "RG-F-b3292dac5925be488f9c",
    "RG-F-b34be787885cf85b976b",
    "RG-F-b3947087ae26a6f102b2",
    "RG-F-b3aaa93c05ec91982298",
    "RG-F-b3d8fc2eae5b8ea8ac17",
    "RG-F-b419087b6863a23e74dd",
    "RG-F-b445c51b636b8d0099bb",
    "RG-F-b45202de116db26f14a2",
    "RG-F-b4991bba97dbd3b2549c",
    "RG-F-b5b381eed8d0ca59a904",
    "RG-F-b5c5ee2f99e92a814e05",
    "RG-F-b5d4c1b2b947c862baf8",
    "RG-F-b62086b5bc6e28ab75ff",
    "RG-F-b627a7fe79b11f4af086",
    "RG-F-b63c109e5666f5d8fd7e",
    "RG-F-b64a430bfba641cec0b1",
    "RG-F-b66a8d96a8746b1de067",
    "RG-F-b66f8b518323e763bf98",
    "RG-F-b678e8ea638457c8a7a5",
    "RG-F-b6ae11ee0ecf46345b5d",
    "RG-F-b6e7bb317c76eb7ffbeb",
    "RG-F-b6eb614d70bae44503e6",
    "RG-F-b6f2e000999425bf7813",
    "RG-F-b70b955a6504096ca4c6",
    "RG-F-b715ac464e3e3ee87502",
    "RG-F-b74397fed388a6859c0c",
    "RG-F-b74ea0c3b07e40cea9ce",
    "RG-F-b7549e0dceee70529c2c",
    "RG-F-b8552616c00e1e1f7d4f",
    "RG-F-b86fded4265b54389d2d",
    "RG-F-b899e2a9c8d5f4637766",
    "RG-F-b8b22c8714b6e48f56de",
    "RG-F-b8d6bfcf5c3fb56338d8",
    "RG-F-b8fbe4d4a5788246a42e",
    "RG-F-b98219945eeab5541eae",
    "RG-F-b992a7f938634f6aee23",
    "RG-F-b9daf4eca19e7a6962e8",
    "RG-F-b9ec9cad42de3b32a4ac",
    "RG-F-ba374c84c3bc3a1660b9",
    "RG-F-ba5f8ef92122364caff2",
    "RG-F-baa5ddd3caec2e115053",
    "RG-F-bbfaee69cf5f9114aa49",
    "RG-F-bc29e62b182841de8e90",
    "RG-F-bc3a4504b8d4a435467f",
    "RG-F-bc5692de9cbfe20564c0",
    "RG-F-bc792dd32f5281896a9d",
    "RG-F-bc938f61c14db455df13",
    "RG-F-bce2035ffbf33cf838cb",
    "RG-F-bd0b1d841138f93ffc7d",
    "RG-F-bd1b9b523217b5966375",
    "RG-F-bd1f340d8ac47536c0a2",
    "RG-F-bd228d392b15d2344020",
    "RG-F-bd28d31eb1726e8f807a",
    "RG-F-bd83c71cb4a23c0f60e5",
    "RG-F-bd8dd33e591e6116c90f",
    "RG-F-bdc84c53fafd339065cc",
    "RG-F-be2959aa06baf0410c5d",
    "RG-F-be2cb35dfbde1d5bba30",
    "RG-F-be4fb6bac4aa0d1906a6",
    "RG-F-be70d5c719016295b80d",
    "RG-F-be924328dfc5e9be99a7",
    "RG-F-be9a2bc49c22dbd2d131",
    "RG-F-bf6581a3dbc59f876346",
    "RG-F-bfe8d60ff5c1ca111f37",
    "RG-F-bff94316c26397640848",
    "RG-F-c004a34a7e50854e247c",
    "RG-F-c02df23a1a402a7a4d59",
    "RG-F-c046766d6fae320c6c08",
    "RG-F-c0663e763062272fc331",
    "RG-F-c0cf3926f855614f56d8",
    "RG-F-c0d24bb320a86779a09e",
    "RG-F-c0febe6904b8a43f771c",
    "RG-F-c12b39479cf49fcf9110",
    "RG-F-c155aba255b133d73969",
    "RG-F-c1785da50f233e6656fa",
    "RG-F-c192fde2d44b7e666b31",
    "RG-F-c1c5fb6d272cef0aa292",
    "RG-F-c24d81aefca155bcc5ed",
    "RG-F-c2829f331ac64a859132",
    "RG-F-c2cd9b1cd1190a6f589e",
    "RG-F-c2e996b203ef8de56806",
    "RG-F-c3624bd3b4889e822cfe",
    "RG-F-c3984e736a01c5b32cb9",
    "RG-F-c40f97f5b232a8ee5efc",
    "RG-F-c414e1f8cd6e0c6c3004",
    "RG-F-c46a6290a40a2a73174d",
    "RG-F-c46d1ecd77558ddf0a28",
    "RG-F-c5628e833406f73b2da0",
    "RG-F-c58bd5e5d630cc315643",
    "RG-F-c590866258cd2260a9b8",
    "RG-F-c5910e29ac1ddc7bbce7",
    "RG-F-c5a0824cc0270071380a",
    "RG-F-c60f417aacae8dc4e4be",
    "RG-F-c67125dc3be16b3a668e",
    "RG-F-c6b4cbe3ef21e2a35bc5",
    "RG-F-c6f2b68f1aff04a6c307",
    "RG-F-c718b93e0ba7ebbcecdd",
    "RG-F-c7421d23fc8c01733159",
    "RG-F-c76fed0dc5d271545372",
    "RG-F-c7a2f8e359fb8407b1e0",
    "RG-F-c7b38819595826f0fab9",
    "RG-F-c7d3359e93081883b23e",
    "RG-F-c85e045bb127e74b295b",
    "RG-F-c8b06b90893110694bfc",
    "RG-F-c8b4eb9f35f49bca9617",
    "RG-F-c8d2d13cd579481249d7",
    "RG-F-c902b59e63d9b0f4942a",
    "RG-F-c9075187f0880f0157e4",
    "RG-F-c91bff4b51d85702ed12",
    "RG-F-c95cb65217bb0a15dded",
    "RG-F-c97d282b21560bc9331b",
    "RG-F-c9aacc1c4a51b4569b4d",
    "RG-F-c9bc535e77aafdedaa16",
    "RG-F-c9d5dc000041096d3298",
    "RG-F-c9f5376f0271a331ad38",
    "RG-F-ca114588fb8038785490",
    "RG-F-ca441dbefacf380b8983",
    "RG-F-ca4a3b00f39d28ee0b70",
    "RG-F-ca68513b5a09b7bfc884",
    "RG-F-ca712a934ff4b67c9f82",
    "RG-F-ca73f21f3aed9f1fd25b",
    "RG-F-ca9cb5a796366653c170",
    "RG-F-cac4e168c42e02cc2398",
    "RG-F-cad5d0984a72d2a42db3",
    "RG-F-cafdb4c963a1a26f7093",
    "RG-F-cb22b558e2b17b3e2222",
    "RG-F-cb29856d5f1914a83cfe",
    "RG-F-cb37147022180eeb9575",
    "RG-F-cb3af3928456507d780a",
    "RG-F-cb80c7052ff9545e4c04",
    "RG-F-cb8b4f27a437ada8d295",
    "RG-F-cba1ca033fe56fb95dc4",
    "RG-F-cbcddb4f51051843f896",
    "RG-F-cbd439bcb7baf098ebd5",
    "RG-F-cbe35d574f6ccc9470a8",
    "RG-F-cc32d670f33a582bd625",
    "RG-F-cc3467c0325479704011",
    "RG-F-cc58a2a17a33c2df4d83",
    "RG-F-ccaacb7c0c1dd0239e8a",
    "RG-F-ccaaf582cb3d30dfd6eb",
    "RG-F-cd2741ab696196b985a4",
    "RG-F-cd3e068e86e28630cf07",
    "RG-F-cd4695baba82d214e2db",
    "RG-F-cdb1f89a461f2bc26b35",
    "RG-F-ce29c77d4e9789b04c57",
    "RG-F-cea9601ee8e40245ed69",
    "RG-F-cf2eab2bc7330bee7b3c",
    "RG-F-cf3026c6eac6d9629146",
    "RG-F-cf4484dc8ce13c8cbe78",
    "RG-F-cf4874ed2fc9f815e1a8",
    "RG-F-cf89bc751903461d0ca8",
    "RG-F-d02a2e8f5374b72249cf",
    "RG-F-d02cde8da152024586fc",
    "RG-F-d046747e237d67d14a52",
    "RG-F-d0be2b9c83077fbada35",
    "RG-F-d0d50aaad9c1b97abb0e",
    "RG-F-d1050c8dffbc32319ae3",
    "RG-F-d107556e805df3ef37fe",
    "RG-F-d11f2561685ecd08d12d",
    "RG-F-d1271f08594059b16449",
    "RG-F-d1617722fc22543228c8",
    "RG-F-d174fbfcace857dd19b9",
    "RG-F-d18af6e7aacac4ddb137",
    "RG-F-d1b0a47649b86f32c6e4",
    "RG-F-d1bd414f498437fcfef1",
    "RG-F-d1e87f1db990e9a3dff8",
    "RG-F-d20c5571513ec921bedb",
    "RG-F-d26508b5acc22dd2c8ba",
    "RG-F-d26ff0730f4dd1953bd7",
    "RG-F-d28236646a8ee6e5432b",
    "RG-F-d2a6efd33943f99876b9",
    "RG-F-d2af6cc3f6e7ab6e7233",
    "RG-F-d3200d53527e1d49e51d",
    "RG-F-d32afbca5b6288094d4a",
    "RG-F-d32d6d0777af2e5e1ea4",
    "RG-F-d338d4aba27d715b2426",
    "RG-F-d34ea849989b46e4e33d",
    "RG-F-d351dd1ff1a711ef6348",
    "RG-F-d35790e114b75ce36b37",
    "RG-F-d3d09a0ed811a54e22ce",
    "RG-F-d3f9a1967eafbfaf2606",
    "RG-F-d404e3987a4e8055e687",
    "RG-F-d4277f02ed7fa4b7acc3",
    "RG-F-d447b25283be8b480306",
    "RG-F-d4898c55d03d24ea127b",
    "RG-F-d4c56cbdb2d3967b8730",
    "RG-F-d4c64aed03a3a7a894ae",
    "RG-F-d5192d4bb702b4b04d40",
    "RG-F-d5b5db9e2dd32fe953c1",
    "RG-F-d5b62cebb39f2db34ea5",
    "RG-F-d662ce4ff6b1e05276bb",
    "RG-F-d673c13e10ca3f173943",
    "RG-F-d679d71be0316c5fe01f",
    "RG-F-d71d3c5ba226b67dbd28",
    "RG-F-d71eced7a31c275ba4a5",
    "RG-F-d724e5a49a607822eb48",
    "RG-F-d7439297fe0226e8f157",
    "RG-F-d746d5fe277c46b2549e",
    "RG-F-d7903ab5798b5a63e58b",
    "RG-F-d7e42f6cd54d2d8ef40a",
    "RG-F-d84d923a6982ef17c93e",
    "RG-F-d863ece7689f79033e9a",
    "RG-F-d8737819cf9ac78c826e",
    "RG-F-d89d31552c9bb1a8c999",
    "RG-F-d8a98b8e42974ba30f33",
    "RG-F-d8b7326c097a95362d3c",
    "RG-F-d8c8e9e569cea1210a14",
    "RG-F-d8e0a50ea15b7f15c23f",
    "RG-F-d8ffb7a35df5c67c2d49",
    "RG-F-d97fd0c2a20d3aa3a13b",
    "RG-F-d9947b943dee35a77365",
    "RG-F-d99fa5c7afa61344fc16",
    "RG-F-d9aeb8302e862ae5189f",
    "RG-F-d9d3da946c12ed8260f7",
    "RG-F-da41a32aa74380f61ec8",
    "RG-F-dac4347444de4944748e",
    "RG-F-dae4c854f1f8dcc4fc43",
    "RG-F-dafcb780cdc32cfd54f0",
    "RG-F-db1d89e77bb4f2275a78",
    "RG-F-db2500172d8259f2b712",
    "RG-F-db6a99a982c10626a563",
    "RG-F-db76e284561fdd79e78d",
    "RG-F-db8197b84e837c600be3",
    "RG-F-dc332234d471d2b2c8ab",
    "RG-F-dca6302aaa3634df916c",
    "RG-F-dcb4b42205187137997c",
    "RG-F-dd608a681de67dbc3f1c",
    "RG-F-dd6d19a5377dc3679c04",
    "RG-F-dd7abbc4c55c63e7965f",
    "RG-F-dda78dd3b0861c1d4969",
    "RG-F-ddb47b1b80b524b60a2a",
    "RG-F-ddbe4fb41d78bfe430dd",
    "RG-F-ddc410446c37a82d3629",
    "RG-F-ddc50c8da3c7d49340f2",
    "RG-F-ddcca3e697279ebe7c54",
    "RG-F-dde339495439ee6cd994",
    "RG-F-de05b7ef5a84b6c2c139",
    "RG-F-de5a4f22e8c1a8add747",
    "RG-F-de6224893317e5fbfb2e",
    "RG-F-deba560ad7910c30291e",
    "RG-F-dec293bcd6b0000c8d1f",
    "RG-F-dee19639691e1e7892a2",
    "RG-F-dee9882fd9d8f5007618",
    "RG-F-dee99407e8e26734fd9c",
    "RG-F-df19443ad63dfc6b2fb1",
    "RG-F-df1ba2b7dadf70a834a3",
    "RG-F-df2f243dfdeea0f544d7",
    "RG-F-df4ba766d66b72066a1e",
    "RG-F-df8aed776091cdabd260",
    "RG-F-df9d9585292b9d153982",
    "RG-F-dfc7d3bfa1c1d97086b3",
    "RG-F-dfc91dc60e9bcaeea46d",
    "RG-F-dfea358014337a412f40",
    "RG-F-e00510968e7bff545520",
    "RG-F-e059a8d51227f7fb92fd",
    "RG-F-e074a8442ca5358a2029",
    "RG-F-e0985097c0b943e5d037",
    "RG-F-e0f55c142097006999a2",
    "RG-F-e119b509eb026635ba44",
    "RG-F-e1389a6f4f36b32ee6b6",
    "RG-F-e13bd5f54140ff90a737",
    "RG-F-e19cadfded7122ab2ac5",
    "RG-F-e19d523167faaeb32710",
    "RG-F-e1c46b6cf3814287a883",
    "RG-F-e2018b945a2a552a7822",
    "RG-F-e23c2a89ac310efa47af",
    "RG-F-e25eb9a4a169a5f9a4c8",
    "RG-F-e2ae768e78b0f9d2407f",
    "RG-F-e30cadbed26529bf4283",
    "RG-F-e331793eab883ca998a7",
    "RG-F-e37176d1751548991b46",
    "RG-F-e38ade47dd7a1d5864de",
    "RG-F-e39be0e41ecede4c0688",
    "RG-F-e43529c7de5adfc21cb9",
    "RG-F-e44c471df07293c101b4",
    "RG-F-e459e248733955c5418a",
    "RG-F-e4da037bc0cc32e2d859",
    "RG-F-e4e606b96ec0762b2786",
    "RG-F-e4f898ef03faf91f8f23",
    "RG-F-e54aa0f584468456aacd",
    "RG-F-e5632e4f36ea77045d6b",
    "RG-F-e62b252cb1219b2952f3",
    "RG-F-e655cdd47b1cf899bf84",
    "RG-F-e6aac6160036788b58db",
    "RG-F-e6d44fe6157734ea6fa8",
    "RG-F-e6e93636b838c329c329",
    "RG-F-e6f46c0676c7a93140e8",
    "RG-F-e6f7a196c2cd7dc7d374",
    "RG-F-e70d8901d08c59cf4f17",
    "RG-F-e72ff64bf310c44c7f92",
    "RG-F-e74f0ae51b62f2fae88e",
    "RG-F-e75e2b91e06438896f05",
    "RG-F-e7cb855a090805b40db6",
    "RG-F-e81038bd7e4a2065a5fe",
    "RG-F-e81a0462e451ef76ad81",
    "RG-F-e827556737420d828661",
    "RG-F-e853107bb8af0732b4af",
    "RG-F-e870edfc62e77b4c067f",
    "RG-F-e89edfcf565609a7c8ba",
    "RG-F-e8abee68a26660a4df0c",
    "RG-F-e8e2357f4ba354faacd8",
    "RG-F-e8f4c2cca65795f7aab1",
    "RG-F-e92a2fc7dcac930e233d",
    "RG-F-e95324941bc04daa0363",
    "RG-F-e954b5b2ebed9fb08b89",
    "RG-F-e9a33eae35da9b837918",
    "RG-F-e9bdf0cf00b82d833119",
    "RG-F-e9d5cadbcfb6d22c0eca",
    "RG-F-e9f17974c69ca17d65cd",
    "RG-F-ea07893c8b1882d9f0d6",
    "RG-F-ea3c67d98535a5bda66b",
    "RG-F-ea48dc05a786b6f83b68",
    "RG-F-eaa082e7f810cfad5d94",
    "RG-F-eacfde4c231a4fe2924c",
    "RG-F-eb1349863e98d980d3e3",
    "RG-F-eb1d20a8e64db78d6aa7",
    "RG-F-eb239d310603b3d34bc9",
    "RG-F-eb2a0d2e9a8c20d296fe",
    "RG-F-eb38452b14a10154fa6b",
    "RG-F-eb6871cff1504f6300ed",
    "RG-F-eb6a1384046628b4ae4f",
    "RG-F-eb854938b0c92f55db66",
    "RG-F-eb8b640bfcd9be7fd671",
    "RG-F-eb9dfdbc7087f2eb1485",
    "RG-F-ebe12c96c7b144704b47",
    "RG-F-ec0b6eece1b8d0ce4a55",
    "RG-F-ec30ce965c3e7629b9a5",
    "RG-F-ec5918a7c276fe9f0d78",
    "RG-F-ec7149a3f12e21885a05",
    "RG-F-ec78931ef77b110a71e0",
    "RG-F-ecc39c3ed64d0fa081a6",
    "RG-F-ed3a71a8c4fc7680bc06",
    "RG-F-ed543a215c3691361673",
    "RG-F-ed6cb8563bdadf54edba",
    "RG-F-edb97ddbc11c8680ec61",
    "RG-F-ede2eebaf51cb8bad142",
    "RG-F-ede7a6974d33939aca2f",
    "RG-F-edf2c381916c42ae4b4f",
    "RG-F-ee13784cda431d900ed5",
    "RG-F-ee27394e6d440f6a7b4c",
    "RG-F-ee5b44dddb0d95807f5e",
    "RG-F-eea7497cf84727c9d5e8",
    "RG-F-eea9a9cd3a780f13551a",
    "RG-F-eed82752ae03018eb5db",
    "RG-F-eef41041ac8e520895ee",
    "RG-F-ef2a045480d66e75091c",
    "RG-F-efc848bdd2b79b8cd683",
    "RG-F-efce8a4b10651aa4e2a1",
    "RG-F-efcf794f8358682dd6e9",
    "RG-F-f002b67af15d16668e6b",
    "RG-F-f011b1701c64da6523fc",
    "RG-F-f0131826bce98f80cda8",
    "RG-F-f013a403aaae2a00ace3",
    "RG-F-f019e346957b535ab455",
    "RG-F-f03bae6585682e8447b8",
    "RG-F-f0791b5d5cf938bebb01",
    "RG-F-f094bb239e3cfa774b1d",
    "RG-F-f0a9a9e2ddecf0519081",
    "RG-F-f0c872a033d6ed8d2afc",
    "RG-F-f0cecbc341fcb11177b2",
    "RG-F-f0f21aeddd1a5c16311d",
    "RG-F-f0f333849a07e7e33040",
    "RG-F-f1448d084686cf246f28",
    "RG-F-f1573abb1a956c17b6c2",
    "RG-F-f166902701b56d286655",
    "RG-F-f186b158f204003d40e4",
    "RG-F-f1cff46f8e1bed98d770",
    "RG-F-f22b2cc8fe8d331c4b19",
    "RG-F-f2543a2ff7315ed0bc19",
    "RG-F-f2584f2f4f7724c0459d",
    "RG-F-f26ece470eb2c0bb6ebb",
    "RG-F-f2afae8f6d9c3f4fe90e",
    "RG-F-f2b3b16ba32af9e3e34d",
    "RG-F-f2d88551b79c980795da",
    "RG-F-f32afee2de00e53e2938",
    "RG-F-f356f8624ee12d3b0eba",
    "RG-F-f38af2d94a8509c75a54",
    "RG-F-f395adbcd1456b05fc54",
    "RG-F-f4081d4e2b4ac823eb98",
    "RG-F-f41320c540657f4c06f5",
    "RG-F-f41d129cd8c5f74d04ce",
    "RG-F-f44ba1e7583dd76ff22a",
    "RG-F-f483e99efdf25c509c5b",
    "RG-F-f49957f86cf3228cbd9f",
    "RG-F-f4a37fc066f4a7fa7875",
    "RG-F-f4dcaba911138303c5e1",
    "RG-F-f4f223640f8b96bee830",
    "RG-F-f5093044d5e344d8211f",
    "RG-F-f51a020fd73cf25438c2",
    "RG-F-f58a503bf0dbaaadedc3",
    "RG-F-f596e70e9ca6b6981c7d",
    "RG-F-f5c0b8bb0089c09179b7",
    "RG-F-f638f5fbf25254ea4a2d",
    "RG-F-f674a1d032dd73a99351",
    "RG-F-f686327ca3b831d8151e",
    "RG-F-f6be8154ecf0cdae791b",
    "RG-F-f6dc557cded942cfa22c",
    "RG-F-f6ec13ccf523ead15526",
    "RG-F-f6f561f5e4f521efc203",
    "RG-F-f79fdd18a3dbc03a2fbe",
    "RG-F-f7da420b609916e78b68",
    "RG-F-f814b653b778db226e7c",
    "RG-F-f8305f268aaa07bf8676",
    "RG-F-f83534827af595642dff",
    "RG-F-f84373ff1e155a4acd7f",
    "RG-F-f88ec61f93f16d7d988e",
    "RG-F-f92a0edb2515064a69d7",
    "RG-F-f94c5a527806ecdace48",
    "RG-F-f9b4694d60058a4b24e0",
    "RG-F-f9cbb84da58fb370770b",
    "RG-F-fa1f2de3112e0f15627b",
    "RG-F-fa245174a9d2e9cb8393",
    "RG-F-fa6e23e05a0058769ae2",
    "RG-F-fa7f7686c00b62605ebb",
    "RG-F-fa8ec6d371b37cee7587",
    "RG-F-fa917bdf89cc8d767995",
    "RG-F-faa153452df183c01d62",
    "RG-F-fabd6ed370dadf216dfc",
    "RG-F-fb4b6c06d2934461776d",
    "RG-F-fbba2371c1e3ee574c60",
    "RG-F-fbc21ba2af6028d4782b",
    "RG-F-fbcd45668c13a4c2a502",
    "RG-F-fc1399613f96ca3e9fcb",
    "RG-F-fc9614ae62a5ca22047d",
    "RG-F-fd0bd9bd27931e1b8240",
    "RG-F-fd18c72db47c3fe0c86b",
    "RG-F-fd6d96df7d494a7a3b22",
    "RG-F-fd82c9d5598cf4e2837b",
    "RG-F-fdc56656082534066c8d",
    "RG-F-fdd80511b012fef20a24",
    "RG-F-fdf70b1f866d0c07943d",
    "RG-F-fe9713f4b622955e432b",
    "RG-F-fe9b0a62c42abc10fcab",
    "RG-F-fefdb48c92ee9155d8c7",
    "RG-F-ff1584966c896f73c5b8",
    "RG-F-ff1924f87ac5baa0fb04",
    "RG-F-ff47a45e9db8b2646a01",
    "RG-F-ff4dba765a53c9d625d3",
    "RG-F-ff54d55ca0d3822cdf67",
    "RG-F-ff741eec389f6e2c6e18",
    "RG-F-ff8c7477404415d54a4f",
    "RG-F-ff97d77a517bc0fe600d",
    "RG-F-ff9e56b34d4facda44b5",
    "RG-F-ffbacacd70c8654d1cd0",
    "RG-F-ffd3261e9186d27ad615",
}

# Non-mut-binding successors must be added here with exact commit, ID, path,
# and blob pins; every rule fires exactly once and the replay refuses any
# removal that no rule proves.  Deletions get reviewed tombstone rules; a
# class introduced and deleted entirely inside the window (never pinned in
# any ledger) is retired by an ephemeral rule instead, because schema 1
# cannot encode an introduced-then-deleted origin.
CONTINUITY_REVIEWED_TRANSITIONS: tuple[dict[str, str], ...] = (
    {
        "base_id": "RG-F-72110be65453cf3d1587",
        "from_id": "RG-F-72110be65453cf3d1587",
        "to_id": "RG-F-49837dd5483eee6ce607",
        "commit": "0d2252dd631677ef221d8266f1267090fecd45da",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "child_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "review": "set_block_range: block-range bounds u64 to Address (0d2252d)",
    },
    {
        "base_id": "RG-F-09d0ffc3ccbb554e789c",
        "from_id": "RG-F-09d0ffc3ccbb554e789c",
        "to_id": "RG-F-cd924c7bc3e50d8e6a9b",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "fallthru: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-29f1bd831bde716de5c4",
        "from_id": "RG-F-29f1bd831bde716de5c4",
        "to_id": "RG-F-813b027ebcd5353c4236",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "finish_process_instruction: shared-return override consumption "
                  "(Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-c9811edb9fb50bdcbb02",
        "from_id": "RG-F-c9811edb9fb50bdcbb02",
        "to_id": "RG-F-3e640a9b136c4a824063",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "generate_ops: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-7d56bab7c0eede6b219e",
        "from_id": "RG-F-7d56bab7c0eede6b219e",
        "to_id": "RG-F-493eb3dfad4a42d40802",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "5f8dbeb93c233836b195418d007da8291f4483e5",
        "child_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "review": "override_flow: shared-return override consumption (Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-fd655d6b3856412c7d46",
        "from_id": "RG-F-fd655d6b3856412c7d46",
        "to_id": "RG-F-e45cf642507c156f4831",
        "commit": "33793c130fed5a7d0ecb858293dfcfd7bc23b88e",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "8907ccac7517b1044b0921bffcecc1344b4eab11",
        "child_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "review": "process_instruction: shared-return override consumption "
                  "(Result returns) (33793c1)",
    },
    {
        "base_id": "RG-F-2c988c04aca0f061a836",
        "from_id": "RG-F-2c988c04aca0f061a836",
        "to_id": "RG-F-8ba6690d9b3d452c451e",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "build_callother_op: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-c292ca37d2c29dfc9361",
        "from_id": "RG-F-c292ca37d2c29dfc9361",
        "to_id": "RG-F-ff7130f442132a11fd55",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "follow_flow: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-681b63f29b27de3a4123",
        "from_id": "RG-F-681b63f29b27de3a4123",
        "to_id": "RG-F-b0bd0fd9650c8dc041d9",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "generate_blocks: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-420b7f1781eaae99bb0c",
        "from_id": "RG-F-420b7f1781eaae99bb0c",
        "to_id": "RG-F-da6d2d3c6a3a39b28deb",
        "commit": "3be7b24cf66fdea133cbbb748ba771586d420b5d",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "c76bd681b78b55e7855769e5e6d438df8c8c4cc2",
        "child_blob": "a51548151141f22102a5d5440332a795b31bb289",
        "review": "split_basic: flow truncation error channel (Result returns) (3be7b24)",
    },
    {
        "base_id": "RG-F-d21d7ad7d37f851c09ed",
        "from_id": "RG-F-d21d7ad7d37f851c09ed",
        "to_id": "RG-F-73c5c36f5fc7758afb22",
        "commit": "577e54bb32aa0ff6c167f5b3bff5a71807439a0a",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "754391522125b69d12f73bdf301598c773afca38",
        "child_blob": "8b0b009a152525dae09c3977072ce86742b8b86c",
        "review": "propagate_from_pointer: pointee propagation gated by dereference width (577e54b)",
    },
    {
        "base_id": "RG-F-9a532c938b1d72c03c1d",
        "from_id": "RG-F-9a532c938b1d72c03c1d",
        "to_id": "RG-F-1692e4d449f0e322a223",
        "commit": "594ed4fa74e895390cbe105e1b0af8afed3aeb7f",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "3f1abd38c977843feb98f9cac30d6bf0779a9ac8",
        "child_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "review": "order_recurse: typefactory layout-preserving definitions (594ed4f)",
    },
    {
        "base_id": "RG-F-b5ab805b4b3320aeb1fa",
        "from_id": "RG-F-b5ab805b4b3320aeb1fa",
        "to_id": "RG-F-32dc11b88842073b5fec",
        "commit": "594ed4fa74e895390cbe105e1b0af8afed3aeb7f",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "3f1abd38c977843feb98f9cac30d6bf0779a9ac8",
        "child_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "review": "resolve_incomplete_typedefs: typefactory layout-preserving definitions (594ed4f)",
    },
    {
        "base_id": "RG-F-cb1453367426bab70b42",
        "from_id": "RG-F-cb1453367426bab70b42",
        "to_id": "RG-F-14308901657e8b225fe7",
        "commit": "805cf887d96b97f85a4b979bf408145e87a22a45",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "child_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "review": "register_trial: register_trial returns bool for tagged spaces (805cf88)",
    },
    {
        "base_id": "RG-F-9f45a266fb8458156812",
        "from_id": "RG-F-9f45a266fb8458156812",
        "to_id": "RG-F-8da24b5ec162432b2e21",
        "commit": "87f9309b5a98af929c765925dbf55b427121d8f7",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "2abd23b88562e6aa23712d78c9edd7a3ac3ffa63",
        "child_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "review": "decode: fspec paramlist output dispatch expansion (87f9309)",
    },
    {
        "base_id": "RG-F-e74efd0e7cd7b12c51d9",
        "from_id": "RG-F-e74efd0e7cd7b12c51d9",
        "to_id": "RG-F-165d45a203c4b7b0a40d",
        "commit": "87f9309b5a98af929c765925dbf55b427121d8f7",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "2abd23b88562e6aa23712d78c9edd7a3ac3ffa63",
        "child_blob": "a93b1fbde0c5fbc4e287544752e5761c0affe202",
        "review": "possible_param: fspec paramlist output dispatch expansion (87f9309)",
    },
    {
        "base_id": "RG-F-7472347f6d20c447c6ef",
        "from_id": "RG-F-7472347f6d20c447c6ef",
        "to_id": "RG-F-4eb112e335ddc8f1c3b5",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "child_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "review": "clone_for_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-ec2d50c00923e0d5796d",
        "from_id": "RG-F-ec2d50c00923e0d5796d",
        "to_id": "RG-F-0706966789d474fb68e6",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "compare_callspecs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-e4e3f26824bc65a83baf",
        "from_id": "RG-F-e4e3f26824bc65a83baf",
        "to_id": "RG-F-150fcf46b07d4de67214",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "child_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "review": "delete_call_spec: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-56aa5a2cb39adcdaa0e7",
        "from_id": "RG-F-56aa5a2cb39adcdaa0e7",
        "to_id": "RG-F-665caf5de788197a7ddb",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "0d186b599d149430849b0c4e8b3a2453746690cd",
        "child_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "review": "find_call_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-cf9c7ee152384ba37e38",
        "from_id": "RG-F-cf9c7ee152384ba37e38",
        "to_id": "RG-F-873b743824356fbc98b7",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "6d8cd933d880d5c104ae30410e82538087282e1d",
        "child_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "review": "find_callspec_for_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-89d1a3bc65108b92a474",
        "from_id": "RG-F-89d1a3bc65108b92a474",
        "to_id": "RG-F-02aff009ce146122520e",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-b1c59d7c1ce83f3fc877",
        "from_id": "RG-F-b1c59d7c1ce83f3fc877",
        "to_id": "RG-F-bdbeb8a17dfc1773937a",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs_mut: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-6875a1df88043187e59d",
        "from_id": "RG-F-6875a1df88043187e59d",
        "to_id": "RG-F-aeed1ce92fc04c5aaf17",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "get_call_specs_of_op: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-5923eb2467cb55ffa55f",
        "from_id": "RG-F-5923eb2467cb55ffa55f",
        "to_id": "RG-F-7f644254abac1693b1ff",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "review": "new_varnode_call_specs: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-5833ec87d885664efa5f",
        "from_id": "RG-F-5833ec87d885664efa5f",
        "to_id": "RG-F-85943640e89de9a361c8",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "cffe8789412f9984882e1fc52b3a20bda46e8b2b",
        "child_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "review": "score_parameter: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-e7ba51c17a135fa5e918",
        "from_id": "RG-F-e7ba51c17a135fa5e918",
        "to_id": "RG-F-746a8b9fa443b0ba04a6",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "cffe8789412f9984882e1fc52b3a20bda46e8b2b",
        "child_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "review": "score_return_type: callspec identity lifecycle (Arc owner handles) (cad41c2)",
    },
    {
        "base_id": "RG-F-f828f9d8a2f59aebb57b",
        "from_id": "RG-F-f828f9d8a2f59aebb57b",
        "to_id": "RG-F-9e79ed98d1092ec72737",
        "commit": "e9a0b7a8911af7f85fb180bef7b50d43f19712c5",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "3c69834d53507811ff1d34c5fdd40086c65f3ab4",
        "child_blob": "365be16020196337d386eb215f0b280ece383847",
        "review": "merge_test_must: merge_test_must returns Result under address-tied gates (e9a0b7a)",
    },
    {
        "base_id": "RG-F-0746077b8faf709f4115",
        "from_id": "RG-F-0746077b8faf709f4115",
        "to_id": "RG-F-1e70a0af95480224f97e",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "register_action_named: action pool cloning allows optional action (bd8e38e)",
    },
    {
        "base_id": "RG-F-140645eda9c6178626bb",
        "from_id": "RG-F-140645eda9c6178626bb",
        "to_id": "RG-F-d336771e87bc3eea28e2",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "add_action_in_group: ActionRestartGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-944ce9ba0db019417ecc",
        "from_id": "RG-F-944ce9ba0db019417ecc",
        "to_id": "RG-F-f37cb83185100090045d",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "child_group: ActionRestartGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-a579c006e0aba9709bc6",
        "from_id": "RG-F-a579c006e0aba9709bc6",
        "to_id": "RG-F-a3f39e93d5b9660d6899",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "add_action_in_group: ActionGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-dd1379a84ce1f896ce22",
        "from_id": "RG-F-dd1379a84ce1f896ce22",
        "to_id": "RG-F-0b56e116e3afefd18da3",
        "commit": "bd8e38e474d1402592d25c6b97749bfe42e2ab50",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "4ab1068cde61e05570d0941243b5e89ab098934f",
        "child_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "review": "child_group: ActionGroup group lifetime &'static str to &str (bd8e38e)",
    },
    {
        "base_id": "RG-F-664cdbe7f00113f64327",
        "from_id": "RG-F-664cdbe7f00113f64327",
        "to_id": "RG-F-23ff4924c25b1bbdf96d",
        "commit": "e3e005336fc86b80542430416b849b9696907d80",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "1dd8e20179e169cd354864f6bac696238ce36069",
        "child_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "review": "new: TypeOpManager takes shared type factory (e3e0053)",
    },
    {
        "base_id": "RG-F-53d171f3bfd9713df232",
        "from_id": "RG-F-53d171f3bfd9713df232",
        "to_id": "RG-F-3104bf41dea30e902230",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/variable.rs",
        "to_path": "src/variable.rs",
        "parent_blob": "20b3f095aa2ae9b813e78281140c8a9304fec9fb",
        "child_blob": "6060cb596b31185d8a395bc78816c4082ea9ef32",
        "review": "finalize_datatype: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-59a3a5731573081b334f",
        "from_id": "RG-F-59a3a5731573081b334f",
        "to_id": "RG-F-e10b314f1c23d10fa36f",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "840e08ae133f285857b0b5ab2a19839976f96c0e",
        "child_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "review": "update_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-81f4ae9753655126716c",
        "from_id": "RG-F-81f4ae9753655126716c",
        "to_id": "RG-F-9555f089ef1a40cbf80e",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "840e08ae133f285857b0b5ab2a19839976f96c0e",
        "child_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "review": "get_sized_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-de86f142eac0c451b496",
        "from_id": "RG-F-de86f142eac0c451b496",
        "to_id": "RG-F-4b68743471f19aa81df9",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "child_blob": "de9ecc914f2fc2cc65b246f8462dfbf26b39f33c",
        "review": "local_symbol_sized_type: exact-piece threading through TypeFactory (f87e4d8)",
    },
    {
        "base_id": "RG-F-81748a75f8538c62a9f7",
        "from_id": "RG-F-81748a75f8538c62a9f7",
        "to_id": "RG-F-ffc6810a059dd112231b",
        "commit": "3fa28023bf4cb0356b23747a97b798df97a57f3c",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "93b94c83a3c33fc218170cc559c266fbf4ab4f22",
        "child_blob": "fc60ceb1de127ce56f1a0adf6088b54e388fcba7",
        "review": "down_chain: virtual dispatch takes orig datatype not TypePointer (3fa2802)",
    },
    {
        "base_id": "RG-F-85bdc46a384c692a66c3",
        "from_id": "RG-F-85bdc46a384c692a66c3",
        "to_id": "RG-F-a5c06a03ffec24675436",
        "commit": "3fa28023bf4cb0356b23747a97b798df97a57f3c",
        "from_path": "src/type_system/typefactory.rs",
        "to_path": "src/type_system/typefactory.rs",
        "parent_blob": "93b94c83a3c33fc218170cc559c266fbf4ab4f22",
        "child_blob": "fc60ceb1de127ce56f1a0adf6088b54e388fcba7",
        "review": "down_chain_pointer: virtual dispatch takes orig datatype not TypePointer (3fa2802)",
    },
    {
        "base_id": "RG-F-2c8bc5541245d8b6fec5",
        "from_id": "RG-F-2c8bc5541245d8b6fec5",
        "to_id": "RG-F-3bb2edeafbf9ec2e3fef",
        "commit": "0f0a060ccd79bdfd78723d33056906778ce2ed7b",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "child_blob": "d1cf58c87fe4869cd8aa9c8aa0cc9cb042328288",
        "review": "get_input_local: TypeOp local defaults drop underscore bindings (0f0a060)",
    },
    {
        "base_id": "RG-F-3840b2aa55741a564b42",
        "from_id": "RG-F-3840b2aa55741a564b42",
        "to_id": "RG-F-b8ad1086fc47b0b0e8f8",
        "commit": "0f0a060ccd79bdfd78723d33056906778ce2ed7b",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "de0f7b944502d199e4a531307d04bff6e8da7a78",
        "child_blob": "d1cf58c87fe4869cd8aa9c8aa0cc9cb042328288",
        "review": "get_output_local: TypeOp local defaults drop underscore bindings (0f0a060)",
    },
    {
        "base_id": "RG-F-2282417c93d08f203cd9",
        "from_id": "RG-F-2282417c93d08f203cd9",
        "to_id": "RG-F-5c1a94676a8a8172bfdd",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "from_path": "src/stringmanage.rs",
        "to_path": "src/stringmanage.rs",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "review": "get_string_data: GhidraStringManager Java contract signature (11371d5)",
    },
    {
        "base_id": "RG-F-9f084ffd4f7bca8a8785",
        "from_id": "RG-F-9f084ffd4f7bca8a8785",
        "to_id": "RG-F-ecbbaedaac3eea1407e1",
        "commit": "7b1da21a3a874598423a4b6b941eb2209545fc15",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "a9179e6432deabd7f9dfd228ed71a94a5d1ff2ba",
        "child_blob": "e5f011d57cba1ed13a4690af964c25a92de3b9af",
        "review": "deindirect: noreturn predicate removed from inherited surface (7b1da21)",
    },
    {
        "base_id": "RG-F-353d179342f1b8c88e5b",
        "from_id": "RG-F-353d179342f1b8c88e5b",
        "to_id": "RG-F-4fc23f9164942392a358",
        "commit": "c042d9a2fac9934806c6e93702fbaaf5d1859a04",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "af7630a51fb0912a494c87fbb34d2a8c513584d5",
        "child_blob": "669fb3487998479941a2a28d1fe4fd70fff422ad",
        "review": "new_with_default: MapState window range vector (c042d9a)",
    },
    {
        "base_id": "RG-F-4cdd5bd19c95d3404ef9",
        "from_id": "RG-F-4cdd5bd19c95d3404ef9",
        "to_id": "RG-F-e2b08074d7ef80d46a19",
        "commit": "c042d9a2fac9934806c6e93702fbaaf5d1859a04",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "af7630a51fb0912a494c87fbb34d2a8c513584d5",
        "child_blob": "669fb3487998479941a2a28d1fe4fd70fff422ad",
        "review": "new: MapState window range vector (c042d9a)",
    },

    {
        "base_id": "RG-F-7e4b009ae1d8d5f62495",
        "from_id": "RG-F-7e4b009ae1d8d5f62495",
        "to_id": "RG-F-8ae418e1953a52a1525c",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_constant_typed: gains vn/op context for the TYPE_SPACEBASE &DAT arm (01712a22)",
    },
    {
        "base_id": "RG-F-dae04c9c907df09546fa",
        "from_id": "RG-F-dae04c9c907df09546fa",
        "to_id": "RG-F-278468edac56855d183b",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_partial_symbol: gains space context for the TYPE_SPACEBASE &DAT arm (01712a22)",
    },
    {
        "base_id": "RG-F-3dde2c94bf8d902d5057",
        "from_id": "RG-F-3dde2c94bf8d902d5057",
        "to_id": "RG-F-bc69c26bf6c937ea608a",
        "commit": "01712a22f679a8edfee0fa7483aca179f243286c",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "2c664422614089f21dc74d6444c220ce2e650266",
        "child_blob": "4a49544aeb54f863fbdc8b30cee076e2099fb59f",
        "review": "push_ptr_char_constant: gains ct/op context for the pointer-char constant arm (01712a22)",
    },
    {
        "base_id": "RG-F-85317e7aebd33b457844",
        "from_id": "RG-F-85317e7aebd33b457844",
        "to_id": "RG-F-98be7769343f7b648186",
        "commit": "0e9aadfb57ea395905fd20bb289539b98eba3d98",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "8cc5d32fece98f1bf7cf6e01cfa85d24b16b8415",
        "child_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "review": "get_local_type: gains type_factory param; STOP early-return + full localType dispatch (0e9aadfb)",
    },
    {
        "base_id": "RG-F-d9bbc5bf257eba661cde",
        "from_id": "RG-F-d9bbc5bf257eba661cde",
        "to_id": "RG-F-a87f5098b9cb3d94a709",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "from_path": "src/options.rs",
        "to_path": "src/options.rs",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "review": "apply: p3 binding now consumed by the 12.0.4 bit semantics (1644180d)",
    },
    {
        "base_id": "RG-F-6f6a818a4e632357b615",
        "from_id": "RG-F-6f6a818a4e632357b615",
        "to_id": "RG-F-0345c93508ad882e10c3",
        "commit": "17e0a639318c0d1248ace608f6a975b8ced85d2c",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "15d1b123a975915a62ee661414b16c4e9cbba5dc",
        "child_blob": "d135ae48b234a97c157a019368b938ef5a5c0ac9",
        "review": "reset: fd binding now consumed by the breakpoint-aware pool executor (17e0a639)",
    },
    {
        "base_id": "RG-F-c1ee72b6e2546281e74f",
        "from_id": "RG-F-c1ee72b6e2546281e74f",
        "to_id": "RG-F-0eb65941d5d8f3ff01fc",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "review": "split_load: gains in_type param for the exact-piece gate chain (26d675e7)",
    },
    {
        "base_id": "RG-F-0e57c9f536067337d286",
        "from_id": "RG-F-0e57c9f536067337d286",
        "to_id": "RG-F-5d4cb90317ed3e77a0b1",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "review": "split_store: gains out_type param for the exact-piece gate chain (26d675e7)",
    },
    {
        "base_id": "RG-F-a952489a1e2a692af4c1",
        "from_id": "RG-F-a952489a1e2a692af4c1",
        "to_id": "RG-F-19772f7e6c72893d19e5",
        "commit": "28a28b1f2059d6f6e854df9bfaa544e4a9fb2a51",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "b1b03416fc4a292ce8b744318b0cb653f440f823",
        "child_blob": "b822eb0d2cd3f8dc9b59bf0217902c42e3695390",
        "review": "justified_contain_range: gains space endianness param (FSPEC-JUSTIFIED-ENDIAN-0002) (28a28b1f)",
    },
    {
        "base_id": "RG-F-51aa66bc4efbef5ce41c",
        "from_id": "RG-F-51aa66bc4efbef5ce41c",
        "to_id": "RG-F-68b7284fc2778ca40e41",
        "commit": "55ef99439ea5944369cd1e9ad19607c84d3e08b8",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "child_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "review": "assumed_extension: gains leading space param (space-aware possible_param) (55ef9943)",
    },
    {
        "base_id": "RG-F-67827efc2b3b4d4016b9",
        "from_id": "RG-F-67827efc2b3b4d4016b9",
        "to_id": "RG-F-3cd23de12de85f61b589",
        "commit": "55ef99439ea5944369cd1e9ad19607c84d3e08b8",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "child_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "review": "assumed_extension: gains query_space param (space-aware possible_param) (55ef9943)",
    },
    {
        "base_id": "RG-F-29b64f515e2cc6b8a2d7",
        "from_id": "RG-F-29b64f515e2cc6b8a2d7",
        "to_id": "RG-F-55f51939bbaf977e476c",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-48cebeae7b1f1b743e6f",
        "from_id": "RG-F-48cebeae7b1f1b743e6f",
        "to_id": "RG-F-328f0cee2b4153e006ab",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-6e9e5fc5dff33182265c",
        "from_id": "RG-F-6e9e5fc5dff33182265c",
        "to_id": "RG-F-60ce0f7505bfbf56fd42",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-903e4bede9d3b38af7ac",
        "from_id": "RG-F-903e4bede9d3b38af7ac",
        "to_id": "RG-F-3d84fca029aa0db125c4",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-b7b473477f7a70c35483",
        "from_id": "RG-F-b7b473477f7a70c35483",
        "to_id": "RG-F-12e5d41fb77844c41884",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-db63a0620cae7f35a1e5",
        "from_id": "RG-F-db63a0620cae7f35a1e5",
        "to_id": "RG-F-58043a6f46ae1c9b28c7",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "build_addresses: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-2ffe7f84827bd91a7a70",
        "from_id": "RG-F-2ffe7f84827bd91a7a70",
        "to_id": "RG-F-fdc4cfca398f53a8cc43",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "find_normalized: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-12a1ac7520a2936215cc",
        "from_id": "RG-F-12a1ac7520a2936215cc",
        "to_id": "RG-F-90a0ee5d5692ac0705d6",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-1500b403d31dc09fa484",
        "from_id": "RG-F-1500b403d31dc09fa484",
        "to_id": "RG-F-bc273d6ed95b82759e0b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-1a0de177364519004226",
        "from_id": "RG-F-1a0de177364519004226",
        "to_id": "RG-F-7877c3db7566ba00b383",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-83f03eae691bb0f57956",
        "from_id": "RG-F-83f03eae691bb0f57956",
        "to_id": "RG-F-5722d20b8628b430605b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-9b9f309fc6f60e4b3272",
        "from_id": "RG-F-9b9f309fc6f60e4b3272",
        "to_id": "RG-F-a3e8132b5200c04bc8bc",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-a0778ccb56479e37c576",
        "from_id": "RG-F-a0778ccb56479e37c576",
        "to_id": "RG-F-7f5eae81c0f3bc99e3f3",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-dbcf028e82133b9565c3",
        "from_id": "RG-F-dbcf028e82133b9565c3",
        "to_id": "RG-F-070808d769156b8f203d",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "recover_model: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-ef67f0f933f00d59516d",
        "from_id": "RG-F-ef67f0f933f00d59516d",
        "to_id": "RG-F-601eb1ab580c9774525d",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "review": "sanity_check: jumptable model-selection chain signature (JUMPTABLE-PIPELINE-0001 seg1) (73b5ef26)",
    },
    {
        "base_id": "RG-F-ba5f8ef92122364caff2",
        "from_id": "RG-F-ba5f8ef92122364caff2",
        "to_id": "RG-F-9abcbe19cd51f069dcce",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "base_local_type: gains metatype param for getBase(size, ctor meta) (8e5944ca)",
    },
    {
        "base_id": "RG-F-1696a469c1e4f234a381",
        "from_id": "RG-F-1696a469c1e4f234a381",
        "to_id": "RG-F-0725ce4eafd7506761ce",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-39e123daf5f57401f23b",
        "from_id": "RG-F-39e123daf5f57401f23b",
        "to_id": "RG-F-e2da956f10d8f38b8bfd",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-471897415751e5d275d8",
        "from_id": "RG-F-471897415751e5d275d8",
        "to_id": "RG-F-dde1a3ccdb9db5f6d490",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-885b524a8f76bbb842bd",
        "from_id": "RG-F-885b524a8f76bbb842bd",
        "to_id": "RG-F-fb859141aef85785ef0f",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-a33c0fce3605345a648e",
        "from_id": "RG-F-a33c0fce3605345a648e",
        "to_id": "RG-F-591ad2963b9ceb809480",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-afcc95cc17357bffe136",
        "from_id": "RG-F-afcc95cc17357bffe136",
        "to_id": "RG-F-25034d16aceabddf9230",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-cc32cb3caeaee660aa33",
        "from_id": "RG-F-cc32cb3caeaee660aa33",
        "to_id": "RG-F-0cd5548a65347108ceb2",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "review": "get_input_local: slot binding now consumed by the getBase dispatch (8e5944ca)",
    },
    {
        "base_id": "RG-F-32b69c55e48850549780",
        "from_id": "RG-F-32b69c55e48850549780",
        "to_id": "RG-F-914ebd32697eb67d4df6",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "review": "truncate_indirect_jump: fail_mode u8 becomes the typed truncation mode (b8da22a8)",
    },
    {
        "base_id": "RG-F-b963ca1fc0328358033f",
        "from_id": "RG-F-b963ca1fc0328358033f",
        "to_id": "RG-F-333df7b03f2b23fe523c",
        "commit": "c37044b8420f80a73ffa16fed6941f760c5b02ba",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "b822eb0d2cd3f8dc9b59bf0217902c42e3695390",
        "child_blob": "60dce4ad46631a8ba4521e2da55f6f115b153731",
        "review": "find_entry: space Option becomes a required AddressSpace (resolver find-window gating) (c37044b8)",
    },
    {
        "base_id": "RG-F-85317e7aebd33b457844",
        "from_id": "RG-F-98be7769343f7b648186",
        "to_id": "RG-F-e1751080679995008f76",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "get_local_type: CALLOTHER arm added to the localType dispatch (userops thread) (c5a421dd)",
    },
    {
        "base_id": "RG-F-44fcf9a5c35080fabaf4",
        "from_id": "RG-F-44fcf9a5c35080fabaf4",
        "to_id": "RG-F-4e04105edbeff7dd0eaa",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "op_input_type_local: CALLOTHER arm added to the input localType dispatch (c5a421dd)",
    },
    {
        "base_id": "RG-F-efcf794f8358682dd6e9",
        "from_id": "RG-F-efcf794f8358682dd6e9",
        "to_id": "RG-F-94a2b6bd1410db433619",
        "commit": "c5a421dd82cff21c6abcd754008a275657b2a86f",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "1c05d7e2d2a27dbb3e971c9b428dc9afefae4747",
        "child_blob": "4f6dc0fb33ad2bf574b2c1699af712036e837976",
        "review": "op_output_type_local: CALLOTHER arm added to the output localType dispatch (c5a421dd)",
    },
    {
        "base_id": "RG-F-5da2232cfccfbc48236b",
        "from_id": "RG-F-5da2232cfccfbc48236b",
        "to_id": "RG-F-147b2914b0460c3b7e89",
        "commit": "c9daaeb58d8c2d8fe2872ae1e015303a35ef42b0",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "64fad62b6c9ad3ec69cb293947c3931d5568bc00",
        "child_blob": "4c78b645cd26782006884344fbb68b1f27f5a6de",
        "review": "map_scope: qpoint binding now consumed by queryContainer/queryProperties (c9daaeb5)",
    },
    {
        "base_id": "RG-F-9e35fb6c959b18a5a1ba",
        "from_id": "RG-F-9e35fb6c959b18a5a1ba",
        "to_id": "RG-F-9e79bde7c5d1fb8f92c3",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "open_branch: returns Option<usize> under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-e1c8120aff0b2b2ab02d",
        "from_id": "RG-F-e1c8120aff0b2b2ab02d",
        "to_id": "RG-F-92442e738d9250d093f2",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "retire_branch: returns Option<usize> under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-bb20c591cf86c2a9f868",
        "from_id": "RG-F-bb20c591cf86c2a9f868",
        "to_id": "RG-F-c9feebcf8cdadccd5d46",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "from_path": "src/tracedag.rs",
        "to_path": "src/tracedag.rs",
        "parent_blob": "86545928d1c129fe81f7b015e96d0423587227b9",
        "child_blob": "e12d39bf91c0512f3c20e9b37bba4cb7d49ce74f",
        "review": "select_bad_edge: &self becomes &mut self under the goto-cascade oracle (cddcefd8)",
    },
    {
        "base_id": "RG-F-d8e0a50ea15b7f15c23f",
        "from_id": "RG-F-d8e0a50ea15b7f15c23f",
        "to_id": "RG-F-d03ae0650e666c500a8e",
        "commit": "d9171ef107031ef5e21dea980319fe6e9982311f",
        "from_path": "src/space.rs",
        "to_path": "src/space.rs",
        "parent_blob": "b27aad8584fe8e4b87b19b35c330e31e66a6ab17",
        "child_blob": "97f05c9ebace339d9ad904438687c8134c0acf4b",
        "review": "decode_attributes: gains spc_manager codec context (packed special-space codec) (d9171ef1)",
    },
    {
        "base_id": "RG-F-208f18dc3bc2543b44b9",
        "from_id": "RG-F-208f18dc3bc2543b44b9",
        "to_id": "RG-F-bdbde6f78df46af9dd05",
        "commit": "f95369a92955988783e0148c496f3a91a95d47ed",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "94730ba339462aabed58e22d45748196acae1095",
        "child_blob": "402ff52d848e396d0cfffaab35167e0e658f2060",
        "review": "call_op_indirect_effect: gains leading space param (guard fl query) (f95369a9)",
    },
    {
        "base_id": "RG-F-c07f97463d7249eed59e",
        "from_id": "RG-F-c07f97463d7249eed59e",
        "to_id": "RG-F-edd4713c9bdadd7ab3e4",
        "commit": "f95369a92955988783e0148c496f3a91a95d47ed",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "94730ba339462aabed58e22d45748196acae1095",
        "child_blob": "402ff52d848e396d0cfffaab35167e0e658f2060",
        "review": "normalize_write_size: gains leading space param (guard fl query) (f95369a9)",
    },

    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-3a923bfee6882417fc96",
        "from_id": "RG-F-057e8e805c9d6f3e0545",
        "to_id": "RG-F-2a34c9f6095ee64fb93b",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_proto: drop param [storage: &X86_64GccStorage]; gain param [model_carrier: &FuncProto] (26eee4ad)",
    },
    {
        "base_id": "RG-F-0dbef8d4c630c37f0f20",
        "from_id": "RG-F-0dbef8d4c630c37f0f20",
        "to_id": "RG-F-10bd03523f37860dd01b",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "get_active_output: returns -> Option<&ParamActive> -> -> &ParamActive (26eee4ad)",
    },
    {
        "base_id": "RG-F-24db94981a0293b2e2b5",
        "from_id": "RG-F-24db94981a0293b2e2b5",
        "to_id": "RG-F-25ed035b36f7473c2032",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_callsite_proto: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-9e895a3a0250ae83b691",
        "from_id": "RG-F-36f312ac16b8aeb056bf",
        "to_id": "RG-F-56e4e3f45e08c5c2f01d",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "review": "func_link_input: returns  -> -> Result<()> (26eee4ad)",
    },
    {
        "base_id": "RG-F-403c62b545e4c4c6862a",
        "from_id": "RG-F-403c62b545e4c4c6862a",
        "to_id": "RG-F-d767ef0840705c775605",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "get_active_input: returns -> Option<&ParamActive> -> -> &ParamActive (26eee4ad)",
    },
    {
        "base_id": "RG-F-407c79f6fb505c89bd8b",
        "from_id": "RG-F-407c79f6fb505c89bd8b",
        "to_id": "RG-F-f6c32b17adf47c37ff5f",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "void_signature_dwarf_prototype_pins_unknown_model: rename: void input list keeps the caller-bound model (fspec.cc decode modellock) (26eee4ad)",
    },
    {
        "base_id": "RG-F-73f78dcee4467e087cd2",
        "from_id": "RG-F-73f78dcee4467e087cd2",
        "to_id": "RG-F-1eb0987634d9064bb18a",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "review": "proto_has_input_errors: param _proto:&crate -> &crate (26eee4ad)",
    },
    {
        "base_id": "RG-F-9bc90d81a5b23d53a9f8",
        "from_id": "RG-F-9bc90d81a5b23d53a9f8",
        "to_id": "RG-F-2a845dc07da7597798b6",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "locked_proto: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-a99abc66852a3dff734e",
        "from_id": "RG-F-a99abc66852a3dff734e",
        "to_id": "RG-F-1ce28154f6b860b85d1e",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "review": "apply: drop param [storage: &X86_64GccStorage] (26eee4ad)",
    },
    {
        "base_id": "RG-F-c0ee2922e77c9119c79f",
        "from_id": "RG-F-c0ee2922e77c9119c79f",
        "to_id": "RG-F-f69d8955656e7dadd499",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "assign_address: param dt:&Datatype -> &Arc<Datatype> (26eee4ad)",
    },
    {
        "base_id": "RG-F-c385cd66a20c157f5332",
        "from_id": "RG-F-c385cd66a20c157f5332",
        "to_id": "RG-F-9fcd346dc88678c0690c",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "dd96fa9045a1c139a553a12d011fb5e2206b2db0",
        "child_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "review": "assign_address_fallback: param tp:&Datatype -> &Arc<Datatype> (26eee4ad)",
    },
    {
        "base_id": "RG-F-02af378dcb9608ea64b2",
        "from_id": "RG-F-02af378dcb9608ea64b2",
        "to_id": "RG-F-92db0ea13919ec8be271",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "set_default_switch: move: trait default re-hosted as mirroring free fn (block.cc:318 FlowBlock::setDefaultSwitch) (2d78b5af)",
    },
    {
        "base_id": "RG-F-183a83727d39b25f669d",
        "from_id": "RG-F-183a83727d39b25f669d",
        "to_id": "RG-F-0f8fe610df74d4044b50",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/blockaction.rs",
        "to_path": "src/block.rs",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "build_copy: move: free build_copy(sblocks, bblocks) becomes BlockGraph::build_copy(&mut self, graph) (2d78b5af)",
    },
    {
        "base_id": "RG-F-1847710578ba36f41a2c",
        "from_id": "RG-F-1847710578ba36f41a2c",
        "to_id": "RG-F-fdec08b5119c673abb6c",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "get_out: param _slot:usize -> usize (2d78b5af)",
    },
    {
        "base_id": "RG-F-1a0435a14acc3aa3522b",
        "from_id": "RG-F-1a0435a14acc3aa3522b",
        "to_id": "RG-F-f2222bbb6aa727fbb4d8",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "get_in: param _slot:usize -> usize (2d78b5af)",
    },
    {
        "base_id": "RG-F-2030541ea9b02a722a22",
        "from_id": "RG-F-2030541ea9b02a722a22",
        "to_id": "RG-F-6fe47f3146f53627e732",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "add_out_edge: param _edge:BlockEdge -> BlockEdge (2d78b5af)",
    },
    {
        "base_id": "RG-F-24364fbcca97705e6585",
        "from_id": "RG-F-24364fbcca97705e6585",
        "to_id": "RG-F-1dd7a348a0462e68228e",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "add_in_edge: param _edge:BlockEdge -> BlockEdge (2d78b5af)",
    },
    {
        "base_id": "RG-F-5b884c90f4650cb85895",
        "from_id": "RG-F-5b884c90f4650cb85895",
        "to_id": "RG-F-59926f42e76a1316cad6",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "review": "_get_change_count: rename: LoopBody::GetChangeCount moved to CollapseStructure::getChangeCount annotation (2d78b5af)",
    },
    {
        "base_id": "RG-F-bbd8e4d05192bc9c2e93",
        "from_id": "RG-F-bbd8e4d05192bc9c2e93",
        "to_id": "RG-F-08a1b796e1c02e6be764",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "negate_condition: param toporbottom:bool -> bool (2d78b5af)",
    },
    {
        "base_id": "RG-F-abf77d064f1ec656081b",
        "from_id": "RG-F-abf77d064f1ec656081b",
        "to_id": "RG-F-426390a6112c3dbc6c2b",
        "commit": "3dc4b2ae3c2b7a29104a26aa54c56d36380bdb70",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "add44383796bbd787055caae7aa406d02d236d4f",
        "child_blob": "8bf645e06a62cffeda585f4d853cf5895ce4fc05",
        "review": "try_output_stack_guard: gain param [locked_output_storage: Option<(Address, i32)>] (3dc4b2ae)",
    },
    {
        "base_id": "RG-F-003416535aaee2f83d44",
        "from_id": "RG-F-003416535aaee2f83d44",
        "to_id": "RG-F-81062ccc03179475b483",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "f8215674fd7558ef4d609c8a296dd8b4d67ea47b",
        "child_blob": "1d914b9597164fd5cc46518d1384d1ed2eb67862",
        "review": "query_container_entry_parent_scope: returns -> Option<(u64, std::sync::Arc<std::sync::RwLock<crate::data -> -> Option<( u64, std::sync::Arc<std::sync::RwLock<crate::dat (3fb97c11)",
    },
    {
        "base_id": "RG-F-11a5ff425fc4c01b4da8",
        "from_id": "RG-F-11a5ff425fc4c01b4da8",
        "to_id": "RG-F-bfadcbc9981a3a281fff",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "get_mult_coeff: returns -> (std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode -> -> ( std::sync::Arc<std::sync::RwLock<crate::varnode::Varnod (3fb97c11)",
    },
    {
        "base_id": "RG-F-13b326553ae8f9898f77",
        "from_id": "RG-F-13b326553ae8f9898f77",
        "to_id": "RG-F-c43098d7d6918b6b28b5",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/type_system/cast.rs",
        "to_path": "src/type_system/cast.rs",
        "parent_blob": "ea420513dfb61cf6dc7be78d03c5910a2cc88bb5",
        "child_blob": "f66af728bc8fe488919cedfb1687368060b20c95",
        "review": "check_int_promotion_for_compare: drop param [op_type: &Datatype]; gain param [op: &PcodeOp; slot: usize] (3fb97c11)",
    },
    {
        "base_id": "RG-F-1a31e6c2b34252958c71",
        "from_id": "RG-F-1a31e6c2b34252958c71",
        "to_id": "RG-F-051d6dc01af5e493d722",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_last_op: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-1f9c977e2c885a2fcd1c",
        "from_id": "RG-F-1f9c977e2c885a2fcd1c",
        "to_id": "RG-F-9e8d3ad4aa0167ab2793",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "test_early_removal_register_output_blocked: rename: REGISTER output now removed under pass-1 strict delay instead of blanket block (3fb97c11)",
    },
    {
        "base_id": "RG-F-35caa9e455d7c3452c64",
        "from_id": "RG-F-35caa9e455d7c3452c64",
        "to_id": "RG-F-00bc5c5c59d8e247f17e",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "build_op: returns -> (crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::varn -> -> ( crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::var (3fb97c11)",
    },
    {
        "base_id": "RG-F-3aae0be2241ef765314f",
        "from_id": "RG-F-3aae0be2241ef765314f",
        "to_id": "RG-F-2160ffb27d9d6b5a7f8d",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "get_boolean_result: returns -> (Option<std::sync::Arc<std::sync::RwLock<crate::varnode:: -> -> ( Option<std::sync::Arc<std::sync::RwLock<crate::varnode: (3fb97c11)",
    },
    {
        "base_id": "RG-F-4519b750d13bed433120",
        "from_id": "RG-F-4519b750d13bed433120",
        "to_id": "RG-F-7ab0b03534ee5b2ef25c",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/type_system/cast.rs",
        "to_path": "src/type_system/cast.rs",
        "parent_blob": "ea420513dfb61cf6dc7be78d03c5910a2cc88bb5",
        "child_blob": "f66af728bc8fe488919cedfb1687368060b20c95",
        "review": "check_int_promotion_for_compare: drop param [op_type: &Datatype]; gain param [op: &PcodeOp; slot: usize] (3fb97c11)",
    },
    {
        "base_id": "RG-F-78f6c10072ae947b9b26",
        "from_id": "RG-F-78f6c10072ae947b9b26",
        "to_id": "RG-F-29239adf25ac56679a79",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "check_clog: returns -> ( i32, Option<(crate::address::Address, usize)>, ) -> -> ( i32, Option<(crate::address::Address, usize)>) (3fb97c11)",
    },
    {
        "base_id": "RG-F-856e53a8550be68cc92e",
        "from_id": "RG-F-856e53a8550be68cc92e",
        "to_id": "RG-F-bf6865da3e03b11eafae",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "child_blob": "a7dea226400f647d5db435bc4f1302236c6ecb16",
        "review": "new_block_if: drop param [negated: bool] (3fb97c11)",
    },
    {
        "base_id": "RG-F-5c67bfa2b4dafad127e9",
        "from_id": "RG-F-885ac55c9454c2379e9b",
        "to_id": "RG-F-55b083f921edad907204",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_block_structured: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-8d0c27bf0ef286bbf8b4",
        "from_id": "RG-F-8d0c27bf0ef286bbf8b4",
        "to_id": "RG-F-b970909461534a9c9b3e",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "make_atom_for_vn: param _op:&PcodeOp -> &PcodeOp (3fb97c11)",
    },
    {
        "base_id": "RG-F-8fbf2f389d0c6c824c78",
        "from_id": "RG-F-8fbf2f389d0c6c824c78",
        "to_id": "RG-F-2303c505805d68842c9a",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_entry_address: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-a176e923c63403710964",
        "from_id": "RG-F-a176e923c63403710964",
        "to_id": "RG-F-0e446c2b7aa88ef6b4a2",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_flow_basic: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-cbd102e6173cd8cf0653",
        "from_id": "RG-F-ac045b62b01e997d6bab",
        "to_id": "RG-F-5701b1ca48b5f80a7e9f",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "is_block_body_empty: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-c1f21ae5ca7ac7e7aa3c",
        "from_id": "RG-F-c1f21ae5ca7ac7e7aa3c",
        "to_id": "RG-F-3a3073abf02fbff97aca",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "build_near_mult: returns -> (crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::varn -> -> ( crate::op::PcodeOpRef, std::sync::Arc<RwLock<crate::var (3fb97c11)",
    },
    {
        "base_id": "RG-F-c7d3359e93081883b23e",
        "from_id": "RG-F-c7d3359e93081883b23e",
        "to_id": "RG-F-e5567279d4d848c68284",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "emit_flow_block: param block_arc:&std -> &std (3fb97c11)",
    },
    {
        "base_id": "RG-F-cffb162ddc3991a0c693",
        "from_id": "RG-F-cffb162ddc3991a0c693",
        "to_id": "RG-F-b98549747f90bdc02553",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "child_blob": "a7dea226400f647d5db435bc4f1302236c6ecb16",
        "review": "new_block_if_else: drop param [negated: bool] (3fb97c11)",
    },
    {
        "base_id": "RG-F-dfc7d3bfa1c1d97086b3",
        "from_id": "RG-F-dfc7d3bfa1c1d97086b3",
        "to_id": "RG-F-5d59c2f260f92a5d1e58",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "flow_next_in_flow: param block_arc:&std -> &std; returns -> Option< std::sync::Arc< std::sync::RwLock<dyn crate::bloc -> -> Option< std::sync::Arc< std::sync::RwLock<dyn crate::bloc (3fb97c11)",
    },
    {
        "base_id": "RG-F-8f4e504512ee200863f5",
        "from_id": "RG-F-e52849a77a9002740164",
        "to_id": "RG-F-4c2d5f93a06006739d44",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "propagate_type_edge: gain param [active_path: &std::collections::HashSet<u64>]; param temps:&TempTypes -> &mut TempTypes (3fb97c11)",
    },
    {
        "base_id": "RG-F-f64771d7c6cdb9599854",
        "from_id": "RG-F-f64771d7c6cdb9599854",
        "to_id": "RG-F-bcee4c5acad4b0d3d723",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "5135162a626b55df13c381c54d7efa669d8db4f9",
        "child_blob": "8c3af8f0602f09477975f38d601c803c60a2375c",
        "review": "build_localtypes: param int_types:&IntTypes -> &IntTypes; param ptr_size:usize -> usize; returns  -> -> Result<()> (3fb97c11)",
    },
    {
        "base_id": "RG-F-3175e312a1638de63b65",
        "from_id": "RG-F-3175e312a1638de63b65",
        "to_id": "RG-F-f10f42d013ccec324dcb",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_type: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-45d25c0eb3e56e0ece17",
        "from_id": "RG-F-45d25c0eb3e56e0ece17",
        "to_id": "RG-F-d4778a26bbcf40edc07f",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_across_returns: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-69082e1a1446056c0929",
        "from_id": "RG-F-69082e1a1446056c0929",
        "to_id": "RG-F-68019a8fe1aec0a0531a",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_one_type: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-8f4e504512ee200863f5",
        "from_id": "RG-F-8f4e504512ee200863f5",
        "to_id": "RG-F-e52849a77a9002740164",
        "commit": "463664610f23956530f627e28f9388a6af858a99",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "70ee13a05dcdc6ee28edbf84bdee655b9619db4b",
        "child_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "review": "propagate_type_edge: gain param [type_factory: Option<&Arc<RwLock<crate::type_system::typefac] (46366461)",
    },
    {
        "base_id": "RG-F-77adb336f064e67308a6",
        "from_id": "RG-F-77adb336f064e67308a6",
        "to_id": "RG-F-e659f766cf51c63bdac0",
        "commit": "4a4bd5c626a32c491be8cd4a2283890118bf92ae",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "18d3743bfc296841f92b9e60cff2157445b993ff",
        "child_blob": "19783ed47f4dd8ec46a0f8aa5c09945068d22068",
        "review": "emit_likely_edges: drop param [&self]; gain param [&mut self] (4a4bd5c6)",
    },
    {
        "base_id": "RG-F-3a923bfee6882417fc96",
        "from_id": "RG-F-3a923bfee6882417fc96",
        "to_id": "RG-F-057e8e805c9d6f3e0545",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "8c3eafbe1797839b0530ec4d05e8aac7db5d435e",
        "child_blob": "4f631611c0899990cd78cb2070603aaf58ed691b",
        "review": "locked_proto: gain param [type_names: Option<&HashMap<String, Arc<Datatype>>>] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-55e8785cf6c756440521",
        "from_id": "RG-F-55e8785cf6c756440521",
        "to_id": "RG-F-c1d047496cda7d91d86b",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "8c3eafbe1797839b0530ec4d05e8aac7db5d435e",
        "child_blob": "4f631611c0899990cd78cb2070603aaf58ed691b",
        "review": "parse_c_type: gain param [type_names: Option<&HashMap<String, Arc<Datatype>>>] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-665e889efe29adc78c07",
        "from_id": "RG-F-665e889efe29adc78c07",
        "to_id": "RG-F-08f7654728d229dc7238",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "child_blob": "138bd3d6ed7356e95a0936ff1f2c187d933e9975",
        "review": "check_multistage_jumptables: drop param [&self]; gain param [&mut self]; returns -> Vec<crate::op::PcodeOpRef> ->  (4d1bcf29)",
    },
    {
        "base_id": "RG-F-6f57a74143457c1e6f5d",
        "from_id": "RG-F-6f57a74143457c1e6f5d",
        "to_id": "RG-F-c0396163cb5428d9eb7d",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "recover_jump_table: gain param [flow_state: &crate::flow::TruncatedFlowState]; returns -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> -> -> crate::error::Result<Option<Arc<RwLock<crate::jumptable:: (4d1bcf29)",
    },
    {
        "base_id": "RG-F-9a81adb6d00ac21cfb47",
        "from_id": "RG-F-9a81adb6d00ac21cfb47",
        "to_id": "RG-F-d4922f3dbfb37b66e235",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "remove_in_edge_from: param _exclude_indices:&[i32] -> &[i32] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-a7c613aedf13259c0b0f",
        "from_id": "RG-F-a7c613aedf13259c0b0f",
        "to_id": "RG-F-b1b28afdc0d96c99bac2",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "child_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "review": "new: gain param [propagate_indirect: bool] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-abb3bf756fd20450f68c",
        "from_id": "RG-F-abb3bf756fd20450f68c",
        "to_id": "RG-F-ca618a5a3392bc3c59c3",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "remove_unreachable_blocks: gain param [issuewarning: bool; checkexistence: bool] (4d1bcf29)",
    },
    {
        "base_id": "RG-F-cf52e890ee8a36a0f5d2",
        "from_id": "RG-F-cf52e890ee8a36a0f5d2",
        "to_id": "RG-F-695928e52bc3d1243201",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "1b243873b6dec9e5d097851afa5145dd47423de6",
        "child_blob": "2077fc815895a435d64db91af6ab62c8104b248c",
        "review": "stage_jump_table: gain param [flow_state: &crate::flow::TruncatedFlowState]; returns -> crate::jumptable::RecoveryMode -> -> crate::error::Result<crate::jumptable::RecoveryMode> (4d1bcf29)",
    },
    {
        "base_id": "RG-F-e1ee4372589486b36d70",
        "from_id": "RG-F-e1ee4372589486b36d70",
        "to_id": "RG-F-211fba91cd3ce658fac7",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/flow.rs",
        "to_path": "src/flow.rs",
        "parent_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "child_blob": "138bd3d6ed7356e95a0936ff1f2c187d933e9975",
        "review": "recover_jump_tables: param new_tables:&mut Vec<Option<crate -> &mut Vec<Option<Arc<RwLock<crate; returns  -> -> crate::error::Result<()> (4d1bcf29)",
    },
    {
        "base_id": "RG-F-3175e312a1638de63b65",
        "from_id": "RG-F-f10f42d013ccec324dcb",
        "to_id": "RG-F-cc2efb8ee4aead475a92",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "child_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "review": "propagate_type: param ptr_size:usize -> usize (4d1bcf29)",
    },
    {
        "base_id": "RG-F-0b65260ce004a84337c9",
        "from_id": "RG-F-0b65260ce004a84337c9",
        "to_id": "RG-F-98082c2ff9434b0485d1",
        "commit": "4d5e89fd7023ca3539f75d062b0f2c5614dd20fb",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "613b9a9e794903c5680947f8269788ad2a2f4dac",
        "child_blob": "0d0b051638992e86071e186ef19f499b15d78cf8",
        "review": "transition_def: returns -> Arc<RwLock<Varnode>> -> -> Option<Arc<RwLock<Varnode>>> (4d5e89fd)",
    },
    {
        "base_id": "RG-F-b3157b943066d8e74d4f",
        "from_id": "RG-F-b3157b943066d8e74d4f",
        "to_id": "RG-F-131206e2dc76ecaa0ea8",
        "commit": "8474ec13393f4f15e6a0095c7ee5d166d5e7b452",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "03b547186bc9498c0bf1c2f39f89ceb892b292e6",
        "child_blob": "3659b164797c3d6cb819214cca650be0eae79efa",
        "review": "get_register_name: param _space:crate -> crate (8474ec13)",
    },
    {
        "base_id": "RG-F-f9711768905eb5bf056c",
        "from_id": "RG-F-f9711768905eb5bf056c",
        "to_id": "RG-F-f873313f735f02cf3937",
        "commit": "8474ec13393f4f15e6a0095c7ee5d166d5e7b452",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "d2bcd5b8ba6b2d9ea010b10b637528b98d49103f",
        "child_blob": "9d3462025e11e47da872d6bb7fa05e75181074dc",
        "review": "spacebase_constant: gain param [entry: &crate::database::QueryContainerHit; spaceid: crate::space::AddressSpace] (8474ec13)",
    },
    {
        "base_id": "RG-F-abf77d064f1ec656081b",
        "from_id": "RG-F-426390a6112c3dbc6c2b",
        "to_id": "RG-F-abf77d064f1ec656081b",
        "commit": "8b387a8d288153a8fccd47673177f7ab9d2a220b",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "8bf645e06a62cffeda585f4d853cf5895ce4fc05",
        "child_blob": "13fa2528105649591841c0b0ba283929cb63a111",
        "review": "try_output_stack_guard: drop param [locked_output_storage: Option<(Address, i32)>] (8b387a8d)",
    },
    {
        "base_id": "RG-F-7d3ec36cb92d748b7de3",
        "from_id": "RG-F-7d3ec36cb92d748b7de3",
        "to_id": "RG-F-13f03568eb3480914790",
        "commit": "8b387a8d288153a8fccd47673177f7ab9d2a220b",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "60ff6efbb9f766bb1677513cbd111545708b444c",
        "child_blob": "fd2a0b2e6d4fe570895ad5df84056978864d7f37",
        "review": "set_output_parameter: gain param [space: AddressSpace] (8b387a8d)",
    },
    {
        "base_id": "RG-F-8dd367f8f6d2e6b25a9f",
        "from_id": "RG-F-8dd367f8f6d2e6b25a9f",
        "to_id": "RG-F-4179788f33f6e4b9f744",
        "commit": "8d9aaf66cf3dffbace3de5b7843835d1a778c734",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "c17f052efa3d89a485c275022967d0d58c5b07a1",
        "child_blob": "60ff6efbb9f766bb1677513cbd111545708b444c",
        "review": "unjustified_container: gain param [space: AddressSpace] (8d9aaf66)",
    },
    {
        "base_id": "RG-F-22aafcc017427cf69c66",
        "from_id": "RG-F-22aafcc017427cf69c66",
        "to_id": "RG-F-fd6c2f138f07d6a434c2",
        "commit": "90d0ec88107a7ceb8876a8c1a78a63cf5d28adb5",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "9d3462025e11e47da872d6bb7fa05e75181074dc",
        "child_blob": "f6936829030cca5446aadff17186116dd4416b5a",
        "review": "map_globals: returns  -> -> Result<(), crate::error::Error> (90d0ec88)",
    },
    {
        "base_id": "RG-F-e2f8fd9656b544eb364c",
        "from_id": "RG-F-e2f8fd9656b544eb364c",
        "to_id": "RG-F-bee721d4d0c8d4474c66",
        "commit": "90d0ec88107a7ceb8876a8c1a78a63cf5d28adb5",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "b7167aba78eee138e9f0068bbafb95f7a025a801",
        "child_blob": "7078a20f3353a3787098f5aeea97fac3772ed65b",
        "review": "test_action_mapglobals_marks_persistent_ram_varnodes: rename: test now asserts Symbol creation instead of flag-only marking (90d0ec88)",
    },
    {
        "base_id": "RG-F-0f440fb28a621f11a2e5",
        "from_id": "RG-F-0f440fb28a621f11a2e5",
        "to_id": "RG-F-506fcb9f9b16958229e0",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [_paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-350bfd7ce36aafc87bc5",
        "from_id": "RG-F-350bfd7ce36aafc87bc5",
        "to_id": "RG-F-df24ec62e96f58098106",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [_paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-4cebbe80d33d76389015",
        "from_id": "RG-F-4cebbe80d33d76389015",
        "to_id": "RG-F-b8398d937fc990bf2792",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [_paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-6a422bdc9f26aad48fad",
        "from_id": "RG-F-6a422bdc9f26aad48fad",
        "to_id": "RG-F-d548b0dad163f4e73bb7",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-7bb1826a9a24ff75f90d",
        "from_id": "RG-F-7bb1826a9a24ff75f90d",
        "to_id": "RG-F-135975b0c3b697afb894",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [_paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-b45a4aaf0ba46f015ebf",
        "from_id": "RG-F-b45a4aaf0ba46f015ebf",
        "to_id": "RG-F-4a2d7b2f308abdd4878d",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "close_paren: gain param [paren: &str; _id: i32] (980f0831)",
    },
    {
        "base_id": "RG-F-c0d432026d80a6803402",
        "from_id": "RG-F-c0d432026d80a6803402",
        "to_id": "RG-F-f3ad82fa5257af315995",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-d0c6ed811bdd75fca718",
        "from_id": "RG-F-d0c6ed811bdd75fca718",
        "to_id": "RG-F-6cc79925c1152ad3d51e",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/printlanguage.rs",
        "to_path": "src/printlanguage.rs",
        "parent_blob": "d6fdc2cf7ae57faf540fed33987a0ab0ea080d9d",
        "child_blob": "a0fc455cd11002cd71cd2de4845830fe604fbe65",
        "review": "emit_spaces: param _bump:i32 -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-e03451a738bd548e1f31",
        "from_id": "RG-F-e03451a738bd548e1f31",
        "to_id": "RG-F-d6fe7b4d2a2591f3f51c",
        "commit": "980f08317308b104fb02cc0094d2845555f98b3d",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "835cc04e8334d8eea5c9418bcdc2cf9085b49714",
        "child_blob": "9d0eb152509f2bf05c2366a3afe930354e70af5f",
        "review": "open_paren: gain param [paren: &str]; returns  -> -> i32 (980f0831)",
    },
    {
        "base_id": "RG-F-5c67bfa2b4dafad127e9",
        "from_id": "RG-F-5c67bfa2b4dafad127e9",
        "to_id": "RG-F-885ac55c9454c2379e9b",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "review": "emit_block_structured: param block_arc:&std -> &std (a5362afc)",
    },
    {
        "base_id": "RG-F-cbd102e6173cd8cf0653",
        "from_id": "RG-F-cbd102e6173cd8cf0653",
        "to_id": "RG-F-ac045b62b01e997d6bab",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "review": "is_block_body_empty: param block_arc:&std -> &std (a5362afc)",
    },
    {
        "base_id": "RG-F-02b973adc674e2dafcca",
        "from_id": "RG-F-02b973adc674e2dafcca",
        "to_id": "RG-F-818e9e9dd2f555e6186c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_for_function: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-02e4be08c92e34abfe47",
        "from_id": "RG-F-02e4be08c92e34abfe47",
        "to_id": "RG-F-22ed1eb12bc5abac17fe",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "set_warning: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-0c9b722a5e2a1f5950bb",
        "from_id": "RG-F-0c9b722a5e2a1f5950bb",
        "to_id": "RG-F-1e3090fe8bc992c441dc",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "set_break_point: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-104e7177e37c491be519",
        "from_id": "RG-F-104e7177e37c491be519",
        "to_id": "RG-F-4fcc20c778fd1c00a6e5",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "mutate_rule_target: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-1e379133c5e93eb237e8",
        "from_id": "RG-F-1e379133c5e93eb237e8",
        "to_id": "RG-F-3cbd3b212adf5233023c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_action_factory_in_group: returns where F: Fn() -> Box<dyn Action> + 'static, -> where F: Fn() -> Box<dyn Action> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-22c46fc05bddb2d4345b",
        "from_id": "RG-F-22c46fc05bddb2d4345b",
        "to_id": "RG-F-766b5e4ed8fc866214d8",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "disable_rule: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2837daddc938af793d3c",
        "from_id": "RG-F-2837daddc938af793d3c",
        "to_id": "RG-F-8015705770472a5fdead",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_opcodes: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2de92d72d9fdbccc7507",
        "from_id": "RG-F-2de92d72d9fdbccc7507",
        "to_id": "RG-F-630ddcebbfe93b0e818c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply_with_state: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-2e96dea7b92ff0ef2a96",
        "from_id": "RG-F-2e96dea7b92ff0ef2a96",
        "to_id": "RG-F-4275c5418379b85fb462",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_rule_flags: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-3f54231b0de2609dc1e5",
        "from_id": "RG-F-3f54231b0de2609dc1e5",
        "to_id": "RG-F-3f316f0a983f0169c0f8",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_flags: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-418f3036e9876a352e13",
        "from_id": "RG-F-418f3036e9876a352e13",
        "to_id": "RG-F-e2bffedfda38a0041452",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_group: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-41f64260f48f0ecc9ce1",
        "from_id": "RG-F-41f64260f48f0ecc9ce1",
        "to_id": "RG-F-0ae09e97f158088ac2d3",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "mutate_action_target: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-4269e256e1890ee9c4fd",
        "from_id": "RG-F-4269e256e1890ee9c4fd",
        "to_id": "RG-F-d529f1aba80316f7645c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "sub_action_match_count: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-46555960b50ff8a7af36",
        "from_id": "RG-F-46555960b50ff8a7af36",
        "to_id": "RG-F-677424a69f8543c266ce",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_num_tests: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-484ed51a1834115a3a27",
        "from_id": "RG-F-484ed51a1834115a3a27",
        "to_id": "RG-F-c5d4b0a7203f6792e696",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_rule_factory_in_group: returns where F: Fn() -> Box<dyn Rule> + 'static, -> where F: Fn() -> Box<dyn Rule> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-4e9f597e3cbe737fd971",
        "from_id": "RG-F-4e9f597e3cbe737fd971",
        "to_id": "RG-F-7145804dcf3c378fbd8d",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_flags: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-503a03cb217c238099fb",
        "from_id": "RG-F-503a03cb217c238099fb",
        "to_id": "RG-F-a7d1311516103ceec64f",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_pool_mut: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-599925663bf4d9151f1b",
        "from_id": "RG-F-599925663bf4d9151f1b",
        "to_id": "RG-F-c40817108c16ed8cd523",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clone_for_groups: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-677d167932e38cfd8059",
        "from_id": "RG-F-677d167932e38cfd8059",
        "to_id": "RG-F-6b77b0a1166c681a2da7",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "add_action_factory_in_group: returns where F: Fn() -> Box<dyn Action> + 'static, -> where F: Fn() -> Box<dyn Action> + Send + Sync + 'static, (b5a554d9)",
    },
    {
        "base_id": "RG-F-6c712f998590fc4f4ea4",
        "from_id": "RG-F-6c712f998590fc4f4ea4",
        "to_id": "RG-F-ba27d12fe911a3f2c401",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply_op: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-6faca00e16168f0d41ef",
        "from_id": "RG-F-6faca00e16168f0d41ef",
        "to_id": "RG-F-e9a648e8c1f60e0e96fa",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clear_break_points: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-782b5bf849af80f65d5c",
        "from_id": "RG-F-782b5bf849af80f65d5c",
        "to_id": "RG-F-5923943cda2aaa09d13d",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_name: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-7c5932644e877daca86f",
        "from_id": "RG-F-7c5932644e877daca86f",
        "to_id": "RG-F-687e0eee77e05580bac1",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "take_count_delta: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-842ae1fa8dfa0b9daf76",
        "from_id": "RG-F-842ae1fa8dfa0b9daf76",
        "to_id": "RG-F-fc454bde9c77551f1734",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_name: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-8d7818eecf4c25ea2fdc",
        "from_id": "RG-F-8d7818eecf4c25ea2fdc",
        "to_id": "RG-F-e2019417ba9532fd82ab",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_for_function: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-959f407b5d68573d1229",
        "from_id": "RG-F-959f407b5d68573d1229",
        "to_id": "RG-F-ad0f5edfae77eb1ce2c7",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-a10d860ce8bc8dd86327",
        "from_id": "RG-F-a10d860ce8bc8dd86327",
        "to_id": "RG-F-23956b20a1c593a174b0",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_stats: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-b6563b02f21bb001353d",
        "from_id": "RG-F-b6563b02f21bb001353d",
        "to_id": "RG-F-5702dd3779ca70860cbb",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "apply: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-c677af856e21301a1be7",
        "from_id": "RG-F-c677af856e21301a1be7",
        "to_id": "RG-F-944b96880e55bb88cc25",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "prepare_apply: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-d2a6efd33943f99876b9",
        "from_id": "RG-F-d2a6efd33943f99876b9",
        "to_id": "RG-F-372d591b6a8a3aca4941",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "clone_for_groups: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-d421f5a0561e50936f18",
        "from_id": "RG-F-d421f5a0561e50936f18",
        "to_id": "RG-F-144b2303dbaaaa3c0906",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_pool: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-df138e1608414f13f855",
        "from_id": "RG-F-df138e1608414f13f855",
        "to_id": "RG-F-97e2e72a7bad8ffb35cc",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-e6d44fe6157734ea6fa8",
        "from_id": "RG-F-e6d44fe6157734ea6fa8",
        "to_id": "RG-F-66a413c393915c485061",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_num_apply: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-e7700e3314cd8bda7097",
        "from_id": "RG-F-e7700e3314cd8bda7097",
        "to_id": "RG-F-7c1d3d4135d705d2ffcb",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "as_action_group_mut: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-ecb07ecfbc33e6ed366d",
        "from_id": "RG-F-ecb07ecfbc33e6ed366d",
        "to_id": "RG-F-c6f2b9c34e68bbcee2ed",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "perform: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-f0c872a033d6ed8d2afc",
        "from_id": "RG-F-f0c872a033d6ed8d2afc",
        "to_id": "RG-F-46888848014d136d6b50",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_group: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-f83534827af595642dff",
        "from_id": "RG-F-f83534827af595642dff",
        "to_id": "RG-F-62677f02a16f1130b552",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "reset_stats: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-fd82c9d5598cf4e2837b",
        "from_id": "RG-F-fd82c9d5598cf4e2837b",
        "to_id": "RG-F-4d35f2595074be762e86",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "get_breakpoint: trait supertrait Send+Sync re-keys the owner context (trait:Rule -> trait:Rule: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-fefdb48c92ee9155d8c7",
        "from_id": "RG-F-fefdb48c92ee9155d8c7",
        "to_id": "RG-F-aee8d565c0bd52e44f5c",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "sub_rule_match_count: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-ff9e56b34d4facda44b5",
        "from_id": "RG-F-ff9e56b34d4facda44b5",
        "to_id": "RG-F-ddbc2a4da7caf5c794ea",
        "commit": "b5a554d900936ada0798fd6323e8d1d5ef1b2a84",
        "from_path": "src/action.rs",
        "to_path": "src/action.rs",
        "parent_blob": "5e8de9beb79ae89c3b5500a805bd3ac0a77921eb",
        "child_blob": "18bafbe0e89f3dfade3a96af790c9e6f6b8f31c0",
        "review": "enable_rule: trait supertrait Send+Sync re-keys the owner context (trait:Action -> trait:Action: Send + Sync); signature unchanged (b5a554d9)",
    },
    {
        "base_id": "RG-F-657993bd9ae7c40f453c",
        "from_id": "RG-F-657993bd9ae7c40f453c",
        "to_id": "RG-F-bc367e56a6c33dd53e16",
        "commit": "cac8f60aa1043e87266052478e44eafc9c9e01fd",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "adca5bb67309ddb2bea742395b05ec87c4e97426",
        "child_blob": "8552e471deaf118387c53573cf45467b327b6e10",
        "review": "base_explicit: drop param [vn: &crate::varnode::Varnode]; gain param [vn_arc: &std::sync::Arc<std::sync::RwLock<crate::varnode::Va] (cac8f60a)",
    },
    {
        "base_id": "RG-F-3dc7c42e2821d00cea8a",
        "from_id": "RG-F-3dc7c42e2821d00cea8a",
        "to_id": "RG-F-a02dabc4695772d39068",
        "commit": "d1d86c5ce1af19ec3f447e0f4ae4b2de3741d783",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "fdcf0b595add596e3fe214c0a51ee918cc5ee6ab",
        "child_blob": "9baff6df1b8904848fc7313fed7e5cc9895faa00",
        "review": "push_constant: param _vn:&Varnode -> &Varnode (d1d86c5c)",
    },
    {
        "base_id": "RG-F-89e016fe2736366562e6",
        "from_id": "RG-F-89e016fe2736366562e6",
        "to_id": "RG-F-32e49f1cfa2f76dd9b1a",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "restructure_varnode: param fd:&crate -> &mut crate (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-e168755a3d3ef1e682d7",
        "from_id": "RG-F-e168755a3d3ef1e682d7",
        "to_id": "RG-F-2fb18593bd567569c47b",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "gather_open: drop param [checker: &AliasChecker]; gain param [types: &Arc<RwLock<crate::type_system::typefactory::TypeFact] (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-e5c3f2b033d412a9ff3c",
        "from_id": "RG-F-e5c3f2b033d412a9ff3c",
        "to_id": "RG-F-a3c894580ae5233ca84f",
        "commit": "dc6f0bfa57ee8d4b20d4edbab9d486b603253cc6",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "efef9d895948d8fbf821c09b3df3d3acd3a6e199",
        "child_blob": "d8941aedb090417d82b478e0d42d899e3c8d926f",
        "review": "derive_boundaries: drop param [local_boundary: u64]; gain param [localrange: &[(u64, u64)]; paramrange: &[(u64, u64)]; has_model: bool] (dc6f0bfa)",
    },
    {
        "base_id": "RG-F-3dd8a09502c79e668db5",
        "from_id": "RG-F-3dd8a09502c79e668db5",
        "to_id": "RG-F-6366ebc7c4d1ef5e164b",
        "commit": "e4c122dd1a259c4c7f9a260bde1d00937a6007e5",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "1739800d4db19500d93b0bcbd955d2434c00e4f4",
        "child_blob": "c135f9ad53b9d9635769b5449b77af68967a15a1",
        "review": "build_subpiece: returns -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode> -> -> Result<std::sync::Arc<std::sync::RwLock<crate::varnode::V (e4c122dd)",
    },
    {
        "base_id": "RG-F-912fef162cc89fe0bf88",
        "from_id": "RG-F-912fef162cc89fe0bf88",
        "to_id": "RG-F-13e779331bc0e4e025d1",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "87e2e62276218b859ff357ad110d936ca8c45e63",
        "child_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "review": "build_input_from_trials: gain param [fd: &mut crate::funcdata::Funcdata; call_op: &crate::op::PcodeOpRef]; returns -> Vec<(Address, i32)> ->  (e65172c8)",
    },
    {
        "base_id": "RG-F-9e895a3a0250ae83b691",
        "from_id": "RG-F-9e895a3a0250ae83b691",
        "to_id": "RG-F-36f312ac16b8aeb056bf",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "a789d82eaa3831e15a17e4ab9e08716e51e0a8c0",
        "child_blob": "60b5e94997c0074ae62f61d5e3dc4758c2bbf1e3",
        "review": "func_link_input: drop param [callee_name: Option<&str>]; gain param [fc_idx: usize] (e65172c8)",
    },
    {
        "base_id": "RG-F-c58bd5e5d630cc315643",
        "from_id": "RG-F-c58bd5e5d630cc315643",
        "to_id": "RG-F-cc05e9e6d69e72d76759",
        "commit": "e65172c82933d7fef46ce68b5342ae121cdb3ae6",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "87e2e62276218b859ff357ad110d936ca8c45e63",
        "child_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "review": "new_for_op: drop param [prototype: FuncProto]; gain param [_caller_funcp: FuncProto] (e65172c8)",
    },
    {
        "base_id": "RG-F-636713cd718416eda469",
        "from_id": "RG-F-636713cd718416eda469",
        "to_id": "RG-F-3f1bd88d4b4e89d8f38f",
        "commit": "ed8279383546ab76f57d50c08204cbf2a1030161",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "28b7501b50858acb11ecca078f174bb7c691431c",
        "child_blob": "ebceddc7cfd31423381303edf3fe8f3a4fbe7b2a",
        "review": "bump_deadcode_delay: gain param [fd: &mut Funcdata] (ed827938)",
    },
    {
        "base_id": "RG-F-e5118215bbe2945b9480",
        "from_id": "RG-F-e5118215bbe2945b9480",
        "to_id": "RG-F-67c7a43469ad14fb90af",
        "commit": "ee7f8f02db93740962d69fae35606fb14e398d16",
        "from_path": "src/database.rs",
        "to_path": "src/database.rs",
        "parent_blob": "93e388f0ebbbfdb2f203f7c0d7f3adca8df0f7e0",
        "child_blob": "c37f65cb7c79a63f780c462ed30484dc2370c722",
        "review": "find_container: gain param [usepoint: Address]; returns -> Option<&SymbolEntry> -> -> Option<usize> (ee7f8f02)",
    },
    {
        "base_id": "RG-F-74239bf8f5f8e8e31fc7",
        "from_id": "RG-F-74239bf8f5f8e8e31fc7",
        "to_id": "RG-F-079b0a68815cef04e6b9",
        "commit": "f35f29d7ae2d4f241283f4553230426ecf3c1f66",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "48d5fa808e3977b275de74c9029b3d7f5a32774e",
        "child_blob": "75dcc22fbb4f1b5cf6d82da28db6bf9ca76d4857",
        "review": "build_output_from_trials: param trial_vn:&[std -> &[Option<std (f35f29d7)",
    },
    {
        "base_id": "RG-F-614df5b0ab663eee9561",
        "from_id": "RG-F-614df5b0ab663eee9561",
        "to_id": "RG-F-c6622ea88f98cd771ceb",
        "commit": "f44f641545188578706e0b5912317cee3402d794",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "9d59388d6012e7a01d71ade00fa7b0f2d6e7d8c9",
        "child_blob": "581421ce4c37aea1173dfda9cbe198d88fcb359a",
        "review": "get_input_cast: param _op:&PcodeOp -> &PcodeOp; param _slot:usize -> usize (f44f6415)",
    },
    {
        "base_id": "RG-F-8afa232b7531c9dbdfd3",
        "from_id": "RG-F-8afa232b7531c9dbdfd3",
        "to_id": "RG-F-ea42b78a0f4dad50a82f",
        "commit": "f9245e16e318581b3c1e131c4e4abd8482e9742b",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "f2f54c1daaef757603b0545acb686ed58a309230",
        "child_blob": "48696998ddeea6c8fc6fb09a237cc606108b6bb5",
        "review": "group_partials: param _fd:&mut Funcdata -> &mut Funcdata (f9245e16)",
    },

    # w-registry2 continuation of ORACLE-REGISTRY-IMPACT-CONTINUITY-0001: the
    # remaining seven window removals are rustfmt multi-line signature splits
    # whose only difference is the trailing parameter separator.  The automatic
    # alias rule cannot fire because none of these functions carries a
    # strict-regex-matching non-empty annotation above the fn line (lineless
    # `// Ghidra: block.hh Fn` markers or plain doc comments), so each alias is
    # pinned here on git-diff evidence that the body is unchanged formatting.
    {
        "base_id": "RG-F-ad4cafa74f583abfbe4f",
        "from_id": "RG-F-ad4cafa74f583abfbe4f",
        "to_id": "RG-F-425cd5352ccd5db995c9",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "5294bda8f0e39fa14facd6b59d066c379a416b35",
        "child_blob": "5f43cf8954f5a62b8573be019c88a3a608d9ccd2",
        "review": "print_raw_implied_goto_trait: rustfmt split adds the trailing parameter separator only; marker line-numberless so automatic evidence is unavailable (2d78b5af)",
    },
    {
        "base_id": "RG-F-098edc738e5a43908809",
        "from_id": "RG-F-098edc738e5a43908809",
        "to_id": "RG-F-b6bfd7d98562fbfd99d7",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "child_needs_parens: rustfmt split adds the trailing parameter separator only; doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-17ef2d9d23d6d220f407",
        "from_id": "RG-F-17ef2d9d23d6d220f407",
        "to_id": "RG-F-343f5a5b111fa2a66a95",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "var_prefix: rustfmt split adds the trailing parameter separator only; doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-48cac975d49aaa45fbc4",
        "from_id": "RG-F-48cac975d49aaa45fbc4",
        "to_id": "RG-F-8fdef7ef5f62224b9392",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "array_sub_entry: rustfmt split adds the trailing parameter separator only; Ghidra marker has no line number so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-49047a901b0905807ad4",
        "from_id": "RG-F-49047a901b0905807ad4",
        "to_id": "RG-F-e24c59a91e3095bd3774",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "review": "find_partial_field: rustfmt split adds the trailing parameter separator only; Ghidra marker has no line number so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-d4793f1f2dc45770289c",
        "from_id": "RG-F-d4793f1f2dc45770289c",
        "to_id": "RG-F-5351aec1c6466b1b9859",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "review": "make_input_vn: rustfmt split adds the trailing parameter separator only (body expression reformat aside); doc-comment header so automatic evidence is unavailable (3fb97c11)",
    },
    {
        "base_id": "RG-F-daa603fd8f42abcfe2fb",
        "from_id": "RG-F-daa603fd8f42abcfe2fb",
        "to_id": "RG-F-b28ed8113612c1d70101",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "18c72f2088c9246030dc852601ac67a335b4726e",
        "child_blob": "d6cbd815b82967b83e6ae6752007f351a20114c2",
        "review": "insert_end: rustfmt split adds the trailing parameter separator only; no annotation header so automatic evidence is unavailable (3fb97c11)",
    },

    # The mapglobals merge resolved both reciprocal half-delete ports to
    # master's non-mut signatures; the first-parent mut variants die and the
    # second-parent variants (same FlowBlock port, mut binding moved into the
    # body) survive into the checkpoint tree, so these are continuity
    # transitions, not retirements.
    {
        "base_id": "RG-F-7622630fcd5425152c42",
        "from_id": "RG-F-2e7d8eae51d63d1dcc39",
        "to_id": "RG-F-87ecf60944cd017f0272",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "half_delete_in_edge: merge resolved to master's non-mut signature with the mut binding moved into the body; same FlowBlock::halfDeleteInEdge port block.cc:100 (4d1bcf29)",
    },
    {
        "base_id": "RG-F-c76e93f7b514cc307344",
        "from_id": "RG-F-68db795ba78535d5e6e6",
        "to_id": "RG-F-30f67e8116795adbb6b2",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "review": "half_delete_out_edge: merge resolved to master's non-mut signature with the mut binding moved into the body; same FlowBlock::halfDeleteOutEdge port block.cc:115 (4d1bcf29)",
    },

    # --- merge window 3fb97c11..65422a62 (master newVarnode symbol tail) ---
    {
        "base_id": "RG-F-955a3451fb0ff43a0e7d",
        "from_id": "RG-F-2c32488e98950122b0c4",
        "to_id": "RG-F-3025cfb61fb588b0b2e3",
        "commit": "65422a62350d774dc3af93d4e194b7717b5ab352",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "child_blob": "af4a0f7269caa2c4b20824a0da5cf1b1ab1adc4c",
        "review": "RuleTrivialBool::apply_op: param renamed _fd: &mut Funcdata -> fd: &mut Funcdata because the master body now reads fd; annotation ruleaction.cc:2451 unchanged above the fn (65422a62 merging 34a10198)",
    },
    {
        "base_id": "RG-F-427fb6d649f3e79ceb1d",
        "from_id": "RG-F-8d782bd762556345d5ca",
        "to_id": "RG-F-100a0ebc98f73bdc511e",
        "commit": "65422a62350d774dc3af93d4e194b7717b5ab352",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "child_blob": "af4a0f7269caa2c4b20824a0da5cf1b1ab1adc4c",
        "review": "RulePiece2Zext::apply_op: param renamed _fd: &mut Funcdata -> fd: &mut Funcdata because the master body now reads fd; annotation ruleaction.cc:219 unchanged above the fn (65422a62 merging 34a10198)",
    },
    {
        "base_id": "RG-F-56e2c07586c6362bfa42",
        "from_id": "RG-F-a4d332b95a9441b0b702",
        "to_id": "RG-F-da4d300bfe1bb0faec44",
        "commit": "65422a62350d774dc3af93d4e194b7717b5ab352",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "child_blob": "af4a0f7269caa2c4b20824a0da5cf1b1ab1adc4c",
        "review": "RulePiece2Sext::apply_op: param renamed _fd: &mut Funcdata -> fd: &mut Funcdata because the master body now reads fd; annotation ruleaction.cc:240 unchanged above the fn (65422a62 merging 34a10198)",
    },
    {
        "base_id": "RG-F-b447d242a143e3ff0006",
        "from_id": "RG-F-b447d242a143e3ff0006",
        "to_id": "RG-F-59286f41a83f786200b2",
        "commit": "65422a62350d774dc3af93d4e194b7717b5ab352",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "5c73f4dc8b31da6e68c66dd8259dbf9527d2ab31",
        "child_blob": "d2624bb6a6a4084be312ae1faf7f2df1b01b2346",
        "review": "set_symbol_properties -> set_symbol_properties_arc: method re-hosted as associated fn taking self_arc: &Arc<RwLock<Varnode>> because the cc:417-418 high->setSymbol(this) reverse link needs the Varnode Arc (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001); anchor varnode.cc:410 setSymbolProperties unchanged (65422a62 merging 34a10198)",
    },

    # --- merge window 65422a62..10ea407d (master DECL-SPACING-NAMEFLOW wave) ---
    {
        "base_id": "RG-F-baa0434992c1363b8d95",
        "from_id": "RG-F-baa0434992c1363b8d95",
        "to_id": "RG-F-6ad94d26468d36295c26",
        "commit": "10ea407df05d4f92cbd71ffe4df20aac70b5afb8",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "child_blob": "505d7a3bfd57ae00f5f6171f66576c56dd494a0e",
        "review": "push_type_start_opt: param retyped ct: Option<&Datatype> -> Option<&Arc<Datatype>> with the typestack rework; anchor printc.cc:264 PrintC::pushTypeStart unchanged (10ea407d)",
    },
    {
        "base_id": "RG-F-9b9931881b1b3c044009",
        "from_id": "RG-F-9b9931881b1b3c044009",
        "to_id": "RG-F-dcdbfeefb263f3c27d3a",
        "commit": "10ea407df05d4f92cbd71ffe4df20aac70b5afb8",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "child_blob": "505d7a3bfd57ae00f5f6171f66576c56dd494a0e",
        "review": "push_type_end_opt: param retyped ct: Option<&Datatype> -> Option<&Arc<Datatype>> with the typestack rework; metatype dispatch order cc:322/324/330 preserved (10ea407d)",
    },
    {
        "base_id": "RG-F-4dffb2ed510f8cb9b14b",
        "from_id": "RG-F-4dffb2ed510f8cb9b14b",
        "to_id": "RG-F-b011bf03cc992c741479",
        "commit": "10ea407df05d4f92cbd71ffe4df20aac70b5afb8",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "child_blob": "505d7a3bfd57ae00f5f6171f66576c56dd494a0e",
        "review": "datatype_name_ends_with_star -> decl_prefix_ends_with_star: name-string check replaced by its structural form over type_stack_for, per the inline comment 'structural form of the join rule above' (printc.cc:73-77 join-spacing rule) (10ea407d)",
    },
    {
        "base_id": "RG-F-631999f3a57799cd3ce3",
        "from_id": "RG-F-631999f3a57799cd3ce3",
        "to_id": "RG-F-2a1c4c6151d8d8414480",
        "commit": "420174438fdf3ae4f7e09b483af14cc04215316d",
        "from_path": "src/block.rs",
        "to_path": "src/block.rs",
        "parent_blob": "bc69f87d61814e00c77b11cb59dd00d43200fbbb",
        "child_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "review": "mark_unstructured_target: receiver &self -> &mut self with the BlockGoto wrapped-component port (block.cc:2859 BlockGraph::markUnstructured recursion into the wrapped child via mark_unstructured_trait; cc:2860-2863 markCopyBlock path now targets the dyn FlowBlock target_dyn through mark_front_leaf) (a2c5ce26)",
    },    {
        "base_id": "RG-F-62c0cf8ffb3794618287",
        "from_id": "RG-F-62c0cf8ffb3794618287",
        "to_id": "RG-F-9b1995ef16a44eef814f",
        "commit": "2c5bdb309d65dd9b38cac62426832235569388f5",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "d2624bb6a6a4084be312ae1faf7f2df1b01b2346",
        "child_blob": "96d8be9a9f6ac05613cc283b54324a5bd5c049ac",
        "review": "get_use_point: _fd renamed fd, free-leg sentinel fd base - 1 (8b2b0f3)",
    },
    {
        "base_id": "RG-F-7a9724a583fb0aad16fa",
        "from_id": "RG-F-7a9724a583fb0aad16fa",
        "to_id": "RG-F-da013bcda528bcaacdcd",
        "commit": "2c5bdb309d65dd9b38cac62426832235569388f5",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "5962e7719accada6a9c4ccea0f1e228a95aa7e24",
        "child_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "review": "eliminate_intersect: returns usize marked= count for UNIFY diag (afdfcdd)",
    },
    {
        "base_id": "RG-F-33c86fd1b415d82ce820",
        "from_id": "RG-F-0b58bd56440200c0d42d",
        "to_id": "RG-F-67f66f09decf8c2d0193",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "f651fd35e39023421745b7e8d8b79e8e4e09b0b6",
        "child_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "review": "is_op_identical: typedef-chain strip reworked the signature (a986dce4); the lineage alias chain 33c86fd1 -> 0b58bd56 (trailing comma, 3fb97c11) advances to 67f66f09",
    },
    {
        "base_id": "RG-F-8fcaf9612ef6a752403d",
        "from_id": "RG-F-35f0c0ffc91782f5f023",
        "to_id": "RG-F-fd44b0e0bd93649279b9",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "56b7c9ac518685e3fb9e032d3e3b8a7432189cbd",
        "child_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "review": "emit_block_goto: wrapped structural dispatch reworked the signature (d4fd9f87); the lineage alias chain 8fcaf961 -> 35f0c0ff (trailing comma, 3fb97c11) advances to fd44b0e0",
    },
    {
        "base_id": "RG-F-680b7aec490d30d27e54",
        "from_id": "RG-F-680b7aec490d30d27e54",
        "to_id": "RG-F-27e5c680f9d99fdeadee",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "b6fe679bd92b09031450c715118bc9f408fadc0b",
        "child_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "review": "block_remove_internal: ActionDoNothing faithful removal chain reworked the signature inside 09b367f5",
    },
    {
        "base_id": "RG-F-dcefd033d937f2b339bd",
        "from_id": "RG-F-dcefd033d937f2b339bd",
        "to_id": "RG-F-259bd0774148eb5c8ab2",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "b6fe679bd92b09031450c715118bc9f408fadc0b",
        "child_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "review": "remove_do_nothing_block: ActionDoNothing faithful removal chain reworked the signature inside 09b367f5",
    },
    {
        "base_id": "RG-F-00572f8089ee0282e3c8",
        "from_id": "RG-F-00572f8089ee0282e3c8",
        "to_id": "RG-F-6916029914151d2db6eb",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_range_must: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-008eae3b0ba4d12666a2",
        "from_id": "RG-F-008eae3b0ba4d12666a2",
        "to_id": "RG-F-0eb47d4f14a0f355f3e8",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "review": "set_pending_brace: signature re-key (e1ee7de6 fix: PendingBrace per-install identity ends the prettyprint.rs:3); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-025f5fca8290ce0dd217",
        "from_id": "RG-F-025f5fca8290ce0dd217",
        "to_id": "RG-F-d21dc52d46b8f7c84e9a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "constraints_from_path: signature re-key (d626a117 core: value-set solver constraint generation family (RANGEUTIL-C); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-0566330cb210c4865002",
        "from_id": "RG-F-0566330cb210c4865002",
        "to_id": "RG-F-fe107f6bac1013c9e1cd",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/datatype.rs",
        "to_path": "src/type_system/datatype.rs",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "review": "get_sub_type: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-07c891e8ebed22a614bf",
        "from_id": "RG-F-07c891e8ebed22a614bf",
        "to_id": "RG-F-073da449723cb9f5d314",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "review": "back_up_pointer: signature re-key (ae1e1e75 core: subflow union facing consults run through the fd-aware twi); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-085c02d6f39c4639fb36",
        "from_id": "RG-F-085c02d6f39c4639fb36",
        "to_id": "RG-F-6fd5b910459f46619697",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/disasm/x86_lift.rs",
        "to_path": "src/disasm/x86_lift.rs",
        "parent_blob": "ae3e144c54a0ed2571aa3624b7c1f5116785f99f",
        "child_blob": "6fae54ab7f5e8f1ca9ef3fa787e6d193cfc8c4f7",
        "review": "compute_mem_addr: signature re-key (ea5010e9 align: port shl/sal shift flags (sla shlflags/shiftresultflags, ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-096cf82d192f9fb97a26",
        "from_id": "RG-F-096cf82d192f9fb97a26",
        "to_id": "RG-F-4c52a144995488a034b3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "finalize_range: signature re-key (0b996bed core: wire ValueSetSolver into LoadGuard establish/finalize (her); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-0a8a5f4c9320af37114a",
        "from_id": "RG-F-cc1b697f5846024da79e",
        "to_id": "RG-F-2cf6bd977285eb0e278e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "float_extension_read: signature re-key (c593705c heritage: processJoins consumer chain 1:1 (join split read/write); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-0d8b13a396b10708badb",
        "from_id": "RG-F-0d8b13a396b10708badb",
        "to_id": "RG-F-0c02c845fb562e683bf6",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/datatype.rs",
        "to_path": "src/type_system/datatype.rs",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "review": "score_single_component: signature re-key (c05c1290 core: coreaction 13 union facing reads consult the resolution ma); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-0df2d06c62d030e3aee1",
        "from_id": "RG-F-0df2d06c62d030e3aee1",
        "to_id": "RG-F-f61cd3727162105b42cf",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/double_precis.rs",
        "to_path": "src/double_precis.rs",
        "parent_blob": "9d4ffe1a072d45accd3e7eb87e3d9942d43d054c",
        "child_blob": "b36ef83c75e227ef9cdf6b65e48b4b9b63d9165e",
        "review": "replace_copy_force: signature re-key (8d6451f4 fix: qualify transform piece, double-precis whole/copy-force and); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-12a1ac7520a2936215cc",
        "from_id": "RG-F-90a0ee5d5692ac0705d6",
        "to_id": "RG-F-dc31cc79ae927e192ee1",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-1500b403d31dc09fa484",
        "from_id": "RG-F-bc273d6ed95b82759e0b",
        "to_id": "RG-F-77e3f1c39c224a8fb08d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-18770556d1ec3727b61f",
        "from_id": "RG-F-18770556d1ec3727b61f",
        "to_id": "RG-F-063a91bacb8e9ce82632",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "fold_in_guards: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-190434e2b136253e7cf8",
        "from_id": "RG-F-190434e2b136253e7cf8",
        "to_id": "RG-F-f937b633d5a6319d9b19",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "score_truncation_inplace: signature re-key (18b020b9 unionres: deref drill-down and canonical-type corrections in sco); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-1a0de177364519004226",
        "from_id": "RG-F-7877c3db7566ba00b383",
        "to_id": "RG-F-d217c0a3cdc7581a6a87",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-21f9a0c8b5fd1e81b17f",
        "from_id": "RG-F-21f9a0c8b5fd1e81b17f",
        "to_id": "RG-F-677b01d48051e870bbd4",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "switch_over_jump_tables: signature re-key (ad42d2b0 align: fix nodeSplit clone output space loss (FUNCDATA-NODESPLIT); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-224286367b10e73e2221",
        "from_id": "RG-F-224286367b10e73e2221",
        "to_id": "RG-F-d13be972489a12b30e0d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "translate_to_op: signature re-key (dbd5d89b core: rangeutil value-set fill/iterate live path + RuleRangeMeld); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-23cf63793beda221308d",
        "from_id": "RG-F-23cf63793beda221308d",
        "to_id": "RG-F-1816889143e3beb44458",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/datatype.rs",
        "to_path": "src/type_system/datatype.rs",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "review": "get_map: signature re-key (4f4c9d78 varmap: live ScopeLocal channel for stack spacebase subtype quer); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-2475c99307254aa5a543",
        "from_id": "RG-F-2475c99307254aa5a543",
        "to_id": "RG-F-db506a6e32389d44cf8d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "only_op_use: signature re-key (79bb0f61 align: CALLSPEC-DRIVER-0001 flow-time callspec anchoring on the ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-2642a89b925f1de36e09",
        "from_id": "RG-F-35cae7c4aaff6a354558",
        "to_id": "RG-F-af8092285f474721e59d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "split_join_write: signature re-key (c593705c heritage: processJoins consumer chain 1:1 (join split read/write); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-2723244b1664e2c12a1c",
        "from_id": "RG-F-2723244b1664e2c12a1c",
        "to_id": "RG-F-ba30411e7974455ce7c2",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/blockaction.rs",
        "to_path": "src/blockaction.rs",
        "parent_blob": "e7d9cde9acd98cbb3c6ccb716bdd07b5a1f20169",
        "child_blob": "69d1fa2979bb1812ed1736b5f31687e12e296220",
        "review": "find_exit: signature re-key (07678863 align: port LoopBody::findExit container arm (extendToContainer)); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-293a5a0812a002b4c7c0",
        "from_id": "RG-F-293a5a0812a002b4c7c0",
        "to_id": "RG-F-1fb8be36fc1e2b1b5b00",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "check_call_double_use: signature re-key (c1e67b23 fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-2b4ab74cff7d2f97b18b",
        "from_id": "RG-F-2b4ab74cff7d2f97b18b",
        "to_id": "RG-F-d5cd0c131fdd09cf6d6c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "review": "evaluate_pointer_expression: signature re-key (99f023f4 core: CR8 rework — circleUnion on RuleRangeMeld OR arm + operato); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-2ffe7f84827bd91a7a70",
        "from_id": "RG-F-fdc4cfca398f53a8cc43",
        "to_id": "RG-F-bd915990f843b42dcec3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "find_normalized: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-368f07c936246d7f38ca",
        "from_id": "RG-F-368f07c936246d7f38ca",
        "to_id": "RG-F-cc4e217c1badd4960228",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "review": "get_value_datatype: signature re-key (dbcac22a fix: wire SubvariableFlow try_call_pull to oracle call-spec guar); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-36ca824e6db9a673db96",
        "from_id": "RG-F-36ca824e6db9a673db96",
        "to_id": "RG-F-1c297303ec4b0839dc87",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-39fe2822c979b62f2ff8",
        "from_id": "RG-F-39fe2822c979b62f2ff8",
        "to_id": "RG-F-bf27faa8da20efb7b41c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "store_input_cast: signature re-key (e14b7a52 align: restore TypeOpMulti phi transparency in ActionInferTypes ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-3d8642a6bd61e196fae6",
        "from_id": "RG-F-3d8642a6bd61e196fae6",
        "to_id": "RG-F-18743618f85614374e05",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "generate_relative_constraint: signature re-key (d626a117 core: value-set solver constraint generation family (RANGEUTIL-C); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-3f8506cdc116cdbcd4af",
        "from_id": "RG-F-3f8506cdc116cdbcd4af",
        "to_id": "RG-F-a8f4359f807b44837726",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "load_input_cast: signature re-key (e14b7a52 align: restore TypeOpMulti phi transparency in ActionInferTypes ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-407c79f6fb505c89bd8b",
        "from_id": "RG-F-f6c32b17adf47c37ff5f",
        "to_id": "RG-F-407c79f6fb505c89bd8b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/debugproto.rs",
        "to_path": "src/debugproto.rs",
        "parent_blob": "535c9607bdda93264fb878060fca5ef55c85fb35",
        "child_blob": "98a933ea48edc9eb2f61519c574b1ab76c8dd31c",
        "review": "void_signature_dwarf_prototype_pins_unknown_model: raw ID reverts to this baseline-era token, closing the lineage loop (af6c5ee2 core: enum-constant seeding, faithful output prototype, dso symb); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4095c525bd79c6a1e9d5",
        "from_id": "RG-F-4095c525bd79c6a1e9d5",
        "to_id": "RG-F-5e4a2aed945a92a3544f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/constseq.rs",
        "to_path": "src/constseq.rs",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "review": "transform: signature re-key (01879607 core: RuleStringStore full HeapSequence chain fires for the strn); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-43b327826f8b7d1a8a5f",
        "from_id": "RG-F-43b327826f8b7d1a8a5f",
        "to_id": "RG-F-4bcb3564a2d811b04567",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "reprocess_free_stores: signature re-key (9a5cac4c fix: match_url Phase 2 first divergence 55->70 (load-guard COPY ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4419c7711d1b266e00dd",
        "from_id": "RG-F-4419c7711d1b266e00dd",
        "to_id": "RG-F-80e27db92dcee96864bf",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/constseq.rs",
        "to_path": "src/constseq.rs",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "review": "select_string_copy_function: signature re-key (01879607 core: RuleStringStore full HeapSequence chain fires for the strn); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-44fcf9a5c35080fabaf4",
        "from_id": "RG-F-4e04105edbeff7dd0eaa",
        "to_id": "RG-F-d14405de53b00443943d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "96d8be9a9f6ac05613cc283b54324a5bd5c049ac",
        "child_blob": "13bec7c6e07f3f2b453cc9a7f7c28d26676e842e",
        "review": "op_input_type_local: signature re-key (af6c5ee2 core: enum-constant seeding, faithful output prototype, dso symb); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-45d25c0eb3e56e0ece17",
        "from_id": "RG-F-d4778a26bbcf40edc07f",
        "to_id": "RG-F-940c93f88545d0a9a335",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "propagate_across_returns: signature re-key (50d6f5f0 core: union resolution wired into pipeline, six producer sites (); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4616eac5c78178841108",
        "from_id": "RG-F-4616eac5c78178841108",
        "to_id": "RG-F-f41724e55935a7f3da26",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "review": "find: signature re-key (5317299b align: port SubfloatFlow (subflow.cc:3070-3481) and replace SUBF); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-46f2bdbe22d5abfead52",
        "from_id": "RG-F-46f2bdbe22d5abfead52",
        "to_id": "RG-F-72f1c0a89849a4fd2a65",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/cast.rs",
        "to_path": "src/type_system/cast.rs",
        "parent_blob": "89ee5be4c2f9485cad5d530874c7f494899edbad",
        "child_blob": "90f1c0ec61308ac3497bc59abd06526ac3ff8907",
        "review": "cast_standard_full: signature re-key (79b75978 cast: partial types exempt from explicit casts in castStandard t); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-48fe6c8f93b446cab259",
        "from_id": "RG-F-48fe6c8f93b446cab259",
        "to_id": "RG-F-a77b988ff57bb863572b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4c8cb470054a31b803d9",
        "from_id": "RG-F-4c8cb470054a31b803d9",
        "to_id": "RG-F-69d80ecebe6b9daee3ca",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "ancestor_op_use: signature re-key (79bb0f61 align: CALLSPEC-DRIVER-0001 flow-time callspec anchoring on the ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4f5c3734d8040f27a454",
        "from_id": "RG-F-4f5c3734d8040f27a454",
        "to_id": "RG-F-b31db2dd8ac3344bd391",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/datatype.rs",
        "to_path": "src/type_system/datatype.rs",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "review": "partial_struct_get_sub_type: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-4f99310a1c165683a602",
        "from_id": "RG-F-4f99310a1c165683a602",
        "to_id": "RG-F-5d6711661d9a6faf6856",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "ancestor_op_use: signature re-key (c1e67b23 fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-54c2084809079c0db1b4",
        "from_id": "RG-F-54c2084809079c0db1b4",
        "to_id": "RG-F-cec50911a394b1916765",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/constseq.rs",
        "to_path": "src/constseq.rs",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "review": "check_interference: signature re-key (01879607 core: RuleStringStore full HeapSequence chain fires for the strn); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-5769dd71cbf54d6f40dc",
        "from_id": "RG-F-5769dd71cbf54d6f40dc",
        "to_id": "RG-F-993a5e957e53c20ab7aa",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "review": "find_substitute: signature re-key (13cb80b1 fix: match_url Phase 2 first divergence 12->55 (concat seqnum, l); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-5acc1fe44524378a2993",
        "from_id": "RG-F-5acc1fe44524378a2993",
        "to_id": "RG-F-a2248f3edeaad9a38159",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "new: signature re-key (05da54b9 wip: fix foldIn* model ports to Ghidra 12.0.4 semantics (foldInO); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-5b842bec1b80d6108a87",
        "from_id": "RG-F-5b842bec1b80d6108a87",
        "to_id": "RG-F-560b3902b8696bea6cf0",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "analyze_new_load_guards: signature re-key (09751dc8 fix: extend typed-global coverage to glob objects); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-614df5b0ab663eee9561",
        "from_id": "RG-F-c6622ea88f98cd771ceb",
        "to_id": "RG-F-943c9ffce54566a72c11",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "review": "get_input_cast: signature re-key (a2d81171 core: typeop facing consumers go fd-aware, COPY token arm wired ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-6321663d15099e9cdffc",
        "from_id": "RG-F-6321663d15099e9cdffc",
        "to_id": "RG-F-7521f4be200a2a2a5ba1",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "new_for_implied_trunc: signature re-key (dbd06779 core: wire union edge-resolution producers into cast/typeprop pi); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-64f5c422e9b306ad0486",
        "from_id": "RG-F-64f5c422e9b306ad0486",
        "to_id": "RG-F-4e73bb88f947f5cbd811",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "analyze_guards: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-660098de7b5be80202a6",
        "from_id": "RG-F-660098de7b5be80202a6",
        "to_id": "RG-F-382d3324bcde3d89f736",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "gather_partial_pieces: signature re-key (9ab15c43 fix: bound Merge gather_partial_pieces recursion with PieceNode ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-6665054cc12a39bea8a7",
        "from_id": "RG-F-6665054cc12a39bea8a7",
        "to_id": "RG-F-85a2695399c05e09116d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "child_blob": "bb34a5998e32da1a49432ebd76ebd81c4f4365c9",
        "review": "update_input_types: signature re-key (13f080fd fix: self-function param recovery via full ActionInputPrototype ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-69082e1a1446056c0929",
        "from_id": "RG-F-68019a8fe1aec0a0531a",
        "to_id": "RG-F-2e0f624c8f20e1cad172",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "propagate_one_type: signature re-key (a77d6c02 fix: stack-domain piece placement for callsite struct params (VA); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-692f60ebcfc4f7c2b57f",
        "from_id": "RG-F-692f60ebcfc4f7c2b57f",
        "to_id": "RG-F-b2e6d53a6de0b5590d13",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "empty: signature re-key (18b020b9 unionres: deref drill-down and canonical-type corrections in sco); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-69e8d03507ac3b1ebe30",
        "from_id": "RG-F-6a67a0999e1aa4999784",
        "to_id": "RG-F-486673c37eac41c29160",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "review": "apply_op: signature re-key (99f023f4 core: CR8 rework — circleUnion on RuleRangeMeld OR arm + operato); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-6b8e37da55f6ecc8eb92",
        "from_id": "RG-F-715c3a005593c01c3b7f",
        "to_id": "RG-F-fa40cb3136b396e182a8",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "integer_text_with_mods: signature re-key (73638841 printc: emit explicit unsigned/long constant suffixes (PRINTC-IN); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-6bc453b29b6e1f28d16b",
        "from_id": "RG-F-6bc453b29b6e1f28d16b",
        "to_id": "RG-F-94cae4a0681c4444a3eb",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "deref_pointer: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-6ee3ee8b5557dec99e2c",
        "from_id": "RG-F-6ee3ee8b5557dec99e2c",
        "to_id": "RG-F-d5aeb202ea5d4c9c70be",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_type_pair: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-7073a637b916fa4ad621",
        "from_id": "RG-F-7073a637b916fa4ad621",
        "to_id": "RG-F-fdb464888cf52ff37017",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printlanguage.rs",
        "to_path": "src/printlanguage.rs",
        "parent_blob": "30a3bd4a19068b2756709a2d0d0bc2459d7ca1fb",
        "child_blob": "38d33dfb88199dcdd8448e8aeab25fc52ae4e2ff",
        "review": "push_type: signature re-key (ebcc6932 printc: RPN CALLIND arm + pushType declarator stack + P6 inline ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-76c63196d7e6b6395e4b",
        "from_id": "RG-F-8d0417520681975b1db5",
        "to_id": "RG-F-2052a82c109bea8a5b43",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "float_extension_write: signature re-key (c593705c heritage: processJoins consumer chain 1:1 (join split read/write); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-78ccc92c113f69e92c6c",
        "from_id": "RG-F-78ccc92c113f69e92c6c",
        "to_id": "RG-F-64582aa32b11c8400313",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "fold_in_normalization: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-78d6138fc67e2a7b6cb2",
        "from_id": "RG-F-78d6138fc67e2a7b6cb2",
        "to_id": "RG-F-6e765bdbf79a52255fc0",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "review": "get_input_cast: signature re-key (a2d81171 core: typeop facing consumers go fd-aware, COPY token arm wired ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-7bb0e8877a320e3beb77",
        "from_id": "RG-F-7bb0e8877a320e3beb77",
        "to_id": "RG-F-caabc4f584b95b2912ea",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "new: signature re-key (05da54b9 wip: fix foldIn* model ports to Ghidra 12.0.4 semantics (foldInO); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-7beafac2b7964f1a7a69",
        "from_id": "RG-F-7beafac2b7964f1a7a69",
        "to_id": "RG-F-117e8317c74b88097687",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_linear: signature re-key (caa9725d core: coverdirty mutations propagate high coverDirty (HIGHCOV)); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-7f4499a24e9d5f6e00f6",
        "from_id": "RG-F-7f4499a24e9d5f6e00f6",
        "to_id": "RG-F-46da1927bc8f8bbed9e9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_required_result: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8026e53037a53df12cd6",
        "from_id": "RG-F-8026e53037a53df12cd6",
        "to_id": "RG-F-79857dc37346a3ede1e1",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-80efb246c1c6cef502b9",
        "from_id": "RG-F-80efb246c1c6cef502b9",
        "to_id": "RG-F-49f913eb36de6f0eb01a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "fold_in_guards: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-815e1275a0974c35cfa6",
        "from_id": "RG-F-815e1275a0974c35cfa6",
        "to_id": "RG-F-b77697a383103414ce26",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "new: signature re-key (05da54b9 wip: fix foldIn* model ports to Ghidra 12.0.4 semantics (foldInO); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-827b6af889449cdfa621",
        "from_id": "RG-F-827b6af889449cdfa621",
        "to_id": "RG-F-2c0a2a0c34601ce91936",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "intersection: signature re-key (1250e5d0 fix: merge_test_with_list routes through precise HighIntersectTe); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-827fe3112766f8b1f36b",
        "from_id": "RG-F-827fe3112766f8b1f36b",
        "to_id": "RG-F-82751c6aba1c2d0b685a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "make_ptr: signature re-key (e14b7a52 align: restore TypeOpMulti phi transparency in ActionInferTypes ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-85317e7aebd33b457844",
        "from_id": "RG-F-e1751080679995008f76",
        "to_id": "RG-F-0f04069b9e821a168708",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "96d8be9a9f6ac05613cc283b54324a5bd5c049ac",
        "child_blob": "13bec7c6e07f3f2b453cc9a7f7c28d26676e842e",
        "review": "get_local_type: signature re-key (af6c5ee2 core: enum-constant seeding, faithful output prototype, dso symb); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-86c1af68dfdcac804331",
        "from_id": "RG-F-86c1af68dfdcac804331",
        "to_id": "RG-F-c950bf3a26e57a4fcc11",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "constraints_from_cbranch: signature re-key (d626a117 core: value-set solver constraint generation family (RANGEUTIL-C); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8783f7e0987e14dd74d6",
        "from_id": "RG-F-8783f7e0987e14dd74d6",
        "to_id": "RG-F-fc31690efe18d4711078",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/type_system/datatype.rs",
        "to_path": "src/type_system/datatype.rs",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "review": "struct_get_sub_type: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-89e016fe2736366562e6",
        "from_id": "RG-F-32e49f1cfa2f76dd9b1a",
        "to_id": "RG-F-ece9814ead84b2737728",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/varmap.rs",
        "to_path": "src/varmap.rs",
        "parent_blob": "3659b164797c3d6cb819214cca650be0eae79efa",
        "child_blob": "df1a96ff16389d09b98711f736546542c3664eff",
        "review": "restructure_varnode: signature re-key (cefd1801 fix: match_url Phase 2 first divergence 70->164 (ScopeLocal cros); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8c9e208aeb94f353de11",
        "from_id": "RG-F-8c9e208aeb94f353de11",
        "to_id": "RG-F-34b986e9ccb55b770590",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "mark_explicit_unsigned: signature re-key (dc977085 core: lift two latent scrutinee read guards to statement scope (); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8e9709511e9ac7f7b9c7",
        "from_id": "RG-F-8e9709511e9ac7f7b9c7",
        "to_id": "RG-F-acfc386205484a8311d4",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "emit_for_loop: signature re-key (0b067de5 fix: goto self-target label pairs were printc ledger anchoring, ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8ecb43535a426d40a019",
        "from_id": "RG-F-8ecb43535a426d40a019",
        "to_id": "RG-F-74b33e705f2209041e2c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_test_with_list: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-8f4e504512ee200863f5",
        "from_id": "RG-F-4c2d5f93a06006739d44",
        "to_id": "RG-F-944cdbc7e4979c473263",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "propagate_type_edge: signature re-key (dbd06779 core: wire union edge-resolution producers into cast/typeprop pi); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-9a298db1ebc4744c4d81",
        "from_id": "RG-F-9a298db1ebc4744c4d81",
        "to_id": "RG-F-28f9624a43ed879fda4a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "refresh_out_high_resolve: signature re-key (780c01fd fix: ActionDeadCode protects spec-less CALL in(0) consume (COREA); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-9b9f309fc6f60e4b3272",
        "from_id": "RG-F-a3e8132b5200c04bc8bc",
        "to_id": "RG-F-b53e1c5710796608a0b3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-9eb8a316387fb8b4eda7",
        "from_id": "RG-F-9eb8a316387fb8b4eda7",
        "to_id": "RG-F-b420b653f54f7c18598b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/varnode.rs",
        "to_path": "src/varnode.rs",
        "parent_blob": "96d8be9a9f6ac05613cc283b54324a5bd5c049ac",
        "child_blob": "13bec7c6e07f3f2b453cc9a7f7c28d26676e842e",
        "review": "find_input: signature re-key (fdb11757 fix: p3batch quartet — splitUses typed newvn, findSubstitute blo); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-a0778ccb56479e37c576",
        "from_id": "RG-F-7f5eae81c0f3bc99e3f3",
        "to_id": "RG-F-269df9ee5cb7d55a01e7",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-a176e923c63403710964",
        "from_id": "RG-F-0e446c2b7aa88ef6b4a2",
        "to_id": "RG-F-a176e923c63403710964",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "emit_flow_basic: raw ID reverts to this baseline-era token, closing the lineage loop (0b067de5 fix: goto self-target label pairs were printc ledger anchoring, ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-a17b6b8e305291daff59",
        "from_id": "RG-F-a17b6b8e305291daff59",
        "to_id": "RG-F-18434fc2854cdfff8473",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "push_type: signature re-key (ebcc6932 printc: RPN CALLIND arm + pushType declarator stack + P6 inline ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-a609af621c4f7aa229af",
        "from_id": "RG-F-a609af621c4f7aa229af",
        "to_id": "RG-F-f188179f04ce5e71dfee",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "cse_find_in_block: signature re-key (3ff35e23 core: four latent closures, type carry, block filter, space matc); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-aa8fd9e00030cf9ce2b6",
        "from_id": "RG-F-aa8fd9e00030cf9ce2b6",
        "to_id": "RG-F-393d63210c286a7210e6",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "ptr_input_reqtype: signature re-key (780c01fd fix: ActionDeadCode protects spec-less CALL in(0) consume (COREA); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-aeb8d423e0f3a9bcc9cd",
        "from_id": "RG-F-aeb8d423e0f3a9bcc9cd",
        "to_id": "RG-F-49dfda3363343e0433d9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/constseq.rs",
        "to_path": "src/constseq.rs",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "review": "form_byte_array: signature re-key (01879607 core: RuleStringStore full HeapSequence chain fires for the strn); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-b4b72e04dd90228ef3bb",
        "from_id": "RG-F-665a47a570add0a10a83",
        "to_id": "RG-F-d4425392f6e84096fc7a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "split_join_read: signature re-key (c593705c heritage: processJoins consumer chain 1:1 (join split read/write); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-b87e3846e27e434b4bfd",
        "from_id": "RG-F-b87e3846e27e434b4bfd",
        "to_id": "RG-F-3e91241d56bd40490b28",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "apply_constraints: signature re-key (d626a117 core: value-set solver constraint generation family (RANGEUTIL-C); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-b9dc9947cf63b842e5d9",
        "from_id": "RG-F-b9dc9947cf63b842e5d9",
        "to_id": "RG-F-3a18532285d86cae6790",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "push_forward_binary: signature re-key (dbd5d89b core: rangeutil value-set fill/iterate live path + RuleRangeMeld); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-bc74f0d9039600d1864e",
        "from_id": "RG-F-bc74f0d9039600d1864e",
        "to_id": "RG-F-90f730e9c1bbca2fc102",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/coreaction.rs",
        "to_path": "src/coreaction.rs",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "review": "analyze_extra_pop: signature re-key (8cf844a1 core: parking-chain family integrated, dual-baseline win (EQ3 ro); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-bcec90a45f20c425e217",
        "from_id": "RG-F-bcec90a45f20c425e217",
        "to_id": "RG-F-16ee7fda412a0a96b79c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "new: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-bd60554faf89984f30be",
        "from_id": "RG-F-bd60554faf89984f30be",
        "to_id": "RG-F-c97d899146f0bbc23a15",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/subflow.rs",
        "to_path": "src/subflow.rs",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "review": "try_call_pull: signature re-key (5317299b align: port SubfloatFlow (subflow.cc:3070-3481) and replace SUBF); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-be4fb6bac4aa0d1906a6",
        "from_id": "RG-F-be4fb6bac4aa0d1906a6",
        "to_id": "RG-F-b51b2deb8da29696dc52",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "review": "set_pending_brace: signature re-key (e1ee7de6 fix: PendingBrace per-install identity ends the prettyprint.rs:3); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-caaba4c4451663e8192a",
        "from_id": "RG-F-caaba4c4451663e8192a",
        "to_id": "RG-F-f520a43dcd8762748705",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-cd9fb6ded582fdb4a253",
        "from_id": "RG-F-cd9fb6ded582fdb4a253",
        "to_id": "RG-F-c9c94fa204bef1d0f6a7",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "new: signature re-key (05da54b9 wip: fix foldIn* model ports to Ghidra 12.0.4 semantics (foldInO); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-d084af6d55490fcb2f03",
        "from_id": "RG-F-d084af6d55490fcb2f03",
        "to_id": "RG-F-6060d4628884d9c7b934",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_speculative: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-d7bbd57335d62c42df4f",
        "from_id": "RG-F-d7bbd57335d62c42df4f",
        "to_id": "RG-F-99f929268ea42c2d5675",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-dae04c9c907df09546fa",
        "from_id": "RG-F-278468edac56855d183b",
        "to_id": "RG-F-e9d1d51845e6a8b2af36",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "push_partial_symbol: binding-mut re-key (5168a735 merge: symbol-first leaf printing with partial-symbol form (DAT ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-dbcf028e82133b9565c3",
        "from_id": "RG-F-070808d769156b8f203d",
        "to_id": "RG-F-b41f1c06100a7f440c36",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "recover_model: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-dc8dd0e36487b3b2fb4a",
        "from_id": "RG-F-dc8dd0e36487b3b2fb4a",
        "to_id": "RG-F-6d463d2e267d5753352c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "child_blob": "bb34a5998e32da1a49432ebd76ebd81c4f4365c9",
        "review": "check_input_trial_use: signature re-key (c1e67b23 fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-ddcc1f330d0332f912ae",
        "from_id": "RG-F-ddcc1f330d0332f912ae",
        "to_id": "RG-F-6a8ca348f696a0ccc27a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "establish_range: signature re-key (0b996bed core: wire ValueSetSolver into LoadGuard establish/finalize (her); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-debbaec13ded4d28d1ed",
        "from_id": "RG-F-debbaec13ded4d28d1ed",
        "to_id": "RG-F-4fe9e16efa2a6b2ffced",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "block_intersection: signature re-key (1250e5d0 fix: merge_test_with_list routes through precise HighIntersectTe); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-df8aed776091cdabd260",
        "from_id": "RG-F-df8aed776091cdabd260",
        "to_id": "RG-F-de4503d9225d9713c77c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/typeop.rs",
        "to_path": "src/typeop.rs",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "review": "comparison_input_cast: signature re-key (a2d81171 core: typeop facing consumers go fd-aware, COPY token arm wired ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-e3c7f85da0796b6253c4",
        "from_id": "RG-F-e3c7f85da0796b6253c4",
        "to_id": "RG-F-9a9ed4cf8bf43083e3ff",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/constseq.rs",
        "to_path": "src/constseq.rs",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "review": "gather_indirect_pairs: signature re-key (01879607 core: RuleStringStore full HeapSequence chain fires for the strn); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-e80d4c879a2f526486ce",
        "from_id": "RG-F-1163f8df2460f380836e",
        "to_id": "RG-F-40549d264fd9c758c752",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "find_varnode_input: signature re-key (21f4205c align: FUNCDATA-SCOPELOCALOVERFLOW-0001 wrap-domain fix (scope_l); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-e878fd4581e333b2901f",
        "from_id": "RG-F-e878fd4581e333b2901f",
        "to_id": "RG-F-f6d4c6dd7f9ae71405a9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/printc.rs",
        "to_path": "src/printc.rs",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "review": "emit_structured_infloop: signature re-key (0b067de5 fix: goto self-target label pairs were printc ledger anchoring, ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-eb3426c01ce39d7eb5e4",
        "from_id": "RG-F-eb3426c01ce39d7eb5e4",
        "to_id": "RG-F-922c621e9666b98875ff",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/ruleaction.rs",
        "to_path": "src/ruleaction.rs",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "review": "verify_preferred_pointer: signature re-key (99f023f4 core: CR8 rework — circleUnion on RuleRangeMeld OR arm + operato); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-eef41041ac8e520895ee",
        "from_id": "RG-F-eef41041ac8e520895ee",
        "to_id": "RG-F-833fb812c4b36c827a42",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/prettyprint.rs",
        "to_path": "src/prettyprint.rs",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "review": "set_pending_brace: signature re-key (e1ee7de6 fix: PendingBrace per-install identity ends the prettyprint.rs:3); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-ef9802b1e78c6b85d7eb",
        "from_id": "RG-F-ef9802b1e78c6b85d7eb",
        "to_id": "RG-F-0ec433144b996e971af4",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/fspec.rs",
        "to_path": "src/fspec.rs",
        "parent_blob": "da974cb01433fd7580dd3cfb1b1d03ca721263d7",
        "child_blob": "bb34a5998e32da1a49432ebd76ebd81c4f4365c9",
        "review": "space_name_for_addr: signature re-key (b275db63 fix: port modelrule fillin dispatch for output trials (match_url); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-effd3684359ae297f230",
        "from_id": "RG-F-effd3684359ae297f230",
        "to_id": "RG-F-c8f3dbd5f36d5397aaa7",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "clone_model: signature re-key (e27e9857 fix: thread real parent table state through switch recovery mode); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f1c07fdfb00e5862b60a",
        "from_id": "RG-F-f1c07fdfb00e5862b60a",
        "to_id": "RG-F-c88411b5ae073a7a72b1",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/heritage.rs",
        "to_path": "src/heritage.rs",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "review": "process_joins: signature re-key (c593705c heritage: processJoins consumer chain 1:1 (join split read/write); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f23c84cf58035a9ebe14",
        "from_id": "RG-F-f23c84cf58035a9ebe14",
        "to_id": "RG-F-1dc9c2147f40511a7a8b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/merge.rs",
        "to_path": "src/merge.rs",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "review": "merge_speculative_by_vn: signature re-key (cfd819be fix: compute_varnode_covers materializes the oracle lazy cover p); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f2badfebbd89a2ed2bc6",
        "from_id": "RG-F-f2badfebbd89a2ed2bc6",
        "to_id": "RG-F-21e0ac28551f044dca6e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "only_op_use: signature re-key (c1e67b23 fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f38d5881cc3a460135ff",
        "from_id": "RG-F-f38d5881cc3a460135ff",
        "to_id": "RG-F-e8ce8c77c3620a5ab966",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/rangeutil.rs",
        "to_path": "src/rangeutil.rs",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "review": "generate_constraints: signature re-key (d626a117 core: value-set solver constraint generation family (RANGEUTIL-C); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f4aa72ee02bdf111fcd3",
        "from_id": "RG-F-f4aa72ee02bdf111fcd3",
        "to_id": "RG-F-b7b702b2308146f88e35",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "fold_in_normalization: signature re-key (c9b4b2cf wip: port JumpTable matchModel/recoverLabels/trivialSwitchOver/f); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f50a838960c2cc4b2803",
        "from_id": "RG-F-f50a838960c2cc4b2803",
        "to_id": "RG-F-e210f36f5ecda32d81c9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "with_field: signature re-key (18b020b9 unionres: deref drill-down and canonical-type corrections in sco); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-f7d034b180f778c0b7a4",
        "from_id": "RG-F-f7d034b180f778c0b7a4",
        "to_id": "RG-F-003a096c5edc6c456ded",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/funcdata.rs",
        "to_path": "src/funcdata.rs",
        "parent_blob": "2148724af96f1d9842b61ef6796199d071e814e6",
        "child_blob": "b14ba33b0ff784d4cea880138a1efc633559e248",
        "review": "adjust_input_varnodes: signature re-key (21f4205c align: FUNCDATA-SCOPELOCALOVERFLOW-0001 wrap-domain fix (scope_l); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-fbb344d0a6765f84f294",
        "from_id": "RG-F-fbb344d0a6765f84f294",
        "to_id": "RG-F-55e1e0c41b7b89a5db6b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "score_truncation: signature re-key (2b324b88 wip: route spacebase subtype through virtual dispatch as Ghidra ); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-fe8f47856b4f6df506ff",
        "from_id": "RG-F-fe8f47856b4f6df506ff",
        "to_id": "RG-F-fba8b8b1904fa47ba493",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/jumptable.rs",
        "to_path": "src/jumptable.rs",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "review": "new: signature re-key (05da54b9 wip: fix foldIn* model ports to Ghidra 12.0.4 semantics (foldInO); master-window change folded at the regen anchor",
    },
    {
        "base_id": "RG-F-ffc9c39bf41866161a52",
        "from_id": "RG-F-ffc9c39bf41866161a52",
        "to_id": "RG-F-188bbf4a5725ad8c3d30",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "from_path": "src/unionresolve.rs",
        "to_path": "src/unionresolve.rs",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "review": "new_for_subpiece: signature re-key (dbd06779 core: wire union edge-resolution producers into cast/typeprop pi); master-window change folded at the regen anchor",
    },
)
CONTINUITY_REVIEWED_TOMBSTONES: tuple[dict[str, str], ...] = (
    # --- merge window 65422a62..10ea407d (master DECL-SPACING-NAMEFLOW wave) ---
    {
        "base_id": "RG-F-cf22821ce96008ff0c7e",
        "from_id": "RG-F-cf22821ce96008ff0c7e",
        "commit": "10ea407df05d4f92cbd71ffe4df20aac70b5afb8",
        "parent_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "child_blob": "505d7a3bfd57ae00f5f6171f66576c56dd494a0e",
        "reason": "type_name_ends_with_star: deleted pure-delegation Rust wrapper (RUDRA-GLUE marked, body was one call to datatype_name_ends_with_star); its join-spacing role succeeded to decl_prefix_ends_with_star (10ea407d)",
    },
    {
        "base_id": "RG-F-6d0b423a6eb30f204ebc",
        "from_id": "RG-F-6d0b423a6eb30f204ebc",
        "commit": "10ea407df05d4f92cbd71ffe4df20aac70b5afb8",
        "parent_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "child_blob": "505d7a3bfd57ae00f5f6171f66576c56dd494a0e",
        "reason": "emit_type_prefix: one-statement Rust text-render helper inlined into push_type_start_opt's type_expr_space branch during the DECL-SPACING-NAMEFLOW rework; no same-role successor exists (10ea407d)",
    },
    {
        "base_id": "RG-F-5ec71c480ba4438dca3a",
        "from_id": "RG-F-5ec71c480ba4438dca3a",
        "commit": "92daed300bcce3c4d855b311cf9667ba21eb475a",
        "parent_blob": "ae2cf089a3f644385d8a64ce213f7f1b0b88103a",
        "child_blob": "b44b6b2204becc01234d3dab8415899d83c7f777",
        "reason": "removed by access-width gating; no successor (92daed3)",
    },
    {
        "base_id": "RG-F-002a9ec13d8e062540b9",
        "from_id": "RG-F-002a9ec13d8e062540b9",
        "commit": "874e81f7b9877b519c8ab55b57cbac24de0918f0",
        "parent_blob": "4fef0e1b7cbaf0ac1508b64cb5e7e0966748a588",
        "child_blob": "f2e73aa6795f35c93f8bceb6e2290a43c427b357",
        "reason": "superseded by canonical type-tree keys; no successor (874e81f)",
    },
    {
        "base_id": "RG-F-bd9141cd6ae9f5a4ddad",
        "from_id": "RG-F-bd9141cd6ae9f5a4ddad",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "parent_blob": "6607bf4acdc7a2b54a47623d473a999f6996d42e",
        "child_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "reason": "replaced by owner-handle call-spec lookup; no successor (cad41c2)",
    },
    {
        "base_id": "RG-F-e43c2d78ba8a0472a781",
        "from_id": "RG-F-e43c2d78ba8a0472a781",
        "commit": "cad41c27104b0b5314fb3bcc78d54f6f5b55a1db",
        "parent_blob": "b01176babb67aa227a2a00ed1ac402221dac2449",
        "child_blob": "81f6344ef0bdecaba1c994c1b0cdfb9a53b5de1a",
        "reason": "replaced by owner-handle call-spec lookup; no successor (cad41c2)",
    },
    {
        "base_id": "RG-F-93890c76dc270880c224",
        "from_id": "RG-F-93890c76dc270880c224",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "parent_blob": "81f6344ef0bdecaba1c994c1b0cdfb9a53b5de1a",
        "child_blob": "97f66c8ac70b5cc2f1795ad4c45647824a5b80a5",
        "reason": "superseded by canonical TypeFactory get_exact_piece; no successor (f87e4d8)",
    },
    {
        "base_id": "RG-F-ded5b6e2aef38fd29e5a",
        "from_id": "RG-F-ded5b6e2aef38fd29e5a",
        "commit": "f87e4d802652244e1b5792097d53a746d164dc07",
        "parent_blob": "f4f0308e571b0ca56af88ab627a6eab2aebb6c7a",
        "child_blob": "de9ecc914f2fc2cc65b246f8462dfbf26b39f33c",
        "reason": "superseded by canonical TypeFactory get_exact_piece; no successor (f87e4d8)",
    },
    {
        "base_id": "RG-F-56411d1c69a8e636a9cc",
        "from_id": "RG-F-56411d1c69a8e636a9cc",
        "commit": "bdc7f341d3a588045832a670f02cf384d3b12e1a",
        "parent_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "child_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "reason": "FuncCallSpecsExt retired with its trait+impl pair; absorbed into FlowInfo queryCall (bdc7f34)",
    },
    {
        "base_id": "RG-F-95a861f4477ffddc9d35",
        "from_id": "RG-F-95a861f4477ffddc9d35",
        "commit": "bdc7f341d3a588045832a670f02cf384d3b12e1a",
        "parent_blob": "f7722f4fb73c31cfbf562222f5767e11864f2ab5",
        "child_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "reason": "FuncCallSpecsExt retired with its trait+impl pair; absorbed into FlowInfo queryCall (bdc7f34)",
    },
    {
        "base_id": "RG-F-8544a0e173d594065ca7",
        "from_id": "RG-F-8544a0e173d594065ca7",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },
    {
        "base_id": "RG-F-9e46078d26f5ecc6cd37",
        "from_id": "RG-F-9e46078d26f5ecc6cd37",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },
    {
        "base_id": "RG-F-b2cb4f664723372b7400",
        "from_id": "RG-F-b2cb4f664723372b7400",
        "commit": "11371d512e9b374ec73d5a7e7181e6ed52eba296",
        "parent_blob": "a5c0c6f9557598bc6a1de70606b74d5d71c7f8ab",
        "child_blob": "33ee849f1de230fd087e1131d1104c3c3522a955",
        "reason": "impl:StringManagerUnicode retired by GhidraStringManager Java contract port; no same-class successor (11371d5)",
    },

    {
        "base_id": "RG-F-bd201b6f89048574b546",
        "from_id": "RG-F-bd201b6f89048574b546",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "reason": "superseded by the 12.0.4 struct/array/pointer bit semantics; no successor (1644180d)",
    },
    {
        "base_id": "RG-F-23e0cdef45d8a01764a7",
        "from_id": "RG-F-23e0cdef45d8a01764a7",
        "commit": "1644180de42b58cd0155f62c9b3ad82efc820a57",
        "parent_blob": "a94e6f58f60a02e2b5ac52e68ed822ccc7ab3f0d",
        "child_blob": "b8734eb52066baf8a30f8e81846f9df3d3855932",
        "reason": "test retired with get_split_datatype_bit; no successor (1644180d)",
    },
    {
        "base_id": "RG-F-b04bd21a5d624e1fc06f",
        "from_id": "RG-F-b04bd21a5d624e1fc06f",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "superseded by the exact-piece gate chain (TypeFactory get_exact_piece); no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-98eb48688773519607ba",
        "from_id": "RG-F-98eb48688773519607ba",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "superseded by the exact-piece gate chain; no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-255edda2318d460e2e4b",
        "from_id": "RG-F-255edda2318d460e2e4b",
        "commit": "26d675e7f6131ed17e8de6a689b5b3d85ec21470",
        "parent_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "child_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "reason": "test replaced by exact-piece gate coverage; no successor (26d675e7)",
    },
    {
        "base_id": "RG-F-88d87eaf0e792af4c255",
        "from_id": "RG-F-88d87eaf0e792af4c255",
        "commit": "4495eb601d22f959bad64a6c085f516431195b42",
        "parent_blob": "80a82de9b2e16872177748299aa8dd325e8ccb64",
        "child_blob": "9d4ffe1a072d45accd3e7eb87e3d9942d43d054c",
        "reason": "reset retired from the Rule surface by the breakpoint-aware pool executor; no successor (4495eb60)",
    },
    {
        "base_id": "RG-F-ef02d5e77634269ac883",
        "from_id": "RG-F-ef02d5e77634269ac883",
        "commit": "4495eb601d22f959bad64a6c085f516431195b42",
        "parent_blob": "e42479af547350de04a1eb368263bd9b8c689c1a",
        "child_blob": "5b0ddb920d904ae2b396c4535713ae28f47d9ac3",
        "reason": "reset retired from the Rule surface by the breakpoint-aware pool executor; no successor (4495eb60)",
    },
    {
        "base_id": "RG-F-069b0702a18335d9be0c",
        "from_id": "RG-F-069b0702a18335d9be0c",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-c261bf862e86c3ae27dd",
        "from_id": "RG-F-c261bf862e86c3ae27dd",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-15a6b977326f7c0a9e15",
        "from_id": "RG-F-15a6b977326f7c0a9e15",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-dda630121a5380c159b1",
        "from_id": "RG-F-dda630121a5380c159b1",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-53ed24ee2a9a1e691b6b",
        "from_id": "RG-F-53ed24ee2a9a1e691b6b",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-080a097af2330629ba3f",
        "from_id": "RG-F-080a097af2330629ba3f",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-e6a5ca59c7df4b468e28",
        "from_id": "RG-F-e6a5ca59c7df4b468e28",
        "commit": "73b5ef26453372a2b562051f113f9b299bcebeef",
        "parent_blob": "a9cb66bb99679d9547d510b01247afe018d73be6",
        "child_blob": "7677154d56ee1df699b9fd86635e10f8be74d146",
        "reason": "EmulateFunction methods retired by the loader/error channel rework; no successor (73b5ef26)",
    },
    {
        "base_id": "RG-F-8e6f7437052ad650c6c7",
        "from_id": "RG-F-8e6f7437052ad650c6c7",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "reason": "TypeOpCopy input locals superseded by the getBase(size, ctor meta) dispatch; no successor (8e5944ca)",
    },
    {
        "base_id": "RG-F-9712364a6d3cf8e6a6a9",
        "from_id": "RG-F-9712364a6d3cf8e6a6a9",
        "commit": "8e5944cad072ae10595214016a5f70e64fcae015",
        "parent_blob": "9caf3207ac72015b8e46a4e397bf514cac75377a",
        "child_blob": "40e9ece4190b8fa96dc885af06466bf5bb13386d",
        "reason": "TypeOpCopy output locals superseded by the getBase(size, ctor meta) dispatch; no successor (8e5944ca)",
    },
    {
        "base_id": "RG-F-30101d742841018ea6b2",
        "from_id": "RG-F-30101d742841018ea6b2",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-aeb06d1101df113fd3b2",
        "from_id": "RG-F-aeb06d1101df113fd3b2",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-8e4485d9f15252be0689",
        "from_id": "RG-F-8e4485d9f15252be0689",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-deed2231a6bf3a9a609f",
        "from_id": "RG-F-deed2231a6bf3a9a609f",
        "commit": "b8da22a86f28cb2750fe85e1a7c69391c900a1fc",
        "parent_blob": "0dcdf7eb67c8994d71e8e80951c0dd71644e2a2e",
        "child_blob": "23cca3811e8d92f034f150dde3216b255206dc96",
        "reason": "FuncCallSpecsExt predicates absorbed into queryCall copyFlowEffects; no successor (b8da22a8)",
    },
    {
        "base_id": "RG-F-cb2c742a239b918218ca",
        "from_id": "RG-F-cb2c742a239b918218ca",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-4a37bb3ab1d3734f0c77",
        "from_id": "RG-F-4a37bb3ab1d3734f0c77",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-addd45c134e9c47b4617",
        "from_id": "RG-F-addd45c134e9c47b4617",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-2f5c843a5f5bb2d862e9",
        "from_id": "RG-F-2f5c843a5f5bb2d862e9",
        "commit": "cddcefd88006dd68ed69284ed31562a08fda3107",
        "parent_blob": "f59e4cdb2e320c7b0ddd3a718f3c0710c42087de",
        "child_blob": "76c7fd80219848d352c7ee156e2cbfa5a90ad221",
        "reason": "goto-cascade internals replaced by the TraceDAG oracle chain; no successor (cddcefd8)",
    },
    {
        "base_id": "RG-F-9f52bbaae4d239936a07",
        "from_id": "RG-F-9f52bbaae4d239936a07",
        "commit": "e956e963b167ed1d57a7a4daed2a3566f2425999",
        "parent_blob": "5db2d8861d2c0be679645503b11acd3679f2a157",
        "child_blob": "5cde46e8aa9a67d5c19e80566aeead7cbbda72db",
        "reason": "retired by the condexe success-channel rework; no successor (e956e963)",
    },

    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-16c31deda08795ad3093",
        "from_id": "RG-F-16c31deda08795ad3093",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "reason": "callspec setup retired onto FlowInfo::setup_call_specs (26eee4ad)",
    },
    {
        "base_id": "RG-F-4991980ba6d7be445656",
        "from_id": "RG-F-4991980ba6d7be445656",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage test helper retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-91b02db0f11bf77a4794",
        "from_id": "RG-F-91b02db0f11bf77a4794",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "a07b84aa844f90a3f2f3656729b449360dbd77df",
        "child_blob": "b03c2682c3c0301b34b14fe273f297b4c067bcc3",
        "reason": "known-callee return-type table retired; no successor (26eee4ad)",
    },
    {
        "base_id": "RG-F-96f8a3e95e70159bece0",
        "from_id": "RG-F-96f8a3e95e70159bece0",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::from_sleigh retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-9b222eeba49a70df3b79",
        "from_id": "RG-F-9b222eeba49a70df3b79",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "test retired with the model-binding rework; no successor (26eee4ad)",
    },
    {
        "base_id": "RG-F-9f7e83ffb52973d9aec4",
        "from_id": "RG-F-9f7e83ffb52973d9aec4",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::assign retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-b8da745f71c85226ca7e",
        "from_id": "RG-F-b8da745f71c85226ca7e",
        "commit": "26eee4ad27fc36a132c948876c9e0fbbb79051e2",
        "parent_blob": "96514bd8772bac89afac235fd8529b0964162885",
        "child_blob": "f6841300be191c28f7bb00239ddac4a1199187e4",
        "reason": "X86_64GccStorage::from_registers retired with the storage carrier rework (26eee4ad)",
    },
    {
        "base_id": "RG-F-b08ab6d33575c1274bd2",
        "from_id": "RG-F-b08ab6d33575c1274bd2",
        "commit": "2d78b5afc4333180187c1c764b9b23fd71289487",
        "parent_blob": "22707482e6a340dfad8f51f8549825816b7426f6",
        "child_blob": "86fc48bd21f36999a488fed88ee221763c9d6eae",
        "reason": "bblocks staleness fingerprint helper retired; no successor (2d78b5af)",
    },
    {
        "base_id": "RG-F-d5b104b5737433f9258f",
        "from_id": "RG-F-d5b104b5737433f9258f",
        "commit": "3b6e3139f3f6e9ba3d8d999b046fe7d30310c224",
        "parent_blob": "73226c089b941c9025aedf39b4d65e6af170403f",
        "child_blob": "f7760d99ae8f2ddaf0690e786d0b7cf964737b0f",
        "reason": "replaced by the ported RootPointer::buildPointers chain; no 1:1 successor (3b6e3139)",
    },
    {
        "base_id": "RG-F-19f611a02beef2ac0b9b",
        "from_id": "RG-F-19f611a02beef2ac0b9b",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "reason": "textual De Morgan helper retired with the structured-negate rework (3fb97c11)",
    },
    {
        "base_id": "RG-F-34ac6f9501dab285e4c2",
        "from_id": "RG-F-34ac6f9501dab285e4c2",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "03efffda74f9c4aaa212407845eb2d963111474b",
        "child_blob": "659bbea603929d97c83ef8ecdf77c42364e293cd",
        "reason": "blanket memory-output block retired with the strict deadcode delay port (3fb97c11)",
    },
    {
        "base_id": "RG-F-abbb15fe53c1fe59162d",
        "from_id": "RG-F-abbb15fe53c1fe59162d",
        "commit": "3fb97c113e3128c78b5856099d0bffe5deeda496",
        "parent_blob": "528741b24e387545ab545ec1e387cb3e94b18690",
        "child_blob": "9e2caa708db715036ac2abda12f8d33317935dfb",
        "reason": "paren-strip helper retired with the textual De Morgan composition (3fb97c11)",
    },
    {
        "base_id": "RG-F-69a24b4aa7a5774bcbbc",
        "from_id": "RG-F-69a24b4aa7a5774bcbbc",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "8f1456eae2533968f04d4c5f50c12c2470bce926",
        "child_blob": "754437b93519caef298467a78341bbf0b330d54e",
        "reason": "RPN constant formatting folded into constant_leaf_text/integer_text; no 1:1 successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-935389e7c53de5c13756",
        "from_id": "RG-F-935389e7c53de5c13756",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "8f1456eae2533968f04d4c5f50c12c2470bce926",
        "child_blob": "754437b93519caef298467a78341bbf0b330d54e",
        "reason": "folded into PrintC::constant_leaf_text pushConstant dispatch; no 1:1 successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-ca8e5e48082eb933ed01",
        "from_id": "RG-F-ca8e5e48082eb933ed01",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "bd4a0a1de7286167b07d6a3d9e1fa9ebcbb36d74",
        "child_blob": "5a72e2f171b8195a063ef7c9d95ec705510a04c6",
        "reason": "ruleBlockGoto no-op stub removed in mapglobals finalize; no successor (4d1bcf29)",
    },
    {
        "base_id": "RG-F-be28b0ba758951601dda",
        "from_id": "RG-F-be28b0ba758951601dda",
        "commit": "8dae10d3c2b02df7424beaba2abf9fdf72bbdb66",
        "parent_blob": "0d976f2593b57a67e2295c82ab0c1576d5c68cb6",
        "child_blob": "9d59388d6012e7a01d71ade00fa7b0f2d6e7d8c9",
        "reason": "TypeOpStore::getInputLocal override removed; base TypeOp dispatch remains (8dae10d3)",
    },
    {
        "base_id": "RG-F-1e84c830545d01637f72",
        "from_id": "RG-F-1e84c830545d01637f72",
        "commit": "a5362afcfcccc25d87e4853552440d4fad619d1b",
        "parent_blob": "8fd771c35277d4ff21739b78b3a3859cfc65ad2b",
        "child_blob": "d57fce1e6051f9980132f919976b4a03ab107192",
        "reason": "DepthDec Drop impl retired with the emit-depth rework; no successor (a5362afc)",
    },
    {
        "base_id": "RG-F-34c3b946a9961b60b651",
        "from_id": "RG-F-fe174638708e62b5cdaf",
        "commit": "420174438fdf3ae4f7e09b483af14cc04215316d",
        "parent_blob": "bc69f87d61814e00c77b11cb59dd00d43200fbbb",
        "child_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "reason": "mark_front_leaf_dyn: specialized BlockBasic leaf-marker (flags |= fl on the block itself) retired with the BlockGoto wrapped-component port; the markCopyBlock call site (block.cc:2860-2863) now routes through the pre-existing general mark_front_leaf, whose front_leaf descent implements FlowBlock::getFrontLeaf (block.cc:340) on the dyn target (a2c5ce26)",
    },
    {
        "base_id": "RG-F-122e53031d85d983b3c5",
        "from_id": "RG-F-122e53031d85d983b3c5",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "parent_blob": "0d8cf0ac26e57fccca9e1c46efa478daffb4a0a1",
        "child_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "reason": "W0 dead-code removal: try_convert_ptr_add deleted with the dead struct-deref trio (f8fe3cb3, POSTFIX-RETIRE-0001); no same-role successor exists",
    },
    {
        "base_id": "RG-F-c5250352efdcc2e7c776",
        "from_id": "RG-F-c5250352efdcc2e7c776",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "parent_blob": "0d8cf0ac26e57fccca9e1c46efa478daffb4a0a1",
        "child_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "reason": "W0 dead-code removal: reconcile_pointer_arith deleted as a dead reconciliation helper (92160892, POSTFIX-RETIRE-0001); no same-role successor exists",
    },
    {
        "base_id": "RG-F-df1ebb5b6896001240d2",
        "from_id": "RG-F-df1ebb5b6896001240d2",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "parent_blob": "0d8cf0ac26e57fccca9e1c46efa478daffb4a0a1",
        "child_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "reason": "W0 dead-code removal: rewrite_struct_deref deleted with the dead struct-deref trio (f8fe3cb3, POSTFIX-RETIRE-0001); no same-role successor exists",
    },
    {
        "base_id": "RG-F-e4e0c8f016826161ad18",
        "from_id": "RG-F-e4e0c8f016826161ad18",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "parent_blob": "0d8cf0ac26e57fccca9e1c46efa478daffb4a0a1",
        "child_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "reason": "W0 dead-code removal: canonicalize_struct_deref deleted with the dead struct-deref trio (f8fe3cb3, POSTFIX-RETIRE-0001); no same-role successor exists",
    },
    {
        "base_id": "RG-F-f6de4e0f5185cd7b9aef",
        "from_id": "RG-F-f6de4e0f5185cd7b9aef",
        "commit": "ac7a35266cf5612ac6d8bb340f53a4a946418d14",
        "parent_blob": "0d8cf0ac26e57fccca9e1c46efa478daffb4a0a1",
        "child_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "reason": "W0 dead-code removal: recover_struct_fields_anon deleted as a dead anon-struct recovery helper (68e3ebdc, POSTFIX-RETIRE-0001); no same-role successor exists",
    },
    {
        "base_id": "RG-F-0956a3c1a45b988e2264",
        "from_id": "RG-F-0956a3c1a45b988e2264",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "reason": "test_rule_subfloat_convert_nonconst_widening_tags_output: deleted at 5317299b (align: port SubfloatFlow (subflow.cc:3070-3481) and replace SUBF); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-0d2289bfdcab7b4448fa",
        "from_id": "RG-F-0d2289bfdcab7b4448fa",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "get_name: deleted at 430ddb3c (core: expel corpus name tables from coreaction (EXPEL-CORPUS-TAB); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-0ed2474deb7fd50b1810",
        "from_id": "RG-F-0ed2474deb7fd50b1810",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after: deleted at cb912769 (blockaction: switch default joins the fall-thru chain graph and ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-11fe8713d50574890a0d",
        "from_id": "RG-F-11fe8713d50574890a0d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "reason": "get_input_cast: deleted at a2d81171 (core: typeop facing consumers go fd-aware, COPY token arm wired ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-1c73f35250d2f790089b",
        "from_id": "RG-F-1c73f35250d2f790089b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "previous_op_in_block: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-1db18bd849feb0c1a2ff",
        "from_id": "RG-F-1db18bd849feb0c1a2ff",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "set_defining_op: deleted at dbd5d89b (core: rangeutil value-set fill/iterate live path + RuleRangeMeld); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-1f5b317e9c9d4e92a42c",
        "from_id": "RG-F-1f5b317e9c9d4e92a42c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "new: deleted at 0106750e (fix: ActionDoNothing self-loop warning lands at the block cover ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-1fa229bcb4933c3aa865",
        "from_id": "RG-F-1fa229bcb4933c3aa865",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "5e1e9bb4870699cadbf7b6c1506e20959b4c4cf7",
        "child_blob": "5882edca234631ee3d1a77e61c4f1ce22b07e0f5",
        "reason": "test_load_guard_range_stubs: deleted at 0b996bed (core: wire ValueSetSolver into LoadGuard establish/finalize (her); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-207970b57ae89033f8ef",
        "from_id": "RG-F-207970b57ae89033f8ef",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "reason": "resolve_in_flow: deleted at e94c3640 (core: intern ResolvedUnion::with_field pointer arm via TypeFacto); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-2a30e8b9fb9513652359",
        "from_id": "RG-F-2a30e8b9fb9513652359",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after_parent: deleted at 5e71c678 (wip: promote nextFlowAfter dispatch to block.rs single source (c); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-2f5becc12de85429ab6e",
        "from_id": "RG-F-2f5becc12de85429ab6e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "new_stride: deleted at 99f023f4 (core: CR8 rework — circleUnion on RuleRangeMeld OR arm + operato); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-34b7e7a5eccad1c230cc",
        "from_id": "RG-F-34b7e7a5eccad1c230cc",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "build_string_copy: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-3524f2b85a89317f48c9",
        "from_id": "RG-F-3524f2b85a89317f48c9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "get_string: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-39e5459fa425a2e12584",
        "from_id": "RG-F-39e5459fa425a2e12584",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "reason": "get_output_token: deleted at a2d81171 (core: typeop facing consumers go fd-aware, COPY token arm wired ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-3d0d2effbe43a91462ce",
        "from_id": "RG-F-3d0d2effbe43a91462ce",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "known_param_count: deleted at 430ddb3c (core: expel corpus name tables from coreaction (EXPEL-CORPUS-TAB); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-3d82ffd9aa8f8d3850b6",
        "from_id": "RG-F-3d82ffd9aa8f8d3850b6",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "new_domain: deleted at 99f023f4 (core: CR8 rework — circleUnion on RuleRangeMeld OR arm + operato); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-444114638e85929a8a7c",
        "from_id": "RG-F-444114638e85929a8a7c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "is_known_function: deleted at 430ddb3c (core: expel corpus name tables from coreaction (EXPEL-CORPUS-TAB); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-482acb248a628653592d",
        "from_id": "RG-F-482acb248a628653592d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "reason": "capture_inline_expr_text: deleted at 439111cb (printc: signature tokenbreaks restored, print-time RAX return re); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-4888aa18f6c00f918567",
        "from_id": "RG-F-4888aa18f6c00f918567",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "goto_prints_walk_level: deleted at 5e71c678 (wip: promote nextFlowAfter dispatch to block.rs single source (c); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-4e37a3628b4770e851f8",
        "from_id": "RG-F-4e37a3628b4770e851f8",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "is_valid_string: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-548dbddabf2cb58f43e3",
        "from_id": "RG-F-548dbddabf2cb58f43e3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "has_pending_print: deleted at e1ee7de6 (fix: PendingBrace per-install identity ends the prettyprint.rs:3); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-59bb7728de73efb30458",
        "from_id": "RG-F-59bb7728de73efb30458",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "has_pending_print: deleted at e1ee7de6 (fix: PendingBrace per-install identity ends the prettyprint.rs:3); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-5b1e839e8d308d43aaf3",
        "from_id": "RG-F-5b1e839e8d308d43aaf3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "reason": "get_output_token: deleted at a2d81171 (core: typeop facing consumers go fd-aware, COPY token arm wired ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-5cf088ee67b09c27078b",
        "from_id": "RG-F-5cf088ee67b09c27078b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "reason": "propagate_cover_through_cfg: deleted at cfd819be (fix: compute_varnode_covers materializes the oracle lazy cover p); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-5d999c09619be29bf43c",
        "from_id": "RG-F-5d999c09619be29bf43c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "has_pending_print: deleted at e1ee7de6 (fix: PendingBrace per-install identity ends the prettyprint.rs:3); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-5dad7059d66628fd9da9",
        "from_id": "RG-F-5dad7059d66628fd9da9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "apply: deleted at 09bc75fb (varmap: NameRecommend store + recover chain wired into the namin); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-616567dbc34f5558543c",
        "from_id": "RG-F-616567dbc34f5558543c",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "transform: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-620248dd286ea7551a37",
        "from_id": "RG-F-620248dd286ea7551a37",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "seed_output_trials: deleted at c1e67b23 (fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-629cf67761b687a8c26d",
        "from_id": "RG-F-629cf67761b687a8c26d",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "test_transform_copy_emits_callother: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-67dc7962c61bc5688142",
        "from_id": "RG-F-67dc7962c61bc5688142",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "reason": "is_textual_self_xor: deleted at 439111cb (printc: signature tokenbreaks restored, print-time RAX return re); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-8761367cefe917fac99f",
        "from_id": "RG-F-8761367cefe917fac99f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after: deleted at cb912769 (blockaction: switch default joins the fall-thru chain graph and ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-89654e80cbde5e7d3ea3",
        "from_id": "RG-F-89654e80cbde5e7d3ea3",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "reason": "test_and_commute_right_shift: deleted at 99886d14 (fix: RuleAndCommute enforces cc:1582-1603 OR/PIECE benefit gate); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-90968956e438c405eacd",
        "from_id": "RG-F-90968956e438c405eacd",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "known_param_types: deleted at 430ddb3c (core: expel corpus name tables from coreaction (EXPEL-CORPUS-TAB); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-90e506c7ea693e6b9770",
        "from_id": "RG-F-90e506c7ea693e6b9770",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "iterate: deleted at d626a117 (core: value-set solver constraint generation family (RANGEUTIL-C); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-927b775bff6275603c45",
        "from_id": "RG-F-927b775bff6275603c45",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "535c9607bdda93264fb878060fca5ef55c85fb35",
        "child_blob": "98a933ea48edc9eb2f61519c574b1ab76c8dd31c",
        "reason": "parameterized_dwarf_prototype_keeps_resolved_model: deleted at ec5e3167 (align: port ELF PLT thunk + default FUN_ symbol import for httpd); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-9a28c4e392ee5121fb7f",
        "from_id": "RG-F-9a28c4e392ee5121fb7f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "4c05a312650b21e66cfd38a21e213b372cf87583",
        "child_blob": "f64668d365901dce30492c8bb69e5ea67af9b363",
        "reason": "sanitize_c_ident: deleted at 9381a879 (printc: emit symbol/function names verbatim; retire postfix char); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-a339a27f5ce4ccf3f7a8",
        "from_id": "RG-F-a339a27f5ce4ccf3f7a8",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "is_exit: deleted at 37895575 (fix: block switch dead is_exit re-derivation removed); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-a5a4a606dbe7165a08de",
        "from_id": "RG-F-a5a4a606dbe7165a08de",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "test_array_sequence_byte_array: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-a92016e1f7d5546f5f4a",
        "from_id": "RG-F-a92016e1f7d5546f5f4a",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "reason": "get_input_cast: deleted at a2d81171 (core: typeop facing consumers go fd-aware, COPY token arm wired ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-ad6cc85c2c3eaa3a8cdf",
        "from_id": "RG-F-ad6cc85c2c3eaa3a8cdf",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "d5afb251a48977be64b3b2767a7048678a5db5f4",
        "child_blob": "d26e8f3c988ada9c8594cca8cb1e4543854768d6",
        "reason": "pull_back_op: deleted at 0d4e1602 (core: RuleRangeMeld markup/heritage gates + SubRight lump addr s); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-b17f9f9f43aed18da23f",
        "from_id": "RG-F-b17f9f9f43aed18da23f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "pretty_print_while_break_fold_compact_prefix: deleted at 8b4f2c66 (chore(retire): remove P-wbfold while-break fold pass (POSTFIX-RE); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-b40b937681743f6e2665",
        "from_id": "RG-F-b40b937681743f6e2665",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "pending_brace_fired: deleted at e1ee7de6 (fix: PendingBrace per-install identity ends the prettyprint.rs:3); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-ba26cfc768c51f9d5d5e",
        "from_id": "RG-F-ba26cfc768c51f9d5d5e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "ff038b3fec58e95f44fe7d2b5d5cfbe117099264",
        "child_blob": "800a8163ad7c89fe31fc5d074fec693407601468",
        "reason": "test_rule_subfloat_convert_nonconst_narrowing_tags_input: deleted at 5317299b (align: port SubfloatFlow (subflow.cc:3070-3481) and replace SUBF); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-bb8e1fa85a210f58bc8f",
        "from_id": "RG-F-bb8e1fa85a210f58bc8f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "412a0ffbf16ae9dfeeb6607c6fcf89d7773eb148",
        "child_blob": "64f6c355b1425aa46a9265d1ca601ef554eb116d",
        "reason": "find_resolve: deleted at e94c3640 (core: intern ResolvedUnion::with_field pointer arm via TypeFacto); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-bc8a763172eb63d51968",
        "from_id": "RG-F-bc8a763172eb63d51968",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after: deleted at cb912769 (blockaction: switch default joins the fall-thru chain graph and ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-bd7035998b3fcfcf09fd",
        "from_id": "RG-F-bd7035998b3fcfcf09fd",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "newparam_push_unique: deleted at c1e67b23 (fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-bf779565541f339a5b98",
        "from_id": "RG-F-bf779565541f339a5b98",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "ptr_shares_base: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-c38867803d56c02e64a5",
        "from_id": "RG-F-c38867803d56c02e64a5",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "derive_func_output_map: deleted at c1e67b23 (fix: returnrecovery ordinal-19 quadruple + RDX trim alignment (R); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-c469c5afb8c5eaa6944e",
        "from_id": "RG-F-c469c5afb8c5eaa6944e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "remove_duplicate_labels: deleted at dc086b58 (chore(retire): remove Pdl duplicate-LAB_ dedup pass (POSTFIX-RET); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-c856c136a6c476dafc73",
        "from_id": "RG-F-c856c136a6c476dafc73",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after: deleted at cb912769 (blockaction: switch default joins the fall-thru chain graph and ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-ca1da07e9a917ec01ce4",
        "from_id": "RG-F-ca1da07e9a917ec01ce4",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "apply: deleted at 09bc75fb (varmap: NameRecommend store + recover chain wired into the namin); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-cac945ca8266a08b1dfa",
        "from_id": "RG-F-cac945ca8266a08b1dfa",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "pending_brace_fired: deleted at e1ee7de6 (fix: PendingBrace per-install identity ends the prettyprint.rs:3); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-cd3e481e567525eef117",
        "from_id": "RG-F-cd3e481e567525eef117",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after: deleted at cb912769 (blockaction: switch default joins the fall-thru chain graph and ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-d7fe24b5271831c9c4e1",
        "from_id": "RG-F-d7fe24b5271831c9c4e1",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "c7b546390d0d0659418aa1ecd17d1eebf0479840",
        "child_blob": "bdc05fc65294fccbe2ed3669ac9f0f847d6d28fd",
        "reason": "pull_back_through_op: deleted at a62435d4 (core: jumptable guard pullback rewires to canonical CircleRange:); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-dc6c8c08206a5ce51b17",
        "from_id": "RG-F-dc6c8c08206a5ce51b17",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "iterate_with: deleted at dbd5d89b (core: rangeutil value-set fill/iterate live path + RuleRangeMeld); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-df518a6031bf229b56b9",
        "from_id": "RG-F-df518a6031bf229b56b9",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "new: deleted at 0106750e (fix: ActionDoNothing self-loop warning lands at the block cover ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-dfecd395bd04ac2f614e",
        "from_id": "RG-F-dfecd395bd04ac2f614e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "14b3650eee3f6c0d9cb78c70cbde8ec80e9a276a",
        "child_blob": "5197b42576b8ac4e2bef309b92c9d6574f892aa2",
        "reason": "type_pointer_strip_array: deleted at 18b020b9 (unionres: deref drill-down and canonical-type corrections in sco); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-e1f620e7a5aeaa73902b",
        "from_id": "RG-F-e1f620e7a5aeaa73902b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "78deb1997fa7a88739948a8f9535971ccab9cad2",
        "child_blob": "87bda740fb72f42c070fdef4fb32d34a8bd55ada",
        "reason": "op_block_order: deleted at cfd819be (fix: compute_varnode_covers materializes the oracle lazy cover p); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-e39dc55a8fc070a1517f",
        "from_id": "RG-F-e39dc55a8fc070a1517f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "35c6df95301df5da63b9c0491e11e18237675675",
        "child_blob": "87b8856dc48ba3b54dacca255ae22ff22565d2e4",
        "reason": "set_iterate_inputs: deleted at dbd5d89b (core: rangeutil value-set fill/iterate live path + RuleRangeMeld); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-ebef02582ed9f5c4ff7f",
        "from_id": "RG-F-ebef02582ed9f5c4ff7f",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "test_transform_store_emits_callother_memcpy: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-f1ff5fa89d5ad21d7426",
        "from_id": "RG-F-f1ff5fa89d5ad21d7426",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "acfa5ecb727af6482c2e0fe6381dde8ad0ceb81e",
        "child_blob": "3bc1025ad89497b4bdc6a898b8dd8b31fdcd2c3c",
        "reason": "get_output_token: deleted at a2d81171 (core: typeop facing consumers go fd-aware, COPY token arm wired ); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-f24c99cca197427aca2e",
        "from_id": "RG-F-f24c99cca197427aca2e",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2aa46f0be3873e4a175af6c88fff9a42f59957f3",
        "child_blob": "ecf1fcd3897c538413e0ed9469b23ee8caceff92",
        "reason": "test_select_string_copy_function: deleted at 01879607 (core: RuleStringStore full HeapSequence chain fires for the strn); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-f38dac80fb60e63f7d37",
        "from_id": "RG-F-f38dac80fb60e63f7d37",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "a92f1d2a8ece4bcdf1625871df84ce7b0ed3bb05",
        "child_blob": "081fe3ed044f92bd1fc004db3f3fe2c6704862cd",
        "reason": "next_flow_after_index: deleted at 5e71c678 (wip: promote nextFlowAfter dispatch to block.rs single source (c); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-f563848b18adbc2e5c71",
        "from_id": "RG-F-f563848b18adbc2e5c71",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "fb460e50fb9e964cf233f8f3baecdff8491da3d5",
        "child_blob": "317c6e33b40fb47ec4c313043eaf9cee7270d7ab",
        "reason": "get_name: deleted at 430ddb3c (core: expel corpus name tables from coreaction (EXPEL-CORPUS-TAB); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-f9bbf97d97898f798acb",
        "from_id": "RG-F-f9bbf97d97898f798acb",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "has_enclosing_loop_ctx: deleted at f8cae893 (chore(retire): remove P1b exit-goto rewrite with pre-scan and he); folded-master-window removal with no same-4-key successor",
    },
    {
        "base_id": "RG-F-fdd3859cc4666533f82b",
        "from_id": "RG-F-fdd3859cc4666533f82b",
        "commit": "80ffb7d138dd6825990a4986ed77f0ae7d2355ee",
        "parent_blob": "2f0eea44cde0fa6d0cdb67170c93f5b250a4da62",
        "child_blob": "a3685f58c6bddc5a404996ec4ac86cf4242c0bf0",
        "reason": "negate_simple_condition: deleted at 2173be28 (chore(retire): remove P16 forward goto-to-if fold pass (POSTFIX-); folded-master-window removal with no same-4-key successor",
    },
)
CONTINUITY_REVIEWED_EPHEMERAL: tuple[dict[str, str], ...] = (
    {
        "base_id": "RG-F-763fefee4ab8d71f0289",
        "from_id": "RG-F-763fefee4ab8d71f0289",
        "commit": "23ef9c90a66be480f91ded91fa7e1e180faa57ce",
        "parent_blob": "f2e73aa6795f35c93f8bceb6e2290a43c427b357",
        "child_blob": "78d21a337d0ea2de3852bf6edb948d2334225573",
    },

    {
        "base_id": "RG-F-1bb5904495b9e4cb393e",
        "from_id": "RG-F-1bb5904495b9e4cb393e",
        "commit": "b15bd104b26bf4977a5d8e06307de44596073fdc",
        "parent_blob": "cae7b73c4da887e634cd5fde6dff16b0343d1933",
        "child_blob": "73226c089b941c9025aedf39b4d65e6af170403f",
    },
    # --- extension window 1f3aea4a..3fb97c11 (ORACLE-REGISTRY-IMPACT-CONTINUITY-0001) ---
    {
        "base_id": "RG-F-170873abbea5dabfb13a",
        "from_id": "RG-F-170873abbea5dabfb13a",
        "commit": "4d1bcf29bf527f542141adef5774980d4831b0ce",
        "parent_blob": "1323dc37c5e45e5990dbf612f11784fb41b42edf",
        "child_blob": "5a6dd28914b4a7251fb9db562b17674e2084e02b",
    },
)


def _reviewed_transition(
    legacy: str,
    source: str,
    target: str,
    commit: str,
    kind: str,
    label: str,
    parent_blob_prefix: str,
    child_blob_prefix: str,
) -> dict[str, str]:
    return {
        "legacy_id": legacy,
        "from_id": source,
        "to_id": target,
        "commit": commit,
        "kind": kind,
        "label": label,
        "parent_blob_prefix": parent_blob_prefix,
        "child_blob_prefix": child_blob_prefix,
    }


# These are evidence-bearing exceptions, not name-based heuristics.  Every
# token, commit, record shape and full blob resolved from the named commit is
# checked before a row is accepted.
REKEY_REVIEWED_TRANSITIONS = (
    _reviewed_transition(
        "RG-F-a1792e61b73118f8c5eb", "RG-F-a0b9aaf1d4e29189ddf4",
        "RG-F-afd2f193d11f7fded2d4", "eb8ad57b5f472c182f25dd245460abdc3c9f33e6",
        "same_name", "ActionDatabase::get_action_mut", "e3032afa", "e6aa9b91",
    ),
    _reviewed_transition(
        "RG-F-c642b079af3e97d8a10d", "RG-F-4a5cecef4b93ac919596",
        "RG-F-360279f7e03f1c7fe438", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::characterize_as_output", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-2efd70f01473014375c2", "RG-F-7a2548c2349bb5f75bc3",
        "RG-F-3e61b4c85c446db8dc90", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::characterize_as_input_param", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-52518230ca5f60ac71e5", "RG-F-da09d8757211d48d7bf6",
        "RG-F-6fb4acf7c117efe31588", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "FuncCallSpecs::has_effect", "bd37797c", "6a4f2a05",
    ),
    _reviewed_transition(
        "RG-F-e4c1a4d9c31459eadc79", "RG-F-ea38acbd08840b54a14b",
        "RG-F-7a1cd2752ad576a23195", "126b56fdefde1e0820ef4126968473d679e1ddd8",
        "same_name", "Heritage::guard_calls", "9e3afa32", "f49d3f8f",
    ),
    _reviewed_transition(
        "RG-F-0695ea49a55e99ff2807", "RG-F-6e4fe065a522eb9bbc94",
        "RG-F-f23c84cf58035a9ebe14", "704699811626f01fc029f284e04e09815b06a39f",
        "same_name", "Merge::merge_speculative_by_vn", "9729b200", "53f856f1",
    ),
    _reviewed_transition(
        "RG-F-24df7359099d9878a582", "RG-F-9b8bb1a4809cd7ca6b16",
        "RG-F-ff1783edd76bcabdc140", "032419b344e973682076bf5c21109b7f05fee192",
        "successor", "Cover::order_of_op -> CoverEndpoint::from_op", "7b8a196e", "d6a5931f",
    ),
    _reviewed_transition(
        "RG-F-700e12a6872c24d82498", "RG-F-0d974b12c723b8e02471",
        "RG-F-2b387a75cbdd7e41a31c", "253707fadb0735ec211289132792934d9ae48e05",
        "successor", "default_alignment_map -> set_default_alignment_map", "c373c0e5", "00d4ac38",
    ),
    _reviewed_transition(
        "RG-F-439b1c3cd8210321d15e", "RG-F-73adae5df6d49b818459",
        "RG-F-d5be9719af51f5bf1fdc", "34940227825405eabd5358c108fbbead2ddb8581",
        "successor", "c_binary_op_str -> optoken::binary_token", "058e2633", "342d87e7",
    ),
    _reviewed_transition(
        "RG-F-a7a04409bf4b8d92ce15", "RG-F-19126ae1c4f800e1531b",
        "RG-F-39a5f83df9995b8bf34b", "38af1fd81973e29fb27071b18144f7b4db4ad428",
        "successor", "unknown_datatype -> default_unknown_type", "a5e0bf66", "9c3db2d2",
    ),
    _reviewed_transition(
        "RG-F-473f9d99b18f17fd9922", "RG-F-9c1b0bf6f51e30a77096",
        "RG-F-c2a760d91fd95478a016", "eb8ad57b5f472c182f25dd245460abdc3c9f33e6",
        "successor", "build_simplify_pool -> build_oppool1", "e3032afa", "e6aa9b91",
    ),
    _reviewed_transition(
        "RG-F-bf22c6ec4313930a2bb3", "RG-F-36cb30229138ce0e46f0",
        "RG-F-7f7a36379bbf2cb1f39f", "ee29a32487702a8044d910202903e83a23996c9e",
        "successor", "update_cover -> update_cover_locked", "54ff245d", "5b4a422d",
    ),
    _reviewed_transition(
        "RG-F-61dfe59ce876d87bb8ad", "RG-F-3c8e1df9334b3c78363a",
        "RG-F-2b52235062c1427143fa", "8ec6bee8fce58231b4ff093290457497206aeab5",
        "successor", "RangeRecord::first successor", "abb9260b", "73cacc26",
    ),
    _reviewed_transition(
        "RG-F-ef3f516520136385508d", "RG-F-32ca3afaf5f64455aa9e",
        "RG-F-9a07be81379bfc511a61", "8ec6bee8fce58231b4ff093290457497206aeab5",
        "successor", "RangeRecord::last successor", "abb9260b", "73cacc26",
    ),
)


def _tombstone(legacy: str, base: str, commit: str, name: str) -> dict[str, str]:
    return {
        "legacy_id": f"RG-F-{legacy}",
        "base_id": f"RG-F-{base}",
        "commit": commit,
        "name": name,
    }


REKEY_REVIEWED_TOMBSTONES = (
    _tombstone("6fccfccb5487c98f7997", "545a2fa83e26f9e8716d", "9825db126fb72f6d7652536f4516a6ea38c77da1", "intersect"),
    _tombstone("0f1afd435338b39ae1c4", "01c37763d9a53ef73ace", "9825db126fb72f6d7652536f4516a6ea38c77da1", "dfs_visit"),
    _tombstone("d051f78879b4ecfbdffb", "df80e19385aea19c30b5", "69ea4e048cb2185f0686b136b044217fc44fc88b", "find_spanning_tree"),
    _tombstone("a515040ca21e3a40b3bd", "965ea4deca6789b2653a", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "setup_block_list"),
    _tombstone("e2e407c3cfa4cb808159", "63f228446a519e0c8d80", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "setup_op_list"),
    _tombstone("c594237c5aae750c1651", "a679e28185a5cd97f9db", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "has_header_comments"),
    _tombstone("e56c7a580c5fbf1735b5", "07a5cf7058ae8cf06026", "c5e685c55e775192dae7b26f0631f6ac8ff85df6", "header_comments"),
    _tombstone("b56384676d5805afa616", "c1c6b7597b9723bcd50a", "bed6ef5605767811fe641201d86da80fe9f96b9e", "is_true_out_to"),
    _tombstone("0144832f561c7cd8e30f", "78de6b876155d5b7f967", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "flip_comparison"),
    _tombstone("44f5ea5f0b19361842c0", "ab960b0c66138f0a51af", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "test_prefercomplement_flips_boolean_flip"),
    _tombstone("07f6d8c1c408863b8543", "e1027492465f482180db", "a9d68f779e7d6d47e4dd0b3da1569f9ce6c5fdc0", "test_prefercomplement_flip_comparison"),
    _tombstone("f5f60231b4dcbaf7a838", "7bba63e94d32b61c1eec", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "build_full_pipeline_actions"),
    _tombstone("c6ceca66030b18e666d1", "afd0a253ec7939ceb0d7", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_nonempty"),
    _tombstone("2772e14a50d16aa73c41", "b89ca9c78de4d43b0641", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_unique_names"),
    _tombstone("1291ed91ecdc95aa474f", "8a03aee5400b8f1aec82", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_has_new_actions"),
    _tombstone("0036b1e6159131b90d5e", "828769ed1d87903b2f49", "dd76d37866dcd2e4dc0a354323e0f016bb62fb35", "test_build_full_pipeline_actions_excludes_block_mutators_and_stubs"),
    _tombstone("f89ffb08d7df8a69b93f", "3f721750f2a9d6acb761", "e034f80ba06d9acff0952ee50be4be39c3f8580a", "target_op_for_branch"),
    _tombstone("3724985bbd4374850d46", "60ba7907d4b5be14485c", "e034f80ba06d9acff0952ee50be4be39c3f8580a", "target_op_by_addr"),
    _tombstone("3864f2c13cdb9e6fdb97", "232322f83bab558eabb2", "3ee30ba0de3e55eb8b8e2cdbe52153df136d8bf9", "address_space_as_u32"),
    _tombstone("82eb3b5be5e838caa58e", "811518e6a28c130e573b", "3ee30ba0de3e55eb8b8e2cdbe52153df136d8bf9", "resolve_callother_payload_name"),
    _tombstone("be571c7397c18d59d8e4", "62677ad8d8248a7ab7c3", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_returns"),
    _tombstone("110e7cb3a979adc595e0", "00414dcba113eb1cf787", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_calls_range"),
    _tombstone("5b9bee2c44266559a724", "535aac7994cb2a0df898", "126b56fdefde1e0820ef4126968473d679e1ddd8", "guard_calls_range_with_space"),
    _tombstone("f2c70dc54daf5faaccad", "58223aa5b23fb6ffa6b1", "c30913076c0bc0033c0a688462030444c95fc264", "insert_multiequal"),
    _tombstone("e8440bf2ca995df09185", "0bb352245a43b1009d50", "0e4c6f45f32cf8ddd48849d1895fb29f68db620b", "assign_names"),
    _tombstone("b864c8440d57e0be0aed", "e0b261758e01fee35673", "0e4c6f45f32cf8ddd48849d1895fb29f68db620b", "register_name"),
    _tombstone("9b3ba477324abf563e92", "df77030350cd56f16c06", "7721b0d722cc8b507696f62922e978c0314fae3f", "register_payload"),
    _tombstone("fb4e57eb1fc08da9b754", "79cd9be355b367b91bea", "7721b0d722cc8b507696f62922e978c0314fae3f", "get_id"),
    _tombstone("ea847040afb0a57a335f", "72bab767946d70c663c6", "7721b0d722cc8b507696f62922e978c0314fae3f", "num_payloads"),
    _tombstone("66eeea2a761b604a28ba", "52ccd48128e40d6f37b0", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_pcode_inject_library"),
    _tombstone("a22612c4dceb25126c6b", "5d67242db4fbc2603002", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_fixup"),
    _tombstone("cb791532f7bd0a7f57c0", "7edaa9a420184bde51c6", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_other_fixup"),
    _tombstone("3cca09c07784d1994f78", "d9e5720a4033361bb683", "7721b0d722cc8b507696f62922e978c0314fae3f", "test_register_call_mechanism"),
    _tombstone("ecc37431989bf168a937", "291fd9ff2aeafadcec76", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "compact_name_for"),
    _tombstone("3d3c79e1fd7d70a102d4", "981f70767c5c8c5729cb", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "preallocate_register_compact_names"),
    _tombstone("dcb5c56857185e0ff75c", "afc5544707c4f91fee45", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "doc_variable_decls_from_funcdata"),
    _tombstone("0b63894a79fa2310c9ce", "98cadcff50035dc0db81", "df0da852bba0fe3f857199fbc5b416e004df8f1c", "test_compact_name_for"),
    _tombstone("9457bf91be8c7fd0b8c4", "27f74050a459dcc39ae2", "192e89407f5af7a419d1fe7bb30d119af8a231e0", "rename_scope_symbol"),
    _tombstone("ab891945fe45a58b7be9", "1aeb4fa12758eb2b41f6", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "new"),
    _tombstone("fae83367c2e7db8035b6", "4b1c37948f6503fb22e4", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "apply_op"),
    _tombstone("1e978e7c99761b05d41c", "2d887962c3671a23a057", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "get_name"),
    _tombstone("79f85567e39a8f3da854", "396b06cb2c37b5ef8bc0", "79a8faa198a23bc0a7c19e11dc360c66a63f1fd4", "get_opcodes"),
    _tombstone("b83de19c3204b2d095f3", "64f3fe19484db472dc7e", "a770ed10df7806bf03e34d798b3f3712a08ec2bd", "test_shift_by_nonzero_unchanged"),
    _tombstone("a72bb5e89b3cb6c78685", "295a58b7a7a62200fc52", "34fd254755441def6e17197cf2431f7fcf920c24", "next_document"),
    _tombstone("b0e2c5a6cf989f5042de", "5fab4d997916a47717d6", "5fb36f0225c6efe606b5e8b5213163d956e9f2f1", "comparable_flags"),
    _tombstone("c2362bc96e45d55b5ca3", "a73a582f615d89a9c4f3", "83a900efd41c9222c74b5e3be9d790fcbe86c645", "query_by_addr"),
    _tombstone("f83ff911cc781b9fd152", "ffc8a907ea67daf0c0c5", "e87ebfc54444d5f043a321ea1a46e3c8004eff23", "collect_copy_sources"),
)


def old_rust_records_at_tree(root: Path, commit: str) -> list[dict[str, object]]:
    """Recompute legacy-scheme Rust IDs (path + name + ordinal) at a commit."""

    listing = command_output(
        ["git", "ls-tree", "-r", "--name-only", commit, "src/"], root
    ).splitlines()
    records: list[dict[str, object]] = []
    for relative in sorted(line for line in listing if line.endswith(".rs")):
        text = command_output(["git", "show", f"{commit}:{relative}"], root)
        ordinals: Counter[str] = Counter()
        for record in scan_rust_functions(text):
            ordinals[record.name] += 1
            records.append(
                {
                    "id": stable_id(
                        OLD_RUST_ID_PREFIX, (relative, record.name, ordinals[record.name])
                    ),
                    "path": relative,
                    "name": record.name,
                    "line": record.start_line + 1,
                    "name_ordinal": ordinals[record.name],
                }
            )
    return records


def old_rust_projection(entries: list[dict[str, object]]) -> list[tuple[object, ...]]:
    return [
        (
            entry["path"],
            entry["name"],
            int(entry["line"]),
            int(entry["name_ordinal"]),
            str(entry["id"]),
        )
        for entry in entries
    ]


def detect_old_ledger_tree(
    root: Path, ledger_path: Path, old_rust: list[dict[str, object]], override: str | None
) -> str:
    """Find the commit whose tree reproduces the existing ledger's Rust scan."""

    target = old_rust_projection(old_rust)
    candidates: list[str] = []
    if override:
        candidates.append(override)
    relative_ledger = ledger_path.relative_to(root).as_posix()
    last_touch = command_output(
        ["git", "log", "-1", "--format=%H", "--", relative_ledger], root
    ).strip()
    if last_touch:
        candidates.append(last_touch)
    candidates.append(command_output(["git", "rev-parse", "HEAD"], root).strip())
    candidates.extend(
        line for line in command_output(["git", "log", "--format=%H", "-n", "30"], root).splitlines()
    )
    seen: set[str] = set()
    for commit in candidates:
        if not commit or commit in seen:
            continue
        seen.add(commit)
        try:
            records = old_rust_records_at_tree(root, commit)
        except RuntimeError:
            continue
        if old_rust_projection(records) == target:
            return commit
    raise RuntimeError(
        "cannot reproduce the existing ledger's Rust records from --migrate-base, the "
        "ledger's last-touching commit, HEAD, or the 30 most recent commits; refusing "
        "to migrate against an unknown source tree"
    )


def migration_rows(
    old_ghidra: list[dict[str, object]],
    new_ghidra: list[dict[str, object]],
    old_rust: list[dict[str, object]],
    new_rust: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Correlate old ledger entries with new-scheme IDs, fail-closed.

    Returns (rows, disambiguators).  Every old entry must correlate with
    exactly one new entry and vice versa; any ambiguity raises instead of
    being guessed.
    """

    ghidra_index: dict[tuple[object, ...], dict[str, object]] = {}
    for entry in new_ghidra:
        key = (entry["path"], int(entry["line"]), entry["entry_kind"], entry["name"])
        if key in ghidra_index:
            raise RuntimeError(f"fresh Ghidra scan is self-ambiguous at {key}")
        ghidra_index[key] = entry
    rust_index: dict[tuple[object, ...], dict[str, object]] = {}
    for record in new_rust:
        key = (record["path"], int(record["line"]), record["name"])
        if key in rust_index:
            raise RuntimeError(f"new Rust scan is self-ambiguous at {key}")
        rust_index[key] = record

    rows: list[dict[str, object]] = []
    disambiguators: list[dict[str, object]] = []
    if len(old_ghidra) != len(ghidra_index):
        raise RuntimeError(
            f"Ghidra record count changed against the locked oracle: old={len(old_ghidra)} new={len(ghidra_index)}"
        )
    for entry in old_ghidra:
        key = (entry["path"], int(entry["line"]), entry["entry_kind"], entry["name"])
        fresh = ghidra_index.get(key)
        if fresh is None:
            raise RuntimeError(f"old Ghidra entry has no locked-oracle counterpart: {key}")
        new_id = str(fresh["id"])
        old_id = str(entry["id"])
        reason = "ghidra_signature_rekey"
        if ORDINAL_SUFFIX_RE.search(old_id):
            reason = "ghidra_ordinal_replaced_by_guard_disambiguator"
        rows.append(
            {
                "old_id": old_id,
                "new_id": new_id,
                "language": "ghidra",
                "reason": reason if old_id != new_id else "unchanged",
            }
        )
        if fresh.get("id_disambiguator"):
            disambiguators.append(
                {
                    "old_id": old_id,
                    "new_id": new_id,
                    "language": "ghidra",
                    "path": fresh["path"],
                    "entry_kind": fresh["entry_kind"],
                    "signature": fresh["signature"],
                    "disambiguator_kind": "preprocessor_guard",
                    "disambiguator": fresh["id_disambiguator"]["value"],
                }
            )
    if len(old_rust) != len(rust_index):
        raise RuntimeError(
            f"Rust record count differs between the old ledger tree and recomputation: "
            f"old={len(old_rust)} new={len(rust_index)}"
        )
    for entry in old_rust:
        key = (entry["path"], int(entry["line"]), entry["name"])
        fresh = rust_index.get(key)
        if fresh is None:
            raise RuntimeError(f"old Rust entry has no counterpart on the ledger tree: {key}")
        old_id = str(entry["id"])
        new_id = str(fresh["id"])
        rows.append(
            {
                "old_id": old_id,
                "new_id": new_id,
                "language": "rust",
                "reason": "rust_identity_rekey" if old_id != new_id else "unchanged",
            }
        )
    return rows, disambiguators


def check_migration_rows(rows: list[dict[str, object]]) -> dict[str, object]:
    """Fail closed on any old-ID ambiguity or new-ID collision."""

    by_old: dict[str, set[str]] = defaultdict(set)
    by_new: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        by_old[str(row["old_id"])].add(str(row["new_id"]))
        by_new[str(row["new_id"])].add(str(row["old_id"]))
    ambiguous_old = sorted(
        {old: sorted(news) for old, news in by_old.items() if len(news) > 1}.items()
    )
    colliding_new = sorted(
        {new: sorted(olds) for new, olds in by_new.items() if len(olds) > 1}.items()
    )
    if ambiguous_old or colliding_new:
        details = []
        for old_id, news in ambiguous_old:
            details.append(f"old id {old_id} maps to multiple new ids: {news}")
        for new_id, olds in colliding_new:
            details.append(f"new id {new_id} would absorb multiple old ids: {olds}")
        raise RuntimeError("migration ambiguity (fail-closed, refusing to guess):\n" + "\n".join(details))
    stable = sum(1 for row in rows if row["old_id"] == row["new_id"])
    return {
        "total": len(rows),
        "stable_unchanged": stable,
        "changed": len(rows) - stable,
        "ambiguous_old_ids": len(ambiguous_old),
        "colliding_new_ids": len(colliding_new),
    }


def migration_document(
    root: Path,
    old_ledger_path: Path,
    output_dir: Path,
    migrate_base: str | None,
) -> dict[str, object]:
    old_ledger = json.loads(old_ledger_path.read_text(encoding="utf-8"))
    old_ghidra = list(old_ledger["ghidra_functions"])
    old_rust = list(old_ledger["rugra_functions"])

    cpp = verify_oracle(root)
    fresh_ghidra, _ = ctags_entries(root, cpp)
    validate_ctags_counts(fresh_ghidra)

    tree = detect_old_ledger_tree(root, old_ledger_path, old_rust, migrate_base)
    tree_rust: list[dict[str, object]] = []
    listing = command_output(["git", "ls-tree", "-r", "--name-only", tree, "src/"], root).splitlines()
    for relative in sorted(line for line in listing if line.endswith(".rs")):
        text = command_output(["git", "show", f"{tree}:{relative}"], root)
        tree_rust.extend(
            collect_rust_identities(relative, text, module_from_relative(relative))
        )
    assign_rust_locked_ids(tree_rust)

    rows, disambiguators = migration_rows(old_ghidra, fresh_ghidra, old_rust, tree_rust)
    stats = check_migration_rows(rows)
    reasons: Counter[str] = Counter(str(row["reason"]) for row in rows)
    per_language: dict[str, dict[str, object]] = {}
    for language in ("ghidra", "rust"):
        language_rows = [row for row in rows if row["language"] == language]
        language_reasons = Counter(str(row["reason"]) for row in language_rows)
        per_language[language] = {
            "total": len(language_rows),
            "stable_unchanged": sum(row["old_id"] == row["new_id"] for row in language_rows),
            **{f"changed_{reason}": count for reason, count in sorted(language_reasons.items()) if reason != "unchanged"},
        }
    subject = command_output(["git", "show", "-s", "--format=%s", tree], root).strip()
    return {
        "schema": 1,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": ID_SCHEME,
        "old_ledger": {
            "path": old_ledger_path.relative_to(root).as_posix(),
            "tree_commit": tree,
            "tree_subject": subject,
        },
        "semantics": (
            "Rust new IDs are computed on the verified old-ledger tree so old-to-new "
            "correlation is positional and exact; Ghidra new IDs recompute from the "
            "locked oracle. Every collision disambiguator is listed explicitly; "
            "ordinal- or line-derived tokens never participate."
        ),
        "stats": {
            **stats,
            "reasons": dict(sorted(reasons.items())),
            "per_language": per_language,
        },
        "disambiguators": disambiguators,
        "entries": rows,
    }


# --- Migration reconciliation: pinned scheme-2 history replay --------------


REKEY_HUNK_RE = re.compile(
    r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@"
)


def _migration_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment.update(
        {"LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    )
    return environment


def _migration_git(root: Path, command: list[str]) -> str:
    result = subprocess.run(
        ["git", *command],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_migration_git_environment(),
    )
    if result.returncode != 0:
        raise MigrationHarnessError(
            f"command failed ({result.returncode}): git {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def _migration_json_from_git(root: Path, revision: str, relative: str) -> dict[str, object]:
    try:
        document = json.loads(_migration_git(root, ["show", f"{revision}:{relative}"]))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(
            f"pinned JSON is malformed at {revision}:{relative}: {error}"
        ) from error
    if not isinstance(document, dict):
        raise MigrationHarnessError(f"pinned JSON root is not an object: {revision}:{relative}")
    return document


def _expect_git_object(root: Path, revision: str, expected: str, label: str) -> str:
    actual = _migration_git(root, ["rev-parse", revision]).strip()
    if actual != expected:
        raise MigrationHarnessError(f"{label} mismatch: expected {expected}, got {actual}")
    return actual


def verify_rekey_boundary(root: Path, *, verify_locked_oracle: bool = True) -> list[str]:
    """Validate every immutable input before replaying or writing output."""

    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}^{{commit}}", REKEY_SOURCE_COMMIT, "source commit"
    )
    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}^{{tree}}", REKEY_SOURCE_COMMIT_TREE,
        "source commit tree",
    )
    _expect_git_object(
        root, f"{REKEY_SOURCE_COMMIT}:src", REKEY_SOURCE_SRC_TREE, "source src tree"
    )
    _expect_git_object(
        root,
        f"{REKEY_SOURCE_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
        REKEY_SOURCE_LEDGER_BLOB,
        "source ledger blob",
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}^{{commit}}", REKEY_TARGET_COMMIT, "target commit"
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}^{{tree}}", REKEY_TARGET_COMMIT_TREE,
        "target commit tree",
    )
    _expect_git_object(
        root, f"{REKEY_TARGET_COMMIT}:src", REKEY_TARGET_SRC_TREE, "target src tree"
    )
    _expect_git_object(
        root,
        f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
        REKEY_TARGET_LEDGER_BLOB,
        "target ledger blob",
    )
    _expect_git_object(
        root,
        f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
        REKEY_SOURCE_MIGRATION_BLOB,
        "source migration blob",
    )

    for ancestor, descendant, label in (
        (REKEY_SOURCE_COMMIT, REKEY_TARGET_COMMIT, "source is not an ancestor of target"),
        (REKEY_TARGET_COMMIT, "HEAD", "target is not an ancestor of HEAD"),
    ):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_migration_git_environment(),
        )
        if result.returncode != 0:
            raise MigrationHarnessError(label)

    commits = _migration_git(
        root,
        ["rev-list", "--first-parent", "--reverse", f"{REKEY_SOURCE_COMMIT}..{REKEY_TARGET_COMMIT}"],
    ).splitlines()
    if len(commits) != REKEY_FIRST_PARENT_COMMIT_COUNT:
        raise MigrationHarnessError(
            "first-parent history length mismatch: "
            f"expected {REKEY_FIRST_PARENT_COMMIT_COUNT}, got {len(commits)}"
        )
    previous = REKEY_SOURCE_COMMIT
    for commit in commits:
        first_parent = _migration_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if first_parent != previous:
            raise MigrationHarnessError(
                f"first-parent discontinuity at {commit}: expected {previous}, got {first_parent}"
            )
        previous = commit
    if previous != REKEY_TARGET_COMMIT:
        raise MigrationHarnessError(
            f"first-parent replay ended at {previous}, not {REKEY_TARGET_COMMIT}"
        )

    head_src = _migration_git(root, ["rev-parse", "HEAD:src"]).strip()
    if head_src != REKEY_TARGET_SRC_TREE:
        raise MigrationHarnessError(
            f"HEAD src tree mismatch: expected {REKEY_TARGET_SRC_TREE}, got {head_src}"
        )
    dirty_src = _migration_git(
        root, ["status", "--porcelain=v1", "--untracked-files=all", "--", "src"]
    ).strip()
    if dirty_src:
        raise MigrationHarnessError(f"target src worktree is dirty:\n{dirty_src}")
    ledger_path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
    if not ledger_path.is_file():
        raise MigrationHarnessError("target ledger is missing from the worktree")
    ledger_blob = _migration_git(root, ["hash-object", str(ledger_path)]).strip()
    if ledger_blob != REKEY_TARGET_LEDGER_BLOB:
        raise MigrationHarnessError(
            f"worktree ledger blob mismatch: expected {REKEY_TARGET_LEDGER_BLOB}, got {ledger_blob}"
        )
    if verify_locked_oracle:
        oracle_root = root / "ghidra"
        oracle_head = _migration_git(oracle_root, ["rev-parse", "HEAD"]).strip()
        if oracle_head != ORACLE_COMMIT:
            raise MigrationHarnessError(
                f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {oracle_head}"
            )
        oracle_dirty = _migration_git(
            oracle_root, ["status", "--porcelain", "--untracked-files=no"]
        ).strip()
        if oracle_dirty:
            raise MigrationHarnessError(
                f"locked Ghidra worktree has tracked changes:\n{oracle_dirty}"
            )
        cpp = oracle_root / "Ghidra/Features/Decompiler/src/decompile/cpp"
        cc_count = len(list(cpp.glob("*.cc")))
        if cc_count != 114:
            raise MigrationHarnessError(
                f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}"
            )
    return commits


def _validate_rekey_source_tables(
    source_ledger: dict[str, object],
    target_ledger: dict[str, object],
    source_migration: dict[str, object],
) -> tuple[list[dict[str, object]], set[str], dict[str, dict[str, object]]]:
    for label, ledger in (("source", source_ledger), ("target", target_ledger)):
        # The pinned source is the pre-scheme-2 ledger by construction and
        # therefore has no id_scheme block.  The target must carry scheme 2.
        if ledger.get("schema") != 1:
            raise MigrationHarnessError(f"{label} ledger schema mismatch")
        if label == "target" and not isinstance(ledger.get("id_scheme"), dict):
            raise MigrationHarnessError("target ledger id_scheme is missing")
        for field in ("ghidra_functions", "rugra_functions"):
            if not isinstance(ledger.get(field), list):
                raise MigrationHarnessError(f"{label} ledger {field} is not an array")
    if source_migration.get("schema") != 1:
        raise MigrationHarnessError("source migration must be immutable schema 1")
    for field in ("entries", "disambiguators"):
        if not isinstance(source_migration.get(field), list):
            raise MigrationHarnessError(f"source migration {field} is not an array")
    entries = list(source_migration["entries"])
    if len(entries) != REKEY_ORIGIN_COUNT:
        raise MigrationHarnessError(
            f"source migration origin count mismatch: expected {REKEY_ORIGIN_COUNT}, got {len(entries)}"
        )
    try:
        source_stats = check_migration_rows(entries)
    except RuntimeError as error:
        raise MigrationHarnessError(str(error)) from error
    if source_stats["total"] != REKEY_ORIGIN_COUNT:
        raise MigrationHarnessError("source migration collision audit did not cover every origin")
    old_ledger = source_migration.get("old_ledger")
    if not isinstance(old_ledger, dict) or old_ledger.get("tree_commit") != REKEY_SOURCE_COMMIT:
        raise MigrationHarnessError("source migration old-ledger commit pin mismatch")
    if source_migration.get("oracle_commit") != ORACLE_COMMIT:
        raise MigrationHarnessError("source migration oracle commit mismatch")
    target_oracle = target_ledger.get("oracle")
    if not isinstance(target_oracle, dict) or target_oracle.get("commit") != ORACLE_COMMIT:
        raise MigrationHarnessError("target ledger oracle commit mismatch")

    target_ids: set[str] = set()
    for field in ("ghidra_functions", "rugra_functions"):
        for record in target_ledger[field]:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise MigrationHarnessError(f"target ledger contains a malformed {field} record")
            fid = str(record["id"])
            if fid in target_ids:
                raise MigrationHarnessError(f"target ledger contains duplicate function id {fid}")
            target_ids.add(fid)

    source_rust_by_legacy: dict[str, dict[str, object]] = {}
    for record in source_ledger["rugra_functions"]:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            raise MigrationHarnessError("source ledger contains a malformed Rust record")
        source_rust_by_legacy[str(record["id"])] = record
    return entries, target_ids, source_rust_by_legacy


def _identity_projection(record: dict[str, object]) -> tuple[object, ...]:
    return tuple(
        record.get(field)
        for field in (
            "id", "path", "name", "line", "end_line", "module", "owner", "signature",
            "is_test", "is_declaration",
        )
    )


def _fresh_target_rust(root: Path, target_ledger: dict[str, object]) -> list[dict[str, object]]:
    fresh: list[dict[str, object]] = []
    for path in sorted((root / "src").rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        text_value = path.read_text(encoding="utf-8")
        fresh.extend(
            collect_rust_identities(relative, text_value, module_from_relative(relative))
        )
    try:
        assign_rust_locked_ids(fresh)
    except RuntimeError as error:
        raise MigrationHarnessError(str(error)) from error
    pinned = list(target_ledger["rugra_functions"])
    fresh_projection = sorted(_identity_projection(record) for record in fresh)
    pinned_projection = sorted(_identity_projection(record) for record in pinned)
    if fresh_projection != pinned_projection:
        missing = sorted(set(pinned_projection) - set(fresh_projection))[:3]
        extra = sorted(set(fresh_projection) - set(pinned_projection))[:3]
        raise MigrationHarnessError(
            "fresh Rust scan does not reproduce the pinned target ledger: "
            f"pinned={len(pinned_projection)} fresh={len(fresh_projection)} "
            f"missing={missing} extra={extra}"
        )
    return fresh


def _blob_text(root: Path, blob: str, cache: dict[str, str]) -> str:
    if blob == "0" * 40:
        return ""
    if blob not in cache:
        cache[blob] = _migration_git(root, ["cat-file", "blob", blob])
    return cache[blob]


def _scan_rekey_blob(
    root: Path,
    relative: str,
    blob: str,
    text_cache: dict[str, str],
    scan_cache: dict[tuple[str, str], list[dict[str, object]]],
) -> list[dict[str, object]]:
    if blob == "0" * 40 or not relative.endswith(".rs"):
        return []
    cache_key = (relative, blob)
    if cache_key in scan_cache:
        return scan_cache[cache_key]
    source = _blob_text(root, blob, text_cache)
    records = collect_rust_identities(relative, source, module_from_relative(relative))
    try:
        assign_rust_locked_ids(records)
    except RuntimeError as error:
        raise MigrationHarnessError(f"{relative}@{blob}: {error}") from error
    code = mask_non_code(source)
    pairs = rust_brace_pairs(code)
    lines = source.splitlines()
    for record in records:
        annotation_kind, annotation = marker_above(lines, int(record["line"]) - 1)
        record["_annotation"] = (
            (annotation_kind, json.dumps(annotation, sort_keys=True, separators=(",", ":")))
            if annotation
            else None
        )
        signature_end = rust_signature_end(code, pairs, int(record["start"]))
        body = " ".join(code[signature_end:int(record["end"])].split())
        record["_masked_body"] = body if body and body != ";" else None
        record["_annotation_kind"] = annotation_kind
        record["_annotation_value"] = annotation
    scan_cache[cache_key] = records
    return records


def _rust_changes(root: Path, parent: str, commit: str) -> list[dict[str, str]]:
    raw = _migration_git(
        root,
        ["diff-tree", "--no-commit-id", "--raw", "-r", "--no-abbrev", "--no-renames",
         parent, commit, "--", "src"],
    )
    changes: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.split("\t")
        header = parts[0].split()
        if len(header) != 5 or not header[0].startswith(":"):
            raise MigrationHarnessError(f"cannot parse raw diff row at {commit}: {line}")
        old_blob, new_blob, status = header[2], header[3], header[4]
        if status.startswith(("R", "C")):
            if len(parts) != 3:
                raise MigrationHarnessError(f"cannot parse rename/copy row at {commit}: {line}")
            old_path, new_path = parts[1], parts[2]
        else:
            if len(parts) != 2:
                raise MigrationHarnessError(f"cannot parse diff path at {commit}: {line}")
            old_path = new_path = parts[1]
        if not old_path.endswith(".rs") and not new_path.endswith(".rs"):
            continue
        changes.append(
            {
                "old_path": old_path,
                "new_path": new_path,
                "old_blob": old_blob,
                "new_blob": new_blob,
                "status": status,
            }
        )
    changes.sort(key=lambda item: (item["old_path"], item["new_path"], item["status"]))
    return changes


def _record_intersects_hunk(record: dict[str, object], start: int, count: int) -> bool:
    if count == 0:
        return int(record["line"]) <= start <= int(record["end_line"]) + 1
    end = start + count - 1
    return int(record["line"]) <= end and start <= int(record["end_line"])


def _diff_hunks(
    root: Path,
    parent: str,
    commit: str,
    path: str,
    cache: dict[tuple[str, str], list[tuple[int, int, int, int]]],
) -> list[tuple[int, int, int, int]]:
    key = (commit, path)
    if key in cache:
        return cache[key]
    diff = _migration_git(
        root, ["diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0",
               parent, commit, "--", path]
    )
    hunks: list[tuple[int, int, int, int]] = []
    for line in diff.splitlines():
        match = REKEY_HUNK_RE.match(line)
        if match:
            hunks.append(
                (
                    int(match.group("old")),
                    int(match.group("old_count") or 1),
                    int(match.group("new")),
                    int(match.group("new_count") or 1),
                )
            )
    cache[key] = hunks
    return hunks


def strict_transition_evidence(
    old: dict[str, object],
    new: dict[str, object],
    hunks: list[tuple[int, int, int, int]],
) -> list[str]:
    evidence: list[str] = []
    if any(
        _record_intersects_hunk(old, old_start, old_count)
        and _record_intersects_hunk(new, new_start, new_count)
        for old_start, old_count, new_start, new_count in hunks
    ):
        evidence.append("same_patch_hunk")
    if old.get("_annotation") and old.get("_annotation") == new.get("_annotation"):
        evidence.append("identical_nonempty_annotation")
    if old.get("_masked_body") and old.get("_masked_body") == new.get("_masked_body"):
        evidence.append("identical_masked_body")
    return evidence


def select_unique_strict_transition(
    commit: str,
    key: tuple[object, ...],
    old_tokens: list[str],
    new_tokens: list[str],
    before: dict[str, tuple[dict[str, object], str]],
    after: dict[str, tuple[dict[str, object], str]],
    hunks: list[tuple[int, int, int, int]],
) -> tuple[str, str, list[str]] | None:
    """Select one evidence-bearing 1->1 transition, or fail on ambiguity."""

    if not new_tokens:
        return None
    if len(old_tokens) != 1 or len(new_tokens) != 1:
        raise MigrationHarnessError(
            f"ambiguous automatic transition at {commit} for {key}: "
            f"removed={old_tokens} added={new_tokens}"
        )
    source_token, target_token = old_tokens[0], new_tokens[0]
    evidence = strict_transition_evidence(
        before[source_token][0], after[target_token][0], hunks
    )
    return (source_token, target_token, evidence) if evidence else None


def _lineage_event(
    old: dict[str, object],
    new: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
    evidence: list[str],
) -> dict[str, object]:
    return {
        "from_id": old["id"],
        "to_id": new["id"],
        "commit": commit,
        "from_path": old["path"],
        "to_path": new["path"],
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "evidence": evidence,
    }


# --- Post-baseline function-ID continuity ---------------------------------


def rust_parameter_binding_mut_normalized_signature(signature: str) -> str:
    """Remove only a leading, top-level Rust parameter binding ``mut``.

    This canonical form is evidence for a continuity event; it is never fed
    to :func:`stable_id`.  In particular, ``&mut T`` and ``*mut T`` stay byte
    significant because their ``mut`` token is not the leading binding token.
    """

    match = re.search(r"\bfn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*", signature)
    if match is None:
        return " ".join(signature.split())
    angle_depth = 0
    open_paren = None
    for index in range(match.end(), len(signature)):
        ch = signature[index]
        if ch == "<":
            angle_depth += 1
        elif ch == ">" and angle_depth:
            angle_depth -= 1
        elif ch == "(" and angle_depth == 0:
            open_paren = index
            break
    if open_paren is None:
        return " ".join(signature.split())

    depth = 0
    close_paren = None
    for index in range(open_paren, len(signature)):
        ch = signature[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    if close_paren is None:
        return " ".join(signature.split())

    inner = signature[open_paren + 1:close_paren]
    parameters: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    closer = {")": "(", "]": "[", "}": "{", ">": "<"}
    for index, ch in enumerate(inner):
        if ch in depths:
            depths[ch] += 1
        elif ch in closer and depths[closer[ch]]:
            depths[closer[ch]] -= 1
        elif ch == "," and not any(depths.values()):
            parameters.append(inner[start:index])
            start = index + 1
    parameters.append(inner[start:])

    normalized: list[str] = []
    for parameter in parameters:
        value = parameter.strip()
        attribute_prefix = ""
        # Parameter outer attributes precede the binding pattern.  Preserve
        # them and only inspect the first token after every complete #[...].
        while value.startswith("#["):
            attr_depth = 0
            attr_end = None
            for index, ch in enumerate(value):
                if ch == "[":
                    attr_depth += 1
                elif ch == "]":
                    attr_depth -= 1
                    if attr_depth == 0:
                        attr_end = index + 1
                        break
            if attr_end is None:
                break
            attribute_prefix += value[:attr_end].strip() + " "
            value = value[attr_end:].lstrip()
        value = re.sub(r"^mut\b\s*", "", value, count=1)
        normalized.append((attribute_prefix + value).strip())
    rebuilt = (
        signature[:open_paren]
        + "("
        + ", ".join(normalized)
        + ")"
        + signature[close_paren + 1:]
    )
    return " ".join(rebuilt.split())


def rust_trailing_comma_normalized_signature(signature: str) -> str:
    """Drop only the trailing parameter separator of the top-level parameter list.

    This canonical form is evidence for a continuity event; it is never fed to
    :func:`stable_id`.  Only the comma immediately before the *top-level*
    parameter-list closing paren is dropped, and whitespace is collapsed, so a
    semantically significant separator inside a nested type (for example the
    1-tuple ``(u8,)``) stays byte significant and mixed changes keep requiring
    a reviewed rule.
    """

    match = re.search(r"\bfn\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*", signature)
    if match is None:
        return " ".join(signature.split())
    angle_depth = 0
    open_paren = None
    for index in range(match.end(), len(signature)):
        ch = signature[index]
        if ch == "<":
            angle_depth += 1
        elif ch == ">" and angle_depth:
            angle_depth -= 1
        elif ch == "(" and angle_depth == 0:
            open_paren = index
            break
    if open_paren is None:
        return " ".join(signature.split())
    depth = 0
    close_paren = None
    for index in range(open_paren, len(signature)):
        if signature[index] == "(":
            depth += 1
        elif signature[index] == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    if close_paren is None:
        return " ".join(signature.split())
    inner = " ".join(signature[open_paren + 1:close_paren].split())
    if inner.endswith(","):
        inner = inner[:-1].rstrip()
    return " ".join(
        (signature[:open_paren + 1] + inner + signature[close_paren:]).split()
    )


RUST_PROJECTION_FIELDS = (
    "id", "path", "name", "line", "end_line", "module", "owner", "signature",
    "is_test", "is_declaration",
)


def rust_identity_projection(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    projection = [
        {field: record.get(field) for field in RUST_PROJECTION_FIELDS}
        for record in records
    ]
    projection.sort(
        key=lambda record: (
            str(record.get("id")), str(record.get("path")),
            int(record.get("line") or 0), str(record.get("signature")),
        )
    )
    return projection


def rust_identity_projection_sha256(records: Iterable[dict[str, object]]) -> str:
    encoded = json.dumps(
        rust_identity_projection(records),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scan_rust_revision(root: Path, revision: str) -> list[dict[str, object]]:
    listing = _migration_git(
        root, ["ls-tree", "-r", "--name-only", revision, "--", "src"]
    ).splitlines()
    records: list[dict[str, object]] = []
    for relative in sorted(path for path in listing if path.endswith(".rs")):
        source = _migration_git(root, ["show", f"{revision}:{relative}"])
        records.extend(
            collect_rust_identities(relative, source, module_from_relative(relative))
        )
    try:
        assign_rust_locked_ids(records)
    except RuntimeError as error:
        raise MigrationHarnessError(f"{revision} Rust scan: {error}") from error
    return records


def _load_worktree_ledger(root: Path) -> dict[str, object]:
    path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
    if not path.is_file():
        raise MigrationHarnessError("current ledger is missing from the worktree")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(f"current ledger JSON is malformed: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("rugra_functions"), list):
        raise MigrationHarnessError("current ledger rudra_functions must be an array")
    return document


def _verify_locked_oracle_for_continuity(root: Path) -> None:
    oracle_root = root / "ghidra"
    oracle_head = _migration_git(oracle_root, ["rev-parse", "HEAD"]).strip()
    if oracle_head != ORACLE_COMMIT:
        raise MigrationHarnessError(
            f"wrong Ghidra oracle: expected {ORACLE_COMMIT}, got {oracle_head}"
        )
    oracle_dirty = _migration_git(
        oracle_root, ["status", "--porcelain", "--untracked-files=no"]
    ).strip()
    if oracle_dirty:
        raise MigrationHarnessError(
            f"locked Ghidra worktree has tracked changes:\n{oracle_dirty}"
        )
    cpp = oracle_root / "Ghidra/Features/Decompiler/src/decompile/cpp"
    cc_count = len(list(cpp.glob("*.cc")))
    if cc_count != 114:
        raise MigrationHarnessError(
            f"wrong Ghidra source closure: expected 114 .cc, got {cc_count}"
        )


def verify_continuity_boundary(
    root: Path, *, verify_locked_oracle: bool = True
) -> tuple[list[str], dict[str, object], dict[str, object], list[dict[str, object]]]:
    """Verify the baseline, checkpoint, worktree ledger, and source projection."""

    for revision, expected, label in (
        (f"{REKEY_TARGET_COMMIT}^{{commit}}", REKEY_TARGET_COMMIT, "baseline commit"),
        (f"{REKEY_TARGET_COMMIT}^{{tree}}", REKEY_TARGET_COMMIT_TREE, "baseline commit tree"),
        (f"{REKEY_TARGET_COMMIT}:src", REKEY_TARGET_SRC_TREE, "baseline src tree"),
        (
            f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json",
            REKEY_TARGET_LEDGER_BLOB,
            "baseline ledger blob",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}^{{commit}}",
            CONTINUITY_CHECKPOINT_COMMIT,
            "checkpoint commit",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}^{{tree}}",
            CONTINUITY_CHECKPOINT_COMMIT_TREE,
            "checkpoint commit tree",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}:src",
            CONTINUITY_CHECKPOINT_SRC_TREE,
            "checkpoint src tree",
        ),
        (
            f"{CONTINUITY_CHECKPOINT_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
            CONTINUITY_BASELINE_MIGRATION_BLOB,
            "baseline migration blob at checkpoint",
        ),
    ):
        _expect_git_object(root, revision, expected, label)
    _expect_git_object(
        root, f"{CONTINUITY_CHECKPOINT_COMMIT}^1",
        CONTINUITY_CHECKPOINT_PARENT, "checkpoint first parent",
    )

    for ancestor, descendant, label in (
        (REKEY_TARGET_COMMIT, CONTINUITY_CHECKPOINT_COMMIT,
         "baseline is not an ancestor of checkpoint"),
        (CONTINUITY_CHECKPOINT_COMMIT, "HEAD",
         "continuity checkpoint is not an ancestor of HEAD"),
    ):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_migration_git_environment(),
        )
        if result.returncode != 0:
            raise MigrationHarnessError(label)

    commits = _migration_git(
        root,
        ["rev-list", "--first-parent", "--reverse",
         f"{REKEY_TARGET_COMMIT}..{CONTINUITY_CHECKPOINT_COMMIT}"],
    ).splitlines()
    if len(commits) != CONTINUITY_FIRST_PARENT_COMMIT_COUNT:
        raise MigrationHarnessError(
            "continuity first-parent history length mismatch: "
            f"expected {CONTINUITY_FIRST_PARENT_COMMIT_COUNT}, got {len(commits)}"
        )
    if not commits or commits[0] != CONTINUITY_FIRST_COMMIT:
        raise MigrationHarnessError(
            f"continuity first commit mismatch: {commits[0] if commits else None}"
        )
    previous = REKEY_TARGET_COMMIT
    for commit in commits:
        first_parent = _migration_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if first_parent != previous:
            raise MigrationHarnessError(
                f"continuity first-parent discontinuity at {commit}: "
                f"expected {previous}, got {first_parent}"
            )
        previous = commit
    if previous != CONTINUITY_CHECKPOINT_COMMIT:
        raise MigrationHarnessError(
            f"continuity replay ended at {previous}, not {CONTINUITY_CHECKPOINT_COMMIT}"
        )

    head_src = _migration_git(root, ["rev-parse", "HEAD:src"]).strip()
    if head_src != CONTINUITY_CHECKPOINT_SRC_TREE:
        raise MigrationHarnessError(
            f"HEAD src tree mismatch: expected {CONTINUITY_CHECKPOINT_SRC_TREE}, got {head_src}"
        )
    dirty_src = _migration_git(
        root, ["status", "--porcelain=v1", "--untracked-files=all", "--", "src"]
    ).strip()
    if dirty_src:
        raise MigrationHarnessError(f"checkpoint src worktree is dirty:\n{dirty_src}")

    migration_path = root / "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
    if not migration_path.is_file():
        raise MigrationHarnessError("baseline migration is missing from the worktree")
    migration_blob = _migration_git(root, ["hash-object", str(migration_path)]).strip()
    migration_sha = sha256_file(migration_path)
    if migration_blob != CONTINUITY_BASELINE_MIGRATION_BLOB:
        raise MigrationHarnessError(
            "worktree baseline migration blob mismatch: expected "
            f"{CONTINUITY_BASELINE_MIGRATION_BLOB}, got {migration_blob}"
        )
    if migration_sha != CONTINUITY_BASELINE_MIGRATION_SHA256:
        raise MigrationHarnessError(
            "worktree baseline migration sha256 mismatch: expected "
            f"{CONTINUITY_BASELINE_MIGRATION_SHA256}, got {migration_sha}"
        )
    try:
        baseline_migration = json.loads(migration_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MigrationHarnessError(f"baseline migration JSON is malformed: {error}") from error
    if not isinstance(baseline_migration, dict) or baseline_migration.get("schema") != 2:
        raise MigrationHarnessError("baseline migration must remain reconciled schema 2")
    target = baseline_migration.get("target")
    expected_target = {
        "commit": REKEY_TARGET_COMMIT,
        "commit_tree": REKEY_TARGET_COMMIT_TREE,
        "src_tree": REKEY_TARGET_SRC_TREE,
        "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
    }
    if not isinstance(target, dict) or any(target.get(k) != v for k, v in expected_target.items()):
        raise MigrationHarnessError("baseline migration target pins drifted")

    baseline_ledger = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    current_ledger = _load_worktree_ledger(root)
    baseline_rust = _scan_rust_revision(root, REKEY_TARGET_COMMIT)
    pinned_baseline = list(baseline_ledger.get("rugra_functions", []))
    if sorted(_identity_projection(row) for row in baseline_rust) != sorted(
        _identity_projection(row) for row in pinned_baseline
    ):
        raise MigrationHarnessError("fresh baseline Rust scan does not reproduce pinned ledger")
    if len(baseline_rust) != CONTINUITY_BASELINE_RUST_RECORDS:
        raise MigrationHarnessError(
            f"baseline Rust record count mismatch: {len(baseline_rust)}"
        )
    fresh_current = _fresh_target_rust(root, current_ledger)
    if len(fresh_current) != CONTINUITY_CHECKPOINT_RUST_RECORDS:
        raise MigrationHarnessError(
            f"checkpoint Rust record count mismatch: {len(fresh_current)}"
        )
    if verify_locked_oracle:
        _verify_locked_oracle_for_continuity(root)
    return commits, baseline_ledger, current_ledger, fresh_current


def continuity_transition_evidence(
    old: dict[str, object],
    new: dict[str, object],
    hunks: list[tuple[int, int, int, int]],
) -> list[str]:
    old_signature = str(old.get("signature") or "")
    new_signature = str(new.get("signature") or "")
    if old_signature == new_signature:
        return []
    if (rust_parameter_binding_mut_normalized_signature(old_signature)
            == rust_parameter_binding_mut_normalized_signature(new_signature)):
        kind = "parameter_binding_mut_only"
    elif (rust_trailing_comma_normalized_signature(old_signature)
            == rust_trailing_comma_normalized_signature(new_signature)):
        # A formatting-only separator change re-keys the raw ID because the
        # scheme-2 signature keeps the separator; the function itself did not
        # change, so the alias is proven without a reviewed rule.
        kind = "signature_trailing_comma_only"
    else:
        return []
    strict = strict_transition_evidence(old, new, hunks)
    # A post-baseline automatic transition is deliberately narrower than the
    # original historical reconciler: both structural pins are mandatory.
    if "same_patch_hunk" not in strict or "identical_nonempty_annotation" not in strict:
        return []
    return ["same_patch_hunk", "identical_nonempty_annotation", kind]


def _continuity_event(
    old: dict[str, object],
    new: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
    evidence: list[str],
) -> dict[str, object]:
    return {
        "from_id": old["id"],
        "to_id": new["id"],
        "commit": commit,
        "from_path": old["path"],
        "to_path": new["path"],
        "from_module": old["module"],
        "to_module": new["module"],
        "from_owner": old["owner"],
        "to_owner": new["owner"],
        "from_name": old["name"],
        "to_name": new["name"],
        "from_signature": old["signature"],
        "to_signature": new["signature"],
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "evidence": evidence,
    }


def _continuity_record_index(
    rows: Iterable[tuple[dict[str, object], str]], label: str
) -> dict[str, tuple[dict[str, object], str]]:
    result: dict[str, tuple[dict[str, object], str]] = {}
    for record, blob in rows:
        token = str(record["id"])
        if token in result:
            raise MigrationHarnessError(f"{label} contains colliding raw ID {token}")
        result[token] = (record, blob)
    return result


def function_id_continuity_document(
    root: Path, *, verify_locked_oracle: bool = True
) -> dict[str, object]:  # noqa: C901
    """Reconcile raw scheme-2 IDs from the immutable baseline to checkpoint."""

    commits, baseline_ledger, current_ledger, fresh_current = verify_continuity_boundary(
        root, verify_locked_oracle=verify_locked_oracle
    )
    baseline_records = list(baseline_ledger["rugra_functions"])
    current_ids = {str(record["id"]) for record in fresh_current}
    baseline_ids = {str(record["id"]) for record in baseline_records}
    if len(baseline_ids) != len(baseline_records):
        raise MigrationHarnessError("baseline ledger contains duplicate Rust IDs")

    states: dict[str, dict[str, object]] = {
        token: {
            "base_id": token,
            "current_id": token,
            "origin_kind": "baseline",
            "events": [],
            "status": "live",
        }
        for token in sorted(baseline_ids)
    }
    tracked = {token: token for token in sorted(baseline_ids)}
    introduced: dict[str, dict[str, object]] = {}
    tombstones: list[dict[str, object]] = []
    text_cache: dict[str, str] = {}
    scan_cache: dict[tuple[str, str], list[dict[str, object]]] = {}
    hunk_cache: dict[tuple[str, str], list[tuple[int, int, int, int]]] = {}
    reviewed_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for rule in CONTINUITY_REVIEWED_TRANSITIONS:
        reviewed_by_commit[rule["commit"]].append(rule)
    reviewed_keys = [
        (rule.get("base_id"), rule.get("from_id"), rule.get("commit"))
        for rule in CONTINUITY_REVIEWED_TRANSITIONS
    ]
    if len(reviewed_keys) != len(set(reviewed_keys)):
        raise MigrationHarnessError("reviewed continuity transition allowlist has duplicates")
    tombstone_rows = [
        ((rule.get("base_id"), rule.get("from_id"), rule.get("commit")), rule)
        for rule in CONTINUITY_REVIEWED_TOMBSTONES
    ]
    if len(tombstone_rows) != len({key for key, _ in tombstone_rows}):
        raise MigrationHarnessError("reviewed continuity tombstone allowlist has duplicates")
    tombstone_by_key = dict(tombstone_rows)
    ephemeral_rows = [
        ((rule.get("base_id"), rule.get("from_id"), rule.get("commit")), rule)
        for rule in CONTINUITY_REVIEWED_EPHEMERAL
    ]
    if len(ephemeral_rows) != len({key for key, _ in ephemeral_rows}):
        raise MigrationHarnessError("reviewed continuity ephemeral allowlist has duplicates")
    ephemeral_by_key = dict(ephemeral_rows)
    used_reviewed: set[tuple[str, str, str]] = set()
    used_tombstones: set[tuple[str, str, str]] = set()
    used_ephemeral: set[tuple[str, str, str]] = set()
    historical_owner_by_token = {token: token for token in baseline_ids}

    def claim_historical_token(token: str, base_id: str, role: str) -> None:
        previous_owner = historical_owner_by_token.get(token)
        if previous_owner is not None and previous_owner != base_id:
            raise MigrationHarnessError(
                f"continuity historical token collision for {token} ({role}): "
                f"{previous_owner}, {base_id}"
            )
        historical_owner_by_token[token] = base_id

    previous = REKEY_TARGET_COMMIT
    for commit in commits:
        changes = _rust_changes(root, previous, commit)
        before_rows: list[tuple[dict[str, object], str]] = []
        after_rows: list[tuple[dict[str, object], str]] = []
        parent_blob_by_path: dict[str, str] = {}
        child_blob_by_path: dict[str, str] = {}
        for change in changes:
            old_path, new_path = change["old_path"], change["new_path"]
            old_blob, new_blob = change["old_blob"], change["new_blob"]
            if old_path.endswith(".rs"):
                parent_blob_by_path[old_path] = old_blob
                before_rows.extend(
                    (record, old_blob) for record in _scan_rekey_blob(
                        root, old_path, old_blob, text_cache, scan_cache
                    )
                )
            if new_path.endswith(".rs"):
                child_blob_by_path[new_path] = new_blob
                after_rows.extend(
                    (record, new_blob) for record in _scan_rekey_blob(
                        root, new_path, new_blob, text_cache, scan_cache
                    )
                )
        before = _continuity_record_index(before_rows, f"{commit} parent")
        after = _continuity_record_index(after_rows, f"{commit} child")
        for token in sorted(set(before).intersection(after)):
            old_record, new_record = before[token][0], after[token][0]
            identity_fields = (
                "path", "module", "owner", "name", "signature", "is_test",
                "is_declaration",
            )
            if any(old_record.get(field) != new_record.get(field) for field in identity_fields):
                raise MigrationHarnessError(
                    f"same raw ID masks a changed identity at {commit}: {token}"
                )
        removed = {
            token: before[token]
            for token in sorted(set(tracked).intersection(before).difference(after))
        }
        newly_added = {
            token: after[token]
            for token in sorted(set(after).difference(before))
        }
        for token in newly_added:
            if token in tracked and token not in removed:
                raise MigrationHarnessError(
                    f"new raw ID collides with an unchanged live function at {commit}: {token}"
                )
        claimed_targets: set[str] = set()
        transitioned_sources: set[str] = set()

        for rule in reviewed_by_commit.get(commit, []):
            required = (
                "base_id", "from_id", "to_id", "commit", "from_path", "to_path",
                "parent_blob", "child_blob", "review",
            )
            if any(not rule.get(field) for field in required):
                raise MigrationHarnessError(f"malformed reviewed continuity rule at {commit}")
            source_token, target_token = rule["from_id"], rule["to_id"]
            base_id = tracked.get(source_token)
            if base_id != rule["base_id"] or source_token not in removed:
                raise MigrationHarnessError(
                    f"reviewed continuity source is not the unique live removal: {source_token}"
                )
            if target_token not in newly_added or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"reviewed continuity target is not a unique new function: {target_token}"
                )
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            pins = {
                "from_path": old_record["path"], "to_path": new_record["path"],
                "parent_blob": parent_blob, "child_blob": child_blob,
            }
            if any(str(rule[field]) != str(value) for field, value in pins.items()):
                raise MigrationHarnessError(
                    f"reviewed continuity path/blob pin mismatch for {source_token}"
                )
            event = _continuity_event(
                old_record, new_record, commit, parent_blob, child_blob,
                ["reviewed_successor_allowlist", str(rule["review"])],
            )
            states[base_id]["events"].append(event)
            states[base_id]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = base_id
            claim_historical_token(target_token, base_id, "reviewed target")
            transitioned_sources.add(source_token)
            claimed_targets.add(target_token)
            used_reviewed.add((base_id, source_token, commit))

        removed_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        added_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        for token, (record, _) in removed.items():
            if token not in transitioned_sources:
                removed_groups[(record["path"], record["module"], record["owner"], record["name"])].append(token)
        for token, (record, _) in newly_added.items():
            if token not in claimed_targets:
                added_groups[(record["path"], record["module"], record["owner"], record["name"])].append(token)

        for key in sorted(removed_groups, key=lambda value: tuple(str(part) for part in value)):
            old_tokens = sorted(removed_groups[key])
            new_tokens = sorted(added_groups.get(key, []))
            if not new_tokens:
                continue
            if len(old_tokens) != 1 or len(new_tokens) != 1:
                raise MigrationHarnessError(
                    f"ambiguous continuity transition at {commit} for {key}: "
                    f"removed={old_tokens} added={new_tokens}"
                )
            source_token, target_token = old_tokens[0], new_tokens[0]
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            hunks = _diff_hunks(root, previous, commit, str(old_record["path"]), hunk_cache)
            evidence = continuity_transition_evidence(old_record, new_record, hunks)
            if not evidence:
                continue
            if target_token in tracked or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"continuity transition target collision at {commit}: {target_token}"
                )
            base_id = tracked[source_token]
            states[base_id]["events"].append(
                _continuity_event(
                    old_record, new_record, commit, parent_blob, child_blob, evidence
                )
            )
            states[base_id]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = base_id
            claim_historical_token(target_token, base_id, "automatic target")
            transitioned_sources.add(source_token)
            claimed_targets.add(target_token)

        for source_token in sorted(set(removed).difference(transitioned_sources)):
            old_record, parent_blob = removed[source_token]
            base_id = tracked[source_token]
            rule_key = (base_id, source_token, commit)
            rule = tombstone_by_key.get(rule_key)
            ephemeral_rule = ephemeral_by_key.get(rule_key)
            if rule is None and ephemeral_rule is not None:
                # Schema 1 cannot encode a class introduced and deleted entirely
                # inside the window (its introduced_live terminal must be current
                # while its tombstone origin must predate the checkpoint).  Such a
                # class was never pinned in any ledger, so the exact reviewed
                # allowlist retires it from the replay instead of emitting a row.
                if states[base_id]["origin_kind"] != "introduced_live":
                    raise MigrationHarnessError(
                        "reviewed continuity ephemeral rule must target an "
                        f"introduced-live class: {base_id}"
                    )
                child_blob = child_blob_by_path.get(str(old_record["path"]))
                required = ("parent_blob", "child_blob")
                if (child_blob is None
                        or any(not ephemeral_rule.get(field) for field in required)
                        or ephemeral_rule["parent_blob"] != parent_blob
                        or ephemeral_rule["child_blob"] != child_blob):
                    raise MigrationHarnessError(
                        f"reviewed continuity ephemeral blob pins mismatch for {base_id}"
                    )
                del states[base_id]
                introduced.pop(base_id, None)
                del tracked[source_token]
                used_ephemeral.add(rule_key)
                continue
            if rule is None:
                raise MigrationHarnessError(
                    "unproved post-baseline removal requires an exact reviewed transition "
                    f"or tombstone: {base_id} {source_token} at {commit} "
                    f"({old_record['path']}::{old_record['name']})"
                )
            # Schema 2 extension: a post-baseline introduced lineage that was
            # pinned at earlier checkpoints may also die under an exact reviewed
            # tombstone rule.  Schema 1 could only encode baseline-origin
            # tombstones; the row now carries the class's introduction origin
            # (introduced_live provenance) so consumers can validate it without
            # the (now dead) introduced_live entry.
            if states[base_id]["origin_kind"] not in ("baseline", "introduced_live"):
                raise MigrationHarnessError(
                    "reviewed continuity tombstone rule targets an unsupported "
                    f"origin kind: {base_id} ({states[base_id]['origin_kind']})"
                )
            child_blob = child_blob_by_path.get(str(old_record["path"]))
            required = ("parent_blob", "child_blob", "reason")
            if (child_blob is None or any(not rule.get(field) for field in required)
                    or rule["parent_blob"] != parent_blob or rule["child_blob"] != child_blob):
                raise MigrationHarnessError(
                    f"reviewed continuity tombstone blob pins mismatch for {base_id}"
                )
            aliases = [str(event["from_id"]) for event in states[base_id]["events"]]
            if source_token not in aliases:
                aliases.append(source_token)
            tombstone_row = {
                "base_id": base_id,
                "aliases": aliases,
                "path": old_record["path"],
                "module": old_record["module"],
                "owner": old_record["owner"],
                "name": old_record["name"],
                "signature": old_record["signature"],
                "deleted_at_commit": commit,
                "parent_blob": parent_blob,
                "child_blob": child_blob,
                "reason": rule["reason"],
                "events": list(states[base_id]["events"]),
            }
            if states[base_id]["origin_kind"] == "introduced_live":
                origin_row = introduced[base_id]
                tombstone_row["origin"] = {
                    "kind": "introduced_live",
                    "introduced_at_commit": origin_row["introduced_at_commit"],
                    "path": origin_row["path"],
                    "module": origin_row["module"],
                    "owner": origin_row["owner"],
                    "name": origin_row["name"],
                    "signature": origin_row["signature"],
                    "parent_blob": origin_row["parent_blob"],
                    "child_blob": origin_row["child_blob"],
                }
            tombstones.append(tombstone_row)
            states[base_id]["status"] = "tombstone"
            states[base_id]["current_id"] = None
            del tracked[source_token]
            used_tombstones.add(rule_key)

        for token in sorted(set(newly_added).difference(claimed_targets)):
            if token in tracked or token in states:
                raise MigrationHarnessError(
                    f"introduced raw ID collides with an existing continuity class: {token}"
                )
            record, child_blob = newly_added[token]
            row = {
                "base_id": token,
                "new_id": token,
                "introduced_at_commit": commit,
                "path": record["path"],
                "module": record["module"],
                "owner": record["owner"],
                "name": record["name"],
                "signature": record["signature"],
                "parent_blob": parent_blob_by_path.get(str(record["path"]), "0" * 40),
                "child_blob": child_blob,
            }
            introduced[token] = row
            states[token] = {
                "base_id": token,
                "current_id": token,
                "origin_kind": "introduced_live",
                "events": [],
                "status": "live",
            }
            tracked[token] = token
            claim_historical_token(token, token, "introduced live")
        previous = commit

    expected_reviewed = {
        (rule["base_id"], rule["from_id"], rule["commit"])
        for rule in CONTINUITY_REVIEWED_TRANSITIONS
    }
    if used_reviewed != expected_reviewed:
        raise MigrationHarnessError("reviewed continuity transition coverage mismatch")
    if used_tombstones != set(tombstone_by_key):
        raise MigrationHarnessError("reviewed continuity tombstone coverage mismatch")
    if used_ephemeral != set(ephemeral_by_key):
        raise MigrationHarnessError(
            "reviewed continuity ephemeral coverage mismatch: "
            f"missing={sorted(set(ephemeral_by_key)-used_ephemeral)} "
            f"extra={sorted(used_ephemeral-set(ephemeral_by_key))}"
        )
    if set(tracked) != current_ids:
        raise MigrationHarnessError(
            "continuity replay does not equal current ledger IDs: "
            f"missing={sorted(current_ids-set(tracked))[:3]} "
            f"extra={sorted(set(tracked)-current_ids)[:3]}"
        )

    lineages = []
    for base_id in sorted(states):
        state = states[base_id]
        events = list(state["events"])
        if state["status"] != "live" or not events:
            continue
        aliases = [str(event["from_id"]) for event in events]
        lineages.append({
            "base_id": base_id,
            "new_id": state["current_id"],
            "origin_kind": state["origin_kind"],
            "aliases": aliases,
            "events": events,
        })
    transitions = {
        (str(row["base_id"]), str(row["new_id"])) for row in lineages
    }
    if transitions != CONTINUITY_EXPECTED_TRANSITIONS:
        raise MigrationHarnessError(
            f"unexpected checkpoint continuity transitions: {sorted(transitions)}"
        )
    live_introduced = {
        token: row for token, row in introduced.items()
        if states[token]["status"] == "live"
    }
    if set(live_introduced) != CONTINUITY_EXPECTED_INTRODUCED:
        raise MigrationHarnessError(
            f"unexpected introduced-live functions: {sorted(live_introduced)}"
        )
    tombstone_keys = {
        (str(row["base_id"]), str(row["aliases"][-1]), str(row["deleted_at_commit"]))
        for row in tombstones
    }
    if tombstone_keys != CONTINUITY_EXPECTED_TOMBSTONES:
        raise MigrationHarnessError(
            f"unexpected checkpoint continuity tombstones: {sorted(tombstone_keys)}"
        )
    for token, row in live_introduced.items():
        row["new_id"] = states[token]["current_id"]

    baseline_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    current_projection_sha = rust_identity_projection_sha256(fresh_current)
    baseline_projection_sha = rust_identity_projection_sha256(baseline_records)
    return {
        "schema": 2,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": ID_SCHEME,
        "baseline": {
            "commit": REKEY_TARGET_COMMIT,
            "commit_tree": REKEY_TARGET_COMMIT_TREE,
            "src_tree": REKEY_TARGET_SRC_TREE,
            "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
            "rust_projection_sha256": baseline_projection_sha,
            "rust_function_records": len(baseline_records),
            "migration_blob_at_checkpoint": CONTINUITY_BASELINE_MIGRATION_BLOB,
            "migration_sha256": CONTINUITY_BASELINE_MIGRATION_SHA256,
        },
        "checkpoint": {
            "commit": CONTINUITY_CHECKPOINT_COMMIT,
            "commit_tree": CONTINUITY_CHECKPOINT_COMMIT_TREE,
            "src_tree": CONTINUITY_CHECKPOINT_SRC_TREE,
            "rust_projection_sha256": current_projection_sha,
            "rust_function_records": len(fresh_current),
        },
        "history": {
            "mode": "first_parent",
            "commit_count": len(commits),
            "first_commit": commits[0],
            "last_commit": commits[-1],
        },
        "semantics": (
            "Raw scheme-2 IDs remain stable_id(module, owner, normalized_signature). "
            "This separate post-baseline layer composes historical aliases to the raw "
            "checkpoint IDs. Automatic transitions require a unique 1-to-1, same "
            "path/module/owner/name pair whose only signature difference is either a "
            "leading parameter binding mut or the trailing parameter separator, in the "
            "same patch hunk with the same non-empty annotation. Tombstones are "
            "diagnostic only; introduced_live rows are new checkpoint definitions, not "
            "fabricated historical origins. Schema 2 extends tombstones to die under "
            "review as classes introduced after the baseline (origin block carries the "
            "introduced_live provenance); schema 1 rows are unchanged."
        ),
        "stats": {
            "baseline_records": len(baseline_records),
            "current_records": len(fresh_current),
            "introduced_live": len(live_introduced),
            "lineages": len(lineages),
            "events": sum(len(row["events"]) for row in lineages),
            "tombstones": len(tombstones),
            "alias_tokens": sum(len(row["aliases"]) for row in lineages),
            "reviewed_transitions": len(used_reviewed),
            "ambiguous": 0,
            "collisions": 0,
        },
        "lineages": lineages,
        "introduced_live": [live_introduced[token] for token in sorted(live_introduced)],
        "tombstones": sorted(tombstones, key=lambda row: str(row["base_id"])),
    }


def validate_reviewed_transition(
    rule: dict[str, str],
    tracked: dict[str, str],
    removed: dict[str, tuple[dict[str, object], str]],
    newly_added: dict[str, tuple[dict[str, object], str]],
    claimed_targets: set[str],
) -> tuple[str, dict[str, object], str, dict[str, object], str]:
    """Validate an exact reviewed transition; name-only lookup is forbidden."""

    source_token, target_token = rule["from_id"], rule["to_id"]
    legacy = tracked.get(source_token)
    if legacy != rule["legacy_id"] or source_token not in removed:
        raise MigrationHarnessError(
            f"reviewed transition source is not the unique live removal at {rule['commit']}: "
            f"{rule['legacy_id']} {source_token}"
        )
    # Requiring membership in newly_added rejects wrapper/deletion rows that
    # attempt to point at a function which already existed before the commit.
    if target_token not in newly_added:
        raise MigrationHarnessError(
            f"reviewed transition target is not newly added at {rule['commit']}: {target_token}"
        )
    if target_token in tracked or target_token in claimed_targets:
        raise MigrationHarnessError(f"reviewed transition target collision: {target_token}")
    old_record, parent_blob = removed[source_token]
    new_record, child_blob = newly_added[target_token]
    if not parent_blob.startswith(rule["parent_blob_prefix"]):
        raise MigrationHarnessError(
            f"reviewed parent blob mismatch for {source_token}: {parent_blob}"
        )
    if not child_blob.startswith(rule["child_blob_prefix"]):
        raise MigrationHarnessError(
            f"reviewed child blob mismatch for {target_token}: {child_blob}"
        )
    if rule["kind"] == "same_name":
        old_key = (
            old_record["path"], old_record["module"], old_record["owner"], old_record["name"]
        )
        new_key = (
            new_record["path"], new_record["module"], new_record["owner"], new_record["name"]
        )
        if old_key != new_key:
            raise MigrationHarnessError(
                f"reviewed same-name record shape drift for {rule['label']}: {old_key} != {new_key}"
            )
    return legacy, old_record, parent_blob, new_record, child_blob


def _tombstone_record(
    state: dict[str, object],
    old: dict[str, object],
    commit: str,
    parent_blob: str,
    child_blob: str,
) -> dict[str, object]:
    aliases = [str(event["from_id"]) for event in state["lineage"]]
    aliases.append(str(old["id"]))
    aliases = list(dict.fromkeys(aliases))
    result: dict[str, object] = {
        "old_id": state["legacy_id"],
        "aliases": aliases,
        "deleted_id": old["id"],
        "path": old["path"],
        "module": old["module"],
        "owner": old["owner"],
        "name": old["name"],
        "signature": old["signature"],
        "line": old["line"],
        "end_line": old["end_line"],
        "is_test": old["is_test"],
        "is_declaration": old["is_declaration"],
        "annotation_kind": old["_annotation_kind"],
        "annotation": old["_annotation_value"],
        "deleted_at_commit": commit,
        "parent_blob": parent_blob,
        "child_blob": child_blob,
        "reason": "deleted_without_reviewed_successor",
    }
    if state["lineage"]:
        result["lineage"] = list(state["lineage"])
    return result


def _validate_reconciled_classes(
    entries: list[dict[str, object]],
    tombstones: list[dict[str, object]],
    target_ids: set[str],
    *,
    expected_origin_count: int = REKEY_ORIGIN_COUNT,
    expected_live_count: int = REKEY_LIVE_ORIGIN_COUNT,
    expected_tombstone_count: int = REKEY_TOMBSTONE_COUNT,
    expected_alias_count: int = REKEY_ALIAS_TOKEN_COUNT,
) -> dict[str, int]:
    if len(entries) != expected_live_count:
        raise MigrationHarnessError(
            f"live origin count mismatch: expected {expected_live_count}, got {len(entries)}"
        )
    if len(tombstones) != expected_tombstone_count:
        raise MigrationHarnessError(
            f"tombstone count mismatch: expected {expected_tombstone_count}, got {len(tombstones)}"
        )
    owner_by_token: dict[str, str] = {}
    final_by_origin: dict[str, str] = {}
    alias_count = 0

    def claim(token: object, origin: str, role: str) -> None:
        token_pattern = (
            r"(?:RG-F-[0-9a-f]{20}|GH12-F-[0-9a-f]{20}(?:-\d{2})?)"
            if "old_id" in role
            else r"(?:RG-F|GH12-F)-[0-9a-f]{20}"
        )
        if not isinstance(token, str) or not re.fullmatch(token_pattern, token):
            raise MigrationHarnessError(f"malformed {role} token in origin {origin}: {token!r}")
        previous = owner_by_token.get(token)
        if previous is not None and previous != origin:
            raise MigrationHarnessError(
                f"function token {token} belongs to two origin classes: {previous}, {origin}"
            )
        owner_by_token[token] = origin

    for entry in entries:
        origin = str(entry.get("old_id"))
        target = str(entry.get("new_id"))
        claim(origin, origin, "old_id")
        claim(target, origin, "new_id")
        if target not in target_ids:
            raise MigrationHarnessError(f"live target {target} for {origin} is absent from target ledger")
        if target in final_by_origin and final_by_origin[target] != origin:
            raise MigrationHarnessError(
                f"two origins converge on target {target}: {final_by_origin[target]}, {origin}"
            )
        final_by_origin[target] = origin
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise MigrationHarnessError(f"aliases for {origin} are not an array")
        if len(aliases) != len(set(aliases)):
            raise MigrationHarnessError(f"origin {origin} repeats an alias token")
        for alias in aliases:
            if alias == target:
                raise MigrationHarnessError(f"alias {alias} equals its live final target for {origin}")
            if alias in target_ids:
                raise MigrationHarnessError(
                    f"alias {alias} for {origin} is an unrelated current-ledger function id"
                )
            claim(alias, origin, "alias")
            alias_count += 1

    for tombstone in tombstones:
        origin = str(tombstone.get("old_id"))
        claim(origin, origin, "tombstone old_id")
        aliases = tombstone.get("aliases")
        required = (
            "path", "module", "owner", "name", "signature", "deleted_at_commit",
            "parent_blob", "child_blob", "reason",
        )
        if not isinstance(aliases, list) or not aliases or any(not tombstone.get(k) for k in required):
            raise MigrationHarnessError(f"tombstone {origin} is missing aliases/commit/blob/signature metadata")
        if len(aliases) != len(set(aliases)):
            raise MigrationHarnessError(f"tombstone {origin} repeats an alias token")
        for field in ("deleted_at_commit", "parent_blob", "child_blob"):
            if not re.fullmatch(r"[0-9a-f]{40}", str(tombstone[field])):
                raise MigrationHarnessError(f"tombstone {origin} has malformed {field}")
        for alias in aliases:
            if alias in target_ids:
                raise MigrationHarnessError(
                    f"tombstone alias {alias} for {origin} is still in the target ledger"
                )
            claim(alias, origin, "tombstone alias")

    if len(entries) + len(tombstones) != expected_origin_count:
        raise MigrationHarnessError("live/tombstone classes do not cover every source origin")
    if alias_count != expected_alias_count:
        raise MigrationHarnessError(
            f"live alias token count mismatch: expected {expected_alias_count}, got {alias_count}"
        )
    return {
        "origin_entries": len(entries),
        "tombstones": len(tombstones),
        "alias_tokens": alias_count,
        "class_tokens": len(owner_by_token),
    }


def migration_reconciliation_document(root: Path) -> dict[str, object]:  # noqa: C901
    commits = verify_rekey_boundary(root)
    source_ledger = _migration_json_from_git(
        root, REKEY_SOURCE_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    target_ledger = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_LEDGER.json"
    )
    source_migration = _migration_json_from_git(
        root, REKEY_TARGET_COMMIT, "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
    )
    source_entries, target_ids, source_rust_by_legacy = _validate_rekey_source_tables(
        source_ledger, target_ledger, source_migration
    )
    fresh_rust = _fresh_target_rust(root, target_ledger)
    fresh_ids = {str(record["id"]) for record in fresh_rust}
    pinned_rust_ids = {
        str(record["id"]) for record in target_ledger["rugra_functions"]
    }
    if fresh_ids != pinned_rust_ids:
        raise MigrationHarnessError("fresh target Rust ID set differs from the pinned ledger")

    gap_rows = [entry for entry in source_entries if entry.get("new_id") not in target_ids]
    if len(gap_rows) != REKEY_GAP_COUNT or any(entry.get("language") != "rust" for entry in gap_rows):
        raise MigrationHarnessError(
            f"source rekey gap mismatch: expected {REKEY_GAP_COUNT} Rust rows, got {len(gap_rows)}"
        )
    original_by_legacy = {str(entry["old_id"]): entry for entry in source_entries}
    original_base_ids = {str(entry["new_id"]) for entry in source_entries}
    if len(original_by_legacy) != len(source_entries) or len(original_base_ids) != len(source_entries):
        raise MigrationHarnessError("source migration origin/base IDs are not one-to-one")

    text_cache: dict[str, str] = {}
    scan_cache: dict[tuple[str, str], list[dict[str, object]]] = {}
    source_path_blobs: dict[str, str] = {}
    source_records_by_id: dict[str, dict[str, object]] = {}
    for row in gap_rows:
        legacy = str(row["old_id"])
        old_record = source_rust_by_legacy.get(legacy)
        if old_record is None:
            raise MigrationHarnessError(f"gap origin {legacy} is absent from source ledger")
        path = str(old_record.get("path"))
        if path not in source_path_blobs:
            source_path_blobs[path] = _migration_git(
                root, ["rev-parse", f"{REKEY_SOURCE_COMMIT}:{path}"]
            ).strip()
            for record in _scan_rekey_blob(
                root, path, source_path_blobs[path], text_cache, scan_cache
            ):
                source_records_by_id[str(record["id"])] = record
        base = str(row["new_id"])
        base_record = source_records_by_id.get(base)
        if base_record is None:
            raise MigrationHarnessError(f"gap base {base} is absent from pinned source scan")
        positional = (base_record["path"], base_record["line"], base_record["name"])
        expected = (old_record.get("path"), old_record.get("line"), old_record.get("name"))
        if positional != expected:
            raise MigrationHarnessError(
                f"source legacy/base positional proof failed for {legacy}: {expected} != {positional}"
            )

    states: dict[str, dict[str, object]] = {
        str(row["old_id"]): {
            "legacy_id": str(row["old_id"]),
            "base_id": str(row["new_id"]),
            "current_id": str(row["new_id"]),
            "lineage": [],
            "status": "live",
        }
        for row in gap_rows
    }
    tracked: dict[str, str] = {
        str(row["new_id"]): str(row["old_id"]) for row in gap_rows
    }
    reviewed_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for rule in REKEY_REVIEWED_TRANSITIONS:
        reviewed_by_commit[rule["commit"]].append(rule)
        source = original_by_legacy.get(rule["legacy_id"])
        if source is None or source.get("new_id") != rule["from_id"]:
            raise MigrationHarnessError(
                f"reviewed transition source pin mismatch for {rule['legacy_id']}"
            )
        if rule["kind"] == "successor" and rule["to_id"] in original_base_ids:
            raise MigrationHarnessError(
                f"reviewed successor {rule['to_id']} already has a source migration predecessor"
            )
    tombstone_by_key = {
        (rule["legacy_id"], rule["base_id"], rule["commit"]): rule
        for rule in REKEY_REVIEWED_TOMBSTONES
    }
    if len(tombstone_by_key) != REKEY_TOMBSTONE_COUNT:
        raise MigrationHarnessError("reviewed tombstone allowlist contains duplicate keys")

    used_reviewed: set[tuple[str, str]] = set()
    used_tombstones: set[tuple[str, str, str]] = set()
    tombstones: list[dict[str, object]] = []
    automatic_events = 0
    automatic_origins: set[str] = set()
    reviewed_counts: Counter[str] = Counter()
    hunk_cache: dict[tuple[str, str], list[tuple[int, int, int, int]]] = {}

    previous = REKEY_SOURCE_COMMIT
    for commit in commits:
        changes = _rust_changes(root, previous, commit)
        before: dict[str, tuple[dict[str, object], str]] = {}
        after: dict[str, tuple[dict[str, object], str]] = {}
        child_blob_by_path: dict[str, str] = {}
        for change in changes:
            old_path, new_path = change["old_path"], change["new_path"]
            old_blob, new_blob = change["old_blob"], change["new_blob"]
            if old_path.endswith(".rs"):
                for record in _scan_rekey_blob(root, old_path, old_blob, text_cache, scan_cache):
                    before[str(record["id"])] = (record, old_blob)
            if new_path.endswith(".rs"):
                child_blob_by_path[new_path] = new_blob
                for record in _scan_rekey_blob(root, new_path, new_blob, text_cache, scan_cache):
                    after[str(record["id"])] = (record, new_blob)

        removed = {
            token: before[token]
            for token in sorted(set(tracked).intersection(before).difference(after))
        }
        newly_added = {
            token: after[token]
            for token in sorted(set(after).difference(before))
        }
        claimed_targets: set[str] = set()

        for rule in reviewed_by_commit.get(commit, []):
            source_token, target_token = rule["from_id"], rule["to_id"]
            legacy, old_record, parent_blob, new_record, child_blob = (
                validate_reviewed_transition(
                    rule, tracked, removed, newly_added, claimed_targets
                )
            )
            event = _lineage_event(
                old_record,
                new_record,
                commit,
                parent_blob,
                child_blob,
                [f"reviewed_{rule['kind']}_allowlist", rule["label"]],
            )
            states[legacy]["lineage"].append(event)
            states[legacy]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = legacy
            removed.pop(source_token)
            claimed_targets.add(target_token)
            used_reviewed.add((rule["legacy_id"], commit))
            reviewed_counts[rule["kind"]] += 1

        removed_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        added_groups: dict[tuple[object, ...], list[str]] = defaultdict(list)
        for token, (record, _) in removed.items():
            key = (record["path"], record["module"], record["owner"], record["name"])
            removed_groups[key].append(token)
        for token, (record, _) in newly_added.items():
            if token in claimed_targets:
                continue
            key = (record["path"], record["module"], record["owner"], record["name"])
            added_groups[key].append(token)

        transitioned: set[str] = set()
        for key in sorted(removed_groups, key=lambda value: tuple(str(part) for part in value)):
            old_tokens = sorted(removed_groups[key])
            new_tokens = sorted(added_groups.get(key, []))
            if not new_tokens:
                continue
            old_record_for_hunk = removed[old_tokens[0]][0]
            hunks = _diff_hunks(
                root, previous, commit, str(old_record_for_hunk["path"]), hunk_cache
            )
            selected = select_unique_strict_transition(
                commit, key, old_tokens, new_tokens, removed, newly_added, hunks
            )
            if selected is None:
                continue
            source_token, target_token, evidence = selected
            old_record, parent_blob = removed[source_token]
            new_record, child_blob = newly_added[target_token]
            legacy = tracked[source_token]
            if target_token in tracked or target_token in claimed_targets:
                raise MigrationHarnessError(
                    f"automatic transition target collision at {commit}: {target_token}"
                )
            event = _lineage_event(
                old_record, new_record, commit, parent_blob, child_blob, evidence
            )
            states[legacy]["lineage"].append(event)
            states[legacy]["current_id"] = target_token
            del tracked[source_token]
            tracked[target_token] = legacy
            claimed_targets.add(target_token)
            transitioned.add(source_token)
            automatic_events += 1
            automatic_origins.add(legacy)

        for source_token in sorted(set(removed).difference(transitioned)):
            old_record, parent_blob = removed[source_token]
            legacy = tracked[source_token]
            key = (legacy, source_token, commit)
            rule = tombstone_by_key.get(key)
            if rule is None:
                candidates = added_groups.get(
                    (old_record["path"], old_record["module"], old_record["owner"], old_record["name"]),
                    [],
                )
                raise MigrationHarnessError(
                    f"unproved removal is neither reviewed transition nor tombstone at {commit}: "
                    f"{legacy} {source_token} {old_record['path']}::{old_record['name']} "
                    f"same-key-added={sorted(candidates)}"
                )
            if rule["name"] != old_record["name"]:
                raise MigrationHarnessError(
                    f"reviewed tombstone name drift for {legacy}: "
                    f"expected {rule['name']}, got {old_record['name']}"
                )
            child_blob = child_blob_by_path.get(str(old_record["path"]))
            if child_blob is None or not re.fullmatch(r"[0-9a-f]{40}", child_blob):
                raise MigrationHarnessError(
                    f"cannot resolve tombstone child blob for {legacy} at {commit}"
                )
            tombstones.append(
                _tombstone_record(
                    states[legacy], old_record, commit, parent_blob, child_blob
                )
            )
            states[legacy]["current_id"] = None
            states[legacy]["status"] = "tombstone"
            del tracked[source_token]
            used_tombstones.add(key)
        previous = commit

    expected_reviewed = {
        (rule["legacy_id"], rule["commit"]) for rule in REKEY_REVIEWED_TRANSITIONS
    }
    if used_reviewed != expected_reviewed:
        raise MigrationHarnessError(
            f"reviewed transition coverage mismatch: missing={sorted(expected_reviewed-used_reviewed)} "
            f"extra={sorted(used_reviewed-expected_reviewed)}"
        )
    if used_tombstones != set(tombstone_by_key):
        raise MigrationHarnessError(
            f"reviewed tombstone coverage mismatch: missing={sorted(set(tombstone_by_key)-used_tombstones)}"
        )
    if automatic_events != REKEY_AUTO_EVENT_COUNT or len(automatic_origins) != REKEY_AUTO_LINEAGE_COUNT:
        raise MigrationHarnessError(
            "automatic history replay count mismatch: "
            f"events={automatic_events}/{REKEY_AUTO_EVENT_COUNT} "
            f"origins={len(automatic_origins)}/{REKEY_AUTO_LINEAGE_COUNT}"
        )
    if reviewed_counts != Counter(
        {"same_name": REKEY_REVIEWED_SAME_NAME_COUNT, "successor": REKEY_REVIEWED_SUCCESSOR_COUNT}
    ):
        raise MigrationHarnessError(f"reviewed transition counts mismatch: {dict(reviewed_counts)}")
    live_rekey = [state for state in states.values() if state["status"] == "live"]
    if len(live_rekey) != REKEY_LIVE_REKEY_LINEAGE_COUNT or len(tracked) != len(live_rekey):
        raise MigrationHarnessError(
            f"live rekey lineage mismatch: states={len(live_rekey)} tracked={len(tracked)}"
        )
    two_hop = sorted(
        state["legacy_id"] for state in live_rekey if len(state["lineage"]) == 2
    )
    expected_two_hop = sorted(
        (
            "RG-F-2d786ec5c86965bc0302",
            "RG-F-3c4065b2a0d827d950cc",
            "RG-F-aed699f2484f67f4d52d",
        )
    )
    if two_hop != expected_two_hop or any(len(state["lineage"]) not in (1, 2) for state in live_rekey):
        raise MigrationHarnessError(f"two-hop lineage set mismatch: {two_hop}")
    for token, legacy in tracked.items():
        if token not in target_ids or states[legacy]["current_id"] != token:
            raise MigrationHarnessError(f"live replay target is absent/inconsistent: {legacy} -> {token}")

    live_rows: list[dict[str, object]] = []
    for source in source_entries:
        legacy = str(source["old_id"])
        state = states.get(legacy)
        if state is not None and state["status"] == "tombstone":
            continue
        if state is None:
            live_rows.append(dict(source))
            continue
        lineage = list(state["lineage"])
        aliases = [str(event["from_id"]) for event in lineage]
        live_rows.append(
            {
                "old_id": legacy,
                "new_id": state["current_id"],
                "language": "rust",
                "reason": "rust_history_rekey",
                "aliases": aliases,
                "lineage": lineage,
            }
        )
    tombstones.sort(key=lambda item: str(item["old_id"]))
    class_stats = _validate_reconciled_classes(live_rows, tombstones, target_ids)

    source_ledger_bytes = _migration_git(
        root, ["show", f"{REKEY_SOURCE_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    target_ledger_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_LEDGER.json"]
    ).encode("utf-8")
    source_migration_bytes = _migration_git(
        root, ["show", f"{REKEY_TARGET_COMMIT}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json"]
    ).encode("utf-8")
    return {
        "schema": 2,
        "oracle_commit": ORACLE_COMMIT,
        "id_scheme": source_migration["id_scheme"],
        "old_ledger": {
            "path": "docs/alignment_audit/FUNCTION_LEDGER.json",
            "tree_commit": REKEY_SOURCE_COMMIT,
            "tree_subject": _migration_git(
                root, ["show", "-s", "--format=%s", REKEY_SOURCE_COMMIT]
            ).strip(),
        },
        "source": {
            "commit": REKEY_SOURCE_COMMIT,
            "commit_tree": REKEY_SOURCE_COMMIT_TREE,
            "src_tree": REKEY_SOURCE_SRC_TREE,
            "ledger_blob": REKEY_SOURCE_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(source_ledger_bytes).hexdigest(),
            "migration_blob": REKEY_SOURCE_MIGRATION_BLOB,
            "migration_sha256": hashlib.sha256(source_migration_bytes).hexdigest(),
        },
        "target": {
            "commit": REKEY_TARGET_COMMIT,
            "commit_tree": REKEY_TARGET_COMMIT_TREE,
            "src_tree": REKEY_TARGET_SRC_TREE,
            "ledger_blob": REKEY_TARGET_LEDGER_BLOB,
            "ledger_sha256": hashlib.sha256(target_ledger_bytes).hexdigest(),
        },
        "history": {
            "mode": "first_parent",
            "commit_count": len(commits),
            "first_commit": commits[0],
            "last_commit": commits[-1],
        },
        "semantics": (
            "Each source origin is reconciled by deterministic first-parent history replay. "
            "Automatic transitions require a unique same-file/module/owner/name pair plus "
            "same-hunk, identical non-empty annotation, or identical masked-body evidence. "
            "Reviewed exceptions are pinned by IDs, commit and blobs. Tombstones are diagnostic "
            "and are never automatic replacement targets."
        ),
        "stats": {
            **class_stats,
            "original_definitions": REKEY_ORIGIN_COUNT,
            "source_rekey_gaps": len(gap_rows),
            "live_rekey_lineages": len(live_rekey),
            "automatic_transition_events": automatic_events,
            "automatic_lineages": len(automatic_origins),
            "reviewed_same_name": reviewed_counts["same_name"],
            "reviewed_successors": reviewed_counts["successor"],
            "two_hop_lineages": len(two_hop),
            "ambiguous_old_ids": 0,
            "colliding_new_ids": 0,
        },
        "disambiguators": list(source_migration["disambiguators"]),
        "entries": live_rows,
        "tombstones": tombstones,
    }


def canonical_json(document: object) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_or_check(path: Path, content: str, check: bool) -> None:
    if check:
        existing = path.read_text(encoding="utf-8") if path.is_file() else ""
        if existing != content:
            raise RuntimeError(f"generated file is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def _ids_by_signature(records: list[dict[str, object]]) -> dict[str, str]:
    return {str(record["signature"]): str(record["id"]) for record in records}


def _git_state_fixture_ids(repo: Path, relative: str, revision_spec: str) -> dict[str, str]:
    text = command_output(["git", "show", revision_spec], repo)
    records = collect_rust_identities(relative, text, module_from_relative(relative))
    assign_rust_locked_ids(records)
    return _ids_by_signature(records)


def self_test() -> int:  # noqa: C901 - self-test is intentionally linear
    first = stable_id("X", ("a", 1, "b"))
    assert first == stable_id("X", ("a", 1, "b"))
    assert first != stable_id("X", ("a", 2, "b"))

    # Dependency extraction must use the named dependency column, preserve
    # code-span pipes, and ignore status/evidence tokens in a mixed cell.
    todo_fixture = """
| ID | write-set | 依赖 / 验收 / 证据 |
|---|---|---|
| `TASK-A-0001` | `left | right` | 依赖=`TASK-B-0001`；验收=`MATCH`；证据提及 `TASK-C-0001` |
| `TASK-B-0001` | none | 依赖=无；状态=`UNTESTED` |
| `TASK-C-0001` | none | 依赖=无 |
| `TASK-E-0001`（历史状态） | none | 依赖=无 |

| ID | 标题 | 依赖 |
|---|---|---|
| `TASK-D-0001` | pure dependency column | `TASK-A-0001`、`TASK-C-0001` |
"""
    todo_nodes, todo_edges = todo_dependency_inventory(todo_fixture)
    assert todo_nodes == {
        "TASK-A-0001",
        "TASK-B-0001",
        "TASK-C-0001",
        "TASK-D-0001",
        "TASK-E-0001",
    }
    assert todo_edges == {
        ("TASK-A-0001", "TASK-B-0001"),
        ("TASK-D-0001", "TASK-A-0001"),
        ("TASK-D-0001", "TASK-C-0001"),
    }
    assert not TODO_ID_RE.search("`MATCH` `MISMATCH` `NO_ORACLE` `UNTESTED`")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n| `TASK-A-0001` | `TASK-Z-0001` |\n"
        )
    except ValueError as error:
        assert "no stable row" in str(error)
    else:
        raise AssertionError("undefined TODO dependencies must fail closed")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n"
            "| `TASK-A-0001` | `TASK-B-0001` |\n"
            "| `TASK-B-0001` | `TASK-A-0001` |\n"
        )
    except ValueError as error:
        assert "dependency cycle" in str(error)
    else:
        raise AssertionError("cyclic TODO dependencies must fail closed")

    try:
        todo_dependency_inventory(
            "| ID | 依赖 |\n|---|---|\n| `TASK-A-0001` | `TASK-A-0001` |\n"
        )
    except ValueError as error:
        assert "TASK-A-0001 -> TASK-A-0001" in str(error)
    else:
        raise AssertionError("self-dependent TODOs must fail closed")

    rust_refs = "crate::real::module; // crate::comment::fake\n\"crate::literal::fake\";"
    masked_refs = [
        match.group("path")
        for match in RUST_CRATE_REF_RE.finditer(mask_non_code(rust_refs))
    ]
    assert masked_refs == ["real::module"], "comments and literals must not create Rust edges"

    # --- Ghidra guard-context disambiguation -------------------------------
    guarded = [
        "#define A 1",
        "void f(void) { A; }",
        "#ifdef _WIN32",
        "void f(void) { B; }",
        "#else",
        "void f(void) { C; }",
        "#endif",
    ]
    entries = [
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 2, "name": "f"},
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 4, "name": "f"},
        {"path": "x.cc", "file": "x.cc", "entry_kind": "definition", "signature": "void f(void)", "line": 6, "name": "f"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        cpp = Path(tmp)
        (cpp / "x.cc").write_text("\n".join(guarded) + "\n", encoding="utf-8")
        disambiguated = assign_ghidra_locked_ids(entries, cpp)
        assert len({entry["id"] for entry in entries}) == 3, "guard contexts must separate duplicates"
        assert len(disambiguated) == 3
        assert {entry["id_disambiguator"]["value"] for entry in disambiguated} == {
            "",
            "defined(_WIN32)",
            "!(defined(_WIN32))",
        }
        # Inserting unrelated lines above must not change any ID: guards are
        # content-derived, and the unguarded entry keeps its plain signature ID.
        shifted = [entries[0]["id"], entries[1]["id"], entries[2]["id"]]
        padded = ["", "// new", "#define Z 9", *guarded]
        padded_entries = [
            {**entry, "line": entry["line"] + 3} for entry in entries
        ]
        (cpp / "x.cc").write_text("\n".join(padded) + "\n", encoding="utf-8")
        assign_ghidra_locked_ids(padded_entries, cpp)
        assert [entry["id"] for entry in padded_entries] == shifted, "IDs must survive line insertion"
        # Two indistinguishable entries with no guards must fail closed.
        twins = [
            {"path": "y.cc", "file": "y.cc", "entry_kind": "definition", "signature": "void g(void)", "line": 1, "name": "g"},
            {"path": "y.cc", "file": "y.cc", "entry_kind": "definition", "signature": "void g(void)", "line": 2, "name": "g"},
        ]
        (cpp / "y.cc").write_text("void g(void) {}\nvoid g(void) {}\n", encoding="utf-8")
        try:
            assign_ghidra_locked_ids(twins, cpp)
        except RuntimeError as error:
            assert "indistinguishable" in str(error)
        else:
            raise AssertionError("unguarded Ghidra duplicates must fail closed")

    # --- Rust identity extraction ------------------------------------------
    trait_fixture = r'''
pub struct Foo;
pub trait Display { fn fmt(&self); }
pub trait Debug { fn fmt(&self); }
impl Display for Foo { pub fn fmt(&self) { } }
impl Debug for Foo { pub fn fmt(&self) { } }
impl<'a> Iterator for &'a mut Foo {
    fn next(&mut self) -> Option<u32> { None }
}
'''
    records = collect_rust_identities("src/trait_fixture.rs", trait_fixture, "trait_fixture")
    assign_rust_locked_ids(records)
    fmt_records = [
        record
        for record in records
        if record["name"] == "fmt" and str(record["owner"]).startswith("impl:")
    ]
    assert {record["owner"] for record in fmt_records} == {
        "impl:Foo as Display",
        "impl:Foo as Debug",
    }, "trait impls must render as 'Type as Trait'"
    assert len({record["id"] for record in records}) == len(records), (
        "same-Type multi-trait same-signature methods must stay distinct"
    )
    next_record = next(record for record in records if record["name"] == "next")
    assert next_record["owner"] == "impl:&'a mut Foo as Iterator"
    assert next_record["module"] == "trait_fixture"
    plain = next(record for record in records if record["name"] == "fmt")
    assert plain["signature"].startswith("fn fmt(&self)"), "visibility must be normalized away"

    # Same-name insert/delete/move must not disturb existing Rust IDs.
    v1 = "fn alpha(x: u32) -> u32 { x + 1 }\nfn beta() {}\n"
    v2 = "fn alpha(y: u64) -> u64 { y + 2 }\n" + v1  # same-name insertion above
    v3 = "fn alpha(x: u32) -> u32 { x + 1 }\n"  # deletion of beta
    v4 = "fn beta() {}\nfn alpha(x: u32) -> u32 { x + 1 }\n"  # move/swap
    base_ids = _ids_by_signature(
        assign_or_fail("src/move.rs", v1)
    )
    inserted_ids = _ids_by_signature(assign_or_fail("src/move.rs", v2))
    deleted_ids = _ids_by_signature(assign_or_fail("src/move.rs", v3))
    moved_ids = _ids_by_signature(assign_or_fail("src/move.rs", v4))
    assert base_ids["fn alpha(x: u32) -> u32"] == inserted_ids["fn alpha(x: u32) -> u32"]
    assert base_ids["fn alpha(x: u32) -> u32"] == deleted_ids["fn alpha(x: u32) -> u32"]
    assert base_ids == moved_ids, "moving functions must not change IDs"

    # Macro template scopes separate identical template functions.
    macro_fixture = r'''
macro_rules! gen_a { ($t:ty) => { impl Helper for $t { fn same(&self) -> u8 { 1 } } } }
macro_rules! gen_b { ($t:ty) => { impl Helper for $t { fn same(&self) -> u8 { 2 } } } }
fn after_macros() {}
'''
    records = collect_rust_identities("src/macro_fixture.rs", macro_fixture, "macro_fixture")
    assign_rust_locked_ids(records)
    same = [record for record in records if record["name"] == "same"]
    assert {record["owner"] for record in same} == {
        "macro:gen_a/impl:$t as Helper",
        "macro:gen_b/impl:$t as Helper",
    }, "macro template scopes must enter the owner context"
    assert len({record["id"] for record in same}) == 2

    # Two truly indistinguishable Rust items must fail closed.
    try:
        assign_rust_locked_ids(
            collect_rust_identities("src/twin.rs", "fn twin() {}\nfn twin() {}\n", "twin")
        )
    except RuntimeError as error:
        assert "indistinguishable" in str(error)
    else:
        raise AssertionError("identical Rust items must fail closed")

    # Identical helpers nested in two different #[test] scopes collide on
    # (module, owner, signature) -- the attribute-decorated headers never
    # enter the owner chain -- and must be separated by the raw enclosing
    # scope header, mirroring the Ghidra preprocessor-guard disambiguator.
    test_scope_fixture = (
        "#[test]\n"
        "fn test_alpha() {\n"
        "    fn helper(v: u64) -> u8 { v as u8 }\n"
        "    helper(1);\n"
        "}\n"
        "#[test]\n"
        "fn test_beta() {\n"
        "    fn helper(v: u64) -> u8 { v as u8 }\n"
        "    helper(2);\n"
        "}\n"
    )
    records = collect_rust_identities(
        "src/test_scope.rs", test_scope_fixture, "test_scope"
    )
    assign_rust_locked_ids(records)
    helpers = [record for record in records if record["name"] == "helper"]
    assert len(helpers) == 2
    assert len({record["id"] for record in helpers}) == 2, (
        "enclosing scope headers must separate identical test-local helpers"
    )
    assert all(record["owner"] == "free" for record in helpers)
    assert {record["id_disambiguator"]["kind"] for record in helpers} == {
        "enclosing_scope_header"
    }
    assert {record["id_disambiguator"]["value"] for record in helpers} == {
        "#[test] fn test_alpha()",
        "#[test] fn test_beta()",
    }, "disambiguator value is the whitespace-normalized raw enclosing header"
    # Inserting unrelated lines above must not change any ID (content-derived,
    # position-independent disambiguator).
    padded_records = collect_rust_identities(
        "src/test_scope.rs",
        "// new\n// new\n" + test_scope_fixture,
        "test_scope",
    )
    assign_rust_locked_ids(padded_records)
    padded_ids = [
        record["id"]
        for record in padded_records
        if record["name"] == "helper"
    ]
    assert sorted(padded_ids) == sorted(
        record["id"] for record in helpers
    ), "IDs must survive line insertion"
    # Two identical helpers nested inside the SAME scope are genuinely
    # indistinguishable and must still fail closed.
    try:
        assign_rust_locked_ids(
            collect_rust_identities(
                "src/test_twin_helper.rs",
                "#[test]\n"
                "fn test_gamma() {\n"
                "    fn helper(v: u64) -> u8 { v as u8 }\n"
                "    fn helper(v: u64) -> u8 { v as u8 }\n"
                "}\n",
                "test_twin_helper",
            )
        )
    except RuntimeError as error:
        assert "indistinguishable" in str(error)
    else:
        raise AssertionError(
            "identical helpers inside one scope must fail closed"
        )

    # --- staged / base / dirty git states -----------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        command_output(["git", "init", "-q", "."], repo)
        command_output(["git", "config", "user.email", "self-test@rudra"], repo)
        command_output(["git", "config", "user.name", "rudra self-test"], repo)
        relative = "src/main.rs"
        (repo / "src").mkdir()
        (repo / relative).write_text(v1, encoding="utf-8")
        command_output(["git", "add", relative], repo)
        command_output(["git", "commit", "-qm", "v1"], repo)
        head_ids = _git_state_fixture_ids(repo, relative, f"HEAD:{relative}")
        # staged: same-name insertion lives in the index only.
        (repo / relative).write_text(v2, encoding="utf-8")
        command_output(["git", "add", relative], repo)
        index_ids = _git_state_fixture_ids(repo, relative, f":{relative}")  # stage 0
        assert head_ids["fn alpha(x: u32) -> u32"] == index_ids["fn alpha(x: u32) -> u32"]
        # dirty: worktree deletes beta while the index still holds v2.
        (repo / relative).write_text(v3, encoding="utf-8")
        worktree_ids = _ids_by_signature(
            assign_or_fail(relative, (repo / relative).read_text(encoding="utf-8"))
        )
        assert index_ids["fn alpha(x: u32) -> u32"] == worktree_ids["fn alpha(x: u32) -> u32"]
        # base: commit and compare across the commit range.
        command_output(["git", "add", relative], repo)
        command_output(["git", "commit", "-qm", "v3"], repo)
        new_head_ids = _git_state_fixture_ids(repo, relative, f"HEAD:{relative}")
        base_ids = _git_state_fixture_ids(repo, relative, f"HEAD~1:{relative}")
        assert new_head_ids["fn alpha(x: u32) -> u32"] == base_ids["fn alpha(x: u32) -> u32"]
        assert head_ids["fn alpha(x: u32) -> u32"] == new_head_ids["fn alpha(x: u32) -> u32"], (
            "ID must be identical across staged, base, dirty, and committed states"
        )

    # --- migration fail-closed behavior --------------------------------------
    fresh_ghidra = [
        {"path": "x.cc", "line": 2, "entry_kind": "definition", "name": "f", "id": "GH12-F-new1"},
        {"path": "x.cc", "line": 4, "entry_kind": "definition", "name": "f", "id": "GH12-F-new2"},
    ]
    old_ghidra = [
        {"path": "x.cc", "line": 2, "entry_kind": "definition", "name": "f", "id": "GH12-F-old1"},
        {"path": "x.cc", "line": 4, "entry_kind": "definition", "name": "f", "id": "GH12-F-old2-01"},
    ]
    rows, disambiguators = migration_rows(
        old_ghidra,
        [dict(entry) for entry in fresh_ghidra],
        [],
        [],
    )
    assert [row["old_id"] for row in rows] == ["GH12-F-old1", "GH12-F-old2-01"]
    assert rows[1]["reason"] == "ghidra_ordinal_replaced_by_guard_disambiguator"
    stats = check_migration_rows(rows)
    assert stats["total"] == 2 and stats["ambiguous_old_ids"] == 0
    # same old id mapping to two new ids must be rejected
    try:
        check_migration_rows(
            [
                {"old_id": "GH12-F-old", "new_id": "GH12-F-a"},
                {"old_id": "GH12-F-old", "new_id": "GH12-F-b"},
            ]
        )
    except RuntimeError as error:
        assert "ambiguity" in str(error)
    else:
        raise AssertionError("ambiguous old ids must fail closed")
    # several old ids collapsing onto one new id must be rejected
    try:
        check_migration_rows(
            [
                {"old_id": "RG-F-old1", "new_id": "RG-F-same"},
                {"old_id": "RG-F-old2", "new_id": "RG-F-same"},
            ]
        )
    except RuntimeError as error:
        assert "ambiguity" in str(error)
    else:
        raise AssertionError("colliding new ids must fail closed")

    # --- reconciled migration lineage and failure matrix ------------------
    def synthetic_record(fid: str, signature: str, *, owner: str = "impl:Demo",
                         name: str = "step", line: int = 10,
                         body: str | None = "{ value }") -> dict[str, object]:
        return {
            "id": fid,
            "path": "src/demo.rs",
            "module": "demo",
            "owner": owner,
            "name": name,
            "signature": signature,
            "line": line,
            "end_line": line + 2,
            "is_test": False,
            "is_declaration": False,
            "_annotation": ("ghidra", '{"file":"x.cc","line":1}'),
            "_annotation_kind": "ghidra",
            "_annotation_value": {"file": "x.cc", "line": 1},
            "_masked_body": body,
        }

    old_token = "RG-F-" + "10" * 10
    new_token = "RG-F-" + "11" * 10
    old_record = synthetic_record(old_token, "fn step(&self, x: u8)")
    new_record = synthetic_record(new_token, "fn step(&self, x: u16)")
    evidence = strict_transition_evidence(old_record, new_record, [(10, 1, 10, 1)])
    assert evidence == [
        "same_patch_hunk", "identical_nonempty_annotation", "identical_masked_body"
    ], "one-hop signature change must retain all deterministic evidence"
    selected = select_unique_strict_transition(
        "a" * 40,
        ("src/demo.rs", "demo", "impl:Demo", "step"),
        [old_token],
        [new_token],
        {old_token: (old_record, "1" * 40)},
        {new_token: (new_record, "2" * 40)},
        [(10, 1, 10, 1)],
    )
    assert selected and selected[:2] == (old_token, new_token)

    # Post-baseline evidence canonicalizes binding modifiers only.  Pointer
    # and reference mutability are part of the function type and stay intact.
    mut_old = synthetic_record(old_token, "fn step(&mut self, slot: usize)")
    mut_new = synthetic_record(new_token, "fn step(&mut self, mut slot: usize)")
    assert rust_parameter_binding_mut_normalized_signature(mut_old["signature"]) == (
        rust_parameter_binding_mut_normalized_signature(mut_new["signature"])
    )
    assert continuity_transition_evidence(mut_old, mut_new, [(10, 1, 10, 1)]) == [
        "same_patch_hunk", "identical_nonempty_annotation", "parameter_binding_mut_only"
    ]
    for signature in (
        "fn borrow(x: &mut T)",
        "fn borrow(x: &'a mut T)",
        "fn pointer(x: *mut T)",
        "fn pattern(&mut x: &mut T)",
    ):
        assert rust_parameter_binding_mut_normalized_signature(signature) == signature
    assert (
        rust_parameter_binding_mut_normalized_signature("fn take(mut self, #[cfg(x)] mut y: T)")
        == "fn take(self, #[cfg(x)] y: T)"
    )
    non_mut_new = synthetic_record(new_token, "fn step(&mut self, slot: u64)")
    assert not continuity_transition_evidence(mut_old, non_mut_new, [(10, 1, 10, 1)])
    no_annotation = dict(mut_new)
    no_annotation["_annotation"] = None
    assert not continuity_transition_evidence(mut_old, no_annotation, [(10, 1, 10, 1)])
    assert not continuity_transition_evidence(mut_old, mut_new, [])

    # A separator-only signature reformat is an automatic alias; the nested
    # 1-tuple separator and a mixed separator+binding change are not.
    comma_old = synthetic_record(old_token, "fn step(&self, slot: usize,)")
    comma_new = synthetic_record(new_token, "fn step(&self, slot: usize)")
    assert continuity_transition_evidence(comma_old, comma_new, [(10, 1, 10, 1)]) == [
        "same_patch_hunk", "identical_nonempty_annotation", "signature_trailing_comma_only"
    ]
    assert not continuity_transition_evidence(comma_old, comma_new, [])
    assert rust_trailing_comma_normalized_signature("fn take(x: u8,) -> u8") == (
        rust_trailing_comma_normalized_signature("fn take(x: u8) -> u8")
    )
    nested_old = synthetic_record(old_token, "fn step(&self, slot: (u8,))")
    nested_new = synthetic_record(new_token, "fn step(&self, slot: (u8))")
    assert rust_trailing_comma_normalized_signature(nested_old["signature"]) != (
        rust_trailing_comma_normalized_signature(nested_new["signature"])
    )
    assert not continuity_transition_evidence(nested_old, nested_new, [(10, 1, 10, 1)])
    mixed_old = synthetic_record(old_token, "fn step(&self, mut slot: usize,)")
    mixed_new = synthetic_record(new_token, "fn step(&self, slot: usize)")
    assert not continuity_transition_evidence(mixed_old, mixed_new, [(10, 1, 10, 1)])

    # Owner-header drift, or a rename plus body rewrite, is not an automatic
    # successor merely because a nearby function appeared.
    owner_drift = synthetic_record(
        "RG-F-" + "12" * 10, "fn step(&self, x: u16)", owner="impl:Demo as Trait"
    )
    renamed = synthetic_record(
        "RG-F-" + "13" * 10, "fn replacement(&self)", name="replacement", body="{ other }"
    )
    assert (old_record["owner"], old_record["name"]) != (owner_drift["owner"], owner_drift["name"])
    assert (old_record["owner"], old_record["name"]) != (renamed["owner"], renamed["name"])
    no_proof = dict(new_record)
    no_proof["_annotation"] = None
    no_proof["_masked_body"] = "{ rewritten }"
    assert not strict_transition_evidence(old_record, no_proof, [])

    reviewed_target = "RG-F-" + "16" * 10
    moved_record = synthetic_record(
        reviewed_target, "fn replacement()", owner="free", name="replacement"
    )
    moved_record["path"] = "src/replacement.rs"
    moved_record["module"] = "replacement"
    reviewed_rule = {
        "legacy_id": "RG-F-" + "17" * 10,
        "from_id": old_token,
        "to_id": reviewed_target,
        "commit": "6" * 40,
        "kind": "successor",
        "label": "reviewed rename and move",
        "parent_blob_prefix": "1" * 8,
        "child_blob_prefix": "2" * 8,
    }
    validated = validate_reviewed_transition(
        reviewed_rule,
        {old_token: reviewed_rule["legacy_id"]},
        {old_token: (old_record, "1" * 40)},
        {reviewed_target: (moved_record, "2" * 40)},
        set(),
    )
    assert validated[0] == reviewed_rule["legacy_id"], "explicit rename+move must use exact pins"
    try:
        validate_reviewed_transition(
            reviewed_rule,
            {old_token: reviewed_rule["legacy_id"]},
            {old_token: (old_record, "1" * 40)},
            {},  # target existed before the commit, so it is not newly added
            set(),
        )
    except MigrationHarnessError as error:
        assert "not newly added" in str(error)
    else:
        raise AssertionError("wrapper/deletion -> existing function must be rejected")
    wrong_blob_rule = dict(reviewed_rule)
    wrong_blob_rule["child_blob_prefix"] = "9" * 8
    try:
        validate_reviewed_transition(
            wrong_blob_rule,
            {old_token: reviewed_rule["legacy_id"]},
            {old_token: (old_record, "1" * 40)},
            {reviewed_target: (moved_record, "2" * 40)},
            set(),
        )
    except MigrationHarnessError as error:
        assert "child blob mismatch" in str(error)
    else:
        raise AssertionError("reviewed transition blob drift must fail closed")

    # 1->2, 2->1, and overload candidate sets are ambiguous even when one
    # candidate happens to have matching body/annotation evidence.
    other_old = "RG-F-" + "14" * 10
    other_new = "RG-F-" + "15" * 10
    before = {
        old_token: (old_record, "1" * 40),
        other_old: (synthetic_record(other_old, "fn step(&self, x: u32)"), "1" * 40),
    }
    after = {
        new_token: (new_record, "2" * 40),
        other_new: (synthetic_record(other_new, "fn step(&self, x: u64)"), "2" * 40),
    }
    for old_ids, new_ids in (
        ([old_token], [new_token, other_new]),
        ([old_token, other_old], [new_token]),
        ([old_token, other_old], [new_token, other_new]),
    ):
        try:
            select_unique_strict_transition(
                "b" * 40, ("src/demo.rs", "demo", "impl:Demo", "step"),
                old_ids, new_ids, before, after, [(10, 2, 10, 2)],
            )
        except MigrationHarnessError as error:
            assert "ambiguous automatic transition" in str(error)
        else:
            raise AssertionError("ambiguous transition cardinality must fail closed")

    def live_row(old: str, new: str, aliases: list[str]) -> dict[str, object]:
        return {"old_id": old, "new_id": new, "aliases": aliases}

    def dead_row(old: str, aliases: list[str]) -> dict[str, object]:
        return {
            "old_id": old,
            "aliases": aliases,
            "path": "src/deleted.rs",
            "module": "deleted",
            "owner": "free",
            "name": "gone",
            "signature": "fn gone()",
            "deleted_at_commit": "3" * 40,
            "parent_blob": "4" * 40,
            "child_blob": "5" * 40,
            "reason": "deleted_without_reviewed_successor",
        }

    legacy_live = "RG-F-" + "20" * 10
    final_live = "RG-F-" + "21" * 10
    base_live = "RG-F-" + "22" * 10
    middle_live = "RG-F-" + "23" * 10
    legacy_dead = "RG-F-" + "30" * 10
    base_dead = "RG-F-" + "31" * 10
    healthy_stats = _validate_reconciled_classes(
        [live_row(legacy_live, final_live, [base_live, middle_live])],
        [dead_row(legacy_dead, [base_dead])],
        {final_live},
        expected_origin_count=2,
        expected_live_count=1,
        expected_tombstone_count=1,
        expected_alias_count=2,
    )
    assert healthy_stats["alias_tokens"] == 2, "two-hop compression must retain intermediate alias"

    def expect_rekey_failure(label: str, thunk) -> None:
        try:
            thunk()
        except MigrationHarnessError:
            return
        raise AssertionError(f"{label} must fail closed")

    # Duplicate aliases across origin classes and 2->1 final convergence.
    second_old = "RG-F-" + "40" * 10
    second_final = "RG-F-" + "41" * 10
    expect_rekey_failure(
        "duplicate alias across classes",
        lambda: _validate_reconciled_classes(
            [
                live_row(legacy_live, final_live, [base_live]),
                live_row(second_old, second_final, [base_live]),
            ], [], {final_live, second_final}, expected_origin_count=2,
            expected_live_count=2, expected_tombstone_count=0, expected_alias_count=2,
        ),
    )
    expect_rekey_failure(
        "two origins converging on one final",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, []), live_row(second_old, final_live, [])],
            [], {final_live}, expected_origin_count=2, expected_live_count=2,
            expected_tombstone_count=0, expected_alias_count=0,
        ),
    )
    expect_rekey_failure(
        "alias equals unrelated current id",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, [second_final])], [],
            {final_live, second_final}, expected_origin_count=1, expected_live_count=1,
            expected_tombstone_count=0, expected_alias_count=1,
        ),
    )
    expect_rekey_failure(
        "live target absent ledger",
        lambda: _validate_reconciled_classes(
            [live_row(legacy_live, final_live, [])], [], set(),
            expected_origin_count=1, expected_live_count=1,
            expected_tombstone_count=0, expected_alias_count=0,
        ),
    )
    malformed_tombstone = dead_row(legacy_dead, [base_dead])
    del malformed_tombstone["parent_blob"]
    expect_rekey_failure(
        "tombstone missing commit/blob/signature",
        lambda: _validate_reconciled_classes(
            [], [malformed_tombstone], set(), expected_origin_count=1,
            expected_live_count=0, expected_tombstone_count=1, expected_alias_count=0,
        ),
    )
    # A lineage that transitions and is later deleted retains both its base
    # and intermediate tokens in the tombstone class.
    intermediate_dead = dead_row(legacy_dead, [base_dead, middle_live])
    _validate_reconciled_classes(
        [], [intermediate_dead], set(), expected_origin_count=1,
        expected_live_count=0, expected_tombstone_count=1, expected_alias_count=0,
    )

    # Pinned git boundary: commit/tree/blob mismatches, unrelated history,
    # dirty src and dirty ledger are harness errors (the CLI maps these to 2).
    pin_names = (
        "REKEY_SOURCE_COMMIT", "REKEY_SOURCE_COMMIT_TREE", "REKEY_SOURCE_SRC_TREE",
        "REKEY_SOURCE_LEDGER_BLOB", "REKEY_TARGET_COMMIT", "REKEY_TARGET_COMMIT_TREE",
        "REKEY_TARGET_SRC_TREE", "REKEY_TARGET_LEDGER_BLOB",
        "REKEY_SOURCE_MIGRATION_BLOB", "REKEY_FIRST_PARENT_COMMIT_COUNT",
    )
    saved_pins = {name: globals()[name] for name in pin_names}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        command_output(["git", "init", "-q", "."], repo)
        command_output(["git", "config", "user.email", "self-test@rudra"], repo)
        command_output(["git", "config", "user.name", "rudra self-test"], repo)
        (repo / "src").mkdir()
        (repo / "docs/alignment_audit").mkdir(parents=True)
        source_text = "fn source() {}\n"
        target_text = "fn source(x: u8) {}\n"
        ledger_path = repo / "docs/alignment_audit/FUNCTION_LEDGER.json"
        migration_path = repo / "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
        bad_json_path = repo / "docs/alignment_audit/bad.json"
        (repo / "src/main.rs").write_text(source_text, encoding="utf-8")
        ledger_path.write_text("{}\n", encoding="utf-8")
        command_output(["git", "add", "src/main.rs", "docs/alignment_audit/FUNCTION_LEDGER.json"], repo)
        command_output(["git", "commit", "-qm", "source"], repo)
        source_commit = command_output(["git", "rev-parse", "HEAD"], repo).strip()
        (repo / "src/main.rs").write_text(target_text, encoding="utf-8")
        ledger_path.write_text('{"target":true}\n', encoding="utf-8")
        migration_path.write_text('{"source":true}\n', encoding="utf-8")
        bad_json_path.write_text("{broken\n", encoding="utf-8")
        command_output(
            ["git", "add", "src/main.rs", "docs/alignment_audit/FUNCTION_LEDGER.json",
             "docs/alignment_audit/FUNCTION_ID_MIGRATION.json",
             "docs/alignment_audit/bad.json"], repo,
        )
        command_output(["git", "commit", "-qm", "target"], repo)
        target_commit = command_output(["git", "rev-parse", "HEAD"], repo).strip()
        synthetic_pins = {
            "REKEY_SOURCE_COMMIT": source_commit,
            "REKEY_SOURCE_COMMIT_TREE": command_output(
                ["git", "rev-parse", f"{source_commit}^{{tree}}"], repo
            ).strip(),
            "REKEY_SOURCE_SRC_TREE": command_output(
                ["git", "rev-parse", f"{source_commit}:src"], repo
            ).strip(),
            "REKEY_SOURCE_LEDGER_BLOB": command_output(
                ["git", "rev-parse", f"{source_commit}:docs/alignment_audit/FUNCTION_LEDGER.json"], repo
            ).strip(),
            "REKEY_TARGET_COMMIT": target_commit,
            "REKEY_TARGET_COMMIT_TREE": command_output(
                ["git", "rev-parse", f"{target_commit}^{{tree}}"], repo
            ).strip(),
            "REKEY_TARGET_SRC_TREE": command_output(
                ["git", "rev-parse", f"{target_commit}:src"], repo
            ).strip(),
            "REKEY_TARGET_LEDGER_BLOB": command_output(
                ["git", "rev-parse", f"{target_commit}:docs/alignment_audit/FUNCTION_LEDGER.json"], repo
            ).strip(),
            "REKEY_SOURCE_MIGRATION_BLOB": command_output(
                ["git", "rev-parse", f"{target_commit}:docs/alignment_audit/FUNCTION_ID_MIGRATION.json"], repo
            ).strip(),
            "REKEY_FIRST_PARENT_COMMIT_COUNT": 1,
        }
        try:
            globals().update(synthetic_pins)
            assert verify_rekey_boundary(repo, verify_locked_oracle=False) == [target_commit]
            expect_rekey_failure(
                "malformed pinned JSON",
                lambda: _migration_json_from_git(
                    repo, target_commit, "docs/alignment_audit/bad.json"
                ),
            )

            (repo / "src/main.rs").write_text(target_text + "// dirty\n", encoding="utf-8")
            expect_rekey_failure(
                "dirty target src", lambda: verify_rekey_boundary(repo, verify_locked_oracle=False)
            )
            (repo / "src/main.rs").write_text(target_text, encoding="utf-8")

            globals()["REKEY_TARGET_SRC_TREE"] = "0" * 40
            expect_rekey_failure(
                "target src tree mismatch",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
            globals()["REKEY_TARGET_SRC_TREE"] = synthetic_pins["REKEY_TARGET_SRC_TREE"]

            ledger_path.write_text('{"dirty":true}\n', encoding="utf-8")
            expect_rekey_failure(
                "target ledger mismatch",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
            ledger_path.write_text('{"target":true}\n', encoding="utf-8")

            expect_rekey_failure(
                "object pin mismatch",
                lambda: _expect_git_object(repo, "HEAD^{commit}", "0" * 40, "test commit"),
            )

            unrelated = command_output(
                ["git", "commit-tree", synthetic_pins["REKEY_TARGET_COMMIT_TREE"], "-m", "unrelated"],
                repo,
            ).strip()
            globals()["REKEY_SOURCE_COMMIT"] = unrelated
            globals()["REKEY_SOURCE_COMMIT_TREE"] = synthetic_pins["REKEY_TARGET_COMMIT_TREE"]
            globals()["REKEY_SOURCE_SRC_TREE"] = synthetic_pins["REKEY_TARGET_SRC_TREE"]
            globals()["REKEY_SOURCE_LEDGER_BLOB"] = synthetic_pins["REKEY_TARGET_LEDGER_BLOB"]
            expect_rekey_failure(
                "source not ancestor",
                lambda: verify_rekey_boundary(repo, verify_locked_oracle=False),
            )
        finally:
            globals().update(saved_pins)

    expect_rekey_failure(
        "malformed migration schema",
        lambda: _validate_rekey_source_tables({}, {}, {}),
    )

    # --- unmapped-disposition classification (GENERATOR_ABSORBED) ----------
    def disposition_entry(
        file: str, line: int, end_line: int, *, mapped: bool = False
    ) -> dict[str, object]:
        return {
            "file": file,
            "line": line,
            "end_line": end_line,
            "name": "synthetic",
            "qualified_name": "synthetic",
            "entry_kind": "definition",
            "rust_mappings": (
                [{"rust_id": "RG-F-syn", "kind": "exact_definition_start"}]
                if mapped
                else []
            ),
        }

    disposition_ghidra = [
        disposition_entry("grammar.cc", 50, 52, mapped=True),
        {"file": "grammar.cc", "line": 60, "end_line": 61, "name": "p",
         "qualified_name": "p", "entry_kind": "prototype", "rust_mappings": []},
        disposition_entry("grammar.cc", 100, 110),
        disposition_entry("grammar.cc", 200, 204),
        disposition_entry("grammar.cc", 300, 307),
        disposition_entry("unrelated.cc", 10, 20),
    ]
    disposition_rust = [
        {"path": "src/grammar.rs", "name": "mod_type", "owner": "free",
         "is_test": False, "id": "RG-F-holder1", "line": 900},
        {"path": "src/grammar.rs", "name": "mod_type", "owner": "impl:TypeModifier",
         "is_test": False, "id": "RG-F-holder2", "line": 800},
    ]
    disposition_whitelist = {
        ("grammar.cc", 100): {"class": "generator_absorbed"},
        ("grammar.cc", 200): {"class": "generator_shim"},
        ("grammar.cc", 300): {
            "class": "residual_relink",
            "twin": ("src/grammar.rs", "pointer_mod_type"),
            "holder": ("src/grammar.rs", "mod_type", "free"),
        },
    }
    disposition_constants = {
        "UNMAPPED_DISPOSITION_FILES": ("grammar.cc",),
        "UNMAPPED_DISPOSITIONS": disposition_whitelist,
        "UNMAPPED_DISPOSITION_EXPECTED_CLASSES": {
            "generator_absorbed": (1, 11),
            "generator_shim": (1, 5),
            "residual_relink": (1, 8),
        },
        "UNMAPPED_DISPOSITION_EXPECTED_POOL": (3, 24),
    }
    saved_dispositions = {
        name: globals()[name] for name in disposition_constants
    }
    try:
        globals().update(disposition_constants)
        stats = classify_unmapped_dispositions(disposition_ghidra, disposition_rust)
        assert stats["pool"] == {"definitions": 3, "loc": 24}
        assert stats["generator_absorbed_family"]["definitions"] == 2
        assert stats["remaining_pool"] == {"definitions": 1, "loc": 8}
        by_line = {
            entry["line"]: entry["unmapped_disposition"]
            for entry in disposition_ghidra
            if "unmapped_disposition" in entry
        }
        assert by_line[100]["face"] == GRAMMAR_FACE_EVIDENCE
        assert by_line[300]["holder"]["rust_id"] == "RG-F-holder1", (
            "holder resolution must pin owner=free, not the TypeModifier method"
        )
        assert by_line[300]["twin"]["status"] == (
            "extracted_on_parseadj_5b4a6b26_pending_merge"
        )

        def expect_disposition_failure(label: str, thunk) -> None:
            try:
                thunk()
            except RuntimeError as error:
                assert label in str(error), error
            else:
                raise AssertionError(f"{label} must fail closed")

        expect_disposition_failure(
            "without a pinned disposition",
            lambda: classify_unmapped_dispositions(
                [dict(entry) for entry in disposition_ghidra]
                + [disposition_entry("grammar.cc", 400, 410)],
                disposition_rust,
            ),
        )
        left_pool = [dict(entry) for entry in disposition_ghidra]
        left_pool[3] = disposition_entry("grammar.cc", 200, 204, mapped=True)
        expect_disposition_failure(
            "left the unmapped pool",
            lambda: classify_unmapped_dispositions(left_pool, disposition_rust),
        )
        globals()["UNMAPPED_DISPOSITION_EXPECTED_CLASSES"] = {
            "generator_absorbed": (1, 11),
            "generator_shim": (1, 4),
            "residual_relink": (1, 8),
        }
        expect_disposition_failure(
            "class drift",
            lambda: classify_unmapped_dispositions(
                [dict(entry) for entry in disposition_ghidra], disposition_rust
            ),
        )
        expect_disposition_failure(
            "target resolution failed",
            lambda: classify_unmapped_dispositions(
                [dict(entry) for entry in disposition_ghidra], []
            ),
        )
    finally:
        globals().update(saved_dispositions)

    lines = ["// Ghidra: x.cc:7 A::f", "fn f() {}"]
    record = scan_rust_functions("\n".join(lines))[0]
    kind, marker = marker_above(lines, record.start_line)
    assert kind == "ghidra" and marker["file"] == "x.cc" and marker["line"] == 7
    print("generate_function_ledger: self-test OK")
    return 0


def assign_or_fail(relative: str, text: str) -> list[dict[str, object]]:
    records = collect_rust_identities(relative, text, module_from_relative(relative))
    assign_rust_locked_ids(records)
    return records


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--cross-check",
        action="store_true",
        help="run the FMAPRECON REFSDEF-parser corroboration of the ctags .cc "
        "enumeration (pinned name-grain counts; writes nothing)",
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    migration_mode = parser.add_mutually_exclusive_group()
    migration_mode.add_argument(
        "--migrate",
        action="store_true",
        help="rewrite the existing ledger's ID space into scheme 2 and emit "
        "FUNCTION_ID_MIGRATION.json",
    )
    migration_mode.add_argument(
        "--reconcile-migration",
        action="store_true",
        help="replay the separately pinned scheme-2 source history into the pinned "
        "target ledger; never replaces the --migrate origin",
    )
    migration_mode.add_argument(
        "--reconcile-continuity",
        action="store_true",
        help="compose post-baseline raw scheme-2 ID continuity through the pinned "
        "source checkpoint; never rewrites FUNCTION_ID_MIGRATION.json",
    )
    parser.add_argument(
        "--migrate-base",
        help="commit whose tree reproduces the existing ledger (default: auto-detect)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    output_dir = args.output_dir.resolve() if args.output_dir else root / "docs/alignment_audit"
    try:
        if args.cross_check:
            cpp = verify_oracle(root)
            ghidra, _ = ctags_entries(root, cpp)
            validate_ctags_counts(ghidra)
            counts = parser_cross_check(cpp, ghidra)
            print(
                "generate_function_ledger: parser cross-check OK "
                f"parser={counts['refsdef_parser_cc_unique_names']} "
                f"ctags={counts['ctags_cc_unique_names_stripped']} "
                f"parser_only={counts['parser_only_names']} "
                f"ctags_only={counts['ctags_only_names']}"
            )
            return 0
        if args.reconcile_continuity:
            try:
                continuity = function_id_continuity_document(root)
            except MigrationHarnessError:
                raise
            except (
                OSError,
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
                UnicodeError,
                json.JSONDecodeError,
            ) as error:
                raise MigrationHarnessError(
                    f"{type(error).__name__}: {error}"
                ) from error
            write_or_check(
                output_dir / "FUNCTION_ID_CONTINUITY.json",
                canonical_json(continuity),
                args.check,
            )
            stats = continuity["stats"]
            print(
                "generate_function_ledger: reconciled continuity "
                f"baseline={stats['baseline_records']} current={stats['current_records']} "
                f"lineages={stats['lineages']} introduced={stats['introduced_live']} "
                f"tombstones={stats['tombstones']}"
            )
            return 0
        if args.reconcile_migration:
            try:
                migration = migration_reconciliation_document(root)
            except MigrationHarnessError:
                raise
            except (
                OSError,
                RuntimeError,
                ValueError,
                KeyError,
                TypeError,
                IndexError,
                UnicodeError,
                json.JSONDecodeError,
            ) as error:
                raise MigrationHarnessError(
                    f"{type(error).__name__}: {error}"
                ) from error
            write_or_check(
                output_dir / "FUNCTION_ID_MIGRATION.json",
                canonical_json(migration),
                args.check,
            )
            stats = migration["stats"]
            print(
                "generate_function_ledger: reconciled migration "
                f"origins={stats['origin_entries']} tombstones={stats['tombstones']} "
                f"lineages={stats['live_rekey_lineages']} aliases={stats['alias_tokens']} "
                f"auto_events={stats['automatic_transition_events']}"
            )
            return 0
        if args.migrate:
            ledger_path = root / "docs/alignment_audit/FUNCTION_LEDGER.json"
            migration = migration_document(root, ledger_path, output_dir, args.migrate_base)
            write_or_check(
                output_dir / "FUNCTION_ID_MIGRATION.json",
                canonical_json(migration),
                args.check,
            )
            stats = migration["stats"]
            print(
                f"generate_function_ledger: migration entries={stats['total']} "
                f"stable={stats['stable_unchanged']} changed={stats['changed']} "
                f"ambiguous={stats['ambiguous_old_ids']} collisions={stats['colliding_new_ids']} "
                f"disambiguators={len(migration['disambiguators'])}"
            )
            return 0
        cpp = verify_oracle(root)
        ghidra, ctags_version = ctags_entries(root, cpp)
        counts = validate_ctags_counts(ghidra)
        rust = rust_entries(root, ghidra)
        dispositions = classify_unmapped_dispositions(ghidra, rust)
        ledger = ledger_document(root, ghidra, rust, ctags_version, counts, dispositions)
        protocols = protocol_document(protocol_entries(root, cpp))
        dag = dependency_dag(root, cpp)
        outputs = {
            output_dir / "FUNCTION_LEDGER.json": canonical_json(ledger),
            output_dir / "FUNCTION_MAP.generated.md": markdown_summary(ledger),
            output_dir / "PROTOCOL_TABLE.json": canonical_json(protocols),
            output_dir / "DEPENDENCY_DAG.json": canonical_json(dag),
        }
        for path, content in outputs.items():
            write_or_check(path, content, args.check)
    except MigrationHarnessError as error:
        print(f"generate_function_ledger: migration harness input error: {error}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"generate_function_ledger: {error}", file=sys.stderr)
        return 1
    action = "verified" if args.check else "generated"
    print(
        f"generate_function_ledger: {action} definitions={ledger['summary']['behavior_definition_denominator']} "
        f"raw={ledger['summary']['raw_function_records']} rust={ledger['summary']['rudra_function_records']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
