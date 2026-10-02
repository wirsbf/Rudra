"""Generate Ghidra annotation mappings for Rudra src/*.rs files.

For each violating fn, find the enclosing struct/impl and derive the Ghidra
counterpart name (e.g. RuleXxx::applyOp). Then search the corresponding
Ghidra .cc file for that pattern and record the line number.

Outputs one JSON file per Rudra source file under result/anno_mappings/.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
GHIDRA_CPP = ROOT / "ghidra" / "Ghidra" / "Features" / "Decompiler" / "src" / "decompile" / "cpp"
OUT_DIR = ROOT / "result" / "anno_mappings"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Mapping from Rudra src file to (primary_ghidra_file, secondary_ghidra_files)
RS_TO_GHIDRA = {
    "src/ruleaction.rs": (["ruleaction.cc"], ["ruleaction.hh"]),
    "src/coreaction.rs": (["coreaction.cc"], ["coreaction.hh"]),
    "src/block.rs": (["block.cc"], ["block.hh"]),
    "src/blockaction.rs": (["blockaction.cc"], ["blockaction.hh"]),
    "src/unify.rs": (["unify.cc"], ["unify.hh"]),
    "src/typeop.rs": (["typeop.cc"], ["typeop.hh"]),
    "src/op.rs": (["op.cc"], ["op.hh"]),
    "src/double_precis.rs": (["double.cc"], ["double.hh"]),
    "src/jumptable.rs": (["jumptable.cc"], ["jumptable.hh"]),
    "src/varnode.rs": (["varnode.cc"], ["varnode.hh"]),
    "src/address.rs": (["address.cc"], ["address.hh"]),
    "src/space.rs": (["space.cc"], ["space.hh"]),
    "src/marshal.rs": (["marshal.cc"], ["marshal.hh"]),
    "src/prettyprint.rs": (["prettyprint.cc"], ["prettyprint.hh"]),
    "src/printc.rs": (["printc.cc"], ["printc.hh"]),
    "src/printlanguage.rs": (["printlanguage.cc"], ["printlanguage.hh"]),
    "src/subflow.rs": (["subflow.cc"], ["subflow.hh"]),
    "src/fspec.rs": (["fspec.cc"], ["fspec.hh"]),
    "src/database.rs": (["database.cc"], ["database.hh"]),
    "src/funcdata.rs": (["funcdata.cc", "funcdata_op.cc", "funcdata_varnode.cc", "funcdata_block.cc"], ["funcdata.hh"]),
    "src/arch.rs": (["arch.cc"], ["arch.hh"]),
    "src/transform.rs": (["transform.cc"], ["transform.hh"]),
    "src/userop.rs": (["userop.cc"], ["userop.hh"]),
    "src/varmap.rs": (["varmap.cc"], ["varmap.hh"]),
    "src/heritage.rs": (["heritage.cc"], ["heritage.hh"]),
    "src/condexe.rs": (["condexe.cc"], ["condexe.hh"]),
    "src/merge.rs": (["merge.cc"], ["merge.hh"]),
    "src/cover.rs": (["cover.cc"], ["cover.hh"]),
    "src/rangeutil.rs": (["rangeutil.cc"], ["rangeutil.hh"]),
    "src/rangemap.rs": (["rangemap.cc"], ["rangemap.hh"]),
    "src/options.rs": (["options.cc"], ["options.hh"]),
    "src/override_rs.rs": (["override.cc"], ["override.hh"]),
    "src/prefersplit.rs": (["prefersplit.cc"], ["prefersplit.hh"]),
    "src/comment.rs": (["comment.cc"], ["comment.hh"]),
    "src/context.rs": (["globalcontext.cc"], ["globalcontext.hh"]),
    "src/memstate.rs": (["memstate.cc"], ["memstate.hh"]),
    "src/float_emulate.rs": (["float.cc"], ["float.hh"]),
    "src/grammar.rs": (["grammar.cc"], ["grammar.hh"]),
    "src/cpool.rs": (["cpool.cc"], ["cpool.hh"]),
    "src/pcodeparse.rs": (["pcodeparse.cc"], ["pcodeparse.hh"]),
    "src/pcodeinject.rs": (["pcodeinject.cc"], ["pcodeinject.hh"]),
    "src/callgraph.rs": (["callgraph.cc"], ["callgraph.hh"]),
    "src/loadimage.rs": (["loadimage.cc"], ["loadimage.hh"]),
    "src/pcoderaw.cc": (["pcoderaw.cc"], ["pcoderaw.hh"]),
    "src/pcoderaw.rs": (["pcoderaw.cc"], ["pcoderaw.hh"]),
    "src/dynamic.rs": (["dynamic.cc"], ["dynamic.hh"]),
    "src/expression.rs": (["expression.cc"], ["expression.hh"]),
    "src/constseq.rs": (["constseq.cc"], ["constseq.hh"]),
    "src/types.rs": (["type.cc"], ["type.hh"]),
    "src/variable.rs": (["variable.cc"], ["variable.hh"]),
    "src/utils.rs": (["utilities.cc"], ["utilities.hh"]),
    "src/signature.rs": (["signature.cc"], ["signature.hh"]),
    "src/stringmanage.rs": (["stringmanage.cc"], ["stringmanage.hh"]),
    "src/tracedag.rs": (["block.cc"], ["block.hh"]),
    "src/unionresolve.rs": (["unionresolve.cc"], ["unionresolve.hh"]),
    "src/paramid.rs": (["paramid.cc"], ["paramid.hh"]),
    "src/emulate.rs": (["emulate.cc"], ["emulate.hh"]),
    "src/compression.rs": ([], []),  # Rust-specific
    "src/capability.rs": (["capability.cc"], ["capability.hh"]),
    "src/error.rs": ([], []),  # Rust-specific
    "src/opbehavior.rs": (["opbehavior.cc"], ["opbehavior.hh"]),
    "src/opcodes.rs": (["opcodes.cc"], ["opcodes.hh"]),
    "src/ffi.rs": ([], []),  # Rust-specific
    "src/lib.rs": ([], []),
    "src/bin/rudra.rs": ([], []),
    "src/disasm/mod.rs": ([], []),
    "src/binary/mod.rs": ([], []),
    "src/type_system/datatype.rs": (["type.cc"], ["type.hh"]),
    "src/type_system/typefactory.rs": (["type.cc"], ["type.hh"]),
    "src/type_system/protomodel.rs": (["type.cc", "arch.cc"], ["type.hh"]),
    "src/type_system/cast.rs": (["cast.cc", "type.cc"], ["type.hh"]),
    "src/align/address.rs": ([], []),
    "src/align/datatype.rs": ([], []),
    "src/align/function_snapshot.rs": ([], []),
    "src/align/mod.rs": ([], []),
    "src/align/pcodeop.rs": ([], []),
    "src/align/range.rs": ([], []),
    "src/align/runtime_verify.rs": ([], []),
    "src/align/varnode.rs": ([], []),
    "src/analysis/type_infer.rs": ([], []),
}

# Rust fn name -> Ghidra method name mapping (camelCase)
FN_NAME_MAP = {
    "apply_op": "applyOp",
    "apply": "apply",
    "get_name": "getName",
    "get_flags": "getFlags",
    "get_opcodes": "getOpList",
    "new": "new",  # constructor - special handling
    "reset": "reset",
    "perform": "perform",
    "with_flags": "withFlags",
    "add_action": "addAction",
    "add_rule": "addRule",
    "num_actions": "numActions",
    "get_flags_val": "getFlagsVal",
    "get_name_str": "getNameStr",
    "push_or_pull": "pushOrPull",
}


def find_enclosing_struct(lines: list[str], fn_idx: int) -> str | None:
    """Walk upward from fn_idx to find the enclosing `impl ... for X` or `struct X`."""
    i = fn_idx - 1
    while i >= 0:
        line = lines[i]
        # impl Rule for RuleXxx {
        m = re.match(r"^\s*impl\s+(?:\w+\s+for\s+)?(\w+)\s*\{", line)
        if m:
            return m.group(1)
        # impl<T> Rule for RuleXxx<T> {
        m = re.match(r"^\s*impl(?:<[^>]+>)?\s+\w+\s+for\s+(\w+)", line)
        if m:
            return m.group(1)
        # pub struct RuleXxx {
        m = re.match(r"^\s*(?:pub\s+)?struct\s+(\w+)", line)
        if m:
            return m.group(1)
        i -= 1
    return None


def rust_fn_to_ghidra_name(rust_fn: str, struct_name: str | None) -> str | None:
    """Convert Rust fn name to Ghidra method name."""
    if rust_fn in FN_NAME_MAP:
        return FN_NAME_MAP[rust_fn]
    # snake_case → camelCase
    parts = rust_fn.split("_")
    if len(parts) > 1:
        return parts[0] + "".join(p.capitalize() for p in parts[1:])
    return rust_fn


def search_ghidra(cc_files: list[Path], hh_files: list[Path], struct_name: str | None, ghidra_fn: str) -> tuple[str, int] | None:
    """Search for `struct_name::ghidra_fn` or `ghidra_fn` in Ghidra source files.

    Returns (ghidra_file, line_number_1based) or None.
    """
    if not struct_name:
        return None

    # Patterns to try, in order of preference:
    # 1. "StructName::method(" — method definition
    # 2. "StructName::StructName(" — constructor
    # 3. "className StructName::method(" — old-style C++
    # 4. "/// \\class StructName" — class declaration comment
    # 5. "class StructName" — class declaration
    patterns = [
        (rf"\b{re.escape(struct_name)}::{re.escape(ghidra_fn)}\b\s*\(", "method_def"),
        (rf"\b{re.escape(struct_name)}::{re.escape(struct_name)}\b\s*\(", "ctor_def"),
        (rf"\\class\s+{re.escape(struct_name)}\b", "class_decl_comment"),
        (rf"\bclass\s+{re.escape(struct_name)}\b", "class_decl"),
        (rf"\bstruct\s+{re.escape(struct_name)}\b", "struct_decl"),
    ]

    for files in (cc_files, hh_files):
        for f in files:
            if not f.exists():
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            file_lines = text.split("\n")
            for pat, kind in patterns:
                for i, line in enumerate(file_lines):
                    if re.search(pat, line):
                        return (f.name, i + 1)
    return None


def process_file(rs_rel: str, violations: list[dict]) -> list[dict]:
    """Generate annotation mappings for one Rust file."""
    rs_abs = ROOT / rs_rel
    if not rs_abs.exists():
        return []

    ghidra_cfg = RS_TO_GHIDRA.get(rs_rel)
    if not ghidra_cfg:
        # No Ghidra counterpart — all RUDRA-GLUE
        return [
            {
                "rust_line": v["line"],
                "rust_fn": v["fn"],
                "kind": "glue",
                "annotation": f"// RUDRA-GLUE: {rs_rel} helper (no direct Ghidra counterpart)",
            }
            for v in violations
        ]

    cc_names, hh_names = ghidra_cfg
    cc_files = [GHIDRA_CPP / n for n in cc_names]
    hh_files = [GHIDRA_CPP / n for n in hh_names]

    try:
        rs_text = rs_abs.read_text(encoding="utf-8")
    except Exception:
        return []
    rs_lines = rs_text.split("\n")

    mappings = []
    glue_count = 0
    found_count = 0
    for v in violations:
        rl = v["line"]
        rust_fn = v["fn"]
        idx = rl - 1
        if idx < 0 or idx >= len(rs_lines):
            mappings.append({
                "rust_line": rl, "rust_fn": rust_fn, "kind": "glue",
                "annotation": f"// RUDRA-GLUE: {rust_fn} (line out of range)",
            })
            glue_count += 1
            continue

        struct = find_enclosing_struct(rs_lines, idx)
        ghidra_fn = rust_fn_to_ghidra_name(rust_fn, struct)

        result = search_ghidra(cc_files, hh_files, struct, ghidra_fn) if ghidra_fn else None

        if result:
            ghidra_file, ghidra_line = result
            mappings.append({
                "rust_line": rl, "rust_fn": rust_fn, "kind": "ghidra",
                "ghidra_file": ghidra_file, "ghidra_line": ghidra_line,
                "ghidra_fn": f"{struct}::{ghidra_fn}" if struct else ghidra_fn,
            })
            found_count += 1
        else:
            # Fallback: try just the fn name without struct prefix
            result2 = search_ghidra(cc_files, hh_files, None, ghidra_fn) if ghidra_fn else None
            if result2:
                ghidra_file, ghidra_line = result2
                mappings.append({
                    "rust_line": rl, "rust_fn": rust_fn, "kind": "ghidra",
                    "ghidra_file": ghidra_file, "ghidra_line": ghidra_line,
                    "ghidra_fn": ghidra_fn,
                })
                found_count += 1
            else:
                mappings.append({
                    "rust_line": rl, "rust_fn": rust_fn, "kind": "glue",
                    "annotation": f"// RUDRA-GLUE: {rust_fn} (no Ghidra counterpart found)",
                })
                glue_count += 1

    return mappings


def main():
    violations = json.loads((ROOT / "result" / "violations_structured.json").read_text(encoding="utf-8"))
    total_found = 0
    total_glue = 0
    for rs_rel, vios in violations.items():
        mappings = process_file(rs_rel, vios)
        if not mappings:
            continue
        out_path = OUT_DIR / (rs_rel.replace("/", "_").replace(".rs", ".json"))
        out_path.write_text(json.dumps(mappings, indent=2), encoding="utf-8")
        found = sum(1 for m in mappings if m["kind"] == "ghidra")
        glue = sum(1 for m in mappings if m["kind"] == "glue")
        total_found += found
        total_glue += glue
        print(f"{rs_rel:<50} {found:>4} ghidra  {glue:>4} glue  →  {out_path.name}")
    print(f"\nTOTAL: {total_found} ghidra annotations, {total_glue} RUDRA-GLUE")


if __name__ == "__main__":
    main()
