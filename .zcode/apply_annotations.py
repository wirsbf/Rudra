#!/usr/bin/env python3
"""Apply Ghidra annotations from a JSON mapping to a Rust source file.

Reads a JSON array of {rust_line, rust_fn, annotation, kind} entries and
inserts the annotation line directly above each fn's definition line.

Processes from BOTTOM to TOP so line numbers in the mapping (which refer to
the ORIGINAL file) stay valid as we insert lines above.

The annotation is placed immediately above the fn line but BELOW any
`#[attribute]` lines that sit directly on top of the fn. If there is an
existing `///` doc-comment block, the annotation goes ABOVE the doc block
(so the Ghidra reference is the first thing seen).

Usage:
    python apply_annotations.py <rust_file> <json_map>
"""
from __future__ import annotations
import json, sys
from pathlib import Path

def main() -> int:
    rs_path = Path(sys.argv[1])
    map_path = Path(sys.argv[2])
    entries = json.loads(map_path.read_text(encoding="utf-8"))
    lines = rs_path.read_text(encoding="utf-8").split("\n")
    # lines is 0-indexed; mapping rust_line is 1-based.

    # Validate: every entry's rust_line should currently be a fn def whose
    # name contains the rust_fn (loose check).
    problems = []
    seen_lines = set()
    for e in entries:
        rl = e["rust_line"]
        if rl in seen_lines:
            problems.append(f"DUP rust_line {rl} ({e['rust_fn']})")
        seen_lines.add(rl)
        idx = rl - 1
        if idx < 0 or idx >= len(lines):
            problems.append(f"rust_line {rl} out of range (file has {len(lines)} lines)")
            continue
        actual = lines[idx]
        if "fn " + e["rust_fn"] not in actual and not actual.strip().endswith(e["rust_fn"] + "(") and e["rust_fn"] not in actual:
            problems.append(f"L{rl}: expected fn {e['rust_fn']!r}, got: {actual!r}")
    if problems:
        print("VALIDATION PROBLEMS (aborting, no write):")
        for p in problems[:50]:
            print("  ", p)
        print(f"  total {len(problems)} problems")
        return 1

    # Sort descending by rust_line so insertions don't shift later (higher) lines.
    entries_sorted = sorted(entries, key=lambda e: e["rust_line"], reverse=True)

    inserted = 0
    skipped_existing = 0
    for e in entries_sorted:
        rl = e["rust_line"]
        idx = rl - 1  # 0-based index of the fn line
        ann = e["annotation"] if e["kind"] == "glue" else (
            f"// Ghidra: {e['ghidra_file']}:{e['ghidra_line']} {e['ghidra_fn']}")
        # Walk upward to find the insertion point: skip attributes (#[...])
        # that sit directly above the fn, AND skip blank lines, to find the
        # first line of the contiguous block above the fn. We insert the
        # annotation just above that block's first line ONLY IF the block
        # doesn't already contain a Ghidra/GLUE annotation.
        j = idx - 1
        # First, skip blank lines and attributes directly above fn
        attr_start = idx
        while j >= 0:
            s = lines[j].strip()
            if s == "":
                j -= 1
                continue
            if s.startswith("#["):
                attr_start = j
                j -= 1
                continue
            break
        # j now points at the first non-blank non-attribute line above fn (or -1)
        # Walk up through the contiguous comment block to see if it already has
        # a Ghidra/GLUE annotation, and find the block's top.
        has_ghidra = False
        block_top = attr_start  # default: insert right above attributes
        k = j
        while k >= 0:
            s = lines[k].strip()
            if s.startswith("//"):
                if "Ghidra:" in s or "RUDRA-GLUE:" in s:
                    has_ghidra = True
                block_top = k
                k -= 1
                continue
            break
        if has_ghidra:
            skipped_existing += 1
            continue
        # Determine indentation: match the fn line's indentation.
        fn_line = lines[idx]
        indent = fn_line[:len(fn_line) - len(fn_line.lstrip())]
        ann_line = indent + ann
        # Insert above block_top (the first line of the comment block, or
        # above the attributes if no comment block).
        lines.insert(block_top, ann_line)
        inserted += 1

    rs_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Inserted {inserted} annotations, skipped {skipped_existing} already-annotated")
    return 0

if __name__ == "__main__":
    sys.exit(main())
