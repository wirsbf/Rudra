"""Batch-apply annotation mappings to all Rudra src/*.rs files."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPLY = ROOT / ".zcode" / "apply_annotations.py"
MAPPING_DIR = ROOT / "result" / "anno_mappings"

if not APPLY.exists():
    print(f"ERROR: {APPLY} not found")
    sys.exit(1)

mappings = sorted(MAPPING_DIR.glob("*.json"))
print(f"Found {len(mappings)} mapping files")

for mp in mappings:
    # Derive rs path from mapping filename: src_foo_bar.json → src/foo/bar.rs
    stem = mp.stem  # e.g. "src_foo_bar"
    # Reverse-encode: src_X_Y → src/X/Y.rs
    parts = stem.split("_")
    if not parts or parts[0] != "src":
        print(f"SKIP {mp.name}: not a src/ mapping")
        continue
    rs_rel_parts = parts[1:]
    # Last part might be the filename without .rs
    rs_rel = "src/" + "/".join(rs_rel_parts) + ".rs"
    rs_abs = ROOT / rs_rel
    if not rs_abs.exists():
        print(f"SKIP {mp.name}: {rs_abs} does not exist")
        continue
    print(f"APPLY {mp.name} → {rs_rel}")
    result = subprocess.run(
        ["python", str(APPLY), str(rs_abs), str(mp)],
        capture_output=True, text=True, cwd=str(ROOT)
    )
    if result.returncode != 0:
        print(f"  FAILED:")
        print(result.stdout[-500:])
        print(result.stderr[-500:])
    else:
        print(f"  {result.stdout.strip()}")
