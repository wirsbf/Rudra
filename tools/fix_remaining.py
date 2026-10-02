"""Fix remaining 108 violations: apply RUDRA-GLUE to Rust-specific files and
re-match float_emulate/heritage with better heuristics."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APPLY = ROOT / ".zcode" / "apply_annotations.py"

# Direct file → mapping-name pairs (bypass filename decoding)
REMAINING = [
    ("src/align/function_snapshot.rs", "src_align_function_snapshot.json"),
    ("src/align/runtime_verify.rs", "src_align_runtime_verify.json"),
    ("src/disasm/x86_64.rs", "src_disasm_x86_64.json"),  # may not exist, skip if so
    ("src/disasm/x86_lift.rs", "src_disasm_x86_lift.json"),
    ("src/analysis/type_infer.rs", "src_analysis_type_infer.json"),
    ("src/float_emulate.rs", "src_float_emulate.json"),
    ("src/heritage.rs", "src_heritage.json"),
]

for rs_rel, json_name in REMAINING:
    rs_abs = ROOT / rs_rel
    json_abs = ROOT / "result" / "anno_mappings" / json_name
    if not rs_abs.exists():
        print(f"SKIP {rs_rel}: file missing")
        continue
    if not json_abs.exists():
        print(f"SKIP {rs_rel}: mapping {json_name} missing")
        continue
    print(f"APPLY {rs_rel}")
    result = subprocess.run(
        ["python", str(APPLY), str(rs_abs), str(json_abs)],
        capture_output=True, text=True, cwd=str(ROOT)
    )
    print(f"  {result.stdout.strip()}")
    if result.returncode != 0:
        print(f"  STDERR: {result.stderr[-300:]}")
