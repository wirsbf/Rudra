#!/usr/bin/env bash
# Verified runner for the locked-oracle OPACTION_DEBUG stage drill
# (tests/oracle/stage_drill_1204.cc).  Mirrors the guard structure of
# tools/run_pipeline_lifecycle_oracle.sh: oracle identity + dirty-tree
# checks, metadata validation, isolated build, run, and output pinning.
# The oracle library is built with -DOPACTION_DEBUG in a stamp-guarded
# git-archive tree (tools/build_stage_drill_oracle.sh); the shared ghidra
# checkout is never built with the debug define.
#
# CLI (batch-driver contract: bash tools/run_<runner>.sh <corpus> <entry> <fn>)
#   run_stage_drill_oracle.sh                          # pinned default:
#   run_stage_drill_oracle.sh curl 4ff0 next_url       #   curl next_url @0x4ff0
#   run_stage_drill_oracle.sh curl 0x25a0 main         # parameterized target
#   run_stage_drill_oracle.sh httpd 0x2b820 main
#
# corpus is curl|httpd -> examples/<corpus>; entry_addr is hex (0x optional).
# The zero-argument / next_url form keeps the legacy fully-pinned mode
# (metadata input pins + expected stdout sha256 + expected_done) and the
# legacy output name next_url.oracle.drill, byte-identical to history.
# Parameterized targets resolve pins from the metadata "functions" map
# (key "<corpus>/<func>", per-function comparand: entry, binary_sha256,
# expected_done, expected_stdout_sha256); a target absent from the map runs
# in capture mode: structural validation only, sha256 + stats reported for
# later pinning.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: tools/run_stage_drill_oracle.sh [corpus entry_addr func_name]
  corpus:      curl | httpd (examples/<corpus> binary)
  entry_addr:  hex entry of the function (0x prefix optional)
  func_name:   BFD symbol name (STAGE_DRILL_FUNC target of the harness)
  no arguments: pinned default capture of curl next_url @0x4ff0
EOF
}

mode=parameterized
corpus=curl
func=next_url
entry=0x4ff0
if [[ $# -eq 0 ]]; then
  mode=default
elif [[ $# -eq 3 ]]; then
  corpus=$1
  entry=$2
  func=$3
else
  usage
  exit 2
fi
case "$corpus" in
  curl|httpd) ;;
  *) echo "unknown corpus: $corpus (expected curl|httpd)" >&2; exit 2 ;;
esac
case "$entry" in
  0x?*|0X?*) entry_digits=${entry:2} ;;
  *) entry_digits=$entry ;;
esac
if [[ "$entry_digits" =~ ^[0-9a-fA-F]+$ ]]; then
  entry_norm=$(printf '0x%x' "$((16#$entry_digits))")
else
  echo "entry_addr is not hexadecimal: $entry" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/stage_drill_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/stage_drill_1204.cc"
build_script="$repo_root/tools/build_stage_drill_oracle.sh"
binary="$repo_root/examples/$corpus"
spec_root="$repo_root/sleigh_specs"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 language source is dirty" >&2
  exit 1
fi

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rugra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUDRA_BFD_INCLUDE" >&2
  exit 1
fi
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$build_script" \
  "$binary" "$spec_root" "$bfd_include/bfd.h" "$bfd_library" \
  "$mode" "$corpus" "$func" "$entry_norm" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    build_script_name,
    binary_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    mode,
    corpus,
    func,
    entry_norm,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {
    "tag": "Ghidra_12.0.4_build",
    "commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler-spec metadata")
if metadata.get("build_flags") != "-DOPACTION_DEBUG":
    raise SystemExit("a drill fixture must record build_flags=-DOPACTION_DEBUG")

def digest(name):
    return hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

comparands = {
    "cpp_fixture": cpp_name,
    "build_script": build_script_name,
}
for key, name in comparands.items():
    actual = digest(name)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"{key} hash mismatch: {actual}")

# Per-function pin lookup (metadata["functions"], key "<corpus>/<func>").
functions = metadata.get("functions", {})
func_entry = functions.get(f"{corpus}/{func}") if mode == "parameterized" else None

shared_assets = {
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": bfd_header_name,
    "bfd_library_sha256": bfd_library_name,
}
binary_pins = {}  # hash -> file to check against
if mode == "default":
    actual_input = json.dumps(
        metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    fingerprint = "sha256:" + hashlib.sha256(actual_input).hexdigest()
    if metadata.get("input_fingerprint") != fingerprint:
        raise SystemExit("input fingerprint mismatch")
    shared_assets["binary_sha256"] = binary_name
elif func_entry is not None:
    pinned_entry = func_entry.get("entry", "")
    normalize = lambda s: s.lower().removeprefix("0x").lstrip("0") or "0"
    if normalize(pinned_entry) != normalize(entry_norm):
        raise SystemExit(
            f"functions[{corpus}/{func}] entry pin mismatch: {pinned_entry} vs {entry_norm}"
        )
    if "binary_sha256" in func_entry:
        binary_pins[func_entry["binary_sha256"]] = binary_name
    elif corpus == "curl":
        # examples/curl is already pinned by the top-level assets block.
        shared_assets["binary_sha256"] = binary_name
    # corpus binary without any pin (fresh httpd target): capture mode for
    # the binary asset, reported by the post-run block.
else:
    if corpus == "curl":
        shared_assets["binary_sha256"] = binary_name
for expected, name in binary_pins.items():
    actual = digest(name)
    if actual != expected:
        raise SystemExit(f"{corpus}/{func} binary_sha256 mismatch: {actual}")
for key, name in shared_assets.items():
    actual = digest(name)
    if metadata["assets"].get(key) != actual:
        raise SystemExit(f"{key} mismatch: {actual}")
compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
PY

bash "$build_script"
drill_bin=${RUDRA_DRILL_WORKROOT:-/dev/shm/rugra-tests/sb-drill/build}/stage_drill_1204
if [[ ! -x "$drill_bin" ]]; then
  echo "drill binary not found after build: $drill_bin" >&2
  exit 1
fi

# Determinism control (root-caused 2026-09-22): the recorded per-application
# DEBUG stream depends on the oracle process's early heap allocation
# sequence, which two levers demonstrably flip:
#   - argv path form: relative vs absolute spec/binary paths shift the
#     harness's std::string allocations and flip the pointer-keyed iteration
#     order inside the oracle (next_url: records=1019 with relative argv,
#     records=1014 with absolute argv, both individually deterministic);
#   - ASLR: with randomization on, large functions (curl main) produce a
#     different stream almost every run (4744/4745/4762/4763 records in four
#     same-input runs).
# Canonical capture recipe, fixed for every pin this runner makes:
#   cwd=repo_root, argv=sleigh_specs examples/<corpus> (relative),
#   env=`env -i` + STAGE_DRILL_FUNC/STAGE_DRILL_ADDR only, ASLR off via
#   `setarch -R`.  This reproduces the historical next_url pin b227ae94...
#   byte-identically, and keeps every capture independent of the caller's
#   environment.  (Environment size itself is irrelevant: an env -i run
#   with a 24-byte padding var reproduces the same hash.)
if ! command -v setarch >/dev/null 2>&1; then
  echo "setarch not found: drill captures require ASLR-disabled execution" >&2
  exit 1
fi

oracle_tmp=$(mktemp -d /tmp/rugra-stage-drill-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-stage-drill-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Canonical recipe: repo-root cwd + relative argv + scrubbed env + ASLR
# off (see the determinism note above).  The mktemp scratch path stays
# absolute and never enters the drill's argv.
cd "$repo_root"
if ! setarch "$(uname -m)" -R env -i \
  STAGE_DRILL_FUNC="$func" STAGE_DRILL_ADDR="$entry_norm" \
  "$drill_bin" sleigh_specs "examples/$corpus" \
  >"$oracle_tmp/stage_drill.stdout" 2>"$oracle_tmp/stage_drill.stderr"; then
  cat "$oracle_tmp/stage_drill.stderr" >&2
  exit 1
fi

if ! python3 -I -S - "$metadata" "$oracle_tmp/stage_drill.stdout" \
  "$mode" "$corpus" "$func" "$entry_norm" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout_path = pathlib.Path(sys.argv[2])
mode, corpus, func, entry_norm = sys.argv[3:]
text = stdout_path.read_text(encoding="utf-8")
actual = hashlib.sha256(stdout_path.read_bytes()).hexdigest()

def norm(s):
    return s.lower().removeprefix("0x").lstrip("0") or "0"

lines = text.splitlines()
meta_line = lines[0] if lines and lines[0].startswith("META ") else ""
for token in ("build_flags=OPACTION_DEBUG", "oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b"):
    if token not in meta_line:
        raise SystemExit(f"META line missing {token}")
meta = dict(item.split("=", 1) for item in meta_line.split()[1:])
if meta.get("func") != func or norm(meta.get("entry", "")) != norm(entry_norm):
    raise SystemExit(
        f"META target drifted: func={meta.get('func')} entry={meta.get('entry')}"
        f" (requested {func} {entry_norm})"
    )

func_entry = metadata.get("functions", {}).get(f"{corpus}/{func}") \
    if mode == "parameterized" else None
if mode == "default":
    expected = metadata["expected_stdout_sha256"]["ghidra"]
    if actual != expected:
        raise SystemExit(f"drill stdout drifted: sha256={actual}")
elif func_entry is not None:
    expected = func_entry.get("expected_stdout_sha256")
    if expected is not None and actual != expected:
        raise SystemExit(f"{corpus}/{func} drill stdout drifted: sha256={actual}")

done_line = [line for line in lines if line.startswith("@DONE ")]
if len(done_line) != 1:
    raise SystemExit("expected exactly one @DONE line")
done = dict(item.split("=", 1) for item in done_line[0].split()[1:])
expected_done = metadata["observation"]["expected_done"] if mode == "default" \
    else (func_entry or {}).get("expected_done", {})
for key, value in expected_done.items():
    if done.get(key) != str(value):
        raise SystemExit(f"@DONE {key} drifted: {done.get(key)} (pinned {value})")
seqs = [
    int(line.split()[1].rstrip(":"))
    for line in lines
    if line.startswith("DEBUG ")
]
if seqs != list(range(len(seqs))):
    raise SystemExit("native DEBUG seq is not strictly 0..N-1")
if len(seqs) != int(done["records"]) or len(seqs) != int(done["opactdbg_final"]):
    raise SystemExit("record count / opactdbg_final disagree with DEBUG headers")
pin_state = "pinned" if (mode == "default" or func_entry is not None) else "capture(unpinned)"
print(f"target={corpus}/{func} entry={entry_norm} mode={pin_state} sha256={actual}")
print(f"records={done['records']} opactdbg_final={done['opactdbg_final']} "
      f"applications={done['applications']} perform_calls={done['perform_calls']} "
      f"final_return={done['final_return']} nodes={done['nodes']}")
PY
then
  # A drift must be investigable: preserve the offending stdout (and the
  # @DONE stats it produced) before the EXIT trap wipes the scratch dir.
  drift_dir=/dev/shm/rugra-tests/sb-drill/drift
  mkdir -p "$drift_dir"
  drift_tag=$(date +%Y%m%d_%H%M%S)
  cp "$oracle_tmp/stage_drill.stdout" "$drift_dir/${corpus}.${func}.${drift_tag}.drill"
  cp "$oracle_tmp/stage_drill.stderr" "$drift_dir/${corpus}.${func}.${drift_tag}.stderr"
  grep '^@DONE ' "$oracle_tmp/stage_drill.stdout" >&2 || true
  echo "drift artifacts preserved in $drift_dir/${corpus}.${func}.${drift_tag}.*" >&2
  exit 1
fi

if [[ -d /dev/shm/rugra-tests/sb-drill ]]; then
  if [[ "$mode" == "default" ]]; then
    cp "$oracle_tmp/stage_drill.stdout" /dev/shm/rugra-tests/sb-drill/next_url.oracle.drill
  else
    cp "$oracle_tmp/stage_drill.stdout" \
      "/dev/shm/rugra-tests/sb-drill/${corpus}.${func}.oracle.drill"
  fi
fi
printf 'stage_drill_1204: raw oracle capture verified (%s %s @%s)\n' \
  "$corpus" "$func" "$entry_norm"
