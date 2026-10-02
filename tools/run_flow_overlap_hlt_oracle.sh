#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=4356e6d5ea31a47859961355794ccfec1cb738bb
rudra_base_tree=$(git -C "$repo_root" rev-parse "${rudra_base_commit}^{tree}")
rudra_base_src_tree=$(git -C "$repo_root" rev-parse "${rudra_base_commit}:src")
rudra_cargo_toml_blob=$(git -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.toml")
rudra_cargo_lock_blob=$(git -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.lock")
rudra_build_rs_blob=$(git -C "$repo_root" rev-parse "${rudra_base_commit}:build.rs")
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$repo_root/sleigh_specs"
metadata="$repo_root/tests/oracle/flow_overlap_hlt_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/flow_overlap_hlt_1204.cc"
rust_fixture="$repo_root/tests/oracle/flow_overlap_hlt_1204.rs"
runner="$repo_root/tools/run_flow_overlap_hlt_oracle.sh"

# No src overlays: the seam adjudication found Rudra's flow code already
# matches the locked oracle in both data environments (unmarked fall-through
# AND analyzer-marked halt); the fixture pins that parity without src edits.
overlay_paths=()

run_cache=${RUDRA_FLOW_OVERLAP_HLT_RUN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-overlap-hlt-1204}
cargo_target=${RUDRA_FLOW_OVERLAP_HLT_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-overlap-hlt-target}
cargo_tmp=${RUDRA_FLOW_OVERLAP_HLT_TMP_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-overlap-hlt-tmp}
mkdir -p "$run_cache" "$cargo_target" "$cargo_tmp"
oracle_tmp=$(mktemp -d "$run_cache/run.XXXXXX")
cleanup() {
  if [[ ${RUDRA_FLOW_OVERLAP_HLT_KEEP:-0} == 1 ]]; then
    echo "keeping oracle workdir: $oracle_tmp" >&2
    return 0
  fi
  case "$oracle_tmp" in
    "$run_cache"/run.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
for relative in "${overlay_paths[@]}"; do
  required="$repo_root/$relative"
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "source overlay is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra source has staged changes" >&2
  exit 1
fi

# Locked binutils 2.38 BFD build (same pins as run_flow_tailcall_overtrace_oracle.sh).
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e
bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" ]]; then
  for candidate in /tmp/rudra-ghidra-bfd-2.38/usr/include /usr/include; do
    if [[ -f "$candidate/bfd.h" ]] && \
        [[ "$(sha256sum "$candidate/bfd.h" | awk '{print $1}')" == "$bfd_header_sha256" ]]; then
      bfd_include=$candidate
      break
    fi
  done
fi
bfd_library=${RUDRA_BFD_LIBRARY:-}
if [[ -z "$bfd_library" ]]; then
  for candidate in \
    /tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
    /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so; do
    if [[ -f "$candidate" ]] && \
        [[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$bfd_library_sha256" ]]; then
      bfd_library=$candidate
      break
    fi
  done
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" || \
      -z "$bfd_library" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD development files are unavailable" >&2
  exit 1
fi

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$rudra_cargo_toml_blob" \
  "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" \
  "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob,
    build_rs_blob, *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "FLOW-OVERLAP-HLT-1204")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("status_note must be a non-empty string")
decisive = metadata.get("decisive_semantics")
expected_decisive = {
    "reference_output_parameters", "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle", "sorting_comparison_keys",
}
if not isinstance(decisive, dict):
    raise SystemExit("decisive_semantics must be an object")
require("decisive semantic classes", set(decisive), expected_decisive)
for key, value in decisive.items():
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"decisive_semantics.{key} must be non-empty")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default (locked fixture binary: gcc -fno-pie naked-function probes; SLEIGH x86-64 via sleigh_specs on both sides)")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")
source = metadata["rugra_source"]
for label, actual, expected in (
    ("base commit", source["base_commit"], base_commit),
    ("base tree", source["base_tree"], base_tree),
    ("base src tree", source["base_src_tree"], base_src_tree),
    ("Cargo.toml blob", source["base_blobs"]["Cargo.toml"], cargo_toml_blob),
    ("Cargo.lock blob", source["base_blobs"]["Cargo.lock"], cargo_lock_blob),
    ("build.rs blob", source["base_blobs"]["build.rs"], build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
overlays = source["overlays"]
require("overlay paths", set(overlays), set(overlay_paths))
for relative in overlay_paths:
    expected = overlays[relative]
    require(f"{relative} live sha", sha((repo / relative).read_bytes()), expected)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])

require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MATCH")
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
for key, record in coverage.items():
    if not isinstance(record, dict):
        raise SystemExit(f"coverage.{key} must be an object")
    require(
        f"coverage.{key} fields",
        set(record),
        {"status", "covers", "residual_todo_ids"},
    )
    status = record["status"]
    if status not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {status!r}")
    residual_ids = record["residual_todo_ids"]
    if not isinstance(residual_ids, list) or any(
        not isinstance(item, str) or not item for item in residual_ids
    ):
        raise SystemExit(f"coverage.{key}.residual_todo_ids is invalid")
    if len(residual_ids) != len(set(residual_ids)):
        raise SystemExit(f"coverage.{key}.residual_todo_ids contains duplicates")
    if status == "MATCH":
        require(f"coverage.{key} MATCH residuals", residual_ids, [])
    elif not residual_ids:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
    coverage_residual_ids.update(residual_ids)
for key in coverage:
    require(f"coverage.{key}.status", coverage[key]["status"], "MATCH")
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list):
    raise SystemExit("top-level residual_todo_ids must be a list")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
require("top-level residual ids", top_residual_ids, [])
observations = metadata.get("out_of_scope_observations")
if not isinstance(observations, list):
    raise SystemExit("out_of_scope_observations must be a list")
for observation in observations:
    if not isinstance(observation, dict):
        raise SystemExit("out_of_scope_observations entries must be objects")
    require(f"observation {observation.get('id')!r} fields", set(observation), {"id", "note"})
    if not observation["id"] or not observation["note"]:
        raise SystemExit("out_of_scope_observations entries must be non-empty")
PY

if [[ ${RUDRA_FLOW_OVERLAP_HLT_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "flow_overlap_hlt_1204 metadata/source lock validation passed"
  exit 0
fi

# ---- Ghidra oracle side ----------------------------------------------------
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
TMPDIR="$cargo_tmp" make --silent -C "$cpp_root" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
TMPDIR="$cargo_tmp" g++ -std=c++11 -O2 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  -Wl,--whole-archive "$cpp_root/libdecomp.a" \
  -Wl,--no-whole-archive "$bfd_library" -lz \
  -o "$oracle_tmp/flow_overlap_hlt_cpp"

bfd_runtime=$(dirname "$bfd_library")
if [[ -n ${LD_LIBRARY_PATH:-} ]]; then
  bfd_runtime="$bfd_runtime:$LD_LIBRARY_PATH"
fi
LD_LIBRARY_PATH="$bfd_runtime" \
  "$oracle_tmp/flow_overlap_hlt_cpp" "$spec_root" \
  "$oracle_tmp/flow_overlap_hlt_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra oracle produced unexpected stderr" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/flow_overlap_hlt_cpp"
fixture_text_base=$(readelf -WS "$oracle_tmp/flow_overlap_hlt_cpp" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
sym_addr() {
  # Drain the full nm listing (no early awk exit: set -o pipefail would
  # otherwise fail the pipeline on nm's SIGPIPE).
  nm -S --defined-only "$oracle_tmp/flow_overlap_hlt_cpp" | \
    awk -v sym="$1" '$4 == sym && addr == "" { addr = $1 } END { if (addr != "") print "0x" addr }'
}
sym_size() {
  nm -S --defined-only "$oracle_tmp/flow_overlap_hlt_cpp" | \
    awk -v sym="$1" '$4 == sym && size == "" { size = $2 } END { if (size != "") print "0x" size }'
}
plain_callee_sym=$(sym_addr ohlt_callee_plain)
marked_callee_sym=$(sym_addr ohlt_callee_marked)
plain_user_addr=$(sym_addr ohlt_user_plain)
plain_user_size=$(sym_size ohlt_user_plain)
marked_user_addr=$(sym_addr ohlt_user_marked)
marked_user_size=$(sym_size ohlt_user_marked)
if [[ -z "$fixture_text_base" || -z "$plain_callee_sym" || -z "$marked_callee_sym" || \
      -z "$plain_user_addr" || -z "$plain_user_size" || \
      -z "$marked_user_addr" || -z "$marked_user_size" ]]; then
  echo "failed to resolve fixture text or symbols" >&2
  exit 1
fi

# ---- Rudra side: pinned base snapshot (no src overlays) --------------------
snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/flow_overlap_hlt_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/flow_overlap_hlt_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/flow_overlap_hlt_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_flow_overlap_hlt_oracle.sh"
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
ln -s "$ghidra_root" "$snapshot_root/ghidra"

if ! /usr/bin/flock -x /tmp/rudra-flow-overlap-hlt-cargo.lock env \
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" TMPDIR="$cargo_tmp" \
  timeout 600 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib; then
  exit 1
fi
TMPDIR="$cargo_tmp" rustc --edition=2021 -O \
  "$snapshot_root/tests/oracle/flow_overlap_hlt_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$oracle_tmp/flow_overlap_hlt_rust"

# Run from the repo root: the SLEIGH translator resolves its x86-64.pspec
# relative to the process working directory.
(
  cd "$repo_root"
  "$oracle_tmp/flow_overlap_hlt_rust" \
    "$oracle_tmp/fixture.text" "$fixture_text_base" \
    "$plain_user_addr" "$plain_user_size" \
    "$marked_user_addr" "$marked_user_size" \
    "$plain_callee_sym" "$marked_callee_sym" \
    >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
)
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture produced unexpected stderr" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

set +e
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/raw.diff" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_bytes()
rudra_stdout = pathlib.Path(sys.argv[3]).read_bytes()
raw_diff = pathlib.Path(sys.argv[4]).read_bytes()
diff_status = int(sys.argv[5])
expected = metadata["expected_results"]
for key, actual in (
    ("ghidra_stdout_sha256", hashlib.sha256(ghidra_stdout).hexdigest()),
    ("rudra_stdout_sha256", hashlib.sha256(rudra_stdout).hexdigest()),
    ("raw_diff_sha256", hashlib.sha256(raw_diff).hexdigest()),
):
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
if diff_status != expected["diff_exit_code"]:
    raise SystemExit(f"diff exit mismatch: {diff_status}")

lines = ghidra_stdout.decode("utf-8").splitlines()
expected_cases = ["ohlt_user_plain", "ohlt_user_marked"]
actual_cases = [line.split("=", 1)[1] for line in lines if line.startswith("case=")]
if actual_cases != expected_cases:
    raise SystemExit(f"fixture case order mismatch: {actual_cases}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'flow_overlap_hlt_1204: covered_projection=2/2 projection_status=MATCH overall_status=MATCH\n'
