#!/usr/bin/env bash
set -euo pipefail

# MINIMALMASK-LADDER-CONSUMERS-0001: locked 12.0.4 differential runner.
#
# Bilateral fixture for the minimalmask whole-byte ladder (address.hh:525-534)
# and its three production consumers:
#   ActionDeadCode::markConsumedParameters (coreaction.cc:3840),
#   ActionDeadCode::gatherConsumedReturn    (coreaction.cc:3871),
#   JumpTable::foldInNormalization          (jumptable.cc:2574).
#
# The Rust comparand is built from a pinned base-commit snapshot with the
# behavior-relevant src files overlaid live and a visibility-only transform
# (mark_consumed_parameters/gather_consumed_return made pub in the snapshot,
# never in the live tree — the action_deadcode_selfloop precedent). The
# oracle side compiles the .cc fixture against the locked tree's libdecomp.a
# via #define private/protected public, so no oracle source is modified.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_base_sleigh_tree=c7729d9d1554dc62c486bcd7d58fdbf44bebb97d
rudra_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5

ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/minimalmask_ladder_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/minimalmask_ladder_1204.cc"
rust_fixture="$repo_root/tests/oracle/minimalmask_ladder_1204.rs"
runner="$repo_root/tools/run_minimalmask_ladder_oracle.sh"
address_overlay="$repo_root/src/address.rs"
coreaction_overlay="$repo_root/src/coreaction.rs"
jumptable_overlay="$repo_root/src/jumptable.rs"
varnode_overlay="$repo_root/src/varnode.rs"
funcdata_overlay="$repo_root/src/funcdata.rs"
fspec_overlay="$repo_root/src/fspec.rs"

overlays=("$address_overlay" "$coreaction_overlay" "$jumptable_overlay" \
  "$varnode_overlay" "$funcdata_overlay" "$fspec_overlay")

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" "${overlays[@]}"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_base_commit^{commit}:$rudra_base_commit" \
  "$rudra_base_commit^{tree}:$rudra_base_tree" \
  "$rudra_base_commit:src:$rudra_base_src_tree" \
  "$rudra_base_commit:sleigh_shim:$rudra_base_sleigh_tree" \
  "$rudra_base_commit:Cargo.toml:$rudra_cargo_toml_blob" \
  "$rudra_base_commit:Cargo.lock:$rudra_cargo_lock_blob" \
  "$rudra_base_commit:build.rs:$rudra_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra base identity mismatch: $expression" >&2
    exit 1
  fi
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$address_overlay" "$coreaction_overlay" "$jumptable_overlay" \
  "$varnode_overlay" "$funcdata_overlay" "$fspec_overlay" \
  "$runner_sha" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, address_raw, coreaction_raw,
    jumptable_raw, varnode_raw, funcdata_raw, fspec_raw, runner_sha,
) = sys.argv[1:]

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

data = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", data["schema_version"], 2)
require("fixture", data["fixture_id"], "MINIMALMASK-LADDER-CONSUMERS-0001")
require("overall", data["overall_status"], "MATCH")
comparand = data["comparand"]
for key, path in (
    ("cpp_fixture_sha256", cpp_raw),
    ("rust_fixture_sha256", rust_raw),
    ("address_overlay_sha256", address_raw),
    ("coreaction_overlay_sha256", coreaction_raw),
    ("jumptable_overlay_sha256", jumptable_raw),
    ("varnode_overlay_sha256", varnode_raw),
    ("funcdata_overlay_sha256", funcdata_raw),
    ("fspec_overlay_sha256", fspec_raw),
):
    require(key, sha(path), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
require(
    "decisive classes", set(data["decisive_semantics"]),
    {"reference_output_parameters", "loop_bounds_traversal_order",
     "counter_accumulator_lifecycle", "sorting_comparison_keys"},
)
expected_coverage = {
    "ladder": "MATCH",
    "callparams_nominal": "MATCH",
    "callparams_bytesgate": "MATCH",
    "callparams_autolive": "MATCH",
    "callparams_inputlock": "MATCH",
    "returns_basic": "MATCH",
    "returns_bytes": "MATCH",
    "returns_outputlock": "MATCH",
    "foldin_gate_forms": "MATCH",
}
require("coverage keys", set(data["coverage"]), set(expected_coverage))
for name, status in expected_coverage.items():
    record = data["coverage"][name]
    require(f"coverage {name}", record["status"], status)
    require(f"coverage {name} residuals", record["residual_todo_ids"], [])
require("top-level residuals", data["residual_todo_ids"], [])
fingerprinted = {
    "architecture": data["architecture"],
    "compiler_spec": data["compiler_spec"],
    "analysis_options": data["analysis_options"],
    "cases": data["input_manifest"]["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", hashlib.sha256(canonical).hexdigest(),
        data["input_manifest"]["sha256"])
PY

oracle_tmp=$(mktemp -d /tmp/rudra-minimalmask-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-minimalmask-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unexpected cleanup path: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

snapshot="$oracle_tmp/workspace"
mkdir -p "$snapshot/tests/oracle"
git -C "$repo_root" archive --format=tar --output="$oracle_tmp/rudra.tar" \
  "$rudra_base_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs src sleigh_shim crates
tar -xf "$oracle_tmp/rudra.tar" -C "$snapshot"
cp "$address_overlay" "$snapshot/src/address.rs"
cp "$coreaction_overlay" "$snapshot/src/coreaction.rs"
cp "$jumptable_overlay" "$snapshot/src/jumptable.rs"
cp "$varnode_overlay" "$snapshot/src/varnode.rs"
cp "$funcdata_overlay" "$snapshot/src/funcdata.rs"
cp "$fspec_overlay" "$snapshot/src/fspec.rs"
cp "$rust_fixture" "$snapshot/tests/oracle/minimalmask_ladder_1204.rs"
# build.rs requires a ghidra tree next to the crate; symlink the locked tree
# (the standard worktree convention — never a copy).
mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$cpp_root" "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

# Visibility-only transform in the isolated snapshot (never the live tree):
# mark_consumed_parameters/gather_consumed_return mirror the private static
# members ActionDeadCode::markConsumedParameters/gatherConsumedReturn
# (coreaction.hh:556-557) that the .cc fixture reaches via
# #define private public.
python3 -I -S - "$snapshot/src/coreaction.rs" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
text = path.read_text(encoding="utf-8")
for needle in (
    "    fn mark_consumed_parameters(\n",
    "    fn gather_consumed_return(fd: &Funcdata)",
):
    if text.count(needle) != 1:
        raise SystemExit(f"visibility transform anchor drifted: {needle.strip()!r}")
    text = text.replace(needle, needle.replace("fn ", "pub fn "))
path.write_text(text, encoding="utf-8")
transform = (
    "ActionDeadCode::mark_consumed_parameters and "
    "ActionDeadCode::gather_consumed_return made public in isolated snapshot only\n"
).encode()
expected = metadata["comparand"]["rust_visibility_transform_sha256"]
actual = hashlib.sha256(transform).hexdigest()
if expected.startswith("PENDING_"):
    raise SystemExit(f"visibility transform hash pending: {actual}")
if expected != actual:
    raise SystemExit(f"visibility transform mismatch: {expected} != {actual}")
PY

# Oracle side: reuse the prebuilt libdecomp.a from the locked tree.
if [[ ! -f "$cpp_root/libdecomp.a" ]]; then
  jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
  make --silent -C "$cpp_root" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
fi
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$cpp_root" "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp_root/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/minimalmask_ladder_cpp"

flock /tmp/rudra-cargo-build.lock -c \
  "CARGO_TARGET_DIR=/tmp/rudra-target-minimalmask cargo build --offline --locked --quiet --manifest-path '$snapshot/Cargo.toml' --lib"
native_archive=$(find /tmp/rudra-target-minimalmask/debug/build -path '*/out/librudra_sleigh.a' -type f | head -1)
if [[ -z "$native_archive" ]]; then
  echo "sleigh native archive missing from cargo target" >&2
  exit 1
fi
native_dir=$(dirname "$native_archive")
rustc --edition=2021 -O \
  -L dependency=/tmp/rudra-target-minimalmask/debug/deps \
  -L native="$native_dir" \
  --extern rudra=/tmp/rudra-target-minimalmask/debug/librudra.rlib \
  "$snapshot/tests/oracle/minimalmask_ladder_1204.rs" \
  -o "$oracle_tmp/minimalmask_ladder_rust"

set +e
"$oracle_tmp/minimalmask_ladder_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/minimalmask_ladder_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
cmp -s "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
stdout_cmp=$?
cmp -s "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr"
stderr_cmp=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/rudra.stderr" "$ghidra_status" "$rudra_status" \
  "$stdout_cmp" "$stderr_cmp" <<'PY'
import hashlib
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
}
expected = data["expected_results"]
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[6])),
    ("rugra_exit_code", int(sys.argv[7])),
    ("stdout_cmp_exit_code", int(sys.argv[8])),
    ("stderr_cmp_exit_code", int(sys.argv[9])),
):
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
lines = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
cases = [line[len("case "):] for line in lines if line.startswith("case ")]
if cases != [
    "ladder", "callparams_nominal", "callparams_bytesgate", "callparams_autolive",
    "callparams_inputlock", "returns_basic", "returns_bytes", "returns_outputlock",
    "foldin",
]:
    raise SystemExit(f"fixture case order drifted: {cases}")
if len(lines) != 55:
    raise SystemExit(f"fixture line count drifted: {len(lines)}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'minimalmask_ladder_1204: MATCH stdout_sha256=%s stderr_sha256=%s\n' \
  "$(sha256sum "$oracle_tmp/ghidra.stdout" | awk '{print $1}')" \
  "$(sha256sum "$oracle_tmp/ghidra.stderr" | awk '{print $1}')"
