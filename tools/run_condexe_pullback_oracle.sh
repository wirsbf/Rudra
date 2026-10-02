#!/usr/bin/env bash
# CONDEXE-PULLBACK-0005 — locked Ghidra 12.0.4 oracle gate for
# ConditionalExecution::pullbackOp storage/insert-position semantics
# (condexe.cc:160-190) and its testOpRead admission gate (condexe.cc:107-142).
# Pin-base schema2, modeled on tools/run_condexe_trueout_oracle.sh with these
# deltas: base is the trueout-integration commit (0d9f8a1, which already
# carries the purely positional getTrueOut/getFalseOut semantics), so the only
# source overlay is src/condexe.rs itself; no BFD, no loader binary, no SLEIGH
# assets (the fixture uses a synthetic FixtureArchitecture and an empty
# spec-path startDecompilerLibrary).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=0d9f8a12c16a68b6a6cb265861a79356dcf4c6e8
rudra_source_tree=b3fb98b80cd18018fc4aef35c9257fec8784ce47
rudra_source_src_tree=ebfca01131df49511d48eabd7549512e13ab1612
rudra_condexe_blob=4ac080386a5f185ec65ff65f30829276775e60e0
rudra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/condexe_pullback_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/condexe_pullback_1204.cc"
rust_fixture="$repo_root/tests/oracle/condexe_pullback_1204.rs"
condexe_overlay="$repo_root/src/condexe.rs"
runner="$repo_root/tools/run_condexe_pullback_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rudra-condexe-pullback-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-condexe-pullback-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$condexe_overlay" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
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

for binding in \
  "$rudra_source_commit^{commit}:$rudra_source_commit" \
  "$rudra_source_commit^{tree}:$rudra_source_tree" \
  "$rudra_source_commit:src:$rudra_source_src_tree" \
  "$rudra_source_commit:src/condexe.rs:$rudra_condexe_blob" \
  "$rudra_source_commit:Cargo.toml:$rudra_source_cargo_toml_blob" \
  "$rudra_source_commit:Cargo.lock:$rudra_source_cargo_lock_blob" \
  "$rudra_source_commit:build.rs:$rudra_source_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra source identity mismatch: $expression" >&2
    exit 1
  fi
done

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
cp "$condexe_overlay" "$snapshot_root/src/condexe.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/condexe_pullback_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/condexe_pullback_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/condexe_pullback_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_condexe_pullback_oracle.sh"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$condexe_overlay" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_source_commit" \
  "$rudra_source_tree" "$rudra_source_src_tree" "$rudra_condexe_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, condexe_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, source_commit,
    source_tree, source_src_tree, condexe_blob, cargo_toml_blob,
    cargo_lock_blob, build_rs_blob,
) = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "CONDEXE-PULLBACK-0005")
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
source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source condexe blob", source["base_condexe_blob"], condexe_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("condexe_overlay_sha256", pathlib.Path(condexe_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])

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
require("overall", metadata["overall_status"], "UNTESTED: (B2 canonicalization)")
expected_matches = {
    "pullback_subpiece_multiequal", "pullback_cache",
    "pullback_crossblock_immeddom", "pullback_const_input",
    "gate_test_op_read",
}
expected_residuals = {
    "execute_and_flow_split",
}
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
require("coverage keys", set(coverage), expected_matches | expected_residuals)
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
observed_statuses = set()
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
    observed_statuses.add(status)
    if not isinstance(record["covers"], str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers must be non-empty")
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
for key in expected_matches:
    require(f"coverage.{key}.status", coverage[key]["status"], "MATCH")
for key in expected_residuals:
    require(f"coverage.{key}.status", coverage[key]["status"], "UNTESTED")
require("coverage status set", observed_statuses, {"MATCH", "UNTESTED"})
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list) or not top_residual_ids:
    raise SystemExit("top-level residual_todo_ids must be a non-empty list")
if any(not isinstance(item, str) or not item for item in top_residual_ids):
    raise SystemExit("top-level residual_todo_ids contains an invalid id")
if len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids contains duplicates")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
residual = metadata["residual_union"]
require("residual TODO", residual["todo_id"], "CFG-0001")
require("residual status", residual["status"], "UNTESTED")
require(
    "residual branch union",
    {branch["id"] for branch in residual["branches"]},
    expected_residuals,
)
for branch in residual["branches"]:
    require(f"residual {branch['id']} status", branch["status"], "UNTESTED")
    if not branch["detail"]:
        raise SystemExit(f"residual {branch['id']} has no detail")
PY

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/condexe_pullback_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" \
  -lz -o "$oracle_tmp/condexe_pullback_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  nice -n 10 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
native_archive=$(find "$oracle_tmp/cargo-target/debug/build" \
  -path '*/out/librudra_sleigh.a' -print -quit)
if [[ ! -f "$native_archive" ]]; then
  echo "Rudra build did not produce librudra_sleigh.a" >&2
  exit 1
fi
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -L "native=$(dirname "$native_archive")" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$snapshot_root/tests/oracle/condexe_pullback_1204.rs" \
  -o "$oracle_tmp/condexe_pullback_1204_rust"

set +e
"$oracle_tmp/condexe_pullback_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/condexe_pullback_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/rudra.stderr" "$oracle_tmp/raw.diff" \
  "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[7])),
    ("rugra_exit_code", int(sys.argv[8])),
    ("diff_exit_code", int(sys.argv[9])),
):
    if actual != metadata["expected_results"][key]:
        raise SystemExit(f"{key} mismatch")
records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
observed_order = [record.split("|", 1)[0] + ":" + record.split("|case=", 1)[1].split("|", 1)[0] for record in records]
expected_order = [
    "pullback:P0", "pullback:P1", "pullback:P1b", "pullback:P3",
    "pullback:P2", "pullback:P5",
    "gate:G1", "gate:G2", "gate:G3", "gate:G4",
    "gate:G5", "gate:G6", "gate:G7", "gate:G8",
]
if observed_order != expected_order:
    raise SystemExit(f"observation order mismatch: {observed_order}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0 or paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'condexe_pullback_1204: covered_projection=5/5 projection_status=MATCH overall_status=UNTESTED residual=CFG-0001\n'
