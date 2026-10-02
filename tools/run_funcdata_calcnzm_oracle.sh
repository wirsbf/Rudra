#!/usr/bin/env bash
set -euo pipefail

# FUNCDATA-CALCNZM-0001 oracle runner — Funcdata::calcNZMask
# (funcdata_varnode.cc:856-926) + PcodeOp::getNZMaskLocal (op.cc:547-771)
# bilateral fixture. Pin-base schema2 pattern follows
# tools/run_lanedivide_infra_oracle.sh; the fixture needs no BFD loader
# (synthetic FixtureArchitecture, cf. funcdata_op_insert_input_1204).
# Pin base rebased to 65a2492 (FUNCDATA-CALCNZM-0002 consolidation:
# the full switch now lives in PcodeOp::get_nz_mask_local, src/op.rs
# pinned via base_op_blob).

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_source_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_source_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_source_funcdata_blob=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_source_op_blob=d5e4c5f972d06844084bf19a505434fd24be3894
rudra_source_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_source_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/funcdata_calcnzm_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/funcdata_calcnzm_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcdata_calcnzm_1204.rs"
runner="$repo_root/tools/run_funcdata_calcnzm_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rudra-funcdata-calcnzm-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-funcdata-calcnzm-1204.??????) rm -rf -- "$oracle_tmp" ;;
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
  "$rudra_source_commit:src/funcdata.rs:$rudra_source_funcdata_blob" \
  "$rudra_source_commit:src/op.rs:$rudra_source_op_blob" \
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

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_source_funcdata_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" "$rudra_source_op_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, runner_sha, oracle_commit,
    oracle_tag, cpp_tree, makefile_blob, source_commit, source_tree,
    source_src_tree, source_funcdata_blob, source_cargo_toml_blob,
    source_cargo_lock_blob, source_build_rs_blob, source_op_blob,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "FUNCDATA-CALCNZM-0001")
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
require("architecture", metadata["architecture"],
        "locked synthetic LE 64-bit Architecture: const=0, other=1, unique=2, "
        "ram=3, register=4, stack=5, join=6, iop=7")
require("compiler spec", metadata["compiler_spec"]["id"], "fixture")
source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source funcdata blob", source["base_funcdata_blob"], source_funcdata_blob),
    ("source op blob", source["base_op_blob"], source_op_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
cases = metadata["input_manifest"]["cases"]
require("case count", len(cases), 6)
require("case keys", [case["key"] for case in cases],
        ["init", "andcopy", "piece", "div", "loopor", "loopand"])
require("manifest sha", metadata["input_manifest"]["sha256"],
        sha(json.dumps(
            {"architecture": metadata["architecture"],
             "compiler_spec": metadata["compiler_spec"],
             "analysis_options": metadata["analysis_options"],
             "cases": cases},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
coverage = metadata.get("coverage")
if not isinstance(coverage, dict) or not coverage:
    raise SystemExit("coverage must be a non-empty object")
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
for key, record in coverage.items():
    if key not in {"init_inputs", "and_copy_chain", "piece_concat",
                   "sc6_div_shapes", "multiequal_loop_clip"}:
        raise SystemExit(f"unexpected coverage key: {key}")
    require(f"coverage.{key} fields", set(record),
            {"status", "covers", "residual_todo_ids"})
    if record["status"] not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {record['status']!r}")
    if record["status"] == "MATCH":
        require(f"coverage.{key} MATCH residuals", record["residual_todo_ids"], [])
    elif not record["residual_todo_ids"]:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
require("coverage keys", set(coverage),
        {"init_inputs", "and_copy_chain", "piece_concat", "sc6_div_shapes",
         "multiequal_loop_clip"})
all_match = all(record["status"] == "MATCH" for record in coverage.values())
require("projection", metadata["projection_status"], "MATCH" if all_match else "UNTESTED")
require("overall", metadata["overall_status"], "MATCH" if all_match else "UNTESTED")
residual_ids = metadata.get("residual_todo_ids")
if not isinstance(residual_ids, list) or any(
    not isinstance(item, str) or not item for item in residual_ids
):
    raise SystemExit("residual_todo_ids must be a list of non-empty ids")
if len(residual_ids) != len(set(residual_ids)):
    raise SystemExit("residual_todo_ids contains duplicates")
residual = metadata.get("residual_union")
if not isinstance(residual, list):
    raise SystemExit("residual_union must be a list")
require("residual TODO ids", {branch["todo_id"] for branch in residual},
        set(residual_ids))
for branch in residual:
    if not branch.get("detail"):
        raise SystemExit(f"residual {branch['todo_id']} has no detail")
expected = metadata["expected_results"]
for key in ("ghidra_stdout_sha256", "rudra_stdout_sha256",
            "ghidra_stderr_sha256", "rudra_stderr_sha256", "raw_diff_sha256"):
    if not isinstance(expected.get(key), str):
        raise SystemExit(f"expected_results.{key} missing")
require("ghidra exit code", expected["ghidra_exit_code"], 0)
require("rudra exit code", expected["rugra_exit_code"], 0)
require("diff exit code", expected["diff_exit_code"], 0)
require("observation prefixes", expected["observation_prefixes"],
        ["init", "andcopy", "piece", "div", "loopor", "loopand"])
PY

# --- Build the oracle C++ fixture from an archived copy of the pinned tree.
git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

# --- Snapshot the pinned Rudra source and overlay the current fixture files.
snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" \
  "$snapshot_root/benches"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/funcdata_calcnzm_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/funcdata_calcnzm_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/funcdata_calcnzm_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_funcdata_calcnzm_oracle.sh"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
nice -n 10 g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/funcdata_calcnzm_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/funcdata_calcnzm_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  nice -n 10 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 "$snapshot_root/tests/oracle/funcdata_calcnzm_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/funcdata_calcnzm_1204_rust"

set +e
"$oracle_tmp/funcdata_calcnzm_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/funcdata_calcnzm_1204_rust" \
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
prefixes = [record.split("|", 1)[0] for record in records]
if prefixes != metadata["expected_results"]["observation_prefixes"]:
    raise SystemExit(f"observation order mismatch: {prefixes}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0 or \
   paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'funcdata_calcnzm_1204: projection_status=MATCH overall_status=MATCH cases=6 residual=FUNCDATA-CALCNZM-0003(varnode.rs get_nz_mask approximation)\n'
