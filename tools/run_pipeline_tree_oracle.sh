#!/usr/bin/env bash
set -euo pipefail

# PIPE-DERIVED-TREE-0001 pin-base schema2 oracle runner.  Builds the locked
# Ghidra 12.0.4 fixture (real ActionDatabase::universalAction -> resetDefaults
# -> getCurrent derive) and the Rudra comparand (real default action database)
# from a pinned base commit overlaid with the working-tree src/action.rs and
# src/coreaction.rs, then requires byte-identical DFS observations.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_base_action_blob=40b15b0873e83caf6318ef26267d799be89e624c
rudra_base_coreaction_blob=e5fb0a75534d714556206c765e6cc075cf3bd8c3
rudra_base_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_base_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/pipeline_tree_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/pipeline_tree_1204.cc"
rust_fixture="$repo_root/tests/oracle/pipeline_tree_1204.rs"
action_overlay="$repo_root/src/action.rs"
coreaction_overlay="$repo_root/src/coreaction.rs"
runner="$repo_root/tools/run_pipeline_tree_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rudra-pipeline-tree-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-pipeline-tree-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$action_overlay" "$coreaction_overlay" "$runner"; do
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
  "$rudra_base_commit^{commit}:$rudra_base_commit" \
  "$rudra_base_commit^{tree}:$rudra_base_tree" \
  "$rudra_base_commit:src:$rudra_base_src_tree" \
  "$rudra_base_commit:src/action.rs:$rudra_base_action_blob" \
  "$rudra_base_commit:src/coreaction.rs:$rudra_base_coreaction_blob" \
  "$rudra_base_commit:Cargo.toml:$rudra_base_cargo_toml_blob" \
  "$rudra_base_commit:Cargo.lock:$rudra_base_cargo_lock_blob" \
  "$rudra_base_commit:build.rs:$rudra_base_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra base identity mismatch: $expression" >&2
    exit 1
  fi
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$action_overlay" "$coreaction_overlay" "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_base_commit" "$rudra_base_tree" "$rudra_base_src_tree" \
  "$rudra_base_action_blob" "$rudra_base_coreaction_blob" \
  "$rudra_base_cargo_toml_blob" "$rudra_base_cargo_lock_blob" \
  "$rudra_base_build_rs_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, action_raw, coreaction_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, base_action_blob,
    base_coreaction_blob, base_cargo_toml_blob, base_cargo_lock_blob,
    base_build_rs_blob,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "PIPE-DERIVED-TREE-0001")
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
    ("base commit", source["base_commit"], base_commit),
    ("base tree", source["base_tree"], base_tree),
    ("base src tree", source["base_src_tree"], base_src_tree),
    ("base action blob", source["base_action_blob"], base_action_blob),
    ("base coreaction blob", source["base_coreaction_blob"], base_coreaction_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], base_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], base_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], base_build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("action_overlay_sha256", pathlib.Path(action_raw)),
    ("coreaction_overlay_sha256", pathlib.Path(coreaction_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "inputs": manifest["inputs"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])

coverage = metadata.get("coverage")
if not isinstance(coverage, dict) or not coverage:
    raise SystemExit("coverage must be a non-empty object")
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
    if record["status"] not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {record['status']!r}")
    if not isinstance(record["covers"], str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers must be non-empty")
    residual_ids = record["residual_todo_ids"]
    if not isinstance(residual_ids, list) or any(
        not isinstance(item, str) or not item for item in residual_ids
    ):
        raise SystemExit(f"coverage.{key}.residual_todo_ids is invalid")
    if len(residual_ids) != len(set(residual_ids)):
        raise SystemExit(f"coverage.{key}.residual_todo_ids contains duplicates")
    if record["status"] == "MATCH":
        require(f"coverage.{key} MATCH residuals", residual_ids, [])
    elif not residual_ids:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
    coverage_residual_ids.update(residual_ids)
require("coverage tree projection", coverage["derived_tree_projection"]["status"], "MATCH")
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list):
    raise SystemExit("top-level residual_todo_ids must be a list")
if any(not isinstance(item, str) or not item for item in top_residual_ids):
    raise SystemExit("top-level residual_todo_ids contains an invalid id")
if len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids contains duplicates")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
require("overall", metadata["overall_status"], "UNTESTED: (B2 canonicalization)")
PY

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/examples"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
cp "$action_overlay" "$snapshot_root/src/action.rs"
cp "$coreaction_overlay" "$snapshot_root/src/coreaction.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/pipeline_tree_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/pipeline_tree_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/pipeline_tree_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_pipeline_tree_oracle.sh"

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$snapshot_root/tests/oracle/pipeline_tree_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/pipeline_tree_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  nice -n 10 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$snapshot_root/tests/oracle/pipeline_tree_1204.rs" \
  -o "$oracle_tmp/pipeline_tree_1204_rust"

set +e
"$oracle_tmp/pipeline_tree_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/pipeline_tree_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" "$oracle_tmp/raw.diff" \
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
lines = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(lines) != 83:
    raise SystemExit(f"expected 83 fixture lines, found {len(lines)}")
if lines[0] != (
    "schema=1|fixture=PIPE-DERIVED-TREE-0001|"
    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
):
    raise SystemExit("fixture envelope mismatch")
if lines[1] != "root_key=decompile" or lines[2] != "root_name=universal" \
        or lines[3] != "root_flags=8":
    raise SystemExit("root observation mismatch")
if lines[-1] != "count=78":
    raise SystemExit(f"node count mismatch: {lines[-1]}")
nodes = [line for line in lines if line.startswith("node|")]
if len(nodes) != 78:
    raise SystemExit(f"expected 78 node lines, found {len(nodes)}")
for expected_absent in (
    "funclink_outonly", "normalizesetup", "normalizebranches",
):
    if any(f"|name={expected_absent}|" in line for line in nodes):
        raise SystemExit(f"{expected_absent} must be filtered from the decompile root")
for name, count in (("unreachable", 2), ("directwrite", 2), ("deadcode", 2), ("dynamicsymbols", 2)):
    observed = sum(1 for line in nodes if f"|name={name}|" in line)
    if observed != count:
        raise SystemExit(f"duplicate node {name}: expected {count}, found {observed}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0 or \
        paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'pipeline_tree_1204: derived_tree_projection=MATCH overall=MATCH nodes=78 stdout_sha256=%s\n' \
  "$(sha256sum "$oracle_tmp/ghidra.stdout" | awk '{print $1}')"
