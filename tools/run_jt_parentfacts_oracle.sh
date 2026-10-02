#!/usr/bin/env bash
# JUMPTABLE-PARENTFACTS-0001 — locked Ghidra 12.0.4 oracle gate for the
# two JumpParentFacts channels of JumpTable::recover_model (e27e985):
#   M1  multistage partial-table -> analyzeGuards usenzmask (cc:1052);
#       the SUBPIECE nzmask rescue (rangeutil.cc:1053-1065) makes the
#       guard-record count differ between stage1/stage2 (3 vs 2).
#   P1/P0  JumpBasic2 sibling BRANCHIND identity (cc:1083-1091): P1's
#       sibling edge hits THIS switch block (guard walk continues, 6
#       records); P0's hits a different BRANCHIND (break, 3 records).
# Pin-base schema2, modeled on tools/run_merge_trim_lane_oracle.sh: base
# is the port-defect fix commit ef2f25f (which carries the
# findDeterminingVarnodes fallback + sanityCheck i=1 fixes this fixture
# exposed); the only source overlay is src/jumptable.rs itself; no BFD,
# no loader binary, no SLEIGH assets (the fixture uses a synthetic
# FixtureArchitecture and an empty spec-path startDecompilerLibrary).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_source_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_source_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_jumptable_blob=2fce5447c396417b691e9a052a465251921ca8d1
rudra_source_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_source_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/jt_parentfacts_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/jt_parentfacts_1204.cc"
rust_fixture="$repo_root/tests/oracle/jt_parentfacts_1204.rs"
jumptable_overlay="$repo_root/src/jumptable.rs"
runner="$repo_root/tools/run_jt_parentfacts_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rudra-jt-parentfacts-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-jt-parentfacts-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner"; do
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
  "$rudra_source_commit:src/jumptable.rs:$rudra_jumptable_blob" \
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
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" "$snapshot_root/tools"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
cp "$jumptable_overlay" "$snapshot_root/src/jumptable.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/jt_parentfacts_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/jt_parentfacts_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/jt_parentfacts_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_jt_parentfacts_oracle.sh"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')

python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$jumptable_overlay" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_source_commit" \
  "$rudra_source_tree" "$rudra_source_src_tree" "$rudra_jumptable_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, jt_overlay_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, source_commit,
    source_tree, source_src_tree, jumptable_blob, cargo_toml_blob,
    cargo_lock_blob, build_rs_blob,
) = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "JUMPTABLE-PARENTFACTS-0001")
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
    ("source jumptable blob", source["base_jumptable_blob"], jumptable_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("jumptable overlay sha", sha(pathlib.Path(jt_overlay_raw).read_bytes()),
        comparand["jumptable_overlay_sha256"])
if comparand["runner_sha256"] != "PENDING":
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
require("overall", metadata["overall_status"], "MATCH")
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
for key, record in coverage.items():
    if not isinstance(record, dict):
        raise SystemExit(f"coverage.{key} must be an object")
    if record.get("status") not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status must be one of {sorted(valid_statuses)}")
    if not isinstance(record.get("covers"), str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers must be a non-empty string")
    if not isinstance(record.get("residual_todo_ids"), list):
        raise SystemExit(f"coverage.{key}.residual_todo_ids must be a list")
residual = metadata.get("residual_union")
if not isinstance(residual, dict):
    raise SystemExit("residual_union must be an object")
require("residual status", residual["status"], "UNTESTED")
expected_stdout = metadata["expected_results"]
require("ghidra stdout", expected_stdout["ghidra_stdout_sha256"],
        expected_stdout["rudra_stdout_sha256"])
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
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/jt_parentfacts_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" \
  -lz -o "$oracle_tmp/jt_parentfacts_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet \
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
  "$snapshot_root/tests/oracle/jt_parentfacts_1204.rs" \
  -o "$oracle_tmp/jt_parentfacts_1204_rust"

"$oracle_tmp/jt_parentfacts_1204_cpp" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/jt_parentfacts_1204_rust" >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$oracle_tmp" "$metadata" "$runner_sha" <<'PY'
import hashlib
import json
import pathlib
import sys

tmp_raw, metadata_raw, runner_sha = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
expected = metadata["expected_results"]
observed = {
    "ghidra_stdout_sha256": sha(pathlib.Path(f"{tmp_raw}/ghidra.stdout").read_bytes()),
    "ghidra_stderr_sha256": sha(pathlib.Path(f"{tmp_raw}/ghidra.stderr").read_bytes()),
    "rudra_stdout_sha256": sha(pathlib.Path(f"{tmp_raw}/rudra.stdout").read_bytes()),
    "rudra_stderr_sha256": sha(pathlib.Path(f"{tmp_raw}/rudra.stderr").read_bytes()),
    "raw_diff_sha256": hashlib.sha256(b"").hexdigest(),
}
for key, value in observed.items():
    if value != expected[key]:
        raise SystemExit(f"expected_results.{key} mismatch: {value}")
if observed["ghidra_stdout_sha256"] != observed["rudra_stdout_sha256"]:
    raise SystemExit("stdout sha divergence despite clean diff")
comparand = metadata["comparand"]
if comparand["runner_sha256"] == "PENDING":
    raise SystemExit("runner_sha256 still PENDING: re-pin after freezing the runner")
if comparand["runner_sha256"] != runner_sha:
    raise SystemExit("runner_sha256 mismatch")
print("JUMPTABLE-PARENTFACTS-0001 MATCH (M1 multistage usenzmask + P1/P0 sibling indirect identity, oracle byte-identical)")
PY
