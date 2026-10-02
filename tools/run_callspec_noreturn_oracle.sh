#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rugra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rugra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rugra_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rugra_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/callspec_noreturn_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/callspec_noreturn_1204.cc"
rust_fixture="$repo_root/tests/oracle/callspec_noreturn_1204.rs"
runner="$repo_root/tools/run_callspec_noreturn_oracle.sh"

overlay_paths=(
  src/fspec.rs
)

run_cache=${RUDRA_CALLSPEC_NORETURN_RUN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-callspec-noreturn-1204}
cargo_target=${RUDRA_CALLSPEC_NORETURN_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-callspec-noreturn-target}
cargo_tmp=${RUDRA_CALLSPEC_NORETURN_TMP_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-callspec-noreturn-tmp}
mkdir -p "$run_cache" "$cargo_target" "$cargo_tmp"
oracle_tmp=$(mktemp -d "$run_cache/run.XXXXXX")
cleanup() {
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

if [[ "$(git -C "$repo_root" rev-parse "${rugra_base_commit}^{commit}")" != "$rugra_base_commit" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}^{tree}")" != "$rugra_base_tree" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:src")" != "$rugra_base_src_tree" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.toml")" != "$rugra_cargo_toml_blob" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.lock")" != "$rugra_cargo_lock_blob" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:build.rs")" != "$rugra_build_rs_blob" ]]; then
  echo "pinned Rugra base identity mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" "$snapshot_root/tools"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/callspec_noreturn_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/callspec_noreturn_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/callspec_noreturn_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_callspec_noreturn_oracle.sh"
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
ln -s "$ghidra_root" "$snapshot_root/ghidra"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rugra_base_commit" "$rugra_base_tree" \
  "$rugra_base_src_tree" "$rugra_cargo_toml_blob" \
  "$rugra_cargo_lock_blob" "$rugra_build_rs_blob" \
  "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob,
    build_rs_blob, *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "CALLSPEC-NORETURN-1204")
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
require("architecture", metadata["architecture"], "locked synthetic LE 64-bit fixture (const/other/unique/ram/register/stack/join/iop spaces, TypeFactory, decoded 'fixture' ProtoModel); no sleigh")
require("compiler id", metadata["compiler_spec"]["id"], "none")
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
    require(f"{relative} snapshot sha", sha((snapshot / relative).read_bytes()), expected)

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
require("overall", metadata["overall_status"], "MATCH: (B2 canonicalization)")
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

if [[ ${RUDRA_CALLSPEC_NORETURN_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "callspec_noreturn_1204 metadata/source lock validation passed"
  exit 0
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
TMPDIR="$cargo_tmp" make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
TMPDIR="$cargo_tmp" g++ -std=c++11 -O2 \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/callspec_noreturn_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$oracle_tmp/callspec_noreturn_cpp"

if ! /usr/bin/flock -x /tmp/rugra-cargo-build.lock env \
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" TMPDIR="$cargo_tmp" \
  cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib; then
  exit 1
fi
TMPDIR="$cargo_tmp" rustc --edition=2021 -O \
  "$snapshot_root/tests/oracle/callspec_noreturn_1204.rs" \
  --extern rugra="$cargo_target/debug/librugra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$oracle_tmp/callspec_noreturn_rust"

set +e
"$oracle_tmp/callspec_noreturn_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/callspec_noreturn_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rugra.stdout" "$oracle_tmp/rugra.stderr" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rugra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rugra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rugra_stderr_sha256": pathlib.Path(sys.argv[5]),
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
        raise SystemExit(f"{key} mismatch: expected={metadata['expected_results'][key]} actual={actual}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0 or paths["rugra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")

lines = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(lines) != 7:
    raise SystemExit(f"expected seven fixture lines, found {len(lines)}")
if lines[0] != (
    "schema=1|fixture=CALLSPEC-NORETURN-1204|"
    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
):
    raise SystemExit("fixture envelope mismatch")
expected_cases = [
    "default_ctor", "explicit_set_idempotent", "copy_flow_effects",
    "full_copy_and_clone", "void_no_inference", "decode_encode_channel",
]
actual_cases = [line.split("|", 1)[0].removeprefix("case=") for line in lines[1:] if line.startswith("case=")]
if actual_cases != expected_cases:
    raise SystemExit(f"fixture case order mismatch: {actual_cases}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'callspec_noreturn_1204: covered_projection=6/6 projection_status=MATCH overall_status=MATCH\n'
