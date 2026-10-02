#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_source_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rugra_source_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rugra_source_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rugra_source_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rugra_source_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rugra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
spec_input_commit=c38edbfbcbc9344a4deb331876a4b5dcf112c7e0
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/truncated_flow_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/truncated_flow_1204.cc"
rust_fixture="$repo_root/tests/oracle/truncated_flow_1204.rs"
runner="$repo_root/tools/run_truncated_flow_oracle.sh"

overlay_paths=(
  src/coreaction.rs
  src/flow.rs
  src/fspec.rs
  src/funcdata.rs
  src/heritage.rs
  src/ruleaction.rs
  src/signature.rs
  src/unionresolve.rs
  src/varnode.rs
)

cache_root=${RUDRA_TRUNCATED_FLOW_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-truncated-flow-1204}
cargo_target_dir=${CARGO_TARGET_DIR:-$cache_root/target}
cargo_tmp_dir=${TMPDIR:-$cache_root/tmp}
mkdir -p "$cache_root" "$cargo_target_dir" "$cargo_tmp_dir"
oracle_tmp=$(mktemp -d "$cache_root/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$cache_root"/run.??????) rm -rf -- "$oracle_tmp" ;;
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
actual_language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source has staged changes" >&2
  exit 1
fi

for binding in \
  "$rugra_source_commit^{commit}:$rugra_source_commit" \
  "$rugra_source_commit^{tree}:$rugra_source_tree" \
  "$rugra_source_commit:src:$rugra_source_src_tree" \
  "$rugra_source_commit:Cargo.toml:$rugra_source_cargo_toml_blob" \
  "$rugra_source_commit:Cargo.lock:$rugra_source_cargo_lock_blob" \
  "$rugra_source_commit:build.rs:$rugra_source_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rugra source identity mismatch: $expression" >&2
    exit 1
  fi
done

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" ]]; then
  for candidate in /tmp/rugra-ghidra-bfd-2.38/usr/include /usr/include; do
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
      /tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
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
if [[ "$(sha256sum "$bfd_include/bfd.h" | awk '{print $1}')" != "$bfd_header_sha256" || \
      "$(sha256sum "$bfd_library" | awk '{print $1}')" != "$bfd_library_sha256" ]]; then
  echo "BFD input fingerprint mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/truncated_flow_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/truncated_flow_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/truncated_flow_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_truncated_flow_oracle.sh"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$spec_input_commit:$asset" \
    >"$snapshot_root/$asset"
done
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
ln -s "$ghidra_root" "$snapshot_root/ghidra"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_sha" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rugra_source_commit" "$rugra_source_tree" \
  "$rugra_source_src_tree" "$rugra_source_cargo_toml_blob" "$rugra_source_cargo_lock_blob" \
  "$rugra_source_build_rs_blob" "$spec_input_commit" \
  "$bfd_include/bfd.h" "$bfd_library" "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, source_commit, source_tree,
    source_src_tree, source_cargo_toml_blob, source_cargo_lock_blob,
    source_build_rs_blob, spec_input_commit, bfd_header_raw, bfd_library_raw,
    *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(
            f"{label} mismatch: expected={expected!r} actual={actual!r}"
        )

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "FLOW-TRUNCATED-0001")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("status_note must be a non-empty string")
decisive = metadata.get("decisive_semantics")
expected_decisive = {
    "reference_output_parameters",
    "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle",
    "sorting_comparison_keys",
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
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")

source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
require("C++ fixture sha", sha(pathlib.Path(cpp_raw).read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture sha", sha(pathlib.Path(rust_raw).read_bytes()), comparand["rust_fixture_sha256"])
require("runner sha", runner_sha, comparand["runner_sha256"])
overlays = {entry["path"]: entry for entry in source["overlays"]}
require("overlay paths", set(overlays), set(overlay_paths))
for relative in overlay_paths:
    expected = overlays[relative]["sha256"]
    require(f"{relative} live sha", sha((repo / relative).read_bytes()), expected)
    require(f"{relative} snapshot sha", sha((snapshot / relative).read_bytes()), expected)
build_link = source["snapshot_build_link"]
require("snapshot build link path", build_link["path"], "ghidra")
ghidra_link = snapshot / build_link["path"]
if not ghidra_link.is_symlink():
    raise SystemExit("snapshot ghidra build path is not a symlink")
require("snapshot ghidra link target", ghidra_link.resolve(), (repo / "ghidra").resolve())

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source commit", record["source_repository_commit"], spec_input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{spec_input_commit}:{relative}"],
        text=True,
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} sha", sha(data), record["sha256"])
    require(f"{key} size", len(data), record["size"])
require("BFD header metadata", assets["bfd"]["header_sha256"], sha(pathlib.Path(bfd_header_raw).read_bytes()))
require("BFD library metadata", assets["bfd"]["library_sha256"], sha(pathlib.Path(bfd_library_raw).read_bytes()))

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "construction": manifest["construction"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", sha(canonical), manifest["sha256"])

require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MISMATCH: (B2 canonicalization)")
expected_statuses = {
    "raw_op_seqnum_list_order_and_uniqid": "MATCH",
    "callspec_fspec_rebind_projection": "MATCH",
    "callspec_complete_identity_and_fields": "MISMATCH",
    "jumptable_partial_copy_skip_and_identity": "MATCH",
    "splitbasic_per_op_lifecycle_and_order": "MATCH",
    "blockbasic_initial_range_and_max_stop": "MATCH",
    "blockbasic_multi_range_copy_merge_and_marshal": "UNTESTED",
    "nonempty_precondition_exception": "MATCH",
    "missing_jumptable_exception_and_partial_mutation": "MATCH",
    "clone_varnode_type_and_complete_flag_mask": "UNTESTED",
    "flowinfo_private_state_and_branch_stubs": "UNTESTED",
    "truncated_injection_branch": "UNTESTED",
    "splitbasic_missing_entry_error": "MATCH",
    "insert_after_dead_invalid_state": "MISMATCH",
}
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
require("coverage keys", set(coverage), set(expected_statuses))
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
for key, expected_status in expected_statuses.items():
    record = coverage[key]
    require(f"coverage.{key} fields", set(record), {"status", "covers", "residual_todo_ids"})
    status = record["status"]
    if status not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {status!r}")
    require(f"coverage.{key}.status", status, expected_status)
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
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list) or len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids is invalid")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))

observations = metadata.get("out_of_scope_observations")
if not isinstance(observations, list):
    raise SystemExit("out_of_scope_observations must be a list")
for observation in observations:
    require(f"observation {observation.get('id')!r} fields", set(observation), {"id", "note"})
    if not observation["id"] or not observation["note"]:
        raise SystemExit("out_of_scope_observations entries must be non-empty")
PY

if [[ ${RUDRA_TRUNCATED_FLOW_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "truncated_flow_1204 metadata/source lock validation passed"
  exit 0
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
if ! TMPDIR="$cargo_tmp_dir" make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" \
    EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  cat "$oracle_tmp/make.stdout" "$oracle_tmp/make.stderr" >&2
  exit 1
fi
TMPDIR="$cargo_tmp_dir" g++ -std=c++11 -O0 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/truncated_flow_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/truncated_flow_cpp"

if ! /usr/bin/flock -x /tmp/rugra-cargo-build.lock env \
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target_dir" \
    TMPDIR="$cargo_tmp_dir" cargo build --offline --locked --quiet \
    --manifest-path "$snapshot_root/Cargo.toml" --lib \
    >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stdout" "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
TMPDIR="$cargo_tmp_dir" rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/truncated_flow_1204.rs" \
  --extern rugra="$cargo_target_dir/debug/librugra.rlib" \
  -L dependency="$cargo_target_dir/debug/deps" \
  -o "$oracle_tmp/truncated_flow_rust"

symbol_args=()
for symbol in truncated_flow_source truncated_flow_target truncated_flow_callee \
  truncated_flow_nonempty truncated_flow_error_source truncated_flow_error_target \
  truncated_flow_entry_source truncated_flow_entry_target \
  truncated_flow_range_source truncated_flow_range_target; do
  address=$(nm -n --defined-only "$oracle_tmp/truncated_flow_cpp" | \
    awk -v name="$symbol" '$3 == name && value == "" { value=$1 } END { print value }')
  if [[ -z "$address" ]]; then
    echo "failed to resolve fixture symbol: $symbol" >&2
    exit 1
  fi
  symbol_args+=("$address")
done

bfd_runtime=$(dirname "$bfd_library")
if [[ -n ${LD_LIBRARY_PATH:-} ]]; then
  bfd_runtime="$bfd_runtime:$LD_LIBRARY_PATH"
fi
set +e
LD_LIBRARY_PATH="$bfd_runtime" "$oracle_tmp/truncated_flow_cpp" \
  "$snapshot_root/sleigh_specs" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/truncated_flow_rust" "${symbol_args[@]}" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/raw.diff"
diff_status=$?
set -e
if [[ "$diff_status" -ne 0 ]]; then
  cat "$oracle_tmp/raw.diff" >&2
fi

objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/truncated_flow_cpp"
python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/rugra.stderr" "$oracle_tmp/raw.diff" \
  "$oracle_tmp/fixture.text" "$ghidra_status" "$rugra_status" \
  "$diff_status" <<'PY'
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
mismatches = []
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        mismatches.append(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[8])),
    ("rugra_exit_code", int(sys.argv[9])),
    ("diff_exit_code", int(sys.argv[10])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        mismatches.append(f"{key} mismatch: expected={expected} actual={actual}")
fixture_text = hashlib.sha256(pathlib.Path(sys.argv[7]).read_bytes()).hexdigest()
expected_text = metadata["machine_input_sha256"]["fixture_text"]
if fixture_text != expected_text:
    mismatches.append(
        f"fixture text mismatch: expected={expected_text} actual={fixture_text}"
    )
if mismatches:
    raise SystemExit("\n".join(mismatches))
if paths["ghidra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Ghidra stderr output")
if paths["rugra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Rugra stderr output")
records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(records) != 17:
    raise SystemExit(f"unexpected observation line count: {len(records)}")
if records[0] != "case=success":
    raise SystemExit("success case is not first")
if records[12] != (
    "case=block_range blocks=1 alive=3 dead=0 start_valid=1 stop_valid=1 "
    "start_space_same=1 stop_space_same=1 start_exact=1 stop_exact=1 "
    "stop_not_last=1 start_delta=0 stop_delta=64 op_deltas=[0,64,32]"
):
    raise SystemExit("block-range observation missing or reordered")
if not records[13].startswith("case=nonempty error=Trying to do truncated flow"):
    raise SystemExit("nonempty exception observation missing or reordered")
if not records[14].startswith("case=missing_jumptable error=Could not trace jumptable"):
    raise SystemExit("missing-jumptable exception observation missing or reordered")
if not records[15].startswith("case=missing_entry before_all=0 before_dead=0"):
    raise SystemExit("missing-entry pre-state observation missing or reordered")
if not records[16].startswith("case=missing_entry error=First op not marked as entry point"):
    raise SystemExit("missing-entry exception observation missing or reordered")
print(
    "truncated_flow_1204 oracle gate: covered projection MATCH; "
    "overall MISMATCH (registered residuals)"
)
PY
