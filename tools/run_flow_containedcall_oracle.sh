#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
spec_input_commit=c38edbfbcbc9344a4deb331876a4b5dcf112c7e0
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/flow_containedcall_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/flow_containedcall_1204.cc"
rust_fixture="$repo_root/tests/oracle/flow_containedcall_1204.rs"
runner="$repo_root/tools/run_flow_containedcall_oracle.sh"
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e

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

run_cache=${RUDRA_FLOW_CONTAINEDCALL_RUN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-containedcall-1204}
cargo_target=${RUDRA_FLOW_CONTAINEDCALL_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-containedcall-target}
cargo_tmp=${RUDRA_FLOW_CONTAINEDCALL_TMP_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-flow-containedcall-tmp}
mkdir -p "$run_cache" "$cargo_target" "$cargo_tmp"
oracle_tmp=$(mktemp -d "$run_cache/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$run_cache"/run.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

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
bfd_header="$bfd_include/bfd.h"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_header" "$bfd_library"; do
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
  echo "locked Ghidra source has staged changes" >&2
  exit 1
fi

if [[ "$(git -C "$repo_root" rev-parse "${rudra_base_commit}^{commit}")" != "$rudra_base_commit" || \
      "$(git -C "$repo_root" rev-parse "${rudra_base_commit}^{tree}")" != "$rudra_base_tree" || \
      "$(git -C "$repo_root" rev-parse "${rudra_base_commit}:src")" != "$rudra_base_src_tree" || \
      "$(git -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.toml")" != "$rudra_cargo_toml_blob" || \
      "$(git -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.lock")" != "$rudra_cargo_lock_blob" || \
      "$(git -C "$repo_root" rev-parse "${rudra_base_commit}:build.rs")" != "$rudra_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim crates
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/flow_containedcall_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/flow_containedcall_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/flow_containedcall_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_flow_containedcall_oracle.sh"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$spec_input_commit:$asset" >"$snapshot_root/$asset"
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
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$rudra_cargo_toml_blob" \
  "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" "$spec_input_commit" \
  "$bfd_header" "$bfd_library" "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, language_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob,
    build_rs_blob, spec_input_commit, bfd_header_raw, bfd_library_raw,
    *overlay_paths,
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
require("fixture", metadata["fixture_id"], "FLOW-CONTAINEDCALL-0001")
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
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default")
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
        ["git", "-C", str(repo), "rev-parse", f"{spec_input_commit}:{relative}"], text=True
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} sha", sha(data), record["sha256"])
    require(f"{key} size", len(data), record["size"])
require("BFD header", sha(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "probes": manifest["probes"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])

capture_toolchain = metadata.get("capture_toolchain")
require("capture toolchain fields", set(capture_toolchain or {}), {"gxx", "rustc"})
if any(not isinstance(value, str) or not value for value in capture_toolchain.values()):
    raise SystemExit("capture_toolchain values must be non-empty strings")
if not isinstance(metadata.get("replay_toolchain_policy"), str) or not metadata["replay_toolchain_policy"]:
    raise SystemExit("replay_toolchain_policy must be a non-empty string")

machine = metadata.get("machine_input")
require(
    "machine input fields",
    set(machine or {}),
    {"canonicalization", "sha256", "records", "legacy_whole_linked_text"},
)
if not isinstance(machine["canonicalization"], str) or not machine["canonicalization"]:
    raise SystemExit("machine_input.canonicalization must be non-empty")
expected_symbol_order = [
    "containedcall_getpc", "containedcall_mid", "containedcall_fwd",
    "containedcall_offcut", "containedcall_beyond", "containedcall_multi",
    "containedcall_back", "containedcall_afterc", "containedcall_pad",
    "containedcall_before", "containedcall_callind", "containedcall_helper",
    "containedcall_extern",
]
records = machine["records"]
if not isinstance(records, list) or len(records) != len(expected_symbol_order):
    raise SystemExit("machine_input.records must contain exactly thirteen symbols")
previous_end = 0
for index, record in enumerate(records):
    require(
        f"machine record {index} fields",
        set(record),
        {"name", "relative_address", "size", "bytes_hex"},
    )
    require(f"machine record {index} name", record["name"], expected_symbol_order[index])
    require(f"machine record {index} boundary", record["relative_address"], previous_end)
    if not isinstance(record["size"], int) or record["size"] <= 0:
        raise SystemExit(f"machine record {index} has invalid size")
    try:
        machine_bytes = bytes.fromhex(record["bytes_hex"])
    except (TypeError, ValueError) as error:
        raise SystemExit(f"machine record {index} has invalid bytes_hex: {error}")
    require(f"machine record {index} byte length", len(machine_bytes), record["size"])
    require(f"machine record {index} canonical hex", machine_bytes.hex(), record["bytes_hex"])
    previous_end += record["size"]
machine_canonical = json.dumps(
    records, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("machine input canonical sha", sha(machine_canonical), machine["sha256"])
legacy = machine["legacy_whole_linked_text"]
require("legacy linked text fields", set(legacy), {"sha256", "status", "note"})
require("legacy linked text status", legacy["status"], "HISTORICAL_NON_REPRODUCIBLE")
require(
    "legacy linked text sha",
    legacy["sha256"],
    "6ae5db85e351c594b8787bf6a0842df89075313200746457ccdb5f104d6703c5",
)
if not isinstance(legacy["note"], str) or not legacy["note"]:
    raise SystemExit("legacy linked text note must be non-empty")
require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MISMATCH: (B2 canonicalization)")
expected_matches = {
    "goto_spec_parity", "exact_match_conversion_fwd", "offcut_warning",
    "beyond_end_skip", "erase_successor_skip_quirk",
    "exact_match_conversion_back", "conversion_unreachable_block_retained",
    "before_begin_skip", "callind_opcode_guard", "funcdata_resolved_skip",
    "generateops_do_while_wiring",
}
expected_residuals = {"callspec_space_representation"}
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
    require(f"coverage.{key}.status", coverage[key]["status"], "MISMATCH")
require("coverage status set", observed_statuses, {"MATCH", "MISMATCH"})
require(
    "projection/coverage consistency",
    metadata["projection_status"],
    "MATCH" if all(coverage[key]["status"] == "MATCH" for key in expected_matches) else "UNTESTED",
)
require(
    "overall/coverage consistency",
    metadata["overall_status"],
    "MISMATCH",
)
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list):
    raise SystemExit("top-level residual_todo_ids must be a list")
if any(not isinstance(item, str) or not item for item in top_residual_ids):
    raise SystemExit("top-level residual_todo_ids contains an invalid id")
if len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids contains duplicates")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
require("top-level residual ids", set(top_residual_ids), {"TYPEOP-FSPEC-SPACE-0001"})
if "residual_union" in metadata:
    raise SystemExit("resolved fixture must not carry a residual_union block")
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

if [[ ${RUDRA_FLOW_CONTAINEDCALL_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "flow_containedcall_1204 metadata/source lock validation passed"
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
TMPDIR="$cargo_tmp" g++ -std=c++11 -O0 -fno-pie -no-pie \
  -fcf-protection=branch \
  -Wl,--build-id=none \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/flow_containedcall_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/flow_containedcall_cpp"

if ! /usr/bin/flock -x /tmp/rudra-cargo-build.lock env \
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" TMPDIR="$cargo_tmp" \
    cargo build --offline --locked --quiet \
    --manifest-path "$snapshot_root/Cargo.toml" --lib; then
  exit 1
fi
TMPDIR="$cargo_tmp" rustc --edition=2021 -O \
  "$snapshot_root/tests/oracle/flow_containedcall_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$oracle_tmp/flow_containedcall_rust"

bfd_runtime=$(dirname "$bfd_library")
if [[ -n ${LD_LIBRARY_PATH:-} ]]; then
  bfd_runtime="$bfd_runtime:$LD_LIBRARY_PATH"
fi
set +e
LD_LIBRARY_PATH="$bfd_runtime" "$oracle_tmp/flow_containedcall_cpp" \
  "$snapshot_root/sleigh_specs" "$oracle_tmp/flow_containedcall_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 ]]; then
  echo "Ghidra contained-call oracle failed with exit code $ghidra_status" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit "$ghidra_status"
fi
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra contained-call oracle produced unexpected stderr" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/flow_containedcall_cpp"
text_base=$(readelf -WS "$oracle_tmp/flow_containedcall_cpp" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
probe_args=()
for probe in getpc mid fwd offcut beyond multi back afterc before callind extern; do
  read -r probe_addr probe_size < <(nm -S --defined-only \
    "$oracle_tmp/flow_containedcall_cpp" | \
    awk -v n="containedcall_$probe" '$4 == n { print "0x" $1, "0x" $2; exit }')
  if [[ -z "$probe_addr" || "$probe_addr" == "0x" || -z "$text_base" ]]; then
    echo "failed to resolve fixture text base or symbol $probe" >&2
    exit 1
  fi
  probe_args+=("$probe_addr" "$probe_size")
done
set +e
"$oracle_tmp/flow_containedcall_rust" \
  "$oracle_tmp/fixture.text" "$text_base" "${probe_args[@]}" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
set -e
if [[ "$rudra_status" -ne 0 ]]; then
  echo "Rudra contained-call fixture failed with exit code $rudra_status" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit "$rudra_status"
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra contained-call fixture produced unexpected stderr" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
set +e
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/raw.diff" "$oracle_tmp/fixture.text" \
  "$oracle_tmp/flow_containedcall_cpp" "$ghidra_status" "$rudra_status" \
  "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
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
    ("ghidra_exit_code", int(sys.argv[9])),
    ("rugra_exit_code", int(sys.argv[10])),
    ("diff_exit_code", int(sys.argv[11])),
):
    if actual != metadata["expected_results"][key]:
        raise SystemExit(f"{key} mismatch")

text_path = pathlib.Path(sys.argv[7])
binary_path = pathlib.Path(sys.argv[8])
text_data = text_path.read_bytes()
readelf_output = subprocess.check_output(
    ["readelf", "-WS", str(binary_path)], text=True
)
text_lines = [line for line in readelf_output.splitlines() if re.search(r"\]\s+\.text\s", line)]
if len(text_lines) != 1:
    raise SystemExit(f"expected exactly one .text section, got {text_lines!r}")
section_match = re.search(
    r"\.text\s+PROGBITS\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s",
    text_lines[0],
)
if section_match is None:
    raise SystemExit(f"cannot parse .text section: {text_lines[0]!r}")
text_base = int(section_match.group(1), 16)
text_size = int(section_match.group(2), 16)
if len(text_data) != text_size:
    raise SystemExit(
        f"dumped .text size mismatch: section={text_size} bytes={len(text_data)}"
    )

nm_output = subprocess.check_output(
    ["nm", "-n", "-S", "--defined-only", str(binary_path)], text=True
)
symbols = []
for line in nm_output.splitlines():
    fields = line.split()
    if len(fields) != 4 or not fields[3].startswith("containedcall_"):
        continue
    if fields[2] != "T":
        raise SystemExit(f"contained-call symbol is not global text: {line!r}")
    symbols.append((fields[3], int(fields[0], 16), int(fields[1], 16)))

expected_records = metadata["machine_input"]["records"]
expected_names = [record["name"] for record in expected_records]
actual_names = [name for name, _, _ in symbols]
if actual_names != expected_names:
    raise SystemExit(
        f"contained-call symbol set/order mismatch: expected={expected_names} actual={actual_names}"
    )
origin = symbols[0][1]
previous_end = origin
actual_records = []
for index, (name, address, size) in enumerate(symbols):
    if address != previous_end:
        raise SystemExit(
            f"contained-call relative layout gap/overlap at {name}: "
            f"expected_address={previous_end:#x} actual_address={address:#x}"
        )
    start = address - text_base
    stop = start + size
    if start < 0 or stop > len(text_data):
        raise SystemExit(
            f"contained-call symbol boundary outside .text: {name} [{start},{stop})"
        )
    record = {
        "name": name,
        "relative_address": address - origin,
        "size": size,
        "bytes_hex": text_data[start:stop].hex(),
    }
    if record != expected_records[index]:
        raise SystemExit(
            f"contained-call machine record mismatch for {name}: "
            f"expected={expected_records[index]!r} actual={record!r}"
        )
    actual_records.append(record)
    previous_end = stop + text_base
machine_canonical = json.dumps(
    actual_records, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
machine_sha = hashlib.sha256(machine_canonical).hexdigest()
if machine_sha != metadata["machine_input"]["sha256"]:
    whole_text_sha = hashlib.sha256(text_data).hexdigest()
    raise SystemExit(
        f"contained-call canonical machine input mismatch: expected="
        f"{metadata['machine_input']['sha256']} actual={machine_sha} "
        f"noncomparand_whole_text={whole_text_sha}"
    )
records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
case_names = [
    record.split("=", 1)[1] for record in records if record.startswith("case=")
]
if case_names != [
    "containedcall_getpc", "containedcall_mid", "containedcall_fwd",
    "containedcall_offcut", "containedcall_beyond", "containedcall_multi",
    "containedcall_back", "containedcall_afterc", "containedcall_before",
    "containedcall_callind", "containedcall_extern",
]:
    raise SystemExit(f"observation order mismatch: {case_names}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0 or paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'flow_containedcall_1204: covered_projection=11/11 projection_status=MATCH overall_status=MISMATCH residual=TYPEOP-FSPEC-SPACE-0001\n'
