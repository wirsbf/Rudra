#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=92daed300bcce3c4d855b311cf9667ba21eb475a
rugra_base_tree=6aea6d3b5b1421170d1bdc5a766c9568483a66af
rugra_base_src_tree=367bb531746f630fe4de5fddc0365c2c2f27eeda
rugra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
spec_input_commit=87aaef2262c85f4e6ffba488881fa4c1c8c2930f
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e

metadata="$repo_root/tests/oracle/callspec_identity_lifecycle_1204.json"
cpp_fixture="$repo_root/tests/oracle/callspec_identity_lifecycle_1204.cc"
rust_fixture="$repo_root/tests/oracle/callspec_identity_lifecycle_1204.rs"
runner="$repo_root/tests/oracle/run_callspec_identity_lifecycle_1204.sh"
ghidra_root="$repo_root/ghidra"

overlay_paths=(
  src/coreaction.rs
  src/flow.rs
  src/fspec.rs
  src/funcdata.rs
  src/heritage.rs
  src/ruleaction.rs
  src/signature.rs
  src/subflow.rs
  src/unionresolve.rs
  src/varnode.rs
)

cache_root=${RUDRA_CALLSPEC_IDENTITY_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-callspec-identity-1204}
mkdir -p "$cache_root/tmp" "$cache_root/target"
run_root=$(mktemp -d "$cache_root/run.XXXXXX")
cleanup() {
  case "$run_root" in
    "$cache_root"/run.??????) rm -rf -- "$run_root" ;;
    *) echo "refusing unsafe cleanup target: $run_root" >&2 ;;
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
  echo "locked Ghidra source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
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

snapshot_root="$run_root/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$run_root/rugra-base.tar" "$rugra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$run_root/rugra-base.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/callspec_identity_lifecycle_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/callspec_identity_lifecycle_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/callspec_identity_lifecycle_1204.json"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$spec_input_commit:$asset" \
    >"$snapshot_root/$asset"
done
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
# build.rs resolves the bundled C++ shim headers through ./ghidra.  The link
# targets the locked, identity-checked oracle checkout above; source overlays
# and the separately archived C++ oracle remain immutable inputs.
ln -s "$ghidra_root" "$snapshot_root/ghidra"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" \
  "$cpp_fixture" "$rust_fixture" "$runner_sha" "$oracle_commit" \
  "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rugra_base_commit" "$rugra_base_tree" \
  "$rugra_base_src_tree" "$rugra_cargo_toml_blob" "$rugra_cargo_lock_blob" \
  "$rugra_build_rs_blob" "$spec_input_commit" "$bfd_include/bfd.h" \
  "$bfd_library" "${overlay_paths[@]}" <<'PY'
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
snapshot = pathlib.Path(snapshot_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "CALLSPEC-IDENTITY-LIFECYCLE-D0-0001")
decisive = metadata.get("decisive_semantics")
require(
    "decisive semantic classes",
    set(decisive or {}),
    {
        "reference_output_parameters",
        "loop_bounds_traversal_order",
        "counter_accumulator_lifecycle",
        "sorting_comparison_keys",
    },
)
if any(not isinstance(value, str) or not value.strip() for value in decisive.values()):
    raise SystemExit("every decisive semantic description must be non-empty")

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
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")

source = metadata["rugra_source"]
for label, actual, expected in (
    ("base commit", source["base_commit"], base_commit),
    ("base tree", source["base_tree"], base_tree),
    ("base src tree", source["base_src_tree"], base_src_tree),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)
overlays = {record["path"]: record for record in source["overlays"]}
require("overlay paths", set(overlays), set(overlay_paths))
for relative in overlay_paths:
    live = repo / relative
    copied = snapshot / relative
    expected = overlays[relative]["sha256"]
    require(f"{relative} live sha", sha(live.read_bytes()), expected)
    require(f"{relative} snapshot sha", sha(copied.read_bytes()), expected)
build_link = source["snapshot_build_link"]
require("snapshot build link path", build_link["path"], "ghidra")
ghidra_link = snapshot / build_link["path"]
if not ghidra_link.is_symlink():
    raise SystemExit("snapshot ghidra build path is not a symlink")
require("snapshot ghidra link target", ghidra_link.resolve(), (repo / "ghidra").resolve())

comparand = metadata["comparand"]
require("C++ fixture sha", sha(pathlib.Path(cpp_raw).read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture sha", sha(pathlib.Path(rust_raw).read_bytes()), comparand["rust_fixture_sha256"])
require("runner sha", runner_sha, comparand["runner_sha256"])

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} commit", record["source_repository_commit"], spec_input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{spec_input_commit}:{relative}"],
        text=True,
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
    "construction": manifest["construction"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", sha(canonical), manifest["sha256"])

require("projection status", metadata["projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "MISMATCH")
valid = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residuals = set()
for key, record in metadata["coverage"].items():
    require(f"coverage.{key} fields", set(record), {"status", "covers", "residual_todo_ids"})
    if record["status"] not in valid or not record["covers"]:
        raise SystemExit(f"invalid coverage record: {key}")
    residuals = record["residual_todo_ids"]
    if record["status"] == "MATCH" and residuals:
        raise SystemExit(f"MATCH coverage has residuals: {key}")
    if record["status"] != "MATCH" and not residuals:
        raise SystemExit(f"non-MATCH coverage lacks residual: {key}")
    coverage_residuals.update(residuals)
require("coverage residual union", coverage_residuals, set(metadata["residual_todo_ids"]))
PY

if [[ ${RUDRA_CALLSPEC_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "callspec_identity_lifecycle_1204 metadata/source lock validation passed"
  exit 0
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$run_root/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$run_root/oracle-source"
tar -xf "$run_root/ghidra-cpp.tar" -C "$run_root/oracle-source"
oracle_cpp="$run_root/oracle-source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
if ! TMPDIR="$cache_root/tmp" make --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="g++ -std=c++11" EXTRA= libdecomp.a \
    >"$run_root/make.stdout" 2>"$run_root/make.stderr"; then
  cat "$run_root/make.stdout" "$run_root/make.stderr" >&2
  exit 1
fi
TMPDIR="$cache_root/tmp" g++ -std=c++11 -O0 -fno-pie -no-pie \
  -Wl,--build-id=none -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/callspec_identity_lifecycle_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$run_root/callspec_identity_cpp"

if ! /usr/bin/flock -x /tmp/rugra-cargo-build.lock env \
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cache_root/target" \
    TMPDIR="$cache_root/tmp" cargo build --offline --locked --quiet \
    --manifest-path "$snapshot_root/Cargo.toml" --lib \
    >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr"; then
  cat "$run_root/cargo.stdout" "$run_root/cargo.stderr" >&2
  exit 1
fi
TMPDIR="$cache_root/tmp" rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/callspec_identity_lifecycle_1204.rs" \
  --extern rugra="$cache_root/target/debug/librugra.rlib" \
  -L dependency="$cache_root/target/debug/deps" \
  -o "$run_root/callspec_identity_rust"

symbol_args=()
for symbol in callspec_identity_owner callspec_identity_clone_source \
  callspec_identity_clone_target callspec_identity_callee; do
  address=$(nm -n --defined-only "$run_root/callspec_identity_cpp" | \
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
LD_LIBRARY_PATH="$bfd_runtime" "$run_root/callspec_identity_cpp" \
  "$snapshot_root/sleigh_specs" \
  >"$run_root/ghidra.stdout" 2>"$run_root/ghidra.stderr"
ghidra_rc=$?
"$run_root/callspec_identity_rust" "${symbol_args[@]}" \
  >"$run_root/rugra.stdout" 2>"$run_root/rugra.stderr"
rugra_rc=$?
diff -u --label ghidra --label rugra \
  "$run_root/ghidra.stdout" "$run_root/rugra.stdout" \
  >"$run_root/raw.diff"
diff_rc=$?
set -e
if [[ "$diff_rc" -ne 0 ]]; then
  cat "$run_root/raw.diff" >&2
fi

objcopy --dump-section .text="$run_root/fixture.text" \
  "$run_root/callspec_identity_cpp"
python3 -I -S - "$metadata" "$run_root/ghidra.stdout" \
  "$run_root/ghidra.stderr" "$run_root/rugra.stdout" \
  "$run_root/rugra.stderr" "$run_root/raw.diff" "$run_root/fixture.text" \
  "$ghidra_rc" "$rugra_rc" "$diff_rc" <<'PY'
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
failures = []
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        failures.append(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[8])),
    ("rugra_exit_code", int(sys.argv[9])),
    ("diff_exit_code", int(sys.argv[10])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        failures.append(f"{key} mismatch: expected={expected} actual={actual}")
machine_sha = hashlib.sha256(pathlib.Path(sys.argv[7]).read_bytes()).hexdigest()
if machine_sha != metadata["machine_input_sha256"]["fixture_text"]:
    failures.append(
        "fixture text mismatch: "
        f"expected={metadata['machine_input_sha256']['fixture_text']} actual={machine_sha}"
    )
if failures:
    raise SystemExit("\n".join(failures))

expected_lines = [
    "case=identity same_addr=1 distinct_ops=1 distinct_specs=1 exact=[1,1,1] initial_order=[2,1,0]",
    "case=sort order=[0,1,2] owner_stable=1 annotation_stable=1 keys=[0:8388610,0:16777218,1:8388610]",
    "case=raw_const same_offset=1 resolved=0 space=const",
    "case=iop_guard real_iop_exact=1 typed_fspec_as_iop=0",
    "case=iop_guard_expired binding_present=1 owner_live=0 typed_fspec_as_iop=0",
    "case=delete count=2 order=[0,2] deleted_annotation_owned=0 survivor_exact=1 shifted_owner_stable=1",
    "case=clone source_count=1 target_count=1 new_owner=1 new_op=1 seq_equal=1 old_annotation_old=1 new_annotation_new=1 old_new_isolated=1 active_source=1/1 active_target=0/0 trials_source=1/1 trials_target=0/0 entry_same=1 stack_same=1",
]
actual_lines = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if actual_lines != expected_lines:
    raise SystemExit("locked callspec observation records changed")
if paths["ghidra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Ghidra stderr")
if paths["rugra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("unexpected Rugra stderr")
print(
    "callspec_identity_lifecycle_1204 oracle gate: covered identity projection MATCH; "
    "overall MISMATCH (TYPEOP-FSPEC-SPACE-0001, CALLSPEC-0001, OPBANK-0001, PIPE-STALL-SHAPE-0001)"
)
PY
