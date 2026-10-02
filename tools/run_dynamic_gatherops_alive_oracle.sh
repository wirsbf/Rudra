#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=cb43401df869f5771f2c1acadc53de102773b4d9
rudra_source_tree=d1aa4cfc9588d53fbe8ac63e3a4becbdb2a2b518
rudra_source_src_tree=49d1c043da33bccc9b3d6be4dc357f988f2a2fb1
rudra_source_dynamic_blob=2bdfbcaa0c217b55d2173331876ac4e5d4fd23c6
rudra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_input_commit=bd781781bcdca6595bd2fbe2bd4151b47b605d30
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/dynamic_gatherops_alive_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/dynamic_gatherops_alive_1204.cc"
rust_fixture="$repo_root/tests/oracle/dynamic_gatherops_alive_1204.rs"
rust_overlay="$repo_root/src/dynamic.rs"
runner="$repo_root/tools/run_dynamic_gatherops_alive_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rudra-dynamic-gatherops-alive-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-dynamic-gatherops-alive-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$rust_overlay" \
  "$runner" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
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

resolved_source_commit=$(git -C "$repo_root" rev-parse "$rudra_source_commit^{commit}")
actual_source_tree=$(git -C "$repo_root" rev-parse "$rudra_source_commit^{tree}")
actual_source_src_tree=$(git -C "$repo_root" rev-parse "$rudra_source_commit:src")
actual_source_dynamic_blob=$(git -C "$repo_root" rev-parse "$rudra_source_commit:src/dynamic.rs")
actual_source_cargo_toml_blob=$(git -C "$repo_root" rev-parse "$rudra_source_commit:Cargo.toml")
actual_source_cargo_lock_blob=$(git -C "$repo_root" rev-parse "$rudra_source_commit:Cargo.lock")
actual_source_build_rs_blob=$(git -C "$repo_root" rev-parse "$rudra_source_commit:build.rs")
if [[ "$resolved_source_commit" != "$rudra_source_commit" || \
      "$actual_source_tree" != "$rudra_source_tree" || \
      "$actual_source_src_tree" != "$rudra_source_src_tree" || \
      "$actual_source_dynamic_blob" != "$rudra_source_dynamic_blob" || \
      "$actual_source_cargo_toml_blob" != "$rudra_source_cargo_toml_blob" || \
      "$actual_source_cargo_lock_blob" != "$rudra_source_cargo_lock_blob" || \
      "$actual_source_build_rs_blob" != "$rudra_source_build_rs_blob" ]]; then
  echo "pinned Rudra source identity mismatch" >&2
  exit 1
fi

resolved_input_commit=$(git -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
resolved_input_blob=$(git -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
input_blob_type=$(git -C "$repo_root" cat-file -t "$resolved_input_blob")
input_blob_size=$(git -C "$repo_root" cat-file -s "$resolved_input_blob")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$resolved_input_blob" != "$rudra_input_blob" || \
      "$input_blob_type" != blob ]]; then
  echo "pinned Rudra input Git object mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$oracle_tmp/input"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" "$snapshot_root/examples"
cp "$rust_overlay" "$snapshot_root/src/dynamic.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_dynamic_gatherops_alive_oracle.sh"
git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$snapshot_root/examples/curl"

for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  mkdir -p "$snapshot_root/$(dirname "$asset")"
  git -C "$repo_root" cat-file blob "$rudra_input_commit:$asset" >"$snapshot_root/$asset"
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$rust_overlay" "$runner" "$runner_sha" "$input_blob_size" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_source_dynamic_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" "$rudra_input_commit" "$rudra_input_blob" \
  "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, overlay_raw,
    runner_raw, runner_sha, binary_size, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, source_commit, source_tree, source_src_tree,
    source_dynamic_blob, source_cargo_toml_blob, source_cargo_lock_blob,
    source_build_rs_blob, input_commit, input_blob, bfd_header_raw,
    bfd_library_raw,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

expected_paths = {
    pathlib.Path(metadata_raw).resolve(): repo / "tests/oracle/dynamic_gatherops_alive_1204.metadata.json",
    pathlib.Path(cpp_raw).resolve(): repo / "tests/oracle/dynamic_gatherops_alive_1204.cc",
    pathlib.Path(rust_raw).resolve(): repo / "tests/oracle/dynamic_gatherops_alive_1204.rs",
    pathlib.Path(overlay_raw).resolve(): repo / "src/dynamic.rs",
    pathlib.Path(runner_raw).resolve(): repo / "tools/run_dynamic_gatherops_alive_oracle.sh",
}
for actual, expected in expected_paths.items():
    require("runner input path", actual, expected.resolve())

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "DYNAMIC-GATHEROPS-ALIVE-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec id", metadata["compiler_spec"]["id"], "gcc")

source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source dynamic blob", source["base_dynamic_blob"], source_dynamic_blob),
    ("source Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("source Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("source build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)
require("overlay path", source["overlay"]["path"], "src/dynamic.rs")
require(
    "overlay metadata hash",
    source["overlay"]["sha256"],
    metadata["comparand"]["dynamic_overlay_sha256"],
)

comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("dynamic_overlay_sha256", pathlib.Path(overlay_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha256", runner_sha, comparand["runner_sha256"])

assets = metadata["assets"]
require("compiler spec path binding", metadata["compiler_spec"]["path"], assets["compiler_spec"]["path"])
require("compiler spec hash binding", metadata["compiler_spec"]["sha256"], assets["compiler_spec"]["sha256"])
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source commit", record["source_repository_commit"], input_commit)
    require(f"{key} source ref", record["source_ref"], f"{input_commit}:{relative}")
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"], text=True
    ).strip()
    require(f"{key} Git blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} size", len(data), record["size"])
    require(f"{key} sha256", sha(data), record["sha256"])

binary = (snapshot / "examples/curl").read_bytes()
binary_record = assets["binary"]
require("binary source commit", binary_record["source_repository_commit"], input_commit)
require("binary Git blob", binary_record["git_blob_oid"], input_blob)
require("binary size", len(binary), int(binary_size))
require("binary metadata size", len(binary), binary_record["size"])
require("binary sha256", sha(binary), binary_record["sha256"])
require("BFD header sha256", sha(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library sha256", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "function": manifest["function"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha256", sha(canonical), manifest["sha256"])
require("overall status", metadata["overall_status"], "MATCH: (B2 canonicalization)")
for key in (
    "output_append_preserved", "dead_filtered", "same_address_seqnum_order",
    "lower_address_excluded", "upper_address_excluded", "empty_range_append_only",
    "bank_state_unchanged",
):
    require(f"coverage.{key}", metadata["coverage"][key], "MATCH")
PY

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/dynamic_gatherops_alive_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/dynamic_gatherops_alive_1204_rust"

set +e
"$oracle_tmp/dynamic_gatherops_alive_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/dynamic_gatherops_alive_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$snapshot_root/tests/oracle/dynamic_gatherops_alive_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
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
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")

records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if len(records) != 4 or [record.split("|", 1)[0] for record in records] != [
    "bank", "target", "empty", "post"
]:
    raise SystemExit(f"oracle observation shape mismatch: {records}")
if paths["ghidra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("Ghidra fixture stderr must be empty")
if paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("Rudra fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'dynamic_gatherops_alive_1204: covered_projection=7/7 overall_status=MATCH\n'
