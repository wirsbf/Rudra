#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# OPTIONS-SPLITDATATYPE-SEMANTICS-0001 locked Ghidra 12.0.4/Rudra bilateral
# runner. The Rust side is built from the frozen production commit c3d12a2
# (OptionSplitDatatypes struct/array/pointer bit semantics, singular option
# name, p1-assign/p2|p3-OR order, toggleAction decision decomposition, and
# the 201-204 elem_ids) via a complete git archive, never from the live
# crate; no source overlays are applied.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_options_splitdatatype_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi

validate_only=0
if [[ $# -eq 1 && "$1" == "--validate-only" ]]; then
  validate_only=1
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--validate-only]" >&2
  exit 2
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
cache_root="$user_home/.cache/rudra-options-splitdatatype-1204"
# Task OPTIONS-SPLITDATATYPE-SEMANTICS-0001 dedicated Cargo dirs: every
# Cargo invocation below is serialized on the shared build flock and uses
# these isolated, pre-created directories (never /tmp or a shared target).
cargo_target=/home/wirs/.cache/a49-options-target
cargo_tmp=/home/wirs/.cache/a49-options-tmp
/usr/bin/mkdir -p "$cargo_target" "$cargo_tmp"
for cargo_dir in "$cargo_target" "$cargo_tmp"; do
  if [[ ! -d "$cargo_dir" || -L "$cargo_dir" ]]; then
    echo "dedicated Cargo directory is not a regular directory: $cargo_dir" >&2
    exit 1
  fi
done
/usr/bin/mkdir -p "$cache_root/tmp"
run_root=$(/usr/bin/mktemp -d "$cache_root/run.XXXXXX")
cleanup() {
  case "$run_root" in
    "$cache_root"/run.??????) /usr/bin/rm -rf -- "$run_root" ;;
    *) echo "refusing unsafe cleanup target: $run_root" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
oracle_options_cc_blob=e0778433e1c2df7ef310026d346dceac9de5a399
oracle_options_hh_blob=7a7f713b84f26f393d135fba673566e732c3afaa
rudra_source_commit=c3d12a20639a9e578c26dd6a416cc654310b8d96
rudra_source_tree=6f0976d073f6158102ccbfc403c59fdcf11ed059
rudra_source_src_tree=727e29f0027a02c7efaad7a06cfb949f3c3b786b
rudra_source_options_blob=b8734eb52066baf8a30f8e81846f9df3d3855932
rudra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_input_commit=34a3febff160031c265cfbd841a94022c68c2c19
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/options_splitdatatype_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/options_splitdatatype_1204.cc"
rust_fixture="$repo_root/tests/oracle/options_splitdatatype_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_header" "$bfd_library"; do
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
actual_options_cc_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/options.cc")
actual_options_hh_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/options.hh")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" || \
      "$actual_options_cc_blob" != "$oracle_options_cc_blob" || \
      "$actual_options_hh_blob" != "$oracle_options_hh_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_source_commit^{commit}:$rudra_source_commit" \
  "$rudra_source_commit^{tree}:$rudra_source_tree" \
  "$rudra_source_commit:src:$rudra_source_src_tree" \
  "$rudra_source_commit:src/options.rs:$rudra_source_options_blob" \
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

resolved_input_commit=$(git -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
resolved_input_blob=$(git -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
input_blob_size=$(git -C "$repo_root" cat-file -s "$resolved_input_blob")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$resolved_input_blob" != "$rudra_input_blob" ]]; then
  echo "pinned Rudra input Git object mismatch" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin HOME="$user_home" \
  /usr/bin/python3 - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_sha" "$input_blob_size" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$oracle_options_cc_blob" "$oracle_options_hh_blob" \
  "$rudra_source_commit" "$rudra_source_tree" "$rudra_source_src_tree" \
  "$rudra_source_options_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" "$rudra_input_commit" "$rudra_input_blob" \
  "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, runner_sha, binary_size,
    oracle_commit, oracle_tag, cpp_tree, language_tree, makefile_blob,
    options_cc_blob, options_hh_blob,
    source_commit, source_tree, source_src_tree, source_options_blob,
    source_cargo_toml_blob, source_cargo_lock_blob, source_build_rs_blob,
    input_commit, input_blob, bfd_header_raw, bfd_library_raw,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 1)
require("fixture", metadata["fixture_id"], "OPTIONS-SPLITDATATYPE-SEMANTICS-0001")
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
    ("oracle options.cc blob", oracle["options_cc_blob"], options_cc_blob),
    ("oracle options.hh blob", oracle["options_hh_blob"], options_hh_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default:gcc")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")
source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source options.rs blob", source["base_options_blob"], source_options_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)
require("runner sha", runner_sha, metadata["comparand"]["runner_sha256"])
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
):
    require(key, sha(path.read_bytes()), metadata["comparand"][key])
require("overlays", source.get("overlays"), [])

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source commit", record["source_repository_commit"], input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"], text=True
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
require("binary blob", assets["binary"]["git_blob_oid"], input_blob)
require("binary size", assets["binary"]["size"], int(binary_size))
require("BFD header", sha(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])
require("overall", metadata["overall_status"], "MATCH")
require("projection", metadata["covered_projection"]["bilateral_comparison"]["status"], "MATCH")
PY

if [[ "$validate_only" == 1 ]]; then
  echo "options_splitdatatype_1204: validation-only pass (pins and metadata verified)"
  exit 0
fi

snapshot_root="$run_root/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" \
  "$snapshot_root/examples" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$run_root/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs src sleigh_shim
tar -xf "$run_root/rudra-source.tar" -C "$snapshot_root"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/options_splitdatatype_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/options_splitdatatype_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/options_splitdatatype_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_options_splitdatatype_oracle.sh"
git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$snapshot_root/examples/curl"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$rudra_input_commit:$asset" >"$snapshot_root/$asset"
done

git -C "$ghidra_root" archive --format=tar \
  --output="$run_root/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$run_root/source"
tar -xf "$run_root/ghidra-cpp.tar" -C "$run_root/source"
oracle_cpp="$run_root/source/Ghidra/Features/Decompiler/src/decompile/cpp"
# build.rs expects a ghidra cpp tree inside the crate checkout.
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
nice -n 10 g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/options_splitdatatype_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$run_root/options_splitdatatype_1204_cpp"

CARGO_TARGET_DIR="$cargo_target" TMPDIR="$cargo_tmp" \
  nice -n 10 flock "$cargo_target" \
  env CARGO_TARGET_DIR="$cargo_target" TMPDIR="$cargo_tmp" HOME="$user_home" \
  cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
nice -n 10 rustc --edition=2021 \
  "$snapshot_root/tests/oracle/options_splitdatatype_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L "dependency=$cargo_target/debug/deps" \
  -o "$run_root/options_splitdatatype_1204_rust"

set +e
for round in 1 2; do
  LD_LIBRARY_PATH=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu \
    "$run_root/options_splitdatatype_1204_cpp" \
    "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
    >"$run_root/ghidra.stdout.$round" 2>"$run_root/ghidra.stderr.$round"
  eval "ghidra_status_$round=\$?"
  "$run_root/options_splitdatatype_1204_rust" \
    >"$run_root/rudra.stdout.$round" 2>"$run_root/rudra.stderr.$round"
  eval "rudra_status_$round=\$?"
done
diff -u --label ghidra --label rudra \
  "$run_root/ghidra.stdout.1" "$run_root/rudra.stdout.1" >"$run_root/raw.diff"
diff_status=$?
set -e

/usr/bin/env -i PATH=/usr/bin:/bin HOME="$user_home" \
  /usr/bin/python3 - "$metadata" "$run_root" \
  "$ghidra_status_1" "$ghidra_status_2" "$rudra_status_1" "$rudra_status_2" \
  "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
run_root = pathlib.Path(sys.argv[2])
ghidra_status_1, ghidra_status_2, rudra_status_1, rudra_status_2, diff_status = (
    int(arg) for arg in sys.argv[3:8]
)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

expected = metadata["expected_results"]
for round_id, suffix in ((1, "1"), (2, "2")):
    for side in ("ghidra", "rugra"):
        key = f"{side}_stdout_sha256"
        actual = sha(run_root / f"{side}.stdout.{suffix}")
        if actual != expected[key]:
            raise SystemExit(
                f"{side} stdout round {round_id} mismatch: "
                f"expected={expected[key]} actual={actual}"
            )
        err_path = run_root / f"{side}.stderr.{suffix}"
        if err_path.stat().st_size != 0:
            raise SystemExit(f"{side} stderr round {round_id} must be empty")
for key, actual in (
    ("ghidra_exit_code", ghidra_status_1),
    ("ghidra_exit_code_round2", ghidra_status_2),
    ("rugra_exit_code", rudra_status_1),
    ("rudra_exit_code_round2", rudra_status_2),
    ("diff_exit_code", diff_status),
):
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
records = (run_root / "ghidra.stdout.1").read_text(encoding="utf-8").splitlines()
if len(records) != expected["records"]:
    raise SystemExit(f"record count mismatch: {len(records)} != {expected['records']}")
bytes_total = (run_root / "ghidra.stdout.1").stat().st_size
if bytes_total != expected["bytes"]:
    raise SystemExit(f"byte count mismatch: {bytes_total} != {expected['bytes']}")
PY

cat "$run_root/ghidra.stdout.1"
printf 'options_splitdatatype_1204: covered_projection=MATCH overall_status=MATCH records=%s bytes=%s\n' \
  "$(wc -l <"$run_root/ghidra.stdout.1")" "$(wc -c <"$run_root/ghidra.stdout.1")"
