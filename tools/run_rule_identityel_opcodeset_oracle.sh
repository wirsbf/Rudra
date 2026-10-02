#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

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
runner="$repo_root/tools/run_rule_identityel_opcodeset_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

resolved_user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$resolved_user_home" || ! -d "$resolved_user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=15f84093c54b6befa066190fe0724133488306e4
rudra_base_tree=23eea775d84a6a34916c7502e648f32290ac8dfe
rudra_base_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rudra_base_action_blob=4ab1068cde61e05570d0941243b5e89ab098934f
rudra_base_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_base_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
input_commit=34a3febff160031c265cfbd841a94022c68c2c19
input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
ghidra_root="$repo_root/ghidra"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(/usr/bin/dirname "$bfd_library")
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for required in "$runner" "$bfd_header" "$bfd_library" "$host_cxx_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$host_python_bin" \
  "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -f "$required" || -L "$required" && "$required" == "$runner" ]]; then
    echo "required input is unavailable or invalid: $required" >&2
    exit 1
  fi
done

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-rule-identityel-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-rule-identityel-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

/usr/bin/mkdir -p "$oracle_tmp/candidate"
for candidate in \
  tests/oracle/rule_identityel_opcodeset_1204.metadata.json \
  tests/oracle/rule_identityel_opcodeset_1204.cc \
  tests/oracle/rule_identityel_opcodeset_1204.rs \
  src/ruleaction.rs Cargo.toml Cargo.lock build.rs; do
  source_path="$repo_root/$candidate"
  if [[ ! -f "$source_path" || -L "$source_path" ]]; then
    echo "candidate must be a regular non-symlink file: $candidate" >&2
    exit 1
  fi
  /usr/bin/cp -- "$source_path" "$oracle_tmp/candidate/$(/usr/bin/basename "$candidate")"
done
metadata="$oracle_tmp/candidate/rule_identityel_opcodeset_1204.metadata.json"
cpp_fixture="$oracle_tmp/candidate/rule_identityel_opcodeset_1204.cc"
rust_fixture="$oracle_tmp/candidate/rule_identityel_opcodeset_1204.rs"
ruleaction_source="$oracle_tmp/candidate/ruleaction.rs"

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_base_commit^{commit}:$rudra_base_commit" \
  "$rudra_base_commit^{tree}:$rudra_base_tree" \
  "$rudra_base_commit:src:$rudra_base_src_tree" \
  "$rudra_base_commit:src/action.rs:$rudra_base_action_blob" \
  "$rudra_base_commit:Cargo.toml:$rudra_base_cargo_toml_blob" \
  "$rudra_base_commit:Cargo.lock:$rudra_base_cargo_lock_blob" \
  "$rudra_base_commit:build.rs:$rudra_base_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git_bin" -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra base mismatch: $expression" >&2
    exit 1
  fi
done

resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$input_commit^{commit}")
resolved_input_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$input_commit:examples/curl")
input_blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$resolved_input_blob")
if [[ "$resolved_input_commit" != "$input_commit" || \
      "$resolved_input_blob" != "$input_blob" ]]; then
  echo "pinned Rudra input identity mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
/usr/bin/mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/examples"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-base.tar" "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches
/usr/bin/tar -xf "$oracle_tmp/rudra-base.tar" -C "$snapshot_root"
/usr/bin/cp -- "$ruleaction_source" "$snapshot_root/src/ruleaction.rs"
/usr/bin/cp -- "$cpp_fixture" "$snapshot_root/tests/oracle/rule_identityel_opcodeset_1204.cc"
/usr/bin/cp -- "$rust_fixture" "$snapshot_root/tests/oracle/rule_identityel_opcodeset_1204.rs"
/usr/bin/cp -- "$metadata" "$snapshot_root/tests/oracle/rule_identityel_opcodeset_1204.metadata.json"
/usr/bin/cp -- "$runner_fd_path" "$snapshot_root/tools/run_rule_identityel_opcodeset_oracle.sh"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$input_blob" \
  >"$snapshot_root/examples/curl"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  /usr/bin/mkdir -p "$snapshot_root/$(/usr/bin/dirname "$asset")"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git_bin" -C "$repo_root" cat-file blob "$input_commit:$asset" \
    >"$snapshot_root/$asset"
done

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$ruleaction_source" "$runner_snapshot_sha" "$input_blob_size" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$rudra_base_action_blob" \
  "$rudra_base_cargo_toml_blob" "$rudra_base_cargo_lock_blob" \
  "$rudra_base_build_rs_blob" "$input_commit" "$input_blob" \
  "$bfd_header" "$bfd_library" "$host_cxx_bin" "$host_cargo_bin" \
  "$host_rustc_bin" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, source_raw,
    runner_sha, binary_size, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, base_commit, base_tree, base_src_tree,
    base_action_blob, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    input_commit, input_blob, bfd_header_raw, bfd_library_raw,
    host_cxx, host_cargo, host_rustc,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "RULE-IDENTITYEL-OPCODESET-0001")
require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "MISMATCH")
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle cpp tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", metadata["oracle"]["x86_language_tree"], language_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
source = metadata["rugra_source"]
for label, actual, expected in (
    ("base commit", source["base_commit"], base_commit),
    ("base tree", source["base_tree"], base_tree),
    ("base src tree", source["base_src_tree"], base_src_tree),
    ("base action blob", source["base_action_rs_blob"], base_action_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("ruleaction_rs_sha256", pathlib.Path(source_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])

versions = {
    "host_cxx": subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo, "--version"], text=True).strip(),
}
for key, value in versions.items():
    require(key, value, comparand[key])

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
        ["git", "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"],
        text=True,
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} sha", sha(data), record["sha256"])
    require(f"{key} size", len(data), record["size"])
binary = (snapshot / "examples/curl").read_bytes()
require("binary blob", assets["binary"]["git_blob_oid"], input_blob)
require("binary size", len(binary), int(binary_size))
require("binary metadata size", len(binary), assets["binary"]["size"])
require("binary sha", sha(binary), assets["binary"]["sha256"])
require("BFD header", sha(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "functions": manifest["functions"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])
require(
    "residual bindings",
    metadata["residual_todo_ids"],
    ["ACTION-EXECUTOR-BREAKPOOL-0001", "PIPE-RULE-RAW-NAMES-0001"],
)
PY

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/rule_identityel_cpp"

fixture_target=/tmp/rudra-target-rule-identityel
# Serialize only Cargo's target mutation; oracle construction and comparison do
# not hold the shared build lane.
cargo_lock=/tmp/rudra-cargo-build.lock
/usr/bin/flock "$cargo_lock" /usr/bin/env -i \
  HOME="$resolved_user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  CARGO_HOME="$resolved_user_home/.cargo" CARGO_TARGET_DIR="$fixture_target" \
  CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CXX="$host_cxx_bin" CC="$host_cc_bin" \
  AR="$host_ar_bin" RUSTC="$host_rustc_bin" RUSTFLAGS=-Awarnings \
  "$host_cargo_bin" build --offline --locked --quiet \
    --manifest-path "$snapshot_root/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librudra_sleigh.a' -print -quit)
if [[ ! -f "$rudra_rlib" || ! -f "$native_archive" ]]; then
  echo "isolated Rudra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i HOME="$resolved_user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O -Awarnings \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" \
  -o "$oracle_tmp/rule_identityel_rust"

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
  "$oracle_tmp/rule_identityel_cpp" "$snapshot_root/sleigh_specs" \
  "$snapshot_root/examples/curl" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/rule_identityel_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/ghidra.covered" "$oracle_tmp/rudra.covered" <<'PYCOVER'
import pathlib
import sys

for source_name, target_name in ((sys.argv[1], sys.argv[3]), (sys.argv[2], sys.argv[4])):
    source = pathlib.Path(source_name).read_text(encoding="utf-8").splitlines()
    lookup = [line for line in source if line.startswith("lookup=")]
    if len(lookup) != 1:
        raise SystemExit("fixture must emit exactly one lookup record")
    covered = [line for line in source if not line.startswith("lookup=")]
    pathlib.Path(target_name).write_text("\n".join(covered) + "\n", encoding="utf-8")
PYCOVER
/usr/bin/diff -u --label ghidra-covered --label rudra-covered \
  "$oracle_tmp/ghidra.covered" "$oracle_tmp/rudra.covered" \
  >"$oracle_tmp/covered.diff"
covered_diff_status=$?
/usr/bin/diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$oracle_tmp/raw.diff"
raw_diff_status=$?
set -e

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/ghidra.covered" "$oracle_tmp/rudra.covered" \
  "$oracle_tmp/covered.diff" "$oracle_tmp/raw.diff" \
  "$ghidra_status" "$rudra_status" "$covered_diff_status" \
  "$raw_diff_status" <<'PYVERDICT'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
named_paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "ghidra_covered_sha256": pathlib.Path(sys.argv[6]),
    "rudra_covered_sha256": pathlib.Path(sys.argv[7]),
    "covered_diff_sha256": pathlib.Path(sys.argv[8]),
    "raw_diff_sha256": pathlib.Path(sys.argv[9]),
}
for key, path in named_paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[10])),
    ("rugra_exit_code", int(sys.argv[11])),
    ("covered_diff_exit_code", int(sys.argv[12])),
    ("raw_diff_exit_code", int(sys.argv[13])),
):
    if actual != metadata["expected_results"][key]:
        raise SystemExit(f"{key} mismatch")
if named_paths["ghidra_stderr_sha256"].stat().st_size != 0 or \
   named_paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("fixture stderr must be empty")
records = named_paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if [record.split("|", 1)[0] for record in records] != metadata["expected_results"]["record_order"]:
    raise SystemExit("observation order mismatch")
PYVERDICT

/usr/bin/cat "$oracle_tmp/ghidra.stdout"
/usr/bin/printf '%s\n' \
  'rule_identityel_opcodeset_1204: covered_projection=20/20 MATCH overall=MISMATCH'
/usr/bin/printf '%s\n' \
  'residuals=ACTION-EXECUTOR-BREAKPOOL-0001(getSubRule API),PIPE-RULE-RAW-NAMES-0001(other raw names)'
