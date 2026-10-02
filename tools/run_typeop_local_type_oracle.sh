#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# TYPEOP-LOCALTYPE-DISPATCH-0001 locked Ghidra 12.0.4/Rudra bilateral
# runner. The Rust side is built from the frozen D1 production commit
# (8b8b541, TypeOpCall::get_input_local port) via a complete git archive,
# never from the live crate; no source overlays are applied.

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
runner="$repo_root/tools/run_typeop_local_type_oracle.sh"
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

clean_path=/usr/bin:/bin
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache"
if [[ ! -d "$cache_parent" || -L "$cache_parent" ]]; then
  echo "cache parent is not a real directory: $cache_parent" >&2
  exit 1
fi
cache_root="$cache_parent/rudra-typeop-localtype-1204"
# Task TYPEOP-LOCALTYPE-DISPATCH-0001 D1 dedicated Cargo dirs: every Cargo
# invocation below is serialized on the shared build flock and uses these
# isolated, pre-created directories (never /tmp or a shared target).
cargo_target=/home/wirs/.cache/a1-typeop-target
cargo_tmp=/home/wirs/.cache/a1-typeop-tmp
/usr/bin/mkdir -p "$cargo_target" "$cargo_tmp"
for cargo_dir in "$cargo_target" "$cargo_tmp"; do
  if [[ ! -d "$cargo_dir" || -L "$cargo_dir" ]]; then
    echo "dedicated Cargo directory is not a regular directory: $cargo_dir" >&2
    exit 1
  fi
done
/usr/bin/mkdir -p "$cache_root/tmp" "$cache_root/target"
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

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=8b8b541993d61f971fddac53e439aa50a1028db3
rudra_base_tree=932f401c05dac390ced18f389f33057265ec7ecd
rudra_base_src_tree=8540c9803b5711ca848d13bce57cc37441ba0513
rudra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_binary_blob=76d9343ea3add321aa4134856323663b36365807
rudra_expected_records=167
rudra_expected_bytes=6367
rudra_expected_stdout_sha256=742c532e72f7653ccbfb24b1ec4708c732195dc95a16468978888b919df136f1
rudra_expected_stderr_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bilateral_expected_diff_exit_code=1
bilateral_expected_diff_records=12
bilateral_expected_diff_bytes=348
bilateral_expected_diff_sha256=bd841375a824e5e517c90a871b209b889a5038c862ade863c7b05d643d555487
ghidra_root="$repo_root/ghidra"
metadata_live="$repo_root/tests/oracle/typeop_local_type_1204.metadata.json"
cpp_fixture_live="$repo_root/tests/oracle/typeop_local_type_1204.cc"
rust_fixture_live="$repo_root/tests/oracle/typeop_local_type_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(/usr/bin/dirname "$bfd_library")

# D1 snapshot model: the frozen production commit already carries the
# TypeOpCall::get_input_local port, so the overlay table is empty.
overlay_paths=()
archive_paths=(
  Cargo.toml
  Cargo.lock
  build.rs
  README.md
  benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs
  tests/oracle/funcproto_lock_1204.rs
  examples/curl
  sleigh_specs
  src
  sleigh_shim
)

for required in "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
  "$bfd_include/bfd.h" "$bfd_library"; do
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

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra source is dirty" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra source has staged changes" >&2
  exit 1
fi

if [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}^{commit}")" != "$rudra_base_commit" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}^{tree}")" != "$rudra_base_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:src")" != "$rudra_base_src_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.toml")" != "$rudra_cargo_toml_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.lock")" != "$rudra_cargo_lock_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:build.rs")" != "$rudra_build_rs_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:examples/curl")" != "$rudra_binary_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

snapshot_root="$run_root/workspace"
/usr/bin/mkdir -p "$snapshot_root/tests/oracle"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$run_root/rudra-base.tar" "$rudra_base_commit" \
  "${archive_paths[@]}"
/usr/bin/tar -xf "$run_root/rudra-base.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  /usr/bin/cp "$repo_root/$relative" "$snapshot_root/$relative"
done
/usr/bin/cp "$cpp_fixture_live" "$snapshot_root/tests/oracle/typeop_local_type_1204.cc"
/usr/bin/cp "$rust_fixture_live" "$snapshot_root/tests/oracle/typeop_local_type_1204.rs"
/usr/bin/cp "$metadata_live" "$snapshot_root/tests/oracle/typeop_local_type_1204.metadata.json"
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
/usr/bin/ln -s "$ghidra_root" "$snapshot_root/ghidra"

verify_owned_inputs() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
    - "$repo_root" "$snapshot_root" "$metadata_live" "$cpp_fixture_live" \
    "$rust_fixture_live" "$runner_sha" "$oracle_commit" "$oracle_tag" \
    "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_base_commit" \
    "$rudra_base_tree" "$rudra_base_src_tree" "$rudra_cargo_toml_blob" \
    "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" "$rudra_binary_blob" \
    "$rudra_expected_records" "$rudra_expected_bytes" \
    "$rudra_expected_stdout_sha256" "$rudra_expected_stderr_sha256" \
    "$bilateral_expected_diff_exit_code" "$bilateral_expected_diff_records" \
    "$bilateral_expected_diff_bytes" "$bilateral_expected_diff_sha256" \
    "$bfd_include/bfd.h" "$bfd_library" "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, base_commit,
    base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    binary_blob, rudra_records, rudra_bytes, rudra_stdout_sha,
    rudra_stderr_sha, bilateral_diff_exit_code, bilateral_diff_records,
    bilateral_diff_bytes, bilateral_diff_sha, bfd_header_raw, bfd_library_raw,
    *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw).resolve()
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "TYPEOP-LOCALTYPE-DISPATCH-0001")
require("overall status", metadata["overall_status"], "MISMATCH")
require("oracle capture status", metadata["covered_projection"]["oracle_capture"]["status"], "ORACLE_CAPTURED")
require("Rudra execution status", metadata["covered_projection"]["rugra_execution"]["status"], "EXECUTED")
require("bilateral status", metadata["covered_projection"]["bilateral_comparison"]["status"], "MISMATCH")
require("Rudra build status", metadata["build"]["rugra_build_status"], "EXECUTED")
require("Cargo invocation evidence", metadata["build"]["cargo_invoked"], True)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle C++ tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)

comparand = metadata["comparand"]
require("base commit", comparand["rugra_base_commit"], base_commit)
require("base tree", comparand["rugra_base_tree"], base_tree)
require("base src tree", comparand["rugra_base_src_tree"], base_src_tree)
require("Cargo.toml blob", comparand["cargo_toml_blob"], cargo_toml_blob)
require("Cargo.lock blob", comparand["cargo_lock_blob"], cargo_lock_blob)
require("build.rs blob", comparand["build_rs_blob"], build_rs_blob)
require("binary blob", comparand["binary_blob"], binary_blob)
require(
    "snapshot model",
    comparand["snapshot_model"],
    "immutable complete D1 crate snapshot: git archive of the frozen production commit 8b8b541 with TypeOpCall::get_input_local; no source overlays",
)
require(
    "archive paths",
    comparand["archive_paths"],
    [
        "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
        "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
        "tests/oracle/funcproto_lock_1204.rs", "examples/curl",
        "sleigh_specs", "src", "sleigh_shim",
    ],
)
overlays = {record["path"]: record for record in comparand["overlays"]}
require("overlay paths", set(overlays), set(overlay_paths))
for relative in overlay_paths:
    expected = overlays[relative]["sha256"]
    require(f"{relative} live sha", sha(repo / relative), expected)
    require(f"{relative} snapshot sha", sha(snapshot / relative), expected)
for relative, expected in comparand["base_source_sha256"].items():
    require(f"{relative} snapshot base sha", sha(snapshot / relative), expected)

build_link = comparand["snapshot_build_link"]
require("snapshot build link path", build_link["path"], "ghidra")
link = snapshot / build_link["path"]
if not link.is_symlink():
    raise SystemExit("snapshot ghidra build path is not a symlink")
require("snapshot ghidra link target", link.resolve(), (repo / "ghidra").resolve())

require("C++ fixture hash", sha(cpp_raw), comparand["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_raw), comparand["rust_fixture_sha256"])
require("runner hash", runner_sha, comparand["runner_sha256"])

paired = metadata["paired_expected"]
require("paired Ghidra status", paired["ghidra"]["status"], "ORACLE_CAPTURED")
require("paired Ghidra runs", paired["ghidra"]["deterministic_runs"], metadata["locked_capture"]["deterministic_runs"])
require("paired Ghidra records", paired["ghidra"]["records"], metadata["locked_capture"]["records"])
require("paired Ghidra bytes", paired["ghidra"]["bytes"], metadata["locked_capture"]["bytes"])
require("paired Ghidra stdout", paired["ghidra"]["stdout_sha256"], metadata["locked_capture"]["stdout_sha256"])
require("paired Ghidra stderr", paired["ghidra"]["stderr_sha256"], metadata["locked_capture"]["stderr_sha256"])
require("paired Rudra status", paired["rugra"]["status"], "EXECUTED")
require("paired Rudra runs", paired["rugra"]["deterministic_runs"], 2)
require("paired Rudra records", paired["rugra"]["records"], int(rudra_records))
require("paired Rudra bytes", paired["rugra"]["bytes"], int(rudra_bytes))
require("paired Rudra stdout", paired["rugra"]["stdout_sha256"], rudra_stdout_sha)
require("paired Rudra stderr", paired["rugra"]["stderr_sha256"], rudra_stderr_sha)
require("bilateral expected status", paired["bilateral"]["status"], "MISMATCH")
require("bilateral diff exit code", paired["bilateral"]["diff_exit_code"], int(bilateral_diff_exit_code))
require("bilateral diff records", paired["bilateral"]["records"], int(bilateral_diff_records))
require("bilateral diff bytes", paired["bilateral"]["bytes"], int(bilateral_diff_bytes))
require("bilateral diff hash", paired["bilateral"]["diff_sha256"], bilateral_diff_sha)

asset_paths = {
    "sla_sha256": snapshot / "sleigh_specs/x86-64.sla",
    "pspec_sha256": snapshot / "sleigh_specs/x86-64.pspec",
    "cspec_sha256": snapshot / "sleigh_specs/x86-64-gcc.cspec",
    "ldefs_sha256": snapshot / "sleigh_specs/x86.ldefs",
    "binary_sha256": snapshot / "examples/curl",
    "bfd_header_sha256": pathlib.Path(bfd_header_raw),
    "bfd_library_sha256": pathlib.Path(bfd_library_raw),
}
for key, path in asset_paths.items():
    require(key, sha(path), metadata["assets"][key])

host = metadata["host_tools"]
require("host cxx", subprocess.check_output(["/usr/bin/g++", "--version"], text=True).splitlines()[0], host["cxx"])
require("host cxx target", subprocess.check_output(["/usr/bin/g++", "-dumpmachine"], text=True).strip(), host["cxx_target"])
require("host cc", subprocess.check_output(["/usr/bin/gcc", "--version"], text=True).splitlines()[0], host["cc"])
require("host cc target", subprocess.check_output(["/usr/bin/gcc", "-dumpmachine"], text=True).strip(), host["cc_target"])
require("host ar", subprocess.check_output(["/usr/bin/ar", "--version"], text=True).splitlines()[0], host["ar"])
require("host make", subprocess.check_output(["/usr/bin/make", "--version"], text=True).splitlines()[0], host["make"])
require("host python", subprocess.check_output(["/usr/bin/python3", "--version"], text=True).strip(), host["python"])
require("host git", subprocess.check_output(["/usr/bin/git", "--version"], text=True).strip(), host["git"])
require("host cargo", subprocess.check_output(["/usr/bin/cargo", "--version"], text=True).strip(), host["cargo"])
require("host rustc", subprocess.check_output(["/usr/bin/rustc", "--version"], text=True).strip(), host["rustc"])
for key, path in {
    "cargo": "/usr/bin/cargo",
    "rustc": "/usr/bin/rustc",
}.items():
    require(f"host {key} binary", sha(path), host["tool_binary_sha256"][key])
PY
}

verify_owned_inputs
if [[ "$validate_only" -eq 1 ]]; then
  echo "typeop_local_type_1204 metadata/source lock validation passed"
  exit 0
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$run_root"
oracle_cpp="$run_root/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$snapshot_root/sleigh_specs"
binary="$snapshot_root/examples/curl"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$cache_root/tmp" \
  "$host_make_bin" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx_bin -std=c++11" "EXTRA=" libdecomp.a \
  >"$run_root/make.stdout" 2>"$run_root/make.stderr"; then
  /usr/bin/cat "$run_root/make.stdout" >&2
  /usr/bin/cat "$run_root/make.stderr" >&2
  exit 1
fi
standard_archive="$oracle_cpp/libdecomp.a"
if [[ ! -f "$standard_archive" || -L "$standard_archive" ]]; then
  echo "locked Makefile did not produce a regular libdecomp.a" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$cache_root/tmp" \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/typeop_local_type_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$standard_archive" \
  "$bfd_library" -lz -o "$run_root/typeop_local_type_1204_cpp" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"; then
  /usr/bin/cat "$run_root/cxx.stdout" >&2
  /usr/bin/cat "$run_root/cxx.stderr" >&2
  exit 1
fi

if ! /usr/bin/flock -x /tmp/rudra-cargo-build.lock \
  /usr/bin/env -i PATH="$clean_path" HOME="$user_home" LC_ALL=C \
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" "$host_cargo_bin" build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib \
  >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr"; then
  /usr/bin/cat "$run_root/cargo.stdout" >&2
  /usr/bin/cat "$run_root/cargo.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" HOME="$user_home" LC_ALL=C \
  TMPDIR="$cargo_tmp" "$host_rustc_bin" --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/typeop_local_type_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$run_root/typeop_local_type_1204_rust" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"; then
  /usr/bin/cat "$run_root/rustc.stdout" >&2
  /usr/bin/cat "$run_root/rustc.stderr" >&2
  exit 1
fi

for run in 1 2; do
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
    "$run_root/typeop_local_type_1204_cpp" "$spec_root" "$binary" \
    >"$run_root/ghidra.$run.stdout" 2>"$run_root/ghidra.$run.stderr"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$run_root/typeop_local_type_1204_rust" \
    >"$run_root/rudra.$run.stdout" 2>"$run_root/rudra.$run.stderr"
done
if ! /usr/bin/cmp -s "$run_root/ghidra.1.stdout" "$run_root/ghidra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/ghidra.1.stderr" "$run_root/ghidra.2.stderr"; then
  echo "locked Ghidra repeated runs diverged" >&2
  exit 1
fi
if ! /usr/bin/cmp -s "$run_root/rudra.1.stdout" "$run_root/rudra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/rudra.1.stderr" "$run_root/rudra.2.stderr"; then
  echo "locked Rudra repeated runs diverged" >&2
  exit 1
fi

set +e
/usr/bin/diff -u --label ghidra --label rudra \
  "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" \
  >"$run_root/bilateral.diff"
diff_rc=$?
set -e
if [[ "$diff_rc" -gt 1 ]]; then
  echo "bilateral diff command failed with status $diff_rc" >&2
  exit 1
fi
if [[ "$diff_rc" -ne 0 ]]; then
  /usr/bin/cat "$run_root/bilateral.diff" >&2
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata_live" "$run_root/ghidra.1.stdout" \
  "$run_root/ghidra.1.stderr" "$run_root/rudra.1.stdout" \
  "$run_root/rudra.1.stderr" "$run_root/bilateral.diff" "$diff_rc" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_bytes()
ghidra_stderr = pathlib.Path(sys.argv[3]).read_bytes()
rudra_stdout = pathlib.Path(sys.argv[4]).read_bytes()
rudra_stderr = pathlib.Path(sys.argv[5]).read_bytes()
raw_diff = pathlib.Path(sys.argv[6]).read_bytes()
diff_rc = int(sys.argv[7])
capture = metadata["locked_capture"]
paired = metadata["paired_expected"]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

if not ghidra_stdout.endswith(b"\n") or not rudra_stdout.endswith(b"\n"):
    raise SystemExit("bilateral stdout lacks a final newline")
require("oracle records", len(ghidra_stdout.decode("utf-8").splitlines()), capture["records"])
require("oracle bytes", len(ghidra_stdout), capture["bytes"])
require("oracle stdout hash", sha(ghidra_stdout), capture["stdout_sha256"])
require("oracle stderr hash", sha(ghidra_stderr), capture["stderr_sha256"])
require("Rudra records", len(rudra_stdout.decode("utf-8").splitlines()), paired["rugra"]["records"])
require("Rudra bytes", len(rudra_stdout), paired["rugra"]["bytes"])
require("Rudra stdout hash", sha(rudra_stdout), paired["rugra"]["stdout_sha256"])
require("Rudra stderr hash", sha(rudra_stderr), paired["rugra"]["stderr_sha256"])
require("bilateral diff status", diff_rc, paired["bilateral"]["diff_exit_code"])
require("bilateral diff records", len(raw_diff.decode("utf-8").splitlines()), paired["bilateral"]["records"])
require("bilateral diff bytes", len(raw_diff), paired["bilateral"]["bytes"])
require("bilateral diff hash", sha(raw_diff), paired["bilateral"]["diff_sha256"])
if ghidra_stderr:
    raise SystemExit("locked oracle unexpectedly wrote stderr")
if rudra_stderr:
    raise SystemExit("Rudra fixture unexpectedly wrote stderr")

status = "MATCH" if diff_rc == 0 else "MISMATCH"
require("bilateral result status", status, paired["bilateral"]["status"])
print(
    f"oracle_records={len(ghidra_stdout.decode('utf-8').splitlines())} "
    f"oracle_bytes={len(ghidra_stdout)} "
    f"oracle_stdout_sha256={sha(ghidra_stdout)}"
)
print(f"oracle_stderr_sha256={sha(ghidra_stderr)}")
print(
    f"rudra_records={len(rudra_stdout.decode('utf-8').splitlines())} "
    f"rudra_bytes={len(rudra_stdout)} "
    f"rudra_stdout_sha256={sha(rudra_stdout)}"
)
print(f"rudra_stderr_sha256={sha(rudra_stderr)}")
print(
    f"bilateral_diff_records={len(raw_diff.decode('utf-8').splitlines())} "
    f"bilateral_diff_bytes={len(raw_diff)} "
    f"bilateral_diff_sha256={sha(raw_diff)} bilateral_status={status}"
)
print(
    "typeop_local_type_1204: oracle_status=ORACLE_CAPTURED "
    f"rudra_status=EXECUTED bilateral_status={status} overall_status=MISMATCH"
)
PY

verify_owned_inputs
