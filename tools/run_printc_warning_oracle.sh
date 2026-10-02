#!/usr/bin/env -S -i PATH=/usr/sbin:/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# PRINTC-WARNING-COMMENT-0001 immutable two-sided oracle runner.
# Mirrors tools/run_comment_sorter_iterators_oracle.sh: identity-locked
# Ghidra 12.0.4 oracle archive build + isolated Rudra snapshot build with
# the owned src/printc.rs overlay, then byte comparison of the
# docFunction/emitBlockBasic comment-protocol emissions.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_printc_warning_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

clean_path=/usr/sbin:/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=9d0674c887aae01213490adb356933bef2853278
rudra_base_src_tree=9f18ac00a84cff5bbdb1d018a6d4f54e69a8d334
rudra_base_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_base_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
ghidra_root="$repo_root/ghidra"
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/sbin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/sbin/rustc)
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-printc-warning-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-printc-warning-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

/usr/bin/mkdir -p "$oracle_tmp/candidate"
for candidate in \
  tests/oracle/printc_warning_1204.metadata.json \
  tests/oracle/printc_warning_1204.cc \
  tests/oracle/printc_warning_1204.rs \
  src/printc.rs Cargo.toml Cargo.lock build.rs; do
  source_path="$repo_root/$candidate"
  if [[ ! -f "$source_path" || -L "$source_path" ]]; then
    echo "candidate must be a regular non-symlink file: $candidate" >&2
    exit 1
  fi
  /usr/bin/cp -- "$source_path" "$oracle_tmp/candidate/$(/usr/bin/basename "$candidate")"
done
metadata="$oracle_tmp/candidate/printc_warning_1204.metadata.json"
cpp_fixture="$oracle_tmp/candidate/printc_warning_1204.cc"
rust_fixture="$oracle_tmp/candidate/printc_warning_1204.rs"
printc_source="$oracle_tmp/candidate/printc.rs"

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$cpp_tree" != "$oracle_cpp_tree" || \
      "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra tree/blob mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
resolved_base=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
base_src_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:src")
base_cargo_toml_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.toml")
base_cargo_lock_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.lock")
base_build_rs_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:build.rs")
if [[ "$resolved_base" != "$rudra_base_commit" || \
      "$base_src_tree" != "$rudra_base_src_tree" || \
      "$base_cargo_toml_blob" != "$rudra_base_cargo_toml_blob" || \
      "$base_cargo_lock_blob" != "$rudra_base_cargo_lock_blob" || \
      "$base_build_rs_blob" != "$rudra_base_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

/usr/bin/mkdir -p "$oracle_tmp/ghidra" "$oracle_tmp/rudra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/ghidra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/rudra"
/usr/bin/cp -- "$printc_source" "$oracle_tmp/rudra/src/printc.rs"
/usr/bin/mkdir -p "$oracle_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" \
  "$oracle_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_cpp="$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$printc_source" \
  "$runner_fd_path" "$runner_snapshot_sha" "$oracle_commit" "$oracle_tag" \
  "$cpp_tree" "$makefile_blob" "$rudra_base_commit" "$base_src_tree" \
  "$base_cargo_toml_blob" "$base_cargo_lock_blob" "$base_build_rs_blob" \
  "$oracle_tmp/candidate/Cargo.toml" "$oracle_tmp/candidate/Cargo.lock" \
  "$oracle_tmp/candidate/build.rs" "$host_cxx_bin" "$host_cargo_bin" \
  "$host_rustc_bin" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name, cpp_name, rust_name, source_name, runner_name,
    runner_snapshot_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    rudra_base_commit, base_src_tree, base_cargo_toml_blob,
    base_cargo_lock_blob, base_build_rs_blob, cargo_toml_name,
    cargo_lock_name, build_rs_name, host_cxx_bin, host_cargo_bin,
    host_rustc_bin,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

require("schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "PRINTC-WARNING-COMMENT-0001")
require("projection status", metadata["projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "MISMATCH")
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle C++ tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("Rudra base", metadata["rugra_base_commit"], rudra_base_commit)
require("Rudra base src tree", metadata["rugra_source"]["base_src_tree"], base_src_tree)
require(
    "Rudra base Cargo.toml blob",
    metadata["rugra_source"]["base_cargo_toml_blob"],
    base_cargo_toml_blob,
)
require(
    "Rudra base Cargo.lock blob",
    metadata["rugra_source"]["base_cargo_lock_blob"],
    base_cargo_lock_blob,
)
require(
    "Rudra base build.rs blob",
    metadata["rugra_source"]["base_build_rs_blob"],
    base_build_rs_blob,
)
for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")
for case_name in ("clean_function", "noreturn_warning", "multi_warning"):
    status = metadata["coverage"][case_name]
    if not isinstance(status, str) or not status.startswith("MATCH"):
        raise SystemExit(f"coverage {case_name} must be MATCH: {status!r}")
require("residual binding", metadata["residual_todo_ids"],
        ["PRINTC-WARNING-COMMENT-0001"])

paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "printc_rs_sha256": pathlib.Path(source_name),
    "runner_sha256": pathlib.Path(runner_name),
    "cargo_toml_sha256": pathlib.Path(cargo_toml_name),
    "cargo_lock_sha256": pathlib.Path(cargo_lock_name),
    "build_rs_sha256": pathlib.Path(build_rs_name),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    require(key, actual, metadata["comparand"][key])
require("runner immutable descriptor", runner_snapshot_sha,
        metadata["comparand"]["runner_sha256"])

versions = {
    "host_cxx": subprocess.check_output([host_cxx_bin, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc_bin, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo_bin, "--version"], text=True).strip(),
}
for key, value in versions.items():
    require(key, value, metadata["comparand"][key])

payload = json.dumps(
    metadata["input_manifest"]["cases"],
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode()
require("input manifest fingerprint", hashlib.sha256(payload).hexdigest(),
        metadata["input_manifest"]["sha256"])
PY

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/printc_warning_cpp"

fixture_target="$oracle_tmp/cargo-target"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  CARGO_TARGET_DIR="$fixture_target" \
  CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
  AR="$host_ar_bin" RUSTC="$host_rustc_bin" RUSTFLAGS=-Awarnings \
  "$host_cargo_bin" build --offline --locked --quiet \
    --manifest-path "$oracle_tmp/rudra/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librudra_sleigh.a' -print -quit)
if [[ ! -f "$rudra_rlib" || ! -f "$native_archive" ]]; then
  echo "isolated Rudra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O -Awarnings \
  -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/printc_warning_rust"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/printc_warning_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/printc_warning_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" || -s "$oracle_tmp/rudra.stderr" ]]; then
  /usr/bin/sed -n '1,80p' "$oracle_tmp/ghidra.stderr" >&2
  /usr/bin/sed -n '1,80p' "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
expected_lines=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" <<'PYLINES'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["build"]["expected_stdout_lines"])
PYLINES
)
if [[ "$(/usr/bin/wc -l < "$oracle_tmp/ghidra.stdout")" -ne "$expected_lines" || \
      "$(/usr/bin/wc -l < "$oracle_tmp/rudra.stdout")" -ne "$expected_lines" ]]; then
  echo "unexpected fixture stdout line count" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PYVERDICT'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_out = pathlib.Path(sys.argv[2]).read_bytes()
rudra_out = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_sha = hashlib.sha256(ghidra_out).hexdigest()
rudra_sha = hashlib.sha256(rudra_out).hexdigest()
if ghidra_sha != metadata["comparand"]["expected_ghidra_stdout_sha256"]:
    raise SystemExit(f"oracle stdout fingerprint drift: {ghidra_sha}")
if rudra_sha != metadata["comparand"]["expected_rudra_stdout_sha256"]:
    raise SystemExit(f"Rudra stdout fingerprint drift: {rudra_sha}")
if ghidra_out != rudra_out:
    ghidra_lines = ghidra_out.decode().splitlines()
    rudra_lines = rudra_out.decode().splitlines()
    for number, (ghidra, rudra) in enumerate(zip(ghidra_lines, rudra_lines), 1):
        if ghidra != rudra:
            print(f"line {number} Ghidra: {ghidra}")
            print(f"line {number} Rudra:  {rudra}")
    raise SystemExit("covered projection mismatch")
print(f"covered_projection={len(ghidra_out.decode().splitlines())} lines byte-identical")
PYVERDICT

/usr/bin/cat "$oracle_tmp/ghidra.stdout"
/usr/bin/printf 'printc_warning_1204: covered_projection=%s/3 projection_status=MATCH overall_status=MISMATCH\n' \
  "$(/usr/bin/wc -l < "$oracle_tmp/ghidra.stdout")"
/usr/bin/printf 'residuals=PRINTC-WARNING-COMMENT-0001(e2e-curl-16-warning-confirmation-pending-root-merge)\n'
