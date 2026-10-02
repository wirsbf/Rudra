#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
# HTTPD-ADDDESCEND-THROW-0001 dominator-root fixture runner.
#
# Compiles tests/oracle/block_domroot_1204.cc against the LOCKED Ghidra
# 12.0.4 oracle (exported fresh from the locked commit, libdecomp.a rebuilt
# in a temp dir), runs it, then builds the current Rudra crate and runs
# tests/oracle/block_domroot_1204.rs, and byte-diffs the two stdouts.
# Fixture hashes and the expected stdout sha256 are pinned in
# tests/oracle/block_domroot_1204.metadata.json.
#
# usage: run_block_domroot_oracle.sh [--ghidra-only]
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
runner="$repo_root/tools/run_block_domroot_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi

ghidra_only=false
if [[ ${1:-} == "--ghidra-only" ]]; then
  ghidra_only=true
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only]" >&2
  exit 2
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi

clean_path=/usr/bin:/bin
rust_toolchain=nightly-x86_64-unknown-linux-gnu
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/block_domroot_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/block_domroot_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_domroot_1204.rs"
block_rs="$repo_root/src/block.rs"

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/rustc"
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture" "$block_rs"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    echo "required input is not a regular non-symlink file: $required_file" >&2
    exit 1
  fi
done

# --- locked oracle identity -------------------------------------------------
actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

# --- pinned fixture identities ----------------------------------------------
expected_cpp_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["comparand"]["cpp_fixture_sha256"])' \
  "$metadata")
expected_rust_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["comparand"]["rust_fixture_sha256"])' \
  "$metadata")
expected_stdout_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' \
  "$metadata")
actual_cpp_sha=$(/usr/bin/sha256sum "$cpp_fixture" | /usr/bin/awk '{print $1}')
actual_rust_sha=$(/usr/bin/sha256sum "$rust_fixture" | /usr/bin/awk '{print $1}')
if [[ "$actual_cpp_sha" != "$expected_cpp_sha" || \
      "$actual_rust_sha" != "$expected_rust_sha" ]]; then
  echo "fixture hash mismatch (cpp: $actual_cpp_sha, rust: $actual_rust_sha)" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-block-domroot-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-block-domroot-1204.?????? ]]; then
    echo "refusing to remove unexpected temporary path: $oracle_tmp" >&2
    return 1
  fi
  if [[ -e "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    if [[ ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
      echo "refusing to remove non-directory temporary path: $oracle_tmp" >&2
      return 1
    fi
    /usr/bin/rm -rf -- "$oracle_tmp"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# --- export + rebuild the locked oracle, compile the C++ fixture -----------
oracle_archive="$oracle_tmp/ghidra-cpp.tar"
/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" CC="$host_cc_bin" AR="$host_ar_bin" \
    EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "locked archive rebuild did not produce a regular libdecomp.a" >&2
  exit 1
fi

cpp_binary="$oracle_tmp/block_domroot_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
    -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.cc" \
    "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
    -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
    -o "$cpp_binary" >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
ghidra_stdout_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | /usr/bin/awk '{print $1}')
if [[ "$ghidra_stdout_sha" != "$expected_stdout_sha" ]]; then
  echo "ghidra stdout sha256 mismatch: $ghidra_stdout_sha" >&2
  exit 1
fi
if [[ "$ghidra_only" == true ]]; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  printf 'block_domroot_1204: GHIDRA_LOCKED_OUTPUT_OK stdout_sha256=%s\n' "$ghidra_stdout_sha"
  exit 0
fi

# --- build the Rudra crate + compile the Rust fixture ----------------------
toolchain_bin=$(/usr/bin/dirname "$host_cargo_bin")
toolchain_path="$clean_path:$toolchain_bin"
fixture_target="$oracle_tmp/cargo-target"
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$toolchain_path" LC_ALL=C.UTF-8 \
  CARGO_TARGET_DIR="$fixture_target" \
  "$host_cargo_bin" build --offline --locked --quiet \
    --manifest-path "$repo_root/Cargo.toml" --lib \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do
  native_archives+=("$archive")
done < <(/usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f)
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "missing or ambiguous fresh Rust link inputs" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")

rust_binary="$oracle_tmp/block_domroot_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
    -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
    --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
    -l dylib=stdc++ -l dylib=m "$rust_fixture" -o "$rust_binary" \
    >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rustc.stdout" || -s "$oracle_tmp/rustc.stderr" ]]; then
  echo "Rust fixture compilation emitted diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$rust_binary" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
/usr/bin/diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e
if [[ "$rudra_status" -ne 0 || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture failed or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ "$diff_status" -ne 0 ]]; then
  /usr/bin/cat "$oracle_tmp/raw.diff" >&2
  exit 1
fi

printf 'block_domroot_1204: MATCH stdout_sha256=%s\n' "$ghidra_stdout_sha"
