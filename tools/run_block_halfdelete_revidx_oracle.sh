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
runner="$repo_root/tools/run_block_halfdelete_revidx_oracle.sh"
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

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=8d917bfe76fa53a0ead09b43e4ce1eddd1c90ce5
rudra_base_tree=6d1749977d38e63d6540a80917379b9777b1f94c
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/block_halfdelete_revidx_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/block_halfdelete_revidx_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_halfdelete_revidx_1204.rs"
block_rs="$repo_root/src/block.rs"
block_doc="$repo_root/docs/api/block.md"
cargo_target=/tmp/rudra-target-block-halfdelete
cargo_lock=/tmp/rudra-cargo-build.lock

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin" \
  /usr/bin/flock /usr/bin/grep; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$block_rs" \
  "$block_doc" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
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

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_rustc=$(/usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$block_rs" "$block_doc" \
  "$runner_fd_path" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$host_cxx" "$host_rustc" "$host_cargo" "$host_platform" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name, cpp_name, rust_name, block_name, doc_name, runner_name,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, rudra_base_commit,
    rudra_base_tree, host_cxx, host_rustc, host_cargo, host_platform,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))

if metadata["oracle"] != {
    "tag": oracle_tag,
    "commit": oracle_commit,
    "decompiler_cpp_tree": cpp_tree,
    "decompiler_makefile_blob": makefile_blob,
}:
    raise SystemExit("metadata oracle identity mismatch")
if metadata["fixture_id"] != "BLOCK-HALFDELETE-REVIDX-0001":
    raise SystemExit("fixture id mismatch")
if metadata["covered_projection_status"] != "MATCH":
    raise SystemExit("covered projection is not MATCH")
if not metadata["overall_status"].startswith("MATCH:"):
    raise SystemExit("overall status is not MATCH")
if metadata["comparand"].get("rugra_base_commit") != rudra_base_commit:
    raise SystemExit("Rudra base commit metadata mismatch")
if metadata["comparand"].get("rugra_base_tree") != rudra_base_tree:
    raise SystemExit("Rudra base tree metadata mismatch")

canonical_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
actual_fingerprint = "sha256:" + hashlib.sha256(canonical_input).hexdigest()
if metadata["input_fingerprint"] != actual_fingerprint:
    raise SystemExit(f"input fingerprint mismatch: {actual_fingerprint}")

comparands = {
    "cpp_fixture_sha256": cpp_name,
    "rust_fixture_sha256": rust_name,
    "block_rs_sha256": block_name,
    "block_doc_sha256": doc_name,
    "runner_sha256": runner_name,
}
for field, filename in comparands.items():
    actual = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
    if metadata["comparand"].get(field) != actual:
        raise SystemExit(f"comparand mismatch for {field}: {actual}")

expected_host = metadata["comparand"]["host"]
actual_host = {
    "cxx": host_cxx,
    "rustc": host_rustc,
    "cargo": host_cargo,
    "rust_toolchain": "system",
    "platform": host_platform,
}
if expected_host != actual_host:
    raise SystemExit(f"host identity mismatch: {actual_host}")
PY

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-block-halfdelete-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-block-halfdelete-1204.?????? ]]; then
    echo "refusing unexpected cleanup path: $oracle_tmp" >&2
    return 1
  fi
  if [[ -e "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    if [[ ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
      echo "refusing non-directory cleanup path: $oracle_tmp" >&2
      return 1
    fi
    /usr/bin/rm -rf -- "$oracle_tmp"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

owned=("$cpp_fixture" "$rust_fixture" "$block_rs" "$block_doc" "$metadata" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"

/usr/bin/mkdir -p "$oracle_tmp/rudra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-base.tar" "$rudra_base_commit"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar \
  -xf "$oracle_tmp/rudra-base.tar" -C "$oracle_tmp/rudra"
/usr/bin/cp -- "$block_rs" "$oracle_tmp/rudra/src/block.rs"
/usr/bin/ln -s "$ghidra_root" "$oracle_tmp/rudra/ghidra"

/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar \
  -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
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

cpp_binary="$oracle_tmp/block_halfdelete_revidx_1204_cpp"
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
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
ghidra_stdout_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | /usr/bin/awk '{print $1}')
expected_stdout_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' \
  "$metadata")
if [[ "$ghidra_stdout_sha" != "$expected_stdout_sha" ]]; then
  echo "Ghidra stdout sha256 mismatch: $ghidra_stdout_sha" >&2
  exit 1
fi
if [[ "$ghidra_only" == true ]]; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  /usr/bin/printf 'block_halfdelete_revidx_1204: GHIDRA_LOCKED_OUTPUT_OK stdout_sha256=%s\n' \
    "$ghidra_stdout_sha"
  exit 0
fi

/usr/bin/mkdir -p "$cargo_target"
if ! /usr/bin/flock "$cargo_lock" /usr/bin/env -i \
  HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  CARGO_TARGET_DIR="$cargo_target" CARGO_INCREMENTAL=0 \
  "$host_cargo_bin" build --offline --locked --quiet \
  --manifest-path "$oracle_tmp/rudra/Cargo.toml" --lib \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$cargo_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do
  build_output="$(/usr/bin/dirname "$(/usr/bin/dirname "$archive")")/output"
  if [[ -f "$build_output" ]] && /usr/bin/grep -Fqx \
    "cargo:rerun-if-changed=$oracle_tmp/rudra/sleigh_shim" "$build_output"; then
    native_archives+=("$archive")
  fi
done < <(/usr/bin/find "$cargo_target/debug/build" \
  -path '*/out/librudra_sleigh.a' -type f)
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "missing or ambiguous Rust link inputs" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
rust_binary="$oracle_tmp/block_halfdelete_revidx_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$cargo_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" -o "$rust_binary" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$rust_binary" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if ! /usr/bin/diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"; then
  exit 1
fi

/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.after"
if ! /usr/bin/cmp -s "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned input drifted while fixture ran" >&2
  exit 1
fi
/usr/bin/printf 'block_halfdelete_revidx_1204: MATCH stdout_sha256=%s\n' \
  "$ghidra_stdout_sha"
