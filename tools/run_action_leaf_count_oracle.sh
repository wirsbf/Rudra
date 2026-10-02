#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH="/usr/bin:/bin" /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_action_leaf_count_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi
HOME=$user_home
export HOME

clean_path=/usr/bin:/bin
rust_toolchain=nightly-x86_64-unknown-linux-gnu
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_input_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
rudra_source_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_source_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_source_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_source_sleigh_shim_tree=c7729d9d1554dc62c486bcd7d58fdbf44bebb97d
rudra_source_coreaction_blob=e5fb0a75534d714556206c765e6cc075cf3bd8c3
rudra_source_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_source_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_source_paths=(
  Cargo.toml
  Cargo.lock
  build.rs
  README.md
  benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs
  tests/oracle/funcproto_lock_1204.rs
  src
  sleigh_shim
)
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/action_leaf_count_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/action_leaf_count_1204.cc"
rust_fixture="$repo_root/tests/oracle/action_leaf_count_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/rustc"
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    echo "required input is not a regular non-symlink file: $required_file" >&2
    exit 1
  fi
done
if [[ ! -d "$bfd_include" || -L "$bfd_include" ]]; then
  echo "BFD include closure is not a real non-symlink directory: $bfd_include" >&2
  exit 1
fi

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
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
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra commit/tree/blob identity mismatch" >&2
  exit 1
fi
locked_dirty=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra cpp/language worktree is dirty" >&2
  echo "$locked_dirty" >&2
  exit 1
fi

actual_repo_root=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse --show-toplevel)
if [[ "$actual_repo_root" != "$repo_root" ]]; then
  echo "unexpected Rudra repository root: $actual_repo_root" >&2
  exit 1
fi
resolved_source_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit^{commit}")
actual_source_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit^{tree}")
actual_source_src_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:src")
actual_source_sleigh_shim_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:sleigh_shim")
actual_source_coreaction_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:src/coreaction.rs")
actual_source_cargo_toml_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:Cargo.toml")
actual_source_cargo_lock_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:Cargo.lock")
actual_source_build_rs_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit:build.rs")
if [[ "$resolved_source_commit" != "$rudra_source_commit" || \
      "$actual_source_tree" != "$rudra_source_tree" || \
      "$actual_source_src_tree" != "$rudra_source_src_tree" || \
      "$actual_source_sleigh_shim_tree" != "$rudra_source_sleigh_shim_tree" || \
      "$actual_source_coreaction_blob" != "$rudra_source_coreaction_blob" || \
      "$actual_source_cargo_toml_blob" != "$rudra_source_cargo_toml_blob" || \
      "$actual_source_cargo_lock_blob" != "$rudra_source_cargo_lock_blob" || \
      "$actual_source_build_rs_blob" != "$rudra_source_build_rs_blob" ]]; then
  echo "pinned Rudra source commit/tree/blob identity mismatch" >&2
  exit 1
fi
resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
binary_blob_oid=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
binary_blob_type=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -t "$binary_blob_oid")
binary_blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$binary_blob_oid")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$binary_blob_oid" != "$rudra_input_blob" || "$binary_blob_type" != blob ]]; then
  echo "pinned Rudra binary commit/blob identity mismatch" >&2
  exit 1
fi

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-action-leaf-count-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-action-leaf-count-1204.?????? ]]; then
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
snapshot_root="$oracle_tmp/workspace"
cargo_home="$oracle_tmp/cargo-home"
registry_cache="$HOME/.cargo/registry/cache"
mkdir -p "$oracle_tmp/input" "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
    --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
    "${rudra_source_paths[@]}"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
binary="$oracle_tmp/input/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$binary_blob_oid" >"$binary"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$repo_root" "$snapshot_root" "$cargo_home" "$registry_cache" \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$runner_snapshot_sha" "$binary" "$rudra_input_commit" "$binary_blob_oid" \
  "$binary_blob_size" "$bfd_include" "$bfd_library" "$oracle_tag" \
  "$oracle_commit" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$host_cxx" "$host_cxx_target" "$host_rustc" \
  "$host_cargo" "$host_platform" "$host_cxx_bin" "$host_cargo_bin" \
  "$host_rustc_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$rust_toolchain" \
  "$rudra_source_commit" "$rudra_source_tree" "$rudra_source_src_tree" \
  "$rudra_source_sleigh_shim_tree" "$rudra_source_coreaction_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import tarfile

(
    repo_raw, snapshot_raw, cargo_home_raw, registry_cache_raw, metadata_raw,
    cpp_fixture_raw, rust_fixture_raw, runner_raw, runner_sha, binary_raw,
    input_commit, binary_oid, binary_size, bfd_include_raw, bfd_library_raw,
    oracle_tag, oracle_commit, cpp_tree, language_tree, makefile_blob,
    host_cxx, host_cxx_target, host_rustc, host_cargo, host_platform,
    host_cxx_bin, host_cargo_bin, host_rustc_bin, host_cc_bin, host_ar_bin,
    host_make_bin, host_python_bin, host_git_bin, rust_toolchain,
    source_commit, source_tree, source_src_tree, source_sleigh_shim_tree,
    source_coreaction_blob, source_cargo_toml_blob, source_cargo_lock_blob,
    source_build_rs_blob,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo / "tests/oracle/action_leaf_count_1204.metadata.json",
    pathlib.Path(cpp_fixture_raw): repo / "tests/oracle/action_leaf_count_1204.cc",
    pathlib.Path(rust_fixture_raw): repo / "tests/oracle/action_leaf_count_1204.rs",
    pathlib.Path(runner_raw): repo / "tools/run_action_leaf_count_oracle.sh",
}
for actual, expected in expected_paths.items():
    if actual.resolve() != expected.resolve():
        raise SystemExit(f"unexpected runner input path: {actual} != {expected}")

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is still pending: {value}")

def live_file(relative):
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"live overlay/input must be a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

archive_paths = [
    "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs", "src", "sleigh_shim",
]
archive_files = []
for path in snapshot.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"pinned Rudra archive rejects symlink: {path}")
    if path.is_file():
        relative = path.relative_to(snapshot)
        key = relative.as_posix()
        if not any(key == root or key.startswith(root + "/") for root in archive_paths):
            raise SystemExit(f"file outside explicit Rudra source closure: {key}")
        archive_files.append(relative)
archive_files.sort(key=lambda item: item.as_posix())
if not archive_files:
    raise SystemExit("pinned Rudra archive is empty")
for required in (
    "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs", "src/lib.rs", "src/coreaction.rs",
    "sleigh_shim/rudra_sleigh.cpp",
):
    path = snapshot / required
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"pinned Rudra closure is missing regular file: {required}")

base_bytes = {}
base_hasher = hashlib.sha256()
base_hasher.update(b"rudra-action-leaf-base-closure-v1\0")
for relative in archive_files:
    data = (snapshot / relative).read_bytes()
    key = relative.as_posix()
    base_bytes[key] = data
    encoded = key.encode("utf-8")
    base_hasher.update(len(encoded).to_bytes(8, "big"))
    base_hasher.update(encoded)
    base_hasher.update(len(data).to_bytes(8, "big"))
    base_hasher.update(data)

special_paths = [
    "tests/oracle/action_leaf_count_1204.cc",
    "tests/oracle/action_leaf_count_1204.rs",
    "tests/oracle/action_leaf_count_1204.metadata.json",
    "tools/run_action_leaf_count_oracle.sh",
    "sleigh_specs/x86-64.sla", "sleigh_specs/x86-64.pspec",
    "sleigh_specs/x86-64-gcc.cspec", "sleigh_specs/x86.ldefs",
]
special = {path: live_file(path) for path in special_paths}
metadata = json.loads(special["tests/oracle/action_leaf_count_1204.metadata.json"])

source = metadata["rugra_source"]
require("Rudra source commit", source["commit"], source_commit)
require("Rudra source tree", source["tree"], source_tree)
require("Rudra src tree", source["src_tree"], source_src_tree)
require("Rudra sleigh_shim tree", source["sleigh_shim_tree"], source_sleigh_shim_tree)
require("Rudra base coreaction blob", source["base_coreaction_blob"], source_coreaction_blob)
require("Rudra Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob)
require("Rudra Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob)
require("Rudra build.rs blob", source["build_rs_blob"], source_build_rs_blob)
require("Rudra archive paths", source["archive_paths"], archive_paths)
require(
    "Rudra archive policy",
    source["archive_policy"],
    "Extract only the explicit dependency closure from the pinned commit; never read live crate files and never require runtime HEAD equality",
)
require(
    "Rudra base closure hash scheme",
    source["base_closure_hash_scheme"],
    "sha256 of rudra-action-leaf-base-closure-v1 plus sorted length-prefixed relative paths and pinned archive contents",
)
reject_pending(source["base_closure_sha256"], "rudra_source.base_closure_sha256")
require("Rudra base closure", source["base_closure_sha256"], base_hasher.hexdigest())
require("Rudra base coreaction sha256", source["base_coreaction_sha256"], sha(base_bytes["src/coreaction.rs"]))

overlay = source["overlay"]
require("Rudra overlay path", overlay["path"], "src/coreaction.rs")
require(
    "Rudra overlay policy",
    overlay["policy"],
    "The sole live library-source input; hash before replacing the pinned archive's src/coreaction.rs",
)
overlay_path = repo / overlay["path"]
if overlay_path.is_symlink() or not overlay_path.is_file():
    raise SystemExit(f"Rudra overlay is not a regular file: {overlay_path}")
overlay_bytes = overlay_path.read_bytes()
reject_pending(overlay["sha256"], "rudra_source.overlay.sha256")
require("Rudra coreaction overlay", overlay["sha256"], sha(overlay_bytes))
(snapshot / overlay["path"]).write_bytes(overlay_bytes)

binary_source = pathlib.Path(binary_raw)
expected_binary_source = snapshot.parent / "input" / "curl"
if (
    binary_source.resolve() != expected_binary_source.resolve()
    or binary_source.is_symlink()
    or not binary_source.is_file()
):
    raise SystemExit(f"unexpected committed binary snapshot: {binary_source}")
binary_data = binary_source.read_bytes()
(snapshot / "examples").mkdir()
(snapshot / "examples/curl").write_bytes(binary_data)

external_root = snapshot / "external"
external_root.mkdir()
bfd_include_source = pathlib.Path(bfd_include_raw)
if bfd_include_source.is_symlink() or not bfd_include_source.is_dir():
    raise SystemExit(f"BFD include closure is not a real directory: {bfd_include_source}")
bfd_include_snapshot = external_root / "include"
bfd_include_snapshot.mkdir()
for path in sorted(bfd_include_source.iterdir(), key=lambda item: item.name):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"BFD include entry is not a regular non-symlink file: {path}")
    shutil.copyfile(path, bfd_include_snapshot / path.name)
bfd_library_source = pathlib.Path(bfd_library_raw)
if bfd_library_source.is_symlink() or not bfd_library_source.is_file():
    raise SystemExit(f"BFD library is not a regular non-symlink file: {bfd_library_source}")
shutil.copyfile(bfd_library_source, external_root / "libbfd.so")

oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")

assets = metadata["assets"]
asset_data = {
    "sla": special["sleigh_specs/x86-64.sla"],
    "processor_spec": special["sleigh_specs/x86-64.pspec"],
    "compiler_spec": special["sleigh_specs/x86-64-gcc.cspec"],
    "language_definitions": special["sleigh_specs/x86.ldefs"],
    "binary": binary_data,
}
asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
    "binary": "examples/curl",
}
for key, data in asset_data.items():
    require(f"assets.{key}.path", assets[key]["path"], asset_paths[key])
    require(f"assets.{key}.sha256", assets[key]["sha256"], sha(data))
require("binary size", assets["binary"]["size"], len(binary_data))
require("binary source commit", assets["binary"]["source_repository_commit"], input_commit)
require("binary blob", assets["binary"]["git_blob_oid"], binary_oid)
require("binary blob size", assets["binary"]["size"], int(binary_size))
require(
    "binary source policy",
    assets["binary"]["source_policy"],
    "Materialize the pinned provenance commit's examples/curl Git blob by verified object ID; never read the working-tree file and never require runtime HEAD equality",
)

require("BFD include", assets["bfd"]["include_path"], bfd_include_raw)
require("BFD header path", assets["bfd"]["header_path"], str(pathlib.Path(bfd_include_raw) / "bfd.h"))
require("BFD library path", assets["bfd"]["library_path"], bfd_library_raw)
require("BFD header", assets["bfd"]["header_sha256"], sha((bfd_include_snapshot / "bfd.h").read_bytes()))
bfd_tree_hasher = hashlib.sha256()
bfd_tree_hasher.update(b"bfd-include-tree-v1\0")
for path in sorted(bfd_include_snapshot.iterdir(), key=lambda item: item.name):
    data = path.read_bytes()
    name = path.name.encode("utf-8")
    bfd_tree_hasher.update(len(name).to_bytes(8, "big"))
    bfd_tree_hasher.update(name)
    bfd_tree_hasher.update(len(data).to_bytes(8, "big"))
    bfd_tree_hasher.update(data)
require("BFD include tree", assets["bfd"]["include_tree_sha256"], bfd_tree_hasher.hexdigest())
require("BFD library", assets["bfd"]["library_sha256"], sha((external_root / "libbfd.so").read_bytes()))

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha(special["tests/oracle/action_leaf_count_1204.cc"]),
    "rust_fixture_sha256": sha(special["tests/oracle/action_leaf_count_1204.rs"]),
    "runner_sha256": runner_sha,
    "host_cxx": host_cxx,
    "host_cxx_target": host_cxx_target,
    "host_cxx_path": host_cxx_bin,
    "host_rustc": host_rustc,
    "host_cargo": host_cargo,
    "host_cargo_path": host_cargo_bin,
    "host_rustc_path": host_rustc_bin,
    "host_cc_path": host_cc_bin,
    "host_ar_path": host_ar_bin,
    "host_make_path": host_make_bin,
    "host_python_path": host_python_bin,
    "host_git_path": host_git_bin,
    "host_rust_toolchain": rust_toolchain,
    "host_platform": host_platform,
}
require("runner snapshot/live", sha(special["tools/run_action_leaf_count_oracle.sh"]), runner_sha)
for key, actual in observed.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require(f"comparand.{key}", comparand[key], actual)

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
require("input manifest", manifest["sha256"], sha(canonical))
if metadata["expected_stdout_sha256"].startswith("PENDING_"):
    raise SystemExit("expected stdout hash is pending")

if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit(f"registry archive cache is not a real directory: {registry_cache}")
package_blocks = base_bytes["Cargo.lock"].decode("utf-8").split("[[package]]")[1:]
registry_packages = []
for block in package_blocks:
    fields = {}
    for field in ("name", "version", "source", "checksum"):
        match = re.search(rf'(?m)^{field} = "([^"\\]+)"$', block)
        if match:
            fields[field] = match.group(1)
    package_source = fields.get("source")
    if package_source is None:
        continue
    if package_source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"unsupported Cargo source in locked closure: {package_source}")
    for required in ("name", "version", "checksum"):
        if required not in fields:
            raise SystemExit(f"registry package missing {required}: {block[:160]!r}")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require("locked registry package count", metadata["build"]["registry_packages"], len(registry_packages))

vendor_root = snapshot / "vendor"
vendor_root.mkdir()
for name, version, checksum in registry_packages:
    archive_name = f"{name}-{version}.crate"
    matches = []
    for namespace in registry_cache.iterdir():
        if namespace.is_symlink() or not namespace.is_dir():
            raise SystemExit(f"registry cache namespace is not a real directory: {namespace}")
        candidate = namespace / archive_name
        if candidate.exists():
            matches.append(candidate)
    if len(matches) != 1:
        raise SystemExit(f"expected one cached archive for {name} {version}, found {matches}")
    archive_path = matches[0]
    if archive_path.is_symlink() or not archive_path.is_file():
        raise SystemExit(f"crate archive is not a regular file: {archive_path}")
    archive_bytes = archive_path.read_bytes()
    require(f"Cargo.lock checksum for {name} {version}", sha(archive_bytes), checksum)
    package_root_name = f"{name}-{version}"
    package_root = vendor_root / package_root_name
    package_root.mkdir()
    file_hashes = {}
    seen_paths = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = pathlib.PurePosixPath(member.name)
            parts = member_path.parts
            if not parts or parts[0] != package_root_name or any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"unsafe crate member path: {member.name!r}")
            relative_parts = parts[1:]
            if not relative_parts:
                if not member.isdir():
                    raise SystemExit(f"crate root is not a directory: {member.name!r}")
                continue
            relative = pathlib.PurePosixPath(*relative_parts)
            relative_key = relative.as_posix()
            if relative_key in seen_paths:
                raise SystemExit(f"duplicate crate member path: {member.name!r}")
            seen_paths.add(relative_key)
            destination = package_root.joinpath(*relative_parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(member.mode & 0o777)
                continue
            if not member.isfile():
                raise SystemExit(f"unsupported crate member type: {member.name!r}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_file = archive.extractfile(member)
            if source_file is None:
                raise SystemExit(f"crate member has no data: {member.name!r}")
            data = source_file.read()
            if len(data) != member.size:
                raise SystemExit(f"short crate member read: {member.name!r}")
            destination.write_bytes(data)
            destination.chmod(member.mode & 0o777)
            file_hashes[relative_key] = sha(data)
    if not (package_root / "Cargo.toml").is_file():
        raise SystemExit(f"vendored crate has no Cargo.toml: {name} {version}")
    checksum_record = json.dumps(
        {"files": file_hashes, "package": checksum}, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    (package_root / ".cargo-checksum.json").write_bytes(checksum_record)

cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\n"
    'replace-with = "locked-vendor"\n\n'
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor_root))}\n",
    encoding="utf-8",
)
PY

metadata="$snapshot_root/tests/oracle/action_leaf_count_1204.metadata.json"
cpp_fixture="$snapshot_root/tests/oracle/action_leaf_count_1204.cc"
rust_fixture="$snapshot_root/tests/oracle/action_leaf_count_1204.rs"
spec_root="$snapshot_root/sleigh_specs"
binary="$snapshot_root/examples/curl"
bfd_include="$snapshot_root/external/include"
bfd_library="$snapshot_root/external/libbfd.so"

mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"
jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a \
    >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/action_leaf_count_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

fixture_target="$oracle_tmp/cargo-target"
for cargo_config in \
  "$snapshot_root/.cargo/config" "$snapshot_root/.cargo/config.toml" \
  "$oracle_tmp/.cargo/config" "$oracle_tmp/.cargo/config.toml" \
  "/tmp/.cargo/config" "/tmp/.cargo/config.toml" \
  "/.cargo/config" "/.cargo/config.toml"; do
  if [[ -e "$cargo_config" ]]; then
    echo "ambient Cargo config is outside the comparand: $cargo_config" >&2
    exit 1
  fi
done
if ! (
  cd "$snapshot_root"
  /usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
    RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
    AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib \
      --manifest-path "$snapshot_root/Cargo.toml"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "isolated Cargo build did not produce one Rudra library/native archive" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" \
  -o "$oracle_tmp/action_leaf_count_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/action_leaf_count_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/action_leaf_count_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout = pathlib.Path(sys.argv[2]).read_bytes()
lines = stdout.decode("utf-8").splitlines()
if len(lines) != 1:
    raise SystemExit(f"expected one JSON line, found {len(lines)}")
document = json.loads(lines[0])
if document.get("schema") != 1 or document.get("fixture") != "PIPE-ACTION-COUNT-0001A":
    raise SystemExit("invalid action leaf fixture envelope")
if document.get("function") != {"name": "GetStr", "entry": 14032, "size": 0}:
    raise SystemExit("unexpected Funcdata identity")
cases = document.get("cases", [])
if [case.get("id") for case in cases] != ["fullloop_starttypes", "once_zero_work"]:
    raise SystemExit("case order mismatch")

start = cases[0]
if start["child_order"] != ["typeobserver", "starttypes"]:
    raise SystemExit("StartTypes child order mismatch")
events = start["events"]
if [event["label"] for event in events] != ["reset_1", "perform_1", "reset_2", "perform_2"]:
    raise SystemExit("StartTypes event order mismatch")
if [event["return"] for event in events] != [None, 1, None, 0]:
    raise SystemExit("StartTypes return sequence mismatch")
if [event["observed_started"] for event in events] != [[], [False, True], [], [True]]:
    raise SystemExit("StartTypes repeat-phase observation mismatch")
if events[1]["group"] != {"status": 1, "count": 1, "lcount": 1, "count_tests": 1, "count_apply": 1}:
    raise SystemExit("StartTypes parent repeat state mismatch")
if events[2]["group"] != events[1]["group"]:
    raise SystemExit("group reset did not preserve counters/statistics")
if events[3]["group"] != {"status": 1, "count": 0, "lcount": 0, "count_tests": 2, "count_apply": 1}:
    raise SystemExit("same-Funcdata group rerun state mismatch")
expected_start_states = [
    ({"status": 1, "count": 0, "lcount": 0, "count_tests": 0, "count_apply": 0}, 0, 1),
    ({"status": 1, "count": 0, "lcount": 0, "count_tests": 2, "count_apply": 1}, 2, 1),
    ({"status": 1, "count": 0, "lcount": 0, "count_tests": 2, "count_apply": 1}, 2, 2),
    ({"status": 1, "count": 0, "lcount": 0, "count_tests": 3, "count_apply": 1}, 3, 2),
]
for event, (state, apply_calls, reset_calls) in zip(events, expected_start_states):
    leaf = event["starttypes"]
    if leaf["raw_flags"] != 0 or leaf["effective_flags"] != 0:
        raise SystemExit("StartTypes flags mismatch")
    if leaf["executor"] != state or leaf["apply_calls"] != apply_calls or leaf["reset_calls"] != reset_calls:
        raise SystemExit("StartTypes leaf executor/call state mismatch")

once = cases[1]
order = ["prototypetypes", "defaultparams", "extrapopsetup", "funclink", "funclink_outonly", "internalstorage"]
if once["action_order"] != order or [item["id"] for item in once["actions"]] != order:
    raise SystemExit("once action order mismatch")
expected_states = [
    {"status": 1, "count": 0, "lcount": 0, "count_tests": 0, "count_apply": 0},
    {"status": 16, "count": 0, "lcount": 0, "count_tests": 1, "count_apply": 0},
    {"status": 16, "count": 0, "lcount": 0, "count_tests": 1, "count_apply": 0},
    {"status": 1, "count": 0, "lcount": 0, "count_tests": 1, "count_apply": 0},
    {"status": 16, "count": 0, "lcount": 0, "count_tests": 2, "count_apply": 0},
]
base_data = {
    "type_recovery_on": True, "type_recovery_started": True,
    "calls": 0, "alive_ops": 0, "blocks": 0, "varnodes": 0,
    "model_locked": True, "input_locked": True, "output_locked": True,
    "model": "__stdcall", "active_output": False,
}
for item in once["actions"]:
    action_events = item["events"]
    if [event["label"] for event in action_events] != ["reset_1", "perform_1", "perform_2", "reset_2", "perform_3"]:
        raise SystemExit(f"{item['id']} event order mismatch")
    if [event["return"] for event in action_events] != [None, 0, 0, None, 0]:
        raise SystemExit(f"{item['id']} return sequence mismatch")
    for index, event in enumerate(action_events):
        action = event["action"]
        if action["raw_flags"] != 8 or action["effective_flags"] != 8:
            raise SystemExit(f"{item['id']} once flags mismatch")
        if action["executor"] != expected_states[index]:
            raise SystemExit(f"{item['id']} executor state mismatch at {index}")
        if action["apply_calls"] != [0, 1, 1, 1, 2][index]:
            raise SystemExit(f"{item['id']} apply-call suppression mismatch")
        if action["reset_calls"] != [1, 1, 1, 2, 2][index]:
            raise SystemExit(f"{item['id']} reset-call count mismatch")
        if event["data"] != base_data:
            raise SystemExit(f"{item['id']} zero-work Funcdata mutation mismatch")

actual_hash = hashlib.sha256(stdout).hexdigest()
if actual_hash != metadata["expected_stdout_sha256"]:
    raise SystemExit(
        f"oracle stdout hash mismatch: expected={metadata['expected_stdout_sha256']} actual={actual_hash}"
    )
PY

/usr/bin/printf 'action_leaf_count_1204: MATCH cases=2 starttypes_passes=2 once_actions=6 reset_reapply=6\n'
