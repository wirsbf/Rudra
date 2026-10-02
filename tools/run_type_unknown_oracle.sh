#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${1:-}" != --immutable-runner-fd ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH="/usr/bin:/bin" /usr/bin/bash \
    "$runner_fd_path" --immutable-runner-fd "$@"
fi
shift
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(
  builtin cd "$(/usr/bin/dirname "$runner_source")/.."
  builtin pwd -P
)
runner="$repo_root/tools/run_type_unknown_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(
  /usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }'
)
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi
HOME=$user_home
export HOME

clean_path="/usr/bin:/bin"
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
rudra_typefactory_base_blob=d34f5038b19eaf5165bcf6fef0304ba0cd86aa25
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/type_unknown_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/type_unknown_1204.cc"
rust_fixture="$repo_root/tests/oracle/type_unknown_1204.rs"
spec_root="$repo_root/sleigh_specs"
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
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra HEAD/tag mismatch: HEAD=$actual_commit tag=$actual_tag_commit" >&2
  exit 1
fi
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra tree/blob identity mismatch" >&2
  exit 1
fi
locked_dirty=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra cpp/language worktree is dirty:" >&2
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
resolved_source_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_source_commit^{tree}")
resolved_typefactory_base_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse \
  "$rudra_source_commit:src/type_system/typefactory.rs")
if [[ "$resolved_source_commit" != "$rudra_source_commit" || \
      "$resolved_source_tree" != "$rudra_source_tree" || \
      "$resolved_typefactory_base_blob" != "$rudra_typefactory_base_blob" ]]; then
  echo "pinned Rudra source commit/tree/blob identity mismatch" >&2
  exit 1
fi
resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
if [[ "$resolved_input_commit" != "$rudra_input_commit" ]]; then
  echo "pinned Rudra input commit mismatch: $resolved_input_commit" >&2
  exit 1
fi
binary_blob_oid=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
if [[ "$binary_blob_oid" != "$rudra_input_blob" ]]; then
  echo "pinned Rudra input blob mismatch: $binary_blob_oid" >&2
  exit 1
fi
binary_blob_type=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -t "$binary_blob_oid")
binary_blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$binary_blob_oid")
if [[ "$binary_blob_type" != blob ]]; then
  echo "Rudra $rudra_input_commit:examples/curl is not a Git blob" >&2
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

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-type-unknown-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-type-unknown-1204.?????? ]]; then
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
mkdir -p "$oracle_tmp/input" "$snapshot_root"
binary="$oracle_tmp/input/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$binary_blob_oid" >"$binary"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot_root"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$repo_root" "$snapshot_root" "$cargo_home" \
  "$HOME/.cargo/registry/cache" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner" "$runner_snapshot_sha" "$binary" "$rudra_input_commit" \
  "$binary_blob_oid" "$binary_blob_size" "$bfd_include" "$bfd_library" \
  "$rudra_source_commit" "$rudra_source_tree" "$rudra_typefactory_base_blob" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$host_cxx" "$host_cxx_target" "$host_rustc" \
  "$host_cargo" "$host_platform" "$host_cxx_bin" "$host_cargo_bin" \
  "$host_rustc_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$rust_toolchain" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import tarfile

(
    repo_root_raw,
    snapshot_root_raw,
    cargo_home_raw,
    registry_cache_raw,
    metadata_raw,
    cpp_fixture_raw,
    rust_fixture_raw,
    runner_raw,
    runner_snapshot_sha,
    binary_raw,
    rudra_input_commit,
    binary_blob_oid,
    binary_blob_size,
    bfd_include_raw,
    bfd_library_raw,
    rudra_source_commit,
    rudra_source_tree,
    rudra_typefactory_base_blob,
    oracle_tag,
    oracle_commit,
    cpp_tree,
    language_tree,
    makefile_blob,
    host_cxx,
    host_cxx_target,
    host_rustc,
    host_cargo,
    host_platform,
    host_cxx_bin,
    host_cargo_bin,
    host_rustc_bin,
    host_cc_bin,
    host_ar_bin,
    host_make_bin,
    host_python_bin,
    host_git_bin,
    rust_toolchain,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
snapshot_root = pathlib.Path(snapshot_root_raw)
snapshot_root.mkdir(parents=True, exist_ok=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo_root / "tests/oracle/type_unknown_1204.metadata.json",
    pathlib.Path(cpp_fixture_raw): repo_root / "tests/oracle/type_unknown_1204.cc",
    pathlib.Path(rust_fixture_raw): repo_root / "tests/oracle/type_unknown_1204.rs",
    pathlib.Path(runner_raw): repo_root / "tools/run_type_unknown_oracle.sh",
}
for actual, expected in expected_paths.items():
    if actual.resolve() != expected.resolve():
        raise SystemExit(f"unexpected runner input path: {actual} != {expected}")

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def snapshot_file(relative):
    source = repo_root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

def snapshot_git_blob(relative):
    source_ref = f"{rudra_input_commit}:{relative.as_posix()}"
    import subprocess
    blob_oid = subprocess.check_output(
        [host_git_bin, "-C", str(repo_root), "rev-parse", source_ref],
        text=True,
    ).strip()
    blob_type = subprocess.check_output(
        [host_git_bin, "-C", str(repo_root), "cat-file", "-t", blob_oid],
        text=True,
    ).strip()
    if blob_type != "blob":
        raise SystemExit(f"pinned asset is not a Git blob: {source_ref}")
    data = subprocess.check_output(
        [host_git_bin, "-C", str(repo_root), "cat-file", "blob", blob_oid]
    )
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data, blob_oid

def snapshot_source_files(directory):
    root = snapshot_root / directory
    result = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"committed source archive rejects symlink: {path}")
        if path.is_file():
            result.append(path.relative_to(snapshot_root))
    return sorted(result, key=lambda path: path.as_posix())

crate_files = [
    pathlib.Path("Cargo.toml"),
    pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"),
    pathlib.Path("README.md"),
    pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + snapshot_source_files("src") + snapshot_source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda path: path.as_posix())
expected_archive_roots = {
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "README.md",
    "benches",
    "tests",
    "src",
    "sleigh_shim",
}
actual_archive_roots = {path.name for path in snapshot_root.iterdir()}
if actual_archive_roots != expected_archive_roots:
    raise SystemExit(
        f"unexpected committed source archive roots: {sorted(actual_archive_roots)}"
    )
for relative in crate_files:
    archived = snapshot_root / relative
    if archived.is_symlink() or not archived.is_file():
        raise SystemExit(f"committed source archive entry is not a regular file: {relative}")

# The sole live source overlay owned by this fixture is snapshotted exactly
# once over the pinned committed crate. All other Rust inputs remain immutable
# Git objects even if the shared worktree or HEAD changes during the run.
snapshot_file(pathlib.Path("src/type_system/typefactory.rs"))
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-type-unknown-lib-snapshot-v2\0")
crate_bytes = {}
for relative in crate_files:
    data = (snapshot_root / relative).read_bytes()
    crate_bytes[relative.as_posix()] = data
    encoded_path = relative.as_posix().encode("utf-8")
    crate_hasher.update(len(encoded_path).to_bytes(8, "big"))
    crate_hasher.update(encoded_path)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_files = [
    pathlib.Path("tests/oracle/type_unknown_1204.cc"),
    pathlib.Path("tests/oracle/type_unknown_1204.rs"),
    pathlib.Path("tests/oracle/type_unknown_1204.metadata.json"),
    pathlib.Path("tools/run_type_unknown_oracle.sh"),
]
special_bytes = {}
for relative in special_files:
    key = relative.as_posix()
    special_bytes[key] = crate_bytes.get(key)
    if special_bytes[key] is None:
        special_bytes[key] = snapshot_file(relative)

asset_paths = {
    "sla": pathlib.Path("sleigh_specs/x86-64.sla"),
    "processor_spec": pathlib.Path("sleigh_specs/x86-64.pspec"),
    "compiler_spec": pathlib.Path("sleigh_specs/x86-64-gcc.cspec"),
    "language_definitions": pathlib.Path("sleigh_specs/x86.ldefs"),
}
pinned_asset_oids = {}
for key, relative in asset_paths.items():
    data, blob_oid = snapshot_git_blob(relative)
    special_bytes[relative.as_posix()] = data
    pinned_asset_oids[key] = blob_oid

binary_source = pathlib.Path(binary_raw)
expected_binary_source = snapshot_root.parent / "input" / "curl"
if (
    binary_source.resolve() != expected_binary_source.resolve()
    or binary_source.is_symlink()
    or not binary_source.is_file()
):
    raise SystemExit(f"unexpected committed binary snapshot: {binary_source}")
binary_bytes = binary_source.read_bytes()
binary_destination = snapshot_root / "examples/curl"
binary_destination.parent.mkdir(parents=True, exist_ok=True)
binary_destination.write_bytes(binary_bytes)
special_bytes["examples/curl"] = binary_bytes

external_root = snapshot_root / "external"
external_root.mkdir()
bfd_include_source = pathlib.Path(bfd_include_raw)
if bfd_include_source.is_symlink() or not bfd_include_source.is_dir():
    raise SystemExit(f"BFD include closure is not a real directory: {bfd_include_source}")
bfd_include_snapshot = external_root / "include"
bfd_include_snapshot.mkdir()
for source in sorted(bfd_include_source.iterdir(), key=lambda path: path.name):
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"BFD include entry is not a regular non-symlink file: {source}")
    shutil.copyfile(source, bfd_include_snapshot / source.name)
bfd_library_source = pathlib.Path(bfd_library_raw)
if bfd_library_source.is_symlink() or not bfd_library_source.is_file():
    raise SystemExit(f"BFD library is not a regular non-symlink file: {bfd_library_source}")
shutil.copyfile(bfd_library_source, external_root / "libbfd.so")

metadata = json.loads(
    special_bytes["tests/oracle/type_unknown_1204.metadata.json"].decode("utf-8")
)

def require_equal(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is still pending: {value}")

oracle = metadata["oracle"]
require_equal("oracle tag", oracle["tag"], oracle_tag)
require_equal("oracle commit", oracle["commit"], oracle_commit)
require_equal("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require_equal("oracle language tree", oracle["x86_language_tree"], language_tree)
require_equal("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require_equal("architecture", metadata["architecture"], "x86:LE:64:default")
require_equal("compiler spec", metadata["compiler_spec"]["id"], "gcc")

assets = metadata["assets"]
validated_asset_paths = {
    key: relative.as_posix() for key, relative in asset_paths.items()
}
validated_asset_paths["binary"] = "examples/curl"
for key, relative in validated_asset_paths.items():
    require_equal(f"{key} path", assets[key]["path"], relative)
    require_equal(
        f"{key} sha256", sha256_bytes(special_bytes[relative]), assets[key]["sha256"]
    )
    require_equal(f"{key} size", len(special_bytes[relative]), assets[key]["size"])
    require_equal(
        f"{key} source commit", assets[key]["source_repository_commit"], rudra_input_commit
    )
    require_equal(f"{key} source ref", assets[key]["source_ref"], f"{rudra_input_commit}:{relative}")
    if key != "binary":
        require_equal(f"{key} Git blob OID", assets[key]["git_blob_oid"], pinned_asset_oids[key])
require_equal(
    "binary Git source ref",
    assets["binary"]["source_ref"],
    f"{rudra_input_commit}:examples/curl",
)
require_equal("binary source repository commit", assets["binary"]["source_repository_commit"], rudra_input_commit)
require_equal("binary Git blob OID", assets["binary"]["git_blob_oid"], binary_blob_oid)
require_equal("binary Git blob size", assets["binary"]["size"], int(binary_blob_size))
require_equal(
    "binary source policy",
    assets["binary"]["source_policy"],
    "Materialize the pinned provenance commit's examples/curl Git blob by its verified object ID; never read the working-tree file and never require runtime HEAD equality",
)
require_equal("BFD include path", assets["bfd"]["include_path"], bfd_include_raw)
require_equal("BFD header path", assets["bfd"]["header_path"], str(pathlib.Path(bfd_include_raw) / "bfd.h"))
require_equal("BFD library path", assets["bfd"]["library_path"], bfd_library_raw)
require_equal(
    "BFD header sha256",
    sha256_bytes((bfd_include_snapshot / "bfd.h").read_bytes()),
    assets["bfd"]["header_sha256"],
)
bfd_tree_hasher = hashlib.sha256()
bfd_tree_hasher.update(b"bfd-include-tree-v1\0")
for path in sorted(bfd_include_snapshot.iterdir(), key=lambda item: item.name):
    data = path.read_bytes()
    name = path.name.encode("utf-8")
    bfd_tree_hasher.update(len(name).to_bytes(8, "big"))
    bfd_tree_hasher.update(name)
    bfd_tree_hasher.update(len(data).to_bytes(8, "big"))
    bfd_tree_hasher.update(data)
require_equal("BFD include tree sha256", bfd_tree_hasher.hexdigest(), assets["bfd"]["include_tree_sha256"])
require_equal(
    "BFD library sha256",
    sha256_bytes((external_root / "libbfd.so").read_bytes()),
    assets["bfd"]["library_sha256"],
)

comparand = metadata["comparand"]
require_equal("Rudra source commit", comparand["rust_base_commit"], rudra_source_commit)
require_equal("Rudra source tree", comparand["rust_base_tree"], rudra_source_tree)
require_equal(
    "Rudra TypeFactory base blob",
    comparand["typefactory_base_blob"],
    rudra_typefactory_base_blob,
)
observed_hashes = {
    "cpp_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/type_unknown_1204.cc"]),
    "rust_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/type_unknown_1204.rs"]),
    "runner_sha256": runner_snapshot_sha,
    "typefactory_rs_sha256": sha256_bytes(crate_bytes["src/type_system/typefactory.rs"]),
    "datatype_rs_sha256": sha256_bytes(crate_bytes["src/type_system/datatype.rs"]),
    "cargo_toml_sha256": sha256_bytes(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha256_bytes(crate_bytes["Cargo.lock"]),
    "build_rs_sha256": sha256_bytes(crate_bytes["build.rs"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require_equal(
    "runner snapshot/live copy",
    sha256_bytes(special_bytes["tools/run_type_unknown_oracle.sh"]),
    runner_snapshot_sha,
)
require_equal(
    "crate snapshot scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-type-unknown-lib-snapshot-v2 plus sorted length-prefixed paths and contents from pinned base commit with the owned TypeFactory overlay",
)
for key, actual in observed_hashes.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

host_values = {
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
for key, actual in host_values.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

manifest = metadata["input_manifest"]
require_equal(
    "input manifest binary",
    manifest["binary"],
    {
        "path": assets["binary"]["path"],
        "source_repository_commit": rudra_input_commit,
        "git_blob_oid": binary_blob_oid,
        "sha256": assets["binary"]["sha256"],
        "size": assets["binary"]["size"],
    },
)
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
reject_pending(manifest["sha256"], "input_manifest.sha256")
require_equal("input manifest sha256", hashlib.sha256(canonical).hexdigest(), manifest["sha256"])
reject_pending(metadata["expected_stdout_sha256"], "expected_stdout_sha256")
require_equal(
    "overall status",
    metadata["overall_status"],
    "PARTIAL_MATCH: targeted unknown atomic-base, structural-order, and clearNoncore observations match; large-base array conversion and general TypeFactory registry remain UNTESTED/MISMATCH",
)
for key in (
    "core_unknown_sizes_1_2_4_8",
    "unnamed_unknown_sizes_3_5_6_7",
    "same_factory_pointer_identity",
    "different_size_non_identity",
    "named_unknown_identity",
    "named_conflicting_definition",
    "anonymous_structural_order",
    "clear_noncore_removes_anonymous",
    "clear_noncore_recreated_repeat_identity",
):
    require_equal(f"coverage.{key}", metadata["coverage"][key], "MATCH")
require_equal(
    "coverage.size_above_architecture_max_basetype_size",
    metadata["coverage"]["size_above_architecture_max_basetype_size"],
    "UNTESTED",
)

if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit(f"registry archive cache is not a real directory: {registry_cache}")
package_blocks = crate_bytes["Cargo.lock"].decode("utf-8").split("[[package]]")[1:]
registry_packages = []
for block in package_blocks:
    fields = {}
    for field in ("name", "version", "source", "checksum"):
        match = re.search(rf'(?m)^{field} = "([^"\\]+)"$', block)
        if match:
            fields[field] = match.group(1)
    source = fields.get("source")
    if source is None:
        continue
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"unsupported Cargo source in locked closure: {source}")
    for required in ("name", "version", "checksum"):
        if required not in fields:
            raise SystemExit(f"registry package missing {required}: {block[:160]!r}")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require_equal("locked registry package count", len(registry_packages), metadata["build"]["registry_packages"])

vendor_root = snapshot_root / "vendor"
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
    require_equal(f"Cargo.lock checksum for {name} {version}", sha256_bytes(archive_bytes), checksum)
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
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"crate member has no data: {member.name!r}")
            data = source.read()
            if len(data) != member.size:
                raise SystemExit(f"short crate member read: {member.name!r}")
            destination.write_bytes(data)
            destination.chmod(member.mode & 0o777)
            file_hashes[relative_key] = sha256_bytes(data)
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

metadata="$snapshot_root/tests/oracle/type_unknown_1204.metadata.json"
cpp_fixture="$snapshot_root/tests/oracle/type_unknown_1204.cc"
rust_fixture="$snapshot_root/tests/oracle/type_unknown_1204.rs"
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

jobs=2
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a \
    >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  cat "$oracle_tmp/make.stdout" >&2
  cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi

cpp_fixture_dir="$oracle_tmp/cpp-fixture"
mkdir -p "$cpp_fixture_dir"
cp -- "$cpp_fixture" "$cpp_fixture_dir/type_unknown_1204.cc"
cpp_fixture="$cpp_fixture_dir/type_unknown_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/type_unknown_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  cat "$oracle_tmp/cxx.stdout" >&2
  cat "$oracle_tmp/cxx.stderr" >&2
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
  /usr/bin/env -i \
    HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" RUSTUP_TOOLCHAIN="$rust_toolchain" \
    PATH="$clean_path" LC_ALL=C.UTF-8 CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$fixture_target" CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2 \
    CXX="$host_cxx_bin" CC="$host_cc_bin" AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib \
      --manifest-path "$snapshot_root/Cargo.toml"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stdout" >&2
  cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce $rudra_rlib" >&2
  exit 1
fi
native_archives=()
while IFS= read -r archive; do
  native_archives+=("$archive")
done < <(find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f)
if [[ "${#native_archives[@]}" -ne 1 ]]; then
  echo "expected one Cargo-built librudra_sleigh.a, found ${#native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/type_unknown_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  cat "$oracle_tmp/rustc.stdout" >&2
  cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/type_unknown_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/type_unknown_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout = pathlib.Path(sys.argv[2]).read_bytes()
documents = stdout.decode("utf-8").splitlines()
if len(documents) != 1:
    raise SystemExit(f"expected exactly one JSON line, found {len(documents)}")
document = json.loads(documents[0])
if document.get("schema") != 1 or document.get("fixture") != "TYPE-UNKNOWN-0001":
    raise SystemExit("invalid type-unknown fixture envelope")
expected_sizes = metadata["input_manifest"]["cases"]["anonymous_sizes"]
if [entry["requested_size"] for entry in document["types"]] != expected_sizes:
    raise SystemExit("request order mismatch")
if document["identity"]["repeat"] != [1] * len(expected_sizes):
    raise SystemExit("same-factory canonical identity mismatch")
if document["identity"]["different_size"] != [0] * (len(expected_sizes) - 1):
    raise SystemExit("cross-size identity mismatch")
if document["named_repeat"] != 1:
    raise SystemExit("named canonical identity mismatch")
if document["collision_error"] != "Trying to alter definition of type: fixture_unknown3":
    raise SystemExit("named collision exception mismatch")
if document["anonymous_order_before_clear"] != [7, 6, 5, 3]:
    raise SystemExit("anonymous structural order mismatch")
if document["anonymous_order_after_clear"] != []:
    raise SystemExit("clearNoncore retained an anonymous unknown")
if document["clear_identity"] != {"new_repeat": 1}:
    raise SystemExit("clearNoncore recreation identity mismatch")
if document["anonymous_order_after_recreate"] != [3]:
    raise SystemExit("recreated anonymous unknown missing from structural order")

actual_hash = hashlib.sha256(stdout).hexdigest()
expected_hash = metadata["expected_stdout_sha256"]
if actual_hash != expected_hash:
    raise SystemExit(f"oracle stdout hash mismatch: expected={expected_hash} actual={actual_hash}")
PY

printf 'type_unknown_1204: MATCH sizes=8 structural_order=4 recreated_repeat=1 named_collision=1\n'
