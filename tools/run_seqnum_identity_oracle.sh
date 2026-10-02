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
runner="$repo_root/tools/run_seqnum_identity_oracle.sh"
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

clean_path=/usr/bin:/bin
rust_toolchain=nightly-x86_64-unknown-linux-gnu
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_input_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/seqnum_identity_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/seqnum_identity_1204.cc"
rust_fixture="$repo_root/tests/oracle/seqnum_identity_1204.rs"
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
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$spec_root/x86-64.sla" "$spec_root/x86-64.pspec" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86.ldefs" \
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
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
locked_dirty=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra decompiler worktree is dirty" >&2
  exit 1
fi

resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
binary_blob_oid=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
binary_blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$binary_blob_oid")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$binary_blob_oid" != "$rudra_input_blob" ]]; then
  echo "pinned Rudra binary commit/blob identity mismatch" >&2
  exit 1
fi

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-seqnum-identity-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-seqnum-identity-1204.?????? ]]; then
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
registry_cache="$user_home/.cargo/registry/cache"
/usr/bin/mkdir -p "$oracle_tmp/input"
binary="$oracle_tmp/input/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$binary_blob_oid" >"$binary"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$repo_root" "$snapshot_root" "$cargo_home" \
  "$registry_cache" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner" "$runner_snapshot_sha" "$oracle_tag" "$oracle_commit" \
  "$oracle_cpp_tree" "$oracle_language_tree" "$oracle_makefile_blob" \
  "$binary" "$rudra_input_commit" "$binary_blob_oid" "$binary_blob_size" \
  "$bfd_include" "$bfd_library" "$host_cxx" "$host_cxx_target" \
  "$host_rustc" "$host_cargo" "$host_platform" "$host_cxx_bin" \
  "$host_cargo_bin" "$host_rustc_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" "$rust_toolchain" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import shutil
import sys
import tarfile

(
    repo_root_raw, snapshot_root_raw, cargo_home_raw, registry_cache_raw,
    metadata_raw, cpp_fixture_raw, rust_fixture_raw, runner_raw,
    runner_snapshot_sha, oracle_tag, oracle_commit, cpp_tree, language_tree,
    makefile_blob, binary_raw, input_commit, binary_oid, binary_size,
    bfd_include_raw, bfd_library_raw, host_cxx, host_cxx_target,
    host_rustc, host_cargo, host_platform,
    host_cxx_bin, host_cargo_bin, host_rustc_bin, host_cc_bin, host_ar_bin,
    host_make_bin, host_python_bin, host_git_bin, rust_toolchain,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
snapshot_root = pathlib.Path(snapshot_root_raw)
snapshot_root.mkdir(parents=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo_root / "tests/oracle/seqnum_identity_1204.metadata.json",
    pathlib.Path(cpp_fixture_raw): repo_root / "tests/oracle/seqnum_identity_1204.cc",
    pathlib.Path(rust_fixture_raw): repo_root / "tests/oracle/seqnum_identity_1204.rs",
    pathlib.Path(runner_raw): repo_root / "tools/run_seqnum_identity_oracle.sh",
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

def source_files(directory):
    root = repo_root / directory
    result = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"source snapshot rejects symlink: {path}")
        if path.is_file():
            result.append(path.relative_to(repo_root))
    return sorted(result, key=lambda path: path.as_posix())

crate_files = [
    pathlib.Path("Cargo.toml"), pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"), pathlib.Path("README.md"),
    pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + source_files("src") + source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda path: path.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-seqnum-identity-lib-snapshot-v1\0")
crate_bytes = {}
for relative in crate_files:
    data = snapshot_file(relative)
    crate_bytes[relative.as_posix()] = data
    encoded = relative.as_posix().encode("utf-8")
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_files = [
    pathlib.Path("tests/oracle/seqnum_identity_1204.cc"),
    pathlib.Path("tests/oracle/seqnum_identity_1204.rs"),
    pathlib.Path("tests/oracle/seqnum_identity_1204.metadata.json"),
    pathlib.Path("tools/run_seqnum_identity_oracle.sh"),
    pathlib.Path("sleigh_specs/x86-64.sla"),
    pathlib.Path("sleigh_specs/x86-64.pspec"),
    pathlib.Path("sleigh_specs/x86-64-gcc.cspec"),
    pathlib.Path("sleigh_specs/x86.ldefs"),
    pathlib.Path("docs/api/address.md"),
    pathlib.Path("docs/api/op.md"),
    pathlib.Path("docs/api/varnode.md"),
    pathlib.Path("docs/api/graph.md"),
    pathlib.Path("docs/api/unionresolve.md"),
    pathlib.Path("docs/api/variable.md"),
    pathlib.Path("docs/api/funcdata.md"),
]
special_bytes = {}
for relative in special_files:
    special_bytes[relative.as_posix()] = snapshot_file(relative)

metadata = json.loads(
    special_bytes["tests/oracle/seqnum_identity_1204.metadata.json"].decode("utf-8")
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
require_equal("compiler spec", metadata["compiler_spec"], "gcc")

binary_source = pathlib.Path(binary_raw)
if (binary_source.resolve() != snapshot_root.parent / "input/curl"
        or binary_source.is_symlink() or not binary_source.is_file()):
    raise SystemExit(f"unexpected committed binary snapshot: {binary_source}")
binary_data = binary_source.read_bytes()
(snapshot_root / "examples").mkdir()
(snapshot_root / "examples/curl").write_bytes(binary_data)

external_root = snapshot_root / "external"
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

assets = metadata["assets"]
asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
for key, relative in asset_paths.items():
    data = special_bytes[relative]
    require_equal(f"assets.{key}.path", assets[key]["path"], relative)
    require_equal(f"assets.{key}.sha256", assets[key]["sha256"], sha256_bytes(data))
require_equal("binary path", assets["binary"]["path"], "examples/curl")
require_equal("binary commit", assets["binary"]["source_repository_commit"], input_commit)
require_equal("binary blob", assets["binary"]["git_blob_oid"], binary_oid)
require_equal("binary size", assets["binary"]["size"], int(binary_size))
require_equal("binary sha256", assets["binary"]["sha256"], sha256_bytes(binary_data))
require_equal("BFD include path", assets["bfd"]["include_path"], bfd_include_raw)
require_equal("BFD library path", assets["bfd"]["library_path"], bfd_library_raw)
require_equal("BFD header", assets["bfd"]["header_sha256"], sha256_bytes((bfd_include_snapshot / "bfd.h").read_bytes()))
bfd_tree_hasher = hashlib.sha256()
bfd_tree_hasher.update(b"bfd-include-tree-v1\0")
for path in sorted(bfd_include_snapshot.iterdir(), key=lambda item: item.name):
    data = path.read_bytes()
    name = path.name.encode("utf-8")
    bfd_tree_hasher.update(len(name).to_bytes(8, "big"))
    bfd_tree_hasher.update(name)
    bfd_tree_hasher.update(len(data).to_bytes(8, "big"))
    bfd_tree_hasher.update(data)
require_equal("BFD include tree", assets["bfd"]["include_tree_sha256"], bfd_tree_hasher.hexdigest())
require_equal("BFD library", assets["bfd"]["library_sha256"], sha256_bytes((external_root / "libbfd.so").read_bytes()))

comparand = metadata["comparand"]
observed_hashes = {
    "cpp_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/seqnum_identity_1204.cc"]),
    "rust_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/seqnum_identity_1204.rs"]),
    "runner_sha256": runner_snapshot_sha,
    "address_rs_sha256": sha256_bytes(crate_bytes["src/address.rs"]),
    "op_rs_sha256": sha256_bytes(crate_bytes["src/op.rs"]),
    "varnode_rs_sha256": sha256_bytes(crate_bytes["src/varnode.rs"]),
    "graph_rs_sha256": sha256_bytes(crate_bytes["src/graph.rs"]),
    "unionresolve_rs_sha256": sha256_bytes(crate_bytes["src/unionresolve.rs"]),
    "variable_rs_sha256": sha256_bytes(crate_bytes["src/variable.rs"]),
    "funcdata_rs_sha256": sha256_bytes(crate_bytes["src/funcdata.rs"]),
    "address_doc_sha256": sha256_bytes(special_bytes["docs/api/address.md"]),
    "op_doc_sha256": sha256_bytes(special_bytes["docs/api/op.md"]),
    "varnode_doc_sha256": sha256_bytes(special_bytes["docs/api/varnode.md"]),
    "graph_doc_sha256": sha256_bytes(special_bytes["docs/api/graph.md"]),
    "unionresolve_doc_sha256": sha256_bytes(special_bytes["docs/api/unionresolve.md"]),
    "variable_doc_sha256": sha256_bytes(special_bytes["docs/api/variable.md"]),
    "funcdata_doc_sha256": sha256_bytes(special_bytes["docs/api/funcdata.md"]),
    "cargo_toml_sha256": sha256_bytes(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha256_bytes(crate_bytes["Cargo.lock"]),
    "build_rs_sha256": sha256_bytes(crate_bytes["build.rs"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require_equal(
    "runner snapshot/live copy",
    sha256_bytes(special_bytes["tools/run_seqnum_identity_oracle.sh"]),
    runner_snapshot_sha,
)
require_equal(
    "crate snapshot scheme", comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-seqnum-identity-lib-snapshot-v1 plus sorted length-prefixed relative paths and contents",
)
for key, actual in observed_hashes.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

host_values = {
    "host_cxx": host_cxx, "host_cxx_target": host_cxx_target,
    "host_cxx_path": host_cxx_bin, "host_rustc": host_rustc,
    "host_cargo": host_cargo, "host_cargo_path": host_cargo_bin,
    "host_rustc_path": host_rustc_bin, "host_cc_path": host_cc_bin,
    "host_ar_path": host_ar_bin, "host_make_path": host_make_bin,
    "host_python_path": host_python_bin, "host_git_path": host_git_bin,
    "host_rust_toolchain": rust_toolchain, "host_platform": host_platform,
}
for key, actual in host_values.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

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
require_equal("input manifest scheme", manifest["canonicalization"], "RFC 8785-compatible JSON subset: UTF-8, sorted keys, compact separators, no floats")
reject_pending(manifest["sha256"], "input_manifest.sha256")
require_equal("input manifest sha256", sha256_bytes(canonical), manifest["sha256"])
require_equal(
    "overall status", metadata["overall_status"],
    "PARTIAL_MATCH: targeted SeqNum identity/order consumer paths byte-match; listed MISMATCH/UNTESTED branches remain",
)
require_equal("status", metadata["status"], "PARTIAL_MATCH")
require_equal("covered projection status", metadata["covered_projection_status"], "MATCH")

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
    (package_root / ".cargo-checksum.json").write_bytes(json.dumps(
        {"files": file_hashes, "package": checksum},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8"))

cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\nreplace-with = \"locked-vendor\"\n\n"
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor_root))}\n",
    encoding="utf-8",
)
PY

metadata="$snapshot_root/tests/oracle/seqnum_identity_1204.metadata.json"
cpp_fixture="$snapshot_root/tests/oracle/seqnum_identity_1204.cc"
rust_fixture="$snapshot_root/tests/oracle/seqnum_identity_1204.rs"
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

cpp_fixture_dir="$oracle_tmp/cpp-fixture"
mkdir -p "$cpp_fixture_dir"
/usr/bin/cp -- "$cpp_fixture" "$cpp_fixture_dir/seqnum_identity_1204.cc"
cpp_fixture="$cpp_fixture_dir/seqnum_identity_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz \
  -o "$oracle_tmp/seqnum_identity_1204_cpp" \
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
  /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
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
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce $rudra_rlib" >&2
  exit 1
fi
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ "${#native_archives[@]}" -ne 1 ]]; then
  echo "expected one Cargo-built librudra_sleigh.a, found ${#native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/seqnum_identity_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/seqnum_identity_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"; then
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/seqnum_identity_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"; then
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture runtime stderr must be empty" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$runner_fd_path" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_bytes()
ghidra_stderr = pathlib.Path(sys.argv[3]).read_bytes()
rudra_stdout = pathlib.Path(sys.argv[4]).read_bytes()
runner_bytes = pathlib.Path(sys.argv[5]).read_bytes()
ghidra_lines = ghidra_stdout.decode("utf-8").splitlines()
rudra_lines = rudra_stdout.decode("utf-8").splitlines()
expected_lines = [
    "time_order=0:4294967251,1:4218271365", "identity=1,1",
    "cross_address=1,1", "lookup=1,1", "varnode_lookup=1,1",
    "optree_prefix=0,1,2", "order_relation=0", "graph_time=1,1",
    "resolve_order=0,1", "compare_name=0,1", "destroy_identity=1,1",
]
if ghidra_lines != expected_lines or rudra_lines != expected_lines:
    raise SystemExit(f"unexpected SeqNum observation lines: Ghidra={ghidra_lines!r} Rudra={rudra_lines!r}")
for label, data, key in (
    ("stdout", ghidra_stdout, "expected_stdout_sha256"),
    ("Ghidra stderr", ghidra_stderr, "expected_ghidra_stderr_sha256"),
    ("runner post-readback", runner_bytes, "runner_sha256"),
):
    actual = hashlib.sha256(data).hexdigest()
    expected = metadata["comparand"][key] if key == "runner_sha256" else metadata[key]
    if actual != expected:
        raise SystemExit(f"{label} hash mismatch: expected={expected} actual={actual}")
PY

/usr/bin/printf 'seqnum_identity_1204: PARTIAL_MATCH lines=11 covered_projection=MATCH residuals=metadata\n'
