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
runner="$repo_root/tools/run_functional_equality_level_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
clean_path=/usr/bin:/bin
rust_toolchain=nightly-x86_64-unknown-linux-gnu
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/rustc"
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
input_commit=34a3febff160031c265cfbd841a94022c68c2c19
input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/functional_equality_level_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/functional_equality_level_1204.cc"
rust_fixture="$repo_root/tests/oracle/functional_equality_level_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rudra-functional-equality-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-functional-equality-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
on_signal() {
  local status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

if [[ ! -d "$bfd_include" || -L "$bfd_include" ]]; then
  echo "BFD include closure is not a real non-symlink directory" >&2
  exit 1
fi
private_bfd_include="$oracle_tmp/bfd/include"
private_bfd_library="$oracle_tmp/bfd/lib/libbfd-2.38-system.so"
mkdir -p "$private_bfd_include" "$(/usr/bin/dirname "$private_bfd_library")"
bfd_header_count=0
for source_header in "$bfd_include"/*; do
  if [[ ! -f "$source_header" || -L "$source_header" ]]; then
    echo "BFD include entry is not a regular non-symlink file: $source_header" >&2
    exit 1
  fi
  /usr/bin/cp -- "$source_header" "$private_bfd_include/$(/usr/bin/basename "$source_header")"
  bfd_header_count=$((bfd_header_count + 1))
done
/usr/bin/cp -- "$bfd_library" "$private_bfd_library"
if [[ ! -f "$private_bfd_include/bfd.h" || -L "$private_bfd_include/bfd.h" || \
      ! -f "$private_bfd_library" || -L "$private_bfd_library" ]]; then
  echo "private BFD snapshot is not regular non-symlink data" >&2
  exit 1
fi
if [[ "$bfd_header_count" -ne 9 ]]; then
  echo "BFD include closure entry count mismatch: $bfd_header_count" >&2
  exit 1
fi

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
      Ghidra/Processors/x86/data/languages || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp \
      Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi

resolved_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$input_commit^{commit}")
resolved_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
resolved_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$input_commit:examples/curl")
blob_type=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -t "$resolved_blob")
blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$resolved_blob")
if [[ "$resolved_commit" != "$input_commit" || \
      "$resolved_base_commit" != "$rudra_base_commit" || \
      "$resolved_blob" != "$input_blob" || \
      "$blob_type" != blob ]]; then
  echo "pinned Rudra input Git object mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$oracle_tmp/input"
oracle_binary="$oracle_tmp/input/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$input_blob" >"$oracle_binary"
cargo_home="$oracle_tmp/cargo-home"
registry_cache="$user_home/.cargo/registry/cache"
owned_files=(
  "$repo_root/src/expression.rs"
  "$repo_root/docs/api/expression.md"
  "$cpp_fixture"
  "$rust_fixture"
  "$metadata"
  "$runner"
  "$repo_root/tests/oracle/fixture_registry.json"
)
/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.before"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_python_bin" -I -S - "$repo_root" "$snapshot_root" "$metadata" "$runner_sha" \
  "$oracle_binary" "$blob_size" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_language_tree" "$oracle_makefile_blob" \
  "$input_commit" "$input_blob" "$rudra_base_commit" "$private_bfd_include" \
  "$private_bfd_library" "$runner_fd_path" "$host_git_bin" \
  "$host_cxx_bin" "$host_rustc_bin" "$host_cargo_bin" \
  "$cargo_home" "$registry_cache" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(repo_raw, snapshot_raw, metadata_raw, runner_sha, binary_raw, binary_size,
 oracle_commit, oracle_tag, cpp_tree, language_tree, makefile_blob,
 input_commit, input_blob, rudra_base_commit, bfd_include_raw, bfd_library_raw, runner_fd_raw,
 host_git, host_cxx, host_rustc, host_cargo, cargo_home_raw,
 registry_cache_raw) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
metadata_path = pathlib.Path(metadata_raw).resolve()
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, path="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{path}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{path} is pending: {value}")

def base_source_files(directory):
    raw = subprocess.check_output([
        host_git, "-C", str(repo), "ls-tree", "-r", "--name-only", "-z",
        rudra_base_commit, "--", directory,
    ])
    return sorted(
        (pathlib.Path(item.decode()) for item in raw.split(b"\0") if item),
        key=lambda item: item.as_posix(),
    )

def base_file(relative):
    spec = f"{rudra_base_commit}:{relative.as_posix()}"
    require(
        f"base object type {relative}",
        subprocess.check_output([host_git, "-C", str(repo), "cat-file", "-t", spec], text=True).strip(),
        "blob",
    )
    return subprocess.check_output([host_git, "-C", str(repo), "cat-file", "blob", spec])

def snapshot_file(relative):
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

crate_files = [
    pathlib.Path("Cargo.toml"), pathlib.Path("Cargo.lock"), pathlib.Path("build.rs"),
    pathlib.Path("README.md"), pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + base_source_files("src") + base_source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda item: item.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-functional-equality-base-overlay-v1\0")
crate_hasher.update(rudra_base_commit.encode())
for relative in crate_files:
    data = snapshot_file(relative) if relative == pathlib.Path("src/expression.rs") else base_file(relative)
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    encoded = relative.as_posix().encode()
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_paths = [
    pathlib.Path("tests/oracle/functional_equality_level_1204.cc"),
    pathlib.Path("tests/oracle/functional_equality_level_1204.rs"),
    pathlib.Path("tests/oracle/functional_equality_level_1204.metadata.json"),
    pathlib.Path("tools/run_functional_equality_level_oracle.sh"),
]
special = {}
for path in special_paths:
    if path == special_paths[3]:
        data = pathlib.Path(runner_fd_raw).read_bytes()
        destination = snapshot / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    else:
        data = snapshot_file(path)
    special[path.as_posix()] = data
require("immutable runner hash", sha(special[special_paths[3].as_posix()]), runner_sha)

binary = pathlib.Path(binary_raw).read_bytes()
(snapshot / "examples").mkdir()
(snapshot / "examples/curl").write_bytes(binary)
metadata = json.loads(special[special_paths[2].as_posix()])
reject_pending(metadata)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "FUNCTIONAL-EQUALITY-0001")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob),
    ("architecture", metadata["architecture"], "x86:LE:64:default"),
    ("compiler spec", metadata["compiler_spec"]["id"], "gcc"),
    ("overall status", metadata["overall_status"], "MISMATCH: (B2 canonicalization)"),
):
    require(label, actual, expected)

assets = metadata["assets"]
asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
for key, relative in asset_paths.items():
    item = assets[key]
    require(f"{key} path", item["path"], relative)
    require(f"{key} source commit", item["source_repository_commit"], input_commit)
    require(f"{key} source ref", item["source_ref"], f"{input_commit}:{relative}")
    oid = subprocess.check_output(
        [host_git, "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"], text=True
    ).strip()
    require(f"{key} blob", oid, item["git_blob_oid"])
    require(f"{key} type", subprocess.check_output(
        [host_git, "-C", str(repo), "cat-file", "-t", oid], text=True
    ).strip(), "blob")
    data = subprocess.check_output([host_git, "-C", str(repo), "cat-file", "blob", oid])
    require(f"{key} size", len(data), item["size"])
    require(f"{key} sha", sha(data), item["sha256"])
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)

binary_meta = assets["binary"]
require("binary source commit", binary_meta["source_repository_commit"], input_commit)
require("binary blob", binary_meta["git_blob_oid"], input_blob)
require("binary size", len(binary), int(binary_size))
require("binary metadata size", len(binary), binary_meta["size"])
require("binary sha", sha(binary), binary_meta["sha256"])
bfd_include = pathlib.Path(bfd_include_raw)
expected_headers = {
    "ansidecl.h": "2015ac40bf11e8e640596808022e3711d0d61df868d82ab8ed8a48fd69b719d6",
    "bfd.h": "c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702",
    "bfdlink.h": "632ba2c792cf4959ee6f4bb9921086f3852d6bce49133f3d0c226d88cc5ecb4e",
    "ctf-api.h": "d9c0fea2bdb6274efbbc0e4bef2ff7b20e10c501248e201ccd39c3f054eaf430",
    "ctf.h": "a36024b84a0c7fe4e543c1a5dccdc648f4b50cabce0b247163b3c6acdc6754ef",
    "diagnostics.h": "4b8b25e7a956e146d2d8bb44caf2cfeb99c7fa384d0e6e26d29c0cdd3a55a6ba",
    "dis-asm.h": "283ebec7d17e0426176e9541450d727893f350c7af835ea57947cf0f7bf31561",
    "plugin-api.h": "2c9d4e7b6edb1a60f04ab053b7b089276cc25c11185d934608d981bc44fd8528",
    "symcat.h": "8e74b7a19ff36bc947e05217d09c87a732621e79ee6ca4d1737c87fe1b1d9ee4",
}
observed_headers = sorted(path.name for path in bfd_include.iterdir())
require("BFD header names", observed_headers, sorted(expected_headers))
bfd_tree = hashlib.sha256()
bfd_tree.update(b"bfd-include-tree-v1\0")
for name in observed_headers:
    path = bfd_include / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"BFD snapshot entry is not regular: {path}")
    data = path.read_bytes()
    require(f"BFD header {name}", sha(data), expected_headers[name])
    require(f"metadata BFD header {name}", assets["bfd"]["headers"][name], expected_headers[name])
    encoded = name.encode()
    bfd_tree.update(len(encoded).to_bytes(8, "big"))
    bfd_tree.update(encoded)
    bfd_tree.update(len(data).to_bytes(8, "big"))
    bfd_tree.update(data)
require("BFD include tree", bfd_tree.hexdigest(), assets["bfd"]["include_tree_sha256"])
require("BFD library sha", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])
require("host g++", subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0], metadata["host_tools"]["g++"])
require("host rustc", subprocess.check_output([host_rustc, "--version"], text=True).strip(), metadata["host_tools"]["rustc"])
require("host cargo", subprocess.check_output([host_cargo, "--version"], text=True).strip(), metadata["host_tools"]["cargo"])

comparand = metadata["comparand"]
require("Rudra base commit", comparand["rugra_base_commit"], rudra_base_commit)
require("C++ fixture sha", sha(special[special_paths[0].as_posix()]), comparand["cpp_fixture_sha256"])
require("Rust fixture sha", sha(special[special_paths[1].as_posix()]), comparand["rust_fixture_sha256"])
require("runner sha", runner_sha, comparand["runner_sha256"])
require("crate hash scheme", comparand["rust_crate_tree_hash_scheme"],
        "sha256 of rudra-functional-equality-base-overlay-v1 plus base commit and sorted length-prefixed paths and contents")
require("crate tree sha", crate_hasher.hexdigest(), comparand["rust_crate_tree_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"], "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"], "binary": manifest["binary"],
    "function": manifest["function"], "cases": manifest["cases"],
}
canonical = json.dumps(fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
require("input manifest sha", sha(canonical), manifest["sha256"])
for dependency, status in (
    ("RULE-PUSHMULTI-CLOSURE-0001", "MISMATCH"),
    ("OPBANK-0001", "MISMATCH"),
    ("ARCH-0001", "MISMATCH"),
    ("EXPRESSION-CALLERS-0001", "UNTESTED"),
    ("FEL-DOMAIN-0001", "UNTESTED"),
    ("RULE-STATE-PROJECTION-0001", "UNTESTED"),
):
    require(f"dependency {dependency}", metadata["known_dependencies"][dependency]["status"], status)

if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit(f"registry archive cache is not a real directory: {registry_cache}")
package_blocks = (snapshot / "Cargo.lock").read_text().split("[[package]]")[1:]
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
    require("Cargo registry source", source, "registry+https://github.com/rust-lang/crates.io-index")
    for field in ("name", "version", "checksum"):
        if field not in fields:
            raise SystemExit(f"registry package missing {field}: {block[:160]!r}")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require("locked registry package count", len(registry_packages), metadata["build"]["registry_packages"])

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
    seen = set()
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
            relative = pathlib.PurePosixPath(*relative_parts).as_posix()
            if relative in seen:
                raise SystemExit(f"duplicate crate member path: {member.name!r}")
            seen.add(relative)
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
            require(f"crate member size {member.name}", len(data), member.size)
            destination.write_bytes(data)
            destination.chmod(member.mode & 0o777)
            file_hashes[relative] = sha(data)
    if not (package_root / "Cargo.toml").is_file():
        raise SystemExit(f"vendored crate has no Cargo.toml: {name} {version}")
    (package_root / ".cargo-checksum.json").write_text(json.dumps(
        {"files": file_hashes, "package": checksum}, sort_keys=True, separators=(",", ":")
    ))
cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    '[source.crates-io]\nreplace-with = "locked-vendor"\n\n'
    '[source.locked-vendor]\n'
    f'directory = {json.dumps(str(vendor_root))}\n'
)
PY

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
    "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" CC="$host_cc_bin" AR="$host_ar_bin" \
    EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare \
    -I"$private_bfd_include" -I"$oracle_cpp" \
    "$snapshot_root/tests/oracle/functional_equality_level_1204.cc" \
    "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
    "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
    "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
    "$private_bfd_library" -lz -o "$oracle_tmp/fixture_cpp" \
    >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

fixture_target="$oracle_tmp/cargo-target"
if ! (
  cd "$snapshot_root"
  /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
    RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
    AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --offline --locked --quiet \
      --manifest-path "$snapshot_root/Cargo.toml" --lib
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 \
    "$snapshot_root/tests/oracle/functional_equality_level_1204.rs" \
    --extern rudra="$fixture_target/debug/librudra.rlib" \
    -L "dependency=$fixture_target/debug/deps" \
    -o "$oracle_tmp/fixture_rust" \
    >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/fixture_cpp" "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/fixture_rust" >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
/usr/bin/head -n 25 "$oracle_tmp/ghidra.stdout" >"$oracle_tmp/ghidra.direct"
/usr/bin/head -n 25 "$oracle_tmp/rudra.stdout" >"$oracle_tmp/rudra.direct"
/usr/bin/diff -u --label ghidra-direct --label rudra-direct \
  "$oracle_tmp/ghidra.direct" "$oracle_tmp/rudra.direct" >"$oracle_tmp/direct.diff"
direct_diff_status=$?
/usr/bin/diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
full_diff_status=$?
set -e

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S - "$snapshot_root/tests/oracle/functional_equality_level_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" "$oracle_tmp/raw.diff" \
  "$ghidra_status" "$rudra_status" "$direct_diff_status" "$full_diff_status" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
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
    ("direct_diff_exit_code", int(sys.argv[9])),
    ("full_diff_exit_code", int(sys.argv[10])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")

for label, path in (("Ghidra", paths["ghidra_stdout_sha256"]), ("Rudra", paths["rudra_stdout_sha256"])):
    records = path.read_text().splitlines()
    if len(records) != 27:
        raise SystemExit(f"{label} record count mismatch: {len(records)}")
    direct = records[:25]
    if sum(record.startswith("fel|") for record in direct) != 24:
        raise SystemExit(f"{label} FEL record count mismatch")
    if sum(record.startswith("addexpr|") for record in direct) != 1:
        raise SystemExit(f"{label} AddExpression record count mismatch")
    for record in (item for item in direct if item.startswith("fel|")):
        fields = dict(field.split("=", 1) for field in record.split("|")[1:])
        if int(fields["equal"]) != int(int(fields["code"]) == 0):
            raise SystemExit(f"{label} wrapper/code disagreement: {record}")
    if records[25].split("|", 4)[2:4] != ["stage=before", "result=na"]:
        raise SystemExit(f"{label} rule before record mismatch")
    if records[26].split("|", 4)[2:4] != ["stage=after", "result=1"]:
        raise SystemExit(f"{label} rule after/result mismatch")
if paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("Rudra runtime stderr must be empty")
if paths["ghidra_stderr_sha256"].stat().st_size == 0:
    raise SystemExit("locked Ghidra BFD initialization diagnostics unexpectedly absent")
if len(paths["ghidra_stderr_sha256"].read_text().splitlines()) != metadata["expected_results"]["ghidra_stderr_line_count"]:
    raise SystemExit("locked Ghidra BFD initialization diagnostic count mismatch")
PY

/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.after"
if ! /usr/bin/cmp -s "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned comparands drifted during authoritative run" >&2
  /usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after" >&2 || true
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S - "$repo_root" "$runner_fd_path" \
  "$host_git_bin" "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

repo = pathlib.Path(sys.argv[1])
runner_fd = pathlib.Path(sys.argv[2])
host_git = sys.argv[3]
rudra_base_commit = sys.argv[4]
metadata = json.loads((repo / "tests/oracle/functional_equality_level_1204.metadata.json").read_text())

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"post-readback {label} mismatch: expected={expected} actual={actual}")

comparand = metadata["comparand"]
require("base commit", comparand["rugra_base_commit"], rudra_base_commit)
require(
    "base commit object",
    subprocess.check_output([host_git, "-C", str(repo), "rev-parse", f"{rudra_base_commit}^{{commit}}"], text=True).strip(),
    rudra_base_commit,
)
require("runner FD", sha(runner_fd.read_bytes()), comparand["runner_sha256"])
require("live runner", sha((repo / "tools/run_functional_equality_level_oracle.sh").read_bytes()), comparand["runner_sha256"])
require("C++ fixture", sha((repo / "tests/oracle/functional_equality_level_1204.cc").read_bytes()), comparand["cpp_fixture_sha256"])
require("Rust fixture", sha((repo / "tests/oracle/functional_equality_level_1204.rs").read_bytes()), comparand["rust_fixture_sha256"])

relative_files = [pathlib.Path(path) for path in (
    "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs",
)]
for directory in ("src", "sleigh_shim"):
    raw = subprocess.check_output([
        host_git, "-C", str(repo), "ls-tree", "-r", "--name-only", "-z",
        rudra_base_commit, "--", directory,
    ])
    relative_files.extend(pathlib.Path(item.decode()) for item in raw.split(b"\0") if item)
hasher = hashlib.sha256()
hasher.update(b"rudra-functional-equality-base-overlay-v1\0")
hasher.update(rudra_base_commit.encode())
for relative in sorted(set(relative_files), key=lambda item: item.as_posix()):
    if relative == pathlib.Path("src/expression.rs"):
        data = (repo / relative).read_bytes()
    else:
        spec = f"{rudra_base_commit}:{relative.as_posix()}"
        require(
            f"base object type {relative}",
            subprocess.check_output([host_git, "-C", str(repo), "cat-file", "-t", spec], text=True).strip(),
            "blob",
        )
        data = subprocess.check_output([host_git, "-C", str(repo), "cat-file", "blob", spec])
    encoded = relative.as_posix().encode()
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
require("full Rust crate", hasher.hexdigest(), comparand["rust_crate_tree_sha256"])
PY

/usr/bin/cat "$oracle_tmp/ghidra.stdout"
printf 'functional_equality_level_1204: MISMATCH direct_records=25 direct=MATCH rule_result=MATCH rule_projection=MISMATCH residuals=metadata\n'
