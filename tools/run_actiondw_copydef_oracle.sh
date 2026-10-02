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
runner="$repo_root/tools/run_actiondw_copydef_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
HOME=$user_home
export HOME

clean_path=/usr/bin:/bin
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
rudra_source_fspec_blob=8c5c2a92a9346deac82ee73cb1d5ce5c76f5bd9f
rudra_source_varnode_blob=13bec7c6e07f3f2b453cc9a7f7c28d26676e842e
rudra_source_action_blob=40b15b0873e83caf6318ef26267d799be89e624c
rudra_source_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rudra_source_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_source_paths=(
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs
  src sleigh_shim crates
)

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/actiondw_copydef_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/actiondw_copydef_1204.cc"
rust_fixture="$repo_root/tests/oracle/actiondw_copydef_1204.rs"
bfd_root=/tmp/rudra-ghidra-bfd-2.38/usr
bfd_include="$bfd_root/include"
bfd_header="$bfd_include/bfd.h"
bfd_library="$bfd_root/lib/x86_64-linux-gnu/libbfd-2.38-system.so"

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_timeout_bin=$(/usr/bin/readlink -f /usr/bin/timeout)
host_cargo_bin=$(command -v cargo)
host_rustc_bin=$(command -v rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_timeout_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for file in "$metadata" "$cpp_fixture" "$rust_fixture" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "required input is not a regular non-symlink file: $file" >&2
    exit 1
  fi
done

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
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
locked_dirty=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra source is dirty" >&2
  exit 1
fi

for pair in \
  "$rudra_source_commit^{commit}:$rudra_source_commit" \
  "$rudra_source_commit^{tree}:$rudra_source_tree" \
  "$rudra_source_commit:src:$rudra_source_src_tree" \
  "$rudra_source_commit:sleigh_shim:$rudra_source_sleigh_shim_tree" \
  "$rudra_source_commit:src/coreaction.rs:$rudra_source_coreaction_blob" \
  "$rudra_source_commit:src/fspec.rs:$rudra_source_fspec_blob" \
  "$rudra_source_commit:src/varnode.rs:$rudra_source_varnode_blob" \
  "$rudra_source_commit:src/action.rs:$rudra_source_action_blob" \
  "$rudra_source_commit:Cargo.toml:$rudra_source_cargo_toml_blob" \
  "$rudra_source_commit:Cargo.lock:$rudra_source_cargo_lock_blob" \
  "$rudra_source_commit:build.rs:$rudra_source_build_rs_blob"; do
  ref=${pair%:*}
  expected=${pair##*:}
  actual=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git_bin" -C "$repo_root" rev-parse "$ref")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra object mismatch: $ref" >&2
    exit 1
  fi
done

resolved_input_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
binary_blob_oid=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
binary_blob_size=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file -s "$binary_blob_oid")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$binary_blob_oid" != "$rudra_input_blob" ]]; then
  echo "pinned input object mismatch" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-actiondw-copydef-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-actiondw-copydef-1204.?????? ]]; then
    echo "refusing unexpected cleanup path: $oracle_tmp" >&2
    return 1
  fi
  if [[ -e "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    if [[ ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
      echo "refusing non-directory cleanup target: $oracle_tmp" >&2
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
/usr/bin/mkdir -p "$oracle_tmp/input" "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  "${rudra_source_paths[@]}"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
binary="$oracle_tmp/input/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" cat-file blob "$binary_blob_oid" >"$binary"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$repo_root" "$snapshot_root" "$cargo_home" "$registry_cache" \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$runner_snapshot_sha" "$binary" "$binary_blob_size" "$bfd_include" \
  "$bfd_library" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_language_tree" "$oracle_makefile_blob" "$rudra_input_commit" \
  "$rudra_input_blob" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_source_sleigh_shim_tree" \
  "$rudra_source_coreaction_blob" "$rudra_source_fspec_blob" \
  "$rudra_source_varnode_blob" "$rudra_source_action_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import sys
import tarfile

(
    repo_raw, snapshot_raw, cargo_home_raw, registry_cache_raw, metadata_raw,
    cpp_raw, rust_raw, runner_raw, runner_sha, binary_raw, binary_size,
    bfd_include_raw, bfd_library_raw, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, input_commit, input_blob, source_commit,
    source_tree, source_src_tree, source_sleigh_tree, source_coreaction_blob,
    source_fspec_blob, source_varnode_blob, source_action_blob,
    cargo_toml_blob, cargo_lock_blob, build_rs_blob,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(label, value):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is pending: {value}")

archive_paths = [
    "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs", "src", "sleigh_shim", "crates",
]
archive_files = []
for path in snapshot.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"pinned source closure rejects symlink: {path}")
    if path.is_file():
        relative = path.relative_to(snapshot)
        key = relative.as_posix()
        if not any(key == root or key.startswith(root + "/") for root in archive_paths):
            raise SystemExit(f"file outside source closure: {key}")
        archive_files.append(relative)
archive_files.sort(key=lambda item: item.as_posix())

base_hasher = hashlib.sha256()
base_hasher.update(b"rudra-actiondw-copydef-base-v1\0")
for relative in archive_files:
    data = (snapshot / relative).read_bytes()
    encoded = relative.as_posix().encode()
    base_hasher.update(len(encoded).to_bytes(8, "big"))
    base_hasher.update(encoded)
    base_hasher.update(len(data).to_bytes(8, "big"))
    base_hasher.update(data)

def live_file(relative):
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"live input is not a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

special_paths = [
    "tests/oracle/actiondw_copydef_1204.cc",
    "tests/oracle/actiondw_copydef_1204.rs",
    "tests/oracle/actiondw_copydef_1204.metadata.json",
    "tools/run_actiondw_copydef_oracle.sh",
]
special = {path: live_file(path) for path in special_paths}
metadata = json.loads(special["tests/oracle/actiondw_copydef_1204.metadata.json"])

source = metadata["rugra_source"]
require("source base commit", source["base_commit"], source_commit)
require("source tree", source["base_tree"], source_tree)
require("source src tree", source["base_src_tree"], source_src_tree)
require("source sleigh tree", source["base_sleigh_shim_tree"], source_sleigh_tree)
require("source coreaction blob", source["base_coreaction_blob"], source_coreaction_blob)
require("source fspec blob", source["base_fspec_blob"], source_fspec_blob)
require("source varnode blob", source["base_varnode_blob"], source_varnode_blob)
require("source action blob", source["base_action_blob"], source_action_blob)
require("source Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob)
require("source Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob)
require("source build.rs blob", source["build_rs_blob"], build_rs_blob)
require("source archive paths", source["archive_paths"], archive_paths)
reject_pending("base_closure_sha256", source["base_closure_sha256"])
require("base closure", source["base_closure_sha256"], base_hasher.hexdigest())

for relative in ("src/coreaction.rs", "src/fspec.rs", "src/varnode.rs", "src/action.rs"):
    data = (repo / relative).read_bytes()
    reject_pending(f"overlay {relative}", source["overlays"][relative]["sha256"])
    require(f"overlay {relative}", source["overlays"][relative]["sha256"], sha(data))
    (snapshot / relative).write_bytes(data)

oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")

asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
assets = metadata["assets"]
for key, relative in asset_paths.items():
    asset = assets[key]
    require(f"{key} path", asset["path"], relative)
    require(f"{key} source commit", asset["source_repository_commit"], input_commit)
    data = __import__("subprocess").check_output(
        ["git", "-C", str(repo), "cat-file", "blob", asset["git_blob_oid"]]
    )
    require(f"{key} size", asset["size"], len(data))
    require(f"{key} sha", asset["sha256"], sha(data))
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)

binary_data = pathlib.Path(binary_raw).read_bytes()
require("binary size", len(binary_data), int(binary_size))
require("binary sha", assets["binary"]["sha256"], sha(binary_data))
(snapshot / "examples").mkdir()
(snapshot / "examples/curl").write_bytes(binary_data)
require("BFD header", assets["bfd"]["header_sha256"], sha((pathlib.Path(bfd_include_raw) / "bfd.h").read_bytes()))
require("BFD library", assets["bfd"]["library_sha256"], sha(pathlib.Path(bfd_library_raw).read_bytes()))

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha(special["tests/oracle/actiondw_copydef_1204.cc"]),
    "rust_fixture_sha256": sha(special["tests/oracle/actiondw_copydef_1204.rs"]),
    "runner_sha256": runner_sha,
}
require("runner snapshot/live", sha(special["tools/run_actiondw_copydef_oracle.sh"]), runner_sha)
for key, actual in observed.items():
    reject_pending(key, comparand[key])
    require(key, actual, comparand[key])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "function": manifest["function"],
    "cases": manifest["cases"],
}
canonical = json.dumps(fingerprinted, sort_keys=True, separators=(",", ":")).encode()
reject_pending("input manifest", manifest["sha256"])
require("input manifest", manifest["sha256"], sha(canonical))

if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit("Cargo registry cache is unavailable")
package_blocks = (snapshot / "Cargo.lock").read_text().split("[[package]]")[1:]
packages = []
for block in package_blocks:
    fields = {}
    for field in ("name", "version", "source", "checksum"):
        match = re.search(rf'(?m)^{field} = "([^"\\]+)"$', block)
        if match:
            fields[field] = match.group(1)
    if "source" not in fields:
        continue
    if fields["source"] != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"unsupported Cargo source: {fields['source']}")
    packages.append((fields["name"], fields["version"], fields["checksum"]))

vendor = snapshot / "vendor"
vendor.mkdir()
for name, version, checksum in packages:
    archive_name = f"{name}-{version}.crate"
    matches = [ns / archive_name for ns in registry_cache.iterdir() if (ns / archive_name).exists()]
    if len(matches) != 1:
        raise SystemExit(f"expected one archive for {archive_name}, got {matches}")
    archive_data = matches[0].read_bytes()
    require(f"crate checksum {archive_name}", sha(archive_data), checksum)
    root_name = f"{name}-{version}"
    root = vendor / root_name
    root.mkdir()
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
        for member in archive.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if not path.parts or path.parts[0] != root_name or ".." in path.parts:
                raise SystemExit(f"unsafe crate path: {member.name}")
            relative = path.parts[1:]
            if not relative:
                continue
            destination = root.joinpath(*relative)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise SystemExit(f"unsupported crate member: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit(f"missing crate data: {member.name}")
            data = stream.read()
            destination.write_bytes(data)
            hashes[pathlib.PurePosixPath(*relative).as_posix()] = sha(data)
    (root / ".cargo-checksum.json").write_text(json.dumps(
        {"files": hashes, "package": checksum}, sort_keys=True, separators=(",", ":")
    ))
cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\nreplace-with = \"locked-vendor\"\n\n"
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor))}\n"
)
PY

/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

# Temporary, deterministic Ghidra fixture-flag instrumentation.
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$oracle_cpp" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
metadata_path = pathlib.Path(sys.argv[2])
patches = {
    "varnode.hh": [
        (
            "  uint4 getFlags(void) const { return flags; } ///< Get all the boolean attributes\n",
            "  uint4 getFlags(void) const { return flags; } ///< Get all the boolean attributes\n"
            "  void fixtureSetFlag(uint4 fl) { flags |= fl; } ///< Temporary fixture-only flag setter\n",
        ),
    ],
    "op.hh": [
        (
            "  bool isDead(void) const { return ((flags&PcodeOp::dead)!=0); }",
            "  void fixtureSetFlag(uint4 fl) { flags |= fl; } ///< Temporary fixture-only flag setter\n"
            "  bool isDead(void) const { return ((flags&PcodeOp::dead)!=0); }",
        ),
    ],
}
hasher = hashlib.sha256()
hasher.update(b"ghidra-actiondw-copydef-instrumentation-v1\0")
for name in sorted(patches):
    path = root / name
    text = path.read_text()
    for old, new in patches[name]:
        if text.count(old) != 1:
            raise SystemExit(f"instrumentation anchor count drifted: {name}: {old[:60]!r}")
        text = text.replace(old, new)
        for value in (name.encode(), old.encode(), new.encode()):
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
    path.write_text(text)
metadata = json.loads(metadata_path.read_text())
expected = metadata["comparand"]["ghidra_instrumentation_sha256"]
actual = hasher.hexdigest()
if expected.startswith("PENDING_"):
    raise SystemExit(f"ghidra instrumentation hash pending: {actual}")
if expected != actual:
    raise SystemExit(f"ghidra instrumentation hash mismatch: {expected} != {actual}")
PY

snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/mkdir -p "$snapshot_decompiler"
/usr/bin/ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"
jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  -Wl,-rpath,"$(/usr/bin/dirname "$bfd_library")" \
  "$snapshot_root/tests/oracle/actiondw_copydef_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/actiondw_copydef_1204_cpp"

fixture_target="$oracle_tmp/cargo-target"
if ! (
  cd "$snapshot_root"
  /usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  PATH="$clean_path:$(/usr/bin/dirname "$host_cargo_bin")" LC_ALL=C.UTF-8 \
  CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
  CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" AR="$host_ar_bin" \
  "$host_cargo_bin" build --quiet --locked --offline --lib
); then
  echo "isolated Cargo build failed" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "isolated Cargo build output mismatch" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$snapshot_root/tests/oracle/actiondw_copydef_1204.rs" \
  -o "$oracle_tmp/actiondw_copydef_1204_rust"

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_timeout_bin" --signal=TERM --kill-after=2s 10s \
  "$oracle_tmp/actiondw_copydef_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?

# The Rust fixture reads sleigh_specs/ relative to its cwd (same convention
# as the production worker_architecture path).
(
  cd "$snapshot_root"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$host_timeout_bin" --signal=TERM --kill-after=2s 10s \
    "$oracle_tmp/actiondw_copydef_1204_rust" \
    >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
)
rudra_status=$?
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/diff -u \
  --label ghidra --label rudra "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$snapshot_root/tests/oracle/actiondw_copydef_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" "$oracle_tmp/raw.diff" \
  "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_normalized_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}
statuses = {
    "ghidra_exit_code": int(sys.argv[7]),
    "rugra_exit_code": int(sys.argv[8]),
}
expected = metadata["expected_results"]
errors = []
actual_results = {}
for key, path in paths.items():
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    actual_results[key] = actual
    if expected[key] != actual:
        errors.append(f"{key} mismatch: expected={expected[key]} actual={actual}")
for key, actual in statuses.items():
    actual_results[key] = actual
    if expected[key] != actual:
        errors.append(f"{key} mismatch: expected={expected[key]} actual={actual}")
timed_out = int(sys.argv[8]) in (124, 137)
actual_results["rugra_timed_out"] = timed_out
if expected["rugra_timed_out"] != timed_out:
    errors.append(
        f"rudra_timed_out mismatch: expected={expected['rudra_timed_out']} actual={timed_out}"
    )

ghidra_lines = paths["ghidra_stdout_sha256"].read_text().splitlines()
rudra_lines = paths["rudra_stdout_sha256"].read_text().splitlines()
cases = [
    "param_inputs", "stackstore_trace", "indirect_marker", "phase2_push",
    "indirect_store_push", "noncopy_defs", "void_input_lock",
]

def validate_records(label, lines):
    case_lines = [line for line in lines if line.startswith("case=")]
    if len(case_lines) != 4 * len(cases):
        raise SystemExit(f"{label} record count mismatch: {len(case_lines)}")
    observed = [line.split("|", 1)[0][5:] for line in case_lines]
    expected_order = [c for c in cases for _ in range(4)]
    if observed != expected_order:
        raise SystemExit(f"{label} case order mismatch: {observed}")
    regs = [line.split("|reg=", 1)[1].split("|", 1)[0] for line in case_lines]
    expected_regs = [reg for _ in cases for reg in ("a", "a", "b", "b")]
    if regs != expected_regs:
        raise SystemExit(f"{label} registration order mismatch: {regs}")
    stages = [line.split("|stage=", 1)[1].split("|", 1)[0] for line in case_lines]
    expected_stages = [s for _ in cases for s in ("before", "after", "before", "after")]
    if stages != expected_stages:
        raise SystemExit(f"{label} stage order mismatch: {stages}")
    afters = [line for line in case_lines if "|stage=after|" in line]
    if any("|result=0|" not in line for line in afters):
        raise SystemExit(f"{label} apply return mismatch")
    befores = [line for line in case_lines if "|stage=before|" in line]
    if any("|result=-1|" not in line for line in befores):
        raise SystemExit(f"{label} before-stage marker mismatch")
    return case_lines

ghidra_records = validate_records("Ghidra", ghidra_lines)
rudra_records = validate_records("Rudra", rudra_lines)

# The iop-space offset normalization is performed by the fixtures themselves
# (both render the referenced op's fixture name); the projection is the raw
# record set.
if ghidra_records != rudra_records:
    import difflib
    print("\n".join(difflib.unified_diff(
        ghidra_records, rudra_records,
        fromfile="ghidra-target-projection", tofile="rudra-target-projection",
        lineterm="",
    )), file=sys.stderr)
    raise SystemExit("target projection mismatch")
if metadata["target_projection"]["status"] != "MATCH":
    raise SystemExit("target projection metadata is not final MATCH")

if errors:
    print("actual_results=" + json.dumps(actual_results, sort_keys=True), file=sys.stderr)
    for error in errors:
        print(error, file=sys.stderr)
    for label, path_key in (
        ("ghidra.stderr", "ghidra_stderr_sha256"),
        ("rudra.stderr", "rudra_stderr_normalized_sha256"),
        ("raw.diff", "raw_diff_sha256"),
    ):
        content = paths[path_key].read_text(errors="replace")
        if content:
            print(f"--- {label} ---", file=sys.stderr)
            print(content, file=sys.stderr, end="" if content.endswith("\n") else "\n")
    raise SystemExit("recorded result mismatch")

if expected["ghidra_exit_code"] != 0:
    raise SystemExit("locked Ghidra fixture must exit zero")
if metadata["overall_status"] not in ("MISMATCH", "MATCH"):
    raise SystemExit("invalid final overall status")
if metadata["overall_status"] != "MATCH":
    raise SystemExit("overall status is not MATCH")
for key, value in metadata["coverage"].items():
    if value not in ("MATCH", "MISMATCH"):
        raise SystemExit(f"coverage remains non-final: {key}={value}")
PY

printf 'actiondw_copydef_1204: %s target_projection=MATCH lines=%s rust_exit=%s timeout=%s raw_diff=%s\n' \
  "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -c \
    'import json,sys; print(json.load(open(sys.argv[1]))["overall_status"])' "$metadata")" \
  "$(wc -l < "$oracle_tmp/ghidra.stdout" | /usr/bin/tr -d ' ')" \
  "$rudra_status" "$([[ "$rudra_status" == 124 || "$rudra_status" == 137 ]] && echo true || echo false)" \
  "$diff_status"
