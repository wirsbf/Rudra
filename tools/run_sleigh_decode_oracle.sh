#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i \
    PATH="/usr/bin:/bin" \
    /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(
  builtin cd "$(/usr/bin/dirname "$runner_source")/.."
  builtin pwd -P
)
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
rust_toolchain=nightly-x86_64-unknown-linux-gnu
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
cpp_fixture="$repo_root/tests/oracle/sleigh_decode_1204.cc"
rust_fixture="$repo_root/tests/oracle/sleigh_decode_1204.rs"
metadata="$repo_root/tests/oracle/sleigh_decode_1204.metadata.json"
runner="$repo_root/tools/run_sleigh_decode_oracle.sh"
sla="$repo_root/sleigh_specs/x86-64.sla"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi

source_units=(
  xml.cc
  marshal.cc
  space.cc
  float.cc
  address.cc
  pcoderaw.cc
  translate.cc
  opcodes.cc
  globalcontext.cc
  sleigh.cc
  pcodeparse.cc
  pcodecompile.cc
  sleighbase.cc
  slghsymbol.cc
  slghpatexpress.cc
  slghpattern.cc
  semantics.cc
  context.cc
  slaformat.cc
  compression.cc
  filemanage.cc
)

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_cargo_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/rustc"
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
clean_path="/usr/bin:/bin"
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_cargo_bin" "$host_rustc_bin" "$host_python_bin" "$host_git_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi

actual_tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "expected tag $oracle_tag to resolve to $oracle_commit, found $actual_tag_commit" >&2
  exit 1
fi

actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
if [[ "$actual_cpp_tree" != "$oracle_cpp_tree" ]]; then
  echo "locked decompiler cpp tree mismatch" >&2
  exit 1
fi

actual_language_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
if [[ "$actual_language_tree" != "$oracle_language_tree" ]]; then
  echo "locked x86 language tree mismatch" >&2
  exit 1
fi

actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked decompiler Makefile blob mismatch" >&2
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

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" -dumpmachine)
host_cc=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cc_bin" --version | head -1)
host_ar=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_ar_bin" --version | head -1)
host_rustc=$(/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)
source_units_csv=$(IFS=,; printf '%s' "${source_units[*]}")

runner_pid=$BASHPID
cleanup_done=0
cleanup_watcher=
oracle_tmp=
watch_parent() {
  watched_tmp=
  cleanup_watched() {
    if [[ -n "$watched_tmp" ]]; then
      remove_owned_tmp "$watched_tmp"
      watched_tmp=
    fi
  }
  trap cleanup_watched EXIT
  trap '' HUP INT TERM
  trap 'exit 0' USR1
  watched_tmp=$(/usr/bin/mktemp -d /tmp/rudra-sleigh-decode-1204.XXXXXX)
  printf '%s\n' "$watched_tmp"
  while kill -0 "$runner_pid" 2>/dev/null; do
    sleep 1
  done
}
remove_owned_tmp() {
  local path=$1
  if [[ "$path" != /tmp/rudra-sleigh-decode-1204.?????? ]]; then
    echo "refusing to remove unexpected temporary path: $path" >&2
    return 1
  fi
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ ! -d "$path" || -L "$path" ]]; then
      echo "refusing to remove non-directory temporary path: $path" >&2
      return 1
    fi
    /usr/bin/rm -rf -- "$path"
  fi
}
cleanup() {
  if [[ "$cleanup_done" -eq 0 && -n "$oracle_tmp" ]]; then
    cleanup_done=1
    remove_owned_tmp "$oracle_tmp"
  fi
  if [[ -n "$cleanup_watcher" ]]; then
    kill -USR1 "$cleanup_watcher" 2>/dev/null || true
    wait "$cleanup_watcher" 2>/dev/null || true
    cleanup_watcher=
  fi
}
handle_signal() {
  local status=$1
  trap '' HUP INT TERM
  cleanup
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
coproc CLEANUP_WATCHER { watch_parent; }
cleanup_watcher=$CLEANUP_WATCHER_PID
IFS= read -r oracle_tmp <&"${CLEANUP_WATCHER[0]}"
snapshot_root="$oracle_tmp/workspace"
cargo_home="$oracle_tmp/cargo-home"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$repo_root" "$snapshot_root" "$cargo_home" \
  "$HOME/.cargo/registry/cache" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner" "$runner_snapshot_sha" "$oracle_tag" "$oracle_commit" \
  "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$host_cxx" "$host_cxx_target" "$host_rustc" "$host_cargo" \
  "$host_platform" "$host_cxx_bin" "$host_cargo_bin" "$host_rustc_bin" \
  "$host_python_bin" "$host_cc" "$host_ar" "$host_cc_bin" "$host_ar_bin" \
  "$rust_toolchain" "$HOME" \
  "$clean_path" "$source_units_csv" <<'PY'
import hashlib
import io
import json
import pathlib
import re
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
    host_python_bin,
    host_cc,
    host_ar,
    host_cc_bin,
    host_ar_bin,
    rust_toolchain,
    host_home,
    clean_path,
    source_units_csv,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
snapshot_root = pathlib.Path(snapshot_root_raw)
snapshot_root.mkdir(parents=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo_root / "tests/oracle/sleigh_decode_1204.metadata.json",
    pathlib.Path(cpp_fixture_raw): repo_root / "tests/oracle/sleigh_decode_1204.cc",
    pathlib.Path(rust_fixture_raw): repo_root / "tests/oracle/sleigh_decode_1204.rs",
    pathlib.Path(runner_raw): repo_root / "tools/run_sleigh_decode_oracle.sh",
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
    pathlib.Path("Cargo.toml"),
    pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"),
    pathlib.Path("README.md"),
] + source_files("src") + source_files("sleigh_shim") + source_files("tests") \
    + source_files("examples") + source_files("benches")
crate_files = [
    path for path in crate_files
    if path != pathlib.Path("tests/oracle/sleigh_decode_1204.metadata.json")
]
crate_files = sorted(set(crate_files), key=lambda path: path.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-crate-snapshot-v1\0")
crate_bytes = {}
for relative in crate_files:
    data = snapshot_file(relative)
    crate_bytes[relative.as_posix()] = data
    encoded_path = relative.as_posix().encode("utf-8")
    crate_hasher.update(len(encoded_path).to_bytes(8, "big"))
    crate_hasher.update(encoded_path)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_files = [
    pathlib.Path("tests/oracle/sleigh_decode_1204.cc"),
    pathlib.Path("tests/oracle/sleigh_decode_1204.rs"),
    pathlib.Path("tests/oracle/sleigh_decode_1204.metadata.json"),
    pathlib.Path("tools/run_sleigh_decode_oracle.sh"),
    pathlib.Path("sleigh_specs/x86-64.sla"),
    pathlib.Path("sleigh_specs/x86-64.pspec"),
    pathlib.Path("sleigh_specs/x86-64-gcc.cspec"),
    pathlib.Path("sleigh_specs/x86.ldefs"),
]
special_bytes = {}
for relative in special_files:
    key = relative.as_posix()
    special_bytes[key] = crate_bytes.get(key)
    if special_bytes[key] is None:
        special_bytes[key] = snapshot_file(relative)
metadata = json.loads(
    special_bytes["tests/oracle/sleigh_decode_1204.metadata.json"].decode("utf-8")
)

def require_equal(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is still pending: {value}")

oracle = metadata["oracle"]
require_equal("metadata oracle tag", oracle["tag"], oracle_tag)
require_equal("metadata oracle commit", oracle["commit"], oracle_commit)
require_equal("metadata cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require_equal("metadata language tree", oracle["x86_language_tree"], language_tree)
require_equal("metadata Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require_equal("architecture", metadata["architecture"], "x86:LE:64:default")
require_equal("compiler spec id", metadata["compiler_spec"]["id"], "gcc")

assets = metadata["assets"]
asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
}
for key in ("sla", "processor_spec", "compiler_spec"):
    require_equal(f"{key} path", assets[key]["path"], asset_paths[key])
    data = special_bytes[asset_paths[key]]
    require_equal(f"{key} sha256", sha256_bytes(data), assets[key]["sha256"])
require_equal("SLA size", len(special_bytes[asset_paths["sla"]]), assets["sla"]["size"])
require_equal(
    "language definitions sha256",
    sha256_bytes(special_bytes["sleigh_specs/x86.ldefs"]),
    assets["language_definitions_sha256"],
)

comparand = metadata["comparand"]
observed_hashes = {
    "cpp_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/sleigh_decode_1204.cc"]),
    "rust_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/sleigh_decode_1204.rs"]),
    "runner_sha256": runner_snapshot_sha,
    "shim_sha256": sha256_bytes(crate_bytes["sleigh_shim/rudra_sleigh.cpp"]),
    "rust_sleigh_ffi_sha256": sha256_bytes(crate_bytes["src/sleigh_ffi.rs"]),
    "rust_opcodes_sha256": sha256_bytes(crate_bytes["src/opcodes.rs"]),
    "build_rs_sha256": sha256_bytes(crate_bytes["build.rs"]),
    "cargo_toml_sha256": sha256_bytes(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha256_bytes(crate_bytes["Cargo.lock"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require_equal(
    "runner snapshot/live copy",
    sha256_bytes(special_bytes["tools/run_sleigh_decode_oracle.sh"]),
    runner_snapshot_sha,
)
require_equal(
    "crate snapshot scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-crate-snapshot-v1 plus sorted length-prefixed relative paths and contents",
)
require_equal("repo Cargo config inputs", comparand["repo_cargo_config_files"], [])
if (repo_root / ".cargo").exists():
    raise SystemExit("repository .cargo config is not part of the isolated comparand")
for key, actual in observed_hashes.items():
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

for key, actual in (
    ("host_cxx", host_cxx),
    ("host_cxx_target", host_cxx_target),
    ("host_rustc", host_rustc),
    ("host_cargo", host_cargo),
    ("host_platform", host_platform),
    ("host_cxx_path", host_cxx_bin),
    ("host_cargo_path", host_cargo_bin),
    ("host_rustc_path", host_rustc_bin),
    ("host_python_path", host_python_bin),
    ("host_cc", host_cc),
    ("host_ar", host_ar),
    ("host_cc_path", host_cc_bin),
    ("host_ar_path", host_ar_bin),
    ("host_rust_toolchain", rust_toolchain),
    ("host_home", host_home),
    ("clean_path", clean_path),
):
    reject_pending(comparand[key], f"comparand.{key}")
    require_equal(key, actual, comparand[key])

source_units = source_units_csv.split(",")
require_equal("source-unit closure", source_units, metadata["build"]["source_units"])
require_equal(
    "build environment policy",
    metadata["build"]["environment_policy"],
    "immutable runner + hashed workspace snapshot; env -i; Cargo.lock-checksummed crate archives extracted into an isolated vendor and CARGO_HOME; pinned direct Rust toolchain and explicit CXX/CC/AR/RUSTC; locked offline Cargo",
)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "context": manifest["context"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
manifest_sha = hashlib.sha256(canonical).hexdigest()
reject_pending(manifest["sha256"], "input_manifest.sha256")
require_equal("input manifest sha256", manifest_sha, manifest["sha256"])

for case in manifest["cases"]:
    image = bytes.fromhex(case["image_hex"])
    require_equal(
        f"{case['id']} image sha256",
        hashlib.sha256(image).hexdigest(),
        case["image_sha256"],
    )

reject_pending(metadata["expected_stdout_sha256"], "expected_stdout_sha256")

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
            raise SystemExit(f"registry package is missing {required}: {block[:160]!r}")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))

require_equal(
    "locked registry package count",
    len(registry_packages),
    metadata["build"]["registry_packages"],
)
vendor_root = snapshot_root / "vendor"
vendor_root.mkdir()
for name, version, checksum in registry_packages:
    archive_name = f"{name}-{version}.crate"
    matches = []
    for cache_namespace in registry_cache.iterdir():
        if cache_namespace.is_symlink() or not cache_namespace.is_dir():
            raise SystemExit(f"registry cache namespace is not a real directory: {cache_namespace}")
        candidate = cache_namespace / archive_name
        if candidate.exists():
            matches.append(candidate)
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one cached archive for {name} {version}, found {matches}"
        )
    archive_path = matches[0]
    if archive_path.is_symlink() or not archive_path.is_file():
        raise SystemExit(f"crate archive is not a regular file: {archive_path}")
    archive_bytes = archive_path.read_bytes()
    require_equal(
        f"Cargo.lock checksum for {name} {version}",
        sha256_bytes(archive_bytes),
        checksum,
    )

    package_root_name = f"{name}-{version}"
    package_root = vendor_root / package_root_name
    package_root.mkdir()
    file_hashes = {}
    seen_paths = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = pathlib.PurePosixPath(member.name)
            parts = member_path.parts
            if (
                not parts
                or parts[0] != package_root_name
                or any(part in ("", ".", "..") for part in parts)
            ):
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
        {"files": file_hashes, "package": checksum},
        sort_keys=True,
        separators=(",", ":"),
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

metadata="$snapshot_root/tests/oracle/sleigh_decode_1204.metadata.json"
cpp_fixture="$snapshot_root/tests/oracle/sleigh_decode_1204.cc"
rust_fixture="$snapshot_root/tests/oracle/sleigh_decode_1204.rs"
sla="$snapshot_root/sleigh_specs/x86-64.sla"
mkdir -p "$oracle_tmp/source"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C tar -xf - -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

oracle_sources=()
for source_unit in "${source_units[@]}"; do
  source_path="$oracle_cpp/$source_unit"
  if [[ ! -f "$source_path" ]]; then
    echo "missing locked oracle source: $source_path" >&2
    exit 1
  fi
  oracle_sources+=("$source_path")
done

cpp_fixture_dir="$oracle_tmp/cpp-fixture"
mkdir -p "$cpp_fixture_dir"
cp -- "$cpp_fixture" "$cpp_fixture_dir/sleigh_decode_1204.cc"
cpp_fixture="$cpp_fixture_dir/sleigh_decode_1204.cc"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture" "${oracle_sources[@]}" -lz \
  -o "$oracle_tmp/sleigh_decode_1204_cpp"

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
for ancestor_input in \
  "$oracle_tmp/Cargo.toml" "$oracle_tmp/rust-toolchain" "$oracle_tmp/rust-toolchain.toml" \
  "/tmp/Cargo.toml" "/tmp/rust-toolchain" "/tmp/rust-toolchain.toml" \
  "/Cargo.toml" "/rust-toolchain" "/rust-toolchain.toml"; do
  if [[ -e "$ancestor_input" ]]; then
    echo "ambient Cargo workspace/toolchain input is outside the comparand: $ancestor_input" >&2
    exit 1
  fi
done
(
  cd "$snapshot_root"
  /usr/bin/env -i \
    HOME="$HOME" \
    RUSTUP_HOME="$HOME/.rustup" \
    RUSTUP_TOOLCHAIN="$rust_toolchain" \
    PATH="$clean_path" \
    LC_ALL=C.UTF-8 \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true \
    CXX="$host_cxx_bin" \
    CC="$host_cc_bin" \
    AR="$host_ar_bin" \
    RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib \
      --manifest-path "$snapshot_root/Cargo.toml"
)
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
native_dir=$(dirname "${native_archives[0]}")

/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" RUSTUP_TOOLCHAIN="$rust_toolchain" \
  PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/sleigh_decode_1204_rust"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/sleigh_decode_1204_cpp" "$sla" >"$oracle_tmp/ghidra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/sleigh_decode_1204_rust" "$sla" >"$oracle_tmp/rudra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout_path = pathlib.Path(sys.argv[2])
stdout = stdout_path.read_bytes()
records = [json.loads(line) for line in stdout.decode("utf-8").splitlines()]
cases = metadata["input_manifest"]["cases"]

expected_ids = [case["id"] for case in cases] + ["unimpl_x86_reachability"]
actual_ids = [record["case"] for record in records]
if actual_ids != expected_ids:
    raise SystemExit(f"case order mismatch: expected={expected_ids} actual={actual_ids}")

context = metadata["input_manifest"]["context"]
for case, record in zip(cases, records):
    if record["schema"] != metadata["schema_version"]:
        raise SystemExit(f"{case['id']}: schema mismatch")
    if record["architecture"] != metadata["architecture"]:
        raise SystemExit(f"{case['id']}: architecture mismatch")
    if record["compiler_spec"] != metadata["compiler_spec"]["id"]:
        raise SystemExit(f"{case['id']}: compiler spec mismatch")
    observed_input = record["input"]
    for key in (
        "base",
        "offset",
        "image_hex",
        "image_sha256",
        "setup",
        "source_after_hex",
    ):
        if observed_input[key] != case[key]:
            raise SystemExit(
                f"{case['id']}: input {key} mismatch: "
                f"expected={case[key]!r} actual={observed_input[key]!r}"
            )
    if observed_input["context"] != context:
        raise SystemExit(f"{case['id']}: context/order mismatch")
    if observed_input["loader_policy"] != "raw-uint64-modulo-start-tail-zero-fill":
        raise SystemExit(f"{case['id']}: loader policy mismatch")

    result = record["result"]
    expected = case["expected"]
    for key in ("status", "step", "op_count", "explain"):
        if key in expected and result[key] != expected[key]:
            raise SystemExit(
                f"{case['id']}: result {key} mismatch: "
                f"expected={expected[key]!r} actual={result[key]!r}"
            )
    if result["op_count"] != len(result["ops"]):
        raise SystemExit(f"{case['id']}: op_count does not match ops length")
    if result["status"] != "OK":
        if result["step"] is not None or result["ops"]:
            raise SystemExit(f"{case['id']}: error leaked step/operations")

    next_identity = 0
    identities = set()
    for op_index, operation in enumerate(result["ops"]):
        if operation["index"] != op_index:
            raise SystemExit(f"{case['id']}: operation index/order mismatch")
        if operation["declared_input_count"] != len(operation["inputs"]):
            raise SystemExit(f"{case['id']}: truncated operation inputs")
        nodes = []
        if operation["output"] is not None:
            nodes.append(operation["output"])
        nodes.extend(operation["inputs"])
        for node in nodes:
            identity = node["identity"]
            if identity not in identities:
                if identity != next_identity:
                    raise SystemExit(
                        f"{case['id']}: non-canonical pointer identity {identity}; "
                        f"expected first-use id {next_identity}"
                    )
                identities.add(identity)
                next_identity += 1
            if node["kind"] == "varnode":
                expected_alias = (
                    f"varnode:{node['space']['index']}:"
                    f"{node['offset']}:{node['size']}"
                )
            elif node["kind"] == "spaceid":
                expected_alias = (
                    f"spaceid:{node['target_space']['index']}:{node['size']}"
                )
            else:
                raise SystemExit(f"{case['id']}: unknown varnode kind")
            if node["alias_key"] != expected_alias:
                raise SystemExit(f"{case['id']}: location alias key mismatch")

cpuid = records[0]["result"]
expected_opcodes = [
    1, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5,
    11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 11, 5, 9, 4, 9,
    4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 9, 4,
    9, 4, 9, 4, 9, 4, 9, 4, 9, 4, 2, 17, 19, 2, 17, 19, 2, 17, 19, 2,
    17,
]
actual_opcodes = [operation["opcode"]["value"] for operation in cpuid["ops"]]
if actual_opcodes != expected_opcodes:
    raise SystemExit("CPUID full opcode order mismatch")
if sum(len(operation["inputs"]) for operation in cpuid["ops"]) != 134:
    raise SystemExit("CPUID full input count mismatch")
if sum(
    node["kind"] == "spaceid"
    for operation in cpuid["ops"]
    for node in operation["inputs"]
) != 4:
    raise SystemExit("CPUID LOAD space-id normalization count mismatch")
if any(
    operation["address"]["offset"] != "0x0000000000001000"
    for operation in cpuid["ops"]
):
    raise SystemExit("CPUID callback address mismatch")

alias_case = next(
    record for record in records if record["case"] == "mov_rax_ptr_rbx_pointer_alias"
)["result"]
alias_identities = []
for operation in alias_case["ops"]:
    if operation["output"] is not None:
        alias_identities.append(operation["output"]["identity"])
    alias_identities.extend(node["identity"] for node in operation["inputs"])
if len(set(alias_identities)) == len(alias_identities):
    raise SystemExit("pointer-alias case did not reuse any VarnodeData identity")

coverage = records[-1]["coverage"]
if coverage != {
    "alignment": 1,
    "constructors": 5707,
    "null_templates": 0,
    "reason": "locked x86-64 SLA has no reachable UnimplError path",
    "status": "UNTESTED",
    "subtables": 236,
}:
    raise SystemExit("x86 Unimpl coverage statement mismatch")

actual_stdout_sha = hashlib.sha256(stdout).hexdigest()
if actual_stdout_sha != metadata["expected_stdout_sha256"]:
    raise SystemExit(
        "oracle stdout hash mismatch: "
        f"expected={metadata['expected_stdout_sha256']} actual={actual_stdout_sha}"
    )

print(
    "sleigh_decode_1204: MATCH "
    f"cases={len(cases)} cpuid_ops={cpuid['op_count']} "
    f"cpuid_inputs={sum(len(op['inputs']) for op in cpuid['ops'])} "
    "unimpl=UNTESTED"
)
PY
