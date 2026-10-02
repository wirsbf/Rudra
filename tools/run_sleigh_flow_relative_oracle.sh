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
runner="$repo_root/tools/run_sleigh_flow_relative_oracle.sh"
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
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/sleigh_flow_relative_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/sleigh_flow_relative_1204.cc"
rust_fixture="$repo_root/tests/oracle/sleigh_flow_relative_1204.rs"
spec_root="$repo_root/sleigh_specs"
# Rudra crate comparand base: the git commit this fixture was produced
# against (with its tree hash pinned in metadata), plus the three leased
# source files overlaid from the working tree. Concurrent agents' uncommitted
# changes to other src files must never enter this comparand.
pinned_base=07efbff6af58fbea91b27a99fb3ecfbe39690e19

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_objcopy_bin=$(/usr/bin/readlink -f /usr/bin/objcopy)
host_cargo_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$user_home/.rustup/toolchains/$rust_toolchain/bin/rustc"
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" "$host_objcopy_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    echo "required input is not a regular non-symlink file: $required_file" >&2
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

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-sleigh-flow-relative-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-sleigh-flow-relative-1204.?????? ]]; then
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
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$repo_root" "$snapshot_root" "$cargo_home" \
  "$user_home/.cargo/registry/cache" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner" "$runner_snapshot_sha" "$oracle_tag" "$oracle_commit" \
  "$oracle_cpp_tree" "$oracle_language_tree" "$oracle_makefile_blob" \
  "$host_cxx" "$host_cxx_target" \
  "$host_rustc" "$host_cargo" "$host_platform" "$host_cxx_bin" \
  "$host_cargo_bin" "$host_rustc_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" "$host_objcopy_bin" \
  "$rust_toolchain" "$pinned_base" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    repo_root_raw, snapshot_root_raw, cargo_home_raw, registry_cache_raw,
    metadata_raw, cpp_fixture_raw, rust_fixture_raw, runner_raw,
    runner_snapshot_sha, oracle_tag, oracle_commit, cpp_tree, language_tree,
    makefile_blob,
    host_cxx, host_cxx_target, host_rustc, host_cargo, host_platform,
    host_cxx_bin, host_cargo_bin, host_rustc_bin, host_cc_bin, host_ar_bin,
    host_make_bin, host_python_bin, host_git_bin, host_objcopy_bin,
    rust_toolchain, pinned_base,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
snapshot_root = pathlib.Path(snapshot_root_raw)
snapshot_root.mkdir(parents=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

# Crate files taken from the working tree instead of the pinned base. This is
# exactly the SLEIGH-FLOW-REL-0001 lease; every other crate file comes from
# git at pinned_base so concurrent uncommitted work never enters the build.
overlay_files = {
    "src/disasm/sleigh_lift.rs",
    "src/flow.rs",
    "src/funcdata.rs",
}

expected_paths = {
    pathlib.Path(metadata_raw): repo_root / "tests/oracle/sleigh_flow_relative_1204.metadata.json",
    pathlib.Path(cpp_fixture_raw): repo_root / "tests/oracle/sleigh_flow_relative_1204.cc",
    pathlib.Path(rust_fixture_raw): repo_root / "tests/oracle/sleigh_flow_relative_1204.rs",
    pathlib.Path(runner_raw): repo_root / "tools/run_sleigh_flow_relative_oracle.sh",
}
for actual, expected in expected_paths.items():
    if actual.resolve() != expected.resolve():
        raise SystemExit(f"unexpected runner input path: {actual} != {expected}")

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def read_pinned(relative):
    """Read one file from the pinned Rudra base commit via git."""
    object_spec = f"{pinned_base}:{relative}"
    return subprocess.check_output(
        [host_git_bin, "-C", str(repo_root), "show", object_spec]
    )

def snapshot_file(relative):
    source = repo_root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

def snapshot_crate_file(relative):
    """Snapshot one crate file: pinned base content, or the leased overlay."""
    if relative.as_posix() in overlay_files:
        return snapshot_file(relative)
    data = read_pinned(relative)
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

def pinned_tree_files(directory):
    """List files under a directory in the pinned base commit."""
    listing = subprocess.check_output(
        [host_git_bin, "-C", str(repo_root), "ls-tree", "-r", "--name-only",
         f"{pinned_base}", directory],
        text=True,
    )
    result = [pathlib.Path(line) for line in listing.splitlines() if line]
    return sorted(result, key=lambda path: path.as_posix())

crate_files = [
    pathlib.Path("Cargo.toml"), pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"), pathlib.Path("README.md"),
] + pinned_tree_files("src") + pinned_tree_files("sleigh_shim") \
  + pinned_tree_files("benches") + pinned_tree_files("examples")

# Cargo fails manifest parsing when a declared [[bin]]/[[example]]/[[bench]]
# target file is missing from the snapshot, so include every explicit path the
# pinned manifest declares as well (e.g. examples living under tests/oracle).
pinned_manifest = subprocess.check_output(
    [host_git_bin, "-C", str(repo_root), "show", f"{pinned_base}:Cargo.toml"],
    text=True,
)
for match in re.finditer(r'(?m)^\s*path\s*=\s*"([^"]+)"\s*$', pinned_manifest):
    declared = pathlib.Path(match.group(1))
    if declared.suffix == ".rs":
        crate_files.append(declared)
crate_files = sorted(set(crate_files), key=lambda path: path.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-sleigh-flow-relative-lib-snapshot-v1\0")
crate_bytes = {}
for relative in crate_files:
    data = snapshot_crate_file(relative)
    crate_bytes[relative.as_posix()] = data
    encoded = relative.as_posix().encode("utf-8")
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_files = [
    pathlib.Path("tests/oracle/sleigh_flow_relative_1204.cc"),
    pathlib.Path("tests/oracle/sleigh_flow_relative_1204.rs"),
    pathlib.Path("tests/oracle/sleigh_flow_relative_1204.metadata.json"),
    pathlib.Path("tools/run_sleigh_flow_relative_oracle.sh"),
    pathlib.Path("docs/api/disasm/sleigh_lift.md"),
    pathlib.Path("docs/api/flow.md"),
    pathlib.Path("docs/api/funcdata.md"),
    pathlib.Path("sleigh_specs/x86-64.sla"),
    pathlib.Path("sleigh_specs/x86-64.pspec"),
    pathlib.Path("sleigh_specs/x86-64-gcc.cspec"),
    pathlib.Path("sleigh_specs/x86.ldefs"),
]
special_bytes = {}
for relative in special_files:
    special_bytes[relative.as_posix()] = snapshot_file(relative)

metadata = json.loads(
    special_bytes["tests/oracle/sleigh_flow_relative_1204.metadata.json"].decode("utf-8")
)

def require_equal(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label):
    if isinstance(value, str) and value.startswith("PENDING_"):
        raise SystemExit(f"{label} is still pending: {value}")

require_equal("metadata schema", metadata["schema_version"], 1)
require_equal("fixture id", metadata["fixture_id"], "SLEIGH-FLOW-REL-0001")
oracle = metadata["oracle"]
require_equal("oracle tag", oracle["tag"], oracle_tag)
require_equal("oracle commit", oracle["commit"], oracle_commit)
require_equal("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require_equal("oracle x86 language tree", oracle["x86_language_tree"], language_tree)
require_equal("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require_equal("architecture", metadata["architecture"], "x86:LE:64:default")
require_equal("compiler spec id", metadata["compiler_spec"]["id"], "gcc")

ghidra_root = repo_root / "ghidra"
for source_name, expected_oid in oracle["source_blobs"].items():
    object_spec = (
        f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp/"
        f"{source_name}"
    )
    actual_oid = subprocess.check_output(
        [host_git_bin, "-C", str(ghidra_root), "rev-parse", object_spec],
        text=True,
    ).strip()
    require_equal(f"locked source blob {source_name}", actual_oid, expected_oid)

asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
for key, relative in asset_paths.items():
    asset = metadata["assets"][key]
    require_equal(f"{key} path", asset["path"], relative)
    require_equal(f"{key} sha256", sha256_bytes(special_bytes[relative]), asset["sha256"])
if metadata["assets"]["sla"]["size"] != len(special_bytes[asset_paths["sla"]]):
    raise SystemExit("SLA byte size mismatch")
for key in ("processor_spec", "compiler_spec", "language_definitions"):
    asset = metadata["assets"][key]
    object_spec = f"{oracle_commit}:Ghidra/Processors/x86/data/languages/{pathlib.Path(asset['path']).name}"
    actual_oid = subprocess.check_output(
        [host_git_bin, "-C", str(ghidra_root), "rev-parse", object_spec],
        text=True,
    ).strip()
    require_equal(f"locked asset blob {key}", actual_oid, asset["blob"])

comparand = metadata["comparand"]
reject_pending(comparand["pinned_base_commit"], "comparand.pinned_base_commit")
reject_pending(comparand["pinned_base_tree"], "comparand.pinned_base_tree")
require_equal("pinned base commit", comparand["pinned_base_commit"], pinned_base)
pinned_base_tree = subprocess.check_output(
    [host_git_bin, "-C", str(repo_root), "rev-parse", f"{pinned_base}^{{tree}}"],
    text=True,
).strip()
require_equal("pinned base tree", comparand["pinned_base_tree"], pinned_base_tree)
pending_pins = sorted(
    key for key, value in comparand.items()
    if isinstance(value, str) and value.startswith("PENDING_")
)
if pending_pins:
    raise SystemExit(
        "comparand metadata is intentionally fail-closed; pending pins: "
        + ",".join(pending_pins)
    )
observed_hashes = {
    "cpp_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/sleigh_flow_relative_1204.cc"]),
    "rust_fixture_sha256": sha256_bytes(special_bytes["tests/oracle/sleigh_flow_relative_1204.rs"]),
    "runner_sha256": runner_snapshot_sha,
    "sleigh_lift_rs_sha256": sha256_bytes(crate_bytes["src/disasm/sleigh_lift.rs"]),
    "flow_rs_sha256": sha256_bytes(crate_bytes["src/flow.rs"]),
    "funcdata_rs_sha256": sha256_bytes(crate_bytes["src/funcdata.rs"]),
    "sleigh_lift_doc_sha256": sha256_bytes(special_bytes["docs/api/disasm/sleigh_lift.md"]),
    "flow_doc_sha256": sha256_bytes(special_bytes["docs/api/flow.md"]),
    "funcdata_doc_sha256": sha256_bytes(special_bytes["docs/api/funcdata.md"]),
    "cargo_toml_sha256": sha256_bytes(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha256_bytes(crate_bytes["Cargo.lock"]),
    "build_rs_sha256": sha256_bytes(crate_bytes["build.rs"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require_equal(
    "runner snapshot/live copy",
    sha256_bytes(special_bytes["tools/run_sleigh_flow_relative_oracle.sh"]),
    runner_snapshot_sha,
)
require_equal(
    "crate snapshot scheme", comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-sleigh-flow-relative-lib-snapshot-v1 plus sorted length-prefixed relative paths and contents from the pinned base commit with the leased SLEIGH-FLOW-REL-0001 overlay files taken from the working tree",
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
    "host_objcopy_path": host_objcopy_bin,
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
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require_equal(
    "input manifest scheme",
    manifest["canonicalization"],
    "SHA-256 of UTF-8 json.dumps({architecture,compiler_spec,analysis_options,cases}, sort_keys=True, separators=(',',':'), ensure_ascii=False)",
)
reject_pending(manifest["sha256"], "input_manifest.sha256")
require_equal("input manifest sha256", sha256_bytes(canonical), manifest["sha256"])
require_equal(
    "locked input manifest sha256", manifest["sha256"],
    "dd8931d44a44d66f7cd68150f81e290a1433966789e14a94a18b79f21297759b",
)
for case in manifest["cases"]:
    image = bytes.fromhex(case["image_hex"])
    require_equal(f"{case['id']} image size", len(image), case["image_size"])
    require_equal(f"{case['id']} image sha256", sha256_bytes(image), case["image_sha256"])
require_equal("overall status", metadata["overall_status"], "MATCH")
require_equal(
    "locked stdout hash",
    metadata["locked_ghidra_capture"]["stdout_sha256"],
    "7490edf559b04929714d4d2c3f92166ea08c522acd1a0e2f7832c95cd3428be8",
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

metadata="$snapshot_root/tests/oracle/sleigh_flow_relative_1204.metadata.json"
cpp_fixture="$snapshot_root/tests/oracle/sleigh_flow_relative_1204.cc"
rust_fixture="$snapshot_root/tests/oracle/sleigh_flow_relative_1204.rs"
spec_root="$snapshot_root/sleigh_specs"
sla="$spec_root/x86-64.sla"

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
/usr/bin/cp -- "$cpp_fixture" "$cpp_fixture_dir/sleigh_flow_relative_1204.cc"
cpp_fixture="$cpp_fixture_dir/sleigh_flow_relative_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/raw_arch.cc" \
  "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/sleigh_flow_relative_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

raw_image="$oracle_tmp/0fa2c3.bin"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_objcopy_bin" \
  --dump-section ".rudra_input=$raw_image" \
  "$oracle_tmp/sleigh_flow_relative_1204_cpp"
if [[ ! -f "$raw_image" || -L "$raw_image" ]]; then
  echo "failed to extract the locked raw input section" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$raw_image" <<'PY'
import hashlib
import pathlib
import sys

image = pathlib.Path(sys.argv[1]).read_bytes()
if image != bytes.fromhex("0fa2c3"):
    raise SystemExit(f"extracted input mismatch: {image.hex()}")
expected = "fb4cb7c9460ac01bfda205963442edccc78b12c6212c101937937ff250a68c72"
if hashlib.sha256(image).hexdigest() != expected:
    raise SystemExit("extracted input SHA-256 mismatch")
PY

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
  "$rust_fixture" -o "$oracle_tmp/sleigh_flow_relative_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

(
  cd "$snapshot_root"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$oracle_tmp/sleigh_flow_relative_1204_cpp" "$spec_root" "$raw_image" \
    >"$oracle_tmp/ghidra.stdout"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$oracle_tmp/sleigh_flow_relative_1204_rust" "$sla" "$raw_image" \
    >"$oracle_tmp/rudra.stdout"
)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys
from collections import Counter

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_bytes()
rudra_stdout = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra_stdout != rudra_stdout:
    raise SystemExit("byte comparison unexpectedly diverged after diff succeeded")
if not ghidra_stdout.endswith(b"\n"):
    raise SystemExit("NDJSON output lacks the required final newline")

records = [json.loads(line) for line in ghidra_stdout.decode("utf-8").splitlines()]
expected_counts = {
    "header": 1,
    "flow_state": 1,
    "visited": 2,
    "op": 81,
    "varnode": 186,
    "relative": 33,
    "raw_edge": 49,
    "block": 34,
    "summary": 1,
}
counts = Counter(record.get("record") for record in records)
if dict(counts) != expected_counts:
    raise SystemExit(f"record-count mismatch: {counts}")
expected_record_order = [
    "header", "flow_state", *(["visited"] * 2), *(["op"] * 81),
    *(["varnode"] * 186), *(["relative"] * 33), *(["raw_edge"] * 49),
    *(["block"] * 34), "summary",
]
if [record.get("record") for record in records] != expected_record_order:
    raise SystemExit("NDJSON record segment order mismatch")
if len(records) != metadata["locked_ghidra_capture"]["records"]:
    raise SystemExit("metadata record count mismatch")
if len(ghidra_stdout) != metadata["locked_ghidra_capture"]["bytes"]:
    raise SystemExit("metadata byte count mismatch")

header = records[0]
if header != {
    "architecture": "x86:LE:64:default",
    "compiler_spec": "gcc",
    "input_hex": "0fa2c3",
    "loaded_archid": "x86:LE:64:default:gcc",
    "record": "header",
}:
    raise SystemExit(f"header mismatch: {header}")

flow_state = next(record for record in records if record["record"] == "flow_state")
for key, expected in {
    "addrlist_count": 0,
    "flags": 32,
    "function_size": 0,
    "inject_count": 0,
    "instruction_count": 2,
    "instruction_max": 100000,
    "phase": "post_generate_blocks",
    "table_count": 0,
    "unprocessed_count": 0,
    "visited_count": 2,
}.items():
    if flow_state[key] != expected:
        raise SystemExit(f"flow_state {key} mismatch: {flow_state[key]}")

visited = [record for record in records if record["record"] == "visited"]
visited_tuples = [
    (record["address"]["offset"], record["first_seq"]["time"], record["size"])
    for record in visited
]
if visited_tuples != [
    ("0x0000000000000000", 0, 2),
    ("0x0000000000000002", 78, 1),
]:
    raise SystemExit(f"visited state mismatch: {visited_tuples}")

ops = [record for record in records if record["record"] == "op"]
if [record["id"] for record in ops] != list(range(81)):
    raise SystemExit("operation identities/order are not canonical")
if [record["seq"]["time"] for record in ops] != list(range(81)):
    raise SystemExit("immutable SeqNum time sequence mismatch")
if [record["seq"]["address"]["offset"] for record in ops[:78]] != [
    "0x0000000000000000"
] * 78:
    raise SystemExit("CPUID operation addresses mismatch")
if [record["seq"]["address"]["offset"] for record in ops[78:]] != [
    "0x0000000000000002"
] * 3:
    raise SystemExit("RET operation addresses mismatch")
expected_opcodes = {
    "BRANCH": 17,
    "CALLOTHER": 17,
    "CBRANCH": 16,
    "INT_EQUAL": 16,
    "LOAD": 5,
    "INT_ADD": 4,
    "INT_ZEXT": 4,
    "COPY": 1,
    "RETURN": 1,
}
if dict(Counter(record["opcode_name"] for record in ops)) != expected_opcodes:
    raise SystemExit("operation opcode multiset mismatch")

varnodes = [record for record in records if record["record"] == "varnode"]
if [record["id"] for record in varnodes] != list(range(186)):
    raise SystemExit("post-emission Varnode identities are not canonical")
if [record["create_index"] for record in varnodes] != list(range(186)):
    raise SystemExit("Varnode creation order mismatch")
if sum(record["kind"] == "spaceid" for record in varnodes) != 5:
    raise SystemExit("LOAD/STORE space-id normalization count mismatch")
if any("identity" in record for record in varnodes):
    raise SystemExit("SLEIGH ABI pointer identity leaked into post-emission records")
code_refs = [
    varnodes[record["inputs"][0]]
    for record in ops
    if record["opcode_name"] in ("BRANCH", "CBRANCH", "CALL")
]
if len(code_refs) != 33 or any(
    record["space"]["name"] != "const"
    or record["size"] != 1
    or record["type"] != {"metatype": 11, "name": "code", "size": 1}
    or record["flags"] != 16777222
    for record in code_refs
):
    raise SystemExit("Const-space code-reference Varnode state mismatch")

expected_def = {}
expected_descendants = [[] for _ in varnodes]
for operation in ops:
    output = operation["output"]
    if output is not None:
        if output in expected_def:
            raise SystemExit("multiple operations define one post-emission Varnode")
        expected_def[output] = operation["id"]
    for input_id in operation["inputs"]:
        expected_descendants[input_id].append(operation["id"])
for varnode in varnodes:
    if varnode["def"] != expected_def.get(varnode["id"]):
        raise SystemExit(f"Varnode definition mismatch: {varnode['id']}")
    if varnode["descendants"] != expected_descendants[varnode["id"]]:
        raise SystemExit(f"Varnode descendant order mismatch: {varnode['id']}")

relatives = [record for record in records if record["record"] == "relative"]
if any(record["kind"] != "internal" for record in relatives):
    raise SystemExit("CPUID fixture unexpectedly contains a relative fallthrough")
for record in relatives:
    if record["computed_target_time"] != record["target"]:
        raise SystemExit(f"relative target mismatch: {record}")
    if record["target_address"] is not None:
        raise SystemExit("internal relative target carried a machine address")

raw_edges = [record for record in records if record["record"] == "raw_edge"]
if [record["ordinal"] for record in raw_edges] != list(range(49)):
    raise SystemExit("raw edge order mismatch")
blocks = [record for record in records if record["record"] == "block"]
if [record["id"] for record in blocks] != list(range(34)):
    raise SystemExit("block order mismatch")
if [record["id"] for record in blocks if record["entry"]] != [0]:
    raise SystemExit("official entry-block identity mismatch")
partitioned_ops = [operation for block in blocks for operation in block["ops"]]
if sorted(partitioned_ops) != list(range(81)) or len(set(partitioned_ops)) != 81:
    raise SystemExit("basic blocks do not partition the operation identities")
for block in blocks:
    expected_orders = [0x800002 + slot * 0x800000 for slot in range(len(block["ops"]))]
    observed_orders = [ops[operation]["seq"]["order"] for operation in block["ops"]]
    if observed_orders != expected_orders:
        raise SystemExit(f"BlockBasic::insert order mismatch in block {block['id']}")
    for operation in block["ops"]:
        if ops[operation]["parent_block"] != block["id"]:
            raise SystemExit(f"operation parent mismatch: {operation}")

out_seen = Counter()
in_seen = Counter()
for raw_edge in raw_edges:
    source_block = ops[raw_edge["source"]]["parent_block"]
    target_block = ops[raw_edge["target"]]["parent_block"]
    out_slot = out_seen[source_block]
    in_slot = in_seen[target_block]
    expected_out = {"block": target_block, "flags": 0, "reverse": in_slot}
    expected_in = {"block": source_block, "flags": 0, "reverse": out_slot}
    if blocks[source_block]["outgoing"][out_slot] != expected_out:
        raise SystemExit(f"ordered outgoing edge mismatch: {raw_edge}")
    if blocks[target_block]["incoming"][in_slot] != expected_in:
        raise SystemExit(f"ordered incoming edge mismatch: {raw_edge}")
    out_seen[source_block] += 1
    in_seen[target_block] += 1
for block in blocks:
    if out_seen[block["id"]] != len(block["outgoing"]):
        raise SystemExit(f"unaccounted outgoing edge in block {block['id']}")
    if in_seen[block["id"]] != len(block["incoming"]):
        raise SystemExit(f"unaccounted incoming edge in block {block['id']}")

summary = records[-1]
expected_summary = metadata["input_manifest"]["cases"][0]["expected_locked_summary"]
observed_summary = {key: summary[key] for key in expected_summary}
if observed_summary != expected_summary:
    raise SystemExit(f"summary mismatch: {observed_summary}")

actual_sha = hashlib.sha256(ghidra_stdout).hexdigest()
expected_sha = metadata["locked_ghidra_capture"]["stdout_sha256"]
if actual_sha != expected_sha:
    raise SystemExit(f"locked stdout hash mismatch: expected={expected_sha} actual={actual_sha}")
PY

/usr/bin/printf 'sleigh_flow_relative_1204: MATCH records=388 ops=81 varnodes=186 relatives=33 blocks=34 edges=49 visited=2\n'
