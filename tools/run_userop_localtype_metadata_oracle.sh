#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# USEROP-LOCALTYPE-METADATA-0001 locked Ghidra/Rudra differential runner.
# The Rust comparand is a complete git archive of the pinned Rudra base with
# exactly one production overlay: src/userop.rs. No other live Rust source is
# read or copied into the build.

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
runner="$repo_root/tools/run_userop_localtype_metadata_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
rust_toolchain=system-x86_64-unknown-linux-gnu
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
# Task USEROP-LOCALTYPE-METADATA-0001 dedicated Cargo dirs: every Cargo
# invocation below is serialized on the shared build flock and uses these
# isolated, pre-created directories (never /tmp or a shared target).
cargo_target=/home/wirs/.cache/a48-userop-target
cargo_tmp=/home/wirs/.cache/a48-userop-tmp
/usr/bin/mkdir -p "$cargo_target" "$cargo_tmp"
for cargo_dir in "$cargo_target" "$cargo_tmp"; do
  if [[ ! -d "$cargo_dir" || -L "$cargo_dir" ]]; then
    echo "dedicated Cargo directory is not a regular directory: $cargo_dir" >&2
    exit 1
  fi
done

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
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
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=a29f5b76079b95acd52b176456c1f52772c511e7
rudra_base_tree=6438abb6a421296eff5b8c74ffff7f3b88363dcf
ghidra_root="$repo_root/ghidra"
metadata_live="$repo_root/tests/oracle/userop_localtype_metadata_1204.metadata.json"
cpp_fixture_live="$repo_root/tests/oracle/userop_localtype_metadata_1204.cc"
rust_fixture_live="$repo_root/tests/oracle/userop_localtype_metadata_1204.rs"
userop_source_live="$repo_root/src/userop.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(/usr/bin/dirname "$bfd_library")
registry_cache="$user_home/.cargo/registry/cache"

for required in "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
  "$userop_source_live" "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "locked Rudra base tree mismatch" >&2
  exit 1
fi

verify_owned_inputs() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
    - "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
    "$userop_source_live" "$runner_sha" "$oracle_commit" "$oracle_tag" \
    "$rudra_base_commit" "$rudra_base_tree" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, userop_raw, runner_sha,
    oracle_commit, oracle_tag, base_commit, base_tree,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "USEROP-LOCALTYPE-METADATA-0001")
require("projection status", metadata["projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "UNTESTED")
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require(
    "snapshot model",
    metadata["comparand"]["snapshot_model"],
    "git archive locked base tree plus src/userop.rs overlay",
)
require("overlay paths", metadata["comparand"]["overlay_paths"], ["src/userop.rs"])
require("C++ fixture hash", sha(cpp_raw), metadata["comparand"]["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_raw), metadata["comparand"]["rust_fixture_sha256"])
require("userop overlay hash", sha(userop_raw), metadata["comparand"]["userop_rs_sha256"])
require("runner hash", runner_sha, metadata["comparand"]["runner_sha256"])
PY
}

verify_owned_inputs

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-userop-localtype-metadata-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-userop-localtype-metadata-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_root="$oracle_tmp/workspace"
fixture_root="$oracle_tmp/fixtures"
oracle_source="$oracle_tmp/oracle-source"
cargo_home="$oracle_tmp/cargo-home"
/usr/bin/mkdir -p "$snapshot_root" "$fixture_root" "$oracle_source"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive "$rudra_base_commit" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

# The sole production overlay. Fixtures are copied outside the Cargo workspace.
/usr/bin/install -D "$userop_source_live" "$snapshot_root/src/userop.rs"
/usr/bin/install -D "$cpp_fixture_live" "$fixture_root/userop_localtype_metadata_1204.cc"
/usr/bin/install -D "$rust_fixture_live" "$fixture_root/userop_localtype_metadata_1204.rs"
/usr/bin/install -D "$metadata_live" "$fixture_root/userop_localtype_metadata_1204.metadata.json"

spec_root="$snapshot_root/sleigh_specs"
binary="$snapshot_root/examples/curl"
for pinned in "$snapshot_root/Cargo.toml" "$snapshot_root/Cargo.lock" \
  "$snapshot_root/build.rs" "$spec_root/x86-64.sla" \
  "$spec_root/x86-64.pspec" "$spec_root/x86-64-gcc.cspec" \
  "$spec_root/x86.ldefs" "$binary"; do
  if [[ ! -f "$pinned" || -L "$pinned" ]]; then
    echo "pinned base input is not a regular file: $pinned" >&2
    exit 1
  fi
done

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root" "$fixture_root" "$cargo_home" "$registry_cache" \
  "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$host_git_bin" "$host_python_bin" "$host_cxx_bin" "$host_rustc_bin" \
  "$host_cargo_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$rust_toolchain" "$bfd_include/bfd.h" "$bfd_library" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    snapshot_raw, fixture_raw, cargo_home_raw, registry_cache_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, host_git, host_python, host_cxx, host_rustc,
    host_cargo, host_cc, host_ar, host_make, rust_toolchain,
    bfd_header_raw, bfd_library_raw,
) = sys.argv[1:]
snapshot = pathlib.Path(snapshot_raw)
fixture = pathlib.Path(fixture_raw)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, label="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{label}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{label} is pending: {value}")

metadata_path = fixture / "userop_localtype_metadata_1204.metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
reject_pending(metadata)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "USEROP-LOCALTYPE-METADATA-0001")
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle C++ tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require("projection status", metadata["projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "UNTESTED")
require("coverage projection", metadata["coverage"]["projection_status"], "MATCH")
require("coverage overall", metadata["coverage"]["overall_status"], "UNTESTED")
require(
    "snapshot model",
    metadata["comparand"]["snapshot_model"],
    "git archive locked base tree plus src/userop.rs overlay",
)
require("overlay paths", metadata["comparand"]["overlay_paths"], ["src/userop.rs"])

comparand_paths = {
    "cpp_fixture_sha256": fixture / "userop_localtype_metadata_1204.cc",
    "rust_fixture_sha256": fixture / "userop_localtype_metadata_1204.rs",
    "userop_rs_sha256": snapshot / "src/userop.rs",
    "cargo_toml_sha256": snapshot / "Cargo.toml",
    "cargo_lock_sha256": snapshot / "Cargo.lock",
    "build_rs_sha256": snapshot / "build.rs",
}
for key, path in comparand_paths.items():
    require(key, sha(path.read_bytes()), metadata["comparand"][key])
require("runner sha256", runner_sha, metadata["comparand"]["runner_sha256"])

asset_paths = {
    "sla_sha256": snapshot / "sleigh_specs/x86-64.sla",
    "pspec_sha256": snapshot / "sleigh_specs/x86-64.pspec",
    "cspec_sha256": snapshot / "sleigh_specs/x86-64-gcc.cspec",
    "ldefs_sha256": snapshot / "sleigh_specs/x86.ldefs",
    "binary_sha256": snapshot / "examples/curl",
    "bfd_header_sha256": pathlib.Path(bfd_header_raw),
    "bfd_library_sha256": pathlib.Path(bfd_library_raw),
}
for key, path in asset_paths.items():
    require(key, sha(path.read_bytes()), metadata["assets"][key])

host = metadata["host_tools"]
require("host cxx", subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0], host["cxx"])
require("host cxx target", subprocess.check_output([host_cxx, "-dumpmachine"], text=True).strip(), host["cxx_target"])
require("host cc", subprocess.check_output([host_cc, "--version"], text=True).splitlines()[0], host["cc"])
require("host cc target", subprocess.check_output([host_cc, "-dumpmachine"], text=True).strip(), host["cc_target"])
require("host ar", subprocess.check_output([host_ar, "--version"], text=True).splitlines()[0], host["ar"])
require("host make", subprocess.check_output([host_make, "--version"], text=True).splitlines()[0], host["make"])
require("host python", subprocess.check_output([host_python, "--version"], text=True).strip(), host["python"])
require("host git", subprocess.check_output([host_git, "--version"], text=True).strip(), host["git"])
require("host rustc", subprocess.check_output([host_rustc, "--version"], text=True).strip(), host["rustc"])
require("host cargo", subprocess.check_output([host_cargo, "--version"], text=True).strip(), host["cargo"])
require("rust toolchain", host["rust_toolchain"], rust_toolchain)

lock_text = comparand_paths["cargo_lock_sha256"].read_text(encoding="utf-8")
package_blocks = lock_text.split("[[package]]")[1:]
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
    require("Cargo source", source, "registry+https://github.com/rust-lang/crates.io-index")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require("registry package count", len(registry_packages), metadata["build"]["registry_packages"])
if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit("registry archive cache is not a real directory")

vendor_root = snapshot / "vendor"
vendor_root.mkdir()
for name, version, checksum in registry_packages:
    archive_name = f"{name}-{version}.crate"
    matches = []
    for namespace in registry_cache.iterdir():
        if namespace.is_symlink() or not namespace.is_dir():
            raise SystemExit(f"invalid registry cache namespace: {namespace}")
        candidate = namespace / archive_name
        if candidate.exists():
            matches.append(candidate)
    if len(matches) != 1:
        raise SystemExit(f"expected one cached archive for {name} {version}, found {matches}")
    archive_bytes = matches[0].read_bytes()
    require(f"Cargo checksum {name} {version}", sha(archive_bytes), checksum)
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
                raise SystemExit(f"unsafe crate path: {member.name!r}")
            relative_parts = parts[1:]
            if not relative_parts:
                if not member.isdir():
                    raise SystemExit(f"crate root is not a directory: {member.name!r}")
                continue
            relative = pathlib.PurePosixPath(*relative_parts).as_posix()
            if relative in seen:
                raise SystemExit(f"duplicate crate path: {member.name!r}")
            seen.add(relative)
            destination = package_root.joinpath(*relative_parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(member.mode & 0o777)
                continue
            if not member.isfile():
                raise SystemExit(f"unsupported crate member: {member.name!r}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            file_object = archive.extractfile(member)
            if file_object is None:
                raise SystemExit(f"crate member has no file object: {member.name!r}")
            data = file_object.read()
            require(f"crate member size {member.name}", len(data), member.size)
            destination.write_bytes(data)
            destination.chmod(member.mode & 0o777)
            file_hashes[relative] = sha(data)
    (package_root / ".cargo-checksum.json").write_text(
        json.dumps({"files": file_hashes, "package": checksum}, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\nreplace-with = \"locked-vendor\"\n\n"
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor_root))}\n",
    encoding="utf-8",
)
PY

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx_bin -std=c++11" "EXTRA=" libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
standard_archive="$oracle_cpp/libdecomp.a"
if [[ ! -f "$standard_archive" || -L "$standard_archive" ]]; then
  echo "locked Makefile did not produce a regular libdecomp.a" >&2
  exit 1
fi

fixture_target="$cargo_target"
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
if ! /usr/bin/flock -x /tmp/rudra-cargo-build.lock \
  /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    TMPDIR="$cargo_tmp" CARGO_INCREMENTAL=0 \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
    AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib \
    --manifest-path "$snapshot_root/Cargo.toml" \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" ]]; then
  echo "cargo build did not produce a regular librudra.rlib" >&2
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

cpp_fixture="$fixture_root/userop_localtype_metadata_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$standard_archive" \
  "$bfd_library" -lz -o "$oracle_tmp/userop_localtype_metadata_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

rust_fixture="$fixture_root/userop_localtype_metadata_1204.rs"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$cargo_tmp" \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/userop_localtype_metadata_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
  "$oracle_tmp/userop_localtype_metadata_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/userop_localtype_metadata_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$fixture_root/userop_localtype_metadata_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_stderr = pathlib.Path(sys.argv[4]).read_bytes()
rudra_stderr = pathlib.Path(sys.argv[5]).read_bytes()
if ghidra != rudra or ghidra_stderr != rudra_stderr:
    raise SystemExit("byte comparison unexpectedly diverged after diff succeeded")
if not ghidra.endswith(b"\n"):
    raise SystemExit("fixture output lacks final newline")
records = ghidra.decode("utf-8").splitlines()
capture = metadata["locked_capture"]
actual_hash = hashlib.sha256(ghidra).hexdigest()
stderr_hash = hashlib.sha256(ghidra_stderr).hexdigest()
if len(records) != capture["records"] or len(ghidra) != capture["bytes"]:
    raise SystemExit("locked capture size mismatch")
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("locked stdout hash mismatch")
if stderr_hash != capture["stderr_sha256"]:
    raise SystemExit("locked stderr hash mismatch")
if metadata["projection_status"] != "MATCH" or metadata["overall_status"] != "UNTESTED":
    raise SystemExit("metadata status mismatch")
print(f"records={len(records)} bytes={len(ghidra)} stdout_sha256={actual_hash}")
print(f"stderr_sha256={stderr_hash}")
print("userop_localtype_metadata_1204: projection_status=MATCH overall_status=UNTESTED")
PY

verify_owned_inputs
