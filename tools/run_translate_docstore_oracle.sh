#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Translate::initialize / DocumentStorage unification oracle runner
# (TRANSLATE-DOCSTORE-UNIFY-0001). Builds the locked Ghidra 12.0.4
# libdecomp oracle and an isolated base-plus-overlay Rust snapshot, runs
# both translate_docstore_1204 fixtures (Sleigh::initialize DocumentStorage
# prologue: missing-tag message, content-as-path open error, same-name
# registerTag overwrite, name-keyed lookup) on identical inputs, and diffs
# the canonical record projections byte for byte.

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
runner="$repo_root/tools/run_translate_docstore_oracle.sh"
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
rust_toolchain=nightly-x86_64-unknown-linux-gnu
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
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=4456a57d3715be2de57d26d018bc2778067ef8b7
rudra_base_tree=903aff2250af2b8f7ac53565f89a821c14e58c08
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/translate_docstore_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/translate_docstore_1204.cc"
rust_fixture="$repo_root/tests/oracle/translate_docstore_1204.rs"
translate_rs="$repo_root/src/translate.rs"
translate_doc="$repo_root/docs/api/translate.md"
registry_cache="$user_home/.cargo/registry/cache"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$translate_rs" \
  "$translate_doc"; do
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
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "locked Rudra base tree mismatch" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-translate-docstore-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-translate-docstore-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_root="$oracle_tmp/workspace"
cargo_home="$oracle_tmp/cargo-home"
oracle_source="$oracle_tmp/oracle-source"
mkdir -p "$snapshot_root" "$oracle_source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive "$rudra_base_commit" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/cp -- "$translate_rs" "$snapshot_root/src/translate.rs"
/usr/bin/cp -- "$translate_doc" "$snapshot_root/docs/api/translate.md"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools"
/usr/bin/cp -- "$cpp_fixture" "$snapshot_root/tests/oracle/translate_docstore_1204.cc"
/usr/bin/cp -- "$rust_fixture" "$snapshot_root/tests/oracle/translate_docstore_1204.rs"
/usr/bin/cp -- "$metadata" "$snapshot_root/tests/oracle/translate_docstore_1204.metadata.json"
/usr/bin/cp -- "$runner_fd_path" "$snapshot_root/tools/run_translate_docstore_oracle.sh"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root" "$cargo_home" "$registry_cache" \
  "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$host_git_bin" "$host_python_bin" "$host_cxx_bin" "$host_rustc_bin" "$host_cargo_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$rust_toolchain" \
  "$user_home" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    snapshot_raw, cargo_home_raw, registry_cache_raw,
    runner_sha, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    base_commit, base_tree, host_git, host_python, host_cxx, host_rustc, host_cargo,
    host_cc, host_ar, host_make, rust_toolchain, user_home,
) = sys.argv[1:]
snapshot = pathlib.Path(snapshot_raw)
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

metadata_path = snapshot / "tests/oracle/translate_docstore_1204.metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
reject_pending(metadata)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "TRANSLATE-DOCSTORE-UNIFY-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require("architecture", metadata["architecture"], "N/A (DocumentStorage contract)")
require("compiler spec", metadata["compiler_spec"], "N/A")
require(
    "initialize observation status",
    metadata["coverage"]["initialize_contract_status"], "MATCH")
require(
    "residual statuses",
    [item["status"] for item in metadata["residuals"]],
    ["UNTESTED", "UNTESTED"])
require(
    "snapshot model",
    metadata["comparand"]["snapshot_model"],
    "git archive locked base tree plus exact owned-file overlays")
require(
    "overlay paths",
    metadata["comparand"]["overlay_paths"],
    [
        "src/translate.rs",
        "docs/api/translate.md",
        "tests/oracle/translate_docstore_1204.cc",
        "tests/oracle/translate_docstore_1204.rs",
        "tests/oracle/translate_docstore_1204.metadata.json",
        "tools/run_translate_docstore_oracle.sh",
    ],
)

paths = {
    "cpp_fixture_sha256": snapshot / "tests/oracle/translate_docstore_1204.cc",
    "rust_fixture_sha256": snapshot / "tests/oracle/translate_docstore_1204.rs",
    "translate_rs_sha256": snapshot / "src/translate.rs",
    "translate_doc_sha256": snapshot / "docs/api/translate.md",
    "runner_sha256": snapshot / "tools/run_translate_docstore_oracle.sh",
    "cargo_toml_sha256": snapshot / "Cargo.toml",
    "cargo_lock_sha256": snapshot / "Cargo.lock",
    "build_rs_sha256": snapshot / "build.rs",
}
for key, path in paths.items():
    actual = sha(path.read_bytes())
    expected = metadata["comparand"][key]
    require(key, actual, expected)
require("immutable runner hash", sha(paths["runner_sha256"].read_bytes()), runner_sha)

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

package_blocks = paths["cargo_lock_sha256"].read_text(encoding="utf-8").split("[[package]]")[1:]
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
    "$host_cargo_bin" build --quiet --locked --offline --lib
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
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

cpp_fixture="$snapshot_root/tests/oracle/translate_docstore_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture" "$standard_archive" -lz \
  -o "$oracle_tmp/translate_docstore_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

rust_fixture="$snapshot_root/tests/oracle/translate_docstore_1204.rs"
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/translate_docstore_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/translate_docstore_1204_cpp" >"$oracle_tmp/ghidra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/translate_docstore_1204_rust" >"$oracle_tmp/rudra.stdout"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root/tests/oracle/translate_docstore_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra != rudra:
    raise SystemExit("byte comparison unexpectedly diverged after diff succeeded")
if not ghidra.endswith(b"\n"):
    raise SystemExit("fixture output lacks final newline")
lines = ghidra.decode("utf-8").splitlines()
expected_last = "S|DONE"
if lines[-1] != expected_last:
    raise SystemExit(f"fixture summary mismatch: {lines[-1]!r}")
prefixes = {prefix: sum(line.startswith(prefix + "|") for line in lines)
            for prefix in ("I", "S")}
if prefixes != metadata["coverage"]["record_counts"]:
    raise SystemExit(f"fixture record counts mismatch: {prefixes}")
capture = metadata["locked_capture"]
actual_hash = hashlib.sha256(ghidra).hexdigest()
if isinstance(capture["bytes"], str) and capture["bytes"].startswith("PENDING"):
    raise SystemExit(
        f"locked capture is pending: records={len(lines)} bytes={len(ghidra)} "
        f"stdout_sha256={actual_hash}"
    )
if len(ghidra) != capture["bytes"] or len(lines) != capture["records"]:
    raise SystemExit("locked capture size mismatch")
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("locked capture hash mismatch")
print(f"records={len(lines)} bytes={len(ghidra)} stdout_sha256={actual_hash}")
print("initialize_contract=MATCH overall=MATCH")
PY
