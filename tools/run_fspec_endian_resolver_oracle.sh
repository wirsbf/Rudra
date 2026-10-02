#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# FSPEC-ENDIAN-RESOLVER-1204 oracle runner (pin-base schema2): rebuilds the
# locked Ghidra 12.0.4 decompiler and the pinned Rudra base plus the
# candidate src/fspec.rs overlay in an isolated snapshot, runs both
# fixtures byte-for-byte, and verifies every comparand hash in the
# metadata. Covered projection: Address::justifiedContain LE/BE x
# forceleft branch matrix (address.cc:138 base->isBigEndian() branch
# key), the unflagged LE ParamEntry ==0 wrapper route, the
# heritage.cc:1221 truncate SUBPIECE constant, and the
# characterizeAsParam resolver gating for extent-out queries
# (FSPEC-JUSTIFIED-ENDIAN-0002 + FSPEC-CHARACTERIZE-RESOLVER-GATE-0003).

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
runner="$repo_root/tools/run_fspec_endian_resolver_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
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

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=d32a0051cd99adf1d8feb4e1f92410cdff07aa35
rudra_base_tree=f7bfeaf5aad8adfd7476b9e212c82f0bb79f6251
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/fspec_endian_resolver_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/fspec_endian_resolver_1204.cc"
rust_fixture="$repo_root/tests/oracle/fspec_endian_resolver_1204.rs"
fspec_rs="$repo_root/src/fspec.rs"
fspec_doc="$repo_root/docs/api/fspec.md"
registry_cache="$user_home/.cargo/registry/cache"

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=/usr/bin/cargo
host_rustc_bin=/usr/bin/rustc
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$fspec_rs" "$fspec_doc" \
  "$runner"; do
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
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
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
  echo "locked Ghidra decompiler source tree is dirty" >&2
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

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-fspec-endian-resolver-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-fspec-endian-resolver-1204.?????? ]]; then
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
cargo_home="$user_home/.cargo"
owned_files=(
  "$fspec_rs"
  "$fspec_doc"
  "$cpp_fixture"
  "$rust_fixture"
  "$metadata"
  "$runner"
)
/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.before"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_python_bin" -I -S - "$repo_root" "$snapshot_root" "$cargo_home" \
  "$registry_cache" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$fspec_rs" "$fspec_doc" \
  "$runner_fd_path" "$runner_snapshot_sha" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_base_commit" "$rudra_base_tree" "$host_cxx" "$host_cxx_target" \
  "$host_rustc" "$host_cargo" "$host_platform" "$host_cxx_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$host_python_bin" \
  "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin" <<'PY'
import hashlib
import json
import pathlib
import re
import subprocess
import sys

(
    repo_raw, snapshot_raw, cargo_home_raw, registry_cache_raw,
    metadata_raw, cpp_raw, rust_raw, fspec_raw,
    fspec_doc_raw,
    runner_fd_raw, runner_snapshot_sha, oracle_tag, oracle_commit,
    cpp_tree, makefile_blob, rudra_base_commit, rudra_base_tree,
    host_cxx, host_cxx_target, host_rustc, host_cargo, host_platform,
    host_cxx_bin, host_cc_bin, host_ar_bin, host_make_bin,
    host_python_bin, host_git_bin, host_cargo_bin, host_rustc_bin,
) = sys.argv[1:]

repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
snapshot.mkdir(parents=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo / "tests/oracle/fspec_endian_resolver_1204.metadata.json",
    pathlib.Path(cpp_raw): repo / "tests/oracle/fspec_endian_resolver_1204.cc",
    pathlib.Path(rust_raw): repo / "tests/oracle/fspec_endian_resolver_1204.rs",
    pathlib.Path(fspec_raw): repo / "src/fspec.rs",
    pathlib.Path(fspec_doc_raw): repo / "docs/api/fspec.md",
}
for actual, expected in expected_paths.items():
    if actual.resolve() != expected.resolve():
        raise SystemExit(f"unexpected runner input path: {actual} != {expected}")

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
        host_git_bin, "-C", str(repo), "ls-tree", "-r", "--name-only", "-z",
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
        subprocess.check_output(
            [host_git_bin, "-C", str(repo), "cat-file", "-t", spec], text=True
        ).strip(),
        "blob",
    )
    return subprocess.check_output(
        [host_git_bin, "-C", str(repo), "cat-file", "blob", spec]
    )

def live_file(relative):
    source = repo / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular non-symlink file: {relative}")
    return source.read_bytes()

overlay_files = {
    pathlib.Path("src/fspec.rs"),
}
crate_files = [
    pathlib.Path("Cargo.toml"),
    pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"),
    pathlib.Path("README.md"),
    pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + base_source_files("src") + base_source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda item: item.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-fspec-endian-resolver-base-overlay-v1\0")
crate_hasher.update(rudra_base_commit.encode())
crate_bytes = {}
for relative in crate_files:
    data = live_file(relative) if relative in overlay_files else base_file(relative)
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    crate_bytes[relative.as_posix()] = data
    encoded = relative.as_posix().encode()
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_paths = [
    pathlib.Path("tests/oracle/fspec_endian_resolver_1204.cc"),
    pathlib.Path("tests/oracle/fspec_endian_resolver_1204.rs"),
    pathlib.Path("tests/oracle/fspec_endian_resolver_1204.metadata.json"),
    pathlib.Path("docs/api/fspec.md"),
    pathlib.Path("tools/run_fspec_endian_resolver_oracle.sh"),
]
special = {}
for relative in special_paths:
    if relative == special_paths[-1]:
        data = pathlib.Path(runner_fd_raw).read_bytes()
    else:
        data = live_file(relative)
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    special[relative.as_posix()] = data
require("immutable runner hash", sha(special[special_paths[-1].as_posix()]), runner_snapshot_sha)
require("live runner/FD hash", sha(live_file(special_paths[-1])), runner_snapshot_sha)

metadata = json.loads(special[special_paths[2].as_posix()].decode("utf-8"))
reject_pending(metadata)
require("metadata schema", metadata["schema"], 2)
require("fixture id", metadata["fixture_id"], "FSPEC-ENDIAN-RESOLVER-1204")
require("overall status", metadata["overall_status"], "UNTESTED")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob),
    ("Rudra base commit", metadata["comparand"]["rugra_base_commit"], rudra_base_commit),
    ("Rudra base tree", metadata["comparand"]["rugra_base_tree"], rudra_base_tree),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
observed_hashes = {
    "cpp_fixture_sha256": sha(special[special_paths[0].as_posix()]),
    "rust_fixture_sha256": sha(special[special_paths[1].as_posix()]),
    "fspec_rs_sha256": sha(crate_bytes["src/fspec.rs"]),
    "fspec_doc_sha256": sha(special[special_paths[3].as_posix()]),
    "runner_sha256": runner_snapshot_sha,
    "cargo_toml_sha256": sha(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha(crate_bytes["Cargo.lock"]),
    "build_rs_sha256": sha(crate_bytes["build.rs"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate snapshot scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-fspec-endian-resolver-base-overlay-v1 plus base commit and sorted length-prefixed paths and contents",
)
for key, actual in observed_hashes.items():
    require(key, actual, comparand[key])

host_values = {
    "cxx": host_cxx,
    "cxx_target": host_cxx_target,
    "cxx_path": host_cxx_bin,
    "cc_path": host_cc_bin,
    "ar_path": host_ar_bin,
    "make_path": host_make_bin,
    "python_path": host_python_bin,
    "git_path": host_git_bin,
    "rustc": host_rustc,
    "cargo": host_cargo,
    "cargo_path": host_cargo_bin,
    "rustc_path": host_rustc_bin,
    "platform": host_platform,
}
require("host toolchain", comparand["host"], host_values)

payload = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": metadata["input_manifest"]["cases"],
}
canonical = json.dumps(
    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha256", sha(canonical), metadata["input_manifest"]["sha256"])
require("expected exit code", metadata["expected_results"]["exit_code"], 0)
require("covered projection status", metadata["covered_projection_status"], "MATCH")

coverage = metadata["coverage"]
for required_key, required_prefix in (
    ("le_be_forceleft_matrix", "MATCH"),
    ("param_entry_le_unflagged_wrapper", "MATCH"),
    ("truncate_subpiece_constant", "MATCH"),
    ("characterize_resolver_gate", "MATCH"),
    ("be_param_entry_wrapper", "UNTESTED"),
    ("join_resolver_window", "UNTESTED"),
    ("space_mismatch_base_branch", "UNTESTED"),
    ("find_entry_resolver_gate", "UNTESTED"),
):
    if required_key not in coverage:
        raise SystemExit(f"coverage table missing {required_key}")
    if not coverage[required_key].startswith(required_prefix):
        raise SystemExit(
            f"coverage {required_key} must start with {required_prefix}: "
            f"{coverage[required_key]!r}"
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
    require(
        "Cargo registry source",
        source,
        "registry+https://github.com/rust-lang/crates.io-index",
    )
    for field in ("name", "version", "checksum"):
        if field not in fields:
            raise SystemExit(f"registry package missing {field}: {block[:160]!r}")
    registry_packages.append((fields["name"], fields["version"], fields["checksum"]))
require("locked registry package count", len(registry_packages), metadata["build"]["registry_packages"])

registry_hasher = hashlib.sha256()
registry_hasher.update(b"rudra-fspec-endian-resolver-registry-lock-v1\0")
for name, version, checksum in registry_packages:
    record = f"{name}\0{version}\0{checksum}".encode()
    registry_hasher.update(len(record).to_bytes(8, "big"))
    registry_hasher.update(record)
require(
    "registry lock closure sha256",
    registry_hasher.hexdigest(),
    metadata["build"]["registry_lock_closure_sha256"],
)

# Cargo itself selects the current target's dependency closure from the fully
# verified lockfile and validates cached crate checksums. Requiring archives
# for every foreign-target package (for example a Windows-only crate) would
# make a Linux oracle depend on irrelevant cache population.
PY

snapshot_metadata="$snapshot_root/tests/oracle/fspec_endian_resolver_1204.metadata.json"
snapshot_cpp="$snapshot_root/tests/oracle/fspec_endian_resolver_1204.cc"
snapshot_rust="$snapshot_root/tests/oracle/fspec_endian_resolver_1204.rs"

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/mkdir -p "$snapshot_decompiler"
/usr/bin/ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" CC="$host_cc_bin" AR="$host_ar_bin" \
    EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "locked archive rebuild did not produce a regular libdecomp.a" >&2
  exit 1
fi

cpp_binary="$oracle_tmp/fspec_endian_resolver_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
    -I"$oracle_cpp" "$snapshot_cpp" "$oracle_cpp/libdecomp.cc" \
    "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
    -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
    -o "$cpp_binary" >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

expected_stdout_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["expected_results"]["ghidra_stdout_sha256"])' \
  "$snapshot_metadata")
actual_stdout_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | /usr/bin/awk '{print $1}')
if [[ "$actual_stdout_sha" != "$expected_stdout_sha" ]]; then
  echo "locked Ghidra stdout hash mismatch" >&2
  exit 1
fi

if $ghidra_only; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  echo "fspec_endian_resolver_1204: GHIDRA_LOCKED_OUTPUT_OK covered=MATCH overall=UNTESTED stdout_sha256=$actual_stdout_sha"
  exit 0
fi

fixture_target=/home/wirs/.cache/a85-fspin-target/fspec-endian-resolver
/usr/bin/mkdir -p "$fixture_target"
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
if ! /usr/bin/flock /tmp/rudra-cargo-build.lock -c \
  "CARGO_HOME='$cargo_home' CARGO_TARGET_DIR='$fixture_target' CARGO_NET_OFFLINE=true CXX='$host_cxx_bin' CC='$host_cc_bin' AR='$host_ar_bin' RUSTC='$host_rustc_bin' timeout 600 '$host_cargo_bin' build --offline --locked --quiet --manifest-path '$snapshot_root/Cargo.toml' --lib" \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librudra_sleigh.a' -type f -print -quit)
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || \
      -z "$native_archive" || ! -f "$native_archive" ]]; then
  echo "fresh Rust link inputs are missing" >&2
  exit 1
fi
if [[ -L "$native_archive" || ! -f "$native_archive" ]]; then
  echo "fresh native archive is not a regular file" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")

rust_binary="$oracle_tmp/fspec_endian_resolver_1204_rust"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
    -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
    --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
    -l dylib=stdc++ -l dylib=m "$snapshot_rust" -o "$rust_binary" \
    >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rustc.stdout" || -s "$oracle_tmp/rustc.stderr" ]]; then
  echo "Rust fixture compilation emitted diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$rust_binary" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
/usr/bin/diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e
if [[ "$rudra_status" -ne 0 || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture failed or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ "$diff_status" -ne 0 ]]; then
  /usr/bin/cat "$oracle_tmp/raw.diff" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$snapshot_metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
raw_diff = pathlib.Path(sys.argv[4]).read_bytes()
expected = metadata["expected_results"]
for label, data, key in (
    ("Ghidra", ghidra, "ghidra_stdout_sha256"),
    ("Rudra", rudra, "rudra_stdout_sha256"),
):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected[key]:
        raise SystemExit(f"{label} stdout mismatch: expected={expected[key]} actual={actual}")
if raw_diff:
    raise SystemExit("byte-equal outputs unexpectedly produced a non-empty diff")
for label, status in (
    ("Ghidra", int(sys.argv[5])),
    ("Rudra", int(sys.argv[6])),
    ("raw diff", int(sys.argv[7])),
):
    if status != expected["exit_code"]:
        raise SystemExit(f"{label} exit mismatch: {status}")

lines = ghidra.decode("utf-8").splitlines()
if len(lines) != metadata["build"]["expected_stdout_lines"]:
    raise SystemExit(f"expected {metadata['build']['expected_stdout_lines']} fixture lines, found {len(lines)}")
if lines[0] != (
    "schema=1|fixture=FSPEC-ENDIAN-RESOLVER-1204|"
    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
):
    raise SystemExit("fixture envelope mismatch")
expected_cases = metadata["input_manifest"]["case_order"]
actual_cases = [line.split("|", 1)[0].removeprefix("case=") for line in lines[1:] if line.startswith("case=")]
if actual_cases != expected_cases:
    raise SystemExit(f"fixture case order mismatch: {actual_cases}")
PY

/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.after"
if ! /usr/bin/cmp -s "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned files were modified during the oracle run" >&2
  exit 1
fi

echo "fspec_endian_resolver_1204: OK covered=MATCH overall=UNTESTED ghidra=$actual_stdout_sha"
