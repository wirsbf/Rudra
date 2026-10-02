#!/usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  requested_tmpdir=${TMPDIR:-}
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin \
    RUDRA_HERITAGE_CALLGUARD_TMPDIR="$requested_tmpdir" \
    /usr/bin/bash "$runner_fd_path" "$@"
fi
requested_tmpdir=${RUDRA_HERITAGE_CALLGUARD_TMPDIR:-}
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_heritage_callguard_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

ghidra_only=false
validate_only=false
case ${1:-} in
  --ghidra-only)
    ghidra_only=true
    shift
    ;;
  --validate-only)
    validate_only=true
    shift
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only|--validate-only]" >&2
  exit 2
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi

if [[ -z "$requested_tmpdir" ]]; then
  requested_tmpdir="$user_home/.cache/rugra-heritage-callguard-1204/tmp"
  /usr/bin/mkdir -p -m 700 "$requested_tmpdir"
fi
if [[ "$requested_tmpdir" != /* || ! -d "$requested_tmpdir" || \
      -L "$requested_tmpdir" || ! -O "$requested_tmpdir" || \
      ! -w "$requested_tmpdir" || ! -x "$requested_tmpdir" ]]; then
  echo "TMPDIR must be an absolute, owned, writable, non-symlink directory" >&2
  exit 1
fi
resolved_tmpdir=$(/usr/bin/readlink -f -- "$requested_tmpdir")
if [[ -z "$resolved_tmpdir" || "$resolved_tmpdir" != "$requested_tmpdir" ]]; then
  echo "TMPDIR must be canonical and contain no symlink components" >&2
  exit 1
fi
tmpdir_mode=$(/usr/bin/stat -c '%a' -- "$requested_tmpdir")
if (( (8#$tmpdir_mode & 0022) != 0 )); then
  echo "TMPDIR must not be writable by group or other users" >&2
  exit 1
fi
runner_tmpdir="$resolved_tmpdir"

clean_path=/usr/bin:/bin
rust_toolchain=system
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=92daed300bcce3c4d855b311cf9667ba21eb475a
rugra_base_tree=6aea6d3b5b1421170d1bdc5a766c9568483a66af
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/heritage_callguard_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/heritage_callguard_1204.cc"
rust_fixture="$repo_root/tests/oracle/heritage_callguard_1204.rs"
heritage_rs="$repo_root/src/heritage.rs"
funcdata_rs="$repo_root/src/funcdata.rs"
fspec_rs="$repo_root/src/fspec.rs"
coreaction_rs="$repo_root/src/coreaction.rs"
flow_rs="$repo_root/src/flow.rs"
ruleaction_rs="$repo_root/src/ruleaction.rs"
signature_rs="$repo_root/src/signature.rs"
unionresolve_rs="$repo_root/src/unionresolve.rs"
varnode_rs="$repo_root/src/varnode.rs"
heritage_doc="$repo_root/docs/api/heritage.md"
funcdata_doc="$repo_root/docs/api/funcdata.md"
fspec_doc="$repo_root/docs/api/fspec.md"
registry_cache="$user_home/.cargo/registry/cache"

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_timeout_bin=$(/usr/bin/readlink -f /usr/bin/timeout)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" "$host_timeout_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
for required_file in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$coreaction_rs" "$flow_rs" "$fspec_rs" "$funcdata_rs" \
  "$heritage_rs" "$ruleaction_rs" "$signature_rs" "$unionresolve_rs" \
  "$varnode_rs" \
  "$heritage_doc" "$funcdata_doc" "$fspec_doc" \
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
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
if [[ "$actual_base_commit" != "$rugra_base_commit" || \
      "$actual_base_tree" != "$rugra_base_tree" ]]; then
  echo "pinned Rugra base identity mismatch" >&2
  exit 1
fi

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d "$runner_tmpdir/rugra-heritage-callguard-1204.XXXXXX")
cleanup() {
  if [[ "$oracle_tmp" != "$runner_tmpdir"/rugra-heritage-callguard-1204.?????? ]]; then
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
owned_files=(
  "$coreaction_rs"
  "$flow_rs"
  "$fspec_rs"
  "$funcdata_rs"
  "$heritage_rs"
  "$ruleaction_rs"
  "$signature_rs"
  "$unionresolve_rs"
  "$varnode_rs"
  "$heritage_doc"
  "$funcdata_doc"
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
  "$coreaction_rs" "$flow_rs" "$fspec_rs" "$funcdata_rs" \
  "$heritage_rs" "$ruleaction_rs" "$signature_rs" "$unionresolve_rs" \
  "$varnode_rs" \
  "$heritage_doc" "$funcdata_doc" "$fspec_doc" \
  "$runner_fd_path" "$runner_snapshot_sha" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rugra_base_commit" "$rugra_base_tree" "$host_cxx" "$host_cxx_target" \
  "$host_rustc" "$host_cargo" "$host_platform" "$host_cxx_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$host_python_bin" \
  "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin" "$rust_toolchain" \
  "$validate_only" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    repo_raw, snapshot_raw, cargo_home_raw, registry_cache_raw,
    metadata_raw, cpp_raw, rust_raw, coreaction_raw, flow_raw, fspec_raw,
    funcdata_raw, heritage_raw, ruleaction_raw, signature_raw,
    unionresolve_raw, varnode_raw, heritage_doc_raw, funcdata_doc_raw,
    fspec_doc_raw,
    runner_fd_raw, runner_snapshot_sha, oracle_tag, oracle_commit,
    cpp_tree, makefile_blob, rugra_base_commit, rugra_base_tree,
    host_cxx, host_cxx_target, host_rustc, host_cargo, host_platform,
    host_cxx_bin, host_cc_bin, host_ar_bin, host_make_bin,
    host_python_bin, host_git_bin, host_cargo_bin, host_rustc_bin,
    rust_toolchain, validate_only_raw,
) = sys.argv[1:]

repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
snapshot.mkdir(parents=True)
cargo_home = pathlib.Path(cargo_home_raw)
registry_cache = pathlib.Path(registry_cache_raw)

expected_paths = {
    pathlib.Path(metadata_raw): repo / "tests/oracle/heritage_callguard_1204.metadata.json",
    pathlib.Path(cpp_raw): repo / "tests/oracle/heritage_callguard_1204.cc",
    pathlib.Path(rust_raw): repo / "tests/oracle/heritage_callguard_1204.rs",
    pathlib.Path(coreaction_raw): repo / "src/coreaction.rs",
    pathlib.Path(flow_raw): repo / "src/flow.rs",
    pathlib.Path(fspec_raw): repo / "src/fspec.rs",
    pathlib.Path(funcdata_raw): repo / "src/funcdata.rs",
    pathlib.Path(heritage_raw): repo / "src/heritage.rs",
    pathlib.Path(ruleaction_raw): repo / "src/ruleaction.rs",
    pathlib.Path(signature_raw): repo / "src/signature.rs",
    pathlib.Path(unionresolve_raw): repo / "src/unionresolve.rs",
    pathlib.Path(varnode_raw): repo / "src/varnode.rs",
    pathlib.Path(heritage_doc_raw): repo / "docs/api/heritage.md",
    pathlib.Path(funcdata_doc_raw): repo / "docs/api/funcdata.md",
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
    elif isinstance(value, str) and value.startswith("REPLACE"):
        raise SystemExit(f"{path} is pending: {value}")

def base_source_files(directory):
    raw = subprocess.check_output([
        host_git_bin, "-C", str(repo), "ls-tree", "-r", "--name-only", "-z",
        rugra_base_commit, "--", directory,
    ])
    return sorted(
        (pathlib.Path(item.decode()) for item in raw.split(b"\0") if item),
        key=lambda item: item.as_posix(),
    )

def base_file(relative):
    spec = f"{rugra_base_commit}:{relative.as_posix()}"
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
    pathlib.Path("src/coreaction.rs"),
    pathlib.Path("src/flow.rs"),
    pathlib.Path("src/fspec.rs"),
    pathlib.Path("src/funcdata.rs"),
    pathlib.Path("src/heritage.rs"),
    pathlib.Path("src/ruleaction.rs"),
    pathlib.Path("src/signature.rs"),
    pathlib.Path("src/unionresolve.rs"),
    pathlib.Path("src/varnode.rs"),
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
crate_hasher.update(b"rugra-heritage-callguard-d0-overlay-v2\0")
crate_hasher.update(rugra_base_commit.encode())
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
    pathlib.Path("tests/oracle/heritage_callguard_1204.cc"),
    pathlib.Path("tests/oracle/heritage_callguard_1204.rs"),
    pathlib.Path("tests/oracle/heritage_callguard_1204.metadata.json"),
    pathlib.Path("docs/api/heritage.md"),
    pathlib.Path("docs/api/funcdata.md"),
    pathlib.Path("docs/api/fspec.md"),
    pathlib.Path("tools/run_heritage_callguard_oracle.sh"),
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
require("fixture id", metadata["fixture_id"], "HERITAGE-CALLGUARD-0001")
require("overall status", metadata["overall_status"].split(":", 1)[0], "PARTIAL_MATCH")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob),
    ("Rugra base commit", metadata["comparand"]["rugra_base_commit"], rugra_base_commit),
    ("Rugra base tree", metadata["comparand"]["rugra_base_tree"], rugra_base_tree),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
observed_hashes = {
    "cpp_fixture_sha256": sha(special[special_paths[0].as_posix()]),
    "rust_fixture_sha256": sha(special[special_paths[1].as_posix()]),
    "coreaction_rs_sha256": sha(crate_bytes["src/coreaction.rs"]),
    "flow_rs_sha256": sha(crate_bytes["src/flow.rs"]),
    "fspec_rs_sha256": sha(crate_bytes["src/fspec.rs"]),
    "funcdata_rs_sha256": sha(crate_bytes["src/funcdata.rs"]),
    "heritage_rs_sha256": sha(crate_bytes["src/heritage.rs"]),
    "ruleaction_rs_sha256": sha(crate_bytes["src/ruleaction.rs"]),
    "signature_rs_sha256": sha(crate_bytes["src/signature.rs"]),
    "unionresolve_rs_sha256": sha(crate_bytes["src/unionresolve.rs"]),
    "varnode_rs_sha256": sha(crate_bytes["src/varnode.rs"]),
    "heritage_doc_sha256": sha(special[special_paths[3].as_posix()]),
    "funcdata_doc_sha256": sha(special[special_paths[4].as_posix()]),
    "fspec_doc_sha256": sha(special[special_paths[5].as_posix()]),
    "runner_sha256": runner_snapshot_sha,
    "cargo_toml_sha256": sha(crate_bytes["Cargo.toml"]),
    "cargo_lock_sha256": sha(crate_bytes["Cargo.lock"]),
    "build_rs_sha256": sha(crate_bytes["build.rs"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate snapshot scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rugra-heritage-callguard-d0-overlay-v2 plus base commit and sorted length-prefixed paths and contents",
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
    "rust_toolchain": rust_toolchain,
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
require("expected exit code", metadata["expected_exit_code"], 0)
require("covered projection status", metadata["covered_projection_status"], "MATCH")

coverage = metadata["coverage"]
for required_key, required_prefix in (
    ("model_effect_state", "MATCH"),
    ("single_call_ten_ranges_full_projection", "MATCH"),
    ("two_calls_ten_ranges_getstr_form", "MATCH"),
    ("unaffected_zero_guards", "MATCH"),
    ("output_input_trials", "MATCH"),
    ("stack_translation_spacebase", "MATCH"),
    ("driver_pass_gating_second_pass_inert", "MATCH"),
    ("locationmap_contained_classification", "MATCH"),
    ("reprocess_free_stores_trigger", "UNTESTED"),
    ("scope_fl_properties", "UNTESTED"),
    ("production_action_switch", "UNTESTED"),
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
registry_hasher.update(b"rugra-heritage-callguard-registry-lock-v1\0")
for name, version, checksum in registry_packages:
    record = f"{name}\0{version}\0{checksum}".encode()
    registry_hasher.update(len(record).to_bytes(8, "big"))
    registry_hasher.update(record)
require(
    "registry lock closure sha256",
    registry_hasher.hexdigest(),
    metadata["build"]["registry_lock_closure_sha256"],
)

if validate_only_raw == "true":
    raise SystemExit(0)
if validate_only_raw != "false":
    raise SystemExit(f"invalid validate-only flag: {validate_only_raw!r}")

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
    (package_root / ".cargo-checksum.json").write_text(
        json.dumps(
            {"files": file_hashes, "package": checksum},
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )

cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    '[source.crates-io]\nreplace-with = "locked-vendor"\n\n'
    '[source.locked-vendor]\n'
    f'directory = {json.dumps(str(vendor_root))}\n',
    encoding="utf-8",
)
PY

if $validate_only; then
  echo "heritage_callguard_1204 metadata/source lock validation passed"
  exit 0
fi

snapshot_metadata="$snapshot_root/tests/oracle/heritage_callguard_1204.metadata.json"
snapshot_cpp="$snapshot_root/tests/oracle/heritage_callguard_1204.cc"
snapshot_rust="$snapshot_root/tests/oracle/heritage_callguard_1204.rs"

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
/usr/bin/mkdir -p "$oracle_tmp/source"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

# build.rs resolves the locked SLEIGH sources at
# <crate>/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp; expose the
# freshly exported oracle subtree there (link into the private temporary
# directory only).
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/mkdir -p "$snapshot_decompiler"
/usr/bin/ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$requested_tmpdir" \
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

cpp_binary="$oracle_tmp/heritage_callguard_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$requested_tmpdir" \
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
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_timeout_bin" 300 \
  "$cpp_binary" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed, hung, or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

expected_stdout_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python_bin" -I -S -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' \
  "$snapshot_metadata")
actual_stdout_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | /usr/bin/awk '{print $1}')
if [[ "$actual_stdout_sha" != "$expected_stdout_sha" ]]; then
  echo "locked Ghidra stdout hash mismatch" >&2
  exit 1
fi

if $ghidra_only; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  echo "heritage_callguard_1204: GHIDRA_LOCKED_OUTPUT_OK overall=PARTIAL_MATCH stdout_sha256=$actual_stdout_sha"
  exit 0
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
  builtin cd "$snapshot_root"
  /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
    RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
    TMPDIR="$requested_tmpdir" \
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
rugra_rlib="$fixture_target/debug/librugra.rlib"
native_archives=()
while IFS= read -r archive; do
  native_archives+=("$archive")
done < <(/usr/bin/find "$fixture_target/debug/build" -path '*/out/librugra_sleigh.a' -type f)
if [[ ! -f "$rugra_rlib" || -L "$rugra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "missing or ambiguous fresh Rust link inputs" >&2
  exit 1
fi
native_archive="${native_archives[0]}"
if [[ -L "$native_archive" || ! -f "$native_archive" ]]; then
  echo "fresh native archive is not a regular file" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")

rust_binary="$oracle_tmp/heritage_callguard_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" RUSTUP_HOME="$user_home/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$requested_tmpdir" \
  "$host_rustc_bin" --edition=2021 -O \
    -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
    --extern "rugra=$rugra_rlib" -l static=rugra_sleigh -l dylib=z \
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
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$host_timeout_bin" 300 \
  "$rust_binary" >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
/usr/bin/diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e
if [[ "$rugra_status" -ne 0 || -s "$oracle_tmp/rugra.stderr" ]]; then
  echo "Rugra fixture failed, hung, or emitted runtime diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi
if [[ "$diff_status" -ne 0 ]]; then
  /usr/bin/cat "$oracle_tmp/raw.diff" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$snapshot_metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rugra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rugra = pathlib.Path(sys.argv[3]).read_bytes()
raw_diff = pathlib.Path(sys.argv[4]).read_bytes()
expected_sha = metadata["expected_stdout_sha256"]
for label, data in (("Ghidra", ghidra), ("Rugra", rugra)):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha:
        raise SystemExit(f"{label} stdout mismatch: expected={expected_sha} actual={actual}")
if raw_diff:
    raise SystemExit("byte-equal outputs unexpectedly produced a non-empty diff")
for label, status in (
    ("Ghidra", int(sys.argv[5])),
    ("Rugra", int(sys.argv[6])),
    ("raw diff", int(sys.argv[7])),
):
    if status != metadata["expected_exit_code"]:
        raise SystemExit(f"{label} exit mismatch: {status}")

lines = ghidra.decode("utf-8").splitlines()
if len(lines) != 8:
    raise SystemExit(f"expected eight fixture lines, found {len(lines)}")
if lines[0] != (
    "schema=1|fixture=HERITAGE-CALLGUARD-0001|"
    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
):
    raise SystemExit("fixture envelope mismatch")
expected_cases = [
    "model_state",
    "single_call_ten_ranges",
    "two_calls_ten_ranges",
    "unaffected_all",
    "output_input_trials",
    "stack_translation",
    "driver_pass_gating",
]
actual_cases = [line.split("|", 1)[0].removeprefix("case=") for line in lines[1:]]
if actual_cases != expected_cases:
    raise SystemExit(f"fixture case order mismatch: {actual_cases}")
for line in lines:
    if line.startswith("case=two_calls_ten_ranges") and "count=20" not in line:
        raise SystemExit(f"GetStr-form case must witness twenty guards: {line}")
    if line.startswith("case=driver_pass_gating") and "pass2new=0" not in line:
        raise SystemExit(f"second pass must create no new guards: {line}")
    if line.startswith("case=unaffected_all") and "count=0" not in line:
        raise SystemExit(f"unaffected model must yield zero guards: {line}")
PY

/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.after"
if ! /usr/bin/cmp -s "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned comparands drifted during authoritative run" >&2
  /usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after" >&2 || true
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_python_bin" -I -S - "$repo_root" "$runner_fd_path" \
  "$host_git_bin" "$rugra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
runner_fd = pathlib.Path(sys.argv[2])
host_git = sys.argv[3]
rugra_base_commit = sys.argv[4]
metadata = json.loads(
    (repo / "tests/oracle/heritage_callguard_1204.metadata.json").read_text(encoding="utf-8")
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"post-readback {label} mismatch: expected={expected!r} actual={actual!r}")

comparand = metadata["comparand"]
require("runner FD", sha(runner_fd.read_bytes()), comparand["runner_sha256"])
require(
    "live runner",
    sha((repo / "tools/run_heritage_callguard_oracle.sh").read_bytes()),
    comparand["runner_sha256"],
)
for label, relative, key in (
    ("C++ fixture", "tests/oracle/heritage_callguard_1204.cc", "cpp_fixture_sha256"),
    ("Rust fixture", "tests/oracle/heritage_callguard_1204.rs", "rust_fixture_sha256"),
    ("coreaction implementation", "src/coreaction.rs", "coreaction_rs_sha256"),
    ("flow implementation", "src/flow.rs", "flow_rs_sha256"),
    ("fspec implementation", "src/fspec.rs", "fspec_rs_sha256"),
    ("funcdata implementation", "src/funcdata.rs", "funcdata_rs_sha256"),
    ("heritage implementation", "src/heritage.rs", "heritage_rs_sha256"),
    ("ruleaction implementation", "src/ruleaction.rs", "ruleaction_rs_sha256"),
    ("signature implementation", "src/signature.rs", "signature_rs_sha256"),
    ("unionresolve implementation", "src/unionresolve.rs", "unionresolve_rs_sha256"),
    ("varnode implementation", "src/varnode.rs", "varnode_rs_sha256"),
    ("heritage API document", "docs/api/heritage.md", "heritage_doc_sha256"),
    ("funcdata API document", "docs/api/funcdata.md", "funcdata_doc_sha256"),
    ("fspec API document", "docs/api/fspec.md", "fspec_doc_sha256"),
):
    require(label, sha((repo / relative).read_bytes()), comparand[key])

overlay_files = {
    "src/coreaction.rs", "src/flow.rs", "src/fspec.rs", "src/funcdata.rs",
    "src/heritage.rs", "src/ruleaction.rs", "src/signature.rs",
    "src/unionresolve.rs", "src/varnode.rs",
}
relative_files = [pathlib.Path(path) for path in (
    "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
    "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
    "tests/oracle/funcproto_lock_1204.rs",
)]
for directory in ("src", "sleigh_shim"):
    raw = subprocess.check_output([
        host_git, "-C", str(repo), "ls-tree", "-r", "--name-only", "-z",
        rugra_base_commit, "--", directory,
    ])
    relative_files.extend(
        pathlib.Path(item.decode()) for item in raw.split(b"\0") if item
    )
hasher = hashlib.sha256()
hasher.update(b"rugra-heritage-callguard-d0-overlay-v2\0")
hasher.update(rugra_base_commit.encode())
for relative in sorted(set(relative_files), key=lambda item: item.as_posix()):
    if relative.as_posix() in overlay_files:
        data = (repo / relative).read_bytes()
    else:
        spec = f"{rugra_base_commit}:{relative.as_posix()}"
        require(
            f"base object type {relative}",
            subprocess.check_output(
                [host_git, "-C", str(repo), "cat-file", "-t", spec], text=True
            ).strip(),
            "blob",
        )
        data = subprocess.check_output(
            [host_git, "-C", str(repo), "cat-file", "blob", spec]
        )
    encoded = relative.as_posix().encode()
    hasher.update(len(encoded).to_bytes(8, "big"))
    hasher.update(encoded)
    hasher.update(len(data).to_bytes(8, "big"))
    hasher.update(data)
require("full Rust crate", hasher.hexdigest(), comparand["rust_crate_tree_sha256"])
PY

echo "heritage_callguard_1204: MATCH covered_projection=7/7 overall=PARTIAL_MATCH stdout_sha256=$actual_stdout_sha"
