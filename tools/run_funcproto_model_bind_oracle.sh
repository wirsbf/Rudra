#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# FUNCPROTO-MODEL-BIND-0001 oracle runner: prototype-model binding parity.
# Builds the locked Ghidra 12.0.4 oracle (BfdArchitecture real chain:
# spec-dir scan -> Architecture::init -> parseCompilerConfig establishes
# defaultfp) and an isolated base-plus-overlay Rust snapshot (the locked
# 92daed3 base plus the complete nine-file D0 callspec source closure; marshal
# DocumentStorage text parse -> parse_compiler_config -> Funcdata::set_arch /
# FuncProto::set_internal / FuncCallSpecs::has_effect), runs both
# funcproto_model_bind_1204 fixtures on identical production x86-64-gcc.cspec
# bytes, and diffs the binding-chain projections byte for byte.

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
runner="$repo_root/tools/run_funcproto_model_bind_oracle.sh"
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

validate_only=0
if [[ $# -eq 1 && "$1" == "--validate-only" ]]; then
  validate_only=1
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--validate-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
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
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
required_tools=("$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin")
for tool in "${required_tools[@]}"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=92daed300bcce3c4d855b311cf9667ba21eb475a
rudra_base_tree=6aea6d3b5b1421170d1bdc5a766c9568483a66af
rudra_base_src_tree=367bb531746f630fe4de5fddc0365c2c2f27eeda
rudra_base_sleigh_shim_tree=c7729d9d1554dc62c486bcd7d58fdbf44bebb97d
rudra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_readme_blob=97198a893828d15c44f12e66960652b96c3e1b87
rudra_bench_blob=774d71f38a85a0ef777aaeb5be658f212bc254d2
rudra_decompress_example_blob=0f080362908a89815777b64e3ce83c90e19e074c
rudra_funcproto_lock_example_blob=2676a485769ad4d0f376012a185be80dc2dfd1bf
ghidra_root="$repo_root/ghidra"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_runtime=$(/usr/bin/dirname "$bfd_library")
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e
metadata="$repo_root/tests/oracle/funcproto_model_bind_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/funcproto_model_bind_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcproto_model_bind_1204.rs"
registry_cache="$user_home/.cargo/registry/cache"

required_inputs=("$metadata" "$cpp_fixture" "$rust_fixture" \
  "$bfd_include/bfd.h" "$bfd_library")
for required in "${required_inputs[@]}"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
if [[ -L "$bfd_runtime" || ! -d "$bfd_runtime" || \
      "$(/usr/bin/readlink -f "$bfd_runtime")" != "$bfd_runtime" ]]; then
  echo "BFD runtime directory is not a real canonical directory: $bfd_runtime" >&2
  exit 1
fi

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

actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
actual_base_src_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:src")
actual_base_sleigh_shim_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:sleigh_shim")
actual_cargo_toml_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.toml")
actual_cargo_lock_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.lock")
actual_build_rs_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:build.rs")
actual_readme_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:README.md")
actual_bench_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:benches/decompile_bench.rs")
actual_decompress_example_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:tests/oracle/decompress_1204.rs")
actual_funcproto_lock_example_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit:tests/oracle/funcproto_lock_1204.rs")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" || \
      "$actual_base_src_tree" != "$rudra_base_src_tree" || \
      "$actual_base_sleigh_shim_tree" != "$rudra_base_sleigh_shim_tree" || \
      "$actual_cargo_toml_blob" != "$rudra_cargo_toml_blob" || \
      "$actual_cargo_lock_blob" != "$rudra_cargo_lock_blob" || \
      "$actual_build_rs_blob" != "$rudra_build_rs_blob" || \
      "$actual_readme_blob" != "$rudra_readme_blob" || \
      "$actual_bench_blob" != "$rudra_bench_blob" || \
      "$actual_decompress_example_blob" != "$rudra_decompress_example_blob" || \
      "$actual_funcproto_lock_example_blob" != "$rudra_funcproto_lock_example_blob" ]]; then
  echo "locked Rudra base tree mismatch" >&2
  exit 1
fi

oracle_tmp_parent="$user_home/.cache/rudra-funcproto-model-bind-1204"
/usr/bin/mkdir -p "$oracle_tmp_parent"
oracle_tmp=$(/usr/bin/mktemp -d "$oracle_tmp_parent/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$oracle_tmp_parent"/run.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
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
spec_root="$oracle_tmp/specs"
build_tmp="$oracle_tmp/build-tmp"
mkdir -p "$snapshot_root" "$oracle_source" "$spec_root"
/usr/bin/mkdir -m 0700 "$build_tmp"
build_tmp_real=$(/usr/bin/readlink -f "$build_tmp")
build_tmp_mode=$(/usr/bin/stat -Lc '%a' "$build_tmp")
build_tmp_uid=$(/usr/bin/stat -Lc '%u' "$build_tmp")
if [[ -L "$build_tmp" || ! -d "$build_tmp" || \
      "$build_tmp_real" != "$build_tmp" || "$build_tmp_mode" != 700 || \
      "$build_tmp_uid" != "$(/usr/bin/id -u)" ]]; then
  echo "private build TMPDIR validation failed: $build_tmp" >&2
  exit 1
fi
base_archive_paths=(
  Cargo.toml
  Cargo.lock
  build.rs
  README.md
  benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs
  tests/oracle/funcproto_lock_1204.rs
  src
  sleigh_shim
)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive "$rudra_base_commit" \
  "${base_archive_paths[@]}" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"

# The pinned production spec set and target binary (from the locked base).
for path in sleigh_specs/x86.ldefs sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86-64.sla; do
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git_bin" -C "$repo_root" show "$rudra_base_commit:$path" \
    > "$spec_root/${path##*/}"
done
binary="$oracle_tmp/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" show "$rudra_base_commit:examples/curl" > "$binary"
/usr/bin/chmod 0700 "$binary"

# The complete D0 callspec source closure.  Keeping this list exact prevents a
# fixture from compiling a mixed old/new callspec API when any downstream
# consumer changes with the identity/lifecycle work.
overlay_paths=(
  "src/coreaction.rs"
  "src/flow.rs"
  "src/fspec.rs"
  "src/funcdata.rs"
  "src/heritage.rs"
  "src/ruleaction.rs"
  "src/signature.rs"
  "src/unionresolve.rs"
  "src/varnode.rs"
)
for rel in "${overlay_paths[@]}"; do
  /usr/bin/install -D "$repo_root/$rel" "$snapshot_root/$rel"
done
for rel in \
  "tests/oracle/funcproto_model_bind_1204.cc" \
  "tests/oracle/funcproto_model_bind_1204.rs" \
  "tests/oracle/funcproto_model_bind_1204.metadata.json" \
  "tools/run_funcproto_model_bind_oracle.sh"; do
  /usr/bin/install -D "$repo_root/$rel" "$snapshot_root/$rel"
done
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root" "$cargo_home" "$registry_cache" \
  "$runner_sha" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$rudra_base_src_tree" "$rudra_base_sleigh_shim_tree" \
  "$rudra_cargo_toml_blob" "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" \
  "$rudra_readme_blob" "$rudra_bench_blob" "$rudra_decompress_example_blob" \
  "$rudra_funcproto_lock_example_blob" \
  "$host_git_bin" "$host_python_bin" "$host_cxx_bin" "$host_rustc_bin" "$host_cargo_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$user_home" "$validate_only" "$bfd_include/bfd.h" "$bfd_library" \
  "$bfd_header_sha256" "$bfd_library_sha256" \
  "${#base_archive_paths[@]}" "${base_archive_paths[@]}" \
  "${overlay_paths[@]}" <<'PY'
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
    base_commit, base_tree, base_src_tree, base_sleigh_shim_tree,
    cargo_toml_blob, cargo_lock_blob, build_rs_blob, readme_blob, bench_blob,
    decompress_example_blob, funcproto_lock_example_blob,
    host_git, host_python, host_cxx, host_rustc, host_cargo,
    host_cc, host_ar, host_make, user_home, validate_only_raw,
    bfd_header_raw, bfd_library_raw, bfd_header_sha256, bfd_library_sha256,
    archive_path_count_raw, *remaining,
) = sys.argv[1:]
archive_path_count = int(archive_path_count_raw)
base_archive_paths = remaining[:archive_path_count]
overlay_paths = remaining[archive_path_count:]
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

metadata_path = snapshot / "tests/oracle/funcproto_model_bind_1204.metadata.json"
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
reject_pending(metadata)
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "FUNCPROTO-MODEL-BIND-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["comparand"]["rugra_base_commit"], base_commit)
require("base tree", metadata["comparand"]["rugra_base_tree"], base_tree)
require("base src tree", metadata["comparand"]["rugra_base_src_tree"], base_src_tree)
require(
    "base sleigh_shim tree",
    metadata["comparand"]["rugra_base_sleigh_shim_tree"],
    base_sleigh_shim_tree,
)
require("Cargo.toml blob", metadata["comparand"]["rugra_cargo_toml_blob"], cargo_toml_blob)
require("Cargo.lock blob", metadata["comparand"]["rugra_cargo_lock_blob"], cargo_lock_blob)
require("build.rs blob", metadata["comparand"]["rugra_build_rs_blob"], build_rs_blob)
require("README blob", metadata["comparand"]["rugra_readme_blob"], readme_blob)
require("bench blob", metadata["comparand"]["rugra_bench_blob"], bench_blob)
require(
    "decompress example blob",
    metadata["comparand"]["rugra_decompress_example_blob"],
    decompress_example_blob,
)
require(
    "funcproto-lock example blob",
    metadata["comparand"]["rugra_funcproto_lock_example_blob"],
    funcproto_lock_example_blob,
)
require("architecture", metadata["architecture"], "x86:LE:64:default (SLEIGH x86-64)")
require("compiler spec", metadata["compiler_spec"], "x86-64-gcc.cspec (production bytes)")
require("BFD header fingerprint", metadata["input_fingerprints"]["bfd.h"], bfd_header_sha256)
require(
    "BFD library fingerprint",
    metadata["input_fingerprints"]["libbfd-2.38-system.so"],
    bfd_library_sha256,
)
require("BFD header bytes", sha(pathlib.Path(bfd_header_raw).read_bytes()), bfd_header_sha256)
require("BFD library bytes", sha(pathlib.Path(bfd_library_raw).read_bytes()), bfd_library_sha256)
require(
    "binding observation status",
    metadata["coverage"]["model_bind_status"], "MATCH")
require(
    "coverage record counts",
    metadata["coverage"]["record_counts"], {
        "SCHEMA": 1, "ARCH_DEFAULTFP": 1, "ARCH_DEFAULTFP_EXTRAPOP": 1,
        "THISCALL_ALIAS": 1, "PRINTFLAG": 4, "CTOR_BIND": 1,
        "OVERLAY_LOCK": 1, "CTOR_UNNAMED": 1, "PROTOTYPE_TYPES_BIND": 1,
        "CALLSPEC_PRE": 1, "CALLSPEC_POST": 1, "EFFECT": 6,
        "CALLSPEC_REBIND": 1, "DONE": 1})
require(
    "residual statuses",
    [item["status"] for item in metadata["residuals"]],
    ["MISMATCH", "MISMATCH", "UNTESTED", "UNTESTED", "UNTESTED"])
require(
    "snapshot model",
    metadata["comparand"]["snapshot_model"],
    "git archive locked base tree plus complete nine-file D0 source closure")
require(
    "build TMPDIR policy",
    metadata["comparand"]["build_tmp_policy"],
    "ignore ambient TMPDIR after immutable env re-exec; create a private mode-0700 build-tmp below the user-cache run root and pass it explicitly to make, Cargo, g++, and rustc")
require("base archive paths", metadata["comparand"]["base_archive_paths"], base_archive_paths)
require(
    "Cargo manifest target audit",
    metadata["comparand"]["cargo_manifest_target_audit"],
    "archive README.md, the explicit decompile_bench target, both explicit tests/oracle examples, the complete src tree for lib/bin targets, and sleigh_shim for build.rs; do not materialize examples/ or top-level tests/*.rs auto-discovery roots")
require(
    "runtime closure",
    metadata["comparand"]["runtime_closure"],
    {
        "cpp_bfd_library": bfd_library_raw,
        "cpp_ld_library_path": str(pathlib.Path(bfd_library_raw).parent),
        "cpp_environment": [
            "PATH=/usr/bin:/bin",
            "LC_ALL=C",
            f"LD_LIBRARY_PATH={pathlib.Path(bfd_library_raw).parent}",
        ],
        "rust_environment": ["PATH=/usr/bin:/bin", "LC_ALL=C"],
        "process_gate": "capture each runtime exit code and stderr; reject any nonzero exit or nonempty stderr with the captured diagnostics",
    },
)
if (snapshot / "examples").exists():
    raise SystemExit("snapshot unexpectedly materialized the examples auto-discovery root")
top_level_tests = sorted(path.name for path in (snapshot / "tests").glob("*.rs"))
require("top-level auto-discovered tests", top_level_tests, [])
bench_targets = sorted(
    path.relative_to(snapshot).as_posix() for path in (snapshot / "benches").glob("*.rs")
)
require("bench target closure", bench_targets, ["benches/decompile_bench.rs"])

require("overlay paths", metadata["comparand"]["overlay_paths"], overlay_paths)

paths = {
    "cpp_fixture_sha256": snapshot / "tests/oracle/funcproto_model_bind_1204.cc",
    "rust_fixture_sha256": snapshot / "tests/oracle/funcproto_model_bind_1204.rs",
    "runner_sha256": snapshot / "tools/run_funcproto_model_bind_oracle.sh",
    "cargo_toml_sha256": snapshot / "Cargo.toml",
    "cargo_lock_sha256": snapshot / "Cargo.lock",
    "build_rs_sha256": snapshot / "build.rs",
}
for key, path in paths.items():
    actual = sha(path.read_bytes())
    expected = metadata["comparand"][key]
    require(key, actual, expected)
require("immutable runner hash", sha(paths["runner_sha256"].read_bytes()), runner_sha)

def git_blob_oid(path):
    return subprocess.check_output(
        [host_git, "hash-object", "--no-filters", str(path)], text=True
    ).strip()

manifest_closure = metadata["comparand"]["manifest_closure_files"]
expected_manifest_closure = {
    "README.md": (readme_blob, snapshot / "README.md"),
    "benches/decompile_bench.rs": (bench_blob, snapshot / "benches/decompile_bench.rs"),
    "tests/oracle/decompress_1204.rs": (
        decompress_example_blob,
        snapshot / "tests/oracle/decompress_1204.rs",
    ),
    "tests/oracle/funcproto_lock_1204.rs": (
        funcproto_lock_example_blob,
        snapshot / "tests/oracle/funcproto_lock_1204.rs",
    ),
}
require("manifest closure paths", set(manifest_closure), set(expected_manifest_closure))
for relative, (expected_blob, path) in expected_manifest_closure.items():
    record = manifest_closure[relative]
    require("manifest closure fields", set(record), {"git_blob_oid", "sha256"})
    require(f"{relative} metadata blob", record["git_blob_oid"], expected_blob)
    require(f"{relative} snapshot blob", git_blob_oid(path), expected_blob)
    require(f"{relative} snapshot sha", sha(path.read_bytes()), record["sha256"])

overlay_records = metadata["comparand"]["overlays"]
require("overlay record paths", set(overlay_records), set(overlay_paths))
for relative in overlay_paths:
    record = overlay_records[relative]
    require("overlay record fields", set(record), {"git_blob_oid", "sha256"})
    live = snapshot / relative
    require(f"{relative} blob", git_blob_oid(live), record["git_blob_oid"])
    require(f"{relative} sha256", sha(live.read_bytes()), record["sha256"])

for key, relative in (
    ("cpp_fixture", "tests/oracle/funcproto_model_bind_1204.cc"),
    ("rust_fixture", "tests/oracle/funcproto_model_bind_1204.rs"),
    ("runner", "tools/run_funcproto_model_bind_oracle.sh"),
):
    record = metadata["comparand"][f"{key}_identity"]
    path = snapshot / relative
    require(f"{key} identity fields", set(record), {"git_blob_oid", "sha256"})
    require(f"{key} identity blob", git_blob_oid(path), record["git_blob_oid"])
    require(f"{key} identity sha256", sha(path.read_bytes()), record["sha256"])

spec_files = {
    "cspec_sha256": snapshot.parent / "specs/x86-64-gcc.cspec",
    "sla_sha256": snapshot.parent / "specs/x86-64.sla",
}
for key, path in spec_files.items():
    require(key, sha(path.read_bytes()), metadata["comparand"][key])

if validate_only_raw not in {"0", "1"}:
    raise SystemExit(f"invalid validate-only selector: {validate_only_raw!r}")

host = metadata["host_tools"]
require(
    "host tool paths",
    host["paths"],
    {
        "cxx": host_cxx,
        "cc": host_cc,
        "ar": host_ar,
        "make": host_make,
        "python": host_python,
        "git": host_git,
        "rustc": host_rustc,
        "cargo": host_cargo,
    },
)
require(
    "Rust toolchain policy",
    host["rust_toolchain_policy"],
    "system /usr/bin cargo and rustc; no rustup indirection",
)
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
if validate_only_raw == "1":
    raise SystemExit(0)

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

if [[ "$validate_only" == 1 ]]; then
  echo "funcproto_model_bind_1204 metadata/source lock validation passed"
  exit 0
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
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
  /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
    TMPDIR="$build_tmp" \
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

cpp_fixture="$snapshot_root/tests/oracle/funcproto_model_bind_1204.cc"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
  "$host_cxx_bin" \
  -std=c++11 -O0 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$standard_archive" \
  "$bfd_library" -lz \
  -o "$oracle_tmp/funcproto_model_bind_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

rust_fixture="$snapshot_root/tests/oracle/funcproto_model_bind_1204.rs"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$build_tmp" \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/funcproto_model_bind_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

ghidra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_runtime" \
  "$oracle_tmp/funcproto_model_bind_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr" || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 ]]; then
  echo "Ghidra funcproto-model-bind oracle failed with exit code $ghidra_status" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit "$ghidra_status"
fi
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra funcproto-model-bind oracle produced unexpected stderr" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

rudra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/funcproto_model_bind_1204_rust" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86-64.sla" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr" || rudra_status=$?
if [[ "$rudra_status" -ne 0 ]]; then
  echo "Rudra funcproto-model-bind fixture failed with exit code $rudra_status" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit "$rudra_status"
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra funcproto-model-bind fixture produced unexpected stderr" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

diff_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
  >"$oracle_tmp/runtime.diff" 2>"$oracle_tmp/diff.stderr" || diff_status=$?
if [[ "$diff_status" -ne 0 ]]; then
  echo "funcproto-model-bind byte comparison failed with exit code $diff_status" >&2
  /usr/bin/cat "$oracle_tmp/diff.stderr" >&2
  /usr/bin/cat "$oracle_tmp/runtime.diff" >&2
  exit "$diff_status"
fi
if [[ -s "$oracle_tmp/diff.stderr" ]]; then
  echo "funcproto-model-bind diff produced unexpected stderr" >&2
  /usr/bin/cat "$oracle_tmp/diff.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$snapshot_root/tests/oracle/funcproto_model_bind_1204.metadata.json" \
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
if lines[-1] != "DONE":
    raise SystemExit(f"fixture summary mismatch: {lines[-1]!r}")
prefixes = {}
for line in lines:
    prefix = line.split("|", 1)[0]
    prefixes[prefix] = prefixes.get(prefix, 0) + 1
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
print("model_bind=MATCH overall=PARTIAL_MATCH (residuals registered in metadata)")
PY
