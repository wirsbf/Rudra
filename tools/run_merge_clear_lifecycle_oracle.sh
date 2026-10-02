#!/usr/bin/bash
set -euo pipefail

runner_tmpdir_input=${TMPDIR:-}
runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin \
    RUDRA_MERGE_CLEAR_CALLER_TMPDIR="$runner_tmpdir_input" \
    /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_tmpdir_input=${RUDRA_MERGE_CLEAR_CALLER_TMPDIR:-}
unset RUDRA_MERGE_CLEAR_CALLER_TMPDIR
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_merge_clear_lifecycle_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

validate_only=0
if [[ "$#" -eq 1 && "$1" == "--validate-only" ]]; then
  validate_only=1
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $runner [--validate-only]" >&2
  exit 2
fi

user_home_raw=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
user_home=$(/usr/bin/readlink -f -- "$user_home_raw")
if [[ -z "$user_home" || ! -d "$user_home" || -L "$user_home_raw" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
HOME=$user_home
export HOME

default_build_tmpdir="$HOME/.cache/rugra-merge-clear-lifecycle-1204/tmp"
if [[ -n "$runner_tmpdir_input" ]]; then
  requested_build_tmpdir="$runner_tmpdir_input"
else
  requested_build_tmpdir="$default_build_tmpdir"
fi
case "$requested_build_tmpdir" in
  /*) ;;
  *)
    echo "TMPDIR must be an absolute path below the resolved user home" >&2
    exit 1
    ;;
esac
normalized_tmpdir_request="$requested_build_tmpdir"
while [[ "$normalized_tmpdir_request" != "/" && "$normalized_tmpdir_request" == */ ]]; do
  normalized_tmpdir_request=${normalized_tmpdir_request%/}
done
if [[ -L "$normalized_tmpdir_request" ]]; then
  echo "TMPDIR must not be a symlink" >&2
  exit 1
fi
prospective_build_tmpdir=$(/usr/bin/realpath -m -- "$normalized_tmpdir_request")
case "$prospective_build_tmpdir" in
  "$HOME"/*) ;;
  *)
    echo "TMPDIR resolves outside the user home: $prospective_build_tmpdir" >&2
    exit 1
    ;;
esac
/usr/bin/mkdir -p -- "$prospective_build_tmpdir"
if [[ -L "$normalized_tmpdir_request" || -L "$prospective_build_tmpdir" ]]; then
  echo "TMPDIR became a symlink during validation" >&2
  exit 1
fi
build_tmpdir=$(/usr/bin/readlink -f -- "$prospective_build_tmpdir")
if [[ "$build_tmpdir" != "$prospective_build_tmpdir" ]]; then
  echo "TMPDIR canonical path changed during validation" >&2
  exit 1
fi
if [[ ! -d "$build_tmpdir" || ! -w "$build_tmpdir" || ! -x "$build_tmpdir" ]]; then
  echo "TMPDIR is not a writable searchable directory: $build_tmpdir" >&2
  exit 1
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=92daed300bcce3c4d855b311cf9667ba21eb475a
rugra_base_tree=6aea6d3b5b1421170d1bdc5a766c9568483a66af
rugra_base_src_tree=367bb531746f630fe4de5fddc0365c2c2f27eeda
rugra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rugra_base_merge_blob=365be16020196337d386eb215f0b280ece383847
overlay_paths=(
  src/coreaction.rs
  src/flow.rs
  src/fspec.rs
  src/funcdata.rs
  src/heritage.rs
  src/ruleaction.rs
  src/signature.rs
  src/unionresolve.rs
  src/varnode.rs
)
ghidra_root="$repo_root/ghidra"
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=/usr/bin/cargo
host_rustc_bin=/usr/bin/rustc
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done
if [[ "$validate_only" -eq 0 ]]; then
  for required_tool in "$host_cargo_bin" "$host_rustc_bin"; do
    if [[ ! -x "$required_tool" ]]; then
      echo "required build tool is not executable: $required_tool" >&2
      exit 1
    fi
  done
fi

runner_tmp_root="$build_tmpdir/rugra-merge-clear-lifecycle-1204"
/usr/bin/mkdir -p -- "$runner_tmp_root"
oracle_tmp=$(/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR="$build_tmpdir" \
  /usr/bin/mktemp -d "$runner_tmp_root/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$runner_tmp_root"/run.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Snapshot every live candidate exactly once before hashing or compiling. The
# runner itself is read from the already-open immutable descriptor above. The
# D0 callspec migration is a nine-file crate closure, so all nine source
# overlays are frozen and hash-checked over the immutable 92daed3 base.
/usr/bin/mkdir -p "$oracle_tmp/candidate/src"
for candidate in \
  tests/oracle/merge_clear_lifecycle_1204.metadata.json \
  tests/oracle/merge_clear_lifecycle_1204.cc \
  tests/oracle/merge_clear_lifecycle_1204.rs \
  Cargo.toml Cargo.lock build.rs; do
  /usr/bin/cp -- "$repo_root/$candidate" "$oracle_tmp/candidate/$(/usr/bin/basename "$candidate")"
done
for overlay in "${overlay_paths[@]}"; do
  /usr/bin/cp -- "$repo_root/$overlay" "$oracle_tmp/candidate/$overlay"
done
metadata="$oracle_tmp/candidate/merge_clear_lifecycle_1204.metadata.json"
cpp_fixture="$oracle_tmp/candidate/merge_clear_lifecycle_1204.cc"
rust_fixture="$oracle_tmp/candidate/merge_clear_lifecycle_1204.rs"

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra tree/blob mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

if [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}^{commit}")" != "$rugra_base_commit" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}^{tree}")" != "$rugra_base_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}:src")" != "$rugra_base_src_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.toml")" != "$rugra_cargo_toml_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.lock")" != "$rugra_cargo_lock_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}:build.rs")" != "$rugra_build_rs_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rugra_base_commit}:src/merge.rs")" != "$rugra_base_merge_blob" ]]; then
  echo "pinned Rugra base identity mismatch" >&2
  exit 1
fi

# Freeze both sides: rebuild Ghidra from the locked commit, and build Rugra
# from the pinned base commit with the complete D0 callspec overlay closure.
/usr/bin/mkdir -p "$oracle_tmp/ghidra" "$oracle_tmp/rugra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/ghidra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar "$rugra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/rugra"
for overlay in "${overlay_paths[@]}"; do
  /usr/bin/cp -- "$oracle_tmp/candidate/$overlay" "$oracle_tmp/rugra/$overlay"
done

/usr/bin/mkdir -p "$oracle_tmp/rugra/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" \
  "$oracle_tmp/rugra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_cpp="$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
cargo_home="$oracle_tmp/cargo-home"
registry_cache="$HOME/.cargo/registry/cache"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$runner_fd_path" \
  "$runner_snapshot_sha" "$ghidra_root" "$oracle_commit" \
  "$oracle_tag" "$oracle_cpp_tree" "$oracle_makefile_blob" "$rugra_base_commit" \
  "$rugra_base_tree" "$rugra_base_src_tree" "$rugra_cargo_toml_blob" \
  "$rugra_cargo_lock_blob" "$rugra_build_rs_blob" "$rugra_base_merge_blob" \
  "$oracle_tmp/candidate/Cargo.toml" "$oracle_tmp/candidate/Cargo.lock" \
  "$oracle_tmp/candidate/build.rs" \
  "$host_cxx_bin" "$host_cargo_bin" "$host_rustc_bin" "$host_make_bin" "$host_git_bin" \
  "$host_python_bin" \
  "$oracle_tmp/candidate" "$oracle_tmp/rugra" "$cargo_home" "$registry_cache" \
  "$build_tmpdir" "$HOME" "$validate_only" "${overlay_paths[@]}" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    metadata_name, cpp_name, rust_name, runner_name, runner_snapshot_sha,
    ghidra_root_name, oracle_commit, oracle_tag,
    oracle_cpp_tree, oracle_makefile_blob, rugra_base_commit, rugra_base_tree,
    rugra_base_src_tree, rugra_cargo_toml_blob, rugra_cargo_lock_blob,
    rugra_build_rs_blob, rugra_base_merge_blob,
    cargo_toml_name, cargo_lock_name, build_rs_name,
    host_cxx_bin, host_cargo_bin, host_rustc_bin, host_make_bin, host_git_bin,
    host_python_bin, candidate_name, snapshot_name, cargo_home_name,
    registry_cache_name, build_tmpdir_name, user_home_name, validate_only,
    *overlay_paths,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["schema_version"] != 2:
    raise SystemExit("schema_version must be 2")
if metadata["fixture_id"] != "MERGE-CLEAR-LIFECYCLE-0001":
    raise SystemExit("fixture id mismatch")
if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle mismatch")
if metadata["oracle"]["decompiler_cpp_tree"] != oracle_cpp_tree:
    raise SystemExit("metadata Ghidra C++ tree mismatch")
if metadata["oracle"]["decompiler_makefile_blob"] != oracle_makefile_blob:
    raise SystemExit("metadata Ghidra Makefile blob mismatch")
if metadata["rugra_base_commit"] != rugra_base_commit:
    raise SystemExit("metadata Rugra base commit mismatch")
if metadata["rugra_base_tree"] != rugra_base_tree:
    raise SystemExit("metadata Rugra base tree mismatch")
if metadata["rugra_base_src_tree"] != rugra_base_src_tree:
    raise SystemExit("metadata Rugra base src tree mismatch")
if metadata["rugra_cargo_toml_blob"] != rugra_cargo_toml_blob:
    raise SystemExit("metadata Rugra Cargo.toml blob mismatch")
if metadata["rugra_cargo_lock_blob"] != rugra_cargo_lock_blob:
    raise SystemExit("metadata Rugra Cargo.lock blob mismatch")
if metadata["rugra_build_rs_blob"] != rugra_build_rs_blob:
    raise SystemExit("metadata Rugra build.rs blob mismatch")
if metadata["rugra_base_merge_blob"] != rugra_base_merge_blob:
    raise SystemExit("metadata Rugra base merge.rs blob mismatch")
if metadata["overall_status"] != "MISMATCH":
    raise SystemExit("fixture must remain MISMATCH overall until registered residuals close")
if metadata["projection_status"] != "MATCH":
    raise SystemExit("covered 4/6-line projection must remain MATCH (registered lines only)")
coverage = metadata["coverage"]
for key in (
    "flags_mask_and_preserved_bits",
    "counters_high_level_index",
    "min_laned_size_rederive",
    "laned_map_persistence",
    "localmap_clear_window_scalars",
    "active_output_clear",
    "union_map_clear",
    "banks_reset_uniqid_create_index",
    "callspecs_clear",
    "jumptables_override_permanents",
    "heritage_reset",
    "merge_channels_clear",
    "restart_gate_procstart",
):
    if coverage[key] != "MATCH":
        raise SystemExit(f"coverage.{key} must be MATCH")
for key in (
    "localmap_typelock_survival",
    "funcproto_unlocked_output",
):
    if coverage[key] != "MISMATCH":
        raise SystemExit(f"coverage.{key} must be MISMATCH")
for key in (
    "reset_local_window_range_rederive",
    "clean_up_and_cast_phase_index",
    "merge_channel_production_population",
    "localoverride_persistence",
):
    if coverage[key] != "UNTESTED":
        raise SystemExit(f"coverage.{key} must be UNTESTED")
for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")

ghidra_root = pathlib.Path(ghidra_root_name)
cpp_tree = subprocess.check_output([
    host_git_bin, "-C", str(ghidra_root), "rev-parse",
    "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp",
], text=True).strip()
if cpp_tree != metadata["oracle"]["decompiler_cpp_tree"]:
    raise SystemExit("locked Ghidra C++ tree mismatch")

paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "runner_sha256": pathlib.Path(runner_name),
    "cargo_toml_sha256": pathlib.Path(cargo_toml_name),
    "cargo_lock_sha256": pathlib.Path(cargo_lock_name),
    "build_rs_sha256": pathlib.Path(build_rs_name),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
if metadata["comparand"]["runner_sha256"] != runner_snapshot_sha:
    raise SystemExit("runner descriptor snapshot mismatch")
candidate = pathlib.Path(candidate_name)
snapshot = pathlib.Path(snapshot_name)
overlay_hashes = metadata["comparand"]["d0_overlay_sha256"]
if set(overlay_hashes) != set(overlay_paths):
    raise SystemExit("metadata D0 overlay closure mismatch")
if metadata["build"]["d0_overlay_paths"] != overlay_paths:
    raise SystemExit("metadata D0 overlay order mismatch")
for relative in overlay_paths:
    expected = overlay_hashes[relative]
    frozen = candidate / relative
    copied = snapshot / relative
    for label, path in (("candidate", frozen), ("snapshot", copied)):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(
                f"{relative} {label} mismatch: metadata={expected} actual={actual}"
            )
merge_sha = hashlib.sha256((snapshot / "src/merge.rs").read_bytes()).hexdigest()
if merge_sha != metadata["comparand"]["base_merge_rs_sha256"]:
    raise SystemExit("archived base src/merge.rs fingerprint mismatch")
tmpdir_policy = metadata["build"]["tmpdir_policy"]
expected_tmpdir_policy = {
    "caller_variable": "TMPDIR",
    "default_relative_to_home": ".cache/rugra-merge-clear-lifecycle-1204/tmp",
    "resolved_root_constraint": "strict_descendant_of_passwd_home",
    "leaf_symlink_allowed": False,
    "creation_order": "canonicalize_and_validate_before_mkdir_then_revalidate",
    "required_access": "directory,writable,searchable",
    "explicit_build_commands": ["make", "g++", "cargo", "rustc"],
}
if tmpdir_policy != expected_tmpdir_policy:
    raise SystemExit("metadata TMPDIR policy mismatch")
user_home = pathlib.Path(user_home_name).resolve(strict=True)
build_tmpdir = pathlib.Path(build_tmpdir_name).resolve(strict=True)
if build_tmpdir == user_home or user_home not in build_tmpdir.parents:
    raise SystemExit("selected TMPDIR is not a strict descendant of the user home")
if not build_tmpdir.is_dir():
    raise SystemExit("selected TMPDIR is not a directory")
tool_paths = {
    "host_cxx_path": host_cxx_bin,
    "host_cargo_path": host_cargo_bin,
    "host_rustc_path": host_rustc_bin,
    "host_make_path": host_make_bin,
    "host_git_path": host_git_bin,
    "host_python_path": host_python_bin,
}
for key, value in tool_paths.items():
    if metadata["comparand"].get(key) != value:
        raise SystemExit(f"tool path mismatch for {key}")
versions = {
    "host_cxx": subprocess.check_output([host_cxx_bin, "--version"], text=True).splitlines()[0],
}
if validate_only != "1":
    versions.update({
        "host_rustc": subprocess.check_output([host_rustc_bin, "--version"], text=True).strip(),
        "host_cargo": subprocess.check_output([host_cargo_bin, "--version"], text=True).strip(),
    })
for key, value in versions.items():
    if metadata["comparand"].get(key) != value:
        raise SystemExit(f"tool version mismatch for {key}")

payload = json.dumps(
    metadata["input_manifest"]["cases"],
    sort_keys=True, separators=(",", ":"), ensure_ascii=False,
).encode()
actual_input = hashlib.sha256(payload).hexdigest()
if actual_input != metadata["input_manifest"]["sha256"]:
    raise SystemExit("input manifest fingerprint mismatch")

# A metadata-only run proves every immutable input and the complete overlay
# closure without touching Cargo or the registry cache.
if validate_only == "1":
    raise SystemExit(0)

# Materialize only the Cargo.lock registry closure. Every .crate is read once
# and checked against its locked checksum before extraction, so no mutable
# registry index/config participates in the build.
cargo_home = pathlib.Path(cargo_home_name)
registry_cache = pathlib.Path(registry_cache_name)
if registry_cache.is_symlink() or not registry_cache.is_dir():
    raise SystemExit("registry archive cache is not a real directory")
blocks = (snapshot / "Cargo.lock").read_text(encoding="utf-8").split("[[package]]")[1:]
packages = []
for block in blocks:
    fields = {}
    for field in ("name", "version", "source", "checksum"):
        match = re.search(rf'(?m)^{field} = "([^"\\]+)"$', block)
        if match:
            fields[field] = match.group(1)
    if "source" not in fields:
        continue
    if fields["source"] != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"unsupported locked Cargo source: {fields['source']}")
    packages.append((fields["name"], fields["version"], fields["checksum"]))
if len(packages) != metadata["build"]["registry_packages"]:
    raise SystemExit("locked registry package-count mismatch")

vendor = snapshot / "vendor"
vendor.mkdir()
for name, version, checksum in packages:
    archive_name = f"{name}-{version}.crate"
    matches = [namespace / archive_name for namespace in registry_cache.iterdir()
               if namespace.is_dir() and not namespace.is_symlink()
               and (namespace / archive_name).exists()]
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise SystemExit(f"expected one regular cached archive for {name} {version}")
    archive_bytes = matches[0].read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != checksum:
        raise SystemExit(f"Cargo.lock checksum mismatch for {name} {version}")
    root_name = f"{name}-{version}"
    root = vendor / root_name
    root.mkdir()
    file_hashes = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_path = pathlib.PurePosixPath(member.name)
            parts = member_path.parts
            if not parts or parts[0] != root_name or any(p in ("", ".", "..") for p in parts):
                raise SystemExit(f"unsafe crate member: {member.name!r}")
            if len(parts) == 1:
                if not member.isdir():
                    raise SystemExit("crate root is not a directory")
                continue
            relative = pathlib.PurePosixPath(*parts[1:])
            key = relative.as_posix()
            if key in seen:
                raise SystemExit(f"duplicate crate member: {member.name!r}")
            seen.add(key)
            destination = root.joinpath(*parts[1:])
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise SystemExit(f"unsupported crate member type: {member.name!r}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"missing crate member payload: {member.name!r}")
            data = source.read()
            if len(data) != member.size:
                raise SystemExit(f"short crate member read: {member.name!r}")
            destination.write_bytes(data)
            file_hashes[key] = hashlib.sha256(data).hexdigest()
    if not (root / "Cargo.toml").is_file():
        raise SystemExit(f"vendored crate has no Cargo.toml: {name} {version}")
    (root / ".cargo-checksum.json").write_text(json.dumps(
        {"files": file_hashes, "package": checksum},
        sort_keys=True, separators=(",", ":")), encoding="utf-8")
cargo_home.mkdir()
(cargo_home / "config.toml").write_text(
    "[source.crates-io]\nreplace-with = \"locked-vendor\"\n\n"
    "[source.locked-vendor]\n"
    f"directory = {json.dumps(str(vendor))}\n", encoding="utf-8")
PY

if [[ "$validate_only" -eq 1 ]]; then
  echo "merge_clear_lifecycle_1204 metadata/source lock validation passed"
  exit 0
fi

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmpdir" \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmpdir" \
  "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/merge_clear_lifecycle_cpp"

fixture_target="$oracle_tmp/cargo-target"
for cargo_config in "$oracle_tmp/rugra/.cargo/config" \
  "$oracle_tmp/rugra/.cargo/config.toml" "$oracle_tmp/.cargo/config" \
  "$oracle_tmp/.cargo/config.toml" /tmp/.cargo/config /tmp/.cargo/config.toml \
  /.cargo/config /.cargo/config.toml; do
  if [[ -e "$cargo_config" ]]; then
    echo "ambient Cargo config is outside comparand: $cargo_config" >&2
    exit 1
  fi
done
/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$build_tmpdir" \
  CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
  CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
  AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
  "$host_cargo_bin" build --offline --locked --quiet \
    --manifest-path "$oracle_tmp/rugra/Cargo.toml" --lib
rugra_rlib="$fixture_target/debug/librugra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librugra_sleigh.a' -print -quit)
if [[ ! -f "$rugra_rlib" || ! -f "$native_archive" ]]; then
  echo "isolated Rugra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$build_tmpdir" \
  "$host_rustc_bin" --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" --extern "rugra=$rugra_rlib" \
  -l static=rugra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/merge_clear_lifecycle_rust"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/merge_clear_lifecycle_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/merge_clear_lifecycle_rust" >"$oracle_tmp/rugra.stdout" \
  2>"$oracle_tmp/rugra.stderr"
test ! -s "$oracle_tmp/ghidra.stderr"
test ! -s "$oracle_tmp/rugra.stderr"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 6
test "$(wc -l < "$oracle_tmp/rugra.stdout")" -eq 6

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" <<'PYVERDICT'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_out = pathlib.Path(sys.argv[2]).read_bytes()
rugra_out = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_sha = hashlib.sha256(ghidra_out).hexdigest()
rugra_sha = hashlib.sha256(rugra_out).hexdigest()
if ghidra_sha != metadata["comparand"]["expected_ghidra_stdout_sha256"]:
    raise SystemExit(f"oracle stdout fingerprint drift: {ghidra_sha}")
if rugra_sha != metadata["comparand"]["expected_rugra_stdout_sha256"]:
    raise SystemExit(f"Rugra stdout fingerprint drift: {rugra_sha}")

ghidra_lines = ghidra_out.decode().splitlines()
rugra_lines = rugra_out.decode().splitlines()
match_lines = sum(1 for g, r in zip(ghidra_lines, rugra_lines) if g == r)
print(f"covered_projection={match_lines}/6 lines byte-identical")
# The two registered MISMATCH domains must be EXACTLY lines 5 and 6
# (1-based) and nothing else may drift.
for index in (4, 5):
    if ghidra_lines[index] == rugra_lines[index]:
        raise SystemExit(f"line {index + 1} unexpectedly matched; metadata MISMATCH status stale")
    if "stage=after" not in ghidra_lines[index]:
        raise SystemExit(f"line {index + 1} is not an after-stage observation")
if match_lines != 4:
    raise SystemExit("fixture regression: projection no longer 4/6")
if "domain=localmap" not in ghidra_lines[4] or "domain=funcproto" not in ghidra_lines[5]:
    raise SystemExit("registered MISMATCH lines are not the localmap/funcproto domains")
for g, r in zip(ghidra_lines, rugra_lines):
    if g != r:
        print(f"MISMATCH ghidra: {g}")
        print(f"MISMATCH rugra:  {r}")
PYVERDICT

cat "$oracle_tmp/ghidra.stdout"
printf 'merge_clear_lifecycle_1204: covered_projection=4/6 projection_status=MATCH overall_status=MISMATCH\n'
printf 'registered_mismatch_domains=localmap_typelock_survival,funcproto_unlocked_output\n'
printf 'residuals=MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001\n'
