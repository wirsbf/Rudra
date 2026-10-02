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
runner="$repo_root/tools/run_merge_persistent_oracle.sh"
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
rust_toolchain=nightly-x86_64-unknown-linux-gnu
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/cargo"
host_rustc_bin="$HOME/.rustup/toolchains/$rust_toolchain/bin/rustc"
for required_tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$required_tool" ]]; then
    echo "required tool is not executable: $required_tool" >&2
    exit 1
  fi
done

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-merge-persistent-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-merge-persistent-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Snapshot every live candidate exactly once before hashing or compiling. The
# runner itself is read from the already-open immutable descriptor above.
# NOTE: src/funcdata.rs is deliberately NOT snapshotted from the working tree
# — it carries unrelated in-flight leases. The pinned base commit carries the
# committed Funcdata merge_state mount (7046998: field/ctor/clear hook) and
# the assignHigh calcCover premise (funcdata_varnode.cc:52-53), so the base
# blob is used verbatim; only src/merge.rs is overlaid from this lease.
/usr/bin/mkdir -p "$oracle_tmp/candidate"
for candidate in \
  tests/oracle/merge_persistent_1204.metadata.json \
  tests/oracle/merge_persistent_1204.cc \
  tests/oracle/merge_persistent_1204.rs \
  src/merge.rs Cargo.toml Cargo.lock build.rs; do
  /usr/bin/cp -- "$repo_root/$candidate" "$oracle_tmp/candidate/$(/usr/bin/basename "$candidate")"
done
metadata="$oracle_tmp/candidate/merge_persistent_1204.metadata.json"
cpp_fixture="$oracle_tmp/candidate/merge_persistent_1204.cc"
rust_fixture="$oracle_tmp/candidate/merge_persistent_1204.rs"
merge_source="$oracle_tmp/candidate/merge.rs"

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
if [[ "$cpp_tree" != b02e230a539c65de14e50f357d0ba834d8184f4f || \
      "$makefile_blob" != ca0719fa5f17aabd14c52f40ed8b030f54d2aac6 ]]; then
  echo "locked Ghidra tree/blob mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# Freeze both sides: rebuild Ghidra from the locked commit, and build Rudra
# from the pinned base commit with only the owned merge.rs candidate overlaid
# (funcdata.rs comes verbatim from the base: the mount is committed there).
/usr/bin/mkdir -p "$oracle_tmp/ghidra" "$oracle_tmp/rudra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/ghidra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -x -C "$oracle_tmp/rudra"
/usr/bin/cp -- "$merge_source" "$oracle_tmp/rudra/src/merge.rs"

/usr/bin/mkdir -p "$oracle_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" \
  "$oracle_tmp/rudra/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_cpp="$oracle_tmp/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
cargo_home="$oracle_tmp/cargo-home"
registry_cache="$HOME/.cargo/registry/cache"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$merge_source" \
  "$runner_fd_path" "$runner_snapshot_sha" "$ghidra_root" "$oracle_commit" \
  "$oracle_tag" "$rudra_base_commit" "$oracle_tmp/candidate/Cargo.toml" \
  "$oracle_tmp/candidate/Cargo.lock" "$oracle_tmp/candidate/build.rs" \
  "$host_cxx_bin" "$host_cargo_bin" "$host_rustc_bin" "$host_make_bin" "$host_git_bin" \
  "$host_python_bin" \
  "$oracle_tmp/rudra" "$cargo_home" "$registry_cache" <<'PY'
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

(
    metadata_name, cpp_name, rust_name, source_name, runner_name,
    runner_snapshot_sha, ghidra_root_name, oracle_commit, oracle_tag,
    rudra_base_commit, cargo_toml_name, cargo_lock_name, build_rs_name,
    host_cxx_bin, host_cargo_bin, host_rustc_bin, host_make_bin, host_git_bin,
    host_python_bin, snapshot_name, cargo_home_name, registry_cache_name,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle mismatch")
if metadata["rugra_base_commit"] != rudra_base_commit:
    raise SystemExit("metadata Rudra base commit mismatch")
if metadata["overall_status"] != "MISMATCH: (B2 canonicalization)":
    raise SystemExit("fixture must remain MISMATCH overall until registered residuals close")
if metadata.get("projection_status") != "MATCH":
    raise SystemExit("covered 29-line projection must remain MATCH")
if metadata["coverage"]["copy_shadow_ladder_full_sequence"] != "MATCH":
    raise SystemExit("copy_shadow_ladder coverage must be MATCH")
if metadata["coverage"]["pipeline_tail_full_sequence_with_merge_all_entry"] != "MATCH":
    raise SystemExit("pipeline_tail coverage must be MATCH")
if metadata["coverage"].get("float_trunc_cast_gate_reject") != "MATCH":
    raise SystemExit("float_trunc_cast coverage must be MATCH")
if metadata["coverage"].get("char_gate_null_world_size1_pass") != "MATCH":
    raise SystemExit("char_gate_null coverage must be MATCH")
if metadata["coverage"].get("char_gate_registered_world_size1_reject") != "MATCH":
    raise SystemExit("char_gate_char coverage must be MATCH")
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
makefile_blob = subprocess.check_output([
    host_git_bin, "-C", str(ghidra_root), "rev-parse",
    "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile",
], text=True).strip()
if makefile_blob != metadata["oracle"]["decompiler_makefile_blob"]:
    raise SystemExit("locked Ghidra Makefile blob mismatch")

paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "merge_rs_sha256": pathlib.Path(source_name),
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
    "host_rustc": subprocess.check_output([host_rustc_bin, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo_bin, "--version"], text=True).strip(),
}
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

# Materialize only the Cargo.lock registry closure. Every .crate is read once
# and checked against its locked checksum before extraction, so no mutable
# registry index/config participates in the build.
snapshot = pathlib.Path(snapshot_name)
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

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
    CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/merge_persistent_cpp"

fixture_target="$oracle_tmp/cargo-target"
for cargo_config in "$oracle_tmp/rudra/.cargo/config" \
  "$oracle_tmp/rudra/.cargo/config.toml" "$oracle_tmp/.cargo/config" \
  "$oracle_tmp/.cargo/config.toml" /tmp/.cargo/config /tmp/.cargo/config.toml \
  /.cargo/config /.cargo/config.toml; do
  if [[ -e "$cargo_config" ]]; then
    echo "ambient Cargo config is outside comparand: $cargo_config" >&2
    exit 1
  fi
done
/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fixture_target" \
  CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
  AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
  "$host_cargo_bin" build --offline --locked --quiet \
    --manifest-path "$oracle_tmp/rudra/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librudra_sleigh.a' -print -quit)
if [[ ! -f "$rudra_rlib" || ! -f "$native_archive" ]]; then
  echo "isolated Rudra build did not produce required libraries" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i HOME="$HOME" RUSTUP_HOME="$HOME/.rustup" \
  RUSTUP_TOOLCHAIN="$rust_toolchain" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/merge_persistent_rust"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/merge_persistent_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/merge_persistent_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr"
test ! -s "$oracle_tmp/ghidra.stderr"
test ! -s "$oracle_tmp/rudra.stderr"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 29
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 29

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PYVERDICT'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_out = pathlib.Path(sys.argv[2]).read_bytes()
rudra_out = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_sha = hashlib.sha256(ghidra_out).hexdigest()
rudra_sha = hashlib.sha256(rudra_out).hexdigest()
if ghidra_sha != metadata["comparand"]["expected_ghidra_stdout_sha256"]:
    raise SystemExit(f"oracle stdout fingerprint drift: {ghidra_sha}")
if rudra_sha != metadata["comparand"]["expected_rudra_stdout_sha256"]:
    raise SystemExit(f"Rudra stdout fingerprint drift: {rudra_sha}")

ghidra_lines = ghidra_out.decode().splitlines()
rudra_lines = rudra_out.decode().splitlines()
match_lines = sum(1 for g, r in zip(ghidra_lines, rudra_lines) if g == r)
print(f"covered_projection={match_lines}/29 lines byte-identical")
for g, r in zip(ghidra_lines, rudra_lines):
    if g != r:
        print(f"MISMATCH ghidra: {g}")
        print(f"MISMATCH rudra:  {r}")
if match_lines != 29:
    raise SystemExit("fixture regression: projection no longer 29/29")
PYVERDICT

cat "$oracle_tmp/ghidra.stdout"
printf 'merge_persistent_1204: covered_projection=29/29 projection_status=MATCH overall_status=MISMATCH\n'
printf 'persistent_premise=UNTESTED: grouping/covers are bilateral; attach-depth/cache-size checks are Rust-only until MERGE-PERSISTENCE-CHANNELS-0001\n'
printf 'gates=PARTIAL_MATCH: mergeTestAdjacent/FLOAT_TRUNC/custom-name nochar canonical Arc cases match; Java ZEXT and CPOOLREF remain MISMATCH\n'
printf 'residuals=TYPEOP-LOCALTYPE-DISPATCH-0001,MERGE-PROTOPARTIAL-GROUP-0001,MERGE-COPYTRIMS-CACHE-0001,MERGE-MARKER-TRIM-0001,MERGE-CLEAR-LIFECYCLE-0001\n'
