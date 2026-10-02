#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Re-execute from an already-open descriptor in a clean environment. Every
# fixture overlay is copied once into the temporary snapshot, then the copied
# bytes are both validated and executed. Git-backed inputs are always read
# from the verified pinned objects, never from their live worktree paths.
runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH="/usr/bin:/bin" /usr/bin/bash "$runner_fd_path" "$@"
fi

runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
live_runner="$repo_root/tools/run_address_phase2_closure_oracle.sh"
if [[ "$runner_source" != "$live_runner" || -L "$live_runner" ]]; then
  echo "runner fd resolved outside the expected regular repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
pinned_base=4f42981d2ed723e6ac53ebb787d90f4b89e889df
pinned_tree=17fd780210a7139a8b3dc30459e627b1926d763e
ghidra_root="$repo_root/ghidra"
live_metadata="$repo_root/tests/oracle/address_phase2_closure_1204.metadata.json"
live_cpp_fixture="$repo_root/tests/oracle/address_phase2_closure_1204.cc"
live_rust_fixture="$repo_root/tests/oracle/address_phase2_closure_1204.rs"
cargo_target=/tmp/rudra-target-address-phase2
cargo_lock=/tmp/rudra-cargo-build.lock

host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_objcopy_bin=$(/usr/bin/readlink -f /usr/bin/objcopy)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
host_flock_bin=$(/usr/bin/readlink -f /usr/bin/flock)
for tool in "$host_git_bin" "$host_python_bin" "$host_make_bin" \
  "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_objcopy_bin" \
  "$host_cargo_bin" "$host_rustc_bin" "$host_flock_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$live_metadata" "$live_cpp_fixture" "$live_rust_fixture" "$live_runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required regular input is missing or a symlink: $input" >&2
    exit 1
  fi
done

git_clean() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
    "$host_git_bin" "$@"
}

actual_commit=$(git_clean -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(git_clean -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
locked_dirty=$(git_clean -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra decompiler sources are dirty" >&2
  echo "$locked_dirty" >&2
  exit 1
fi

actual_pinned_commit=$(git_clean -C "$repo_root" rev-parse "$pinned_base^{commit}")
actual_pinned_tree=$(git_clean -C "$repo_root" rev-parse "$pinned_base^{tree}")
if [[ "$actual_pinned_commit" != "$pinned_base" || \
      "$actual_pinned_tree" != "$pinned_tree" ]]; then
  echo "pinned Rudra commit/tree identity mismatch" >&2
  exit 1
fi

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-address-phase2-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-address-phase2-1204.??????)
      /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe temporary cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot="$oracle_tmp/workspace"
/usr/bin/mkdir -p "$snapshot" "$snapshot/tests/oracle" "$snapshot/tools" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile" \
  "$oracle_tmp/ghidra-source"
git_clean -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$pinned_base"
/usr/bin/tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot"
git_clean -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-source.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/tar -xf "$oracle_tmp/ghidra-source.tar" -C "$oracle_tmp/ghidra-source"
oracle_cpp="$oracle_tmp/ghidra-source/Ghidra/Features/Decompiler/src/decompile/cpp"

# Copy each live overlay once. All validation and execution below use only
# these snapshots; final cmp checks reject concurrent live changes.
/usr/bin/cp -- "$live_metadata" \
  "$snapshot/tests/oracle/address_phase2_closure_1204.metadata.json"
/usr/bin/cp -- "$live_cpp_fixture" \
  "$snapshot/tests/oracle/address_phase2_closure_1204.cc"
/usr/bin/cp -- "$live_rust_fixture" \
  "$snapshot/tests/oracle/address_phase2_closure_1204.rs"
/usr/bin/cp -- "$runner_fd_path" \
  "$snapshot/tools/run_address_phase2_closure_oracle.sh"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

metadata="$snapshot/tests/oracle/address_phase2_closure_1204.metadata.json"
cpp_fixture="$snapshot/tests/oracle/address_phase2_closure_1204.cc"
rust_fixture="$snapshot/tests/oracle/address_phase2_closure_1204.rs"
runner="$snapshot/tools/run_address_phase2_closure_oracle.sh"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$repo_root" "$ghidra_root" "$snapshot" "$cpp_fixture" \
  "$rust_fixture" "$runner" "$runner_snapshot_sha" "$host_git_bin" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$pinned_base" "$pinned_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, repo_raw, ghidra_raw, snapshot_raw, cpp_raw, rust_raw,
    runner_raw, runner_snapshot_sha, git_bin, oracle_commit, oracle_tag,
    cpp_tree, makefile_blob, pinned_base, pinned_tree,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw)
ghidra = pathlib.Path(ghidra_raw)
snapshot = pathlib.Path(snapshot_raw)

def regular(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"expected regular non-symlink file: {path}")
    return path.read_bytes()

def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

git_env = {
    "PATH": "/usr/bin:/bin",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_NO_REPLACE_OBJECTS": "1",
}

def git_rev(root, expression):
    return subprocess.check_output(
        [git_bin, "-C", str(root), "rev-parse", expression],
        text=True,
        env=git_env,
    ).strip()

def git_blob(root, oid):
    return subprocess.check_output(
        [git_bin, "-C", str(root), "cat-file", "blob", oid],
        env=git_env,
    )

metadata = json.loads(regular(metadata_raw).decode("utf-8"))
require("schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "ADDRESS-PHASE2-CLOSURE-0001")
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle cpp tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")
require("overall status", metadata["observation"]["overall_status"], "MISMATCH")
require("pinned base", metadata["comparand"]["pinned_base_commit"], pinned_base)
require("pinned tree", metadata["comparand"]["pinned_base_tree"], pinned_tree)
require("pinned commit object", git_rev(repo, f"{pinned_base}^{{commit}}"), pinned_base)
require("pinned tree object", git_rev(repo, f"{pinned_base}^{{tree}}"), pinned_tree)

canonical_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require(
    "input fingerprint", metadata["input_fingerprint"],
    "sha256:" + hashlib.sha256(canonical_input).hexdigest(),
)

file_hashes = {
    "cpp_fixture_sha256": sha_bytes(regular(cpp_raw)),
    "rust_fixture_sha256": sha_bytes(regular(rust_raw)),
    "runner_sha256": sha_bytes(regular(runner_raw)),
}
for key, actual in file_hashes.items():
    require(key, metadata["comparand"][key], actual)
require("runner fd snapshot", file_hashes["runner_sha256"], runner_snapshot_sha)

required_source_paths = {
    "Cargo.lock", "Cargo.toml", "build.rs",
    "sleigh_shim/rudra_sleigh.cpp", "src/address.rs", "src/block.rs",
    "src/disasm/sleigh_lift.rs", "src/flow.rs", "src/funcdata.rs",
    "src/op.rs", "src/space.rs",
}
source_blobs = metadata["comparand"]["source_blobs"]
require("Rudra source blob path set", set(source_blobs), required_source_paths)
for relative, expected_blob in source_blobs.items():
    actual = git_rev(repo, f"{pinned_base}:{relative}")
    require(f"Rudra source blob {relative}", actual, expected_blob)

cpp_prefix = "Ghidra/Features/Decompiler/src/decompile/cpp/"
for relative, expected_blob in metadata["oracle"]["source_blobs"].items():
    actual = git_rev(ghidra, f"{oracle_commit}:{cpp_prefix}{relative}")
    require(f"Ghidra source blob {relative}", actual, expected_blob)

assets = metadata["assets"]
expected_asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
require(
    "asset key set", set(assets),
    set(expected_asset_paths),
)
for key, asset in assets.items():
    require(f"asset path {key}", asset["path"], expected_asset_paths[key])
    relative = pathlib.PurePosixPath(asset["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit(f"unsafe asset path {key}: {asset['path']!r}")
    path = snapshot.joinpath(*relative.parts)
    data = regular(path)
    actual_blob = git_rev(repo, f"{pinned_base}:{relative.as_posix()}")
    require(f"asset git blob {key}", actual_blob, asset["git_blob_oid"])
    require(f"asset blob hash {key}", sha_bytes(git_blob(repo, actual_blob)), asset["sha256"])
    require(f"asset snapshot hash {key}", sha_bytes(data), asset["sha256"])

compiler_asset = assets["compiler_spec"]
for field in ("path", "sha256", "git_blob_oid"):
    require(
        f"compiler spec duplicate {field}",
        metadata["compiler_spec"][field], compiler_asset[field],
    )

expected_keys = {
    "ghidra_stdout_sha256", "ghidra_stderr_sha256",
    "rudra_stdout_sha256", "rudra_stderr_sha256", "unified_diff_sha256",
}
require("expected output key set", set(metadata["expected"]), expected_keys)
for key, value in metadata["expected"].items():
    if not isinstance(value, str) or len(value) != 64 or value.startswith("PENDING"):
        raise SystemExit(f"expected output pin is invalid: {key}={value!r}")

statuses = {case["id"]: case["status"] for case in metadata["observation"]["cases"]}
required = {
    "address_space_identity_order": "MATCH",
    "bank_create_lifecycle": "MISMATCH",
    "bank_destroy_alive_exception": "MISMATCH",
    "split_parent_order": "MATCH",
    "split_entry_start_stop_cover": "MISMATCH",
    "split_missing_start_exception": "MISMATCH",
    "flow_ram_tagged_entry": "MISMATCH",
    "flow_overlay_tagged_entry": "MISMATCH",
    "flow_stack_tagged_entry": "MISMATCH",
    "combined_cross_space_visited": "UNTESTED",
}
require("case status matrix", statuses, required)
PY

jobs=4
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp" \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp" \
  "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/raw_arch.cc" \
  "$oracle_cpp/libdecomp.a" -lz -o "$oracle_tmp/address_phase2_closure_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_objcopy_bin" \
  --dump-section ".rudra_input=$oracle_tmp/input.bin" \
  "$oracle_tmp/address_phase2_closure_cpp"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$oracle_tmp/input.bin" <<'PY'
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
if data != bytes.fromhex("750190c3"):
    raise SystemExit(f"raw input bytes differ: {data.hex()}")
PY

ghidra_status=0
(
  builtin cd "$snapshot"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp" \
    "$oracle_tmp/address_phase2_closure_cpp" sleigh_specs "$oracle_tmp/input.bin"
) >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr" || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 ]]; then
  echo "Ghidra comparand failed: $ghidra_status" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

/usr/bin/mkdir -p "$cargo_target"
if ! (
  builtin cd "$snapshot"
  "$host_flock_bin" "$cargo_lock" \
    /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
      TMPDIR="$oracle_tmp" CARGO_HOME="$user_home/.cargo" \
      CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$cargo_target" \
      CXX="$host_cxx_bin" CC="$host_cc_bin" AR="$host_ar_bin" \
      RUSTC="$host_rustc_bin" \
      "$host_cargo_bin" build --offline --locked --lib \
        --manifest-path "$snapshot/Cargo.toml"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi

rudra_rlib="$cargo_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$cargo_target/debug/build" -path '*/out/librudra_sleigh.a' \
    -type f | /usr/bin/sort
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "Cargo did not produce exactly one Rudra rlib/native archive" >&2
  /usr/bin/printf '%s\n' "${native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$oracle_tmp" "$host_rustc_bin" --edition=2021 -O \
  -C linker-features=-lld -L "dependency=$cargo_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/address_phase2_closure_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

rudra_status=0
(
  builtin cd "$snapshot"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 TMPDIR="$oracle_tmp" \
    "$oracle_tmp/address_phase2_closure_rust"
) >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr" || rudra_status=$?
if [[ "$rudra_status" -ne 0 ]]; then
  echo "Rudra comparand failed: $rudra_status" >&2
  /usr/bin/cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

diff_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/diff \
  --label ghidra --label rudra -u "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" >"$oracle_tmp/output.diff" || diff_status=$?
if [[ "$diff_status" -ne 1 ]]; then
  echo "unexpected comparand diff status: $diff_status" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/output.diff" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "unified_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")

ghidra = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
rudra = paths["rudra_stdout_sha256"].read_text(encoding="utf-8").splitlines()

def selected(lines, prefix):
    return [line for line in lines if line.startswith(prefix)]

for side, lines in (("ghidra", ghidra), ("rugra", rudra)):
    if len(selected(lines, "record=header ")) != 1:
        raise SystemExit(f"{side}: missing unique header")
    if len(selected(lines, "record=coverage ")) != 1:
        raise SystemExit(f"{side}: missing unique UNTESTED coverage record")
    for case in ("flow_ram", "flow_code_overlay", "flow_stack"):
        if len(selected(lines, f"case={case} record=run ")) != 1:
            raise SystemExit(f"{side}: missing independent run for {case}")
        if len(selected(lines, f"case={case} record=generated ")) != 1:
            raise SystemExit(f"{side}: missing production generation for {case}")
        if len(selected(lines, f"case={case} record=visited ")) != 3:
            raise SystemExit(f"{side}: expected three visited records for {case}")

mismatch_prefixes = [
    "case=bank_spaces record=membership phase=create ",
    "case=bank_spaces record=destroy_alive ",
    "case=split_spaces record=block ",
    "case=split_missing_start record=exception ",
    "case=flow_ram record=generated ",
    "case=flow_code_overlay record=exception ",
    "case=flow_stack record=exception ",
]
for prefix in mismatch_prefixes:
    if selected(ghidra, prefix) == selected(rudra, prefix):
        raise SystemExit(f"registered MISMATCH disappeared for {prefix!r}")

coverage = selected(rudra, "record=coverage ")[0]
if "combined_cross_space_visited=UNTESTED" not in coverage:
    raise SystemExit("combined cross-space visited residual was not retained")
PY

for binding in \
  "$metadata|$live_metadata" \
  "$cpp_fixture|$live_cpp_fixture" \
  "$rust_fixture|$live_rust_fixture" \
  "$runner|$live_runner"; do
  snapshot_input=${binding%%|*}
  live_input=${binding#*|}
  if [[ ! -f "$snapshot_input" || -L "$snapshot_input" || ! -f "$live_input" || -L "$live_input" ]]; then
    echo "input type changed during runner execution: $live_input" >&2
    exit 1
  fi
  if ! /usr/bin/cmp -s -- "$snapshot_input" "$live_input"; then
    echo "live input changed during runner execution: $live_input" >&2
    exit 1
  fi
done

echo "address_phase2_closure_1204: MISMATCH (expected, real dual execution)"
echo "address_phase2_closure_1204: combined_cross_space_visited=UNTESTED"
