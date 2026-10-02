#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001 locked differential runner.
# It rebuilds the Ghidra 12.0.4 oracle, constructs the pinned Rugra
# base-plus-overlay snapshot, and verifies the pinned, complete serialized
# outputs independently.  The production cspec's join_dual_class ModelRule
# is intentionally not normalized away: the locked oracle and Rugra are
# expected to differ until a separately reviewed ModelRule atom lands.

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  bfd_include_arg=${RUDRA_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
  bfd_library_arg=${RUDRA_BFD_LIBRARY:-/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin \
    RUDRA_BFD_INCLUDE="$bfd_include_arg" \
    RUDRA_BFD_LIBRARY="$bfd_library_arg" \
    /usr/bin/bash "$runner_fd_path" "$@"
fi

runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_fspec_paramlist_output_oracle.sh"
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

ghidra_only=false
if [[ ${1:-} == "--ghidra-only" ]]; then
  ghidra_only=true
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/fspec_paramlist_output_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/fspec_paramlist_output_1204.cc"
rust_fixture="$repo_root/tests/oracle/fspec_paramlist_output_1204.rs"
fspec_rs="$repo_root/src/fspec.rs"
fspec_doc="$repo_root/docs/api/fspec.md"
bfd_include=${RUDRA_BFD_INCLUDE}
bfd_header="$bfd_include/bfd.h"
bfd_library=${RUDRA_BFD_LIBRARY}
host_git=/usr/bin/git
host_python=/usr/bin/python3
host_cxx=/usr/bin/g++
host_cc=/usr/bin/gcc
host_ar=/usr/bin/ar
host_make=/usr/bin/make
host_cargo=/usr/bin/cargo
host_rustc=/usr/bin/rustc
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve the current user's home directory" >&2
  exit 1
fi

for tool in "$host_git" "$host_python" "$host_cxx" "$host_cc" \
  "$host_ar" "$host_make" "$host_cargo" "$host_rustc"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$fspec_rs" \
  "$fspec_doc" "$runner" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

rugra_base_commit=$($host_python -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["comparand"]["rugra_base_commit"])' \
  "$metadata")
rugra_base_tree=$($host_python -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["comparand"]["rugra_base_tree"])' \
  "$metadata")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
if [[ "$actual_base_tree" != "$rugra_base_tree" ]]; then
  echo "pinned Rugra base tree mismatch" >&2
  exit 1
fi

owned_files=("$fspec_rs" "$fspec_doc" "$cpp_fixture" "$rust_fixture" "$metadata" "$runner")
oracle_tmp=$(/usr/bin/mktemp -d /tmp/rugra-fspec-paramlist-output-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-fspec-paramlist-output-1204.??????) /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.before"

$host_python -I - "$metadata" "$repo_root" "$runner_sha" "$bfd_header" \
  "$bfd_library" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
repo = pathlib.Path(sys.argv[2]).resolve()
runner_sha, bfd_header_raw, bfd_library_raw = sys.argv[3:6]
oracle_commit, cpp_tree, makefile_blob = sys.argv[6:9]
document = json.loads(metadata_path.read_text(encoding="utf-8"))

def reject_pending(value, label="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{label}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{label} is pending: {value}")

reject_pending(document)
if document["schema"] != 2 or document["overall_status"] != "MISMATCH":
    raise SystemExit("metadata schema/status mismatch")
if document["covered_projection_status"] != "MISMATCH":
    raise SystemExit("metadata covered-projection status mismatch")
if document["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit mismatch")
if document["oracle"]["decompiler_cpp_tree"] != cpp_tree:
    raise SystemExit("metadata oracle cpp tree mismatch")
if document["oracle"]["decompiler_makefile_blob"] != makefile_blob:
    raise SystemExit("metadata oracle Makefile blob mismatch")

for relative, expected in document["comparand"]["overlay_sha256"].items():
    path = (repo / relative).resolve()
    try:
        path.relative_to(repo)
    except ValueError as error:
        raise SystemExit(f"overlay escapes repository: {relative}") from error
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"overlay is not a regular file: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"overlay hash mismatch: {relative}")
if document["comparand"]["overlay_sha256"]["tools/run_fspec_paramlist_output_oracle.sh"] != runner_sha:
    raise SystemExit("immutable runner hash differs from metadata")

for raw, key in (
    (bfd_header_raw, "bfd_header_sha256"),
    (bfd_library_raw, "bfd_library_sha256"),
):
    path = pathlib.Path(raw)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != document["external_inputs"][key]:
        raise SystemExit(f"external input hash mismatch: {path}")

payload = {
    "architecture": document["architecture"],
    "compiler_spec": document["compiler_spec"],
    "analysis_options": document["analysis_options"],
    "assets": document["assets"],
    "cases": document["input_manifest"]["cases"],
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
actual_manifest = hashlib.sha256(canonical).hexdigest()
if actual_manifest != document["input_manifest"]["sha256"]:
    raise SystemExit("input manifest hash mismatch")
PY

snapshot="$oracle_tmp/rugra"
oracle_source="$oracle_tmp/oracle"
spec_root="$oracle_tmp/specs"
/usr/bin/mkdir -p "$snapshot" "$oracle_source" "$spec_root"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive "$rugra_base_commit" | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$snapshot"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"

overlay_paths=(
  src/fspec.rs
  docs/api/fspec.md
  tests/oracle/fspec_paramlist_output_1204.cc
  tests/oracle/fspec_paramlist_output_1204.rs
  tests/oracle/fspec_paramlist_output_1204.metadata.json
  tools/run_fspec_paramlist_output_oracle.sh
)
for relative in "${overlay_paths[@]}"; do
  /usr/bin/install -D "$repo_root/$relative" "$snapshot/$relative"
done
/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

for relative in sleigh_specs/x86.ldefs sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86-64.sla; do
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git" -C "$repo_root" show "$rugra_base_commit:$relative" \
    >"$spec_root/${relative##*/}"
done
binary="$oracle_tmp/curl"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" show "$rugra_base_commit:examples/curl" >"$binary"
/usr/bin/chmod 0700 "$binary"

$host_python -I - "$metadata" "$repo_root" "$rugra_base_commit" \
  "$spec_root" "$binary" "$snapshot" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
repo = pathlib.Path(sys.argv[2])
base_commit = sys.argv[3]
spec_root = pathlib.Path(sys.argv[4])
binary = pathlib.Path(sys.argv[5])
snapshot = pathlib.Path(sys.argv[6])
paths = {
    "language_definitions": spec_root / "x86.ldefs",
    "processor_spec": spec_root / "x86-64.pspec",
    "compiler_spec": spec_root / "x86-64-gcc.cspec",
    "sla": spec_root / "x86-64.sla",
    "binary": binary,
}
for name, path in paths.items():
    record = document["assets"][name]
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise SystemExit(f"asset sha256 mismatch: {name}")
    if len(data) != record["size"]:
        raise SystemExit(f"asset size mismatch: {name}")
    blob = subprocess.check_output(
        ["/usr/bin/git", "-C", str(repo), "rev-parse", f"{base_commit}:{record['path']}"],
        text=True,
    ).strip()
    if blob != record["git_blob"]:
        raise SystemExit(f"asset blob mismatch: {name}")

closure_files = [snapshot / "Cargo.toml", snapshot / "Cargo.lock", snapshot / "build.rs"]
closure_files += sorted((snapshot / "src").rglob("*.rs"))
closure_files += sorted(path for path in (snapshot / "sleigh_shim").rglob("*") if path.is_file())
digest = hashlib.sha256()
for path in closure_files:
    relative = path.relative_to(snapshot).as_posix().encode()
    data = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)
if digest.hexdigest() != document["comparand"]["crate_closure_sha256"]:
    raise SystemExit("base-plus-overlay crate closure hash mismatch")
PY

jobs=8
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make" --silent -C "$oracle_cpp" -j "$jobs" \
  "CXX=$host_cxx -std=c++11" EXTRA= libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx" -std=c++11 -O0 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/fspec_paramlist_output_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi
bfd_library_dir=$(/usr/bin/dirname "$bfd_library")
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
  "$oracle_tmp/fspec_paramlist_output_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout"

$host_python -I - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout = pathlib.Path(sys.argv[2]).read_bytes()
expected = document["expected_results"]
actual_sha = hashlib.sha256(stdout).hexdigest()
if actual_sha != expected["ghidra_stdout_sha256"]:
    raise SystemExit(
        "locked Ghidra stdout hash mismatch: "
        f"expected={expected['ghidra_stdout_sha256']} actual={actual_sha}"
    )
if not stdout.startswith(b"SCHEMA|1\nORACLE|e40ed13014025f82488b1f8f7bca566894ac376b\n"):
    raise SystemExit("invalid locked Ghidra fixture envelope")
if not stdout.endswith(b"DONE\n"):
    raise SystemExit("incomplete locked Ghidra fixture output")
if b"OUTPUT_STATE|auto_killed_by_call=0\n" not in stdout:
    raise SystemExit("locked Ghidra ModelRule state observation changed")
if len(stdout.splitlines()) != expected["stdout_lines"]:
    raise SystemExit("locked Ghidra stdout line count mismatch")
PY

if $ghidra_only; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  /usr/bin/printf '%s\n' 'fspec_paramlist_output_1204: GHIDRA_LOCKED_OUTPUT_OK covered=MISMATCH overall=MISMATCH'
  exit 0
fi

fixture_target=/home/wirs/.cache/a55-fspecpin-target/fspec-paramlist-output
/usr/bin/mkdir -p "$fixture_target"
if ! /usr/bin/flock /tmp/rugra-cargo-build.lock -c \
  "CARGO_HOME='$user_home/.cargo' CARGO_TARGET_DIR='$fixture_target' CARGO_NET_OFFLINE=true CXX='$host_cxx' CC='$host_cc' AR='$host_ar' RUSTC='$host_rustc' '$host_cargo' build --manifest-path '$snapshot/Cargo.toml' --lib --locked --offline --quiet" \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rlib="$fixture_target/debug/librugra.rlib"
native_archive=$(/usr/bin/find "$fixture_target/debug/build" \
  -path '*/out/librugra_sleigh.a' -type f -print -quit)
if [[ ! -f "$rlib" || -z "$native_archive" || ! -f "$native_archive" ]]; then
  echo "fresh Rugra link inputs are missing" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "$native_archive")
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_rustc" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rugra=$rlib" -l static=rugra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" \
  -o "$oracle_tmp/fspec_paramlist_output_1204_rust"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$oracle_tmp/fspec_paramlist_output_1204_rust" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86-64.sla" \
  >"$oracle_tmp/rugra.stdout"
if /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
     >"$oracle_tmp/observations.diff"; then
  echo "declared MISMATCH unexpectedly became byte-identical" >&2
  exit 1
else
  diff_status=$?
  if [[ $diff_status -ne 1 ]]; then
    echo "observation diff failed with status $diff_status" >&2
    exit 1
  fi
fi

$host_python -I - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rugra.stdout" "$oracle_tmp/observations.diff" <<'PY'
import hashlib
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rugra = pathlib.Path(sys.argv[3]).read_bytes()
diff = pathlib.Path(sys.argv[4]).read_bytes()
expected = document["expected_results"]
rugra_sha = hashlib.sha256(rugra).hexdigest()
if rugra_sha != expected["rugra_stdout_sha256"]:
    raise SystemExit(
        "Rugra stdout hash mismatch: "
        f"expected={expected['rugra_stdout_sha256']} actual={rugra_sha}"
    )
if expected["ghidra_stdout_sha256"] == expected["rugra_stdout_sha256"]:
    raise SystemExit("metadata does not declare distinct side observations")
if hashlib.sha256(ghidra).hexdigest() != expected["ghidra_stdout_sha256"]:
    raise SystemExit("Ghidra stdout changed between runner stages")
if not rugra.startswith(b"SCHEMA|1\nORACLE|e40ed13014025f82488b1f8f7bca566894ac376b\n"):
    raise SystemExit("invalid Rugra fixture envelope")
if not rugra.endswith(b"DONE\n"):
    raise SystemExit("incomplete Rugra fixture output")
if b"OUTPUT_STATE|auto_killed_by_call=1\n" not in rugra:
    raise SystemExit("Rugra ModelRule residual observation changed")
if len(rugra.splitlines()) != expected["stdout_lines"]:
    raise SystemExit("Rugra stdout line count mismatch")
if not diff:
    raise SystemExit("declared MISMATCH produced an empty diff")

case_order = [case["id"] for case in document["input_manifest"]["cases"]
              if "active" in case]
for side, payload in (("Ghidra", ghidra), ("Rugra", rugra)):
    actual = [line.removeprefix(b"CASE|").decode("ascii")
              for line in payload.splitlines() if line.startswith(b"CASE|")]
    if actual != case_order:
        raise SystemExit(f"{side} case order mismatch: {actual!r}")
PY

/usr/bin/sha256sum "${owned_files[@]}" >"$oracle_tmp/owned.after"
/usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"
/usr/bin/cmp -s "$runner_fd_path" "$runner"
/usr/bin/cat "$oracle_tmp/rugra.stdout"
/usr/bin/printf '%s\n' 'fspec_paramlist_output_1204: DECLARED_MISMATCH_REPRODUCED covered=MISMATCH overall=MISMATCH'
