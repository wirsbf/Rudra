#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Locked bilateral gate for GETSTR-FUNCLINK-SPACE-0001.  The Ghidra side is
# rebuilt from tag Ghidra_12.0.4_build.  The Rudra side is a pinned base plus
# the exact live source closure owned by this repair, so unrelated dirty files
# and ambient build products cannot enter either comparand.

runner_fd=/proc/$$/fd/3
if [[ "${BASH_SOURCE[0]}" != "$runner_fd" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_action_funclink_input_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner identity mismatch" >&2
  exit 1
fi
if [[ "$(/usr/bin/stat -Lc '%a' "$runner_fd")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

mode=both
if [[ $# -eq 1 && "$1" == --ghidra-only ]]; then
  mode=ghidra
elif [[ $# -eq 1 && "$1" == --validate-only ]]; then
  mode=validate
elif [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only|--validate-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=356fafc786bce7835e669f571e93d66797e7a069
rudra_base_tree=5caa8e4fc60e50a1185e3e3e4763bcaf002dc930

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/action_funclink_input_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/action_funclink_input_1204.cc"
rust_fixture="$repo_root/tests/oracle/action_funclink_input_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_runtime=$(/usr/bin/dirname "$bfd_library")

spec_files=(
  sleigh_specs/x86.ldefs
  sleigh_specs/x86-64.pspec
  sleigh_specs/x86-64-gcc.cspec
  sleigh_specs/x86-64.sla
)
overlay_files=(
  src/coreaction.rs
  src/debugproto.rs
  src/fspec.rs
  src/funcdata.rs
  src/grammar.rs
  src/heritage.rs
  src/type_system/datatype.rs
  src/type_system/typefactory.rs
  src/varnode.rs
)

host_cxx=/usr/bin/g++
host_cc=/usr/bin/gcc
host_ar=/usr/bin/ar
host_make=/usr/bin/make
host_git=/usr/bin/git
host_python=/usr/bin/python3
host_cargo=/usr/bin/cargo
host_rustc=/usr/bin/rustc
for tool in "$host_cxx" "$host_cc" "$host_ar" "$host_make" "$host_git" \
  "$host_python" "$host_cargo" "$host_rustc"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
    exit 1
  fi
done
for relative in "${spec_files[@]}" "${overlay_files[@]}"; do
  if [[ ! -f "$repo_root/$relative" || -L "$repo_root/$relative" ]]; then
    echo "required comparand is not a regular non-symlink file: $relative" >&2
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
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

runner_sha=$(/usr/bin/sha256sum "$runner_fd" | /usr/bin/awk '{print $1}')
"$host_python" -I -S - "$repo_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_fd" "$runner_sha" "$bfd_include/bfd.h" \
  "$bfd_library" "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "${spec_files[@]}" -- "${overlay_files[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

args = sys.argv[1:]
repo = pathlib.Path(args.pop(0)).resolve()
metadata_path = pathlib.Path(args.pop(0)).resolve()
cpp = pathlib.Path(args.pop(0)).resolve()
rust = pathlib.Path(args.pop(0)).resolve()
runner_fd = pathlib.Path(args.pop(0))
runner_sha = args.pop(0)
bfd_header = pathlib.Path(args.pop(0)).resolve()
bfd_library = pathlib.Path(args.pop(0)).resolve()
oracle_tag, oracle_commit, cpp_tree, makefile_blob = args[:4]
base_commit, base_tree = args[4:6]
args = args[6:]
separator = args.index("--")
specs = args[:separator]
overlays = args[separator + 1:]

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["makefile_blob"], makefile_blob)
base = metadata["rugra_base"]
require("Rudra base commit", base["commit"], base_commit)
require("Rudra base tree", base["tree"], base_tree)

pins = metadata["sha256"]
checks = {
    "cpp_fixture": cpp,
    "rust_fixture": rust,
    "runner": runner_fd,
    "bfd_header": bfd_header,
    "bfd_library": bfd_library,
}
for relative in specs:
    checks[relative] = repo / relative
for relative in overlays:
    checks[relative] = repo / relative
for label, path in checks.items():
    actual = runner_sha if label == "runner" else sha(path)
    require(f"sha256 {label}", actual, pins[label])

manifest = hashlib.sha256()
for label in sorted(checks):
    manifest.update(label.encode())
    manifest.update(b"\0")
    manifest.update(pins[label].encode())
    manifest.update(b"\0")
manifest.update(oracle_commit.encode())
manifest.update(b"\0")
manifest.update(base_commit.encode())
require("input manifest", manifest.hexdigest(), metadata["input_manifest_sha256"])
PY

if [[ "$mode" == validate ]]; then
  echo "action_funclink_input_1204 metadata/source validation passed"
  exit 0
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 {print $6}')
cache_parent="$user_home/.cache/rudra-action-funclink-input-1204"
/usr/bin/mkdir -p "$cache_parent"
work=$(/usr/bin/mktemp -d "$cache_parent/run.XXXXXX")
cleanup() {
  case "$work" in
    "$cache_parent"/run.??????)
      # The build.rs oracle archive is intentionally read-only during the
      # run. Restore owner write permission only inside this validated
      # task-specific work directory so cleanup can remove it.
      if [[ -d "$work/workspace/ghidra" && ! -L "$work/workspace/ghidra" ]]; then
        /usr/bin/chmod -R u+w "$work/workspace/ghidra"
      fi
      /usr/bin/rm -rf -- "$work"
      ;;
    *) echo "refusing unsafe cleanup target: $work" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot="$work/workspace"
oracle_source="$work/oracle-source"
spec_root="$work/specs"
build_tmp="$work/build-tmp"
/usr/bin/mkdir -p "$snapshot" "$oracle_source" "$spec_root"
/usr/bin/mkdir -m 0700 "$build_tmp"

base_paths=(
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs
  src sleigh_shim
)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive "$rudra_base_commit" \
  "${base_paths[@]}" | /usr/bin/tar -xf - -C "$snapshot"
for relative in "${overlay_files[@]}"; do
  /usr/bin/install -D -m 0644 "$repo_root/$relative" "$snapshot/$relative"
done
/usr/bin/install -D -m 0644 "$rust_fixture" \
  "$snapshot/tests/oracle/action_funclink_input_1204.rs"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$oracle_source"
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"

# build.rs resolves the locked SLEIGH sources relative to the isolated Cargo
# snapshot.  Materialize a second, read-only archive at that exact path; do
# not let it fall through to the ambient worktree or to the mutable C++ build
# directory above.
/usr/bin/mkdir -p "$snapshot/ghidra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$snapshot/ghidra"
/usr/bin/chmod -R a-w "$snapshot/ghidra"

for relative in "${spec_files[@]}"; do
  /usr/bin/install -m 0644 "$repo_root/$relative" "$spec_root/${relative##*/}"
done

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
  "$host_make" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx -std=c++11" EXTRA= libdecomp.a \
  >"$work/make.stdout" 2>"$work/make.stderr"; then
  /usr/bin/cat "$work/make.stdout" >&2
  /usr/bin/cat "$work/make.stderr" >&2
  exit 1
fi

cpp_binary="$work/action_funclink_input_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
  "$host_cxx" -std=c++11 -O0 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$cpp_binary" \
  >"$work/cxx.stdout" 2>"$work/cxx.stderr"; then
  /usr/bin/cat "$work/cxx.stdout" >&2
  /usr/bin/cat "$work/cxx.stderr" >&2
  exit 1
fi

ghidra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_LIBRARY_PATH="$bfd_runtime" \
  "$cpp_binary" "$spec_root" >"$work/ghidra.stdout" \
  2>"$work/ghidra.stderr" || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 || -s "$work/ghidra.stderr" ]]; then
  echo "Ghidra ActionFuncLink oracle failed: exit=$ghidra_status" >&2
  /usr/bin/cat "$work/ghidra.stderr" >&2
  exit 1
fi

if [[ "$mode" == ghidra ]]; then
  "$host_python" -I -S - "$metadata" "$work/ghidra.stdout" <<'PY'
import hashlib, json, pathlib, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_text())
data = pathlib.Path(sys.argv[2]).read_bytes()
if hashlib.sha256(data).hexdigest() != m["capture"]["stdout_sha256"]:
    raise SystemExit("Ghidra stdout capture hash mismatch")
print(f"records={len(data.splitlines())} bytes={len(data)} stdout_sha256={hashlib.sha256(data).hexdigest()}")
PY
  /usr/bin/cat "$work/ghidra.stdout"
  exit 0
fi

fixture_target="$work/cargo-target"
if ! (
  builtin cd "$snapshot"
  /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$build_tmp" CXX="$host_cxx" \
    CC="$host_cc" AR="$host_ar" RUSTC="$host_rustc" \
    "$host_cargo" build --quiet --locked --offline --lib
) >"$work/cargo.stdout" 2>"$work/cargo.stderr"; then
  /usr/bin/cat "$work/cargo.stdout" >&2
  /usr/bin/cat "$work/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "Rudra library/native archive build output mismatch" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
rust_binary="$work/action_funclink_input_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$build_tmp" "$host_rustc" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/action_funclink_input_1204.rs" \
  -o "$rust_binary" >"$work/rustc.stdout" 2>"$work/rustc.stderr"; then
  /usr/bin/cat "$work/rustc.stdout" >&2
  /usr/bin/cat "$work/rustc.stderr" >&2
  exit 1
fi

rudra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rust_binary" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86-64.sla" \
  >"$work/rudra.stdout" 2>"$work/rudra.stderr" || rudra_status=$?
if [[ "$rudra_status" -ne 0 || -s "$work/rudra.stderr" ]]; then
  echo "Rudra ActionFuncLink fixture failed: exit=$rudra_status" >&2
  /usr/bin/cat "$work/rudra.stderr" >&2
  exit 1
fi

diff_status=0
/usr/bin/diff -u "$work/ghidra.stdout" "$work/rudra.stdout" \
  >"$work/runtime.diff" || diff_status=$?
if [[ "$diff_status" -ne 0 ]]; then
  echo "ActionFuncLink byte comparison failed" >&2
  /usr/bin/cat "$work/runtime.diff" >&2
  exit "$diff_status"
fi

"$host_python" -I -S - "$metadata" "$work/ghidra.stdout" \
  "$work/rudra.stdout" <<'PY'
import hashlib, json, pathlib, sys
m = json.loads(pathlib.Path(sys.argv[1]).read_text())
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra != rudra:
    raise SystemExit("byte diff unexpectedly diverged")
capture = m["capture"]
if len(ghidra) != capture["bytes"] or len(ghidra.splitlines()) != capture["records"]:
    raise SystemExit("capture size/record mismatch")
actual = hashlib.sha256(ghidra).hexdigest()
if actual != capture["stdout_sha256"]:
    raise SystemExit("capture stdout hash mismatch")
if not ghidra.endswith(b"done\n"):
    raise SystemExit("fixture completion marker mismatch")
print(f"records={capture['records']} bytes={capture['bytes']} stdout_sha256={actual}")
print("funcLinkInput=MATCH ParamActive_mapping=MATCH ActionFuncLink_apply_projection=MATCH ActionFuncLink_overall=UNTESTED")
PY
