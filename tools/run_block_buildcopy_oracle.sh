#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Locked bilateral gate for BLOCK-BUILDCOPY-STATE-0001.  The oracle is
# rebuilt from Ghidra 12.0.4 commit e40ed130.  Rudra is materialized from a
# pinned base and overlays the two production files under test plus the
# hash-pinned Funcdata build-closure required by their current API.

runner_fd=/proc/$$/fd/3
if [[ "${BASH_SOURCE[0]}" != "$runner_fd" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_block_buildcopy_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner identity mismatch" >&2
  exit 1
fi
if [[ "$(/usr/bin/stat -Lc '%a' "$runner_fd")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

mode=both
if [[ $# -eq 1 && "$1" == --validate-only ]]; then
  mode=validate
elif [[ $# -eq 1 && "$1" == --ghidra-only ]]; then
  mode=ghidra
elif [[ $# -ne 0 ]]; then
  echo "usage: $runner [--validate-only|--ghidra-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=a5362afcfcccc25d87e4853552440d4fad619d1b
rudra_base_tree=4b1174a8fdd53c5835f304ac5bab0732ea81713c
rudra_base_src_tree=bcd7c6846e4c34834265f3999a326389adbc4882
rudra_base_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_base_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/block_buildcopy_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/block_buildcopy_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_buildcopy_1204.rs"
block_overlay="$repo_root/src/block.rs"
blockaction_overlay="$repo_root/src/blockaction.rs"
funcdata_overlay="$repo_root/src/funcdata.rs"

host_cxx=/usr/bin/g++
host_cc=/usr/bin/gcc
host_ar=/usr/bin/ar
host_make=/usr/bin/make
host_git=/usr/bin/git
host_python=/usr/bin/python3
host_cargo=/usr/bin/cargo
host_rustc=/usr/bin/rustc
for tool in "$host_cxx" "$host_cc" "$host_ar" "$host_make" "$host_git" \
  "$host_python" "$host_cargo" "$host_rustc" /usr/bin/flock; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$block_overlay" \
  "$blockaction_overlay" "$funcdata_overlay" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
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

actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{tree}")
actual_base_src_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:src")
actual_base_cargo_toml_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:Cargo.toml")
actual_base_cargo_lock_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:Cargo.lock")
actual_base_build_rs_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:build.rs")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" || \
      "$actual_base_src_tree" != "$rudra_base_src_tree" || \
      "$actual_base_cargo_toml_blob" != "$rudra_base_cargo_toml_blob" || \
      "$actual_base_cargo_lock_blob" != "$rudra_base_cargo_lock_blob" || \
      "$actual_base_build_rs_blob" != "$rudra_base_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

runner_sha=$(/usr/bin/sha256sum "$runner_fd" | /usr/bin/awk '{print $1}')
"$host_python" -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_fd" "$runner_sha" "$block_overlay" "$blockaction_overlay" \
  "$funcdata_overlay" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_base_commit" "$rudra_base_tree" "$rudra_base_src_tree" \
  "$rudra_base_cargo_toml_blob" "$rudra_base_cargo_lock_blob" \
  "$rudra_base_build_rs_blob" "$host_cxx" "$host_rustc" "$host_cargo" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, cpp_raw, rust_raw, runner_raw, runner_sha, block_raw,
    blockaction_raw, funcdata_raw, oracle_tag, oracle_commit, cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob,
    build_rs_blob, host_cxx, host_rustc, host_cargo,
) = sys.argv[1:]

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "BLOCK-BUILDCOPY-STATE-0001")
require("covered projection", metadata["covered_projection_status"], "MATCH")
require("overall status", metadata["overall_status"], "MISMATCH")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)

base = metadata["rugra_source"]
for key, expected in {
    "base_commit": base_commit,
    "base_tree": base_tree,
    "base_src_tree": base_src_tree,
    "base_cargo_toml_blob": cargo_toml_blob,
    "base_cargo_lock_blob": cargo_lock_blob,
    "base_build_rs_blob": build_rs_blob,
}.items():
    require(key, base[key], expected)
overlays = base["overlays"]
require("overlay paths", [item["path"] for item in overlays],
        ["src/block.rs", "src/blockaction.rs", "src/funcdata.rs"])
require("block overlay hash", overlays[0]["sha256"], sha(block_raw))
require("blockaction overlay hash", overlays[1]["sha256"], sha(blockaction_raw))
require("funcdata overlay hash", overlays[2]["sha256"], sha(funcdata_raw))

comparand = metadata["comparand"]
for key, path in {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "block_rs_sha256": block_raw,
    "blockaction_rs_sha256": blockaction_raw,
    "funcdata_rs_sha256": funcdata_raw,
}.items():
    require(key, comparand[key], sha(path))
require("runner_sha256", comparand["runner_sha256"], runner_sha)
versions = {
    "host_cxx": subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo, "--version"], text=True).strip(),
}
for key, actual in versions.items():
    require(key, comparand[key], actual)

for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")
case_ids = [case["id"] for case in metadata["input_manifest"]["cases"]]
require("case order", case_ids,
        ["incoming_order_6_2", "append_prefix_untouched", "live_delegate",
         "blockbasic_insert_end", "parallel_remove_after_swap"])
payload = json.dumps(metadata["input_manifest"]["cases"], sort_keys=True,
                     separators=(",", ":"), ensure_ascii=False).encode()
require("input fingerprint", metadata["input_manifest"]["sha256"],
        hashlib.sha256(payload).hexdigest())
for case_id in case_ids:
    require(f"coverage {case_id}", metadata["coverage"][case_id], "MATCH")
PY

if [[ "$mode" == validate ]]; then
  echo "block_buildcopy_1204 metadata/source validation passed"
  exit 0
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | \
  /usr/bin/awk -F: 'NR == 1 {print $6}')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache/rudra-block-buildcopy-1204"
/usr/bin/mkdir -p "$cache_parent"
exec 9>"$cache_parent/runner.lock"
if ! /usr/bin/flock -n 9; then
  echo "another block_buildcopy_1204 runner is active" >&2
  exit 1
fi
work=$(/usr/bin/mktemp -d "$cache_parent/run.XXXXXX")
snapshot="$work/rudra"
cleanup() {
  case "$work" in
    "$cache_parent"/run.??????) /usr/bin/rm -rf -- "$work" ;;
    *) echo "refusing unsafe cleanup target: $work" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/mkdir -p "$snapshot" "$work/oracle-source" "$work/build-tmp"

owned=("$metadata" "$cpp_fixture" "$rust_fixture" "$block_overlay" \
       "$blockaction_overlay" "$funcdata_overlay" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$work/owned.before"

base_paths=(
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs
  src sleigh_shim
)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive "$rudra_base_commit" \
  "${base_paths[@]}" | /usr/bin/tar -xf - -C "$snapshot"
/usr/bin/install -m 0644 "$block_overlay" "$snapshot/src/block.rs"
/usr/bin/install -m 0644 "$blockaction_overlay" "$snapshot/src/blockaction.rs"
/usr/bin/install -m 0644 "$funcdata_overlay" "$snapshot/src/funcdata.rs"
/usr/bin/install -D -m 0644 "$rust_fixture" \
  "$snapshot/tests/oracle/block_buildcopy_1204.rs"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$work/oracle-source"
oracle_cpp="$work/oracle-source/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$work/build-tmp" \
  "$host_make" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx -std=c++11" EXTRA= libdecomp.a \
  >"$work/make.stdout" 2>"$work/make.stderr"; then
  /usr/bin/cat "$work/make.stdout" "$work/make.stderr" >&2
  exit 1
fi
cpp_binary="$work/block_buildcopy_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$work/build-tmp" \
  "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive \
  -lz -o "$cpp_binary" >"$work/cxx.stdout" 2>"$work/cxx.stderr"; then
  /usr/bin/cat "$work/cxx.stdout" "$work/cxx.stderr" >&2
  exit 1
fi

ghidra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" \
  >"$work/ghidra.stdout" 2>"$work/ghidra.stderr" || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 || -s "$work/ghidra.stderr" ]]; then
  echo "Ghidra fixture execution failed: status=$ghidra_status" >&2
  /usr/bin/cat "$work/ghidra.stderr" >&2
  exit 1
fi

if [[ "$mode" == ghidra ]]; then
  /usr/bin/cat "$work/ghidra.stdout"
  ghidra_sha=$(/usr/bin/sha256sum "$work/ghidra.stdout" | /usr/bin/awk '{print $1}')
  /usr/bin/printf 'block_buildcopy_1204: GHIDRA_LOCKED_OUTPUT_OK stdout_sha256=%s\n' \
    "$ghidra_sha"
  exit 0
fi

fixture_target="$cache_parent/cargo-target"
if ! (
  builtin cd "$snapshot"
  /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$work/build-tmp" CXX="$host_cxx" \
    CC="$host_cc" AR="$host_ar" RUSTC="$host_rustc" RUSTFLAGS=-Awarnings \
    "$host_cargo" build --quiet --locked --offline --lib
) >"$work/cargo.stdout" 2>"$work/cargo.stderr"; then
  /usr/bin/cat "$work/cargo.stdout" "$work/cargo.stderr" >&2
  exit 1
fi
rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" \
    -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "Rudra library/native archive build output mismatch" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
rust_binary="$work/block_buildcopy_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$work/build-tmp" "$host_rustc" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/block_buildcopy_1204.rs" -o "$rust_binary" \
  >"$work/rustc.stdout" 2>"$work/rustc.stderr"; then
  /usr/bin/cat "$work/rustc.stdout" "$work/rustc.stderr" >&2
  exit 1
fi

rudra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rust_binary" \
  >"$work/rudra.stdout" 2>"$work/rudra.stderr" || rudra_status=$?
if [[ "$rudra_status" -ne 0 || -s "$work/rudra.stderr" ]]; then
  echo "Rudra fixture execution failed: status=$rudra_status" >&2
  /usr/bin/cat "$work/rudra.stderr" >&2
  exit 1
fi

diff_status=0
/usr/bin/diff -u "$work/ghidra.stdout" "$work/rudra.stdout" \
  >"$work/runtime.diff" || diff_status=$?
if [[ "$diff_status" -ne 0 ]]; then
  echo "BlockGraph::buildCopy byte comparison failed" >&2
  /usr/bin/cat "$work/runtime.diff" >&2
  exit "$diff_status"
fi

"$host_python" -I -S - "$metadata" "$work/ghidra.stdout" \
  "$work/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra != rudra:
    raise SystemExit("byte diff unexpectedly diverged")
capture = metadata["capture"]
if len(ghidra) != capture["bytes"] or len(ghidra.splitlines()) != capture["records"]:
    raise SystemExit("capture size/record mismatch")
actual_hash = hashlib.sha256(ghidra).hexdigest()
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("capture stdout hash mismatch")
lines = ghidra.decode("utf-8").splitlines()
expected_envelope = (
    "schema=1|fixture=BLOCK-BUILDCOPY-STATE-0001"
    "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    "|overall=MISMATCH|covered_projection=MATCH"
)
if lines[0] != expected_envelope:
    raise SystemExit("fixture envelope drift")
joined = "\n".join(lines)
required = [
    "block=c4|type=copy,index=26,flags=32,visit=0,numdesc=304,idom=c2,in=[c6:0:129,c2:0:258]",
    "block=c1|type=copy,index=11,flags=262160,visit=0,numdesc=301",
    "phase=after|target_list=[p0,p1,c0,c1,c2]|target_index=31",
    "phase=before|block=c0|type=copy|sub0=s0|sub7=s0|exit_self=1|first=op0|last=op1|complex=0|split=s1",
    "phase=after|block=c0|type=copy|sub0=s0|sub7=s0|exit_self=1|first=op2|last=op2|complex=1|split=null",
    "case=blockbasic_insert_end|phase=after|block=s0|ops=[0>op0:time=10:order=8388610:parent=s0,1>op1:time=11:order=16777218:parent=s0,2>op2:time=12:order=25165826:parent=s0]|flags=16|switch_out=1|last=op2",
    "case=parallel_remove_after_swap|phase=swapped|src_out=[0>d0:1:98,1>d0:0:49]|dst_in=[0>s0:1:49,1>s0:0:98]|src_flags=65536|src_ok=1|dst_ok=1",
    "case=parallel_remove_after_swap|phase=removed|src_out=[0>d0:0:98]|dst_in=[0>s0:0:98]|src_flags=65536|src_ok=1|dst_ok=1",
]
for needle in required:
    if needle not in joined:
        raise SystemExit(f"required semantic observation missing: {needle}")
print(f"records={capture['records']} bytes={capture['bytes']} stdout_sha256={actual_hash}")
print("covered_projection=MATCH overall=MISMATCH raw_diff=empty")
PY

/usr/bin/sha256sum "${owned[@]}" >"$work/owned.after"
if ! /usr/bin/cmp -s "$work/owned.before" "$work/owned.after"; then
  echo "owned input drift detected during runner" >&2
  /usr/bin/diff -u "$work/owned.before" "$work/owned.after" >&2 || true
  exit 1
fi
