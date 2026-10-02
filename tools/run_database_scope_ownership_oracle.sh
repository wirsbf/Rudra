#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Immutable runner for DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001.  The Ghidra
# oracle, Rugra source, binary/spec inputs, fixtures, toolchain, and BFD input
# closure are all pinned and checked before either comparand executes.
runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH="/usr/bin:/bin" /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_database_scope_ownership_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside expected repository path" >&2
  exit 1
fi
runner_snapshot_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
HOME=$user_home
export HOME

clean_path=/usr/bin:/bin
rust_toolchain=system-path
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_source_commit=2be910a2513a9a049eb8bad0bd0a7c13a566bd6a
rugra_source_tree=4810d810e0f1932537cd849a634ce51f19f067d9
rugra_source_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rugra_source_sleigh_shim_tree=c7729d9d1554dc62c486bcd7d58fdbf44bebb97d
rugra_source_arch_blob=cd3fd77747d6377e14f2e672956ddfbc9ff17877
rugra_source_database_blob=840e08ae133f285857b0b5ab2a19839976f96c0e
rugra_source_funcdata_blob=9800c38b1c1bb37d9c2c28841151e0ad2bf9c148
rugra_source_varmap_blob=af7630a51fb0912a494c87fbb34d2a8c513584d5
rugra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rugra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rugra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rugra_input_commit=34a3febff160031c265cfbd841a94022c68c2c19
rugra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
rugra_source_paths=(
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

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/database_scope_ownership_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/database_scope_ownership_1204.cc"
rust_fixture="$repo_root/tests/oracle/database_scope_ownership_1204.rs"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_flock_bin=$(/usr/bin/readlink -f /usr/bin/flock)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_flock_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
if [[ ! -d "$bfd_include" || -L "$bfd_include" ]]; then
  echo "BFD include closure is not a real non-symlink directory" >&2
  exit 1
fi

git_clean() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    "$host_git_bin" "$@"
}

actual_commit=$(git_clean -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git_clean -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra commit/tree/blob identity mismatch" >&2
  exit 1
fi
locked_dirty=$(git_clean -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  Ghidra/Processors/x86/data/languages)
if [[ -n "$locked_dirty" ]]; then
  echo "locked Ghidra cpp/language worktree is dirty" >&2
  echo "$locked_dirty" >&2
  exit 1
fi

for binding in \
  "$rugra_source_commit^{commit}|$rugra_source_commit" \
  "$rugra_source_commit^{tree}|$rugra_source_tree" \
  "$rugra_source_commit:src|$rugra_source_src_tree" \
  "$rugra_source_commit:sleigh_shim|$rugra_source_sleigh_shim_tree" \
  "$rugra_source_commit:src/arch.rs|$rugra_source_arch_blob" \
  "$rugra_source_commit:src/database.rs|$rugra_source_database_blob" \
  "$rugra_source_commit:src/funcdata.rs|$rugra_source_funcdata_blob" \
  "$rugra_source_commit:src/varmap.rs|$rugra_source_varmap_blob" \
  "$rugra_source_commit:Cargo.toml|$rugra_source_cargo_toml_blob" \
  "$rugra_source_commit:Cargo.lock|$rugra_source_cargo_lock_blob" \
  "$rugra_source_commit:build.rs|$rugra_source_build_rs_blob"; do
  expression=${binding%%|*}
  expected=${binding#*|}
  actual=$(git_clean -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rugra identity mismatch: $expression" >&2
    exit 1
  fi
done
input_commit=$(git_clean -C "$repo_root" rev-parse "$rugra_input_commit^{commit}")
input_blob=$(git_clean -C "$repo_root" rev-parse \
  "$rugra_input_commit:examples/curl")
input_size=$(git_clean -C "$repo_root" cat-file -s "$input_blob")
if [[ "$input_commit" != "$rugra_input_commit" || \
      "$input_blob" != "$rugra_input_blob" ]]; then
  echo "pinned input commit/blob identity mismatch" >&2
  exit 1
fi

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx_bin" -dumpmachine)
host_rustc=$(/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rugra-database-scope-ownership-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-database-scope-ownership-1204.??????)
      /usr/bin/rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot="$oracle_tmp/workspace"
mkdir -p "$snapshot" "$snapshot/tests/oracle" "$snapshot/tools" \
  "$snapshot/sleigh_specs" "$snapshot/examples" "$snapshot/external/include" \
  "$oracle_tmp/ghidra-source"
git_clean -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_source_commit" \
  "${rugra_source_paths[@]}"
/usr/bin/tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot"
git_clean -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$oracle_tmp/ghidra-source"
oracle_cpp="$oracle_tmp/ghidra-source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

cp "$metadata" "$snapshot/tests/oracle/database_scope_ownership_1204.metadata.json"
cp "$cpp_fixture" "$snapshot/tests/oracle/database_scope_ownership_1204.cc"
cp "$rust_fixture" "$snapshot/tests/oracle/database_scope_ownership_1204.rs"
cp "$runner_fd_path" "$snapshot/tools/run_database_scope_ownership_oracle.sh"
for asset in x86-64.sla x86-64.pspec x86-64-gcc.cspec x86.ldefs; do
  git_clean -C "$repo_root" cat-file blob \
    "$rugra_input_commit:sleigh_specs/$asset" >"$snapshot/sleigh_specs/$asset"
done
git_clean -C "$repo_root" cat-file blob "$rugra_input_blob" \
  >"$snapshot/examples/curl"
for header in "$bfd_include"/*; do
  if [[ ! -f "$header" || -L "$header" ]]; then
    echo "BFD include entry is not a regular non-symlink file: $header" >&2
    exit 1
  fi
  cp "$header" "$snapshot/external/include/"
done
cp "$bfd_library" "$snapshot/external/libbfd-2.38-system.so"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$repo_root" "$snapshot" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$runner_snapshot_sha" "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" \
  "$oracle_language_tree" "$oracle_makefile_blob" "$rugra_source_commit" \
  "$rugra_source_tree" "$rugra_source_src_tree" \
  "$rugra_source_sleigh_shim_tree" "$rugra_source_arch_blob" \
  "$rugra_source_database_blob" "$rugra_source_funcdata_blob" \
  "$rugra_source_varmap_blob" "$rugra_source_cargo_toml_blob" \
  "$rugra_source_cargo_lock_blob" "$rugra_source_build_rs_blob" \
  "$rugra_input_commit" "$rugra_input_blob" "$input_size" \
  "$host_cxx" "$host_cxx_target" "$host_rustc" "$host_cargo" \
  "$host_platform" "$host_cxx_bin" "$host_cargo_bin" "$host_rustc_bin" \
  "$host_cc_bin" "$host_ar_bin" "$host_make_bin" "$host_python_bin" \
  "$host_git_bin" "$host_flock_bin" "$rust_toolchain" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_tag, oracle_commit, cpp_tree, language_tree, makefile_blob,
    source_commit, source_tree, source_src_tree, source_shim_tree,
    source_arch_blob, source_database_blob, source_funcdata_blob,
    source_varmap_blob, source_cargo_toml_blob, source_cargo_lock_blob,
    source_build_blob, input_commit, input_blob, input_size, host_cxx,
    host_cxx_target, host_rustc, host_cargo, host_platform, host_cxx_bin,
    host_cargo_bin, host_rustc_bin, host_cc_bin, host_ar_bin,
    host_make_bin, host_python_bin, host_git_bin, host_flock_bin,
    rust_toolchain,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def regular(path):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"expected regular non-symlink file: {path}")
    return path.read_bytes()

require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "DATABASE-SCOPE-OWNERSHIP-1204")
require("todo ids", metadata["todo_ids"], ["DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001"])
require("overall", metadata["overall_status"], "MISMATCH")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler", metadata["compiler_spec"]["id"], "gcc")

find_create = metadata["coverage"]["find_create_scope_projection"]
require("find-create projection", find_create["status"], "MISMATCH")
require("find-create full", find_create["full"]["status"], "MISMATCH")
require("find-create selected", find_create["selected"]["status"], "MATCH")
require(
    "find-create selected fields",
    find_create["selected"]["fields"],
    [
        "id_matches", "resolver_key_present", "repeat_key_same",
        "name_preserved", "parent_id", "parent_child_key_resolves",
        "parent_child_count",
    ],
)
require(
    "find-create multi-child order",
    find_create["multi_child_order"]["status"],
    "UNTESTED",
)
require(
    "find-create residual ids",
    find_create["residual_todo_ids"],
    ["DATABASE-0001", "DB-LOCALSCOPE-MAP-0001"],
)
require(
    "find-create multi-child residual ids",
    find_create["multi_child_order"]["residual_todo_ids"],
    ["DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001", "DB-LOCALSCOPE-MAP-0001"],
)

source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["commit"], source_commit),
    ("source tree", source["tree"], source_tree),
    ("source src tree", source["src_tree"], source_src_tree),
    ("source shim tree", source["sleigh_shim_tree"], source_shim_tree),
    ("source arch", source["arch_blob"], source_arch_blob),
    ("source database", source["database_blob"], source_database_blob),
    ("source funcdata", source["funcdata_blob"], source_funcdata_blob),
    ("source varmap", source["varmap_blob"], source_varmap_blob),
    ("source Cargo.toml", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("source Cargo.lock", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("source build.rs", source["build_rs_blob"], source_build_blob),
):
    require(label, actual, expected)

fixture_bytes = regular(pathlib.Path(cpp_raw))
rust_bytes = regular(pathlib.Path(rust_raw))
runner_bytes = regular(repo / "tools/run_database_scope_ownership_oracle.sh")
comparand = metadata["comparand"]
require("C++ fixture", comparand["cpp_fixture_sha256"], sha(fixture_bytes))
require("Rust fixture", comparand["rust_fixture_sha256"], sha(rust_bytes))
require("runner", comparand["runner_sha256"], runner_sha)
require("runner fd/live", sha(runner_bytes), runner_sha)

asset_files = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
    "binary": "examples/curl",
}
for key, relative in asset_files.items():
    data = regular(snapshot / relative)
    record = metadata["assets"][key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} sha", record["sha256"], sha(data))
    require(f"{key} size", record["size"], len(data))
require("binary commit", metadata["assets"]["binary"]["source_repository_commit"], input_commit)
require("binary blob", metadata["assets"]["binary"]["git_blob_oid"], input_blob)
require("binary Git size", metadata["assets"]["binary"]["size"], int(input_size))

bfd_hasher = hashlib.sha256()
bfd_hasher.update(b"bfd-include-tree-v1\0")
header_count = 0
for path in sorted((snapshot / "external/include").iterdir(), key=lambda item: item.name):
    data = regular(path)
    name = path.name.encode("utf-8")
    bfd_hasher.update(len(name).to_bytes(8, "big"))
    bfd_hasher.update(name)
    bfd_hasher.update(len(data).to_bytes(8, "big"))
    bfd_hasher.update(data)
    header_count += 1
bfd = metadata["assets"]["bfd"]
require("BFD header count", bfd["include_file_count"], header_count)
require("BFD include tree", bfd["include_tree_sha256"], bfd_hasher.hexdigest())
require("BFD bfd.h", bfd["header_sha256"], sha(regular(snapshot / "external/include/bfd.h")))
require(
    "BFD library",
    bfd["library_sha256"],
    sha(regular(snapshot / "external/libbfd-2.38-system.so")),
)

host = metadata["host"]
for label, actual, expected in (
    ("host cxx", host["cxx"], host_cxx),
    ("host cxx target", host["cxx_target"], host_cxx_target),
    ("host rustc", host["rustc"], host_rustc),
    ("host cargo", host["cargo"], host_cargo),
    ("host platform", host["platform"], host_platform),
    ("host cxx path", host["cxx_path"], host_cxx_bin),
    ("host cargo path", host["cargo_path"], host_cargo_bin),
    ("host rustc path", host["rustc_path"], host_rustc_bin),
    ("host cc path", host["cc_path"], host_cc_bin),
    ("host ar path", host["ar_path"], host_ar_bin),
    ("host make path", host["make_path"], host_make_bin),
    ("host python path", host["python_path"], host_python_bin),
    ("host git path", host["git_path"], host_git_bin),
    ("host flock path", host["flock_path"], host_flock_bin),
    ("host toolchain", host["rust_toolchain"], rust_toolchain),
):
    require(label, actual, expected)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input fingerprint", manifest["sha256"], sha(canonical))

decisive = metadata["decisive_semantics"]
require(
    "decisive semantic classes",
    set(decisive),
    {
        "reference_output_parameters", "loop_bounds_traversal_order",
        "counter_accumulator_lifecycle", "sorting_comparison_keys",
    },
)
for key, value in decisive.items():
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"decisive_semantics.{key} must be non-empty")
PY

jobs=${RUDRA_DB_SCOPE_GHIDRA_JOBS:-4}
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_make_bin" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx_bin -std=c++11" EXTRA= libdecomp.a \
  >"$oracle_tmp/make.stdout" 2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" >&2
  /usr/bin/cat "$oracle_tmp/make.stderr" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$snapshot/external/include" -I"$oracle_cpp" \
  "$snapshot/tests/oracle/database_scope_ownership_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$snapshot/external/libbfd-2.38-system.so" -lz \
  -Wl,-rpath,"$snapshot/external" \
  -o "$oracle_tmp/database_scope_ownership_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

fixture_target=${RUDRA_DB_SCOPE_TARGET_DIR:-/tmp/rugra-target-db-scope-fixture}
mkdir -p "$fixture_target"
if ! (
  cd "$snapshot"
  "$host_flock_bin" /tmp/rugra-cargo-build.lock \
  /usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$HOME/.cargo" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true CXX="$host_cxx_bin" CC="$host_cc_bin" \
    AR="$host_ar_bin" RUSTC="$host_rustc_bin" \
    "$host_cargo_bin" build --quiet --locked --offline --lib \
      --manifest-path "$snapshot/Cargo.toml"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  /usr/bin/cat "$oracle_tmp/cargo.stdout" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rugra_rlib="$fixture_target/debug/librugra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" -path '*/out/librugra_sleigh.a' \
    -type f | /usr/bin/sort
)
if [[ ! -f "$rugra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "Cargo build did not produce exactly one Rugra rlib/native archive" >&2
  printf '%s\n' "${native_archives[@]}" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
if ! /usr/bin/env -i HOME="$HOME" PATH="$clean_path" LC_ALL=C.UTF-8 \
  "$host_rustc_bin" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rugra=$rugra_rlib" -l static=rugra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/database_scope_ownership_1204.rs" \
  -o "$oracle_tmp/database_scope_ownership_1204_rust" \
  >"$oracle_tmp/rustc.stdout" 2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" >&2
  /usr/bin/cat "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi

ghidra_status=0
LD_LIBRARY_PATH="$snapshot/external" \
  "$oracle_tmp/database_scope_ownership_1204_cpp" \
  "$snapshot/sleigh_specs" "$snapshot/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr" || ghidra_status=$?
rugra_status=0
"$oracle_tmp/database_scope_ownership_1204_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr" || rugra_status=$?
diff_status=0
/usr/bin/diff -u --label ghidra-12.0.4 --label rugra-pinned \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/ownership.diff" || diff_status=$?
if [[ "$ghidra_status" -ne 0 || "$rugra_status" -ne 0 || "$diff_status" -ne 1 ]]; then
  echo "unexpected comparand exit: ghidra=$ghidra_status rugra=$rugra_status diff=$diff_status" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$snapshot/tests/oracle/database_scope_ownership_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rugra.stdout" "$oracle_tmp/rugra.stderr" \
  "$oracle_tmp/ownership.diff" "$ghidra_status" "$rugra_status" \
  "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rugra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rugra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

find_create = metadata["coverage"]["find_create_scope_projection"]
require("find-create projection", find_create["status"], "MISMATCH")
require("find-create full", find_create["full"]["status"], "MISMATCH")
require("find-create selected", find_create["selected"]["status"], "MATCH")
require(
    "find-create selected fields",
    find_create["selected"]["fields"],
    [
        "id_matches", "resolver_key_present", "repeat_key_same",
        "name_preserved", "parent_id", "parent_child_key_resolves",
        "parent_child_count",
    ],
)
require(
    "find-create multi-child order",
    find_create["multi_child_order"]["status"],
    "UNTESTED",
)
require(
    "find-create residual ids",
    find_create["residual_todo_ids"],
    ["DATABASE-0001", "DB-LOCALSCOPE-MAP-0001"],
)
require(
    "find-create multi-child residual ids",
    find_create["multi_child_order"]["residual_todo_ids"],
    ["DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001", "DB-LOCALSCOPE-MAP-0001"],
)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

expected = metadata["expected_results"]
hash_drifts = []
for key, path in paths.items():
    actual = sha(path)
    if expected[key] != actual:
        hash_drifts.append(f"{key}={actual}")
if hash_drifts:
    raise SystemExit("registered output hashes drifted: " + " ".join(hash_drifts))
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[7])),
    ("rugra_exit_code", int(sys.argv[8])),
    ("diff_exit_code", int(sys.argv[9])),
):
    if expected[key] != actual:
        raise SystemExit(f"registered {key} drifted: {actual}")

def records(path):
    parsed = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        fields = raw.split("|")
        record = {}
        for field in fields:
            key, value = field.split("=", 1)
            record[key] = value
        parsed.append(record)
    return parsed

ghidra = records(paths["ghidra_stdout_sha256"])
rugra = records(paths["rugra_stdout_sha256"])
if len(ghidra) != expected["ghidra_record_count"]:
    raise SystemExit("Ghidra record count drifted")
if len(rugra) != expected["rugra_record_count"]:
    raise SystemExit("Rugra record count drifted")
if [record["case"] for record in ghidra] != expected["ghidra_case_order"]:
    raise SystemExit("Ghidra case order drifted")
if [record["case"] for record in rugra] != expected["rugra_case_order"]:
    raise SystemExit("Rugra case order drifted")

by_case = {record["case"]: record for record in ghidra}
for key in (
    "result_global_alias", "database_arch_alias", "global_arch_alias",
    "global_name_empty", "global_parent_null", "global_is_global",
):
    if by_case["build_database"][key] != "1":
        raise SystemExit(f"build_database.{key} is not true")
for side, case in (
    ("Ghidra", by_case["find_create_scope"]),
    ("Rugra", {record["case"]: record for record in rugra}["find_create_scope"]),
):
    for key in (
        "id_matches", "resolver_key_present", "repeat_key_same",
        "name_preserved", "parent_child_key_resolves",
    ):
        if case[key] != "1":
            raise SystemExit(f"{side} find_create_scope.{key} is not true")
    if case["parent_id"] != "0":
        raise SystemExit(f"{side} find_create_scope.parent_id is not global")
    if case["parent_child_count"] != "1":
        raise SystemExit(f"{side} find_create_scope.parent_child_count drifted")
ghidra_find = by_case["find_create_scope"]
rugra_find = {record["case"]: record for record in rugra}["find_create_scope"]
for key, expected_value in (
    ("return_class", "pointer"),
    ("resolver_return_alias", "1"),
    ("repeat_return_alias", "1"),
    ("parent_child_return_alias", "1"),
    ("resolved_slot_stable", "UNNEEDED"),
    ("parent_child_resolved_slot_alias", "UNNEEDED"),
    ("scope_storage_class", "pointer"),
    ("parent_child_storage_class", "pointer"),
    ("next_scope_id_before", "UNAVAILABLE"),
    ("next_scope_id_after_create", "UNAVAILABLE"),
    ("next_scope_id_after_repeat", "UNAVAILABLE"),
):
    if ghidra_find[key] != expected_value:
        raise SystemExit(f"Ghidra find_create_scope.{key} drifted")
for key, expected_value in (
    ("return_class", "value"),
    ("resolver_return_alias", "UNAVAILABLE"),
    ("repeat_return_alias", "UNAVAILABLE"),
    ("parent_child_return_alias", "UNAVAILABLE"),
    ("resolved_slot_stable", "1"),
    ("parent_child_resolved_slot_alias", "1"),
    ("scope_storage_class", "value"),
    ("parent_child_storage_class", "value"),
    ("next_scope_id_before", "1"),
    ("next_scope_id_after_create", "302252035"),
    ("next_scope_id_after_repeat", "302252035"),
):
    if rugra_find[key] != expected_value:
        raise SystemExit(f"Rugra find_create_scope.{key} drifted")
for key in (
    "symbol_scope_alias", "function_cached_alias", "function_symbol_backref",
    "function_arch_alias", "local_resolver_alias", "local_parent_alias",
    "local_arch_alias", "local_name_matches",
):
    if by_case["function_graph"][key] != "1":
        raise SystemExit(f"function_graph.{key} is not true")
if by_case["function_graph"]["local_backref_class"] != "function":
    raise SystemExit("ScopeLocal did not expose its Funcdata backref class")
duplicate = by_case["duplicate_id"]
if duplicate["exception"] != "RecovError" or duplicate["message"] != "Duplicate scope id: ":
    raise SystemExit("duplicate-id exception contract drifted")
if duplicate["incoming_events"] != "dtor:duplicate_scope":
    raise SystemExit("duplicate-id incoming ownership contract drifted")
invalid = by_case["invalid_global_name"]
if invalid["exception"] != "LowlevelError" or invalid["message"] != "Global scope does not have empty name":
    raise SystemExit("invalid-global exception contract drifted")
if invalid["events_before_caller_delete"] != "none" or invalid["events_after_caller_delete"] != "dtor:invalid_global":
    raise SystemExit("invalid-global caller ownership contract drifted")
destroy = by_case["function_destroy"]
for key in ("local_resolver_gone", "local_child_gone", "function_mapping_gone"):
    if destroy[key] != "1":
        raise SystemExit(f"function_destroy.{key} is not true")
if by_case["architecture_destroy"]["events"] != "dtor:exit_ns>dtor:sentinel:local_present=0":
    raise SystemExit("architecture destructor order drifted")

rugra_by_case = {record["case"]: record for record in rugra}
constructor = rugra_by_case["rugra_constructor_state"]
if any(constructor[key] != "0" for key in (
    "architecture_symboltab_present", "funcdata_arch_present",
    "funcdata_local_scope_present",
)):
    raise SystemExit("Rugra missing-capability constructor prestate drifted")
missing = rugra_by_case["missing_capability"]
if "explicit_scope_id_attach" in missing:
    raise SystemExit("find_create_scope exists; explicit-id attach must not be reported missing")
for key in (
    "caller_owned_scope_identity_attach",
    "caller_owned_scope_failure_contract",
):
    if missing.get(key) != "missing":
        raise SystemExit(f"Rugra missing capability {key} drifted")
if rugra_by_case["overall"]["status"] != "MISMATCH":
    raise SystemExit("Rugra overall status must remain MISMATCH")
if paths["ghidra_stderr_sha256"].read_bytes() or paths["rugra_stderr_sha256"].read_bytes():
    raise SystemExit("comparand stderr must remain empty")
PY

/usr/bin/cat "$oracle_tmp/ghidra.stdout"
/usr/bin/cat "$oracle_tmp/rugra.stdout"
/usr/bin/cat "$oracle_tmp/ownership.diff"
echo "database_scope_ownership_1204: covered_oracle=MATCH rugra_capability=MISMATCH overall=MISMATCH"
