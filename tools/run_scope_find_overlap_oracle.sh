#!/usr/bin/env bash
# Immutable SCOPE-FINDOVERLAP-KEY-0001 / SCOPE-FINDOVERLAP-DYNAMIC-0001
# oracle runner (scope_find_overlap_1204).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, builds the Rudra crate from the pinned base commit plus the
# funcdata.rs overlay, compiles both fixtures, runs them, and requires
# byte-identical stdout.  The seven records cover the rangemap
# partition-owner semantics of ScopeInternal::findOverlap
# (database.cc:2392 + rangemap.hh:411-423):
#   - EntrySubsort(usepoint) tie-break inside one partition unit
#     (partition_usepoint / partition_usepoint_far),
#   - the minimal address-tied subsort winning a shared unit
#     (addrtied_wins),
#   - an uncovered query start resolved by the leftmost intersecting unit
#     (gap_query / gap_query_short),
#   - and dynamic-symbol invisibility (dynamic_null / dynamic_no_shadow,
#     database.cc:1866-1876).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/scope_find_overlap_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/scope_find_overlap_1204.cc"
rust_fixture="$repo_root/tests/oracle/scope_find_overlap_1204.rs"
funcdata_rs="$repo_root/src/funcdata.rs"
doc_funcdata="$repo_root/docs/api/funcdata.md"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
# 2026-08-30: the pre-reboot canonical system slot is preferred; after a
# reboot the hash-pinned blob from the /tmp oracle env extraction is
# accepted (identical f9ca64d0 content) so the gate cannot silently rot.
bfd_library=""
for bfd_candidate in \
  /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
  "$bfd_include/../lib/x86_64-linux-gnu/libbfd-2.38-system.so"; do
  if [[ -f "$bfd_candidate" && ! -L "$bfd_candidate" ]] && \
     [[ "$(sha256sum -- "$bfd_candidate" | cut -d' ' -f1)" == \
        f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e ]]; then
    bfd_library="$bfd_candidate"
    break
  fi
done
if [[ -z "$bfd_library" ]]; then
  echo "no libbfd-2.38-system.so matching f9ca64d0... in the known slots" >&2
  exit 1
fi

oracle_tmp=$(mktemp -d /tmp/rudra-scope-find-overlap-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-scope-find-overlap-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$funcdata_rs" "$doc_funcdata" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# Build the Rust comparand from an immutable repository snapshot with only
# the reviewed funcdata candidate overlaid, so concurrent worktree writers
# cannot enter the fixture's crate closure.
rudra_workspace="$oracle_tmp/rudra-workspace"
mkdir -p "$rudra_workspace"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  tests/oracle/infertypes_settle_1204.rs tests/oracle/varmap_dupdecl_1204.rs \
  tests/oracle/funcdata_nodesplit_space_1204.rs \
  | tar -x -C "$rudra_workspace"
cp "$funcdata_rs" "$rudra_workspace/src/funcdata.rs"
mkdir -p "$rudra_workspace/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$rudra_workspace/ghidra"
snapshot_cpp_root="$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$funcdata_rs" "$doc_funcdata" \
  "${BASH_SOURCE[0]}" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, source_path, docs_path, runner_path = map(
    pathlib.Path, sys.argv[1:7]
)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
oracle = metadata.get("oracle", {})
if oracle.get("tag") != "Ghidra_12.0.4_build" or \
        oracle.get("commit") != "e40ed13014025f82488b1f8f7bca566894ac376b":
    raise SystemExit("metadata oracle mismatch")
if not metadata.get("architecture") or not metadata.get("compiler_spec"):
    raise SystemExit("metadata architecture/compiler spec missing")
if not metadata.get("analysis_options"):
    raise SystemExit("metadata analysis options missing")
paths = {
    "cpp_fixture": cpp_path,
    "rust_fixture": rust_path,
    "rugra_funcdata_source": source_path,
    "api_document": docs_path,
    "runner": runner_path,
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand_sha256"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$snapshot_cpp_root" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$snapshot_cpp_root" \
  "$cpp_fixture" \
  "$snapshot_cpp_root/libdecomp.cc" \
  "$snapshot_cpp_root/sleigh_arch.cc" \
  "$snapshot_cpp_root/inject_sleigh.cc" \
  "$snapshot_cpp_root/bfd_arch.cc" \
  "$snapshot_cpp_root/loadimage_bfd.cc" \
  "$snapshot_cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/scope_find_overlap_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/scope_find_overlap_1204_rust"

LD_LIBRARY_PATH="$(dirname -- "$bfd_library")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$oracle_tmp/scope_find_overlap_1204_cpp" \
  "$repo_root/sleigh_specs" "$repo_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/scope_find_overlap_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

test -s "$oracle_tmp/ghidra.stdout"
test -s "$oracle_tmp/rudra.stdout"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 7
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 7

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
expected = metadata["expected_stdout_sha256"]
if hashlib.sha256(ghidra).hexdigest() != expected:
    raise SystemExit(
        f"oracle stdout hash mismatch: metadata={expected} "
        f"actual={hashlib.sha256(ghidra).hexdigest()}"
    )
if ghidra != rudra:
    ghidra_lines = ghidra.decode().splitlines()
    rudra_lines = rudra.decode().splitlines()
    for index, (left, right) in enumerate(zip(ghidra_lines, rudra_lines)):
        if left != right:
            raise SystemExit(
                f"record {index} differs:\n  ghidra: {left}\n  rudra:  {right}"
            )
    raise SystemExit("record counts differ")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'scope_find_overlap_1204: MATCH\n'
