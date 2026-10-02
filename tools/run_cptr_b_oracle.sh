#!/usr/bin/env bash
set -euo pipefail

# Immutable B3-COREACTION-CONSTANTPTR-0001 (b) bilateral oracle runner
# (cptr_b_1204): ActionConstantPtr::apply — the constant-space iteration,
# selectInferSpace, isPointer's op/range/bit-form/container gates and the
# spacebaseConstant PTRSUB/INT_ADD rewrite chain (coreaction.cc:957-1217,
# funcdata.cc:360-462).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive (adding one read-only fixture accessor: Funcdata::
# fixtureAddToCallList over the private qlst), builds the Rudra crate from
# the working tree, compiles both fixtures, runs them, and requires
# byte-identical stdout. The 23 records cover:
#   - w_7180/w_99a8/w_c1d8: the invalid-UTF-8 hugehelp alias shapes —
#     undefined1 DAT entries, exact hits -> PTRSUB with pointer-to-undefined
#     output (the `&DAT_*` chain of coreaction.cc:1210).
#   - w_ea40/w_11270/w_13ad0: the string-typed alias shapes — char-array
#     entries -> PTRSUB with pointer-to-char output (ruleaction.cc:7366-
#     7369's charPrint input).
#   - needexact_mid: the cc:1161-1162 rejection with the post-search
#     setPtrCheck (cc:1208); chararray_mid: the cc:1153-1159 middle
#     exception + the extra!=0 COPY->INT_ADD(PTRSUB,extra) reuse chain
#     (funcdata.cc:382/421-433).
#   - bounds_low (cc:1138) / bitform (cc:1143) rejections.
#   - zero_const (cc:1188) / ptrsub_in (cc:1203) / intadd_spacebase
#     (cc:1201) skips — none set PtrCheck.
#   - call_locked_ptr / call_locked_notptr / call_no_spec: the cc:1093-1101
#     CALL arms (locked char* accepts, locked int rejects, no-spec needs
#     infer_pointers).
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/cptr_b_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/cptr_b_1204.cc"
rust_fixture="$repo_root/tests/oracle/cptr_b_1204.rs"
doc_coreaction="$repo_root/docs/api/coreaction.md"
runner="$repo_root/tools/run_cptr_b_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(dirname "$bfd_library")
# Task-dedicated Cargo dirs: every Cargo invocation below is serialized on
# the shared build flock and uses these isolated, pre-created directories.
cargo_target=/home/wirs/.cache/b3-cptrb-fixture-target
cargo_tmp=/home/wirs/.cache/b3-cptrb-fixture-tmp
mkdir -p "$cargo_target" "$cargo_tmp"

oracle_tmp=$(mktemp -d /tmp/rudra-cptr-b-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-cptr-b-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$doc_coreaction" "$runner" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

# The single read-only instrumentation: expose the private qlst push so the
# fixture can install its locked callspecs (Ghidra's production writers run
# during FlowInfo::queryCall, which the fixture replaces with direct
# construction). Production sources in the repository are never modified —
# the patch lives only inside this throwaway archive.
python3 -I -S - "$oracle_cpp" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
path = root / "funcdata.hh"
text = path.read_text()
old = "  int4 numCalls(void) const { return qlst.size(); }\t///< Get the number of calls made by \\b this function"
new = old + "\n  void fixtureAddToCallList(FuncCallSpecs *fc) { qlst.push_back(fc); } ///< fixture-only qlst install"
if text.count(old) != 1:
    raise SystemExit("instrumentation anchor count drifted: funcdata.hh numCalls")
path.write_text(text.replace(old, new))
# varnode.hh: Varnode::setFlags is protected; expose the spacebase bit for
# the fixture's manually built RSP varnode (production sets it via
# Funcdata::spacebase / heritage).
vpath = root / "varnode.hh"
vtext = vpath.read_text()
vold = "  bool isSpacebase(void) const { return ((flags&Varnode::spacebase)!=0); } ///< Is this location used to store the base point for a virtual address space?"
vnew = vold + "\n  void fixtureSetSpacebase(void) { setFlags(Varnode::spacebase); } ///< fixture-only spacebase pin"
if vtext.count(vold) != 1:
    raise SystemExit("instrumentation anchor count drifted: varnode.hh setUnaffected")
vpath.write_text(vtext.replace(vold, vnew))
PY

# The Rust fixture builds against the working tree (this branch carries the
# segment-b src changes under test); the C++ side is the immutable oracle.
snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root"
cp -r "$repo_root/src" "$snapshot_root/src"
cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$repo_root/build.rs" "$snapshot_root/" 2>/dev/null || true
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" "$snapshot_root/sleigh_shim" "$snapshot_root/examples" "$snapshot_root/benches"
cp "$repo_root/benches/decompile_bench.rs" "$snapshot_root/benches/" 2>/dev/null || true
cp -r "$repo_root/sleigh_shim/." "$snapshot_root/sleigh_shim/" 2>/dev/null || true
cp "$cpp_fixture" "$snapshot_root/tests/oracle/cptr_b_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/cptr_b_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/cptr_b_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_cptr_b_oracle.sh"
git -C "$repo_root" cat-file blob "HEAD:examples/curl" >"$snapshot_root/examples/curl"
# build.rs requires the locked Ghidra SLEIGH tree at the conventional
# workspace-relative path (worktree symlink convention): link the oracle
# archive's cpp tree in.
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  mkdir -p "$snapshot_root/$(dirname "$asset")"
  cp "$repo_root/$asset" "$snapshot_root/$asset"
done

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/cptr_b_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/cptr_b_1204_cpp"

env -i PATH=/usr/bin:/bin HOME="$HOME" LC_ALL=C \
  flock -x /tmp/rudra-cargo-build.lock \
  env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" \
  timeout 600 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
env -i PATH=/usr/bin:/bin TMPDIR="$cargo_tmp" \
  rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/cptr_b_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$oracle_tmp/cptr_b_1204_rust"

set +e
env -i PATH=/usr/bin:/bin LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
  "$oracle_tmp/cptr_b_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
env -i PATH=/usr/bin:/bin LC_ALL=C \
  "$oracle_tmp/cptr_b_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
rudra = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
stderr = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
ghidra_status, rudra_status, diff_status = (int(v) for v in sys.argv[5:8])
if ghidra_status != 0:
    raise SystemExit(f"locked Ghidra fixture exited {ghidra_status}")
if rudra_status != 0:
    raise SystemExit(f"Rudra fixture exited {rudra_status} (stderr: {stderr[:400]})")
if diff_status != 0:
    raise SystemExit("bilateral stdout mismatch")
records = ghidra.splitlines()
expected_order = [
    "setup",
    "w_7180", "w_99a8", "w_c1d8", "w_ea40", "w_11270", "w_13ad0",
    "needexact_mid", "chararray_mid", "bounds_low", "bitform",
    "zero_const", "ptrsub_in", "intadd_spacebase",
    "call_locked_ptr", "call_locked_notptr", "call_no_spec",
]
observed = [r.split("|", 1)[0][len("case="):] for r in records]
if observed != expected_order:
    raise SystemExit(f"observation order mismatch: {observed}")
if len(records) != metadata["expected_results"]["record_count"]:
    raise SystemExit("record count mismatch")
if stderr:
    raise SystemExit("Rust fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'cptr_b_1204: bilateral_projection=MATCH overall_status=MATCH records=%s residuals=PRINTC-PTRCHAR-CONSTANT-0001 (string_literal_fold_chain fixture coverage; E2E fold evidence delivered by MAINDIFF-STRCONST-0001)\n' \
  "$(wc -l <"$oracle_tmp/ghidra.stdout")"
