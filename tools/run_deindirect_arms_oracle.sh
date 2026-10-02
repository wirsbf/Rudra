#!/usr/bin/env bash
set -euo pipefail

# FSPEC-DEINDIRECT-TRIGGER-0001 bilateral oracle runner (deindirect_arms_1204):
# ActionDeindirect::apply's three conversion arms (coreaction.cc:1219-1280)
# and the FuncCallSpecs conversions they drive (fspec.cc:5443-5472 deindirect
# / fspec.cc:5485-5509 forceSet) — constant arm with funcptr_align strip,
# COPY-chain walk, isOverride early return, external-reference arm,
# typed-funcptr forceSet arm.
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive (adding two read-only fixture accessors: Funcdata::
# fixtureAddToCallList over the private qlst, Varnode::fixtureSetExternRef
# over the protected setFlags), builds the Rugra crate from the working
# tree, compiles both fixtures, runs them, and diffs stdout.
#
# Known production-channel residuals (documented MISMATCH coverage on the
# ticket, not silent): the Rust extref case cannot resolve the ExternRef
# referral (Scope-side refaddr storage, CALLSPEC-0001 seam) and the Rust
# norestart_gate case cannot see the per-callee noreturn bit (flow-time
# callee-proto channel only). Both cases still print so the diff pins the
# exact gap.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
cpp_fixture="$repo_root/tests/oracle/deindirect_arms_1204.cc"
rust_fixture="$repo_root/tests/oracle/deindirect_arms_1204.rs"
runner="$repo_root/tools/run_deindirect_arms_oracle.sh"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
cargo_target=${RUDRA_DEINDIRECT_TARGET_DIR:-/dev/shm/rugra-targets/fspecdein-fixture}
cargo_tmp=${RUDRA_DEINDIRECT_TMP_DIR:-/dev/shm/rugra-tests/fspecdein/fixture-tmp}
mkdir -p "$cargo_target" "$cargo_tmp"

oracle_tmp=$(mktemp -d /tmp/rugra-deindirect-arms-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-deindirect-arms-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$cpp_fixture" "$rust_fixture" "$runner" "$bfd_header" "$bfd_library"; do
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

# Read-only instrumentation (lives only inside the throwaway archive):
#  - expose the private qlst push so the fixture can install callspecs
#    (production writers run during FlowInfo, which the fixture replaces
#    with direct construction);
#  - expose a persist|externref pin over the protected setFlags for the
#    external-reference arm's input varnode (production sets the pair via
#    the symbol mapping layer).
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
vpath = root / "varnode.hh"
vtext = vpath.read_text()
vold = "  bool isExternalRef(void) const { return ((flags&Varnode::externref)!=0); } ///< Is \\b this storage location mapped by the loader to an external location?"
vnew = vold + "\n  void fixtureSetExternRef(void) { setFlags(Varnode::externref | Varnode::persist); } ///< fixture-only externref pin"
if vtext.count(vold) != 1:
    raise SystemExit("instrumentation anchor count drifted: varnode.hh isExternalRef")
vpath.write_text(vtext.replace(vold, vnew))
PY

# The Rust fixture builds against the working tree (this branch carries the
# src changes under test); the C++ side is the immutable oracle.
snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root"
cp -r "$repo_root/src" "$snapshot_root/src"
cp -r "$repo_root/crates" "$snapshot_root/crates"
cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$repo_root/build.rs" "$snapshot_root/" 2>/dev/null || true
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" "$snapshot_root/sleigh_shim" "$snapshot_root/examples" "$snapshot_root/benches"
cp "$repo_root/benches/decompile_bench.rs" "$snapshot_root/benches/" 2>/dev/null || true
cp -r "$repo_root/sleigh_shim/." "$snapshot_root/sleigh_shim/" 2>/dev/null || true
cp "$cpp_fixture" "$snapshot_root/tests/oracle/deindirect_arms_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/deindirect_arms_1204.rs"
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
  "$snapshot_root/tests/oracle/deindirect_arms_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/deindirect_arms_cpp"

env -i PATH="$PATH" HOME="$HOME" LC_ALL=C \
  flock -x /tmp/rugra-cargo-build.lock \
  env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" \
  timeout 600 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
env -i PATH="$PATH" TMPDIR="$cargo_tmp" \
  rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/deindirect_arms_1204.rs" \
  --extern rugra="$cargo_target/debug/librugra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$oracle_tmp/deindirect_arms_rust"

set +e
"$oracle_tmp/deindirect_arms_cpp" sleigh_specs "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/deindirect_arms_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
set -e

echo "== ghidra stdout =="
cat "$oracle_tmp/ghidra.stdout"
echo "== ghidra stderr =="
cat "$oracle_tmp/ghidra.stderr"
echo "== rugra stdout =="
cat "$oracle_tmp/rugra.stdout"
echo "== rugra stderr =="
cat "$oracle_tmp/rugra.stderr"
echo "== exit codes: ghidra=$ghidra_status rust=$rugra_status"

if [[ "$ghidra_status" -ne 0 || "$rugra_status" -ne 0 ]]; then
  echo "fixture process failed" >&2
  exit 1
fi

diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" || {
    echo "bilateral diff (see above): known residuals = extref refaddr channel," \
         "norestart_gate per-callee noreturn channel — full parity otherwise" >&2
    exit 3
  }
echo "deindirect_arms_1204: bilateral stdout identical"
