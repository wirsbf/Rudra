#!/usr/bin/env bash
# Draft build script for tests/oracle/stage_drill_1204.cc: an ISOLATED
# -DOPACTION_DEBUG build of the locked Ghidra 12.0.4 oracle tree.
#
# Why isolated (DRILL_DESIGN.md section 2): the shared checkout's
# libdecomp.a objects (com_opt/*.o) are cached without the define; a flag
# flip in place would silently mix stale and fresh objects.  We therefore
# git-archive the locked oracle commit into a scratch dir (same technique as
# tools/regen_ghidra_golden.py) and build there.  The shared ghidra checkout
# is never written to.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
fixture="$repo_root/tests/oracle/stage_drill_1204.cc"
workroot=${RUDRA_DRILL_WORKROOT:-/dev/shm/rudra-tests/sb-drill/build}
mkdir -p "$workroot"

# BFD for the BfdArchitecture loader (binutils 2.38).
bfd_include=${RUDRA_BFD_INCLUDE:-/tmp/rudra-ghidra-bfd-2.38/usr/include}
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_include/bfd.h" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD not found (include=$bfd_include lib=$bfd_library)" >&2
  exit 1
fi

# Fresh git-archive of the locked oracle commit; a stamp file guards reuse
# (a workroot archived from a different commit is wiped and re-extracted).
cpp_root="$workroot/locked-cpp"
stamp="$workroot/locked-cpp.commit"
if [[ -f "$stamp" && "$(cat "$stamp")" == "$oracle_commit" && -d "$cpp_root" ]]; then
  : # reusable
else
  rm -rf -- "$cpp_root" "$stamp"
  archive="$workroot/locked-cpp.tar"
  git -C "$ghidra_root" archive --format=tar --output="$archive" "$oracle_commit" \
    Ghidra/Features/Decompiler/src/decompile/cpp
  mkdir -p "$cpp_root"
  tar -xf "$archive" -C "$cpp_root"
  rm -f "$archive"
  printf '%s\n' "$oracle_commit" > "$stamp"
fi
cpp_root="$cpp_root/Ghidra/Features/Decompiler/src/decompile/cpp"
[[ -f "$cpp_root/libdecomp.hh" ]] || { echo "archive layout unexpected" >&2; exit 1; }

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
# ADDITIONAL_FLAGS is the Makefile's own extension point (Makefile:6);
# OPACTION_DEBUG must cover every library object, so a clean dedicated
# object tree is required (objects are cached without the define).
make --silent -C "$cpp_root" -j "$jobs" EXTRA= \
  ADDITIONAL_FLAGS="-DOPACTION_DEBUG" libdecomp.a

g++ -std=c++11 -O2 -DOPACTION_DEBUG \
  -I"$bfd_include" -I"$cpp_root" \
  "$fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$workroot/stage_drill_1204"

echo "built $workroot/stage_drill_1204 (OPACTION_DEBUG oracle drill)" >&2
