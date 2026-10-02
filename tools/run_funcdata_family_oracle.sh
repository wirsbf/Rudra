#!/usr/bin/env bash
# MIGW1-FUNCDATA-0004 bilateral oracle runner — the Funcdata maintenance /
# query / mutation / print / debug families (funcdata_*.cc fixtures).
#
# usage: tools/run_funcdata_family_oracle.sh <fixture-name>
#   fixture-name: one of
#     funcdata_fwd_query_1204    — query/iterator face (beginLoc/endLoc,
#                                  beginDef/endDef, find*, startCleanUp, ...)
#     funcdata_fwd_mutate_1204  — mutation forwarder face (markReturnCopy,
#                                  opDeadInsertAfter, opDeadAndGone, ...)
#     funcdata_print_family_1204 — printRaw/printVarnodeTree/printLocalRange
#     funcdata_dbg_family_1204   — OPACTION_DEBUG observation face (built
#                                  against a -DOPACTION_DEBUG oracle; the
#                                  Rust debug members are always compiled and
#                                  gated on opactdbg_on)
#
# Rebuilds the locked Ghidra 12.0.4 decompiler (oracle commit pinned below,
# identity-verified against the ghidra/ checkout), builds the Rudra crate
# from the working tree, compiles both fixture sides, runs them, and
# requires byte-identical stdout. The oracle library build is cached per
# (source tree, build flags) under the XDG cache dir and reused across
# fixtures; the identity check re-runs on every invocation so a moved or
# repinned oracle can never silently reuse a stale cache.
#
# Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b
# (the sole source oracle of AGENTS.md).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"

name=${1:-}
case "$name" in
  funcdata_fwd_query_1204|funcdata_fwd_mutate_1204|funcdata_print_family_1204)
    extra_cxxflags=""
    ;;
  funcdata_dbg_family_1204)
    # The whole debug family lives under the OPACTION_DEBUG ifdef
    # (funcdata.hh:580-612, funcdata.cc:1007-1118).
    extra_cxxflags="-DOPACTION_DEBUG"
    ;;
  *)
    echo "usage: $0 <funcdata_{fwd_query,fwd_mutate,print_family,dbg_family}_1204>" >&2
    exit 2
    ;;
esac

cpp_fixture="$repo_root/tests/oracle/${name}.cc"
rust_fixture="$repo_root/tests/oracle/${name}.rs"
for required in "$cpp_fixture" "$rust_fixture"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

# --- oracle identity (same four-point pin as the sibling runners) ---------
actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle identity mismatch (HEAD=$actual_commit)" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# --- work + cache dirs ----------------------------------------------------
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/rudra-funcdata-family-oracle"
work=$(mktemp -d "${TMPDIR:-/tmp}/rudra-funcdata-family.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/rudra-funcdata-family.??????) rm -rf -- "$work" ;;
    *) echo "refusing unsafe cleanup target: $work" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

oracle_cache="$cache_root/oracle-cpp-${actual_cpp_tree}"
[[ -n "$extra_cxxflags" ]] && oracle_cache="$oracle_cache-dbg"
mkdir -p "$oracle_cache" "$cache_root/target"

if [[ ! -f "$oracle_cache/libdecomp.a" ]]; then
  rm -rf "$oracle_cache/source"
  mkdir -p "$oracle_cache/source" "$work/extract"
  git -C "$ghidra_root" archive --format=tar \
    --output="$work/ghidra-cpp.tar" "$oracle_commit" \
    Ghidra/Features/Decompiler/src/decompile/cpp
  tar -xf "$work/ghidra-cpp.tar" -C "$work/extract"
  mv "$work/extract/Ghidra/Features/Decompiler/src/decompile/cpp"/* \
     "$oracle_cache/source/"
  make -C "$oracle_cache/source" -j"$(nproc)" \
    CXX="/usr/bin/g++ -std=c++11 $extra_cxxflags" EXTRA= libdecomp.a
fi

# --- fixture cpp side ------------------------------------------------------
g++ -std=c++11 $extra_cxxflags -O1 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cache/source" \
  "$cpp_fixture" "$oracle_cache/source/libdecomp.cc" \
  "$oracle_cache/source/sleigh_arch.cc" \
  "$oracle_cache/source/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cache/source/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$work/${name}_cpp"

# --- fixture rust side -----------------------------------------------------
CARGO_TARGET_DIR="$cache_root/target" cargo build --quiet --lib \
  --manifest-path "$repo_root/Cargo.toml"
rustc --edition=2021 -O "$rust_fixture" \
  --extern "rudra=$cache_root/target/debug/librudra.rlib" \
  -L "dependency=$cache_root/target/debug/deps" \
  -o "$work/${name}_rust"

# --- run + byte compare ----------------------------------------------------
"$work/${name}_cpp" > "$work/${name}.ghidra.out" 2> "$work/${name}.ghidra.err" \
  || echo "cpp exit $?" >> "$work/${name}.ghidra.err"
"$work/${name}_rust" > "$work/${name}.rudra.out" 2> "$work/${name}.rudra.err" \
  || echo "rust exit $?" >> "$work/${name}.rudra.err"

if diff -u "$work/${name}.ghidra.out" "$work/${name}.rudra.out"; then
  echo "STDOUT MATCH (${name})"
else
  echo "^^ stdout mismatch (${name})" >&2
  sed -n '1,20p' "$work/${name}.ghidra.err" >&2 || true
  sed -n '1,20p' "$work/${name}.rudra.err" >&2 || true
  exit 1
fi
if [[ -s "$work/${name}.ghidra.err" || -s "$work/${name}.rudra.err" ]]; then
  echo "stderr non-empty (${name})" >&2
  cat "$work/${name}.ghidra.err" >&2
  cat "$work/${name}.rudra.err" >&2
  exit 1
fi
sha256sum "$work/${name}.ghidra.out" "$work/${name}.rudra.out"
