#!/usr/bin/env bash
# CSPEC-GLOBAL-DB-0001 oracle runner (compact bilateral form): the global
# scope Database write path (CSPEC-GLOBAL-APPLY-0001) — the cspec
# <global> + OTHER triples land in the symbol table's global scope, and
# Scope::queryProperties folds them into Varnode flags
# (mapped|addrtied|persist). Builds the locked Ghidra 12.0.4 oracle
# libdecomp from the repo's ghidra checkout (must sit at e40ed130), runs
# the C++ fixture against the pinned curl blob, runs the Rust fixture
# against this tree's librudra, and diffs the two byte for byte.
#
# The formal immutable-runner pin ceremony (base commit/tree, per-file
# sha256 comparands, fixture_registry.json row) is performed by root at
# integration; this compact runner reproduces the exact bilateral run
# recorded in tests/oracle/cspec_global_db_1204.metadata.json.
#
# usage: tools/run_cspec_global_db_oracle.sh [workdir]
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
work="${1:-$(mktemp -d /tmp/rudra-cspec-global-db.XXXXXX)}"

bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
[[ -f "$bfd_include/bfd.h" && -f "$bfd_library" ]] || {
  echo "BFD headers/library missing (oracle env rebuilt needed): $bfd_include" >&2
  exit 1
}

oracle_commit=$(git -C "$repo_root/ghidra" rev-parse HEAD)
[[ "$oracle_commit" == "e40ed13014025f82488b1f8f7bca566894ac376b" ]] || {
  echo "locked Ghidra oracle identity mismatch: $oracle_commit" >&2
  exit 1
}

# ---- oracle side: libdecomp from the locked cpp tree, then the fixture.
cpp="$work/oracle-cpp/cpp"
mkdir -p "$work/oracle-cpp"
cp -r "$repo_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" "$work/oracle-cpp/"
make --no-print-directory -C "$cpp" -j"$(nproc)" "CXX=g++ -std=c++11" "EXTRA=" libdecomp.a >/dev/null
g++ -std=c++11 -O0 -w -m64 -I"$bfd_include" -I"$cpp" \
  "$repo_root/tests/oracle/cspec_global_db_1204.cc" \
  "$cpp/libdecomp.cc" "$cpp/sleigh_arch.cc" "$cpp/inject_sleigh.cc" \
  "$cpp/bfd_arch.cc" "$cpp/loadimage_bfd.cc" "$cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$work/global_db_cpp"

mkdir -p "$work/specs"
for f in x86.ldefs x86-64.pspec x86-64.sla x86-64-gcc.cspec; do
  cp "$repo_root/sleigh_specs/$f" "$work/specs/"
done

"$work/global_db_cpp" "$work/specs" "$repo_root/examples/curl" \
  >"$work/ghidra.stdout" 2>"$work/ghidra.stderr"

# ---- Rust side: this tree's librudra + the fixture.
# SLEIGH-RUSTIFY-PHASE2 (applied at MERGEBATCH17): the C++ shim
# (librudra_sleigh.a) is retired — librudra embeds the vendored kuna-sleigh
# engine, so the fixture links pure-Rust (same form as the no-shim runner
# family, e.g. run_rule_subcommute_sdiv_oracle.sh).
cargo_target="${CARGO_TARGET_DIR:-$repo_root/target}"
cargo build --profile fast-release --lib >/dev/null
rlib=$(ls -t "$cargo_target"/fast-release/deps/librudra-*.rlib | head -1)
rustc --edition=2021 -O \
  -L "dependency=$cargo_target/fast-release/deps" \
  --extern "rudra=$rlib" \
  "$repo_root/tests/oracle/cspec_global_db_1204.rs" -o "$work/global_db_rust"
"$work/global_db_rust" "$repo_root/sleigh_specs/x86-64-gcc.cspec" \
  "$repo_root/sleigh_specs/x86-64.sla" \
  >"$work/rudra.stdout" 2>"$work/rudra.stderr"

if diff -u "$work/ghidra.stdout" "$work/rudra.stdout"; then
  echo "CSPEC-GLOBAL-DB-0001: MATCH (bilateral byte-identical)"
else
  echo "CSPEC-GLOBAL-DB-0001: MISMATCH" >&2
  exit 1
fi
