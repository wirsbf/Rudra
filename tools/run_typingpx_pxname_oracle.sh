#!/usr/bin/env bash
# TYPINGPX-PXNAME-0001 oracle runner (compact bilateral form): the
# Funcdata::mapGlobals discovery-arm naming with POINTER-typed highs —
# the px/pax/pi/pc/ppx first-character family of
# ScopeInternal::buildVariableName's persist arm (database.cc:2455-2466)
# driven by the RECURSIVE TypePointer::printNameBase (type.hh:424).
# Builds the locked Ghidra 12.0.4 oracle libdecomp from the repo's ghidra
# checkout (must sit at e40ed130), runs the C++ fixture, runs the Rust
# fixture against this tree's librudra, and diffs the two byte for byte.
#
# The formal immutable-runner pin ceremony (base commit/tree, per-file
# sha256 comparands, fixture_registry.json row) is performed by root at
# integration; this compact runner reproduces the exact bilateral run
# recorded in tests/oracle/typingpx_pxname_1204.metadata.json.
#
# usage: tools/run_typingpx_pxname_oracle.sh [workdir]
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
work="${1:-$(mktemp -d /tmp/rudra-typingpx-pxname.XXXXXX)}"

oracle_commit=$(git -C "$repo_root/ghidra" rev-parse HEAD)
[[ "$oracle_commit" == "e40ed13014025f82488b1f8f7bca566894ac376b" ]] || {
  echo "locked Ghidra oracle identity mismatch: $oracle_commit" >&2
  exit 1
}
if ! git -C "$repo_root/ghidra" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# ---- oracle side: libdecomp from the locked cpp tree, then the fixture.
cpp="$work/oracle-cpp/cpp"
mkdir -p "$work/oracle-cpp"
cp -r "$repo_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp" "$work/oracle-cpp/"
make --no-print-directory -C "$cpp" -j"$(nproc)" "CXX=g++ -std=c++11" "EXTRA=" libdecomp.a >/dev/null
g++ -std=c++11 -O2 -w -m64 -I"$cpp" \
  "$repo_root/tests/oracle/typingpx_pxname_1204.cc" \
  "$cpp/libdecomp.cc" "$cpp/sleigh_arch.cc" "$cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$work/pxname_cpp"

"$work/pxname_cpp" >"$work/ghidra.stdout" 2>"$work/ghidra.stderr"

# ---- Rust side: this tree's librudra + the fixture.
# Same form as the no-shim runner family (run_cspec_global_db_oracle.sh):
# librudra embeds the vendored engine, the fixture links pure-Rust.
cargo_target="${CARGO_TARGET_DIR:-$repo_root/target}"
cargo build --profile fast-release --lib >/dev/null
rlib=$(ls -t "$cargo_target"/fast-release/deps/librudra-*.rlib | head -1)
rustc --edition=2021 -O \
  -L "dependency=$cargo_target/fast-release/deps" \
  --extern "rudra=$rlib" \
  "$repo_root/tests/oracle/typingpx_pxname_1204.rs" -o "$work/pxname_rust"
# The direct-runner (standalone SLEIGH) core-type contract: the C++ twin
# registers the sleigh_arch.cc:204-238 table (xunknownN/int8/code), so the
# Rust side must select the same tier (typefactory flavor switch;
# MIRROR-ENVS-CANONICAL-0001) — the headless data-org flavor spells its
# cores undefinedN/long and the first-character family would differ.
RUDRA_MIRROR=1 "$work/pxname_rust" >"$work/rudra.stdout" 2>"$work/rudra.stderr"

echo "=== ghidra stdout ==="
cat "$work/ghidra.stdout"
echo "=== rudra stdout ==="
cat "$work/rudra.stdout"

if diff -u "$work/ghidra.stdout" "$work/rudra.stdout"; then
  echo "TYPINGPX-PXNAME-0001: MATCH (bilateral byte-identical)"
else
  echo "TYPINGPX-PXNAME-0001: MISMATCH" >&2
  exit 1
fi
