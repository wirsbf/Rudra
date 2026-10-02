#!/usr/bin/env bash
# PRINTC-SUBPIECE-FIELDEXTRACT-0001 oracle runner (live-tree mode).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler library from the pinned
# ghidra/ checkout, compiles the C++ fixture against it (real oracle), builds
# the Rudra crate (live working tree, consuming the printc/cast/datatype
# WIP) and the Rust fixture, runs both, and requires the 31 stdout records
# to be byte-identical:
#   piece.*  — Datatype::isPieceStructured sweep incl. the TypeEnum ctor
#              metatype normalization (type.hh:489-494).
#   cast.*   — CastStrategyC::isSubpieceCast partial arms (cast.cc:413-418).
#   armA/B.* — PrintC::opSubpiece doesSpecialPrinting bodies
#              (printc.cc:846-871): pushPartialSymbol walk, array element
#              walk, synthetic unnamedField, findTruncation field atom.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/printc_subpiece_fieldextract_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/printc_subpiece_fieldextract_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_subpiece_fieldextract_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/sleigh_specs/x86-64.sla" "$repo_root/examples/curl" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" ]]; then
    echo "required input is missing: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

python3 - "$metadata" "$cpp_fixture" "$rust_fixture" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, oracle_commit = (
    pathlib.Path(sys.argv[1]),
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    sys.argv[4],
)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")
for key, path in (
    ("cpp_fixture_sha256", cpp_path),
    ("rust_fixture_sha256", rust_path),
):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(
            f"fixture hash mismatch for {path.name}: "
            f"metadata={metadata[key]} actual={actual}"
        )
PY

oracle_tmp=$(mktemp -d /tmp/rudra-printc-subpiece-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-printc-subpiece-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
# The Makefile's auto-discovered EXTRA set includes optional BFD-backed
# tools; this fixture only needs the locked CORE+DECCORE library.
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/printc_subpiece_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$rust_fixture" -o "$oracle_tmp/printc_subpiece_rust"

"$oracle_tmp/printc_subpiece_cpp" \
  "$repo_root/sleigh_specs" "$repo_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/printc_subpiece_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
if [[ "$ghidra_status" != 0 || "$rudra_status" != 0 ]]; then
  echo "fixture exit codes: ghidra=$ghidra_status rudra=$rudra_status" >&2
  tail -3 "$oracle_tmp/ghidra.stderr" >&2
  tail -3 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "rudra fixture stderr is not empty" >&2
  exit 1
fi

diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2]).read_bytes()
actual = hashlib.sha256(output).hexdigest()
if metadata["expected_stdout_sha256"] != actual:
    raise SystemExit(
        "oracle output hash mismatch: "
        f"metadata={metadata['expected_stdout_sha256']} actual={actual}"
    )
record_count = len(output.decode().splitlines())
print(f"records={record_count}")
PY
printf 'printc_subpiece_fieldextract_1204: MATCH\n'
