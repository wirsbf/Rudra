#!/usr/bin/env bash
# PRINTC-SINGLETON-IRFIX-0001 oracle runner (live-tree mode).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler library from the pinned
# ghidra/ checkout, compiles the C++ fixture against it (real oracle),
# builds the Rudra crate (live working tree) and the Rust fixture, runs
# both, and requires the 10 stdout records to be byte-identical:
#   cast.*     — PrintC::checkAddressOfCast (printc.cc:376-418) observed
#                through the REAL emitExpression over hand-built CAST
#                ops: PTRSUB-def positive arm, dt1-non-pointer reject,
#                non-array base0 reject, element mismatch reject, array
#                size mismatch reject, whole-map SymbolEntry positive.
#   implied.*  — PrintC::pushImpliedField (printc.cc:2085-2116) observed
#                through emitExpression over RETURN ops whose value vn
#                is implied + has_implied_field: union proceed arm,
#                struct fieldNum-0 proceed arm, no-resolution !proceed
#                arm, plain-parent !proceed arm.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/printc_checkaddr_impliedfield_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/printc_checkaddr_impliedfield_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_checkaddr_impliedfield_1204.rs"
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
actual_input_fingerprint = "sha256:" + hashlib.sha256(
    metadata["input"].encode("utf-8")
).hexdigest()
if metadata["input_fingerprint"] != actual_input_fingerprint:
    raise SystemExit(
        "input fingerprint mismatch: "
        f"metadata={metadata['input_fingerprint']} actual={actual_input_fingerprint}"
    )
for key, path in (
    ("cpp_fixture_sha256", cpp_path),
    ("rust_fixture_sha256", rust_path),
):
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual_hash:
        raise SystemExit(
            f"fixture hash mismatch for {path.name}: "
            f"metadata={metadata[key]} actual={actual_hash}"
        )
PY

# Host toolchain pinning (same shape as the singleton runner).
compiler=$(g++ --version | head -1)
rustc_version=$(rustc --version)
python3 - "$metadata" "$compiler" "$rustc_version" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if metadata["host_compiler"] != sys.argv[2]:
    raise SystemExit(
        f"host compiler mismatch: metadata={metadata['host_compiler']} actual={sys.argv[2]}"
    )
if metadata["host_rustc"] != sys.argv[3]:
    raise SystemExit(
        f"host rustc mismatch: metadata={metadata['host_rustc']} actual={sys.argv[3]}"
    )
PY

oracle_tmp=$(mktemp -d)
trap 'rm -rf "$oracle_tmp"' EXIT

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" libdecomp.a

g++ -std=c++11 -O2 -I"$cpp_root" -I"$bfd_include" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/printc_checkaddr_impliedfield_1204"

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" cargo build --quiet --lib --profile fast-release
rudra_rlib="$fixture_target/fast-release/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
TMPDIR="$oracle_tmp" rustc --edition=2021 -O \
  -L "dependency=$fixture_target/fast-release/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/printc_checkaddr_impliedfield_rudra"

"$oracle_tmp/printc_checkaddr_impliedfield_1204" "$repo_root/sleigh_specs" \
  "$repo_root/examples/curl" 2>/dev/null >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/printc_checkaddr_impliedfield_rudra" >"$oracle_tmp/rudra.stdout"

if diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"; then
  cat "$oracle_tmp/ghidra.stdout"
else
  echo "printc_checkaddr_impliedfield_1204: MISMATCH (see diff above)" >&2
  exit 1
fi

python3 - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2]).read_bytes()
actual_hash = hashlib.sha256(output).hexdigest()
if metadata["expected_stdout_sha256"] != actual_hash:
    raise SystemExit(
        "oracle output hash mismatch: "
        f"metadata={metadata['expected_stdout_sha256']} actual={actual_hash}"
    )
PY
printf 'printc_checkaddr_impliedfield_1204: MATCH\n'
