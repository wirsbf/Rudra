#!/usr/bin/env bash
# PRINTC-INTNOT-TOKEN-0001 oracle runner (GLOBWORD-C4-INTNOT-TOKEN-0001).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler library from the pinned
# ghidra/ checkout, compiles the C++ fixture against it (real oracle),
# builds the Rudra crate (live working tree) and the Rust fixture, runs
# both, and requires the 6 stdout records to be byte-identical:
#   schema line + 5 cases locking the unary_prefix token order under the
#   RPN drain (printlanguage.cc:566-573 opUnary / cc:338-342 emitOp
#   visited==0 / cc:143+171 entry emitOp):
#     intnot_deref    AND(ADD(LOAD(0x20),0xfefefeff), NEGATE(LOAD(0x20)))
#                     -> `*0x20 + 0xfefefeff & ~*0x20` (the curl defect
#                        shape; eager `~` emission yields the illegal
#                        `0xfefefeff~ & ...` form)
#     intnot_const    NEGATE(0x10)          -> `~0x10`
#     int2comp_const  INT_2COMP(0x10)       -> `-0x10`
#     intnot_left     OR(NEGATE(0x30), ADD(0x11, 0x22)) -> `~0x30 | 0x11 + 0x22`
#     intnot_addright ADD(0x11, NEGATE(0x10))           -> `0x11 + ~0x10`
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/printc_intnot_token_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_intnot_token_1204.rs"
metadata="$repo_root/tests/oracle/printc_intnot_token_1204.metadata.json"

for required in "$metadata" "$cpp_fixture" "$rust_fixture"; do
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

metadata_path = pathlib.Path(sys.argv[1])
cpp_fixture_path = pathlib.Path(sys.argv[2])
rust_fixture_path = pathlib.Path(sys.argv[3])
oracle_commit = sys.argv[4]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")
for key, path in (
    ("cpp_fixture_sha256", cpp_fixture_path),
    ("rust_fixture_sha256", rust_fixture_path),
):
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual_hash:
        raise SystemExit(
            f"fixture hash mismatch for {path.name}: "
            f"metadata={metadata[key]} actual={actual_hash}"
        )
PY

oracle_tmp=$(mktemp -d /tmp/rudra-printc-intnot-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-printc-intnot-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
# The Makefile's auto-discovered EXTRA set includes optional BFD-backed
# tools; this fixture only needs the locked CORE+DECCORE library.
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.a" -lz \
  -o "$oracle_tmp/printc_intnot_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$rust_fixture" -o "$oracle_tmp/printc_intnot_rust"

"$oracle_tmp/printc_intnot_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/printc_intnot_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rust_status=$?
if [[ "$ghidra_status" != 0 || "$rust_status" != 0 ]]; then
  echo "fixture exit codes: ghidra=$ghidra_status rudra=$rust_status" >&2
  tail -5 "$oracle_tmp/ghidra.stderr" >&2
  tail -5 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "ghidra fixture stderr is not empty" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "rudra fixture stderr is not empty" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
cat "$oracle_tmp/ghidra.stdout"

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
printf 'printc_intnot_token_1204: MATCH\n'
