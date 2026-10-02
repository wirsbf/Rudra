#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/printc_display_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_display_1204.rs"
metadata="$repo_root/tests/oracle/printc_display_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi

python3 - "$metadata" "$cpp_fixture" "$rust_fixture" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

metadata_path = pathlib.Path(sys.argv[1])
cpp_fixture_path = pathlib.Path(sys.argv[2])
rust_fixture_path = pathlib.Path(sys.argv[3])
oracle_commit = sys.argv[4]
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
    ("cpp_fixture_sha256", cpp_fixture_path),
    ("rust_fixture_sha256", rust_fixture_path),
):
    actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual_hash:
        raise SystemExit(
            f"fixture hash mismatch for {path.name}: "
            f"metadata={metadata[key]} actual={actual_hash}"
        )
compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata["host_compiler"] != compiler:
    raise SystemExit(
        f"host compiler mismatch: metadata={metadata['host_compiler']} actual={compiler}"
    )
if metadata["host_rustc"] != rustc:
    raise SystemExit(
        f"host rustc mismatch: metadata={metadata['host_rustc']} actual={rustc}"
    )
PY

oracle_tmp=$(mktemp -d)
trap 'rm -rf "$oracle_tmp"' EXIT

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
# The Makefile's auto-discovered EXTRA set includes optional BFD-backed tools.
# This fixture only needs the locked CORE + DECCORE library, so keep EXTRA
# empty and avoid introducing a host binutils-dev dependency.
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.a" -lz \
  -o "$oracle_tmp/printc_display_1204"

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" cargo build --quiet --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/printc_display_rudra"

"$oracle_tmp/printc_display_1204" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/printc_display_rudra" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
cat "$oracle_tmp/ghidra.stdout"

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
printf 'printc_display_1204: MATCH\n'
