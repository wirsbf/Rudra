#!/usr/bin/env bash
set -euo pipefail

# PRINTC-UNMAP-SINGLETON-0001 bilateral fixture runner — the printc
# singleton emission family (WORKPKG-UNMAP-PRINTC-0004) against locked
# Ghidra 12.0.4 (e40ed13014025f82488b1f8f7bca566894ac376b).
#
# Covers: push_float (printc.cc:1380), setCommentStyle (:2350),
# genericFunctionName (:3359), emitSymbolScope (:233), pushMismatchSymbol
# (:2067), pushTypePointerRel (printc.hh:365), doEmitWideCharPrefix
# (:1504). The oracle side boots a real BfdArchitecture over the pinned
# curl blob (the translate's default 4/8-byte float formats,
# translate.cc:962-970, are the input contract for push_float).

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/printc_singleton_emission_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_singleton_emission_1204.rs"
metadata="$repo_root/tests/oracle/printc_singleton_emission_1204.metadata.json"
spec_root="$repo_root/sleigh_specs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

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
if [[ ! -f "$bfd_header" ]]; then
  echo "missing BFD dev header: $bfd_header (oracle env rebuild: see AGENTS.md)" >&2
  exit 1
fi
if [[ ! -f "$bfd_library" ]]; then
  echo "missing BFD system library: $bfd_library" >&2
  exit 1
fi

# Pinned Rudra input (the curl blob the action_perform runner established).
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
rudra_input_commit=34a3febff160031c265cfbd841a94022c68c2c19

clean_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
binary_blob_oid=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  git -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
if [[ "$binary_blob_oid" != "$rudra_input_blob" ]]; then
  echo "pinned Rudra input blob mismatch: $binary_blob_oid" >&2
  exit 1
fi

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
  -o "$oracle_tmp/printc_singleton_emission_1204"

git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$oracle_tmp/input_curl_blob"

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" cargo build --quiet --lib --profile fast-release
rudra_rlib="$fixture_target/fast-release/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$fixture_target/fast-release/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/printc_singleton_emission_rudra"

"$oracle_tmp/printc_singleton_emission_1204" "$spec_root" "$oracle_tmp/input_curl_blob" \
  >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/printc_singleton_emission_rudra" >"$oracle_tmp/rudra.stdout"

if diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"; then
  cat "$oracle_tmp/ghidra.stdout"
else
  echo "printc_singleton_emission_1204: MISMATCH (see diff above)" >&2
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
printf 'printc_singleton_emission_1204: MATCH\n'
