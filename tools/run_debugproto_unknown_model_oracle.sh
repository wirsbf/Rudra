#!/usr/bin/env bash
set -euo pipefail

# PLTSTUB-WARNLOSS-0001 seeding-layer bilateral oracle runner
# (debugproto_unknown_model_1204).  Compiles the locked Ghidra 12.0.4 oracle
# fixture against the standalone decompiler archive plus the production
# x86-64-gcc.cspec/sla spec set, builds the Rugra comparand example, runs
# both on identical inputs (BfdArchitecture spec dir + the locked curl
# fixture binary for the DWARF half), and diffs the boundary projections
# byte for byte.  Template: tools/run_varmap_dupdecl_oracle.sh (extended
# with the BFD/spec/binary inputs the BfdArchitecture chain requires).
#
# Salvage note (SALVAGE-BRANAUDIT-DEBUGPROTO-FIXTURE-0001): replayed by
# content from wt2/debugwarn commit 5aecd028 and re-pinned against current
# master.  Adaptation vs the branch version: the cargo target stages under
# ${HOME}/.cache (persistent NVMe, not /tmp tmpfs: the shared quota can
# EDQUOT/SIGBUS the linker mid-write) with the RUDRA_DEBUGPROTO_TARGET_DIR
# override, matching the blockstruct runner path-hygiene convention.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/debugproto_unknown_model_1204.cc"
rust_fixture="$repo_root/tests/oracle/debugproto_unknown_model_1204.rs"
metadata="$repo_root/tests/oracle/debugproto_unknown_model_1204.metadata.json"
runner="$repo_root/tools/run_debugproto_unknown_model_oracle.sh"
curl_fixture="$repo_root/examples/curl"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_runtime=$(dirname "$bfd_library")
spec_files=(
  sleigh_specs/x86.ldefs
  sleigh_specs/x86-64.pspec
  sleigh_specs/x86-64-gcc.cspec
  sleigh_specs/x86-64.sla
)

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse 'Ghidra_12.0.4_build^{commit}')
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if [[ -n "$(git -C "$ghidra_root" status --porcelain --untracked-files=no)" ]]; then
  echo "locked Ghidra source tree is dirty" >&2
  exit 1
fi
if [[ ! -f "$cpp_root/libdecomp.a" ]]; then
  echo "missing $cpp_root/libdecomp.a; build the locked standalone decompiler first" >&2
  exit 1
fi
for required in "$bfd_include/bfd.h" "$bfd_library" "$curl_fixture"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
for relative in "${spec_files[@]}"; do
  if [[ ! -f "$repo_root/$relative" ]]; then
    echo "missing spec file: $relative" >&2
    exit 1
  fi
done

python3 -I - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$curl_fixture" "$repo_root" "$oracle_commit" -- "${spec_files[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[6])
paths = {
    "cpp_fixture": pathlib.Path(sys.argv[2]),
    "rust_fixture": pathlib.Path(sys.argv[3]),
    "runner": pathlib.Path(sys.argv[4]),
    "curl_fixture": pathlib.Path(sys.argv[5]),
}
oracle_commit = sys.argv[7]
for relative in sys.argv[9:]:
    paths[relative] = repo_root / relative

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit mismatch")
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["sha256"][key] != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata['sha256'][key]} actual={actual}")
PY

oracle_tmp=$(mktemp -d)
trap 'rm -rf -- "$oracle_tmp"' EXIT HUP INT TERM

spec_root="$oracle_tmp/specs"
mkdir -p "$spec_root"
for relative in "${spec_files[@]}"; do
  cp "$repo_root/$relative" "$spec_root/${relative##*/}"
done
cp "$curl_fixture" "$oracle_tmp/curl"
chmod 0700 "$oracle_tmp/curl"

g++ -std=c++11 -O1 -I"$bfd_include" -I"$cpp_root" "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" "$cpp_root/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/debugproto_unknown_model_1204_cpp"

# Persistent cargo target on the user's home cache (see the salvage note in
# the header); override with RUDRA_DEBUGPROTO_TARGET_DIR.
fixture_target=${RUDRA_DEBUGPROTO_TARGET_DIR:-${HOME}/.cache/rugra-debugproto-target}
mkdir -p "$fixture_target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --manifest-path "$repo_root/Cargo.toml" --locked --offline --quiet \
  --example debugproto_unknown_model_1204_oracle

LD_LIBRARY_PATH="$bfd_runtime" \
  "$oracle_tmp/debugproto_unknown_model_1204_cpp" "$spec_root" "$oracle_tmp/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$fixture_target/debug/examples/debugproto_unknown_model_1204_oracle" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86-64.sla" "$oracle_tmp/curl" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"

if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra oracle produced unexpected stderr" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rugra.stderr" ]]; then
  echo "Rugra fixture produced unexpected stderr" >&2
  cat "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

python3 -I - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if metadata["expected_stdout_sha256"] != actual:
    raise SystemExit(
        f"oracle stdout hash mismatch: metadata={metadata['expected_stdout_sha256']} actual={actual}"
    )
PY

echo "debugproto_unknown_model_1204: MATCH"
