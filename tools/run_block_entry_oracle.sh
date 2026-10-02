#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$repo_root/sleigh_specs"
cpp_fixture="$repo_root/tests/oracle/block_entry_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_entry_1204.rs"
metadata="$repo_root/tests/oracle/block_entry_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
oracle_files=(flow.cc flow.hh block.cc block.hh funcdata_op.cc)
for oracle_file in "${oracle_files[@]}"; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rugra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUDRA_BFD_INCLUDE" >&2
  exit 1
fi
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$cpp_root" "$repo_root/src/flow.rs" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    cpp_root_name,
    rugra_flow_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle tag/commit mismatch")
if metadata["architecture"] != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata["compiler_spec"] != "gcc":
    raise SystemExit("unexpected compiler spec metadata")
if metadata["observation"]["overall_status"] != "UNTESTED":
    raise SystemExit("entry-block fixture must be MATCH")

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

input_bytes = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
if metadata["input_fingerprint"] != "sha256:" + hashlib.sha256(input_bytes).hexdigest():
    raise SystemExit("input fingerprint mismatch")

comparands = {
    "cpp_fixture": cpp_fixture_name,
    "rust_fixture": rust_fixture_name,
    "rugra_flow": rugra_flow_name,
    "ghidra_flow_cc": pathlib.Path(cpp_root_name) / "flow.cc",
    "ghidra_flow_hh": pathlib.Path(cpp_root_name) / "flow.hh",
    "ghidra_block_cc": pathlib.Path(cpp_root_name) / "block.cc",
    "ghidra_block_hh": pathlib.Path(cpp_root_name) / "block.hh",
    "ghidra_funcdata_op_cc": pathlib.Path(cpp_root_name) / "funcdata_op.cc",
}
for key, path in comparands.items():
    actual = digest(path)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"comparand mismatch for {key}: {actual}")

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata["host_compiler"] != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
if metadata["host_rustc"] != rustc:
    raise SystemExit(f"host rustc mismatch: {rustc}")
PY

oracle_tmp=$(mktemp -d /tmp/rugra-block-entry-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-block-entry-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O0 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/block_entry_1204"

"$oracle_tmp/block_entry_1204" "$spec_root" >"$oracle_tmp/ghidra.stdout"
objcopy --dump-section .text="$oracle_tmp/text.bin" "$oracle_tmp/block_entry_1204"
text_base=$(readelf -WS "$oracle_tmp/block_entry_1204" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
read -r ret_addr ret_size < <(nm -S --defined-only "$oracle_tmp/block_entry_1204" | \
  awk '$4 == "block_entry_ret_probe" { print "0x" $1, "0x" $2; exit }')
read -r loop_addr loop_size < <(nm -S --defined-only "$oracle_tmp/block_entry_1204" | \
  awk '$4 == "block_entry_loop_probe" { print "0x" $1, "0x" $2; exit }')
if [[ -z "$text_base" || -z "$ret_addr" || -z "$loop_addr" ]]; then
  echo "failed to resolve fixture .text/probe symbols" >&2
  exit 1
fi

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rugra_rlib="$fixture_target/debug/librugra.rlib"
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rugra=$rugra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/block_entry_rugra"
"$oracle_tmp/block_entry_rugra" "$oracle_tmp/text.bin" "$text_base" \
  "$ret_addr" "$ret_size" "$loop_addr" "$loop_size" \
  >"$oracle_tmp/rugra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/text.bin" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
text_digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
stdout_digest = hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest()
if metadata["machine_input_sha256"] != text_digest:
    raise SystemExit(f"machine input mismatch: {text_digest}")
if metadata["expected_stdout_sha256"] != stdout_digest:
    raise SystemExit(f"expected stdout mismatch: {stdout_digest}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'block_entry_1204: MATCH\n'
