#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$repo_root/sleigh_specs"
cpp_fixture="$repo_root/tests/oracle/flow_target_boundary_1204.cc"
rust_fixture="$repo_root/tests/oracle/flow_target_boundary_1204.rs"
metadata="$repo_root/tests/oracle/flow_target_boundary_1204.metadata.json"
rudra_fixture_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
curl_blob_oid=4e26a362f92ac1961bab63000215a84b4d7212dd
curl_blob_type=blob
curl_blob_size=162544
curl_binary_sha256=4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a

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
if [[ -z "$bfd_include" && -f /tmp/rudra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
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

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$repo_root" \
  "$rudra_fixture_commit" "$curl_blob_oid" "$curl_blob_type" \
  "$curl_blob_size" "$curl_binary_sha256" "$cpp_root" \
  "$repo_root/src/flow.rs" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    repo_root_name,
    rudra_fixture_commit,
    curl_blob_oid,
    curl_blob_type,
    curl_blob_size,
    curl_binary_sha256,
    cpp_root_name,
    rudra_flow_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
curl_blob_size = int(curl_blob_size)
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle tag/commit mismatch")
if metadata["architecture"] != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata["compiler_spec"] != "gcc":
    raise SystemExit("unexpected compiler spec metadata")
if metadata["observation"]["overall_status"] != "UNTESTED":
    raise SystemExit("target-boundary fixture must be MATCH")

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
    "rugra_flow": rudra_flow_name,
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

getstr_input = next(case for case in metadata["input"]["cases"] if case["name"] == "GetStr")
expected_provenance = {
    "repository_commit": rudra_fixture_commit,
    "git_blob_oid": curl_blob_oid,
    "git_object_type": curl_blob_type,
    "git_object_size": curl_blob_size,
    "binary_sha256": curl_binary_sha256,
}
for key, expected in expected_provenance.items():
    if getstr_input.get(key) != expected:
        raise SystemExit(f"curl provenance metadata mismatch for {key}")

resolved_oid = subprocess.check_output(
    ["git", "-C", repo_root_name, "rev-parse", f"{rudra_fixture_commit}:examples/curl"],
    text=True,
).strip()
if resolved_oid != curl_blob_oid:
    raise SystemExit(f"curl commit:path resolved to {resolved_oid}")
actual_type = subprocess.check_output(
    ["git", "-C", repo_root_name, "cat-file", "-t", curl_blob_oid], text=True
).strip()
actual_size = int(subprocess.check_output(
    ["git", "-C", repo_root_name, "cat-file", "-s", curl_blob_oid], text=True
).strip())
if actual_type != curl_blob_type or actual_size != curl_blob_size:
    raise SystemExit(f"curl object mismatch: type={actual_type} size={actual_size}")
curl_binary = subprocess.check_output(
    ["git", "-C", repo_root_name, "cat-file", "blob", curl_blob_oid]
)
curl_digest = hashlib.sha256(curl_binary).hexdigest()
if curl_digest != curl_binary_sha256:
    raise SystemExit(f"curl blob content mismatch: {curl_digest}")
if metadata["comparand_sha256"].get("curl_binary") != curl_digest:
    raise SystemExit(f"comparand mismatch for curl_binary: {curl_digest}")

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata["host_compiler"] != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
if metadata["host_rustc"] != rustc:
    raise SystemExit(f"host rustc mismatch: {rustc}")
PY

oracle_tmp=$(mktemp -d /tmp/rudra-flow-target-boundary-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-flow-target-boundary-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

locked_curl="$oracle_tmp/curl"
git -C "$repo_root" cat-file blob "$curl_blob_oid" >"$locked_curl"

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
  -o "$oracle_tmp/flow_target_boundary_1204"

"$oracle_tmp/flow_target_boundary_1204" "$spec_root" "$locked_curl" \
  >"$oracle_tmp/ghidra.stdout"
objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/flow_target_boundary_1204"
objcopy --dump-section .text="$oracle_tmp/curl.text" "$locked_curl"
fixture_text_base=$(readelf -WS "$oracle_tmp/flow_target_boundary_1204" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
curl_text_base=$(readelf -WS "$locked_curl" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
read -r probe_addr probe_size < <(nm -S --defined-only \
  "$oracle_tmp/flow_target_boundary_1204" | \
  awk '$4 == "flow_target_boundary_probe" { print "0x" $1, "0x" $2; exit }')
read -r getstr_addr getstr_size < <(nm -S --defined-only "$locked_curl" | \
  awk '$4 == "GetStr" { print "0x" $1, "0x" $2; exit }')
if [[ -z "$fixture_text_base" || -z "$curl_text_base" || \
      -z "$probe_addr" || -z "$getstr_addr" ]]; then
  echo "failed to resolve fixture/curl text or symbols" >&2
  exit 1
fi

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/flow_target_boundary_rudra"
"$oracle_tmp/flow_target_boundary_rudra" \
  "$oracle_tmp/fixture.text" "$fixture_text_base" "$probe_addr" "$probe_size" \
  "$oracle_tmp/curl.text" "$curl_text_base" "$getstr_addr" "$getstr_size" \
  >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/fixture.text" \
  "$oracle_tmp/curl.text" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observed = {
    "fixture_text": hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest(),
    "curl_text": hashlib.sha256(pathlib.Path(sys.argv[3]).read_bytes()).hexdigest(),
}
if metadata["machine_input_sha256"] != observed:
    raise SystemExit(f"machine input mismatch: {observed}")
stdout_digest = hashlib.sha256(pathlib.Path(sys.argv[4]).read_bytes()).hexdigest()
if metadata["expected_stdout_sha256"] != stdout_digest:
    raise SystemExit(f"expected stdout mismatch: {stdout_digest}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'flow_target_boundary_1204: MATCH\n'
