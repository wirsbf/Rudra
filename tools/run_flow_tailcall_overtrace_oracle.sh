#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
spec_root="$repo_root/sleigh_specs"
cpp_fixture="$repo_root/tests/oracle/flow_tailcall_overtrace_1204.cc"
rust_fixture="$repo_root/tests/oracle/flow_tailcall_overtrace_1204.rs"
metadata="$repo_root/tests/oracle/flow_tailcall_overtrace_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
oracle_files=(flow.cc flow.hh fspec.cc fspec.hh funcdata_op.cc funcdata.cc)
for oracle_file in "${oracle_files[@]}"; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done

# Locked binutils 2.38 BFD build (same pins as run_flow_containedcall_oracle.sh).
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e
bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" ]]; then
  for candidate in /tmp/rugra-ghidra-bfd-2.38/usr/include /usr/include; do
    if [[ -f "$candidate/bfd.h" ]] && \
        [[ "$(sha256sum "$candidate/bfd.h" | awk '{print $1}')" == "$bfd_header_sha256" ]]; then
      bfd_include=$candidate
      break
    fi
  done
fi
bfd_library=${RUDRA_BFD_LIBRARY:-}
if [[ -z "$bfd_library" ]]; then
  for candidate in \
      /tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
      /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so; do
    if [[ -f "$candidate" ]] && \
        [[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$bfd_library_sha256" ]]; then
      bfd_library=$candidate
      break
    fi
  done
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" || \
      -z "$bfd_library" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD development files are unavailable" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$repo_root" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    repo_root_name,
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
    raise SystemExit("tailcall-overtrace fixture must be MATCH")

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
}
for key, path in comparands.items():
    actual = digest(path)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"comparand mismatch for {key}: {actual}")
PY

oracle_tmp=$(mktemp -d /tmp/rugra-flow-tailcall-overtrace-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-flow-tailcall-overtrace-1204.??????) rm -rf -- "$oracle_tmp" ;;
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
  -o "$oracle_tmp/flow_tailcall_overtrace_1204"

bfd_runtime=$(dirname "$bfd_library")
if [[ -n ${LD_LIBRARY_PATH:-} ]]; then
  bfd_runtime="$bfd_runtime:$LD_LIBRARY_PATH"
fi
LD_LIBRARY_PATH="$bfd_runtime" \
  "$oracle_tmp/flow_tailcall_overtrace_1204" "$spec_root" \
  "$oracle_tmp/flow_tailcall_overtrace_1204" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra tailcall-overtrace oracle produced unexpected stderr" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
objcopy --dump-section .text="$oracle_tmp/fixture.text" \
  "$oracle_tmp/flow_tailcall_overtrace_1204"
fixture_text_base=$(readelf -WS "$oracle_tmp/flow_tailcall_overtrace_1204" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
read -r user_addr user_size < <(nm -S --defined-only \
  "$oracle_tmp/flow_tailcall_overtrace_1204" | \
  awk '$4 == "tailover_sym_user" { print "0x" $1, "0x" $2; exit }')
read -r callee_addr callee_size < <(nm -S --defined-only \
  "$oracle_tmp/flow_tailcall_overtrace_1204" | \
  awk '$4 == "tailover_sym_callee" { print "0x" $1, "0x" $2; exit }')
read -r offcut_addr offcut_size < <(nm -S --defined-only \
  "$oracle_tmp/flow_tailcall_overtrace_1204" | \
  awk '$4 == "tailover_offcut_user" { print "0x" $1, "0x" $2; exit }')
if [[ -z "$fixture_text_base" || -z "$user_addr" || \
      -z "$callee_addr" || -z "$offcut_addr" ]]; then
  echo "failed to resolve fixture text or symbols" >&2
  exit 1
fi

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rugra_rlib="$fixture_target/debug/librugra.rlib"
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rugra=$rugra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/flow_tailcall_overtrace_rust"
# Run from the repo root: the SLEIGH translator resolves its x86-64.pspec
# relative to the process working directory.
(
  cd "$repo_root"
  LD_LIBRARY_PATH="$bfd_runtime" "$oracle_tmp/flow_tailcall_overtrace_rust" \
    "$oracle_tmp/fixture.text" "$fixture_text_base" \
    "$user_addr" "$callee_addr" \
    "$user_addr" "$user_size" \
    "$offcut_addr" "$offcut_size" \
    >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
)
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout_digest = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if metadata["expected_stdout_sha256"] != stdout_digest:
    raise SystemExit(f"expected stdout mismatch: {stdout_digest}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'flow_tailcall_overtrace_1204: MATCH\n'
