#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rugra_input_commit=183d2a1b8b62b865b177ece7001dd18dd816f82d
rugra_input_tree=85636ac61b6ec5b4140b660fc8587f6eccb3d7ff
rugra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
rugra_input_blob_type=blob
rugra_input_blob_size=162544
rugra_input_sha256=4ee4002baf3525d9fef062f9fcb9b7a9a890509b8bc5211740d0155d7c6b5d1a
bfd_header_sha256=c8c9c20823ebd8d427d9f91dd642b82b263fca2245a8ef4eb34f0de0cde25702
bfd_library_sha256=f9ca64d035c483bbfac32ca550074c20398ae2f0bb84dd989059dadb9cea8a1e
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/op_insert_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/op_insert_1204.cc"
rust_fixture="$repo_root/tests/oracle/op_insert_1204.rs"
spec_root="$repo_root/sleigh_specs"
runner="$repo_root/tools/run_op_insert_oracle.sh"

oracle_tmp=$(mktemp -d /tmp/rugra-op-insert-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-op-insert-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Materialize the immutable Git blob recorded by the fixture.  Reading
# HEAD:examples/curl here would silently retarget the oracle whenever the
# repository updates its sample binary.
oracle_binary="$oracle_tmp/curl"

actual_input_commit=$(git -C "$repo_root" rev-parse "$rugra_input_commit^{commit}")
actual_input_tree=$(git -C "$repo_root" rev-parse "$rugra_input_commit^{tree}")
actual_input_blob=$(git -C "$repo_root" rev-parse "$rugra_input_commit:examples/curl")
actual_input_blob_type=$(git -C "$repo_root" cat-file -t "$rugra_input_blob")
actual_input_blob_size=$(git -C "$repo_root" cat-file -s "$rugra_input_blob")
if [[ "$actual_input_commit" != "$rugra_input_commit" || \
      "$actual_input_tree" != "$rugra_input_tree" || \
      "$actual_input_blob" != "$rugra_input_blob" || \
      "$actual_input_blob_type" != "$rugra_input_blob_type" || \
      "$actual_input_blob_size" != "$rugra_input_blob_size" ]]; then
  echo "locked Rugra fixture input identity mismatch" >&2
  exit 1
fi
git -C "$repo_root" cat-file blob "$rugra_input_blob" > "$oracle_binary"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source has staged changes" >&2
  exit 1
fi

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
      /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so \
      /tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so; do
    if [[ -f "$candidate" ]] && \
        [[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$bfd_library_sha256" ]]; then
      bfd_library=$candidate
      break
    fi
  done
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD development files are unavailable" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_include/bfd.h" "$bfd_library" "$oracle_binary" \
  "$oracle_commit" "$oracle_tag" "$rugra_input_commit" "$rugra_input_tree" \
  "$rugra_input_blob" "$rugra_input_blob_type" "$rugra_input_blob_size" \
  "$rugra_input_sha256" "$bfd_header_sha256" "$bfd_library_sha256" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name,
    cpp_name,
    rust_name,
    runner_name,
    bfd_header_name,
    bfd_library_name,
    binary_name,
    oracle_commit,
    oracle_tag,
    rugra_input_commit,
    rugra_input_tree,
    rugra_input_blob,
    rugra_input_blob_type,
    rugra_input_blob_size,
    rugra_input_sha256,
    bfd_header_sha256,
    bfd_library_sha256,
) = sys.argv[1:]
metadata_path = pathlib.Path(metadata_name)
cpp_path = pathlib.Path(cpp_name)
rust_path = pathlib.Path(rust_name)
runner_path = pathlib.Path(runner_name)
bfd_header_path = pathlib.Path(bfd_header_name)
bfd_library_path = pathlib.Path(bfd_library_name)
binary_path = pathlib.Path(binary_name)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("metadata architecture mismatch")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("metadata compiler spec mismatch")
if metadata.get("fixture_id") != "OP-INSERT-0001":
    raise SystemExit("metadata fixture id mismatch")
if metadata.get("status") != "MISMATCH":
    raise SystemExit("metadata overall status must preserve residual MISMATCH")
if metadata.get("covered_projection_status") != "MATCH":
    raise SystemExit("metadata covered projection status mismatch")
if not metadata.get("residual_union"):
    raise SystemExit("metadata residual union missing")
expected_input = {
    "binary": "examples/curl",
    "repository_commit": rugra_input_commit,
    "repository_tree": rugra_input_tree,
    "git_blob_oid": rugra_input_blob,
    "git_object_type": rugra_input_blob_type,
    "git_object_size": int(rugra_input_blob_size),
    "binary_sha256": rugra_input_sha256,
}
for key, expected in expected_input.items():
    if metadata.get("input", {}).get(key) != expected:
        raise SystemExit(f"metadata input {key} mismatch")
manifest = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
if metadata.get("input_fingerprint") != "sha256:" + hashlib.sha256(manifest).hexdigest():
    raise SystemExit("metadata input fingerprint mismatch")
if hashlib.sha256(binary_path.read_bytes()).hexdigest() != rugra_input_sha256:
    raise SystemExit("input binary fingerprint mismatch")
comparands = {
    "runner_sha256": runner_path,
    "cpp_fixture_sha256": cpp_path,
    "rust_fixture_sha256": rust_path,
    "bfd_header_sha256": bfd_header_path,
    "bfd_library_sha256": bfd_library_path,
}
expected_comparands = {
    "bfd_header_sha256": bfd_header_sha256,
    "bfd_library_sha256": bfd_library_sha256,
}
for key, expected in expected_comparands.items():
    if metadata.get("comparand", {}).get(key) != expected:
        raise SystemExit(f"metadata {key} mismatch")
for key, path in comparands.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata.get("comparand", {}).get(key) != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata.get('comparand', {}).get(key)} actual={actual}"
        )
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/funcdata_op.cc" \
  "$cpp_root/block.cc" \
  "$cpp_root/op.cc" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/op_insert_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rugra="$oracle_tmp/cargo-target/debug/librugra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/op_insert_1204_rust"

LD_LIBRARY_PATH="$(dirname "$bfd_library")" \
  "$oracle_tmp/op_insert_1204_cpp" "$spec_root" "$oracle_binary" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/op_insert_1204_rust" >"$oracle_tmp/rugra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if metadata.get("expected_stdout_sha256") != actual:
    raise SystemExit(
        f"oracle stdout hash mismatch: metadata={metadata.get('expected_stdout_sha256')} actual={actual}"
    )
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'op_insert_1204: covered_projection=MATCH overall=MISMATCH\n'
