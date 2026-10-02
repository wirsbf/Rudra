#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/op_previous_block_order_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/op_previous_block_order_1204.cc"
rust_fixture="$repo_root/tests/oracle/op_previous_block_order_1204.rs"
spec_root="$repo_root/sleigh_specs"

oracle_tmp=$(mktemp -d /tmp/rudra-op-prev-block-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-op-prev-block-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# The worktree binary can be rebuilt concurrently. Materialize the committed
# fixture input so the metadata fingerprint and both comparands are insulated
# from unrelated worktree writes.
oracle_binary="$oracle_tmp/curl"
git -C "$repo_root" cat-file blob "HEAD:examples/curl" > "$oracle_binary"

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

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rudra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
fi
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" || ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD development files are unavailable" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$oracle_binary" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, binary_path = map(pathlib.Path, sys.argv[1:5])
oracle_commit, oracle_tag = sys.argv[5:7]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("metadata architecture mismatch")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("metadata compiler spec mismatch")
if metadata.get("input", {}).get("binary") != "examples/curl":
    raise SystemExit("metadata input path mismatch")
if hashlib.sha256(binary_path.read_bytes()).hexdigest() != metadata["input"]["binary_sha256"]:
    raise SystemExit("input binary fingerprint mismatch")
for key, path in (("cpp_fixture_sha256", cpp_path), ("rust_fixture_sha256", rust_path)):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata.get(key) != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata.get(key)} actual={actual}")
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
  -o "$oracle_tmp/op_previous_block_order_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/op_previous_block_order_1204_rust"

"$oracle_tmp/op_previous_block_order_1204_cpp" "$spec_root" "$oracle_binary" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/op_previous_block_order_1204_rust" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

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
printf 'op_previous_block_order_1204: MATCH\n'
