#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/decompress_1204.cc"
rust_fixture="$repo_root/tests/oracle/decompress_1204.rs"
metadata="$repo_root/tests/oracle/decompress_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
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

oracle_tmp=$(mktemp -d)
trap 'rm -rf "$oracle_tmp"' EXIT

g++ -std=c++11 -O2 -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/compression.cc" -lz \
  -o "$oracle_tmp/decompress_1204"

target_dir=$(cargo metadata --no-deps --format-version 1 | \
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
if ! cargo build --quiet --example decompress_1204_oracle \
  2>"$oracle_tmp/cargo-build.stderr"; then
  cat "$oracle_tmp/cargo-build.stderr" >&2
  exit 1
fi
rust_binary="$target_dir/debug/examples/decompress_1204_oracle"

oracle_zlib=$(ldd "$oracle_tmp/decompress_1204" | awk '$1 ~ /^libz[.]so/ { print $3; exit }')
rust_zlib=$(ldd "$rust_binary" | awk '$1 ~ /^libz[.]so/ { print $3; exit }')
if [[ -z "$oracle_zlib" || -z "$rust_zlib" ]]; then
  echo "both fixtures must dynamically link system libz" >&2
  exit 1
fi
if [[ "$(realpath "$oracle_zlib")" != "$(realpath "$rust_zlib")" ]]; then
  echo "fixtures resolved different libz implementations" >&2
  exit 1
fi

"$oracle_tmp/decompress_1204" >"$oracle_tmp/ghidra.stdout"
"$rust_binary" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
cat "$oracle_tmp/ghidra.stdout"

oracle_output=$(<"$oracle_tmp/ghidra.stdout")
python3 - "$metadata" "$oracle_output" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
lines = sys.argv[2].splitlines()
expected_version = f"zlib.version={metadata['host_compression_version']}"
if not lines or lines[0] != expected_version:
    raise SystemExit(
        f"zlib version mismatch: expected={expected_version} "
        f"actual={lines[0] if lines else '<empty>'}"
    )
actual_hash = hashlib.sha256((sys.argv[2] + "\n").encode()).hexdigest()
if metadata["expected_stdout_sha256"] != actual_hash:
    raise SystemExit(
        "oracle output hash mismatch: "
        f"metadata={metadata['expected_stdout_sha256']} actual={actual_hash}"
    )
PY
printf 'decompress_1204: MATCH\n'
