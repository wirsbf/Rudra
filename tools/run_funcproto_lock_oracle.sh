#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/funcproto_lock_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcproto_lock_1204.rs"
metadata="$repo_root/tests/oracle/funcproto_lock_1204.metadata.json"

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

python3 -I - "$metadata" "$cpp_fixture" "$rust_fixture" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path = map(pathlib.Path, sys.argv[1:4])
oracle_commit = sys.argv[4]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit mismatch")
for key, path in (("cpp_fixture_sha256", cpp_path), ("rust_fixture_sha256", rust_path)):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata[key]} actual={actual}")
PY

oracle_tmp=$(mktemp -d)
trap 'rm -rf -- "$oracle_tmp"' EXIT HUP INT TERM

# Replace the archive's fspec object with one compiled directly from the
# locked source. The remaining archive members only satisfy the concrete
# class/vtable dependency closure exercised by this fixture.
cp "$cpp_root/libdecomp.a" "$oracle_tmp/libdecomp.a"
g++ -std=c++11 -O2 -I"$cpp_root" -c "$cpp_root/fspec.cc" -o "$oracle_tmp/fspec.o"
ar r "$oracle_tmp/libdecomp.a" "$oracle_tmp/fspec.o"
ranlib "$oracle_tmp/libdecomp.a"
g++ -std=c++11 -O2 -I"$cpp_root" "$cpp_fixture" \
  "$oracle_tmp/libdecomp.a" -lz -o "$oracle_tmp/funcproto_lock_1204"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --manifest-path "$repo_root/Cargo.toml" --locked --offline --quiet \
  --example funcproto_lock_1204_oracle

"$oracle_tmp/funcproto_lock_1204" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/cargo-target/debug/examples/funcproto_lock_1204_oracle" \
  >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

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

cat "$oracle_tmp/ghidra.stdout"
printf 'funcproto_lock_1204: MATCH\n'
