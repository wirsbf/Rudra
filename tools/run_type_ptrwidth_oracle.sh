#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
ghidra_root="$repo_root/ghidra"
cpp_path=Ghidra/Features/Decompiler/src/decompile/cpp
metadata="$repo_root/tests/oracle/type_ptrwidth_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/type_ptrwidth_1204.cc"
rust_fixture="$repo_root/tests/oracle/type_ptrwidth_1204.rs"
target_dir=${RUDRA_TYPE_PTRWIDTH_TARGET_DIR:-/home/wirs/.cache/rudra-type-ptrwidth-target}
runner_tmp_parent=/home/wirs/.cache/rudra-type-ptrwidth-runner

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
if [[ "$actual_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" ]]; then
  echo "locked Ghidra identity mismatch" >&2
  exit 1
fi
if [[ -n $(git -C "$ghidra_root" status --porcelain -- \
  Ghidra/Features/Decompiler/src/decompile/cpp) ]]; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

python3 - "$repo_root" "$metadata" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text())
payload = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": metadata["input_manifest"]["cases"],
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
actual_manifest = hashlib.sha256(canonical).hexdigest()
expected_manifest = metadata["input_manifest"]["sha256"]
if actual_manifest != expected_manifest:
    raise SystemExit(f"input manifest hash mismatch: {actual_manifest}")
runner = root / "tools/run_type_ptrwidth_oracle.sh"
actual_runner = hashlib.sha256(runner.read_bytes()).hexdigest()
expected_runner = metadata["comparand"]["runner_sha256"]
if actual_runner != expected_runner:
    raise SystemExit(f"runner hash mismatch: {actual_runner}")
for relative, expected in metadata["comparand"]["overlay_sha256"].items():
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"comparand hash mismatch: {relative}: {actual}")
PY

mkdir -p "$runner_tmp_parent" "$target_dir"
tmpdir=$(mktemp -d "$runner_tmp_parent/run.XXXXXX")
tool_tmp="$tmpdir/tool-tmp"
rust_binary="$tmpdir/rudra-fixture"
mkdir -p "$tool_tmp"
cleanup() {
  case "$tmpdir" in
    "$runner_tmp_parent"/run.??????) rm -rf -- "$tmpdir" ;;
    *) echo "refusing to remove unexpected temp path: $tmpdir" >&2; exit 1 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$tmpdir/oracle"
git -C "$ghidra_root" archive "$oracle_commit" "$cpp_path" | \
  tar -xf - -C "$tmpdir/oracle"
oracle_cpp="$tmpdir/oracle/$cpp_path"
env TMPDIR="$tool_tmp" make --silent -C "$oracle_cpp" -j2 libdecomp.a
env TMPDIR="$tool_tmp" g++ -std=c++11 -O2 -I"$oracle_cpp" "$cpp_fixture" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$tmpdir/ghidra_fixture"
"$tmpdir/ghidra_fixture" >"$tmpdir/ghidra.out"

if ! flock /tmp/rudra-cargo-build.lock env CARGO_INCREMENTAL=0 TMPDIR="$tool_tmp" \
  CARGO_TARGET_DIR="$target_dir" cargo build --manifest-path "$repo_root/Cargo.toml" \
  --lib --quiet >"$tmpdir/cargo.log" 2>&1; then
  cat "$tmpdir/cargo.log" >&2
  exit 1
fi
rlib="$target_dir/debug/librudra.rlib"
if [[ ! -f "$rlib" ]]; then
  echo "could not locate built Rudra rlib" >&2
  exit 1
fi
env TMPDIR="$tool_tmp" rustc --edition=2021 "$rust_fixture" --extern "rudra=$rlib" \
  -L "dependency=$target_dir/debug/deps" -o "$rust_binary"
"$rust_binary" >"$tmpdir/rudra.out"

ghidra_stdout_sha=$(sha256sum "$tmpdir/ghidra.out" | awk '{print $1}')
rudra_stdout_sha=$(sha256sum "$tmpdir/rudra.out" | awk '{print $1}')
read -r expected_ghidra_sha expected_rudra_sha < <(python3 -c \
  'import json,sys; e=json.load(open(sys.argv[1]))["expected_stdout_sha256"]; print(e["ghidra"], e["rugra"])' \
  "$metadata")
if [[ "$ghidra_stdout_sha" != "$expected_ghidra_sha" || \
      "$rudra_stdout_sha" != "$expected_rudra_sha" ]]; then
  echo "paired stdout hash mismatch: ghidra=$ghidra_stdout_sha rudra=$rudra_stdout_sha" >&2
  exit 1
fi
if ! cmp -s "$tmpdir/ghidra.out" "$tmpdir/rudra.out"; then
  diff -u "$tmpdir/ghidra.out" "$tmpdir/rudra.out" >&2 || true
  exit 1
fi

cat "$tmpdir/ghidra.out"
echo "TYPE-PTRWIDTH-PTRSUB-0001 targeted cases: MATCH" >&2
