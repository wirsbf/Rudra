#!/usr/bin/env bash
set -euo pipefail

# VARNODE-ADDDESCEND-THROW-0001 (op_insert_input 收编子项) oracle runner —
# Funcdata::opInsertInput (funcdata_op.cc:308-317) bilateral fixture.
# Pattern follows tools/run_op_insert_oracle.sh; the fixture needs no BFD
# loader (synthetic FixtureArchitecture, cf. varnode_add_descend_1204).

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/funcdata_op_insert_input_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/funcdata_op_insert_input_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcdata_op_insert_input_1204.rs"

oracle_tmp=$(mktemp -d /tmp/rudra-funcdata-opii-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-funcdata-opii-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path = map(pathlib.Path, sys.argv[1:4])
oracle_commit, oracle_tag = sys.argv[4:6]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if not metadata.get("architecture", "").startswith(
    "locked synthetic LE 64-bit Architecture"
):
    raise SystemExit("metadata architecture mismatch")
if metadata.get("overall_status") != "UNTESTED: (B2 migration) no declared complete bilateral observation":
    raise SystemExit("metadata status mismatch")
for key, path in (("cpp_fixture_sha256", cpp_path), ("rust_fixture_sha256", rust_path)):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata.get(key) != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata.get(key)} actual={actual}")
if not metadata.get("input", {}).get("cases"):
    raise SystemExit("metadata input case manifest missing")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp_root/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/funcdata_op_insert_input_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/funcdata_op_insert_input_1204_rust"

"$oracle_tmp/funcdata_op_insert_input_1204_cpp" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/funcdata_op_insert_input_1204_rust" >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
if [[ -s "$oracle_tmp/ghidra.stderr" || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "fixture runtime stderr must be empty" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for label, path in (("ghidra", pathlib.Path(sys.argv[2])), ("rugra", pathlib.Path(sys.argv[3]))):
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if metadata.get("expected_stdout_sha256") != actual:
        raise SystemExit(
            f"{label} stdout hash mismatch: metadata={metadata.get('expected_stdout_sha256')} actual={actual}"
        )
    lines = data.decode("utf-8").splitlines()
    if len(lines) != metadata.get("expected_stdout_lines"):
        raise SystemExit(
            f"{label} line count mismatch: metadata={metadata.get('expected_stdout_lines')} actual={len(lines)}"
        )
    required_prefixes = (
        "shift:", "middle:", "same_vn:", "const_dedup:", "free_first:", "free_second_throw:"
    )
    for prefix, line in zip(required_prefixes, lines):
        if not line.startswith(prefix):
            raise SystemExit(f"{label} observation order mismatch at {prefix}: {line!r}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'funcdata_op_insert_input_1204: MATCH lines=6 slot_shift=1 append=1 middle=1 same_vn=1 const_dedup=1 free_first=1 free_second_throw=1\n'
