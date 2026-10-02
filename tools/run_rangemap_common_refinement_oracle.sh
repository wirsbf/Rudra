#!/usr/bin/env bash
# Immutable RANGEMAP-COMMON-REFINEMENT-0001 oracle runner.
#
# Compiles the template fixture against rangemap.hh from the locked Ghidra
# 12.0.4 commit, builds Rudra from a pinned clean repository snapshot with
# only the reviewed rangemap.rs candidate overlaid, and requires byte-identical
# stdout for all common-refinement, sub-sort, iterator, and erase cases.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=8012627083360e0111506dc70d891552383a8c65
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/rangemap_common_refinement_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/rangemap_common_refinement_1204.cc"
rust_fixture="$repo_root/tests/oracle/rangemap_common_refinement_1204.rs"
rangemap_source="$repo_root/src/rangemap.rs"
api_document="$repo_root/docs/api/rangemap.md"

oracle_tmp=$(mktemp -d /tmp/rudra-rangemap-common-refinement-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-rangemap-common-refinement-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$rangemap_source" "$api_document"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

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

rudra_workspace="$oracle_tmp/rudra-workspace"
mkdir -p "$rudra_workspace"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | tar -x -C "$rudra_workspace"
cp "$rangemap_source" "$rudra_workspace/src/rangemap.rs"

mkdir -p "$rudra_workspace/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$rudra_workspace/ghidra"
snapshot_cpp_root="$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$rangemap_source" "$api_document" "${BASH_SOURCE[0]}" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, source_path, docs_path, runner_path = map(
    pathlib.Path, sys.argv[1:7]
)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
oracle = metadata.get("oracle", {})
if oracle.get("tag") != "Ghidra_12.0.4_build" or \
        oracle.get("commit") != "e40ed13014025f82488b1f8f7bca566894ac376b":
    raise SystemExit("metadata oracle mismatch")
if not metadata.get("architecture") or not metadata.get("compiler_spec"):
    raise SystemExit("metadata architecture/compiler spec missing")
if not metadata.get("analysis_options"):
    raise SystemExit("metadata analysis options missing")
paths = {
    "cpp_fixture": cpp_path,
    "rust_fixture": rust_path,
    "rugra_rangemap_source": source_path,
    "api_document": docs_path,
    "runner": runner_path,
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand_sha256"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
PY

g++ -std=c++11 -O2 -Wall -Wextra -Wno-deprecated-copy -pedantic \
  -I"$snapshot_cpp_root" "$cpp_fixture" \
  -o "$oracle_tmp/rangemap_common_refinement_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet \
  --manifest-path "$rudra_workspace/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/rangemap_common_refinement_1204_rust"

"$oracle_tmp/rangemap_common_refinement_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/rangemap_common_refinement_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

test -s "$oracle_tmp/ghidra.stdout"
test -s "$oracle_tmp/rudra.stdout"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 43
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 43

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
expected = metadata["expected_stdout_sha256"]
actual = hashlib.sha256(ghidra).hexdigest()
if actual != expected:
    raise SystemExit(f"oracle stdout hash mismatch: metadata={expected} actual={actual}")
if ghidra != rudra:
    ghidra_lines = ghidra.decode().splitlines()
    rudra_lines = rudra.decode().splitlines()
    for index, (left, right) in enumerate(zip(ghidra_lines, rudra_lines)):
        if left != right:
            raise SystemExit(
                f"record {index} differs:\n  ghidra: {left}\n  rudra:  {right}"
            )
    raise SystemExit("record counts differ")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'rangemap_common_refinement_1204: covered_projection=43/43 overall_status=MATCH\n'
