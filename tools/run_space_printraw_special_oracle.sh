#!/usr/bin/env bash
# Immutable SPACE-PRINTRAW-SPECIAL-0001 oracle runner (space_printraw_special_1204).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, builds the Rudra crate from the pinned base commit plus the
# src/space.rs and src/op.rs overlays, compiles both fixtures, runs them,
# and requires byte-identical stdout.  The 11 lines lock
# JoinSpace::printRaw (space.cc:590-609) through the manager join halves —
# AddrSpaceManager::findAddJoin (translate.cc:671-715: the four validation
# throws, dedup via JoinRecord::operator< ordering, 16-byte-rounded
# allocation) and findJoin (translate.cc:746-762, including the
# "Unlinked join address" throw) — for the 2-piece/3-piece/1-piece
# float-extension pieces forms, the wordsize-2 piece recursion (scaling +
# "+cut" inside the braces), and the allocation sequence
# 0x0/0x10/0x20/0x30/0x40.  The IopSpace::printRaw forms are NOT covered
# (SPACE-IOP-PRINTRAW-0001 residual: spaceless legacy SeqNum.addr /
# BlockBasic::start_addr, blocked by ADDRESS-0001).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/space_printraw_special_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/space_printraw_special_1204.cc"
rust_fixture="$repo_root/tests/oracle/space_printraw_special_1204.rs"
space_rs="$repo_root/src/space.rs"
op_rs="$repo_root/src/op.rs"
doc_space="$repo_root/docs/api/space.md"
doc_op="$repo_root/docs/api/op.md"

oracle_tmp=$(mktemp -d /tmp/rudra-space-printraw-special.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-space-printraw-special.??????) rm -rf "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$space_rs" "$op_rs" "$doc_space" "$doc_op"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}"
  2>/dev/null || printf 'missing')
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
for overlay in "$space_rs" "$op_rs"; do
  if [[ -n "$(git -C "$repo_root" status --porcelain -- "$overlay" | grep -v '^ M')" ]]; then
    echo "$overlay must be a plain modified file for the overlay" >&2
    exit 1
  fi
done

# Build the Rust comparand from an immutable repository snapshot with only
# the reviewed space.rs/op.rs candidates overlaid, so concurrent worktree
# writers cannot enter the fixture's crate closure.
rudra_workspace="$oracle_tmp/rudra-workspace"
mkdir -p "$rudra_workspace"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim crates benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | tar -x -C "$rudra_workspace"
cp "$space_rs" "$rudra_workspace/src/space.rs"
cp "$op_rs" "$rudra_workspace/src/op.rs"
mkdir -p "$rudra_workspace/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$rudra_workspace/ghidra"
snapshot_cpp_root="$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$space_rs" "$op_rs" "$doc_space" "$doc_op" \
  "${BASH_SOURCE[0]}" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, space_path, op_path, docs_space_path, docs_op_path, runner_path = map(
    pathlib.Path, sys.argv[1:9]
)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
oracle = metadata.get("oracle", {})
if oracle.get("tag") != "Ghidra_12.0.4_build" or \
        oracle.get("commit") != "e40ed13014025f82488b1f8f7bca566894ac376b":
    raise SystemExit("metadata oracle mismatch")
for key in ("architecture", "compiler_spec", "analysis_options", "cases", "coverage"):
    if not metadata.get(key):
        raise SystemExit(f"metadata field missing: {key}")
if not metadata.get("todo_ids") or not metadata.get("fixture_id"):
    raise SystemExit("metadata fixture identity missing")
paths = {
    "cpp_fixture": cpp_path,
    "rust_fixture": rust_path,
    "rugra_space_source": space_path,
    "rugra_op_source": op_path,
    "api_document_space": docs_space_path,
    "api_document_op": docs_op_path,
    "runner": runner_path,
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand_sha256"][key]
    if expected.startswith("PENDING"):
        raise SystemExit(f"{key} hash is still pending")
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$snapshot_cpp_root" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$snapshot_cpp_root" \
  "$cpp_fixture" \
  "$snapshot_cpp_root/libdecomp.cc" \
  "$snapshot_cpp_root/sleigh_arch.cc" \
  "$snapshot_cpp_root/inject_sleigh.cc" \
  -Wl,--whole-archive "$snapshot_cpp_root/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/space_printraw_special_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/space_printraw_special_1204_rust"

"$oracle_tmp/space_printraw_special_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/space_printraw_special_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

test -s "$oracle_tmp/ghidra.stdout"
test -s "$oracle_tmp/rudra.stdout"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 11
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 11
test ! -s "$oracle_tmp/ghidra.stderr"
test ! -s "$oracle_tmp/rudra.stderr"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
expected = metadata["expected_stdout_sha256"]
if hashlib.sha256(ghidra).hexdigest() != expected:
    raise SystemExit(
        f"oracle stdout hash mismatch: metadata={expected} "
        f"actual={hashlib.sha256(ghidra).hexdigest()}"
    )
if ghidra != rudra:
    ghidra_lines = ghidra.decode().splitlines()
    rudra_lines = rudra.decode().splitlines()
    if len(ghidra_lines) != len(rudra_lines):
        raise SystemExit(
            f"record count differs: ghidra={len(ghidra_lines)} rudra={len(rudra_lines)}"
        )
    for index, (left, right) in enumerate(zip(ghidra_lines, rudra_lines)):
        if left != right:
            raise SystemExit(
                f"record {index} differs:\n  ghidra: {left}\n  rudra:  {right}"
            )
    raise SystemExit("outputs differ")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'space_printraw_special_1204: MATCH\n'
