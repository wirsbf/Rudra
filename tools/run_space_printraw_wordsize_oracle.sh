#!/usr/bin/env bash
# Immutable SPACE-PRINTRAW-WORDSIZE-0001 oracle runner (space_printraw_wordsize_1204).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, builds the Rudra crate from the pinned base commit plus the
# src/space.rs overlay, compiles both fixtures, runs them, and requires
# byte-identical stdout.  The 61 lines lock AddrSpace::printRaw
# (space.cc:206-222) across wordsize 1/2/4 spaces — byteToAddress scaling,
# the "+cut" suffix, the addrsize>4 shrink rule, setw minimum-width
# semantics, the ConstantSpace/OtherSpace overrides (space.cc:372/410) —
# and the per-space getAddrSize projection (space.hh:348): const/OTHER/iop
# = 8, unique = UniqueSpace::SIZE = 4 (space.cc:418/428), join =
# sizeof(uintm) = 4 (space.cc:447), overlay copies its base.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/space_printraw_wordsize_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/space_printraw_wordsize_1204.cc"
rust_fixture="$repo_root/tests/oracle/space_printraw_wordsize_1204.rs"
space_rs="$repo_root/src/space.rs"
doc_space="$repo_root/docs/api/space.md"

oracle_tmp=$(mktemp -d /tmp/rudra-space-printraw-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-space-printraw-1204.??????) rm -rf "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$space_rs" "$doc_space"; do
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
if ! git -C "$ghidra_root" diff --quiet -- Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
if [[ -n "$(git -C "$repo_root" status --porcelain -- "$space_rs" | grep -v '^ M')" ]]; then
  echo "src/space.rs must be a plain modified file for the overlay" >&2
  exit 1
fi

# Build the Rust comparand from an immutable repository snapshot with only
# the reviewed space.rs candidate overlaid, so concurrent worktree writers
# cannot enter the fixture's crate closure.
rudra_workspace="$oracle_tmp/rudra-workspace"
mkdir -p "$rudra_workspace"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | tar -x -C "$rudra_workspace"
cp "$space_rs" "$rudra_workspace/src/space.rs"
mkdir -p "$rudra_workspace/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$rudra_workspace/ghidra"
snapshot_cpp_root="$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$space_rs" "$doc_space" \
  "${BASH_SOURCE[0]}" <<'PY'
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
for key in ("architecture", "compiler_spec", "analysis_options", "cases", "coverage"):
    if not metadata.get(key):
        raise SystemExit(f"metadata field missing: {key}")
if not metadata.get("todo_ids") or not metadata.get("fixture_id"):
    raise SystemExit("metadata fixture identity missing")
paths = {
    "cpp_fixture": cpp_path,
    "rust_fixture": rust_path,
    "rugra_space_source": source_path,
    "api_document": docs_path,
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
  -o "$oracle_tmp/space_printraw_wordsize_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/space_printraw_wordsize_1204_rust"

"$oracle_tmp/space_printraw_wordsize_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/space_printraw_wordsize_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

test -s "$oracle_tmp/ghidra.stdout"
test -s "$oracle_tmp/rudra.stdout"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 61
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 61
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
printf 'space_printraw_wordsize_1204: MATCH\n'
