#!/usr/bin/env bash
# BLOCKSTRUCT-NORETURN-DEADREGION-0001 bilateral runner.
#
# Builds the locked Ghidra 12.0.4 oracle fixture (CollapseStructure::
# collapseAll over no-return-halt control-flow graphs) against the oracle
# cpp tree, builds the Rudra comparand against the crate rlib, runs both,
# and diffs the shared projection. Residual diffs are the registered
# MISMATCH set (see tests/oracle/blockstruct_deadregion_1204.metadata.json).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/blockstruct_deadregion_1204.cc"
rust_fixture="$repo_root/tests/oracle/blockstruct_deadregion_1204.rs"
metadata="$repo_root/tests/oracle/blockstruct_deadregion_1204.metadata.json"
bfd_root="${RUDRA_BFD_ROOT:-/tmp/rudra-ghidra-bfd-2.38}"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
for oracle_file in blockaction.cc blockaction.hh block.cc block.hh; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done
if [[ ! -f "$bfd_root/usr/include/bfd.h" ]]; then
  echo "bfd oracle env missing at $bfd_root (see AGENTS.md oracle rebuild note)" >&2
  exit 1
fi

# Metadata comparand gate: fixture + comparand source hashes must match the
# pinned values (re-pinned with every fixture/source change).
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/blockaction.rs" "$repo_root/src/tracedag.rs" <<'PY'
import hashlib, json, pathlib, sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pairs = {
    "cpp_fixture_sha256": pathlib.Path(sys.argv[2]),
    "rust_fixture_sha256": pathlib.Path(sys.argv[3]),
    "rudra_blockaction_sha256": pathlib.Path(sys.argv[4]),
    "rudra_tracedag_sha256": pathlib.Path(sys.argv[5]),
}
for key, path in pairs.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["comparand_sha256"][key] != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata['comparand_sha256'][key]} actual={actual}"
        )
PY

oracle_tmp=$(mktemp -d /tmp/rudra-blockstruct-deadregion-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-blockstruct-deadregion-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# ---- Ghidra oracle side ----------------------------------------------------
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
TMPDIR=/tmp make --silent -C "$cpp_root" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
TMPDIR=/tmp g++ -std=c++11 -O2 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_root/usr/include" -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  -Wl,--whole-archive "$cpp_root/libdecomp.a" \
  -Wl,--no-whole-archive "$bfd_root/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so" -lz \
  -o "$oracle_tmp/deadregion_cpp"

bfd_runtime="$bfd_root/usr/lib/x86_64-linux-gnu"
LD_LIBRARY_PATH="$bfd_runtime" \
  timeout 120 "$oracle_tmp/deadregion_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"

# ---- Rudra comparand side --------------------------------------------------
# Build the library with the shared per-agent target dir, then link the
# fixture against the produced rlib (same layout as the goto-cascade
# runner, but without the git-archive overlay: the fixture pins this
# branch's blockaction.rs/tracedag.rs hashes directly).
# Persistent cargo target on the user's home (not /tmp tmpfs: the shared
# quota can EDQUOT/SIGBUS the linker mid-write). 2026-09-26: default moved
# off the branch-era author home /home/wirs (absent on this machine) to
# $HOME; override with RUDRA_DEADREGION_TARGET_DIR (salvage of
# wt/sb-fixturehyg 69a8f690, SALVAGE-BRANAUDIT-FIXTUREHYG-PINENV-0001).
fixture_target=${RUDRA_DEADREGION_TARGET_DIR:-${HOME}/.cache/rudra-deadregion-target}
mkdir -p "$fixture_target"
TMPDIR=/tmp CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rlib=$(ls -t "$fixture_target/debug/deps/librudra-"*.rlib 2>/dev/null | head -1 || true)
if [[ -z "$rlib" ]]; then
  rlib=$(ls -t "$fixture_target/debug/librudra.rlib" 2>/dev/null | head -1 || true)
fi
if [[ -z "$rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O --extern "rudra=$rlib" \
  -L "dependency=$fixture_target/debug/deps" \
  -o "$oracle_tmp/deadregion_rs" "$rust_fixture"
TMPDIR=/tmp timeout 120 "$oracle_tmp/deadregion_rs" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

# ---- Diff ------------------------------------------------------------------
if diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
    >"$oracle_tmp/diff.txt"; then
  echo "blockstruct_deadregion_1204: MATCH (0 diff lines)"
  exit 0
fi
diff_lines=$(wc -l <"$oracle_tmp/diff.txt")
echo "blockstruct_deadregion_1204: MISMATCH ($diff_lines diff lines) — registered to BLOCKSTRUCT-DEADREGION-COLLAPSE-SHAPE-0001 + BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 (see metadata)"
cat "$oracle_tmp/diff.txt"
exit 1
