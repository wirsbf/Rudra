#!/usr/bin/env bash
set -euo pipefail

# FUNCDATA-MAPGLOBALS-MAXVN-0001 bilateral oracle runner
# (funcdata_mapglobals_maxvn_1204): Funcdata::mapGlobals — the inner group
# loop's maxvn reassignment on strictly greater size (funcdata_varnode.cc:
# 1685-1686) and the ct read from the biggest varnode's high type
# (cc:1692-1693), discriminated on the same-address dual-width persist
# shape flagged by the R-MAPGLOBALS independent review (fix-forward).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive (no instrumentation: the fixture uses test-only access defines,
# cf. varnode_copy_symbol_1204), builds the Rudra crate from the working
# tree, compiles both fixtures, runs them, and requires byte-identical
# stdout. The 6 records cover:
#   - a_maxvn_type: discovery-arm addSymbol takes the MAX varnode's
#     high type (forced uint4 on an 8-byte maxvn): symbol type size 4,
#     metatype uint, name base 'u' — not the span fallback, not the
#     1-byte group-start type.
#   - b_entryflip: entry arm with a seeded 4-byte entry, an 8-byte-typed
#     group start and a 2-byte-typed max member — no overflow, no
#     inconsistentuse/warningHeader (the pre-fix group-start source would
#     read the 8-byte start type and flip it).
#   - c_fallback: internal 1-byte@+1 member shrinks endaddr (cc:1684),
#     the span gate fails, ct = getBase(2,TYPE_UNKNOWN) — entry size 2,
#     unknown metatype.
#   - d_nomaxswap: equal-size member never swaps maxvn (strict '>'):
#     ct is the FIRST (start) member's type.
#   - e_multigroup: three-member group — ct from the max member, internal
#     trailing member ignored in the discovery arm.
#   - warn: warningheader comment count after mapGlobals (0 aligned).
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/funcdata_mapglobals_maxvn_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/funcdata_mapglobals_maxvn_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcdata_mapglobals_maxvn_1204.rs"
runner="$repo_root/tools/run_funcdata_mapglobals_maxvn_oracle.sh"
# Task-dedicated Cargo dirs: every Cargo invocation below is serialized on
# the shared build flock and uses the isolated target the R-MAPGLOBALS
# fix-forward E2E also uses.
cargo_target=/home/wirs/.cache/mapglobals-target
cargo_tmp=/home/wirs/.cache/mapglobals-fixture-tmp
mkdir -p "$cargo_target" "$cargo_tmp"

oracle_tmp=$(mktemp -d /tmp/rudra-mapglobals-maxvn-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-mapglobals-maxvn-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

# The Rust fixture builds against the working tree (this branch carries the
# fix-forward src change under test); the C++ side is the immutable oracle.
snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root"
cp -r "$repo_root/src" "$snapshot_root/src"
cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$repo_root/build.rs" "$snapshot_root/"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tools" \
  "$snapshot_root/sleigh_shim" "$snapshot_root/benches"
cp "$repo_root/benches/decompile_bench.rs" "$snapshot_root/benches/" 2>/dev/null || true
cp -r "$repo_root/sleigh_shim/." "$snapshot_root/sleigh_shim/"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/funcdata_mapglobals_maxvn_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/funcdata_mapglobals_maxvn_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/funcdata_mapglobals_maxvn_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_funcdata_mapglobals_maxvn_oracle.sh"
# build.rs requires the locked Ghidra SLEIGH tree at the conventional
# workspace-relative path (worktree symlink convention): link the oracle
# archive's cpp tree in.
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/funcdata_mapglobals_maxvn_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/funcdata_mapglobals_maxvn_1204_cpp"

env -i PATH=/usr/bin:/bin HOME="$HOME" LC_ALL=C \
  flock -x /tmp/rudra-cargo-build.lock \
  env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" \
  timeout 600 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
env -i PATH=/usr/bin:/bin TMPDIR="$cargo_tmp" \
  rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/funcdata_mapglobals_maxvn_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$oracle_tmp/funcdata_mapglobals_maxvn_1204_rust"

set +e
env -i PATH=/usr/bin:/bin LC_ALL=C \
  "$oracle_tmp/funcdata_mapglobals_maxvn_1204_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
env -i PATH=/usr/bin:/bin LC_ALL=C \
  "$oracle_tmp/funcdata_mapglobals_maxvn_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/ghidra.stderr" \
  "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
rudra = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
stderr = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
ghidra_stderr = pathlib.Path(sys.argv[5]).read_text(encoding="utf-8")
ghidra_status, rudra_status, diff_status = (int(v) for v in sys.argv[6:9])
if ghidra_status != 0:
    raise SystemExit(f"locked Ghidra fixture exited {ghidra_status}: {ghidra_stderr[:400]}")
if rudra_status != 0:
    raise SystemExit(f"Rudra fixture exited {rudra_status} (stderr: {stderr[:400]})")
if diff_status != 0:
    raise SystemExit("bilateral stdout mismatch")
records = ghidra.splitlines()
expected_order = [
    "a_maxvn_type", "b_entryflip", "c_fallback", "d_nomaxswap",
    "e_multigroup", "warn",
]
observed = [r.split("|", 1)[0][len("case="):] for r in records]
if observed != expected_order:
    raise SystemExit(f"observation order mismatch: {observed}")
if len(records) != metadata["expected_results"]["record_count"]:
    raise SystemExit("record count mismatch")
if stderr or ghidra_stderr:
    raise SystemExit("fixture runtime stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'funcdata_mapglobals_maxvn_1204: bilateral_projection=MATCH overall_status=MATCH records=%s residuals=none (FUNCDATA-MAPGLOBALS-MAXVN-0001; R-MAPGLOBALS REJECT fix-forward)\n' \
  "$(wc -l <"$oracle_tmp/ghidra.stdout")"
