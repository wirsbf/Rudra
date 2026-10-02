#!/usr/bin/env bash
# HERITAGE-STORELOAD-FWD-0001 bilateral fixture runner (GEN5 archive shape).
#
# Oracle side : tests/oracle/heritage_storeload_fwd_1204.cc driven against the
#               locked Ghidra 12.0.4 cpp tree (synthetic Translate/Architecture
#               — no BFD needed); stdout archived at
#               tests/oracle/heritage_storeload_fwd_1204.oracle.out
#               (sha-pinned below). Live oracle re-capture only under
#               RUDRA_STORELOADFWD_ORACLE_RUN=1 (rebuilds libdecomp.a from
#               the locked tree and re-verifies the archived record hash).
# Rudra side  : current worktree lib (cargo build --lib) + the mirrored
#               tests/oracle/heritage_storeload_fwd_1204.rs.
# Comparand   : byte-compare of both stdouts against the archived record;
#               stderr must be empty on both sides; the metadata's
#               expected sha/line-count/case-prefixes are re-verified.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
fixture_cc="$repo_root/tests/oracle/heritage_storeload_fwd_1204.cc"
fixture_rs="$repo_root/tests/oracle/heritage_storeload_fwd_1204.rs"
oracle_record="$repo_root/tests/oracle/heritage_storeload_fwd_1204.oracle.out"
metadata="$repo_root/tests/oracle/heritage_storeload_fwd_1204.metadata.json"

fixture_cc_sha256=a2bd5c2da6d6e7a940075d3af8fb3d38e67140475e00622cf7a4392f8b1e61bd
fixture_rs_sha256=e627410a54d6e5eaa8da6dcf8056c3bca6e0852ff793655968aa553d43fb9831
oracle_record_sha256=468bf48ef02de3c0b4c3a7856eb2cb6b534bb4df0dedbc27158c5578ae20632b

die() { echo "run_heritage_storeload_fwd_1204: FAIL: $*" >&2; exit 1; }

for f in "$fixture_cc" "$fixture_rs" "$oracle_record" "$metadata"; do
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
done
[[ $(sha256sum "$fixture_cc" | cut -d' ' -f1) == "$fixture_cc_sha256" ]] \
  || die "oracle fixture source drifted (re-pin per AGENTS.md fixture discipline)"
[[ $(sha256sum "$fixture_rs" | cut -d' ' -f1) == "$fixture_rs_sha256" ]] \
  || die "rust fixture source drifted"
[[ $(sha256sum "$oracle_record" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
  || die "archived oracle record drifted"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rudra-storeload-fwd.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# ---- oracle comparand (archive or live) -----------------------------------
oracle_out="$workdir/oracle.stdout"
if [[ ${RUDRA_STORELOADFWD_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_STORELOADFWD_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-storeload-fwd-1204}
  runner="$cache_root/heritage_storeload_fwd_1204_cpp"
  if [[ ! -x $runner ]]; then
    [[ $(git -C "$repo_root/ghidra" rev-parse HEAD) == "$oracle_commit" ]] \
      || die "ghidra checkout not at locked oracle commit"
    [[ -z $(git -C "$repo_root/ghidra" status --porcelain -- \
        Ghidra/Features/Decompiler/src/decompile/cpp) ]] \
      || die "locked Ghidra decompiler tree is dirty"
    mkdir -p "$cache_root/x"
    git -C "$repo_root/ghidra" archive --format=tar \
      --output="$cache_root/locked-cpp.tar" "$oracle_commit" \
      Ghidra/Features/Decompiler/src/decompile/cpp
    tar -xf "$cache_root/locked-cpp.tar" -C "$cache_root/x"
    cpp="$cache_root/x/Ghidra/Features/Decompiler/src/decompile/cpp"
    make --silent -C "$cpp" -j "$(nproc)" EXTRA= libdecomp.a
    g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$cpp" "$fixture_cc" \
      "$cpp/libdecomp.cc" "$cpp/sleigh_arch.cc" "$cpp/inject_sleigh.cc" \
      -Wl,--whole-archive "$cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
      -o "$runner"
  fi
  timeout 60s "$runner" > "$oracle_out" 2> "$workdir/oracle.err"
  [[ $? -eq 0 ]] || die "live oracle run failed"
  [[ -s "$workdir/oracle.err" ]] && die "live oracle stderr non-empty"
  [[ $(sha256sum "$oracle_out" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
    || die "live oracle re-capture diverged from the archived record"
  oracle_source=live
else
  cp "$oracle_record" "$oracle_out"
  oracle_source=archive
fi

# ---- Rudra side -----------------------------------------------------------
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
(cd "$repo_root" && CARGO_TARGET_DIR="$target_dir" cargo build --offline --locked --quiet --lib)
rustc --edition=2021 -O "$fixture_rs" \
  --extern "rudra=$target_dir/debug/librudra.rlib" \
  -L "dependency=$target_dir/debug/deps" \
  -o "$workdir/heritage_storeload_fwd_1204_rust"

timeout 60s "$workdir/heritage_storeload_fwd_1204_rust" \
  > "$workdir/rudra.stdout" 2> "$workdir/rudra.err"
[[ $? -eq 0 ]] || die "rudra fixture run failed"
[[ -s "$workdir/rudra.err" ]] && die "rudra fixture stderr non-empty"

# ---- compare: byte-identical against the archived record ------------------
if cmp -s "$oracle_out" "$workdir/rudra.stdout"; then
  echo "heritage_storeload_fwd_1204: MATCH (byte-identical, 13 lines, oracle=$oracle_source)"
else
  echo "heritage_storeload_fwd_1204: MISMATCH" >&2
  diff -u --label ghidra --label rudra "$oracle_out" "$workdir/rudra.stdout" | head -40 >&2
  exit 1
fi

# ---- metadata expectations -------------------------------------------------
python3 - "$metadata" "$workdir/rudra.stdout" <<'PY'
import hashlib, json, pathlib, sys
metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
data = pathlib.Path(sys.argv[2]).read_bytes()
expected = metadata["expected_results"]["normal_stdout_sha256"]
actual = hashlib.sha256(data).hexdigest()
if actual != expected:
    raise SystemExit(f"stdout hash mismatch: expected={expected} actual={actual}")
lines = data.decode().splitlines()
if len(lines) != metadata["expected_results"]["normal_stdout_lines"]:
    raise SystemExit("stdout line-count mismatch")
prefixes = tuple(metadata["expected_results"]["case_order"])
if tuple(line.startswith(prefix) for line, prefix in zip(lines, prefixes)) != (True,) * len(prefixes):
    raise SystemExit("stdout case order mismatch")
PY

echo "heritage_storeload_fwd_1204: metadata expectations verified (sha/lines/prefixes)"
