#!/usr/bin/env bash
# bench_decompile.sh — PERF-BENCH reproducible same-scope decompile-speed
# benchmark: Rudra (release) vs locked-oracle Ghidra 12.0.4 direct runner
# (e40ed130), same inputs, same process model.
#
# See docs/alignment_docs/PERF_BENCH_2026-09-26.md for the full protocol and
# the 2026-09-26 results. Measurement discipline (AGENTS.md compilation-
# performance rules applied to decompilation):
#   * every configuration >= 3 runs, medians reported;
#   * wall/user/sys via /usr/bin/time -v or getrusage(RUSAGE_CHILDREN)
#     deltas (zero per-child overhead), peak RSS recorded;
#   * load average snapshot per sweep (31-user shared host: user CPU time
#     is the primary metric, wall secondary);
#   * page-cache state noted (all sweeps warm-cache; no root to drop caches).
#
# Fair head-to-head (P1A): both sides run the canon golden protocol —
# per-function hermetic child process (oracle golden_dump_1204 "one" mode vs
# rudra gen_decompile "--one"), 12 concurrent workers, per-function 20 s cap,
# identical function indices (discovery counts are asserted equal first).
#   oracle side : tools/regen_ghidra_golden.py fixture (git-archive of the
#                 locked cpp tree -> libdecomp.a -> golden_dump_1204)
#   rudra side  : examples/gen_decompile (bare face mirroring the fixture's
#                 discovery 1:1 — static+dynamic FUNC symbols + PLT
#                 JUMP_SLOT stubs, (offset,name) order)
#
# Context tiers (NOT head-to-head cells):
#   P1B serial  : workers=1 sweep, per-child user/sys attribution;
#   P2 allmode  : oracle in-process all-functions engine throughput;
#   P3 canon    : full canon-driver run (curl_decompile/httpd_decompile
#                 All mode) — project canon gate metric;
#   P4 headless : analyzeHeadless full Java analysis (tools/
#                 build_ghidra_1204_headless.sh) — different scope, never
#                 comparable to pure decompilation.
#
# Usage (from the repo root of a perfbench worktree):
#   bash tools/bench_decompile.sh [--skip-build] [--corpora curl,httpd,sqlite,llvm]
#
# Environment:
#   BENCH_WORK     scratch dir (default /dev/shm/rudra-tests/perfbench)
#   CARGO_TARGET_DIR  release build dir (default /dev/shm/rudra-targets/perfbench)
#   REPEATS        repeats per configuration (default 3)

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

BENCH_WORK=${BENCH_WORK:-/dev/shm/rudra-tests/perfbench}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/dev/shm/rudra-targets/perfbench}
REPEATS=${REPEATS:-3}
WORKERS=${WORKERS:-12}
CAP=${CAP:-20}
SKIP_BUILD=false
CORPORA=${CORPORA:-curl,httpd,sqlite,llvm}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=true ;;
    --corpora) CORPORA=$2; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

mkdir -p "$BENCH_WORK"
REC=$BENCH_WORK/sweeps.jsonl
: > "$REC.tmp"

SQLITE=/usr/lib/x86_64-linux-gnu/libsqlite3.so.0
LLVM=/usr/lib/x86_64-linux-gnu/libLLVM-15.so.1

binary_for() {
  case "$1" in
    curl) echo examples/curl ;;
    httpd) echo examples/httpd ;;
    sqlite) echo "$SQLITE" ;;
    llvm) echo "$LLVM" ;;
    *) echo "unknown corpus: $1" >&2; return 2 ;;
  esac
}

indices_for() {
  case "$1" in
    llvm) echo sample:100 ;;
    *) echo all ;;
  esac
}

if [[ $SKIP_BUILD == false ]]; then
  echo "[bench] building rudra release examples (fresh target dir)"
  cargo build --release --example gen_decompile \
    --example curl_decompile --example httpd_decompile
  echo "[bench] building locked-oracle direct runner"
  python3 - <<'PY'
import sys
sys.path.insert(0, "tools")
import regen_ghidra_golden as regen
env = regen.preflight()
runner, info = regen.build_runner("/dev/shm/rudra-tests/perfbench/runner-work", env)
print("[bench] oracle runner:", runner)
PY
fi

RUNNER=$BENCH_WORK/runner-work/golden_dump_1204
GEN=$CARGO_TARGET_DIR/release/examples/gen_decompile
CURL_DRV=$CARGO_TARGET_DIR/release/examples/curl_decompile
HTTPD_DRV=$CARGO_TARGET_DIR/release/examples/httpd_decompile
SW=tools/perfbench_sweep.py

echo "[bench] same-scope precondition: discovery counts must match"
for corpus in ${CORPORA//,/ }; do
  bin=$(binary_for "$corpus")
  python3 "$SW" hermetic --side oracle --runner "$RUNNER" --binary "$bin" \
    --indices 0 --workers 1 --timeout 20 --record-file "$REC.tmp" >/dev/null
  oc=$(python3 -c "import json;print(json.loads(open('$REC.tmp').read().splitlines()[-1])['function_count'])")
  rc=$("$GEN" "$bin" --list 2>&1 | grep "functions discovered" | awk '{print $2}')
  [[ "$oc" == "$rc" ]] || { echo "DISCOVERY MISMATCH $corpus oracle=$oc rudra=$rc" >&2; exit 1; }
  echo "  $corpus: $oc functions (match)"
done

echo "[bench] P1A head-to-head hermetic sweeps (workers=$WORKERS cap=${CAP}s reps=$REPEATS)"
for rep in $(seq 1 "$REPEATS"); do
  for corpus in ${CORPORA//,/ }; do
    bin=$(binary_for "$corpus"); idx=$(indices_for "$corpus")
    python3 "$SW" hermetic --side oracle --runner "$RUNNER" --binary "$bin" \
      --indices "$idx" --workers "$WORKERS" --timeout "$CAP" --record-file "$REC"
    python3 "$SW" hermetic --side rudra --runner "$GEN" --binary "$bin" \
      --indices "$idx" --workers "$WORKERS" --timeout "$CAP" --record-file "$REC"
  done
done

if [[ $CORPORA == *curl* ]]; then
  echo "[bench] P3 canon driver full runs (context tier)"
  for rep in $(seq 1 "$REPEATS"); do
    python3 "$SW" canon --runner "$CURL_DRV" --binary examples/curl \
      --record-file "$REC"
    python3 "$SW" canon --runner "$HTTPD_DRV" --binary examples/httpd \
      --record-file "$REC"
  done
fi

echo "[bench] P2 oracle in-process all-mode (context tier, small corpora)"
for rep in $(seq 1 "$REPEATS"); do
  for corpus in curl httpd sqlite; do
    [[ $CORPORA == *$corpus* ]] || continue
    bin=$(binary_for "$corpus")
    python3 "$SW" allmode --runner "$RUNNER" --binary "$bin" --record-file "$REC"
  done
done

echo "[bench] raw records: $REC"
python3 - "$REC" <<'PY'
import json, statistics, sys
rows = {}
for line in open(sys.argv[1]):
    d = json.loads(line)
    if d.get("mode") != "hermetic" or d.get("workers") != 12:
        continue
    key = (d["binary"].split("/")[-1], d["side"])
    rows.setdefault(key, []).append(d)
print(f"{'corpus':24s} {'side':7s} {'n':>5s} {'wall(med)':>10s} {'user(med)':>10s} {'sys(med)':>9s}")
for (binary, side), runs in sorted(rows.items()):
    walls = sorted(r["wall_total"] for r in runs)
    users = sorted(r["user_total"] for r in runs)
    syss = sorted(r["sys_total"] for r in runs)
    n = runs[0]["n_indices"]
    print(f"{binary[:24]:24s} {side:7s} {n:5d} {statistics.median(walls):10.1f} "
          f"{statistics.median(users):10.1f} {statistics.median(syss):9.1f}")
PY
echo "BENCH-DONE records=$REC"
