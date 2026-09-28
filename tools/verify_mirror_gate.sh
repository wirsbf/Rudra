#!/usr/bin/env bash
# verify_mirror_gate.sh — 第四门禁（镜面三口径）runner（MIRROR2-GATE4-PROPOSAL-0001
# 阶段一形态：冻结基线 + 漂移报警，绑定 MIRROR3-GATE4-BASELINE-0001）。
#
# 契约（Ghidra 12.0.4 e40ed130 direct-runner golden，tests/golden/*_1204.direct-runner.c）：
#   curl  : RUGRA_MIRROR=1     examples/curl_decompile  vs ghidra_curl_1204.direct-runner.c  --base 0
#   httpd : RUGRA_MIRROR=1     examples/httpd_decompile vs ghidra_httpd_1204.direct-runner.c --base 0
#   vsh   : RUGRA_GEN_MIRROR=1 examples/gen_decompile /usr/bin/virt-ssh-helper
#                                   vs ghidra_vsh_1204.direct-runner.c --base 0
#   sq    : RUGRA_GEN_MIRROR=1 examples/gen_decompile /usr/local/bin/sasquatch
#                                   vs ghidra_sq_1204.direct-runner.c --base 0
#                                   (GEN4 fourth-corpus ratchet face)
#
# 判定（阶段一：单向棘轮上限，超出即 FAIL）：
#   skeleton > ceiling            → FAIL（漂移报警：新残差族或既有族回归）
#   defects  > 0 或 numbering > 0 → FAIL（硬断言，与 ceiling 无关）
#   matched  < floor              → FAIL（函数覆盖丢失）
#   健康信号（timeout/panic/worker 失败/ok 计数）非零 → FAIL
#   skeleton ≤ ceiling 即 PASS（低于上限不算失败；收紧上限须先登记 TODO）
#
# 用法：
#   tools/verify_mirror_gate.sh [--corpus curl|httpd|vsh|sq|sqlite|all] [--bin-dir DIR] [--keep-dir DIR]
#                               [--jobs N]   # N>1: 五面并发(SPEEDPROF-PAR-FACES-0001)，默认 1=串行原形
#   tools/verify_mirror_gate.sh --update-baseline <TODO_ID>   # 重钉（须给 TODO ID，写入台账行）
#   tools/verify_mirror_gate.sh --self-test                   # 无二进制自检（解析/断言逻辑）
#
# vsh/sq 面的语料二进制（/usr/bin/virt-ssh-helper、/usr/local/bin/sasquatch）是宿主特定资产：
# 缺失时该面显式 SKIP（exit 0，输出 SKIP 行），curl/httpd 两面仍照常门禁（CI 形态）。
#
# 陈旧二进制守卫（INFRA-EXAMPLES-STALELINK-0001，双层）:
#   (a) mtime 层: curl/httpd/gen 三驱动二进制早于 HEAD commit 时间戳即 FAIL;
#   (b) 内容层: gen_decompile --stale-guard-probe — build.rs 嵌入的源码指纹
#       （src/**/*.rs + examples/gen_decompile.rs）运行时重算比对，不符即 FAIL。
#       覆盖 cargo 增量/缓存复用未重链的事故形态（MB29 漏检 r3merge 镜面效应、
#       CASTFUSEB 错归因两口实录——内容级守卫与 mtime 无关，是权威判定）。

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINES_FILE="${MIRROR_GATE_BASELINES:-$SCRIPT_DIR/mirror_gate_baselines.tsv}"

CORPUS_FILTER="all"
BIN_DIR=""
KEEP=0
MODE="gate"
UPDATE_TODO=""
SELF_TEST=0
# SPEEDPROF-PAR-FACES-0001: parallel face scheduling (default 1 = exact
# historical serial form; >1 runs independent faces concurrently, verdict
# lines re-emitted in canonical face order after all faces finish).
PAR_JOBS=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus) CORPUS_FILTER="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --keep-dir) KEEP=1; shift ;;
        --jobs) PAR_JOBS="$2"; shift 2 ;;
        --update-baseline) MODE="update"; UPDATE_TODO="${2:-}"; shift 2 ;;
        --self-test) SELF_TEST=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
case "$PAR_JOBS" in
    ''|*[!0-9]*|0) echo "--jobs must be a positive integer (got '$PAR_JOBS')" >&2; exit 2 ;;
esac

# compare_ghidra.py 摘要行解析：从 compare 输出取 matched/skeleton/defects/numbering。
parse_compare() {
    local out="$1"
    MATCHED=$(sed -n 's/^Matched: \([0-9]*\)$/\1/p' "$out" | head -1)
    SKELETON=$(sed -n 's/^Total skeleton diff lines: \([0-9]*\)$/\1/p' "$out" | head -1)
    DEFECTS=$(sed -n 's/^Total Rugra defects: \([0-9]*\).*/\1/p' "$out" | head -1)
    NUMBERING=$(sed -n 's/^Total Rugra numbering issues: \([0-9]*\)$/\1/p' "$out" | head -1)
    MATCHED="${MATCHED:-0}"; SKELETON="${SKELETON:-999999}"
    DEFECTS="${DEFECTS:-999999}"; NUMBERING="${NUMBERING:-999999}"
}

# 基线台账列：corpus  ceiling  floor  todo_id  pinned_commit  measured_at
read_baseline() {
    local corpus="$1"
    BASE_CEILING=""; BASE_FLOOR=""; BASE_TODO=""; BASE_COMMIT=""
    while IFS=$'\t' read -r c ceiling floor todo commit measured; do
        [[ "$c" == "corpus" || "$c" == \#* || -z "$c" ]] && continue
        if [[ "$c" == "$corpus" ]]; then
            BASE_CEILING="$ceiling"; BASE_FLOOR="$floor"
            BASE_TODO="$todo"; BASE_COMMIT="$commit"; BASE_MEASURED="$measured"
            return 0
        fi
    done < "$BASELINES_FILE"
    return 1
}

GLOBAL_RC=0
run_face() {
    local corpus="$1"
    if [[ "$CORPUS_FILTER" != "all" && "$CORPUS_FILTER" != "$corpus" ]]; then return; fi

    local golden bin_out err_log compare_log
    golden="$REPO_ROOT/tests/golden/ghidra_${corpus}_1204.direct-runner.c"
    bin_out="$WORK_DIR/${corpus}_mirror.c"
    err_log="$WORK_DIR/${corpus}_mirror.err"
    compare_log="$WORK_DIR/${corpus}_mirror.compare.txt"

    if [[ ! -f "$golden" ]]; then
        echo "MIRROR-GATE[$corpus] FAIL: golden missing: $golden"
        GLOBAL_RC=1; return
    fi

    # ---- 1. 运行驱动（镜像态） ----
    case "$corpus" in
        curl)
            RUGRA_MIRROR=1 "$BIN_DIR/curl_decompile" > "$bin_out" 2> "$err_log" || true ;;
        httpd)
            RUGRA_MIRROR=1 "$BIN_DIR/httpd_decompile" > "$bin_out" 2> "$err_log" || true ;;
        vsh)
            local vsh_bin="${VSH_BINARY:-/usr/bin/virt-ssh-helper}"
            if [[ ! -x "$vsh_bin" ]]; then
                echo "MIRROR-GATE[vsh] SKIP: corpus binary $vsh_bin absent (host-specific asset)"
                return
            fi
            RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
                "$BIN_DIR/gen_decompile" "$vsh_bin" > "$bin_out" 2> "$err_log" || true ;;
        sq)
            local sq_bin="${SQ_BINARY:-/usr/local/bin/sasquatch}"
            if [[ ! -x "$sq_bin" ]]; then
                echo "MIRROR-GATE[sq] SKIP: corpus binary $sq_bin absent (host-specific asset)"
                return
            fi
            RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
                "$BIN_DIR/gen_decompile" "$sq_bin" > "$bin_out" 2> "$err_log" || true ;;
        sqlite)
            # GENWIRE-SQLITE-RATCHET-REPIN-0001 (MERGEBATCH17): fifth gate
            # face — the libsqlite3 corpus (SQLITE3_SCOREBOARD §10 proposal,
            # genwire −140 landing). Same mirror-arm contract as vsh/sq.
            local sqlite_bin="${SQLITE3_BINARY:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6}"
            if [[ ! -e "$sqlite_bin" ]]; then
                echo "MIRROR-GATE[sqlite] SKIP: corpus binary $sqlite_bin absent (host-specific asset)"
                return
            fi
            RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=600 \
                "$BIN_DIR/gen_decompile" "$sqlite_bin" > "$bin_out" 2> "$err_log" || true ;;
    esac

    # ---- 2. compare 摘要 ----
    python3 "$REPO_ROOT/tools/compare_ghidra.py" "$bin_out" "$golden" \
        --base 0 --summary-only > "$compare_log" 2>&1 || true
    parse_compare "$compare_log"

    # ---- 3. 健康信号 ----
    local health="ok" health_detail=""
    case "$corpus" in
        curl)
            local summary
            summary=$(grep -o '=== Summary:.*===' "$bin_out" | tail -1)
            if [[ -z "$summary" ]]; then
                health="fail"; health_detail="no Summary line"
            else
                local attempted total
                attempted=$(sed -n 's/.*Summary: \([0-9]*\)\/\([0-9]*\) .*/\1/p' <<<"$summary")
                total=$(sed -n 's/.*Summary: \([0-9]*\)\/\([0-9]*\) .*/\2/p' <<<"$summary")
                local t p wf pf es
                t=$(sed -n 's/.* \([0-9]*\) timeout.*/\1/p' <<<"$summary")
                p=$(sed -n 's/.* \([0-9]*\) panic.*/\1/p' <<<"$summary")
                wf=$(sed -n 's/.* \([0-9]*\) worker-failure.*/\1/p' <<<"$summary")
                pf=$(sed -n 's/.* \([0-9]*\) protocol-failure ===/\1/p' <<<"$summary")
                if [[ "${t:-1}" != "0" || "${p:-1}" != "0" || "${wf:-1}" != "0" || "${pf:-1}" != "0" ]]; then
                    health="fail"
                    health_detail="timeout=${t:-?} panic=${p:-?} worker-failure=${wf:-?} protocol-failure=${pf:-?}"
                fi
            fi
            ;;
        httpd)
            local ntimeouts
            ntimeouts=$(grep -c "TIMEOUT (>" "$bin_out" || true)
            if [[ "${ntimeouts:-0}" != "0" ]]; then
                health="fail"; health_detail="timeout markers=$ntimeouts"
            fi
            ;;
        vsh|sq|sqlite)
            local okline
            okline=$(grep -o '\[GEN\] ok=[0-9]*/[0-9]* functions' "$err_log" | tail -1)
            local ok total
            ok=$(sed -n 's/.*ok=\([0-9]*\)\/\([0-9]*\).*/\1/p' <<<"$okline")
            total=$(sed -n 's/.*ok=\([0-9]*\)\/\([0-9]*\).*/\2/p' <<<"$okline")
            if [[ -z "$ok" ]]; then
                health="fail"; health_detail="no [GEN] ok= line"
            elif [[ "$ok" != "$total" ]]; then
                health="fail"; health_detail="ok=$ok/$total"
            fi
            ;;
    esac

    # ---- 4. 基线判定 ----
    if ! read_baseline "$corpus"; then
        echo "MIRROR-GATE[$corpus] FAIL: no baseline row for '$corpus' in $BASELINES_FILE"
        GLOBAL_RC=1; return
    fi
    local verdict="PASS" why=""
    if (( SKELETON > BASE_CEILING )); then
        verdict="FAIL"; why="skeleton $SKELETON > ceiling $BASE_CEILING (drift; TODO $BASE_TODO)"
    fi
    if (( DEFECTS > 0 )); then
        verdict="FAIL"; why="$why defects=$DEFECTS (hard assert 0)"
    fi
    if (( NUMBERING > 0 )); then
        verdict="FAIL"; why="$why numbering=$NUMBERING (hard assert 0)"
    fi
    if (( MATCHED < BASE_FLOOR )); then
        verdict="FAIL"; why="$why matched=$MATCHED < floor $BASE_FLOOR"
    fi
    if [[ "$health" != "ok" ]]; then
        verdict="FAIL"; why="$why health: $health_detail"
    fi

    echo "MIRROR-GATE[$corpus] $verdict: skeleton=$SKELETON/$BASE_CEILING defects=$DEFECTS numbering=$NUMBERING matched=$MATCHED/$BASE_FLOOR health=$health"
    [[ -n "$why" ]] && echo "  -> $why"
    echo "  (baseline TODO $BASE_TODO @ $BASE_COMMIT, measured $BASE_MEASURED; artifacts: $bin_out $compare_log)"
    if [[ "$verdict" == "FAIL" ]]; then GLOBAL_RC=1; fi
}

# ---------- 自检模式（无二进制：只验证解析与判定逻辑） ----------
if [[ "$SELF_TEST" == 1 ]]; then
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/rugra-mgate.XXXXXX")
    cat > "$tmp/compare.txt" <<EOF
Rugra functions: 76
Ghidra functions: 74
Matched: 74

Total skeleton diff lines: 259
Total Rugra defects: 0 (in 0/74 functions)
Total Rugra numbering issues: 0
EOF
    parse_compare "$tmp/compare.txt"
    [[ "$MATCHED" == "74" && "$SKELETON" == "259" && "$DEFECTS" == "0" && "$NUMBERING" == "0" ]] \
        || { echo "SELF-TEST FAIL: parse_compare"; exit 1; }
    # 缺行 → fail-closed 计数
    printf 'Matched: 1\n' > "$tmp/short.txt"
    parse_compare "$tmp/short.txt"
    [[ "$SKELETON" == "999999" && "$DEFECTS" == "999999" ]] \
        || { echo "SELF-TEST FAIL: fail-closed defaults"; exit 1; }
    read_baseline curl && [[ "$BASE_CEILING" =~ ^[0-9]+$ ]] \
        || { echo "SELF-TEST FAIL: read_baseline"; exit 1; }
    read_baseline no-such-corpus && { echo "SELF-TEST FAIL: bogus corpus row"; exit 1; } || true
    echo "SELF-TEST PASS"
    rm -rf "$tmp"
    exit 0
fi

if [[ "$MODE" == "update" ]]; then
    if [[ -z "$UPDATE_TODO" ]]; then
        echo "--update-baseline requires a TODO id argument" >&2; exit 2
    fi
    echo "baseline re-pin writes are done by hand with review; measured values printed below."
    echo "(edit $BASELINES_FILE: ceiling=measured skeleton, floor=measured matched, todo=$UPDATE_TODO)"
    MODE="gate"
fi

# ---------- 门禁模式 ----------
BIN_DIR="${BIN_DIR:-$REPO_ROOT/target/fast-release/examples}"
# staleness guard (a): binaries older than the HEAD commit are stale (2026-09-25 incident:
# pre-tier binaries printed the canon face under the mirror env and silently exploded the diff).
# INFRA-EXAMPLES-STALELINK-0001 (2026-09-28): loop extended to gen_decompile — the MB29
# integration (missed r3merge mirror effect) and CASTFUSEB (mis-attributed −86/−138) bites
# both ran stale gen_decompile binaries that this check never covered.
HEAD_TS=$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null || echo 0)
for _b in curl_decompile httpd_decompile gen_decompile; do
  _p="$BIN_DIR/$_b"
  if [[ -x "$_p" ]]; then
    _bt=$(stat -c %Y "$_p" 2>/dev/null || echo 0)
    if (( HEAD_TS > 0 && _bt > 0 && _bt < HEAD_TS )); then
      echo "MIRROR-GATE: FAIL — stale binary $_p (older than HEAD; rebuild: cargo build --profile fast-release --examples)" >&2
      exit 1
    fi
  fi
done
if [[ -z "$(ls -A "$BIN_DIR" 2>/dev/null)" ]]; then
    cat >&2 <<EOF
no example binaries in $BIN_DIR — build first:
  CARGO_TARGET_DIR=<dir> cargo build --profile fast-release --examples
EOF
    exit 2
fi
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rugra-mirror-gate.XXXXXX")

# ---- 0b. 内容级陈旧自检（INFRA-EXAMPLES-STALELINK-0001） ----
# gen_decompile 内嵌 build 期源码指纹（build.rs: src/**/*.rs +
# examples/gen_decompile.rs 的 FNV-1a-64 内容摘要），启动自检不符即拒跑。
# 这是不依赖 mtime 的权威守卫：cargo 增量/缓存复用未重链的陈旧二进制
# （MB29 漏检 r3merge 镜面效应、CASTFUSEB 错归因两口实录）在此 FAIL。
if [[ -x "$BIN_DIR/gen_decompile" ]]; then
    if ! (cd "$REPO_ROOT" && "$BIN_DIR/gen_decompile" --stale-guard-probe) \
            > "$WORK_DIR/stale_guard_probe.out" 2> "$WORK_DIR/stale_guard_probe.err"; then
        echo "MIRROR-GATE: FAIL — gen_decompile 陈旧二进制 (stale binary, content self-check failed):" >&2
        sed 's/^/  /' "$WORK_DIR/stale_guard_probe.err" >&2
        echo "  重链 (relink): 在目标 worktree 内执行 cargo build --profile fast-release --examples" >&2
        exit 1
    fi
    echo "MIRROR-GATE: stale-guard content probe OK — $(head -1 "$WORK_DIR/stale_guard_probe.out")"
fi

# SPEEDPROF-PAR-FACES-0001: concurrent face dispatcher. The five faces are
# independent single-child streams — disjoint artifact files under WORK_DIR,
# per-face verdict computed in its own subshell (run_face's global writes
# stay local). Only completion order changes; verdict output is re-emitted
# in the canonical face order after every face finishes. Fail-closed:
# nonzero subshell exit or any per-face FAIL line sets GLOBAL_RC=1.
run_faces_parallel() {
    local faces=() corpus pid i fail=0
    for corpus in curl httpd vsh sq sqlite; do
        [[ "$CORPUS_FILTER" != "all" && "$CORPUS_FILTER" != "$corpus" ]] && continue
        faces+=("$corpus")
    done
    local pids=() names=()
    for corpus in "${faces[@]}"; do
        ( run_face "$corpus" ) > "$WORK_DIR/face_${corpus}.verdict" 2>&1 &
        pids+=("$!"); names+=("$corpus")
    done
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            echo "MIRROR-GATE[${names[$i]}] FAIL: face worker exited nonzero"
            fail=1
        fi
    done
    for corpus in "${faces[@]}"; do
        cat "$WORK_DIR/face_${corpus}.verdict"
        grep -q "MIRROR-GATE\[$corpus\] FAIL" "$WORK_DIR/face_${corpus}.verdict" && GLOBAL_RC=1
    done
    (( fail == 1 )) && GLOBAL_RC=1
    return 0
}

if (( PAR_JOBS > 1 )); then
    run_faces_parallel
else
    run_face curl
    run_face httpd
    run_face vsh
    run_face sq
    run_face sqlite
fi

if [[ "$KEEP" == "1" ]]; then
    echo "artifacts kept in $WORK_DIR"
else
    [[ "$GLOBAL_RC" == "0" ]] && rm -rf "$WORK_DIR" || { echo "artifacts kept in $WORK_DIR (for diagnosis)"; }
fi

if [[ "$GLOBAL_RC" == "0" ]]; then
    echo "MIRROR-GATE: PASS (phase-1 frozen-baseline form, MIRROR3-GATE4-BASELINE-0001)"
else
    echo "MIRROR-GATE: FAIL — drift above frozen baseline; every new/residual family must be registered (TODO) before ceilings may move"
fi
exit "$GLOBAL_RC"
