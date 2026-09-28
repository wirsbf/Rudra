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
#                               [--no-cache] # 禁用 digest 缓存（等价 RUGRA_GATE_CACHE=0）
#   tools/verify_mirror_gate.sh --update-baseline <TODO_ID>   # 重钉（须给 TODO ID，写入台账行）
#   tools/verify_mirror_gate.sh --self-test                   # 无二进制自检（解析/断言/缓存逻辑）
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
#
# digest 缓存（GATE-DIGEST-CACHE-0001 / SPEEDPROF-GATE-DIGEST-CACHE-0001）:
#   重复验收轮（同二进制+同语料+同 golden → 同结果）免全量重跑。每面独立缓存：
#     键   = sha256(schema, corpus, 驱动二进制 sha256, 语料输入二进制 sha256,
#                   golden sha256, baselines 台账 sha256, compare_ghidra.py sha256,
#                   sleigh_specs/{x86-64-gcc.cspec, x86-64.pspec} sha256)
#           —— 覆盖驱动运行期读取的全部输入（examples/curl、examples/httpd、
#           cspec/pspec 均为运行时 fs::read；env-gated 种子清单在镜面态被驱动
#           显式忽略，不入键）。任一分量变 → 键变 → 失效全量重跑（fail-closed）。
#     值   = verdict 块 + mirror.c/mirror.err/compare.txt 产物（重放时物化回当轮
#           WORK_DIR，路径替换后 stdout 与冷轮字节恒等），manifest 记录每件产物
#           sha256，命中时逐件重算校验——校验不过视为未命中（fail-closed）。
#     只缓存 PASS 轮: FAIL 轮永远全量重跑（诊断新鲜性；不缓存瞬时噪声）。
#     陈旧守卫(a/b)每轮照常先行——缓存只跳过 face 执行，不跳过守卫；
#     键含二进制内容 digest，与 stale-guard 天然协同（无键碰撞面）。
#   缓存目录: ${RUGRA_GATE_CACHE_DIR:-/tmp/rugra-gate-cache}（默认上限 40 条，
#   LRU 按 mtime 淘汰，只删除匹配 <corpus>-<64hex> 的条目目录）。
#   禁用: --no-cache 或 RUGRA_GATE_CACHE=0。

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
# GATE-DIGEST-CACHE-0001: repeat-round digest cache (default on;
# --no-cache / RUGRA_GATE_CACHE=0 disables).
CACHE_ON=1
[[ "${RUGRA_GATE_CACHE:-1}" == "0" ]] && CACHE_ON=0
CACHE_ROOT="${RUGRA_GATE_CACHE_DIR:-/tmp/rugra-gate-cache}"
CACHE_SCHEMA="v1"   # bump on any change to verdict/artifact/cache semantics

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus) CORPUS_FILTER="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --keep-dir) KEEP=1; shift ;;
        --jobs) PAR_JOBS="$2"; shift 2 ;;
        --no-cache) CACHE_ON=0; shift ;;
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

# ---------- digest 缓存基础设施（GATE-DIGEST-CACHE-0001） ----------
# 全部 fail-closed：任一输入缺失/校验不过 → 无键或未命中 → 全量重跑。

sha256_file() { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }

# 面的运行期输入清单（驱动二进制 + 语料输入二进制）。curl/httpd 的语料是
# examples/ 下 repo 资产（驱动内 fs::read 相对 CWD，这里按 REPO_ROOT 锚定）；
# vsh/sq/sqlite 的语料是宿主资产（缺失时该面 SKIP，键也因此算不出 → 不缓存）。
face_runtime_inputs() {
    case "$1" in
        curl)   echo "$BIN_DIR/curl_decompile"$'\t'"$REPO_ROOT/examples/curl" ;;
        httpd)  echo "$BIN_DIR/httpd_decompile"$'\t'"$REPO_ROOT/examples/httpd" ;;
        vsh)    echo "$BIN_DIR/gen_decompile"$'\t'"${VSH_BINARY:-/usr/bin/virt-ssh-helper}" ;;
        sq)     echo "$BIN_DIR/gen_decompile"$'\t'"${SQ_BINARY:-/usr/local/bin/sasquatch}" ;;
        sqlite) echo "$BIN_DIR/gen_decompile"$'\t'"${SQLITE3_BINARY:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6}" ;;
        *)      return 1 ;;
    esac
}

# FACE_KEY = sha256 over (schema, corpus, driver sha, input sha, golden sha,
# baselines sha, compare tool sha, cspec sha, pspec sha)。函数内导出
# FACE_DRIVER/FACE_INPUT 供 provenance 输出。
face_cache_key() {
    local corpus="$1" golden="$2"
    FACE_KEY=""; FACE_DRIVER=""; FACE_INPUT=""
    local runtime driver input
    runtime=$(face_runtime_inputs "$corpus") || return 1
    driver="${runtime%%$'\t'*}"; input="${runtime#*$'\t'}"
    [[ -f "$driver" && -f "$input" ]] || return 1
    local cs="$REPO_ROOT/sleigh_specs/x86-64-gcc.cspec"
    local ps="$REPO_ROOT/sleigh_specs/x86-64.pspec"
    [[ -f "$cs" && -f "$ps" && -f "$golden" ]] || return 1
    local d i g b c ch ph
    d=$(sha256_file "$driver");   [[ -n "$d"  ]] || return 1
    i=$(sha256_file "$input");    [[ -n "$i"  ]] || return 1
    g=$(sha256_file "$golden");   [[ -n "$g"  ]] || return 1
    b=$(sha256_file "$BASELINES_FILE"); [[ -n "$b" ]] || return 1
    c=$(sha256_file "$REPO_ROOT/tools/compare_ghidra.py"); [[ -n "$c" ]] || return 1
    ch=$(sha256_file "$cs");      [[ -n "$ch" ]] || return 1
    ph=$(sha256_file "$ps");      [[ -n "$ph" ]] || return 1
    FACE_DRIVER="$driver"; FACE_INPUT="$input"
    FACE_KEY=$(printf 'schema=%s\ncorpus=%s\ndriver=%s\ninput=%s\ngolden=%s\nbaselines=%s\ncompare=%s\ncspec=%s\npspec=%s\n' \
        "$CACHE_SCHEMA" "$corpus" "$d" "$i" "$g" "$b" "$c" "$ch" "$ph" | sha256sum | cut -d' ' -f1)
    [[ "${#FACE_KEY}" == 64 ]] || { FACE_KEY=""; return 1; }
    return 0
}

manifest_field() { grep -m1 "^$2=" "$1/entry.manifest" 2>/dev/null | cut -d= -f2-; }

# 命中校验：manifest 存在、键匹配、verdict=PASS、orig_workdir 非空、
# 四件产物逐件 sha256 重算比对。任一不过 → 非零（视为未命中）。
cache_entry_valid() {
    local entry="$1"
    [[ -d "$entry" && -f "$entry/entry.manifest" ]] || return 1
    [[ "$(manifest_field "$entry" key)" == "$FACE_KEY" ]] || return 1
    [[ "$(manifest_field "$entry" verdict)" == "PASS" ]] || return 1
    [[ -n "$(manifest_field "$entry" orig_workdir)" ]] || return 1
    local f field want got
    for f in "mirror.c:sha_mirror_c" "mirror.err:sha_mirror_err" \
             "compare.txt:sha_compare" "verdict.block:sha_verdict_block"; do
        [[ -f "$entry/${f%%:*}" ]] || return 1
        want=$(manifest_field "$entry" "${f##*:}")
        got=$(sha256_file "$entry/${f%%:*}")
        [[ "$want" =~ ^[0-9a-f]{64}$ && "$want" == "$got" ]] || return 1
    done
    return 0
}

# LRU 淘汰：只删 CACHE_ROOT 下形如 <corpus>-<64hex> 的条目目录，保守不动其他。
cache_prune() {
    local max="${RUGRA_GATE_CACHE_MAX:-40}"
    [[ "$max" =~ ^[0-9]+$ ]] || max=40
    (( max > 0 )) || return 0
    local d
    while IFS= read -r d; do
        [[ -n "$d" && -d "$d" ]] && rm -rf -- "$d"
    done < <(find "$CACHE_ROOT" -maxdepth 1 -mindepth 1 -type d \
        -regextype posix-extended -regex '.*/[a-z]+-[0-9a-f]{64}' -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | awk -v m="$max" 'NR > m { print $2 }')
    return 0
}

# 写入（原子：tmp 目录整备完毕后 rename；写路径只会在未命中[条目缺失或
# 校验不过]后到达，且同键全量重跑的产物确定性恒等——无条件替换目标
# 条目，顺带自愈损坏条目；竞态下同键写者内容相同，后到者覆盖无害）。
cache_write_entry() {
    local corpus="$1" bin_out="$2" err_log="$3" compare_log="$4" block="$5"
    local entry="$CACHE_ROOT/${corpus}-${FACE_KEY}"
    local tmp="$CACHE_ROOT/.tmp.${corpus}.$$.${RANDOM}"
    mkdir -p "$tmp" || return 1
    cp -- "$bin_out" "$tmp/mirror.c" && cp -- "$err_log" "$tmp/mirror.err" \
     && cp -- "$compare_log" "$tmp/compare.txt" && cp -- "$block" "$tmp/verdict.block" \
     || { rm -rf -- "$tmp"; return 1; }
    {
        echo "schema=$CACHE_SCHEMA"
        echo "corpus=$corpus"
        echo "key=$FACE_KEY"
        echo "verdict=PASS"
        echo "orig_workdir=$WORK_DIR"
        echo "created=$(date +%s)"
        echo "driver=$FACE_DRIVER"
        echo "input=$FACE_INPUT"
        echo "sha_mirror_c=$(sha256_file "$tmp/mirror.c")"
        echo "sha_mirror_err=$(sha256_file "$tmp/mirror.err")"
        echo "sha_compare=$(sha256_file "$tmp/compare.txt")"
        echo "sha_verdict_block=$(sha256_file "$tmp/verdict.block")"
    } > "$tmp/entry.manifest"
    rm -rf -- "$entry" 2>/dev/null
    mv -T -- "$tmp" "$entry" 2>/dev/null || rm -rf -- "$tmp"
    cache_prune
}

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

    # ---- 0. digest 缓存命中重放（GATE-DIGEST-CACHE-0001） ----
    # 只跳过 face 执行；stale-guard（mtime+内容探针）已在门禁入口先行，
    # 命中重放的产物物化回本轮 WORK_DIR，verdict 块经 WORK_DIR 路径替换后
    # stdout 与冷轮字节恒等。provenance 走 stderr（stdout 保持冷轮形态）。
    local verdict_block="$WORK_DIR/${corpus}_verdict_block.txt"
    : > "$verdict_block"
    if [[ "$CACHE_ON" == 1 ]] && face_cache_key "$corpus" "$golden"; then
        local entry="$CACHE_ROOT/${corpus}-${FACE_KEY}"
        if cache_entry_valid "$entry"; then
            cp -- "$entry/mirror.c" "$bin_out" \
             && cp -- "$entry/mirror.err" "$err_log" \
             && cp -- "$entry/compare.txt" "$compare_log" \
             || { echo "MIRROR-GATE[$corpus] FAIL: cache replay materialization error" >&2; GLOBAL_RC=1; return; }
            local orig_workdir
            orig_workdir=$(manifest_field "$entry" orig_workdir)
            python3 - "$orig_workdir" "$WORK_DIR" "$entry/verdict.block" > "$verdict_block" <<'PY'
import sys
old, new, path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as fh:
    sys.stdout.write(fh.read().replace(old, new))
PY
            cat "$verdict_block"
            echo "MIRROR-GATE[$corpus] digest-cache HIT: key=${FACE_KEY:0:12}… entry=$entry (replayed; guards ran, face skipped)" >&2
            return 0
        fi
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

    # verdict 块双写：stdout（冷轮历史形态字节不变）+ block 文件（缓存载体）
    local line
    emit() { printf '%s\n' "$1"; printf '%s\n' "$1" >> "$verdict_block"; }
    line="MIRROR-GATE[$corpus] $verdict: skeleton=$SKELETON/$BASE_CEILING defects=$DEFECTS numbering=$NUMBERING matched=$MATCHED/$BASE_FLOOR health=$health"
    emit "$line"
    [[ -n "$why" ]] && emit "  -> $why"
    emit "  (baseline TODO $BASE_TODO @ $BASE_COMMIT, measured $BASE_MEASURED; artifacts: $bin_out $compare_log)"
    if [[ "$verdict" == "FAIL" ]]; then GLOBAL_RC=1; fi

    # ---- 5. PASS 轮写缓存（FAIL 轮不缓存——永远全量重跑，保诊断新鲜性） ----
    if [[ "$verdict" == "PASS" && "$CACHE_ON" == 1 && -n "$FACE_KEY" ]]; then
        cache_write_entry "$corpus" "$bin_out" "$err_log" "$compare_log" "$verdict_block" \
            || echo "MIRROR-GATE[$corpus] digest-cache: write skipped (nonfatal)" >&2
    fi
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

    # ---- digest 缓存自检（GATE-DIGEST-CACHE-0001，无需真实二进制） ----
    sbin=$(mktemp -d "${TMPDIR:-/tmp}/rugra-mgate-sb.XXXXXX")
    printf 'fake-driver-v1\n' > "$sbin/curl_decompile"
    chmod +x "$sbin/curl_decompile"
    printf 'fake-golden-a\n' > "$tmp/golden.a"
    printf 'fake-golden-b\n' > "$tmp/golden.b"
    BIN_DIR="$sbin"; WORK_DIR="$tmp"; CACHE_ROOT="$tmp/cache"
    mkdir -p "$CACHE_ROOT"
    real_golden="$REPO_ROOT/tests/golden/ghidra_curl_1204.direct-runner.c"
    face_cache_key curl "$real_golden" || { echo "SELF-TEST FAIL: face_cache_key (curl)"; exit 1; }
    k1="$FACE_KEY"
    face_cache_key curl "$real_golden"
    [[ -n "$FACE_KEY" && "$FACE_KEY" == "$k1" ]] || { echo "SELF-TEST FAIL: key not deterministic"; exit 1; }
    # 键分量敏感性：驱动内容变 / golden 变 → 键必变（fail-closed）
    printf 'x' >> "$sbin/curl_decompile"
    face_cache_key curl "$real_golden"
    [[ -n "$FACE_KEY" && "$FACE_KEY" != "$k1" ]] || { echo "SELF-TEST FAIL: driver digest not in key"; exit 1; }
    k2="$FACE_KEY"
    face_cache_key curl "$tmp/golden.a"   # 不同 golden 内容 → 不同键
    [[ "$FACE_KEY" != "$k2" ]] || { echo "SELF-TEST FAIL: golden digest not in key"; exit 1; }
    face_cache_key curl "$tmp/golden.b"
    [[ "$FACE_KEY" != "$k2" ]] || { echo "SELF-TEST FAIL: golden digest not in key (b)"; exit 1; }
    # 缺输入 → 无键（不缓存，走全量）
    BIN_DIR="$tmp/does-not-exist"
    face_cache_key curl "$real_golden" && { echo "SELF-TEST FAIL: missing driver must yield no key"; exit 1; } || true
    BIN_DIR="$sbin"
    face_cache_key curl "$real_golden" || { echo "SELF-TEST FAIL: face_cache_key rerun"; exit 1; }
    # 写入 + 完整性校验 + 篡改检测
    printf 'mirror-out-v1\n' > "$tmp/w.c"; : > "$tmp/w.err"
    printf 'compare-out-v1\n' > "$tmp/w.txt"; printf 'verdict-block-v1\n' > "$tmp/w.block"
    cache_write_entry curl "$tmp/w.c" "$tmp/w.err" "$tmp/w.txt" "$tmp/w.block"
    sentry="$CACHE_ROOT/curl-$FACE_KEY"
    cache_entry_valid "$sentry" || { echo "SELF-TEST FAIL: fresh entry invalid"; exit 1; }
    grep -q "orig_workdir=$WORK_DIR" "$sentry/entry.manifest" || { echo "SELF-TEST FAIL: orig_workdir recorded"; exit 1; }
    grep -q 'verdict-block-v1' "$sentry/verdict.block" || { echo "SELF-TEST FAIL: block stored"; exit 1; }
    printf 'tampered\n' > "$sentry/mirror.c"
    cache_entry_valid "$sentry" && { echo "SELF-TEST FAIL: artifact corruption undetected"; exit 1; } || true
    sed -i 's/^verdict=PASS$/verdict=FAIL/' "$sentry/entry.manifest"
    printf 'mirror-out-v1\n' > "$sentry/mirror.c"
    cache_entry_valid "$sentry" && { echo "SELF-TEST FAIL: non-PASS entry must not validate"; exit 1; } || true
    sed -i "s/^key=.*/key=deadbeef/" "$sentry/entry.manifest"
    cache_entry_valid "$sentry" && { echo "SELF-TEST FAIL: key mismatch must not validate"; exit 1; } || true
    # LRU 淘汰：上限 1 时较旧条目被删、较新保留（只删 <corpus>-<64hex> 目录）
    hex64=$(printf 'a%.0s' {1..64})
    mkdir "$CACHE_ROOT/httpd-$hex64"
    touch -d 'now + 2 seconds' "$CACHE_ROOT/httpd-$hex64"
    RUGRA_GATE_CACHE_MAX=1 cache_prune
    [[ -d "$sentry" ]] && { echo "SELF-TEST FAIL: prune kept over-limit entry"; exit 1; } || true
    [[ -d "$CACHE_ROOT/httpd-$hex64" ]] || { echo "SELF-TEST FAIL: prune dropped the newest entry"; exit 1; }
    echo "SELF-TEST PASS"
    rm -rf "$tmp" "$sbin"
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

# GATE-DIGEST-CACHE-0001: digest 缓存目录（默认 /tmp/rugra-gate-cache，env 可改）。
if [[ "$CACHE_ON" == 1 ]]; then
    mkdir -p "$CACHE_ROOT" 2>/dev/null \
        || { echo "MIRROR-GATE: WARN — cache dir $CACHE_ROOT unusable, continuing uncached" >&2; CACHE_ON=0; }
fi

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
        # GATE-DIGEST-CACHE-0001: face worker stderr 拆到独立 log（缓存 HIT
        # provenance 走 stderr；冷轮 run_face 本就不产 stderr，行为不变），
        # verdict 文件只含 stdout 块——并行/串行/命中三态 stdout 形态一致。
        ( run_face "$corpus" ) > "$WORK_DIR/face_${corpus}.verdict" 2> "$WORK_DIR/face_${corpus}.log" &
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
        cat "$WORK_DIR/face_${corpus}.log" >&2
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
