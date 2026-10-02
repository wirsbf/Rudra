#!/usr/bin/env bash
# verify_parallel_determinism.sh — 并行确定性门禁（PAREVAL-PHASE1-LAND-0001，
# "并行 = 观察中性"协议常设化，PARALLELIZATION_DESIGN_2026-09-26.md §2.2）。
#
# 契约：examples/parallel_decompile 是生产并行驱动（bin_sweep 族的线程形态）。
# 对同一语料同一函数集：
#   serial 臂 = --jobs 1（单 worker 线程，index 序——串行形态退化）
#   par 臂   = --jobs N（N worker 线程，动态队列）
# 门禁 GREEN ⇔ 两臂逐函数 C 文本字节恒等（cmp），且非 Ok 结果（err/panic）
# 的 status+signature 恒等。输出目录按函数索引组织（f<NNN>_<name>.c），
# 与串行驱动逐函数可比。
#
# 用法：
#   tools/verify_parallel_determinism.sh [--corpus curl|httpd|sqlite3|all]
#       [--jobs N] [--bin-dir DIR] [--keep-dir DIR] [--self-test]
#
#   --corpus   语料面（默认 curl；sqlite3 需 /tmp/sqlite3 存在，缺失显式 SKIP）
#   --jobs     并行臂 worker 数（默认 8）
#   --bin-dir  parallel_decompile 二进制目录（默认自动构建 fast-release）
#   --keep-dir 保留运行产物供审计（默认 /dev/shm 易失清理）
#   --self-test 无二进制自检（参数解析/报告逻辑）
#
# 判定（exit code）：
#   0 = 全部启用语料面 GREEN
#   1 = 任一启用语料面 RED（字节差异或签名差异）
#   2 = 驱动/环境失败（构建失败、语料缺失、运行退出 2）
#
# 注：本门禁是观察中性检查（并行 vs 串行自比对），不是 oracle 差分门禁
# （那是 compare_ghidra.py / verify_mirror_gate.sh 的职责）。两臂跑的都是
# 同一 bare-native face，oracle 对齐性由既有门禁保证。

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CORPUS_FILTER="curl"
JOBS=8
BIN_DIR=""
KEEP=0
SELF_TEST=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --corpus) CORPUS_FILTER="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --keep-dir) KEEP=1; shift ;;
        --self-test) SELF_TEST=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ "$SELF_TEST" == "1" ]]; then
    # 无二进制自检：参数与语料表解析逻辑。
    ok=1
    [[ "$CORPUS_FILTER" =~ ^(curl|httpd|sqlite3|all)$ ]] || { echo "SELF-TEST FAIL: bad corpus filter"; ok=0; }
    [[ "$JOBS" =~ ^[0-9]+$ ]] && [[ "$JOBS" -ge 1 ]] || { echo "SELF-TEST FAIL: bad jobs"; ok=0; }
    [[ "$ok" == "1" ]] && echo "SELF-TEST PASS"
    exit $((1 - ok))
fi

# 语料面表：名称 -> (二进制路径, max-funcs, skip 列表)。
#   curl    : 仓库锁定 fixture examples/curl，31 函数全量（PoC 覆盖面）。
#   httpd   : 仓库锁定 fixture examples/httpd，34 函数（canon 门禁覆盖面）。
#   sqlite3 : /tmp/sqlite3（PoC 测量集 48 最大函数筛 3 个病态函数，
#             PATHOSLOW-DIVCHAIN-0001 残差慢尾——skip 表沿用 PoC 口径）。
corpus_binary() {
    case "$1" in
        curl) echo "examples/curl" ;;
        httpd) echo "examples/httpd" ;;
        sqlite3) echo "/tmp/sqlite3" ;;
        *) return 1 ;;
    esac
}
corpus_max_funcs() {
    case "$1" in
        curl) echo "31" ;;
        httpd) echo "34" ;;
        sqlite3) echo "48" ;;
        *) return 1 ;;
    esac
}
corpus_skip() {
    case "$1" in
        curl|httpd) echo "" ;;
        sqlite3) echo "8,24,30" ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# 构建（或复用）parallel_decompile 二进制。
# ---------------------------------------------------------------------------
if [[ -z "$BIN_DIR" ]]; then
    BIN_DIR="/dev/shm/rudra-targets/phaseland/fast-release/examples"
    echo "[GATE] building parallel_decompile (fast-release)..."
    if ! (cd "$REPO_ROOT" && CARGO_TARGET_DIR=/dev/shm/rudra-targets/phaseland \
        cargo build --profile fast-release --example parallel_decompile >/dev/null 2>&1); then
        echo "[GATE] FAIL: build failed"
        exit 2
    fi
fi
DRIVER="$BIN_DIR/parallel_decompile"
if [[ ! -x "$DRIVER" ]]; then
    echo "[GATE] FAIL: driver not found at $DRIVER"
    exit 2
fi

WORK_ROOT="/dev/shm/rudra-tests/phaseland/determinism"
mkdir -p "$WORK_ROOT"
# NOTE: the per-run wipe happens per-corpus inside run_face (a global wipe
# here would destroy --keep-dir evidence of other faces from earlier runs).

GLOBAL_RC=0
run_face() {
    local corpus="$1"
    local binary max_funcs skip
    binary="$(corpus_binary "$corpus")" || { echo "[GATE] unknown corpus $corpus"; exit 2; }
    max_funcs="$(corpus_max_funcs "$corpus")"
    skip="$(corpus_skip "$corpus")"

    if [[ ! -f "$binary" ]]; then
        echo "[GATE] $corpus: SKIP (corpus binary $binary missing)"
        return 0
    fi

    # Per-face wipe: only this corpus's subdir, so --keep-dir evidence of
    # other faces (earlier runs) survives.
    rm -rf "$WORK_ROOT/$corpus"
    mkdir -p "$WORK_ROOT/$corpus"

    echo "[GATE] $corpus: serial arm (jobs=1)..."
    local serial_dir="$WORK_ROOT/$corpus/serial"
    local skip_args=()
    [[ -n "$skip" ]] && skip_args=(--skip "$skip")
    (cd "$REPO_ROOT" && "$DRIVER" "$binary" --jobs 1 --max-funcs "$max_funcs" \
        "${skip_args[@]}" --out-dir "$WORK_ROOT/$corpus" --name serial >/dev/null 2>"$WORK_ROOT/$corpus/serial.err")
    rc=$?
    if [[ $rc -eq 2 ]]; then
        echo "[GATE] $corpus: FAIL (serial arm driver error rc=2)"
        GLOBAL_RC=1
        return 0
    fi
    # rc=1：存在非 Ok 函数（语料属性）——门禁继续做逐函数比对。
    [[ $rc -eq 1 ]] && echo "[GATE] $corpus: serial arm has non-ok functions (rc=1, corpus property)"

    echo "[GATE] $corpus: parallel arm (jobs=$JOBS)..."
    local par_dir="$WORK_ROOT/$corpus/par"
    (cd "$REPO_ROOT" && "$DRIVER" "$binary" --jobs "$JOBS" --max-funcs "$max_funcs" \
        "${skip_args[@]}" --out-dir "$WORK_ROOT/$corpus" --name par >/dev/null 2>"$WORK_ROOT/$corpus/par.err")
    rc=$?
    if [[ $rc -eq 2 ]]; then
        echo "[GATE] $corpus: FAIL (parallel arm driver error rc=2)"
        GLOBAL_RC=1
        return 0
    fi
    [[ $rc -eq 1 ]] && echo "[GATE] $corpus: parallel arm has non-ok functions (rc=1, corpus property)"

    # ---- 逐函数比对：C 文本字节恒等 + manifest 签名恒等 ----
    local red=0 compared=0 identical=0
    local manifest_s="$serial_dir/manifest.jsonl"
    local manifest_p="$par_dir/manifest.jsonl"
    if [[ ! -f "$manifest_s" || ! -f "$manifest_p" ]]; then
        echo "[GATE] $corpus: FAIL (manifest missing)"
        GLOBAL_RC=1
        return 0
    fi
    # 行数一致（= 同函数集）
    local lines_s lines_p
    lines_s=$(wc -l < "$manifest_s")
    lines_p=$(wc -l < "$manifest_p")
    if [[ "$lines_s" != "$lines_p" ]]; then
        echo "[GATE] $corpus: FAIL (manifest line count $lines_s vs $lines_p)"
        GLOBAL_RC=1
        return 0
    fi
    # 逐行：idx/name/status/signature 必须恒等（md5 恒等即文本恒等）；
    # Ok 函数再 cmp 文件本体（防 md5 实现缺陷，双保险）。
    local line_s line_p idx name status_s status_p md5_s md5_p file_c
    local i=0
    while IFS= read -r line_s && IFS= read -r line_p <&3; do
        i=$((i + 1))
        idx=$(sed -n 's/.*"idx":\([0-9]*\).*/\1/p' <<<"$line_s")
        name=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' <<<"$line_s")
        status_s=$(sed -n 's/.*"status":"\([^"]*\)".*/\1/p' <<<"$line_s")
        status_p=$(sed -n 's/.*"status":"\([^"]*\)".*/\1/p' <<<"$line_p")
        md5_s=$(sed -n 's/.*"md5":"\([0-9a-f]*\)".*/\1/p' <<<"$line_s")
        md5_p=$(sed -n 's/.*"md5":"\([0-9a-f]*\)".*/\1/p' <<<"$line_p")
        sig_s=$(sed -n 's/.*"signature":"\([^"]*\)".*/\1/p' <<<"$line_s")
        sig_p=$(sed -n 's/.*"signature":"\([^"]*\)".*/\1/p' <<<"$line_p")
        compared=$((compared + 1))
        if [[ "$status_s" != "$status_p" || "$sig_s" != "$sig_p" ]]; then
            echo "[GATE] $corpus: RED f$idx $name — status/signature mismatch ($status_s/$sig_s vs $status_p/$sig_p)"
            red=$((red + 1))
            continue
        fi
        if [[ "$status_s" == "ok" ]]; then
            if [[ "$md5_s" != "$md5_p" ]]; then
                echo "[GATE] $corpus: RED f$idx $name — md5 mismatch ($md5_s vs $md5_p)"
                red=$((red + 1))
                continue
            fi
            # File names are f%03d_<sanitized-name>.c (driver-side format).
            local pat
            pat=$(printf 'f%03d_*.c' "$idx")
            file_c=$(ls "$serial_dir"/$pat 2>/dev/null | head -1)
            if [[ -z "$file_c" ]]; then
                echo "[GATE] $corpus: RED f$idx $name — serial output file missing"
                red=$((red + 1))
                continue
            fi
            file_base=$(basename "$file_c")
            if ! cmp -s "$file_c" "$par_dir/$file_base"; then
                echo "[GATE] $corpus: RED f$idx $name — BYTE MISMATCH in $file_base"
                red=$((red + 1))
                continue
            fi
            identical=$((identical + 1))
        fi
    done < "$manifest_s" 3< "$manifest_p"

    local verdict="GREEN"
    [[ "$red" -gt 0 ]] && verdict="RED"
    echo "[GATE] $corpus: $verdict — compared=$compared identical-ok=$identical red=$red (serial jobs=1 vs parallel jobs=$JOBS)"
    if [[ "$verdict" == "RED" ]]; then
        GLOBAL_RC=1
    fi
}

case "$CORPUS_FILTER" in
    all)
        run_face curl
        run_face httpd
        run_face sqlite3
        ;;
    curl|httpd|sqlite3)
        run_face "$CORPUS_FILTER"
        ;;
    *)
        echo "unknown corpus: $CORPUS_FILTER" >&2
        exit 2
        ;;
esac

if [[ "$KEEP" != "1" ]]; then
    rm -rf "$WORK_ROOT"
else
    echo "[GATE] artifacts kept at $WORK_ROOT"
fi

if [[ "$GLOBAL_RC" == "0" ]]; then
    echo "[GATE] PARALLEL-DETERMINISM: GREEN"
else
    echo "[GATE] PARALLEL-DETERMINISM: RED"
fi
exit "$GLOBAL_RC"
