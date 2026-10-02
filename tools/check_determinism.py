#!/usr/bin/env python3
"""
check_determinism.py — Rudra 反编译输出确定性双跑门禁（DETERMINISM-GATE-CI-0006）。

背景（RUN-NONDETERM-0001）：std HashMap 随机种子曾使 heritage phi 放置序逐次漂移，
All 模式 6/6 次输出互异。NONDETERM-DOMFRONT-0001 根修后需要一道 CI 门禁把此类
回归变成响亮失败，而不是靠人眼比对。

门禁内容：
  1. All 模式：`curl_decompile`（无参）跑 --runs 次（默认 2），stdout 的 sha256
     必须全部相等，且每次进程退出码为 0。
  2. compare 模式：`--rudra-timeout-isolation-compare-function <fn>`（默认 main）
     跑 --runs 次，不得报 "isolated output changed"，退出码必须为 0。
  3. 失败时打印两次运行的 sha256、字节数与首个差异行（含行号与两侧内容），
     并保留两个输出文件供 forensics（成功时才清理临时目录）。

实现说明：先 `cargo build --release --example curl_decompile` 一次，再直接执行
target/release/examples/curl_decompile。这比逐次 `cargo run` 更严格地隔离
"run-to-run 非确定性" 与 "并发编辑导致的中间重编译"，避免把别人的并发改动
误报成非确定性（--no-build 可复用既有二进制）。

用法:
    python3 tools/check_determinism.py                     # both 模式 ×2 跑
    python3 tools/check_determinism.py --mode all --runs 3
    python3 tools/check_determinism.py --mode compare --compare-fn main
    python3 tools/check_determinism.py --self-test         # 注入假漂移自检
"""
import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_NAME = "curl_decompile"
EXAMPLE_BIN = REPO_ROOT / "target" / "release" / "examples" / EXAMPLE_NAME
COMPARE_ARG = "--rudra-timeout-isolation-compare-function"
ISOLATED_CHANGED_MARKER = "isolated output changed"
DEFAULT_RUNS = 2
DEFAULT_TIMEOUT = 900  # 单次全量 All 跑实测 ~110s，留足余量


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_diff(a: bytes, b: bytes):
    """首个差异行：(1-based 行号, a 行, b 行)；一方是另一方前缀时给出行数差。"""
    la = a.decode("utf-8", errors="replace").splitlines()
    lb = b.decode("utf-8", errors="replace").splitlines()
    for i, (xa, xb) in enumerate(zip(la, lb), start=1):
        if xa != xb:
            return i, xa, xb
    if len(la) != len(lb):
        longer, shorter = (la, lb) if len(la) > len(lb) else (lb, la)
        return len(shorter) + 1, longer[len(shorter)], "<EOF>"
    return None


def report_mismatch(label: str, run_a, run_b) -> None:
    """打印两 sha + 首个差异行；输出文件保留在磁盘上供 forensics。"""
    sha_a, out_a, path_a = run_a
    sha_b, out_b, path_b = run_b
    print(f"[DETERMINISM] FAIL ({label}): run-to-run stdout drift detected")
    print(f"  run 1: sha256={sha_a}  bytes={len(out_a)}  file={path_a}")
    print(f"  run 2: sha256={sha_b}  bytes={len(out_b)}  file={path_b}")
    diff = first_diff(out_a, out_b)
    if diff:
        line_no, la, lb = diff
        print(f"  first diff at line {line_no}:")
        print(f"    run 1: {la[:160]}")
        print(f"    run 2: {lb[:160]}")
    else:
        print("  (line split identical; diff is in line terminators/encoding)")


def report_proc_failure(tag: str, returncode: int, stderr: bytes, extra: str = "") -> None:
    tail = b"\n".join(stderr.splitlines()[-8:]).decode("utf-8", "replace")
    print(f"[DETERMINISM] FAIL ({tag}): exit code {returncode}{extra}")
    print(f"  stderr tail:\n{tail}")


def snapshot_binary(outdir: Path) -> Path:
    """把构建产物快照到临时目录再执行。

    多 agent 工作区里并发 `cargo build` 会在两次运行之间替换共享的
    target/release/examples/curl_decompile，把"别人换了二进制"误报成
    run-to-run 非确定性（实测 30679B↔50966B 输出互换）。快照后整组
    运行执行同一份字节，漂移只可能来自进程内部（HashMap 种子等）。
    """
    snap = outdir / EXAMPLE_NAME
    shutil.copy2(EXAMPLE_BIN, snap)
    snap.chmod(0o755)
    return snap


def run_example(binary: Path, args_extra, timeout: int, tag: str, outdir: Path):
    """执行一次 example，返回 (sha256, stdout, returncode, stderr, 输出文件路径)。"""
    cmd = [str(binary)] + args_extra
    shown = " ".join(cmd[:6]) + (" ..." if len(cmd) > 6 else "")
    print(f"[DETERMINISM] run {tag}: {shown}")
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=REPO_ROOT)
    except subprocess.TimeoutExpired:
        print(f"[DETERMINISM] FAIL ({tag}): exceeded {timeout}s timeout")
        sys.exit(1)
    out_path = outdir / f"{tag}.c"
    out_path.write_bytes(r.stdout)
    (outdir / f"{tag}.stderr").write_bytes(r.stderr)
    return sha256_bytes(r.stdout), r.stdout, r.returncode, r.stderr, out_path


def gate_all(binary: Path, runs: int, timeout: int, outdir: Path) -> bool:
    baseline = None  # (sha, stdout, path)
    for i in range(1, runs + 1):
        sha, out, rc, err, path = run_example(binary, [], timeout, f"all-{i}", outdir)
        if rc != 0:
            report_proc_failure(f"all-{i}", rc, err)
            return False
        if baseline is None:
            baseline = (sha, out, path)
        elif sha != baseline[0]:
            report_mismatch("all mode", baseline, (sha, out, path))
            return False
    print(f"[DETERMINISM] all mode: {runs} runs, sha256 {baseline[0]} — identical")
    return True


def gate_compare(binary: Path, fns, runs: int, timeout: int, outdir: Path) -> bool:
    baseline = None  # (sha, stdout, path)
    for i in range(1, runs + 1):
        sha, out, rc, err, path = run_example(
            binary, [COMPARE_ARG, *fns], timeout, f"compare-{i}", outdir
        )
        if rc != 0:
            report_proc_failure(f"compare-{i}", rc, err)
            return False
        if ISOLATED_CHANGED_MARKER in err.decode("utf-8", errors="replace"):
            report_proc_failure(
                f"compare-{i}", rc, err,
                extra=f" (driver reported '{ISOLATED_CHANGED_MARKER}')",
            )
            return False
        if baseline is None:
            baseline = (sha, out, path)
        elif sha != baseline[0]:
            report_mismatch("compare mode", baseline, (sha, out, path))
            return False
    print(
        f"[DETERMINISM] compare mode ({' '.join(fns)}): {runs} runs, "
        f"no isolated-changed, sha256 {baseline[0]} — identical"
    )
    return True


def self_test(binary: Path, timeout: int, outdir: Path) -> bool:
    """假漂移自检：真实跑一次，用 sed 改掉输出中间一行，验证门禁能抓到。

    期望：修改后的 sha 与基线不等、first_diff 指向被改的行、两 sha 均可报告。
    """
    sha, out, rc, err, path = run_example(binary, [], timeout, "selftest-baseline", outdir)
    if rc != 0:
        report_proc_failure("selftest-baseline", rc, err)
        return False
    drifted = outdir / "selftest-drifted.c"
    drifted.write_bytes(out)
    lines = out.decode("utf-8", errors="replace").splitlines()
    mid = max(1, len(lines) // 2)
    # 任务规格：用 sed 改一次输出中间物（只改 mid 行，内容替换为漂移标记）
    subprocess.run(
        ["sed", "-i", f"{mid}s/.*/__RUDRA_DETERMINISM_DRIFT__/", str(drifted)],
        check=True,
    )
    drifted_bytes = drifted.read_bytes()
    drifted_sha = sha256_bytes(drifted_bytes)
    if drifted_sha == sha:
        print("[DETERMINISM] self-test FAIL: sed drift did not change the output")
        return False
    diff = first_diff(out, drifted_bytes)
    if not diff or diff[0] != mid:
        found = diff[0] if diff else None
        print(
            f"[DETERMINISM] self-test FAIL: first diff at {found}, expected line {mid}"
        )
        return False
    report_mismatch("self-test injected drift", (sha, out, path),
                    (drifted_sha, drifted_bytes, drifted))
    print(
        "[DETERMINISM] self-test PASS: fabricated drift caught — "
        f"sha {sha[:12]}.. vs {drifted_sha[:12]}.., first diff at line {mid}"
    )
    return True


def build_example() -> bool:
    print("[DETERMINISM] cargo build --release --example curl_decompile")
    r = subprocess.run(
        ["cargo", "build", "--release", "--example", EXAMPLE_NAME],
        cwd=REPO_ROOT,
    )
    if r.returncode != 0 or not EXAMPLE_BIN.exists():
        print(f"[DETERMINISM] FAIL: cargo build failed (binary: {EXAMPLE_BIN})")
        return False
    return True


def main():
    ap = argparse.ArgumentParser(
        description="Rudra double-run determinism gate (DETERMINISM-GATE-CI-0006)"
    )
    ap.add_argument("--mode", choices=["all", "compare", "both"], default="both")
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS,
                    help="repetitions per mode (default 2)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="per-run timeout seconds (default 900)")
    ap.add_argument("--compare-fn", action="append", default=None,
                    help="compare-mode function (repeatable, default main)")
    ap.add_argument("--self-test", action="store_true",
                    help="fabricate a sed drift on one real run and verify the gate catches it")
    ap.add_argument("--no-build", action="store_true",
                    help="reuse target/release/examples/curl_decompile as-is")
    args = ap.parse_args()
    if args.runs < 1:
        ap.error("--runs must be >= 1")
    fns = args.compare_fn or ["main"]

    if not args.no_build and not build_example():
        sys.exit(2)

    outdir = Path(tempfile.mkdtemp(prefix="rudra-determinism-"))
    ok = False
    try:
        binary = snapshot_binary(outdir)
        if args.self_test:
            ok = self_test(binary, args.timeout, outdir)
        else:
            ok = True
            if args.mode in ("all", "both"):
                ok = gate_all(binary, args.runs, args.timeout, outdir)
            if ok and args.mode in ("compare", "both"):
                ok = gate_compare(binary, fns, args.runs, args.timeout, outdir)
            if ok:
                print("[DETERMINISM] PASS")
    finally:
        # 失败时保留输出文件供 forensics（路径已打印在失败报告里），成功才清理
        if ok:
            shutil.rmtree(outdir, ignore_errors=True)
        else:
            print(f"[DETERMINISM] artifacts kept at {outdir}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
