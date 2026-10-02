#!/usr/bin/env python3
"""perfbench_sweep.py — PERF-BENCH lane measurement driver (2026-09-26).

Rudra vs locked-oracle Ghidra 12.0.4 decompile-speed sweep on identical
inputs and an identical process model.  Pure measurement: no src changes,
no pipeline semantics; this tool only times existing drivers.

Sides
-----
oracle : tools/regen_ghidra_golden.py golden_dump_1204 fixture built from the
         locked cpp tree (commit e40ed130, tree b02e230a) — BfdArchitecture
         bare face, full universal action, PrintC docFunction (the B2/direct-
         runner tier infra).
rudra  : examples/gen_decompile (bare face mirroring golden_dump_1204.cc
         discovery 1:1) or the canon drivers examples/curl_decompile /
         examples/httpd_decompile (canon tier, richer input face).

Modes
-----
hermetic : per-function isolated child process — oracle `one` mode vs rudra
           `gen_decompile --one`.  Both sides pay per-child process start +
           spec load + binary ingestion + decompile.  This is the same
           process model the goldens/canon sweeps use (fair head-to-head).
allmode  : oracle `all` mode, single process, all functions, one
           Architecture (oracle engine-only throughput context; rudra has no
           in-process multi-function driver, so this row is oracle-side
           context, never a head-to-head cell).
canon    : full canon-driver run (curl_decompile/httpd_decompile All mode)
           through /usr/bin/time -v — the project canon gate metric shape.

Every sweep records wall/user/sys via resource.getrusage(RUSAGE_CHILDREN)
deltas (zero per-child overhead) plus a load-average snapshot (31-user
shared host: user CPU time is the primary metric, wall is secondary).

Repeat protocol: run the same sweep >= 3 times, take the median (caller
drives repeats; this tool appends one JSON record per invocation to
--record-file).

Usage (run from the repo root):
  python3 tools/perfbench_sweep.py hermetic --side oracle \
      --runner /dev/shm/rudra-tests/perfbench/runner-work/golden_dump_1204 \
      --binary /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 --indices all \
      --record-file /dev/shm/rudra-tests/perfbench/sweeps.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_snapshot() -> dict:
    """One-line host-load snapshot (shared 31-user machine: mandatory)."""
    with open("/proc/loadavg") as handle:
        parts = handle.read().split()
    return {
        "loadavg_1m": float(parts[0]),
        "loadavg_5m": float(parts[1]),
        "loadavg_15m": float(parts[2]),
    }


def children_rusage() -> tuple[float, float, float]:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime, usage.ru_stime, usage.ru_maxrss


def run_child(argv: list[str], timeout: float, stdout_pipe: bool = False):
    """Run one child, return (status, wall, user, sys, stdout_bytes, stdout).

    Timeout kills the child (SIGKILL via subprocess.run semantics); both
    sides use the identical mechanism so the cap is symmetric.
    """
    user0, sys0, _ = children_rusage()
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE if stdout_pipe else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        wall = time.monotonic() - started
        out = proc.stdout if stdout_pipe else b""
        status = (
            "ok" if proc.returncode == 0 else f"exit_{proc.returncode}"
        )
    except subprocess.TimeoutExpired as expired:
        wall = time.monotonic() - started
        out = expired.stdout or b""
        status = "timeout"
    user1, sys1, _ = children_rusage()
    return status, wall, user1 - user0, sys1 - sys0, len(out), out


def list_oracle(runner: str, spec_root: str, binary: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        out = Path(handle.name)
    try:
        proc = subprocess.run(
            [runner, "list", spec_root, binary, str(out)],
            cwd=str(REPO_ROOT), capture_output=True, timeout=600,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"oracle list failed rc={proc.returncode}: "
                f"{proc.stderr.decode(errors='replace')[-800:]}")
        return json.loads(out.read_text())["functions"]
    finally:
        out.unlink(missing_ok=True)


def list_rudra(runner: str, binary: str) -> int:
    proc = subprocess.run(
        [runner, binary, "--list"],
        cwd=str(REPO_ROOT), capture_output=True, timeout=900,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"rudra --list failed rc={proc.returncode}: "
            f"{proc.stderr.decode(errors='replace')[-800:]}")
    # stderr lines look like: "[GEN]  12 0x   25a0   123 name"
    count = 0
    for line in proc.stderr.decode(errors="replace").splitlines():
        if line.startswith("[GEN]") and " functions discovered" in line:
            count = int(line.split()[1])
    return count


def sweep_hermetic(args) -> dict:
    spec_root = str((REPO_ROOT / args.spec_root).resolve())
    binary = args.binary
    if args.side == "oracle":
        functions = list_oracle(args.runner, spec_root, binary)
        count = len(functions)
    else:
        count = list_rudra(args.runner, binary)
        functions = None

    indices: list[int]
    if args.indices == "all":
        indices = list(range(count))
    elif args.indices.startswith("sample:"):
        want = int(args.indices.split(":")[1])
        if want >= count:
            indices = list(range(count))
        else:
            indices = [round(i * (count - 1) / (want - 1)) for i in range(want)]
            indices = sorted(set(indices))
    else:
        indices = [int(piece) for piece in args.indices.split(",")]

    def one_child(index: int) -> dict:
        if args.side == "oracle":
            with tempfile.NamedTemporaryFile(
                    suffix=".json", delete=False) as handle:
                out = Path(handle.name)
            try:
                argv = [args.runner, "one", spec_root, binary,
                        str(index), str(out)]
                status, wall, user, sys, _, _ = run_child(argv, args.timeout)
                if status == "ok":
                    try:
                        record = json.loads(out.read_text())
                        if record.get("status") != "OK":
                            status = f"oracle_{record.get('status')}"
                    except json.JSONDecodeError:
                        status = "oracle_bad_record"
            finally:
                out.unlink(missing_ok=True)
        else:
            argv = [args.runner, binary, "--one", str(index)]
            status, wall, user, sys, out_bytes, out = run_child(
                argv, args.timeout, stdout_pipe=True)
            if status == "ok" and b"/* ----" not in out:
                status = "no_output_block"
        entry = {"index": index, "status": status, "wall": round(wall, 6)}
        if args.workers == 1:
            # per-child user/sys attribution is only exact in serial mode
            entry["user"] = round(user, 6)
            entry["sys"] = round(sys, 6)
        return entry

    load_before = load_snapshot()
    sweep_started = time.monotonic()
    user0, sys0, _ = children_rusage()
    if args.workers == 1:
        per_index = [one_child(index) for index in indices]
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            per_index = list(pool.map(one_child, indices))
    wall_total = time.monotonic() - sweep_started
    user1, sys1, _ = children_rusage()
    load_after = load_snapshot()
    outcomes: dict[str, int] = {}
    for entry in per_index:
        outcomes[entry["status"]] = outcomes.get(entry["status"], 0) + 1
    return {
        "schema": 1,
        "side": args.side,
        "mode": "hermetic",
        "binary": binary,
        "binary_sha256": file_sha256(binary),
        "function_count": count,
        "n_indices": len(indices),
        "indices_head": indices[:5],
        "timeout": args.timeout,
        "workers": args.workers,
        "wall_total": round(wall_total, 3),
        "user_total": round(user1 - user0, 3),
        "sys_total": round(sys1 - sys0, 3),
        "outcomes": outcomes,
        "load_before": load_before,
        "load_after": load_after,
        "per_index": per_index,
    }


def sweep_time_v(argv: list[str], label: dict, timeout: float) -> dict:
    """One /usr/bin/time -v wrapped full run (allmode / canon tiers)."""
    load_before = load_snapshot()
    started = time.monotonic()
    proc = subprocess.run(
        ["/usr/bin/time", "-v", "-o", "/dev/shm/rudra-tests/perfbench/_timev.tmp"] + argv,
        cwd=str(REPO_ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
    )
    wall = time.monotonic() - started
    load_after = load_snapshot()
    fields = parse_timev_fields(
        Path("/dev/shm/rudra-tests/perfbench/_timev.tmp").read_text())

    def seconds(name: str) -> float:
        text = ""
        for key, value in fields.items():
            if key.startswith(name):
                text = value
                break
        return parse_timev_seconds(text)

    return {
        "schema": 1,
        **label,
        "argv": [str(piece) for piece in argv],
        "returncode": proc.returncode,
        "wall_total": round(wall, 3),
        "time_v_wall": seconds("Elapsed (wall clock) time"),
        "user_total": seconds("User time (seconds)"),
        "sys_total": seconds("System time (seconds)"),
        "max_rss_kb": int(fields.get("Maximum resident set size (kbytes)", "0") or 0),
        "load_before": load_before,
        "load_after": load_after,
    }


def parse_timev_fields(text: str) -> dict:
    """/usr/bin/time -v label lines -> {key: value}.

    The elapsed-time label itself contains colons ("Elapsed (wall clock) time
    (h:mm:ss or m:ss): 1:05.94"), so a naive partition-at-first-colon
    contaminates the value with the label tail; split at the last ": "
    instead.
    """
    fields = {}
    for line in text.splitlines():
        if ": " not in line:
            continue
        key, _, value = line.rpartition(": ")
        fields[key.strip()] = value.strip()
    return fields


def parse_timev_seconds(value: str) -> float:
    """'1:05.94' / '0:01:02.03' / '12.34' -> seconds."""
    pieces = value.replace("h", ":").replace("m", ":").replace("s", "")
    try:
        if ":" in pieces:
            parts = [float(piece) for piece in pieces.split(":")]
            while len(parts) < 3:
                parts.insert(0, 0.0)
            return parts[0] * 3600 + parts[1] * 60 + parts[2]
        return float(pieces)
    except ValueError:
        return 0.0


def file_sha256(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    hermetic = sub.add_parser("hermetic")
    hermetic.add_argument("--side", choices=["oracle", "rugra"], required=True)
    hermetic.add_argument("--runner", required=True)
    hermetic.add_argument("--spec-root", default="sleigh_specs")
    hermetic.add_argument("--binary", required=True)
    hermetic.add_argument("--indices", default="all",
                          help="all | sample:N | comma-separated indices")
    hermetic.add_argument("--timeout", type=float, default=20.0)
    hermetic.add_argument("--workers", type=int, default=1,
                          help="concurrent children (canon golden protocol "
                               "uses 12); per-child user/sys attribution is "
                               "only recorded at workers=1")
    hermetic.add_argument("--record-file", required=True)

    allmode = sub.add_parser("allmode")
    allmode.add_argument("--runner", required=True)
    allmode.add_argument("--spec-root", default="sleigh_specs")
    allmode.add_argument("--binary", required=True)
    allmode.add_argument("--timeout", type=float, default=7200.0)
    allmode.add_argument("--record-file", required=True)

    canon = sub.add_parser("canon")
    canon.add_argument("--runner", required=True)
    canon.add_argument("--binary", required=True,
                       help="label only — the canon drivers hardcode their "
                            "input and take no argv")
    canon.add_argument("--timeout", type=float, default=7200.0)
    canon.add_argument("--record-file", required=True)

    args = parser.parse_args()
    Path("/dev/shm/rudra-tests/perfbench").mkdir(parents=True, exist_ok=True)

    if args.command == "hermetic":
        record = sweep_hermetic(args)
    elif args.command == "allmode":
        spec_root = str((REPO_ROOT / args.spec_root).resolve())
        out_dir = Path("/dev/shm/rudra-tests/perfbench/allmode-out")
        out_dir.mkdir(parents=True, exist_ok=True)
        argv = [args.runner, "all", spec_root, args.binary, str(out_dir)]
        record = sweep_time_v(
            argv, {"side": "oracle", "mode": "allmode", "binary": args.binary,
                   "binary_sha256": file_sha256(args.binary)},
            args.timeout)
    else:
        # canon drivers hardcode their input binary and take no argv
        argv = [args.runner]
        record = sweep_time_v(
            argv, {"side": "rugra", "mode": "canon", "binary": args.binary,
                   "binary_sha256": file_sha256(args.binary)},
            args.timeout)

    with open(args.record_file, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    summary = {key: value for key, value in record.items()
               if key != "per_index"}
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
