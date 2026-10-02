#!/usr/bin/env python3
"""perfbench_report.py — median/ratio tables from perfbench_sweep.py JSONL.

Groups sweeps by (tier, side, binary, workers), takes medians over repeats,
and prints the head-to-head table plus per-run load provenance.  Read-only
consumer of sweeps.jsonl — no measurement logic here.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict

DISPLAY = {
    "examples/curl": "curl(74)",
    "examples/httpd": "httpd(790)",
    "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0": "libsqlite3.so(1385)",
    "/usr/lib/x86_64-linux-gnu/libLLVM-15.so.1": "libLLVM-15.so(35387,s100)",
}


def main() -> int:
    records = []
    for path in sys.argv[1:]:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for record in records:
        mode = record.get("mode")
        if mode == "hermetic":
            workers = record.get("workers", 1)
            key = ("P1" if workers == 12 else "P1B-serial",
                   record["side"], record["binary"], workers)
        elif mode == "allmode":
            key = ("P2-allmode", record["side"], record["binary"], 1)
        elif mode == "canon":
            key = ("P3-canon", record["side"], record["binary"], 1)
        else:
            continue
        groups[key].append(record)

    print("=" * 100)
    print("PERF-BENCH medians (user CPU = primary; wall = secondary; load recorded per run)")
    print("=" * 100)
    pairs: dict[tuple, dict] = {}
    for key in sorted(groups):
        runs = groups[key]
        tier, side, binary, workers = key
        n = runs[0].get("n_indices") or runs[0].get("function_count", "?")
        med = {
            "wall": statistics.median(r["wall_total"] for r in runs),
            "user": statistics.median(r["user_total"] for r in runs),
            "sys": statistics.median(r["sys_total"] for r in runs),
            "runs": len(runs),
            "n": n,
            "load1m": [r["load_before"]["loadavg_1m"] for r in runs],
            "outcomes": runs[len(runs) // 2].get("outcomes", {}),
            "rss_kb": max(
                (r.get("max_rss_kb") or 0) for r in runs) or None,
        }
        pairs.setdefault((tier, binary), {})[side] = med
        load_txt = "/".join(f"{value:.0f}" for value in med["load1m"])
        print(f"{tier:10s} {side:6s} {DISPLAY.get(binary, binary)[:28]:28s} "
              f"n={med['n']:>5} reps={med['runs']} "
              f"wall={med['wall']:8.1f} user={med['user']:8.1f} "
              f"sys={med['sys']:6.1f} load1m={load_txt}")

    print("-" * 100)
    print("head-to-head ratios (rudra / oracle), CPU(user+sys) primary:")
    for (tier, binary), sides in sorted(pairs.items()):
        if "oracle" not in sides or "rugra" not in sides:
            continue
        o, r = sides["oracle"], sides["rugra"]
        cpu_o = o["user"] + o["sys"]
        cpu_r = r["user"] + r["sys"]
        per_fn_o = cpu_o / o["n"]
        per_fn_r = cpu_r / r["n"]
        print(f"{tier:10s} {DISPLAY.get(binary, binary)[:28]:28s} "
              f"cpu_ratio={cpu_r / cpu_o:5.2f}x  "
              f"per_fn: oracle={per_fn_o * 1000:6.0f}ms rudra={per_fn_r * 1000:6.0f}ms  "
              f"wall_ratio={r['wall'] / o['wall']:5.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
