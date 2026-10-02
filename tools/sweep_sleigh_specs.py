#!/usr/bin/env python3
"""Full locked-spec sweep: vendored Rust slacomp vs locked C++ sleigh_opt.

Lane SLEIGHP1 entry gate (ticket SLEIGH-RUSTIFY-PHASE1-0001). For every
.slaspec in the locked Ghidra 12.0.4 oracle tree (commit e40ed130...), this
driver compiles the spec with BOTH compilers and applies the three-part
content gate decided after Phase0 (BORROW-TRACK verdict):

  1. FORMAT_VERSION equality (byte 4 of the .sla header, slaformat.cc);
  2. decompressed element-stream sha256 equality (the canonical criterion:
     everything the compiler emits -- symbol table, constructors, decision
     trees, templates, space table, source file index -- lives in this
     stream; the raw deflated bytes legitimately differ because the C++
     side uses zlib C and the Rust side flate2/miniz_oxide);
  3. size band: inflated sizes must be equal; deflated sizes must agree
     within a band (default 8%; observed deltas across the 146-spec locked
     sweep are -0.15%..-4.77% -- the small 8/16-bit specs compress
     relatively better under flate2 than zlib; the inflated sha is the real
     content gate, the band only rejects pathological backend swaps).

Any spec whose three-part check does not fully pass is a divergence to be
root-caused against the locked oracle (fix the vendored compiler side).

Usage:
  python3 tools/sweep_sleigh_specs.py [--ghidra-dir DIR] [--workdir DIR]
      [--jobs N] [--md OUT.md] [--json OUT.json] [--slacomp-bin PATH]

Defaults: workdir /dev/shm/rudra-tests/sleighp1/sweep, md/json written into
the workdir. The oracle sleigh_opt is rebuilt from the locked tree via
`git archive` (bypassing the sparse checkout) every run; slacomp is built
from the vendored crates unless --slacomp-bin is given.
"""

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zlib
from pathlib import Path

LOCKED_ORACLE = "e40ed13014025f82488b1f8f7bca566894ac376b"
ARCHIVE_PATHS = [
    "Ghidra/Features/Decompiler/src/decompile/cpp",
    "Ghidra/Processors",
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inflate_sla(path: Path):
    """Return (format_version, inflated_bytes) for a .sla file."""
    raw = path.read_bytes()
    if raw[:3] != b"sla":
        raise ValueError(f"{path}: bad magic {raw[:4]!r}")
    version = raw[3]
    body = zlib.decompress(raw[4:])
    return version, body


def run(cmd, **kw):
    t0 = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, **kw)
    dt = time.monotonic() - t0
    return proc, dt


def compile_one(compiler, spec: Path, out: Path):
    """Compile one spec; return (exit, wall_seconds, stderr_tail)."""
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
    proc, dt = run([str(compiler), str(spec), str(out)])
    tail = proc.stderr.decode("utf-8", "replace")[-600:]
    return proc.returncode, dt, tail


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ghidra-dir", default=None)
    ap.add_argument("--workdir", default="/dev/shm/rudra-tests/sleighp1/sweep")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--md", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--slacomp-bin", default=None)
    ap.add_argument("--size-band-pct", type=float, default=8.0)
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    ghidra = Path(args.ghidra_dir) if args.ghidra_dir else repo_root / "ghidra"
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # --- oracle tree provenance -----------------------------------------
    head = subprocess.run(
        ["git", "-C", str(ghidra), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    if head != LOCKED_ORACLE:
        print(f"sweep: ghidra HEAD={head} != locked {LOCKED_ORACLE}", file=sys.stderr)
        return 2

    extract = workdir / "locked"
    if not (extract / "Ghidra" / "Processors").exists():
        archive = workdir / "locked.tar"
        subprocess.run(
            ["git", "-C", str(ghidra), "archive", "--format=tar",
             f"--output={archive}", LOCKED_ORACLE] + ARCHIVE_PATHS, check=True)
        extract.mkdir(parents=True, exist_ok=True)
        subprocess.run(["tar", "-xf", str(archive), "-C", str(extract)], check=True)
        archive.unlink()

    cpp_dir = extract / "Ghidra/Features/Decompiler/src/decompile/cpp"
    processors = extract / "Ghidra/Processors"

    # --- oracle compiler (C++ sleigh_opt) --------------------------------
    sleigh_opt = cpp_dir / "sleigh_opt"
    if not sleigh_opt.exists():
        t0 = time.monotonic()
        subprocess.run(
            ["make", "-s", "-C", str(cpp_dir), f"-j{args.jobs}", "sleigh_opt"],
            check=True)
        oracle_build_s = time.monotonic() - t0
    else:
        oracle_build_s = None

    # --- rust compiler (vendored slacomp) ---------------------------------
    if args.slacomp_bin:
        slacomp = Path(args.slacomp_bin)
        rust_build_s = None
    else:
        t0 = time.monotonic()
        subprocess.run(
            ["cargo", "build", "--release", "-p", "kuna-slacomp", "--bin", "slacomp"],
            cwd=repo_root, check=True,
            env={**os.environ, "CARGO_TARGET_DIR": os.environ.get(
                "CARGO_TARGET_DIR", str(repo_root / "target"))})
        rust_build_s = time.monotonic() - t0
        slacomp = Path(os.environ.get("CARGO_TARGET_DIR", str(repo_root / "target"))
                       ) / "release" / "slacomp"

    # --- enumerate specs ---------------------------------------------------
    specs = sorted(processors.rglob("*.slaspec"))
    print(f"sweep: {len(specs)} .slaspec under {processors}")

    out_root = workdir / "out"
    out_root.mkdir(parents=True, exist_ok=True)

    def key(spec: Path) -> str:
        return str(spec.relative_to(processors))

    def work(spec: Path):
        k = key(spec).replace("/", "__")
        o_out = out_root / f"{k}.oracle.sla"
        r_out = out_root / f"{k}.rust.sla"
        o_rc, o_dt, o_err = compile_one(sleigh_opt, spec, o_out)
        r_rc, r_dt, r_err = compile_one(slacomp, spec, r_out)
        row = {
            "spec": key(spec),
            "oracle_rc": o_rc, "rust_rc": r_rc,
            "oracle_s": round(o_dt, 3), "rust_s": round(r_dt, 3),
        }
        if o_rc == 0 and r_rc == 0:
            o_ver, o_body = inflate_sla(o_out)
            r_ver, r_body = inflate_sla(r_out)
            row.update({
                "format_version": {"oracle": o_ver, "rust": r_ver},
                "inflated_sha256": {"oracle": hashlib.sha256(o_body).hexdigest(),
                                     "rust": hashlib.sha256(r_body).hexdigest()},
                "inflated_size": {"oracle": len(o_body), "rust": len(r_body)},
                "deflated_size": {"oracle": o_out.stat().st_size,
                                   "rust": r_out.stat().st_size},
            })
            delta_pct = 100.0 * (r_out.stat().st_size - o_out.stat().st_size) \
                / o_out.stat().st_size
            row["deflated_delta_pct"] = round(delta_pct, 3)
            checks = {
                "format_version": o_ver == r_ver,
                "inflated_sha": row["inflated_sha256"]["oracle"]
                                == row["inflated_sha256"]["rust"],
                "size": (len(o_body) == len(r_body)
                         and abs(delta_pct) <= args.size_band_pct),
            }
            row["checks"] = checks
            row["verdict"] = "MATCH" if all(checks.values()) else "MISMATCH"
        else:
            # Both-fail parity is recorded but is NOT a content MATCH: no
            # stream exists to compare. Divergent rc = hard MISMATCH.
            row["verdict"] = "BOTH_FAIL" if (o_rc != 0 and r_rc != 0) else "MISMATCH"
            row["oracle_err_tail"] = o_err[-300:]
            row["rust_err_tail"] = r_err[-300:]
        return row

    t0 = time.monotonic()
    rows = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        for row in ex.map(work, specs):
            rows.append(row)
            mark = row["verdict"]
            if mark != "MATCH":
                print(f"  !! {row['spec']}: {mark}", file=sys.stderr)
    sweep_s = time.monotonic() - t0

    n_match = sum(1 for r in rows if r["verdict"] == "MATCH")
    n_bf = sum(1 for r in rows if r["verdict"] == "BOTH_FAIL")
    n_mm = sum(1 for r in rows if r["verdict"] == "MISMATCH")
    summary = {
        "total": len(rows), "match": n_match, "both_fail": n_bf,
        "mismatch": n_mm, "sweep_seconds": round(sweep_s, 1),
        "oracle_build_seconds": oracle_build_s,
        "rust_build_seconds": rust_build_s,
        "slacomp_bin": str(slacomp), "sleigh_opt_bin": str(sleigh_opt),
        "size_band_pct": args.size_band_pct,
        "ghidra_head": head,
    }
    print(json.dumps(summary, indent=2))

    json_path = Path(args.json) if args.json else workdir / "sweep_results.json"
    json_path.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))

    md_path = Path(args.md) if args.md else workdir / "sweep_results.md"
    with open(md_path, "w") as f:
        f.write(f"# SLEIGH 146-spec sweep ({n_match}/{len(rows)} MATCH)\n\n")
        f.write(json.dumps(summary, indent=1) + "\n\n")
        f.write("| spec | verdict | ver(o/r) | inflated B (o/r) | deflated B (o/r) | Δdefl% | t C++ s | t Rust s |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in rows:
            if r["verdict"] == "MATCH":
                f.write(f"| {r['spec']} | MATCH | {r['format_version']['oracle']}/{r['format_version']['rust']} "
                        f"| {r['inflated_size']['oracle']}/{r['inflated_size']['rust']} "
                        f"| {r['deflated_size']['oracle']}/{r['deflated_size']['rust']} "
                        f"| {r['deflated_delta_pct']} | {r['oracle_s']} | {r['rust_s']} |\n")
            else:
                f.write(f"| {r['spec']} | **{r['verdict']}** | rc {r['oracle_rc']}/{r['rust_rc']} | - | - | - "
                        f"| {r['oracle_s']} | {r['rust_s']} |\n")
    print(f"sweep: wrote {json_path} and {md_path}")
    return 0 if (n_mm == 0) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
