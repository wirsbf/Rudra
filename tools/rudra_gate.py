#!/usr/bin/env python3
"""Run Rudra's tiered, impact-aware validation gates with JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from .select_fixtures import selection_document
except ImportError:
    from select_fixtures import selection_document


@dataclass(frozen=True)
class Check:
    check_id: str
    command: list[str]
    timeout_seconds: int
    category: str = "gate"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def git_bytes(root: Path, args: list[str]) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def working_tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(git_bytes(root, ["rev-parse", "HEAD"]))
    digest.update(git_bytes(root, ["diff", "--binary", "HEAD", "--", ".", ":(exclude)ghidra"]))
    untracked = git_bytes(root, ["ls-files", "--others", "--exclude-standard"]).decode().splitlines()
    for relative in sorted(untracked):
        path = root / relative
        if not path.is_file():
            continue
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def changed_source_paths(selection: dict[str, object], root: Path) -> list[str]:
    return sorted(
        {
            str(change["path"])
            for change in selection["changed"]
            if str(change["path"]).startswith("src/")
            and str(change["path"]).endswith(".rs")
            and (root / str(change["path"])).is_file()
        }
    )


def checks_for_tier(
    tier: str, python: str, root: Path, selection: dict[str, object]
) -> list[Check]:
    changed_sources = changed_source_paths(selection, root)
    edit = [Check("gate-health", [python, "tools/check_gate_health.py"], 30)]
    if changed_sources:
        edit.extend(
            [
                Check(
                    "annotations-changed",
                    [python, "tools/check_ghidra_annotations.py", *changed_sources],
                    60,
                ),
                Check(
                    "refs-changed",
                    [python, "tools/check_ghidra_refs.py", "--strict", *changed_sources],
                    60,
                ),
            ]
        )
    edit.append(
        Check(
            "fast-check-lib",
            [python, "tools/rudra_build.py", "check", "--cache", "auto"],
            600,
            "build",
        )
    )
    if tier == "edit":
        return edit

    commit = [
        Check("gate-health", [python, "tools/check_gate_health.py"], 30),
        Check("doc-sync", [python, "tools/check_doc_sync.py"], 60),
        Check("annotations-all", [python, "tools/check_ghidra_annotations.py", "--all"], 120),
        Check("refs-all", [python, "tools/check_ghidra_refs.py", "--all", "--strict"], 120),
        Check("evidence-self-test", [python, "tools/check_alignment_evidence.py", "--self-test"], 30),
        Check("ledger-check", [python, "tools/generate_function_ledger.py", "--check"], 180),
        Check(
            "fast-check-all",
            [python, "tools/rudra_build.py", "check", "--all-targets", "--cache", "auto"],
            900,
            "build",
        ),
    ]
    if tier == "commit":
        return commit

    wave = [
        *commit,
        Check("tests-all", ["cargo", "test", "--offline", "--locked", "--all-targets"], 1200, "test"),
        Check(
            "curl-example",
            ["cargo", "run", "--offline", "--locked", "--release", "--example", "curl_decompile"],
            1200,
            "regression",
        ),
        Check(
            "httpd-example",
            ["cargo", "run", "--offline", "--locked", "--release", "--example", "httpd_decompile"],
            1200,
            "regression",
        ),
        Check("curl-syntax", [python, "tools/audit_syntax.py", "result/curl_cur.c"], 300, "regression"),
        Check(
            "curl-golden-summary",
            [
                python,
                "tools/compare_ghidra.py",
                "result/curl_cur.c",
                "tests/golden/ghidra_curl.c",
                "--summary-only",
            ],
            300,
            "diagnostic",
        ),
    ]
    if tier == "wave":
        return wave
    return [
        *wave,
        Check(
            "cold-release-all",
            [
                python,
                "tools/rudra_build.py",
                "build",
                "--profile",
                "release",
                "--all-targets",
                "--fresh-target",
                "--cache",
                "auto",
            ],
            3600,
            "build",
        ),
    ]


def merged_cache_group(
    defaults: dict[str, object], fixture: dict[str, object], group: str
) -> dict[str, str]:
    merged = {
        str(label): str(path)
        for label, path in dict(defaults.get(group, {})).items()
    }
    for label, path in dict(fixture.get(group, {})).items():
        label = str(label)
        if label in merged:
            raise ValueError(f"duplicate fixture cache {group} label: {label}")
        merged[label] = str(path)
    return dict(sorted(merged.items()))


def cached_fixture_command(
    python: str,
    selection: dict[str, object],
    fixture: dict[str, object],
    force_run: bool,
) -> list[str]:
    config = fixture.get("cache")
    if not isinstance(config, dict):
        return [str(argument) for argument in fixture["runner"]]
    defaults = dict(selection.get("cache_defaults", {}))
    command = [
        python,
        "tools/oracle_cache.py",
        "capture",
        "--metadata",
        str(config["metadata"]),
        "--timeout",
        str(int(fixture["timeout_seconds"])),
    ]
    for group, option in (
        ("inputs", "--input"),
        ("tools", "--tool"),
        ("comparands", "--comparand"),
    ):
        for label, path in merged_cache_group(defaults, config, group).items():
            command.extend([option, f"{label}={path}"])
    context = {
        "fixture_id": str(fixture["id"]),
        "evidence_status": str(fixture["evidence_status"]),
        **{str(key): str(value) for key, value in dict(config.get("context", {})).items()},
    }
    for key, value in sorted(context.items()):
        command.extend(["--context", f"{key}={value}"])
    environment = set(str(name) for name in defaults.get("environment", []))
    environment.update(str(name) for name in config.get("environment", []))
    for name in sorted(environment):
        command.extend(["--env", name])
    if force_run:
        command.append("--force-run")
    command.append("--")
    command.extend(str(argument) for argument in fixture["runner"])
    return command


def fixture_checks(
    selection: dict[str, object],
    requested: list[str],
    python: str,
    use_cache: bool,
    force_run: bool,
) -> list[Check]:
    selected = selection["selected_fixtures"]
    known = {str(fixture["id"]) for fixture in selected}
    missing = sorted(set(requested) - known)
    if missing:
        raise ValueError(f"requested fixture is not selected for this impact/tier: {missing}")
    checks = []
    for fixture in selected:
        fixture_id = str(fixture["id"])
        if requested and fixture_id not in requested:
            continue
        command = (
            cached_fixture_command(python, selection, fixture, force_run)
            if use_cache
            else [str(argument) for argument in fixture["runner"]]
        )
        checks.append(
            Check(
                f"fixture:{fixture_id}",
                command,
                int(fixture["timeout_seconds"]) + (60 if use_cache else 0),
                "fixture",
            )
        )
    return checks


def command_input_hash(tree_hash: str, check: Check) -> str:
    digest = hashlib.sha256()
    digest.update(tree_hash.encode("ascii"))
    for argument in check.command:
        encoded = argument.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def output_tail(data: bytes, limit: int = 16384) -> str:
    return data[-limit:].decode("utf-8", errors="replace")


def run_check(
    root: Path,
    check: Check,
    tree_hash: str,
    environment: dict[str, str],
    verbose: bool,
) -> dict[str, object]:
    print(f"[gate] START {check.check_id}: {' '.join(check.command)}", flush=True)
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            check.command,
            cwd=root,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=check.timeout_seconds,
        )
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as error:
        return_code = 124
        timed_out = True
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    elapsed = time.monotonic() - started
    if verbose or return_code != 0:
        if stdout:
            sys.stdout.write(stdout.decode("utf-8", errors="replace"))
        if stderr:
            sys.stderr.write(stderr.decode("utf-8", errors="replace"))
    status = "PASS" if return_code == 0 else "FAIL"
    print(f"[gate] {status} {check.check_id} ({elapsed:.3f}s)", flush=True)
    return {
        "id": check.check_id,
        "category": check.category,
        "command": check.command,
        "timeout_seconds": check.timeout_seconds,
        "timed_out": timed_out,
        "started_at": started_at,
        "elapsed_seconds": round(elapsed, 6),
        "return_code": return_code,
        "input_sha256": command_input_hash(tree_hash, check),
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_tail": output_tail(stdout),
        "stderr_tail": output_tail(stderr),
    }


def atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def selector_args(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        staged=args.staged,
        base=args.base,
        path=args.path,
        function=args.function,
        tier=args.tier,
    )


def self_test() -> int:
    root = Path(__file__).resolve().parent.parent
    python = sys.executable
    selection = {"changed": []}
    assert [check.check_id for check in checks_for_tier("edit", python, root, selection)] == [
        "gate-health",
        "fast-check-lib",
    ]
    assert checks_for_tier("commit", python, root, selection)[-1].check_id == "fast-check-all"
    assert checks_for_tier("nightly", python, root, selection)[-1].check_id == "cold-release-all"
    cache_selection = {
        "cache_defaults": {
            "tools": {"registry": "tests/oracle/fixture_registry.json"},
            "comparands": {"rust": "src"},
            "environment": ["RUSTFLAGS"],
        }
    }
    cached = cached_fixture_command(
        python,
        cache_selection,
        {
            "id": "sample",
            "runner": ["tools/run_decompress_oracle.sh"],
            "timeout_seconds": 10,
            "evidence_status": "MATCH",
            "cache": {
                "metadata": "tests/oracle/decompress_1204.metadata.json",
                "inputs": {"fixture": "tests/oracle/decompress_1204.cc"},
                "tools": {"runner": "tools/run_decompress_oracle.sh"},
            },
        },
        False,
    )
    assert cached[:3] == [python, "tools/oracle_cache.py", "capture"]
    assert cached[-2:] == ["--", "tools/run_decompress_oracle.sh"]
    environment = dict(os.environ)
    passing = run_check(
        root,
        Check("self-pass", [python, "-c", "print('ok')"], 10),
        "0" * 64,
        environment,
        False,
    )
    assert passing["return_code"] == 0 and passing["stdout_sha256"] == sha256_bytes(b"ok\n")
    timeout = run_check(
        root,
        Check("self-timeout", [python, "-c", "import time; time.sleep(1)"], 0.01),
        "0" * 64,
        environment,
        False,
    )
    assert timeout["return_code"] == 124 and timeout["timed_out"]
    print("rudra_gate: self-test OK")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tier", choices=("edit", "commit", "wave", "nightly"), nargs="?", default="edit")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--base")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--function", action="append", default=[])
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--no-fixtures", action="store_true")
    cache = parser.add_mutually_exclusive_group()
    cache.add_argument("--no-cache", action="store_true")
    cache.add_argument("--refresh-fixtures", action="store_true")
    parser.add_argument("--keep-going", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    python = sys.executable
    try:
        selection = selection_document(root, selector_args(args))
        checks = checks_for_tier(args.tier, python, root, selection)
        if not args.no_fixtures and args.tier != "edit":
            checks.extend(
                fixture_checks(
                    selection,
                    args.fixture,
                    python,
                    not args.no_cache,
                    args.refresh_fixtures,
                )
            )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"rudra_gate: {error}", file=sys.stderr)
        return 1

    report: dict[str, object] = {
        "schema": 1,
        "tier": args.tier,
        "dry_run": args.dry_run,
        "selection": selection,
        "checks": [],
        "status": "PENDING",
    }
    if args.tier in ("commit", "wave", "nightly") and selection["uncovered_source_changes"]:
        report["status"] = "COVERAGE_GAP"
        if args.report:
            atomic_json(args.report.resolve(), report)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return 2

    if args.dry_run:
        report["checks"] = [
            {
                "id": check.check_id,
                "category": check.category,
                "command": check.command,
                "timeout_seconds": check.timeout_seconds,
            }
            for check in checks
        ]
        report["status"] = "DRY_RUN"
        if args.report:
            atomic_json(args.report.resolve(), report)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return 0

    try:
        tree_hash = working_tree_fingerprint(root)
    except RuntimeError as error:
        print(f"rudra_gate: {error}", file=sys.stderr)
        return 1
    environment = dict(os.environ)
    environment.update({"CARGO_NET_OFFLINE": "true", "LC_ALL": "C", "TZ": "UTC"})
    failed = False
    for check in checks:
        result = run_check(root, check, tree_hash, environment, args.verbose)
        report["checks"].append(result)
        if result["return_code"] != 0:
            failed = True
            if not args.keep_going:
                break
    report["working_tree_sha256"] = tree_hash
    report["status"] = "FAIL" if failed else "PASS"
    if args.report:
        atomic_json(args.report.resolve(), report)
    print(f"rudra_gate: {report['status']} tier={args.tier} checks={len(report['checks'])}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
