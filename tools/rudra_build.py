#!/usr/bin/env python3
"""Reproducible, cache-aware Cargo entry point for Rudra development."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable


BUILD_ENV_KEYS = (
    "AR",
    "CC",
    "CFLAGS",
    "CXX",
    "CXXFLAGS",
    "RANLIB",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_DIR",
)
FINGERPRINT_FILES = ("Cargo.toml", "Cargo.lock", "build.rs")
BUILD_INPUT_ROOTS = ("src", "sleigh_shim")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fingerprint(root: Path) -> dict[str, str]:
    return {
        relative: sha256_file(root / relative)
        for relative in FINGERPRINT_FILES
        if (root / relative).is_file()
    }


def build_input_digest(root: Path) -> tuple[str, int]:
    paths = [root / relative for relative in FINGERPRINT_FILES]
    for relative in BUILD_INPUT_ROOTS:
        paths.extend(path for path in (root / relative).rglob("*") if path.is_file())
    cpp_root = root / "ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
    paths.extend(path for path in cpp_root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    unique_paths = sorted(set(paths))
    for path in unique_paths:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest(), len(unique_paths)


def run_text(command: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd="/",
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout.strip()


def available_programs(names: Iterable[str]) -> dict[str, str]:
    return {name: path for name in names if (path := shutil.which(name))}


def choose_cache(preference: str, available: dict[str, str]) -> tuple[str, str | None]:
    if preference == "none":
        return "none", None
    if preference in ("sccache", "ccache"):
        path = available.get(preference)
        if path is None:
            raise ValueError(f"requested cache tool is unavailable: {preference}")
        return preference, path
    for name in ("sccache", "ccache"):
        if name in available:
            return name, available[name]
    return "none", None


def git_value(root: Path, args: list[str], default: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else default


def controlled_environment(
    root: Path,
    jobs: int,
    cache_name: str,
    cache_path: str | None,
    target_dir: Path | None,
    remap_paths: bool,
) -> dict[str, str]:
    env = dict(os.environ)
    for key in BUILD_ENV_KEYS:
        env.pop(key, None)
    env.update(
        {
            "CARGO_BUILD_JOBS": str(jobs),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "LC_ALL": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": git_value(root, ["show", "-s", "--format=%ct", "HEAD"], "0"),
        }
    )
    rustc = shutil.which("rustc")
    cc = shutil.which("cc") or shutil.which("gcc")
    cxx = shutil.which("c++") or shutil.which("g++")
    ar = shutil.which("ar")
    if rustc:
        env["RUSTC"] = rustc
    if ar:
        env["AR"] = ar
    if target_dir is not None:
        env["CARGO_TARGET_DIR"] = str(target_dir)

    rust_flags: list[str] = []
    c_flags: list[str] = []
    if remap_paths:
        rust_flags.append(f"--remap-path-prefix={root}=/rudra")
        if os.name != "nt":
            c_flags.extend(
                [
                    f"-ffile-prefix-map={root}=/rudra",
                    f"-fdebug-prefix-map={root}=/rudra",
                ]
            )
    if rust_flags:
        env["RUSTFLAGS"] = " ".join(rust_flags)
    if c_flags:
        env["CFLAGS"] = " ".join(c_flags)
        env["CXXFLAGS"] = " ".join(c_flags)

    if cache_name == "sccache" and cache_path:
        env["RUSTC_WRAPPER"] = cache_path
        if cc:
            env["CC"] = f"{cache_path} {cc}"
        if cxx:
            env["CXX"] = f"{cache_path} {cxx}"
    elif cache_name == "ccache" and cache_path:
        env.update(
            {
                "CCACHE_BASEDIR": str(root),
                "CCACHE_COMPILERCHECK": "content",
                "CCACHE_NOHASHDIR": "true",
            }
        )
        if cc:
            env["CC"] = f"{cache_path} {cc}"
        if cxx:
            env["CXX"] = f"{cache_path} {cxx}"
    else:
        if cc:
            env["CC"] = cc
        if cxx:
            env["CXX"] = cxx
    return env


def cargo_command(args: argparse.Namespace, cargo: str) -> list[str]:
    command = [cargo, args.action, "--locked", "--offline"]
    if args.profile:
        command.extend(["--profile", args.profile])
    if args.all_targets:
        command.append("--all-targets")
    if args.no_default_features:
        command.append("--no-default-features")
    if args.features:
        command.extend(["--features", args.features])
    command.extend(args.cargo_args)
    return command


def cache_stats(cache_name: str, cache_path: str | None, env: dict[str, str]) -> str:
    if not cache_path:
        return ""
    if cache_name == "sccache":
        return run_text([cache_path, "--show-stats"], env)
    if cache_name == "ccache":
        return run_text([cache_path, "--show-stats"], env)
    return ""


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def self_test() -> int:
    assert choose_cache("auto", {"ccache": "/x/ccache"}) == ("ccache", "/x/ccache")
    assert choose_cache("auto", {"sccache": "/x/sccache", "ccache": "/x/ccache"}) == (
        "sccache",
        "/x/sccache",
    )
    assert choose_cache("none", {"sccache": "/x/sccache"}) == ("none", None)
    try:
        choose_cache("sccache", {})
    except ValueError:
        pass
    else:
        raise AssertionError("missing requested cache must fail")
    print("rudra_build: self-test OK")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    cargo_args: list[str] = []
    if "--" in argv:
        separator = argv.index("--")
        cargo_args = argv[separator + 1 :]
        argv = argv[:separator]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "build", "test"), nargs="?", default="check")
    parser.add_argument("--profile", default="fast-release")
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument("--cache", choices=("auto", "none", "sccache", "ccache"), default="auto")
    parser.add_argument("--all-targets", action="store_true")
    parser.add_argument("--features", default="")
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--fresh-target", action="store_true")
    parser.add_argument("--no-remap-paths", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    args.cargo_args = cargo_args
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.fresh_target and args.target_dir:
        parser.error("--fresh-target and --target-dir are mutually exclusive")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(__file__).resolve().parent.parent
    cargo = shutil.which("cargo")
    if cargo is None:
        print("cargo is unavailable", file=sys.stderr)
        return 2
    available = available_programs(("sccache", "ccache"))
    try:
        cache_name, cache_path = choose_cache(args.cache, available)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    temporary_target: tempfile.TemporaryDirectory[str] | None = None
    target_dir = args.target_dir.resolve() if args.target_dir else None
    if args.fresh_target:
        temporary_target = tempfile.TemporaryDirectory(prefix="rudra-build-")
        target_dir = Path(temporary_target.name)
    env = controlled_environment(
        root,
        args.jobs,
        cache_name,
        cache_path,
        target_dir,
        not args.no_remap_paths,
    )
    command = cargo_command(args, cargo)
    tool_versions = {
        "cargo": run_text([cargo, "--version", "--verbose"], env),
        "rustc": run_text([env.get("RUSTC", "rustc"), "-vV"], env),
        "cc": run_text([shutil.which("cc") or "cc", "--version"], env).splitlines()[:1],
        "cxx": run_text([shutil.which("c++") or "c++", "--version"], env).splitlines()[:1],
        "cache": run_text([cache_path, "--version"], env) if cache_path else "none",
    }
    input_digest, input_count = build_input_digest(root)
    started = time.monotonic()
    if args.dry_run:
        return_code = 0
    else:
        return_code = subprocess.run(command, cwd=root, env=env, check=False).returncode
    elapsed = time.monotonic() - started
    report: dict[str, object] = {
        "schema": 1,
        "action": args.action,
        "cache": {"kind": cache_name, "path": cache_path, "stats": cache_stats(cache_name, cache_path, env)},
        "command": command,
        "dry_run": args.dry_run,
        "elapsed_seconds": round(elapsed, 6),
        "git_commit": git_value(root, ["rev-parse", "HEAD"], "NO_GIT"),
        "git_status": git_value(root, ["status", "--short", "--untracked-files=all"], ""),
        "build_input_digest": input_digest,
        "build_input_file_count": input_count,
        "inputs": source_fingerprint(root),
        "jobs": args.jobs,
        "profile": args.profile,
        "return_code": return_code,
        "target_dir": str(target_dir) if target_dir else None,
        "tools": tool_versions,
    }
    if args.report:
        write_report(args.report.resolve(), report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if temporary_target is not None:
        temporary_target.cleanup()
    return return_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
