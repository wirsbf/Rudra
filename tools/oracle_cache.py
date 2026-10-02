#!/usr/bin/env python3
"""Content-addressed, fail-closed cache for Rugra oracle artifacts.

Captured commands execute under exactly the environment recorded in the
provenance (``Popen(env=...)`` is the declared snapshot; undeclared ambient
variables are invisible, PATH-like content changes rotate the key). Ambient
environment or provenance drift observed after execution refuses to store,
and every restore cross-checks the full artifact bundle closure (hash, size,
structure, missing/extra) before a single byte is published.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


LOCKED_ORACLE = "e40ed13014025f82488b1f8f7bca566894ac376b"
SCHEMA = 1
DEFAULT_ENV_KEYS = (
    "AR",
    "CARGO",
    "CARGO_HOME",
    "CC",
    "CFLAGS",
    "CXX",
    "CXXFLAGS",
    "LDFLAGS",
    "PATH",
    "PKG_CONFIG_PATH",
    "RANLIB",
    "RUSTC",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
)
# Ambient variables that execution itself depends on even when the caller did
# not declare them (cargo/rustc default to $HOME, mktemp honors TMPDIR,
# dynamic loaders honor LD_LIBRARY_PATH, GCC locale catalogs honor LANG/LC_*).
# They are always declared for capture so the executed environment and the
# provenance environment stay byte-identical.
EXEC_ENV_KEYS = (
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LD_LIBRARY_PATH",
    "TMPDIR",
)


class CacheError(RuntimeError):
    """A cache entry or its provenance failed validation."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_file_record(path: Path) -> tuple[int, str]:
    before = path.stat()
    digest = sha256_file(path)
    after = path.stat()
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise CacheError(f"file changed while being fingerprinted: {path}")
    return after.st_size, digest


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CacheError(f"cannot read JSON {path}: {error}") from error


def oracle_commit(metadata: dict[str, Any]) -> str:
    oracle = metadata.get("oracle")
    if isinstance(oracle, dict):
        commit = oracle.get("commit")
    else:
        commit = metadata.get("oracle_commit")
    if commit != LOCKED_ORACLE:
        raise CacheError(
            f"metadata oracle commit must be {LOCKED_ORACLE}, got {commit!r}"
        )
    return str(commit)


def validate_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise CacheError("metadata root must be an object")
    oracle_commit(metadata)
    for field in ("architecture", "compiler_spec", "analysis_options"):
        if field not in metadata or metadata[field] in (None, "", {}, []):
            raise CacheError(f"metadata is missing required field {field!r}")
    return metadata


def parse_assignment(value: str, option: str) -> tuple[str, str]:
    if "=" not in value:
        raise CacheError(f"{option} expects LABEL=PATH, got {value!r}")
    label, raw_path = value.split("=", 1)
    if not label or not raw_path:
        raise CacheError(f"{option} expects non-empty LABEL=PATH")
    return label, raw_path


def display_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def user_path(root: Path, raw_path: str | Path) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else root / path


def fingerprint_path(label: str, path: Path, root: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise CacheError(f"provenance path must not be a symlink: {path}")
    if path.is_file():
        size, digest = stable_file_record(path)
        return {
            "label": label,
            "path": display_path(path, root),
            "kind": "file",
            "size": size,
            "sha256": digest,
        }
    if not path.is_dir():
        raise CacheError(f"provenance path is not a regular file or directory: {path}")
    files: list[dict[str, Any]] = []
    for candidate in sorted(path.rglob("*")):
        if candidate.is_symlink():
            raise CacheError(f"provenance tree must not contain symlinks: {candidate}")
        if not candidate.is_file():
            continue
        size, digest = stable_file_record(candidate)
        files.append(
            {
                "path": candidate.relative_to(path).as_posix(),
                "size": size,
                "sha256": digest,
            }
        )
    return {
        "label": label,
        "path": display_path(path, root),
        "kind": "directory",
        "files": files,
        "tree_sha256": sha256_bytes(canonical_bytes(files)),
    }


def fingerprint_group(values: list[str], option: str, root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    labels: set[str] = set()
    for value in values:
        label, raw_path = parse_assignment(value, option)
        if label in labels:
            raise CacheError(f"duplicate {option} label {label!r}")
        labels.add(label)
        records.append(fingerprint_path(label, user_path(root, raw_path), root))
    return sorted(records, key=lambda record: str(record["label"]))


def parse_context(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, item = parse_assignment(value, "--context")
        if key in result:
            raise CacheError(f"duplicate --context key {key!r}")
        result[key] = item
    return dict(sorted(result.items()))


def capture_env_names(extra: list[str]) -> list[str]:
    """Every environment variable declared for a capture execution.

    The child environment handed to ``Popen(env=...)`` is derived from exactly
    this snapshot: a name with a ``None`` value is absent for the child, and
    nothing outside this set is ever visible to the captured command.
    """
    return sorted(set(DEFAULT_ENV_KEYS).union(EXEC_ENV_KEYS).union(extra))


def environment_snapshot(names: list[str]) -> dict[str, str | None]:
    """Materialize the declared environment once; ``None`` marks absence."""
    return {name: os.environ.get(name) for name in names}


def child_environment(snapshot: dict[str, str | None]) -> dict[str, str]:
    """The exact ``Popen(env=...)`` mapping for a provenance snapshot.

    Inverse property: the child observes a variable if and only if it is
    declared with a non-``None`` value in the provenance environment.
    """
    return {
        name: value
        for name, value in snapshot.items()
        if isinstance(value, str)
    }


def environment_drift(snapshot: dict[str, str | None]) -> list[str]:
    """Declared variables whose ambient value moved away from the snapshot."""
    return sorted(
        name for name, value in snapshot.items() if os.environ.get(name) != value
    )


def resolve_executable(
    program: str, exec_env: dict[str, str], root: Path
) -> Path | None:
    """Resolve argv0 exactly the way ``os.execvpe`` will for the child.

    PATH lookup uses the child environment's PATH (falling back to
    ``os.defpath`` like execvpe), never the parent's, so the fingerprinted
    executable is the one the child actually executes. Relative entries and
    relative slash-paths resolve against the child working directory ``root``.
    """
    candidate = Path(program)
    if os.sep in program or (os.altsep and os.altsep in program):
        if not candidate.is_absolute():
            candidate = root / candidate
        # os.path.isfile stays False on unsearchable PATH directories
        # instead of raising like Path.is_file().
        return candidate if os.path.isfile(candidate) else None
    search_path = exec_env.get("PATH", os.defpath)
    for directory in search_path.split(os.pathsep):
        base = Path(directory) if directory else Path(".")
        if not base.is_absolute():
            base = root / base
        candidate = base / program
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def build_provenance(args: argparse.Namespace, root: Path, command: list[str] | None = None) -> dict[str, Any]:
    metadata_path = user_path(root, args.metadata)
    if metadata_path.is_symlink():
        raise CacheError(f"metadata must not be a symlink: {metadata_path}")
    metadata = validate_metadata(load_json(metadata_path))
    inputs = fingerprint_group(args.input, "--input", root)
    tools = fingerprint_group(args.tool, "--tool", root)
    comparands = fingerprint_group(args.comparand, "--comparand", root)
    for field, records in (("input", inputs), ("tool", tools), ("comparand", comparands)):
        if not records:
            raise CacheError(f"at least one --{field} fingerprint is required")
    provenance: dict[str, Any] = {
        "schema": SCHEMA,
        "oracle_commit": oracle_commit(metadata),
        "architecture": metadata["architecture"],
        "compiler_spec": metadata["compiler_spec"],
        "analysis_options": metadata["analysis_options"],
        "metadata": {
            "path": display_path(metadata_path, root),
            "sha256": sha256_file(metadata_path),
            "document_sha256": sha256_bytes(canonical_bytes(metadata)),
        },
        "inputs": inputs,
        "tools": tools,
        "comparands": comparands,
        "cache_implementation": fingerprint_path("oracle_cache", Path(__file__), root),
        "context": parse_context(args.context),
    }
    if command is not None:
        if not command:
            raise CacheError("capture requires a command after --")
        provenance["command"] = command
        environment = environment_snapshot(capture_env_names(args.env))
        provenance["environment"] = environment
        executable = resolve_executable(command[0], child_environment(environment), root)
        if executable is None:
            raise CacheError(f"capture command executable not found: {command[0]}")
        provenance["command_executable"] = fingerprint_path(
            "argv0", executable.resolve(), root
        )
    return provenance


def provenance_key(provenance: dict[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(provenance))


def safe_relative_name(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if (
        not name
        or pure.is_absolute()
        or pure.as_posix() != name
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        raise CacheError(f"artifact name must be a safe relative path: {name!r}")
    return pure


def cache_entry(cache_dir: Path, key: str) -> Path:
    return cache_dir / "v1" / key[:2] / key


def artifact_records(entry: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise CacheError("cache manifest has no artifact list")
    seen: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise CacheError("cache artifact record is not an object")
        name = str(record.get("name", ""))
        safe_relative_name(name)
        if name in seen:
            raise CacheError(f"duplicate artifact name in cache: {name}")
        seen.add(name)
        path = entry / "artifacts" / name
        if path.is_symlink() or not path.is_file():
            raise CacheError(f"cached artifact is missing or not regular: {name}")
        if path.stat().st_size != record.get("size"):
            raise CacheError(f"cached artifact size mismatch: {name}")
        if sha256_file(path) != record.get("sha256"):
            raise CacheError(f"cached artifact hash mismatch: {name}")
    actual: set[str] = set()
    artifact_root = entry / "artifacts"
    for candidate in artifact_root.rglob("*"):
        if candidate.is_symlink():
            raise CacheError(f"cached artifact tree contains a symlink: {candidate}")
        if candidate.is_file():
            actual.add(candidate.relative_to(artifact_root).as_posix())
    if actual != seen:
        raise CacheError(
            f"cached artifact manifest mismatch: expected={sorted(seen)} actual={sorted(actual)}"
        )
    return artifacts


def verify_entry(cache_dir: Path, provenance: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    key = provenance_key(provenance)
    entry = cache_entry(cache_dir, key)
    manifest_path = entry / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CacheError(f"cache miss: {key}")
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise CacheError(f"unsupported cache manifest schema for {key}")
    if manifest.get("key") != key:
        raise CacheError(f"cache manifest key mismatch for {key}")
    if manifest.get("provenance") != provenance:
        raise CacheError(f"cache provenance mismatch for {key}")
    artifact_records(entry, manifest)
    return entry, manifest


def make_writable(path: Path) -> None:
    if not path.exists():
        return
    for candidate in [path, *path.rglob("*")]:
        try:
            candidate.chmod(candidate.stat().st_mode | stat.S_IWUSR)
        except OSError:
            pass


def remove_tree(path: Path) -> None:
    if path.exists():
        make_writable(path)
        shutil.rmtree(path)


def store_entry(
    cache_dir: Path,
    provenance: dict[str, Any],
    artifacts: list[tuple[str, Path]],
) -> tuple[Path, dict[str, Any], bool]:
    key = provenance_key(provenance)
    target = cache_entry(cache_dir, key)
    desired_records = []
    desired_names: set[str] = set()
    for name, source in artifacts:
        safe_relative_name(name)
        if name in desired_names:
            raise CacheError(f"duplicate artifact name {name!r}")
        desired_names.add(name)
        if source.is_symlink() or not source.is_file():
            raise CacheError(f"artifact must be a regular non-symlink file: {source}")
        desired_records.append(
            {
                "name": name,
                "size": source.stat().st_size,
                "sha256": sha256_file(source),
                "executable": bool(source.stat().st_mode & stat.S_IXUSR),
            }
        )
    desired_records.sort(key=lambda record: str(record["name"]))
    if target.exists():
        entry, manifest = verify_entry(cache_dir, provenance)
        if manifest["artifacts"] != desired_records:
            raise CacheError(f"nondeterministic artifact collision for cache key {key}")
        return entry, manifest, True
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".{key}.{os.getpid()}.{time.time_ns()}.tmp"
    records: list[dict[str, Any]] = []
    try:
        (temporary / "artifacts").mkdir(parents=True)
        for name, source in artifacts:
            pure = safe_relative_name(name)
            destination = temporary / "artifacts" / Path(*pure.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            executable = bool(source.stat().st_mode & stat.S_IXUSR)
            destination.chmod(0o555 if executable else 0o444)
            records.append(
                {
                    "name": name,
                    "size": destination.stat().st_size,
                    "sha256": sha256_file(destination),
                    "executable": executable,
                }
            )
        records.sort(key=lambda record: str(record["name"]))
        if records != desired_records:
            raise CacheError("artifact changed while being copied into the cache")
        manifest = {
            "schema": SCHEMA,
            "key": key,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "provenance": provenance,
            "artifacts": records,
        }
        manifest_path = temporary / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o444)
        for directory in sorted(
            [item for item in temporary.rglob("*") if item.is_dir()],
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        temporary.chmod(0o555)
        try:
            os.rename(temporary, target)
        except OSError:
            if not target.exists():
                raise
            remove_tree(temporary)
            entry, existing = verify_entry(cache_dir, provenance)
            if existing["artifacts"] != desired_records:
                raise CacheError(f"nondeterministic artifact collision for cache key {key}")
            return entry, existing, True
        return target, manifest, False
    except Exception:
        remove_tree(temporary)
        raise


def parse_artifacts(values: list[str], root: Path) -> list[tuple[str, Path]]:
    artifacts: list[tuple[str, Path]] = []
    for value in values:
        name, raw_path = parse_assignment(value, "--artifact")
        artifacts.append((name, user_path(root, raw_path)))
    if not artifacts:
        raise CacheError("store requires at least one --artifact NAME=PATH")
    return artifacts


def restore_entry(entry: Path, manifest: dict[str, Any], output: Path) -> None:
    if output.exists():
        raise CacheError(f"restore output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        temporary.mkdir()
        restored: dict[str, tuple[int, str]] = {}
        for record in artifact_records(entry, manifest):
            name = str(record["name"])
            source = entry / "artifacts" / name
            destination = temporary / Path(*safe_relative_name(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o555 if record.get("executable") else 0o444)
            # Cross-check every restored artifact against the manifest: hash,
            # size, and (via stable_file_record's before/after stat identity)
            # mid-copy mutation of the bytes just written.
            size, digest = stable_file_record(destination)
            if size != record.get("size"):
                raise CacheError(f"restored artifact size mismatch: {name}")
            if digest != record.get("sha256"):
                raise CacheError(f"restored artifact hash mismatch: {name}")
            restored[name] = (size, digest)
        actual: set[str] = set()
        for candidate in temporary.rglob("*"):
            if candidate.is_symlink():
                raise CacheError(f"restored bundle contains a symlink: {candidate}")
            if candidate.is_file():
                actual.add(candidate.relative_to(temporary).as_posix())
        if actual != set(restored):
            raise CacheError(
                "restored bundle closure mismatch: "
                f"expected={sorted(restored)} actual={sorted(actual)}"
            )
        # TOCTOU closure: the cache entry must still validate identically
        # after the copy, proving no source artifact was swapped mid-restore.
        artifact_records(entry, manifest)
        os.rename(temporary, output)
    except Exception:
        remove_tree(temporary)
        raise


def result_document(key: str, entry: Path, manifest: dict[str, Any], hit: bool) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "key": key,
        "cache_hit": hit,
        "entry": entry.as_posix(),
        "artifacts": manifest["artifacts"],
    }


def capture(args: argparse.Namespace, root: Path, command: list[str]) -> int:
    provenance = build_provenance(args, root, command)
    key = provenance_key(provenance)
    # The executed environment is derived verbatim from the provenance
    # snapshot: every variable visible to the child is declared with a
    # non-None value in provenance["environment"], and nothing else leaks in
    # through process inheritance.
    environment = dict(provenance["environment"])
    exec_env = child_environment(environment)
    cache_dir = user_path(root, args.cache_dir)
    if args.timeout <= 0:
        raise CacheError("--timeout must be positive")
    if args.verify_only:
        entry, manifest = verify_entry(cache_dir, provenance)
        print(json.dumps(result_document(key, entry, manifest, True), sort_keys=True))
        return 0
    if not args.force_run:
        try:
            entry, manifest = verify_entry(cache_dir, provenance)
        except CacheError as error:
            if not str(error).startswith("cache miss:"):
                raise
        else:
            records = {record["name"]: record for record in manifest["artifacts"]}
            required = {"stdout.bin", "stderr.bin", "result.json"}
            if set(records) != required:
                raise CacheError(f"captured cache entry has unexpected artifacts: {sorted(records)}")
            stdout_blob = (entry / "artifacts" / "stdout.bin").read_bytes()
            stderr_blob = (entry / "artifacts" / "stderr.bin").read_bytes()
            # Replay cross-check: the bytes about to be echoed are hashed
            # against the verified manifest, so a swap between verify_entry
            # and the read cannot be replayed verbatim.
            if (
                len(stdout_blob) != records["stdout.bin"]["size"]
                or sha256_bytes(stdout_blob) != records["stdout.bin"]["sha256"]
            ):
                raise CacheError("captured stdout was swapped after verification")
            if (
                len(stderr_blob) != records["stderr.bin"]["size"]
                or sha256_bytes(stderr_blob) != records["stderr.bin"]["sha256"]
            ):
                raise CacheError("captured stderr was swapped after verification")
            result = load_json(entry / "artifacts" / "result.json")
            if not isinstance(result, dict) or result.get("schema") != SCHEMA:
                raise CacheError("captured result has an invalid schema")
            if result.get("return_code") != 0:
                raise CacheError("only successful commands may be restored from capture cache")
            if result.get("stdout_sha256") != records["stdout.bin"]["sha256"]:
                raise CacheError("captured stdout/result hash mismatch")
            if result.get("stderr_sha256") != records["stderr.bin"]["sha256"]:
                raise CacheError("captured stderr/result hash mismatch")
            sys.stdout.buffer.write(stdout_blob)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.write(stderr_blob)
            sys.stderr.write(f"[oracle-cache] HIT {key}\n")
            sys.stderr.flush()
            return 0

    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=root,
        env=exec_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        sys.stderr.write(f"[oracle-cache] TIMEOUT after {args.timeout}s\n")
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
        return 124
    elapsed = time.monotonic() - started
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()
    if process.returncode != 0:
        return process.returncode
    # Post-readback drift gate (fail closed; the command output above was
    # already relayed, but nothing enters the cache). The ambient environment
    # must not have moved while the command executed, and re-deriving the full
    # provenance must reproduce the same key, which also catches inputs,
    # tools, or the resolved executable being swapped mid-run.
    drift = environment_drift(environment)
    if drift:
        raise CacheError(
            "environment drifted while the command executed, refusing to store: "
            + ", ".join(drift)
        )
    if provenance_key(build_provenance(args, root, command)) != key:
        raise CacheError(
            "provenance drifted while the command executed, refusing to store"
        )
    with tempfile.TemporaryDirectory(prefix="rugra-oracle-capture-") as raw_temp:
        temp = Path(raw_temp)
        stdout_path = temp / "stdout.bin"
        stderr_path = temp / "stderr.bin"
        result_path = temp / "result.json"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        result_path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "return_code": process.returncode,
                    "stdout_sha256": sha256_bytes(stdout),
                    "stderr_sha256": sha256_bytes(stderr),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        _, _, hit = store_entry(
            cache_dir,
            provenance,
            [
                ("stdout.bin", stdout_path),
                ("stderr.bin", stderr_path),
                ("result.json", result_path),
            ],
        )
    action = "VERIFY" if hit else "STORE"
    sys.stderr.write(f"[oracle-cache] {action} {key} ({elapsed:.3f}s)\n")
    return 0


def add_provenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--input", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--tool", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--comparand", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--context", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--cache-dir", type=Path, default=Path(".rugra-cache/oracle"))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    for command in ("key", "verify", "restore", "store", "capture"):
        subparser = subparsers.add_parser(command)
        add_provenance_arguments(subparser)
        if command == "restore":
            subparser.add_argument("--output", required=True, type=Path)
        elif command == "store":
            subparser.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
        elif command == "capture":
            subparser.add_argument("--env", action="append", default=[])
            subparser.add_argument("--force-run", action="store_true")
            subparser.add_argument("--verify-only", action="store_true")
            subparser.add_argument("--timeout", type=float, default=3600.0)
            subparser.add_argument("capture_command", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def self_test() -> int:
    root = Path(__file__).resolve().parent.parent
    python = sys.executable
    with tempfile.TemporaryDirectory(prefix="rugra-oracle-cache-test-") as raw_temp:
        temp = Path(raw_temp)
        metadata = temp / "metadata.json"
        metadata.write_text(
            json.dumps(
                {
                    "oracle": {"commit": LOCKED_ORACLE, "tag": "Ghidra_12.0.4_build"},
                    "architecture": "test",
                    "compiler_spec": "test",
                    "analysis_options": {"mode": "unit"},
                }
            ),
            encoding="utf-8",
        )
        input_path = temp / "input.bin"
        tool_path = temp / "tool.py"
        comparand_path = temp / "comparand.rs"
        artifact_path = temp / "stage.json"
        input_path.write_bytes(b"input")
        tool_path.write_text("tool\n", encoding="utf-8")
        comparand_path.write_text("comparand\n", encoding="utf-8")
        artifact_path.write_text("stage\n", encoding="utf-8")
        args = argparse.Namespace(
            metadata=metadata,
            input=[f"sample={input_path}"],
            tool=[f"runner={tool_path}"],
            comparand=[f"rust={comparand_path}"],
            context=["mode=test"],
            env=[],
        )

        # --- store / verify / restore / tamper --------------------------------
        provenance = build_provenance(args, root)
        key = provenance_key(provenance)
        cache_dir = temp / "cache"
        entry, manifest, hit = store_entry(
            cache_dir, provenance, [("stages/one.json", artifact_path)]
        )
        assert not hit and entry == cache_entry(cache_dir, key)
        verified_entry, verified_manifest = verify_entry(cache_dir, provenance)
        assert verified_entry == entry and verified_manifest == manifest
        output = temp / "restore"
        restore_entry(entry, manifest, output)
        restored = output / "stages/one.json"
        assert restored.read_text(encoding="utf-8") == "stage\n"
        assert not (restored.stat().st_mode & stat.S_IWUSR)
        input_path.write_bytes(b"changed")
        changed = build_provenance(args, root)
        assert provenance_key(changed) != key
        input_path.write_bytes(b"input")
        cached = entry / "artifacts/stages/one.json"
        make_writable(entry)
        cached.write_text("tampered\n", encoding="utf-8")
        try:
            verify_entry(cache_dir, provenance)
        except CacheError as error:
            assert "mismatch" in str(error)
        else:
            raise AssertionError("tampered artifact passed verification")

        # --- environment snapshot matrix -------------------------------------
        declared = "RUDRA_CACHE_TEST_DECLARED"
        undeclared = "RUDRA_CACHE_TEST_UNDECLARED"
        absent = "RUDRA_CACHE_TEST_ABSENT_1204"
        original_path = os.environ.get("PATH")
        assert original_path, "self-test requires an ambient PATH"
        try:
            os.environ[undeclared] = "ambient-payload"
            os.environ[declared] = "v1"
            names = capture_env_names([declared])
            assert declared in names and undeclared not in names and absent not in names
            snapshot = environment_snapshot(names)
            assert snapshot[declared] == "v1" and snapshot.get(absent) is None
            exec_env = child_environment(snapshot)
            assert exec_env.get(declared) == "v1"
            assert all(isinstance(value, str) for value in exec_env.values())
            assert undeclared not in exec_env and absent not in exec_env
            assert environment_drift(snapshot) == []
            env_args = argparse.Namespace(**{**vars(args), "env": [declared]})
            env_probe = [python, "-c", "pass"]
            key_v1 = provenance_key(build_provenance(env_args, root, env_probe))
            # declared value drift is detected and changes the key
            os.environ[declared] = "v2"
            assert environment_drift(snapshot) == [declared]
            assert provenance_key(build_provenance(env_args, root, env_probe)) != key_v1
            os.environ[declared] = "v1"
            # PATH content change changes the key
            os.environ["PATH"] = f"{temp / 'no-such-dir'}{os.pathsep}{original_path}"
            assert provenance_key(build_provenance(env_args, root, env_probe)) != key_v1
        finally:
            os.environ["PATH"] = original_path
            os.environ.pop(undeclared, None)
            os.environ.pop(declared, None)

        # --- executable resolution matrix ------------------------------------
        assert (
            resolve_executable("tools/oracle_cache.py", {"PATH": ""}, root)
            == root / "tools/oracle_cache.py"
        )
        assert resolve_executable("no-such-binary-1204", {"PATH": "/usr/bin"}, root) is None
        bin_dir = temp / "probebin"
        bin_dir.mkdir()
        probe = bin_dir / "rugra-cache-probe"
        probe.write_text("#!/bin/sh\necho v1\n", encoding="utf-8")
        probe.chmod(0o755)
        try:
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{original_path}"
            probe_args = argparse.Namespace(**{**vars(args), "env": []})
            probe_key_v1 = provenance_key(
                build_provenance(probe_args, root, ["rugra-cache-probe"])
            )
            # same PATH directory, different executable content -> new key
            probe.write_text("#!/bin/sh\necho v2\n", encoding="utf-8")
            probe.chmod(0o755)
            assert (
                provenance_key(build_provenance(probe_args, root, ["rugra-cache-probe"]))
                != probe_key_v1
            )
            # outside the declared PATH the probe must be invisible
            os.environ["PATH"] = original_path
            try:
                build_provenance(probe_args, root, ["rugra-cache-probe"])
            except CacheError as error:
                assert "executable not found" in str(error)
            else:
                raise AssertionError("probe resolved outside the child PATH")
        finally:
            os.environ["PATH"] = original_path

        # --- capture end-to-end through the CLI ------------------------------
        def run_cli(cli_env: dict[str, str], cache: Path, command: list[str]):
            return subprocess.run(
                [
                    python,
                    "tools/oracle_cache.py",
                    "capture",
                    "--metadata",
                    str(metadata),
                    "--input",
                    f"sample={input_path}",
                    "--tool",
                    f"runner={tool_path}",
                    "--comparand",
                    f"rust={comparand_path}",
                    "--context",
                    "mode=test",
                    "--env",
                    "RUDRA_CACHE_TEST_CLI",
                    "--cache-dir",
                    str(cache),
                    "--timeout",
                    "30",
                    "--",
                    *command,
                ],
                cwd=root,
                env=cli_env,
                capture_output=True,
            )

        env_dump = temp / "env_dump.py"
        env_dump.write_text(
            "import json, os\nprint(json.dumps(dict(os.environ), sort_keys=True))\n",
            encoding="utf-8",
        )
        cli_cache = temp / "cli-cache"
        cli_env = dict(os.environ)
        cli_env["RUDRA_ATTACK_UNDECLARED"] = "ambient-payload"
        cli_env["RUDRA_CACHE_TEST_CLI"] = "ok"
        first = run_cli(cli_env, cli_cache, [python, str(env_dump)])
        assert first.returncode == 0, first.stderr.decode()
        assert b"STORE" in first.stderr
        observed_env = json.loads(first.stdout.decode("utf-8"))
        expected_env = child_environment(
            {
                name: cli_env.get(name)
                for name in capture_env_names(["RUDRA_CACHE_TEST_CLI"])
            }
        )
        # Popen(env=...) is exactly the provenance environment: undeclared
        # ambient variables are invisible to the captured command.
        assert observed_env == expected_env
        assert "RUDRA_ATTACK_UNDECLARED" not in observed_env
        assert observed_env["RUDRA_CACHE_TEST_CLI"] == "ok"
        # undeclared ambient change neither busts the cache nor leaks in
        cli_env["RUDRA_ATTACK_UNDECLARED"] = "different-payload"
        replay = run_cli(cli_env, cli_cache, [python, str(env_dump)])
        assert replay.returncode == 0, replay.stderr.decode()
        assert b"HIT" in replay.stderr
        assert replay.stdout == first.stdout
        # declared value change must produce a different key (miss)
        cli_env["RUDRA_CACHE_TEST_CLI"] = "tampered"
        rotated = run_cli(cli_env, cli_cache, [python, str(env_dump)])
        assert rotated.returncode == 0, rotated.stderr.decode()
        assert b"STORE" in rotated.stderr
        assert json.loads(rotated.stdout.decode("utf-8"))["RUDRA_CACHE_TEST_CLI"] == "tampered"
        # PATH value change must produce a different key (miss)
        cli_env["RUDRA_CACHE_TEST_CLI"] = "ok"
        cli_env["PATH"] = f"{temp / 'path-shadow'}{os.pathsep}{cli_env.get('PATH', original_path)}"
        repathed = run_cli(cli_env, cli_cache, [python, str(env_dump)])
        assert repathed.returncode == 0, repathed.stderr.decode()
        assert b"STORE" in repathed.stderr
        # failing and timed-out commands are never cached
        fail_cache = temp / "fail-cache"
        failing = run_cli(cli_env, fail_cache, [python, "-c", "import sys; sys.exit(3)"])
        assert failing.returncode == 3
        assert not fail_cache.exists() or not list(fail_cache.rglob("manifest.json"))
        timing_out = subprocess.run(
            [
                python,
                "tools/oracle_cache.py",
                "capture",
                "--metadata",
                str(metadata),
                "--input",
                f"sample={input_path}",
                "--tool",
                f"runner={tool_path}",
                "--comparand",
                f"rust={comparand_path}",
                "--context",
                "mode=timeout",
                "--cache-dir",
                str(fail_cache),
                "--timeout",
                "1",
                "--",
                python,
                "-c",
                "import time; time.sleep(30)",
            ],
            cwd=root,
            env=cli_env,
            capture_output=True,
            timeout=30,
        )
        assert timing_out.returncode == 124, timing_out.stderr.decode()
        assert not list(fail_cache.rglob("manifest.json"))

        # --- mid-execution environment drift refuses to store -----------------
        drift_cache = temp / "drift-cache"
        drift_var = "RUDRA_CACHE_TEST_DRIFT"
        os.environ[drift_var] = "before"

        def mutate_during_execution() -> None:
            time.sleep(0.3)
            os.environ[drift_var] = "during"

        mutator = threading.Thread(target=mutate_during_execution)
        mutator.start()
        try:
            drift_args = argparse.Namespace(
                **{
                    **vars(args),
                    "env": [drift_var],
                    "cache_dir": drift_cache,
                    "force_run": False,
                    "verify_only": False,
                    "timeout": 30.0,
                }
            )
            try:
                capture(drift_args, root, [python, "-c", "import time; time.sleep(0.8)"])
            except CacheError as error:
                assert drift_var in str(error)
                assert "refusing to store" in str(error)
            else:
                raise AssertionError("mid-execution environment drift was stored")
        finally:
            mutator.join()
            os.environ.pop(drift_var, None)
        assert not drift_cache.exists() or not list(drift_cache.rglob("manifest.json"))

        # --- TOCTOU / artifact bundle closure matrix --------------------------
        bundle_sources = {
            "stage/00-lift.json": temp / "bundle-stage.json",
            "comparison/report.json": temp / "bundle-comparison.json",
            "min-case/input.bin": temp / "bundle-min-case.bin",
        }
        bundle_sources["stage/00-lift.json"].write_text(
            json.dumps({"stage": "lift", "ops": 103}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        bundle_sources["comparison/report.json"].write_text(
            json.dumps({"first_diff": 77}, sort_keys=True) + "\n", encoding="utf-8"
        )
        bundle_sources["min-case/input.bin"].write_bytes(b"\x00\x01\x02mincase")
        bundle_sources["min-case/input.bin"].chmod(0o755)
        toctou_cache = temp / "toctou-cache"
        toctou_entry, toctou_manifest, toctou_hit = store_entry(
            toctou_cache,
            provenance,
            [(name, path) for name, path in bundle_sources.items()],
        )
        assert not toctou_hit
        restored_bundle = temp / "restored-bundle"
        restore_entry(toctou_entry, toctou_manifest, restored_bundle)
        for name, source in bundle_sources.items():
            destination = restored_bundle / Path(*PurePosixPath(name).parts)
            assert destination.read_bytes() == source.read_bytes()
            record = next(r for r in toctou_manifest["artifacts"] if r["name"] == name)
            assert destination.stat().st_size == record["size"]
            assert sha256_file(destination) == record["sha256"]
            expected_mode = bool(record.get("executable"))
            assert bool(destination.stat().st_mode & stat.S_IXUSR) == expected_mode
        restored_names = {
            item.relative_to(restored_bundle).as_posix()
            for item in restored_bundle.rglob("*")
            if item.is_file()
        }
        assert restored_names == set(bundle_sources)
        # restoring over an existing output is refused
        try:
            restore_entry(toctou_entry, toctou_manifest, restored_bundle)
        except CacheError as error:
            assert "already exists" in str(error)
        else:
            raise AssertionError("restore over existing output was allowed")
        # extra artifact inside the cache entry breaks the closure
        make_writable(toctou_entry)
        (toctou_entry / "artifacts" / "extra.txt").write_text("extra\n", encoding="utf-8")
        try:
            verify_entry(toctou_cache, provenance)
        except CacheError as error:
            assert "manifest mismatch" in str(error)
        else:
            raise AssertionError("extra cached artifact passed verification")
        (toctou_entry / "artifacts" / "extra.txt").unlink()
        # a missing artifact breaks the closure
        victim = toctou_entry / "artifacts" / "min-case/input.bin"
        victim.unlink()
        try:
            verify_entry(toctou_cache, provenance)
        except CacheError as error:
            assert "missing or not regular" in str(error)
        else:
            raise AssertionError("missing cached artifact passed verification")
        try:
            restore_entry(toctou_entry, toctou_manifest, temp / "restore-missing")
        except CacheError as error:
            assert "missing or not regular" in str(error)
        else:
            raise AssertionError("restore with a missing artifact was allowed")
        assert not (temp / "restore-missing").exists()
        # tampered source is rejected before any byte is restored
        shutil.copyfile(bundle_sources["min-case/input.bin"], victim)
        victim_source = toctou_entry / "artifacts" / "stage/00-lift.json"
        victim_source.chmod(0o644)
        victim_source.write_text("tampered\n", encoding="utf-8")
        try:
            restore_entry(toctou_entry, toctou_manifest, temp / "restore-tampered")
        except CacheError as error:
            assert "mismatch" in str(error)
        else:
            raise AssertionError("tampered cache entry was restored")
        assert not (temp / "restore-tampered").exists()
        assert not list(temp.glob(".restore-tampered.*.tmp"))
        # mid-restore source swap (TOCTOU) is detected by post-copy revalidation
        victim_source.write_text(
            json.dumps({"stage": "lift", "ops": 103}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        real_copyfile = shutil.copyfile
        sabotage_done: list[bool] = []

        def sabotaging_copyfile(source, destination, **kwargs):
            real_copyfile(source, destination, **kwargs)
            if not sabotage_done:
                sabotage_done.append(True)
                swapped = toctou_entry / "artifacts" / "comparison/report.json"
                make_writable(swapped)
                swapped.write_text("swapped-mid-restore\n", encoding="utf-8")

        shutil.copyfile = sabotaging_copyfile
        try:
            try:
                restore_entry(toctou_entry, toctou_manifest, temp / "restore-swap")
            except CacheError as error:
                assert "mismatch" in str(error)
            else:
                raise AssertionError("mid-restore artifact swap was not detected")
        finally:
            shutil.copyfile = real_copyfile
        assert not (temp / "restore-swap").exists()
        assert not list(temp.glob(".restore-swap.*.tmp"))
    print("oracle_cache: self-test OK")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.command:
        print("oracle_cache: a command is required", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent.parent
    try:
        if args.command == "capture":
            command = args.capture_command
            if command and command[0] == "--":
                command = command[1:]
            return capture(args, root, command)
        provenance = build_provenance(args, root)
        key = provenance_key(provenance)
        cache_dir = user_path(root, args.cache_dir)
        if args.command == "key":
            print(json.dumps({"schema": SCHEMA, "key": key}, sort_keys=True))
            return 0
        if args.command == "verify":
            entry, manifest = verify_entry(cache_dir, provenance)
            print(json.dumps(result_document(key, entry, manifest, True), sort_keys=True))
            return 0
        if args.command == "restore":
            entry, manifest = verify_entry(cache_dir, provenance)
            restore_entry(entry, manifest, user_path(root, args.output))
            print(json.dumps(result_document(key, entry, manifest, True), sort_keys=True))
            return 0
        artifacts = parse_artifacts(args.artifact, root)
        entry, manifest, hit = store_entry(cache_dir, provenance, artifacts)
        print(json.dumps(result_document(key, entry, manifest, hit), sort_keys=True))
        return 0
    except (CacheError, OSError, subprocess.SubprocessError) as error:
        print(f"oracle_cache: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
