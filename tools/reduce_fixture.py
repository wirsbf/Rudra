#!/usr/bin/env python3
"""Delta-reduce a deterministic oracle mismatch fixture without invoking a shell.

Schema 2 contract:

- The seed is first executed fresh on the ORIGINAL file bytes (memo bypassed),
  so the predicate is proven interesting for the fixture the user actually
  supplied, not for the reducer's re-rendered form.
- Render normalization drift between the original bytes and the codec's
  re-rendered seed is detected and recorded; if the drift also changes the
  predicate signature the run fails closed, because the reducer's rendering
  layer must never mask which real failure is being reduced.
- The final minimal case is re-verified fresh (memo bypassed) ``--retries``
  times and must reproduce the seed's predicate signature, so a stale memo
  entry can never certify a reduction (no cache false positives).
- Every predicate execution is classified as one of
  ``INTERESTING(predicate_signature)`` / ``BORING`` / ``INVALID`` /
  ``HARNESS_ERROR``.  ``INVALID`` only skips the current candidate and a
  candidate whose signature differs from the seed signature is ``INVALID``,
  so bug A can never be reduced into bug B.  ``HARNESS_ERROR`` fails closed.
- Signatures are extracted from predicate stdout JSON (whole output or the
  last non-empty line) under the ``predicate_signature`` key and canonicalized
  to sorted compact JSON, making them comparable across processes.
- Evaluations are appended incrementally to ``<trace>.eval.jsonl`` (fsync'd)
  so an interrupted run can be continued with ``--resume``, which warm-starts
  the memo only after the predicate identity matches fail-closed.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, NoReturn

try:
    from .oracle_cache import (
        DEFAULT_ENV_KEYS,
        display_path,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
    )
except ImportError:
    from oracle_cache import (
        DEFAULT_ENV_KEYS,
        display_path,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
    )


SCHEMA = 2
PLACEHOLDER = "{input}"
REDUCER_ENV_KEYS = (*DEFAULT_ENV_KEYS, "HOME", "LD_LIBRARY_PATH", "TMPDIR")
SIGNATURE_KEY = "predicate_signature"
DEFAULT_INVALID_EXIT = 3

INTERESTING = "INTERESTING"
BORING = "BORING"
INVALID = "INVALID"
HARNESS_ERROR = "HARNESS_ERROR"
CLASSIFICATIONS = (INTERESTING, BORING, INVALID)


class ReduceError(RuntimeError):
    """The fixture, predicate, or reduction contract is invalid."""


@dataclass(frozen=True)
class Codec:
    kind: str
    units: list[Any]
    render: Callable[[list[Any]], bytes]
    suffix: str


@dataclass(frozen=True)
class Outcome:
    """One settled predicate classification for a candidate."""

    classification: str
    interesting: bool
    signature_value: Any = None
    signature_canonical: str | None = None
    signature_sha256: str | None = None
    invalid_reason: str | None = None

    def trace_signature(self) -> dict[str, Any] | None:
        if self.signature_canonical is None:
            return None
        return {
            "value": self.signature_value,
            "canonical": self.signature_canonical,
            "sha256": self.signature_sha256,
        }


def atomic_bytes(path: Path, data: bytes) -> None:
    if path.exists():
        raise ReduceError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.link(temporary, path)
        temporary.unlink()
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    atomic_bytes(
        path,
        (
            json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8"),
    )


def json_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def canonical_signature(value: Any) -> str:
    """Canonical, process-independent text form of a predicate signature."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _signature_from_text(text: str) -> Any | None:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict) or SIGNATURE_KEY not in parsed:
        return None
    return parsed[SIGNATURE_KEY]


def extract_signature(stdout: bytes) -> tuple[Any, str | None, str | None]:
    """Return (value, canonical, sha256) or (None, None, None).

    The predicate may print a JSON object on stdout (whole output, or the last
    non-empty line) carrying its stable failure identity under
    ``predicate_signature``.  Missing or unparsable output means no signature.
    """

    text = stdout.decode("utf-8", "replace").strip()
    if not text:
        return None, None, None
    value = _signature_from_text(text)
    if value is None:
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            value = _signature_from_text(line)
            if value is not None:
                break
    if value is None or not isinstance(value, (str, int, float, bool, list, dict)):
        return None, None, None
    canonical = canonical_signature(value)
    return value, canonical, sha256_bytes(canonical.encode("ascii"))


def pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ReduceError("--field must be an RFC 6901 JSON Pointer beginning with '/'")
    if pointer == "/":
        return [""]
    tokens = pointer[1:].split("/")
    result = []
    for token in tokens:
        index = 0
        decoded = ""
        while index < len(token):
            if token[index] != "~":
                decoded += token[index]
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in "01":
                raise ReduceError(f"invalid JSON Pointer escape in {pointer!r}")
            decoded += "~" if token[index + 1] == "0" else "/"
            index += 2
        result.append(decoded)
    return result


def child(container: Any, token: str, pointer: str) -> Any:
    if isinstance(container, dict):
        if token not in container:
            raise ReduceError(f"JSON Pointer {pointer!r} does not exist")
        return container[token]
    if isinstance(container, list):
        if not token.isdigit():
            raise ReduceError(f"JSON Pointer list token must be an index: {token!r}")
        index = int(token)
        if index >= len(container):
            raise ReduceError(f"JSON Pointer index is out of range: {token}")
        return container[index]
    raise ReduceError(f"JSON Pointer traverses a scalar at token {token!r}")


def list_at_pointer(document: Any, pointer: str) -> list[Any]:
    value = document
    for token in pointer_tokens(pointer):
        value = child(value, token, pointer)
    if not isinstance(value, list):
        raise ReduceError(f"JSON Pointer {pointer!r} does not select a list")
    return value


def replace_at_pointer(document: Any, pointer: str, replacement: list[Any]) -> Any:
    result = copy.deepcopy(document)
    tokens = pointer_tokens(pointer)
    parent = result
    for token in tokens[:-1]:
        parent = child(parent, token, pointer)
    final = tokens[-1]
    if isinstance(parent, dict):
        if final not in parent:
            raise ReduceError(f"JSON Pointer {pointer!r} does not exist")
        parent[final] = replacement
    elif isinstance(parent, list):
        if not final.isdigit() or int(final) >= len(parent):
            raise ReduceError(f"JSON Pointer final index is invalid: {final!r}")
        parent[int(final)] = replacement
    else:
        raise ReduceError(f"JSON Pointer parent is a scalar: {pointer!r}")
    return result


def parse_hex(data: bytes) -> list[int]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReduceError("hex fixture must be ASCII") from error
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if len(compact) % 2 or any(character not in "0123456789abcdefABCDEF" for character in compact):
        raise ReduceError("hex fixture must contain an even number of hexadecimal digits")
    return list(bytes.fromhex(compact))


def codec_for(data: bytes, requested: str, field: str | None) -> Codec:
    parsed: Any = None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    kind = requested
    if kind == "auto":
        if isinstance(parsed, list) and field is None:
            kind = "json-list"
        elif isinstance(parsed, dict) and field is not None:
            kind = "json-field"
        else:
            kind = "hex"
    if kind == "json-list":
        if field is not None:
            raise ReduceError("--field is only valid with json-field")
        if not isinstance(parsed, list):
            raise ReduceError("json-list format requires a top-level JSON list")
        return Codec(kind, parsed, json_bytes, ".json")
    if kind == "json-field":
        if parsed is None or field is None:
            raise ReduceError("json-field format requires JSON input and --field")
        units = list_at_pointer(parsed, field)
        return Codec(
            kind,
            list(units),
            lambda reduced: json_bytes(replace_at_pointer(parsed, field, reduced)),
            ".json",
        )
    if field is not None:
        raise ReduceError("--field is only valid with json-field")
    units = parse_hex(data)
    return Codec(
        "hex",
        units,
        lambda reduced: (bytes(reduced).hex() + "\n").encode("ascii"),
        ".hex",
    )


def resolve_executable(root: Path, command: str) -> Path:
    resolved = shutil.which(command)
    if resolved is None:
        candidate = user_path(root, command)
        if candidate.is_file():
            resolved = str(candidate)
    if resolved is None:
        raise ReduceError(f"predicate executable not found: {command}")
    return Path(resolved).resolve()


def command_for(template: list[str], candidate: Path) -> list[str]:
    if PLACEHOLDER not in template:
        raise ReduceError(f"predicate command must contain an exact {PLACEHOLDER!r} argument")
    return [str(candidate) if argument == PLACEHOLDER else argument for argument in template]


def stable_read(path: Path) -> bytes:
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity or len(data) != after.st_size:
        raise ReduceError(f"input changed while being read: {path}")
    return data


class PredicateRunner:
    """Executes the predicate and settles every candidate into an Outcome."""

    def __init__(
        self,
        root: Path,
        template: list[str],
        interesting_exit: int,
        boring_exit: int,
        timeout: float,
        retries: int,
        max_evaluations: int,
        temp: Path,
        suffix: str,
        environment_names: list[str],
        invalid_exit: int = DEFAULT_INVALID_EXIT,
    ) -> None:
        if not template:
            raise ReduceError("predicate command is empty")
        if len({interesting_exit, boring_exit, invalid_exit}) != 3:
            raise ReduceError("interesting, boring, and invalid exit codes must differ")
        if timeout <= 0 or retries <= 0 or max_evaluations <= 0:
            raise ReduceError("timeout, retries, and max-evaluations must be positive")
        command_for(template, temp / f"probe{suffix}")
        self.root = root
        self.template = template
        self.interesting_exit = interesting_exit
        self.boring_exit = boring_exit
        self.invalid_exit = invalid_exit
        self.timeout = timeout
        self.retries = retries
        self.max_evaluations = max_evaluations
        self.temp = temp
        self.suffix = suffix
        self.memo: dict[str, Outcome] = {}
        self.trace: list[dict[str, Any]] = []
        self.evaluations = 0
        self.process_runs = 0
        self.cache_hits = 0
        self.sink: Callable[[dict[str, Any]], None] | None = None
        self.reference_signature: str | None = None
        self.reference_signature_value: Any = None
        executable = resolve_executable(root, template[0])
        size, digest = stable_file_record(executable)
        self.executable = {
            "argv0": template[0],
            "path": display_path(executable, root),
            "size": size,
            "sha256": digest,
        }
        names = sorted(set(REDUCER_ENV_KEYS).union(environment_names))
        self.environment_record = {name: os.environ.get(name) for name in names}
        self.environment_record.update(
            {"CARGO_NET_OFFLINE": "true", "LC_ALL": "C", "TZ": "UTC"}
        )
        self.environment = {
            name: value for name, value in self.environment_record.items() if value is not None
        }
        command_files = []
        seen_files: set[str] = set()
        for argument in template[1:]:
            if argument == PLACEHOLDER:
                continue
            candidate = user_path(root, argument)
            if not candidate.is_file():
                continue
            resolved_candidate = candidate.resolve()
            key = resolved_candidate.as_posix()
            if key in seen_files:
                continue
            seen_files.add(key)
            file_size, file_digest = stable_file_record(resolved_candidate)
            command_files.append(
                {
                    "argument": argument,
                    "path": display_path(resolved_candidate, root),
                    "size": file_size,
                    "sha256": file_digest,
                }
            )
        self.command_files = command_files

    def set_reference(self, outcome: Outcome) -> None:
        """Lock the seed signature that every accepted candidate must reproduce."""

        self.reference_signature = outcome.signature_canonical
        self.reference_signature_value = outcome.signature_value

    def signature_enforced(self) -> bool:
        return self.reference_signature is not None

    def identity_record(
        self,
        codec_kind: str,
        field: str | None,
        original_digest: str,
        original_size: int,
    ) -> dict[str, Any]:
        """Fields that must match before a resumed trace may warm the memo."""

        return {
            "command": list(self.template),
            "placeholder": PLACEHOLDER,
            "interesting_exit": self.interesting_exit,
            "boring_exit": self.boring_exit,
            "invalid_exit": self.invalid_exit,
            "timeout_seconds": self.timeout,
            "retries": self.retries,
            "executable": {
                "size": self.executable["size"],
                "sha256": self.executable["sha256"],
            },
            "environment": dict(self.environment_record),
            "format": codec_kind,
            "field": field,
            "original": {"sha256": original_digest, "size": original_size},
        }

    def _emit(self, entry: dict[str, Any], executed: bool = True) -> None:
        self.trace.append(entry)
        if executed and self.sink is not None:
            self.sink(entry)

    def _harness_failure(
        self,
        digest: str,
        data: bytes,
        unit_count: int,
        phase: str,
        fresh: bool,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> NoReturn:
        entry: dict[str, Any] = {
            "sha256": digest,
            "size": len(data),
            "unit_count": unit_count,
            "phase": phase,
            "fresh": fresh,
            "cache_hit": False,
            "classification": HARNESS_ERROR,
            "interesting": False,
            "invalid_reason": None,
            "signature": None,
            "error": message,
        }
        if details:
            entry.update(details)
        self._emit(entry)
        raise ReduceError(f"HARNESS_ERROR: {message}")

    def _execute(
        self, data: bytes, unit_count: int, phase: str, fresh: bool
    ) -> Outcome:
        digest = sha256_bytes(data)
        if not fresh:
            if self.evaluations >= self.max_evaluations:
                self._harness_failure(
                    digest,
                    data,
                    unit_count,
                    phase,
                    fresh,
                    f"predicate exceeded max evaluations ({self.max_evaluations})",
                )
            self.evaluations += 1
        candidate = self.temp / f"candidate-{digest}{self.suffix}"
        candidate.write_bytes(data)
        outcomes: list[int] = []
        elapsed: list[float] = []
        stdout_hashes: list[str] = []
        stderr_hashes: list[str] = []
        stdout_buffers: list[bytes] = []
        try:
            for _ in range(self.retries):
                command = command_for(self.template, candidate)
                started = time.monotonic()
                process = subprocess.Popen(
                    command,
                    cwd=self.root,
                    env=self.environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                self.process_runs += 1
                try:
                    stdout, stderr = process.communicate(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    self._harness_failure(
                        digest,
                        data,
                        unit_count,
                        phase,
                        fresh,
                        f"predicate timed out after {self.timeout}s for candidate {digest}",
                    )
                elapsed.append(round(time.monotonic() - started, 6))
                outcomes.append(int(process.returncode))
                stdout_hashes.append(sha256_bytes(stdout))
                stderr_hashes.append(sha256_bytes(stderr))
                stdout_buffers.append(stdout)
                if sha256_file(candidate) != digest:
                    self._harness_failure(
                        digest,
                        data,
                        unit_count,
                        phase,
                        fresh,
                        "predicate modified its candidate input",
                    )
            if len(set(outcomes)) != 1:
                self._harness_failure(
                    digest,
                    data,
                    unit_count,
                    phase,
                    fresh,
                    f"predicate is nondeterministic for {digest}: exit codes {outcomes}",
                )
            outcome = outcomes[0]
            extracted = [extract_signature(buffer) for buffer in stdout_buffers]
            if outcome == self.interesting_exit:
                canonicals = {signature[1] for signature in extracted}
                if len(canonicals) > 1:
                    self._harness_failure(
                        digest,
                        data,
                        unit_count,
                        phase,
                        fresh,
                        "predicate signature is nondeterministic for "
                        f"{digest}: {sorted(str(c) for c in canonicals)}",
                    )
                value, canonical, signature_digest = extracted[0]
                if (
                    self.reference_signature is not None
                    and canonical != self.reference_signature
                ):
                    result = Outcome(
                        INVALID,
                        False,
                        value,
                        canonical,
                        signature_digest,
                        "signature_mismatch",
                    )
                else:
                    result = Outcome(
                        INTERESTING, True, value, canonical, signature_digest, None
                    )
            elif outcome == self.boring_exit:
                result = Outcome(BORING, False)
            elif outcome == self.invalid_exit:
                value, canonical, signature_digest = extracted[0]
                result = Outcome(INVALID, False, value, canonical, signature_digest, "exit")
            else:
                self._harness_failure(
                    digest,
                    data,
                    unit_count,
                    phase,
                    fresh,
                    f"predicate harness error for {digest}: unexpected exit code {outcome}",
                )
            if not fresh:
                self.memo[digest] = result
            self._emit(
                {
                    "sha256": digest,
                    "size": len(data),
                    "unit_count": unit_count,
                    "phase": phase,
                    "fresh": fresh,
                    "cache_hit": False,
                    "classification": result.classification,
                    "interesting": result.interesting,
                    "invalid_reason": result.invalid_reason,
                    "signature": result.trace_signature(),
                    "exit_codes": outcomes,
                    "elapsed_seconds": elapsed,
                    "stdout_sha256": stdout_hashes,
                    "stderr_sha256": stderr_hashes,
                }
            )
            return result
        finally:
            if candidate.exists():
                candidate.unlink()

    def evaluate_outcome(
        self, data: bytes, unit_count: int, phase: str = "reduce"
    ) -> Outcome:
        digest = sha256_bytes(data)
        cached = self.memo.get(digest)
        if cached is not None:
            self.cache_hits += 1
            self._emit(
                {
                    "sha256": digest,
                    "size": len(data),
                    "unit_count": unit_count,
                    "phase": phase,
                    "fresh": False,
                    "cache_hit": True,
                    "classification": cached.classification,
                    "interesting": cached.interesting,
                    "invalid_reason": cached.invalid_reason,
                    "signature": cached.trace_signature(),
                },
                executed=False,
            )
            return cached
        return self._execute(data, unit_count, phase, fresh=False)

    def evaluate(self, data: bytes, unit_count: int, phase: str = "reduce") -> bool:
        return self.evaluate_outcome(data, unit_count, phase).interesting

    def fresh_evaluate(
        self, data: bytes, unit_count: int, phase: str = "fresh"
    ) -> Outcome:
        """Run the predicate on fresh processes, bypassing the memo entirely."""

        return self._execute(data, unit_count, phase, fresh=True)

    def outcome_counts(self) -> dict[str, int]:
        counts = {INTERESTING: 0, BORING: 0, INVALID: 0, HARNESS_ERROR: 0}
        for entry in self.trace:
            classification = entry.get("classification")
            if classification in counts:
                counts[classification] += 1
        return counts


class EvaluationLog:
    """Incremental, fsync'd JSONL record of executions for crash resume."""

    def __init__(self, path: Path, identity: dict[str, Any]) -> None:
        if path.exists():
            raise ReduceError(
                f"evaluation log already exists: {path} (pass --resume <log> to continue "
                "it, or remove it to start over)"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.stream = path.open("w", encoding="utf-8")
        self.evaluation_records = 0
        self._emit({"record": "header", "schema": SCHEMA, "identity": identity})

    def _emit(self, document: dict[str, Any]) -> None:
        self.stream.write(json.dumps(document, sort_keys=True, ensure_ascii=False) + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def append(self, entry: dict[str, Any]) -> None:
        self._emit({"record": "evaluation", **entry})
        self.evaluation_records += 1

    def close(self) -> None:
        if not self.stream.closed:
            self.stream.close()

    def discard(self) -> None:
        """Remove the log after its contents were promoted to the final trace."""

        self.close()
        self.path.unlink(missing_ok=True)


def identity_from_trace(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ReduceError("resumed trace root must be an object")
    predicate = document.get("predicate")
    original = document.get("original")
    executable = predicate.get("executable") if isinstance(predicate, dict) else None
    if not isinstance(predicate, dict) or not isinstance(original, dict):
        raise ReduceError("resumed trace is missing predicate/original provenance")
    return {
        "command": predicate.get("command"),
        "placeholder": predicate.get("placeholder", PLACEHOLDER),
        "interesting_exit": predicate.get("interesting_exit"),
        "boring_exit": predicate.get("boring_exit"),
        "invalid_exit": predicate.get("invalid_exit"),
        "timeout_seconds": predicate.get("timeout_seconds"),
        "retries": predicate.get("retries"),
        "executable": {
            "size": (executable or {}).get("size") if isinstance(executable, dict) else None,
            "sha256": (executable or {}).get("sha256") if isinstance(executable, dict) else None,
        },
        "environment": predicate.get("environment"),
        "format": document.get("format"),
        "field": document.get("field"),
        "original": {"sha256": original.get("sha256"), "size": original.get("size")},
    }


def compare_identity(current: dict[str, Any], loaded: dict[str, Any], source: str) -> None:
    for field in sorted(current):
        if current[field] != loaded.get(field):
            raise ReduceError(
                f"cannot resume {source}: identity field {field!r} differs "
                f"(current={current[field]!r}, resumed={loaded.get(field)!r})"
            )


def load_resume_source(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load identity + evaluation records from a JSONL eval log or final trace."""

    if path.is_symlink() or not path.is_file():
        raise ReduceError(f"--resume source must be a regular non-symlink file: {path}")
    text = stable_read(path).decode("utf-8")
    document: Any = None
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        if document.get("schema") != SCHEMA:
            raise ReduceError(
                f"cannot resume {path}: schema {document.get('schema')!r} is not supported "
                f"(only schema {SCHEMA} traces and eval logs can be resumed)"
            )
        records = document.get("evaluations")
        if not isinstance(records, list):
            raise ReduceError(f"cannot resume {path}: trace has no evaluations array")
        return identity_from_trace(document), [entry for entry in records if isinstance(entry, dict)]
    header: dict[str, Any] | None = None
    records: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ReduceError(f"cannot resume {path}:{number}: not valid JSON: {error}") from error
        if not isinstance(record, dict):
            raise ReduceError(f"cannot resume {path}:{number}: record must be an object")
        kind = record.get("record")
        if kind == "header":
            if header is not None:
                raise ReduceError(f"cannot resume {path}: duplicate header record")
            if record.get("schema") != SCHEMA:
                raise ReduceError(
                    f"cannot resume {path}: log schema {record.get('schema')!r} is not supported"
                )
            loaded_identity = record.get("identity")
            if not isinstance(loaded_identity, dict):
                raise ReduceError(f"cannot resume {path}: header has no identity object")
            header = loaded_identity
        elif kind == "evaluation":
            records.append({key: value for key, value in record.items() if key != "record"})
        else:
            raise ReduceError(f"cannot resume {path}:{number}: unknown record kind {kind!r}")
    if header is None:
        raise ReduceError(f"cannot resume {path}: evaluation log has no header record")
    return header, records


def outcomes_from_records(records: list[dict[str, Any]]) -> dict[str, Outcome]:
    """Rebuild the memo from executed evaluations; the last record for a digest wins."""

    memo: dict[str, Outcome] = {}
    for entry in records:
        digest = entry.get("sha256")
        classification = entry.get("classification")
        if not isinstance(digest, str) or classification not in CLASSIFICATIONS:
            continue
        signature = entry.get("signature")
        if not isinstance(signature, dict):
            signature = {}
        memo[digest] = Outcome(
            classification=classification,
            interesting=bool(entry.get("interesting")),
            signature_value=signature.get("value"),
            signature_canonical=signature.get("canonical"),
            signature_sha256=signature.get("sha256"),
            invalid_reason=entry.get("invalid_reason"),
        )
    return memo


def chunks(length: int, count: int) -> list[tuple[int, int]]:
    return [
        (index * length // count, (index + 1) * length // count)
        for index in range(count)
        if index * length // count < (index + 1) * length // count
    ]


def ddmin(units: list[Any], interesting: Callable[[list[Any]], bool]) -> list[Any]:
    current = list(units)
    granularity = 2
    while len(current) >= 2:
        reduced = False
        for start, finish in chunks(len(current), granularity):
            candidate = current[:start] + current[finish:]
            if interesting(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    index = 0
    while index < len(current):
        candidate = current[:index] + current[index + 1 :]
        if interesting(candidate):
            current = candidate
        else:
            index += 1
    return current


def one_minimal(units: list[Any], interesting: Callable[[list[Any]], bool]) -> bool:
    return all(
        not interesting(units[:index] + units[index + 1 :])
        for index in range(len(units))
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trace", type=Path)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--format", choices=("auto", "json-list", "json-field", "hex"), default="auto")
    parser.add_argument("--field")
    parser.add_argument("--interesting-exit", type=int, default=1)
    parser.add_argument("--boring-exit", type=int, default=0)
    parser.add_argument("--invalid-exit", type=int, default=DEFAULT_INVALID_EXIT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-evaluations", type=int, default=10000)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("predicate", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def run_main(argv: list[str]) -> tuple[int, str, str]:
    """Invoke main() with captured streams so self-tests stay quiet on success."""

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
        code = main(argv)
    return code, stdout_buffer.getvalue(), stderr_buffer.getvalue()


HEX_VALUES_SOURCE = (
    "import sys\n"
    "raw = open(sys.argv[1], encoding='ascii').read()\n"
    "compact = ''.join(raw.split())\n"
    "if compact.startswith(('0x', '0X')):\n"
    "    compact = compact[2:]\n"
    "values = list(bytes.fromhex(compact))\n"
)


def self_test() -> int:
    def predicate(values: list[int]) -> bool:
        return 2 in values and 4 in values

    first = ddmin([1, 2, 3, 4, 5, 6], predicate)
    second = ddmin([1, 2, 3, 4, 5, 6], predicate)
    assert first == second == [2, 4]
    assert one_minimal(first, predicate)
    document = {"outer": {"ops": [1, 2, 3]}, "keep": [9]}
    replaced = replace_at_pointer(document, "/outer/ops", [2])
    assert replaced == {"outer": {"ops": [2]}, "keep": [9]}
    assert document["outer"]["ops"] == [1, 2, 3]
    assert parse_hex(b"0x00 ff 10\n") == [0, 255, 16]
    value, canonical, digest = extract_signature(b'{"predicate_signature": {"b": 1, "a": 2}}')
    assert value == {"a": 2, "b": 1} and canonical == '{"a":2,"b":1}' and digest
    _, canonical_line, _ = extract_signature(
        b'progress: things happened\n{"predicate_signature": {"a": 2, "b": 1}}\n'
    )
    assert canonical_line == canonical
    assert extract_signature(b"") == (None, None, None)
    assert extract_signature(b'{"other": 1}') == (None, None, None)
    assert extract_signature(b"not json at all") == (None, None, None)
    with tempfile.TemporaryDirectory(prefix="rudra-reducer-test-") as raw_temp:
        temp = Path(raw_temp)
        helper = temp / "predicate.py"
        helper.write_text(
            "import json,sys\n"
            "mode,path=sys.argv[1:]\n"
            "if mode=='json-list': values=json.load(open(path,encoding='utf-8'))\n"
            "elif mode=='json-field': values=json.load(open(path,encoding='utf-8'))['ops']\n"
            "else: values=list(bytes.fromhex(open(path,encoding='ascii').read()))\n"
            "raise SystemExit(1 if 2 in values and 4 in values else 0)\n",
            encoding="utf-8",
        )
        codecs = [
            ("json-list", codec_for(b"[1,2,3,4,5,6]", "json-list", None)),
            (
                "json-field",
                codec_for(b'{"ops":[1,2,3,4,5,6],"keep":9}', "json-field", "/ops"),
            ),
            ("hex", codec_for(b"010203040506", "hex", None)),
        ]
        for mode, codec in codecs:
            with tempfile.TemporaryDirectory(prefix="candidates-", dir=temp) as raw_candidates:
                runner = PredicateRunner(
                    Path(__file__).resolve().parent.parent,
                    [sys.executable, str(helper), mode, PLACEHOLDER],
                    1,
                    0,
                    5.0,
                    2,
                    100,
                    Path(raw_candidates),
                    codec.suffix,
                    [],
                )
                reduced = ddmin(
                    codec.units,
                    lambda units: runner.evaluate(codec.render(units), len(units)),
                )
                assert reduced == [2, 4]
                assert one_minimal(
                    reduced,
                    lambda units: runner.evaluate(codec.render(units), len(units)),
                )
                previous_runs = runner.process_runs
                assert runner.evaluate(codec.render(reduced), len(reduced))
                assert runner.process_runs == previous_runs and runner.cache_hits > 0

        def write_predicate(name: str, source: str) -> Path:
            path = temp / name
            path.write_text(source, encoding="utf-8")
            return path

        def load_json(path: Path) -> Any:
            return json.loads(path.read_text(encoding="utf-8"))

        # Scenario A: seed runs on the original bytes; render drift is detected
        # and recorded without masking the failure; signature is enforced.
        signature_hex = write_predicate(
            "hex_signature.py",
            "import json, sys\n"
            + HEX_VALUES_SOURCE
            + "if 2 in values and 4 in values:\n"
            "    print(json.dumps({'predicate_signature': {'bug': 'hex-2-and-4'}}))\n"
            "    raise SystemExit(1)\n"
            "raise SystemExit(0)\n",
        )
        scenario_a = temp / "a"
        scenario_a.mkdir()
        input_a = scenario_a / "input.hex"
        input_a.write_bytes(b"0x010203040506")
        output_a = scenario_a / "min.hex"
        trace_a = scenario_a / "min.trace.json"
        code, _, stderr = run_main(
            [
                "--input", str(input_a), "--output", str(output_a), "--trace", str(trace_a),
                "--", sys.executable, str(signature_hex), PLACEHOLDER,
            ]
        )
        assert code == 0, f"scenario A failed: {stderr}"
        document_a = load_json(trace_a)
        assert document_a["schema"] == SCHEMA
        assert document_a["seed"]["original_bytes"]["classification"] == INTERESTING
        assert document_a["seed"]["original_bytes"]["fresh"] is True
        drift = document_a["seed"]["render_normalization_drift"]
        assert drift["detected"] is True
        assert drift["original_sha256"] != drift["rendered_sha256"]
        assert document_a["seed"]["rendered_bytes"]["classification"] == INTERESTING
        assert document_a["signature"]["enforced"] is True
        assert document_a["signature"]["canonical"] == '{"bug":"hex-2-and-4"}'
        assert document_a["final_verification"]["fresh"] is True
        assert document_a["final_verification"]["classification"] == INTERESTING
        assert document_a["final_verification"]["signature_matches_seed"] is True
        phases = [entry["phase"] for entry in document_a["evaluations"]]
        assert "seed-original" in phases and "final-fresh" in phases
        fresh_entries = [entry for entry in document_a["evaluations"] if entry["fresh"]]
        assert any(entry["phase"] == "final-fresh" for entry in fresh_entries)
        assert all(entry["classification"] in CLASSIFICATIONS for entry in fresh_entries)
        assert document_a["minimized"]["one_minimal"] is True
        assert output_a.read_bytes() == b"0204\n"
        assert not trace_a.with_name(trace_a.name + ".eval.jsonl").exists()

        # Scenario B: INVALID never shrinks bug A into bug B.  The seed
        # reproduces bug A (values 2 and 4), but many candidates would exit
        # interesting for a DIFFERENT, smaller bug (value 5 alone); those must
        # be skipped as INVALID instead of being accepted for reduction.
        two_bugs = write_predicate(
            "two_bugs.py",
            "import json, sys\n"
            "values = json.load(open(sys.argv[1], encoding='utf-8'))\n"
            "if 2 in values and 4 in values:\n"
            "    print(json.dumps({'predicate_signature': 'bug-a'}))\n"
            "    raise SystemExit(1)\n"
            "if 5 in values:\n"
            "    print(json.dumps({'predicate_signature': 'bug-b'}))\n"
            "    raise SystemExit(1)\n"
            "raise SystemExit(0)\n",
        )
        scenario_b = temp / "b"
        scenario_b.mkdir()
        input_b = scenario_b / "input.json"
        input_b.write_bytes(b"[1, 2, 3, 4, 5, 6]")
        output_b = scenario_b / "min.json"
        trace_b = scenario_b / "min.trace.json"
        code, _, stderr = run_main(
            [
                "--input", str(input_b), "--output", str(output_b), "--trace", str(trace_b),
                "--", sys.executable, str(two_bugs), PLACEHOLDER,
            ]
        )
        assert code == 0, f"scenario B failed: {stderr}"
        document_b = load_json(trace_b)
        assert load_json(output_b) == [2, 4]
        assert document_b["minimized"]["unit_count"] == 2
        assert document_b["signature"]["canonical"] == json.dumps("bug-a")
        mismatched = [
            entry
            for entry in document_b["evaluations"]
            if entry.get("classification") == INVALID
            and entry.get("invalid_reason") == "signature_mismatch"
        ]
        assert mismatched, "expected signature-mismatch candidates to be skipped as INVALID"
        assert document_b["outcome_counts"][INVALID] == len(mismatched)
        assert document_b["final_verification"]["classification"] == INTERESTING

        # Scenario C: exit-code INVALID only skips the current candidate; the
        # reduction still finishes and keeps the units the predicate needs.
        invalid_marker = write_predicate(
            "invalid_marker.py",
            "import json, sys\n"
            + HEX_VALUES_SOURCE
            + "if not values or values[-1] != 0:\n"
            "    raise SystemExit(3)\n"
            "if 2 in values and 4 in values:\n"
            "    print(json.dumps({'predicate_signature': {'bug': 'hex-2-and-4'}}))\n"
            "    raise SystemExit(1)\n"
            "raise SystemExit(0)\n",
        )
        scenario_c = temp / "c"
        scenario_c.mkdir()
        input_c = scenario_c / "input.hex"
        input_c.write_bytes(b"0102030405 00")
        output_c = scenario_c / "min.hex"
        trace_c = scenario_c / "min.trace.json"
        code, _, stderr = run_main(
            [
                "--input", str(input_c), "--output", str(output_c), "--trace", str(trace_c),
                "--", sys.executable, str(invalid_marker), PLACEHOLDER,
            ]
        )
        assert code == 0, f"scenario C failed: {stderr}"
        document_c = load_json(trace_c)
        assert output_c.read_bytes() == b"020400\n"
        assert document_c["minimized"]["unit_count"] == 3
        exit_invalid = [
            entry
            for entry in document_c["evaluations"]
            if entry.get("classification") == INVALID and entry.get("invalid_reason") == "exit"
        ]
        assert exit_invalid, "expected exit-code INVALID candidates in the trace"
        assert document_c["outcome_counts"][INVALID] == len(exit_invalid)

        # Scenario D: the fresh final verification catches a memo false
        # positive.  The predicate is interesting only on the FIRST process
        # sighting of each candidate, so the memoized minimal case flips to
        # BORING when the final verification re-runs it for real.
        first_sighting = write_predicate(
            "first_sighting.py",
            "import hashlib, json, os, sys\n"
            "candidate, state_path = sys.argv[1], sys.argv[2]\n"
            "data = open(candidate, 'rb').read()\n"
            "digest = hashlib.sha256(data).hexdigest()\n"
            "state = {}\n"
            "if os.path.exists(state_path):\n"
            "    state = json.load(open(state_path, encoding='utf-8'))\n"
            "seen = int(state.get(digest, 0))\n"
            "state[digest] = seen + 1\n"
            "with open(state_path, 'w', encoding='utf-8') as handle:\n"
            "    json.dump(state, handle)\n"
            "if seen == 0:\n"
            "    compact = ''.join(data.decode('ascii').split())\n"
            "    if compact.startswith(('0x', '0X')):\n"
            "        compact = compact[2:]\n"
            "    values = list(bytes.fromhex(compact))\n"
            "    if 2 in values and 4 in values:\n"
            "        print(json.dumps({'predicate_signature': {'bug': 'hex-2-and-4'}}))\n"
            "        raise SystemExit(1)\n"
            "raise SystemExit(0)\n",
        )
        scenario_d = temp / "d"
        scenario_d.mkdir()
        input_d = scenario_d / "input.hex"
        input_d.write_bytes(b"0x010203040506")
        output_d = scenario_d / "min.hex"
        trace_d = scenario_d / "min.trace.json"
        log_d = trace_d.with_name(trace_d.name + ".eval.jsonl")
        code, _, stderr = run_main(
            [
                "--input", str(input_d), "--output", str(output_d), "--trace", str(trace_d),
                "--retries", "1",
                "--", sys.executable, str(first_sighting), PLACEHOLDER, str(scenario_d / "state.json"),
            ]
        )
        assert code == 2, "scenario D must fail closed on the fresh verification"
        assert "fresh final verification failed" in stderr
        assert not output_d.exists() and not trace_d.exists()
        assert log_d.exists(), "interrupted/failed run must keep the eval log for resume"
        log_entries = [
            json.loads(line)
            for line in log_d.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert log_entries[0]["record"] == "header" and log_entries[0]["schema"] == SCHEMA
        final_entry = [e for e in log_entries if e.get("phase") == "final-fresh"]
        assert len(final_entry) == 1
        assert final_entry[0]["fresh"] is True
        assert final_entry[0]["classification"] == BORING
        memoized = [
            e
            for e in log_entries
            if e.get("sha256") == final_entry[0]["sha256"] and e is not final_entry[0]
        ]
        assert memoized and memoized[0]["classification"] == INTERESTING

        # Scenario E: resume from an interrupted evaluation trace; the resumed
        # run warm-starts the memo, converges to the same minimal case, and
        # derives the identical cross-process signature.
        list_signature = write_predicate(
            "list_signature.py",
            "import json, sys\n"
            "values = json.load(open(sys.argv[1], encoding='utf-8'))\n"
            "if 2 in values and 4 in values:\n"
            "    print(json.dumps({'predicate_signature': {'bug': 'list-2-and-4'}}))\n"
            "    raise SystemExit(1)\n"
            "raise SystemExit(0)\n",
        )
        scenario_e = temp / "e"
        scenario_e.mkdir()
        input_e = scenario_e / "input.json"
        input_e.write_bytes(json_bytes([1, 2, 3, 4, 5, 6]))
        baseline_out = scenario_e / "baseline.json"
        baseline_trace = scenario_e / "baseline.trace.json"
        code, _, stderr = run_main(
            [
                "--input", str(input_e), "--output", str(baseline_out),
                "--trace", str(baseline_trace), "--retries", "1",
                "--", sys.executable, str(list_signature), PLACEHOLDER,
            ]
        )
        assert code == 0, f"scenario E baseline failed: {stderr}"
        baseline = load_json(baseline_trace)
        assert baseline["seed"]["render_normalization_drift"]["detected"] is False
        interrupted_out = scenario_e / "interrupted.json"
        interrupted_trace = scenario_e / "interrupted.trace.json"
        interrupted_log = interrupted_trace.with_name(interrupted_trace.name + ".eval.jsonl")
        code, _, stderr = run_main(
            [
                "--input", str(input_e), "--output", str(interrupted_out),
                "--trace", str(interrupted_trace), "--retries", "1", "--max-evaluations", "3",
                "--", sys.executable, str(list_signature), PLACEHOLDER,
            ]
        )
        assert code == 2 and "exceeded max evaluations" in stderr
        assert interrupted_log.exists() and not interrupted_out.exists()
        resumed_out = scenario_e / "resumed.json"
        resumed_trace = scenario_e / "resumed.trace.json"
        code, _, stderr = run_main(
            [
                "--input", str(input_e), "--output", str(resumed_out),
                "--trace", str(resumed_trace), "--retries", "1",
                "--resume", str(interrupted_log),
                "--", sys.executable, str(list_signature), PLACEHOLDER,
            ]
        )
        assert code == 0, f"scenario E resume failed: {stderr}"
        resumed = load_json(resumed_trace)
        assert resumed["resumed"]["records_loaded"] >= 3
        assert resumed["resumed"]["memo_entries"] >= 3
        assert resumed["cache_hits"] > 0
        assert 0 < resumed["process_run_count"] < baseline["process_run_count"]
        assert load_json(resumed_out) == load_json(baseline_out) == [2, 4]
        assert (
            resumed["signature"]["canonical"]
            == baseline["signature"]["canonical"]
            == '{"bug":"list-2-and-4"}'
        )
        assert (
            resumed["final_verification"]["sha256"] == baseline["final_verification"]["sha256"]
        )
        other = write_predicate(
            "other_predicate.py",
            "import sys\n"
            "raise SystemExit(int(sys.argv[1] == 'x'))\n",
        )
        code, _, stderr = run_main(
            [
                "--input", str(input_e), "--output", str(scenario_e / "x.json"),
                "--trace", str(scenario_e / "x.trace.json"), "--retries", "1",
                "--resume", str(interrupted_log),
                "--", sys.executable, str(other), PLACEHOLDER,
            ]
        )
        assert code == 2 and "identity field" in stderr and "cannot resume" in stderr

        # Scenario F: when render drift changes the predicate signature the
        # reducer fails closed instead of reducing a masked, different failure.
        raw_prefix = write_predicate(
            "raw_prefix.py",
            "import json, sys\n"
            "raw = open(sys.argv[1], encoding='ascii').read()\n"
            + HEX_VALUES_SOURCE
            + "print(json.dumps({'predicate_signature': {'raw_prefix': raw[:6]}}))\n"
            "raise SystemExit(1 if 2 in values and 4 in values else 0)\n",
        )
        scenario_f = temp / "f"
        scenario_f.mkdir()
        input_f = scenario_f / "input.hex"
        input_f.write_bytes(b"0x010203040506")
        code, _, stderr = run_main(
            [
                "--input", str(input_f), "--output", str(scenario_f / "min.hex"),
                "--trace", str(scenario_f / "min.trace.json"),
                "--", sys.executable, str(raw_prefix), PLACEHOLDER,
            ]
        )
        assert code == 2, "scenario F must fail closed on signature-changing drift"
        assert "render normalization drift changed the predicate signature" in stderr
        assert not (scenario_f / "min.hex").exists()
    print("reduce_fixture: self-test OK")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    if args.input is None or args.output is None or args.trace is None:
        print("reduce_fixture: --input, --output, and --trace are required", file=sys.stderr)
        return 2
    predicate = args.predicate
    if predicate and predicate[0] == "--":
        predicate = predicate[1:]
    root = Path(__file__).resolve().parent.parent
    input_path = user_path(root, args.input)
    output_path = user_path(root, args.output)
    trace_path = user_path(root, args.trace)
    try:
        if input_path.is_symlink() or not input_path.is_file():
            raise ReduceError(f"input must be a regular non-symlink file: {input_path}")
        if len({input_path.resolve(), output_path.resolve(), trace_path.resolve()}) != 3:
            raise ReduceError("input, output, and trace paths must be distinct")
        if output_path.exists() or trace_path.exists():
            raise ReduceError("output and trace paths must not already exist")
        original = stable_read(input_path)
        codec = codec_for(original, args.format, args.field)
        log_path = trace_path.with_name(trace_path.name + ".eval.jsonl")
        resumed_section: dict[str, Any] | None = None
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="rudra-reducer-") as raw_temp:
            runner = PredicateRunner(
                root,
                predicate,
                args.interesting_exit,
                args.boring_exit,
                args.timeout,
                args.retries,
                args.max_evaluations,
                Path(raw_temp),
                codec.suffix,
                args.env,
                args.invalid_exit,
            )
            identity = runner.identity_record(
                codec.kind, args.field, sha256_bytes(original), len(original)
            )
            if args.resume is not None:
                resume_path = user_path(root, args.resume)
                resume_identity, records = load_resume_source(resume_path)
                compare_identity(
                    identity, resume_identity, display_path(resume_path, root)
                )
                memo = outcomes_from_records(records)
                runner.memo.update(memo)
                resume_size, resume_digest = stable_file_record(resume_path)
                resumed_section = {
                    "source": display_path(resume_path, root),
                    "source_size": resume_size,
                    "source_sha256": resume_digest,
                    "records_loaded": len(records),
                    "memo_entries": len(memo),
                }
            log = EvaluationLog(log_path, identity)
            runner.sink = log.append
            try:
                # 1. The seed is proven interesting on the ORIGINAL bytes first,
                #    on fresh processes, before any rendering happens.
                seed_outcome = runner.fresh_evaluate(
                    original, len(codec.units), phase="seed-original"
                )
                if seed_outcome.classification == BORING:
                    raise ReduceError(
                        "initial fixture is not interesting (predicate run on the original bytes)"
                    )
                if seed_outcome.classification == INVALID:
                    raise ReduceError(
                        "initial fixture is INVALID on the original bytes "
                        f"(reason={seed_outcome.invalid_reason})"
                    )
                runner.set_reference(seed_outcome)

                # 2. Detect render normalization drift between the original
                #    bytes and the reducer's rendered seed.
                rendered_seed = codec.render(list(codec.units))
                drift = {
                    "detected": sha256_bytes(rendered_seed) != sha256_bytes(original),
                    "original_sha256": sha256_bytes(original),
                    "rendered_sha256": sha256_bytes(rendered_seed),
                    "original_size": len(original),
                    "rendered_size": len(rendered_seed),
                }

                # 3. The rendered seed must still reproduce the same failure.
                rendered_outcome = runner.evaluate_outcome(
                    rendered_seed, len(codec.units), phase="seed-rendered"
                )
                if rendered_outcome.classification != INTERESTING:
                    if (
                        rendered_outcome.classification == INVALID
                        and rendered_outcome.invalid_reason == "signature_mismatch"
                    ):
                        raise ReduceError(
                            "render normalization drift changed the predicate signature: the "
                            "reducer rendering layer would mask which real failure is reduced "
                            f"(seed={runner.reference_signature}, "
                            f"rendered={rendered_outcome.signature_canonical})"
                        )
                    raise ReduceError(
                        f"rendered seed is {rendered_outcome.classification} "
                        f"(reason={rendered_outcome.invalid_reason}); the render layer "
                        "changed the predicate outcome"
                    )

                # 4. Reduce.  INVALID candidates (exit code or signature
                #    mismatch) are skipped, never accepted.
                reduced = ddmin(
                    list(codec.units),
                    lambda units: runner.evaluate(
                        codec.render(units), len(units), phase="reduce"
                    ),
                )
                final = codec.render(reduced)

                minimal = one_minimal(
                    reduced,
                    lambda units: runner.evaluate(
                        codec.render(units), len(units), phase="one-minimal"
                    ),
                )
                if not minimal:
                    raise ReduceError("reducer failed the 1-minimal verification")

                # 5. Final verification bypasses the memo and re-runs the
                #    minimal case on fresh processes, retries times.
                final_outcome = runner.fresh_evaluate(
                    final, len(reduced), phase="final-fresh"
                )
                if final_outcome.classification != INTERESTING:
                    raise ReduceError(
                        "HARNESS_ERROR: fresh final verification failed: minimal case is "
                        f"{final_outcome.classification} "
                        f"(reason={final_outcome.invalid_reason}); the memoized reduction "
                        "result was a false positive"
                    )
                if (
                    runner.reference_signature is not None
                    and final_outcome.signature_canonical != runner.reference_signature
                ):
                    raise ReduceError(
                        "HARNESS_ERROR: fresh final verification failed: minimal case "
                        "signature differs from the seed signature (bug identity changed "
                        "during reduction)"
                    )
                signature_matches_seed = (
                    runner.reference_signature is None
                    or final_outcome.signature_canonical == runner.reference_signature
                )
            finally:
                log.close()
            trace = {
                "schema": SCHEMA,
                "format": codec.kind,
                "field": args.field,
                "input": display_path(input_path, root),
                "output": display_path(output_path, root),
                "trace": display_path(trace_path, root),
                "resumed": resumed_section,
                "original": {
                    "sha256": sha256_bytes(original),
                    "size": len(original),
                    "unit_count": len(codec.units),
                },
                "seed": {
                    "original_bytes": {
                        "sha256": sha256_bytes(original),
                        "size": len(original),
                        "fresh": True,
                        "classification": seed_outcome.classification,
                        "signature": seed_outcome.trace_signature(),
                    },
                    "rendered_bytes": {
                        "sha256": drift["rendered_sha256"],
                        "size": len(rendered_seed),
                        "unit_count": len(codec.units),
                        "classification": rendered_outcome.classification,
                        "signature": rendered_outcome.trace_signature(),
                    },
                    "render_normalization_drift": drift,
                },
                "signature": {
                    "enforced": runner.signature_enforced(),
                    "value": runner.reference_signature_value,
                    "canonical": runner.reference_signature,
                    "sha256": (
                        sha256_bytes(runner.reference_signature.encode("ascii"))
                        if runner.reference_signature is not None
                        else None
                    ),
                },
                "minimized": {
                    "sha256": sha256_bytes(final),
                    "size": len(final),
                    "unit_count": len(reduced),
                    "one_minimal": minimal,
                    "fresh_verified": True,
                },
                "final_verification": {
                    "fresh": True,
                    "retries": args.retries,
                    "sha256": sha256_bytes(final),
                    "classification": final_outcome.classification,
                    "signature": final_outcome.trace_signature(),
                    "signature_matches_seed": signature_matches_seed,
                },
                "predicate": {
                    "command": predicate,
                    "executable": runner.executable,
                    "command_files": runner.command_files,
                    "environment": runner.environment_record,
                    "placeholder": PLACEHOLDER,
                    "interesting_exit": args.interesting_exit,
                    "boring_exit": args.boring_exit,
                    "invalid_exit": args.invalid_exit,
                    "timeout_seconds": args.timeout,
                    "retries": args.retries,
                },
                "evaluation_count": runner.evaluations,
                "process_run_count": runner.process_runs,
                "cache_hits": runner.cache_hits,
                "outcome_counts": runner.outcome_counts(),
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "evaluations": runner.trace,
            }
        atomic_bytes(output_path, final)
        try:
            atomic_json(trace_path, trace)
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
        log.discard()
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "status": "REDUCED",
                    "format": codec.kind,
                    "original_units": len(codec.units),
                    "minimized_units": len(reduced),
                    "evaluations": trace["evaluation_count"],
                    "cache_hits": trace["cache_hits"],
                    "outcome_counts": trace["outcome_counts"],
                    "one_minimal": True,
                    "fresh_verified": True,
                    "render_drift": drift["detected"],
                    "signature_enforced": runner.signature_enforced(),
                    "signature": runner.reference_signature,
                    "resumed_records": (
                        resumed_section["records_loaded"] if resumed_section else 0
                    ),
                    "output": display_path(output_path, root),
                    "trace": display_path(trace_path, root),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ReduceError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"reduce_fixture: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
