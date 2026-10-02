#!/usr/bin/env python3
"""Oracle fixture registry doctor, schema gate, and deterministic migration planner.

TODO ORACLE-REGISTRY-0001 (P0). RUDRA-GLUE: this tool has no Ghidra counterpart;
it is repo bookkeeping glue around the locked-oracle fixture corpus.

Subcommands
-----------
doctor    Reverse-discover every tracked metadata/runner/comparand and run all
          fail-closed checks (orphans, duplicate ids, missing provenance,
          status conflicts, stale/tombstoned function ids). Exit 0 clean,
          1 findings, 2 harness-input error.
schema    Validate tests/oracle/fixture_registry.json against
          tests/oracle/schema/fixture-v1.schema.json (target contract).
lint      doctor + schema in one fail-closed pass (strict is the only mode).
migration-status
          Summarize every doctor/schema/pre-B2 blocker that prevents metadata
          migration completion. Read-only and deterministic; exit 0 clean,
          1 with blockers, 2 on harness-input error.
plan      Emit the deterministic old->new function-id replacement plan for the
          registry fixtures, the runner-hardcoded GH12-F literals, and the
          metadata stable-function-id fields. Tombstones are diagnostic-only
          and never enter replacements. Never mutates files.
          --check-determinism renders the plan twice and verifies the outputs
          are byte-identical.
self-test Build a synthetic fixture matrix in a throwaway directory and verify
          that one-sided fake MATCH, orphans, duplicates, conflicts, and stale
          ids are each rejected, and that plan output is deterministic.

All output is repo-relative, sorted, and free of timestamps or host state, so
two runs over the same tree are byte-identical.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

TOOL_NAME = "oracle_registry.py"

REGISTRY_RELPATH = "tests/oracle/fixture_registry.json"
SCHEMA_RELPATH = "tests/oracle/schema/fixture-v1.schema.json"
LEDGER_RELPATH = "docs/alignment_audit/FUNCTION_LEDGER.json"
MIGRATION_RELPATH = "docs/alignment_audit/FUNCTION_ID_MIGRATION.json"
CONTINUITY_RELPATH = "docs/alignment_audit/FUNCTION_ID_CONTINUITY.json"
METADATA_DIR = "tests/oracle"
RUNNER_GLOB = "run_*_oracle.sh"
RUNNER_DIR = "tools"

REKEY_GAP_TODO = "FUNCTION-ID-MIGRATE-REKEY-0001"

FUNC_ID_RE = re.compile(r"\b(?:RG-F|GH12-F)-[A-Za-z0-9-]+")
RG_ID_RE = re.compile(r"^RG-F-[0-9a-f]{20}$")
GH_ID_RE = re.compile(r"^GH12-F-[0-9a-f]{20}$")
FIXTURE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]*[A-Z0-9]$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUNNER_METADATA_RE = re.compile(r"tests/oracle/[A-Za-z0-9_.\-/]+\.metadata\.json")

B2_STATUSES = ("MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED")
PRE_B2_STATUSES = ("PARTIAL_MATCH",)
RESIDUAL_TOKENS = ("MISMATCH", "UNTESTED", "NO_ORACLE", "PARTIAL_MATCH",
                   "PARTIAL", "MISSING")
LEGACY_RESIDUAL_MARKERS = ("OUT_OF_SCOPE", "OUT_OF_DOMAIN", "PROGRESS_ONLY", "RECORDED")
EMBEDDED_RESIDUAL_RE = re.compile(
    r"(?<![A-Z0-9_])(" + "|".join(
        re.escape(token)
        for token in sorted(RESIDUAL_TOKENS + LEGACY_RESIDUAL_MARKERS,
                            key=lambda item: (-len(item), item))
    ) + r")(?![A-Z0-9_])"
)
COMMON_OUTPUT_PIN_KEYS = (
    "expected_observation_sha256",
    "expected_statement_stdout_sha256",
    "expected_stdout_sha256",
)

INPUT_HASH_PATHS = (
    ("input_fingerprint",),
    ("machine_input_sha256",),
    ("input_sha256",),
    ("input_manifest", "sha256"),
    ("input", "sha256"),
    ("machine_input", "sha256"),
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_HARNESS = 2
LOCKED_ORACLE_COMMIT = "e40ed13014025f82488b1f8f7bca566894ac376b"
RUST_PROJECTION_FIELDS = (
    "id", "path", "name", "line", "end_line", "module", "owner", "signature",
    "is_test", "is_declaration",
)


class HarnessError(Exception):
    """Raised when the tool's own inputs are unusable (exit 2)."""


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump_json_canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True).encode("utf-8") + b"\n"


def delimited_status_token(value, tokens):
    """Parse an exact token with an optional non-empty delimited explanation."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if "\n" in text or "\r" in text:
        return None
    for token in sorted(tokens, key=lambda item: (-len(item), item)):
        if text == token:
            return token
        if not text.startswith(token):
            continue
        suffix = text[len(token):]
        if suffix.startswith((":", "：")):
            return token if suffix[1:].strip() else None
        suffix = suffix.lstrip(" \t")
        pairs = {"(": ")", "（": "）"}
        if not suffix or suffix[0] not in pairs:
            return None
        opener = suffix[0]
        closer = pairs[opener]
        if not suffix.endswith(closer) or not suffix[1:-1].strip():
            return None
        depth = 0
        for index, char in enumerate(suffix):
            if char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth < 0 or depth == 0 and index != len(suffix) - 1:
                    return None
        return token if depth == 0 else None
    return None


def status_token(value):
    """Return a canonical B2/pre-B2 prefix, or None for an invalid value.

    Legacy metadata uses ``MISMATCH: reason`` and ``NO_ORACLE (reason)``.
    ASCII/full-width colons and parentheses are recognized, but arbitrary
    whitespace prose is not: the delimiter remains mandatory so values such
    as ``MATCHED`` or ``MATCH explanation`` cannot be mistaken for ``MATCH``.
    """
    return delimited_status_token(value, B2_STATUSES + PRE_B2_STATUSES)


def residual_token(value):
    """Return the leading residual state used by legacy evidence containers."""
    return delimited_status_token(value, ("MATCH",) + RESIDUAL_TOKENS)


def dig(obj, path):
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def find_token_positions(text: str, token: str):
    """All (line, column) positions of token in text, in file order."""
    positions = []
    escaped = re.escape(token)
    pattern = re.compile(r"(?<![A-Za-z0-9_-])" + escaped + r"(?![A-Za-z0-9_-])")
    for line_no, line in enumerate(text.splitlines(), start=1):
        for match in pattern.finditer(line):
            positions.append((line_no, match.start() + 1))
    return positions


# ---------------------------------------------------------------------------
# minimal JSON-Schema (draft-07 subset) validator
# ---------------------------------------------------------------------------


class MiniSchemaValidator:
    """Validates the subset of draft-07 used by fixture-v1.schema.json.

    Supported keywords: type, const, enum, pattern, minLength, minimum,
    minItems, uniqueItems, minProperties, required, properties,
    additionalProperties (bool or schema), items, $ref (internal), title,
    description (ignored).
    """

    TYPE_CHECKS = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "null": type(None),
    }

    def __init__(self, schema: dict):
        self.schema = schema

    def resolve_ref(self, schema: dict) -> dict:
        seen = 0
        while isinstance(schema, dict) and "$ref" in schema:
            ref = schema["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                raise HarnessError(f"unsupported external $ref: {ref}")
            node = self.schema
            try:
                for part in ref[2:].split("/"):
                    node = node[part]
            except (KeyError, TypeError) as exc:
                raise HarnessError(f"unresolved internal $ref: {ref}") from exc
            schema = node
            seen += 1
            if seen > 32:
                raise HarnessError(f"cyclic $ref: {ref}")
        if not isinstance(schema, dict):
            raise HarnessError("schema nodes must be JSON objects")
        return schema

    def validate(self, instance, path: str = "$"):
        """Yield (path, rule, message) deviations in document order."""
        yield from self._validate(instance, self.schema, path)

    def _validate(self, instance, schema: dict, path: str):
        schema = self.resolve_ref(schema)
        if "type" in schema:
            expected = schema["type"]
            checker = self.TYPE_CHECKS.get(expected)
            if checker is None:
                raise HarnessError(f"unsupported type: {expected}")
            if isinstance(instance, bool) and expected in ("integer", "number"):
                yield (path, "type", f"expected {expected}, got boolean")
                return
            if not isinstance(instance, checker):
                yield (path, "type", f"expected {expected}, got {type(instance).__name__}")
                return
        if "const" in schema and instance != schema["const"]:
            yield (path, "const", f"expected const {schema['const']!r}, got {instance!r}")
        if "enum" in schema and instance not in schema["enum"]:
            yield (path, "enum", f"{instance!r} not in enum {schema['enum']}")
        if "pattern" in schema and isinstance(instance, str):
            if re.search(schema["pattern"], instance) is None:
                yield (path, "pattern", f"{instance!r} does not match {schema['pattern']}")
        if "minLength" in schema and isinstance(instance, str):
            if len(instance) < schema["minLength"]:
                yield (path, "minLength", f"length {len(instance)} < {schema['minLength']}")
        if "minimum" in schema and isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if instance < schema["minimum"]:
                yield (path, "minimum", f"{instance} < {schema['minimum']}")
        if "minItems" in schema and isinstance(instance, list):
            if len(instance) < schema["minItems"]:
                yield (path, "minItems", f"length {len(instance)} < {schema['minItems']}")
        if "uniqueItems" in schema and schema["uniqueItems"] and isinstance(instance, list):
            seen = []
            for item in instance:
                key = json.dumps(item, sort_keys=True)
                if key in seen:
                    yield (path, "uniqueItems", f"duplicate item {item!r}")
                    break
                seen.append(key)
        if "minProperties" in schema and isinstance(instance, dict):
            if len(instance) < schema["minProperties"]:
                yield (path, "minProperties", f"{len(instance)} properties < {schema['minProperties']}")
        if isinstance(instance, dict):
            for key in schema.get("required", []):
                if key not in instance:
                    yield (path, "required", f"missing required property {key!r}")
            properties = schema.get("properties", {})
            additional = schema.get("additionalProperties", True)
            for key in sorted(instance):
                child = f"{path}.{key}"
                if key in properties:
                    yield from self._validate(instance[key], properties[key], child)
                elif additional is False:
                    yield (child, "additionalProperties", "additional property not allowed")
                elif isinstance(additional, dict):
                    yield from self._validate(instance[key], additional, child)
        if isinstance(instance, list) and "items" in schema:
            for idx, item in enumerate(instance):
                yield from self._validate(item, schema["items"], f"{path}[{idx}]")


def validate_registry_against_schema(registry, schema_doc):
    validator = MiniSchemaValidator(schema_doc)
    return list(validator.validate(registry))


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def list_dir(root: str, rel_dir: str, predicate) -> list:
    directory = os.path.join(root, rel_dir)
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        rel = f"{rel_dir}/{name}"
        if predicate(rel):
            out.append(rel)
    return out


def load_registry(root: str):
    path = os.path.join(root, REGISTRY_RELPATH)
    if not os.path.isfile(path):
        raise HarnessError(f"registry missing: {REGISTRY_RELPATH}")
    try:
        return load_json(path)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"registry is not valid JSON: {exc}") from exc


def _git_environment() -> dict:
    environment = os.environ.copy()
    for name in (
        "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        environment.pop(name, None)
    environment.update(
        {"LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    )
    return environment


def _registry_git(root: str, arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_git_environment(),
        )
    except OSError as exc:
        raise HarnessError(f"cannot execute git: {exc}") from exc
    if result.returncode != 0:
        raise HarnessError(
            f"git {' '.join(arguments)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def _registry_git_optional(root: str, arguments: list[str]):
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_git_environment(),
        )
    except OSError as exc:
        raise HarnessError(f"cannot execute git: {exc}") from exc
    return result.stdout if result.returncode == 0 else None


def _expect_git_object(root: str, revision: str, expected: str, label: str) -> None:
    actual = _registry_git(root, ["rev-parse", revision]).strip()
    if actual != expected:
        raise HarnessError(f"continuity {label} mismatch: expected {expected}, got {actual}")


def _git_path_blob(root: str, revision: str, relative: str) -> str:
    output = _registry_git_optional(root, ["rev-parse", f"{revision}:{relative}"])
    return output.strip() if output is not None else "0" * 40


def _load_ledger_generator():
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "generate_function_ledger.py")
    if not os.path.isfile(module_path):
        raise HarnessError("generate_function_ledger.py is missing for continuity validation")
    module_dir = os.path.dirname(module_path)
    inserted = module_dir not in sys.path
    if inserted:
        sys.path.insert(0, module_dir)
    try:
        spec = importlib.util.spec_from_file_location("_rudra_function_ledger", module_path)
        if spec is None or spec.loader is None:
            raise HarnessError("cannot load generate_function_ledger.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, OSError, RuntimeError) as exc:
        raise HarnessError(f"cannot load function ledger scanner: {exc}") from exc
    finally:
        if inserted:
            sys.path.remove(module_dir)


def _rust_projection(records) -> list:
    projection = [
        {field: record.get(field) for field in RUST_PROJECTION_FIELDS}
        for record in records
    ]
    projection.sort(key=lambda record: (
        str(record.get("id")), str(record.get("path")),
        int(record.get("line") or 0), str(record.get("signature")),
    ))
    return projection


def _rust_projection_sha256(records) -> str:
    encoded = json.dumps(
        _rust_projection(records), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scan_current_rust(root: str, generator) -> list:
    source_root = os.path.join(root, "src")
    if not os.path.isdir(source_root):
        raise HarnessError("src directory is missing for continuity validation")
    records = []
    for directory, subdirs, files in os.walk(source_root):
        subdirs.sort()
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            records.extend(generator.collect_rust_identities(
                relative, read_text(path), generator.module_from_relative(relative)
            ))
    try:
        generator.assign_rust_locked_ids(records)
    except RuntimeError as exc:
        raise HarnessError(f"current Rust raw-ID collision: {exc}") from exc
    return records


def _scan_rust_blob(root: str, relative: str, blob: str, generator, cache: dict) -> dict:
    if blob == "0" * 40:
        return {}
    key = (relative, blob)
    if key in cache:
        return cache[key]
    source = _registry_git(root, ["cat-file", "blob", blob])
    records = generator.collect_rust_identities(
        relative, source, generator.module_from_relative(relative)
    )
    try:
        generator.assign_rust_locked_ids(records)
    except RuntimeError as exc:
        raise HarnessError(f"continuity blob {relative}@{blob} has raw-ID collision: {exc}") from exc
    code = generator.mask_non_code(source)
    pairs = generator.rust_brace_pairs(code)
    lines = source.splitlines()
    indexed = {}
    for record in records:
        annotation_kind, annotation = generator.marker_above(
            lines, int(record["line"]) - 1
        )
        record["_annotation"] = (
            (annotation_kind, json.dumps(annotation, sort_keys=True, separators=(",", ":")))
            if annotation else None
        )
        signature_end = generator.rust_signature_end(code, pairs, int(record["start"]))
        body = " ".join(code[signature_end:int(record["end"])].split())
        record["_masked_body"] = body if body and body != ";" else None
        token = record.get("id")
        if token in indexed:
            raise HarnessError(f"continuity blob {relative}@{blob} repeats ID {token}")
        indexed[token] = record
    cache[key] = indexed
    return indexed


def _validate_record_fields(record: dict, row: dict, prefix: str, label: str) -> None:
    fields = ("path", "module", "owner", "name", "signature")
    for field in fields:
        key = f"{prefix}_{field}" if prefix else field
        if row.get(key) != record.get(field):
            raise HarnessError(
                f"continuity {label} {key} mismatch: expected {record.get(field)!r}, "
                f"got {row.get(key)!r}"
            )


def _continuity_reviewed_indexes(generator):
    transition_required = (
        "base_id", "from_id", "to_id", "commit", "from_path", "to_path",
        "parent_blob", "child_blob", "review",
    )
    transition_rows = list(generator.CONTINUITY_REVIEWED_TRANSITIONS)
    transition_index = {}
    for row in transition_rows:
        if not isinstance(row, dict) or any(not row.get(field) for field in transition_required):
            raise HarnessError("generator continuity reviewed transition allowlist is malformed")
        key = (row["base_id"], row["from_id"], row["to_id"], row["commit"])
        if key in transition_index:
            raise HarnessError("generator continuity reviewed transition allowlist has duplicates")
        transition_index[key] = row

    tombstone_required = (
        "base_id", "from_id", "commit", "parent_blob", "child_blob", "reason",
    )
    tombstone_rows = list(generator.CONTINUITY_REVIEWED_TOMBSTONES)
    tombstone_index = {}
    for row in tombstone_rows:
        if not isinstance(row, dict) or any(not row.get(field) for field in tombstone_required):
            raise HarnessError("generator continuity reviewed tombstone allowlist is malformed")
        key = (row["base_id"], row["from_id"], row["commit"])
        if key in tombstone_index:
            raise HarnessError("generator continuity reviewed tombstone allowlist has duplicates")
        tombstone_index[key] = row
    return transition_index, tombstone_index


def _validate_reviewed_continuity_event(
    origin, event, evidence, reviewed_index, used_reviewed
) -> None:
    key = (origin, event["from_id"], event["to_id"], event["commit"])
    rule = reviewed_index.get(key)
    if rule is None:
        raise HarnessError(f"continuity reviewed event is absent from exact allowlist: {key}")
    expected = {
        "from_path": event["from_path"],
        "to_path": event["to_path"],
        "parent_blob": event["parent_blob"],
        "child_blob": event["child_blob"],
    }
    if any(rule[field] != value for field, value in expected.items()):
        raise HarnessError(f"continuity reviewed event path/blob pin mismatch: {key}")
    if evidence != ["reviewed_successor_allowlist", rule["review"]]:
        raise HarnessError(f"continuity reviewed event evidence/review mismatch: {key}")
    used_reviewed.add(key)


def _validate_continuity_tombstone_alias_chain(base_id, aliases, events) -> str:
    if (not isinstance(aliases, list) or not aliases
            or len(aliases) != len(events) + 1
            or len(aliases) != len(set(aliases))
            or aliases[0] != base_id):
        raise HarnessError(
            f"continuity tombstone aliases must be unique event chain plus terminal: {base_id}"
        )
    for index, event in enumerate(events):
        if (not isinstance(event, dict) or event.get("from_id") != aliases[index]
                or event.get("to_id") != aliases[index + 1]):
            raise HarnessError(
                f"continuity tombstone alias/event chain mismatch at {index}: {base_id}"
            )
    return aliases[-1]


def _verify_continuity_git(
    root: str, continuity: dict, migration: dict, ledger: dict
) -> tuple[set, set, object]:
    """Verify Git pins and return (baseline Rust IDs, current Rust IDs, scanner)."""

    baseline = continuity["baseline"]
    checkpoint = continuity["checkpoint"]
    history = continuity["history"]
    migration_target = migration.get("target")
    if not isinstance(migration_target, dict):
        raise HarnessError("continuity requires reconciled migration.target")
    for field in ("commit", "commit_tree", "src_tree", "ledger_blob", "ledger_sha256"):
        if baseline.get(field) != migration_target.get(field):
            raise HarnessError(
                f"continuity baseline.{field} does not equal migration target pin"
            )

    for block_name, block, pin_fields, sha_fields in (
        ("baseline", baseline,
         ("commit", "commit_tree", "src_tree", "ledger_blob",
          "migration_blob_at_checkpoint"),
         ("ledger_sha256", "rust_projection_sha256", "migration_sha256")),
        ("checkpoint", checkpoint,
         ("commit", "commit_tree", "src_tree"),
         ("rust_projection_sha256",)),
    ):
        for field in pin_fields:
            if not COMMIT_RE.fullmatch(str(block.get(field) or "")):
                raise HarnessError(f"continuity {block_name}.{field} is not a 40-hex pin")
        for field in sha_fields:
            if not SHA256_RE.fullmatch(str(block.get(field) or "")):
                raise HarnessError(f"continuity {block_name}.{field} is not a sha256 pin")
        if (not isinstance(block.get("rust_function_records"), int)
                or block["rust_function_records"] < 0):
            raise HarnessError(
                f"continuity {block_name}.rust_function_records must be a nonnegative integer"
            )

    _expect_git_object(root, f"{baseline['commit']}^{{commit}}", baseline["commit"],
                       "baseline commit")
    _expect_git_object(root, f"{baseline['commit']}^{{tree}}", baseline["commit_tree"],
                       "baseline commit tree")
    _expect_git_object(root, f"{baseline['commit']}:src", baseline["src_tree"],
                       "baseline src tree")
    _expect_git_object(
        root, f"{baseline['commit']}:{LEDGER_RELPATH}", baseline["ledger_blob"],
        "baseline ledger blob",
    )
    _expect_git_object(root, f"{checkpoint['commit']}^{{commit}}", checkpoint["commit"],
                       "checkpoint commit")
    _expect_git_object(root, f"{checkpoint['commit']}^{{tree}}", checkpoint["commit_tree"],
                       "checkpoint commit tree")
    _expect_git_object(root, f"{checkpoint['commit']}:src", checkpoint["src_tree"],
                       "checkpoint src tree")
    _expect_git_object(
        root, f"{checkpoint['commit']}:{MIGRATION_RELPATH}",
        baseline["migration_blob_at_checkpoint"], "baseline migration blob at checkpoint",
    )

    baseline_ledger_bytes = _registry_git(
        root, ["show", f"{baseline['commit']}:{LEDGER_RELPATH}"]
    ).encode("utf-8")
    if hashlib.sha256(baseline_ledger_bytes).hexdigest() != baseline["ledger_sha256"]:
        raise HarnessError("continuity baseline ledger sha256 mismatch")
    try:
        baseline_ledger = json.loads(baseline_ledger_bytes)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"continuity baseline ledger JSON is malformed: {exc}") from exc
    baseline_rust = baseline_ledger.get("rugra_functions")
    if not isinstance(baseline_rust, list):
        raise HarnessError("continuity baseline ledger rudra_functions is not an array")
    if (len(baseline_rust) != baseline["rust_function_records"]
            or _rust_projection_sha256(baseline_rust) != baseline["rust_projection_sha256"]):
        raise HarnessError("continuity baseline Rust projection count/hash mismatch")
    baseline_ids = {row.get("id") for row in baseline_rust if isinstance(row, dict)}
    if len(baseline_ids) != len(baseline_rust) or None in baseline_ids:
        raise HarnessError("continuity baseline ledger contains duplicate/malformed Rust IDs")

    migration_path = os.path.join(root, MIGRATION_RELPATH)
    migration_bytes = read_text(migration_path).encode("utf-8")
    if hashlib.sha256(migration_bytes).hexdigest() != baseline["migration_sha256"]:
        raise HarnessError("continuity worktree baseline migration sha256 mismatch")
    migration_blob = _registry_git(root, ["hash-object", migration_path]).strip()
    if migration_blob != baseline["migration_blob_at_checkpoint"]:
        raise HarnessError("continuity worktree baseline migration blob mismatch")

    if history.get("mode") != "first_parent":
        raise HarnessError("continuity history.mode must be first_parent")
    if (not isinstance(history.get("commit_count"), int)
            or history["commit_count"] <= 0
            or not COMMIT_RE.fullmatch(str(history.get("first_commit") or ""))
            or not COMMIT_RE.fullmatch(str(history.get("last_commit") or ""))):
        raise HarnessError("continuity history pins are malformed")
    if history["last_commit"] != checkpoint["commit"]:
        raise HarnessError("continuity history does not terminate at checkpoint")
    commits = _registry_git(
        root, ["rev-list", "--first-parent", "--reverse",
               f"{baseline['commit']}..{checkpoint['commit']}"],
    ).splitlines()
    if (len(commits) != history["commit_count"] or not commits
            or commits[0] != history["first_commit"]
            or commits[-1] != history["last_commit"]):
        raise HarnessError("continuity first-parent history count/endpoints mismatch")
    previous = baseline["commit"]
    for commit in commits:
        parent = _registry_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if parent != previous:
            raise HarnessError(
                f"continuity first-parent discontinuity at {commit}: {parent} != {previous}"
            )
        previous = commit

    for ancestor, descendant, label in (
        (baseline["commit"], checkpoint["commit"], "baseline/checkpoint ancestry"),
        (checkpoint["commit"], "HEAD", "checkpoint/HEAD ancestry"),
    ):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=root, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=_git_environment(),
        )
        if result.returncode != 0:
            raise HarnessError(f"continuity {label} mismatch")
    head_src = _registry_git(root, ["rev-parse", "HEAD:src"]).strip()
    if head_src != checkpoint["src_tree"]:
        raise HarnessError("continuity HEAD src tree differs from checkpoint")
    dirty_src = _registry_git(
        root, ["status", "--porcelain=v1", "--untracked-files=all", "--", "src"]
    ).strip()
    if dirty_src:
        raise HarnessError(f"continuity current src worktree is dirty:\n{dirty_src}")

    generator = _load_ledger_generator()
    fresh_rust = _scan_current_rust(root, generator)
    current_rust = ledger.get("rugra_functions")
    if not isinstance(current_rust, list):
        raise HarnessError("current ledger rudra_functions is not an array")
    if _rust_projection(fresh_rust) != _rust_projection(current_rust):
        raise HarnessError("continuity current ledger projection differs from fresh src scan")
    if (len(fresh_rust) != checkpoint["rust_function_records"]
            or _rust_projection_sha256(fresh_rust) != checkpoint["rust_projection_sha256"]):
        raise HarnessError("continuity checkpoint Rust projection count/hash mismatch")
    current_ids = {row.get("id") for row in fresh_rust}
    if len(current_ids) != len(fresh_rust) or None in current_ids:
        raise HarnessError("continuity current Rust projection contains duplicate/malformed IDs")
    return baseline_ids, current_ids, generator


def _load_and_validate_continuity(
    root: str, ledger: dict, migration: dict, baseline_token_owner: dict,
    *, path_override=None,
):  # noqa: C901
    # ``path_override`` is a private test seam; CLI callers always load the
    # canonical repository path and every byte is still checked against pins.
    path = path_override or os.path.join(root, CONTINUITY_RELPATH)
    if not os.path.isfile(path):
        return {}, {}, None
    try:
        continuity = load_json(path)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"continuity table is not valid JSON: {exc}") from exc
    if not isinstance(continuity, dict) or continuity.get("schema") not in (1, 2):
        raise HarnessError("function continuity root must be a schema 1 or 2 object")
    if continuity.get("oracle_commit") != LOCKED_ORACLE_COMMIT:
        raise HarnessError("function continuity oracle commit pin mismatch")
    if (continuity.get("id_scheme") != migration.get("id_scheme")
            or continuity.get("id_scheme") != ledger.get("id_scheme")):
        raise HarnessError("function continuity id_scheme differs from migration/current ledger")
    for field in ("baseline", "checkpoint", "history", "stats"):
        if not isinstance(continuity.get(field), dict):
            raise HarnessError(f"function continuity {field} must be an object")
    for field in ("lineages", "introduced_live", "tombstones"):
        if not isinstance(continuity.get(field), list):
            raise HarnessError(f"function continuity {field} must be an array")

    baseline_ids, current_ids, generator = _verify_continuity_git(
        root, continuity, migration, ledger
    )
    reviewed_index, reviewed_tombstone_index = _continuity_reviewed_indexes(generator)
    used_reviewed = set()
    used_reviewed_tombstones = set()
    ordered_history = _registry_git(
        root, ["rev-list", "--first-parent", "--reverse",
               f"{continuity['baseline']['commit']}..{continuity['checkpoint']['commit']}"],
    ).splitlines()
    history_commits = set(ordered_history)
    commit_order = {commit: index for index, commit in enumerate(ordered_history)}
    blob_cache = {}
    owner_by_token = dict(baseline_token_owner)
    final_owner = {}
    live_map = {}
    tombstone_map = {}

    def class_owner(base_id):
        return baseline_token_owner.get(base_id, f"continuity:{base_id}")

    def claim(token, origin, role):
        if not isinstance(token, str) or not RG_ID_RE.fullmatch(token):
            raise HarnessError(f"continuity {role} token is not a scheme-2 Rust ID: {token!r}")
        previous = owner_by_token.get(token)
        if previous is not None and previous != origin:
            raise HarnessError(
                f"continuity token {token} belongs to multiple classes: {previous}, {origin}"
            )
        owner_by_token[token] = origin

    introduced_by_base = {}
    for row in continuity["introduced_live"]:
        required = (
            "base_id", "new_id", "introduced_at_commit", "path", "module", "owner",
            "name", "signature", "parent_blob", "child_blob",
        )
        if not isinstance(row, dict) or any(not row.get(field) for field in required):
            raise HarnessError("malformed continuity introduced_live row")
        base_id = row["base_id"]
        if (base_id in introduced_by_base or base_id in baseline_ids
                or base_id in baseline_token_owner):
            raise HarnessError(f"continuity introduced base is duplicate/historical: {base_id}")
        if row["introduced_at_commit"] not in history_commits:
            raise HarnessError(f"continuity introduced commit is outside history: {base_id}")
        for field in ("introduced_at_commit", "parent_blob", "child_blob"):
            if not COMMIT_RE.fullmatch(str(row[field])):
                raise HarnessError(f"continuity introduced {base_id} has malformed {field}")
        commit = row["introduced_at_commit"]
        parent = _registry_git(root, ["rev-parse", f"{commit}^1"]).strip()
        actual_parent_blob = _git_path_blob(root, parent, row["path"])
        actual_child_blob = _git_path_blob(root, commit, row["path"])
        if (actual_parent_blob != row["parent_blob"]
                or actual_child_blob != row["child_blob"]):
            raise HarnessError(f"continuity introduced {base_id} blob pin mismatch")
        parent_records = _scan_rust_blob(
            root, row["path"], row["parent_blob"], generator, blob_cache
        )
        child_records = _scan_rust_blob(
            root, row["path"], row["child_blob"], generator, blob_cache
        )
        if base_id in parent_records or base_id not in child_records:
            raise HarnessError(f"continuity introduced {base_id} is not newly added in its event")
        _validate_record_fields(child_records[base_id], row, "", f"introduced {base_id}")
        introduced_by_base[base_id] = row
        claim(base_id, class_owner(base_id), "introduced base")

    def validate_events(origin, aliases, events, expected_terminal, minimum_order=-1):
        if len(aliases) != len(set(aliases)) or len(events) != len(aliases):
            raise HarnessError(f"continuity alias/event length or uniqueness mismatch for {origin}")
        expected_from = origin
        previous_order = minimum_order
        for index, event in enumerate(events):
            required = (
                "from_id", "to_id", "commit", "from_path", "to_path",
                "from_module", "to_module", "from_owner", "to_owner",
                "from_name", "to_name", "from_signature", "to_signature",
                "parent_blob", "child_blob", "evidence",
            )
            if not isinstance(event, dict) or any(field not in event for field in required):
                raise HarnessError(f"malformed continuity event {index} for {origin}")
            if event["from_id"] != expected_from or aliases[index] != event["from_id"]:
                raise HarnessError(f"non-contiguous continuity event {index} for {origin}")
            if event["commit"] not in history_commits:
                raise HarnessError(f"continuity event commit outside history for {origin}")
            event_order = commit_order[event["commit"]]
            if event_order <= previous_order:
                raise HarnessError(f"continuity events are not strictly chronological for {origin}")
            previous_order = event_order
            for field in ("commit", "parent_blob", "child_blob"):
                if not COMMIT_RE.fullmatch(str(event[field])):
                    raise HarnessError(f"continuity event {index} has malformed {field}")
            evidence = event["evidence"]
            if (not isinstance(evidence, list) or not evidence
                    or len(evidence) != len(set(evidence))):
                raise HarnessError(f"continuity event {index} lacks unique evidence")
            commit = event["commit"]
            parent = _registry_git(root, ["rev-parse", f"{commit}^1"]).strip()
            actual_parent_blob = _git_path_blob(root, parent, event["from_path"])
            actual_child_blob = _git_path_blob(root, commit, event["to_path"])
            if (actual_parent_blob != event["parent_blob"]
                    or actual_child_blob != event["child_blob"]):
                raise HarnessError(f"continuity event {index} blob pin mismatch for {origin}")
            before = _scan_rust_blob(
                root, event["from_path"], event["parent_blob"], generator, blob_cache
            )
            after = _scan_rust_blob(
                root, event["to_path"], event["child_blob"], generator, blob_cache
            )
            if event["from_id"] not in before or event["to_id"] not in after:
                raise HarnessError(f"continuity event {index} IDs absent from pinned blobs")
            if event["to_id"] in before or event["from_id"] in after:
                raise HarnessError(
                    f"continuity event {index} is not a removed-to-new transition for {origin}"
                )
            _validate_record_fields(before[event["from_id"]], event, "from",
                                    f"event {index} from")
            _validate_record_fields(after[event["to_id"]], event, "to",
                                    f"event {index} to")
            automatic_kind = None
            if "parameter_binding_mut_only" in evidence:
                automatic_kind = "parameter_binding_mut_only"
            elif "signature_trailing_comma_only" in evidence:
                automatic_kind = "signature_trailing_comma_only"
            if automatic_kind is not None:
                required_auto = {
                    "same_patch_hunk", "identical_nonempty_annotation",
                    automatic_kind,
                }
                if set(evidence) != required_auto:
                    raise HarnessError(f"continuity automatic evidence set drift for {origin}")
                if any(event[f"from_{field}"] != event[f"to_{field}"]
                       for field in ("path", "module", "owner", "name")):
                    raise HarnessError(f"continuity automatic identity context drift for {origin}")
                old_signature = event["from_signature"]
                new_signature = event["to_signature"]
                if automatic_kind == "parameter_binding_mut_only":
                    if (old_signature == new_signature
                            or generator.rust_parameter_binding_mut_normalized_signature(old_signature)
                            != generator.rust_parameter_binding_mut_normalized_signature(new_signature)):
                        raise HarnessError(f"continuity non-mut signature change for {origin}")
                elif (old_signature == new_signature
                        or generator.rust_trailing_comma_normalized_signature(old_signature)
                        != generator.rust_trailing_comma_normalized_signature(new_signature)):
                    raise HarnessError(
                        f"continuity non-separator signature change for {origin}")
                hunks = generator._diff_hunks(
                    generator.Path(root), parent, commit, event["from_path"], {}
                )
                computed = generator.continuity_transition_evidence(
                    before[event["from_id"]], after[event["to_id"]], hunks
                )
                if set(computed) != required_auto:
                    raise HarnessError(
                        f"continuity automatic evidence does not reproduce from Git for {origin}"
                    )
            else:
                _validate_reviewed_continuity_event(
                    origin, event, evidence, reviewed_index, used_reviewed
                )
            expected_from = event["to_id"]
        if expected_from != expected_terminal:
            raise HarnessError(f"continuity lineage for {origin} terminates at {expected_from}")
        return previous_order

    lineage_bases = set()
    for row in continuity["lineages"]:
        if not isinstance(row, dict):
            raise HarnessError("continuity lineage must be an object")
        base_id, new_id = row.get("base_id"), row.get("new_id")
        aliases, events = row.get("aliases"), row.get("events")
        origin_kind = row.get("origin_kind")
        if (not isinstance(base_id, str) or not isinstance(new_id, str)
                or not isinstance(aliases, list) or not isinstance(events, list)):
            raise HarnessError("malformed continuity lineage")
        if base_id in lineage_bases:
            raise HarnessError(f"continuity contains duplicate lineage base {base_id}")
        lineage_bases.add(base_id)
        if ((origin_kind == "baseline" and base_id not in baseline_ids)
                or (origin_kind == "introduced_live" and base_id not in introduced_by_base)
                or origin_kind not in ("baseline", "introduced_live")):
            raise HarnessError(f"continuity lineage origin kind/base mismatch for {base_id}")
        if new_id not in current_ids:
            raise HarnessError(f"continuity live terminal absent current ledger: {new_id}")
        if base_id in current_ids and new_id != base_id:
            # A base token that still lives while its lineage terminates
            # elsewhere is stale.  new_id == base_id is the proven round-trip
            # (param added then reverted, e.g. try_output_stack_guard
            # 3dc4b2ae -> 8b387a8d): the original identity is current again.
            raise HarnessError(f"continuity stale base remains in current ledger: {base_id}")
        owner = class_owner(base_id)
        previous_final = final_owner.get(new_id)
        if previous_final is not None and previous_final != owner:
            raise HarnessError(
                f"continuity multiple classes converge on {new_id}: {previous_final}, {owner}"
            )
        if new_id in baseline_ids and new_id != base_id:
            raise HarnessError(f"continuity terminal collides with baseline class: {new_id}")
        if new_id in baseline_token_owner and new_id != base_id:
            # new_id == base_id is the proven round-trip return: the class
            # terminates on its own historical token, which it never left.
            raise HarnessError(f"continuity terminal reuses a historical migration token: {new_id}")
        minimum_order = (
            commit_order[introduced_by_base[base_id]["introduced_at_commit"]]
            if origin_kind == "introduced_live" else -1
        )
        validate_events(base_id, aliases, events, new_id, minimum_order)
        claim(base_id, owner, "lineage base")
        for alias_index, alias in enumerate(aliases):
            if alias in current_ids and alias != new_id:
                # An alias equal to the terminal is the live record; a
                # round-trip lineage (param added then reverted) terminates on
                # its own base, which is also aliases[0].
                raise HarnessError(f"continuity stale alias remains current: {alias}")
            if (alias in baseline_token_owner
                    and not (alias_index == 0 and alias == base_id)):
                raise HarnessError(
                    f"continuity intermediate alias reuses a historical migration token: {alias}"
                )
            claim(alias, owner, "lineage alias")
            live_map[alias] = new_id
        claim(new_id, owner, "lineage terminal")
        final_owner[new_id] = owner
        live_map[base_id] = new_id

    for base_id, row in introduced_by_base.items():
        terminal = live_map.get(base_id, base_id)
        if row["new_id"] != terminal or terminal not in current_ids:
            raise HarnessError(f"continuity introduced {base_id} terminal mismatch/absent")

    tombstone_bases = set()
    for row in continuity["tombstones"]:
        required = (
            "base_id", "aliases", "path", "module", "owner", "name", "signature",
            "deleted_at_commit", "parent_blob", "child_blob", "reason", "events",
        )
        if not isinstance(row, dict) or any(field not in row for field in required):
            raise HarnessError("malformed continuity tombstone")
        base_id, aliases, events = row["base_id"], row["aliases"], row["events"]
        if base_id in tombstone_bases or base_id in lineage_bases:
            raise HarnessError(f"continuity duplicate live/tombstone base {base_id}")
        tombstone_bases.add(base_id)
        # Schema 2: a tombstone of a post-baseline introduced class carries its
        # origin provenance inline (the class no longer has an introduced_live
        # row), validated here exactly like a live introduction.
        origin_minimum_order = -1
        if base_id not in baseline_ids and base_id not in introduced_by_base:
            origin = row.get("origin")
            if not isinstance(origin, dict) or origin.get("kind") != "introduced_live":
                raise HarnessError(
                    f"continuity tombstone base has no known origin: {base_id}"
                )
            origin_required = (
                "kind", "introduced_at_commit", "path", "module", "owner",
                "name", "signature", "parent_blob", "child_blob",
            )
            if any(not origin.get(field) for field in origin_required):
                raise HarnessError(
                    f"malformed continuity tombstone origin {base_id}"
                )
            origin_commit = origin["introduced_at_commit"]
            if (origin_commit not in history_commits
                    or not COMMIT_RE.fullmatch(str(origin_commit))):
                raise HarnessError(
                    f"continuity tombstone origin commit outside history: {base_id}"
                )
            origin_parent = _registry_git(
                root, ["rev-parse", f"{origin_commit}^1"]
            ).strip()
            if (_git_path_blob(root, origin_parent, origin["path"]) != origin["parent_blob"]
                    or _git_path_blob(root, origin_commit, origin["path"])
                    != origin["child_blob"]):
                raise HarnessError(
                    f"continuity tombstone origin blob pin mismatch: {base_id}"
                )
            origin_parent_records = _scan_rust_blob(
                root, origin["path"], origin["parent_blob"], generator, blob_cache
            )
            origin_child_records = _scan_rust_blob(
                root, origin["path"], origin["child_blob"], generator, blob_cache
            )
            if base_id in origin_parent_records or base_id not in origin_child_records:
                raise HarnessError(
                    f"continuity tombstone origin {base_id} is not newly added in its event"
                )
            _validate_record_fields(
                origin_child_records[base_id], origin,
                "", f"tombstone origin {base_id}",
            )
            claim(base_id, class_owner(base_id), "tombstone origin base")
            origin_minimum_order = commit_order[origin_commit]
        if (not isinstance(aliases, list)
                or not isinstance(events, list) or not row["reason"]):
            raise HarnessError(f"malformed continuity tombstone {base_id}")
        final_deleted = _validate_continuity_tombstone_alias_chain(
            base_id, aliases, events
        )
        minimum_order = (
            commit_order[introduced_by_base[base_id]["introduced_at_commit"]]
            if base_id in introduced_by_base else origin_minimum_order
        )
        last_event_order = validate_events(
            base_id, aliases[:len(events)], events, final_deleted, minimum_order
        )
        commit = row["deleted_at_commit"]
        if commit not in history_commits:
            raise HarnessError(f"continuity tombstone commit outside history: {base_id}")
        if commit_order[commit] <= last_event_order:
            raise HarnessError(f"continuity tombstone is not after its lineage: {base_id}")
        tombstone_key = (base_id, final_deleted, commit)
        tombstone_rule = reviewed_tombstone_index.get(tombstone_key)
        if tombstone_rule is None:
            raise HarnessError(
                f"continuity tombstone is absent from exact allowlist: {tombstone_key}"
            )
        tombstone_pins = {
            "parent_blob": row["parent_blob"],
            "child_blob": row["child_blob"],
            "reason": row["reason"],
        }
        if any(tombstone_rule[field] != value for field, value in tombstone_pins.items()):
            raise HarnessError(f"continuity tombstone allowlist pin mismatch: {base_id}")
        for field in ("path", "module", "owner", "name", "signature"):
            if field in tombstone_rule and tombstone_rule[field] != row[field]:
                raise HarnessError(
                    f"continuity tombstone allowlist {field} mismatch: {base_id}"
                )
        used_reviewed_tombstones.add(tombstone_key)
        parent = _registry_git(root, ["rev-parse", f"{commit}^1"]).strip()
        if (_git_path_blob(root, parent, row["path"]) != row["parent_blob"]
                or _git_path_blob(root, commit, row["path"]) != row["child_blob"]):
            raise HarnessError(f"continuity tombstone blob pin mismatch: {base_id}")
        before = _scan_rust_blob(
            root, row["path"], row["parent_blob"], generator, blob_cache
        )
        after = _scan_rust_blob(
            root, row["path"], row["child_blob"], generator, blob_cache
        )
        if final_deleted not in before or final_deleted in after:
            raise HarnessError(f"continuity tombstone deletion proof failed: {base_id}")
        _validate_record_fields(before[final_deleted], row, "", f"tombstone {base_id}")
        owner = class_owner(base_id)
        for token in [base_id, *aliases]:
            if token in current_ids:
                raise HarnessError(f"continuity tombstone token remains current: {token}")
            if (token in baseline_token_owner
                    and token != base_id):
                raise HarnessError(
                    f"continuity tombstone alias reuses a historical migration token: {token}"
                )
            claim(token, owner, "tombstone")
            tombstone_map[token] = row

    for base_id in baseline_ids:
        if base_id in current_ids:
            if base_id in tombstone_map:
                raise HarnessError(f"continuity current baseline ID also has a terminal: {base_id}")
            if base_id in live_map and live_map[base_id] != base_id:
                # live_map[base_id] == base_id is the proven round-trip return;
                # any other terminal means the token is current while its
                # lineage claims it moved on.
                raise HarnessError(f"continuity current baseline ID also has a terminal: {base_id}")
        elif base_id not in live_map and base_id not in tombstone_map:
            raise HarnessError(
                f"continuity missing unique terminal/tombstone for old baseline ID {base_id}"
            )

    covered_current = set(baseline_ids).intersection(current_ids)
    covered_current.update(final_owner)
    covered_current.update(row["new_id"] for row in introduced_by_base.values())
    if covered_current != current_ids:
        raise HarnessError(
            "continuity current Rust closure is incomplete/colliding: "
            f"missing={sorted(current_ids-covered_current)[:3]} "
            f"extra={sorted(covered_current-current_ids)[:3]}"
        )

    stats = continuity["stats"]
    expected_stats = {
        "baseline_records": len(baseline_ids),
        "current_records": len(current_ids),
        "introduced_live": len(continuity["introduced_live"]),
        "lineages": len(continuity["lineages"]),
        "events": sum(len(row.get("events", [])) for row in continuity["lineages"]),
        "tombstones": len(continuity["tombstones"]),
        "alias_tokens": sum(len(row.get("aliases", [])) for row in continuity["lineages"]),
    }
    for field, expected in expected_stats.items():
        if stats.get(field) != expected:
            raise HarnessError(
                f"continuity stats.{field} mismatch: expected {expected}, got {stats.get(field)!r}"
            )
    for field in ("ambiguous", "collisions"):
        if stats.get(field) != 0:
            raise HarnessError(f"continuity stats.{field} must be zero")
    reviewed_events = sum(
        1 for row in continuity["lineages"] for event in row.get("events", [])
        if event.get("evidence", [None])[0] == "reviewed_successor_allowlist"
    )
    if stats.get("reviewed_transitions") != reviewed_events:
        raise HarnessError(
            "continuity stats.reviewed_transitions mismatch: "
            f"expected {reviewed_events}, got {stats.get('reviewed_transitions')!r}"
        )
    if used_reviewed != set(reviewed_index):
        raise HarnessError(
            "continuity reviewed transition allowlist coverage mismatch: "
            f"missing={sorted(set(reviewed_index)-used_reviewed)} "
            f"extra={sorted(used_reviewed-set(reviewed_index))}"
        )
    if used_reviewed_tombstones != set(reviewed_tombstone_index):
        raise HarnessError(
            "continuity reviewed tombstone allowlist coverage mismatch: "
            f"missing={sorted(set(reviewed_tombstone_index)-used_reviewed_tombstones)} "
            f"extra={sorted(used_reviewed_tombstones-set(reviewed_tombstone_index))}"
        )
    return live_map, tombstone_map, continuity


def load_function_tables(root: str, *, _continuity_path=None):
    """Return IDs, composed aliases, tombstones, migration, and continuity.

    Reconciled schema-2 migrations preserve the immutable legacy ``old_id``
    and every intermediate scheme-2 alias.  Tombstones deliberately do not
    enter the replacement map: references to them get their own diagnostic.
    """
    ledger_path = os.path.join(root, LEDGER_RELPATH)
    migration_path = os.path.join(root, MIGRATION_RELPATH)
    if not os.path.isfile(ledger_path):
        raise HarnessError(f"function ledger missing: {LEDGER_RELPATH}")
    if not os.path.isfile(migration_path):
        raise HarnessError(f"migration table missing: {MIGRATION_RELPATH}")
    try:
        ledger = load_json(ledger_path)
        migration = load_json(migration_path)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"ledger/migration JSON error: {exc}") from exc
    if not isinstance(ledger, dict) or not isinstance(migration, dict):
        raise HarnessError("ledger and migration roots must be JSON objects")
    for field in ("ghidra_functions", "rugra_functions"):
        if not isinstance(ledger.get(field), list):
            raise HarnessError(f"function ledger {field} must be an array")
    for field in ("entries", "disambiguators"):
        if not isinstance(migration.get(field), list):
            raise HarnessError(f"function migration {field} must be an array")
    schema = migration.get("schema")
    if schema not in (1, 2):
        raise HarnessError(f"function migration schema must be 1 or 2, got {schema!r}")
    tombstone_rows = migration.get("tombstones", [])
    if not isinstance(tombstone_rows, list):
        raise HarnessError("function migration tombstones must be an array")
    if schema == 2:
        for field in ("source", "target", "history", "stats"):
            if not isinstance(migration.get(field), dict):
                raise HarnessError(f"reconciled function migration {field} must be an object")
        if migration.get("oracle_commit") != LOCKED_ORACLE_COMMIT:
            raise HarnessError("reconciled function migration oracle commit pin mismatch")
        pin_shapes = {
            "source": ("commit", "commit_tree", "src_tree", "ledger_blob", "migration_blob"),
            "target": ("commit", "commit_tree", "src_tree", "ledger_blob"),
        }
        for block, fields in pin_shapes.items():
            for field in fields:
                if not COMMIT_RE.fullmatch(str(migration[block].get(field) or "")):
                    raise HarnessError(f"reconciled migration {block}.{field} is not a 40-hex pin")
            for field in ("ledger_sha256",) + (("migration_sha256",) if block == "source" else ()):
                if not SHA256_RE.fullmatch(str(migration[block].get(field) or "")):
                    raise HarnessError(f"reconciled migration {block}.{field} is not a sha256 pin")
        history = migration["history"]
        if (history.get("mode") != "first_parent"
                or not isinstance(history.get("commit_count"), int)
                or history.get("commit_count", 0) <= 0
                or not COMMIT_RE.fullmatch(str(history.get("first_commit") or ""))
                or not COMMIT_RE.fullmatch(str(history.get("last_commit") or ""))):
            raise HarnessError("reconciled migration history pins are malformed")
    ids = set()
    for fn in ledger["ghidra_functions"] + ledger["rugra_functions"]:
        if not isinstance(fn, dict):
            raise HarnessError("function ledger entries must be JSON objects")
        fid = fn.get("id")
        if isinstance(fid, str):
            if fid in ids:
                raise HarnessError(f"function ledger contains duplicate function id {fid}")
            ids.add(fid)
    old_to_new = {}
    owner_by_token = {}
    final_owner = {}

    def claim_live(token, new_id, origin, role):
        if not isinstance(token, str) or not isinstance(new_id, str):
            raise HarnessError(f"function migration {role} tokens must be strings")
        previous_owner = owner_by_token.get(token)
        if previous_owner is not None and previous_owner != origin:
            raise HarnessError(
                f"function migration token {token} belongs to multiple origins: "
                f"{previous_owner}, {origin}"
            )
        owner_by_token[token] = origin
        if token in old_to_new and old_to_new[token] != new_id:
            raise HarnessError(f"ambiguous migration mapping for {token}")
        old_to_new[token] = new_id

    for entry in migration["entries"]:
        if not isinstance(entry, dict):
            raise HarnessError("function migration entries must be JSON objects")
        old_id, new_id = entry.get("old_id"), entry.get("new_id")
        if not isinstance(old_id, str) or not isinstance(new_id, str):
            raise HarnessError("function migration entry old_id/new_id must be strings")
        previous_final_owner = final_owner.get(new_id)
        if previous_final_owner is not None and previous_final_owner != old_id:
            raise HarnessError(
                f"multiple migration origins converge on {new_id}: {previous_final_owner}, {old_id}"
            )
        final_owner[new_id] = old_id
        previous_token_owner = owner_by_token.get(new_id)
        if previous_token_owner is not None and previous_token_owner != old_id:
            raise HarnessError(
                f"function migration final token {new_id} also belongs to origin "
                f"{previous_token_owner}"
            )
        owner_by_token[new_id] = old_id
        claim_live(old_id, new_id, old_id, "entry")
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise HarnessError(f"function migration aliases for {old_id} must be an array")
        if len(aliases) != len(set(aliases)):
            raise HarnessError(f"function migration aliases for {old_id} contain duplicates")
        for alias in aliases:
            if alias == new_id:
                raise HarnessError(f"function migration alias {alias} equals its final target")
            if schema == 2 and alias in ids:
                raise HarnessError(
                    f"function migration alias {alias} is an unrelated current-ledger id"
                )
            claim_live(alias, new_id, old_id, "alias")
        if schema == 2 and aliases:
            lineage = entry.get("lineage")
            if not isinstance(lineage, list) or len(lineage) != len(aliases):
                raise HarnessError(f"reconciled migration lineage/alias length mismatch for {old_id}")
            expected_from = aliases[0]
            for index, event in enumerate(lineage):
                required = ("from_id", "to_id", "commit", "from_path", "to_path",
                            "parent_blob", "child_blob", "evidence")
                if not isinstance(event, dict) or any(field not in event for field in required):
                    raise HarnessError(f"malformed lineage event {index} for {old_id}")
                if event["from_id"] != expected_from or event["from_id"] != aliases[index]:
                    raise HarnessError(f"non-contiguous lineage event {index} for {old_id}")
                for field in ("commit", "parent_blob", "child_blob"):
                    if not COMMIT_RE.fullmatch(str(event[field])):
                        raise HarnessError(f"lineage event {index} for {old_id} has malformed {field}")
                if not isinstance(event["evidence"], list) or not event["evidence"]:
                    raise HarnessError(f"lineage event {index} for {old_id} lacks evidence")
                expected_from = event["to_id"]
            if expected_from != new_id:
                raise HarnessError(f"lineage for {old_id} does not terminate at {new_id}")
        elif schema == 2 and entry.get("lineage"):
            raise HarnessError(f"reconciled migration {old_id} has lineage without aliases")
    for entry in migration["disambiguators"]:
        if not isinstance(entry, dict):
            raise HarnessError("function migration disambiguators must be JSON objects")
        old_id, new_id = entry.get("old_id"), entry.get("new_id")
        if not isinstance(old_id, str) or not isinstance(new_id, str):
            raise HarnessError("function migration disambiguator old_id/new_id must be strings")
        claim_live(old_id, new_id, old_id, "disambiguator")

    tombstones = {}
    for row in tombstone_rows:
        if not isinstance(row, dict):
            raise HarnessError("function migration tombstones must be JSON objects")
        origin = row.get("old_id")
        aliases = row.get("aliases")
        required = ("path", "module", "owner", "name", "signature",
                    "deleted_at_commit", "parent_blob", "child_blob", "reason")
        if (not isinstance(origin, str) or not isinstance(aliases, list) or not aliases
                or any(not row.get(field) for field in required)):
            raise HarnessError(f"malformed function migration tombstone {origin!r}")
        if len(aliases) != len(set(aliases)):
            raise HarnessError(f"tombstone {origin} contains duplicate aliases")
        for field in ("deleted_at_commit", "parent_blob", "child_blob"):
            if not COMMIT_RE.fullmatch(str(row[field])):
                raise HarnessError(f"tombstone {origin} has malformed {field}")
        for token in [origin, *aliases]:
            if not isinstance(token, str):
                raise HarnessError(f"tombstone {origin} alias is not a string")
            if token in ids:
                raise HarnessError(f"tombstoned function id {token} is still in current ledger")
            previous_owner = owner_by_token.get(token)
            if previous_owner is not None and previous_owner != origin:
                raise HarnessError(
                    f"function migration token {token} belongs to live/tombstone origins "
                    f"{previous_owner}, {origin}"
                )
            if token in tombstones and tombstones[token].get("old_id") != origin:
                raise HarnessError(f"tombstone alias {token} belongs to multiple origins")
            owner_by_token[token] = origin
            tombstones[token] = row
    if schema == 2:
        stats = migration["stats"]
        live_alias_count = sum(len(entry.get("aliases", [])) for entry in migration["entries"])
        expected_stats = {
            "origin_entries": len(migration["entries"]),
            "tombstones": len(tombstone_rows),
            "alias_tokens": live_alias_count,
            "original_definitions": len(migration["entries"]) + len(tombstone_rows),
        }
        for field, expected in expected_stats.items():
            if stats.get(field) != expected:
                raise HarnessError(
                    f"reconciled migration stats.{field} mismatch: expected {expected}, "
                    f"got {stats.get(field)!r}"
                )
    continuity_live, continuity_tombstones, continuity = _load_and_validate_continuity(
        root, ledger, migration, owner_by_token, path_override=_continuity_path
    )
    if continuity is None:
        if schema == 2:
            missing = sorted(
                str(entry.get("new_id")) for entry in migration["entries"]
                if entry.get("new_id") not in ids
            )
            if missing:
                raise HarnessError(
                    "reconciled migration live target is absent from current ledger and "
                    f"no continuity table is present: {missing[0]}"
                )
        return ids, old_to_new, tombstones, migration, None

    effective_live = {}
    effective_tombstones = dict(tombstones)
    for token, baseline_target in old_to_new.items():
        if baseline_target in continuity_tombstones:
            effective_tombstones[token] = continuity_tombstones[baseline_target]
            continue
        terminal = continuity_live.get(baseline_target, baseline_target)
        if terminal not in ids:
            raise HarnessError(
                f"continuity composition leaves migration token {token} without live target: "
                f"{baseline_target} -> {terminal}"
            )
        effective_live[token] = terminal
    for token, terminal in continuity_live.items():
        if token in effective_tombstones:
            raise HarnessError(f"continuity token is both live and tombstoned: {token}")
        previous = effective_live.get(token)
        if previous is not None and previous != terminal:
            raise HarnessError(
                f"continuity composition is ambiguous for {token}: {previous}, {terminal}"
            )
        if terminal not in ids:
            raise HarnessError(f"continuity terminal absent current ledger: {terminal}")
        effective_live[token] = terminal
    for token, row in continuity_tombstones.items():
        if token in effective_live:
            raise HarnessError(f"continuity token is both live and tombstoned: {token}")
        effective_tombstones[token] = row
    # Propagate a post-baseline tombstone through every immutable migration
    # token that formerly resolved to its baseline final.
    for token, baseline_target in old_to_new.items():
        if baseline_target in continuity_tombstones:
            effective_tombstones[token] = continuity_tombstones[baseline_target]
    return ids, effective_live, effective_tombstones, migration, continuity


def discover(root: str, registry) -> dict:
    """Reverse-discover disk metadata/runners and their cross-references."""
    disk_metadata = list_dir(root, METADATA_DIR, lambda p: p.endswith(".metadata.json"))
    disk_runners = list_dir(root, RUNNER_DIR, lambda p: re.fullmatch(
        r"tools/" + RUNNER_GLOB.replace("*", "[a-z0-9_]*"), p) is not None)
    disk_cc = list_dir(root, METADATA_DIR, lambda p: p.endswith(".cc"))
    disk_rs = list_dir(root, METADATA_DIR, lambda p: p.endswith(".rs"))

    fixtures = registry.get("fixtures") if isinstance(registry, dict) else None
    fixtures = fixtures if isinstance(fixtures, list) else []

    registry_runners = []
    registry_metadata = []
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        for runner in fixture.get("runner", []) or []:
            registry_runners.append(runner)
        cache = fixture.get("cache") or {}
        if isinstance(cache, dict) and cache.get("metadata"):
            registry_metadata.append(cache["metadata"])

    runner_links = {}
    for runner in disk_runners:
        text = read_text(os.path.join(root, runner))
        runner_links[runner] = sorted(set(RUNNER_METADATA_RE.findall(text)))

    return {
        "disk_metadata": disk_metadata,
        "disk_runners": disk_runners,
        "disk_cc": disk_cc,
        "disk_rs": disk_rs,
        "registry_runners": sorted(set(registry_runners)),
        "registry_metadata": sorted(set(registry_metadata)),
        "runner_links": runner_links,
        "fixtures": fixtures,
    }


def collect_function_id_refs(root: str, discovery: dict):
    """Collect every RG-F/GH12-F reference with a deterministic position.

    Sources, in fixed order: registry impact lists, metadata stable-function-id
    fields, runner hardcoded literals. Positions come from a line scan of the
    raw file so the plan can express file:line:old->new.
    """
    refs = []

    registry_text = read_text(os.path.join(root, REGISTRY_RELPATH))
    registry_fields = {}
    for fixture in discovery["fixtures"]:
        if not isinstance(fixture, dict):
            continue
        impact = fixture.get("impact") or {}
        for field in ("rust_function_ids", "ghidra_function_ids"):
            for fid in impact.get(field, []) or []:
                if isinstance(fid, str):
                    registry_fields.setdefault(fid, set()).add(
                        (fixture.get("id") or "?", f"impact.{field}"))
    for fid in sorted(registry_fields):
        for line, col in find_token_positions(registry_text, fid):
            refs.append({
                "file": REGISTRY_RELPATH,
                "line": line,
                "column": col,
                "id": fid,
                "source": "registry",
                "where": ";".join(
                    f"{fx}/{field}" for fx, field in sorted(registry_fields[fid])),
            })

    for metadata in discovery["disk_metadata"]:
        path = os.path.join(root, metadata)
        try:
            doc = load_json(path)
        except json.JSONDecodeError:
            continue
        text = read_text(path)
        fields = {}
        sid = doc.get("stable_function_id")
        if isinstance(sid, str):
            fields.setdefault(sid, set()).add("stable_function_id")
        closure = doc.get("stable_function_closure")
        hints = {}
        if isinstance(closure, list):
            for entry in closure:
                if not isinstance(entry, str):
                    continue
                parts = entry.split(None, 1)
                if parts and FUNC_ID_RE.fullmatch(parts[0]):
                    fields.setdefault(parts[0], set()).add("stable_function_closure")
                    hints[parts[0]] = parts[1] if len(parts) > 1 else ""
        for fid in sorted(fields):
            for line, col in find_token_positions(text, fid):
                refs.append({
                    "file": metadata,
                    "line": line,
                    "column": col,
                    "id": fid,
                    "source": "metadata",
                    "where": ";".join(sorted(fields[fid])),
                    "hint": hints.get(fid, ""),
                })

    for runner in discovery["disk_runners"]:
        path = os.path.join(root, runner)
        text = read_text(path)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in FUNC_ID_RE.finditer(line):
                refs.append({
                    "file": runner,
                    "line": line_no,
                    "column": match.start() + 1,
                    "id": match.group(0),
                    "source": "runner",
                    "where": "runner_literal",
                    "hint": "",
                })

    refs.sort(key=lambda r: (r["file"], r["line"], r["column"], r["id"]))
    return refs


def classify_function_ids(refs, ledger_ids, old_to_new, tombstones=None):
    """Attach a classification to every reference; also return the family sets."""
    tombstones = tombstones or {}
    classes = {
        "current": [],
        "stale_migratable": [],
        "tombstoned": [],
        "rekey_gap": [],
        "unmappable": [],
    }
    for ref in refs:
        fid = ref["id"]
        if fid in ledger_ids:
            ref["class"] = "current"
            classes["current"].append(ref)
        elif fid in tombstones:
            ref["class"] = "tombstoned"
            ref["tombstone"] = tombstones[fid]
            classes["tombstoned"].append(ref)
        elif fid in old_to_new:
            new_id = old_to_new[fid]
            ref["new_id"] = new_id
            if new_id in ledger_ids:
                ref["class"] = "stale_migratable"
                classes["stale_migratable"].append(ref)
            else:
                ref["class"] = "rekey_gap"
                classes["rekey_gap"].append(ref)
        else:
            ref["class"] = "unmappable"
            classes["unmappable"].append(ref)
    return classes


def rekey_gap_family(migration, ledger_ids, effective_live=None, tombstones=None) -> list:
    """Migration live entries whose final target misses the current ledger.

    Tombstoned lineages are deliberately excluded: they are dead by review
    and already carry the TOMBSTONED_FUNCTION_ID diagnostic; counting them
    here would conflate retirement with a missing replacement target.
    """
    effective_live = effective_live or {}
    tombstones = tombstones or {}
    family = []
    for entry in migration.get("entries", []):
        old_id = entry.get("old_id")
        if old_id in tombstones:
            continue
        new_id = effective_live.get(old_id, entry.get("new_id"))
        if isinstance(new_id, str) and new_id not in ledger_ids:
            family.append({
                "old_id": old_id,
                "table_new_id": new_id,
                "language": entry.get("language"),
                "reason": entry.get("reason"),
            })
    family.sort(key=lambda e: (e["old_id"] or "", e["table_new_id"]))
    return family


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def metadata_status(doc):
    """Return the metadata's valid and invalid declared overall statuses.

    The fourth return value is a sorted ``(location, raw-value)`` list.  This
    distinguishes a missing declaration from a present but invalid token, so a
    typo cannot be silently downgraded to METADATA_STATUS_MISSING.
    """
    locations = (
        ("overall_status", ("overall_status",)),
        ("status", ("status",)),
        ("evidence_status", ("evidence_status",)),
        ("observation.overall_status", ("observation", "overall_status")),
    )
    found = []
    invalid = []
    for label, path in locations:
        value = dig(doc, path)
        if value is None:
            continue
        token = status_token(value)
        if token is not None:
            found.append((token, label))
        else:
            invalid.append((label, value))
    if not found:
        location = invalid[0][0] if invalid else None
        return None, location, [], sorted(invalid, key=lambda item: item[0])
    tokens = {t for t, _ in found}
    return found[0][0], found[0][1], sorted(tokens), sorted(invalid, key=lambda item: item[0])


def metadata_has_input_hash(doc) -> bool:
    for path in INPUT_HASH_PATHS:
        value = dig(doc, path)
        if isinstance(value, str) and value.strip():
            return True
    return False


def metadata_has_expected_pin(doc) -> bool:
    """True when output expectations are common or explicitly paired.

    Legacy fixtures use one common ``expected_stdout_sha256`` for the output
    both sides must produce; this remains valid.  Once side-qualified output
    keys are present, however, at least one Ghidra/Rudra pair is mandatory.
    Paired pins may live at the top level or in a nested object such as
    ``expected_results``.
    """

    def valid_hash(value):
        return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None

    output_kinds = ("stdout", "output", "raw", "observation", "result")
    side_declared = False
    complete_pairs = 0
    all_declared_pairs_valid = True

    expected_results = doc.get("expected_results")
    if isinstance(expected_results, dict):
        for kind in output_kinds:
            ghidra_key = f"ghidra_{kind}_sha256"
            rudra_key = f"rudra_{kind}_sha256"
            ghidra_present = ghidra_key in expected_results
            rudra_present = rudra_key in expected_results
            if ghidra_present or rudra_present:
                side_declared = True
                if (valid_hash(expected_results.get(ghidra_key))
                        and valid_hash(expected_results.get(rudra_key))):
                    complete_pairs += 1
                else:
                    all_declared_pairs_valid = False

    paired_containers = [doc]
    if isinstance(doc.get("comparand"), dict):
        paired_containers.append(doc["comparand"])
    for container in paired_containers:
        for kind in output_kinds:
            ghidra_key = f"expected_ghidra_{kind}_sha256"
            rudra_key = f"expected_rudra_{kind}_sha256"
            ghidra_present = ghidra_key in container
            rudra_present = rudra_key in container
            if ghidra_present or rudra_present:
                side_declared = True
                if valid_hash(container.get(ghidra_key)) and valid_hash(container.get(rudra_key)):
                    complete_pairs += 1
                else:
                    all_declared_pairs_valid = False

    if side_declared:
        return complete_pairs > 0 and all_declared_pairs_valid

    # The legacy common-output contract is top-level and deliberately exact:
    # both executions must equal the same pinned bytes.  New spellings require
    # an explicit tool change so an input/tool/raw-diff hash cannot masquerade
    # as a two-sided output observation.
    for key in COMMON_OUTPUT_PIN_KEYS:
        if valid_hash(doc.get(key)):
            return True
    return False


def residual_evidence(doc) -> list:
    """Collect untested/mismatched residual evidence inside a metadata doc."""
    found = []

    def nonmatch_token(value):
        token = residual_token(value)
        return token if token is not None and token != "MATCH" else None

    prose_keys = {
        "cover", "covers", "description", "detail", "details", "note", "notes",
        "observed", "projection", "reason", "scope", "summary",
    }

    def collect_status_map(path, value):
        if isinstance(value, str):
            tokens = sorted({match.group(1) for match in EMBEDDED_RESIDUAL_RE.finditer(value)})
            for token in tokens:
                found.append(f"{path}={token}")
            return
        if isinstance(value, list):
            for index, entry in enumerate(value):
                collect_status_map(f"{path}[{index}]", entry)
            return
        if not isinstance(value, dict):
            return
        if "status" in value:
            raw_status = value.get("status")
            token = nonmatch_token(raw_status)
            if token is not None:
                found.append(f"{path}={token}")
            elif residual_token(raw_status) is None:
                found.append(f"{path}=INVALID_STATUS")
        for key in sorted(value):
            if key == "status" or key.lower() in prose_keys:
                continue
            collect_status_map(f"{path}.{key}", value[key])

    collect_status_map("coverage", doc.get("coverage"))
    collect_status_map("observation_scope", doc.get("observation_scope"))
    collect_status_map("known_dependencies", doc.get("known_dependencies"))

    def collect_explicit(field, value):
        """Collect a named residual container without treating MATCH as residual."""
        if isinstance(value, str):
            if not value.strip():
                return
            token = residual_token(value)
            if token == "MATCH":
                return
            found.append(f"{field}={token}" if token else field)
            return
        if isinstance(value, list):
            for index, entry in enumerate(value):
                collect_explicit(f"{field}[{index}]", entry)
            return
        if isinstance(value, dict):
            if "status" in value:
                token = residual_token(value.get("status"))
                if token != "MATCH":
                    found.append(f"{field}={token}" if token else f"{field}=INVALID_STATUS")
                for key in sorted(value):
                    if key != "status" and key.lower() not in prose_keys:
                        collect_explicit(f"{field}.{key}", value[key])
                return
            if not value:
                return
            for key in sorted(value):
                collect_explicit(f"{field}.{key}", value[key])

    for field in ("known_residuals", "residuals", "uncovered_boundaries", "residual_union"):
        collect_explicit(field, doc.get(field))
    observation = doc.get("observation")
    if isinstance(observation, dict):
        for field in ("untested", "mismatch"):
            value = observation.get(field)
            if isinstance(value, list) and value:
                found.append(f"observation.{field}[{len(value)}]")
    return sorted(found)


def doctor(root: str) -> dict:
    registry = load_registry(root)
    ledger_ids, old_to_new, tombstones, migration, _continuity = load_function_tables(root)
    discovery = discover(root, registry)
    issues = []

    def add(code, path, line, detail):
        issues.append({
            "code": code,
            "path": path,
            "line": line,
            "detail": detail,
        })

    oracle_commit = registry.get("oracle_commit") if isinstance(registry, dict) else None
    fixtures = discovery["fixtures"]

    # --- duplicate fixture ids (registry) ---------------------------------
    seen_ids = {}
    for fixture in fixtures:
        if isinstance(fixture, dict):
            fid = fixture.get("id")
            if isinstance(fid, str):
                seen_ids.setdefault(fid, []).append(fid)
    for fid in sorted(seen_ids):
        if len(seen_ids[fid]) > 1:
            add("DUPLICATE_FIXTURE_ID", REGISTRY_RELPATH, 0,
                f"fixture id {fid!r} declared {len(seen_ids[fid])} times")

    runner_owners = {}
    metadata_owners = {}
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict):
            continue
        owner = fixture.get("id") if isinstance(fixture.get("id"), str) else f"index:{index}"
        for rel in fixture.get("runner", []) or []:
            if isinstance(rel, str):
                runner_owners.setdefault(rel, []).append(owner)
        cache = fixture.get("cache") or {}
        metadata = cache.get("metadata") if isinstance(cache, dict) else None
        if isinstance(metadata, str):
            metadata_owners.setdefault(metadata, []).append(owner)
    for rel in sorted(runner_owners):
        if len(runner_owners[rel]) > 1:
            add("DUPLICATE_RUNNER_OWNER", REGISTRY_RELPATH, 0,
                f"runner {rel!r} is owned by fixtures {runner_owners[rel]}")
    for rel in sorted(metadata_owners):
        if len(metadata_owners[rel]) > 1:
            add("DUPLICATE_METADATA_OWNER", REGISTRY_RELPATH, 0,
                f"metadata {rel!r} is owned by fixtures {metadata_owners[rel]}")

    # --- per-fixture structure and path existence -------------------------
    required_fixture_fields = ("id", "description", "runner", "timeout_seconds",
                               "always_tiers", "evidence_status", "cache", "impact")
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            add("FIXTURE_MALFORMED", REGISTRY_RELPATH, 0, "non-object fixture entry")
            continue
        fid = fixture.get("id") or "?"
        for field in required_fixture_fields:
            if field not in fixture:
                add("FIXTURE_FIELD_MISSING", REGISTRY_RELPATH, 0, f"{fid}: missing {field}")
        cache = fixture.get("cache") or {}
        if isinstance(cache, dict):
            for group in ("metadata", "inputs", "tools", "comparands"):
                value = cache.get(group)
                paths = []
                if group == "metadata":
                    if isinstance(value, str):
                        paths = [value]
                elif isinstance(value, dict):
                    paths = [v for v in sorted(value.values()) if isinstance(v, str)]
                for rel in paths:
                    if not os.path.exists(os.path.join(root, rel)):
                        add("REGISTRY_PATH_MISSING", REGISTRY_RELPATH, 0,
                            f"{fid}: {group} path {rel!r} does not exist on disk")
        runner = fixture.get("runner")
        if isinstance(runner, list):
            for rel in runner:
                if isinstance(rel, str) and not os.path.isfile(os.path.join(root, rel)):
                    add("REGISTRY_PATH_MISSING", REGISTRY_RELPATH, 0,
                        f"{fid}: runner path {rel!r} does not exist on disk")
        impact = fixture.get("impact") or {}
        if isinstance(impact, dict):
            for field in ("rust_function_ids", "ghidra_function_ids"):
                for fid_ref in impact.get(field, []) or []:
                    if not isinstance(fid_ref, str):
                        continue
                    pattern = RG_ID_RE if field == "rust_function_ids" else GH_ID_RE
                    if not pattern.match(fid_ref):
                        add("FUNCTION_ID_MALFORMED", REGISTRY_RELPATH, 0,
                            f"{fid}: {field} entry {fid_ref!r} is not a canonical scheme-2 id")

    # --- cache_defaults path existence -------------------------------------
    defaults = registry.get("cache_defaults") if isinstance(registry, dict) else None
    if isinstance(defaults, dict):
        for group in ("tools", "comparands"):
            value = defaults.get(group)
            if isinstance(value, dict):
                for key in sorted(value):
                    rel = value[key]
                    if isinstance(rel, str) and not os.path.exists(os.path.join(root, rel)):
                        add("REGISTRY_PATH_MISSING", REGISTRY_RELPATH, 0,
                            f"cache_defaults.{group}.{key} path {rel!r} does not exist")

    # --- orphans ------------------------------------------------------------
    for rel in discovery["disk_runners"]:
        if rel not in set(discovery["registry_runners"]):
            add("ORPHAN_RUNNER", rel, 0, "runner on disk is not referenced by any registry fixture")
    for rel in discovery["disk_metadata"]:
        if rel not in set(discovery["registry_metadata"]):
            add("ORPHAN_METADATA", rel, 0, "metadata on disk is not referenced by any registry fixture")

    # --- runner <-> metadata cross-checks ----------------------------------
    fixture_by_runner = {}
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        for rel in fixture.get("runner", []) or []:
            if isinstance(rel, str):
                fixture_by_runner.setdefault(rel, fixture)
    for runner in discovery["disk_runners"]:
        links = discovery["runner_links"].get(runner, [])
        for link in links:
            if link not in set(discovery["disk_metadata"]):
                add("RUNNER_METADATA_MISSING_ON_DISK", runner, 0,
                    f"embedded metadata path {link!r} does not exist")
        if runner in fixture_by_runner:
            fixture = fixture_by_runner[runner]
            expected = (fixture.get("cache") or {}).get("metadata")
            # Metadata files listed as the fixture's own cache inputs are
            # shared corpus data (e.g. program_flow_metadata_1204), not
            # pairing targets; only foreign fixture metadata makes the link
            # ambiguous.
            input_paths = set((fixture.get("cache") or {}).get("inputs", {}).values())
            pairing_links = [link for link in links if link not in input_paths]
            if not links:
                add("RUNNER_METADATA_UNRESOLVED", runner, 0,
                    f"tracked by fixture {fixture.get('id')!r} but embeds no metadata path")
            elif len(pairing_links) > 1:
                add("RUNNER_METADATA_AMBIGUOUS", runner, 0,
                    f"embeds multiple metadata paths {pairing_links}; expected only {expected!r}")
            elif pairing_links and expected not in pairing_links:
                add("RUNNER_METADATA_MISMATCH", runner, 0,
                    f"embeds {pairing_links} but fixture {fixture.get('id')!r} tracks {expected!r}")

    # --- metadata provenance / status / fixture-id --------------------------
    metadata_docs = {}
    for rel in discovery["disk_metadata"]:
        try:
            metadata_docs[rel] = load_json(os.path.join(root, rel))
        except json.JSONDecodeError as exc:
            add("METADATA_MALFORMED", rel, 0, f"invalid JSON: {exc}")
            metadata_docs[rel] = None

    fixture_id_map = {}
    for rel in sorted(metadata_docs):
        doc = metadata_docs[rel]
        if doc is None:
            continue
        fid = doc.get("fixture_id")
        if not fid:
            add("METADATA_FIXTURE_ID_MISSING", rel, 0, "no fixture_id field")
        elif not isinstance(fid, str) or not FIXTURE_ID_RE.match(fid):
            add("METADATA_FIXTURE_ID_MALFORMED", rel, 0,
                f"fixture_id {fid!r} does not match {FIXTURE_ID_RE.pattern}")
        else:
            fixture_id_map.setdefault(fid, []).append(rel)
    for fid in sorted(fixture_id_map):
        if len(fixture_id_map[fid]) > 1:
            add("DUPLICATE_METADATA_FIXTURE_ID", fixture_id_map[fid][0], 0,
                f"fixture_id {fid!r} declared by {fixture_id_map[fid]}")

    status_by_fixture = {}
    for fixture in fixtures:
        if isinstance(fixture, dict) and isinstance(fixture.get("evidence_status"), str):
            cache = fixture.get("cache") or {}
            if isinstance(cache, dict) and isinstance(cache.get("metadata"), str):
                status_by_fixture[cache["metadata"]] = fixture["evidence_status"]

    for rel in sorted(metadata_docs):
        doc = metadata_docs[rel]
        if doc is None:
            continue
        oracle = doc.get("oracle")
        commit = oracle.get("commit") if isinstance(oracle, dict) else None
        if not commit:
            add("METADATA_ORACLE_COMMIT_MISSING", rel, 0, "no oracle.commit provenance")
        elif not isinstance(commit, str) or not COMMIT_RE.match(commit):
            add("METADATA_ORACLE_COMMIT_MALFORMED", rel, 0, f"oracle.commit {commit!r} is not a 40-hex commit")
        elif isinstance(oracle_commit, str) and commit != oracle_commit:
            add("METADATA_ORACLE_COMMIT_MISMATCH", rel, 0,
                f"oracle.commit {commit} != registry oracle_commit {oracle_commit}")
        for code, field in (
            ("METADATA_ARCH_MISSING", "architecture"),
            ("METADATA_CSPEC_MISSING", "compiler_spec"),
            ("METADATA_OPTIONS_MISSING", "analysis_options"),
        ):
            value = doc.get(field)
            if value is None or value == "" or value == {} or value == []:
                add(code, rel, 0, f"no {field} provenance")
        if not metadata_has_input_hash(doc):
            add("METADATA_INPUT_HASH_MISSING", rel, 0,
                "no input hash pin (input_fingerprint/machine_input_sha256/input_sha256/input_manifest.sha256)")

        token, location, tokens, invalid_statuses = metadata_status(doc)
        if invalid_statuses:
            rendered = ", ".join(f"{label}={value!r}" for label, value in invalid_statuses)
            add("METADATA_STATUS_INVALID", rel, 0,
                "declared status is not a canonical B2/pre-B2 token: " + rendered)
        if token is None and not invalid_statuses:
            add("METADATA_STATUS_MISSING", rel, 0,
                "no overall_status/status/evidence_status/observation.overall_status")
        if token is not None:
            if len(tokens) > 1:
                add("STATUS_INTERNAL_CONFLICT", rel, 0,
                    f"metadata declares conflicting status tokens {tokens} at {location}")
            registry_status = status_by_fixture.get(rel)
            if registry_status is not None:
                registry_token = status_token(registry_status)
                if registry_token is not None and token != registry_token:
                    add("STATUS_CONFLICT", rel, 0,
                        f"metadata {location}={token} contradicts registry evidence_status={registry_token}")
            if token == "MATCH":
                pins = []
                if not metadata_has_expected_pin(doc):
                    pins.append("no paired Ghidra/Rudra output sha256 pins")
                if not metadata_has_input_hash(doc):
                    pins.append("no input hash pin")
                if not isinstance(doc.get("comparand"), dict):
                    pins.append("no comparand block")
                if pins:
                    add("SINGLE_SIDE_MATCH", rel, 0,
                        "MATCH claimed without two-sided pinning: " + "; ".join(pins))
                residuals = residual_evidence(doc)
                if residuals:
                    add("MATCH_WITH_UNMATCHED_RESIDUAL", rel, 0,
                        "MATCH claimed while residuals exist: " + ", ".join(residuals))

    # --- stale function ids --------------------------------------------------
    refs = collect_function_id_refs(root, discovery)
    classes = classify_function_ids(refs, ledger_ids, old_to_new, tombstones)
    for ref in classes["stale_migratable"]:
        add("STALE_FUNCTION_ID", ref["file"], ref["line"],
            f"{ref['id']} is a pre-scheme-2 id; migration maps it to {ref['new_id']}")
    for ref in classes["rekey_gap"]:
        add("REKEY_GAP_FUNCTION_ID", ref["file"], ref["line"],
            f"{ref['id']} maps to {ref['new_id']} which is not in the current ledger "
            f"({REKEY_GAP_TODO})")
    for ref in classes["tombstoned"]:
        tombstone = ref["tombstone"]
        add("TOMBSTONED_FUNCTION_ID", ref["file"], ref["line"],
            f"{ref['id']} names deleted {tombstone['path']}::{tombstone['name']} at "
            f"{tombstone['deleted_at_commit']}; tombstones are diagnostic and cannot "
            "be replaced automatically")
    for ref in classes["unmappable"]:
        hint = f"; closure hint: {ref['hint']}" if ref.get("hint") else ""
        add("UNMAPPABLE_FUNCTION_ID", ref["file"], ref["line"],
            f"{ref['id']} is neither in the current ledger nor in the migration table; "
            f"reselect from the ledger{hint}")

    issues.sort(key=lambda i: (i["code"], i["path"], i["line"], i["detail"]))

    stats = {
        "disk": {
            "metadata": len(discovery["disk_metadata"]),
            "runners": len(discovery["disk_runners"]),
            "cc_fixtures": len(discovery["disk_cc"]),
            "rs_fixtures": len(discovery["disk_rs"]),
        },
        "registry": {
            "fixtures": len(fixtures),
            "runner_refs": len(discovery["registry_runners"]),
            "metadata_refs": len(discovery["registry_metadata"]),
        },
        "orphan_metadata": sum(1 for i in issues if i["code"] == "ORPHAN_METADATA"),
        "orphan_runners": sum(1 for i in issues if i["code"] == "ORPHAN_RUNNER"),
        "function_id_refs": {
            "total": len(refs),
            "current": len(classes["current"]),
            "stale_migratable": len(classes["stale_migratable"]),
            "tombstoned": len(classes["tombstoned"]),
            "rekey_gap": len(classes["rekey_gap"]),
            "unmappable": len(classes["unmappable"]),
        },
        "issues": len(issues),
        "issue_codes": {},
    }
    for issue in issues:
        stats["issue_codes"][issue["code"]] = stats["issue_codes"].get(issue["code"], 0) + 1
    return {"issues": issues, "stats": stats}


# ---------------------------------------------------------------------------
# schema gate
# ---------------------------------------------------------------------------


def schema_check(root: str) -> dict:
    registry = load_registry(root)
    schema_path = os.path.join(root, SCHEMA_RELPATH)
    if not os.path.isfile(schema_path):
        raise HarnessError(f"schema missing: {SCHEMA_RELPATH}")
    try:
        schema_doc = load_json(schema_path)
    except json.JSONDecodeError as exc:
        raise HarnessError(
            f"schema is not valid JSON: {SCHEMA_RELPATH}:{exc.lineno}:{exc.colno}"
        ) from exc
    except OSError as exc:
        raise HarnessError(f"schema is unreadable: {SCHEMA_RELPATH}: {exc.strerror}") from exc
    if not isinstance(schema_doc, dict):
        raise HarnessError("fixture-v1 schema root must be a JSON object")
    deviations = validate_registry_against_schema(registry, schema_doc)
    deviations.sort(key=lambda d: (d[0], d[1], d[2]))
    formatted = []
    for path, rule, message in deviations:
        formatted.append({
            "code": "SCHEMA_DEVIATION",
            "path": REGISTRY_RELPATH,
            "json_pointer": path,
            "rule": rule,
            "detail": message,
        })
    return {"deviations": formatted, "count": len(formatted)}


# ---------------------------------------------------------------------------
# migration completion status
# ---------------------------------------------------------------------------


def migration_status_report(root: str) -> dict:
    """Return deterministic blockers for completing the fixture-v1 migration."""
    registry = load_registry(root)
    discovery = discover(root, registry)
    doctor_report = doctor(root)
    schema_report = schema_check(root)
    plan = build_plan(root)
    blockers = []

    def add(code, path, line, detail, source):
        blockers.append({
            "code": code,
            "path": path,
            "line": line,
            "detail": detail,
            "source": source,
        })

    for issue in doctor_report["issues"]:
        add(issue["code"], issue["path"], issue["line"], issue["detail"], "doctor")

    registry_status_counts = {}
    specific_registry_status_paths = set()
    fixtures = discovery["fixtures"]
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict):
            registry_status_counts["INVALID"] = registry_status_counts.get("INVALID", 0) + 1
            continue
        raw = fixture.get("evidence_status")
        token = status_token(raw)
        bucket = token or ("MISSING" if raw is None else "INVALID")
        registry_status_counts[bucket] = registry_status_counts.get(bucket, 0) + 1
        pointer = f"$.fixtures[{index}].evidence_status"
        if token in PRE_B2_STATUSES:
            specific_registry_status_paths.add(pointer)
            add("REGISTRY_PRE_B2_STATUS", REGISTRY_RELPATH, 0,
                f"{fixture.get('id') or '?'}: evidence_status={token} must migrate to a B2 state",
                "migration")
        elif raw is not None and token not in B2_STATUSES:
            specific_registry_status_paths.add(pointer)
            add("REGISTRY_STATUS_INVALID", REGISTRY_RELPATH, 0,
                f"{fixture.get('id') or '?'}: evidence_status={raw!r} is not a canonical B2 state",
                "migration")

    metadata_status_counts = {}
    for rel in discovery["disk_metadata"]:
        try:
            doc = load_json(os.path.join(root, rel))
        except json.JSONDecodeError:
            metadata_status_counts["INVALID"] = metadata_status_counts.get("INVALID", 0) + 1
            continue
        token, location, tokens, invalid = metadata_status(doc)
        bucket = token or ("INVALID" if invalid else "MISSING")
        metadata_status_counts[bucket] = metadata_status_counts.get(bucket, 0) + 1
        pre_tokens = sorted(set(tokens).intersection(PRE_B2_STATUSES))
        if pre_tokens:
            add("METADATA_PRE_B2_STATUS", rel, 0,
                f"{location or 'status'} declares pre-B2 state(s) {pre_tokens}", "migration")

    for deviation in schema_report["deviations"]:
        # A PRE_B2/invalid evidence status has a more actionable blocker above.
        if (deviation["rule"] == "enum"
                and deviation["json_pointer"] in specific_registry_status_paths):
            continue
        add("REGISTRY_SCHEMA_DEVIATION", deviation["path"], 0,
            f"{deviation['json_pointer']} ({deviation['rule']}): {deviation['detail']}",
            "schema")

    plan_counts = {
        "auto_replacements": plan["summary"]["auto_replacements"],
        "manual_reselect": plan["summary"]["manual_reselect"],
        "tombstoned": plan["summary"]["tombstoned"],
        "unmappable": plan["summary"]["unmappable"],
        "rekey_gap_family_size": plan["summary"]["rekey_gap_family_size"],
    }
    plan_blocker_codes = {
        "auto_replacements": "PLAN_AUTO_REPLACEMENTS_PENDING",
        "manual_reselect": "PLAN_MANUAL_RESELECT_PENDING",
        "tombstoned": "PLAN_TOMBSTONED_PENDING",
        "unmappable": "PLAN_UNMAPPABLE_PENDING",
        "rekey_gap_family_size": "PLAN_REKEY_GAP_FAMILY_PENDING",
    }
    for field in sorted(plan_counts):
        count = plan_counts[field]
        if count:
            add(plan_blocker_codes[field], MIGRATION_RELPATH, 0,
                f"migration plan {field}={count}", "plan")

    blockers.sort(key=lambda item: (
        item["code"], item["path"], item["line"], item["detail"], item["source"]
    ))
    blocker_codes = {}
    for blocker in blockers:
        code = blocker["code"]
        blocker_codes[code] = blocker_codes.get(code, 0) + 1
    return {
        "blockers": blockers,
        "stats": {
            "blockers": len(blockers),
            "blocker_codes": dict(sorted(blocker_codes.items())),
            "registry_statuses": dict(sorted(registry_status_counts.items())),
            "metadata_statuses": dict(sorted(metadata_status_counts.items())),
            "doctor_issues": len(doctor_report["issues"]),
            "schema_deviations": schema_report["count"],
            "plan": plan_counts,
        },
    }


def migration_status_exit_code(report: dict) -> int:
    return EXIT_OK if not report["blockers"] else EXIT_FINDINGS


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------


def build_plan(root: str) -> dict:
    registry = load_registry(root)
    ledger_ids, old_to_new, tombstones, migration, continuity = load_function_tables(root)
    discovery = discover(root, registry)
    refs = collect_function_id_refs(root, discovery)
    classes = classify_function_ids(refs, ledger_ids, old_to_new, tombstones)

    replacements = []
    for ref in classes["stale_migratable"]:
        replacements.append({
            "file": ref["file"],
            "line": ref["line"],
            "column": ref["column"],
            "old_id": ref["id"],
            "new_id": ref["new_id"],
            "where": ref["where"],
        })
    replacements.sort(key=lambda r: (r["file"], r["line"], r["column"], r["old_id"]))

    manual = []
    for ref in classes["rekey_gap"]:
        manual.append({
            "file": ref["file"],
            "line": ref["line"],
            "column": ref["column"],
            "old_id": ref["id"],
            "table_new_id": ref["new_id"],
            "where": ref["where"],
            "reason": f"migration-table new_id is not in the current ledger; reselect per "
                      f"the regenerated ledger ({REKEY_GAP_TODO})",
        })
    manual.sort(key=lambda r: (r["file"], r["line"], r["column"], r["old_id"]))

    unmappable = []
    for ref in classes["unmappable"]:
        entry = {
            "file": ref["file"],
            "line": ref["line"],
            "column": ref["column"],
            "old_id": ref["id"],
            "where": ref["where"],
            "reason": "id is neither in the current ledger nor in the migration table; "
                      "derive the correct id from the ledger before replacing",
        }
        if ref.get("hint"):
            entry["closure_hint"] = ref["hint"]
        unmappable.append(entry)
    unmappable.sort(key=lambda r: (r["file"], r["line"], r["column"], r["old_id"]))

    tombstoned = []
    for ref in classes["tombstoned"]:
        row = ref["tombstone"]
        tombstoned.append({
            "file": ref["file"],
            "line": ref["line"],
            "column": ref["column"],
            "old_id": ref["id"],
            "where": ref["where"],
            "deleted_path": row["path"],
            "deleted_name": row["name"],
            "deleted_at_commit": row["deleted_at_commit"],
            "reason": "function lineage is tombstoned; select a reviewed semantic successor "
                      "or remove the stale evidence reference",
        })
    tombstoned.sort(key=lambda r: (r["file"], r["line"], r["column"], r["old_id"]))

    family = rekey_gap_family(migration, ledger_ids, old_to_new, tombstones)
    referenced = {ref["id"] for ref in classes["rekey_gap"]}
    family_out = []
    for entry in family:
        family_out.append({
            "old_id": entry["old_id"],
            "table_new_id": entry["table_new_id"],
            "language": entry["language"],
            "referenced_by_registry_or_metadata": entry["old_id"] in referenced,
        })

    edited_runners = sorted({r["file"] for r in replacements + manual + unmappable
                             if r["file"].startswith("tools/")})
    collateral = []
    for metadata in discovery["disk_metadata"]:
        try:
            doc = load_json(os.path.join(root, metadata))
        except json.JSONDecodeError:
            continue
        comparand = doc.get("comparand")
        if not isinstance(comparand, dict) or "runner_sha256" not in comparand:
            continue
        # The metadata pins its runner's sha256; if that runner's bytes change,
        # the pin must be re-pinned in the same commit.
        if any_edited_runner_for(root, metadata, edited_runners):
            collateral.append({
                "metadata_file": metadata,
                "field": "comparand.runner_sha256",
                "pinned_file": pinned_runner_for(root, metadata),
                "reason": "runner bytes change, so the pinned sha256 must be re-pinned in the same commit",
            })
    collateral.sort(key=lambda c: (c["metadata_file"], c["field"], c["pinned_file"] or ""))

    registry_sha = sha256_file(os.path.join(root, REGISTRY_RELPATH))
    ledger_sha = sha256_file(os.path.join(root, LEDGER_RELPATH))
    migration_sha = sha256_file(os.path.join(root, MIGRATION_RELPATH))
    continuity_path = os.path.join(root, CONTINUITY_RELPATH)
    continuity_input = (
        {"path": CONTINUITY_RELPATH, "sha256": sha256_file(continuity_path)}
        if continuity is not None else None
    )
    return {
        "plan_version": 1,
        "todo": "ORACLE-REGISTRY-0001",
        "deterministic": True,
        "inputs": {
            "registry": {"path": REGISTRY_RELPATH, "sha256": registry_sha},
            "ledger": {"path": LEDGER_RELPATH, "sha256": ledger_sha},
            "migration": {"path": MIGRATION_RELPATH, "sha256": migration_sha},
            "continuity": continuity_input,
            "migration_old_ledger_tree_commit": (migration or {}).get("old_ledger", {}).get("tree_commit"),
        },
        "summary": {
            "auto_replacements": len(replacements),
            "manual_reselect": len(manual),
            "unmappable": len(unmappable),
            "tombstoned": len(tombstoned),
            "rekey_gap_family_size": len(family_out),
            "collateral_pins": len(collateral),
        },
        "replacements": replacements,
        "manual_reselect": manual,
        "unmappable": unmappable,
        "tombstoned": tombstoned,
        "rekey_gap_family": family_out,
        "collateral_pins": collateral,
        "apply_notes": [
            "Apply replacements exactly at file:line:column with the given old->new token.",
            "manual_reselect, tombstoned, and unmappable entries must NOT be text-replaced; "
            "pick a reviewed live id from the current ledger or remove the stale reference.",
            "Editing a runner invalidates the metadata comparand.runner_sha256 pin and the runner's own immutable-fd snapshot hash; re-pin in the same commit.",
            "Editing metadata invalidates any hash pinning that metadata elsewhere (registry cache inputs are content-addressed at run time).",
            "fixture_registry.json is listed in its own global_paths cache closure; bump cache-aware consumers after the edit.",
            "After applying, re-run: python3 tools/oracle_registry.py doctor (expect zero STALE/UNMAPPABLE/REKEY_GAP issues) and the fixture runners.",
        ],
    }


def runner_id_of(metadata_rel: str) -> str:
    base = os.path.basename(metadata_rel)
    stem = base[:-len(".metadata.json")]
    if stem.endswith("_1204"):
        stem = stem[: -len("_1204")]
    return stem


def any_edited_runner_for(root: str, metadata_rel: str, edited_runners) -> bool:
    pinned = pinned_runner_for(root, metadata_rel)
    return pinned in edited_runners if pinned else False


def pinned_runner_for(root: str, metadata_rel: str):
    """Best-effort resolution of the runner a metadata file pins."""
    stem = runner_id_of(metadata_rel)
    candidate = f"tools/run_{stem}_oracle.sh"
    if os.path.isfile(os.path.join(root, candidate)):
        return candidate
    text_path = os.path.join(root, metadata_rel)
    try:
        text = read_text(text_path)
    except OSError:
        return None
    for match in re.finditer(r"tools/run_[a-z0-9_]+_oracle\.sh", text):
        return match.group(0)
    return None


def render_plan_text(plan: dict) -> str:
    lines = []
    lines.append("# ORACLE-REGISTRY-0001 deterministic function-id migration plan")
    inputs = plan["inputs"]
    lines.append(f"registry: {inputs['registry']['path']} sha256={inputs['registry']['sha256']}")
    lines.append(f"ledger: {inputs['ledger']['path']} sha256={inputs['ledger']['sha256']}")
    lines.append(f"migration: {inputs['migration']['path']} sha256={inputs['migration']['sha256']}")
    continuity = inputs.get("continuity")
    if continuity:
        lines.append(
            f"continuity: {continuity['path']} sha256={continuity['sha256']}"
        )
    tree = inputs.get("migration_old_ledger_tree_commit")
    if tree:
        lines.append(f"migration old-ledger tree commit: {tree}")
    summary = plan["summary"]
    lines.append(f"summary: auto={summary['auto_replacements']} "
                 f"manual={summary['manual_reselect']} "
                 f"tombstoned={summary['tombstoned']} "
                 f"unmappable={summary['unmappable']} "
                 f"rekey_gap_family={summary['rekey_gap_family_size']} "
                 f"collateral_pins={summary['collateral_pins']}")
    lines.append("")
    lines.append(f"## replacements ({summary['auto_replacements']})")
    for rep in plan["replacements"]:
        lines.append(f"{rep['file']}:{rep['line']}:{rep['column']}: {rep['old_id']} -> {rep['new_id']}"
                     f"  [{rep['where']}]")
    lines.append("")
    lines.append(f"## manual_reselect ({summary['manual_reselect']}) -- do NOT text-replace")
    for entry in plan["manual_reselect"]:
        lines.append(f"{entry['file']}:{entry['line']}:{entry['column']}: {entry['old_id']} "
                     f"X-> {entry['table_new_id']} (table new_id not in ledger; {REKEY_GAP_TODO})"
                     f"  [{entry['where']}]")
    lines.append("")
    lines.append(f"## tombstoned ({summary['tombstoned']}) -- do NOT text-replace")
    for entry in plan["tombstoned"]:
        lines.append(
            f"{entry['file']}:{entry['line']}:{entry['column']}: {entry['old_id']} "
            f"deleted {entry['deleted_path']}::{entry['deleted_name']} at "
            f"{entry['deleted_at_commit']}  [{entry['where']}]"
        )
    lines.append("")
    lines.append(f"## unmappable ({summary['unmappable']}) -- derive id from ledger first")
    for entry in plan["unmappable"]:
        hint = f"  closure: {entry['closure_hint']}" if entry.get("closure_hint") else ""
        lines.append(f"{entry['file']}:{entry['line']}:{entry['column']}: {entry['old_id']} -> ?"
                     f"  [{entry['where']}]{hint}")
    lines.append("")
    lines.append(f"## rekey_gap_family ({summary['rekey_gap_family_size']}) -- {REKEY_GAP_TODO}")
    for entry in plan["rekey_gap_family"]:
        flag = "referenced" if entry["referenced_by_registry_or_metadata"] else "unreferenced"
        lines.append(f"{entry['old_id']} X-> {entry['table_new_id']} ({entry['language']}, {flag})")
    lines.append("")
    lines.append(f"## collateral_pins ({summary['collateral_pins']})")
    for entry in plan["collateral_pins"]:
        lines.append(f"{entry['metadata_file']}: {entry['field']} pins {entry['pinned_file']}")
    lines.append("")
    lines.append("## apply_notes")
    for note in plan["apply_notes"]:
        lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_doctor_text(report: dict) -> str:
    stats = report["stats"]
    lines = []
    lines.append(f"# oracle registry doctor: {stats['issues']} issue(s)")
    lines.append(f"disk: metadata={stats['disk']['metadata']} runners={stats['disk']['runners']} "
                 f"cc={stats['disk']['cc_fixtures']} rs={stats['disk']['rs_fixtures']} | "
                 f"registry: fixtures={stats['registry']['fixtures']} "
                 f"runner_refs={stats['registry']['runner_refs']} "
                 f"metadata_refs={stats['registry']['metadata_refs']}")
    refs = stats["function_id_refs"]
    lines.append(f"function-id refs: total={refs['total']} current={refs['current']} "
                 f"stale_migratable={refs['stale_migratable']} tombstoned={refs['tombstoned']} "
                 f"rekey_gap={refs['rekey_gap']} "
                 f"unmappable={refs['unmappable']}")
    lines.append("issue codes: " + (", ".join(
        f"{code}={count}" for code, count in sorted(stats["issue_codes"].items())) or "none"))
    lines.append("")
    for issue in report["issues"]:
        location = issue["path"] if not issue["line"] else f"{issue['path']}:{issue['line']}"
        lines.append(f"[{issue['code']}] {location}: {issue['detail']}")
    return "\n".join(lines) + "\n"


def render_schema_text(report: dict) -> str:
    lines = [f"# registry schema gate (fixture-v1): {report['count']} deviation(s)"]
    for dev in report["deviations"]:
        lines.append(f"[{dev['code']}] {dev['json_pointer']} ({dev['rule']}): {dev['detail']}")
    return "\n".join(lines) + "\n"


def render_migration_status_text(report: dict) -> str:
    stats = report["stats"]
    lines = [f"# oracle metadata migration status: {stats['blockers']} blocker(s)"]
    lines.append("registry statuses: " + (", ".join(
        f"{status}={count}" for status, count in stats["registry_statuses"].items()) or "none"))
    lines.append("metadata statuses: " + (", ".join(
        f"{status}={count}" for status, count in stats["metadata_statuses"].items()) or "none"))
    lines.append("blocker codes: " + (", ".join(
        f"{code}={count}" for code, count in stats["blocker_codes"].items()) or "none"))
    lines.append(f"inputs: doctor_issues={stats['doctor_issues']} "
                 f"schema_deviations={stats['schema_deviations']}")
    lines.append("plan: " + ", ".join(
        f"{field}={count}" for field, count in sorted(stats["plan"].items())))
    lines.append("")
    for blocker in report["blockers"]:
        location = blocker["path"] if not blocker["line"] else f"{blocker['path']}:{blocker['line']}"
        lines.append(f"[{blocker['code']}] {location}: {blocker['detail']}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------


GH_NEW = "GH12-F-" + "a1" * 10
RG_NEW = "RG-F-" + "b2" * 10
RG_OLD = "RG-F-" + "c3" * 10
RG_GAP_OLD = "RG-F-" + "d4" * 10
RG_GAP_NEW = "RG-F-" + "e5" * 10
RG_GHOST = "RG-F-" + "f6" * 10
RG_ALIAS = "RG-F-" + "a7" * 10
RG_DELETED_OLD = "RG-F-" + "b8" * 10
RG_DELETED_ALIAS = "RG-F-" + "c9" * 10


def synthetic_ledger() -> dict:
    return {
        "schema": 1,
        "oracle": {"commit": "0" * 40},
        "ghidra_functions": [{"id": GH_NEW, "qualified_name": "ghidra::Demo::fn", "path": "ghidra/x.cc"}],
        "rugra_functions": [{"id": RG_NEW, "module": "demo", "name": "fn", "path": "src/demo.rs"}],
    }


def synthetic_migration() -> dict:
    return {
        "schema": 1,
        "entries": [
            {"language": "rust", "old_id": RG_OLD, "new_id": RG_NEW, "reason": "rust_identity_rekey"},
        ],
        "disambiguators": [],
        "tombstones": [],
        "old_ledger": {"tree_commit": "1" * 40},
    }


def synthetic_registry(commit: str, fixtures: list) -> dict:
    return {
        "schema": "fixture-v1",
        "oracle_commit": commit,
        "global_paths": ["Cargo.toml", "tests/oracle/fixture_registry.json"],
        "cache_defaults": {
            "tools": {"fixture_registry": "tests/oracle/fixture_registry.json"},
            "comparands": {"rugra_src": "src"},
            "environment": ["CC"],
        },
        "fixtures": fixtures,
    }


def base_fixture(fixture_id: str, metadata_rel: str, runner_rel: str, extra_impact=None) -> dict:
    impact = {
        "paths": [metadata_rel, runner_rel],
        "rust_function_ids": [RG_NEW],
        "ghidra_function_ids": [GH_NEW],
    }
    if extra_impact:
        impact.update(extra_impact)
    return {
        "id": fixture_id,
        "description": "synthetic fixture",
        "runner": [runner_rel],
        "timeout_seconds": 60,
        "always_tiers": ["wave"],
        "evidence_status": "MATCH",
        "cache": {
            "metadata": metadata_rel,
            "inputs": {"cpp_fixture": "tests/oracle/demo_a.cc", "rust_fixture": "tests/oracle/demo_a.rs"},
            "tools": {"runner": runner_rel},
        },
        "impact": impact,
    }


def base_metadata(fixture_id: str, commit: str) -> dict:
    return {
        "schema": 2,
        "fixture_id": fixture_id,
        "stable_function_id": GH_NEW,
        "stable_function_closure": [f"{GH_NEW} ghidra::Demo::fn x.cc:10"],
        "oracle": {"tag": "T", "commit": commit},
        "architecture": "x86:LE:64:default",
        "compiler_spec": "gcc",
        "analysis_options": {"action": "none"},
        "input_manifest": {"sha256": "0" * 64},
        "comparand": {
            "cpp_fixture_sha256": "1" * 64,
            "rust_fixture_sha256": "2" * 64,
            "runner_sha256": "3" * 64,
        },
        "expected_results": {
            "ghidra_stdout_sha256": "4" * 64,
            "rudra_stdout_sha256": "4" * 64,
        },
        "overall_status": "MATCH (synthetic complete projection)",
        "coverage": {"case_one": "MATCH"},
    }


def write_synth_base(root: str, commit: str) -> None:
    os.makedirs(os.path.join(root, "tests/oracle/schema"), exist_ok=True)
    os.makedirs(os.path.join(root, "tools"), exist_ok=True)
    os.makedirs(os.path.join(root, "docs/alignment_audit"), exist_ok=True)
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    real_root = repo_root()
    with open(os.path.join(real_root, SCHEMA_RELPATH), "rb") as src:
        schema_bytes = src.read()
    with open(os.path.join(root, SCHEMA_RELPATH), "wb") as dst:
        dst.write(schema_bytes)
    with open(os.path.join(root, LEDGER_RELPATH), "w", encoding="utf-8") as handle:
        json.dump(synthetic_ledger(), handle)
    with open(os.path.join(root, MIGRATION_RELPATH), "w", encoding="utf-8") as handle:
        json.dump(synthetic_migration(), handle)
    for name in ("demo_a.cc", "demo_a.rs"):
        with open(os.path.join(root, "tests/oracle", name), "w", encoding="utf-8") as handle:
            handle.write("// synthetic\n")
    metadata_rel = "tests/oracle/demo_a_1204.metadata.json"
    runner_rel = "tools/run_demo_a_oracle.sh"
    with open(os.path.join(root, metadata_rel), "w", encoding="utf-8") as handle:
        json.dump(base_metadata("DEMO-A-0001", commit), handle, indent=1)
    with open(os.path.join(root, runner_rel), "w", encoding="utf-8") as handle:
        handle.write("#!/usr/bin/env bash\n")
        handle.write(f'metadata="$repo_root/{metadata_rel}"\n')
        handle.write(f'pin = "{GH_NEW}"\n')
    registry = synthetic_registry(commit, [base_fixture("demo_a_1204", metadata_rel, runner_rel)])
    with open(os.path.join(root, REGISTRY_RELPATH), "w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=1)


def rewrite_json(path: str, mutate) -> None:
    doc = load_json(path)
    mutate(doc)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=1)


def self_test() -> int:
    commit = "2" * 40
    failures = []

    def expect(label, condition, detail=""):
        if condition:
            print(f"  PASS {label}")
        else:
            failures.append(label)
            print(f"  FAIL {label} {detail}")

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write_synth_base(root, commit)

        # 1. healthy baseline
        report = doctor(root)
        expect("healthy baseline is clean", not report["issues"],
               detail=json.dumps(report["issues"][:3]))
        schema_report = schema_check(root)
        expect("healthy baseline passes fixture-v1 schema", schema_report["count"] == 0,
               detail=json.dumps(schema_report["deviations"][:3]))
        migration_report = migration_status_report(root)
        expect("clean migration status has no blockers",
               migration_status_exit_code(migration_report) == EXIT_OK,
               detail=json.dumps(migration_report["blockers"][:3]))

        def codes(report):
            return {issue["code"] for issue in report["issues"]}

        # Continuity reviewed evidence is not a free-form escape hatch.  This
        # reproduces the malicious half-in/half-out swap: an event carrying a
        # reviewed label must still match the exact code allowlist key/pins.
        malicious_event = {
            "from_id": "RG-F-" + "01" * 10,
            "to_id": "RG-F-" + "02" * 10,
            "commit": "3" * 40,
            "from_path": "src/block.rs",
            "to_path": "src/block.rs",
            "parent_blob": "4" * 40,
            "child_blob": "5" * 40,
        }
        malicious_rejected = False
        try:
            _validate_reviewed_continuity_event(
                malicious_event["from_id"], malicious_event,
                ["reviewed_successor_allowlist", "forged half-edge swap"], {}, set(),
            )
        except HarnessError:
            malicious_rejected = True
        expect("forged reviewed continuity event rejected", malicious_rejected)

        exact_key = (
            malicious_event["from_id"], malicious_event["from_id"],
            malicious_event["to_id"], malicious_event["commit"],
        )
        exact_rule = {
            "base_id": malicious_event["from_id"],
            **malicious_event,
            "review": "independent review receipt",
        }
        used = set()
        _validate_reviewed_continuity_event(
            malicious_event["from_id"], malicious_event,
            ["reviewed_successor_allowlist", "independent review receipt"],
            {exact_key: exact_rule}, used,
        )
        expect("exact reviewed continuity event accepted", used == {exact_key})

        chain_a = "RG-F-" + "06" * 10
        chain_b = "RG-F-" + "07" * 10
        chain_event = {"from_id": chain_a, "to_id": chain_b}
        expect("tombstone alias chain has exact event-plus-terminal shape",
               _validate_continuity_tombstone_alias_chain(
                   chain_a, [chain_a, chain_b], [chain_event]
               ) == chain_b)
        for aliases in (
            [chain_a],
            [chain_a, chain_b, "RG-F-" + "08" * 10],
            [chain_a, chain_b, chain_b],
        ):
            rejected = False
            try:
                _validate_continuity_tombstone_alias_chain(
                    chain_a, aliases, [chain_event]
                )
            except HarnessError:
                rejected = True
            expect(f"malformed tombstone alias chain rejected ({len(aliases)})", rejected)

        expect("status parser accepts only colon/parenthesis suffixes",
               status_token("MISMATCH: detail") == "MISMATCH"
               and status_token("UNTESTED：detail") == "UNTESTED"
               and status_token("NO_ORACLE (detail)") == "NO_ORACLE"
               and status_token("PARTIAL_MATCH（detail）") == "PARTIAL_MATCH"
               and status_token("MATCH(foo") is None
               and status_token("MATCH(foo)garbage") is None
               and status_token("MATCH()") is None
               and status_token("MATCH:") is None
               and status_token("MATCH explanation") is None
               and status_token("MATCHED") is None
               and status_token("match") is None
               and status_token("MATCH/MISMATCH") is None)

        expect("common and nested paired output pins accepted",
               metadata_has_expected_pin({"expected_stdout_sha256": "1" * 64})
               and metadata_has_expected_pin({
                   "expected_statement_stdout_sha256": "1" * 64,
               })
               and metadata_has_expected_pin({
                   "expected_observation_sha256": "1" * 64,
               })
               and metadata_has_expected_pin({"expected_results": {
                   "ghidra_stdout_sha256": "2" * 64,
                   "rudra_stdout_sha256": "2" * 64,
               }})
               and metadata_has_expected_pin({"comparand": {
                   "expected_ghidra_stdout_sha256": "2" * 64,
                   "expected_rudra_stdout_sha256": "2" * 64,
               }})
               and not metadata_has_expected_pin({"expected_stdout_sha256": "short"})
               and not metadata_has_expected_pin({
                   "expected_raw_diff_sha256": "3" * 64,
               })
               and not metadata_has_expected_pin({
                   "expected_not_actually_output_sha256": "3" * 64,
               })
               and not metadata_has_expected_pin({"expected_results": {
                   "ghidra_stdout_sha256": "2" * 64,
               }})
               and not metadata_has_expected_pin({"expected_results": {
                   "ghidra_stdout_sha256": "2" * 64,
                   "rudra_stdout_sha256": "2" * 64,
                   "ghidra_raw_sha256": "3" * 64,
               }})
               and not metadata_has_expected_pin({
                   "expected_results": {
                       "ghidra_stdout_sha256": "2" * 64,
                       "rudra_stdout_sha256": "2" * 64,
                   },
                   "expected_ghidra_raw_sha256": "short",
                   "expected_rudra_raw_sha256": "3" * 64,
               }))

        residual_probe = {
            "coverage": {
                "covered": {"status": "MATCH (complete)"},
                "gap": {"status": "UNTESTED (branch)"},
                "direct_progress": "PROGRESS_ONLY",
                "group": {
                    "status": "MATCH (parent projection)",
                    "notes": "UNTESTED: prose is not a status declaration",
                    "projection": "MISMATCH: prose is not a status declaration",
                    "cases": [
                        {"status": "MATCH"},
                        {"status": "UNTESTED: nested child"},
                    ],
                },
            },
            "observation_scope": {"missing": "MISSING (production path)"},
            "known_dependencies": {
                "dep": {"status": "MISMATCH: state"},
                "unknown": {"status": "OUT_OF_SCOPE"},
                "progress": {"status": "PROGRESS_ONLY"},
                "note": "plain dependency prose",
            },
            "residual_union": [
                {
                    "status": "MATCH",
                    "detail": "closed parent",
                    "children": [{"status": "UNTESTED: nested child"}],
                },
                {"status": "NO_ORACLE (undefined oracle path)", "detail": "open"},
            ],
        }
        residual_probe_result = residual_evidence(residual_probe)
        expect("nested residual containers keep only open evidence",
               "coverage.gap=UNTESTED" in residual_probe_result
               and "observation_scope.missing=MISSING" in residual_probe_result
               and "known_dependencies.dep=MISMATCH" in residual_probe_result
               and "known_dependencies.unknown=INVALID_STATUS" in residual_probe_result
               and "known_dependencies.progress=INVALID_STATUS" in residual_probe_result
               and "coverage.direct_progress=PROGRESS_ONLY" in residual_probe_result
               and "coverage.group.cases[1]=UNTESTED" in residual_probe_result
               and "residual_union[0].children[0]=UNTESTED" in residual_probe_result
               and "residual_union[1]=NO_ORACLE" in residual_probe_result
               and all("covered" not in item and item != "residual_union[0]=MATCH"
                       and "known_dependencies.note" not in item
                       and ".notes" not in item and ".projection" not in item
                       for item in residual_probe_result),
               detail=json.dumps(residual_probe_result))
        mixed_scope = residual_evidence({
            "observation_scope": "MATCH only for scalar output; codec error is UNTESTED",
        })
        plain_scope = residual_evidence({
            "observation_scope": "scalar output and codec behavior are described here",
        })
        expect("mixed observation-scope prose exposes bounded residual tokens",
               mixed_scope == ["observation_scope=UNTESTED"] and not plain_scope,
               detail=json.dumps({"mixed": mixed_scope, "plain": plain_scope}))

        # 2. one-sided fake MATCH (only the Ghidra output is pinned)
        def mutate(doc):
            del doc["expected_results"]["rudra_stdout_sha256"]
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"), mutate)
        report = doctor(root)
        expect("one-sided fake MATCH rejected", "SINGLE_SIDE_MATCH" in codes(report),
               detail=json.dumps(report["issues"][:3]))
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc["expected_results"].update(
                         {"rudra_stdout_sha256": "4" * 64}))

        # 2b. nested coverage status with a parenthesized explanation
        def mutate_residuals(doc):
            doc["coverage"]["case_two"] = {
                "status": "UNTESTED (branch not exercised)",
                "detail": "synthetic residual",
            }
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"), mutate_residuals)
        report = doctor(root)
        expect("MATCH with nested residual rejected",
               "MATCH_WITH_UNMATCHED_RESIDUAL" in codes(report))
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc["coverage"].pop("case_two"))

        # 3. orphan metadata
        with open(os.path.join(root, "tests/oracle/lonely_1204.metadata.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(base_metadata("LONELY-0001", commit), handle, indent=1)
        report = doctor(root)
        expect("orphan metadata rejected", "ORPHAN_METADATA" in codes(report))
        os.remove(os.path.join(root, "tests/oracle/lonely_1204.metadata.json"))

        # 4. orphan runner
        with open(os.path.join(root, "tools/run_lonely_oracle.sh"), "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\n")
        report = doctor(root)
        expect("orphan runner rejected", "ORPHAN_RUNNER" in codes(report))
        os.remove(os.path.join(root, "tools/run_lonely_oracle.sh"))

        # 5. duplicate registry fixture id
        extra = base_fixture("demo_a_1204", "tests/oracle/demo_a_1204.metadata.json",
                             "tools/run_demo_a_oracle.sh")
        rewrite_json(os.path.join(root, REGISTRY_RELPATH), lambda doc: doc["fixtures"].append(extra))
        report = doctor(root)
        expect("duplicate fixture id rejected", "DUPLICATE_FIXTURE_ID" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH), lambda doc: doc["fixtures"].pop())

        # 5b. distinct fixture ids may not share one runner or metadata owner
        shared = base_fixture("demo_b_1204", "tests/oracle/demo_a_1204.metadata.json",
                              "tools/run_demo_a_oracle.sh")
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"].append(shared))
        report = doctor(root)
        expect("duplicate runner and metadata ownership rejected",
               {"DUPLICATE_RUNNER_OWNER", "DUPLICATE_METADATA_OWNER"} <= codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH), lambda doc: doc["fixtures"].pop())

        # 6. duplicate metadata fixture_id
        with open(os.path.join(root, "tests/oracle/twin_1204.metadata.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(base_metadata("DEMO-A-0001", commit), handle, indent=1)
        report = doctor(root)
        expect("duplicate metadata fixture id rejected", "DUPLICATE_METADATA_FIXTURE_ID" in codes(report))
        # twin stays for the orphan test below; remove to isolate
        os.remove(os.path.join(root, "tests/oracle/twin_1204.metadata.json"))

        # 7. status conflict registry vs metadata
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0].update({"evidence_status": "MISMATCH"}))
        report = doctor(root)
        expect("status conflict rejected", "STATUS_CONFLICT" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0].update({"evidence_status": "MATCH"}))

        # 7b. a declared but invalid status is not reported as merely missing
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc.update({"overall_status": "MATCHED"}))
        report = doctor(root)
        found = codes(report)
        expect("invalid metadata status rejected explicitly",
               "METADATA_STATUS_INVALID" in found and "METADATA_STATUS_MISSING" not in found)
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc.update(
                         {"overall_status": "MATCH (synthetic complete projection)"}))

        # 8. missing provenance
        def strip(doc):
            del doc["oracle"]["commit"]
            del doc["architecture"]
            del doc["compiler_spec"]
            del doc["analysis_options"]
            del doc["input_manifest"]
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"), strip)
        report = doctor(root)
        found = codes(report)
        expected = {"METADATA_ORACLE_COMMIT_MISSING", "METADATA_ARCH_MISSING",
                    "METADATA_CSPEC_MISSING", "METADATA_OPTIONS_MISSING",
                    "METADATA_INPUT_HASH_MISSING"}
        expect("missing provenance rejected", expected <= found,
               detail=f"missing={sorted(expected - found)}")
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc.update(base_metadata("DEMO-A-0001", commit)))

        # 9. registry path missing on disk
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["runner"].append("tools/run_ghost_oracle.sh"))
        report = doctor(root)
        expect("registry path missing on disk rejected", "REGISTRY_PATH_MISSING" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["runner"].pop())

        # 10. stale (migratable) function id in registry
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_OLD]}))
        report = doctor(root)
        expect("stale migratable id rejected", "STALE_FUNCTION_ID" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))

        # 10b. a stale base/intermediate alias resolves directly to the final
        # live ID; it never enters the rekey-gap family.
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["entries"][0].update({"aliases": [RG_ALIAS]}))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_ALIAS]}))
        report = doctor(root)
        plan = build_plan(root)
        expect("intermediate alias resolves to final live id",
               "STALE_FUNCTION_ID" in codes(report)
               and plan["summary"]["auto_replacements"] == 1
               and plan["replacements"][0]["new_id"] == RG_NEW
               and plan["summary"]["rekey_gap_family_size"] == 0)
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["entries"][0].pop("aliases"))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))

        # 10c. tombstones are diagnostics, never replacement candidates.
        tombstone = {
            "old_id": RG_DELETED_OLD,
            "aliases": [RG_DELETED_ALIAS],
            "path": "src/deleted.rs",
            "module": "deleted",
            "owner": "free",
            "name": "gone",
            "signature": "fn gone()",
            "deleted_at_commit": "6" * 40,
            "parent_blob": "7" * 40,
            "child_blob": "8" * 40,
            "reason": "deleted_without_reviewed_successor",
        }
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["tombstones"].append(tombstone))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update(
                         {"rust_function_ids": [RG_DELETED_ALIAS]}))
        report = doctor(root)
        plan = build_plan(root)
        expect("referenced tombstone rejected without auto replacement",
               "TOMBSTONED_FUNCTION_ID" in codes(report)
               and plan["summary"]["tombstoned"] == 1
               and plan["summary"]["auto_replacements"] == 0)
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["tombstones"].pop())
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))

        # 11. rekey-gap family id
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["entries"].append({
                         "language": "rust",
                         "old_id": RG_GAP_OLD,
                         "new_id": RG_GAP_NEW,
                         "reason": "rust_identity_rekey",
                     }))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_GAP_OLD]}))
        report = doctor(root)
        expect("rekey-gap id rejected", "REKEY_GAP_FUNCTION_ID" in codes(report))
        plan = build_plan(root)
        expect("rekey-gap family listed", plan["summary"]["rekey_gap_family_size"] == 1
               and plan["summary"]["manual_reselect"] == 1)
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))
        migration_report = migration_status_report(root)
        expect("unreferenced rekey-gap family blocks migration completion",
               migration_report["stats"]["plan"]["rekey_gap_family_size"] == 1
               and "PLAN_REKEY_GAP_FAMILY_PENDING" in {
                   blocker["code"] for blocker in migration_report["blockers"]
               })
        rewrite_json(os.path.join(root, MIGRATION_RELPATH),
                     lambda doc: doc["entries"].pop())

        # 12. unmappable id
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_GHOST]}))
        report = doctor(root)
        expect("unmappable id rejected", "UNMAPPABLE_FUNCTION_ID" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))

        # 13. malformed function id shape
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update(
                         {"rust_function_ids": ["RG-F-not-a-scheme2-id"]}))
        report = doctor(root)
        expect("malformed function id rejected", "FUNCTION_ID_MALFORMED" in codes(report))
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0]["impact"].update({"rust_function_ids": [RG_NEW]}))

        # 14. plan determinism on the synthetic tree
        plan_a = render_plan_text(build_plan(root)).encode("utf-8")
        plan_b = render_plan_text(build_plan(root)).encode("utf-8")
        expect("plan deterministic (synthetic)", plan_a == plan_b)
        json_a = dump_json_canonical(build_plan(root))
        json_b = dump_json_canonical(build_plan(root))
        expect("plan json deterministic (synthetic)", json_a == json_b)

        # 15. migration status is deterministic and pre-B2 states are blockers
        rewrite_json(os.path.join(root, REGISTRY_RELPATH),
                     lambda doc: doc["fixtures"][0].update(
                         {"evidence_status": "PARTIAL_MATCH"}))
        rewrite_json(os.path.join(root, "tests/oracle/demo_a_1204.metadata.json"),
                     lambda doc: doc.update(
                         {"overall_status": "PARTIAL_MATCH (coverage incomplete)"}))
        migration_a = migration_status_report(root)
        migration_b = migration_status_report(root)
        migration_codes = {item["code"] for item in migration_a["blockers"]}
        expect("dirty migration status rejects pre-B2 registry and metadata",
               migration_status_exit_code(migration_a) == EXIT_FINDINGS
               and {"REGISTRY_PRE_B2_STATUS", "METADATA_PRE_B2_STATUS"} <= migration_codes)
        expect("migration status deterministic (synthetic)", migration_a == migration_b)
        expect("migration status text deterministic (synthetic)",
               render_migration_status_text(migration_a)
               == render_migration_status_text(migration_b))

        # 16. malformed schema is a stable harness error, never a traceback
        schema_path = os.path.join(root, SCHEMA_RELPATH)
        with open(schema_path, "rb") as handle:
            schema_before = handle.read()
        with open(schema_path, "w", encoding="utf-8") as handle:
            handle.write("{\n")
        captured_out = io.StringIO()
        captured_err = io.StringIO()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            malformed_rc = main(["--root", root, "migration-status", "--strict"])
        with open(schema_path, "wb") as handle:
            handle.write(schema_before)
        expect("malformed schema exits as harness error without traceback",
               malformed_rc == EXIT_HARNESS
               and "harness input error" in captured_err.getvalue()
               and "Traceback" not in captured_err.getvalue()
               and not captured_out.getvalue(),
               detail=json.dumps({"rc": malformed_rc, "stderr": captured_err.getvalue()}))
        unresolved_ref_rejected = False
        try:
            list(MiniSchemaValidator({"$ref": "#/definitions/missing"}).validate({}))
        except HarnessError:
            unresolved_ref_rejected = True
        expect("unresolved internal schema ref is a harness error", unresolved_ref_rejected)

    print()
    if failures:
        print(f"self-test: {len(failures)} FAILURE(S): {failures}")
        return 1
    print("self-test: all cases passed")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=None, help="repository root (default: tool parent)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("doctor", "schema"):
        child = sub.add_parser(name, help=f"run {name}")
        child.add_argument("--json", action="store_true", help="emit machine JSON")

    lint_parser = sub.add_parser("lint", help="doctor + schema in one fail-closed pass")
    lint_parser.add_argument("--json", action="store_true", help="emit machine JSON")
    lint_parser.add_argument("--strict", action="store_true",
                             help="fail-closed mode (the only mode; kept for gate compatibility)")

    migration_parser = sub.add_parser(
        "migration-status", help="summarize fail-closed metadata migration blockers")
    migration_parser.add_argument("--json", action="store_true", help="emit machine JSON")
    migration_parser.add_argument("--strict", action="store_true",
                                  help="fail-closed mode (the only mode)")

    plan_parser = sub.add_parser("plan", help="emit deterministic migration plan")
    plan_parser.add_argument("--json", action="store_true", help="emit machine JSON")
    plan_parser.add_argument("--output", default=None, help="write the plan to this file")
    plan_parser.add_argument("--check-determinism", action="store_true",
                             help="render the plan twice and verify byte equality")

    sub.add_parser("self-test", help="synthetic fixture matrix")

    args = parser.parse_args(argv)
    root = os.path.abspath(args.root) if args.root else repo_root()

    try:
        if args.command == "self-test":
            return self_test()
        if args.command == "doctor":
            report = doctor(root)
            sys.stdout.write(json.dumps(report, sort_keys=True, indent=1) + "\n"
                             if args.json else render_doctor_text(report))
            return EXIT_OK if not report["issues"] else EXIT_FINDINGS
        if args.command == "schema":
            report = schema_check(root)
            sys.stdout.write(json.dumps(report, sort_keys=True, indent=1) + "\n"
                             if args.json else render_schema_text(report))
            return EXIT_OK if not report["deviations"] else EXIT_FINDINGS
        if args.command == "lint":
            doctor_report = doctor(root)
            schema_report = schema_check(root)
            combined = {
                "doctor": {"issues": doctor_report["issues"], "stats": doctor_report["stats"]},
                "schema": {"deviations": schema_report["deviations"], "count": schema_report["count"]},
            }
            total = len(doctor_report["issues"]) + schema_report["count"]
            if args.json:
                sys.stdout.write(json.dumps(combined, sort_keys=True, indent=1) + "\n")
            else:
                sys.stdout.write(render_doctor_text(doctor_report))
                sys.stdout.write(render_schema_text(schema_report))
                sys.stdout.write(f"# lint total findings: {total}\n")
            return EXIT_OK if total == 0 else EXIT_FINDINGS
        if args.command == "migration-status":
            report = migration_status_report(root)
            sys.stdout.write(json.dumps(report, sort_keys=True, indent=1) + "\n"
                             if args.json else render_migration_status_text(report))
            return migration_status_exit_code(report)
        if args.command == "plan":
            plan = build_plan(root)
            text = render_plan_text(plan).encode("utf-8") if not args.json else dump_json_canonical(plan)
            if args.check_determinism:
                again = build_plan(root)
                text_again = (render_plan_text(again).encode("utf-8") if not args.json
                              else dump_json_canonical(again))
                text_other = dump_json_canonical(plan)
                again_other = dump_json_canonical(again)
                if text != text_again or text_other != again_other:
                    sys.stderr.write("determinism check: FAIL (two runs differ)\n")
                    return EXIT_FINDINGS
                sys.stdout.write(text.decode("utf-8"))
                determinism_line = (
                    f"determinism: PASS (text sha256={sha256_bytes(text)}, "
                    f"json sha256={sha256_bytes(text_other)})\n"
                )
                # JSON mode remains a single canonical JSON document; the
                # human determinism receipt goes to stderr instead of making
                # stdout unparsable via trailing prose.
                if args.json:
                    sys.stderr.write(determinism_line)
                else:
                    sys.stdout.write(determinism_line)
                if args.output:
                    with open(args.output, "wb") as handle:
                        handle.write(text)
                return EXIT_OK
            if args.output:
                with open(args.output, "wb") as handle:
                    handle.write(text)
            sys.stdout.write(text.decode("utf-8"))
            return EXIT_OK
    except HarnessError as exc:
        sys.stderr.write(f"{TOOL_NAME}: harness input error: {exc}\n")
        return EXIT_HARNESS
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        # Malformed repository inputs must never leak a traceback or be
        # confused with migration findings.  Specific loaders above provide
        # repo-relative diagnostics; this is the final fail-closed boundary.
        sys.stderr.write(
            f"{TOOL_NAME}: harness input error: {type(exc).__name__}: {exc}\n"
        )
        return EXIT_HARNESS
    return EXIT_HARNESS


if __name__ == "__main__":
    sys.exit(main())
