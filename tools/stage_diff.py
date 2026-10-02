#!/usr/bin/env python3
"""Create and compare ordered Rudra/Ghidra pipeline-stage manifests."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from .oracle_cache import (
        CacheError,
        LOCKED_ORACLE,
        canonical_bytes,
        display_path,
        load_json,
        oracle_commit,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
        validate_metadata,
    )
except ImportError:
    from oracle_cache import (
        CacheError,
        LOCKED_ORACLE,
        canonical_bytes,
        display_path,
        load_json,
        oracle_commit,
        sha256_bytes,
        sha256_file,
        stable_file_record,
        user_path,
        validate_metadata,
    )


SCHEMA = 1
STAGE_ID = re.compile(r"^[A-Za-z0-9_.:-]+$")


class StageError(RuntimeError):
    """A stage manifest or snapshot request is invalid."""


def atomic_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def parse_assignment(value: str, option: str) -> tuple[str, str]:
    if "=" not in value:
        raise StageError(f"{option} expects NAME=VALUE, got {value!r}")
    name, item = value.split("=", 1)
    if not name or not item:
        raise StageError(f"{option} expects non-empty NAME=VALUE")
    return name, item


def parse_context(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, item = parse_assignment(value, "--context")
        if name in result:
            raise StageError(f"duplicate context key {name!r}")
        result[name] = item
    return dict(sorted(result.items()))


def json_observation(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"encoding": "binary", "schema": None, "state": None}
    if not isinstance(document, dict):
        return {"encoding": "json", "schema": None, "state": None}
    state = document.get("state", document.get("status"))
    return {
        "encoding": "json",
        "schema": document.get("schema", document.get("schema_version")),
        "state": state if isinstance(state, (str, int, float, bool)) or state is None else None,
    }


def stage_record(index: int, stage_id: str, path: Path, root: Path) -> dict[str, Any]:
    if not STAGE_ID.fullmatch(stage_id):
        raise StageError(f"invalid stage ID {stage_id!r}")
    if path.is_symlink() or not path.is_file():
        raise StageError(f"stage artifact must be a regular non-symlink file: {path}")
    size, digest = stable_file_record(path)
    observation = json_observation(path)
    return {
        "index": index,
        "id": stage_id,
        "path": display_path(path, root),
        "size": size,
        "sha256": digest,
        **observation,
    }


def create_manifest(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    metadata_path = user_path(root, args.metadata)
    if metadata_path.is_symlink():
        raise StageError(f"metadata must not be a symlink: {metadata_path}")
    metadata = validate_metadata(load_json(metadata_path))
    stages: list[dict[str, Any]] = []
    seen: set[str] = set()
    output_path = user_path(root, args.output).resolve()
    for index, value in enumerate(args.stage):
        stage_id, raw_path = parse_assignment(value, "--stage")
        if stage_id in seen:
            raise StageError(f"duplicate stage ID {stage_id!r}")
        seen.add(stage_id)
        artifact_path = user_path(root, raw_path)
        if artifact_path.resolve() == output_path:
            raise StageError("snapshot output must not overwrite a stage artifact")
        stages.append(stage_record(index, stage_id, artifact_path, root))
    if not stages:
        raise StageError("snapshot requires at least one --stage ID=PATH")
    return {
        "schema": SCHEMA,
        "producer": args.producer,
        "provenance": {
            "oracle_commit": oracle_commit(metadata),
            "architecture": metadata["architecture"],
            "compiler_spec": metadata["compiler_spec"],
            "analysis_options": metadata["analysis_options"],
            "metadata_path": display_path(metadata_path, root),
            "metadata_sha256": sha256_file(metadata_path),
            "metadata_document_sha256": sha256_bytes(canonical_bytes(metadata)),
            "context": parse_context(args.context),
            "generator_sha256": sha256_file(Path(__file__)),
        },
        "stages": stages,
    }


def validate_manifest(document: Any, label: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise StageError(f"{label} manifest root must be an object")
    if document.get("schema") != SCHEMA:
        raise StageError(f"{label} manifest schema is not {SCHEMA}")
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise StageError(f"{label} manifest has no provenance object")
    if provenance.get("oracle_commit") != LOCKED_ORACLE:
        raise StageError(f"{label} manifest does not name locked Ghidra 12.0.4")
    for field in ("architecture", "compiler_spec", "analysis_options"):
        if provenance.get(field) in (None, "", {}, []):
            raise StageError(f"{label} manifest provenance is missing {field}")
    for field in ("metadata_sha256", "metadata_document_sha256", "generator_sha256"):
        digest = provenance.get(field)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise StageError(f"{label} manifest provenance has an invalid {field}")
    stages = document.get("stages")
    if not isinstance(stages, list) or not stages:
        raise StageError(f"{label} manifest has no stages")
    seen: set[str] = set()
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            raise StageError(f"{label} stage {index} is not an object")
        stage_id = str(stage.get("id", ""))
        if not STAGE_ID.fullmatch(stage_id) or stage_id in seen:
            raise StageError(f"{label} stage {index} has an invalid/duplicate ID")
        seen.add(stage_id)
        if stage.get("index") != index:
            raise StageError(f"{label} stage {stage_id} has a non-contiguous index")
        if not isinstance(stage.get("size"), int) or int(stage["size"]) < 0:
            raise StageError(f"{label} stage {stage_id} has an invalid size")
        digest = stage.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise StageError(f"{label} stage {stage_id} has an invalid hash")
    return document


def difference(kind: str, index: int | None, left: Any, right: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "index": index,
        "left": left,
        "right": right,
    }


def compare_manifests(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left = validate_manifest(left, "left")
    right = validate_manifest(right, "right")
    if left["provenance"] != right["provenance"]:
        return {
            "schema": SCHEMA,
            "equal": False,
            "first_difference": difference(
                "provenance_mismatch", None, left["provenance"], right["provenance"]
            ),
        }
    left_stages = left["stages"]
    right_stages = right["stages"]
    left_ids = [stage["id"] for stage in left_stages]
    right_ids = [stage["id"] for stage in right_stages]
    if left_ids != right_ids and sorted(left_ids) == sorted(right_ids):
        first = next(
            index
            for index, (left_id, right_id) in enumerate(zip(left_ids, right_ids))
            if left_id != right_id
        )
        return {
            "schema": SCHEMA,
            "equal": False,
            "first_difference": difference(
                "stage_order_mismatch", first, left_ids[first], right_ids[first]
            ),
        }
    shared = min(len(left_stages), len(right_stages))
    for index in range(shared):
        left_stage = left_stages[index]
        right_stage = right_stages[index]
        if left_stage["id"] != right_stage["id"]:
            kind = (
                "missing_stage_right"
                if left_stage["id"] not in right_ids
                else "missing_stage_left"
                if right_stage["id"] not in left_ids
                else "stage_id_mismatch"
            )
            return {
                "schema": SCHEMA,
                "equal": False,
                "first_difference": difference(
                    kind, index, left_stage["id"], right_stage["id"]
                ),
            }
        for field, kind in (
            ("schema", "stage_schema_mismatch"),
            ("state", "stage_state_mismatch"),
            ("sha256", "stage_hash_mismatch"),
            ("size", "stage_size_mismatch"),
        ):
            if left_stage.get(field) != right_stage.get(field):
                return {
                    "schema": SCHEMA,
                    "equal": False,
                    "first_difference": difference(
                        kind,
                        index,
                        {"id": left_stage["id"], field: left_stage.get(field)},
                        {"id": right_stage["id"], field: right_stage.get(field)},
                    ),
                }
    if len(left_stages) != len(right_stages):
        if len(left_stages) > shared:
            return {
                "schema": SCHEMA,
                "equal": False,
                "first_difference": difference(
                    "missing_stage_right", shared, left_stages[shared]["id"], None
                ),
            }
        return {
            "schema": SCHEMA,
            "equal": False,
            "first_difference": difference(
                "missing_stage_left", shared, None, right_stages[shared]["id"]
            ),
        }
    return {
        "schema": SCHEMA,
        "equal": True,
        "first_difference": None,
        "stage_count": len(left_stages),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--metadata", required=True, type=Path)
    snapshot.add_argument("--producer", required=True)
    snapshot.add_argument("--stage", action="append", default=[], metavar="ID=PATH")
    snapshot.add_argument("--context", action="append", default=[], metavar="KEY=VALUE")
    snapshot.add_argument("--output", required=True, type=Path)
    compare = subparsers.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("--report", type=Path)
    compare.add_argument("--pretty", action="store_true")
    return parser.parse_args(argv)


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rudra-stage-diff-test-") as raw_temp:
        temp = Path(raw_temp)
        provenance = {
            "oracle_commit": LOCKED_ORACLE,
            "architecture": "test",
            "compiler_spec": "test",
            "analysis_options": {"mode": "test"},
            "metadata_path": "metadata.json",
            "metadata_sha256": "1" * 64,
            "metadata_document_sha256": "2" * 64,
            "context": {},
            "generator_sha256": "3" * 64,
        }

        def manifest(stages: list[tuple[str, int, str, Any]]) -> dict[str, Any]:
            return {
                "schema": SCHEMA,
                "producer": "test",
                "provenance": provenance,
                "stages": [
                    {
                        "index": index,
                        "id": stage_id,
                        "path": f"{stage_id}.json",
                        "size": size,
                        "sha256": digest,
                        "encoding": "json",
                        "schema": stage_schema,
                        "state": "OK",
                    }
                    for index, (stage_id, size, digest, stage_schema) in enumerate(stages)
                ],
            }

        base = manifest([("lift", 1, "a" * 64, 1), ("ssa", 2, "b" * 64, 1)])
        assert compare_manifests(base, json.loads(json.dumps(base)))["equal"]
        changed = manifest([("lift", 1, "a" * 64, 1), ("ssa", 2, "c" * 64, 1)])
        assert compare_manifests(base, changed)["first_difference"]["kind"] == "stage_hash_mismatch"
        reordered = manifest([("ssa", 2, "b" * 64, 1), ("lift", 1, "a" * 64, 1)])
        assert compare_manifests(base, reordered)["first_difference"]["kind"] == "stage_order_mismatch"
        missing = manifest([("lift", 1, "a" * 64, 1)])
        assert compare_manifests(base, missing)["first_difference"]["kind"] == "missing_stage_right"
        schema = manifest([("lift", 1, "a" * 64, 2), ("ssa", 2, "b" * 64, 1)])
        assert compare_manifests(base, schema)["first_difference"]["kind"] == "stage_schema_mismatch"
        artifact = temp / "artifact.json"
        artifact.write_text('{"schema":1,"status":"OK","ops":[1,2]}\n', encoding="utf-8")
        observation = json_observation(artifact)
        assert observation == {"encoding": "json", "schema": 1, "state": "OK"}
    print("stage_diff: self-test OK")
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command is None:
        print("stage_diff: a command is required", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent.parent
    try:
        if args.command == "snapshot":
            manifest = create_manifest(args, root)
            atomic_json(user_path(root, args.output), manifest)
            print(
                json.dumps(
                    {
                        "schema": SCHEMA,
                        "output": display_path(user_path(root, args.output), root),
                        "stage_count": len(manifest["stages"]),
                        "manifest_sha256": sha256_bytes(canonical_bytes(manifest)),
                    },
                    sort_keys=True,
                )
            )
            return 0
        left = validate_manifest(load_json(user_path(root, args.left)), "left")
        right = validate_manifest(load_json(user_path(root, args.right)), "right")
        report = compare_manifests(left, right)
        if args.report:
            atomic_json(user_path(root, args.report), report)
        print(
            json.dumps(
                report,
                indent=2 if args.pretty else None,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
        return 0 if report["equal"] else 1
    except (CacheError, StageError, OSError, json.JSONDecodeError) as error:
        print(f"stage_diff: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
