#!/usr/bin/env bash
# DATATYPE-TYPEORDER-0001 locked Ghidra/Rudra differential runner.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_datatype_base_blob=f766badaff4a4b2761edaa4e4ff0f138ba86679b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/datatype_type_order_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/datatype_type_order_1204.cc"
rust_fixture="$repo_root/tests/oracle/datatype_type_order_1204.rs"
datatype_source="$repo_root/src/type_system/datatype.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$datatype_source" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required regular non-symlink input is missing: $required" >&2
    exit 1
  fi
done

actual_oracle_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_oracle_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

actual_base_commit=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
actual_datatype_blob=$(git -C "$repo_root" rev-parse \
  "$rudra_base_commit:src/type_system/datatype.rs")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" || \
      "$actual_datatype_blob" != "$rudra_datatype_base_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

python3 - "$metadata" "$cpp_fixture" "$rust_fixture" "$datatype_source" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_base_commit" "$rudra_base_tree" "$rudra_datatype_base_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw,
    cpp_raw,
    rust_raw,
    datatype_raw,
    oracle_tag,
    oracle_commit,
    cpp_tree,
    makefile_blob,
    rudra_base_commit,
    rudra_base_tree,
    datatype_base_blob,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
if metadata.get("schema_version") != 2:
    raise SystemExit("metadata schema_version must be 2")
if metadata.get("fixture_id") != "DATATYPE-TYPEORDER-0001":
    raise SystemExit("metadata fixture_id mismatch")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("metadata status_note must be non-empty")
decisive = metadata.get("decisive_semantics")
expected_decisive = {
    "reference_and_output_parameters",
    "loop_boundaries_and_iteration_order",
    "counters_accumulators_and_scope",
    "sorting_and_comparison_keys",
}
if not isinstance(decisive, dict) or set(decisive) != expected_decisive:
    raise SystemExit("metadata decisive_semantics must contain the four exact classes")
if any(not isinstance(value, str) or not value.strip() for value in decisive.values()):
    raise SystemExit("metadata decisive_semantics entries must be non-empty strings")

coverage = metadata.get("coverage")
if not isinstance(coverage, dict) or not coverage:
    raise SystemExit("metadata coverage must be a non-empty object")
all_residuals = set()
mismatch_residuals = set()
for name, entry in coverage.items():
    if not isinstance(entry, dict) or set(entry) != {
        "status", "covers", "residual_todo_ids"
    }:
        raise SystemExit(f"coverage entry has wrong schema: {name}")
    status = entry["status"]
    if status not in {"MATCH", "MISMATCH", "UNTESTED"}:
        raise SystemExit(f"coverage entry has invalid status: {name}={status}")
    if not isinstance(entry["covers"], str) or not entry["covers"].strip():
        raise SystemExit(f"coverage entry has empty covers: {name}")
    residuals = entry["residual_todo_ids"]
    if not isinstance(residuals, list) or len(residuals) != len(set(residuals)):
        raise SystemExit(f"coverage residual ids are invalid: {name}")
    if status == "MATCH" and residuals:
        raise SystemExit(f"MATCH coverage entry has residual ids: {name}")
    if status != "MATCH" and not residuals:
        raise SystemExit(f"non-MATCH coverage entry lacks residual ids: {name}")
    all_residuals.update(residuals)
    if status == "MISMATCH":
        mismatch_residuals.update(residuals)

top_residuals = metadata.get("residual_todo_ids")
if not isinstance(top_residuals, list) or len(top_residuals) != len(set(top_residuals)):
    raise SystemExit("top-level residual_todo_ids are invalid")
if set(top_residuals) != all_residuals:
    raise SystemExit("top-level and coverage residual TODO sets differ")

expected_mismatches = metadata.get("expected_mismatches")
if not isinstance(expected_mismatches, dict) or not expected_mismatches:
    raise SystemExit("expected_mismatches must be a non-empty object")
mismatch_todos = set()
for key, entry in expected_mismatches.items():
    if not isinstance(entry, dict) or set(entry) != {"ghidra", "rugra", "todo"}:
        raise SystemExit(f"expected mismatch has wrong schema: {key}")
    if entry["ghidra"] == entry["rugra"]:
        raise SystemExit(f"expected mismatch is actually equal: {key}")
    if not isinstance(entry["todo"], str) or not entry["todo"]:
        raise SystemExit(f"expected mismatch lacks TODO id: {key}")
    mismatch_todos.add(entry["todo"])
if mismatch_todos != mismatch_residuals:
    raise SystemExit("expected-mismatch and MISMATCH-coverage TODO sets differ")

oracle = metadata["oracle"]
expected_oracle = {
    "repository": "NationalSecurityAgency/ghidra",
    "tag": oracle_tag,
    "commit": oracle_commit,
    "decompiler_cpp_tree": cpp_tree,
    "decompiler_makefile_blob": makefile_blob,
}
if oracle != expected_oracle:
    raise SystemExit("metadata oracle identity mismatch")

comparand = metadata["comparand"]
expected_base = {
    "rust_base_commit": rudra_base_commit,
    "rust_base_tree": rudra_base_tree,
    "datatype_base_blob": datatype_base_blob,
}
for key, value in expected_base.items():
    if comparand[key] != value:
        raise SystemExit(f"metadata {key} mismatch")

for key, raw in {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "datatype_rs_sha256": datatype_raw,
}.items():
    actual = hashlib.sha256(pathlib.Path(raw).read_bytes()).hexdigest()
    if comparand[key] != actual:
        raise SystemExit(f"input hash mismatch for {raw}: {actual}")

manifest_payload = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "cases": metadata["input_manifest"]["cases"],
}
canonical = json.dumps(
    manifest_payload, sort_keys=True, separators=(",", ":")
).encode("utf-8")
actual_manifest = hashlib.sha256(canonical).hexdigest()
if metadata["input_manifest"]["sha256"] != actual_manifest:
    raise SystemExit(f"input manifest hash mismatch: {actual_manifest}")
if metadata["projection_status"] != "MATCH" or metadata["overall_status"] != "MISMATCH: (B2 canonicalization)":
    raise SystemExit("fixture metadata status is not projection MATCH / overall MISMATCH")
PY

oracle_tmp=$(mktemp -d /tmp/rudra-datatype-type-order-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-datatype-type-order-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

snapshot_root="$oracle_tmp/rudra"
mkdir -p "$snapshot_root/ghidra"
git -C "$repo_root" archive --format=tar "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim examples/curl sleigh_specs/x86-64.sla \
  sleigh_specs/x86-64.pspec sleigh_specs/x86-64-gcc.cspec \
  sleigh_specs/x86.ldefs | tar -xf - -C "$snapshot_root"
git -C "$ghidra_root" archive --format=tar "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  tar -xf - -C "$snapshot_root/ghidra"
mkdir -p "$snapshot_root/tests/oracle"
cp "$datatype_source" "$snapshot_root/src/type_system/datatype.rs"
cp "$rust_fixture" "$snapshot_root/tests/oracle/datatype_type_order_1204.rs"

python3 - "$metadata" "$snapshot_root" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
root = pathlib.Path(sys.argv[2])
for asset in metadata["assets"].values():
    if not isinstance(asset, dict) or "path" not in asset:
        continue
    path = root / asset["path"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != asset["sha256"]:
        raise SystemExit(f"asset hash mismatch for {asset['path']}: {actual}")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -w -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" "$cpp_root/libdecomp.a" \
  "$bfd_library" -lz \
  -o "$oracle_tmp/datatype_type_order_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" RUSTFLAGS="-Awarnings" \
  cargo build --quiet --locked --offline \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$snapshot_root/tests/oracle/datatype_type_order_1204.rs" \
  -o "$oracle_tmp/datatype_type_order_rust"

"$oracle_tmp/datatype_type_order_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/datatype_type_order_rust" >"$oracle_tmp/rudra.stdout"

python3 - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_output = pathlib.Path(sys.argv[2]).read_bytes()
rudra_output = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_sha = hashlib.sha256(ghidra_output).hexdigest()
rudra_sha = hashlib.sha256(rudra_output).hexdigest()
if metadata["expected_ghidra_stdout_sha256"] != ghidra_sha:
    raise SystemExit(f"Ghidra stdout hash mismatch: {ghidra_sha}")
if metadata["expected_rudra_stdout_sha256"] != rudra_sha:
    raise SystemExit(f"Rudra stdout hash mismatch: {rudra_sha}")

def parse(raw, side):
    result = {}
    for line in raw.decode("utf-8").splitlines():
        if "=" not in line:
            raise SystemExit(f"malformed {side} record: {line!r}")
        key, value = line.split("=", 1)
        if key in result:
            raise SystemExit(f"duplicate {side} key: {key}")
        result[key] = value
    return result

ghidra = parse(ghidra_output, "Ghidra")
rudra = parse(rudra_output, "Rudra")
if set(ghidra) != set(rudra):
    raise SystemExit("Ghidra/Rudra observation keys differ")
expected_mismatches = metadata["expected_mismatches"]
actual_mismatches = {}
for key in sorted(ghidra):
    if ghidra[key] != rudra[key]:
        actual_mismatches[key] = {"ghidra": ghidra[key], "rugra": rudra[key]}
declared_mismatches = {
    key: {"ghidra": value["ghidra"], "rugra": value["rugra"]}
    for key, value in expected_mismatches.items()
}
if actual_mismatches != declared_mismatches:
    raise SystemExit(
        f"mismatch set drifted: expected={declared_mismatches} actual={actual_mismatches}"
    )
records = len(ghidra)
expected_records = metadata["observation_schema"]["record_count"]
if records != expected_records:
    raise SystemExit(f"record-count mismatch: {records}")
print(f"records={records}")
print(f"matched={records-len(actual_mismatches)} mismatched={len(actual_mismatches)}")
print(f"ghidra_stdout_sha256={ghidra_sha}")
print(f"rudra_stdout_sha256={rudra_sha}")
PY
printf 'datatype_type_order_1204: projection_status=MATCH overall_status=MISMATCH\n'
