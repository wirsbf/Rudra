#!/usr/bin/env bash
set -euo pipefail

# Immutable SCOPELOCAL-QUERY-0001 r2 oracle runner
# (scopelocal_query_1204): the entry-granular ScopeLocal query layer
# (findOverlap / findAddr / findContainer / queryProperties) over the
# oracle-proven rangemap.
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, builds the Rudra crate from the pinned base commit plus the
# varmap.rs overlay (hash-verified to equal the pinned commit's blob),
# compiles both fixtures, runs them, and requires byte-identical stdout.
# The 27 records cover:
#   - the equal-subsort bracketing quirk: the second insert's rangemap
#     parts (hinted-before + tail-after) bracket the first, so BOTH the
#     forward findOverlap walk and the backward findAddr walk answer the
#     SECOND inserted (rangemap.hh:223-277, database.cc:2392/2224),
#   - the wide/narrow dual order: the EntrySubsort-minimum record owns the
#     shared partition unit regardless of insertion order or start address,
#     while findAddr demands the exact start plus RANGE-containment inUse
#     (database.cc:114-120),
#   - multi-uselimit entries: a usepoint in the second disjoint range
#     answers, the gap does not (subsort from the first range,
#     database.cc:102-106),
#   - the per-space maptable dimension (database.cc:2227/2254/2395),
#   - one symbol with two mappings: both entries answer, removeSymbol
#     drops both, the survivor keeps answering (database.cc:2117-2150),
#   - findContainer's smallest-container walk, exact-size break and
#     equal-size equal-subsort tie (database.cc:2250-2282),
#   - join-piece entries with getOffset() != 0 and precishi extraflags
#     (database.cc:1156-1177),
#   - the three queryProperties flag branches, the parent (global scope)
#     stackContainer walk, the constant-space short-circuit
#     (database.cc:1263-1281, 943-962, 950), and markNotMapped's
#     symbol-removal + ownership-window split (varmap.cc:510-546).
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=0e2c87d5d75ca755198d1f2cae1218d8d0a88135
rudra_source_tree=2eaa964981c4c49377888972d57d2a83b044be17
rudra_source_src_tree=9c45fab3e135b71a0d68e1dc1978413f9b25b168
rudra_source_varmap_blob=9d46add750c3b48967a70b825d73260318d740dc
rudra_source_cargo_toml_blob=990a23789c5cebc24b6d453a6832e5c8dbee117a
rudra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_input_commit=0e2c87d5d75ca755198d1f2cae1218d8d0a88135
rudra_input_blob=76d9343ea3add321aa4134856323663b36365807
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/scopelocal_query_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/scopelocal_query_1204.cc"
rust_fixture="$repo_root/tests/oracle/scopelocal_query_1204.rs"
rust_overlay="$repo_root/src/varmap.rs"
doc_varmap="$repo_root/docs/api/varmap.md"
runner="$repo_root/tools/run_scopelocal_query_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rudra-scopelocal-query-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-scopelocal-query-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$rust_overlay" \
  "$doc_varmap" "$runner" "$bfd_header" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_language_tree" != "$oracle_language_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_source_commit^{commit}:$rudra_source_commit" \
  "$rudra_source_commit^{tree}:$rudra_source_tree" \
  "$rudra_source_commit:src:$rudra_source_src_tree" \
  "$rudra_source_commit:src/varmap.rs:$rudra_source_varmap_blob" \
  "$rudra_source_commit:Cargo.toml:$rudra_source_cargo_toml_blob" \
  "$rudra_source_commit:Cargo.lock:$rudra_source_cargo_lock_blob" \
  "$rudra_source_commit:build.rs:$rudra_source_build_rs_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra source identity mismatch: $expression" >&2
    exit 1
  fi
done

resolved_input_commit=$(git -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
resolved_input_blob=$(git -C "$repo_root" rev-parse "$rudra_input_commit:examples/curl")
input_blob_size=$(git -C "$repo_root" cat-file -s "$resolved_input_blob")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$resolved_input_blob" != "$rudra_input_blob" ]]; then
  echo "pinned Rudra input Git object mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$snapshot_root/tests/oracle" \
  "$snapshot_root/tools" "$snapshot_root/examples"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-source.tar" "$rudra_source_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
tar -xf "$oracle_tmp/rudra-source.tar" -C "$snapshot_root"
cp "$rust_overlay" "$snapshot_root/src/varmap.rs"
cp "$cpp_fixture" "$snapshot_root/tests/oracle/scopelocal_query_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/scopelocal_query_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/scopelocal_query_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_scopelocal_query_oracle.sh"
git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$snapshot_root/examples/curl"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  mkdir -p "$snapshot_root/$(dirname "$asset")"
  git -C "$repo_root" cat-file blob "$rudra_input_commit:$asset" >"$snapshot_root/$asset"
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$rust_overlay" "$doc_varmap" "$runner_sha" \
  "$input_blob_size" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_source_varmap_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" "$rudra_input_commit" "$rudra_input_blob" \
  "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, overlay_raw,
    doc_raw, runner_sha, binary_size, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, source_commit, source_tree, source_src_tree,
    source_varmap_blob, source_cargo_toml_blob, source_cargo_lock_blob,
    source_build_rs_blob, input_commit, input_blob, bfd_header_raw,
    bfd_library_raw,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "SCOPELOCAL-QUERY-1204")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("status_note must be a non-empty string")
decisive = metadata.get("decisive_semantics")
expected_decisive = {
    "reference_output_parameters", "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle", "sorting_comparison_keys",
}
if not isinstance(decisive, dict):
    raise SystemExit("decisive_semantics must be an object")
require("decisive semantic classes", set(decisive), expected_decisive)
for key, value in decisive.items():
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"decisive_semantics.{key} must be non-empty")
oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle language tree", oracle["x86_language_tree"], language_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")
source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source varmap blob", source["base_varmap_blob"], source_varmap_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("varmap_overlay_sha256", pathlib.Path(overlay_raw)),
    ("api_document_sha256", pathlib.Path(doc_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
# The overlay must equal the pinned commit's varmap.rs blob: this runner
# proves a COMMITTED projection, not a working-tree candidate.
require(
    "overlay equals pinned varmap blob",
    sha(pathlib.Path(overlay_raw).read_bytes()),
    hashlib.sha256(
        subprocess.check_output(
            ["git", "-C", str(repo), "cat-file", "blob", source_varmap_blob]
        )
    ).hexdigest(),
)

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    record = assets[key]
    require(f"{key} path", record["path"], relative)
    require(f"{key} source commit", record["source_repository_commit"], input_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{input_commit}:{relative}"], text=True
    ).strip()
    require(f"{key} blob", oid, record["git_blob_oid"])
    data = (snapshot / relative).read_bytes()
    require(f"{key} sha", sha(data), record["sha256"])
    require(f"{key} size", len(data), record["size"])
binary = (snapshot / "examples/curl").read_bytes()
require("binary blob", assets["binary"]["git_blob_oid"], input_blob)
require("binary size", len(binary), int(binary_size))
require("binary metadata size", len(binary), assets["binary"]["size"])
require("binary sha", sha(binary), assets["binary"]["sha256"])
require("BFD header", sha(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library", sha(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "functions": manifest["functions"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("manifest sha", sha(canonical), manifest["sha256"])
require("projection", metadata["projection_status"], "MATCH")
# overall_status keeps the annotated B2-canonicalization form
# ("UNTESTED: (B2 canonicalization)") — the runner predates the annotation
# convention; accept any UNTESTED-prefixed form (any MATCH would be wrong
# here: production consumers are a registered residual).
if not str(metadata["overall_status"]).startswith("UNTESTED"):
    raise SystemExit(
        f"overall mismatch: {metadata['overall_status']!r} (expected UNTESTED prefix)"
    )
expected_matches = {
    "setup_space_indices", "equal_subsort_both_walks", "wide_narrow_dual_order",
    "multi_uselimit_containment", "cross_space_maptable",
    "multi_mapping_removal", "find_container_smallest_tie",
    "partial_offset_piece", "query_properties_local_branches",
    "query_properties_parent_walk", "marknotmapped_window",
}
expected_residuals = {
    "production_consumer_threading", "multientryset_wholecount",
    "addmap_property_fold", "database_flagbase_partmap",
    "space_index_unverified_variants",
}
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
require("coverage keys", set(coverage), expected_matches | expected_residuals)
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
coverage_residual_ids = set()
observed_statuses = set()
for key, record in coverage.items():
    if not isinstance(record, dict):
        raise SystemExit(f"coverage.{key} must be an object")
    require(
        f"coverage.{key} fields",
        set(record),
        {"status", "covers", "residual_todo_ids"},
    )
    status = record["status"]
    if status not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {status!r}")
    observed_statuses.add(status)
    if not isinstance(record["covers"], str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers must be non-empty")
    residual_ids = record["residual_todo_ids"]
    if not isinstance(residual_ids, list) or any(
        not isinstance(item, str) or not item for item in residual_ids
    ):
        raise SystemExit(f"coverage.{key}.residual_todo_ids is invalid")
    if len(residual_ids) != len(set(residual_ids)):
        raise SystemExit(f"coverage.{key}.residual_todo_ids contains duplicates")
    if status == "MATCH":
        require(f"coverage.{key} MATCH residuals", residual_ids, [])
    elif not residual_ids:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
    coverage_residual_ids.update(residual_ids)
for key in expected_matches:
    require(f"coverage.{key}.status", coverage[key]["status"], "MATCH")
for key in expected_residuals:
    require(f"coverage.{key}.status", coverage[key]["status"], "UNTESTED")
require("coverage status set", observed_statuses, {"MATCH", "UNTESTED"})
require(
    "projection/coverage consistency",
    metadata["projection_status"],
    "MATCH" if all(coverage[key]["status"] == "MATCH" for key in expected_matches) else "UNTESTED",
)
if not str(metadata["overall_status"]).startswith(
    "UNTESTED"
    if any(record["status"] == "UNTESTED" for record in coverage.values())
    else "MATCH"
):
    raise SystemExit(
        "overall/coverage consistency mismatch: "
        f"{metadata['overall_status']!r}"
    )
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list) or not top_residual_ids:
    raise SystemExit("top-level residual_todo_ids must be a non-empty list")
if any(not isinstance(item, str) or not item for item in top_residual_ids):
    raise SystemExit("top-level residual_todo_ids contains an invalid id")
if len(top_residual_ids) != len(set(top_residual_ids)):
    raise SystemExit("top-level residual_todo_ids contains duplicates")
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
require(
    "top-level residual ids",
    set(top_residual_ids),
    {"SCOPELOCAL-QUERY-RESIDUAL-0002", "DB-LOCALSCOPE-MAP-0001", "ADDRESS-0001"},
)
residual_union = metadata["residual_union"]
for entry in residual_union:
    require("residual TODO status", entry["status"], "UNTESTED")
    for branch in entry["branches"]:
        require(f"residual {branch['id']} status", branch["status"], "UNTESTED")
        if not branch["detail"]:
            raise SystemExit(f"residual {branch['id']} has no detail")
branch_ids = {branch["id"] for entry in residual_union for branch in entry["branches"]}
require("residual branch union", branch_ids, expected_residuals)
PY

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$oracle_cpp" "$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/scopelocal_query_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/scopelocal_query_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 "$snapshot_root/tests/oracle/scopelocal_query_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/scopelocal_query_1204_rust"

set +e
"$oracle_tmp/scopelocal_query_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/scopelocal_query_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$snapshot_root/tests/oracle/scopelocal_query_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[7])),
    ("rugra_exit_code", int(sys.argv[8])),
    ("diff_exit_code", int(sys.argv[9])),
):
    if actual != metadata["expected_results"][key]:
        raise SystemExit(f"{key} mismatch")
records = paths["ghidra_stdout_sha256"].read_text(encoding="utf-8").splitlines()
if [record.split("|", 1)[0][len("case="):] for record in records] != [
    "setup", "equal_subsort_overlap", "equal_subsort_findaddr",
    "wide_narrow_overlap", "wide_narrow_overlap_wide_cell",
    "wide_narrow_findaddr_midrange", "wide_narrow_findaddr_wide_use",
    "wide_narrow_findaddr_nouse", "multi_uselimit_second_range",
    "multi_uselimit_gap", "cross_space_stack_query", "cross_space_ram_query",
    "multi_mapping_first", "multi_mapping_second", "remove_requery_first",
    "remove_requery_second", "remove_requery_survivor",
    "find_container_smallest", "find_container_equal_tie",
    "partial_offset_piece_hi", "qp_local_symbol", "qp_scope_symbol_victim",
    "marknotmapped_window", "qp_scope_only_property", "qp_parent_symbol",
    "qp_none", "qp_constant",
]:
    raise SystemExit(f"observation order mismatch: {records}")
if len(records) != metadata["expected_results"]["record_count"]:
    raise SystemExit("record count mismatch")
if paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("Rust fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'scopelocal_query_1204: covered_projection=11/11 projection_status=MATCH overall_status=UNTESTED residuals=SCOPELOCAL-QUERY-RESIDUAL-0002,DB-LOCALSCOPE-MAP-0001,ADDRESS-0001\n'
