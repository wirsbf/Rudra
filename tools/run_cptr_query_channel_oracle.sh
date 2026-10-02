#!/usr/bin/env bash
set -euo pipefail

# Immutable B3-COREACTION-CONSTANTPTR-0001 (a1) bilateral oracle runner
# (cptr_query_channel_1204): the Funcdata symbol query channel —
# Database-level Scope::queryContainer / queryProperties / isReadOnly /
# queryByName behind Funcdata::{query_container_parent_scope,
# query_properties_parent_scope, is_scope_read_only,
# query_name_parent_scope}.
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, builds the Rudra crate from the pinned base commit (which
# already carries the query-channel src changes), compiles both fixtures,
# runs them, and requires byte-identical stdout. The 18 records cover:
#   - qc_exact / qc_mid_needexact: the needexacthit input
#     (entry->getAddr() == rampoint, coreaction.cc:1160) observed through
#     the exact data.getScopeLocal()->getParent()->queryContainer(...)
#     call form (coreaction.cc:1151 / funcdata_varnode.cc:1207).
#   - qc_chararray_mid: the TYPE_ARRAY + base isCharPrint middle
#     exception input (coreaction.cc:1153-1159); qc_intarray_mid is the
#     non-char contrast.
#   - getBase(16,TYPE_UNKNOWN) materializes an ARRAY of sixteen 1-byte
#     unknowns (type.cc:3652-3657) — mirrored on the Rust side.
#   - qc_after_range_fold / ro_symbol_after_range: the addMap property
#     fold (database.cc:1153) vs ro_symbol_before_range's install-order
#     non-fold.
#   - ro_scope_only / ro_prop_only / ro_none: the three queryProperties
#     flag branches (database.cc:1269-1280), with the property-only
#     window carved out of the global scope's ram ownership via
#     removeRange so the branch is observable on both sides.
#   - name_hit / name_miss / name_child_shadowed: queryByName (database.cc
#     :1198) — a namespace child's symbols are invisible from the parent.
#   - trav_child_wins / trav_discovery_shadow / trav_plain_global: the
#     mapScope resolvemap split semantics (database.cc:3185,
#     ScopeResolve rangemap insert) and stackContainer's discovery stop
#     (database.cc:957-958).
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
# Repinned 2026-08-25 (R-RAWQUAR F4): the first post-a1 docs/api/database.md
# + funcdata.md edits (register-name channel, segment (b)) broke the
# comparand sha256 gate; source pins bumped from c4a89fa8 to the reworked
# fb1181a0 (a5446455) so the archived src carries the F1/F2 fixes. Input
# pins (binary + sleigh assets, unchanged blobs) stay at c4a89fa8.
rudra_source_commit=a5446455990f95c70f97a360d96fa22f602d9223
rudra_source_tree=ba4af5b19e844f37e7d85d5fb47d836df209dc21
rudra_source_src_tree=5ac2b51c096a2312185ebfb814911ea663e8d231
rudra_source_database_blob=a04143bf057efb5dadac186e89446b30505c7139
rudra_source_funcdata_blob=9d3462025e11e47da872d6bb7fa05e75181074dc
rudra_source_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_source_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_source_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_input_commit=c4a89fa88a48dba18601c17a8648fe688f981131
rudra_input_blob=76d9343ea3add321aa4134856323663b36365807
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/cptr_query_channel_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/cptr_query_channel_1204.cc"
rust_fixture="$repo_root/tests/oracle/cptr_query_channel_1204.rs"
doc_database="$repo_root/docs/api/database.md"
doc_funcdata="$repo_root/docs/api/funcdata.md"
runner="$repo_root/tools/run_cptr_query_channel_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
bfd_library_dir=$(dirname "$bfd_library")
# Task-dedicated Cargo dirs: every Cargo invocation below is serialized
# on the shared build flock and uses these isolated, pre-created
# directories (never /tmp or a shared target).
cargo_target=/home/wirs/.cache/a23-cptr-target
cargo_tmp=/home/wirs/.cache/a23-cptr-tmp
mkdir -p "$cargo_target" "$cargo_tmp"

oracle_tmp=$(mktemp -d /tmp/rudra-cptr-query-channel-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-cptr-query-channel-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$doc_database" "$doc_funcdata" "$runner" "$bfd_header" "$bfd_library"; do
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
  "$rudra_source_commit:src/database.rs:$rudra_source_database_blob" \
  "$rudra_source_commit:src/funcdata.rs:$rudra_source_funcdata_blob" \
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
cp "$cpp_fixture" "$snapshot_root/tests/oracle/cptr_query_channel_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/cptr_query_channel_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/cptr_query_channel_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_cptr_query_channel_oracle.sh"
git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$snapshot_root/examples/curl"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  mkdir -p "$snapshot_root/$(dirname "$asset")"
  git -C "$repo_root" cat-file blob "$rudra_input_commit:$asset" >"$snapshot_root/$asset"
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$doc_database" "$doc_funcdata" "$runner_sha" \
  "$input_blob_size" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_source_database_blob" \
  "$rudra_source_funcdata_blob" \
  "$rudra_source_cargo_toml_blob" "$rudra_source_cargo_lock_blob" \
  "$rudra_source_build_rs_blob" "$rudra_input_commit" "$rudra_input_blob" \
  "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, doc_db_raw,
    doc_fd_raw, runner_sha, binary_size, oracle_commit, oracle_tag, cpp_tree,
    language_tree, makefile_blob, source_commit, source_tree, source_src_tree,
    source_database_blob, source_funcdata_blob, source_cargo_toml_blob,
    source_cargo_lock_blob, source_build_rs_blob, input_commit, input_blob,
    bfd_header_raw, bfd_library_raw,
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
require("fixture", metadata["fixture_id"], "CPTR-QUERY-CHANNEL-1204")
if not isinstance(metadata.get("status_note"), str) or not metadata["status_note"].strip():
    raise SystemExit("status_note must be a non-empty string")
if metadata["todo_ids"] != ["B3-COREACTION-CONSTANTPTR-0001"]:
    raise SystemExit("todo_ids mismatch")
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
    ("source database blob", source["base_database_blob"], source_database_blob),
    ("source funcdata blob", source["base_funcdata_blob"], source_funcdata_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], source_cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], source_cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], source_build_rs_blob),
):
    require(label, actual, expected)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("api_database_sha256", pathlib.Path(doc_db_raw)),
    ("api_funcdata_sha256", pathlib.Path(doc_fd_raw)),
):
    require(key, sha(path.read_bytes()), comparand[key])
require("runner sha", runner_sha, comparand["runner_sha256"])
# The pinned commit already carries the query-channel src changes: the
# snapshot's database.rs/funcdata.rs blobs prove it.
for relative, blob in (
    ("src/database.rs", source_database_blob),
    ("src/funcdata.rs", source_funcdata_blob),
):
    require(
        f"snapshot {relative} equals pinned blob",
        sha((snapshot / relative).read_bytes()),
        hashlib.sha256(
            subprocess.check_output(
                ["git", "-C", str(repo), "cat-file", "blob", blob]
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
require("overall", metadata["overall_status"], "UNTESTED")
coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
expected_matches = {
    "query_container_exact_hit", "query_container_miss",
    "needexacthit_entry_start_input", "char_array_middle_exception",
    "nonchar_array_contrast", "getbase_unknown16_array_product",
    "addmap_property_fold_order", "readonly_symbol_branches",
    "readonly_scope_only_branch", "readonly_property_only_branch",
    "name_query_parent_visibility", "mapscope_resolvemap_split",
    "stackcontainer_discovery_stop", "query_properties_flag_bits",
}
for key in expected_matches:
    record = coverage.get(key)
    if not isinstance(record, dict) or record.get("status") != "MATCH":
        raise SystemExit(f"coverage.{key} must be a MATCH record")
    if record.get("residual_todo_ids") != []:
        raise SystemExit(f"coverage.{key} MATCH must carry no residual")
expected_residuals = {"production_consumer_threading"}
for key in expected_residuals:
    record = coverage.get(key)
    if not isinstance(record, dict) or record.get("status") != "UNTESTED":
        raise SystemExit(f"coverage.{key} must be an UNTESTED record")
    if not record.get("residual_todo_ids"):
        raise SystemExit(f"coverage.{key} UNTESTED needs residual TODO ids")
require("coverage keys", set(coverage), expected_matches | expected_residuals)
top_residual_ids = metadata.get("residual_todo_ids")
if not isinstance(top_residual_ids, list) or not top_residual_ids:
    raise SystemExit("top-level residual_todo_ids must be a non-empty list")
coverage_residual_ids = {
    item
    for record in coverage.values()
    for item in record.get("residual_todo_ids", [])
}
require("coverage/top-level residual union", coverage_residual_ids, set(top_residual_ids))
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
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$cargo_tmp" \
  g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/cptr_query_channel_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/cptr_query_channel_1204_cpp"
env -i PATH=/usr/bin:/bin HOME="$HOME" LC_ALL=C \
  flock -x /tmp/rudra-cargo-build.lock \
  env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" \
  timeout 600 cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
env -i PATH=/usr/bin:/bin TMPDIR="$cargo_tmp" \
  rustc --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/cptr_query_channel_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$oracle_tmp/cptr_query_channel_1204_rust"

set +e
env -i PATH=/usr/bin:/bin LC_ALL=C LD_LIBRARY_PATH="$bfd_library_dir" \
  "$oracle_tmp/cptr_query_channel_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
env -i PATH=/usr/bin:/bin LC_ALL=C \
  "$oracle_tmp/cptr_query_channel_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$snapshot_root/tests/oracle/cptr_query_channel_1204.metadata.json" \
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
    "setup", "qc_exact", "qc_mid_needexact", "qc_miss",
    "qc_chararray_mid", "qc_intarray_mid", "qc_after_range_fold",
    "ro_symbol_before_range", "ro_symbol_after_range", "ro_scope_only",
    "ro_prop_only", "ro_none",
    "name_hit", "name_miss", "name_child_shadowed",
    "trav_child_wins", "trav_discovery_shadow", "trav_plain_global",
]:
    raise SystemExit(f"observation order mismatch: {records}")
if len(records) != metadata["expected_results"]["record_count"]:
    raise SystemExit("record count mismatch")
if paths["rudra_stderr_sha256"].stat().st_size != 0:
    raise SystemExit("Rust fixture stderr must be empty")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'cptr_query_channel_1204: covered_projection=14/14 projection_status=MATCH overall_status=UNTESTED residuals=B3-COREACTION-CONSTANTPTR-0001(segment-b consumer),B3-HUGEHELP-CONSTANTPTR(driver DAT data source a0)\n'
