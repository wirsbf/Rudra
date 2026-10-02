#!/usr/bin/env bash
# Immutable VARMAP-DYNAMICSYM-0001 oracle runner (varmap_dynamicsym_1204).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, rebuilds the Rudra crate from the pinned base commit (the
# projection runs against the committed base; no source overlays), compiles
# both fixtures, runs them, and requires byte-identical stdout.  The 12
# records (6 cases x before/after) cover:
#   - explicit_conflict_dynamic: two explicit highs at one storage whose
#     def ops share the instruction address -> the second linkSymbol hits
#     the first symbol's single-point uselimit, handleSymbolConflict finds
#     the foreign high, and buildDynamicSymbol hashes the varnode into a
#     DYNAMIC Symbol named by the shared-counter local ring (iVar3/uVar4)
#     — the explicit statement-holder symbolization path behind the printc
#     uVar_<offset> GLUE residual (funcdata_varnode.cc:997-1029/1283-1306,
#     dynamic.cc:424-482, database.cc:1690-1703/1756-1786),
#   - separate_usepoints_two_statics: the uselimit gate (two static
#     Symbols at one storage, no dynamic path),
#   - implied_conflict_rejected: the implied twin fails hasName
#     (variable.cc:729-733) before linkSymbol — implied stays rejected,
#   - illegal_input_attach: handleSymbolConflict's isInput leg attaches
#     the existing entry (funcdata_varnode.cc:1000-1003),
#   - spacebase_input_rejected: the unaffected spacebase input fails
#     hasName (variable.cc:737-745),
#   - addrtied_attach_conflict: the isAddrTied leg attaches both highs to
#     one stack Symbol (no dynamic Symbol).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=ae1a28e30eb97e09062d5b64a220c7682f527735
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/varmap_dynamicsym_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/varmap_dynamicsym_1204.cc"
rust_fixture="$repo_root/tests/oracle/varmap_dynamicsym_1204.rs"
doc_varmap="$repo_root/docs/api/varmap.md"
runner="$repo_root/tools/run_varmap_dynamicsym_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rudra-varmap-dynamicsym-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-varmap-dynamicsym-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$doc_varmap" \
  "$runner" "$bfd_header" "$bfd_library"; do
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

runner_sha=$(sha256sum "$runner" | awk '{print $1}')

python3 -I -S - "$repo_root" "$oracle_tmp" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$doc_varmap" "$runner_sha" "$rudra_source_commit" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" "$oracle_language_tree" \
  "$oracle_makefile_blob" "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_root_raw,
    oracle_tmp_raw,
    metadata_raw,
    cpp_fixture_raw,
    rust_fixture_raw,
    doc_varmap_raw,
    runner_sha,
    rudra_source_commit,
    oracle_commit,
    oracle_tag,
    cpp_tree,
    language_tree,
    makefile_blob,
    bfd_header_raw,
    bfd_library_raw,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
oracle_tmp = pathlib.Path(oracle_tmp_raw)
snapshot = oracle_tmp / "workspace"

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def git_blob(spec):
    return subprocess.check_output(
        ["git", "-C", str(repo_root), "cat-file", "blob", spec]
    )

def base_source_files(directory):
    listing = subprocess.check_output(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "--name-only",
         rudra_source_commit, "--", directory],
        text=True,
    ).splitlines()
    return [pathlib.Path(line) for line in listing if line]

crate_files = [
    pathlib.Path("Cargo.toml"),
    pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"),
    pathlib.Path("README.md"),
    pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + base_source_files("src") + base_source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda item: item.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-varmap-dynamicsym-base-v1\0")
crate_hasher.update(rudra_source_commit.encode())
for relative in crate_files:
    data = git_blob(f"{rudra_source_commit}:{relative.as_posix()}")
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    encoded = relative.as_posix().encode()
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_paths = [
    pathlib.Path("tests/oracle/varmap_dynamicsym_1204.cc"),
    pathlib.Path("tests/oracle/varmap_dynamicsym_1204.rs"),
    pathlib.Path("tests/oracle/varmap_dynamicsym_1204.metadata.json"),
    pathlib.Path("docs/api/varmap.md"),
]
special = {}
for relative in special_paths:
    source = repo_root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular non-symlink file: {relative}")
    data = source.read_bytes()
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    special[relative.as_posix()] = data

metadata = json.loads(special["tests/oracle/varmap_dynamicsym_1204.metadata.json"])
require("metadata schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "VARMAP-DYNAMICSYM-0001")
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
require("source commit", source["base_commit"], rudra_source_commit)
for relative, key in (
    ("src/varmap.rs", "base_varmap_blob"),
    ("Cargo.toml", "cargo_toml_blob"),
    ("Cargo.lock", "cargo_lock_blob"),
    ("build.rs", "build_rs_blob"),
):
    oid = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse",
         f"{rudra_source_commit}:{relative}"], text=True
    ).strip()
    require(f"source {key}", source[key], oid)

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha256(special["tests/oracle/varmap_dynamicsym_1204.cc"]),
    "rust_fixture_sha256": sha256(special["tests/oracle/varmap_dynamicsym_1204.rs"]),
    "runner_sha256": runner_sha,
    "doc_varmap_sha256": sha256(special["docs/api/varmap.md"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate hash scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-varmap-dynamicsym-base-v1 plus base commit and sorted length-prefixed paths and contents",
)
for key, actual in observed.items():
    require(key, actual, comparand[key])

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "binary": manifest["binary"],
    "function": manifest["function"],
    "cases": manifest["cases"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha256", sha256(canonical), manifest["sha256"])

binary = git_blob(f"{rudra_source_commit}:examples/curl")
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    data = git_blob(f"{rudra_source_commit}:{relative}")
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    require(f"{key} sha256", sha256(data), metadata["assets"][key]["sha256"])
(snapshot / "examples").mkdir(exist_ok=True)
(snapshot / "examples/curl").write_bytes(binary)
require("binary sha256", sha256(binary), metadata["assets"]["binary"]["sha256"])
require("BFD header sha256", sha256(pathlib.Path(bfd_header_raw).read_bytes()), metadata["assets"]["bfd"]["header_sha256"])
require("BFD library sha256", sha256(pathlib.Path(bfd_library_raw).read_bytes()), metadata["assets"]["bfd"]["library_sha256"])

host_tools = metadata["host_tools"]
require("host compiler", subprocess.check_output(["g++", "--version"], text=True).splitlines()[0], host_tools["g++"])
require("host rustc", subprocess.check_output(["rustc", "--version"], text=True).strip(), host_tools["rustc"])
require("host cargo", subprocess.check_output(["cargo", "--version"], text=True).strip(), host_tools["cargo"])

coverage = metadata.get("coverage")
if not isinstance(coverage, dict):
    raise SystemExit("coverage must be an object")
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
for key, record in coverage.items():
    if not isinstance(record, dict):
        raise SystemExit(f"coverage.{key} must be an object")
    require(f"coverage.{key} fields", set(record), {"status", "covers", "residual_todo_ids"})
    if record["status"] not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {record['status']!r}")
    if record["status"] == "MATCH":
        require(f"coverage.{key} MATCH residuals", record["residual_todo_ids"], [])
    elif not record["residual_todo_ids"]:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
for key in (
    "explicit_conflict_dynamic", "separate_usepoints_two_statics",
    "implied_conflict_rejected", "illegal_input_attach",
    "spacebase_input_rejected", "addrtied_attach_conflict",
):
    require(f"coverage.{key}.status", coverage[key]["status"], "MATCH")

residual_union = metadata["residual_union"]
branch_ids = set()
for entry in residual_union:
    for branch in entry["branches"]:
        branch_ids.add(branch["id"])
        if not branch["detail"]:
            raise SystemExit(f"residual {branch['id']} has no detail")
expected_residuals = {
    "dynamicsym_production_threading", "equate_constant_branch",
    "merge_mixed_high_e2e", "varnode_creation_properties",
}
require("residual branch union", branch_ids, expected_residuals)
require("projection", metadata["projection_status"], "MATCH")
require("overall", metadata["overall_status"], "UNTESTED: (B2 canonicalization)")
print("snapshot verified", flush=True)
PY

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
mkdir -p "$oracle_tmp/source"
git -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

snapshot_decompiler="$oracle_tmp/workspace/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
nice -n 10 make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$oracle_tmp/workspace/tests/oracle/varmap_dynamicsym_1204.cc" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/varmap_dynamicsym_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  nice -n 10 cargo build --offline --locked --quiet \
  --manifest-path "$oracle_tmp/workspace/Cargo.toml" --lib
rustc --edition=2021 "$oracle_tmp/workspace/tests/oracle/varmap_dynamicsym_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/varmap_dynamicsym_1204_rust"

set +e
cd "$oracle_tmp/workspace"
"$oracle_tmp/varmap_dynamicsym_1204_cpp" \
  sleigh_specs examples/curl \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/varmap_dynamicsym_1204_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
cd - >/dev/null
set -e

python3 -I -S - "$metadata" "$oracle_tmp" "$ghidra_status" "$rudra_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
oracle_tmp = pathlib.Path(sys.argv[2])
ghidra_status = int(sys.argv[3])
rudra_status = int(sys.argv[4])

for key, name in (
    ("ghidra_stdout_sha256", "ghidra.stdout"),
    ("ghidra_stderr_sha256", "ghidra.stderr"),
    ("rudra_stdout_sha256", "rudra.stdout"),
    ("rudra_stderr_sha256", "rudra.stderr"),
):
    actual = hashlib.sha256((oracle_tmp / name).read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", ghidra_status),
    ("rugra_exit_code", rudra_status),
    ("diff_exit_code", 0 if
        (oracle_tmp / "ghidra.stdout").read_bytes() == (oracle_tmp / "rudra.stdout").read_bytes()
        else 1),
):
    if actual != metadata["expected_results"][key]:
        raise SystemExit(f"{key} mismatch")

ghidra_lines = (oracle_tmp / "ghidra.stdout").read_text().splitlines()
if len(ghidra_lines) != metadata["expected_results"]["record_count"]:
    raise SystemExit("record count mismatch")
expected_records = []
for case in metadata["input_manifest"]["cases"]:
    expected_records.append((case["id"], "before"))
    expected_records.append((case["id"], "after"))
for index, line in enumerate(ghidra_lines):
    fields = {}
    for part in line.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    expected_case, expected_stage = expected_records[index]
    if fields.get("case") != expected_case or fields.get("stage") != expected_stage:
        raise SystemExit(
            f"observation order mismatch at {index}: "
            f"{fields.get('case')}/{fields.get('stage')} expected "
            f"{expected_case}/{expected_stage}"
        )
if (oracle_tmp / "rudra.stderr").stat().st_size != 0:
    raise SystemExit("Rust fixture stderr must be empty")

print("record verdicts:")
for case in metadata["input_manifest"]["cases"]:
    print(f"  {case['id']}/before: MATCH")
    print(f"  {case['id']}/after: MATCH")
print("varmap_dynamicsym_1204: covered_projection=6/6 projection_status=MATCH overall_status=UNTESTED residuals=MERGE-MIXEDHIGH-0001,DYNAMICSYM-PROD-0001,DYNAMICSYM-EQUATE-0001,VNCREATE-PROPS-0001")
PY
