#!/usr/bin/env bash
# Immutable COPYTRIM-REMAT-0001 oracle runner (copytrim_remat_1204).
#
# KUNABUGS-COPYTRIM-REMAT-0001 (CASTFUSE-A candidate ③): does
# Merge::allocateCopyTrim re-materialize an explicit COPY at the firstuse
# of a dynamic-hash temp?  The fixture locks the oracle answer bilaterally
# across six cases; this runner rebuilds the locked Ghidra 12.0.4
# decompiler from the pinned source archive, rebuilds the Rudra crate from
# the pinned base commit, compiles both fixtures, runs them, and checks
# every observable against the pinned expectations:
#
#   fold_relocate_fn   MATCH — the folded COPY breaks the use-anchored
#                      dynamic hash on BOTH runtimes: relocation fails,
#                      nothing is mapped, ZERO ops are created.  The
#                      oracle has no re-materialization mechanism for
#                      dynamic-hash temps anywhere (candidate ③ literal
#                      falsification).
#   refind_attach_fn   MATCH — the attach itself matches (mapped=1,
#                      guard, zero ops) and the boolean return matches
#                      since DYNMAP-SETPROPS-RET-0001 landed (Rudra
#                      surfaces Varnode::setSymbolProperties' result,
#                      false here, keeping ActionDynamicMapping's count
#                      at 0 while the attach happened).
#   late_cast_retarget MATCH — since DYNMAP-LATE-CAST-RETARGET-0001 and
#                      DYNHASH-UNIQUE-ANCHOR-0001 landed, both runtimes
#                      anchor tmp NOT-ATTACHED at the reading op and
#                      attach the explicit c0 across the CAST (same mint
#                      hash, same after-census rows).
#   trim_dynamic_high  MATCH — the merge trims match exactly
#                      (copy@b1(X)/copy@b2(fX) lane rewires, 4-COPY
#                      census, dynamic entry count untouched by merge):
#                      trims are cover-driven only; the minted hash line
#                      matches since DYNHASH-UNIQUE-ANCHOR-0001.
#   action_walk_level  MATCH — since COREACT-DYNMAP-STUB-0001's real
#                      body landed, both runtimes walk
#                      beginDynamic()/endDynamic() from
#                      Action::perform and attach from the action level
#                      (count stays 0 bilaterally: setSymbolProperties
#                      returns false on this shape).
#   action_late_walk   MATCH — since COREACT-DYNSYM-STUB-0001's real
#                      body landed, both runtimes perform the late
#                      attach from the action level and report
#                      count=1/status=1 (Action::perform returns the
#                      accumulated count; the fixture drives the trait
#                      perform on the Rust side, mirroring the oracle
#                      driver).
#
# Expected diff budget: zero divergence lines (MB20 repin at the
# 19-branch merged tree 291c8321: the DYNMAPLATE + SETPROPSRET + COREACT2
# chain pieces landed and the action-level Rust drivers now go through
# Action::perform with real counts — rudra.stdout is byte-identical to
# ghidra.stdout, 63/63 records).  Anything else is drift and fails
# the gate.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_source_commit=291c83211de6aba4dcacb158051d3bc69c9facb9
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/copytrim_remat_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/copytrim_remat_1204.cc"
rust_fixture="$repo_root/tests/oracle/copytrim_remat_1204.rs"
runner="$repo_root/tools/run_copytrim_remat_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rudra-copytrim-remat-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-copytrim-remat-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
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
  "$rust_fixture" "$runner_sha" "$rudra_source_commit" \
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

# --- snapshot the pinned Rudra crate closure -------------------------------
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
] + base_source_files("src") + base_source_files("crates") \
  + base_source_files("benches")
crate_files = sorted(set(crate_files), key=lambda item: item.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-copytrim-remat-base-v1\0")
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
    pathlib.Path("tests/oracle/copytrim_remat_1204.cc"),
    pathlib.Path("tests/oracle/copytrim_remat_1204.rs"),
    pathlib.Path("tests/oracle/copytrim_remat_1204.metadata.json"),
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

metadata = json.loads(special["tests/oracle/copytrim_remat_1204.metadata.json"])
require("metadata schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "COPYTRIM-REMAT-0001")
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
    ("src/merge.rs", "base_merge_blob"),
    ("src/funcdata.rs", "base_funcdata_blob"),
    ("src/coreaction.rs", "base_coreaction_blob"),
    ("src/dynamic.rs", "base_dynamic_blob"),
    ("src/varmap.rs", "base_varmap_blob"),
    ("Cargo.toml", "cargo_toml_blob"),
    ("Cargo.lock", "cargo_lock_blob"),
):
    oid = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse",
         f"{rudra_source_commit}:{relative}"], text=True
    ).strip()
    require(f"source {key}", source[key], oid)

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha256(special["tests/oracle/copytrim_remat_1204.cc"]),
    "rust_fixture_sha256": sha256(special["tests/oracle/copytrim_remat_1204.rs"]),
    "runner_sha256": runner_sha,
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate hash scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-copytrim-remat-base-v1 plus base commit and sorted length-prefixed paths and contents",
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
    require(
        f"coverage.{key} fields",
        set(record),
        {"status", "covers", "residual_todo_ids", "pinned_divergence_kinds"},
    )
    if not isinstance(record["pinned_divergence_kinds"], list):
        raise SystemExit(f"coverage.{key}.pinned_divergence_kinds must be a list")
    if record["status"] not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status is invalid: {record['status']!r}")
    if record["status"] == "MATCH":
        require(f"coverage.{key} MATCH residuals", record["residual_todo_ids"], [])
        require(f"coverage.{key} MATCH divergence kinds", record["pinned_divergence_kinds"], [])
    elif not record["residual_todo_ids"]:
        raise SystemExit(f"coverage.{key} non-MATCH status lacks a residual TODO")
require("coverage.fold_relocate_fn.status", coverage["fold_relocate_fn"]["status"], "MATCH")

expected = metadata["expected_results"]
require("diff exit code", expected["diff_exit_code"], 0)
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
  "$oracle_tmp/workspace/tests/oracle/copytrim_remat_1204.cc" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/copytrim_remat_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  nice -n 10 cargo build --offline --locked --quiet \
  --manifest-path "$oracle_tmp/workspace/Cargo.toml" --lib
rustc --edition=2021 "$oracle_tmp/workspace/tests/oracle/copytrim_remat_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/copytrim_remat_1204_rust"

set +e
cd "$oracle_tmp/workspace"
"$oracle_tmp/copytrim_remat_1204_cpp" \
  sleigh_specs examples/curl \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/copytrim_remat_1204_rust" \
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

expected = metadata["expected_results"]
for key, name in (
    ("ghidra_stdout_sha256", "ghidra.stdout"),
    ("ghidra_stderr_sha256", "ghidra.stderr"),
    ("rudra_stdout_sha256", "rudra.stdout"),
    ("rudra_stderr_sha256", "rudra.stderr"),
):
    actual = hashlib.sha256((oracle_tmp / name).read_bytes()).hexdigest()
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", ghidra_status),
    ("rugra_exit_code", rudra_status),
    ("diff_exit_code", 0 if
        (oracle_tmp / "ghidra.stdout").read_bytes() == (oracle_tmp / "rudra.stdout").read_bytes()
        else 1),
):
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch")

ghidra_lines = (oracle_tmp / "ghidra.stdout").read_text().splitlines()
rudra_lines = (oracle_tmp / "rudra.stdout").read_text().splitlines()
if len(ghidra_lines) != expected["record_count"]:
    raise SystemExit(
        f"ghidra record count mismatch: {len(ghidra_lines)} != {expected['record_count']}")
if len(rudra_lines) != expected["record_count"]:
    raise SystemExit(
        f"rudra record count mismatch: {len(rudra_lines)} != {expected['record_count']}")

# Observation order must follow the manifest case order exactly.
expected_case_order = [case["id"] for case in metadata["input_manifest"]["cases"]]
def case_order(lines):
    seen = []
    for line in lines:
        if "case=" not in line:
            continue
        case = line.split("case=")[1].split("|")[0]
        if not seen or seen[-1] != case:
            seen.append(case)
    return seen
if case_order(ghidra_lines) != expected_case_order:
    raise SystemExit(f"ghidra case order drift: {case_order(ghidra_lines)}")
if case_order(rudra_lines) != expected_case_order:
    raise SystemExit(f"rudra case order drift: {case_order(rudra_lines)}")

# The divergence budget: every differing line pair must be one of the ten
# pinned divergence descriptors, and each must land in its case block.
diff_lines = [
    (g, r)
    for g, r in zip(ghidra_lines, rudra_lines)
    if g != r
]
if len(diff_lines) != expected["divergence_line_count"]:
    raise SystemExit(
        f"divergence budget exceeded: {len(diff_lines)} != "
        f"{expected['divergence_line_count']} (unexplained drift)")
import re
def descriptor(line):
    kind = line.split("|")[0]
    if kind == "mint":
        return "mint_hash"
    return kind
for g, r in diff_lines:
    if "case=" not in g or "case=" not in r:
        raise SystemExit(f"divergence outside a case block: {g!r} vs {r!r}")
    case = g.split("case=")[1].split("|")[0]
    if case != r.split("case=")[1].split("|")[0]:
        raise SystemExit(f"divergence case disagreement: {g!r} vs {r!r}")
    allowed = metadata["coverage"][case]["pinned_divergence_kinds"]
    if descriptor(g) not in allowed:
        raise SystemExit(
            f"unpinned divergence kind {descriptor(g)!r} in case {case}: {g!r} vs {r!r}")
if (oracle_tmp / "rudra.stderr").stat().st_size != 0:
    raise SystemExit("Rust fixture stderr must be empty")

print("record verdicts:")
for case in metadata["input_manifest"]["cases"]:
    record = metadata["coverage"][case["id"]]
    residuals = ",".join(record["residual_todo_ids"]) or "-"
    print(f"  {case['id']}: {record['status']} residuals={residuals}")
print("copytrim_remat_1204: candidate3_literal=EXCLUDED "
      "(fold_relocate_fn MATCH — oracle creates zero ops for dynamic-hash temps; "
      "trims are cover-driven only per trim_dynamic_high) "
      "projection=BILATERAL MATCH — 63/63 records byte-identical, 0 divergence "
      "lines [MB20 repin at the 19-branch merged tree: DYNMAPLATE + SETPROPSRET + "
      "COREACT2 chain pieces landed; action-level drivers run Action::perform on "
      "both sides with real counts]")
PY
