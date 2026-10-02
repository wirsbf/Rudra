#!/usr/bin/env bash
# Immutable RULE-MULTICOLLAPSE-ABORT-0001 oracle runner (cover_rebuild mode).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source
# archive, rebuilds the Rugra crate from the pinned base commit plus the
# ruleaction.rs overlay, compiles both fixtures, runs them, and classifies
# every output record.  Records must be byte-identical except the two
# documented classes:
#   1. func_eq_skiplist_def_preserved/after: Ghidra dead ops retain NULL
#      input-slot cardinality, Rugra's Vec cannot (OPBANK-0001).
#   2. const_pair_distinct_objects/after: the locked oracle dereferences
#      null at ruleaction.cc:3306 and dies with SIGSEGV (observed in a
#      forked child); Rugra completes the absolute-constant collapse.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rugra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/rule_multi_collapse_abort_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/rule_multi_collapse_abort_1204.cc"
rust_fixture="$repo_root/tests/oracle/rule_multi_collapse_abort_1204.rs"
overlay_rs="$repo_root/src/ruleaction.rs"
doc_md="$repo_root/docs/api/ruleaction.md"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

oracle_tmp=$(mktemp -d /tmp/rugra-rule-multi-collapse-abort-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-rule-multi-collapse-abort-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$overlay_rs" \
  "$doc_md" "$bfd_header" "$bfd_library"; do
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

resolved_base_commit=$(git -C "$repo_root" rev-parse "$rugra_base_commit^{commit}")
resolved_base_tree=$(git -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
if [[ "$resolved_base_commit" != "$rugra_base_commit" || \
      "$resolved_base_tree" != "$rugra_base_tree" ]]; then
  echo "pinned Rugra base commit/tree mismatch" >&2
  exit 1
fi

runner_sha=$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')

python3 -I -S - "$repo_root" "$oracle_tmp" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$overlay_rs" "$doc_md" "$runner_sha" "$rugra_base_commit" \
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
    overlay_rs_raw,
    doc_md_raw,
    runner_sha,
    rugra_base_commit,
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
         rugra_base_commit, "--", directory],
        text=True,
    ).splitlines()
    return [pathlib.Path(line) for line in listing if line]

def base_file(relative):
    return git_blob(f"{rugra_base_commit}:{relative.as_posix()}")

def live_file(relative):
    source = repo_root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular non-symlink file: {relative}")
    return source.read_bytes()

overlay_files = {
    pathlib.Path("src/ruleaction.rs"),
}
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
crate_hasher.update(b"rugra-rule-multi-collapse-abort-base-overlay-v1\0")
crate_hasher.update(rugra_base_commit.encode())
for relative in crate_files:
    data = live_file(relative) if relative in overlay_files else base_file(relative)
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    encoded = relative.as_posix().encode()
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_paths = [
    pathlib.Path("tests/oracle/rule_multi_collapse_abort_1204.cc"),
    pathlib.Path("tests/oracle/rule_multi_collapse_abort_1204.rs"),
    pathlib.Path("tests/oracle/rule_multi_collapse_abort_1204.metadata.json"),
    pathlib.Path("docs/api/ruleaction.md"),
]
special = {}
for relative in special_paths:
    data = live_file(relative)
    destination = snapshot / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    special[relative.as_posix()] = data

metadata = json.loads(special["tests/oracle/rule_multi_collapse_abort_1204.metadata.json"])
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "RULE-MULTICOLLAPSE-ABORT-0001")
oracle = metadata["oracle"]
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("base commit", metadata["rugra_base_commit"], rugra_base_commit)

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha256(special["tests/oracle/rule_multi_collapse_abort_1204.cc"]),
    "rust_fixture_sha256": sha256(special["tests/oracle/rule_multi_collapse_abort_1204.rs"]),
    "runner_sha256": runner_sha,
    "doc_sha256": sha256(special["docs/api/ruleaction.md"]),
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate hash scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rugra-rule-multi-collapse-abort-base-overlay-v1 plus base commit and sorted length-prefixed paths and contents",
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

binary_spec = f"{rugra_base_commit}:examples/curl"
binary = git_blob(binary_spec)
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    data = git_blob(f"{rugra_base_commit}:{relative}")
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
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$oracle_tmp/workspace/tests/oracle/rule_multi_collapse_abort_1204.cc" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/rule_multi_collapse_abort_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$oracle_tmp/workspace/Cargo.toml" --lib
rustc --edition=2021 "$oracle_tmp/workspace/tests/oracle/rule_multi_collapse_abort_1204.rs" \
  --extern rugra="$oracle_tmp/cargo-target/debug/librugra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/rule_multi_collapse_abort_1204_rust"

set +e
cd "$oracle_tmp/workspace"
"$oracle_tmp/rule_multi_collapse_abort_1204_cpp" \
  sleigh_specs examples/curl \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/rule_multi_collapse_abort_1204_rust" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_status=$?
cd - >/dev/null
set -e

python3 -I -S - "$oracle_tmp" "$metadata" "$ghidra_status" "$rugra_status" <<'PY'
import json
import pathlib
import sys

oracle_tmp = pathlib.Path(sys.argv[1])
metadata = json.loads(pathlib.Path(sys.argv[2]).read_bytes())
ghidra_status = int(sys.argv[3])
rugra_status = int(sys.argv[4])

ghidra_lines = (oracle_tmp / "ghidra.stdout").read_text().splitlines()
rugra_lines = (oracle_tmp / "rugra.stdout").read_text().splitlines()

def record(line):
    fields = {}
    for part in line.split("|"):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    return fields

if len(ghidra_lines) != len(rugra_lines):
    raise SystemExit(
        f"record count differs: ghidra={len(ghidra_lines)} rugra={len(rugra_lines)}"
    )

expected_records = []
for case in metadata["input_manifest"]["cases"]:
    expected_records.append((case["id"], "before"))
    expected_records.append((case["id"], "after"))

verdicts = []
for index, (ghidra_line, rust_line) in enumerate(zip(ghidra_lines, rugra_lines)):
    ghidra_record = record(ghidra_line)
    rust_record = record(rust_line)
    expected_case, expected_stage = expected_records[index]
    for side, rec in (("ghidra", ghidra_record), ("rugra", rust_record)):
        if rec.get("case") != expected_case or rec.get("stage") != expected_stage:
            raise SystemExit(
                f"record {index} {side} drift: {rec.get('case')}/{rec.get('stage')} "
                f"expected {expected_case}/{expected_stage}"
            )
    if ghidra_line == rust_line:
        verdicts.append((expected_case, expected_stage, "MATCH", ""))
        continue
    if expected_case == "const_pair_distinct_objects" and expected_stage == "after":
        if "result=SIGSEGV" not in ghidra_line:
            raise SystemExit(
                "oracle crash record drifted (expected SIGSEGV observation): "
                + ghidra_line
            )
        if "result=1" not in rust_line:
            raise SystemExit("rugra const-pair collapse did not complete: " + rust_line)
        verdicts.append((
            expected_case, expected_stage,
            "ORACLE_CRASH_VS_RUDRA_COLLAPSE",
            "oracle null-def deref ruleaction.cc:3306; rugra absolute-constant collapse",
        ))
        continue
    if expected_case == "func_eq_skiplist_def_preserved" and expected_stage == "after":
        import re
        mask = re.compile(r"(nested|root)\{opc=60[^}]*\}")
        if mask.sub("MASK", ghidra_line) != mask.sub("MASK", rust_line):
            raise SystemExit(
                "func_eq after-record differs beyond dead-op null-slot cardinality"
            )
        verdicts.append((
            expected_case, expected_stage,
            "MATCH_MASKED_OPBANK_0001",
            "only Ghidra dead-op NULL input-slot cardinality differs",
        ))
        continue
    raise SystemExit(
        f"unexpected record difference at {expected_case}/{expected_stage}:\n"
        f"ghidra: {ghidra_line[:400]}\nrugra:  {rust_line[:400]}"
    )

ghidra_stderr = (oracle_tmp / "ghidra.stderr").read_text()
rugra_stderr = (oracle_tmp / "rugra.stderr").read_text()
if ghidra_status != 0:
    raise SystemExit(f"ghidra fixture exited {ghidra_status} (SIGSEGV must be contained in the forked child)")
if rugra_status != 0:
    raise SystemExit(f"rugra fixture exited {rugra_status}")
if rugra_stderr.strip():
    raise SystemExit("rugra fixture stderr is not empty")

print("record verdicts:")
for case_id, stage, verdict, note in verdicts:
    print(f"  {case_id}/{stage}: {verdict}" + (f" ({note})" if note else ""))
overall = metadata["overall_status"]
print(f"overall_status={overall} (metadata-declared; crash-case keeps this below MATCH)")
PY
