#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_input_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_input_blob=4e26a362f92ac1961bab63000215a84b4d7212dd
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/rule_propcopy_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/rule_propcopy_1204.cc"
rust_fixture="$repo_root/tests/oracle/rule_propcopy_1204.rs"
runner="$repo_root/tools/run_rule_propcopy_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
# The fixture binary resolves libbfd-2.38-system.so through the runtime
# linker, so the deb-unpack lib directory must be on LD_LIBRARY_PATH.
export LD_LIBRARY_PATH="/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

oracle_tmp=$(mktemp -d /tmp/rudra-rule-propcopy-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-rule-propcopy-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$bfd_header" "$bfd_library"; do
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

resolved_input_commit=$(git -C "$repo_root" rev-parse "$rudra_input_commit^{commit}")
resolved_input_blob=$(git -C "$repo_root" rev-parse \
  "$rudra_input_commit:examples/curl")
input_blob_type=$(git -C "$repo_root" cat-file -t "$resolved_input_blob")
input_blob_size=$(git -C "$repo_root" cat-file -s "$resolved_input_blob")
if [[ "$resolved_input_commit" != "$rudra_input_commit" || \
      "$resolved_input_blob" != "$rudra_input_blob" || \
      "$input_blob_type" != blob ]]; then
  echo "pinned Rudra input Git object mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root" "$oracle_tmp/input"
oracle_binary="$oracle_tmp/input/curl"
git -C "$repo_root" cat-file blob "$rudra_input_blob" >"$oracle_binary"
runner_sha=$(sha256sum "$runner" | awk '{print $1}')

python3 -I -S - "$repo_root" "$snapshot_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner" "$runner_sha" "$oracle_binary" \
  "$input_blob_size" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_language_tree" "$oracle_makefile_blob" "$rudra_input_commit" \
  "$rudra_input_blob" "$bfd_header" "$bfd_library" <<'PY'
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

(
    repo_root_raw,
    snapshot_root_raw,
    metadata_raw,
    cpp_fixture_raw,
    rust_fixture_raw,
    runner_raw,
    runner_sha,
    binary_raw,
    binary_size,
    oracle_commit,
    oracle_tag,
    cpp_tree,
    language_tree,
    makefile_blob,
    input_commit,
    input_blob,
    bfd_header_raw,
    bfd_library_raw,
) = sys.argv[1:]

repo_root = pathlib.Path(repo_root_raw).resolve()
snapshot_root = pathlib.Path(snapshot_root_raw)
metadata_path = pathlib.Path(metadata_raw).resolve()
cpp_fixture_path = pathlib.Path(cpp_fixture_raw).resolve()
rust_fixture_path = pathlib.Path(rust_fixture_raw).resolve()
runner_path = pathlib.Path(runner_raw).resolve()
binary_path = pathlib.Path(binary_raw).resolve()

expected_paths = {
    metadata_path: repo_root / "tests/oracle/rule_propcopy_1204.metadata.json",
    cpp_fixture_path: repo_root / "tests/oracle/rule_propcopy_1204.cc",
    rust_fixture_path: repo_root / "tests/oracle/rule_propcopy_1204.rs",
    runner_path: repo_root / "tools/run_rule_propcopy_oracle.sh",
}
for actual, expected in expected_paths.items():
    if actual != expected.resolve():
        raise SystemExit(f"unexpected runner input path: {actual} != {expected}")

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(label, value):
    if isinstance(value, str) and (value == "PENDING" or value.startswith("PENDING_")):
        raise SystemExit(f"{label} is pending: {value}")

def source_files(directory):
    root = repo_root / directory
    result = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"crate snapshot rejects symlink: {path}")
        if path.is_file():
            result.append(path.relative_to(repo_root))
    return sorted(result, key=lambda value: value.as_posix())

def snapshot_file(relative):
    source = repo_root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"snapshot input must be a regular file: {relative}")
    data = source.read_bytes()
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return data

crate_files = [
    pathlib.Path("Cargo.toml"),
    pathlib.Path("Cargo.lock"),
    pathlib.Path("build.rs"),
    pathlib.Path("README.md"),
    pathlib.Path("benches/decompile_bench.rs"),
    pathlib.Path("tests/oracle/decompress_1204.rs"),
    pathlib.Path("tests/oracle/funcproto_lock_1204.rs"),
] + source_files("src") + source_files("sleigh_shim")
crate_files = sorted(set(crate_files), key=lambda value: value.as_posix())
crate_hasher = hashlib.sha256()
crate_hasher.update(b"rudra-rule-propcopy-lib-snapshot-v1\0")
crate_bytes = {}
for relative in crate_files:
    data = snapshot_file(relative)
    key = relative.as_posix()
    crate_bytes[key] = data
    encoded = key.encode("utf-8")
    crate_hasher.update(len(encoded).to_bytes(8, "big"))
    crate_hasher.update(encoded)
    crate_hasher.update(len(data).to_bytes(8, "big"))
    crate_hasher.update(data)

special_paths = [
    pathlib.Path("tests/oracle/rule_propcopy_1204.cc"),
    pathlib.Path("tests/oracle/rule_propcopy_1204.rs"),
    pathlib.Path("tests/oracle/rule_propcopy_1204.metadata.json"),
    pathlib.Path("tools/run_rule_propcopy_oracle.sh"),
]
special = {path.as_posix(): snapshot_file(path) for path in special_paths}
require(
    "runner snapshot/live copy",
    sha256(special["tools/run_rule_propcopy_oracle.sh"]),
    runner_sha,
)

binary = binary_path.read_bytes()
(snapshot_root / "examples").mkdir()
(snapshot_root / "examples/curl").write_bytes(binary)

metadata = json.loads(special["tests/oracle/rule_propcopy_1204.metadata.json"])
require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "RULE-PROPCOPY-BOOKKEEP-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle language tree", oracle["x86_language_tree"], language_tree)
require("oracle Makefile blob", oracle["decompiler_makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")

assets = metadata["assets"]
asset_paths = {
    "sla": "sleigh_specs/x86-64.sla",
    "processor_spec": "sleigh_specs/x86-64.pspec",
    "compiler_spec": "sleigh_specs/x86-64-gcc.cspec",
    "language_definitions": "sleigh_specs/x86.ldefs",
}
for key, relative in asset_paths.items():
    require(f"{key} path", assets[key]["path"], relative)
    require(f"{key} source commit", assets[key]["source_repository_commit"], input_commit)
    require(f"{key} source ref", assets[key]["source_ref"], f"{input_commit}:{relative}")
    resolved_blob = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", f"{input_commit}:{relative}"],
        text=True,
    ).strip()
    require(f"{key} Git blob", resolved_blob, assets[key]["git_blob_oid"])
    blob_type = subprocess.check_output(
        ["git", "-C", str(repo_root), "cat-file", "-t", resolved_blob],
        text=True,
    ).strip()
    require(f"{key} Git object type", blob_type, "blob")
    data = subprocess.check_output(
        ["git", "-C", str(repo_root), "cat-file", "blob", resolved_blob]
    )
    require(f"{key} size", len(data), assets[key]["size"])
    require(f"{key} sha256", sha256(data), assets[key]["sha256"])
    destination = snapshot_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    special[relative] = data
require(
    "compiler spec path binding",
    metadata["compiler_spec"]["path"],
    assets["compiler_spec"]["path"],
)
require(
    "compiler spec sha256 binding",
    metadata["compiler_spec"]["sha256"],
    assets["compiler_spec"]["sha256"],
)
require("binary source commit", assets["binary"]["source_repository_commit"], input_commit)
require("binary Git blob", assets["binary"]["git_blob_oid"], input_blob)
require("binary source ref", assets["binary"]["source_ref"], f"{input_commit}:examples/curl")
require("binary path", assets["binary"]["path"], "examples/curl")
require("binary size", len(binary), int(binary_size))
require("binary metadata size", len(binary), assets["binary"]["size"])
require("binary sha256", sha256(binary), assets["binary"]["sha256"])
require("BFD header sha256", sha256(pathlib.Path(bfd_header_raw).read_bytes()), assets["bfd"]["header_sha256"])
require("BFD library sha256", sha256(pathlib.Path(bfd_library_raw).read_bytes()), assets["bfd"]["library_sha256"])

host_tools = metadata["host_tools"]
require(
    "host compiler",
    subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
    host_tools["g++"],
)
require(
    "host rustc",
    subprocess.check_output(["rustc", "--version"], text=True).strip(),
    host_tools["rustc"],
)
require(
    "host cargo",
    subprocess.check_output(["cargo", "--version"], text=True).strip(),
    host_tools["cargo"],
)

known_dependencies = metadata["known_dependencies"]
for dependency, status in (
    ("OPBANK-0001", "MISMATCH"),
    ("TYPE-UNKNOWN-0001", "UNTESTED"),
    ("ARCH-0001", "MISMATCH"),
):
    require(
        f"known dependency {dependency}",
        known_dependencies[dependency]["status"],
        status,
    )
    if not known_dependencies[dependency]["detail"]:
        raise SystemExit(f"known dependency {dependency} has no detail")

comparand = metadata["comparand"]
observed = {
    "cpp_fixture_sha256": sha256(special["tests/oracle/rule_propcopy_1204.cc"]),
    "rust_fixture_sha256": sha256(special["tests/oracle/rule_propcopy_1204.rs"]),
    "runner_sha256": runner_sha,
    "rust_crate_tree_sha256": crate_hasher.hexdigest(),
}
require(
    "crate hash scheme",
    comparand["rust_crate_tree_hash_scheme"],
    "sha256 of rudra-rule-propcopy-lib-snapshot-v1 plus sorted length-prefixed relative paths and contents",
)
for key, actual in observed.items():
    reject_pending(f"comparand.{key}", comparand[key])
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
reject_pending("input_manifest.sha256", manifest["sha256"])
require("input manifest sha256", sha256(canonical), manifest["sha256"])
reject_pending("expected_stdout_sha256", metadata["expected_stdout_sha256"])
require("expected exit code", metadata["expected_exit_code"], 0)
require(
    "overall status",
    metadata["overall_status"],
    "PARTIAL_MATCH: eleven target-relevant structural projections match; full-state input/output remains MISMATCH through OPBANK-0001 and ARCH-0001, TYPE-UNKNOWN-0001 and explicitly listed branches remain UNTESTED",
)
for key in (
    "reader_propagate_slot0",
    "slot_scan_unwritten_const",
    "slot_scan_noncopy_def",
    "free_input_guard",
    "return_copy_guard",
    "marker_constant_guard",
    "marker_addrtied_merge_guard",
    "marker_addrforce_guard",
    "multi_reader_bookkeeping",
    "constant_dedup_bookkeeping",
    "self_defined_throw",
):
    require(
        f"coverage.{key}",
        metadata["coverage"][key],
        "TARGET_STRUCTURAL_MATCH",
    )
PY

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
mkdir -p "$oracle_tmp/source"
git -C "$ghidra_root" archive --format=tar --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
tar -xf "$oracle_archive" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$oracle_cpp" "$snapshot_decompiler/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/rule_propcopy_1204.cc" \
  "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" \
  "$oracle_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/rule_propcopy_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 "$snapshot_root/tests/oracle/rule_propcopy_1204.rs" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/rule_propcopy_1204_rust"

"$oracle_tmp/rule_propcopy_1204_cpp" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/rule_propcopy_1204_rust" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$snapshot_root/tests/oracle/rule_propcopy_1204.metadata.json" \
  "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if actual != metadata["expected_stdout_sha256"]:
    raise SystemExit(
        f"oracle stdout hash mismatch: expected={metadata['expected_stdout_sha256']} actual={actual}"
    )
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'rule_propcopy_1204: PARTIAL_MATCH target_structural_cases=11 records=23 dependencies=OPBANK-0001,ARCH-0001 untested=TYPE-UNKNOWN-0001\n'
