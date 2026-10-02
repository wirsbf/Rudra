#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_language_tree=84265e1e6fe7ac9725367b57fb861253e4915984
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rugra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rugra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rugra_cargo_toml_blob=f3d9fa9d3ba45eb2f6f5b736c6cd581820c0f341
rugra_cargo_lock_blob=c1eef0a52f44f92d77b02f3e48b5d6781ec4bd94
rugra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
spec_input_commit=87aaef2262c85f4e6ffba488881fa4c1c8c2930f
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/flow_sharedreturn_process_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/flow_sharedreturn_process_1204.cc"
rust_fixture="$repo_root/tests/oracle/flow_sharedreturn_process_1204.rs"
program_metadata="$repo_root/tests/oracle/program_flow_metadata_1204.metadata.json"
ghidra_golden="$repo_root/tests/golden/ghidra_curl_1204.c"
compare_tool="$repo_root/tools/compare_ghidra.py"
runner="$repo_root/tools/run_flow_sharedreturn_process_oracle.sh"
cargo_lock=/tmp/rugra-cargo-build.lock
cargo_target=${RUDRA_FLOW_SHAREDRETURN_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-flow-sharedreturn-target}
cargo_tmp=${RUDRA_FLOW_SHAREDRETURN_TMP_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-flow-sharedreturn-tmp}
bfd_include=${RUDRA_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
bfd_library=${RUDRA_BFD_LIBRARY:-/tmp/rugra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}

overlay_paths=(
  examples/curl_decompile.rs
  src/coreaction.rs
  src/flow.rs
  src/fspec.rs
  src/funcdata.rs
  src/heritage.rs
  src/ruleaction.rs
  src/signature.rs
  src/unionresolve.rs
  src/varnode.rs
)

run_cache=${RUDRA_FLOW_SHAREDRETURN_RUN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-flow-sharedreturn-1204}
/usr/bin/mkdir -p "$run_cache" "$cargo_tmp"
oracle_tmp=$(mktemp -d "$run_cache/run.XXXXXX")
link_tmp=$(mktemp -d "$cargo_tmp/rust-fixture.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$run_cache"/run.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
  case "$link_tmp" in
    "$cargo_tmp"/rust-fixture.??????) rm -rf -- "$link_tmp" ;;
    *) echo "refusing unsafe cleanup target: $link_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$program_metadata" "$ghidra_golden" "$compare_tool" "$runner" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
for relative in "${overlay_paths[@]}"; do
  required="$repo_root/$relative"
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "source overlay is not a regular non-symlink file: $required" >&2
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
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --cached --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra source has staged changes" >&2
  exit 1
fi

if [[ "$(git -C "$repo_root" rev-parse "${rugra_base_commit}^{commit}")" != "$rugra_base_commit" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}^{tree}")" != "$rugra_base_tree" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:src")" != "$rugra_base_src_tree" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.toml")" != "$rugra_cargo_toml_blob" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:Cargo.lock")" != "$rugra_cargo_lock_blob" || \
      "$(git -C "$repo_root" rev-parse "${rugra_base_commit}:build.rs")" != "$rugra_build_rs_blob" ]]; then
  echo "pinned Rugra base identity mismatch" >&2
  exit 1
fi

snapshot_root="$oracle_tmp/workspace"
mkdir -p "$snapshot_root/tests/oracle" "$snapshot_root/tests/golden" \
  "$snapshot_root/tools" "$snapshot_root/examples" "$snapshot_root/sleigh_specs"
git -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-source.tar" "$rugra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  tests/oracle/program_flow_metadata_1204.metadata.json \
  tests/golden/ghidra_curl_1204.c tools/compare_ghidra.py \
  examples/curl src sleigh_shim crates
tar -xf "$oracle_tmp/rugra-source.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  cp "$repo_root/$relative" "$snapshot_root/$relative"
done
cp "$cpp_fixture" "$snapshot_root/tests/oracle/flow_sharedreturn_process_1204.cc"
cp "$rust_fixture" "$snapshot_root/tests/oracle/flow_sharedreturn_process_1204.rs"
cp "$metadata" "$snapshot_root/tests/oracle/flow_sharedreturn_process_1204.metadata.json"
cp "$runner" "$snapshot_root/tools/run_flow_sharedreturn_process_oracle.sh"
for asset in sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs; do
  git -C "$repo_root" cat-file blob "$spec_input_commit:$asset" \
    >"$snapshot_root/$asset"
done
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
ln -s "$ghidra_root" "$snapshot_root/ghidra"

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$repo_root" "$ghidra_root" "$snapshot_root" "$metadata" \
  "$cpp_fixture" "$rust_fixture" "$program_metadata" "$ghidra_golden" \
  "$compare_tool" "$runner_sha" "$oracle_commit" "$oracle_tag" \
  "$oracle_cpp_tree" "$oracle_language_tree" "$oracle_makefile_blob" \
  "$rugra_base_commit" "$rugra_base_tree" "$rugra_base_src_tree" \
  "$rugra_cargo_toml_blob" "$rugra_cargo_lock_blob" "$rugra_build_rs_blob" \
  "$spec_input_commit" "$bfd_include/bfd.h" "$bfd_library" \
  "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, ghidra_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw,
    program_metadata_raw, golden_raw, compare_raw, runner_sha, oracle_commit,
    oracle_tag, cpp_tree, language_tree, makefile_blob, base_commit,
    base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    spec_commit, bfd_header_raw, bfd_library_raw, *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw)
ghidra = pathlib.Path(ghidra_raw)
snapshot = pathlib.Path(snapshot_raw)
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()

def sha_file(file_name):
    return sha_bytes(pathlib.Path(file_name).read_bytes())

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "FLOW-SHAREDRETURN-0001")
require("projection status", metadata["projection_status"], "MISMATCH")
require("overall status", metadata["overall_status"], "MISMATCH: (B2 canonicalization)")
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler id", metadata["compiler_spec"]["id"], "gcc")
require(
    "decisive semantic classes",
    set(metadata["decisive_semantics"]),
    {
        "reference_output_parameters", "loop_bounds_traversal_order",
        "counter_accumulator_lifecycle", "sorting_comparison_keys",
    },
)
for key, value in metadata["decisive_semantics"].items():
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"decisive_semantics.{key} must be non-empty")

oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("language tree", oracle["x86_language_tree"], language_tree),
    ("makefile blob", oracle["decompiler_makefile_blob"], makefile_blob),
):
    require(label, actual, expected)
cpp_root = ghidra / "Ghidra/Features/Decompiler/src/decompile/cpp"
for source_name, expected in oracle["native_sources"].items():
    require(f"native source {source_name}", sha_file(cpp_root / source_name), expected)
for source_name, record in oracle["program_sources"].items():
    oid = subprocess.check_output(
        ["git", "-C", str(ghidra), "rev-parse", f"{oracle_commit}:{source_name}"],
        text=True,
    ).strip()
    require(f"program source oid {source_name}", oid, record["git_blob_oid"])
    data = subprocess.check_output(
        ["git", "-C", str(ghidra), "cat-file", "blob", oid]
    )
    require(f"program source sha {source_name}", sha_bytes(data), record["sha256"])

source = metadata["rugra_source"]
require("base commit", source["base_commit"], base_commit)
require(
    "base commit identity",
    subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{base_commit}^{{commit}}"], text=True
    ).strip(),
    base_commit,
)
require(
    "base tree",
    subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{base_commit}^{{tree}}"], text=True
    ).strip(),
    base_tree,
)
require("metadata base tree", source["base_tree"], base_tree)
require(
    "base src tree",
    subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{base_commit}:src"], text=True
    ).strip(),
    base_src_tree,
)
require("metadata base src tree", source["base_src_tree"], base_src_tree)
require("Cargo.toml blob", source["base_blobs"]["Cargo.toml"], cargo_toml_blob)
require("Cargo.lock blob", source["base_blobs"]["Cargo.lock"], cargo_lock_blob)
require("build.rs blob", source["base_blobs"]["build.rs"], build_rs_blob)
for source_name, expected in source["base_blobs"].items():
    actual = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{base_commit}:{source_name}"],
        text=True,
    ).strip()
    require(f"base blob {source_name}", actual, expected)
require(
    "overlay paths",
    set(source["overlays"]),
    set(overlay_paths),
)
for source_name, expected in source["overlays"].items():
    require(f"overlay {source_name}", sha_file(repo / source_name), expected)
    require(f"snapshot overlay {source_name}", sha_file(snapshot / source_name), expected)
build_link = source["snapshot_build_link"]
require("snapshot build link path", build_link["path"], "ghidra")
ghidra_link = snapshot / build_link["path"]
if not ghidra_link.is_symlink():
    raise SystemExit("snapshot ghidra build path is not a symlink")
require("snapshot ghidra link target", ghidra_link.resolve(), ghidra.resolve())

comparands = metadata["comparand_sha256"]
for key, file_name in (
    ("cpp_fixture", cpp_raw),
    ("rust_fixture", rust_raw),
    ("program_flow_metadata", program_metadata_raw),
    ("ghidra_curl_golden", golden_raw),
    ("compare_ghidra", compare_raw),
):
    require(key, sha_file(file_name), comparands[key])
require("runner", runner_sha, comparands["runner"])

binary = metadata["assets"]["binary"]
binary_oid = subprocess.check_output(
    ["git", "-C", str(repo), "rev-parse", binary["source_ref"]], text=True
).strip()
require("binary oid", binary_oid, binary["git_blob_oid"])
binary_data = subprocess.check_output(
    ["git", "-C", str(repo), "cat-file", "blob", binary_oid]
)
require("binary size", len(binary_data), binary["git_object_size"])
require("binary sha", sha_bytes(binary_data), binary["sha256"])
require("snapshot binary", sha_file(snapshot / "examples/curl"), binary["sha256"])

for asset_key in ("sla", "processor_spec", "compiler_spec", "language_definitions"):
    record = metadata["assets"][asset_key]
    require(f"{asset_key} source commit", record["source_repository_commit"], spec_commit)
    oid = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", f"{spec_commit}:{record['path']}"],
        text=True,
    ).strip()
    require(f"{asset_key} oid", oid, record["git_blob_oid"])
    data = (snapshot / record["path"]).read_bytes()
    require(f"{asset_key} sha", sha_bytes(data), record["sha256"])
    require(f"{asset_key} size", len(data), record["size"])
require("BFD header", sha_file(bfd_header_raw), metadata["assets"]["bfd"]["header_sha256"])
require("BFD library", sha_file(bfd_library_raw), metadata["assets"]["bfd"]["library_sha256"])

toolchain = metadata["host_toolchain"]
observed_tools = {
    "gxx": subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
    "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "objcopy": subprocess.check_output(["objcopy", "--version"], text=True).splitlines()[0],
    "readelf": subprocess.check_output(["readelf", "--version"], text=True).splitlines()[0],
    "make": subprocess.check_output(["make", "--version"], text=True).splitlines()[0],
}
require("host toolchain", observed_tools, toolchain)

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "host_toolchain": metadata["host_toolchain"],
    "binary": metadata["assets"]["binary"],
    "cases": manifest["cases"],
    "standalone_expected_records": manifest["standalone_expected_records"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input fingerprint", sha_bytes(canonical), manifest["sha256"])

coverage = metadata["coverage"]
valid_statuses = {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}
residual_union = set()
for key, record in coverage.items():
    require(f"coverage.{key} fields", set(record), {"status", "covers", "residual_todo_ids"})
    if record["status"] not in valid_statuses:
        raise SystemExit(f"coverage.{key}.status invalid")
    if not isinstance(record["covers"], str) or not record["covers"].strip():
        raise SystemExit(f"coverage.{key}.covers empty")
    residuals = record["residual_todo_ids"]
    if len(residuals) != len(set(residuals)):
        raise SystemExit(f"coverage.{key} duplicate residual")
    if record["status"] == "MATCH" and residuals:
        raise SystemExit(f"coverage.{key} MATCH has residual")
    if record["status"] != "MATCH" and not residuals:
        raise SystemExit(f"coverage.{key} non-MATCH lacks residual")
    residual_union.update(residuals)
require("residual union", residual_union, set(metadata["residual_todo_ids"]))
PY

if [[ ${RUDRA_FLOW_SHAREDRETURN_VALIDATE_ONLY:-0} == 1 ]]; then
  echo "flow_sharedreturn_process_1204 metadata/source lock validation passed"
  exit 0
fi

git -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O0 -fno-pie -no-pie -Wl,--build-id=none \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/flow_sharedreturn_process_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/flow_sharedreturn_ghidra"

/usr/bin/flock "$cargo_lock" env TMPDIR="$cargo_tmp" CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR="$cargo_target" cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib --example curl_decompile
TMPDIR="$cargo_tmp" rustc --edition=2021 -O \
  -L "dependency=$cargo_target/debug/deps" \
  --extern rugra="$cargo_target/debug/librugra.rlib" \
  "$snapshot_root/tests/oracle/flow_sharedreturn_process_1204.rs" \
  -o "$link_tmp/flow_sharedreturn_rugra"

objcopy --dump-section .text="$oracle_tmp/curl.text" "$snapshot_root/examples/curl"
curl_text_base=$(readelf -WS "$snapshot_root/examples/curl" | \
  awk '$2 == ".text" { print "0x" $4; exit }')
if [[ -z "$curl_text_base" ]]; then
  echo "failed to resolve curl .text base" >&2
  exit 1
fi

set +e
LD_LIBRARY_PATH="$(dirname "$bfd_library")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$oracle_tmp/flow_sharedreturn_ghidra" \
  "$snapshot_root/sleigh_specs" "$snapshot_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_exit=$?
"$link_tmp/flow_sharedreturn_rugra" "$oracle_tmp/curl.text" "$curl_text_base" \
  >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"
rugra_exit=$?
diff -u --label ghidra --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/raw.diff"
raw_diff_exit=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rugra.stdout" "$oracle_tmp/raw.diff" "$oracle_tmp/curl.text" \
  "$ghidra_exit" "$rugra_exit" "$raw_diff_exit" <<'PY'
import difflib
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
rugra = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
raw_diff = pathlib.Path(sys.argv[4]).read_bytes()

def sha(data):
    return hashlib.sha256(data).hexdigest()

expected = metadata["expected_results"]
observed = {
    "ghidra_stdout_sha256": sha(ghidra.encode()),
    "rugra_stdout_sha256": sha(rugra.encode()),
    "raw_diff_sha256": sha(raw_diff),
}
for key, actual in observed.items():
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")
for label, actual in (
    ("ghidra exit", int(sys.argv[6])),
    ("rugra exit", int(sys.argv[7])),
):
    if actual != 0:
        raise SystemExit(f"{label} nonzero: {actual}")
if int(sys.argv[8]) != expected["raw_diff_exit_code"]:
    raise SystemExit("raw diff exit mismatch")
curl_text_sha = sha(pathlib.Path(sys.argv[5]).read_bytes())
if curl_text_sha != metadata["machine_input_sha256"]["curl_text"]:
    raise SystemExit(f"curl .text mismatch: {curl_text_sha}")

normalized_diff = list(difflib.unified_diff(
    ghidra.splitlines(), rugra.splitlines()
))
normalized_exit = 1 if normalized_diff else 0
if normalized_exit != expected["normalized_diff_exit_code"]:
    raise SystemExit("unexpected normalized behavior difference")
# Exact callspec pointer identity now matches without normalization. The only
# +/- records must be RAM-space versus null-space case headers, one pair per
# lane; Address-space identity itself is never normalized.
changed = [
    line for line in normalized_diff
    if (line.startswith("+") or line.startswith("-"))
    and not line.startswith("+++") and not line.startswith("---")
]
if len(changed) != 6 or any(
    "site_space=ram" not in line and "site_space=null" not in line
    for line in changed
):
    raise SystemExit(f"unexpected post-callspec semantic diff: {changed}")
if sum("site_space=ram" in line for line in changed) != 3 or \
   sum("site_space=null" in line for line in changed) != 3:
    raise SystemExit("address-space mismatch projection is incomplete")
for label, output in (("Ghidra", ghidra), ("Rugra", rugra)):
    if output.count("callspec_binding=pointer_identity callspec_same_op=1") != 2:
        raise SystemExit(f"{label} callspec pointer identity observations missing")
    if "callspec_binding=address_lookup" in output:
        raise SystemExit(f"{label} retained obsolete address-only callspec evidence")
if ghidra.count("callspec_binding=none binding_resolves=0") != 1 or \
   rugra.count("callspec_binding=none binding_resolves=0") != 1:
    raise SystemExit("negative callspec representation mismatch")
case_order = [
    line.split("=", 1)[1].split()[0]
    for line in ghidra.splitlines() if line.startswith("case=")
]
if case_order != ["hugehelp", "progressbarinit", "myprogress"]:
    raise SystemExit(f"case order mismatch: {case_order}")
PY

curl_example="$cargo_target/debug/examples/curl_decompile"
(cd "$snapshot_root" && "$curl_example" --rugra-selected-function \
  hugehelp progressbarinit >"$oracle_tmp/enabled.c" 2>"$oracle_tmp/enabled.err")
(cd "$snapshot_root" && RUDRA_DISABLE_SHARED_RETURN=1 \
  "$curl_example" --rugra-selected-function hugehelp progressbarinit \
  >"$oracle_tmp/disabled.c" 2>"$oracle_tmp/disabled.err")
python3 "$snapshot_root/tools/compare_ghidra.py" "$oracle_tmp/enabled.c" \
  "$snapshot_root/tests/golden/ghidra_curl_1204.c" --func hugehelp -v \
  >"$oracle_tmp/compare_hugehelp.txt"
python3 "$snapshot_root/tools/compare_ghidra.py" "$oracle_tmp/enabled.c" \
  "$snapshot_root/tests/golden/ghidra_curl_1204.c" --func progressbarinit -v \
  >"$oracle_tmp/compare_progressbarinit.txt"

python3 -I -S - "$metadata" "$oracle_tmp/enabled.c" \
  "$oracle_tmp/enabled.err" "$oracle_tmp/disabled.c" \
  "$oracle_tmp/disabled.err" "$oracle_tmp/compare_hugehelp.txt" \
  "$oracle_tmp/compare_progressbarinit.txt" <<'PY'
import json
import pathlib
import re
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
enabled = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
enabled_err = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
disabled = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
disabled_err = pathlib.Path(sys.argv[5]).read_text(encoding="utf-8")
compare_outputs = [
    pathlib.Path(sys.argv[6]).read_text(encoding="utf-8"),
    pathlib.Path(sys.argv[7]).read_text(encoding="utf-8"),
]
expected = metadata["expected_results"]["e2e"]

def function_body(document, name):
    marker = re.search(rf"/\* ---- 0x[0-9a-f]+: {re.escape(name)} \([^\n]+\) ---- \*/", document)
    if marker is None:
        raise SystemExit(f"missing function section: {name}")
    tail = document[marker.end():]
    end = re.search(r"\n/\* ----|\n=== Summary:", tail)
    return tail[:end.start()] if end else tail

enabled_huge = function_body(enabled, "hugehelp")
disabled_huge = function_body(disabled, "hugehelp")
enabled_progress = function_body(enabled, "progressbarinit")
disabled_progress = function_body(disabled, "progressbarinit")
counts = {
    "enabled_hugehelp_puts": enabled_huge.count("puts("),
    "disabled_hugehelp_puts": disabled_huge.count("puts("),
    "enabled_progressbarinit_free": enabled_progress.count("free("),
    "disabled_progressbarinit_free": disabled_progress.count("free("),
}
for key, actual in counts.items():
    if actual != expected[key]:
        raise SystemExit(f"{key} mismatch: expected={expected[key]} actual={actual}")

record_pattern = re.compile(
    r"\[PREPASS\] flow override owner=0x([0-9a-f]+) site=0x([0-9a-f]+) type=callreturn"
)
records = [(f"0x{owner}", f"0x{site}") for owner, site in record_pattern.findall(enabled_err)]
expected_records = [tuple(record) for record in metadata["input_manifest"]["standalone_expected_records"]]
if records != expected_records or len(records) != expected["metadata_records"]:
    raise SystemExit(f"standalone metadata mismatch: {records}")
if "Shared Return Calls disabled for A/B" not in disabled_err:
    raise SystemExit("disabled A/B marker missing")

for name, enabled_count, disabled_count in (
    ("hugehelp", expected["enabled_hugehelp_callspecs"], expected["disabled_hugehelp_callspecs"]),
    ("progressbarinit", expected["enabled_progressbarinit_callspecs"], expected["disabled_progressbarinit_callspecs"]),
):
    enabled_match = re.search(rf"\[PREPASS\] {name} call specs: (\d+) callspecs", enabled_err)
    disabled_match = re.search(rf"\[PREPASS\] {name} call specs: (\d+) callspecs", disabled_err)
    if enabled_match is None or int(enabled_match.group(1)) != enabled_count:
        raise SystemExit(f"enabled callspec mismatch for {name}")
    if disabled_match is None or int(disabled_match.group(1)) != disabled_count:
        raise SystemExit(f"disabled callspec mismatch for {name}")
if "Function flow out of bounds: 0x4a4f flows to 0x2320" in enabled_err or \
   "Function flow out of bounds: 0x49e7 flows to 0x22f0" in enabled_err:
    raise SystemExit("enabled run retained shared-return OOB")
for warning in (
    "Function flow out of bounds: 0x4a4f flows to 0x2320",
    "Function flow out of bounds: 0x49e7 flows to 0x22f0",
):
    if warning not in disabled_err:
        raise SystemExit(f"disabled OOB evidence missing: {warning}")
for output in compare_outputs:
    if "Total Rugra defects: 0" not in output or \
       "Total Rugra numbering issues: 0" not in output:
        raise SystemExit("compare_ghidra defects/numbering regression")
print("flow_sharedreturn_process_1204: selected numeric/op and exact callspec identity projection MATCH; address-space MISMATCH (expected)")
print("flow_sharedreturn_process_1204: curl A/B puts 5->6, free 0->1; six metadata records")
PY

cat "$oracle_tmp/ghidra.stdout"
