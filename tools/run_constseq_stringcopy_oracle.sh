#!/usr/bin/env bash
# run_constseq_stringcopy_oracle.sh — CONSTSEQ-STRINGCOPY-1204 bilateral
# fixture runner (WORKPKG-UNMAP-STRFOLD-0006): drives the real
# RuleStringCopy::applyOp / StringSequence analysis chain on both the locked
# Ghidra 12.0.4 oracle and the pinned Rudra snapshot, and requires
# byte-identical stdout (double-run determinism on both sides).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ghidra_root="$repo_root/ghidra"

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
oracle_constseq_blob=b5e31405ebb8ffc4550abacc9456313752c59d74
rudra_pinned_commit=3665702f81826a4d966932fd753553df4fad39fc
rudra_pinned_tree=a49d5080c624c80f4742b9f9f75437b54394fc54
rudra_pinned_src_tree=5ffc174b4a45365538e2226c5894d6929c725ea2
rudra_constseq_blob=2192287225c508221092b8581b4698f0dc3eec15
rudra_cargo_toml_blob=205ab6c1e1c057d7ed3c04a3df2c927cf6603890
rudra_cargo_lock_blob=dcb52f7bca56892266b532c30994bb5147a37f58
spec_input_commit="$rudra_pinned_commit"

metadata="$repo_root/tests/oracle/constseq_stringcopy_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/constseq_stringcopy_1204.cc"
rust_fixture="$repo_root/tests/oracle/constseq_stringcopy_1204.rs"
doc_constseq="$repo_root/docs/api/constseq.md"
runner="$repo_root/tools/run_constseq_stringcopy_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_header="$bfd_include/bfd.h"
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

cache_root=${RUDRA_CONSTSEQ_STRINGCOPY_CACHE_ROOT:-/dev/shm/rudra-tests/strfold/runner}
mkdir -p "$cache_root"
oracle_tmp=$(mktemp -d "$cache_root/run.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$cache_root"/run.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$doc_constseq" \
  "$runner" "$bfd_header" "$bfd_library" \
  sleigh_specs/x86-64.sla sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86.ldefs examples/curl; do
  path="$required"
  [[ $required != /* ]] && path="$repo_root/$required"
  if [[ ! -f "$path" ]]; then
    echo "required input is missing: $path" >&2
    exit 1
  fi
done

# ---------- oracle identity ----------
actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
actual_constseq_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/constseq.cc")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" || \
      "$actual_constseq_blob" != "$oracle_constseq_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# ---------- rudra pinned-commit identity ----------
for binding in \
  "$rudra_pinned_commit^{commit}:$rudra_pinned_commit" \
  "$rudra_pinned_commit^{tree}:$rudra_pinned_tree" \
  "$rudra_pinned_commit:src:$rudra_pinned_src_tree" \
  "$rudra_pinned_commit:src/constseq.rs:$rudra_constseq_blob" \
  "$rudra_pinned_commit:Cargo.toml:$rudra_cargo_toml_blob" \
  "$rudra_pinned_commit:Cargo.lock:$rudra_cargo_lock_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra identity mismatch: $expression" >&2
    exit 1
  fi
done

# ---------- metadata + comparand shas ----------
python3 -I -S - "$repo_root" "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$doc_constseq" "$runner" "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_constseq_blob" "$rudra_pinned_commit" "$rudra_constseq_blob" <<'PY'
import hashlib, json, pathlib, sys

(repo_raw, metadata_raw, cpp_raw, rust_raw, doc_raw, runner_raw, oracle_commit,
 oracle_tag, cpp_tree, constseq_blob, rudra_commit, rudra_constseq_blob) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: metadata={expected!r} actual={actual!r}")

require("schema", metadata["schema_version"], 2)
require("fixture", metadata["fixture_id"], "CONSTSEQ-STRINGCOPY-1204")
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle cpp tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle constseq blob", metadata["oracle"]["constseq_cc_blob"], constseq_blob)
require("rudra commit", metadata["rugra_source"]["base_commit"], rudra_commit)
require("rudra constseq blob", metadata["rugra_source"]["base_constseq_blob"], rudra_constseq_blob)
decisive = metadata.get("decisive_semantics")
expected_classes = {
    "reference_output_parameters", "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle", "sorting_comparison_keys",
}
if not isinstance(decisive, dict) or set(decisive) != expected_classes:
    raise SystemExit("decisive_semantics must cover exactly the four classes")
import subprocess
repo_path = pathlib.Path(repo_raw)
doc_path = pathlib.Path(doc_raw)
comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_raw)),
    ("rust_fixture_sha256", pathlib.Path(rust_raw)),
    ("constseq_rs_sha256", repo_path / "src" / "constseq.rs"),
    ("api_document_sha256", doc_path),
    ("runner_sha256", pathlib.Path(runner_raw)),
):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    require(key, actual, comparand[key])
pinned_constseq = subprocess.check_output(
    ["git", "-C", repo_raw, "cat-file", "blob", rudra_constseq_blob])
require(
    "overlay equals pinned constseq blob",
    hashlib.sha256(pinned_constseq).hexdigest(),
    comparand["constseq_rs_sha256"],
)
PY

# ---------- oracle build + fixture compile ----------
git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra-cpp.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/source"
tar -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_cpp/libdecomp.a" \
  "$bfd_library" -lz -o "$oracle_tmp/constseq_cpp"

# ---------- rudra snapshot build (pinned commit) ----------
snapshot_root="$oracle_tmp/snapshot"
mkdir -p "$snapshot_root"
git -C "$repo_root" archive --format=tar --output="$oracle_tmp/rudra.tar" \
  "$rudra_pinned_commit"
tar -xf "$oracle_tmp/rudra.tar" -C "$snapshot_root"
CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 "$snapshot_root/tests/oracle/constseq_stringcopy_1204.rs" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/constseq_rust"

# ---------- run + compare ----------
set +e
"$oracle_tmp/constseq_cpp" "$repo_root/sleigh_specs" "$repo_root/examples/curl" \
  >"$oracle_tmp/ghidra.first" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/constseq_cpp" "$repo_root/sleigh_specs" "$repo_root/examples/curl" \
  >"$oracle_tmp/ghidra.second" 2>/dev/null
"$oracle_tmp/constseq_rust" >"$oracle_tmp/rudra.first" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
"$oracle_tmp/constseq_rust" >"$oracle_tmp/rudra.second" 2>/dev/null
diff -u --label ghidra.first --label ghidra.second \
  "$oracle_tmp/ghidra.first" "$oracle_tmp/ghidra.second" >"$oracle_tmp/det1.diff"
det1=$?
diff -u --label rudra.first --label rudra.second \
  "$oracle_tmp/rudra.first" "$oracle_tmp/rudra.second" >"$oracle_tmp/det2.diff"
det2=$?
diff -u --label ghidra --label rudra \
  "$oracle_tmp/ghidra.first" "$oracle_tmp/rudra.first" >"$oracle_tmp/raw.diff"
diff_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.first" "$oracle_tmp/rudra.first" \
  "$ghidra_status" "$rudra_status" "$det1" "$det2" "$diff_status" <<'PY'
import hashlib, json, pathlib, sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
ghidra_status, rudra_status, det1, det2, diff_status = map(int, sys.argv[4:9])
if ghidra_status != 0:
    raise SystemExit(f"oracle fixture exited {ghidra_status}")
if rudra_status != 0:
    raise SystemExit(f"rudra fixture exited {rudra_status}")
if det1 != 0:
    raise SystemExit("oracle double-run is not deterministic")
if det2 != 0:
    raise SystemExit("rudra double-run is not deterministic")
if diff_status != 0:
    raise SystemExit("bilateral stdout differs (see raw.diff)")
for side, data, key in (
    ("ghidra", ghidra, "ghidra_expected_stdout_sha256"),
    ("rugra", rudra, "rudra_expected_stdout_sha256"),
):
    actual = hashlib.sha256(data).hexdigest()
    if metadata["comparand"][key] != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata['comparand'][key]} actual={actual}")
print("constseq_stringcopy_1204: MATCH")
PY
