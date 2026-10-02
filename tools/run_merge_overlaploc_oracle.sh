#!/usr/bin/env bash
set -euo pipefail

# MERGE-OVERLAPLOC-FLAGUNION-1204: locked 12.0.4 bilateral runner.  Pins the
# overlapLoc flag-gate semantics of Merge::mergeAddrTied:
#   (1) varnode.cc:1791-1819 — overlapLoc's uint4 return is the union of the
#       HEAD varnode's flags of each visited exact-location run (:1798 initial
#       read + :1813 one OR per later run head); same-location later members
#       are never read (the endLoc(size,addr,written) jump at :1800/:1815
#       skips them), and
#   (2) merge.cc:629-643 — mergeAddrTied gates the forced cluster merge on
#       (flags & Varnode::addrtied) of that head union.
# The positive case proves a raw run-1 head + addrtied run-2 head merge
# (a+b share one 2-instance HighVariable, c separate); the negative case
# proves an addrtied NON-head same-location member alone does NOT gate
# (no merge at all).  Asserts both sides byte-identical.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_base_src_tree=2f252f03a1542c5e3aee261b4000b9614541390e
rudra_base_merge_blob=87bda740fb72f42c070fdef4fb32d34a8bd55ada

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/merge_overlaploc_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/merge_overlaploc_1204.cc"
rust_fixture="$repo_root/tests/oracle/merge_overlaploc_1204.rs"
runner="$repo_root/tools/run_merge_overlaploc_oracle.sh"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_base_commit^{commit}:$rudra_base_commit" \
  "$rudra_base_commit^{tree}:$rudra_base_tree" \
  "$rudra_base_commit:src:$rudra_base_src_tree" \
  "$rudra_base_commit:src/merge.rs:$rudra_base_merge_blob"; do
  expression=${binding%:*}
  expected=${binding##*:}
  actual=$(git -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra base identity mismatch: $expression" >&2
    exit 1
  fi
done

runner_sha=$(sha256sum "$runner" | awk '{print $1}')
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/merge.rs" "$runner_sha" <<'PY'
import hashlib
import json
import pathlib
import sys

(metadata_raw, cpp_raw, rust_raw, merge_raw, runner_sha) = sys.argv[1:]

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

data = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
require("fixture", data["fixture_id"], "MERGE-OVERLAPLOC-FLAGUNION-1204")
require("overall", data["overall_status"], "UNTESTED: (B2 downgrade: two-sided output pinning incomplete; original claim was pre-B2 match prose)")
comparand = data["comparand"]
for key, path in (
    ("cpp_fixture_sha256", cpp_raw),
    ("rust_fixture_sha256", rust_raw),
    ("candidate_merge_rs_sha256", merge_raw),
):
    require(key, sha(path), comparand[key])
require("runner sha", runner_sha, data["expected_runner_sha256"])

fingerprinted = {
    "architecture": data["architecture"],
    "compiler_spec": data["compiler_spec"],
    "analysis_options": data["analysis_options"],
    "inputs": data["input_manifest"]["inputs"],
}
canonical = json.dumps(
    fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
require("input manifest sha", hashlib.sha256(canonical).hexdigest(),
        data["input_manifest"]["sha256"])
PY

oracle_tmp=$(mktemp -d /tmp/rudra-merge-overlaploc-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-merge-overlaploc-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Recreate both codebases from immutable Git objects. Only the leased
# candidate src/merge.rs is overlaid on the pinned Rudra base.
snapshot="$oracle_tmp/workspace"
mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
git -C "$repo_root" archive --format=tar --output="$oracle_tmp/rudra.tar" \
  "$rudra_base_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs src sleigh_shim crates
tar -xf "$oracle_tmp/rudra.tar" -C "$snapshot"
cp "$repo_root/src/merge.rs" "$snapshot/src/merge.rs"
cp "$rust_fixture" "$snapshot/tests/oracle/merge_overlaploc_1204.rs"

git -C "$ghidra_root" archive --format=tar --output="$oracle_tmp/ghidra.tar" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
mkdir -p "$oracle_tmp/oracle"
tar -xf "$oracle_tmp/ghidra.tar" -C "$oracle_tmp/oracle"
oracle_cpp="$oracle_tmp/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"
ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/merge_overlaploc_cpp"

flock /tmp/rudra-cargo-build.lock -c \
  "CARGO_TARGET_DIR='$oracle_tmp/cargo-target' cargo build --offline --locked --quiet --manifest-path '$snapshot/Cargo.toml' --lib"
rustc --edition=2021 -O \
  -L dependency="$oracle_tmp/cargo-target/debug/deps" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$snapshot/tests/oracle/merge_overlaploc_1204.rs" \
  -o "$oracle_tmp/merge_overlaploc_rust"

set +e
"$oracle_tmp/merge_overlaploc_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/merge_overlaploc_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
set -e

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" "$ghidra_status" "$rudra_status" \
  "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" <<'PY'
import hashlib
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
rudra_stdout = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
ghidra_status = int(sys.argv[4])
rudra_status = int(sys.argv[5])
ghidra_stderr = pathlib.Path(sys.argv[6]).read_text(encoding="utf-8")
rudra_stderr = pathlib.Path(sys.argv[7]).read_text(encoding="utf-8")

if ghidra_status != 0 or rudra_status != 0:
    raise SystemExit(
        f"fixture exit codes must be 0: ghidra={ghidra_status} rudra={rudra_status}"
    )
if ghidra_stderr or rudra_stderr:
    raise SystemExit("fixture stderr must be empty")

def line_sha(text):
    return hashlib.sha256(text.encode()).hexdigest()

expected = data["expected_stdout"]
if line_sha(ghidra_stdout) != expected["ghidra_stdout_sha256"]:
    raise SystemExit("ghidra stdout hash mismatch")
if line_sha(rudra_stdout) != expected["rudra_stdout_sha256"]:
    raise SystemExit("rudra stdout hash mismatch")

glines = ghidra_stdout.splitlines()
rlines = rudra_stdout.splitlines()
if len(glines) != expected["lines_per_side"]:
    raise SystemExit("stdout line-count mismatch")
for index, (gl, rl) in enumerate(zip(glines, rlines)):
    if gl != rl:
        raise SystemExit(f"divergence on line {index + 1}: {gl!r} vs {rl!r}")

text = rudra_stdout
required = (
    "case=cross_run_head_union|post|vns=[a:in=0,wr=1,ex=1,im=0,at=0,hi=2,"
    "b:in=0,wr=1,ex=1,im=0,at=1,hi=2,c:in=0,wr=1,ex=1,im=0,at=1,hi=1]",
    "same=a~b=1;a~c=0;b~c=0",
    "case=same_loc_later_member_no_gate|post|vns=[a:in=0,wr=1,ex=1,im=0,at=0,hi=1,"
    "b:in=0,wr=1,ex=1,im=0,at=1,hi=1]|same=a~b=0",
    "case=cross_run_head_union|verdict=PIPELINE-OK",
    "case=same_loc_later_member_no_gate|verdict=PIPELINE-OK",
)
for token in required:
    if token not in text:
        raise SystemExit(f"missing decisive observation: {token}")
print("merge_overlaploc_1204: decisive_projection=MATCH "
      "registered_mismatch=0 overall=MATCH")
PY
