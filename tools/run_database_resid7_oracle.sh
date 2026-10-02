#!/usr/bin/env bash
set -euo pipefail

# Immutable runner for DATABASE-RESID7-FIXTURE-0001 (MIGW1-DATABASE-0005
# phase 3, residual-seven closure lane wt/database7).  The Ghidra oracle,
# Rudra base commit, leased database.rs, both fixture sources, spec
# assets, the pinned curl blob, and the BFD closure are all
# identity-checked before either comparand executes; the bilateral stdout
# must be byte-identical and match the registered hash.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
oracle_cpp_path=Ghidra/Features/Decompiler/src/decompile/cpp
metadata="$repo_root/tests/oracle/database_resid7_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/database_resid7_1204.cc"
rust_fixture="$repo_root/tests/oracle/database_resid7_1204.rs"
runner="$repo_root/tools/run_database_resid7_oracle.sh"
database_rs="$repo_root/src/database.rs"
database_doc="$repo_root/docs/api/database.md"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$database_rs" "$database_doc" "$bfd_include/bfd.h" "$bfd_library" \
  "$repo_root/sleigh_specs/x86-64.sla" "$repo_root/sleigh_specs/x86-64.pspec" \
  "$repo_root/sleigh_specs/x86-64-gcc.cspec" "$repo_root/sleigh_specs/x86.ldefs"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra HEAD/tag mismatch: HEAD=$actual_commit tag=$actual_tag_commit" >&2
  exit 1
fi
if [[ -n "$(git -C "$ghidra_root" status --porcelain -- \
    "$oracle_cpp_path/database.cc" "$oracle_cpp_path/database.hh" \
    "$oracle_cpp_path/rangemap.hh" "$oracle_cpp_path/space.cc" \
    "$oracle_cpp_path/sleigh_arch.cc" "$oracle_cpp_path/type.cc" \
    "$oracle_cpp_path/ghidra_arch.cc")" ]]; then
  echo "locked oracle source files are dirty" >&2
  exit 1
fi
if [[ -n "$(git -C "$repo_root" status --porcelain -- sleigh_specs examples/curl)" ]]; then
  echo "spec assets or the curl example are dirty in the worktree" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$database_rs" "$database_doc" "$repo_root" "$ghidra_root" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, cpp_raw, rust_raw, runner_raw, database_raw,
    doc_raw, repo_raw, ghidra_raw, oracle_commit, oracle_tag,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
if metadata["fixture_id"] != "DATABASE-RESID7-FIXTURE-0001":
    raise SystemExit("unexpected fixture id")
if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle mismatch")
if metadata["observation"]["overall_status"] != "MATCH":
    raise SystemExit("resid7 fixture must be MATCH")

input_bytes = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
actual_fingerprint = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
if metadata["input_fingerprint"] != actual_fingerprint:
    raise SystemExit(f"input fingerprint mismatch: {actual_fingerprint}")

def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

repo = pathlib.Path(repo_raw)
comparand = metadata["comparand"]
expected_files = {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "runner_sha256": runner_raw,
    "database_rs_sha256": database_raw,
    "database_doc_sha256": doc_raw,
    "cargo_toml_sha256": repo / "Cargo.toml",
    "cargo_lock_sha256": repo / "Cargo.lock",
}
for key, path in expected_files.items():
    actual = sha256(path)
    if comparand.get(key) != actual:
        raise SystemExit(f"comparand mismatch for {key}: {actual}")

ghidra_root = pathlib.Path(ghidra_raw)
for key, relative in (
    ("ghidra_database_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.cc"),
    ("ghidra_database_hh_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.hh"),
    ("ghidra_rangemap_hh_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/rangemap.hh"),
    ("ghidra_space_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/space.cc"),
    ("ghidra_sleigh_arch_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.cc"),
    ("ghidra_type_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/type.cc"),
    ("ghidra_ghidra_arch_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc"),
):
    actual = subprocess.check_output(
        ["git", "-C", str(ghidra_root), "rev-parse", f"{oracle_commit}:{relative}"],
        text=True,
    ).strip()
    if comparand.get(key) != actual:
        raise SystemExit(f"locked oracle blob mismatch for {relative}: {actual}")

base_commit = comparand["rugra_base_commit"]
base_tree = comparand["rugra_base_tree"]
actual_base_commit = subprocess.check_output(
    ["git", "-C", repo_raw, "rev-parse", f"{base_commit}^{{commit}}"], text=True
).strip()
actual_base_tree = subprocess.check_output(
    ["git", "-C", repo_raw, "rev-parse", f"{base_commit}^{{tree}}"], text=True
).strip()
if actual_base_commit != base_commit or actual_base_tree != base_tree:
    raise SystemExit("pinned Rudra base commit/tree mismatch")

assets = metadata["assets"]
for key, relative in (
    ("sla", "sleigh_specs/x86-64.sla"),
    ("processor_spec", "sleigh_specs/x86-64.pspec"),
    ("compiler_spec", "sleigh_specs/x86-64-gcc.cspec"),
    ("language_definitions", "sleigh_specs/x86.ldefs"),
):
    if assets[key]["sha256"] != sha256(repo / relative):
        raise SystemExit(f"asset hash mismatch for {relative}")

binary = assets["binary"]
blob = subprocess.check_output(
    ["git", "-C", repo_raw, "rev-parse", f"{binary['source_repository_commit']}:examples/curl"],
    text=True,
).strip()
if blob != binary["git_blob_oid"]:
    raise SystemExit("pinned curl blob identity mismatch")

bfd = assets["bfd"]
if bfd["header_sha256"] != sha256(bfd["include_path"] + "/bfd.h"):
    raise SystemExit("BFD header hash mismatch")
if bfd["library_sha256"] != sha256(bfd["library_path"]):
    raise SystemExit("BFD library hash mismatch")
PY

oracle_tmp=$(mktemp -d /tmp/rudra-database-resid7-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-database-resid7-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

ghidra_snapshot="$oracle_tmp/ghidra"
rudra_snapshot="$oracle_tmp/rudra"
mkdir -p "$ghidra_snapshot" "$rudra_snapshot"
git -C "$ghidra_root" archive "$oracle_commit" "$oracle_cpp_path" | \
  tar -x -C "$ghidra_snapshot"
cpp_snapshot="$ghidra_snapshot/$oracle_cpp_path"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_snapshot" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -Wno-exceptions -m64 \
  -I"$bfd_include" -I"$cpp_snapshot" \
  "$cpp_fixture" "$cpp_snapshot/libdecomp.cc" "$cpp_snapshot/sleigh_arch.cc" \
  "$cpp_snapshot/inject_sleigh.cc" "$cpp_snapshot/bfd_arch.cc" \
  "$cpp_snapshot/loadimage_bfd.cc" "$cpp_snapshot/libdecomp.a" \
  "$bfd_library" -lz \
  -o "$oracle_tmp/database_resid7_ghidra"

# Materialize the pinned curl blob (never the working-tree file).
git -C "$repo_root" cat-file blob "$(git -C "$repo_root" rev-parse \
  34a3febff160031c265cfbd841a94022c68c2c19:examples/curl)" \
  > "$oracle_tmp/curl"
mkdir -p "$oracle_tmp/sleigh_specs"
for asset in x86-64.sla x86-64.pspec x86-64-gcc.cspec x86.ldefs; do
  cp "$repo_root/sleigh_specs/$asset" "$oracle_tmp/sleigh_specs/$asset"
done
ghidra_status=0
"$oracle_tmp/database_resid7_ghidra" \
  "$oracle_tmp/sleigh_specs" "$oracle_tmp/curl" \
  > "$oracle_tmp/ghidra.stdout" 2> "$oracle_tmp/ghidra.stderr" \
  || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 ]]; then
  echo "ghidra comparand exited $ghidra_status" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

# Build the Rust comparand from the pinned base snapshot plus exactly the
# leased database.rs (which carries all MIGW1-DATABASE-0005 phases) and
# the fixture as a crate bin, so the proof compiles the production module
# in its real dependency closure while excluding unrelated live edits.
git -C "$repo_root" archive "$(python3 -I -S -c \
  "import json,sys;print(json.load(open('$metadata'))['comparand']['rudra_base_commit'])")" \
  | tar -x -C "$rudra_snapshot"
cp "$database_rs" "$rudra_snapshot/src/database.rs"
mkdir -p "$rudra_snapshot/src/bin"
cp "$rust_fixture" "$rudra_snapshot/src/bin/database_resid7_1204.rs"
mkdir -p "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
cp -a "$cpp_snapshot" \
  "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet \
  --manifest-path "$rudra_snapshot/Cargo.toml" \
  --bin database_resid7_1204
rudra_status=0
"$oracle_tmp/cargo-target/debug/database_resid7_1204" \
  > "$oracle_tmp/rudra.stdout" 2> "$oracle_tmp/rudra.stderr" \
  || rudra_status=$?
if [[ "$rudra_status" -ne 0 ]]; then
  echo "rudra comparand exited $rudra_status" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

diff -u --label ghidra-12.0.4 --label rudra-pinned \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for label, path in (
    ("expected_stdout_sha256", sys.argv[2]),
    ("expected_stdout_sha256", sys.argv[3]),
):
    actual = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    if metadata[label] != actual:
        raise SystemExit(f"{label} mismatch for {path}: {actual}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'database_resid7_1204: covered_oracle=MATCH rudra=MATCH overall=MATCH\n'
