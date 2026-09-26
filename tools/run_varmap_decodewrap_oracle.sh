#!/usr/bin/env bash
set -euo pipefail

# Immutable runner for VARMAP-DECODEWRAP-0001 (handed over from
# MIGW1-DATABASE-0005 phase 3, ruling R5).  The Ghidra oracle, Rugra base
# commit, leased varmap.rs, both fixture sources, and the locked oracle
# blobs are all identity-checked before either comparand executes; the
# bilateral stdout must be byte-identical and match the registered hash.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
oracle_cpp_path=Ghidra/Features/Decompiler/src/decompile/cpp
metadata="$repo_root/tests/oracle/varmap_decodewrap_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/varmap_decodewrap_1204.cc"
rust_fixture="$repo_root/tests/oracle/varmap_decodewrap_1204.rs"
runner="$repo_root/tools/run_varmap_decodewrap_oracle.sh"
varmap_rs="$repo_root/src/varmap.rs"
varmap_doc="$repo_root/docs/api/varmap.md"
marshal_rs="$repo_root/src/marshal.rs"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$varmap_rs" "$varmap_doc" "$marshal_rs"; do
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
    "$oracle_cpp_path/varmap.cc" "$oracle_cpp_path/varmap.hh" \
    "$oracle_cpp_path/database.cc" "$oracle_cpp_path/database.hh" \
    "$oracle_cpp_path/marshal.cc" "$oracle_cpp_path/database.hh")" ]]; then
  echo "locked oracle source files are dirty" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$varmap_rs" "$varmap_doc" "$marshal_rs" "$repo_root" "$ghidra_root" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw, cpp_raw, rust_raw, runner_raw, varmap_raw,
    doc_raw, marshal_raw, repo_raw, ghidra_raw,
    oracle_commit, oracle_tag,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
if metadata["fixture_id"] != "VARMAP-DECODEWRAP-0001":
    raise SystemExit("unexpected fixture id")
if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle mismatch")
if metadata["observation"]["overall_status"] != "MATCH":
    raise SystemExit("decodewrap fixture must be MATCH")

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
    "varmap_rs_sha256": varmap_raw,
    "varmap_doc_sha256": doc_raw,
    "marshal_rs_sha256": marshal_raw,
    "cargo_toml_sha256": repo / "Cargo.toml",
    "cargo_lock_sha256": repo / "Cargo.lock",
}
for key, path in expected_files.items():
    actual = sha256(path)
    if comparand.get(key) != actual:
        raise SystemExit(f"comparand mismatch for {key}: {actual}")

ghidra_root = pathlib.Path(ghidra_raw)
for key, relative in (
    ("ghidra_varmap_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/varmap.cc"),
    ("ghidra_varmap_hh_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/varmap.hh"),
    ("ghidra_database_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.cc"),
    ("ghidra_database_hh_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.hh"),
    ("ghidra_marshal_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/marshal.cc"),
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
    raise SystemExit("pinned Rugra base commit/tree mismatch")
PY

oracle_tmp=$(mktemp -d /tmp/rugra-varmap-decodewrap-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-varmap-decodewrap-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

ghidra_snapshot="$oracle_tmp/ghidra"
rugra_snapshot="$oracle_tmp/rugra"
mkdir -p "$ghidra_snapshot" "$rugra_snapshot"
git -C "$ghidra_root" archive "$oracle_commit" "$oracle_cpp_path" | \
  tar -x -C "$ghidra_snapshot"
cpp_snapshot="$ghidra_snapshot/$oracle_cpp_path"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_snapshot" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$cpp_snapshot" \
  "$cpp_fixture" "$cpp_snapshot/libdecomp.cc" "$cpp_snapshot/sleigh_arch.cc" \
  "$cpp_snapshot/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp_snapshot/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/varmap_decodewrap_ghidra"

ghidra_status=0
"$oracle_tmp/varmap_decodewrap_ghidra" \
  > "$oracle_tmp/ghidra.stdout" 2> "$oracle_tmp/ghidra.stderr" \
  || ghidra_status=$?
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "ghidra comparand exited $ghidra_status or emitted diagnostics" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi

# Build the Rust comparand from the pinned base snapshot plus exactly the
# leased varmap.rs (which carries the decodeWrappingAttributes port) and
# the fixture as a crate bin, so the proof compiles the production module
# in its real dependency closure while excluding unrelated live edits.
git -C "$repo_root" archive "$(python3 -I -S -c \
  "import json,sys;print(json.load(open('$metadata'))['comparand']['rugra_base_commit'])")" \
  | tar -x -C "$rugra_snapshot"
cp "$varmap_rs" "$rugra_snapshot/src/varmap.rs"
cp "$marshal_rs" "$rugra_snapshot/src/marshal.rs"
mkdir -p "$rugra_snapshot/src/bin"
cp "$rust_fixture" "$rugra_snapshot/src/bin/varmap_decodewrap_1204.rs"
mkdir -p "$rugra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
cp -a "$cpp_snapshot" \
  "$rugra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet \
  --manifest-path "$rugra_snapshot/Cargo.toml" \
  --bin varmap_decodewrap_1204
rugra_status=0
"$oracle_tmp/cargo-target/debug/varmap_decodewrap_1204" \
  > "$oracle_tmp/rugra.stdout" 2> "$oracle_tmp/rugra.stderr" \
  || rugra_status=$?
if [[ "$rugra_status" -ne 0 || -s "$oracle_tmp/rugra.stderr" ]]; then
  echo "rugra comparand exited $rugra_status or emitted diagnostics" >&2
  cat "$oracle_tmp/rugra.stderr" >&2
  exit 1
fi

diff -u --label ghidra-12.0.4 --label rugra-pinned \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" <<'PY'
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

lines = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
if len(lines) != 13:
    raise SystemExit(f"expected thirteen fixture lines, found {len(lines)}")
if lines[0] != (
    "schema=1|fixture=VARMAP-DECODEWRAP-0001|"
    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
):
    raise SystemExit("fixture envelope mismatch")
expected_cases = [
    "decode_lock_true", "decode_lock_false", "decode_lock_one",
    "decode_lock_yes", "decode_lock_truecap",
    "decode_main_ram", "decode_main_other", "decode_main_unknown",
    "decode_main_missing", "decode_lock_missing", "reset_locked",
    "reset_unlocked",
]
actual_cases = [line.split("|", 1)[0].removeprefix("case=") for line in lines[1:]]
if actual_cases != expected_cases:
    raise SystemExit(f"fixture case order mismatch: {actual_cases}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'varmap_decodewrap_1204: covered_oracle=MATCH rugra=MATCH overall=MATCH\n'
