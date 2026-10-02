#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
ghidra_root="$repo_root/ghidra"
oracle_cpp_path=Ghidra/Features/Decompiler/src/decompile/cpp
metadata="$repo_root/tests/oracle/scope_category_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/scope_category_1204.cc"
rust_fixture="$repo_root/tests/oracle/scope_category_1204.rs"
runner="$repo_root/tools/run_scope_category_oracle.sh"
database_rs="$repo_root/src/database.rs"
database_doc="$repo_root/docs/api/database.md"

for required in "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$database_rs" "$database_doc"; do
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
    "$oracle_cpp_path/database.cc" "$oracle_cpp_path/database.hh")" ]]; then
  echo "locked database.cc/.hh worktree is dirty" >&2
  exit 1
fi

actual_base_commit=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_commit" != "$rudra_base_commit" || "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "pinned Rudra base commit/tree mismatch" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$database_rs" "$database_doc" "$repo_root" "$ghidra_root" \
  "$oracle_commit" "$oracle_tag" "$rudra_base_commit" "$rudra_base_tree" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_raw,
    cpp_raw,
    rust_raw,
    runner_raw,
    database_raw,
    doc_raw,
    repo_raw,
    ghidra_raw,
    oracle_commit,
    oracle_tag,
    base_commit,
    base_tree,
) = sys.argv[1:]

metadata_path = pathlib.Path(metadata_raw)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["fixture_id"] != "SCOPE-CAT0-0001":
    raise SystemExit("unexpected fixture id")
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata["compiler_spec"] != "N/A: category operations do not consult a compiler specification":
    raise SystemExit("unexpected compiler-spec metadata")
if metadata["observation"]["overall_status"] != "MATCH":
    raise SystemExit("scope category fixture must be MATCH")

input_bytes = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode("utf-8")
actual_fingerprint = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
if metadata["input_fingerprint"] != actual_fingerprint:
    raise SystemExit(f"input fingerprint mismatch: {actual_fingerprint}")

def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

comparand = metadata["comparand"]
expected_files = {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "runner_sha256": runner_raw,
    "database_rs_sha256": database_raw,
    "database_doc_sha256": doc_raw,
    "cargo_toml_sha256": pathlib.Path(repo_raw) / "Cargo.toml",
    "cargo_lock_sha256": pathlib.Path(repo_raw) / "Cargo.lock",
    "build_rs_sha256": pathlib.Path(repo_raw) / "build.rs",
}
for key, path in expected_files.items():
    actual = sha256(path)
    if comparand.get(key) != actual:
        raise SystemExit(f"comparand mismatch for {key}: {actual}")

if comparand.get("rugra_base_commit") != base_commit:
    raise SystemExit("metadata Rudra base commit mismatch")
if comparand.get("rugra_base_tree") != base_tree:
    raise SystemExit("metadata Rudra base tree mismatch")

ghidra_root = pathlib.Path(ghidra_raw)
for key, relative in (
    ("ghidra_database_cc_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.cc"),
    ("ghidra_database_hh_blob", "Ghidra/Features/Decompiler/src/decompile/cpp/database.hh"),
):
    actual = subprocess.check_output(
        ["git", "-C", str(ghidra_root), "rev-parse", f"{oracle_commit}:{relative}"],
        text=True,
    ).strip()
    if comparand.get(key) != actual:
        raise SystemExit(f"locked oracle blob mismatch for {relative}: {actual}")

host = {
    "host_cxx": subprocess.check_output(["g++", "--version"], text=True).splitlines()[0],
    "host_cxx_target": subprocess.check_output(["g++", "-dumpmachine"], text=True).strip(),
    "host_rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
    "host_platform": subprocess.check_output(["uname", "-srm"], text=True).strip(),
}
for key, actual in host.items():
    if comparand.get(key) != actual:
        raise SystemExit(f"host comparand mismatch for {key}: {actual}")
PY

oracle_tmp=$(mktemp -d /tmp/rudra-scope-category-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-scope-category-1204.??????) rm -rf -- "$oracle_tmp" ;;
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
g++ -std=c++11 -O2 -I"$cpp_snapshot" \
  "$cpp_fixture" "$cpp_snapshot/libdecomp.cc" "$cpp_snapshot/sleigh_arch.cc" \
  "$cpp_snapshot/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp_snapshot/libdecomp.a" -Wl,--no-whole-archive \
  -lz -o "$oracle_tmp/scope_category_ghidra"
"$oracle_tmp/scope_category_ghidra" >"$oracle_tmp/ghidra.stdout"

# Build the Rust comparand from a pinned repository snapshot plus exactly the
# leased database.rs.  This prevents unrelated concurrent workspace edits from
# entering the proof while still compiling the production module in its real
# crate dependency closure.
git -C "$repo_root" archive "$rudra_base_commit" | tar -x -C "$rudra_snapshot"
cp "$database_rs" "$rudra_snapshot/src/database.rs"
mkdir -p "$rudra_snapshot/src/bin"
cp "$rust_fixture" "$rudra_snapshot/src/bin/scope_category_1204.rs"
mkdir -p "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
cp -a "$cpp_snapshot" \
  "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_snapshot/Cargo.toml" \
  --bin scope_category_1204
"$oracle_tmp/cargo-target/debug/scope_category_1204" >"$oracle_tmp/rudra.stdout"

diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if metadata["expected_stdout_sha256"] != actual:
    raise SystemExit(f"oracle stdout hash mismatch: {actual}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'scope_category_1204: MATCH\n'
