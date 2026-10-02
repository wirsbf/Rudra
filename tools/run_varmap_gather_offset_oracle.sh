#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/varmap_gather_offset_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/varmap_gather_offset_1204.cc"
rust_fixture="$repo_root/tests/oracle/varmap_gather_offset_1204.rs"
runner="$repo_root/tools/run_varmap_gather_offset_oracle.sh"
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d

oracle_tmp=$(mktemp -d /tmp/rudra-varmap-gather-offset-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-varmap-gather-offset-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# Build the Rust comparand from an immutable repository snapshot with only the
# reviewed varmap candidate overlaid.  Concurrent worktree writers therefore
# cannot enter the fixture's crate closure.
rudra_workspace="$oracle_tmp/rudra-workspace"
mkdir -p "$rudra_workspace"
git -C "$repo_root" archive "$rudra_base_commit" -- \
  Cargo.toml Cargo.lock build.rs README.md src sleigh_shim benches \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  | tar -x -C "$rudra_workspace"
cp "$repo_root/src/varmap.rs" "$rudra_workspace/src/varmap.rs"
mkdir -p "$rudra_workspace/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -x -C "$rudra_workspace/ghidra"
snapshot_cpp_root="$rudra_workspace/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/varmap.rs" "$repo_root/docs/api/varmap.md" "$runner" \
  "$ghidra_root" "$rudra_workspace" "$oracle_commit" "$oracle_tag" \
  "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

metadata_path, cpp_path, rust_path, source_path, docs_path, runner_path, ghidra_root, workspace = map(
    pathlib.Path, sys.argv[1:9]
)
oracle_commit, oracle_tag, rudra_base_commit = sys.argv[9:12]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if not metadata.get("architecture") or not metadata.get("compiler_spec"):
    raise SystemExit("metadata architecture/compiler spec missing")
if not metadata.get("analysis_options"):
    raise SystemExit("metadata analysis options missing")
if metadata.get("rugra_base_commit") != rudra_base_commit:
    raise SystemExit("metadata Rudra base commit mismatch")
expected_tree = metadata["comparand_sha256"]["ghidra_cpp_tree"]
actual_tree = subprocess.check_output(
    ["git", "-C", str(ghidra_root), "rev-parse", "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp"],
    text=True,
).strip()
if actual_tree != expected_tree:
    raise SystemExit(f"locked Ghidra cpp tree mismatch: metadata={expected_tree} actual={actual_tree}")
paths = {
    "cpp_fixture": cpp_path,
    "rust_fixture": rust_path,
    "rugra_varmap_source": source_path,
    "api_document": docs_path,
    "runner": runner_path,
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand_sha256"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: metadata={expected} actual={actual}")
build_paths = [
    pathlib.Path(name)
    for name in (
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "README.md",
        "tests/oracle/decompress_1204.rs",
        "tests/oracle/funcproto_lock_1204.rs",
    )
]
for directory in ("src", "sleigh_shim", "benches"):
    build_paths.extend(
        path.relative_to(workspace)
        for path in sorted((workspace / directory).rglob("*"))
        if path.is_file()
    )
build_hash = hashlib.sha256()
for relative in sorted(build_paths, key=lambda path: path.as_posix()):
    encoded_path = relative.as_posix().encode()
    data = (workspace / relative).read_bytes()
    build_hash.update(len(encoded_path).to_bytes(8, "big"))
    build_hash.update(encoded_path)
    build_hash.update(len(data).to_bytes(8, "big"))
    build_hash.update(data)
actual_build_hash = build_hash.hexdigest()
expected_build_hash = metadata["comparand_sha256"]["rugra_build_inputs"]
if actual_build_hash != expected_build_hash:
    raise SystemExit(
        f"Rudra build-input tree mismatch: metadata={expected_build_hash} actual={actual_build_hash}"
    )
if len(build_paths) != metadata["rugra_build_input_files"]:
    raise SystemExit("Rudra build-input file-count mismatch")
actual_lock = hashlib.sha256((workspace / "Cargo.lock").read_bytes()).hexdigest()
if actual_lock != metadata["comparand_sha256"]["cargo_lock"]:
    raise SystemExit("Cargo.lock fingerprint mismatch")
input_payload = json.dumps(
    {"sequence": metadata["input"]["sequence"], "state": metadata["input"]["state"]},
    separators=(",", ":"),
    sort_keys=True,
    ensure_ascii=False,
).encode()
actual_input = "sha256:" + hashlib.sha256(input_payload).hexdigest()
if metadata["input"]["fingerprint"] != actual_input:
    raise SystemExit(
        f"input fingerprint mismatch: metadata={metadata['input']['fingerprint']} actual={actual_input}"
    )
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$snapshot_cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$snapshot_cpp_root" "$cpp_fixture" \
  "$snapshot_cpp_root/libdecomp.a" -lz -o "$oracle_tmp/varmap_gather_offset_1204_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --offline --locked --quiet --manifest-path "$rudra_workspace/Cargo.toml" --lib
rustc --edition=2021 "$rust_fixture" \
  --extern rudra="$oracle_tmp/cargo-target/debug/librudra.rlib" \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  -o "$oracle_tmp/varmap_gather_offset_1204_rust"

"$oracle_tmp/varmap_gather_offset_1204_cpp" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/varmap_gather_offset_1204_rust" >"$oracle_tmp/rudra.stdout"
test -s "$oracle_tmp/ghidra.stdout"
test -s "$oracle_tmp/rudra.stdout"
test "$(wc -l < "$oracle_tmp/ghidra.stdout")" -eq 9
test "$(wc -l < "$oracle_tmp/rudra.stdout")" -eq 9
grep -Fxq 'copy8_all_bits|result=0xfedcba9876543210' "$oracle_tmp/ghidra.stdout"
grep -Fxq 'add8_wrap|result=0x25' "$oracle_tmp/ghidra.stdout"
grep -Fxq 'add7_mask|result=0x25' "$oracle_tmp/ghidra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
expected = metadata["expected_stdout_sha256"]
if actual != expected:
    raise SystemExit(f"oracle stdout hash mismatch: metadata={expected} actual={actual}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'varmap_gather_offset_1204: MATCH\n'
