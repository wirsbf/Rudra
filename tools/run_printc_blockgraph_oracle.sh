#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/printc_blockgraph_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_blockgraph_1204.rs"
metadata="$repo_root/tests/oracle/printc_blockgraph_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi

oracle_files=(printc.cc printc.hh block.cc block.hh printlanguage.hh)
for oracle_file in "${oracle_files[@]}"; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root" "$cpp_root" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    repo_root_name,
    cpp_root_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
repo_root = pathlib.Path(repo_root_name)
cpp_root = pathlib.Path(cpp_root_name)

if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle tag/commit does not match runner")
if metadata["architecture"] != "language-independent PrintC structured BlockGraph":
    raise SystemExit("unexpected architecture metadata")
if metadata["compiler_spec"] != "none":
    raise SystemExit("unexpected compiler spec metadata")
if metadata["observation"]["covered_status"] != "MATCH":
    raise SystemExit("block-list traversal status must be MATCH")
if metadata["observation"]["overall_status"] != "MISMATCH":
    raise SystemExit("full docFunction fixture status must remain MISMATCH")

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

input_hash = "sha256:" + hashlib.sha256(metadata["input"].encode()).hexdigest()
if metadata["input_fingerprint"] != input_hash:
    raise SystemExit("input fingerprint mismatch")

fixture_hashes = {
    "cpp_fixture_sha256": pathlib.Path(cpp_fixture_name),
    "rust_fixture_sha256": pathlib.Path(rust_fixture_name),
}
for key, path in fixture_hashes.items():
    actual = digest(path)
    if metadata[key] != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata[key]} actual={actual}")

comparands = {
    "rugra_printc": repo_root / "src/printc.rs",
    "rugra_block": repo_root / "src/block.rs",
    "rugra_funcdata": repo_root / "src/funcdata.rs",
    "rugra_prettyprint": repo_root / "src/prettyprint.rs",
    "ghidra_printc_cc": cpp_root / "printc.cc",
    "ghidra_printc_hh": cpp_root / "printc.hh",
    "ghidra_block_cc": cpp_root / "block.cc",
    "ghidra_block_hh": cpp_root / "block.hh",
    "ghidra_printlanguage_hh": cpp_root / "printlanguage.hh",
}
for key, path in comparands.items():
    actual = digest(path)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(
            f"comparand mismatch for {key}: "
            f"metadata={metadata['comparand_sha256'].get(key)} actual={actual}"
        )

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata["host_compiler"] != compiler:
    raise SystemExit("host C++ compiler mismatch")
if metadata["host_rustc"] != rustc:
    raise SystemExit("host rustc mismatch")
PY

oracle_tmp=$(mktemp -d /tmp/rudra-printc-blockgraph-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-printc-blockgraph-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -I"$cpp_root" \
  "$oracle_tmp/fixture.cc" "$cpp_root/libdecomp.a" -lz \
  -o "$oracle_tmp/printc_blockgraph_1204"

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/printc_blockgraph_rudra"

"$oracle_tmp/printc_blockgraph_1204" >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/printc_blockgraph_rudra" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if metadata["expected_stdout_sha256"] != actual:
    raise SystemExit(
        "expected stdout mismatch: "
        f"metadata={metadata['expected_stdout_sha256']} actual={actual}"
    )
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'printc_blockgraph_1204: MATCH list-order/single-dispatch; overall=MISMATCH\n'
