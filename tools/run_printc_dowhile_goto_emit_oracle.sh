#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/printc_dowhile_goto_emit_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_dowhile_goto_emit_1204.rs"
metadata="$repo_root/tests/oracle/printc_dowhile_goto_emit_1204.metadata.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi

oracle_files=(printc.cc printc.hh block.cc block.hh prettyprint.cc prettyprint.hh)
for oracle_file in "${oracle_files[@]}"; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/printc.rs" "$repo_root/src/prettyprint.rs" "$cpp_root" \
  "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    rust_printc_name,
    rust_prettyprint_name,
    cpp_root_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata_path = pathlib.Path(metadata_name)
cpp_fixture_path = pathlib.Path(cpp_fixture_name)
rust_fixture_path = pathlib.Path(rust_fixture_name)
cpp_root = pathlib.Path(cpp_root_name)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle tag/commit does not match runner")
if metadata["observation"]["overall_status"] != "MATCH":
    raise SystemExit("dowhile/goto emit fixture must stay MATCH on both layers")

def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

input_hash = "sha256:" + hashlib.sha256(metadata["input"].encode()).hexdigest()
if metadata["input_fingerprint"] != input_hash:
    raise SystemExit("input fingerprint mismatch")

expected = {
    "cpp_fixture_sha256": digest(cpp_fixture_path),
    "rust_fixture_sha256": digest(rust_fixture_path),
}
for key, actual in expected.items():
    if metadata[key] != actual:
        raise SystemExit(f"{key} mismatch: metadata={metadata[key]} actual={actual}")

comparands = {
    "rugra_printc": pathlib.Path(rust_printc_name),
    "rugra_prettyprint": pathlib.Path(rust_prettyprint_name),
    "ghidra_printc_cc": cpp_root / "printc.cc",
    "ghidra_printc_hh": cpp_root / "printc.hh",
    "ghidra_block_cc": cpp_root / "block.cc",
    "ghidra_block_hh": cpp_root / "block.hh",
    "ghidra_prettyprint_cc": cpp_root / "prettyprint.cc",
    "ghidra_prettyprint_hh": cpp_root / "prettyprint.hh",
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
if metadata["host"]["cxx"] != compiler:
    raise SystemExit("host C++ compiler mismatch")
if metadata["host"]["rustc"] != rustc:
    raise SystemExit("host rustc mismatch")
PY

# Stage under /home/wirs/.cache (persistent NVMe) rather than /tmp: the
# fixture links the full debug librudra plus its dependency rlibs, and the
# shared /tmp tmpfs (heavily used by concurrent agent worktrees) can SIGBUS
# the linker when it runs out of space mid-write.
stage_root=/home/wirs/.cache
mkdir -p "$stage_root"
oracle_tmp=$(mktemp -d "$stage_root/rudra-printc-dowhile-goto-emit-1204.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$stage_root"/rudra-printc-dowhile-goto-emit-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -I"$cpp_root" \
  "$oracle_tmp/fixture.cc" "$cpp_root/libdecomp.a" -lz \
  -o "$oracle_tmp/printc_dowhile_goto_emit_1204"

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
  -o "$oracle_tmp/printc_dowhile_goto_emit_rudra"

"$oracle_tmp/printc_dowhile_goto_emit_1204" >"$oracle_tmp/ghidra.statement"
"$oracle_tmp/printc_dowhile_goto_emit_rudra" >"$oracle_tmp/rudra.statement"
diff -u "$oracle_tmp/ghidra.statement" "$oracle_tmp/rudra.statement"

"$oracle_tmp/printc_dowhile_goto_emit_1204" --raw >"$oracle_tmp/ghidra.raw"
"$oracle_tmp/printc_dowhile_goto_emit_rudra" --raw >"$oracle_tmp/rudra.raw"
if ! cmp -s "$oracle_tmp/ghidra.raw" "$oracle_tmp/rudra.raw"; then
  echo "raw PrintC dowhile/goto output mismatch; both layers must MATCH" >&2
  diff -u "$oracle_tmp/ghidra.raw" "$oracle_tmp/rudra.raw" >&2 || true
  exit 1
fi

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.statement" \
  "$oracle_tmp/ghidra.raw" "$oracle_tmp/rudra.raw" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
observed = {
    "expected_statement_stdout_sha256": pathlib.Path(sys.argv[2]),
    "expected_ghidra_raw_sha256": pathlib.Path(sys.argv[3]),
    "expected_rudra_raw_sha256": pathlib.Path(sys.argv[4]),
}
for key, path in observed.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata[key]} actual={actual}"
        )
PY

cat "$oracle_tmp/ghidra.statement"
printf 'printc_dowhile_goto_emit_1204: MATCH statement bytes; MATCH raw bytes; overall=MATCH\n'
