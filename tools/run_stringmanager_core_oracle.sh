#!/usr/bin/env bash
set -euo pipefail

# STRINGMANAGER-CORE-JAVACONTRACT-0001 locked Ghidra 12.0.4/Rudra bilateral
# runner. The C++ side drives the REAL native StringManagerUnicode
# production object and a StringManager subclass implementing the DECLARED
# GhidraStringManager/Java contract over the real Ghidra primitives; the
# Rust side drives the Architecture-owned StringManager readers. The Java
# contract (detection unbounded, 2048-char return truncation + isTrunc) is
# declared here and in the metadata; it is NOT the native
# StringManagerUnicode 2048-byte search clamp, whose behavior is locked in
# parallel by the same fixture.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
baseline_commit=a800c80c487186be3f40e45e435fae852fc37a6e
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/stringmanager_core_1204.cc"
rust_fixture="$repo_root/tests/oracle/stringmanager_core_1204.rs"
metadata="$repo_root/tests/oracle/stringmanager_core_1204.metadata.json"
stringmanage_source="$repo_root/src/stringmanage.rs"
arch_source="$repo_root/src/arch.rs"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse 'Ghidra_12.0.4_build^{commit}')
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "expected locked Ghidra tag/HEAD $oracle_commit, found tag=$actual_tag_commit HEAD=$actual_commit" >&2
  exit 1
fi
git -C "$ghidra_root" diff --quiet "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.hh \
  Ghidra/Features/Decompiler/src/decompile/cpp/string_ghidra.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/architecture.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/architecture.hh \
  Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.hh \
  Ghidra/Features/Decompiler/src/decompile/cpp/crc32.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/crc32.hh \
  Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_arch.cc \
  Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_arch.cc
git -C "$repo_root" merge-base --is-ancestor "$baseline_commit" HEAD

python3 - "$metadata" "$cpp_fixture" "$rust_fixture" "$stringmanage_source" \
  "$arch_source" "$oracle_commit" "$baseline_commit" "$repo_root" \
  "$ghidra_root" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    rust_name,
    stringmanage_name,
    arch_name,
    oracle_commit,
    baseline_commit,
    repo_name,
    ghidra_name,
) = sys.argv[1:]
metadata_path = pathlib.Path(metadata_name)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
repo = pathlib.Path(repo_name)
ghidra = pathlib.Path(ghidra_name)

if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")
if metadata["rugra_baseline"]["commit"] != baseline_commit:
    raise SystemExit("metadata Rudra baseline does not match runner")

def git_rev_parse(directory: pathlib.Path, revision: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(directory), "rev-parse", revision], text=True
    ).strip()

oracle_revisions = {
    "decompiler_cpp_tree": "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp",
    "stringmanage_cc_blob": "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp/stringmanage.cc",
    "string_ghidra_cc_blob": "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp/string_ghidra.cc",
}
for key, revision in oracle_revisions.items():
    actual = git_rev_parse(ghidra, revision)
    if metadata["oracle"][key] != actual:
        raise SystemExit(f"oracle {key} mismatch: metadata={metadata['oracle'][key]} actual={actual}")

baseline_revisions = {
    "tree": f"{baseline_commit}^{{tree}}",
    "stringmanage_rs_blob": f"{baseline_commit}:src/stringmanage.rs",
    "arch_rs_blob": f"{baseline_commit}:src/arch.rs",
}
for key, revision in baseline_revisions.items():
    actual = git_rev_parse(repo, revision)
    if metadata["rugra_baseline"][key] != actual:
        raise SystemExit(f"baseline {key} mismatch: metadata={metadata['rudra_baseline'][key]} actual={actual}")

actual_fingerprint = "sha256:" + hashlib.sha256(metadata["input"].encode("utf-8")).hexdigest()
if metadata["input_fingerprint"] != actual_fingerprint:
    raise SystemExit(
        f"input fingerprint mismatch: metadata={metadata['input_fingerprint']} actual={actual_fingerprint}"
    )

for key, path in (
    ("cpp_fixture_sha256", pathlib.Path(cpp_name)),
    ("rust_fixture_sha256", pathlib.Path(rust_name)),
    ("stringmanage_rs_sha256", pathlib.Path(stringmanage_name)),
    ("arch_rs_sha256", pathlib.Path(arch_name)),
):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(f"{key} mismatch for {path.name}: metadata={metadata[key]} actual={actual}")

compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata["host_compiler"] != compiler:
    raise SystemExit(f"host compiler mismatch: metadata={metadata['host_compiler']} actual={compiler}")
if metadata["host_rustc"] != rustc:
    raise SystemExit(f"host rustc mismatch: metadata={metadata['host_rustc']} actual={rustc}")
PY

mkdir -p /home/wirs/.cache
oracle_tmp=$(mktemp -d /home/wirs/.cache/rudra-stringmanager-core.XXXXXX)
trap 'rm -rf "$oracle_tmp"' EXIT

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -w -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.a" -lz \
  -o "$oracle_tmp/stringmanager_core_1204"

# Only the Cargo subprocess holds the shared build lock. The oracle compiler,
# rustc fixture link, and repeatability/differential runs remain outside it.
fixture_target=${CARGO_TARGET_DIR:-/home/wirs/.cache/rudra-stringmanager-core-target}
flock /tmp/rudra-cargo-build.lock \
  env CARGO_TARGET_DIR="$fixture_target" CARGO_INCREMENTAL=0 \
  cargo build --quiet --lib --manifest-path "$repo_root/Cargo.toml"
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce $rudra_rlib" >&2
  exit 1
fi
TMPDIR="$oracle_tmp" rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/stringmanager_core_rudra"

"$oracle_tmp/stringmanager_core_1204" >"$oracle_tmp/ghidra.first"
"$oracle_tmp/stringmanager_core_1204" >"$oracle_tmp/ghidra.second"
"$oracle_tmp/stringmanager_core_rudra" >"$oracle_tmp/rudra.first"
"$oracle_tmp/stringmanager_core_rudra" >"$oracle_tmp/rudra.second"
diff -u "$oracle_tmp/ghidra.first" "$oracle_tmp/ghidra.second"
diff -u "$oracle_tmp/rudra.first" "$oracle_tmp/rudra.second"
diff -u "$oracle_tmp/ghidra.first" "$oracle_tmp/rudra.first"
cat "$oracle_tmp/ghidra.first"

python3 - "$metadata" "$oracle_tmp/ghidra.first" "$oracle_tmp/rudra.first" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for side, path, key in (
    ("ghidra", pathlib.Path(sys.argv[2]), "ghidra_expected_stdout_sha256"),
    ("rugra", pathlib.Path(sys.argv[3]), "rudra_expected_stdout_sha256"),
):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(f"{side} output hash mismatch: metadata={metadata[key]} actual={actual}")
    if metadata["expected_stdout_sha256"] != actual:
        raise SystemExit(
            f"shared output hash mismatch for {side}: "
            f"metadata={metadata['expected_stdout_sha256']} actual={actual}"
        )
PY
printf 'stringmanager_core_1204: MATCH (fixture); consumers remain D3 wiring (TYPEOP-LOCALTYPE-DISPATCH-0001 D3)\n'
