#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/pipeline_lifecycle_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/pipeline_lifecycle_1204.cc"
rust_fixture="$repo_root/tests/oracle/pipeline_lifecycle_1204.rs"
binary="$repo_root/examples/curl"
spec_root="$repo_root/sleigh_specs"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp \
    Ghidra/Processors/x86/data/languages; then
  echo "locked Ghidra decompiler/x86 language source is dirty" >&2
  exit 1
fi

bfd_include=${RUDRA_BFD_INCLUDE:-}
if [[ -z "$bfd_include" && -f /usr/include/bfd.h ]]; then
  bfd_include=/usr/include
fi
if [[ -z "$bfd_include" && -f /tmp/rugra-ghidra-bfd-2.38/usr/include/bfd.h ]]; then
  bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
fi
if [[ -z "$bfd_include" || ! -f "$bfd_include/bfd.h" ]]; then
  echo "binutils 2.38 bfd.h not found; set RUDRA_BFD_INCLUDE" >&2
  exit 1
fi
bfd_library=${RUDRA_BFD_LIBRARY:-/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so}
if [[ ! -f "$bfd_library" ]]; then
  echo "binutils 2.38 BFD library not found: $bfd_library" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/coreaction.rs" "$binary" "$spec_root" \
  "$bfd_include/bfd.h" "$bfd_library" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name,
    cpp_name,
    rust_name,
    coreaction_name,
    binary_name,
    spec_root_name,
    bfd_header_name,
    bfd_library_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata.get("oracle") != {"tag": oracle_tag, "commit": oracle_commit}:
    raise SystemExit("metadata oracle mismatch")
if metadata.get("architecture") != "x86:LE:64:default":
    raise SystemExit("unexpected architecture metadata")
if metadata.get("compiler_spec") != "gcc":
    raise SystemExit("unexpected compiler-spec metadata")
observation = metadata.get("observation", {})
if observation.get("wrapper_fields_status") != "MATCH":
    raise SystemExit("wrapper-field observation must be MATCH")
if observation.get("overall_status") != "MISMATCH":
    raise SystemExit("full lifecycle must remain MISMATCH")

def digest(name):
    return hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

actual_input = json.dumps(
    metadata["input"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
).encode()
fingerprint = "sha256:" + hashlib.sha256(actual_input).hexdigest()
if metadata.get("input_fingerprint") != fingerprint:
    raise SystemExit("input fingerprint mismatch")
comparands = {
    "cpp_fixture": cpp_name,
    "rust_fixture": rust_name,
    "coreaction_rs": coreaction_name,
}
for key, name in comparands.items():
    actual = digest(name)
    if metadata["comparand_sha256"].get(key) != actual:
        raise SystemExit(f"{key} hash mismatch: {actual}")
assets = {
    "binary_sha256": binary_name,
    "sla_sha256": pathlib.Path(spec_root_name) / "x86-64.sla",
    "pspec_sha256": pathlib.Path(spec_root_name) / "x86-64.pspec",
    "cspec_sha256": pathlib.Path(spec_root_name) / "x86-64-gcc.cspec",
    "ldefs_sha256": pathlib.Path(spec_root_name) / "x86.ldefs",
    "bfd_header_sha256": bfd_header_name,
    "bfd_library_sha256": bfd_library_name,
}
for key, name in assets.items():
    actual = digest(name)
    if metadata["assets"].get(key) != actual:
        raise SystemExit(f"{key} mismatch: {actual}")
compiler = subprocess.check_output(["g++", "--version"], text=True).splitlines()[0]
rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
if metadata.get("host_compiler") != compiler:
    raise SystemExit(f"host compiler mismatch: {compiler}")
if metadata.get("host_rustc") != rustc:
    raise SystemExit(f"host rustc mismatch: {rustc}")
PY

oracle_tmp=$(mktemp -d /tmp/rugra-pipeline-lifecycle-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rugra-pipeline-lifecycle-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" \
  "$cpp_root/libdecomp.cc" \
  "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/pipeline_lifecycle_1204"

# Reuse Cargo's normal incremental cache.  The executable and observations
# remain isolated in oracle_tmp; only dependency compilation is cached.
fixture_target=${RUDRA_PIPELINE_LIFECYCLE_TARGET_DIR:-"$repo_root/target"}
if ! CARGO_TARGET_DIR="$fixture_target" \
  cargo build --manifest-path "$repo_root/Cargo.toml" --locked --offline --quiet --lib \
  2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
rugra_rlib="$fixture_target/debug/librugra.rlib"
if [[ ! -f "$rugra_rlib" ]]; then
  echo "cargo build did not produce a Rugra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rugra=$rugra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/pipeline_lifecycle_rugra"

if ! "$oracle_tmp/pipeline_lifecycle_1204" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"; then
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
"$oracle_tmp/pipeline_lifecycle_rugra" >"$oracle_tmp/rugra.stdout"

diff_status=0
diff -u --label ghidra-12.0.4 --label rugra \
  "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
  >"$oracle_tmp/lifecycle.diff" || diff_status=$?
if [[ "$diff_status" -ne 1 ]]; then
  echo "expected the registered complete-lifecycle mismatch, diff status=$diff_status" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rugra.stdout" "$oracle_tmp/lifecycle.diff" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra": pathlib.Path(sys.argv[2]),
    "rugra": pathlib.Path(sys.argv[3]),
    "diff": pathlib.Path(sys.argv[4]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["expected_stdout_sha256"].get(key) != actual:
        raise SystemExit(f"registered {key} observation drifted: {actual}")

def parse(path):
    result = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if ":" in raw:
            label, fields = raw.split(":", 1)
            result[label] = dict(item.split("=", 1) for item in fields.split(","))
        else:
            key, value = raw.split("=", 1)
            result[key] = value
    return result

ghidra = parse(paths["ghidra"])
rugra = parse(paths["rugra"])
for scalar in ("start_return", "stop_dead_before", "stop_return"):
    if ghidra[scalar] != rugra[scalar]:
        raise SystemExit(f"wrapper scalar mismatch: {scalar}")
flow_fields = {"alive", "ops", "varnodes", "blocks", "calls"}
for label in ("before_start", "after_start", "after_stop"):
    for key, value in ghidra[label].items():
        if key in flow_fields:
            continue
        if rugra[label].get(key) != value:
            raise SystemExit(f"wrapper/lifecycle field mismatch: {label}.{key}")
if not any(
    ghidra[label][key] != rugra[label][key]
    for label in ("after_start", "after_stop")
    for key in flow_fields
):
    raise SystemExit("registered missing-followFlow mismatch unexpectedly vanished")
PY

cat "$oracle_tmp/ghidra.stdout"
cat "$oracle_tmp/lifecycle.diff"
printf 'pipeline_lifecycle_1204: wrapper_fields=MATCH overall=MISMATCH\n'
