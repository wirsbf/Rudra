#!/usr/bin/env bash
set -euo pipefail

# ARCH-CONTEXT-TRACKED-0001 oracle runner: pspec <context_data> tracked-set
# ingest parity.  Compiles the locked Ghidra 12.0.4 oracle fixture (real
# BfdArchitecture chain: spec-dir scan -> Architecture::init ->
# parseProcessorConfig's ELEM_CONTEXT_DATA arm -> ContextInternal::
# decodeFromSpec) and an isolated base-plus-overlay Rust snapshot
# (fixture-local Element DOM -> TreeDecoder -> Architecture::
# decode_context_data), runs both arch_context_tracked_1204 fixtures on
# identical locked x86-64.pspec bytes plus synthetic <context_data>
# documents, and diffs the state projections byte for byte.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
oracle_cpp="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_archive="$oracle_cpp/libdecomp.a"
cpp_fixture="$repo_root/tests/oracle/arch_context_tracked_1204.cc"
rust_fixture="$repo_root/tests/oracle/arch_context_tracked_1204.rs"
metadata="$repo_root/tests/oracle/arch_context_tracked_1204.metadata.json"
runner="$repo_root/tools/run_arch_context_tracked_oracle.sh"
arch_rs="$repo_root/src/arch.rs"
arch_doc="$repo_root/docs/api/arch.md"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
ghidra_only=false

if [[ ${1:-} == "--ghidra-only" ]]; then
  ghidra_only=true
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $0 [--ghidra-only]" >&2
  exit 2
fi

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_language_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Processors/x86/data/languages")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ -n "$(git -C "$ghidra_root" status --porcelain --untracked-files=no -- Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

rudra_base_commit=$(python3 -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["comparand"]["rugra_base_commit"])' \
  "$metadata")
rudra_base_tree=$(python3 -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["comparand"]["rugra_base_tree"])' \
  "$metadata")
actual_rudra_base_tree=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_rudra_base_tree" != "$rudra_base_tree" ]]; then
  echo "locked Rudra base tree mismatch" >&2
  exit 1
fi

for required in "$cpp_fixture" "$rust_fixture" "$metadata" "$runner" \
  "$arch_rs" "$arch_doc" "$bfd_include/bfd.h" "$bfd_library" "$oracle_archive"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "missing or non-regular fixture input: $required" >&2
    exit 1
  fi
done

python3 -I - "$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "$arch_rs" "$arch_doc" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
paths = [pathlib.Path(value) for value in sys.argv[2:7]]
oracle_commit = sys.argv[7]
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit mismatch")
keys = [
    "cpp_fixture_sha256", "rust_fixture_sha256", "runner_sha256",
    "arch_rs_sha256", "arch_doc_sha256",
]
for key, path in zip(keys, paths):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")

payload = {
    "architecture": metadata["architecture"],
    "analysis_options": metadata["analysis_options"],
    "assets": metadata["assets"],
    "cases": metadata["input_manifest"]["cases"],
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
actual_manifest = hashlib.sha256(canonical).hexdigest()
expected_manifest = metadata["input_manifest"]["sha256"]
if actual_manifest != expected_manifest:
    raise SystemExit(
        f"input manifest mismatch: expected={expected_manifest} actual={actual_manifest}"
    )
PY

python3 -I - "$metadata" "$bfd_include/bfd.h" "$bfd_library" \
  "$actual_cpp_tree" "$actual_language_tree" "$actual_makefile_blob" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bfd_header = pathlib.Path(sys.argv[2])
bfd_library = pathlib.Path(sys.argv[3])
actual_oracle_ids = sys.argv[4:7]
expected_oracle_ids = [
    metadata["oracle"]["decompiler_cpp_tree"],
    metadata["oracle"]["x86_language_tree"],
    metadata["oracle"]["decompiler_makefile_blob"],
]
if actual_oracle_ids != expected_oracle_ids:
    raise SystemExit("locked oracle tree/blob identity mismatch")
for path, expected in (
    (bfd_header, metadata["external_inputs"]["bfd_header_sha256"]),
    (bfd_library, metadata["external_inputs"]["bfd_library_sha256"]),
):
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"external BFD input hash mismatch: {path}")
PY

actual_archive_sha=$(sha256sum "$oracle_archive" | awk '{print $1}')
expected_archive_sha=$(python3 -I -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["comparand"]["locked_libdecomp_a_sha256"])' \
  "$metadata")
if [[ "$actual_archive_sha" != "$expected_archive_sha" ]]; then
  echo "locked libdecomp.a hash mismatch" >&2
  exit 1
fi

oracle_tmp=$(mktemp -d /tmp/rudra-arch-context-tracked-1204.XXXXXX)
cleanup() {
  if [[ ${KEEP_TMP:-0} == 1 ]]; then
    echo "keeping oracle tmp: $oracle_tmp" >&2
    return 0
  fi
  case "$oracle_tmp" in
    /tmp/rudra-arch-context-tracked-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing to remove unexpected temporary path: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

rudra_overlay="$oracle_tmp/rudra-overlay"
mkdir "$rudra_overlay"
git -C "$repo_root" archive "$rudra_base_commit" | tar -x -C "$rudra_overlay"
cp "$arch_rs" "$rudra_overlay/src/arch.rs"
mkdir -p "$rudra_overlay/ghidra"
git -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | tar -x -C "$rudra_overlay/ghidra"

spec_root="$oracle_tmp/specs"
mkdir "$spec_root"
for path in \
  sleigh_specs/x86.ldefs \
  sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec \
  sleigh_specs/x86-64.sla; do
  git -C "$repo_root" show "$rudra_base_commit:$path" > "$spec_root/${path##*/}"
done
binary="$oracle_tmp/curl"
git -C "$repo_root" show "$rudra_base_commit:examples/curl" > "$binary"
chmod 0700 "$binary"

python3 -I - "$metadata" "$repo_root" "$rudra_base_commit" "$spec_root" "$binary" \
  "$rudra_overlay/Cargo.toml" "$rudra_overlay/Cargo.lock" "$rudra_overlay/build.rs" \
  "$rudra_overlay/src/arch.rs" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
repo_root = pathlib.Path(sys.argv[2])
base_commit = sys.argv[3]
spec_root = pathlib.Path(sys.argv[4])
binary = pathlib.Path(sys.argv[5])
overlay_paths = [pathlib.Path(value) for value in sys.argv[6:10]]

asset_paths = {
    "language_definitions": spec_root / "x86.ldefs",
    "processor_spec": spec_root / "x86-64.pspec",
    "compiler_spec": spec_root / "x86-64-gcc.cspec",
    "sla": spec_root / "x86-64.sla",
    "binary": binary,
}
for name, path in asset_paths.items():
    record = metadata["assets"][name]
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise SystemExit(f"asset hash mismatch: {name}")
    if len(data) != record["size"]:
        raise SystemExit(f"asset size mismatch: {name}")
    actual_blob = subprocess.check_output(
        ["git", "-C", str(repo_root), "rev-parse", f"{base_commit}:{record['path']}"],
        text=True,
    ).strip()
    if actual_blob != record["git_blob"]:
        raise SystemExit(f"asset blob mismatch: {name}")

keys = [
    "cargo_toml_sha256", "cargo_lock_sha256", "build_rs_sha256",
    "arch_rs_sha256",
]
for key, path in zip(keys, overlay_paths):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["comparand"][key]
    if actual != expected:
        raise SystemExit(f"overlay {key} mismatch: expected={expected} actual={actual}")
PY

if ! g++ -std=c++11 -O0 -Wall -Wno-sign-compare -m64 \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_archive" \
  "$bfd_library" -lz -o "$oracle_tmp/arch_context_tracked_1204_cpp" \
  >"$oracle_tmp/cxx.stdout" 2>"$oracle_tmp/cxx.stderr"; then
  cat "$oracle_tmp/cxx.stdout" >&2
  cat "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi

"$oracle_tmp/arch_context_tracked_1204_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout"

python3 -I - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
stdout = pathlib.Path(sys.argv[2]).read_bytes()
document = json.loads(stdout.decode("utf-8"))
if document.get("schema") != 1 or document.get("fixture") != "ARCH-CONTEXT-TRACKED-0001":
    raise SystemExit("invalid fixture envelope")
if document.get("done") != 1:
    raise SystemExit("fixture did not complete")
production = document.get("production", {})
if production.get("context_set_children") != 1:
    raise SystemExit(f"production context_set_children mismatch: {production}")
probes = {probe["off"]: probe for probe in production.get("probes", [])}
if probes.get("0x0", {}).get("count") != 1:
    raise SystemExit("production ram:0x0 must carry the tracked DF entry")
if probes.get("0xffffffffffffffff", {}).get("count") != 1:
    raise SystemExit("production ram:highest must stay covered (next-space boundary)")
cases = {case["name"]: case for case in document.get("cases", [])}
if len(cases) != 5:
    raise SystemExit(f"expected 5 cases, found {sorted(cases)}")
errors = {error["name"]: error["error"] for error in document.get("errors", [])}
if errors.get("e2b_bad_child_with_range") != "Bad <context_data> tag":
    raise SystemExit("bad-child-with-range oracle text mismatch")
if errors.get("e6_non_set_child") != "Expecting <set> but got <register>":
    raise SystemExit("non-set-child oracle text mismatch")
actual = hashlib.sha256(stdout).hexdigest()
expected = metadata["expected_stdout_sha256"]
if actual != expected:
    raise SystemExit(f"stdout hash mismatch: expected={expected} actual={actual}")
PY

if $ghidra_only; then
  cat "$oracle_tmp/ghidra.stdout"
  printf 'arch_context_tracked_1204: GHIDRA_LOCKED_OUTPUT_OK\n'
  exit 0
fi

if ! CARGO_TARGET_DIR="$oracle_tmp/cargo-target" cargo build \
  --manifest-path "$rudra_overlay/Cargo.toml" --lib --locked --offline --quiet \
  >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr"; then
  cat "$oracle_tmp/cargo.stdout" >&2
  cat "$oracle_tmp/cargo.stderr" >&2
  exit 1
fi
cargo_target="$oracle_tmp/cargo-target"
set +o pipefail
rlib=$(ls -t "$cargo_target"/debug/deps/librudra-*.rlib | head -1)
native_archive=$(ls -t "$cargo_target"/debug/build/rudra-*/out/librudra_sleigh.a | head -1)
set -o pipefail
if [[ ! -f "$rlib" || ! -f "$native_archive" ]]; then
  echo "missing freshly built Rudra link inputs" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$cargo_target/debug/deps" \
  -L "native=$(dirname "$native_archive")" --extern "rudra=$rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/arch_context_tracked_1204_rust"

"$oracle_tmp/arch_context_tracked_1204_rust" "$spec_root" \
  >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
cat "$oracle_tmp/ghidra.stdout"
printf 'arch_context_tracked_1204: DECLARED_OBSERVATIONS_MATCH\n'
