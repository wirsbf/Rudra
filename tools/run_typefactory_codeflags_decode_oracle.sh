#!/usr/bin/env bash
# TYPEFACTORY-CODEFLAGS-DECODE-0001 locked Ghidra/Rudra differential runner
# (typefactory_codeflags_decode_1204): TypeFactory::decodeTypeWithCodeFlags
# (type.cc:4193-4212), the decodeCode stub/compare/define chain
# (type.cc:4401-4429, 2903-2931), and the XmlDecode cursor partial state of
# every error path.
#
# Rebuilds the locked Ghidra 12.0.4 decompiler from the pinned source tree,
# builds the Rudra crate from the pinned base commit plus the two hash
# verified live overlays (src/type_system/typefactory.rs and
# src/type_system/datatype.rs), compiles both fixtures, runs them, and
# requires byte-identical stdout. The 89 records cover:
#   - the kludge entry's three error paths: "Bad size for type " from the
#     decodeStub re-read of the exhausted outer element (the empirically
#     verified 12.0.4 behaviour for every nested pointer->code XML, with
#     byte-identical output across varargs/model/ctor/dtor/thiscall flag
#     combinations), "Special type decode does not see pointer", and the
#     first decodeBasic's own "Bad size for type <name>",
#   - the cursor partial state after each throw: the still-open element's
#     unread children, its successful close, and the readable <void/>
#     sibling behind it,
#   - decodeCode via decodeType: prototype-less stub creation, in-place
#     completion through the setPrototype wrapper (type_incomplete cleared
#     even for a null prototype), re-decode dedup identity, the
#     "Redefinition of code data-type" compareDependency error with the
#     surviving definition, the "Trying to redefine type" findByIdLocal
#     metatype check with the surviving int, the varlength hashSize id
#     folding, and the anonymous structural dedup,
#   - the pointer->code chain via decodeType including the wordsize
#     attribute and the canonical pointee identity.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
rudra_base_tree=ace2e9c5fddf79050ad9f8fe2bd2de6aa954cc03
rudra_typefactory_base_blob=c7f80d486e3393b4722dc5654a082421046c8c09
rudra_datatype_base_blob=03980bc2f8b7fabb4af486018c2a68a85f763dc0
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/typefactory_codeflags_decode_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/typefactory_codeflags_decode_1204.cc"
rust_fixture="$repo_root/tests/oracle/typefactory_codeflags_decode_1204.rs"
typefactory_overlay="$repo_root/src/type_system/typefactory.rs"
datatype_overlay="$repo_root/src/type_system/datatype.rs"
doc_typefactory="$repo_root/docs/api/type_system/typefactory.md"
doc_datatype="$repo_root/docs/api/type_system/datatype.md"
runner="$repo_root/tools/run_typefactory_codeflags_decode_oracle.sh"
spec_root="$repo_root/sleigh_specs"
binary="$repo_root/examples/curl"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$typefactory_overlay" "$datatype_overlay" "$doc_typefactory" \
  "$doc_datatype" "$runner" \
  "$spec_root/x86-64.sla" "$spec_root/x86-64.pspec" \
  "$spec_root/x86-64-gcc.cspec" "$spec_root/x86.ldefs" "$binary" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required regular non-symlink input is missing: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra HEAD/tag mismatch: HEAD=$actual_commit tag=$actual_tag_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "HEAD:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra cpp tree/Makefile mismatch: tree=$actual_cpp_tree makefile=$actual_makefile_blob" >&2
  exit 1
fi

resolved_base_commit=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{commit}")
resolved_base_tree=$(git -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
resolved_typefactory_blob=$(git -C "$repo_root" rev-parse \
  "$rudra_base_commit:src/type_system/typefactory.rs")
resolved_datatype_blob=$(git -C "$repo_root" rev-parse \
  "$rudra_base_commit:src/type_system/datatype.rs")
if [[ "$resolved_base_commit" != "$rudra_base_commit" || \
      "$resolved_base_tree" != "$rudra_base_tree" || \
      "$resolved_typefactory_blob" != "$rudra_typefactory_base_blob" || \
      "$resolved_datatype_blob" != "$rudra_datatype_base_blob" ]]; then
  echo "pinned Rudra source identity mismatch" >&2
  exit 1
fi

verify_inputs() {
  python3 - "$metadata" "$cpp_fixture" "$rust_fixture" \
    "$typefactory_overlay" "$datatype_overlay" \
    "$doc_typefactory" "$doc_datatype" "$runner" \
    "$spec_root/x86-64.sla" "$spec_root/x86-64.pspec" \
    "$spec_root/x86-64-gcc.cspec" "$spec_root/x86.ldefs" "$binary" \
    "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw,
    cpp_raw,
    rust_raw,
    typefactory_raw,
    datatype_raw,
    doc_typefactory_raw,
    doc_datatype_raw,
    runner_raw,
    sla_raw,
    pspec_raw,
    cspec_raw,
    ldefs_raw,
    binary_raw,
    cargo_toml_raw,
    cargo_lock_raw,
    oracle_commit,
) = sys.argv[1:]

metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")

inputs = {
    "cpp_fixture_sha256": pathlib.Path(cpp_raw),
    "rust_fixture_sha256": pathlib.Path(rust_raw),
    "typefactory_overlay_sha256": pathlib.Path(typefactory_raw),
    "datatype_overlay_sha256": pathlib.Path(datatype_raw),
    "api_typefactory_document_sha256": pathlib.Path(doc_typefactory_raw),
    "api_datatype_document_sha256": pathlib.Path(doc_datatype_raw),
    "runner_sha256": pathlib.Path(runner_raw),
    "sla_sha256": pathlib.Path(sla_raw),
    "pspec_sha256": pathlib.Path(pspec_raw),
    "cspec_sha256": pathlib.Path(cspec_raw),
    "ldefs_sha256": pathlib.Path(ldefs_raw),
    "binary_sha256": pathlib.Path(binary_raw),
    "cargo_toml_sha256": pathlib.Path(cargo_toml_raw),
    "cargo_lock_sha256": pathlib.Path(cargo_lock_raw),
}
declared = metadata["comparand"] | metadata["assets"]
for key, path in inputs.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = declared[key]
    if actual != expected:
        raise SystemExit(
            f"input hash mismatch for {path.name}: metadata={expected} actual={actual}"
        )
PY
}

verify_inputs

oracle_tmp=$(mktemp -d /tmp/rudra-typefactory-codeflags-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-typefactory-codeflags-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

snapshot_root="$oracle_tmp/rudra"
mkdir -p "$snapshot_root"
git -C "$repo_root" archive --format=tar "$rudra_base_commit" \
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim | tar -xf - -C "$snapshot_root"
cp -- "$typefactory_overlay" "$snapshot_root/src/type_system/typefactory.rs"
cp -- "$datatype_overlay" "$snapshot_root/src/type_system/datatype.rs"
snapshot_decompiler="$snapshot_root/ghidra/Ghidra/Features/Decompiler/src/decompile"
mkdir -p "$snapshot_decompiler"
ln -s "$cpp_root" "$snapshot_decompiler/cpp"

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/typefactory_codeflags_decode_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --quiet --locked --offline --manifest-path "$snapshot_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$rust_fixture" -o "$oracle_tmp/typefactory_codeflags_decode_rust"

"$oracle_tmp/typefactory_codeflags_decode_cpp" "$spec_root" "$binary" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/typefactory_codeflags_decode_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
if [[ "$ghidra_status" != 0 || "$rudra_status" != 0 ]]; then
  echo "fixture exit codes: ghidra=$ghidra_status rudra=$rudra_status" >&2
  tail -5 "$oracle_tmp/ghidra.stderr" >&2
  tail -5 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture stderr is not empty" >&2
  tail -5 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
verify_inputs

python3 - "$metadata" "$oracle_tmp/ghidra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
output = pathlib.Path(sys.argv[2]).read_bytes()
actual = hashlib.sha256(output).hexdigest()
expected = metadata["expected_stdout_sha256"]
if actual != expected:
    raise SystemExit(f"oracle output hash mismatch: metadata={expected} actual={actual}")
if metadata["projection_status"] != "MATCH":
    raise SystemExit("metadata projection_status must remain MATCH")
print(f"records={len(output.decode('utf-8').splitlines())}")
print(f"stdout_sha256={actual}")
PY
printf 'typefactory_codeflags_decode_1204: projection_status=MATCH\n'
