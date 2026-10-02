#!/usr/bin/env bash
# Locked CPOOL-TYPED-RECORD-0001 bilateral oracle runner.
#
# Rudra is materialized from one committed base archive. The only live source
# overlaid into that snapshot is this task's owned src/cpool.rs. Both fixture
# sources are copied outside the repository and snapshot before compilation.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
rudra_base_commit=895f69d0baebeb67db7ae27cc1ba676b8fcb4f5d
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/cpool_typed_record_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/cpool_typed_record_1204.cc"
rust_fixture="$repo_root/tests/oracle/cpool_typed_record_1204.rs"
cpool_source="$repo_root/src/cpool.rs"
api_document="$repo_root/docs/api/cpool.md"
runner="$repo_root/tools/run_cpool_typed_record_oracle.sh"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$cpool_source" "$api_document" "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" ]]; then
    echo "required input is missing: $required" >&2
    exit 1
  fi
done
if [[ "$(stat -c '%a' "$runner")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

actual_oracle=$(git -C "$ghidra_root" rev-parse HEAD)
tag_oracle=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_oracle" != "$oracle_commit" || "$tag_oracle" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi
git -C "$repo_root" cat-file -e "$rudra_base_commit^{commit}"

oracle_tmp=$(mktemp -d /tmp/rudra-cpool-typed-record-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-cpool-typed-record-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

rudra_snapshot="$oracle_tmp/rudra"
oracle_archive="$oracle_tmp/oracle"
fixture_dir="$oracle_tmp/fixtures"
mkdir -p "$rudra_snapshot" "$oracle_archive" "$fixture_dir"

# Materialize the complete committed Rudra tree. No live source directory is
# copied. The sole source overlay is cpool.rs, whose hash is checked below.
git -C "$repo_root" archive --format=tar "$rudra_base_commit" \
  | tar -xf - -C "$rudra_snapshot"
cp -- "$cpool_source" "$rudra_snapshot/src/cpool.rs"

# Materialize the locked oracle C++ subtree from the Git object, not from live
# files. Mount it where build.rs expects the Ghidra source tree.
git -C "$ghidra_root" archive --format=tar "$oracle_commit" -- \
  Ghidra/Features/Decompiler/src/decompile/cpp \
  | tar -xf - -C "$oracle_archive"
snapshot_cpp="$oracle_archive/Ghidra/Features/Decompiler/src/decompile/cpp"
mkdir -p "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
ln -s "$snapshot_cpp" \
  "$rudra_snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

# Fixtures are compiled only from workspace-external copies.
cp -- "$cpp_fixture" "$fixture_dir/cpool_typed_record_1204.cc"
cp -- "$rust_fixture" "$fixture_dir/cpool_typed_record_1204.rs"
snapshot_cpp_fixture="$fixture_dir/cpool_typed_record_1204.cc"
snapshot_rust_fixture="$fixture_dir/cpool_typed_record_1204.rs"

python3 -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$snapshot_cpp_fixture" \
  "$snapshot_rust_fixture" "$cpool_source" "$api_document" "$runner" \
  "$rudra_snapshot" "$ghidra_root" "$oracle_commit" "$oracle_tag" \
  "$rudra_base_commit" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    metadata_name, cpp_name, rust_name, copied_cpp_name, copied_rust_name,
    cpool_name, docs_name, runner_name, snapshot_name, ghidra_root_name,
    oracle_commit, oracle_tag, rudra_base_commit,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
snapshot = pathlib.Path(snapshot_name)

if metadata.get("schema") != 2:
    raise SystemExit("metadata schema must be 2")
if metadata.get("fixture_id") != "CPOOL-TYPED-RECORD-0001":
    raise SystemExit("metadata fixture id mismatch")
if metadata.get("projection_status") != "MATCH":
    raise SystemExit("projection_status must be MATCH")
if metadata.get("overall_status") != "MISMATCH: (B2 canonicalization)":
    raise SystemExit("overall_status must be MISMATCH")
if not metadata.get("status_note"):
    raise SystemExit("status_note must be non-empty")
if metadata.get("rugra_base_commit") != rudra_base_commit:
    raise SystemExit("metadata Rudra base mismatch")
if metadata.get("oracle", {}).get("tag") != oracle_tag or \
        metadata.get("oracle", {}).get("commit") != oracle_commit:
    raise SystemExit("metadata oracle mismatch")
for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")

expected_coverage = {
    "typed_tags_and_order": "MATCH",
    "lookup_projection": "MATCH",
    "duplicate_and_replacement": "MATCH",
    "missing_data_partial_state": "MATCH",
    "type_resolution_partial_state": "MATCH",
    "packed_wire": "MISMATCH",
    "constructor_destructor_codeflags": "MISMATCH",
    "byte_data_ge_0x80": "UNTESTED",
}
coverage = metadata.get("coverage", {})
if set(coverage) != set(expected_coverage):
    raise SystemExit("coverage keys drifted")
bound_residuals = set()
for key, expected_status in expected_coverage.items():
    entry = coverage[key]
    if not isinstance(entry, dict) or entry.get("status") != expected_status:
        raise SystemExit(f"coverage status drifted for {key}")
    ids = entry.get("residual_todo_ids", [])
    if expected_status != "MATCH" and not ids:
        raise SystemExit(f"non-MATCH coverage lacks TODO binding: {key}")
    bound_residuals.update(ids)
expected_residuals = {
    "MARSHAL-ID-0001",
    "MARSHAL-PACKED-0001",
    "TYPEFACTORY-CODEFLAGS-DECODE-0001",
}
if set(metadata.get("residual_todo_ids", [])) != expected_residuals:
    raise SystemExit("top-level residual_todo_ids drifted")
if bound_residuals != expected_residuals:
    raise SystemExit("coverage residual bindings do not close top-level residuals")

cases = metadata["input_manifest"].get("cases")
payload = json.dumps(
    cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
).encode()
actual_manifest = hashlib.sha256(payload).hexdigest()
if metadata["input_manifest"].get("sha256") != actual_manifest:
    raise SystemExit("input_manifest.sha256 mismatch")

ghidra_root = pathlib.Path(ghidra_root_name)
cpp_tree = subprocess.check_output([
    "git", "-C", str(ghidra_root), "rev-parse",
    f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp",
], text=True).strip()
if cpp_tree != metadata["oracle"].get("decompiler_cpp_tree"):
    raise SystemExit("locked Ghidra C++ tree mismatch")
makefile_blob = subprocess.check_output([
    "git", "-C", str(ghidra_root), "rev-parse",
    f"{oracle_commit}:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile",
], text=True).strip()
if makefile_blob != metadata["oracle"].get("decompiler_makefile_blob"):
    raise SystemExit("locked Ghidra Makefile mismatch")

comparand = metadata.get("comparand", {})
paths = {
    "cpp_fixture_sha256": pathlib.Path(cpp_name),
    "rust_fixture_sha256": pathlib.Path(rust_name),
    "cpool_rs_sha256": pathlib.Path(cpool_name),
    "api_document_sha256": pathlib.Path(docs_name),
    "runner_sha256": pathlib.Path(runner_name),
    "cargo_toml_sha256": snapshot / "Cargo.toml",
    "cargo_lock_sha256": snapshot / "Cargo.lock",
    "build_rs_sha256": snapshot / "build.rs",
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if comparand.get(key) != actual:
        raise SystemExit(f"{key} mismatch: metadata={comparand.get(key)} actual={actual}")
base_cpool = subprocess.check_output([
    "git", "-C", str(pathlib.Path(runner_name).parents[1]), "show",
    f"{rudra_base_commit}:src/cpool.rs",
])
if comparand.get("base_cpool_rs_sha256") != hashlib.sha256(base_cpool).hexdigest():
    raise SystemExit("base cpool hash mismatch")
if pathlib.Path(copied_cpp_name).read_bytes() != pathlib.Path(cpp_name).read_bytes() or \
        pathlib.Path(copied_rust_name).read_bytes() != pathlib.Path(rust_name).read_bytes():
    raise SystemExit("workspace-external fixture copy mismatch")
if (snapshot / "src/cpool.rs").read_bytes() != pathlib.Path(cpool_name).read_bytes():
    raise SystemExit("cpool overlay mismatch")
if metadata.get("build", {}).get("runner_mode") != "755":
    raise SystemExit("metadata runner mode mismatch")

asset_map = {
    "sla": snapshot / metadata["assets"]["sla"]["path"],
    "processor_spec": snapshot / metadata["assets"]["processor_spec"]["path"],
    "language_definitions": snapshot / metadata["assets"]["language_definitions"]["path"],
    "binary": snapshot / metadata["assets"]["binary"]["path"],
}
for key, path in asset_map.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["assets"][key]["sha256"] != actual:
        raise SystemExit(f"asset hash mismatch: {key}")
compiler_path = snapshot / metadata["compiler_spec"]["path"]
if hashlib.sha256(compiler_path.read_bytes()).hexdigest() != metadata["compiler_spec"]["sha256"]:
    raise SystemExit("compiler spec hash mismatch")
PY

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$snapshot_cpp" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$snapshot_cpp" \
  "$snapshot_cpp_fixture" "$snapshot_cpp/libdecomp.cc" \
  "$snapshot_cpp/sleigh_arch.cc" "$snapshot_cpp/inject_sleigh.cc" \
  "$snapshot_cpp/bfd_arch.cc" "$snapshot_cpp/loadimage_bfd.cc" \
  "$snapshot_cpp/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/cpool_typed_record_cpp"

export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$oracle_tmp/cargo-target"
if ! cargo test --offline --locked --quiet \
    --manifest-path "$rudra_snapshot/Cargo.toml" \
    --lib cpool::tests \
    >"$oracle_tmp/cpool-tests.stdout" 2>"$oracle_tmp/cpool-tests.stderr"; then
  tail -80 "$oracle_tmp/cpool-tests.stderr" >&2
  exit 1
fi
grep -Fq '15 passed; 0 failed' "$oracle_tmp/cpool-tests.stdout"
cargo build --offline --locked --quiet \
  --manifest-path "$rudra_snapshot/Cargo.toml" --lib \
  >"$oracle_tmp/cargo-build.stdout" 2>"$oracle_tmp/cargo-build.stderr"
rustc --edition=2021 -O \
  -L "dependency=$CARGO_TARGET_DIR/debug/deps" \
  --extern "rudra=$CARGO_TARGET_DIR/debug/librudra.rlib" \
  "$snapshot_rust_fixture" -o "$oracle_tmp/cpool_typed_record_rust"

set +e
"$oracle_tmp/cpool_typed_record_cpp" \
  "$rudra_snapshot/sleigh_specs" "$rudra_snapshot/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/cpool_typed_record_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed or emitted diagnostics" >&2
  tail -20 "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ "$rudra_status" -ne 0 || -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture failed or emitted diagnostics" >&2
  tail -20 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import difflib
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_bytes = pathlib.Path(sys.argv[2]).read_bytes()
rudra_bytes = pathlib.Path(sys.argv[3]).read_bytes()
comparand = metadata["comparand"]
for key, payload in (
    ("expected_ghidra_stdout_sha256", ghidra_bytes),
    ("expected_rudra_stdout_sha256", rudra_bytes),
):
    actual = hashlib.sha256(payload).hexdigest()
    if comparand.get(key) != actual:
        raise SystemExit(f"{key} mismatch: metadata={comparand.get(key)} actual={actual}")

ghidra_lines = ghidra_bytes.splitlines(keepends=True)
rudra_lines = rudra_bytes.splitlines(keepends=True)
if len(ghidra_lines) != 18 or len(rudra_lines) != 18:
    raise SystemExit(
        f"unexpected record count: ghidra={len(ghidra_lines)} rudra={len(rudra_lines)}"
    )

def partition(lines):
    residual = [line for line in lines if line.startswith(b"packed=") or line.startswith(b"codeflags|")]
    covered = [line for line in lines if not (line.startswith(b"packed=") or line.startswith(b"codeflags|"))]
    return covered, residual

ghidra_covered, ghidra_residual = partition(ghidra_lines)
rudra_covered, rudra_residual = partition(rudra_lines)
if ghidra_covered != rudra_covered:
    diff = b"".join(difflib.diff_bytes(
        difflib.unified_diff, ghidra_covered, rudra_covered,
        fromfile=b"ghidra.covered", tofile=b"rudra.covered",
    )).decode("utf-8", errors="replace")
    raise SystemExit("covered projection mismatch:\n" + diff)
if len(ghidra_covered) != 16:
    raise SystemExit("covered projection count drifted")
if len(ghidra_residual) != 2 or len(rudra_residual) != 2:
    raise SystemExit("residual record count drifted")
if ghidra_residual[0] == rudra_residual[0]:
    raise SystemExit("registered packed-wire mismatch disappeared")

expected_ghidra_codeflags = (
    b"codeflags|status=ERROR|error=Bad size for type |record_ctor=1|record_dtor=1|"
    b"type_null=1|prototype=0|proto_ctor=0|proto_dtor=0\n"
)
expected_rudra_codeflags = (
    b"codeflags|status=ERROR|error=Rudra gap: FuncProto::decode (fspec.cc:4675) "
    b"not ported; <prototype> child rejected (TYPEFACTORY-CODEFLAGS-DECODE-0001 "
    b"residual)|record_ctor=1|record_dtor=1|type_null=1|"
    b"prototype=0|proto_ctor=0|proto_dtor=0\n"
)
if ghidra_residual[1] != expected_ghidra_codeflags:
    raise SystemExit("Ghidra codeflags observation drifted")
if rudra_residual[1] != expected_rudra_codeflags:
    raise SystemExit("Rudra codeflags observation drifted")

print("records=18")
print("cpool_tests=15/15")
print("covered_projection=16/16 projection_status=MATCH")
print("packed_wire=MISMATCH residual=MARSHAL-ID-0001,MARSHAL-PACKED-0001")
print("codeflags=MISMATCH residual=TYPEFACTORY-CODEFLAGS-DECODE-0001")
print("overall_status=MISMATCH")
PY

printf 'cpool_typed_record_1204: cpool_tests=15/15 covered_projection=16/16 projection_status=MATCH overall_status=MISMATCH\n'
