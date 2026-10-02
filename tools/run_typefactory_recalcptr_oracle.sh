#!/usr/bin/env bash
# TYPEFACTORY-RECALCPTR-WARNINGS-0001 oracle runner (live-tree mode).
#
# Rebuilds the locked Ghidra 12.0.4 decompiler library from the pinned
# ghidra/ checkout, compiles the C++ fixture against it (real oracle),
# builds the Rudra crate (live working tree) and the Rust fixture, runs
# both, and requires the 39 stdout records to be byte-identical EXCEPT
# the two records registered under TYPEFACTORY-ARC-IDENTITY-0001:
#   recalc.single.identity / recalc.multi.identity
# Ghidra's recalcPointerSubmeta erases the incomplete-composite pointer,
# mutates submeta in place, and reinserts, so the pre-completion handle
# IS the post-completion probe result (identity=1); Rudra's immutable
# Arc<Datatype> can only do controlled replacement, so the external
# pre-handle keeps the old object (identity=0). The ticket forbids
# marking MATCH before the global interior-mutability migration, so this
# runner pins the EXACT registered delta and fails on any other
# divergence (a ratchet: fixing the seam flips the two records and this
# runner must then be re-pinned to the MATCH form).
#
# Records:
#   s2tc.*    — string2typeclass (type.cc:371-411) spelling table + two
#               verbatim LowlevelError rejections.
#   m2tc.*    — metatype2typeclass (type.cc:420-432).
#   recalc.*  — TypeFactory::recalcPointerSubmeta (type.cc:3724-3745) as
#               driven by the struct setFields tail (type.cc:3490-3491):
#               single-field SUB_PTR_STRUCT(4)->SUB_PTR(6) with identity,
#               multi-field early-out.
#   setname.* — TypeFactory::setName (type.cc:3445-3459): rename
#               registration + the anonymous id-0 hashName branch.
#   warn.*    — the insertWarning channel (type.cc:3750-3757) through
#               PUBLIC triggers: anonymous (id-0) overlapping struct via
#               decodeType throws verbatim (type.cc:4357-4358); a named
#               one gets hasWarning; destroyType drains via removeWarning
#               (type.cc:4126-4127).
#   destroy.* — destroyType (type.cc:4122-4132): core-type verbatim
#               throw + warned named type removal.
#   ptrspace.*— getTypePointerWithSpace (type.cc:4055-4065).
#   flags.*   — the setFields flags mask (type.cc:3487-3488/3508-3509):
#               struct transfers opaque_string AND variable_length; the
#               union mask has NO opaque_string.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
metadata="$repo_root/tests/oracle/typefactory_recalcptr_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/typefactory_recalcptr_1204.cc"
rust_fixture="$repo_root/tests/oracle/typefactory_recalcptr_1204.rs"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

for required in "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/sleigh_specs/x86-64.sla" "$repo_root/examples/curl" \
  "$bfd_include/bfd.h" "$bfd_library"; do
  if [[ ! -f "$required" ]]; then
    echo "required input is missing: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
if [[ "$actual_commit" != "$oracle_commit" ]]; then
  echo "expected Ghidra $oracle_commit, found $actual_commit" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

python3 - "$metadata" "$cpp_fixture" "$rust_fixture" "$oracle_commit" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path, cpp_path, rust_path, oracle_commit = (
    pathlib.Path(sys.argv[1]),
    pathlib.Path(sys.argv[2]),
    pathlib.Path(sys.argv[3]),
    sys.argv[4],
)
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
if metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle commit does not match runner")
for key, path in (
    ("cpp_fixture_sha256", cpp_path),
    ("rust_fixture_sha256", rust_path),
):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata[key] != actual:
        raise SystemExit(
            f"fixture hash mismatch for {path.name}: "
            f"metadata={metadata[key]} actual={actual}"
        )
PY

oracle_tmp=$(mktemp -d /tmp/rudra-typefactory-recalcptr-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-typefactory-recalcptr-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
g++ -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$bfd_include" -I"$cpp_root" \
  "$cpp_fixture" "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" \
  "$cpp_root/inject_sleigh.cc" "$cpp_root/bfd_arch.cc" \
  "$cpp_root/loadimage_bfd.cc" \
  "$cpp_root/libdecomp.a" "$bfd_library" -lz \
  -o "$oracle_tmp/typefactory_recalcptr_cpp"

CARGO_TARGET_DIR="$oracle_tmp/cargo-target" \
  cargo build --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 -O \
  -L "dependency=$oracle_tmp/cargo-target/debug/deps" \
  --extern "rudra=$oracle_tmp/cargo-target/debug/librudra.rlib" \
  "$rust_fixture" -o "$oracle_tmp/typefactory_recalcptr_rust"

"$oracle_tmp/typefactory_recalcptr_cpp" \
  "$repo_root/sleigh_specs" "$repo_root/examples/curl" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/typefactory_recalcptr_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
if [[ "$ghidra_status" != 0 || "$rudra_status" != 0 ]]; then
  echo "fixture exit codes: ghidra=$ghidra_status rudra=$rudra_status" >&2
  tail -3 "$oracle_tmp/ghidra.stderr" >&2
  tail -3 "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "rudra fixture stderr is not empty" >&2
  exit 1
fi

# The registered TYPEFACTORY-ARC-IDENTITY-0001 delta: exactly the two
# identity records differ (oracle=1, rudra=0). Any other divergence
# fails the gate.
python3 - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_bytes = pathlib.Path(sys.argv[2]).read_bytes()
rudra_bytes = pathlib.Path(sys.argv[3]).read_bytes()
ghidra = ghidra_bytes.decode(encoding="utf-8").splitlines()
rudra = rudra_bytes.decode(encoding="utf-8").splitlines()

oracle_hash = hashlib.sha256(ghidra_bytes).hexdigest()
if metadata["expected_stdout_sha256"] != oracle_hash:
    raise SystemExit(
        "oracle output hash mismatch: "
        f"metadata={metadata['expected_stdout_sha256']} actual={oracle_hash}"
    )
if len(ghidra) != metadata["expected_stdout_records"]:
    raise SystemExit(
        f"oracle record count mismatch: {len(ghidra)} != "
        f"{metadata['expected_stdout_records']}"
    )
if len(ghidra) != len(rudra):
    raise SystemExit(
        f"record count diverged: ghidra={len(ghidra)} rudra={len(rudra)}"
    )

registered = {
    "recalc.single.identity": ("1", "0"),
    "recalc.multi.identity": ("1", "0"),
}
mismatches = []
for gh, ru in zip(ghidra, rudra):
    if gh == ru:
        continue
    key = gh.split("=", 1)[0] if "=" in gh else gh
    expected = registered.get(key)
    if expected is None:
        raise SystemExit(f"UNREGISTERED divergence: {gh!r} vs {ru!r}")
    if not (gh.endswith("=" + expected[0]) and ru.endswith("=" + expected[1])):
        raise SystemExit(
            f"registered record diverged from pinned delta: {gh!r} vs {ru!r}"
        )
    mismatches.append(key)
if sorted(mismatches) != sorted(registered):
    raise SystemExit(
        f"registered-delta set changed: {sorted(mismatches)} != "
        f"{sorted(registered)} (if the seam was fixed, re-pin this runner "
        "to the MATCH form)"
    )
print(f"records={len(ghidra)} registered_mismatch={len(mismatches)}")
PY
printf 'typefactory_recalcptr_1204: MISMATCH (registered TYPEFACTORY-ARC-IDENTITY-0001 delta only)\n'
