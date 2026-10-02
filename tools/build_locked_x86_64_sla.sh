#!/bin/sh
# Rebuild the tracked x86-64 SLEIGH assets from the locked Ghidra 12.0.4 tree.
#
# The production compiler is the vendored Rust `slacomp` (crates/kuna-slacomp,
# the sleigh_opt equivalent; 146/146 locked-spec content sweep in
# docs/alignment_docs/SLEIGH_SWEEP_146_2026-09-26.md). The C++ compiler is
# retired from this path (the C++ runtime stays linked via build.rs until the
# Phase 2 runtime switch).
#
# .sla gate criterion (three-part, decided after the Phase0 BORROW-TRACK
# verdict): the zlib C and flate2/miniz_oxide deflate backends produce
# different (content-equivalent) compressed bytes, so raw-byte sha is NOT the
# gate. Instead:
#   1. FORMAT_VERSION: bytes 0..3 == "sla\x04" (slaformat.cc FORMAT_VERSION=4);
#   2. decompressed element-stream sha256 + size (exact pins below) -- every
#      observable the compiler emits lives in this stream;
#   3. deflated file size within a band of the pin (backend drift guard).

set -eu

LOCKED_ORACLE=e40ed13014025f82488b1f8f7bca566894ac376b
EXPECTED_LANGUAGE_TREE=84265e1e6fe7ac9725367b57fb861253e4915984
EXPECTED_SLASPEC_SHA=9d66a01a4219ab0bee0697caf2d1ee389e094e927a857299cebb6182e40a4e6e
EXPECTED_PSPEC_SHA=3c3dab75a2ac0b98b0552856f690e613d661e0df7cf94d6252e5604d9821629f
EXPECTED_CSPEC_SHA=5eaa848f3eba7ebd4023541f9f37645dae077e8426fb562592f398d599530a9e
EXPECTED_LDEFS_SHA=b2aa14d94a6162844b18bf47f2aed8579bf90cef3459f6e322b9c1f58146098b

# Three-part gate pins (Rust slacomp output; inflated stream is byte-identical
# to the retired C++ sleigh_opt product, sweep doc above).
EXPECTED_SLA_FORMAT_VERSION=4
EXPECTED_SLA_INFLATED_SHA=2e36b32d8194a344b482dda969c1838d8d3507a3407c0021bfe1955aeead1da3
EXPECTED_SLA_INFLATED_SIZE=4124687
EXPECTED_SLA_DEFLATED_SIZE=484937
EXPECTED_SLA_SIZE_BAND_PCT=8

repo_root=$(git rev-parse --show-toplevel)
ghidra_repo=${RUDRA_GHIDRA_DIR:-"$repo_root/ghidra"}
output_dir=${1:-"$repo_root/sleigh_specs"}

die() {
    echo "build_locked_x86_64_sla: $*" >&2
    exit 1
}

file_sha256() {
    digest=$(sha256sum "$1")
    printf '%s\n' "${digest%% *}"
}

check_sha256() {
    actual=$(file_sha256 "$1")
    [ "$actual" = "$2" ] || die "$1 sha256=$actual; expected $2"
}

git -C "$ghidra_repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 || \
    die "missing Ghidra repository: $ghidra_repo"
oracle_head=$(git -C "$ghidra_repo" rev-parse HEAD)
[ "$oracle_head" = "$LOCKED_ORACLE" ] || \
    die "Ghidra HEAD=$oracle_head; expected $LOCKED_ORACLE"

language_tree=$(git -C "$ghidra_repo" rev-parse \
    "$LOCKED_ORACLE:Ghidra/Processors/x86/data/languages")
[ "$language_tree" = "$EXPECTED_LANGUAGE_TREE" ] || \
    die "x86 language tree=$language_tree; expected $EXPECTED_LANGUAGE_TREE"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/rudra-x86-64-sla.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

source_archive="$work_dir/locked-source.tar"
git -C "$ghidra_repo" archive --format=tar --output="$source_archive" "$LOCKED_ORACLE" \
    Ghidra/Processors/x86/data/languages
tar -xf "$source_archive" -C "$work_dir"

language_dir="$work_dir/Ghidra/Processors/x86/data/languages"
slaspec="$language_dir/x86-64.slaspec"
first_sla="$work_dir/x86-64.first.sla"
second_sla="$work_dir/x86-64.second.sla"

check_sha256 "$slaspec" "$EXPECTED_SLASPEC_SHA"
check_sha256 "$language_dir/x86-64.pspec" "$EXPECTED_PSPEC_SHA"
check_sha256 "$language_dir/x86-64-gcc.cspec" "$EXPECTED_CSPEC_SHA"
check_sha256 "$language_dir/x86.ldefs" "$EXPECTED_LDEFS_SHA"

# --- build the production compiler (vendored Rust slacomp) -----------------
# Cargo target dir: respect an ambient CARGO_TARGET_DIR, else the repo default.
slacomp="$repo_root/target/release/slacomp"
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    slacomp="$CARGO_TARGET_DIR/release/slacomp"
fi
(
    cd "$repo_root"
    CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$repo_root/target"} \
        cargo build --release -p kuna-slacomp --bin slacomp
)
[ -x "$slacomp" ] || die "slacomp binary not found at $slacomp"

export LC_ALL=C
export TZ=UTC

# --- double compile: determinism check --------------------------------------
"$slacomp" "$slaspec" "$first_sla"
"$slacomp" "$slaspec" "$second_sla"
cmp -s "$first_sla" "$second_sla" || \
    die "two slacomp compilations produced different bytes"

# --- three-part content gate --------------------------------------------------
sla_verify=$(python3 - "$first_sla" "$EXPECTED_SLA_FORMAT_VERSION" \
    "$EXPECTED_SLA_INFLATED_SHA" "$EXPECTED_SLA_INFLATED_SIZE" \
    "$EXPECTED_SLA_DEFLATED_SIZE" "$EXPECTED_SLA_SIZE_BAND_PCT" <<'PYEOF'
import hashlib, sys, zlib
path, want_ver, want_sha, want_inf, want_def, band = sys.argv[1:7]
want_ver, want_inf, want_def, band = int(want_ver), int(want_inf), int(want_def), float(band)
raw = open(path, "rb").read()
if raw[:3] != b"sla":
    print(f"FORMAT_VERSION bad magic {raw[:4]!r}"); sys.exit(1)
if raw[3] != want_ver:
    print(f"FORMAT_VERSION {raw[3]} != {want_ver}"); sys.exit(1)
body = zlib.decompress(raw[4:])
if len(body) != want_inf:
    print(f"inflated size {len(body)} != {want_inf}"); sys.exit(1)
got = hashlib.sha256(body).hexdigest()
if got != want_sha:
    print(f"inflated sha256 {got} != {want_sha}"); sys.exit(1)
delta = 100.0 * (len(raw) - want_def) / want_def
if abs(delta) > band:
    print(f"deflated size {len(raw)} off pin {want_def} by {delta:.3f}% (band {band}%)"); sys.exit(1)
print(f"OK deflated={len(raw)} ({delta:+.3f}%) inflated={len(body)}")
PYEOF
) || die "three-part .sla gate failed: $sla_verify"

mkdir -p "$output_dir"
install -m 0644 "$first_sla" "$output_dir/x86-64.sla"
install -m 0644 "$language_dir/x86-64.pspec" "$output_dir/x86-64.pspec"
install -m 0644 "$language_dir/x86-64-gcc.cspec" "$output_dir/x86-64-gcc.cspec"

sla_sha=$(file_sha256 "$output_dir/x86-64.sla")
sla_size=$(wc -c < "$output_dir/x86-64.sla" | tr -d '[:space:]')
echo "build_locked_x86_64_sla: OK (compiler=vendored Rust slacomp)"
echo "  oracle=$LOCKED_ORACLE"
echo "  sla_sha256=$sla_sha (bytes; gate=inflated stream)"
echo "  sla_size=$sla_size"
echo "  sla_inflated_sha256=$EXPECTED_SLA_INFLATED_SHA"
echo "  sla_inflated_size=$EXPECTED_SLA_INFLATED_SIZE"
echo "  pspec_sha256=$EXPECTED_PSPEC_SHA"
echo "  cspec_sha256=$EXPECTED_CSPEC_SHA"
echo "  ldefs_sha256=$EXPECTED_LDEFS_SHA"
