#!/usr/bin/env bash
# PATHOSLOW-DIVCHAIN-B2-0001 bilateral fixture runner.
#
# Oracle side : tests/oracle/divchain_sqlite_bitvec_1204.cc (verbatim
#               GEN5-provenance golden_dump_1204.cc contract) run as
#               `one <spec_root> <libsqlite3> 55 <out.json>` against the
#               locked Ghidra 12.0.4 cpp tree + BFD 2.38 headers.
# Rugra side  : examples/gen_decompile.rs production diff-gate driver with
#               RUDRA_GEN_MIRROR=1 ... --one 55 (hermetic single function).
# Comparand   : tests/oracle/divchain_sqlite_bitvec_1204.oracle.json
#               (archived locked-oracle capture; body byte-compare).
#
# Modes:
#   default            compare Rugra body vs the archived oracle record
#                      (no oracle toolchain needed; the archive is pinned
#                      by sha256 in the metadata).
#   RUDRA_DIVCHAIN_ORACLE_RUN=1
#                      additionally re-run the oracle runner live. Uses a
#                      cached build when present, otherwise builds it from
#                      the repo ghidra/ checkout at the locked commit
#                      (requires /tmp/rugra-ghidra-bfd-2.38 include tree;
#                      rebuild that first when the host reboots).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6

fixture_cc="$repo_root/tests/oracle/divchain_sqlite_bitvec_1204.cc"
fixture_cc_sha256=c82028e4d7375b2ca0055aa5deb0fa17536cceaf437ccb45e5d25622823be93d
oracle_record="$repo_root/tests/oracle/divchain_sqlite_bitvec_1204.oracle.json"
oracle_record_sha256=65fbc51921b4649e67355b097ecc35360a32d853c12cc5267a462a21db108d54
expected_text_sha256=a50f9e6834bab69b8cc3bc286e6b57f74d54f2963db3ed28daa038d550623ecd

expected_binary_sha256=f5a7fc236f80f3185608d14e9f4dea3e3fd647582e123e8a00f253629fe16830
sqlite3_bin=${SQLITE3_BINARY:-/usr/lib/x86_64-linux-gnu/libsqlite3.so.0}

expected_name=sqlite3BitvecTestNotNull
expected_offset=127776
expected_size=195
one_index=55

spec_root="$repo_root/sleigh_specs"
spec_sha256() {
  case "$1" in
    x86-64.sla) echo 406bfa48bca420786dd61e2b739913c30f85822fff5af1b1a10578e3b83cf52a ;;
    x86-64.pspec) echo 3c3dab75a2ac0b98b0552856f690e613d661e0df7cf94d6252e5604d9821629f ;;
    x86-64-gcc.cspec) echo 5eaa848f3eba7ebd4023541f9f37645dae077e8426fb562592f398d599530a9e ;;
    x86.ldefs) echo b2aa14d94a6162844b18bf47f2aed8579bf90cef3459f6e322b9c1f58146098b ;;
    *) return 1 ;;
  esac
}

die() { echo "run_divchain_sqlite_bitvec_1204: FAIL: $*" >&2; exit 1; }

# ---- inputs ---------------------------------------------------------------
for f in "$fixture_cc" "$oracle_record"; do
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
done
[[ $(sha256sum "$fixture_cc" | cut -d' ' -f1) == "$fixture_cc_sha256" ]] \
  || die "oracle runner source drifted (re-pin per AGENTS.md fixture discipline)"
[[ $(sha256sum "$oracle_record" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
  || die "archived oracle record drifted"
[[ -f $sqlite3_bin ]] || die "corpus binary missing: $sqlite3_bin (set SQLITE3_BINARY)"
actual_binary_sha=$(sha256sum "$(readlink -f "$sqlite3_bin")" | cut -d' ' -f1)
[[ $actual_binary_sha == "$expected_binary_sha256" ]] \
  || die "corpus binary sha256=$actual_binary_sha expected $expected_binary_sha256"
for asset in x86-64.sla x86-64.pspec x86-64-gcc.cspec x86.ldefs; do
  want=$(spec_sha256 "$asset") || die "unknown asset $asset"
  got=$(sha256sum "$spec_root/$asset" | cut -d' ' -f1)
  [[ $got == "$want" ]] || die "spec asset $asset drifted: $got"
done

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rugra-divchain-b2.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# ---- oracle comparand (archive or live) -----------------------------------
oracle_json="$workdir/oracle_idx55.json"
if [[ ${RUDRA_DIVCHAIN_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_DIVCHAIN_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-divchain-b2-1204}
  runner="$cache_root/golden_dump_1204"
  if [[ ! -x $runner ]]; then
    bfd_include=${RUDRA_DIVCHAIN_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
    [[ -d $bfd_include ]] || die "BFD include tree missing: $bfd_include (see AGENTS.md oracle env note)"
    mkdir -p "$cache_root/x"
    git -C "$repo_root/ghidra" archive --format=tar \
      --output="$cache_root/locked-cpp.tar" "$oracle_commit" \
      Ghidra/Features/Decompiler/src/decompile/cpp
    [[ $(git -C "$repo_root/ghidra" rev-parse HEAD) == "$oracle_commit" ]] \
      || die "ghidra checkout not at locked oracle commit"
    tar -xf "$cache_root/locked-cpp.tar" -C "$cache_root/x"
    cpp="$cache_root/x/Ghidra/Features/Decompiler/src/decompile/cpp"
    make --silent -C "$cpp" -j "$(nproc)" EXTRA= libdecomp.a
    g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp" "$fixture_cc" \
      "$cpp/libdecomp.cc" "$cpp/sleigh_arch.cc" "$cpp/inject_sleigh.cc" \
      "$cpp/bfd_arch.cc" "$cpp/loadimage_bfd.cc" "$cpp/libdecomp.a" \
      /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so -lz -o "$runner"
  fi
  (cd "$cache_root" && "$runner" one "$spec_root" "$sqlite3_bin" "$one_index" "$oracle_json")
  oracle_source=live
else
  cp "$oracle_record" "$oracle_json"
  oracle_source=archive
fi

python3 - "$oracle_json" "$expected_name" "$expected_offset" "$expected_size" <<'PY'
import json, sys
record = json.load(open(sys.argv[1]))
assert record["name"] == sys.argv[2], f'name drift: {record["name"]}'
assert record["offset"] == int(sys.argv[3]), f'offset drift: {record["offset"]}'
assert record["size"] == int(sys.argv[4]), f'size drift: {record["size"]}'
assert record["status"] == "OK", f'status: {record["status"]}'
PY

# ---- Rugra side -----------------------------------------------------------
gen_bin=${RUDRA_DIVCHAIN_GEN_BIN:-}
if [[ -z $gen_bin ]]; then
  (cd "$repo_root" && cargo build --release --example gen_decompile >/dev/null)
  gen_bin="$repo_root/target/release/examples/gen_decompile"
fi
[[ -x $gen_bin ]] || die "gen_decompile binary missing"

rugra_out="$workdir/rugra_idx55.c"
RUDRA_GEN_MIRROR=1 RUDRA_GEN_TIMEOUT_SECS=120 \
  "$gen_bin" "$sqlite3_bin" --one "$one_index" > "$rugra_out" 2> "$workdir/rugra.err"

# ---- compare --------------------------------------------------------------
python3 - "$oracle_json" "$rugra_out" "$expected_text_sha256" "$expected_name" <<'PY'
import hashlib, json, sys
oracle = json.load(open(sys.argv[1]))
expected_sha = sys.argv[3]
name = sys.argv[4]
text = oracle["text"].strip("\n")
assert hashlib.sha256(text.encode()).hexdigest() == expected_sha, "oracle text sha drift"

lines = open(sys.argv[2]).read().split("\n")
header = next((l for l in lines if l.startswith("/* ---- 0x")), "")
assert name in header, f"rugra header does not name {name}: {header!r}"
start = next(i for i, l in enumerate(lines) if l.startswith("/* ---- 0x"))
body_start = next(i for i, l in enumerate(lines[start + 1:], start + 1)
                  if l.startswith(("typedef", "struct")) is False and l != "")
rugra_body = "\n".join(lines[body_start:]).rstrip("\n")
if rugra_body == text:
    print("divchain_sqlite_bitvec_1204: MATCH (byte-identical body)")
else:
    import difflib
    diff = list(difflib.unified_diff(text.split("\n"), rugra_body.split("\n"),
                                     "oracle", "rugra", lineterm=""))
    print(f"divchain_sqlite_bitvec_1204: MISMATCH ({len(diff)} diff lines)")
    for l in diff[:60]:
        print(l)
    sys.exit(1)
PY

echo "divchain_sqlite_bitvec_1204: PASS (oracle source: $oracle_source)"
