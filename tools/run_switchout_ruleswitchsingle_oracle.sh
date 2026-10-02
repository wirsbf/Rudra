#!/usr/bin/env bash
# SWITCHOUT-CLEAR-REMOVETABLE-0001 bilateral fixture runner (GEN5 archive shape).
#
# Oracle side : tests/oracle/switchout_ruleswitchsingle_1204.cc driven
#               against the locked Ghidra 12.0.4 cpp tree + BFD 2.38
#               headers; stdout/stderr archived at
#               tests/oracle/switchout_ruleswitchsingle_1204.oracle.{out,err}
#               (sha-pinned below). Live oracle re-verification under
#               RUDRA_SWITCHOUT_ORACLE_RUN=1 (see AGENTS.md oracle env note).
# Rugra side  : current worktree fast-release gen_decompile driver over the
#               banked single-target dispatch ELF (mirror arm), function
#               single_target_switch located by name via --list (index-stable
#               against future discovery-order changes), stdout compared to
#               the banked tests/oracle/switchout_ruleswitchsingle_1204.rudra.c.
# Comparand   : C body (from `int4 single_target_switch` to EOF) byte-equal
#               oracle-vs-rugra; warning-comment line byte-equal; oracle
#               stderr [BLOCKFLAGS]/[JT-REMAIN] are the direct observables of
#               funcdata_block.cc:73-76 (flag cleared, table gone).
# Fixture     : hand-written .S keeps the 8 statically-identical table
#               entries alive (pure-C switch forms are folded away by gcc
#               -O1/-O2/-Os — lane-proven), so BRANCHIND survives to
#               RuleSwitchSingle (ruleaction.cc:5412-5471), whose
#               removeJumpTable call is the fix seam.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
base="$repo_root/tests/oracle/switchout_ruleswitchsingle_1204"
fixture_asm="$base.S"
fixture_target_c="${base}_target.c"
fixture_sink_c="${base}_sink.c"
fixture_cc="$base.cc"
fixture_elf="$base.elf"
oracle_out="$base.oracle.out"
oracle_err="$base.oracle.err"
rudra_record="$base.rudra.c"
prefix_record="$base.prefix.c"

fixture_asm_sha256=58ce246067c22d33681f83cbd8f42b38facaef60977dfdf6a078c5348a96e568
fixture_target_c_sha256=85fc8ac458ce55d59ac319bf0b9733a5af99c82c86e7240f564f712b84294829
fixture_sink_c_sha256=8ce850602c67d2e4bb0996f2b4563567d078529095feac3f14a0944f1e8486d4
fixture_cc_sha256=04a4b994081a64c24419d02bf7605b400fa7d6ab8a0993fa85fc36b67f12897e
fixture_elf_sha256=dda2b61364f689538ce5ffe7c79f1ffc493d8b232684461a39c7967aad6efafd
oracle_out_sha256=2a920d4487514bcd3dad87fad5e6330f64ad65a10123004d18dbbc762ea55f87
oracle_err_sha256=d770faa770bccf106df521be04e0150c6cd051b44f03db69d7ee55ef16f3a3bb
rugra_record_sha256=4568eccb8f3739d1711dfcdcb06a0fbcf9b01e839ace083fdab2eb01a8aec1bf
prefix_record_sha256=8c275dd8d4136f3ad1fb81c4f7f4f8d096b9682509b441b7504f8f634705910e

die() { echo "run_switchout_ruleswitchsingle_1204: FAIL: $*" >&2; exit 1; }

check_sha() {
  local f="$1" want="$2"
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
  [[ $(sha256sum "$f" | cut -d' ' -f1) == "$want" ]] \
    || die "$(basename "$f") drifted (re-pin per AGENTS.md fixture discipline)"
}
check_sha "$fixture_asm"    "$fixture_asm_sha256"
check_sha "$fixture_target_c" "$fixture_target_c_sha256"
check_sha "$fixture_sink_c" "$fixture_sink_c_sha256"
check_sha "$fixture_cc"     "$fixture_cc_sha256"
check_sha "$fixture_elf"    "$fixture_elf_sha256"
check_sha "$oracle_out"     "$oracle_out_sha256"
check_sha "$oracle_err"     "$oracle_err_sha256"
check_sha "$rudra_record"   "$rugra_record_sha256"
check_sha "$prefix_record"  "$prefix_record_sha256"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rugra-switchout.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# Optional source-rebuild verification (toolchain-sensitive; never replaces
# the banked pinned ELF as the gate input).
if [[ ${RUDRA_SWITCHOUT_REBUILD:-0} == 1 ]]; then
  gcc -O2 -no-pie -o "$workdir/rebuilt.elf" "$fixture_asm" "$fixture_target_c" "$fixture_sink_c"
  [[ $(sha256sum "$workdir/rebuilt.elf" | cut -d' ' -f1) == "$fixture_elf_sha256" ]] \
    || die "rebuilt ELF sha drifted from pin (toolchain changed?)"
  echo "switchout_ruleswitchsingle_1204[rebuild]: deterministic ELF rebuild OK"
fi

# ---- oracle comparand (archive or live) -----------------------------------
live_oracle_err="$workdir/oracle_stderr.err"
if [[ ${RUDRA_SWITCHOUT_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_SWITCHOUT_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-switchout-1204}
  runner="$cache_root/switchout_ruleswitchsingle_1204_cpp"
  if [[ ! -x $runner ]]; then
    bfd_include=${RUDRA_SWITCHOUT_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
    [[ -d $bfd_include ]] || die "BFD include tree missing: $bfd_include (see AGENTS.md oracle env note)"
    mkdir -p "$cache_root/x"
    [[ $(git -C "$repo_root/ghidra" rev-parse HEAD) == "$oracle_commit" ]] \
      || die "ghidra checkout not at locked oracle commit"
    git -C "$repo_root/ghidra" archive --format=tar \
      --output="$cache_root/locked-cpp.tar" "$oracle_commit" \
      Ghidra/Features/Decompiler/src/decompile/cpp
    tar -xf "$cache_root/locked-cpp.tar" -C "$cache_root/x"
    cpp="$cache_root/x/Ghidra/Features/Decompiler/src/decompile/cpp"
    make --silent -C "$cpp" -j "$(nproc)" EXTRA= libdecomp.a
    g++ -std=c++11 -O2 -I"$bfd_include" -I"$cpp" "$fixture_cc" \
      "$cpp/libdecomp.cc" "$cpp/sleigh_arch.cc" "$cpp/inject_sleigh.cc" \
      "$cpp/bfd_arch.cc" "$cpp/loadimage_bfd.cc" "$cpp/libdecomp.a" \
      /usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so -lz -o "$runner"
  fi
  set +e
  "$runner" "$repo_root/sleigh_specs" "$fixture_elf" \
    > "$workdir/oracle_live.out" 2> "$workdir/oracle_live.err"
  oracle_rc=$?
  set -e
  [[ $oracle_rc -eq 0 ]] || die "live oracle run failed rc=$oracle_rc"
  cmp -s "$oracle_out" "$workdir/oracle_live.out" \
    || die "live oracle stdout drifted from the archived record (re-pin!)"
  cmp -s "$oracle_err" "$workdir/oracle_live.err" \
    || die "live oracle stderr drifted from the archived record (re-pin!)"
  cp "$workdir/oracle_live.err" "$live_oracle_err"
  oracle_source=live
else
  cp "$oracle_err" "$live_oracle_err"
  oracle_source=archive
fi

# ---- Rugra side -----------------------------------------------------------
bin_dir=${RUDRA_SWITCHOUT_BIN_DIR:-$repo_root/target/fast-release/examples}
gen_bin="$bin_dir/gen_decompile"
[[ -x $gen_bin ]] || die "gen_decompile missing under $bin_dir (build --profile fast-release --lib --examples)"

list_out=$(RUDRA_GEN_MIRROR=1 RUDRA_GEN_TIMEOUT_SECS=120 "$gen_bin" "$fixture_elf" --list 2>&1) \
  || die "driver --list failed"
index=$(sed -n 's/^\[GEN\] *\([0-9]*\) 0x *401166 *4 single_target_switch$/\1/p' <<<"$list_out")
[[ -n $index ]] || die "single_target_switch @0x401166 not discovered; listing: $list_out"

RUDRA_GEN_MIRROR=1 RUDRA_GEN_TIMEOUT_SECS=120 "$gen_bin" "$fixture_elf" --one "$index" \
  > "$workdir/rugra.out" 2> "$workdir/rugra.err" \
  || die "driver --one $index failed"

# Full-driver stdout vs the banked merged-tree record (byte-exact).
cmp -s "$rudra_record" "$workdir/rugra.out" \
  || die "rugra driver stdout drifted from banked .rugra.c (behavior change on this fixture!)"

# ---- decisive bilateral comparands ----------------------------------------
# 1. C body byte-equality oracle-vs-rugra (from the signature line to EOF).
sed -n '/^int4 single_target_switch/,$p' "$oracle_out" > "$workdir/oracle_body"
sed -n '/^int4 single_target_switch/,$p' "$workdir/rugra.out"  > "$workdir/rugra_body"
cmp -s "$workdir/oracle_body" "$workdir/rugra_body" \
  || die "C body mismatch oracle-vs-rugra"

# 2. The RuleSwitchSingle warning renders identically (modulo the 0x0040117a
#    address formatting difference the oracle header uses).
grep -q 'Switch with 1 destination removed at 0x0040117a : 8 cases all go to same destination' "$oracle_out" \
  || die "oracle record lost the warning line (re-pin!)"
grep -q 'Switch with 1 destination removed at 0x40117a: 8 cases all go to same destination' "$workdir/rugra.out" \
  || die "rugra output lost the warning line (RuleSwitchSingle no longer firing?)"

# 3. Oracle stderr observables: flag cleared + table gone (funcdata_block.cc:76).
grep -q '\[BLOCKFLAGS\] i=0 start=0x40116a flags=0x200 switch_out=0' "$live_oracle_err" \
  || die "oracle stderr [BLOCKFLAGS] switch_out=0 missing (re-pin!)"
grep -q '\[JT-REMAIN\] count=0' "$live_oracle_err" \
  || die "oracle stderr [JT-REMAIN] count=0 missing (re-pin!)"

# 4. Discriminating power: the banked pre-fix excerpt must NOT match the
#    current output (it is the degenerate switch skeleton the missing clear
#    produced) — the fixture stays able to detect the regression.
if cmp -s "$prefix_record" "$workdir/rugra.out"; then
  die "current output == pre-fix prefix record (SWITCHOUT regression: clear side dead?)"
fi

echo "switchout_ruleswitchsingle_1204[normal]: MATCH (C body byte-identical; flag cleared; table removed; pre-fix skeleton excluded)"
echo "switchout_ruleswitchsingle_1204: PASS (oracle source: $oracle_source; rugra index=$index)"
