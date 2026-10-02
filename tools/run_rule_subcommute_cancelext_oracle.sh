#!/usr/bin/env bash
# RULE-SUBCOMMUTE-CANCELEXT-0001 bilateral fixture runner (GEN5 archive shape).
#
# Oracle side : tests/oracle/rule_subcommute_cancelext_1204.cc driven
#               against the locked Ghidra 12.0.4 cpp tree + BFD 2.38
#               headers; normal-mode stdout archived at
#               tests/oracle/rule_subcommute_cancelext_1204.oracle.out
#               (sha-pinned below). Live oracle re-verification under
#               RUDRA_RULEADJ_ORACLE_RUN=1 (see AGENTS.md oracle env note).
# Rugra side  : current worktree lib (cargo build --lib) + the mirrored
#               tests/oracle/rule_subcommute_cancelext_1204.rs.
# Comparand   : normal mode = byte-compare vs the archived oracle record.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
fixture_cc="$repo_root/tests/oracle/rule_subcommute_cancelext_1204.cc"
fixture_rs="$repo_root/tests/oracle/rule_subcommute_cancelext_1204.rs"
oracle_record="$repo_root/tests/oracle/rule_subcommute_cancelext_1204.oracle.out"

fixture_cc_sha256=52cdaef1d29f0703de2b49595122182192f75fd4b113e099e82c287026797583
fixture_rs_sha256=05b07aaf80be3c9f6ad7f5663ec79fd71930861655e6695e0a1269698d60c3c3
oracle_record_sha256=894a00dc98d37930450c543b5332e6e6f9bcdbe8b5bf2b811c9a080ce8a506f7

die() { echo "run_rule_subcommute_cancelext_1204: FAIL: $*" >&2; exit 1; }

for f in "$fixture_cc" "$fixture_rs" "$oracle_record"; do
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
done
[[ $(sha256sum "$fixture_cc" | cut -d' ' -f1) == "$fixture_cc_sha256" ]] \
  || die "oracle fixture source drifted (re-pin per AGENTS.md fixture discipline)"
[[ $(sha256sum "$fixture_rs" | cut -d' ' -f1) == "$fixture_rs_sha256" ]] \
  || die "rust fixture source drifted"
[[ $(sha256sum "$oracle_record" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
  || die "archived oracle record drifted"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rugra-cancelext.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# ---- oracle comparand (archive or live) -----------------------------------
oracle_out="$workdir/oracle_normal.out"
if [[ ${RUDRA_RULEADJ_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_RULEADJ_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-subcommute-1204}
  runner="$cache_root/rule_subcommute_cancelext_1204_cpp"
  if [[ ! -x $runner ]]; then
    bfd_include=${RUDRA_RULEADJ_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
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
  "$runner" "$repo_root/sleigh_specs" "$repo_root/examples/curl" normal \
    > "$oracle_out" 2> "$workdir/oracle.err"
  oracle_rc=$?
  set -e
  [[ $oracle_rc -eq 0 ]] || die "live oracle normal run failed rc=$oracle_rc"
  cmp -s "$oracle_record" "$oracle_out" \
    || die "live oracle output drifted from the archived record (re-pin!)"
  oracle_source=live
else
  cp "$oracle_record" "$oracle_out"
  oracle_source=archive
fi

# ---- Rugra side -----------------------------------------------------------
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
(cd "$repo_root" && CARGO_TARGET_DIR="$target_dir" cargo build --offline --locked --quiet --lib)
rustc --edition=2021 "$fixture_rs" \
  --extern rugra="$target_dir/debug/librugra.rlib" \
  -L "dependency=$target_dir/debug/deps" \
  -o "$workdir/rule_subcommute_cancelext_1204_rust"

"$workdir/rule_subcommute_cancelext_1204_rust" normal \
  > "$workdir/rugra_normal.out" 2> "$workdir/rugra_normal.err"
[[ -s "$workdir/rugra_normal.err" ]] && die "rugra normal stderr non-empty"

# ---- compare: normal mode golden diff --------------------------------------
if cmp -s "$oracle_out" "$workdir/rugra_normal.out"; then
  echo "rule_subcommute_cancelext_1204[normal]: MATCH (byte-identical, 9/9 cases)"
else
  echo "rule_subcommute_cancelext_1204[normal]: MISMATCH"
  diff -u --label ghidra --label rugra "$oracle_out" "$workdir/rugra_normal.out" | head -40 >&2
  exit 1
fi
echo "rule_subcommute_cancelext_1204: PASS (oracle source: $oracle_source)"
