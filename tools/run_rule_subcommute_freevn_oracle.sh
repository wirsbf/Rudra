#!/usr/bin/env bash
# RULE-SUBCOMMUTE-FREEVN-0001 bilateral fixture runner (GEN5 archive shape).
#
# Oracle side : tests/oracle/rule_subcommute_freevn_1204.cc driven against the
#               locked Ghidra 12.0.4 cpp tree + BFD 2.38 headers; normal-mode
#               stdout archived at tests/oracle/rule_subcommute_freevn_1204.oracle.out
#               (sha-pinned below); trap mode takes LowlevelError rc 1 with
#               "Free varnode has multiple descendants" on stderr (form record
#               in the metadata, no golden — the crash-form pair is the
#               deliverable, both sides throw per varnode.cc:334-336).
# Rugra side  : current worktree lib (cargo build --lib) + the mirrored
#               tests/oracle/rule_subcommute_freevn_1204.rs.
# Comparand   : normal mode = byte-compare vs the archived oracle record;
#               trap mode = form assertions (Rugra rc 101 + the exact panic
#               site varnode.rs:2716; oracle re-verified live only under
#               RUDRA_FREEVN_ORACLE_RUN=1).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
fixture_cc="$repo_root/tests/oracle/rule_subcommute_freevn_1204.cc"
fixture_rs="$repo_root/tests/oracle/rule_subcommute_freevn_1204.rs"
oracle_record="$repo_root/tests/oracle/rule_subcommute_freevn_1204.oracle.out"
metadata="$repo_root/tests/oracle/rule_subcommute_freevn_1204.metadata.json"

fixture_cc_sha256=53a5bd4fd6424f71e707947c589bbd531e01aacb84b21229b0f6a3e2d31f6a1d
fixture_rs_sha256=2fd706e0288f137a8463d1011fea92a0e67e591e3189765f6e0dd7b7c407eaaa
oracle_record_sha256=5634e84db6b14ce5ada210e222641107bcd67264f884a80f62231fa0f019b75f

die() { echo "run_rule_subcommute_freevn_1204: FAIL: $*" >&2; exit 1; }

for f in "$fixture_cc" "$fixture_rs" "$oracle_record" "$metadata"; do
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
done
[[ $(sha256sum "$fixture_cc" | cut -d' ' -f1) == "$fixture_cc_sha256" ]] \
  || die "oracle fixture source drifted (re-pin per AGENTS.md fixture discipline)"
[[ $(sha256sum "$fixture_rs" | cut -d' ' -f1) == "$fixture_rs_sha256" ]] \
  || die "rust fixture source drifted"
[[ $(sha256sum "$oracle_record" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
  || die "archived oracle record drifted"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rugra-subcommute-freevn.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# ---- oracle comparand (archive or live) -----------------------------------
oracle_out="$workdir/oracle_normal.out"
if [[ ${RUDRA_FREEVN_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_FREEVN_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rugra-subcommute-1204}
  runner="$cache_root/rule_subcommute_freevn_1204_cpp"
  if [[ ! -x $runner ]]; then
    bfd_include=${RUDRA_FREEVN_BFD_INCLUDE:-/tmp/rugra-ghidra-bfd-2.38/usr/include}
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
  -o "$workdir/rule_subcommute_freevn_1204_rust"

"$workdir/rule_subcommute_freevn_1204_rust" normal \
  > "$workdir/rugra_normal.out" 2> "$workdir/rugra_normal.err"
[[ -s "$workdir/rugra_normal.err" ]] && die "rugra normal stderr non-empty"

# ---- compare: normal mode golden diff --------------------------------------
if cmp -s "$oracle_out" "$workdir/rugra_normal.out"; then
  echo "rule_subcommute_freevn_1204[normal]: MATCH (byte-identical, 13/13 cases)"
else
  echo "rule_subcommute_freevn_1204[normal]: MISMATCH"
  diff -u --label ghidra --label rugra "$oracle_out" "$workdir/rugra_normal.out" | head -40 >&2
  exit 1
fi

# ---- trap mode: crash-form comparison (no golden) --------------------------
set +e
"$workdir/rule_subcommute_freevn_1204_rust" trap_dupfree \
  > "$workdir/rugra_trap.out" 2> "$workdir/rugra_trap.err"
trap_rc=$?
set -e

[[ $trap_rc -eq 101 ]] || die "trap_dupfree: expected Rust panic rc=101, got $trap_rc"
grep -q "panicked at src/varnode.rs:2716" "$workdir/rugra_trap.err" \
  || die "trap_dupfree: panic site drift (expected varnode.rs:2716)"
grep -q "Free varnode has multiple descendants" "$workdir/rugra_trap.err" \
  || die "trap_dupfree: panic message drift (expected varnode.cc:336 text)"
[[ -s "$workdir/rugra_trap.out" ]] && die "trap_dupfree: stdout must be empty (crash before output)"

echo "rule_subcommute_freevn_1204[trap_dupfree]: FORM-LOCKED (Rugra panic rc=101 varnode.rs:2716 'Free varnode has multiple descendants' vs oracle LowlevelError rc=1 same message — varnode.cc:334-336 invariant preserved on both sides)"
echo "rule_subcommute_freevn_1204: PASS (oracle source: $oracle_source)"
