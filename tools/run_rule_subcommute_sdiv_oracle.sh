#!/usr/bin/env bash
# RULE-SUBCOMMUTE-SDIV-0001 bilateral fixture runner (GEN5 archive shape).
#
# Oracle side : tests/oracle/rule_subcommute_sdiv_1204.cc driven against the
#               locked Ghidra 12.0.4 cpp tree + BFD 2.38 headers; normal-mode
#               stdout archived at tests/oracle/rule_subcommute_sdiv_1204.oracle.out
#               (sha-pinned below); trap modes take SIGFPE rc 136 (form record
#               in the metadata, no golden — KUNAUB-SDIV-0001 ruling (a)).
# Rudra side  : current worktree lib (cargo build --lib) + the mirrored
#               tests/oracle/rule_subcommute_sdiv_1204.rs.
# Comparand   : normal mode = byte-compare vs the archived oracle record;
#               trap modes = form assertions (Rudra rc 101 + the exact
#               opbehavior panic messages; oracle re-verified live only under
#               RUDRA_SUBCOMMUTE_ORACLE_RUN=1).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
fixture_cc="$repo_root/tests/oracle/rule_subcommute_sdiv_1204.cc"
fixture_rs="$repo_root/tests/oracle/rule_subcommute_sdiv_1204.rs"
oracle_record="$repo_root/tests/oracle/rule_subcommute_sdiv_1204.oracle.out"
metadata="$repo_root/tests/oracle/rule_subcommute_sdiv_1204.metadata.json"

fixture_cc_sha256=1d4da30ea53f864a13b2ad81e80f7603de2c7b9c2f3752e34aa8f144bcad0602
fixture_rs_sha256=c41f4d86447e46e84d353f2520f1e790dcb3c884e4b6c3cffbae9436ef3d899c
oracle_record_sha256=28d3bcd15d8110fdf5cfdaa8c86d7e6d37e63fb26f5414d4a39f64c5a84fe4dd

die() { echo "run_rule_subcommute_sdiv_1204: FAIL: $*" >&2; exit 1; }

for f in "$fixture_cc" "$fixture_rs" "$oracle_record" "$metadata"; do
  [[ -f $f && ! -L $f ]] || die "required input missing or symlink: $f"
done
[[ $(sha256sum "$fixture_cc" | cut -d' ' -f1) == "$fixture_cc_sha256" ]] \
  || die "oracle fixture source drifted (re-pin per AGENTS.md fixture discipline)"
[[ $(sha256sum "$fixture_rs" | cut -d' ' -f1) == "$fixture_rs_sha256" ]] \
  || die "rust fixture source drifted"
[[ $(sha256sum "$oracle_record" | cut -d' ' -f1) == "$oracle_record_sha256" ]] \
  || die "archived oracle record drifted"

workdir=$(mktemp -d "${TMPDIR:-/tmp}/rudra-subcommute-sdiv.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# ---- oracle comparand (archive or live) -----------------------------------
oracle_out="$workdir/oracle_normal.out"
if [[ ${RUDRA_SUBCOMMUTE_ORACLE_RUN:-0} == 1 ]]; then
  cache_root=${RUDRA_SUBCOMMUTE_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/rudra-subcommute-1204}
  runner="$cache_root/rule_subcommute_sdiv_1204_cpp"
  if [[ ! -x $runner ]]; then
    bfd_include=${RUDRA_SUBCOMMUTE_BFD_INCLUDE:-/tmp/rudra-ghidra-bfd-2.38/usr/include}
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
  oracle_source=live
else
  cp "$oracle_record" "$oracle_out"
  oracle_source=archive
fi

# ---- Rudra side -----------------------------------------------------------
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
(cd "$repo_root" && CARGO_TARGET_DIR="$target_dir" cargo build --offline --locked --quiet --lib)
rustc --edition=2021 "$fixture_rs" \
  --extern rudra="$target_dir/debug/librudra.rlib" \
  -L "dependency=$target_dir/debug/deps" \
  -o "$workdir/rule_subcommute_sdiv_1204_rust"

"$workdir/rule_subcommute_sdiv_1204_rust" normal \
  > "$workdir/rudra_normal.out" 2> "$workdir/rudra_normal.err"
[[ -s "$workdir/rudra_normal.err" ]] && die "rudra normal stderr non-empty"

# ---- compare: normal mode golden diff --------------------------------------
if cmp -s "$oracle_out" "$workdir/rudra_normal.out"; then
  echo "rule_subcommute_sdiv_1204[normal]: MATCH (byte-identical, 16/16 cases)"
else
  echo "rule_subcommute_sdiv_1204[normal]: MISMATCH"
  diff -u --label ghidra --label rudra "$oracle_out" "$workdir/rudra_normal.out" | head -40 >&2
  exit 1
fi

# ---- trap modes: crash-form comparison (no golden, KUNASDIV precedent) ----
set +e
"$workdir/rule_subcommute_sdiv_1204_rust" trap_sdiv \
  > "$workdir/rudra_trap_sdiv.out" 2> "$workdir/rudra_trap_sdiv.err"
trap_sdiv_rc=$?
"$workdir/rule_subcommute_sdiv_1204_rust" trap_srem \
  > "$workdir/rudra_trap_srem.out" 2> "$workdir/rudra_trap_srem.err"
trap_srem_rc=$?
set -e

[[ $trap_sdiv_rc -eq 101 ]] || die "trap_sdiv: expected Rust panic rc=101, got $trap_sdiv_rc"
grep -q "attempt to divide with overflow" "$workdir/rudra_trap_sdiv.err" \
  || die "trap_sdiv: panic form drift (missing 'attempt to divide with overflow')"
[[ -s "$workdir/rudra_trap_sdiv.out" ]] && die "trap_sdiv: stdout must be empty (crash before output)"
[[ $trap_srem_rc -eq 101 ]] || die "trap_srem: expected Rust panic rc=101, got $trap_srem_rc"
grep -q "attempt to calculate the remainder with overflow" "$workdir/rudra_trap_srem.err" \
  || die "trap_srem: panic form drift (missing 'attempt to calculate the remainder with overflow')"
[[ -s "$workdir/rudra_trap_srem.out" ]] && die "trap_srem: stdout must be empty"

echo "rule_subcommute_sdiv_1204[trap_sdiv]: FORM-LOCKED (Rudra panic rc=101 'attempt to divide with overflow' vs oracle SIGFPE rc=136 — KUNAUB-SDIV-0001 ruling (a))"
echo "rule_subcommute_sdiv_1204[trap_srem]: FORM-LOCKED (Rudra panic rc=101 'attempt to calculate the remainder with overflow' vs oracle SIGFPE rc=136)"
echo "rule_subcommute_sdiv_1204: PASS (oracle source: $oracle_source)"
