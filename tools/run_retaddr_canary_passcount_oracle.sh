#!/usr/bin/env bash
# retaddr_canary_passcount_1204 — bilateral multi-pass invariant gate for the
# httpd main dead-canary (RETADDR) family (HTTPDMAIN-RETADDR-FLOOR-0001).
#
# Mechanism B2 multi-pass fixture per the LOSS-247-v2 lesson: the dead-STORE
# survival boundary is pass-sensitive, so a single-pass fixture would pin the
# wrong boundary. This gate observes the FULL pipeline pass sequence on both
# sides (native OPACTION_DEBUG drill grammar) plus a seed A/B control arm,
# and checks the invariants recorded in
# tests/oracle/retaddr_canary_passcount_1204.metadata.json:
#
#   1. pass-count parity   — heritage brackets 9==9, restarts 0==0
#   2. conversion parity   — both sides run RuleStoreVarnode on the canary STORE
#   3. COPY-death parity   — both sides destroy the named-local COPY via
#                            RuleEarlyRemoval late in the run
#   4. web survival        — oracle ALIVE (registered MISMATCH on the canon
#                            face: rugra+typeseed DEAD, bound to
#                            HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001);
#                            rugra bare face (RUDRA_SEEDS=0) must be ALIVE
#                            (library-side chain oracle-faithful)
#   5. output face pins    — sha256 drift alarms for the three artifacts
#
# Exit codes: 0 = all invariants in expected state (registered divergence
# included); 1 = unexpected drift (a new divergence or a healed one — either
# way the metadata must be re-examined and re-pinned).
#
# Usage: bash tools/run_retaddr_canary_passcount_oracle.sh
#   (fixed target httpd/main @0x2b820; no arguments)
set -euo pipefail

repo_root=$(builtin cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=/dev/shm/rugra-tests/retaddr
mkdir -p "$work"

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
expected_oracle_drill_sha=4e0aac505419f280bb48e82c45492d1260ba028b0eabc2db729bc0d6ebba32f1
expected_rugra_drill_sha=7857da1216e35dd253df1b5c1b9e598fa3383b8fc1828b6ad0f1152cbb3a3f7c
expected_rugra_canon_sha=6154826afaf6ea8b0431c026f8b9829e0098fe95f1929fd41e05d331c2bffbec
expected_rugra_bare_sha=589411d06761e1c98251268993800adc690d5573570c58d52b37f6088f504c7f

fail=0
note() { echo "[RETADDR-GATE] $*"; }
bad()  { echo "[RETADDR-GATE] FAIL: $*" >&2; fail=1; }

# ---------- 0. oracle identity ----------
if [[ ! -d "$repo_root/ghidra" ]]; then
  echo "ghidra/ oracle tree missing" >&2; exit 2
fi
head=$(git -C "$repo_root/ghidra" rev-parse --short=8 HEAD 2>/dev/null || true)
if [[ "$head" != "${oracle_commit:0:8}" ]]; then
  echo "oracle HEAD $head != locked $oracle_commit" >&2; exit 2
fi

# ---------- 1. oracle drill (pinned capture via the verified stage-drill runner) ----------
note "capturing oracle stage drill (httpd main @0x2b820)..."
bash "$repo_root/tools/run_stage_drill_oracle.sh" httpd 0x2b820 main > "$work/gate_oracle_runner.log" 2>&1 || {
  echo "oracle stage drill runner failed:" >&2; cat "$work/gate_oracle_runner.log" >&2; exit 2;
}
oracle_drill=/dev/shm/rugra-tests/sb-drill/httpd.main.oracle.drill
[[ -f "$oracle_drill" ]] || { echo "oracle drill artifact missing: $oracle_drill" >&2; exit 2; }
oracle_sha=$(sha256sum "$oracle_drill" | awk '{print $1}')
[[ "$oracle_sha" == "$expected_oracle_drill_sha" ]] || bad "oracle drill sha $oracle_sha != pin $expected_oracle_drill_sha (oracle-side drift)"

# ---------- 2. rugra canon drill + canon/bare outputs ----------
bin_dir=${CARGO_TARGET_DIR:-$repo_root/target}/fast-release/examples
httpd_bin="$bin_dir/httpd_decompile"
[[ -x "$httpd_bin" ]] || { echo "build first: CARGO_TARGET_DIR=<dir> cargo build --profile fast-release --examples" >&2; exit 2; }

note "capturing rugra canon drill..."
( cd "$repo_root" && RUDRA_STAGE_DRILL=1 RUDRA_STAGE_FUNC=main \
    RUDRA_STAGE_DRILL_OUT="$work/gate_rugra_drill.txt" "$httpd_bin" > /dev/null 2>/dev/null ) \
  || { echo "rugra drill run failed" >&2; exit 2; }
rugra_sha=$(sha256sum "$work/gate_rugra_drill.txt" | awk '{print $1}')
[[ "$rugra_sha" == "$expected_rugra_drill_sha" ]] || bad "rugra drill sha $rugra_sha != pin $expected_rugra_drill_sha (canon-face pipeline drift)"

note "capturing rugra canon output..."
( cd "$repo_root" && "$httpd_bin" > "$work/gate_rugra_canon.c" 2>/dev/null ) \
  || { echo "rugra canon run failed" >&2; exit 2; }
canon_sha=$(sha256sum "$work/gate_rugra_canon.c" | awk '{print $1}')
[[ "$canon_sha" == "$expected_rugra_canon_sha" ]] || bad "rugra canon output sha $canon_sha != pin $expected_rugra_canon_sha"

note "capturing rugra bare face (RUDRA_SEEDS=0)..."
( cd "$repo_root" && RUDRA_SEEDS=0 "$httpd_bin" > "$work/gate_rugra_bare.c" 2>/dev/null ) \
  || { echo "rugra bare run failed" >&2; exit 2; }
bare_sha=$(sha256sum "$work/gate_rugra_bare.c" | awk '{print $1}')
[[ "$bare_sha" == "$expected_rugra_bare_sha" ]] || bad "rugra bare output sha $bare_sha != pin $expected_rugra_bare_sha"

# ---------- 3. invariants ----------
py_fail=$(python3 - "$oracle_drill" "$work/gate_rugra_drill.txt" "$work/gate_rugra_canon.c" "$work/gate_rugra_bare.c" "$repo_root" <<'PYEOF'
import re, sys

oracle_d, rugra_d, rugra_canon, rugra_bare, repo = sys.argv[1:6]
problems = []

def count(path, pat):
    # re.M: '$' must anchor per line (the drill records are one per line)
    return len(re.findall(pat, open(path, errors='replace').read(), re.M))

def extract_main_decl_and_stmt(path):
    """Return (has_in_FS_decl, has_canary_stmt) for main()."""
    lines = open(path, errors='replace').read().splitlines()
    start = None
    for i, l in enumerate(lines):
        if re.match(r'\s*\w[\w\s\*]*\bmain\s*\(', l) and ' apr_' not in l:
            start = i; break
    if start is None:
        return None, None
    depth = 0; started = False; body = []
    for l in lines[start:]:
        body.append(l)
        depth += l.count('{') - l.count('}')
        if '{' in l: started = True
        if started and depth == 0: break
    text = '\n'.join(body)
    return ('in_FS_OFFSET;' in text), ('(in_FS_OFFSET + 0x28)' in text)

# invariant 1: pass-count parity
o_h = count(oracle_d, r'^@BEGIN \d+ universal:fullloop:mainloop:heritage')
r_h = count(rugra_d, r'^@BEGIN \d+ universal:fullloop:mainloop:heritage')
o_h_empty = count(oracle_d, r'^@BEGIN \d+ universal:fullloop:mainloop:heritage empty')
r_h_empty = count(rugra_d, r'^@BEGIN \d+ universal:fullloop:mainloop:heritage empty')
o_dc = count(oracle_d, r'^@END \d+ universal:fullloop:mainloop:deadcode')
r_dc = count(rugra_d, r'^@END \d+ universal:fullloop:mainloop:deadcode')
o_r = count(oracle_d, r'@RESTART')
r_r = count(rugra_d, r'@RESTART')
print(f"heritage applications: oracle={o_h} (empty {o_h_empty}) rugra={r_h} (empty {r_h_empty}); "
      f"mainloop:deadcode applications: oracle={o_dc} rugra={r_dc}; restarts {o_r}/{r_r}")
if (o_h, o_h_empty, o_dc, o_r) != (r_h, r_h_empty, r_dc, r_r):
    problems.append(f"pass-count parity broken: heritage ({o_h},{o_h_empty}) vs ({r_h},{r_h_empty}), "
                    f"deadcode {o_dc} vs {r_dc}, restarts {o_r} vs {r_r}")
if o_h != 7 or o_h_empty != 5 or o_dc != 7 or o_r != 0:
    problems.append(f"oracle pass counts drifted from pin: heritage={o_h}/{o_h_empty} deadcode={o_dc} restarts={o_r}")

# invariant 2: canary STORE->COPY conversion on both sides (stack slot s0x...c0)
# (TYPESEEDARB repin: post-arbitration the canon drill carries the
#  oracle-identical id form :35 / u0x23e00(:31); the pre-arbitration ids
#  :32 / u0x1068 recorded the DEAD-web state)
o_conv = count(oracle_d, r's0xffffffffffffffc0\(0x0002b85a:35\) = u0x00023e00')
r_conv = count(rugra_d, r's0xffffffffffffffc0\(0x0012b85a:35\) = u0x00023e00')
print(f"storevarnode conversion: oracle={o_conv} rugra={r_conv}")
if not (o_conv >= 1 and r_conv >= 1):
    problems.append("RuleStoreVarnode canary conversion missing on a side "
                    f"(oracle={o_conv}, rugra={r_conv})")

# invariant 3: canary COPY destroyed by earlyremoval on both sides
o_copy_death = count(oracle_d, r'0x0002b85a:35: s0xffffffffffffffc0\(0x0002b85a:35\) = u0x00023e00[^\n]*\n\s+0x0002b85a:35: \*\*')
r_copy_death = count(rugra_d, r'0x0012b85a:35: s0xffffffffffffffc0\(0x0012b85a:35\) = u0x00023e00[^\n]*\n\s+0x0012b85a:35: \*\*')
print(f"canary COPY earlyremoval death: oracle={o_copy_death} rugra={r_copy_death}")
if not (o_copy_death >= 1 and r_copy_death >= 1):
    problems.append("canary COPY earlyremoval death missing on a side "
                    f"(oracle={o_copy_death}, rugra={r_copy_death})")

# invariant 4a: oracle LOAD survives (no destruction record for the canary LOAD)
o_load_death = count(oracle_d, r'0x0002b851:31: u0x00023e00[^\n]*\n\s+0x0002b851:31: \*\*')
print(f"oracle canary LOAD destruction records: {o_load_death}")
if o_load_death != 0:
    problems.append(f"oracle canary LOAD destroyed ({o_load_death}) - oracle boundary moved; re-read heritage/ruleaction chain")

# invariant 4b: rugra canon LOAD survives too (repinned MATCH arm:
# HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001 landed 2026-09-27 - the canon
# face keeps the web ALIVE; a NEW destruction record means the arbitration
# regressed, a missing one is the expected state)
r_load_death = count(rugra_d, r'0x0012b851:31: u0x00023e00[^\n]*\n\s+0x0012b851:31: \*\*')
print(f"rugra canon canary LOAD destruction records: {r_load_death} (expected 0 - MATCH arm)")
if r_load_death != 0:
    problems.append("rugra canon canary LOAD destroyed again - TYPESEED-LOCK-ARBITRATION regressed (web must stay ALIVE)")

# invariant 4c: both faces keep the statement (golden parity on canon,
# library-chain faithfulness on bare)
bare_decl, bare_stmt = extract_main_decl_and_stmt(rugra_bare)
canon_decl, canon_stmt = extract_main_decl_and_stmt(rugra_canon)
golden = open(f"{repo}/tests/golden/ghidra_httpd_1204.c", errors='replace').read()
g_decl = 'long in_FS_OFFSET;' in golden
g_stmt = 'local_40 = *(undefined8 *)(in_FS_OFFSET + 0x28);' in golden
print(f"canary statement: golden={g_stmt} rugra_canon={canon_stmt} rugra_bare={bare_stmt}")
if not g_stmt:
    problems.append("canon golden no longer carries the canary statement - golden drift")
if bare_stmt is not True:
    problems.append(f"rugra bare face lost the canary statement ({bare_stmt}) - library-side chain regressed (this is the oracle-faithful arm)")
if canon_stmt is not True:
    problems.append("rugra canon face lost the canary statement - web-death regression (TYPESEED-LOCK-ARBITRATION must keep it ALIVE)")

sys.exit(1 if problems else 0)
PYEOF
) || fail=1

# ---------- verdict ----------
if [[ $fail -ne 0 ]]; then
  echo "[RETADDR-GATE] FAIL — unexpected state (see above)" >&2
  exit 1
fi
note "PASS — pass-count parity 7/7+0/0, conversion/death parity hold, oracle web ALIVE, canon-face web ALIVE (TYPESEED-LOCK-ARBITRATION landed, repinned MATCH), bare-face ALIVE"
