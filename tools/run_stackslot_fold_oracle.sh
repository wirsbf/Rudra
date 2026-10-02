#!/usr/bin/env bash
set -euo pipefail

# HTTPD-STACKSLOT-FOLD-0001 oracle runner: spacebase-relative STORE/LOAD
# stack-space reindex regression.  The bilateral comparand evidence lives
# in the pinned excerpts (tests/oracle/stackslot_fold_1204.ghidra.c from
# the headless golden tests/golden/ghidra_httpd_1204.c vs
# tests/oracle/stackslot_fold_1204.rugra.c) and the deterministic
# regression driver examples/stackfold_dbg.rs, which re-runs the
# ap_parse_vhost_addrs pipeline with the canonical Architecture attached
# and fails unless every in_RSP-chained LOAD/STORE folded (census under the
# canon cspec arch, loop-2 active: surviving=9 register-pointer/stack-address
# survivors, in_RSP-chained=0).  The per-function B2 status stays MISMATCH
# with the registered param-inference/deref/loop-rotation residual
# families; this runner guards the fold observable itself (in_RSP census
# 148 -> 0).

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/stackslot_fold_1204.metadata.json"
ghidra_excerpt="$repo_root/tests/oracle/stackslot_fold_1204.ghidra.c"
rugra_excerpt="$repo_root/tests/oracle/stackslot_fold_1204.rugra.c"
golden="$repo_root/tests/golden/ghidra_httpd_1204.c"
golden_provenance="$repo_root/tests/golden/ghidra_httpd_1204.provenance.json"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
for path in "$ghidra_excerpt" "$rugra_excerpt" "$golden" "$golden_provenance" \
  "$repo_root/examples/httpd" "$repo_root/examples/stackfold_dbg.rs"; do
  if [[ ! -f "$path" ]]; then
    echo "missing comparand asset: $path" >&2
    exit 1
  fi
done

python3 -I -S - "$metadata" "$ghidra_excerpt" "$rugra_excerpt" "$golden" \
  "$golden_provenance" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name,
    ghidra_excerpt_name,
    rugra_excerpt_name,
    golden_name,
    golden_provenance_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))

if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle tag/commit does not match runner")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


expected = {
    "ghidra_excerpt_sha256": digest(pathlib.Path(ghidra_excerpt_name)),
    "rugra_excerpt_sha256": digest(pathlib.Path(rugra_excerpt_name)),
    "golden_sha256": digest(pathlib.Path(golden_name)),
    "golden_provenance_sha256": digest(pathlib.Path(golden_provenance_name)),
}
comparand = metadata["comparand"]
for key, actual in expected.items():
    pinned = comparand.get(key)
    if pinned != actual:
        raise SystemExit(f"{key} mismatch: metadata={pinned} actual={actual}")

fingerprint = "sha256:" + hashlib.sha256(metadata["input"].encode()).hexdigest()
if metadata["input_fingerprint"] != fingerprint:
    raise SystemExit("input fingerprint mismatch")
PY

# 2026-09-26 SLEIGHP3 (d8c525ed): the stage root was a stale hardcoded
# /home/wirs/.cache (unwritable on other machines, mechanism-F style path
# hardcode). Portable form: XDG_CACHE_HOME/HOME, overridable for /dev/shm
# staging.
stage_root="${RUDRA_FIXTURE_STAGE:-${XDG_CACHE_HOME:-$HOME/.cache}}"
mkdir -p "$stage_root"
oracle_tmp=$(mktemp -d "$stage_root/rugra-stackslot-fold-1204.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$stage_root"/rugra-stackslot-fold-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# The deterministic driver runs in release mode, matching the E2E gate
# configuration every stackslot_fold observation was captured with (the
# httpd/curl gates are release binaries).  Note: debug builds additionally
# trap a pre-existing i32 size sign overflow in scope_local_find_overlap
# (funcdata.rs:173, introduced with 38881244) on this corpus; that overflow
# is a src-side gap outside this fixture's write-set and is registered in
# the metadata residuals, not papered over here.
fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --release --offline --locked --quiet \
  --manifest-path "$repo_root/Cargo.toml" --example stackfold_dbg
driver="$fixture_target/release/examples/stackfold_dbg"
if [[ ! -f "$driver" ]]; then
  echo "cargo build did not produce the stackfold_dbg driver" >&2
  exit 1
fi

cd "$repo_root"
set +e
"$driver" >"$oracle_tmp/driver.stdout" 2>"$oracle_tmp/driver.stderr"
driver_rc=$?
set -e
if [[ $driver_rc -ne 0 ]]; then
  echo "stackfold_dbg driver failed (rc=$driver_rc)" >&2
  cat "$oracle_tmp/driver.stderr" >&2
  exit 1
fi
if ! grep -q '^total surviving LOAD/STORE: 9$' "$oracle_tmp/driver.stderr"; then
  echo "fold census regression: expected exactly 9 surviving LOAD/STORE" >&2
  grep '^total surviving LOAD/STORE' "$oracle_tmp/driver.stderr" >&2 || true
  exit 1
fi
if ! grep -q '^STACKFOLD FIXTURE PASS: surviving=9 in_RSP-chained=0$' "$oracle_tmp/driver.stderr"; then
  echo "fold assertion did not pass (expected surviving=9 in_RSP-chained=0)" >&2
  exit 1
fi

grep '^total surviving LOAD/STORE' "$oracle_tmp/driver.stderr"
grep '^STACKFOLD FIXTURE PASS' "$oracle_tmp/driver.stderr"
# STACKFOLD-FIXTURE-F6DC-BREAK-0001: census re-observed under the canon
# cspec-bearing arch (ActionRestrictLocal loop-2 active) — surviving=9
# (param-register pointer chains + RBP-derived stack-address values), the
# loop-1-era "surviving=1" pin retired; the guarded fold observable is
# unchanged: zero in_RSP-chained survivors (E2E in_RSP census 148 -> 0).
printf 'stackslot_fold_1204: fold observable guarded (in_RSP census 0; 9 surviving register-pointer/stack-address LOAD/STOREs, zero RSP chains); per-function B2 stays MISMATCH with registered residuals\n'
