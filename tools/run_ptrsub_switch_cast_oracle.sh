#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail
umask 077

# Bilateral runner for PTRSUB-SWITCH-CAST-RESIDUAL-0001 (phase B: apply-side
# gaps fixed).  A successful run verifies that both sides produced their
# pinned byte streams and that the two streams are byte-identical
# (overall=MATCH); under MATCH any raw difference, and any registered
# known_raw_differences entry, is a failure.
runner_fd=/proc/$$/fd/3
if [[ ${1:-} != --captured ]]; then
  case ${1:-} in
    "") mode=normal ;;
    --ghidra-only) mode=ghidra-only ;;
    --validate-only) mode=validate-only ;;
    *)
      echo "usage: ${BASH_SOURCE[0]} [--ghidra-only|--validate-only]" >&2
      exit 2
      ;;
  esac
  if [[ -L ${BASH_SOURCE[0]} || ! -f ${BASH_SOURCE[0]} ]]; then
    echo "runner entrypoint must be a regular non-symlink file" >&2
    exit 1
  fi
  runner_path=$(/usr/bin/readlink -f "${BASH_SOURCE[0]}")
  repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_path")/.." && builtin pwd -P)
  exec 3<"$runner_path"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd" \
    --captured "$repo_root" "$mode"
fi

if [[ $# -ne 3 ]]; then
  echo "invalid captured invocation" >&2
  exit 2
fi
repo_root=$2
mode=$3
runner_source=$(/usr/bin/readlink -f "$runner_fd")
expected_runner="$repo_root/tools/run_ptrsub_switch_cast_oracle.sh"
if [[ "$runner_source" != "$expected_runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "captured runner identity mismatch" >&2
  exit 1
fi

metadata="$repo_root/tests/oracle/ptrsub_switch_cast_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/ptrsub_switch_cast_1204.cc"
rust_fixture="$repo_root/tests/oracle/ptrsub_switch_cast_1204.rs"
ghidra_entry="$repo_root/ghidra"
ghidra_root=$(/usr/bin/readlink -f "$ghidra_entry")
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6

for path in "$metadata" "$cpp_fixture" "$rust_fixture"; do
  if [[ ! -e "$path" || -L "$path" ]]; then
    echo "required evidence input is missing or a symlink: $path" >&2
    exit 1
  fi
done
if [[ -z "$ghidra_root" || ! -d "$ghidra_root" ]]; then
  echo "ghidra entrypoint must resolve to a directory: $ghidra_entry" >&2
  exit 1
fi

host_git=$(/usr/bin/readlink -f /usr/bin/git)
host_python=$(/usr/bin/readlink -f /usr/bin/python3)
host_cxx=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar=$(/usr/bin/readlink -f /usr/bin/ar)
host_make=$(/usr/bin/readlink -f /usr/bin/make)
host_cargo=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc=$(/usr/bin/readlink -f /usr/bin/rustc)
host_flock=$(/usr/bin/readlink -f /usr/bin/flock)
for tool in "$host_git" "$host_python" "$host_cxx" "$host_cc" "$host_ar" \
  "$host_make" "$host_cargo" "$host_rustc" "$host_flock"; do
  if [[ ! -x "$tool" || -L "$tool" ]]; then
    echo "required tool must resolve to an executable regular file: $tool" >&2
    exit 1
  fi
done

git_clean() {
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 "$host_git" "$@"
}

reject_replace_refs() {
  local repository=$1
  local refs
  refs=$(git_clean -C "$repository" for-each-ref --format='%(refname)' refs/replace/)
  if [[ -n "$refs" ]]; then
    echo "Git replace refs are forbidden in $repository" >&2
    exit 1
  fi
}

reject_replace_refs "$repo_root"
reject_replace_refs "$ghidra_root"
if [[ "$(git_clean -C "$ghidra_root" rev-parse HEAD)" != "$oracle_commit" || \
      "$(git_clean -C "$ghidra_root" rev-parse "$oracle_tag^{commit}")" != "$oracle_commit" || \
      "$(git_clean -C "$ghidra_root" rev-parse "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")" != "$oracle_cpp_tree" || \
      "$(git_clean -C "$ghidra_root" rev-parse "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if [[ -n "$(git_clean -C "$ghidra_root" status --porcelain --untracked-files=no -- Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

run_parent="$repo_root/target/oracle-runs"
/usr/bin/mkdir -p "$run_parent"
run_root=$(/usr/bin/mktemp -d "$run_parent/ptrsub-switch-cast.XXXXXX")
cleanup() {
  if [[ -n ${run_root:-} && "$run_root" == "$run_parent"/ptrsub-switch-cast.* && -d "$run_root" ]]; then
    /usr/bin/find "$run_root" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM
/usr/bin/mkdir -p "$run_root/tmp" "$run_root/oracle" "$run_root/rudra" \
  "$run_root/evidence/tests/oracle"

# Freeze every mutable input before validating any content.
/usr/bin/cp -- "$metadata" "$run_root/evidence/metadata.json"
/usr/bin/cp -- "$cpp_fixture" \
  "$run_root/evidence/tests/oracle/ptrsub_switch_cast_1204.cc"
/usr/bin/cp -- "$rust_fixture" \
  "$run_root/evidence/tests/oracle/ptrsub_switch_cast_1204.rs"
metadata="$run_root/evidence/metadata.json"
cpp_fixture="$run_root/evidence/tests/oracle/ptrsub_switch_cast_1204.cc"
rust_fixture="$run_root/evidence/tests/oracle/ptrsub_switch_cast_1204.rs"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$repo_root" "$runner_source" "$run_root/evidence" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
runner = pathlib.Path(sys.argv[3])
evidence = pathlib.Path(sys.argv[4])
meta = json.loads(metadata_path.read_text())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected!r}, got {actual!r}")

require("schema", meta["schema_version"], 2)
require("fixture", meta["fixture_id"], "PTRSUB-SWITCH-CAST-0001")
require("overall status", meta["overall_status"], "MATCH")
if meta.get("known_raw_differences"):
    raise SystemExit("MATCH metadata may not carry known_raw_differences")
require("oracle commit", meta["oracle"]["commit"], "e40ed13014025f82488b1f8f7bca566894ac376b")
require("oracle tag", meta["oracle"]["tag"], "Ghidra_12.0.4_build")
require("oracle cpp tree", meta["oracle"]["decompiler_cpp_tree"], "b02e230a539c65de14e50f357d0ba834d8184f4f")
require("oracle Makefile blob", meta["oracle"]["decompiler_makefile_blob"], "ca0719fa5f17aabd14c52f40ed8b030f54d2aac6")
require("runner hash", sha(runner), meta["comparand"]["runner_sha256"])
expected_fixtures = [
    "tests/oracle/ptrsub_switch_cast_1204.cc",
    "tests/oracle/ptrsub_switch_cast_1204.rs",
]
require("fixture set", sorted(meta["comparand"]["fixture_sha256"]), sorted(expected_fixtures))
for relative, expected in meta["comparand"]["fixture_sha256"].items():
    require(f"fixture {relative}", sha(evidence / relative), expected)
require("record count", meta["expected_results"]["record_count"], 21)
require("raw diff labels", meta["expected_results"]["raw_diff_labels"], ["ghidra.stdout", "rudra.stdout"])
require("exit codes", meta["expected_results"]["exit_codes"], {
    "ghidra": 0, "rugra": 0,
})
if "PENDING" in metadata_path.read_text():
    raise SystemExit("committed evidence metadata may not contain PENDING")
PY

for binding in \
  coreaction.cc:a392076ad23ddad3350e0fe7a2ebe96a8868f74b \
  op.hh:7e516fdf57185c74ea4efac8d9d3b324f259ade8 \
  typeop.cc:5197e3eefd185ed39c58e65af0687d605e34ec5e \
  typeop.hh:90ac4ed35194c5fd9bbb86759481c89a5388cb52 \
  varnode.cc:a04614c582a1fd987d615dcec4a8b47d3501f95f \
  varnode.hh:b78368fc8c3fbdda2a419122b759b4dcd44fe8d2 \
  variable.hh:5e833b633aa81b169a27273aba587906704e5a91 \
  cast.cc:2f3590aee76b84d2cf398b60e66e80639111eb4c \
  printc.cc:dfdc6b4bed7226110f0696c85e31a1f12d066b2d; do
  file=${binding%%:*}
  expected=${binding#*:}
  actual=$(git_clean -C "$ghidra_root" rev-parse \
    "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/$file")
  if [[ "$actual" != "$expected" ]]; then
    echo "locked oracle source blob mismatch: $file" >&2
    exit 1
  fi
done

if [[ "$mode" == validate-only ]]; then
  echo "PTRSUB-SWITCH-CAST evidence pins validated; overall=MATCH (phase B fixed)"
  exit 0
fi

uid=$(/usr/bin/id -u)
user_home=$(/usr/bin/getent passwd "$uid" | /usr/bin/cut -d: -f6)
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "unable to resolve user home" >&2
  exit 1
fi

git_clean -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$run_root/oracle"
oracle_cpp="$run_root/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_root/tmp" \
  /usr/bin/timeout 600 "$host_make" --no-print-directory -s -C "$oracle_cpp" -j2 \
  "CXX=$host_cxx -std=c++11" "CC=$host_cc" "AR=$host_ar" EXTRA= libdecomp.a \
  >"$run_root/make.stdout" 2>"$run_root/make.stderr"
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "locked oracle build did not produce libdecomp.a" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_root/tmp" \
  /usr/bin/timeout 600 "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
  "$oracle_cpp/libdecomp.a" -lz -o "$run_root/ptrsub_sw_cpp" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"

for run in 1 2; do
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/ptrsub_sw_cpp" \
    >"$run_root/ghidra.$run.stdout" 2>"$run_root/ghidra.$run.stderr"
done
if ! /usr/bin/cmp -s "$run_root/ghidra.1.stdout" "$run_root/ghidra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/ghidra.1.stderr" "$run_root/ghidra.2.stderr"; then
  echo "Ghidra fixture output is nondeterministic" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/ghidra.1.stdout" "$run_root/ghidra.1.stderr" <<'PY'
import hashlib, json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = pathlib.Path(sys.argv[2])
err = pathlib.Path(sys.argv[3])
exp = meta["expected_results"]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sha(out) != exp["ghidra_stdout_sha256"] or sha(err) != exp["ghidra_stderr_sha256"]:
    raise SystemExit("Ghidra output hash mismatch")
if err.read_bytes():
    raise SystemExit("Ghidra stderr must be empty")
lines = out.read_text().splitlines()
if len(lines) != exp["record_count"] or not out.read_bytes().endswith(b"\n"):
    raise SystemExit("Ghidra record count/newline mismatch")
PY

if [[ "$mode" == ghidra-only ]]; then
  echo "PTRSUB-SWITCH-CAST Ghidra oracle verified records=21 overall=MATCH"
  exit 0
fi

snapshot="$run_root/rudra"
git_clean -C "$repo_root" archive HEAD | /usr/bin/tar -xf - -C "$snapshot"
/usr/bin/mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/cp -- "$rust_fixture" "$snapshot/tests/oracle/ptrsub_switch_cast_1204.rs"
/usr/bin/ln -s "$oracle_cpp" "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

cargo_target="$repo_root/target/ptrsub-switch-cast-oracle"
/usr/bin/mkdir -p "$cargo_target"
exec 9>"$cargo_target/.build.lock"
"$host_flock" -x 9
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$user_home" CARGO_HOME="$user_home/.cargo" \
  LC_ALL=C CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$cargo_target" TMPDIR="$run_root/tmp" \
  CXX="$host_cxx" CC="$host_cc" AR="$host_ar" RUSTC="$host_rustc" \
  /usr/bin/timeout 900 "$host_cargo" build --offline --locked --frozen --jobs 2 \
  --manifest-path "$snapshot/Cargo.toml" --lib \
  >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr"

/usr/bin/env -i PATH=/usr/bin:/bin HOME="$user_home" LC_ALL=C TMPDIR="$run_root/tmp" \
  "$host_rustc" --edition=2021 -C opt-level=0 -C overflow-checks=yes \
  "$snapshot/tests/oracle/ptrsub_switch_cast_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" -o "$run_root/ptrsub_sw_rust" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"
"$host_flock" -u 9
if [[ ! -f "$run_root/ptrsub_sw_rust" ]]; then
  /usr/bin/cat "$run_root/rustc.stdout" "$run_root/rustc.stderr" >&2
  exit 1
fi

for run in 1 2; do
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/ptrsub_sw_rust" \
    >"$run_root/rudra.$run.stdout" 2>"$run_root/rudra.$run.stderr"
done
if ! /usr/bin/cmp -s "$run_root/rudra.1.stdout" "$run_root/rudra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/rudra.1.stderr" "$run_root/rudra.2.stderr"; then
  echo "Rudra fixture output is nondeterministic" >&2
  exit 1
fi

/usr/bin/diff -u --label ghidra.stdout --label rudra.stdout \
  "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" >"$run_root/raw.diff" || true

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/ghidra.1.stdout" \
  "$run_root/ghidra.1.stderr" "$run_root/rudra.1.stdout" \
  "$run_root/rudra.1.stderr" "$run_root/raw.diff" <<'PY'
import hashlib
import json
import pathlib
import sys

meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
gout, gerr, rout, rerr, rawdiff = map(pathlib.Path, sys.argv[2:])
exp = meta["expected_results"]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

checks = {
    "ghidra stdout": (sha(gout), exp["ghidra_stdout_sha256"]),
    "ghidra stderr": (sha(gerr), exp["ghidra_stderr_sha256"]),
    "rudra stdout": (sha(rout), exp["rudra_stdout_sha256"]),
    "rudra stderr": (sha(rerr), exp["rudra_stderr_sha256"]),
    "raw diff": (sha(rawdiff), exp["raw_diff_sha256"]),
}
for label, (actual, expected) in checks.items():
    if actual != expected:
        raise SystemExit(f"{label} hash mismatch: {actual} != {expected}")
if gerr.read_bytes() or rerr.read_bytes():
    raise SystemExit("both stderr streams must be empty")
glines = gout.read_text().splitlines()
rlines = rout.read_text().splitlines()
if len(glines) != exp["record_count"] or len(rlines) != exp["record_count"]:
    raise SystemExit("record count mismatch")


def record_identity(line):
    parts = line.split("|")
    return parts[0] + "|" + parts[1] if len(parts) > 1 else parts[0]


if [record_identity(line) for line in rlines] != [record_identity(line) for line in glines]:
    raise SystemExit("record case/stage order drift")

# Every changed rudra record must be covered by a registered known
# difference keyed on its record identity.
known = {entry["record"]: entry for entry in meta["known_raw_differences"]}
changed = set()
for line in rawdiff.read_text().splitlines():
    if line.startswith("+") and not line.startswith("+++") and line.count("|") >= 1:
        changed.add(record_identity(line[1:]))
unregistered = sorted(changed - set(known))
if unregistered:
    raise SystemExit(f"unregistered raw differences: {unregistered}")
PY

echo "PTRSUB-SWITCH-CAST bilateral run complete"
echo "records=21 overall=MATCH (byte-identical streams; no known differences)"
echo "raw_diff_sha256=$(/usr/bin/sha256sum "$run_root/raw.diff" | /usr/bin/awk '{print $1}')"
