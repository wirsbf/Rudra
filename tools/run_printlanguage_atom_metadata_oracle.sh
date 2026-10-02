#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail
umask 077

# Bilateral runner for PRINTLANGUAGE-ATOM-METADATA-0001.  The covered
# Atom -> RPN -> tagVariable projection is byte-matched.  The full printing
# module remains MISMATCH because deeper EmitPrettyPrint/TokenSplit metadata
# transport and the other Atom variants are outside this fixture.

runner_fd=/proc/$$/fd/3
if [[ ${1:-} != --captured ]]; then
  case ${1:-} in
    "") mode=normal ;;
    --validate-only) mode=validate-only ;;
    *)
      echo "usage: ${BASH_SOURCE[0]} [--validate-only]" >&2
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
expected_runner="$repo_root/tools/run_printlanguage_atom_metadata_oracle.sh"
if [[ "$runner_source" != "$expected_runner" || ! -f "$runner_source" || \
      -L "$runner_source" ]]; then
  echo "captured runner identity mismatch" >&2
  exit 1
fi
if [[ "$(/usr/bin/stat -Lc '%a' "$runner_fd")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=7e91aef6aa28cbf0a77b9812858c276cafa7fbd3
rudra_base_tree=fd155bc4dd996000d3012c2d49f7244c3a6308ec
rudra_base_src_tree=c6a2eb0fb690ff9ac693d12d6ea45b606bc713ae
rudra_base_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_base_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_base_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5

metadata_live="$repo_root/tests/oracle/printlanguage_atom_metadata_1204.metadata.json"
cpp_fixture_live="$repo_root/tests/oracle/printlanguage_atom_metadata_1204.cc"
rust_fixture_live="$repo_root/tests/oracle/printlanguage_atom_metadata_1204.rs"
prettyprint_overlay_live="$repo_root/src/prettyprint.rs"
printlanguage_overlay_live="$repo_root/src/printlanguage.rs"
ghidra_entry="$repo_root/ghidra"
ghidra_root=$(/usr/bin/readlink -f "$ghidra_entry")

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
for input in "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live" \
  "$prettyprint_overlay_live" "$printlanguage_overlay_live"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input must be a regular non-symlink file: $input" >&2
    exit 1
  fi
done
if [[ -z "$ghidra_root" || ! -d "$ghidra_root" ]]; then
  echo "ghidra entrypoint must resolve to a directory" >&2
  exit 1
fi

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
if [[ -n "$(git_clean -C "$ghidra_root" status --porcelain --untracked-files=no -- \
      Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi
if [[ "$(git_clean -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")" != "$rudra_base_tree" || \
      "$(git_clean -C "$repo_root" rev-parse "$rudra_base_commit:src")" != "$rudra_base_src_tree" || \
      "$(git_clean -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.toml")" != "$rudra_base_cargo_toml_blob" || \
      "$(git_clean -C "$repo_root" rev-parse "$rudra_base_commit:Cargo.lock")" != "$rudra_base_cargo_lock_blob" || \
      "$(git_clean -C "$repo_root" rev-parse "$rudra_base_commit:build.rs")" != "$rudra_base_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

for binding in \
  printlanguage.cc:79642ef234ffa59fa4a9b03b9b7ea57e3948982d \
  printlanguage.hh:af6e87cb041a777309541000691d86655f0a8a9d \
  prettyprint.cc:ad8a6ded10382bb4792deba67a2f41007d45c5dc \
  prettyprint.hh:9f6ac1b999d5e0406ae7ab9bedccce2defbf700a; do
  file=${binding%%:*}
  expected=${binding#*:}
  actual=$(git_clean -C "$ghidra_root" rev-parse \
    "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/$file")
  if [[ "$actual" != "$expected" ]]; then
    echo "locked oracle source blob mismatch: $file" >&2
    exit 1
  fi
done

run_parent="$repo_root/target/oracle-runs"
/usr/bin/mkdir -p "$run_parent"
run_root=$(/usr/bin/mktemp -d "$run_parent/printlanguage-atom-metadata.XXXXXX")
cleanup() {
  if [[ -n ${run_root:-} && \
        "$run_root" == "$run_parent"/printlanguage-atom-metadata.* && \
        -d "$run_root" ]]; then
    /usr/bin/find "$run_root" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM
/usr/bin/mkdir -p "$run_root/evidence/src" \
  "$run_root/evidence/tests/oracle" "$run_root/oracle" \
  "$run_root/rudra" "$run_root/tmp"

# Freeze every mutable input before content validation.  Validation, builds,
# comparisons, and post-run rehashes consume only this private capture.
/usr/bin/cp -- "$metadata_live" "$run_root/evidence/metadata.json"
/usr/bin/cp -- "$cpp_fixture_live" \
  "$run_root/evidence/tests/oracle/printlanguage_atom_metadata_1204.cc"
/usr/bin/cp -- "$rust_fixture_live" \
  "$run_root/evidence/tests/oracle/printlanguage_atom_metadata_1204.rs"
/usr/bin/cp -- "$prettyprint_overlay_live" \
  "$run_root/evidence/src/prettyprint.rs"
/usr/bin/cp -- "$printlanguage_overlay_live" \
  "$run_root/evidence/src/printlanguage.rs"
/usr/bin/cp -- "$runner_fd" "$run_root/evidence/runner.sh"

metadata="$run_root/evidence/metadata.json"
cpp_fixture="$run_root/evidence/tests/oracle/printlanguage_atom_metadata_1204.cc"
rust_fixture="$run_root/evidence/tests/oracle/printlanguage_atom_metadata_1204.rs"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/evidence" "$host_cxx" "$host_rustc" \
  "$host_cargo" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

metadata_path = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2])
host_cxx, host_rustc, host_cargo = sys.argv[3:]
meta = json.loads(metadata_path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected!r}, got {actual!r}")

require("schema", meta["schema_version"], 2)
require("fixture", meta["fixture_id"], "PRINTLANGUAGE-ATOM-METADATA-0001")
require("covered status", meta["covered_projection_status"], "MATCH")
require("overall status", meta["overall_status"], "MISMATCH")
require("oracle", meta["oracle"], {
    "tag": "Ghidra_12.0.4_build",
    "commit": "e40ed13014025f82488b1f8f7bca566894ac376b",
    "decompiler_cpp_tree": "b02e230a539c65de14e50f357d0ba834d8184f4f",
    "decompiler_makefile_blob": "ca0719fa5f17aabd14c52f40ed8b030f54d2aac6",
    "source_blobs": {
        "printlanguage.cc": "79642ef234ffa59fa4a9b03b9b7ea57e3948982d",
        "printlanguage.hh": "af6e87cb041a777309541000691d86655f0a8a9d",
        "prettyprint.cc": "ad8a6ded10382bb4792deba67a2f41007d45c5dc",
        "prettyprint.hh": "9f6ac1b999d5e0406ae7ab9bedccce2defbf700a",
    },
})
require("architecture", meta["architecture"], "language-independent PrintLanguage RPN")
require("compiler spec", meta["compiler_spec"], "none")

source = meta["rugra_source"]
require("Rudra base commit", source["base_commit"], "7e91aef6aa28cbf0a77b9812858c276cafa7fbd3")
require("Rudra base tree", source["base_tree"], "fd155bc4dd996000d3012c2d49f7244c3a6308ec")
require("Rudra base src tree", source["base_src_tree"], "c6a2eb0fb690ff9ac693d12d6ea45b606bc713ae")
require("Cargo.toml blob", source["base_cargo_toml_blob"], "f15ed7d02b38aef3c21a564641344a156855b632")
require("Cargo.lock blob", source["base_cargo_lock_blob"], "9736a3c5619f7fd188abd9609d0dccd20ef06607")
require("build.rs blob", source["base_build_rs_blob"], "a0c81c8521547efebbb463a640ecec69d83ed4c5")
require("overlay paths", sorted(source["overlays"]), ["src/prettyprint.rs", "src/printlanguage.rs"])

comparand = meta["comparand"]
require("overlay set", sorted(comparand["overlay_sha256"]),
        ["src/prettyprint.rs", "src/printlanguage.rs"])
require("fixture set", sorted(comparand["fixture_sha256"]), [
    "tests/oracle/printlanguage_atom_metadata_1204.cc",
    "tests/oracle/printlanguage_atom_metadata_1204.rs",
])
for relative, expected in comparand["overlay_sha256"].items():
    require(f"overlay {relative}", sha(evidence / relative), expected)
    require(f"overlay declaration {relative}", source["overlays"][relative], expected)
for relative, expected in comparand["fixture_sha256"].items():
    require(f"fixture {relative}", sha(evidence / relative), expected)
require("runner hash", sha(evidence / "runner.sh"), comparand["runner_sha256"])

versions = {
    "host_cxx": subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo, "--version"], text=True).strip(),
}
for key, actual in versions.items():
    require(key, actual, comparand[key])

manifest = meta["input_manifest"]
canonical = json.dumps(
    manifest["manifest"], sort_keys=True, separators=(",", ":"), ensure_ascii=False,
).encode()
require("input fingerprint", hashlib.sha256(canonical).hexdigest(), manifest["sha256"])
require("event order", meta["expected_results"]["event_order"],
        [
            "open_group:g0", "variable:obj0:obj1", "close_group:g0",
            "open_group:g1", "variable:obj0:obj1", "close_group:g1",
            "syntax:none:none",
        ])
if "PENDING" in metadata_path.read_text(encoding="utf-8"):
    raise SystemExit("committed evidence metadata may not contain PENDING")
PY

if [[ "$mode" == validate-only ]]; then
  echo "PRINTLANGUAGE-ATOM-METADATA-0001 pins validated; covered_projection=MATCH overall=MISMATCH"
  exit 0
fi

uid=$(/usr/bin/id -u)
user_home=$(/usr/bin/getent passwd "$uid" | /usr/bin/cut -d: -f6)
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "unable to resolve user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache/rudra-printlanguage-atom-metadata-1204"
/usr/bin/mkdir -p "$cache_parent"
exec 9>"$cache_parent/runner.lock"
if ! "$host_flock" -n 9; then
  echo "another printlanguage atom-metadata runner is active" >&2
  exit 1
fi

git_clean -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$run_root/oracle"
oracle_cpp="$run_root/oracle/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_root/tmp" \
  /usr/bin/timeout 600 "$host_make" --no-print-directory -s -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx -std=c++11" "CC=$host_cc" "AR=$host_ar" EXTRA= libdecomp.a \
  >"$run_root/make.stdout" 2>"$run_root/make.stderr"
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "locked oracle build did not produce libdecomp.a" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$run_root/tmp" \
  /usr/bin/timeout 600 "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.a" -lz \
  -o "$run_root/ghidra_fixture" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"

snapshot="$run_root/rudra"
git_clean -C "$repo_root" archive "$rudra_base_commit" | \
  /usr/bin/tar -xf - -C "$snapshot"
/usr/bin/cp -- "$run_root/evidence/src/prettyprint.rs" "$snapshot/src/prettyprint.rs"
/usr/bin/cp -- "$run_root/evidence/src/printlanguage.rs" "$snapshot/src/printlanguage.rs"
/usr/bin/mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/cp -- "$rust_fixture" \
  "$snapshot/tests/oracle/printlanguage_atom_metadata_1204.rs"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

fixture_target="$run_root/cargo-target"
if ! (
  builtin cd "$snapshot"
  /usr/bin/env -i HOME="$user_home" PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$run_root/tmp" CXX="$host_cxx" \
    CC="$host_cc" AR="$host_ar" RUSTC="$host_rustc" RUSTFLAGS=-Awarnings \
    /usr/bin/timeout 900 "$host_cargo" build --quiet --locked --offline --lib
) >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr"; then
  /usr/bin/cat "$run_root/cargo.stdout" "$run_root/cargo.stderr" >&2
  exit 1
fi

rudra_rlib="$fixture_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$fixture_target/debug/build" \
    -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || "${#native_archives[@]}" -ne 1 ]]; then
  echo "Rudra library/native archive build output mismatch" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
/usr/bin/env -i HOME="$user_home" PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
  TMPDIR="$run_root/tmp" /usr/bin/timeout 600 "$host_rustc" \
  --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/printlanguage_atom_metadata_1204.rs" \
  -o "$run_root/rudra_fixture" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"

for run in 1 2; do
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/ghidra_fixture" \
    >"$run_root/ghidra.$run.stdout" 2>"$run_root/ghidra.$run.stderr"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/rudra_fixture" \
    >"$run_root/rudra.$run.stdout" 2>"$run_root/rudra.$run.stderr"
done
for side in ghidra rudra; do
  if ! /usr/bin/cmp -s "$run_root/$side.1.stdout" "$run_root/$side.2.stdout" || \
     ! /usr/bin/cmp -s "$run_root/$side.1.stderr" "$run_root/$side.2.stderr"; then
    echo "$side fixture output is nondeterministic" >&2
    exit 1
  fi
  if [[ -s "$run_root/$side.1.stderr" ]]; then
    echo "$side fixture stderr must be empty" >&2
    /usr/bin/cat "$run_root/$side.1.stderr" >&2
    exit 1
  fi
done
if ! /usr/bin/cmp -s "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout"; then
  echo "Atom metadata bilateral byte comparison failed" >&2
  /usr/bin/diff -u "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" >&2 || true
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" \
  "$run_root/evidence" <<'PY'
import hashlib
import json
import pathlib
import sys

meta = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
evidence = pathlib.Path(sys.argv[4])
expected = meta["expected_results"]
sha_bytes = lambda data: hashlib.sha256(data).hexdigest()
sha_file = lambda path: sha_bytes(path.read_bytes())

if ghidra != rudra:
    raise SystemExit("byte comparison unexpectedly diverged")
if len(ghidra) != expected["stdout_bytes_each"]:
    raise SystemExit("stdout byte count mismatch")
if len(ghidra.splitlines()) != expected["record_count"] or not ghidra.endswith(b"\n"):
    raise SystemExit("record count/final newline mismatch")
if sha_bytes(ghidra) != expected["stdout_sha256_each"]:
    raise SystemExit("stdout hash mismatch")

lines = ghidra.decode("utf-8").splitlines()
envelope = (
    "schema=1|fixture=PRINTLANGUAGE-ATOM-METADATA-0001"
    "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    "|covered_projection=MATCH|overall=MISMATCH"
)
if lines[0] != envelope:
    raise SystemExit("fixture envelope drift")
expected_events = [
    {"event": "0", "kind": "open_group", "text_hex": "",
     "highlight": "none", "vn": "none", "op": "none", "group": "g0"},
    {"event": "1", "kind": "variable", "text_hex": "275c3027",
     "highlight": "const", "vn": "obj0", "op": "obj1", "group": "none"},
    {"event": "2", "kind": "close_group", "text_hex": "",
     "highlight": "none", "vn": "none", "op": "none", "group": "g0"},
    {"event": "3", "kind": "open_group", "text_hex": "",
     "highlight": "none", "vn": "none", "op": "none", "group": "g1"},
    {"event": "4", "kind": "variable", "text_hex": "275c3027",
     "highlight": "const", "vn": "obj0", "op": "obj1", "group": "none"},
    {"event": "5", "kind": "close_group", "text_hex": "",
     "highlight": "none", "vn": "none", "op": "none", "group": "g1"},
    {"event": "6", "kind": "syntax", "text_hex": "3b",
     "highlight": "none", "vn": "none", "op": "none", "group": "none"},
]
observed = [dict(field.split("=", 1) for field in line.split("|"))
            for line in lines[1:]]
if observed != expected_events:
    raise SystemExit(f"event sequence mismatch: {observed!r}")

# Rehash the exact captured bytes after all builds/runs.  This detects fixture
# or overlay mutation during execution without rereading mutable live paths.
for group in ("overlay_sha256", "fixture_sha256"):
    for relative, wanted in meta["comparand"][group].items():
        if sha_file(evidence / relative) != wanted:
            raise SystemExit(f"post-run captured input drift: {relative}")
if sha_file(evidence / "runner.sh") != meta["comparand"]["runner_sha256"]:
    raise SystemExit("post-run runner drift")

print(
    f"records={expected['record_count']} bytes={expected['stdout_bytes_each']} "
    f"stdout_sha256={expected['stdout_sha256_each']}"
)
print("covered_projection=MATCH overall=MISMATCH")
PY
