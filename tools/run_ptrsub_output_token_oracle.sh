#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail
umask 077

# Bilateral evidence runner for PTRSUB-OUTPUT-TOKEN-0001.  A successful run
# verifies byte-identical selected observations; it does not relabel the full
# mapped functions or the overall fixture as MATCH.
runner_fd=/proc/$$/fd/3
if [[ ${1:-} != --captured ]]; then
  case ${1:-} in
    "") mode=normal ;;
    --ghidra-only) mode=ghidra-only ;;
    --require-match) mode=require-match ;;
    --validate-only) mode=validate-only ;;
    *)
      echo "usage: ${BASH_SOURCE[0]} [--ghidra-only|--require-match|--validate-only]" >&2
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
expected_runner="$repo_root/tools/run_ptrsub_output_token_oracle.sh"
if [[ "$runner_source" != "$expected_runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "captured runner identity mismatch" >&2
  exit 1
fi

metadata="$repo_root/tests/oracle/ptrsub_output_token_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/ptrsub_output_token_1204.cc"
rust_fixture="$repo_root/tests/oracle/ptrsub_output_token_1204.rs"
ghidra_entry="$repo_root/ghidra"
ghidra_root=$(/usr/bin/readlink -f "$ghidra_entry")
base_commit=7e91aef6aa28cbf0a77b9812858c276cafa7fbd3
base_tree=fd155bc4dd996000d3012c2d49f7244c3a6308ec
base_src_tree=c6a2eb0fb690ff9ac693d12d6ea45b606bc713ae
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
if [[ "$(git_clean -C "$repo_root" rev-parse "$base_commit^{tree}")" != "$base_tree" || \
      "$(git_clean -C "$repo_root" rev-parse "$base_commit:src")" != "$base_src_tree" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

run_parent="$repo_root/target/oracle-runs"
/usr/bin/mkdir -p "$run_parent"
run_root=$(/usr/bin/mktemp -d "$run_parent/ptrsub-output-token.XXXXXX")
cleanup() {
  if [[ -n ${run_root:-} && "$run_root" == "$run_parent"/ptrsub-output-token.* && -d "$run_root" ]]; then
    /usr/bin/find "$run_root" -depth -delete 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM
/usr/bin/mkdir -p "$run_root/tmp" "$run_root/oracle" "$run_root/rudra" \
  "$run_root/evidence/src/type_system" "$run_root/evidence/tests/oracle"

# Freeze every mutable input before validating any content.  The validator,
# compilers, output checks, and final readback all consume these same private
# bytes, closing the former live-validate/capture race.
/usr/bin/cp -- "$metadata" "$run_root/evidence/metadata.json"
/usr/bin/cp -- "$cpp_fixture" \
  "$run_root/evidence/tests/oracle/ptrsub_output_token_1204.cc"
/usr/bin/cp -- "$rust_fixture" \
  "$run_root/evidence/tests/oracle/ptrsub_output_token_1204.rs"
for relative in src/coreaction.rs src/space.rs src/type_system/cast.rs src/type_system/typefactory.rs src/typeop.rs src/varnode.rs; do
  /usr/bin/cp -- "$repo_root/$relative" "$run_root/evidence/$relative"
done
metadata="$run_root/evidence/metadata.json"
cpp_fixture="$run_root/evidence/tests/oracle/ptrsub_output_token_1204.cc"
rust_fixture="$run_root/evidence/tests/oracle/ptrsub_output_token_1204.rs"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$repo_root" "$runner_source" "$run_root/evidence" <<'PY'
import hashlib
import json
import pathlib
import subprocess
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
require("fixture", meta["fixture_id"], "PTRSUB-OUTPUT-TOKEN-0001")
require("covered status", meta["covered_projection_status"], "MATCH")
require("overall status", meta["overall_status"], "MISMATCH")
require("oracle commit", meta["oracle"]["commit"], "e40ed13014025f82488b1f8f7bca566894ac376b")
require("oracle tag", meta["oracle"]["tag"], "Ghidra_12.0.4_build")
require("oracle cpp tree", meta["oracle"]["decompiler_cpp_tree"], "b02e230a539c65de14e50f357d0ba834d8184f4f")
require("oracle Makefile blob", meta["oracle"]["decompiler_makefile_blob"], "ca0719fa5f17aabd14c52f40ed8b030f54d2aac6")
require("Rudra base commit", meta["comparand"]["rust_base_commit"], "7e91aef6aa28cbf0a77b9812858c276cafa7fbd3")
require("Rudra base tree", meta["comparand"]["rust_base_tree"], "fd155bc4dd996000d3012c2d49f7244c3a6308ec")
require("Rudra base src tree", meta["comparand"]["rust_base_src_tree"], "c6a2eb0fb690ff9ac693d12d6ea45b606bc713ae")
require("runner hash", sha(runner), meta["comparand"]["runner_sha256"])
expected_overlays = [
    "src/coreaction.rs",
    "src/space.rs",
    "src/type_system/cast.rs",
    "src/type_system/typefactory.rs",
    "src/typeop.rs",
    "src/varnode.rs",
]
expected_fixtures = [
    "tests/oracle/ptrsub_output_token_1204.cc",
    "tests/oracle/ptrsub_output_token_1204.rs",
]
require("overlay set", sorted(meta["comparand"]["overlay_sha256"]), sorted(expected_overlays))
require("fixture set", sorted(meta["comparand"]["fixture_sha256"]), sorted(expected_fixtures))
for relative, expected in meta["comparand"]["overlay_sha256"].items():
    require(f"overlay {relative}", sha(evidence / relative), expected)
for relative, expected in meta["comparand"]["fixture_sha256"].items():
    require(f"fixture {relative}", sha(evidence / relative), expected)
expected_order = [
    "header",
    "scale:normal", "scale:wrap_zero", "scale:wrap_nonzero",
    "scale:max_product", "scale:zero_wordsize",
    "direct:exact0", "direct:exact8", "direct:inside12", "direct:nested12",
    "direct:hole28", "direct:size32", "direct:negative1", "direct:wordsize2",
    "direct:wordsize2_inside", "direct:wordsize2_wrap",
    "direct:wordsize2_wrap_nonzero", "direct:exact24", "direct:scalar0",
    "direct:nonpointer", "action_pre", "action_post",
    "infer_pre", "infer_post",
]
require("record count", meta["expected_results"]["record_count"], 24)
require("record order", meta["expected_results"]["record_order"], expected_order)
require("raw diff labels", meta["expected_results"]["raw_diff_labels"], ["ghidra.stdout", "rudra.stdout"])
require("stdout bytes", meta["expected_results"]["stdout_bytes_each"], 3740)
require("raw diff bytes", meta["expected_results"]["raw_diff_bytes"], 0)
require("exit codes", meta["expected_results"]["exit_codes"], {
    "ghidra": 0, "rugra": 0, "raw_diff": 0,
    "normal_runner": 0, "require_match_runner": 0,
})
require("known raw differences", meta["known_raw_differences"], [])
manifest = meta["input_manifest"]
require("input manifest keys", sorted(manifest["manifest"]), sorted([
    "architecture", "compiler_spec", "analysis_options", "factory_bootstrap", "types",
    "scale_cases", "direct_graph", "direct_cases", "action_graph",
    "infer_graph",
]))
bootstrap = manifest["manifest"]["factory_bootstrap"]
require("factory constructor", bootstrap["constructor"], "raw TypeFactory")
require("factory setup sizes", bootstrap["setup_sizes_inputs"], {
    "stack_spacebase_size": 8,
    "default_data_space_addr_size": 8,
    "default_size": 8,
    "far_pointer": None,
})
require("factory derived sizes", bootstrap["derived_sizes"], {
    "int": 4, "long": 8, "char": 1, "wchar": 2,
    "pointer": 8, "alt_pointer": 0, "enum": 8,
    "enum_metatype": "uint",
})
require("factory alignment map", bootstrap["alignment_map"], [0, 1, 2, 2, 4, 4, 4, 4, 8])
require("factory max base", bootstrap["max_base_type_size"], 10)
require("factory inventory count", bootstrap["core_inventory_count"], 6)
require("factory dependent order", bootstrap["dependent_order"], [
    "int8", "int4", "xunknown8", "xunknown4", "xunknown2", "xunknown1",
])
require("factory cache identities", bootstrap["get_base_named_identity"], [1, 1, 1, 1, 1, 1])
require("factory ordered core types", bootstrap["ordered_core_types"], [
    {"name": "xunknown1", "size": 1, "metatype": "unknown", "id": "0xf56e6b6d9089e9a9", "alignment": 1, "align_size": 1, "flags": "0x1"},
    {"name": "xunknown2", "size": 2, "metatype": "unknown", "id": "0xf56e6b6d6e221701", "alignment": 2, "align_size": 2, "flags": "0x1"},
    {"name": "xunknown4", "size": 4, "metatype": "unknown", "id": "0xf56e6b6d6e221707", "alignment": 4, "align_size": 4, "flags": "0x1"},
    {"name": "xunknown8", "size": 8, "metatype": "unknown", "id": "0xf56e6b6d6e22171b", "alignment": 8, "align_size": 8, "flags": "0x1"},
    {"name": "int4", "size": 4, "metatype": "int", "id": "0xc000fe2ec290219f", "alignment": 4, "align_size": 4, "flags": "0x1"},
    {"name": "int8", "size": 8, "metatype": "int", "id": "0xc000fe2ec2902193", "alignment": 8, "align_size": 8, "flags": "0x1"},
])
require("random seed", manifest["manifest"]["analysis_options"]["random_seed"], "none")
require("error injection", manifest["manifest"]["analysis_options"]["error_injection"], "none")
canonical = json.dumps(
    manifest["manifest"], sort_keys=True, separators=(",", ":"),
).encode()
require("input manifest hash", hashlib.sha256(canonical).hexdigest(), manifest["sha256"])
if "PENDING" in metadata_path.read_text():
    raise SystemExit("committed evidence metadata may not contain PENDING")

require("host toolchain set", sorted(meta["host_toolchain"]), sorted([
    "git", "python", "cxx", "cc", "ar", "make", "cargo", "rustc", "flock",
]))
for name, entry in meta["host_toolchain"].items():
    path = pathlib.Path(entry["path"])
    require(f"tool hash {name}", sha(path), entry["sha256"])
    cmd = [str(path), "--version"]
    version = subprocess.check_output(cmd, text=True).splitlines()[0]
    require(f"tool version {name}", version, entry["version"])
PY

for binding in \
  action.cc:9a4e2e26d04d45805f14900fadcbbac01270a2f0 \
  action.hh:e929dbb98e8e1fb23d7ac8e8d86e9f4f39fc998c \
  coreaction.cc:a392076ad23ddad3350e0fe7a2ebe96a8868f74b \
  coreaction.hh:d974875d7d71ac76121379eba139c2e8450ae8a3 \
  op.hh:7e516fdf57185c74ea4efac8d9d3b324f259ade8 \
  typeop.cc:5197e3eefd185ed39c58e65af0687d605e34ec5e \
  typeop.hh:90ac4ed35194c5fd9bbb86759481c89a5388cb52 \
  varnode.cc:a04614c582a1fd987d615dcec4a8b47d3501f95f \
  varnode.hh:b78368fc8c3fbdda2a419122b759b4dcd44fe8d2 \
  type.cc:962c525b7f9c6a901d84d6396de245a0bf6e5d60 \
  type.hh:92d4882b25b602464909fdeea63bbc278761ac6d \
  space.hh:bc88fcd6c589d585490a395a69ec4755a37b0610 \
  translate.hh:09daa8005aadaa93f8d634e394ab644e469c7477 \
  types.h:ef752b59243b7d70630b4512b65920a1316f8969; do
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
  echo "PTRSUB evidence pins validated; covered=MATCH overall=MISMATCH"
  exit 0
fi

uid=$(/usr/bin/id -u)
user_home=$(/usr/bin/getent passwd "$uid" | /usr/bin/cut -d: -f6)
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "unable to resolve user home" >&2
  exit 1
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/evidence" <<'PY'
import hashlib, json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for group in ("overlay_sha256", "fixture_sha256"):
    for relative, expected in meta["comparand"][group].items():
        actual = sha(root / relative)
        if actual != expected:
            raise SystemExit(f"captured evidence mismatch: {relative}")
PY

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
  "$oracle_cpp/libdecomp.a" -lz -o "$run_root/ptrsub_cpp" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"

for run in 1 2; do
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/ptrsub_cpp" \
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
  echo "PTRSUB Ghidra oracle verified records=24 covered=MATCH overall=MISMATCH"
  exit 0
fi

snapshot="$run_root/rudra"
git_clean -C "$repo_root" archive "$base_commit" | /usr/bin/tar -xf - -C "$snapshot"
for relative in src/coreaction.rs src/space.rs src/type_system/cast.rs src/type_system/typefactory.rs src/typeop.rs src/varnode.rs; do
  /usr/bin/cp -- "$run_root/evidence/$relative" "$snapshot/$relative"
done
/usr/bin/mkdir -p "$snapshot/tests/oracle" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/cp -- "$rust_fixture" "$snapshot/tests/oracle/ptrsub_output_token_1204.rs"
/usr/bin/ln -s "$oracle_cpp" "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$snapshot" <<'PY'
import hashlib, json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for relative, expected in meta["comparand"]["overlay_sha256"].items():
    if not relative.startswith("src/"):
        continue
    actual = sha(root / relative)
    if actual != expected:
        raise SystemExit(f"snapshot overlay mismatch: {relative}")
PY

cargo_target="$repo_root/target/ptrsub-output-token-oracle"
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
  "$snapshot/tests/oracle/ptrsub_output_token_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" -o "$run_root/ptrsub_rust" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"
"$host_flock" -u 9

for run in 1 2; do
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout 60 \
    "$run_root/ptrsub_rust" \
    >"$run_root/rudra.$run.stdout" 2>"$run_root/rudra.$run.stderr"
done
if ! /usr/bin/cmp -s "$run_root/rudra.1.stdout" "$run_root/rudra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/rudra.1.stderr" "$run_root/rudra.2.stderr"; then
  echo "Rudra fixture output is nondeterministic" >&2
  exit 1
fi

set +e
/usr/bin/diff -u --label ghidra.stdout --label rudra.stdout \
  "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" >"$run_root/raw.diff"
diff_rc=$?
set -e
if [[ $diff_rc -ne 0 ]]; then
  /usr/bin/cat "$run_root/raw.diff" >&2
  echo "selected PTRSUB bilateral output must be byte-identical" >&2
  exit 1
fi

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
if len(gout.read_bytes()) != exp["stdout_bytes_each"] or len(rout.read_bytes()) != exp["stdout_bytes_each"]:
    raise SystemExit("stdout byte count mismatch")
if len(rawdiff.read_bytes()) != exp["raw_diff_bytes"]:
    raise SystemExit("raw diff byte count mismatch")
if rawdiff.read_bytes():
    raise SystemExit("raw diff must be empty for the covered MATCH projection")

ORDER = [
    ("schema", "PTRSUB-OUTPUT-TOKEN-0001"),
    *[("scale", case) for case in (
        "normal", "wrap_zero", "wrap_nonzero", "max_product", "zero_wordsize",
    )],
    *[("direct", case) for case in (
        "exact0", "exact8", "inside12", "nested12", "hole28", "size32",
        "negative1", "wordsize2", "wordsize2_inside", "wordsize2_wrap",
        "wordsize2_wrap_nonzero", "exact24", "scalar0", "nonpointer",
    )],
    ("action_pre", "paired"), ("action_post", "paired"),
    ("infer_pre", "spacebase_ptrsub_local"),
    ("infer_post", "spacebase_ptrsub_local"),
]
KEYS = {
    "schema": ["schema", "fixture", "oracle"],
    "scale": ["case", "val", "ws", "result"],
    "direct": ["case", "token", "token_identity", "pointee_present",
               "pointee_identity", "repeat_identity", "local",
               "local_identity", "local_core"],
    "action_pre": ["case", "ops", "equal_def", "mismatch_def",
                   "equal_type", "mismatch_type"],
    "action_post": ["case", "result", "count_before_delta", "delta_first",
                    "count_after_delta", "delta_second", "ops", "casts", "equal_same",
                    "equal_def", "mismatch_def", "mismatch_out_same", "mid_new",
                    "mid_def", "mid_use", "cast_input_mid", "mid_implied",
                    "mid_type", "final_type"],
    "infer_pre": ["case", "base_spacebase", "base_type", "out_type",
                  "out_stop", "def_stop"],
    "infer_post": ["case", "result", "base_spacebase", "base_type",
                   "out_type", "out_identity", "out_stop", "def"],
}

def parse(path, side):
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\r" in raw:
        raise SystemExit(f"{side}: newline contract drift")
    lines = raw.decode("utf-8", errors="strict")[:-1].split("\n")
    if len(lines) != 24:
        raise SystemExit(f"{side}: expected 24 records, got {len(lines)}")
    records = []
    for index, line in enumerate(lines):
        parts = line.split("|")
        kind = "schema" if index == 0 else parts[0]
        field_parts = parts if index == 0 else parts[1:]
        fields, seen = [], set()
        for part in field_parts:
            if "=" not in part:
                raise SystemExit(f"{side}: malformed field on line {index + 1}")
            key, value = part.split("=", 1)
            if key in seen:
                raise SystemExit(f"{side}: duplicate field {key!r} on line {index + 1}")
            seen.add(key)
            fields.append((key, value))
        record = dict(fields)
        expected_keys = KEYS.get(kind)
        if kind == "direct" and record.get("case") == "exact0":
            expected_keys = expected_keys + ["factory_core"]
        if [key for key, _ in fields] != expected_keys:
            raise SystemExit(f"{side}: field/order drift on line {index + 1}")
        identity = record["fixture"] if kind == "schema" else record["case"]
        if (kind, identity) != ORDER[index]:
            raise SystemExit(f"{side}: record/order drift on line {index + 1}")
        records.append((kind, fields))
    if lines[0] != ("schema=1|fixture=PTRSUB-OUTPUT-TOKEN-0001|"
                    "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"):
        raise SystemExit(f"{side}: header identity drift")
    return records

grecords = parse(gout, "Ghidra")
rrecords = parse(rout, "Rudra")
expected_factory_core = (
    "count:6;order:int8,int4,xunknown8,xunknown4,xunknown2,xunknown1;"
    "sizes:4,8,1,2,8,0;align:0,1,2,2,4,4,4,4,8;types:"
    "xunknown1:1:unknown:0xf56e6b6d9089e9a9:1:1:0x1:cache1,"
    "xunknown2:2:unknown:0xf56e6b6d6e221701:2:2:0x1:cache1,"
    "xunknown4:4:unknown:0xf56e6b6d6e221707:4:4:0x1:cache1,"
    "xunknown8:8:unknown:0xf56e6b6d6e22171b:8:8:0x1:cache1,"
    "int4:4:int:0xc000fe2ec290219f:4:4:0x1:cache1,"
    "int8:8:int:0xc000fe2ec2902193:8:8:0x1:cache1"
)
for side, records in (("Ghidra", grecords), ("Rudra", rrecords)):
    exact0 = dict(records[6][1])
    if exact0.get("factory_core") != expected_factory_core:
        raise SystemExit(f"{side}: factory bootstrap observation drift")
for index, ((gkind, gfields), (rkind, rfields)) in enumerate(zip(grecords, rrecords)):
    if gkind != rkind or [key for key, _ in gfields] != [key for key, _ in rfields]:
        raise SystemExit(f"record shape differs on line {index + 1}")
    gd, rd = dict(gfields), dict(rfields)
    for key in gd:
        if gd[key] != rd[key]:
            raise SystemExit(
                f"field mismatch on line {index + 1}: {gkind}.{key}: "
                f"{gd[key]!r} != {rd[key]!r}"
            )
actual = []
if meta["known_raw_differences"]:
    raise SystemExit("covered MATCH projection must have no registered raw differences")
actual_mismatch_json = json.dumps(
    actual, sort_keys=True, separators=(",", ":"),
).encode()
if hashlib.sha256(actual_mismatch_json).hexdigest() != exp["field_mismatch_json_sha256"]:
    raise SystemExit("field mismatch JSON hash drift")

glines_raw = gout.read_bytes().splitlines(keepends=True)
rlines_raw = rout.read_bytes().splitlines(keepends=True)
projection_checks = {
    "header": (b"".join(glines_raw[0:1]), exp["header_sha256"]),
    "scale": (b"".join(glines_raw[1:6]), exp["scale_projection_sha256"]),
    "direct": (b"".join(glines_raw[6:20]), exp["direct_projection_sha256"]),
    "Ghidra action": (b"".join(glines_raw[20:22]), exp["ghidra_action_projection_sha256"]),
    "Rudra action": (b"".join(rlines_raw[20:22]), exp["rudra_action_projection_sha256"]),
    "Ghidra infer": (b"".join(glines_raw[22:24]), exp["ghidra_infer_projection_sha256"]),
    "Rudra infer": (b"".join(rlines_raw[22:24]), exp["rudra_infer_projection_sha256"]),
}
for label, (payload, expected) in projection_checks.items():
    if hashlib.sha256(payload).hexdigest() != expected:
        raise SystemExit(f"{label} projection hash drift")

if gout.read_bytes() != rout.read_bytes():
    raise SystemExit("selected projection is not byte-identical")
PY

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$run_root/evidence" <<'PY'
import hashlib, json, pathlib, sys
meta = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for group in ("overlay_sha256", "fixture_sha256"):
    for relative, expected in meta["comparand"][group].items():
        if sha(root / relative) != expected:
            raise SystemExit(f"post-run captured evidence drift: {relative}")
PY

echo "PTRSUB evidence contract verified records=24 direct=14 scale=5 infer=1"
echo "covered_projection=MATCH registered_raw_mismatches=0 overall=MISMATCH"
