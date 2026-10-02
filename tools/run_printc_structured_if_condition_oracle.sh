#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# Locked bilateral gate for PRINTC-STRUCTURED-IF-CONDITION-0001.  Ghidra is
# archived from 12.0.4 commit e40ed130.  Rudra is archived from one pinned
# base and overlays exactly the live src/printc.rs and src/varnode.rs under
# test.  All temporary
# files live below the user's task-specific cache because /tmp is not an
# available trust boundary on the fixture hosts.

runner_fd=/proc/$$/fd/3
if [[ "${BASH_SOURCE[0]}" != "$runner_fd" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_printc_structured_if_condition_oracle.sh"
if [[ "$runner_source" != "$runner" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner identity mismatch" >&2
  exit 1
fi
if [[ "$(/usr/bin/stat -Lc '%a' "$runner_fd")" != 755 ]]; then
  echo "runner must have mode 755" >&2
  exit 1
fi

mode=both
if [[ $# -eq 1 && "$1" == --validate-only ]]; then
  mode=validate
elif [[ $# -ne 0 ]]; then
  echo "usage: $runner [--validate-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
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

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/printc_structured_if_condition_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/printc_structured_if_condition_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_structured_if_condition_1204.rs"
printc_overlay="$repo_root/src/printc.rs"
varnode_overlay="$repo_root/src/varnode.rs"

host_cxx=/usr/bin/g++
host_cc=/usr/bin/gcc
host_ar=/usr/bin/ar
host_make=/usr/bin/make
host_git=/usr/bin/git
host_python=/usr/bin/python3
host_cargo=/usr/bin/cargo
host_rustc=/usr/bin/rustc
for tool in "$host_cxx" "$host_cc" "$host_ar" "$host_make" "$host_git" \
  "$host_python" "$host_cargo" "$host_rustc"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$printc_overlay" \
  "$varnode_overlay" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git" -C "$ghidra_root" diff --cached --quiet -- \
      Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{tree}")
actual_base_src_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:src")
actual_base_cargo_toml_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:Cargo.toml")
actual_base_cargo_lock_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:Cargo.lock")
actual_base_build_rs_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit:build.rs")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" || \
      "$actual_base_src_tree" != "$rudra_base_src_tree" || \
      "$actual_base_cargo_toml_blob" != "$rudra_base_cargo_toml_blob" || \
      "$actual_base_cargo_lock_blob" != "$rudra_base_cargo_lock_blob" || \
      "$actual_base_build_rs_blob" != "$rudra_base_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

runner_sha=$(/usr/bin/sha256sum "$runner_fd" | /usr/bin/awk '{print $1}')
"$host_python" -I -S - "$repo_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$runner_fd" "$runner_sha" "$printc_overlay" \
  "$varnode_overlay" \
  "$oracle_tag" "$oracle_commit" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$rudra_base_commit" "$rudra_base_tree" "$rudra_base_src_tree" \
  "$rudra_base_cargo_toml_blob" "$rudra_base_cargo_lock_blob" \
  "$rudra_base_build_rs_blob" "$host_cxx" "$host_rustc" "$host_cargo" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, runner_raw, runner_sha,
    printc_overlay_raw, varnode_overlay_raw, oracle_tag, oracle_commit,
    cpp_tree, makefile_blob,
    base_commit, base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob,
    build_rs_blob, host_cxx, host_rustc, host_cargo,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
metadata_path = pathlib.Path(metadata_raw).resolve()

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
require("schema", metadata["schema_version"], 2)
require("fixture id", metadata["fixture_id"], "PRINTC-STRUCTURED-IF-CONDITION-0001")
require("overall status", metadata["overall_status"], "MISMATCH")
require("covered projection", metadata["covered_projection_status"], "MATCH")

oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob)

base = metadata["rugra_source"]
require("Rudra base commit", base["base_commit"], base_commit)
require("Rudra base tree", base["base_tree"], base_tree)
require("Rudra base src tree", base["base_src_tree"], base_src_tree)
require("Cargo.toml blob", base["base_cargo_toml_blob"], cargo_toml_blob)
require("Cargo.lock blob", base["base_cargo_lock_blob"], cargo_lock_blob)
require("build.rs blob", base["base_build_rs_blob"], build_rs_blob)
overlays = base["overlays"]
if not (
    isinstance(overlays, list) and len(overlays) == 2
    and overlays[0].get("path") == "src/printc.rs"
    and overlays[1].get("path") == "src/varnode.rs"
):
    raise SystemExit(
        "comparand must overlay exactly src/printc.rs and src/varnode.rs: "
        f"{overlays!r}"
    )

comparand = metadata["comparand"]
checks = {
    "cpp_fixture_sha256": cpp_raw,
    "rust_fixture_sha256": rust_raw,
    "runner_sha256": runner_raw,
    "printc_rs_sha256": printc_overlay_raw,
    "varnode_rs_sha256": varnode_overlay_raw,
}
for key, path in checks.items():
    actual = runner_sha if key == "runner_sha256" else sha(path)
    require(key, actual, comparand[key])
require("printc overlay hash", sha(printc_overlay_raw), overlays[0]["sha256"])
require("varnode overlay hash", sha(varnode_overlay_raw), overlays[1]["sha256"])

versions = {
    "host_cxx": subprocess.check_output([host_cxx, "--version"], text=True).splitlines()[0],
    "host_rustc": subprocess.check_output([host_rustc, "--version"], text=True).strip(),
    "host_cargo": subprocess.check_output([host_cargo, "--version"], text=True).strip(),
}
for key, actual in versions.items():
    require(key, actual, comparand[key])

for field in ("architecture", "compiler_spec", "analysis_options", "input_manifest"):
    if not metadata.get(field):
        raise SystemExit(f"missing oracle descriptor: {field}")
case_ids = [case["id"] for case in metadata["input_manifest"]["cases"]]
require(
    "case order",
    case_ids,
    ["basic_condition", "direct_blockif_condition", "block_condition", "getstr_list_shape"],
)
payload = json.dumps(
    metadata["input_manifest"]["cases"],
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode()
require("input fingerprint", hashlib.sha256(payload).hexdigest(),
        metadata["input_manifest"]["sha256"])
for case_id in case_ids:
    require(f"coverage {case_id}", metadata["coverage"][case_id], "MATCH")
PY

if [[ "$mode" == validate ]]; then
  echo "printc_structured_if_condition_1204 metadata/source validation passed"
  exit 0
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | \
  /usr/bin/awk -F: 'NR == 1 {print $6}')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache/rudra-printc-structured-if-condition-1204"
/usr/bin/mkdir -p "$cache_parent"
exec 9>"$cache_parent/runner.lock"
if ! /usr/bin/flock -n 9; then
  echo "another printc_structured_if_condition_1204 runner is active" >&2
  exit 1
fi

work=$(/usr/bin/mktemp -d "$cache_parent/run.XXXXXX")
snapshot="$cache_parent/workspace"
cleanup() {
  case "$work" in
    "$cache_parent"/run.??????)
      /usr/bin/rm -rf -- "$work"
      ;;
    *) echo "refusing unsafe cleanup target: $work" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$snapshot" in
  "$cache_parent"/workspace) /usr/bin/rm -rf -- "$snapshot" ;;
  *) echo "refusing unsafe snapshot cleanup target: $snapshot" >&2; exit 1 ;;
esac
/usr/bin/mkdir -p "$snapshot" "$work/oracle-source"
build_tmp="$work/build-tmp"
/usr/bin/mkdir -m 0700 "$build_tmp"

base_paths=(
  Cargo.toml Cargo.lock build.rs README.md benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs
  src sleigh_shim
)
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive "$rudra_base_commit" \
  "${base_paths[@]}" | /usr/bin/tar -xf - -C "$snapshot"
/usr/bin/install -m 0644 "$printc_overlay" "$snapshot/src/printc.rs"
/usr/bin/install -m 0644 "$varnode_overlay" "$snapshot/src/varnode.rs"
/usr/bin/install -D -m 0644 "$rust_fixture" \
  "$snapshot/tests/oracle/printc_structured_if_condition_1204.rs"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/tar -xf - -C "$work/oracle-source"
oracle_cpp="$work/oracle-source/Ghidra/Features/Decompiler/src/decompile/cpp"
/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
  "$host_make" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx -std=c++11" EXTRA= libdecomp.a \
  >"$work/make.stdout" 2>"$work/make.stderr"; then
  /usr/bin/cat "$work/make.stdout" "$work/make.stderr" >&2
  exit 1
fi

cpp_binary="$work/printc_structured_if_condition_1204_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmp" \
  "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare \
  -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive \
  -lz -o "$cpp_binary" >"$work/cxx.stdout" 2>"$work/cxx.stderr"; then
  /usr/bin/cat "$work/cxx.stdout" "$work/cxx.stderr" >&2
  exit 1
fi

fixture_target="$cache_parent/cargo-target"
if ! (
  builtin cd "$snapshot"
  /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
    CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$fixture_target" \
    CARGO_NET_OFFLINE=true TMPDIR="$build_tmp" CXX="$host_cxx" \
    CC="$host_cc" AR="$host_ar" RUSTC="$host_rustc" RUSTFLAGS=-Awarnings \
    "$host_cargo" build --quiet --locked --offline --lib
) >"$work/cargo.stdout" 2>"$work/cargo.stderr"; then
  /usr/bin/cat "$work/cargo.stdout" "$work/cargo.stderr" >&2
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
rust_binary="$work/printc_structured_if_condition_1204_rust"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  TMPDIR="$build_tmp" "$host_rustc" --edition=2021 -O \
  -L "dependency=$fixture_target/debug/deps" -L "native=$native_dir" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m \
  "$snapshot/tests/oracle/printc_structured_if_condition_1204.rs" \
  -o "$rust_binary" >"$work/rustc.stdout" 2>"$work/rustc.stderr"; then
  /usr/bin/cat "$work/rustc.stdout" "$work/rustc.stderr" >&2
  exit 1
fi

ghidra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" \
  >"$work/ghidra.stdout" 2>"$work/ghidra.stderr" || ghidra_status=$?
rudra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rust_binary" \
  >"$work/rudra.stdout" 2>"$work/rudra.stderr" || rudra_status=$?
if [[ "$ghidra_status" -ne 0 || "$rudra_status" -ne 0 || \
      -s "$work/ghidra.stderr" || -s "$work/rudra.stderr" ]]; then
  echo "fixture execution failed: ghidra=$ghidra_status rudra=$rudra_status" >&2
  /usr/bin/cat "$work/ghidra.stderr" "$work/rudra.stderr" >&2
  exit 1
fi

diff_status=0
/usr/bin/diff -u "$work/ghidra.stdout" "$work/rudra.stdout" \
  >"$work/runtime.diff" || diff_status=$?
if [[ "$diff_status" -ne 0 ]]; then
  echo "PrintC structured-if condition byte comparison failed" >&2
  /usr/bin/cat "$work/runtime.diff" >&2
  exit "$diff_status"
fi

"$host_python" -I -S - "$metadata" "$work/ghidra.stdout" \
  "$work/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra = pathlib.Path(sys.argv[2]).read_bytes()
rudra = pathlib.Path(sys.argv[3]).read_bytes()
if ghidra != rudra:
    raise SystemExit("byte diff unexpectedly diverged")
capture = metadata["capture"]
if len(ghidra) != capture["bytes"] or len(ghidra.splitlines()) != capture["records"]:
    raise SystemExit("capture size/record mismatch")
actual_hash = hashlib.sha256(ghidra).hexdigest()
if actual_hash != capture["stdout_sha256"]:
    raise SystemExit("capture stdout hash mismatch")

lines = ghidra.decode("utf-8").splitlines()
envelope = (
    "schema=1|fixture=PRINTC-STRUCTURED-IF-CONDITION-0001"
    "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    "|overall=MISMATCH|covered_projection=MATCH"
)
if lines[0] != envelope:
    raise SystemExit("fixture envelope drift")
case_ids = [line.split("|", 1)[0].split("=", 1)[1] for line in lines[1:]]
expected_ids = [case["id"] for case in metadata["input_manifest"]["cases"]]
if case_ids != expected_ids:
    raise SystemExit(f"case order drift: {case_ids!r}")
for line in lines[1:]:
    fields = dict(field.split("=", 1) for field in line.split("|"))
    for key in ("tree_equal", "sentinel_equal", "post_fresh_equal"):
        if fields.get(key) != "1":
            raise SystemExit(f"{fields['case']} invariant failed: {key}")
    if fields["case"] == "getstr_list_shape":
        expected = (
            "INNER_FREE:1,COND_SECOND:1,OUTER_STORE:1>"
            "INNER_FREE:0,COND_SECOND:0,OUTER_STORE:0>"
            "INNER_FREE:1,COND_SECOND:1,OUTER_STORE:1"
        )
        if fields["comments"] != expected:
            raise SystemExit("comment emitted lifecycle drift")
print(f"records={capture['records']} bytes={capture['bytes']} stdout_sha256={actual_hash}")
print("covered_projection=MATCH overall=MISMATCH")
PY
