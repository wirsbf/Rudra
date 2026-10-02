#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

# RETURNFOLD-GAPA-UPSTREAM-0001 locked Ghidra 12.0.4/Rudra bilateral runner.
# The Rust side is built from the master base commit (5943dc6b) via a partial
# git archive with one source overlay — the live src/coreaction.rs carrying
# the MarkExplicit/MarkImplied port — plus the fixture trio copied from the
# live tree; everything is pinned by sha256. The fixture drives the
# production ActionMarkExplicit::perform, ActionMarkImplied::perform and
# PrintC block emission (emit_block_graph -> emitBlockBasic) on four
# scenarios pinning the return-value fold chain (implied fold vs explicit).

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd does not resolve to a regular file" >&2
  exit 1
fi
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_returnfold_upstream_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi
runner_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
runner_mode=$(/usr/bin/stat -Lc '%a' "$runner_fd_path")
if [[ "$runner_mode" != 755 ]]; then
  echo "immutable runner mode mismatch: expected=755 actual=$runner_mode" >&2
  exit 1
fi

validate_only=0
if [[ $# -eq 1 && "$1" == "--validate-only" ]]; then
  validate_only=1
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--validate-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi
cache_parent="$user_home/.cache"
if [[ ! -d "$cache_parent" || -L "$cache_parent" ]]; then
  echo "cache parent is not a real directory: $cache_parent" >&2
  exit 1
fi
cache_root="$cache_parent/rudra-returnfold-upstream-1204"
# Task RETURNFOLD-GAPA-UPSTREAM-0001 dedicated Cargo dirs: every Cargo
# invocation below is serialized on the shared build flock and uses these
# isolated, pre-created directories (never /tmp or a shared target).
cargo_target=/home/wirs/.cache/returnfold-upstream-target
cargo_tmp=/home/wirs/.cache/returnfold-upstream-tmp
/usr/bin/mkdir -p "$cargo_target" "$cargo_tmp"
for cargo_dir in "$cargo_target" "$cargo_tmp"; do
  if [[ ! -d "$cargo_dir" || -L "$cargo_dir" ]]; then
    echo "dedicated Cargo directory is not a regular directory: $cargo_dir" >&2
    exit 1
  fi
done

/usr/bin/mkdir -p "$cache_root/tmp"
run_root=$(/usr/bin/mktemp -d "$cache_root/run.XXXXXX")
cleanup() {
  case "$run_root" in
    "$cache_root"/run.??????) /usr/bin/rm -rf -- "$run_root" ;;
    *) echo "refusing unsafe cleanup target: $run_root" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" \
  "$host_make_bin" "$host_python_bin" "$host_git_bin" \
  "$host_cargo_bin" "$host_rustc_bin"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=5943dc6b36560c82d2519f617cdfb5dcfbb1366a
rudra_base_tree=13fa95d3e8b426a7c85e4a568e30f279f1811e3c
rudra_base_src_tree=7ce946070bb0535d1367d004f2c7d7b1224aaec4
rudra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_expected_records=22
rudra_expected_bytes=1521
rudra_expected_stdout_sha256=c1472b991fac668f098f5ecb082124ab30e9257dc77be6a12c106fe417ecaef5
rudra_expected_stderr_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
bilateral_expected_diff_exit_code=0
bilateral_expected_diff_records=0
bilateral_expected_diff_bytes=0
bilateral_expected_diff_sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
ghidra_root="$repo_root/ghidra"
metadata_live="$repo_root/tests/oracle/returnfold_upstream_1204.metadata.json"
cpp_fixture_live="$repo_root/tests/oracle/returnfold_upstream_1204.cc"
rust_fixture_live="$repo_root/tests/oracle/returnfold_upstream_1204.rs"

# RETURNFOLD-GAPA-UPSTREAM-0001 snapshot model: base master commit 5943dc6b
# plus the live src/coreaction.rs overlay (the MarkExplicit/MarkImplied
# port: baseExplicit full port incl. numInstances rule, multipleInteraction/
# processMultiplier/checkNewToConstructor, MarkImplied count bridge).
overlay_paths=(
  src/coreaction.rs
)
archive_paths=(
  Cargo.toml
  Cargo.lock
  build.rs
  README.md
  benches/decompile_bench.rs
  tests/oracle/decompress_1204.rs
  tests/oracle/funcproto_lock_1204.rs
  examples/curl
  sleigh_specs
  src
  sleigh_shim
)

for required in "$metadata_live" "$cpp_fixture_live" "$rust_fixture_live"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done
for relative in "${overlay_paths[@]}"; do
  required="$repo_root/$relative"
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "source overlay is not a regular non-symlink file: $required" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra source is dirty" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra source has staged changes" >&2
  exit 1
fi

if [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}^{commit}")" != "$rudra_base_commit" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}^{tree}")" != "$rudra_base_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:src")" != "$rudra_base_src_tree" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.toml")" != "$rudra_cargo_toml_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:Cargo.lock")" != "$rudra_cargo_lock_blob" || \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
      "$host_git_bin" -C "$repo_root" rev-parse "${rudra_base_commit}:build.rs")" != "$rudra_build_rs_blob" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

snapshot_root="$run_root/workspace"
/usr/bin/mkdir -p "$snapshot_root/tests/oracle"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$run_root/rudra-base.tar" "$rudra_base_commit" \
  "${archive_paths[@]}"
/usr/bin/tar -xf "$run_root/rudra-base.tar" -C "$snapshot_root"
for relative in "${overlay_paths[@]}"; do
  /usr/bin/cp "$repo_root/$relative" "$snapshot_root/$relative"
done
/usr/bin/cp "$cpp_fixture_live" "$snapshot_root/tests/oracle/returnfold_upstream_1204.cc"
/usr/bin/cp "$rust_fixture_live" "$snapshot_root/tests/oracle/returnfold_upstream_1204.rs"
/usr/bin/cp "$metadata_live" "$snapshot_root/tests/oracle/returnfold_upstream_1204.metadata.json"
if [[ -e "$snapshot_root/ghidra" || -L "$snapshot_root/ghidra" ]]; then
  echo "snapshot unexpectedly already contains a ghidra path" >&2
  exit 1
fi
/usr/bin/ln -s "$ghidra_root" "$snapshot_root/ghidra"

verify_owned_inputs() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
    - "$repo_root" "$snapshot_root" "$metadata_live" "$cpp_fixture_live" \
    "$rust_fixture_live" "$runner_sha" "$oracle_commit" "$oracle_tag" \
    "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_base_commit" \
    "$rudra_base_tree" "$rudra_base_src_tree" "$rudra_cargo_toml_blob" \
    "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" \
    "$rudra_expected_records" "$rudra_expected_bytes" \
    "$rudra_expected_stdout_sha256" "$rudra_expected_stderr_sha256" \
    "$bilateral_expected_diff_exit_code" "$bilateral_expected_diff_records" \
    "$bilateral_expected_diff_bytes" "$bilateral_expected_diff_sha256" \
    "${overlay_paths[@]}" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

(
    repo_raw, snapshot_raw, metadata_raw, cpp_raw, rust_raw, runner_sha,
    oracle_commit, oracle_tag, cpp_tree, makefile_blob, base_commit,
    base_tree, base_src_tree, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    rudra_records, rudra_bytes, rudra_stdout_sha,
    rudra_stderr_sha, bilateral_diff_exit_code, bilateral_diff_records,
    bilateral_diff_bytes, bilateral_diff_sha, *overlay_paths,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
snapshot = pathlib.Path(snapshot_raw).resolve()
metadata = json.loads(pathlib.Path(metadata_raw).read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

require("metadata schema", metadata["schema_version"], 1)
require("fixture id", metadata["fixture_id"], "RETURNFOLD-GAPA-UPSTREAM-0001")
require("overall status", metadata["overall_status"], "MATCH")
require("oracle capture status", metadata["covered_projection"]["oracle_capture"]["status"], "ORACLE_CAPTURED")
require("Rudra execution status", metadata["covered_projection"]["rugra_execution"]["status"], "EXECUTED")
require("bilateral status", metadata["covered_projection"]["bilateral_comparison"]["status"], "MATCH")
require("Rudra build status", metadata["build"]["rugra_build_status"], "EXECUTED")
require("Cargo invocation evidence", metadata["build"]["cargo_invoked"], True)
require("oracle commit", metadata["oracle"]["commit"], oracle_commit)
require("oracle tag", metadata["oracle"]["tag"], oracle_tag)
require("oracle C++ tree", metadata["oracle"]["decompiler_cpp_tree"], cpp_tree)
require("oracle Makefile blob", metadata["oracle"]["decompiler_makefile_blob"], makefile_blob)

comparand = metadata["comparand"]
require("base commit", comparand["rugra_base_commit"], base_commit)
require("base tree", comparand["rugra_base_tree"], base_tree)
require("base src tree", comparand["rugra_base_src_tree"], base_src_tree)
require("Cargo.toml blob", comparand["cargo_toml_blob"], cargo_toml_blob)
require("Cargo.lock blob", comparand["cargo_lock_blob"], cargo_lock_blob)
require("build.rs blob", comparand["build_rs_blob"], build_rs_blob)
require(
    "snapshot model",
    comparand["snapshot_model"],
    "immutable partial crate snapshot: git archive of master base 5943dc6b plus the live src/coreaction.rs overlay (MarkExplicit/MarkImplied port)",
)
require(
    "archive paths",
    comparand["archive_paths"],
    [
        "Cargo.toml", "Cargo.lock", "build.rs", "README.md",
        "benches/decompile_bench.rs", "tests/oracle/decompress_1204.rs",
        "tests/oracle/funcproto_lock_1204.rs", "examples/curl",
        "sleigh_specs", "src", "sleigh_shim",
    ],
)
overlays = {record["path"]: record for record in comparand["overlays"]}
require("overlay paths", set(overlays), set(overlay_paths))
for relative in overlay_paths:
    expected = overlays[relative]["sha256"]
    require(f"{relative} live sha", sha(repo / relative), expected)
    require(f"{relative} snapshot sha", sha(snapshot / relative), expected)
for relative, expected in comparand["base_source_sha256"].items():
    require(f"{relative} snapshot base sha", sha(snapshot / relative), expected)

build_link = comparand["snapshot_build_link"]
require("snapshot build link path", build_link["path"], "ghidra")
link = snapshot / build_link["path"]
if not link.is_symlink():
    raise SystemExit("snapshot ghidra build path is not a symlink")
require("snapshot ghidra link target", link.resolve(), (repo / "ghidra").resolve())

require("C++ fixture hash", sha(cpp_raw), comparand["cpp_fixture_sha256"])
require("Rust fixture hash", sha(rust_raw), comparand["rust_fixture_sha256"])
require("runner hash", runner_sha, comparand["runner_sha256"])

capture = metadata["locked_capture"]
require("locked Ghidra status", capture["status"], "ORACLE_CAPTURED")
paired = metadata["paired_expected"]
require("paired Ghidra status", paired["ghidra"]["status"], "ORACLE_CAPTURED")
require("paired Ghidra runs", paired["ghidra"]["deterministic_runs"], capture["deterministic_runs"])
require("paired Ghidra records", paired["ghidra"]["records"], capture["records"])
require("paired Ghidra bytes", paired["ghidra"]["bytes"], capture["bytes"])
require("paired Ghidra stdout", paired["ghidra"]["stdout_sha256"], capture["stdout_sha256"])
require("paired Ghidra stderr", paired["ghidra"]["stderr_sha256"], capture["stderr_sha256"])
require("paired Rudra status", paired["rugra"]["status"], "EXECUTED")
require("paired Rudra runs", paired["rugra"]["deterministic_runs"], 2)
require("paired Rudra records", paired["rugra"]["records"], int(rudra_records))
require("paired Rudra bytes", paired["rugra"]["bytes"], int(rudra_bytes))
require("paired Rudra stdout", paired["rugra"]["stdout_sha256"], rudra_stdout_sha)
require("paired Rudra stderr", paired["rugra"]["stderr_sha256"], rudra_stderr_sha)
require("bilateral expected status", paired["bilateral"]["status"], "MATCH")
require("bilateral diff exit code", paired["bilateral"]["diff_exit_code"], int(bilateral_diff_exit_code))
require("bilateral diff records", paired["bilateral"]["records"], int(bilateral_diff_records))
require("bilateral diff bytes", paired["bilateral"]["bytes"], int(bilateral_diff_bytes))
require("bilateral diff hash", paired["bilateral"]["diff_sha256"], bilateral_diff_sha)

coverage = metadata["coverage"]
for name, entry in coverage.items():
    if entry["status"] not in {"MATCH", "MISMATCH", "NO_ORACLE", "UNTESTED"}:
        raise SystemExit(f"{name}: invalid coverage status")
for name in ("s1_fold", "s2_merged", "s3_dup3", "s4_mult2"):
    require(f"{name} status", coverage[name]["status"], "MATCH")
for name in ("new_constructor", "addrtied_branches", "cover_crossing", "marking_order"):
    require(f"case_{name} status", coverage[f"case_{name}"]["status"], "UNTESTED")
for name, entry in coverage.items():
    if entry["status"] == "MATCH" and "residual" in entry["detail"]:
        raise SystemExit(f"{name}: MATCH coverage must not cite a residual id")
for residual in metadata["residual_ids"]:
    cited = any(residual in entry["detail"] for entry in coverage.values())
    if not cited:
        raise SystemExit(f"residual {residual} is never cited by coverage")

host = metadata["host_tools"]
require("host cxx", subprocess.check_output(["/usr/bin/g++", "--version"], text=True).splitlines()[0], host["cxx"])
require("host cxx target", subprocess.check_output(["/usr/bin/g++", "-dumpmachine"], text=True).strip(), host["cxx_target"])
require("host cc", subprocess.check_output(["/usr/bin/gcc", "--version"], text=True).splitlines()[0], host["cc"])
require("host cc target", subprocess.check_output(["/usr/bin/gcc", "-dumpmachine"], text=True).strip(), host["cc_target"])
require("host ar", subprocess.check_output(["/usr/bin/ar", "--version"], text=True).splitlines()[0], host["ar"])
require("host make", subprocess.check_output(["/usr/bin/make", "--version"], text=True).splitlines()[0], host["make"])
require("host python", subprocess.check_output(["/usr/bin/python3", "--version"], text=True).strip(), host["python"])
require("host git", subprocess.check_output(["/usr/bin/git", "--version"], text=True).strip(), host["git"])
require("host cargo", subprocess.check_output(["/usr/bin/cargo", "--version"], text=True).strip(), host["cargo"])
require("host rustc", subprocess.check_output(["/usr/bin/rustc", "--version"], text=True).strip(), host["rustc"])
for key, path in {
    "cargo": "/usr/bin/cargo",
    "rustc": "/usr/bin/rustc",
}.items():
    require(f"host {key} binary", sha(path), host["tool_binary_sha256"][key])
PY
}

verify_owned_inputs
if [[ "$validate_only" -eq 1 ]]; then
  echo "returnfold_upstream_1204 metadata/source lock validation passed"
  exit 0
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp | \
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar -xf - -C "$run_root"
oracle_cpp="$run_root/Ghidra/Features/Decompiler/src/decompile/cpp"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$cache_root/tmp" \
  /usr/bin/timeout 600 "$host_make_bin" --no-print-directory -C "$oracle_cpp" -j4 \
  "CXX=$host_cxx_bin -std=c++11" "EXTRA=" libdecomp.a \
  >"$run_root/make.stdout" 2>"$run_root/make.stderr"; then
  /usr/bin/cat "$run_root/make.stdout" >&2
  /usr/bin/cat "$run_root/make.stderr" >&2
  exit 1
fi
standard_archive="$oracle_cpp/libdecomp.a"
if [[ ! -f "$standard_archive" || -L "$standard_archive" ]]; then
  echo "locked Makefile did not produce a regular libdecomp.a" >&2
  exit 1
fi

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$cache_root/tmp" \
  /usr/bin/timeout 600 "$host_cxx_bin" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" \
  "$snapshot_root/tests/oracle/returnfold_upstream_1204.cc" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$standard_archive" \
  -lz -o "$run_root/returnfold_cpp" \
  >"$run_root/cxx.stdout" 2>"$run_root/cxx.stderr"; then
  /usr/bin/cat "$run_root/cxx.stdout" >&2
  /usr/bin/cat "$run_root/cxx.stderr" >&2
  exit 1
fi

if ! /usr/bin/flock -x /tmp/rudra-cargo-build.lock \
  /usr/bin/env -i PATH="$clean_path" HOME="$user_home" LC_ALL=C \
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$cargo_target" \
  TMPDIR="$cargo_tmp" /usr/bin/timeout 600 \
  "$host_cargo_bin" build --offline --locked --quiet \
  --manifest-path "$snapshot_root/Cargo.toml" --lib \
  >"$run_root/cargo.stdout" 2>"$run_root/cargo.stderr"; then
  /usr/bin/cat "$run_root/cargo.stdout" >&2
  /usr/bin/cat "$run_root/cargo.stderr" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" HOME="$user_home" LC_ALL=C \
  TMPDIR="$cargo_tmp" "$host_rustc_bin" --edition=2021 -C opt-level=0 \
  "$snapshot_root/tests/oracle/returnfold_upstream_1204.rs" \
  --extern rudra="$cargo_target/debug/librudra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$run_root/returnfold_rust" \
  >"$run_root/rustc.stdout" 2>"$run_root/rustc.stderr"; then
  /usr/bin/cat "$run_root/rustc.stdout" >&2
  /usr/bin/cat "$run_root/rustc.stderr" >&2
  exit 1
fi

for run in 1 2; do
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$run_root/returnfold_cpp" \
    >"$run_root/ghidra.$run.stdout" 2>"$run_root/ghidra.$run.stderr"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C \
    "$run_root/returnfold_rust" \
    >"$run_root/rudra.$run.stdout" 2>"$run_root/rudra.$run.stderr"
done
if ! /usr/bin/cmp -s "$run_root/ghidra.1.stdout" "$run_root/ghidra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/ghidra.1.stderr" "$run_root/ghidra.2.stderr"; then
  echo "locked Ghidra repeated runs diverged" >&2
  exit 1
fi
if ! /usr/bin/cmp -s "$run_root/rudra.1.stdout" "$run_root/rudra.2.stdout" || \
   ! /usr/bin/cmp -s "$run_root/rudra.1.stderr" "$run_root/rudra.2.stderr"; then
  echo "locked Rudra repeated runs diverged" >&2
  exit 1
fi

set +e
/usr/bin/diff -u --label ghidra --label rudra \
  "$run_root/ghidra.1.stdout" "$run_root/rudra.1.stdout" \
  >"$run_root/bilateral.diff"
diff_rc=$?
set -e
if [[ "$diff_rc" -gt 1 ]]; then
  echo "bilateral diff command failed with status $diff_rc" >&2
  exit 1
fi
if [[ "$diff_rc" -ne 0 ]]; then
  /usr/bin/cat "$run_root/bilateral.diff" >&2
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S \
  - "$metadata_live" "$run_root/ghidra.1.stdout" \
  "$run_root/ghidra.1.stderr" "$run_root/rudra.1.stdout" \
  "$run_root/rudra.1.stderr" "$run_root/bilateral.diff" "$diff_rc" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
ghidra_stdout = pathlib.Path(sys.argv[2]).read_bytes()
ghidra_stderr = pathlib.Path(sys.argv[3]).read_bytes()
rudra_stdout = pathlib.Path(sys.argv[4]).read_bytes()
rudra_stderr = pathlib.Path(sys.argv[5]).read_bytes()
raw_diff = pathlib.Path(sys.argv[6]).read_bytes()
diff_rc = int(sys.argv[7])
capture = metadata["locked_capture"]
paired = metadata["paired_expected"]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

if not ghidra_stdout.endswith(b"\n") or not rudra_stdout.endswith(b"\n"):
    raise SystemExit("bilateral stdout lacks a final newline")
require("oracle records", len(ghidra_stdout.decode("utf-8").splitlines()), capture["records"])
require("oracle bytes", len(ghidra_stdout), capture["bytes"])
require("oracle stdout hash", sha(ghidra_stdout), capture["stdout_sha256"])
require("oracle stderr hash", sha(ghidra_stderr), capture["stderr_sha256"])
require("Rudra records", len(rudra_stdout.decode("utf-8").splitlines()), paired["rugra"]["records"])
require("Rudra bytes", len(rudra_stdout), paired["rugra"]["bytes"])
require("Rudra stdout hash", sha(rudra_stdout), paired["rugra"]["stdout_sha256"])
require("Rudra stderr hash", sha(rudra_stderr), paired["rugra"]["stderr_sha256"])
require("bilateral diff status", diff_rc, paired["bilateral"]["diff_exit_code"])
require("bilateral diff records", len(raw_diff.decode("utf-8").splitlines()), paired["bilateral"]["records"])
require("bilateral diff bytes", len(raw_diff), paired["bilateral"]["bytes"])
require("bilateral diff hash", sha(raw_diff), paired["bilateral"]["diff_sha256"])
if ghidra_stderr:
    raise SystemExit("locked oracle unexpectedly wrote stderr")
if rudra_stderr:
    raise SystemExit("Rudra fixture unexpectedly wrote stderr")

status = "MATCH" if diff_rc == 0 else "MISMATCH"
require("bilateral result status", status, paired["bilateral"]["status"])
print(
    f"oracle_records={len(ghidra_stdout.decode('utf-8').splitlines())} "
    f"oracle_bytes={len(ghidra_stdout)} "
    f"oracle_stdout_sha256={sha(ghidra_stdout)}"
)
print(f"oracle_stderr_sha256={sha(ghidra_stderr)}")
print(
    f"rudra_records={len(rudra_stdout.decode('utf-8').splitlines())} "
    f"rudra_bytes={len(rudra_stdout)} "
    f"rudra_stdout_sha256={sha(rudra_stdout)}"
)
print(f"rudra_stderr_sha256={sha(rudra_stderr)}")
print(
    f"bilateral_diff_records={len(raw_diff.decode('utf-8').splitlines())} "
    f"bilateral_diff_bytes={len(raw_diff)} "
    f"bilateral_diff_sha256={sha(raw_diff)} bilateral_status={status}"
)
print(
    "returnfold_upstream_1204: oracle_status=ORACLE_CAPTURED "
    f"rudra_status=EXECUTED bilateral_status={status} "
    f"overall_status={metadata['overall_status']} "
    "scope=return-value fold chain (MarkExplicit numinstances/multlist + MarkImplied count + PrintC implied inlining)"
)
PY

verify_owned_inputs
