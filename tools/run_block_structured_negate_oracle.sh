#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

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
runner_tmp_parent="$repo_root/target"
/usr/bin/mkdir -p "$runner_tmp_parent"
export TMPDIR="$runner_tmp_parent"
runner="$repo_root/tools/run_block_structured_negate_oracle.sh"
if [[ "$runner_source" != "$runner" ]]; then
  echo "runner fd resolved outside the expected repository path" >&2
  exit 1
fi

mode=full
case "${1:-}" in
  "") ;;
  --validate-only) mode=validate; shift ;;
  --ghidra-only) mode=ghidra; shift ;;
  *) echo "usage: $runner [--validate-only|--ghidra-only]" >&2; exit 2 ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--validate-only|--ghidra-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rudra_base_commit=7e91aef6aa28cbf0a77b9812858c276cafa7fbd3
rudra_base_tree=fd155bc4dd996000d3012c2d49f7244c3a6308ec

ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/block_structured_negate_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/block_structured_negate_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_structured_negate_1204.rs"
block_rs="$repo_root/src/block.rs"
blockaction_rs="$repo_root/src/blockaction.rs"

host_git=/usr/bin/git
host_python=/usr/bin/python3
host_tar=/usr/bin/tar
host_make=/usr/bin/make
host_cxx=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar=$(/usr/bin/readlink -f /usr/bin/ar)
host_cargo=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc=$(/usr/bin/readlink -f /usr/bin/rustc)

for tool in "$host_git" "$host_python" "$host_tar" "$host_make" \
  "$host_cxx" "$host_cc" "$host_ar" "$host_cargo" "$host_rustc"; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for file in "$metadata" "$cpp_fixture" "$rust_fixture" "$block_rs" \
  "$blockaction_rs" "$runner"; do
  if [[ ! -f "$file" || -L "$file" ]]; then
    echo "required input is not a regular non-symlink file: $file" >&2
    exit 1
  fi
done

actual_oracle_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$ghidra_root" rev-parse HEAD)
actual_tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$ghidra_root" \
  rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_oracle_commit" != "$oracle_commit" || \
      "$actual_tag_commit" != "$oracle_commit" || \
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
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

actual_base_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{commit}")
actual_base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  GIT_CONFIG_NOSYSTEM=1 "$host_git" -C "$repo_root" \
  rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_base_commit" != "$rudra_base_commit" || \
      "$actual_base_tree" != "$rudra_base_tree" ]]; then
  echo "pinned Rudra base identity mismatch" >&2
  exit 1
fi

runner_fd_sha=$(/usr/bin/sha256sum "$runner_fd_path" | /usr/bin/awk '{print $1}')
host_cxx_version=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx" --version | /usr/bin/head -1)
host_cxx_target=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cxx" -dumpmachine)
host_rustc_version=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_rustc" --version)
host_cargo_version=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_cargo" --version)

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_python" -I -S - "$repo_root" "$metadata" "$cpp_fixture" \
  "$rust_fixture" "$block_rs" "$blockaction_rs" "$runner_fd_path" \
  "$runner_fd_sha" "$ghidra_root" "$oracle_tag" "$oracle_commit" \
  "$oracle_cpp_tree" "$oracle_makefile_blob" "$rudra_base_commit" \
  "$rudra_base_tree" "$host_cxx_version" "$host_cxx_target" \
  "$host_rustc_version" "$host_cargo_version" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    repo_raw, metadata_raw, cpp_raw, rust_raw, block_raw, blockaction_raw,
    runner_fd_raw, runner_fd_sha, ghidra_raw, oracle_tag, oracle_commit,
    cpp_tree, makefile_blob, base_commit, base_tree, host_cxx,
    host_cxx_target, host_rustc, host_cargo,
) = sys.argv[1:]
repo = pathlib.Path(repo_raw).resolve()
ghidra = pathlib.Path(ghidra_raw).resolve()
metadata_path = pathlib.Path(metadata_raw).resolve()
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

def reject_pending(value, path="metadata"):
    if isinstance(value, dict):
        for key, child in value.items():
            reject_pending(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_pending(child, f"{path}[{index}]")
    elif isinstance(value, str) and value.startswith("PENDING"):
        raise SystemExit(f"{path} is pending: {value}")

reject_pending(metadata)
require("fixture schema", metadata["schema"], 2)
require("fixture id", metadata["fixture_id"], "BLOCK-STRUCTURED-NEGATE-0001")
oracle = metadata["oracle"]
require("oracle tag", oracle["tag"], oracle_tag)
require("oracle commit", oracle["commit"], oracle_commit)
require("oracle cpp tree", oracle["cpp_tree"], cpp_tree)
require("oracle Makefile blob", oracle["makefile_blob"], makefile_blob)
require("architecture", metadata["architecture"], "x86:LE:64:default")
require("compiler spec", metadata["compiler_spec"]["id"], "gcc")

manifest_bytes = json.dumps(
    metadata["input_manifest"], sort_keys=True, separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
require(
    "input fingerprint", metadata["input_fingerprint"],
    "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
)

comparand = metadata["comparand"]
require("C++ fixture", sha(cpp_raw), comparand["cpp_fixture_sha256"])
require("Rust fixture", sha(rust_raw), comparand["rust_fixture_sha256"])
require("runner fd", runner_fd_sha, comparand["runner_sha256"])
require("block.rs", sha(block_raw), comparand["block_rs_sha256"])
require("blockaction.rs", sha(blockaction_raw), comparand["blockaction_rs_sha256"])

oracle_cpp = ghidra / "Ghidra/Features/Decompiler/src/decompile/cpp"
for key, name in (
    ("block_cc_sha256", "block.cc"),
    ("block_hh_sha256", "block.hh"),
    ("blockaction_cc_sha256", "blockaction.cc"),
    ("blockaction_hh_sha256", "blockaction.hh"),
):
    require(name, sha(oracle_cpp / name), comparand[key])

source_files = sorted(
    (p for p in (repo / "src").rglob("*.rs") if p.is_file() and not p.is_symlink()),
    key=lambda p: p.relative_to(repo).as_posix(),
)
h = hashlib.sha256()
h.update(b"rudra-block-structured-negate-full-src-overlay-v1\0")
for path in source_files:
    rel = path.relative_to(repo).as_posix().encode("utf-8")
    data = path.read_bytes()
    h.update(len(rel).to_bytes(8, "big")); h.update(rel)
    h.update(len(data).to_bytes(8, "big")); h.update(data)
overlay = metadata["rugra_source"]["overlay"]
require("overlay file count", len(source_files), overlay["file_count"])
require("overlay tree", h.hexdigest(), overlay["tree_sha256"])
require("Rudra base commit", metadata["rugra_source"]["base_commit"], base_commit)
require("Rudra base tree", metadata["rugra_source"]["base_tree"], base_tree)

require("host C++", host_cxx, metadata["host"]["cxx"])
require("host C++ target", host_cxx_target, metadata["host"]["cxx_target"])
require("host rustc", host_rustc, metadata["host"]["rustc"])
require("host cargo", host_cargo, metadata["host"]["cargo"])
require("scoped status", metadata["coverage"]["scoped_status"], "MATCH")
require("full status", metadata["coverage"]["full_status"], "MISMATCH")
PY

if [[ "$mode" == validate ]]; then
  echo "block_structured_negate_1204: VALIDATED"
  exit 0
fi

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | \
  /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$user_home" || ! -d "$user_home" ]]; then
  echo "could not resolve current user's home directory" >&2
  exit 1
fi

temp_parent="$repo_root/target/oracle-runs"
/usr/bin/mkdir -p "$temp_parent"
run_tmp=$(/usr/bin/mktemp -d "$temp_parent/block-structured-negate-1204.XXXXXX")
cleanup() {
  case "$run_tmp" in
    "$temp_parent"/block-structured-negate-1204.??????)
      /usr/bin/rm -rf -- "$run_tmp" ;;
    *) echo "refusing unsafe cleanup target: $run_tmp" >&2; return 1 ;;
  esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

source_files=()
while IFS= read -r -d '' source_file; do source_files+=("$source_file"); done < <(
  /usr/bin/find "$repo_root/src" -type f -name '*.rs' -print0 | /usr/bin/sort -z
)
owned_files=("$metadata" "$cpp_fixture" "$rust_fixture" "$runner" \
  "${source_files[@]}")
/usr/bin/sha256sum "${owned_files[@]}" >"$run_tmp/owned.before"

oracle_archive="$run_tmp/oracle.tar"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$ghidra_root" archive --format=tar \
  --output="$oracle_archive" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/mkdir -p "$run_tmp/oracle-source"
"$host_tar" -xf "$oracle_archive" -C "$run_tmp/oracle-source"
oracle_cpp="$run_tmp/oracle-source/Ghidra/Features/Decompiler/src/decompile/cpp"

jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$run_tmp" \
  "$host_make" --silent -C "$oracle_cpp" -j "$jobs" \
  CXX="$host_cxx -std=c++11" CC="$host_cc" AR="$host_ar" EXTRA= \
  libdecomp.a >"$run_tmp/make.stdout" 2>"$run_tmp/make.stderr"; then
  /usr/bin/cat "$run_tmp/make.stdout" >&2
  /usr/bin/cat "$run_tmp/make.stderr" >&2
  exit 1
fi

cpp_binary="$run_tmp/block_structured_negate_cpp"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$run_tmp" \
  "$host_cxx" -std=c++11 -O2 -Wall -Wno-sign-compare -m64 \
  -I"$oracle_cpp" "$cpp_fixture" "$oracle_cpp/libdecomp.cc" \
  "$oracle_cpp/sleigh_arch.cc" "$oracle_cpp/inject_sleigh.cc" \
  -Wl,--whole-archive "$oracle_cpp/libdecomp.a" -Wl,--no-whole-archive \
  -lz -o "$cpp_binary" >"$run_tmp/cxx.stdout" 2>"$run_tmp/cxx.stderr"; then
  /usr/bin/cat "$run_tmp/cxx.stdout" >&2
  /usr/bin/cat "$run_tmp/cxx.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$cpp_binary" \
  >"$run_tmp/ghidra.stdout" 2>"$run_tmp/ghidra.stderr"
ghidra_status=$?
set -e
if [[ "$ghidra_status" -ne 0 || -s "$run_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture failed or emitted diagnostics" >&2
  /usr/bin/cat "$run_tmp/ghidra.stderr" >&2
  exit 1
fi

expected_stdout=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python" -I -S -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' \
  "$metadata")
ghidra_stdout_sha=$(/usr/bin/sha256sum "$run_tmp/ghidra.stdout" | \
  /usr/bin/awk '{print $1}')
if [[ "$ghidra_stdout_sha" != "$expected_stdout" ]]; then
  echo "locked Ghidra stdout hash mismatch: $ghidra_stdout_sha" >&2
  exit 1
fi

if [[ "$mode" == ghidra ]]; then
  /usr/bin/cat "$run_tmp/ghidra.stdout"
  echo "block_structured_negate_1204: GHIDRA_LOCKED_OUTPUT_OK stdout_sha256=$ghidra_stdout_sha"
  exit 0
fi

snapshot="$run_tmp/rudra-snapshot"
/usr/bin/mkdir -p "$snapshot"
base_archive="$run_tmp/rudra-base.tar"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git" -C "$repo_root" archive --format=tar --output="$base_archive" \
  "$rudra_base_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/oracle/decompress_1204.rs \
  tests/oracle/funcproto_lock_1204.rs sleigh_shim
"$host_tar" -xf "$base_archive" -C "$snapshot"
/usr/bin/cp -a "$repo_root/src" "$snapshot/src"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python" -I -S - \
  "$metadata" "$snapshot" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
snapshot = pathlib.Path(sys.argv[2])
files = sorted(
    (p for p in (snapshot / "src").rglob("*.rs") if p.is_file() and not p.is_symlink()),
    key=lambda p: p.relative_to(snapshot).as_posix(),
)
h = hashlib.sha256()
h.update(b"rudra-block-structured-negate-full-src-overlay-v1\0")
for path in files:
    rel = path.relative_to(snapshot).as_posix().encode("utf-8")
    data = path.read_bytes()
    h.update(len(rel).to_bytes(8, "big")); h.update(rel)
    h.update(len(data).to_bytes(8, "big")); h.update(data)
overlay = metadata["rugra_source"]["overlay"]
if len(files) != overlay["file_count"] or h.hexdigest() != overlay["tree_sha256"]:
    raise SystemExit(
        f"snapshotted source overlay mismatch: files={len(files)} tree={h.hexdigest()}"
    )

comparand = metadata["comparand"]
for key, relative in (
    ("cargo_toml_sha256", "Cargo.toml"),
    ("cargo_lock_sha256", "Cargo.lock"),
    ("build_rs_sha256", "build.rs"),
    ("readme_sha256", "README.md"),
    ("bench_decompile_sha256", "benches/decompile_bench.rs"),
    ("example_decompress_sha256", "tests/oracle/decompress_1204.rs"),
    ("example_funcproto_sha256", "tests/oracle/funcproto_lock_1204.rs"),
):
    actual = hashlib.sha256((snapshot / relative).read_bytes()).hexdigest()
    if actual != comparand[key]:
        raise SystemExit(
            f"snapshotted {relative} mismatch: "
            f"expected={comparand[key]} actual={actual}"
        )
PY
/usr/bin/mkdir -p "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile"
/usr/bin/ln -s "$oracle_cpp" \
  "$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"

cargo_target="$run_tmp/cargo-target"
if ! /usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 \
  CARGO_HOME="$user_home/.cargo" CARGO_TARGET_DIR="$cargo_target" \
  CARGO_NET_OFFLINE=true TMPDIR="$run_tmp" CXX="$host_cxx" CC="$host_cc" \
  AR="$host_ar" RUSTC="$host_rustc" \
  "$host_cargo" build --offline --locked --quiet \
  --manifest-path "$snapshot/Cargo.toml" --lib \
  >"$run_tmp/cargo.stdout" 2>"$run_tmp/cargo.stderr"; then
  /usr/bin/cat "$run_tmp/cargo.stdout" >&2
  /usr/bin/cat "$run_tmp/cargo.stderr" >&2
  exit 1
fi

rudra_rlib="$cargo_target/debug/librudra.rlib"
native_archives=()
while IFS= read -r archive; do native_archives+=("$archive"); done < <(
  /usr/bin/find "$cargo_target/debug/build" -path '*/out/librudra_sleigh.a' -type f
)
if [[ ! -f "$rudra_rlib" || -L "$rudra_rlib" || \
      "${#native_archives[@]}" -ne 1 ]]; then
  echo "missing or ambiguous fresh Rust link inputs" >&2
  exit 1
fi
native_dir=$(/usr/bin/dirname "${native_archives[0]}")
rust_binary="$run_tmp/block_structured_negate_rust"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 TMPDIR="$run_tmp" \
  "$host_rustc" --edition=2021 -O -L "dependency=$cargo_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$rust_binary" \
  >"$run_tmp/rustc.stdout" 2>"$run_tmp/rustc.stderr"; then
  /usr/bin/cat "$run_tmp/rustc.stdout" >&2
  /usr/bin/cat "$run_tmp/rustc.stderr" >&2
  exit 1
fi
if [[ -s "$run_tmp/rustc.stdout" || -s "$run_tmp/rustc.stderr" ]]; then
  echo "Rust fixture compilation emitted diagnostics" >&2
  /usr/bin/cat "$run_tmp/rustc.stdout" >&2
  /usr/bin/cat "$run_tmp/rustc.stderr" >&2
  exit 1
fi

set +e
/usr/bin/env -i PATH="$clean_path" LC_ALL=C.UTF-8 "$rust_binary" \
  >"$run_tmp/rudra.stdout" 2>"$run_tmp/rudra.stderr"
rudra_status=$?
/usr/bin/diff -u --label ghidra --label rudra "$run_tmp/ghidra.stdout" \
  "$run_tmp/rudra.stdout" >"$run_tmp/raw.diff"
diff_status=$?
set -e
if [[ "$rudra_status" -ne 0 ]]; then
  echo "Rudra fixture failed" >&2
  /usr/bin/cat "$run_tmp/rudra.stderr" >&2
  exit 1
fi
if [[ "$diff_status" -ne 0 ]]; then
  /usr/bin/cat "$run_tmp/raw.diff" >&2
  exit 1
fi

rudra_stdout_sha=$(/usr/bin/sha256sum "$run_tmp/rudra.stdout" | \
  /usr/bin/awk '{print $1}')
rudra_stderr_sha=$(/usr/bin/sha256sum "$run_tmp/rudra.stderr" | \
  /usr/bin/awk '{print $1}')
expected_rudra_stderr=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
  "$host_python" -I -S -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["expected_rudra_stderr_sha256"])' \
  "$metadata")
if [[ "$rudra_stdout_sha" != "$expected_stdout" || \
      "$rudra_stderr_sha" != "$expected_rudra_stderr" ]]; then
  echo "Rudra output hash mismatch: stdout=$rudra_stdout_sha stderr=$rudra_stderr_sha" >&2
  exit 1
fi

/usr/bin/sha256sum "${owned_files[@]}" >"$run_tmp/owned.after"
if ! /usr/bin/cmp -s "$run_tmp/owned.before" "$run_tmp/owned.after"; then
  echo "owned fixture/comparand input changed during run" >&2
  exit 1
fi

/usr/bin/cat "$run_tmp/ghidra.stdout"
echo "block_structured_negate_1204: scoped=MATCH full=MISMATCH residual=RUDRA_DIAGNOSTIC_STDERR stdout_sha256=$ghidra_stdout_sha rudra_stderr_sha256=$rudra_stderr_sha"
