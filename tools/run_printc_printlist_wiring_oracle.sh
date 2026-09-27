#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_printc_printlist_wiring_oracle.sh"
if [[ -z "$runner_source" || "$runner_source" != "$runner" || \
      ! -f "$runner_source" || -L "$runner_source" ]]; then
  echo "immutable runner fd did not resolve to the expected regular file" >&2
  exit 1
fi

ghidra_only=false
if [[ ${1:-} == "--ghidra-only" ]]; then
  ghidra_only=true
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "usage: $runner [--ghidra-only]" >&2
  exit 2
fi

clean_path=/usr/bin:/bin
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
rugra_base_commit=6a458387
rugra_base_tree=623ef61ad2e18b337da538d455239134a6c02193
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/printc_printlist_wiring_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/printc_printlist_wiring_1204.cc"
rust_fixture="$repo_root/tests/oracle/printc_printlist_wiring_1204.rs"
prettyprint_rs="$repo_root/src/prettyprint.rs"
printlanguage_rs="$repo_root/src/printlanguage.rs"
printc_rs="$repo_root/src/printc.rs"
arch_rs="$repo_root/src/arch.rs"
options_rs="$repo_root/src/options.rs"
prettyprint_doc="$repo_root/docs/api/prettyprint.md"
printlanguage_doc="$repo_root/docs/api/printlanguage.md"
printc_doc="$repo_root/docs/api/printc.md"
arch_doc="$repo_root/docs/api/arch.md"
options_doc="$repo_root/docs/api/options.md"
cargo_lock=/tmp/rugra-cargo-build.lock

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
# The cargo target and compiler temp dir live under the user home rather
# than /tmp because this host mounts /tmp as a quota-limited tmpfs shared
# by the concurrent agent fleet (same rationale as the
# OPTIONS-SPLITDATATYPE-WIRING-0003 re-pin).
cargo_target="$user_home/.cache/rugra-target-printc-printlist"
build_tmpdir="$user_home/.cache/rugra-printc-printlist-tmp"
/usr/bin/mkdir -p "$build_tmpdir"
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
# cargo/rustc are rustup-managed under the user home on this host (the
# /usr/bin/cargo assumption of the OPTIONS-WIRING runner is a known
# environment drift); resolve them through the home bin directory while
# keeping the otherwise clean environment. `rustup which` follows the
# shim to the real toolchain binary so --version captures the compiler
# line, not the rustup banner.
host_cargo_path=$(/usr/bin/env -i HOME="$user_home" \
  PATH="$clean_path:$user_home/.cargo/bin" /usr/bin/sh -c 'rustup which cargo')
host_cargo_bin=$(/usr/bin/readlink -f "$host_cargo_path")
host_rustc_path=$(/usr/bin/env -i HOME="$user_home" \
  PATH="$clean_path:$user_home/.cargo/bin" /usr/bin/sh -c 'rustup which rustc')
host_rustc_bin=$(/usr/bin/readlink -f "$host_rustc_path")
if [[ -z "$host_cargo_bin" || -z "$host_rustc_bin" ]]; then
  echo "could not resolve cargo/rustc through $user_home/.cargo/bin" >&2
  exit 1
fi
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin" \
  /usr/bin/flock /usr/bin/tar /usr/bin/sha256sum; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$prettyprint_rs" \
  "$printlanguage_rs" "$printc_rs" "$arch_rs" "$options_rs" \
  "$prettyprint_doc" "$printlanguage_doc" "$printc_doc" "$arch_doc" \
  "$options_doc" "$runner"; do
  if [[ ! -f "$input" || -L "$input" ]]; then
    echo "required input is not a regular non-symlink file: $input" >&2
    exit 1
  fi
done

actual_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
cpp_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
makefile_blob=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
base_tree=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" rev-parse "$rugra_base_commit^{tree}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" || \
      "$base_tree" != "$rugra_base_tree" ]]; then
  echo "locked oracle or pinned Rugra base identity mismatch" >&2
  exit 1
fi
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp || \
   ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" diff --cached --quiet -- \
  Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi

host_cxx=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_cxx_bin" --version | /usr/bin/head -1)
host_rustc=$(/usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 "$host_rustc_bin" --version)
host_cargo=$(/usr/bin/env -i HOME="$user_home" PATH="$clean_path" LC_ALL=C.UTF-8 "$host_cargo_bin" --version)
host_platform=$(/usr/bin/uname -srm)

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$prettyprint_rs" \
  "$printlanguage_rs" "$printc_rs" "$arch_rs" "$options_rs" \
  "$prettyprint_doc" "$printlanguage_doc" "$printc_doc" "$arch_doc" \
  "$options_doc" "$runner_fd_path" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rugra_base_commit" "$rugra_base_tree" \
  "$host_cxx" "$host_rustc" "$host_cargo" "$host_platform" <<'PY'
import hashlib, json, pathlib, sys
(metadata_name, cpp_name, rust_name, prettyprint_name, printlanguage_name,
 printc_name, arch_name, options_name, prettyprint_doc_name,
 printlanguage_doc_name, printc_doc_name, arch_doc_name, options_doc_name,
 runner_name, oracle_commit, oracle_tag, cpp_tree, makefile_blob, base_commit,
 base_tree, host_cxx, host_rustc, host_cargo, host_platform) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["fixture_id"] != "PRINTC-PRINTLIST-WIRING-0001":
    raise SystemExit("fixture id mismatch")
if metadata["covered_projection_status"] != "MATCH":
    raise SystemExit("covered projection is not MATCH")
if not metadata["overall_status"].startswith("MATCH"):
    raise SystemExit("overall status must remain MATCH-conservative")
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit,
        "decompiler_cpp_tree": cpp_tree, "decompiler_makefile_blob": makefile_blob}:
    raise SystemExit("oracle metadata mismatch")
comparand = metadata["comparand"]
if comparand["rugra_base_commit"] != base_commit or comparand["rugra_base_tree"] != base_tree:
    raise SystemExit("Rugra base metadata mismatch")
canonical = json.dumps(metadata["input"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()
if metadata["input_fingerprint"] != "sha256:" + hashlib.sha256(canonical).hexdigest():
    raise SystemExit("input fingerprint mismatch")
for field, filename in {
    "cpp_fixture_sha256": cpp_name, "rust_fixture_sha256": rust_name,
}.items():
    actual = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
    if metadata[field] != actual:
        raise SystemExit(f"fixture comparand mismatch for {field}: {actual}")
for field, filename in {
    "prettyprint_rs_sha256": prettyprint_name,
    "printlanguage_rs_sha256": printlanguage_name,
    "printc_rs_sha256": printc_name, "arch_rs_sha256": arch_name,
    "options_rs_sha256": options_name,
    "prettyprint_doc_sha256": prettyprint_doc_name,
    "printlanguage_doc_sha256": printlanguage_doc_name,
    "printc_doc_sha256": printc_doc_name, "arch_doc_sha256": arch_doc_name,
    "options_doc_sha256": options_doc_name,
    "runner_sha256": runner_name,
}.items():
    actual = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
    if comparand[field] != actual:
        raise SystemExit(f"comparand mismatch for {field}: {actual}")
if comparand["host"] != {"cxx": host_cxx, "rustc": host_rustc,
        "cargo": host_cargo, "rust_toolchain": "system", "platform": host_platform}:
    raise SystemExit("host metadata mismatch")
PY

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rugra-printc-printlist-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rugra-printc-printlist-1204.?????? || \
        ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "refusing unexpected cleanup path: $oracle_tmp" >&2
    return 1
  fi
  /usr/bin/rm -rf -- "$oracle_tmp"
  if [[ "$build_tmpdir" == "$user_home"/.cache/rugra-printc-printlist-tmp && \
        -d "$build_tmpdir" && ! -L "$build_tmpdir" ]]; then
    /usr/bin/rm -rf -- "$build_tmpdir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
owned=("$cpp_fixture" "$rust_fixture" "$prettyprint_rs" "$printlanguage_rs" \
  "$printc_rs" "$arch_rs" "$options_rs" "$prettyprint_doc" \
  "$printlanguage_doc" "$printc_doc" "$arch_doc" "$options_doc" \
  "$metadata" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"

/usr/bin/mkdir -p "$oracle_tmp/source" "$oracle_tmp/rugra"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$ghidra_root" archive --format=tar \
  --output="$oracle_tmp/ghidra-cpp.tar" "$oracle_commit" \
  Ghidra/Features/Decompiler/src/decompile/cpp
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar \
  -xf "$oracle_tmp/ghidra-cpp.tar" -C "$oracle_tmp/source"
oracle_cpp="$oracle_tmp/source/Ghidra/Features/Decompiler/src/decompile/cpp"
jobs=$(/usr/bin/getconf _NPROCESSORS_ONLN 2>/dev/null || /usr/bin/printf '1')
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmpdir" \
  "$host_make_bin" --silent \
  -C "$oracle_cpp" -j "$jobs" CXX="$host_cxx_bin -std=c++11" \
  CC="$host_cc_bin" AR="$host_ar_bin" EXTRA= libdecomp.a
cpp_binary="$oracle_tmp/printc_printlist_wiring_cpp"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$build_tmpdir" "$host_cxx_bin" \
  -std=c++11 -O2 -Wall -Wno-sign-compare -m64 -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" -Wl,--whole-archive "$oracle_cpp/libdecomp.a" \
  -Wl,--no-whole-archive -lz -o "$cpp_binary"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cpp_binary" >"$oracle_tmp/ghidra.stdout"
expected_sha=$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$host_python_bin" -I -S -c \
  'import json,sys;print(json.load(open(sys.argv[1]))["expected_stdout_sha256"])' "$metadata")
actual_sha=$(/usr/bin/sha256sum "$oracle_tmp/ghidra.stdout" | /usr/bin/awk '{print $1}')
if [[ "$actual_sha" != "$expected_sha" ]]; then
  echo "Ghidra stdout sha256 mismatch: $actual_sha" >&2
  exit 1
fi
if [[ "$ghidra_only" == true ]]; then
  /usr/bin/cat "$oracle_tmp/ghidra.stdout"
  echo "PRINTC-PRINTLIST-WIRING-0001 locked Ghidra projection SHA256 $actual_sha" >&2
  exit 0
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rugra-base.tar" "$rugra_base_commit"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar \
  -xf "$oracle_tmp/rugra-base.tar" -C "$oracle_tmp/rugra"
/usr/bin/cp -- "$prettyprint_rs" "$oracle_tmp/rugra/src/prettyprint.rs"
/usr/bin/cp -- "$printlanguage_rs" "$oracle_tmp/rugra/src/printlanguage.rs"
/usr/bin/cp -- "$printc_rs" "$oracle_tmp/rugra/src/printc.rs"
/usr/bin/cp -- "$arch_rs" "$oracle_tmp/rugra/src/arch.rs"
/usr/bin/cp -- "$options_rs" "$oracle_tmp/rugra/src/options.rs"
/usr/bin/mkdir -p "$oracle_tmp/rugra/src/bin"
/usr/bin/cp -- "$rust_fixture" \
  "$oracle_tmp/rugra/src/bin/printc_printlist_wiring_1204_fixture.rs"
/usr/bin/ln -s "$ghidra_root" "$oracle_tmp/rugra/ghidra"

# cargo needs rustc on PATH; expose the resolved toolchain bin directory
# (rustup-managed on this host) alongside the clean path.
rustc_bindir=$(/usr/bin/dirname "$host_rustc_bin")
/usr/bin/flock "$cargo_lock" /usr/bin/env -i HOME="$user_home" \
  PATH="$clean_path:$user_home/.cargo/bin:$rustc_bindir" \
  LC_ALL=C.UTF-8 TMPDIR="$build_tmpdir" \
  CARGO_HOME="$user_home/.cargo" \
  CARGO_TARGET_DIR="$cargo_target" CARGO_INCREMENTAL=0 \
  "$host_cargo_bin" run --quiet --offline --locked \
  --manifest-path "$oracle_tmp/rugra/Cargo.toml" \
  --bin printc_printlist_wiring_1204_fixture >"$oracle_tmp/rust.stdout"
if ! /usr/bin/cmp -s "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rust.stdout"; then
  /usr/bin/diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rust.stdout" >&2 || true
  exit 1
fi
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.after"
if ! /usr/bin/cmp -s "$oracle_tmp/owned.before" "$oracle_tmp/owned.after"; then
  echo "owned inputs changed while the runner was active" >&2
  /usr/bin/diff -u "$oracle_tmp/owned.before" "$oracle_tmp/owned.after" >&2 || true
  exit 1
fi
records=$(/usr/bin/wc -l <"$oracle_tmp/ghidra.stdout")
echo "PRINTC-PRINTLIST-WIRING-0001 B2 covered projection MATCH ($records lines) SHA256 $actual_sha"
