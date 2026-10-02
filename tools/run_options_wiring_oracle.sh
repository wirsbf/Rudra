#!/usr/bin/env -S -i PATH=/usr/bin:/bin /usr/bin/bash
set -euo pipefail

runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash "$runner_fd_path" "$@"
fi
runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
runner="$repo_root/tools/run_options_wiring_oracle.sh"
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
rudra_base_commit=fce01555
rudra_base_tree=37bc660cdefa47c5844d596d00caad8b8edd810a
ghidra_root="$repo_root/ghidra"
metadata="$repo_root/tests/oracle/options_wiring_1204.metadata.json"
cpp_fixture="$repo_root/tests/oracle/options_wiring_1204.cc"
rust_fixture="$repo_root/tests/oracle/options_wiring_1204.rs"
action_rs="$repo_root/src/action.rs"
arch_rs="$repo_root/src/arch.rs"
options_rs="$repo_root/src/options.rs"
action_doc="$repo_root/docs/api/action.md"
arch_doc="$repo_root/docs/api/arch.md"
options_doc="$repo_root/docs/api/options.md"
cargo_lock=/tmp/rudra-cargo-build.lock

user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | /usr/bin/awk -F: 'NR == 1 { print $6 }')
# The cargo target and compiler temp dir live under the user home rather
# than /tmp because this host mounts /tmp as a quota-limited tmpfs shared
# by the concurrent agent fleet: cc-rs's c++ invocations and g++'s internal
# .s temp files otherwise exhaust the per-user quota
# (OPTIONS-SPLITDATATYPE-WIRING-0003 re-pin).
cargo_target="$user_home/.cache/rudra-target-options-wiring"
build_tmpdir="$user_home/.cache/rudra-options-wiring-tmp"
/usr/bin/mkdir -p "$build_tmpdir"
host_cxx_bin=$(/usr/bin/readlink -f /usr/bin/g++)
host_cc_bin=$(/usr/bin/readlink -f /usr/bin/gcc)
host_ar_bin=$(/usr/bin/readlink -f /usr/bin/ar)
host_make_bin=$(/usr/bin/readlink -f /usr/bin/make)
host_python_bin=$(/usr/bin/readlink -f /usr/bin/python3)
host_git_bin=$(/usr/bin/readlink -f /usr/bin/git)
host_cargo_bin=$(/usr/bin/readlink -f /usr/bin/cargo)
host_rustc_bin=$(/usr/bin/readlink -f /usr/bin/rustc)
for tool in "$host_cxx_bin" "$host_cc_bin" "$host_ar_bin" "$host_make_bin" \
  "$host_python_bin" "$host_git_bin" "$host_cargo_bin" "$host_rustc_bin" \
  /usr/bin/flock /usr/bin/tar /usr/bin/sha256sum; do
  if [[ ! -x "$tool" ]]; then
    echo "required tool is not executable: $tool" >&2
    exit 1
  fi
done
for input in "$metadata" "$cpp_fixture" "$rust_fixture" "$action_rs" \
  "$arch_rs" "$options_rs" "$action_doc" "$arch_doc" "$options_doc" "$runner"; do
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
  "$host_git_bin" -C "$repo_root" rev-parse "$rudra_base_commit^{tree}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" || \
      "$cpp_tree" != "$oracle_cpp_tree" || "$makefile_blob" != "$oracle_makefile_blob" || \
      "$base_tree" != "$rudra_base_tree" ]]; then
  echo "locked oracle or pinned Rudra base identity mismatch" >&2
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
  "$metadata" "$cpp_fixture" "$rust_fixture" "$action_rs" "$arch_rs" \
  "$options_rs" "$action_doc" "$arch_doc" "$options_doc" "$runner_fd_path" \
  "$oracle_commit" "$oracle_tag" "$oracle_cpp_tree" \
  "$oracle_makefile_blob" "$rudra_base_commit" "$rudra_base_tree" \
  "$host_cxx" "$host_rustc" "$host_cargo" "$host_platform" <<'PY'
import hashlib, json, pathlib, sys
(metadata_name, cpp_name, rust_name, action_name, arch_name, options_name,
 action_doc_name, arch_doc_name, options_doc_name, runner_name, oracle_commit,
 oracle_tag, cpp_tree, makefile_blob, base_commit, base_tree, host_cxx,
 host_rustc, host_cargo, host_platform) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
if metadata["fixture_id"] != "OPTIONS-SPLITDATATYPE-WIRING-0002":
    raise SystemExit("fixture id mismatch")
if metadata["covered_projection_status"] != "MATCH":
    raise SystemExit("covered projection is not MATCH")
if metadata["overall_status"] != "MISMATCH":
    raise SystemExit("overall status must remain conservative")
if metadata["oracle"] != {"tag": oracle_tag, "commit": oracle_commit,
        "decompiler_cpp_tree": cpp_tree, "decompiler_makefile_blob": makefile_blob}:
    raise SystemExit("oracle metadata mismatch")
comparand = metadata["comparand"]
if comparand["rugra_base_commit"] != base_commit or comparand["rugra_base_tree"] != base_tree:
    raise SystemExit("Rudra base metadata mismatch")
canonical = json.dumps(metadata["input"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()
if metadata["input_fingerprint"] != "sha256:" + hashlib.sha256(canonical).hexdigest():
    raise SystemExit("input fingerprint mismatch")
for field, filename in {
    "cpp_fixture_sha256": cpp_name, "rust_fixture_sha256": rust_name,
    "action_rs_sha256": action_name, "arch_rs_sha256": arch_name,
    "options_rs_sha256": options_name,
    "action_doc_sha256": action_doc_name, "arch_doc_sha256": arch_doc_name,
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

oracle_tmp=$(/usr/bin/mktemp -d /tmp/rudra-options-wiring-1204.XXXXXX)
cleanup() {
  if [[ "$oracle_tmp" != /tmp/rudra-options-wiring-1204.?????? || \
        ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "refusing unexpected cleanup path: $oracle_tmp" >&2
    return 1
  fi
  /usr/bin/rm -rf -- "$oracle_tmp"
  if [[ "$build_tmpdir" == "$user_home"/.cache/rudra-options-wiring-tmp && \
        -d "$build_tmpdir" && ! -L "$build_tmpdir" ]]; then
    /usr/bin/rm -rf -- "$build_tmpdir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
owned=("$cpp_fixture" "$rust_fixture" "$action_rs" "$arch_rs" "$options_rs" \
  "$action_doc" "$arch_doc" "$options_doc" "$metadata" "$runner")
/usr/bin/sha256sum "${owned[@]}" >"$oracle_tmp/owned.before"

/usr/bin/mkdir -p "$oracle_tmp/source" "$oracle_tmp/rudra"
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
cpp_binary="$oracle_tmp/action_pool_clone_filter_cpp"
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
  echo "OPTIONS-SPLITDATATYPE-WIRING-0002 locked Ghidra projection SHA256 $actual_sha" >&2
  exit 0
fi

/usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
  "$host_git_bin" -C "$repo_root" archive --format=tar \
  --output="$oracle_tmp/rudra-base.tar" "$rudra_base_commit"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C /usr/bin/tar \
  -xf "$oracle_tmp/rudra-base.tar" -C "$oracle_tmp/rudra"
/usr/bin/cp -- "$action_rs" "$oracle_tmp/rudra/src/action.rs"
/usr/bin/cp -- "$arch_rs" "$oracle_tmp/rudra/src/arch.rs"
/usr/bin/cp -- "$options_rs" "$oracle_tmp/rudra/src/options.rs"
/usr/bin/mkdir -p "$oracle_tmp/rudra/src/bin"
/usr/bin/cp -- "$rust_fixture" \
  "$oracle_tmp/rudra/src/bin/options_wiring_1204_fixture.rs"
/usr/bin/ln -s "$ghidra_root" "$oracle_tmp/rudra/ghidra"

/usr/bin/flock "$cargo_lock" /usr/bin/env -i HOME="$user_home" \
  PATH="$clean_path" LC_ALL=C.UTF-8 TMPDIR="$build_tmpdir" \
  CARGO_HOME="$user_home/.cargo" \
  CARGO_TARGET_DIR="$cargo_target" CARGO_INCREMENTAL=0 \
  "$host_cargo_bin" run --quiet --offline --locked \
  --manifest-path "$oracle_tmp/rudra/Cargo.toml" \
  --bin options_wiring_1204_fixture >"$oracle_tmp/rust.stdout"
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
echo "OPTIONS-SPLITDATATYPE-WIRING-0002 B2 covered projection MATCH ($records records) SHA256 $actual_sha"
