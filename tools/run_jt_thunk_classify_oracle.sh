#!/usr/bin/env -S --default-signal=HUP --default-signal=INT --default-signal=QUIT --default-signal=TERM -i PATH=/usr/bin:/bin /usr/bin/bash
# JUMPTABLE-THUNK-CLASSIFY-0001 — locked Ghidra 12.0.4 differential gate.
# The six owned inputs are required clean at one captured Git commit, materialized as
# immutable blobs, and revalidated after both comparands finish.
set -euo pipefail
umask 077

clean_path=/usr/bin:/bin
# Immutable staging root. /tmp is a usrquota tmpfs whose per-user quota is
# exhausted by concurrent agents' runs on this machine, so all run-local
# evidence, build trees and compiler temporaries live under this pinned
# task-owned directory instead (validated before any use).
oracle_tmp_root=/home/wirs/.cache/a3-jtthunk-tmp
runner_fd_path="/proc/$$/fd/3"
if [[ "${BASH_SOURCE[0]}" != "$runner_fd_path" ]]; then
  if [[ -L "${BASH_SOURCE[0]}" || ! -f "${BASH_SOURCE[0]}" ]]; then
    echo "runner entrypoint must be a regular non-symlink file" >&2
    exit 1
  fi
  exec 3<"${BASH_SOURCE[0]}"
  exec /usr/bin/env --default-signal=HUP --default-signal=INT \
    --default-signal=QUIT --default-signal=TERM -i PATH="$clean_path" \
    /usr/bin/bash "$runner_fd_path" "$@"
fi

runner_source=$(/usr/bin/readlink -f "$runner_fd_path")
if [[ -z "$runner_source" || ! -f "$runner_source" ]]; then
  echo "captured runner fd does not resolve to a regular file" >&2
  exit 1
fi

validate_oracle_tmp_root() {
  if [[ "$oracle_tmp_root" == /tmp* ]]; then
    echo "staging root must not be the quota-capped /tmp tmpfs" >&2
    return 1
  fi
  if [[ ! -d "$oracle_tmp_root" || -L "$oracle_tmp_root" ]]; then
    echo "staging root is not a real directory: $oracle_tmp_root" >&2
    return 1
  fi
  if [[ "$(/usr/bin/stat -c '%U:%a' "$oracle_tmp_root")" != "$(id -un):700" ]]; then
    echo "staging root must be user-owned with mode 700: $oracle_tmp_root" >&2
    return 1
  fi
}
validate_oracle_tmp_root

remove_oracle_tmp() {
  case "$oracle_tmp" in
    "$oracle_tmp_root"/rudra-jt-thunk-1204.??????) ;;
    *)
      echo "refusing unsafe temporary cleanup target: $oracle_tmp" >&2
      return 1
      ;;
  esac
  if [[ ! -e "$oracle_tmp" && ! -L "$oracle_tmp" ]]; then
    return 0
  fi
  if [[ ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "temporary cleanup target changed type: $oracle_tmp" >&2
    return 1
  fi
  /usr/bin/chmod -R u+w "$oracle_tmp" 2>/dev/null || true
  if ! /usr/bin/rm -rf -- "$oracle_tmp"; then
    echo "could not remove temporary evidence tree: $oracle_tmp" >&2
    return 1
  fi
  if [[ -e "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "temporary evidence tree remains after cleanup: $oracle_tmp" >&2
    return 1
  fi
}

cleanup() {
  local status=$?
  local cleanup_status=0
  trap - EXIT
  trap '' HUP INT QUIT TERM
  set +e
  if [[ "$status" -ne 0 ]]; then
    failure_log=$(/usr/bin/mktemp \
      "$oracle_tmp_root/rudra-jt-thunk-run-failure.XXXXXX.log")
    if [[ -n "$failure_log" ]]; then
      {
        printf 'runner_exit=%s\n' "$status"
        for log in make.stdout make.stderr cxx.stdout cxx.stderr cargo.stdout \
          cargo.stderr rustc.stdout rustc.stderr ghidra.stdout ghidra.stderr \
          rudra.stdout rudra.stderr raw.diff; do
          if [[ -f "$oracle_tmp/$log" ]]; then
            printf '\n[%s]\n' "$log"
            /usr/bin/cat "$oracle_tmp/$log"
          fi
        done
      } >"$failure_log"
      printf 'preserved runner failure log: %s\n' "$failure_log" >&2
    else
      echo "could not allocate failure log" >&2
    fi
  fi
  if [[ "$status" -eq 0 && -n "${candidate_commit:-}" ]]; then
    evidence_bundle="$oracle_tmp_root/jt-thunk-classify-evidence-$candidate_commit"
    if /usr/bin/mkdir -p "$evidence_bundle"; then
      for evidence_file in run-record.txt ghidra.stdout ghidra.stderr \
        rudra.stdout rudra.stderr raw.diff focused-results.txt \
        comparands.before comparands.after \
        comparand-binaries.before comparand-binaries.final \
        cargo-artifacts.before cargo-artifacts.final \
        libdecomp.before-link libdecomp.after-link; do
        if [[ -f "$oracle_tmp/$evidence_file" && ! -L "$oracle_tmp/$evidence_file" ]]; then
          /usr/bin/cp -- "$oracle_tmp/$evidence_file" "$evidence_bundle/$evidence_file" 2>/dev/null || true
        fi
      done
      /usr/bin/chmod -R go-rwx "$evidence_bundle" 2>/dev/null || true
      printf 'retained success evidence bundle: %s\n' "$evidence_bundle" >&2
    else
      echo "could not retain success evidence bundle" >&2
    fi
  fi
  remove_oracle_tmp || cleanup_status=$?
  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    status=$cleanup_status
  fi
  exit "$status"
}

captured_stage=false
if [[ ${1:-} == --captured-evidence-stage ]]; then
  if [[ $# -ne 11 ]]; then
    echo "invalid internal captured-evidence invocation" >&2
    exit 2
  fi
  captured_stage=true
  captured_repo_root=$2
  oracle_tmp=$3
  candidate_commit=$4
  candidate_tree=$5
  candidate_blob_oids=("${@:6}")
  set --
  if [[ "$oracle_tmp" != "$oracle_tmp_root"/rudra-jt-thunk-1204.?????? || \
        ! -d "$oracle_tmp" || -L "$oracle_tmp" ]]; then
    echo "invalid captured-evidence temporary directory" >&2
    exit 1
  fi
  trap cleanup EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 131' QUIT
  trap 'exit 143' TERM
  repo_root=$(builtin cd "$captured_repo_root" && builtin pwd -P)
  if [[ "$repo_root" != "$captured_repo_root" ]]; then
    echo "captured repository root is not canonical" >&2
    exit 1
  fi
  expected_runner="$oracle_tmp/captured-runner.sh"
  if [[ "$runner_source" != "$expected_runner" ]]; then
    echo "captured-stage runner is not the materialized Git blob" >&2
    exit 1
  fi
else
  if [[ $# -ne 0 ]]; then
    echo "usage: ${BASH_SOURCE[0]}" >&2
    exit 2
  fi
  repo_root=$(builtin cd "$(/usr/bin/dirname "$runner_source")/.." && builtin pwd -P)
  expected_runner="$repo_root/tools/run_jt_thunk_classify_oracle.sh"
  if [[ "$runner_source" != "$expected_runner" ]]; then
    echo "runner fd resolved outside the expected repository path" >&2
    exit 1
  fi
fi

oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
oracle_cpp_archive_sha=503b60e0fcde80c38abfeb8161fe37d5d83ded16bc9783b53ddd759c053389e4
rudra_source_commit=8d3a5561f259420d00ec3ecb54e766b206f89331
rudra_source_tree=c8ee095912b9d56b80c38d72f0bea447ebc998c4
rudra_source_src_tree=004b20c8ed6da74cf6457a4386570bae4801bc78
rudra_jumptable_blob=64c824f03f41040696c9c6242f05e83a23e1ef55
rudra_cargo_toml_blob=f15ed7d02b38aef3c21a564641344a156855b632
rudra_cargo_lock_blob=9736a3c5619f7fd188abd9609d0dccd20ef06607
rudra_build_rs_blob=a0c81c8521547efebbb463a640ecec69d83ed4c5
rudra_base_archive_sha=8751c496049f739e279963365409b299fb0c697d3575bc7bd0c4e150e2d6bc3f

cxx_path=/usr/bin/g++
cxx_version='g++ (GCC) 16.2.1 20260810'
cxx_sha=f04191f6a7b2cd7d9a62e1745872b8a6088791e5af6955488c69c9b2c4668bc9
cc_path=/usr/bin/gcc
cc_sha=8aac907d6fbf40394b424b5fa4a2ad1aa291dac7d3a0315c5b415c1f5ace1287
ar_path=/usr/bin/ar
ar_sha=41861189eb10fb9fe73ffcb8c82bdbbe5f6084de78e03f15acddd1d33071c3a4
make_path=/usr/bin/make
make_sha=9018663161af324a74326c035cfd05408cba13a26c1f6b801cf5f3195f2bee40
flock_path=/usr/bin/flock
flock_sha=0099a150fad09ff4bb8cbd839dfa397043a48d08d8294c6cda13ab805aca50da
setsid_path=/usr/bin/setsid
setsid_sha=b61b9575667fbd37ca93f63bd1c899f210f7f3b02f4b4961cd2c418e336f8968
env_path=/usr/bin/env
env_sha=08392d72874da4f88c619ee717f2b4a5f28ba0534ff8cf1083fb2edc37d6475f
git_path=/usr/bin/git
git_sha=93473c28694fd72bd889364107cd2770514de59780885a6a4aafca4d602e30ad
python_path=/usr/bin/python3.14
python_sha=d78f9cf7178ecff09963551399855543c297f37ac207e626228bfe43cb26a70c
cargo_path=/usr/bin/cargo
cargo_version='cargo 1.98.0 (797e8a9bc 2026-08-05) (Arch Linux rust 1:1.98.0-1)'
cargo_sha=b965d714ec3336e5321c6143c93a8e76ab952ac937f06a80ec95b145ce6194ee
rustc_path=/usr/bin/rustc
rustc_version='rustc 1.98.0 (88d9e12ae 2026-08-18) (Arch Linux rust 1:1.98.0-1)'
rustc_sha=c81a4d1946d6359e423b3cd13fcfbaead55817dec3fee0c2d9b7aeb4f6920fcc
cc1_path=/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1
cc1_sha=49a325fc4c6c5aa5a8f9ea8c828e37f3900a757c6be48d997ff4af0b51ee8315
cc1plus_path=/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1plus
cc1plus_sha=0026a9e66550c7f470558dfbe99f861073294e601d62b7b74eeb50fdebb09bef
collect2_path=/usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2
collect2_sha=6a575bbac80e335d20fc2ca631798899956cbbef882d6c3b83f8b13d01865155
ld_path=/usr/bin/ld
ld_sha=4d83828f709f0eade25bcae2f4a2508c47db2f01b58daaca5c1c4cefce897847
as_path=/usr/bin/as
as_sha=3dfdf6007545ea36176c350eef201d1ece55c347a182697bb5f9bac815a1f34b
ranlib_path=/usr/bin/ranlib
ranlib_sha=1359d302a8d12aa2c86bf3f26047360c050ec95b0584ce084ec40bbaf9c98613
rustc_driver_path=/usr/lib/librustc_driver-66a47b5a6ae9dff7.so
rustc_driver_sha=902decc7402389c9fe26cdc85e7a435d1adf7224cc497c3f3a5cc8bfb1f4aad8
llvm_path=/usr/lib/libLLVM.so.22.1
llvm_sha=06662e11c1faa7b4cb199e03c9ef681b74655ad4274473273b41dfc754a6f16f
ldd_path=/usr/bin/ldd
ldd_sha=94f332c23cf00596d0387d6f54693664f9a53334d65953b2ff308057cc8530b1
ld_so_cache_path=/etc/ld.so.cache
ld_so_cache_sha=04e49d85dc0f45e8804d29a63fbeec51907177d5c4f088570ed8d91839d47662
shell_link_path=/bin/sh
shell_path=/usr/bin/bash
shell_sha=575e03ac834b739349a4484de481abcd06a6f7193cefc795260a32a1943f20a5
uname_path=/usr/bin/uname
uname_sha=fbb43fff8c84e68aa921b43cbf8a20b20a3521c46b35311d8d1ba38d02df60a8
sed_path=/usr/bin/sed
sed_sha=c16be69e87ba0f9c5f364e3d25060d872629e26ba9db8681ad962f4485f6f31a
mkdir_path=/usr/bin/mkdir
mkdir_sha=71b43dbb72e6ec1a509205a1ea948504cbbb76619967edc9b496798a2c600342
rm_path=/usr/bin/rm
rm_sha=d5b182ba415bf4571cb6712c96dcee160dcb317c86814879a3fda36ef46ec36b
dynamic_runtime_count=55
dynamic_runtime_sha=ec201dcbb355d03982d02869cf6db5cb56acad6bf8891f86e4a5c59a4b507788
gcc_specs_sha=c0ab03f7de3cd1a5d70e16bd0a11a71048d782fbc03dd974fa4bba6ce2ef5257
cargo_vendor_manifest_sha=3e652e86f2ed80e9790abe3bea048f23c389052563e2ddde7a56fb59b7c5b39c
cargo_vendor_package_count=164
libdecomp_object_manifest_sha=70393006a3c0d91392e73734abb204f8cfc8a76b37e7038ab41657b122dbcb86
libdecomp_member_manifest_sha=019a03e343985e9883f06178c0601c9a819e9b83dae28f2ba12bcae4249acb97
libdecomp_member_count=79
rust_target_libdir=/usr/lib/rustlib/x86_64-unknown-linux-gnu/lib
rust_target_libdir_sha=36d8546104749e3f665ad0c51975c4076fa9c07e5df70a6264f05fbae5b2f4b2
rust_target_libdir_count=62
rust_target_libdir_bytes=160048673
gcc_semantic_root=/usr/lib/gcc/x86_64-pc-linux-gnu/16
gcc_semantic_root_sha=006e26ecb4de682155c8cc653f72d02b907027a51192cf6324273e153726ca82
gcc_semantic_root_count=838
gcc_semantic_root_bytes=188527599
libstdcpp_include_root=/usr/include/c++/16
libstdcpp_include_root_sha=ebff2ff8a3f2418deb1ef6015614f96a6ef67531922bd447d108667571de511d
libstdcpp_include_root_count=887
libstdcpp_include_root_bytes=14780438
system_include_root=/usr/include
system_include_root_sha=45e87f75aec2e199ccb874a8609524d57d5ef2ff0cad4a7f82b9705468a018b1
system_include_root_count=34328
system_include_root_bytes=340852508
local_include_root=/usr/local/include
local_include_root_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
local_include_root_count=0
local_include_root_bytes=0
python_stdlib_root=/usr/lib/python3.14
python_stdlib_root_sha=f80893a55085da3d5f4994dcd9516b067e8019f7b10776d8558d7b584ac01ae3
python_stdlib_root_count=12553
python_stdlib_root_bytes=265155715
libstdcpp_path=/usr/lib/libstdc++.so.6.0.36
libstdcpp_sha=f5fc7380f2ae46fa4053a64be04e7b98109f1066a4bbfff3c37042488aa0be0e
zlib_link_path=/usr/lib/libz.so
zlib_soname_path=/usr/lib/libz.so.1
zlib_path=/usr/lib/libz.so.1.3.2
zlib_sha=9ba92a0b85dc9b659e8f5e596a69452cec801def6ece0883a8a2c1f032e52397
zlib_header_path=/usr/include/zlib.h
zlib_header_sha=818667d6ab6a37fe7469cb06a7f0cb2c2cb2f2c948a03e5accf1a4a74bf3020a
zconf_header_path=/usr/include/zconf.h
zconf_header_sha=0718a11beb3295b345fb29a63b44b654b282d82c4cd0513f6225587f2b29b8bb
scrt1_path=/usr/lib/Scrt1.o
scrt1_sha=98d76691c6d97233c9e1a062f32ea2d7a89f047632156d1bf7b811727fb19921
crti_path=/usr/lib/crti.o
crti_sha=caf7f0c99019735e97e9bfabf52c376e86e1ef92d1b53a63c36a5bc2688e8fcc
crtn_path=/usr/lib/crtn.o
crtn_sha=71236f0a232a3686adf2319f3ae172831e8fd8166b9f0764ed184bc4df11be3c
libc_link_path=/usr/lib/libc.so
libc_link_sha=362665345c2d0149815700776a1e3e1a7fff45ab16f32352dbe224c55d12c964
libc_nonshared_path=/usr/lib/libc_nonshared.a
libc_nonshared_sha=de2e822b005fc8ab5a2e6c99ad5067ff9e548f495f9e54c6a027506125507430
libm_link_path=/usr/lib/libm.so
libm_link_sha=258e8802b225f70a439bbe23d6ecd468a33ce8875a02a52846a7bb5d21ff34c3
libmvec_path=/usr/lib/libmvec.so.1
libmvec_sha=c807927adfba7c54714a232b348c9afef8b0ad91799eae3a353f1911734b6834
libpthread_archive_path=/usr/lib/libpthread.a
libpthread_archive_sha=f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5
libdl_archive_path=/usr/lib/libdl.a
libdl_archive_sha=f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5
librt_archive_path=/usr/lib/librt.a
librt_archive_sha=f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5
libutil_archive_path=/usr/lib/libutil.a
libutil_archive_sha=f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5
stl_algo_path=/usr/include/c++/16/bits/stl_algo.h
stl_algo_sha=b1b7526cce2cbc6e734eaec98efbe30daaa8029f489bffbd9f0b5adb266b2241
stl_heap_path=/usr/include/c++/16/bits/stl_heap.h
stl_heap_sha=2f046a6e3441ae683e56fbce2584d8c5a0703b01d95f80b11cd7ae75ecea76f5
stl_algobase_path=/usr/include/c++/16/bits/stl_algobase.h
stl_algobase_sha=d4526f229676944d321e4884cd854b6fab142278676e662fc776389d50c55a49
predefined_ops_path=/usr/include/c++/16/bits/predefined_ops.h
predefined_ops_sha=420506532d36ef29350163fa55318ea5a573875857660cf0b41e782ae48b964c

ghidra_root="$repo_root/ghidra"
owned_relative_paths=(
  src/jumptable.rs
  docs/api/jumptable.md
  tests/oracle/jt_thunk_classify_1204.cc
  tests/oracle/jt_thunk_classify_1204.rs
  tests/oracle/jt_thunk_classify_1204.metadata.json
  tools/run_jt_thunk_classify_oracle.sh
)
owned_expected_modes=(100644 100644 100644 100644 100644 100755)
owned_live_paths=()
for relative in "${owned_relative_paths[@]}"; do
  owned_live_paths+=("$repo_root/$relative")
done

git_clean() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
    "$git_path" "$@"
}

regular_file_state() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - "$1" <<'PY'
import hashlib
import os
import stat
import sys

flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(sys.argv[1], flags)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"not a regular file: {sys.argv[1]}")
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    print(f"{stat.S_IMODE(info.st_mode):o} {digest.hexdigest()}")
finally:
    os.close(descriptor)
PY
}

reject_replace_refs() {
  local checked_repo=$1
  local refs
  refs=$(git_clean -C "$checked_repo" for-each-ref --format='%(refname)' refs/replace/)
  if [[ -n "$refs" ]]; then
    echo "Git replace refs are forbidden in $checked_repo" >&2
    echo "$refs" >&2
    exit 1
  fi
}

reject_replace_refs "$repo_root"
reject_replace_refs "$ghidra_root"

if $captured_stage; then
  if [[ ${#candidate_blob_oids[@]} -ne ${#owned_relative_paths[@]} ]]; then
    echo "captured owned blob count mismatch" >&2
    exit 1
  fi
  current_head=$(git_clean -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
  current_tree=$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{tree}")
  if [[ "$current_head" != "$candidate_commit" || "$current_tree" != "$candidate_tree" ]]; then
    echo "captured candidate commit/tree drifted before evidence stage" >&2
    exit 1
  fi
else
  candidate_commit=$(git_clean -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
  candidate_tree=$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{tree}")
  candidate_blob_oids=()
fi
if [[ ! "$candidate_commit" =~ ^[0-9a-f]{40}$ || \
      ! "$candidate_tree" =~ ^[0-9a-f]{40}$ || \
      "$(git_clean -C "$repo_root" cat-file -t "$candidate_commit")" != commit || \
      "$(git_clean -C "$repo_root" cat-file -t "$candidate_tree")" != tree ]]; then
  echo "captured candidate commit/tree identity is invalid" >&2
  exit 1
fi

candidate_dirty=$(git_clean -C "$repo_root" status --porcelain=v1 \
  --untracked-files=all -- "${owned_relative_paths[@]}")
if [[ -n "$candidate_dirty" ]]; then
  echo "owned evidence paths must exactly match captured HEAD" >&2
  echo "$candidate_dirty" >&2
  exit 1
fi

candidate_blob_sha256=()
for index in "${!owned_relative_paths[@]}"; do
  relative=${owned_relative_paths[$index]}
  live=${owned_live_paths[$index]}
  read -r live_mode live_sha < <(regular_file_state "$live")
  tree_entry=$(git_clean -C "$repo_root" ls-tree "$candidate_commit" -- "$relative")
  tree_mode=$(/usr/bin/awk 'NR == 1 { print $1 }' <<<"$tree_entry")
  tree_type=$(/usr/bin/awk 'NR == 1 { print $2 }' <<<"$tree_entry")
  blob=$(/usr/bin/awk 'NR == 1 { print $3 }' <<<"$tree_entry")
  index_entry=$(git_clean -C "$repo_root" ls-files --stage -- "$relative")
  index_lines=$(/usr/bin/wc -l <<<"$index_entry")
  index_mode=$(/usr/bin/awk 'NR == 1 { print $1 }' <<<"$index_entry")
  index_blob=$(/usr/bin/awk 'NR == 1 { print $2 }' <<<"$index_entry")
  index_stage=$(/usr/bin/awk 'NR == 1 { print $3 }' <<<"$index_entry")
  if [[ "$index_lines" -ne 1 || "$tree_mode" != "${owned_expected_modes[$index]}" || \
        "$tree_type" != blob || "$index_mode" != "$tree_mode" || \
        "$index_blob" != "$blob" || "$index_stage" != 0 || \
        "$live_mode" != "${owned_expected_modes[$index]:3}" || \
        "$(git_clean -C "$repo_root" cat-file -t "$blob")" != blob ]]; then
    echo "owned path tree/index identity mismatch: $relative" >&2
    exit 1
  fi
  if $captured_stage; then
    if [[ "${candidate_blob_oids[$index]}" != "$blob" ]]; then
      echo "captured owned blob drifted: $relative" >&2
      exit 1
    fi
  else
    candidate_blob_oids+=("$blob")
  fi
  blob_sha=$(git_clean -C "$repo_root" cat-file blob "$blob" | \
    /usr/bin/sha256sum | /usr/bin/awk '{print $1}')
  if [[ "$live_sha" != "$blob_sha" ]]; then
    echo "owned worktree bytes differ from captured blob: $relative" >&2
    exit 1
  fi
  candidate_blob_sha256+=("$blob_sha")
done
runner_snapshot_blob=$(git_clean -C "$repo_root" hash-object -- "$runner_source")
if [[ "$runner_snapshot_blob" != "${candidate_blob_oids[5]}" ]]; then
  echo "runner fd differs from captured HEAD runner blob" >&2
  exit 1
fi

if ! $captured_stage; then
  oracle_tmp=
  captured_launcher_pid=
  captured_group_pid=
  captured_group_verified=false
  pending_signal=
  requested_exit_status=1
  signal_exit_status() {
    case "$1" in
      HUP) requested_exit_status=129 ;;
      INT) requested_exit_status=130 ;;
      QUIT) requested_exit_status=131 ;;
      TERM) requested_exit_status=143 ;;
      *) requested_exit_status=1 ;;
    esac
  }
  forward_or_defer_signal() {
    local requested=$1
    if [[ -z "$pending_signal" ]]; then
      pending_signal=$requested
    fi
    if $captured_group_verified; then
      builtin kill -s "$requested" -- "-$captured_group_pid" 2>/dev/null || true
    fi
  }
  cleanup_outer() {
    local status=$?
    local cleanup_status=0
    trap - EXIT
    trap '' HUP INT QUIT TERM
    set +e
    if $captured_group_verified && \
        builtin kill -0 -- "-$captured_group_pid" 2>/dev/null; then
      builtin kill -s TERM -- "-$captured_group_pid" 2>/dev/null || true
    fi
    if [[ "$captured_launcher_pid" =~ ^[1-9][0-9]*$ ]] && \
        builtin kill -0 "$captured_launcher_pid" 2>/dev/null; then
      builtin kill -s TERM "$captured_launcher_pid" 2>/dev/null || true
      wait "$captured_launcher_pid" 2>/dev/null || true
    fi
    if [[ -n "$oracle_tmp" ]]; then
      remove_oracle_tmp || cleanup_status=$?
    fi
    if [[ -n "$pending_signal" ]]; then
      signal_exit_status "$pending_signal"
      status=$requested_exit_status
    fi
    if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
      status=$cleanup_status
    fi
    exit "$status"
  }
  trap cleanup_outer EXIT
  trap 'forward_or_defer_signal HUP' HUP
  trap 'forward_or_defer_signal INT' INT
  trap 'forward_or_defer_signal QUIT' QUIT
  trap 'forward_or_defer_signal TERM' TERM
  oracle_tmp=$(/usr/bin/mktemp -d "$oracle_tmp_root/rudra-jt-thunk-1204.XXXXXX")
  if [[ -n "$pending_signal" ]]; then
    signal_exit_status "$pending_signal"
    exit "$requested_exit_status"
  fi
  captured_runner="$oracle_tmp/captured-runner.sh"
  git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[5]}" >"$captured_runner"
  /usr/bin/chmod 0444 "$captured_runner"
  exec 4<"$captured_runner"
  if ! /usr/bin/cmp --silent "$runner_fd_path" "/proc/$$/fd/4"; then
    echo "materialized runner differs from executing captured runner" >&2
    exit 1
  fi
  exec 3<&4
  exec 4<&-
  captured_ready="$oracle_tmp/captured-session.ready"
  "$env_path" --default-signal=HUP --default-signal=INT \
    --default-signal=QUIT --default-signal=TERM -i PATH="$clean_path" \
    "$setsid_path" --wait /usr/bin/bash -c \
    'ready=$1; shift
     if ! (set -o noclobber; printf "%s\n" "$$" >"$ready"); then exit 125; fi
     exec /usr/bin/bash "/proc/$$/fd/3" "$@"' bash "$captured_ready" \
    --captured-evidence-stage "$repo_root" "$oracle_tmp" \
    "$candidate_commit" "$candidate_tree" "${candidate_blob_oids[@]}" &
  captured_launcher_pid=$!
  handshake_deadline=$((SECONDS + 5))
  while [[ ! -s "$captured_ready" ]]; do
    if ! builtin kill -0 "$captured_launcher_pid" 2>/dev/null; then
      if wait "$captured_launcher_pid"; then
        captured_status=0
      else
        captured_status=$?
      fi
      if [[ -n "$pending_signal" ]]; then
        signal_exit_status "$pending_signal"
        exit "$requested_exit_status"
      fi
      echo "captured evidence session exited before PGID handshake" >&2
      [[ "$captured_status" -ne 0 ]] && exit "$captured_status"
      exit 1
    fi
    if (( SECONDS >= handshake_deadline )); then
      echo "captured evidence PGID handshake timed out" >&2
      exit 1
    fi
  done
  if [[ ! -f "$captured_ready" || -L "$captured_ready" || \
        "$(/usr/bin/stat -c '%a' "$captured_ready")" != 600 ]]; then
    echo "captured evidence PGID handshake has invalid type/mode" >&2
    exit 1
  fi
  read -r captured_group_pid handshake_extra <"$captured_ready"
  if [[ ! "$captured_group_pid" =~ ^[1-9][0-9]*$ || \
        -n "$handshake_extra" ]] || \
      ! /usr/bin/env -i PATH="$clean_path" "$python_path" -I -S - \
        "$captured_ready" "$captured_group_pid" <<'PY'
import os
import stat
import sys

ready = sys.argv[1]
pid = int(sys.argv[2])
flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(ready, flags)
try:
    info = os.fstat(descriptor)
    data = b""
    while chunk := os.read(descriptor, 4096):
        data += chunk
finally:
    os.close(descriptor)
if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
        info.st_uid != os.getuid() or data != f"{pid}\n".encode("ascii")):
    raise SystemExit("invalid captured PGID handshake record")
if os.getpgid(pid) != pid or os.getsid(pid) != pid:
    raise SystemExit("captured process is not its session/process-group leader")
PY
  then
    echo "captured evidence PGID handshake is invalid" >&2
    exit 1
  fi
  captured_group_verified=true
  if [[ -n "$pending_signal" ]]; then
    builtin kill -s "$pending_signal" -- "-$captured_group_pid" 2>/dev/null || true
  fi
  captured_status=0
  while :; do
    if wait "$captured_launcher_pid"; then
      captured_status=0
      break
    else
      captured_status=$?
    fi
    if ! builtin kill -0 "$captured_launcher_pid" 2>/dev/null; then
      break
    fi
  done
  if [[ -n "$pending_signal" ]]; then
    signal_exit_status "$pending_signal"
    exit "$requested_exit_status"
  fi
  exit "$captured_status"
fi

task_user_home=$(/usr/bin/getent passwd "$(/usr/bin/id -u)" | \
  /usr/bin/awk -F: 'NR == 1 { print $6 }')
if [[ -z "$task_user_home" || ! -d "$task_user_home" || -L "$task_user_home" ]]; then
  echo "could not resolve current user home" >&2
  exit 1
fi

toolchain_state() {
  local path expected actual resolved_libstdcpp owner mode
  local link_binding link_name link_expected link_actual
  for binding in \
    "$cxx_path|$cxx_sha" "$cc_path|$cc_sha" "$ar_path|$ar_sha" \
    "$make_path|$make_sha" "$flock_path|$flock_sha" "$git_path|$git_sha" \
    "$setsid_path|$setsid_sha" "$env_path|$env_sha" \
    "$shell_path|$shell_sha" \
    "$uname_path|$uname_sha" "$sed_path|$sed_sha" \
    "$mkdir_path|$mkdir_sha" "$rm_path|$rm_sha" \
    "$python_path|$python_sha" "$cargo_path|$cargo_sha" "$rustc_path|$rustc_sha" \
    "$cc1_path|$cc1_sha" "$cc1plus_path|$cc1plus_sha" \
    "$collect2_path|$collect2_sha" "$ld_path|$ld_sha" "$as_path|$as_sha" \
    "$ranlib_path|$ranlib_sha" "$rustc_driver_path|$rustc_driver_sha" \
    "$llvm_path|$llvm_sha" "$ldd_path|$ldd_sha" \
    "$ld_so_cache_path|$ld_so_cache_sha" \
    "$libstdcpp_path|$libstdcpp_sha" "$zlib_path|$zlib_sha" \
    "$zlib_header_path|$zlib_header_sha" "$zconf_header_path|$zconf_header_sha" \
    "$scrt1_path|$scrt1_sha" "$crti_path|$crti_sha" "$crtn_path|$crtn_sha" \
    "$libc_link_path|$libc_link_sha" \
    "$libc_nonshared_path|$libc_nonshared_sha" \
    "$libm_link_path|$libm_link_sha" "$libmvec_path|$libmvec_sha" \
    "$libpthread_archive_path|$libpthread_archive_sha" \
    "$libdl_archive_path|$libdl_archive_sha" \
    "$librt_archive_path|$librt_archive_sha" \
    "$libutil_archive_path|$libutil_archive_sha" \
    "$stl_algo_path|$stl_algo_sha" \
    "$stl_heap_path|$stl_heap_sha" "$stl_algobase_path|$stl_algobase_sha" \
    "$predefined_ops_path|$predefined_ops_sha"; do
    path=${binding%%|*}
    expected=${binding#*|}
    if [[ ! -f "$path" || -L "$path" ]]; then
      echo "toolchain input is not a regular non-symlink file: $path" >&2
      return 1
    fi
    actual=$(/usr/bin/sha256sum "$path" | /usr/bin/awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
      echo "toolchain input hash mismatch: $path" >&2
      return 1
    fi
    owner=$(/usr/bin/stat -c '%u' "$path")
    mode=$(/usr/bin/stat -c '%a' "$path")
    if [[ "$owner" -ne 0 ]] || (( (8#$mode & 8#022) != 0 )); then
      echo "toolchain input is not root-owned/non-writable: $path" >&2
      return 1
    fi
    printf '%s %s %s  %s\n' "$actual" "$owner" "$mode" "$path"
  done
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" --version | /usr/bin/sed -n '1p')" == "$cxx_version" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cargo_path" --version)" == "$cargo_version" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rustc_path" --version)" == "$rustc_version" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rustc_path" --print sysroot)" == /usr ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$rustc_path" --print target-libdir)" == "$rust_target_libdir" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-prog-name=cc1plus)" == "$cc1plus_path" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cc_path" -print-prog-name=cc1)" == "$cc1_path" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-prog-name=collect2)" == "$collect2_path" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-prog-name=ld)" == ld ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-prog-name=as)" == as ]]
  [[ -L "$shell_link_path" && "$(/usr/bin/readlink -f "$shell_link_path")" == "$shell_path" ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$uname_path" -s)" == Linux ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$uname_path" -m)" == x86_64 ]]
  [[ "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -dumpspecs | /usr/bin/sha256sum | /usr/bin/awk '{print $1}')" == "$gcc_specs_sha" ]]
  resolved_libstdcpp=$(/usr/bin/readlink -f \
    "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-file-name=libstdc++.so)")
  [[ "$resolved_libstdcpp" == "$libstdcpp_path" ]]
  [[ -L "$zlib_link_path" && "$(/usr/bin/readlink -f "$zlib_link_path")" == "$zlib_path" ]]
  [[ -L "$zlib_soname_path" && "$(/usr/bin/readlink -f "$zlib_soname_path")" == "$zlib_path" ]]
  [[ "$(/usr/bin/readlink -f \
    "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$cxx_path" -print-file-name=libz.so)")" == \
    "$zlib_path" ]]
  for link_binding in \
    "Scrt1.o|$scrt1_path" "crti.o|$crti_path" "crtn.o|$crtn_path" \
    "libc.so|$libc_link_path" "libc_nonshared.a|$libc_nonshared_path" \
    "libm.so|$libm_link_path" "libmvec.so.1|$libmvec_path" \
    "libpthread.a|$libpthread_archive_path" "libdl.a|$libdl_archive_path" \
    "librt.a|$librt_archive_path" "libutil.a|$libutil_archive_path"; do
    link_name=${link_binding%%|*}
    link_expected=${link_binding#*|}
    link_actual=$(/usr/bin/readlink -f \
      "$(/usr/bin/env -i PATH="$clean_path" LC_ALL=C \
        "$cxx_path" -print-file-name="$link_name")")
    [[ "$link_actual" == "$link_expected" ]]
  done
  printf '%s\n%s\n%s\n%s\n' "$cxx_version" "$cargo_version" \
    "$rustc_version" "$resolved_libstdcpp"
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
    "$ldd_path" "$dynamic_runtime_sha" "$dynamic_runtime_count" \
    "$cxx_path" "$cc_path" "$cc1_path" "$cc1plus_path" "$collect2_path" \
    "$ld_path" "$as_path" "$ranlib_path" "$ar_path" "$make_path" \
    "$cargo_path" "$rustc_path" "$python_path" "$git_path" \
    "$flock_path" "$setsid_path" "$env_path" "$shell_path" "$uname_path" \
    "$sed_path" "$mkdir_path" "$rm_path" <<'PY'
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys

ldd = pathlib.Path(sys.argv[1])
expected_hash = sys.argv[2]
expected_count = int(sys.argv[3])
roots = [pathlib.Path(raw) for raw in sys.argv[4:]]
libraries = set()
for root in roots:
    output = subprocess.run(
        [str(ldd), str(root)], check=True, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    for line in output.splitlines():
        match = re.search(r"=>\s+(/\S+)\s+\(", line)
        if match is None:
            match = re.match(r"\s*(/\S+)\s+\(", line)
        if match is not None:
            libraries.add(pathlib.Path(match.group(1)).resolve(strict=True))

digest = hashlib.sha256()
for path in sorted(libraries, key=lambda item: str(item).encode()):
    info = path.stat()
    if path.is_symlink() or not path.is_file() or info.st_uid != 0:
        raise SystemExit(f"invalid dynamic runtime input: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit(f"writable dynamic runtime input: {path}")
    encoded = str(path).encode()
    content_hash = hashlib.sha256(path.read_bytes()).digest()
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    digest.update(content_hash)
actual_hash = digest.hexdigest()
if len(libraries) != expected_count or actual_hash != expected_hash:
    raise SystemExit(
        f"dynamic runtime closure mismatch: count={len(libraries)} sha256={actual_hash}"
    )
print(f"dynamic-runtime {len(libraries)} {actual_hash}")
PY
  toolchain_tree_state "$rust_target_libdir" "$rust_target_libdir_sha" \
    "$rust_target_libdir_count" "$rust_target_libdir_bytes"
  toolchain_tree_state "$gcc_semantic_root" "$gcc_semantic_root_sha" \
    "$gcc_semantic_root_count" "$gcc_semantic_root_bytes"
  toolchain_tree_state "$libstdcpp_include_root" "$libstdcpp_include_root_sha" \
    "$libstdcpp_include_root_count" "$libstdcpp_include_root_bytes"
  toolchain_tree_state "$system_include_root" "$system_include_root_sha" \
    "$system_include_root_count" "$system_include_root_bytes"
  toolchain_tree_state "$local_include_root" "$local_include_root_sha" \
    "$local_include_root_count" "$local_include_root_bytes"
  toolchain_tree_state "$python_stdlib_root" "$python_stdlib_root_sha" \
    "$python_stdlib_root_count" "$python_stdlib_root_bytes"
}

toolchain_tree_state() {
  local tree_root=$1 expected_hash=$2 expected_count=$3 expected_bytes=$4
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
    "$tree_root" "$expected_hash" "$expected_count" "$expected_bytes" <<'PY'
import hashlib
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
expected = (sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
    raise SystemExit(f"invalid toolchain tree root: {root}")
digest = hashlib.sha256()
count = 0
size_total = 0
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()):
    relative = path.relative_to(root).as_posix().encode()
    if path.is_symlink():
        target = path.readlink().as_posix().encode()
        digest.update(b"L")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(target).to_bytes(8, "big"))
        digest.update(target)
        count += 1
        continue
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit(f"non-regular toolchain tree input: {path}")
    info = path.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit(f"writable/non-root toolchain tree input: {path}")
    digest.update(b"F")
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
    digest.update(info.st_size.to_bytes(8, "big"))
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    count += 1
    size_total += info.st_size
actual = (digest.hexdigest(), count, size_total)
if actual != expected:
    raise SystemExit(f"toolchain tree mismatch: {root}: {actual}")
print(f"toolchain-tree {root} {actual[0]} {count} {size_total}")
PY
}

toolchain_state >"$oracle_tmp/toolchain.before"

verify_git_materialization() {
  local checked_repo=$1
  local checked_commit=$2
  local destination=$3
  local label=$4
  shift 4
  local expected_paths="$oracle_tmp/$label.expected.paths"
  local actual_paths="$oracle_tmp/$label.actual.paths"
  local tree_records="$oracle_tmp/$label.tree.records"
  local symlink_paths="$oracle_tmp/$label.symlinks"
  local blob_copy="$oracle_tmp/$label.readback.blob"
  local entry metadata relative mode object_type object_id live live_mode
  : >"$expected_paths"
  if ! git_clean -C "$checked_repo" ls-tree -rz -r --full-tree \
      "$checked_commit" -- "$@" >"$tree_records"; then
    echo "$label could not enumerate the locked Git tree" >&2
    return 1
  fi
  while IFS= read -r -d '' entry; do
    metadata=${entry%%$'\t'*}
    relative=${entry#*$'\t'}
    read -r mode object_type object_id <<<"$metadata"
    live="$destination/$relative"
    if [[ "$object_type" != blob || "$mode" != 100644 && "$mode" != 100755 || \
          ! -f "$live" || -L "$live" ]]; then
      echo "$label extracted path/type mismatch: $relative" >&2
      return 1
    fi
    live_mode=$(/usr/bin/stat -c '%a' "$live")
    if [[ "$live_mode" != "${mode:3}" ]]; then
      echo "$label extracted mode mismatch: $relative" >&2
      return 1
    fi
    git_clean -C "$checked_repo" cat-file blob "$object_id" >"$blob_copy"
    if ! /usr/bin/cmp --silent "$blob_copy" "$live"; then
      echo "$label extracted blob mismatch: $relative" >&2
      return 1
    fi
    printf '%s\0' "$relative" >>"$expected_paths"
  done <"$tree_records"
  /usr/bin/sort -z -o "$expected_paths" "$expected_paths"
  if ! /usr/bin/find "$destination" -type l -print >"$symlink_paths"; then
    echo "$label could not enumerate extracted symlinks" >&2
    return 1
  fi
  if [[ -s "$symlink_paths" ]]; then
    echo "$label extraction unexpectedly contains a symlink" >&2
    return 1
  fi
  if ! /usr/bin/find "$destination" -type f -printf '%P\0' | \
      /usr/bin/sort -z >"$actual_paths"; then
    echo "$label could not enumerate extracted files" >&2
    return 1
  fi
  if ! /usr/bin/cmp --silent "$expected_paths" "$actual_paths"; then
    echo "$label extracted path set differs from locked Git tree" >&2
    return 1
  fi
}

actual_oracle=$(git_clean -C "$ghidra_root" rev-parse --verify 'HEAD^{commit}')
tag_oracle=$(git_clean -C "$ghidra_root" rev-parse --verify "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_oracle" != "$oracle_commit" || "$tag_oracle" != "$oracle_commit" || \
      "$actual_cpp_tree" != "$oracle_cpp_tree" || \
      "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
oracle_dirty=$(git_clean -C "$ghidra_root" status --porcelain=v1 \
  --untracked-files=all -- Ghidra/Features/Decompiler/src/decompile/cpp)
if [[ -n "$oracle_dirty" ]]; then
  echo "locked Ghidra decompiler source worktree is dirty" >&2
  echo "$oracle_dirty" >&2
  exit 1
fi

for binding in \
  "$rudra_source_commit^{commit}|$rudra_source_commit" \
  "$rudra_source_commit^{tree}|$rudra_source_tree" \
  "$rudra_source_commit:src|$rudra_source_src_tree" \
  "$rudra_source_commit:src/jumptable.rs|$rudra_jumptable_blob" \
  "$rudra_source_commit:Cargo.toml|$rudra_cargo_toml_blob" \
  "$rudra_source_commit:Cargo.lock|$rudra_cargo_lock_blob" \
  "$rudra_source_commit:build.rs|$rudra_build_rs_blob"; do
  expression=${binding%%|*}
  expected=${binding#*|}
  actual=$(git_clean -C "$repo_root" rev-parse "$expression")
  if [[ "$actual" != "$expected" ]]; then
    echo "pinned Rudra source identity mismatch: $expression" >&2
    exit 1
  fi
done

snapshot="$oracle_tmp/workspace"
oracle_source="$oracle_tmp/ghidra-source"
cargo_target="$oracle_tmp/cargo-target"
cargo_home="$oracle_tmp/cargo-home"
cargo_archive_cache="$task_user_home/.cargo/registry/cache"
/usr/bin/mkdir -p "$snapshot" "$snapshot/tests/oracle" "$snapshot/docs/api" \
  "$snapshot/tools" "$oracle_source" "$cargo_home"

base_archive="$oracle_tmp/rudra-source.tar"
# tar.umask is pinned so archive member modes are exactly the Git tree modes
# (100644 -> 644, 100755 -> 755) regardless of the invoking shell's umask;
# materialization then verifies the extraction against the tree itself.
git_clean -c tar.umask=0022 -C "$repo_root" archive --format=tar \
  --output="$base_archive" \
  "$rudra_source_commit" Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/doc_sync.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim
if [[ "$(/usr/bin/sha256sum "$base_archive" | /usr/bin/awk '{print $1}')" != \
      "$rudra_base_archive_sha" ]]; then
  echo "pinned Rudra base archive mismatch" >&2
  exit 1
fi
/usr/bin/chmod a-w "$base_archive"
/usr/bin/tar --same-permissions -xf "$base_archive" -C "$snapshot"
verify_git_materialization "$repo_root" "$rudra_source_commit" "$snapshot" \
  rudra-base Cargo.toml Cargo.lock build.rs README.md \
  benches/decompile_bench.rs tests/doc_sync.rs \
  tests/oracle/decompress_1204.rs tests/oracle/funcproto_lock_1204.rs \
  src sleigh_shim

vendor_root="$snapshot/vendor"
cargo_config="$snapshot/.cargo/config.toml"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
  "$snapshot/Cargo.lock" "$cargo_archive_cache" "$vendor_root" \
  "$cargo_config" "$cargo_vendor_manifest_sha" \
  "$cargo_vendor_package_count" <<'PY'
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import tomllib

lock_path = pathlib.Path(sys.argv[1])
cache_root = pathlib.Path(sys.argv[2])
vendor_root = pathlib.Path(sys.argv[3])
config_path = pathlib.Path(sys.argv[4])
expected_manifest = sys.argv[5]
expected_count = int(sys.argv[6])
if cache_root.is_symlink() or not cache_root.is_dir():
    raise SystemExit(f"invalid Cargo archive cache: {cache_root}")

lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
records = []
for package in lock["package"]:
    source = package.get("source")
    if source is None:
        if package["name"] != "rugra":
            raise SystemExit(f"unexpected path package: {package['name']}")
        continue
    if source != "registry+https://github.com/rust-lang/crates.io-index":
        raise SystemExit(f"unsupported dependency source: {source}")
    checksum = package.get("checksum", "")
    if re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
        raise SystemExit(f"invalid Cargo.lock checksum: {package['name']}")
    if re.fullmatch(r"[A-Za-z0-9_.+-]+", package["name"]) is None or \
       re.fullmatch(r"[A-Za-z0-9_.+-]+", package["version"]) is None:
        raise SystemExit("unsafe package name/version")
    records.append({
        "name": package["name"], "version": package["version"],
        "source": source, "checksum": checksum,
    })
records.sort(key=lambda item: (item["name"], item["version"], item["source"]))
stems = [(item["name"], item["version"]) for item in records]
if len(stems) != len(set(stems)):
    raise SystemExit("ambiguous duplicate Cargo package name/version")
manifest_bytes = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
actual_manifest = hashlib.sha256(manifest_bytes).hexdigest()
if len(records) != expected_count or actual_manifest != expected_manifest:
    raise SystemExit(
        f"Cargo.lock vendor manifest mismatch: count={len(records)} sha256={actual_manifest}"
    )

vendor_root.mkdir(mode=0o700)
for record in records:
    stem = f"{record['name']}-{record['version']}"
    candidates = sorted(cache_root.glob(f"*/{stem}.crate"))
    archive_bytes = None
    for candidate in candidates:
        if candidate.parent.is_symlink():
            continue
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                continue
            chunks = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            candidate_bytes = b"".join(chunks)
        finally:
            os.close(descriptor)
        if hashlib.sha256(candidate_bytes).hexdigest() == record["checksum"]:
            archive_bytes = candidate_bytes
            break
    if archive_bytes is None:
        raise SystemExit(f"no Cargo.lock-authenticated archive for {stem}")

    destination = vendor_root / stem
    destination.mkdir(mode=0o755)
    file_hashes = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
        for member in archive.getmembers():
            parts = pathlib.PurePosixPath(member.name).parts
            if len(parts) < 2 or parts[0] != stem or any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"unsafe crate member: {member.name}")
            relative = pathlib.PurePosixPath(*parts[1:]).as_posix()
            if relative in seen or relative == ".cargo-checksum.json" or not member.isreg():
                raise SystemExit(f"unsupported/duplicate crate member: {member.name}")
            seen.add(relative)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit(f"could not read crate member: {member.name}")
            content = extracted.read()
            if len(content) != member.size:
                raise SystemExit(f"short crate member: {member.name}")
            output = destination.joinpath(*parts[1:])
            output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with output.open("xb") as sink:
                sink.write(content)
            output.chmod(0o755 if member.mode & 0o111 else 0o644)
            file_hashes[relative] = hashlib.sha256(content).hexdigest()
    checksum_record = json.dumps(
        {"files": file_hashes, "package": record["checksum"]},
        sort_keys=True, separators=(",", ":"),
    ).encode() + b"\n"
    (destination / ".cargo-checksum.json").write_bytes(checksum_record)
    (destination / ".cargo-checksum.json").chmod(0o644)

config_path.parent.mkdir(mode=0o755)
config_path.write_text(
    '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
    '[source.vendored-sources]\ndirectory = "vendor"\n\n'
    '[net]\noffline = true\n',
    encoding="utf-8",
)
config_path.chmod(0o644)
print(f"cargo-vendor {actual_manifest} {len(records)}")
PY

oracle_archive="$oracle_tmp/ghidra-cpp.tar"
git_clean -c tar.umask=0022 -C "$ghidra_root" archive --format=tar \
  --output="$oracle_archive" \
  "$oracle_commit" Ghidra/Features/Decompiler/src/decompile/cpp
if [[ "$(/usr/bin/sha256sum "$oracle_archive" | /usr/bin/awk '{print $1}')" != \
      "$oracle_cpp_archive_sha" ]]; then
  echo "locked Ghidra archive mismatch" >&2
  exit 1
fi
/usr/bin/chmod a-w "$oracle_archive"
/usr/bin/tar --same-permissions -xf "$oracle_archive" -C "$oracle_source"
verify_git_materialization "$ghidra_root" "$oracle_commit" "$oracle_source" \
  ghidra-build Ghidra/Features/Decompiler/src/decompile/cpp
oracle_cpp="$oracle_source/Ghidra/Features/Decompiler/src/decompile/cpp"
if [[ ! -d "$oracle_cpp" || -L "$oracle_cpp" ]]; then
  echo "locked Ghidra source snapshot is not a real directory" >&2
  exit 1
fi
cold_artifact=$(/usr/bin/find "$oracle_cpp" -type f \
  \( -name '*.o' -o -name '*.a' -o -name '*.so' \) -print -quit)
if [[ -n "$cold_artifact" ]]; then
  echo "locked Ghidra archive unexpectedly contains build artifacts" >&2
  exit 1
fi
oracle_specials_before="$oracle_tmp/oracle-specials.before"
if ! /usr/bin/find "$oracle_cpp" ! -type f ! -type d \
    -print >"$oracle_specials_before"; then
  echo "could not enumerate locked Ghidra source input types" >&2
  exit 1
fi
if [[ -s "$oracle_specials_before" ]]; then
  echo "locked Ghidra source contains a non-regular filesystem node" >&2
  /usr/bin/cat "$oracle_specials_before" >&2
  exit 1
fi

snapshot_owned_paths=()
for index in "${!owned_relative_paths[@]}"; do
  relative=${owned_relative_paths[$index]}
  destination="$snapshot/$relative"
  /usr/bin/mkdir -p "$(/usr/bin/dirname "$destination")"
  git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[$index]}" >"$destination"
  /usr/bin/chmod "${owned_expected_modes[$index]:2}" "$destination"
  if [[ ! -f "$destination" || -L "$destination" || \
        "$(/usr/bin/sha256sum "$destination" | /usr/bin/awk '{print $1}')" != \
        "${candidate_blob_sha256[$index]}" ]]; then
    echo "captured owned blob materialization mismatch: $relative" >&2
    exit 1
  fi
  snapshot_owned_paths+=("$destination")
done
if ! /usr/bin/cmp --silent "$runner_fd_path" "${snapshot_owned_paths[5]}"; then
  echo "captured runner fd differs from snapshot runner" >&2
  exit 1
fi

/usr/bin/mkdir -p "$snapshot/ghidra"
/usr/bin/tar --same-permissions -xf "$oracle_archive" -C "$snapshot/ghidra"
verify_git_materialization "$ghidra_root" "$oracle_commit" "$snapshot/ghidra" \
  ghidra-snapshot Ghidra/Features/Decompiler/src/decompile/cpp
snapshot_oracle_cpp="$snapshot/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp"
snapshot_specials="$oracle_tmp/snapshot-specials.before"
if ! /usr/bin/find "$snapshot" ! -type f ! -type d -print >"$snapshot_specials"; then
  echo "could not enumerate snapshot input types" >&2
  exit 1
fi
if [[ ! -d "$snapshot_oracle_cpp" || -L "$snapshot_oracle_cpp" || \
      -s "$snapshot_specials" ]]; then
  echo "snapshot must contain only materialized regular files/directories" >&2
  exit 1
fi

/usr/bin/find "$snapshot" -type f -print0 | /usr/bin/sort -z | \
  /usr/bin/xargs -0 /usr/bin/sha256sum >"$oracle_tmp/snapshot.before"
/usr/bin/sha256sum "${snapshot_owned_paths[@]}" >"$oracle_tmp/comparands.before"
/usr/bin/find "$oracle_cpp" -type f -print0 | /usr/bin/sort -z \
  >"$oracle_tmp/oracle-source.paths"
{
  printf '%s .\0' "$(/usr/bin/stat -c '%a' "$oracle_cpp")"
  /usr/bin/find "$oracle_cpp" -mindepth 1 -type d -printf '%m %P\0'
} | /usr/bin/sort -z >"$oracle_tmp/oracle-source.dirs.before"
while IFS= read -r -d '' source_path; do
  /usr/bin/sha256sum "$source_path"
done <"$oracle_tmp/oracle-source.paths" >"$oracle_tmp/oracle-source.before"
/usr/bin/find "$snapshot" "$oracle_cpp" -type f -exec /usr/bin/chmod a-w {} +
/usr/bin/find "$snapshot" -type d -exec /usr/bin/chmod a-w {} +
/usr/bin/find "$snapshot" -type f -printf '%m %p\0' | /usr/bin/sort -z \
  >"$oracle_tmp/snapshot.modes.before"
/usr/bin/find "$snapshot" -type d -printf '%m %p\0' | /usr/bin/sort -z \
  >"$oracle_tmp/snapshot.dirs.before"
while IFS= read -r -d '' source_path; do
  /usr/bin/stat -c '%a %n' "$source_path"
done <"$oracle_tmp/oracle-source.paths" >"$oracle_tmp/oracle-source.modes.before"

metadata="${snapshot_owned_paths[4]}"
cpp_fixture="${snapshot_owned_paths[2]}"
rust_fixture="${snapshot_owned_paths[3]}"
jumptable_overlay="${snapshot_owned_paths[0]}"
api_document="${snapshot_owned_paths[1]}"
runner="${snapshot_owned_paths[5]}"

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
  "$metadata" "$cpp_fixture" "$rust_fixture" "$jumptable_overlay" \
  "$api_document" "$runner" "$runner_snapshot_blob" "$oracle_commit" \
  "$oracle_tag" "$oracle_cpp_tree" "$oracle_makefile_blob" \
  "$oracle_cpp_archive_sha" "$rudra_source_commit" "$rudra_source_tree" \
  "$rudra_source_src_tree" "$rudra_jumptable_blob" "$rudra_cargo_toml_blob" \
  "$rudra_cargo_lock_blob" "$rudra_build_rs_blob" "$rudra_base_archive_sha" \
  "$cxx_path" "$cxx_version" "$cxx_sha" "$cc_path" "$cc_sha" \
  "$ar_path" "$ar_sha" "$make_path" "$make_sha" "$flock_path" "$flock_sha" \
  "$setsid_path" "$setsid_sha" "$env_path" "$env_sha" \
  "$git_path" "$git_sha" "$python_path" "$python_sha" "$cargo_path" \
  "$cargo_version" "$cargo_sha" "$rustc_path" "$rustc_version" "$rustc_sha" \
  "$libstdcpp_path" "$libstdcpp_sha" "$stl_algo_sha" "$stl_heap_sha" \
  "$stl_algobase_sha" "$predefined_ops_sha" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_raw, cpp_raw, rust_raw, overlay_raw, api_raw, runner_raw,
    runner_fd_blob, oracle_commit, oracle_tag, cpp_tree, makefile_blob,
    oracle_archive_sha, source_commit, source_tree, source_src_tree,
    jumptable_blob, cargo_toml_blob, cargo_lock_blob, build_rs_blob,
    base_archive_sha, cxx_path, cxx_version, cxx_sha, cc_path, cc_sha,
    ar_path, ar_sha, make_path, make_sha, flock_path, flock_sha,
    setsid_path, setsid_sha, env_path, env_sha, git_path, git_sha,
    python_path, python_sha, cargo_path, cargo_version, cargo_sha,
    rustc_path, rustc_version, rustc_sha, libstdcpp_path, libstdcpp_sha,
    stl_algo_sha, stl_heap_sha, stl_algobase_sha, predefined_ops_sha,
) = sys.argv[1:]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def regular(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"expected regular non-symlink file: {path}")
    return path.read_bytes()

def require(label, actual, expected):
    if actual != expected:
        raise SystemExit(f"{label} mismatch: expected={expected!r} actual={actual!r}")

metadata = json.loads(regular(metadata_raw).decode("utf-8"))
require("schema", metadata["schema_version"], 3)
require("fixture", metadata["fixture_id"], "JT-THUNK-CLASSIFY-1204")
require("overall", metadata["overall_status"], "MISMATCH")
require("known diffs", metadata["known_diffs"], [])
validation = metadata["latest_validation"]
runner_preexec = validation["current_runner_executed"] is False
if runner_preexec:
    require("projection before evidence", metadata["projection_status"], "UNTESTED")
else:
    require("projection observed", metadata["projection_status"], "MATCH")
    require("attempted runner blob is this runner", validation["attempted_runner_blob"], runner_fd_blob)
    require("recorded runner exit", str(validation["runner_exit_code"]), "0")
    require("recorded validation status", validation["status"], "PASS")
    require("recorded failure stage", repr(validation["failure_stage"]), "None")
    require("recorded cargo result", validation["cargo_result"],
            "35 passed; 0 failed; 0 ignored; 0 measured; 1537 filtered out")
    require("recorded evidence retention", validation["run_local_artifacts_retained"], True)

candidate = metadata["candidate_evidence"]
require("candidate evidence keys", set(candidate), {
    "capture_policy", "materialization_policy", "owned_paths",
    "metadata_self_authentication", "external_anchor",
})
require("candidate paths", candidate["owned_paths"], [
    "src/jumptable.rs", "docs/api/jumptable.md",
    "tests/oracle/jt_thunk_classify_1204.cc",
    "tests/oracle/jt_thunk_classify_1204.rs",
    "tests/oracle/jt_thunk_classify_1204.metadata.json",
    "tools/run_jt_thunk_classify_oracle.sh",
])
require("metadata self authentication", candidate["metadata_self_authentication"], False)
if not candidate["capture_policy"] or not candidate["materialization_policy"] or not candidate["external_anchor"]:
    raise SystemExit("candidate evidence policy must be explicit")

oracle = metadata["oracle"]
for label, actual, expected in (
    ("oracle tag", oracle["tag"], oracle_tag),
    ("oracle commit", oracle["commit"], oracle_commit),
    ("oracle cpp tree", oracle["decompiler_cpp_tree"], cpp_tree),
    ("oracle Makefile", oracle["decompiler_makefile_blob"], makefile_blob),
    ("oracle archive", oracle["decompiler_cpp_archive_sha256"], oracle_archive_sha),
):
    require(label, actual, expected)

source = metadata["rugra_source"]
for label, actual, expected in (
    ("source commit", source["base_commit"], source_commit),
    ("source tree", source["base_tree"], source_tree),
    ("source src tree", source["base_src_tree"], source_src_tree),
    ("source jumptable blob", source["base_jumptable_blob"], jumptable_blob),
    ("Cargo.toml blob", source["cargo_toml_blob"], cargo_toml_blob),
    ("Cargo.lock blob", source["cargo_lock_blob"], cargo_lock_blob),
    ("build.rs blob", source["build_rs_blob"], build_rs_blob),
    ("base archive", source["base_archive_sha256"], base_archive_sha),
):
    require(label, actual, expected)

comparand = metadata["comparand"]
for key, path in (
    ("cpp_fixture_sha256", cpp_raw),
    ("rust_fixture_sha256", rust_raw),
    ("jumptable_overlay_sha256", overlay_raw),
    ("api_document_sha256", api_raw),
):
    require(key, sha(regular(path)), comparand[key])
require("runner blob", runner_fd_blob, comparand["runner_blob"])

toolchain = metadata["oracle_toolchain"]
require("toolchain keys", set(toolchain), {
    "cxx_path", "cxx_version", "cxx_sha256", "libstdcxx_path",
    "libstdcxx_sha256", "headers", "std_sort_contract", "rustc_version",
    "cargo_version", "cargo_path", "cargo_sha256", "rustc_path",
    "rustc_sha256", "cc_path", "cc_sha256", "ar_path", "ar_sha256",
    "make_path", "make_sha256", "flock_path", "flock_sha256",
    "setsid_path", "setsid_sha256", "env_path", "env_sha256", "git_path",
    "git_sha256", "python_path", "python_sha256", "gcc_specs_sha256",
    "compiler_subprograms", "build_helpers", "rust_semantic_engine",
    "dynamic_runtime_closure", "semantic_trees", "zlib_link_inputs",
    "system_link_inputs", "ghidra_libdecomp_contract",
})
for label, actual, expected in (
    ("cxx path", toolchain["cxx_path"], cxx_path),
    ("cxx version", toolchain["cxx_version"], cxx_version),
    ("cxx sha", toolchain["cxx_sha256"], cxx_sha),
    ("cc path", toolchain["cc_path"], cc_path),
    ("cc sha", toolchain["cc_sha256"], cc_sha),
    ("ar path", toolchain["ar_path"], ar_path),
    ("ar sha", toolchain["ar_sha256"], ar_sha),
    ("make path", toolchain["make_path"], make_path),
    ("make sha", toolchain["make_sha256"], make_sha),
    ("flock path", toolchain["flock_path"], flock_path),
    ("flock sha", toolchain["flock_sha256"], flock_sha),
    ("setsid path", toolchain["setsid_path"], setsid_path),
    ("setsid sha", toolchain["setsid_sha256"], setsid_sha),
    ("env path", toolchain["env_path"], env_path),
    ("env sha", toolchain["env_sha256"], env_sha),
    ("git path", toolchain["git_path"], git_path),
    ("git sha", toolchain["git_sha256"], git_sha),
    ("python path", toolchain["python_path"], python_path),
    ("python sha", toolchain["python_sha256"], python_sha),
    ("cargo path", toolchain["cargo_path"], cargo_path),
    ("cargo version", toolchain["cargo_version"], cargo_version),
    ("cargo sha", toolchain["cargo_sha256"], cargo_sha),
    ("rustc path", toolchain["rustc_path"], rustc_path),
    ("rustc version", toolchain["rustc_version"], rustc_version),
    ("rustc sha", toolchain["rustc_sha256"], rustc_sha),
    ("libstdc++ path", toolchain["libstdcxx_path"], libstdcpp_path),
    ("libstdc++ sha", toolchain["libstdcxx_sha256"], libstdcpp_sha),
    ("stl_algo sha", toolchain["headers"]["stl_algo.h"], stl_algo_sha),
    ("stl_heap sha", toolchain["headers"]["stl_heap.h"], stl_heap_sha),
    ("stl_algobase sha", toolchain["headers"]["stl_algobase.h"], stl_algobase_sha),
    ("predefined_ops sha", toolchain["headers"]["predefined_ops.h"], predefined_ops_sha),
):
    require(label, actual, expected)
require("GCC specs", toolchain["gcc_specs_sha256"],
        "c0ab03f7de3cd1a5d70e16bd0a11a71048d782fbc03dd974fa4bba6ce2ef5257")
require("STL headers", toolchain["headers"], {
    "stl_algo.h": "b1b7526cce2cbc6e734eaec98efbe30daaa8029f489bffbd9f0b5adb266b2241",
    "stl_heap.h": "2f046a6e3441ae683e56fbce2584d8c5a0703b01d95f80b11cd7ae75ecea76f5",
    "stl_algobase.h": "d4526f229676944d321e4884cd854b6fab142278676e662fc776389d50c55a49",
    "predefined_ops.h": "420506532d36ef29350163fa55318ea5a573875857660cf0b41e782ae48b964c",
})
require("std::sort contract", toolchain["std_sort_contract"],
        "Observable reproduction of this pinned libstdc++ implementation only; the C++ standard does not specify equivalent-key order.")
require("compiler subprograms", toolchain["compiler_subprograms"], {
    "cc1": {"path": "/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1", "sha256": "49a325fc4c6c5aa5a8f9ea8c828e37f3900a757c6be48d997ff4af0b51ee8315"},
    "cc1plus": {"path": "/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1plus", "sha256": "0026a9e66550c7f470558dfbe99f861073294e601d62b7b74eeb50fdebb09bef"},
    "collect2": {"path": "/usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2", "sha256": "6a575bbac80e335d20fc2ca631798899956cbbef882d6c3b83f8b13d01865155"},
    "ld": {"path": "/usr/bin/ld", "sha256": "4d83828f709f0eade25bcae2f4a2508c47db2f01b58daaca5c1c4cefce897847"},
    "as": {"path": "/usr/bin/as", "sha256": "3dfdf6007545ea36176c350eef201d1ece55c347a182697bb5f9bac815a1f34b"},
    "ranlib": {"path": "/usr/bin/ranlib", "sha256": "1359d302a8d12aa2c86bf3f26047360c050ec95b0584ce084ec40bbaf9c98613"},
})
require("build helpers", toolchain["build_helpers"], {
    "shell_link": "/bin/sh",
    "shell": {"path": "/usr/bin/bash", "sha256": "575e03ac834b739349a4484de481abcd06a6f7193cefc795260a32a1943f20a5"},
    "uname": {"path": "/usr/bin/uname", "sha256": "fbb43fff8c84e68aa921b43cbf8a20b20a3521c46b35311d8d1ba38d02df60a8", "expected": ["Linux", "x86_64"]},
    "sed": {"path": "/usr/bin/sed", "sha256": "c16be69e87ba0f9c5f364e3d25060d872629e26ba9db8681ad962f4485f6f31a"},
    "mkdir": {"path": "/usr/bin/mkdir", "sha256": "71b43dbb72e6ec1a509205a1ea948504cbbb76619967edc9b496798a2c600342"},
    "rm": {"path": "/usr/bin/rm", "sha256": "d5b182ba415bf4571cb6712c96dcee160dcb317c86814879a3fda36ef46ec36b"},
})
require("Rust semantic engine", toolchain["rust_semantic_engine"], {
    "librustc_driver": {"path": "/usr/lib/librustc_driver-66a47b5a6ae9dff7.so", "sha256": "902decc7402389c9fe26cdc85e7a435d1adf7224cc497c3f3a5cc8bfb1f4aad8"},
    "llvm": {"path": "/usr/lib/libLLVM.so.22.1", "sha256": "06662e11c1faa7b4cb199e03c9ef681b74655ad4274473273b41dfc754a6f16f"},
})
require("dynamic runtime closure", toolchain["dynamic_runtime_closure"], {
    "roots": ["/usr/bin/g++", "/usr/bin/gcc", "/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1", "/usr/lib/gcc/x86_64-pc-linux-gnu/16/cc1plus", "/usr/lib/gcc/x86_64-pc-linux-gnu/16/collect2", "/usr/bin/ld", "/usr/bin/as", "/usr/bin/ranlib", "/usr/bin/ar", "/usr/bin/make", "/usr/bin/cargo", "/usr/bin/rustc", "/usr/bin/python3.14", "/usr/bin/git", "/usr/bin/flock", "/usr/bin/setsid", "/usr/bin/env", "/usr/bin/bash", "/usr/bin/uname", "/usr/bin/sed", "/usr/bin/mkdir", "/usr/bin/rm"],
    "ldd_path": "/usr/bin/ldd",
    "ldd_sha256": "94f332c23cf00596d0387d6f54693664f9a53334d65953b2ff308057cc8530b1",
    "ld_so_cache_path": "/etc/ld.so.cache",
    "ld_so_cache_sha256": "04e49d85dc0f45e8804d29a63fbeec51907177d5c4f088570ed8d91839d47662",
    "resolved_library_count": 55,
    "path_content_manifest_sha256": "ec201dcbb355d03982d02869cf6db5cb56acad6bf8891f86e4a5c59a4b507788",
    "manifest_algorithm": "sort canonical resolved paths as bytes; hash u64be(path_len), path bytes, sha256(file bytes)",
})
require("semantic trees", toolchain["semantic_trees"], {
    "rust_target_libdir": {"path": "/usr/lib/rustlib/x86_64-unknown-linux-gnu/lib", "sha256": "36d8546104749e3f665ad0c51975c4076fa9c07e5df70a6264f05fbae5b2f4b2", "entry_count": 62, "regular_bytes": 160048673},
    "gcc_16_root": {"path": "/usr/lib/gcc/x86_64-pc-linux-gnu/16", "sha256": "006e26ecb4de682155c8cc653f72d02b907027a51192cf6324273e153726ca82", "entry_count": 838, "regular_bytes": 188527599},
    "libstdcxx_include_root": {"path": "/usr/include/c++/16", "sha256": "ebff2ff8a3f2418deb1ef6015614f96a6ef67531922bd447d108667571de511d", "entry_count": 887, "regular_bytes": 14780438},
    "system_include_root": {"path": "/usr/include", "sha256": "45e87f75aec2e199ccb874a8609524d57d5ef2ff0cad4a7f82b9705468a018b1", "entry_count": 34328, "regular_bytes": 340852508},
    "local_include_root": {"path": "/usr/local/include", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "entry_count": 0, "regular_bytes": 0},
    "python_stdlib_root": {"path": "/usr/lib/python3.14", "sha256": "f80893a55085da3d5f4994dcd9516b067e8019f7b10776d8558d7b584ac01ae3", "entry_count": 12553, "regular_bytes": 265155715},
})
require("zlib link inputs", toolchain["zlib_link_inputs"], {
    "link_path": "/usr/lib/libz.so",
    "soname_path": "/usr/lib/libz.so.1",
    "resolved_path": "/usr/lib/libz.so.1.3.2",
    "resolved_sha256": "9ba92a0b85dc9b659e8f5e596a69452cec801def6ece0883a8a2c1f032e52397",
    "zlib_h_sha256": "818667d6ab6a37fe7469cb06a7f0cb2c2cb2f2c948a03e5accf1a4a74bf3020a",
    "zconf_h_sha256": "0718a11beb3295b345fb29a63b44b654b282d82c4cd0513f6225587f2b29b8bb",
    "cargo_policy": "LIBZ_SYS_STATIC=1 makes libz-sys build the Cargo.lock-authenticated bundled zlib and bypass pkg-config; the pinned system zlib remains the explicit C++ and direct-rustc link input and is preloaded at fixture execution",
})
require("system link inputs", toolchain["system_link_inputs"], {
    "Scrt1.o": {"path": "/usr/lib/Scrt1.o", "sha256": "98d76691c6d97233c9e1a062f32ea2d7a89f047632156d1bf7b811727fb19921"},
    "crti.o": {"path": "/usr/lib/crti.o", "sha256": "caf7f0c99019735e97e9bfabf52c376e86e1ef92d1b53a63c36a5bc2688e8fcc"},
    "crtn.o": {"path": "/usr/lib/crtn.o", "sha256": "71236f0a232a3686adf2319f3ae172831e8fd8166b9f0764ed184bc4df11be3c"},
    "libc.so": {"path": "/usr/lib/libc.so", "sha256": "362665345c2d0149815700776a1e3e1a7fff45ab16f32352dbe224c55d12c964"},
    "libc_nonshared.a": {"path": "/usr/lib/libc_nonshared.a", "sha256": "de2e822b005fc8ab5a2e6c99ad5067ff9e548f495f9e54c6a027506125507430"},
    "libm.so": {"path": "/usr/lib/libm.so", "sha256": "258e8802b225f70a439bbe23d6ecd468a33ce8875a02a52846a7bb5d21ff34c3"},
    "libmvec.so.1": {"path": "/usr/lib/libmvec.so.1", "sha256": "c807927adfba7c54714a232b348c9afef8b0ad91799eae3a353f1911734b6834"},
    "libpthread.a": {"path": "/usr/lib/libpthread.a", "sha256": "f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5"},
    "libdl.a": {"path": "/usr/lib/libdl.a", "sha256": "f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5"},
    "librt.a": {"path": "/usr/lib/librt.a", "sha256": "f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5"},
    "libutil.a": {"path": "/usr/lib/libutil.a", "sha256": "f0a17a43c74d2fe5474fa2fd29c8f14799e777d7d75a2cc4d11c20a6e7b161c5"},
})
require("Ghidra libdecomp contract", toolchain["ghidra_libdecomp_contract"], {
    "manifest_make_overrides": {"DEPNAMES": "", "EXTRA": ""},
    "archive_build_overrides": {"EXTRA": ""},
    "archive_default_dependency_outputs": ["com_dbg/depend", "com_opt/depend"],
    "member_count": 79,
    "object_path_manifest_sha256": "70393006a3c0d91392e73734abb204f8cfc8a76b37e7038ab41657b122dbcb86",
    "member_order_manifest_sha256": "019a03e343985e9883f06178c0601c9a819e9b83dae28f2ba12bcae4249acb97",
    "verification": "expand locked Makefile LIBDECOMP_OPT_OBJS independently, require exact ar member sequence without duplicates, and compare every member byte-for-byte with its com_opt object",
})

cargo_vendor = metadata["cargo_dependency_vendor"]
require("Cargo dependency vendor", cargo_vendor, {
    "lock_blob": "9736a3c5619f7fd188abd9609d0dccd20ef06607",
    "source": "registry+https://github.com/rust-lang/crates.io-index",
    "package_count": 164,
    "lock_record_manifest_sha256": "3e652e86f2ed80e9790abe3bea048f23c389052563e2ddde7a56fb59b7c5b39c",
    "manifest_algorithm": "sort Cargo.lock registry records by (name,version,source), then SHA-256 compact sorted-key JSON records containing name/version/source/checksum",
    "archive_authentication": "each selected .crate is opened once with O_NOFOLLOW and accepted only when its bytes equal the exact Cargo.lock checksum; duplicate name/version records are forbidden",
    "extraction_policy": "safe in-memory extraction accepts only regular members under the exact name-version prefix, rejects duplicate/traversal/link/device members, writes a Cargo directory-source checksum file, then snapshot pre/post binds every vendor byte and mode",
    "cargo_config": "captured snapshot .cargo/config.toml replaces crates-io with the run-local vendor directory and forces offline mode",
    "cargo_home": "run-local CARGO_HOME; live home config, index, credentials and unpacked sources are not consumed. Cargo 1.97 unconditionally stamps a registry/CACHEDIR.TAG marker (sha256 6d9d1d216e0f83abc5e5662ca62c92b4f23009466b54fa27321a69acdb778bb2) even for fully offline directory-source builds; the runner admits exactly that marker and no other registry/git/config/credential state",
})

manifest = metadata["input_manifest"]
fingerprinted = {
    "architecture": metadata["architecture"],
    "compiler_spec": metadata["compiler_spec"],
    "analysis_options": metadata["analysis_options"],
    "oracle_toolchain": toolchain,
    "cargo_dependency_vendor": cargo_vendor,
    "cases": manifest["cases"],
}
canonical = json.dumps(fingerprinted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
require("manifest", sha(canonical), manifest["sha256"])
require("case count", len(manifest["cases"]), 25)
require("Ghidra expected provenance", metadata["expected_results_provenance"]["ghidra"],
        "OBSERVED_LOCKED_CPP_25_CASE_OUTPUT")
if runner_preexec:
    require("Rudra expected provenance", metadata["expected_results_provenance"]["rugra"],
            "PROSPECTIVE_CURRENT_CANDIDATE_EXPECTATION_NOT_YET_EXECUTED")
    require("diff expected provenance", metadata["expected_results_provenance"]["diff"],
            "PROSPECTIVE_ZERO_DIFF_EXPECTATION_NOT_YET_EXECUTED")
else:
    require("Rudra observed provenance", metadata["expected_results_provenance"]["rugra"],
            "OBSERVED_CURRENT_CANDIDATE_25_CASE_OUTPUT")
    require("diff observed provenance", metadata["expected_results_provenance"]["diff"],
            "OBSERVED_ZERO_DIFF_25_CASE_BILATERAL")

required_decisive = {
    "reference_output_parameters", "loop_bounds_traversal_order",
    "counter_accumulator_lifecycle", "sorting_comparison_keys",
}
require("decisive semantics", set(metadata["decisive_semantics"]), required_decisive)
if any(not isinstance(value, str) or not value for value in metadata["decisive_semantics"].values()):
    raise SystemExit("decisive semantics entries must be non-empty")

expected_bilateral = {
    "single_target_boundary", "multi_target_bypass",
    "is_reachable_guard_matrix", "override_short_circuit",
    "recover_preconditions_and_collect_gate", "recover_thunk_and_model_reject",
    "successful_truncation_warning_order", "equal_address_pinned_toolchain_order",
    "address_space_wrap_and_order", "production_load_input_invariant",
}
expected_mismatch = {
    "production_typed_stage_consumption": "JUMPTABLE-PIPELINE-0001",
    "sort_toolchain_portability": "JUMPTABLE-SORT-TOOLCHAIN-0001",
    "emulate_function_lowlevel_channel": "JUMPTABLE-EMULFN-0001",
}
coverage = metadata["coverage"]
require("coverage keys", set(coverage), expected_bilateral | set(expected_mismatch))
if runner_preexec:
    for key in expected_bilateral:
        require(f"coverage {key}", coverage[key]["status"], "UNTESTED")
        require(f"coverage {key} evidence", coverage[key]["evidence_kind"],
                "FIXTURE_SPEC_WITHOUT_CURRENT_RUST_EXECUTION")
else:
    for key in expected_bilateral:
        require(f"coverage {key}", coverage[key]["status"], "MATCH")
        require(f"coverage {key} evidence", coverage[key]["evidence_kind"],
                "BILATERAL_25_CASE_BYTE_IDENTICAL")
for key in expected_bilateral:
    require(f"coverage {key} residuals", coverage[key]["residual_todo_ids"], [])
for key, todo in expected_mismatch.items():
    require(f"coverage {key}", coverage[key]["status"], "MISMATCH")
    require(f"coverage {key} residuals", coverage[key]["residual_todo_ids"], [todo])
require("pipeline evidence kind", coverage["production_typed_stage_consumption"]["evidence_kind"],
        "LOCKED_SOURCE_AUDIT_OUTSIDE_25_CASE_FIXTURE")
require("sort evidence kind", coverage["sort_toolchain_portability"]["evidence_kind"],
        "PINNED_ORACLE_CONTRACT_WITH_CROSS_TOOLCHAIN_PORTABILITY_GAP")
require("emulfn evidence kind", coverage["emulate_function_lowlevel_channel"]["evidence_kind"],
        "LOCKED_SOURCE_AUDIT_OUTSIDE_25_CASE_FIXTURE")
if any(set(entry) != {"status", "evidence_kind", "covers", "residual_todo_ids"} or not entry["covers"]
       for entry in coverage.values()):
    raise SystemExit("coverage schema/text drift")

residual_ids = {entry["todo_id"] for entry in metadata["residuals"]}
require("residual ids", residual_ids, {
    "JUMPTABLE-PIPELINE-0001", "JUMPTABLE-SORT-TOOLCHAIN-0001",
    "JUMPTABLE-EMULFN-0001",
})
if any(entry["status"] != "MISMATCH" or not entry.get("detail") or not entry.get("branches")
       for entry in metadata["residuals"]):
    raise SystemExit("residual schema/text drift")
PY

libdecomp_manifest_make="$oracle_tmp/libdecomp-manifest.mk"
libdecomp_expected_objects="$oracle_tmp/libdecomp-objects.expected"
libdecomp_expected_members="$oracle_tmp/libdecomp-members.expected"
{
  printf '%s\n' '.PHONY: __jt_libdecomp_manifest' \
    '__jt_libdecomp_manifest:' \
    $'\t@for item in $(LIBDECOMP_OPT_OBJS); do printf "%s\\n" "$$item"; done'
} >"$libdecomp_manifest_make"
/usr/bin/chmod 0444 "$libdecomp_manifest_make"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$make_path" --silent \
    -C "$oracle_cpp" DEPNAMES= EXTRA= -f Makefile -f "$libdecomp_manifest_make" \
    __jt_libdecomp_manifest >"$libdecomp_expected_objects" \
    2>"$oracle_tmp/libdecomp-manifest.stderr"; then
  /usr/bin/cat "$oracle_tmp/libdecomp-manifest.stderr" >&2
  exit 1
fi
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
  "$libdecomp_expected_objects" "$libdecomp_expected_members" \
  "$libdecomp_object_manifest_sha" "$libdecomp_member_manifest_sha" \
  "$libdecomp_member_count" <<'PY'
import hashlib
import pathlib
import re
import sys

objects_path = pathlib.Path(sys.argv[1])
members_path = pathlib.Path(sys.argv[2])
expected_object_hash = sys.argv[3]
expected_member_hash = sys.argv[4]
expected_count = int(sys.argv[5])
object_bytes = objects_path.read_bytes()
objects = object_bytes.decode("ascii").splitlines()
if (len(objects) != expected_count or len(objects) != len(set(objects)) or
        hashlib.sha256(object_bytes).hexdigest() != expected_object_hash or
        any(re.fullmatch(r"com_opt/[A-Za-z0-9_]+[.]o", item) is None
            for item in objects)):
    raise SystemExit("locked Makefile LIBDECOMP_OPT_OBJS manifest mismatch")
member_bytes = "".join(f"{pathlib.PurePosixPath(item).name}\n" for item in objects).encode()
if hashlib.sha256(member_bytes).hexdigest() != expected_member_hash:
    raise SystemExit("locked libdecomp member manifest mismatch")
members_path.write_bytes(member_bytes)
print(f"libdecomp-manifest {expected_count} {expected_object_hash} {expected_member_hash}")
PY
/usr/bin/chmod 0444 "$libdecomp_expected_objects" "$libdecomp_expected_members"

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp_root" \
    "$make_path" --silent -C "$oracle_cpp" -j 16 CXX="$cxx_path -std=c++11" CC="$cc_path" \
    AR="$ar_path" EXTRA= libdecomp.a >"$oracle_tmp/make.stdout" \
    2>"$oracle_tmp/make.stderr"; then
  /usr/bin/cat "$oracle_tmp/make.stdout" "$oracle_tmp/make.stderr" >&2
  exit 1
fi
if [[ ! -f "$oracle_cpp/libdecomp.a" || -L "$oracle_cpp/libdecomp.a" ]]; then
  echo "cold Ghidra build did not produce regular libdecomp.a" >&2
  exit 1
fi
verify_libdecomp_archive() {
  local actual_members="$oracle_tmp/libdecomp-members.actual"
  if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$ar_path" t \
      "$oracle_cpp/libdecomp.a" >"$actual_members"; then
    echo "could not enumerate locked libdecomp.a" >&2
    return 1
  fi
  if ! /usr/bin/cmp --silent "$libdecomp_expected_members" "$actual_members"; then
    echo "libdecomp.a member order differs from locked Makefile expansion" >&2
    return 1
  fi
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
    "$oracle_cpp" "$libdecomp_expected_objects" "$libdecomp_expected_members" \
    "$ar_path" <<'PY'
import pathlib
import stat
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
objects = pathlib.Path(sys.argv[2]).read_text(encoding="ascii").splitlines()
members = pathlib.Path(sys.argv[3]).read_text(encoding="ascii").splitlines()
archive = root / "libdecomp.a"
for relative, member in zip(objects, members, strict=True):
    path = root / relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit(f"non-regular libdecomp object: {relative}")
    archived = subprocess.run(
        [sys.argv[4], "p", str(archive), member], check=True, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ).stdout
    if archived != path.read_bytes():
        raise SystemExit(f"libdecomp member bytes differ from {relative}")
PY
}
verify_libdecomp_archive
/usr/bin/sha256sum "$oracle_cpp/libdecomp.a" \
  >"$oracle_tmp/libdecomp.before-link"
if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp_root" \
    "$cxx_path" \
    -std=c++11 -O2 -Wall -Wno-sign-compare -I"$oracle_cpp" \
  "$cpp_fixture" "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/libdecomp.a" -lz \
  -o "$oracle_tmp/jt_thunk_classify_1204_cpp" >"$oracle_tmp/cxx.stdout" \
  2>"$oracle_tmp/cxx.stderr"; then
  /usr/bin/cat "$oracle_tmp/cxx.stdout" "$oracle_tmp/cxx.stderr" >&2
  exit 1
fi
/usr/bin/sha256sum "$oracle_cpp/libdecomp.a" \
  >"$oracle_tmp/libdecomp.after-link"
/usr/bin/cmp --silent "$oracle_tmp/libdecomp.before-link" \
  "$oracle_tmp/libdecomp.after-link"

config_probe=${snapshot%/*}
while :; do
  for config_name in .cargo/config .cargo/config.toml; do
    if [[ -e "$config_probe/$config_name" || -L "$config_probe/$config_name" ]]; then
      echo "Cargo ancestor config is forbidden: $config_probe/$config_name" >&2
      exit 1
    fi
  done
  [[ "$config_probe" == / ]] && break
  config_probe=${config_probe%/*}
  [[ -n "$config_probe" ]] || config_probe=/
done
for config_name in config config.toml credentials credentials.toml; do
  if [[ -e "$cargo_home/$config_name" || -L "$cargo_home/$config_name" ]]; then
    echo "run-local CARGO_HOME config/credential is forbidden: $config_name" >&2
    exit 1
  fi
done

cargo_command="/usr/bin/env -i PATH='$clean_path' LC_ALL=C.UTF-8 TMPDIR='$oracle_tmp_root' CARGO_HOME='$cargo_home' CARGO_TARGET_DIR='$cargo_target' CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER='$cc_path' LIBZ_SYS_STATIC=1 CXX='$cxx_path' CC='$cc_path' AR='$ar_path' RUSTC='$rustc_path' '$cargo_path' test --offline --locked --jobs 2 --lib --test doc_sync 'jumptable::tests::'"
cargo_status=0
(
  builtin cd "$snapshot"
  "$flock_path" /tmp/rudra-cargo-build.lock -c "$cargo_command"
) >"$oracle_tmp/cargo.stdout" 2>"$oracle_tmp/cargo.stderr" || cargo_status=$?
if [[ "$cargo_status" -ne 0 ]]; then
  echo "Cargo failed with exit code $cargo_status" >&2
  /usr/bin/cat "$oracle_tmp/cargo.stdout" "$oracle_tmp/cargo.stderr" >&2
  exit "$cargo_status"
fi
cargo_registry_tag_sha=6d9d1d216e0f83abc5e5662ca62c92b4f23009466b54fa27321a69acdb778bb2
if [[ -e "$cargo_home/git" || -L "$cargo_home/git" || \
      -e "$cargo_home/config" || -L "$cargo_home/config" || \
      -e "$cargo_home/config.toml" || -L "$cargo_home/config.toml" || \
      -e "$cargo_home/credentials" || -L "$cargo_home/credentials" || \
      -e "$cargo_home/credentials.toml" || -L "$cargo_home/credentials.toml" ]]; then
  echo "offline vendored Cargo unexpectedly consulted/created external-source state" >&2
  exit 1
fi
# Cargo 1.97 unconditionally stamps an empty registry/ cache-directory tag
# into CARGO_HOME even for a fully offline directory-source build. Admit the
# bare marker and nothing else: any index/cache/src payload stays forbidden.
if [[ -e "$cargo_home/registry" && ! -d "$cargo_home/registry" ]] || \
   [[ -L "$cargo_home/registry" ]]; then
  echo "run-local Cargo registry is not a real directory" >&2
  exit 1
fi
if [[ -d "$cargo_home/registry" ]]; then
  registry_children=$(/usr/bin/find "$cargo_home/registry" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)
  if [[ "$registry_children" != CACHEDIR.TAG ]]; then
    echo "offline vendored Cargo wrote unexpected registry state" >&2
    /usr/bin/printf '%s\n' "$registry_children" >&2
    exit 1
  fi
  if [[ ! -f "$cargo_home/registry/CACHEDIR.TAG" || \
        -L "$cargo_home/registry/CACHEDIR.TAG" ]] || \
     [[ "$(/usr/bin/sha256sum "$cargo_home/registry/CACHEDIR.TAG" | /usr/bin/awk '{print $1}')" != \
        "$cargo_registry_tag_sha" ]]; then
    echo "run-local Cargo registry cache tag is not the pinned marker" >&2
    exit 1
  fi
fi
focused_results="$oracle_tmp/focused-results.txt"
if ! /usr/bin/grep '^test result:' "$oracle_tmp/cargo.stdout" >"$focused_results"; then
  echo "focused Cargo output contains no test summary" >&2
  exit 1
fi
if [[ "$(/usr/bin/wc -l <"$focused_results")" -ne 2 ]]; then
  echo "focused Cargo output must contain exactly the lib and doc_sync summaries" >&2
  /usr/bin/cat "$focused_results" >&2
  exit 1
fi
focused_result=$(/usr/bin/sed -n '1p' "$focused_results")
doc_sync_result=$(/usr/bin/sed -n '2p' "$focused_results")
case "$focused_result" in
  'test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 1537 filtered out;'*) ;;
  *) echo "unexpected focused jumptable result: $focused_result" >&2; exit 1 ;;
esac
case "$doc_sync_result" in
  'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out;'*) ;;
  *) echo "unexpected filtered doc_sync result: $doc_sync_result" >&2; exit 1 ;;
esac
printf '%s\n%s\n' "$focused_result" "$doc_sync_result"

root_output_candidates="$oracle_tmp/root-output-candidates"
root_output_list="$oracle_tmp/root-outputs.list"
if ! /usr/bin/find "$cargo_target/debug/build" -mindepth 2 -maxdepth 2 \
    -type f -name root-output -print0 >"$root_output_candidates"; then
  echo "could not enumerate run-local root-output files" >&2
  exit 1
fi
: >"$root_output_list"
while IFS= read -r -d '' candidate; do
  candidate_parent=${candidate%/*}
  case "${candidate_parent##*/}" in
    rudra-*) printf '%s\n' "$candidate" >>"$root_output_list" ;;
  esac
done <"$root_output_candidates"
/usr/bin/sort -o "$root_output_list" "$root_output_list"
root_outputs=()
while IFS= read -r root_output; do
  [[ -n "$root_output" ]] && root_outputs+=("$root_output")
done <"$root_output_list"
if [[ ${#root_outputs[@]} -ne 1 || -L "${root_outputs[0]:-}" ]]; then
  echo "expected one regular run-local Rudra root-output, found ${#root_outputs[@]}" >&2
  /usr/bin/printf '%s\n' "${root_outputs[@]}" >&2
  exit 1
fi
root_output=${root_outputs[0]}
build_root=$cargo_target/debug/build
root_output_parent=${root_output%/*}
cargo_target_real=$(/usr/bin/readlink -f "$cargo_target")
build_root_real=$(/usr/bin/readlink -f "$build_root")
root_output_parent_real=$(/usr/bin/readlink -f "$root_output_parent")
if [[ "$cargo_target_real" != "$cargo_target" || \
      "$build_root_real" != "$cargo_target_real/debug/build" || \
      -z "$root_output_parent_real" || \
      "${root_output_parent_real%/*}" != "$build_root_real" || \
      ! "${root_output_parent_real##*/}" =~ ^rudra-[0-9a-f]+$ || \
      "$root_output" != "$root_output_parent/root-output" ]]; then
  echo "root-output parent is not one exact run-local Rudra build directory" >&2
  exit 1
fi
native_output=$(<"$root_output")
native_output_real=$(/usr/bin/readlink -f "$native_output")
if [[ "$native_output" != "$root_output_parent/out" || \
      "$native_output_real" != "$root_output_parent_real/out" || \
      ! -d "$native_output_real" || -L "$native_output" ]]; then
  echo "root-output does not name its exact regular run-local out directory" >&2
  exit 1
fi
native_output=$native_output_real
native_archive="$native_output/librudra_sleigh.a"

rlib_candidates="$oracle_tmp/rudra-rlibs.list"
if ! /usr/bin/find "$cargo_target/debug/deps" -maxdepth 1 -type f \
    -name 'librudra-*.rlib' -print0 >"$rlib_candidates"; then
  echo "could not enumerate run-local Rudra rlibs" >&2
  exit 1
fi
/usr/bin/sort -z -o "$rlib_candidates" "$rlib_candidates"
rudra_rlibs=()
while IFS= read -r -d '' rlib; do rudra_rlibs+=("$rlib"); done <"$rlib_candidates"
if [[ ${#rudra_rlibs[@]} -ne 1 || ! -f "$native_archive" || \
      -L "$native_archive" || -L "${rudra_rlibs[0]:-}" ]]; then
  echo "expected one regular current Rudra rlib/native archive" >&2
  /usr/bin/printf '%s\n' "${rudra_rlibs[@]}" "$native_archive" >&2
  exit 1
fi
rudra_rlib=$(/usr/bin/readlink -f "${rudra_rlibs[0]}")
native_archive_real=$(/usr/bin/readlink -f "$native_archive")
deps_root_real=$(/usr/bin/readlink -f "$cargo_target/debug/deps")
if [[ "$native_archive_real" != "$native_output/librudra_sleigh.a" || \
      "${rudra_rlib%/*}" != "$deps_root_real" || \
      ! "${rudra_rlib##*/}" =~ ^librudra-[0-9a-f]+\.rlib$ ]]; then
  echo "Rudra artifacts escaped their exact run-local directories" >&2
  exit 1
fi
native_archive=$native_archive_real
artifact_input_state() {
  /usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
    "$deps_root_real" "$native_output" <<'PY'
import hashlib
import pathlib
import stat
import sys

for label, raw_root in (("deps", sys.argv[1]), ("native", sys.argv[2])):
    root = pathlib.Path(raw_root)
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise SystemExit(f"invalid direct-rustc artifact root: {root}")
    root_info = root.lstat()
    print(f"D {label} {stat.S_IMODE(root_info.st_mode):04o} .")
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            print(f"D {label} {mode:04o} {relative}")
        elif stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            print(f"F {label} {mode:04o} {info.st_size} {digest.hexdigest()} {relative}")
        else:
            raise SystemExit(f"non-regular direct-rustc artifact input: {path}")
PY
}
artifact_input_state >"$oracle_tmp/direct-rustc-inputs.before"
/usr/bin/sha256sum "$native_archive" "$rudra_rlib" \
  >"$oracle_tmp/cargo-artifacts.before"
native_sha=$(/usr/bin/awk 'NR == 1 { print $1 }' "$oracle_tmp/cargo-artifacts.before")
rlib_sha=$(/usr/bin/awk 'NR == 2 { print $1 }' "$oracle_tmp/cargo-artifacts.before")

if ! /usr/bin/env -i PATH="$clean_path" LC_ALL=C TMPDIR="$oracle_tmp_root" \
    "$rustc_path" \
    --edition=2021 -O -C "linker=$cc_path" \
  -L "dependency=$cargo_target/debug/deps" -L "native=$native_output" \
  --extern "rudra=$rudra_rlib" -l static=rudra_sleigh -l dylib=z \
  -l dylib=stdc++ -l dylib=m "$rust_fixture" \
  -o "$oracle_tmp/jt_thunk_classify_1204_rust" >"$oracle_tmp/rustc.stdout" \
  2>"$oracle_tmp/rustc.stderr"; then
  /usr/bin/cat "$oracle_tmp/rustc.stdout" "$oracle_tmp/rustc.stderr" >&2
  exit 1
fi
/usr/bin/sha256sum "$native_archive" "$rudra_rlib" \
  >"$oracle_tmp/cargo-artifacts.after"
/usr/bin/cmp --silent "$oracle_tmp/cargo-artifacts.before" \
  "$oracle_tmp/cargo-artifacts.after"
artifact_input_state >"$oracle_tmp/direct-rustc-inputs.after"
/usr/bin/cmp --silent "$oracle_tmp/direct-rustc-inputs.before" \
  "$oracle_tmp/direct-rustc-inputs.after"
for executable in "$oracle_tmp/jt_thunk_classify_1204_cpp" \
  "$oracle_tmp/jt_thunk_classify_1204_rust"; do
  if [[ ! -f "$executable" || -L "$executable" ]]; then
    echo "fixture executable is not a regular file: $executable" >&2
    exit 1
  fi
done
/usr/bin/sha256sum "$oracle_cpp/libdecomp.a" \
  "$oracle_tmp/jt_thunk_classify_1204_cpp" \
  "$oracle_tmp/jt_thunk_classify_1204_rust" \
  >"$oracle_tmp/comparand-binaries.before"

ghidra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_PRELOAD="$libstdcpp_path:$zlib_path" \
  "$oracle_tmp/jt_thunk_classify_1204_cpp" >"$oracle_tmp/ghidra.stdout" \
  2>"$oracle_tmp/ghidra.stderr" || ghidra_status=$?
rudra_status=0
/usr/bin/env -i PATH="$clean_path" LC_ALL=C LD_PRELOAD="$libstdcpp_path:$zlib_path" \
  "$oracle_tmp/jt_thunk_classify_1204_rust" >"$oracle_tmp/rudra.stdout" \
  2>"$oracle_tmp/rudra.stderr" || rudra_status=$?
diff_status=0
/usr/bin/diff -u --label ghidra --label rudra "$oracle_tmp/ghidra.stdout" \
  "$oracle_tmp/rudra.stdout" >"$oracle_tmp/raw.diff" || diff_status=$?

/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
  "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/ghidra.stderr" \
  "$oracle_tmp/rudra.stdout" "$oracle_tmp/rudra.stderr" \
  "$oracle_tmp/raw.diff" "$ghidra_status" "$rudra_status" "$diff_status" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
paths = {
    "ghidra_stdout_sha256": pathlib.Path(sys.argv[2]),
    "ghidra_stderr_sha256": pathlib.Path(sys.argv[3]),
    "rudra_stdout_sha256": pathlib.Path(sys.argv[4]),
    "rudra_stderr_sha256": pathlib.Path(sys.argv[5]),
    "raw_diff_sha256": pathlib.Path(sys.argv[6]),
}
for key, path in paths.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
for key, actual in (
    ("ghidra_exit_code", int(sys.argv[7])),
    ("rugra_exit_code", int(sys.argv[8])),
    ("diff_exit_code", int(sys.argv[9])),
):
    expected = metadata["expected_results"][key]
    if actual != expected:
        raise SystemExit(f"{key} mismatch: expected={expected} actual={actual}")
PY
if [[ "$ghidra_status" -ne 0 || "$rudra_status" -ne 0 || \
      "$diff_status" -ne 0 || -s "$oracle_tmp/ghidra.stderr" || \
      -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "bilateral fixture failed or emitted diagnostics" >&2
  /usr/bin/cat "$oracle_tmp/ghidra.stderr" "$oracle_tmp/rudra.stderr" \
    "$oracle_tmp/raw.diff" >&2
  exit 1
fi

final_specials="$oracle_tmp/final-specials.list"
if ! /usr/bin/find "$snapshot" "$oracle_cpp" ! -type f ! -type d \
    -print >"$final_specials"; then
  echo "could not enumerate final snapshot/oracle source types" >&2
  exit 1
fi
if [[ -s "$final_specials" ]]; then
  echo "snapshot/oracle source gained a non-regular filesystem node" >&2
  /usr/bin/cat "$final_specials" >&2
  exit 1
fi
/usr/bin/find "$snapshot" -type f -print0 | /usr/bin/sort -z | \
  /usr/bin/xargs -0 /usr/bin/sha256sum >"$oracle_tmp/snapshot.after"
/usr/bin/cmp --silent "$oracle_tmp/snapshot.before" "$oracle_tmp/snapshot.after"
/usr/bin/find "$snapshot" -type f -printf '%m %p\0' | /usr/bin/sort -z \
  >"$oracle_tmp/snapshot.modes.after"
/usr/bin/cmp --silent "$oracle_tmp/snapshot.modes.before" \
  "$oracle_tmp/snapshot.modes.after"
/usr/bin/find "$snapshot" -type d -printf '%m %p\0' | /usr/bin/sort -z \
  >"$oracle_tmp/snapshot.dirs.after"
/usr/bin/cmp --silent "$oracle_tmp/snapshot.dirs.before" \
  "$oracle_tmp/snapshot.dirs.after"
/usr/bin/sha256sum "${snapshot_owned_paths[@]}" >"$oracle_tmp/comparands.after"
/usr/bin/cmp --silent "$oracle_tmp/comparands.before" "$oracle_tmp/comparands.after"
while IFS= read -r -d '' source_path; do
  /usr/bin/sha256sum "$source_path"
done <"$oracle_tmp/oracle-source.paths" >"$oracle_tmp/oracle-source.after"
/usr/bin/cmp --silent "$oracle_tmp/oracle-source.before" \
  "$oracle_tmp/oracle-source.after"
while IFS= read -r -d '' source_path; do
  /usr/bin/stat -c '%a %n' "$source_path"
done <"$oracle_tmp/oracle-source.paths" >"$oracle_tmp/oracle-source.modes.after"
/usr/bin/cmp --silent "$oracle_tmp/oracle-source.modes.before" \
  "$oracle_tmp/oracle-source.modes.after"
{
  printf '%s .\0' "$(/usr/bin/stat -c '%a' "$oracle_cpp")"
  /usr/bin/find "$oracle_cpp" -mindepth 1 -type d -printf '%m %P\0'
} | /usr/bin/sort -z >"$oracle_tmp/oracle-source.dirs.after"
/usr/bin/env -i PATH="$clean_path" LC_ALL=C "$python_path" -I -S - \
  "$oracle_cpp" "$oracle_tmp/oracle-source.paths" \
  "$libdecomp_expected_objects" "$oracle_tmp/oracle-source.dirs.before" \
  "$oracle_tmp/oracle-source.dirs.after" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
before = {
    pathlib.Path(raw.decode()).relative_to(root).as_posix()
    for raw in pathlib.Path(sys.argv[2]).read_bytes().split(b"\0") if raw
}
after = {
    path.relative_to(root).as_posix()
    for path in root.rglob("*") if path.is_file() and not path.is_symlink()
}
objects = pathlib.Path(sys.argv[3]).read_text(encoding="ascii").splitlines()
expected_outputs = {"com_dbg/depend", "com_opt/depend", "libdecomp.a"}
expected_outputs.update(objects)
if not before <= after or after - before != expected_outputs:
    raise SystemExit(
        f"unexpected locked Ghidra build outputs: removed={sorted(before - after)} "
        f"missing={sorted(expected_outputs - (after - before))} "
        f"extra={sorted((after - before) - expected_outputs)}"
    )

def directory_records(raw_path):
    records = {}
    for raw in pathlib.Path(raw_path).read_bytes().split(b"\0"):
        if not raw:
            continue
        mode, relative = raw.decode("utf-8").split(" ", 1)
        if relative in records:
            raise SystemExit(f"duplicate Ghidra directory record: {relative}")
        records[relative] = mode
    return records

before_dirs = directory_records(sys.argv[4])
after_dirs = directory_records(sys.argv[5])
expected_new_dirs = {"com_dbg": "700", "com_opt": "700"}
if not before_dirs.keys() <= after_dirs.keys():
    raise SystemExit(
        f"locked Ghidra source directory removed: "
        f"{sorted(before_dirs.keys() - after_dirs.keys())}"
    )
changed_modes = {
    relative: (mode, after_dirs[relative])
    for relative, mode in before_dirs.items()
    if after_dirs[relative] != mode
}
new_dirs = {relative: after_dirs[relative] for relative in after_dirs.keys() - before_dirs.keys()}
if changed_modes or new_dirs != expected_new_dirs:
    raise SystemExit(
        f"unexpected locked Ghidra build directories: "
        f"changed_modes={changed_modes} new={new_dirs}"
    )
PY
verify_libdecomp_archive
if [[ "$(/usr/bin/sha256sum "$base_archive" | /usr/bin/awk '{print $1}')" != \
      "$rudra_base_archive_sha" || \
      "$(/usr/bin/sha256sum "$oracle_archive" | /usr/bin/awk '{print $1}')" != \
      "$oracle_cpp_archive_sha" ]]; then
  echo "immutable source archive drifted" >&2
  exit 1
fi
toolchain_state >"$oracle_tmp/toolchain.after"
/usr/bin/cmp --silent "$oracle_tmp/toolchain.before" "$oracle_tmp/toolchain.after"
/usr/bin/sha256sum "$native_archive" "$rudra_rlib" \
  >"$oracle_tmp/cargo-artifacts.final"
/usr/bin/cmp --silent "$oracle_tmp/cargo-artifacts.before" \
  "$oracle_tmp/cargo-artifacts.final"
artifact_input_state >"$oracle_tmp/direct-rustc-inputs.final"
/usr/bin/cmp --silent "$oracle_tmp/direct-rustc-inputs.before" \
  "$oracle_tmp/direct-rustc-inputs.final"
/usr/bin/sha256sum "$oracle_cpp/libdecomp.a" \
  "$oracle_tmp/jt_thunk_classify_1204_cpp" \
  "$oracle_tmp/jt_thunk_classify_1204_rust" \
  >"$oracle_tmp/comparand-binaries.final"
/usr/bin/cmp --silent "$oracle_tmp/comparand-binaries.before" \
  "$oracle_tmp/comparand-binaries.final"
if ! /usr/bin/cmp --silent "$runner_fd_path" "$runner"; then
  echo "runner fd/materialized runner drifted" >&2
  exit 1
fi

reject_replace_refs "$repo_root"
reject_replace_refs "$ghidra_root"
final_oracle_head=$(git_clean -C "$ghidra_root" rev-parse --verify 'HEAD^{commit}')
final_oracle_tag=$(git_clean -C "$ghidra_root" rev-parse --verify \
  "refs/tags/$oracle_tag^{commit}")
final_oracle_cpp_tree=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
final_oracle_makefile=$(git_clean -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$(git_clean -C "$repo_root" rev-parse --verify 'HEAD^{commit}')" != \
      "$candidate_commit" || \
      "$(git_clean -C "$repo_root" rev-parse --verify "$candidate_commit^{tree}")" != \
      "$candidate_tree" || \
      "$final_oracle_head" != "$oracle_commit" || \
      "$final_oracle_tag" != "$oracle_commit" || \
      "$final_oracle_cpp_tree" != "$oracle_cpp_tree" || \
      "$final_oracle_makefile" != "$oracle_makefile_blob" ]]; then
  echo "candidate/oracle commit drifted during evidence run" >&2
  exit 1
fi
final_owned_dirty=$(git_clean -C "$repo_root" status --porcelain=v1 \
  --untracked-files=all -- "${owned_relative_paths[@]}")
final_oracle_dirty=$(git_clean -C "$ghidra_root" status --porcelain=v1 \
  --untracked-files=all -- Ghidra/Features/Decompiler/src/decompile/cpp)
if [[ -n "$final_owned_dirty" || -n "$final_oracle_dirty" ]]; then
  echo "candidate/oracle worktree drifted during evidence run" >&2
  exit 1
fi
for index in "${!owned_relative_paths[@]}"; do
  relative=${owned_relative_paths[$index]}
  readback="$oracle_tmp/readback-$index.blob"
  git_clean -C "$repo_root" cat-file blob "${candidate_blob_oids[$index]}" >"$readback"
  read -r final_live_mode final_live_sha < <(regular_file_state "${owned_live_paths[$index]}")
  if ! /usr/bin/cmp --silent "$readback" "${snapshot_owned_paths[$index]}" || \
     [[ "$final_live_sha" != "${candidate_blob_sha256[$index]}" || \
        "$final_live_mode" != "${owned_expected_modes[$index]:3}" ]]; then
    echo "captured candidate blob readback drifted: $relative" >&2
    exit 1
  fi
done

{
  printf 'candidate_commit=%s\ncandidate_tree=%s\n' "$candidate_commit" "$candidate_tree"
  for index in "${!owned_relative_paths[@]}"; do
    printf 'candidate_blob[%s]=%s sha256=%s\n' "${owned_relative_paths[$index]}" \
      "${candidate_blob_oids[$index]}" "${candidate_blob_sha256[$index]}"
  done
  printf 'JT-THUNK-CLASSIFY-1204: bilateral PASS (25/25 byte-identical); focused jumptable tests PASS; metadata projection pending independent review; current native=%s rlib=%s; overall MISMATCH: JUMPTABLE-PIPELINE-0001,JUMPTABLE-SORT-TOOLCHAIN-0001,JUMPTABLE-EMULFN-0001\n' \
    "$native_sha" "$rlib_sha"
} >"$oracle_tmp/run-record.txt"
/usr/bin/cat "$oracle_tmp/run-record.txt"
