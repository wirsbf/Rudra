#!/usr/bin/env bash
set -euo pipefail

# NODEJOIN-F2/F3/F4/F5: locked Ghidra 12.0.4 ConditionalJoin differential
# runner. Builds the pristine oracle cpp tree, compiles the C++ driver
# (tests/oracle/nodejoin_condjoin_1204.cc) and the Rust mirror
# (tests/oracle/nodejoin_condjoin_1204.rs) against the built rudra lib,
# runs both over the same nine synthetic diamond cases and requires
# byte-identical stdout projections.

usage() {
  echo "usage: $0 [--validate-only]" >&2
}

validate_only=false
case ${1:-} in
  "")
    ;;
  --validate-only)
    validate_only=true
    shift
    ;;
  *)
    usage
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6

ghidra_root="$repo_root/ghidra"
cpp_fixture="$repo_root/tests/oracle/nodejoin_condjoin_1204.cc"
rust_fixture="$repo_root/tests/oracle/nodejoin_condjoin_1204.rs"
metadata="$repo_root/tests/oracle/nodejoin_condjoin_1204.metadata.json"
runner="$repo_root/tools/run_nodejoin_condjoin_oracle.sh"

for required in "$cpp_fixture" "$rust_fixture" "$metadata" "$runner"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    echo "required input is missing or a symlink: $required" >&2
    exit 1
  fi
done
# Worktree convention: ghidra may be a symlink into the main repo checkout
# (gitignored); the oracle identity checks below follow it via git -C.
if [[ ! -d "$ghidra_root" ]]; then
  echo "ghidra oracle checkout missing: $ghidra_root" >&2
  exit 1
fi

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
actual_tag=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$actual_tag" != "$oracle_commit" || \
  "$actual_cpp_tree" != "$oracle_cpp_tree" || \
  "$actual_makefile" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi

# Metadata comparand pins (sha256 over file content) are enforced on every
# invocation; --validate-only stops here, mirroring the sibling runner
# convention (run_heritage_callguard_oracle.sh).
metadata_pins=$(python3 - "$metadata" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    comparand = json.load(handle)["comparand"]
for key in ("cpp_fixture_sha256", "rust_fixture_sha256", "runner_sha256"):
    print(key, comparand[key])
PY
)
pin_error=0
while read -r pin_key pin_expected; do
  case "$pin_key" in
    cpp_fixture_sha256) pin_target="$cpp_fixture" ;;
    rust_fixture_sha256) pin_target="$rust_fixture" ;;
    runner_sha256) pin_target="$runner" ;;
    *)
      echo "unknown metadata comparand key: $pin_key" >&2
      pin_error=1
      continue
      ;;
  esac
  pin_actual=$(sha256sum "$pin_target" | awk '{print $1}')
  if [[ "$pin_actual" != "$pin_expected" ]]; then
    echo "metadata pin mismatch: $pin_key expected=$pin_expected actual=$pin_actual ($pin_target)" >&2
    pin_error=1
  fi
done <<< "$metadata_pins"
if [[ "$pin_error" -ne 0 ]]; then
  exit 1
fi
if [[ "$validate_only" == true ]]; then
  echo "nodejoin_condjoin_1204 metadata/source lock validation passed"
  exit 0
fi

oracle_tmp=${NODEJOIN_ORACLE_TMP:-/tmp/rudra-nodejoin-condjoin-oracle}
mkdir -p "$oracle_tmp"
cpp_dir="$oracle_tmp/cpp"
if [[ ! -f "$cpp_dir/libdecomp.a" || "$cpp_dir/libdecomp.a" -ot \
      "$repo_root/.git" ]]; then
  rm -rf "$cpp_dir"
  mkdir -p "$cpp_dir"
  git -C "$ghidra_root" archive \
    "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp" \
    | tar -x -C "$cpp_dir"
fi
ref_blockaction="$oracle_tmp/oracle_blockaction_ref.cc"
git -C "$ghidra_root" show \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/blockaction.cc" \
  > "$ref_blockaction"
if ! diff -q "$ref_blockaction" "$cpp_dir/blockaction.cc" >/dev/null; then
  echo "extracted oracle blockaction.cc is not pristine" >&2
  exit 1
fi

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$cpp_dir" -j "$jobs" \
  CXX="g++ -std=c++11" EXTRA= libdecomp.a

g++ -std=c++11 -O1 -w -m64 \
  -I"$cpp_dir" "$cpp_fixture" \
  "$cpp_dir/libdecomp.cc" "$cpp_dir/sleigh_arch.cc" \
  "$cpp_dir/inject_sleigh.cc" \
  -Wl,--whole-archive "$cpp_dir/libdecomp.a" -Wl,--no-whole-archive -lz \
  -o "$oracle_tmp/nodejoin_condjoin_cpp"

flock /tmp/rudra-cargo-build.lock -c \
  "CARGO_TARGET_DIR='$oracle_tmp/rudra-target' cargo build --offline --locked --quiet --profile fast-release --lib --manifest-path '$repo_root/Cargo.toml'"
rustc --edition=2021 -O \
  -L dependency="$oracle_tmp/rudra-target/fast-release/deps" \
  --extern rudra="$oracle_tmp/rudra-target/fast-release/librudra.rlib" \
  "$rust_fixture" \
  -o "$oracle_tmp/nodejoin_condjoin_rust"

set +e
"$oracle_tmp/nodejoin_condjoin_cpp" \
  >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
ghidra_status=$?
"$oracle_tmp/nodejoin_condjoin_rust" \
  >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"
rudra_status=$?
cmp -s "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"
stdout_cmp=$?
set -e

echo "ghidra_exit=$ghidra_status rudra_exit=$rudra_status stdout_cmp=$stdout_cmp"
sha256sum "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" | sed 's|'"$oracle_tmp"'/||'
if [[ "$ghidra_status" -eq 0 && "$rudra_status" -eq 0 && "$stdout_cmp" -eq 0 ]]; then
  echo "MATCH: nodejoin_condjoin_1204 (byte-identical projections)"
  exit 0
fi
echo "MISMATCH: nodejoin_condjoin_1204" >&2
diff "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" | head -40 >&2
exit 1
