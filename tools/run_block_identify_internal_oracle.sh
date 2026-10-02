#!/usr/bin/env bash
# BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 bilateral runner.
#
# Builds the locked Ghidra 12.0.4 oracle fixture (BlockGraph::newBlockList →
# identifyInternal + selfIdentify + dedup, block.cc:940-963/895-931/525-539,
# on synthetic plain FlowBlock graphs) against the oracle cpp tree, builds the
# Rudra comparand (CollapseStructure::identify_internal) against the crate
# rlib, runs both, and diffs the complete raw state projection: top-level
# membership, composite children order, parent ownership, raw flags (no
# f_dead on components), boundary edge slots/labels/reverse indices, peer
# retargets, parallel-edge dedup label merge, f_switch_out /
# f_interior_goto* propagation, and internal (component-to-component) edge
# retention.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
oracle_cpp_tree=b02e230a539c65de14e50f357d0ba834d8184f4f
oracle_makefile_blob=ca0719fa5f17aabd14c52f40ed8b030f54d2aac6
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/block_identify_internal_1204.cc"
rust_fixture="$repo_root/tests/oracle/block_identify_internal_1204.rs"
metadata="$repo_root/tests/oracle/block_identify_internal_1204.metadata.json"
bfd_root="${RUDRA_BFD_ROOT:-/tmp/rudra-ghidra-bfd-2.38}"

mode=full
case "${1:-}" in
  "") ;;
  --validate-only) mode=validate; shift ;;
  --ghidra-only) mode=ghidra; shift ;;
  *) echo "usage: $0 [--validate-only|--ghidra-only]" >&2; exit 2 ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: $0 [--validate-only|--ghidra-only]" >&2; exit 2
fi

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
actual_cpp_tree=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp")
actual_makefile_blob=$(git -C "$ghidra_root" rev-parse \
  "$oracle_commit:Ghidra/Features/Decompiler/src/decompile/cpp/Makefile")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" \
      || "$actual_cpp_tree" != "$oracle_cpp_tree" \
      || "$actual_makefile_blob" != "$oracle_makefile_blob" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
for oracle_file in block.cc block.hh blockaction.cc blockaction.hh; do
  if ! git -C "$ghidra_root" diff --quiet -- \
      "Ghidra/Features/Decompiler/src/decompile/cpp/$oracle_file"; then
    echo "dirty locked oracle file: $oracle_file" >&2
    exit 1
  fi
done
if [[ ! -d "$bfd_root/usr/include/bfd.h" && ! -f "$bfd_root/usr/include/bfd.h" ]]; then
  echo "bfd oracle env missing at $bfd_root (see AGENTS.md oracle rebuild note)" >&2
  exit 1
fi

# Metadata comparand gate: fixture + comparand source hashes must match the
# pinned values (re-pinned with every fixture/source change).
python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/src/block.rs" "$repo_root/src/blockaction.rs" <<'PY'
import hashlib, json, pathlib, sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pairs = {
    "cpp_fixture_sha256": pathlib.Path(sys.argv[2]),
    "rust_fixture_sha256": pathlib.Path(sys.argv[3]),
    "rudra_block_rs_sha256": pathlib.Path(sys.argv[4]),
    "rudra_blockaction_rs_sha256": pathlib.Path(sys.argv[5]),
}
for key, path in pairs.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["comparand_sha256"][key] != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata['comparand_sha256'][key]} actual={actual}"
        )
oracle = metadata["oracle"]
if oracle["commit"] != "e40ed13014025f82488b1f8f7bca566894ac376b":
    raise SystemExit("metadata oracle commit drift")
if metadata["coverage"]["scoped_status"] != "MATCH":
    raise SystemExit("metadata scoped_status must be MATCH for a green run")
PY

if [[ "$mode" == validate ]]; then
  echo "block_identify_internal_1204: VALIDATED"
  exit 0
fi

oracle_tmp=$(mktemp -d /tmp/rudra-block-identify-1204.XXXXXX)
cleanup() {
  case "$oracle_tmp" in
    /tmp/rudra-block-identify-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Oracle side: reuse the prebuilt libdecomp.a from the locked tree (the
# environment bootstrap builds it); rebuild when absent.
if [[ ! -f "$cpp_root/libdecomp.a" ]]; then
  jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
  make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
fi
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -Wall -Wno-sign-compare -I"$cpp_root" -I"$bfd_root/usr/include" \
  "$oracle_tmp/fixture.cc" "$cpp_root/libdecomp.a" \
  -L"$bfd_root/usr/lib/x86_64-linux-gnu" -lbfd -lz \
  -Wl,-rpath,"$bfd_root/usr/lib/x86_64-linux-gnu" \
  -o "$oracle_tmp/block_identify_internal_1204"

if [[ "$mode" == ghidra ]]; then
  "$oracle_tmp/block_identify_internal_1204"
  exit $?
fi

# Rust comparand: crate rlib + rustc-linked fixture (goto_cascade runner
# pattern, plus the native sleigh archive link set from the negate runner).
fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
native_archive=$(find "$fixture_target/debug/build" -path '*/out/librudra_sleigh.a' -type f | head -n1)
if [[ -z "$native_archive" ]]; then
  echo "cargo build did not produce the native sleigh archive" >&2
  exit 1
fi
native_dir=$(dirname "$native_archive")
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  -L "native=$native_dir" --extern "rudra=$rudra_rlib" \
  -l static=rudra_sleigh -l dylib=z -l dylib=stdc++ -l dylib=m \
  "$rust_fixture" -o "$oracle_tmp/block_identify_internal_rudra"

"$oracle_tmp/block_identify_internal_1204" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/block_identify_internal_rudra" >"$oracle_tmp/rudra.stdout" 2>"$oracle_tmp/rudra.stderr"

expected_stdout=$(python3 -I -S -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["oracle_stdout_sha256"])' \
  "$metadata")
ghidra_stdout_sha=$(sha256sum "$oracle_tmp/ghidra.stdout" | awk '{print $1}')
if [[ "$ghidra_stdout_sha" != "$expected_stdout" ]]; then
  echo "locked Ghidra stdout hash drift: $ghidra_stdout_sha" >&2
  exit 1
fi

if [[ -s "$oracle_tmp/ghidra.stderr" ]]; then
  echo "Ghidra fixture emitted diagnostics" >&2
  cat "$oracle_tmp/ghidra.stderr" >&2
  exit 1
fi
if [[ -s "$oracle_tmp/rudra.stderr" ]]; then
  echo "Rudra fixture emitted diagnostics" >&2
  cat "$oracle_tmp/rudra.stderr" >&2
  exit 1
fi

if diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" \
    >"$oracle_tmp/bilateral.diff"; then
  cat "$oracle_tmp/ghidra.stdout"
  printf 'block_identify_internal_1204: MATCH stdout_sha256=%s\n' "$ghidra_stdout_sha"
else
  cat "$oracle_tmp/bilateral.diff"
  printf 'block_identify_internal_1204: MISMATCH (%s diff lines)\n' \
    "$(wc -l <"$oracle_tmp/bilateral.diff")"
  exit 1
fi
