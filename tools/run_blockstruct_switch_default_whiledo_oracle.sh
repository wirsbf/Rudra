#!/usr/bin/env bash
# BLOCK-FINALIZE-DEFAULT-RECURSE-0001 bilateral runner.
#
# Builds the locked Ghidra 12.0.4 oracle fixture (BlockGraph::finalizePrinting
# recursion over a switch DEFAULT arm carrying a while-do: block.cc:3556-3559
# -> 1364-1371 -> BlockWhileDo::finalizePrinting 3403-3424) against the oracle
# cpp tree, builds the Rugra comparand against the crate rlib, runs both, and
# diffs the shared sorted observation (structure-tree fact lines + per-block
# op notPrinted flags).
#
# Decisive observable: the default arm's WhileDo for-extraction runs through
# the switch's finalize recursion — `op blk2#0 INT_ADD notprinted=1`
# (block.cc:3422 opMarkNonPrinting). Pre-fix Rugra printed 0 (the finalize
# dispatch skipped the default_case slot).
#
# Fixture shape note: the tree is installed through the production factories
# (newBlockWhileDo then newBlockSwitch / try_rule_switch) because a single
# CollapseStructure run consumes the raw default target before a loop can
# form under it (ruleSwitch's obvious-exit scan takes any 2-in successor) and
# the corpus has no default-nested-loop sample — see the .cc/.rs headers and
# the metadata normalizations.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
cpp_fixture="$repo_root/tests/oracle/blockstruct_switch_default_whiledo_1204.cc"
rust_fixture="$repo_root/tests/oracle/blockstruct_switch_default_whiledo_1204.rs"
metadata="$repo_root/tests/oracle/blockstruct_switch_default_whiledo_1204.metadata.json"
bfd_root="${RUDRA_BFD_ROOT:-/tmp/rugra-ghidra-bfd-2.38}"

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "expected $oracle_tag at $oracle_commit; HEAD=$actual_commit tag=$tag_commit" >&2
  exit 1
fi
for oracle_file in block.cc block.hh blockaction.cc funcdata_block.cc jumptable.cc; do
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
  "$repo_root/src/block.rs" <<'PY'
import hashlib, json, pathlib, sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pairs = {
    "cpp_fixture_sha256": pathlib.Path(sys.argv[2]),
    "rust_fixture_sha256": pathlib.Path(sys.argv[3]),
    "rugra_block_sha256": pathlib.Path(sys.argv[4]),
}
for key, path in pairs.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if metadata["comparand_sha256"][key] != actual:
        raise SystemExit(
            f"{key} mismatch: metadata={metadata['comparand_sha256'][key]} actual={actual}"
        )
PY

# TMPDIR override: the Rust comparand's debug build needs several GB and
# /tmp is a quota-limited tmpfs on this host; allow redirecting to /home.
scratch_dir="${TMPDIR:-/tmp}"
oracle_tmp=$(mktemp -d "$scratch_dir/rugra-blockstruct-swdefwd-1204.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$scratch_dir"/rugra-blockstruct-swdefwd-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

# Oracle side: reuse the prebuilt libdecomp.a from the locked tree; link the
# capability bootstrap objects (startDecompilerLibrary) like
# run_condexe_success_state_oracle.sh does.
if [[ ! -f "$cpp_root/libdecomp.a" ]]; then
  jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
  make --silent -C "$cpp_root" -j "$jobs" EXTRA= libdecomp.a
fi
cp "$cpp_fixture" "$oracle_tmp/fixture.cc"
g++ -std=c++11 -O2 -I"$cpp_root" -I"$bfd_root/usr/include" \
  "$oracle_tmp/fixture.cc" \
  "$cpp_root/libdecomp.cc" "$cpp_root/sleigh_arch.cc" "$cpp_root/inject_sleigh.cc" \
  "$cpp_root/libdecomp.a" \
  -L"$bfd_root/usr/lib/x86_64-linux-gnu" -lbfd -lz \
  -Wl,-rpath,"$bfd_root/usr/lib/x86_64-linux-gnu" \
  -o "$oracle_tmp/blockstruct_switch_default_whiledo_1204"

# Rust comparand: crate rlib + rustc-linked fixture.
fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rugra_rlib="$fixture_target/debug/librugra.rlib"
if [[ ! -f "$rugra_rlib" ]]; then
  echo "cargo build did not produce a Rugra rlib" >&2
  exit 1
fi
rustc --edition 2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rugra=$rugra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/blockstruct_switch_default_whiledo_rugra"

"$oracle_tmp/blockstruct_switch_default_whiledo_1204" >"$oracle_tmp/ghidra.stdout" 2>"$oracle_tmp/ghidra.stderr"
"$oracle_tmp/blockstruct_switch_default_whiledo_rugra" >"$oracle_tmp/rugra.stdout" 2>"$oracle_tmp/rugra.stderr"

if diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rugra.stdout" \
    >"$oracle_tmp/bilateral.diff"; then
  cat "$oracle_tmp/ghidra.stdout"
  printf 'blockstruct_switch_default_whiledo_1204: MATCH\n'
else
  cat "$oracle_tmp/bilateral.diff"
  printf 'blockstruct_switch_default_whiledo_1204: MISMATCH (%s diff lines) — see metadata\n' \
    "$(wc -l <"$oracle_tmp/bilateral.diff")"
  exit 1
fi
