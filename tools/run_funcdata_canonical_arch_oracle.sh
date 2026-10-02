#!/usr/bin/env bash
set -euo pipefail

# FUNCDATA-CANONICAL-ARCH-0001 oracle runner: Funcdata constructor
# Architecture-binding parity (glb = scope->getArch(), funcdata.cc:48).
# Compiles the locked Ghidra 12.0.4 oracle fixture (real BfdArchitecture
# chain on the production x86-64 SLEIGH/BFD spec set, the same path as the
# arch_context_tracked fixture) and the worktree Rudra rlib (Funcdata::new
# binds the canonical default Architecture), runs both
# funcdata_canonical_arch_1204 fixtures and diffs the three diffed
# projections (arch_nonnull / space_name / arch_identity_shared) byte for
# byte; the Rust-only tails (min_laned_size wiring, SplitDatatype gates,
# set_arch override) are in-binary assertions on the Rust side.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
oracle_cpp="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
oracle_archive="$oracle_cpp/libdecomp.a"
cpp_fixture="$repo_root/tests/oracle/funcdata_canonical_arch_1204.cc"
rust_fixture="$repo_root/tests/oracle/funcdata_canonical_arch_1204.rs"
metadata="$repo_root/tests/oracle/funcdata_canonical_arch_1204.metadata.json"
bfd_include=/tmp/rudra-ghidra-bfd-2.38/usr/include
bfd_library=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle mismatch" >&2
  exit 1
fi
if [[ -n "$(git -C "$ghidra_root" status --porcelain --untracked-files=no -- Ghidra/Features/Decompiler/src/decompile/cpp)" ]]; then
  echo "locked Ghidra decompiler source tree is dirty" >&2
  exit 1
fi
for path in sleigh_specs/x86.ldefs sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86-64.sla; do
  if [[ ! -f "$repo_root/$path" ]]; then
    echo "missing spec asset: $path" >&2
    exit 1
  fi
done

python3 -I -S - "$metadata" "$cpp_fixture" "$rust_fixture" \
  "$repo_root/sleigh_specs/x86-64.sla" "$oracle_commit" "$oracle_tag" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    metadata_name,
    cpp_fixture_name,
    rust_fixture_name,
    sla_name,
    oracle_commit,
    oracle_tag,
) = sys.argv[1:]
metadata = json.loads(pathlib.Path(metadata_name).read_text(encoding="utf-8"))
cpp_fixture = pathlib.Path(cpp_fixture_name)
rust_fixture = pathlib.Path(rust_fixture_name)

if metadata["oracle"]["tag"] != oracle_tag or metadata["oracle"]["commit"] != oracle_commit:
    raise SystemExit("metadata oracle tag/commit does not match runner")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


expected = {
    "cpp_fixture_sha256": digest(cpp_fixture),
    "rust_fixture_sha256": digest(rust_fixture),
    "sla_sha256": digest(pathlib.Path(sla_name)),
}
comparand = metadata["comparand"]
for key, actual in expected.items():
    pinned = comparand.get(key) or metadata.get(key)
    if pinned != actual:
        raise SystemExit(f"{key} mismatch: metadata={pinned} actual={actual}")

fingerprint = "sha256:" + hashlib.sha256(metadata["input"].encode()).hexdigest()
if metadata["input_fingerprint"] != fingerprint:
    raise SystemExit("input fingerprint mismatch")
PY

# Stage under /home/wirs/.cache (persistent NVMe) rather than /tmp: the
# shared /tmp tmpfs can SIGBUS the linker when concurrent agent worktrees
# fill it mid-write.
stage_root=/home/wirs/.cache
mkdir -p "$stage_root"
oracle_tmp=$(mktemp -d "$stage_root/rudra-funcdata-canonical-arch-1204.XXXXXX")
cleanup() {
  case "$oracle_tmp" in
    "$stage_root"/rudra-funcdata-canonical-arch-1204.??????) rm -rf -- "$oracle_tmp" ;;
    *) echo "refusing unsafe cleanup target: $oracle_tmp" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

spec_root="$oracle_tmp/specs"
mkdir "$spec_root"
for path in sleigh_specs/x86.ldefs sleigh_specs/x86-64.pspec \
  sleigh_specs/x86-64-gcc.cspec sleigh_specs/x86-64.sla; do
  cp "$repo_root/$path" "$spec_root/${path##*/}"
done

jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')
make --silent -C "$oracle_cpp" -j "$jobs" EXTRA= libdecomp.a

g++ -std=c++11 -O2 -m64 \
  -I"$bfd_include" -I"$oracle_cpp" "$cpp_fixture" \
  "$oracle_cpp/libdecomp.cc" "$oracle_cpp/sleigh_arch.cc" \
  "$oracle_cpp/inject_sleigh.cc" "$oracle_cpp/bfd_arch.cc" \
  "$oracle_cpp/loadimage_bfd.cc" "$oracle_archive" \
  "$bfd_library" -lz -o "$oracle_tmp/funcdata_canonical_arch_1204_cpp"

fixture_target="$oracle_tmp/cargo-target"
CARGO_TARGET_DIR="$fixture_target" \
  cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rudra_rlib="$fixture_target/debug/librudra.rlib"
if [[ ! -f "$rudra_rlib" ]]; then
  echo "cargo build did not produce a Rudra rlib" >&2
  exit 1
fi
rustc --edition=2021 -O -L "dependency=$fixture_target/debug/deps" \
  --extern "rudra=$rudra_rlib" "$rust_fixture" \
  -o "$oracle_tmp/funcdata_canonical_arch_rudra"

# The oracle fixture boots BfdArchitecture over its own executable
# (argv[0]); the diffed projections depend only on the spec set, never on
# the host binary's symbol table.
bfd_runtime=/tmp/rudra-ghidra-bfd-2.38/usr/lib/x86_64-linux-gnu
LD_LIBRARY_PATH="$bfd_runtime${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$oracle_tmp/funcdata_canonical_arch_1204_cpp" "$spec_root" \
  >"$oracle_tmp/ghidra.stdout"
"$oracle_tmp/funcdata_canonical_arch_rudra" >"$oracle_tmp/rudra.stdout"
diff -u "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout"

python3 -I -S - "$metadata" "$oracle_tmp/ghidra.stdout" "$oracle_tmp/rudra.stdout" <<'PY'
import hashlib
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
comparand = metadata["comparand"]
observed = {
    "cpp_stdout_sha256": pathlib.Path(sys.argv[2]),
    "rust_stdout_sha256": pathlib.Path(sys.argv[3]),
}
for key, path in observed.items():
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if comparand[key] != actual:
        raise SystemExit(f"{key} mismatch: metadata={comparand[key]} actual={actual}")
PY

cat "$oracle_tmp/ghidra.stdout"
printf 'funcdata_canonical_arch_1204: MATCH diffed projections (arch_nonnull/space_name/arch_identity_shared); registered residuals stay open (FUNCDATA-LOCALSCOPE-OWNERSHIP-0001)\n'
