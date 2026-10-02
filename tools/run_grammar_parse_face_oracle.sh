#!/usr/bin/env bash
set -euo pipefail

# WORKPKG-UNMAP-PARSEADJ-0015 bilateral runner: builds the locked-oracle
# projection of grammar_parse_face_1204.cc against the shared libdecomp.a
# and the Rust twin from the current tree, runs both, and byte-diffs the
# streams. This fixture IS the "generator absorbed" equivalence unit for
# grammar.cc's bison yyparse + yy* skeleton (see
# docs/alignment_audit/GENERATOR_ABSORBED_2026-09-27.md): the class may
# only claim behaviour equivalence when this whole-parser face reaches
# bilateral identity.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
fixture_cc="$repo_root/tests/oracle/grammar_parse_face_1204.cc"
fixture_rs="$repo_root/tests/oracle/grammar_parse_face_1204.rs"
bfd_include=/tmp/rugra-ghidra-bfd-2.38/usr/include
bfd_library=/usr/lib/x86_64-linux-gnu/libbfd-2.38-system.so
spec_dir="$repo_root/sleigh_specs"
binary="$repo_root/examples/curl"

workroot=${RUDRA_GRAMMAR_PARSE_FACE_WORKROOT:-/dev/shm/rugra-tests/parseadj/runner}
mkdir -p "$workroot"

for required in "$fixture_cc" "$fixture_rs" \
    "$bfd_include/bfd.h" "$bfd_library" \
    "$spec_dir/x86-64.sla" "$spec_dir/x86-64-gcc.cspec" "$binary"; do
  if [[ ! -f "$required" ]]; then
    echo "required input is missing: $required" >&2
    exit 1
  fi
done

actual_commit=$(git -C "$ghidra_root" rev-parse HEAD)
tag_commit=$(git -C "$ghidra_root" rev-parse "refs/tags/$oracle_tag^{commit}")
if [[ "$actual_commit" != "$oracle_commit" || "$tag_commit" != "$oracle_commit" ]]; then
  echo "locked Ghidra oracle identity mismatch" >&2
  exit 1
fi
if ! git -C "$ghidra_root" diff --quiet -- \
    Ghidra/Features/Decompiler/src/decompile/cpp; then
  echo "locked Ghidra decompiler source is dirty" >&2
  exit 1
fi

# --- Oracle side -----------------------------------------------------------
if [[ ! -f "$workroot/grammar_parse_face_oracle" || \
      "$fixture_cc" -nt "$workroot/grammar_parse_face_oracle" ]]; then
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" -c "$cpp_root/libdecomp.cc" -o "$workroot/libdecomp.o"
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" -c "$cpp_root/bfd_arch.cc" -o "$workroot/bfd_arch.o"
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" -c "$cpp_root/sleigh_arch.cc" -o "$workroot/sleigh_arch.o"
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" -c "$cpp_root/loadimage_bfd.cc" -o "$workroot/loadimage_bfd.o"
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" -c "$cpp_root/inject_sleigh.cc" -o "$workroot/inject_sleigh.o"
  g++ -std=c++11 -O1 -I"$cpp_root" -I"$bfd_include" \
    "$fixture_cc" "$workroot/libdecomp.o" "$workroot/bfd_arch.o" \
    "$workroot/sleigh_arch.o" "$workroot/loadimage_bfd.o" \
    "$workroot/inject_sleigh.o" "$cpp_root/libdecomp.a" \
    "$bfd_library" -lz -s -o "$workroot/grammar_parse_face_oracle"
fi
"$workroot/grammar_parse_face_oracle" "$spec_dir" "$binary" \
  > "$workroot/oracle_out.txt" 2> "$workroot/oracle_err.txt"
oracle_status=$?

# --- Rugra side (current tree) ---------------------------------------------
cargo_target=${CARGO_TARGET_DIR:-$workroot/target}
cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 -C opt-level=0 "$fixture_rs" \
  --extern rugra="$cargo_target/debug/librugra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$workroot/grammar_parse_face_rugra"
"$workroot/grammar_parse_face_rugra" \
  > "$workroot/rugra_out.txt" 2> "$workroot/rugra_err.txt"
rugra_status=$?

echo "oracle_exit=$oracle_status rugra_exit=$rugra_status"
if [[ "$oracle_status" != 0 || "$rugra_status" != 0 ]]; then
  echo "fixture side failed" >&2
  tail -5 "$workroot/oracle_err.txt" >&2 || true
  tail -5 "$workroot/rugra_err.txt" >&2 || true
  exit 1
fi
if diff -q "$workroot/oracle_out.txt" "$workroot/rugra_out.txt" >/dev/null; then
  oracle_sha=$(sha256sum "$workroot/oracle_out.txt" | awk '{print $1}')
  echo "BILATERAL MATCH: $oracle_sha ($(wc -l < "$workroot/oracle_out.txt") records)"
  exit 0
fi
echo "BILATERAL MISMATCH" >&2
diff "$workroot/oracle_out.txt" "$workroot/rugra_out.txt" | head -60 >&2
exit 1
