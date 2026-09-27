#!/usr/bin/env bash
set -euo pipefail

# PARSEADJ-PARSEFACE-PCODE-0001 bilateral runner: builds the locked-oracle
# projection of pcode_snippet_face_1204.cc against the shared libdecomp.a
# and the Rust twin from the current tree, runs both, and byte-diffs the
# streams. This fixture IS the "generator absorbed" equivalence unit for
# pcodeparse.cc's whole parse face (bison yyparse + yy* skeleton +
# handwritten PcodeLexer/PcodeSnippet members; see
# GENERATOR_ABSORBED_2026-09-27.md §3/§4): the face may only claim
# behaviour equivalence when this whole-parser fixture reaches bilateral
# identity over the p-code semantic-string case matrix.
#
# Lane-iteration form (base 6a458387): root re-pins the metadata to the
# frozen-commit form at integration, mirroring the grammar_parse_face
# runner's lifecycle.

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b
oracle_tag=Ghidra_12.0.4_build
ghidra_root="$repo_root/ghidra"
cpp_root="$ghidra_root/Ghidra/Features/Decompiler/src/decompile/cpp"
fixture_cc="$repo_root/tests/oracle/pcode_snippet_face_1204.cc"
fixture_rs="$repo_root/tests/oracle/pcode_snippet_face_1204.rs"
spec_dir="$repo_root/sleigh_specs"

workroot=${RUGRA_PCODE_SNIPPET_FACE_WORKROOT:-/dev/shm/rugra-tests/pcodeface/runner}
mkdir -p "$workroot"

for required in "$fixture_cc" "$fixture_rs" "$spec_dir/x86-64.sla"; do
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

# --- Oracle side (bare SLEIGH engine, parseInject lifecycle) ---------------
if [[ ! -f "$workroot/pcode_snippet_face_oracle" || \
      "$fixture_cc" -nt "$workroot/pcode_snippet_face_oracle" ]]; then
  g++ -std=c++11 -O1 -I"$cpp_root" \
    "$fixture_cc" "$cpp_root/sleigh.cc" "$cpp_root/libdecomp.a" \
    -lz -s -o "$workroot/pcode_snippet_face_oracle"
fi
"$workroot/pcode_snippet_face_oracle" "$spec_dir" \
  > "$workroot/oracle_out.txt" 2> "$workroot/oracle_err.txt"
oracle_status=$?

# --- Rugra side (current tree) ---------------------------------------------
cargo_target=${CARGO_TARGET_DIR:-$workroot/target}
cargo build --offline --locked --quiet --manifest-path "$repo_root/Cargo.toml" --lib
rustc --edition=2021 -C opt-level=0 "$fixture_rs" \
  --extern rugra="$cargo_target/debug/librugra.rlib" \
  -L dependency="$cargo_target/debug/deps" \
  -o "$workroot/pcode_snippet_face_rugra"
"$workroot/pcode_snippet_face_rugra" \
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
diff "$workroot/oracle_out.txt" "$workroot/rugra_out.txt" | head -80 >&2
exit 1
