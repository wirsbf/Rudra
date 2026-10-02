# Vendored SLEIGH Rust compiler crates (from kuna)

These four crates are the SLEIGH compiler half (the `sleigh_opt` equivalent)
plus its library foundations, borrowed verbatim from
[kuna](https://github.com/Noelo-Lab/kuna) (Apache-2.0) at pinned commit
`0096e984d74846e45f42c1dbe1fb95252083dda2`. See the repository `NOTICE` for
the attribution chain (kuna/Noelo-Lab → Ghidra/NSA).

| Crate | Role | External deps |
|---|---|---|
| `kuna-base` | foundation: addresses/spaces, XML+marshal, raw p-code, compression, filemanage | thiserror, flate2 |
| `kuna-num` | multiprecision, IEEE float emulation, op behaviors | (kuna-base) |
| `kuna-sleigh` | .sla reader, decode runtime types, symbol/pattern/template/FormatEncode layers used by the compiler | (kuna-base, kuna-num) |
| `kuna-slacomp` | **the `.slaspec` → `.sla` compiler** (`slacomp` bin, the `sleigh_opt` replacement) | (kuna-base, kuna-num, kuna-sleigh) |

## Why they are workspace members

`kuna-sleigh` (plus `kuna-base`/`kuna-num`, which its public API names
directly) **is in the rudra build graph**: `src/sleigh_ffi.rs` drives it as
the production SLEIGH decode engine (Phase2 of SLEIGH-RUSTIFY — the C++
FFI runtime was retired 2026-09-26 after the dual-engine gates passed, see
`docs/alignment_docs/SLEIGH_PHASE2_SWAP_2026-09-26.md`). `kuna-slacomp`
stays standalone: `tools/build_locked_x86_64_sla.sh` builds
`-p kuna-slacomp --bin slacomp` and uses it as the production `.slaspec` →
`.sla` compiler. The `.sla` gate criterion is the decompressed element
stream (FORMAT_VERSION + inflated sha256 + size band), because the zlib C
and flate2/miniz_oxide deflate backends produce different (but
content-equivalent) compressed bytes.

Runtime dedup with Rudra's own `marshal/space/pcoderaw/translate/...`
modules is deliberately deferred (Phase 0 §7.1 decision item); the sources
are kept byte-identical to the pinned upstream commit for auditability.

## What is NOT vendored

- kuna's per-crate `tests/` integration trees (they reference kuna's
  repo-root datatest corpus).
- kuna's own vendored Ghidra processor-spec tree (148 specs, ≠ the locked
  12.0.4 oracle's 146). Rudra spec inputs always come from the locked oracle
  tree via `git archive` (see `tools/build_locked_x86_64_sla.sh`).

Known consequence: a few `#[cfg(test)]` unit tests inside
`kuna-base/src/xml.rs` and `kuna-sleigh/src/loadimage_xml.rs` read fixtures
from `<repo-root>/tests/datatests/` (the kuna corpus layout); in this tree
those paths do not exist, so `cargo test -p kuna-base` / `-p kuna-sleigh`
has expected failures in those specific tests. Measured at vendoring time
(release, `--lib`): kuna-base 127 passed / 4 failed (all datatests file-not-found),
kuna-num 32/0, kuna-sleigh 205 passed / 5 failed (same class),
kuna-slacomp 3/0. Rudra's gates exercise the root package
(`cargo test --lib`) and the compiler binary, not those tests.

## Verification

- Full 146/146 locked-spec sweep (vendored `slacomp` vs locked C++
  `sleigh_opt`, decompressed-stream identity): see
  `docs/alignment_docs/SLEIGH_SWEEP_146_2026-09-26.md` and
  `tools/sweep_sleigh_specs.py`.
