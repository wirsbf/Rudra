# SSA / CBRANCH condition def-loss — root cause diagnosis

**Date:** 2026-07-27
**Scope:** Why a `CBRANCH`'s condition varnode (`in(1)`) loses its SSA def in
the curl decompile, producing the `while (local_0 == local_0)` dead-loop.
**Verdict:** The def is lost **only inside loops**. The trigger is a bug in
`calc_dom_frontier` (every loop's dominance frontier is computed empty), which
prevents `place_multiequals_direct` from inserting any MULTIEQUAL (phi) for the
EFLAGS ZF varnode. Rename then never links `CBRANCH in(1)` to the `cmp`'s
`INT_EQUAL` output, so the condition stays a free/unwritten varnode and
`printc::emit_block_condition_inner`'s value-based scan picks a garbage
comparison, emitting `local_0 == local_0`.

---

## 1. How x86 conditional jumps are modelled (real lifter)

The curl pipeline does **not** use `src/disasm/x86_lift.rs`. It uses the SLEIGH
FFI lifter (`SleighLifter::lift_function`, `examples/curl_decompile.rs:284`).
Decoding `cmp rdi,rsi; je rel8` through SLEIGH produces (dumped via a temporary
SLEIGH probe):

```
cmp rdi, rsi @ 0x1000:
  [3] INT_EQUAL  register:0x206/1 = register:0x0/2  const:0x0/2   ← ZF lives at 0x206
  [4] INT_AND    unique:0x58300/2 = register:0x0/2  const:0xff/2
  [5] POPCOUNT   unique:0x58400/1 = unique:0x58300/2
  [6] INT_AND    unique:0x58500/1 = unique:0x58400/1 const:0x1/1
  [7] INT_EQUAL  register:0x202/1 = unique:0x58500/1 const:0x0/1  ← CF lives at 0x202

je 0x100a @ 0x1003:
  [0] CBRANCH    ram:0x100a/8  register:0x206/1
```

Key facts:
- **ZF is at `register:0x206`** (NOT `0x201` as in the hand-written
  `x86_lift.rs`; the native lifter is stale/unused for curl).
- ZF is *written* by `INT_EQUAL` and *read* by `CBRANCH in(1)`.
- The cmp also writes several other flag varnodes (`0x202`, `0x207`, `0x20b`).
- Multiple instructions in a loop body (`cmp`, `add`, `sub`, …) each re-write
  `0x206`, so inside a loop ZF has **several definitions** and **must** get a
  MULTIEQUAL (phi) at the loop header.

## 2. Heritage rename wiring — works in straight-line code, breaks in loops

The pipeline calls `Funcdata::run_heritage_direct` (`src/funcdata.rs:480`),
which runs `place_multiequals_direct` → `rename_direct`.

`rename_direct` (`src/heritage.rs:3337`) marks every non-constant/non-annotation
varnode `active_heritage` (line 3356–3362), so the rename input-replacement
guard at line 3485 (`is_heritage_known() || !is_active_heritage()`) does not
skip the condition. `visit_rename_direct` faithfully ports Ghidra's
`renameRecurse` (heritage.cc:2480–2563), including the empty-stack input
promotion and INDIRECT same-time deepening.

End-to-end probe results (SLEIGH p-code → `Funcdata` → `run_heritage_direct`):

| Pattern | CBRANCH `in(1)` after Heritage |
|---|---|
| A: straight `cmp; je` (no back-edge) | `def=CPUI_INT_EQUAL@0x1001`, `is_written=true` ✅ |
| B: loop `cmp; je exit; add; jmp back` | `def=<none/dead>`, `is_written=false` ❌ |

So the def is lost **exactly when a loop back-edge is present**. Rename itself
is correct; the failure is that **no phi is placed** for ZF.

Confirmed: after Heritage on pattern B there are **8 `INT_EQUAL` defs of
`register:0x206` and zero `MULTIEQUAL` ops**. ZF never gets a phi, so the
CBRANCH read can never be resolved.

## 3. Root cause — `calc_dom_frontier` produces empty frontiers

Phi placement uses a custom SSA builder, `place_multiequals_direct`
(`src/heritage.rs:3150`), which at line 3216–3245 iterates each written
varnode's defining blocks and seeds the Cooper-Harvey-Kennedy worklist from
`bblocks.get_dom_frontier()`.

The dominance frontier is computed by `BlockGraph::calc_dom_frontier`
(`src/block.rs:1863`). It has the standard structure but with a load-bearing
guard:

```rust
// src/block.rs:1863-1913 (excerpt)
pub fn calc_dom_frontier(&mut self) {
    for i in 0..self.blocks.len() {
        ...
        if incoming.len() >= 2 {        // ← line 1876: join-points only
            let b_index = ...;
            let b_idom_ref = ...;
            for edge in incoming {
                let mut runner_ref = edge.point.clone();
                while !Arc::ptr_eq(&runner_ref, idom) && steps < max_steps {
                    runner_ref.write().unwrap().add_to_dom_frontier(b_index);
                    runner_ref = runner_ref's idom;
                }
            }
        }
    }
}
```

For pattern B the block structure (dumped from the same probe) is:

```
blk[0] start=0x2000 size_in=1 idom=None dom_frontier=[] preds=[1]   ← loop header / entry
blk[1] start=0x2005 size_in=1 idom=Some(0) dom_frontier=[] preds=[0] ← loop body
blk[2] start=0x200b size_in=1 idom=Some(0) dom_frontier=[] preds=[0] ← exit (ret)
```

**Every block's `dom_frontier` is empty.** The reason:

- blk[0] is the function entry (`idom=None`) **and** the loop header. Its only
  *recorded* predecessor is the back-edge `blk[1] → blk[0]` (`preds=[1]`).
  The function-entry flow into blk[0] is **not modelled as a predecessor
  edge**, so `incoming.len() == 1` and the `>= 2` guard skips blk[0] entirely.
- blk[1] and blk[2] each have exactly one predecessor.

By the CHK algorithm the back-edge `blk[1] → blk[0]` (where blk[0] dominates
blk[1]) must put **blk[0] in blk[0]'s own dominance frontier**. That requires
blk[0] to be processed as a join-point with ≥2 predecessors. Because the
implicit entry predecessor is missing, blk[0] is never a join-point, its DF
stays empty, and the phi-placement worklist for ZF produces nothing.

(The straight-line pattern A has no back-edge, so it needs no phi and rename
links the single cmp→CBRANCH def directly — which is why A works and only loops
break.)

## 4. How this becomes `while (local_0 == local_0)`

With no phi for ZF, `CBRANCH in(1)` (`register:0x206/1`) remains the raw free
varnode that `inject_raw_ops` created via `find_or_create_input_space`
(`src/varnode.rs:2264`, which deliberately returns a *separate* free varnode
because it filters `!is_written()`). Rename leaves it unwritten.

`printc::emit_block_condition_inner` (`src/printc.rs:3984`) then scans the
condition block's ops for a comparison whose **output has the same
`(space, offset)`** as the condition varnode (lines 4064–4092). Because the
condition is the *unwritten* `register:0x206`, the value-based scan finds some
`INT_EQUAL` writing `0x206` whose own inputs were already constant-folded to
the same garbage Stack-0 placeholder, yielding the tautology
`local_0 == local_0`. (The recent commit `dc67af5` papers over the *symptom*
by textually folding `X==X` to `1`; this document addresses the *cause*.)

## 5. Evidence / reproducers

- `examples/dump_cmp_jcc_pcode.rs` (temporary probe, removed after capture):
  decodes `cmp rdi,rsi; je` via SLEIGH and runs `Funcdata` + Heritage, printing
  the block graph (index / idom / dom_frontier / preds) and each op's def
  status. Patterns A and B give the table in §2 and the block dump in §3.
- `src/funcdata.rs` — added regression test
  `test_cbranch_condition_def_wired_via_heritage_single_block` (passes:
  single-block cmp→je is wired correctly) and
  `test_cbranch_condition_def_wired_multiblock_real_x86` (also passes for the
  *forward* branch case). A failing test for the loop case can be added on top
  of pattern B once `calc_dom_frontier` is fixed.

## 6. Recommended fix direction

Primary (the actual defect):

1. **Make `calc_dom_frontier` (`src/block.rs:1863`) treat the function entry
   block as having an implicit external predecessor**, so a loop header that is
   also the entry (or any single-predecessor block reached by a back-edge)
   becomes a join-point. Two viable approaches:
   - **(a)** Model function entry as a real predecessor edge (a synthetic
     "entry" source) when building the CFG, so entry-block `size_in >= 1`
     counts the entry flow. This matches Ghidra's `FlowBlock` model where the
     entry is a real in-edge.
   - **(b)** In `calc_dom_frontier`, replace the `incoming.len() >= 2` guard
     with the **back-edge-aware** formulation: for every predecessor edge
     `p → b` where `p` does not strictly dominate `b` (i.e. a back/cross edge),
     run the runner from `p` up to `idom(b)`. This is the correct CHK
     formulation and does not depend on counting predecessors. Concretely:
     iterate all blocks (not only join-points), and for each predecessor `p`
     of `b` with `!dominates(p, b)` (or `p == b`), ascend `p` adding `b` to
     each runner's DF until reaching `idom(b)`.
   - Approach (b) is the smaller, more localised fix.

2. After the fix, re-run the pattern-B probe: expect `blk[0].dom_frontier = {0}`
   and a `MULTIEQUAL` for `register:0x206` at `blk[0]`, after which
   `CBRANCH in(1)` resolves to the phi and `local_0 == local_0` disappears
   without the `dc67af5` textual workaround.

Secondary clean-ups (not the cause, but related stale code):

3. `src/disasm/x86_lift.rs` models ZF at `Register:0x201` and is **not** the
   lifter used by the curl pipeline (which uses SLEIGH at `0x206`). Either
   retire it or align the flag offsets with SLEIGH; do not rely on it for
   diagnosis.
4. `printc::emit_block_condition_inner`'s value-based `(space, offset)` scan
   (`src/printc.rs:4064`) is fragile: it should prefer the SSA `def` chain
   (which it already does in `emit_condition`, lines 4116–4139) and only fall
   back to the value scan when the def is genuinely absent. Once §1–2 land,
   the def chain will be populated and the scan becomes unnecessary for the
   CBRANCH case.

## 7. File references (absolute)

- Defect: `D:/ghidra/rudra/src/block.rs:1863` (`calc_dom_frontier`, guard at
  line 1876 `if incoming.len() >= 2`).
- Phi placement that depends on it: `D:/ghidra/rudra/src/heritage.rs:3150`
  (`place_multiequals_direct`), uses `get_dom_frontier` at line 3231.
- Rename (correct, not the cause): `D:/ghidra/rudra/src/heritage.rs:3337`
  (`rename_direct`) and `:3415` (`visit_rename_direct`).
- Curl pipeline lifter: `D:/ghidra/rudra/examples/curl_decompile.rs:284`
  (`SleighLifter::lift_function`); `D:/ghidra/rudra/src/disasm/sleigh_lift.rs`.
- Varnode dedup that separates written ZF from free ZF read:
  `D:/ghidra/rudra/src/varnode.rs:2264` (`find_or_create_input_space`).
- printc value-based scan: `D:/ghidra/rudra/src/printc.rs:3984`
  (`emit_block_condition_inner`).
- Stale native lifter (unused for curl): `D:/ghidra/rudra/src/disasm/x86_lift.rs`.
- Regression tests added: `D:/ghidra/rudra/src/funcdata.rs`
  (`test_cbranch_condition_def_wired_via_heritage_single_block`,
   `test_cbranch_condition_def_wired_multiblock_real_x86`).
