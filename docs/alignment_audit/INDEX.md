# Cross-Review Audit — Core Algorithm Modules (2026-07-05)

**Scope**: rule-12 whitelist core-algorithm modules, audited by 6 parallel independent
cross-review agents (per AGENTS.md rule 12). Each auditor read the actual Ghidra source at the
cited lines and verified the four decisive-semantic categories (reference params, traversal
order, counter scope, comparison key) — not just the surface annotation.

**Goal reference (user directive)**: "每个 ghidra 原有函数都必须保证语义完全对齐；每个 rudra
自定义函数都必须解释为什么不和 ghidra 对齐；解释不合理的都必须与 ghidra 做到完全对齐；
不应该存在任何理由和 ghidra 不对齐。"

## 2026-08-11 targeted audits (Ghidra 12.0.4)

- [`PcodeSnippet` mandatory punctuation and failure state](PCODEPARSE_SYNTAX_2026-08-11.md)
  — confirmed Rudra accepts malformed snippets that the locked Bison grammar rejects.
- [Foundation and pipeline audit](FOUNDATION_PIPELINE_2026-08-11.md)
  — records deterministic Action-tree/executor, callspec, opcode/flags, SLEIGH,
  compression, multiprecision, ledger, and gate failures without promoting
  source-only evidence to runtime MATCH.
- [Core identity and state foundations](CORE_FOUNDATIONS_2026-08-11.md)
  — records the Space/Address/SeqNum, Block, Varnode/PcodeOp, Cover,
  Database/Fspec, and Marshal dependency DAG with locked-source counterexamples.
- [Control, recovery, and output pipelines](CONTROL_OUTPUT_PIPELINES_2026-08-11.md)
  — records production reachability and state-order failures in Heritage,
  CondExe/PathMeld, JumpTable, Print, Architecture, UserOp, and PcodeInject.
- [Packed marshal state machine](MARSHAL_PACKED_2026-08-11.md)
  — records cursor, attribute, nesting, type/error, raw-string, and missing API
  differences in PackedDecode/PackedEncode.

## Per-module report files

| Module | File | Rule-12? | Total | OK | MISMATCH | PARTIAL | MISSING/STUB | GLUE-UNJUSTIFIED | CITED-LINE-DRIFT |
|---|---|---|---|---|---|---|---|---|---|
| heritage.rs | `heritage.md` | ✅ | 33 | 11 | 12 | 5 | 11 | 0 | 12 |
| blockaction.rs | `blockaction.md` | ✅ | 67 | 8 | 26 | 13 | 7 | 7 | 33 |
| condexe.rs | `condexe_jumptable.md` | ✅ | ~30 | 19 | 4 | 3 | 2 | 1 | ~10 |
| jumptable.rs | `condexe_jumptable.md` | ✅ | ~60 | 41 | 7 | 6 | 5+ | 0 | — |
| merge.rs | `merge_varmap.md` | ✅ | ~70 | 38 | 4 | 9 | 0 | 0 | 16 |
| varmap.rs | `merge_varmap.md` | ✅ | ~46 | 28 | 6 | 5 | 0 | 0 | 9 |
| coreaction.rs | `coreaction.md` | main pipeline | 78 | 9 | 14 | 23 | 11 | 4 | 0 |
| ruleaction.rs | `ruleaction.md` | main pipeline | ~68 sampled | ~60 | 0 | 4 | 0 | 2 | 1 |

**Aggregate**: ~480 functions/items audited; **73 MISMATCH**, **68 PARTIAL**, **36+ MISSING/stub**,
**14 GLUE-UNJUSTIFIED**, **~91 CITED-LINE-DRIFT**.

## P0 — user-visible correctness defects (likely root causes of documented symptoms)

| ID | Module:fn | Symptom | Ghidra line |
|---|---|---|---|
| P0-1 | `varmap.rs:715 has_local_alias` + `:551 gather_internal` | **direction convention inverted vs Ghidra** → `has_local_alias` always returns false on x86 → alias analysis silently disabled on primary target | varmap.cc:700, 721-723, 673-678 |
| P0-2 | `condexe.rs:794 boolean_match_evaluate` | commutative swap is dead code (`match (a,d,c,b) { _ => {} }`) → switches with swapped AND/OR operand order classified UNCORRELATED → if/else folding missed | expression.cc:111-216 |
| P0-3 | `jumptable.rs:2010 build_addresses` | drops `AddrSpace::addressToByte` + `funcptr_align` mask + EmulateFunction loader wiring → addresses wrong on word-addressed spaces / non-trivial switches → directly causes documented `switch=0 ❌` for curl | jumptable.cc:1453-1481 |
| P0-4 | `jumptable.rs:2916 get_varnode_value` | returns 0 instead of consulting loader for non-const/non-mapped inputs → any switch reading a global/memory value gets wrong targets | jumptable.cc:181-193 |
| P0-5 | `jumptable.rs:2333 analyze_guards` | missing `checkUnrolledGuard`, missing cross-edge `i!=0` check, missing `getFlipPath()` consultation → guards missed/mis-recorded | jumptable.cc:1063-1129 |
| P0-6 | `heritage.rs:712 place_multiequals_direct` | implements generic dom-frontier worklist instead of Ghidra's Augmented Dominator Tree (`buildADT`+`visitIncr`+`calcMultiequals`) → phi placement diverges on any CFG with back-edges | heritage.cc:2316/2395/2440 |
| P0-7 | `heritage.rs:945 visit_rename_direct` | missing 3 load-bearing semantics: INDIRECT same-time stack-deepening, empty-stack input promotion, `deleteVarnode` of consumed frees → SSA name assignment wrong | heritage.cc:2480 (renameRecurse) |

## P1 — IR/SSA correctness, output drift (high blast radius)

| ID | Module:fn | Defect |
|---|---|---|
| P1-1 | `coreaction.rs` (~30 Actions) | **systemic return-value divergence**: every Ghidra `Action::apply` returns `0`, Rudra returns `CHANGE`/`NO_CHANGE` leaking `count` into parent group's repeatapply driver → root cause of disabled mainloop/fullloop repeatapply + deleted ActionSimplify workaround (rule-5 violation surface) |
| P1-2 | `coreaction.rs:7193 build_full_pipeline_actions` | shadowed by `action.rs::set_default_actions`; double-registers ActionInferTypes/ActionActiveParam/ActionReturnRecovery |
| P1-3 | `coreaction.rs:3561 ActionNameVars` | STUB — does nothing → **Rudra never names local variables** |
| P1-4 | `coreaction.rs:5632 ActionConditionalConst` | STUB — entire conditional-constant machinery missing |
| P1-5 | `coreaction.rs:5730 ActionReturnRecovery` | rewritten as hardcoded x86-64 RAX scan, not ParamActive/AncestorRealistic |
| P1-6 | `coreaction.rs:327 ActionConstantPtr` | rewritten as READONLY flag tag, not selectInferSpace/isPointer/spacebaseConstant |
| P1-7 | `merge.rs:647 assign_names` | invented fn (cited `Merge::assignNames` doesn't exist); wrong grammar (`local_{:x}h` not `<printNameBase>Var<n>`) + per-call counter instead of single shared `int4 base=1` — **181538f-class regression** |
| P1-8 | `varmap.rs:1508 build_variable_name` | no `&mut index`, no `printNameBase`, no `makeNameUnique` — 181538f-class |
| P1-9 | `blockaction.rs:645 collapse_all` | 7-phase pipeline replaces Ghidra's 5-line `collapseAll` (orderLoopBodies→collapseConditions→collapseInternal+selectGoto) → likely root cause of documented `goto=2 ❌` |
| P1-10 | `blockaction.rs:1429 select_and_mark_goto` | invented graph-wide scan replaces Ghidra's lazy innermost-loop-scoped `selectGoto`/`updateLoopBody`/TraceDAG one-edge-at-a-time |
| P1-11 | `blockaction.rs:4857 ActionNormalizeBranches::apply` | does BREAK/CONTINUE tagging (Ghidra's scopeBreak, belongs in ActionFinalStructure) instead of `opFlipInPlace` |
| P1-12 | `blockaction.rs:4770 ActionFinalStructure::apply` | does GOTO tagging + dead-op removal instead of `orderBlocks`+`finalizePrinting`+`scopeBreak`+`markUnstructured`+`markLabelBumpUp` |
| P1-13 | `blockaction.rs:3982 collapse_switches` | `ruleBlockSwitch` MISSING; existing fn is a different algorithm under misleading name → `switch=0 ❌` |
| P1-14 | `blockaction.rs apply_rules_to_block` | `ruleBlockInfLoop` MISSING (infinite loops never structured), `ruleBlockOr` absent from `collapseConditions` (no AND/OR short-circuit folding) |
| P1-15 | `condexe.rs:632 do_replacement` (RETURN branch) | new COPY's output never wired into RETURN slot 1 (Rudra feeds `retvn`, Ghidra feeds `outvn`) |
| P1-16 | `condexe.rs:1330 ActionConditionalExe::apply` | constructs fresh `ConditionalExecution` per block + early-break restart; Ghidra reuses one instance + continues inner loop |
| P1-17 | `heritage.rs:679 heritage` (entry) | gutted to 3 lines vs Ghidra's 90-line per-space/per-range orchestrator (no buildADT/processJoins/disjoint-range/guard/analyzeNewLoadGuards) |
| P1-18 | `heritage.rs:36 LocationMap::add` | replaces disjoint-cover merge with blind BTreeMap insert |

## P2 — annotation hygiene (rule 5.5 / 13 Red Flags)

- **`blockaction.hh:46` placeholder cluster** (33 fns cite the line `class LoopBody {` instead of real `blockaction.cc:<line>` or `RUDRA-GLUE`).
- **`merge.hh:83` fabricated-name cluster** (15 fns cite non-existent `Merge::<name>` methods; should be `RUDRA-GLUE` or renamed to match real Ghidra).
- **`condexe.cc:432` mis-cite cluster** (~10 fns cite the constructor; expression-matching fns should cite `expression.cc`).
- **`varmap.hh:137` / `varmap.hh:90` mis-cite cluster** (5 invented helpers `resolve_rsp_offset*`/`find_spacebase_input`/`make_int_type` should be `RUDRA-GLUE`).
- **`heritage.cc:219` drift** (~10 fns all cite the Heritage ctor).
- All drifts pass `check_ghidra_refs.py` because the cited line exists but is the wrong target. The annotation gate needs strengthening (rule 14) OR fns need re-annotation.

## Methodology notes

- Auditors ran as read-only Explore agents and could not write files; reports captured by parent
  session and persisted as `<module>.md`.
- "MISMATCH" = at least one of the four decisive-semantic categories diverges with user-visible
  or correctness impact.
- "CITED-LINE-DRIFT" = the `// Ghidra:` line either points at a class-decl/ctor line or a
  non-existent function; does not by itself prove semantic divergence but is an AGENTS.md rule 13
  Red Flag.
- Counter-scope audit (181538f regression prevention): 2 regressions found (assign_names,
  build_variable_name — both lack single-shared-`&base` threading); 1 direction-convention
  inversion (AliasChecker — 181538f-class semantic flip).

## Next actions (priority order)

1. **P0 fixes** — start with varmap AliasChecker direction inversion (smallest change, biggest
   correctness gain on x86). Each fix = 1 atomic commit with `## Alignment Evidence` block per
   rule 10. Each fix runs `cargo test` + (for visible-output modules) `compare_ghidra.py`.
2. **P1 fixes** — grouped by module; the heritage/blockaction/coreaction triad is the largest
   work (structural rewrites of the heritage driver and the structuring algorithm).
3. **P2 re-annotation** — mechanical pass; can run in parallel with P0/P1 once the gate is
   strengthened to detect class-decl/ctor-line drift.
