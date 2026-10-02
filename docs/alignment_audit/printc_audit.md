# Function-Level Alignment Audit: printc.cc vs src/printc.rs

**Sources**:
- Ghidra: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc` (3401 lines, ~104 `PrintC::` methods)
- Rudra: `src/printc.rs` (6560 lines) + `src/printlanguage.rs` (`PrintLanguage` trait / shared helpers)

**Audit method**: Extracted every `PrintC::method` definition in `printc.cc`, then name-matched each
against `fn method` declarations across `src/printc.rs` and `src/printlanguage.rs`. Methods whose
semantics are split across multiple Rudra helpers (or replaced by a direct-emit equivalent) are
flagged `PARTIAL`/`EQUIV`; methods with no Rust callable of recognizably similar name are flagged
`MISSING`.

**Legend**: ✅=faithful port  ⚠️=PARTIAL (renamed / different signature / stub)  ❌=MISSING (no callable)
📝=EQUIV (semantics folded into a differently-named function)

## Summary counts

| Category | Count |
|---|---|
| Total Ghidra `PrintC::` methods (excluding ctors / static token defs) | 95 |
| ✅ Present + faithful (or EQUIV by a direct-emit helper) | 27 |
| ⚠️ PARTIAL (present but signature/semantics diverge or stub body) | 14 |
| ❌ MISSING (no callable in Rudra) | 54 |

**Missing method total: 54** (counting `PrintCCapability` / ctor methods as informational;
strictly `PrintC` member-function gap = **52**).

## Per-method status

### Capabilities / construction (L23-L143)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L108 | `PrintCCapability::PrintCCapability` / `initialize` / `buildPrinter` | none | ❌ MISSING |
| L123 | `PrintC::PrintC(Architecture*, string)` (ctor) | `PrintC::new(emit)` at printc.rs:319 | ⚠️ PARTIAL — different signature, no Architecture binding, no `resetDefaults()` call chain |

### Type/symbol scope helpers (L143-L353)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L143 | `PrintC::buildTypeStack` | none | ❌ MISSING |
| L169 | `PrintC::pushPrototypeInputs` | none (inlined into `emit_prototype_inputs`) | ⚠️ PARTIAL — logic folded |
| L202 | `PrintC::pushSymbolScope` | none | ❌ MISSING |
| L233 | `PrintC::emitSymbolScope` | none | ❌ MISSING |
| L264 | `PrintC::pushTypeStart` | `push_type_start_opt` at printc.rs:6218 | ⚠️ PARTIAL — text-only, no OpToken/typestack |
| L313 | `PrintC::pushTypeEnd` | `push_type_end_opt` at printc.rs:6254 | ⚠️ PARTIAL |
| L353 | `PrintC::checkArrayDeref` | none | ❌ MISSING |
| L376 | `PrintC::checkAddressOfCast` | none | ❌ MISSING |

### op* family — core P-code emission (L424-L929)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L424 | `PrintC::opFunc` | none (op dispatch via `doc_statement`→`op.push(self)`) | ❌ MISSING — the master `opFunc` dispatcher |
| L448 | `PrintC::opTypeCast` | `op_type_cast` at printc.rs:5649 | ⚠️ PARTIAL — stub: emits in(0) only, no cast markup |
| L474 | `PrintC::opHiddenFunc` | none | ❌ MISSING |
| L481 | `PrintC::opCopy` | `op_copy` at printc.rs:4623 | ✅ |
| L487 | `PrintC::opLoad` | `op_load` at printc.rs:4636 | ⚠️ PARTIAL — extra typed-deref branch |
| L500 | `PrintC::opStore` | `op_store` at printc.rs:4665 | ⚠️ PARTIAL |
| L520 | `PrintC::opBranch` | `op_branch` at printc.rs:5115 | ⚠️ PARTIAL |
| L536 | `PrintC::opCbranch` | `op_cbranch` at printc.rs:5069 | ⚠️ PARTIAL — large custom condition-folding body |
| L582 | `PrintC::opBranchind` | `op_branchind` at printc.rs:5553 | ⚠️ PARTIAL — emits literal `switch(...)` only |
| L593 | `PrintC::opCall` | `op_call` at printc.rs:4960 | ⚠️ PARTIAL |
| L637 | `PrintC::opCallind` | `op_callind` at printc.rs:5562 | ⚠️ PARTIAL — hard-coded `(*...)(...)` form |
| L673 | `PrintC::opCallother` | none | ❌ MISSING |
| L717 | `PrintC::opConstructor` | none | ❌ MISSING |
| L754 | `PrintC::opReturn` | `op_return` at printc.rs:5013 | ⚠️ PARTIAL |
| L786 | `PrintC::opIntZext` | none (cast handled inline in `push_varnode`) | ❌ MISSING — explicit zext collapse not ported |
| L799 | `PrintC::opIntSext` | none | ❌ MISSING |
| L814 | `PrintC::opBoolNegate` | none (negation handled in `try_fold_bool_comparison`) | ❌ MISSING |
| L830 | `PrintC::opFloatInt2Float` | none | ❌ MISSING |
| L843 | `PrintC::opSubpiece` | none (folded into `push_varnode` byte-trunc) | ❌ MISSING |
| L880 | `PrintC::opPtradd` | none (array index inline in `push_varnode`) | ❌ MISSING |
| L929 | `PrintC::opPtrsub` | `op_ptrsub` at printc.rs:5624 | ⚠️ PARTIAL — emits `->field_XX` only, no struct-field lookup |

### op* family — extended P-code (L1150-L1288)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L1150 | `PrintC::opSegmentOp` | `op_segment` at printc.rs:5638 | ⚠️ PARTIAL — emits literal `SEGMENTOP(...)` |
| L1156 | `PrintC::opCpoolRefOp` | `op_cpoolref` at printc.rs:5580 | ⚠️ PARTIAL — emits literal `CPOOLREF` |
| L1230 | `PrintC::opNewOp` | `op_new` at printc.rs:5613 | ⚠️ PARTIAL — emits literal `new(...)` |
| L1264 | `PrintC::opInsertOp` | `op_insert` at printc.rs:5602 | ⚠️ PARTIAL — emits literal `INSERT(...)` |
| L1270 | `PrintC::opExtractOp` | `op_extract` at printc.rs:5591 | ⚠️ PARTIAL — emits literal `EXTRACT(...)` |

### Constant/value pushers (L1288-L1606)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L1288 | `PrintC::push_integer` | none (closest: `emit_integer_value` at printc.rs:6303) | ❌ MISSING — no hex/decimal/char-mode dispatch |
| L1380 | `PrintC::push_float` | none | ❌ MISSING |
| L1426 | `PrintC::printUnicode` | none | ❌ MISSING |
| L1472 | `PrintC::pushType` | `push_type` at printc.rs:5145 | ⚠️ PARTIAL |
| L1488 | `PrintC::pushBoolConstant` | `push_bool_constant` at printc.rs:5672 | ⚠️ PARTIAL — drops `tag/vn/op` params |
| L1504 | `PrintC::doEmitWideCharPrefix` | none | ❌ MISSING |
| L1512 | `PrintC::printCharHexEscape` | none | ❌ MISSING |
| L1534 | `PrintC::printCharacterConstant` | none | ❌ MISSING |
| L1562 | `PrintC::getHiddenThisSlot` | none | ❌ MISSING |
| L1581 | `PrintC::resetDefaultsPrintC` | none (only base `reset_defaults` trait default `{}`) | ❌ MISSING |

### Constant pushers (L1606-L2085)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L1606 | `PrintC::pushCharConstant` | `push_char_constant` at printc.rs:5661 | ⚠️ PARTIAL — drops tag/vn/op; partial logic |
| L1666 | `PrintC::pushEnumConstant` | `push_enum_constant` at printc.rs:5667 | ⚠️ PARTIAL — no enum-name lookup, emits raw hex |
| L1698 | `PrintC::pushPtrCharConstant` | `push_ptr_char_constant` at printc.rs:5677 | ⚠️ PARTIAL — stub: emits literal `"<str>"` |
| L1730 | `PrintC::pushPtrCodeConstant` | none | ❌ MISSING |
| L1744 | `PrintC::pushConstant` | `push_constant` at printc.rs:5654 | ⚠️ PARTIAL — drops tag/vn/op, no int-format |
| L1818 | `PrintC::pushEquate` | `push_equate` at printc.rs:5682 | ⚠️ PARTIAL — just delegates to `push_constant` |
| L1861 | `PrintC::pushAnnotation` | none | ❌ MISSING |
| L1905 | `PrintC::pushSymbol` | none (inline in `push_varnode` via symbol table) | ❌ MISSING |
| L1938 | `PrintC::pushUnnamedLocation` | none (referenced in comments only, printc.rs:5430) | ❌ MISSING |
| L1947 | `PrintC::pushPartialSymbol` | none | ❌ MISSING |
| L2067 | `PrintC::pushMismatchSymbol` | none | ❌ MISSING |
| L2085 | `PrintC::pushImpliedField` | none | ❌ MISSING |

### Struct/enum/prototype emission (L2120-L2350)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L2120 | `PrintC::emitStructDefinition` | `emit_struct_definition` at printc.rs:6061 | ✅ |
| L2153 | `PrintC::emitEnumDefinition` | `emit_enum_definition` at printc.rs:6121 | ✅ |
| L2194 | `PrintC::emitPrototypeOutput` | `emit_prototype_output` at printc.rs:5875 | ✅ |
| L2222 | `PrintC::emitPrototypeInputs` | `emit_prototype_inputs` at printc.rs:5918 | ✅ |
| L2260 | `PrintC::emitLocalVarDecls` | none (functionally replaced by `doc_variable_decls_from_funcdata` at printc.rs:1738) | ⚠️ PARTIAL — different approach, not Ghidra-faithful |
| L2285 | `PrintC::emitStatement` | none (closest: `doc_statement` at printc.rs:4612) | ⚠️ PARTIAL — different dispatch |
| L2303 | `PrintC::emitGotoStatement` | `emit_goto_statement` at printc.rs:5707 | ⚠️ PARTIAL — different signature (addr+goto_type vs FlowBlock*) |
| L2325 | `PrintC::resetDefaults` | `PrintLanguage::reset_defaults` at printlanguage.rs:1458 | ⚠️ PARTIAL — trait default `{}` only, no PrintC-specific reset |
| L2332 | `PrintC::initializeFromArchitecture` | none | ❌ MISSING |
| L2342 | `PrintC::adjustTypeOperators` | none | ❌ MISSING |
| L2350 | `PrintC::setCommentStyle` | none | ❌ MISSING |

### Type/definition/global docs (L2369-L2641)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L2369 | `PrintC::emitTypeDefinition` | `emit_type_definition` at printc.rs:6021 | ✅ |
| L2388 | `PrintC::checkPrintNegation` | none | ❌ MISSING |
| L2401 | `PrintC::docTypeDefinitions` | `doc_type_definitions` at printc.rs:5993 | ✅ |
| L2418 | `PrintC::emitInplaceOp` | none (compound-assign attempted in `op_binary`) | ❌ MISSING |
| L2468 | `PrintC::emitExpression` | `emit_inline_expr` at printc.rs:2713 | ⚠️ PARTIAL — different scope (inlines into parent) |
| L2497 | `PrintC::emitVarDecl` | `emit_var_decl` at printc.rs:5753 | ✅ |
| L2510 | `PrintC::emitVarDeclStatement` | `emit_var_decl_statement` at printc.rs:5776 | ✅ |
| L2518 | `PrintC::emitScopeVarDecls` | none | ❌ MISSING |
| L2577 | `PrintC::emitFunctionDeclaration` | `emit_function_declaration` at printc.rs:5815 | ✅ |
| L2608 | `PrintC::emitGlobalVarDeclsRecursive` | none | ❌ MISSING |
| L2621 | `PrintC::docAllGlobals` | none | ❌ MISSING |
| L2631 | `PrintC::docSingleGlobal` | none | ❌ MISSING |
| L2641 | `PrintC::docFunction` | `PrintLanguage::doc_function` at printc.rs:3673 | ⚠️ PARTIAL — heavily customized, no `emitFunctionDeclaration`/`docAllGlobals` callsites |

### Block emission (L2678-L3359)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L2678 | `PrintC::emitBlockBasic` | none (closest: `emit_structured_basic` at printc.rs:1396 + `emit_block_ops` at printc.rs:429) | ⚠️ PARTIAL — split across two helpers, neither is the faithful walk |
| L2746 | `PrintC::emitBlockGraph` | none (closest: `emit_block_structured` at printc.rs:662 — the dispatcher) | ⚠️ PARTIAL — different recursion, no `emitBlockCopy`/`Goto`/`Ls` chain |
| L2759 | `PrintC::emitBlockCopy` | none | ❌ MISSING |
| L2766 | `PrintC::emitBlockGoto` | none | ❌ MISSING |
| L2781 | `PrintC::emitBlockLs` | none (closest: `emit_structured_list` at printc.rs:1129) | ⚠️ PARTIAL |
| L2836 | `PrintC::emitBlockCondition` | `emit_block_condition` at printc.rs:2974 (+ `_inner` at 3255) | ⚠️ PARTIAL |
| L2878 | `PrintC::emitBlockIf` | `emit_structured_if` at printc.rs:750 | ⚠️ PARTIAL — different signature |
| L2957 | `PrintC::emitForLoop` | none (for-loop pattern detection missing) | ❌ MISSING |
| L3001 | `PrintC::emitBlockWhileDo` | `emit_structured_whiledo` at printc.rs:965 | ⚠️ PARTIAL |
| L3068 | `PrintC::emitBlockDoWhile` | `emit_structured_dowhile` at printc.rs:1049 | ⚠️ PARTIAL |
| L3097 | `PrintC::emitBlockInfLoop` | `emit_structured_infloop` at printc.rs:1095 | ⚠️ PARTIAL |
| L3129 | `PrintC::emitSwitchCase` | none (inlined into `emit_structured_switch` at printc.rs:1217) | ⚠️ PARTIAL |
| L3164 | `PrintC::emitLabel` | none (label logic inlined in `emit_block_structured` at printc.rs:723-734) | ⚠️ PARTIAL |
| L3198 | `PrintC::emitLabelStatement` | `emit_label_statement` at printc.rs:5687 | ⚠️ PARTIAL — different signature (addr vs FlowBlock*) |
| L3219 | `PrintC::emitAnyLabelStatement` | `emit_any_label_statement` at printc.rs:5695 | ⚠️ PARTIAL |
| L3313 | `PrintC::emitBlockSwitch` | `emit_structured_switch` at printc.rs:1217 | ⚠️ PARTIAL |

### Comment emission (L3231-L3359)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L3231 | `PrintC::emitCommentGroup` | none | ❌ MISSING |
| L3247 | `PrintC::emitCommentBlockTree` | `emit_comment_block_tree` at printc.rs:5704 | ⚠️ PARTIAL — empty stub `{}` |
| L3272 | `PrintC::emitCommentFuncHeader` | none | ❌ MISSING |

### Misc helpers (L3359-L3373)

| Ghidra line | Ghidra method | Rudra | Status |
|---|---|---|---|
| L3359 | `PrintC::genericFunctionName` | none (inline in `code_label`/`sanitize_c_ident`) | ❌ MISSING |
| L3373 | `PrintC::genericTypeName` | none | ❌ MISSING |

## High-priority MISSING methods (output-correctness impact)

Ordered by impact on emitted C-text fidelity. The Rudra `PrintC` re-implements the high-level
emission flow but **bypasses Ghidra's expression-stack (`pushAtom`/`OpToken`/`recurse`) machinery**
that the bulk of `printc.cc` is built on; the gap below is therefore dominated by missing
`push*`/constant-formatting helpers and the structured-block / comment subtrees.

### P0 — direct output-text defects

| ID | Method | Ghidra line | Why it matters |
|---|---|---|---|
| P0-1 | `opFunc` (master op dispatcher) | L424 | Rudra replaces with `op.push(self)` Rust trait dispatch; divergence in any opcode mapping silently mis-emits |
| P0-2 | `pushConstant` / `pushCharConstant` / `pushEnumConstant` / `push_integer` | L1288/L1606/L1666/L1744 | Rudra versions drop the `tag/vn/op` params and the hex/decimal/char-mode dispatch (`mods & force_hex` etc.) → constants print in wrong base, char literals never emitted, enum values never named |
| P0-3 | `pushSymbol` / `pushPartialSymbol` / `pushMismatchSymbol` / `pushUnnamedLocation` / `pushImpliedField` / `pushAnnotation` | L1861-L2085 | None ported; Rudra inlines raw symbol-name lookup in `push_varnode`. No partial-symbol offsetting, no implied-field rendering, no annotation markup → struct/union field access, dynamic symbols, and `hidden` pcode ops render incorrectly |
| P0-4 | `resetDefaultsPrintC` (PrintC-specific option flags) | L1581 | Only the trait-default `reset_defaults(){}` exists; `option_convention`/`option_hide_thisparam`/`option_nocprops`/`option_max_implied_ref` etc. never reset → option state leaks across functions |
| P0-5 | `pushPtrCodeConstant` | L1730 | Function-pointer constants never emitted; `pushPtrCharConstant` is also a stub (`"<str>"`) |
| P0-6 | `opIntZext` / `opIntSext` / `opBoolNegate` / `opSubpiece` / `opPtradd` | L786-L880 | None ported as named callables; cast/truncation/negation logic is scattered across `push_varnode` and `try_fold_bool_comparison` with no Ghidra-faithful equivalents (cast-implied checks, sign-extension printing, `!` collapse) |
| P0-7 | `opCallother` / `opConstructor` / `opHiddenFunc` | L424/L673/L717 | Callother ops emit nothing; C++ constructor/new wrapping missing |

### P1 — structured-output / scope drift

| ID | Method | Ghidra line | Why it matters |
|---|---|---|---|
| P1-1 | `emitBlockBasic` / `emitBlockGraph` / `emitBlockCopy` / `emitBlockGoto` / `emitBlockLs` | L2678-L2781 | Block-tree emission replaced by `emit_block_structured` dispatcher + `emit_structured_*` family with different signatures; the Ghidra block-copy (goto forwarding) and block-list (consecutive stmt) cases have no faithful equivalent |
| P1-2 | `emitForLoop` | L2957 | For-loop pattern detection (`while`-with-init+update) missing → all loops emit as `while` |
| P1-3 | `emitCommentGroup` / `emitCommentFuncHeader` | L3231/L3272 | Header/body comments never emitted |
| P1-4 | `docAllGlobals` / `docSingleGlobal` / `emitGlobalVarDeclsRecursive` / `emitScopeVarDecls` | L2518-L2631 | Global/scope var decl emission missing; Rudra uses a different `doc_variable_decls_from_funcdata` path |
| P1-5 | `emitInplaceOp` (compound assignment `+=` etc.) | L2418 | Compound-assign detection missing; all updates emit `x = x + y` |
| P1-6 | `checkPrintNegation` | L2388 | Negation-folding predicate missing; `!(a==b)` may not collapse |
| P1-7 | `emitStatement` | L2285 | Rudra uses `doc_statement` (different signature/role); not a drop-in replacement |

### P2 — infrastructure (lower blast radius but blocks faithful alignment)

| ID | Method | Ghidra line | Why it matters |
|---|---|---|---|
| P2-1 | `buildTypeStack` / `pushTypeStart` / `pushTypeEnd` / `pushPrototypeInputs` / `pushSymbolScope` / `emitSymbolScope` / `checkArrayDeref` / `checkAddressOfCast` / `getHiddenThisSlot` | L143-L376 | Type-expression stack machinery (the foundation of all `push*` / declaration emission) is replaced by direct-text emission; `push_type_start_opt` covers only the common case |
| P2-2 | `printUnicode` / `printCharHexEscape` / `printCharacterConstant` / `doEmitWideCharPrefix` / `push_float` | L1288-L1534 | Char/string/float formatting helpers missing |
| P2-3 | `initializeFromArchitecture` / `adjustTypeOperators` / `setCommentStyle` | L2332-L2350 | Architecture-specific option wiring (comment style, type-op overrides) missing |
| P2-4 | `genericFunctionName` / `genericTypeName` | L3359/L3373 | Name-generation fallbacks missing (logic inlined into `code_label`) |
| P2-5 | `PrintCCapability::*` (printer registration) | L108 | No capability/plugin registration; Rudra instantiates `PrintC::new` directly |

## Notes on PARTIAL items

- **`opPtrsub`/`opCallind`/`opCpoolRefOp`/`opNewOp`/`opInsertOp`/`opExtractOp`/`opSegmentOp`/`opTypeCast`** (printc.rs:5549-5651): all are one-line literal-text stubs that emit a fixed token (`SEGMENTOP(...)`, `INSERT(...)`, `CPOOLREF`, etc.) instead of the Ghidra-faithful logic. They satisfy the name-match but diverge semantically.
- **`push_constant`/`push_char_constant`/`push_enum_constant`/`push_bool_constant`/`push_ptr_char_constant`/`push_equate`** (printc.rs:5654-5684): all carry the `// Missing printc.cc methods (batch 1)` banner — explicitly self-identified stubs with simplified signatures and bodies.
- **`emit_comment_block_tree`** (printc.rs:5704): empty body `{}`.
- **`emit_block_structured` + `emit_structured_*`** family (printc.rs:662-1553): the Rudra replacement for the entire `emitBlock*` subtree; functionally emits *a* C representation but is not a line-by-line port of `emitBlockBasic`/`Graph`/`Copy`/`Goto`/`Ls`/`If`/`WhileDo`/`DoWhile`/`InfLoop`/`Switch`.

## Detailed P1 inventory: `emitBlock*` subtree and comment system

The summary tables above flag the `emitBlock*` / comment methods as PARTIAL or MISSING at a
per-name level. This section enumerates, per Ghidra method, (a) the exact line range in
`printc.cc`, (b) what the method does, and (c) what (if anything) exists in Rudra today, so a
porter can scope each gap without re-reading the C++.

All references are to `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc`.

### Block-tree emission (`emitBlock*`) — L2678-L3353

| Ghidra method (line) | Signature / role | Rudra status | Gap |
|---|---|---|---|
| `emitBlockBasic` (L2678-L2744, 67 lines) | `void emitBlockBasic(const BlockBasic *bb)` — walks the basic block's PcodeOp list, skipping `notPrinted`/`BRANCH`/implied-output ops, calling `emitCommentGroup` + `emitStatement` per op, applying `comma_separate` / `only_branch` / `no_branch` mods, and emitting the flat-print `goto` when `nofallthru` is set. Drives the per-op comment sorter via `commsorter.setupBlockList(bb)`. | **PARTIAL** — split across `emit_block_ops` (printc.rs:491) and `emit_structured_basic` (printc.rs:1458). Neither is the faithful walk: `emit_block_ops` skips branches/implied ops but has no `comma_separate` handling, no per-op `emitCommentGroup`, no flat-print goto path, and adds Rudra-original dead-output/COPY/rip-relative filters not present in Ghidra. | No `commsorter` integration (comments never per-op), no `comma_separate`, no flat-goto, extra filters diverge output. |
| `emitBlockGraph` (L2746-L2757, 12 lines) | `void emitBlockGraph(const BlockGraph *bl)` — iterates the block list, bracketing each child in `beginBlock`/`endBlock` and recursing via `(*iter)->emit(this)`. The top-level entry for block-tree emission. | **PARTIAL** — closest is `emit_block_structured` (printc.rs:724), the Rudra dispatcher. It uses `Arc<RwLock<dyn FlowBlock>>` + `BlockGraph` + `emitted` set (Rudra-original cycle-break) instead of the recursive `emit` virtual dispatch. | No `beginBlock`/`endBlock` bracketing (Emit markup ids dropped), no virtual-dispatch recursion. |
| `emitBlockCopy` (L2759-L2764, 6 lines) | `void emitBlockCopy(const BlockCopy *bl)` — emits any label, then recurses into the single sub-block. The block-duplication forwarding case. | **MISSING** — no Rust callable. Rudra's `emit_block_structured` does not special-case `BlockCopy`/`BlockGoto` block types; the goto-forwarding that `BlockCopy`/`BlockGoto` exist to express has no equivalent. | Entire block-copy class unhandled. |
| `emitBlockGoto` (L2766-L2779, 14 lines) | `void emitBlockGoto(const BlockGoto *bl)` — emits the body with `no_branch`, then conditionally emits `emitGotoStatement(...)` based on `bl->gotoPrints()` (suppresses goto when the target is the next block). | **MISSING** — referenced in a comment at printc.rs:540 but not implemented. `emit_goto_statement` (printc.rs:5768) exists with a different signature (addr + goto_type, not `FlowBlock*` + `getGotoTarget()`/`getGotoType()`). | The `gotoPrints()` adjacency check (suppress goto if target is next-in-flow) is not ported → spurious `goto next_label;`. |
| `emitBlockLs` (L2781-L2834, 54 lines) | `void emitBlockLs(const BlockList *bl)` — emits the list of sub-blocks; for non-flat prints it sets `no_branch` on all but the last block and sets `nofallthru` on any sub-block whose successor is not `nextInFlow()`. | **PARTIAL** — closest is `emit_structured_list` (printc.rs:1191), a thin iterator over the list. It does not apply the `no_branch`/`nofallthru` per-subblock mod logic that drives correct goto insertion between non-adjacent list members. | Missing per-subblock fallthru-mod logic → missing `goto` between non-flow-adjacent siblings. |
| `emitBlockCondition` (L2836-L2870, 35 lines) | `void emitBlockCondition(const BlockCondition *bl)` — emits `(A && B)` / `(A || B)` using the `ReversePolish`/`emitOp` machinery for the boolean token; honors `only_branch`/`comma_separate`/`no_branch`. | **PARTIAL** — `emit_block_condition` (printc.rs:3036) + `emit_block_condition_inner` (printc.rs:3317). Emits text `&&`/`||` rather than going through the OpToken stack; does not honor `only_branch`/`comma_separate` mods. | No OpToken-stack emission, mod handling incomplete. |
| `emitBlockIf` (L2878-L2949, 72 lines) | `void emitBlockIf(const BlockIf *bl)` — full `if`/`else if`/`else` with `PendingBrace` (for `option_brace_ifelse`), conditional `else if` merging via `pending_brace`, `emitGotoStatement` when `getGotoTarget()!=0`, `emitCommentBlockTree(condBlock)`. | **PARTIAL** — `emit_structured_if` (printc.rs:812). Emits if/else but no `PendingBrace` deferred-brace logic, no `else if` merge via `cancelPendingPrint`, no conditional goto-target path. | Missing `else if` brace-merge and goto-target branches. |
| `emitForLoop` (L2957-L2999, 43 lines) | `void emitForLoop(const BlockWhileDo *bl)` — emits `for (init; cond; iter) { body }` using `getInitializeOp()`/`getIterateOp()`, `comma_separate` mod, `beginStatement`/`endStatement` markup per slot. | **PARTIAL** — for-loop text is emitted inline inside `emit_structured_whiledo` (printc.rs:1047-1059) when `for_init`/`for_iter` are set, but there is no standalone callable. The inline path uses pre-baked text strings (`while_data.for_init`) rather than re-emitting the init/iterate ops through `emitExpression`. | No standalone method; init/iter rendered from cached strings, not op re-emission → no markup ids, no nested expression formatting. |
| `emitBlockWhileDo` (L3001-L3066, 66 lines) | `void emitBlockWhileDo(const BlockWhileDo *bl)` — dispatches to `emitForLoop` when `getIterateOp()!=0`; otherwise emits `while(cond){body}` OR the overflow form `while(true){ condbody; if(cond) break; }` when `hasOverflowSyntax()`. | **PARTIAL** — `emit_structured_whiledo` (printc.rs:1027) handles both the for-loop and overflow-syntax cases, but the overflow body emits `if (...) break;` textually rather than via `emitGotoStatement(condBlock, 0, f_break_goto)`. | Overflow break uses text, not `emitGotoStatement`. |
| `emitBlockDoWhile` (L3068-L3095, 28 lines) | `void emitBlockDoWhile(const BlockDoWhile *bl)` — `do { body } while(cond);`. | **PARTIAL** — `emit_structured_dowhile` (printc.rs:1111). | Signature divergence; body reuses `emit_block_ops`. |
| `emitBlockInfLoop` (L3097-L3122, 26 lines) | `void emitBlockInfLoop(const BlockInfLoop *bl)` — `do { body } while(true);`. | **PARTIAL** — `emit_structured_infloop` (printc.rs:1157). | Signature divergence. |
| `emitBlockSwitch` (L3313-L3353, 41 lines) | `void emitBlockSwitch(const BlockSwitch *bl)` — emits `switch(cond){ case ...: ... }` calling `emitSwitchCase` per case, with `f_break_goto` for exit cases and `getGotoType(i)` fallthrough handling. | **PARTIAL** — `emit_structured_switch` (printc.rs:1279). | No `emitSwitchCase` separation (P1 partial), no `getGotoType(i)` fallthrough. |

**Subtree status**: 12 `emitBlock*` methods. Of these, **2 are MISSING** (`emitBlockCopy`, `emitBlockGoto`) and **10 are PARTIAL** (`emitBlockBasic`, `emitBlockGraph`, `emitBlockLs`, `emitBlockCondition`, `emitBlockIf`, `emitForLoop`, `emitBlockWhileDo`, `emitBlockDoWhile`, `emitBlockInfLoop`, `emitBlockSwitch`). Additionally `emitSwitchCase` (L3129-L3158) is folded into `emit_structured_switch` and `emitLabel`/`emitLabelStatement`/`emitAnyLabelStatement` (L3164-L3230) are PARTIAL with `FlowBlock*`-vs-`addr` signature divergence.

The common structural divergence is that Rudra's `emit_block_structured` dispatcher takes
`(block_arc: Arc<RwLock<dyn FlowBlock>>, graph: &BlockGraph, emitted: &mut HashSet<usize>)` and
dispatches by `BlockType` enum, whereas Ghidra's `FlowBlock::emit(this)` is a virtual call that
lands in each `emitBlock*` overload. This means none of the per-block mod stacking
(`pushMod`/`setMod(no_branch|only_branch|comma_separate|nofallthru|pending_brace)`), the
`PendingBrace`/brace-indent machinery, or the `beginBlock`/`endBlock` markup ids are reproduced.

### Comment system — L3231-L3311

The Ghidra comment system is built on a `CommentSorter commsorter` member driven by
`setupBlockList` / `setupOpList` / `setupHeader`, and gated by two printer flags
(`instr_comment_type`, `head_comment_type`). **Rudra has no `CommentSorter` equivalent at all**
— comments are never collected, sorted, or emitted anywhere in `printc.rs` (confirmed: grep for
`commsorter`/`CommentSorter`/`comment_sorter` in `src/printc.rs` returns zero hits outside
string literals).

| Ghidra method (line) | Signature / role | Rudra status | Gap |
|---|---|---|---|
| `emitCommentGroup` (L3231-L3241, 11 lines) | `void emitCommentGroup(const PcodeOp *inst)` — drains `commsorter` (set up via `setupOpList`) and emits each non-already-emitted comment whose type passes `instr_comment_type` via `emitLineComment(-1, comm)`. Called per-op in `emitBlockBasic`. | **MISSING** — no callable, no `commsorter`. | All per-op line comments (header/body/tail/warning) dropped. |
| `emitCommentBlockTree` (L3247-L3267, 21 lines) | `void emitCommentBlockTree(const FlowBlock *bl)` — recursively descends the block subtree (collapsing `t_copy`, skipping `t_plain`), calls `commsorter.setupBlockList` + `emitCommentGroup(0)` at each basic block. Used by `emitBlockIf`/`emitForLoop`/`emitBlockWhileDo` to flush comments for statements printed on a shared line. | **PARTIAL — empty stub** — `emit_comment_block_tree` (printc.rs:5766) is `pub fn emit_comment_block_tree(&self, _block: ...) {}` (empty body, `_block` unused). | Stub; no recursion, no `setupBlockList`, no `emitCommentGroup`. |
| `emitCommentFuncHeader` (L3272-L3311, 40 lines) | `void emitCommentFuncHeader(const Funcdata *fd)` — drains `commsorter.setupHeader(header_basic)`, then (if `option_unplaced`) drains `header_unplaced` with a `"Comments that could not be placed..."` banner, then (if `option_nocasts`) emits the `"DISPLAY WARNING: Type casts are NOT being printed"` banner. | **MISSING** — no callable. `doc_function` (printc.rs:3735) does not call any header-comment emitter. | Function header comments, unplaced-comment banner, and nocasts warning all missing. |

**Comment system status**: 3 methods. **2 MISSING** (`emitCommentGroup`, `emitCommentFuncHeader`),
**1 PARTIAL/stub** (`emitCommentBlockTree` empty body). The root cause is the absent
`CommentSorter` infrastructure plus the missing `emitLineComment` lower half (which itself is not
in the `PrintC::` method set audited here but lives in `printlanguage.cc`). The two gating fields
`instr_comment_type` / `head_comment_type` and the `option_unplaced` / `option_nocasts` flags are
also absent in Rudra.

### Global / scope var-decl emission — L2518-L2641

These four methods form the global-symbol-documentation path that Ghidra's `docFunction` calls
into (`docFunction` at L2641 calls `docAllGlobals`; `emitScopeVarDecls` is also reused for
function-local category emission). They are grouped here because they share the
`Symbol`/`Scope`/`MapIterator` traversal that Rudra's `doc_variable_decls_from_funcdata`
(printc.rs:1800) bypasses.

| Ghidra method (line) | Signature / role | Rudra status | Gap |
|---|---|---|---|
| `emitScopeVarDecls` (L2518-L2575, 58 lines) | `bool emitScopeVarDecls(const Scope *symScope, int4 cat)` — iterates category symbols (if `cat>=0`) or the full `MapIterator` + dynamic-entry list, skipping pieces/unnamed/`FunctionSymbol`/`LabSymbol` and de-duping multi-entry symbols via `getFirstWholeMap()`, emitting `emitVarDeclStatement(sym)` for each. Returns whether anything was emitted. | **MISSING** — no callable. `doc_variable_decls_from_funcdata` (printc.rs:1800) walks `fd`'s stack/param varnodes via a different path; it does not iterate a `Scope`/category map. | No `Scope`-map iteration, no category filter, no `FunctionSymbol`/`LabSymbol`/multi-entry de-dup. |
| `emitGlobalVarDeclsRecursive` (L2608-L2619, 12 lines) | `void emitGlobalVarDeclsRecursive(Scope *symScope)` — guards on `isGlobal()`, calls `emitScopeVarDecls(symScope, no_category)`, recurses over all non-function child scopes. | **MISSING** — no callable. | No recursive global-scope walk. |
| `docAllGlobals` (L2621-L2629, 9 lines) | `void docAllGlobals(void)` — wraps a `beginDocument`/`endDocument`/`flush` around `emitGlobalVarDeclsRecursive(glb->symboltab->getGlobalScope())`. | **MISSING** — no callable. | No global-symbol document emission; Rudra's `doc_function` (printc.rs:3735) emits only the current function and never the global table. |
| `docSingleGlobal` (L2631-L2639, 9 lines) | `void docSingleGlobal(const Symbol *sym)` — wraps `beginDocument`/`endDocument` around a single `emitVarDeclStatement(sym)`. | **MISSING** — no callable. | No single-global decl emission. |

**Global/scope status**: all **4 methods MISSING**. They block faithful alignment of
`docFunction` (L2641), whose Ghidra body calls `docAllGlobals` as its first act; Rudra's
`doc_function` (printc.rs:3735) is a from-scratch reimplementation that never emits globals.

### P1 subtotal

- `emitBlock*` subtree: **2 MISSING + 10 PARTIAL** across 12 methods (plus `emitSwitchCase` /
  `emitLabel*` partial).
- Comment system: **2 MISSING + 1 PARTIAL-stub** across 3 methods; the underlying `CommentSorter`
  infrastructure is entirely absent.
- Global/scope decls: **4 MISSING**.

This P1 inventory accounts for **8 MISSING + 11 PARTIAL** of the 54-method gap from the summary
table; the remainder of the gap sits in the P0 (op-dispatch + `push*`/constant family) and P2
(type-stack + char/float formatting + arch wiring) buckets described above.

## Methodology caveats

1. This audit is **name-based**; PARTIAL items may share a name but emit substantially different
   text. A second-pass body audit (per INDEX.md's four-decisive-semantics rubric) is recommended
   for the P0/P1 items before claiming faithful alignment.
2. Rudra helper functions named `emit_*` / `push_*` / `doc_*` that do **not** correspond to a
   Ghidra `PrintC::` method (e.g. `emit_cbranch_condition`, `emit_block_ops`,
   `doc_variable_decls_from_funcdata`, `emit_inline_expr`, `emit_call_arg_text`,
   `emit_block_condition_inner`, `emit_condition`, `emit_type_prefix`, `emit_integer_value`,
   `capture_*`, `mark_variable_used`, `preallocate_register_compact_names`, etc.) are
   **Rudra-original glue** and are not counted as covering Ghidra methods.
3. `push_varnode` (printc.rs:5150) is the Rudra amalgam of `pushVnExplicit` + several `push*`
   helpers; it is marked PARTIAL for each `push*` it partially absorbs rather than counted once.
