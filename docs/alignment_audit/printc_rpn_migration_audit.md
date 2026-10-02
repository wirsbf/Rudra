# printc.cc RPN vs Direct-Emit Migration Audit

**Scope**: Cross-reference every `PrintC::op*` / `emit*` / `doc*` function in
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc` (3401 lines)
against its Rudra counterpart in `src/printc.rs` (9220 lines), with focus on
whether the function uses Ghidra's Reverse-Polish-Notation (RPN) expression
stack (`pushOp` / `pushAtom` / `pushVn` / `recurse`) or emits text directly.

**Audit goal**: Produce a function-by-function table answering three questions:

1. Ghidra side: does the function push onto the RPN stack or emit directly?
2. Rudra side: does the function emit directly (current default) or use RPN?
3. Migration: would migrating the Rudra function to RPN improve fidelity?

## Background: how Ghidra's RPN engine works

Ghidra's `PrintLanguage` (printlanguage.cc) maintains an expression stack
(`std::vector<NodePending> nodepend` + `std::vector<ReversePolish> revpollist`).
The `op*` functions on `PrintC` are *pure producers*: they push `OpToken`s and
`Atom`s onto the stack but never call `emit->*` themselves. The actual text
generation happens later in `PrintLanguage::recurse()` / `emitExpression`
(printc.cc:2493-2494) which calls `op->getOpcode()->push(this, op, 0)` then
`recurse()` — and `recurse()` walks the RPN stack, consulting operator
precedence to decide when to emit parentheses.

Key RPN primitives (printlanguage.cc):

- `pushOp(&token, op)` — push an `OpToken` (e.g. `&binary_plus`, `&assignment`).
- `pushAtom(Atom{...})` — push a leaf token (variable name, constant, keyword).
- `pushVn(vn, op, mods)` — push a varnode; if it is implied, recursively push
  its defining op's `op*` function (the inlining happens here).
- `recurse()` — drain the pending stack and emit text via `emitOp`.

The shared `PrintLanguage::opBinary` / `opUnary` (printlanguage.cc:546-573)
are the canonical RPN producers for two- and one-input operators; per-opcode
`TypeOp*::push` overrides in `typeop_*.cc` mostly delegate to these.

## Rudra's current architecture

`src/printc.rs` does **not** use an RPN stack. Each `op_*` method emits text
directly via `self.emit.print(...)`, `self.emit.tag_op(...)`,
`self.emit.tag_variable(...)`. Implied-varnode inlining is performed inline in
`push_varnode` (printc.rs:5322-5343, depth-guarded at 8 levels) instead of via
an explicit `recurse()` drain. The canonical Ghidra RPN data-types
(`OpToken`, `ReversePolish`, `Atom`, `NodePending`) are ported in
`src/printlanguage.rs` but are *not wired into* `printc.rs`; they exist only
as references for the parenthesization helper `child_needs_parens`
(printlanguage.rs:14-16 documents this explicitly).

Consequently every `op_*` method in Rudra is a **direct-emit** function.
Whether migration to RPN is *beneficial* depends on (a) how much
parenthesization / precedence logic the function needs and (b) how cleanly its
Ghidra counterpart maps onto the RPN primitives.

---

## Per-function table

Format: `Ghidra line` — `Ghidra impl` | `Rudra line` — `Rudra impl` | Migrate?

### opCopy (printc.cc:481)

| | Location | Implementation |
|---|---|---|
| **Ghidra** | printc.cc:481-485 | **RPN**: `pushVn(op->getIn(0), op, mods)` — single leaf push, no `emit->*` calls. |
| **Rudra** | printc.rs:5272-5282 | **Direct emit**: emits `out = ` then `push_varnode(in0)`; *adds* an LHS-assignment wrapper Ghidra omits (Ghidra emits the assignment in `emitExpression`, not in `opCopy`). |
| **Migrate?** | **No** | One-push function — RPN would add zero value. **However**, the LHS-assignment emit (`out = `) here is a divergence from Ghidra's model where `op->getOpcode()->push(this, op)` is wrapped by `emitExpression`'s `pushOp(&assignment)`. See `emitExpression` note below. |

### opLoad (printc.cc:487)

| | Location | Implementation |
|---|---|---|
| **Ghidra** | printc.cc:487-498 | **RPN**: `pushOp(&dereference, op)` (or sets `print_load_value` mod), then `pushVn(op->getIn(1), op, m)`. |
| **Rudra** | printc.rs:5285-5311 | **Direct emit**: `emit.print("*(long *)")` / `emit.print("*(type )")` then `push_input(op, 1)`, wrapped in a `out = ` LHS emit Ghidra does not perform here. Also **adds** a typed-deref branch (when `in(1)` has a pointer type) and a synthetic `*(long *)` cast that Ghidra never emits. |
| **Migrate?** | **Yes (medium priority)** | The `dereference` OpToken + `pushVn` form would let the precedence machinery parenthesize the deref against the surrounding expression (e.g. `*a + b` vs `*(a + b)`). Rudra's hardcoded `*(long *)` cast is an output-legalizing hack that would be unnecessary if Rudra modelled the pointer type on `in(1)` properly. **Blocker**: Rudra also lacks `checkArrayDeref` (printc.cc:353) which is what selects between `*` and `[i]` form — without that, RPN migration alone would not close the gap. |

### opStore (printc.cc:500)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:500-518 | **RPN**: `pushOp(&assignment, op)`, `pushOp(&dereference, op)`, then `pushVn(in2)` and `pushVn(in1, m)` in reverse for RPN efficiency. Assumes the STORE is being emitted as a statement. |
| **Rudra** | printc.rs:5311-5481 | **Direct emit**: ~170 lines of address-computation inlining (RIP-relative, stack-variable, struct-field detection, capture_varnode_text bare-ident heuristics), all via `emit.print`. The final fallback is `emit.print("*(long *)")` + `push_input(op, 1)` + `emit.tag_op(" = ")` + `push_input(op, 2)`. |
| **Migrate?** | **No (architectural divergence)** | The RPN form (`assignment` + `dereference` + two `pushVn`) is 4 lines; Rudra's 170-line inliner cannot map onto it because Rudra is doing all the address-resolution work that Ghidra performs *upstream* in p-code analyses (`RuleSubnormalStore`, `ActionRestructureVarnode`, type propagation). To migrate faithfully, the address-inlining would have to move out of `op_store` entirely (becoming a pre-pass) and `op_store` reduced to the 4-line RPN form. That is a major refactor, not a mechanical port. **Lower-effort path**: keep direct-emit but model `assignment` + `dereference` OpTokens for parenthesization. |

### opCall (printc.cc:610)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:593-635 | **RPN**: `pushOp(&function_call, op)`; then either `pushAtom(Atom{name, functoken, ...})` for a named callee, or — if the call-point is an `IPTR_FSPEC` const — pulls the `FuncCallSpecs`. For args: pushes `comma` operators between, then `pushVn(op->getIn(i), ...)` in *reverse* order. Falls back to `pushAtom(EMPTY_STRING, blanktoken)` for void. |
| **Rudra** | printc.rs:5606-5655 | **Direct emit**: emits `out = ` (if output), resolves target via `symbol_table` / `FUN_<addr>` / null-pointer sentinel, then `emit.open_paren()`, loops `in[1..]` calling `emit_call_arg_text(op, i)` and joining with `", "`, `emit.close_paren()`. |
| **Migrate?** | **Partial (low priority)** | The `function_call` + `comma` OpTokens in RPN enable consistent spacing/parenthesization and would let Rudra drop the manual `open_paren`/`close_paren` bookkeeping. However, Rudra's lack of `FuncCallSpecs` (it synthesizes `FUN_<addr>` from the const target) is the larger fidelity gap; RPN migration would not fix the callee-resolution path. **Recommend**: leave as direct-emit; capture `function_call` OpToken spacing constants from printlanguage for the parens. |

### opCallind (printc.cc:637)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:637-671 | **RPN**: `pushOp(&function_call, op)`; `pushOp(&dereference, op)`; then three-way dispatch (count>1, ==1, ==0) pushing `comma`/`pushVn` in reverse order, with `getHiddenThisSlot` skipping the C++ `this`. |
| **Rudra** | printc.rs:6334-6376 | **Direct emit**: emits `out = ` (if output); then `emit.print("(*")` + `push_varnode(in0)` + `emit.print(")(")` + comma-joined args + `emit.print(")")`. `get_hidden_this_slot` returns -1 (not ported), matching Ghidra's own `opCall` TODO at printc.cc:619-620. |
| **Migrate?** | **Partial (low priority)** | The doc-comment (printc.rs:6326-6332) explicitly notes that Ghidra's `function_call` + `dereference` OpTokens render textually as `(*callable)(args)` — Rudra already produces this exact text via direct emit. RPN migration would be cosmetic. |

### opReturn (printc.cc:754 → audit's "690" is the `EMPTY_STRING` line)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:754-784 | **Mixed**: the common case `emit->tagOp(KEYWORD_return, ...)` + `pushVn(op->getIn(1), op, mods)` is **direct emit** (the source even carries a `// FIXME: This routine shouldn't emit directly` comment at line 760). The halt-variant cases (`halt`, `halt_baddata`, ...) use RPN: `pushOp(&function_call, op)` + two `pushAtom`s. |
| **Rudra** | printc.rs:5659-5716 | **Direct emit**: `emit.print("return")` + (if `num_input() > 1`) `emit.print(" ")` + `push_varnode(in1)`. When no return-value input, scans the parent block backwards for a write to RAX/EAX (offset 0x0) and emits that expression — this is a Rudra-specific heuristic (Ghidra would never reach `opReturn` without `in(1)` because RETURN ops always carry the return value). The halt variants are not implemented. |
| **Migrate?** | **No** | Ghidra itself acknowledges this routine "shouldn't emit directly" but does anyway because `return` is a statement-level keyword, not an operator. Rudra's direct emit is faithful to the common case. The halt variants are a separate porting task (P2). |

### opBranch / opCbranch (printc.cc:520 / 536)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:520-580 | **Mixed / direct emit**. `opBranch` (flat mode only): `emit->tagOp(KEYWORD_goto, ...)` + `pushVn(in0)` — direct emit. `opCbranch`: direct `emit->tagOp(KEYWORD_IF, ...)` and `emit->openParen(...)`/`closeParen(...)`, but uses RPN for the condition: `pushOp(&boolean_not, op)` (if booleanflipped) + `pushVn(in1, m)` + `recurse()`. The closing `emit->print(KEYWORD_GOTO)` + `pushVn(in0)` after the paren is direct emit. |
| **Rudra** | printc.rs:5718-5791 | **Direct emit**: dispatches on `op.branch_type` (BREAK / CONTINUE / GOTO), prints `if (...) break` / `continue` / `goto <label>` directly. The condition is emitted via `emit_cbranch_condition` which captures the output of `emit_condition` into a buffer and falls back to `1` if invalid. |
| **Migrate?** | **No** | Both sides are predominantly direct-emit for the keyword/label parts. The RPN piece (boolean_not + condition) is small; Rudra's `emit_condition` already handles the negation explicitly via `negatetoken`-equivalent logic. Branching is statement-level, where RPN's precedence machinery is irrelevant. |

### opBinary (printlanguage.cc:546)

| | | |
|---|---|---|
| **Ghidra** | printlanguage.cc:546-560 | **RPN (canonical)**: handles `negatetoken` (flips the token via `tok->negate`), then `pushOp(tok, op)` + `pushVn(in1, mods)` + `pushVn(in0, mods)` (reverse for RPN). Invoked by most `TypeOpBinary::push` overrides in `typeop_*.cc`. |
| **Rudra** | printc.rs:5482-5546 | **Direct emit**: emits `out = ` (LHS wrapper Ghidra does not add here — Ghidra adds the assignment in `emitExpression`), then `push_input_parenthesized(op, opcode, 0)` + a hardcoded per-opcode `match` table of operator strings + `push_input_parenthesized(op, opcode, 1)`. Has extra pre-branches (RIP-relative fold, stack-variable fold, boolean-comparison fold) that Ghidra performs in earlier p-code passes. |
| **Migrate?** | **Yes (HIGH priority — best candidate)** | This is the canonical RPN use site. Ghidra's `pushOp(tok)` lets the precedence walker emit parentheses only when the child operator binds looser; Rudra's `push_input_parenthesized` is a per-call heuristic that approximates this. Migrating `op_binary` to push onto a (newly-introduced) RPN stack and then calling a shared `recurse()` would: (1) eliminate the divergent LHS-assignment emit; (2) get Ghidra-exact parenthesization for nested binary expressions (a known source of `(a) + (b)` noise and missing-paren bugs); (3) let `negatetoken` flip operators the way Ghidra does (e.g. `<` → `>=`) instead of via Rudra's separate `try_fold_bool_comparison`. **Blocker**: requires the full RPN-stack + `recurse` infrastructure in printc.rs (see "Infrastructure prerequisite" below). |

### opUnary (printlanguage.cc:566)

| | | |
|---|---|---|
| **Ghidra** | printlanguage.cc:566-573 | **RPN (canonical)**: `pushOp(tok, op)` + `pushVn(in0, mods)`. |
| **Rudra** | printc.rs:5549-5589 | **Direct emit**: emits `out = ` + a per-opcode `match` of prefix operator strings + `push_input(op, 0)`. Has special-case branches for `INT_ZEXT`/`INT_SEXT` that look up the output type for a typed cast. |
| **Migrate?** | **Yes (medium priority)** | Same precedence argument as `op_binary` (though unary precedence is simpler). The bigger win is unifying the ZEXT/SEXT cast rendering with Ghidra's `opIntZext`/`opIntSext` (printc.cc:786-810) which dispatch to `opTypeCast` / `opHiddenFunc` / `opFunc` rather than the unary-token path. **Blocker**: same RPN infrastructure. |

### opPtrsub (printc.cc:929)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:929-1143 | **RPN (heavily)**: 200+ lines selecting between `addressof`, `object_member`, `pointer_member`, `subscript`, `dereference`, `typecast` OpTokens and pushing them via `pushOp`. Pushes field-name `Atom`s via `pushAtom(Atom{fieldname, fieldtoken, ...})`. Falls back to `pushPartialSymbol`, `pushSymbol`, `pushUnnamedLocation`. |
| **Rudra** | printc.rs:6877-7007 | **Direct emit**: ~130 lines. Dispatches on `ct.get_metatype()` (Struct/Union, Array, Spacebase) and prints `&in0->field`, `in0->field`, `in0[0]`, `*in0`, `in0->field_0x<hex>` directly. Uses `find_partial_field` for named-field lookup with a `field_0x<hex>` fallback. |
| **Migrate?** | **Yes (medium priority)** | The struct/array/spacebase metatype dispatch is identical in spirit; the difference is purely RPN-push vs direct-print. The precedence issue matters most here: `&in0->field` vs `&(in0->field)` vs `(&in0)->field` are semantically distinct and Rudra's direct emit currently hardcodes the form. Migrating to push `addressof` / `pointer_member` / `object_member` OpTokens and letting `recurse` parenthesize would handle nested cases (`&p->a->b`) correctly. **Blocker**: same RPN infrastructure; also requires porting `TypePointerRel` (printc.cc:947-954) and the spacebase symbol-resolution path (`pushUnnamedLocation`, `pushPartialSymbol`). |

### opSubpiece (printc.cc:843 → audit's "860" is the `field` lookup line)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:843-878 | **RPN + delegation**: special-printing branch (piece-structured composite) pushes `pushPartialSymbol` or `pushOp(&object_member)` + `pushVn` + `pushAtom(fieldtoken)`. Otherwise delegates to `opTypeCast` (cast form) or `opFunc` (functional form). |
| **Rudra** | printc.rs:9138-9189 | **Direct emit + delegation**: special-printing branch is a stub (no `findTruncation` port — comment at line 9164 acknowledges this). Falls through to `op_type_cast` (cast form) or `op_binary` (functional form). |
| **Migrate?** | **No (low value until upstream ports land)** | The delegation pattern (cast / func) is already preserved. The special-printing branch needs `Datatype::findTruncation` and `TypeOpSubpiece::computeByteOffsetForComposite` ported before any RPN-vs-direct distinction matters — until then both sides collapse to the same `op_type_cast`/`op_binary` call. |

### emitExpression (printc.cc:2468)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:2468-2495 | **RPN drain**: if the op has an output and `option_inplace_ops` applies, calls `emitInplaceOp` (which itself pushes onto RPN + `recurse()`s). Otherwise, if `doesSpecialPrinting()` (constructor case), pushes `assignment` + `pushSymbolDetail` + `opConstructor(true)` + `recurse()` and returns. **Generic case**: `op->getOpcode()->push(this, op, 0); recurse();` — the opcode's `push` populates the RPN stack and `recurse()` drains it to text. **Crucially**, the LHS-assignment wrapper (`pushOp(&assignment, op); pushSymbolDetail(outvn, op, false)`) lives *here*, in `emitExpression`, not in each per-opcode function. |
| **Rudra** | printc.rs:5740-5754 | **Direct dispatch**: `if op.get_out() && option_inplace_ops && emit_inplace_op(op) { return }`. (Constructor special-printing branch not ported — comment at line 5746.) Then `op.push(self)` — which dispatches to the per-opcode `op_*` method that emits text directly. |
| **Migrate?** | **Yes (HIGH priority — structural change)** | This is the *root* of the LHS-assignment divergence. Every Rudra `op_*` function begins with `if let Some(out) = op.get_out() { emit out =; }` because the assignment wrapping was inlined into each opcode handler instead of centralized in `emitExpression`. Migrating to Ghidra's model — `emitExpression` pushes `assignment` + LHS, then dispatches to `op_*` which only emits the RHS — would delete ~30 duplicated `out = ` blocks across Rudra and align with Ghidra's structure. This is the single highest-leverage refactor. **Couples to**: full RPN-stack adoption (otherwise the centralized `assignment` push has nowhere to go). |

### emitStatement (printc.cc:2285)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:2285-2293 | **Direct emit (statement framing)**: `emit->beginStatement(inst)` → `emitExpression(inst)` → `emit->endStatement(id)` → optional `emit->print(SEMICOLON)`. The expression itself is RPN-backed via `emitExpression`. |
| **Rudra** | printc.rs:5777-5788 (`emit_statement`) and 5261-5267 (`doc_statement`) | **Direct emit**: `emit.begin_statement()` → `emit_expression(op)` → `emit.end_statement()` → optional `emit.print(";")`. `doc_statement` (the actually-used path) prepends `emit.tag_line(0)`. |
| **Migrate?** | **No** | Statement framing is correctly faithful. The RPN question lives one level down in `emitExpression` (see above). |

### emitBlockBasic (printc.cc:2678)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:2678-2744 | **Driver (calls `emitStatement` per op)**: iterates the block's op list, skips `notPrinted()` / branch / implied-output ops, calls `emitCommentGroup` + `emit->tagLine()` + `emitStatement(inst)`. Adds a synthetic `goto` for flat prints with no fallthru. |
| **Rudra** | printc.rs:548-747 (`emit_block_ops`) | **Driver (calls `doc_statement` per op)**: equivalent iteration. Adds Rudra-specific skips: COPY (folded via `copy_map`), RIP-relative INT_ADD, INT_SUB(RSP) stack-frame setup, dead-output pure-computation ops, ops after RETURN, ops already in `inlined_ops`. Branch handling (`CPUI_BRANCH` always skipped; CBRANCH/BRANCHIND skipped when `skip_terminal`) is faithful to Ghidra's `no_branch`/`only_branch` mod system. |
| **Migrate?** | **No** | The driver does not itself use RPN; it delegates to `emitStatement`/`doc_statement`. The extra Rudra skips are upstream-analysis gaps (COPY folding, dead-code elimination, RIP-relative resolution) that Ghidra performs in earlier actions — they belong in those actions, not in the block emitter. |

### docFunction (printc.cc:2641)

| | | |
|---|---|---|
| **Ghidra** | printc.cc:2641-2676 | **Driver**: `emit->beginFunction(fd)` → `emitCommentFuncHeader` → `emitFunctionDeclaration` → `emit->openBraceIndent` → `emitLocalVarDecls` → `emitBlockGraph(structure or basic blocks)` → `popScope` → `closeBraceIndent` → `endFunction` → `flush`. The RPN stack is asserted empty at entry/exit (`#ifdef CPUI_DEBUG`). |
| **Rudra** | printc.rs:3788-4700+ (multi-pass: discovery + emit) | **Driver**: caches `cpool`/`userops`, builds `symbol_table`/`string_table`/`scope`/`param_names`/`call_targets`/`pointer_varnodes`, then runs a two-pass emit (discovery pass to populate `used_varnode_names`/`global_used_outputs`, then real emit via `emit_block_structured`). |
| **Migrate?** | **No** | Driver function; the RPN question is internal to the `op_*` helpers it eventually invokes. The discovery-pass split is a Rudra-specific output-quality measure (Ghidra achieves similar effects via `ActionMarkImplied` + `ActionDeadCode`). |

---

## Summary

### Functions that genuinely need RPN migration (ranked by leverage)

| Priority | Function | Ghidra line | Rudra line | Reason |
|---|---|---|---|---|
| **P0** | `emitExpression` | 2468 | 5740 | Centralize the LHS-assignment wrapping; remove ~30 duplicated `out = ` blocks. Structural root of the direct-emit divergence. |
| **P0** | `opBinary` (via `op_binary`) | printlanguage.cc:546 | 5482 | Canonical RPN site; migrating fixes per-operator parenthesization bugs and unifies `negatetoken` handling. |
| **P1** | `opUnary` (via `op_unary`) | printlanguage.cc:566 | 5549 | Smaller win than `op_binary` but same precedence argument; unifies ZEXT/SEXT with `opIntZext`/`opIntSext`. |
| **P1** | `opPtrsub` | 929 | 6877 | `&`/`->`/`.`/`[]` precedence-sensitive; Rudra currently hardcodes one form per metatype. |
| **P2** | `opLoad` | 487 | 5285 | `dereference` OpToken would let the precedence walker handle `*a + b`. Blocked by missing `checkArrayDeref`. |
| **P2** | `opStore` | 500 | 5311 | Same `assignment`+`dereference` argument, but Rudra's address-inlining is the bigger issue. |
| **P3** | `opCall` / `opCallind` | 610 / 637 | 5606 / 6334 | `function_call` + `comma` OpTokens would replace manual paren bookkeeping; mostly cosmetic. |

### Functions that should NOT be migrated

| Function | Reason |
|---|---|
| `opCopy` | Single-push; no precedence concerns. |
| `opReturn` | Statement-level keyword; Ghidra itself direct-emits (`// FIXME shouldn't emit directly`). |
| `opBranch` / `opCbranch` | Statement-level keywords; both sides direct-emit the framing. |
| `opSubpiece` | Already delegates to `opTypeCast` / `opFunc`; special-printing branch needs upstream type-system ports first. |
| `emitStatement` | Faithful statement framing. |
| `emitBlockBasic` (`emit_block_ops`) | Driver; delegates per-op emission. |
| `docFunction` | Driver; delegates to block / expression emitters. |

### Infrastructure prerequisite

Migrating **any** of the P0/P1/P2 functions requires introducing a real RPN
expression stack in `printc.rs`. The pieces already exist in
`src/printlanguage.rs` (`OpToken`, `ReversePolish`, `Atom`, `NodePending`) but
are not wired up. A minimum-viable migration would need:

1. A `revpollist: Vec<ReversePolish>` field on `PrintC` (mirroring
   `PrintLanguage::revpollist`).
2. A `nodepend: Vec<NodePending>` field mirroring `PrintLanguage::nodepend`.
3. Working `push_op`, `push_atom`, `push_vn` methods that populate those
   vectors (the current `printlanguage.rs` has free-function versions taking
   `&mut Vec<ReversePolish>` — they would need to become methods on `PrintC`).
4. A `recurse(&mut self)` method that drains `nodepend`, invokes each pending
   op's `op_*` to push its tokens, then emits text from `revpollist` using the
   precedence/parenthesization algorithm (which `printlanguage.rs` already
   ports as `parentheses()`).

Without step 4, the RPN tokens have nowhere to render. The current direct-emit
path can be kept as a fallback during incremental migration.

### Recommendation

The migration is **not** a mechanical 1:1 port — Rudra's `op_*` methods have
absorbed work that Ghidra performs in upstream p-code analyses (COPY folding,
RIP-relative resolution, dead-code elimination, type-driven cast rendering).
A full RPN migration would require either (a) moving that work out of `op_*`
into pre-pass actions, or (b) running the RPN stack in parallel with the
direct-emit heuristics.

**Highest-value, lowest-risk first step**: implement the RPN stack + `recurse`
and migrate **only** `op_binary` (plus the `emitExpression` LHS-wrap
centralization). This addresses the most common parenthesization bugs without
touching the statement-level or address-resolution paths. Defer `op_ptrsub`,
`op_load`, `op_store` until the upstream type-system and analysis ports
(`checkArrayDeref`, `TypePointerRel`, `findTruncation`) are in place.
