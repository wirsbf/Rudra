# unionresolve.rs — Union resolution API

Rust implementation corresponding to Ghidra's `unionresolve.hh` /
`unionresolve.cc` (1110 lines).

**Status:** The authoritative roadmap currently records this module as L2.
The typed implementation uses
`Arc<Datatype>` / `Arc<RwLock<PcodeOp>>` / `Arc<RwLock<Varnode>>` threading
in place of Ghidra's raw `Datatype*` / `PcodeOp*` / `Varnode*` API, but the
documented RUDRA-GLUE gaps and absence of a locked-oracle `MATCH` fixture
preclude an L3 claim.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/unionresolve.{hh,cc}`.

## Structs

### `ResolvedUnion`
A data-type resolved from a TypeUnion/TypeStruct (unionresolve.hh:39).
Holds `Arc<Datatype>` for `resolve` and `base_type`.
- `new(parent: Arc<Datatype>)` — resolves to itself (cc:25).
- `with_field(parent, fld_num, typegrp: &mut TypeFactory)` — specific field
  (cc:40); the pointer-parent arm interns via `TypeFactory::get_type_pointer`
  (type.cc:3867), callers hold a factory write guard.
- `new_self(parent_name)`, `new_field(parent_name, field_name, fld_num)` —
  RUDRA-GLUE string ctors for legacy callers.
- `get_datatype()`, `get_base()`, `get_field_num()`, `is_locked()`,
  `set_lock(val)`.

### `ResolveEdge`
A data-flow edge for resolved types (unionresolve.hh:60).
- `new(parent: &Datatype, op: &PcodeOp, slot)` — typed ctor (cc:64).
  Pointer encoding `+0x1000` (cc:71).
- `from_components(type_id, op_time, slot, is_pointer)` — RUDRA-GLUE.
- Implements `Ord` exactly as `ResolveEdge::operator<`, keying by
  `(type_id, encoding, immutable op_time)`; block-order renumbering cannot
  invalidate an edge key.

### `DirType`
- `FitDown`, `FitUp` (unionresolve.hh:87).

### `Trial`
Trial data-type fitted to a data-flow position (unionresolve.hh:84).
Holds `Arc<RwLock<Varnode>>` and optional `Arc<RwLock<PcodeOp>>`.
- `new_down(op, slot, ct, index, is_array)` (hh:106).
- `new_up(vn, ct, index, is_array)` (hh:115).

### `VisitMark`
Visit tracking for Varnode+field (unionresolve.hh:120).
- `new(vn: &Arc<RwLock<Varnode>>, index)`, `from_id(vn_id, index)`.
- Derives `Ord` by `(vn_key, index)` (hh:130).

### `ScoreUnionFields<'t>`
Scores union fields for a specific access (unionresolve.hh:82).
Constructors (all run the scoring loop internally):
- `new(typegrp, parent_type, op, slot)` — primary edge ctor (cc:990).
- `new_for_subpiece(typegrp, union_type, offset, op)` — SUBPIECE (cc:1050).
- `new_for_implied_trunc(typegrp, union_type, offset, op, slot)` (cc:1083).
- `with_field_names(parent_name, field_names)` — RUDRA-GLUE for tests.
- `get_result() -> &ResolvedUnion`, `num_fields()`, `add_score(index, score)`.
- `compute_best_index()` — pick highest-scoring field (cc:945).
- `run_on_func(fd)` — legacy Funcdata-scanning entry.

## Scoring methods (private, 1:1 with Ghidra)
- `test_array_arithmetic(op, in_slot, base_size)` (cc:88).
- `score_simple_cases_inner(op, in_slot, parent)` (cc:119).
- `score_locked_type(ct, lock_type)` (cc:144).
- `score_parameter(ct, fd, call_op, param_slot)` (cc:184).
- `score_return_type(ct, fd, call_op)` (cc:204).
- `deref_pointer(ct, vn_size)` (cc:227). 2026-09-22 起 chain 返回
  `(Option<Arc<Datatype>>, i32)`：种子取 pointer 的 canonical `ptr_to` Arc，
  下钻经 `Datatype::get_sub_type` 虚分派拿 canonical component Arc（不再
  `Arc::new(rt.clone())` 深拷贝，与 Ghidra 返回 factory-owned `Datatype*` 一致）。
- `new_trials_down(vn, ct, score_index, is_array)` (cc:253).
- `new_trials(op, slot, ct, score_index, is_array)` (cc:276).
- `score_trial_down(trial, last_level)` — ~50 opcodes (cc:305-640).
- `score_trial_up(trial, last_level)` — ~40 opcodes (cc:642-833).
- `score_truncation(ct_in, vn_size, offset, score_index)` (cc:843). 参数为
  `&Arc<Datatype>`、返回 `Option<Arc<Datatype>>`（canonical component，
  2026-09-22 随 `get_sub_type` 签名变更）。
- `score_constant_fit(trial)` (cc:884).
- `run_one_level(last_pass)` (cc:931).
- `run_passes()` — multi-pass loop (cc:963).

## Free helpers (RUDRA-GLUE)
- `num_depend(dt)`, `get_depend(dt, i)`, `depend_at(dt, i)` — Datatype virtual
  dispatch aggregator.
- `pointee_of`, `pointer_pointee`, `as_union`, `strip_pointer_layer`,
  `pointee_word_size`, `union_field_list`, `type_pointer_strip_array`.
- `bit_transition_count(val, size)` — address.cc port.
- `test_simple_cases`, `score_truncation_inplace` — free-function forms used
  before `self` exists.

## Constants (unionresolve.cc:79-81)
- `THRESHOLD = 256`, `MAX_PASSES = 6`, `MAX_TRIALS = 1024`.

## RUDRA-GLUE gaps
- `scoreParameter` / `scoreReturnType` need Funcdata handle via
  `op->getParent()->getFuncdata()`; typed ctor lacks it, uses unlocked fallback.
- `TypePointer::downChain` not ported; INT_ADD constant-offset path approximated.
- `TypeOpSubpiece::computeByteOffsetForComposite` not ported; uses constant offset.
- `AddrSpace::getPointerLowerBound/UpperBound` not ported; bit-transition test only.
- `FloatFormat::for_size` not ported; uses `FloatFormat::new(size)`.
- `TypeFactory::getTypePointerStripArray` not ported; array-element fallback.

## 2026-06-27: ScoreUnionFields::run_on_func Funcdata integration
- **run_on_func(fd)**: scans Funcdata PcodeOps for union field access patterns
  (SUBPIECE extraction + INT_AND mask), scores matching fields, then calls
  compute_best_index.

## 2026-07-22: Historical scoring implementation pass
- Implemented scoring methods corresponding to unionresolve.cc:88-926 with typed API.
- Fixed constants: THRESHOLD 10→256, MAX_PASSES 5→6, MAX_TRIALS 50→1024.
- Fixed pointer encoding: +0x10000 → +0x1000 (cc:71).
- 18 tests covering scoring semantics and typed API.

## 2026-08-11 ANN-I annotation bootstrap

The six previously unannotated helpers are now explicitly classified as
RUDRA-GLUE. `VisitMark::{eq,partial_cmp}` satisfy Rust trait requirements around
the canonical `Ord::cmp` mapping to unionresolve.hh:130; the four pointer/union
helpers replace repeated C++ casts and raw-pointer borrows with Rust enum
downcasts or `Arc` ownership. No behavior changed and no status was promoted.

<!-- annotation-pass: 2026-08-11 ANN-I; provenance-only -->

## 2026-08-24: CALLSPEC-IDENTITY-D0 scoring lookup

- `score_parameter` and `score_return_type` now receive a `PcodeOpRef` and
  resolve the call site through `Funcdata::get_call_specs_of_op`. The returned
  stable owner is read under a short `RwLock` guard before the locked parameter
  or return type is scored.
- The former `fc.op_addr == call_op.get_addr()` scan is gone. Two distinct call
  ops at the same machine address cannot share a prototype, and a raw constant
  with a matching numeric offset cannot impersonate a typed FSPEC annotation;
  an already-bound op can still resolve through the oracle's exact-op fallback.
- This is only the D0 identity/guard adaptation. The module remains L2 and the
  overall verdict remains `MISMATCH`: Rugra still uses `AddressSpace::Iop`
  instead of dedicated `IPTR_FSPEC` (`TYPEOP-FSPEC-SPACE-0001`), does not wire
  the TypeOp getter/PrintC/StringManager path in this phase, and retains the
  other scoring gaps listed above.

## 2026-09-23: pipeline wiring — resolveInFlow/findResolve dispatch + fd-aware read-facing twins (UNIONRESOLVE-PIPELINE-WIRING-0001 / lane EN2)

**2026-09-26（UNIONRESOLVE-PKG-A-0001 / lane PKGA）**: the Array/Struct arm's
`TypeStruct::score_single_component` call site now passes `(fd, op, slot)`
directly — the helper's signature changed from a `&PcodeOp` view to
`(parent, fd, op_ref, slot)` so its LOAD/STORE pointer arm (type.cc:1908
`vn->getTypeReadFacing(op)`) consults the resolution map through
`vn_type_read_facing` (slot-1 key) instead of the degenerate map-miss form.
No scorer/dispatch logic in this file changed otherwise.

The module now HAS its pipeline producers. New public free functions
(threading `fd` in place of Ghidra's virtual `Datatype` dispatch, since
Rugra's `Datatype` enum has no Funcdata back-pointer):

- `resolve_in_flow(fd, ct, op, slot)` — `Datatype::resolveInFlow` virtual
  mirror (type.cc:574 base / 1177 pointer-to-union / 1283 array / 1929
  struct / 2125 union / 2498 partial-union): consult `fd.union_map`, on
  miss score via `ScoreUnionFields` (union arms) or
  `TypeStruct::score_single_component` (array/struct arms) and write the
  edge; partial-union walks the container via `union_resolve_truncation`
  / `get_sub_type` with NO map write. Callers gate on `needs_resolution`
  exactly as the oracle call sites do.
- `union_resolve_truncation(fd, union, offset, op, slot)` —
  `TypeUnion::resolveTruncation` (type.cc:2147-2177): cached-hit
  fieldNum>=0 return (field, offset-field.offset); miss scores via the
  SUBPIECE slot-1 constructor (cc:2160, newoff=0) or implied-truncation
  constructor (cc:2168, newoff=offset-field.offset).
- `find_resolve(fd, ct, op, slot)` — const `Datatype::findResolve` mirror
  (type.cc:586/1192/1298/1944/2137/2517): consult-only, no scoring;
  array→element / struct→field[0] fallbacks per oracle.
- `find_compatible_resolve(ct, other)` — `findCompatibleResolve` mirror
  (type.cc:596/1308/1954/2201/2536) for
  `ActionSetCasts::tryResolutionAdjustment`: pointer-identity at offset 0
  (non-resolution other) / size-gated mutual recursion (resolution other).
- `get_depend(dt, i)` made `pub` (coreaction.cc:2441 consumer).
- Read-facing twins of varnode.cc:626-672 (varnode.rs stays degenerate
  under the EJ2 write-domain lease; handover registered in the wiring
  commit): `vn_type_read_facing` / `vn_type_def_facing` /
  `vn_high_type_read_facing` / `vn_high_type_def_facing` — `find_resolve`
  when the instance/high type needs resolution.

Producers wired in coreaction.rs (cc:2499/2556/5083 + tryResolutionAdjustment
cc:2424 + insertPtrsubZero cc:2630 + CAST bookkeeping cc:2713-2717) and
ruleaction.rs (cc:7675/7678 PIECE leaf COPY); `get_union_field`/
`set_union_field`/`force_facing_type`/`inherit_resolution` consumers were
already in place (funcdata.rs:917-1005 mirror).

Observable: curl main ② line now `(char **)` (== golden 746), curl E2E
2589/0/0 (-4 vs parent), httpd 2335/0/0 byte-identical, three projections
(next_url/match_url/parseconfig) MATCH.

## 2026-09-23: union drill-down fidelity pass (lane wt/unionres, DZ)

Dead-code scorer brought 1:1 with unionresolve.cc ahead of the pipeline
wiring (UNIONRESOLVE-PIPELINE-WIRING-0001). The module has NO pipeline
producer yet — `ScoreUnionFields` is never constructed outside its own
tests, and `Funcdata::union_map` has no writer — so every change below is
pipeline-invisible by construction (curl/httpd E2E byte-identical,
2585/2333 skeleton, 0/0).

Faithfulness fixes, each keyed to the oracle line:

- `ResolveEdge::new` gained the TYPE_PARTIALUNION key arm
  (unionresolve.cc:73-74): a partial union keys by its container union id,
  without the +0x1000 pointer encoding bump. Handed over by
  TYPEUNION-CACHE-READSIDE-0001 observation (a).
- `ResolvedUnion::with_field` now mirrors unionresolve.cc:40-59 in full:
  the cc:43-44 partial-union parent unwrap (baseType is the container),
  and the cc:51-55 pointer-parent arm resolving to a POINTER to the field
  (`ptrTo->getDepend(fldNum)` wrapped by `getTypePointer(parent.size,
  field, wordSize)`). The pointer is constructed structurally because the
  signature receives `&TypeFactory` (funcdata.rs holds a read guard);
  canonical interning lands with the wiring.
- `ScoreUnionFields.typegrp` is now `Arc<RwLock<TypeFactory>>` — the
  mutable twin of Ghidra's `TypeFactory&` — because the scoring interning
  arms mutate the factory (getTypePointerStripArray cc:1022, downChain
  cc:435, getTypePointer cc:665). `get_type_pointer_strip_array` is a real
  port of TypeFactory::getTypePointerStripArray (type.cc:3849-3859):
  strip the formal stripped twin, strip one array level, intern the
  pointer. The old approximation returned the bare stripped pointee (not a
  pointer), which also broke the constructor's field-size gate for
  pointer-parent trials.
- `ScoreUnionFields` carries `fd: Option<&Funcdata>`; the CALL/CALLOTHER/
  CALLIND arms of both scoring directions now consult
  `score_parameter`/`score_return_type` (locked call-specs) exactly as
  cc:184/cc:204 do, falling back to the unlocked heuristic when `fd` is
  absent (Ghidra derives fd from `op->getParent()->getFuncdata()`;
  Rugra PcodeOps have no back-pointer).
- `score_trial_down` INT_ADD/INT_SUB/PTRSUB pointer+const arm drills via
  the virtual `TypePointer::downChain(off, par, parOff, array)`
  (type.cc:1084) through `TypeFactory::down_chain_virtual`, with the +5
  score granted only on drill success (cc:429-438). The old code invented
  an `off == 0 -> resType = fitType` shortcut and always scored +5.
- `score_trial_up` LOAD arm wraps the trial type in an interned pointer
  sized by the pointer input with wordsize 1 and recurses on slot 1
  (cc:664-666). The old code recursed the bare fit type on slot 0.
- `test_simple_cases_inner` compares array-arithmetic constants against
  the pointer-stripped union size (`result.baseType->getSize()`), not the
  pointer size (cc:94/101/108 via the cc:993 ctor).
- `score_locked_type` lost an invented in-loop identity re-check; the
  +5 identity bonus is once, before the pointer peel (cc:149-150).
- `score_truncation`/`score_truncation_inplace` compare the +5 bonus by
  `result.getBase() == unionDt` Arc identity (cc:856-857), replacing a
  field-count approximation.

Module verdict stays L1→L2 (typed API, no pipeline connection): the
observable DV②③ targets (main `pattern[8]` cast target, PartialStruct
bare-ification) are gated OUTSIDE this file — see
CAST-PARTIAL-REQ-NOCAST-0001 (cast.rs missing the cast.cc:341-349
partial no-cast arms) and UNIONRESOLVE-PIPELINE-WIRING-0001 (read-facing
resolveInFlow + setUnionField producers) on the TODO board. 21/21 module
tests; full lib 1655 pass / 18 pre-existing failures unchanged.

## 2026-09-26: with_field canonical interning + header producer census（UNIONRESOLVE-PKG-G-0001 / lane PKGG）

- `ResolvedUnion::with_field` signature: `typegrp: &TypeFactory` →
  `&mut TypeFactory`. The cc:51-55 pointer-parent arm now interns through
  `TypeFactory::get_type_pointer(parent.size, field, wordSize)`
  (type.cc:3867 `findAdd` + pointee `getStripped` step) instead of building
  a structural `Arc::new(Datatype::Pointer(..))`. The resolve Arc is now
  factory-canonical, so `Arc::ptr_eq` identity comparisons hit exactly
  where Ghidra's factory-owned `Datatype*` identity does — most notably
  cast.cc:303-304 `castStandard`'s `curtype == reqtype` no-cast
  short-circuit (formerly dead for with_field-minted pointers).
- Callers flipped to write guards: `resolve_in_flow` Array/Struct arm
  (unionresolve.rs, same lock discipline as the union arms' scoring
  interning), `Funcdata::force_facing_type` + `Funcdata::apply_union_facet`
  (funcdata.rs, formerly read guards), and
  `ActionSetCasts::try_resolution_adjustment`'s `build_resolve`
  (coreaction.rs, call-site ripple).
- Header NOTE rewritten: the stale "wiring gap … no pipeline producer"
  claim is replaced by the producer census — coreaction.rs `resolve_union`
  (cc:2499) / `castOutput` (cc:2556) / typeprop (cc:5083) + ruleaction.rs
  `RulePieceStructure` (cc:7678), all via `resolve_in_flow` →
  `ScoreUnionFields`.
- Unit gate: `test_with_field_pointer_parent_builds_field_pointer` now
  also asserts a second `get_type_pointer(8, field, 1)` mint returns the
  identical Arc (the interning property castStandard rides on).
- Dead-twin cleanup companion (type_system/datatype.rs):
  `TypePartialUnion::resolve_in_flow` / `find_resolve` method forms
  deleted — zero callers, no fd-cache consult (oracle type.cc:2505/2524
  do consult), name-clash trap with the fd-aware free functions here.
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。
