# `variable.rs` API Reference

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定审计）**——方法覆盖不等于行为对齐；VN↔High 挂接/销毁、annotation/后建节点、Arc 所有权环、instances 排序及 cover/flags dirty 传播均未闭合。

**源代码路径**: `src/variable.rs`

## 模块说明 (Module Doc)

High-level variable management

Corresponds to Ghidra's `variable.hh` / `variable.cc`. A `HighVariable`
models a source-level variable as a list of SSA `Varnode` members (each
written once). It inherits a Cover, data-type, and boolean properties from
its members, tracked here with the dual-flag dirty model from Ghidra.

## 双标志模型 (Dual-Flag Dirty Model)

Faithful to Ghidra's HighVariable (variable.hh:112-232). Rugra preserves
two flag fields exactly as Ghidra does:

- `highflags: u32` — dirtiness/status bits (variable.hh:119-131)
- `flags: u32` — inherited Varnode properties (refreshed via `update_flags`)

## `pub mod high_internal_flags`

Dirtiness / status bits for a `HighVariable`. Faithful to the anonymous enum
in `variable.hh:119-131`.

| Constant | Value | Ghidra meaning |
|----------|-------|----------------|
| `FLAGSDIRTY` | 1 | Boolean properties are dirty (re-derive via updateFlags) |
| `NAMEREPDIRTY` | 2 | The name representative is dirty |
| `TYPEDIRTY` | 4 | The data-type is dirty |
| `COVERDIRTY` | 8 | The cover is dirty |
| `SYMBOLDIRTY` | 0x10 | The symbol attachment is dirty |
| `COPY_IN1` | 0x20 | At least 1 COPY into this HighVariable from others exists |
| `COPY_IN2` | 0x40 | At least 2 COPYs into this HighVariable from others exist |
| `TYPE_FINALIZED` | 0x80 | Final data-type locked; dirtying disabled |
| `UNMERGED` | 0x100 | Part of a multi-entry Symbol but unmerged |
| `INTERSECTDIRTY` | 0x200 | Intersections need recompute |
| `EXTENDCOVERDIRTY` | 0x400 | Extended cover needs recompute |

## `pub mod high_flags`

Inherited Varnode property flag aliases (numeric values from `varnode_flags`):
`NAMELOCK`, `TYPELOCK`, `PERSIST`, `ADDRTIED`, `MAPPED`, `CONSTANT`, `INSERT`,
`INPUT`, `IMPLIED`, `SPACEBASE`, `UNAFFECTED`, `MARK`, `ANNOTATION`,
`DIRECTWRITE`, `INDIRECT_CREATION`, `PROTO_PARTIAL`.

## `pub struct TypeCell`

RUGRA-GLUE lock domain for the `mutable Datatype *type` cache
(variable.hh:141): `RwLock<Arc<Datatype>>` keeps `HighVariable` `Send + Sync`
while letting the const `getType` (variable.hh:174) swap the cache through
`&self` — the Rust counterpart of C++ logical constness. `get()` clones the
`Arc` (Ghidra returns the shared `Datatype*`); `set()` swaps it. The
`highflags`/`flags` words stay plain `pub u32` because raw place-form
`x.highflags & MASK` readers across the tree (fixtures, test modules) cannot
be satisfied by a newtype (binary-operator lookup never autorefs).

## `pub struct HighVariable`

A high-level variable modeled as a list of low-level (SSA) Varnodes.
Faithful to Ghidra's `HighVariable` (variable.hh:112-232).

### Fields

| Field | Type | Ghidra |
|-------|------|--------|
| `name` | `String` | (Rugra addition; Ghidra derives from Symbol) |
| `v_type` | `TypeCell` (lock domain) | `type` (`mutable`, variable.hh:141) |
| `instances` | `Vec<Arc<RwLock<Varnode>>>` | `inst` (sorted by storage address) |
| `flags` | `u32` | `flags` |
| `id` | `u64` | (Rugra diagnostic) |
| `cover` | `Cover` | `internalCover` |
| `highflags` | `u32` | `highflags` |
| `num_merge_classes` | `i32` | `numMergeClasses` |
| `symbol` | `Option<Arc<RwLock<Symbol>>>` | `symbol` |
| `symbol_offset` | `i32` | `symboloffset` (-1 = perfect match) |
| `name_representative` | `Option<Arc<RwLock<Varnode>>>` | `nameRepresentative` |
| `piece` | `Option<Arc<RwLock<VariablePiece>>>` | `piece` |

## 构造与生命周期

### `pub fn new(v_type: Arc<Datatype>) -> Self`
Ghidra: variable.cc:220 `HighVariable::HighVariable`. Seeds dirty bits
`FLAGSDIRTY|NAMEREPDIRTY|TYPEDIRTY|COVERDIRTY`, `numMergeClasses=1`,
`symboloffset=-1`.

## Symbol 管理

`HighVariable::compare_name` 的最后一个 tie-break 使用 defining op 的
不可变 `PcodeOp::get_time()`，对应 `variable.cc:485-486`。基本块对
`SeqNum.order` 的重编号不会改变名称代表元。

### `pub fn get_symbol(&self) -> Option<Arc<RwLock<Symbol>>>`
Ghidra: variable.hh:176 `getSymbol`.

### `pub fn get_symbol_offset(&self) -> i32`
Ghidra: variable.hh:178 `getSymbolOffset`. -1 = perfect match, >=0 = byte offset.

### `pub fn get_symbol_entry(&self) -> Option<Arc<RwLock<SymbolEntry>>>`
Ghidra: variable.cc:537 `getSymbolEntry`. Scans members for the SymbolEntry
whose Symbol matches.

### `pub fn set_symbol(&mut self, vn: &Arc<RwLock<Varnode>>)`
Ghidra: variable.cc:245 `setSymbol`. Updates Symbol info from a member Varnode;
computes the offset via `Address::overlap` (Rugra's overlapJoin equivalent).
Re-arms `typedirty` when the cached type is a partial union (variable.cc:
272-273, `TYPE_PARTIALUNION` — previously mis-checked as Unknown).

### `pub fn set_symbol_reference(&mut self, sym: Arc<RwLock<Symbol>>, off: i32)`
Ghidra: variable.cc:283 `setSymbolReference`.

## 数据类型

### `pub fn strip_type(&self)`
Ghidra: variable.cc:302 `stripType`. `&self` mirrors the Ghidra const member:
the write goes through the `mutable` type cache (`TypeCell`). Preserves a
partial-union/partial-struct when a struct/union backing Symbol exists
(variable.cc:308-313) and a partial enum on a single constant member
(variable.cc:315-318).

### `pub fn get_type(&self) -> Arc<Datatype>`
Ghidra: variable.hh:174 `getType` — `updateType(); return type;`. The lazy
re-derivation triggers here through a shared reference: when `typedirty` is
set and the type is not finalized, the representative member's type is
re-derived into the `TypeCell` cache (variable.cc:408-415, incl. `stripType`),
so a dirtying event (`typeDirty` from `Varnode::updateType`/`copySymbol`,
`remove`, `mergeInternal`, `setSymbol` on a partial-union cache) is reflected
by the next `get_type`, and a second call returns the same stable type.
Residual (VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001): unlike Ghidra's
`updateType()`, this `&self` path cannot clear the `typedirty` bit in the
plain `highflags` word (raw place-form bit readers across the tree require
the field to stay `u32`); it re-derives idempotently on each call until a
`&mut` path (`update_type`, `type_dirty`) re-syncs the bit. Output behavior
is identical; no current consumer observes the raw bit after a `&self`-only
clean.

### `pub fn get_type_representative(&self) -> Option<Arc<RwLock<Varnode>>>`
Ghidra: variable.cc:377 `getTypeRepresentative`. Picks member with strongest type.

### `pub fn update_type(&mut self)`
Ghidra: variable.cc:400 `updateType`. Re-derives data-type from members.
Clears `typedirty` FIRST, then a `TYPE_FINALIZED` type short-circuits
(variable.cc:405-407). Stays `&mut self`: it owns the authoritative dirty-bit
clear in the plain `highflags` word; the `&self` lazy read path lives in
`get_type` (variable.hh:174).

### `pub fn finalize_datatype(&mut self, type_factory: &mut TypeFactory)`
Ghidra: variable.cc:551 `finalizeDatatype(TypeFactory*)`. Assigns final type
from Symbol. 2026-08-24（TYPEFACTORY-EXACTPIECE-CALLERS-0001）：调用方显式传入
Architecture 持有的 TypeFactory（Ghidra 由调用方 `data.getArch()->types` 传入，
coreaction.cc:2946/2972），piece 查找走 canonical
`TypeFactory::get_exact_piece`（type.cc:4090），保留 PartialStruct/PartialUnion/
PartialEnum 的 canonical Arc identity 与工厂 mutation；`null`/`TYPE_UNKNOWN`
结果保持 early return（variable.cc:561-562）。双侧门禁
`tests/oracle/exactpiece_callers_1204`。

## Cover

### `pub fn update_internal_cover(&mut self)`
Ghidra: variable.cc:324 `updateInternalCover`.

### `pub fn update_cover(&mut self)`
Ghidra: variable.cc:338 `updateCover`. With a piece, recomputes intersections
and the piece's extended cover.

### `pub fn get_cover(&self) -> &Cover`
Ghidra: variable.hh:294-300 `getCover`.

### `pub fn print_cover(&self) -> String`
Ghidra: variable.hh:188 `printCover`.

### `pub fn is_cover_dirty(&self) -> bool`
Ghidra: variable.hh:285-289 `isCoverDirty`.

### `pub fn cover_dirty(&mut self)`
Ghidra: variable.hh:275-281 `coverDirty`.

## Flags 与属性查询 (variable.hh:197-223)

All property queries below take `&self` and read the cached `flags` bit
directly (Rugra call-sites in merge.rs hold only a `RwLockReadGuard`).
Ghidra's inline variants call `updateFlags()` first; Rugra keeps the cache
fresh via `update_flags()` on the `&mut self` mutation paths.

### `pub fn update_flags(&mut self)`
Ghidra: variable.cc:352 `updateFlags`. OR's member flags together.

### `pub fn is_mapped(&self) -> bool` — variable.hh:197
### `pub fn is_persist(&self) -> bool` — variable.hh:198
### `pub fn is_addr_tied(&self) -> bool` — variable.hh:199
### `pub fn is_input(&self) -> bool` — variable.hh:200
### `pub fn is_implied(&self) -> bool` — variable.hh:201
### `pub fn is_spacebase(&self) -> bool` — variable.hh:202
### `pub fn is_constant(&self) -> bool` — variable.hh:203
### `pub fn is_unaffected(&self) -> bool` — variable.hh:204
### `pub fn is_extra_out(&self) -> bool` — variable.hh:205
### `pub fn is_proto_partial(&self) -> bool` — variable.hh:206
### `pub fn has_cover(&self) -> bool` — variable.hh:217
### `pub fn is_unattached(&self) -> bool` — variable.hh:221
### `pub fn is_type_locked(&self) -> bool`
Backward-compat shared-ref alias for `is_type_lock` (merge.rs:480, :1140);
now a faithful alias of `isTypeLock` (variable.hh:222).
### `pub fn is_type_lock(&self) -> bool` — variable.hh:222
`updateType(); return (flags & typelock) != 0;` — a const member in Ghidra,
so `&self`. When the type is dirty, the refreshed typelock value is derived
transiently from the representative (what `updateType` would write into
`flags`, variable.cc:413-415); when clean, the cached `flags` bit is read.
### `pub fn is_name_lock(&mut self) -> bool` — variable.hh:223

## 标记 (Mark)

### `pub fn set_mark(&mut self)` — variable.hh:207
### `pub fn clear_mark(&mut self)` — variable.hh:208
### `pub fn is_mark(&self) -> bool` — variable.hh:209

## 合并与组 (Merge / Group)

### `pub fn merge_internal(&mut self, tv2: &mut HighVariable, isspeculative: bool)`
Ghidra: variable.cc:626 `mergeInternal`. Merges another HighVariable's
instances, classes, symbol, and cover. The retired `tv2` shell gets its
`NAMEREPDIRTY` bit set after the instance drain (Rugra keeps the shell
object where Ghidra deletes `tv2`; the invalidation makes any late
name-representative query on the shell re-derive from the empty list,
matching the pre-cache `&self` behavior).

### `pub fn merge(&mut self, tv2: &mut HighVariable, _test_cache: Option<()>, isspeculative: bool)`
Ghidra: variable.cc:675 `merge`. Group-aware merge.

### `pub fn group_with(&mut self, off: i32, hi2: &mut HighVariable)`
Ghidra: variable.cc:571 `groupWith`.

### `pub fn establish_group_symbol_offset(&self)`
Ghidra: variable.cc:610 `establishGroupSymbolOffset`.

### `pub fn transfer_piece(&mut self, tv2: &mut HighVariable)`
Ghidra: variable.cc:291 `transferPiece`.

### `pub fn is_same_group(&self, op2: &HighVariable) -> bool` — variable.hh:211

## 名称代表 (Name Representative)

### `pub fn get_name_representative(&self) -> Option<Arc<RwLock<Varnode>>>`
Ghidra: variable.cc:492 `getNameRepresentative`. Takes `&self` (coreaction.rs:3799
holds only a read lock); recomputes the `compareName` walk per call without
touching the cache.

### `pub fn get_name_representative_mut(&mut self) -> Option<Arc<RwLock<Varnode>>>`
Ghidra: variable.cc:492 `getNameRepresentative` (mutable-cache form). Mirrors
the oracle's `mutable`-member cache write exactly: cache-hit return when
`NAMEREPDIRTY` is clear (cc:495-496); otherwise the dirty bit is cleared
FIRST (cc:497), the representative is re-derived from `instances[0]` via
`compare_name` (cc:502-509), stored into `name_representative`, and
returned. The selection walk is the same deterministic algorithm as the
`&self` form — the only delta is cache population, which is precisely what
Ghidra's const method does through its `mutable` members.
`ActionNameVars::link_symbols` (coreaction.cc:2959) uses this form under a
write lock so each HighVariable's O(k) walk runs once per scan instead of
per member varnode (PERF-NVREP-CACHE-0001). Cache safety: every
`instances` mutation path re-sets `NAMEREPDIRTY` — init (variable.cc:224),
`merge_internal` (variable.cc:631, plus the retired-shell `tv2`
invalidation where Ghidra deletes tv2 outright), `remove`/`remove_instance`
(variable.cc:524), `flags_dirty` (variable.hh:164), and `add_instance`
(glue mutator, now dirty-marking like its oracle construction/merge
counterparts).

### `pub fn compare_name(vn1: &Varnode, vn2: &Varnode) -> bool` (static)
Ghidra: variable.cc:456 `compareName`.

### `pub fn compare_just_loc(a: &Varnode, b: &Varnode) -> bool` (static)
Ghidra: variable.cc:439 `compareJustLoc`. Compares via `Address::operator<`
(address.hh:375-393): space index first (`space_id()` mirrors
`AddrSpace::getIndex()`), then offset — a total order across spaces
(previously offset-only, which mis-ordered cross-space varnodes in
`merge_internal`'s `std::merge`).

### `pub fn has_name(&self) -> bool`
Ghidra: variable.cc:718 `hasName`.

## 成员管理 (Instance Management)

### `pub fn remove(&mut self, vn: &Arc<RwLock<Varnode>>)`
Ghidra: variable.cc:515 `remove`. Removes a member and marks properties dirty.

### `pub fn remove_instance(&mut self, index: usize)`
Backward-compat alias (merge.rs:1793); body faithful to `remove`.

### `pub fn instance_index(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize>`
Ghidra: variable.cc:808 `instanceIndex`.

### `pub fn get_tied_varnode(&self) -> Option<Arc<RwLock<Varnode>>>`
Ghidra: variable.cc:752 `getTiedVarnode`. Returns None instead of throwing.

### `pub fn get_input_varnode(&self) -> Option<Arc<RwLock<Varnode>>>`
Ghidra: variable.cc:767 `getInputVarnode`. Returns None instead of throwing.

## Dirty 辅助 (variable.hh:153-170)

### `pub fn set_copy_in1(&mut self)` — variable.hh:153
### `pub fn set_copy_in2(&mut self)` — variable.hh:154
### `pub fn clear_copy_ins(&mut self)` — variable.hh:155
### `pub fn has_copy_in1(&self) -> bool` — variable.hh:156
### `pub fn has_copy_in2(&self) -> bool` — variable.hh:157
### `pub fn flags_dirty(&mut self)` — variable.hh:164
### `pub fn type_dirty(&mut self)` — variable.hh:166
### `pub fn symbol_dirty(&mut self)` — variable.hh:167
### `pub fn set_unmerged(&mut self)` — variable.hh:168
### `pub fn is_unmerged(&self) -> bool` — variable.hh:210

## 序列化与调试

### `pub fn print_info(&mut self) -> String`
Ghidra: variable.cc:778 `printInfo`.

### `pub fn encode(&self) -> String`
Ghidra: variable.cc:820 `encode`. Encodes as a `<high>` element.

### `pub fn mark_expression(vn: &Arc<RwLock<Varnode>>, high_list: &mut Vec<Arc<RwLock<HighVariable>>>) -> i32` (static)
Ghidra: variable.cc:872 `markExpression`. Returns bitset: 1=call, 2=LOAD.

## Legacy Rugra 便利方法

`get_type`, `num_instances`, `get_instance`, and `get_num_merge_classes` map to
the inline Ghidra accessors at variable.hh:174, :179, :180, and :196;
`get_type` now carries the lazy `updateType()` trigger of variable.hh:174
(see Data Types above).
`get_name`, `set_name`, `set_type`, and `add_instance` are legacy
RUGRA-GLUE APIs: Ghidra derives names through Symbol state, derives/finalizes
types through dedicated methods, and changes membership through construction
or merge rather than these direct field mutators.

---

## `pub struct VariableGroup`

Faithful to Ghidra's `VariableGroup` (variable.hh:44-68). Manages a set of
VariablePiece objects, tracks total size and symbol offset.

### Fields
- `pieces: Vec<Arc<RwLock<VariablePiece>>>` — sorted by (offset, size)
- `size: i32` — bytes covered by the whole group
- `symbol_offset: i32` — byte offset within containing Symbol

### Methods
- `pub fn new() -> Self` — variable.hh:56
- `pub fn is_empty(&self) -> bool` — variable.hh:57
- `pub fn add_piece(&mut self, piece: Arc<RwLock<VariablePiece>>)` — variable.cc:43 `addPiece`
- `pub fn adjust_offsets(&mut self, amt: i32)` — variable.cc:56 `adjustOffsets`
- `pub fn remove_piece(&mut self, piece: &Arc<RwLock<VariablePiece>>)` — variable.cc:67 `removePiece`
- `pub fn get_size(&self) -> i32` — variable.hh:61
- `pub fn set_symbol_offset(&mut self, val: i32)` — variable.hh:62
- `pub fn get_symbol_offset(&self) -> i32` — variable.hh:63
- `pub fn combine_groups(&mut self, op2: &mut VariableGroup)` — variable.cc:78 `combineGroups`; transfers source pieces in PieceCompareByOffset order, rewires each piece's group pointer, and empties the source group

---

## `pub struct VariablePiece`

Faithful to Ghidra's `VariablePiece` (variable.hh:71-96). Describes how a
HighVariable fits into a larger group or Symbol.

### Fields
- `group: Option<Arc<RwLock<VariableGroup>>>`
- `high: Option<Weak<RwLock<HighVariable>>>` — owner back-ref (Weak avoids cycle)
- `group_offset: i32`
- `size: i32`
- `intersection: Vec<Arc<RwLock<VariablePiece>>>`
- `cover: Cover`

### Methods
- `pub fn new(high, offset, size, group) -> Self` — variable.cc:96
- `pub fn get_high(&self)` — variable.hh:82
- `pub fn get_group_arc(&self)` — Rugra helper (Ghidra returns raw group ptr)
- `pub fn get_group(&self)` — variable.hh:83
- `pub fn get_offset(&self) -> i32` — variable.hh:84
- `pub fn get_size(&self) -> i32` — variable.hh:85
- `pub fn get_cover(&self) -> &Cover` — variable.hh:86
- `pub fn num_intersection(&self) -> usize` — variable.hh:87
- `pub fn get_intersection(&self, i) -> Option<Arc<RwLock<VariablePiece>>>` — variable.hh:88
- `pub fn mark_intersection_dirty(&self)` — variable.cc:119
- `pub fn mark_extend_cover_dirty(&self)` — variable.cc:128
- `pub fn update_intersections(self_arc: &Arc<RwLock<VariablePiece>>)` — variable.cc:140
- `pub fn update_cover(&mut self, owner: &mut HighVariable)` — variable.cc:160
- `pub fn set_high(&mut self, new_high)` — variable.hh:94
- `pub fn merge_groups(self_piece, op2_piece) -> Vec<(Weak, Weak)>` — variable.cc:193
  （完整版：offset 对齐 + matched (offset,size) 对收集与 op2 侧分离/移除
  （:206-211，含 `~VariablePiece` 的 markIntersectionDirty :111-114）+
  未 matched 的 transferGroup（:213）；MERGE-COPYTRIMS-CACHE-0001）
- `pub fn mark_intersection_dirty(&self)`（VariableGroup 成员函数版）—
  variable.cc:116 的组遍历形态（`~VariablePiece`/`HighVariable::merge`
  :710 的组级标记路径）

---

## 测试 (Tests)

18 unit tests covering: basic construction, name lock, mergeInternal (symbol
inheritance + speculative class counts), copy-in flag toggling, dirty
helpers, compareJustLoc, type/name representatives (including the &self
shared-ref regression guard), instanceIndex, remove-dirties, isUnattached,
VariableGroup basics, VariablePiece construction, and the bit-exact values of
all 11 high_internal_flags constants.

## 变更历史

- 2026-06-28: Historical implementation baseline
  (`merge_internal`/`get_type_representative`/`strip_type`); this was not a
  locked-oracle `MATCH` and is not an L3 claim.
- 2026-07-04: +instance-delegated accessors (is_input/is_extra_out/is_proto_partial).
- 2026-07-22: Historical broad implementation pass — mergeInternal, merge (group-aware), setSymbol,
  getSymbol, getSymbolOffset, getSymbolEntry, setSymbolReference, transferPiece,
  stripType, updateCover, updateFlags, updateType, updateSymbol, finalizeDatatype,
  groupWith, establishGroupSymbolOffset, compareJustLoc, compareName,
  getNameRepresentative, remove, hasName, getTiedVarnode, getInputVarnode,
  printInfo, printCover, instanceIndex, encode, markExpression, all property
  queries (variable.hh:197-223), all dirty helpers (variable.hh:153-170),
  high_internal_flags (11 bits), VariableGroup (8 methods), VariablePiece
  (15 methods). 18 unit tests. Property queries take &self for RwLockReadGuard
  callers.
- 2026-08-23 (`VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001`): `get_type(&self)` now
  performs the lazy `updateType()` re-derivation of variable.hh:174 (dirty ->
  representative type -> strip -> cache), via a new `TypeCell`
  (`RwLock<Arc<Datatype>>`) lock domain standing in for Ghidra's `mutable`
  cache; `is_type_lock`/`is_type_locked` moved to `&self` with the transient
  typelock derivation (variable.cc:413-415); `strip_type` to `&self` with the
  previously-dropped partial-union/partial-struct backing-Symbol guard
  (variable.cc:308-313) restored; `set_symbol` partial-union re-dirty fixed
  to `TYPE_PARTIALUNION` (variable.cc:272-273). Compile-required `v_type`
  accessor adaptations in type_infer.rs/coreaction.rs/merge.rs. Residual:
  the `&self` path cannot clear the plain-word `typedirty` bit (raw-bit
  readers require `u32`); registered as VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001
  follow-up.
- 2026-08-11 (`ANN-I`): provenance-only annotation bootstrap for 14 functions.
  Four direct inline mappings now cite variable.hh:174/:179/:180/:196; the ten
  remaining legacy, ownership, and `Arc<RwLock>` entry points are explicitly
  classified as RUGRA-GLUE. No behavior changed, no oracle fixture was added,
  and the module status is not promoted; `ALIGNMENT_ROADMAP.md` remains
  authoritative.
