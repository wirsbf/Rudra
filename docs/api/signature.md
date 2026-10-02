# `signature.rs` API Reference

**Source path**: `src/signature.rs`
**Ghidra counterpart**: `signature.hh` / `signature.cc` (1148 lines)
**Status**: L1 -> L2 (faithful port of the full feature-generation framework)

## Module overview

Function signature / feature generation. Ghidra extracts a feature vector from a
function's data-flow and control-flow graphs by iteratively hashing information
through the graph edges. The vector can be compared against a database of known
function signatures to identify standard library calls.

This module is a faithful 1:1 port of `signature.hh` / `signature.cc`. Every
ported function carries a `// Ghidra: signature.cc:<line> <name>` comment
pointing at the exact Ghidra source line; pure Rust glue (arena indices,
`Mutex` settings, disjoint-borrow helpers) is marked `// RUDRA-GLUE: <reason>`.

2026-08-12 ANN-N 仅补 provenance：为 scanner 先前遗漏的两个 const holder
构造器补充具体 Rust-glue 注释；本次未改变行为或模块状态。

### Key type-alignment note

`hashword` is `uint8` (8-byte unsigned) in Ghidra, so the iterative hash slots
`SignatureEntry::hash[2]` and `BlockSignatureEntry::hash[2]` are `[u64; 2]`.
`Signature::sig` is explicitly `uint4` (32-bit) per `signature.hh:51`, so the
emitted feature hash stored in a `Signature` is truncated to 32 bits (matching
the constructor cast `sig=(uint4)h`). The original Rudra skeleton used `[u32; 2]`
for the hash slots, which was incorrect.

## Public API

### Marshaling ids
- `LazyAttrib` / `LazyElem` - const-fn holders for `AttributeId` / `ElementId`,
  materialized on demand (Rust statics cannot run the allocating constructor).
- `ATTRIB_BADDATA` (145), `ATTRIB_HASH` (146), `ATTRIB_UNIMPL` (147),
  `ATTRIB_VAL` (71), `ATTRIB_INDEX` (27), `ATTRIB_SPACE` (9), `ATTRIB_OFFSET` (4).
- `ELEM_BLOCKSIG` (258), `ELEM_CALL` (259), `ELEM_GENSIG` (260), `ELEM_COPYSIG`
  (263), `ELEM_SIG` (265), `ELEM_SIGNATUREDESC` (266), `ELEM_SIGNATURES` (267),
  `ELEM_VARSIG` (269). All ids match `signature.cc:26-41`.

### Modifier bits (`sig_mods`)
`SIG_COLLAPSE_SIZE` (0x1), `SIG_COLLAPSE_INDNOISE` (0x2), `SIG_DONOTUSE_CONST`
(0x10), `SIG_DONOTUSE_INPUT` (0x20), `SIG_DONOTUSE_PERSIST` (0x40). Faithful to
`GraphSigManager::Mods` (`signature.hh:268-275`).

### Entry flags (`entry_flags`)
`SIG_NODE_TERMINAL` (0x1), `SIG_NODE_COMMUTATIVE` (0x2), `SIG_NODE_NOT_EMITTED`
(0x4), `SIG_NODE_STANDALONE` (0x8), `VISITED` (0x10), `MARKER_ROOT` (0x20).
Faithful to `SignatureEntry::SignatureFlags` (`signature.hh:80-87`).

### `pub struct Signature`
A single 32-bit feature hash. Faithful to `Signature` (`signature.hh:50`).
- `new(h: u64)` - truncate 64-bit hashword to 32-bit `sig`.
- `get_hash()`, `print(s)`, `print_origin(s)`, `compare(op2)`, `compare_ptr(a,b)`,
  `encode(encoder)`.

### Feature subtypes (emitted)
- `VarnodeSignature` (`signature.hh:183`) - data-flow rooted feature.
- `BlockSignature` (`signature.hh:197`) - control-flow rooted feature (two forms).
- `CopySignature` (`signature.hh:215`) - stand-alone COPY feature.
- `SignatureFeature` - Rust enum replacing Ghidra's `Signature*` virtual hierarchy.

### `pub struct SignatureEntry`
Data-flow feature-generation node. Faithful to `SignatureEntry`
(`signature.hh:78`). Rust uses an **arena** (`SignatureGraph`) instead of
Ghidra's `map<int4,SignatureEntry*>` to avoid shared mutable aliasing.
- `new(vn, modifiers)`, `new_virtual(ind)` - constructors.
- Accessors: `is_terminal`, `is_not_emitted`, `is_commutative`, `is_standalone_copy`,
  `num_inputs`, `is_visited`, `set_visited`, `get_in`, `marker_size_in`,
  `get_marker_in`, `flip`, `get_hash`, `get_varnode`.
- Hash methods: `calculate_shadow`, `calculate_shadow_via` (closure variant),
  `get_op_hash`, `test_standalone_copy`, `standalone_copy_hash`, `hash_size`,
  `local_hash`, `hash_in`.
- Noise removal: `noise_post_order`, `noise_dominator`, `intersect`, `remove_noise`
  (dominator-tree based COPY/INDIRECT/MULTIEQUAL collapse).

### `pub struct SignatureGraph`
Arena of `SignatureEntry` values + a `create_index -> VnIdx` lookup map. Owns
entries by value and exposes index-based access so entries can reference each
other via `shadow` without violating Rust aliasing rules.
- `map_to_entry`, `map_to_entry_collapse`, `entry`, `entry_mut`, `push_root`,
  `push_virtual`.
- `calculate_shadows_all`, `apply_hash_in_round` - disjoint-borrow helpers that
  keep `&create_to_slot` (immut) and `&mut entries` visible within one method
  body for the borrow checker.

### `pub struct BlockSignatureEntry`
Control-flow feature-generation node. Faithful to `BlockSignatureEntry`
(`signature.hh:167`).
- `new`, `local_hash(size_in, size_out)`, `flip`, `get_hash`, `get_block`.

### `pub struct SigSettings` / `pub struct SigManager`
- `SigSettings::get()` / `set(value)` - process-wide settings static (Rust uses
  a `Mutex<Option<u32>>` since mutable statics are unsafe).
- `SigManager` - feature vector container (`signature.hh:233`): `new`,
  `add_signature`, `clear`, `set_current_function`, `num_signatures`,
  `get_signature`, `get_signature_vector`, `get_overall_hash`, `sort_by_hash`,
  `print`, `encode`.

### `pub struct GraphSigManager`
Data-flow + control-flow feature driver. Faithful to `GraphSigManager`
(`signature.hh:265`). Composes a `SigManager` (Rust composition replaces
inheritance).
- `new`, `set_max_iteration`, `set_max_block_iteration`, `set_max_varnode`,
  `test_settings`, `varnode_clear`, `block_clear`, `clear`, `set_current_function`,
  `flip_varnodes`, `flip_blocks`, `signature_iterate`, `signature_block_iterate`,
  `initialize_blocks`, `collect_varnode_sigs`, `collect_block_sigs`, `generate`.

### Free functions
- `has_unimplemented(fd)`, `has_bad_data(fd)` - scan the op bank for
  `UNIMPLEMENTED` / `BADINSTRUCTION` flags (Ghidra `Funcdata::hasUnimplemented` /
  `hasBadData`).
- `simple_signature(fd, encoder)` - faithful to `signature.cc:1099`.
- `debug_signature(fd, encoder)` - faithful to `signature.cc:1137`.

## Alignment evidence

- `ghidra/.../signature.hh` (357 lines) and `signature.cc` (1148 lines) read in
  full before writing any code.
- `hashword` verified as `uint8` (64-bit); `Signature::sig` kept as `uint4`
  (32-bit) per `signature.hh:51`.
- Every ported function annotated `// Ghidra: signature.cc:<line> <name>`.
- Pure Rust glue marked `// RUDRA-GLUE: <reason>`.
- No simplified implementations: iterative graph hashing, dominator-tree noise
  removal, all three feature types, and both free functions ported faithfully.
- Magic constants preserved verbatim (`0xbafabaca`, `0x78abbf`, `0xfeedface`,
  `0x55055055`, `0x9b1c5f`, `0xa2de3c`, `0xaf29e23b`, `0xd7651ec3`, etc.).

## Verification

- `cargo check --lib`: `signature.rs` compiles with **0 errors, 0 warnings**.
  (The wider crate has pre-existing errors in `type_system`, `varmap`, `block`,
  `graph`, etc. from concurrent ports; none are in `signature.rs`.)
- 18 unit tests (`signature::tests`) covering `hash_mixin` determinism/asymmetry,
  32-bit truncation, `Signature::compare`, `test_settings` validity matrix,
  `BlockSignatureEntry::local_hash`, arena lookup, and feature-vector sorting.
  Test logic verified against the real CRC32 table.

## History

- 2026-08-11: ANN-D provenance-only pass added function-local annotations for
  12 Rust arena/static-materialization accessors and `Default` implementations;
  no behavior changed. Oracle `e40ed13014025f82488b1f8f7bca566894ac376b`
  `signature.cc` / `signature.hh` were reread in full.
- 2026-07-22: full faithful port of `signature.cc`. Replaced the 289-line
  skeleton (which had an incorrect `[u32; 2]` hashword and a non-existent
  `SignatureDB` class) with a 2302-line port covering every Ghidra type and
  function in scope.

## 2026-08-24: CALLSPEC-IDENTITY-D0 guard adaptation

`simple_signature` still emits call-target addresses in qlst order, but
`Funcdata::get_call_specs` now returns an `RwLockReadGuard`. The implementation
copies the `Option<Address>` while that guard is live and releases it before
encoding, instead of returning a reference into a callspec that is owned by an
`Arc<RwLock<_>>`. This is a borrow/lifecycle adaptation only: encoding order and
address filtering are unchanged.

Signature status is not promoted. D0 remains `MISMATCH` because Rudra's typed
handle is still carried in temporary `AddressSpace::Iop`, not dedicated
`IPTR_FSPEC` (`TYPEOP-FSPEC-SPACE-0001`), and this phase intentionally does not
wire TypeOp getter, PrintC, StringManager, or close other callspec/signature
residuals.


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 1 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
