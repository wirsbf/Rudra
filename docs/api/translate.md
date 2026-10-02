# `translate.rs` API Reference

**状态**: 🔧 L2 / `NO_ORACLE`（2026-08-11 ANN-J 注释 bootstrap；源码锚点不等于行为对齐。例外：`Translate::initialize` 的 DocumentStorage 消费契约自 2026-08-16 起由 `translate_docstore_1204` fixture 以锁定 oracle 验证 `MATCH`，其余方法仍 `NO_ORACLE`）
**源代码路径**: `src/translate.rs`  
**Ghidra 对应**: `translate.hh` / `translate.cc`（1018 / 1018 行）

## 模块说明 (Module Doc)

Instruction translation engine interfaces corresponding to Ghidra's
`translate.hh` / `translate.cc`. Dynamic address-space identity and metadata
remain a foundation gap, so this module is not claimed as a complete port.

This module provides the core interfaces for disassembly and P-code
generation for a single processor architecture. It is the bridge between a
binary's raw instruction bytes and the P-code IR the rest of the decompiler
operates on.

### Ghidra classes ported

| Ghidra class (`translate.hh`) | Line | Rust port |
| --- | --- | --- |
| `UnimplError` | 53 | [`UnimplError`] |
| `BadDataError` | 68 | [`BadDataError`] |
| `TruncationTag` | 81 | [`TruncationTag`] |
| `PcodeEmit` | 94 | [`PcodeEmit`] (trait) |
| `AssemblyEmit` | 120 | [`AssemblyEmit`] (trait) |
| `AddressResolver` | 142 | [`AddressResolver`] (trait) |
| `SpacebaseSpace` | 172 | [`SpacebaseSpace`] |
| `JoinRecord` | 196 | [`JoinRecord`] |
| `AddrSpaceManager` | 220 | [`AddrSpaceManager`] |
| `Translate` | 299 | [`Translate`] (trait) |
| `Translate::UniqueLayout` | 302 | [`UniqueLayout`] |

# Core Types

- [`PcodeEmit`] — callback for receiving generated P-code.
- [`AssemblyEmit`] — callback for receiving disassembly text.
- [`AddressResolver`] — converts native constants to addresses (segmented /
  near-pointer extension).
- [`SpacebaseSpace`] — a virtual stack-like space indexed relative to a base
  register.
- [`JoinRecord`] — describes how a logical value is split across physical
  locations.
- [`AddrSpaceManager`] — owns and indexes the address spaces for a processor.
- [`Translate`] — the processor translation engine (P-code + disassembly).
- [`UniqueLayout`] — tagged regions of the `unique` address space.

## 导出的公共 API (Public API)

### Translation-specific errors

#### `pub struct UnimplError`

Faithful to `UnimplError` (translate.hh:53). Thrown when a machine
instruction is valid but cannot be represented in pcode.

- `message: String`
- `instruction_length: i32` — byte length of the offending instruction.
- `pub fn new(message: impl Into<String>, length: i32) -> Self`
  — Ghidra: translate.hh:59 `UnimplError::UnimplError`.
- Implements `std::fmt::Display` and `std::error::Error` (RUDRA-GLUE for
  Rust error interop; Ghidra inherits `LowlevelError::what()`).

#### `pub struct BadDataError`

Faithful to `BadDataError` (translate.hh:68). Thrown when instruction data
cannot be decoded.

- `message: String`
- `pub fn new(message: impl Into<String>) -> Self`
  — Ghidra: translate.hh:72 `BadDataError::BadDataError`.
- Implements `std::fmt::Display` and `std::error::Error`.

### TruncationTag (translate.hh:81)

#### `pub struct TruncationTag`

Override for the size of an address space as defined by the architecture.

- `space_name: String` — Ghidra: translate.hh:83 `spaceName`.
- `size: u32` — Ghidra: translate.hh:84 `size`.
- `pub fn get_name(&self) -> &str` — Ghidra: translate.hh:86 `getName`.
- `pub fn get_size(&self) -> u32` — Ghidra: translate.hh:87 `getSize`.
- `pub fn decode(&mut self, decoder: &mut dyn Decoder)` — Ghidra:
  translate.cc:38 `TruncationTag::decode`. Reads a `<truncate_space>`
  element.

### PcodeEmit (translate.hh:94)

#### `pub trait PcodeEmit`

Abstract callback for emitting pcode to an application.

- `fn dump(&mut self, addr: Address, opc: OpCode,
  outvar: Option<&VarnodeData>, vars: &[VarnodeData])`
  — Ghidra: translate.hh:110 `PcodeEmit::dump`. `outvar` is `None` when the
  op has no output varnode. The `isize` parameter is implicit in the slice
  length.
- `fn decode_op(&mut self, addr: Address, decoder: &mut dyn Decoder)`
  — Ghidra: translate.cc:996 `PcodeEmit::decodeOp`. Default implementation
  parses an `<op>` element and invokes `dump`. (Ghidra reuses a 16-entry
  stack array; Rugra always heap-allocates the input vec — observable
  behavior is identical.)

The trait is **object-safe** (`dyn PcodeEmit` is usable) because the
PcodeOpRaw decode helper is a free function rather than a trait method:

- `pub fn decode_pcode_raw(decoder, isize, vars, outvar, has_output) -> OpCode`
  — RUDRA-GLUE placeholder returning `CPUI_COPY`. A full port of
  `PcodeOpRaw::decode` (pcoderaw.cc) will replace it.

### AssemblyEmit (translate.hh:120)

#### `pub trait AssemblyEmit`

Abstract callback for emitting disassembly text.

- `fn dump(&mut self, addr: Address, mnem: &str, body: &str)` — Ghidra:
  translate.hh:133 `AssemblyEmit::dump`.

### AddressResolver (translate.hh:142)

#### `pub trait AddressResolver`

Converts native constants to addresses (segmented / near-pointer extension).

- `fn resolve(&mut self, val: u64, sz: i32, point: Address,
  full_encoding: &mut u64) -> Address` — Ghidra: translate.hh:158
  `resolve`. `sz == -1` signals a full pointer encoding.

### SpacebaseSpace (translate.hh:172)

#### `pub struct SpacebaseSpace`

A virtual stack space indexed relative to a base register. In Ghidra this
inherits from `AddrSpace`; Rugra's enum address spaces carry the identity, so
this struct holds only the spacebase-specific state.

Fields (all `pub`): `contain`, `has_base_register`, `is_negative_stack`,
`base_loc`, `base_orig`, `name`, `index`, `addr_size`, `delay`.

- `pub fn new(nm, ind, sz, base, dl, is_formal) -> Self` — Ghidra:
  translate.cc:57 full ctor. Stack-grows-negative defaults to `true`.
- `pub fn new_for_decode() -> Self` — Ghidra: translate.cc:73 decode ctor.
- `pub fn set_base_register(&mut self, data: &VarnodeData, trunc_size: i32,
  stack_growth: bool)` — Ghidra: translate.cc:86 `setBaseRegister`. Panics
  if a different base register was already assigned; truncates `base_loc`
  for big-endian spaces.
- `pub fn num_spacebase(&self) -> i32` — Ghidra: translate.cc:104.
- `pub fn get_spacebase(&self, i: i32) -> &VarnodeData` — Ghidra:
  translate.cc:110. Panics if no base register / `i != 0`.
- `pub fn get_spacebase_full(&self, i: i32) -> &VarnodeData` — Ghidra:
  translate.cc:118.
- `pub fn stack_grows_negative(&self) -> bool` — Ghidra: translate.hh:186.
- `pub fn get_contain(&self) -> AddressSpace` — Ghidra: translate.hh:187.
- `pub fn decode(&mut self, decoder: &mut dyn Decoder)` — Ghidra:
  translate.cc:126 `SpacebaseSpace::decode`.

### JoinRecord (translate.hh:196)

#### `pub struct JoinRecord`

Describes how a logical value is split across physical locations (pieces
listed most-significant first).

- `pieces: Vec<VarnodeData>` — Ghidra: translate.hh:198.
- `unified: VarnodeData` — Ghidra: translate.hh:199.
- `pub fn num_pieces(&self) -> usize` — translate.hh:201.
- `pub fn is_float_extension(&self) -> bool` — translate.hh:202.
- `pub fn get_piece(&self, i: usize) -> &VarnodeData` — translate.hh:203.
- `pub fn get_unified(&self) -> &VarnodeData` — translate.hh:204.
- `pub fn get_equivalent_address(&self, offset: u64) -> Option<(Address, usize)>`
  — Ghidra: translate.cc:141. Returns `None` if `offset` is outside the
  unified range.
- `pub fn less_than(&self, op2: &JoinRecord) -> bool` — Ghidra:
  translate.cc:172 `operator<`. Lexicographic on `(unified.size, pieces)`.
- `pub fn merge_sequence<F>(seq: &mut Vec<VarnodeData>, exact_register_name: F)
  where F: FnMut(&AddressSpace, u64, usize) -> String` — Ghidra:
  translate.cc:196. Merges contiguous varnodes; non-stack merges are
  inhibited unless the result has a formal register name (queried via the
  closure).

### AddrSpaceManager (translate.hh:220)

#### `pub struct AddrSpaceManager`

Owns and indexes the address spaces for a processor. In Ghidra this is the
base class of `Translate`; Rugra composes it as a field.

Fields mirror Ghidra's members (translate.hh:221-235): `base_list`,
`resolve_list` (`Vec<Option<Box<dyn AddressResolver>>>`), `name_to_space`,
`shortcut_to_space`, `constant_space`, `default_code_space`,
`default_data_space`, `iop_space`, `fspec_space`, `join_space`,
`stack_space`, `uniq_space`, `join_allocate`, `split_set`, `split_list`.

Lookup / iteration (all faithful to the inline accessors at
translate.hh:448-561):

- `pub fn new() -> Self` — translate.cc:235.
- `get_default_size`, `get_space_by_name` (translate.cc:590),
  `get_space_by_shortcut` (translate.cc:604), `get_iop_space`,
  `get_fspec_space`, `get_join_space`, `get_stack_space`,
  `get_unique_space`, `get_default_code_space`,
  `get_default_data_space`, `get_constant_space`.
- `get_constant(val)` — translate.hh:532.
- `create_const_from_space(spc)` — translate.hh:542 (encodes `space_id`).
- `num_spaces`, `get_space(i)`.
- `get_next_space_in_order(spc)` — translate.cc:647.
- `find_add_join(pieces, logical_size) -> &JoinRecord` — translate.cc:671.
  Panics on the same invalid inputs as Ghidra.
- `find_join(offset) -> &JoinRecord` — translate.cc:746 (panics on
  unlinked address).
- `find_join_internal(offset) -> Option<&JoinRecord>` — translate.cc:722
  (range match; the public `find_join` panics instead of returning `None`).
- `set_deadcode_delay(spc, delta)` — translate.cc:768 (no-op in Rugra's
  fixed-delay enum model).
- `truncate_space(tag)` — translate.cc:776.
- `construct_float_extension_address(real_addr, real_size, logical_size)`
  — translate.cc:792.
- `construct_join_address(hi_addr, hi_sz, lo_addr, lo_sz,
  exact_register_name)` — translate.cc:817.
- `renormalize_join_address(addr, size)` — translate.cc:870.
- `parse_address_simple(val)` — translate.cc:923.
- `set_default_code_space(index)` — translate.cc:309.
- `set_default_data_space(index)` — translate.cc:323.
- `insert_space(spc)` — translate.cc:352 (RUDRA-GLUE: the
  `name_type_mismatch` branch is dropped because Rugra's enum variants
  carry their type; duplicate-name / duplicate-id checks remain).
- `resolve_constant(spc, val, sz, point, full_encoding)` — translate.cc:628.
- (private) `assign_shortcut(spc)` — translate.cc:517.

### Translate (translate.hh:299)

#### `pub enum UniqueLayout`

Tagged regions of the `unique` address space. Faithful to
`Translate::UniqueLayout` (translate.hh:302-308).

Variants: `RuntimeBooleanInvert` (0), `RuntimeReturnLocation` (0x80),
`RuntimeBitrangeEa` (0x100), `Inject` (0x200), `Analysis` (0x10000000).

#### `pub trait Translate`

The processor translation engine. In Ghidra this inherits from
`AddrSpaceManager`; Rugra uses composition (`manager`/`manager_mut`).

- `fn manager(&self) -> &AddrSpaceManager` / `fn manager_mut(&mut self)`
  — RUDRA-GLUE for the inherited base.
- `fn is_big_endian(&self) -> bool` — translate.hh:586.
- `fn get_alignment(&self) -> i32` — translate.hh:596.
- `fn get_unique_base(&self) -> u32` — translate.hh:603.
- `fn get_unique_start(&self, layout: UniqueLayout) -> u32` — translate.hh:611
  (provided default method; `Analysis` returns the raw layout value, others
  add `unique_base`).
- `fn get_float_format(&self, size: usize) -> Option<&FloatFormat>` —
  translate.cc:979.
- `fn initialize(&mut self, store: &mut crate::marshal::DocumentStorage)`
  — translate.hh:332 (pure virtual). The concrete `DocumentStorage`
  (marshal.rs; xml.cc:2435-2478) is passed by mutable reference exactly like
  the C++ non-const `DocumentStorage &store` parameter. Implementations
  consume it via `getTag` (Sleigh reads the `<sleigh>` tag registered by
  `SleighArchitecture::buildSpecFile`, sleigh_arch.cc:409-417, and throws
  `LowlevelError("Could not find sleigh tag")` on a miss, sleigh.cc:558-561;
  GhidraTranslate mirrors this at ghidra_translate.cc:35-41).
- `fn register_context(&mut self, name, sbit, ebit)` — translate.hh:344
  (default no-op).
- `fn set_context_default(&mut self, name, val)` — translate.hh:353
  (default no-op).
- `fn allow_context_set(&self, val)` — translate.hh:363 (default no-op).
- `fn get_register(&self, nm) -> VarnodeData` — translate.hh:370.
- `fn get_register_name(&self, base, off, size) -> String` — translate.hh:380.
- `fn get_exact_register_name(&self, base, off, size) -> String` —
  translate.hh:390.
- `fn get_all_registers(&self, reglist: &mut HashMap<VarnodeData, String>)`
  — translate.hh:398.
- `fn get_user_op_names(&self, res: &mut Vec<String>)` — translate.hh:408.
- `fn instruction_length(&self, baseaddr) -> i32` — translate.hh:417.
- `fn one_instruction(&mut self, emit: &mut dyn PcodeEmit, baseaddr) -> i32`
  — translate.hh:432 (the main pcode translation entry point).
- `fn print_assembly(&mut self, emit: &mut dyn AssemblyEmit, baseaddr) -> i32`
  — translate.hh:442 (the main disassembly entry point).

### DocumentStorage (unified, TRANSLATE-DOCSTORE-UNIFY-0001)

`Translate::initialize` consumes the concrete
`crate::marshal::DocumentStorage` — the 1:1 twin of Ghidra's
`DocumentStorage` (`xml.hh:258-291`, `xml.cc:2435-2478`) with
`parse_document` / `open_document` / `register_tag` / `get_tag` (see
`docs/api/marshal.md`). The former local RUDRA-GLUE trait stub
(`next_document(&mut self) -> Option<String>`, which had no Ghidra
counterpart — Ghidra exposes no `nextDocument`) was removed on 2026-08-16.
Behavior is pinned by the `translate_docstore_1204` oracle fixture: the
`Sleigh::initialize` DocumentStorage prologue (missing-tag message,
content-as-path open error, same-name overwrite through `registerTag`,
name-keyed lookup) is byte-identical against the locked 12.0.4 oracle.

## 2026-08-11 ANN-J annotation bootstrap

This pass only added source provenance; it did not change behavior and does
not establish `MATCH` or L3:

- `is_contiguous` is anchored to `pcoderaw.cc:73
  VarnodeData::isContiguous`. The oracle calls the concrete space's
  `isBigEndian()` and `wrapOffset()`; Rugra still depends on its flat
  `AddressSpace` model, so endian/wrap branches remain unproven.
- `TruncationTag::new`, `AddrSpaceManager::fmt`, `addr_mask_for`, and
  `Translate::manager_mut` are explicit Rust glue. The annotation pass had
  also listed `DocumentStorage::next_document` as glue; that invented trait
  stub was removed by TRANSLATE-DOCSTORE-UNIFY-0001 (2026-08-16) in favor of
  the concrete `marshal::DocumentStorage` (Ghidra's `DocumentStorage` exposes
  `parseDocument/openDocument/registerTag/getTag`; it has no `nextDocument`).
- `addr_mask_for` is not `AddrSpace::wrapOffset`: it derives a bit mask from
  Rugra's current address-size accessor and cannot preserve all descriptor and
  signed-remainder semantics.

Canonical Ghidra 12.0.4 runtime fixtures for these paths are still missing;
the formal behavior status is `NO_ORACLE`.

## 对齐说明 (Alignment Notes)

- **Inheritance → composition**: Ghidra's `Translate : public AddrSpaceManager`
  is modeled as composition in Rust (`Translate::manager` / `manager_mut`).
- **`SpacebaseSpace : public AddrSpace`**: Rugra's enum address spaces carry
  the space identity, so `SpacebaseSpace` holds only the spacebase-specific
  state.
- **Panics for `LowlevelError`**: Ghidra throws `LowlevelError` in several
  methods (`get_spacebase`, `find_join`, `insert_space`, etc.). Rugra
  panics with the same messages, preserving the control-flow contract.
  Callers that prefer `Result` can wrap these.
- **`decode_pcode_raw` placeholder**: returns `CPUI_COPY` until
  `PcodeOpRaw::decode` (pcoderaw.cc) is ported; kept as a free function so
  `PcodeEmit` stays object-safe.
- **Marshaling ids**: `ATTRIB_CODE`/`ATTRIB_CONTAIN`/`ATTRIB_DEFAULTSPACE`/
  `ATTRIB_UNIQBASE` and `ELEM_OP`…`ELEM_TRUNCATE_SPACE` use the exact numeric
  ids from translate.cc:20-34 so encoded streams stay wire-compatible.
  `ATTRIB_SPACE`/`ATTRIB_SIZE` are added (translate.cc references them but
  defines them elsewhere in marshal.cc).

## 依赖 (Dependencies)

- `crate::address::Address`
- `crate::float_emulate::FloatFormat`
- `crate::marshal::{AttributeId, Decoder, ElementId}`
- `crate::opcodes::OpCode`
- `crate::space::{AddressSpace, VarnodeData}`
- `std::collections::HashMap`


### 2026-08-15：SPACE-0001 translate 桥（架构动态 space 注册表接入）

- `AddrSpaceManager` 新增 `space_registry: crate::space::SpaceRegistry` 字段（Ghidra 单一
  AddrSpaceManager = Translate 基类；Rugra 过渡期为旧 enum 表 + 架构owned 双表，消费方在
  ADDRESS-0001 切换后收敛）。resolver/join 半部（resolvelist/splitset/splitlist）仍在旧 manager。
- 新增桥方法：
  - `insert_dyn_space(&mut self, spc: AddrSpace) -> Result<(), String>`（translate.hh:244
    insertSpace / translate.cc:352 经由注册表）；
  - `add_dyn_spacebase_pointer(&mut self, basespace, ptrdata, trunc_size, stack_growth)`
    （translate.hh:246 addSpacebasePointer / translate.cc:460）。
- 语义与错误消息与 Ghidra LowlevelError 逐字一致；oracle 证据见
  `tests/oracle/space_registry_1204.*` 与 `tools/run_space_registry_oracle.sh`。

### 2026-08-15：EXTERNAL-STUB-SUPPORT-0001 构造期 decode 注册（Ghidra translate.cc:257/285）

- 新增 marshal 常量 `ATTRIB_NAME`("name",14, marshal.cc:1241)、`ATTRIB_INDEX`("index",10,
  marshal.cc:1237)、`ATTRIB_BASE`("base",89, space.cc:21)（与既有
  `ATTRIB_DEFAULTSPACE`("defaultspace",45) 配套）。
- `impl crate::space::SpaceRegistry`（在本模块，因 ELEM/ATTRIB 常量居此、space.rs 引入本模块
  会成环）：
  - `decode_space(&mut self, decoder)`（translate.cc:257-275 AddrSpaceManager::decodeSpace）：
    peek element id → `space_base`/`space_unique`/`space_other`/`space_overlay`/plain
    `AddrSpace(m,t,IPTR_PROCESSOR)` 分派；space_base 的 `contain` 与 space_overlay 的
    `base` 属性按 `Decoder::readSpace`（marshal.cc:400-409）经本 manager 名字解析，缺失
    返回 `Err("Unknown address space name: X")`（Ghidra DecoderError）。
  - `decode_spaces(&mut self, decoder)`（translate.cc:285-303 AddrSpaceManager::decodeSpaces）：
    先 `insert_space(new ConstantSpace)`；`<spaces defaultspace=...>` 属性逐子 decode+insert；
    末尾按名字查 default space（缺失 `Err("Bad 'defaultspace' attribute: X")`）并
    `set_default_code_space(index)`。insert/setDefault 的 LowlevelError 原样向外传。
  - `named_attrib_id(id, name)`（RUDRA-GLUE）：const `AttributeId` 不能保留 name，而
    TreeDecoder 的 `read_*_attr` 按 name 定位；decode 路径重建运行时具名 twin。
- Oracle 证据：`tests/oracle/external_stub_1204.{cc,rs}` + `tools/run_external_stub_oracle.sh`
  （锁定 12.0.4，7 case 逐字节 MATCH）。EXTERNAL 工件语义考证（12.0.4 无 IPTR_EXTERNAL；
  Java AddressSpace.java:80 + ElfProgramBuilder.java:1532 人工 EXTERNAL 内存块 + 
  DecompileCallback.java:417 拒绝反汇编 → flow.cc:446 BadDataError → halt_baddata）记录于
  `docs/api/space.md` 同日小节。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 2 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。
