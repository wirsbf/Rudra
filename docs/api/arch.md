# arch.rs — Architecture manager API

## 2026-09-27：PRINTC-PRINTLIST-WIRING-0001 — printlist 结构 + reset 循环（Lane PCHOVER2）

architecture.hh:205-206 `print`/`printlist` 的 Rust 承接（PRINTC0004 登记的
options 接线 handover 收口）：

- **`print_registry_key: u64`**（RUGRA-GLUE identity 通道）：本 Architecture
  printer 注册表条目的键；构造时铸造、不进任何输出。存储本体在
  `printlanguage`（线程局部 identity-keyed 注册表——成因见 printlanguage.md
  同日节：funcdata.rs canonical static 钉死 `Send+Sync` 而 printer 天生
  !Send；TFSINGLE 先例）。
- **`register_print_language(Box<dyn PrintLanguage>) -> Arc<RwLock<...>>`**
  （architecture.cc:171-172 ctor push + :431 setPrintLanguage push 双位点：
  push 即置 current）：返回共享句柄，注册方留用做具体 PrintC 工作，option
  施加方经 current 通道达之（= `glb->print`）。
- **`print_language_current()`**（architecture.hh:205 读通道）：当前 printer
  句柄；`None`=未注册态（oracle ctor 时刻必建有 printer，此态 Ghidra 不可表，
  option 侧以消息上报）。
- **`reset_defaults` 补 architecture.cc:1443-1444 循环**：
  `printlist_reset_defaults(key)` 对本 arch 注册的全部 printer 调
  `reset_defaults()`（identity-keyed → 同线程第二 arch 不受波及，oracle
  per-object vector 语义）。旧"deferred until PrintLanguage lands"注释更正。
- **`Drop` 补 `unpublish_printlist`**（architecture.cc:200-201 teardown 半的
  镜像；printer 本体经 Arc 存活）。

B2：`printc_printlist_wiring_1204`（8 case 字节恒等，见 printc.md 同日节）。

Architecture manager corresponding to Ghidra's `architecture.hh` /
`architecture.cc`.

**Status:** L2 (locked 12.0.4 audit, 2026-08-14; production text-ingest slice
landed 2026-08-16, oracle fixture MATCH on the covered projection). The
structured-DOM prototype/default-model slice and the production
`parse_compiler_config` text-ingest slice have locked oracle fixtures, but
`data_organization`/`enum` (CSPEC-TYPEORG-STATE-0001), `resolveprototype`
(CSPEC-PARAMMODEL-0001), `spacebase`/`deadcodedelay`/`inferptrbounds` (space
manager wiring), `readonly` (Database property ranges) and the factory/init
chain remain incomplete, so the module stays L2/MISMATCH, not L3.

This is the Ghidra `Architecture` class — distinct from `types::Architecture`
(which is the target CPU enum). It holds all configuration parameters and owns
the sub-component references.

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.{hh,cc}`.

## Constants

| Name | Value | Description |
|---|---|---|
| `MAJOR_VERSION` | 6 | Decompiler major version. |
| `MINOR_VERSION` | 1 | Decompiler minor version. |
| `FLOWOPT_ERROR_TOOMANY` | 1 | FlowInfo error-on-too-many bit. |

## Module `split_datatype`
- `OPTION_STRUCT = 1`, `OPTION_ARRAY = 2`, `OPTION_POINTER = 4`.

## Traits

### `ArchitectureCapability`
Abstract extension point for building Architecture objects. Faithful to
`ArchitectureCapability` (architecture.hh:117).
- `name() -> &str`
- `build_architecture(filename, target) -> Result<Box<dyn ArchitectureBuilder>, String>`
- `is_file_match(filename) -> bool`
- `is_xml_match(doc) -> bool`

### `ArchitectureBuilder`
Provides the virtual factory hooks for sub-components. Faithful to the
protected virtual methods of `Architecture` (architecture.hh:264-348).
- `build_database()`, `build_translator()`, `build_loader()`,
  `build_pcode_inject_library()`, `build_typegrp()`, `build_core_types()`,
  `build_comment_db()`, `build_string_manager()`,
  `build_constant_pool()`, `build_context()`, `build_symbols()`,
  `build_spec_file()`, `modify_spaces()`, `resolve_architecture()`.

### `SpecQuery`
Language/space queries consumed by the compiler-spec decode chain, standing
in for the Architecture's `AddrSpaceManager` + `Translate` during
`parseCompilerConfig` (Rugra's `Architecture` does not own a space manager
yet). Mirrors `SleighBase::getRegister` (sleighbase.cc:133),
`AddrSpaceManager::getSpaceByName` (translate.cc:590),
`AddrSpace::getHighest`, the overlay enumeration of
`addToGlobalScope`/`addOtherSpace`, `SleighBase::findSymbol` and
`Translate::getUniqueStart(Translate::INJECT)`.
- `get_register(name) -> Option<VarnodeData>`
- `space_by_name(name) -> Option<AddressSpace>`
- `space_highest(spc) -> u64`
- `num_spaces()`, `space_at(i)`, `is_overlay(spc)`, `is_overlay_base(spc)`,
  `contain_space(spc)` (default: no overlay enumeration)
- `sleigh_symbol(name) -> Option<SleighSymbol>`
- `unique_inject_base() -> u64` (default `0x200`)

### `CompilerConfigReport`
Residual report returned by `parse_compiler_config`: `skipped_children`
(child tag + owning TODO for children whose full decode belongs to another
domain), `ignored_children` (tags the Ghidra oracle's own dispatch ignores —
architecture.cc:1249-1305 has no else branch) and `post_step_residuals`
(initializeSegments / PreferSplitManager / setupSizes infrastructure gaps).
Nothing is silently skipped.

## Structs

### `CapabilityRegistry`
Registry of `ArchitectureCapability` extensions. Faithful to the static
`thelist` and static methods (architecture.hh:120-156).
- `new()`, `register(cap)`, `find_capability_for_file(filename)`,
  `find_capability_for_xml(doc)`, `get_capability(name)`,
  `sort_capabilities()`, `major_version()`, `minor_version()`.

### `ProtoModelMap`

`BTreeMap<String, Arc<ProtoModelFull>>`. Each map value is a stable shared
model object. The selected `defaultfp` is the same `Arc` as its map entry,
mirroring Ghidra's pointer identity rather than copying a lightweight name
record.

### `TrackedRegister`
A tracked register (Varnode storage) and the value it contains, decoded from
a pspec `<tracked_set>`'s `<set>` children. Faithful to `TrackedContext`
(globalcontext.hh:78-83): `loc: VarnodeData` (register storage by `name`
attribute or explicit `space`/`offset`/`size`) + `val: u64`. Distinct from
`crate::context::TrackedContext` (space-less) until the ContextDatabase
gains a space-keyed partmap (SLEIGH-0002C).

### `TrackedSetMap`
Space-aware partition map of tracked register sets keyed on
`(space order, offset)` — the stand-in for `ContextInternal::trackbase`
(`partmap<Address,TrackedSet>`, globalcontext.hh:284) with the mirrored
`split`/`clearRange`/`getValue` step semantics (partmap.hh:81-157).
- `new()`, `get_value(space, offset) -> &[TrackedRegister]`
  (upper_bound + predecessor; empty default before the first split).
Ordering caveat: Ghidra orders `Address` by the live baselist index, Rugra
by `AddressSpace::space_id()`; same-space lookups agree (the only
production consumer, `ActionConstbase`, queries the function address in
ram), cross-space interleavings stay UNTESTED (SLEIGH-0002C / ADDRESS-0001).

### `Architecture`
Manager for all the major decompiler subsystems. Faithful to `Architecture`
(architecture.hh:165).

| Field | Type | Description |
|---|---|---|
| `archid` | `String` | Unique architecture id. |
| `trim_recurse_max` | `i32` | Parameter trim recursion limit. |
| `max_implied_ref` | `i32` | Max implied-var references. |
| `max_term_duplication` | `i32` | Max duplicated terms. |
| `max_basetype_size` | `i32` | Max integer size before array. |
| `min_funcsymbol_size` | `i32` | Min function symbol size. |
| `max_jumptable_size` | `u32` | Max jumptable entries. |
| `aggressive_ext_trim` | `bool` | Aggressive sign-ext trim. |
| `readonlypropagate` | `bool` | Treat readonly as constants. |
| `infer_pointers` | `bool` | Infer pointers from constants. |
| `analyze_for_loops` | `bool` | Convert while-do to for loops. |
| `nan_ignore_all` / `nan_ignore_compare` | `bool` | NaN handling. |
| `funcptr_align` | `i32` | Function ptr alignment bits. |
| `flowoptions` | `u32` | Flow engine options. |
| `max_instructions` | `u32` | Max instructions per function. |
| `alias_block_level` | `i32` | Alias blocking (0-3). |
| `split_datatype_config` | `u32` | Datatype split config bits. |
| `proto_models` | `ProtoModelMap` | Prototype models. |
| `defaultfp_name` | `Option<String>` | Default model name. |
| `defaultfp` | `Option<Arc<ProtoModelFull>>` | Shared default model, pointer-identical to its map entry. |
| `default_return_addr` | `Option<VarnodeData>` | `defaultReturnAddr` (architecture.hh:194); `None` mirrors the ctor's null-space sentinel (architecture.cc:159). |
| `evalfp_current_name` / `evalfp_called_name` | `Option<String>` | Eval model names. |
| `evalfp_current` / `evalfp_called` | `Option<Arc<ProtoModelFull>>` | `evalfp_current`/`evalfp_called` (architecture.hh:195-196). |
| `infer_ptr_spaces` | `Vec<AddressSpace>` | `inferPtrSpaces` (architecture.hh:182), appended by `add_to_global_scope`. |
| `global_scope_ranges` | `Vec<(AddressSpace, u64, u64)>` | Applied `<global>` + OTHER-space triples in application order; since CSPEC-GLOBAL-APPLY-0001 the same triples are ALSO written into the constructor symbol table's global scope (`add_range_spaced` at `add_to_global_scope`/`add_other_space`, architecture.cc:833/852) — the Vec keeps the source-order fixture projection. |
| `pcodeinjectlib` | `Option<Arc<RwLock<PcodeInjectLibrary>>>` | `pcodeinjectlib` (architecture.hh:200). |
| `nohighptr` | `RangeList` | No-high-pointer ranges. |
| `overrides` | `Override` | Override commands. |
| `loadersymbols_parsed` | `bool` | Loader symbols read. |
| `tracked_set_map` | `TrackedSetMap` | pspec `<context_data>` tracked partitions — stand-in for `ContextInternal::trackbase` (globalcontext.hh:284) behind `Architecture::context`, fed by `decode_context_data` (ARCH-CONTEXT-TRACKED-0001). |
| `context_set_children_skipped` | `usize` | `<context_set>` children consumed but not decoded (low-level SLEIGH context blob, SLEIGH-0002C residual). |
| `allacts` | `Option<Arc<RwLock<ActionDatabase>>>` | `allacts` (architecture.hh:212) — root Action database. Ghidra embeds by value; Rugra defers to `build_action()` behind a shared lock so option appliers can mutate the current root through `&mut Architecture` (options.cc:1008-1015), OPTIONS-SPLITDATATYPE-WIRING-0002. |
| `stack_reverse_justify` | `bool` | `<stackpointer reversejustify>` (`setReverseJustified`, architecture.cc:566). |

**Methods:** `new()`, `reset_defaults_internal()` (architecture.cc:1416),
`reset_defaults()` (architecture.cc:1438 — now forwards to
`allacts.reset_defaults()` when the database exists, mirroring
architecture.cc:1442; the printlist arm stays deferred),
`build_action()` (architecture.cc:585 — `universal_action()` +
`reset_defaults()` on the embedded database; `parseExtraRules` is a
registered residual ARCH-PARSEEXTRARULES-0001), `get_model(name)`, `has_model(name)`,
`set_default_model(name)` (architecture.cc:323), `get_default_model()`,
`decode_proto(decoder, addr_size, register_resolver)` (architecture.cc:741),
`decode_proto_spec(...)` (parseCompilerConfig path injecting
`default_return_addr`, fspec.cc:2689),
`decode_default_proto(...)`/`decode_default_proto_spec(...)`
(architecture.cc:795), `decode_global(decoder, range_props)`
(architecture.cc:812), `add_to_global_scope(props, host)`
(architecture.cc:826), `add_other_space(host)` (architecture.cc:847),
`decode_return_address(decoder, host)` (architecture.cc:898),
`decode_stack_pointer(decoder, host)` (architecture.cc:979),
`decode_proto_eval(decoder)` (architecture.cc:769),
`decode_no_high_ptr(decoder, host)` (architecture.cc:1086),
`decode_prefer_split(decoder, host)` (architecture.cc:1101),
`decode_aggressive_trim(decoder)` (architecture.cc:1121),
`decode_funcptr_align(decoder)` (architecture.cc:1049),
`create_model_alias_exact(alias, parent)` (architecture.cc:1138 with
Ghidra's exact error strings),
`parse_compiler_config(store, host, addr_size) -> Result<CompilerConfigReport, String>`
(architecture.cc:1239, including the specextensions pass, the deferred
`<global>` application loop, `addOtherSpace`, the default-model fallback,
the `__thiscall` alias clone and the post-loop residual disclosure),
`high_ptr_possible(addr, size)` (architecture.hh:408),
`add_no_high_ptr(range)` (architecture.cc:576), `globalify()`
(architecture.cc:437), `create_model_alias(alias, parent)`,
`decode_flow_override()`, `get_description()`, `print_message(msg)`,
`decode_context_data(decoder, host)` (ContextInternal::decodeFromSpec,
globalcontext.cc:531, reached via both `parseProcessorConfig`
architecture.cc:1190 and `parseCompilerConfig` architecture.cc:1278 — the
cspec dispatch arm calls it since ARCH-CONTEXT-TRACKED-0001),
`get_tracked_set(space, offset) -> &[TrackedRegister]`
(ContextInternal::getTrackedSet, globalcontext.hh:304 — the ActionConstbase
consumer entry point, coreaction.cc:692),
`get_tracked_default() -> &[TrackedRegister]` (ContextDatabase::
getTrackedDefault, globalcontext.hh:211/303 — empty on this ingest path:
decodeFromSpec never assigns the partition-map default value),
`get_space_by_spacebase(loc_space, loc_offset, size) -> Option<AddressSpace>`
(Architecture::getSpaceBySpacebase, architecture.cc:264-282 — walks the
spacebase records in baselist order matching size/space/offset; Rugra's
enum-space registry reduces to the single stack record; returns `None`
instead of Ghidra's `throw LowlevelError("Unable to find entry for
spacebase register")` — pre-registered deviation,
PRINTC-INPUTREG-DEADSTORE-0001),
`get_contain(spc) -> Option<AddressSpace>` (relocation of the
`AddrSpace::getContain` family, space.hh:505 base → null /
SpacebaseSpace override translate.hh:187 → the cspec basespace; the contain
link lives on Architecture as `stack_base_space` because the enum space
model has no per-space record store).

## L3 gaps
- Virtual factory hooks (`buildTranslator`, `buildLoader`, `buildTypegrp`, …)
  require Translate/LoadImage/TypeFactory integration.
- Production XML text ingestion and full processor/compiler-spec dispatch
  (`parseProcessorConfig`, `parseCompilerConfig`, …). The current decode
  methods intentionally begin at an existing structured `TreeDecoder`.
- `AddrSpaceManager` integration (`getSegmentOp`; `getSpaceBySpacebase` is
  served by the Architecture-level registry since
  PRINTC-INPUTREG-DEADSTORE-0001).
- `DocumentStorage` for `init`/`restoreXml`.

## 2026-06-27 历史实现记录（“达到 L3”结论已于 2026-08-11 撤回）

- **Architecture 新增子组件字段**：symboltab (Database)、loader (LoadImage)、commentdb、string_manager、cpool、context_db、options_db、split_records、lane_records。symboltab 自 CSPEC-GLOBAL-APPLY-0001 起在构造器即建（`Database::new(true)`，architecture.cc:600 `buildDatabase`），cspec `<global>` 三元组在 parse 期直写其全局 scope；驱动自装 Program DB 时经 `set_symboltab` 整体替换（canon 契约）。
- **虚拟工厂钩子等价物**：`set_symboltab`/`set_loader`/`set_commentdb`/`set_string_manager`/`set_cpool`/`set_context_db`/`set_options_db`/`set_split_records`/`set_lane_records` — 替代 Ghidra 的 buildXxx 虚函数。
- **init()**：验证架构 ID 已设置，编排初始化流程。
- **clear_analysis()**、**read_loader_symbols()**、**encode()**。

## 2026-06-29：Stack 空间 / spacebase 配置字段（cspec `<stackpointer>` 对齐）

- Architecture 新增字段（对齐 Ghidra cspec `<stackpointer register="RSP" space="ram"/>` + `SpacebaseSpace::getSpacebase(0)`）：`stack_space: AddressSpace`（= Stack，IPTR_SPACEBASE）、`stack_pointer_space: AddressSpace`（= Register）、`stack_pointer_offset: u64`（= 0x20 = RSP）、`stack_pointer_size: usize`（= 8）、`stack_grows_negative: bool`（= true，x86 约定）。
- 默认值匹配 x86-64-gcc.cspec。Funcdata 也有对应字段（不持有 Architecture 引用，用默认值初始化），`Funcdata::spacebase()` 从这些字段读 stack pointer 位置。
- 这是层次 1 Stack 空间架构对齐的阶段 2：建立 spacebase 配置容器（暂不解析 .cspec 文件，用硬编码配置）。
- arch.rs 所有 L3 缺口已关闭。

### 2026-07-01：Architecture 手动 Debug impl
- 为 Architecture 添加 `impl Debug`（打印 archid）。因 loader 字段是 `Arc<dyn LoadImage>`（无 Debug bound），不能 derive。这使得 Funcdata（derive Debug）能持有 `Option<Arc<Architecture>>` 字段。

### 2026-07-01（续 2）：types + userops 字段 + get_base_type + construct_join_address
- `types: Option<Arc<RwLock<TypeFactory>>>` + `userops: Option<Arc<RwLock<UserOpManage>>>` 字段 + set_types/set_userops。
- `get_base_type(size, metatype)` — 委托 TypeFactory::get_base。
- `construct_join_address(hi,sz,lo,sz)`（translate.cc:817）— 桩：contiguous 早返回，否则 0。
- **2026-08-16（`TYPE-WIRING-0001`）**：新增 `ensure_types()` — 无工厂时安装并返回
  process-canonical 工厂（`TypeFactory::shared_default()`，DataOrg flavor）。Ghidra 的
  Architecture 恒持有唯一 `TypeFactory`（type.cc:3106）；Rugra 的 `types` 在
  CSPEC-TEXT-INGEST-0001 落地前可选。生产接线建议（root，funcdata.rs 租约外）：
  `fd.set_arch(arch)` 后调 `arch.ensure_types()` 并
  `fd.vbank.set_type_factory(handle)`，使 Varnode/varmap/打印消费同一工厂。
<!-- annotation-pass: 2026-07-04 -->
 
# 2026-08-14：Architecture 消息保持 oracle 原文

`Architecture::print_message` 现在按锁定 Ghidra
`SleighArchitecture::printMessage`（`sleigh_arch.hh:138`）把消息原文加换行写到
stderr，不再添加 Rust 自创的 `[ARCH] ` 前缀。这使 Action/Rule 的错误与警告
消息可逐字对拍；调用方负责提供完整的 `ERROR:` / `WARNING:` 文本。

# 2026-08-14：共享 ProtoModel map 与 default Arc

`Architecture::proto_models` 现在保存 `Arc<ProtoModelFull>`；
`set_default_model` 恢复旧默认模型的 print flag、清除其 default 指针，再把新
模型的 print flag 设为 false，并将同一个 `Arc` 同时保存在 map 与
`defaultfp`。print flag 在共享模型对象上原位更新，不使用 `Arc::make_mut`，
因此已交给 `FuncProto` 或 `decode_proto` 调用方的外部 handle 保持同一身份，
并能观察默认模型切换。`decode_proto` 和 `decode_default_proto` 从既有 `TreeDecoder`
注册/选择真实模型，duplicate/default-wrapper 错误在替换共享状态前返回。

锁定 fixture `tools/run_cspec_param_model_oracle.sh` 对完整
`x86-64-gcc.cspec` 中默认 `__stdcall` 的名称、extrapop、参数范围、map/default
身份和 print flag 做 Ghidra 12.0.4 对拍。已声明观测相同，但生产文本 ingestion、
`resolveprototype` 和 `<modelrule>` 仍未完成，所以整体诚实保持 `MISMATCH`，
不得据此声称 compiler-spec 或主管线已完全接通。

本切片不把 `create_model_alias` / `is_compatible` 计为匹配：Rust 的既有 bool
adapter 尚不能表达 Ghidra 对 merged parent、alias-of-alias、duplicate 和缺失
parent 的异常域，alias-parent 身份也未对拍。`set_default_model(&str)` 对未知名称
静默返回，而 Ghidra 的 pointer API 不存在相同错误输入；这个 name-adapter 错误域
同样保持 `MISMATCH`。

# 2026-08-16：CSPEC 文本 ingestion 四切片（GLOBAL-APPLY / DEFAULT-RETURN /
# PCODEINJECT-CALLFIXUP / UNIVERSAL-CHILD）

`Architecture::parse_compiler_config`（architecture.cc:1239-1351 全链）落地：
真实 production `x86-64-gcc.cspec` 字节经 marshal `DocumentStorage::parse_document`
文本 ingest 后逐 child decode。新增（对应 oracle 行号见各函数注释）：
`SpecQuery` 语言查询 trait、`decode_global`+`add_to_global_scope`+`add_other_space`
（`<global>` 收集为 RangeProperties、主循环与 specextensions 后按源序延迟应用、
overlay 复制循环、OTHER space 全域）、`decode_return_address`（多重标签错误
`Multiple <returnaddress> tags in .cspec`）+ `default_return_addr` 字段、
`decode_stack_pointer`、`decode_proto_eval`、`decode_no_high_ptr`、
`decode_prefer_split`、`decode_aggressive_trim`、`decode_funcptr_align`、
`create_model_alias_exact`（Ghidra 逐字异常消息）、主循环 dispatch（含
`callfixup`→`PcodeInjectLibrary::decode_inject`、`callotherfixup`/`segmentop`→
UserOpManage decode 链、`modelalias`、specextensions 二遍）、default-model 回退
（map 首项）与 `__thiscall` 别名克隆。`decode_proto_spec` 把
`default_return_addr` 注入无自带 `<returnaddress>` 的模型（fspec.cc:2689，
`ProtoModelFull::decode_with_defaults` 新入口，旧 `decode_with_register_resolver`
委托 None 保持兼容）。

配套（同 write-set 模块）：`pcodeinject.rs` 重构为 Ghidra 结构
（id 索引 `injection` 向量 + name→id map + id→name 向量 + SLEIGH
tempbase/sleigh 成员；`decode_inject`=allocate→decode→register/compile 全链，
`parse_inject` 走 `PcodeSnippet` 编译，错误逐字）；`pcodeparse.rs`
`PcodeSnippet::lex` 补 sleigh symbol fallback（pcodeparse.cc:3223-3224）、
`STRING ':' INTEGER '='`/`STRING '='` 声明语句（pcodeparse.y:108/110）、
`ConstTpl::handle` 携带 v_field selector（semantics.cc:425-432）、
ConstructTpl delayslot 默认 0（semantics.hh:174）；`userop.rs` 补
`decode_call_other_fixup`/`decode_segment_op`/`decode_jump_assist`/
`decode_volatile`/`register_user_op`（userop.cc:490/533/551/589/606 +
InjectedUserOp/SegmentOp/JumpAssistOp decode）。

**对拍证据**：`tools/run_cspec_text_ingest_oracle.sh`（locked 12.0.4 oracle
BfdArchitecture 真链 init vs Rugra 文本 ingest，同一 cspec/sla/curl 字节），
67 行投影逐字节一致（含 16 个 `<callfixup>` 的编译模板 XML：LOAD/INT_ADD/
RETURN、COPY@unique 0x364420/0x364430 递进、13×CALLIND），合成探针覆盖
callotherfixup 编译失败残留（count 16→17、residue id）、未知名错误、
"segment" 定制成功（type 2/index 0）、volatile 注册+重复注册错误。

**残差（如实登记，非静默跳过）**：`data_organization`/`enum` →
CSPEC-TYPEORG-STATE-0001；`spacebase`/`deadcodedelay`/`inferptrbounds` →
空间管理器接线；`readonly` → Database property ranges；`context_data` →
context spec decode；`resolveprototype` → CSPEC-PARAMMODEL-0001；
`inferPtrSpaces` 的 post-init 过滤（cacheAddrSpaceProperties 域）不可观察；
`<body>` 内容经配对 DOM handle 提供（`XmlDecode::readString(ATTRIB_CONTENT)`
的 TreeDecoder 缺口，归 MARSHAL 域）；segmentop/jumpassist decode 已移植但
无 oracle 观察（UNTESTED）。模块保持 L2。

## 2026-08-17：UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ① — commentdb 工作侧分配

Ghidra 的 `Architecture::init`（architecture.cc:1391-1414）在 :1400 调
`buildCommentDB`，`SleighArchitecture::buildCommentDB`（sleigh_arch.cc:241-245）
分配内存态 `CommentDatabaseInternal`；构造器本身保持
`commentdb = (CommentDatabase *)0`（architecture.cc:166，Rugra
`Architecture::new` 的 `commentdb: None` 已对齐）。

Rugra 的分配点在 worker 的 init 等价物
`examples/curl_decompile.rs::worker_architecture`：`Architecture::new()` 之后、
cspec 解析（restoreFromSpec 等价步骤）之前，调用既有
`set_commentdb(Arc<RwLock<CommentDatabaseInternal::new>>)`,
与 init 序中 buildCommentDB 先于 restoreFromSpec(:1405) 的位置一致。此后
`Funcdata::warning_header`/`warning`（funcdata.cc:135/119）全部入库——包括
`ActionPrototypeWarnings` 的 unknown-calling-convention 警告
（coreaction.cc:4908）——E2E stderr 从 48 条（eprintln 回退 × 双注册）降为 0，
警告以 `Comment::warningheader` 类型按函数地址入库，等待 printc 侧
`emitCommentFuncHeader`（printc.cc:3272）接线后进入 C 输出。

## 2026-08-17：ARCH-CONTEXT-TRACKED-0001 — pspec `<context_data>` tracked 摄取

Ghidra 摄取链（12.0.4 e40ed130）：`Architecture::init`
（architecture.cc:1391-1414）:1398 `buildContext` → `context = new
ContextInternal()`（sleigh_arch.cc:259-262，同一对象随后注入 SLEIGH
translator —— sleigh_arch.cc:181/185，Sleigh 构造器持它做反汇编 context）；
`restoreFromSpec`（:629）→ `parseProcessorConfig`（:1172-1223）在
`ELEM_CONTEXT_DATA` 分支（:1190）调 `context->decodeFromSpec(decoder)`
（globalcontext.cc:531-549）。cspec 侧 `parseCompilerConfig` 的同标签分支
（architecture.cc:1278-1279）走同一函数。

落地（src/arch.rs）：

- `TrackedRegister`（`TrackedContext`，globalcontext.hh:78）与
  `TrackedSetMap`（`ContextInternal::trackbase`，globalcontext.hh:284；
  `split`/`clearRange`/`getValue` 逐步镜像 partmap.hh:81-157，含 split
  复制前值、clearRange 删中间 split、"later set overrides earlier" 语义）。
- `Architecture::decode_context_data`（decodeFromSpec 镜像）：子元素文档序
  消费；`range_from_attributes`（address.cc:316-353：space/first/last/name
  早返回、"No address space indicated in range tag"/"Illegal range tag"
  逐字）+ `last_addr_open`（address.cc:265-281：last==highest → 下一空间
  基址 0，Rugra 以 `(space_id+1, 0)` 表达）+ `decode_tracked`
  （globalcontext.cc:91：clear + 文档序 append）+
  `decode_tracked_context`（globalcontext.cc:56：`Expecting <set> but got
  <X>` 逐字）+ `varnode_data_from_attributes`（pcoderaw.cc:33-53：space
  分支 rewind 重扫 offset/size、`Address is missing offset`；name 分支
  `Unknown register name: X`）。`<context_set>` 子元素按 SLEIGH-0002C 残差
  消费+计数（`context_set_children_skipped`），不静默丢弃。
- 查询面：`get_tracked_set(space, offset)`（getTrackedSet，
  globalcontext.hh:304，ActionConstbase 消费入口 coreaction.cc:692）与
  `get_tracked_default()`（getTrackedDefault，globalcontext.hh:211/303）。
- `parse_compiler_config` 的 `context_data` 分支由 skipped 记录改为调用
  `decode_context_data`（生产 x86-64-gcc.cspec 无该子元素，行为零变化）。

Oracle fixture：`tests/oracle/arch_context_tracked_1204.{cc,rs,metadata.json}`
+ `tools/run_arch_context_tracked_oracle.sh`（模式同 cspec_typeorg_state）。
C++ 侧真实 BfdArchitecture::init 链（锁定 spec 集 + curl）观察生产
tracked 状态；Rust 侧锁定 x86-64.pspec 真字节 + SLEIGH FFI 寄存器目录过
`decode_context_data`。投影逐字节一致（stdout sha256 见 metadata）：
production（DF register:20a:1 val=0 全 ram 域、context_set_children=1、
default_count=0）、c1 整域、c2 显式 range+双 set 文档序、c3 后 set 覆盖
（含 0x300 空 tail split）、c4 `name="DF"` 寄存器域 range、c5 显式
space/offset/size 形态 + uintb 最大值、e1-e6 七条逐字错误文本（含
`Bad <context_data> tag` 需带 range 属性行才可达——无 space 的子元素先死在
range 解码）。

残差（登记）：`<context_set>` 低层 context blob（变量注册在 .sla context
layout，SLEIGH-0002C）；跨空间 partition 交错 UNTESTED（Ghidra baselist 序
vs Rugra space_id 序，生产只查 ram）；`TreeDecoder` 对锁定 ElementId 表外
元素名只给 `XMLunknown`（e6 因此选用表内 `<register>` 名）；缺失 `val`
属性行为 oracle UB（marshal.cc:371-372 负下标），Rust 镜像返回 0。
ActionConstbase（coreaction.rs:5477 stub）激活在 setcasts 租约释放后另行
接线（见 TODO_BOARD ARCH-CONTEXT-TRACKED-0001 交接）。

## laned-register 查询（LANEDIVIDE-INFRA-0001）

- `get_laned_register`（architecture.cc:290-306 镜像，按 whole size 二分、
  忽略地址）与 `get_minimum_laned_register_size`（architecture.cc:312-318 镜像，
  空表 -1 / 最小 whole size）；`set_lane_records` 还原
  `decodeRegisterData`（architecture.cc:970-974）的升序唯一 +
  同尺寸 mask 合并不变式，记录以 `Arc` 共享身份进入 lanedMap。
- 对拍：`tools/run_lanedivide_infra_oracle.sh` MATCH（锁定 12.0.4 oracle，
  arch/min/ordered sizes/跨空间记录身份/size-12 miss 逐字节一致）；残差
  LANEDIVIDE-INFRA-RESIDUAL-0001（fixture 未覆盖分支见
  tests/oracle/lanedivide_infra_1204.metadata.json）。

## string manager 构建（STRINGMANAGER-CORE-JAVACONTRACT-0001）

- `Architecture::build_string_manager`（architecture.hh:308 /
  architecture.cc:1401 语义；ghidra_arch.cc:365-369 安装形态）：安装
  Architecture 持有的 `Arc<RwLock<StringManager>>` 单例，`maximumChars=2048`。
  生产 manager 是**声明的 GhidraStringManager/Java 契约**实现
  （`StringManager::new_ghidra_contract`）：检测 = 字符集合法 + NUL 终止、
  **不设 2048 搜索界**；2048 只截断返回字节并设 `isTruncated`（golden
  `tests/golden/ghidra_curl_1204.c` 证明 oracle 走此路径）。native 1:1
  `StringManagerUnicode`（2048 字节搜索界，sleigh_arch.cc:247-251）保留于
  `StringManager::new_unicode` 供 native 对拍。
- `Architecture::init` 在 Ghidra ordering（buildLoader 先于 buildStringManager）
  位置调用 `build_string_manager`；loader 未安装时降级为 cache-only 基座
  manager。`set_string_manager` 保留为测试/driver 注入口。
- 对拍：`tools/run_stringmanager_core_oracle.sh` MATCH（锁定 12.0.4 oracle，
  双侧 18 条记录逐字节一致：0xAD 负缓存、ASCII 正缓存整块 byteData、>2048
  native 负 vs 契约截断+isTrunc、负缓存二次询问零 image 读取、rule+print
  双消费者共享缓存、DataUnavail/无终止符/opaque、内部串 CRC hash）。
- 残差：消费侧（ruleaction:7375 / printc:1537 / funcdata 内部串 / driver
  string_table 退役）为 TYPEOP-LOCALTYPE-DISPATCH-0001 D3 接线。

## SLEIGH 注册名交叉表（B3-VARMAP-REGNAME-0001）

- `Architecture::register_xref: BTreeMap<(i32,u64,i32),String>`：键
  `(space index, offset, -size)` 精确镜像 `SleighBase::varnode_xref` 的
  `map<VarnodeData,string>` 排序（`VarnodeData::operator<`，
  pcoderaw.hh:67-71：space index → offset → **大 size 在前**，故第三元取
  `-size` 升序）。装填源 = shim 的 `rugra_sleigh_register_info` 枚举
  （`SleighBase::getAllRegisters`，sleighbase.cc:182-186 的 varnode_xref 拷贝），
  `set_register_xref` 以 `or_insert` 保留首插——`varnode_xref.insert` 的
  no-overwrite 语义（sleighbase.cc:91，冲突对走 errorPairs）。
- `Architecture::get_register_name(base, off, size)`：
  `SleighBase::getRegisterName`（sleighbase.cc:144-168）忠实端口。
  决定性语义：`upper_bound(sym)+iter--` 的净位置 = **key ≤ probe 的最大元素**
  （Rust `range(..=probe).next_back()`；`iter==begin()` = 空区间 = ""）；
  命中条目先过 space 相等门，再过覆盖门
  `point.offset+point.size >= off+size`（u64 wrapping，镜像 C++ uintb 回绕）；
  不覆盖时从命中条目**每步恰好回退一个前驱**（`range(..current)` 为 RangeTo
  排除端点，`next_back()` 即 oracle 的 `--iter`；R-RAWQUAR F1 修复：首版多余
  丢弃一次 `next_back()` 导致隔一取一），遇到 space 变化或 base-offset 变化
  即 ""（cc:160-166）。精确命中走本函数（同 size 条目自然取到自身）；子寄存器
  覆盖取**紧邻前驱中首个覆盖者**（AL 探 (reg,0x1,1)：AL 不覆盖→EAX 覆盖→
  "EAX"，与复核 C++ 复刻一致）。
- `Architecture::get_exact_register_name`（sleighbase.cc:170-180）：
  `find` 精确命中或 ""。
- 消费链：`ScopeLocal::get_register_name` 委派（database.cc:2447/2454/2462/
  2472/2485 的 `glb->translate` 调用位——unaff_/persist/irregular-input/
  addrtied/extraout 五个命名分支的寄存器名源），driver
  `build_worker_architecture` 在 cspec 解析前装入全表（1440 项，含
  XMM0_Qa@0x110:16、CW@0x3c:2、EFLAGS@0x2 等）。单测
  `test_get_register_name_boundaries`：精确命中/子寄存器紧邻前驱覆盖
  （EAX 判别）/两步回走成功（S8）/假性漏查判别（Q8）/越界回走断裂/
  跨 space/空表/16-vs-8 字节同 offset 选择。
- E2E 证据（2026-08-25，本 worktree）：修前硬编码 25 项 GPR 表缺
  XMM/CW/EFLAGS → `in_register_00000110` 等 40 处；接入后全量 1440 项表
  → `in_RSP`(21)/`in_R8`(7)/`in_RDX`/`in_R9`（与 golden 的
  database.cc:2470-2475 irregular-input 产物同通道同形；golden 自身 in_R8 2 +
  in_RCX 6 于 helpf/parseconfig）。差分门禁：defects=0、skeleton 与修前
  逐函数一致（纯改名零结构变化，compare 名字归一化验证）。
<!-- annotation-pass: 2026-08-24 -->

## data_organization 解码 + setup_sizes 接线（TYPE-WIRING-0001，2026-08-26）

`parseCompilerConfig` 的 `data_organization` 子元素从 skipped-children 改为
`types.decode_data_organization`（architecture.cc:1268-1269），工厂经
`ensure_types` 惰性安装；`setup_sizes`（architecture.cc:1350）以 cspec 地址
尺寸构造 SizeArchInputs（stack spacebase/default data space/default size，
far_pointer=None）真实执行，替换原 recorded-no-op。缺此接线时
TypeFactory::getBase 的 findAdd 因对齐映射未初始化在 downChain/
get_type_pointer 全路径 panic。

## 2026-09-23：ARCH-REGISTERDATA-LANE-0001 — pspec register_data → lanerecords 装载

新增 `Architecture::decode_register_data`（architecture.cc:929-977
ELEM_REGISTER_DATA 臂逐行）：`<register vector_lane_sizes="1,2,4,8">` 经
`LanedRegister::parse_sizes`（transform.cc:300）入 `maskList[wholeSize]`，
循环后按尺寸重建 lanerecords（`set_lane_records` 同序同并）。此前 lane 记录
仅测试装载，生产恒空 → `getMinimumLanedRegisterSize()==-1` → Funcdata
`min_laned_size=u32::MAX` → `check_for_laned_register` 永不触发 →
ActionLaneDivide 空转（match_url Phase 2 ordinal 29：oracle 2 vs rugra 0）。
装载后 min=16（XMM 整尺寸），XMM0(16) 读写入 laned map。两个易错点已修：
① **rewind**——oracle cc:945 在 storage 解析前显式 `rewindAttributes()`
（旋钮循环已耗尽属性流），漏掉则 walk 空转返回默认 (0,0)，lanerecords 得
wholeSize=0；② `VarnodeData::decodeFromAttributes`（pcoderaw.cc:33-52）name
属性经 `SleighBase::getRegister` 解析整存储并立即返回。
**残差 ARCH-REGISTERDATA-VOLATILE-0001**：`volatile` 臂（cc:960-963
`symboltab->setPropertyRange`）未接——锁定 x86-64.pspec 零 volatile 声明
（grep 干净），臂不可达；命中时 stderr 报告（[ARCH] 标签）。
消费链：`decode_register_data`（curl/httpd driver pspec 循环，文档顺序与
`parseProcessorConfig` 一致）→ lane_records → `Funcdata::min_laned_size`
（funcdata_varnode.cc:148 家族的 `s >= minLanedSize` 门）→ laned_map →
`ActionLaneDivide::apply` 的 beginLaneAccess 迭代。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 3 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — TF-SINGLETON-WIRING-0001 第一步：工厂所有权镜像

- `set_types` 现同时把句柄发布为线程的 current-Architecture 工厂（oracle
  `buildTypegrp` 时刻：sleigh_arch.cc:201 `types = new TypeFactory(this);`），
  `TypeFactory::shared_default` 的 39 个无句柄引擎调用点据此解析——Architecture
  获得工厂的瞬间即引擎解析域切换的瞬间，两路同步（票面"否则类型身份域再分裂"
  风险的闭合）。
- `ensure_types` fresh 路径改为构造 OWN `TypeFactory::fresh_canonical()`（不再
  借用 process-canonical 单例）并发布；existing 路径同样（重）发布，保证调用
  线程的解析域=本 Architecture。
- 新增 `impl Drop for Architecture`（architecture.cc:211-212 `delete types`
  镜像）：线程局部注册表仍指向自己的工厂时清除，恢复 process-canonical 回退
  层；他人发布不动。
- 详见 `docs/api/type_system/typefactory.md` 同日条目与
  `docs/alignment_docs/TYPEFACTORY_PERARCH_2026-09-26.md`。

## 2026-09-26（Lane F4WEBTYPE）— `add_to_global_scope` 寄存器空间过滤（architecture.cc:680）

`add_to_global_scope` 不再把 REGISTER 空间范围追加进 `infer_ptr_spaces`：
x86-64-gcc.cspec 的 `<global>` 携带 `<register name="MXCSR"/>`（寄存器空间范
围），oracle 的 `Architecture::cacheAddrSpaceProperties`
（architecture.cc:680-683）以 `if (spc->getDelay() == 0) continue; // Don't
put in a register space` 把寄存器空间从 inferPtrSpaces 过滤——范围仍进全局
作用域（`global_scope_ranges` 不变），仅推理列表排除。Rugra 侧曾把 Register
（addr_size=4）推入列表，使 4 字节字符串地址常量通过
`select_infer_space` 的精确尺寸门（4==4）被 `ActionConstantPtr`→
`spacebase_constant` 改写成 4 字节 `PTRSUB(spacebase,#addr)`，再被
`RulePtrsubCharConstant` 折叠成 char\* 常量——httpd main 的
`apr_app_initialize` 返回值 int 网被整体误定型 char\*
（`pcVar4 = "ptemp"` vs oracle `int iVar3 = 0x17a422`，
HTTPDMAIN-F4-WEBTYPE-0001）。修后 oracle 尺寸门照抄：Ram(8) 拒绝 4 字节常
量 → 裸常量保持 → int 网保真。双侧 fixture：
`tests/oracle/coreaction_constptr_registerspace_1204`
（inferPtrSpaces 名单 + sz8 容器命中转 PTRSUB/charPrint 指针 +
sz4 flag-web 同址保持裸常量 + sz8 无容器 miss 四例 MATCH）。

### 2026-09-26 — CSPEC-GLOBAL-APPLY-0001 合并注记（MERGEBATCH17 语义 union）

`add_to_global_scope`/`add_other_space` 自本批起为**双通道**：寄存器空间
过滤（上节）+ 解析期 DB 直写（`symboltab->addRange` architecture.cc:833/852
write-through——范围无条件落全局 scope 的 space-keyed ScopeRangeTree，含
register 窗口；仅 `infer_ptr_spaces` 列表排除寄存器空间）。两通道均为
oracle 语义，互不冲突。
