# `fspec.rs` API Reference

`FuncProto` now represents Ghidra's resolved `ProtoModel *` with a shared
`Arc<ProtoModelFull>`. `copy_from` preserves exact model identity while
value-copying the local effect vector. `set_model` applies Ghidra's guarded
extra-pop update and sticky `hasThis` / constructor / auto-killed flags; a
null model resets extra-pop to `0x8000` without clearing those flags.
The legacy `calling_convention == "unknown"` string remains a compatibility
sentinel for existing pipeline consumers; pointer-presence observables such
as `has_model` and `print_raw` consult the resolved `Arc`, not that sentinel.

## PLTSTUB-WARNLOSS-0001 stack-placeholder gate

`FuncCallSpecs::create_placeholder` now performs only Ghidra's canonical
creation sequence: append a one-byte spacebase LOAD, record its CALL slot, and
mark the result as the placeholder. Duplicate suppression and the locked-stack
decision belong to `ActionFuncLink::funcLinkInput`; the former self-invented
guards were removed.

Call-effect lookup also follows the locked oracle: a non-empty local effect
list is a complete override, while an empty list delegates to the shared
model. Records are ordered by address-space index and offset (not Rust enum
declaration order), unique-space storage is always unaffected, size-zero
records cover their whole space, only fully contained ranges inherit an
effect, and constant-space addresses do not overlap ordinary records.

`ProtoModelFull::output` now owns a concrete output parameter-list variant
through `ParamListOutput`: the standard strategy dispatches to
`ParamListStandardOut`, while the register strategy dispatches to
`ParamListRegisterOut`. Output decode, assignment, recovery, possibility
queries, entry iteration, containment queries, and killed-by-call state all
flow through that one owned variant. `ParamTrial` also carries its complete
address space. `ParamActive::register_trial(Address, ...)` now requires the
address's architecture-owned space tag, projects its type/index without using
the space name, and fails closed without mutation when the address is
spaceless or unrepresentable. Known-space transitional callers use the
explicit `register_trial_in_space` bridge. Both paths preserve Ghidra's
1-based slot sequence and mark non-spacebase trials killed-by-call.

The locked differential fixture
`tools/run_funcproto_effect_model_oracle.sh` compares these observations
against Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`. Its Rust side is built from a
recorded Rugra HEAD archive with only `src/fspec.rs` overlaid, so concurrent
workspace source changes cannot enter the comparand. The covered slice is
`MATCH`; the module remains L2 because compiler-spec/loader attachment,
`ProtoStore` parity, likely-trash/injection copy state, and downstream
Funcdata parameter recovery are outside this atom. In particular this model
primitive alone does not claim to resolve the `GetStr` parameter-name/output
differences.

`FuncProto` also represents Ghidra's `voidinputlock` explicitly. An empty
parameter vector is therefore unlocked until `set_input_lock(true)` is called;
a known `f(void)` remains locked through analysis, while an empty stripped
prototype is still eligible for active recovery. `clearInput` clears the void
lock, `clearUnlockedInput` preserves an authoritative prototype as a whole,
and `copy` preserves the flag.

As in `FuncProto::setInputLock` / `setOutputLock` (`fspec.cc:3921-3948`),
setting either lock also locks the prototype model. Clearing an individual
input/output lock does not implicitly unlock the model.

**状态**: 🔧 **L2（2026-08-23 锁定审计）**——结构化 DOM 中的
`ParamEntry` / `ParamListStandard` / `ProtoModelFull` 解码切片已有锁定
12.0.4 行为对拍，生产 `.cspec` loader 已进入 output fixture；但
`ModelRule` 构造与若干未覆盖分支仍为 `MISMATCH` / `UNTESTED`，因此不升 L3。
**源代码路径**: `src/fspec.rs`

## 模块说明 (Module Doc)

Function prototypes and call specifications

Corresponds to Ghidra's `fspec.hh`. This module manages how functions
are defined (prototypes) and how call sites are handled (call specs).

## 导出的公共 API (Public API)

### `pub const THIS_POINTER: u32 = 1`

*暂无代码注释*

### `pub const HIDDEN_RETURN: u32 = 2`

*暂无代码注释*

### `pub const INDIRECT_STORAGE: u32 = 4`

*暂无代码注释*

### `pub const NAME_LOCKED: u32 = 1 << 3`

*暂无代码注释*

### `pub const TYPE_LOCKED: u32 = 1 << 4`

*暂无代码注释*

### `pub struct ProtoParameter`

A single parameter in a function signature

Corresponds to Ghidra's `ProtoParameter` class.

### `pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self`

Create a new function parameter

### `pub fn is_this_pointer(&self) -> bool`

Returns true if this parameter is a "this" pointer

### `pub fn is_type_locked(&self) -> bool`

Returns true if the type is locked (user-defined)

### `pub struct FuncProto`

A formal function prototype

Corresponds to Ghidra's `FuncProto` class. It defines the return type,
parameters, and calling convention of a function.

### `pub fn new(name: String, return_type: Arc<Datatype>) -> Self`

Create a new function prototype

### `pub fn add_parameter(&mut self, param: ProtoParameter)`

Add a parameter to the prototype

### `pub fn num_params(&self) -> usize`

Get the number of parameters

### `pub fn get_param(&self, index: usize) -> Option<&ProtoParameter>`

Get a parameter by index

### `pub fn set_model(&mut self, model: Option<Arc<ProtoModelFull>>)`

Install or clear the shared prototype model and update model-derived state.

### `pub fn has_model(&self) -> bool`

Test the stored model pointer/`Arc`, independently of its printable name.

### `pub fn has_effect(&self, space: AddressSpace, offset: u64, size: i32) -> EffectType`

Look up a full address-space/range call effect through the local override or
the shared model fallback.

### `pub fn try_has_effect(&self, space: AddressSpace, offset: u64, size: i32) -> Option<EffectType>`

Non-panicking form of `has_effect` for input registration
(`Funcdata::setInputVarnode` tail, funcdata_varnode.cc:365). `None` (no
model and no local override) has no Ghidra counterpart and skips the
effect-flag writes. Added 2026-09-23 (SB-MATCHURL-ORD70-0001).

### `pub fn effect_iter(&self) -> &[EffectRecord]`

Iterate the effective local-override or shared-model effect list.

### `pub fn get_extra_pop(&self) -> i32`

Return the prototype-local extra stack-pop value.

### `pub fn is_auto_killed_by_call(&self) -> bool`

Return the sticky model property, with output locking as an independent true
condition.

### `pub struct FuncCallSpecs`

Specification for a specific function call site

Corresponds to Ghidra's `FuncCallSpecs` class.

### `pub fn new(op_addr: Address, prototype: FuncProto) -> Self`

Create a new call specification

### `pub fn set_funcdata(&mut self, display_name: &str, entry: Address)`

(`CALLSPEC-DRIVER-0001`) Associate the callee with this call site — the
faithful observable port of `FuncCallSpecs::setFuncdata` (fspec.cc:4949-4960):
the entry address is taken from the callee and a non-empty display name
replaces `prototype.name`. Ghidra additionally keeps the callee `Funcdata*`
(and throws `LowlevelError` on a double set); Rugra has no per-callee Funcdata
objects, so the front-end boundary (`FlowInfo::queryCall`, flow.cc:660-669 —
driven by the driver's symbol/signature tables) hands the observable
(name, entry) pair directly, and re-association overwrites instead of
throwing. The previous `Option<&Funcdata>` form had no callers and was
consolidated into this signature.

### `pub fn set_callee_proto(&mut self, proto: Arc<FuncProto>)` / `pub fn callee_proto(&self) -> Option<&Arc<FuncProto>>`

(`CALLSPEC-COPY-0001`, 2026-09-27) The callee's own recovered prototype —
Rugra's observable slice of Ghidra's `FuncCallSpecs::fd` (fspec.hh:1649, set
by `setFuncdata` at flow time) as consumed by `ActionDefaultParams::apply`
(coreaction.cc:2321-2324 `Funcdata *otherfunc = fc->getFuncdata()` +
`otherfunc->getFuncProto()`). The driver's queryCall boundary stores the
callee's locked signature Arc here (libc generic_clib signature or the
DWARF-analyzer prototype — the two platform sources the oracle's callee
Funcdata would carry); `Some` mirrors the non-null `otherfunc` arm, `None`
keeps the `setInternal(evalfp, void)` else arm. `clone_for_op` carries the
link (fspec.cc:4968 `res->setFuncdata(fd)`).

### `pub fn copy_proto_from(&mut self, other: &FuncProto)`

(`CALLSPEC-COPY-0001`, 2026-09-27) The `fc->copy(otherfunc->getFuncProto())`
channel (coreaction.cc:2323): `FuncProto::copy_from` (fspec.cc:3789-3805)
assigns model, extrapop, the whole flag word, a clone of the parameter store
(names/types/lock markup/storage addresses) and the effect list —
FuncCallSpecs-level state (op, entry address, trial containers) stays out,
exactly as in the oracle where `FuncCallSpecs` does not override the
base-class `copy`. The callsite's own name survives (Ghidra's FuncProto base
has no name member; the wrapper restores the callsite spelling over Rugra's
glue name field). Bilateral fixture: `tests/oracle/callspec_copy_1204.*`
(MATCH, 25 records byte-identical; the lane row/commit said 24 — MB24
erratum: true counts COPY=8/COPY_LOCKEDMISMATCH=7/NOFUNC=6 plus 4 singles).
Latent gaps annotated in the source doc (CR-CALLSPEC O3): the oracle also
copies `likelytrash` (fspec.cc:3802) and `injectid` (fspec.cc:3803); Rugra
has no inject-id field (INJECT-0001 stub) and `copy_from` does not yet carry
the `likelytrash` field — dormant while the COPY arm is canon-unreachable.

### `FuncProto::set_input_lock` — named-parameter namelock side-effect

(`CALLSPEC-COPY-0001`, 2026-09-27) Locking a NAMED parameter's type now locks
its name too — the mirror of `ParameterSymbol::setTypeLock`
(fspec.cc:3047-3057: `attrs = typelock; if (!sym->isNameUndefined())
attrs |= namelock`), the behavior the scope-backed stores behind every
platform-locked prototype exhibit. Rugra's flat parameter vector is the
projection of that symbol-backed store, so `set_input_lock(true)` sets
`NAME_LOCKED` on non-empty-named params (unnamed `param_N` stand-ins gain
nothing). The oracle's `ParameterBasic::setTypeLock` (fspec.cc:2925) has no
such side-effect, but that class backs only scopeless internal stores —
never the locked platform boundary the copy channel serves.


### 2026-06-27（会话3 G5 续）：ParamTrial + ParamActive 基础设施移植

完整移植 Ghidra `ParamTrial`（fspec.hh:210-273）+ `ParamActive`（fspec.hh:285-380）——参数恢复基础设施，是 FuncCallSpecs Action（ActionFuncLink/ActionParamDouble/ActionActiveParam 等）的依赖。

**ParamTrial**（30+ 方法）：参数候选存储位置的试验，含 checked/used/active/unref/killedbycall 等标志位 + splitHi/splitLo 分割。
**ParamActive**（15+ 方法）：试验容器，registerTrial/whichTrial/splitTrial/getNumUsed 等。

**关键状态**：ParamTrial/ParamActive 已接入 FuncCallSpecs。两个容器永久
嵌入，是否处于恢复阶段由独立 boolean 表示；容器是否存在不再被错误地当成
active 状态。

当前实现已由 2026-08-23 的 output fixture 补齐 `AddressSpace`、1-based
`slotbase`、非 spacebase `killedbycall` 标记及空 entry 的 offset=0 状态；
本段保留为历史接入记录。

### 2026-06-27（会话3 G5 接入）：FuncCallSpecs active_input/active_output 字段 + 访问器

- `FuncCallSpecs.active_input: ParamActive` / `active_output: ParamActive` —
  永久嵌入；`input_recovery_active` / `output_recovery_active` 独立承载
  `isinputactive` / `isoutputactive`。
- `is_input_locked()` / `is_output_locked()` — FuncCallSpecs::isInputLocked/isOutputLocked
- `is_dotdotdot()` — isDotdotdot
- `init_active_input()` / `init_active_output()` — initActiveInput/initActiveOutput
- `get_active_input()` / `get_active_output()` — getActiveInput/getActiveOutput

### 2026-06-27（会话3 G5 接入续）：ActionFuncLink apply() + funcLinkInput/funcLinkOutput

本节是历史接入记录，不再构成“完整移植”声明。当前 `funcLinkInput` 的选定
x86 scalar 投影已有双侧门禁；`funcLinkOutput` 仍绑定 `CALLSPEC-0001`。

- `func_link_input(fc)`：unlocked/varargs → init_active_input；locked → 注册每个参数为 trial 并 mark_active（Ghidra 的 opStackLoad/opInsertInput pcode 注入需 Funcdata op-edit，暂缓）
- `func_link_output(fc_idx, op)`（2026-06-30 完整移植 coreaction.cc:1521-1572）：① 若 CALL 已有 output，op_unset_output 移除（让返回值重新决定）；② 若 `is_output_locked()`：return-type 为 Void → **不产生 output**（exit/free/__stack_chk_fail 等 void 函数永不产生返回 varnode）；非 void → `new_varnode_out(sz, RAX_addr)`；③ 若 unlocked → `init_active_output()`（不立即建 output，留给 ActionActiveReturn 试验恢复）。locked-stack-output 与 assumedOutputExtension 路径需更多 Funcdata op-edit，暂缓。
- `ActionFuncLink::apply`：遍历 callspecs 调用 func_link_input + func_link_output
- `ActionFuncLinkOutOnly::apply`：只调用 func_link_output

### 2026-06-30 历史记录：FuncProto.output_type_locked 与已删除的返回值表

- `FuncProto.output_type_locked: bool` — 忠实于 Ghidra `FuncProto::isOutputLocked`（fspec.cc:3906-3914）。`set_output_lock(val)` 现真正置位（此前是空桩）。`FuncCallSpecs::is_output_locked()` 委托给 `prototype.is_output_locked()`（此前误用 `is_input_locked()` 启发式）。
- 旧 `ensure_callspecs` / `known_return_type` 是数据库原型的硬编码替代物，现已
  删除。CALL 规范由 flow/driver 建立，返回类型来自 callee `FuncProto`。
- 效果：curl gcc 审计 17→19（match_url/__libc_csu_init 的 void-赋值 bug 消除）。


3 单元测试：空 Funcdata、unlocked callspec 初始化 active_input/output、is_input_locked。712/712 测试。

### 2026-06-27（会话3 G5续）：FuncCallSpecs 参数恢复支撑方法 + ParamActive pass控制

- FuncCallSpecs: is_input_active/is_output_active/clear_active_input/clear_active_output/check_input_trial_use（简化版，核心版需 AncestorRealistic）
- ParamActive: finish_pass/is_fully_checked/mark_fully_checked/mark_needs_final_check

### 2026-06-27（会话3 G5接入）：ProtoModel 接入 FuncCallSpecs + checkInputTrialUse 升级

FuncCallSpecs 新增 `proto_model: Option<ProtoModel>` 字段 + 方法：
- `has_model()` / `set_model(model)` — hasModel/setModel
- `resolve_model()` — resolveModel（non-merged 模型为 no-op）
- `derive_input_map()` — 调用 ProtoModel.fillin_input_map（完整版，替代简化版）
- `derive_output_map()` — 调用 ProtoModel.derive_output_map

**checkInputTrialUse 升级**：当 proto_model 存在时，用 ProtoModel.possible_input_param 判断每个试验是否匹配参数存储位置（Register/Stack），匹配→mark_active，不匹配→mark_no_use。无 model 时回退到简化版（全标记 active）。

**ActionActiveParam 升级**：finalize 路径现调用 resolve_model + derive_input_map（ProtoModel.fillinMap 驱动），不再是纯简化版。

### 2026-06-27（会话3 G5闭环）：buildInputFromTrials

- `build_input_from_trials() -> Vec<(Address, i32)>` — `FuncCallSpecs::buildInputFromTrials`（fspec.cc:5685-5741）忠实适配：遍历 active-input 试验，收集 USED 试验的 (address, size) 作为最终参数列表，删除未用试验。关闭参数恢复闭环：checkInputTrialUse → deriveInputMap → buildInputFromTrials。

### 2026-06-29：FuncCallSpecs::stackoffset + get_spacebase_offset
- 新增 `stackoffset: i64` 字段 + `OFFSET_UNKNOWN` 常量（fspec.hh:1641/1651）。
- `get_spacebase_offset() -> i64` — 忠实移植 `FuncCallSpecs::getSpacebaseOffset`（fspec.hh:1689）。
- `set_spacebase_offset(offset)` / `has_spacebase_offset()` — 设置/查询。
- 解锁 ActionRestrictLocal 的完整版（Loop 1: 遍历 locked stack params → markNotMapped）。

### 2026-06-29（续）：EffectRecord + FuncProto::effects
- 新增 `EffectRecord` 结构 + `EffectType` 枚举（unaffected/killedbycall/return_address/unknown_effect）。忠实移植 Ghidra `EffectRecord`（fspec.hh:391-416）。
- `FuncProto` 新增 `effects: Vec<EffectRecord>` 字段 + `effect_iter()` / `add_effect()` 方法。对应 Ghidra `FuncProto::effectlist` + `effectBegin/effectEnd`。
- 解锁 ActionRestrictLocal Loop 2（遍历 effect records 找 saved registers → COPY to stack → markNotMapped）。

### 2026-07-01：bytes_consumed tracking
FuncProto: +return_bytes_consumed 字段 + get/set（fspec.hh:1367/1429）。
FuncCallSpecs: +input_consume Vec + get/set_input_bytes_consumed（fspec.cc:5870）。

### 2026-07-04：AncestorRealistic + finalInputCheck + checkInputTrialUse 1:1 对齐

**AncestorRealistic**（funcdata.rs，移植自 funcdata.hh:655-724 + funcdata_varnode.cc:1997-2237）：
- `AncestorRealistic` 结构 + `ArState`（op/slot/flags/offset）+ `state_flags`/`ar_command` 模块
- `execute(op, slot, trial, allow_fail) -> bool` — 深度优先祖先遍历，检测 varnode 是否有 realistic 祖先
- `enter_node` — 处理 INDIRECT/SUBPIECE/COPY/MULTIEQUAL/PIECE 5 个 case（全部分支）
- `upon_pop` — MULTIEQUAL 回溯逻辑（seen_solid/seen_kill + checkConditionalExe）
- `check_conditional_exe` — 条件执行路径验证（BlockBasic.size_in/get_in/size_out）
- Rust 所有权适配：trial_killed_by_call/trial_size 快照 + 延迟 pending 标志（避免 &mut ParamTrial 别名）

**finalInputCheck**（fspec.rs，移植自 fspec.cc:5564-5576）：
- `final_input_check(op_ref)` — 对 hasCondExeEffect 的活跃试验重新运行 AncestorRealistic，失败→markNoUse

**checkInputTrialUse 重写**（fspec.rs，移植自 fspec.cc:5585-5653）：
- 签名改为 `check_input_trial_use(fd, op_ref, aliascheck, maxancestor) -> Vec<(slot, vn_size)>`
  （Ghidra 原签名持 `Funcdata &data`；`&self` 作为 checkCallDoubleUse 的 match spec
  以引用传入，trial 走克隆回写以避免借用冲突）
- Stack 空间试验：aliascheck.hasLocalAlias → markNoUse；否则 AncestorRealistic + ancestorOpUse
- Register 空间试验：AncestorRealistic(allowFail=true) + ancestorOpUse + condexe 标记
- 返回 definitelyNotUsed 试验的 (slot, size) 供调用者执行 opSetInput(newConstant)
- 2026-09-29（ACTIVEPARAM 速度道）：trial 循环入口激活 per-walk op→callspec 解析
  memo（`OpSpecMemoScope`，见 docs/api/funcdata.md get_call_specs_of_op 条目）——
  单次 checkInputTrialUse 域内 callspecs/op 绑定不可变，memo 解析=重算（观测恒等）；
  域随函数退出撤销，先于调用方 opSetInput/newConstant 尾部。走查形态计数与
  stdout 逐字节恒等（VdbeExec 实证）。

**ancestorOpUse + onlyOpUse**（funcdata.rs，移植自 funcdata_varnode.cc:1805-1994）：
- `ancestor_op_use(fd, maxlevel, vn, op, trial, offset, flags, match_fc) -> bool`
- 递归跟随 def 链（INDIRECT/MULTIEQUAL/COPY/PIECE/SUBPIECE），调用 only_op_use
- `only_op_use` — 前向遍历 descend，检测 BRANCH/LOAD/STORE/CALL/RETURN 等"非参数使用"

**FuncProto/ProtoModel getMaxOutputDelay**（fspec.hh:998/1572 + fspec.cc:1153 calcDelay）：
- `FuncProto::get_max_output_delay()` → `ProtoModelFull::get_max_output_delay()` →
  `ParamListOutput::get_max_delay()`（ParamListStandard::calcDelay 的 maxdelay）。
  供 `Funcdata::init_active_output` 使用。

**ActionActiveParam 借用重组**（coreaction.cc:1725-1771 Rust 侧）：
- checkInputTrialUse 调用改为「取值出锁 → 走 walk → 写回」：spec 值被 park 出 RwLock，
  占位符的 op Weak 悬空使身份扫描永不匹配（单线程管线语义等价 Ghidra 裸指针）。
- TraverseNode flags（ACTIONALT/INDIRECT/INDIRECTALT/LSB_TRUNCATED/CONCAT_HIGH）

**ActionActiveParam::apply 1:1 重写**（coreaction.rs，移植自 coreaction.cc:1725-1771）：
- AliasChecker gather → 每个活跃 callspec：trimmable 检查 → checkInputTrialUse → finishPass → maxPass 检查 → trimmable+fullyChecked 时 finalInputCheck → resolveModel → deriveInputMap → buildInputFromTrials → clearActiveInput

**Varnode/PcodeOp 访问器补齐**：
- Varnode: is_return_address/is_indirect_zero/is_incidental_copy/overlap（varnode.hh:257/271/277 + varnode.cc:178）
- PcodeOp: is_indirect_creation/is_indirect_store/is_incidental_copy/is_store_unmarked/is_mark/set_mark/clear_mark（op.hh:179/180/209/225/190/234/235）

**验证**：cargo test --lib 952/952 通过；curl 24/24 反编译；compare_ghidra defects=0（0/24 函数）。
<!-- annotation-pass: 2026-07-04 -->
<!-- activeparam-port: 1783158350.9591746 -->
 
 
**2026-07-22**: +10 FuncProto methods (clearInput/copyFlowEffects/paramShift/resolveExtraPop/setInjectId/cancelInjectId/clearUnlockedOutput/setInternal/updateThisPointer)

### 2026-07-22：ParamEntry + ParamListStandard 算法主体

完整移植 Ghidra `ParamEntry`（fspec.hh:84-155 / fspec.cc:60-595）+ `ParamListStandard`（fspec.hh:589-646 / fspec.cc:597-1517）——参数存储资源建模 + 资源分配算法。

**ParamEntry**（参数存储资源条目：寄存器集合 / 栈槽范围 / join）—— 30+ 方法：
- 资源查询：`get_group`/`get_all_groups`/`get_size`/`get_min_size`/`get_align`/`get_type`/`get_space`/`get_base`/`get_join_pieces`（fspec.hh:126-148）
- 状态谓词：`is_exclusion`/`is_reverse_stack`/`is_grouped`/`is_overlap`/`is_first_in_class`/`is_param_check_high`/`is_param_check_low`（fspec.hh:134-153）
- 包含/相交：`contained_by`(cc:199)/`intersects`(cc:214)/`justified_contain`(cc:248)/`justified_contain_in_space`(cc:248 带查询空间的完整空间守卫形态)/`get_container`(cc:295)/`contains`(cc:335)/`subsumes_definition`(cc:184)/`group_overlap`(cc:157)
- 解析：`find_entry_by_storage`(cc:60)/`resolve_first`(cc:76)/`resolve_join`(cc:94)/`resolve_overlap`(cc:122)/`order_within_group`(cc:583)
- 地址分配：`get_slot`(cc:407)/`get_addr_by_slot` 3-arg(cc:434)/`get_addr_by_slot_just` 4-arg(cc:450)
- 扩展：`assumed_extension`(cc:366) 返回 CPUI_COPY/INT_ZEXT/INT_SEXT/PIECE
- 标志模块 `param_entry_flags`（FORCE_LEFT_JUSTIFY..FIRST_STORAGE，fspec.hh:88-97）+ `containment` 模块（NO_CONTAINMENT..CONTAINED_BY）

**ParamListStandard**（标准参数列表模型：ParamEntry 数组 + 资源分配）—— 35+ 方法：
- 资源分配核心：`assign_address_fallback`(cc:735)/`assign_address`(cc:772)/`assign_map`(cc:785) —— 给定数据类型列表，映射到存储位置
- 试验映射：`build_trial_map`(cc:849) —— 将 ParamActive 试验关联到 ParamEntry；`fillin_map`(cc:1285) —— 决定正式参数列表（buildTrialMap → forceExclusionGroup → separateSections → forceNoUse → forceInactiveChain）
- 排除/链规则：`force_exclusion_group`(cc:1032)/`force_no_use`(cc:1069)/`force_inactive_chain`(cc:1111)/`mark_group_no_use`(cc:974)/`mark_best_inactive`(cc:997)/`select_unreference_entry`(cc:820)/`separate_sections`(cc:946)
  - `force_inactive_chain` 的 unref-seenchaining 栈测试读**试验自身存储空间**
    （cc:1121-1128 `trial.getAddress().getSpace()->getType() == IPTR_SPACEBASE`），
    绝不读模型的 stack spacebase——REGISTER 空间 unref 试验在末位 active 试验之前
    正是 hole-filling 尾部要保活的"隐含参数"形（tail-jmp thunk 的 RDI/RSI 转发；
    PROTORECOVER 2026-09-28 修复，canon httpd ap_getword_nc 4→0）；
    STACK 空间 unref 仍触发 seenchain（caller/callee 栈相对偏移不同，cc:1122-1125 注释）。
- 查询：`find_entry`(cc:661)/`characterize_as_param`(cc:682)/`possible_param`(cc:1354)/`possible_param_with_slot`(cc:1360)/`get_biggest_contained_param`(cc:1375)/`unjustified_container`(cc:1411)/`assumed_extension`(cc:1426)/`check_join`(cc:1315)/`check_split`(cc:1342)
- 解析/finalize：`parse_pentry`(cc:1226)/`parse_group`(cc:1262)/`finalize_after_decode`(cc:1451)/`calc_delay`(cc:1153)/`populate_resolver`(cc:1191)/`add_resolver_range`(cc:1174)
- 辅助：`extract_tiles`(cc:626)/`get_stack_entry`(cc:642)/`get_range_list`(cc:1439)/`clone_model`(hh:645)

**辅助类型**（fspec 模块局部副本，与 modelrules 模块的同名类型互不冲突）：
- `TypeClass` 枚举（General/Float/Pointer/HiddenReturn/Vector/Class1-4，fspec.hh:421-431）
- `VarnodeData`（space+offset+size，varnode.hh）+ `ParamEntryJoin`（fspec.hh:99）
- `ParamListKind`（Standard/StandardOut/Register/RegisterOut/Merged，fspec.hh:427-433）
- `AssignActionResponse`（Success/Fail/NoAssignment，modelrules.hh:264-271）
- `ParameterPieces`（addr+ty+flags，fspec.hh:451-460）+ `HIDDEN_RET_PARM`/`INDIRECT_STORAGE_PIECE` 常量
- `PrototypePieces`（out_type+in_types+first_var_arg_slot，fspec.hh:445-450）
- 自由函数：`string_to_type_class`/`metatype_to_type_class`/`justified_contain_range`/`is_contiguous`

**ParamTrial 扩展**：+`entry_index: Option<usize>` 字段（替代 Ghidra `const ParamEntry*` 指针，fspec.hh:230）+ `set_entry(entry_index, off)`/`clear_entry`/`get_entry_index` 访问器 + `op_less(entries, a, b)`（`operator<` 1:1 移植，cc:1893-1914）。`ParamActive::sort_trials`（hh:316）按 `op_less` 模型槽序（group → entry 序 → exclusion offset / reverseStack 地址 → size）排序试验，见 2026-08-23 节。

**ALIGNMENT_ROADMAP 记录的未移植依赖**（每个 TODO 均有记录）：
- `ParamEntryResolver` rangemap 数据结构本体（fspec.hh:597）—— `find_entry`/
  `characterize_as_param`/`get_biggest_contained_param` 以 `registered_extents`
  窗口化线性扫描等价复刻（见 2026-08-25 节；`add_resolver_range` 仍是
  API-parity no-op stub）
- `AddrSpaceManager::findJoin`（space.cc）—— `resolve_join`/`set_join_pieces` 由调用方提供 pieces
- 生产 `.cspec` 文本到 `Element` DOM 的解析器尚缺；本模块现可通过既有
  `TreeDecoder` 消费结构化 DOM，真实文本 ingestion 仍在本模块之外
- `ModelRule`（modelrules.hh）—— `assign_address` 直接走 fallback
- `Datatype::getAlignSize`/`getAlignment` —— 用 size/alignment=1 近似

### 2026-08-14：compiler-spec 参数模型结构化 DOM 解码

- `ParamEntry::decode` 从 `<pentry>` 读取 `minsize`、`maxsize`、对齐、存储类、
  extension 与地址子元素；命名寄存器通过调用方提供的 Translate 等价解析器
  查询，不嵌入 SysV/Windows ABI 寄存器表。
- `ParamListStandard::decode` 按文档顺序处理 `<pentry>` / `<group>`，保留共享
  group counter、split-float resource 起点、重叠检查、正向/反向栈边界，并由
  `get_range_list` 从实际 stack pentry 推导区间。
- `ProtoModelFull::decode_with_register_resolver` 解码 input/output、effects、trash、
  internal storage，并优先从实际 input stack entries 派生 parameter range；
  `decode` 保留为无命名寄存器目录时的兼容入口。
- `ProtoModelFull` 的 declaration-print flag 使用对象内部的原子可变状态：所有
  指向同一模型的 `Arc` 观察同一次 `setPrintInDecl` 原位突变；复制 alias 时则
  新建独立 flag，匹配 Ghidra 新 `ProtoModel` 对象而非共享 flag。
- 锁定 fixture `tools/run_cspec_param_model_oracle.sh` 用完整
  `x86-64-gcc.cspec`：Ghidra 端走生产 `DocumentStorage`，Rust 端把同一锁定文本
  转为结构化 `Element` 后调用现有 `TreeDecoder` 和上述生产函数。默认模型、
  MSABI 分组、栈区间、正向栈与错误路径的已声明观测逐字节一致。
- 整体状态仍是 `MISMATCH`：Rust 生产路径尚不能直接 ingest `.cspec` 文本；
  `<rule>` 当前仅被消费，尚未构造 `ModelRule`。`resolveprototype`、join-space
  pentry 与 default-return 注入仍为 `UNTESTED`。fixture 不把这些残差归为匹配。

**验证**：cargo check --lib 0 错误；cargo test --lib fspec:: 12/12 通过（6 原有 + 6 新增：ParamEntry exclusion/aligned/justified_contain + ParamListStandard new/possible_param）。repo 中 6 个预存失败（pcodeparse/unionresolve）与本移植无关。

### 2026-08-23：fspec Phase-0 对齐修复（FSPEC-SPACEFILTER-0002 + FSPEC-TRIALCMP-0003）

审计依据 `docs/alignment_audit/FSPEC_GAPS_2026-08-23.md` §3.B/§3.C/§3.D。两处修复均以锁定
oracle `fspec_phase0_1204` fixture（`tools/run_fspec_phase0_oracle.sh`，pin-base schema2）
双侧投影逐字节 MATCH 验证。

- `ParamListStandard::find_entry`（cc:661-680）：删除自创的 `!= AddressSpace::Ram` 过滤，
  改为查询空间 vs entry 空间比较（`e.get_space() != space`），对齐 Ghidra 每空间
  `resolverMap` 的语义（`populateResolver` 只把 entry 注册进它自己空间的 resolver，
  cc:1191-1216）。签名增补 `space: Option<AddressSpace>`：`Some(s)` 精确对齐（寄存器/栈
  entry 正常命中，const/unique 查询不会在别的空间 offset 上假命中）；`None` 只保留给
  遗留 spaceless 兼容调用。`build_trial_map`/output fill-in 两个 trial 驱动调用点现从
  `ParamTrial` 读取完整空间并传入 `Some(space)`。
  下游 `possible_param`/`possible_param_with_slot`/`check_join`/`check_split` 签名随之增补
  显式 `space: AddressSpace`（同 `characterize_as_param`/`get_biggest_contained_param`
  的既有模式）。
- `unjustified_container`（cc:1411-1424）/`assumed_extension`（cc:1426-1437）：删除
  Ram-only 过滤，无空间过滤地遍历全部 entry（Ghidra 依赖逐 entry `justifiedContain` 的
  空间拒绝）。残差：Rust 逐 entry 谓词是 offset-only（遗留无空间 Address），来自异空间
  的查询理论上可假命中 —— 登记为 ADDRESS-0001 的下游缺口。
- `ParamTrial::op_less`（cc:1893-1914 新增移植）：排序键逐分支对齐 —— null entry 恒后、
  group id、entry 指针序（Rust 用 `entry_index`：`std::list` 只在 decode 期 push_back，
  节点分配序 == 声明序 == 索引序）、exclusion entry 的 justified offset、非 exclusion 的
  reverseStack 地址序、size。`sort_trials` 签名改为 `(entries: &[ParamEntry])`，四处调用
  点（`build_trial_map`、`Out::fillin_map`/`fillin_map_fallback`×2）传入所属 entry 表。
  残差：Rust `sort_by` 稳定 vs `std::sort` introsort 不稳定 —— 比较器等价元素（同 entry/
  地址/size）的相对次序可能不同；生产 trial 集不会产生比较器等价重复。
- `ParamTrial::split_hi`/`split_lo`（cc:1845/1856）：`split_lo` 低片地址改
  `addr + (size - sz)`（原 `+sz` 错误，仅 size==2*sz 时巧合相等；12 字节切 4 时
  0x104→0x108），两函数补 `res.flags = flags` 复制（used/checked/active 跨切分保留）。
- `ParamActive::split_trial`（cc:2033-2057 全量移植）：补 stackplaceholder>=0 panic 守卫、
  分裂点以上 trial 的 slot 重编号、`splitLo(getSize()-sz)` 调用形、`slotbase += 1`。
- 单测：`test_param_trial_split_12_at_4_flags_and_address`、
  `test_param_active_split_trial_12_at_4_renumbers_slots`、
  `test_param_active_sort_trials_uses_model_order`、扩展
  `test_param_list_standard_possible_param`（空间负例）。
- fixture `fspec_phase0_1204`：跨空间 entry 查找（register 命中 / const/unique/ram 交叉
  miss / minsize 门）、无空间过滤的容器/扩展判定（register INT_ZEXT、ram PIECE、COPY 门）、
  comparator 阶梯排序（group/entry/offset/reverseStack/null-entry）、12/4 切分的边界地址与
  flags 继承、split_trial slot 重编号。该 fixture 的 Rust 侧现在还会断言每个
  tagged-address 注册成功；它仍只打印 split 前后的 slot delta，而绝对 1-based slot
  与 register-trial flags 由 `fspec_paramlist_output_1204` 直接观察。

**验证**：cargo check --lib 0 错误；cargo test --lib fspec:: 19/19；全库 1473 通过、
2 失败均为 base 即存的 funcdata 推断测试（`test_infer_params_and_return_type`/
`test_type_propagation`，与本改动无关，已 stash 复核）。
`tools/run_fspec_phase0_oracle.sh`：covered_projection=6/6 MATCH。

### 2026-08-23：output ParamList 多态分派（FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001）

- `ParamListOutput::{Standard,Register}` 是 Ghidra `ProtoModel::output`
  虚函数所有权在 Rust 中的封闭表示；`build_param_list("")` /
  `build_param_list("standard")` 建立 `ParamListStandardOut`，而
  `build_param_list("register")` 建立 `ParamListRegisterOut`。所有 output
  decode/assign/fillin/possible/containment/entry 查询均由该枚举按具体类分派，
  不再把 output 存成 input 型 `ParamListStandard`。
- `ParamListStandardOut::decode` 现在完整委托 `ParamListStandard::decode` 后执行
  `initialize`；`ProtoModelFull::decode_with_defaults` 因而把生产 cspec 的 output
  pentry 写入 output 自有列表。`derive_output_map` 与
  `possible_output_param(space,offset,size)` 直接消费同一列表。
- `ParamTrial` 增加 address-space 分量；tagged `register_trial` 不再把缺失空间
  猜作 Register，无法证明空间时零突变返回 `false`。显式
  `register_trial_in_space` 使用 1-based slotbase，并对非 Stack/spacebase trial
  设置 `KILLEDBYCALL`。output fallback
  以 trial space 查 entry，`setEntry(nullptr,0)` 的 Rust 表示同时清 entry index
  和 offset；before/after 序列化因此覆盖 slot、entry group/offset 和全部 flags。
- 锁定 fixture：`tools/run_fspec_paramlist_output_oracle.sh` 使用真实
  `BfdArchitecture` + `examples/curl` + `x86-64-gcc.cspec` 运行 Ghidra，Rust 侧
  使用生产 `DocumentStorage` / SLA / `Architecture::parse_compiler_config`。
  `float_only`、`general_only`、`general_beats_float`、`invalid_output` 四个
  subprojection 的 model/possible 查询及全部 trial 容器突变逐字节一致。
  fixture 另外逐侧序列化 output 的 `autoKilledByCall` 以及只给
  `XMM1_Qa`/`RDX` 的 second-resource case：Ghidra 的生产 `join_dual_class`
  令 `useFillinFallback=false`、`autoKilledByCall=false` 并拒绝缺少首资源的
  second trial；Rust 尚未拥有/执行 decoded `ModelRule`，仍强制 fallback/auto-kill
  为 true 并接受该 trial。因此双侧输出分别 pin，overall/covered projection
  明确为 `MISMATCH`，runner 只有在该差异被完整复现时才成功。

保守残差：`ModelRule` 状态/second-resource 行为已是有真实 oracle 的
`MISMATCH`；成功合成 dual join 与 hidden-return 的分支仍为 `UNTESTED`。input 侧
`ParamListRegister` 所有权、register-output assignment、void/oversize hidden
return、双寄存器 join、错误路径与 endian 边界也不在本 fixture 的 MATCH 投影内。
这些残差使 fspec 保持 L2；本批不声称 output 参数模型整体 L3。

### 2026-08-11：ANN-C 函数来源注释审计

以锁定 oracle `Ghidra 12.0.4`（commit `e40ed13014025f82488b1f8f7bca566894ac376b`）复核 `fspec.cc/.hh` 后，为注释扫描器报告的 18 个函数补齐来源分类。本轮只增加来源注释，不改变任何运行时行为，也不提升模块的 L2 状态。

- 真实 Ghidra 映射（3 个）：`set_input_parameter` → `ProtoStoreInternal::setInput`、`set_output_parameter` → `ProtoStoreInternal::setOutput`、`is_left_justified` → `ParamEntry::isLeftJustified`。
- Rust 数据表示胶水（3 个）：`VarnodeData::default`、`ParameterPieces::default`、`parse_u64`；C++ 侧使用无 `default()` 成员的 aggregate 或 typed `Decoder`。
- Rust trait/继承胶水（6 个）：`ParamListStandard::default`、`ParamListStandardOut::default`、`ParamListRegisterOut::default`、`get_num_group`、`entry_mut`、`is_alias_of`。
- 分阶段 loader 胶水（6 个）：`set_base`、`set_sizes`、`set_alignment`、`set_type_class`、`set_auto_killed_by_call`、`set_num_group`；Ghidra 在 `ParamEntry::decode`、`ParamListStandard::decode` 或派生类中直接写字段，没有这些独立 setter。

这些注释只声明函数来源或 Rust 结构适配原因；尤其不证明扁平 `FuncProto` 存储、默认值、alias identity 或分阶段 loader 与 Ghidra 行为等价。

### 2026-08-15：FuncCallSpecs effect/characterize 委托 FuncProto（HERITAGE-CALLGUARD-0001）

- `FuncCallSpecs::has_effect(space, offset, size) -> EffectType`：对齐
  `FuncCallSpecs : public FuncProto`（fspec.hh:1645）的继承解析——非空本地
  effect 列表完整覆盖，空列表委托 `FuncProto::has_effect`（fspec.cc:4234，
  即 PROTO-EFFECT-MODEL-0001 的 ProtoModelFull 查询）。modelless 的
  FuncProto 在 Ghidra 是无效状态（解引用即错）；Rugra 生产侧在
  FUNCPROTO-MODEL-BIND-0001 落地前保守返回 `unknown_effect`（guardCalls
  因此建 INDIRECT，不会欠保护）。
- `characterize_as_output`/`characterize_as_input_param` 改为委托
  `FuncProto::characterize_as_{output,input_param}`（fspec.cc:4336/4289 新增
  端口）——修复 HERITAGE-DRIVER 审计指出的 output 塌缩到 input
  characterization 的问题。locked-param/output 分支因 Rugra
  `ProtoParameter.address` 无空间身份降级到 model 分支（ADDRESS-0001 移除）。
- `is_auto_killed_by_call` 委托 `FuncProto::is_auto_killed_by_call`
  （fspec.cc:4609：model output 的 autoKilledByCall 粘滞位或 locked output），
  替代写死的 `true`。
- `ParamListStandard::characterize_as_param(space, offset, size)`：修复原
  `space != Ram` 过滤（x86-64 的参数 entry 在 Register 空间，被全部滤掉），
  按 per-entry space 匹配（Ghidra 的 per-space resolverMap 语义）。
- `ParamListStandard::get_biggest_contained_param(space, offset, size)`：
  忠实端口（cc:1375-1409：环绕检查、intersect 窗口、containedBy、取最大、
  `isExclusion` 要求），替代被删除的 Ram-only 旧版。
- `FuncProto::get_biggest_contained_input_param/output`（cc:4459/4492）、
  `justified_contain_range` 转公开（heritage 的 call-guard helper 复用同一
  `Address::justifiedContain` 数学）、`ParamEntry::from_storage`（fixture
  构造 glue）、`FuncCallSpecs::has_effect_translate` 签名更新。
- 证据：`tests/oracle/heritage_callguard_1204.*`（model_state/effect 探针 +
  trials case 双侧逐字节 MATCH）。


# 2026-08-16：defaultReturnAddr 注入点（CSPEC-DEFAULT-RETURN-0001）

`ProtoModelFull::decode_with_defaults`：`decode_with_register_resolver` 的
超集（追加 `default_return_addr: Option<&VarnodeData>` 参数）。模型无自带
`<returnaddress>`（!saw_retaddr）且 Architecture defaultReturnAddr 已设置时，
在 effectlist 排序前追加 `EffectRecord(default, return_address)`——逐字对齐
fspec.cc:2689-2691。旧入口委托 None（等价 defaultReturnAddr.space==null 的
Ghidra 行为），`Architecture::decode_proto_spec`/`decode_default_proto_spec`
为 parse_compiler_config 路径传真值。另新增
`get_alias_parent_marker`/`set_alias_parent_marker`（Ghidra
`getAliasParent()`/copy-ctor `compatModel` 的 Some/None 可观测面）。

# 2026-08-25：proto-store 输出存储 + 锁定分支落地（FSPEC-OUTPUT-STORAGE-0001）

- `FuncProto::output_storage: Option<(AddressSpace, u64)>`：扁平 store 的
  `ProtoStore*::outparam` `ParameterBasic::addr`（fspec.hh:1164-1165）站立
  位——返回值存储位置（空间+偏移）。legacy `Address` 无空间身份，空间随
  偏移并存（ADDRESS-0001 落地时折叠进地址）。`FuncProto::new` 初始化
  `None`；`copy_from` 携带（fspec.cc:3797-3798 store clone）。
- `set_output_parameter(pieces, space)` 改公开并记录存储（fspec.cc:3385
  `new ParameterBasic("",piece.addr,piece.type,piece.flags)` 全量——类型进
  `return_type`，地址进 `output_storage`）；trial-commit 路径
  （`update_output_types`）以 varnode 空间调用。
- `characterize_as_output` 锁定分支（fspec.cc:4339-4353）逐行落地：
  TYPE_VOID 门 + cc:4346 `justifiedContain`（端序按存储空间路由）+
  cc:4351 `containedBy`。锁定但无记录存储时降级 model 分支（Ghidra 锁定
  分支为终态；no-storage 是 Rugra 过渡不可达态，保持生产行为不变）。
- `get_biggest_contained_output` 锁定分支（fspec.cc:4495-4506）同构落地
  （cc:4500 containedBy + `base != op2.base` 空间等值检查）。
- 新 helper `contained_by_range`（address.cc:110-118 `Address::containedBy`
  的 spaceless-offsets 形态，与 `justified_contain_range` 同约定：空间
  等值检查留在调用方）。
- `FuncCallSpecs`：`is_stack_output_locked` 字段（fspec.hh:1661
  `isstackoutputlock`，构造 false = fspec.cc:4946）+ `set_stack_output_lock`
  （fspec.hh:1703）+ 真实 `is_stack_output_lock`（替代写死 false）+
  `get_output_storage` 委托（fspec.hh:1536 `getOutput` 的继承投影）。
  生产者 = `ActionFuncLink::func_link_output`（coreaction.cc:1546-1549），
  消费者 = `Heritage::guard_calls` cc:1487 门。
- decode 通道残差收窄：`FuncProto::decode` 的 returnsym 地址仍在
  `decode_output_storage` 闭包边界丢失空间身份（丢弃并注释登记，
  ADDRESS-0001 家族）；签名 ingestion 落地前 funcLinkOutput 走无存储回退。
- 证据：`tests/oracle/heritage_tryoutput_1204.*` 四 case 双侧逐字节
  MATCH（11/12 covered；BE 栈空间 UNTESTED 保持）。


### 2026-08-17：setInternal 签名对齐（FUNCPROTO-MODEL-BIND-0001）

- `set_internal(&mut self, model: Option<Arc<ProtoModelFull>>, vt)`——参数从
  简化 `type_system::protomodel::ProtoModel` 改为完整 `ProtoModelFull`，并
  逐字对齐 fspec.cc:3891-3898：`return_type = vt`（内部 store 的 void 输出
  可观测面，store 本体属 PROTOSTORE-SYMBOL-0001）+ `if (model == None)
  set_model(model)` 守卫——已绑定 model（如 set_arch 链安装的 defaultfp）
  不被后续 internal setup 覆盖。零调用者受签名影响（此前无生产调用点）。

### 2026-08-17（续）：print_model_in_decl 修复为模型自有 flag（FUNCPROTO-MODEL-BIND-0001）

- `print_model_in_decl()` 原实现 `!is_model_unknown()` 是字符串哨兵简化——
  model 绑定后会把 `__stdcall` 打进所有声明（golden 为 0 处）。修复为
  fspec.hh:1395 的 `model->printInDecl()` 委托：`setDefaultModel` 将旧默认
  置 true、新默认置 false（architecture.cc:326-329，Rugra `set_default_model`
  已实现同一翻转），别名 clone（copy-ctor `isPrinted=true` 不继承，
  fspec.cc:2360-2366）保持打印。modelless（PLT 锁定路径）保持 false，
  `is_model_unknown` 哨兵语义（"Unknown calling convention" golden warning）
  不受影响。

### 2026-08-17（r2 返工）：has_matching_model（FUNCPROTO-MODEL-BIND-0001）

- `FuncProto::has_matching_model(&Arc<ProtoModelFull>)`——逐字移植
  fspec.hh:1391 内联 `(model == op2)` 指针相等，供 ActionPrototypeTypes
  绑定守卫（coreaction.cc:4617）与 ActionDefaultParams（cc:2325）消费。

### 2026-08-24：CALLSPEC-IDENTITY-D0 exact call-op identity

- `FuncCallSpecs` 现在保存 `op: Weak<RwLock<PcodeOp>>`，精确对应 Ghidra 的
  非拥有 `PcodeOp *`；类型不再派生 `Clone`，避免通过普通值复制悄悄复制一个
  身份对象。`find_call_op` 只升级该 `Weak`，不再按 `op_addr` 扫描 alive op。
- `new_for_op(&PcodeOpRef, FuncProto)` 绑定 exact op。直接 CALL 在 setup 用 FSPEC
  annotation 替换 input(0) 之前捕获目标；若克隆的 input(0) 已携带 typed FSPEC
  handle，则从原 callspec 恢复 entry。裸 Iop constant 即使 offset 相同也不被
  当作 callspec。CALLIND 初建时不臆造 entry。
- `clone_for_op(&PcodeOpRef)` 显式创建新的 callspec 身份并绑定新 op，复制当前已
  建模的 prototype/entry/stack offset；`active_input` 与 `active_output` 由新构造器
  重置。这个专用 clone 是 truncated-flow 生命周期操作，不等同于 `Clone` trait。
- callspec → op 和 CALL input annotation → callspec 均为 `Weak`；
  `Funcdata::callspecs: Vec<Arc<RwLock<FuncCallSpecs>>>` 是权威的持久强 owner。
  短生命周期的局部/返回 `Arc` handle 不会成为反向边，因此没有强引用环。
- D0 的行为门禁是 `callspec_identity_lifecycle_1204`，但总体判定保持
  `MISMATCH`：专用 `IPTR_FSPEC` 尚未实现，当前仍用 `AddressSpace::Iop`
  （`TYPEOP-FSPEC-SPACE-0001`）；本阶段不接 TypeOp getter、PrintC、
  StringManager，也不消除其它既有 FuncCallSpecs 字段残差。
- 旧 `deindirect` helper 没有生产调用者，且 hook 仍只接收裸
  `&mut FuncCallSpecs`，无法把 `new_varnode_call_specs` 所需的 stable `Arc` owner
  传给 typed annotation。owner/rebind seam、override flag 与 callee prototype
  分支均为 `CALLSPEC-0001` 的 `UNTESTED` consumer residual；D0 只更正“annotation
  API 未实现”的过时前提，不宣称该 helper 行为已接通。

### 2026-08-24：noreturn 位生命周期补齐（CALLSPEC-NORETURN-WIRE-0001 段a）

以锁定 oracle `Ghidra 12.0.4`（commit `e40ed13014025f82488b1f8f7bca566894ac376b`）
复核 `fspec.hh:1343-1459/1645` 与 `fspec.cc:3778-3812/5443-5472/4625-4840` 后落地：

- **`FuncProto::copy_flow_effects` 修正为 Ghidra 语义**（fspec.cc:3806-3812）：
  只单向覆盖 `is_inline|no_return` 位子集（Ghidra 先 `flags &= ~(...)` 再
  `flags |= op2.flags & (...)`，源位为 0 时清空目标位），不再拷贝 effects
  列表——effectlist 的整体拷贝属于 `FuncProto::copy`（fspec.cc:3801），旧
  实现是自创语义。这是 `FlowInfo::queryCall`（flow.cc:664）把 callee 的
  noreturn 状态传播到 call-site FuncCallSpecs 的主通道（`__stack_chk_fail`
  路径）。`injectid = op2.injectid` 拷贝暂缺：FuncProto 无 injection id
  存储（`set_inject_id` 为 INJECT-0001 stub），登记于 INJECT-0001。
- **`FuncCallSpecs` 补继承面委托访问器** `is_no_return`/`set_no_return`/
  `is_inline`/`set_inline`/`copy_flow_effects`：Ghidra 的
  `class FuncCallSpecs : public FuncProto`（fspec.hh:1645）经继承直接暴露
  fspec.hh:1434/1439/1411/1417 与 fspec.cc:3806；Rugra 组合持有 prototype，
  以委托等价暴露。flow.rs 的消费侧接线（`FuncCallSpecsExt` stub 退役、
  `query_call` 补 `copy_flow_effects` 调用、`truncate_indirect_jump` 的
  `set_no_return(true)`）为段(b)（flow 租约释放后）。
- **`FuncCallSpecs::deindirect` 的 noreturn/inline 门直接接线**：删除
  `callee_is_no_return_or_inline` closure 参数，改为直接读
  `newfd.get_func_proto()` 的 `is_no_return()/is_inline()`（fspec.cc:5460-5461
  `FuncProto &newproto(newfd->getFuncProto())`）。该方法无生产调用方。
- FuncProto 侧 noreturn 的既有生命周期维持不变：默认构造 `flags=0`
  （fspec.cc:3783 → `no_return:false`）、`set_no_return`/`is_no_return`
  （fspec.hh:1439/1434）、`copy_from`/`clone` 整位拷贝（fspec.cc:3794）、
  decode 的 `noreturn` 属性（fspec.cc:4720-4722）、encode 的
  `ATTRIB_NORETURN`（fspec.cc:4642-4643）、`is_compatible` 的位子集比较
  （fspec.cc:4567）。Ghidra fspec 层**没有** void 返回 → noreturn 的推断
  通道（`setNoReturn` 的全部调用点仅 flow.cc:747、options.cc:358 与 decode
  直接置位），noreturn 只能来自数据库 prototype XML、`OptionNoReturn`、
  call-site 直置或 `copyFlowEffects` 传播。
- 双侧 fixture：`tests/oracle/callspec_noreturn_1204.{cc,rs,metadata.json}` +
  `tools/run_callspec_noreturn_oracle.sh`（六 case 投影：default_ctor、
  explicit_set_idempotent、copy_flow_effects、full_copy_and_clone、
  void_no_inference、decode_encode_channel）。

### 2026-08-24：justified_contain_range 极性修复（FSPEC-JUSTIFIED-CONTAIN-0001）

- **`justified_contain_range(base, sz2, addr, sz, force_left)`** 谓词重写为
  `Address::justifiedContain`（address.cc:131-141）的逐字语义：**任一侧独立
  越界即 -1**——`if addr < base { return -1 }`（cc:133 `op2.offset < offset`）
  与 `if end_addr > this_end { return -1 }`（cc:137 `off2 > off1`），两个
  检查相互独立。旧实现的成对条件（`addr < base && end_addr < this_end` /
  `addr > base && end_addr > this_end`）漏判三类几何：等始越顶
  （`view=start` 返回 0 = 假 justified）、低侧重叠止于 entry 尾（`view=end`
  返回 0）、双端溢出（落入 u64 回绕减法，dev 构建直接 panic 于
  `this_end - end_addr`）。
- **投影后果**：`characterize_as_param`（fspec.cc:682-719）对 range⊃entry 的
  query 曾错判 `contains_justified`（off=0），修复后走 `containedBy` →
  `contained_by`（fspec.cc:707），`guardReturnsOverlapping` 的触发前提在
  Rust 侧可达。
- **分支算术维持**：`force_left=true` → `op2.offset - offset`（start 距离），
  `force_left=false` → `off1 - off2`（end 距离 = Ghidra BE+!forceleft）。
  已知未对齐面：小端空间 + forceleft=false 时 Ghidra 返回 start 距离，而
  spaceless helper 取 flag 直接选分支——LE 调用方传 `false` 会得到 end 距离
  （heritage truncate_amount 与 LE 无 flag entry 的 `==0` 判定受影响）。修
  复需把空间端序穿进 helper 签名（含 heritage.rs 调用点），超出本租约，
  待登记 TODO 后另行处理。
  （当日后续：已由 FSPEC-JUSTIFIED-ENDIAN-0002 修复，见下方条目。）
- 双侧 fixture：`tests/oracle/justified_contain_1204.{cc,rs,metadata.json}` +
  `tools/run_justified_contain_oracle.sh`（三 case 投影：LE/BE×forceleft 的
  17 几何极性+分支算术矩阵（含 1/4/8/cross-4 尺寸边界）、ParamEntry
  alignment==0 包装、characterizeAsParam 三分类；63 行双侧逐字节 MATCH）。

### 2026-08-24：空间端序穿签名 + characterizeAsParam resolver 门控（FSPEC-JUSTIFIED-ENDIAN-0002 / FSPEC-CHARACTERIZE-RESOLVER-GATE-0003）

- **`justified_contain_range(base, sz2, addr, sz, force_left, space_is_big_endian)`**
  增加第 6 参空间端序，分支条件重写为 Ghidra 原文的
  `base->isBigEndian() && !forceleft`（address.cc:138）：仅
  **BE 空间 + forceleft=false** 返回 end 距离 `off1 - off2`，其余组合（含
  **LE 空间任意 forceleft**）返回 start 距离 `op2.offset - offset`
  （address.cc:141）。旧实现把 `!force_left` 直接当 BE 路由，LE 调用方
  （heritage truncate_amount、无 flag LE entry 的 `==0` 判定）拿到错误的
  end 距离。
- **调用点端序来源**（Ghidra 均为 `base->isBigEndian()`，即地址所在空间）：
  - `ParamEntry::justified_contain` alignment==0 路径传
    `self.space.is_big_endian()`（cc:266-267 构造 `Address entry(spaceid,…)`）；
    join-piece walk 传各 piece 自己的 `vdata.space.is_big_endian()`（cc:255）。
    过渡期 enum `AddressSpace::is_big_endian` 恒 LE（space.rs 默认），即生产
    闭包全部走 start 距离；BE ParamEntry 空间在 enum 模型下不可表达
    （ADDRESS-0001 残差）。
  - `transfer_locked_output_param` 四处（cc:5073/5075/5082/5084）只观察
    `>= 0`（containment），距离不可观测，传 LE 默认并注释声明。
  - `heritage.rs guard_call_overlapping_input` 的 truncate_amount（cc:1221）
    传 heritage 空间 `space.is_big_endian()` —— LE 下 SUBPIECE 常量 =
    `truncAddr - addr`（start 距离），不再是 end 距离。
- **`characterize_as_param` 重构为 Ghidra 的 resolver 门控两段扫描**
  （fspec.cc:682-719）：phase-1 只访问**注册 extent 包含 query 起点**的 entry
  （`resolver->find(loc.getOffset())`，rangemap.hh:332；populateResolver
  fspec.cc:1191-1216 按 entry 自身 extent / join 逐 piece extent 注册），
  phase-2 仅当 phase-1 块不是 resolver 最后一块（cc:708
  `iterpair.first != resolver->end()`，等价于该空间存在**起点高于 query
  起点**的注册 extent——细化区间在每个注册起点处分裂，上方存在区间 iff
  存在更高起点）时扫描**注册起点落在 `(offset, offset+size-1]`** 的 entry
  （cc:709-716 `find_end(loc.getOffset()+size-1)`）。query 起点在所有同空间
  extent 之上时门控关闭、containedBy 扫描整体跳过、直返
  `no_containment`。join entry 的 `containedBy` 因 spaceid=join 空间恒 false
  （cc:202），Rust 以 `e.space == space` 守卫复刻。线性扫描被窗口化扫描
  取代；窗口辅助 `registered_extents`（RUGRA-GLUE）。
- 单元测试：`test_justified_contain_range_one_sided_violations` /
  `test_param_entry_justified_contain` 改钉 LE 端序语义（无 flag Register
  entry 的 0x202/2 → start 距离 2，非 end 距离 4）。
- 双侧 fixture：`tests/oracle/fspec_endian_resolver_1204.{cc,rs,metadata.json}`
  + `tools/run_fspec_endian_resolver_oracle.sh`（三 case：helper 级
  LE/BE×forceleft 四组合距离判别、LE 无 flag entry 的 wrapper 投影、
  heritage truncate 的 SUBPIECE 常量形态 + characterizeAsParam 的
  extent-out 门控 query 集）。`justified_contain_1204` 因 src 行为变更
  同 commit 重钉（Rust 侧 view=start 行改走 `force_left=false`+LE 的真实
  缺陷路由，be=1 行改 helper 显式端序直调——enum 空间无法 staging BE
  ParamEntry，ADDRESS-0001 过渡声明）。

### 2026-08-25：findEntry 的 resolver find-窗口门控 + join piece 访问（FSPEC-FINDENTRY-GATE-0005）

- **`ParamListStandard::find_entry(space, loc, size, just)`**（cc:661-680）：
  无限定的逐 entry 线性扫描 + `e.get_space() != space` 平面过滤被
  `characterize_as_param` 同款 **resolver find-窗口**取代——只访问
  `registered_extents(e, space)`（populateResolver fspec.cc:1191-1216 的
  per-space 注册：普通 entry 自身 extent / join 逐 piece extent）数值上
  包含 query 起点的 entry。find 窗口 = 起点所在的唯一细化子区间
  （rangemap.hh:332 `find(point)`），窗口内 record 共享同一 `last` 键、按
  `position` 子序排列（AddrRange::operator<），而 position 按 entry 列表
  注册序递增——**有序列表扫描 = 恰好按 Ghidra 顺序访问恰好的窗口集**。
  可观测后果（fixture 钉住）：`just=false` 下 extent-out query（低于/介于/
  高于该空间全部 extent）返回 `None`（旧实现会返回首个同空间 entry）；
  窗口内 minSize 门控不再被窗口外的更早 entry 抢先。
- **join entry 可达**：旧实现的 `get_space() != space` 过滤把 join entry
  （spaceid=join 空间）结构性排除；新窗口按 piece 空间注册访问，findEntry
  可以返回 join entry（cc:1201-1207 逐 piece `addResolverRange`）。
- **`ParamEntry::justified_contain_in_space(addr, sz, query_space)`**
  （cc:248-283 的完整空间守卫形态，resolver 窗口调用方
  `find_entry`/`characterize_as_param` 使用；R13 复核发现 B 的修复）：
  - join walk（cc:253-261，从最低有效 piece 起）：异空间 piece 走
    address.cc:133 `base != op2.base` → -1，仅向跳过累加器贡献自身 size
    ——跨空间 join 的数值巧合不再误报 ≥0；
  - alignment==0（cc:264-267）：entry 空间 Address 的 cc:133 守卫；
  - alignment!=0（cc:269）：显式 `spaceid != addr.getSpace()` 守卫。
  无查询空间的过渡调用方保留 spaceless `justified_contain`
  （ADDRESS-0001）。
- `characterize_as_param` phase-1 的 `justifiedContain` 调用切换到
  space-aware 形态（`loc` 在 Ghidra 原文携带空间）；7 个 `find_entry`
  调用点（build_trial_map/check_join×2/check_split×2/possible_param/
  possible_param_with_slot/fillin_map）签名去 `Option`（Ghidra 的
  `loc.getSpace()` 恒存在，与 characterize 的显式空间形态一致）。
- 双侧 fixture：`tests/oracle/fspec_findentry_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_findentry_oracle.sh`（四 case 29 行：窗口内外几何、
  just=false 的 NULL 形态、join piece 访问与位置序、跨空间 join 的
  per-piece 空间守卫、find/characterize 对照）。`fspec_phase0_1204` 的
  12 行 findEntry 投影在新窗口语义下逐行不变（已复核），无需重钉。

### 2026-08-24：possible_param join 可达 + assumed_extension 空间守卫（FSPEC-POSSIBLEPARAM-JOIN-0006，A46 残差 3）

- `ParamListStandardOut::possible_param`（cc:1765-1774）：删除调用方级
  `get_space() != space` 过滤（Ghidra 原文遍历**全部** entry，无空间过滤、
  无 resolver 窗口、无 minSize 门），逐 entry 改走
  `justified_contain_in_space(loc, size, space)`：
  - **join entry 可达**（旧过滤把 spaceid=join 空间的 entry 结构性排除）：
    join walk 逐 piece 空间守卫（address.cc:133），`0x104/4` 返回 offset
    4，`>= 0` 即 true（对比 `find_entry(just=true)` 的 `== 0` 门——
    possibleParam 接受未对齐包含）；
  - 普通 entry 的空间拒绝只发生在 `justifiedContain` 内部
    （cc:269 对齐路由 / address.cc:133 exclusion 路由），
    异空间数值巧合 offset 不再假命中；
  - 无 minSize 门：小于 entry minsize 但数值包含的查询仍 true。
- `ParamEntry::assumed_extension`（cc:366-394）签名增补
  `query_space: AddressSpace`（`addr` 在 Ghidra 原文携带空间）：
  cc:377 的 `justifiedContain(addr,sz)!=0` 调用改走 space-aware 形态——
  异空间查询在数值上 justified 的 offset 也返回 `CPUI_COPY`
  （旧 spaceless 形态会误报 ZEXT/SEXT/PIECE 并写入 res）。join entry 在
  cc:376 已提前返回 COPY，不达该调用。容器回写两种形态不变
  （alignment!=0 整对齐 cc:383-388 / exclusion 整 entry cc:378-382），
  flag 优先级 zext→inttype→sext（cc:389-393）。
- `ParamListStandard::assumed_extension`（cc:1426-1437）签名随之增补
  `space: AddressSpace` 透传（list 级 minSize 跳过 cc:1431 不变）。
- 单测 4 个：`test_param_list_standard_out_possible_param_join_and_space`、
  `test_param_list_standard_out_possible_param_aligned_foreign_space`、
  `test_assumed_extension_space_join_and_minsize_gates`、
  `test_assumed_extension_exclusion_container_and_flags`。
- 双侧 fixture：`tests/oracle/fspec_possibleparam_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_possibleparam_oracle.sh`（四 case 34 观察行：普通 entry
  的 `>=0` 接受与双空间守卫路由、join 可达性与 poke-out、跨空间 join 的
  offset-4 接受、assumed_extension 的异空间 COPY/join 守卫/sz 门/
  minSize 跳过/双容器/flag 优先级）。
- 残差：BE 空间行仍 UNTESTED（ADDRESS-0001 过渡 enum 小端限定）；
  spaceless `justified_contain` 的其余调用方（`unjustified_container`
  cc:1411、`ParamListStandard::fillin_map` cc:1382-1410 两处 trial 查询）
  不在本租约内，保持过渡形态。

### 2026-08-25：unjustified_container/fillin_map_fallback 空间线程化（FSPEC-SPACELESS-REMAINDER）

最后两处 spaceless `justified_contain` 调用方收口（A46 残差 4，由
FSPEC-POSSIBLEPARAM-JOIN-0006 的 metadata residual 登记）：

- **`ParamListStandard::unjustified_container`（cc:1411-1424）** 签名增补
  `space: AddressSpace`（Ghidra 从 `const Address &loc` 携带；过渡
  spaceless `Address` 需旁路传入——同 `find_entry`/`assumed_extension` 形态）。
  cc:1417 的 `justifiedContain(loc,size)` 改走
  `justified_contain_in_space(loc, size, space)`：异空间查询在数值上
  unjustified 的 offset 也返回 hit=0（旧 spaceless 形态会把 stack 查询
  数值巧合地匹配进 register/ram entry 并回写容器）；join entry 经逐
  piece walk 可达，cc:295-302 `getContainer` 回写**包含该 range 的
  piece**（register:0x100/4），而非整个 join。调用方级无空间过滤
  （Ghidra 没有）；minSize 门（cc:1415）在 justifiedContain 之前跳过
  entry；just==0 提前返回 false（cc:1420）。
- **`ParamListStandardOut::fillin_map_fallback`（cc:1638-1719）** 两处
  trial 查询（cc:1656 逐 entry 评估 + cc:1702 best entry 复评）均改走
  `justified_contain_in_space(t_addr, t_size, t_space)`，并**删除自创的
  调用方级 `curentry.get_space() == t_space` 守卫**——该守卫使 join
  entry 永不可达（join space != register），Ghidra 中 join 经逐 piece
  空间匹配可达：register trial 命中 join 后被 mark_used/set_entry，
  而旧代码 bestentry 为 null、全部 trial markNoUse。异空间 rejection
  只发生在 walk 内部（逐 piece address.cc:133 / fspec.cc:269 +
  address.cc:133），与 plain entry 行为等价。
- 单测 2 个：`test_unjustified_container_space_guards_and_join`、
  `test_fillin_map_fallback_join_reachable`（含 bestentry null 分支）。
- 双侧 fixture：`tests/oracle/fspec_spaceless_rem_1204.{cc,rs,metadata.json}` +
  `tools/run_fspec_spaceless_rem_oracle.sh`（7 case 31 行：uc 普通 entry
  的跨空间拒绝/对齐路由/minSize 门/just==0 早退、uc join 可达性与
  piece 容器、fb plain best-cover 与 tie 拒绝、fb join 可达性（核心
  分歧行）、fb 跨空间 join piece、fb firstOnly 跳过与放行）真实双侧
  执行 byte-identical。
- 关联重钉：`fspec_phase0_1204`（unjustified_container 唯一存量调用方）
  更新调用签名并重钉 comparand；possibleparam/findentry/endian_resolver
  runner 的 fspec_rs pin 因本次 src 变更滞后，登记 TODO
  `FSPEC-PIN-STALE-0002` 待重钉。
- 残差：BE 空间行仍 UNTESTED（ADDRESS-0001 过渡 enum 小端限定）；
  fspec 内 spaceless `justified_contain` 生产调用方清零（仅
  `justified_contain_in_space` 内部委托与测试保留）。
## locked_output_storage 域（FSPEC-LOCKEDOUTSTORAGE-0001，2026-08-25）

新增 `FuncProto::locked_output_storage`（coreaction.cc:4637-4648 的
outparam getAddress/getSize 支撑）：解析类型锁定返回值的存储为
`(space, offset, size)`。Ghidra 的 `FuncProto::getOutput()` 携带已解析
ProtoParameter（锁定签名时地址由模型输出指派固定）；Rugra FuncProto 只保存
返回数据类型，故按需跑同一指派：`ProtoModel::assignParameterStorage` 的输出
半（fspec.cc:2429-2440），再把指派 offset 映射回所属输出 ParamEntry 恢复
空间标识（ParameterPieces.addr 在过渡 Address 模型中无空间）。void/不可
指派返回返回 None；assignAddressFallback 在成功路径 piece.type 为 null
（fspec.cc:748-770），只有降级 void 兜底才填 void 类型（fspec.cc:2438-2442）
——前置 metatype 过滤后残余 Some(void) 即降级信号，同样返回 None。
消费方：coreaction.rs ActionPrototypeTypes Step 3（锁定 RETURN 读插入）。

## spacebase placeholder 链（HERITAGE-GUARD-STACKOFFSET-0001，本次新增）

`FuncCallSpecs` 的 stack-pointer placeholder 解析闭环，1:1 对齐
`fspec.cc:4849-4921`：

- `FuncProto::get_spacebase`（fspec.hh:1611）：委托 `model->input.get_spacebase()`
  （ParamListStandard 的 `space_base`，仅当模型 input 列表含 stack pentry 时
  非 None）。cspec 解码路径已在 pentry 循环设置该字段。
- `FuncCallSpecs::create_placeholder`（fspec.cc:4849-4858）：
  `opStackLoad(spacebase,0,1,op,null,false)` + `opInsertInput` 追加为 CALL 最后
  一个输入，`setStackPlaceholderSlot(slot)` + `setSpacebasePlaceholder()`。
  调用方：`ActionFuncLink::apply` 的 funcLinkInput 尾巴（coreaction.cc:1511-1513）。
- `FuncCallSpecs::set_stack_placeholder_slot` / `clear_stack_placeholder_slot`
  （fspec.hh:1653/1654）：slot 索引记录。
- `FuncCallSpecs::resolve_spacebase_relative`（fspec.cc:4870-4908）：当
  `RuleLoadVarnode` 把 placeholder LOAD 解析为 COPY 后（ruleaction.cc:4294-4303
  尾巴），读取 COPY 源 varnode 的偏移写入 `stackoffset`；placeholder 本身在
  placeholder slot 时走 `abort_spacebase_relative` 清除；input-locked 路径从
  锁定参数地址换算（`stackoffset -= addr.offset` + wrapOffset）。Ghidra 的
  LowlevelError 以 stderr 约定呈现（驱动无异常通道）。
- `abort_spacebase_relative`（fspec.cc:4910-4921）死锁修复：原实现
  `if let Some(def) = vn.read().unwrap().def...` 的 scrutinee 临时 read guard
  在整个 if-let 体内存活，而 `op_destroy(LOAD)` → `destroy_varnode(vn)` →
  `make_free(vn)` 需要 `vn.write()` —— 单线程 RwLock 自死锁（main() worker
  futex 挂起，coredump 栈 `abort_spacebase_relative → op_destroy →
  op_unset_output → make_free_prevalidated` 复现）。修复为先在块作用域内快照
  `def_to_destroy` 再 destroy，保序等同 oracle。

可观测效果：stackoffset 已解析的 call 使 `Heritage::guard_calls` 的
`has_effect_translate` 命中模型 effectlist（unaffected/killedbycall），不再为
每个 (stack range × call) 生成 unknown-effect INDIRECT（main 从 8190 个 guard
INDIRECT 降至 ~5460，mainloop repeatapply 收敛轮数 37+ → 1）。

## 2026-08-25（ACTIONDW-COPYDEF-MARKING-0001）：FuncProto::possible_input_param + ProtoModelFull::possible_input_param

- **`FuncProto::possible_input_param(addr_offset, size, addr_space)`**（fspec.cc:4366-4387）：`!isDotdotdot` 时先过 `void_input_locked` 门（→false），再遍历锁定参数 `justifiedContain(param_size, addr, size, false)==0 → true`、`locktest` 后无命中 →false；否则落到 model。锁定参数环与仓内兄弟移植 `characterize_as_input_param`（fspec.rs:410）同一降级口径：Rugra `ProtoParameter` 存无空间 `Address` 且无独立 size，锁定环 inert；protorecovery 阶段（本方法唯一调用方 ActionDirectWrite cc:1368）`numParams()==0`，控制流与 oracle 的 num==0 路径完全一致。modelless FuncProto 是 Ghidra 不存在的状态，保守返回 false。
- **`ProtoModelFull::possible_input_param(loc_space, loc, size)`**（fspec.hh:883 内联）：`input->possibleParam(loc,size)` 一行委托。

## 2026-08-26（TRI2-CALLOUT-ASSIGN-0001）：build_output_from_trials 签名对齐 vector<Varnode*> trialvn

- `trial_vn` 参数从 `&[Varnode]` 改为 `&[Option<Varnode>]`：Ghidra 的
  `vector<Varnode*> trialvn` 是 dense 位置索引表（fspec.cc:5541-5542 pad 到
  `getNumTrials()`），`None` 即 C++ null 槽位。slot 在 registration 时从 1 编
  （fspec.cc:1963-1975 slotbase），随 trial 穿越 `sortTrials`，故
  `curtrial.getSlot()-1` 恒为原 registration 位置——**禁止**压缩列表。
- finalvn 同为 `Vec<Option<...>>`；单 trial 路径 `finalvn[0]` 依
  used⟹active⟹非空 不变量（fspec.cc:1704 + 5672-5673）解包，空即 panic
  （C++ 侧为解引用崩溃）。
- 2-trial join 路径：`findPreexistingWhole`（fspec.cc:5750-5760）未移植，
  恒走 caller-supplied join hook——TODO(FSPEC-OUTPUTJOIN-0001)；
  `setPrecisLo/Hi` 同登记该 TODO。

## 2026-08-26（续，TRI2-CALLOUT-ASSIGN-0001）：FuncCallSpecs::derive_output_map 路由到 FuncProto::model

- 调用点从简化 `type_system::protomodel::ProtoModel`（"first active" 规则、
  无排序）改路由到 Ghidra 的单一模型字段 `FuncProto::model`
  （fspec.hh:1501-1502 `model->deriveOutputMap(active)`）→
  `ParamListStandardOut::fillin_map`（fspec.cc:1721-1763；无输出 modelrule
  的 legacy 模型 defer 到 `fillin_map_fallback` fspec.cc:1638-1719）。
- 决定性语义：`fillinMapFallback` 尾部 `sortTrials()` 的 entry==null
  比较臂（fspec.cc:1907-1908）把未匹配/inactive trial 排到队尾——这是
  `buildOutputFromTrials` 的 `if (!curtrial.isUsed()) break;` 重排循环
  （fspec.cc:5778）所依赖的 used-first 不变量的来源。旧路由下 myprogress
  出现 [inactive, active] trial 序 → finalvn 空 → 越界 panic（修复后 0
  panic、76/124 反编译恢复）。
- `derive_input_map` 的同构路由残差登记 TODO
  （FSPEC-DERIVEINPUT-ROUTING-0001，ActionActiveParam 域）。
  **合并注记（2026-08-26 master 并入）**：master 侧 MAINDIFF-CALLPROTO-0001
  已将 `derive_input_map`/`derive_output_map` 统一路由到
  `prototype.model`（full-model 优先、简化 seam 回退），该 TODO 就此关闭，
  以 master 实现为准。

## 调用实参收敛链（MAINDIFF-CALLPROTO-0001，master 并入）

`FuncCallSpecs` 输入参数收敛的完整闭环，1:1 对齐 fspec.cc:5685-5741 与
fspec.hh:310-317/1653-1654：

- `build_input_from_trials(fd, call_op)`（fspec.cc:5685 `buildInputFromTrials`）
  完整化：保留 fspec 输入槽 0 → varargs+locked 时 `sort_fixed_position` →
  逐 USED 试验：spacebase 试验按 `stackoffset` 换算 caller 视角、UNREF 试验
  经 `Funcdata::newVarnode`（bank create + assignHigh + queryProperties flag
  尾，funcdata_varnode.cc:148-165）新建 varnode、过大 varnode 经 SUBPIECE
  截断（fspec.cc:5720-5732，x86-64 little-endian 臂）→ `op_set_all_input`
  一次性重写 CALL 输入（fspec.cc:5739）→ spacebase 参数范围
  `scope.mark_not_mapped(off, sz, parameter=true)` →
  `delete_unused_trials()` 重排 slot。旧版只返回 (address,size) 表、
  从不落 CALL 输入（curl_version 6 试验参数的直接根因）。
- `new_for_op(op, _caller_funcp)`（fspec.cc:4926 `: FuncProto()` 基类初始化）
  改为组装全新默认 FuncProto（无参/无锁/extrapop unknown）；flow.rs 传入的
  caller funcp 克隆不再合成（oracle 中 caller 形参永不进入 call site——
  parseconfig 内 `__stack_chk_fail(filename,config)` 2 参 bug 根因）。
- `derive_input_map` / `derive_output_map`（fspec.hh:1494/1501）：优先走
  `prototype.model`（cspec 解码的 ProtoModelFull，input 为 ParamListStandard
  port，含 fspec.cc:1305-1312 "mark every active trial used" 尾环），仅在
  full model 缺席时回退简化版 `proto_model` seam。
- `commit_new_inputs`（fspec.cc:5150）修正：首个 IPTR_SPACEBASE（stack）锁定
  参数在 varnode 上 `set_spacebase_placeholder()` 并把待定 placeholder 置
  None（cc:5172-5177——锁定 stack 参数存在时不再追加 stack-pointer
  placeholder）；placeholder 重挂改经 `set_stack_placeholder_slot` inline
  （isinputactive 门控）。零调用方状态与 oracle 一致：仅 deindirect
  （fspec.cc:5466）/forceSet（fspec.cc:5497）调用，二者均在 CALLSPEC-0001
  未接线 seam 之后。
- `ParamActive::set_placeholder_slot`（fspec.hh:310）/
  `free_placeholder_slot`（fspec.cc:1995-2011：slot>placeholder 的 trial
  slot-1、stackplaceholder=-2、slotbase-1、maxpass=0）/
  `sort_fixed_position`（fspec.hh:317 + fixedPositionCompare fspec.cc:1920-1933；
  双 (-1) 臂在 deriveInputMap 的 buildTrialMap+sortTrials 之后以稳定排序
  保持既有 operator< 组序，entry-less trial 已被 markNoUse 不可观测）接入
  `set/clear_stack_placeholder_slot` inline（isinputactive 门控）。
- `characterize_as_param`（fspec.cc:1145）`max=-1` 哨兵防护：oracle
  `for(i=start;i<=max;++i)` 在无 active 试验前置链时循环体不执行，
  usize 回绕会反向饱和 hole-filling 循环（XMM0-7 unref 爆炸根因）。

### FSPEC-CALLPROTO-LATENT-0001：FuncCallSpecs 输入锁定谓词

`FuncCallSpecs` 继承 `FuncProto`；因此 `is_input_locked()` 必须委托
`FuncProto::isInputLocked`（fspec.cc:3906-3914），而不能要求所有参数都
存在且逐个 type-locked。Oracle 的顺序是：先检查 `voidinputlock`；若无参数
返回 false；否则只检查首参数的 `isTypeLocked()`。`setInputLock(true)` 在
无参数时设置 `voidinputlock`（fspec.cc:3921-3929），有参数时逐项设置
type-lock。Rugra 现已通过 `prototype.is_input_locked()` 对齐该门与首参检查；
空参数、void 锁定与多参数首参锁定均纳入域语义。

## 2026-08-28：FuncLink input 数据面限定证据

`FuncCallSpecs` 的 input/output `ParamActive` 现在永久嵌入，active 状态由
独立 boolean 表示；`init_active_input` 将正数 model max-delay 设为 3。
`ProtoParameter` 与 `ParameterPieces` 保留 coarse space，类型以同一 `Arc`
穿过 assignment，`swap_markup` 仅交换 type+flags。prototype flags 为
`this=1, hidden-return=2, indirect=4, name-lock=8, type-lock=16`。

`ACTION-FUNCLINK-INPUT-1204` 的 101-record 双侧输出逐字节一致，证明上述
scalar x86 input/slot/placeholder 投影。它不批准 `commitNewInputs/Outputs` 的
完整分支、ParamEntry join/reverse/endian/error 状态、hidden-return pointer、
ModelRules 或 Architecture-owned Address identity；`fspec` 保持 L2。


## 2026-09-23（SB-MATCHURL-ORD164-0001）：`<rule>` fillin 投影接入 output 派发链

- **根因**（match_url Phase 2 ordinal 164，`universal:fullloop:activereturn`
  op-idx 139）：exit@plt 调用点（0x53ee）的 RDX 输出试探（guardCalls
  killedbycall 臂 `newIndirectCreation` 的 const0 DELAY_SLOT）被错误提交为
  CALL 正式输出。链路：oracle `ParamListStandardOut::initialize`
  （fspec.cc:1614-1627）因 gcc `__stdcall` output 含
  `<join_dual_class/>`（`MultiSlotDualAssign` 构造器置
  `fillinOutputActive=true`，modelrules.cc:1143）而得
  `useFillinFallback=false` → `fillinMap`（fspec.cc:1721-1763）走规则步：
  `MultiSlotDualAssign::fillinOutputMap`（modelrules.cc:1242-1291）对唯一
  active 的 RDX 试探因 `!entry->isFirstInClass()`（RAX 才是 general 类
  首entry，resolveFirst fspec.cc:76-88）拒绝 → `fillinMapFallback(true)`
  的 firstOnly 过滤（cc:1649）跳过 RDX → 全部 markNoUse →
  `buildOutputFromTrials`（fspec.cc:5770-5860）在
  `getNumTrials()==0` 早退，CALL out=- 保持、const0 试探 INDIRECT 存活。
  Rugra 侧 `initialize` 钉死空规则分支（`use_fillin_fallback=true` 强制
  legacy）→ `fillin_map_fallback(active,false)` 的 firstOnly=false 让
  非-first 的 RDX entry 参选 → lone RDX 试探被 markUsed → 输出直连 +
  DELAY_SLOT 销毁（ordinal 164 分歧形态）。
- **修复**：`src/fspec.rs` 新增 `ModelRuleFillin`/`FillinAction` ——
  `<rule>` 元素到 fillin 相关状态的解码投影（`ModelRule::decode`
  modelrules.cc:1676-1709 只委托 assign action，datatype filter/qualifier/
  precondition/sideeffect 不进 fillin 路径，结构化跳过保持流位置）。
  七种 assign action（decodeAction 派发 modelrules.cc:587-614）中五种
  `fillinOutputActive=true`（GotoStack/MultiSlotAssign/MultiMemberAssign/
  MultiSlotDualAssign/ConsumeAs），`fillin_output_map` 逐行移植五种
  trial-walk（cc:731/902/1019/1242/1345）+ 默认 false 两种
  （ConvertToPointer/HiddenReturn，cc:579）。`ParamListStandard` 增加
  `model_rules` 字段，`decode` 的 `<rule>` 分支从 skip 改为真解码；
  `ParamListStandardOut::initialize` 忠实扫描
  `canAffectFillinOutput()`（仅 legacy 分支强制
  `auto_killed_by_call=true`）；`fillin_map` 在 `sort_trials` 后按声明序
  走规则（cc:1746-1761：首个接受的规则把 active 全部 markUsed、
  inactive markNoUse+清 entry 后 return），否则落
  `fillin_map_fallback(true)`。
- **验证**：match_url Phase 2 投影首分歧 164 → **191**（oppool2
  CROSSBUILD 族，新登记 SB-MATCHURL-ORD191-0001）；三门禁 curl 124
  函数 defects=0/numbering=0（skeleton 2795=亲父实测基线）、httpd 29/29
  0/0（2339=基线）、config 域 10 函数逐个 0/0、next_url Phase 2 投影
  MATCH 保持（335 stages/96457 ops）；cargo test --lib 串行 1650/18
  失败集与基线逐名一致；gcc 审计 81 OK/26 FAIL=预存基线。
- **残差**：`ModelRule` 的 forward `assignAddress` 消费端仍属
  FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001 / FSPEC-0002（本投影只覆盖
  fillin 两入口消费的状态）；`HiddenReturnAssign::decode` 的
  voidlock/strategy 读入后不入 fillin 状态（oracle 同样无消费）。

### 2026-09-23（HTTPD-CALL-PUSH-0001 RC3）：FuncCallSpecs::effective_extrapop 存储
- `FuncCallSpecs` 新增 `effective_extrapop: i32` 私有字段 + 
  `set_effective_extrapop`/`get_effective_extrapop`（fspec.hh:1687-1688 的
  inline 访问器镜像），构造初始化 `ProtoModel::extrapop_unknown`
  （fspec.cc:4927，`EXTRAPOP_UNKNOWN_FULL`）。此前该"每个调用点的实际
  extrapop"无存储面——`ActionExtraPopSetup`（coreaction.cc:1454）与
  `ActionStackPtrFlow::analyzeExtraPop`（cc:306）两处写回均无落点，
  CALLSPEC-0001 残差的主要存储半边就此闭合。
- 写入方：coreaction.rs 的 `ActionExtraPopSetup::apply`（已知 extrapop 分支
  cc:1454，调用点索引延迟到循环外统一回写避免借用交叉）与
  `analyze_extra_pop`（StackSolver 解出的 INDIRECT 变量按
  `soln-soln2` 写回，cc:302-307）。Ghidra 的 clone 携带面
  （fspec.cc:4971）在 Rugra 无 FuncCallSpecs 克隆路径，无对应物。

## 2026-09-23（BOOMATTR lane）：FuncProto 自函数参数恢复三件套 + updateInputNoTypes

- `FuncProto::resolve_model()`（fspec.cc:3767-3776 镜像）：null model 早退 +
  非 merged 模型早退——Rugra 的 `ProtoModelFull` 恒为具体模型，merged 分支
  （`ProtoModelMerged::selectModel`）不可达，保留完整签名面供 merged 支持
  落地时接通。
- `FuncProto::derive_input_map(&mut ParamActive)`（fspec.hh:1494-1495 inline
  `model->deriveInputMap(active)` = fspec.hh:791-792 `input->fillinMap(active)`）：
  与 `FuncCallSpecs::derive_input_map` 同一 dispatch；modelless FuncProto 是
  Ghidra 的非法状态（解引用即 fault），Rugra 生产侧由
  `ActionInputPrototype` 的 setScope-fallback glue 先绑模型，防御性 no-op 兜底。
- `FuncProto::unjustified_input_param(space,offset,size,res)`（fspec.cc:4426-4453）：
  锁定参数 justifiedContain 环（ ADDRESS-0001 退化同
  `characterize_as_input_param`：spaceless legacy Address + 记录的
  address_space 空间等价守卫替代 address.cc:133 的 `base != op2.base`）+
  模型 `unjustifiedContainer` 尾（fspec.rs:6946 已有移植首次接通到
  FuncProto 侧）。
- `FuncProto::update_input_types`：空类型折叠补齐——Ghidra high 类型永不为
  null（最少是尺寸派生 TYPE_UNKNOWN），Rugra `Option::None` 折叠为
  shared_default 工厂的 unknown base（对应 updateInputNoTypes 的
  fspec.cc:4118 factory 调用）；参数命名折叠为 `param_<count+1>`
  （ProtoStoreSymbol 的 ScopeInternal 符号在 commit 时按 category
  function_parameter + catindex 默认命名，database.cc:2481）。
- `FuncProto::update_input_no_types`（fspec.cc:4097-4128 全量镜像）：
  与 update_input_types 同 used-trial 走查，仅用尺寸——persist 臂用
  varnode 自身 (addr,size) 作 findDisjointCover stand-in（同
  update_input_types 的 persist 臂折叠）。

## 2026-09-23（BOOMATTR lane）：行为边界（实测）

- 调用方 = coreaction `ActionInputPrototype::apply`（fixateproto，见
  docs/api/coreaction.md 同日条目）。镜像契约下 main 19 参塌缩恢复为
  2 参（RDI int + RSI int8）、next_url 4→1（RDI）、match_url 3→2、
  myprogress 6→5、glob_word 9→5——全部与 direct-runner golden
  （tests/golden/ghidra_curl_1204.direct-runner.c）签名形态一致。
- 残差：未知类型命名轨道（`undefined8`/`unkbyte1` vs oracle
  `xunknown8`/`xunknown1`）与返回类型（`long` vs `xunknown8`）不折叠——
  属 TypeFactory 命名轨道域，非参数恢复语义。

## 2026-09-23（CHAINFIX lane EY2）：update_input_(no_)types 接通 ProtoStoreSymbol::setInput 折叠回调

- `FuncProto::update_input_types` / `FuncProto::update_input_no_types` 新增
  `store_set_input: &mut dyn FnMut(usize, &ParameterPieces)` 参数，在两处
  `store->setInput(count, "", pieces)` 调用点（fspec.cc:4079 / fspec.cc:4121）
  逐字镜像位置回调——Ghidra 的 store 是 ScopeLocal 背书的
  `ProtoStoreSymbol`（`FuncProto::setScope`，fspec.cc:3879-3885；
  `funcdata.cc:69` 以 `baseaddr + -1` 构造 restricted_usepoint），其
  `setInput`（fspec.cc:3147-3214）把 function_parameter category 符号装进
  ScopeLocal。Rugra 的 FuncProto 只持平铺 `parameters` store，该副作用由
  调用方（coreaction `ActionInputPrototype`）注入的闭包折叠执行；两函数
  本体（used-trial 走查、persist 臂、mark 清理、`update_this_pointer`）
  不变。回调签名 `&mut dyn FnMut` 保持单调用方（ActionInputPrototype）
  语义；无其他调用方。

## 2026-09-24：update_output_types 的 None→undefined 折叠（Lane GG2）

`pieces.ty = vn0.get_type()` 为 None 时折叠为 `get_base(size, Unknown)`
（undefined<N>）——对应 Ghidra 高类型永不为空的不变量：每个无类型 Varnode
自创建即携 `getBase(size,TYPE_UNKNOWN)`（Funcdata::newVarnode/newUnique/
newConstant，funcdata_varnode.cc:83/148/…），未约束返回值因此定型
`undefined8`（锁定 oracle 见证）。与输入侧 fspec.cc:4118 折叠约定一致。
此前 None 走 set_output_parameter 的保留旧值路径（void）。

## 2026-09-24（CR29 返工）：update_output_types 空表臂真 void 复位

fspec.cc:4142 的 `store->clearOutput()` 是**无条件 void 输出**（ProtoStoreInternal
:3389-3395 `ParameterBasic(voidtype)`；ProtoStoreSymbol:3262-3270 `getTypeVoid()`），
此前委托 `clear_unlocked_output`（仅清锁标志）保留了陈旧 return_type——af6c5ee2
Evidence 断言了未实现的行为（机制 D 红旗，CR29 件④子项①）。修正为该臂直接复位
return_type=void 基类型。另登记 PROTOSTORE-SIZELOCK-UPGRADE-0001（locked+
TYPE_UNKNOWN 态 Ghidra 可经 isSizeTypeLocked 臂升级而 Rugra 合流建模不可达；
含 fspec.rs:1608 合流的解除条件）。

## 2026-09-25（SPACEFIX lane）：buildInputFromTrials SUBPIECE 输出空间修正（FSPEC-DEALLOC-SPACE-0001）

CR-XCROSS 复核登记的 P2 空间钉死残留位：`build_input_from_trials` 过大参数
SUBPIECE 截断臂（fspec.cc:5720-5732，x86-64 little-endian 臂 cc:5726）此前经
spaceless 适配器 `new_varnode_out` 把 outvn 钉死 Register 空间。oracle 的
`data.newVarnodeOut(sz,vn->getAddr(),newop)` 中 `vn->getAddr()` 是**当前参数
varnode 的完整存储地址**（空间+偏移）——栈传参即 stack 空间、寄存器传参即
register 空间。修正为在读锁快照内一并捕获 `vn_r.get_space()`，改走
`new_varnode_out_full(sz, vn_space, vn_off, newop)`（与 XCROSS/OPZERO 同族
三元组同源修法：size 用参数型 sz、space/offset 用 vn 自身存储）。

- 探针实证（已回滚）：curl / httpd-default / httpd-SYMDB 三态 0 次触发
  （触发条件=USED 试验的现 varnode 大于参数型且需截断；现语料 call 参数
  均按槽位精确装载）——位点语料休眠，correct-by-construction。
- 门禁：三态输出与亲父 e452244d cmp 字节恒等（curl 1099/0/0、httpd
  1472/0/0、SYMDB 1328/0/0）；bank 26/26。

## 2026-09-25（CALLSPEC lane）：FuncCallSpecs badjumptable 数据面建模（CALLSPEC-0001）

JTEDGE 移交残差（ap_vhost_iterate_given_conn `code *UNRECOVERED_JUMPTABLE`
参数命名缺口）的 fspec 侧数据面补齐——四件落地，零行为变化（无 setter
调用点/无消费者接线，Rugra 生产侧恒 false = oracle 构造初值）：

- `is_bad_jump_table` 字段（fspec.hh:1660 `isbadjumptable`），置于
  `is_stack_output_locked` 之前保持 oracle 字段序（1658-1661:
  isinputactive/isoutputactive/isbadjumptable/isstackoutputlock）。
- 构造初值 `false`（fspec.cc:4945 `isbadjumptable = false`）。
- `set_bad_jump_table(bool)` / `bad_jump_table()` 访问器
  （fspec.hh:1701/1702 内联原样）。oracle 生产者 =
  `FlowInfo::truncateIndirectJump` 默认失败臂（flow.cc:754
  `fc->setBadJumpTable(true)`，Rugra 侧 flow.rs 截断臂仍 TODO 登记——
  flow 租约不在本 lane 写域）；oracle 消费者 =
  `ActionNameVars::lookForBadJumpTables`（coreaction.cc:2779-2803，按
  `sym->getScope()==localmap && !isNameLocked` 门把 CALLIND in(0) 的符号
  重命名 `UNRECOVERED_JUMPTABLE`，coreaction 侧同属移交）。
- `clone_for_op` 携带（fspec.cc:4974 `res->isbadjumptable =
  isbadjumptable`），文档注释同步撤下"isbadjumptable not modelled"。

### CALLSPEC 族残差量化与根因（车道证据，移交在案）

- 亲测基线（默认脸 1123/0/0，PDOTFORM 后）：ap_vhost_iterate_given_conn
  diff=50。族残差四桶：①循环路径真实 CALLIND（0x2daa5 `call *%r12`）
  零实参（canon/direct-runner 双 golden 均 3 实参
  `(param_3,param_1,iVar2)`）；②param_2 命名 `void(*)()param_2` vs
  `code *UNRECOVERED_JUMPTABLE`；③返回 join RDX:RAX 16B 存活
  （`auVar8._0_8_` 截断）vs canon 8B `xVar3`；④push 门店面
  （`*puVar6=0x2daa8` + puVar6/puVar7/uStack_40/auStack_38 追踪链）。
- ①的根因（本 lane A/B 亲证）：`inject_raw_ops` 相位 1.5 锚定环只认
  `CPUI_CALL`（funcdata.rs，CALLSPEC-DRIVER-0001 时代注释"lifter 只产
  CALL"已过期——iced lifter 对寄存器间接调用产 `CPUI_CALLIND`，
  x86_lift.rs:4890-4894），lifter 出生 CALLIND 全程无 FuncCallSpecs →
  ActionFuncLink 不激活输入恢复 → heritage guardCalls 不注册
  RDI/RSI/RDX 试验 → 打印零实参。补 CALLIND 锚定臂（flow.cc:340-342
  xrefControlFlow CALLIND 臂 → setupCallindSpecs 无 in(0) 换写的镜像）
  A/B 实测：ap_vhost 50→**14**、main 间接调用点
  `(*(code *)pVar8)();`→`iVar2 = (*(code *)pVar8)((long)plVar9+0x34,*plVar9);`
  （==canon 逐形），curl 727/0/0 与 bank 391/391 不动；但 httpd 总量
  1123→**1175**（main +88 = MERGE-COPYNOISE-DIFFHIGH-0001 吸收缺口的
  新表面：canon 把 killedbycall 栈重载拷贝吸收进命名高变量
  `strcasecmp(pcVar13,...)`，Rugra 读槽位 `strcasecmp(plVar9[3],...)` +
  自赋值店面换形 + 对齐回声）——违反默认脸不回退门，**该锚定臂已回滚
  暂存于车道证据**，解锁条件=MERGE-COPYNOISE 吸收域（merge 相 Cover）
  落地后重放。
- ②需 flow.rs 截断臂 setter + coreaction lookForBadJumpTables 消费者
  （均不在本 lane 写域，随本字段一并在案）；③=activereturn/processJoins
  存根（COREACTION-JOINSPACE 残差行）；④与 ①同根（无 spec →
  callOpIndirectEffect 极性保守 → 栈屏障 INDIRECT 全开）。

### 2026-09-25：opCall entry 空间通道填充侧（PRINTC-OPCALL-ENTRYSPACE-0001 fspec 半项，Lane FSPECW）

- **记录点带空间**：`FuncCallSpecs::new_for_op` 的 entry 快照（varnode 守卫
  先释再锁 callspec 的锁序保持不变）此前产 `Address::new(offset)`——无空间
  legacy 形。oracle 的记录点是 fspec.cc:4934
  `entryaddress = call_op->getIn(0)->getAddr()`：CALL 注解化**前**的 in(0)
  varnode 完整地址（空间+offset）。Rugra 的 in(0) varnode 只携带 flat
  `AddressSpace` enum（`loc` 恒 spaceless），故经新增 RUGRA-GLUE 桥
  `entry_address_with_space(space, offset)` 以 ADDRESS-0001 tag 形重建完整
  地址：per-variant stand-in 句柄（thread-local 单例表，携带该 variant 的
  name/addrsize/wordsize）+ 原offset。
- **行为面**：offset 通道逐字节不变（annotation varnode 的
  compatibility_offset、fspec_print_raw 十六进制、encode offset 全走
  `as_u64()`）；空间通道激活——printc 的 `entry_addr_dims`
  （`fc->getEntryAddress()` 消费侧，NAMFIX 已落）从 flat Ram 兜底改为解析
  stand-in 的真实 dims；`space_name_for_addr`（fspec.cc:2132-2133
  `writeSpace` 镜像）从硬编码 "ram" 改为读 tag 名，legacy spaceless 形
  （set_funcdata/deindirect 调用方传入的 ADDRESS-0001 phase-1 形）保留
  "ram" 占位。CALLIND 仍 None（fspec.cc:4942 间接调用不记录）；克隆臂
  （in(0) 已是 FSPEC 注解）仍经 typed Weak 恢复原 spec 的 entry（fspec.cc:
  4935-4940，含其空间 tag）。
- **休眠正确化**：当前双语料（curl/httpd）所有直接 CALL 的 in(0) 均为 ram
  空间（SLEIGH `*[ram]` export 与 iced `VarnodeRaw(Ram,…)` 两路同形），
  stand-in dims (8,1) == flat Ram 兜底，printc func_ 兜底面 0 触发
  （NAMFIX 已证）——E2E 输出恒等；单测
  `test_new_for_op_entry_addr_carries_in0_space` 钉 ram/const/iop/克隆四臂。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 3 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-26 — MIGW-FSPEC batch 1-2（EffectRecord 相等面 / ParamUnassignedError / ParameterBasic 旗标面 / ParamEntryRange 解析器数据面，Lane MIGWFSPEC）

- **EffectRecord 相等性**：`impl PartialEq for EffectRecord` 按 oracle
  fspec.hh:1769-1781 逐字段投影——`range != op2.range` 展开为
  (space, offset, size) 成员比较 + `type == op2.type`。消费方
  `ProtoModelMerged::intersectEffects`（fspec.cc:2791-2800）依赖"地址相等
  且效果类型相等"才保留的语义。
- **ParamUnassignedError**（fspec.hh:63-66）：`assignParameterStorage` 无法
  为某原型位分配存储时抛出；Rust 形态为独立错误类型（String 载荷），
  供 `FuncProto::updateAllTypes`（fspec.cc:4220-4222）的 catch 位模式匹配。
- **ParameterBasic 旗标面（坍缩注记）**：Rugra 扁平 `ProtoParameter` 即
  Ghidra `ParameterBasic` 的承载形态（结构文档已有注记）。本批补齐
  `is_name_locked`/`is_size_type_locked`/`is_indirect_storage`/
  `is_name_undefined`/`from_pieces`/`set_type_lock`（含 TYPE_UNKNOWN 时
  附带 sizelock 的 cc:2929-2930 语义）/`set_name_lock`/
  `override_size_lock_type`（尺寸必须精确相等 + 必须已 sizelock，否则
  Err 镜像 throw）/`reset_size_lock_type`（经 TypeFactory 取同尺寸
  TYPE_UNKNOWN）/`get_symbol`（恒 Err 镜像 cc:1190 throw）。
  `impl PartialEq for ProtoParameter` 镜像基类内联 ==（fspec.hh:1144-1155）：
  仅比存储地址 + 类型身份（`Arc::ptr_eq` 承载 Ghidra 指针等值），名字与
  旗标不参与。
- **ParamTrial::slot_group**（fspec.hh:265）：`entry->getSlot(addr,size-1)`
  经 entry-index 投影（trial 持索引，调用方传 entry 切片）。
  **ParamActive::test_shrink/shrink**（fspec.hh:329/336）：到
  `trial[i]` 的逐字转发（shrink=endianness 参数由调用方携带，见
  `ParamTrial::test_shrink` 注记）。
- **ParamEntryRange 家族（fspec.hh:157-194，11 条）**：
  `ParamEntryRange`（first/last/position/entry-index）、`InitData`
  （→`ParamEntryRangeInitData`）、`SubsortPosition`（含 `bool ? 1000000 : 0`
  极值形）、ctor/`getFirst`/`getLast`/`getSubsort`/`getParamEntry` 全部
  落地。`ParamEntryResolver`（rangemap 的 Vec 投影，按 (first, position)
  = (linetype, subsort) 序）提供 `insert`/`find`（物化"包含该 offset 的
  全部 range"迭代器对）与 `has_range_starting_above`（cc:708
  `iterpair.first != resolver->end()` 门探针）。
- **resolver 数据面接通**：`ParamListStandard::populate_resolver`/
  `add_resolver_range` 从 TODO 存根变为真实实现（cc:1174-1216 逐字：join
  entry 按 piece 逐段注册、position 每段 +1、per-space 惰性建表）。
  **管线零行为变化**：现行 `find_entry` 线性扫描与 `characterize_as_param`
  查询路径未改动，resolver 仅作数据面填充 + `resolver_for` 查询面；
  `stack_entry_index` 缓存行为保持（非 exclusion 栈 entry 最后写入者胜）。

### 2026-09-26 — MIGW-FSPEC batch 3-4（ParamListMerged / ScoreProtoModel / ProtoModelMerged / UnknownProtoModel + ProtoModel 查询转发面，Lane MIGWFSPEC）

- **ParamListMerged（fspec.hh:712-724 + cc:1794-1833）**：owned-base 形态
  （`base: ParamListStandard` 承载 C++ 公有基类）。`fold_in` 逐字移植——
  空并集直取 op2 的 spacebase+entry 列表；spacebase 冲突（op2 侧非空）报
  "Cannot merge prototype models with different stacks"；subsume 分类
  （existing subsumes new=typeint2 / new subsumes existing=typeint1，扫描
  首个命中即断）+ minsize 不齐降级 append + typeint1 原位替换。
  `finalize`=`populateResolver`；`assignMap`/`fillinMap` 拒绝形（Err 镜像
  LowlevelError）。ctor 双形态（decode 形 + ParamListStandard 拷贝形）。
- **ScoreProtoModel（fspec.hh:1040-1064 + cc:2705-2775）**：PEntry
  （origIndex/slot/size，Ord=slot）+ ctor（finalscore=-1, mismatch=0,
  reserve(numparam)）+ `add_parameter`（输入侧走
  `possible_input_param_with_slot`，输出侧 `possible_output_param_with_slot`，
  miss 计 mismatch）+ `do_score` 逐字（penalty 表 16/10/7/5、flat 3、
  duplication 20、hole 逐槽累加、nextfree 推进三分支、终分
  basescore+20*mismatch）。
- **ProtoModelMerged（fspec.hh:1077-1090 + cc:2834-2921）**：整型落地。
  `fold_in`——glb 守卫由单 Architecture 表结构性吸收（同表模型共享 glb）；
  p_standard/p_register 输入种类守卫由 ProtoModelFull::input 共享 owner
  形态结构性通过（register 残差已在 build_param_list 注记）；首折
  分配 merged input + 拷贝 output StandardOut 面 + extrapop/injects/
  effects/trash/ranges 逐字复制；后续折 input foldIn + extrapop 不齐降
  `EXTRA_POP_UNKNOWN`(0x8000) + inject 不齐报错 + effects/trash/internal
  三相交（复用既有 `ProtoModelFull::intersect_effects/intersect_registers`
  静态助手术语）+ localrange/paramrange 取并。`select_model` 逐字：严格 <
  保首个最优、score==0 早退、无 <500 者报 "No model matches : missing
  default"。numModels/getModel/isMerged 访问面齐。
- **UnknownProtoModel（fspec.hh:1025-1032）**：alias 拷贝构造（经
  ProtoModelFull::clone 承载 `ProtoModel(nm,*placeHold)`）+ 改名 +
  `placeholder_model` Arc 保身份 + `get_placeholder_model`/`is_unknown`。
- **ProtoModel 查询转发面（fspec.hh:812-975 内联族，12 条）**：
  check_input_join/check_output_join/internal_iter/characterize_as_output/
  possible_input_param_with_slot/possible_output_param_with_slot/
  unjustified_input_param/assumed_input_extension/assumed_output_extension/
  get_biggest_contained_input_param/get_biggest_contained_output 落到
  ProtoModelFull。effectBegin/effectEnd/trashBegin/trashEnd（hh:840-843）
  既有 `effect_iter`/`trash_iter` 切片访问器即迭代器对等价物（hh:1017-1021
  同名族已锚），本轮仅补 internalBegin/internalEnd。

### 2026-09-26 — MIGW-FSPEC batch 5-6（FuncProto 方法残项 / ParameterSymbol / ProtoStoreSymbol / internal-store encode / setScope，Lane MIGWFSPEC）

- **FuncProto 方法残项**：`update_output_no_types`（cc:4172-4185 逐字：locked
  直返 / 空 trial 清输出 / 否则 trial[0] 地址 + getBase(size,UNKNOWN) 重建）、
  `check_input_join`/`check_input_split`（hh:1513/1524 转发模型）、
  `remove_param`（hh:1534 store->clearInput 的扁平 Vec::remove 投影）、
  `internal_iter`（hh:1551-1552 → model.internal_iter）、
  `assumed_input_extension`/`assumed_output_extension`（hh:1586/1599 转发）、
  `get_this_pointer_storage`（cc:4516-4533：无 thisptr 模型得 None；
  assignParameterStorage(ignoreOutputError=true) 后首个非 hiddenretparm 输入
  piece 的地址）。effectEnd/trashBegin/trashEnd（cc:4251/4260/4269）由既有
  `effect_iter`/`trash_iter` 切片访问器承载（FuncProto 侧 override-empty
  委派语义已在其中），本轮不重复实现。
- **ParameterSymbol（hh:1256-1279 + cc:2981-3099）**：整型落地，
  (scope, Option<symbol>) 对承载 C++ 虚接口。13 个访问器全部逐字：读走
  Symbol（name/type/五旗标），getAddress/getSize 经
  `get_first_whole_map(scope.entries)`；`set_type_lock`（attr mask =
  typelock|(≠undefined: namelock)，cc:3047-3058）、`set_name_lock`、
  `set_this_pointer`（=Scope::setThisPointer 的 Symbol 直改，database.hh:770）、
  `override_size_lock_type`/`reset_size_lock_type`（callee Scope 版逐字，
  database.cc:1387-1408）、`clone_refuses`（Err 镜像 throw）、`get_symbol`。
- **ProtoStoreSymbol（hh:1286-1306 + cc:3103-3303）**：整型落地。
  ctor 装载 void outparam；`get_symbol_backed` 惰性缓存视图；
  `set_input` 大体逐字（category-0 符号解析 → 存储 mismatch 移除重建 →
  新符号 addSymbol+setCategory+mirror 旗标 → 既有符号只打 attr 增量 +
  改名/改型）；`clear_input`（去类目+移除+重编号）、`clear_all_inputs`、
  `get_num_inputs`、`get_input`、`set_output`/`clear_output`/`get_output`、
  `duplicate`（=clone，inparam 缓存惰性重建）、`encode_noop`（cc:3293 注释
  语义）、`decode_refuses`。Rugra 适配注记：add_symbol 走 type_name 形 +
  dtype Arc 直挂；discoverScope 的多 scope usepoint 纪律为 ADDRESS-0001 期
  残差（单函数 Scope 全拥 category-0，restricted_usepoint 恒为操作形）。
- **encode_internal_store（cc:3421-3462）**：`<internallist>` 序列化逐字
  （retparam typelock+addr+typeref / null outparam 的空 addr+void 对 /
  每 param 的可选 name+真值旗标+addr+typeref）。FuncProto::encode 的
  `encode_store` 钩子从此有真实实现可传。
- **FuncProto::set_scope（cc:3879-3885）**：装 `symbol_store` +
  无模型时取 default_model。`set_input_parameter` 在 store 存在时路由到
  符号侧（管线零行为变化：现无调用方设置 scope）。扁平 `parameters`
  保持 ProtoStoreInternal 投影同步。

### 2026-09-26 — MIGW-FSPEC batch 7-8（FuncCallSpecs 调用点族 / internal-store encode 剩项 / assignAddressFromPieces + B2 fixture，Lane MIGWFSPEC）

- **FuncCallSpecs 调用点族**：`compare_by_entry_address`（hh:1740）、
  `get_spacebase_relative`（cc:4982-4992：占位 slot→spacebase 占位 varnode→
  LOAD def→取 in(1)）、`check_input_join`（cc:5349-5368：active 拒绝/规模
  拒绝/hi-lo 尺寸核对/模型 checkInputJoin 终裁）、`do_input_join`
  （cc:5376-5395：locked 拒绝；constructJoinAddress 为闭包接缝）；
  `late_restriction`（cc:5408-5431：无模型整拷 / 兼容+dotdotdot 门 /
  locked 输入输出转移 / 终拷）、`force_set`（cc:5485-5509：override 登记→
  late_restriction→commit 或 restart→恒锁 + 双 error 旗标采纳；
  commit 钩子沿用既有接缝形）、`insert_pcode`（cc:5517-5528：负 id 直返/
  payload 查证/live-inject 接缝）、`collect_output_trial_varnodes`
  （cc:5536-5557：premature-output 拒绝/尺寸对齐/INDIRECT 创建回溯/试件
  地址重钉）、`check_output_trial_use`（cc:5661-5677：checked 拒绝/
  active-inactive 二分）、`find_preexisting_whole`（cc:5750-5760：双 lone
  descendant 同一 PIECE→其 out）。
- **FSPEC-OUTPUTJOIN-0001 半项**：`find_preexisting_whole` 移植完成
  （静态方法本体 + 双 loneDescend/同一 PIECE/取 out 语义）。管线接线
  **暂缓**（MIGW-FSPEC-0004）：hi/lo 的 def 本就是同一 PIECE op（两 piece
  的 loneDescend 即 PIECE），销毁语义两臂同形；join 钩子增加 Some(whole)
  复用臂属钩子契约变更，须随自身差分证据另行票决。
- **FuncProto error_outputparam**（hh:1352/1464/1471）：`has_output_errors`/
  `set_output_errors` + 旗标字段（forceSet 依赖）。
- **ParameterPieces::assign_address_from_pieces**（cc:2191-2207）：
  least→most 就地反转 → JoinRecord::merge_sequence 折并（经
  space::VarnodeData 尺寸域转换）→ 单 piece 直取地址 / 多 piece 走
  findAddJoin 闭包（吸收 SpaceVarnodeData 空间模型转换）。
- **B2 双侧 fixture `fspec_score_merged_1204`**：ScoreProtoModel 罚分走
  （exact 0/hole 16/dup 20/mixed 56/mismatch25 500 阈值/output 0）、
  ParamListMerged::foldIn（adopt/replace/subsumed/different-stacks 拒绝/
  finalize 后 characterize+slot 查询）、ProtoModelMerged::foldIn
  （首折采纳/extrapop 降 unknown/inject 拒绝/effects+trash 相交）、
  selectModel（strict-< 首优/无 active/500 阈值拒绝）。oracle 直跑（锁定
  源自建 libdecomp + FixtureArchitecture/SpacebaseSpace 手工构型）与
  Rust 侧 25 行字节全等。**该 fixture 抓到并修正一处移植缺陷**：
  `ProtoModelMerged::fold_in` 曾误把 model push 进 modellist——oracle 证据
  （两次 foldIn 后 numModels()==0）证明 push 属 decode（cc:2918）。
  C++ 侧构型注记：output 列表必须 populateResolver（fspec.cc:1504 配置
  形态;12.0.4 findEntry 走 resolver）。

### 2026-09-26 — MIGW-FSPEC 终验补丁（锁缺陷修复 + resolver 幂等 + fixture 重钉，Lane MIGWFSPEC）

- **Rust 回归测试抓到 `ProtoStoreSymbol::set_input` 自死锁**：if-let 绑定持有
  scope 读锁跨 `set_category` 写请求（同线程 read+write 相持）。读锁作用域
  收敛到查表语句后修复（oracle 侧无锁不显现——双侧 fixture 之外 Rust 侧
  并发语义自行兜底的实例）。
- `ParamListStandard::populate_resolver` 先清表再插（Ghidra 恒对新表调用——
  decode cc:1504 一次、拷贝 ctor cc:610 对新拷贝；清表使 Rust 跨阶段 staging
  调用幂等，保持 fresh-map 前置条件）。
- 测试修正两笔：compare_by_entry_address 测试经 set_funcdata 建条目（ctor
  只记 op 地址）；resolver extent 查询点 0x202（0x204 在 4B 域外）。
- fixture 元数据重钉（fspec_rs/crate tree），runner 端到端复验 PASS
  （ghidra=rugra=df4b4fbd…，25 行字节全等）；全部门禁在最终态复跑：
  cargo test --lib 1758/0、canon curl+httpd vs 基线 0/0 行差、
  镜面四面 PASS、bank 391/391、annotations/refs OK。

### 2026-09-26 — FSPEC-DEINDIRECT-TRIGGER-0001（FuncProto is_override / deindirect+forceSet 生产化 / commit 生产 hook 族，Lane FSPECDEIN）

以锁定 oracle `Ghidra 12.0.4`（commit `e40ed13014025f82488b1f8f7bca566894ac376b`）
亲读 `fspec.cc:5005-5027/5150-5190/5201-5329/5408-5431/5443-5472/5485-5509` 与
`fspec.hh:1544-1545` 后落地（TRIGFACE 测绘票：oracle fspec 两触发点在 Rugra
生产不可达——ActionDeindirect 部分重实现，永不 pending）：

- **`FuncProto` 补 `is_override` 旗标**（fspec.hh:1357 `is_override=0x1000`、
  :1544-1545 访问器）：`FuncProto::copy`（fspec.cc:3794 `flags = op2.flags`）整
  位携带进 `copy_from`。这是 `Override::insertProtoOverride`（override.cc:130）
  在存储副本上打标、重启后 `Override::applyPrototype`（flow.cc:714）把带标
  proto 重拷回 callspec 的通道——`deindirect` 的 `isOverride()` 早退门
  （fspec.cc:5462）据此跳过已 override 站点的 late restriction。
- **`FuncCallSpecs::deindirect` 生产化**（fspec.cc:5443-5472 逐句）：签名改为
  `(owner: &Arc<RwLock<FuncCallSpecs>>, fd, call_op, entry, display_name,
  &FuncProto) -> bool`——Rugra 无 per-callee Funcdata（flow.rs queryCall 确立的
  前端边界），生产调用方 `ActionDeindirect` 交 oracle `newfd` 三元观测片
  （getAddress/getDisplayName/getFuncProto）。语义链：entry/name 采纳 →
  typed annotation 重写 in(0) → CALLIND→CALL → `insertIndirectOverride` →
  （非 noreturn/inline 且非 override 时）`lateRestriction` 成功即 commit +
  不重启 / 失败 `setRestartPending(true)`。guard 以分段 scope 取用（annotation
  铸造需在读锁间读更新后的 entry）。旧 hook 形态与 `DeindirectOutcome` 枚举
  （零调用方死代码）随之退役。
- **`FuncCallSpecs::force_set` 生产化**（fspec.cc:5485-5509 逐句）：
  proto override 登记（Rugra `Override` 尚不存储 proto 本体，CALLSPEC-0001
  seam——重启重应用面维持未接线）→ lateRestriction commit/重启二择 → 无论结果
  `setInputLock(true)` + 双 error 旗标采纳。
- **`commit_new_inputs` 补 `stackref` 读取**（fspec.cc:5154 `getSpacebaseRelative()`
  在 placeholder 状态清空前读取）+ hook 扩展为
  `(fd, op, existing, pspace, paddr, psize, stackref)`——`buildParam` 的
  spacebase 参数臂需要空间与栈参照。
- **生产 hook 族**（free fn）：`prod_get_call_in`（cc:5103/5110 内联读）、
  `prod_build_param`（fspec.cc:5005-5027 逐句：null→opStackLoad、等宽直返、
  SUBPIECE(0) 前插 + free 重版本化）、`prod_get_return_addr_size`/
  `prod_set_call_output`（cc:5208-5230：opSetOutput + 非自身 INDIRECT
  opUnlink）。`prod_truncate_output` 为登记残差（commit-outputs 截断图编辑，
  FSPEC-DEINDIRECT-TRIGGER-0001 残项，CALLSPEC-0001 seam）。

### 2026-09-26 — FSPEC-DEINDIRECT-TRIGGER-0001 补充（deindirect 名字段分离恢复 + B2 双侧 fixture，Lane FSPECDEIN）

- **`deindirect` 名字段分离恢复**：Ghidra 的 `name` 挂在 FuncCallSpecs
  （fspec.hh:1645）——`FuncProto::copy`（fspec.cc:3789-3804）只拷
  model/extrapop/flags/store/effectlist/likelytrash/injectid，**从不触碰名**，
  故 lateRestriction 的 copy 不会扰动 cc:5447 采纳的 display name。Rugra 的
  FuncProto 内嵌 name 字段，copy_from 会连带覆盖——deindirect 在
  lateRestriction 之后（commit 与 restart 两路）重新断言 display name 以镜像
  字段分离（双侧 fixture const_hit 案例钉死：copy 后名保持 target_const）。
- **B2 双侧 fixture** `tests/oracle/deindirect_arms_1204.{cc,rs}` +
  `tools/run_deindirect_arms_oracle.sh`（BfdArchitecture host + 真全局 scope
  addFunction/addExternalRef + 两个 runner 侧 throwaway-补丁访问器）：八案
  覆盖三臂全路径——**6/8 双侧逐字节一致**（const_hit/const_miss/align_strip
  （funcptr_align=2 双移位剥编码位）/copy_chain/override_site（isOverride
  早退无重启）/funcptr_force（forceSet 锁+commit arity 折叠））；**2 案
  MISMATCH 残差如实登记**：norestart_gate（db callee noreturn 位——Rugra 该
  观测片走 flow 期 callee_func_protos 通道,deindirect 时点不可见,语料 0
  触达）、extref（Scope 图不存 per-symbol refaddr——检测可达、referral 解析
  落空=oracle newfd==0 形态,语料 0 触达）。metadata
  `deindirect_arms_1204.metadata.json` 逐案 coverage 状态 + 残差
  TODO ID（-R2/-R3）；fixture_registry 登记留 root 串行。

### 2026-09-27 — FSPEC-LIKELYTRASH-FOLD（likelytrash 独立载体 1:1 移植，Lane FSPECTRASH）

- **`FuncProto::likelytrash` 独立载体字段**（fspec.hh:1365
  `vector<VarnodeData> likelytrash`——"Locations that may contain trash
  values"）：函数级 `<likelytrash>` 覆盖列表。此前 `FuncProto::decode` 把
  `<likelytrash>` 折叠进 effects 当 KilledByCall（自创形态，oracle 无对应
  消费路径）——COREACT2 残差①的根因：`ActionLikelyTrash::apply`
  （coreaction.cc:2146-2147 经 `FuncProto::trashBegin..trashEnd`）的 trash
  源结构性不存在。本轮改为 1:1 独立载体，trash 源落地。
- **`FuncProto::decode` 的 `<likelytrash>` 臂**（fspec.cc:4806-4813）：
  子 `<addr>` 按 VarnodeData 属性读入 `likelytrash` 字段；同函数
  `<unaffected>`/`<killedbycall>` 进 effectlist 的路径与 oracle 分流一致
  （likelytrash 从不是 effect）。
- **decode 尾接通 `decodeLikelyTrash` 合并**（fspec.cc:4827 调用点，
  体=fspec.cc:3684-3699）：局部覆盖表 + 模型 trash 表合成完整表
  （模型表逐条 push → 局部项对模型表 binary_search 去重后 append → 整表
  重排序）；本 decode 通道未绑定模型时以空模型表合并，= oracle
  `createUnknownModel` 空载体的同一可观察形态。
- **`FuncProto::trash_iter`**（fspec.cc:4260-4275 `trashBegin`/`trashEnd`
  对的切片等价物）：自身 `likelytrash` 非空用自身，空则回落底层
  `ProtoModelFull::trash_iter`（动态回落，非拷贝时点——与 oracle 迭代器
  对同形）。
- **`is_compatible` 补 likelytrash 比较**（fspec.cc:4573-4575）：先长度、
  后逐元素 `operator==`（space/offset/size 三全等，pcoderaw.hh:77-81）。
- **`VarnodeData::compare`**（pcoderaw.hh:67-70 `operator<` 1:1）：space
  （指数序投影）→ offset 升序 → **size 降序（大者先）**。fspec 内四处
  trash 排序/查找统一改用该比较键：`ProtoModelFull::decode` 的
  likelytrash/internalstorage 表排序（fspec.cc:2694-2695）、
  `decode_likely_trash` 的合并排序与 binary_search、
  `encode_likely_trash` 的 binary_search、`intersect_registers` 的
  merge-join——消除旧 (space,offset) 升序无 size 破坏键与 join 比较键
  两处偏差（oracle 键下 join 同 (space,offset) 异 size 才有序不strike等价）。
- **语义中性**：Ghidra_12.0.4 x86-64-gcc.cspec 无 `<likelytrash>` 元素
  （CR-COREACT2 经 GitHub raw 亲取）→ 生产语料构造性休眠，canon A/B
  字节恒等；触发面=32 位 x86gcc.cspec 形（EAX cdecl/thiscall/regparm），
  单测以带 `<likelytrash>` 的 `<prototype>` 文档驱动解码/合并/回落/比较
  四路径 + 比较键 size 降序钉死。

## 2026-09-28（S1W2-PIECE16-CHAIN，SQLCENSUS-STACKSLOT-GROUP-0001 wave-2）：build_output_from_trials DoublePrecis 标记接线

- 2-trial join 路径的 `if (data.isDoublePrecisOn())` 臂（fspec.cc:5816-5819）
  此前是登记在案的 TODO（FSPEC-OUTPUTJOIN-0001），本波接线
  `lo_vn.set_precis_lo()` + `hi_vn.set_precis_hi()`。标记骑在与
  `build_join_output` 随后 re-home 为 SUBPIECE 输出（`opSetOutput(sublo, lovn)`）
  **相同的 Varnode 对象**上，故 RuleDoubleIn 稍后在 join SUBPIECE 上以
  `out isPrecisLo`（double.cc:3263）命中，经 `SplitVarnode::findCreateWhole`
  （double.cc:527 `newUniqueOut` PIECE）重建 unique 空间 16B 逻辑整值——
  即 RulePieceStructure 随后标记为 partial root 的 PIECE16 族（vmprintf 侧
  事件级验证：Rugra 终态 piece=110/piece16=101/partialroot=101 与 oracle
  census 完全一致，修复前 Rugra 终态 PIECE16=0）。
- `findPreexistingWhole` 的接线延期（MIGW-FSPEC-0004）保持不变，仍属
  FSPEC-OUTPUTJOIN-0001 剩余域。
## 2026-09-30：op 链迭代面机械迁移（PERF-ARENA-FLIP-0001 (b)）

`fd.obank.{alivelist,deadlist,storelist,loadlist,returnlist,useroplist}`
的 Vec 迭代/克隆消费位随 PcodeOpBank 7 链 IdList 翻转机械改写为 bank 链
API（`iter_alive()/iter_dead()/iter_store()...` 与 `.cloned().collect()`），
迭代序与语义恒等（链序=原 Vec 序=oracle 列表序）；测试面裸
`alivelist.push` 改 `adopt_alive_op`（bank API，单链不变量保持）。
