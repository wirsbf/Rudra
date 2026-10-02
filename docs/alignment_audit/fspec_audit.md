# fspec 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 5976行 (`fspec.cc`) / Rudra: 2794行 (`src/fspec.rs`) / 比率: 46%

Ghidra 头文件 `fspec.hh` 声明的内联/虚方法（`ParamEntry::getGroup/getSize/getAlign/...`、`ParamTrial::getAddress/getSize/markUsed/...`、`FuncProto::isOutputLocked/...` 等）一并纳入。

## 设计说明（重要架构偏差 — 这是 46% 覆盖率的根因）
1. **`ProtoModel` 类拆分且为 stub**：Ghidra 的 `ProtoModel`（fspec.cc:2263-2922，含 `decode`/`isCompatible`/`assignParameterStorage`/`lookupEffect`/`buildParamList` 等约 12 个方法）在 Rudra 拆到独立文件 `src/type_system/protomodel.rs`（315 行），且**所有方法均标注 `RUDRA-GLUE: no Ghidra counterpart found`**——即未做 1:1 对齐，是简化的 x86_64 专用 stub。完整的模型解码（fspec.cc:2549-2700，约 150 行）完全缺失。
2. **ParamList 子类型缺失**：Ghidra 有 4 个 ParamList 子类（`ParamListStandard`/`ParamListRegister`/`ParamListRegisterOut`/`ParamListStandardOut`）+ `ParamListMerged`，分别承载输入/输出路径。Rudra **只实现了 `ParamListStandard`**，其余 4 个类完全缺失（输出原型路径无入口）。
3. **Parameter/ProtoStore 层级缺失**：Ghidra 的 `ParameterBasic`/`ParameterSymbol`/`ProtoStoreSymbol`/`ProtoStoreInternal`（参数对象的多态实现与原型存储）在 Rudra 完全缺失，参数改用单一扁平 struct `ProtoParameter`。
4. **FspecSpace 缺失**：Ghidra 的 `FspecSpace`（地址空间，fspec.cc:2116）整类缺失。
5. **FuncProto 多个方法为空 stub**：`param_shift`/`resolve_extra_pop`/`update_this_pointer`/`set_inject_id` 存在签名但函数体为空注释，因依赖未实现的 ProtoModel。
6. **FuncCallSpecs 大半方法缺失**：21 个方法（transferLocked*、commitNew*、deindirect、forceSet、insertPcode、checkInputJoin、lateRestriction 等）缺失，调用规约恢复的核心链路不完整。

## 已对齐函数 (按类统计)

### EffectRecord (5)
- `EffectRecord::new` — Ghidra: fspec.cc:2212 (构造) ✅
- `EffectRecord::get_type` — Ghidra: fspec.cc:2212 `getType` ✅
- `EffectRecord::get_offset` — Ghidra: fspec.cc:2212 `getOffset` ✅
- `EffectRecord::get_size` — Ghidra: fspec.cc:2212 `getSize` ✅
- (构造重载 `EffectRecord(addr,size)` / `EffectRecord(entry,t)` / `EffectRecord(data,t)` 与 `encode`/`decode` 见缺失段)

### ProtoParameter (3) — Rudra 扁平化替代 ParameterBasic/ParameterSymbol
- `ProtoParameter::new` — Ghidra: fspec.hh:1100 ✅
- `ProtoParameter::is_this_pointer` — Ghidra: fspec.hh:1100 ✅
- `ProtoParameter::is_type_locked` — Ghidra: fspec.hh:1100 ✅

### ParamEntry (32) — 本模块覆盖最完整的类
- 构造/字段访问器: `new` (hh:125), `get_group`(hh:126), `get_all_groups`(hh:127), `get_size`(hh:129), `get_min_size`(hh:130), `get_align`(hh:131), `get_type`(hh:133), `is_exclusion`(hh:134), `is_reverse_stack`(hh:135), `is_grouped`(hh:136), `is_overlap`(hh:137), `is_first_in_class`(hh:138), `is_param_check_high`(hh:152), `is_param_check_low`(hh:153), `get_space`(hh:147), `get_base`(hh:148), `get_join_record`(hh:132) ✅
- `find_entry_by_storage` — Ghidra: fspec.cc:60 ✅
- `resolve_first` — Ghidra: fspec.cc:76 ✅
- `resolve_join` — Ghidra: fspec.cc:94 ✅
- `resolve_overlap` — Ghidra: fspec.cc:122 ✅
- `group_overlap` — Ghidra: fspec.cc:157 ✅
- `subsumes_definition` — Ghidra: fspec.cc:184 ✅
- `contained_by` — Ghidra: fspec.cc:199 ✅
- `intersects` — Ghidra: fspec.cc:214 ✅
- `justified_contain` — Ghidra: fspec.cc:248 ✅
- `get_container` — Ghidra: fspec.cc:295 ✅
- `contains` — Ghidra: fspec.cc:335 ✅
- `assumed_extension` — Ghidra: fspec.cc:366 ✅
- `get_slot` — Ghidra: fspec.cc:407 ✅
- `get_addr_by_slot` (3-arg) — Ghidra: fspec.cc:434 ✅
- `get_addr_by_slot` (4-arg) — Ghidra: fspec.cc:450 ✅
- `order_within_group` — Ghidra: fspec.cc:583 ✅
- `decode` — Ghidra: fspec.cc:501 ✅ (拆为 builder-setters + ParamListStandard::parse_pentry，合理)

### ParamListStandard (29) — 输入 ParamList 主类，覆盖完整
- 字段访问器: `get_type`(hh:628), `get_spacebase`(hh:639), `is_this_before_ret_pointer`(hh:640), `get_max_delay`(hh:642), `is_auto_killed_by_call`(hh:643), `get_entry`(hh:620), `is_big_endian`(hh:621), `clone`(hh:645) ✅
- `extract_tiles` — Ghidra: fspec.cc:626 ✅
- `get_stack_entry` — Ghidra: fspec.cc:642 (推断; 实现为 find_entry 的特化) ✅
- `find_entry` — Ghidra: fspec.cc:661 ✅
- `characterize_as_param` — Ghidra: fspec.cc:682 ✅
- `assign_address_fallback` — Ghidra: fspec.cc:735 ✅
- `assign_address` — Ghidra: fspec.cc:772 ✅
- `assign_map` — Ghidra: fspec.cc:785 ✅
- `select_unreference_entry` — Ghidra: fspec.cc:820 (私有辅助) ✅
- `build_trial_map` — Ghidra: fspec.cc:849 ✅
- `separate_sections` — Ghidra: fspec.cc:946 ✅
- `mark_group_no_use` — Ghidra: fspec.cc:974 ✅
- `mark_best_inactive` — Ghidra: fspec.cc:997 ✅
- `force_exclusion_group` — Ghidra: fspec.cc:1032 ✅
- `force_no_use` — Ghidra: fspec.cc:1069 ✅
- `force_inactive_chain` — Ghidra: fspec.cc:1111 ✅
- `calc_delay` — Ghidra: fspec.cc:1153 ✅
- `add_resolver_range` — Ghidra: fspec.cc:1174 ✅
- `populate_resolver` — Ghidra: fspec.cc:1191 ✅
- `parse_pentry` — Ghidra: fspec.cc:1226 ✅
- `parse_group` — Ghidra: fspec.cc:1262 ✅
- `fillin_map` — Ghidra: fspec.cc:1285 ✅
- `check_join` — Ghidra: fspec.cc:1315 ✅
- `check_split` — Ghidra: fspec.cc:1342 ✅
- `possible_param` — Ghidra: fspec.cc:1354 ✅
- `possible_param_with_slot` — Ghidra: fspec.cc:1360 ✅
- `get_biggest_contained_param` — Ghidra: fspec.cc:1375 ✅
- `unjustified_container` — Ghidra: fspec.cc:1411 ✅
- `assumed_extension` — Ghidra: fspec.cc:1426 ✅
- `get_range_list` — Ghidra: fspec.cc:1439 ✅
- `decode` — Ghidra: fspec.cc:1451 ✅

### ParamTrial (33) — 覆盖完整（trial 状态机字段访问器齐全）
- `new`/`get_address`/`get_size`/`get_slot`/`set_slot`/`get_offset`/`set_entry`/`clear_entry`/`get_entry`/`set_fixed_position`/`mark_used`/`mark_active`/`mark_inactive`/`mark_no_use`/`mark_unref`/`mark_killed_by_call`/`is_checked`/`is_active`/`is_definitely_not_used`/`is_used`/`is_unref`/`is_killed_by_call`/`set_rem_formed`/`is_rem_formed`/`set_ind_create_formed`/`is_ind_create_formed`/`set_condexe_effect`/`has_condexe_effect`/`set_ancestor_realistic`/`has_ancestor_realistic`/`set_ancestor_solid`/`has_ancestor_solid`/`set_address` — Ghidra: fspec.hh:210 (内联访问器) ✅
- `split_hi` — Ghidra: fspec.cc:1845 `splitHi` ✅
- `split_lo` — Ghidra: fspec.cc:1856 `splitLo` ✅

### ParamActive (16)
- `new` — Ghidra: fspec.cc:1936 ✅
- `clear` — Ghidra: fspec.cc:1949 ✅
- `get_num_trials`/`get_trial`/`get_trial_mut`/`get_slot_base`/`set_slot_base`/`get_num_passes`/`get_max_pass`/`set_max_pass`/`is_recover_subcall`/`is_join_reverse`/`set_join_reverse`/`needs_final_check`/`set_needs_final_check`/`mark_needs_final_check`/`finish_pass`/`is_fully_checked`/`mark_fully_checked` — Ghidra: fspec.cc:1936 (字段访问器) ✅
- `register_trial` — Ghidra: fspec.cc:1963 ✅
- `which_trial` — Ghidra: fspec.cc:1982 ✅
- `split_trial` — Ghidra: fspec.cc:2033 ✅
- `get_num_used` — Ghidra: fspec.cc:2097 ✅
- `sort_trials` — Ghidra: fspec.cc:2087 ✅

### FuncProto (~35，含多个 stub)
- `new` (cc:3778), `add_parameter`, `num_params`, `get_param`, `effect_iter`(effectBegin/effectEnd), `add_effect` ✅
- `is_input_locked`(cc:3906), `set_input_lock`(cc:3921), `set_output_lock`(cc:3942), `is_output_locked`, `get_return_bytes_consumed`, `set_return_bytes_consumed`(cc:3954) ✅
- `copy_from`(cc:3789 copy), `clear_unlocked_input`(cc:3994), `clear_input`(cc:4016), `copy_flow_effects`(cc:3806) ✅
- `param_shift`(cc:3706) ⚠️ stub, `resolve_extra_pop`(cc:3971) ⚠️ stub, `set_inject_id`(cc:4025) ⚠️ stub, `cancel_inject_id`(cc:4036) ⚠️ stub, `clear_unlocked_output`(cc:4001), `set_internal`(cc:3891), `update_this_pointer`(cc:3572) ⚠️ stub ✅(签名对齐，实现待补)
- `is_varargs`, `set_dotdotdot`, `get_model_name`, `set_model_name`, `is_model_unknown`(hh:1394), `print_model_in_decl`(hh:1395) ✅
- `resolve_model`(cc:3767) ✅ (Rudra FuncCallSpecs 版)
- `has_effect`(cc:4234) ✅
- `possible_input_param`(cc:4366) ✅

### FuncCallSpecs (~22，含多个 stub)
- `new`(cc:4924), `get_spacebase_offset`, `set_spacebase_offset`, `has_spacebase_offset` ✅
- `characterize_as_output`(hh:1553), `characterize_as_input_param`(hh:1553), `possible_input_param`(委托 FuncProto) ✅
- `has_effect`(cc:4234 委托), `is_auto_killed_by_call`(hh:1630), `is_stack_output_lock`(hh:1543) ✅
- `is_input_locked`/`is_output_locked`/`is_dotdotdot`/`has_model`/`set_model`/`resolve_model`/`derive_input_map`/`derive_output_map` ✅
- `build_input_from_trials`(cc:5685), `is_input_active`/`is_output_active`/`clear_active_input`/`clear_active_output` ✅
- `get_input_bytes_consumed`(cc:5870), `set_input_bytes_consumed`(cc:5887) ✅
- `get_op`(hh via op_addr), `final_input_check`(cc:5564), `check_input_trial_use`(cc:5585) ✅
- `init_active_input`(cc:5331), `init_active_output`, `get_active_input`/`get_active_output` ✅
- `abort_spacebase_relative`(cc:4910), `clear_stack_placeholder_slot`(hh:1654) ✅

### VarnodeData / ParameterPieces / PrototypePieces (辅助结构, 合理)
- `VarnodeData` 字段+`get_addr`(RUDRA-GLUE) ✅
- `ParameterPieces::swap_markup`(cc:2175)/`assign_address_from_pieces`(cc:2191) ✅
- `PrototypePieces` 结构 ✅

## 缺失函数

### 整类缺失 (12个类)

#### ProtoModel — 缺失（拆到 protomodel.rs 且为 stub，缺 12 个方法）
- `ProtoModel::defaultLocalRange` — Ghidra: fspec.cc:2263 — 优先级: **高** — 建立默认本地变量范围。Rudra protomodel.rs 无对应。
- `ProtoModel::defaultParamRange` — Ghidra: fspec.cc:2292 — 优先级: **高**
- `ProtoModel::buildParamList` — Ghidra: fspec.cc:2323 — 优先级: **高** — 根据 strategy 字符串构建 ParamList 子类。Rudra 无 ParamList 子类机制。
- `ProtoModel::ProtoModel` (构造 cc:2339 / 拷贝 cc:2360 / 析构 cc:2392) — 优先级: 中
- `ProtoModel::isCompatible` — Ghidra: fspec.cc:2406 — 优先级: **高** — 判定两个模型是否兼容（调用规约匹配的核心）。
- `ProtoModel::assignParameterStorage` — Ghidra: fspec.cc:2429 — 优先级: **高** — 为原型各参数分配存储位置（ABI 参数放置算法）。Rudra 缺失，无法从类型推导参数寄存器/栈槽。
- `ProtoModel::lookupEffect` — Ghidra: fspec.cc:2472 — 优先级: 中
- `ProtoModel::lookupRecord` — Ghidra: fspec.cc:2510 — 优先级: 中
- `ProtoModel::hasEffect` — Ghidra: fspec.cc:2541 — 优先级: 中
- `ProtoModel::decode` — Ghidra: fspec.cc:2549 — 优先级: **高** — 从 XML 解码整个调用规约（约 150 行，含 `<pentry>`/`<group>`/`<resolvelist>`/`<model>` 等）。Rudra 完全缺失，无法从 .cspec 加载非默认调用规约。
- `ScoreProtoModel` 整类 — Ghidra: fspec.cc:2705 (`addParameter`/`doScore`) — 优先级: 中 — 调用规约评分（用于自动推断未知调用规约）。
- `ProtoModelMerged` 整类 — Ghidra: fspec.cc:2780 (`intersectEffects`/`intersectRegisters`/`foldIn`/`decode`) — 优先级: 中 — 合并多个兼容模型的效果。

#### ParamList 子类型 — 缺失 4 个类
- `ParamListRegisterOut` — Ghidra: fspec.cc:1519 (`assignMap`) — 优先级: **高** — 寄存器输出参数列表。Rudra 无输出 ParamList。
- `ParamListRegister` — Ghidra: fspec.cc:1542 (`fillinMap`) — 优先级: 中 — 寄存器输入参数列表（无 trial 映射）。
- `ParamListStandardOut` — Ghidra: fspec.cc:1569-1776 (`assignMap`/`initialize`/`fillinMapFallback`/`fillinMap`/`possibleParam`/`decode`) — 优先级: **高** — 标准输出参数列表，含输出 trial 恢复（`fillinMapFallback` 是 ActionActiveOutput 的核心）。
- `ParamListMerged` — Ghidra: fspec.cc:1794 (`foldIn`) — 优先级: 中

#### Parameter / ProtoStore 层级 — 缺失 4 个类
- `ParameterBasic` 整类 — Ghidra: fspec.cc:2924 (`setTypeLock`/`setNameLock`/`setThisPointer`/`overrideSizeLockType`/`resetSizeLockType`) — 优先级: 中 — 参数的基本实现。Rudra 用扁平 `ProtoParameter` 替代，部分标志位访问无对应方法。
- `ParameterSymbol` 整类 — Ghidra: fspec.cc:2993-3083 (`getAddress`/`getSize`/`isTypeLocked`/...共 12 个访问器 + `setTypeLock`/`setNameLock`/...) — 优先级: 中 — 基于 Symbol 的参数实现。
- `ProtoStoreSymbol` 整类 — Ghidra: fspec.cc:3103-3304 (`clearInput`/`clearAllInputs`/`getNumInputs`/`clearOutput`/`encode`/`decode`) — 优先级: 中 — 基于 Symbol 作用域的原型存储。
- `ProtoStoreInternal` 整类 — Ghidra: fspec.cc:3306-3464 (`clearInput`/`clearAllInputs`/`getNumInputs`/`clearOutput`/`encode`/`decode`) — 优先级: 中 — 内部原型存储（无 Symbol）。

#### FspecSpace — 缺失整类
- `FspecSpace` — Ghidra: fspec.cc:2116-2166 (`FspecSpace`/`encodeAttributes`(2 arg)/`encodeAttributes`(3 arg)/`printRaw`/`decode`) — 优先级: 中 — 函数规格地址空间。Rudra 无此 AddressSpace 子类。

### FuncProto — 缺失方法 (19个)
- `FuncProto::setModel` — Ghidra: fspec.cc:3818 — 优先级: **高** — 绑定 ProtoModel。Rudra `set_model` 只存名字字符串，不绑定模型对象。
- `FuncProto::setPieces` — Ghidra: fspec.cc:3843 — 优先级: 中 — 从 PrototypePieces 设置原型。
- `FuncProto::getPieces` — Ghidra: fspec.cc:3857 — 优先级: 中
- `FuncProto::setScope` — Ghidra: fspec.cc:3879 — 优先级: 中
- `FuncProto::updateInputTypes` — Ghidra: fspec.cc:4052 — 优先级: **高** — 从 active trials 更新输入参数类型（ActionActiveInput 的核心）。
- `FuncProto::updateInputNoTypes` — Ghidra: fspec.cc:4097 — 优先级: **高**
- `FuncProto::updateOutputTypes` — Ghidra: fspec.cc:4136 — 优先级: **高** — 从 active trials 更新输出类型。
- `FuncProto::updateOutputNoTypes` — Ghidra: fspec.cc:4172 — 优先级: **高**
- `FuncProto::updateAllTypes` — Ghidra: fspec.cc:4194 — 优先级: **高**
- `FuncProto::characterizeAsOutput` — Ghidra: fspec.cc:4336 — 优先级: 中 (Rudra 在 FuncCallSpecs 有，FuncProto 自身缺)
- `FuncProto::possibleOutputParam` — Ghidra: fspec.cc:4398 — 优先级: 中
- `FuncProto::unjustifiedInputParam` — Ghidra: fspec.cc:4426 — 优先级: 中
- `FuncProto::getBiggestContainedInputParam` — Ghidra: fspec.cc:4459 — 优先级: 中
- `FuncProto::getBiggestContainedOutput` — Ghidra: fspec.cc:4492 — 优先级: 中
- `FuncProto::getThisPointerStorage` — Ghidra: fspec.cc:4516 — 优先级: 中
- `FuncProto::isCompatible` — Ghidra: fspec.cc:4542 — 优先级: **高**
- `FuncProto::printRaw` — Ghidra: fspec.cc:4583 — 优先级: 低 (Rudra 有 print_model_in_decl，部分覆盖)
- `FuncProto::encode` — Ghidra: fspec.cc:4625 — 优先级: 中
- `FuncProto::decode` — Ghidra: fspec.cc:4675 — 优先级: **高** — 从 XML 解码整个函数原型（约 170 行）。Rudra 缺失，无法从 .xml 加载函数签名。
- `FuncProto::encodeEffect`/`encodeLikelyTrash`/`decodeEffect`/`decodeLikelyTrash` — Ghidra: fspec.cc:3589/3631/3652/3684 — 优先级: 中 — effect/trash 的编解码。
- `FuncProto::trashBegin`/`trashEnd` — Ghidra: fspec.cc:4260/4269 — 优先级: 低 — likely-trash 迭代器。
- `FuncProto::characterizeAsInputParam` — Ghidra: fspec.cc:4289 — 优先级: 中 (FuncProto 自身缺，FuncCallSpecs 有委托)

### FuncCallSpecs — 缺失方法 (21个)
- `FuncCallSpecs::createPlaceholder` — Ghidra: fspec.cc:4849 — 优先级: 中
- `FuncCallSpecs::resolveSpacebaseRelative` — Ghidra: fspec.cc:4870 — 优先级: 中
- `FuncCallSpecs::setFuncdata` — Ghidra: fspec.cc:4949 — 优先级: **高** — 将 call 目标解析到具体 Funcdata（deindirect 的前置）。
- `FuncCallSpecs::transferLockedInputParam` — Ghidra: fspec.cc:5038 — 优先级: **高** — 转移锁定输入参数到 call 的输入槽。
- `FuncCallSpecs::transferLockedOutputParam` — Ghidra: fspec.cc:5068 — 优先级: **高**
- `FuncCallSpecs::transferLockedInput` — Ghidra: fspec.cc:5100 — 优先级: **高**
- `FuncCallSpecs::transferLockedOutput` — Ghidra: fspec.cc:5130 — 优先级: **高**
- `FuncCallSpecs::commitNewInputs` — Ghidra: fspec.cc:5150 — 优先级: **高** — 提交新输入参数（ActionFuncProto 的核心）。
- `FuncCallSpecs::commitNewOutputs` — Ghidra: fspec.cc:5201 — 优先级: **高**
- `FuncCallSpecs::checkInputJoin` — Ghidra: fspec.cc:5349 — 优先级: 中
- `FuncCallSpecs::doInputJoin` — Ghidra: fspec.cc:5376 — 优先级: 中
- `FuncCallSpecs::lateRestriction` — Ghidra: fspec.cc:5408 — 优先级: 中
- `FuncCallSpecs::deindirect` — Ghidra: fspec.cc:5443 — 优先级: **高** — 将间接 call 解析为直接 call（ActionDeindirect 的核心）。
- `FuncCallSpecs::forceSet` — Ghidra: fspec.cc:5485 — 优先级: 中
- `FuncCallSpecs::insertPcode` — Ghidra: fspec.cc:5517 — 优先级: 中
- `FuncCallSpecs::collectOutputTrialVarnodes` — Ghidra: fspec.cc:5536 — 优先级: 中
- `FuncCallSpecs::checkOutputTrialUse` — Ghidra: fspec.cc:5661 — 优先级: 中
- `FuncCallSpecs::buildOutputFromTrials` — Ghidra: fspec.cc:5770 — 优先级: **高** — 从输出 trial 构建返回值（ActionActiveOutput 的核心）。
- `FuncCallSpecs::paramshiftModifyStart`/`paramshiftModifyStop` — Ghidra: fspec.cc:5901/5911 — 优先级: 低
- `FuncCallSpecs::hasEffectTranslate` — Ghidra: fspec.cc:5934 — 优先级: 中
- `FuncCallSpecs::countMatchingCalls` — Ghidra: fspec.cc:5950 — 优先级: 低

### ParamEntry / ParamTrial / ParamActive / EffectRecord — 缺失少量 (7个)
- `ParamEntry::decode` — Ghidra: fspec.cc:501 — 优先级: 低 (已拆到 parse_pentry，合理)
- `ParamTrial::test_shrink` — Ghidra: fspec.cc:1871 — 优先级: 中 — 测试 trial 是否能收缩到更小地址/尺寸。
- `ParamTrial::fixed_position_compare` — Ghidra: fspec.cc:1920 (静态) — 优先级: 低
- `ParamActive::delete_unused_trials` — Ghidra: fspec.cc:2013 — 优先级: 中
- `ParamActive::free_placeholder_slot` — Ghidra: fspec.cc:1995 — 优先级: 中
- `ParamActive::join_trial` — Ghidra: fspec.cc:2063 — 优先级: 中
- `EffectRecord::encode`/`EffectRecord::decode`/构造重载 (3个) — Ghidra: fspec.cc:2212/2243/2256 — 优先级: 中

## 高优先级缺失清单 (按影响排序)

### 调用规约恢复链路（最关键，整条链断裂）
1. **`ProtoModel::decode`** (fspec.cc:2549) — 无法从 .cspec 加载调用规约
2. **`ProtoModel::assignParameterStorage`** (fspec.cc:2429) — 无法按 ABI 放置参数
3. **`ProtoModel::isCompatible`** (fspec.cc:2406) — 无法匹配调用规约
4. **`FuncCallSpecs::setFuncdata`** (fspec.cc:4949) — call 目标无法解析
5. **`FuncCallSpecs::deindirect`** (fspec.cc:5443) — 间接 call 无法转直接
6. **`FuncCallSpecs::transferLockedInput/Output` + commitNewInputs/Outputs** (fspec.cc:5100/5130/5150/5201) — 锁定参数无法转移到 call
7. **`FuncCallSpecs::buildOutputFromTrials`** (fspec.cc:5770) — 返回值无法从 trial 恢复
8. **`FuncProto::updateInputTypes/OutputTypes/AllTypes`** (fspec.cc:4052/4097/4136/4172/4194) — 参数类型无法从 trial 更新
9. **`FuncProto::decode`** (fspec.cc:4675) — 无法从 .xml 加载函数签名
10. **`ProtoModel::defaultLocalRange`/`defaultParamRange`/`buildParamList`** (fspec.cc:2263/2292/2323) — 默认范围与 ParamList 构建缺失

### ParamList 输出路径（关键）
11. **`ParamListStandardOut` 整类** (fspec.cc:1569-1776) — 输出 trial 恢复无入口
12. **`ParamListRegisterOut`** (fspec.cc:1519) — 寄存器输出参数列表缺失

## 说明
- `ProtoModel` 在 `src/type_system/protomodel.rs`（315 行，10 个方法），但全部标注 `RUDRA-GLUE: no Ghidra counterpart found`，是对齐缺失而非位置拆分。
- `FuncProto::param_shift`/`resolve_extra_pop`/`update_this_pointer`/`set_inject_id`/`cancel_inject_id` 在 Rudra 中为空 stub（签名对齐，函数体为空），因依赖未实现的 ProtoModel。这些计入"已对齐"但标 ⚠️。
- `ParamEntry`/`ParamTrial`/`ParamActive`/`ParamListStandard` 四个类覆盖率高（trial 状态机与输入 ParamList 完整），是 fspec.rs 中质量最高的部分。
- 缺失根因是 **ProtoModel 基础设施未完成**：调用规约的解码/放置/匹配依赖 ProtoModel，而 ProtoModel 为 stub，导致 FuncProto/FuncCallSpecs 的大量方法无意义而留空或缺省。
