# 主管线 Action apply 审计

审计日期：2026-07-22
审计范围：`src/coreaction.rs` 中 10 个主管线 Action 的 `apply()` 实现。
对比基准：`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc` 和 `coreaction.hh`。

图例：
- ✅ 真实逻辑 — 与 Ghidra 算法语义等价（完整或仅委托给完整子例程）
- 🟡 部分实现 — 核心算法存在但有显著功能缺口
- 🔴 空壳 stub — 无实质逻辑，仅返回 NO_CHANGE

汇总：4 ✅ / 4 🟡 / 2 🔴

---

## ActionNameVars
- Rudra: coreaction.rs:3819
- Ghidra: coreaction.cc:2978
- 状态: 🟡 部分实现
- 分析：
  - ✅ `linkSymbols` (cc:2930) — 完整实现于 coreaction.rs:3764。
  - ✅ `assignDefaultNames(base)` (cc:2988) — 委托给 `Merge::assign_names` (merge.rs:659)，逐个 high 分配默认名。
  - ✅ `lookForFuncParamNames` (cc:2858) — 在 apply 内联实现 (coreaction.rs:3840-3891)，从 callspec 推导参数名到输入 varnode。
  - 🔴 `recoverNameRecommendationsForSymbols` (cc:2984) — 缺失（Rudra 在 link_symbols 中直接处理，未单独调用恢复接口）。
  - 🔴 `lookForBadJumpTables` (cc:2779-2856) — 显式标注为 no-op (coreaction.rs:3831-3835)，理由是 FuncCallSpecs 上没有 `isBadJumpTable` 标志。
- 缺失逻辑：
  1. `lookForBadJumpTables` 未实现，跳转表异常检测缺失，相关 "UNRECOVERED_JUMPTABLE" 符号重命名不会发生。
  2. 名字推荐恢复路径与 Ghidra 不严格一致。

---

## ActionDirectWrite
- Rudra: coreaction.rs:4310
- Ghidra: coreaction.cc:1350
- 状态: ✅ 真实逻辑
- 分析：两阶段工作列表算法完整移植：
  - ✅ Phase 1 (cc:1360-1416)：清 direct_write + 初始 worklist（input+persist/spacebase、persist 写、非 COPY/PIECE/SUBPIECE 写、非常量）。
  - ✅ Phase 2 (cc:1418-1432)：沿 descend 传播，INDIRECT 区分 `propagateIndirect || isIndirectStore`。
- 已知差异（已在注释中标注）：缺少 `propagateIndirect` 标志，对 INDIRECT 采取保守传播（始终传播）。同时未实现 `possibleInputParam` 对 input 的标记 (cc:1368-1371)、stack-store COPY 链回溯 (cc:1381-1394)、INDIRECT 地址变更检测 (cc:1401-1408)。这些差异使某些边界判定偏离 Ghidra，但主算法是真实的。

---

## ActionPrototypeTypes
- Rudra: coreaction.rs:4590
- Ghidra: coreaction.cc:4609
- 状态: 🟡 部分实现
- 分析：
  - ✅ Step "Strip indirect register from RETURN" (cc:4625-4635) — 完整实现 (coreaction.rs:4608-4624)：当 input(0) 非常量时替换为 newConstant(size,0)。
  - ✅ Step "initActiveOutput when not locked" (cc:4651) — 实现 (coreaction.rs:4628-4638)，但仅在 return type 为 Void 且未初始化时创建。
  - 🔴 `setModel(evalfp)` (cc:4615-4619) — 未实现：不设置 evaluation prototype。
  - 🔴 `prepareThisPointer` (cc:4620-4621) — 未实现。
  - 🔴 `isOutputLocked` 分支 (cc:4637-4648) — 未实现：不会为每个 RETURN 插入 return varnode 并 updateType。
  - 🔴 truncated space stack pointer zext 插入 (cc:4653-4680) — 未实现。
  - 🔴 `extendInput` (cc:4590-4607) — 在 .cc 同区域但属另一函数，Rudra 未实现。
- 缺失逻辑：locked-output 分支、model 设置、truncated-space 处理均缺。

---

## ActionVarnodeProps
- Rudra: coreaction.rs:3906
- Ghidra: coreaction.cc:1282
- 状态: 🔴 空壳 stub
- 分析：apply (coreaction.rs:3908-3962) 仅遍历 varnode 计数 `change_count`，但两条分支都返回 `NO_CHANGE`，从未实际调用任何变更函数（`change_count += 1` 纯粹是计数器，且最终被丢弃）。
- 对比 Ghidra (cc:1282-1348)，缺失的核心逻辑：
  1. `clearAutoLiveHold` (cc:1314) — 未调用，autolive-hold 标志不会在 pass>0 时清除。
  2. `fillinReadOnly(vn)` (cc:1320) — 未调用，readonly Varnode 不会被 LoadImage 查表替换。
  3. `replaceVolatile(vn)` (cc:1324) — 未调用，volatile Varnode 不会被替换为 pcode op。
  4. `totalReplaceConstant(vn, 0)` (cc:1342) — 未调用：(NZMask & Consume)==0 的零值 varnode 不会被替换为常量 0。这是关键功能（驱动 dead-code 消除）。
  5. COPY 0 无限递归保护 (cc:1331-1340) — 因上游逻辑未实现，无需此保护。
- 结论：实现仅为骨架，不会对 IR 产生任何副作用，所有四个核心路径全部空缺。

---

## ActionNonzeroMask
- Rudra: coreaction.rs:7430
- Ghidra: coreaction.hh:300（内联 `data.calcNZMask()`）
- 状态: ✅ 真实逻辑
- 分析：Ghidra 的 apply 本身就是单行委托 `data.calcNZMask()`。Rudra 同样单行委托 `fd.calc_nz_mask()` (funcdata.rs:3630)，后者是完整的 NZM 计算：
  - 按 alivelist 顺序遍历 op。
  - 对 INT_EQUAL/BOOL_*/FLOAT_* 返回 1；COPY/ZEXT 直接传播；SEXT 处理符号位；OR/XOR/AND/LEFT/RIGHT/NEGATE/2COMP/SUBPIECE 等每个 opcode 都有对应公式。
  - 与 Ghidra `getNZMaskLocal` (op.cc:547-700) 语义一致。

---

## ActionActiveParam
- Rudra: coreaction.rs:4653
- Ghidra: coreaction.cc:1725
- 状态: ✅ 真实逻辑
- 分析：apply (coreaction.rs:4655-4732) 是 Ghidra 算法的 1:1 移植：
  - ✅ `AliasChecker::gather` (cc:1731) — `AliasChecker::gather_internal` (coreaction.rs:4660)。
  - ✅ `trimmable = (numPasses>0) || op != CALLIND` (cc:1741) — 完整移植 (coreaction.rs:4677)。
  - ✅ `checkInputTrialUse` (cc:1743) — 委托 `fc.check_input_trial_use`，并处理 `replace_slots`（用 new_constant 填零，coreaction.rs:4684-4691）。Ghidra 版直接改 data，Rudra 显式收集 slot 后批量 op_set_input。
  - ✅ `finishPass` + `markFullyChecked` + `count++` (cc:1744-1748) — 完整移植 (coreaction.rs:4696-4710)。
  - ✅ `needsFinalCheck -> finalInputCheck -> resolveModel -> deriveInputMap -> buildInputFromTrials -> clearActiveInput` (cc:1749-1757) — 完整移植 (coreaction.rs:4712-4729)。
  - ✅ 返回 `count`（Ghidra return 0 但用内部 count 字段）。

---

## ActionReturnRecovery
- Rudra: coreaction.rs:7350
- Ghidra: coreaction.cc:1908
- 状态: 🔴 空壳 stub
- 分析：apply (coreaction.rs:7352-7415) 实现了一个自创的"找 RAX 写"启发式（扫 RETURN 父块反向找 Register space offset=0 的输出，找不到再扫 alivelist），与 Ghidra 的 AncestorRealistic + ancestorOpUse + deriveOutputMap + buildReturnOutput 算法没有任何对应关系。
- 对比 Ghidra (cc:1908-1955)，缺失的核心逻辑：
  1. `data.getActiveOutput()` 检查 (cc:1911) — Rudra 不读 active_output，无视 ParamActive 流程。
  2. `AncestorRealistic::execute` + `data.ancestorOpUse(maxancestor, vn, op, trial, ...)` (cc:1920-1934) — 真实参数使用追踪，Rudra 完全没有。
  3. 对每个 trial (slot) 而非整个 RETURN 做检测 (cc:1925-1934) — Rudra 只关心 slot 1（硬编码"返回值"）。
  4. `active->finishPass()` + `markFullyChecked()` (cc:1937-1939) — Rudra 不调用。
  5. `getFuncProto().deriveOutputMap(active)` + `buildReturnOutput(active, op, data)` + `clearActiveOutput` (cc:1942-1950) — Rudra 不调用，没有真正的输出原型推导。
- 结论：Ghidra 的 active-output 收集协议被完全跳过；Rudra 用一个硬编码 RAX=offset 0 的启发式替代，在非 x86_64 或多 slot 返回场景下会失效。属实质性的重新设计而非移植。

---

## ActionMergeCopy
- Rudra: coreaction.rs:655
- Ghidra: coreaction.hh:392（内联 `data.getMerge().mergeOpcode(CPUI_COPY)`）
- 状态: ✅ 真实逻辑
- 分析：Ghidra 单行委托 `mergeOpcode(CPUI_COPY)`。Rudra 同样单行委托 `Merge::merge_opcode(fd, CPUI_COPY)` (merge.rs:964)，后者完整实现：
  - 遍历所有 block 中 opcode==CPUI_COPY 的 op。
  - 对 output + 每个 input 跑 `merge_test_basic` + `merge_test_required`。
  - 通过 `merge_speculative` 执行 cover-guarded 合并。
  - 与 Ghidra merge.cc::mergeOpcode 语义一致。

---

## ActionMergeMultiEntry
- Rudra: coreaction.rs:682
- Ghidra: coreaction.hh:403（内联 `data.getMerge().mergeMultiEntry()`）
- 状态: ✅ 真实逻辑
- 分析：Ghidra 单行委托 `mergeMultiEntry()`。Rudra 单行委托 `Merge::merge_multi_entry(fd)` (merge.rs:881)，后者完整实现：
  - 按 Symbol 分组 live + merge-eligible Varnode。
  - 过滤掉无 mapentry 的 Varnode。
  - 对每 Symbol 统计 distinct whole-sized entries（≥2）。
  - 取首 vn 为 anchor，对组内其余 vn 调用 merge。
  - 与 Ghidra merge.cc:916-948 语义一致。

---

## ActionConditionalConst
- Rudra: coreaction.rs:7056
- Ghidra: coreaction.cc:4514
- 状态: 🟡 部分实现
- 分析：apply (coreaction.rs:7058-7249) 在结构上忠实移植，但两条关键 IR-变异路径被显式禁用：
  - ✅ `useMultiequal` 门控 (cc:4517-4525) — 按 heritage pass 设置 (coreaction.rs:7109)。
  - ✅ 遍历每个 block 找 CBRANCH 作为最后 op (cc:4529-4532) — 完整移植 (coreaction.rs:7120-7137)。
  - ✅ `boolVn = cBranch->getIn(1)` + `blockDom[0/1] = restrictedByConditional` (cc:4533-4535) — 完整移植 (coreaction.rs:7139-7178)。
  - ✅ `flipEdge = isBooleanFlip` (cc:4536) — 移植 (coreaction.rs:7181)。
  - 🟡 implied-boolean ConstPoint 推送 (cc:4537-4541) — 代码存在 (coreaction.rs:7195-7224)，但整体被 `cond_const_done` 守卫屏蔽（每函数最多运行一次）。
  - ✅ `findConstCompare` (cc:4542) — 完整实现并实际调用 (coreaction.rs:7227, 6633)。
  - 🟡 `propagateConstant` (cc:4543) — 实现 (coreaction.rs:6834)，但被两个安全闸门限制：
    1. `use_multiequal = false` 强制 (coreaction.rs:7117)：handlePhiNodes/placeCopy 路径禁用，因为 op 插入在 mainloop 下不收敛。
    2. `cond_const_done` 标志 (coreaction.rs:7105-7106)：IR 变异每函数只跑一次，后续 pass 跳过。
- 缺失/禁用逻辑：
  1. MULTIEQUAL / phi-node 替换路径（placeCopy + handlePhiNodes）在运行时被强制禁用。
  2. 多次 IR 变异被收敛守卫禁止（Ghidra 在一个 mainloop 周期内可多次传播）。
  3. 注释说明这些闸门是为避免 5/24 curl 函数超时（repeatapply 不收敛）而临时加的，技术上属已知技术债。
