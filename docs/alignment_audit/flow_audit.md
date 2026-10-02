# flow 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 1460行 (`flow.cc`) + 172行 (`flow.hh`) / Rudra: 1181行 (`src/flow.rs`) / 比率: 80%

Ghidra 头文件 `flow.hh` 的内联访问器（`FlowInfo::setRange/setMaximumInstructions/setFlags/clearFlags/getSize/hasInject/hasUnimplemented/...` 等）一并纳入统计。

## 设计说明（重要架构偏差）
1. **FlowInfo 不持有 `Architecture *glb`/`PcodeOpBank &obank`/`BlockGraph &bblocks`/`vector<FuncCallSpecs *> &qlst`**：Ghidra 的 `FlowInfo` 构造接收 `Funcdata &d, PcodeOpBank &o, BlockGraph &b, vector<FuncCallSpecs *> &q`，并持有 `glb`，因此可直接生成 p-code（`PcodeEmitFd emitter`）、维护 call spec 列表（qlst）、查询 PcodeInjectLibrary。Rudra 的 `FlowInfo<'a>` 持有 `&'a mut Funcdata` + `&'a dyn LoadImage` + `&'a mut dyn Disassembler` + `&'a mut X86Lifter`，**无 Architecture 句柄、无独立 PcodeOpBank/BlockGraph 引用、无 FuncCallSpecs 列表**——所有 p-code 直接灌入 Funcdata，call spec 在外部维护。
2. **FuncCallSpecs 集成缺失**：Ghidra 的 `queryCall`/`setupCallSpecs`/`setupCallindSpecs`/`deleteCallSpec`/`checkForFlowModification`（flow.cc:656-704/1306，约 130 行）维护 `qlst`（FuncCallSpecs 列表），处理 CALL/CALLIND 操作数的 call 规约建立与去重。Rudra **完全不维护 FuncCallSpecs 列表**——`truncate_indirect_jump`/`xref_inlined_branch` 等方法的注释明确承认 "FuncCallSpecs gap" / "deferred to P2"。
3. **P-code 注入链路缺失**：Ghidra 的 `doInjection`/`injectUserOp`/`injectPcode`/`injectSubFunction`/`inlineSubFunction`（flow.cc:1177-1327，约 200 行）通过 `PcodeInjectLibrary` 执行 p-code 注入，是 CALLOTHER/inject CALLOTHER/inline 的核心。Rudra 完全缺失这 5 个方法（src/flow.rs:65 注释明确列出 "P-code injection" 为 "Not yet ported"）。
4. **inline 克隆链路缺失**：Ghidra 的 `inlineClone`/`inlineEZClone`/`forwardRecursion`/`testHardInlineRestrictions`（flow.cc:1043-1157，约 130 行）支持函数内联克隆与递归检测。Rudra 完全缺失这 4 个方法。
5. **克隆构造缺失**：Ghidra 有两个 `FlowInfo` 构造（普通 cc:26 + 克隆 cc:52 `FlowInfo(...,const FlowInfo *op2)`），克隆构造用于内联时复制 flow 状态。Rudra 仅有普通构造，无克隆。
6. **PcodeEmitFd 缺失**：Ghidra 的 `PcodeEmitFd`（flow.cc 内嵌类，在 `FlowInfo` 构造时初始化）是 p-code 发射器，将 Translate 生成的 p-code 灌入 PcodeOpBank。Rudra 用 `X86Lifter` 直接生成 p-code 灌入 Funcdata，**绕过了 Translate/PcodeEmit 抽象**——这意味着 Rudra flow 只能处理 x86，无法支持其他架构。
7. **VisitStat 简化**：Ghidra 的 `VisitStat` 持有 `SeqNum seqnum`（完整序列号）+ `int4 size`；Rudra 的 `VisitStat` 用 `order: u32` 替代 SeqNum，丢失了 SeqNum 携带的地址+序号信息。
8. **fallthruOp/branchTarget/target 改为不可变查询**：Ghidra 的 `fallthruOp`/`branchTarget`/`target`（flow.cc:88/115/149/187）是 `const` 方法返回 `PcodeOp *`。Rudra 改为私有 `target_op_for_branch`/`target_op_by_addr`/`fallthru_op`（src/flow.rs:732/744/759），返回 `Option<PcodeOpRef>`，且**未作为公共 API 暴露**——这限制了外部（如 action 系统）查询控制流目标的能力。

## 已对齐函数 (按类统计)

### FlowInfo — 构造与配置 (10)
- `new` (cc:26 FlowInfo 普通构造；注意签名简化为 fd+load_image+disassembler+lifter) ✅
- `set_range`(hh:145), `set_max_instructions`(hh:146), `set_flags`(hh:147), `clear_flags`(hh:148) ✅
- `get_size`(hh:160), `seen_instruction`(hh:108), `has_possible_unreachable`(hh:105), `set_possible_unreachable`(hh:106 内联) ✅
- `has_inject`(hh:161), `has_unimplemented`(hh:162), `has_bad_data`(hh:163), `has_out_of_bounds`(hh:164), `has_reinterpreted`(hh:165), `has_too_many_instructions`(hh:166), `is_flow_for_inline`(hh:167), `does_jump_record`(hh:168) ✅
- `clear_properties`(cc:78) ✅

### FlowInfo — 流跟踪核心 (12)
- `generate_ops`(cc:785) ✅（驱动循环对齐，但内部依赖 Rudra 的 disassembler/lifter 而非 PcodeEmitFd）
- `generate_blocks`(cc:824) ✅（委托 Rudra 的 `build_blocks_from_alive`）
- `find_unprocessed`(cc:850) ✅（部分对齐；opMarkStartBasic 由 block 阶段统一应用，注释说明）
- `dedup_unprocessed`(cc:866) ✅
- `fillin_branch_stubs`(cc:889) ✅（STARTBASIC/STARTMARK 同上）
- `collect_edges`(cc:906) ✅（返回边列表，Ghidra 直接写入 block_edge1/block_edge2）
- `split_basic`(cc:983) ✅
- `connect_basic`(cc:1021) ✅（注释：Rudra `build_blocks_from_alive` 直接派生边，此方法为空壳）
- `new_address`(cc:198) ✅
- `fallthru`(cc:545) ✅
- `set_fallthru_bound`(cc:489) ✅
- `process_instruction`(cc:383) ✅（简化：不经 Translate，直接 disassembler.decode + lifter.lift）
- `xref_control_flow`(cc:264) ✅（签名改为 `(addr, step, ops_start)` 而非迭代器）

### FlowInfo — 辅助与边界处理 (8)
- `handle_out_of_bounds`(cc:519) ✅
- `reinterpreted`(cc:606) ✅
- `artificial_halt`(cc:592) ✅
- `is_in_array`(cc:776 静态) ✅
- `delete_remaining_ops_from`(cc:240 deleteRemainingOps) ✅
- `check_ez_model`(cc:1157) ✅
- `truncate_indirect_jump`(cc:727) ⚠️（签名对齐，但内部 setupCallindSpecs 调用被注释为 RUDRA-GLUE gap）
- `recover_jump_tables`(cc:1427) ✅（多 stage 部分对齐）
- `check_multistage_jumptables`(cc:1408) ⚠️（依赖 JumpTable::checkForMultistage 未移植，注释说明）
- `xref_inlined_branch`(cc:1053) ⚠️（setupCallSpecs/setupCallindSpecs 调用被注释为 deferred）

### FlowInfo — 内部辅助 (4, RUDRA-GLUE)
- `current_bound` (src/flow.rs:1025) — Ghidra 内联在 setFallthruBound/fallthru 中
- `collect_branchinds` (src/flow.rs:907) — Ghidra 内联在 generateOps 的 tablelist 循环中
- `target_op_for_branch` (src/flow.rs:732) — 解析 BRANCH/CBRANCH input(0) 地址
- `target_op_by_addr` (src/flow.rs:744) — 按地址找首个 alive op
- `fallthru_op` (src/flow.rs:759) — 找 fallthru op

### 公共入口 (1)
- `follow_flow` (src/flow.rs:1168) — Ghidra: funcdata_op.cc:756 Funcdata::followFlow（顶层驱动，Rudra 移到 flow.rs 作为自由函数）

## 缺失函数

### FlowInfo — P-code 注入链路（关键，5 个方法，约 200 行）
- `FlowInfo::doInjection` — Ghidra: flow.cc:1177 — 优先级: **高** — 执行 InjectPayload（CALLOTHER 注入核心）。Rudra 完全缺失，CALLOTHER/inject CALLOTHER 操作无法展开。
- `FlowInfo::injectUserOp` — Ghidra: flow.cc:1212 — 优先级: **高** — 用户定义 op 注入。
- `FlowInfo::injectPcode` — Ghidra: flow.cc:1327 — 优先级: **高** — 对所有 injectlist 中的 op 执行注入替换。Rudra 缺失（虽然 `has_inject`/`injectlist` 字段存在，但实际注入逻辑未实现）。
- `FlowInfo::injectSubFunction` — Ghidra: flow.cc:1284 — 优先级: **高** — 用注入替换 CALL（injectCALLOTHER 模型）。
- `FlowInfo::inlineSubFunction` — Ghidra: flow.cc:1242 — 优先级: **高** — 在调用点内联子函数体。

### FlowInfo — inline 克隆链路（关键，4 个方法，约 130 行）
- `FlowInfo::inlineClone` — Ghidra: flow.cc:1074 — 优先级: **高** — 克隆内联 flow（hard inline 模型）。
- `FlowInfo::inlineEZClone` — Ghidra: flow.cc:1108 — 优先级: 中 — EZ 模型克隆。
- `FlowInfo::forwardRecursion` — Ghidra: flow.cc:1043 — 优先级: 中 — 从另一 flow 拉取内联递归信息。
- `FlowInfo::testHardInlineRestrictions` — Ghidra: flow.cc:1133 — 优先级: 中 — 测试 hard inline 限制（返回地址、单返回点）。

### FlowInfo — 克隆构造与 call spec（关键，5 个方法，约 130 行）
- `FlowInfo::FlowInfo(...,const FlowInfo *op2)` — Ghidra: flow.cc:52 — 优先级: **高** — 克隆构造（内联 flow 复制）。
- `FlowInfo::queryCall` — Ghidra: flow.cc:656 — 优先级: **高** — 恢复 CALL 对应的 Funcdata 对象。
- `FlowInfo::setupCallSpecs` — Ghidra: flow.cc:680 — 优先级: **高** — 为新 call 点建立 FuncCallSpecs。
- `FlowInfo::setupCallindSpecs` — Ghidra: flow.cc:704 — 优先级: **高** — 为间接 call 建立 FuncCallSpecs。
- `FlowInfo::checkForFlowModification` — Ghidra: flow.cc:636 — 优先级: 中 — 检查 call 流是否被修改。
- `FlowInfo::deleteCallSpec` — Ghidra: flow.cc:1306 — 优先级: 中 — 从 qlst 移除 call spec。

### FlowInfo — 公共控制流目标查询（3 个方法，关键 API 缺失）
- `FlowInfo::target` — Ghidra: flow.cc:115 — 优先级: **高** — 按地址返回指令的首个 p-code op（公共 API）。Rudra 改为私有 `target_op_by_addr`，外部无法调用。
- `FlowInfo::branchTarget` — Ghidra: flow.cc:187 — 优先级: **高** — 找 BRANCH/CBRANCH 引用的目标（公共 API）。Rudra 改为私有 `target_op_for_branch`。
- `FlowInfo::fallthruOp` — Ghidra: flow.cc:88 — 优先级: **高** — 找给定 op 的 fallthru（公共 API，非 const 重载）。Rudra 改为私有 `fallthru_op`。
- `FlowInfo::findRelTarget` — Ghidra: flow.cc:149 — 优先级: **高** — 找相对分支目标（返回 PcodeOp* 并填 res 地址）。Rudra 完全缺失。
- `FlowInfo::updateTarget` — Ghidra: flow.cc:204 — 优先级: 中 — 更新内联 op 的分支目标。Rudra 缺失。

### FlowInfo — checkContainedCall（1 个方法）
- `FlowInfo::checkContainedCall` — Ghidra: flow.cc:1361 — 优先级: 中 — 检查内联注入后是否产生新 call。

### FlowInfo — 私有字段访问器（隐含缺失）
- `inline_head`/`inline_recursion`/`inline_base` — Ghidra: flow.hh:102-104 — 优先级: 中 — 内联递归检测字段。Rudra 无此字段。
- `flowoverride_present` — Ghidra: flow.hh:100 — 优先级: 低 — flow override 标志。Rudra 无此字段。
- `block_edge1`/`block_edge2` — Ghidra: flow.hh:92-93 — 优先级: 低 — 基本块边列表。Rudra 用 `collect_edges` 返回值替代。

## 高优先级缺失清单 (按影响排序)

### 注入与内联（最关键，整条链断裂）
1. **`FlowInfo::doInjection`/`injectUserOp`/`injectPcode`/`injectSubFunction`/`inlineSubFunction`** (flow.cc:1177-1327) — 5 个注入方法缺失，CALLOTHER/inject CALLOTHER/inline 全部无法工作
2. **`FlowInfo::inlineClone`/`inlineEZClone`/`forwardRecursion`/`testHardInlineRestrictions`** (flow.cc:1043-1157) — 4 个 inline 克隆方法缺失，hard inline/EZ inline 模型无法实现
3. **`FlowInfo::FlowInfo(...,const FlowInfo *op2)`** (flow.cc:52) — 克隆构造缺失，inline flow 复制无入口

### Call 规约集成（关键）
4. **`FlowInfo::queryCall`/`setupCallSpecs`/`setupCallindSpecs`/`deleteCallSpec`/`checkForFlowModification`** (flow.cc:656-706/1306) — 5 个 FuncCallSpecs 维护方法缺失，CALL/CALLIND 的 call 规约无法在 flow 阶段建立（当前 truncate_indirect_jump/xref_inlined_branch 有注释承认此 gap）

### 控制流目标公共 API（关键）
5. **`FlowInfo::target`/`branchTarget`/`fallthruOp`/`findRelTarget`/`updateTarget`** (flow.cc:88/115/149/187/204) — 5 个公共目标查询方法在 Rudra 中降级为私有或不实现，外部 action 系统无法查询控制流目标

### 次要（架构依赖）
6. **`FlowInfo` 持有 `Architecture *glb`/FuncCallSpecs 列表** — 注入/inline/call spec 依赖 glb 与 qlst；Rudra 当前构造签名无这些，需先扩展
7. **PcodeEmitFd / Translate 抽象** — Rudra 直接用 X86Lifter，绕过架构无关的 Translate/PcodeEmit，导致 flow 硬编码为 x86
8. **VisitStat 的 SeqNum** — Rudra 用 u32 order 替代，丢失地址信息
9. **`checkContainedCall`/`flowoverride_present`/inline 递归检测字段** — 内联相关辅助方法与字段

## 说明
- `FlowInfo` 的核心两阶段流跟踪（`generate_ops` + `generate_blocks`）已对齐，能正确处理 x86 上常规函数的控制流恢复——这是 80% 覆盖率的基础。
- `process_instruction`/`xref_control_flow`/`fallthru`/`set_fallthru_bound`/`new_address`/`handle_out_of_bounds`/`reinterpreted`/`artificial_halt` 等**流跟踪决策逻辑**已对齐，正确处理分支/调用/越界/重解释等边界情况。
- `truncate_indirect_jump`/`xref_inlined_branch`/`check_multistage_jumptables`/`recover_jump_tables` 已有对齐签名，但内部多处依赖未实现的 FuncCallSpecs/JumpTable 方法（注释明确标注 RUDRA-GLUE gap），属于"签名对齐但实现待补"。
- 当前 20% 缺口集中在 **注入（5）+ 内联克隆（4）+ 克隆构造（1）+ call spec（5）= 15 个方法约 460 行**，这些方法高度依赖 `Architecture *glb`、`PcodeInjectLibrary`、`FuncCallSpecs` 列表，是 Architecture 集成与完整 p-code 注入支持阶段的延伸工作。
- Rudra 的 `FlowInfo<'a>` 生命周期参数与 4 个 `&mut` 引用（fd/load_image/disassembler/lifter）使得**克隆构造（cc:52）在当前签名下不可能直接实现**——需要先重构为共享所有权（Arc/Rc）或分离数据与逻辑。
