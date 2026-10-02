# funcdata 对齐审计 (2026-07-22)

## 覆盖率

| 维度 | 数值 |
|---|---|
| Ghidra 4 个 `funcdata_*.cc` 源文件 | 5969 行 |
| Ghidra `Funcdata::` 类外方法定义 | **173 个**（去重后唯一签名 173 个） |
| Rudra `src/funcdata.rs` | 6728 行 |
| Rudra `impl Funcdata` 方法 | 111 个 |
| 已对齐（Ghidra→Rudra 一一映射） | **67 / 173 = 38.7%** |
| 缺失（无对应 Rudra 方法） | **106 个** |
| 优先级分布 | 高 **87** / 中 **13** / 低 **6** |

按来源文件拆分：

| Ghidra 文件 | 方法总数 | 已对齐 | 缺失 | 文件级覆盖率 |
|---|---|---|---|---|
| `funcdata.cc` (1122行) | 40 | 4 | 36 | 10.0% |
| `funcdata_op.cc` (1502行) | 48 | 30 | 18 | 62.5% |
| `funcdata_varnode.cc` (2239行) | 56 | 18 | 38 | 32.1% |
| `funcdata_block.cc` (1106行) | 29 | 15 | 14 | 51.7% |

**结论**：`funcdata_op.cc`（PcodeOp 操作原语）覆盖最好，Rudra 已落地的绝大多数 op-级 API 都位于此处。`funcdata.cc` 覆盖最差——Rudra 几乎完全跳过了 XML 编解码、警告注释、callspec 排序、union 解析与所有 OPACTION_DEBUG 调试钩子。`funcdata_varnode.cc` 缺失集中在符号映射（dynamic symbol、remap、linkProtoPartial）和只读/易失内存建模，这部分是 Rudra 当前分析管线的明显空白。`funcdata_block.cc` 缺失集中在 jumptable 恢复（stage/recover/early-fail）和 basic-block 移除原语（branchRemoveInternal / blockRemoveInternal / pushMultiequals / opZeroMulti）。

注：`onlyOpUse` / `ancestorOpUse` 在 Rudra 中以**自由函数**形式实现（`src/funcdata.rs:6333`, `6428`），不属于 `impl Funcdata`；逻辑等价但签名不对齐，本审计按"缺失方法"计。

---

## 已对齐函数 (67个)

### funcdata.cc (4)
- `clear` — Ghidra: funcdata.cc:84 → `Funcdata::clear` (rust L3193) ✅
- `warningHeader` — Ghidra: funcdata.cc:135 → `Funcdata::warning_header` (rust L339) ✅
- `spacebase` — Ghidra: funcdata.cc:230 → `Funcdata::spacebase` (rust L2466) ✅
- `getCallSpecs` — Ghidra: funcdata.cc:484 → `Funcdata::get_call_specs` (rust L593) ✅

### funcdata_op.cc (30)
- `opSetOpcode` → `op_set_opcode` (rust L741) ✅
- `opMarkHalt` → `op_mark_halt` (rust L716) ✅
- `opUnsetOutput` → `op_unset_output` (rust L1027) ✅
- `opSetOutput` → `op_set_output` (rust L880) ✅
- `opUnsetInput` → `op_unset_input` (rust L1010) ✅
- `opSetInput` → `op_set_input` (rust L795) ✅
- `opSwapInput` → `op_swap_input` (rust L869) ✅
- `opUninsert` → `op_uninsert` (rust L2317) ✅
- `opDestroy` → `op_destroy` (rust L896) ✅
- `opDestroyRecursive` → `op_destroy_recursive` (rust L920) ✅
- `opSetAllInput` → `op_set_all_input` (rust L2398) ✅
- `opRemoveInput` → `op_remove_input` (rust L858) ✅
- `opInsertInput` → `op_insert_input` (rust L848) ✅
- `newOp(int4,Address&)` / `newOp(int4,SeqNum&)` → `new_op` (rust L629) ✅
- `opInsertBefore` → `op_insert_before` (rust L2054) ✅
- `opInsertAfter` → `op_insert_after` (rust L2304) ✅
- `opInsertBegin` → `op_insert_begin` (rust L2327) ✅
- `opInsertEnd` → `op_insert_end` (rust L2335) ✅
- `opBoolNegate` → `op_bool_negate` (rust L2776) ✅
- `opUndoPtradd` → `op_undo_ptradd` (rust L2172) ✅
- `getFirstReturnOp` → `get_first_return_op` (rust L688) ✅
- `newOpBefore` → `op_insert_before` (rust L2054) ✅（共用入口）
- `newIndirectOp` → `new_indirect_op` (rust L2087) ✅
- `newIndirectCreation` → `new_indirect_creation` (rust L2242) ✅
- `markIndirectCreation` → `mark_indirect_creation` (rust L2417) ✅
- `replaceLessequal` → `replace_lessequal` (rust L1947) ✅
- `distributeIntMultAdd` → `distribute_int_mult_add` (rust L1985) ✅
- `cseElimination` → `cse_elimination` (rust L2703) ✅
- `cseEliminateList` → `cse_eliminate_list` (rust L2730) ✅

### funcdata_varnode.cc (18)
- `newConstant` → `new_constant` (rust L649) ✅
- `newUnique` → `new_unique` (rust L708) ✅
- `newVarnodeOut` → `new_varnode_out` (rust L1039) ✅
- `newUniqueOut` → `new_unique_out` (rust L637) ✅
- `newVarnode(int4,Address&,Datatype*)` / `newVarnode(int4,AddrSpace*,uintb)` → `new_varnode` (rust L200) ✅
- `newVarnodeIop` → `new_varnode_iop` (rust L2129) ✅
- `destroyVarnode` → `delete_varnode` (rust L221) ✅（Rudra 命名为 `delete_varnode`）
- `setInputVarnode` → `set_input_varnode` (rust L211) ✅
- `combineInputVarnodes` → `combine_input_varnodes` (rust L230) ✅
- `newExtendedConstant` → `new_extended_constant` (rust L659) ✅
- `setHighLevel` → `set_high_level` (rust L422) ✅
- `calcNZMask` → `calc_nz_mask` (rust L2525) ✅
- `syncVarnodesWithSymbols` (复数) → `sync_varnodes_with_symbols` (rust L1552) ✅
- `linkSymbol` → `link_symbol` (rust L482) ✅
- `linkSymbolReference` → `link_symbol_reference` (rust L514) ✅
- `totalReplace` → `total_replace` (rust L967) ✅
- `splitUses` → `split_uses` (rust L2627) ✅

### funcdata_block.cc (15)
- `removeJumpTable` → `remove_jump_table` (rust L2294) ✅
- `removeBranch` → `remove_branch` (rust L1294) ✅
- `removeDoNothingBlock` → `remove_do_nothing_block` (rust L1390) ✅
- `removeUnreachableBlocks` → `remove_unreachable_blocks` (rust L1656) ✅
- `pushBranch` → `push_branch` (rust L1054) ✅
- `findJumpTable(const PcodeOp*)` → `find_jump_table` (rust L2283) ✅
- `installSwitchDefaults` → `install_switch_defaults` (rust L1367) ✅
- `structureReset` → `structure_reset` (rust L1352) ✅
- `forceGoto` → `force_goto` (rust L1188) ✅
- `nodeJoinCreateBlock` → `node_join_create_block` (rust L1418) ✅
- `nodeSplitBlockEdge` → `node_split_block_edge` (rust L1489) ✅
- `nodeSplit` → `node_split` (rust L1517) ✅
- `removeFromFlowSplit` → `remove_from_flow_split` (rust L1600) ✅
- `switchEdge` → `switch_edge` (rust L1468) ✅
- `spliceBlockBasic` → `splice_block_basic` (rust L1815) ✅

---

## 缺失函数（按来源文件分组）

优先级图例：**[高]** = 分析管线核心调用 / 影响反编译正确性；**[中]** = 次级 pass 或 XML 持久化；**[低]** = 仅 OPACTION_DEBUG 调试或控制台输出。

### funcdata.cc (36 缺失)

#### 警告与处理生命周期 — 高
- **[高]** `warning(const string &txt,const Address &ad)` — funcdata.cc:119 — 地址级警告注释。Rudra 仅实现了 `warning_header`（函数级），缺失将 warning 挂到具体 p-code 地址的能力，所有需要带地址的诊断信息（如 `fillinReadOnly` 写只读、`replaceVolatile` 异常）都无落脚点。
- **[高]** `startProcessing(void)` — funcdata.cc:150 — 处理流水线启动入口（`followFlow` + `structureReset` + `sortCallSpecs` + `heritage.buildInfoList` + `localoverride.applyDeadCodeDelay`）。Rudra 把这些步骤散落到调用方手动编排，缺少一站式入口。
- **[高]** `stopProcessing(void)` — funcdata.cc:170 — 处理完成钩子（`destroyDead` + `issueDatatypeWarnings` + 统计）。Rudra 无对应收尾。
- **[高]** `startTypeRecovery(void)` — funcdata.cc:182 — 标记类型恢复开始（设置 `typerecovery_start` flag）。Rudra 提供 `set_type_recovery_started` 但缺少"原子检查并设置"语义。

#### Spacebase 体系 — 高
- **[高]** `newSpacebasePtr(AddrSpace *id)` — funcdata.cc:275 — 构造栈指针 Varnode。`createStackRef`/`opStackStore`/`opStackLoad` 全部依赖它。
- **[高]** `findSpacebaseInput(AddrSpace *id)` — funcdata.cc:291 — 查找输入栈指针 Varnode。
- **[高]** `constructSpacebaseInput(AddrSpace *id)` — funcdata.cc:309 — 幂等构造输入栈指针（设置 TypeSpacebase 类型）。
- **[高]** `constructConstSpacebase(AddrSpace *id)` — funcdata.cc:332 — 构造全局空间基址常量。
- **[高]** `spacebaseConstant(PcodeOp*,int4,SymbolEntry*,const Address&,uintb,int4)` — funcdata.cc:360 — 把常量指针重写为 PTRSUB 形式以触发符号查找，是全局变量识别的关键变换。

#### Callspec 管理 — 高
- **[高]** `clearCallSpecs(void)` — funcdata.cc:464 — `clear()` 调用链一环，释放 qlst。
- **[高]** `issueDatatypeWarnings(void)` — funcdata.cc:475 — 把 type 系统累积的警告通过 `warningHeader` 输出。
- **[高]** `compareCallspecs(const FuncCallSpecs*,const FuncCallSpecs*)` — funcdata.cc:504 — `sortCallSpecs` 的比较谓词（按 block 索引 + seqnum order）。
- **[高]** `sortCallSpecs(void)` — funcdata.cc:516 — 把 callspecs 排成支配序，影响参数分析。
- **[高]** `deleteCallSpecs(PcodeOp *op)` — funcdata.cc:524 — 删除与某 CALL 关联的 spec（不可达 CALL 清理）。
- **[高]** `fillinExtrapop(void)` — funcdata.cc:545 — 从返回指令字节恢复 x86 extrapop（栈清理量）。x86-target 必需。

#### Union 字段解析 — 高
- **[高]** `getUnionField(const Datatype*,const PcodeOp*,int4) const` — funcdata.cc:917 — 查询 (parent, op, slot) 三元组对应的已解析 union 字段。
- **[高]** `setUnionField(const Datatype*,const PcodeOp*,int4,const ResolvedUnion&)` — funcdata.cc:937 — 记录 union 字段解析（含 MULTIEQUAL 同 Varnode 跨 slot 复制）。
- **[高]** `forceFacingType(Datatype*,int4,PcodeOp*,int4)` — funcdata.cc:974 — 强制某条边采用特定 union 字段（用于 locked 解析）。
- **[高]** `inheritResolution(Datatype*,const PcodeOp*,int4,PcodeOp*,int4)` — funcdata.cc:995 — 把一个 PcodeOp 的 union 字段解析继承到另一个 PcodeOp（cast 插入后必需）。

#### P-code 注入 — 高
- **[高]** `doLiveInject(InjectPayload*,const Address&,BlockBasic*,list<PcodeOp*>::iterator)` — funcdata.cc:848 — 在活块中插入注入 payload 生成的 p-code。Rudra 有 `inject_raw_ops*` 但接口形态不同。

#### XML 编解码 — 中
- **[中]** `printRaw(ostream&) const` — funcdata.cc:209 — 控制台打印原始 p-code。
- **[中]** `printVarnodeTree(ostream&) const` — funcdata.cc:579 — 打印所有 Varnode 信息。
- **[中]** `printLocalRange(ostream&) const` — funcdata.cc:597 — 打印局部 scope 内存范围。
- **[中]** `decodeJumpTable(Decoder&)` — funcdata.cc:613 — 从 XML 恢复 jumptable。
- **[中]** `encodeJumpTable(Encoder&) const` — funcdata.cc:628 — 序列化 jumptable。
- **[中]** `encodeVarnode(Encoder&,iter,enditer)` — funcdata.cc:648 — 序列化一段 Varnode（静态）。
- **[中]** `encodeHigh(Encoder&) const` — funcdata.cc:661 — 序列化 HighVariable 列表。
- **[中]** `encodeTree(Encoder&) const` — funcdata.cc:689 — 序列化 AST 树。
- **[中]** `encode(Encoder&,uint8,bool) const` — funcdata.cc:737 — 函数级序列化总入口。
- **[中]** `decode(Decoder&)` — funcdata.cc:767 — 函数级反序列化总入口。

#### OPACTION_DEBUG 钩子 — 低
- **[低]** `debugModCheck(PcodeOp*)` — funcdata.cc:1012 — 缓存 op 修改前状态。
- **[低]** `debugModClear(void)` — funcdata.cc:1024 — 清除修改跟踪。
- **[低]** `debugModPrint(const string&)` — funcdata.cc:1035 — 打印 action 修改前后对比。
- **[低]** `debugSetRange(const Address&,const Address&,uintm,uintm)` — funcdata.cc:1063 — 设置调试追踪范围。
- **[低]** `debugCheckRange(PcodeOp*)` — funcdata.cc:1076 — 判断 op 是否在追踪范围内。
- **[低]** `debugPrintRange(int4) const` — funcdata.cc:1100 — 打印第 i 个追踪范围。

### funcdata_op.cc (18 缺失)

#### Op 维护原语 — 高
- **[高]** `opInsert(PcodeOp*,BlockBasic*,list<PcodeOp*>::iterator)` — funcdata_op.cc:150 — 所有 `opInsertBefore/After/Begin/End` 的底层实现（markAlive + bl->insert）。Rudra 各 `op_insert_*` 直接操作 list，未抽取公共底层；签名缺失。
- **[高]** `opUnlink(PcodeOp*)` — funcdata_op.cc:179 — 同时 unset 输入输出并 uninsert（op 销毁前的标准清理）。Rudra 无对应一站式入口。
- **[高]** `opDestroyRaw(PcodeOp*)` — funcdata_op.cc:253 — 销毁原始 op 及其所有 io Varnode（用于 flow 生成期的替换）。Rudra 的 `op_destroy` 不破坏 io，签名不同。

#### Stack ref 工具链 — 高
- **[高]** `createStackRef(AddrSpace*,uintb,PcodeOp*,Varnode*,bool)` — funcdata_op.cc:459 — 构造相对于栈指针的 INT_ADD（带段运算）。`opStackStore`/`opStackLoad` 的公共依赖。
- **[高]** `opStackStore(AddrSpace*,uintb,PcodeOp*,bool)` — funcdata_op.cc:508 — 生成相对栈指针的 STORE。
- **[高]** `opStackLoad(AddrSpace*,uintb,uint4,PcodeOp*,Varnode*,bool)` — funcdata_op.cc:541 — 生成相对栈指针的 LOAD。

#### 克隆与流复制 — 高/中
- **[高]** `cloneOp(const PcodeOp*,const SeqNum&)` — funcdata_op.cc:616 — 深克隆 op（含 io Varnode）。`truncatedFlow`/`inlineFlow` 的依赖。
- **[高]** `followFlow(const Address&,const Address&)` — funcdata_op.cc:756 — 从入口跟随流生成原始 p-code + 块 + callspec。Rudra 把这部分能力放到了 `inject_raw_ops*`（rust L2829-3018），签名与流程都不对齐。
- **[中]** `truncatedFlow(const Funcdata*,const FlowInfo*)` — funcdata_op.cc:792 — 部分流克隆（用于 jumptable 恢复）。Rudra 设计上不做 partial clone，标记为有意省略。
- **[中]** `inlineFlow(Funcdata*,FlowInfo&,PcodeOp*)` — funcdata_op.cc:853 — 函数内联。Rudra 不做 inline，标记为有意省略。

#### 流覆盖与控制流覆写 — 高
- **[高]** `findPrimaryBranch(iter,enditer,bool,bool,bool)` — funcdata_op.cc:929 — 在一段 p-code 中找到主分支/调用/返回 op。`overrideFlow` 的依赖。
- **[高]** `overrideFlow(const Address&,uint4)` — funcdata_op.cc:969 — 应用用户 flow override（BRANCH/CALL/CALL_RETURN/RETURN）。Rudra 计划放到独立 `override.rs`，当前缺失。

#### 表达式规范化 — 高
- **[高]** `collapseIntMultMult(Varnode*)` — funcdata_op.cc:1132 — 合并两条链式常量乘法。
- **[高]** `buildCopyTemp(Varnode*,PcodeOp*)` — funcdata_op.cc:1161 — 为某 Varnode 在指定点之前构造 unique COPY，覆盖管理的关键原语。
- **[高]** `opFlipInPlaceTest(PcodeOp*,vector<PcodeOp*>&)` — funcdata_op.cc:1223 — 测试布尔表达式是否可就地翻转（返回 0/1/2 三态）。
- **[高]** `opFlipInPlaceExecute(vector<PcodeOp*>&)` — funcdata_op.cc:1282 — 执行 op 翻转列表。
- **[高]** `cseFindInBlock(PcodeOp*,Varnode*,BlockBasic*,PcodeOp*)` — funcdata_op.cc:1326 — 在块内找重复计算（CSE 子例程）。
- **[高]** `moveRespectingCover(PcodeOp*,PcodeOp*)` — funcdata_op.cc:1459 — 在尊重 cover 的前提下把 op 移过 lastOp（用于表达式重排）。

### funcdata_varnode.cc (38 缺失)

#### Varnode 属性与 HighVariable — 高
- **[高]** `setVarnodeProperties(Varnode*) const` — funcdata_varnode.cc:25 — 从 localmap 查询属性并应用到 Varnode；cover 计算；几乎所有新 Varnode 的统一后处理。Rudra 内联到各 new_* 入口，缺公共函数。
- **[高]** `assignHigh(Varnode*)` — funcdata_varnode.cc:48 — 为 Varnode 分配/构造 HighVariable。
- **[高]** `findHigh(const string&) const` — funcdata_varnode.cc:316 — 按名查 HighVariable。
- **[高]** `transferVarnodeProperties(Varnode*,Varnode*,int4)` — funcdata_varnode.cc:614 — 把 consume 位与 directwrite/addrforce flag 从旧 Varnode 转移到新 Varnode（SUBPIECE / 截断后必需）。

#### Spacebase / 注解 Varnode 构造 — 高
- **[高]** `newVarnodeSpace(AddrSpace*)` — funcdata_varnode.cc:190 — 把地址空间编码为常量 Varnode（LOAD/STORE 第一参数）。
- **[高]** `newVarnodeCallSpecs(FuncCallSpecs*)` — funcdata_varnode.cc:205 — 把 callspec 编码为 fspace 注解 Varnode（CALL 第 0 输入）。
- **[高]** `newCodeRef(const Address&)` — funcdata_varnode.cc:222 — 构造 coderef 注解 Varnode（BRANCH 目标）。
- **[高]** `cloneVarnode(const Varnode*)` — funcdata_varnode.cc:252 — 浅克隆 Varnode（含允许 flag 子集）。
- **[高]** `checkForLanedRegister(int4,const Address&)` — funcdata_varnode.cc:298 — 检测并登记 lane 寄存器。

#### 输入 Varnode 整理 — 高
- **[高]** `adjustInputVarnodes(const Address&,int4)` — funcdata_varnode.cc:494 — 把范围内的多个小输入 Varnode 合并为一个大输入，旧输入改为 SUBPIECE。
- **[高]** `descend2Undef(Varnode*)` — funcdata_varnode.cc:543 — 把 Varnode 的所有读取改为 0xBADDEF 常量（不可达块清理时用）。
- **[高]** `initActiveOutput(void)` — funcdata_varnode.cc:585 — 初始化返回原型恢复（ParamActive）。

#### 只读 / 易失 / 间接 — 高
- **[高]** `fillinReadOnly(Varnode*)` — funcdata_varnode.cc:635 — 用 LoadImage 内容替换只读 Varnode 的所有读取为常量。
- **[高]** `replaceVolatile(Varnode*)` — funcdata_varnode.cc:717 — 把 volatile Varnode 的访问替换为 userop（BUILTIN_VOLATILE_READ/WRITE）。
- **[高]** `checkIndirectUse(Varnode*)` — funcdata_varnode.cc:771 — 测试 Varnode 是否只流入 call-based INDIRECT。
- **[高]** `markIndirectOnly(void)` — funcdata_varnode.cc:815 — 把仅间接使用的非法输入标记 `indirectonly`。
- **[高]** `clearDeadVarnodes(void)` — funcdata_varnode.cc:832 — 回收无 descendant 的 free Varnode。

#### 符号映射 — 高
- **[高]** `syncVarnodesWithSymbol(VarnodeLocSet::const_iterator&,uint4,Datatype*)` — funcdata_varnode.cc:1048 — `syncVarnodesWithSymbols` 的单 set 内部辅助（处理同址 Varnode 集合的属性更新）。
- **[高]** `handleSymbolConflict(SymbolEntry*,Varnode*)` — funcdata_varnode.cc:997 — Varnode 与已存在符号冲突时重映射到 dynamic 符号。
- **[高]** `remapVarnode(Varnode*,Symbol*,const Address&)` — funcdata_varnode.cc:1104 — 静态重映射符号-Varnode 关联。
- **[高]** `remapDynamicVarnode(Varnode*,Symbol*,const Address&,uint8)` — funcdata_varnode.cc:1120 — 动态哈希重映射。
- **[高]** `linkProtoPartial(Varnode*)` — funcdata_varnode.cc:1132 — 为 PIECE 局部 Varnode 链接上层符号。
- **[高]** `findLinkedVarnodes(SymbolEntry*,vector<Varnode*>&) const` — funcdata_varnode.cc:1257 — 找出所有映射到某 SymbolEntry 的 Varnode。
- **[中]** `findLinkedVarnode(SymbolEntry*) const` — funcdata_varnode.cc:1218 — 单返回版（首个匹配）。
- **[高]** `buildDynamicSymbol(Varnode*)` — funcdata_varnode.cc:1283 — 为 Varnode 创建 dynamic 符号（基于 DynamicHash）。
- **[高]** `attemptDynamicMapping(SymbolEntry*,DynamicHash&)` — funcdata_varnode.cc:1314 — 尝试用 dynamic 符号映射回 Varnode（含 union_facet 分支）。
- **[高]** `attemptDynamicMappingLate(SymbolEntry*,DynamicHash&)` — funcdata_varnode.cc:1347 — 后期映射（仅挂名，不强制类型）。

#### 字符串 / 返回地址 / 替换 — 高
- **[高]** `getInternalString(const uint1*,int4,Datatype*,PcodeOp*)` — funcdata_varnode.cc:1413 — 把字符串字节数据注册到 StringManager 并构造显示用 stringdata userop 输出 Varnode。
- **[高]** `testForReturnAddress(Varnode*)` — funcdata_varnode.cc:1442 — 回溯 Varnode 是否来自返回地址（用于 jumptable fail_return 判定）。
- **[高]** `totalReplaceConstant(Varnode*,uintb)` — funcdata_varnode.cc:1496 — 把 Varnode 的所有读取替换为常量值（marker op 走 COPY 中转）。
- **[高]** `findDisjointCover(Varnode*,int4&)` — funcdata_varnode.cc:1573 — 找出不切分其他 Varnode 的最小覆盖区间。
- **[高]** `coverVarnodes(SymbolEntry*,vector<Varnode*>&)` — funcdata_varnode.cc:1606 — 为越界 Varnode 创建保护性符号。
- **[高]** `applyUnionFacet(SymbolEntry*,DynamicHash&)` — funcdata_varnode.cc:1637 — 把 UnionFacetSymbol 缓存到 unionMap。
- **[高]** `mapGlobals(void)` — funcdata_varnode.cc:1653 — 为全局 persist Varnode 创建/链接全局符号。
- **[高]** `prepareThisPointer(void)` — funcdata_varnode.cc:1723 — 为 C++ "this" 指针准备类型推荐。

#### 参数 trial 分析 — 高
- **[高]** `checkCallDoubleUse(const PcodeOp*,const PcodeOp*,const Varnode*,uint4,const ParamTrial&) const` — funcdata_varnode.cc:1756 — 测试同一 Varnode 在两个 CALL 间是否合法双重使用。
- **[高]** `onlyOpUse(const Varnode*,const PcodeOp*,const ParamTrial&,uint4) const` — funcdata_varnode.cc:1805 — 测试 trial Varnode 是否只用于指定 CALL/RETURN。Rudra 以自由函数 `only_op_use`（rust L6333）实现，逻辑等价但签名不对齐。
- **[高]** `ancestorOpUse(int4,const Varnode*,const PcodeOp*,ParamTrial&,int4,uint4) const` — funcdata_varnode.cc:1917 — 沿祖先链测试 trial 是否仅用于指定 op。Rudra 以自由函数 `ancestor_op_use`（rust L6428）实现。

### funcdata_block.cc (14 缺失)

#### 块结构维护 — 高
- **[高]** `printBlockTree(ostream&) const` — funcdata_block.cc:28 — 打印结构化块树。
- **[高]** `clearBlocks(void)` — funcdata_block.cc:35 — 清空 bblocks+sblocks（`clear()` 的一环）。
- **[高]** `clearJumpTables(void)` — funcdata_block.cc:43 — 清空非 override 的 jumptable（`clear()` 的一环）。
- **[高]** `pushMultiequals(BlockBasic*)` — funcdata_block.cc:85 — 块删除时把 MULTIEQUAL 推到后继块（数据流修补）。
- **[高]** `opZeroMulti(PcodeOp*)` — funcdata_block.cc:178 — 把 0/1 输入 MULTIEQUAL 降级为 COPY。
- **[高]** `branchRemoveInternal(BlockBasic*,int4)` — funcdata_block.cc:196 — `removeBranch` 的内部实现（不重置结构）。
- **[高]** `descendantsOutside(Varnode*)` — funcdata_block.cc:234 — 测试 Varnode 是否有活块 descendant。
- **[高]** `blockRemoveInternal(BlockBasic*,bool)` — funcdata_block.cc:255 — 块删除核心（pushMultiequals + removeFromFlow + op destroy）。`removeDoNothingBlock`/`removeUnreachableBlocks` 的公共依赖。

#### Jumptable 恢复 — 高
- **[高]** `linkJumpTable(PcodeOp*)` — funcdata_block.cc:427 — 按地址关联 pre-existing jumptable 与 BRANCHIND op。
- **[高]** `installJumpTable(const Address&)` — funcdata_block.cc:464 — 安装 override jumptable（流追踪前）。
- **[高]** `stageJumpTable(Funcdata&,JumpTable*,PcodeOp*,FlowInfo*)` — funcdata_block.cc:492 — 在 partial clone 上跑 jumptable strategy 恢复地址。
- **[高]** `earlyJumpTableFail(PcodeOp*)` — funcdata_block.cc:555 — 提前判定 jumptable 恢复必失败（回溯检测未注入 CALLOTHER）。
- **[高]** `recoverJumpTable(Funcdata&,PcodeOp*,FlowInfo*,JumpTable::RecoveryMode&)` — funcdata_block.cc:640 — jumptable 恢复总入口（link→stage→commit）。
- **[高]** `switchOverJumpTables(const FlowInfo&)` — funcdata_block.cc:679 — 把每个 jumptable 的地址转换为块索引 + 计算默认分支。

---

## 高优先级清单（87 项，建议优先补齐的核心 API）

按主题分组：

1. **警告与处理生命周期 (4)** — `warning`、`startProcessing`、`stopProcessing`、`startTypeRecovery`。Rudra 当前缺地址级 warning 落点与一站式 start/stop。
2. **Spacebase 体系 (5)** — `newSpacebasePtr`、`findSpacebaseInput`、`constructSpacebaseInput`、`constructConstSpacebase`、`spacebaseConstant`。栈/全局寻址的核心构造块，缺失会阻断 stack-relative 分析。
3. **Callspec 管理 (6)** — `clearCallSpecs`、`issueDatatypeWarnings`、`compareCallspecs`、`sortCallSpecs`、`deleteCallSpecs`、`fillinExtrapop`。参数分析与 x86 extrapop 恢复必需。
4. **Union 字段解析 (4)** — `getUnionField`、`setUnionField`、`forceFacingType`、`inheritResolution`。union 类型传播的关键存储。
5. **P-code 注入 (1)** — `doLiveInject`。
6. **Op 维护原语 (3)** — `opInsert`、`opUnlink`、`opDestroyRaw`。
7. **Stack ref 工具链 (3)** — `createStackRef`、`opStackStore`、`opStackLoad`。
8. **克隆与流复制 (2)** — `cloneOp`、`followFlow`（Rudra 当前用 `inject_raw_ops*` 但签名不对齐）。
9. **流覆盖与覆写 (2)** — `findPrimaryBranch`、`overrideFlow`。
10. **表达式规范化 (6)** — `collapseIntMultMult`、`buildCopyTemp`、`opFlipInPlaceTest`、`opFlipInPlaceExecute`、`cseFindInBlock`、`moveRespectingCover`。
11. **Varnode 属性 (4)** — `setVarnodeProperties`、`assignHigh`、`findHigh`、`transferVarnodeProperties`。
12. **Spacebase/注解构造 (5)** — `newVarnodeSpace`、`newVarnodeCallSpecs`、`newCodeRef`、`cloneVarnode`、`checkForLanedRegister`。
13. **输入整理 (3)** — `adjustInputVarnodes`、`descend2Undef`、`initActiveOutput`。
14. **只读/易失/间接 (5)** — `fillinReadOnly`、`replaceVolatile`、`checkIndirectUse`、`markIndirectOnly`、`clearDeadVarnodes`。
15. **符号映射 (10)** — `syncVarnodesWithSymbol`(单)、`handleSymbolConflict`、`remapVarnode`、`remapDynamicVarnode`、`linkProtoPartial`、`findLinkedVarnodes`、`buildDynamicSymbol`、`attemptDynamicMapping`、`attemptDynamicMappingLate`、`mapGlobals`。
16. **字符串/返回地址/替换 (6)** — `getInternalString`、`testForReturnAddress`、`totalReplaceConstant`、`findDisjointCover`、`coverVarnodes`、`applyUnionFacet`、`prepareThisPointer`。
17. **参数 trial (3)** — `checkCallDoubleUse`、`onlyOpUse`(已有自由函数)、`ancestorOpUse`(已有自由函数)。
18. **块结构维护 (8)** — `printBlockTree`、`clearBlocks`、`clearJumpTables`、`pushMultiequals`、`opZeroMulti`、`branchRemoveInternal`、`descendantsOutside`、`blockRemoveInternal`。
19. **Jumptable 恢复 (6)** — `linkJumpTable`、`installJumpTable`、`stageJumpTable`、`earlyJumpTableFail`、`recoverJumpTable`、`switchOverJumpTables`。

中优先级 (13)：XML 编解码全套（`encode`/`decode`/`encodeJumpTable`/`decodeJumpTable`/`encodeVarnode`/`encodeHigh`/`encodeTree`）、`printRaw`、`printVarnodeTree`、`printLocalRange`、`findLinkedVarnode`(单)、`truncatedFlow`、`inlineFlow`（后两者 Rudra 设计上已决定不做 partial clone / inline）。

低优先级 (6)：全部 OPACTION_DEBUG 调试钩子（`debugModCheck`、`debugModClear`、`debugModPrint`、`debugSetRange`、`debugCheckRange`、`debugPrintRange`）。

---

## 说明

- **签名归一**：Ghidra 的 `Funcdata::method` 与 Rudra 的 `snake_case` 方法对齐时，允许返回类型 `*` 紧贴方法名（如 `PcodeOp *Funcdata::newOp`）和参数换行；本审计以多行括号平衡算法提取，确保 `stageJumpTable`/`recoverJumpTable`/`overrideFlow` 等长签名被正确捕获。
- **逻辑等价但签名不对齐**：`onlyOpUse` / `ancestorOpUse` 在 Rudra 中以自由函数（带显式 `has_active_output` 等参数）实现，逻辑忠实于 Ghidra，但因不是 `impl Funcdata` 方法而计入"缺失"。如需严格 API 对齐，应改为 `impl Funcdata` 上的方法或提供 trait 桥接。
- **重载合并**：Ghidra 的 `newOp(int4,Address&)` 与 `newOp(int4,SeqNum&)` 在 Rudra 合并为单个 `new_op`；`newVarnode` 的两个重载合并为单个 `new_varnode`。Rudra 的 `new_op_before` 与 Ghidra 的 `newOpBefore` 均复用 `op_insert_before` 入口。这些合并视为合理 Rust 适配，算作对齐。
- **命名差异**：`destroyVarnode` → `delete_varnode`（Rudra 改名）；`syncVarnodesWithSymbols` → `sync_varnodes_with_symbols`（已实现），但其内部辅助 `syncVarnodesWithSymbol`（单数）缺失。
- **设计性省略**：`truncatedFlow` 与 `inlineFlow` 依赖 partial-function 克隆机制，Rudra 当前架构不做 partial clone；FUNC_funcdata.md 已标注为设计决策（➖），本审计按"缺失但中优先级"计，以待后续架构调整时再评估。
- **来源行号基准**：所有 Ghidra 行号基于 `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/funcdata*.cc`；Rudra 行号基于 `src/funcdata.rs`。
