# `double_precis.rs` API Reference

## 2026-09-26：`is_arithmetic_op` 对齐 oracle TypeOp 旗标表（BYTELANE）

`is_arithmetic_op`（RuleDoubleIn/RuleDoubleOut attemptMarking 的 whole-def
分类门，double.cc:3239 `typeop->isArithmeticOp()` 的 opcode 枚举镜像）此前
错误地把 INT_ZEXT/INT_SEXT/INT_NEGATE/INT_XOR/INT_AND/INT_OR/INT_LEFT/
INT_RIGHT/INT_SRIGHT/PIECE/SUBPIECE 全部列为 arithmetic。逐构造器核对锁定
oracle typeop.cc 的 `addlflags` 权威表后修正为恰好 13 个
arithmetic_op 旗标持有者：INT_ADD(:1171)/INT_SUB(:1322)/INT_CARRY(:1336)/
INT_SCARRY(:1352)/INT_SBORROW(:1368)/INT_2COMP(:1384)/INT_MULT(:1621)/
INT_DIV(:1635)/INT_SDIV(:1655)/INT_REM(:1675)/INT_SREM(:1695)/PTRADD(:2228)/
PTRSUB(:2304)；logical_op（INT_AND/INT_OR/INT_XOR/INT_NEGATE，:1398/1412/
1445/1478）、shift_op（INT_LEFT/INT_RIGHT/INT_SRIGHT，:1506/1531/1571）与
无旗标构造器（INT_ZEXT/INT_SEXT/PIECE/SUBPIECE）全部拒绝。

**行为效应（GEN4-SQ-BYTELANE-STRUCT-0001）**：sq 语料 read_inode_1 的
0x156998 字节车道里，refineWrite 拆出的 2B whole 由 INT_OR 定义；旧清单把
INT_OR 误判为 arithmetic，RuleDoubleIn 在 SUBPIECE(W,1) 上错误标记
double-precision half 对并触发 1433 次 SplitVarnode::applyRuleIn 重构级联，
摧毁 heritage 已建立的 1B MULTIEQUAL/INDIRECT 结构（oracle 同点
`REJECT consume`/`def-notarith` 拒绝）。修复后 sq 镜面 4481→4323（−158），
read_inode_1 骨架 178→80，canon curl/httpd 与 master 档案字节恒等。B2 双侧
fixture `tests/oracle/rule_doublein_arithgate_1204.*`（11 行投影 sha
b59d7a3a…双侧恒等）钉死该门。

## 2026-08-24：RuleDoubleIn reset 接入 pool virtual-reset seam

`RuleDoubleIn` 的派生 reset（double.cc:3198-3202，
`data.setDoublePrecisRecovery(true)`）此前是无法被池调度的独立方法；现改为
`Rule::reset_for_function` 覆盖，经 `ActionPool::reset` 的 virtual 派发执行，
并按 oracle 覆盖意图**不**调用基类 `Rule::reset`（base warning-given 位跨
reset 存活）。


**源代码路径**: `src/double_precis.rs`
**Ghidra 对应**: `double.cc` (双精度合并子系统, ~1000行)
**状态**: ✅ **L2.5（2026-07-01 核心算法 1:1 移植完成）**——SplitVarnode 核心 + 4 Rule 完整移植 + 21 单元测试。已注册进 oppool1(5643-5646)。

## 模块说明

双精度合并（double-precision merge）：检测被拆成两半的 Varnode（成对的 LOAD/STORE/
COPY），在数据流允许时合并为单一宽类型操作。对应 Ghidra `double.cc` 的 `SplitVarnode`
与 `RuleDouble*` 系列。

## 导出的公共 API

### `SplitVarnode` (double.cc)
表示一个被拆成 hi/lo 两半的 Varnode，用于检测可合并的成对操作。
Ghidra `SplitVarnode` 类的 1:1 移植（~50 方法）。
- `from_constant` / `from_pieces` — 从常量/PIECE 构造
- `init_partial_const` / `init_partial_pieces` / `init_all` — 初始化
- `in_hand_*` — 手牌查询（是否有 hi/lo/whole）
- `find_whole_split_to_pieces` / `find_definition_point` / `find_earliest_split_point`
  / `find_whole_built_from_pieces` — 定义点查找
- `is_whole_feasible` / `is_whole_phi_feasible` — 合并可行性
- `find_create_whole` / `find_create_output_whole` / `create_joined_whole` — 合并创建
- `build_lo_from_whole` / `build_hi_from_whole` — 从整体重建半部
  - **2026-09-26（GEN4-SQ-DBLHI-UNINSERT-0001）**：`build_hi_from_whole` MULTIEQUAL 臂
    补齐 double.cc:635 `data.opUninsert(hiop)`（重插前先脱块，与 lo 孪生臂 :597 同构）。
    此前漏抄导致 op 保持挂块 → `op_insert_begin` → `block_insert_op` 的
    `parent.is_none()` 断言炸（funcdata.rs:4984）；sasquatch 语料 4 函数
    （progress_bar/read_inode_1/read_inode_3/LzmaEnc_CodeOneBlock.part.0）worker panic。
    修复后 progress_bar 完整产出（vs golden defects=0/numbering=0）；其余 3 函数越过
    RuleDoubleIn 后暴露此前被掩盖的下游缺陷（merge 强制合并交集 panic ×2、
    NULL local type ×1），已登记 GEN4-SQ-MERGE-FORCEDINTERSECT-0001 /
    GEN4-SQ-NULLLOCALTYPE-0001。
  - **2026-09-26（GEN4-SQ-NULLLOCALTYPE-0001）**：两个 build_*_from_whole 共用的
    `set_opcode_and_inputs` 胶水（所有 MULTIEQUAL/INDIRECT/else 臂的
    `opSetOpcode+opSetAllInput` 对，double.cc:598-599/:607-608/:613-614/:636-637/
    :645-646/:651-652）此前用裸 `inrefs.clear()` 换输入，漏掉
    `Funcdata::opSetAllInput`（funcdata_op.cc:276-278）的逐槽 `opUnsetInput` 循环
    ——每个被换掉的旧输入 varnode 的 descend 表残留指向该 op 的陈旧条目。
    后果：一个无 def、无符号的输入 varnode（sq LzmaEnc 的 `stack:-0xd8:2`）在
    6 个 SUBPIECE 读者被改写后仍"看似有后代"，逃过
    `ActionInferTypes::buildLocaltypes` 的 `(!isWritten)&&(hasNoDescend)` 跳过
    （coreaction.cc:5019），进入 `Varnode::getLocalType`，无类型可取而抛
    LowlevelError("NULL local type")——oracle 同路径靠 opUnsetInput 维护的不变量
    保证该 varnode 早已零后代、被跳过、永不触发 cc:934。修复 = 胶水改调
    `Funcdata::op_set_all_input`（funcdata.rs，funcdata_op.cc:267-284 的既有忠实
    移植）；varnode.rs `get_local_type` 本身与 varnode.cc:900-936 逐行一致、
    零改动（域判定：根因在 double_precis 胶水层，不在 varnode 层）。
- `adjacent_offsets` — 指针相邻判断
- `test_contiguous_pointers` — **核心**：成对 LOAD 指针连续性检测 (double.cc)
- `is_addr_tied_contiguous` / `is_addr_tied_contiguous_result`
- `verify_mult_neg_one` — MULT(-1) 校验
- `whole_list` / `find_copies` / `get_true_false`
  - **2026-08-23（CONDEXE-TRUEOUT-0002）**：`get_true_false` 对齐 double.cc:916-930 全语义 —
    `getTrueOut/getFalseOut` 纯位置（block.hh:299-300），交换条件改为
    `boolop->isBooleanFlip() != flip`（此前只看调用方 flip，漏了 CBRANCH 自身的
    BOOLEAN_FLIP，两种 flip 形态下极性均错）。
- `prepare_*` / `create_*` / `replace_*` op builders
- `apply_rule_in` — opcode 分派骨架（*Form 子类依赖 block 级控制流，标 TODO）

### `SplitDatatype`
结构体/数组拆分辅助类型（与 subflow.rs 共用）。halves 分析。

### oppool1 Rule (coreaction.cc:5643-5646)
- `RuleDoubleLoad` (double.cc:3442) — PIECE，双 LOAD 合并
- `RuleDoubleStore` (double.cc:3513) — STORE，双 STORE 合并
- `RuleDoubleIn` (double.cc:3259) — CALLOTHER (double-in)
- `RuleDoubleOut` (double.cc:3332) — CALLOTHER (double-out)

### 辅助函数
`get_space_from_const` / `is_addr_tied_contiguous` / `parent_block` /
`is_arithmetic_op` / `is_floating_point_op` / `make_space_varnode` / precis-flag helpers。

## 基础设施缺口（已标注 TODO，未绕过）
- `*Form` 类（AddForm/SubForm/…, double.cc:1433-3196）——依赖 block 级控制流（dominance、
  CBRANCH flip），Rugra 缺。`apply_rule_in` 为骨架返回 0；4 Rule + SplitVarnode 核心非 stub。
- 缺失 Rugra 原语：`newVarnodeIop` / `combineInputVarnodes` / `hasUnreachableBlocks`。

## 测试
21 单元测试：`adjacent_offsets`（const-const/const-vs-nonconst/INT_ADD-from-common-base）、
`test_contiguous_pointers`（LE two-loads/mismatched-spaces）、`is_addr_tied_contiguous`（LE/gap/not-addr-tied）、
`init_partial`（implied-zero-hi/two-constants）、`exceeds_const_precision`、`verify_mult_neg_one`、
`SplitDatatype` halves、4 Rule（触发 + 拒绝路径）、rule-registration surface。

### 2026-07-01（续）：TODO 替换 — iop-space 基础设施接入
- replace_indirect_op / reassign_indirects：iop 输入从 `new_constant(8,0)` 占位改为 `fd.new_varnode_iop(&op)`（double.cc:1386/3643）。
- build_lo/hi_from_whole INDIRECT 分支：用 `fd.get_op_from_const(in1)` 解析 affector，op_uninsert→transform→op_insert_after（double.cc:602-648）。
- no_write_conflict / test_indirect_use：iop varnode 精确配对（affector==op1/op2），替代保守 return None（double.cc:3406/3598）。
- *Form 类族（依赖 block 级控制流）保留 TODO。

### 2026-07-01（续 2）：*Form 类完整移植（double.cc:1104-3196）
13 个 Form 类全部 1:1 移植：AddForm/SubForm/LogicalForm/Equal1-3Form/LessThreeWay(13方法)/LessConstForm/ShiftForm/MultForm(9方法)/PhiForm/IndirectForm/CopyForceForm。SplitVarnode::apply_rule_in 调度器按 opcode 映射到 Form（double.cc:1090-1232）。各 Form 的 verify/apply_rule 完整实现，非 stub。

### 2026-07-01（续 3）：Layer-6 剩余 TODO 填补（14 处，仅剩 1）
isEntryPoint/getStartBlock/opInsertBegin/constructJoinAddress/newVarnode/combine_input_varnodes/set_double_precis_recovery/isPrimitiveWhole/typelock/getTrueOut/getFalseOut/ReturnCopy/ordered getBasicIter 全部用真实基础设施填掉。删过期 TODO：isBigEndian/ordered iteration/newVarnodeSpace（实现已忠实）。仅剩 hasUnreachableBlocks 1 处（Funcdata 无只读查询，需加方法）。

### 2026-08-13：RuleDoubleOut 传播 combine 错误

`RuleDoubleOut::apply_op` 对 `Funcdata::combine_input_varnodes` 使用 `?` 传播
`LowlevelError` 映射后的 `Result`，不再忽略 non-input/non-contiguous 或 bank 删除失败。
该单点只闭合返回值传播；combine 的 synthetic fixture 证据与未覆盖 Architecture/ProtoModel
边界记录在 `docs/api/funcdata.md` 和 `VARNODE-INIT-0001` metadata。

### 2026-09-25：空间限定构造收口（FAMILY-AUDIT-SPACELESS-SITES-0001）

三处 Register/RAM 钉死构造改用 oracle 的完整 (space,offset) 源：

1. `SplitVarnode::create_joined_whole`（double.cc:565-578）：oracle `newaddr`
   是空间限定地址——contiguous 分支 = pieces 自身地址（double.cc:572
   `res = lo/hi->getAddr()`），join 分支走 `constructJoinAddress`
   （translate.cc:817-860：spacebase/stack 与 default-code/ram 在偏移连续时
   保留原空间 cc:827-836，其余落 **join 空间** formal JoinRecord cc:848-859）。
   Rugra 原 implicit-RAM `new_varnode` 把寄存器/栈 piece 的 whole 伪造成
   `Ram@offset`（HERITAGE-CROSSSPACE-MERGE 同族垃圾种子）。修复：
   `(newaddr, whole_space)` 二元组 + `new_varnode_in_space(wholesize,
   whole_space, newaddr)`；join 分支的 offset 计算保持既有 degraded glue
   （arch.rs `construct_join_address`，无 join-record 分配/register-name 查询），
   本审计只钉死空间。
2. `SplitVarnode::replace_copy_force`（double.cc:1402-1431）双构造点
   （cc:1416/1423）：oracle `addr` 参数是 `CopyForceForm::verify` 里
   `isAddrTiedContiguous` 填的 reslo/reshi piece 自身完整地址（double.cc:3158
   → cc:811/816）。修复：`CopyForceForm` 增 `addr_out_space`（verify 时从
   reslo 取，double.cc:805 已保证两 piece 同空间），签名加 `space` 参数，
   两构造点改 `new_varnode_out_full(size, space, addr, op)`。

触发面实证（curl/httpd 默认态 release 探针）：joined-whole 与 copy-force
双位点 **0 次触发**（双精度恢复路径语料休眠）——恒等 = correct-by-construction；
一旦触发即按 oracle 空间构造。输出字节恒等见 TODO 板该行验收。
<!-- annotation-pass: 2026-07-04 -->
<!-- ref-fix2: 1783141346.313316 -->

 

- 2026-09-25 (FAMAUDIT integration): constructor sites merged to master; this note records the integration commit touching the module.

## join 基建接线（SQLCENSUS-STACKSLOT-GROUP-0001 第一波，2026-09-28）

- 本文件对应源码的改动均为 join 空间基建（translate.cc:817
  constructJoinAddress / :671 findAddJoin 的 1:1 移植，详见 docs/api/arch.md
  与 docs/api/space.md 条目）的接线/适配面：CALL 侧 join 闭包 whole 落
  Join 空间注册地址；RETURN 侧 return_join_address 委托 Architecture；
  double_precis create_joined_whole 消费空间限定结果；process_joins /
  build_subpiece 经 RwLock 读 join_db。无独立新语义。

## 2026-09-28（S1W2-PIECE16-CHAIN，SQLCENSUS-STACKSLOT-GROUP-0001 wave-2）：find_definition_point 跨块支配成功路径的成员 defblock 赋值

- **`SplitVarnode::find_definition_point`**（double.cc:322-375）的 hi 写入臂
  此前把 `cc:343 defblock = lastop->getParent()` 降格为**局部变量**——跨块
  分支的支配成功路径（cc:349-352 `curbl == otherblock → return true`）带着
  `defpoint=Some` 但 `self.defblock=None` 返回，`find_create_whole` 的
  cc:541 `defblock != 0` 测试随之落入 topblock 分支，重建的 PIECE 整值被
  `opInsertBegin` 到**函数入口块**（vmprintf 实测 89/101 个 PIECE16 根全在
  0xad254 入口），其覆盖自此横跨全函数，后续 mergecopy 全部 required merge
  被保守拒绝。修复=按 oracle 语义在分支前赋**成员** `self.defblock`
  （cc:343），第二次尝试臂的 `self.defblock = otherblock`（cc:353）与
  同块臂（cc:366）原已正确。回归锁=
  `test_find_definition_point_dominance_success_sets_defblock_member`。
