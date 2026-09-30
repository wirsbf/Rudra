# `condexe.rs` API Reference

## 2026-08-24（CONDEXE-SUCCESS-STATE-0001）：成功通道对齐（per-space heritage / live 遍历 / numhits→count / RETURN 空间保持）

Action 侧四处缺陷修复（condexe.cc:478-503 + cc:23-37 + cc:392 + cc:343）：

1. **per-space buildHeritageArray（cc:23-37）**：原实现硬编码 `vec![true; 4]`
   （"所有空间已 heritage"近似）。现按 oracle 逐语句移植：
   `resize(numSpaces,false)` 起全 false，逐空间 `is_heritaged()` 过滤
   （cc:33，先于 numHeritagePasses 查询，oracle 的 non-heritaged throw
   不可达）+ `numHeritagePasses(spc) > 0` 置位（cc:34 =
   `pass - info->delay`，heritage.cc:2779-2788，经 `fd.heritage`
   直读——funcdata.hh:237 内联委派）。空间枚举 =
   `Heritage::build_info_list` 的固定 enum 表（heritage.rs:660，
   Rugra 对 `glb->numSpaces()` 的现行替身；Overlay/Other 在
   AddrSpaceManager 可从 Funcdata 到达前不可枚举，SPACE-0001），
   索引为表内位置（`AddrSpace::getIndex` 替身）。
2. **cc:392 真实接线**：`test_removability` 的无后继 Varnode 门
   `heritageyes[vn->getSpace()->getIndex()]` 原被忽略恒真；现缺
   heritage pass 的空间返回 false（拒绝移动）。列表外空间（Overlay/
   Other）读作 not heritaged。
3. **live BlockGraph 遍历（cc:487-500）**：原实现每轮快照 block 列表 +
   `sin==2&&sout==2&&is_cb` 预过滤 + 每轮重建 ConditionalExecution。
   现按 oracle：apply 全程**一个** ConditionalExecution（buildHeritageArray
   每 apply 恰缓存一次，cc:487），`bblocks.getSize()/getBlock(i)` 每次
   迭代**活读**（cc:488 引用语义）——execute 折叠后 iblock 被移除、列表
   左移，紧跟其后的块本轮被跳过（游标已过）、下一轮才重试；预过滤删除
   （所有检查在 trial/verify 内，cc:494）。
4. **numhits→Action count（cc:496/501）**：`ActionConditionalExe` 增加
   `count: i32` 字段，apply 末 `self.count += numhits`（统计专用，返回值
   仍 0），经 `take_count_delta` 外化（action.rs perform 收割，与
   coreaction.rs multicse/restructure_varnote 同模式）。Err 上抛路径
   跳过累加，同 oracle throw。
5. **space-preserving RETURN 替换（cc:343）**：doReplacement RETURN 腿的
   COPY 输出原用 `new_varnode_out`（pin Register 空间，丢失原空间）；
   现与 pullbackOp 共用 `new_varnode_out_with_space`（funcdata_varnode.cc:
   104-127 逐语句：createDef→setOutput→assignHigh→laned→properties），
   保留 RETURN 存储地址**与其地址空间**（unique/register 等）。

**fixture**：`tests/oracle/condexe_success_state_1204`（.cc/.rs/.metadata.json）
+ `tools/run_condexe_success_state_oracle.sh`（pin-base schema2）。13 记录：
S1p0..p3 逐空间数组（ram/register/unique pass1 翻转、stack delay=1 pass2
翻转）、S2 三钻石链（iblock 创建序 3/4/5 连续——活索引遍历是 cc:488 引用
语义：每次 execute 后 relist、游标每步消费新表；pinned 折叠序 A,B,C，
`multi` 记录按新 MULTIEQUAL 输出 unique 偏移（=创建序）排序，pinned 输出
b8,b13,b18 即 A,B,C 折叠序的无指针钉定）、count=3、
reciprocal pre→post 重连）、S3 RETURN 腿（ret_in1==copy_out==unique:0x2000:4、
copy_in0=const:0x5、posta_ops=COPY,RETURN）、S4p0/p1 cc:392 门（pass=0
拒绝 count=0、pass=1 放行 count=1）。负对照：旧 heritageyes 恒真实现在
S4p0 给 count=1、旧 new_varnode_out 在 S3 给 register:0x2000。
（勘误 R17：初版把 pinned 序误写为 b8,b18,b13 并把折叠序误记为 A 折后 B
被跳过、round 2 补折；实际 pinned 输出为 b8,b13,b18 = A,B,C。S2 图形上
被 relist 移到游标下方的只是三个 1in/1out postb 路径块（b7/b12/b17），
round 1 即完成 A,B,C，live 与每轮快照在该图形上折叠序不变——S2 不判别
live/snapshot，对齐由 cc:488 活读算法本身保证；一般图形下快照不变性
不成立（R17 §2(b) 反例）。）

新增 fixture 胶水：`ConditionalExecution::fixture_heritage_array` /
`fixture_heritage_space_names`。

## 2026-08-24：RuleOrPredicate 名对齐锁定 oracle 构造器字符串

`RuleOrPredicate::get_name` → `orpredicate`（condexe.hh:189 ctor 精确名，
原 `or_predicate`）。


**源代码路径**: `src/condexe.rs`
**Ghidra 对应**: `condexe.hh` / `condexe.cc` (712 行)
**状态**: 🔧 **L2（2026-08-24 更新）**——trueout 极性（CONDEXE-TRUEOUT-0002）、
pullbackOp storage/插入位置（CONDEXE-PULLBACK-0005，`condexe_pullback_1204`
5/5 MATCH）、错误通道（CONDEXE-ERROR-0006 + CONDEXE-UNREACHGUARD-0001，
`condexe_error_1204` 4/4 MATCH）、成功通道（CONDEXE-SUCCESS-STATE-0001，
`condexe_success_state_1204` 6/6 MATCH：per-space heritage、live 遍历、
numhits→count、RETURN 空间保持、reciprocal edge）已对齐；RuleOrPredicate
端到端差分与 directsplit 变体仍留待后续任务，故保持 L2。

## 模块说明

条件执行简化。对应 Ghidra 的 `ConditionalExecution` 类与 `ActionConditionalExe`
（condexe.hh:91, condexe.cc:478-503）。

当两个 CBRANCH 测试相同（或互补）的布尔值时，第二个路径合并是冗余的，可被消除：

```text
   if (a) {           if (a) {
      BODY1              BODY1
   }          ==>        BODY2
   if (a) {           }
      BODY2
   }
```

iblock 是两条流不必要汇合的块；initblock 是最初计算布尔值的块。两条路径从
initblock 到 iblock（prea / preb），两条路径离开 iblock（posta / postb）。
若 iblock 的 CBRANCH 冗余，则移除 iblock，将 prea 重连到 posta（条件互补时连到
postb），并通过把读推入正确路径来保留 MULTIEQUAL 数据流。

## 2026-06-27：完整 1:1 移植

此前实现仅检测候选并 `eprintln!` 标记，**核心图重写完全缺失**。本次完整移植：

### ConditionalExecution（condexe.hh:91, 712 行算法全部移植）

| 方法 | Ghidra 行号 | 说明 |
|---|---|---|
| `new` | 432 | 构造 + buildHeritageArray |
| `test_iblock` | 43 | iblock 必须有 2 入/2 出 + 末尾 CBRANCH |
| `find_init_pre` | 55 | 沿 prea/preb 链回溯找 initblock + 设 init2a_true |
| `verify_same_condition` | 80 | BooleanExpressionMatch 验证同/互补条件 |
| `test_multi_read` | 101 | MULTIEQUAL 的读是否可移动 |
| `test_op_read` | 120 | 非 MULTIEQUAL op 的读是否可移动 |
| `test_removability` | 361 | iblock 内 op 是否可移除 |
| `verify` | 402 | 完整配置验证 + 所有 op 可移除性检查 |
| `find_pullback` | 146 | 查找已构造的 pull-back |
| `pullback_op` | 160 | 将 iblock 内 op 复制到前驱块（MULTIEQUAL slot 选择）；Result 化（Err=结构不变量守卫，oracle 无失败路径） |
| `get_new_multi` | 198 | 在给定块创建 MULTIEQUAL 持有数据流；Result 化（同上） |
| `resolve_read` | 224 | 计算通过任意块的读的替换 Varnode；Result 化 |
| `resolve_iblock_read` | 242 | 计算通过 iblock 的读的替换；**Err = 逐字 `LowlevelError("Conditional execution: Illegal op in iblock")`（condexe.cc:261）** |
| `get_multiequal_read` | 270 | MULTIEQUAL 读的替换；Result 化 |
| `get_replacement_read` | 291 | 块的替换 Varnode（缓存 + 支配者回溯）；**Err = 逐字 `LowlevelError("Conditional execution: Could not find dominator")`（condexe.cc:303）** |
| `do_replacement` | 320 | 重写给定 iblock op 的数据流；Result 化（每轮必删一个后继或上抛 Err，无静默跳过） |
| `trial` | 448 | 测试给定块是否为可修改的 iblock |
| `execute` | 457 | 消除 iblock 的不必要路径汇合；**`Result<()>`——doReplacement/removeFromFlowSplit 的 LowlevelError 上抛（apply 异常中断协议）** |

### BooleanMatch / BooleanExpressionMatch（expression.cc:57-232）

- `boolean_match_evaluate` — `BooleanMatch::evaluate`（SAME/COMPLEMENTARY/UNCORRELATED）。**2026-07-05 修正**：expression.cc:154-164 的 commutative re-pairing 之前是死代码（`match (a,d,c,b) { _ => {} }` 从未真正递归），导致 swapped-operand AND/OR 被误判 UNCORRELATED，condexe 折叠失效。现按 Ghidra 行 154-164 完整移植：`pair1==uncorrelated` 时尝试 `(in1[0],in2[1])`，仍 uncorrelated 才返回；否则计算 `(in1[1],in2[0])` 作为 pair2。
- `same_op_complement` — `sameOpComplement`（INT_LESS/INT_SLESS 常量互补）
- `varnode_same` — `varnodeSame`
- `boolean_match_verify_condition` — `BooleanExpressionMatch::verifyCondition`

### 底层原语（为支撑 condexe 新增）

**`block.rs`**：
- `BlockBasic::get_out_rev_index` / `get_in_rev_index`（block.cc）
- `BlockBasic::half_delete_in_edge` / `half_delete_out_edge`（block.cc:140/149）
- `BlockBasic::replace_edges_thru`（block.cc:198-216）—— 核心边重定向
- `BlockGraph::remove_block_arc` / `remove_edge_blocks`（block.cc:1517）

**`funcdata.rs`**：
- `Funcdata::remove_from_flow_split`（funcdata_block.cc:892 + block.cc:1575）
- `Funcdata::structure_reset`（funcdata_block.cc:705）

**`op.rs`**：
- `PcodeOp::is_boolean_flip`（op.hh:210）

### 主管线接入

`ActionConditionalExe` 注册在 `decompile` group 的 `ActionDeadCode` 之后、
`ActionBlockStructure` 之前（对应 Ghidra coreaction.cc:5675 mainloop 顺序）。

## 已知限制

1. ~~**边顺序适配**~~ **已修复（2026-08-23，CONDEXE-TRUEOUT-0002）**：Rugra CBRANCH
   出边实际为 `[fallthru, branch_target]`（flow.rs:920-928，同 flow.cc:960-967），
   与 Ghidra `[falseOut, trueOut]` 布局相同，无需任何 flip 适配。
   `is_true_out_to` 已删除（其 flip 重映射是多余翻转，`find_init_pre` 现内联
   condexe.cc:72 的纯位置比较）；`discover_path_is_true` 改纯位置
   getTrueOut/getFalseOut（condexe.cc:575-582）。BOOLEAN_FLIP 的合法消费点只剩
   `discover_conditional_zero`（condexe.cc:612-613）与 `verify_same_condition`
   的 matchflip 合成（expression.cc:227-230），各恰好一次。
2. ~~**heritageyes 近似**~~ **已修复（2026-08-24，CONDEXE-SUCCESS-STATE-0001）**：
   buildHeritageArray 现为逐空间真实数组（cc:23-37），cc:392 门真实接线；
   空间枚举在 AddrSpaceManager 可从 Funcdata 到达前使用 Heritage 固定表
   （SPACE-0001 前 Overlay/Other 不可枚举，读作 not heritaged）。
3. **真实二进制未触发**：curl/httpd 的函数恰好无 `if(a){}if(a){}` 或
   `cond ? val : 0` 谓词模式，故 apply 返回 NO_CHANGE（正确行为）。算法正确性由
   单元测试守护。

**fixture 可观测胶水（RUGRA-GLUE，2026-08-23）**：`ConditionalExecution::fixture_find_init_pre`
/ `fixture_verify`、`RuleOrPredicate::fixture_discover_path_is_true` —
供 locked oracle fixture（tests/oracle/condexe_trueout_1204）在隔离状态下驱动
私有阶段并观察 init2a_true / camethruposta_slot / zero_path_is_true；Ghidra 侧经
`#define private public` 读取同一批私有成员。

## 2026-08-23（CONDEXE-PULLBACK-0005）：pullbackOp storage/插入位置对齐

审计（docs/alignment_audit/CONDEXE_GAPS_2026-08-22.md §1 #8）定位的两处缺陷修复：

1. **storage（cc:182）**：`pullback_op` 的复制输出原为 `new_unique_out`（匿名
   unique 地址）；Ghidra 是 `fd->newVarnodeOut(origOutVn->getSize(),
   origOutVn->getAddr(), newOp)` — 保留原输出地址**与其地址空间**。新增私有
   `pullback_new_varnode_out`（funcdata_varnode.cc:104 newVarnodeOut 的逐语句复制：
   createDef → setOutput → assignHigh → laned → queryProperties），因 Rugra
   `Funcdata::new_varnode_out` 在 split Address 模型下硬编码 Register 空间，
   无法表达 unique 空间原地址（P2 投影即钉死该差异）。
2. **插入位置（cc:187）**：`op_insert_begin` → `op_insert_end`（funcdata_op.cc:435-446，
   落在块尾、trailing flow-break 之前，而非 MULTIEQUAL 组之后）。
3. **defOp slot 语义（cc:172）**：`defOp->getIn(inbranch)` 缺槽时不再回退原
   varnode，而是按 Ghidra 的不可达语义向上传播 `None`。

**fixture**：`tests/oracle/condexe_pullback_1204`（.cc/.rs/.metadata.json）+
`tools/run_condexe_pullback_oracle.sh`（pin-base schema2，base 0d9f8a1 + 单
src/condexe.rs overlay）。三投影（块位 idx/nops、SeqNum pc:time、storage
space:offset/size）覆盖：P1/P1b SUBPIECE 经 iblock MULTIEQUAL 的 inbranch 0/1
pullback（目标块 = iblock->In(inbranch)，input 0 = MULTIEQUAL slot）、P3
findPullback 缓存命中（同指针、零新 op）、P2 跨块 immedDom pullback（unique
空间原地址保留）、P5 常量 input 0 直传 immedDom、G1-G8 testOpRead 准入矩阵
（INT_ADD/PTRSUB 非常量 input 1 拒绝 cc:126-128、非 MULTIEQUAL in-ib 定义者拒绝
cc:131-133、free/常量 input 0 拒绝 cc:135-136）。14/14 记录双侧字节一致
（`covered_projection=5/5 projection_status=MATCH`）。负向对照已验证：回退到
`new_unique_out`+`op_insert_begin` 后 P1-P5 全部 MISMATCH（`out=unique:<counter>`、
`idx=0`）。

新增 fixture 胶水：`ConditionalExecution::fixture_pullback_op` /
`fixture_test_op_read`（同上 trueout 胶水模式）。

**残差（CFG-0001）**：execute/doReplacement/removeFromFlowSplit 与 pullback 输出的
交互未投影（fixture metadata `residual_union`）；doReplacement RETURN 腿的
newVarnodeOut 地址保留（condexe.cc:340-349）留待同一后续任务。

## 2026-08-23（CONDEXE-ERROR-0006）：错误通道对齐（resolve 链 Result 化）

审计（CONDEXE_GAPS_2026-08-22.md §1 #11/#13/#14/#19, §2.3 缺陷 E）定位的三处缺陷修复：

1. **resolve/verify 链 Result 化，错误逐字对应 Ghidra throw**：
   - `resolve_iblock_read`：非法 iblock op（含 COPY 的 input 0 被非 iblock
     MULTIEQUAL 的 op 写入的 fall-through 腿）→ `Error::Lowlevel(
     "Conditional execution: Illegal op in iblock")`（condexe.cc:261 逐字）。
     旧代码此处静默 `None`。
   - `get_replacement_read`：支配者链走出图仍未到 iblock → `Error::Lowlevel(
     "Conditional execution: Could not find dominator")`（condexe.cc:303 逐字）。
     旧代码此处静默 `None`。
   - Ghidra 中不可达的空指针路径（`op->getIn(0)`/`getDef()`/`getOut()`/
     `getImmedDom()` 解引用，oracle 里是 UB 崩溃而非 LowlevelError）映射为
     `structural()` 助手产生的 `Error::Generic`（RUGRA-GLUE，消息明确标注
     "no oracle counterpart"），与 oracle 可达错误严格区分。
2. **do_replacement 死循环消灭**：oracle 的循环不变量是每轮恰好移除一个后继
   （iblock 内 `opUnsetInput`，否则 `opSetInput`，cc:333/352），resolve 链要么
   给 Varnode 要么 throw，不存在静默跳过。旧 Rust 代码 `rvn == None` 时跳过
   `op_set_input` → 后继表不收缩 → `descends[0]` 永远是同一 readop → 死循环。
   现重写为与 cc:320-357 同构：先算 `rvn`（可上抛 Err，保留部分状态），成功则
   必定 set/unset input（保证前进），slot 丢失映射为 structural Err。
   RETURN 腿（cc:339-349）保持 oracle 的调用顺序：先建 COPY + 替换 RETURN
   input[1] + 插入，**再** `get_replacement_read`（此处上抛时 newcopy 无
   input 0 落地 = oracle throw 后的部分状态）。
3. **Err 不丢弃——execute/apply 返回协议**：`execute` 改 `Result<()>`，
   `doReplacement` 的 Err 经 `?` 上抛；`remove_from_flow_split` 的
   `Result<(), String>` 不再 `let _ =` 丢弃，在调用边界映射为
   `Error::Lowlevel(msg)`（oracle 侧 Funcdata::removeFromFlowSplit 对非空块
   `throw LowlevelError("Can only split the flow for an empty block")`，
   funcdata_block.cc:884-885，异常同样穿透 execute/apply）。
   `ActionConditionalExe::apply` 用 `condexe.execute()?` 上抛——对应 oracle 的
   异常中断行为：apply 永不返回，整个反编译管线中止本函数，Funcdata 停留在
   部分变换状态（已 destroy 的 iblock op 保持 destroyed、出错 op 存活、
   removeFromFlowSplit 未执行）。Rust 侧 `ActionGroup::apply` 对 `?` 中止
   （action.rs），语义等价。
   **RESIDUAL CFG-0001**：Rugra `funcdata.rs remove_from_flow_split` 的 Err
   消息文本仍是 Rugra 侧文案（"remove_from_flow_split: block must be empty"
   ≠ oracle 逐字文本）且 swap 映射未修——该文件归 CFG-0001 租约，错误路径
   在此只做到调用边界并如实登记。

**fixture**：`tests/oracle/condexe_error_1204`（.cc/.rs/.metadata.json）+
`tools/run_condexe_error_oracle.sh`（pin-base schema2，base e6b4ec0 + 单
src/condexe.rs overlay）。经 `ActionConditionalExe::apply` 全协议驱动四类观察：
E1 非法 iblock op（cc:261）、E2 断链 dominator（cc:303）、E3 verify 失败
（条件不相关 → trial false → apply 正常返回 0、零状态变化）、E4
unreachable-blocks 前置返回（CONDEXE-UNREACHGUARD-0001）。E1/E2 双侧断言
逐字错误消息 + 中止点部分状态（逐块 op 存量、iblock 仍在图中 2in/2out、
出错 op 存活、其后继读未动）；E1 输入同时是死循环回归（旧代码该输入死循环）。
E4 用 E1 形状的 diamond 先跑 `structure_reset`（浮动 b6 无入边 →
findSpanningTree 收集双根 → funcdata_block.cc:713-714 经**正规途径**置
blocks_unreachable；pre 记录回显 unreach=1 防御 flag 未置位的空转通过），
apply 触发 cc:485-486 守卫**立即**返回 0：零构造、零 trial、零状态变化、
numhits 保持 0（cc:501 的 count 累加被短路）。负对照：去掉守卫的 Rust 在
E4 复现 E1 中止（err kind=lowlevel），即守卫是唯一行为翻转点。
9/9 记录双侧字节一致。

**新增单元测试**：`test_apply_aborts_illegal_iblock_op`、
`test_apply_aborts_missing_dominator`（逐字消息 + 部分状态 + 终止性）、
`test_apply_verify_failure_no_change`、
`test_apply_unreachable_blocks_early_return`（CONDEXE-UNREACHGUARD-0001：
flag 置位 → apply 立即返回 0、零状态变化）。

## 2026-08-23（CONDEXE-UNREACHGUARD-0001）：apply 的 unreachable-blocks 前置返回

condexeerr 复核发现 `ActionConditionalExe::apply` 缺 oracle condexe.cc:485-486
的前置守卫。已接线：

```rust
if fd.has_unreachable_blocks() {
    return Ok(action_status::NO_CHANGE);
}
```

对齐要点（condexe.cc:478-503 逐行核对）：
- **位置**：守卫是 apply 首条语句，先于 `ConditionalExecution` 构造（cc:487）
  与 do-while 轮循环（cc:490）——只读 `Funcdata::hasUnreachableBlocks()`
  （funcdata.hh:149，缓存位由 `structure_reset` 维护，
  funcdata_block.cc:710/714），零状态变化。
- **返回值**：oracle `return 0` ↔ `Ok(action_status::NO_CHANGE)`（=0），
  与正常完成路径同值。
- **计数器**：cc:501 的 `count += numhits` 被短路——numhits 保持 0，
  Action::count 不更新（Rugra 侧本就无 count 状态，语义空变）。
- **oracle 注释**："Conditional execution elimination logic may not work
  with unreachable blocks"。

## 2026-06-27（续）：RuleOrPredicate 完整移植（condexe.cc:509-712）

condexe.cc 的第二部分，一个独立的 Rule，处理谓词构造：
```text
    tmp1 = cond ? val1 : 0;
    tmp2 = cond ?  0 : val2;
    result = tmp1 | tmp2;   ==>   newtmp = val1 ? val2;  result = newtmp;
```

**MultiPredicate**（condexe.hh:174）全部 4 个方法移植：
- `discover_zero_slot` — `discoverZeroSlot`（509）：检测 2 输入 MULTIEQUAL，一端为 COPY(#0)
- `discover_cbranch` — `discoverCbranch`（539）：找控制 MULTIEQUAL 两入路径的单一 CBRANCH
- `discover_path_is_true` — `discoverPathIsTrue`（572）：判定 condBlock 真出边是否流向 zero set
- `discover_conditional_zero` — `discoverConditionalZero`（590）：验证 CBRANCH 布尔是 (vn==0)/(vn!=0)

**RuleOrPredicate**（condexe.hh:172）：
- `get_opcodes` — `getOpList`（617）：INT_OR + INT_XOR
- `check_single` — `checkSingle`（638）：交替形式 `tmp1=(val2==0)?val1:0; result=tmp1|other`
- `apply_op` — `applyOp`（654）：双 branch 模式 + 共享/独立条件 + finalBlock MULTIEQUAL 重写

**支撑原语新增**：
- `block.rs`: `BlockGraph::find_common_block`（block.cc:736 支配者树 LCA）
- `op.rs`: `PcodeOp::compare_order`（op.cc:778 控制流顺序比较）
- `condexe.rs`: `verify_condition_with_flip`（暴露 BooleanExpressionMatch::getFlip）

**接入**：在 ActionSimplify 的硬编码简化之后，对 INT_OR/INT_XOR op 单独跑 RuleOrPredicate
（Ghidra 里它在 actprop rule group，即简化阶段）。

## 测试

`condexe::tests`（15 个）：action_name、correlation_constants、varnode_same_identity、
apply_on_empty_fd、boolean_match_same_condition、trial_rejects_unrelated_conditions、
rule_or_predicate_rejects_plain_input、rule_or_predicate_opcodes、compare_order_basic、
rule_or_predicate_trait_name_and_opcodes、rule_or_predicate_trait_apply_no_form、
apply_aborts_illegal_iblock_op、apply_aborts_missing_dominator、
apply_verify_failure_no_change（后三个为 CONDEXE-ERROR-0006 错误通道回归）、
apply_unreachable_blocks_early_return（CONDEXE-UNREACHGUARD-0001 守卫回归）。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

### 2026-07-01（管线改造）：ActionConditionalExe apply &self→&mut self

### 2026-07-01：RuleOrPredicate impl Rule trait
包装现有 apply_op 为 Rule trait（INT_OR/INT_XOR dispatch）。注册 oppool1:5631。
<!-- annotation-pass: 2026-07-04 -->

 


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
