# `heritage.rs` API Reference

## 2026-09-26：KUNABUGS-STORELOAD-FWD-0001 — store→load 转发链双侧 fixture 验证（MATCH）+ guard_loads_range 注释刷新

P1 验证票（kuna LOSS-237 桌面候选根因的实证裁决）：pre-heritage 栈 store→load
转发机制链——`discover_indexed_stack_pointers`（cc:986）→ `generate_load_guard`
（cc:909）→ `guard()` addIndirects 半区（cc:1188-1198）→ `guard_stores_range`
INDIRECT 插入（cc:1538-1559）+ `guard_loads_range` COPY 边界插入（cc:1570-1601）
→ rename 把 COPY 输入接到被追踪栈版本（cc:2489-2561）→ `analyze_new_load_guards`
（cc:834，ValueSetSolver 窗口精化）→ `handle_new_load_copies`/`find_address_forces`
/`propagate_copy_away`（cc:619-730）消除 guard COPY 并对分析窗口内的边界写打
ADDRFORCE。

新双侧 fixture `tests/oracle/heritage_storeload_fwd_1204.{cc,rs}`（B2 四件套 +
`tools/run_heritage_storeload_fwd_oracle.sh`）三 case × 两 heritage pass
（stack delay=1：pass 0 处理寄存器空间，pass 1 处理栈空间）：

- `fwd_indexed_load`：双写栈槽 0x40 + 常量偏移 STORE（INDIRECT 守卫）+ 索引化
  LOAD（loadGuard COPY 置入→rename 接 INDIRECT 输出→传播销毁；末次写 ADDRFORCE）；
- `const_load_no_fwd`：负对照——常量偏移 LOAD 指针（traversals==0）不产生
  loadGuard，无 COPY 生命周期、无 ADDRFORCE；STORE 的 INDIRECT 仍在；
- `phi_fwd`：双臂写 + join 后索引化 LOAD——COPY 输入 rename 到 join
  MULTIEQUAL，双臂写均 ADDRFORCE。

**判定 MATCH**：13 行 stdout 双侧字节恒等（sha256
`468bf48ef02de3c0b4c3a7856eb2cb6b534bb4df0dedbc27158c5578ae20632b`，双侧各双跑
恒等，stderr 空）。观察面覆盖：guard 记录（pointerBase/min/max/step/state）、
INDIRECT 引入与输入别名、COPY 邻接消除、ADDRFORCE 落点、phi 槽位、逐 op 顺序/
flags/desc/active/known/def、逐空间 bank census、restart 位。F-RESIDE/STACKSLOT
残差族的 LOSS-237 候选根因（转发缺失）在 fixture 观察面上**排除**；残差族根因
另寻（DB-LOCALSCOPE 簇/merge 平局等其余候选不受本票影响）。

同 commit 刷新 `guard_loads_range` 头注释：原注释仍声称 COPY 插入体为登记
stub、ValueSetSolver 为 stub——两者自 SB-MATCHURL-ORD55-0001 /
GETPARAM-OPPOOL-COUNT-0001 / RANGEUTIL-VSEMPTY-0001 起即为实装，本 fixture
复证；注释改为如实描述并引用 fixture。零行为改动（纯注释）。

## 2026-09-23：SB-MATCHURL-ORD55-0001 — discoverIndexedStackPointers 落地 + guardLoads COPY 边界体（load-guard COPY 族）

match_url Phase 2 ordinal 55（heritage 二轮）根因修复。oracle 在 heritage 二轮对每个
stack range 的 `guard()` 内由 `Heritage::guardLoads`（heritage.cc:1570-1601）为每条
与 range 相交的 `loadGuard` 记录创建一个 COPY 边界 op（cc:1590-1599，uniq 消耗 =
每 range 每记录 1 个），`handleNewLoadCopies`（cc:695-730）在 pass 尾
`propagateCopyAway` 把它们传播销毁——drill 中表现为 7 个"双 `**`"即死临时 op
（52bd:643..52c5:649），使后续 MULTIEQUAL 的 uniq 从 64a 起。Rugra 侧
`load_guard` 记录生产链整体缺失（`guard_loads` 记录构造器仅测试调用，
`guard_loads_range` 的 COPY 插入体为登记 stub）→ phi uniq 前移 7 至 643。

本 lane 落地内容（全部对齐锁定 oracle 12.0.4 e40ed130）：

- `discover_indexed_stack_pointers`（cc:986-1102 全函数移植）：显式 DFS 栈
  （`StackWalkNode` 镜像 heritage.hh:216-236 的 `StackNode`，`iter` 为 descend
  下标），Varnode mark 防指数梯子；INT_ADD 常量臂累积 wrapOffset 偏移/非常量臂
  置 `nonconstant_index`，SEGMENTOP 仅 in(2) 为当前指针时落 COPY 语义，
  INDIRECT/COPY 同偏移同 traversals，MULTIEQUAL 置 `multiequal`；LOAD 在
  traversals≠0 时 `generate_load_guard`（cc:909-917：!usesSpacebasePtr 门 +
  `LoadGuard::set(op,spc,node.offset)` 记录 pointerBase + opMarkSpacebasePtr），
  STORE 在指针输入来自链上时 traversals≠0 走 `generate_store_guard`
  （cc:926-936）否则仅 mark（cc:1087）；链死端输出落 SPACEBASE 型空间
  （enum 模型 = Stack）置 `unknown_stack_storage`，结尾按 checkFreeStores 调
  `protect_free_stores`。Rugra 语义注记：INT_SUB 不在 oracle switch 内，不移植
  （旧近似 `discover_and_guard_stack_stores_fd` 曾含 INT_SUB 且自建 INDIRECT——
  非 oracle 行为，该函数保留但生产路径不再触达）。
- `protect_free_stores`（cc:944-972）：bank 序 STORE，指针经 COPY / INT_ADD(常量)
  链回溯到基 varnode，`isFree`（varnode.hh:238 = 非 written 非 input）且落本
  空间 → opMarkSpacebasePtr + freeStores 追加。
- `heritage()` 接线（cc:2691-2697）：`load_guard_search` 首趟置位时调
  discovery（checkFreeStores=true），返回真时 reprocessStackCount/stackSpace
  记账 → cc:2751-2752 `reprocess_free_stores` 首次可达。
- `reprocess_free_stores` cc:1117 行：近似调用换真实 discovery
  （checkFreeStores=false）。
- `guard_loads_range` 补 COPY 插入体（cc:1590-1599 逐行）：
  `new_op(1, load_addr)` → `new_varnode_out_full(size, space, addr, op)` +
  setActiveHeritage + setAddrForce → COPY → 输入
  `create_with_space`+`set_varnode_properties`（HERITAGE-MULTIEQ-VNIN-
  SYMBOLTAIL-0001 同模式）+ setActiveHeritage → `op_set_input` →
  `op_insert_before(load_op)` → `load_copy_ops` 压栈。窗口判定从"range 相交"
  改回 oracle 原形（cc:1588-1589：range **起始** offset 对
  [minimumOffset, maximumOffset] 的逐侧 continue）。

对齐证据（match_url Phase 2 mirror 投影 vs curl.match_url.oracle.projection
sha 2bdabd73…，340 stages/80385 ops）：首分歧 ordinal 55 → **70**。heritage 二轮
drill 块（oracle 847 行 vs rugra 846 行）除既有 `ffunc_0x…` vs `i0x…` 调用名显示
噪音外逐行一致，slot 130 的 phi uniq 64a-64f 双侧对齐（64d/725/741… 处处相等）。
新首分歧 ordinal 70 = stackstall:oppool1 count 102 vs 151（RuleIndirectCollapse
+39），探针实证为 stack 槽位 varnode `nolocalalias` flag 状态差
（`ActionRestructureVarnode` cc:2279 `aliasyes=(numpass!=0)` 门 + 二趟
markUnaliased 别名表内容差）→ varmap/ScopeLocal 域，登记
SB-MATCHURL-ORD70-0001，非本 lane write-set。

**heritage.rs=机制 C 白名单：本改动合并主管线前需独立 Cross-Review。**

## 2026-09-22：place_multiequals MULTIEQUAL 输出改走 newVarnodeOut 完整尾（VARGROUP-ABSORB-0001 / SUBRIGHT-ADDRTIE-0001 二段）

heritage.cc:2634 的原调用是 `vnout = fd->newVarnodeOut(size, memrange.addr, multiop)`——带
assignHigh + laned 检查 + localmap queryProperties 尾(funcdata_varnode.cc:104-122),其 local 腿
对域内栈存储折叠 mapped|addrtied(database.cc:1268-1277,无符号条目也如此)。Rugra 此前用
vbank 裸构造 + set_varnode_properties(无 local 腿)→ 影写合并的 MULTIEQUAL 输出从不 addr-tied
→ RuleSubRight 的 overlap 守卫(ruleaction.cc:7265-7268,双侧 tied)不触发 → splitCopy 建出的
45 个栈地址 SUBPIECE 被化成 INT_RIGHT 移位梯(42 处 CONCAT 中间态直接诱因)。改走
new_varnode_out_full 后守卫按 Ghidra 语义跳过,件存活;A/B(base=70e76ce6):curl skeleton
3105→3074,defects=0/numbering=0,glob_set/glob_range/glob_url 逐函数 IDENTICAL,
getparameter 向 golden 靠拢,httpd 2392==基线字节稳定。**heritage.rs=机制 C 白名单:
本改动合并主管线前需独立 Cross-Review。**


**源代码路径**: `src/heritage.rs`

## 2026-09-22：HERITAGE-PROMOTE-SYMBOLTAIL-0001 剩余位点裁决与补齐（CR-BZ 收尾）

BZ 8 处之后的同类位点族逐点裁决（每点先读 oracle 函数完整体再判定,非盲补）。
oracle 侧事实基础: `Funcdata::newVarnode`（funcdata_varnode.cc:148-169,符号尾
usepoint=INVALID `Address()`）与 `Funcdata::newVarnodeOut`（cc:104-122,符号尾
usepoint=`op->getAddr()`,**同样有 queryProperties→setSymbolProperties 尾**）;
`Funcdata::opSetOutput`（funcdata_op.cc:85）自身也调 `setVarnodeProperties`;
`newIndirectOp`（cc:683-698）in/out 两腿均走上述带尾路径。

**裁决表（补 = 照 BZ 模式在 create 与 flags 折叠之间/def 输出接线后插
`fd.set_varnode_properties(&vn)`）**:

| oracle 位点 | oracle 路径 | 裁决 | 理由 |
|---|---|---|---|
| cc:288 removeRevisitedMarkers `big` | newVarnode | **补** | Rust 2725 裸建(连折叠都无) |
| cc:391 normalizeReadSize `vn1` | newVarnode | **补** | Rust 1869 仅折叠 |
| cc:440 nWS `mostvn` | newVarnodeOut | **补** | Rust 1988 def-裸建+折叠;def 已设故 usepoint=op addr 与 cc:115 一致 |
| cc:441/462 nWS `big` ×2 | newVarnode | **补** | Rust 1996/2046 仅折叠 |
| cc:461 nWS `leastvn` | newVarnodeOut | **补** | Rust 2040 |
| cc:473/475 nWS `midvn` | newVarnodeOut | **补** | Rust 2072 |
| cc:485 nWS `bigout` | newVarnodeOut | **补** | Rust 2095 |
| cc:1225 guardCallOverlappingInput `wholeVn` | newVarnode | **补** | Rust 2943 裸建 |
| cc:1332/1353 guardOutputOverlapStack `newInput` ×2 | newVarnode | **补** | Rust 3523/3584 裸建(stack 域,当前 no-op,结构补齐) |
| cc:1595 guardLoads `invn` | newVarnode | **已补**（2026-09-23 SB-MATCHURL-ORD55-0001） | COPY 插入体落地：`create_with_space` + `set_varnode_properties`（HERITAGE-MULTIEQ-VNIN-SYMBOLTAIL-0001 模式） |
| cc:1742/1750 splitByRefinement 循环片 | newVarnode | **补** | Rust 4422 循环单建点覆盖两行 |
| cc:2008 guardInput `newout` | newVarnode | **补** | Rust 4327 裸建(concat 目标) |
| cc:2095/2100 splitJoinLevel 半片 | newVarnode(Address 形) | **补** | Rust 3390/3397 + 2-piece 内联点 3284/3285(read)/3327/3337(write);register 空间在 Rugra 当前查询通道为 no-op,结构补齐 |
| cc:2241 floatExtensionRead `bigvn` | newVarnode(Address 形) | **补** | Rust 3433;同上 no-op 结构补齐 |
| (新发现,同族) cc:1502 guardCalls trial 输入 | newVarnode | **补** | Rust 1550 仅折叠 |
| (新发现,同族) cc:1634 guardReturnsOverlapping `retVal` | newVarnodeOut | **补** | Rust 1694 def-裸建+折叠 |
| (新发现,同族) cc:1682 guardReturns return-copy 输出 | newVarnodeOut | **补** | Rust 1815 def-裸建+折叠 |
| cc:435/456/1253/1257/1270/1522 newIndirectCreation 系 | newVarnodeOut(经 cc:719) | **不补(登记)** | 缺口在 `funcdata.rs::new_indirect_creation_in_space`/`new_indirect_op`(注释声称带尾,实现仅 `apply_new_varnode_flags` 折叠)——超出本 lane write-set,登记为子项待 funcdata owner |

已确认无缺口: cc:1229/1330/1348/1370/1414/1423/2267/2634(Rust 已走
`new_varnode_out`/既有 `set_varnode_properties`,FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001);
cc:537/1778/1812/2097/2103 `newUnique` 系(unique 空间不入 scope,oracle 亦无尾)。

**验证（A/B 同机同树,base=978a0a80 vs after,均 defects=numbering=0）**:
curl 全语料**字节级一致**(skeleton 3601=3601,defects 0/124, numbering 0);
httpd 29 函数**字节级一致**(2459/0/0);config 域重放 main/getparameter/
parseconfig/glob_set/glob_range/glob_url 逐函数**字节级一致**,全语料
`::config.`=181、DAT_00117[56]xx=0、.rodata witnesses、glob_expand 字段化
形态(5 处)全部与 base 相等——零回退、零改善(语料内这些位点未激活或无可附着
符号,Rugra 侧行为中性)。join 族/register 空间位点按结构补齐(oracle 有尾,
Rugra 通道 no-op)。

## 2026-09-22：heritage 提升/守卫路径补符号尾（HERITAGE-PROMOTE-SYMBOLTAIL-0001）

`HERITAGE-MULTIEQ-VNIN-SYMBOLTAIL-0001` 同族根因的剩余面落地。oracle 中
`Heritage::renameRecurse` 的三处输入提升（heritage.cc:2500-2502/2509-2512/2539-2546）、
`Heritage::guardReturns` 的三处 return-copy/重叠除输入（cc:1628/1670-1672/1687）、
`Heritage::guardInput` 的两处洞填补（cc:1973-1976/1985-1988）全部经
`Funcdata::newVarnode`（funcdata_varnode.cc:148-169），其符号尾
`queryProperties → setSymbolProperties`（cc:161-166）把 typelocked 全局符号的
DWARF 类型挂到被提升 varnode 上。Rugra 这些点此前只跑 `apply_new_varnode_flags`
（仅 flags 折叠，且 Ram 腿给一切全局地址 OR 上 MAPPED——`set_varnode_properties`
的 `isMapped` 守卫被预先堵死，符号 attach 永不发生）。witness：glob_set 的
`glob_expand` 读（ram:0x17660，8B，DWARF `URLGlob*`）经 renameRecurse 提升后
`t=Int/int8` 无 typelock——RulePtrArith（ruleaction.cc:6629，输入需 TYPE_PTR）
永不点火，输出保持 `(int *)glob_expand + … * 0x18` 原始算术；修复后该 varnode
typelocked `URLGlob*`，PTRADD/PTRSUB 重写为 `glob_expand->size / ->pattern /
->type / ->content` 字段化形态（glob_set 97→94、glob_range 80→76，
oracle=ghidra_curl_1204）。各点在 `create_with_space` 后、`apply_new_varnode_flags`
前补 `fd.set_varnode_properties(&vn)`（顺序承载 cc:148 尾内联语义；flags OR 可结合、
不 Clear typelock）。

## 2026-09-22：SUBFLOW-SUBPIECE-WIDTH-0001 — normalizeReadSize 常量宽度

`normalize_read_size`（heritage.cc:382-401）的 SUBPIECE 偏移常量由硬编码
`new_constant(8, overlap)` 改为 `vn.space.addr_size()`（heritage 循环按空间划分，
vn 与 range addr 同空间），对齐 cc:393 `newConstant(addr.getAddrSize(),
(uintb)overlap)`；register 空间宽度随 space.rs `addr_size()` 修正为 4。
`normalize_write_size` 的两处（cc:445/466，Rust 1987/2037）原本已传
`space.addr_size()`，宽度随 Register=4 一并收敛。Phase 2 next_url 对拍：
heritage op-line 22 `4ff4:5ad/5b0 SUBPIECE` 尾常量 `c:0:8`/`c:4:8` →
`c:0:4`/`c:4:4`，首分歧后移（证据见 docs/TODO_BOARD.md 该 TODO 条目）。

## 2026-08-28：EarlyRemoval 所需 Heritage 状态

锁定 EarlyRemoval fixture 证明的范围是：`dead_removal_allowed_seen` 使用严格
`pass > delay`，且成功删除后 `deadremoved=1`；相关 pass/delay/deadremoved 与 covered
op 突变投影为 MATCH。`reset`/`clear`/`propagate_copy_away` 的完整容器、别名、错误及
生命周期并未由该 fixture 覆盖，仍为 UNTESTED；固定枚举遗漏 FSPEC manager slot、
nullable op input 与完整 manager 生命周期也继续作为残差。

## 文档状态

- **状态**: 🔧 **L2（2026-08-11 锁定 12.0.4 审计）**——canonical `Heritage::heritage` 没有生产调用且会重入写锁；主管线改走未建 dominator 的 direct phi/rename 两遍。pass、def-use、IOP、block membership、refinement 与 guard 闭包均不等价，正式行为门禁为 `NO_ORACLE`。详见 `docs/alignment_audit/CONTROL_OUTPUT_PIPELINES_2026-08-11.md`。
- **文档目标**: 说明 Rugra 当前 `heritage.rs` 在 SSA 构造与相关中间状态管理中的职责、边界与公开接口
- **可信边界**: 本文档围绕“当前架构中的 SSA / Heritage 责任分工”进行说明，不把“结构存在”写成“已完成与 Ghidra 的运行时一致性验证”
- **阅读建议**: 请结合以下模块一起理解：
  - `src/funcdata.rs`
  - `src/op.rs`
  - `src/varnode.rs`
  - `src/block.rs`
  - `src/action.rs`
  - `docs/data_contract.md`
  - `ALIGNMENT_PROGRESS.md`
  - `docs/VERIFICATION_GUIDE.md`

> 重要提醒：  
> `heritage.rs` 对应的是 Rugra 当前 SSA / heritage 相关核心层之一。  
> 结构存在不等于生产接线正确；修复前不得把 direct 算法单测当作 Ghidra 运行时 1:1 对拍。

## 2026-08-28：load-guard COPY 的销毁语义

`Heritage::propagate_copy_away` 在完成 `total_replace` 后通过
`Funcdata::op_destroy` 删除 COPY，与 Ghidra 12.0.4 `heritage.cc:675-688`
一致。该调用同时断开 Varnode 连接、把操作移到 dead list，并从所属
`BlockBasic` 移除；只设置 `PcodeOp::DEAD` 会让 op bank、基本块和 parent
状态彼此矛盾。完整 Heritage 仍保持 L2，需以锁定 oracle fixture 覆盖该
生命周期及其 GetStr 调用闭包后，才能提升对应函数状态。

---

## 模块定位

`heritage.rs` 是 Rugra 当前反编译主线中，负责 **SSA 构造、变量版本传播、Phi / MULTIEQUAL 放置及其辅助状态管理** 的关键模块。

从整体链路看，它大致处在这样的位置：

```text
raw p-code / injected ops
  -> Funcdata
  -> block / CFG
  -> Heritage
  -> SSA versioning / multiequals
  -> Action / Rule passes
  -> PrintLanguage / PrintC
```

换句话说，`heritage.rs` 主要解决的问题是：

1. 如何在函数级图结构上构造 SSA 形式
2. 如何为值节点分配和传播版本
3. 如何在控制流汇合点插入 `MULTIEQUAL` / Phi 风格节点
4. 如何维护与 SSA 过程相关的辅助索引、优先队列与状态记录

它**不应**被理解为：

- 最终代码生成层
- 最终类型恢复层
- 最终变量命名层
- 与 Ghidra 行为已完成对拍的证明模块

---

## “Heritage” 在当前工程中的含义

“Heritage” 在这里更接近 Ghidra 反编译器语义中的 heritage 过程，核心关注点是：

- 某个存储位置上的值如何随着控制流传播
- 某个 `Varnode` 在不同定义点之间如何形成版本序列
- 汇合控制流下，哪些位置需要插入合流节点
- 后续规则系统和输出层如何依赖这种 SSA 形态

因此，它不是一个抽象的“优化器”，而更像：

> **负责把函数级 IR 变成更适合数据流分析和高层恢复的 SSA 语义骨架的层。**

---

## 当前模块的责任边界

为了避免文档继续失真，下面明确 `heritage.rs` 当前应负责和不应负责的内容。

### 应负责

- 组织 SSA 构造流程
- 跟踪地址空间上的 heritage 状态
- 处理版本传播相关辅助结构
- 决定何时放置 `MULTIEQUAL`
- 进行 SSA rename 相关工作
- 维护与 heritage 过程有关的中间状态

### 不应负责

- 单独证明 SSA 已和 Ghidra 完全一致
- 单独恢复最终源码变量名
- 单独恢复最终高级类型
- 单独负责最终控制流结构化输出
- 把尚未验证的版本分配写成“已保证一致”

---

## 与其他模块的关系

### 与 `Funcdata`
`Funcdata` 是函数级分析上下文。  
`Heritage` 运行在 `Funcdata` 所承载的操作图、值节点和 block 信息之上。

可以把关系理解为：

- `Funcdata`: “函数级总容器
”
- `Heritage`: “在这个容器上进行 SSA 组织与版本传播的过程控制器”

### 与 `Varnode`
`Varnode` 是 SSA 的直接承载体之一。  
版本号、定义/使用关系、空间位置语义，都会在 heritage 过程中被使用和强化。

### 与 `PcodeOp`
`PcodeOp` 是操作节点。  
`MULTIEQUAL` 放置、rename 传播、def-use 组织，都离不开对操作节点的遍历和改写。

### 与 `BlockBasic` / CFG
SSA 不是孤立构造的，它依赖控制流结构。  
因此：

- block 划分
- 前驱后继
- 支配关系
- 合流位置

都会直接影响 heritage 过程。

### 与 `ActionDatabase`
Heritage 通常是后续高层规则与优化动作的前置基础之一。  
如果 SSA 形态不稳定，后续 Action / Rule 的推断和简化效果也会受到影响。

---

## 公开 API 说明

以下内容围绕当前可见公开接口展开，并重点解释它们在“SSA / Heritage 责任链”中的角色。

---

## `pub struct LocationMap`

### 作用
`LocationMap` 用于按地址位置记录与 heritage 过程相关的信息映射。

### 语义
从当前命名和职责来看，它更接近：

> “按 Address 维度记录某类尺寸 / pass / heritage 状态信息的辅助映射结构”

### 为什么需要它
在 SSA / heritage 过程中，经常需要回答类似问题：

- 某个位置之前已经在哪一轮处理过？
- 某个地址对应的 heritage pass 信息是什么？
- 某个存储位置是否已经被纳入当前阶段处理？

`LocationMap` 正是这类“位置级辅助索引”的容器。

### 当前边界
它是 SSA 构造过程中的工具对象，不应被当成最终用户可见语义，也不应写成“高层变量映射”。

---

## `pub struct SizePass`

### 作用
`SizePass` 是与“大小 + pass 信息”相关的辅助记录结构。

### 当前理解
它更适合作为 `LocationMap` 内部所依赖的记录单元，负责描述：

- 某个地址位置相关的大小信息
- heritage 过程中的 pass 状态

### 注意事项
当前文档不应夸大它的角色。  
更保守的表述是：

- 它是 heritage 过程中的辅助状态结构
- 它服务于位置索引和阶段控制
- 它不是最终 SSA 结果对象

---

## `pub fn new() -> Self`
适用于 `LocationMap` / `PriorityQueue` / `HeritageInfo` / `Heritage` 等结构的构造接口时，统一理解为：

- 创建一个空的、尚未承载 heritage 状态的新实例
- 作为后续分析过程的起点
- 不代表该对象一创建就处于“分析已完成”状态

---

## `pub fn add(&mut self, addr: Address, size: i32, pass: i32)`

### 所属
`LocationMap`

### 作用
向位置映射中登记一条与 heritage 相关的位置信息记录。

### 参数
- `addr`: 目标地址
- `size`: 关联尺寸
- `pass`: 关联处理轮次

### 语义
该接口更适合被理解为：

> “把某个地址位置在当前 heritage 流程中的元信息写入位置映射表中”

### 使用价值
这类接口通常有助于：

- 避免重复处理
- 查询某位置的历史处理信息
- 为多轮 heritage / SSA 过程提供追踪依据

---

## `pub fn find_pass(&self, addr: Address) -> i32`

### 所属
`LocationMap`

### 作用
查询某个地址对应的 heritage pass 信息。

### 典型用途
- 判断某个位置此前是否已被处理
- 决定当前阶段是否需要重复进入某个空间或地址位置
- 给调试或日志输出提供处理轮次依据

### 当前边界
返回值有助于控制流程，但不应被误写为“证明某位置 SSA 已正确完成”的最终证据。

---

## `pub fn clear(&mut self)`

### 所属
`LocationMap` / `Heritage`

### 作用
清空当前记录或重置 heritage 状态。

### 语义
这类 `clear()` 应统一理解为：

- 清除当前对象中的 heritage 过程状态
- 便于重新分析、重跑或测试复位
- 不是“回退整个工程状态”的万能接口

### 注意
在 `Heritage` 语境下，`clear()` 更偏向于“重置 heritage 过程内部状态”，而不是删除所有函数级 IR。

---

## `pub struct PriorityQueue`

### 作用
用于 heritage 过程中按优先级组织 block 的辅助队列。

### 语义
这是一个服务于 SSA / heritage 流程的调度结构。  
从命名和公开方法看，它主要用于：

- 插入 block
- 依据深度或优先级组织处理顺序
- 在 heritage 过程中抽取下一待处理块

### 为什么会有它
Heritage 过程往往并不是简单线性扫描，而是要考虑：

- CFG 深度
- 支配关系
- 处理顺序
- 汇合点传播

因此需要优先队列这类结构帮助决定处理顺序。

---

## `pub fn reset(&mut self, maxdepth: usize)`

### 所属
`PriorityQueue`

### 作用
重置优先队列状态，并按给定深度边界重新初始化。

### 适用场景
- 每轮 heritage 前初始化
- 重新构造调度环境
- 在测试中清空并重新配置队列状态

---

## `pub fn insert(&mut self, bl: Arc<RwLock<BlockBasic>>, depth: i32)`

### 所属
`PriorityQueue`

### 作用
把某个基本块按深度信息插入调度队列。

### 参数
- `bl`: 目标基本块
- `depth`: 与处理优先级有关的深度信息

### 设计意义
说明 heritage 并不是“按文件顺序处理块”，而是需要按图结构组织处理顺序。

---

## `pub fn extract(&mut self) -> Option<Arc<RwLock<BlockBasic>>>`

### 所属
`PriorityQueue`

### 作用
从优先队列中取出下一个待处理 block。

### 返回
- `Some(block)`: 取到下一个块
- `None`: 当前队列已空

### 用途
这是 heritage 过程中“驱动下一步处理”的关键接口之一。

---

## `pub fn empty(&self) -> bool`

### 所属
`PriorityQueue`

### 作用
判断队列是否已空。

### 用途
用于控制 heritage 处理循环是否结束。

---

## `pub struct HeritageInfo`

### 作用
表示某个地址空间上的 heritage 状态信息。

### 当前理解
它更适合被解释为：

> “针对单个 AddressSpace 的 heritage/SSA 处理上下文记录”

### 为什么按空间区分
这是很重要的设计点。  
因为不同地址空间上的值传播语义并不完全相同，例如：

- register
- ram
- stack
- unique
- const

在 heritage 过程中，按空间维护状态有助于：

- 避免混淆不同空间上的传播逻辑
- 更细粒度地控制版本化
- 让后续对齐 Ghidra 时更容易保持语义分层

---

## `pub fn new(space: AddressSpace) -> Self`

### 所属
`HeritageInfo`

### 作用
为指定地址空间创建一份 heritage 状态记录。

### 参数
- `space`: 目标地址空间

### 设计意义
说明 heritage 过程不是完全“无差别地处理所有值”，而是会显式关注不同空间的传播上下文。

---

## `pub struct LoadGuard`

### 作用
用于处理 `LOAD` / `STORE` 相关保护状态的辅助记录。

### 当前理解
它更适合作为：

- SSA / heritage 过程中处理内存相关操作的保护/跟踪结构
- 防止某些加载与存储语义在分析过程中被错误折叠或重复传播的辅助机制

### 文档边界
当前不应把它写成完整内存模型，只应描述为：

- 与内存读写保护有关的辅助记录
- 服务于 heritage 过程中的特殊场景

---

## `pub struct Heritage`

### 作用
这是 `heritage.rs` 中的主控制对象，负责组织 SSA / heritage 的整体过程。

### 当前定位
`Heritage` 更适合被理解为：

> “在单函数上下文上执行 SSA 组织、合流节点放置和 rename 的过程控制器”

### 典型职责
从当前公开接口来看，它至少会承担：

- 启动 heritage 主流程
- 放置 `MULTIEQUAL`
- 执行 rename
- 提供更直接、避免额外锁冲突的
变体接口
- 维护内部 pass 状态

### 当前不要夸大的地方
`Heritage` 的存在和接口完整度，不能直接推出：

- SSA 与 Ghidra 已行为一致
- 所有边界控制流已验证通过
- 所有 Phi 放置策略都已完成运行时对拍

它说明的是：**架构上已经明确把 SSA / heritage 当成正式主线能力来建设**。

---

## `pub fn heritage(&mut self, fd: &mut Funcdata)`

### 作用
执行一个规范 heritage 单 pass（对齐 `Heritage::heritage`，
heritage.cc:2663-2758）。

### 语义（HERITAGE-OWNERSHIP-0001 重写）
签名从无参（内部 `Weak<RwLock<Funcdata>>` 升级取锁）改为显式
`&mut Funcdata`。单 pass 序列 1:1 对应锁定 oracle：

1. `maxdepth == -1` 时重建增广支配树（cc:2676-2677；Rugra 先
   `build_dom_tree` 再 `build_adt`，对齐上游 structureReset）；
2. `process_joins`（cc:2679）；
3. pass 0：同一个局部 `PreferSplitManager` init+split（cc:2680-2683）；
4. per-space 循环（cc:2684-2748）：delay 门控、
   `clear_stack_placeholders`、有序 Varnode 扫描喂持久
   `globaldisjoint` + 本 pass `disjoint`（prev 0/1/2 分类、
   warning 分支）；`discoverIndexedStackPointers` 为已登记缺口
   （HERITAGE-CALLGUARD-0001），故 `reprocessFreeStores` 不触发；
5. `place_multiequals(fd)`（cc:2749）；
6. `rename(fd)`（cc:2750，末尾 `disjoint.clear()` 对齐 cc:2592）；
7. `analyze_new_load_guards` + `handle_new_load_copies(fd)`
   （cc:2753-2754）；
8. pass 0：同一个 manager 上 `split_additional`（cc:2755-2756）；
9. `pass += 1` 恰好一次（cc:2757）。

与 oracle 一致：**不** 内部构建 infolist（`buildInfoList` 属于
`startProcessing`，funcdata.cc:166），也**不**运行 DeadCode /
不设 `pass >= 2` 早退 —— 重复调度属于 Action 执行器。

### 持久状态
`Heritage` 对象跨 pass 持久：`pass`、`maxdepth`、`globaldisjoint`、
per-space `HeritageInfo`（delay/deadcodedelay/loadGuardSearch/
hasCallPlaceholders）、load/store guards。`Funcdata::op_heritage`
用 `mem::take` 暂移整个对象、跑完一个 pass、原样回写，持久状态因此
跨调用保留且无锁路径。

### 构造与清零
`Heritage::new` / `Heritage::clear` 均置 `maxdepth = -1`
（heritage.cc:218-224 / 2882），这是首次 pass 重建 ADT 的哨兵。

---

## `pub fn build_adt(&mut self, fd: &Funcdata)`

### 作用
构建增广支配树（对齐 `Heritage::buildADT`，heritage.cc:2316-2385）。

### 语义（HERITAGE-OWNERSHIP-0001 重写）
显式 `&Funcdata`（只读），不再升级 `Weak`。步骤逐行对齐：
domchild 由 `immed_dom` 按列表序组装（无 idom 的块进 `size` 死桶，
block.cc:2036-2051）；`buildDomDepth` 根深度 1、子 = 父+1、尾部哨兵
`depth[size]=0`（block.cc:2056-2075）；up-edge 判定 `u != immed_dom(v)`
（指针同一性 → 块索引）；bottom-up a[]/z[] 与 boundary 标记、
`z[0] = -1`、top-down 传播、`k = z[k]` 的 augment 构造。

---

## `pub fn place_multiequals(&mut self, fd: &mut Funcdata)`

### 作用
按锁定 oracle `Heritage::placeMultiequals`（heritage.cc:2599-2645）逐段
消费当前 `disjoint` TaskList：每段 `collect` 分类 NEW/OLD（cc:2609）、
`size > 4 && max < size` 时走 `refinement` 细分并重 collect 第一片
（cc:2610-2616）、无读且无写/输入或内部空间/旧段跳过（cc:2619-2625）、
`removeRevisitedMarkers`（cc:2626-2627）、`guard_input`（cc:2628）、
`guard`（cc:2629，addIndirects 取 `new_addresses()`）、`calc_multiequals`
吃 collect 的 write varnode 列表（cc:2630/2439），随后对 `merge` 里每个
块用 `Funcdata::new_op(sizeIn, block.start)` + `create_def_with_space` 输出
（active-heritage）+ 每 slot 一个 fresh free 输入 + `op_insert_begin` 落在
块首（cc:2631-2642）。

### 语义
2026-08-15（HERITAGE-ADT-RENAME-0001）起该函数不再以
`(space, address)` 分组整个 bank，改按 TaskList 顺序消费；四个输出向量在
循环外声明、由每次 `collect` 清空复用（cc:2603-2609）；`MemRange` 的
`clear_property(new_addresses)` 突变经 clone/写回镜像 cc:334 的就地突变。
块首插入序即创建序的倒序（MULTIEQUAL 的 opInsertBegin 落 index 0），
`tests/oracle/heritage_adt_rename_1204` 三案例（diamond/oldmark/two-join
`seq=6,3`）对锁定 oracle 逐字节 MATCH。

### 残差（如实登记）
- `collect` 现为探针驱动的 loc_tree 活窗口（本空间限定；历史全 bank 偏移扫描已废），
  跨空间偏移碰撞会误分类——`HERITAGE-DRIVER-SWITCH-0001` 硬前置。
- 2026-08-17（HERITAGE-COLLECT-WRAPAROUND-0001）起 collect 已镜像 oracle 的
  endaddr 回绕钳位（heritage.cc:317-320）：`endaddr = wrapOffset(addr+size)` 落到
  start 之下时，窗口终点不用 beginLoc(endaddr)（会立刻截断成空窗口），而是钳到
  `endLoc(space, getHighest())` —— 从 start 扫到本空间末尾（首个异空间成员终止，
  无偏移上界）。Rugra 空间均为 8 字节寻址（`space_highest` 约定），u64 wrapping add
  即 oracle 算术。生产可达性：仅当 MemRange 跨越空间顶端（offset 0xffffffffffffffff
  且 size>1 的 varnode 进入 disjoint cover）触发，真实 loader 不产出 —— 预存非 r2
  引入。单点 fixture `tests/oracle/heritage_collect_wraparound_1204` 三案例（回绕
  跨顶 SUBPIECE 链接 / 同形非回绕对照 / 回绕恰顶字节直连）与锁定 oracle 逐字节
  MATCH；去掉钳位后 fixture 的 free_with_reader 断言即失败（判别力实证）。
- refinement/guardInput concat/removeRevisitedMarkers 已按 oracle 调用
  形状接线，但 fixture 未触发（UNTESTED）。

---

## `pub fn place_multiequals_direct(`

### 作用
以更直接的方式插入 `MULTIEQUAL`，并显式传入所需 bank 引用。

### 设计意义
从接口命名和描述看，它的意义主要在于：

- 避免额外锁层级带来的冲突
- 让 heritage 过程在共享对象图上更稳定地操作
- 适配当前工程使用共享读写容器的架构方式

### 确定性（RUN-NONDETERM 最小修，2026-08-15）
dominance frontier 是 `HashSet<i32>`（std SipHash 每进程随机种子）；
直接迭代会使 MULTIEQUAL 创建序逐进程随机 → 输出漂移。迭代前先
`sort_unstable()` 按块索引定序（/tmp 因果验证 20/20 全语料字节一致）。
canonical 路径不走 dom_frontier——merge 块由深度序 PriorityQueue +
有序 augment 推导（calcMultiequals cc:2448-2463 / visitIncr cc:2394-2428，
非块索引序，`seq=6,3` witness 可区分）；生产切换归
`HERITAGE-DRIVER-SWITCH-0001`。

---

## `pub fn rename(&mut self)`

###
 作用
执行 SSA rename。

### 语义
2026-08-15（HERITAGE-ADT-RENAME-0001）起该函数是
`Heritage::rename`（heritage.cc:2587-2593）的忠实移植入口：新建
VariableStack，**仅从 block 0** 起调 `rename_recurse`，随后
`disjoint.clear()`。`rename_recurse`（cc:2479-2562，迭代化
Enter/Leave 工作栈镜像"先子树后弹栈"的递归序）逐块：

- 单趟按执行序遍历 op（cc:2489）——MULTIEQUAL 只跳过读替换内层
  循环（cc:2491），其输出仍在**自身 op 位置**走公共写压栈尾
  （cc:2523-2529），不再有独立的 phi 预处理趟；
- 读槽升序（cc:2493）：heritage-known 跳过（cc:2495）、非 active
  free 跳过且不清标（cc:2496）、消费时清 active（cc:2497）、空栈
  input 提升（cc:2499-2502）、INDIRECT same-time 深栈
  （cc:2507-2516）、经 `Funcdata::op_set_input` 替换（cc:2518）、
  consumed free 删除（cc:2519-2520）；
- 后继循环（cc:2531-2552）：出边升序、精确 reverse slot、只扫后继
  **前导** MULTIEQUAL 组（cc:2536 break）；phi 输入只查
  `isHeritageKnown`（cc:2538——phi 环上已写的 loop-carried 输入保持
  原样，即 old-marker skip），无 active 检查/清除；
- domchild 序递归、writelist 按遇到序在全部子树后弹（cc:2553-2561）。

`tests/oracle/heritage_adt_rename_1204` 三案例（含 oldmark 环）对该路径
逐字节 MATCH。生产 direct 路径的差异（全入口块、预置 input 栈、
v_type 拷贝、宽泛 active 标记）仍留在 `rename_direct`，切换归
`HERITAGE-DRIVER-SWITCH-0001`。

---

## `pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph)`

### 作用
以更直接的方式执行 rename，并显式使用 bank 与 block graph。

### 设计意义
这通常意味着：

- 当前实现中已有更强调工程稳定性的 rename 路径
- 共享对象图上的锁和引用关系是实际问题
- heritage 模块已经不只是概念实现，而是开始面向实际执行问题做接口分化

### 使用价值
相比间接依赖上下文，这类接口更利于：

- 测试
- 避免死锁
- 控制底层 bank 访问顺序
- 与当前图模型更紧密集成

### 2026-07-05 对齐修正（visit_rename_direct 三个 load-bearing 语义）

`visit_rename_direct` 此前声称对齐 Ghidra `renameRecurse`（heritage.cc:2479-2562），但漏掉了 3 个决定性语义：

1. **empty-stack input promotion**（cc:2499-2502 / cc:2540-2543）—— 当 varstack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为函数输入。Rugra 此前静默跳过 → 自由读未被替换 → SSA 不完整。现移植：通过 `VarnodeBank::set_input_varnode`（对齐 `Funcdata::setInputVarnode` cc:340-373）。

2. **INDIRECT same-time stack-deepening**（cc:2507-2516）—— 当栈顶 vnnew 是 INDIRECT 写且其 iop-const input(1) 指向当前 op 时，Ghidra 认为 "INDIRECT 和它的 op 同时发生"，深入栈一层（`stack[size-2]`）。Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 拿到错误的 SSA 名。现已按 cc:2508 比对 iop 偏移与当前 op 指针。

3. **deleteVarnode of consumed frees**（cc:2519-2520 / cc:2548-2549）—— 替换后若 `vnin->hasNoDescend()` 则 `fd->deleteVarnode(vnin)`。Rugra 此前从不删除 → 死 varnode 留在 loc_tree 污染后续 pass。现由该 exact guard 调 `VarnodeBank::destroy_varnode_prevalidated`；debug build 重新断言 no-def/no-descendant 与 bank ownership，public integrated 错误没有被吞掉。

2026-08-13 `VARNODE-INIT-0001` caller closure：生产 direct 路径的 `insert_multiequal_direct` 为 fresh bank-owned 输出调用 `set_def_prevalidated`，并把 xref 返回的 canonical Arc 写入 MULTIEQUAL output；每个 fresh placeholder 也像 locked `heritage.cc:2638-2639` 的 `opSetInput` 一样建立一条 descendant。`renameRecurse` 的普通 op 与 successor MULTIEQUAL 两条替换路径都先从旧 Varnode 精确擦除一个 descendant，再向 canonical 新值添加一条，并保留 same-Arc early return；删除仅发生在 locked `heritage.cc:2519/2548 hasNoDescend()` 守卫内。Rust graph tests 覆盖普通 free replacement 后旧值退 bank、两 predecessor 的 phi placeholder 逐槽退 bank，以及 same-Arc 不增边/不删除；这些是 Rust-only 生命周期回归，不是同输入 Ghidra 差分，故 `visit_rename_direct` caller graph 仍为 `UNTESTED`，Heritage 整体仍无逐函数 oracle。低层 erase/add/slot 迁移另由 Varnode/combine oracle 覆盖。legacy `place_multiequals` 尚未统一到这条 setDef 路径，仍归 `HERITAGE-OWNERSHIP-0001`/后续 driver 闭包。该原子只修所触及 direct 路径的引用/输出身份和 destroy 先验，不提升 Heritage 模块整体级别。

同时修正 `rename_direct` 开头的 marker：原来只对 `!is_heritage_known()` 的 varnode 设 `activeHeritage`（即只标 free，跳过 written），但 Ghidra `guard()`（cc:1174/1181）对 **read+write** 两个 list 都设。written varnode 漏标导致 rename 的 `if (!vnout->isActiveHeritage()) continue;`（cc:2526）跳过 push → stack 空 → empty-stack promotion 触发 → set_input_varnode 把多分支 input 去重成同一个 → diamond merge 丢失分支独立性。现按 Ghidra 语义对非常量/非 annotation 的所有 varnode（含 written）设 activeHeritage。

---

## `pub fn get_pass(&self) -> i32`

### 作用
返回当前 heritage 过程的 pass 信息。

### 用途
可用于：

- 调试
- 日志输出
- 判断 heritage 推进轮次
- 分析阶段状态检查

### 边界
pass 计数只代表处理轮次，不等于质量保证。

---

## 常量标志位

### `pub const BOUNDARY_NODE: u32 = 1 << 0`
表示边界节点相关标志。

### `pub const MARK_NODE: u32 = 1 << 1`
表示标记节点相关状态。

### `pub const MERGED_NODE: u32 = 1 << 2`
表示已合并节点相关状态。

### 当前理解
这些常量说明 heritage 过程中还需要对节点做状态分类，例如：

- 是否是边界引入节点
- 是否已被 heritage 标记
- 是否已经参与合并过程

这再次说明 heritage 过程不是简单一次遍历，而是一个带有中间状态管理的多阶段处理过程。

---

## `pub struct StackNode`

### 作用
表示 SSA rename 栈中的节点。

### 语义
在 SSA rename 中，通常需要维护某种“当前定义栈”或“版本栈”来跟踪不同路径下的值版本。  
`StackNode` 就是服务于这种过程的辅助结构。

### 当前应如何理解
把它理解为：

- rename 过程中的内部工作单元
- 服务于版本传播和回溯
- 为递归或图遍历中的 SSA 状态跟踪提供支撑

而不是最终暴露给用户的高层数据结构。

---

## 当前应如何看待 `heritage.rs`

如果你正在理解当前 Rugra 主线，可以把 `heritage.rs` 概括为：

> **负责把函数级 IR 推进到更稳定 SSA 形态的核心模块。**

它的重要性体现在：

- 是后续 Action / Rule 的基础
- 是变量恢复和高层语义整理的重要前提
- 是对齐 Ghidra 时必须重点关注的行为层模块之一

但它当前的存在**不应被直接夸大为**：

- SSA 质量已成熟
- SSA 与 Ghidra 已完成运行时一致
- Heritage 全路径已被实证验证

---

## 推荐联动阅读

建议按以下顺序继续理解：

1. `funcdata.md`
2. `varnode.md`
3. `op.md`
4. `block.md`
5. `heritage.md`
6. `action.md`
7. `printlanguage.md`
8. `printc.md`
9. `../data_contract.md`
10. `../../ALIGNMENT_PROGRESS.md`

---

## 维护注意事项

后续维护本文档时，应特别注意以下几点：

### 1. 不要把概念对齐写成行为对齐
即使名称和对象组织对应 Ghidra，也不能直接写成“已完全一致”。

### 2. 不要把 `place_multiequals` / `rename` 的存在写成验证完成
这些接口说明能力方向存在，不等于对拍闭环已完成。

### 3. 如果共享引用模型变化，要同步更新本文
尤其是：
- direct 变体接口
- bank 访问方式
- queue / state 管理方式
- pass 统计方式

### 4. 如果未来加入更明确的测试证据，应同步补到状态文档
但 API 文档本身不替代验证报告。

---

## 一句话总结

`heritage.rs` 是 Rugra 当前 **SSA 构造与 heritage 过程控制** 的核心模块：它负责
组织版本传播、合流节点放置、rename 及相关辅助状态管理，为后续数据流分析、变量恢复和输出层提供更稳定的函数级语义骨架。

## 2026-08-16：HERITAGE-DRIVER-SWITCH-0001 —— 生产路径切 canonical 单 pass + LocationMap 空间键

- **`ActionHeritage::apply` 切换**（coreaction.rs，逐字对齐 coreaction.hh:289）：`{ fd.op_heritage(); Ok(0) }`。删除 pass>=2 guard、global_struct_ptrs v_type 预戳、direct 双 pass、内嵌 ActionDeadCode 夹层与 discover_and_guard_stack_stores_fd 调用。收敛性验证：curl 124/124 processed、`multiple descendants` WARN 351（=HEAD 基线，FLAGFREE 审计的 44 在 HEAD 不可复现，两态均为 351）、"not settling" 5（=基线，type-propagation 家族）、3× 输出 sha 一致。
- **LocationMap 空间键**（heritage.hh:48 `map<Address,SizePass>`，Address 含 space；`Address::overlap` 跨空间恒 -1）：`themap` 键从裸 offset 改为 `(AddressSpace, Address)`，`add/find_pass/entry_containing` 只在本空间子区间找候选——跨空间同 offset 碰撞不再误分类 NEW/OLD（126b56f 复核硬前置）。新增看门狗测试 `test_location_map_cross_space_keys_are_disjoint`。
- **normalize_read_size 修复**（heritage.cc:382-401）：此前直接 `newop.output = Some(vn)` 绕过 `Funcdata::op_set_output`，被归一的 varnode `def` 从未置位、永远 FREE，驱动器每 pass 重新归一、每 pass 新建 SUBPIECE——canonical 切换后实测 main 800+ mainloop 迭代/WARN 21630 的 ping-pong 根因。现走 `op_set_output`（装 def + def_tree）+ cc:398 `set_write_mask`（驱动器 cc:2706 跳过）。
- **collect 活窗口（复核 M1 修正，2026-08-16 r2；heritage.cc:323-325）**：collect 每 range 用合成探针 varnode（size 0，同 offset 排最前）构造 `loc_tree.range(probe..)`——字面 beginLoc(addr) 语义的**活迭代器**，只走本空间窗口成员（O(log V + hits)），兼修跨空间同 offset 误收。**活性是承载语义的**：refinement（cc:1902-1906）在本 placeMultiequals 行进中创建 pieces，oracle 的 cc:2615 re-collect 与后续各 piece 的 collect 都必须看到；早先的入口冻结快照实现把 pieces 对整个 pass 隐藏、下一 pass 该范围已成 OLD（addIndirects=false）→ INDIRECT 永不补建（x86-64 部分寄存器写高频触发 `size>4 && max<size`）。fixture case E（switch_refinement_recollect）锁定：冻结实现下该 case `free_with_reader=0` 断言失败（判别力实证），live 实现下与 oracle 逐字节一致（`phi.PIECE(R54:4:I,R50:4:W+INT_SUB)`）。
- **direct 族移出生产路径**：`place_multiequals_direct`/`rename_direct`/`insert_multiequal_direct`/`run_heritage_direct` 仅剩 example 侧 throwaway-Funcdata 参数估计与 crate 内测试调用；无调用者的 `insert_multiequal`（fd 适配壳）删除。`insert_multiequal_direct` 的 phi 尺寸回退（`.unwrap_or(4)`）随之不再有生产可达路径。
- **E2E 残差**（如实登记，绑定后继）：(1) 生产 callspec 无 model（FUNCPROTO-MODEL-BIND-0001/CSPEC-TEXT-INGEST-0001）→ `FuncCallSpecs::has_effect` 恒 UnknownEffect（fspec.rs 保守分支）→ canonical guardCalls 每 call×range 建 INDIRECT（main pass 0 = 13,462 INDIRECT + 4,098 phi，ops 674→22,186、vns 8K→68K）；(2) varnode bank descend 列表 O(n) `has_no_descend`（Weak upgrade 逐元素）× 共享 free varnode → pass 0 rename 30s。两因叠加 8 函数超 example 的 10s worker 预算（decompiled 76→68），skeleton diff 于 11 个文本变化函数 +1..+277（defects=0 不变）。

## 2026-06-29：discover_and_guard_stack_stores_fd（heritage.cc:985 + 1539）

- 新增 `Heritage::discover_and_guard_stack_stores_fd(fd: &mut Funcdata)`——对齐 Ghidra 的 `discoverIndexedStackPointers` + `guardStores`。从 RSP input 前向 descend 追踪 INT_ADD/INT_SUB/COPY 链，对到达的 STORE 算 stack offset，调 `new_indirect_op` 建 Stack 空间 INDIRECT。（2026-08-16 起移出生产路径，仅 reprocess_free_stores 近似与测试调用。）
- 前置依赖：varnode 去重（find_or_create_input_space）修复 descend 碎片化后，RSP input 有 64 个 descendants。
- 当前局限：written varnode（如 INT_ADD output）未去重，BFS 从 RSP 到 INT_ADD output 后，output 的 descend 不含 STORE（STORE 用独立副本）——待 inject_raw_ops 连接 op 图修复。

### 2026-06-29（续）：rename isHeritageKnown 检查 + 两 pass heritage

- **rename 跳过 heritage-known varnode**（对齐 heritage.cc:2495 `isHeritageKnown`）：input 重写只替换 free varnode（非 input/written/constant），跳过已 SSA 解析的。此前 Rugra rename 无条件替换所有 input，会错误 re-rename。这是 written varnode dedup 的前提。
- **两 pass heritage**：ActionHeritage::apply 跑两遍 place+rename。Pass 1 连接 op 图（rename 重写 STORE input 引用 INT_ADD output），Pass 2 的 discover 在连接后的图上发现 stack STOREs。对齐 Ghidra 多 pass heritage。
- **varnode 去重仍限 free/input**：written varnode 去重需要 loc_tree 排序按 input/written/free 分类（VarnodeCompareLocDef），是更深的重构。
- **VarnodeCompareLocDef 排序已对齐**（2026-06-29 续）：loc_tree 排序键改为 `(address_space, loc, size, input/written/free, def SeqNum or createIndex)`，对齐 Ghidra VarnodeCompareLocDef（varnode.cc:34-52）。input 同位置返回 Equal；written 按 def SeqNum 区分；free 按 createIndex 区分。
- **INSERT/activeHeritage flag 对齐**（2026-06-29 续 2）：rename 使用 `is_heritage_known()`（检查 INSERT flag，对齐 varnode.hh:298）+ `is_active_heritage()`（addl_flags，对齐 varnode.hh:115）。rename_direct 对所有 free varnode 设 activeHeritage（对齐 guard heritage.cc:1174/1181）。create 不设 INSERT（对齐 varnode.cc:1250）；set_def/set_input 设 INSERT（对齐 createDef/makeInput→xref）。
### 2026-07-01：LoadGuard methods + Heritage get_store/load_guard
- `LoadGuard::is_guarded(space, offset)`（heritage.cc:818-826）— 范围检查 space+minimum/maximum。
- `LoadGuard::get_minimum/get_maximum/get_op`（heritage.hh:164-165/161）。
- `Heritage::get_store_guard(op)/get_load_guard(op)`（heritage.hh:337-338）— 线性扫描 guard Vec。

### 2026-07-01（续）：LoadGuard/StoreGuard 填充逻辑
guard_stores（heritage.cc:1538+927）：扫描 spacebase-marked stack STORE，创建 StoreGuard 记录，去重。
guard_loads（heritage.cc:1570+910）：同理 LOAD，含 stale-record 清理。
guard_calls/guard_returns：stub（需 FuncCallSpecs effect characterization）。
guard_all：调用全部 4 个阶段。
establish_range/finalize_range：~~stub~~ **2026-09-23（GETPARAM-OPPOOL-COUNT-0001）改为
faithful 全量移植**（heritage.cc:740-785 / 787-813，接收 `&rangeutil::ValueSetRead`；
含 cc:746-781 的 empty/full/leftStable/rightStable 分支与 cc:774-784 的 uintb 回绕
clamp——Ram 全空间时 maxSize 回绕 0 → 窗口回到 highest，与 C++ 无符号语义一致）。
`analyze_new_load_guards(fd)`（heritage.cc:834-900）同样从 stub 换成真接线：
尾随 state==0 守卫收集（loads 先于 stores）、`find_spacebase_input(Stack)`、
`ValueSetSolver::establish_value_sets(sinks,reads,stackReg,false)` + `solve(10000,
WidenerNone)` + establish、任一 state==0 时 `WidenerFull` 重解 + finalize。
2026-09-23（RANGEUTIL-CONSTGEN-0001）：求解器约束生成族已全量（见
docs/api/rangeutil.md），本方法头部的"Known residual: constraint machinery
still stubbed"注释同步移除——约束只会收窄守卫窗口，finalize 爆窗残差由此
路径解决。
`find_address_forces` 补上 cc:637 `vn->isAddrForce() continue` 停走守卫（此前只
有注释没有检查）。
LoadGuard::set/new_unanalyzed/Default/space_highest。测试更新：`test_load_guard_
range_establish_finalize`（empty-range 臂语义）。

> 残差（登记 RANGEUTIL-VSEMPTY-0001）：`rangeutil.rs` 的 ValueSetSolver 虽有
> establish/solve 骨架，但对 getparameter 的全部 guard sinks 返回 `empty=true`
> 的 ValueSetRead（系统未填充或迭代不传播），因此 load 守卫停留在 establish
> 的 `[pointerBase, highest]` 窗口（state=1），oracle 则以约束收敛到
> `[fb08..ffa7]` 类窄区间（state=2）。后果：`handle_new_load_copies` 对
> `stack:fc40` 误设 ADDRFORCE → `RulePropagateCopy` marker 守卫
> (ruleaction.cc:3948) 拒绝 op 0x3f52:1a6e → getparameter oppool1 ord 65
> 计数残差 -2（740 vs 738）。修复需 rangeutil 求解器实跑（约束机制 +
> establish_value_sets 填充调试），另行立项。

### 2026-07-01（续 2）：block-not-found 优雅降级
place_multiequal_direct 的 block 查找从 .expect 改为优雅 return。

### 2026-07-01（续 3）：visit_rename 迭代化（消除递归栈深度）
visit_rename_impl 从递归改为迭代式（显式 work stack + Enter/Leave 状态）。work stack 有 100000 上限防循环。消除 dominator-tree 递归深度。但 mainloop repeatapply 仍栈溢出（即使 cap=1+迭代 Heritage），根因待进一步调查。
<!-- annotation-pass: 2026-07-04 -->

### 2026-08-11：ANN-F provenance 分类（无行为变更）

`guard_calls_range_with_space` 不是 Ghidra 的独立 overload。锁定 oracle 只有
`Heritage::guardCalls(uint4, const Address &, int4, vector<Varnode *> &)`
(`heritage.cc:1443-1527`)，其中 address-space 身份由 `Address` 自身携带。Rugra
当前 `Address` 只有数值 offset，因此该 helper 额外传递 `AddressSpace`，属于
临时参数适配层；由 `ADDRESS-0001` / `HERITAGE-0001` 跟踪并在 space-aware
`Address` 与 canonical Heritage 接线完成后移除。本轮只补 `RUGRA-GLUE`
provenance，不改变 guard 行为或对齐状态。
 

### 2026-07-05: HeritageInfo + dead-code 时序对齐 Ghidra cc:180/2793/2843
- `HeritageInfo::new` 全字段对齐:delay/deadcodedelay 从 `AddressSpace::get_delay()` 读（2026-08-25 MAINDIFF-UNIQLEAK-0001 起：ram=1/stack=2/unique=register=0，锁定 x86-64 oracle .sla + architecture.cc:566 合成值；此前 Stack=1/其他=0 是错误硬编码）;deadremoved=0(was -1);loadGuardSearch=false(was true,反义);hasCallPlaceholders=is_stack。
- `AddressSpace::get_delay/get_deadcode_delay/is_heritaged` 新增(space.hh)。
- `Heritage::build_info_list`(cc:2664)/`get_info`(hh:257)新增。
- `num_heritage_passes`(cc:2793): `pass - delay` (was `pass`)。
- `dead_removal_allowed`(cc:2843): `pass > deadcodedelay` (was const true)。
- `seen_dead_code`(cc:2805): 设 deadremoved=1 (was no-op)。
- `set/get_dead_code_delay`(cc:2829/2817): 读写 infolist (was no-op/const 2)。

### 2026-08-15: HERITAGE-CALLGUARD-0001 — 规范 guardCalls + 驱动器接线

- `Heritage::guard_calls(fd, fl, space, addr, size, write)`（heritage.cc:1443-1527）
  1:1 移植：callspec 顺序循环、assignment 跳过（cc:1453-1456）、Stack spacebase
  偏移翻译（cc:1457-1466，`OFFSET_UNKNOWN` → `tryregister=false`）、
  `has_effect` 查询、output-active/stack-output-lock 双分支（cc:1469-1494，
  autoKilledByCall 升级 + `try_output_overlap_guard`/`try_output_stack_guard`）、
  input-active 双分支（cc:1495-1509，contains_justified 注册 trial 并
  `op_insert_input`、contained_by → `guard_call_overlapping_input`）、三态
  INDIRECT 创建（unknown/return_address → `new_indirect_op` + holdind/return
  标志；killedbycall → `new_indirect_creation_in_space`）。旧的
  `guard_calls_range`/`guard_calls_range_with_space` stub（按指令地址找 call、
  丢输出效果、只处理 unknown_effect）已删除。
- `guard_range` 接入 per-space `AddressSpace` 参数（Ghidra 的 `Address` 自带
  space 身份；`ADDRESS-0001` 移除该参数后删除）。`place_multiequals` 按
  `MemRange::new_addresses()` 门控执行 guard fan-out（cc:2608-2629 的
  addIndirects 半边；collect/refinement/guardInput 仍归
  HERITAGE-ADT-RENAME-0001）。`guard_returns` 死 stub 删除（需
  FuncProto::activeoutput，归 PARAM-BIND 家族）。
- `MemRange`/`TaskList::add` 增加 `space` 字段/参数（Ghidra MemRange 的
  space-carrying Address 的显式镜像）。
- `guard_call_overlapping_input`/`try_output_overlap_guard`/`guard_output_overlap`/
  `try_output_stack_guard` 改为 per-callspec 签名（fc + caller/callee 双地址），
  `guard_output_overlap` 用 `new_indirect_creation_in_space`（cc:1253 真正用
  creation 而非 indirect op）。
- `guard_call_overlapping_input` 的 truncate_amount（cc:1221
  `addr.justifiedContain(size, truncAddr, vData.size, false)`，
  2026-08-24 FSPEC-JUSTIFIED-ENDIAN-0002）：`justified_contain_range` 增加第 6
  参空间端序后，此调用点传 heritage 空间 `space.is_big_endian()`——LE 空间
  forceleft=false 返回 start 距离 `truncAddr - addr`（address.cc:141），SUBPIECE
  常量不再误取 BE 的 end 距离。双侧投影见
  `tests/oracle/fspec_endian_resolver_1204`（truncate_subpiece case）。
- `guard_stores_range`/`guard_loads_range` 忠实化：STORE 空间匹配（range space
  或其 container + usesSpacebasePtr，cc:1551-1552）、`indirect_store` flag 由
  调用方传入、fl/addrtied 早退（cc:1576）。
- `reprocess_free_stores`（cc:1111-1141）：改为 `previous_op_in_block` 反向
  遍历 + `get_op_from_const` IOP 别名校验 + `op_clear_spacebase_ptr` +
  `op_destroy`（原实现按 bank 顺序收集 prev 列表，非连续组语义）。
- **Bug 修复（本 fixture 发现）**：`LocationMap::add`（heritage.cc:33-71）在
  查询地址与既有 key 精确相等且前一 key 不重叠时，把该 entry 走了 merge
  循环（返回 1=partial）而非 contained 检查（应返回 2）。这使第二趟
  heritage 把已覆盖 range 重新标 NEW，guard 重复创建。修复后
  driver_pass_gating 第二趟 0 新 INDIRECT 与 oracle 一致。
- 锁定 oracle fixture `tests/oracle/heritage_callguard_1204`（7 case 双侧逐
  字节 MATCH，GetStr 形态 2 calls × 10 ranges = 20 INDIRECT 全对象投影）。
- 残差：ScopeLocal queryProperties 的 fl（addrtied → ADDRFORCE）——2026-08-29
  GETPARAM-EMPTYELSE-0001 已补 Ram 空间 global-scope 尾巴（见
  HERITAGE-GUARD-NORMALIZE-0001 节 2026-08-29 补记）；该 fixture 投影中
  `af` 仍双侧省略，未随fixture重钉（fixture 重钉归 heritage owner）；
  reprocessFreeStores 的 discoverIndexedStackPointers 触发链与生产 Action 切换
  **已于 2026-09-23 SB-MATCHURL-ORD55-0001 落地**（discovery 接入 heritage()
  cc:2691-2697 与 reprocess cc:1117）。

### 2026-08-15: HERITAGE-ADT-RENAME-0001 — canonical placeMultiequals/rename 消费 disjoint

- `place_multiequals`（heritage.cc:2599-2645）改为逐段消费 `disjoint`
  TaskList：collect →（>4B 且 max<size 时）refinement → 无读跳过规则
  （cc:2619-2625，含 IPTR_INTERNAL/oldAddresses）→ removeRevisitedMarkers
  → guardInput → guard（`new_addresses()` 门控）→ calcMultiequals →
  块首 MULTIEQUAL 插入。旧的"全 bank (space,address) 分组 + bank 近似插入"
  删除；phi 经 `fd.new_op(sizeIn, block.start)` +
  `create_def_with_space`/`set_varnode_properties`（newVarnodeOut 的
  space-carrying 镜像）+ `op_set_input` + `op_insert_begin` 创建，无条件
  dominator 重建也一并删除（cc:2599 无 buildADT/buildDomTree 调用，
  dominator 状态由 driver 的 maxdepth==-1 分支供给）。
- `calc_multiequals`（cc:2439-2466）签名改为吃 write **varnode** 列表，
  块索引从 `write[i]->def->parent` 派生（cc:2449）。
- `collect`（cc:307-347）改为 MemRange 引用形式：write-mask 跳过
  （cc:326，`Varnode::is_write_mask` 已存在）、marker/return-COPY 旧
  heritage 证据（cc:329）、`clear_property(NEW_ADDRESSES)`（cc:334）。
- 新增 `refinement`（cc:1890-1940）orchestrator：size+1 fencepost、
  边界→分区尺寸转换、`remove13_refinement` 按 cc:1857-1880 重写、
  tasklist 就地 splice + globaldisjoint 逐片 add（原 pass 号）。
- `refine_read/refine_write/refine_input`（cc:1772/1806/1836）重写为
  oracle 调用形状：concatPieces/splitPieces + totalReplace +
  deleteVarnode；refineInput 不再凭空 setFlags(INPUT)（消除
  VARNODE-INPLACE-MUTATION-SITES-0001 登记的 heritage.rs 突变点）。
- `concat_pieces`/`split_pieces` 的 null-insertop 分支对齐 cc:516-519/
  578-581（start block begin + 函数地址，无 entry 标志时如 Ghidra
  getStartNode 抛错路径降级为 stderr 警告）；splitPieces 的 Some 分支
  改为插在写 op **之后**（++insertiter）。
- **机制 C 复核返工（2026-08-16，M1-M5）**：concatPieces/splitPieces 的
  插入改为**元素锚**——cc:516-518/582-587 的 insertiter 是进入循环前捕获的
  固定元素（原首 op X / write 之后的元素 Y），cc:546/602 每片插在该元素
  **之前**，片序=创建序 [P1..Pn,X] / [W,S1..Sn,Y]；首轮交付的固定数值
  索引（每轮 index 0 / write_pos+1）会把组反转成 use-before-def 块内序，
  已由 `adt_refine_order` 案例的 block-order 投影钉死（runner 断言
  `b1=PIECE,PIECE,PIECE,r` 与 `wa,SUBPIECE,SUBPIECE`）。refineRead 非自由
  路径按 cc:1786 改为 panic（保留 "Refining non-free varnode" 原文）。
  二轮复核（M5a/b）修正：warning 文本为 printRaw 原形——`0x` + 按
  2*addrsize 零填充、高位缩短规则（>>32==0→4B / >>48==0→6B）、**无空间名**
  （space.cc:206-221），如 `0x00000070`；removeRevisitedMarkers 的重插位置
  改为**元素锚**——在 opUninsert 之前于移除前列表解析锚（dead/不可解析
  target→INDIRECT 自身后继 cc:268-269；alive target→target 后继
  cc:270-272；MULTIEQUAL→组后首个非 ME cc:275-280），uninsert 后
  `op_insert_before(op, anchor)`、锚为尾时追加——数值索引在移除后列表上
  平移一位且块尾越界 panic（`adt_revisit_positions` 案例钉死
  [a2,S,f2]/[a3,S]/[m2,S,x] 三形态）。附带修复 refine_read 把
  lone_descend 内联进 if-let 条件导致的同线程 RwLock 死锁（读守卫跨块
  存活 × op_set_input 对同一 varnode 取写锁）。
- `rename`/`rename_recurse`（cc:2587-2593/2479-2562）：canonical rename
  不再走 `rename_direct`——block 0 唯一根、单趟 op 序、精确
  `op_set_input`、phi 输入 old-marker skip、无预置 input 栈、无
  v_type 拷贝、无宽泛 active 标记；直接路径保持不变（生产用）。
- RUN-NONDETERM 最小修：`place_multiequals_direct` 的 dom_frontier
  `HashSet` 迭代前 `sort_unstable()`（详见上文该函数小节）。
- 锁定 oracle fixture `tests/oracle/heritage_adt_rename_1204`（3 case
  双侧逐字节 MATCH，含 merge 序 witness `seq=6,3` 与 ownership 波受限
  phi_cycle 案例的完整投影）。残差：collect 全 bank 偏移窗口
  （跨空间碰撞，DRIVER-SWITCH 硬前置）、refinement/guardInput concat/
  removeRevisitedMarkers 分支 UNTESTED。


## 测试区维护（2026-08-17）

`test_op_heritage_leaves_deadcode_to_the_action_executor` 的 harness 修正
（VARNODE-ADDDESCEND-THROW-0001 前置件，最后一个 WARN 源）：原 harness 把同一
free varnode 对象同时交给 b0 的 d1 读与 b1 的 r1 读（free-with-2-readers）。
Ghidra 的 PcodeEmitFd::dump 对每个输入引用独立调 newVarnode（funcdata.cc:905），
同一寄存器两处读=两个分立 free varnode（loc-tree 以 createIndex 区分，
VarnodeCompareLocDef），单对象双读者会触发 addDescend throw（varnode.cc:336）。
修法=分立 per-read free 实例（不走 set_input：保持 free 才能保留 heritage 的
read 工作负载——INPUT 会置 insert 使 isHeritageKnown 跳过该读）；两实例仍在
Register@0x30 同一 loc，collect 按地址窗口照常收作 read，断言（alive 计数差、
pass==3）零变化，生产代码未动。
<!-- annotation-pass: 2026-08-17 -->

## ParamActive 地址空间传递（2026-08-24）

`guard_calls`、`guard_call_overlapping_input` 和
`try_output_overlap_guard` 对 trial 的查询与注册均显式携带当前 heritage
range 的 `AddressSpace`。这对应 Ghidra `transAddr`/`truncAddr` 保留
`AddrSpace *` 的语义，防止不同空间中 offset 相同的 trial 被误判为同一项；
trial 大小、注册时机、callspec 遍历顺序与既有分支均未改变。

## force_restructure（block_domroot_1204，2026-08-19）

**`Heritage::force_restructure`** — `heritage.hh:333`
`void forceRestructure(void) { maxdepth = -1; }` 的一行移植。闭环：
`heritage()` 入口 `maxdepth==-1` → `build_dom_tree + build_adt`
（对应 heritage.cc:2676-2677 增广支配树重建），调用点为
`Funcdata::structure_reset` 尾部（funcdata_block.cc:730）。对齐证据：
block_domroot_1204 权威 runner MATCH + 机制 C 复核 APPROVE（2026-08-19）。

## CALLSPEC-IDENTITY-D0 guard/placeholder owner 接线（2026-08-24）

- callspec 现由 `Arc<RwLock<FuncCallSpecs>>` 稳定拥有；active-input/output trial
  查询在 read guard 内产生布尔快照，注册则使用独立 write guard，不把内部引用
  带出锁域，也不改变既有 callspec 顺序、trial 大小或注册时机。
- `clear_stack_placeholders` 克隆的是 owner `Arc` 列表，而不是把 qlst 按值
  `take` 出再放回。每个 callspec 通过自身的 exact op `Weak` 找 CALL/CALLIND，
  随后在同一 owner 上执行 `abort_spacebase_relative`；相同指令地址的两个 op
  不会互相冒充，且操作期间 qlst/annotation 的身份保持稳定。
- 这是 D0 所有权适配，不批准 Heritage 其余分支。总体仍为 `MISMATCH`：
  `AddressSpace::Iop` 暂代专用 `IPTR_FSPEC`
  （`TYPEOP-FSPEC-SPACE-0001`），TypeOp getter、PrintC、StringManager 与既有
  heritage/callspec 残差均未接通，模块状态不提升。
- `call_op_indirect_effect` 仍未消费已经可用的 exact owner 与
  `has_effect_translate`：CALL/CALLIND 继续保守返回 true，CALLOTHER/NEW 也尚未
  恢复 oracle 的 false 分支。源码审计已确认该缺口，但没有同输入双侧 fixture，
  所以证据状态为 `UNTESTED`，绑定 `CALLSPEC-0001`；本 D0 不把它虚升为行为
  `MATCH`，也不在 identity/lifecycle 租约内扩写 Heritage 算法。

## HERITAGE-GUARD-NORMALIZE-0001 — guard/return 归一化切片（2026-08-24）

`Heritage::guard` 的 addIndirects 半边（heritage.cc:1188-1198）与
normalizeWriteSize/callOpIndirectEffect 的 1:1 移植：

- **`guard_query_properties`**（database.cc:1263 `Scope::queryProperties`，
  guard cc:1191 空 usepoint 调用形态）：最小包含符号 → getAllFlags
  （mapped|addrtied(无 usepoint)|typelock|namelock|nolocalalias）；在
  local_range 内 → mapped|addrtied；否则 → Architecture::symboltab 的
  flagbase（persist 等属性带）。残余：Ghidra 的 stackContainer 会继续走到
  父（global）scope，Rugra ScopeLocal 无父链，global 符号不可见（管线内
  stack/register 路径不依赖）；`fd.scope` 为空时属性查询走 arch flagbase。
- **2026-08-29 补（GETPARAM-EMPTYELSE-0001）**：上条"global scope 不可见"
  残差被 oracle 实测证为行为缺口——oracle 的 `Scope::queryProperties`
  （database.cc:1271-1276）对 ram 空间地址经 `Database::mapScope` 落到
  global scope 且 `finalscope != null`，返回 `mapped|addrtied|persist|
  getProperty(addr)`。`guard_query_properties` 新增该 Ram 分支（原走纯
  flagbase 尾），使 `guard_calls` 的 `holdind`（cc:1451 addrtied）为真 →
  每个 guard INDIRECT 输出被 `set_addr_force`（cc:1516-1517）→
  `isAutoLive` → ActionDeadCode 播种（coreaction.cc:3947-3950）consume 整个
  call-guard 格，并经 propagateConsumed 的 marker 分支消费全部全局写。
  缺失该分支时第一个 removal-allowed deadcode pass（pass=2，ram delay=1）
  把 write-only 全局写连同 INDIRECT 格一起删除——语料级症状=
  getparameter 空 else（timecond/condtime 赋值消失）+ 全语料所有
  `::config.X = ...` write-only 赋值丢失。oracle 侧证据=插桩 decomp_opt
  （/tmp/w-nonconverge2-ore）：18 次 deadcode ENTER（pass 1..9 含一次
  restart 归 1），ram:delay=1/1，17620/17628 从非 deletion 候选。
  register/unique 空间仍走 flagbase 尾巴（residual，scope 链未建模）。
- **2026-09-25 补（HERITAGE-FLAGBASE-SPACELESS-0001）**：上一行的"flagbase 尾巴"
  在 SYMDB 门控态被证为跨空间碰撞缺陷——oracle 的 `getProperty(addr)`
  （database.cc:1276/1279 → database.hh:946 `flagbase.getValue`）以**全址**
  （空间+偏移）查 `partmap<Address,uint4>`，而 `Address::operator<`
  （address.hh:375-390）先比空间索引再比偏移，故 RAM 空间的 readonly/volatile
  分区永不覆盖 Register/Unique/Stack 地址（锁定 pspec 零 `<volatile>`，loader
  readonly 均在 RAM——非 ram 查询的 oracle 值恒 0）。Rugra 的 `PartMap` 键是
  legacy **无空间** `Address`（只装过 RAM 域），非 ram 查询只能与 RAM 分区按
  偏移碰撞：门控态 R-only PT_LOAD `[0,0x29000)` 把 Register/Unique/Stack 小偏移
  varnode 标 READONLY → `ActionVarnodeProps` 的 `hasActionProperty` 分支
  （coreaction.cc:1318-1326 `continue`）跳过 NZMask/consume 消除分支 →
  门控 main 丢整条 call 语句（+74 行残差的主导项）。修复：`guard_query_properties`
  臂 (2)（stack in-scope）的属性折算与臂 (4)（非 ram flagbase 尾）均折算为
  oracle 的 0（同 funcdata/ruleaction 消费点的 Ram-only guard 模式）；臂 (3)
  （Ram global tail）的 flagbase 查询保留（.rodata readonly → printc 字符串
  字面量通道）。残差：pspec 若将来装非 RAM flagbase 分区，需先落地空间键
  flagbase。
- **2026-09-27 补（FLAGBASE-CR-F1/F2，comment+debug_assert 级，零行为变化）**：
  臂 (4) 残差补第二条——**开放尾 Ram 属性 range**（pspec/SYMDB range 只带
  `first` 不带 `last`）同样破坏折 0 前提：oracle 解析补
  `last = spc->getHighest()`（address.cc:347-349），`Range::getLastAddrOpen`
  （address.cc:265-275）跨界到顺序下一空间 offset 0（translate.cc:647-665；
  末空间之后返回 `~0` 哨兵基址+offset 0，`isInvalid()` 只查 null 基址
  （address.hh:285-287）不命中，故 database.cc:3229-3234 走 split 分支、
  walk-to-`end()` 无闭合 `else` 保持防御性死分支）——留下非零 Ram 尾分区
  `[X, ram-top]`，唯一闭合 changepoint 落在 Ram 空间之外；Rugra 无空间镜像
  完全丢弃开放形（`decode_hole` 缺 `last` 补 0 退化成 [0,0]；legacy
  `get_last_addr_open = last.next()` 无跨空间/哨兵机制，无空间顶会回卷 0 什么
  也不装），于是臂 (3) 在 Ram 尾上答 0 而 oracle 答属性（非 ram 查询 oracle
  侧仍 0——尾分区在下一空间基址处闭合）。触发条件=pspec 出现开放属性 range。
  另补键形态约定（CR-F2）：无空间键形态是跨文件承重约定，由 database.rs
  `PartMap::debug_assert_spaceless_key_form`（get_value/split 边界，
  debug_assert 级）强制——任一侧单独改 `with_space` 会因 `Address::cmp`
  None 恒排 Some 前而静默错序；ADDRESS-0001 phase-3 合并时两侧必须同迁带
  tag 键。
- **`guard_range`**：fl 改为真实查询（原硬编码 0）；调用顺序
  guardCalls → **guardReturns**（新接入）→ `high_ptr_possible` 门控
  guardStores/guardLoads（cc:1194，原无条件调用）；write 表项由
  `normalize_write_size` 的返回值替换（cc:1180 `*iter = vn =`，原丢弃）。
- **`guard_returns`**（heritage.cc:1652-1692，新移植）：activeoutput 半边 ——
  `characterize_as_output` 分 contained_by（→ guardReturnsOverlapping）、
  其余 containment（registerTrial + 每个 live 非 halt RETURN 追加全范围新
  input，cc:1663-1673）；persist 半边 —— 每个 **live RETURN（含 halt，
  cc:1678-1680 无 halt 检查）** 前插 return-copy COPY（out addrForce+
  activeHeritage，op 带 `PcodeOp::return_copy`，cc:1681-1690）。coreaction
  侧 ANN-F 默认模型输出 seed（coreaction.rs）不在本租约内，待 PARAM-BIND
  家族收敛时统一去重。
- **`guard_returns_overlapping`**（heritage.cc:1609-1638，新移植）：
  `get_biggest_contained_output` → 截断 trial 注册（BE 偏移从高位重算，
  cc:1620-1622）+ 每个 live 非 halt RETURN 前 SUBPIECE(#offset) 截断
  （cc:1628-1636），常量 4 字节（cc:1632）。
- **`normalize_write_size`**（heritage.cc:416-494，完全重写）：most/least
  两片 CALL 分支（`call_op_indirect_effect` 真 → `new_indirect_creation`；
  假 → 全范围 free read 的 SUBPIECE，常量宽度 = `space.addr_size()`）；
  midvn PIECE(vn, leastvn)（BE 输出地址取 vn 原地址，cc:472-475）；bigout
  PIECE(mostvn, midvn)（插在 midvn def 之后，cc:489）；原 vn `set_write_mask`
  （cc:493）；返回 bigout。旧实现的三处结构性错误（不回写替换、PIECE 用
  全范围新建 free varnode 当输入、new_op(3) 元数）全部消除。
- **`call_op_indirect_effect`**（heritage.cc:358-370，极性修复）：
  CALL/CALLIND → `get_call_specs_of_op` exact owner + `has_effect_translate
  != Unaffected`（无 spec → true）；**CALLOTHER/NEW → false**（原恒 true，
  两分支极性均错）。D0 时登记的 `CALLSPEC-0001` UNTESTED 缺口就此闭合并由
  heritage_guard_normalize_1204 双侧 fixture 提供证据。
- RETURN 遍历顺序 = `obank.returnlist` 创建序（Ghidra `beginOp(CPUI_RETURN)`
  的插入序镜像）；halt 判定 = `HALT|BADINSTRUCTION|UNIMPLEMENTED|NORETURN|
  MISSING`（op.hh:171）。
- fixture：`tests/oracle/heritage_guard_normalize_1204.{cc,rs}` +
  `tools/run_heritage_guard_normalize_oracle.sh`（锁定 oracle e40ed130 双侧
  执行、字节级 stdout diff）。covered projections = MATCH（六 case）；
  模块整体仍 MISMATCH：loadGuard COPY 插入、indexed/ValueSet、join、
  removeRevisitedMarkers COPY 形态等未做切片按 TODO 登记（load/join/indexed
  归 HERITAGE-CALLGUARD/PROCESSJOINS 家族）。

### 追记（同 slice，fixture 迭代发现）

- `guard_query_properties` in-scope 分支补 space 比较：Ghidra
  `Scope::inScope` 走 space-carrying `RangeList::inRange`
  （database.hh:597）；缺 space 比较会让数值落在 stack 窗口内的
  register/ram 偏移错误获得 mapped|addrtied。
- 新增 `apply_new_varnode_flags`：`Funcdata::newVarnode`/`newVarnodeOut`
  的属性尾部（queryProperties + `setFlags(vflags & ~typelock)`，
  funcdata_varnode.cc:148-165/104-127），施加于 guard 家族 bank 创建的
  varnode 与 rename 的 input promotion —— persist 属性带（case 3 双侧
  persist1/persist1 字节级一致依赖此尾部）。**R9-F2 限定**："与 oracle
  完全一致"仅覆盖已接线位点；guard 家族仍有欠应用位点：heritage.rs 侧
  两处（guardCalls input-trial vn ↔ cc:1502、normalizeReadSize vn1 ↔
  cc:391）已在本轮补齐；`src/funcdata.rs` 侧两处
  （`new_indirect_op` newin/newout ↔ funcdata_op.cc:689/692、
  `new_indirect_creation_in_space` newout ↔ cc:719）在 funcdata.rs 租约
  外，登记 `FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001`（write-set=
  src/funcdata.rs + docs/api/funcdata.md）由 root 落板。
- **登记的跨模块 MISMATCH（fixture case 2 暴露，本租约外）**：
  `fspec.rs` `justified_contain_range` 的 -1 条件与 Ghidra
  `Address::justifiedContain`（address.cc:131-141：`op2.offset < offset`
  或 query 尾超出 entry 尾 → -1）不一致 —— Rust 仅当"两侧同时越界"才返
  -1，部分重叠被当作 justified。结果是 `characterize_as_param` 对
  range⊃entry 返回 contains 系而非 contained_by，guardReturnsOverlapping
  的 SUBPIECE 截断路径在 Rust 不可达。修复属 fspec.rs 租约
  （FSPEC-JUSTIFIED-CONTAIN，建议 root 登记 TODO）；fixture 双侧逐行
  hash 钉住该差异，修复后翻 MATCH 重钉。（R9 独立复核核实归因成立，并
  指出该极性缺陷还覆盖"低侧外凸+末端对齐/高侧外凸+起点对齐/双侧严格
  包含"三类误判与一处 u64 下溢。）

### R9 复核整改（2026-08-24，附条件 APPROVE 绑定项）

- **R9-F1（BE-aware overlap）**：`normalizeWriteSize`/`normalizeReadSize`
  的 overlap 原为 LE-only 内联投影（`saturating_sub`）；Ghidra
  `Varnode::overlap`（varnode.cc:217-228）endian-aware —— BE 下
  `over = loc.overlap(size-1,…)`，命中时返回 `op2size-1-over`（自最低
  显著侧起算）。本轮：`Varnode::overlap_addr`（src/varnode.rs）补 BE
  分支与既有 -1 哨兵的 BE 路径，heritage 两处 normalize 改为调用它。
  **BE 域整体 UNTESTED**（不只是 pieceaddr 选择：BE 下 overlap 值不同 ⇒
  overlap/mostsigsize 分支触发条件互换、pieceaddr（cc:452）与 SUBPIECE
  常量全部漂移）——fixture 语料保持 LE 域不变式，登记为
  `HERITAGE-BE-OVERLAP`（BE fixture 待后续租约）。d4705ae Evidence 中
  "overlap/mostsigsize 公式逐字镜像 cc:426-427" 的表述由本节修正为
  "LE 投影镜像；BE 经 overlap_addr 的 varnode.cc:221-226 分支"。
- **R9-F2（属性尾欠应用）**：heritage.rs 两处（见上追记）本轮补
  `apply_new_varnode_flags`；funcdata.rs 两处不改（租约外），登记
  `FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001`。8da9295 message 中
  "persist-property ranges propagate exactly as the oracle does" 的表述
  限定为"已接线位点"（见上）。
- **R9-F4（fl 符号分支精度残差，不改代码）**：`guard_query_properties`
  分支 (1) 与 Ghidra `ScopeInternal::findContainer`
  （database.cc:2265-2279）有两处偏差：(i) tie-break 应为**最小 entry
  尺寸**（oldsize 反向遍历、同尺寸先见者胜），现为最小 subsort、同
  (0,0) 取插入序首个；(ii) 空 usepoint 下 use-limited（非 addrtied）
  条目经 `SymbolEntry::inUse`（database.cc:117-118）不可选，现可误选；
  (iii) mapScope 的 namespace 重定向（database.cc:3185-3194）未投影。
  登记 `HERITAGE-GUARD-FLSYMBOL-TIEBREAK-0001`，并入
  `guard_fl_scope_symbol_flags`（varmap 符号租约）后续验收项；该分支
  在符号域交付前保持 UNTESTED。
- **R9-F3（流程）**：TODO_BOARD/ALIGNMENT_ROADMAP 同步由 root 在集成时
  完成（本租约禁改两文件）。

## `pub fn guard_output_overlap_stack`（HERITAGE-GUARD-SUBPIECE-CONST-0001，2026-08-25）

- **Ghidra**: `Heritage::guardOutputOverlapStack`（heritage.cc:1322-1375）。
  栈区间包含 call 返回值存储时，前/后残段经 SUBPIECE+INDIRECT 穿过调用
  并用 PIECE 重组（cc:1331-1351 前段、cc:1352-1372 后段）。
- **SUBPIECE 截断常量（本修复核心）**：
  - 前件 cc:1336 `addr.justifiedContain(size, addr, sizeFront, false)` —
    op2 == addr，containment 平凡成立；`Address::justifiedContain`
    （address.cc:131-141）按**区间空间的端序**路由距离：LE 取 start 距离
    （恒 0），BE 取 end 距离（size - sizeFront）。
  - 后件 cc:1358 `addr.justifiedContain(size, addrBack, sizeBack, false)`，
    addrBack = retAddr + retSize — LE 真值 = **sizeFront + retSize**（不是
    0），BE 真值 = size - sizeFront - retSize - sizeBack = 0。
  - 修复前两处均硬编码 0（后件把前件的 LE 值误复制，LE 下 SUBPIECE 取错
    字节段）；现在两处改调 6 参 `justified_contain_range`（src/fspec.rs），
    端序取 `AddressSpace::Stack.is_big_endian()`（当前全 LE 过渡模型下为
    false，与 cc:138 路由键同源）。
- **同函数修复的另外三处（R13 复核发现 A 的同族预存缺陷，均有 cc 行背书）**：
  1. **cc:1329-1330 自死锁**：`call_op.read()...unwrap_or_else(|| fd.new_varnode_out(...))`
     在读锁存续中对同一 call op 取写锁；call 无输出时（cc:1330 分支）必然
     挂死。改为先绑定 `existing_out` 再分支（该路径此前从未被真实执行）。
  2. **cc:1327/1349-1350/1371 insertPoint 链**：两个 PIECE concat 都应插在
     **游标** insertPoint 之后（前件后游标推进为 concatFront）；旧代码两处
     都插在 call 后，前后段并存时后件 concat 错位到前件 concat 之前。
  3. **cc:1340/1362 opSetOutput 完整接线**：`fd->opSetOutput(subPiece,
     indOp->getIn(0))` 要求 vbank setDef + setVarnodeProperties
     （funcdata_op.cc:70-83）；旧代码裸写 output 字段，SUBPIECE 的输出
     varnode 永不成为 written（INDIRECT 的 in[0] 一直保持 free 读语义）。
- **双侧 fixture**: `tests/oracle/heritage_subpiece_const_1204.{cc,rs}` +
  `tools/run_heritage_subpiece_const_oracle.sh`（pin-base schema2，
  base=3f07f96）。五个触发几何（front+back ×2 含 call 预存输出分支、
  back-only、front-only）驱动真实函数，投影 block 内 op 序、SUBPIECE
  常量、PIECE slot、write 表项；case2 钉 cc:1336/cc:1358 调用形态的
  LE/BE 双路由算术。covered=MATCH（47 行双侧字节一致，
  ghidra_stdout_sha256=rugra_stdout_sha256）；overall=UNTESTED（BE 栈
  空间在过渡枚举模型下不可 stage、guardCalls→tryOutputStackGuard 生产
  入口未驱动、负 sf/sb 生产不可达分支未覆盖）。
- **before 证据**：预修复代码 geom0 即死锁（超时无输出）；仅解锁死锁
  （保留旧常量/旧插入/旧接线）时差异行：back 常量 c4(0) vs oracle
  c4(8/6/4/12)、前后 concat 顺序颠倒、SUBPIECE 输出与 INDIRECT in0
  状态 F vs W。

## `pub fn try_output_stack_guard`（HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS，2026-08-25）

- **Ghidra**: `Heritage::tryOutputStackGuard`（heritage.cc:1391-1430）的
  output-contains 分支（cc:1406-1430）——**第 4 个 justifiedContain 触点**
  （cc:1420，继 guardOutputOverlapStack 的 cc:1336/cc:1358 与 fspec.cc:4344
  的表征读取之后）。
- **分支语义**（到达条件：guardCalls cc:1487 的 isStackOutputLock 门 + 非
  no_containment 表征）：
  - cc:1407-1410：`retAddr = fc->getOutput()->getAddress()`（callee 视角
    存储地址）+ `diff = addr - transAddr`（caller/callee 栈指针差）平移到
    caller 视角；`retSize = fc->getOutput()->getSize()`。
  - cc:1411-1416：call 无输出时 `newVarnodeOut(retSize, retAddr, callOp)`
    并令 vnFinal = outvn。
  - cc:1417-1425：`size < retSize` 时 SUBPIECE 截断输出到守卫区间，
    截断常量 = `retAddr.justifiedContain(retSize, addr, size, false)`——
    容器 = caller 视角返回存储、contained = 守卫区间、forceleft=false，
    address.cc:138-141 按 retAddr 空间端序路由（LE start 距离 / BE end
    距离）。SUBPIECE 插在 call 之后（cc:1424），其输出即 vnFinal。
  - cc:1426-1429：vnFinal 非空才 `setActiveHeritage` + push write；
    cc:1430 恒返回 true（vnFinal 空的 no-op 几何也如此）。
- **Rugra 适配**（FSPEC-OUTPUT-STORAGE-0001 修复后形态，2026-08-25）：
  返回存储不再经参数暂存——函数自身从 call spec 的 proto-store 输出参数
  读取（`FuncCallSpecs::get_output_storage`，即 cc:1407 的
  `fc->getOutput()->getAddress()`；`retSize` = 返回类型 size，即
  `ParameterBasic::getSize()` = `type->getSize()`）。生产路径只在
  isStackOutputLock 门（cc:1487）下到达，而该 flag 仅由
  `ActionFuncLink::funcLinkOutput` 在读到 spacebase 输出存储时置位
  （coreaction.cc:1546-1549），故生产恒有存储；无记录存储的 call spec
  （Ghidra 不可达态）保守返回 false，保持 unknown_effect INDIRECT 守卫
  （永不 under-protect）。读取锁纪律：`existing_out` 先绑定再分支
  （edition 2021 下 match scrutinee 临时值会活过臂体，内联 scrutinee 将在
  `None` 臂内对同一 call op 自死锁——与 guard_output_overlap_stack
  cc:1329 同族坑）。
- **双侧 fixture**: `tests/oracle/heritage_tryoutput_1204.{cc,rs}` +
  `tools/run_heritage_tryoutput_oracle.sh`。四个 case：
  (1) 六个触发几何（justified / unjustified +2 / 远端 +4 / size==retSize
  无 SUBPIECE / 预存输出复用 / 预存输出 no-op 空 write）直接驱动真实函数，
  投影 block 内 op 序、SUBPIECE 常量、输出创建/复用、caller 平移（存储
  0x1000 + diff 0x10 → 0x1010）、write 表项与 {ah} 标志、cc:1430 返回值，
  两侧均以 `set_output_parameter`+`set_output_lock` 安装真实
  proto-store 存储前置态，occ 经生产 `characterize_as_output` 锁定分支
  （fspec.cc:4339-4353）求值——无 staged 元组；(2) cc:1420 调用形态的
  LE/BE 双路由算术（LE 0/2/4/0/0/0，BE 4/2/0/0/4/0）；(3)
  `output_storage_projection`——锁定分支存储读取（characterizeAsOutput +
  getBiggestContainedOutput，fspec.cc:4339-4353/4495-4506）五几何（含
  contained_by 触发 cc:1398 的 16 字节区间）；(4)
  `production_entry_guardcalls`——funcLinkOutput 生产者（stack 存储 →
  setStackOutputLock + 延迟输出 varnode；register 存储 → 立即
  newVarnodeOut）+ `guard_calls` 全链（spacebase 平移 0x10）：stack 锁定
  几何升级 unaffected（无 INDIRECT、SUBPIECE 截断守卫），register 控制
  几何保持 unknown_effect（INDIRECT op 守卫，cc:1511-1519）。
  covered=MATCH（双侧逐字节一致，11/12）；overall=PARTIAL_MATCH（BE 栈
  空间过渡模型下不可 stage，登记为 UNTESTED）。


## LocationMap::add 导航重写（本次性能修复）

`LocationMap::add`（heritage.cc:33-71）原先以 `Vec` 快照全部同 space 键再
线性定位（每次 add O(n)，每 pass 覆盖构建 O(n²)）。现按 oracle 的
lower_bound/--iter/++iter 语义改用 BTreeMap range 查询（`range(..(space,addr))`
取 prev、`range((space,addr)..)` 取 lb1/lb2），后续 merge 循环同样以 range
游标推进。分类结果（prev=0/1/2、合并后 size/pass、插入位置）与原实现逐分支
等价：selected=prev 时不 revisit (prev, addr) 区间（prev 是 addr 前最后键），
merge 循环前向 only 亦与 forward-only iterator 对齐。

## `pub fn bump_deadcode_delay`（MAIN-POSTSTRUCT-SPIN-0001，2026-08-27）

忠实移植 `Heritage::bumpDeadcodeDelay`（heritage.cc:2571，函数体
cc:2573-2582）。签名改为携带 `&mut Funcdata`：oracle 通过 `fd` 上的
Override/重启标志生效，而非改 `HeritageInfo`。语义链：

- cc:2574-2575 空间种类门（IPTR_PROCESSOR/IPTR_SPACEBASE → 锁定 x86-64
  的 Ram/Register/Stack）；
- cc:2576-2577 `getDelay() != getDeadcodeDelay()` 早退（已有全局 delay）；
- cc:2578-2579 `Override::hasDeadcodeDelay` 早退（只允许装一次，
  override.cc:92-103，按 `AddrSpace::getIndex` 索引）；
- cc:2580 `Override::insertDeadcodeDelay(spc, deadcodedelay+1)`
  （override.cc:79-89）——**不**改本 pass 的 `HeritageInfo`；
- cc:2581 `fd->setRestartPending(true)`——重启由
  `ActionRestartGroup::apply`（action.cc:553-582）执行；Rugra 侧重启环
  未接线（PIPE-RESTART-0001，有界完成，见 action.md）。

旧实现（已删）：直接 `infolist[i].deadcodedelay += 1` 的 pass 中途变异 +
仅打日志。该中途变异违反 oracle 的"下一遍 startProcessing 才生效"契约，
是不健康状态的喂入源之一（MAIN-POSTSTRUCT-SPIN-0001 根因链）。调用点
`heritage()`（cc:2710/2719 needwarning 路径）与 `removeRevisitedMarkers`
同步传 `fd`。同步修正引注行号：`setDeadCodeDelay`=cc:2815（体 2815-2822，
`delay < info->delay` 时 panic 镜像 LowlevelError）、`getDeadCodeDelay`
=cc:2803、`seenDeadCode`=cc:2791。

## 2026-09-26：`remove_revisited_markers` 空间来源改权威形式（TRIGFACE）

`HeritageInfo` 的选取从"`remove[0]` 的空间（空表回退 Register）"改为
调用方传入的**段空间** `memrange.space`（`place_multiequals` 调用点），
镜像 oracle `getInfo(addr.getSpace())`（cc:247——用被 heritage 的大段
地址取空间，而非被移除 varnode 的空间）。oracle 的 `placeMultiequals`
以 `!removevars.empty()` 守卫调用（cc:2626）且 `collect` 的 loc-tree 窗口
不跨空间，故两种推导在一切 oracle 可达输入上恒等——本改为保真形式修正，
语料行为零变化（canon 双语料字节恒等亲证）。完整触发面 parity 测绘见
`docs/alignment_docs/RESTART_TRIGFACE_PARITY_2026-09-26.md`。

## 2026-08-28：永久 ParamActive 容器调用点适配

`guard_calls`、input/output overlap guard 及 stack-output guard 已适配
`FuncCallSpecs` 永久嵌入的 `active_input`/`active_output`；active 状态继续由
独立 boolean 门控。这个改动只消除了 Option 容器与 Ghidra 对象生命周期的
差异，没有为 Heritage 的 range/alias/SSA 分支新增 oracle 证据，模块状态保持
L2/MISMATCH。

## RUGRA_HERITAGE_TRACE（worktree 临时诊断，非对齐面）

`RUGRA_HERITAGE_TRACE=1` 时，`guard_returns` 的 persist 循环对每个非 dead
RETURN 打印 `[H-GRET] pass=<pass> range=<off>/<size> return=<addr>`（heritage.cc
1677-1691 的观察位）。用于 LATTICE-GEN 阻塞①双侧对拍：锁定 oracle 探针（/tmp/
w-carry-ore，CARRY_FAKE_NORET_ADDRS 供给 golden headless 环境的 {exit,
__stack_chk_fail} noreturn 数据）的等价 [ORE-GRET]/[ORE-RETLIST] 输出。默认关
闭，合入 root 前按需移除或保留为 env-gated 诊断。

## 2026-08-30:multiequal 输入补符号尾(HERITAGE-MULTIEQ-VNIN-SYMBOLTAIL-0001)

w-typeflow 根因④落地:heritage.rs vnin(heritage.cc:2638 经 data.newVarnode 带符号尾)裸建
create_with_space;实证幸存 phi 输入 varnode 无 mapentry → 只读全局类型流断。补
`fd.set_varnode_properties(&vnin)`。

## 2026-09-22 追加（BLOCKSTRUCT-SWITCHOUT-NOCLEAR-0001 同型排查 — 无代码改动）

对 `apply_new_varnode_flags`（heritage.rs:2363 `set_flags(fl & !TYPELOCK)`）做同型
no-op 排查后**裁定不改**：Ghidra 原文 funcdata_varnode.cc:119/166 就是
`vn->setFlags(vflags & ~Varnode::typelock)`，而 `Varnode::setFlags`
（varnode.cc:352-361）同样 `flags |= fl` OR 语义——掩码的作用是**阻止** queryProperties
属性集中的 typelock 被 OR 进新建 varnode（"Typelock set by updateType"），不是清
已有位。该行只作用于 bank 新建 varnode（22 个调用点全部传入新建对象），Rust 与
oracle 逐字一致，改成 `clear_flags` 反而偏离原文（若 `fl` 含 TYPELOCK 会错误置位）。
与 blockaction.rs 两处真 no-op（自旗派生掩码 `set_flags(own & !BIT)`）本质不同。

## 2026-09-23：MATCHURL-CONCAT-SEQNUM-0001 — guardOutputOverlap concat op 地址忠实化（Phase 2 ordinal 12 清零）

match_url Phase 2 mirror 首分歧（ordinal 12 heritage，op-idx 0）：双侧 1503-op
快照仅差 14 个 PIECE 的 **SeqNum pc**——oracle `526c:5a0`（call 地址），Rugra
`1200:5a0`（返回存储地址）。根因：Rugra `guard_output_overlap` 的两个 concat
（heritage.rs:3054/3075）以 `ret_addr` 为 op 地址；oracle cc:1259/1272 用
`indOp->getAddr()`——第一个 `newIndirectCreation`（cc:1253）的地址，即
致效 call 的地址（`newIndirectCreation` 以 `newOp(2, indeffect->getAddr())`
建 op，funcdata_op.cc:716）。修复 = 建一次 `ind_op_addr` 双臂共用。uniq 序号
两侧本就相同（5a0..5d4），仅 pc 字段翻转；投影 op 序为 seqnum 排序，pc 翻转
使这 14 个 PIECE 从快照头部归位，ordinal 12 快照双侧逐字节一致。oracle 侧
行为证据：guardCalls→tryOutputOverlapGuard（`outputCharacter==contained_by`，
16 字节 XMM0 范围含 8 字节 XMM0_Qa 输出）→guardOutputOverlap back-piece 臂
（sizeFront=0，sizeBack=8，`CONCAT88(Qb[create], Qa[create])`，drill 双侧
窗口逐行同构）。四类核对：引用参数=indOp 句柄（非拷贝）；遍历序=front 臘后
back 臂（同 oracle）；计数器=无；排序键=SeqNum(pc=call,uniq=创建序)。

## 2026-09-24：TEMP-DBG 清理（Lane GG2）

移除 guard_returns 输入处的 [DBGRD] 环境门调试块（lane 前代遗留；提交规范
要求临时 TAG 提交前删除）。无行为变化。

## 2026-09-24：test_heritage_creation 陈旧期望修正（TESTLIB-STATE-CONTAMINATION-0001）

`#[cfg(test)]` 内 `test_heritage_creation` 仍断言 Stack deadcode delay=2
（旧 "ram+1" 读法），而 `space.rs get_delay` 已在 6821e158 按指针空间规则
修正为 register(0)+1=**1**（oracle HeritageInfo dump
`stack:idx=8,type=IPTR_SPACEBASE,delay=1`，RCA2_MAXPASS.md §4.3/§5，
architecture.cc:565 `ptrdata.space->getDelay()+1` 中 ptrdata.space 是栈指针
寄存器空间而非 ram basespace）。测试断言与注释同步改为 1；`Heritage`/
`HeritageInfo` 生产代码零改动。

## 2026-09-25：HERITAGE-CROSSSPACE-MERGE-0001 — guard 家族输出 varnode 空间限定

**根因**（backtrace 探针实锤，wt/xcross lane）：CURB2 登记的"MULTIEQUAL 输出
Ram@0x90、输入 Register@0x90"跨空间合并垃圾，注入点不在 collect/guard 的
loc_tree 窗口（`HERITAGE-DRIVER-SWITCH-0001` 后已 space-correct），而在
**guard/block-removal 家族的无空间 varnode 创建**：Rugra 的
`new_varnode_out`/`new_varnode` 历史适配器分别 **Register-pin/implicit-RAM**，
而 oracle 的 `newVarnodeOut(s, Address, op)`/`newVarnode(s, Address)` 携带
完整 (space, offset)：

| 位点 | oracle 行 | Address 的空间 | 修复 |
|---|---|---|---|
| `guard_call_overlapping_input` | cc:1229 | 守护 RANGE 空间 | `new_varnode_out_full(v_size, space, trunc_addr, …)` |
| `guard_output_overlap` ×2 | cc:1264/1277 | 守护 RANGE 空间 | `new_varnode_out_full(…, space, addr, …)` |
| `float_extension_write` | cc:2267 | join piece 自带空间 | `new_varnode_out_full(…, vdata.space, …)` |
| `guard_output_overlap_stack` ×3 | cc:1330/1348/1370 | STACK（range） | `new_varnode_out_full(…, AddressSpace::Stack, …)` |
| `try_output_stack_guard` ×2 | cc:1414/1423 | cc:1414=callspec 输出存储空间；cc:1423=RANGE 空间 | `_full(ret_space, …)` / `_full(space, …)` |

对 REGISTER range（x86-64 上 guardOutputOverlap 的主战场）行为不变
（Register-pin 恰好等于 range 空间）；对 STACK/RAM range 不再伪造
Register@range偏移/Register@stack偏移 varnode。funcdata.rs `push_multiequals`
cc:135 的 implicit-RAM 伪造（RAM@register 偏移 = 门控 ap_getparents 的
`uRam0000000000000008/80/90` 族）见 docs/api/funcdata.md 同日节。

**验收（亲父 7a63a1b1 双态对照）**：
- 默认路径 httpd **1472/0/0 输出 cmp 字节恒等**（Register-pin 位点在语料
  上只触 register-range，行为不变）；
- 门控 `RUGRA_SYMDB=1` httpd **1561→1519**：ap_getparents 106→64（−42），
  **小偏移 uRam(<0x10000)/unique0x/register0x 兜底名 0 处**，suck_in_APR
  零差 ✓ 不回退，✓ 集合与亲父门控基线恒等；
- curl 1099/0/0、bank 26/26 MATCH、cargo test --lib 1709P/1F（唯一失败
  test_nonzeromask_pipeline_wiring 预存）。
- 残差：门控 main +74 归 HERITAGE-FLAGBASE-SPACELESS-0001（另一 P1 阻塞，
  flagbase 无空间查询域）；默认路径 ap_fini unique0x000a0830/register0x 族
  与本根因无关（AFINI lane 已归因 X86LIFT/PRINTC/headless 桥接域）。

## 2026-09-25：processJoins 消费链 1:1 落地（Lane PJOINS，HERITAGE-PJOINS-0001）

`process_joins`（heritage.cc:2281-2313）从扫描+log 存根改为完整消费端口，
`split_join_read`（cc:2119-2163）/`split_join_write`（cc:2172-2227）从
"2-piece 特例"改为逐层 `split_join_level` 迭代，`float_extension_read`/
`float_extension_write`（cc:2235-2273）改为 joinrec 由调用方传入（oracle
签名形态）。逐项语义：

- **迭代**（cc:2287-2292）：loc 序快照 join 空间 varnode。oracle 的
  `beginLoc(joinspace)..endLoc` + `getSpace()!=joinspace` break 守卫防御
  迭代中插入；split 系列只往 piece/const 空间建 varnode，join 子区间不
  增长，快照与守卫式游走可观察等价。
- **findJoin**（cc:2293→translate.cc:746-762）：miss 时 oracle 抛
  LowlevelError("Unlinked join address")。Rugra 生产者
  （coreaction.rs `return_join_address`）以无状态 hash 铸 offset、无
  findAddJoin 登记——**降级为响亮 log+跳过**（HERITAGE-PJOINS-UNLINKED-0001，
  见下方证据：oracle 本语料上 trials 全程 used=0，生产侧分歧才是 canon
  收敛正解）。
- **尺寸校验**（cc:2296-2297）：unified.size≠vn 尺寸 oracle 抛错，同因
  降级 log+continue。
- **free 读拆分**（cc:2298-2303）：floatExtensionRead / splitJoinRead。
  后者：`op` 从 loneDescend 起步，每层对非透传 curvn 建
  `PIECE(mosthalf,leasthalf)`（output=curvn，insertBefore(op)，op 前滑）；
  isPrimitive（typelock→isPrimitiveWhole，否则 true）置
  `setPrecisHi/Lo`，否则 `opMarkNoCollapse(concat)`（cc:2145-2151）。
- **delay 门**（cc:2305-2306）：`pass != get_info(piece0 空间).delay →
  continue`——写拆分恰在 pass==delay 的一次发生。register 空间 delay=0。
- **写拆分**（cc:2308-2311）：floatExtensionWrite / splitJoinWrite。后者：
  `op`=def（input vn 为 None），input 基底锚 block0 起址（cc:2192-2195）；
  每 SUBPIECE 对先 most（shift=leasthalf 尺寸）后 least（shift=0），
  op==null 时 opInsertBegin(block0)（cc:2200-2203），op 后滑到最新。
  SUBPIECE 常量与输出全部经 `fd.new_constant`/`fd.op_set_output` 全
  def 接线（旧存根直写字段绕过 descend 簿记）。

**Oracle 探针证据**（锁定 e40ed130 libdecomp + BFD，/dev/shm/rugra-tests/
pjoins/oracle-cpp/，instrumented processJoins/ActionReturnRecovery）：
httpd 473 函数全量扫描——9 函数产生 return-pair join
（join:0x0,sz=16,pieces=[reg:0x10+8,reg:0x0+8],free=0：
ap_build_cont_config/ap_die/ap_fini_vhost_config/ap_internal_redirect×2/
ap_is_recursion_limit_exceeded/ap_mpm_run/ap_walk_config/unixd_setup_child），
**80/80 次访问全部 `pass(≥1) != delay(0) → skip_write`，零次 split**；
curl 全量仅 main 4 次访问同形态 skip。即 oracle 消费链在两语料上的可观察
行为=迭代+查找+尺寸校验+跳过；join 存续到打印层。ap_init_vhost_config
（Rugra 唯一 join 产地）oracle 侧 trials
`[slot=1 reg:0x0+8 used=0 active=0][slot=2 reg:0x10+8 used=0 active=0]`——
`buildReturnOutput` 的 `isUsed()` 早退使 oracle 根本不建 join；Rugra 生产
者建了=生产侧（coreaction 判定链）分歧，AUVar16 残差归它（另行 TODO）。

**Rugra 回归测试**（不升 B2 状态，仅回归锚）：write-split 双 SUBPIECE
（shift 8→reg:0x10+precis_hi、shift 0→reg:0x0+precis_lo、均读 join vn）、
delay 门（pass=2 零 SUBPIECE）、unlinked 降级（无记录零 SUBPIECE 不崩）、
read-split（free+单读者→PIECE 链定义 join vn、半片 precis 旗）。

**验收**：httpd/curl 输出与亲父 9d91f00c **cmp 字节恒等**（httpd 908/0/0、
curl 489/0/0）；bank 391/391 MATCH；cargo test --lib 1717P/1F（预存
nonzeromask 同败）；annotations/refs 检查全绿。

## 2026-09-25：split 族注解行修正（CR-PJOINS F1）

六个 `// Ghidra:` 注解从空行（定义行+1）改指真定义起始行：
splitJoinLevel 2068→**2067**、splitJoinRead 2119→**2118**、splitJoinWrite
2172→**2171**、floatExtensionRead 2236→**2235**、floatExtensionWrite
2256→**2255**、processJoins 2282→**2281**（机制 D cited-line-drift 防逸）；
连带两处区间引用起点同步（2118-2163/2171-2227）。零行为改动。


### 2026-09-26 — TOOLS-REFS-DEFSTART-0001 citation re-anchor

- 本模块 25 处 `// Ghidra:` 头注解的 file:line 已重锚到锁定 oracle (e40ed130)
  的函数定义起始行；本文件中同名单点引用同步更新（正文内点引用/区间端点不在
  机制 D checker 范围，遗留见 RULEACTION-ANNO-PROSE-RANGE-0001）。注释-only，零行为变化。

### 2026-09-27 — CANON-REGJUNK 双票新增生产路径回归测试

- 新增 `test_call_shadowed_read_binds_to_call_output_under_heritage`
  （CANON-REGJUNK-XMM-EXTRAOUT-0001 + CANON-REGJUNK-INRAX-LIVEVAR-0001）：
  CALL 带锁定输出（funcLinkOutput 形，coreaction.cc:1551）+ 其后 `RBX = COPY
  RAX` 读——钉死 inject 时读保持 free（无线性序输入预提升）+ 生产单 pass
  `op_heritage` 后读绑到 CALL 输出 varnode 且不伪造 `in_RAX` 输入。这是
  funcdata.rs inject Phase 3 退役（寄存器 INPUT 仅由 renameRecurse 晋升，
  heritage.cc:2499-2503）的行为门。另：`test_spacebase_marks_rsp_input`
  （funcdata.rs 侧）以显式 `set_input_varnode` 模拟 heritage 后态后跑
  spacebase()，oracle 动作序 heritage 先于 spacebase（coreaction.cc:5506）。

## join 基建接线（SQLCENSUS-STACKSLOT-GROUP-0001 第一波，2026-09-28）

- 本文件对应源码的改动均为 join 空间基建（translate.cc:817
  constructJoinAddress / :671 findAddJoin 的 1:1 移植，详见 docs/api/arch.md
  与 docs/api/space.md 条目）的接线/适配面：CALL 侧 join 闭包 whole 落
  Join 空间注册地址；RETURN 侧 return_join_address 委托 Architecture；
  double_precis create_joined_whole 消费空间限定结果；process_joins /
  build_subpiece 经 RwLock 读 join_db。无独立新语义。

## 2026-09-30：returnlist/optree 消费迁移（PERF-ARENA-FLIP-0001 (b)）

`guardReturns`/`guardReturnsOverlapping` 三处 `fd.obank.returnlist.clone()`
快照改 `fd.obank.iter_return().cloned().collect()`（heritage.cc:1623-1691
`beginOp(CPUI_RETURN)` 链序快照，序恒等）；storelist 两处消费同迁
`iter_store()`。optree/loc_tree 消费已在 (a) 段经 PcodeOpTree/
VarnodeLocSet 桥接零改动，本段无新增投影位点（SeqNum/Address→SpaceOff
仍单点 `space_off_of_address` 携带 offset）。canon 双 md5 恒等亲证。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。

## BLOCKFLIPW2（2026-10-01）消费位点族影子读迁移（wave 2 批 5: heritage）

PERF-BLOCKSTORAGE-FLIP-0001 wave 2 批 5: `build_adt` 的 up-edge 扫描
（heritage.cc:2343-2350——oracle 即 `u != v->getImmedDom()` 指针比较+
`b[u->getIndex()]` 字段读）改读 bank index 影子（block.hh:160）,前驱
句柄不再解析（该位点 u 的 Arc 仅服务于 index 读,属纯死句柄面）。
`rename_recurse`/`visit_rename_direct` 的 get_ops 深走保留 peer 守卫。
行为恒等: canon curl `b7773087` + httpd `54f9b02c` 字节恒等 + tests 2026P。
