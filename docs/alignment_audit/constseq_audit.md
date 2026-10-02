# constseq 对齐审计 (2026-07-22)

## 覆盖率
Ghidra: 1004行 (`constseq.cc`) / Rudra: 805行 (`src/constseq.rs`) / 比率: 80%

## 设计说明（重要架构偏差）
Ghidra 用三个类 `ArraySequence` / `StringSequence` / `HeapSequence` 分别承载 COPY 路径与 STORE 路径的逻辑；Rudra 将三者折叠为单一 `ArraySequence` 类，`StringSequence`/`HeapSequence` 退化为仅含 `base: ArraySequence` 的空 wrapper，原属 `StringSequence::*` / `HeapSequence::*` 的逻辑被搬进 `ArraySequence::*`（如 `check_interference`、`build_string_copy`、`transform`）或搬进两个 Rule 的 `apply_op` 内联体。本审计按"语义是否被覆盖"而非"类是否对应"来判定对齐。

## 已对齐函数 (19个)

### WriteNode
- `WriteNode::new` — Ghidra: constseq.hh:39 `WriteNode::WriteNode` (构造) ✅

### ArraySequence (含从 StringSequence/HeapSequence 折合的逻辑)
- `ArraySequence::is_valid` — Ghidra: constseq.cc:28 (推断; `isValid`) ✅
- `ArraySequence::interfere_between` — Ghidra: constseq.cc:42 `ArraySequence::interfereBetween` ✅
- `ArraySequence::check_interference` — Ghidra: constseq.cc:62 `ArraySequence::checkInterference` ✅ (并吸收了 `StringSequence::collectCopyOps` 的部分逻辑)
- `ArraySequence::new` — Ghidra: constseq.hh:56 `ArraySequence::ArraySequence` ✅
- `ArraySequence::sort_ops` — Ghidra: 内联 `WriteNode::operator<` 的比较语义 (constseq.hh:41) ✅ (非同名实现)
- `ArraySequence::form_byte_array` — Ghidra: constseq.cc:108 `ArraySequence::formByteArray` ✅
- `ArraySequence::is_valid_string` — Ghidra: 内联 (constseq.cc 内 byte_array 校验) ✅
- `ArraySequence::get_string` — Ghidra: 内联 (constseq.cc 内取串) ✅
- `ArraySequence::select_string_copy_function` — Ghidra: constseq.cc:161 `ArraySequence::selectStringCopyFunction` ✅
- `ArraySequence::build_string_copy` — Ghidra: constseq.cc:347/698 `StringSequence::buildStringCopy` + `HeapSequence::buildStringCopy` (合并) ✅
- `ArraySequence::transform` — Ghidra: constseq.cc:453 `StringSequence::transform` + constseq.cc:927 `HeapSequence::transform` (合并) ✅ (同时吸收了 `removeCopyOps` @ constseq.cc:415 与 `removeStoreOps` @ constseq.cc:871 的 op 销毁逻辑)

### RuleStringCopy (实现 Rule trait)
- `RuleStringCopy::new` — Ghidra: constseq.hh:121 `RuleStringCopy::RuleStringCopy` ✅
- `RuleStringCopy::apply_op` — Ghidra: constseq.cc:954 `RuleStringCopy::applyOp` ✅
- `RuleStringCopy::get_name` — Ghidra: `Rule::getName` (基类) ✅
- `RuleStringCopy::get_opcodes` — Ghidra: constseq.cc:942 `RuleStringCopy::getOpList` ✅

### RuleStringStore (实现 Rule trait)
- `RuleStringStore::new` — Ghidra: constseq.hh:132 `RuleStringStore::RuleStringStore` ✅
- `RuleStringStore::apply_op` — Ghidra: constseq.cc:986 `RuleStringStore::applyOp` ✅ (并吸收了 `HeapSequence::collectStoreOps` @ constseq.cc:663 的简化收集逻辑)
- `RuleStringStore::get_name` — Ghidra: `Rule::getName` (基类) ✅
- `RuleStringStore::get_opcodes` — Ghidra: constseq.cc:974 `RuleStringStore::getOpList` ✅
- `RuleStringStore::ptr_shares_base` — Ghidra: constseq.cc:465 `HeapSequence::findBasePointer` (简化版) ✅

## 缺失函数 (14个)

### StringSequence — 缺失 1 个
- `StringSequence::removeForward` — Ghidra: constseq.cc:383 — 优先级: 中 — 从写集合中移除一个节点并维护 xref 反向索引（用于 `removeCopyOps` 的辅助）。Rudra 直接整批销毁 move_ops，未做单节点前向清理，对当前 transform 路径无影响，但与 Ghidra 的细粒度维护不同。

### HeapSequence — 缺失 11 个（多数为复杂地址分析逻辑）
- `HeapSequence::findBasePointer` — Ghidra: constseq.cc:465 — 优先级: **高** — 完整的基指针识别（处理 PTRADD/COPY/MULT/SEGMENTOP 等地址计算链）。Rudra `ptr_shares_base` 仅做 PTRADD/COPY 两层回溯，未覆盖 MULT/SEGMENTOP/ADD 常量分量，漏判风险高。
- `HeapSequence::findDuplicateBases` — Ghidra: constseq.cc:486 — 优先级: **高** — 发现指向同一区域的多个不同基指针（别名基址）。Rudra 完全缺失，会导致多基址的字符串序列无法识别。
- `HeapSequence::findInitialStores` — Ghidra: constseq.cc:544 — 优先级: 中 — 从根 STORE 出发定位初始 store 集合（含对齐/重叠剔除）。Rudra 用 `applyOp` 内联的简化收集替代，未做重叠剔除。
- `HeapSequence::calcAddElements` — Ghidra: constseq.cc:583 — 优先级: 中 — 递归计算 PTRADD/INT_ADD 地址表达式中的元素个数与非常量分量。Rudra 缺失，无法精确推断序列长度。
- `HeapSequence::calcPtraddOffset` — Ghidra: constseq.cc:604 — 优先级: 中 — 计算 PTRADD 相对基址的偏移。Rudra 缺失。
- `HeapSequence::setsEqual` — Ghidra: constseq.cc:636 — 优先级: 低 — 比较两个 Varnode 集合是否相等（去重用）。
- `HeapSequence::testValue` — Ghidra: constseq.cc:648 — 优先级: 中 — 测试一个 STORE 是否写入指定 char 值（用于配对去重）。
- `HeapSequence::collectStoreOps` — Ghidra: constseq.cc:663 — 优先级: **高** — 完整的 store 收集算法（处理间接对、重复基址、跨步）。Rudra 仅做同块同基址的线性扫描，缺失间接对与去重。
- `HeapSequence::gatherIndirectPairs` — Ghidra: constseq.cc:770 — 优先级: 中 — 收集 STORE 间的间接配对（用于合并跨越 CALL/STORE 的串写）。
- `HeapSequence::deduplicatePairs` — Ghidra: constseq.cc:827 — 优先级: 中 — 对间接配对去重，确保每个元素只写一次。
- `HeapSequence::removeStoreOps` — Ghidra: constseq.cc:871 — 优先级: 低 — 销毁 store 序列（含递归销毁地址算子）。Rudra 由 `transform` 内的 `op_destroy_recursive` 替代，语义等价但无独立入口。

### WriteNode — 缺失 1 个
- `WriteNode::operator<` — Ghidra: constseq.hh:41 (内联) — 优先级: 低 — 按 SeqNum order 排序的比较算子。Rudra 用 `ArraySequence::sort_ops` 内联比较替代。

## HeapSequence 详细缺失清单 (2026-07-22 细化)

> 背景：Ghidra `class HeapSequence`（constseq.hh:86-117）继承 `ArraySequence`，专责 STORE 路径的堆指针分析。Rudra `src/constseq.rs` 仅有 `struct HeapSequence`（constseq.rs:397-404），**无 `impl HeapSequence` 块**，所有原属 HeapSequence 的逻辑被折叠进 `RuleStringStore::apply_op` 的内联线性扫描（constseq.rs:482-583）或 `ArraySequence::*`。下面按字段、方法、嵌套类三层细化。

### A. 结构体字段缺失 (constseq.hh:97-101)

| Ghidra 字段 | 行号 | Rudra 对应 | 状态 |
|---|---|---|---|
| `basePointer` | hh:97 | `HeapSequence.base_pointer` (rs:401) | **已声明但永不填充**（apply_op 未走构造路径） |
| `baseOffset` | hh:98 | `HeapSequence.base_offset` (rs:403) | **已声明但永不填充** |
| `storeSpace` | hh:99 | — | **缺失**（`AddrSpace *`，Rudra AddrSpace 基础设施不完整） |
| `ptrAddMult` | hh:100 | — | **缺失**（`int4`，元素大小映射到地址单位的倍率，calcPtraddOffset 依赖） |
| `nonConstAdds` | hh:101 | — | **缺失**（`vector<Varnode *>`，非常量地址分量，buildStringCopy 依赖构造 destPtr） |

### B. 方法覆盖矩阵 (constseq.cc:465-940)

| # | Ghidra 方法 | 行号 | Rudra 状态 | 对齐说明 |
|---|---|---|---|---|
| 1 | `findBasePointer` | cc:465 | **部分**（`RuleStringStore::ptr_shares_base` rs:598） | 简化版：仅 PTRADD/COPY 两层回溯，**未校验 `ptrAddMult` 分量**（cc:473-475），漏判倍率不符的 PTRADD |
| 2 | `findDuplicateBases` | cc:486 | **完全缺失** | 别名基址发现，需 PTRSUB/INT_ADD/PTRADD 常量偏移反向跟踪 + 正向匹配。**多基址场景全部漏判** |
| 3 | `findInitialStores` | cc:544 | **部分**（apply_op 内联 rs:516-559） | 未做 `findDuplicateBases` 扩展、未做对齐/重叠剔除 |
| 4 | `calcAddElements` | cc:583 | **缺失** | 递归 INT_ADD 树求和 + 收集非常量分量（maxDepth=3）。精确长度推断依赖 |
| 5 | `calcPtraddOffset` | cc:604 | **缺失** | PTRADD/COPY 反向偏移累加 + 字节转换。`baseOffset` 计算 + 非常量分量收集依赖 |
| 6 | `setsEqual` | cc:636 | **缺失** | 两个已排序 Varnode 集合比较（collectStoreOps 去重用） |
| 7 | `testValue` | cc:648 | **部分**（apply_op `is_constant` 单测 rs:539） | 仅测常量，未校验 `charType->getSize()`（cc:654），size 不符的 STORE 未剔除 |
| 8 | `collectStoreOps` | cc:663 | **部分**（apply_op 内联 rs:508-564） | 仅同块同基址线性扫描；**缺 `calcPtraddOffset`/`setsEqual`/`testValue` 的 wrapMask 回绕校验**（cc:671-684），偏移回绕场景误判 |
| 9 | `buildStringCopy` | cc:698 | **已对齐**（`ArraySequence::build_string_copy` rs:276） | 合并版，但**未构造非零 `baseOffset`/`nonConstAdds` 的 PTRADD index Varnode**（cc:709-748 整段缺失），destPtr 恒为裸 basePointer |
| 10 | `gatherIndirectPairs` | cc:770 | **缺失** | STORE 前驱 INDIRECT 链收集 + 跨链 in/out 配对 |
| 11 | `deduplicatePairs` | cc:827 | **缺失** | 按 outVn 存储 sort + characterizeOverlap 去重（partial overlap 判失败） |
| 12 | `removeStoreOps` | cc:871 | **部分**（`ArraySequence::transform` 的 `op_destroy_recursive` rs:379） | 销毁语义等价，但**未处理 INDIRECT 对的 unhook/重建**（cc:875-893） |
| 13 | `HeapSequence::HeapSequence`（构造） | cc:907 | **缺失** | 无 `impl`，构造逻辑（storeSpace/ptrAddMult 初始化 + findBasePointer + collectStoreOps + formByteArray 链）从未执行 |
| 14 | `transform` | cc:927 | **部分**（`ArraySequence::transform` rs:356 合并版） | 缺 gatherIndirectPairs/deduplicatePairs 前置 + INDIRECT 重建后置 |

**HeapSequence 方法小结**：14 个成员（13 方法 + 1 构造）中，**完全缺失 6 个**（findDuplicateBases、calcAddElements、calcPtraddOffset、setsEqual、gatherIndirectPairs、deduplicatePairs）、**部分覆盖 6 个**（findBasePointer、findInitialStores、testValue、collectStoreOps、removeStoreOps、transform）、**已对齐 1 个**（buildStringCopy 合并版）、**构造缺失 1 个**。

### C. 嵌套类 IndirectPair 完全缺失（原审计遗漏）

> **新发现**：Ghidra `HeapSequence::IndirectPair`（constseq.hh:88-96，嵌套 helper 类）承载 STORE 间 INDIRECT 的 in/out Varnode 配对，是 gatherIndirectPairs/deduplicatePairs/removeStoreOps 的数据载体。**原审计未提及该类，Rudra 完全无对应**。这是 STORE 路径无法正确处理跨 STORE 的 INDIRECT 衔接的根因。

| # | Ghidra 成员 | 行号 | 优先级 | 说明 |
|---|---|---|---|---|
| 1 | `IndirectPair::IndirectPair`（构造） | hh:92 | 中 | 持 inVn/outVn |
| 2 | `IndirectPair::markDuplicate` | hh:93 | 中 | 标记重复（置 inVn=null） |
| 3 | `IndirectPair::isDuplicate` | hh:94 | 中 | 查询重复标记 |
| 4 | `IndirectPair::compareOutput` | cc:808 | 中 | 按 (space,offset,size) 排序，deduplicatePairs 依赖 |

### D. 数据流影响（为何 STORE 路径覆盖远低于 COPY 路径）

`RuleStringStore::apply_op`（constseq.rs:482）的实际数据流是：
1. 取 root STORE 的 input[1] 作为 base（**不调用 findBasePointer，无 ptrAddMult 校验**）
2. 线性扫描同块 STORE，用 `ptr_shares_base` 判同基（**PTRADD 多层/SEGMENTOP/INT_ADD 常量分量全不处理**）
3. 按 seqnum 顺序拼 byte_array（**不做 offset 对齐/回绕/去重校验**）
4. 调 `ArraySequence::transform` 销毁 + 建 CALLOTHER（**destPtr 恒为裸 base，无 baseOffset/非常量 index 重建**）

对比 Ghidra 完整路径：构造 → findBasePointer → collectStoreOps(findInitialStores→findDuplicateBases + calcPtraddOffset + setsEqual + testValue) → checkInterference → formByteArray → transform(gatherIndirectPairs→deduplicatePairs→buildStringCopy→removeStoreOps)。Rudra 仅保留了"同块同基址线性扫描 + 销毁重建"骨架，**6 个地址分析方法 + 4 个 INDIRECT 配对方法 = 10 个核心分析点缺失**。

### StringSequence/HeapSequence 构造 — 缺失 2 个
- `StringSequence::StringSequence` — Ghidra: constseq.hh:77 — 优先级: 低 — 构造（需 SymbolEntry，Rudra 暂无 Symbol 基础设施）。
- `HeapSequence::HeapSequence` — Ghidra: constseq.hh:115 — 优先级: 低 — 构造。

## 高优先级缺失清单 (6个)
1. `HeapSequence::findDuplicateBases` (constseq.cc:486) — 多基址场景完全不支持，别名基址漏判
2. `HeapSequence::calcPtraddOffset` (constseq.cc:604) — STORE 偏移精确计算缺失，baseOffset 恒为 0
3. `HeapSequence::collectStoreOps` (constseq.cc:663) — store 收集过于简化，缺 wrapMask 回绕/setsEqual/testValue 校验
4. `HeapSequence::deduplicatePairs` + `gatherIndirectPairs` (constseq.cc:770/827) — 跨 STORE INDIRECT 配对分析整段缺失
5. `HeapSequence::buildStringCopy` 的 index Varnode 构造 (constseq.cc:709-748) — destPtr 恒为裸 base，非零 baseOffset/非常量分量丢失
6. `StringSequence::collectCopyOps` 的完整形态 — Rudra `check_interference` 仅覆盖线性同块场景

## 说明
- `StringSequence` / `HeapSequence` 两个类在 Rudra 中为空 wrapper（仅 `base: ArraySequence`），其方法被折叠进 `ArraySequence` 或 Rule 的 `apply_op`。这是明确的架构决策（模块头注释已声明"skeleton"），但导致 13 个 HeapSequence 方法 + 4 个 IndirectPair 方法无独立对应入口。
- `HeapSequence` 在 Rust 中**无 `impl` 块**（constseq.rs:397 仅有 `struct`，3/5 字段缺失），所有逻辑内联进 `RuleStringStore::apply_op`，这是 STORE 路径覆盖远低于 COPY 路径的结构性原因。
- 依赖未实现的基础设施：完整的 `HeapSequence` 路径需要 `Symbol`/`SymbolEntry`、`Scope`、`AddrSpace::addressToByteInt`、`Varnode::characterizeOverlap`、间接配对分析等，Rudra 目前未具备。
- 原审计"14个缺失方法"未区分"完全缺失 vs 部分覆盖"。细化后：HeapSequence 实际**完全缺失 6 + 部分覆盖 6 + 构造缺失 1**，外加 IndirectPair 嵌套类 4 个方法（原审计遗漏）。

## 覆盖率修正
- 原统计"14个缺失方法"低估了 HeapSequence 路径。计入 5 个新增（IndirectPair 嵌套类 4 + 构造 1）与 3 个结构体字段缺失后，STORE 路径的实际有效覆盖约为 Ghidra 的 30-40%（仅 buildStringCopy 骨架 + 线性扫描），远低于模块整体的 80%。
