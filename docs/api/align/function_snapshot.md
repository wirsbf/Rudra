# `align/function_snapshot.rs` API Reference

**源代码路径**: `src/align/function_snapshot.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **可信边界**: 本文档描述的是 Rudra 当前已经落地的**函数级语义快照脚手架**，用于支持后续批量函数对齐工作；这不是“函数级与 Ghidra 已完成一致性验证”的证明
- **重要提醒**: 本模块的价值在于把“按函数批量对齐”这件事变成有结构、有格式、有层级的数据出口，而不是继续停留在口头目标上
- **不应误解为**:
  - 已完成 Ghidra 侧同格式导出
  - 已完成 Rudra ↔ Ghidra 的批量函数级对拍
  - 已证明每个函数的语义实现都与 Ghidra 相同
  - 已形成稳定的批量回归体系

---

## 模块定位

`align/function_snapshot.rs` 是 Rudra 为“**按函数批量语义对齐 Ghidra**”所建立的**函数级快照结构层**。

如果把此前的最小样本工作理解为：

- 单条指令
- 小型指令序列
- 局部 P-code 比较

那么本模块要解决的是更高一层的问题：

> 如何把一个完整函数当前在 Rudra 中可见的语义状态，导出为一个**可序列化、可对比、可批量处理**的统一结构。

它的核心价值在于：

1. 为单函数导出统一语义摘要
2. 为后续 Ghidra 侧导出提供目标格式
3. 为批量对比器提供稳定输入结构
4. 为差异按层归因提供基础数据形态

---

## 为什么需要这个模块

如果目标是：

- “批量对齐 ghidra 的函数”
- “保证每个函数的语义实现一样”

那么仅靠：

- 单条 `mov`
- 单条 `add`
- 运行时 stdout 日志

是远远不够的。

函数级语义对齐至少要覆盖：

- 函数身份信息
- P-code 序列
- CFG / block 结构
- SSA / varnode 关系
- 批量报告与差异归类

而 `function_snapshot.rs` 当前做的事情，就是先把这些对象定义出来，并让 Rudra 侧能够输出它们。

更准确地说，本模块是：

> **函数级批量语义对齐的“导出层 / 数据层 / 中间契约层”**

而不是：

> **已经完成函数级对齐本身**

---

## 当前适用场景

本模块当前适合用于以下场景：

### 1. Rudra 侧导出函数语义快照
把一个 `Funcdata` 当前状态导出为结构化快照对象，用于：

- 调试
- 存档
- 后续落盘为 JSON
- 人工审阅
- 批量 runner 输入

### 2. 为 Ghidra 侧建立对齐目标格式
即使 Ghidra 侧导出当前还没接上，这个模块也已经把未来需要对齐的结构明确下来了。

### 3. 为批量比较器提供数据模型
后续只要 Ghidra 侧也能导出兼容结构，就可以直接进入：

- 按函数比较
- 分层归因
- 批量统计
- mismatch 报告

### 4. 为状态文档和工程日志提供函数级证据出口
相比“某函数看起来不对”，快照结构可以支持更具体的描述：

- P-code 层错
- CFG 层错
- SSA 层错
- 元信息层错

---

## 当前设计边界

必须明确区分下面三件事：

### A. 已实现
当前已经实现的是：

- 函数级快照结构定义
- 从 `Funcdata` 提取 Rudra 当前状态
- 批量比较结果与 mismatch 的骨架结构
- 基础单元测试

### B. 部分实现
当前部分实现的是：

- Rudra 侧函数级语义导出能力
- 批量报告的数据层
- 语义层级分类的结果结构

### C. 尚未完成
当前尚未完成的是：

- Ghidra 侧同格式导出
- Rudra ↔ Ghidra 真正的函数级批量比较执行器
- 大规模函数批量跑的闭环
- 真实 corpus 上的批量一致性统计
- “每个函数语义实现都一样”的可验证结论

---

## 对外公开类型概览

本模块当前公开的主要类型可以分为四组：

### 1. 函数级快照主对象
- `FunctionSemanticSnapshot`
- `FunctionIdentitySnapshot`
- `FunctionSummarySnapshot`

### 2. 语义层快照
- `PcodeSnapshot`
- `PcodeOpSnapshot`
- `CfgSnapshot`
- `BasicBlockSnapshot`
- `SsaSnapshot`
- `SsaVarnodeSnapshot`
- `VarnodeSnapshot`

### 3. 对比结果与差异分类
- `SnapshotSemanticLayer`
- `FunctionSemanticMismatch`
- `FunctionSemanticCompareResult`

### 4. 对比结果与批量 runner
- `BatchSemanticCompareReport`
- `compare_function_snapshots(...)`
- `compare_snapshot_batches(...)`

---

## 公开 API 说明

---

### `pub struct FunctionSemanticSnapshot`

函数级语义快照的顶层对象。

#### 角色
这是整个模块中最核心的结构。  
它表示：

> “某个函数在当前 Rudra 中被观察到的语义状态摘要”

#### 组成
它把一个函数拆成多个层次进行组织：

- schema 版本
- 函数身份信息
- 粗粒度 summary
- P-code 层
- CFG 层
- SSA 层
- tags
- notes

#### 设计意义
它的目标不是承载所有底层运行时细节，而是承载：

- 足够稳定
- 足够清晰
- 足够可序列化
- 足够适合对比

的函数级语义表示。

#### 适用场景
- 从 Rudra 侧导出函数语义摘要
- 作为未来 Ghidra 对齐输入格式
- 作为批量比较报告的单函数基础对象

#### 边界
它是“快照”，不是 live graph 本身。  
也就是说：

- 它描述当前状态
- 但不保留所有可变引用与运行时结构关系

---

### `pub const CURRENT_SCHEMA_VERSION: u32 = 1`

当前快照 schema 版本。

#### 作用
用于标记当前函数级快照格式的版本号。

#### 为什么重要
函数级批量比较最终很可能要落盘、跨工具传递、长时间保留。  
一旦 schema 结构变更，就需要一种方式来区分：

- 旧版本快照
- 新版本快照

#### 当前含义
当前值为 `1`，意味着这套快照结构已经被当作第一版稳定草案来使用。

---

### `pub fn from_funcdata(func: &Funcdata) -> Self`

从 `Funcdata` 构造函数级语义快照。

#### 角色
这是本模块当前最重要的构造入口。

#### 语义
它会从当前函数上下文中提取：

- 函数基础信息
- P-code 操作摘要
- CFG block 摘要
- SSA / varnode 摘要
- 粗粒度 summary 计数

然后组成一个完整的 `FunctionSemanticSnapshot`。

#### 当前已提取的信息

##### 函数层
- `name`
- `entry`
- `size`

##### P-code 层
- `seq`
- `opcode`
- `output`
- `inputs`

##### CFG 层
- `index`
- `start`
- `ops`
- `successors`
- `predecessors`

##### SSA 层
- `varnode`
- `version`
- `is_input`
- `is_written`
- `defining_op`
- `uses`

##### summary 层
- `pcode_op_count`
- `basic_block_count`
- `varnode_count`
- `has_symbols`
- `has_strings`

##### P-code 层
- 每条 op 的 `SeqNum`
- opcode
- output
- inputs

##### CFG 层
- block index
- start address
- block 中的 op seq 列表
- successors
- predecessors

##### SSA / varnode 层
- varnode identity
- version
- 是否 input
- 是否 written
- defining op
- use 列表

#### 边界
这个构造函数提取的是：

- Rudra 当前**可见**的函数状态

它不意味着：

- 这些状态已经和 Ghidra 对齐
- 这些状态已经完整覆盖所有未来对拍需求

---

### `pub fn with_tag(mut self, tag: impl Into<String>) -> Self`

给快照附加一个标签。

#### 作用
为调用方提供一种轻量的元信息附加方式。

#### 适合放什么
例如：

- `rudra`
- `batch-candidate`
- `x86_64`
- `cfg-only`
- `needs-ghidra-export`

#### 设计意义
批量处理时，经常需要在不改变主结构的情况下，给快照附上：

- 来源标记
- 阶段标记
- 过滤标记

这个接口就是为此服务。

---

### `pub fn with_note(mut self, note: impl Into<String>) -> Self`

给快照附加一条备注。

#### 作用
用于补充自由文本说明。

#### 典型用途
例如：

- 当前函数导出时尚无字符串表
- 当前函数 CFG 已建立，但 SSA 尚不稳定
- 当前样本来自最小对齐实验集

#### 与 `tag` 的区别
- `tag` 更适合机器筛选
- `note` 更适合人工阅读和临时说明

---

## 身份与摘要层

---

### `pub struct FunctionIdentitySnapshot`

函数身份信息快照。

#### 当前字段
- `name`
- `entry`
- `size`

#### 作用
用于唯一化和标识函数。

#### 使用场景
- 批量比较时按入口地址或名字显示
- mismatch 记录中作为锚点
- 报告表格中显示函数头信息

#### 边界
`name` 当前仍然可能受：

- 输入命名
- 符号表情况
- 后续恢复逻辑

影响，因此它是“当前已知名”，不是“绝对真实源码名”。

---

### `pub struct FunctionSummarySnapshot`

函数粗粒度摘要。

#### 当前字段
- `pcode_op_count`
- `basic_block_count`
- `varnode_count`
- `has_symbols`
- `has_strings`

#### 作用
为批量统计和仪表盘式展示提供低成本概览。

#### 为什么重要
在批量比较里，很多时候你不想先看完整快照，而是先看：

- 这个函数规模多大
- graph 大概多复杂
- 有没有符号
- 有没有字符串
- 是否值得优先排查

这个结构就是为这种粗筛服务。

---

## P-code 层

---

### `pub struct PcodeSnapshot`

函数的 P-code 层快照。

#### 当前内容
- `ops: Vec<PcodeOpSnapshot>`

#### 作用
用于承载线性化的 P-code 操作序列。

#### 当前设计意图
先保证：

- op 顺序
- opcode
- input/output 基本结构

能被稳定导出。

未来如果需要更细粒度对拍，可以继续扩展。

---

### `pub struct PcodeOpSnapshot`

单条 P-code 操作的快照。

#### 当前字段
- `seq`
- `opcode`
- `output`
- `inputs`

#### 作用
这是函数级 P-code 层最小可比较单位。

#### 为什么这几个字段重要
- `seq`：区分同地址多 op
- `opcode`：最直接的语义操作类型
- `output`：结果写回目标
- `inputs`：依赖源

#### 当前边界
它目前还不是完整的 “all metadata op dump”，而是：

- 面向批量比较的稳定摘要

---

## CFG 层

---

### `pub struct CfgSnapshot`

函数的 CFG 层快照。

#### 当前内容
- `blocks: Vec<BasicBlockSnapshot>`

#### 作用
表示当前函数的 block 结构摘要。

#### 使用意义
函数级对齐里，仅比较 opcode 序列是不够的。  
很多真实差异会体现在：

- block 划分
- successor 数量
- predecessor 关系
- terminator 组织

`CfgSnapshot` 是进入函数级结构比较的基础。

---

### `pub struct BasicBlockSnapshot`

单个 basic block 的快照。

#### 当前字段
- `index`
- `start`
- `ops`
- `successors`
- `predecessors`

#### 作用
表示一个 block 当前在 Rudra 里被观察到的结构轮廓。

#### 字段含义
- `index`：当前 block 序号
- `start`：block 起始地址
- `ops`：该 block 内 op 的 `SeqNum`
- `successors`：后继 block 起始地址
- `predecessors`：前驱 block 起始地址

#### 价值
这个结构允许后续批量对齐器回答：

- block 数量是否一致
- block 起点是否一致
- edge 结构是否一致
- 某个函数的控制流在哪一层开始偏离

---

## SSA / varnode 层

---

### `pub struct SsaSnapshot`

SSA / varnode 层快照。

#### 当前内容
- `varnodes: Vec<SsaVarnodeSnapshot>`

#### 作用
承载函数中当前被观测到的 varnode / SSA 摘要。

#### 为什么重要
如果只比 P-code 和 CFG，很多更深层的差异仍然看不到，例如：

- 某个 varnode 是否被当作 input
- 某个值是否被视为 written
- def-use 关系是否不同
- version 分配是否偏移

---

### `pub struct SsaVarnodeSnapshot`

单个 SSA-oriented varnode 摘要。

#### 当前字段
- `varnode`
- `version`
- `is_input`
- `is_written`
- `defining_op`
- `uses`

#### 作用
这是把一个 varnode 从“底层存储节点”提升到“函数语义摘要对象”的关键结构。

#### 当前能表达的东西
- 它是什么位置的值
- 它的当前 version
- 它像不像 formal input
- 它是否被定义过
- 谁定义了它
- 谁使用了它

#### 边界
这仍然不是完整 SSA 图对象，只是用于：

- 对齐摘要
- 批量统计
- mismatch 定位

---

### `pub struct VarnodeSnapshot`

面向比较的 varnode 基础摘要。

#### 当前字段
- `space`
- `offset`
- `size`

#### 作用
为 P-code 层和 SSA 层共用一套稳定的 varnode 描述。

#### 设计原则
它故意保持轻量，不试图导出所有 flags 或所有内部状态。  
其目标是：

- 稳定
- 可序列化
- 便于对比

而不是“完整镜像 live Varnode 对象”。

---

## 差异与批量结果层

---

### `pub enum SnapshotSemanticLayer`

语义层分类枚举。

#### 当前取值
- `Function`
- `Pcode`
- `Cfg`
- `Ssa`

#### 作用
让未来的 mismatch 不再只是“一堆字符串”，而是能明确说：

- 这是函数元信息层的问题
- 这是 P-code 层的问题
- 这是 CFG 层的问题
- 这是 SSA 层的问题

#### 工程意义
这对批量报告非常关键，因为后续可以统计：

- 哪一层问题最多
- 当前主阻塞在哪一层
- 某一轮修复后哪一层 mismatch 降了

---

### `pub struct FunctionSemanticMismatch`

单条函数级语义差异记录。

#### 当前字段
- `function_entry`
- `function_name`
- `layer`
- `code`
- `details`

#### 作用
这是未来 batch compare 真正落地后，用于记录单条差异的标准对象。

#### 当前状态
现在主要还是数据模型层准备。  
它的价值在于：

- 已经把 mismatch 结构约定好
- 后续不需要再临时发明报告格式

---

### `pub struct FunctionSemanticCompareResult`

单函数比较结果摘要。

#### 当前字段
- `function_entry`
- `function_name`
- `matched`
- `mismatches`

#### 作用
表示“一个函数比完之后”的结果。

#### 设计意义
未来批量比较器只需要返回一组这个对象，就能组成批量报告。

---

### `pub fn match_result(snapshot: &FunctionSemanticSnapshot) -> Self`

构造一个“匹配”的单函数比较结果。

#### 作用
用于快速生成通过结果。

#### 适用场景
- 某函数在当前比较规则下通过
- 测试里需要快速构造通过项

---

### `pub fn mismatch_result(snapshot: &FunctionSemanticSnapshot, mismatches: Vec<FunctionSemanticMismatch>) -> Self`

构造一个“不匹配”的单函数比较结果。

#### 作用
用于快速封装一个函数的 mismatch 集合。

#### 适用场景
- 批量比较器返回失败函数
- 测试里构造失败结果
- 后续报告聚合

---

### `pub struct BatchSemanticCompareReport`

批量函数语义比较报告。

#### 当前字段
- `total_functions`
- `matched_functions`
- `mismatched_functions`
- `results`

#### 作用
这是未来“批量对齐 ghidra 的函数”最直接需要的顶层报告对象。

#### 可以支持的后续问题
它未来可以直接回答：

- 一次对齐批次总共跑了多少函数
- 多少函数匹配
- 多少函数不匹配
- 每个函数失败在哪些层

---

### `pub fn from_results(results: Vec<FunctionSemanticCompareResult>) -> Self`

从一组单函数结果构造批量报告。

#### 作用
负责把逐函数结果聚合成批次摘要。

#### 当前行为
会自动计算：

- 总函数数
- 匹配数
- 不匹配数

---

### `pub fn match_rate(&self) -> f64`

返回匹配率百分比。

#### 作用
适合批量 dashboard 或工程日志中的快速展示。

#### 典型用途
例如输出：

- 当前 50 个函数中 18 个匹配
- 匹配率 36%

---

### `pub fn mismatch_count_by_layer(&self) -> BTreeMap<SnapshotSemanticLayer, usize>`

按语义层统计 mismatch 数量。

#### 作用
这是批量语义对齐中非常重要的聚合接口。

#### 能回答的问题
例如：

- 当前主要是 P-code 层在失败
- CFG 层已经比较稳定
- SSA 层是下一阶段主要阻塞

---

## 内部采集函数说明

虽然这些函数不是面向外部的大型公共 API，但它们构成了本模块当前真正能工作的核心。

---

### `collect_pcode_ops(func: &Funcdata) -> Vec<PcodeOpSnapshot>`

采集函数中的 P-code 快照。

#### 当前行为
- 遍历 `obank.optree`
- 提取 `seq`
- 提取 `opcode`
- 提取 output
- 提取 inputs
- 最后按 `SeqNum` 排序

#### 作用
保证函数级 P-code 快照是：

- 稳定
- 有序
- 可对比

---

### `collect_cfg_blocks(func: &Funcdata) -> Vec<BasicBlockSnapshot>`

采集函数中的 CFG block 快照。

#### 当前行为
- 遍历当前 block graph 中的 block
- 收集 block 内 op 的 `SeqNum`
- 收集 predecessor / successor
- 最后按 `(start, index)` 排序

#### 作用
让未来的 CFG 层比较建立在稳定顺序之上。

---

### `collect_ssa_varnodes(func: &Funcdata) -> Vec<SsaVarnodeSnapshot>`

采集函数中的 varnode / SSA 摘要。

#### 当前行为
- 遍历当前函数能访问到的 varnode 集合
- 做去重
- 提取 defining op 和 use 列表
- 汇总为稳定排序的快照数组

#### 作用
为未来的 SSA 层对齐提供初步数据出口。

---

### `iter_unique_varnodes(func: &Funcdata) -> Vec<Arc<RwLock<Varnode>>>`

从当前 `Funcdata` 中提取去重后的 varnode 集合。

#### 作用
当前 `VarnodeBank` 的内部组织并不是一个现成的线性列表，因此这里提供了一个内部去重收集步骤，为 SSA 快照采集服务。

---

## 测试覆盖

当前模块已经有基础测试，至少覆盖：

### `test_snapshot_from_funcdata_basic`
验证：

- 能从一个最小 `Funcdata` 成功导出快照
- `schema_version` 正常
- 函数身份信息正常
- P-code 计数正常
- block 计数正常
- P-code opcode 正常
- SSA varnode 数量有合理结果

### `test_batch_report_counts`
验证：

- 批量报告能从单函数结果构造
- `total_functions`
- `matched_functions`
- `mismatched_functions`
- `match_rate()`

这些基础测试并不证明“函数级对齐已经完成”，但它们证明：

- 这个数据层脚手架已经可以工作
- 不是停留在空文档或空结构定义阶段

---

## 与其他模块的关系

本模块和以下模块关系紧密：

### `funcdata.rs`
快照当前的主要数据来源。

### `op.rs`
P-code op 的结构与序列信息来源。

### `block.rs`
CFG / block 快照来源。

### `varnode.rs`
SSA / varnode 快照来源。

### `align/runtime_verify.rs`
两者都属于对齐方向，但职责不同：

- `runtime_verify.rs`：更偏运行时局部验证与差异记录
- `function_snapshot.rs`：更偏函数级批量导出与批量比较数据层

---

## 当前最准确的模块结论

截至当前代码状态，`align/function_snapshot.rs` 最准确的描述应是：

> Rudra 已经开始建立**函数级批量语义对齐**所需的数据结构基础。  
> 当前已能从 `Funcdata` 导出函数级语义快照，并已具备批量结果与分层 mismatch 的骨架结构。  
> 但这仍然只是“批量函数对齐框架的 Rudra 侧导出层”，不是对 Ghidra 函数级 parity 的既成证明。

---

## 后续最合理的下一步

围绕本模块，最自然的下一步通常会是：

1. 补 Rudra 侧批量 runner
2. 为快照增加落盘 / JSON 导出路径
3. 设计 Ghidra 侧同格式导出
4. 实现真正的 Rudra ↔ Ghidra 函数级批量 compare
5. 在状态文档中记录按层 mismatch 统计

在这些步骤没完成前，不应把本模块写成：

- “函数级对齐已完成”
- “已经保证每个函数语义实现相同”

---
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
