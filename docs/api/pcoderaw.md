# `pcoderaw.rs` API Reference

**源代码路径**: `src/pcoderaw.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **文档目标**: 说明 Rudra 当前 `pcoderaw.rs` 在主链路中的角色，以及它如何作为 **raw p-code → `Funcdata`** 的桥接层
- **可信边界**: 本文档描述的是当前工程中“原始 P-code 表示层”的职责与公开接口，不代表：
  - lifting 已与 Ghidra 完全一致
  - raw p-code 已完成运行时对拍
  - 该层单独就能证明端到端反编译质量
- **当前定位**: `pcoderaw.rs` 是当前主线中非常关键的中间层，但它不是最终 IR，也不是最终输出层

---

## 模块定位

`pcoderaw.rs` 定义了 Rudra 中的 **原始 P-code 操作表示层**。  
它位于“反汇编 / 指令语义提升”和“正式函数级图结构”之间，用于表达：

- 一条机器指令被拆解后的原始语义操作
- 每条原始操作的输入、输出、顺序信息
- 在进入 `Funcdata` 前的轻量级、可注入表示

当前更准确的主链路应理解为：

```text
binary / disasm
  -> instruction semantics
  -> PcodeOpRaw / VarnodeRaw
  -> Funcdata::inject_raw_ops(...)
  -> PcodeOp / Varnode / Block graph
  -> Heritage / ActionDatabase / PrintC
```

因此，`pcoderaw.rs` 的角色是：

> **原始语义操作的承载层**  
> 用来把 lifting 阶段产出的结果，以统一、可传递、可注入的形式送入 `Funcdata`

---

## 为什么这一层重要

如果没有 `pcoderaw.rs` 这一层，整个主链路会面临两个问题：

### 1. lifting 结果很难稳定传递
反汇编 / 指令语义提升阶段往往先得到的是“原始语义片段”，而不是已经进入图容器的正式对象。  
`PcodeOpRaw` 负责把这些结果先稳定保存下来。

### 2. `Funcdata` 无法直接接收杂乱的语义结果
`Funcdata` 需要的是可按顺序注入、可构建 `PcodeOp` / `Varnode` / block 结构的输入。  
`PcodeOpRaw` 恰好提供了这种“桥接表示”。

因此可以把这一层理解为：

- 对下游：是 `Funcdata` 的输入桥
- 对上游：是 lifting 结果的收纳层

---

## 当前职责边界

为了避免文档继续失真，下面明确这层应该负责什么、不负责什么。

### 应负责
- 保存原始操作码
- 保存原始输入和输出
- 保存顺序/地址锚点
- 保存基础行为标志
- 提供编码/解码或构造辅助
- 为 `Funcdata::inject_raw_ops(...)` 提供稳定输入

### 不应负责
- 不直接承担完整 SSA
- 不直接承担 CFG
- 不直接承担变量恢复
- 不直接承担最终 C 输出
- 不应被写成“正式 IR 的最终形态”
- 不应被写成“与 Ghidra 已完成行为对拍”的证据

---

## 与其他模块的关系

### 与 `disasm/` 的关系
`disasm` 负责把机器码解码为指令级表示；  
`pcoderaw` 负责把这些指令语义进一步表达为 **raw p-code**。

可以简单理解为：

- `disasm`: “这是什么指令”
- `pcoderaw`: “这条指令应拆成哪些原始语义操作”

### 与 `op.rs` 的关系
`PcodeOpRaw` 不是正式 `PcodeOp`。  
更准确的关系是：

- `PcodeOpRaw`: 原始、轻量、待注入的操作表示
- `PcodeOp`: 已进入函数级图结构后的正式操作节点

### 与 `varnode.rs` 的关系
`VarnodeRaw` 不是正式 `Varnode`。  
它只是为了在 raw 阶段表达输入输出节点的最小信息。

### 与 `funcdata.rs` 的关系
这是当前最关键的关系：

> `pcoderaw.rs` 的主要现实意义，就是给 `Funcdata::inject_raw_ops(...)` 提供桥接输入。

因此，理解 `pcoderaw.rs` 时，应始终把它看成“进入 `Funcdata` 之前的一层”，而不是独立终点。

---

## 导出的公共 API

---

## `pub struct VarnodeRaw`

`VarnodeRaw` 是 raw p-code 阶段使用的原始 varnode 表示。

### 角色
它用于在 lifting 阶段表达一个输入或输出节点的最小信息，包括：

- 地址空间
- 偏移
- 大小

### 为什么需要它
在 raw 阶段，调用方往往只需要表达：

- 这个输入在什么空间
- 偏移多少
- 大小多少

还不需要立即构造成带共享引用、带分析状态、带版本信息的正式 `Varnode`。

因此，`VarnodeRaw` 可以理解为：

> **进入正式 `Varnode` 之前的轻量存储节点表示**

### 当前边界
它不是：

- 最终高层变量
- 正式图节点
- SSA 节点
- 完整数据流对象

---

### `pub fn new(space
: AddressSpace, offset: u64, size: usize) -> Self`

创建一个新的 `VarnodeRaw`。

#### 参数
- `space`: 地址空间
- `offset`: 空间内偏移
- `size`: 字节大小

#### 作用
这是 raw 阶段最基础的 varnode 构造入口，用于表达：

- 一个寄存器输入
- 一个常量输入
- 一个 unique 临时值
- 一个内存 / 栈槽位置

#### 使用语义
它适合用于：

- lifting 阶段直接构造输入输出
- builder 模式中补充操作数
- decode 后恢复出原始节点描述

---

### `pub fn to_varnode_data(&self) -> VarnodeData`

将 `VarnodeRaw` 转换为更正式或更统一的数据表示。

#### 作用
这个接口说明 `VarnodeRaw` 并不是完全孤立的临时结构，而是和后续 `Varnode` 相关的数据模型有连接点。

#### 典型用途
- 在注入前做结构转换
- 与更正式的 varnode 数据结构对接
- 在中间阶段做标准化表示

#### 边界
它不等于“直接进入正式图节点”，更像是：

> raw 节点到统一数据表示之间的转换入口

---

## `pub struct PcodeOpRaw`

`PcodeOpRaw` 是本模块最核心的类型，表示一条原始 P-code 操作。

### 角色
它承担的职责包括：

- 保存 opcode
- 保存输入列表
- 保存可选输出
- 保存序号 / 地址锚点
- 保存行为标志
- 为后续 `Funcdata::inject_raw_ops(...)` 提供注入源

### 当前最准确的理解
请把 `PcodeOpRaw` 理解为：

> “一条还没有进入正式函数级图结构的原始语义操作”

它不是：

- 正式 `PcodeOp`
- 最终 AST 节点
- 最终 C 语句
- 已完成 CFG/SSA 组织的操作节点

它的本质是“桥接表示”。

---

### `pub fn new(opcode: i32) -> Self`

创建一条新的 raw p-code 操作。

#### 参数
- `opcode`: 原始操作码

#### 作用
这是最基础的构造入口，用于建立一条原始语义操作记录。

#### 当前语义
创建后通常还需要进一步补充：

- 输入
- 输出
- 序号
- 行为标志

所以它只是“原始操作壳”的开始，而不是完整操作的结束。

---

### `pub fn add_input(&mut self, varnode: VarnodeRaw)`

向当前 raw 操作追加一个输入节点。

#### 作用
用于构造该操作的输入列表。

#### 典型场景
- lifting 阶段按语义顺序逐个添加输入
- builder 模式底层支撑
- decode 后重建输入列表

#### 重要性
输入顺序通常具有语义意义，因此调用时应保持：

- 顺序稳定
- 槽位语义明确
- 与 opcode 期望输入数相匹配

---

### `pub fn clear_inputs(&mut self)`

清空当前 raw 操作的所有输入。

#### 作用
用于重置或重建输入列表。

#### 适用场景
- 解析失败后的回退
- 重写 raw 操作
- decode / builder 中重新装配输入

#### 注意
这个接口只影响 raw 阶段的输入集合，不应被误解为“正式图中输入关系已同步清理”。

---

### `pub fn get_opcode(&self) -> i32`

获取当前 raw 操作的 opcode。

#### 作用
用于：

- 调试输出
- 规则分支
- decode / encode 检查
- 转正式 `PcodeOp` 前的判定

#### 注意
这里的 opcode 是 raw 层面的操作标识，不等同于已经完成高层语义分类。

---

### `pub fn set_opcode(&mut self, opcode: i32)`（2026-08-27 新增）

RUDRA-GLUE 变更器：`Funcdata::overrideFlow` raw 层传输
（funcdata_op.cc:991-1020 的 `opSetOpcode` 表）需要原地改写 raw op 的
opcode（BRANCH→CALL 等）。Ghidra 在块形成前直接改 dead `PcodeOp`；Rudra
的注入路径在 `inject_raw_ops` phase-1 创建 `PcodeOp` 之前改写 raw op，
builder API 只覆盖整 op 构造，故补此 setter。消费方：
`Funcdata::apply_flow_overrides_raw`（见 docs/api/funcdata.md 同日节）。

---

### `pub fn num_input(&self) -> usize`

返回当前 raw 操作的输入数量。

#### 作用
用于：

- 检查构造是否完整
- 构造阶段做防御式判断
- 注入阶段预判槽位数量
- 调试和验证

---

### `pub fn inputs(&self) -> &[VarnodeRaw]`

返回当前 raw 操作的输入切片。

#### 作用
供调用方读取所有输入节点，而不需要逐个索引访问。

#### 典型用途
- 注入 `Funcdata` 前遍历输入
- 调试打印
- encode / decode
- 对拍和差异分析

---

### `pub fn set_output(&mut self, varnode: VarnodeRaw)`

设置当前 raw 操作的输出节点。

#### 作用
用于给当前操作附加结果节点。

#### 注意
不是所有操作都一定有输出，例如控制流相关操作可能没有普通意义上的输出。

#### 当前边界
这一步只是设置 raw 阶段的输出信息，并不等于正式图中的 def-use 关系已经建立。

---

### `pub fn output(&self) -> Option<&VarnodeRaw>`

获取当前 raw 操作的输出节点。

#### 返回
- `Some(...)`: 有输出
- `None`: 当前操作无输出

#### 作用
便于调用方在注入前检查该操作是否产出结果值。

---

### `pub fn set_seq_num(&mut self, seqnum: SeqNum)`

设置当前 raw 操作的序号锚点。

#### 作用
为 raw 操作附加“地址 + 顺序”定位信息。

#### 为什么重要
因为在进入正式图结构前，系统仍需要知道：

- 这条 raw 操作属于哪条指令
- 在同一地址下是第几条展开出来的微操作

这对于后续：

- 转为正式 `PcodeOp`
- 建立 block 边界
- 关联调试信息
- 做顺序敏感分析

都很关键。

---

### `pub fn seq_num(&self) -> Option<SeqNum>`

获取当前 raw 操作的序号。

#### 返回
- `Some(seq)`: 已设置序号
- `None`: 尚未设置

#### 作用
供注入和调试阶段读取顺序锚点。

#### 注意
没有 `SeqNum` 的 raw 操作，通常意味着它还处在“不完整构造”状态。

---

### `pub fn set_behavior(&mut self, behavior: u32)`

设置行为标志。

#### 作用
为 raw 操作附加额外语义信息或行为属性。

#### 可能用途
- 标记特殊控制流
- 标记间接行为
- 标记某些低层操作属性
- 为注入或后续分类提供辅助信息

#### 注意
这类 behavior 标志通常是过渡层语义，不应直接被当作最终高层语义恢复结论。

---

### `pub fn behavior(&self) -> u32`

获取当前行为标志。

#### 作用
供注入、调试或分类判断使用。

---

### `pub fn decode(s: &str) -> Option<Self>`

从字符串格式解码出一个 `PcodeOpRaw`。

#### 作用
这是一个非常有用的桥接接口，说明 `PcodeOpRaw` 不只是内存对象，还具备：

- 文本交换
- 调试导出/导入
- 测试样例构造
- 轻量序列化表达

#### 典型用途
- 从测试字符串恢复 raw 操作
- 从日志或快照文本重建 raw 记录
- 快速构造小型验证样本

#### 当前边界
这不等于“完整序列化体系已成熟”，但它是 raw 层很有价值的调试和测试入口。

---

### `pub fn encode(&self) -> String`

将当前 `PcodeOpRaw` 编码为字符串。

#### 作用
与 `decode(...)` 成对，便于：

- 调试打印
- 生成快
照
- 对比实验
- 日志归档
- 手工测试样例制作

#### 价值
这说明 raw 层是当前做：

- 轻量调试
- 差异比较
- 简单回归样例

的一个很好入口。

---

## `pub struct PcodeOpRawBuilder`

`PcodeOpRawBuilder` 是构造 raw 操作的 builder 类型。

### 角色
它的意义在于让调用方可以更自然地按链式方式构造一条 raw 操作，例如：

- 先定 opcode
- 再加 output
- 再加多个 input
- 再加 seq_num
- 再加 behavior
- 最后 `build()`

### 为什么需要 builder
raw 操作通常包含多个可选部分，直接用大量可变方法堆叠时可读性较差。  
builder 模式能提高：

- 可读性
- 测试构造便利性
- 原始语义样例的表达性

---

### `pub fn new(opcode: i32) -> Self`

创建一个新的 raw 操作 builder。

#### 作用
作为链式构造入口。

---

### `pub fn output(mut self, space: AddressSpace, offset: u64, size: usize) -> Self`

设置输出节点。

#### 作用
用更紧凑的方式在 builder 中定义输出。

---

### `pub fn input(mut self, space: AddressSpace, offset: u64, size: usize) -> Self`

追加一个输入节点。

#### 作用
在 builder 链式调用中添加输入。

#### 典型意义
这对写测试或手工构造小型 p-code 样本特别方便。

---

### `pub fn seq_num(mut self, addr: Address, order: u32) -> Self`

设置序号锚点。

#### 作用
在 builder 链中补充地址与顺序信息。

---

### `pub fn behavior(mut self, behavior: u32) -> Self`

设置行为标志。

#### 作用
在 builder 构造链中补充行为属性。

---

### `pub fn build(self) -> PcodeOpRaw`

完成构造，返回最终的 `PcodeOpRaw`。

#### 作用
将 builder 中累计的信息收敛为一条完整 raw 操作。

#### 边界
“build 成功”只表示 raw 层对象构造完成，不等于：

- 已注入 `Funcdata`
- 已转为正式 `PcodeOp`
- 已建立 CFG / SSA
- 已能直接输出高层
语义

---

## 当前主线中的真实作用：作为 `Funcdata` 的桥

这是本文件最重要的一点。

当前 `pcoderaw.rs` 的现实意义，不在于“单独形成一个完整子系统”，而在于：

> 它是当前主线里最关键的桥接层之一，负责把 lifting 阶段的原始语义，稳定送入 `Funcdata::inject_raw_ops(...)`

因此，理解 `pcoderaw.rs` 时，建议始终连着看：

- `docs/api/funcdata.md`
- `docs/api/op.md`
- `docs/api/varnode.md`

更具体地说，这一层的桥接作用体现在：

1. `VarnodeRaw` 提供 raw 阶段最小节点表示  
2. `PcodeOpRaw` 提供 raw 阶段最小操作表示  
3. `PcodeOpRawBuilder` 提供方便构造路径  
4. `Funcdata::inject_raw_ops(...)` 将这些 raw 对象转为正式图对象

所以它是：

- 当前主线的重要桥
- 但不是当前主线的终点

---

## 当前文档建议口径

后续其它文档如果需要引用 `pcoderaw.rs`，建议使用以下表述。

### 推荐表述
- “`pcoderaw.rs` 是原始 P-code 表示层”
- “它负责承接 lifting 阶段的语义结果”
- “它是进入 `Funcdata` 的桥接层”
- “它表达的是 raw 操作，不是最终正式 IR”
- “它适合做调试、快照、测试样例和注入准备”

### 不推荐表述
- “`pcoderaw.rs` 就是当前完整 P-code 主线”
- “raw p-code 已经等同于正式 IR”
- “有 `PcodeOpRaw` 就说明 lifting 已和 Ghidra 一致”
- “该层已经独立完成 CFG / SSA / 输出”
- “只要 raw 层存在，端到端主线就已完全打通”

---

## 风险与限制提示

### 1. raw 层不等于正式 IR
`PcodeOpRaw` 和 `VarnodeRaw` 是过渡表示，不应与 `PcodeOp`、`Varnode` 混为一谈。

### 2. 有桥接层不等于 bridge 已完全验证
即使 `Funcdata::inject_raw_ops(...)` 存在，也不能据此直接宣称整个 raw → formal IR 转换已经与 Ghidra 一致。

### 3. encode/decode 适合调试，不等于完整序列化系统
它们很有价值，但不应被夸大成成熟的持久化/交换协议。

### 4. raw 操作构造成功不等于分析完成
raw 层只解决“如何表达原始语义”，不解决后续 SSA、类型恢复、变量恢复和高层输出问题。

---

## 推荐联动阅读

建议继续阅读：

- `funcdata.md`
- `op.md`
- `varnode.md`
- `disasm/mod.md`
- `printc.md`
- `../data_contract.md`
- `../VERIFICATION_GUIDE.md`

推荐顺序：

1. `disasm/mod.md`
2. `pcoderaw.md`
3. `funcdata.md`
4. `op.md`
5. `varnode.md`
6. `printc.md`

---

## 一句话总结

`pcoderaw.rs` 是 Rudra 当前主线中的 **raw p-code 桥接层**：  
它用 `VarnodeRaw` 和 `PcodeOpRaw` 承接 lifting 阶段的原始语义结果，并把这些结果以可注入、可调试、可构造的形式送入 `Funcdata`，为后续正式图结构、分析动作和输出链路提供输入基础。
<!-- annotation-pass: 2026-07-04 -->
