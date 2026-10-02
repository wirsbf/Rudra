# `op.rs` API Reference

**源代码路径**: `src/op.rs`

## 文档状态

- **状态**: 已核对（当前有效）
- **文档目标**: 解释 Rugra 当前 `PcodeOp` 相关结构、标志位和操作银行的职责
- **可信边界**: 本文以当前 `src/op.rs` 所体现的 **P-code 操作结构建模** 为核心，不再沿用旧式“完整旧架构已稳定可用”的写法
- **阅读方式**: 请结合以下文件一起看：
  - `src/op.rs`
  - `src/opcodes.rs`
  - `src/varnode.rs`
  - `src/address.rs`
  - `src/funcdata.rs`
  - `docs/data_contract.md`

> 若本文与源码不一致，应以当前源码为准，并优先修正文档。

---

## 模块定位

`op.rs` 是 Rugra 当前 **P-code 操作层** 的核心模块之一，主要负责：

1. 定义单条 P-code 操作的结构表示：`PcodeOp`
2. 定义与操作状态相关的一组位标志（flags）
3. 提供操作引用包装类型：`PcodeOpRef`
4. 提供操作片段/拼接分析辅助结构：`PieceNode`
5. 提供操作容器：`PcodeOpBank`

它在整体链路中的位置大致是：

- `pcoderaw.rs` 表示更原始的、接近 lifting 输出的操作
- `op.rs` 表示进入图结构后的正式操作对象
- `funcdata.rs` 将这些对象组织到单函数分析上下文中
- `heritage.rs`、`action.rs`、`ruleaction.rs` 等在此基础上做 SSA、重写和分析
- `printlanguage.rs` / `printc.rs` 最终消费这些结构并生成文本输出

---

## 与 Ghidra 的关系

本文档中涉及的核心类型主要对应 Ghidra 的：

- `op.hh`
- `PcodeOp`
- `PcodeOpBank`
- 若干与操作属性相关的 flag 语义

但需要明确：

- **结构命名接近 Ghidra，不等于运行时行为已经与 Ghidra 完全一致**
- 本模块当前应被理解为 **Rugra 的现行操作层建模基础**
- 与 Ghidra 的“行为级一致性”仍需依赖单独的验证与对拍文档，而不是由 API 文档直接证明

---

## 核心设计思路

`op.rs` 的关注点不是“如何直接生成 C 代码”，而是如何为函数级分析提供一个可变换、可追踪、可链接的操作图层。

它解决的问题包括：

- 一条 P-code 操作如何保存 opcode、输入、输出、时序信息
- 如何标记这条操作是否为：
  - 分支
  - 调用
  - 已死亡
  - 布尔输出
  - 不可折叠
  - 间接来源
  - 非打印节点
- 如何将操作对象放进容器统一管理
- 如何在重写、DCE、SSA、结构恢复过程中追踪这些对象

---

## 公共 API 总览

当前本文重点覆盖以下公共项：

- `TypeOp`
- 一组公开的操作标志常量
- `IopSpace`
- `PcodeOp`
- `PcodeOpRef`
- `PieceNode`
- `PcodeOpBank`

---

## 1. `TypeOp`

### `pub struct TypeOp`

`TypeOp` 是与操作类型语义相关的结构体。

### 当前文档口径

从当前模块职责来看，`TypeOp` 更适合被理解为：

- 操作语义分类/行为支持的基础类型
- 与 opcode 的高级语义或类别信息有关
- 为更高层的分析或规则处理提供辅助

### 说明

由于当前公开文档中缺少更详细的源码注释，本文不把它夸大描述为完整稳定的“行为数据库”或“完全对齐 Ghidra 的语义工厂”。

更保守的理解是：

- 它属于操作语义层的一部分
- 它可能参与操作类别、属性或行为推断
- 具体字段和使用方式应以 `src/op.rs` 实现为准

---

## 2. 操作标志位常量（flags）

`op.rs` 公开了一大组 `u32` 标志位常量，用于描述一条 `PcodeOp` 的属性状态。

这些常量本质上属于：

- **位掩码（bit flags）**
- **操作元信息**
- **规则系统和打印系统的判定依据**

### 标志位的作用

这些标志不是“单独的业务对象”，而是用来回答类似问题：

- 这条操作是不是分支？
- 这条操作是不是调用？
- 这条操作是不是已经被标记为 dead？
- 这条操作是否有布尔输出？
- 这条操作是不是不可折叠？
- 这条操作是不是特殊控制流节点？
- 这条操作是不是仅用于内部分析、不应出现在最终打印中？

### 当前公开常量

- `STARTBASIC`
- `BRANCH`
- `CALL`
- `RETURNS`
- `NOCOLLAPSE`
- `DEAD`
- `MARKER`
- `BOOLOUTPUT`
- `BOOLEAN_FLIP`
- `FALLTHRU_TRUE`
- `INDIRECT_SOURCE`
- `CODEREF`
- `STARTMARK`
- `MARK`
- `COMMUTATIVE`
- `UNARY`
- `BINARY`
- `SPECIAL`
- `TERNARY`
- `RETURN_COPY`
- `NONPRINTING`
- `HALT`
- `BADINSTRUCTION`
- `UNIMPLEMENTED`
- `NORETURN`
- `MISSING`
- `SPACEBASE_PTR`
- `INDIRECT_CREATION`
- `CALCULATED_BOOL`
- `HAS_CALLSPEC`
- `PTRFLOW`
- `INDIRECT_STORE`

---

### 标志位分组理解

虽然源码里这些是平铺的常量，但在阅读时可以按语义粗分：

#### A. 控制流相关
- `STARTBASIC`
- `BRANCH`
- `CALL`
- `RETURNS`
- `HALT`
- `NORETURN`
- `FALLTHRU_TRUE`

这类标志帮助回答：

- 是否会切分基本块
- 是否影响 CFG 边
- 是否代表函数调用/返回语义
- 是否是停止点

#### B. 生命周期与状态相关
- `DEAD`
- `MARKER`
- `MARK`
- `MISSING`
- `UNIMPLEMENTED`
- `BADINSTRUCTION`

这类标志帮助规则系统和错误处理识别：

- 节点是否还活着
- 节点是否为内部标记用途
- 节点是否由坏指令或未实现语义产生

#### C. 运算性质相关
- `COMMUTATIVE`
- `UNARY`
- `BINARY`
- `TERNARY`
- `SPECIAL`
- `BOOLOUTPUT`
- `BOOLEAN_FLIP`
- `CALCULATED_BOOL`

这类标志更偏操作语义，用于：

- 简化匹配
- 规则分类
- 打印与表达式生成
- 条件逻辑推断

#### D. 间接/内存/调用语义相关
- `INDIRECT_SOURCE`
- `INDIRECT_CREATION`
- `INDIRECT_STORE`
- `HAS_CALLSPEC`
- `SPACEBASE_PTR`
- `PTRFLOW`
- `RETURN_COPY`
- `CODEREF`

这类标志常用于更高层分析，例如：

- 间接引用
- 指针流
- 调用语义
- 返回值复制
- 地址/代码引用识别

#### E. 输出与显示控制相关
- `NONPRINTING`
- `NOCOLLAPSE`

这类标志偏向表示层或规则约束层，帮助决定：

- 某些节点是否适合进入最终文本输出
- 某些节点是否可以被折叠、合并或简化

---

### `pub fn opcode_flags(opc: OpCode) -> u32`

Ghidra: `typeop.cc` 各 `TypeOpXxx::TypeOpXxxx` 构造函数体中的 `opflags = ...` 赋值（约 70 个 ctor）。Rugra 无 `TypeOp` 层，本函数作为 `TypeOp::getFlags()` 的等价替代。

#### 语义
对每个 `CPUI_*` 变体返回对应的 TypeOp 衍生标志位（`unary`/`binary`/`ternary`/`special`/`branch`/`call`/`coderef`/`returns`/`nocollapse`/`marker`/`booloutput`/`commutative`/`has_callspec`/`return_copy`）。每个 match arm 标注了对应 typeop.cc 的 ctor 行号。

#### 示例映射
| CPUI_* | opflags | 来源 |
|---|---|---|
| `CPUI_INT_ADD` | `binary | commutative` | typeop.cc:1170 |
| `CPUI_INT_EQUAL` | `binary | booloutput | commutative` | typeop.cc:927 |
| `CPUI_INT_ZEXT` | `unary` | typeop.cc:1118 |
| `CPUI_BOOL_NEGATE` | `unary | booloutput` | typeop.cc:1694 |
| `CPUI_CALL` | `special | call | has_callspec | coderef | nocollapse` | typeop.cc:663 |
| `CPUI_MAX` | `0`（sentinel 非真实 opcode） | opcodes.rs:91 |
| `CPUI_INT_LEFT` | `binary`（**非** commutative，易误判） | typeop.cc:1505 |
| `CPUI_INT_DIV` | `binary`（**非** commutative，易误判） | typeop.cc:1645 |
| `CPUI_INT_CARRY` | `binary | commutative | booloutput` | typeop.cc:1335 |

#### 用途
供 `set_opcode_flags`、`create`、`change_opcode` 在设置 opcode 时一次性写入所有 TypeOp 衍生标志，保证 `get_eval_type()` / `is_commutative()` / `is_bool_output()` 等下游查询正确。

---

### `pub fn set_opcode_flags(&mut self, opc: OpCode)`

Ghidra: `op.cc:276 PcodeOp::setOpcode`。清空 14 位 opcode-衍生标志（含 `COMMUTATIVE`），然后 `flags |= opcode_flags(opc)`。同时设置 `self.opcode = opc`。

#### 用途
为给定 opcode 一次性设置所有衍生的标志位。Rugra 无 TypeOp 层，故将 Ghidra 的 `flags |= t_op->getFlags()` 替换为查表 `opcode_flags(opc)`。

---

## 3. `IopSpace`

### `pub struct IopSpace`

`IopSpace` 对应 Ghidra 中 `op.hh` 的相关概念。

它更适合被理解为：

- 与 P-code 操作引用或内部操作空间有关的辅助结构
- 为某些特殊操作节点或间接操作标识提供命名/空间支撑

### `pub const NAME: &'static str = "iop"`

这是 `IopSpace` 暴露的名称常量。

### 语义理解

`"iop"` 一般可理解为：

- internal op / indirect op 之类的内部命名空间
- 用来给某类“不是普通 RAM / register / unique”的操作相关对象提供可识别标签

### 注意事项

在当前文档层面，不应把 `IopSpace` 夸大解释为完整独立的“通用地址空间体系”或“最终用户可感知空间”。

它更像：

- 内部语义工具
- 用于支持 IR / op 级建模
- 不直接面向最终 C 代码使用者

### 2026-08-23：RULE-PORT-COLLAPSECONSTANTS-0001（collapse 走 TypeOp evaluate 桥）

`PcodeOp::collapse()`（cc:450-472）的求值路径从直接调 `opbehavior::{evaluate_unary,
evaluate_binary}` 改为经 `typeop::{evaluate_unary, evaluate_binary}` 桥（typeop.hh:
81-92 的 Rust 对应物），对齐 Ghidra 分层 `PcodeOp::collapse -> TypeOp::evaluate* ->
OpBehavior::evaluate*`。行为差异仅 FLOAT_*：此前 FLOAT 族在自由函数表里返回 None
（即被当作"不可折叠"），现在经桥完成 `OpBehaviorFloat*::evaluate*`（opbehavior.cc:
569-750）的 `getFloatFormat(sizein/sizeout)` 查找 + `FloatFormat::op*` 求值；
缺格式（如 2 字节浮点）依旧 None → RuleCollapseConstants 的 opMarkNoCollapse
错误路径。`is_collapsible`（cc:115-125）与 `collapse_constant_symbol`
（cc:503-540）本就存在，本次仅修正 `collapse_constant_symbol` 上方一条错挂的
`isCollapsible` 文档注释（其真正落位在 op.rs `is_collapsible`）。

### 2026-08-17：SPACE-IOP-PRINTRAW-0001（Ghidra op.cc:41-59 IopSpace::printRaw）

`IopSpace` 新增 `print_raw(offset) -> Option<String>`（op.cc:41 的 Rust 落位，
Ghidra 虚派发对应物；`space::AddrSpace::print_raw` 的 `SpaceType::Iop` 分支为同
残差登记的内联回落，解阻塞后同 wave 接上本函数）。Ghidra 语义：offset 即
`(PcodeOp *)(uintp)offset`（op.cc:46，`Funcdata::newVarnodeIop` 的同一编码，
Rugra 侧为 `Arc::as_ptr` 数据指针）；非分支 op 打印其 `SeqNum`（address.cc:32：
`pc.printRaw` + `':'` + uniq/time，ostream 粘滞 hex 故 uniq 为无填充小写 hex）；
分支 op 打印非落 fall-thru 目标块 `code_` + 目标块起始地址空间 shortcut + 起始
地址 printRaw（父块 `sizeOut()==2` 时 `isFallthruTrue() ? getOut(0) : getOut(1)`，
否则 `getOut(0)`）。

配套新增 `PcodeOp::is_fallthru_true`（op.hh:193，`flags & fallthru_true`）。

当前状态（登记残差 `SPACE-IOP-PRINTRAW-0001`，见 docs/TODO_BOARD.md）：两种终态
渲染均被 legacy 无空间地址模型阻塞——`SeqNum.addr`（address.rs）与
`BlockBasic::start_addr`（block.rs；flow.rs:1918 赋标量形态）均不携带空间句柄，
`pc.printRaw` 的宽度/wordsize 缩放与 `getShortcut()` 不可从 op 导出；阻塞链
ADDRESS-0001（`src/address.rs` 现由 CSPEC-RANGEPROPS-0001 租约中）。落地前
`print_raw` 对两种形式返回 `None`，space.rs 派发臂内联回落 base
`AddrSpace::print_raw`（与特化引入前的可观察行为一致，且 space.rs 保持独立编译、
不依赖本函数，避免破坏按旧 base 钉住的 registry-overlay runner），iop 字节级形式
不在 `tests/oracle/space_printraw_special_1204` fixture 覆盖内。

---

## 4. `PcodeOp`

### `pub struct PcodeOp`

`PcodeOp` 是本模块最核心的类型，表示 **一条正式进入 Rugra IR 图结构的 P-code 操作**。

它承担的核心职责包括：

- 保存该操作的 `OpCode`
- 保存该操作的输入列表
- 保存可选输出
- 保存操作时序锚点 `SeqNum`
- 保存与标志位相关的状态
- 为后续：
  - SSA
  - def-use
  - DCE
  - 规则重写
  - CFG/结构化打印
  提供操作级访问入口

### 核心语义

可以把 `PcodeOp` 理解为：

> “图中的一条带有输入、输出、时序和语义类别的操作节点。”

它不是：

- 原始 lifting 结果本身（那更接近 `PcodeOpRaw`）
- 最终高层 AST 节点
- 直接面向用户的 C 代码语句

它是 Rugra 当前反编译分析主链路中的 **正式 IR 操作节点**。

---

### `pub fn new(start: SeqNum, opcode: OpCode) -> Self`

创建新的 `PcodeOp`。

#### 参数
- `start`: 该操作的时序/地址锚点
- `opcode`: 操作码

#### 返回
- 一个新的 `PcodeOp`

#### 作用
这是最基础的构造入口，用于在图中创建一条操作记录。

#### 约束理解
新建后的 `PcodeOp` 一般还需要进一步补充：

- 输入
- 输出
- 标志状态
- 图中链接关系

因此它是“节点创建起点”，不是“完整操作生命周期的终点”。

---

### `pub fn get_opcode(&self) -> OpCode`

获取当前操作的操作码。

#### 用途
常用于：

- 分析分支
- 规则匹配
- 打印阶段判断
- 分类判断（算术、控制流、调用、比较等）

---

### `pub fn get_addr(&self) -> Address`

获取该操作关联的地址。

#### 语义
这是从操作的时序锚点中提取出的地址语义，用于：

- 调试
- 查找
- 报错定位
- CFG / block 相关逻辑

#### 注意
这里的地址是 IR 操作关联的地址锚点，不应简单理解为“源码行号”或“最终语句地址”。

---

### `pub fn get_seq_num(&self) -> &SeqNum`

获取该操作的完整序号对象。

#### 用途
比 `get_addr()` 更完整，因为 `SeqNum` 通常还包含：

- `get_time()`：不可变创建身份，供 `PcodeOpBank::optree`、序列化引用和
  varnode 定义点使用；
- `get_order()`：块内可变执行次序，只用于控制流位置比较。

### `pub fn get_time(&self) -> u32`

返回不可变创建身份，对应锁定 oracle `PcodeOp::getTime`。对 op 做
`setOrder` 或 block 重编号不会改变该值。

- 地址
- 顺序
- 时间/局部序

这对同一机器指令展开出多条 P-code 时尤其重要。

---

### `pub fn num_input(&self) -> usize`

返回输入数量。

#### 用途
常用于：

- 操作分类
- 规则匹配
- 防御式遍历
- 打印表达式时检查输入是否合法

---

### `pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>>`

获取指定输入槽位的输入 `Varnode`。

#### 参数
- `slot`: 输入位置索引

#### 返回
- 对应输入 varnode 的只读引用包装，若不存在则返回 `None`

#### 说明
之所以返回带锁的共享引用，说明当前 Rugra 的操作对象与 varnode 对象是图式共享结构，而不是简单值复制。

---

### `pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>>`

获取输出 `Varnode`。

#### 返回
- 若该操作有输出，则返回输出节点
- 否则返回 `None`

#### 说明
不是所有操作都有输出，例如某些控制流类操作就可能没有普通意义上的输出 varnode。

---

### `pub fn is_dead(&self) -> bool`

判断该操作是否被标记为 dead。

#### 语义
通常用于：

- 死代码消除
- 清理阶段
- 打印过滤
- 规则跳过

#### 注意
“dead” 是操作生命周期状态，不等于对象已经物理销毁。

---

### `pub fn is_call(&self) -> bool`

判断该操作是否具有调用语义。

#### 用途
可用于：

- 调用恢复
- 参数与返回值分析
- 打印阶段生成调用表达式

---

### `pub fn is_branch(&self) -> bool`

判断该操作是否具有分支语义。

#### 用途
可用于：

- 基本块切分
- CFG 边构建
- 结构化控制流恢复

---

### `pub fn is_moveable(&self, point: &PcodeOp, bank: &PcodeOpBank) -> bool`

Ghidra: `op.cc:178 PcodeOp::isMoveable`。判断该操作是否可在所属基本块内移动越过 `point` 操作（同一父块内），不改变语义。

#### 决定性语义
- **引用/输出参数**: `&self` + `&point` + `&PcodeOpBank`（bank 仅为调用点兼容保留，Ghidra 方法只读 `basiciter`/`parent`）全程只读；`crossed_ops: Vec<PcodeOpRef>` 共享所有权（等价 Ghidra `basiciter` 游走的 op 指针）；`tied_list: Vec<Arc<RwLock<Varnode>>>`（等价 Ghidra `vector<const Varnode*>`）。
- **遍历顺序**: 解析 parent `BlockBasic::ops`（块序）中 self 与 point 的索引，遍历 `ops[self_idx+1..=point_idx]`——严格后于 self 到 **含 point** 的闭区间，块序。等价 Ghidra 的 `biter = basiciter; do { ++biter; ... } while (biter != point->basiciter)` block-local 遍历。**不是** alivelist（markAlive 追加序，op.cc:1022）：块中段重插/move 后与块序发散（OP-ISMOVEABLE-WALKORDER-0001）。point 先于 self 时 Ghidra 越界 UB，Rugra fail-closed 返回 false；索引缺失（Rust 侧异常态）同样 fail-closed。
- **计数器**: `cross_calls`（普通 op，输出+所有输入均非 addr-tied/persist 时 true）、`moving_load`（LOAD special op）、`tied_list`（addr-tied 输入集合）。
- **排序/比较键**: `Arc::ptr_eq` 比对 parent 身份（替代 Ghidra 裸指针 `!=`）；`basic_block_index` 按 `PcodeOp` 对象地址在块 ops 中定位（替代 Ghidra `basiciter` O(1) 迭代器，O(块长) 代价、可观测语义恒等）；`readOp->start.getOrder() <= point->start.getOrder()` 判输出被过早读；`op->getEvalType()==special` 后按 `op->code()` switch（LOAD/STORE/INDIRECT/SEGMENTOP/CPOOLREF/CALL/CALLIND/NEW）；`vn->overlap(*op_output)>=0 && op_output->overlap(*vn)>=0` 判 addr-tied 重叠。

#### 跨越规则（switch 各 case）
| 被 cross 的 op | 返回 false 的条件 |
|---|---|
| LOAD | 输出 addr-tied |
| STORE (movingLoad) | 总是 false |
| STORE (非 movingLoad) | tiedList 非空 OR 输出 addr-tied |
| INDIRECT/SEGMENTOP/CPOOLREF | 通过 |
| CALL/CALLIND/NEW | !crossCalls |
| 其他 special | 总是 false |

非 special op 的输出若 addr-tied 或与 tiedList 中某 vn 互含（overlap>=0），返回 false。

#### 用途
用于：
- `BlockWhileDo::finalTransform` 的 iterate/initialize 终端搬移门（block.cc:3389-3396 两个调用点，point 均为所在块 lastOp；Rugra 消费方 `block.rs` `while_do_final_transform`）
- SSA 优化中操作重排
- 跨操作 dead-code/merge 分析
- INDIRECT 围绕操作的合法性判断

---

### `pub fn previous_op_in_block(&self, bank: &PcodeOpBank) -> Option<PcodeOpRef>`

Ghidra: `op.cc:344 PcodeOp::previousOp`。返回在同一基本块内紧邻本 op 之前的 op；本 op 是块首时返回 `None`。搜索范围**不越过所属基本块**。

#### 决定性语义
- **引用/输出参数**: `&self` 只读；Ghidra 版本无 bank 参数（只读 `basiciter`/`parent`），Rugra 保留 `bank` 参数仅为既有调用点签名兼容，函数体不使用它。
- **遍历顺序**: **父块 op 列表序（`BlockBasic::ops` 的下标序，等价 Ghidra `basiciter` 前驱）**，不是 `alivelist` 的 mark-alive 追加序。`op_insert_before` 晚插入的 op（如 INDIRECT guard）位于块中部但 alivelist 尾部——本函数必须返回它。
- **计数器**: 无计数器/累加器。
- **排序/比较键**: 用 `PcodeOp` 对象地址（`&*guard as *const PcodeOp`）在父块 `ops` 中定位自身下标（等价 Ghidra 裸 `PcodeOp*` 身份）；下标为 0（块首）返回 `None`，否则返回 `ops[index-1]`。

#### 注意
- 死 op / 未挂块 op（`parent == None`）返回 `None`；Ghidra 对 dead op 读 stale `basiciter` 是未定义行为，Rugra 以安全 `None` 收敛（调用方约定只在 alive op 上调用，与 Ghidra 调用点一致）。
- Ghidra 的 `basiciter` 是 O(1) 存储迭代器；Rugra 按地址重算下标为 O(块大小)，可观察语义一致。
- Oracle fixture: `tests/oracle/op_previous_block_order_1204.*`（runner `tools/run_op_previous_block_order_oracle.sh`，状态 MATCH）。

---

### `pub fn next_op_in_flow(&self, bank: &PcodeOpBank) -> Option<PcodeOpRef>`

Ghidra: `op.cc:323 PcodeOp::nextOp`。返回流程上紧随本 op 的下一个 op：通常是同块内后继；本 op 是块内最后一个 op 时，沿 out 边 0（fall-thru）进入后继块取其首 op，**仅当本块出度恰为 1 或 2**（`op.cc:334`）；出度为 0 或 ≥3 时返回 `None`。

#### 决定性语义
- **引用/输出参数**: `&self` 只读；`bank` 参数同上仅签名兼容，不参与计算。
- **遍历顺序**: 先父块 op 列表 `index = 自身下标 + 1`（等价 `basiciter++`）；命中块尾（`index == ops.len()`，等价 `iter == p->endOp()`）时循环检查 `size_out() ∈ {1,2}`，否则返回 `None`；满足则 `p = get_out(0).point`，`index = 0`（等价 `iter = p->beginOp()`）继续。
- **计数器/状态机**: 循环变量 `p`（当前块）与 `index`（块内下标），跨块时 `index` 重置为 0；无其他累加器。
- **排序/比较键**: 同 `previous_op_in_block`——`PcodeOp` 对象地址定位自身下标；出边选择固定 `get_out(0)`（Ghidra `p->getOut(0)`）。

#### 注意
- 出度 ≥3（switch 块）与出度 0（末端块）都终止搜索返回 `None`。
- 后继块为空块时与 Ghidra 一样继续沿其后继搜索（忠实移植 `while` 循环）。
- Oracle fixture: 同上 `op_previous_block_order_1204.*`（`edges` 阶段覆盖 sizeOut=2 穿越、sizeOut=3 拒绝）。

---

## 5. `PcodeOpRef`

### `pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>)`

这是对 `Arc<RwLock<PcodeOp>>` 的包装类型。

### 作用

它的主要作用是：

- 让 `PcodeOp` 的共享引用更方便进入集合或银行结构
- 统一操作对象在容器层的引用形式
- 避免在上层接口中到处直接暴露底层锁包装类型

### 为什么需要包装

因为当前 Rugra 的 IR 不是简单的树或线性列表，而是带有共享引用关系的图结构。  
`PcodeOpRef` 让以下事情更容易处理：

- 存入 bank
- 在多个分析阶段共享同一节点
- 做标记、销毁、替换时保留同一对象身份

---

## 6. `PieceNode`

### `pub struct PieceNode`

`PieceNode` 对应 Ghidra `op.hh` 中的相关结构，用于表示与“piece / 拼接 / 分片”语义有关的节点。

### 适合理解为

- 某种与操作局部片段有关的辅助结构
- 为分析复合数据拼接关系提供支持
- 在处理子片段、piece 合成、偏移等场景下使用

### 当前不要夸大理解的部分

在当前文档层面，不应把它描述成一个“完整的结构化表达式系统”或“通用 AST 片段节点”。

更保守的说法是：

- 它是 P-code 操作分析中的辅助节点
- 它与某个 `PcodeOp` 的弱引用、输入槽位和偏移量有关
- 它主要服务于内部 IR 级处理，而不是直接服务于最终 C 输出

---

### `pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self`

创建新的 `PieceNode`。

#### 参数
- `op`: 关联的操作弱引用
- `slot`: 所关联的输入槽位
- `offset`: 类型或片段偏移

---

### `pub fn is_leaf(&self) -> bool`

判断当前片段节点是否为叶子节点。

#### 用途
适合用于：

- 片段树/分解结构遍历
- 判断是否还能继续展开
- 递归处理终止条件

---

### `pub fn get_type_offset(&self) -> i32`

获取类型偏移量。

### `pub fn get_slot(&self) -> i32`

获取关联输入槽位。

这两个接口都属于 `PieceNode` 的基础查询接口，用于在片段分析中定位当前节点的上下文。

---

## 7. `PcodeOpBank`

### `pub struct PcodeOpTree`（2026-09-30 PERF-ARENA-FLIP-0001 (a) 更新；2026-09-29 PERF-ACTIONPOOL-ITER-0001 / OPTREE 原条）

`PcodeOpTree` 是 bank 主排序容器（`optree` 字段）的类型——**SeqNum 键化树，
oracle `map<SeqNum,PcodeOp*>`（op.hh:280）的原生同构形态**。

**2026-09-30 arena 形态**（PERF-ARENA-FLIP-0001 (a)，ARENA_DESIGN §1.2）:
内部容器翻转为 `BTreeMap<SeqNumKey, OpId>` + `Arena<OpCell, OpId>` 槽存储
（`OpCell { op: PcodeOpRef, seq_key: SeqNumKey }`）——键为 W0 冻结的 POD
`SeqNumKey { pc: SpaceOff, uniq }`（序 = `SeqNum::operator<` 投影, SpaceOff
镜像 `Address::operator<` 的 null-first/index/offset），值为类型化
`OpId` 句柄；`PcodeOp::op_id` 回指槽位，槽内 `seq_key` 副本 = oracle
存储 map 迭代器的 id 形态（`remove` 主路径按存储键删除；SeqNum 创建后
不可变故键副本永不漂移——ffi.rs:447 重赋值为等值 SeqNum）。**destroy/
destroy_dead 后槽保持占用**（= oracle deadandgone 保留语义, op.cc:984-999
"memory not reclaimed … in case pointer references still exist"），仅
`clear()` 真释放（gen+1, 陈旧句柄一律 None）。公共面不变:
`insert/remove/contains/len/is_empty/clear/iter/range/find_op/
target_lower_bound` + `&tree` IntoIterator + 新增 `get_by_id(OpId)`——
迭代序仍为 SeqNum 全序，元素仍逐个 yield `&PcodeOpRef`，action/heritage/
merge/comment/coreaction 与 funcdata 前转器全部调用形态零改动（funcdata
`begin_op_all`/`end_op_all` 返回类型随动为 `impl Iterator`）。

**键形态**：键为 `SeqNum` **值快照**（插入时一次短读锁取得），排序即
`SeqNum::operator<`（address.hh:154-158：先 `pc` 后 `uniq`；Rugra 对应
`Ord for SeqNum` = `(addr, time)`，不含可变的 `order` 字段）。树下降过程
只比较键值——**下降内部零 RwLock**。

**历史与动机**（OPTREE 车道, PERF-ACTIONPOOL-ITER-0001）: 原形态为
`BTreeSet<PcodeOpRef>`，其 `Ord for PcodeOpRef` 每次比较取两侧各一次
RwLock 读——规则池后继重建（`ActionPool` 的 advance, action.cc:871
`op_state++` 的 Rust 重建）每次下降付出 2 锁 × O(log n) 次比较（VdbeExec
极点 5,648,144 次 advance × ~894ns = 5.05s, OPPPOOL §0/§7 分票）。

**行为恒等契约**（vs 原 `BTreeSet<PcodeOpRef>`, OPTREE 红线 = 输出零变）:

- **迭代序恒等**：BTreeMap 以 SeqNum::cmp 排键——与原 `Ord for PcodeOpRef`
  投影（`self.start.cmp`）完全同一全序。
- **插入去重恒等（keep-first）**：原 `BTreeSet::insert` 在 cmp==Equal 时保留
  已存元素；`entry(key)` 键已存在时保留已存值。（oracle op.cc:945
  `optree[seq] = op` 是**替换**语义；重复键在 bank 创建路径不可达——uniqid
  单调且 create_with_seq 推进到给定 time 之后, op.cc:962-963——故差异
  bank 内不可观测。）
- **键不陈化**：键 = (addr,time) 快照，创建后不可变（仅 `set_order` 改
  `order`，排序不含它）。ffi.rs:447 重赋 `start` 为值恒等 SeqNum（create
  前捕获的同 addr/time），当前路径无就地键突变。

**API 面**（BTreeSet<PcodeOpRef> 兼容面 + oracle 形态访问器）:

- `new()` / `Default`
- `insert(PcodeOpRef) -> bool`（keep-first; BTreeSet::insert 返回形）
- `remove(&PcodeOpRef) -> bool`（键删除; op.cc:995 erase 对应）
- `contains(&PcodeOpRef) -> bool`（键存在性 = 原 Ord 等价存在性）
- `clear()` / `len()` / `is_empty()`
- `iter()` 与 `&PcodeOpTree: IntoIterator`——`for op in &bank.optree` 逐
  调用点零改（heritage/merge/funcdata/comment/flow/ffi/align/examples）
- `range((Bound<&PcodeOpRef>, Bound<&PcodeOpRef>))`——界翻译为键界（每界
  一次读锁），下降本身免锁；action.rs `next_op_after` 的
  `range((Excluded(current), Unbounded))` 调用点逐字节不变
- `find_op(&SeqNum) -> Option<&PcodeOpRef>`——op.cc:1102 `optree.find` 同构
  O(log n)（原为线性扫描,结果恒等）
- `target_lower_bound(Address)`——op.cc:1092 `lower_bound(SeqNum(addr,0))`
  同构（原线性扫描 `start.addr >= addr` 首命中恒等）

**oracle 迭代器差异（既有 ACTIONLOOP-RESTART-0001 记录,非本车道新增）**:
oracle 的 `++op_state` 是 std::map 节点迭代器 O(1) 均摊后继且跨插入/删除
稳定；Rust BTreeMap 迭代器不能跨 Rule 突变持有，故用严格后继 range 重建
同一访问序列。键化后该重建的下降成本与 oracle 键比较同阶（无锁）。

---

### `pub struct PcodeOpBank`

`PcodeOpBank` 是当前 Rugra 中 **统一管理 P-code 操作对象的容器**。

你可以把它理解为：

> “函数级 P-code 操作节点的银行/仓库/统一管理器”。

它通常承担：

- 创建操作
- 保存操作
- 查询操作
- 标记操作状态
- 修改 opcode
- 清理 dead 操作
- 销毁指定操作

在 Rugra 当前架构里，它通常会与以下对象协作：

- `Funcdata`
- `VarnodeBank`（若在其他模块中定义）
- `BlockBasic`
- `ActionDatabase`

---

### `pub fn new() -> Self`

创建空的 `PcodeOpBank`。

---

### `pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef`

创建一条新的操作并加入 bank。

#### 参数
- `opcode`: 操作码
- `num_inputs`: 输入数量
- `addr`: 操作关联地址

#### 返回
- 新建操作的引用包装 `PcodeOpRef`

#### 作用
这是 bank 层的统一创建入口，适合保证：

- 操作统一纳管
- 节点身份稳定
- 后续查找、标记和销毁一致

#### 说明
与 `PcodeOp::new` 相比，这个入口更偏“容器负责的创建与注册”。

---

### `pub fn create_with_seq(&mut self, opcode: OpCode, num_inputs: usize, seq: SeqNum) -> PcodeOpRef`（2026-09-28 CANON-DECLORDER-TRANSPORT-0001）

带显式 `SeqNum` 的 `create`：编号取 clone 形态（op.cc:957-969）的显式序号，创建侧状态
则保留本 bank `create` 的**全部**不变量——TypeOp 旗标（`set_opcode_flags`，算术类的
eval type 源）、code-list 注册（RETURN/LOAD/STORE/CALLOTHER，op.cc:881-900）、以及
历史 alivelist 插入契约（create ⇒ alive；Ghidra 推 deadlist，mark_alive/mark_dead 循环保
留区分）。uniqid 计数器仍按 op.cc:962-963 抬过显式序号，后续 `create` 的时间恒晚于本 op。

#### 用途
canon 线性传输的访序铸造入口：`Funcdata::inject_raw_ops_with_uniq` 用它把 SeqNum uniq 按
oracle FlowInfo 访问序钉入（`HighVariable::compareName` 的最早定义决胜键直读
`getDef()->getTime()`，variable.cc:485-486）。裸 `create_seq` 缺三半（旗标/列表/
alivelist），注入后 alivelist=0、RETURN 对 ActionReturnRecovery 隐身——不可直接使用。

---

### `pub fn mark_alive(&mut self, op: PcodeOpRef)`

将操作标记为活跃。

#### 用途
适用于：

- 恢复被误判的节点
- 重写后重新启用节点
- 生命周期管理

#### 尾部快速擦除（PERF-VARMAP-OPCREATE-0001，2026-09-29）

oracle `markAlive`（op.cc:1017-1022）经存储 `insertiter` 的 `deadlist.erase`
是 O(1)，随后 `alivelist.insert(end)`。Rust `Vec` 无存储句柄，原实现对整条
deadlist 做 `retain` 线性扫描（VdbeExec 峰值 dead 3.5K 条/次）。主流迁移形态
（create/markDead 紧接插入期 markAlive，无中间迁移）下 op 恰在 deadlist 尾部，
此时 `pop()` 完成同一次擦除且零扫描；非尾部（中段复活）保持原保序 `retain`，
两种路径的删除结果与其余元素相对序逐元素等价（== oracle 链表 erase 的结果序）。

---

### `pub fn mark_dead(&mut self, op: PcodeOpRef)`

将操作标记为死亡。

#### 用途
适用于：

- DCE
- 重写中替换旧节点
- 延迟清理策略

#### 尾部快速擦除（PERF-VARMAP-OPCREATE-0001，2026-09-29）

oracle `markDead`（op.cc:1028-1034）经存储 `insertiter` 的 `alivelist.erase`
是 O(1)，随后 `deadlist.insert(end)`。Rugra 原实现 `alivelist.retain` 全表扫描
——[OPCPROF] 实测 VdbeExec 单函数 207,611 次调用/5.58s/均值 32.6K 元素扫描，
其中 56% 调用（创建形态：`obank::create` 的 alivelist push 紧接
`Funcdata::newOp` 的 markDead，op.cc:941 → funcdata_op.cc:322-327）op 位于
alivelist 尾部，`pop()` 以零扫描完成同一擦除（覆盖 ~50% 扫描量）；中段销毁
（ActionDeadCode 批量 opDestroy 路径）保持保序 `retain` 兜底，结果与其余元素
相对序逐元素等价。`new_indirect_op` 内 `new_op` 段实测 31.4µs → 1.0µs。

#### 注意
被标记 dead 不等于立刻从 bank 中物理移除。

---

### `pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode)`

修改某条操作的 opcode。

#### 用途
可用于：

- 规则重写
- 语义规范化
- 将某类操作替换为更简化的形式

#### 风险
修改 opcode 必须保证：

- 输入/输出数量仍然语义合理
- 不会破坏下游打印或分析假设
- 图仍保持自洽

---

### `pub fn destroy_dead(&mut self)`

销毁所有已经被标记为 dead 的操作。

#### 作用
这是延迟清理机制的重要部分。

#### 典型使用方式
常见流程是：

1. 先 `mark_dead`
2. 后统一 `destroy_dead`

这种方式比“见一个删一个”更安全，因为它允许规则系统先完成批量重写，再统一收尾。

每个被销毁的 dead 操作从 `optree`/`deadlist`/code-list 移除后**退役进
`deadandgone` 保留列表**（见下），内存直至 `clear()` 才回收——与 Ghidra
`destroyDead` → `destroy` 的链路逐层同构（op.cc:971-982 → op.cc:989-999）。

---

### `pub fn destroy(&mut self, op: PcodeOpRef)`

销毁指定操作。

#### 说明
与 `destroy_dead` 相比，这是更直接的单节点销毁入口。

#### 注意
调用前通常需要确保：

- 引用关系可安全解除
- 不会留下悬空输入/输出链接
- 上层图与 bank 状态保持一致

销毁即**退役**：操作从所有索引（optree/alivelist|deadlist/code-list）移除后，
其句柄进入 `deadandgone` 保留列表（op.cc:998 `deadandgone.push_back(op)`），
分配在 `clear()` 前不被回收。这是 iop 空间常量（`Arc::as_ptr` 编码，
`Funcdata::get_op_from_const` 解码）能继续安全解引用的生命周期契约。

---

### `pub deadandgone: Vec<PcodeOpRef>`

退役操作保留列表（Ghidra `deadandgone`，op.hh:297）。

Ghidra op.cc:984-999 注释明确："The memory is not reclaimed until the whole
container is destroyed, in case pointer references still exist. These will all
still be marked as *dead*." 悬空引用 = iop 空间常量编码的裸指针。Rust 侧
缺少该保留时，被销毁操作的最后一个外部句柄 drop 即释放分配，glibc tcache
元数据覆写 Arc 计数与 `inrefs`，之后 `get_op_from_const` 从常量伪造的句柄
在 drop 时对已释放内存做 `-1`（HTTPD-FULL-SEGV：httpd 全量
ap_content_length_filter 在 RuleIndirectCollapse dead-indop 路径 SIGSEGV，
引入点 af6c5ee2 的 IR 内容首次使该函数以"ActionPool 已 purge indop"的形态
到达该规则）。`clear()`（op.cc:1194-1211 镜像）清空全部三个列表并真正回收。

---

### `pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef>`

按 `SeqNum` 查找操作。

#### 参数
- `seq`: 目标操作的时序锚点

#### 返回
- 找到则返回 `Some(PcodeOpRef)`
- 否则返回 `None`

#### 作用
这是调试、对齐、验证、图遍历时非常关键的查找入口。

---

## 8. 当前模块在主流程中的作用

`op.rs` 当前可以被放在以下主链路中理解：

```text
PcodeOpRaw
  ↓
注入 Funcdata
  ↓
创建/组织 PcodeOp 与 Varnode
  ↓
由 PcodeOpBank 管理操作节点
  ↓
被 CFG / SSA / Action / Rule / Print 层消费
```

也就是说，本模块不负责：

- 直接从二进制解码机器码
- 直接输出最终 C 源码
- 单独完成 SSA
- 单独完成变量恢复

它负责的是：

- 把“操作”这件事稳定地建模出来
- 让后续所有分析和打印都有统一的操作节点可用

---

## 9. 当前文档边界与风险提醒

在使用 `op.rs` API 时，请特别注意以下几点：

### 9.1 不要把结构存在等同于能力完成
例如：

- 有 `PcodeOp`
- 有 `PcodeOpBank`
- 有大量 flags

并不自动代表：

- 所有优化规则都已完善
- 所有 opcode 都已完整消费
- 与 Ghidra 行为已经完全一致

---

### 9.2 不要把 `PcodeOp` 当成最终高层语句
`PcodeOp` 是 IR 节点，不是最终用户看到的高级 C 语句。

---

### 9.3 修改 opcode 或标志位时要同步考虑图一致性
任何对 `PcodeOp` 的重写都可能影响：

- Varnode 连接
- CFG 切分
- SSA 语义
- 打印行为
- DCE 与清理阶段

---

### 9.4 `PcodeOpBank` 是统一真相源之一
如果某操作已经由 bank 管理，就不应在其他地方偷偷维护一套脱离 bank 的“影子节点集”。

---

## 10. 推荐联动阅读

想继续理解本模块，建议接着看：

1. `opcodes.md`
   - 看 opcode 语义分类

2. `varnode.md`
   - 看操作的输入输出节点如何表示

3. `pcoderaw.md`
   - 看原始操作如何进入正式图结构

4. `funcdata.md`
   - 看操作如何进入单函数上下文

5. `heritage.md`
   - 看这些操作如何进入 SSA / heritage 相关过程

6. `printlanguage.md` / `printc.md`
   - 看这些操作如何最终参与文本输出

---

## 11. 一句话总结

`op.rs` 是 Rugra 当前 P-code 操作层的核心建模模块：它定义了**操作节点是什么、如何被标记、如何被引用、如何被统一管理**，并为后续的 SSA、规则重写、控制流分析和打印输出提供操作级基础设施。
## 2026-06-26：is_calculated_bool

- `is_calculated_bool()` — `PcodeOp::isCalculatedBool`（op.hh:211）：检查 CALCULATED_BOOL|BOOLOUTPUT 标志。解锁 RuleBooleanNegate/RuleLogic2Bool。

## 2026-06-27：is_marker / is_bool_output

- `is_marker() -> bool`（op.hh:185）：检查 MARKER 标志（MULTIEQUAL/INDIRECT）。解锁 JumpBasic::is_prune。
- `is_bool_output() -> bool`（op.hh:190）：检查 BOOLOUTPUT 标志。解锁 Varnode::is_bool_output_def。

## 2026-06-29：uses_spacebase_ptr / mark_spacebase_ptr（op.hh:432 + funcdata.hh:487）

- `uses_spacebase_ptr() -> bool`（对齐 `PcodeOp::usesSpacebasePtr`）：检查 SPACEBASE_PTR 标志。heritage 的 discoverIndexedStackPointers 给 stack-pointer-relative STORE 打此 flag，guardStores 据此决定是否建 Stack 空间 INDIRECT。
- `mark_spacebase_ptr(&mut self)`（对齐 `Funcdata::opMarkSpacebasePtr`）：设置 SPACEBASE_PTR 标志。

## 2026-06-27（续）：CSE 方法

- `get_eval_type() -> u32` — `PcodeOp::getEvalType`（op.hh:169）：返回 unary/binary/special/ternary 标志位。
- `get_cse_hash() -> u64` — `PcodeOp::getCseHash`（op.cc:130-147）：计算公共子表达式检测哈希。非 unary/binary 或 COPY 返回 0。
- `is_cse_match(other) -> bool` — `PcodeOp::isCseMatch`（op.cc:153-171）：完整 CSE 匹配测试（相同 opcode + 大小 + 输入）。

### 2026-06-27（会话2）：is_boolean_flip（解锁 condexe）

- `is_boolean_flip() -> bool` — `PcodeOp::isBooleanFlip`（op.hh:210）：CBRANCH 的布尔语义是否翻转。当为 true 时，CBRANCH 在输入为 TRUE 时走 fallthru 边（FALSE 时跳转）。condexe 的 verifySameCondition + is_true_out_to 用此适配 Rugra 边顺序。

### 2026-06-27（会话2 续）：compare_order（解锁 RuleOrPredicate）

- `compare_order(bop) -> i32` — `PcodeOp::compareOrder`（op.cc:778-790）：比较两个 op 的控制流顺序。同块比较 SeqNum.order；不同块用 find_common_block 找 LCA，LCA 是本块则在前（-1），是 bop 块则在后（1），否则无序（0）。RuleOrPredicate 用此决定 branch0/branch1 谁在后以定位 finalBlock。
### 2026-06-27（续；2026-08-28 勘误）：is_indirect_source（RuleEarlyRemoval）
- `is_indirect_source()` 读取 INDIRECT_SOURCE；旧“SET 路径未移植、当前总 false”
  已失效。当前 producer 包括 coreaction/ruleaction 的 INDIRECT 创建路径，
  EarlyRemoval fixture 已覆盖该守卫的 selected 行为；所有 producer、清除时机、
  op-bank 重连与错误生命周期仍未完整对拍，保持 UNTESTED/MISMATCH。

### 2026-07-01：PcodeOp flag accessor（解锁 RulePtrFlow/RuleTransformCpool）
- `is_ptr_flow/set_ptr_flow`（op.hh:205-206）— PTRFLOW flag(1<<30)。RulePtrFlow 用。
- `is_cpool_transformed/mark_cpool_transformed`（op.hh:213/140）— addlflags 0x20。RuleTransformCpool 去重保护用。

### 2026-07-01（续 2）：op_addl_flags mod + 访问器
- `op_addl_flags` mod（op.hh:108-120）：SPECIAL_PRINT/MODIFIED/WARNING/INCIDENTAL_COPY/IS_CPOOL_TRANSFORMED/STOP_TYPE_PROPAGATION/HOLD_OUTPUT/CONCAT_ROOT/NO_INDIRECT_COLLAPSE/STORE_UNMAPPED。
- `does_special_printing()`（op.hh:208）、`clear_stop_type_propagation()`/`stops_type_propagation()`（op.hh:217）、`no_indirect_collapse()`/`set_no_indirect_collapse()`（op.hh:223-224）。

### 2026-07-04：新增 PcodeOp::slot_of_input
- `slot_of_input(vn)`（对齐 op.hh:166 PcodeOp::getSlot）：线性搜索 inrefs 返回 vn 的槽位。供 snip_reads 使用。
<!-- annotation-pass: 2026-07-04 -->
<!-- ref-fix2: 1783141346.3262112 -->
<!-- activeparam-port: 1783158350.9670146 -->
 

### 2026-07-05: op.cc 缺失方法批量补齐
- `is_assignment`/`is_flow_break`/`is_instruction_start`(op.hh inline)。
- `is_collapsible`(cc:115)、`set_num_inputs`/`remove_input`/`insert_input_slot`(cc:290/301/311)、`get_repeat_slot`(cc:93)、`print_debug`(cc:376)。
- （2026-09-22，SB-ORD159-NULLSLOT-0001）`set_num_inputs` 忠实化：cc:290-296 的
  "All slots, regardless of the total being increased or decreased, are set to
  null"——先 clear 再以共享 null 哨兵 resize 到 `num`（旧实现增长时 panic，
  且缩减时保留旧槽）。新增 `pub fn null_slot_sentinel()`（RUDRA-GLUE）：
  Ghidra NULL input-slot 指针 `(Varnode*)0` 的进程级共享替身（脱离 bank、
  size-0、无 descendant、无 create-index）；单一实例保证两个 NULL 槽之间
  `Arc::ptr_eq` 为 true，对应 Ghidra `inrefs[i] == vn` 指针相等语义
  （op.hh:166 getSlot）。`Funcdata::op_unset_input` 的 clearInput 写入与
  观察投影的 NULL 渲染（`-`）都消费它。
 
 
 
 
 
 
 

### 2026-08-23：collapse_constant_symbol 调用点适配（VARNODE-COPYSYMBOL-HIGHBRANCH-0001）

- `PcodeOp::collapse_constant_symbol`（op.cc:503-540）cc:537 调用点改为
  `Varnode::copy_symbol_if_valid(new_const, ...)` 关联函数形态：copySymbolIfValid
  的 copySymbol 尾声现在能携带 varnode.cc:500-504 的 high 簿记
  （typeDirty + setSymbol），折叠出的新常量在 highlevel_on 下其
  HighVariable 正确附着 equate 符号。行为由
  `tests/oracle/varnode_highbranch_1204`（hb_op_level_marked_input）门禁。

### 2026-08-23：get_nz_mask_local 完整 oracle switch 合并（FUNCDATA-CALCNZM-0002）

- `PcodeOp::get_nz_mask_local(cliploop) -> u64` — `PcodeOp::getNZMaskLocal`
  （op.cc:547-771）完整 switch 从 funcdata.rs 暂存副本（原
  `Funcdata::pcode_op_nz_mask_local`）值等价迁回 PcodeOp 方法。旧行为本
  （divergent，零调用方）已删除：忽略 cliploop、缺 INT_DIV/INT_REM/
  POPCOUNT/LZCOUNT/INT_MULT/CALL/CALLIND/CPOOLREF 臂、INT_LEFT 用裸
  wrapping_shl（无 pcode_left 的 sa>=64→0 保护）、INT_RIGHT 缺 >8 字节
  扩展精度分支（cc:612-630）、INT_SRIGHT 缺符号位已知 0 分支
  （cc:639-644）、SUBPIECE 缺扩展精度（cc:682-690）、输入 mask 走保守
  近似 `get_nz_mask()` 而非存储字段。
- **输入 NZM 读取直接访问存储字段**（`get_nzm`，oracle varnode.hh:231
  `getNZMask() { return nzm; }`）；`Varnode::get_nz_mask()` 的保守近似合并
  仍是残差 TODO FUNCDATA-CALCNZM-0003。
- MULTIEQUAL 臂实现 `cliploop` 裁剪（op.cc:746-751，`parent->isLoopIn(i)`
  跳过 looping 边）；CALL/CALLIND/CPOOLREF 臂按 `is_calculated_bool()` → 1
  （op.cc:758-765）。
- `Funcdata::calc_nz_mask` 两个调用点（phase-1 cc:874 / phase-2 cc:919）改调
  `PcodeOp::get_nz_mask_local`，funcdata.rs 暂存副本删除。行为由
  `tests/oracle/funcdata_calcnzm_1204`（6/6 MATCH）门禁。
## 2026-08-23：dead-list 移动的 Vec 索引语义

`PcodeOpBank::insert_after_dead(op, prev)` 对应 `op.cc:1039-1048`。Ghidra 的
`std::list` 在删除位于 `prev` 之前的 `op` 后，`prev->insertiter` 仍指向同一节点；
Rust 的 `Vec` 删除会把后方索引左移。因此实现现在先解析两个节点身份，删除
`op`，若 `op_idx < prev_idx` 则把目标索引减一，再插到 `prev` 后。真实
`truncated_flow_1204` fixture 用同地址 times `[0,1,2]` 锁住
`insertAfterDead(time0,time1)` 的结果必须为 `[1,0,2]`，并继续证明该顺序被
partial clone 与 `splitBasic` 保留；旧结果 `[1,2,0]` 是 Vec 适配缺陷。

### 2026-08-25：PcodeOpBank::destroy 单列表分支
- `PcodeOpBank::destroy`（op.cc:989-999）— Ghidra 只 erase deadlist（stored insertiter），
  alivelist/deadlist 互斥（markAlive/markDead 迁移）。Rust 按 `is_dead()` 分支只 retain 所在
  的那一个列表，行为等价（每个 op 恰在其中一个列表），每 op 销毁扫描减半，
  ActionDeadCode 批量销毁收益。

## PcodeOp concat_root 旗标（RULE-PTRARITH-ADDTREE-0001，本次新增）

`PcodeOp::is_partial_root` / `set_partial_root`（op.hh:220-221，
addlflags `concat_root` = 0x100，常量此前已存在但无访问器与使用者）。
RulePieceStructure::applyOp 顶部闸门（ruleaction.cc:7610）+ 建树前
`setPartialRoot()`（:7642）——CONCAT 树只重排一次；缺失该闸门时
cleanup 池对同一根反复返回 change 导致 universal 尾部不收敛。

## 2026-09-24：create 即注册 code-list（前代 WIP 收编核证）

Ghidra cc:941-948 PcodeOpBank::create 无操作码分配；操作码经 opSetOpcode→
changeOpcode（op.cc:1005-1012）的 addToCodeList（op.cc:881-900）注册进
STORE/LOAD/RETURN/CALLOTHER 专用表。Rugra create() 直接收操作码，故在
create 处补 add_to_code_list 以维持"可列表操作码自诞生即在表中"不变量
（否则 inject_raw_ops 出生的 RETURN 对 begin_op(RETURN) 消费者不可见，
httpd 语系未锁返回值全体塌缩 `return;`）。change_opcode 的先删后加防双注册。

## 2026-09-24：destroy 退役进 deadandgone（HTTPD-FULL-SEGV 修复）

`PcodeOpBank::destroy`/`destroy_dead`/`clear` 补齐 Ghidra 的**退役保留**
语义（op.hh:297 `deadandgone` 列表；op.cc:984-999 destroy 把已 dead 的操作
从 optree/deadlist/code-list 移除后 `deadandgone.push_back(op)`，op.cc:1203-1209
clear 才统一 delete）。Ghidra 在容器析构前**从不回收退役操作的内存**，
正是为了让 iop 空间常量（`RuleIndirectCollapse::getOpFromConst` 等解码的
裸指针）在原对象销毁后仍可安全读 `isDead()` 等旗标。Rugra 此前 destroy
直接丢弃 bank 全部句柄 → 末句柄 drop 即释放 → tcache 元数据覆写 Arc 计数/
`inrefs` → `Funcdata::get_op_from_const` 依据陈旧常量伪造的 `Arc<PcodeOp>`
在 RuleIndirectCollapse 尾部 drop 时对已释放内存 `-1`，级联 drop 垃圾
`inrefs` 中的 `Arc<Varnode>` → SIGSEGV（回归窗 bisect 钉死内容触发点
af6c5ee2/GG2：其 RETURN-类型播种使 ap_content_length_filter 首次以
"indop 已被 ActionPool processOp 死臂 purge"形态到达该规则；生命周期缺陷
本身先于该 commit 潜伏，同 EW 车道"锁缺陷潜伏+内容触发"先例）。
验证：MAX_FUNCS=840 全量 473 函数零 SEGV；三门禁 curl 1438/0/0、httpd
1447/0/0 与 master 逐数一致且门禁 stdout 修复前后**逐字节相同**；
五投影 next_url/match_url/myprogress/getparameter/parseconfig 全 MATCH 保持；
cargo test --lib 串行 1688P/18F == master 预存集。

## 2026-09-27：op_addl_flags 补 SPECIAL_PROP + does_special_propagation（VARNODE-CALLOTHER-VOLATILEOUT-0001）

`op_addl_flags` mod 补 `SPECIAL_PROP: u32 = 0x1`（op.hh:109
`special_prop = 1`，此前缺失）与访问器 `does_special_propagation()`
（op.hh:207）。读取者=`VolatileReadOp::getOutputLocal`（userop.cc:131）与
`VolatileWriteOp::getInputLocal`（userop.cc:162）；置位者仅
`Funcdata::replaceVolatile`（funcdata_varnode.cc:761-762，源 varnode
typelock 时）。setAdditionalFlag 泛形（op.hh:140）即写入通道，无需专属
setter。

## 2026-09-30：PcodeOpBank 7 链侵入式 IdList 翻转（PERF-ARENA-FLIP-0001 (b)）

`PcodeOpBank` 的 7 条成员链（`deadlist`/`alivelist`/`deadandgone`/
`storelist`/`loadlist`/`returnlist`/`useroplist`）从 `Vec<PcodeOpRef>`
翻为 arena.rs 冻结原语 `IdList`（op.hh:291-297 的 `list<PcodeOp*>` 镜像）。
链链接对内嵌在 op 树 arena 槽 `OpCell`（`ins_prev/ins_next` = 单一
`insertiter` op.hh:128 的 id 形态；`code_prev/code_next` = 单一 `codeiter`
op.hh:129）——链手术即存储迭代器手术，`mark_alive`/`mark_dead`
（op.cc:1017-1034）成为 O(1) unlink+push_back，原 `retain` O[n] 扫描地板
（VARMAPOPCREATE 实测 207,611 次/5.58s）删除；`move_sequence_dead` 改走
冻结 `splice_after`（op.cc:1063 退化守卫 + pos==last no-op，CR-ARENACORE
F1）。Vec 镜像删除。

**新读 API**（链序 = oracle 列表序）：`iter_alive/iter_dead/iter_deadandgone/
iter_store/iter_load/iter_return/iter_userop`（`OpChainIter`，产出
`&PcodeOpRef`）；`iter_dead_from(Option<OpId>)`（marker 起步的尾段游走，
flow.cc:240 `oiter` 形态）；`dead_next/dead_prev/alive_prev`（O(1) 存储链
前后驱）；`dead_head/dead_tail(+_id)`；`in_dead/in_alive`；`dead_at/
dead_id_at/dead_at_strict`（冷位点位桥）；`adopt_alive_op`（遗留 fixture
裸 `alivelist.push` 的 bank API 替代——slot-only 入 arena 不进 SeqNum map，
重链入 alive 尾，单链不变量保持）；`alive_insert_before/alive_insert_after/
alive_push_back/unlink_alive_if_member`（funcdata GLUE 分支的位置插入链形
态）。`begin_op(OpCode)`/`end_op` 返回 `OpChainIter`（原 slice 迭代器面换
链迭代器，序同）。

**行为恒等**：链序 == 原 Vec 序 == oracle 列表序（同构操作 × 同位点的归纳，
ARENA_DESIGN §2.4）；`mark_dead` 等对未入链外源句柄（legacy fixture 裸 op）
走成员守卫 no-op（原 retain miss 等价）。canon curl/httpd 双 md5 字节恒等
（4ab1db2a/7d5b9e7c）+ tests 2018P 恒等亲证。

## 2026-09-30（续）：clear() 七链全部先摘链再回收槽（sqlite 三函数 panic 修复）

翻转首版的 `clear()` 先摘三条 insert 链，随后 `optree.clear()` 释放全部
arena 槽，最后才 `clear_code_lists()`——opcode 链仍链在已释放槽上，下一次
code 链手术即 `clear: node vanished` panic（arena.rs）。镜面 sqlite 面捕获：
sqlite3_config/sqlite3_test_control/sqlite3_db_config 反编译 worker 阵亡
（matched 1382/1385 < floor、skeleton 778/785）；canon 双面与单测面不触达
带非空 code 链的 bank clear。修复序：clear_code_lists → 三条 insert 链摘链
→ optree.clear → uniqid=0（op.cc:1194-1209 先删对象后清表的等价重排）。
修复态复验：镜面五面全 PASS 恰钉值、canon 双 md5 字节恒等、2018P/0F/5I。

## 2026-09-30（c 段）：OpCell opcode 影子 + id 游标/工作集读 API（PERF-ARENA-FLIP-0001 (c)）

**OpCell opcode 影子**（存储迭代器反规范化，同 `seq_key` 模式）：槽元新增
`opcode: OpCode` 反规范化副本——`op->code()`（op.hh:233，oracle 纯字段读）
的 id 空间读形态。维护位点 = 源字段的全部突变点：`PcodeOpTree::insert`/
`slot_only` 入槽时单守卫快照（opcode 自构造即存在）；`change_opcode`
（op.cc:1005-1012，`Funcdata::opSetOpcode` 背后的唯一 choke point）在
`set_opcode_flags` 同语句位更新。生产路径无其它 `PcodeOp::opcode` 写点
（grep 亲证：唯 RuleBxor2NotEqual 曾直写，已改走 `op_set_opcode`——
ruleaction.cc:272 oracle 原形，该 opcode 对派生 flag 集相同且互非 code-list
成员，可观测效果恒等）。

**新读 API**：
- `PcodeOpTree::first_id()/next_id_after(OpId)`——ActionPool 保留游标
  （action.hh:265 `op_state`）的 id 形态支撑：后继查找读当前槽的
  `seq_key`（锁自由），map 严格后继 = std::map `++` 语义（规则中途 erase
  不受影响，ACTIONLOOP-RESTART-0001 同论证）；`opcode_by_id(OpId)`——
  槽影子读。`PcodeOpBank::opcode_of` 为 bank 级转发。
- `OpChainIdIter` + `iter_alive_ids()/iter_load_ids()/iter_return_ids()`——
  `OpChainIter` 的 id 产出伴生（同一存储链游走，产出 Copy 的 `OpId`，
  零句柄克隆零锁）；Action/Rule 工作集的采集形态。

**读模式收益**：ActionPool 派发的 per-try `opc != op->code()` 复读
（action.cc:846/853-857，VdbeExec 极 27.7M 次锁读）与游标推进的
SeqNum 守卫+Arc 克隆（5.6M 次）改走槽读；Action 工作集 filter
（RETURN/INT_ADD 扫描）走影子读。


## 2026-10-02：OpCell dead 影子 + optree version 计数器 + 派发读/地址 API（PERF-DISPATCH-0001）

**OpCell dead 影子**（同 `seq_key`/`opcode` 的第三项反规范化）：槽元新增
`dead: bool` 副本——`op->isDead()`（op.hh:173，oracle 内联位掩码测试）的
id 空间读形态。维护位点 = DEAD 位全部生产写点（grep 亲证，与 opcode 影子
同纪律）：`PcodeOpTree::insert`/`slot_only` 入槽时随守卫快照（`create_seq`
cc:966-967 的出生置位发生在 Arc 包装/入槽前，快照必然命中）；`mark_alive`/
`mark_dead`（op.hh:313/314 choke points，cc:1021/1031）在写 flag 的同语句
位同步更新影子。cfg(test) fixture 的 `flags =` 整字赋值不经 bank 入槽，无
cell 即无影子失同步面。派发面读点（`action.cc:829` 入口判定、`:846` 命中
后复核）经 `PcodeOpBank::is_dead_of(OpId)` 槽读，取代 PcodeOp RwLock 往返。

**optree version 计数器**：`PcodeOpTree.version: u64` 单调计数，`inner`
（`BTreeMap<SeqNumKey, OpId>`）的插入/删除/clear 全位点 bump（`insert` 仅
Vacant 臂、`remove` 两个删除位、`clear`；remove 内部先删后回插的错键自愈
路径 bump 一次=保守误报，只触发 fresh 搜索回退，语义安全）。用途 =
ActionPool 派发的 memo 守卫（见 action.md 2026-10-02 节）：同 version ⇒
`inner` 未变 ⇒ 预算的严格后继 === 尾推进的 fresh 搜索结果（同树同键）。
读 API `PcodeOpBank::optree_version()`。

**新读/地址 API**：
- `PcodeOpTree::dead_by_id(OpId) -> Option<bool>`——槽影子读（op.hh:173 等价）。
- `PcodeOpTree::cell_hint_addr(OpId) -> Option<*const u8>`——槽纯地址投影
  （经 `Arena::slot_addr`，不触槽行），供派发循环对后继槽行发 PREFETCHT0。
- `PcodeOpBank::is_dead_of/ optree_version`——bank 级转发。

RUDRA-GLUE（version/addr 投影无 oracle 对应物：oracle 的 `op_state++` 是
活 map 迭代器 O(1) 指针步进 action.hh:265；isDead 影子=存储迭代器读形态）。


## ARENAFLIP-e（2026-09-30）BlockEdge.point 值化翻转表示层变更

**PERF-ARENA-FLIP-0001 (e) 段**: `BlockEdge.point` 由 `Arc<RwLock<dyn FlowBlock>>`
翻转为 `BlockId`（oracle block.hh:57-65 的 12B 值形态,Copy struct;`point_id`
孪生字段并入 `point`）。本模块的消费位点已随迁:对端解析经**属主 bank**
（每块 `Weak` owner-bank 回指,`BlockBank::{expect_arc,expect_index,arc_of,
index_of,btype_of}` + `BlockBankView` 同形）;`Arc::ptr_eq(&e.point, x)` 改为
id 相等（同 bank 域内）;`e.point.clone()` 改为 `bank.expect_arc(e.point)`。
行为恒等证明链: canon curl `4ab1db2a`+httpd `7d5b9e7c` 字节恒等 +
tests 2018P（细节见车道终报与 commit 7f1d71b4.. 的 Alignment Evidence）。
