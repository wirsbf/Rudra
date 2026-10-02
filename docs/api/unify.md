# `unify.rs` API Reference

**源代码路径**: `src/unify.rs`
**Ghidra 对应**: `unify.hh` / `unify.cc` (2358行)
**状态**: 🟢 **L2.5**，与 `ALIGNMENT_ROADMAP.md` 一致。现有实现覆盖主要
类型与方法，但尚无锁定 12.0.4 oracle `MATCH` fixture；ANN-P 仅补 provenance，
不构成 L3 证据。

## 模块说明

统一化模式匹配基础设施。对应 Ghidra 的 `unify.hh`。
用于基于模式的规则系统和用户自定义规则。

## 导出的公共 API

### `pub enum UnifyDatatype`
统一化状态槽的数据类型（OpType/VarType/ConstType/BlockType）。

### `pub struct UnifyState`
匹配状态：保存已匹配的 op、varnode、常量。
- `register_slot(dt)` — 注册一个槽，返回其索引
- `set_op/set_varnode/set_constant(idx, val)` — 设置槽值
- `get_op/get_varnode/get_constant(idx)` — 获取槽值

### `pub enum RHSConstant`
RHS 常量构造（Named/Absolute/NZMask/Consumed/Offset/IsConstant）。
`get_constant(state)` 对状态求值。

### `pub enum UnifyConstraint`
约束类型（OpCode/OpEqual/VarnodeEqual/NumParams/ConstEqual/VarnodeSize/AlwaysTrue）。

测试：unify::tests 3 个。

## 2026-06-26（续）：unify.rs 完善实现

新增约束评估引擎：
- `UnifyConstraint::evaluate(state)` — 评估单个约束（unify.cc）
- `ConstraintSequence` — 约束序列容器，`add(constraint)` + `evaluate_all(state)` 批量评估
- `UnifyConstraint::OpCode(slot, opc)` — 现在带 slot 参数，评估时从 state 读取 op
- `UnifyConstraint::CopyVarnode(from, to)` — 复制 varnode 槽（action 约束）
- 约束类型：OpCode/OpEqual/VarnodeEqual/NumParams/ConstEqual/VarnodeSize/CopyVarnode/AlwaysTrue

测试：新增 3 个（constraint_always_true/const_equal/constraint_sequence）。

### 2026-06-27（会话3 L1）：unify.cc 约束系统扩展

移植 8 个新约束类型（忠实于 Ghidra unify.hh/cc）：
- **OpOutput(op_idx, vn_idx)** — ConstraintOpOutput (unify.hh:361)：从 op 获取输出 varnode，存入 state
- **OpInput(op_idx, vn_idx, slot)** — ConstraintOpInput (unify.hh:335)：从 op 获取指定 slot 的输入 varnode
- **OpNotEqual(a, b)** — ConstraintOpCompare 的不等变体
- **VarnodeWritten(idx)** — 检查 varnode 是否有定义 op
- **VarnodeConstant(idx)** / **VarnodeNotConstant(idx)** — 检查 varnode 是否为常量
- **VarnodeFuncEqual(a, b)** — functional_equality 比较
- **OpOutputNoDescend(op_idx)** — 检查 op 输出无后代

新增 evaluate_mut() 方法用于动作约束（OpOutput/OpInput 需修改 state）。
4 个新单元测试：OpOutput、OpInput、VarnodeWritten、VarnodeConstant。
### 2026-06-27：历史实现扩展记录（非 L3 证据）
- 从 ~460 行骨架扩展到 2415 行：43 个 struct 覆盖约束层级（ConstantAbsolute/Consumed/Expression/NZMask, ConstraintOpcode/OpInput/OpOutput/Group/Or/VarCompare, UnifyState, RuleMatcher, UnifyCPrinter, TraverseGroupState/DescendState/CountState）。该历史记录没有锁定 oracle fixture，且保留 CPrinter 常量运算边缘缺口。

### 2026-08-12：ANN-P expanded-scanner annotation bootstrap

- 六个 RHS 常量构造器映射到 unify.hh:90/:99/:108/:117/:126/:135；三个
  Dummy 构造器映射到 unify.hh:226/:238/:250。Dummy 的 Rust 实现额外把
  `uniqid` 初始化为 0，而 Ghidra 留待 `setId` 写入；这是映射函数的既有状态差异，
  不能以 `RUDRA-GLUE` 隐藏。
- `ConstraintGroup::default` 标为 RUDRA-GLUE。Ghidra 没有 Rust `Default`
  trait，并且 unify.cc:974 构造器把 `maxnum` 初始化为 -1，而当前 Rust
  `ConstraintGroup::new()` 使用 0。这是既有行为差异，本轮未修改。
- 只有 `ConstraintGroup::default` 是 Rust trait glue。本轮只做注释和单行函数格式
  展开，不改变行为、不提升模块状态。

<!-- annotation-pass: 2026-08-12 ANN-P; provenance-only -->

### 2026-08-13：opcode bank mutation 调用闭包

- `ConstraintNewOp` 与 `ConstraintSetOpcode` 现在以 `Funcdata` 写锁调用
  `op_set_opcode`。这是 `Funcdata::opSetOpcode` 委托
  `PcodeOpBank::changeOpcode` 后所需的 Rust 借用边界，使 opcode 派生 flags
  以及 LOAD/STORE/RETURN/CALLOTHER 专用列表在同一次原位突变中更新。
- 此项仅作为 `RULE-MULTICOLLAPSE-0001` 的调用闭包；Unify 的完整匹配、
  状态回溯与错误路径仍未获得锁定 12.0.4 全函数 oracle，模块状态不变。
 
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
