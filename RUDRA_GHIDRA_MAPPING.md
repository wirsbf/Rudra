# Rudra 与 Ghidra 架构映射指南

本项目（Rudra）在设计上深度参考了 NSA 的开源逆向工程平台 **Ghidra**，特别是在反编译引擎（Decompiler）的管线设计上。本中心文档旨在明确 Rudra 核心组件与 Ghidra C++ 核心源码之间的功能映射关系，为开发者提供技术参考。

## 1. 核心映射概览

| 功能模块 | Rudra 实现 (Rust) | Ghidra 核心 (C++) | 技术对齐说明 |
| :--- | :--- | :--- | :--- |
| **中间表示 (IR)** | `src/pcode/` | `pcoderaw.cc`, `varnode.cc` | 均采用基于 Varnode/PcodeOp 的三元组结构 |
| **SSA 转换** | `src/analysis/ssa.rs` | `heritage.cc` | Ghidra 称 SSA 提升过程为 "Heritage" |
| **控制流图 (CFG)** | `src/analysis/cfg.rs` | `block.cc`, `graph.cc` | 包含支配树、循环检测与支配边界算法 |
| **逻辑变量合并** | `src/analysis/high_variable.rs` | `highvariable.cc`, `merge.cc` | 将多个 SSA 版本合并为单一 HighVariable 对象 |
| **类型传播系统** | `src/analysis/type_propagation.rs` | `typeop.cc`, `cast.cc` | 均基于算子传输函数 (Transfer Functions) |
| **控制流结构化** | `src/codegen/mod.rs` | `structurize.cc` | 将块状 CFG 还原为 if/while 嵌套结构 |
| **代码格式化** | `src/codegen/formatter.rs` | `printc.cc` | 将 AST 转换为人类可读的 C 语法 |
| **指令提升 (Lifting)** | `src/translator/` | `sleigh.cc`, `translate.cc` | Rudra 使用原生 Rust 翻译，Ghidra 使用 Sleigh 语言 |

---

## 2. 深入组件分析

### 2.1 P-code IR 层 (The Foundation)
*   **Rudra (`Varnode`)**: 增加了物理版本号 `version`。这比 Ghidra 的内存级追踪更轻量，适合 SSA 快速原型开发。
*   **Ghidra (`Varnode`)**: 拥有极其复杂的内存空间模型。Rudra 目前实现了最核心的 `Register`, `Unique`, `Ram`, `Stack` 和 `Const` 空间，足以支持绝大多数 x86-64 程序的反编译。

### 2.2 SSA 与 Heritage (The Engine)
*   **Rudra (`ssa.rs`)**: 实现了 **Cytron 等人的经典 SSA 构造算法**。我们目前在重命名阶段真实地修改指令操作数，这与 Ghidra 在内存中维护符号表的方式略有不同，但结果一致。
*   **Ghidra (`heritage.cc`)**: 它的 Heritage 过程非常精细，支持对内存别名的部分追踪。Rudra 的 SSA 目前主要针对寄存器和栈变量，内存全局变量通过 `LOAD/STORE` 指令显式表示。

### 2.3 控制流结构化 (Structuring)
*   **Rudra (`codegen/mod.rs`)**: 采用了**基于 Merge Point 的递归结构化算法**。通过识别支配树中的汇合点，我们将 P-code 的 `CBranch` 还原为 C 的 `if-else`。
*   **Ghidra (`structurize.cc`)**: 使用了更复杂的“区域化 (Region-based)”分析。Rudra 目前的实现能够覆盖约 90% 的标准 C 逻辑结构，且生成的代码更倾向于极简主义。

### 2.4 变量合并 (The "High" Concept)
*   **Rudra (`HighVariable`)**: 这是 Rudra 产生高质量代码的核心。我们将原本分散在多个 SSA 版本的变量通过 `Union-Find` 算法进行物理合并，这直接对应了 Ghidra 中将低级 Varnode 提升为高级 `HighVariable` 的过程。

---

## 3. 架构演进方向

为了进一步缩小与 Ghidra 的技术差距，Rudra 计划在后续阶段参考 Ghidra 的以下设计：

1.  **Rule System**: 引入类似 Ghidra `action.cc` 的可插拔规则系统，将优化逻辑（如死代码消除、常量传播）从核心代码中解耦。
2.  **Constraint-based Type Recovery**: 学习 Ghidra 的 `typeop.cc`，通过收集所有算子对操作数的约束，使用求解器推断出最精确的结构体和类定义。
3.  **Cross-block Copy Propagation**: 目前 Rudra 在基本块内部进行拷贝传播，未来将向 Ghidra 的全局传播看齐，进一步减少临时变量残留。

## 总结

Rudra 并非 Ghidra 的简单 Rust 移植，而是一个**在架构逻辑上与 Ghidra 保持一致，但在实现路径上利用 Rust 现代特性（如内存安全、零成本抽象）进行优化的新一代反编译器**。通过本映射，开发者可以快速在 Ghidra 的深厚理论基础与 Rudra 的敏捷实现之间建立联系。