# Ghidra 对齐说明：类型推导机制与格理论 (Type Lattice & Propagation)

**[状态]**: 🟢 规划中 (Planned)  
**[目标模块]**: `src/type_system/` 及 `src/analysis/type_propagation.rs`  
**[关联 Ghidra 源码位置]**: `Ghidra/Features/Decompiler/src/decompile/cpp/type.hh`, `cast.hh`, `coreaction.cc` (ActionInferTypes)  

---

## 1. 目标描述 (Description)

Rudra 需要在 P-code 的基础上，通过抽象解释与约束求解（Constraint Solving）推导出每个 `Varnode` 的高级数据类型（如 `int`, `float`, `struct *` 等）。为了与 Ghidra 的输出保持 1:1, 需要严格挂载其**类型格（Type Lattice）**与**强制转换（Casting）**策略。

## 2. Ghidra 的实现逻辑 (Ghidra Implementation)

Ghidra 的类型推导分为局部和全局机制，依赖于：
1. **格子理论 (Lattice Propagation)**: 类型的约束具有方向性。例如 `INT` 与 `FLOAT`，在不同 P-code 操作下存在提升（Promotion）或降级。底类型为 `UNKNOWN`。
2. **Casting Strategy (`cast.hh`)**: 规定了在生成 C 代码时，何时需要插入显式 `(类型)` 类型转换符。例如短整型参与加法时的整型提升。

## 3. Rudra 的对齐蓝图 (Rudra Blueprint)

Rudra 将在 `type_system` 和 `analysis::type_propagation` 模块中落实以下规范：

### 3.1. 类型格子结构 (Type Lattice Structure)
- **初始态认定**: 将反汇编常量、导入导出函数 API 签名硬编码为**数据流源点 (Sources)**。
- **约束生成 (Constraint Generation)**: 针对 SSA 图中的每种 `PcodeOp`，设定传递方程：
  - `INT_ADD(a, b)`: `out` = `max_type(a, b)`，若 `a` 为指针，则此操作变为指针偏移（Pointer Arithmetic）。
  - `STORE(space, ptr, val)`: 强制 `ptr` 的类型为一个指向 `val` 类型尺寸的空间指针。
- **迭代收敛 (Iterative Propagation)**: 利用工作表 (Worklist) 算法顺着 `inrefs` 和 `descend` 有向边传播类型属性，直至没有新类型更迭。

### 3.2. 数据流强制转换规则 (Data-Flow Casting Rules)
继承自 `CastStrategyC` 接口设计（见 `src/type_system/cast.rs`）：
- **无符号与有符号混合 (Signedness)**: 当不同符号类型相遇时，遵从 C 语言标准的隐式转换规则（通常向无符号提升或向更宽字节提升）。
- **截断与扩展 (Truncation & Extension)**: `SUBPIECE` 和 `INT_SEXT`/`INT_ZEXT` P-code，在代码生成期（`codegen`）必须显式套上目标数据类型的转换声明。
