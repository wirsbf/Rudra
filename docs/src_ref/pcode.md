# P-code IR 中间表示技术参考

本文档详细说明了 `src/pcode` 模块。该模块承载和管理 Rudra 内部的 P-code 中间表示 (IR) 和相关的核心类数据结构。

---

## 1. 程序管理容器 (`program.rs`)

`Program` 结构体代表了某个正被反编译函数的完整 P-code 表示集合，并且采用线性序列存放所有的抽象指令操作，同时集中维护唯一编号的序列生成器。

*   **`add_operation`**: 在指令流尾部追加一个经过识别提升 (Lifting) 而来的 `PcodeOperation`，主要供底层架构 `Translator` 调用。
*   **`operations_mut`**: 获取其持有的可变指令分片。所有的分析和数据流步骤都需要遍历这个线性集合（控制流状态由平行的 `CFG` 图来打理）。
*   **`new_unique_varnode`**: 专门用于产生一个占用 `Unique` (独特临时区) 的临时变量节点。内部通过 `next_unique_id` 技术保证绝对去重。主要是为了转译一些隐藏硬件细节的副作用结果时充当临时计算宿主（桥接寄存器等）。

---

## 2. 最小单元：P-code 操作 (`program.rs`)

`PcodeOperation` 表示单行 P-code 微指令。

*   **`id`与`seqnum`**: 每个操作具备一个可用于追踪的全局唯一ID和指示原机码位置映射序列的基号（Seqnum）。
*   **指令布局**: 主要由动作字 `opcode`（比如加减跳等），以及 `output`（可选操作结果存储宿主）、`inputs`（运算参与参数源端节点）构成。
*   **`has_side_effects(&self) -> bool`**: 测定该词条是否具备环境层副作用 (如 `STORE`, `BRANCH`, `CBRANCH`, `BRANCHInd`, `CALL`, `CALLInd`, `RETURN`, 和自定义的 `CALLOTHER`)。死代码分析阶段必须保留这些有副作用的指令。
*   **`is_terminator(&self) -> bool`**: 测定该词条是否为基本块的终结符（所有继承自控制流调度的分支代码皆是）。

---

## 3. 原生变量容器：Varnode (`varnode.rs`)

`Varnode`（变量节点）用于表达正在 P-code 世界中被操作的实质性数据体——也就是底层执行过程中最小的数据池。可以将其比作机器中的广义“槽”。

*   **生成构造子**:
    *   `new_register`: 构造以“物理 CPU 寄存器”起家的槽。
    *   `new_unique`: 构造代表着隐藏或者临时中间状态的槽。
    *   `new_constant`: 构造纯属“即刻常数”的字面量。
*   **四象限基础属性**: 所有的 Varnode 都可以借由其基础接口追溯到其 `AddressSpace`(驻扎的地址大空间：RAM/寄存器/栈/堆等)、自身起址 `Offset`、占用字节数 `Size` 以及 `Version`（SSA分析时附加的版本标识）。 

---

## 4. Opcodes 操作总集 (`ops.rs`)

系统中使用的 `PcodeOp` 包含了标准 Ghidra 所定义的各类操作动作词穷举，详见如下重要子集:

| 操作码词 / Opcode | 输入数 | 是否有输出 | 对应逻辑描绘 |
| :--- | :--- | :--- | :--- |
| `COPY` | 1 | 是 | `out = in1` (值直传) |
| `LOAD` | 2 | 是 | `out = *in1` (in2作空间指定符) |
| `STORE` | 3 | 否 | `*in1 = in2` (写入操作) |
| `INT_ADD` | 2 | 是 | 整数加法运算 |
| `INT_ZEXT` / `INT_SEXT`| 1 | 是 | 整数零扩展或符号位扩展 |
| `BRANCH` / `CBRANCH` | 1/2 | 否 | `goto` 与 conditional `if goto` |
| `BRANCHIND`| 1 | 否 | 涉及间接查表或函数指针触发的无条件多出边跨越 `goto *val` |
| `CALL` / `CALLInd`| 1+ | 可选 | 函数(直接/间接)调用记录 `call fn(args...)` |
| `RETURN` | 0+ | 否 | 终止并返回 `return (in1...)` |
| `PHI` | N | 是 |  纯构想指令：多出处流并齐后的合并赋值 `phi(in1..inN)` |
| `CALLOTHER` | N | 可选 | 用户自定义黑盒调用 (如汇编级IO请求) |

---

## 5. 快速排布器 (`program.rs` 的 `PcodeBuilder`)

主要是用于转译引擎（Translator）快速地从原 x86 抽象出这数百条 Pcode 指令的辅助构造器，简化大量机械的内部组装。内部包裹了 `add_op` 可以一次性赋予唯一的时序排号和关联位置并插回 `Program`。