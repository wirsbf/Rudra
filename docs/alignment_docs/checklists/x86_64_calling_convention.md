# Ghidra 对齐说明：x86_64 调用约定 (Calling Convention)

**[状态]**: 🔴 TODO  
**[目标模块]**: x86_64 架构下系统及用户函数的参数传递规则还原  
**[关联 Ghidra 源码位置]**: `Ghidra/Processors/x86/data/languages/x86-64.cspec` 及对应分析层  
**[关联 Rudra 源码位置]**: 待新建或补充 `src/analysis/calls.rs` 等模块  

---

## 1. 目标描述 (Description)

在反编译推导阶段，不仅需要识别函数的位置，还需要正确找出被调用函数究竟**使用了哪些寄存器或栈偏移作为形式参数**，并遵循了何种清理栈的规范（`__stdcall`, `__cdecl`, `__fastcall` 等）。
目前尚未建立与 Ghidra 的 `cspec` （Compiler Specification）驱动等价的传参规约动态推算系统，这导致所有通过栈传递的参数或者隐藏参数 (Hidden Return Pointer) 无法被正确识别和类型挂接。

## 2. Ghidra 的实现逻辑 (Ghidra Implementation)

- **数据结构**: 
  - 通过加载 `<compiler_spec>` 相关的 XML 定义树。
  - `ProtoModel` 类对 `__cdecl`, `__stdcall` 等概念进行分离开箱。
- **核心算法**:
  1. 通过支配与活跃度分析，收集入参点寄存器 (`RCX`, `RDX`, `R8`, `R9` 等) 或者出参寄存器 (`RAX`) 是否在其定义前被该函数块消费者所读取 (`Varnode::is_input() == true`)。
  2. 匹配 `cspec` 中的顺序模板分配规则，按字长给他们贴上实参编号。

## 3. Rudra 的对齐方案 (Rudra Approach)

Rudra 计划在后续模块中实现一套针对 FFI 的静态传参推导状态机，以对齐 Ghidra 的 `cspec` 核心机制。现硬编码规定以下两种主流 ABI 规约作为分析器推断基准：

### 3.1. System V AMD64 ABI (Linux/macOS)
- **整型/指针参数寄存器 (按序)**: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`
- **浮点参数寄存器 (按序)**: `XMM0` 到 `XMM7`
- **返回值寄存器**: `RAX` (整型/指针), `XMM0`, `XMM1` (浮点)
- **栈传递**: 超过寄存器数量的参数按从右向左的顺序压栈（由调用者清理栈）。

### 3.2. Windows x64 ABI (Microsoft x64 calling convention)
- **整型/指针参数寄存器 (按序)**: `RCX`, `RDX`, `R8`, `R9`
- **浮点参数寄存器 (按序)**: `XMM0` 到 `XMM3` (与整型寄存器槽位一一对应共享)
- **Shadow Space**: 栈顶上方（即调用者的栈帧中）必须为这前四个参数预留 32 字节的空间（Shadow Store），即便参数少于 4 个。
- **返回值寄存器**: `RAX` (整型/指针), `XMM0` (浮点)
- **栈传递**: 第 5 个开始的参数从右向左压栈（由调用者清理栈）。

### 执行步骤
- [x] **规划: 步骤 1**: 在 Rust 端界定轻量的静态调用规约序列表（见上述 Windows x64 与 System V AMD64 ABI 规则）。
- [ ] **待办: 步骤 2**: 数据流提取。改造基于 `Funcdata` 和 `ActionDatabase` 的分析系统，提取入口处被读取（`is_input() == true` 及未初始化先读）的 `Varnode`，利用此存活寄存器序列与上述规约求交配对，得出函数传参原型 `CallPrototype`。
- [ ] **待办: 测试验证**: 编译各类带混合传参（如 `int foo(int a, float b, int c, double d)`）的 C 代码片段进行 FFI 验证，端对端断言恢复出的传参位置与 Ghidra 原生 C++ 架构的输出完全等价。
