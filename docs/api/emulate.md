# `emulate.rs` API Reference

**源代码路径**: `src/emulate.rs`
**Ghidra 对应**: `emulate.hh` / `emulate.cc` (1013行)
**状态**: 📋 L1→🔧 L2（Emulate 骨架 + execute_op 使用 opbehavior evaluate）

## 模块说明

P-code 模拟执行引擎。对应 Ghidra 的 `emulate.hh`。
执行 P-code 操作于虚拟机状态，用于常量传播和跳转表分析。

## 导出的公共 API

### `pub enum EmulateOpBehavior`
执行结果（Continue/Branch/Return/Error）。

### `pub struct Emulate`
基础 P-code 模拟器。对应 Ghidra `Emulate`。
- `new()` — 构造
- `execute_op(op)` — 执行单个 PcodeOp，使用 opbehavior evaluate 进行常量折叠
- `terminated` — 是否已终止

**当前限制**：BreakCallBack/BreakTable、内存 LOAD/STORE 集成待补。

测试：emulate::tests 1 个。

## 2026-06-26（续）：emulate.rs 完善实现

新增完整模拟器功能：
- **Register file**：`(space_id, offset) → value` 映射，`set_register/get_register`
- **LOAD/STORE 集成**：execute_op 现在通过 MemState 执行 LOAD/STORE
- **CBRANCH 条件检查**：评估常量条件决定分支
- **Instruction limit**：`max_instructions` 限制模拟指令数（0=无限）
- **结果存储**：算术/逻辑操作结果存入寄存器文件

测试：新增 2 个（register_file + instruction_limit）。

### 2026-06-27（会话3 G7）：execute_current_op + execute() 主循环完整移植

完整移植 Ghidra `Emulate::executeCurrentOp`（emulate.cc:143-216）+ 主 execute 循环：

- `get_value(vn)` / `set_value(vn, val)` — MemoryState::getValue/setValue 等价：常量返回 offset，其他 varnode 返回寄存器值（非仅常量）。
- `execute_current_op(op)` — executeCurrentOp dispatch：LOAD/STORE→MemState，BRANCH/CBRANCH/BRANCHIND/CALL/CALLIND/RETURN 控制流，COPY/unary→execute_unary，binary→execute_binary。
- `execute_unary` / `execute_binary` — EmulateMemory::executeUnary/Binary：opbehavior evaluate + set_value。
- `execute_load` / `execute_store` — executeLoad/Store：MemState bank get/set。
- `execute(ops)` — 主循环：按序步进 ops，Continue 推进，Branch/Return/Error 终止。

4 单元测试：COPY 常量、INT_ADD、链式执行（COPY→INT_ADD 结果传递）、RETURN 终止。
2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rudra→rudra identity sweep; this module doc carried no prior-name tokens -->
