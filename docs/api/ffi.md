# `ffi.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/ffi.rs`

## 模块说明 (Module Doc)

FFI interface for Rugra

This module provides C-compatible interfaces to Rugra's core logic,
allowing it to be integrated into Ghidra's C++ decompiler or used for
comparison testing ("对拍").

## 2026-08-12：ANN-L extern ABI provenance

锁定 oracle 为 Ghidra 12.0.4 commit
`e40ed13014025f82488b1f8f7bca566894ac376b`。本轮为 10 个导出的
`extern "C"` / `unsafe extern "C"` 函数补充了逐入口 `RUDRA-GLUE`
来源说明：这些函数是 Rugra 的 C/Python 对拍 ABI，不是 Ghidra 的一对一算法函数。

- `rugra_evaluate_constant` 聚合桥接多个
  `OpBehavior::evaluateUnary/evaluateBinary` 实现；Ghidra 没有相同的单一 C ABI
  dispatcher。
- `rugra_init_test_program` 与 `rugra_add_test_op` 构造 Rugra 专用的全局测试
  fixture；它们不是 `Funcdata`、`PcodeOpBank` 或 `Varnode` 构造算法的映射。
- `rugra_observe_jumptable`、`rugra_check_varnode_version`、
  `rugra_check_block_structure` 与 `rugra_check_action_apply` 只消费并记录外部观察，
  分别不等同于 `JumpTable::recoverAddresses`、`Heritage::rename`、`FlowBlock`
  算法或 `Action::perform`。
- `rugra_version`、`rugra_set_binary_data` 与 `rugra_compare_pcode` 分别是版本导出、
  仅忽略外部指针并记录长度的诊断入口和跨引擎比较器，Ghidra 没有对应的 Rugra
  ABI endpoint。Ghidra 的 `Varnode` 也没有 `rugra_check_varnode_version` 所接收的
  数字 `version` 字段。

本轮只增加 provenance 注释与文档，未改变 ABI 或运行行为；这些注释不构成
Ghidra 函数行为 `MATCH` 证据，也不升级模块状态。

## 导出的公共 API (Public API)

### `pub struct VarnodeFFI`

C-compatible representation of a Varnode for FFI comparison

### `pub extern "C" fn rugra_evaluate_constant(`

FFI interface for constant folding evaluation

This adapter covers a subset of Ghidra's distributed
OpBehavior::evaluateBinary/Unary implementations; it is not a one-to-one mapping.

# Arguments
* `opcode` - The Ghidra OpCode integer
* `size_out` - Expected output size in bytes
* `val1` - First input constant value
* `size1` - First input size in bytes
* `val2` - Second input constant value
* `size2` - Second input size in bytes
* `has_val2` - Boolean indicating if the second input is used (binary op)

# Returns
The resulting constant value, or 0 if evaluation failed or opcode is unsupported.

### `pub extern "C" fn rugra_version() -> *const c_char`

Get the version of Rugra as a C string

### `pub fn set_current_program(program: Funcdata)`

Set the current program for comparison
This is called by Rugra before starting the comparison with Ghidra

**2026-09-24**：`CURRENT_PROGRAM` 四个访问点（`set_current_program` /
`rugra_init_test_program` / `rugra_add_test_op` / `rugra_compare_pcode`）的
`.lock().unwrap()` 改为 `unwrap_or_else(|p| p.into_inner())`（中毒恢复）。
互斥语义不变；修复 TESTLIB-STATE-CONTAMINATION-0001 的次级污染向量——某测试
在持锁临界区内 panic 时毒化单例，后续所有 `set_current_program` 调用者级联
`PoisonError`。调用者总是在读取前整槽覆写，恢复边界不会泄漏对拍状态。

### `pub extern "C" fn rugra_init_test_program()`

Initialize a blank program for FFI testing

### `pub extern "C" fn rugra_add_test_op(`

Add an operation to the current test program
This allows Python/C++ to simulate Rugra's analysis state for comparison tests

### `pub extern "C" fn rugra_set_binary_data(_ptr: *const u8, len: usize)`

Report binary-buffer metadata received from an FFI caller.
The pointer is currently ignored; only the supplied length is logged.

### `pub extern "C" fn rugra_observe_jumptable(op_addr: u64, table_addr: u64, size: usize)`

Observe and validate a jumptable recovery in Ghidra

This is used for comparison testing to ensure Rugra's jumptable
recovery matches Ghidra's and is logically sound.

### `pub unsafe extern "C" fn rugra_compare_pcode(`

Compare a P-code operation from Ghidra with Rugra's internal state

This is the "ultimate comparison" function that verifies if Rugra's
entire analysis pipeline produces the same P-code structure as Ghidra.

### `pub unsafe extern "C" fn rugra_check_varnode_version(`

Intercept and compare SSA versioning (Heritage)

### `pub unsafe extern "C" fn rugra_check_block_structure(`

Intercept and compare Control Flow Graph structure

### `pub unsafe extern "C" fn rugra_check_action_apply(`

Intercept and compare Transformation Actions

### OpCode → Ghidra numeric value mapping

`fn opcode_to_ghidra_value(opc: OpCode) -> Option<u32>` maps Rugra's
`OpCode` enum to the integer wire-value used by Ghidra's P-code format
(`opcodes.hh`). **2026-06-27**：新增 `CPUI_CAST => Some(64)`，填补
`SUBPIECE(63)` 与 `PTRADD(65)` 之间的空缺。

 2026-06-27: opcode 改名对齐 Ghidra 规范名 — BOOL_NOT->BOOL_NEGATE / INT_NEG->INT_2COMP / INT_NOT->INT_NEGATE (opcodes.hh:67/68/81)。纯重命名，行为不变。

**2026-07-02**：`map_ghidra_opcode(64)` Ghidra→Rugra 方向原被注释掉，与 `to_ghidra_opcode`（Rugra→Ghidra 已映射 CPUI_CAST→64）不对称，导入时丢失 CPUI_CAST。现已补回 `64 => Some(OpCode::CPUI_CAST)`，往返对称。
<!-- annotation-pass: 2026-07-04 -->
<!-- opcode-correct: 1783180039.0619004 -->
