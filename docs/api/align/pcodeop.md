# `align/pcodeop.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/pcodeop.rs`

## 模块说明 (Module Doc)

PcodeOp and PcodeOperation alignment verification logic.

This module ensures that Rudra's P-code operations match Ghidra's
internal PcodeOp representation as defined in `op.hh`.

## 导出的公共 API (Public API)

### `pub fn verify_opcode(rudra_op: OpCode, ghidra_opcode: i32) -> bool`

Verify that a Rudra OpCode matches a Ghidra opcode

### `pub fn verify_operation(`

Verify that a complete PcodeOperation aligns with Ghidra's representation

This checks:
- Opcode match
- SeqNum match
- Input count and values
- Output presence and value

### `pub fn verify_inputs(rudra_inputs: &[Varnode], ghidra_inputs: &[VarnodeFFI]) -> bool`

Verify input list alignment

### `pub fn verify_output(rudra_output: Option<&Varnode>, ghidra_output: Option<&VarnodeFFI>) -> bool`

Verify output alignment

 
<!-- annotation-pass: 2026-07-04 -->
