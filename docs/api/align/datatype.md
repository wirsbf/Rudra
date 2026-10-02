# `align/datatype.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/datatype.rs`

## 模块说明 (Module Doc)

DataType alignment verification logic.

This module ensures that Rudra's type system matches Ghidra's
internal Datatype representation as defined in `type.hh`.

## 导出的公共 API (Public API)

### `pub fn verify_datatype(`

Verify that a Rudra DataType aligns with Ghidra's representation

Checks size and metatype compatibility

### `pub fn verify_struct_layout(`

Verify struct layout alignment

Checks that field offsets and sizes match between Rudra and Ghidra

### `pub fn verify_field(`

Verify field definition alignment

### `pub fn verify_pointer_type(`

Verify pointer type alignment

### `pub fn verify_array_type(`

Verify array type alignment

### `pub fn verify_primitive_size(rudra_type: &DataType, ghidra_size: usize) -> bool`

Verify primitive type size alignment

<!-- annotation-pass: 2026-07-04 -->
