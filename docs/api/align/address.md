# `align/address.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/address.rs`

## 模块说明 (Module Doc)

Address and SeqNum alignment verification logic.

This module ensures that Rudra's address representation matches Ghidra's
internal Address and SeqNum classes as defined in `address.hh`.

## 导出的公共 API (Public API)

### `pub fn verify_address(`

Verify that a Rudra Address aligns with Ghidra's representation.

Ghidra Addresses consist of an AddressSpace and an offset.

### `pub fn verify_seqnum(`

Verify that a Rudra SeqNum aligns with Ghidra's representation.

Ghidra SeqNum includes an Address and a 'time' or 'order' index
used to distinguish multiple P-code operations for a single instruction.

### `pub fn map_ghidra_space(space_id: i32) -> AddressSpace`

Helper to convert Ghidra space ID to Rudra AddressSpace for verification

 
<!-- annotation-pass: 2026-07-04 -->
