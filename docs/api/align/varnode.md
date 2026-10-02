# `align/varnode.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/varnode.rs`

## 模块说明 (Module Doc)

Varnode alignment verification logic.

This module ensures that Rudra's Varnode representation matches Ghidra's
internal Varnode class as defined in `varnode.hh`.

## 导出的公共 API (Public API)

### `pub fn verify_varnode(rudra_vn: &Varnode, ghidra_vn: &VarnodeFFI) -> bool`

Verify that a Rudra Varnode aligns with Ghidra's FFI representation.

This checks space, offset, and size parity.

### `pub fn verify_varnode_list(rudra_list: &[Varnode], ghidra_list: &[VarnodeFFI]) -> bool`

Verify a list of Varnodes (typically P-code operation inputs)

 
<!-- annotation-pass: 2026-07-04 -->
