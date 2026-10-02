# `align/mod.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/mod.rs`

## 模块说明 (Module Doc)

Alignment verification module for Rudra and Ghidra.

This module contains the logic to verify that Rudra's internal data structures
and analysis results match Ghidra's C++ decompiler implementation.

# Runtime Verification

The `runtime_verify` module provides actual runtime comparison testing between
Rudra and Ghidra outputs, going beyond static type checking to ensure behavioral
equivalence. This is critical for guaranteeing output consistency.

Note: Runtime verification requires `once_cell` dependency in Cargo.toml

## 导出的公共 API (Public API)

### `pub trait AlignmentCheck`

Helper trait for objects that can be cross-verified with Ghidra

<!-- annotation-pass: 2026-07-04 -->
