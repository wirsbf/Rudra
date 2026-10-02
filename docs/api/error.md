# `error.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/error.rs`

## 模块说明 (Module Doc)

Error types for Rudra

This module defines all error types used throughout the decompiler.
We use `thiserror` for ergonomic error handling.

## 导出的公共 API (Public API)

### 2026-09-26 变体清理（SLEIGH-RUSTIFY-PHASE3-0001）

`Error::Capstone`（`#[cfg(feature = "capstone")]` 变体）与
`From<capstone::Error>` 转换已删除：capstone 依赖随 iced-x86 解码器一同从
`Cargo.toml` 退役（capstone feature flag 一并移除，default features 现为
`["cli"]`）。该变体自引入起无生产消费方。

### `pub type Result<T> = std::result::Result<T, Error>`

Result type alias for Rudra operations

### `pub enum Error`

Main error type for Rudra

- `Lowlevel(String)` represents Ghidra's aborting `LowlevelError` category and
  preserves its explanatory message.

### `pub trait ErrorContext<T>`

Helper trait for adding context to errors

<!-- annotation-pass: 2026-07-04 -->
