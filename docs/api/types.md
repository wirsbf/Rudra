# `types.rs` API Reference

## 文档状态

- **状态**: 部分有效（需对照源码）

2026-08-12 ANN-N 仅补 provenance：本模块的 13 个 const helper 属于 Rudra
兼容层标量/枚举元数据；锁定 oracle 的 `Address`、`Architecture`、`Datatype`
及 `HOST_ENDIAN` 没有同语义的独立函数。本次未改变行为或模块状态。

**源代码路径**: `src/types.rs`

## 模块说明 (Module Doc)

Core type definitions for Rudra

This module contains fundamental types used throughout the decompiler,
including address types, architecture definitions, and basic data types.

## 导出的公共 API (Public API)

### `pub struct Address(u64)`

Memory address type

Represents a virtual memory address in the target binary.
Internally stored as u64 to support 64-bit architectures.

### `pub const fn new(addr: u64) -> Self`

Create a new address

### `pub const fn as_u64(&self) -> u64`

Get the raw address value

### `pub fn offset(&self, offset: i64) -> Self`

Add an offset to the address

### `pub fn is_null(&self) -> bool`

Check if address is null (0x0)

### `pub fn is_aligned(&self, alignment: u64) -> bool`

Check if address is aligned to the given boundary

### `pub enum Architecture`

Target CPU architecture

### `pub const fn pointer_size(&self) -> usize`

Get the pointer size in bytes for this architecture

### `pub const fn pointer_bits(&self) -> usize`

Get the pointer size in bits for this architecture

### `pub const fn is_64bit(&self) -> bool`

Check if this is a 64-bit architecture

### `pub const fn register_count(&self) -> usize`

Get the register count (approximate)

### `pub const fn name(&self) -> &'static str`

Get architecture name as string

### `pub enum TypeKind`

Data type sizes and kinds

### `pub const fn size_bytes(&self) -> Option<usize>`

Get the size in bytes of this type (if fixed-size)

### `pub const fn is_integer(&self) -> bool`

Check if this is an integer type

### `pub const fn is_signed(&self) -> bool`

Check if this is a signed integer type

### `pub const fn is_float(&self) -> bool`

Check if this is a floating point type

### `pub const fn is_pointer(&self) -> bool`

Check if this is a pointer type

### `pub enum CallingConvention`

Calling convention

### `pub enum Endianness`

Endianness

### `pub const fn native() -> Self`

Get the native endianness of the current system

### `pub enum DataType`

Rich data type representation for analysis

### `pub fn size(&self) -> usize`

Get the size of the type in bytes

### `pub fn is_unknown(&self) -> bool`

Check if this is an unknown type

### `pub fn is_pointer(&self) -> bool`

Check if this is a pointer type

### `pub fn is_integer(&self) -> bool`

Check if this is an integer type

### `pub fn meet(&self, other: &DataType) -> DataType`

The "meet" operation in the type lattice.
Combines two types into their greatest lower bound.

### `pub struct StructDef`

A structure definition

### `pub struct FieldDef`

A field in a structure

### `pub fn new(name: String) -> Self`

Create a new empty struct definition

### `pub fn add_field(&mut self, name: String, data_type: DataType, offset: usize)`

Add a field to the struct

### `pub fn size(&self) -> usize`

Get the total size of the struct

### `pub fn parse_type_string(s: &str, size: usize) -> DataType`

Parse a C-style type string into a DataType


<!-- annotation-pass: 2026-07-04 -->
