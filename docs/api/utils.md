# `utils.rs` API Reference

## 文档状态

- **状态**: 部分有效（需对照源码）


**源代码路径**: `src/utils.rs`

## 模块说明 (Module Doc)

Utility functions and helpers for Rudra

This module contains various utility functions used throughout the decompiler,
including bit manipulation, collection helpers, and common operations.

## 导出的公共 API (Public API)

### `pub fn extract(value: u64, start: usize, length: usize) -> u64`

Extract a bit range from a value

# Arguments

* `value` - The value to extract from
* `start` - Starting bit position (0-indexed)
* `length` - Number of bits to extract

# Example

```rust,ignore
let value = 0b11010110u8;
let bits = extract(value as u64, 2, 4);
assert_eq!(bits, 0b0101);
```

### `pub fn insert(value: u64, start: usize, length: usize, bits: u64) -> u64`

Set a bit range in a value

# Arguments

* `value` - The original value
* `start` - Starting bit position
* `length` - Number of bits to set
* `bits` - The bits to insert

### `pub fn sign_extend(value: u64, bits: usize) -> i64`

Sign-extend a value

# Arguments

* `value` - The value to sign-extend
* `bits` - Number of significant bits in the value

### `pub fn popcount(value: u64) -> u32`

Count the number of set bits (population count)

### `pub fn leading_zeros(value: u64) -> u32`

Count leading zeros

### `pub fn trailing_zeros(value: u64) -> u32`

Count trailing zeros

### `pub fn is_power_of_two(value: u64) -> bool`

Check if a value is a power of 2

### `pub fn next_power_of_two(value: u64) -> u64`

Get the next power of 2 greater than or equal to the value

### `pub fn hex_bytes(bytes: &[u8]) -> String`

Format a byte slice as a hexadecimal string

### `pub fn format_address(addr: Address, width: usize) -> String`

Format an address with padding

### `pub fn escape_c_string(s: &str) -> String`

Escape a string for C output

### `pub fn make_c_identifier(s: &str) -> String`

Generate a valid C identifier from a string

### `pub fn compute_dominators<T>(`

Compute dominators using the iterative algorithm

Returns a map from each node to its immediate dominator

### `pub fn topological_sort<T>(nodes: &[T], edges: &HashMap<T, Vec<T>>) -> Option<Vec<T>>`

Perform topological sort on a directed acyclic graph

### `pub fn read_u64(bytes: &[u8], offset: usize, size: usize, little_endian: bool) -> Result<u64>`

Read a value from bytes with the given endianness

### `pub fn align_up(value: u64, alignment: u64) -> u64`

Align a value up to the given alignment

### `pub fn align_down(value: u64, alignment: u64) -> u64`

Align a value down to the given alignment

### `pub fn is_aligned(value: u64, alignment: u64) -> bool`

Check if a value is aligned

### `pub fn hash_map_with_capacity<K, V>(capacity: usize) -> HashMap<K, V>`

Create a HashMap with initial capacity

### `pub fn group_by<T, K, F>(items: Vec<T>, key_fn: F) -> HashMap<K, Vec<T>>`

Group items by a key function

 
<!-- annotation-pass: 2026-07-04 -->
