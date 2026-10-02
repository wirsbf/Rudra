# `align/range.rs` API Reference

**状态**: 已核对（当前有效）  
**源代码路径**: `src/align/range.rs`

## 模块说明 (Module Doc)

Range and RangeList alignment verification logic.

This module ensures that Rudra's address range representation matches Ghidra's
internal Range and RangeList classes as defined in `address.hh`.

## 导出的公共 API (Public API)

### `pub struct Range`

Represents an address range (start, end)

Corresponds to Ghidra's Range class

### `pub fn new(first: Address, last: Address) -> Option<Self>`

Create a new range

### `pub fn contains(&self, addr: Address) -> bool`

Check if an address is contained in this range

### `pub fn get_first(&self) -> Address`

Get the first address

### `pub fn get_last(&self) -> Address`

Get the last address

### `pub fn size(&self) -> u64`

Get the size of the range in bytes

### `pub fn overlaps(&self, other: &Range) -> bool`

Check if this range overlaps with another

### `pub fn is_adjacent(&self, other: &Range) -> bool`

Check if this range is adjacent to another

### `pub struct RangeList`

Represents a collection of non-overlapping address ranges

Corresponds to Ghidra's RangeList class

### `pub fn new() -> Self`

Create a new empty range list

### `pub fn insert_range(&mut self, new_range: Range)`

Insert a range into the list, merging overlapping ranges

### `pub fn remove_range(&mut self, to_remove: Range)`

Remove a range from the list

### `pub fn in_range(&self, addr: Address) -> bool`

Check if an address is in any range in the list

### `pub fn num_ranges(&self) -> usize`

Get the number of ranges in the list

### `pub fn ranges(&self) -> &[Range]`

Get all ranges

### `pub fn merge(&mut self, other: &RangeList)`

Merge another RangeList into this one

### `pub fn is_empty(&self) -> bool`

Check if the list is empty

### `pub fn clear(&mut self)`

Clear all ranges

### `pub fn verify_range(`

Verify that a Rudra Range aligns with Ghidra's representation

### `pub fn verify_range_list(`

Verify that a Rudra RangeList aligns with Ghidra's representation

### `pub fn verify_contains(`

Verify that contains() function aligns

<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
