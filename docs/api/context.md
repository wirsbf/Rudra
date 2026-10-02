# context.rs — Context database API

Faithful port of Ghidra's `globalcontext.hh` / `globalcontext.cc` (618 lines).

**Status:** L1 → L2. Complete ContextBitRange + TrackedContext + ContextDatabase
trait + ContextInternal + ContextCache. L3 gap: XML encode/decode +
partmap-based partition (currently Vec-backed) + ParserContext/ParserWalker
(SLEIGH-specific, context.hh).

Ghidra reference:
`ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/globalcontext.{hh,cc}`.

## Structs

### `ContextBitRange`
Description of a context variable within the blob (globalcontext.hh:40).
- `new(sbit, ebit)` — construct from absolute bit range (globalcontext.cc:33).
- `get_shift()`, `get_mask()`, `get_word()`.
- `set_value(vec, val)` — set within blob (globalcontext.hh:57).
- `get_value(vec) -> u32` — get from blob (globalcontext.hh:68).

### `TrackedContext`
A tracked register and its value (globalcontext.hh:78).
- Fields: `offset: u64`, `size: u32`, `val: u64`.

### `TrackedSet` = `Vec<TrackedContext>`

### `ContextBlob`
A context blob (values + mask) across an address range
(globalcontext.hh:271).
- `new(size)`, `reset(size)`.

## Trait `ContextDatabase`
Interface to context information (globalcontext.hh:118).
- `get_context(addr) -> &[ContextWord]`
- `get_tracked_set(addr) -> &TrackedSet`
- `create_set(addr1, addr2) -> &mut TrackedSet`
- `get_tracked_default() -> &TrackedSet`
- `get_default_value() -> &[ContextWord]` / `get_default_value_mut()`
- `register_variable(nm, sbit, ebit)`
- `get_context_size() -> usize`
- `get_tracked_value(offset, size, point) -> u64`

## `ContextInternal`
In-memory implementation (globalcontext.hh:264).
- `new()`, `register_variable`, `set_variable_default`,
  `get_default_value_for`, `set_variable`, `get_variable_at`,
  `get_variable`/`get_variable_mut`.
- Implements `ContextDatabase`.

## `ContextCache`
Helper caching the active blob (globalcontext.hh:317).
- `new(database)`, `allow_set(val)`, `get_context(addr)`, `set_context(...)`.

## L3 gaps
- XML encode/decode (`<context_data>`/`<context_pointset>`/`<tracked_set>`).
- `partmap<Address, FreeArray>` partition map (currently Vec-backed).
- `getRegionForSet`/`getRegionToChangePoint` for multi-region context setting.
- `ParserContext`/`ParserWalker` (context.hh — SLEIGH-specific, needs
  Constructor/TripleSymbol).

## 2026-06-27（续）：XML encode/decode — context.rs 达到 L3

- **ContextInternal::encode**：编码 `<context_points>` + `<context_pointset>`（每个 changepoint 的变量值）+ `<tracked_pointset>`（tracked 寄存器）。
- **ContextInternal::decode**：解码 `<context_points>` 恢复 context blob + tracked set。
- **get_or_create_blob_at_mut**：辅助方法用于 decode 时获取或创建 mutable blob。
- context.rs XML encode/decode L3 缺口已关闭。
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
