# loadimage.rs — Binary load image API

Faithful port of Ghidra's `loadimage.hh` / `loadimage.cc` (116 lines).

**Status:** ✅ **L3（2026-06-28 完整对齐）**. Complete LoadImage trait covering all Ghidra virtuals + RawLoadImage + MemoryLoadImage. 10 unit tests.
implementations. This unblocks EmulateFunction's `getLoadImageValue`,
JumpBasic's `sanityCheck`, and Architecture's `loader` field.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.{hh,cc}`.

## Structs

### `DataUnavailError`
Error indicating data was not available (loadimage.hh:31).

### `LoadImageFunc`
A record indicating a function symbol (loadimage.hh:38).
- Fields: `address: Address`, `name: String`.

### `LoadImageSection`
A record describing a section of bytes (loadimage.hh:46).
- Fields: `address: Address`, `size: u64`, `flags: u32`.

### Module `section_flags`
- `UNALLOC = 1`, `NOLOAD = 2`, `CODE = 4`, `DATA = 8`, `READONLY = 16`.

## Trait `LoadImage`
Interface into a binary executable image (loadimage.hh:73).
- `get_filename() -> &str`
- `load_fill(size, addr) -> Result<Vec<u8>, DataUnavailError>` — core routine
  (loadimage.hh:80)
- `load(size, addr) -> Result<Vec<u8>, DataUnavailError>` — convenience wrapper
  (loadimage.cc:29)
- `load_value(addr, size) -> Result<u64, DataUnavailError>` — single-value load
- `open_symbols()` / `close_symbols()` / `get_next_symbol(record) -> bool`
- `open_section_info()` / `close_section_info()` / `get_next_section(record) -> bool`
- `get_readonly() -> RangeList`
- `get_arch_type() -> String`, `adjust_vma(adjust)`

## Implementations

### `RawLoadImage`
Simple raw binary load image (loadimage.hh:98). Reads bytes from file data.
- `new(filename)`, `open()` (loadimage.cc:58), `from_bytes(filename, vma, data)`.
- `file_size() -> u64`.

### `MemoryLoadImage`
In-memory load image backed by a byte buffer. Useful for testing and the
existing Rudra binary-parsing pipeline.
- `new(data, base_addr, arch_type)`.
<!-- annotation-pass: 2026-07-04 -->
