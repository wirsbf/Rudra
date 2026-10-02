# compression.rs — Compression API

Rust wrappers corresponding to Ghidra's `compression.hh` / `compression.cc`.

**Status:** L2. `Decompress` has a persistent low-level inflate state and a
locked 12.0.4 behavior fixture for its normal, replacement, alias-mutation,
and data-error paths. `Compress` is still non-equivalent and `CompressBuffer`
is absent, so this module is not L3.

Ghidra reference: `ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/compression.{hh,cc}`.

## Structs

### `Compress`
Wrapper for the deflate algorithm (compression.hh:34).
- `new(level)` — initialize (compression.hh:37).
- `input(buffer)` — provide bytes to compress (compression.hh:44).
- `deflate(buffer, finish) -> i32` — compress into buffer (compression.hh:48).

### `Decompress`
Wrapper for the inflate algorithm (compression.hh:55).
- `new() -> Result<Decompress>` — initialize persistent system-zlib state and
  preserve the constructor failure (`compression.cc:59`).
- `unsafe input(buffer, size)` — replace `next_in/avail_in` without resetting
  state (`compression.hh:66`). The raw pointer and `i32` size preserve the C++
  parameter domain. The caller retains the pointed-to allocation and may mutate
  it only between calls.
- `is_finished() -> bool` — end of stream reached.
- `unsafe inflate(buffer, size) -> Result<i32>` — perform one inflate step and
  return the remaining output capacity (`compression.cc:78`). Raw input and
  output pointers may alias, including at the same address. Only `StreamEnd`
  marks the stream finished; zlib errors become `Error::Lowlevel`.
- `Drop` calls `inflateEnd` exactly once (`compression.cc:101`).

## Free functions
- `compress_all(data, level) -> Vec<u8>` — one-shot deflate.
- `decompress_all(data) -> Vec<u8>` — one-shot inflate.

## Remaining alignment work

- `Compress` rebuilds the encoder per call, clamps legal levels, ignores true
  finish/streaming semantics, and returns bytes written instead of remaining
  capacity.
- `CompressBuffer` is not implemented.
- `compress_all` / `decompress_all` are Rust convenience glue and are not
  substitutes for the two Ghidra stream classes.
- Constructor failure, `Z_NEED_DICT`, `Z_MEM_ERROR`, `Z_STREAM_ERROR`, and
  destructor fault-injection paths do not yet have locked runtime observations.

## Runtime evidence

`tools/run_decompress_oracle.sh` builds the locked 12.0.4 `compression.cc`
fixture and the Rust mirror, verifies both resolve the same system `libz.so.1`
and version, then directly diffs their byte-for-byte stdout. The fixture covers
no input, output-limited streaming, clean and mid-stream input replacement,
caller-side input mutation, same-address input/output, normal stream
completion, and `Z_DATA_ERROR`.
<!-- annotation-pass: 2026-07-04 -->
<!-- rename-pass: 2026-10-02 rugra→rudra identity sweep; this module doc carried no prior-name tokens -->
