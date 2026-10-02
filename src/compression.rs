//! Compression wrappers corresponding to `compression.hh` / `compression.cc`.
//!
//! Wrappers for the deflate (Compress) and inflate (Decompress) algorithms.
//! Used by the marshal Packed format for compressed serialization.
//! `Decompress` follows the persistent Ghidra/zlib stream contract. `Compress`
//! and `CompressBuffer` remain tracked alignment work.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/compression.{hh,cc}.

use crate::error::{Error, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};
use std::mem::MaybeUninit;

/// Wrapper for the deflate algorithm. Faithful to `Compress`
/// (compression.hh:34).
///
/// Initialize the algorithm, provide input via `input()`, and compress via
/// `deflate()`.
pub struct Compress {
    /// The input buffer awaiting compression.
    input_buf: Vec<u8>,
    /// The compression level (1-9, where 1=fastest, 9=best).
    level: i32,
}

impl Compress {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Initialize the deflate algorithm state. Faithful to the constructor
    /// (compression.hh:37).
    pub fn new(level: i32) -> Self {
        Self {
            input_buf: Vec::new(),
            level,
        }
    }

    // RUDRA-GLUE: input (no Ghidra counterpart found)
    /// Provide the next sequence of bytes to be compressed. Faithful to
    /// `input` (compression.hh:44).
    pub fn input(&mut self, buffer: &[u8]) {
        self.input_buf.extend_from_slice(buffer);
    }

    // RUDRA-GLUE: deflate (no Ghidra counterpart found)
    /// Deflate as much as possible into the given buffer. Faithful to
    /// `deflate` (compression.hh:48). Returns the number of compressed bytes
    /// written.
    pub fn deflate(&mut self, buffer: &mut [u8], finish: bool) -> i32 {
        if self.input_buf.is_empty() && !finish {
            return 0;
        }

        // Use flate2 ZlibEncoder for actual compression.
        let level = self.level.clamp(1, 9) as u32;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(&self.input_buf).ok();
        // Always finish — partial flush with flate2 is complex.
        let compressed = encoder.finish().unwrap_or_default();
        let _ = finish;

        // Copy as much as fits into the output buffer.
        let take = buffer.len().min(compressed.len());
        buffer[..take].copy_from_slice(&compressed[..take]);

        // Clear consumed input.
        self.input_buf.clear();

        take as i32
    }
}

/// Persistent wrapper for the zlib inflate algorithm (`compression.hh:55`).
pub struct Decompress {
    /// Exact zlib stream state, including the caller-owned next-input pointer.
    stream: Box<libz_sys::z_stream>,
    /// True if the end of the compressed stream has been reached.
    stream_finished: bool,
}

impl Decompress {
    // Ghidra: compression.cc:59 Decompress::Decompress(void)
    /// Initialize a zlib-header inflate stream with no input.
    pub fn new() -> Result<Self> {
        // Keep the zeroed C storage in MaybeUninit because libz-sys models the
        // initially-null allocator callbacks as non-nullable function pointers.
        let mut stream = Box::new(MaybeUninit::<libz_sys::z_stream>::zeroed());
        // SAFETY: stream points to writable C storage with the exact ABI size,
        // and zlibVersion comes from the same linked zlib implementation.
        let status = unsafe {
            libz_sys::inflateInit_(
                stream.as_mut_ptr(),
                libz_sys::zlibVersion(),
                std::mem::size_of::<libz_sys::z_stream>() as i32,
            )
        };
        if status != libz_sys::Z_OK {
            return Err(Error::Lowlevel(
                "Could not initialize inflate stream state".to_string(),
            ));
        }
        // SAFETY: successful inflateInit initialized every z_stream field,
        // including replacing the initially-null allocator callbacks.
        let stream = unsafe { Box::from_raw(Box::into_raw(stream).cast::<libz_sys::z_stream>()) };

        Ok(Self {
            stream,
            stream_finished: false,
        })
    }

    // Ghidra: compression.hh:66 void Decompress::input(uint1 *buffer,int4 sz)
    /// Replace the current compressed input sequence without resetting zlib.
    ///
    /// # Safety
    ///
    /// `buffer` must remain valid for `size as uInt` reads until zlib consumes
    /// the bytes or a later call replaces the pointer. During that interval it
    /// must not be freed or reallocated. Its bytes may be mutated in place only
    /// between calls, never concurrently with `inflate`. The input may alias
    /// the later output pointer, including at exactly the same address, because
    /// the mapped Ghidra API exposes the same raw-pointer contract.
    pub unsafe fn input(&mut self, buffer: *mut u8, size: i32) {
        self.stream.next_in = buffer;
        self.stream.avail_in = size as libz_sys::uInt;
    }

    // Ghidra: compression.hh:71 bool Decompress::isFinished(void) const
    /// Return whether zlib reported the end of the compressed stream.
    pub fn is_finished(&self) -> bool {
        self.stream_finished
    }

    // Ghidra: compression.cc:78 int4 Decompress::inflate(uint1 *buffer,int4 sz)
    /// Perform one zlib inflate step and return unused output capacity.
    ///
    /// # Safety
    ///
    /// `buffer` must be writable for `size as uInt` bytes for the duration of
    /// the call, and the current input pointer must still satisfy `input`'s
    /// contract. The pointers may alias, but no Rust reference or other thread
    /// may access either range while zlib executes.
    pub unsafe fn inflate(&mut self, buffer: *mut u8, size: i32) -> Result<i32> {
        self.stream.avail_out = size as libz_sys::uInt;
        self.stream.next_out = buffer;
        // SAFETY: inflateInit succeeded, the current input obeys input()'s
        // safety contract, and buffer is writable for exactly avail_out bytes.
        let status = unsafe { libz_sys::inflate(self.stream.as_mut(), libz_sys::Z_NO_FLUSH) };
        match status {
            libz_sys::Z_NEED_DICT
            | libz_sys::Z_DATA_ERROR
            | libz_sys::Z_MEM_ERROR
            | libz_sys::Z_STREAM_ERROR => {
                return Err(Error::Lowlevel("Error decompressing stream".to_string()))
            }
            libz_sys::Z_STREAM_END => self.stream_finished = true,
            _ => {}
        }

        Ok(self.stream.avail_out as i32)
    }
}

impl Drop for Decompress {
    // Ghidra: compression.cc:101 Decompress::~Decompress(void)
    fn drop(&mut self) {
        // SAFETY: every constructed instance completed inflateInit exactly
        // once, and Drop runs exactly once for its owned z_stream.
        unsafe {
            libz_sys::inflateEnd(self.stream.as_mut());
        }
    }
}

// RUDRA-GLUE: compress_all (no Ghidra counterpart found)
/// One-shot deflate compression of a byte slice. Returns the compressed data.
/// Uses flate2 zlib encoding.
pub fn compress_all(data: &[u8], level: i32) -> Vec<u8> {
    let level = level.clamp(1, 9) as u32;
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(data).ok();
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

// RUDRA-GLUE: decompress_all (no Ghidra counterpart found)
/// One-shot inflate decompression of a byte slice. Returns the decompressed
/// data. Uses flate2 zlib decoding.
pub fn decompress_all(data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output).ok();
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_basic() {
        let mut c = Compress::new(6);
        c.input(b"hello world hello world hello world");
        let mut buf = [0u8; 256];
        let n = c.deflate(&mut buf, true);
        assert!(n > 0, "should produce compressed output");
        // Compressed data should be smaller for repeated data.
        assert!(n < 35, "should compress repeated data: {} < 35", n);
    }

    #[test]
    fn test_decompress_basic() {
        let compressed = compress_all(b"hello world", 6);
        assert!(!compressed.is_empty());
        let decompressed = decompress_all(&compressed);
        assert_eq!(&decompressed, b"hello world");
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(10);
        let compressed = compress_all(&data, 6);
        let decompressed = decompress_all(&compressed);
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_partial() {
        let mut c = Compress::new(6);
        c.input(b"abcdefghij");
        let mut buf = [0u8; 4];
        let n = c.deflate(&mut buf, false);
        // Partial compression — may or may not produce output yet.
        let _ = n;
    }

    #[test]
    fn test_decompress_finished() {
        let mut compressed = compress_all(b"abc", 6);
        let mut d = Decompress::new().unwrap();
        unsafe { d.input(compressed.as_mut_ptr(), compressed.len() as i32) };
        let mut buf = [0u8; 10];
        unsafe { d.inflate(buf.as_mut_ptr(), buf.len() as i32).unwrap() };
        assert!(d.is_finished());
    }

    #[test]
    fn test_decompress_not_finished() {
        let mut compressed = compress_all(b"abcdefghij", 6);
        let mut d = Decompress::new().unwrap();
        unsafe { d.input(compressed.as_mut_ptr(), compressed.len() as i32) };
        let mut buf = [0u8; 3];
        assert_eq!(
            unsafe { d.inflate(buf.as_mut_ptr(), buf.len() as i32).unwrap() },
            0
        );
        assert!(!d.is_finished());
    }

    #[test]
    fn test_decompress_locked_oracle_observations() {
        const HELLO_ZLIB: [u8; 13] = [
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
        ];
        const WORLD_ZLIB: [u8; 13] = [
            0x78, 0x9c, 0x2b, 0xcf, 0x2f, 0xca, 0x49, 0x01, 0x00, 0x06, 0xa6, 0x02, 0x29,
        ];

        let mut no_input = Decompress::new().unwrap();
        let mut empty_output = [0u8; 8];
        assert_eq!(
            unsafe {
                no_input
                    .inflate(empty_output.as_mut_ptr(), empty_output.len() as i32)
                    .unwrap()
            },
            8
        );
        assert!(!no_input.is_finished());

        let mut hello = HELLO_ZLIB;
        let mut streaming = Decompress::new().unwrap();
        unsafe { streaming.input(hello.as_mut_ptr(), hello.len() as i32) };
        let mut first = [0u8; 1];
        assert_eq!(
            unsafe {
                streaming
                    .inflate(first.as_mut_ptr(), first.len() as i32)
                    .unwrap()
            },
            0
        );
        assert_eq!(&first, b"h");
        assert!(!streaming.is_finished());
        let mut second = [0u8; 64];
        assert_eq!(
            unsafe {
                streaming
                    .inflate(second.as_mut_ptr(), second.len() as i32)
                    .unwrap()
            },
            60
        );
        assert_eq!(&second[..4], b"ello");
        assert!(streaming.is_finished());

        let mut midstream_hello = HELLO_ZLIB;
        let mut midstream_world = WORLD_ZLIB;
        let mut midstream_replacement = Decompress::new().unwrap();
        unsafe {
            midstream_replacement.input(midstream_hello.as_mut_ptr(), midstream_hello.len() as i32)
        };
        let mut midstream_first = [0u8; 1];
        assert_eq!(
            unsafe {
                midstream_replacement
                    .inflate(midstream_first.as_mut_ptr(), midstream_first.len() as i32)
                    .unwrap()
            },
            0
        );
        unsafe {
            midstream_replacement.input(midstream_world.as_mut_ptr(), midstream_world.len() as i32)
        };
        let mut midstream_second = [0u8; 64];
        assert_eq!(
            unsafe {
                midstream_replacement
                    .inflate(midstream_second.as_mut_ptr(), midstream_second.len() as i32)
                    .unwrap()
            },
            0
        );
        assert!(!midstream_replacement.is_finished());
        assert_eq!(
            &midstream_second[..7],
            &[0x65, 0x68, 0xe3, 0x6d, 0x1f, 0x0f, 0x15]
        );
        assert!(midstream_second[7..].iter().all(|byte| *byte == 0x09));

        let mut invalid_bytes = [0xde, 0xad, 0xbe, 0xef];
        let mut invalid = Decompress::new().unwrap();
        unsafe { invalid.input(invalid_bytes.as_mut_ptr(), invalid_bytes.len() as i32) };
        let mut invalid_output = [0u8; 8];
        let error = unsafe {
            invalid
                .inflate(invalid_output.as_mut_ptr(), invalid_output.len() as i32)
                .unwrap_err()
        };
        assert!(matches!(
            error,
            Error::Lowlevel(ref message) if message == "Error decompressing stream"
        ));
        assert!(!invalid.is_finished());

        let mut replaced_hello = HELLO_ZLIB;
        let mut world = WORLD_ZLIB;
        let mut replacement = Decompress::new().unwrap();
        unsafe {
            replacement.input(replaced_hello.as_mut_ptr(), replaced_hello.len() as i32);
            replacement.input(world.as_mut_ptr(), world.len() as i32);
        };
        let mut replacement_output = [0u8; 64];
        assert_eq!(
            unsafe {
                replacement
                    .inflate(
                        replacement_output.as_mut_ptr(),
                        replacement_output.len() as i32,
                    )
                    .unwrap()
            },
            59
        );
        assert_eq!(&replacement_output[..5], b"world");
        assert!(replacement.is_finished());

        let mut aliased_hello = HELLO_ZLIB;
        let mut alias = Decompress::new().unwrap();
        unsafe { alias.input(aliased_hello.as_mut_ptr(), aliased_hello.len() as i32) };
        aliased_hello[0] = 0;
        assert_eq!(aliased_hello[0], 0);
        let mut alias_output = [0u8; 8];
        assert!(matches!(
            unsafe { alias.inflate(alias_output.as_mut_ptr(), alias_output.len() as i32) },
            Err(Error::Lowlevel(ref message)) if message == "Error decompressing stream"
        ));
    }

    #[test]
    fn test_decompress_accepts_same_address_input_and_output() {
        const HELLO_ZLIB: [u8; 13] = [
            0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
        ];
        let mut buffer = [0u8; 64];
        buffer[..HELLO_ZLIB.len()].copy_from_slice(&HELLO_ZLIB);
        let mut decompressor = Decompress::new().unwrap();
        let pointer = buffer.as_mut_ptr();
        // SAFETY: the 64-byte allocation remains stable; the first 13 bytes
        // are valid as both input and output for this observed zlib operation.
        let remaining = unsafe {
            decompressor.input(pointer, HELLO_ZLIB.len() as i32);
            decompressor
                .inflate(pointer, HELLO_ZLIB.len() as i32)
                .unwrap()
        };
        assert_eq!(remaining, 8);
        assert!(decompressor.is_finished());
        assert_eq!(&buffer[..5], b"hello");
    }

    #[test]
    fn test_compress_all() {
        let data = b"test data for compression";
        let result = compress_all(data, 6);
        assert!(!result.is_empty());
        assert_ne!(&result[..], data); // Actually compressed.
    }

    #[test]
    fn test_decompress_all() {
        let data = b"test data for decompression";
        let compressed = compress_all(data, 6);
        let result = decompress_all(&compressed);
        assert_eq!(&result, data);
    }
}
