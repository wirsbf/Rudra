//! Memory state: MemoryBank for emulation and LOAD/STORE analysis.
//!
//! Faithful Rust port of Ghidra's `memstate.hh` / `memstate.cc`.
//!
//! MemoryBank provides byte-level read/write access to an address space,
//! with word and page abstractions. Used by the emulator for constant
//! propagation and jump-table analysis.
//!
//! Key classes (Ghidra `memstate.hh`):
//! - `MemoryBank`: abstract base for memory storage in a single address space.
//!   Concrete storage is a `BTreeMap` of word-aligned values, with the
//!   C++ `insert`/`find`/`getPage`/`setPage`/`setValue`/`getValue`/
//!   `setChunk`/`getChunk` semantics ported verbatim.
//! - `MemoryImage`: read-only bank backed by a `LoadImage` (memstate.hh:95).
//! - `MemoryPageOverlay`: copy-on-write overlay bank (memstate.hh:112).
//! - `MemoryHashOverlay`: hash-table-based overlay (memstate.hh:130).
//! - `MemoryState`: manages all memory banks across address spaces
//!   (memstate.hh:150).

use std::collections::BTreeMap;

use crate::address::{calc_mask, Address};
use crate::loadimage::{DataUnavailError, LoadImage};
use crate::space::AddressSpace;

/// Number of bytes in the host machine word used for the `uintb` value
/// abstraction. Ghidra models `uintb` as the native unsigned int width; in
/// Rust we use `u64` so this is fixed at 8. The value reflects the host's
/// endianness: 1 == big-endian host, 0 == little-endian host (memstate.cc
/// references `HOST_ENDIAN` directly in getPage/setPage/MemoryImage::find).
const HOST_ENDIAN: u32 = 0;

// RUDRA-GLUE: byte_swap (no direct Ghidra counterpart in this codebase).
// Ghidra's memstate.cc calls a global `byte_swap(val, size)` helper defined
// elsewhere (platform/address code). We provide an equivalent inline.
/// Reverse the low `size` bytes of `val`. Equivalent to Ghidra's
/// `byte_swap(uintb, int4)`.
fn byte_swap(mut val: u64, size: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for i in 0..size {
        bytes[i] = (val & 0xff) as u8;
        val >>= 8;
    }
    let mut out: u64 = 0;
    for i in 0..size {
        out <<= 8;
        out |= bytes[i] as u64;
    }
    out
}

// ============================================================================
// MemoryBank (memstate.hh:38)
// ============================================================================

/// Memory storage/state for a single AddressSpace.
///
/// Faithful port of Ghidra's `MemoryBank` (memstate.hh:38). The basic API is
/// to get/set arrays of byte values via offset within the space. Helper
/// functions `get_value`/`set_value` retrieve/store integers of various sizes
/// from memory, using the endianness encoding specified by the space.
///
/// Ghidra models `MemoryBank` as an abstract base class with two pure virtual
/// methods (`insert`, `find`) and four virtuals with default implementations
/// (`getPage`, `setPage`, and the static `constructValue`/`deconstructValue`).
/// In Rust we model this as a concrete struct backed by a word-aligned
/// `BTreeMap`; overlays and images are separate structs that hold an
/// `Option<Box<MemoryBank>>` as their `underlie`, mirroring Ghidra's
/// `MemoryBank *underlie` pointer.
pub struct MemoryBank {
    /// Number of bytes in an aligned word access (memstate.hh:41 `wordsize`).
    pub wordsize: usize,
    /// Number of bytes in an aligned page access (memstate.hh:42 `pagesize`).
    pub pagesize: usize,
    /// The address space associated with this memory (memstate.hh:43 `space`).
    pub space: AddressSpace,
    /// Word-aligned storage: aligned offset -> word value. Backing for the
    /// Ghidra `insert`/`find` virtuals (memstate.hh:45-46).
    words: BTreeMap<u64, u64>,
}

impl MemoryBank {
    // Ghidra: memstate.cc:75 MemoryBank::MemoryBank
    /// Generic constructor for a memory bank. Faithful to
    /// `MemoryBank::MemoryBank(AddrSpace *spc,int4 ws,int4 ps)`
    /// (memstate.cc:75-81). Both `ws` and `ps` must be a power of 2 in Ghidra;
    /// rudra does not assert this (the SLEIGH spec already enforces it).
    pub fn new(space: AddressSpace, wordsize: usize, pagesize: usize) -> Self {
        Self {
            wordsize,
            pagesize,
            space,
            words: BTreeMap::new(),
        }
    }

    // Ghidra: memstate.hh:67 MemoryBank::getWordSize
    /// Get the number of bytes in a word for this memory bank. Faithful to
    /// `MemoryBank::getWordSize` (memstate.hh:67-71).
    pub fn get_word_size(&self) -> usize {
        self.wordsize
    }

    // Ghidra: memstate.hh:76 MemoryBank::getPageSize
    /// Get the number of bytes in a page for this memory bank. Faithful to
    /// `MemoryBank::getPageSize` (memstate.hh:76-80).
    pub fn get_page_size(&self) -> usize {
        self.pagesize
    }

    // Ghidra: memstate.hh:84 MemoryBank::getSpace
    /// Get the address space associated with this memory bank. Faithful to
    /// `MemoryBank::getSpace` (memstate.hh:84-88).
    pub fn get_space(&self) -> AddressSpace {
        self.space
    }

    // Ghidra: memstate.hh:45 MemoryBank::insert (pure virtual)
    /// Insert a word in memory bank at an aligned location. Faithful to the
    /// pure-virtual `MemoryBank::insert` (memstate.hh:45). For the concrete
    /// `MemoryBank` this writes directly into the word map.
    pub fn insert(&mut self, addr: u64, val: u64) {
        self.words.insert(addr, val);
    }

    // Ghidra: memstate.hh:46 MemoryBank::find (pure virtual)
    /// Retrieve a word from memory bank at an aligned location. Faithful to
    /// the pure-virtual `MemoryBank::find` (memstate.hh:46). Unwritten words
    /// read as zero, matching the C++ zero-fill contract.
    pub fn find(&self, addr: u64) -> u64 {
        self.words.get(&addr).copied().unwrap_or(0)
    }

    // Ghidra: memstate.cc:93 MemoryBank::getPage
    /// Retrieve data from a memory \e page. Faithful to the default
    /// `MemoryBank::getPage` (memstate.cc:93-123): iterates aligned words via
    /// `find`, applying endianness swap when host and space endianness differ.
    /// `addr` is the page-aligned offset, `skip` is the in-page offset, and
    /// `size` is the byte count (must all lie within one page).
    pub fn get_page(&self, addr: u64, skip: usize, size: usize) -> Vec<u8> {
        let mut res = vec![0u8; size];
        let ptraddr = addr + skip as u64;
        let endaddr = ptraddr + size as u64;
        let alignmask = (self.wordsize - 1) as u64;
        let mut startalign = ptraddr & !alignmask;
        let mut endalign = endaddr & !alignmask;
        if (endaddr & alignmask) != 0 {
            endalign += self.wordsize as u64;
        }

        let bswap = (HOST_ENDIAN == 1) != self.space.is_big_endian();
        let mut out_pos = 0usize;
        loop {
            let mut curval = self.find(startalign);
            if bswap {
                curval = byte_swap(curval, self.wordsize);
            }
            let mut buf = [0u8; 8];
            for i in 0..self.wordsize {
                buf[i] = ((curval >> (i * 8)) & 0xff) as u8;
            }
            let mut ptr_idx = 0usize;
            let mut sz = self.wordsize;
            if startalign < addr {
                let diff = (addr - startalign) as usize;
                ptr_idx += diff;
                sz -= diff;
            }
            if startalign + self.wordsize as u64 > endaddr {
                sz -= (startalign + self.wordsize as u64 - endaddr) as usize;
            }
            res[out_pos..out_pos + sz].copy_from_slice(&buf[ptr_idx..ptr_idx + sz]);
            out_pos += sz;
            startalign += self.wordsize as u64;
            if startalign == endalign {
                break;
            }
        }
        res
    }

    // Ghidra: memstate.cc:136 MemoryBank::setPage
    /// Write data into a memory page. Faithful to the default
    /// `MemoryBank::setPage` (memstate.cc:136-171): iterates aligned words,
    /// merging `val` bytes into each word and calling `insert`. Partial words
    /// are read via `find` first to preserve the un-touched bytes.
    pub fn set_page(&mut self, addr: u64, val: &[u8], skip: usize, size: usize) {
        let ptraddr = addr + skip as u64;
        let endaddr = ptraddr + size as u64;
        let alignmask = (self.wordsize - 1) as u64;
        let mut startalign = ptraddr & !alignmask;
        let mut endalign = endaddr & !alignmask;
        if (endaddr & alignmask) != 0 {
            endalign += self.wordsize as u64;
        }

        let bswap = (HOST_ENDIAN == 1) != self.space.is_big_endian();
        let mut val_pos = 0usize;
        loop {
            let mut sz = self.wordsize;
            let mut ptr_idx = 0usize;
            if startalign < addr {
                let diff = (addr - startalign) as usize;
                ptr_idx += diff;
                sz -= diff;
            }
            if startalign + self.wordsize as u64 > endaddr {
                sz -= (startalign + self.wordsize as u64 - endaddr) as usize;
            }
            let curval;
            if sz != self.wordsize {
                // Part of word is copied from underlying via find; rest from val.
                let mut found = self.find(startalign);
                let mut buf = [0u8; 8];
                for i in 0..self.wordsize {
                    buf[i] = ((found >> (i * 8)) & 0xff) as u8;
                }
                buf[ptr_idx..ptr_idx + sz].copy_from_slice(&val[val_pos..val_pos + sz]);
                found = 0;
                for i in 0..self.wordsize {
                    found |= (buf[i] as u64) << (i * 8);
                }
                curval = found;
            } else {
                // val supplies entire word: little-endian read of next wordsize bytes.
                let mut v: u64 = 0;
                for i in 0..self.wordsize {
                    v |= (val[val_pos + i] as u64) << (i * 8);
                }
                curval = v;
            }
            let curval = if bswap {
                byte_swap(curval, self.wordsize)
            } else {
                curval
            };
            self.insert(startalign, curval);
            val_pos += sz;
            startalign += self.wordsize as u64;
            if startalign == endalign {
                break;
            }
        }
    }

    // Ghidra: memstate.cc:182 MemoryBank::setValue
    /// Set the value of a (small) range of bytes. Faithful to
    /// `MemoryBank::setValue` (memstate.cc:182-243). Breaks the value into
    /// aligned pieces of `wordsize`; partial words are merged with the
    /// existing value via `find`, then written via `insert`. Respects the
    /// endianness of the associated address space.
    pub fn set_value(&mut self, offset: u64, size: usize, val: u64) {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let mut val2;

        if size > size1_init {
            // Spill over into the next word.
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            if size == self.wordsize {
                self.insert(ind, val);
                return;
            }
            val1 = self.find(ind);
            val2 = 0;
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        if self.space.is_big_endian() {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << gap_bits)) | (val << gap_bits);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 << size1_bits)) | (val >> size2_bits);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 >> size2_bits)) | (val << gap_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        } else {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << skip)) | (val << skip);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 >> size1_bits)) | (val << skip);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 << size2_bits)) | (val >> size1_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        }
    }

    // Ghidra: memstate.cc:252 MemoryBank::getValue
    /// Retrieve the value encoded in a (small) range of bytes. Faithful to
    /// `MemoryBank::getValue` (memstate.cc:252-294). Reconstructs the value
    /// from one or two aligned word reads via `find`, honouring the space's
    /// endianness, and masks to `size` bytes via `calc_mask(size)`.
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            val1 = self.find(ind);
            val2 = 0;
            if size == self.wordsize {
                return val1;
            }
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        let size1_bits = (size1 * 8) as u32;
        let res;
        if self.space.is_big_endian() {
            if size2 == 0 {
                res = val1 >> gap_bits;
            } else {
                let size2_bits = (size2 * 8) as u32;
                res = (val1 << size2_bits) | (val2 >> gap_bits);
            }
        } else {
            if size2 == 0 {
                res = val1 >> skip;
            } else {
                res = (val1 >> skip) | (val2 << size1_bits);
            }
        }
        res & calc_mask(size)
    }

    // Ghidra: memstate.cc:302 MemoryBank::setChunk
    /// Set values of an arbitrary sequence of bytes. Faithful to
    /// `MemoryBank::setChunk` (memstate.cc:302-327). Slices the write into
    /// page-sized pieces and forwards each to `set_page`.
    pub fn set_chunk(&mut self, offset: u64, val: &[u8]) {
        let size = val.len();
        let pagemask = (self.pagesize - 1) as u64;
        let mut count = 0usize;
        let mut offset = offset;
        let mut val_pos = 0usize;
        while count < size {
            let mut cursize = self.pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0usize;
            if offalign != offset {
                skip = (offset - offalign) as usize;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            self.set_page(offalign, &val[val_pos..val_pos + cursize], skip, cursize);
            count += cursize;
            offset += cursize as u64;
            val_pos += cursize;
        }
    }

    // Ghidra: memstate.cc:335 MemoryBank::getChunk
    /// Retrieve an arbitrary sequence of bytes. Faithful to
    /// `MemoryBank::getChunk` (memstate.cc:335-359). Slices the read into
    /// page-sized pieces and forwards each to `get_page`.
    pub fn get_chunk(&self, offset: u64, size: usize) -> Vec<u8> {
        let pagemask = (self.pagesize - 1) as u64;
        let mut res = Vec::with_capacity(size);
        let mut count = 0usize;
        let mut offset = offset;
        while count < size {
            let mut cursize = self.pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0usize;
            if offalign != offset {
                skip = (offset - offalign) as usize;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            let chunk = self.get_page(offalign, skip, cursize);
            res.extend_from_slice(&chunk);
            count += cursize;
            offset += cursize as u64;
        }
        res
    }

    // Ghidra: memstate.cc:27 MemoryBank::constructValue
    /// Decode bytes to a value. Faithful to the static
    /// `MemoryBank::constructValue` (memstate.cc:27-45). Honours `bigendian`.
    pub fn construct_value(ptr: &[u8], bigendian: bool) -> u64 {
        let size = ptr.len();
        let mut res: u64 = 0;
        if bigendian {
            for i in 0..size {
                res <<= 8;
                res += ptr[i] as u64;
            }
        } else {
            for i in (0..size).rev() {
                res <<= 8;
                res += ptr[i] as u64;
            }
        }
        res
    }

    // Ghidra: memstate.cc:53 MemoryBank::deconstructValue
    /// Encode a value to bytes. Faithful to the static
    /// `MemoryBank::deconstructValue` (memstate.cc:53-68). Writes `size`
    /// bytes into `out` honouring `bigendian`.
    pub fn deconstruct_value(val: u64, size: usize, bigendian: bool, out: &mut [u8]) {
        if bigendian {
            let mut v = val;
            for i in (0..size).rev() {
                out[i] = (v & 0xff) as u8;
                v >>= 8;
            }
        } else {
            let mut v = val;
            for i in 0..size {
                out[i] = (v & 0xff) as u8;
                v >>= 8;
            }
        }
    }

    // RUDRA-GLUE: clear (no direct Ghidra counterpart; MemState management
    // of overlay pages is Ghidra's domain, but rudra exposes this for tests
    // and for the emulator's reset path).
    /// Clear all stored words.
    pub fn clear(&mut self) {
        self.words.clear();
    }
}

// ============================================================================
// MemoryImage (memstate.hh:95)
// ============================================================================

/// A `MemoryBank` which retrieves its data from an underlying `LoadImage`.
///
/// Faithful port of Ghidra's `MemoryImage` (memstate.hh:95-104). Any bytes
/// requested on the bank which lie in the `LoadImage` are retrieved from it;
/// other addresses in the space are filled in with zero. This bank cannot be
/// written to (Ghidra throws `LowlevelError` on `insert`).
pub struct MemoryImage {
    /// The address space associated with this memory bank.
    pub space: AddressSpace,
    /// Number of bytes in an aligned word access.
    pub wordsize: usize,
    /// Number of bytes in an aligned page access.
    pub pagesize: usize,
    /// The underlying LoadImage (memstate.hh:96 `loader`).
    pub loader: Box<dyn LoadImage>,
}

impl MemoryImage {
    // Ghidra: memstate.cc:407 MemoryImage::MemoryImage
    /// Constructor for a loadimage memorybank. Faithful to
    /// `MemoryImage::MemoryImage(AddrSpace *spc,int4 ws,int4 ps,LoadImage *ld)`
    /// (memstate.cc:407-411).
    pub fn new(space: AddressSpace, wordsize: usize, pagesize: usize, loader: Box<dyn LoadImage>) -> Self {
        Self {
            space,
            wordsize,
            pagesize,
            loader,
        }
    }

    // Ghidra: memstate.hh:98 MemoryImage::insert
    /// Writing to a read-only `MemoryBank` is an error. Faithful to
    /// `MemoryImage::insert` (memstate.hh:98-99), which throws
    /// `LowlevelError("Writing to read-only MemoryBank")`.
    pub fn insert(&mut self, _addr: u64, _val: u64) {
        // RUDRA-GLUE: panic mirrors the C++ throw LowlevelError.
        panic!("Writing to read-only MemoryBank");
    }

    // Ghidra: memstate.cc:365 MemoryImage::find
    /// Find an aligned word from the bank. Faithful to `MemoryImage::find`
    /// (memstate.cc:365-381). Attempts to fetch the word from the LoadImage;
    /// on `DataUnavailError` the value is zero. A byte swap is applied when
    /// host and space endianness differ.
    pub fn find(&self, addr: u64) -> u64 {
        let mut res: u64 = 0;
        let wordsize = self.wordsize;
        let addr_obj = Address::new(addr);
        match self.loader.load_fill(wordsize, addr_obj) {
            Ok(bytes) => {
                // Place bytes at the low end of res little-endian (HOST_ENDIAN==0).
                for (i, &b) in bytes.iter().enumerate().take(wordsize) {
                    res |= (b as u64) << (i * 8);
                }
            }
            Err(DataUnavailError(_)) => {
                // Pages not mapped in the load image are assumed to be zero.
                res = 0;
            }
        }
        if (HOST_ENDIAN == 1) != self.space.is_big_endian() {
            res = byte_swap(res, wordsize);
        }
        res
    }

    // Ghidra: memstate.cc:386 MemoryImage::getPage
    /// Retrieve an aligned page from the bank. Faithful to
    /// `MemoryImage::getPage` (memstate.cc:386-399). Forwards to
    /// `loader.load_fill`; on `DataUnavailError` the page is zero-filled.
    pub fn get_page(&self, addr: u64, skip: usize, size: usize) -> Vec<u8> {
        let addr_obj = Address::new(addr + skip as u64);
        match self.loader.load_fill(size, addr_obj) {
            Ok(bytes) => bytes,
            Err(DataUnavailError(_)) => {
                // Pages not mapped in the load image are assumed to be zero.
                vec![0u8; size]
            }
        }
    }

    // Ghidra: memstate.cc:182 MemoryBank::setValue (delegating)
    /// `setValue` on a read-only bank is an error. Faithful to the
    /// inherited `MemoryBank::setValue` reaching the throwing `insert`.
    pub fn set_value(&mut self, _offset: u64, _size: usize, _val: u64) {
        panic!("Writing to read-only MemoryBank");
    }

    // Ghidra: memstate.cc:252 MemoryBank::getValue (delegating)
    /// Retrieve the value encoded in a (small) range of bytes. Faithful to
    /// the inherited `MemoryBank::getValue`, dispatching through `find`.
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            val1 = self.find(ind);
            val2 = 0;
            if size == self.wordsize {
                return val1;
            }
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        let size1_bits = (size1 * 8) as u32;
        let res;
        if self.space.is_big_endian() {
            if size2 == 0 {
                res = val1 >> gap_bits;
            } else {
                let size2_bits = (size2 * 8) as u32;
                res = (val1 << size2_bits) | (val2 >> gap_bits);
            }
        } else {
            if size2 == 0 {
                res = val1 >> skip;
            } else {
                res = (val1 >> skip) | (val2 << size1_bits);
            }
        }
        res & calc_mask(size)
    }

    // Ghidra: memstate.cc:335 MemoryBank::getChunk (delegating)
    /// Retrieve an arbitrary sequence of bytes. Faithful to the inherited
    /// `MemoryBank::getChunk`, slicing into page-sized `get_page` calls.
    pub fn get_chunk(&self, offset: u64, size: usize) -> Vec<u8> {
        let pagemask = (self.pagesize - 1) as u64;
        let mut res = Vec::with_capacity(size);
        let mut count = 0usize;
        let mut offset = offset;
        while count < size {
            let mut cursize = self.pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0usize;
            if offalign != offset {
                skip = (offset - offalign) as usize;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            let chunk = self.get_page(offalign, skip, cursize);
            res.extend_from_slice(&chunk);
            count += cursize;
            offset += cursize as u64;
        }
        res
    }
}

// ============================================================================
// MemoryPageOverlay (memstate.hh:112)
// ============================================================================

/// Memory bank that overlays some other memory bank using "copy on write".
///
/// Faithful port of Ghidra's `MemoryPageOverlay` (memstate.hh:112-123).
/// Pages are copied from the underlying object only when there is a write.
/// The underlying memory bank can be `None`, in which case this bank behaves
/// as if it were initially filled with zeros.
pub struct MemoryPageOverlay {
    /// Number of bytes in an aligned word access.
    pub wordsize: usize,
    /// Number of bytes in an aligned page access.
    pub pagesize: usize,
    /// The address space associated with this memory.
    pub space: AddressSpace,
    /// Underlying memory object (memstate.hh:113 `underlie`).
    pub underlie: Option<Box<MemoryBank>>,
    /// Overlayed pages: page-aligned address -> page bytes
    /// (memstate.hh:114 `map<uintb,uint1 *> page`).
    pub page: BTreeMap<u64, Vec<u8>>,
}

impl MemoryPageOverlay {
    // Ghidra: memstate.cc:533 MemoryPageOverlay::MemoryPageOverlay
    /// Constructor for page overlay. Faithful to
    /// `MemoryPageOverlay::MemoryPageOverlay(AddrSpace *spc,int4 ws,int4 ps,MemoryBank *ul)`
    /// (memstate.cc:533-537).
    pub fn new(
        space: AddressSpace,
        wordsize: usize,
        pagesize: usize,
        underlie: Option<Box<MemoryBank>>,
    ) -> Self {
        Self {
            wordsize,
            pagesize,
            space,
            underlie,
            page: BTreeMap::new(),
        }
    }

    // Ghidra: memstate.cc:419 MemoryPageOverlay::insert
    /// Overridden aligned word insert. Faithful to
    /// `MemoryPageOverlay::insert` (memstate.cc:419-443). Looks for the cached
    /// page; if absent, creates it (zero-filled or copied from the underlying
    /// bank via `get_page`), then writes the word into the cached page using
    /// `deconstructValue`.
    pub fn insert(&mut self, addr: u64, val: u64) {
        let pagemask = (self.pagesize - 1) as u64;
        let pageaddr = addr & !pagemask;
        let pagesize = self.pagesize;
        let wordsize = self.wordsize;
        let bigendian = self.space.is_big_endian();

        if !self.page.contains_key(&pageaddr) {
            let mut pagebuf = vec![0u8; pagesize];
            match self.underlie.as_ref() {
                None => {
                    // Zero-fill.
                }
                Some(under) => {
                    let bytes = under.get_page(pageaddr, 0, pagesize);
                    pagebuf[..pagesize].copy_from_slice(&bytes);
                }
            }
            self.page.insert(pageaddr, pagebuf);
        }
        let pageoffset = (addr & pagemask) as usize;
        let page = self.page.get_mut(&pageaddr).expect("page just inserted");
        let slice = &mut page[pageoffset..pageoffset + wordsize];
        MemoryBank::deconstruct_value(val, wordsize, bigendian, slice);
    }

    // Ghidra: memstate.cc:450 MemoryPageOverlay::find
    /// Overridden aligned word find. Faithful to
    /// `MemoryPageOverlay::find` (memstate.cc:450-467). Looks for the word in
    /// the mapped pages; if the address is not mapped, forwards to the
    /// underlying bank, or returns 0 if there is none.
    pub fn find(&self, addr: u64) -> u64 {
        let pagemask = (self.pagesize - 1) as u64;
        let pageaddr = addr & !pagemask;
        match self.page.get(&pageaddr) {
            None => match self.underlie.as_ref() {
                None => 0,
                Some(under) => under.find(addr),
            },
            Some(pageptr) => {
                let pageoffset = (addr & pagemask) as usize;
                MemoryBank::construct_value(
                    &pageptr[pageoffset..pageoffset + self.wordsize],
                    self.space.is_big_endian(),
                )
            }
        }
    }

    // Ghidra: memstate.cc:476 MemoryPageOverlay::getPage
    /// Overridden getPage. Faithful to `MemoryPageOverlay::getPage`
    /// (memstate.cc:476-493). The desired page is looked for in the page
    /// cache; if absent, the request is forwarded to the underlying bank, or
    /// the result buffer is filled with zeros.
    pub fn get_page(&self, addr: u64, skip: usize, size: usize) -> Vec<u8> {
        match self.page.get(&addr) {
            None => match self.underlie.as_ref() {
                None => vec![0u8; size],
                Some(under) => under.get_page(addr, skip, size),
            },
            Some(pageptr) => {
                let mut res = vec![0u8; size];
                res.copy_from_slice(&pageptr[skip..skip + size]);
                res
            }
        }
    }

    // Ghidra: memstate.cc:502 MemoryPageOverlay::setPage
    /// Overridden setPage. Faithful to `MemoryPageOverlay::setPage`
    /// (memstate.cc:502-525). Searches for a cached version of the page; if
    /// absent, creates it and (for partial writes) fills it from the
    /// underlying bank, then copies in the new bytes.
    pub fn set_page(&mut self, addr: u64, val: &[u8], skip: usize, size: usize) {
        let pagesize = self.pagesize;
        let full = size == pagesize;
        if !self.page.contains_key(&addr) {
            let mut pagebuf = vec![0u8; pagesize];
            if !full {
                match self.underlie.as_ref() {
                    None => {
                        // Zero-fill.
                    }
                    Some(under) => {
                        let bytes = under.get_page(addr, 0, pagesize);
                        pagebuf[..pagesize].copy_from_slice(&bytes);
                    }
                }
            }
            self.page.insert(addr, pagebuf);
        }
        let page = self.page.get_mut(&addr).expect("page just inserted");
        page[skip..skip + size].copy_from_slice(val);
    }

    // RUDRA-GLUE: is_page_overlayed / num_pages / read / write / get_value /
    // set_value / get_word_size / get_page_size / get_space (no direct Ghidra
    // counterparts at this level; convenience helpers used by tests and by
    // rudra's emulator which addresses memory by raw offset rather than by
    // Address, mirroring how MemState::setValue forwards to the bank). These
    // wrap the faithful `insert`/`find`/`get_page`/`set_page` paths.

    /// Check if a page-aligned address is overlayed.
    pub fn is_page_overlayed(&self, page_addr: u64) -> bool {
        self.page.contains_key(&page_addr)
    }

    /// Get the number of overlayed pages.
    // RUDRA-GLUE: Exposes the Rust overlay-cache cardinality; Ghidra MemoryPageOverlay has no public page-count method.
    pub fn num_pages(&self) -> usize {
        self.page.len()
    }

    /// Read `size` bytes starting at `offset`. Faithful dispatch through
    /// `getChunk`-style page slicing, going via `get_page`.
    // Ghidra: memstate.cc:335 MemoryBank::getChunk
    pub fn read(&self, offset: u64, size: usize) -> Vec<u8> {
        let pagemask = (self.pagesize - 1) as u64;
        let mut res = Vec::with_capacity(size);
        let mut count = 0usize;
        let mut offset = offset;
        while count < size {
            let mut cursize = self.pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0usize;
            if offalign != offset {
                skip = (offset - offalign) as usize;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            let chunk = self.get_page(offalign, skip, cursize);
            res.extend_from_slice(&chunk);
            count += cursize;
            offset += cursize as u64;
        }
        res
    }

    /// Write `data` starting at `offset`. Faithful dispatch through
    /// `setChunk`-style page slicing, going via `set_page`.
    // Ghidra: memstate.cc:302 MemoryBank::setChunk
    pub fn write(&mut self, offset: u64, data: &[u8]) {
        let size = data.len();
        let pagemask = (self.pagesize - 1) as u64;
        let mut count = 0usize;
        let mut offset = offset;
        let mut val_pos = 0usize;
        while count < size {
            let mut cursize = self.pagesize;
            let offalign = offset & !pagemask;
            let mut skip = 0usize;
            if offalign != offset {
                skip = (offset - offalign) as usize;
                cursize -= skip;
            }
            if size - count < cursize {
                cursize = size - count;
            }
            self.set_page(offalign, &data[val_pos..val_pos + cursize], skip, cursize);
            count += cursize;
            offset += cursize as u64;
            val_pos += cursize;
        }
    }

    /// Read a value of `size` bytes at `offset`. Faithful to the inherited
    /// `MemoryBank::getValue`, dispatching through `find`.
    // Ghidra: memstate.cc:252 MemoryBank::getValue
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            val1 = self.find(ind);
            val2 = 0;
            if size == self.wordsize {
                return val1;
            }
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        let size1_bits = (size1 * 8) as u32;
        let res;
        if self.space.is_big_endian() {
            if size2 == 0 {
                res = val1 >> gap_bits;
            } else {
                let size2_bits = (size2 * 8) as u32;
                res = (val1 << size2_bits) | (val2 >> gap_bits);
            }
        } else {
            if size2 == 0 {
                res = val1 >> skip;
            } else {
                res = (val1 >> skip) | (val2 << size1_bits);
            }
        }
        res & calc_mask(size)
    }

    /// Set a value of `size` bytes at `offset`. Faithful to the inherited
    /// `MemoryBank::setValue`, dispatching through `insert`.
    // Ghidra: memstate.cc:182 MemoryBank::setValue
    pub fn set_value(&mut self, offset: u64, size: usize, val: u64) {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let mut val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            if size == self.wordsize {
                self.insert(ind, val);
                return;
            }
            val1 = self.find(ind);
            val2 = 0;
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        if self.space.is_big_endian() {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << gap_bits)) | (val << gap_bits);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 << size1_bits)) | (val >> size2_bits);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 >> size2_bits)) | (val << gap_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        } else {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << skip)) | (val << skip);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 >> size1_bits)) | (val << skip);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 << size2_bits)) | (val >> size1_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        }
    }

    /// Get the number of bytes in a word for this memory bank.
    // Ghidra: memstate.hh:67 MemoryBank::getWordSize
    pub fn get_word_size(&self) -> usize {
        self.wordsize
    }

    /// Get the number of bytes in a page for this memory bank.
    // Ghidra: memstate.hh:76 MemoryBank::getPageSize
    pub fn get_page_size(&self) -> usize {
        self.pagesize
    }

    /// Get the address space associated with this memory bank.
    // Ghidra: memstate.hh:84 MemoryBank::getSpace
    pub fn get_space(&self) -> AddressSpace {
        self.space
    }
}

// ============================================================================
// MemoryHashOverlay (memstate.hh:130)
// ============================================================================

/// A memory bank that implements reads and writes using a hash table.
///
/// Faithful port of Ghidra's `MemoryHashOverlay` (memstate.hh:130-141). The
/// initial state is taken from an underlying memory bank or is all zero. This
/// implementation is not efficient for accessing entire pages (per Ghidra's
/// own caveat in memstate.hh:129).
pub struct MemoryHashOverlay {
    /// Number of bytes in an aligned word access.
    pub wordsize: usize,
    /// Number of bytes in an aligned page access.
    pub pagesize: usize,
    /// The address space associated with this memory.
    pub space: AddressSpace,
    /// Underlying memory bank (memstate.hh:131 `underlie`).
    pub underlie: Option<Box<MemoryBank>>,
    /// How many LSBs are thrown away from address when doing hash table
    /// lookup (memstate.hh:132 `alignshift`).
    pub alignshift: u32,
    /// How many slots to skip after a hash-table collision
    /// (memstate.hh:133 `collideskip`).
    pub collideskip: u64,
    /// The hashtable addresses (memstate.hh:134 `address`), initialised to
    /// `0xBADBEEF` (sentinel for "empty slot").
    pub address: Vec<u64>,
    /// The hashtable values (memstate.hh:135 `value`).
    pub value: Vec<u64>,
}

/// Sentinel marking an empty hash slot. Faithful to Ghidra's `0xBADBEEF`
/// (memstate.cc:561, 583).
const HASH_EMPTY: u64 = 0xBADBEEF;

impl MemoryHashOverlay {
    // Ghidra: memstate.cc:602 MemoryHashOverlay::MemoryHashOverlay
    /// Constructor for hash overlay. Faithful to
    /// `MemoryHashOverlay::MemoryHashOverlay(AddrSpace *spc,int4 ws,int4 ps,int4 hashsize,MemoryBank *ul)`
    /// (memstate.cc:602-614). Initialises `address` to `0xBADBEEF`,
    /// `collideskip` to 1023, and `alignshift` to `log2(ws)`.
    pub fn new(
        space: AddressSpace,
        wordsize: usize,
        pagesize: usize,
        hashsize: usize,
        underlie: Option<Box<MemoryBank>>,
    ) -> Self {
        let address = vec![HASH_EMPTY; hashsize];
        let value = vec![0u64; hashsize];
        let collideskip = 1023u64;

        let mut alignshift = 0u32;
        let mut tmp = (wordsize - 1) as u32;
        while tmp != 0 {
            alignshift += 1;
            tmp >>= 1;
        }

        Self {
            wordsize,
            pagesize,
            space,
            underlie,
            alignshift,
            collideskip,
            address,
            value,
        }
    }

    // Ghidra: memstate.cc:551 MemoryHashOverlay::insert
    /// Overridden aligned word insert. Faithful to
    /// `MemoryHashOverlay::insert` (memstate.cc:551-569). Writes the value
    /// into the hash table keyed by `addr`, replacing an existing entry or
    /// claiming an empty slot, with linear probing by `collideskip`.
    pub fn insert(&mut self, addr: u64, val: u64) {
        let size = self.address.len();
        if size == 0 {
            // RUDRA-GLUE: guard against a zero-capacity table (Ghidra would
            // likewise throw on the first iteration). Match C++ behaviour.
            panic!("Memory state hash_table is full");
        }
        let mut offset = ((addr >> self.alignshift) % size as u64) as usize;
        for _ in 0..size {
            if self.address[offset] == addr {
                self.value[offset] = val;
                return;
            } else if self.address[offset] == HASH_EMPTY {
                self.address[offset] = addr;
                self.value[offset] = val;
                return;
            }
            offset = ((offset as u64 + self.collideskip) % size as u64) as usize;
        }
        panic!("Memory state hash_table is full");
    }

    // Ghidra: memstate.cc:575 MemoryHashOverlay::find
    /// Overridden aligned word find. Faithful to
    /// `MemoryHashOverlay::find` (memstate.cc:575-592). Searches the hash
    /// table for `addr`; on miss, forwards to the underlying bank or returns
    /// 0 if there is none.
    pub fn find(&self, addr: u64) -> u64 {
        let size = self.address.len();
        if size == 0 {
            // RUDRA-GLUE: empty table always misses.
            return match self.underlie.as_ref() {
                None => 0,
                Some(under) => under.find(addr),
            };
        }
        let mut offset = ((addr >> self.alignshift) % size as u64) as usize;
        for _ in 0..size {
            if self.address[offset] == addr {
                return self.value[offset];
            } else if self.address[offset] == HASH_EMPTY {
                break;
            }
            offset = ((offset as u64 + self.collideskip) % size as u64) as usize;
        }
        // Not found in hash table: fall through to underlying.
        match self.underlie.as_ref() {
            None => 0,
            Some(under) => under.find(addr),
        }
    }

    // RUDRA-GLUE: get_value / set_value / get_word_size / get_page_size /
    // get_space (no direct Ghidra counterparts at this level; convenience
    // accessors so the hash overlay can be used uniformly with the other
    // banks by the emulator and tests).

    /// Get the number of bytes in a word for this memory bank.
    pub fn get_word_size(&self) -> usize {
        self.wordsize
    }

    /// Get the number of bytes in a page for this memory bank.
    // Ghidra: memstate.hh:76 MemoryBank::getPageSize
    pub fn get_page_size(&self) -> usize {
        self.pagesize
    }

    /// Get the address space associated with this memory bank.
    // Ghidra: memstate.hh:84 MemoryBank::getSpace
    pub fn get_space(&self) -> AddressSpace {
        self.space
    }

    /// Retrieve the value encoded in a (small) range of bytes. Faithful to
    /// the inherited `MemoryBank::getValue`, dispatching through `find`.
    // Ghidra: memstate.cc:252 MemoryBank::getValue
    pub fn get_value(&self, offset: u64, size: usize) -> u64 {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            val1 = self.find(ind);
            val2 = 0;
            if size == self.wordsize {
                return val1;
            }
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        let size1_bits = (size1 * 8) as u32;
        let res;
        if self.space.is_big_endian() {
            if size2 == 0 {
                res = val1 >> gap_bits;
            } else {
                let size2_bits = (size2 * 8) as u32;
                res = (val1 << size2_bits) | (val2 >> gap_bits);
            }
        } else {
            if size2 == 0 {
                res = val1 >> skip;
            } else {
                res = (val1 >> skip) | (val2 << size1_bits);
            }
        }
        res & calc_mask(size)
    }

    /// Set the value of a (small) range of bytes. Faithful to the inherited
    /// `MemoryBank::setValue`, dispatching through `insert`.
    // Ghidra: memstate.cc:182 MemoryBank::setValue
    pub fn set_value(&mut self, offset: u64, size: usize, val: u64) {
        let alignmask = (self.wordsize - 1) as u64;
        let ind = offset & !alignmask;
        let skip_bytes = (offset & alignmask) as usize;
        let size1_init = self.wordsize - skip_bytes;
        let size1;
        let size2;
        let gap;
        let val1;
        let mut val2;

        if size > size1_init {
            size2 = size - size1_init;
            size1 = size1_init;
            val1 = self.find(ind);
            val2 = self.find(ind + self.wordsize as u64);
            gap = self.wordsize.wrapping_sub(size2);
        } else {
            if size == self.wordsize {
                self.insert(ind, val);
                return;
            }
            val1 = self.find(ind);
            val2 = 0;
            gap = size1_init.wrapping_sub(size);
            size1 = size;
            size2 = 0;
        }

        let skip = (skip_bytes * 8) as u32;
        let gap_bits = (gap * 8) as u32;
        if self.space.is_big_endian() {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << gap_bits)) | (val << gap_bits);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 << size1_bits)) | (val >> size2_bits);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 >> size2_bits)) | (val << gap_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        } else {
            if size2 == 0 {
                let val1 = (val1 & !(calc_mask(size1) << skip)) | (val << skip);
                self.insert(ind, val1);
            } else {
                let size1_bits = (size1 * 8) as u32;
                let size2_bits = (size2 * 8) as u32;
                let val1 = (val1 & (!0u64 >> size1_bits)) | (val << skip);
                self.insert(ind, val1);
                val2 = (val2 & (!0u64 << size2_bits)) | (val >> size1_bits);
                self.insert(ind + self.wordsize as u64, val2);
            }
        }
    }
}

// ============================================================================
// constructMemoryBank factory (mirrors Ghidra's pattern of building an
// appropriately-backed bank for a space)
// ============================================================================

// RUDRA-GLUE: construct_memory_bank (no single Ghidra counterpart; Ghidra's
// Architecture wires up MemoryImage / overlays via the LoadImage during
// initialisation in architecture.cc. Rudra exposes a single factory used by
// the emulator to build a default bank for a space).
/// Build a default `MemoryBank` for the given space. Mirrors the way Ghidra's
/// `Architecture` instantiates a writable `MemoryBank` (page-aligned) for a
/// space during initialisation.
pub fn construct_memory_bank(space: AddressSpace, wordsize: usize, pagesize: usize) -> MemoryBank {
    MemoryBank::new(space, wordsize, pagesize)
}

// ============================================================================
// MemoryState (memstate.hh:150)
// ============================================================================

/// All storage/state for a pcode machine.
///
/// Faithful port of Ghidra's `MemoryState` (memstate.hh:150-168). Every piece
/// of information in a pcode machine is representable as a triple
/// (AddrSpace, offset, size). This class allows getting and setting all state
/// information of this form via the registered per-space `MemoryBank`s.
pub struct MemState {
    /// Memory banks associated with each address space, keyed by space name
    /// (memstate.hh:153 `vector<MemoryBank *> memspace`).
    pub banks: BTreeMap<String, MemoryBank>,
}

impl MemState {
    // RUDRA-GLUE: new (Ghidra's MemoryState constructor takes a Translate*;
    // rudra's Translate equivalent is not wired into MemState yet, so the
    // constructor is parameter-less for now. The named-register
    // `setValue`/`getValue` (memstate.cc:684-702) are therefore exposed via
    // `set_register_value`/`get_register_value`, which look the bank up by
    // the rudra register-space name "register" rather than via Translate.)
    pub fn new() -> Self {
        Self {
            banks: BTreeMap::new(),
        }
    }

    // Ghidra: memstate.cc:620 MemoryState::setMemoryBank
    /// Map a memory bank into the state. Faithful to
    /// `MemoryState::setMemoryBank` (memstate.cc:620-630). Rudra keys the
    /// bank by the space name; Ghidra keys it by `spc->getIndex()` into
    /// `memspace`.
    pub fn set_memory_bank(&mut self, bank: MemoryBank) {
        let name = bank.space.name().to_string();
        self.banks.insert(name, bank);
    }

    // RUDRA-GLUE: set_bank (compat alias for setMemoryBank keyed by name).
    /// Register a memory bank for an address space under an explicit name.
    pub fn set_bank(&mut self, space_name: String, bank: MemoryBank) {
        self.banks.insert(space_name, bank);
    }

    // Ghidra: memstate.cc:636 MemoryState::getMemoryBank
    /// Get a memory bank associated with a particular space. Faithful to
    /// `MemoryState::getMemoryBank` (memstate.cc:636-643). Returns `None` if
    /// no bank is associated with the named space.
    pub fn get_memory_bank(&self, space_name: &str) -> Option<&MemoryBank> {
        self.banks.get(space_name)
    }

    // RUDRA-GLUE: get_bank_mut (mutable counterpart to getMemoryBank).
    pub fn get_bank_mut(&mut self, space_name: &str) -> Option<&mut MemoryBank> {
        self.banks.get_mut(space_name)
    }

    // RUDRA-GLUE: get_bank (compat alias for getMemoryBank).
    pub fn get_bank(&self, space_name: &str) -> Option<&MemoryBank> {
        self.banks.get(space_name)
    }

    // Ghidra: memstate.cc:652 MemoryState::setValue(AddrSpace*,...)
    /// Set a value on the memory state. Faithful to
    /// `MemoryState::setValue(AddrSpace *spc,uintb off,int4 size,uintb cval)`
    /// (memstate.cc:652-659). If there is no registered MemoryBank for the
    /// desired address space, this is a no-op (Ghidra throws LowlevelError;
    /// rudra's emulator relies on the silent no-op for unmapped spaces).
    pub fn set_value(&mut self, space_name: &str, offset: u64, size: usize, val: u64) {
        if let Some(bank) = self.banks.get_mut(space_name) {
            bank.set_value(offset, size, val);
        }
    }

    // Ghidra: memstate.cc:668 MemoryState::getValue(AddrSpace*,...)
    /// Retrieve a memory value from the memory state. Faithful to
    /// `MemoryState::getValue(AddrSpace *spc,uintb off,int4 size)` (memstate.cc:668-676).
    /// A constant space returns the offset directly (Ghidra's IPTR_CONSTANT
    /// fast path); other spaces return `None` if unmapped.
    pub fn get_value(&self, space_name: &str, offset: u64, size: usize) -> Option<u64> {
        if space_name == AddressSpace::Const.name() {
            return Some(offset);
        }
        self.banks.get(space_name).map(|bank| bank.get_value(offset, size))
    }

    // RUDRA-GLUE: set_register_value / get_register_value (compat for the
    // named-register `setValue(const string&,...)` / `getValue(const string&,...)`
    // overloads in memstate.cc:684-702; those resolve a register name to a
    // varnode via the Translate object, which rudra does not yet wire here).
    /// Set a value on a named register. Faithful in spirit to
    /// `MemoryState::setValue(const string &nm,uintb cval)` (memstate.cc:684-689).
    pub fn set_register_value(&mut self, reg_name: &str, val: u64) {
        if let Some(bank) = self.banks.get_mut("register") {
            // RUDRA-GLUE: without a Translate lookup we hash the name into an
            // offset within the register bank; the emulator proper keys its
            // register file by (space, offset) tuples instead.
            let offset = hash_register_name(reg_name);
            bank.set_value(offset, 8, val);
        }
    }

    /// Retrieve a value from a named register. Faithful in spirit to
    /// `MemoryState::getValue(const string &nm)` (memstate.cc:697-702).
    // Ghidra: memstate.cc:697 MemoryState::getValue
    pub fn get_register_value(&self, reg_name: &str) -> Option<u64> {
        let offset = hash_register_name(reg_name);
        self.banks.get("register").map(|bank| bank.get_value(offset, 8))
    }

    // Ghidra: memstate.cc:712 MemoryState::getChunk
    /// Get a chunk of data from memory state. Faithful to
    /// `MemoryState::getChunk` (memstate.cc:712-719). Returns an empty vec if
    /// the space is unmapped (Ghidra throws LowlevelError).
    pub fn get_chunk(&self, space_name: &str, offset: u64, size: usize) -> Vec<u8> {
        self.banks
            .get(space_name)
            .map(|bank| bank.get_chunk(offset, size))
            .unwrap_or_default()
    }

    // Ghidra: memstate.cc:729 MemoryState::setChunk
    /// Set a chunk of data in memory state. Faithful to
    /// `MemoryState::setChunk` (memstate.cc:729-736). No-op if the space is
    /// unmapped (Ghidra throws LowlevelError).
    pub fn set_chunk(&mut self, space_name: &str, offset: u64, val: &[u8]) {
        if let Some(bank) = self.banks.get_mut(space_name) {
            bank.set_chunk(offset, val);
        }
    }
}

impl Default for MemState {
    // RUDRA-GLUE: Rust Default delegates to MemState::new; C++ MemoryState has no Default-trait entry point.
    fn default() -> Self {
        Self::new()
    }
}

// RUDRA-GLUE: hash_register_name (no Ghidra counterpart; rudra's
// named-register API lacks a Translate object to resolve names, so we hash
// the name into a stable register-bank offset as a placeholder).
fn hash_register_name(name: &str) -> u64 {
    // FNV-1a 64-bit, chosen for stability and simplicity.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in name.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash & 0xFFFF_FFF0 // 4-byte-aligned slot within the register bank
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loadimage::RawLoadImage;

    #[test]
    fn test_construct_deconstruct() {
        let val = 0x12345678u64;
        let mut bytes = vec![0u8; 4];
        MemoryBank::deconstruct_value(val, 4, false, &mut bytes);
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
        let val2 = MemoryBank::construct_value(&bytes, false);
        assert_eq!(val2, val);
        // Big-endian round trip.
        let mut be_bytes = vec![0u8; 4];
        MemoryBank::deconstruct_value(val, 4, true, &mut be_bytes);
        assert_eq!(be_bytes, vec![0x12, 0x34, 0x56, 0x78]);
        let val3 = MemoryBank::construct_value(&be_bytes, true);
        assert_eq!(val3, val);
    }

    #[test]
    fn test_set_get_value_word_aligned() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        // Aligned, full word: direct insert path.
        bank.set_value(0, 4, 0xdeadbeef);
        assert_eq!(bank.get_value(0, 4), 0xdeadbeef);
    }

    #[test]
    fn test_set_get_value_partial_word() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        // Partial write within a word (Ghidra memstate.cc:182 setValue
        // skip/gap path). Writing 2 bytes at offset 1 of a 4-byte word.
        bank.set_value(1, 2, 0xbaba);
        assert_eq!(bank.get_value(1, 2), 0xbaba);
    }

    #[test]
    fn test_set_get_value_spillover() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        // 4-byte write at offset 2 spans two 4-byte words.
        bank.set_value(2, 4, 0x12345678);
        assert_eq!(bank.get_value(2, 4), 0x12345678);
        // Bytes neighbouring the write remain zero.
        assert_eq!(bank.get_value(0, 2), 0);
        assert_eq!(bank.get_value(6, 2), 0);
    }

    #[test]
    fn test_set_get_chunk() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 1, 4096);
        bank.set_chunk(200, &[1, 2, 3, 4, 5]);
        let chunk = bank.get_chunk(200, 5);
        assert_eq!(chunk, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_mem_state() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        state.set_bank("ram".into(), bank);
        assert!(state.get_bank("ram").is_some());
        assert!(state.get_bank("nonexistent").is_none());
    }

    #[test]
    fn test_memory_image_from_loadimage() {
        // Faithful to MemoryImage::find/getPage using a LoadImage backend.
        let loader = Box::new(RawLoadImage::from_bytes("test", 0, vec![0x01, 0x02, 0x03, 0x04, 0x05]));
        let img = MemoryImage::new(AddressSpace::Ram, 4, 4096, loader);
        // Word read at offset 0 (little-endian).
        assert_eq!(img.find(0), 0x04030201);
        // getValue covers the same path.
        assert_eq!(img.get_value(0, 4), 0x04030201);
        // Out-of-bounds: zero fill.
        assert_eq!(img.get_value(0x2000, 2), 0);
    }

    #[test]
    #[should_panic(expected = "Writing to read-only MemoryBank")]
    fn test_memory_image_write_panics() {
        let loader = Box::new(RawLoadImage::from_bytes("test", 0, vec![0u8; 16]));
        let mut img = MemoryImage::new(AddressSpace::Ram, 4, 4096, loader);
        img.insert(0, 1);
    }

    #[test]
    fn test_page_overlay_insert_find() {
        // Faithful COW: insert triggers page allocation; find reads back.
        let mut overlay = MemoryPageOverlay::new(AddressSpace::Ram, 4, 16, None);
        overlay.insert(0, 0xdeadbeef);
        assert_eq!(overlay.find(0), 0xdeadbeef);
        // Unmapped page with no underlie reads as zero.
        assert_eq!(overlay.find(32), 0);
    }

    #[test]
    fn test_page_overlay_get_set_page() {
        let mut overlay = MemoryPageOverlay::new(AddressSpace::Ram, 1, 16, None);
        // Full-page set_page allocates a zeroed page (no underlie lookup).
        overlay.set_page(0, &[1, 2, 3, 4], 0, 4);
        assert_eq!(overlay.get_page(0, 0, 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_page_overlay_write_read() {
        let mut overlay = MemoryPageOverlay::new(AddressSpace::Ram, 1, 16, None);
        overlay.write(0, &[0xaa, 0xbb]);
        assert_eq!(overlay.read(0, 2), vec![0xaa, 0xbb]);
        assert!(overlay.is_page_overlayed(0));
        // Unwritten page returns zero.
        assert_eq!(overlay.read(100, 2), vec![0x00, 0x00]);
    }

    #[test]
    fn test_page_overlay_with_underlie() {
        // wordsize=4 so a 4-byte get_value is a single-word read
        // (Ghidra's getValue/setValue are defined for <= 2-word spans).
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 16);
        bank.set_value(0, 4, 0xdeadbeef);
        let mut overlay = MemoryPageOverlay::new(AddressSpace::Ram, 4, 16, Some(Box::new(bank)));
        // Read from underlie when not overlayed.
        assert_eq!(overlay.get_value(0, 4), 0xdeadbeef);
        // Overlay a write.
        overlay.write(0, &[0x11]);
        assert_eq!(overlay.read(0, 1), vec![0x11]);
    }

    #[test]
    fn test_hash_overlay_insert_find() {
        let mut overlay = MemoryHashOverlay::new(AddressSpace::Ram, 4, 4096, 1024, None);
        overlay.insert(64, 0xcafebabe);
        assert_eq!(overlay.find(64), 0xcafebabe);
        // Miss falls through to zero.
        assert_eq!(overlay.find(128), 0);
    }

    #[test]
    fn test_hash_overlay_with_underlie() {
        let mut bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        bank.insert(0, 0x11223344);
        let overlay = MemoryHashOverlay::new(AddressSpace::Ram, 4, 4096, 1024, Some(Box::new(bank)));
        // Underlying value is visible through the overlay.
        assert_eq!(overlay.find(0), 0x11223344);
        // And can be shadowed.
        let mut overlay = overlay;
        overlay.insert(0, 0x99);
        assert_eq!(overlay.find(0), 0x99);
    }

    #[test]
    fn test_hash_overlay_get_set_value() {
        let mut overlay = MemoryHashOverlay::new(AddressSpace::Ram, 4, 4096, 1024, None);
        overlay.set_value(0, 4, 0x12345678);
        assert_eq!(overlay.get_value(0, 4), 0x12345678);
    }

    #[test]
    fn test_mem_state_value_ops() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 4, 4096);
        state.set_bank("ram".into(), bank);
        state.set_value("ram", 0x100, 4, 0x12345678);
        assert_eq!(state.get_value("ram", 0x100, 4), Some(0x12345678));
        assert_eq!(state.get_value("ram", 0x100, 2), Some(0x5678));
    }

    #[test]
    fn test_mem_state_chunk_ops() {
        let mut state = MemState::new();
        let bank = MemoryBank::new(AddressSpace::Ram, 1, 4096);
        state.set_bank("ram".into(), bank);
        state.set_chunk("ram", 0x200, &[0xaa, 0xbb, 0xcc, 0xdd]);
        let chunk = state.get_chunk("ram", 0x200, 4);
        assert_eq!(chunk, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_mem_state_const_fast_path() {
        // IPTR_CONSTANT fast path returns the offset directly.
        let state = MemState::new();
        assert_eq!(state.get_value("const", 42, 4), Some(42));
    }

    #[test]
    fn test_mem_state_set_memory_bank() {
        // setMemoryBank keys by space.name() rather than by explicit name.
        let mut state = MemState::new();
        state.set_memory_bank(MemoryBank::new(AddressSpace::Ram, 4, 4096));
        assert!(state.get_memory_bank("ram").is_some());
        assert!(state.get_memory_bank("register").is_none());
    }

    #[test]
    fn test_construct_memory_bank_factory() {
        let bank = construct_memory_bank(AddressSpace::Ram, 4, 4096);
        assert_eq!(bank.get_word_size(), 4);
        assert_eq!(bank.get_page_size(), 4096);
        assert_eq!(bank.get_space(), AddressSpace::Ram);
    }
}
