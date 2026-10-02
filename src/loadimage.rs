//! Binary load image — faithful port of `loadimage.hh` / `loadimage.cc`
//! (116 lines).
//!
//! Classes and API for accessing a binary load image. The `LoadImage` trait
//! provides the abstraction the decompiler needs for the numerous load file
//! formats used to encode binary executables. The data encoding the machine
//! instructions can be accessed via the addresses where that data would be
//! loaded into RAM.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/loadimage.{hh,cc}.

use crate::address::{Address, RangeList};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Error indicating data was not available at the requested address.
/// Faithful to `DataUnavailError` (loadimage.hh:31).
#[derive(Debug, Clone)]
pub struct DataUnavailError(pub String);

/// A record indicating a function symbol. Faithful to `LoadImageFunc`
/// (loadimage.hh:38).
#[derive(Debug, Clone)]
pub struct LoadImageFunc {
    /// Start of function.
    pub address: Address,
    /// Name of function.
    pub name: String,
}

/// A record describing a section of bytes in the executable. Faithful to
/// `LoadImageSection` (loadimage.hh:46).
#[derive(Debug, Clone)]
pub struct LoadImageSection {
    /// Starting address of section.
    pub address: Address,
    /// Number of bytes in section.
    pub size: u64,
    /// Properties of the section.
    pub flags: u32,
}

/// Boolean properties a section might have. Faithful to the enum in
/// `LoadImageSection` (loadimage.hh:48).
pub mod section_flags {
    /// Not allocated in memory (debug info).
    pub const UNALLOC: u32 = 1;
    /// Uninitialized section.
    pub const NOLOAD: u32 = 2;
    /// Code only.
    pub const CODE: u32 = 4;
    /// Data only.
    pub const DATA: u32 = 8;
    /// Read only section.
    pub const READONLY: u32 = 16;
}

/// An interface into a particular binary executable image. Faithful to
/// `LoadImage` (loadimage.hh:73).
///
/// The core routine is `load_fill`, which retrieves the exact byte values
/// stored at a given address range. Properties other than the main data are
/// intended to be read once during initialization.
pub trait LoadImage: Send + Sync {
    // Ghidra: loadimage.hh:46 LoadImageSection::getFilename
    /// Get the name of the load image file. Faithful to `getFileName`.
    fn get_filename(&self) -> &str;

    // Ghidra: loadimage.hh:46 LoadImageSection::loadFill
    /// Get data from the load image. This is the core routine. Given a
    /// particular address range, retrieves the exact byte values stored at
    /// that address. If the requested address range does not exist, returns
    /// an `Err(DataUnavailError)`. Faithful to `loadFill` (loadimage.hh:80).
    fn load_fill(&self, size: usize, addr: Address) -> Result<Vec<u8>, DataUnavailError>;

    // Ghidra: loadimage.hh:46 LoadImageSection::openSymbols
    /// Prepare to read symbols. Faithful to `openSymbols`. Default: no-op.
    fn open_symbols(&self) {}

    // Ghidra: loadimage.hh:46 LoadImageSection::closeSymbols
    /// Stop reading symbols. Faithful to `closeSymbols`. Default: no-op.
    fn close_symbols(&self) {}

    // Ghidra: loadimage.hh:46 LoadImageSection::getNextSymbol
    /// Get the next symbol record. Returns true if a record was filled in.
    /// Faithful to `getNextSymbol`. Default: no symbols.
    fn get_next_symbol(&self, _record: &mut LoadImageFunc) -> bool {
        false
    }

    // Ghidra: loadimage.hh:46 LoadImageSection::openSectionInfo
    /// Prepare to read section info. Faithful to `openSectionInfo`. Default: no-op.
    fn open_section_info(&self) {}

    // Ghidra: loadimage.hh:46 LoadImageSection::closeSectionInfo
    /// Stop reading section info. Faithful to `closeSectionInfo`. Default: no-op.
    fn close_section_info(&self) {}

    // Ghidra: loadimage.hh:46 LoadImageSection::getNextSection
    /// Get info on the next section. Returns true if a record was filled in.
    /// Faithful to `getNextSection`. Default: no sections.
    fn get_next_section(&self, _record: &mut LoadImageSection) -> bool {
        false
    }

    // Ghidra: loadimage.hh:46 LoadImageSection::getReadonly
    /// Return list of readonly address ranges. Faithful to `getReadonly`.
    /// Default: no readonly ranges.
    fn get_readonly(&self) -> RangeList {
        RangeList::new()
    }

    // Ghidra: loadimage.hh:46 LoadImageSection::getArchType
    /// Get a string indicating the architecture type. Faithful to
    /// `getArchType`.
    fn get_arch_type(&self) -> String;

    // Ghidra: loadimage.hh:46 LoadImageSection::adjustVma
    /// Adjust load addresses with a global offset. Faithful to `adjustVma`.
    fn adjust_vma(&mut self, adjust: i64);

    // Ghidra: loadimage.hh:46 LoadImageSection::load
    /// Load a chunk of image. Convenience method wrapping `load_fill`.
    /// Faithful to `LoadImage::load` (loadimage.cc:29).
    fn load(&self, size: usize, addr: Address) -> Result<Vec<u8>, DataUnavailError> {
        self.load_fill(size, addr)
    }

    // Ghidra: loadimage.hh:46 LoadImageSection::loadValue
    /// Load a single value of a given byte size from the image at the given
    /// address. Returns the value as a `u64`. Used by `EmulateFunction` and
    /// `JumpBasic` for readonly memory lookups.
    fn load_value(&self, addr: Address, size: usize) -> Result<u64, DataUnavailError> {
        let bytes = self.load_fill(size, addr)?;
        let mut val = 0u64;
        for (i, &b) in bytes.iter().enumerate().take(8) {
            val |= (b as u64) << (i * 8);
        }
        Ok(val)
    }
}

/// A simple raw binary load image. Faithful to `RawLoadImage`
/// (loadimage.hh:98).
///
/// Bytes from the image are read directly from a file. The address associated
/// with each byte is determined by a single value, the `vma`, which is the
/// address of the first byte in the file. No symbols or sections are
/// supported.
pub struct RawLoadImage {
    /// Name of the load image file.
    filename: String,
    /// Address of first byte in the file.
    vma: u64,
    /// The file data, read into memory.
    filedata: Vec<u8>,
}

impl RawLoadImage {
    // Ghidra: loadimage.cc:39 RawLoadImage::new
    /// Construct given the filename. Faithful to the constructor
    /// (loadimage.cc:39).
    pub fn new(filename: &str) -> Self {
        Self {
            filename: filename.to_string(),
            vma: 0,
            filedata: Vec::new(),
        }
    }

    // Ghidra: loadimage.cc:58 RawLoadImage::open
    /// Open the raw file for reading and read all data into memory. Faithful
    /// to `open` (loadimage.cc:58).
    pub fn open(&mut self) -> Result<(), String> {
        let mut file = File::open(&self.filename)
            .map_err(|e| format!("Unable to open raw image file {}: {}", self.filename, e))?;
        file.read_to_end(&mut self.filedata)
            .map_err(|e| format!("Unable to read raw image file {}: {}", self.filename, e))?;
        Ok(())
    }

    // Ghidra: loadimage.cc:39 RawLoadImage::fromBytes
    /// Construct from raw byte data (for testing).
    pub fn from_bytes(filename: &str, vma: u64, data: Vec<u8>) -> Self {
        Self {
            filename: filename.to_string(),
            vma,
            filedata: data,
        }
    }

    // Ghidra: loadimage.cc:39 RawLoadImage::fileSize
    /// Get the file size.
    pub fn file_size(&self) -> u64 {
        self.filedata.len() as u64
    }
}

impl LoadImage for RawLoadImage {
    // Ghidra: loadimage.cc:39 RawLoadImage::getFilename
    fn get_filename(&self) -> &str {
        &self.filename
    }

    // Ghidra: loadimage.cc:84 RawLoadImage::loadFill
    fn load_fill(&self, size: usize, addr: Address) -> Result<Vec<u8>, DataUnavailError> {
        let mut result = vec![0u8; size];
        let mut cur_addr = addr.as_u64();
        let mut offset = 0usize;
        let mut remaining = size;

        // Compute relative offset from vma.
        cur_addr = cur_addr.wrapping_sub(self.vma);

        while remaining > 0 {
            if cur_addr >= self.filedata.len() as u64 {
                if offset == 0 {
                    // Initial address not within file.
                    return Err(DataUnavailError(format!(
                        "Unable to load {size} bytes at {addr:#x}"
                    )));
                }
                // Fill the rest with zeros (already zero-initialized).
                return Ok(result);
            }
            let read_size = remaining.min(self.filedata.len() - cur_addr as usize);
            result[offset..offset + read_size]
                .copy_from_slice(&self.filedata[cur_addr as usize..cur_addr as usize + read_size]);
            offset += read_size;
            remaining -= read_size;
            cur_addr += read_size as u64;
        }
        Ok(result)
    }

    // Ghidra: loadimage.cc:71 RawLoadImage::getArchType
    fn get_arch_type(&self) -> String {
        "unknown".to_string()
    }

    // Ghidra: loadimage.cc:77 RawLoadImage::adjustVma
    fn adjust_vma(&mut self, adjust: i64) {
        self.vma = (self.vma as i64 + adjust) as u64;
    }
}

/// An in-memory load image backed by a byte buffer at a specific address.
/// Useful for testing and for the existing Rudra binary-parsing pipeline.
pub struct MemoryLoadImage {
    /// The byte data.
    data: Vec<u8>,
    /// The base address where the data starts.
    base_addr: u64,
    /// Architecture type string.
    arch_type: String,
}

impl MemoryLoadImage {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Construct from byte data at a base address.
    pub fn new(data: Vec<u8>, base_addr: u64, arch_type: &str) -> Self {
        Self {
            data,
            base_addr,
            arch_type: arch_type.to_string(),
        }
    }
}

impl LoadImage for MemoryLoadImage {
    // RUDRA-GLUE: get_filename (no Ghidra counterpart found)
    fn get_filename(&self) -> &str {
        "<memory>"
    }

    // RUDRA-GLUE: load_fill (no Ghidra counterpart found)
    fn load_fill(&self, size: usize, addr: Address) -> Result<Vec<u8>, DataUnavailError> {
        let offset = addr.as_u64().saturating_sub(self.base_addr);
        if offset as usize + size > self.data.len() {
            return Err(DataUnavailError(format!(
                "Address {addr:#x} + {size} not in image (base={:#x}, len={})",
                self.base_addr,
                self.data.len()
            )));
        }
        Ok(self.data[offset as usize..offset as usize + size].to_vec())
    }

    // RUDRA-GLUE: get_arch_type (no Ghidra counterpart found)
    fn get_arch_type(&self) -> String {
        self.arch_type.clone()
    }

    // RUDRA-GLUE: adjust_vma (no Ghidra counterpart found)
    fn adjust_vma(&mut self, adjust: i64) {
        self.base_addr = (self.base_addr as i64 + adjust) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_load_image_from_bytes() {
        let img = RawLoadImage::from_bytes("test", 0x1000, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(img.file_size(), 4);
        let bytes = img.load_fill(4, Address::new(0x1000)).unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_raw_load_image_partial() {
        let img = RawLoadImage::from_bytes("test", 0x1000, vec![1, 2, 3, 4]);
        // Read 4 bytes starting at 0x1002 — only 2 are in range, rest zero.
        let bytes = img.load_fill(4, Address::new(0x1002)).unwrap();
        assert_eq!(bytes, vec![3, 4, 0, 0]);
    }

    #[test]
    fn test_raw_load_image_out_of_range() {
        let img = RawLoadImage::from_bytes("test", 0x1000, vec![1, 2, 3, 4]);
        let result = img.load_fill(4, Address::new(0x9999));
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_load_image_load_value() {
        let img = RawLoadImage::from_bytes("test", 0x1000, vec![0x78, 0x56, 0x34, 0x12]);
        // Little-endian: 0x12345678.
        let val = img.load_value(Address::new(0x1000), 4).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_raw_load_image_adjust_vma() {
        let mut img = RawLoadImage::from_bytes("test", 0x1000, vec![1, 2, 3]);
        img.adjust_vma(0x100);
        assert_eq!(img.vma, 0x1100);
        // Now the same data is at 0x1100.
        let bytes = img.load_fill(3, Address::new(0x1100)).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_raw_load_image_arch_type() {
        let img = RawLoadImage::from_bytes("test", 0, vec![]);
        assert_eq!(img.get_arch_type(), "unknown");
    }

    #[test]
    fn test_memory_load_image() {
        let img = MemoryLoadImage::new(vec![0xAA, 0xBB, 0xCC, 0xDD], 0x400000, "x86:LE:64:default");
        assert_eq!(img.get_arch_type(), "x86:LE:64:default");
        let bytes = img.load_fill(2, Address::new(0x400000)).unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB]);
        let bytes = img.load_fill(4, Address::new(0x400000)).unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_memory_load_image_out_of_range() {
        let img = MemoryLoadImage::new(vec![1, 2], 0x1000, "test");
        let result = img.load_fill(4, Address::new(0x1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_image_func() {
        let f = LoadImageFunc {
            address: Address::new(0x401000),
            name: "main".to_string(),
        };
        assert_eq!(f.address.as_u64(), 0x401000);
        assert_eq!(f.name, "main");
    }

    #[test]
    fn test_load_image_section() {
        let s = LoadImageSection {
            address: Address::new(0x1000),
            size: 256,
            flags: section_flags::CODE | section_flags::READONLY,
        };
        assert_eq!(s.size, 256);
        assert!(s.flags & section_flags::CODE != 0);
        assert!(s.flags & section_flags::READONLY != 0);
    }
}
