//! Binary parsing and loading module
//!
//! This module handles parsing and loading of various binary formats including:
//! - ELF (Executable and Linkable Format) - Linux
//! - PE (Portable Executable) - Windows
//! - Mach-O - macOS
//!
//! # Example
//!
//! ```rust,no_run
//! use rudra::binary::Binary;
//!
//! # fn main() -> anyhow::Result<()> {
//! let data = std::fs::read("program.exe")?;
//! let binary = Binary::parse(&data)?;
//! println!("Entry point: {}", binary.entry_point());
//! # Ok(())
//! # }
//! ```

use crate::{Address, Architecture, Error, Result};
use goblin::Object;

/// Binary format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// ELF format (Linux, BSD, etc.)
    Elf,
    /// PE format (Windows)
    Pe,
    /// Mach-O format (macOS, iOS)
    MachO,
    /// Raw binary
    Raw,
}

/// Parsed binary file
#[derive(Debug)]
pub struct Binary {
    /// Binary format
    format: BinaryFormat,
    /// Target architecture
    architecture: Architecture,
    /// Entry point address
    entry_point: Address,
    /// Binary data
    data: Vec<u8>,
    /// Discovered functions (address -> name)
    functions: std::collections::HashMap<Address, String>,
}

impl Binary {
    // RUDRA-GLUE: parse (no Ghidra counterpart found)
    /// Parse a binary file from raw bytes
    ///
    /// # Arguments
    ///
    /// * `data` - Raw binary data
    ///
    /// # Returns
    ///
    /// Parsed binary or error
    pub fn parse(data: &[u8]) -> Result<Self> {
        let obj = Object::parse(data)?;

        match obj {
            Object::Elf(elf) => Self::parse_elf(data, elf),
            Object::PE(pe) => Self::parse_pe(data, pe),
            Object::Mach(mach) => Self::parse_macho(data, mach),
            _ => Err(Error::UnsupportedFormat("Unknown format".into())),
        }
    }

    // RUDRA-GLUE: entry_point (no Ghidra counterpart found)
    /// Get the entry point address
    pub fn entry_point(&self) -> Address {
        self.entry_point
    }

    // RUDRA-GLUE: format (no Ghidra counterpart found)
    /// Get the binary format
    pub fn format(&self) -> BinaryFormat {
        self.format
    }

    // RUDRA-GLUE: architecture (no Ghidra counterpart found)
    /// Get the target architecture
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    // RUDRA-GLUE: get_functions (no Ghidra counterpart found)
    /// Get list of function addresses
    ///
    /// # Returns
    ///
    /// Vector of function entry point addresses
    pub fn get_functions(&self) -> Vec<Address> {
        self.functions.keys().cloned().collect()
    }

    // RUDRA-GLUE: get_function_name (no Ghidra counterpart found)
    /// Get function name by address
    pub fn get_function_name(&self, addr: Address) -> Option<&String> {
        self.functions.get(&addr)
    }

    // RUDRA-GLUE: read_string_at (no Ghidra counterpart found)
    /// Read a null-terminated string from the binary at the given address
    pub fn read_string_at(&self, addr: Address) -> Option<String> {
        // Simple heuristic: address maps directly to offset for now
        // In a full implementation, we would map VA to file offset via sections/segments
        let offset = addr.as_u64() as usize;

        if offset >= self.data.len() {
            return None;
        }

        let max_len = 256; // Reasonable max length for string literals
        let end = std::cmp::min(offset + max_len, self.data.len());
        let slice = &self.data[offset..end];

        // Find null terminator
        if let Some(null_pos) = slice.iter().position(|&b| b == 0) {
            let string_bytes = &slice[..null_pos];

            // Heuristic: ignore empty strings or single characters which might just be random bytes
            if string_bytes.len() < 2 {
                return None;
            }

            // Check if valid UTF-8 and printable
            if let Ok(s) = std::str::from_utf8(string_bytes) {
                // Heuristic: check if mostly printable characters
                // We allow whitespace and common control chars like \n, \r, \t
                if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
                    return Some(s.to_string());
                }
            }
        }

        None
    }

    // RUDRA-GLUE: parse_elf (no Ghidra counterpart found)
    // Private parsing methods

    fn parse_elf(data: &[u8], elf: goblin::elf::Elf) -> Result<Self> {
        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_AARCH64 => Architecture::ARM64,
            goblin::elf::header::EM_ARM => Architecture::ARM,
            goblin::elf::header::EM_MIPS => Architecture::MIPS,
            _ => return Err(Error::UnsupportedArchitecture("Unknown ELF machine".into())),
        };

        let entry_point = Address::new(elf.entry);
        let mut functions = std::collections::HashMap::new();

        // Extract functions and data from symbol table
        for sym in elf.syms.iter() {
            let st_type = sym.st_type();
            if (st_type == goblin::elf::sym::STT_FUNC || st_type == goblin::elf::sym::STT_OBJECT) && sym.st_value != 0 {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    functions.insert(Address::new(sym.st_value), name.to_string());
                }
            }
        }

        // Add entry point if not already present
        if !functions.contains_key(&entry_point) {
            functions.insert(entry_point, "_start".to_string());
        }

        // Parse PLT sections to resolve imported functions
        // We scan sections for .plt and .plt.sec to identify thunks
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                if name == ".plt" || name == ".plt.sec" {
                    let start = header.sh_addr;
                    let entry_size: u64 = 16; // x86-64 PLT entry size
                    let relocs = &elf.pltrelocs;

                    if !relocs.is_empty() {
                        if name == ".plt.sec" {
                            // .plt.sec entries map 1-to-1 to relocations
                            for (idx, reloc) in relocs.iter().enumerate() {
                                let func_addr = start + (idx as u64 * entry_size);
                                let sym_idx = reloc.r_sym;
                                if let Some(sym) = elf.dynsyms.get(sym_idx) {
                                    if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                                        functions.insert(Address::new(func_addr), sym_name.to_string());
                                    }
                                }
                            }
                        } else if name == ".plt" {
                            // Standard .plt has a reserved entry at the beginning (PLT0)
                            // Subsequent entries map to relocations
                            // PLT0 is 16 bytes. PLT1..N correspond to relocs 0..N-1
                            for (idx, reloc) in relocs.iter().enumerate() {
                                let func_addr = start + 16 + (idx as u64 * entry_size);
                                // Ensure we don't go out of bounds of the section
                                if func_addr < start + header.sh_size {
                                    let sym_idx = reloc.r_sym;
                                    if let Some(sym) = elf.dynsyms.get(sym_idx) {
                                        if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                                            functions.insert(Address::new(func_addr), sym_name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Binary {
            format: BinaryFormat::Elf,
            architecture,
            entry_point,
            data: data.to_vec(),
            functions,
        })
    }

    // RUDRA-GLUE: parse_pe (no Ghidra counterpart found)
    fn parse_pe(data: &[u8], pe: goblin::pe::PE) -> Result<Self> {
        let architecture = match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
            goblin::pe::header::COFF_MACHINE_X86 => Architecture::X86,
            _ => return Err(Error::UnsupportedArchitecture("Unknown PE machine".into())),
        };

        let image_base = pe.header.optional_header
            .map(|oh| oh.windows_fields.image_base)
            .unwrap_or(0);

        let entry_point = Address::new(
            pe.header.optional_header
                .map(|oh| oh.standard_fields.address_of_entry_point as u64 + image_base)
                .unwrap_or(0)
        );

        let mut functions = std::collections::HashMap::new();

        // Extract functions from export table
        for export in pe.exports {
            if let Some(name) = export.name {
                let addr = Address::new(export.rva as u64 + image_base);
                functions.insert(addr, name.to_string());
            }
        }

        Ok(Binary {
            format: BinaryFormat::Pe,
            architecture,
            entry_point,
            data: data.to_vec(),
            functions,
        })
    }

    // RUDRA-GLUE: parse_macho (no Ghidra counterpart found)
    fn parse_macho(data: &[u8], _mach: goblin::mach::Mach) -> Result<Self> {
        // TODO: Implement Mach-O parsing
        Ok(Binary {
            format: BinaryFormat::MachO,
            architecture: Architecture::X86_64, // Placeholder
            entry_point: Address::new(0),
            data: data.to_vec(),
            functions: std::collections::HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_format() {
        assert_eq!(BinaryFormat::Elf, BinaryFormat::Elf);
        assert_ne!(BinaryFormat::Elf, BinaryFormat::Pe);
    }
}
