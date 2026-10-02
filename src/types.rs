//! Core type definitions for Rudra
//!
//! This module contains fundamental types used throughout the decompiler,
//! including address types, architecture definitions, and basic data types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Memory address type
///
/// Represents a virtual memory address in the target binary.
/// Internally stored as u64 to support 64-bit architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(u64);

impl Address {
    /// Create a new address
    // RUDRA-GLUE: Legacy scalar compatibility type; Ghidra Address stores both an AddrSpace pointer and an offset.
    pub const fn new(addr: u64) -> Self {
        Address(addr)
    }

    /// Get the raw address value
    // RUDRA-GLUE: Accessor for the legacy scalar compatibility type, which has no separate Ghidra counterpart.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    // RUDRA-GLUE: offset (no Ghidra counterpart found)
    /// Add an offset to the address
    pub fn offset(&self, offset: i64) -> Self {
        Address((self.0 as i64 + offset) as u64)
    }

    // RUDRA-GLUE: is_null (no Ghidra counterpart found)
    /// Check if address is null (0x0)
    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    // RUDRA-GLUE: is_aligned (no Ghidra counterpart found)
    /// Check if address is aligned to the given boundary
    pub fn is_aligned(&self, alignment: u64) -> bool {
        self.0 % alignment == 0
    }
}

impl fmt::Display for Address {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl fmt::LowerHex for Address {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl fmt::UpperHex for Address {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl From<u64> for Address {
    // RUDRA-GLUE: from (no Ghidra counterpart found)
    fn from(addr: u64) -> Self {
        Address(addr)
    }
}

impl From<Address> for u64 {
    // RUDRA-GLUE: from (no Ghidra counterpart found)
    fn from(addr: Address) -> Self {
        addr.0
    }
}

/// Target CPU architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    /// x86 32-bit
    X86,
    /// x86 64-bit (AMD64)
    X86_64,
    /// ARM 32-bit
    ARM,
    /// ARM 64-bit (AArch64)
    ARM64,
    /// MIPS 32-bit
    MIPS,
    /// MIPS 64-bit
    MIPS64,
    /// RISC-V 32-bit
    RISCV32,
    /// RISC-V 64-bit
    RISCV64,
    /// PowerPC 32-bit
    PPC,
    /// PowerPC 64-bit
    PPC64,
}

impl Architecture {
    /// Get the pointer size in bytes for this architecture
    // RUDRA-GLUE: Hard-coded target-enum metadata; Ghidra derives pointer size from configured spaces and type data.
    pub const fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86 => 4,
            Architecture::X86_64 => 8,
            Architecture::ARM => 4,
            Architecture::ARM64 => 8,
            Architecture::MIPS => 4,
            Architecture::MIPS64 => 8,
            Architecture::RISCV32 => 4,
            Architecture::RISCV64 => 8,
            Architecture::PPC => 4,
            Architecture::PPC64 => 8,
        }
    }

    /// Get the pointer size in bits for this architecture
    // RUDRA-GLUE: Rust convenience conversion over pointer_size; Ghidra has no equivalent target-enum helper.
    pub const fn pointer_bits(&self) -> usize {
        self.pointer_size() * 8
    }

    /// Check if this is a 64-bit architecture
    // RUDRA-GLUE: Predicate over a compatibility enum; Ghidra Architecture is a configured subsystem manager.
    pub const fn is_64bit(&self) -> bool {
        self.pointer_size() == 8
    }

    /// Get the register count (approximate)
    // RUDRA-GLUE: Approximate metadata; Ghidra obtains its register inventory from the active Translate/specification.
    pub const fn register_count(&self) -> usize {
        match self {
            Architecture::X86 => 8,
            Architecture::X86_64 => 16,
            Architecture::ARM => 16,
            Architecture::ARM64 => 32,
            Architecture::MIPS | Architecture::MIPS64 => 32,
            Architecture::RISCV32 | Architecture::RISCV64 => 32,
            Architecture::PPC | Architecture::PPC64 => 32,
        }
    }

    /// Get architecture name as string
    // RUDRA-GLUE: Compatibility-enum label; Ghidra uses configured architecture and language identifiers.
    pub const fn name(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::ARM => "arm",
            Architecture::ARM64 => "arm64",
            Architecture::MIPS => "mips",
            Architecture::MIPS64 => "mips64",
            Architecture::RISCV32 => "riscv32",
            Architecture::RISCV64 => "riscv64",
            Architecture::PPC => "ppc",
            Architecture::PPC64 => "ppc64",
        }
    }
}

impl fmt::Display for Architecture {
    // Ghidra: type.hh:155 Architecture::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Data type sizes and kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TypeKind {
    /// Void type
    Void,
    /// Boolean (1 byte)
    Bool,
    /// Signed 8-bit integer
    Int8,
    /// Unsigned 8-bit integer
    UInt8,
    /// Signed 16-bit integer
    Int16,
    /// Unsigned 16-bit integer
    UInt16,
    /// Signed 32-bit integer
    Int32,
    /// Unsigned 32-bit integer
    UInt32,
    /// Signed 64-bit integer
    Int64,
    /// Unsigned 64-bit integer
    UInt64,
    /// 32-bit floating point
    Float32,
    /// 64-bit floating point
    Float64,
    /// Pointer to another type
    Pointer,
    /// Array of elements
    Array,
    /// Structure/compound type
    Struct,
    /// Union type
    Union,
    /// Function pointer
    Function,
    /// Unknown/inferred type
    Unknown,
}

impl TypeKind {
    /// Get the size in bytes of this type (if fixed-size)
    // RUDRA-GLUE: Coarse enum metadata; Ghidra Datatype stores size per instance instead of using this fixed table.
    pub const fn size_bytes(&self) -> Option<usize> {
        match self {
            TypeKind::Void => Some(0),
            TypeKind::Bool | TypeKind::Int8 | TypeKind::UInt8 => Some(1),
            TypeKind::Int16 | TypeKind::UInt16 => Some(2),
            TypeKind::Int32 | TypeKind::UInt32 | TypeKind::Float32 => Some(4),
            TypeKind::Int64 | TypeKind::UInt64 | TypeKind::Float64 => Some(8),
            TypeKind::Pointer => None, // Architecture-dependent
            TypeKind::Array | TypeKind::Struct | TypeKind::Union => None, // Depends on contents
            TypeKind::Function => None, // Not a value type
            TypeKind::Unknown => None,
        }
    }

    /// Check if this is an integer type
    // RUDRA-GLUE: Predicate over Rudra's coarse TypeKind enum; Ghidra classifies per-instance Datatype metatypes.
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            TypeKind::Int8
                | TypeKind::UInt8
                | TypeKind::Int16
                | TypeKind::UInt16
                | TypeKind::Int32
                | TypeKind::UInt32
                | TypeKind::Int64
                | TypeKind::UInt64
        )
    }

    /// Check if this is a signed integer type
    // RUDRA-GLUE: Predicate over Rudra's coarse TypeKind enum; Ghidra represents signedness through Datatype metatypes.
    pub const fn is_signed(&self) -> bool {
        matches!(
            self,
            TypeKind::Int8 | TypeKind::Int16 | TypeKind::Int32 | TypeKind::Int64
        )
    }

    /// Check if this is a floating point type
    // RUDRA-GLUE: Predicate over Rudra's coarse TypeKind enum; Ghidra tests a Datatype's stored metatype.
    pub const fn is_float(&self) -> bool {
        matches!(self, TypeKind::Float32 | TypeKind::Float64)
    }

    /// Check if this is a pointer type
    // RUDRA-GLUE: Predicate over Rudra's coarse TypeKind enum; Ghidra uses Datatype subclasses and stored metatypes.
    pub const fn is_pointer(&self) -> bool {
        matches!(self, TypeKind::Pointer)
    }
}

impl fmt::Display for TypeKind {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TypeKind::Void => "void",
            TypeKind::Bool => "bool",
            TypeKind::Int8 => "i8",
            TypeKind::UInt8 => "u8",
            TypeKind::Int16 => "i16",
            TypeKind::UInt16 => "u16",
            TypeKind::Int32 => "i32",
            TypeKind::UInt32 => "u32",
            TypeKind::Int64 => "i64",
            TypeKind::UInt64 => "u64",
            TypeKind::Float32 => "f32",
            TypeKind::Float64 => "f64",
            TypeKind::Pointer => "ptr",
            TypeKind::Array => "array",
            TypeKind::Struct => "struct",
            TypeKind::Union => "union",
            TypeKind::Function => "fn",
            TypeKind::Unknown => "?",
        };
        write!(f, "{}", name)
    }
}

/// Calling convention
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// C calling convention (cdecl on x86)
    C,
    /// Standard call (stdcall on x86)
    Stdcall,
    /// Fast call (fastcall)
    Fastcall,
    /// Microsoft x64 calling convention
    Win64,
    /// System V AMD64 ABI
    SysV64,
    /// ARM AAPCS
    AAPCS,
    /// Unknown/custom calling convention
    Unknown,
}

impl fmt::Display for CallingConvention {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            CallingConvention::C => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Fastcall => "fastcall",
            CallingConvention::Win64 => "win64",
            CallingConvention::SysV64 => "sysv64",
            CallingConvention::AAPCS => "aapcs",
            CallingConvention::Unknown => "unknown",
        };
        write!(f, "{}", name)
    }
}

/// Endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    /// Little-endian byte order
    Little,
    /// Big-endian byte order
    Big,
}

impl Endianness {
    /// Get the native endianness of the current system
    // RUDRA-GLUE: Rust target_cfg wrapper; Ghidra exposes host endianness through HOST_ENDIAN, not a function.
    pub const fn native() -> Self {
        #[cfg(target_endian = "little")]
        return Endianness::Little;
        #[cfg(target_endian = "big")]
        return Endianness::Big;
    }
}

impl fmt::Display for Endianness {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endianness::Little => write!(f, "little"),
            Endianness::Big => write!(f, "big"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let addr = Address::new(0x1000);
        assert_eq!(addr.as_u64(), 0x1000);
    }

    #[test]
    fn test_address_offset() {
        let addr = Address::new(0x1000);
        let new_addr = addr.offset(0x100);
        assert_eq!(new_addr.as_u64(), 0x1100);

        let neg_addr = addr.offset(-0x10);
        assert_eq!(neg_addr.as_u64(), 0x0ff0);
    }

    #[test]
    fn test_address_alignment() {
        let addr = Address::new(0x1000);
        assert!(addr.is_aligned(4));
        assert!(addr.is_aligned(16));

        let unaligned = Address::new(0x1001);
        assert!(!unaligned.is_aligned(4));
    }

    #[test]
    fn test_address_display() {
        let addr = Address::new(0x1234);
        assert_eq!(addr.to_string(), "0x1234");
        assert_eq!(format!("{:x}", addr), "1234");
        assert_eq!(format!("{:X}", addr), "1234");
    }

    #[test]
    fn test_architecture_sizes() {
        assert_eq!(Architecture::X86.pointer_size(), 4);
        assert_eq!(Architecture::X86_64.pointer_size(), 8);
        assert_eq!(Architecture::ARM.pointer_size(), 4);
        assert_eq!(Architecture::ARM64.pointer_size(), 8);
    }

    #[test]
    fn test_architecture_64bit() {
        assert!(!Architecture::X86.is_64bit());
        assert!(Architecture::X86_64.is_64bit());
        assert!(!Architecture::ARM.is_64bit());
        assert!(Architecture::ARM64.is_64bit());
    }

    #[test]
    fn test_type_kind_size() {
        assert_eq!(TypeKind::Int8.size_bytes(), Some(1));
        assert_eq!(TypeKind::Int32.size_bytes(), Some(4));
        assert_eq!(TypeKind::Int64.size_bytes(), Some(8));
        assert_eq!(TypeKind::Float64.size_bytes(), Some(8));
    }

    #[test]
    fn test_type_kind_predicates() {
        assert!(TypeKind::Int32.is_integer());
        assert!(TypeKind::Int32.is_signed());
        assert!(!TypeKind::UInt32.is_signed());
        assert!(TypeKind::Float32.is_float());
        assert!(TypeKind::Pointer.is_pointer());
    }

    #[test]
    fn test_endianness() {
        let le = Endianness::Little;
        let be = Endianness::Big;
        assert_ne!(le, be);
        assert_eq!(le.to_string(), "little");
        assert_eq!(be.to_string(), "big");
    }
}

/// Rich data type representation for analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    /// Unknown type (bottom of lattice) with size in bytes
    Unknown(usize),
    /// Void type (top of lattice / error)
    Void,
    /// Boolean
    Bool,
    /// Integer types: size in bytes, whether it's signed
    Int(usize, bool),
    /// Floating point: size in bytes
    Float(usize),
    /// Pointer to another type: pointee type, pointer size
    Pointer(Box<DataType>, usize),
    /// Array of elements: element type, count
    Array(Box<DataType>, usize),
    /// Structure: name of the struct
    Struct(String),
}

impl DataType {
    // RUDRA-GLUE: size (no Ghidra counterpart found)
    /// Get the size of the type in bytes
    pub fn size(&self) -> usize {
        match self {
            DataType::Unknown(sz) => *sz,
            DataType::Void => 0,
            DataType::Bool => 1,
            DataType::Int(sz, _) => *sz,
            DataType::Float(sz) => *sz,
            DataType::Pointer(_, sz) => *sz,
            DataType::Array(t, count) => t.size() * count,
            DataType::Struct(_) => 0, // Needs definition lookup
        }
    }

    // RUDRA-GLUE: is_unknown (no Ghidra counterpart found)
    /// Check if this is an unknown type
    pub fn is_unknown(&self) -> bool {
        matches!(self, DataType::Unknown(_))
    }

    // RUDRA-GLUE: is_pointer (no Ghidra counterpart found)
    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        matches!(self, DataType::Pointer(_, _))
    }

    // RUDRA-GLUE: is_integer (no Ghidra counterpart found)
    /// Check if this is an integer type
    pub fn is_integer(&self) -> bool {
        matches!(self, DataType::Int(_, _))
    }

    // RUDRA-GLUE: meet (no Ghidra counterpart found)
    /// The "meet" operation in the type lattice.
    /// Combines two types into their greatest lower bound.
    pub fn meet(&self, other: &DataType) -> DataType {
        if self == other {
            return self.clone();
        }

        match (self, other) {
            (DataType::Unknown(_), t) | (t, DataType::Unknown(_)) => t.clone(),
            (DataType::Void, _) | (_, DataType::Void) => DataType::Void,

            // Pointer merging
            (DataType::Pointer(t1, s1), DataType::Pointer(t2, s2)) => {
                if s1 != s2 { return DataType::Void; }
                let inner = t1.meet(t2);
                if inner == DataType::Void {
                    // Conflict in pointee type -> void*
                    DataType::Pointer(Box::new(DataType::Unknown(1)), *s1)
                } else {
                    DataType::Pointer(Box::new(inner), *s1)
                }
            },

            // Int merging
            (DataType::Int(s1, sign1), DataType::Int(s2, sign2)) => {
                if s1 != s2 { return DataType::Void; }
                if sign1 != sign2 {
                    DataType::Int(*s1, false) // Fallback to unsigned
                } else {
                    self.clone()
                }
            },

            _ => DataType::Void
        }
    }
}

/// A structure definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructDef {
    /// Structure name
    pub name: String,
    /// Fields in the structure
    pub fields: Vec<FieldDef>,
}

/// A field in a structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Field name
    pub name: String,
    /// Field type
    pub data_type: DataType,
    /// Offset in bytes from the start of the struct
    pub offset: usize,
}

impl StructDef {
    // RUDRA-GLUE: new (no Ghidra counterpart found)
    /// Create a new empty struct definition
    pub fn new(name: String) -> Self {
        StructDef {
            name,
            fields: Vec::new(),
        }
    }

    // RUDRA-GLUE: add_field (no Ghidra counterpart found)
    /// Add a field to the struct
    pub fn add_field(&mut self, name: String, data_type: DataType, offset: usize) {
        self.fields.push(FieldDef { name, data_type, offset });
        // Keep fields sorted by offset
        self.fields.sort_by_key(|f| f.offset);
    }

    // RUDRA-GLUE: size (no Ghidra counterpart found)
    /// Get the total size of the struct
    pub fn size(&self) -> usize {
        self.fields.iter()
            .map(|f| f.offset + f.data_type.size())
            .max()
            .unwrap_or(0)
    }
}

// RUDRA-GLUE: parse_type_string (no Ghidra counterpart found)
/// Parse a C-style type string into a DataType
pub fn parse_type_string(s: &str, size: usize) -> DataType {
    let s = s.trim();
    if s.ends_with('*') {
        let inner_s = s[..s.len() - 1].trim();
        let inner_type = parse_type_string(inner_s, 1);
        return DataType::Pointer(Box::new(inner_type), size);
    }

    match s {
        "char" | "int8_t" | "i8" => DataType::Int(1, true),
        "unsigned char" | "uint8_t" | "u8" => DataType::Int(1, false),
        "short" | "int16_t" | "i16" => DataType::Int(2, true),
        "unsigned short" | "uint16_t" | "u16" => DataType::Int(2, false),
        "int" | "int32_t" | "i32" => DataType::Int(4, true),
        "unsigned int" | "uint32_t" | "u32" => DataType::Int(4, false),
        "long" | "int64_t" | "i64" => DataType::Int(8, true),
        "unsigned long" | "uint64_t" | "u64" => DataType::Int(8, false),
        "float" => DataType::Float(4),
        "double" => DataType::Float(8),
        "bool" | "_Bool" => DataType::Bool,
        "void" => DataType::Void,
        _ if s.starts_with("struct ") => DataType::Struct(s[7..].to_string()),
        _ => DataType::Unknown(size),
    }
}
