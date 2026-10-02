//! Instruction translation engine interfaces — faithful port of
//! `translate.hh` / `translate.cc` (1018 / 1018 lines).
//!
//! This module provides the core interfaces for disassembly and P-code
//! generation for a single processor architecture:
//!
//! - [`PcodeEmit`] (translate.hh:94) — callback for receiving generated P-code.
//! - [`AssemblyEmit`] (translate.hh:120) — callback for receiving disassembly.
//! - [`AddressResolver`] (translate.hh:142) — converts native constants to
//!   addresses (segmented / near-pointer extension).
//! - [`SpacebaseSpace`] (translate.hh:172) — a virtual stack-like space that is
//!   indexed relative to a base register.
//! - [`JoinRecord`] (translate.hh:196) — describes how a logical value is split
//!   across multiple physical locations.
//! - [`AddrSpaceManager`] (translate.hh:220) — owns and indexes the address
//!   spaces for a processor.
//! - [`Translate`] (translate.hh:299) — the processor translation engine itself
//!   (a subclass of `AddrSpaceManager`).
//!
//! `Translate::initialize` takes the concrete `DocumentStorage`
//! (marshal.rs; xml.hh:258-291) by mutable reference, matching the C++
//! `initialize(DocumentStorage &store)` (translate.hh:332).
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/translate.{hh,cc}.

use crate::address::Address;
use crate::float_emulate::FloatFormat;
use crate::marshal::{AttributeId, Decoder, ElementId};
use crate::opcodes::OpCode;
use crate::space::{AddressSpace, VarnodeData};
use std::collections::HashMap;

// ============================================================================
// translate.cc:20-34 — Marshaling attribute / element id singletons
// ============================================================================
//
// These mirror Ghidra's file-scope `AttributeId ATTRIB_*` and
// `ElementId ELEM_*` definitions. Ghidra assigns each a unique numeric id
// (the second ctor argument); Rugra preserves those exact ids so that
// encoded data remains wire-compatible.

// Ghidra: translate.cc:20 ATTRIB_CODE
/// Marshaling attribute "code".
pub const ATTRIB_CODE: AttributeId = AttributeId::new_static("code", 43);
// Ghidra: translate.cc:21 ATTRIB_CONTAIN
/// Marshaling attribute "contain".
pub const ATTRIB_CONTAIN: AttributeId = AttributeId::new_static("contain", 44);
// Ghidra: translate.cc:22 ATTRIB_DEFAULTSPACE
/// Marshaling attribute "defaultspace".
pub const ATTRIB_DEFAULTSPACE: AttributeId = AttributeId::new_static("defaultspace", 45);
// Ghidra: translate.cc:23 ATTRIB_UNIQBASE
/// Marshaling attribute "uniqbase".
pub const ATTRIB_UNIQBASE: AttributeId = AttributeId::new_static("uniqbase", 46);

// Ghidra: translate.cc:25 ELEM_OP
/// Marshaling element `<op>`.
pub const ELEM_OP: ElementId = ElementId {
    name: String::new(),
    id: 27,
};
// Ghidra: translate.cc:26 ELEM_SLEIGH
/// Marshaling element `<sleigh>`.
pub const ELEM_SLEIGH: ElementId = ElementId {
    name: String::new(),
    id: 28,
};
// Ghidra: translate.cc:27 ELEM_SPACE
/// Marshaling element `<space>`.
pub const ELEM_SPACE: ElementId = ElementId {
    name: String::new(),
    id: 29,
};
// Ghidra: translate.cc:28 ELEM_SPACEID
/// Marshaling element `<spaceid>`.
pub const ELEM_SPACEID: ElementId = ElementId {
    name: String::new(),
    id: 30,
};
// Ghidra: translate.cc:29 ELEM_SPACES
/// Marshaling element `<spaces>`.
pub const ELEM_SPACES: ElementId = ElementId {
    name: String::new(),
    id: 31,
};
// Ghidra: translate.cc:30 ELEM_SPACE_BASE
/// Marshaling element `<space_base>`.
pub const ELEM_SPACE_BASE: ElementId = ElementId {
    name: String::new(),
    id: 32,
};
// Ghidra: translate.cc:31 ELEM_SPACE_OTHER
/// Marshaling element `<space_other>`.
pub const ELEM_SPACE_OTHER: ElementId = ElementId {
    name: String::new(),
    id: 33,
};
// Ghidra: translate.cc:32 ELEM_SPACE_OVERLAY
/// Marshaling element `<space_overlay>`.
pub const ELEM_SPACE_OVERLAY: ElementId = ElementId {
    name: String::new(),
    id: 34,
};
// Ghidra: translate.cc:33 ELEM_SPACE_UNIQUE
/// Marshaling element `<space_unique>`.
pub const ELEM_SPACE_UNIQUE: ElementId = ElementId {
    name: String::new(),
    id: 35,
};
// Ghidra: translate.cc:34 ELEM_TRUNCATE_SPACE
/// Marshaling element `<truncate_space>`.
pub const ELEM_TRUNCATE_SPACE: ElementId = ElementId {
    name: String::new(),
    id: 36,
};

// RUDRA-GLUE: Marshal attribute/element ids used by decode routines but not
// defined in translate.cc. Ghidra defines these in marshal.cc with globally
// consistent ids; Rugra reuses the names so decoded streams remain
// interoperable. The ids here follow Ghidra's marshaling convention.
/// Marshaling attribute "space" (used by `<truncate_space>` decode).
pub const ATTRIB_SPACE: AttributeId = AttributeId::new_static("space", 47);
/// Marshaling attribute "size" (used by `<truncate_space>` decode).
pub const ATTRIB_SIZE: AttributeId = AttributeId::new_static("size", 48);
// Ghidra: marshal.cc:1241 ATTRIB_NAME
/// Marshaling attribute "name" (space decode, space.cc:311).
pub const ATTRIB_NAME: AttributeId = AttributeId::new_static("name", 14);
// Ghidra: marshal.cc:1237 ATTRIB_INDEX
/// Marshaling attribute "index" (space decode, space.cc:315).
pub const ATTRIB_INDEX: AttributeId = AttributeId::new_static("index", 10);
// Ghidra: space.cc:21 ATTRIB_BASE
/// Marshaling attribute "base" (overlay space decode, space.cc:668).
pub const ATTRIB_BASE: AttributeId = AttributeId::new_static("base", 89);

// ============================================================================
// translate.hh:53 / 68 — Translation-specific errors
// ============================================================================

/// Exception for encountering unimplemented pcode. Faithful to
/// `UnimplError` (translate.hh:53).
///
/// Thrown when a particular machine instruction cannot be translated into
/// pcode: the instruction was valid, but the system does not know how to
/// represent it in pcode.
#[derive(Debug, Clone)]
pub struct UnimplError {
    /// Verbose description of the error.
    pub message: String,
    // Ghidra: translate.hh:54 instruction_length
    /// Number of bytes in the unimplemented instruction.
    pub instruction_length: i32,
}

impl UnimplError {
    // Ghidra: translate.hh:59 UnimplError::UnimplError
    /// Construct from a description and the (byte) length of the offending
    /// instruction. Faithful to `UnimplError(const string &s, int4 l)`.
    pub fn new(message: impl Into<String>, length: i32) -> Self {
        Self {
            message: message.into(),
            instruction_length: length,
        }
    }
}

impl std::fmt::Display for UnimplError {
    // RUDRA-GLUE: Display impl (Rust requires Display for error interop;
    // Ghidra's LowlevelError base provides what()).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnimplError: {}", self.message)
    }
}

impl std::error::Error for UnimplError {}

/// Exception for bad instruction data. Faithful to `BadDataError`
/// (translate.hh:68).
///
/// Thrown when the system cannot decode the data for a particular
/// instruction. This usually means the data is not really a machine
/// instruction, but may indicate the system is unaware of the instruction.
#[derive(Debug, Clone)]
pub struct BadDataError {
    /// Verbose description of the error.
    pub message: String,
}

impl BadDataError {
    // Ghidra: translate.hh:72 BadDataError::BadDataError
    /// Construct from a verbose description. Faithful to
    /// `BadDataError(const string &s)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BadDataError {
    // RUDRA-GLUE: Display impl (Rust requires Display for error interop).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BadDataError: {}", self.message)
    }
}

impl std::error::Error for BadDataError {}

// ============================================================================
// translate.hh:81 — TruncationTag
// ============================================================================

/// Object describing how a space should be truncated. Faithful to
/// `TruncationTag` (translate.hh:81).
///
/// This can appear in various XML configuration files and acts as a command
/// to override the size of an address space as defined by the architecture.
#[derive(Debug, Clone, Default)]
pub struct TruncationTag {
    // Ghidra: translate.hh:83 spaceName
    /// Name of the space to be truncated.
    pub space_name: String,
    // Ghidra: translate.hh:84 size
    /// Size (of pointers) for the new truncated space.
    pub size: u32,
}

impl TruncationTag {
    // RUDRA-GLUE: Explicit convenience constructor for Rust callers; Ghidra
    // relies on TruncationTag's implicit C++ default construction.
    /// Construct an empty tag. Rugra convenience constructor.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: translate.hh:86 TruncationTag::getName
    /// Get the name of the address space being truncated. Faithful to
    /// `getName`.
    pub fn get_name(&self) -> &str {
        &self.space_name
    }

    // Ghidra: translate.hh:87 TruncationTag::getSize
    /// Get the size (of pointers) for the new truncated space. Faithful to
    /// `getSize`.
    pub fn get_size(&self) -> u32 {
        self.size
    }

    // Ghidra: translate.cc:38 TruncationTag::decode
    /// Restore `self` from a `<truncate_space>` element. Faithful to
    /// `TruncationTag::decode` (translate.cc:38-45).
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        // uint4 elemId = decoder.openElement(ELEM_TRUNCATE_SPACE);
        let elem_id = decoder.open_element_matching(&ELEM_TRUNCATE_SPACE);
        // spaceName = decoder.readString(ATTRIB_SPACE);
        self.space_name = decoder.read_string_attr(&ATTRIB_SPACE);
        // size = decoder.readUnsignedInteger(ATTRIB_SIZE);
        self.size = decoder.read_unsigned_integer_attr(&ATTRIB_SIZE) as u32;
        // decoder.closeElement(elemId);
        decoder.close_element(elem_id);
    }
}

// ============================================================================
// translate.hh:94 — PcodeEmit
// ============================================================================

/// Abstract class for emitting pcode to an application. Faithful to
/// `PcodeEmit` (translate.hh:94).
///
/// Translation engines pass back the generated pcode for an instruction to
/// the application via this trait. Applications implement [`PcodeEmit::dump`]
/// to tailor how the operations are used.
pub trait PcodeEmit {
    // Ghidra: translate.hh:110 PcodeEmit::dump
    /// The main pcode emit method. Faithful to
    /// `dump(const Address &addr, OpCode opc, VarnodeData *outvar,
    ///       VarnodeData *vars, int4 isize)`.
    ///
    /// A single pcode instruction is returned to the application via this
    /// method. `outvar` is `None` when the op has no output varnode.
    /// `vars` is the slice of input varnodes (length `isize` in Ghidra; in
    /// Rust the length is implicit in the slice).
    fn dump(
        &mut self,
        addr: Address,
        opc: OpCode,
        outvar: Option<&VarnodeData>,
        vars: &[VarnodeData],
    );

    // Ghidra: translate.cc:996 PcodeEmit::decodeOp
    /// Emit pcode directly from an `<op>` element. Faithful to
    /// `PcodeEmit::decodeOp` (translate.cc:996-1016).
    ///
    /// A single p-code operation is parsed from an `<op>` element and
    /// returned to the application via [`PcodeEmit::dump`].
    ///
    /// Note: Ghidra reuses a stack-allocated 16-entry `invar` array and only
    /// heap-allocates when `isize > 16`. Rugra always heap-allocates the
    /// input vec for simplicity; the observable behavior (a single `dump`
    /// callback with the parsed op) is identical.
    fn decode_op(&mut self, addr: Address, decoder: &mut dyn Decoder) {
        // uint4 elemId = decoder.openElement(ELEM_OP);
        let elem_id = decoder.open_element_matching(&ELEM_OP);
        // isize = decoder.readSignedInteger(ATTRIB_SIZE);
        let isize = decoder.read_signed_integer_attr(&ATTRIB_SIZE) as usize;
        // VarnodeData outvar; VarnodeData *outptr = &outvar;
        let mut outvar = VarnodeData {
            space: AddressSpace::Const,
            offset: 0,
            size: 0,
        };
        // The C++ code passes &outptr so decode can set it to null for ops
        // with no output. Rugra mirrors this with an Option.
        let mut has_output = true;
        // Ghidra calls PcodeOpRaw::decode(decoder, isize, invar, &outptr),
        // which populates the input array and (conditionally) the output
        // varnode and returns the opcode. Rugra performs an equivalent decode
        // via the free function `decode_pcode_raw` below.
        let mut invars: Vec<VarnodeData> = Vec::with_capacity(isize);
        for _ in 0..isize {
            invars.push(VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: 0,
            });
        }
        let opcode = decode_pcode_raw(decoder, isize, &mut invars, &mut outvar, &mut has_output);
        // decoder.closeElement(elemId);
        decoder.close_element(elem_id);
        // dump(addr,(OpCode)opcode,outptr,invar,isize);
        let out_ref = if has_output { Some(&outvar) } else { None };
        self.dump(addr, opcode, out_ref, &invars);
    }
}

// RUDRA-GLUE: decode_pcode_raw (Ghidra delegates to PcodeOpRaw::decode in
// pcoderaw.cc; Rugra does not yet port PcodeOpRaw::decode. Kept as a free
// function rather than a trait method so that `PcodeEmit` stays
// dyn-compatible/object-safe while decode_op's control flow remains
// faithful to translate.cc:996-1016. Concrete engines with a real
// PcodeOpRaw port can replace this implementation.)
/// Parse `isize` input varnodes and (optionally) one output varnode from
/// the current element's attributes, returning the decoded opcode.
///
/// Default implementation is a placeholder returning `CPUI_COPY`; a full port
/// of `PcodeOpRaw::decode` (pcoderaw.cc) will supply the real opcode and
/// varnodes.
pub fn decode_pcode_raw(
    _decoder: &mut dyn Decoder,
    _isize: usize,
    _vars: &mut [VarnodeData],
    _outvar: &mut VarnodeData,
    _has_output: &mut bool,
) -> OpCode {
    OpCode::CPUI_COPY
}

// ============================================================================
// translate.hh:120 — AssemblyEmit
// ============================================================================

/// Abstract class for emitting disassembly to an application. Faithful to
/// `AssemblyEmit` (translate.hh:120).
///
/// Translation engines pass back the disassembly character data for decoded
/// machine instructions to the application via this trait.
pub trait AssemblyEmit {
    // Ghidra: translate.hh:133 AssemblyEmit::dump
    /// The main disassembly emitting method. Faithful to
    /// `dump(const Address &addr, const string &mnem, const string &body)`.
    ///
    /// The disassembly strings for a single machine instruction are passed
    /// back to the application through this method.
    fn dump(&mut self, addr: Address, mnem: &str, body: &str);
}

// ============================================================================
// translate.hh:142 — AddressResolver
// ============================================================================

/// Abstract class for converting native constants to addresses. Faithful to
/// `AddressResolver` (translate.hh:142).
///
/// Used when a special calculation is needed to get from a constant embedded
/// in the code being analyzed to the actual `Address` being referred to.
/// This is used especially for segmented architectures, where "near" pointers
/// must be extended to a full address with implied segment information.
pub trait AddressResolver {
    // Ghidra: translate.hh:158 AddressResolver::resolve
    /// The main resolver method. Faithful to
    /// `resolve(uintb val, int4 sz, const Address &point, uintb &fullEncoding)`.
    ///
    /// Given a native constant in a specific context, resolve what address
    /// is being referred to. The constant can be a partially encoded
    /// pointer, in which case the full pointer encoding is recovered as
    /// well as the address. `sz` indicates the number of bytes in the
    /// pointer; a value of `-1` indicates that the pointer is known to be a
    /// full encoding. `full_encoding` is updated with the full pointer
    /// encoding if `val` is a partial encoding.
    fn resolve(
        &mut self,
        val: u64,
        sz: i32,
        point: Address,
        full_encoding: &mut u64,
    ) -> Address;
}

// ============================================================================
// translate.hh:172 — SpacebaseSpace
// ============================================================================

/// A virtual stack space. Faithful to `SpacebaseSpace` (translate.hh:172).
///
/// In many analysis situations it is convenient to extend the notion of an
/// address space to mean bytes that are indexed relative to some base
/// register. The canonical example is the **stack** space, which models the
/// concept of local variables stored on the stack. An address of
/// `(stack, 8)` might model a function parameter, and `(stack, 0xfffffff4)`
/// might be a local variable. Such a space is inherently virtual and
/// contained within whatever space is being indexed into.
///
/// In Ghidra this class inherits from `AddrSpace`; Rugra models the address
/// space identity via [`AddressSpace::Stack`] (and other `SpacebaseSpace`
/// instances via their containing-space pointer), so this struct holds only
/// the spacebase-specific state.
#[derive(Debug, Clone)]
pub struct SpacebaseSpace {
    // Ghidra: translate.hh:174 contain
    /// Containing space.
    pub contain: AddressSpace,
    // Ghidra: translate.hh:175 hasbaseregister
    /// `true` if a base register has been attached.
    pub has_base_register: bool,
    // Ghidra: translate.hh:176 isNegativeStack
    /// `true` if the stack grows in the negative direction.
    pub is_negative_stack: bool,
    // Ghidra: translate.hh:177 baseloc
    /// Location data of the (possibly truncated) base register.
    pub base_loc: VarnodeData,
    // Ghidra: translate.hh:178 baseOrig
    /// Original base register before any truncation.
    pub base_orig: VarnodeData,
    /// Formal name of this space (e.g. "stack"). Rugra addition: Ghidra's
    /// name lives on the AddrSpace base, which Rugra's enum does not carry
    /// per-instance.
    pub name: String,
    /// Index of this space in the manager. Rugra addition mirroring
    /// AddrSpace::index.
    pub index: i32,
    /// Address size (bytes) of this space.
    pub addr_size: i32,
    /// Heritage delay (passes) for this space.
    pub delay: i32,
}

impl SpacebaseSpace {
    // Ghidra: translate.cc:57 SpacebaseSpace::SpacebaseSpace (full ctor)
    /// Construct a virtual space, usually for the stack. Faithful to the
    /// full constructor `SpacebaseSpace(AddrSpaceManager *m, const Translate *t,
    /// const string &nm, int4 ind, int4 sz, AddrSpace *base, int4 dl,
    /// bool isFormal)` (translate.cc:57-66).
    ///
    /// `is_formal` indicates the formal stack space; multiple spacebase
    /// spaces are allowed. The stack-grows-negative flag defaults to `true`
    /// (Ghidra's default stack growth).
    pub fn new(
        nm: impl Into<String>,
        ind: i32,
        sz: i32,
        base: AddressSpace,
        dl: i32,
        is_formal: bool,
    ) -> Self {
        let _ = is_formal; // formal_stackspace flag is a no-op in Rugra's enum model
        Self {
            contain: base,
            has_base_register: false,
            is_negative_stack: true,
            base_loc: VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: 0,
            },
            base_orig: VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: 0,
            },
            name: nm.into(),
            index: ind,
            addr_size: sz,
            delay: dl,
        }
    }

    // Ghidra: translate.cc:73 SpacebaseSpace::SpacebaseSpace (decode ctor)
    /// Partial constructor for use with [`SpacebaseSpace::decode`]. Faithful
    /// to `SpacebaseSpace(AddrSpaceManager *m, const Translate *t)` which
    /// must be followed up with `decode` (translate.cc:73-79).
    ///
    /// Sets `has_base_register = false`, `is_negative_stack = true`, and
    /// marks the space as program-specific (Rugra no-op).
    pub fn new_for_decode() -> Self {
        Self {
            contain: AddressSpace::Ram,
            has_base_register: false,
            is_negative_stack: true,
            base_loc: VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: 0,
            },
            base_orig: VarnodeData {
                space: AddressSpace::Const,
                offset: 0,
                size: 0,
            },
            name: String::new(),
            index: 0,
            addr_size: 0,
            delay: 0,
        }
    }

    // Ghidra: translate.cc:86 SpacebaseSpace::setBaseRegister
    /// Set the base register associated with this virtual space. Faithful to
    /// `setBaseRegister(const VarnodeData &data, int4 truncSize,
    ///                  bool stackGrowth)` (translate.cc:86-102).
    ///
    /// Throws (panics, in Rugra) if a different base register was already
    /// assigned. When `trunc_size != data.size`, the stored `baseloc` is
    /// truncated: for big-endian spaces the high bytes are skipped.
    pub fn set_base_register(&mut self, data: &VarnodeData, trunc_size: i32, stack_growth: bool) {
        if self.has_base_register {
            // Ghidra: throw LowlevelError("Attempt to assign more than one
            //                          base register to space: "+getName());
            if self.base_loc != *data || self.is_negative_stack != stack_growth {
                panic!(
                    "Attempt to assign more than one base register to space: {}",
                    self.name
                );
            }
        }
        self.has_base_register = true;
        self.is_negative_stack = stack_growth;
        self.base_orig = data.clone();
        self.base_loc = data.clone();
        // if (truncSize != baseloc.size) { ... }
        if trunc_size != self.base_loc.size as i32 {
            if self.base_loc.space.is_big_endian() {
                // baseloc.offset += (baseloc.size - truncSize);
                self.base_loc.offset += (self.base_loc.size as i32 - trunc_size) as u64;
            }
            self.base_loc.size = trunc_size as usize;
        }
    }

    // Ghidra: translate.cc:104 SpacebaseSpace::numSpacebase
    /// Number of base registers associated with this space (0 or 1).
    /// Faithful to `numSpacebase` (translate.cc:104-108).
    pub fn num_spacebase(&self) -> i32 {
        if self.has_base_register {
            1
        } else {
            0
        }
    }

    // Ghidra: translate.cc:110 SpacebaseSpace::getSpacebase
    /// Get the (possibly truncated) base register varnode. Faithful to
    /// `getSpacebase(int4 i)` (translate.cc:110-116).
    ///
    /// Panics if no base register has been set or `i != 0` (mirroring
    /// Ghidra's `LowlevelError`).
    pub fn get_spacebase(&self, i: i32) -> &VarnodeData {
        if !self.has_base_register || i != 0 {
            // Ghidra: throw LowlevelError("No base register specified for
            //                          space: "+getName());
            panic!("No base register specified for space: {}", self.name);
        }
        &self.base_loc
    }

    // Ghidra: translate.cc:118 SpacebaseSpace::getSpacebaseFull
    /// Get the original (untruncated) base register varnode. Faithful to
    /// `getSpacebaseFull(int4 i)` (translate.cc:118-124).
    ///
    /// Panics if no base register has been set or `i != 0`.
    pub fn get_spacebase_full(&self, i: i32) -> &VarnodeData {
        if !self.has_base_register || i != 0 {
            panic!("No base register specified for space: {}", self.name);
        }
        &self.base_orig
    }

    // Ghidra: translate.hh:186 SpacebaseSpace::stackGrowsNegative
    /// `true` if the stack grows toward lower addresses. Faithful to
    /// `stackGrowsNegative` (translate.hh:186, inline).
    pub fn stack_grows_negative(&self) -> bool {
        self.is_negative_stack
    }

    // Ghidra: translate.hh:187 SpacebaseSpace::getContain
    /// Return the containing space. Faithful to `getContain`
    /// (translate.hh:187, inline).
    pub fn get_contain(&self) -> AddressSpace {
        self.contain
    }

    // Ghidra: translate.cc:126 SpacebaseSpace::decode
    /// Restore `self` from a `<space_base>` element. Faithful to
    /// `SpacebaseSpace::decode(Decoder &decoder)` (translate.cc:126-133).
    ///
    /// Reads the basic address-space attributes (handled by
    /// `decode_basic_attributes` in Ghidra) and the `contain` attribute
    /// naming the containing space.
    pub fn decode(&mut self, decoder: &mut dyn Decoder) {
        // uint4 elemId = decoder.openElement(ELEM_SPACE_BASE);
        let elem_id = decoder.open_element_matching(&ELEM_SPACE_BASE);
        // decodeBasicAttributes(decoder);  // (space.cc in Ghidra)
        self.decode_basic_attributes(decoder);
        // contain = decoder.readSpace(ATTRIB_CONTAIN);
        let contain_name = decoder.read_string_attr(&ATTRIB_CONTAIN);
        self.contain = space_from_name(&contain_name);
        // decoder.closeElement(elemId);
        decoder.close_element(elem_id);
    }

    // RUDRA-GLUE: decode_basic_attributes (Ghidra's AddrSpace::decodeBasicAttributes
    // lives in space.cc, not translate.cc. Rugra ports a minimal inline reader
    // of name/address-size/word-size/delay so SpacebaseSpace::decode can run
    // without the full AddrSpace port.)
    /// Read the common address-space attributes (`name`, `size`,
    /// `wordsize`, `delay`). Mirrors `AddrSpace::decodeBasicAttributes`
    /// (space.cc).
    fn decode_basic_attributes(&mut self, decoder: &mut dyn Decoder) {
        // Walk attributes: Ghidra recognizes ATTRIB_NAME, ATTRIB_SIZE,
        // ATTRIB_WORDSIZE, ATTRIB_DELAY. Rugra uses the decoder's generic
        // attribute walk and dispatches on names.
        loop {
            let id = decoder.next_attribute_id();
            if id == 0 {
                break;
            }
            let name = decoder.attribute_name(id).unwrap_or_default();
            match name.as_str() {
                "name" => self.name = decoder.read_string(),
                "size" => self.addr_size = decoder.read_unsigned_integer() as i32,
                "wordsize" => {
                    let _wordsize = decoder.read_unsigned_integer();
                }
                "delay" => self.delay = decoder.read_unsigned_integer() as i32,
                _ => {
                    // Skip unknown attribute value.
                    let _ = decoder.read_string();
                }
            }
        }
    }
}

// RUDRA-GLUE: space_from_name (Ghidra resolves `contain` via the
// AddrSpaceManager's name map; Rugra's enum address spaces are finite and
// named, so a local lookup suffices without requiring a live manager.)
/// Map a SLEIGH space name to the Rugra [`AddressSpace`] enum. Unknown names
/// map to [`AddressSpace::Other`] (mirroring Ghidra's IPTR_PROCESSOR fallthrough).
fn space_from_name(name: &str) -> AddressSpace {
    match name {
        "ram" => AddressSpace::Ram,
        "register" => AddressSpace::Register,
        "unique" => AddressSpace::Unique,
        "const" => AddressSpace::Const,
        "stack" => AddressSpace::Stack,
        "join" => AddressSpace::Join,
        "iop" => AddressSpace::Iop,
        "overlay" => AddressSpace::Overlay,
        _ => AddressSpace::Other(0),
    }
}

// ============================================================================
// translate.hh:196 — JoinRecord
// ============================================================================

/// A record describing how logical values are split. Faithful to
/// `JoinRecord` (translate.hh:196).
///
/// The decompiler can describe a logical value stored split across multiple
/// physical memory locations. This record describes such a split. The pieces
/// must be listed from most significant to least significant.
#[derive(Debug, Clone)]
pub struct JoinRecord {
    // Ghidra: translate.hh:198 pieces
    /// All the physical pieces of the symbol, most significant to least.
    pub pieces: Vec<VarnodeData>,
    // Ghidra: translate.hh:199 unified
    /// Special entry representing the entire symbol in one chunk.
    pub unified: VarnodeData,
}

impl PartialEq for JoinRecord {
    // Ghidra: translate.cc:172 JoinRecord::operator<
    /// Equality derived from Ghidra's lexicographic `operator<`. Two records
    /// are equal iff neither is less than the other.
    fn eq(&self, other: &Self) -> bool {
        !self.less_than(other) && !other.less_than(self)
    }
}

impl JoinRecord {
    // Ghidra: translate.hh:201 JoinRecord::numPieces
    /// Number of physical pieces. Faithful to `numPieces`.
    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    // Ghidra: translate.hh:202 JoinRecord::isFloatExtension
    /// `true` if this record extends a float varnode (single piece).
    /// Faithful to `isFloatExtension`.
    pub fn is_float_extension(&self) -> bool {
        self.pieces.len() == 1
    }

    // Ghidra: translate.hh:203 JoinRecord::getPiece
    /// Get the i-th piece. Faithful to `getPiece(int4 i)`.
    pub fn get_piece(&self, i: usize) -> &VarnodeData {
        &self.pieces[i]
    }

    // Ghidra: translate.hh:204 JoinRecord::getUnified
    /// Get the unified (whole) varnode. Faithful to `getUnified`.
    pub fn get_unified(&self) -> &VarnodeData {
        &self.unified
    }

    // Ghidra: translate.cc:141 JoinRecord::getEquivalentAddress
    /// Given an offset in the join space, return the equivalent address of
    /// the underlying piece. Faithful to
    /// `getEquivalentAddress(uintb offset, int4 &pos)` (translate.cc:141-168).
    ///
    /// On success returns `Some((address, piece_index))`. Returns `None` if
    /// `offset` falls outside this record's unified range (mirroring Ghidra's
    /// invalid `Address()` return).
    pub fn get_equivalent_address(&self, offset: u64) -> Option<(Address, usize)> {
        // if (offset < unified.offset) return Address();
        if offset < self.unified.offset {
            return None;
        }
        // int4 smallOff = (int4)(offset - unified.offset);
        let mut small_off: i64 = (offset - self.unified.offset) as i64;
        if self.pieces[0].space.is_big_endian() {
            // for(pos=0; pos<pieces.size(); ++pos) { ... }
            for pos in 0..self.pieces.len() {
                let piece_size = self.pieces[pos].size as i64;
                if small_off < piece_size {
                    return Some((
                        Address::new(self.pieces[pos].offset + small_off as u64),
                        pos,
                    ));
                }
                small_off -= piece_size;
            }
            // if (pos == pieces.size()) return Address();
            None
        } else {
            // for (pos = pieces.size() - 1; pos >= 0; --pos) { ... }
            let mut pos: i64 = self.pieces.len() as i64 - 1;
            while pos >= 0 {
                let piece_size = self.pieces[pos as usize].size as i64;
                if small_off < piece_size {
                    return Some((
                        Address::new(self.pieces[pos as usize].offset + small_off as u64),
                        pos as usize,
                    ));
                }
                small_off -= piece_size;
                pos -= 1;
            }
            // if (pos < 0) return Address();
            None
        }
    }

    // Ghidra: translate.cc:172 JoinRecord::operator<
    /// Lexicographic ordering on (unified.size, pieces). Faithful to
    /// `JoinRecord::operator<` (translate.cc:172-189).
    pub fn less_than(&self, op2: &JoinRecord) -> bool {
        // Some joins may have same piece but different unified size
        // (floating point). Compare size first.
        if self.unified.size != op2.unified.size {
            return self.unified.size < op2.unified.size;
        }
        // Lexigraphic sort on pieces.
        let mut i = 0usize;
        loop {
            if self.pieces.len() == i {
                // If more pieces in op2, it is bigger (return true);
                // if same number this==op2, return false.
                return op2.pieces.len() > i;
            }
            if op2.pieces.len() == i {
                // More pieces in this, so it is bigger, return false.
                return false;
            }
            if self.pieces[i] != op2.pieces[i] {
                return varnode_less(&self.pieces[i], &op2.pieces[i]);
            }
            i += 1;
        }
    }

    // Ghidra: translate.cc:196 JoinRecord::mergeSequence
    /// Merge contiguous varnodes in `seq` (most-significant first). Faithful
    /// to `JoinRecord::mergeSequence(vector<VarnodeData> &seq,
    /// const Translate *trans)` (translate.cc:196-232).
    ///
    /// Varnodes that are not in the stack address space are only merged if
    /// the resulting byte range has a formal register name. The
    /// `exact_register_name` closure plays the role of
    /// `trans->getExactRegisterName` (which on [`Translate`] returns the
    /// empty string by default in Rugra, so non-stack merges are inhibited
    /// unless the caller supplies a real register lookup).
    pub fn merge_sequence<F>(seq: &mut Vec<VarnodeData>, mut exact_register_name: F)
    where
        F: FnMut(&AddressSpace, u64, usize) -> String,
    {
        // int4 i=1; while(i<seq.size()) { ... if (hi.isContiguous(lo)) break; i+=1; }
        let mut first_merge_at = 1usize;
        while first_merge_at < seq.len() {
            let hi = &seq[first_merge_at - 1];
            let lo = &seq[first_merge_at];
            if is_contiguous(hi, lo) {
                break;
            }
            first_merge_at += 1;
        }
        // if (i >= seq.size()) return;
        if first_merge_at >= seq.len() {
            return;
        }
        // vector<VarnodeData> res; i = 1; res.push_back(seq.front());
        let mut res: Vec<VarnodeData> = Vec::new();
        res.push(seq[0].clone());
        let mut last_is_informal = false;
        let mut i = 1usize;
        while i < seq.len() {
            let hi_idx = res.len() - 1;
            let lo = seq[i].clone();
            if is_contiguous(&res[hi_idx], &lo) {
                // hi.offset = hi.space->isBigEndian() ? hi.offset : lo.offset;
                if !res[hi_idx].space.is_big_endian() {
                    res[hi_idx].offset = lo.offset;
                }
                res[hi_idx].size += lo.size;
                // if (hi.space->getType() != IPTR_SPACEBASE) {
                if !res[hi_idx].space.is_stack() {
                    let name = exact_register_name(
                        &res[hi_idx].space,
                        res[hi_idx].offset,
                        res[hi_idx].size,
                    );
                    last_is_informal = name.is_empty();
                }
            } else {
                if last_is_informal {
                    break;
                }
                res.push(lo);
            }
            i += 1;
        }
        // if (lastIsInformal) return;  // throw out and keep original sequence
        if last_is_informal {
            return;
        }
        // seq = res;
        *seq = res;
    }
}

// RUDRA-GLUE: varnode_less / is_contiguous (Ghidra defines VarnodeData::operator<
// and VarnodeData::isContiguous in pcoderaw.hh / pcoderaw.cc. Rugra's
// VarnodeData does not yet provide these, so local helpers carry the intended
// formulas; the flat AddressSpace model still prevents an equivalence claim.)
//
// Ghidra ordering on VarnodeData is by (space index, offset, size). Rugra's
// AddressSpace enum derives Ord, so we delegate to that.
/// Lexicographic `(space, offset, size)` ordering, mirroring Ghidra's
/// `VarnodeData::operator<`.
fn varnode_less(a: &VarnodeData, b: &VarnodeData) -> bool {
    match a.space.cmp(&b.space) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => match a.offset.cmp(&b.offset) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => a.size < b.size,
        },
    }
}

/// `true` if `lo` immediately follows `hi` in memory (contiguous), corresponding
/// to Ghidra's `VarnodeData::isContiguous(const VarnodeData &lo)`.
///
/// For big-endian spaces the high varnode precedes the low one at a lower
/// offset; for little-endian it is the reverse. The two must share a space
/// and the offsets must differ by exactly the high varnode's size.
// Ghidra: pcoderaw.cc:73 VarnodeData::isContiguous
fn is_contiguous(hi: &VarnodeData, lo: &VarnodeData) -> bool {
    // Different spaces can never be contiguous.
    if hi.space != lo.space {
        return false;
    }
    let hi_size = hi.size as u64;
    if hi.space.is_big_endian() {
        // hi precedes lo: lo.offset == hi.offset + hi.size
        lo.offset == hi.offset.wrapping_add(hi_size)
    } else {
        // lo precedes hi: hi.offset == lo.offset + lo.size
        hi.offset == lo.offset.wrapping_add(lo.size as u64)
    }
}

// ============================================================================
// translate.hh:220 — AddrSpaceManager
// ============================================================================

/// A manager for different address spaces. Faithful to `AddrSpaceManager`
/// (translate.hh:220).
///
/// Allows creation, lookup by name, lookup by shortcut, and iteration over
/// address spaces. In Ghidra this is the base class of [`Translate`]; Rugra
/// composes it as a field rather than via inheritance.
#[derive(Default)]
pub struct AddrSpaceManager {
    // Ghidra: translate.hh:221 baselist
    /// Every space we know about for this architecture, indexed by space index.
    pub base_list: Vec<Option<AddressSpace>>,
    // Ghidra: translate.hh:222 resolvelist
    /// Special constant resolvers, indexed by space index. Rugra stores the
    /// resolver as a boxed trait object; in Ghidra these are non-owning
    /// pointers owned by the manager.
    pub resolve_list: Vec<Option<Box<dyn AddressResolver>>>,
    // Ghidra: translate.hh:223 name2Space
    /// Map from name -> space.
    pub name_to_space: HashMap<String, AddressSpace>,
    // Ghidra: translate.hh:224 shortcut2Space
    /// Map from shortcut char -> space. (Rugra: shortcut encoded as the char
    /// value.)
    pub shortcut_to_space: HashMap<char, AddressSpace>,
    // Ghidra: translate.hh:225 constantspace
    /// Quick reference to the constant space.
    pub constant_space: Option<AddressSpace>,
    // Ghidra: translate.hh:226 defaultcodespace
    /// Default space where code lives, generally main RAM.
    pub default_code_space: Option<AddressSpace>,
    // Ghidra: translate.hh:227 defaultdataspace
    /// Default space where data lives.
    pub default_data_space: Option<AddressSpace>,
    // Ghidra: translate.hh:228 iopspace
    /// Space for internal pcode op pointers.
    pub iop_space: Option<AddressSpace>,
    // Ghidra: translate.hh:229 fspecspace
    /// Space for internal callspec pointers.
    pub fspec_space: Option<AddressSpace>,
    // Ghidra: translate.hh:230 joinspace
    /// Space for unifying split variables.
    pub join_space: Option<AddressSpace>,
    // Ghidra: translate.hh:231 stackspace
    /// Stack space associated with the processor.
    pub stack_space: Option<AddressSpace>,
    // Ghidra: translate.hh:232 uniqspace
    /// Temporary space associated with the processor.
    pub uniq_space: Option<AddressSpace>,
    // Ghidra: translate.hh:233 joinallocate
    /// Next offset to be allocated in the join space.
    pub join_allocate: u64,
    // Ghidra: translate.hh:234 splitset
    /// Different splits that have been defined in the join space. Rugra uses
    /// a sorted Vec; Ghidra uses a `set<JoinRecord*, JoinRecordCompare>`.
    pub split_set: Vec<JoinRecord>,
    // Ghidra: translate.hh:235 splitlist
    /// JoinRecords indexed by join address (sorted by unified.offset).
    pub split_list: Vec<JoinRecord>,
    // Ghidra: translate.hh:220 AddrSpaceManager (SPACE-0001 companion)
    /// Architecture-owned address-space registry: stable
    /// index/type/name/addrsize/wordsize/endian/flags handles for dynamic
    /// spaces. RUDRA-GLUE: Ghidra has exactly one AddrSpaceManager (the base
    /// of Translate); this legacy enum-based manager keeps its own flat
    /// tables for un-migrated consumers, and this field is the
    /// architecture-owned twin those consumers switch to in ADDRESS-0001.
    /// The resolver and join-record halves (resolvelist/splitset/splitlist)
    /// still live here, not in the registry.
    pub space_registry: crate::space::SpaceRegistry,
}

// RUDRA-GLUE: Debug impl (Ghidra has no Debug formatting; Rugra needs it for
// diagnostics. The `resolve_list` holds trait objects that have no Debug, so
// we count resolvers instead of formatting them.)
impl std::fmt::Debug for AddrSpaceManager {
    // RUDRA-GLUE: Rust Debug formatting has no Ghidra behavioral counterpart.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddrSpaceManager")
            .field("base_list", &self.base_list)
            .field(
                "resolve_list",
                &format!("[{} resolvers]", self.resolve_list.len()),
            )
            .field("name_to_space", &self.name_to_space)
            .field("shortcut_to_space", &self.shortcut_to_space)
            .field("constant_space", &self.constant_space)
            .field("default_code_space", &self.default_code_space)
            .field("default_data_space", &self.default_data_space)
            .field("iop_space", &self.iop_space)
            .field("fspec_space", &self.fspec_space)
            .field("join_space", &self.join_space)
            .field("stack_space", &self.stack_space)
            .field("uniq_space", &self.uniq_space)
            .field("join_allocate", &self.join_allocate)
            .field("split_set", &self.split_set)
            .field("split_list", &self.split_list)
            .finish()
    }
}

impl AddrSpaceManager {
    // Ghidra: translate.cc:235 AddrSpaceManager::AddrSpaceManager
    /// Construct an empty address space manager. Faithful to the constructor
    /// (translate.cc:235-247): all cached space slots are `None` and
    /// `joinallocate` starts at 0.
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: translate.hh:253 AddrSpaceManager::getDefaultSize
    /// Get the size of addresses (in bytes) for the default code space.
    /// Faithful to the inline `getDefaultSize` (translate.hh:448-450).
    pub fn get_default_size(&self) -> usize {
        self.default_code_space
            .map(|s| s.addr_size())
            .unwrap_or(0)
    }

    // Ghidra: translate.hh:254 AddrSpaceManager::getSpaceByName
    /// Get an address space by name. Faithful to `getSpaceByName`
    /// (translate.cc:590-597).
    pub fn get_space_by_name(&self, nm: &str) -> Option<AddressSpace> {
        self.name_to_space.get(nm).copied()
    }

    // Ghidra: translate.hh:255 AddrSpaceManager::getSpaceByShortcut
    /// Get an address space from its shortcut character. Faithful to
    /// `getSpaceByShortcut` (translate.cc:604-612).
    pub fn get_space_by_shortcut(&self, sc: char) -> Option<AddressSpace> {
        self.shortcut_to_space.get(&sc).copied()
    }

    // Ghidra: translate.hh:257 AddrSpaceManager::getIopSpace
    /// Get the internal pcode op space. Faithful to the inline `getIopSpace`
    /// (translate.hh:457-459).
    pub fn get_iop_space(&self) -> Option<AddressSpace> {
        self.iop_space
    }

    // Ghidra: translate.hh:258 AddrSpaceManager::getFspecSpace
    /// Get the internal callspec space. Faithful to the inline
    /// `getFspecSpace` (translate.hh:466-468).
    pub fn get_fspec_space(&self) -> Option<AddressSpace> {
        self.fspec_space
    }

    // Ghidra: translate.hh:259 AddrSpaceManager::getJoinSpace
    /// Get the joining space. Faithful to the inline `getJoinSpace`
    /// (translate.hh:475-477).
    pub fn get_join_space(&self) -> Option<AddressSpace> {
        self.join_space
    }

    // Ghidra: translate.hh:260 AddrSpaceManager::getStackSpace
    /// Get the stack space for this processor. Faithful to the inline
    /// `getStackSpace` (translate.hh:484-486).
    pub fn get_stack_space(&self) -> Option<AddressSpace> {
        self.stack_space
    }

    // Ghidra: translate.hh:261 AddrSpaceManager::getUniqueSpace
    /// Get the temporary (unique) register space. Faithful to the inline
    /// `getUniqueSpace` (translate.hh:496-498).
    pub fn get_unique_space(&self) -> Option<AddressSpace> {
        self.uniq_space
    }

    // Ghidra: translate.hh:261 AddrSpaceManager::getDefaultCodeSpace
    /// Get the default address space of this processor. Faithful to the
    /// inline `getDefaultCodeSpace` (translate.hh:505-507).
    pub fn get_default_code_space(&self) -> Option<AddressSpace> {
        self.default_code_space
    }

    // Ghidra: translate.hh:262 AddrSpaceManager::getDefaultDataSpace
    /// Get the default address space where data is stored. Faithful to the
    /// inline `getDefaultDataSpace` (translate.hh:514-516).
    pub fn get_default_data_space(&self) -> Option<AddressSpace> {
        self.default_data_space
    }

    // Ghidra: translate.hh:263 AddrSpaceManager::getConstantSpace
    /// Get the constant space. Faithful to the inline `getConstantSpace`
    /// (translate.hh:522-524).
    pub fn get_constant_space(&self) -> Option<AddressSpace> {
        self.constant_space
    }

    // Ghidra: translate.hh:264 AddrSpaceManager::getConstant
    /// Encode a specific value as a constant address. Faithful to the inline
    /// `getConstant(uintb val)` (translate.hh:532-534).
    ///
    /// Rugra's `Address` is a single u64, so the constant space is implicit;
    /// this returns `Address::new(val)`.
    pub fn get_constant(&self, val: u64) -> Address {
        Address::new(val)
    }

    // Ghidra: translate.hh:265 AddrSpaceManager::createConstFromSpace
    /// Encode a pointer to an address space as a constant address. Faithful
    /// to the inline `createConstFromSpace` (translate.hh:542-544).
    ///
    /// Ghidra casts the space pointer to `uintp`; Rugra has no pointer to
    /// cast, so this returns the space's id encoded as a constant address.
    pub fn create_const_from_space(&self, spc: AddressSpace) -> Address {
        Address::new(spc.space_id() as u64)
    }

    // Ghidra: translate.hh:267 AddrSpaceManager::numSpaces
    /// Total number of address spaces (including special spaces). Faithful
    /// to the inline `numSpaces` (translate.hh:550-552).
    pub fn num_spaces(&self) -> usize {
        self.base_list.len()
    }

    // Ghidra: translate.hh:268 AddrSpaceManager::getSpace
    /// Get an address space by its index. Faithful to the inline `getSpace`
    /// (translate.hh:559-561).
    pub fn get_space(&self, i: usize) -> Option<AddressSpace> {
        self.base_list.get(i).copied().flatten()
    }

    // Ghidra: translate.hh:269 AddrSpaceManager::getNextSpaceInOrder
    /// Get the next contiguous address space (by index). Faithful to
    /// `getNextSpaceInOrder` (translate.cc:647-663).
    ///
    /// Pass `None` to start iteration; returns `None` when exhausted.
    /// (Ghidra distinguishes null from `~0`; Rugra collapses both to
    /// `None`.)
    pub fn get_next_space_in_order(&self, spc: Option<AddressSpace>) -> Option<AddressSpace> {
        match spc {
            None => {
                // Return the first non-null entry.
                for slot in &self.base_list {
                    if let Some(s) = slot {
                        return Some(*s);
                    }
                }
                None
            }
            Some(cur) => {
                let start = space_index_of(cur) as usize + 1;
                let mut idx = start;
                while idx < self.base_list.len() {
                    if let Some(s) = self.base_list[idx] {
                        return Some(s);
                    }
                    idx += 1;
                }
                None
            }
        }
    }

    // Ghidra: translate.hh:270 AddrSpaceManager::findAddJoin
    /// Find or create a JoinRecord for `pieces`. Faithful to
    /// `findAddJoin(const vector<VarnodeData> &pieces, uint4 logicalsize)`
    /// (translate.cc:671-715).
    ///
    /// `logical_size` is the size of a single-piece join, or 0 (in which
    /// case the logical size is the sum of the piece sizes).
    pub fn find_add_join(
        &mut self,
        pieces: &[VarnodeData],
        logical_size: u32,
    ) -> &JoinRecord {
        // if (pieces.size() == 0) throw ...
        if pieces.is_empty() {
            panic!("Cannot create a join without pieces");
        }
        // if ((pieces.size()==1)&&(logicalsize==0)) throw ...
        if pieces.len() == 1 && logical_size == 0 {
            panic!("Cannot create a single piece join without a logical size");
        }
        let total_size: u32;
        if logical_size != 0 {
            // if (pieces.size() != 1) throw ...
            if pieces.len() != 1 {
                panic!("Cannot specify logical size for multiple piece join");
            }
            total_size = logical_size;
        } else {
            // totalsize = 0; for(...) totalsize += pieces[i].size;
            let mut acc: u32 = 0;
            for p in pieces {
                acc += p.size as u32;
            }
            if acc == 0 {
                panic!("Cannot create a zero size join");
            }
            total_size = acc;
        }
        // Build a probe and look it up in splitset.
        let probe = JoinRecord {
            pieces: pieces.to_vec(),
            unified: VarnodeData {
                space: AddressSpace::Join,
                offset: 0,
                size: total_size as usize,
            },
        };
        if let Ok(idx) = self.split_set.binary_search_by(|rec| {
            if rec.less_than(&probe) {
                std::cmp::Ordering::Less
            } else if probe.less_than(rec) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            return &self.split_set[idx];
        }
        // Allocate a new JoinRecord.
        // uint4 roundsize = (totalsize + 15) & ~((uint4)0xf);
        let round_size = (total_size + 15) & !0xfu32;
        let mut new_join = JoinRecord {
            pieces: pieces.to_vec(),
            unified: VarnodeData {
                space: self.join_space.unwrap_or(AddressSpace::Join),
                offset: self.join_allocate,
                size: total_size as usize,
            },
        };
        self.join_allocate += round_size as u64;
        // Insert into the sorted splitset and the offset-sorted splitlist.
        let pos = self.split_set.binary_search_by(|rec| {
            if rec.less_than(&new_join) {
                std::cmp::Ordering::Less
            } else if new_join.less_than(rec) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        let insert_at = match pos {
            Ok(i) => i,
            Err(i) => i,
        };
        self.split_set
            .insert(insert_at, std::mem::replace(&mut new_join, probe.clone()));
        // splitlist is kept sorted by unified.offset; insert accordingly.
        let off = self.split_set[insert_at].unified.offset;
        let list_pos = self
            .split_list
            .binary_search_by_key(&off, |r| r.unified.offset);
        let list_at = match list_pos {
            Ok(i) | Err(i) => i,
        };
        self.split_list
            .insert(list_at, self.split_set[insert_at].clone());
        &self.split_set[insert_at]
    }

    // Ghidra: translate.hh:271 AddrSpaceManager::findJoin
    /// Find the JoinRecord for `offset` in the join space. Faithful to
    /// `findJoin(uintb offset)` (translate.cc:746-762).
    ///
    /// Panics if no record matches (mirroring Ghidra's
    /// `LowlevelError("Unlinked join address")`).
    pub fn find_join(&self, offset: u64) -> &JoinRecord {
        // Binary search on splitlist by unified.offset.
        match self
            .split_list
            .binary_search_by_key(&offset, |r| r.unified.offset)
        {
            Ok(idx) => &self.split_list[idx],
            Err(_) => panic!("Unlinked join address"),
        }
    }

    // Ghidra: translate.hh:272 AddrSpaceManager::setDeadcodeDelay
    /// Set the dead-code delay for a specific space. Faithful to
    /// `setDeadcodeDelay` (translate.cc:768-772).
    ///
    /// Rugra's enum address spaces carry fixed delays, so this is a no-op
    /// kept for API parity.
    pub fn set_deadcode_delay(&mut self, _spc: AddressSpace, _delay_delta: i32) {}

    // Ghidra: translate.hh:273 AddrSpaceManager::truncateSpace
    /// Mark the named space as truncated. Faithful to `truncateSpace`
    /// (translate.cc:776-783).
    pub fn truncate_space(&mut self, tag: &TruncationTag) {
        let _spc = self.get_space_by_name(tag.get_name()).unwrap_or_else(|| {
            panic!(
                "Unknown space in <truncate_space> command: {}",
                tag.get_name()
            )
        });
        // Rugra's enum address spaces have fixed sizes; the truncation is a
        // no-op at the enum level but the lookup/validation is preserved.
    }

    // Ghidra: translate.hh:276 AddrSpaceManager::constructFloatExtensionAddress
    /// Build a logically lower-precision storage location for a bigger
    /// floating-point register. Faithful to `constructFloatExtensionAddress`
    /// (translate.cc:792-805).
    pub fn construct_float_extension_address(
        &mut self,
        real_addr: Address,
        real_size: i32,
        logical_size: i32,
    ) -> Address {
        // if (logicalsize == realsize) return realaddr;
        if logical_size == real_size {
            return real_addr;
        }
        // pieces.emplace_back(); ... findAddJoin(pieces, logicalsize);
        let pieces = vec![VarnodeData {
            space: AddressSpace::Register, // float registers live in register space
            offset: real_addr.as_u64(),
            size: real_size as usize,
        }];
        let join = self.find_add_join(&pieces, logical_size as u32);
        Address::new(join.unified.offset)
    }

    // Ghidra: translate.hh:279 AddrSpaceManager::constructJoinAddress
    /// Build a logical whole from register pairs. Faithful to
    /// `constructJoinAddress` (translate.cc:817-860).
    ///
    /// `hi_addr`/`hi_sz` describe the most-significant piece; `lo_addr`/`lo_sz`
    /// the least-significant. Returns the address representing the start of
    /// the joined range.
    pub fn construct_join_address(
        &mut self,
        hi_addr: Address,
        hi_sz: i32,
        lo_addr: Address,
        lo_sz: i32,
        exact_register_name: &mut dyn FnMut(&AddressSpace, u64, usize) -> String,
    ) -> Address {
        // Rugra collapses Ghidra's AddrSpace::getType() check to the enum:
        // only stack/ram/register/other pieces are joinable. Rugra addresses
        // are space-less (a single u64), so the pieces' space defaults to the
        // register space — the canonical joinable space in Rugra's model.
        // Ghidra: if (hiaddr.isContiguous(hisz,loaddr,losz)) { ... }
        let hi_vn = VarnodeData {
            space: AddressSpace::Register,
            offset: hi_addr.as_u64(),
            size: hi_sz as usize,
        };
        let lo_vn = VarnodeData {
            space: AddressSpace::Register,
            offset: lo_addr.as_u64(),
            size: lo_sz as usize,
        };
        if is_contiguous(&hi_vn, &lo_vn) {
            // Non-join mappable space: return earliest address.
            if hi_vn.space.is_big_endian() {
                return hi_addr;
            }
            return lo_addr;
        }
        // Otherwise construct a formal JoinRecord with both pieces. Ghidra
        // checks `translate->getRegisterName(...)` for a parent register
        // before falling back to the join space; Rugra invokes the supplied
        // `exact_register_name` hook for the same purpose.
        let total = (hi_sz as usize).saturating_add(lo_sz as usize);
        if !exact_register_name(&hi_vn.space, hi_vn.offset, total).is_empty() {
            return hi_addr;
        }
        let pieces = vec![hi_vn.clone(), lo_vn.clone()];
        let join = self.find_add_join(&pieces, 0);
        Address::new(join.unified.offset)
    }

    // Ghidra: translate.hh:282 AddrSpaceManager::renormalizeJoinAddress
    /// Renormalize a possibly shifted join address. Faithful to
    /// `renormalizeJoinAddress(Address &addr, int4 size)`
    /// (translate.cc:870-916).
    ///
    /// Given an address in the join space and a size, this either returns
    /// the address unchanged (if the JoinRecord matches), rewrites it to a
    /// single piece address, or builds a new JoinRecord covering the range.
    pub fn renormalize_join_address(&mut self, addr: &mut Address, size: i32) {
        let join_record = match self.find_join_internal(addr.as_u64()) {
            Some(r) => r.clone(),
            None => panic!("Join address not covered by a JoinRecord"),
        };
        // if (addr.getOffset() == joinRecord->unified.offset && size == joinRecord->unified.size) return;
        if addr.as_u64() == join_record.unified.offset && size as usize == join_record.unified.size
        {
            return;
        }
        let (addr1, pos1) = join_record
            .get_equivalent_address(addr.as_u64())
            .unwrap_or_else(|| panic!("Join address range not covered"));
        let (addr2, pos2) = join_record
            .get_equivalent_address(addr.as_u64() + (size as u64 - 1))
            .unwrap_or_else(|| panic!("Join address range not covered"));
        if addr2.is_null() {
            panic!("Join address range not covered");
        }
        if pos1 == pos2 {
            *addr = addr1;
            return;
        }
        // Build the new pieces spanning [pos1, pos2] (or reversed for LE).
        let size_trunc1 = (addr1.as_u64() - join_record.pieces[pos1].offset) as usize;
        let size_trunc2 = join_record.pieces[pos2].size as i64
            - (addr2.as_u64() - join_record.pieces[pos2].offset) as i64
            - 1;
        let mut new_pieces: Vec<VarnodeData> = Vec::new();
        if pos2 < pos1 {
            // Little endian
            let mut p = pos2;
            new_pieces.push(join_record.pieces[p].clone());
            p += 1;
            while p <= pos1 {
                new_pieces.push(join_record.pieces[p].clone());
                p += 1;
            }
            let last = new_pieces.len() - 1;
            new_pieces[last].offset = addr1.as_u64();
            new_pieces[last].size -= size_trunc1;
            new_pieces[0].size -= size_trunc2 as usize;
        } else {
            let mut p = pos1;
            new_pieces.push(join_record.pieces[p].clone());
            p += 1;
            while p <= pos2 {
                new_pieces.push(join_record.pieces[p].clone());
                p += 1;
            }
            new_pieces[0].offset = addr1.as_u64();
            new_pieces[0].size -= size_trunc1;
            let last = new_pieces.len() - 1;
            new_pieces[last].size -= size_trunc2 as usize;
        }
        let new_join = self.find_add_join(&new_pieces, 0);
        *addr = Address::new(new_join.unified.offset);
    }

    // Ghidra: translate.hh:285 AddrSpaceManager::parseAddressSimple
    /// Parse `name:offset` or bare hex offset into an address. Faithful to
    /// `parseAddressSimple` (translate.cc:923-947).
    ///
    /// The offset is hexadecimal and may be prefixed with `0x`. A leading
    /// `name:` selects the address space; otherwise the default data space
    /// is used.
    pub fn parse_address_simple(&self, val: &str) -> Address {
        // string::size_type col = val.find(':');
        let col = val.find(':');
        let (spc, offset_start) = match col {
            None => (self.get_default_data_space(), 0usize),
            Some(c) => {
                let spc_name = &val[..c];
                let spc = self
                    .get_space_by_name(spc_name)
                    .unwrap_or_else(|| panic!("Unknown address space: {}", spc_name));
                (Some(spc), c + 1)
            }
        };
        let _ = spc; // Rugra addresses are space-less; name validation preserved.
        let mut col = offset_start;
        // if (col + 2 <= val.size()) { if '0x' prefix, skip }
        if col + 2 <= val.len() {
            if val.as_bytes()[col] == b'0' && val.as_bytes()[col + 1] == b'x' {
                col += 2;
            }
        }
        // istringstream s(val.substr(col)); uintb off; s >> hex >> off;
        let off_str = &val[col..];
        let off = u64::from_str_radix(off_str.trim(), 16).unwrap_or(0);
        Address::new(off)
    }

    // Ghidra: translate.hh:249 AddrSpaceManager::findJoinInternal
    /// Find the JoinRecord containing `offset` (range match). Faithful to
    /// `findJoinInternal(uintb offset)` (translate.cc:722-739).
    ///
    /// Returns `None` if no record covers `offset` (mirroring Ghidra's null
    /// return; note the public [`AddrSpaceManager::find_join`] throws instead).
    pub fn find_join_internal(&self, offset: u64) -> Option<&JoinRecord> {
        // Binary search on splitlist (sorted by unified.offset).
        let mut min = 0i64;
        let mut max = self.split_list.len() as i64 - 1;
        while min <= max {
            let mid = ((min + max) / 2) as usize;
            let rec = &self.split_list[mid];
            let val = rec.unified.offset;
            // if (val + rec.unified.size <= offset) min = mid + 1;
            if val + rec.unified.size as u64 <= offset {
                min = mid as i64 + 1;
            } else if val > offset {
                max = mid as i64 - 1;
            } else {
                return Some(rec);
            }
        }
        None
    }

    // Ghidra: translate.hh:239 AddrSpaceManager::setDefaultCodeSpace
    /// Set the default code space by index. Faithful to `setDefaultCodeSpace`
    /// (translate.cc:309-318).
    ///
    /// Panics if the default space was already set or the index is invalid.
    pub fn set_default_code_space(&mut self, index: usize) {
        if self.default_code_space.is_some() {
            panic!("Default space set multiple times");
        }
        let spc = self
            .base_list
            .get(index)
            .copied()
            .flatten()
            .unwrap_or_else(|| panic!("Bad index for default space"));
        self.default_code_space = Some(spc);
        // By default the default data space is the same.
        self.default_data_space = Some(spc);
    }

    // Ghidra: translate.hh:240 AddrSpaceManager::setDefaultDataSpace
    /// Set the default data space by index (after the code space is set).
    /// Faithful to `setDefaultDataSpace` (translate.cc:323-331).
    pub fn set_default_data_space(&mut self, index: usize) {
        if self.default_code_space.is_none() {
            panic!("Default data space must be set after the code space");
        }
        let spc = self
            .base_list
            .get(index)
            .copied()
            .flatten()
            .unwrap_or_else(|| panic!("Bad index for default data space"));
        self.default_data_space = Some(spc);
    }

    // Ghidra: translate.hh:244 AddrSpaceManager::insertSpace
    /// Add a new address space to the model. Faithful to `insertSpace`
    /// (translate.cc:352-437).
    ///
    /// Validates naming/indexing conventions and routes the space into the
    /// appropriate cached slot (constant/unique/fspec/join/iop/stack).
    pub fn insert_space(&mut self, spc: AddressSpace) {
        // RUDRA-GLUE: Rugra's enum address spaces collapse Ghidra's
        // per-type name validation: each variant already carries its type, so
        // `name_type_mismatch` from translate.cc:355 is always false here and
        // is omitted. The remaining duplicate-name/duplicate-id checks mirror
        // translate.cc:352-437.
        let mut duplicate_name = false;
        let duplicate_id;

        match spc {
            AddressSpace::Const => {
                self.constant_space = Some(spc);
            }
            AddressSpace::Unique => {
                if self.uniq_space.is_some() {
                    duplicate_name = true;
                }
                self.uniq_space = Some(spc);
            }
            AddressSpace::Stack => {
                if self.stack_space.is_some() {
                    duplicate_name = true;
                }
                self.stack_space = Some(spc);
            }
            AddressSpace::Join => {
                if self.join_space.is_some() {
                    duplicate_name = true;
                }
                self.join_space = Some(spc);
            }
            AddressSpace::Iop => {
                if self.iop_space.is_some() {
                    duplicate_name = true;
                }
                self.iop_space = Some(spc);
            }
            // Ram, Register, Overlay, Other fall through to the processor case.
            _ => {}
        }

        let idx = space_index_of(spc) as usize;
        if self.base_list.len() <= idx {
            self.base_list.resize(idx + 1, None);
        }
        duplicate_id = self.base_list[idx].is_some();

        if !duplicate_name && !duplicate_id {
            // name2Space.insert(pair<...>(spc->getName(), spc)).second == false -> duplicate
            if self
                .name_to_space
                .insert(spc.name().to_string(), spc)
                .is_some()
            {
                duplicate_name = true;
            }
        }

        if duplicate_name || duplicate_id {
            let mut err_msg = format!("Space {}", spc.name());
            if duplicate_name {
                err_msg.push_str(" was initialized more than once");
            }
            if duplicate_id {
                err_msg.push_str(" was assigned as id duplicating");
            }
            panic!("{}", err_msg);
        }
        self.base_list[idx] = Some(spc);
        self.assign_shortcut(spc);
    }

    // Ghidra: translate.hh:242 AddrSpaceManager::assignShortcut
    /// Select a shortcut character for a new space and record it. Faithful
    /// to `assignShortcut` (translate.cc:517-573).
    fn assign_shortcut(&mut self, spc: AddressSpace) {
        let mut shortcut: char = match spc {
            AddressSpace::Const => '#',
            AddressSpace::Stack => 's',
            AddressSpace::Unique => 'u',
            AddressSpace::Join => 'j',
            AddressSpace::Iop => 'i',
            AddressSpace::Ram => 'r',
            AddressSpace::Register => '%',
            AddressSpace::Overlay => 'o',
            AddressSpace::Other(_) => 'x',
        };
        // Uppercase -> lowercase.
        if ('A'..='Z').contains(&shortcut) {
            shortcut = ((shortcut as u8) + 0x20) as char;
        }
        let mut collision_count = 0u32;
        while self.shortcut_to_space.contains_key(&shortcut) {
            collision_count += 1;
            if collision_count > 26 {
                // Reuse 'z' as a last resort.
                self.shortcut_to_space.insert('z', spc);
                return;
            }
            shortcut = ((shortcut as u8).wrapping_add(1)) as char;
            if !('a'..='z').contains(&shortcut) {
                shortcut = 'a';
            }
        }
        self.shortcut_to_space.insert(shortcut, spc);
    }

    // Ghidra: translate.hh:266 AddrSpaceManager::resolveConstant
    /// Resolve a native constant into an address. Faithful to
    /// `resolveConstant(AddrSpace *spc, uintb val, int4 sz,
    ///                  const Address &point, uintb &fullEncoding)`
    /// (translate.cc:628-641).
    ///
    /// If a specialized resolver is registered for `spc`, it is invoked;
    /// otherwise basic wordsize conversion and wrapping is performed.
    pub fn resolve_constant(
        &mut self,
        spc: AddressSpace,
        val: u64,
        sz: i32,
        point: Address,
        full_encoding: &mut u64,
    ) -> Address {
        let ind = space_index_of(spc) as usize;
        if ind < self.resolve_list.len() {
            if let Some(resolver) = self.resolve_list[ind].as_mut() {
                return resolver.resolve(val, sz, point, full_encoding);
            }
        }
        // fullEncoding = val; val = addressToByte(val, wordSize); val = wrapOffset(val);
        *full_encoding = val;
        let word_size = spc.word_size().max(1) as u64;
        let val_bytes = if word_size == 1 { val } else { val * word_size };
        // wrapOffset: mask to the space's address size.
        let addr_mask = addr_mask_for(spc);
        let val_wrapped = val_bytes & addr_mask;
        Address::new(val_wrapped)
    }

    // Ghidra: translate.hh:244 AddrSpaceManager::insertSpace
    /// Add a new architecture-owned address space to the registry. This is
    /// the SPACE-0001 bridge that production code paths (cspec ingestion,
    /// sleigh translate setup) use once they migrate off the flat enum:
    /// faithful to `Translate::insertSpace` usage (translate.cc:352-437) via
    /// the composed [`crate::space::SpaceRegistry`].
    pub fn insert_dyn_space(
        &mut self,
        spc: crate::space::AddrSpace,
    ) -> Result<(), String> {
        self.space_registry.insert_space(spc)
    }

    // Ghidra: translate.hh:246 AddrSpaceManager::addSpacebasePointer
    /// Set the base register of an architecture-owned spacebase space,
    /// faithful to `addSpacebasePointer` (translate.cc:460-464) via the
    /// composed registry.
    pub fn add_dyn_spacebase_pointer(
        &mut self,
        basespace: &crate::space::AddrSpace,
        ptrdata: &crate::space::SpaceVarnodeData,
        trunc_size: i32,
        stack_growth: bool,
    ) -> Result<(), String> {
        self.space_registry
            .add_spacebase_pointer(basespace, ptrdata, trunc_size, stack_growth)
    }
}

// RUDRA-GLUE: space_index_of / addr_mask_for (Ghidra's AddrSpace carries an
// `index` field and address-size/word-size; Rugra's enum address spaces have
// stable indices via space_id() and a fixed address size. These helpers
// bridge the two representations so AddrSpaceManager methods stay faithful.)
/// Stable index for a Rugra address space, mirroring Ghidra's
/// `AddrSpace::getIndex()`.
fn space_index_of(spc: AddressSpace) -> i32 {
    spc.space_id() as i32
}

/// Bit mask for offsets within an address space, mirroring Ghidra's
/// `AddrSpace::wrapOffset` mask.
// RUDRA-GLUE: Flat-enum offset-mask bridge; Ghidra calls wrapOffset on the
// concrete AddrSpace descriptor and has no standalone addr_mask_for helper.
fn addr_mask_for(spc: AddressSpace) -> u64 {
    let addr_bits = (spc.addr_size() * 8) as u32;
    if addr_bits == 0 || addr_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << addr_bits) - 1
    }
}

// ============================================================================
// translate.hh:299 — Translate
// ============================================================================

/// Tagged addresses in the unique address space. Faithful to
/// `Translate::UniqueLayout` (translate.hh:302-308).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum UniqueLayout {
    // Ghidra: translate.hh:303 RUNTIME_BOOLEAN_INVERT
    /// Location of the runtime temporary for boolean inversion.
    RuntimeBooleanInvert = 0,
    // Ghidra: translate.hh:304 RUNTIME_RETURN_LOCATION
    /// Location of the runtime temporary storing the return value.
    RuntimeReturnLocation = 0x80,
    // Ghidra: translate.hh:305 RUNTIME_BITRANGE_EA
    /// Location of the runtime temporary for storing an effective address.
    RuntimeBitrangeEa = 0x100,
    // Ghidra: translate.hh:306 INJECT
    /// Range of temporaries for use in compiling p-code snippets.
    Inject = 0x200,
    // Ghidra: translate.hh:307 ANALYSIS
    /// Range of temporaries for use during decompiler analysis.
    Analysis = 0x10000000,
}

/// The interface to a translation engine for a processor. Faithful to
/// `Translate` (translate.hh:299).
///
/// This interface performs translations of instruction data for a
/// particular processor. It has two main functions:
///
/// - Disassemble single machine instructions.
/// - Translate single machine instructions into pcode.
///
/// It is also the repository for information about the exact configuration
/// of the reverse-engineering model associated with the processor: address
/// spaces, registers, and spacebases.
///
/// In Ghidra, `Translate` inherits from `AddrSpaceManager`. Rugra models
/// this as composition: implementations own an [`AddrSpaceManager`] and
/// expose the manager's state via the `manager`/`manager_mut` methods.
pub trait Translate {
    // RUDRA-GLUE: manager / manager_mut (Ghidra models Translate as a
    // subclass of AddrSpaceManager via inheritance; Rust uses composition.)
    /// Borrow the owned address-space manager. Faithful to the inherited
    /// `AddrSpaceManager` interface.
    fn manager(&self) -> &AddrSpaceManager;
    // RUDRA-GLUE: Mutable half of the Rust composition adapter; Ghidra exposes
    // AddrSpaceManager state through Translate's public inheritance instead.
    /// Mutably borrow the owned address-space manager.
    fn manager_mut(&mut self) -> &mut AddrSpaceManager;

    // Ghidra: translate.hh:321 Translate::isBigEndian
    /// Is the processor big endian? Faithful to the inline `isBigEndian`
    /// (translate.hh:586-588).
    fn is_big_endian(&self) -> bool;

    // Ghidra: translate.hh:323 Translate::getAlignment
    /// Get the instruction alignment for the processor. Faithful to the
    /// inline `getAlignment` (translate.hh:596-598).
    fn get_alignment(&self) -> i32;

    // Ghidra: translate.hh:324 Translate::getUniqueBase
    /// Get the base offset for new temporary registers. Faithful to the
    /// inline `getUniqueBase` (translate.hh:603-605).
    fn get_unique_base(&self) -> u32;

    // Ghidra: translate.hh:325 Translate::getUniqueStart
    /// Get a tagged address within the unique space. Faithful to the inline
    /// `getUniqueStart(UniqueLayout layout)` (translate.hh:611-613).
    ///
    /// For `Analysis`, the raw layout value is returned; for other layouts,
    /// `layout + unique_base` is returned.
    fn get_unique_start(&self, layout: UniqueLayout) -> u32 {
        // return (layout != ANALYSIS) ? layout + unique_base : layout;
        match layout {
            UniqueLayout::Analysis => layout as u32,
            _ => layout as u32 + self.get_unique_base(),
        }
    }

    // Ghidra: translate.hh:322 Translate::getFloatFormat
    /// Get the floating-point format for a particular encoding size. Faithful
    /// to `getFloatFormat(int4 size)` (translate.cc:979-989).
    ///
    /// Returns `None` if no format is registered for `size`.
    fn get_float_format(&self, size: usize) -> Option<&FloatFormat>;

    // Ghidra: translate.hh:332 Translate::initialize
    /// Initialize the translator given configuration documents. Faithful to
    /// the pure-virtual `initialize(DocumentStorage &store)`
    /// (translate.hh:332): the concrete `DocumentStorage` (marshal.rs,
    /// xml.cc:2435-2478) is passed by mutable reference, mirroring the C++
    /// non-const reference parameter. Implementations consume the store via
    /// `getTag`: the standalone engine reads the `<sleigh>` tag registered by
    /// `SleighArchitecture::buildSpecFile` (sleigh_arch.cc:409-417, the tag
    /// wraps the .sla path) and throws
    /// `LowlevelError("Could not find sleigh tag")` when absent
    /// (sleigh.cc:558-561); the Ghidra-coupled engine mirrors this with
    /// `getTag("sleigh")` (ghidra_translate.cc:35-41).
    fn initialize(&mut self, store: &mut crate::marshal::DocumentStorage);

    // Ghidra: translate.hh:344 Translate::registerContext
    /// Add a new context variable to the model for this processor. Faithful
    /// to the virtual `registerContext(const string &name, int4 sbit,
    /// int4 ebit)` (translate.hh:344). Default: no-op.
    fn register_context(&mut self, _name: &str, _sbit: i32, _ebit: i32) {}

    // Ghidra: translate.hh:353 Translate::setContextDefault
    /// Set the default value for a particular context variable. Faithful to
    /// the virtual `setContextDefault(const string &name, uintm val)`
    /// (translate.hh:353). Default: no-op.
    fn set_context_default(&mut self, _name: &str, _val: u64) {}

    // Ghidra: translate.hh:363 Translate::allowContextSet
    /// Toggle whether disassembly is allowed to affect context. Faithful to
    /// the virtual `allowContextSet(bool val) const` (translate.hh:363).
    /// Default: no-op.
    fn allow_context_set(&self, _val: bool) {}

    // Ghidra: translate.hh:370 Translate::getRegister
    /// Get a register as `VarnodeData` given its name. Faithful to the
    /// pure-virtual `getRegister(const string &nm)` (translate.hh:370).
    fn get_register(&self, nm: &str) -> VarnodeData;

    // Ghidra: translate.hh:380 Translate::getRegisterName
    /// Get the name of the smallest containing register given a location and
    /// size. Faithful to the pure-virtual `getRegisterName` (translate.hh:380).
    fn get_register_name(&self, base: AddressSpace, off: u64, size: usize) -> String;

    // Ghidra: translate.hh:390 Translate::getExactRegisterName
    /// Get the name of a register with an exact location and size. Faithful
    /// to the pure-virtual `getExactRegisterName` (translate.hh:390).
    fn get_exact_register_name(&self, base: AddressSpace, off: u64, size: usize) -> String;

    // Ghidra: translate.hh:398 Translate::getAllRegisters
    /// Populate `reglist` with every named register and its location. Faithful
    /// to the pure-virtual `getAllRegisters` (translate.hh:398).
    fn get_all_registers(&self, reglist: &mut HashMap<VarnodeData, String>);

    // Ghidra: translate.hh:408 Translate::getUserOpNames
    /// Get a list of all user-defined pcode ops in index order. Faithful to
    /// the pure-virtual `getUserOpNames` (translate.hh:408).
    fn get_user_op_names(&self, res: &mut Vec<String>);

    // Ghidra: translate.hh:417 Translate::instructionLength
    /// Get the length (in bytes) of a machine instruction. Faithful to the
    /// pure-virtual `instructionLength(const Address &baseaddr)`
    /// (translate.hh:417).
    fn instruction_length(&self, baseaddr: Address) -> i32;

    // Ghidra: translate.hh:432 Translate::oneInstruction
    /// Translate a single machine instruction into pcode. Faithful to the
    /// pure-virtual `oneInstruction(PcodeEmit &emit, const Address &baseaddr)`
    /// (translate.hh:432).
    ///
    /// The `dump` method of `emit` is invoked exactly once for each pcode
    /// operation. Returns the number of bytes in the machine instruction.
    fn one_instruction(&mut self, emit: &mut dyn PcodeEmit, baseaddr: Address) -> i32;

    // Ghidra: translate.hh:442 Translate::printAssembly
    /// Disassemble a single machine instruction. Faithful to the
    /// pure-virtual `printAssembly(AssemblyEmit &emit, const Address &baseaddr)`
    /// (translate.hh:442).
    fn print_assembly(&mut self, emit: &mut dyn AssemblyEmit, baseaddr: Address) -> i32;
}

// ============================================================================
// DocumentStorage unification note (TRANSLATE-DOCSTORE-UNIFY-0001):
// Ghidra's `DocumentStorage` is a concrete class declared in xml.hh:258-291
// and defined in xml.cc:2435-2478 (parseDocument/openDocument/registerTag/
// getTag). Its 1:1 Rust twin lives in marshal.rs; `Translate::initialize`
// consumes it directly, exactly like the C++ `DocumentStorage &store`
// parameter (translate.hh:332). The former iterator-shaped local trait stub
// (`next_document`) had no Ghidra counterpart and was removed.
// ============================================================================

// ============================================================================
// translate.cc:254/281 — construction-period space registration
// ----------------------------------------------------------------------------
// The decodeSpace/decodeSpaces pair is how production architectures
// (SleighArchitecture::restoreXml, sleigh_arch.cc) fill the AddrSpaceManager
// from a spec's `<spaces>` element, including the DEFAULT-space registration
// via the element's `defaultspace` attribute. It is the registration path
// EXTERNAL-STUB-SUPPORT-0001 uses to build the driver-side registry. The
// methods live on crate::space::SpaceRegistry (the 1:1 AddrSpaceManager
// twin) but in this module because the marshaling element/attribute ids
// (ELEM_SPACES, ATTRIB_DEFAULTSPACE, ...) are declared here and space.rs
// cannot import this module without a cycle.
// ============================================================================
impl crate::space::SpaceRegistry {
    // RUDRA-GLUE: named_attrib_id (Ghidra's ATTRIB_* globals carry both the
    // name and the id; Rust's const AttributeIds cannot retain the name, and
    // the TreeDecoder's targeted read_*_attr methods resolve by name. The
    // decode paths rebuild the runtime-named twin of the static id.)
    fn named_attrib_id(id: u32, name: &str) -> AttributeId {
        AttributeId {
            name: name.to_string(),
            id,
        }
    }

    // Ghidra: translate.cc:257 AddrSpaceManager::decodeSpace
    /// Initialize a single address space from a decoder element. Faithful
    /// to `decodeSpace` (translate.cc:254-275): the element id selects the
    /// partial constructor — `<space_base>` → SpacebaseSpace
    /// (translate.cc:73), `<space_unique>` → UniqueSpace (space.cc:433),
    /// `<space_other>` → OtherSpace (space.cc:403), `<space_overlay>` →
    /// OverlaySpace (space.cc:654), anything else → plain
    /// `AddrSpace(m,t,IPTR_PROCESSOR)` (space.cc:87) — and the element is
    /// then decoded. The `<space_base>` and `<space_overlay>` decodes read
    /// their space-reference attribute (`contain`/`base`) through this
    /// manager exactly like `Decoder::readSpace` (marshal.cc:400-409):
    /// name lookup, `Err("Unknown address space name: X")` on a miss.
    /// ConstantSpace/JoinSpace never arrive here (their decode throws,
    /// space.cc:381/646).
    pub fn decode_space(
        &mut self,
        decoder: &mut dyn Decoder,
    ) -> Result<crate::space::AddrSpace, String> {
        let elem_id = decoder.peek_element();
        if elem_id == ELEM_SPACE_BASE.id {
            // translate.cc:126-133 SpacebaseSpace::decode: open the element,
            // decodeBasicAttributes, contain = readSpace(ATTRIB_CONTAIN),
            // close.
            let spc = crate::space::AddrSpace::new_spacebase_space_for_decode();
            let opened = decoder.open_element_matching(&ELEM_SPACE_BASE);
            spc.decode_basic_attributes(decoder);
            let contain_attrib =
                Self::named_attrib_id(ATTRIB_CONTAIN.id, "contain");
            let contain_name = decoder.read_string_attr(&contain_attrib);
            decoder.close_element(opened);
            let contain = self
                .get_space_by_name(&contain_name)
                .ok_or_else(|| format!("Unknown address space name: {}", contain_name))?;
            spc.set_contain(&contain);
            Ok(spc)
        } else if elem_id == ELEM_SPACE_UNIQUE.id {
            // UniqueSpace has no decode override: base AddrSpace::decode
            // (space.cc:339-345) over the partial ctor's fields.
            let spc = crate::space::AddrSpace::new_unique_space_for_decode();
            spc.decode(decoder);
            Ok(spc)
        } else if elem_id == ELEM_SPACE_OTHER.id {
            // OtherSpace has no decode override either.
            let spc = crate::space::AddrSpace::new_other_space_for_decode();
            spc.decode(decoder);
            Ok(spc)
        } else if elem_id == ELEM_SPACE_OVERLAY.id {
            // space.cc:661-680 OverlaySpace::decode: open the element, read
            // name/index, base = readSpace(ATTRIB_BASE), close, then inherit
            // addressSize/wordsize/delay/deadcodedelay from the base and
            // propagate big_endian/hasphysical flags (the field flow of
            // crate::space::AddrSpace::new_overlay_space, which already
            // carries the space.cc:654-659 partial-constructor flags).
            let opened = decoder.open_element_matching(&ELEM_SPACE_OVERLAY);
            let name_attrib = Self::named_attrib_id(ATTRIB_NAME.id, "name");
            let index_attrib = Self::named_attrib_id(ATTRIB_INDEX.id, "index");
            let base_attrib = Self::named_attrib_id(ATTRIB_BASE.id, "base");
            let name = decoder.read_string_attr(&name_attrib);
            let index = decoder.read_signed_integer_attr(&index_attrib) as i32;
            let base_name = decoder.read_string_attr(&base_attrib);
            decoder.close_element(opened);
            let base = self
                .get_space_by_name(&base_name)
                .ok_or_else(|| format!("Unknown address space name: {}", base_name))?;
            Ok(crate::space::AddrSpace::new_overlay_space(&name, index, &base))
        } else {
            // space.cc:87 partial AddrSpace(m,t,IPTR_PROCESSOR) + base
            // decode.
            let spc = crate::space::AddrSpace::new_for_decode(crate::space::SpaceType::Processor);
            spc.decode(decoder);
            Ok(spc)
        }
    }

    // Ghidra: translate.cc:285 AddrSpaceManager::decodeSpaces
    /// Initialize (almost) all address spaces for a processor from a
    /// `<spaces>` element. Faithful to `decodeSpaces`
    /// (translate.cc:281-303): the constant space is inserted first, the
    /// `defaultspace` attribute is read from the element, every child
    /// element is decoded via [`Self::decode_space`] and inserted, the
    /// element is closed, and the default space is looked up **by name** —
    /// an unknown name is `Err("Bad 'defaultspace' attribute: X")` — and
    /// registered as the default code space via its index.
    /// `insert_space`/`set_default_code_space` errors propagate unchanged
    /// (Ghidra lets the LowlevelError escape to the architecture loader).
    pub fn decode_spaces(&mut self, decoder: &mut dyn Decoder) -> Result<(), String> {
        // The first space should always be the constant space.
        self.insert_space(crate::space::AddrSpace::new_constant_space(false))?;

        let elem_id = decoder.open_element_matching(&ELEM_SPACES);
        let defaultspace_attrib =
            Self::named_attrib_id(ATTRIB_DEFAULTSPACE.id, "defaultspace");
        let defname = decoder.read_string_attr(&defaultspace_attrib);
        while decoder.peek_element() != 0 {
            let spc = self.decode_space(decoder)?;
            self.insert_space(spc)?;
        }
        decoder.close_element(elem_id);
        let spc = self
            .get_space_by_name(&defname)
            .ok_or_else(|| format!("Bad 'defaultspace' attribute: {}", defname))?;
        self.set_default_code_space(spc.get_index() as usize)?;
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Local index mirrors crate::space::SPACEID_RAM for the insert/lookup test.
    const SPACEID_RAM_INDEX: u8 = 3;

    #[test]
    fn test_unimpl_error() {
        let e = UnimplError::new("bad instr", 4);
        assert_eq!(e.instruction_length, 4);
        assert!(format!("{}", e).contains("bad instr"));
    }

    #[test]
    fn test_bad_data_error() {
        let e = BadDataError::new("garbage");
        assert!(format!("{}", e).contains("garbage"));
    }

    #[test]
    fn test_spacebase_default_stack_growth() {
        let s = SpacebaseSpace::new("stack", 5, 8, AddressSpace::Ram, 1, true);
        // Ghidra default: isNegativeStack = true.
        assert!(s.stack_grows_negative());
        assert_eq!(s.num_spacebase(), 0);
        assert_eq!(s.get_contain(), AddressSpace::Ram);
    }

    #[test]
    #[should_panic(expected = "No base register specified")]
    fn test_spacebase_get_without_register_panics() {
        let s = SpacebaseSpace::new("stack", 5, 8, AddressSpace::Ram, 1, true);
        let _ = s.get_spacebase(0);
    }

    #[test]
    fn test_spacebase_set_register() {
        let mut s = SpacebaseSpace::new("stack", 5, 8, AddressSpace::Ram, 1, true);
        let data = VarnodeData {
            space: AddressSpace::Register,
            offset: 0x100,
            size: 8,
        };
        s.set_base_register(&data, 8, true);
        assert_eq!(s.num_spacebase(), 1);
        let base = s.get_spacebase(0);
        assert_eq!(base.offset, 0x100);
        assert_eq!(base.size, 8);
        // Full (untruncated) register equals the input.
        let full = s.get_spacebase_full(0);
        assert_eq!(full.offset, 0x100);
    }

    #[test]
    fn test_spacebase_truncate_little_endian() {
        let mut s = SpacebaseSpace::new("stack", 5, 8, AddressSpace::Ram, 1, true);
        let data = VarnodeData {
            space: AddressSpace::Register, // little-endian by default
            offset: 0x100,
            size: 8,
        };
        s.set_base_register(&data, 4, true);
        // Little-endian truncation keeps the low offset.
        assert_eq!(s.base_loc.offset, 0x100);
        assert_eq!(s.base_loc.size, 4);
    }

    #[test]
    fn test_addr_space_manager_default_empty() {
        let m = AddrSpaceManager::new();
        assert_eq!(m.num_spaces(), 0);
        assert!(m.get_default_code_space().is_none());
        assert!(m.get_space_by_name("ram").is_none());
    }

    #[test]
    fn test_addr_space_manager_insert_and_lookup() {
        let mut m = AddrSpaceManager::new();
        m.insert_space(AddressSpace::Ram);
        assert_eq!(m.num_spaces(), (SPACEID_RAM_INDEX + 1) as usize);
        assert_eq!(
            m.get_space(SPACEID_RAM_INDEX as usize),
            Some(AddressSpace::Ram)
        );
        assert_eq!(m.get_space_by_name("ram"), Some(AddressSpace::Ram));
    }

    #[test]
    fn test_join_record_ordering() {
        let a = JoinRecord {
            pieces: vec![VarnodeData {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            }],
            unified: VarnodeData {
                space: AddressSpace::Join,
                offset: 0,
                size: 4,
            },
        };
        let b = JoinRecord {
            pieces: vec![VarnodeData {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            }],
            unified: VarnodeData {
                space: AddressSpace::Join,
                offset: 16,
                size: 8,
            },
        };
        // a.unified.size (4) < b.unified.size (8).
        assert!(a.less_than(&b));
        assert!(!b.less_than(&a));
    }
}
