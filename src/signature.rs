//! Function signature/feature generation - faithful port of
//! `signature.hh` / `signature.cc` (1148 lines).
//!
//! Ghidra's signature system extracts a feature vector from a function's
//! data-flow and control-flow graphs by iteratively hashing information through
//! the edges of the graphs. The feature vector can be compared against a
//! database of known function signatures to identify standard library calls.
//!
//! # Key types
//! - `Signature`: a single 32-bit feature hash.
//! - `SignatureEntry`: a node for data-flow feature generation.
//! - `BlockSignatureEntry`: a node for control-flow feature generation.
//! - `VarnodeSignature`/`BlockSignature`/`CopySignature`: emitted features.
//! - `SigManager`/`GraphSigManager`: feature collection and generation.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/signature.{hh,cc}.
//!
//! # Status
//! L1->L2. The iterative graph hashing, noise removal (dominator-tree based),
//! and all three feature types are ported faithfully. Marshaling via the
//! `Encoder` trait is ported. The two free functions `simple_signature` and
//! `debug_signature` are ported. `Decoder`-based restore of `Signature` is
//! not needed for the write-only signature workflow and is deferred.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::address::Address;
use crate::crc32::crc_update;
use crate::funcdata::Funcdata;
use crate::marshal::{AttributeId, ElementId, Encoder};
use crate::op::{opcode_flags, pcodeop_flags, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::varnode::{Varnode, VarnodeLocRef};

// ---------------------------------------------------------------------------
// hashword: Ghidra typedefs `hashword` as `uint8` (= 8-byte unsigned long
// long), so the iterative hash slots are 64-bit. NOTE: `Signature::sig` is
// explicitly `uint4` (32-bit) in signature.hh:51, so the final feature hash
// stored in a `Signature` is 32-bit even though the iterative computation
// uses 64-bit values.
// ---------------------------------------------------------------------------

/// Marshaling attribute ids. Faithful to the `extern AttributeId` declarations
/// (signature.hh:27-29) and definitions (signature.cc:26-28).
pub static ATTRIB_BADDATA: LazyAttrib = LazyAttrib::new("baddata", 145);
pub static ATTRIB_HASH: LazyAttrib = LazyAttrib::new("hash", 146);
pub static ATTRIB_UNIMPL: LazyAttrib = LazyAttrib::new("unimpl", 147);

/// Additional attributes used by simpleSignature's element stream
/// (signature.cc:1116, 1126-1127). Ghidra reuses the global ATTRIB_VAL,
/// ATTRIB_SPACE, ATTRIB_OFFSET and ATTRIB_INDEX ids.
pub static ATTRIB_VAL: LazyAttrib = LazyAttrib::new("val", 71);
pub static ATTRIB_INDEX: LazyAttrib = LazyAttrib::new("index", 27);
pub static ATTRIB_SPACE: LazyAttrib = LazyAttrib::new("space", 9);
pub static ATTRIB_OFFSET: LazyAttrib = LazyAttrib::new("offset", 4);

/// Marshaling element ids. Faithful to the `extern ElementId` declarations
/// (signature.hh:31-42) and definitions (signature.cc:30-41).
pub static ELEM_BLOCKSIG: LazyElem = LazyElem::new("blocksig", 258);
pub static ELEM_CALL: LazyElem = LazyElem::new("call", 259);
pub static ELEM_GENSIG: LazyElem = LazyElem::new("gensig", 260);
pub static ELEM_COPYSIG: LazyElem = LazyElem::new("copysig", 263);
pub static ELEM_SIG: LazyElem = LazyElem::new("sig", 265);
pub static ELEM_SIGNATUREDESC: LazyElem = LazyElem::new("signaturedesc", 266);
pub static ELEM_SIGNATURES: LazyElem = LazyElem::new("signatures", 267);
pub static ELEM_VARSIG: LazyElem = LazyElem::new("varsig", 269);

/// A const-fn holder for an AttributeId. Rust statics cannot run the
/// AttributeId::new constructor (which allocates a String), so we store the
/// (name, id) pair and materialize an AttributeId on demand.
// RUGRA-GLUE: stand-in for Ghidra's static-initialized AttributeId objects.
pub struct LazyAttrib {
    name: &'static str,
    id: u32,
}
impl LazyAttrib {
    // RUGRA-GLUE: Const holder constructor because Ghidra's static AttributeId objects call an allocating constructor directly.
    pub const fn new(name: &'static str, id: u32) -> Self { Self { name, id } }
    // RUGRA-GLUE: Materializes an AttributeId on demand because Rust statics cannot run its allocating constructor.
    pub fn get(&self) -> AttributeId { AttributeId::new(self.name, self.id) }
}

/// A const-fn holder for an ElementId. See `LazyAttrib`.
// RUGRA-GLUE: stand-in for Ghidra's static-initialized ElementId objects.
pub struct LazyElem {
    name: &'static str,
    id: u32,
}
impl LazyElem {
    // RUGRA-GLUE: Const holder constructor because Ghidra's static ElementId objects call an allocating constructor directly.
    pub const fn new(name: &'static str, id: u32) -> Self { Self { name, id } }
    // RUGRA-GLUE: Materializes an ElementId on demand because Rust statics cannot run its allocating constructor.
    pub fn get(&self) -> ElementId { ElementId::new(self.name, self.id) }
}

/// Signature generation modifier bits. Faithful to `GraphSigManager::Mods`
/// (signature.hh:268-275).
pub mod sig_mods {
    // Ghidra: signature.hh:269 SIG_COLLAPSE_SIZE
    pub const SIG_COLLAPSE_SIZE: u32 = 0x1;
    // Ghidra: signature.hh:270 SIG_COLLAPSE_INDNOISE
    pub const SIG_COLLAPSE_INDNOISE: u32 = 0x2;
    // Ghidra: signature.hh:272 SIG_DONOTUSE_CONST
    pub const SIG_DONOTUSE_CONST: u32 = 0x10;
    // Ghidra: signature.hh:273 SIG_DONOTUSE_INPUT
    pub const SIG_DONOTUSE_INPUT: u32 = 0x20;
    // Ghidra: signature.hh:274 SIG_DONOTUSE_PERSIST
    pub const SIG_DONOTUSE_PERSIST: u32 = 0x40;
}

/// Mix two 64-bit hash values into a single 64-bit result. Faithful to the
/// static helper `hash_mixin` (signature.cc:43-59).
///
/// The high and low 32-bit halves of `val1` are fed through `crc_update`
/// (crc32.cc) in an interleaved fashion using successive bytes of `val2`.
// Ghidra: signature.cc:43 hash_mixin
fn hash_mixin(val1: u64, val2: u64) -> u64 {
    let mut hashhi: u32 = (val1 >> 32) as u32;
    let mut hashlo: u32 = val1 as u32;
    let mut v2 = val2;
    for _ in 0..8 {
        let tmphi = hashhi;
        let tmplo: u32 = v2 as u32;
        v2 >>= 8;
        hashhi = crc_update(hashhi, tmplo);
        hashlo = crc_update(hashlo, tmphi);
    }
    let res = (hashhi as u64) << 32 | hashlo as u64;
    res
}

/// A feature describing some aspect of a function or other unit of code.
///
/// The underlying representation is just a 32-bit hash of the information
/// representing the feature. Derived classes may contain other meta-data
/// describing where and how the feature was formed. Two features are generally
/// unordered (they are either equal or not equal), but an ordering is used
/// internally to normalize the vector representation and accelerate comparison.
///
/// Faithful to `Signature` (signature.hh:50-68). Note `sig` is explicitly
/// `uint4` (32-bit) even though `hashword` is 64-bit, because the iterative
/// computation produces 64-bit values but the emitted feature hash is truncated
/// to 32 bits (matching Ghidra's constructor cast `sig=(uint4)h`).
// Ghidra: signature.hh:50 Signature
pub struct Signature {
    /// Underlying 32-bit hash. Faithful to `uint4 sig` (signature.hh:51).
    pub sig: u32,
}

impl Signature {
    /// Constructor. Faithful to `Signature(hashword h)` (signature.hh:53),
    /// which casts the 64-bit hashword to a 32-bit uint4.
    // Ghidra: signature.hh:53 Signature::Signature
    pub fn new(h: u64) -> Self { Self { sig: h as u32 } }

    /// Get the underlying 32-bit hash of the feature. Faithful to `getHash`
    /// (signature.hh:54).
    // Ghidra: signature.hh:54 Signature::getHash
    pub fn get_hash(&self) -> u32 { self.sig }

    /// Print the feature hash and a brief description of this feature.
    /// Faithful to `print` (signature.cc:62-68).
    // Ghidra: signature.cc:62 Signature::print
    pub fn print(&self, s: &mut String) {
        s.push('*');
        self.print_origin(s);
        s.push_str(&format!(" = 0x{:08x}\n", self.sig));
    }

    /// Print a brief description of this feature. Faithful to `printOrigin`
    /// (signature.hh:62-64) - the base form prints the hex hash.
    // Ghidra: signature.hh:62 Signature::printOrigin
    pub fn print_origin(&self, s: &mut String) {
        s.push_str(&format!("0x{:08x}", self.sig));
    }

    /// Compare two features. Faithful to `compare` (signature.cc:73-79).
    /// Returns -1, 0, or 1.
    // Ghidra: signature.cc:73 Signature::compare
    pub fn compare(&self, op2: &Signature) -> i32 {
        if self.sig != op2.sig {
            return if self.sig < op2.sig { -1 } else { 1 };
        }
        0
    }

    /// Compare two Signature references via their underlying hash values.
    /// Faithful to `comparePtr` (signature.hh:67).
    // Ghidra: signature.hh:67 Signature::comparePtr
    pub fn compare_ptr(a: &Signature, b: &Signature) -> bool { a.sig < b.sig }

    /// Encode this feature to the stream. Faithful to `encode`
    /// (signature.cc:609-615).
    // Ghidra: signature.cc:609 Signature::encode
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ELEM_GENSIG.get());
        encoder.write_unsigned_integer(&ATTRIB_HASH.get(), self.get_hash() as u64);
        encoder.close_element(&ELEM_GENSIG.get());
    }
}

/// A feature representing a portion of the data-flow graph rooted at a
/// particular Varnode. Faithful to `VarnodeSignature` (signature.hh:183-189).
// Ghidra: signature.hh:183 VarnodeSignature
pub struct VarnodeSignature {
    /// The base feature data.
    // RUGRA-GLUE: Rust composes rather than inheriting from Signature.
    pub base: Signature,
    /// The root Varnode.
    // Ghidra: signature.hh:184 vn
    pub vn: Arc<RwLock<Varnode>>,
}

impl VarnodeSignature {
    /// Constructor. Faithful to `VarnodeSignature(const Varnode *v,hashword h)`
    /// (signature.hh:186).
    // Ghidra: signature.hh:186 VarnodeSignature::VarnodeSignature
    pub fn new(v: Arc<RwLock<Varnode>>, h: u64) -> Self {
        Self { base: Signature::new(h), vn: v }
    }

    /// Get the underlying 32-bit hash. Delegates to the base Signature.
    // Ghidra: signature.hh:54 Signature::getHash
    pub fn get_hash(&self) -> u32 { self.base.get_hash() }

    /// Encode the feature. Faithful to `VarnodeSignature::encode`
    /// (signature.cc:627-636).
    // Ghidra: signature.cc:627 VarnodeSignature::encode
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ELEM_VARSIG.get());
        encoder.write_unsigned_integer(&ATTRIB_HASH.get(), self.get_hash() as u64);
        // Ghidra emits vn->encode(encoder) and, if written, vn->getDef()->encode(encoder).
        // Rugra Varnode/PcodeOp do not yet implement encode() (L3 gap), so we
        // emit a textual origin via ATTRIB_INDEX carrying the create index as a
        // stable identifier, preserving the feature-comparison semantics.
        // RUGRA-GLUE: origin encoding (Ghidra vn->encode / op->encode are L3 gaps).
        let ci = self.vn.read().unwrap().get_create_index();
        encoder.write_unsigned_integer(&ATTRIB_INDEX.get(), ci as u64);
        encoder.close_element(&ELEM_VARSIG.get());
    }

    /// Print a brief description of this feature. Faithful to `printOrigin`
    /// (signature.hh:188) which calls `vn->printRaw(s)`.
    // Ghidra: signature.hh:188 VarnodeSignature::printOrigin
    pub fn print_origin(&self, s: &mut String) {
        s.push_str(&self.vn.read().unwrap().print_raw());
    }
}

/// A feature rooted in a basic block. There are two forms (signature.hh:191-
/// 197): form 1 contains only local control-flow information; form 2 combines
/// two operations that occur in sequence within the block. Faithful to
/// `BlockSignature` (signature.hh:197-207).
// Ghidra: signature.hh:197 BlockSignature
pub struct BlockSignature {
    /// The base feature data.
    pub base: Signature,
    /// The root basic block. Faithful to `bl` (signature.hh:198).
    pub block_index: i32,
    /// The block start address.
    // RUGRA-GLUE: address carried for encoding (Ghidra bl->getStart().encode).
    pub start_addr: Address,
    /// (Form 2) The first operation in sequence, or None for form 1.
    /// Faithful to `op1` (signature.hh:199).
    pub op1: Option<PcodeOpRef>,
    /// (Form 2) The second operation in sequence, or None for form 1.
    /// Faithful to `op2` (signature.hh:200).
    pub op2: Option<PcodeOpRef>,
}

impl BlockSignature {
    /// Constructor. Faithful to `BlockSignature(const BlockBasic *b,hashword h,
    /// const PcodeOp *o1,const PcodeOp *o2)` (signature.hh:202-204).
    // Ghidra: signature.hh:202 BlockSignature::BlockSignature
    pub fn new(
        block_index: i32,
        start_addr: Address,
        h: u64,
        op1: Option<PcodeOpRef>,
        op2: Option<PcodeOpRef>,
    ) -> Self {
        Self { base: Signature::new(h), block_index, start_addr, op1, op2 }
    }

    /// Get the underlying 32-bit hash.
    // Ghidra: signature.hh:54 Signature::getHash
    pub fn get_hash(&self) -> u32 { self.base.get_hash() }

    /// Encode the feature. Faithful to `BlockSignature::encode`
    /// (signature.cc:638-650).
    // Ghidra: signature.cc:638 BlockSignature::encode
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ELEM_BLOCKSIG.get());
        encoder.write_unsigned_integer(&ATTRIB_HASH.get(), self.get_hash() as u64);
        // Ghidra: bl->getIndex() (signed). RUGRA-GLUE: block index carried on the
        // feature because Rust features do not hold a back-pointer to BlockBasic.
        encoder.write_signed_integer(&ATTRIB_INDEX.get(), self.block_index as i64);
        // Ghidra emits bl->getStart().encode(encoder). Rugra Address has no
        // encode(); emit the offset instead. RUGRA-GLUE: address encoding.
        encoder.write_unsigned_integer(&ATTRIB_OFFSET.get(), self.start_addr.as_u64());
        // Ghidra: if (op2 != 0) op2->encode(encoder); if (op1 != 0) op1->encode(encoder);
        // Rugra PcodeOp lacks encode(); emit opcodes as a stable stand-in.
        // RUGRA-GLUE: op encode is an L3 gap; emit opcode as identifier.
        if let Some(op2) = &self.op2 {
            let code = op2.0.read().unwrap().get_opcode() as u64;
            encoder.write_unsigned_integer(&ATTRIB_VAL.get(), code);
        }
        if let Some(op1) = &self.op1 {
            let code = op1.0.read().unwrap().get_opcode() as u64;
            encoder.write_unsigned_integer(&ATTRIB_VAL.get(), code);
        }
        encoder.close_element(&ELEM_BLOCKSIG.get());
    }
}

/// A feature representing 1 or more stand-alone copies in a basic block.
/// Faithful to `CopySignature` (signature.hh:215-222).
// Ghidra: signature.hh:215 CopySignature
pub struct CopySignature {
    /// The base feature data.
    pub base: Signature,
    /// The basic block containing the COPY. Faithful to `bl` (signature.hh:216).
    pub block_index: i32,
}

impl CopySignature {
    /// Constructor. Faithful to `CopySignature(const BlockBasic *b,hashword h)`
    /// (signature.hh:218-219).
    // Ghidra: signature.hh:218 CopySignature::CopySignature
    pub fn new(block_index: i32, h: u64) -> Self {
        Self { base: Signature::new(h), block_index }
    }

    /// Get the underlying 32-bit hash.
    // Ghidra: signature.hh:54 Signature::getHash
    pub fn get_hash(&self) -> u32 { self.base.get_hash() }

    /// Encode the feature. Faithful to `CopySignature::encode`
    /// (signature.cc:652-659).
    // Ghidra: signature.cc:652 CopySignature::encode
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ELEM_COPYSIG.get());
        encoder.write_unsigned_integer(&ATTRIB_HASH.get(), self.get_hash() as u64);
        encoder.write_signed_integer(&ATTRIB_INDEX.get(), self.block_index as i64);
        encoder.close_element(&ELEM_COPYSIG.get());
    }

    /// Print a brief description of this feature. Faithful to `printOrigin`
    /// (signature.cc:661-666).
    // Ghidra: signature.cc:661 CopySignature::printOrigin
    pub fn print_origin(&self, s: &mut String) {
        s.push_str("Copies in block ");
        s.push_str(&self.block_index.to_string());
    }
}

/// An enum holding any emitted feature type. Rust replaces Ghidra virtual
/// `Signature *` polymorphism with an enum so the manager can own all features
/// in a single vector.
// RUGRA-GLUE: Rust enum replaces Ghidra Signature virtual hierarchy.
pub enum SignatureFeature {
    Plain(Signature),
    Varnode(VarnodeSignature),
    Block(BlockSignature),
    Copy(CopySignature),
}

impl SignatureFeature {
    /// Get the underlying 32-bit hash of any feature variant.
    // Ghidra: signature.hh:54 Signature::getHash (virtual dispatch)
    pub fn get_hash(&self) -> u32 {
        match self {
            SignatureFeature::Plain(s) => s.get_hash(),
            SignatureFeature::Varnode(v) => v.get_hash(),
            SignatureFeature::Block(b) => b.get_hash(),
            SignatureFeature::Copy(c) => c.get_hash(),
        }
    }

    /// Encode any feature variant. Faithful to the virtual `encode` dispatch.
    // Ghidra: signature.hh:58 Signature::encode (virtual dispatch)
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        match self {
            SignatureFeature::Plain(s) => s.encode(encoder),
            SignatureFeature::Varnode(v) => v.encode(encoder),
            SignatureFeature::Block(b) => b.encode(encoder),
            SignatureFeature::Copy(c) => c.encode(encoder),
        }
    }
}

// ---------------------------------------------------------------------------
// SignatureEntry: data-flow feature generation node.
// ---------------------------------------------------------------------------

/// Varnode properties that must be explicit during feature generation.
/// Faithful to `SignatureEntry::SignatureFlags` (signature.hh:80-87).
pub mod entry_flags {
    // Ghidra: signature.hh:81 SIG_NODE_TERMINAL
    pub const SIG_NODE_TERMINAL: u32 = 0x1;
    // Ghidra: signature.hh:82 SIG_NODE_COMMUTATIVE
    pub const SIG_NODE_COMMUTATIVE: u32 = 0x2;
    // Ghidra: signature.hh:83 SIG_NODE_NOT_EMITTED
    pub const SIG_NODE_NOT_EMITTED: u32 = 0x4;
    // Ghidra: signature.hh:84 SIG_NODE_STANDALONE
    pub const SIG_NODE_STANDALONE: u32 = 0x8;
    // Ghidra: signature.hh:85 VISITED
    pub const VISITED: u32 = 0x10;
    // Ghidra: signature.hh:86 MARKER_ROOT
    pub const MARKER_ROOT: u32 = 0x20;
}

/// A typed index into the arena of SignatureEntrys. Rust replaces Ghidra raw
/// `SignatureEntry *` pointers with arena indices because Rust forbids the
/// shared mutable aliasing that Ghidra relies on (entries reference each other
/// via `shadow`).
// RUGRA-GLUE: arena index replaces Ghidra SignatureEntry* aliasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VnIdx(pub usize);

impl VnIdx {
    // RUGRA-GLUE: Constructs the typed Rust arena index that replaces a raw Ghidra SignatureEntry pointer.
    pub fn from_raw(i: usize) -> Self { VnIdx(i) }
    // RUGRA-GLUE: Exposes the vector slot behind the typed arena index; Ghidra dereferences SignatureEntry pointers directly.
    pub fn raw(self) -> usize { self.0 }
}

/// A node for data-flow feature generation. Faithful to `SignatureEntry`
/// (signature.hh:78-160). A node is rooted at a specific Varnode and iteratively
/// hashes information about the Varnode and its nearest neighbors.
// Ghidra: signature.hh:78 SignatureEntry
pub struct SignatureEntry {
    /// The root Varnode. None for virtual nodes. Faithful to `vn`
    /// (signature.hh:93).
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// Feature generation properties. Faithful to `uint4 flags`
    /// (signature.hh:94).
    pub flags: u32,
    /// Current and previous hash. Faithful to `hashword hash[2]`
    /// (signature.hh:95) - 64-bit per the hashword typedef.
    pub hash: [u64; 2],
    /// The effective defining PcodeOp. Faithful to `const PcodeOp *op`
    /// (signature.hh:96).
    pub op: Option<PcodeOpRef>,
    /// First incoming edge (via the effective PcodeOp). Faithful to `startvn`
    /// (signature.hh:97).
    pub startvn: i32,
    /// Number of incoming edges. Faithful to `inSize` (signature.hh:98).
    pub in_size: i32,
    /// Post-order index. Faithful to `index` (signature.hh:99).
    pub index: i32,
    /// (If set) the Varnode being shadowed by this, as an arena index.
    /// Faithful to `SignatureEntry *shadow` (signature.hh:100).
    pub shadow: Option<VnIdx>,
    /// The Varnode create-index this entry was built for. Used by the
    /// map_to_entry lookup.
    // RUGRA-GLUE: stored so the SignatureGraph can build a create_index -> VnIdx map.
    pub create_index: i32,
}

/// The arena of SignatureEntrys plus the lookup map. Replaces Ghidra
/// `map<int4,SignatureEntry *> sigmap`. Rust owns the entries by value and
/// exposes index-based access so that entries can reference each other (via
/// `shadow`) without violating the aliasing rules.
// RUGRA-GLUE: arena owns SignatureEntry values (Ghidra uses map<int4,SignatureEntry*>).
pub struct SignatureGraph {
    /// All entries, in insertion order. Real Varnode-rooted entries come
    /// first; virtual nodes (the noise-graph root) are pushed afterwards.
    pub entries: Vec<SignatureEntry>,
    /// Map from Varnode create-index to the entry's index in `entries`.
    /// Mirrors the key of Ghidra `map<int4,SignatureEntry *>`.
    pub create_to_slot: HashMap<i32, usize>,
}

impl SignatureGraph {
    /// Construct an empty graph.
    // RUGRA-GLUE: default (Ghidra sigmap starts empty).
    pub fn new() -> Self {
        Self { entries: Vec::new(), create_to_slot: HashMap::new() }
    }

    /// Number of entries.
    // RUGRA-GLUE: Reports the Rust arena length; Ghidra queries the sigmap container directly.
    pub fn len(&self) -> usize { self.entries.len() }

    /// Iterate over entries immutably.
    // RUGRA-GLUE: Exposes slice iteration over the Rust-owned arena in place of direct Ghidra sigmap traversal.
    pub fn iter(&self) -> std::slice::Iter<'_, SignatureEntry> { self.entries.iter() }

    /// Iterate over entries mutably.
    // RUGRA-GLUE: Exposes mutable slice iteration required by Rust ownership; Ghidra mutates pointer-valued sigmap entries directly.
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, SignatureEntry> {
        self.entries.iter_mut()
    }

    /// Given a Varnode, find its SignatureEntry overlay. Faithful to
    /// `mapToEntry` (signature.hh:310-317).
    // Ghidra: signature.hh:310 SignatureEntry::mapToEntry
    pub fn map_to_entry(&self, vn: &Arc<RwLock<Varnode>>) -> VnIdx {
        let k = vn.read().unwrap().get_create_index() as i32;
        let slot = *self.create_to_slot.get(&k).expect("map_to_entry: varnode not in sigmap");
        VnIdx(slot)
    }

    /// Given a Varnode, find its SignatureEntry overlay, collapsing shadows.
    /// Faithful to `mapToEntryCollapse` (signature.hh:325-332).
    // Ghidra: signature.hh:325 SignatureEntry::mapToEntryCollapse
    pub fn map_to_entry_collapse(&self, vn: &Arc<RwLock<Varnode>>) -> VnIdx {
        let res = self.map_to_entry(vn);
        match self.entries[res.0].shadow {
            None => res,
            Some(s) => s,
        }
    }

    /// Immutable access to an entry by index.
    // RUGRA-GLUE: Resolves a Rust arena index to a shared reference; Ghidra uses a SignatureEntry pointer directly.
    pub fn entry(&self, idx: VnIdx) -> &SignatureEntry { &self.entries[idx.0] }

    /// Mutable access to an entry by index.
    // RUGRA-GLUE: Resolves a Rust arena index to an exclusive reference; Ghidra mutates through a SignatureEntry pointer.
    pub fn entry_mut(&mut self, idx: VnIdx) -> &mut SignatureEntry { &mut self.entries[idx.0] }

    /// Add a root entry for a Varnode, registering it in the lookup map.
    /// Mirrors the body of `GraphSigManager::setCurrentFunction`
    /// (signature.cc:972-973).
    // RUGRA-GLUE: drives signature.cc:972 GraphSigManager::setCurrentFunction (insert).
    pub fn push_root(&mut self, entry: SignatureEntry) {
        let ci = entry.create_index;
        let slot = self.entries.len();
        self.entries.push(entry);
        self.create_to_slot.insert(ci, slot);
    }

    /// Add a virtual entry (no backing Varnode). Mirrors
    /// `SignatureEntry(int4 ind)` usage in `removeNoise` (signature.cc:484).
    // RUGRA-GLUE: drives signature.cc:484 removeNoise virtual root.
    pub fn push_virtual(&mut self, entry: SignatureEntry) -> VnIdx {
        let slot = self.entries.len();
        self.entries.push(entry);
        VnIdx(slot)
    }
}

impl Default for SignatureGraph {
    // RUGRA-GLUE: Rust Default delegates to SignatureGraph::new; C++ has no Default-trait entry point.
    fn default() -> Self { Self::new() }
}

impl SignatureEntry {
    /// Construct from a Varnode, deciding the effective defining op and the
    /// incoming-edge properties. Faithful to
    /// `SignatureEntry::SignatureEntry(Varnode *v,uint4 modifiers)`
    /// (signature.cc:144-209).
    // Ghidra: signature.cc:144 SignatureEntry::SignatureEntry(Varnode*,uint4)
    pub fn new(v: Arc<RwLock<Varnode>>, modifiers: u32) -> Self {
        let create_index = v.read().unwrap().get_create_index() as i32;
        let def = v.read().unwrap().get_def();
        let mut e = SignatureEntry {
            vn: Some(v.clone()),
            flags: 0,
            hash: [0, 0],
            op: def.map(PcodeOpRef),
            in_size: 0,
            startvn: 0,
            index: -1,
            shadow: None,
            create_index,
        };
        // signature.cc:155-158: no defining op => terminal.
        let op_ref = match &e.op {
            None => {
                e.flags |= entry_flags::SIG_NODE_TERMINAL;
                return e;
            }
            Some(r) => r.clone(),
        };
        let op_rg = op_ref.0.read().unwrap();
        // signature.cc:159-160
        e.startvn = 0;
        e.in_size = op_rg.num_input() as i32;
        let code = op_rg.get_opcode();
        match code {
            // signature.cc:162-165
            OpCode::CPUI_COPY => {
                if Self::test_standalone_copy(&v) {
                    e.flags |= entry_flags::SIG_NODE_STANDALONE;
                }
            }
            // signature.cc:166-170
            OpCode::CPUI_INDIRECT => {
                e.in_size -= 1;
                if Self::test_standalone_copy(&v) {
                    e.flags |= entry_flags::SIG_NODE_STANDALONE;
                }
            }
            // signature.cc:171-172
            OpCode::CPUI_MULTIEQUAL => {
                e.flags |= entry_flags::SIG_NODE_COMMUTATIVE;
            }
            // signature.cc:174-193: CALL/CALLIND/CALLOTHER/STORE/LOAD skip input 0.
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER
            | OpCode::CPUI_STORE | OpCode::CPUI_LOAD => {
                e.startvn = 1;
                e.in_size -= 1;
            }
            // signature.cc:194-200: shift/truncation with constant amount => 1 input.
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT
            | OpCode::CPUI_SUBPIECE => {
                if let Some(inp1) = op_rg.get_in(1) {
                    if inp1.read().unwrap().is_constant() {
                        e.in_size = 1;
                    }
                }
            }
            // signature.cc:201-203
            OpCode::CPUI_CPOOLREF => {
                e.in_size = 0;
            }
            // signature.cc:204-208: default - commutative ops.
            _ => {
                if (opcode_flags(code) & pcodeop_flags::COMMUTATIVE) != 0 {
                    e.flags |= entry_flags::SIG_NODE_COMMUTATIVE;
                }
            }
        }
        // Suppress unused-modifier lint: the modifiers affect localHash/hashSize,
        // not the constructor in Ghidra.
        let _ = modifiers;
        e
    }

    /// Construct a virtual node. Faithful to
    /// `SignatureEntry::SignatureEntry(int4 ind)` (signature.cc:213-223).
    // Ghidra: signature.cc:213 SignatureEntry::SignatureEntry(int4)
    pub fn new_virtual(ind: i32) -> Self {
        SignatureEntry {
            vn: None,
            flags: 0,
            hash: [0, 0],
            op: None,
            in_size: 0,
            startvn: 0,
            index: ind,
            shadow: None,
            create_index: -1,
        }
    }

    /// Return true if this node has no inputs. Faithful to `isTerminal`
    /// (signature.hh:131).
    // Ghidra: signature.hh:131 SignatureEntry::isTerminal
    pub fn is_terminal(&self) -> bool { (self.flags & entry_flags::SIG_NODE_TERMINAL) != 0 }

    /// Return true if this is not emitted as a feature. Faithful to `isNotEmitted`
    /// (signature.hh:132).
    // Ghidra: signature.hh:132 SignatureEntry::isNotEmitted
    pub fn is_not_emitted(&self) -> bool { (self.flags & entry_flags::SIG_NODE_NOT_EMITTED) != 0 }

    /// Return true if inputs to this are unordered. Faithful to `isCommutative`
    /// (signature.hh:133).
    // Ghidra: signature.hh:133 SignatureEntry::isCommutative
    pub fn is_commutative(&self) -> bool { (self.flags & entry_flags::SIG_NODE_COMMUTATIVE) != 0 }

    /// Return true if this is a stand-alone COPY. Faithful to `isStandaloneCopy`
    /// (signature.hh:134).
    // Ghidra: signature.hh:134 SignatureEntry::isStandaloneCopy
    pub fn is_standalone_copy(&self) -> bool { (self.flags & entry_flags::SIG_NODE_STANDALONE) != 0 }

    /// Return the number of incoming edges. Faithful to `numInputs`
    /// (signature.hh:135).
    // Ghidra: signature.hh:135 SignatureEntry::numInputs
    pub fn num_inputs(&self) -> i32 { self.in_size }

    /// Return true if this node has been visited before. Faithful to `isVisited`
    /// (signature.hh:102).
    // Ghidra: signature.hh:102 SignatureEntry::isVisited
    pub fn is_visited(&self) -> bool { (self.flags & entry_flags::VISITED) != 0 }

    /// Mark that this node has been visited. Faithful to `setVisited`
    /// (signature.hh:103).
    // Ghidra: signature.hh:103 SignatureEntry::setVisited
    pub fn set_visited(&mut self) { self.flags |= entry_flags::VISITED; }

    /// Get the i-th incoming node, collapsing shadows. Faithful to `getIn`
    /// (signature.hh:142-144).
    // Ghidra: signature.hh:142 SignatureEntry::getIn
    pub fn get_in(&self, i: i32, graph: &SignatureGraph) -> VnIdx {
        let op = self.op.as_ref().expect("getIn: no effective op");
        let op_rg = op.0.read().unwrap();
        let slot = (i + self.startvn) as usize;
        let invn = op_rg.get_in(slot).expect("getIn: input slot out of range").clone();
        drop(op_rg);
        graph.map_to_entry_collapse(&invn)
    }

    /// Get the number of input edges in the noise-reduced form. Faithful to
    /// `markerSizeIn` (signature.hh:108-111).
    // Ghidra: signature.hh:108 SignatureEntry::markerSizeIn
    pub fn marker_size_in(&self) -> i32 {
        if (self.flags & entry_flags::MARKER_ROOT) != 0 {
            1
        } else {
            self.num_inputs()
        }
    }

    /// Get a specific node coming into this in the noise-reduced form. Faithful
    /// to `getMarkerIn` (signature.hh:119-122).
    // Ghidra: signature.hh:119 SignatureEntry::getMarkerIn
    pub fn get_marker_in(&self, i: i32, v_root: VnIdx, graph: &SignatureGraph) -> VnIdx {
        if (self.flags & entry_flags::MARKER_ROOT) != 0 {
            return v_root;
        }
        let op = self.op.as_ref().expect("getMarkerIn: no effective op");
        let op_rg = op.0.read().unwrap();
        let slot = (i + self.startvn) as usize;
        let invn = op_rg.get_in(slot).expect("getMarkerIn: input slot out of range").clone();
        drop(op_rg);
        graph.map_to_entry(&invn)
    }

    /// Store hash from previous iteration. Faithful to `flip`
    /// (signature.hh:148).
    // Ghidra: signature.hh:148 SignatureEntry::flip
    pub fn flip(&mut self) { self.hash[1] = self.hash[0]; }

    /// Get the current hash value. Faithful to `getHash` (signature.hh:151).
    // Ghidra: signature.hh:151 SignatureEntry::getHash
    pub fn get_hash(&self) -> u64 { self.hash[0] }

    /// Get the underlying Varnode which this overlays. Faithful to `getVarnode`
    /// (signature.hh:150).
    // Ghidra: signature.hh:150 SignatureEntry::getVarnode
    pub fn get_varnode(&self) -> Option<&Arc<RwLock<Varnode>>> { self.vn.as_ref() }

    /// Calculate a hash encoding the OpCode of the effective defining PcodeOp.
    /// Faithful to `getOpHash` (signature.cc:105-116). Returns 0 if there is no
    /// effective op. For CPOOLREF, hashes in the resolved tag type constant
    /// (last input's offset).
    // Ghidra: signature.cc:105 SignatureEntry::getOpHash
    pub fn get_op_hash(&self) -> u64 {
        let op_ref = match &self.op {
            None => return 0,
            Some(r) => r,
        };
        let op_rg = op_ref.0.read().unwrap();
        let opc = op_rg.get_opcode();
        let mut ophash: u64 = opc as u64;
        if opc == OpCode::CPUI_CPOOLREF {
            let last = op_rg.num_input() - 1;
            let offset = op_rg.get_in(last).expect("getOpHash: CPOOLREF has no inputs")
                .read().unwrap().get_offset();
            // signature.cc:114: ophash = (ophash + 0xfeedface) ^ op->getIn(numInput-1)->getOffset();
            ophash = (ophash.wrapping_add(0xfeedface)) ^ offset;
        }
        ophash
    }

    /// Determine if the given Varnode is a stand-alone COPY. Faithful to
    /// `testStandaloneCopy` (signature.cc:231-258).
    // Ghidra: signature.cc:231 SignatureEntry::testStandaloneCopy
    pub fn test_standalone_copy(vn: &Arc<RwLock<Varnode>>) -> bool {
        let def = vn.read().unwrap().get_def().expect("testStandaloneCopy: no defining op");
        let def_rg = def.read().unwrap();
        let invn = def_rg.get_in(0).expect("testStandaloneCopy: no input 0").clone();
        drop(def_rg);
        let invn_rg = invn.read().unwrap();
        // signature.cc:236-237: input must not be written by another op.
        if invn_rg.is_written() {
            return false;
        }
        // signature.cc:238-239: addresses must differ.
        if invn_rg.get_addr() == vn.read().unwrap().get_addr() {
            return false;
        }
        let vn_is_persist = vn.read().unwrap().is_persist();
        let def_code = def.read().unwrap().get_opcode();
        // signature.cc:241-242: persistent + INDIRECT => standalone.
        if vn_is_persist && def_code == OpCode::CPUI_INDIRECT {
            return true;
        }
        drop(invn_rg);
        // signature.cc:243-245: no descendants => standalone. Bind the read
        // guard to a named variable so it outlives the descend iterator.
        let vn_rg2 = vn.read().unwrap();
        let mut descend = vn_rg2.descend_iter();
        let first = match descend.next() {
            None => return true,
            Some(d) => d,
        };
        // signature.cc:247-249: more than one descendant => not standalone.
        if descend.next().is_some() {
            return false;
        }
        let desc_op = first.read().unwrap();
        let opc = desc_op.get_opcode();
        // signature.cc:251-253: persistent + single INDIRECT descendant => standalone.
        if vn_is_persist && opc == OpCode::CPUI_INDIRECT {
            return true;
        }
        // signature.cc:254-257: only COPY/INDIRECT descendants qualify, and only
        // if that descendant's output has no further descendants.
        if opc != OpCode::CPUI_COPY && opc != OpCode::CPUI_INDIRECT {
            return false;
        }
        match desc_op.get_out() {
            Some(outvn) => outvn.read().unwrap().has_no_descend(),
            None => false,
        }
    }

    /// Calculate the hash for a stand-alone COPY. Faithful to
    /// `standaloneCopyHash` (signature.cc:122-140).
    // Ghidra: signature.cc:122 SignatureEntry::standaloneCopyHash
    pub fn standalone_copy_hash(&mut self, vn: &Arc<RwLock<Varnode>>, modifiers: u32) {
        let mut val = Self::hash_size(vn, modifiers);
        val ^= 0xaf29e23bu64;
        let vn_rg = vn.read().unwrap();
        if vn_rg.is_persist() {
            val ^= 0x55055055u64;
        }
        drop(vn_rg);
        let def = vn.read().unwrap().get_def().expect("standaloneCopyHash: no defining op");
        let invn = def.read().unwrap().get_in(0).expect("standaloneCopyHash: no input 0").clone();
        drop(def);
        let invn_rg = invn.read().unwrap();
        if invn_rg.is_constant() {
            // signature.cc:131-135
            if (modifiers & sig_mods::SIG_DONOTUSE_CONST) == 0 {
                val ^= vn.read().unwrap().get_offset();
            } else {
                val ^= 0xa0a0a0a0u64;
            }
        } else if invn_rg.is_persist() {
            // signature.cc:136-137
            val ^= 0xd7651ec3u64;
        }
        drop(invn_rg);
        self.hash[0] = val;
        self.hash[1] = val;
    }

    /// Calculate a hash describing the size of a given Varnode. Faithful to
    /// `hashSize` (signature.hh:342-351).
    // Ghidra: signature.hh:342 SignatureEntry::hashSize
    pub fn hash_size(vn: &Arc<RwLock<Varnode>>, modifiers: u32) -> u64 {
        let mut val = vn.read().unwrap().get_size() as u64;
        if (modifiers & sig_mods::SIG_COLLAPSE_SIZE) != 0 && val > 4 {
            val = 4;
        }
        val ^ (val << 7) ^ (val << 14) ^ (val << 21)
    }
}

impl SignatureEntry {
    /// Determine if this node shadows another. A Varnode shadows another if it
    /// is defined by a chain of COPY/INDIRECT/CAST ops; follow the chain and set
    /// `shadow` to the terminator's entry. Faithful to `calculateShadow`
    /// (signature.cc:84-99).
    // Ghidra: signature.cc:84 SignatureEntry::calculateShadow
    pub fn calculate_shadow(&mut self, graph: &SignatureGraph) {
        let mut shadow_vn = match self.vn.clone() {
            None => return,
            Some(v) => v,
        };
        let start_vn = shadow_vn.clone();
        loop {
            // signature.cc:89: op = shadowVn->getDef();
            let next = shadow_vn.read().unwrap().get_def();
            let op_ref = match next {
                None => break,
                Some(o) => o,
            };
            let code = op_ref.read().unwrap().get_opcode();
            // signature.cc:93-94
            if code != OpCode::CPUI_COPY && code != OpCode::CPUI_INDIRECT && code != OpCode::CPUI_CAST {
                break;
            }
            // signature.cc:95: shadowVn = op->getIn(0);
            shadow_vn = op_ref
                .read()
                .unwrap()
                .get_in(0)
                .expect("calculateShadow: COPY/INDIRECT/CAST with no input")
                .clone();
        }
        // signature.cc:97-98
        if !Arc::ptr_eq(&shadow_vn, &start_vn) {
            self.shadow = Some(graph.map_to_entry(&shadow_vn));
        }
        // Ghidra assigns op = shadowVn->getDef() inside the loop; mirror by
        // updating the effective op to the terminator's def.
        self.op = shadow_vn.read().unwrap().get_def().map(PcodeOpRef);
    }

    /// Compute an initial hash based on local properties of the Varnode.
    /// Faithful to `localHash` (signature.cc:268-316).
    // Ghidra: signature.cc:268 SignatureEntry::localHash
    pub fn local_hash(&mut self, modifiers: u32) {
        let vn = match &self.vn {
            None => return, // virtual node has no local hash
            Some(v) => v.clone(),
        };
        let vn_rg = vn.read().unwrap();
        // signature.cc:273-279: annotation => constant hash, not emitted, terminal.
        if vn_rg.is_annotation() {
            let localhash: u64 = 0xb7b7b7b7;
            self.flags |= entry_flags::SIG_NODE_NOT_EMITTED | entry_flags::SIG_NODE_TERMINAL;
            self.hash[0] = localhash;
            self.hash[1] = localhash;
            return;
        }
        // signature.cc:280-286: shadow => not emitted; standalone copies get a
        // special hash.
        if self.shadow.is_some() {
            self.flags |= entry_flags::SIG_NODE_NOT_EMITTED;
            if self.is_standalone_copy() {
                drop(vn_rg);
                self.standalone_copy_hash(&vn, modifiers);
            }
            return;
        }
        // signature.cc:288
        let mut localhash = Self::hash_size(&vn, modifiers);
        // signature.cc:290-291: if not written, don't emit but still hash.
        if !vn_rg.is_written() {
            self.flags |= entry_flags::SIG_NODE_NOT_EMITTED;
        }
        let ophash = self.get_op_hash();
        // signature.cc:295-300: constant handling.
        if vn_rg.is_constant() {
            if (modifiers & sig_mods::SIG_DONOTUSE_CONST) == 0 {
                localhash ^= vn_rg.get_offset();
            } else {
                localhash ^= 0xa0a0a0a0u64;
            }
        }
        // signature.cc:301-306: persist + input handling.
        if (modifiers & sig_mods::SIG_DONOTUSE_PERSIST) == 0 && vn_rg.is_persist() && vn_rg.is_input() {
            localhash ^= 0x55055055u64;
        }
        // signature.cc:307-309: input handling.
        if vn_rg.is_input() {
            localhash ^= 0x10101u64;
        }
        drop(vn_rg);
        // signature.cc:310-312: op hash mixing.
        if ophash != 0 {
            localhash ^= ophash ^ (ophash << 9) ^ (ophash << 18);
        }
        // signature.cc:314-315
        self.hash[0] = localhash;
        self.hash[1] = localhash;
    }

    /// Hash info from other nodes into this. Faithful to `hashIn`
    /// (signature.cc:321-342).
    // Ghidra: signature.cc:321 SignatureEntry::hashIn
    pub fn hash_in(&mut self, neigh: &[VnIdx], graph: &SignatureGraph) {
        let mut curhash = self.hash[1];
        if self.is_commutative() {
            // signature.cc:326-334: order-invariant accumulation.
            let mut accum: u64 = 0;
            for nidx in neigh {
                let tmphash = hash_mixin(curhash, graph.entries[nidx.0].hash[1]);
                accum = accum.wrapping_add(tmphash);
            }
            curhash = hash_mixin(curhash, accum);
        } else {
            // signature.cc:335-340: ordered mixing.
            for nidx in neigh {
                curhash = hash_mixin(curhash, graph.entries[nidx.0].hash[1]);
            }
        }
        // signature.cc:341
        self.hash[0] = curhash;
    }
}

impl SignatureGraph {
    /// Run `calculateShadow` on every entry. This helper exists so the per-entry
    /// lookup of `create_to_slot` (immut) can coexist with the `entries` mut
    /// borrow within one method body, satisfying Rust's disjoint-field borrow.
    // RUGRA-GLUE: drives signature.cc:983-984 GraphSigManager::setCurrentFunction.
    pub fn calculate_shadows_all(&mut self) {
        let create_to_slot = &self.create_to_slot;
        for i in 0..self.entries.len() {
            // Re-resolve each entry's own create_index through the map, matching
            // Ghidra's mapToEntry(vn) lookup.
            let map_fn = |vn: &Arc<RwLock<Varnode>>| -> VnIdx {
                let k = vn.read().unwrap().get_create_index() as i32;
                let slot = *create_to_slot
                    .get(&k)
                    .expect("calculate_shadows_all: varnode not in sigmap");
                VnIdx(slot)
            };
            self.entries[i].calculate_shadow_via(map_fn);
        }
    }

    /// Apply one round of `hashIn` to a precomputed work list. Lives on
    /// `SignatureGraph` so the disjoint borrow of entries (mut target /
    /// immut neighbours) is visible within one method body, which the borrow
    /// checker requires.
    // RUGRA-GLUE: drives signature.cc:1025-1036 GraphSigManager::signatureIterate.
    pub fn apply_hash_in_round(&mut self, work: &[(VnIdx, Vec<VnIdx>)]) {
        // Two-phase: read all neighbour hashes immutably, then write targets.
        // This avoids holding a &mut to an entry while reading its neighbours.
        let entries = &self.entries;
        let new_hashes: Vec<u64> = work
            .iter()
            .map(|(entry_idx, neigh)| {
                let mut curhash = entries[entry_idx.0].hash[1];
                if entries[entry_idx.0].is_commutative() {
                    let mut accum: u64 = 0;
                    for nidx in neigh {
                        let tmphash = hash_mixin(curhash, entries[nidx.0].hash[1]);
                        accum = accum.wrapping_add(tmphash);
                    }
                    curhash = hash_mixin(curhash, accum);
                } else {
                    for nidx in neigh {
                        curhash = hash_mixin(curhash, entries[nidx.0].hash[1]);
                    }
                }
                curhash
            })
            .collect();
        for (i, (entry_idx, _)) in work.iter().enumerate() {
            self.entries[entry_idx.0].hash[0] = new_hashes[i];
        }
    }
}

impl SignatureEntry {
    /// Variant of `calculate_shadow` that accepts a closure to resolve a
    /// Varnode to its arena index. This decouples the `&mut self` write from the
    /// `&graph` read, which is needed because Rust cannot split `self` from the
    /// containing `SignatureGraph` across a method call boundary.
    // RUGRA-GLUE: closure-based shadow lookup (Ghidra uses a const map ref).
    pub fn calculate_shadow_via<F>(&mut self, map_fn: F)
    where
        F: Fn(&Arc<RwLock<Varnode>>) -> VnIdx,
    {
        let mut shadow_vn = match self.vn.clone() {
            None => return,
            Some(v) => v,
        };
        let start_vn = shadow_vn.clone();
        loop {
            let next = shadow_vn.read().unwrap().get_def();
            let op_ref = match next {
                None => break,
                Some(o) => o,
            };
            let code = op_ref.read().unwrap().get_opcode();
            if code != OpCode::CPUI_COPY && code != OpCode::CPUI_INDIRECT && code != OpCode::CPUI_CAST {
                break;
            }
            shadow_vn = op_ref
                .read()
                .unwrap()
                .get_in(0)
                .expect("calculate_shadow_via: COPY/INDIRECT/CAST with no input")
                .clone();
        }
        if !Arc::ptr_eq(&shadow_vn, &start_vn) {
            self.shadow = Some(map_fn(&shadow_vn));
        }
        self.op = shadow_vn.read().unwrap().get_def().map(PcodeOpRef);
    }
}

impl SignatureEntry {
    /// Do a post-ordering of the modified noise graph. Faithful to
    /// `noisePostOrder` (signature.cc:353-386).
    ///
    /// The noise graph is formed from the original graph by removing all
    /// non-marker edges (only COPY/marker edges are traversed via descendants).
    // Ghidra: signature.cc:353 SignatureEntry::noisePostOrder
    pub fn noise_post_order(
        rootlist: &[VnIdx],
        post_order: &mut Vec<VnIdx>,
        graph: &mut SignatureGraph,
    ) {
        // Each stack frame holds the entry index and the current descend iterator
        // materialized as a Vec (so it can be paused/resumed). Ghidra stores a
        // list<PcodeOp*>::const_iterator per frame.
        struct Frame {
            entry: VnIdx,
            descend: Vec<Arc<RwLock<crate::op::PcodeOp>>>,
            pos: usize,
        }
        let mut stack: Vec<Frame> = Vec::new();
        for &root in rootlist {
            // signature.cc:361-362: mark root visited, seed its descendents.
            graph.entries[root.0].set_visited();
            let descend: Vec<Arc<RwLock<crate::op::PcodeOp>>> = graph.entries[root.0]
                .vn
                .as_ref()
                .expect("noisePostOrder: root has no varnode")
                .read()
                .unwrap()
                .descend_iter()
                .collect();
            stack.push(Frame { entry: root, descend, pos: 0 });
            while !stack.is_empty() {
                let frame_len = stack.len();
                let frame = &mut stack[frame_len - 1];
                if frame.pos >= frame.descend.len() {
                    // signature.cc:367-369: no more children; assign post-order index.
                    let entry = frame.entry;
                    stack.pop();
                    let idx = post_order.len() as i32;
                    graph.entries[entry.0].index = idx;
                    post_order.push(entry);
                } else {
                    let op_arc = frame.descend[frame.pos].clone();
                    frame.pos += 1;
                    let (is_marker_or_copy, out_vn) = {
                        let op_rg = op_arc.read().unwrap();
                        (
                            op_rg.is_marker() || op_rg.get_opcode() == OpCode::CPUI_COPY,
                            op_rg.get_out().cloned(),
                        )
                    };
                    // signature.cc:374-382: traverse only marker/COPY descendants.
                    if is_marker_or_copy {
                        if let Some(outvn) = out_vn {
                            let child_idx = graph.map_to_entry(&outvn);
                            if !graph.entries[child_idx.0].is_visited() {
                                graph.entries[child_idx.0].set_visited();
                                let child_descend: Vec<Arc<RwLock<crate::op::PcodeOp>>> = graph.entries
                                    [child_idx.0]
                                    .vn
                                    .as_ref()
                                    .expect("noisePostOrder: child has no varnode")
                                    .read()
                                    .unwrap()
                                    .descend_iter()
                                    .collect();
                                stack.push(Frame { entry: child_idx, descend: child_descend, pos: 0 });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Construct the dominator tree for the modified noise graph. Faithful to
    /// `noiseDominator` (signature.cc:396-438).
    ///
    /// After this routine completes, the shadow field of each node is filled in
    /// with its immediate dominator relative to the modified noise graph (using
    /// arena indices to represent the dominator pointers).
    // Ghidra: signature.cc:396 SignatureEntry::noiseDominator
    pub fn noise_dominator(post_order: &[VnIdx], graph: &mut SignatureGraph, v_root: VnIdx) {
        // signature.cc:400-401: the official start node is the last in post-order.
        let b = post_order[post_order.len() - 1];
        graph.entries[b.0].shadow = Some(b);
        let mut changed = true;
        while changed {
            changed = false;
            // signature.cc:406: for all nodes in reverse post-order except root.
            let mut i = post_order.len() as isize - 2;
            while i >= 0 {
                let b_idx = post_order[i as usize];
                // signature.cc:408: skip nodes whose dominator is already the root.
                if graph.entries[b_idx.0].shadow.map_or(true, |s| s != post_order[post_order.len() - 1]) {
                    let size_in = graph.entries[b_idx.0].marker_size_in();
                    let mut new_idom: Option<VnIdx> = None;
                    let mut j = 0;
                    // signature.cc:411-415: find first processed node.
                    while j < size_in {
                        let cand = graph.entries[b_idx.0].get_marker_in(j, v_root, graph);
                        if graph.entries[cand.0].shadow.is_some() {
                            new_idom = Some(cand);
                            break;
                        }
                        j += 1;
                    }
                    j += 1;
                    // signature.cc:417-430: intersection routine.
                    while j < size_in {
                        let rho = graph.entries[b_idx.0].get_marker_in(j, v_root, graph);
                        if let Some(rho_idx) = graph.entries[rho.0].shadow {
                            if let Some(ni) = new_idom {
                                new_idom = Some(Self::intersect(rho_idx, ni, graph, post_order));
                            }
                        }
                        j += 1;
                    }
                    // signature.cc:431-434.
                    if let Some(ni) = new_idom {
                        if graph.entries[b_idx.0].shadow != Some(ni) {
                            graph.entries[b_idx.0].shadow = Some(ni);
                            changed = true;
                        }
                    }
                }
                i -= 1;
            }
        }
    }

    /// Intersection helper for the dominator-tree construction. Walks two
    /// fingers up the (provisional) dominator tree until they meet. Faithful to
    /// the inner loop of `noiseDominator` (signature.cc:419-428).
    // Ghidra: signature.cc:419-428 (inline intersection in noiseDominator)
    fn intersect(rho: VnIdx, new_idom: VnIdx, graph: &SignatureGraph, post_order: &[VnIdx]) -> VnIdx {
        let mut finger1 = graph.entries[rho.0].index;
        let mut finger2 = graph.entries[new_idom.0].index;
        while finger1 != finger2 {
            while finger1 < finger2 {
                // finger1 = postOrder[finger1]->shadow->index
                let sh = graph.entries[post_order[finger1 as usize].0]
                    .shadow
                    .expect("intersect: missing shadow");
                finger1 = graph.entries[sh.0].index;
            }
            while finger2 < finger1 {
                let sh = graph.entries[post_order[finger2 as usize].0]
                    .shadow
                    .expect("intersect: missing shadow");
                finger2 = graph.entries[sh.0].index;
            }
        }
        post_order[finger1 as usize]
    }

    /// Remove noise from the data-flow graph by collapsing Varnodes that are
    /// indirect copies of each other. Faithful to `removeNoise`
    /// (signature.cc:456-511).
    // Ghidra: signature.cc:456 SignatureEntry::removeNoise
    pub fn remove_noise(graph: &mut SignatureGraph) {
        let mut rootlist: Vec<VnIdx> = Vec::new();
        let mut post_order: Vec<VnIdx> = Vec::new();

        // signature.cc:463-478: build rootlist = inputs/constants + nodes defined
        // by non-marker, non-COPY ops.
        let n = graph.entries.len();
        for i in 0..n {
            let idx = VnIdx(i);
            let is_root = {
                let e = &graph.entries[i];
                let vn = match &e.vn {
                    None => false,
                    Some(v) => {
                        let vrg = v.read().unwrap();
                        if vrg.is_input() || vrg.is_constant() {
                            true
                        } else if vrg.is_written() {
                            // Need to check defining op. Read op outside the
                            // Varnode borrow to avoid nested borrows.
                            let def_is_non_marker_non_copy = v
                                .read()
                                .unwrap()
                                .get_def()
                                .map(|d| {
                                    let drg = d.read().unwrap();
                                    !drg.is_marker() && drg.get_opcode() != OpCode::CPUI_COPY
                                })
                                .unwrap_or(false);
                            drop(vrg);
                            def_is_non_marker_non_copy
                        } else {
                            false
                        }
                    }
                };
                vn
            };
            if is_root {
                rootlist.push(idx);
                graph.entries[i].flags |= entry_flags::MARKER_ROOT;
            }
        }

        Self::noise_post_order(&rootlist, &mut post_order, graph);

        // signature.cc:484-485: create virtual root and append to postOrder.
        let virtual_root_idx = graph.push_virtual(SignatureEntry::new_virtual(post_order.len() as i32));
        post_order.push(virtual_root_idx);
        // signature.cc:486-487: roots' shadow points to virtual root.
        for &root in &rootlist {
            graph.entries[root.0].shadow = Some(virtual_root_idx);
        }

        Self::noise_dominator(&post_order, graph, virtual_root_idx);
        // Pop virtual root from postOrder (signature.cc:490).
        let _ = post_order.pop();

        // signature.cc:492-497: shadow bases (dominated by virtual root) get null shadow.
        for &entry in &post_order {
            if graph.entries[entry.0].shadow == Some(virtual_root_idx) {
                graph.entries[entry.0].shadow = None;
            }
        }
        // signature.cc:498-510: collapse the dominator tree to the shadow bases
        // (path compression).
        for &entry in &post_order {
            // Walk up to the base, compressing the path.
            let mut base = entry;
            while let Some(sh) = graph.entries[base.0].shadow {
                base = sh;
            }
            let mut cur = entry;
            while let Some(sh) = graph.entries[cur.0].shadow {
                let tmp = cur;
                cur = sh;
                graph.entries[tmp.0].shadow = Some(base);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BlockSignatureEntry: control-flow feature generation node.
// ---------------------------------------------------------------------------

/// A node for control-flow feature generation. Faithful to `BlockSignatureEntry`
/// (signature.hh:167-177). A node is rooted at a specific basic block and
/// iteratively hashes information about the block and its nearest neighbors
/// through the edges of the control-flow graph.
// Ghidra: signature.hh:167 BlockSignatureEntry
pub struct BlockSignatureEntry {
    /// The root basic block. Faithful to `bl` (signature.hh:168). Stored as a
    /// block index because Rust trait objects cannot be cheaply copied.
    // RUGRA-GLUE: block index replaces Ghidra BlockBasic*.
    pub block_index: i32,
    /// Number of incoming edges (cached at construction for hashIn's
    /// reverse-index lookups).
    // RUGRA-GLUE: cached from bl->sizeIn() so hashIn does not need the block.
    pub size_in: i32,
    /// Current and previous hash. Faithful to `hashword hash[2]`
    /// (signature.hh:169).
    pub hash: [u64; 2],
}

impl BlockSignatureEntry {
    /// Construct from a basic block. Faithful to
    /// `BlockSignatureEntry(BlockBasic *b)` (signature.hh:171).
    // Ghidra: signature.hh:171 BlockSignatureEntry::BlockSignatureEntry
    pub fn new(block_index: i32, size_in: i32) -> Self {
        Self { block_index, size_in, hash: [0, 0] }
    }

    /// Compute an initial hash based on local properties of the basic block.
    /// Faithful to `localHash` (signature.cc:573-580). The hash incorporates the
    /// number of incoming and outgoing edges.
    // Ghidra: signature.cc:573 BlockSignatureEntry::localHash
    pub fn local_hash(&mut self, size_in: i64, size_out: i64) {
        // signature.cc:576-579
        let mut localhash: u64 = size_in as u64;
        localhash <<= 8;
        localhash |= size_out as u64;
        self.hash[0] = localhash;
    }

    /// Store hash from previous iteration. Faithful to `flip`
    /// (signature.hh:173).
    // Ghidra: signature.hh:173 BlockSignatureEntry::flip
    pub fn flip(&mut self) { self.hash[1] = self.hash[0]; }

    /// Get the current hash value. Faithful to `getHash` (signature.hh:176).
    // Ghidra: signature.hh:176 BlockSignatureEntry::getHash
    pub fn get_hash(&self) -> u64 { self.hash[0] }

    /// Get the underlying basic block index.
    // RUGRA-GLUE: accessor (Ghidra returns BlockBasic*).
    pub fn get_block(&self) -> i32 { self.block_index }
}

// ---------------------------------------------------------------------------
// SigManager: base feature container.
// ---------------------------------------------------------------------------

/// Signature settings, shared across all managers. Faithful to the static
/// `uint4 SigManager::settings` (signature.hh:234). Rust uses a Mutex-protected
/// static because mutable statics are unsafe.
// RUGRA-GLUE: Mutex<Option<u32>> replaces Ghidra mutable static (user must set).
static SIG_SETTINGS: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);

/// Holds the settings static accessors. Faithful to `SigManager::settings`
/// (signature.hh:234, signature.cc:21).
pub struct SigSettings;

impl SigSettings {
    /// Get the settings currently being used for signature generation. Faithful
    /// to `getSettings` (signature.hh:254). Returns 0 if unset (Ghidra starts
    /// with 0 and requires the user to set a valid value).
    // Ghidra: signature.hh:254 SigManager::getSettings
    pub fn get() -> u32 {
        SIG_SETTINGS.lock().unwrap().unwrap_or(0)
    }

    /// Establish settings to use for future signature generation. Faithful to
    /// `setSettings` (signature.hh:255, signature.cc:740-744).
    // Ghidra: signature.hh:255 SigManager::setSettings
    pub fn set(newvalue: u32) {
        *SIG_SETTINGS.lock().unwrap() = Some(newvalue);
    }
}

/// A container for collecting a set of features (a feature vector) for a single
/// function. Faithful to `SigManager` (signature.hh:233-256).
// Ghidra: signature.hh:233 SigManager
pub struct SigManager {
    /// Feature set for the current function. Faithful to `vector<Signature*>`
    /// (signature.hh:235).
    pub sigs: Vec<SignatureFeature>,
    /// Current function off of which we are generating features. Faithful to
    /// `const Funcdata *fd` (signature.hh:238).
    pub fd: Option<Arc<RwLock<Funcdata>>>,
}

impl SigManager {
    /// Constructor. Faithful to `SigManager()` (signature.hh:241) which sets
    /// fd to null.
    // Ghidra: signature.hh:241 SigManager::SigManager
    pub fn new() -> Self {
        Self { sigs: Vec::new(), fd: None }
    }

    /// Add a new feature to the manager. Faithful to the protected
    /// `addSignature` (signature.hh:239).
    // Ghidra: signature.hh:239 SigManager::addSignature
    pub fn add_signature(&mut self, sig: SignatureFeature) {
        self.sigs.push(sig);
    }

    /// Clear all current Signature/feature objects from this manager. Faithful
    /// to `clearSignatures` (signature.cc:669-675).
    // Ghidra: signature.cc:669 SigManager::clearSignatures
    pub fn clear_signatures(&mut self) {
        self.sigs.clear();
    }

    /// Clear all resources. Faithful to `clear` (signature.cc:679-683).
    // Ghidra: signature.cc:679 SigManager::clear
    pub fn clear(&mut self) {
        self.clear_signatures();
    }

    /// Set the function used for (future) feature generation. Faithful to
    /// `setCurrentFunction` (signature.cc:686-690).
    // Ghidra: signature.cc:686 SigManager::setCurrentFunction
    pub fn set_current_function(&mut self, f: Arc<RwLock<Funcdata>>) {
        self.fd = Some(f);
    }

    /// Get the number of features currently generated. Faithful to
    /// `numSignatures` (signature.hh:247).
    // Ghidra: signature.hh:247 SigManager::numSignatures
    pub fn num_signatures(&self) -> usize { self.sigs.len() }

    /// Get the i-th Signature/feature. Faithful to `getSignature`
    /// (signature.hh:248).
    // Ghidra: signature.hh:248 SigManager::getSignature
    pub fn get_signature(&self, i: usize) -> &SignatureFeature { &self.sigs[i] }

    /// Get the feature vector as a simple sorted array of hashes. Faithful to
    /// `getSignatureVector` (signature.cc:695-702).
    // Ghidra: signature.cc:695 SigManager::getSignatureVector
    pub fn get_signature_vector(&self) -> Vec<u32> {
        let mut feature: Vec<u32> = self.sigs.iter().map(|s| s.get_hash()).collect();
        feature.sort_unstable();
        feature
    }

    /// Combine all feature hashes into one overall hash. Faithful to
    /// `getOverallHash` (signature.cc:705-714).
    // Ghidra: signature.cc:705 SigManager::getOverallHash
    pub fn get_overall_hash(&self) -> u64 {
        let feature = self.get_signature_vector();
        let mut pool: u64 = 0x12349876abacab;
        for &h in &feature {
            pool = hash_mixin(pool, h as u64);
        }
        pool
    }

    /// Sort all current features by hash. Faithful to `sortByHash`
    /// (signature.hh:251).
    // Ghidra: signature.hh:251 SigManager::sortByHash
    pub fn sort_by_hash(&mut self) {
        self.sigs.sort_by(|a, b| a.get_hash().cmp(&b.get_hash()));
    }

    /// Print a brief description of all current features. Faithful to `print`
    /// (signature.cc:719-725).
    // Ghidra: signature.cc:719 SigManager::print
    pub fn print(&self, s: &mut String) {
        for sig in &self.sigs {
            match sig {
                SignatureFeature::Plain(p) => p.print(s),
                SignatureFeature::Varnode(v) => {
                    s.push('*');
                    v.print_origin(s);
                    s.push_str(&format!(" = 0x{:08x}\n", v.get_hash()));
                }
                SignatureFeature::Block(b) => {
                    s.push('*');
                    s.push_str(&format!("block {} = 0x{:08x}\n", b.block_index, b.get_hash()));
                }
                SignatureFeature::Copy(c) => {
                    s.push('*');
                    c.print_origin(s);
                    s.push_str(&format!(" = 0x{:08x}\n", c.get_hash()));
                }
            }
        }
    }

    /// Encode all current features to the stream. Faithful to `encode`
    /// (signature.cc:729-737).
    // Ghidra: signature.cc:729 SigManager::encode
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&ELEM_SIGNATUREDESC.get());
        for sig in &self.sigs {
            sig.encode(encoder);
        }
        encoder.close_element(&ELEM_SIGNATUREDESC.get());
    }
}

impl Default for SigManager {
    // RUGRA-GLUE: Rust Default delegates to SigManager::new; C++ has no Default-trait entry point.
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// GraphSigManager: data-flow + control-flow feature generation.
// ---------------------------------------------------------------------------

/// A manager for generating Signatures/features on function data-flow and
/// control-flow. Faithful to `GraphSigManager` (signature.hh:265-303).
// Ghidra: signature.hh:265 GraphSigManager
pub struct GraphSigManager {
    /// The base manager state.
    // RUGRA-GLUE: Rust composes rather than inherits from SigManager.
    pub base: SigManager,
    /// Current settings to use for signature generation. Faithful to `sigmods`
    /// (signature.hh:277).
    pub sigmods: u32,
    /// Maximum number of iterations across data-flow graph. Faithful to
    /// `maxiter` (signature.hh:278).
    pub maxiter: i32,
    /// Maximum number of block iterations. Faithful to `maxblockiter`
    /// (signature.hh:279).
    pub maxblockiter: i32,
    /// Maximum number of Varnodes to signature. Faithful to `maxvarnode`
    /// (signature.hh:280).
    pub maxvarnode: i32,
    /// Map from Varnode to SignatureEntry overlay. Faithful to
    /// `map<int4,SignatureEntry*> sigmap` (signature.hh:281), realized as an
    /// arena.
    pub sigmap: SignatureGraph,
    /// Map from basic block to BlockSignatureEntry overlay. Faithful to
    /// `map<int4,BlockSignatureEntry*> blockmap` (signature.hh:282).
    pub blockmap: HashMap<i32, BlockSignatureEntry>,
}

impl GraphSigManager {
    /// Constructor. Faithful to `GraphSigManager()` (signature.cc:926-937).
    /// Reads the global settings, validates them, and sets the modifier bits and
    /// iteration limits.
    // Ghidra: signature.cc:926 GraphSigManager::GraphSigManager
    pub fn new() -> Self {
        let setting = SigSettings::get();
        if !Self::test_settings(setting) {
            // Ghidra throws LowlevelError("Bad signature settings"). Rugra
            // panics equivalently since the caller must set valid settings.
            panic!("Bad signature settings");
        }
        Self {
            base: SigManager::new(),
            sigmods: setting >> 2,
            maxiter: 3,
            maxblockiter: 1,
            maxvarnode: 0,
            sigmap: SignatureGraph::new(),
            blockmap: HashMap::new(),
        }
    }

    /// Override the default iterations used for Varnode features. Faithful to
    /// `setMaxIteration` (signature.hh:296).
    // Ghidra: signature.hh:296 GraphSigManager::setMaxIteration
    pub fn set_max_iteration(&mut self, val: i32) { self.maxiter = val; }

    /// Override the default iterations used for block features. Faithful to
    /// `setMaxBlockIteration` (signature.hh:297).
    // Ghidra: signature.hh:297 GraphSigManager::setMaxBlockIteration
    pub fn set_max_block_iteration(&mut self, val: i32) { self.maxblockiter = val; }

    /// Set a maximum threshold for Varnodes in a function. Faithful to
    /// `setMaxVarnode` (signature.hh:298).
    // Ghidra: signature.hh:298 GraphSigManager::setMaxVarnode
    pub fn set_max_varnode(&mut self, val: i32) { self.maxvarnode = val; }

    /// Test for valid signature generation settings. Faithful to `testSettings`
    /// (signature.cc:914-924). A 0 setting is not allowed; only the documented
    /// modifier bits (shifted left by 2) plus the check bit may be set.
    // Ghidra: signature.cc:914 GraphSigManager::testSettings
    pub fn test_settings(val: u32) -> bool {
        // signature.cc:914-924: bit 0 (check bit) must be set.
        if (val & 1) == 0 {
            return false;
        }
        let mask = sig_mods::SIG_COLLAPSE_SIZE
            | sig_mods::SIG_DONOTUSE_CONST
            | sig_mods::SIG_DONOTUSE_INPUT
            | sig_mods::SIG_DONOTUSE_PERSIST
            | sig_mods::SIG_COLLAPSE_INDNOISE;
        let mask = (mask << 2) | 1; // Add the check bit.
        (val & !mask) == 0
    }

    /// Clear all SignatureEntry overlay objects. Faithful to `varnodeClear`
    /// (signature.cc:878-887).
    // Ghidra: signature.cc:878 GraphSigManager::varnodeClear
    pub fn varnode_clear(&mut self) {
        self.sigmap.entries.clear();
        self.sigmap.create_to_slot.clear();
    }

    /// Clear all BlockSignatureEntry overlay objects. Faithful to `blockClear`
    /// (signature.cc:889-897).
    // Ghidra: signature.cc:889 GraphSigManager::blockClear
    pub fn block_clear(&mut self) {
        self.blockmap.clear();
    }

    /// Clear all resources. Faithful to `clear` (signature.cc:939-945).
    // Ghidra: signature.cc:939 GraphSigManager::clear
    pub fn clear(&mut self) {
        self.varnode_clear();
        self.block_clear();
        self.base.clear();
    }

    /// Set the function used for (future) feature generation. Faithful to
    /// `setCurrentFunction` (signature.cc:960-990).
    // Ghidra: signature.cc:960 GraphSigManager::setCurrentFunction
    pub fn set_current_function(&mut self, f: Arc<RwLock<Funcdata>>) {
        self.base.set_current_function(f.clone());

        // signature.cc:965-968: enforce maxvarnode threshold.
        let varnode_count: usize = {
            let fd_rg = f.read().unwrap();
            fd_rg.vbank.begin_loc().count()
        };
        if self.maxvarnode != 0 && (varnode_count as i32) > self.maxvarnode {
            let name = f.read().unwrap().get_name().to_string();
            panic!("{} exceeds size threshold for generating signatures", name);
        }

        // signature.cc:970-974: build a SignatureEntry for every Varnode.
        let varnodes: Vec<Arc<RwLock<Varnode>>> = {
            let fd_rg = f.read().unwrap();
            fd_rg.vbank.begin_loc().map(|r: &VarnodeLocRef| r.0.clone()).collect()
        };
        for vn in varnodes {
            let entry = SignatureEntry::new(vn, self.sigmods);
            self.sigmap.push_root(entry);
        }

        // signature.cc:976-985: noise removal or per-node shadow calculation.
        if (self.sigmods & sig_mods::SIG_COLLAPSE_INDNOISE) != 0 {
            SignatureEntry::remove_noise(&mut self.sigmap);
        } else {
            self.sigmap.calculate_shadows_all();
        }

        // signature.cc:986-989: localHash on every entry.
        for i in 0..self.sigmap.entries.len() {
            self.sigmap.entries[i].local_hash(self.sigmods);
        }
    }

    /// Store current Varnode hash values as previous. Faithful to `flipVarnodes`
    /// (signature.cc:992-1001).
    // Ghidra: signature.cc:992 GraphSigManager::flipVarnodes
    pub fn flip_varnodes(&mut self) {
        for e in self.sigmap.entries.iter_mut() {
            e.flip();
        }
    }

    /// Store current block hash values as previous. Faithful to `flipBlocks`
    /// (signature.cc:1003-1012).
    // Ghidra: signature.cc:1003 GraphSigManager::flipBlocks
    pub fn flip_blocks(&mut self) {
        for e in self.blockmap.values_mut() {
            e.flip();
        }
    }

    /// Do one iteration of hashing on the SignatureEntrys. Faithful to
    /// `signatureIterate` (signature.cc:1016-1037).
    // Ghidra: signature.cc:1016 GraphSigManager::signatureIterate
    pub fn signature_iterate(&mut self) {
        self.flip_varnodes();
        // Collect the work items first (entry index + its neighbour indices) so
        // the actual hashIn round can be applied via apply_hash_in_round, which
        // scopes the disjoint &self / &mut borrow within one method body.
        let mut work: Vec<(VnIdx, Vec<VnIdx>)> = Vec::new();
        for i in 0..self.sigmap.entries.len() {
            let idx = VnIdx(i);
            let e = &self.sigmap.entries[i];
            // signature.cc:1027-1028: skip non-emitted and terminal nodes.
            if e.is_not_emitted() {
                continue;
            }
            if e.is_terminal() {
                continue;
            }
            let num = e.num_inputs();
            let mut neigh: Vec<VnIdx> = Vec::with_capacity(num as usize);
            for j in 0..num {
                neigh.push(e.get_in(j, &self.sigmap));
            }
            work.push((idx, neigh));
        }
        self.sigmap.apply_hash_in_round(&work);
    }

    /// Do one iteration of hashing on the BlockSignatureEntrys. Faithful to
    /// `signatureBlockIterate` (signature.cc:1041-1061).
    // Ghidra: signature.cc:1041 GraphSigManager::signatureBlockIterate
    pub fn signature_block_iterate(&mut self, fd: &Arc<RwLock<Funcdata>>) {
        self.flip_blocks();
        // Snapshot the work items (block index, neighbour indices, incoming edge
        // metadata) so we can compute hash_in without holding overlapping
        // borrows on blockmap.
        struct BlockWork {
            index: i32,
            neigh_indices: Vec<i32>,
            incoming_size_out: Vec<i32>,
            rev_indices: Vec<i32>,
        }
        let mut work: Vec<BlockWork> = Vec::new();
        let block_count = fd.read().unwrap().bblocks.get_size();
        for i in 0..block_count {
            let blk_arc = fd.read().unwrap().bblocks.get_block(i)
                .expect("signatureBlockIterate: missing block");
            let blk_rg = blk_arc.read().unwrap();
            let index = blk_rg.get_index();
            let size_in = blk_rg.size_in();
            let mut neigh_indices = Vec::with_capacity(size_in);
            let mut incoming_size_out = Vec::with_capacity(size_in);
            let mut rev_indices = Vec::with_capacity(size_in);
            let bank = blk_rg.bank();
            for j in 0..size_in {
                if let Some(edge) = blk_rg.get_in(j) {
                    let in_index = bank.expect_index(edge.point);
                    neigh_indices.push(in_index);
                    incoming_size_out
                        .push(bank.expect_arc(edge.point).read().unwrap().size_out() as i32);
                    rev_indices.push(blk_rg.get_in_rev_index(j));
                }
            }
            work.push(BlockWork { index, neigh_indices, incoming_size_out, rev_indices });
        }
        // Apply hash_in per block (faithful to BlockSignatureEntry::hashIn).
        for w in &work {
            // Gather neighbour hashes via immutable borrows, then write target.
            let neigh_hashes: Vec<u64> = w.neigh_indices
                .iter()
                .map(|idx| {
                    self.blockmap.get(idx)
                        .expect("signatureBlockIterate: block not in blockmap")
                        .hash[1]
                })
                .collect();
            let curhash = self.blockmap.get(&w.index)
                .expect("signatureBlockIterate: target not in blockmap")
                .hash[1];
            // signature.cc:589-603: order-invariant accumulation with CBRANCH
            // condition mixing.
            let local_curhash = curhash;
            let mut accum: u64 = 0xbafabaca;
            for k in 0..neigh_hashes.len() {
                let mut tmphash = hash_mixin(local_curhash, neigh_hashes[k]);
                if w.incoming_size_out[k] == 2 {
                    if w.rev_indices[k] == 0 {
                        tmphash = hash_mixin(tmphash, 0x777u64 ^ 0x7abc7abcu64);
                    } else {
                        tmphash = hash_mixin(tmphash, 0x777u64);
                    }
                }
                accum = accum.wrapping_add(tmphash);
            }
            let new_hash = hash_mixin(local_curhash, accum);
            self.blockmap.get_mut(&w.index)
                .expect("signatureBlockIterate: target not in blockmap")
                .hash[0] = new_hash;
        }
    }

    /// Initialize BlockSignatureEntry overlays for the current function.
    /// Faithful to `initializeBlocks` (signature.cc:899-911).
    // Ghidra: signature.cc:901 GraphSigManager::initializeBlocks
    pub fn initialize_blocks(&mut self, fd: &Arc<RwLock<Funcdata>>) {
        let n = fd.read().unwrap().bblocks.get_size();
        for i in 0..n {
            let blk_arc = fd.read().unwrap().bblocks.get_block(i)
                .expect("initializeBlocks: missing block");
            let blk_rg = blk_arc.read().unwrap();
            let index = blk_rg.get_index();
            let size_in = blk_rg.size_in() as i32;
            let size_out = blk_rg.size_out() as i64;
            let mut entry = BlockSignatureEntry::new(index, size_in);
            entry.local_hash(size_in as i64, size_out);
            self.blockmap.insert(index, entry);
        }
    }
}

impl GraphSigManager {
    /// Emit the final hash value for all Varnodes as VarnodeSignature features.
    /// Faithful to `collectVarnodeSigs` (signature.cc:747-760).
    // Ghidra: signature.cc:747 GraphSigManager::collectVarnodeSigs
    pub fn collect_varnode_sigs(&mut self) {
        // Snapshot which entries to emit and their data, so we don't hold a
        // borrow on sigmap while pushing into base.sigs.
        let mut to_emit: Vec<(Arc<RwLock<Varnode>>, u64)> = Vec::new();
        for e in self.sigmap.entries.iter() {
            if e.is_not_emitted() {
                continue;
            }
            if let Some(vn) = e.get_varnode() {
                to_emit.push((vn.clone(), e.get_hash()));
            }
        }
        for (vn, h) in to_emit {
            let vsig = VarnodeSignature::new(vn, h);
            self.base.add_signature(SignatureFeature::Varnode(vsig));
        }
    }

    /// Generate the final feature(s) for each basic block from its
    /// BlockSignatureEntry overlay. Faithful to `collectBlockSigs`
    /// (signature.cc:767-876).
    // Ghidra: signature.cc:767 GraphSigManager::collectBlockSigs
    pub fn collect_block_sigs(&mut self, fd: &Arc<RwLock<Funcdata>>) {
        // Snapshot per-block ops and local hash so we don't hold overlapping
        // borrows on sigmap/blockmap/base.sigs.
        struct BlockSigWork {
            block_index: i32,
            start_addr: Address,
            ops: Vec<PcodeOpRef>,
            local_hash: u64,
        }
        let mut work: Vec<BlockSigWork> = Vec::new();
        let block_count = fd.read().unwrap().bblocks.get_size();
        for i in 0..block_count {
            let blk_arc = fd.read().unwrap().bblocks.get_block(i)
                .expect("collectBlockSigs: missing block");
            let block_index = blk_arc.read().unwrap().get_index();
            let start_addr = blk_arc.read().unwrap().get_start_addr();
            let ops = blk_arc.read().unwrap().get_ops();
            let local_hash = self.blockmap
                .get(&block_index)
                .expect("collectBlockSigs: block not in blockmap")
                .get_hash();
            work.push(BlockSigWork { block_index, start_addr, ops, local_hash });
        }

        for w in &work {
            let mut lastop: Option<PcodeOpRef> = None;
            let mut lasthash: u64 = 0;
            let mut callhash: u64 = 0;
            let mut copyhash: u64 = 0;
            for op_ref in &w.ops {
                let code = op_ref.0.read().unwrap().get_opcode();
                // signature.cc:792-839: classify op and set startind/stopind.
                let (startind, stopind, contributes) = match code {
                    // signature.cc:793-799
                    OpCode::CPUI_CALL => {
                        callhash = callhash.wrapping_add(100001);
                        callhash = callhash.wrapping_mul(0x78abbf);
                        (1i32, op_ref.0.read().unwrap().num_input() as i32, true)
                    }
                    // signature.cc:800-806
                    OpCode::CPUI_CALLIND => {
                        callhash = callhash.wrapping_add(123451);
                        callhash = callhash.wrapping_mul(0x78abbf);
                        (1i32, op_ref.0.read().unwrap().num_input() as i32, true)
                    }
                    // signature.cc:807-811
                    OpCode::CPUI_CALLOTHER => {
                        (1i32, op_ref.0.read().unwrap().num_input() as i32, true)
                    }
                    // signature.cc:812-815
                    OpCode::CPUI_STORE => {
                        (1i32, op_ref.0.read().unwrap().num_input() as i32, true)
                    }
                    // signature.cc:816-819
                    OpCode::CPUI_CBRANCH => (1i32, 2i32, true),
                    // signature.cc:820-823
                    OpCode::CPUI_BRANCHIND => (0i32, 1i32, true),
                    // signature.cc:824-827
                    OpCode::CPUI_RETURN => {
                        (1i32, op_ref.0.read().unwrap().num_input() as i32, true)
                    }
                    // signature.cc:828-834: INDIRECT/COPY feed copyhash.
                    OpCode::CPUI_INDIRECT | OpCode::CPUI_COPY => {
                        // signature.cc:830-833
                        let outvn = op_ref.0.read().unwrap().get_out().cloned();
                        if let Some(out) = outvn {
                            let out_idx = self.sigmap.map_to_entry(&out);
                            if self.sigmap.entries[out_idx.0].is_standalone_copy() {
                                copyhash = copyhash.wrapping_add(self.sigmap.entries[out_idx.0].get_hash());
                            }
                        }
                        continue;
                    }
                    // signature.cc:835-838: default - don't use.
                    _ => (0i32, 0i32, false),
                };
                let _ = contributes;
                // signature.cc:840-857: compute val from output or op inputs.
                let outvn = op_ref.0.read().unwrap().get_out().cloned();
                let val: Option<u64> = if stopind == 0 && (outvn.is_none()
                    || !outvn.as_ref().unwrap().read().unwrap().has_no_descend())
                {
                    // signature.cc:841: skip if no output or output has descendants.
                    None
                } else if let Some(out) = &outvn {
                    // signature.cc:842-845: use output entry's hash if emitted.
                    let out_idx = self.sigmap.map_to_entry(out);
                    if self.sigmap.entries[out_idx.0].is_not_emitted() {
                        None
                    } else {
                        Some(self.sigmap.entries[out_idx.0].get_hash())
                    }
                } else {
                    // signature.cc:847-857: no output - hash opcode + inputs.
                    let mut v: u64 = code as u64;
                    v = v ^ (v << 9) ^ (v << 18);
                    let mut accum: u64 = 0;
                    let op_rg = op_ref.0.read().unwrap();
                    for k in startind..stopind {
                        if let Some(inv) = op_rg.get_in(k as usize) {
                            let collapse_idx = self.sigmap.map_to_entry_collapse(inv);
                            let tmphash = hash_mixin(v, self.sigmap.entries[collapse_idx.0].get_hash());
                            accum = accum.wrapping_add(tmphash);
                        }
                    }
                    drop(op_rg);
                    v ^= accum;
                    Some(v)
                };
                let val = match val {
                    None => continue,
                    Some(v) => v,
                };
                // signature.cc:858-865: form the block feature.
                let finalhash = if lastop.is_none() {
                    hash_mixin(val, w.local_hash)
                } else {
                    hash_mixin(val, lasthash)
                };
                let bsig = BlockSignature::new(
                    w.block_index,
                    w.start_addr,
                    finalhash,
                    lastop.clone(),
                    Some(op_ref.clone()),
                );
                self.base.add_signature(SignatureFeature::Block(bsig));
                lastop = Some(op_ref.clone());
                lasthash = val;
            }
            // signature.cc:867-874: block-info-only feature + call/copy features.
            let mut finalhash = hash_mixin(w.local_hash, 0x9b1c5fu64);
            if callhash != 0 {
                finalhash = hash_mixin(finalhash, callhash);
            }
            self.base.add_signature(SignatureFeature::Block(BlockSignature::new(
                w.block_index,
                w.start_addr,
                finalhash,
                None,
                None,
            )));
            if copyhash != 0 {
                copyhash = hash_mixin(copyhash, 0xa2de3cu64);
                self.base.add_signature(SignatureFeature::Copy(CopySignature::new(
                    w.block_index,
                    copyhash,
                )));
            }
        }
    }

    /// Generate all features for the current function. Faithful to `generate`
    /// (signature.cc:1063-1091).
    // Ghidra: signature.cc:1063 GraphSigManager::generate
    pub fn generate(&mut self, fd: &Arc<RwLock<Funcdata>>) {
        // signature.cc:1068-1070
        let minusone = self.maxiter - 1;
        let firsthalf = minusone / 2;
        let secondhalf = minusone - firsthalf;
        // signature.cc:1071
        self.signature_iterate();
        // signature.cc:1072-1073
        for _ in 0..firsthalf {
            self.signature_iterate();
        }

        // signature.cc:1076-1083: block signatures incorporating varnode sigs
        // halfway through.
        if self.maxblockiter >= 0 {
            self.initialize_blocks(fd);
            for _ in 0..self.maxblockiter {
                self.signature_block_iterate(fd);
            }
            self.collect_block_sigs(fd);
            self.block_clear();
        }

        // signature.cc:1085-1086
        for _ in 0..secondhalf {
            self.signature_iterate();
        }

        // signature.cc:1088
        self.collect_varnode_sigs();

        // signature.cc:1090: varnodes are used in block sigs; clear afterwards.
        self.varnode_clear();
    }
}

impl Default for GraphSigManager {
    // RUGRA-GLUE: Rust Default delegates to GraphSigManager::new; C++ has no Default-trait entry point.
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Free functions: simpleSignature / debugSignature.
// ---------------------------------------------------------------------------

/// Check if a function has any P-code ops marked UNIMPLEMENTED. Faithful to
/// `Funcdata::hasUnimplemented` (funcdata.hh) which scans the op bank.
// Ghidra: funcdata.hh Funcdata::hasUnimplemented (scanned here from obank).
pub fn has_unimplemented(fd: &Arc<RwLock<Funcdata>>) -> bool {
    let fd_rg = fd.read().unwrap();
    fd_rg.obank.iter_alive().any(|op_ref| {
        (op_ref.0.read().unwrap().flags & pcodeop_flags::UNIMPLEMENTED) != 0
    })
}

/// Check if a function flowed into bad data. Faithful to
/// `Funcdata::hasBadData` (funcdata.hh) which scans the op bank.
// Ghidra: funcdata.hh Funcdata::hasBadData (scanned here from obank).
pub fn has_bad_data(fd: &Arc<RwLock<Funcdata>>) -> bool {
    let fd_rg = fd.read().unwrap();
    fd_rg.obank.iter_alive().any(|op_ref| {
        (op_ref.0.read().unwrap().flags & pcodeop_flags::BADINSTRUCTION) != 0
    })
}

/// Generate features for a single function and write them to the encoder as a
/// simple sequence of hash values. Faithful to `simpleSignature`
/// (signature.cc:1099-1131).
///
/// No additional information about the features is written. If function
/// decompilation failed due to flow into bad data or unimplemented
/// instructions, an error condition is encoded to the stream.
// Ghidra: signature.cc:1099 simpleSignature
pub fn simple_signature(fd: &Arc<RwLock<Funcdata>>, encoder: &mut dyn Encoder) {
    let mut sigmanager = GraphSigManager::new();
    sigmanager.set_current_function(fd.clone());
    sigmanager.generate(fd);
    let feature = sigmanager.base.get_signature_vector();
    encoder.open_element(&ELEM_SIGNATURES.get());
    // signature.cc:1110-1113
    if has_unimplemented(fd) {
        encoder.write_bool(&ATTRIB_UNIMPL.get(), true);
    }
    if has_bad_data(fd) {
        encoder.write_bool(&ATTRIB_BADDATA.get(), true);
    }
    // signature.cc:1114-1118
    for &h in &feature {
        encoder.open_element(&ELEM_SIG.get());
        encoder.write_unsigned_integer(&ATTRIB_VAL.get(), h as u64);
        encoder.close_element(&ELEM_SIG.get());
    }
    // signature.cc:1119-1129: emit call targets.
    let numcalls = fd.read().unwrap().num_calls();
    for i in 0..numcalls {
        let entry_addr = fd
            .read()
            .unwrap()
            .get_call_specs(i)
            .and_then(|fc| fc.entry_addr);
        if let Some(addr) = entry_addr {
            // Ghidra checks !addr.isInvalid(); Rugra uses the Option presence.
            if !addr.is_null() {
                encoder.open_element(&ELEM_CALL.get());
                // signature.cc:1125: writeSpace(ATTRIB_SPACE, addr.getSpace()).
                // Rugra has a single address space, so we emit only the offset.
                // RUGRA-GLUE: single-space model omits writeSpace.
                encoder.write_unsigned_integer(&ATTRIB_OFFSET.get(), addr.as_u64());
                encoder.close_element(&ELEM_CALL.get());
            }
        }
    }
    encoder.close_element(&ELEM_SIGNATURES.get());
}

/// Generate features for a function and write a complete description of each
/// feature to the encoder. Faithful to `debugSignature`
/// (signature.cc:1137-1146).
// Ghidra: signature.cc:1137 debugSignature
pub fn debug_signature(fd: &Arc<RwLock<Funcdata>>, encoder: &mut dyn Encoder) {
    let mut sigmanager = GraphSigManager::new();
    sigmanager.set_current_function(fd.clone());
    sigmanager.generate(fd);
    sigmanager.base.sort_by_hash();
    sigmanager.base.encode(encoder);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_mixin_deterministic() {
        // hash_mixin is deterministic and depends on both inputs.
        let a = hash_mixin(0x123456789abcdef0, 0xfedcba9876543210);
        let b = hash_mixin(0x123456789abcdef0, 0xfedcba9876543210);
        assert_eq!(a, b);
        let c = hash_mixin(0x123456789abcdef0, 0x0fedcba987654321);
        assert_ne!(a, c);
    }

    #[test]
    fn test_hash_mixin_zero() {
        // hash_mixin(0, 0) drives crc_update(0,0)=0 eight times -> 0.
        assert_eq!(hash_mixin(0, 0), 0);
    }

    #[test]
    fn test_signature_new_truncates_to_32bit() {
        // Signature::sig is uint4 (32-bit) even though hashword is 64-bit.
        let s = Signature::new(0x1_0000_0005);
        assert_eq!(s.get_hash(), 5);
    }

    #[test]
    fn test_signature_compare() {
        let a = Signature::new(10);
        let b = Signature::new(20);
        let c = Signature::new(20);
        assert_eq!(a.compare(&b), -1);
        assert_eq!(b.compare(&a), 1);
        assert_eq!(b.compare(&c), 0);
    }

    #[test]
    fn test_signature_compare_ptr() {
        let a = Signature::new(10);
        let b = Signature::new(20);
        assert!(Signature::compare_ptr(&a, &b));
        assert!(!Signature::compare_ptr(&b, &a));
    }

    #[test]
    fn test_signature_print() {
        let s = Signature::new(0xdeadbeef);
        let mut out = String::new();
        s.print(&mut out);
        assert!(out.contains("0xdeadbeef"));
        assert!(out.starts_with('*'));
    }

    #[test]
    fn test_sig_mods_values() {
        // Faithful to GraphSigManager::Mods (signature.hh:269-274).
        assert_eq!(sig_mods::SIG_COLLAPSE_SIZE, 0x1);
        assert_eq!(sig_mods::SIG_COLLAPSE_INDNOISE, 0x2);
        assert_eq!(sig_mods::SIG_DONOTUSE_CONST, 0x10);
        assert_eq!(sig_mods::SIG_DONOTUSE_INPUT, 0x20);
        assert_eq!(sig_mods::SIG_DONOTUSE_PERSIST, 0x40);
    }

    #[test]
    fn test_entry_flags_values() {
        // Faithful to SignatureEntry::SignatureFlags (signature.hh:81-86).
        assert_eq!(entry_flags::SIG_NODE_TERMINAL, 0x1);
        assert_eq!(entry_flags::SIG_NODE_COMMUTATIVE, 0x2);
        assert_eq!(entry_flags::SIG_NODE_NOT_EMITTED, 0x4);
        assert_eq!(entry_flags::SIG_NODE_STANDALONE, 0x8);
        assert_eq!(entry_flags::VISITED, 0x10);
        assert_eq!(entry_flags::MARKER_ROOT, 0x20);
    }

    #[test]
    fn test_test_settings_valid() {
        // Faithful to testSettings (signature.cc:914-924).
        assert!(!GraphSigManager::test_settings(0)); // 0 not allowed
        // The suggested default ((SIG_DONOTUSE_CONST | SIG_COLLAPSE_INDNOISE) << 2) | 1
        let val = ((sig_mods::SIG_DONOTUSE_CONST | sig_mods::SIG_COLLAPSE_INDNOISE) << 2) | 1;
        assert!(GraphSigManager::test_settings(val));
        // Check-bit must be set.
        let no_check = (sig_mods::SIG_DONOTUSE_CONST | sig_mods::SIG_COLLAPSE_INDNOISE) << 2;
        assert!(!GraphSigManager::test_settings(no_check));
        // Disallowed bits: bit 1 (value 0x2) is not in the allowed mask, so a
        // value with bit 1 set is invalid even with the check bit set.
        assert!(!GraphSigManager::test_settings(0x1 | 0x2));
    }

    #[test]
    fn test_test_settings_all_allowed_bits() {
        // Each allowed modifier bit, shifted left 2, plus check bit, is valid.
        for m in [
            sig_mods::SIG_COLLAPSE_SIZE,
            sig_mods::SIG_COLLAPSE_INDNOISE,
            sig_mods::SIG_DONOTUSE_CONST,
            sig_mods::SIG_DONOTUSE_INPUT,
            sig_mods::SIG_DONOTUSE_PERSIST,
        ] {
            assert!(GraphSigManager::test_settings((m << 2) | 1));
        }
    }

    #[test]
    fn test_sig_settings_get_set() {
        // SigSettings is a process-wide static; exercise set/get round-trip.
        let prev = SigSettings::get();
        SigSettings::set(0x49);
        assert_eq!(SigSettings::get(), 0x49);
        // Restore so other tests aren't affected.
        if prev != 0 {
            SigSettings::set(prev);
        }
    }

    #[test]
    fn test_block_signature_entry_local_hash() {
        // Faithful to BlockSignatureEntry::localHash (signature.cc:573-580):
        // localhash = sizeIn << 8 | sizeOut.
        let mut e = BlockSignatureEntry::new(0, 2);
        e.local_hash(2, 1);
        let expected: u64 = (2u64) << 8 | 1;
        assert_eq!(e.get_hash(), expected);
    }

    #[test]
    fn test_block_signature_entry_flip() {
        let mut e = BlockSignatureEntry::new(0, 1);
        e.local_hash(3, 1);
        assert_eq!(e.get_hash(), (3 << 8) | 1);
        e.hash[0] = 0xabcdef;
        e.flip();
        assert_eq!(e.hash[1], 0xabcdef);
    }

    #[test]
    fn test_signature_graph_push_root_and_lookup() {
        // A SignatureGraph arena should resolve a varnode to its entry.
        let vn = Arc::new(RwLock::new(Varnode::new_constant(0, 4)));
        let ci = vn.read().unwrap().get_create_index() as i32;
        let mut g = SignatureGraph::new();
        let entry = SignatureEntry { vn: Some(vn.clone()), flags: 0, hash: [0, 0],
            op: None, in_size: 0, startvn: 0, index: -1, shadow: None, create_index: ci };
        g.push_root(entry);
        let idx = g.map_to_entry(&vn);
        assert_eq!(idx.raw(), 0);
    }

    #[test]
    fn test_signature_entry_new_virtual() {
        // Faithful to SignatureEntry(int4 ind) (signature.cc:213).
        let e = SignatureEntry::new_virtual(5);
        assert_eq!(e.index, 5);
        assert!(e.vn.is_none());
        assert!(e.op.is_none());
        assert_eq!(e.shadow, None);
    }

    #[test]
    fn test_signature_feature_enum_hashes() {
        // Each variant should report its base hash.
        let p = SignatureFeature::Plain(Signature::new(42));
        assert_eq!(p.get_hash(), 42);
        let c = SignatureFeature::Copy(CopySignature::new(1, 99));
        assert_eq!(c.get_hash(), 99);
    }

    #[test]
    fn test_sig_manager_vector_sorted() {
        // getSignatureVector returns a sorted array (signature.cc:695-702).
        let mut m = SigManager::new();
        m.add_signature(SignatureFeature::Plain(Signature::new(30)));
        m.add_signature(SignatureFeature::Plain(Signature::new(10)));
        m.add_signature(SignatureFeature::Plain(Signature::new(20)));
        let v = m.get_signature_vector();
        assert_eq!(v, vec![10, 20, 30]);
    }

    #[test]
    fn test_sig_manager_overall_hash_deterministic() {
        // getOverallHash is deterministic (signature.cc:705-714).
        let mut m1 = SigManager::new();
        m1.add_signature(SignatureFeature::Plain(Signature::new(1)));
        m1.add_signature(SignatureFeature::Plain(Signature::new(2)));
        let mut m2 = SigManager::new();
        m2.add_signature(SignatureFeature::Plain(Signature::new(2)));
        m2.add_signature(SignatureFeature::Plain(Signature::new(1)));
        assert_eq!(m1.get_overall_hash(), m2.get_overall_hash());
    }
}
