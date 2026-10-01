//! Large-scale data-flow transforms: lane splitting and Dolphin transforms.
//!
//! Faithful port of Ghidra's `transform.hh` / `transform.cc` (767 lines).
//!
//! This module provides the infrastructure for building large-scale transforms
//! of function data-flow. The main use case is lane splitting — decomposing
//! large register operations into smaller logical "lanes".
//!
//! # Design (Rust adaptation)
//!
//! Ghidra uses raw `TransformVar*` / `TransformOp*` pointers into
//! `list<TransformVar>` / `list<TransformOp>` owned by `TransformManager`.
//! Rugra mirrors this with arena-style ID indexing: `TransformManager` owns
//! `Vec<TransformVar>` and `Vec<TransformOp>`, and references are stable
//! `usize` indices. Split arrays (Ghidra's `new TransformVar[n]`) are stored
//! as contiguous runs whose start index is recorded in `piece_map`.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/transform.{hh,cc}.

use crate::address::{calc_mask, Address};
use crate::funcdata::Funcdata;
use crate::op::PcodeOpRef;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::Varnode;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

// ===========================================================================
// LanedRegister — transform.hh:93-125
// ===========================================================================

/// Describes a (register) storage location and the ways it might be split into
/// lanes. Faithful to `LanedRegister` (transform.hh:93).
///
/// A 1-bit at position N in `size_bit_mask` means lane size N (in bytes) is
/// allowed.
#[derive(Debug, Clone, Default)]
pub struct LanedRegister {
    /// Size of the whole register in bytes.
    pub whole_size: i32,
    /// Bit mask: bit N set means size N is an allowed lane size.
    pub size_bit_mask: u32,
}

impl LanedRegister {
    // Ghidra: transform.hh:94 LanedRegister::withSizes
    /// Construct with a whole size and an initial mask.
    pub fn with_sizes(sz: i32, mask: u32) -> Self {
        Self {
            whole_size: sz,
            size_bit_mask: mask,
        }
    }

    // Ghidra: transform.hh:94 LanedRegister::addLaneSize
    /// Add a new lane size to the allowed list. Faithful to `addLaneSize`
    /// (transform.hh:121).
    pub fn add_lane_size(&mut self, size: i32) {
        self.size_bit_mask |= 1u32 << size;
    }

    // Ghidra: transform.hh:94 LanedRegister::allowedLane
    /// Is `size` among the allowed lane sizes? Faithful to `allowedLane`
    /// (transform.hh:122).
    pub fn allowed_lane(&self, size: i32) -> bool {
        ((self.size_bit_mask >> size) & 1) != 0
    }

    // Ghidra: transform.hh:94 LanedRegister::getWholeSize
    /// Get the whole register size.
    pub fn get_whole_size(&self) -> i32 {
        self.whole_size
    }

    // Ghidra: transform.hh:94 LanedRegister::getSizeBitMask
    /// Get the bit mask of possible lane sizes.
    pub fn get_size_bit_mask(&self) -> u32 {
        self.size_bit_mask
    }

    // Ghidra: transform.cc:300 LanedRegister::parseSizes
    /// Collect specific lane sizes from a comma-separated string. Faithful to
    /// `parseSizes` (transform.cc:300-327).
    pub fn parse_sizes(&mut self, register_size: i32, lane_sizes: &str) {
        self.whole_size = register_size;
        self.size_bit_mask = 0;
        for tok in lane_sizes.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let sz: i32 = tok.parse().unwrap_or(-1);
            if sz < 0 || sz > 16 {
                // Ghidra throws LowlevelError; Rugra logs and skips.
                eprintln!("[TRANSFORM] Bad lane size: {}", tok);
                continue;
            }
            self.add_lane_size(sz);
        }
    }

    // Ghidra: transform.hh:94 LanedRegister::laneSizes
    /// Iterate over all allowed lane sizes, smallest first. Mirrors
    /// `LanedIterator` (transform.hh:98-110 / transform.cc:284-295).
    pub fn lane_sizes(&self) -> Vec<i32> {
        let mut result = Vec::new();
        let mut mask = self.size_bit_mask;
        let mut size = 0i32;
        while mask != 0 {
            if mask & 1 != 0 {
                result.push(size);
            }
            mask >>= 1;
            size += 1;
        }
        result
    }
}

// ===========================================================================
// LaneDescription — transform.hh:127-148
// ===========================================================================

/// Description of logical lanes within a big Varnode. Faithful to
/// `LaneDescription` (transform.hh:132). Lanes are disjoint byte ranges; in
/// general all lanes are the same size, but the API allows non-uniform lanes.
#[derive(Debug, Clone)]
pub struct LaneDescription {
    /// Size of the region being split in bytes.
    pub whole_size: i32,
    /// Size of each lane in bytes.
    pub lane_size: Vec<i32>,
    /// Significance position (byte offset) of each lane.
    pub lane_position: Vec<i32>,
}

impl LaneDescription {
    // Ghidra: transform.cc:24 LaneDescription::uniform
    /// Construct uniform lanes: split `orig_size` into lanes of size `sz`.
    /// Faithful to the constructor (transform.cc:35-48).
    pub fn uniform(orig_size: i32, sz: i32) -> Self {
        let num = orig_size / sz;
        let mut lane_size = Vec::with_capacity(num as usize);
        let mut lane_position = Vec::with_capacity(num as usize);
        let mut pos = 0;
        for _ in 0..num {
            lane_size.push(sz);
            lane_position.push(pos);
            pos += sz;
        }
        Self {
            whole_size: orig_size,
            lane_size,
            lane_position,
        }
    }

    // Ghidra: transform.cc:24 LaneDescription::twoLane
    /// Construct two lanes of arbitrary sizes (lo then hi). Faithful to the
    /// constructor (transform.cc:53-63).
    pub fn two_lane(orig_size: i32, lo: i32, hi: i32) -> Self {
        Self {
            whole_size: orig_size,
            lane_size: vec![lo, hi],
            lane_position: vec![0, lo],
        }
    }

    // Ghidra: transform.cc:72 LaneDescription::subset
    /// Trim this description to a subrange. Faithful to `subset`
    /// (transform.cc:72-93). Returns false if the subrange splits any lane.
    pub fn subset(&mut self, lsb_offset: i32, size: i32) -> bool {
        if lsb_offset == 0 && size == self.whole_size {
            return true;
        }
        let first_lane = self.get_boundary(lsb_offset);
        if first_lane < 0 {
            return false;
        }
        let last_lane = self.get_boundary(lsb_offset + size);
        if last_lane < 0 {
            return false;
        }
        let mut new_lane_size = Vec::new();
        self.lane_position.clear();
        let mut new_position = 0;
        for i in first_lane..last_lane {
            let sz = self.lane_size[i as usize];
            self.lane_position.push(new_position);
            new_lane_size.push(sz);
            new_position += sz;
        }
        self.whole_size = size;
        self.lane_size = new_lane_size;
        true
    }

    // Ghidra: transform.cc:24 LaneDescription::getNumLanes
    /// Get the number of lanes.
    pub fn get_num_lanes(&self) -> usize {
        self.lane_size.len()
    }

    // Ghidra: transform.cc:24 LaneDescription::getSize
    /// Get the size of the i-th lane.
    pub fn get_size(&self, i: usize) -> i32 {
        self.lane_size[i]
    }

    // Ghidra: transform.cc:24 LaneDescription::getPosition
    /// Get the position of the i-th lane.
    pub fn get_position(&self, i: usize) -> i32 {
        self.lane_position[i]
    }

    // Ghidra: transform.cc:24 LaneDescription::getWholeSize
    /// Get the whole region size.
    pub fn get_whole_size(&self) -> i32 {
        self.whole_size
    }

    // Ghidra: transform.cc:100 LaneDescription::getBoundary
    /// Map a byte position to the index of the lane starting there.
    /// Faithful to `getBoundary` (transform.cc:100-119). Returns -1 if the
    /// position is out of bounds or not on a lane boundary. Position equal to
    /// whole size returns the lane count.
    pub fn get_boundary(&self, byte_pos: i32) -> i32 {
        if byte_pos < 0 || byte_pos > self.whole_size {
            return -1;
        }
        if byte_pos == self.whole_size {
            return self.lane_position.len() as i32;
        }
        // Binary search for the position.
        let mut min = 0i32;
        let mut max = self.lane_position.len() as i32 - 1;
        while min <= max {
            let index = (min + max) / 2;
            let pos = self.lane_position[index as usize];
            if pos == byte_pos {
                return index;
            }
            if pos < byte_pos {
                min = index + 1;
            } else {
                max = index - 1;
            }
        }
        -1
    }

    // Ghidra: transform.cc:133 LaneDescription::restriction
    /// Decide if a given truncation is natural for this description. Faithful
    /// to `restriction` (transform.cc:133-143). On success, returns
    /// `(num_lanes, skip_lanes)`; on failure, returns None.
    pub fn restriction(
        &self,
        _num_lanes: i32,
        skip_lanes: i32,
        byte_pos: i32,
        size: i32,
    ) -> Option<(i32, i32)> {
        let res_skip_lanes = self.get_boundary(self.lane_position[skip_lanes as usize] + byte_pos);
        if res_skip_lanes < 0 {
            return None;
        }
        let final_index =
            self.get_boundary(self.lane_position[skip_lanes as usize] + byte_pos + size);
        if final_index < 0 {
            return None;
        }
        let res_num_lanes = final_index - res_skip_lanes;
        if res_num_lanes == 0 {
            None
        } else {
            Some((res_num_lanes, res_skip_lanes))
        }
    }

    // Ghidra: transform.cc:158 LaneDescription::extension
    /// Decide if a given subset of lanes can be extended naturally. Faithful
    /// to `extension` (transform.cc:158-168). On success, returns
    /// `(num_lanes, skip_lanes)`; on failure, returns None.
    pub fn extension(
        &self,
        _num_lanes: i32,
        skip_lanes: i32,
        byte_pos: i32,
        size: i32,
    ) -> Option<(i32, i32)> {
        let res_skip_lanes = self.get_boundary(self.lane_position[skip_lanes as usize] - byte_pos);
        if res_skip_lanes < 0 {
            return None;
        }
        let final_index =
            self.get_boundary(self.lane_position[skip_lanes as usize] - byte_pos + size);
        if final_index < 0 {
            return None;
        }
        let res_num_lanes = final_index - res_skip_lanes;
        if res_num_lanes == 0 {
            None
        } else {
            Some((res_num_lanes, res_skip_lanes))
        }
    }
}

// ===========================================================================
// TransformVar — transform.hh:34-47
// ===========================================================================

/// Types of replacement Varnodes. Faithful to the enum in transform.hh:36-43.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformVarType {
    /// New Varnode is a piece of an original Varnode.
    Piece = 1,
    /// Varnode preexisted in the original data-flow.
    Preexisting = 2,
    /// A new temporary (unique space) Varnode.
    NormalTemp = 3,
    /// A temporary representing a piece of an original Varnode.
    PieceTemp = 4,
    /// A new constant Varnode.
    Constant = 5,
    /// Special iop constant encoding a PcodeOp reference.
    ConstantIop = 6,
}

/// Flags for a TransformVar. Faithful to the enum in transform.hh:45-47.
pub mod transform_var_flags {
    /// The last (most significant piece) of a split array.
    pub const SPLIT_TERMINATOR: u32 = 1;
    /// This is a piece of an input that has already been visited.
    pub const INPUT_DUPLICATE: u32 = 2;
}

/// Placeholder node for a Varnode that will exist after a transform. Faithful
/// to `TransformVar` (transform.hh:34).
#[derive(Debug, Clone)]
pub struct TransformVar {
    /// Original big Varnode of which this is a component (None for new temps).
    pub vn: Option<Arc<RwLock<Varnode>>>,
    /// The new explicit lane Varnode (set by `create_replacement`).
    pub replacement: Option<Arc<RwLock<Varnode>>>,
    /// Type of new Varnode.
    pub var_type: TransformVarType,
    /// Boolean properties (transform_var_flags).
    pub flags: u32,
    /// Size of the lane Varnode in bytes.
    pub byte_size: i32,
    /// Size of the logical value in bits.
    pub bit_size: i32,
    /// Value of constant or (bit) position within the original big Varnode.
    pub val: u64,
    /// Index of the defining TransformOp (None if not an output).
    pub def: Option<usize>,
}

impl TransformVar {
    // Ghidra: transform.hh:203 TransformVar::initialize
    /// Initialize from raw data. Faithful to `initialize` (transform.hh:203-214).
    pub fn initialize(
        tp: TransformVarType,
        v: Option<Arc<RwLock<Varnode>>>,
        bits: i32,
        bytes: i32,
        value: u64,
    ) -> Self {
        Self {
            var_type: tp,
            vn: v,
            val: value,
            bit_size: bits,
            byte_size: bytes,
            flags: 0,
            def: None,
            replacement: None,
        }
    }

    // Ghidra: transform.cc:175 TransformVar::createReplacement
    /// Create the Varnode object described by this placeholder. Faithful to
    /// `createReplacement` (transform.cc:175-220).
    pub fn create_replacement(&mut self, fd: &mut Funcdata, def_op: Option<&PcodeOpRef>) {
        if self.replacement.is_some() {
            return; // Already created.
        }
        match self.var_type {
            TransformVarType::Preexisting => {
                self.replacement = self.vn.clone();
            }
            TransformVarType::Constant => {
                self.replacement = Some(fd.new_constant(self.byte_size as usize, self.val));
            }
            TransformVarType::NormalTemp | TransformVarType::PieceTemp => {
                if let Some(def) = def_op {
                    self.replacement = Some(fd.new_unique_out(self.byte_size as usize, def));
                } else {
                    self.replacement = Some(fd.new_unique(self.byte_size as usize));
                }
            }
            TransformVarType::Piece => {
                let mut byte_pos = self.val as i32;
                if (byte_pos & 7) != 0 {
                    // cc:197-198 throws LowlevelError("Varnode piece is not
                    // byte aligned"); panic! is Rugra's established
                    // LowlevelError mapping (cf. funcdata.rs opSetOutput
                    // precondition, funcdata.rs:1706).
                    panic!("Varnode piece is not byte aligned");
                }
                byte_pos >>= 3;
                let (vn_size, vn_space, vn_offset, is_big_endian) = {
                    let vn_rg = self.vn.as_ref().unwrap().read().unwrap();
                    (
                        vn_rg.get_size() as i32,
                        vn_rg.space(),
                        vn_rg.get_offset(),
                        vn_rg.space().is_big_endian(),
                    )
                };
                if is_big_endian {
                    byte_pos = vn_size - byte_pos - self.byte_size;
                }
                let addr = Address::new(vn_offset + byte_pos as u64);
                // renormal(byteSize) is a no-op for Rugra's Address (no sub-byte
                // alignment tracking); the address is already byte-aligned.
                // transform.cc:202-207: the piece address stays in the ORIGINAL
                // varnode's space (`Address addr = vn->getAddr() + bytePos`
                // keeps vn's space; both newVarnode/newVarnodeOut take the full
                // space-qualified Address) — unique-space temporaries and
                // stack/ram pieces must not be pinned to the register space
                // (FAMILY-AUDIT-SPACELESS-SITES-0001).
                if let Some(def) = def_op {
                    self.replacement = Some(
                        fd.new_varnode_out_full(self.byte_size as usize, vn_space, addr, def),
                    );
                } else {
                    // Create a free varnode at the piece address.
                    self.replacement = Some(
                        fd.vbank
                            .create_with_space(self.byte_size as usize, vn_space, addr.as_u64()),
                    );
                }
                // transferVarnodeProperties (transform.cc:208): preserve the
                // consume mask and the directwrite|addrforce flags on the
                // address-preserving piece. Skipped pre-READINODE2 with a
                // "no API" note, which dropped addrforce on split pieces of
                // guarded locations (e.g. the persist return-copy of a
                // global) — RuleEarlyRemoval/ActionDeadCode then ate the
                // write-back lattice (READINODE2 drill, read_super
                // xRam156858: oracle earlyremoval 6785 keeps the 6-byte
                // return-copy via isAutoLive; Rugra killed it at 6257).
                {
                    let orig = self.vn.as_ref().expect("piece vn").clone();
                    let repl = self.replacement.as_ref().expect("piece replacement").clone();
                    fd.transfer_varnode_properties(&orig, &repl, byte_pos);
                }
                let _ = (vn_size, vn_offset);
            }
            TransformVarType::ConstantIop => {
                // transform.cc:211-215:
                //   PcodeOp *indeffect = PcodeOp::getOpFromConst(
                //       Address(fd->getArch()->getIopSpace(),val));
                //   replacement = fd->newVarnodeIop(indeffect);
                // The placeholder `val` (captured by new_iop from the original
                // iop varnode's offset) is decoded back into the affecting op
                // and re-materialized as an iop-space annotation varnode —
                // never as a const-space constant. getOpFromConst is a bare
                // `(PcodeOp*)(uintp)addr.getOffset()` (op.hh:249): a zero
                // offset decodes to a NULL PcodeOp* (valid, non-dereferenced
                // in Ghidra); Rugra models that as None, and newVarnodeIop
                // then re-encodes offset 0 (funcdata_varnode.cc:176-184) —
                // the annotation flag comes from the Varnode ctor
                // (varnode.cc:599-601) and assignHigh is the annotation
                // no-op leg (funcdata_varnode.cc:54-56).
                match get_op_from_const_offset(fd, self.val) {
                    Some(indeffect) => {
                        self.replacement = Some(fd.new_varnode_iop(&indeffect));
                    }
                    None => {
                        self.replacement = Some(fd.vbank.create_with_space(
                            std::mem::size_of::<usize>(),
                            crate::space::AddressSpace::Iop,
                            0,
                        ));
                    }
                }
            }
        }
    }
}

// Ghidra: op.hh:249 PcodeOp::getOpFromConst
/// Resolve an iop-space offset back to the PcodeOp it references. Faithful to
/// the static `PcodeOp::getOpFromConst(const Address &addr)` (op.hh:249),
/// which reinterprets the address offset as a `PcodeOp*`. This is the
/// offset-based overload of `Funcdata::get_op_from_const` (funcdata.rs,
/// varnode-parametered) mirroring transform.cc:213, where the Address is
/// constructed directly from the placeholder value without a materialized
/// Varnode. Rugra decodes the same `Arc::as_ptr` encoding written by
/// `Funcdata::new_varnode_iop` (funcdata.rs).
///
/// Ghidra's decode is a nullable `(PcodeOp*)(uintp)addr.getOffset()`; offset
/// 0 decodes to NULL, which `newVarnodeIop` re-encodes without dereferencing.
/// The safe Rugra form resolves the offset by IDENTITY SEARCH over the op
/// bank (optree + deadandgone — destroy keeps the allocation bank-resident,
/// op.cc:984-999, so retired targets still resolve): the producer contract
/// (`OPBANK-0001`, cf. `Funcdata::get_op_from_const`) guarantees the encoded
/// op is alive in the bank, so the search finds exactly the Arc the oracle's
/// pointer reinterpretation would have produced — without reconstructing an
/// `Arc` from a raw address. The ConstantIop placeholder path is a cold,
/// per-transform site (lane splitting), so the linear scan is not on any
/// measured face.
fn get_op_from_const_offset(fd: &Funcdata, offset: u64) -> Option<PcodeOpRef> {
    if offset == 0 {
        // Ghidra: NULL PcodeOp* — carried through, never dereferenced.
        return None;
    }
    let target = offset as usize;
    fd.obank
        .optree
        .iter()
        .chain(fd.obank.iter_deadandgone())
        .find(|op| std::sync::Arc::as_ptr(&op.0) as *const () as usize == target)
        .cloned()
}

// ===========================================================================
// TransformOp — transform.hh:63-91
// ===========================================================================

/// Special annotations on new pcode ops. Faithful to the enum in
/// transform.hh:70-74.
pub mod transform_op_special {
    /// Op replaces an existing op.
    pub const OP_REPLACEMENT: u32 = 1;
    /// Op already exists (but will be transformed).
    pub const OP_PREEXISTING: u32 = 2;
    /// Mark op as indirect creation.
    pub const INDIRECT_CREATION: u32 = 4;
    /// Mark op as indirect creation and possible call output.
    pub const INDIRECT_CREATION_POSSIBLE_OUT: u32 = 8;
}

/// Placeholder node for a PcodeOp that will exist after a transform. Faithful
/// to `TransformOp` (transform.hh:63).
#[derive(Debug, Clone)]
pub struct TransformOp {
    /// Original op which this is splitting (or None).
    pub op: Option<PcodeOpRef>,
    /// The new replacement op (set by `create_replacement`).
    pub replacement: Option<PcodeOpRef>,
    /// Opcode of the new op.
    pub opc: OpCode,
    /// Special handling code (transform_op_special).
    pub special: u32,
    /// Output placeholder variable index.
    pub output: Option<usize>,
    /// Input placeholder variable indices.
    pub input: Vec<Option<usize>>,
    /// The following op index after this (None if inserted immediately).
    pub follow: Option<usize>,
}

impl TransformOp {
    // Ghidra: transform.hh:26 TransformOp::empty
    /// Create an empty placeholder.
    fn empty() -> Self {
        Self {
            op: None,
            replacement: None,
            opc: OpCode::CPUI_COPY,
            special: 0,
            output: None,
            input: Vec::new(),
            follow: None,
        }
    }

    // Ghidra: transform.cc:254 TransformOp::attemptInsertion
    /// Try to put the new PcodeOp into its basic block. Faithful to
    /// `attemptInsertion` (transform.cc:254-269). Returns true if inserted or
    /// already inserted.
    pub fn attempt_insertion(&mut self, fd: &mut Funcdata, ops: &[TransformOp]) -> bool {
        if let Some(follow_idx) = self.follow {
            let follow_follows = ops[follow_idx].follow.is_some();
            if !follow_follows {
                // The follow is inserted; insert this before it.
                let follow_rep = ops[follow_idx].replacement.clone();
                if let Some(follow_rep) = follow_rep {
                    let my_rep = self.replacement.clone().unwrap();
                    if self.opc == OpCode::CPUI_MULTIEQUAL {
                        let parent = follow_rep
                            .0
                            .read()
                            .unwrap()
                            .parent
                            .as_ref()
                            .and_then(std::sync::Weak::upgrade)
                            .expect("MULTIEQUAL follow replacement has no basic block");
                        fd.op_insert_begin(&my_rep, &parent);
                    } else {
                        fd.op_insert_before(&my_rep, &follow_rep);
                    }
                    self.follow = None;
                    return true;
                }
            }
            false
        } else {
            true // Already inserted.
        }
    }

    // Ghidra: transform.cc:273 TransformOp::inheritIndirect
    /// Set indirect-creation flags based on the given INDIRECT op. Faithful to
    /// `inheritIndirect` (transform.cc:273-282): if `indOp` carries
    /// `PcodeOp::indirect_creation`, the `indirect_creation` placeholder bit
    /// is taken when input(0) is an "indirect zero" (`isIndirectZero`,
    /// varnode.hh:271: indirect_creation|constant flags both set), otherwise
    /// `indirect_creation_possible_out`.
    pub fn inherit_indirect(&mut self, ind_op: &PcodeOpRef) {
        let (is_indirect_creation, in0_indirect_zero) = {
            let r = ind_op.0.read().unwrap();
            let creation = (r.flags & crate::op::pcodeop_flags::INDIRECT_CREATION) != 0;
            let zero = r
                .get_in(0)
                .map(|vn| vn.read().unwrap().is_indirect_zero())
                .unwrap_or(false);
            (creation, zero)
        };
        if is_indirect_creation {
            if in0_indirect_zero {
                self.special |= transform_op_special::INDIRECT_CREATION;
            } else {
                self.special |= transform_op_special::INDIRECT_CREATION_POSSIBLE_OUT;
            }
        }
    }
}

// ===========================================================================
// TransformManager — transform.hh:150-194
// ===========================================================================

/// Class for splitting larger registers holding smaller logical lanes. Faithful
/// to `TransformManager` (transform.hh:156). Given a starting Varnode, looks
/// for evidence of the Varnode being interpreted as disjoint logical values
/// concatenated (lanes), and splits Varnode and data-flow into explicit
/// operations on the lanes.
pub struct TransformManager {
    /// Map from a big Varnode's create-index to the start index of its split
    /// array in `new_varnodes`. Mirrors Ghidra's `map<int4,TransformVar*>`.
    piece_map: BTreeMap<u32, usize>,
    /// Storage for Varnode placeholder nodes (the "arena").
    pub new_varnodes: Vec<TransformVar>,
    /// Storage for PcodeOp placeholder nodes.
    pub new_ops: Vec<TransformOp>,
    /// RUGRA-GLUE: Ghidra's `preserveAddress` is virtual (transform.hh:171)
    /// and overridden by subclasses (e.g. `SubfloatFlow::preserveAddress`,
    /// subflow.cc:3451, which returns `vn->isInput()`). Rust has no
    /// inheritance, so this optional override hook plays the role of the
    /// subclass vtable slot; `None` runs the base implementation. The hook
    /// observes the same `(vn, bitSize, lsbOffset)` arguments Ghidra passes.
    pub preserve_address_override: Option<fn(&Varnode, i32, i32) -> bool>,
}

// RUGRA-GLUE: Ghidra's NULL input-slot pointer, shared process-wide via
// crate::op::null_slot_sentinel (one instance keeps `Arc::ptr_eq` between two
// NULL slots `true`, matching Ghidra's pointer equality inrefs[i] == vn,
// op.hh:166 getSlot). Ghidra's `PcodeOp` ctor (op.cc:71) pre-sizes `inrefs` to
// `inputs` NULL slots, and `TransformOp::createReplacement` (transform.cc:236)
// inserts further NULL slots via `opInsertInput(op, (Varnode*)0, ...)`; the
// NULLs persist until `placeInputs` (transform.cc:750) overwrites every slot.
// The sentinel is never created through `VarnodeBank` (no create-index or bank
// count side effects), carries no descendants, and observation projections
// render it as the NULL slot ("-"). (SB-ORD159-NULLSLOT-0001)
fn null_slot_sentinel() -> std::sync::Arc<RwLock<Varnode>> {
    crate::op::null_slot_sentinel()
}

// P6 borrowing form (ARENA_DESIGN §3.2/§3.4, D11): Ghidra's TransformManager
// holds `Funcdata *fd` (transform.hh:157) set at construction — the god-object
// the oracle's friend-class architecture already is. Rust cannot store the
// `&mut` (it would alias every later borrower), so per the campaign's P6
// ruling the fd-using lifecycle methods take `fd: &mut Funcdata` at each call
// (call sites already hold it — subflow.cc's SplitFlow/LaneDivide forward
// from methods that receive fd). With the raw pointer gone, the manager is
// automatically Send+Sync: the former `unsafe impl Send` shim is deleted.

impl Default for TransformManager {
    // Ghidra: transform.hh:32 TransformManager::default
    fn default() -> Self {
        Self::new()
    }
}

impl TransformManager {
    // Ghidra: transform.hh:32 TransformManager::new
    /// Construct an empty manager (no Funcdata binding yet).
    pub fn new() -> Self {
        Self {
            piece_map: BTreeMap::new(),
            new_varnodes: Vec::new(),
            new_ops: Vec::new(),
            preserve_address_override: None,
        }
    }

    // Ghidra: transform.hh:169 TransformManager::TransformManager
    /// Bind to a Funcdata. Faithful to the oracle constructor
    /// (`TransformManager(Funcdata *f) { fd = f; }`, transform.hh:169),
    /// which binds the function at construction; the P6 Rust form does not
    /// store the reference (the lifecycle methods receive `fd` per call),
    /// so this only resets the placeholder storages exactly as the oracle
    /// ctor's fresh member state.
    pub fn init(&mut self, _fd: &mut Funcdata) {
        self.piece_map.clear();
        self.new_varnodes.clear();
        self.new_ops.clear();
    }

    // Ghidra: transform.cc:348 TransformManager::preserveAddress
    /// Should the address of the given Varnode be preserved when constructing a
    /// piece? Faithful to `preserveAddress` (transform.cc:348-354). Returns
    /// false if the logical value is not byte-aligned or the Varnode is in the
    /// internal (unique) space. This is Ghidra's virtual dispatch point
    /// (transform.hh:171; `SubfloatFlow::preserveAddress`, subflow.cc:3451,
    /// overrides it), so an installed `preserve_address_override` hook takes
    /// precedence over the base logic.
    pub fn preserve_address(&self, vn: &Arc<RwLock<Varnode>>, bit_size: i32, lsb_offset: i32) -> bool {
        if let Some(override_fn) = self.preserve_address_override {
            let guard = vn.read().unwrap();
            return override_fn(&guard, bit_size, lsb_offset);
        }
        if (lsb_offset & 7) != 0 {
            return false; // Logical value not aligned.
        }
        let vn_rg = vn.read().unwrap();
        vn_rg.space() != AddressSpace::Unique
    }

    // RUGRA-GLUE: setter for the virtual-dispatch hook documented on
    // `preserve_address_override` (Ghidra reaches the same effect by
    /// subclassing TransformManager; Rust mirrors the vtable slot).
    pub fn set_preserve_address_override(&mut self, f: fn(&Varnode, i32, i32) -> bool) {
        self.preserve_address_override = Some(f);
    }

    // Ghidra: transform.cc:356 TransformManager::clearVarnodeMarks
    /// Clear the mark for all Varnodes referenced by placeholders. Faithful to
    /// `clearVarnodeMarks` (transform.cc:356-366).
    pub fn clear_varnode_marks(&mut self) {
        let targets: Vec<Arc<RwLock<Varnode>>> = self
            .piece_map
            .values()
            .filter_map(|&start| {
                let v = &self.new_varnodes[start];
                v.vn.clone()
            })
            .collect();
        for vn in targets {
            vn.write().unwrap().clear_mark();
        }
    }

    // ---- Placeholder creation (transform.cc:370-575) ----

    // Ghidra: transform.cc:370 TransformManager::newPreexistingVarnode
    /// Make a placeholder for a preexisting Varnode. Faithful to
    /// `newPreexistingVarnode` (transform.cc:370-380). Returns the arena index.
    pub fn new_preexisting_varnode(&mut self, vn: Arc<RwLock<Varnode>>) -> usize {
        let create_index = vn.read().unwrap().create_index;
        let (bit_size, byte_size) = {
            let r = vn.read().unwrap();
            ((r.get_size() * 8) as i32, r.get_size() as i32)
        };
        let mut res = TransformVar::initialize(TransformVarType::Preexisting, Some(vn), bit_size, byte_size, 0);
        res.flags = transform_var_flags::SPLIT_TERMINATOR;
        let idx = self.new_varnodes.len();
        self.new_varnodes.push(res);
        self.piece_map.insert(create_index, idx);
        idx
    }

    // Ghidra: transform.cc:384 TransformManager::newUnique
    /// Make a placeholder for a new unique-space Varnode. Faithful to
    /// `newUnique` (transform.cc:384-391).
    pub fn new_unique(&mut self, size: i32) -> usize {
        let res = TransformVar::initialize(TransformVarType::NormalTemp, None, size * 8, size, 0);
        let idx = self.new_varnodes.len();
        self.new_varnodes.push(res);
        idx
    }

    // Ghidra: transform.cc:399 TransformManager::newConstant
    /// Make a placeholder for a constant Varnode. Faithful to `newConstant`
    /// (transform.cc:399-406). `lsb_offset` strips bits off the existing value.
    pub fn new_constant(&mut self, size: i32, lsb_offset: i32, val: u64) -> usize {
        let shifted = (val >> lsb_offset) & calc_mask(size as usize);
        let res = TransformVar::initialize(TransformVarType::Constant, None, size * 8, size, shifted);
        let idx = self.new_varnodes.len();
        self.new_varnodes.push(res);
        idx
    }

    // Ghidra: transform.cc:411 TransformManager::newIop
    /// Make a placeholder for a special iop constant. Faithful to `newIop`
    /// (transform.cc:411-418).
    pub fn new_iop(&mut self, vn: Arc<RwLock<Varnode>>) -> usize {
        let (byte_size, val) = {
            let r = vn.read().unwrap();
            (r.get_size() as i32, r.get_offset())
        };
        let res = TransformVar::initialize(TransformVarType::ConstantIop, None, byte_size * 8, byte_size, val);
        let idx = self.new_varnodes.len();
        self.new_varnodes.push(res);
        idx
    }

    // Ghidra: transform.cc:426 TransformManager::newPiece
    /// Make a placeholder for a piece of a Varnode. Faithful to `newPiece`
    /// (transform.cc:426-436).
    pub fn new_piece(&mut self, vn: Arc<RwLock<Varnode>>, bit_size: i32, lsb_offset: i32) -> usize {
        let create_index = vn.read().unwrap().create_index;
        let byte_size = (bit_size + 7) / 8;
        let var_type = if self.preserve_address(&vn, bit_size, lsb_offset) {
            TransformVarType::Piece
        } else {
            TransformVarType::PieceTemp
        };
        let mut res = TransformVar::initialize(var_type, Some(vn), bit_size, byte_size, lsb_offset as u64);
        res.flags = transform_var_flags::SPLIT_TERMINATOR;
        let idx = self.new_varnodes.len();
        self.new_varnodes.push(res);
        self.piece_map.insert(create_index, idx);
        idx
    }

    // Ghidra: transform.cc:445 TransformManager::newSplit
    /// Make placeholders splitting a Varnode into all its lanes. Faithful to
    /// `newSplit` (transform.cc:445-470). Returns the start index of the lane
    /// array.
    pub fn new_split(&mut self, vn: Arc<RwLock<Varnode>>, description: &LaneDescription) -> usize {
        let num = description.get_num_lanes();
        let create_index = vn.read().unwrap().create_index;
        let is_const = vn.read().unwrap().is_constant();
        let vn_offset = vn.read().unwrap().get_offset();
        let start = self.new_varnodes.len();
        for i in 0..num {
            let bitpos = description.get_position(i) * 8;
            let byte_size = description.get_size(i);
            let new_var = if is_const {
                let val = if bitpos < 64 {
                    (vn_offset >> bitpos as u64) & calc_mask(byte_size as usize)
                } else {
                    0
                };
                TransformVar::initialize(
                    TransformVarType::Constant,
                    Some(vn.clone()),
                    byte_size * 8,
                    byte_size,
                    val,
                )
            } else {
                let var_type = if self.preserve_address(&vn, byte_size * 8, bitpos) {
                    TransformVarType::Piece
                } else {
                    TransformVarType::PieceTemp
                };
                TransformVar::initialize(var_type, Some(vn.clone()), byte_size * 8, byte_size, bitpos as u64)
            };
            self.new_varnodes.push(new_var);
        }
        // Mark the most-significant piece as the split terminator.
        self.new_varnodes[start + num - 1].flags |= transform_var_flags::SPLIT_TERMINATOR;
        self.piece_map.insert(create_index, start);
        start
    }

    // Ghidra: transform.hh:32 TransformManager::newSplitSubset
    /// Make placeholders splitting a Varnode into a subset of lanes. Faithful
    /// to `newSplit` (transform.cc:481-506). Returns the start index.
    pub fn new_split_subset(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
        description: &LaneDescription,
        num_lanes: usize,
        start_lane: usize,
    ) -> usize {
        let create_index = vn.read().unwrap().create_index;
        let is_const = vn.read().unwrap().is_constant();
        let vn_offset = vn.read().unwrap().get_offset();
        let base_bit_pos = description.get_position(start_lane) * 8;
        let start = self.new_varnodes.len();
        for i in 0..num_lanes {
            let bitpos = description.get_position(start_lane + i) * 8 - base_bit_pos;
            let byte_size = description.get_size(start_lane + i);
            let new_var = if is_const {
                let val = if bitpos < 64 {
                    (vn_offset >> bitpos as u64) & calc_mask(byte_size as usize)
                } else {
                    0
                };
                TransformVar::initialize(
                    TransformVarType::Constant,
                    Some(vn.clone()),
                    byte_size * 8,
                    byte_size,
                    val,
                )
            } else {
                let var_type = if self.preserve_address(&vn, byte_size * 8, bitpos) {
                    TransformVarType::Piece
                } else {
                    TransformVarType::PieceTemp
                };
                TransformVar::initialize(var_type, Some(vn.clone()), byte_size * 8, byte_size, bitpos as u64)
            };
            self.new_varnodes.push(new_var);
        }
        self.new_varnodes[start + num_lanes - 1].flags |= transform_var_flags::SPLIT_TERMINATOR;
        self.piece_map.insert(create_index, start);
        start
    }

    // Ghidra: transform.cc:515 TransformManager::newOpReplace
    /// Create a new placeholder op intended to replace an existing op. Faithful
    /// to `newOpReplace` (transform.cc:515-528).
    pub fn new_op_replace(&mut self, num_params: usize, opc: OpCode, replace: PcodeOpRef) -> usize {
        let mut rop = TransformOp::empty();
        rop.op = Some(replace);
        rop.opc = opc;
        rop.special = transform_op_special::OP_REPLACEMENT;
        rop.input = vec![None; num_params];
        let idx = self.new_ops.len();
        self.new_ops.push(rop);
        idx
    }

    // Ghidra: transform.cc:538 TransformManager::newOp
    /// Create a new placeholder op that will not replace an existing op.
    /// Faithful to `newOp` (transform.cc:538-551). `follow` is the placeholder
    /// for the op that follows the new op when it is created.
    pub fn new_op(&mut self, num_params: usize, opc: OpCode, follow: usize) -> usize {
        let follow_op = self.new_ops[follow].op.clone();
        let mut rop = TransformOp::empty();
        rop.op = follow_op;
        rop.opc = opc;
        rop.follow = Some(follow);
        rop.input = vec![None; num_params];
        let idx = self.new_ops.len();
        self.new_ops.push(rop);
        idx
    }

    // Ghidra: transform.cc:562 TransformManager::newPreexistingOp
    /// Create a new placeholder op for an existing PcodeOp. Faithful to
    /// `newPreexistingOp` (transform.cc:562-575).
    pub fn new_preexisting_op(&mut self, num_params: usize, opc: OpCode, original: PcodeOpRef) -> usize {
        let mut rop = TransformOp::empty();
        rop.op = Some(original);
        rop.opc = opc;
        rop.special = transform_op_special::OP_PREEXISTING;
        rop.input = vec![None; num_params];
        let idx = self.new_ops.len();
        self.new_ops.push(rop);
        idx
    }

    // ---- Placeholder lookup (transform.cc:581-649) ----

    // Ghidra: transform.cc:581 TransformManager::getPreexistingVarnode
    /// Get (or create) a placeholder for a preexisting Varnode. Faithful to
    /// `getPreexistingVarnode` (transform.cc:581-591).
    pub fn get_preexisting_varnode(&mut self, vn: Arc<RwLock<Varnode>>) -> usize {
        if vn.read().unwrap().is_constant() {
            let (sz, off) = {
                let r = vn.read().unwrap();
                (r.get_size() as i32, r.get_offset())
            };
            return self.new_constant(sz, 0, off);
        }
        let create_index = vn.read().unwrap().create_index;
        if let Some(&idx) = self.piece_map.get(&create_index) {
            return idx;
        }
        self.new_preexisting_varnode(vn)
    }

    // Ghidra: transform.cc:599 TransformManager::getPiece
    /// Find (or create) the placeholder for a logical piece of a Varnode.
    /// Faithful to `getPiece` (transform.cc:599-611).
    pub fn get_piece(&mut self, vn: Arc<RwLock<Varnode>>, bit_size: i32, lsb_offset: i32) -> usize {
        let create_index = vn.read().unwrap().create_index;
        if let Some(&idx) = self.piece_map.get(&create_index) {
            let res = &self.new_varnodes[idx];
            if res.bit_size != bit_size || res.val != lsb_offset as u64 {
                eprintln!(
                    "[TRANSFORM] Cannot create multiple pieces for one Varnode through getPiece"
                );
            }
            return idx;
        }
        self.new_piece(vn, bit_size, lsb_offset)
    }

    // Ghidra: transform.cc:620 TransformManager::getSplit
    /// Find (or create) placeholders splitting a Varnode into its lanes.
    /// Faithful to `getSplit` (transform.cc:620-629).
    pub fn get_split(&mut self, vn: Arc<RwLock<Varnode>>, description: &LaneDescription) -> usize {
        let create_index = vn.read().unwrap().create_index;
        if let Some(&idx) = self.piece_map.get(&create_index) {
            return idx;
        }
        self.new_split(vn, description)
    }

    // Ghidra: transform.hh:32 TransformManager::getSplitSubset
    /// Find (or create) placeholders splitting a Varnode into a subset of
    /// lanes. Faithful to `getSplit` (transform.cc:640-649).
    pub fn get_split_subset(
        &mut self,
        vn: Arc<RwLock<Varnode>>,
        description: &LaneDescription,
        num_lanes: usize,
        start_lane: usize,
    ) -> usize {
        let create_index = vn.read().unwrap().create_index;
        if let Some(&idx) = self.piece_map.get(&create_index) {
            return idx;
        }
        self.new_split_subset(vn, description, num_lanes, start_lane)
    }

    // Ghidra: transform.hh:219 TransformManager::opSetInput
    /// Mark the given variable as input to the given op. Faithful to
    /// `opSetInput` (transform.hh:219-223).
    pub fn op_set_input(&mut self, rop_idx: usize, rvn_idx: usize, slot: usize) {
        let rop = &mut self.new_ops[rop_idx];
        while rop.input.len() <= slot {
            rop.input.push(None);
        }
        rop.input[slot] = Some(rvn_idx);
    }

    // Ghidra: transform.hh:229 TransformManager::opSetOutput
    /// Mark the given variable as output of the given op. Faithful to
    /// `opSetOutput` (transform.hh:229-234).
    pub fn op_set_output(&mut self, rop_idx: usize, rvn_idx: usize) {
        self.new_ops[rop_idx].output = Some(rvn_idx);
        self.new_varnodes[rvn_idx].def = Some(rop_idx);
    }

    // Ghidra: transform.hh:246 TransformManager::preexistingGuard
    /// Should `newPreexistingOp` be called? Faithful to `preexistingGuard`
    /// (transform.hh:246-253).
    pub fn preexisting_guard(slot: usize, rvn: &TransformVar) -> bool {
        if slot == 0 {
            return true;
        }
        if rvn.var_type == TransformVarType::Piece || rvn.var_type == TransformVarType::PieceTemp {
            return false;
        }
        true
    }

    // ---- Apply lifecycle (transform.cc:651-766) ----

    // Ghidra: transform.cc:654 TransformManager::specialHandling
    /// Handle special PcodeOp marking. Faithful to `specialHandling`
    /// (transform.cc:654-660): `indirect_creation` routes to
    /// `Funcdata::markIndirectCreation(replacement, false)`,
    /// `indirect_creation_possible_out` to `markIndirectCreation(replacement,
    /// true)` (funcdata_op.cc:736-748 sets `PcodeOp::indirect_creation` on the
    /// replacement, `Varnode::indirect_creation` on the output and — only for
    /// the non-possible-out form — on input(0)).
    fn special_handling(&self, fd: &Funcdata, rop: &TransformOp) {
        if (rop.special & transform_op_special::INDIRECT_CREATION) != 0 {
            if let Some(replacement) = &rop.replacement {
                fd.mark_indirect_creation(replacement, false);
            }
        } else if (rop.special & transform_op_special::INDIRECT_CREATION_POSSIBLE_OUT) != 0 {
            if let Some(replacement) = &rop.replacement {
                fd.mark_indirect_creation(replacement, true);
            }
        }
    }

    // Ghidra: transform.hh:32 TransformManager::createOpReplacement
    /// Create a new PcodeOp or modify an existing one to match the placeholder
    /// at `op_idx`. Faithful to `TransformOp::createReplacement`
    /// (transform.cc:225-250). The `op_preexisting` arm retargets the existing
    /// op in place (opcode + shrink/clear/grow input slots, cc:228-237); the
    /// new-op arm creates the PcodeOp, materializes the output placeholder
    /// (cc:241-242) and inserts immediately when no follow is pending
    /// (cc:243-248). NULL input slots are modelled by detached size-0
    /// sentinels (`null_slot_sentinel`).
    fn create_op_replacement(&mut self, fd: &mut Funcdata, op_idx: usize) {
        let is_preexisting = (self.new_ops[op_idx].special & transform_op_special::OP_PREEXISTING) != 0;
        if is_preexisting {
            // cc:228: replacement = op (identity preserved; never re-inserted).
            let op = self.new_ops[op_idx].op.clone().unwrap();
            // cc:229-230: fd->opSetOpcode(op, opc).
            let opc = self.new_ops[op_idx].opc;
            fd.op_set_opcode(&op, opc);
            let target_len = self.new_ops[op_idx].input.len();
            // cc:231-232: while (input.size() < op->numInput())
            //   fd->opRemoveInput(op, op->numInput()-1);  — trim from the end.
            loop {
                let cur = op.0.read().unwrap().inrefs.len();
                if cur <= target_len {
                    break;
                }
                fd.op_remove_input(&op, cur - 1);
            }
            // cc:233-234: opUnsetInput(op, i) for every remaining slot — the
            // Varnode loses this descendant and the slot is nulled in place
            // (the shared sentinel models Ghidra's NULL; op_unset_input now
            // performs the clearInput write itself).
            let cur = op.0.read().unwrap().inrefs.len();
            for i in 0..cur {
                fd.op_unset_input(&op, i);
            }
            // cc:235-236: while (op->numInput() < input.size())
            //   fd->opInsertInput(op, (Varnode *)0, op->numInput()-1);
            // opInsertInput (funcdata_op.cc:308-317) is insertInput(slot)
            // followed by opSetInput(op, NULL, slot), which early-returns on
            // the fresh NULL slot (funcdata_op.cc:107), so the net effect is a
            // bare slot insertion at numInput()-1 — no bank Varnode involved.
            while op.0.read().unwrap().inrefs.len() < target_len {
                let slot = op.0.read().unwrap().inrefs.len() - 1;
                op.0.write().unwrap().inrefs.insert(slot, null_slot_sentinel());
            }
            self.new_ops[op_idx].replacement = Some(op);
        } else {
            let op_ref = self.new_ops[op_idx].op.clone().unwrap();
            let addr = op_ref.0.read().unwrap().get_addr();
            let input_len = self.new_ops[op_idx].input.len();
            // cc:239: fd->newOp(input.size(), op->getAddr()) — Ghidra's
            // PcodeOp ctor (op.cc:71, `inrefs(s)`) pre-sizes the input slots
            // to NULL; Rugra's PcodeOpBank::create only reserves capacity, so
            // pre-fill sentinels to keep numInput identical until placeInputs
            // (transform.cc:747-751) overwrites every slot.
            let newop = fd.new_op(input_len, addr);
            if input_len > 0 {
                let mut guard = newop.0.write().unwrap();
                for _ in 0..input_len {
                    guard.inrefs.push(null_slot_sentinel());
                }
            }
            let opc = self.new_ops[op_idx].opc;
            // cc:240: fd->opSetOpcode(replacement, opc).
            fd.op_set_opcode(&newop, opc);
            // cc:241-242: if (output != 0) output->createReplacement(fd) —
            // with output == nullptr no output Varnode is materialized.
            if let Some(out_idx) = self.new_ops[op_idx].output {
                self.new_varnodes[out_idx].create_replacement(fd, Some(&newop));
                if let Some(out_vn) = self.new_varnodes[out_idx].replacement.clone() {
                    fd.op_set_output(&newop, out_vn);
                }
            }
            if self.new_ops[op_idx].follow.is_none() {
                // cc:243-248: Can be inserted immediately.
                if opc == OpCode::CPUI_MULTIEQUAL {
                    let parent = op_ref
                        .0
                        .read()
                        .unwrap()
                        .parent
                        .as_ref()
                        .and_then(std::sync::Weak::upgrade)
                        .expect("MULTIEQUAL replacement target has no basic block");
                    fd.op_insert_begin(&newop, &parent);
                } else {
                    fd.op_insert_before(&newop, &op_ref);
                }
            }
            self.new_ops[op_idx].replacement = Some(newop);
        }
    }

    // Ghidra: transform.cc:665 TransformManager::createOps
    /// Create the actual PcodeOps from placeholders. Faithful to `createOps`
    /// (transform.cc:665-680).
    fn create_ops(&mut self, fd: &mut Funcdata) {
        // First pass: create all op replacements.
        let n_ops = self.new_ops.len();
        for i in 0..n_ops {
            self.create_op_replacement(fd, i);
        }
        // Second pass: insert ops that follow another op, iterating until all
        // are inserted.
        loop {
            let mut follow_count = 0;
            let n = self.new_ops.len();
            for i in 0..n {
                let needs_insert = self.new_ops[i].follow.is_some();
                if !needs_insert {
                    continue;
                }
                // Snapshot the follow index before the call.
                let _ = i;
                // We must borrow new_ops immutably for attempt_insertion's
                // lookup while mutating new_ops[i]. Clone the slice view.
                let ops_snapshot: Vec<TransformOp> = self.new_ops.clone();
                let mut tmp = self.new_ops[i].clone();
                let inserted = tmp.attempt_insertion(fd, &ops_snapshot);
                self.new_ops[i] = tmp;
                if !inserted {
                    follow_count += 1;
                }
            }
            if follow_count == 0 {
                break;
            }
        }
    }

    // Ghidra: transform.cc:684 TransformManager::createVarnodes
    /// Create the actual Varnodes from placeholders. Faithful to
    /// `createVarnodes` (transform.cc:684-711). Collects input varnodes into
    /// `input_list`.
    fn create_varnodes(&mut self, fd: &mut Funcdata, input_list: &mut Vec<(usize, bool)>) {
        // Iterate over all split arrays (referenced by piece_map) and create
        // replacements, collecting input pieces.
        let entries: Vec<(u32, usize)> = self.piece_map.iter().map(|(&k, &v)| (k, v)).collect();
        for (_create_index, start) in entries {
            let mut i = start;
            loop {
                let is_piece = self.new_varnodes[i].var_type == TransformVarType::Piece;
                let is_input = self.new_varnodes[i]
                    .vn
                    .as_ref()
                    .map(|v| v.read().unwrap().is_input())
                    .unwrap_or(false);
                if is_piece && is_input {
                    let already_marked = self.new_varnodes[i]
                        .vn
                        .as_ref()
                        .map(|v| v.read().unwrap().is_mark())
                        .unwrap_or(false);
                    if already_marked {
                        self.new_varnodes[i].flags |= transform_var_flags::INPUT_DUPLICATE;
                        input_list.push((i, true));
                    } else {
                        self.new_varnodes[i]
                            .vn
                            .as_ref()
                            .unwrap()
                            .write()
                            .unwrap()
                            .set_mark();
                        input_list.push((i, false));
                    }
                }
                // Create the replacement Varnode.
                let def_op = self.new_varnodes[i]
                    .def
                    .and_then(|di| self.new_ops[di].replacement.clone());
                let mut tmp = self.new_varnodes[i].clone();
                tmp.create_replacement(fd, def_op.as_ref());
                self.new_varnodes[i] = tmp;
                if (self.new_varnodes[i].flags & transform_var_flags::SPLIT_TERMINATOR) != 0 {
                    break;
                }
                i += 1;
            }
        }
        // Create standalone (non-piece-map) varnodes.
        // Ghidra iterates newVarnodes (the list of non-piece-map vars). Rugra
        // stores everything in one arena; standalone vars are those not in any
        // piece_map range. For simplicity, create all uncreated non-piece vars.
        let standalone_indices: Vec<usize> = (0..self.new_varnodes.len())
            .filter(|&i| {
                self.new_varnodes[i].replacement.is_none()
                    && self.new_varnodes[i].var_type != TransformVarType::Piece
                    && self.new_varnodes[i].var_type != TransformVarType::PieceTemp
            })
            .collect();
        for i in standalone_indices {
            let def_op = self.new_varnodes[i]
                .def
                .and_then(|di| self.new_ops[di].replacement.clone());
            let mut tmp = self.new_varnodes[i].clone();
            tmp.create_replacement(fd, def_op.as_ref());
            self.new_varnodes[i] = tmp;
        }
    }

    // Ghidra: transform.cc:713 TransformManager::removeOld
    /// Remove old preexisting PcodeOps that are now obsolete. Faithful to
    /// `removeOld` (transform.cc:713-724).
    fn remove_old(&mut self, fd: &mut Funcdata) {
        let to_destroy: Vec<PcodeOpRef> = self
            .new_ops
            .iter()
            .filter(|rop| {
                (rop.special & transform_op_special::OP_REPLACEMENT) != 0
            })
            .filter_map(|rop| rop.op.clone())
            .filter(|op| !op.0.read().unwrap().is_dead())
            .collect();
        for op in to_destroy {
            fd.op_destroy(&op);
        }
    }

    // Ghidra: transform.cc:729 TransformManager::transformInputVarnodes
    /// Remove old input Varnodes and mark new ones as inputs. Faithful to
    /// `transformInputVarnodes` (transform.cc:729-738).
    fn transform_input_varnodes(&mut self, fd: &mut Funcdata, input_list: &[(usize, bool)]) {
        for &(rvn_idx, is_duplicate) in input_list {
            if !is_duplicate {
                // cc:734-735: fd->deleteVarnode(rvn->vn) — the old input
                // varnode is detached at this point (removeOld destroyed its
                // remaining readers), so Funcdata::deleteVarnode
                // (funcdata.hh:294) removes it from both trees instead of
                // leaving a stale entry behind.
                if let Some(old_vn) = self.new_varnodes[rvn_idx].vn.clone() {
                    if let Err(error) = fd.delete_varnode(&old_vn) {
                        eprintln!("[TRANSFORM] WARN: deleteVarnode(rvn->vn) failed: {error:#}");
                    }
                }
            }
            // cc:736: rvn->replacement = fd->setInputVarnode(rvn->replacement)
            // — Funcdata::setInputVarnode (funcdata_varnode.cc:340-373)
            // routes through VarnodeBank::setInput (varnode.cc:1358), which
            // erases both tree entries by identity, sets the INPUT flag and
            // re-inserts under the input key. The canonical return value
            // must be stored back so placeInputs wires the bank-owned
            // varnode; never an in-place INPUT flag mutation on a
            // tree-resident varnode.
            if let Some(rep) = self.new_varnodes[rvn_idx].replacement.clone() {
                let canonical = fd.set_input_varnode(rep);
                self.new_varnodes[rvn_idx].replacement = Some(canonical);
            }
        }
    }

    // Ghidra: transform.cc:740 TransformManager::placeInputs
    /// Set input Varnodes for all new ops. Faithful to `placeInputs`
    /// (transform.cc:740-754).
    fn place_inputs(&mut self, fd: &mut Funcdata) {
        // Snapshot the replacement varnodes to avoid borrow conflicts.
        let replacements: Vec<Option<Arc<RwLock<Varnode>>>> = self
            .new_varnodes
            .iter()
            .map(|v| v.replacement.clone())
            .collect();
        let n_ops = self.new_ops.len();
        for i in 0..n_ops {
            let op_rep = self.new_ops[i].replacement.clone();
            let input_indices: Vec<Option<usize>> = self.new_ops[i].input.clone();
            let special = self.new_ops[i].special;
            if let Some(op) = op_rep {
                for (slot, rvn_idx) in input_indices.iter().enumerate() {
                    if let Some(&Some(idx)) = Some(rvn_idx) {
                        if let Some(vn) = &replacements[idx] {
                            fd.op_set_input(&op, vn.clone(), slot);
                        }
                    }
                }
                // special_handling needs &rop; we have the index.
                let rop = &self.new_ops[i];
                let _ = special;
                self.special_handling(fd, rop);
            }
        }
    }

    // Ghidra: transform.cc:756 TransformManager::apply
    /// Apply the full transform to the function. Faithful to `apply`
    /// (transform.cc:756-765). P6 form: the oracle's stored `fd` member is
    /// threaded as the call parameter (the whole lifecycle runs under this
    /// one borrow).
    pub fn apply(&mut self, fd: &mut Funcdata) {
        let mut input_list: Vec<(usize, bool)> = Vec::new();
        self.create_ops(fd);
        self.create_varnodes(fd, &mut input_list);
        self.remove_old(fd);
        self.transform_input_varnodes(fd, &input_list);
        self.place_inputs(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laned_register_basic() {
        let lr = LanedRegister::with_sizes(16, 0b1010); // sizes 1 and 3
        assert!(lr.allowed_lane(1));
        assert!(lr.allowed_lane(3));
        assert!(!lr.allowed_lane(2));
        assert_eq!(lr.lane_sizes(), vec![1, 3]);
    }

    #[test]
    fn test_laned_register_parse_sizes() {
        let mut lr = LanedRegister::default();
        lr.parse_sizes(16, "1, 2, 4, 8");
        assert!(lr.allowed_lane(1));
        assert!(lr.allowed_lane(2));
        assert!(lr.allowed_lane(4));
        assert!(lr.allowed_lane(8));
        assert!(!lr.allowed_lane(3));
        assert_eq!(lr.get_whole_size(), 16);
    }

    #[test]
    fn test_lane_description_uniform() {
        let ld = LaneDescription::uniform(8, 2);
        assert_eq!(ld.get_num_lanes(), 4);
        assert_eq!(ld.get_size(0), 2);
        assert_eq!(ld.get_position(2), 4);
        assert_eq!(ld.get_whole_size(), 8);
    }

    #[test]
    fn test_lane_description_two_lane() {
        let ld = LaneDescription::two_lane(4, 1, 3);
        assert_eq!(ld.get_num_lanes(), 2);
        assert_eq!(ld.get_size(0), 1);
        assert_eq!(ld.get_size(1), 3);
        assert_eq!(ld.get_position(1), 1);
    }

    #[test]
    fn test_lane_description_get_boundary() {
        let ld = LaneDescription::uniform(8, 2);
        assert_eq!(ld.get_boundary(0), 0);
        assert_eq!(ld.get_boundary(2), 1);
        assert_eq!(ld.get_boundary(4), 2);
        assert_eq!(ld.get_boundary(6), 3);
        assert_eq!(ld.get_boundary(8), 4); // whole size -> lane count
        assert_eq!(ld.get_boundary(1), -1); // not on boundary
        assert_eq!(ld.get_boundary(-1), -1); // out of bounds
        assert_eq!(ld.get_boundary(9), -1); // out of bounds
    }

    #[test]
    fn test_lane_description_subset() {
        let mut ld = LaneDescription::uniform(8, 2);
        assert!(ld.subset(2, 4));
        assert_eq!(ld.get_whole_size(), 4);
        assert_eq!(ld.get_num_lanes(), 2);
        assert_eq!(ld.get_position(0), 0);
        assert_eq!(ld.get_position(1), 2);
    }

    #[test]
    fn test_lane_description_subset_whole() {
        let mut ld = LaneDescription::uniform(8, 2);
        assert!(ld.subset(0, 8));
        assert_eq!(ld.get_num_lanes(), 4);
    }

    #[test]
    fn test_lane_description_subset_splits_lane() {
        let mut ld = LaneDescription::uniform(8, 2);
        assert!(!ld.subset(1, 4)); // 1 is not on a boundary
    }

    #[test]
    fn test_lane_description_restriction() {
        let ld = LaneDescription::uniform(8, 2);
        let r = ld.restriction(4, 0, 2, 4);
        assert!(r.is_some());
        let (num, skip) = r.unwrap();
        assert_eq!(num, 2);
        assert_eq!(skip, 1);
    }

    #[test]
    fn test_lane_description_extension() {
        let ld = LaneDescription::uniform(8, 2);
        let r = ld.extension(2, 1, 2, 4);
        assert!(r.is_some());
    }

    #[test]
    fn test_transform_var_initialize() {
        let v = TransformVar::initialize(TransformVarType::Constant, None, 32, 4, 0xff);
        assert_eq!(v.var_type, TransformVarType::Constant);
        assert_eq!(v.byte_size, 4);
        assert_eq!(v.bit_size, 32);
        assert_eq!(v.val, 0xff);
        assert_eq!(v.flags, 0);
        assert!(v.def.is_none());
        assert!(v.replacement.is_none());
    }

    #[test]
    fn test_transform_manager_preexisting_varnode() {
        let mut mgr = TransformManager::new();
        let vn = Arc::new(RwLock::new(Varnode::new(4, Address::new(0x100))));
        let idx = mgr.new_preexisting_varnode(vn);
        assert_eq!(mgr.new_varnodes[idx].var_type, TransformVarType::Preexisting);
        assert!(mgr.new_varnodes[idx].vn.is_some());
        assert_eq!(mgr.piece_map.len(), 1);
    }

    #[test]
    fn test_transform_manager_unique_and_constant() {
        let mut mgr = TransformManager::new();
        let u = mgr.new_unique(4);
        let c = mgr.new_constant(4, 0, 0xff);
        assert_eq!(mgr.new_varnodes[u].var_type, TransformVarType::NormalTemp);
        assert_eq!(mgr.new_varnodes[u].byte_size, 4);
        assert_eq!(mgr.new_varnodes[c].var_type, TransformVarType::Constant);
        assert_eq!(mgr.new_varnodes[c].val, 0xff);
    }

    #[test]
    fn test_transform_manager_new_constant_shift() {
        let mut mgr = TransformManager::new();
        // val = 0xABCD, lsb_offset = 8 -> (0xABCD >> 8) & calc_mask(1) = 0xAB
        let c = mgr.new_constant(1, 8, 0xABCD);
        assert_eq!(mgr.new_varnodes[c].val, 0xAB);
    }

    #[test]
    fn test_transform_manager_split() {
        let mut mgr = TransformManager::new();
        let vn = Arc::new(RwLock::new(Varnode::new(8, Address::new(0x100))));
        let ld = LaneDescription::uniform(8, 2);
        let start = mgr.new_split(vn, &ld);
        assert_eq!(mgr.new_varnodes.len(), 4);
        // Most-significant piece is the terminator.
        assert_ne!(
            mgr.new_varnodes[start + 3].flags & transform_var_flags::SPLIT_TERMINATOR,
            0
        );
        assert_eq!(mgr.new_varnodes[start].val, 0); // bitpos 0
        assert_eq!(mgr.new_varnodes[start + 1].val, 16); // bitpos 16 (position 2 * 8)
    }

    #[test]
    fn test_transform_manager_op_replace() {
        use crate::address::SeqNum;
        use crate::op::PcodeOp;
        let dummy_op = Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        )));
        let mut mgr = TransformManager::new();
        let op_ref = crate::op::PcodeOpRef(dummy_op);
        let idx = mgr.new_op_replace(2, OpCode::CPUI_INT_ADD, op_ref);
        assert!(mgr.new_ops[idx].op.is_some());
        assert_eq!(mgr.new_ops[idx].opc, OpCode::CPUI_INT_ADD);
        assert_ne!(mgr.new_ops[idx].special & transform_op_special::OP_REPLACEMENT, 0);
        assert_eq!(mgr.new_ops[idx].input.len(), 2);
    }

    #[test]
    fn test_transform_manager_op_set_input_output() {
        let mut mgr = TransformManager::new();
        let out_vn = mgr.new_unique(4);
        let in_vn = mgr.new_unique(4);
        let dummy_follow_op = mgr.new_preexisting_op(
            1,
            OpCode::CPUI_COPY,
            crate::op::PcodeOpRef(Arc::new(RwLock::new(crate::op::PcodeOp::new(
                crate::address::SeqNum::new(Address::new(0x1000), 0),
                OpCode::CPUI_COPY,
            )))),
        );
        let op_idx = mgr.new_op(2, OpCode::CPUI_INT_ADD, dummy_follow_op);
        mgr.op_set_output(op_idx, out_vn);
        mgr.op_set_input(op_idx, in_vn, 0);
        assert_eq!(mgr.new_ops[op_idx].output, Some(out_vn));
        assert_eq!(mgr.new_ops[op_idx].input[0], Some(in_vn));
        assert_eq!(mgr.new_varnodes[out_vn].def, Some(op_idx));
    }

    #[test]
    fn test_preexisting_guard() {
        let piece_var = TransformVar::initialize(
            TransformVarType::Piece,
            None,
            16,
            2,
            0,
        );
        let normal_var = TransformVar::initialize(
            TransformVarType::NormalTemp,
            None,
            16,
            2,
            0,
        );
        assert!(TransformManager::preexisting_guard(0, &piece_var));
        assert!(!TransformManager::preexisting_guard(1, &piece_var));
        assert!(TransformManager::preexisting_guard(1, &normal_var));
    }

    #[test]
    fn test_get_preexisting_varnode_constant() {
        let mut mgr = TransformManager::new();
        let vn = Arc::new(RwLock::new(Varnode::new(4, Address::new(0xff))));
        vn.write().unwrap().set_flags(crate::varnode::varnode_flags::CONSTANT);
        vn.write().unwrap().address_space = AddressSpace::Const;
        let idx = mgr.get_preexisting_varnode(vn);
        assert_eq!(mgr.new_varnodes[idx].var_type, TransformVarType::Constant);
        assert_eq!(mgr.new_varnodes[idx].val, 0xff);
    }

    fn insertion_times(opcode: OpCode, use_follow: bool) -> Vec<u32> {
        let mut fd = Funcdata::new("insert", Address::new(0x1000), 0);
        let block = fd.create_new_block();
        let anchor = fd.new_op(0, Address::new(0x1000));
        fd.op_set_opcode(&anchor, OpCode::CPUI_COPY);
        fd.op_insert_end(&anchor, &block);
        let mut manager = TransformManager::new();
        manager.init(&mut fd);
        if use_follow {
            let follow = manager.new_op_replace(0, OpCode::CPUI_COPY, anchor.clone());
            manager.new_op(0, opcode, follow);
            manager.new_op(0, opcode, follow);
        } else {
            manager.new_op_replace(0, opcode, anchor.clone());
            manager.new_op_replace(0, opcode, anchor);
        }
        manager.apply(&mut fd);
        let result = block
            .read()
            .unwrap()
            .get_ops()
            .iter()
            .map(|op| op.0.read().unwrap().start.get_time())
            .collect();
        result
    }

    #[test]
    fn test_multiequal_insert_begin_vs_nonphi_order() {
        assert_eq!(
            insertion_times(OpCode::CPUI_MULTIEQUAL, false),
            vec![2, 1]
        );
        assert_eq!(insertion_times(OpCode::CPUI_COPY, false), vec![1, 2]);
        assert_eq!(
            insertion_times(OpCode::CPUI_MULTIEQUAL, true),
            vec![3, 2, 1]
        );
        assert_eq!(insertion_times(OpCode::CPUI_COPY, true), vec![2, 3, 1]);
    }
}

#[cfg(test)]
mod readinode2_tests {
    use super::*;

    // READINODE2: transform.cc:202-209 — a Piece replacement of an
    // address-preserving lane must run transferVarnodeProperties
    // (funcdata_varnode.cc:614-629), preserving directwrite|addrforce
    // and the shifted consume mask. Pre-fix this call was skipped, so
    // split pieces of guarded locations (e.g. the persist return-copy
    // of a global guarded by Heritage::guardReturns) lost addrforce and
    // RuleEarlyRemoval destroyed the write-back lattice.
    #[test]
    fn test_piece_replacement_transfers_addrforce_and_consume() {
        use crate::varnode::varnode_flags;
        let mut fd = crate::funcdata::Funcdata::new("piece_transfer", crate::address::Address::new(0x1000), 1);
        let op = fd.new_op(1, crate::address::Address::new(0x1004));
        let orig = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            8,
            crate::address::Address::new(0x156858),
        )));
        {
            let mut o = orig.write().unwrap();
            o.set_addr_force();
            o.set_direct_write();
            o.set_consume(0xffff_ffff_ffff_ffff);
        }
        // Lane 0 of an 8->6+2 split: 6 bytes at bitpos 0.
        let mut tv = TransformVar::initialize(
            TransformVarType::Piece,
            Some(orig.clone()),
            48,
            6,
            0,
        );
        tv.create_replacement(&mut fd, Some(&op));
        let repl = tv.replacement.expect("piece replacement created");
        let r = repl.read().unwrap();
        assert!(r.is_addr_force(), "addrforce must transfer to the piece");
        assert!(r.is_direct_write(), "directwrite must transfer to the piece");
        assert_eq!(r.get_consume(), crate::address::calc_mask(6));
        // Lane 1: 2 bytes at bitpos 48 (byte 6).
        let mut tv2 = TransformVar::initialize(
            TransformVarType::Piece,
            Some(orig.clone()),
            16,
            2,
            48,
        );
        tv2.create_replacement(&mut fd, Some(&op));
        let repl2 = tv2.replacement.expect("high piece replacement created");
        let r2 = repl2.read().unwrap();
        assert!(r2.is_addr_force());
        // cc:619-622: (consume >> 48 | fill) & mask(2) — all-ones stays all-ones.
        assert_eq!(r2.get_consume(), crate::address::calc_mask(2));
        // Non-addrforced original keeps the piece clean of both flags.
        let plain = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            8,
            crate::address::Address::new(0x200),
        )));
        plain.write().unwrap().set_consume(0);
        let mut tv3 =
            TransformVar::initialize(TransformVarType::Piece, Some(plain), 48, 6, 0);
        tv3.create_replacement(&mut fd, Some(&op));
        let repl3 = tv3.replacement.unwrap();
        let r3 = {
            let g = repl3.read().unwrap();
            (g.is_addr_force(), g.is_direct_write(), g.get_consume())
        };
        assert!(!r3.0);
        assert!(!r3.1);
        assert_eq!(r3.2, 0, "zero consume must not gain fill bits at lsb 0");
    }

    // CR-READINODE2 §5-2 remediation: two assertions for the branches the
    // original test left uncovered.
    #[test]
    fn test_piece_transfer_lsb8_guard_false_and_no_def_path() {
        use crate::varnode::varnode_flags;
        let mut fd = crate::funcdata::Funcdata::new(
            "piece_transfer_edge",
            crate::address::Address::new(0x1000),
            1,
        );
        // (1) lsbOffset >= sizeof(uintb): funcdata_varnode.cc:618 guard is
        // false, so cc:617's initializer survives — newConsume stays ~0
        // regardless of the source consume and is NOT masked by calc_mask
        // (the & calc_mask(newSize) lives inside the guarded block only).
        let wide = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            16,
            crate::address::Address::new(0x300),
        )));
        {
            let mut w = wide.write().unwrap();
            w.set_addr_force();
            w.set_consume(0); // zero source consume must still yield ~0
        }
        let mut tv_wide = TransformVar::initialize(
            TransformVarType::Piece,
            Some(wide),
            128, // bit_size of the 16-byte source (unused by the Piece arm)
            2,
            64, // val: bit 64 -> bytePos 8 -> lsbOffset 8 (== sizeof(uintb))
        );
        let op = fd.new_op(1, crate::address::Address::new(0x1008));
        tv_wide.create_replacement(&mut fd, Some(&op));
        let rw = tv_wide.replacement.expect("lsb8 piece replacement created");
        let w = rw.read().unwrap();
        assert!(w.is_addr_force(), "flags transfer is outside the lsb guard");
        assert_eq!(w.get_consume(), !0u64, "lsb>=8 keeps the ~0 initializer");
        // (2) def == None path: transform.cc:204-205 takes newVarnode (not
        // newVarnodeOut) and cc:208 still transfers properties.
        let orig = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new(
            8,
            crate::address::Address::new(0x400),
        )));
        {
            let mut o = orig.write().unwrap();
            o.set_addr_force();
            o.set_consume(0xffff_ffff_ffff_ffff);
        }
        let mut tv_nodef = TransformVar::initialize(
            TransformVarType::Piece,
            Some(orig),
            48,
            6,
            0,
        );
        tv_nodef.create_replacement(&mut fd, None);
        let rn = tv_nodef.replacement.expect("no-def piece replacement created");
        let n = rn.read().unwrap();
        assert!(n.is_addr_force(), "cc:208 transfer runs on the def==0 path");
        assert_eq!(n.get_consume(), crate::address::calc_mask(6));
    }
}
