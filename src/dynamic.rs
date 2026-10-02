//! Dynamic hash-based variable/op identification.
//!
//! Corresponds to Ghidra's `dynamic.hh` / `dynamic.cc` (773 lines).
//!
//! DynamicHash provides a content-addressable hash for Varnodes and PcodeOps
//! that is stable across recompilation. It builds a local sub-graph around
//! the target and hashes the op-code structure + addresses to produce a
//! unique identifier. This is used by the decompiler for:
//! - Equate/rename annotations that reference specific varnodes
//! - Cross-compilation variable identification
//! - Debug/trace annotations
//!
//! Key classes (dynamic.hh):
//! - `ToOpEdge`: an edge from a Varnode to a PcodeOp (with slot, -1 = output)
//! - `DynamicHash`: the hashing engine
//!
//! # Status (2026-07-22)
//! Full port of dynamic.cc: transtable, ToOpEdge compare/hash, buildVn{Up,Down},
//! buildOp{Up,Down}, gather{UnmarkedVn,UnmarkedOp}, calcHash (both overloads),
//! pieceTogetherHash, moveOffSkip, dedupVarnodes, uniqueHash (both overloads),
//! findVarnode, findOp, gatherFirstLevelVars, gatherOpsAtAddress, and the
//! hash-decode statics (getSlotFromHash, getMethodFromHash, ...).

use crate::address::Address;
use crate::opcodes::OpCode;
use crate::op::PcodeOp;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};

// Ghidra: dynamic.cc:24-63 DynamicHash::transtable
/// Translation table for hashing op-codes. Lumps certain operators together
/// (i.e. ADD/SUB/PTRADD/PTRSUB all hash as INT_ADD) so that the hash is
/// invariant under common rewrites. Zero indicates the operator should be
/// skipped (CAST only; also the unused FLOAT slot 45).
///
/// Faithful to `DynamicHash::transtable` (dynamic.cc:24-63). Indexed by the
/// OpCode discriminant, matching Ghidra's `CPUI_*` numeric ordering. Both
/// Ghidra's C++ enum and Rudra's `#[repr(i32)]` enum assign the same numeric
/// values (note value 45 is unused in both, so FLOAT_NAN == 46).
pub const TRANSTABLE: [u32; 75] = {
    let mut t = [0u32; 75];
    t[1] = 1; // CPUI_COPY
    t[2] = 2; // CPUI_LOAD
    t[3] = 3; // CPUI_STORE
    t[4] = 4; // CPUI_BRANCH
    t[5] = 5; // CPUI_CBRANCH
    t[6] = 6; // CPUI_BRANCHIND
    t[7] = 7; // CPUI_CALL
    t[8] = 8; // CPUI_CALLIND
    t[9] = 9; // CPUI_CALLOTHER
    t[10] = 10; // CPUI_RETURN
    t[11] = 11; // CPUI_INT_EQUAL
    t[12] = 11; // CPUI_INT_NOTEQUAL (hashes same as EQUAL)
    t[13] = 13; // CPUI_INT_SLESS
    t[14] = 13; // CPUI_INT_SLESSEQUAL (hashes same as SLESS)
    t[15] = 15; // CPUI_INT_LESS
    t[16] = 15; // CPUI_INT_LESSEQUAL (hashes same as LESS)
    t[17] = 17; // CPUI_INT_ZEXT
    t[18] = 18; // CPUI_INT_SEXT
    t[19] = 19; // CPUI_INT_ADD
    t[20] = 19; // CPUI_INT_SUB (hashes same as ADD)
    t[21] = 21; // CPUI_INT_CARRY
    t[22] = 22; // CPUI_INT_SCARRY
    t[23] = 23; // CPUI_INT_SBORROW
    t[24] = 24; // CPUI_INT_2COMP
    t[25] = 25; // CPUI_INT_NEGATE
    t[26] = 26; // CPUI_INT_XOR
    t[27] = 27; // CPUI_INT_AND
    t[28] = 28; // CPUI_INT_OR
    t[29] = 32; // CPUI_INT_LEFT (hashes same as MULT)
    t[30] = 30; // CPUI_INT_RIGHT
    t[31] = 31; // CPUI_INT_SRIGHT
    t[32] = 32; // CPUI_INT_MULT
    t[33] = 33; // CPUI_INT_DIV
    t[34] = 34; // CPUI_INT_SDIV
    t[35] = 35; // CPUI_INT_REM
    t[36] = 36; // CPUI_INT_SREM
    t[37] = 37; // CPUI_BOOL_NEGATE
    t[38] = 38; // CPUI_BOOL_XOR
    t[39] = 39; // CPUI_BOOL_AND
    t[40] = 40; // CPUI_BOOL_OR
    t[41] = 41; // CPUI_FLOAT_EQUAL
    t[42] = 41; // CPUI_FLOAT_NOTEQUAL (hashes same as EQUAL)
    t[43] = 43; // CPUI_FLOAT_LESS
    t[44] = 43; // CPUI_FLOAT_LESSEQUAL (hashes same as LESS)
    t[45] = 0; // Unused slot -> skip
    t[46] = 46; // CPUI_FLOAT_NAN
    t[47] = 47; // CPUI_FLOAT_ADD
    t[48] = 48; // CPUI_FLOAT_DIV
    t[49] = 49; // CPUI_FLOAT_MULT
    t[50] = 47; // CPUI_FLOAT_SUB (hashes same as ADD)
    t[51] = 51; // CPUI_FLOAT_NEG
    t[52] = 52; // CPUI_FLOAT_ABS
    t[53] = 53; // CPUI_FLOAT_SQRT
    t[54] = 54; // CPUI_FLOAT_INT2FLOAT
    t[55] = 55; // CPUI_FLOAT_FLOAT2FLOAT
    t[56] = 56; // CPUI_FLOAT_TRUNC
    t[57] = 57; // CPUI_FLOAT_CEIL
    t[58] = 58; // CPUI_FLOAT_FLOOR
    t[59] = 59; // CPUI_FLOAT_ROUND
    t[60] = 60; // CPUI_MULTIEQUAL
    t[61] = 61; // CPUI_INDIRECT
    t[62] = 62; // CPUI_PIECE
    t[63] = 63; // CPUI_SUBPIECE
    t[64] = 0; // CPUI_CAST -> skip
    t[65] = 19; // CPUI_PTRADD (hashes same as INT_ADD)
    t[66] = 19; // CPUI_PTRSUB (hashes same as INT_ADD)
    t[67] = 67; // CPUI_SEGMENTOP
    t[68] = 68; // CPUI_CPOOLREF
    t[69] = 69; // CPUI_NEW
    t[70] = 70; // CPUI_INSERT
    t[71] = 71; // CPUI_EXTRACT
    t[72] = 72; // CPUI_POPCOUNT
    t[73] = 73; // CPUI_LZCOUNT
    t
};

// RUDRA-GLUE: translate_opcode is a thin accessor over the `transtable`
//   constant array. Ghidra indexes the C++ array directly
//   (`transtable[op->code()]`); Rust wraps the indexing because `OpCode`
//   has no `as usize` that is guaranteed in range without a repr.
/// Look up the hash-translation value for `opc`. Zero means skip (CAST or the
/// unused FLOAT slot). Faithful to indexing `DynamicHash::transtable[]`
/// (dynamic.cc:24-63).
pub fn translate_opcode(opc: OpCode) -> u32 {
    let idx = opc as usize;
    if idx < TRANSTABLE.len() {
        TRANSTABLE[idx]
    } else {
        0
    }
}

/// Number of address bytes hashed in `ToOpEdge::hash`. Ghidra uses
/// `op->getSeqNum().getAddr().getAddrSize()`. Rudra's `Address` is a bare
/// `u64` with no associated space, so we hash all 8 bytes — matches Ghidra
/// on 64-bit targets, conservative superset on 32-bit.
const HASH_ADDR_SIZE: usize = 8;

/// An edge between a Varnode and a PcodeOp. Faithful to `ToOpEdge`
/// (dynamic.hh:32). slot == -1 represents the op's output (Ghidra int4 -1).
#[derive(Clone, Debug)]
pub struct ToOpEdge {
    /// The PcodeOp defining the edge. Faithful to `op` (dynamic.hh:34).
    pub op: Arc<RwLock<PcodeOp>>,
    /// Slot containing the input Varnode, or -1 for the op output.
    pub slot: i32,
}

impl ToOpEdge {
    // Ghidra: dynamic.hh:36 ToOpEdge::ToOpEdge
    pub fn new(op: Arc<RwLock<PcodeOp>>, slot: i32) -> Self {
        Self { op, slot }
    }

    // Ghidra: dynamic.hh:37 ToOpEdge::getOp
    pub fn get_op(&self) -> &Arc<RwLock<PcodeOp>> {
        &self.op
    }

    // Ghidra: dynamic.hh:38 ToOpEdge::getSlot
    pub fn get_slot(&self) -> i32 {
        self.slot
    }

    // Ghidra: dynamic.cc:69 ToOpEdge::operator<
    /// Compare two edges based on PcodeOp sequence number, then slot. Faithful
    /// to `ToOpEdge::operator<` (dynamic.cc:69-81). Sort order: SeqNum addr,
    /// then SeqNum order, then slot.
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        let (addr_a, ord_a) = {
            let a = self.op.read().unwrap();
            (a.start.addr, a.start.order)
        };
        let (addr_b, ord_b) = {
            let b = other.op.read().unwrap();
            (b.start.addr, b.start.order)
        };
        if addr_a != addr_b {
            return addr_a.cmp(&addr_b);
        }
        if ord_a != ord_b {
            return ord_a.cmp(&ord_b);
        }
        self.slot.cmp(&other.slot)
    }

    // Ghidra: dynamic.cc:92 ToOpEdge::hash
    /// Fold this edge into the hash accumulator. Faithful to `ToOpEdge::hash`
    /// (dynamic.cc:92-104). Hashes slot, translated opcode, each address byte.
    pub fn hash_into(&self, reg: u32) -> u32 {
        let mut h = crate::crc32::crc_update(reg, self.slot as u32);
        let (opc_translated, addr) = {
            let op_r = self.op.read().unwrap();
            (translate_opcode(op_r.opcode), op_r.start.addr.as_u64())
        };
        h = crate::crc32::crc_update(h, opc_translated);
        let mut val = addr;
        for _ in 0..HASH_ADDR_SIZE {
            h = crate::crc32::crc_update(h, (val & 0xff) as u32);
            val >>= 8;
        }
        h
    }
}

/// The dynamic hashing engine. Faithful to `DynamicHash` (dynamic.hh:62).
pub struct DynamicHash {
    vnproc: usize,
    opproc: usize,
    opedgeproc: usize,
    mark_op: Vec<Arc<RwLock<PcodeOp>>>,
    mark_vn: Vec<Arc<RwLock<Varnode>>>,
    vn_edge: Vec<Arc<RwLock<Varnode>>>,
    op_edge: Vec<ToOpEdge>,
    addr_result: Address,
    hash: u64,
}

impl DynamicHash {
    // Ghidra: dynamic.hh:62 DynamicHash (default ctor)
    pub fn new() -> Self {
        Self {
            vnproc: 0,
            opproc: 0,
            opedgeproc: 0,
            mark_op: Vec::new(),
            mark_vn: Vec::new(),
            vn_edge: Vec::new(),
            op_edge: Vec::new(),
            addr_result: Address::new(0),
            hash: 0,
        }
    }

    // Ghidra: dynamic.cc:193 DynamicHash::clear
    /// Clear all sub-graph state for a new hash calculation. Faithful to
    /// `DynamicHash::clear` (dynamic.cc:193-200).
    pub fn clear(&mut self) {
        self.mark_op.clear();
        self.mark_vn.clear();
        self.vn_edge.clear();
        self.op_edge.clear();
        self.vnproc = 0;
        self.opproc = 0;
        self.opedgeproc = 0;
    }

    // Ghidra: dynamic.hh:91 DynamicHash::getHash
    pub fn get_hash(&self) -> u64 {
        self.hash
    }

    // Ghidra: dynamic.hh:93 DynamicHash::getAddress
    pub fn get_address(&self) -> Address {
        self.addr_result
    }

    // Ghidra: dynamic.cc:109 DynamicHash::buildVnUp
    /// Add the edge between a Varnode and its defining PcodeOp. Faithful to
    /// `buildVnUp` (dynamic.cc:109-120). Walks up through skip ops (CAST).
    fn build_vn_up(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let mut cur = vn.clone();
        loop {
            if !cur.read().unwrap().is_written() {
                return;
            }
            let def = match cur.read().unwrap().get_def() {
                Some(d) => d,
                None => return,
            };
            let def_opc = def.read().unwrap().opcode;
            if translate_opcode(def_opc) != 0 {
                self.op_edge.push(ToOpEdge::new(def, -1));
                return;
            }
            let next = def.read().unwrap().get_in(0).cloned();
            cur = match next {
                Some(v) => v,
                None => return,
            };
        }
    }

    // Ghidra: dynamic.cc:125 DynamicHash::buildVnDown
    /// Add edges between a Varnode and ops that read it. Faithful to
    /// `buildVnDown` (dynamic.cc:125-148). Walks down through skip ops.
    fn build_vn_down(&mut self, vn: &Arc<RwLock<Varnode>>) {
        let insize = self.op_edge.len();
        let descends: Vec<Arc<RwLock<PcodeOp>>> = vn.read().unwrap().descend_iter().collect();
        for d_op in descends {
            let mut tmpvn = vn.clone();
            let mut op = d_op;
            let mut dead_end = false;
            loop {
                let cur_opc = op.read().unwrap().opcode;
                if translate_opcode(cur_opc) != 0 {
                    break;
                }
                let out = match op.read().unwrap().output.clone() {
                    Some(o) => o,
                    None => {
                        dead_end = true;
                        break;
                    }
                };
                tmpvn = out;
                match tmpvn.read().unwrap().lone_descend() {
                    Some(n) => op = n,
                    None => {
                        dead_end = true;
                        break;
                    }
                }
            }
            if dead_end {
                continue;
            }
            let slot = match op.read().unwrap().slot_of_input(&tmpvn) {
                Some(s) => s as i32,
                None => {
                    let is_output = op
                        .read()
                        .unwrap()
                        .output
                        .as_ref()
                        .map(|o| Arc::ptr_eq(o, &tmpvn))
                        .unwrap_or(false);
                    if is_output {
                        -1
                    } else {
                        continue;
                    }
                }
            };
            self.op_edge.push(ToOpEdge::new(op, slot));
        }
        if self.op_edge.len() - insize > 1 {
            self.op_edge[insize..].sort_by(ToOpEdge::compare);
        }
    }

    // Ghidra: dynamic.cc:152 DynamicHash::buildOpUp
    /// Stage input Varnodes of an op. Faithful to `buildOpUp` (152-159).
    fn build_op_up(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        let n = op.read().unwrap().num_input();
        for i in 0..n {
            if let Some(inv) = op.read().unwrap().get_in(i).cloned() {
                self.vn_edge.push(inv);
            }
        }
    }

    // Ghidra: dynamic.cc:162 DynamicHash::buildOpDown
    /// Stage the output Varnode of an op. Faithful to `buildOpDown` (162-167).
    fn build_op_down(&mut self, op: &Arc<RwLock<PcodeOp>>) {
        if let Some(out) = op.read().unwrap().output.clone() {
            self.vn_edge.push(out);
        }
    }

    // Ghidra: dynamic.cc:170 DynamicHash::gatherUnmarkedVn
    /// Move staged Varnodes into the sub-graph, marking each. Faithful to
    /// `gatherUnmarkedVn` (170-180).
    fn gather_unmarked_vn(&mut self) {
        for vn in self.vn_edge.drain(..) {
            if vn.read().unwrap().is_mark() {
                continue;
            }
            vn.write().unwrap().set_mark();
            self.mark_vn.push(vn);
        }
    }

    // Ghidra: dynamic.cc:182 DynamicHash::gatherUnmarkedOp
    /// Mark new PcodeOps referenced by op_edge. Faithful to
    /// `gatherUnmarkedOp` (182-191).
    fn gather_unmarked_op(&mut self) {
        while self.opedgeproc < self.op_edge.len() {
            let op = self.op_edge[self.opedgeproc].op.clone();
            self.opedgeproc += 1;
            if op.read().unwrap().is_mark() {
                continue;
            }
            op.write().unwrap().set_mark();
            self.mark_op.push(op);
        }
    }

    // Ghidra: dynamic.cc:323 DynamicHash::pieceTogetherHash
    /// Assemble the final 64-bit hash from the collected sub-graph. Faithful
    /// to `pieceTogetherHash` (dynamic.cc:323-381).
    fn piece_together_hash(&mut self, root: &Arc<RwLock<Varnode>>, method: u32) {
        for vn in &self.mark_vn {
            vn.write().unwrap().clear_mark();
        }
        for op in &self.mark_op {
            op.write().unwrap().clear_mark();
        }
        if self.op_edge.is_empty() {
            self.hash = 0;
            self.addr_result = Address::new(0);
            return;
        }
        let mut reg: u32 = 0x3ba0fe06;
        let (root_size, root_is_const, root_offset) = {
            let r = root.read().unwrap();
            (r.get_size(), r.is_constant(), r.get_offset())
        };
        reg = crate::crc32::crc_update(reg, root_size as u32);
        if root_is_const {
            let mut val = root_offset;
            for _ in 0..root_size {
                reg = crate::crc32::crc_update(reg, (val & 0xff) as u32);
                val >>= 8;
            }
        }
        for edge in &self.op_edge {
            reg = edge.hash_into(reg);
        }
        let mut attached_op: Option<Arc<RwLock<PcodeOp>>> = None;
        let mut attached_slot: i32 = 0;
        let mut attached = true;
        for edge in &self.op_edge {
            let op_arc = edge.op.clone();
            let slot = edge.slot;
            let matches = if slot < 0 {
                op_arc
                    .read()
                    .unwrap()
                    .output
                    .as_ref()
                    .map(|o| Arc::ptr_eq(o, root))
                    .unwrap_or(false)
            } else {
                op_arc
                    .read()
                    .unwrap()
                    .get_in(slot as usize)
                    .map(|v| Arc::ptr_eq(v, root))
                    .unwrap_or(false)
            };
            if matches {
                attached_op = Some(op_arc);
                attached_slot = slot;
                break;
            }
        }
        if attached_op.is_none() {
            attached_op = Some(self.op_edge[0].op.clone());
            attached_slot = self.op_edge[0].slot;
            attached = false;
        }
        let attached_op = attached_op.unwrap();
        let translated_opc = translate_opcode(attached_op.read().unwrap().opcode);
        let mut h: u64 = if attached { 0 } else { 1 };
        h <<= 4;
        h |= (method & 0xf) as u64;
        h <<= 7;
        h |= (translated_opc & 0x7f) as u64;
        h <<= 5;
        h |= (attached_slot as u32 & 0x1f) as u64;
        h <<= 32;
        h |= reg as u64;
        self.hash = h;
        self.addr_result = attached_op.read().unwrap().start.addr;
    }

    // Ghidra: dynamic.cc:202 DynamicHash::calcHash(PcodeOp*, int4, uint4)
    /// Calculate the hash for a given PcodeOp + slot + method. Faithful to
    /// `calcHash(const PcodeOp *op,int4 slot,uint4 method)` (202-255).
    pub fn calc_hash_op(&mut self, op: &Arc<RwLock<PcodeOp>>, slot: i32, method: u32) {
        let root: Arc<RwLock<Varnode>> = if slot < 0 {
            match op.read().unwrap().output.clone() {
                Some(o) => o,
                None => {
                    self.hash = 0;
                    self.addr_result = Address::new(0);
                    return;
                }
            }
        } else {
            match op.read().unwrap().get_in(slot as usize).cloned() {
                Some(v) => v,
                None => {
                    self.hash = 0;
                    self.addr_result = Address::new(0);
                    return;
                }
            }
        };
        self.vnproc = 0;
        self.opproc = 0;
        self.opedgeproc = 0;
        self.op_edge.push(ToOpEdge::new(op.clone(), slot));
        match method {
            4 => {}
            5 => {
                self.gather_unmarked_op();
                while self.opproc < self.mark_op.len() {
                    let mop = self.mark_op[self.opproc].clone();
                    self.opproc += 1;
                    self.build_op_up(&mop);
                }
                self.gather_unmarked_vn();
                while self.vnproc < self.mark_vn.len() {
                    let vn = self.mark_vn[self.vnproc].clone();
                    self.vnproc += 1;
                    self.build_vn_up(&vn);
                }
            }
            6 => {
                self.gather_unmarked_op();
                while self.opproc < self.mark_op.len() {
                    let mop = self.mark_op[self.opproc].clone();
                    self.opproc += 1;
                    self.build_op_down(&mop);
                }
                self.gather_unmarked_vn();
                while self.vnproc < self.mark_vn.len() {
                    let vn = self.mark_vn[self.vnproc].clone();
                    self.vnproc += 1;
                    self.build_vn_down(&vn);
                }
            }
            _ => {}
        }
        self.piece_together_hash(&root, method);
    }

    // Ghidra: dynamic.cc:268 DynamicHash::calcHash(Varnode*, uint4)
    /// Calculate the hash for a given root Varnode + method. Faithful to
    /// `calcHash(const Varnode *root,uint4 method)` (268-316).
    pub fn calc_hash_vn(&mut self, root: &Arc<RwLock<Varnode>>, method: u32) {
        self.vnproc = 0;
        self.opproc = 0;
        self.opedgeproc = 0;
        self.vn_edge.push(root.clone());
        self.gather_unmarked_vn();
        // dynamic.cc:277-280 four-class semantics: the up pass walks a
        // LOCAL index from vnproc (still 0) without consuming it, then the
        // down pass re-runs from vnproc=0 — the root gets BOTH its up edge
        // (defining op, walking up through skip ops) AND its down edges
        // (every reader, walking down through skip ops) in the base level
        // of every calcHash(Varnode*, method) call. The previous shape set
        // vnproc = mark_vn.len() between the two loops, which killed the
        // down pass entirely (DYNHASH-UNIQUE-ANCHOR-0001).
        let mut i = self.vnproc;
        while i < self.mark_vn.len() {
            let vn = self.mark_vn[i].clone();
            i += 1;
            self.build_vn_up(&vn);
        }
        while self.vnproc < self.mark_vn.len() {
            let vn = self.mark_vn[self.vnproc].clone();
            self.vnproc += 1;
            self.build_vn_down(&vn);
        }
        match method {
            0 => {}
            1 => {
                self.gather_unmarked_op();
                while self.opproc < self.mark_op.len() {
                    let mop = self.mark_op[self.opproc].clone();
                    self.opproc += 1;
                    self.build_op_up(&mop);
                }
                self.gather_unmarked_vn();
                while self.vnproc < self.mark_vn.len() {
                    let vn = self.mark_vn[self.vnproc].clone();
                    self.vnproc += 1;
                    self.build_vn_up(&vn);
                }
            }
            2 => {
                self.gather_unmarked_op();
                while self.opproc < self.mark_op.len() {
                    let mop = self.mark_op[self.opproc].clone();
                    self.opproc += 1;
                    self.build_op_down(&mop);
                }
                self.gather_unmarked_vn();
                while self.vnproc < self.mark_vn.len() {
                    let vn = self.mark_vn[self.vnproc].clone();
                    self.vnproc += 1;
                    self.build_vn_down(&vn);
                }
            }
            3 => {
                self.gather_unmarked_op();
                while self.opproc < self.mark_op.len() {
                    let mop = self.mark_op[self.opproc].clone();
                    self.opproc += 1;
                    self.build_op_up(&mop);
                }
                self.gather_unmarked_vn();
                while self.vnproc < self.mark_vn.len() {
                    let vn = self.mark_vn[self.vnproc].clone();
                    self.vnproc += 1;
                    self.build_vn_down(&vn);
                }
            }
            _ => {}
        }
        self.piece_together_hash(root, method);
    }

    // Ghidra: dynamic.cc:389 DynamicHash::moveOffSkip
    /// Walk past skip ops (CAST) along the data-flow indicated by slot.
    /// Faithful to `moveOffSkip(const PcodeOp *&,int4 &)` (389-407).
    pub fn move_off_skip(op: &mut Option<Arc<RwLock<PcodeOp>>>, slot: &mut i32) {
        loop {
            let cur = match op.clone() {
                Some(c) => c,
                None => return,
            };
            if translate_opcode(cur.read().unwrap().opcode) != 0 {
                return;
            }
            if *slot >= 0 {
                let out = match cur.read().unwrap().output.clone() {
                    Some(o) => o,
                    None => {
                        *op = None;
                        return;
                    }
                };
                let next = { out.read().unwrap().lone_descend() };
                match next {
                    Some(n) => {
                        let new_slot = { n.read().unwrap().slot_of_input(&out) };
                        *slot = new_slot.map(|s| s as i32).unwrap_or(-1);
                        *op = Some(n);
                    }
                    None => {
                        *op = None;
                        return;
                    }
                }
            } else {
                let in0 = match cur.read().unwrap().get_in(0).cloned() {
                    Some(v) => v,
                    None => {
                        *op = None;
                        return;
                    }
                };
                if !in0.read().unwrap().is_written() {
                    *op = None;
                    return;
                }
                let def = { in0.read().unwrap().get_def() };
                match def {
                    Some(d) => *op = Some(d),
                    None => {
                        *op = None;
                        return;
                    }
                }
            }
        }
    }

    // Ghidra: dynamic.cc:424 DynamicHash::uniqueHash(Varnode*, Funcdata*)
    /// Select the simplest hash method (0..3) making root unique. Faithful to
    /// `uniqueHash(const Varnode *root,Funcdata *fd)` (424-477).
    pub fn unique_hash_vn(&mut self, root: &Arc<RwLock<Varnode>>, fd: &crate::funcdata::Funcdata) {
        let mut vnlist: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut vnlist2: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut champion: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let maxduplicates = 8usize;
        let mut tmphash: u64 = 0;
        let mut tmpaddr = Address::new(0);
        for method in 0..4u32 {
            self.clear();
            self.calc_hash_vn(root, method);
            if self.hash == 0 {
                return;
            }
            tmphash = self.hash;
            tmpaddr = self.addr_result;
            vnlist.clear();
            vnlist2.clear();
            Self::gather_first_level_vars(&mut vnlist, fd, tmpaddr, tmphash);
            for tmpvn in vnlist.iter().cloned() {
                self.clear();
                self.calc_hash_vn(&tmpvn, method);
                if Self::get_comparable(self.hash) == Self::get_comparable(tmphash) {
                    vnlist2.push(tmpvn);
                    if vnlist2.len() > maxduplicates {
                        break;
                    }
                }
            }
            if vnlist2.len() <= maxduplicates
                && (champion.is_empty() || vnlist2.len() < champion.len())
            {
                champion = vnlist2.clone();
                if champion.len() == 1 {
                    break;
                }
            }
        }
        if champion.is_empty() {
            self.hash = 0;
            self.addr_result = Address::new(0);
            return;
        }
        let total = champion.len() - 1;
        let mut pos = 0usize;
        while pos <= total {
            if Arc::ptr_eq(&champion[pos], root) {
                break;
            }
            pos += 1;
        }
        if pos > total {
            self.hash = 0;
            self.addr_result = Address::new(0);
            return;
        }
        self.hash = tmphash | ((pos as u64) << 49) | ((total as u64) << 52);
        self.addr_result = tmpaddr;
    }

    // Ghidra: dynamic.cc:485 DynamicHash::uniqueHash(PcodeOp*, int4, Funcdata*)
    /// Select a unique hash method (4..6) for the given op+slot. Faithful to
    /// `uniqueHash(const PcodeOp *op,int4 slot,Funcdata *fd)` (485-548).
    pub fn unique_hash_op(
        &mut self,
        op: &Arc<RwLock<PcodeOp>>,
        slot: i32,
        fd: &crate::funcdata::Funcdata,
    ) {
        let mut cur_op: Option<Arc<RwLock<PcodeOp>>> = Some(op.clone());
        let mut cur_slot = slot;
        Self::move_off_skip(&mut cur_op, &mut cur_slot);
        let op = match cur_op {
            Some(o) => o,
            None => {
                self.hash = 0;
                self.addr_result = Address::new(0);
                return;
            }
        };
        let mut oplist: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut oplist2: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut champion: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let maxduplicates = 8usize;
        let mut tmphash: u64 = 0;
        let mut tmpaddr = Address::new(0);
        let addr = op.read().unwrap().get_addr();
        Self::gather_ops_at_address(&mut oplist, fd, addr);
        for method in 4..7u32 {
            self.clear();
            self.calc_hash_op(&op, cur_slot, method);
            if self.hash == 0 {
                return;
            }
            tmphash = self.hash;
            tmpaddr = self.addr_result;
            oplist2.clear();
            for tmpop in oplist.iter().cloned() {
                if (cur_slot as usize) >= tmpop.read().unwrap().num_input() {
                    continue;
                }
                self.clear();
                self.calc_hash_op(&tmpop, cur_slot, method);
                if Self::get_comparable(self.hash) == Self::get_comparable(tmphash) {
                    oplist2.push(tmpop);
                    if oplist2.len() > maxduplicates {
                        break;
                    }
                }
            }
            if oplist2.len() <= maxduplicates
                && (champion.is_empty() || oplist2.len() < champion.len())
            {
                champion = oplist2.clone();
                if champion.len() == 1 {
                    break;
                }
            }
        }
        if champion.is_empty() {
            self.hash = 0;
            self.addr_result = Address::new(0);
            return;
        }
        let total = champion.len() - 1;
        let mut pos = 0usize;
        while pos <= total {
            if Arc::ptr_eq(&champion[pos], &op) {
                break;
            }
            pos += 1;
        }
        if pos > total {
            self.hash = 0;
            self.addr_result = Address::new(0);
            return;
        }
        self.hash = tmphash | ((pos as u64) << 49) | ((total as u64) << 52);
        self.addr_result = tmpaddr;
    }

    // Ghidra: dynamic.cc:561 DynamicHash::findVarnode
    /// Find the unique matching Varnode for an address+hash. Faithful to
    /// `findVarnode` (dynamic.cc:561-580).
    pub fn find_varnode(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        addr: Address,
        mut h: u64,
    ) -> Option<Arc<RwLock<Varnode>>> {
        let method = Self::get_method_from_hash(h);
        let total = Self::get_total_from_hash(h);
        let pos = Self::get_position_from_hash(h);
        Self::clear_total_position(&mut h);
        let mut vnlist: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut vnlist2: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        Self::gather_first_level_vars(&mut vnlist, fd, addr, h);
        for tmpvn in vnlist {
            self.clear();
            self.calc_hash_vn(&tmpvn, method);
            if Self::get_comparable(self.hash) == Self::get_comparable(h) {
                vnlist2.push(tmpvn);
            }
        }
        if total != vnlist2.len() {
            return None;
        }
        vnlist2.into_iter().nth(pos)
    }

    // Ghidra: dynamic.cc:593 DynamicHash::findOp
    /// Find the unique matching PcodeOp for an address+hash. Faithful to
    /// `findOp` (dynamic.cc:593-615).
    pub fn find_op(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        addr: Address,
        mut h: u64,
    ) -> Option<Arc<RwLock<PcodeOp>>> {
        let method = Self::get_method_from_hash(h);
        let slot = Self::get_slot_from_hash(h);
        let total = Self::get_total_from_hash(h);
        let pos = Self::get_position_from_hash(h);
        Self::clear_total_position(&mut h);
        let mut oplist: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut oplist2: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        Self::gather_ops_at_address(&mut oplist, fd, addr);
        for tmpop in oplist {
            if slot >= 0 && (slot as usize) >= tmpop.read().unwrap().num_input() {
                continue;
            }
            self.clear();
            self.calc_hash_op(&tmpop, slot, method);
            if Self::get_comparable(self.hash) == Self::get_comparable(h) {
                oplist2.push(tmpop);
            }
        }
        if total != oplist2.len() {
            return None;
        }
        oplist2.into_iter().nth(pos)
    }

    // Ghidra: dynamic.cc:619 DynamicHash::dedupVarnodes
    /// Remove duplicate Varnodes preserving order. Faithful to
    /// `dedupVarnodes` (dynamic.cc:619-634).
    pub fn dedup_varnodes(varlist: &mut Vec<Arc<RwLock<Varnode>>>) {
        if varlist.len() < 2 {
            return;
        }
        let mut res_list: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        for vn in varlist.iter() {
            if vn.read().unwrap().is_mark() {
                continue;
            }
            vn.write().unwrap().set_mark();
            res_list.push(vn.clone());
        }
        for vn in &res_list {
            vn.write().unwrap().clear_mark();
        }
        std::mem::swap(varlist, &mut res_list);
    }

    // Ghidra: dynamic.cc:645 DynamicHash::gatherFirstLevelVars
    /// Collect Varnodes immediately attached to PcodeOps at addr. Faithful to
    /// `gatherFirstLevelVars` (dynamic.cc:645-685).
    pub fn gather_first_level_vars(
        varlist: &mut Vec<Arc<RwLock<Varnode>>>,
        fd: &crate::funcdata::Funcdata,
        addr: Address,
        h: u64,
    ) {
        let opc_val = Self::get_opcode_from_hash(h);
        let slot = Self::get_slot_from_hash(h);
        let isnotattached = Self::get_is_not_attached(h);
        let mut ops_here: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        Self::gather_ops_at_address(&mut ops_here, fd, addr);
        for op in ops_here {
            if op.read().unwrap().is_dead() {
                continue;
            }
            let cur_opc = op.read().unwrap().opcode;
            if translate_opcode(cur_opc) != opc_val {
                continue;
            }
            if slot < 0 {
                let vn = match op.read().unwrap().output.clone() {
                    Some(v) => v,
                    None => continue,
                };
                if isnotattached {
                    // RUDRA-GLUE: scrutinee read guard lifted to statement
                    // scope (lock-hygiene family: ER ruleaction SubRight /
                    // EW castInput / EM3 cover_dirty). An `if let Some(x) =
                    // vn.read().unwrap().lone_descend()` scrutinee would hold
                    // the read guard through the entire if-let body; any
                    // future write lock on vn inside the body self-deadlocks
                    // (std RwLock is non-reentrant). lone_descend returns an
                    // owned Option<Arc<_>> so the guard dies at the end of
                    // this let; read order is unchanged (dynamic.cc:663
                    // loneDescend read, then cc:665/666 opcode + getOut).
                    let lone_descend = vn.read().unwrap().lone_descend();
                    if let Some(no) = lone_descend {
                        if translate_opcode(no.read().unwrap().opcode) == 0 {
                            // dynamic.cc:667 `if (vn == (Varnode *)0) continue;`
                            // — a skipped op with no output contributes NO
                            // varnode. The old shape fell through to the
                            // bottom push and leaked the pre-skip vn instead.
                            let Some(nv) = no.read().unwrap().output.clone() else {
                                continue;
                            };
                            varlist.push(nv);
                            continue;
                        }
                    }
                }
                varlist.push(vn);
            } else if (slot as usize) < op.read().unwrap().num_input() {
                let vn = op.read().unwrap().get_in(slot as usize).cloned().unwrap();
                if isnotattached {
                    // RUDRA-GLUE: same scrutinee-guard lift as the slot<0
                    // arm above; read order unchanged (dynamic.cc:677 getDef
                    // read, then cc:678/679 opcode + getIn(0)).
                    let def = vn.read().unwrap().get_def();
                    if let Some(d) = def {
                        if translate_opcode(d.read().unwrap().opcode) == 0 {
                            // dynamic.cc:679 pushes getIn(0) unconditionally
                            // (a live def always has slot 0); the Rust mirror
                            // keeps a defensive fallback to the original vn
                            // for a degenerate empty-slot def instead of
                            // crashing like Ghidra would.
                            if let Some(v0) = d.read().unwrap().get_in(0).cloned() {
                                varlist.push(v0);
                                continue;
                            }
                        }
                    }
                }
                varlist.push(vn);
            }
        }
        Self::dedup_varnodes(varlist);
    }

    // Ghidra: dynamic.cc:692 DynamicHash::gatherOpsAtAddress
    /// Place all live PcodeOps at addr into op_list. Faithful to
    /// `gatherOpsAtAddress` (dynamic.cc:692-702).
    pub fn gather_ops_at_address(
        op_list: &mut Vec<Arc<RwLock<PcodeOp>>>,
        fd: &crate::funcdata::Funcdata,
        addr: Address,
    ) {
        for op_ref in fd.obank.begin_addr(addr) {
            let (op_addr, is_dead) = {
                let op = op_ref.0.read().unwrap();
                (op.start.addr, op.is_dead())
            };
            if op_addr > addr {
                break;
            }
            if is_dead {
                continue;
            }
            op_list.push(op_ref.0.clone());
        }
    }

    // --- Hash-decode statics (dynamic.cc:707-771) ---

    // Ghidra: dynamic.cc:707 DynamicHash::getSlotFromHash
    /// Retrieve encoded slot. Bits 32-36; 31 -> -1 (output).
    pub fn get_slot_from_hash(h: u64) -> i32 {
        let res = ((h >> 32) & 0x1f) as i32;
        if res == 31 {
            -1
        } else {
            res
        }
    }

    // Ghidra: dynamic.cc:719 DynamicHash::getMethodFromHash
    /// Retrieve encoded method. Bits 44-47.
    pub fn get_method_from_hash(h: u64) -> u32 {
        ((h >> 44) & 0xf) as u32
    }

    // Ghidra: dynamic.cc:728 DynamicHash::getOpCodeFromHash
    /// Retrieve encoded translated opcode. Bits 37-43.
    pub fn get_opcode_from_hash(h: u64) -> u32 {
        ((h >> 37) & 0x7f) as u32
    }

    // Ghidra: dynamic.cc:737 DynamicHash::getPositionFromHash
    /// Retrieve encoded collision-list position. Bits 49-51.
    pub fn get_position_from_hash(h: u64) -> usize {
        ((h >> 49) & 7) as usize
    }

    // Ghidra: dynamic.cc:746 DynamicHash::getTotalFromHash
    /// Retrieve encoded collision total. Bits 52-54, plus one.
    pub fn get_total_from_hash(h: u64) -> usize {
        (((h >> 52) & 7) as usize) + 1
    }

    // Ghidra: dynamic.cc:755 DynamicHash::getIsNotAttached
    /// Retrieve attachment flag. Bit 48.
    pub fn get_is_not_attached(h: u64) -> bool {
        ((h >> 48) & 1) != 0
    }

    // Ghidra: dynamic.cc:764 DynamicHash::clearTotalPosition
    /// Clear collision total+position fields. Bits 49-54.
    pub fn clear_total_position(h: &mut u64) {
        *h &= !(0x3fu64 << 49);
    }

    // Ghidra: dynamic.hh:103 DynamicHash::getComparable
    /// Get only the formal 32-bit hash for comparing.
    pub fn get_comparable(h: u64) -> u32 {
        h as u32
    }
}

impl Default for DynamicHash {
    // RUDRA-GLUE: Rust Default delegates to new(); Ghidra's DynamicHash class
    // (dynamic.hh:62) declares no explicit constructor or Default-style method.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::funcdata::Funcdata;

    fn build_add_ir(
        fd: &mut Funcdata,
    ) -> (
        Arc<RwLock<PcodeOp>>,
        Arc<RwLock<Varnode>>,
        Arc<RwLock<Varnode>>,
        Arc<RwLock<Varnode>>,
    ) {
        let pc = Address::new(0x1000);
        let op_ref = fd.new_op(2, pc);
        fd.op_set_opcode(&op_ref, OpCode::CPUI_INT_ADD);
        let c0 = fd.new_constant(4, 0x10);
        let c1 = fd.new_constant(4, 0x20);
        fd.op_set_input(&op_ref, c0.clone(), 0);
        fd.op_set_input(&op_ref, c1.clone(), 1);
        let out = fd.new_unique_out(4, &op_ref);
        (op_ref.0.clone(), c0, c1, out)
    }

    #[test]
    fn test_dynamic_hash_creation() {
        let dh = DynamicHash::new();
        assert_eq!(dh.get_hash(), 0);
        assert_eq!(dh.get_address(), Address::new(0));
    }

    #[test]
    fn test_translate_opcode_basic() {
        assert_eq!(translate_opcode(OpCode::CPUI_COPY), OpCode::CPUI_COPY as u32);
        assert_eq!(
            translate_opcode(OpCode::CPUI_INT_ADD),
            OpCode::CPUI_INT_ADD as u32
        );
        assert_eq!(translate_opcode(OpCode::CPUI_CAST), 0);
    }

    #[test]
    fn test_translate_opcode_variants_collapse() {
        assert_eq!(
            translate_opcode(OpCode::CPUI_INT_SUB),
            translate_opcode(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            translate_opcode(OpCode::CPUI_INT_NOTEQUAL),
            translate_opcode(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(
            translate_opcode(OpCode::CPUI_INT_LEFT),
            translate_opcode(OpCode::CPUI_INT_MULT)
        );
        assert_eq!(
            translate_opcode(OpCode::CPUI_PTRADD),
            translate_opcode(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            translate_opcode(OpCode::CPUI_PTRSUB),
            translate_opcode(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            translate_opcode(OpCode::CPUI_FLOAT_SUB),
            translate_opcode(OpCode::CPUI_FLOAT_ADD)
        );
    }

    #[test]
    fn test_to_op_edge_compare_and_hash() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (op, _, _, _) = build_add_ir(&mut fd);
        let e1 = ToOpEdge::new(op.clone(), 0);
        let e2 = ToOpEdge::new(op.clone(), 1);
        assert_eq!(e1.compare(&e2), std::cmp::Ordering::Less);
        let h1 = e1.hash_into(0x1234_5678);
        assert_eq!(h1, e1.hash_into(0x1234_5678));
        assert_ne!(h1, e2.hash_into(0x1234_5678));
    }

    #[test]
    fn test_hash_decode_roundtrip_method() {
        let h: u64 = (3u64 << 44) | 0xdead_beef;
        assert_eq!(DynamicHash::get_method_from_hash(h), 3);
    }

    #[test]
    fn test_hash_decode_roundtrip_opcode() {
        let opc = OpCode::CPUI_INT_ADD as u64;
        let h: u64 = (opc << 37) | 0xdead_beef;
        assert_eq!(DynamicHash::get_opcode_from_hash(h), opc as u32);
    }

    #[test]
    fn test_hash_decode_slot_output_sentinel() {
        let h: u64 = 0x1fu64 << 32;
        assert_eq!(DynamicHash::get_slot_from_hash(h), -1);
        let h: u64 = 7u64 << 32;
        assert_eq!(DynamicHash::get_slot_from_hash(h), 7);
    }

    #[test]
    fn test_hash_decode_position_total() {
        let h: u64 = (5u64 << 49) | (2u64 << 52);
        assert_eq!(DynamicHash::get_position_from_hash(h), 5);
        assert_eq!(DynamicHash::get_total_from_hash(h), 3);
    }

    #[test]
    fn test_hash_decode_is_not_attached() {
        assert!(!DynamicHash::get_is_not_attached(0));
        assert!(DynamicHash::get_is_not_attached(1u64 << 48));
    }

    #[test]
    fn test_clear_total_position() {
        let mut h: u64 = (5u64 << 49) | (2u64 << 52) | 0xffff;
        DynamicHash::clear_total_position(&mut h);
        assert_eq!(DynamicHash::get_position_from_hash(h), 0);
        assert_eq!(DynamicHash::get_total_from_hash(h), 1);
        assert_eq!(h & 0xffff, 0xffff);
    }

    #[test]
    fn test_get_comparable() {
        let h: u64 = 0xABCD_1234_5678;
        assert_eq!(DynamicHash::get_comparable(h), 0x1234_5678);
    }

    #[test]
    fn test_calc_hash_vn_simple() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (_, _, _, out) = build_add_ir(&mut fd);
        let mut dh = DynamicHash::new();
        dh.calc_hash_vn(&out, 0);
        assert_ne!(dh.get_hash(), 0, "hash must be non-zero");
        assert_eq!(
            DynamicHash::get_opcode_from_hash(dh.get_hash()),
            translate_opcode(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(DynamicHash::get_slot_from_hash(dh.get_hash()), -1);
        assert_eq!(DynamicHash::get_method_from_hash(dh.get_hash()), 0);
    }

    #[test]
    fn test_calc_hash_op_input_slot() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (op, _, _, _) = build_add_ir(&mut fd);
        let mut dh = DynamicHash::new();
        dh.calc_hash_op(&op, 0, 4);
        assert_ne!(dh.get_hash(), 0);
        assert_eq!(
            DynamicHash::get_opcode_from_hash(dh.get_hash()),
            translate_opcode(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(DynamicHash::get_slot_from_hash(dh.get_hash()), 0);
        assert_eq!(DynamicHash::get_method_from_hash(dh.get_hash()), 4);
    }

    #[test]
    fn test_calc_hash_vn_stable_across_methods() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (_, _, _, out) = build_add_ir(&mut fd);
        let mut dh = DynamicHash::new();
        dh.calc_hash_vn(&out, 0);
        let h0 = dh.get_hash();
        dh.clear();
        dh.calc_hash_vn(&out, 0);
        assert_eq!(dh.get_hash(), h0);
    }

    #[test]
    fn test_gather_ops_at_address() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let block = fd.create_new_block();
        let target = Address::new(0x1000);
        let before = fd.new_op_with_seq(0, &crate::address::SeqNum::new(Address::new(0x0fff), 40));
        let late = fd.new_op_with_seq(0, &crate::address::SeqNum::new(target, 30));
        let dead = fd.new_op_with_seq(0, &crate::address::SeqNum::new(target, 20));
        let early = fd.new_op_with_seq(0, &crate::address::SeqNum::new(target, 10));
        let after = fd.new_op_with_seq(0, &crate::address::SeqNum::new(Address::new(0x1001), 0));
        for op in [&before, &late, &early, &after] {
            fd.op_insert_end(op, &block);
        }

        let seed = Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(Address::new(0xdead), 0),
            OpCode::CPUI_COPY,
        )));
        let mut ops = vec![seed.clone()];
        DynamicHash::gather_ops_at_address(&mut ops, &fd, target);
        assert_eq!(ops.len(), 3);
        assert!(Arc::ptr_eq(&ops[0], &seed));
        assert!(Arc::ptr_eq(&ops[1], &early.0));
        assert!(Arc::ptr_eq(&ops[2], &late.0));
        assert!(dead.0.read().unwrap().is_dead());
        assert!(!early.0.read().unwrap().is_dead());
        assert!(!late.0.read().unwrap().is_dead());

        ops.clear();
        DynamicHash::gather_ops_at_address(&mut ops, &fd, Address::new(0xdead));
        assert!(ops.is_empty());
    }

    #[test]
    fn test_dedup_varnodes() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (_, c0, c1, out) = build_add_ir(&mut fd);
        let mut list = vec![c0.clone(), c0.clone(), c1.clone(), out.clone(), c0.clone()];
        DynamicHash::dedup_varnodes(&mut list);
        assert_eq!(list.len(), 3);
        assert!(Arc::ptr_eq(&list[0], &c0));
        assert!(Arc::ptr_eq(&list[1], &c1));
        assert!(Arc::ptr_eq(&list[2], &out));
    }

    #[test]
    fn test_move_off_skip_no_skip() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (op, _, _, _) = build_add_ir(&mut fd);
        let mut cur = Some(op.clone());
        let mut slot = 0i32;
        DynamicHash::move_off_skip(&mut cur, &mut slot);
        assert!(cur.is_some());
        assert!(Arc::ptr_eq(&cur.unwrap(), &op));
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_move_off_skip_through_cast() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let pc = Address::new(0x2000);
        let cast_ref = fd.new_op(1, pc);
        fd.op_set_opcode(&cast_ref, OpCode::CPUI_CAST);
        let zext_ref = fd.new_op(1, pc);
        fd.op_set_opcode(&zext_ref, OpCode::CPUI_INT_ZEXT);
        let const_in = fd.new_constant(4, 0x42);
        let zext_out = fd.new_unique_out(8, &zext_ref);
        fd.op_set_input(&zext_ref, const_in, 0);
        let _cast_out = fd.new_unique_out(8, &cast_ref);
        fd.op_set_input(&cast_ref, zext_out.clone(), 0);
        let mut cur = Some(cast_ref.0.clone());
        let mut slot = -1i32;
        DynamicHash::move_off_skip(&mut cur, &mut slot);
        assert!(cur.is_some());
        assert!(Arc::ptr_eq(&cur.as_ref().unwrap(), &zext_ref.0));
    }

    #[test]
    fn test_find_varnode_roundtrip() {
        let mut fd = Funcdata::new("t", Address::new(0), 8);
        let (_, _, _, out) = build_add_ir(&mut fd);
        let mut dh = DynamicHash::new();
        dh.unique_hash_vn(&out, &fd);
        if dh.get_hash() != 0 {
            let addr = dh.get_address();
            let h = dh.get_hash();
            let mut dh2 = DynamicHash::new();
            let found = dh2.find_varnode(&fd, addr, h);
            assert!(found.is_some(), "find_varnode must round-trip");
            assert!(Arc::ptr_eq(&found.unwrap(), &out));
        }
    }

    /// gatherFirstLevelVars slot<0 + isnotattached (dynamic.cc:659-672):
    /// a skip-op (transtable==0, e.g. CAST) lone descendant redirects the
    /// gather to its own output, while a non-skip lone descendant (INT_ZEXT)
    /// keeps the original output varnode in the list.
    #[test]
    fn test_gather_first_level_vars_not_attached_skip_op() {
        // (a) skip-op CAST lone descendant with output nv -> gather [nv].
        let mut fd = Funcdata::new("t_gather1st", Address::new(0), 8);
        let block = fd.create_new_block();
        let pc = Address::new(0x1000);
        let op = fd.new_op(2, pc);
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        let c_1_op = fd.new_constant(4, 1);
        fd.op_set_input(&op, c_1_op, 0);
        let c_2_op = fd.new_constant(4, 2);
        fd.op_set_input(&op, c_2_op, 1);
        let vn = fd.new_unique_out(4, &op);
        fd.op_insert_end(&op, &block);
        let cast = fd.new_op(1, pc);
        fd.op_set_opcode(&cast, OpCode::CPUI_CAST);
        fd.op_set_input(&cast, vn.clone(), 0);
        let nv = fd.new_unique_out(4, &cast);
        fd.op_insert_end(&cast, &block);
        let h = ((translate_opcode(OpCode::CPUI_INT_ADD) as u64) << 37)
            | (0x1fu64 << 32) // slot = -1 (output)
            | (1u64 << 48); // isnotattached
        let mut varlist: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        DynamicHash::gather_first_level_vars(&mut varlist, &fd, pc, h);
        assert_eq!(varlist.len(), 1);
        assert!(
            Arc::ptr_eq(&varlist[0], &nv),
            "skip-op lone descendant redirects the gather to its output"
        );

        // (b) non-skip lone descendant (INT_ZEXT, translate != 0) -> [vn].
        let mut fd2 = Funcdata::new("t_gather1st_b", Address::new(0), 8);
        let block2 = fd2.create_new_block();
        let op2 = fd2.new_op(2, pc);
        fd2.op_set_opcode(&op2, OpCode::CPUI_INT_ADD);
        let c_1_op2 = fd2.new_constant(4, 1);
        fd2.op_set_input(&op2, c_1_op2, 0);
        let c_2_op2 = fd2.new_constant(4, 2);
        fd2.op_set_input(&op2, c_2_op2, 1);
        let vn2 = fd2.new_unique_out(4, &op2);
        fd2.op_insert_end(&op2, &block2);
        let zext = fd2.new_op(1, pc);
        fd2.op_set_opcode(&zext, OpCode::CPUI_INT_ZEXT);
        fd2.op_set_input(&zext, vn2.clone(), 0);
        let _zext_out = fd2.new_unique_out(8, &zext);
        fd2.op_insert_end(&zext, &block2);
        let mut varlist2: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        DynamicHash::gather_first_level_vars(&mut varlist2, &fd2, pc, h);
        assert_eq!(varlist2.len(), 1);
        assert!(
            Arc::ptr_eq(&varlist2[0], &vn2),
            "non-skip lone descendant keeps the original output varnode"
        );
    }

    /// dynamic.cc:667 `if (vn == (Varnode *)0) continue;` — a skip-op lone
    /// descendant WITHOUT an output contributes NO varnode. The pre-fix Rust
    /// shape fell through the inner if-let and pushed the pre-skip output
    /// varnode instead (LOCKHYGIENE-SCRUTINEE-FAMILY-0001).
    #[test]
    fn test_gather_first_level_vars_skip_op_without_output_contributes_nothing() {
        let mut fd = Funcdata::new("t_gather1st_c", Address::new(0), 8);
        let block = fd.create_new_block();
        let pc = Address::new(0x1000);
        let op = fd.new_op(2, pc);
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        let c_1_op = fd.new_constant(4, 1);
        fd.op_set_input(&op, c_1_op, 0);
        let c_2_op = fd.new_constant(4, 2);
        fd.op_set_input(&op, c_2_op, 1);
        let vn = fd.new_unique_out(4, &op);
        fd.op_insert_end(&op, &block);
        // Output-less CAST reading vn: descend registration via op_set_input
        // is what lone_descend needs; the op is never inserted.
        let cast = fd.new_op(1, pc);
        fd.op_set_opcode(&cast, OpCode::CPUI_CAST);
        fd.op_set_input(&cast, vn.clone(), 0);
        let h = ((translate_opcode(OpCode::CPUI_INT_ADD) as u64) << 37)
            | (0x1fu64 << 32)
            | (1u64 << 48);
        let mut varlist: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        DynamicHash::gather_first_level_vars(&mut varlist, &fd, pc, h);
        assert!(
            varlist.is_empty(),
            "skip-op without output must contribute nothing (dynamic.cc:667 continue)"
        );
    }

    /// Lock-hygiene pin for the lifted scrutinee in
    /// gather_first_level_vars (family: ER ruleaction SubRight / EW
    /// castInput / EM3 cover_dirty). The exact production call shape must
    /// release the vn read guard at the `let` statement, so a write lock on
    /// vn taken while inspecting the lone descendant (the body shape that
    /// deadlocked ER/EW in production) completes instead of self-deadlocking.
    /// Run in a worker thread with a hard timeout so a regression to the
    /// scrutinee-guard shape fails fast instead of hanging the harness.
    #[test]
    fn test_gather_first_level_vars_scrutinee_guard_released_before_body() {
        let mut fd = Funcdata::new("t_gather1st_pin", Address::new(0), 8);
        let block = fd.create_new_block();
        let pc = Address::new(0x1000);
        let op = fd.new_op(2, pc);
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
        let c_1_op = fd.new_constant(4, 1);
        fd.op_set_input(&op, c_1_op, 0);
        let c_2_op = fd.new_constant(4, 2);
        fd.op_set_input(&op, c_2_op, 1);
        let vn = fd.new_unique_out(4, &op);
        fd.op_insert_end(&op, &block);
        let cast = fd.new_op(1, pc);
        fd.op_set_opcode(&cast, OpCode::CPUI_CAST);
        fd.op_set_input(&cast, vn.clone(), 0);
        let nv = fd.new_unique_out(4, &cast);
        fd.op_insert_end(&cast, &block);

        let (tx, rx) = std::sync::mpsc::channel();
        let vn_thread = vn.clone();
        let handle = std::thread::spawn(move || {
            // Exact production call shape of the lifted arm:
            let lone_descend = vn_thread.read().unwrap().lone_descend();
            if let Some(no) = lone_descend {
                // Pre-lift `if let Some(x) = vn.read().unwrap()...` kept
                // the read guard alive here, so this write self-deadlocks
                // (std RwLock is non-reentrant) — the exact ER/EW failure.
                let _guard = vn_thread.write().unwrap();
                assert_eq!(translate_opcode(no.read().unwrap().opcode), 0);
                assert!(no.read().unwrap().output.is_some());
                tx.send(()).unwrap();
            } else {
                panic!("lone descendant must exist");
            }
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok(),
            "scrutinee read guard must be released before the if-let body"
        );
        handle.join().unwrap();
        drop(nv);
    }
}
