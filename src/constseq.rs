//! Constant sequence analysis: combining COPY/STORE ops into string copies.
//!
//! Corresponds to Ghidra's `constseq.hh` / `constseq.cc` (1146 lines).
//!
//! This module detects sequences of COPY or STORE operations that write
//! constant characters to a contiguous memory region, and replaces them
//! with a single `strncpy`/`wcsncpy`/`memcpy` CALLOTHER.
//!
//! Key classes:
//! - `ArraySequence`: base class collecting a maximal set of sequential ops
//! - `StringSequence`: for COPY ops writing to a stack/local array
//! - `HeapSequence`: for STORE ops writing through a heap pointer
//! - `RuleStringCopy`: rule triggering on COPY ops
//! - `RuleStringStore`: rule triggering on STORE ops
//!
//! # Status
//! RuleStringStore is fully wired: the HeapSequence analysis chain
//! (findBasePointer/findDuplicateBases/findInitialStores/calcPtraddOffset/
//! collectStoreOps/checkInterference/formByteArray) and the CALLOTHER
//! transform (buildStringCopy via `Funcdata::get_internal_string` +
//! typed builtin registration) follow constseq.cc 1:1. RuleStringCopy's
//! StringSequence chain (collectCopyOps/constructTypedPointer/
//! buildStringCopy/removeForward/removeCopyOps) is likewise ported
//! (WORKPKG-UNMAP-STRFOLD-0006), with the `queryContainer` entry lookup
//! bridged through `ScopeLocal::find_container_entry` plus the Database
//! ram leg.

use std::sync::{Arc, RwLock};
use crate::varnode::Varnode;
use crate::op::PcodeOp;
use crate::opcodes::OpCode;
use crate::funcdata::Funcdata;
use crate::type_system::Datatype;
use crate::action::{Rule, action_status};
use crate::error::Result;

/// Minimum number of sequential characters to trigger replacement
/// (constseq.cc:21 `ArraySequence::MINIMUM_SEQUENCE_LENGTH = 4`).
pub const MINIMUM_SEQUENCE_LENGTH: i32 = 4;
/// Maximum number of characters in replacement string
/// (constseq.cc:22 `ArraySequence::MAXIMUM_SEQUENCE_LENGTH = 0x20000`).
pub const MAXIMUM_SEQUENCE_LENGTH: i32 = 0x20000;

/// Helper class holding a data-flow edge and optionally a memory offset.
/// Corresponds to Ghidra's `ArraySequence::WriteNode` (constseq.hh:34).
#[derive(Clone, Debug)]
pub struct WriteNode {
    /// Offset into the memory region
    pub offset: u64,
    /// PcodeOp moving into/out of memory region
    pub op: Arc<RwLock<PcodeOp>>,
    /// Input slot (>=0) or output (-1)
    pub slot: i32,
}

impl WriteNode {
    // Ghidra: constseq.hh:34 WriteNode::new
    pub fn new(offset: u64, op: Arc<RwLock<PcodeOp>>, slot: i32) -> Self {
        Self { offset, op, slot }
    }
}

/// A sequence of PcodeOps that move data into/out of an array data-type.
/// Corresponds to Ghidra's `ArraySequence` (constseq.hh:29).
pub struct ArraySequence {
    /// The root PcodeOp
    pub root_op: Arc<RwLock<PcodeOp>>,
    /// Element data-type
    pub char_type: Option<Arc<Datatype>>,
    /// Number of elements in the final sequence (0 = not found)
    pub num_elements: i32,
    /// COPY/STORE ops into the array memory region
    pub move_ops: Vec<WriteNode>,
    /// Constants collected in a single byte array
    pub byte_array: Vec<u8>,
}

impl ArraySequence {
    // Ghidra: constseq.cc:28 ArraySequence::isValid
    /// Return true if a valid sequence was found.
    pub fn is_valid(&self) -> bool {
        self.num_elements != 0
    }

    // Ghidra: constseq.cc:42 ArraySequence::interfereBetween
    /// Check for interfering ops between the two given ops. Faithful to
    /// `interfereBetween` (constseq.cc:42-56): walk `nextOp()` from
    /// `start_op` (exclusive) toward `end_op`; an op interferes iff its eval
    /// type is `special` AND its opcode is not one of the five exemptions
    /// (INDIRECT, CALLOTHER, SEGMENTOP, CPOOLREF, NEW). Returns true when
    /// there is NO interference.
    ///
    /// The walk follows block order via `PcodeOp::nextOp()` (op.cc:323-339),
    /// crossing into the unique out-edge block when the parent has 1 or 2
    /// exits. If the walk runs off the end (no unique successor) before
    /// reaching `end_op`, the oracle would dereference null; Rudra returns
    /// `true` (no interference) as the conservative non-crashing reading —
    /// this only differs on malformed sequences the oracle never builds.
    pub fn interfere_between(
        fd: &Funcdata,
        start_op: &Arc<RwLock<PcodeOp>>,
        end_op: &Arc<RwLock<PcodeOp>>,
    ) -> bool {
        // cc:45: startOp = startOp->nextOp().
        let mut cur = {
            let g = start_op.read().unwrap();
            g.next_op_in_flow(&fd.obank).map(|n| n.0.clone())
        };
        // cc:46: while (startOp != endOp).
        while let Some(c) = cur {
            if Arc::ptr_eq(&c, end_op) {
                break;
            }
            // cc:47-51: special eval-type gate with the five exemptions.
            let g = c.read().unwrap();
            if g.get_eval_type() == crate::op::pcodeop_flags::SPECIAL {
                match g.opcode {
                    OpCode::CPUI_INDIRECT
                    | OpCode::CPUI_CALLOTHER
                    | OpCode::CPUI_SEGMENTOP
                    | OpCode::CPUI_CPOOLREF
                    | OpCode::CPUI_NEW => {}
                    _ => return false,
                }
            }
            cur = g.next_op_in_flow(&fd.obank).map(|n| n.0.clone());
        }
        true
    }

    // Ghidra: constseq.cc:62 ArraySequence::checkInterference
    /// Sort `move_ops` on block order, then walk backward/forward from the
    /// root op accumulating the maximal set of ops with no interfering gap,
    /// truncating `move_ops` to that set. Faithful to `checkInterference`
    /// (constseq.cc:62-96), including the truncation write-back (cc:89-94)
    /// and the minimum-length gate (cc:87-88). Callers (the StringSequence /
    /// HeapSequence constructors) pre-populate `move_ops` before calling.
    pub fn check_interference(&mut self, fd: &Funcdata) -> bool {
        // cc:65: sort(moveOps) — WriteNode::operator< compares
        // op->getSeqNum().getOrder(), the block execution-order field.
        self.move_ops
            .sort_by_key(|n| n.op.read().unwrap().start.get_order());
        // cc:66-70: locate the root op.
        let mut pos = None;
        for (i, node) in self.move_ops.iter().enumerate() {
            if Arc::ptr_eq(&node.op, &self.root_op) {
                pos = Some(i);
                break;
            }
        }
        let Some(pos) = pos else { return false };
        // cc:71-78: walk backward from the root.
        let mut cur_op = self.move_ops[pos].op.clone();
        let mut starting_pos = pos as isize - 1;
        while starting_pos >= 0 {
            let prev_op = self.move_ops[starting_pos as usize].op.clone();
            if !Self::interfere_between(fd, &prev_op, &cur_op) {
                break;
            }
            cur_op = prev_op;
            starting_pos -= 1;
        }
        starting_pos += 1;
        // cc:79-86: walk forward from the root.
        let mut cur_op = self.move_ops[pos].op.clone();
        let mut ending_pos = pos + 1;
        while ending_pos < self.move_ops.len() {
            let next_op = self.move_ops[ending_pos].op.clone();
            if !Self::interfere_between(fd, &cur_op, &next_op) {
                break;
            }
            cur_op = next_op;
            ending_pos += 1;
        }
        // cc:87-88: too many truncated ops.
        if ending_pos as isize - starting_pos < MINIMUM_SEQUENCE_LENGTH as isize {
            return false;
        }
        // cc:89-94: truncate moveOps to [startingPos, endingPos).
        if starting_pos > 0 {
            self.move_ops.drain(..starting_pos as usize);
            ending_pos -= starting_pos as usize;
        }
        self.move_ops.truncate(ending_pos);
        true
    }

    // Ghidra: constseq.cc:28 ArraySequence::new
    /// Construct from a root op.
    pub fn new(root_op: Arc<RwLock<PcodeOp>>) -> Self {
        Self {
            root_op,
            char_type: None,
            num_elements: 0,
            move_ops: Vec::new(),
            byte_array: Vec::new(),
        }
    }

    // Ghidra: constseq.cc:28 ArraySequence::sortOps
    /// Sort move_ops by their op's sequence order.
    pub fn sort_ops(&mut self) {
        self.move_ops.sort_by(|a, b| {
            let a_order = a.op.read().unwrap().start.get_order() as u64;
            let b_order = b.op.read().unwrap().start.get_order() as u64;
            a_order.cmp(&b_order)
        });
    }

    // Ghidra: constseq.cc:161 ArraySequence::selectStringCopyFunction
    /// Use the \b charType to select the appropriate string copying
    /// function. Faithful to `selectStringCopyFunction` (constseq.cc:161-175):
    /// identity comparison against the factory's canonical char type selects
    /// BUILTIN_STRNCPY (element count), then the canonical wide-char type
    /// selects BUILTIN_WCSNCPY (element count); anything else falls back to
    /// BUILTIN_MEMCPY with the byte length. Rudra compares via factory-canonical
    /// `Arc` identity (the direct analogue of Ghidra's cached `Datatype *`
    /// identity), falling back to (size, char-print flag) equality for types
    /// that flowed through cloned records.
    pub fn select_string_copy_function(&self, fd: &Funcdata) -> (u32, i32) {
        use crate::userop::{BUILTIN_MEMCPY, BUILTIN_STRNCPY, BUILTIN_WCSNCPY};
        let types = fd.arch.as_ref().and_then(|a| a.types.clone());
        if let Some(types) = types {
            let factory = types.read().unwrap();
            let char_size = factory.get_size_of_char().max(0) as usize;
            if Self::matches_factory_char(self.char_type.as_ref(), &factory, char_size) {
                return (BUILTIN_STRNCPY, self.num_elements);
            }
            let wchar_size = factory.get_size_of_wchar().max(0) as usize;
            if Self::matches_factory_char(self.char_type.as_ref(), &factory, wchar_size) {
                return (BUILTIN_WCSNCPY, self.num_elements);
            }
        }
        let align = self
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1) as i32;
        (BUILTIN_MEMCPY, self.num_elements * align)
    }

    /// Identity comparison of `candidate` against the factory's canonical
    /// character type of `size` (the cc:165/169 `charType == types->
    /// getTypeChar(...)` pointer compare). Rudra's factory hands out
    /// canonical `Arc`s so `Arc::ptr_eq` is the direct analogue; types that
    /// flowed through cloned records fall back to (name, size, char-print
    /// flags) equality.
    // Ghidra: constseq.cc:161 ArraySequence::selectStringCopyFunction (charType == types->getTypeChar identity test)
    fn matches_factory_char(
        candidate: Option<&Arc<Datatype>>,
        factory: &crate::type_system::typefactory::TypeFactory,
        size: usize,
    ) -> bool {
        use crate::type_system::datatype::type_flags;
        let Some(candidate) = candidate else { return false };
        match factory.get_type_char(size) {
            Ok(canonical) => {
                if Arc::ptr_eq(candidate, &canonical) {
                    return true;
                }
                let flag_mask = type_flags::CHARTYPE | type_flags::UTF16 | type_flags::UTF32;
                candidate.get_name() == canonical.get_name()
                    && candidate.get_size() == canonical.get_size()
                    && (candidate.get_flags() & flag_mask) == (canonical.get_flags() & flag_mask)
            }
            Err(_) => false,
        }
    }

    // Ghidra: constseq.cc:108 ArraySequence::formByteArray
    /// Put constant values from the collected move ops into a single byte
    /// array. Faithful to `formByteArray` (constseq.cc:108-155):
    ///  - each op's input (at `slot`) constant lands at
    ///    `move_ops[i].offset - root_off`, ops outside the array are skipped;
    ///  - the `used` marks record 1 (data) / 2 (null terminator) per byte;
    ///  - the contiguous leading run of full elements is counted, allowing a
    ///    single trailing null terminator (cc:135-142);
    ///  - fewer than MINIMUM_SEQUENCE_LENGTH characters returns 0;
    ///  - when the count does not cover all collected ops, the ops beyond
    ///    `root_off + count*alignSize` are dropped (cc:145-152).
    pub fn form_byte_array(
        &mut self,
        sz: i32,
        slot: i32,
        root_off: u64,
        big_endian: bool,
    ) -> i32 {
        let el_size = self
            .char_type
            .as_ref()
            .map(|t| t.get_size())
            .unwrap_or(1) as i32;
        self.byte_array = vec![0u8; sz.max(0) as usize];
        let mut used = vec![0u8; sz.max(0) as usize];
        for node in &self.move_ops {
            let byte_pos = node.offset as i64 - root_off as i64;
            if byte_pos < 0 || byte_pos + el_size as i64 > sz as i64 {
                continue;
            }
            let val = {
                let op = node.op.read().unwrap();
                match op.inrefs.get(slot as usize) {
                    Some(v) => v.read().unwrap().get_offset(),
                    None => continue,
                }
            };
            let bp = byte_pos as usize;
            used[bp] = if val == 0 { 2 } else { 1 };
            if big_endian {
                for j in 0..el_size as usize {
                    let b = (val >> ((el_size as usize - 1 - j) * 8)) & 0xff;
                    self.byte_array[bp + j] = b as u8;
                }
            } else {
                let mut v = val;
                for j in 0..el_size as usize {
                    self.byte_array[bp + j] = (v & 0xff) as u8;
                    v >>= 8;
                }
            }
        }
        let big_el_size = self
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1);
        let max_el = if big_el_size > 0 {
            used.len() / big_el_size
        } else {
            used.len()
        };
        let mut count = 0usize;
        while count < max_el {
            let val = used[count * big_el_size];
            if val != 1 {
                if val == 2 {
                    count += 1; // Allow a single null terminator
                }
                break;
            }
            count += 1;
        }
        let count = count as i32;
        if count < MINIMUM_SEQUENCE_LENGTH {
            return 0;
        }
        if count != self.move_ops.len() as i32 {
            let max_off = root_off.wrapping_add(count as u64 * big_el_size as u64);
            let mut final_ops: Vec<WriteNode> = Vec::new();
            for node in &self.move_ops {
                if node.offset < max_off {
                    final_ops.push(node.clone());
                }
            }
            self.move_ops = final_ops;
        }
        count
    }
}

/// A class for collecting sequences of COPY ops writing characters to a string.
/// Corresponds to Ghidra's `StringSequence` (constseq.hh:66).
///
/// Given a starting Address and a Symbol with a character array as a
/// component, a class instance collects a maximal set of COPY ops that can be
/// treated as writing a single string into memory. `transform` then replaces
/// the COPYs with a single strncpy/wcsncpy/memcpy CALLOTHER (constseq.hh:62).
pub struct StringSequence {
    /// Base ArraySequence
    pub base: ArraySequence,
    /// Address of the root COPY's output within the memory region
    /// (constseq.hh:67 `rootAddr`). Rudra keeps the space separately
    /// (`space`) because its `Address` carries no space.
    pub root_addr: u64,
    /// Starting address of the memory region (constseq.hh:68 `startAddr`).
    pub start_addr: u64,
    /// Space of `rootAddr`/`startAddr` (Rudra seam for Ghidra's
    /// `Address::getSpace()`).
    pub space: crate::space::AddressSpace,
    /// The container SymbolEntry projection at the root Address
    /// (constseq.hh:69 `entry`): first offset, size, and the owning Symbol's
    /// data-type — the observable reads of `entry` in the constructor and
    /// `constructTypedPointer` (cc:193-200, 283, 293).
    pub entry_first: u64,
    pub entry_size: i32,
    pub symbol_type: Option<Arc<Datatype>>,
}

/// `charType == candidate` — Ghidra's `Datatype*` identity compare as it
/// appears in the StringSequence constructor walk (constseq.cc:188 ctor,
/// the `if (parentType == ct) break;` at cc:204) and
/// `constructTypedPointer` loop guard (cc:294 `while(baseType != charType)`).
/// Rudra compares canonical `Arc`s
/// by pointer, falling back to (name, size, char-print flag) equality for
/// types that flowed through cloned records — the same fallback shape as
/// `ArraySequence::matches_factory_char`.
// Ghidra: constseq.cc:188 StringSequence::StringSequence
fn same_datatype(a: &Arc<Datatype>, b: &Arc<Datatype>) -> bool {
    if Arc::ptr_eq(a, b) {
        return true;
    }
    a.get_name() == b.get_name() && a.get_size() == b.get_size()
}

impl StringSequence {
    // Ghidra: constseq.cc:188 StringSequence::StringSequence
    /// Set-up for recovering COPY ops into a memory range, given a Symbol
    /// and an Address being COPYed into. Faithful to the constructor
    /// (constseq.cc:188-219): the space/size/zero-constant guards, the
    /// getSubType walk from the Symbol's type down to the character type
    /// (tracking the innermost enclosing array and its offset), then the
    /// collectCopyOps → checkInterference → formByteArray chain. On any
    /// guard failure the sequence stays invalid (`num_elements == 0`).
    ///
    /// `ent` is the container query hit (`LocalMapEntry` from
    /// `ScopeLocal::find_container_entry`, the mirror of the
    /// `queryContainer` call at constseq.cc:963); `sym_type` is
    /// `ent->getSymbol()->getType()`.
    pub fn new(
        fd: &Funcdata,
        ct: Arc<Datatype>,
        ent: &crate::varmap::LocalMapEntry,
        sym_type: Option<Arc<Datatype>>,
        root: Arc<RwLock<PcodeOp>>,
        addr_space: crate::space::AddressSpace,
        addr_offset: u64,
    ) -> Self {
        let mut seq = Self {
            base: ArraySequence::new(root.clone()),
            root_addr: addr_offset,
            start_addr: addr_offset,
            space: addr_space,
            entry_first: ent.start,
            entry_size: ent.size,
            symbol_type: sym_type.clone(),
        };
        seq.base.char_type = Some(ct.clone());
        // cc:193-194: entry must be in the same space as the root address.
        if ent.space != addr_space {
            return seq;
        }
        // cc:195-197: off = rootAddr - entry->getFirst(); off >= entry size.
        let off = addr_offset as i64 - ent.start as i64;
        if off >= ent.size as i64 {
            return seq;
        }
        // cc:198-199: root constant is the null terminator -> no string.
        let root_const_zero = {
            let op = root.read().unwrap();
            op.inrefs
                .first()
                .map(|v| v.read().unwrap().get_offset() == 0)
                .unwrap_or(true)
        };
        if root_const_zero {
            return seq;
        }
        // cc:200-211: walk down from the Symbol's type to the character
        // type, tracking the last array layer and its offset.
        let Some(parent) = sym_type else {
            // RUDRA-GLUE: Rudra's ScopeLocal symbols may carry no type;
            // Ghidra's Symbol always has one (TYPE_UNDEF at minimum), so the
            // walk below would simply fail to reach ct.
            return seq;
        };
        let mut parent_type = parent;
        let mut array_type: Option<Arc<Datatype>> = None;
        let mut last_off = 0i64;
        let mut off = off;
        let mut reached_char = <Arc<Datatype>>::ptr_eq(&parent_type, &ct)
            || same_datatype(&parent_type, &ct);
        loop {
            if reached_char {
                break;
            }
            array_type = Some(parent_type.clone());
            last_off = off;
            let (sub, new_off) = Datatype::get_sub_type(parent_type.as_ref(), off);
            match sub {
                Some(t) => {
                    parent_type = t;
                    off = new_off;
                }
                None => break, // parentType == null -> walk ran off
            }
            reached_char = Arc::ptr_eq(&parent_type, &ct) || same_datatype(&parent_type, &ct);
        }
        if !reached_char {
            return seq; // cc:210: parentType != ct
        }
        let Some(array_type) = array_type else {
            return seq; // cc:210: arrayType == null
        };
        if array_type.get_metatype() != crate::type_system::TypeMetatype::Array {
            return seq; // cc:210: not TYPE_ARRAY
        }
        // cc:212: startAddr = rootAddr - lastOff.
        seq.start_addr = (addr_offset as i64 - last_off) as u64;
        // cc:213-216: collect the COPYs and check interference.
        if !seq.collect_copy_ops(fd, array_type.get_size() as i32) {
            return seq;
        }
        if !seq.base.check_interference(fd) {
            return seq;
        }
        // cc:217-218: form the byte array over the remaining array span.
        let arr_size = array_type.get_size() as i64 - (addr_offset as i64 - seq.start_addr as i64);
        let big_endian = addr_space.is_big_endian();
        seq.base.num_elements =
            seq.base.form_byte_array(arr_size as i32, 0, addr_offset, big_endian);
        seq
    }

    // Ghidra: constseq.cc:227 StringSequence::collectCopyOps
    /// Collect ops COPYing constants into the memory region. Faithful to
    /// `collectCopyOps` (constseq.cc:227-264): the varnode loc-set span
    /// [beginAddr..endAddr] (beginAddr = array start or the character before
    /// the root, whichever is later; endAddr = last byte of the array), and
    /// per-varnode guards — written, COPY, same block, constant input, exact
    /// character size (wrong size aborts: the COPY still needs splitting),
    /// and the previous-element/gap/advance offset arithmetic on `diff`.
    /// Returns true when at least MINIMUM_SEQUENCE_LENGTH ops were found.
    fn collect_copy_ops(&mut self, fd: &Funcdata, size: i32) -> bool {
        // cc:230-234: startAddr - endAddr bounds the formal array; the
        // search starts at the array start or the character before the root.
        let end_addr = self.start_addr + (size as i64 - 1).max(0) as u64;
        let char_align = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1) as i64;
        let mut begin_addr = self.start_addr;
        if self.start_addr != self.root_addr {
            begin_addr = (self.root_addr as i64 - char_align) as u64;
        }
        // cc:235-236: VarnodeLocSet iteration from beginLoc(beginAddr) to
        // endLoc(endAddr) — Rudra walks the bank's loc tree (same
        // VarnodeCompareLocDef order). The tree is ordered
        // (space, loc, size, ...), so the walk stops as soon as an entry
        // sorts past (space, endAddr) — the exact bound of Ghidra's
        // endLoc(endAddr) upper bound — and skips entries that sort before
        // (space, beginAddr).
        let mut diff = self.root_addr as i64 - self.start_addr as i64;
        let space = self.space;
        let root_parent = self.base.root_op.read().unwrap().parent.clone();
        for entry in fd.vbank.loc_tree.iter() {
            let vn = entry.0.read().unwrap();
            // The varnode.rs `compare_address_spaces` ordering key
            // (space_id, enum) — private there, so mirrored inline.
            let spc_ord = vn
                .address_space
                .space_id()
                .cmp(&space.space_id())
                .then_with(|| vn.address_space.cmp(&space));
            match spc_ord {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Greater => break,
                std::cmp::Ordering::Equal => {}
            }
            let off = vn.loc.as_u64();
            if off > end_addr {
                break; // endLoc bound: remaining same-space entries are past
                       // the span (loc ordering within the space).
            }
            if off < begin_addr {
                continue;
            }
            // cc:241: isWritten (a dropped def Weak is the destroyed-op
            // seam — treated as not written).
            let Some(op) = vn.def.as_ref().and_then(|w| w.upgrade()) else {
                continue;
            };
            let op_guard = op.read().unwrap();
            // cc:243: def must be a COPY.
            if op_guard.opcode != OpCode::CPUI_COPY {
                continue;
            }
            // cc:244: COPY must be in the root's basic block.
            let same_block = match (&root_parent, &op_guard.parent) {
                (Some(a), Some(b)) => std::sync::Weak::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            };
            if !same_block {
                continue;
            }
            // cc:245: input must be constant.
            let in0_const = op_guard
                .inrefs
                .first()
                .map(|v| v.read().unwrap().is_constant())
                .unwrap_or(false);
            if !in0_const {
                continue;
            }
            // cc:246-247: wrong size — the COPY has yet to be split.
            let char_size = self
                .base
                .char_type
                .as_ref()
                .map(|t| t.get_size())
                .unwrap_or(1);
            if vn.size != char_size {
                return false;
            }
            // cc:248-260: offset arithmetic relative to the sequence start.
            let tmp_diff = off as i64 - self.start_addr as i64;
            if tmp_diff < diff {
                if tmp_diff + char_align == diff {
                    // cc:250-251: COPY to the previous element — the root is
                    // not the first in the sequence.
                    return false;
                }
                continue;
            } else if tmp_diff > diff {
                if tmp_diff - diff < char_align {
                    continue;
                }
                if tmp_diff - diff > char_align {
                    break; // cc:258: gap in COPYs
                }
                diff = tmp_diff; // cc:259: advanced by one character
            }
            self.base
                .move_ops
                .push(WriteNode::new(off, op.clone(), -1));
        }
        // cc:263.
        self.base.move_ops.len() >= MINIMUM_SEQUENCE_LENGTH as usize
    }

    // Ghidra: constseq.cc:273 StringSequence::constructTypedPointer
    /// Construct a Varnode, with data-type, that acts as a pointer (in)to
    /// the Symbol at the root Address. Faithful to `constructTypedPointer`
    /// (constseq.cc:273-339): a base PTRSUB off the spacebase (stack input
    /// or constant spacebase), then one PTRSUB/PTRADD per nesting level
    /// (PTRADD skipped for element 0 of an array), each with the
    /// `getTypePointerStripArray` pointer type, and a final INT_ADD when the
    /// residual offset inside the character type is non-zero.
    pub fn construct_typed_pointer(
        &self,
        fd: &mut Funcdata,
        insert_point: &crate::op::PcodeOpRef,
    ) -> Option<Arc<RwLock<Varnode>>> {
        // cc:276-282: spacebase input (stack) or constant spacebase.
        let space_ptr = if self.space.is_stack() {
            fd.construct_spacebase_input(self.space)
        } else {
            fd.construct_const_spacebase(self.space)
        };
        let insert_addr = insert_point.0.read().unwrap().get_addr();
        let ptr_size = space_ptr.read().unwrap().get_size();
        let word_size = self.space.word_size() as u32;
        // cc:283-292: PTRSUB(spacebase, entry first offset) typed pointer
        // to the Symbol (array stripped).
        let Some(base_type) = self.symbol_type.clone() else {
            return None;
        };
        let ptrsub = fd.new_op(2, insert_addr);
        fd.op_set_opcode(&ptrsub, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&ptrsub, space_ptr.clone(), 0);
        // cc:287: convert the entry offset to address units.
        let base_off = crate::space::AddrSpace::byte_to_address(self.entry_first, word_size);
        let const_vn = fd.new_constant(ptr_size, base_off);
        fd.op_set_input(&ptrsub, const_vn, 1);
        let mut space_ptr = fd.new_unique_out(ptr_size, &ptrsub);
        fd.op_insert_before(&ptrsub, insert_point);
        let cur_type = Self::type_pointer_strip_array(fd, ptr_size, base_type.clone(), word_size);
        space_ptr.write().unwrap().update_type(cur_type);
        // cc:293-326: descend through the nesting levels.
        let char_type = self.base.char_type.clone()?;
        let mut base_type = base_type;
        let mut cur_off = self.root_addr as i64 - self.entry_first as i64;
        while !(Arc::ptr_eq(&base_type, &char_type) || same_datatype(&base_type, &char_type)) {
            // cc:295-297: element size when the current level is an array.
            let el_size: i64 = if let Datatype::Array(a) = base_type.as_ref() {
                a.array_of.get_align_size() as i64
            } else {
                -1
            };
            // cc:299-300: one getSubType level down.
            let (sub, new_off) = Datatype::get_sub_type(base_type.as_ref(), cur_off);
            let Some(sub_type) = sub else {
                break;
            };
            base_type = sub_type;
            // cc:301: offset of the chosen component within this level.
            cur_off -= new_off;
            let base_off = crate::space::AddrSpace::byte_to_address(cur_off as u64, word_size);
            let new_op;
            if el_size >= 0 {
                // cc:304-307: element 0 of an array needs no PTRADD(#0,...).
                if cur_off == 0 {
                    continue;
                }
                // cc:309-313: PTRADD(prev, numEl, elSize).
                new_op = fd.new_op(3, insert_addr);
                fd.op_set_opcode(&new_op, OpCode::CPUI_PTRADD);
                let num_el = cur_off / el_size;
                let idx_vn = fd.new_constant(4, num_el as u64);
                fd.op_set_input(&new_op, idx_vn, 1);
                let el_vn = fd.new_constant(4, el_size as u64);
                fd.op_set_input(&new_op, el_vn, 2);
            } else {
                // cc:316-318: PTRSUB(prev, byte offset of the field).
                new_op = fd.new_op(2, insert_addr);
                fd.op_set_opcode(&new_op, OpCode::CPUI_PTRSUB);
                let off_vn = fd.new_constant(ptr_size, base_off);
                fd.op_set_input(&new_op, off_vn, 1);
            }
            // cc:320-324: wire input/output, insert before the insert
            // point, and type the output pointer.
            fd.op_set_input(&new_op, space_ptr.clone(), 0);
            space_ptr = fd.new_unique_out(ptr_size, &new_op);
            fd.op_insert_before(&new_op, insert_point);
            let cur_type = Self::type_pointer_strip_array(fd, ptr_size, base_type.clone(), word_size);
            space_ptr.write().unwrap().update_type(cur_type);
            // cc:325: descend to the offset within the new level.
            cur_off = new_off;
        }
        // cc:327-337: residual offset inside the character type.
        if cur_off != 0 {
            let add_op = fd.new_op(2, insert_addr);
            fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
            fd.op_set_input(&add_op, space_ptr.clone(), 0);
            let base_off = crate::space::AddrSpace::byte_to_address(cur_off as u64, word_size);
            let off_vn = fd.new_constant(ptr_size, base_off);
            fd.op_set_input(&add_op, off_vn, 1);
            space_ptr = fd.new_unique_out(ptr_size, &add_op);
            fd.op_insert_before(&add_op, insert_point);
            // cc:335-336: getTypePointer (NOT strip-array) for the final
            // pointer to the character type.
            let char_ptr = Self::type_pointer(fd, ptr_size, char_type, word_size);
            space_ptr.write().unwrap().update_type(char_ptr);
        }
        Some(space_ptr)
    }

    /// `types->getTypePointerStripArray(size, pt, ws)` (type.cc:3849): strip
    /// the formal stripped twin and one ARRAY level from the pointee, then
    /// intern the pointer through the factory.
    // Ghidra: type.cc:3849 TypeFactory::getTypePointerStripArray
    fn type_pointer_strip_array(
        fd: &mut Funcdata,
        size: usize,
        pt: Arc<Datatype>,
        word_size: u32,
    ) -> Arc<Datatype> {
        let mut pt = pt;
        if let Some(stripped) = Datatype::get_stripped_arc(&pt) {
            pt = stripped;
        }
        if let Datatype::Array(a) = pt.as_ref() {
            pt = a.array_of.clone();
        }
        Self::type_pointer(fd, size, pt, word_size)
    }

    /// `types->getTypePointer(size, pt, ws)` (type.cc:3867) through the
    /// architecture's factory.
    // Ghidra: type.cc:3867 TypeFactory::getTypePointer
    fn type_pointer(
        fd: &mut Funcdata,
        size: usize,
        pt: Arc<Datatype>,
        word_size: u32,
    ) -> Arc<Datatype> {
        let types_arc = match fd.arch.as_ref().and_then(|a| a.types.clone()) {
            Some(t) => t,
            None => return pt,
        };
        let result = types_arc
            .write()
            .unwrap()
            .get_type_pointer(size, pt, word_size as usize);
        result
    }

    // Ghidra: constseq.cc:347 StringSequence::buildStringCopy
    /// A built-in user-op that copies string data is created: destination is
    /// a typed pointer constructed into the array (which may be nested in
    /// other arrays or structures), source is an internal string built from
    /// the byte array, third input the length constant typed by the
    /// registered user-op's slot-3 local type. Faithful to
    /// `StringSequence::buildStringCopy` (constseq.cc:347-372), including
    /// `numBytes = moveOps.size() * charType->getSize()` (cc:351 — the
    /// collected-op count, not the element count) and insertion just before
    /// the earliest COPY.
    pub fn build_string_copy(&mut self, fd: &mut Funcdata) -> Option<crate::op::PcodeOpRef> {
        // cc:350: moveOps[0] is the earliest COPY in block order (sorted by
        // checkInterference).
        let insert_point =
            crate::op::PcodeOpRef(self.base.move_ops.first()?.op.clone());
        let insert_addr = insert_point.0.read().unwrap().get_addr();
        // cc:351: numBytes = moveOps.size() * charType->getSize().
        let char_size = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_size())
            .unwrap_or(1);
        let num_bytes = self.base.move_ops.len() * char_size;
        // cc:354: charPtrType = getTypePointer(sizeOfPointer, charType, ws).
        let char_type = self.base.char_type.clone()?;
        let ptr_size = fd
            .arch
            .as_ref()
            .and_then(|a| a.types.clone())
            .map(|t| t.read().unwrap().get_size_of_pointer().max(0) as usize)
            .unwrap_or(8);
        let char_ptr_type = Self::type_pointer(fd, ptr_size, char_type, self.space.word_size() as u32);
        // cc:355-357: srcPtr = getInternalString(byteArray, numBytes, ...).
        if self.base.byte_array.len() < num_bytes {
            return None;
        }
        let src_ptr = fd.get_internal_string(
            &self.base.byte_array[..num_bytes],
            &char_ptr_type,
            &insert_point,
        )?;
        // cc:358-360: select the builtin and register it with local types.
        let (builtin_id, length_index) = self.base.select_string_copy_function(fd);
        HeapSequence::register_builtin_typed(fd, builtin_id);
        // cc:361-370: CALLOTHER(builtinId, destPtr, srcPtr, lenVn).
        let copy_op = fd.new_op(4, insert_addr);
        fd.op_set_opcode(&copy_op, OpCode::CPUI_CALLOTHER);
        let id_vn = fd.new_constant(4, builtin_id as u64);
        fd.op_set_input(&copy_op, id_vn, 0);
        let dest_ptr = self.construct_typed_pointer(fd, &insert_point)?;
        fd.op_set_input(&copy_op, dest_ptr, 1);
        fd.op_set_input(&copy_op, src_ptr, 2);
        // cc:367-368: lenVn typed by the user-op's slot-3 local type
        // (inputTypeLocal(3)).
        let len_vn = fd.new_constant(4, length_index as u64);
        if let Some(int4) = fd
            .arch
            .as_ref()
            .and_then(|a| a.userops.clone())
            .and_then(|uo| {
                uo.read()
                    .unwrap()
                    .get_input_local(builtin_id as i32, 3)
                    .cloned()
            })
        {
            len_vn.write().unwrap().update_type(int4);
        }
        fd.op_set_input(&copy_op, len_vn, 3);
        fd.op_insert_before(&copy_op, &insert_point);
        Some(copy_op)
    }

    // Ghidra: constseq.cc:383 StringSequence::removeForward
    /// Analyze output descendants of the given PcodeOp being removed.
    /// Faithful to `removeForward` (constseq.cc:383-409): record the read
    /// points for later replacement; a PIECE seen twice merges its two
    /// points into a dead op carrying the smaller offset. Rudra mirrors the
    /// `map<PcodeOp*, list<WriteNode>::iterator>` xref as
    /// `Arc::as_ptr` keys into indices over the `points` vector, with
    /// `alive` as the erase projection of `points.erase(iter)`.
    fn remove_forward(
        cur_node: &WriteNode,
        xref: &mut std::collections::HashMap<usize, usize>,
        points: &mut Vec<WriteNode>,
        alive: &mut Vec<bool>,
        dead_ops: &mut Vec<WriteNode>,
    ) {
        let out_vn = cur_node.op.read().unwrap().output.clone();
        let Some(out_vn) = out_vn else { return };
        let descends: Vec<Arc<RwLock<PcodeOp>>> =
            out_vn.read().unwrap().descend_iter().collect();
        for op in descends {
            let op_key = Arc::as_ptr(&op) as usize;
            if let Some(&idx) = xref.get(&op_key) {
                // cc:391-397: we have seen the PIECE twice.
                let off = {
                    let prev = &points[idx];
                    let mut off = prev.offset;
                    if cur_node.offset < off {
                        off = cur_node.offset;
                    }
                    off
                };
                alive[idx] = false; // points.erase(miter->second)
                xref.remove(&op_key);
                dead_ops.push(WriteNode::new(off, op.clone(), -1));
            } else {
                // cc:399-406: record the read point; PIECEs register their
                // points iterator for the second visit.
                let (slot, is_piece) = {
                    let g = op.read().unwrap();
                    let slot = g
                        .slot_of_input(&out_vn)
                        .map(|s| s as i32)
                        .unwrap_or(-1);
                    (slot, g.opcode == OpCode::CPUI_PIECE)
                };
                points.push(WriteNode::new(cur_node.offset, op.clone(), slot));
                alive.push(true);
                if is_piece {
                    let idx = points.len() - 1;
                    xref.insert(op_key, idx);
                }
            }
        }
    }

    // Ghidra: constseq.cc:415 StringSequence::removeCopyOps
    /// The COPY ops are removed. Faithful to `removeCopyOps`
    /// (constseq.cc:415-447): the removeForward pass over the sequence ops
    /// and then over the cascading dead PIECE ops, the surviving read points
    /// redefined through an INDIRECT around the CALLOTHER (skipping inputs
    /// already defined by an INDIRECT), and the destruction of the sequence
    /// and dead ops.
    pub fn remove_copy_ops(&mut self, fd: &mut Funcdata, replace_op: &crate::op::PcodeOpRef) {
        // cc:418-428: forward analysis with the PIECE cascade.
        let mut concat_set: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        let mut points: Vec<WriteNode> = Vec::new();
        let mut alive: Vec<bool> = Vec::new();
        let mut dead_ops: Vec<WriteNode> = Vec::new();
        for node in self.base.move_ops.clone() {
            Self::remove_forward(&node, &mut concat_set, &mut points, &mut alive, &mut dead_ops);
        }
        let mut pos = 0;
        while pos < dead_ops.len() {
            let node = dead_ops[pos].clone();
            Self::remove_forward(&node, &mut concat_set, &mut points, &mut alive, &mut dead_ops);
            pos += 1;
        }
        // cc:429-441: redefine surviving read points as INDIRECTs around
        // the CALLOTHER.
        let replace_addr = replace_op.0.read().unwrap().get_addr();
        for (i, node) in points.iter().enumerate() {
            if !alive[i] {
                continue;
            }
            let op = node.op.clone();
            let vn = {
                let g = op.read().unwrap();
                g.inrefs.get(node.slot.max(0) as usize).cloned()
            };
            let Some(vn) = vn else { continue };
            let def_is_indirect = {
                let g = vn.read().unwrap();
                g.def
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .map(|d| d.read().unwrap().opcode == OpCode::CPUI_INDIRECT)
                    .unwrap_or(false)
            };
            if def_is_indirect {
                continue;
            }
            let vn_size = vn.read().unwrap().get_size();
            let new_in = fd.new_constant(vn_size, 0);
            let ind_op = fd.new_op(2, replace_addr);
            fd.op_set_opcode(&ind_op, OpCode::CPUI_INDIRECT);
            fd.op_set_input(&ind_op, new_in, 0);
            let iop_vn = fd.new_varnode_iop(replace_op);
            fd.op_set_input(&ind_op, iop_vn, 1);
            fd.op_set_output(&ind_op, vn.clone());
            fd.mark_indirect_creation(&ind_op, false);
            fd.op_insert_before(&ind_op, replace_op);
        }
        // cc:443-446: destroy the sequence ops, then the dead PIECE ops.
        for node in self.base.move_ops.clone() {
            fd.op_destroy(&crate::op::PcodeOpRef(node.op));
        }
        for node in dead_ops {
            fd.op_destroy(&crate::op::PcodeOpRef(node.op));
        }
    }

    // Ghidra: constseq.cc:453 StringSequence::transform
    /// Transform COPYs into a single CALLOTHER memcpy/strncpy user-op.
    /// Faithful to `StringSequence::transform` (constseq.cc:453-461): the
    /// transform fails only when `buildStringCopy` fails (the byte array
    /// does not encode a legal string); otherwise the COPYs are removed
    /// around the new CALLOTHER.
    pub fn transform(&mut self, fd: &mut Funcdata) -> bool {
        let mem_cpy_op = match self.build_string_copy(fd) {
            Some(op) => op,
            None => return false,
        };
        self.remove_copy_ops(fd, &mem_cpy_op);
        true
    }
}

/// A sequence of STORE operations writing characters through a string pointer.
/// Corresponds to Ghidra's `HeapSequence` (constseq.hh:86).
pub struct HeapSequence {
    /// Base ArraySequence
    pub base: ArraySequence,
    /// Pointer that sequence is stored to (constseq.hh:97 `basePointer`)
    pub base_pointer: Option<Arc<RwLock<Varnode>>>,
    /// Offset relative to pointer to root STORE (constseq.hh:98 `baseOffset`)
    pub base_offset: u64,
    /// Address space being STOREd to (constseq.hh:99 `storeSpace`).
    /// Rudra stores the AddressSpace enum directly (Ghidra holds an `AddrSpace *`).
    pub store_space: crate::space::AddressSpace,
    /// Required multiplier for PTRADD ops (constseq.hh:100 `ptrAddMult`).
    /// Maps element size to address units. Rudra: with word_size==1, this equals
    /// `charType->getAlignSize()` (see HeapSequence::new_heap).
    pub ptr_add_mult: u64,
    /// Non-constant Varnodes being added into pointer calculation
    /// (constseq.hh:101 `nonConstAdds`). Built by calcPtraddOffset and consumed
    /// by buildStringCopy's index-Varnode construction.
    pub non_const_adds: Vec<Arc<RwLock<Varnode>>>,
}

/// Helper class containing Varnode pairs that flow across a sequence of
/// INDIRECTs. Corresponds to Ghidra's `HeapSequence::IndirectPair`
/// (constseq.hh:88-96). Holds the in/out Varnode pair of a STORE-side
/// INDIRECT, with a "duplicate" marker used by deduplicatePairs.
#[derive(Clone, Debug)]
pub struct IndirectPair {
    /// Input to INDIRECTs (constseq.hh:90 `inVn`). Set to `None` by
    /// `mark_duplicate` to signal that this pair is a duplicate of another.
    pub in_vn: Option<Arc<RwLock<Varnode>>>,
    /// Output of INDIRECTs (constseq.hh:91 `outVn`).
    pub out_vn: Arc<RwLock<Varnode>>,
}

impl IndirectPair {
    // Ghidra: constseq.hh:92 IndirectPair::IndirectPair
    /// Construct from the input/output Varnode pair. Faithful to
    /// `IndirectPair(Varnode *in, Varnode *out)` (constseq.hh:92).
    pub fn new(in_vn: Arc<RwLock<Varnode>>, out_vn: Arc<RwLock<Varnode>>) -> Self {
        Self { in_vn: Some(in_vn), out_vn }
    }

    // Ghidra: constseq.hh:93 IndirectPair::markDuplicate
    /// Note that `this` is a duplicate of another pair. Faithful to
    /// `markDuplicate(void)` (constseq.hh:93): sets `inVn = (Varnode *)0`.
    /// Rudra uses `Option::None` as the null sentinel.
    pub fn mark_duplicate(&mut self) {
        self.in_vn = None;
    }

    // Ghidra: constseq.hh:94 IndirectPair::isDuplicate
    /// Return true if `this` is marked as a duplicate. Faithful to
    /// `isDuplicate(void) const` (constseq.hh:94): returns `inVn == null`.
    pub fn is_duplicate(&self) -> bool {
        self.in_vn.is_none()
    }

    // Ghidra: constseq.cc:808 IndirectPair::compareOutput
    /// Compare pairs by output storage, ordering on (space index, offset, size).
    /// Faithful to `IndirectPair::compareOutput` (constseq.cc:808-820). Used as
    /// the sort comparator in `deduplicatePairs`. Returns true if `a < b`.
    ///
    /// Ghidra orders address spaces by `AddrSpace::getIndex()`; Rudra uses
    /// `AddressSpace::space_id()` (the SLEIGH space index) for the same ordering.
    pub fn compare_output(a: &IndirectPair, b: &IndirectPair) -> std::cmp::Ordering {
        let va = a.out_vn.read().unwrap();
        let vb = b.out_vn.read().unwrap();
        // cc:813: compare by space index.
        let sa = va.address_space.space_id();
        let sb = vb.address_space.space_id();
        if sa != sb {
            return sa.cmp(&sb);
        }
        // cc:815: compare by offset.
        if va.get_offset() != vb.get_offset() {
            return va.get_offset().cmp(&vb.get_offset());
        }
        // cc:817: compare by size.
        if va.get_size() != vb.get_size() {
            return va.get_size().cmp(&vb.get_size());
        }
        // cc:819: equal storage.
        std::cmp::Ordering::Equal
    }
}

/// Convert byte offset to address units. Intended counterpart of
/// `AddrSpace::byteToAddressInt` (space.hh); the current identity body is a
/// known mismatch for `word_size != 1`.
// Ghidra: space.hh:541 AddrSpace::byteToAddressInt
fn byte_to_address_int(byte_off: u64, _word_size: usize) -> u64 {
    byte_off
}

/// Convert address units to byte offset. Intended counterpart of
/// `AddrSpace::addressToByteInt` (space.hh); the current identity body is a
/// known mismatch for `word_size != 1`.
// Ghidra: space.hh:532 AddrSpace::addressToByteInt
fn address_to_byte_int(addr_off: u64, _word_size: usize) -> u64 {
    addr_off
}

/// Extract the destination AddressSpace of a STORE from its space-id constant
/// input. Intended counterpart of `Varnode::getSpaceFromConst` (varnode.hh),
/// but the current numeric SpaceId model is not Ghidra's encoded pointer.
// Ghidra: varnode.hh:426 Varnode::getSpaceFromConst
fn get_space_from_const(vn: &Arc<RwLock<Varnode>>) -> crate::space::AddressSpace {
    let r = vn.read().unwrap();
    if !r.is_constant() {
        // Defensive: Ghidra's getSpaceFromConst assumes a constant; if not,
        // fall back to the varnode's own space.
        return r.address_space;
    }
    crate::space::AddressSpace::from_id(r.get_offset() as crate::space::SpaceId)
}

impl HeapSequence {
    // Ghidra: constseq.hh:88 HeapSequence::HeapSequence (constructor body at
    //   constseq.cc:907-921) — Rudra separates allocation (Struct::new) from
    //   analysis (new_heap / collect_store_ops). `new_heap` performs the
    //   storeSpace / ptrAddMult initialization that Ghidra does inline in the
    //   constructor (cc:911-912), then defers to find_base_pointer +
    //   collect_store_ops + check_interference + form_byte_array. Callers that
    //   only want a heap object without running analysis should use `new`.
    /// Construct a HeapSequence around `root_op` (a STORE). Faithful to the
    /// Ghidra `HeapSequence::HeapSequence` constructor (constseq.cc:907-921)
    /// up to the `baseOffset = 0` initialization (cc:910); the full analysis
    /// chain (`findBasePointer` → `collectStoreOps` → ...) is launched by
    /// `new_heap`, mirroring the rest of the Ghidra constructor body.
    pub fn new(root_op: Arc<RwLock<PcodeOp>>) -> Self {
        Self {
            base: ArraySequence::new(root_op),
            base_pointer: None,
            base_offset: 0,
            store_space: crate::space::AddressSpace::Ram,
            ptr_add_mult: 1,
            non_const_adds: Vec::new(),
        }
    }

    // Ghidra: constseq.cc:907 HeapSequence::HeapSequence (analysis body)
    /// Run the full HeapSequence analysis chain on the root STORE. Faithful to
    /// the body of the Ghidra constructor (constseq.cc:910-921):
    ///   1. baseOffset = 0; storeSpace = root->getIn(0)->getSpaceFromConst()
    ///   2. ptrAddMult  = byteToAddressInt(charType->getAlignSize(), wordSize)
    ///   3. findBasePointer(root->getIn(1))
    ///   4. if (!collectStoreOps()) return
    ///   5. if (!checkInterference()) return
    ///   6. numElements = formByteArray(moveOps.size()*alignSize, 2, 0, bigEndian)
    /// Returns true if a valid sequence was recovered (`base.is_valid()`).
    pub fn new_heap(&mut self, fd: &Funcdata) -> bool {
        let (space, char_align_size) = {
            let root = self.base.root_op.read().unwrap();
            // cc:911: storeSpace = root->getIn(0)->getSpaceFromConst().
            let space_vn = match root.inrefs.first() {
                Some(v) => v.clone(),
                None => return false,
            };
            let store_space = get_space_from_const(&space_vn);
            // cc:912: ptrAddMult = byteToAddressInt(charType->getAlignSize(),
            //                                       storeSpace->getWordSize()).
            let char_align = self
                .base
                .char_type
                .as_ref()
                .map(|t| t.get_align_size())
                .unwrap_or(1) as u64;
            (store_space, char_align)
        };
        self.store_space = space;
        self.ptr_add_mult = byte_to_address_int(char_align_size, space.word_size());

        // cc:913: findBasePointer(rootOp->getIn(1)).
        let root_ptr = {
            let root = self.base.root_op.read().unwrap();
            match root.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return false,
            }
        };
        self.find_base_pointer(&root_ptr);

        // cc:914-915: if (!collectStoreOps()) return.
        if !self.collect_store_ops(fd) {
            return false;
        }
        // cc:916-917: if (!checkInterference()) return — the faithful
        // block-order maximal-set walk (constseq.cc:62-96); a failure leaves
        // num_elements=0 (isValid=false), mirroring the oracle constructor.
        if !self.base.check_interference(fd) {
            return false;
        }
        // cc:918-920: numElements = formByteArray(arrSize, 2, 0, bigEndian)
        // with arrSize = moveOps.size() * charType->getAlignSize().
        let elem_size = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1) as i32;
        let arr_size = self.base.move_ops.len() as i32 * elem_size;
        let big_endian = self.store_space.is_big_endian();
        let count = self.base.form_byte_array(arr_size, 2, 0, big_endian);
        self.base.num_elements = count;
        count > 0
    }

    // Ghidra: constseq.cc:465 HeapSequence::findBasePointer
    /// From a starting pointer, backtrack through PTRADDs and COPYs to a
    /// putative root Varnode pointer. Faithful to `findBasePointer`
    /// (constseq.cc:465-480). This is the FULL version: it verifies the
    /// PTRADD multiplier (input[2]) equals `self.ptr_add_mult` (cc:473-475),
    /// which the simplified `RuleStringStore::ptr_shares_base` helper omits.
    /// Sets `self.base_pointer` to the discovered root.
    pub fn find_base_pointer(&mut self, init_ptr: &Arc<RwLock<Varnode>>) {
        let mut base_ptr = init_ptr.clone();
        loop {
            let def = {
                let g = base_ptr.read().unwrap();
                if !g.is_written() {
                    break;
                }
                g.get_def()
            };
            let Some(def_op) = def else { break };
            let (opc, in0, in2_offset) = {
                let d = def_op.read().unwrap();
                (
                    d.opcode,
                    d.inrefs.first().cloned(),
                    d.inrefs.get(2).map(|v| v.read().unwrap().get_offset()),
                )
            };
            if opc == OpCode::CPUI_PTRADD {
                // cc:473-475: break if multiplier != ptrAddMult.
                if let Some(sz) = in2_offset {
                    if sz != self.ptr_add_mult {
                        break;
                    }
                } else {
                    break;
                }
            } else if opc != OpCode::CPUI_COPY {
                // cc:476-477: any other defining op stops the walk.
                break;
            }
            // cc:478: basePointer = op->getIn(0).
            let Some(next) = in0 else { break };
            base_ptr = next;
        }
        self.base_pointer = Some(base_ptr);
    }

    // Ghidra: constseq.cc:486 HeapSequence::findDuplicateBases
    /// Back-track from `base_pointer` through PTRSUBs, INT_ADDs, and PTRADDs
    /// to an earlier root, keeping track of any offsets; then trace forward
    /// through ops trying to match the offsets. Faithful to
    /// `findDuplicateBases` (constseq.cc:486-539). `duplist` is filled with
    /// the discovered alias base Varnodes, including `base_pointer` itself.
    ///
    /// Locked-text chain form: the entry gate (cc:495) accepts PTRSUB,
    /// INT_ADD, and PTRADD with constant input[1], but BOTH chain filters
    /// (the back-track break at cc:510-511 and the forward-scan accept at
    /// cc:526-527) test `!= CPUI_PTRSUB && != CPUI_INT_ADD && !=
    /// CPUI_PTRSUB` — the duplicated CPUI_PTRSUB is verbatim 12.0.4
    /// upstream text and is the locked behavior: CPUI_PTRADD is NOT a
    /// chain op anywhere past the entry gate (the cc:503-504/cc:531-532
    /// PTRADD offset scaling applies to the gate-admitted entry op only;
    /// under the locked forward filter the scaling branch is dead).
    pub fn find_duplicate_bases(
        &self,
        duplist: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let base_ptr = match &self.base_pointer {
            Some(b) => b.clone(),
            None => return,
        };
        // cc:489-492: if basePointer is not written, push it and return.
        let def_op = match base_ptr.read().unwrap().get_def() {
            Some(d) => Some(d),
            None => None,
        };
        let def_op = match def_op {
            Some(d) => d,
            None => {
                duplist.push(base_ptr);
                return;
            }
        };
        // cc:493-498: gate on PTRSUB/INT_ADD/PTRADD with constant input[1].
        let (opc, in1_const) = {
            let d = def_op.read().unwrap();
            let in1_const = d
                .inrefs
                .get(1)
                .map(|v| v.read().unwrap().is_constant())
                .unwrap_or(false);
            (d.opcode, in1_const)
        };
        if (opc != OpCode::CPUI_PTRSUB
            && opc != OpCode::CPUI_INT_ADD
            && opc != OpCode::CPUI_PTRADD)
            || !in1_const
        {
            duplist.push(base_ptr);
            return;
        }
        // cc:499-513: back-track collecting offsets.
        let mut copy_root = base_ptr.clone();
        let mut offsets: Vec<u64> = Vec::new();
        let mut cur_op = def_op;
        let mut cur_opc = opc;
        let mut cur_in1_const = in1_const;
        loop {
            let (off, in0, in0_def, next_opc, next_in1_const) = {
                let d = cur_op.read().unwrap();
                let raw_off = d
                    .inrefs
                    .get(1)
                    .map(|v| v.read().unwrap().get_offset())
                    .unwrap_or(0);
                let off = if cur_opc == OpCode::CPUI_PTRADD {
                    // cc:503-504: PTRADD offsets are scaled by input[2].
                    let mult = d
                        .inrefs
                        .get(2)
                        .map(|v| v.read().unwrap().get_offset())
                        .unwrap_or(1);
                    raw_off.wrapping_mul(mult)
                } else {
                    raw_off
                };
                let in0 = d.inrefs.first().cloned();
                let in0_def = in0.as_ref().and_then(|v| v.read().unwrap().get_def());
                // Peek the next defining op's opcode + input[1] constness.
                let (next_opc, next_in1_const) = match &in0_def {
                    Some(op) => {
                        let od = op.read().unwrap();
                        let c = od
                            .inrefs
                            .get(1)
                            .map(|v| v.read().unwrap().is_constant())
                            .unwrap_or(false);
                        (od.opcode, c)
                    }
                    None => (OpCode::CPUI_COPY, false),
                };
                (off, in0, in0_def, next_opc, next_in1_const)
            };
            offsets.push(off);
            let Some(next) = in0 else { break };
            copy_root = next;
            // cc:507-512: stop if copyRoot is not written, or its def fails
            // the locked chain test `opc != CPUI_PTRSUB && opc !=
            // CPUI_INT_ADD && opc != CPUI_PTRSUB` (constseq.cc:510-511 —
            // the duplicated CPUI_PTRSUB is the 12.0.4 upstream text and is
            // locked behavior: only PTRSUB/INT_ADD continue the chain;
            // CPUI_PTRADD is NOT a chain op, it is accepted only by the
            // entry gate at cc:495). The duplicated test is idempotent in
            // Rust, so it collapses to the two-arm form here.
            let next_def = match in0_def {
                Some(d) => d,
                None => break,
            };
            if next_opc != OpCode::CPUI_PTRSUB && next_opc != OpCode::CPUI_INT_ADD {
                break;
            }
            cur_op = next_def;
            cur_opc = next_opc;
            cur_in1_const = next_in1_const;
            if !cur_in1_const {
                break;
            }
        }
        // cc:514: duplist.push_back(copyRoot).
        duplist.push(copy_root.clone());

        // cc:516-538: trace forward through each offset layer.
        for i in (0..offsets.len()).rev() {
            let target_off = offsets[i];
            // Swap current duplist into midlist, clear duplist for this layer.
            let midlist: Vec<Arc<RwLock<Varnode>>> = std::mem::take(duplist);
            for vn in &midlist {
                // For each candidate in midlist, scan its descendants for ops
                // that re-add the matching offset (cc:521-536).
                let descendants: Vec<Arc<RwLock<PcodeOp>>> =
                    vn.read().unwrap().descend_iter().collect();
                for op in descendants {
                    let d = op.read().unwrap();
                    let d_opc = d.opcode;
                    // cc:526-527: the locked forward-scan filter `opc !=
                    // CPUI_PTRSUB && opc != CPUI_INT_ADD && opc !=
                    // CPUI_PTRSUB` (duplicated CPUI_PTRSUB = 12.0.4 upstream
                    // text, locked behavior) accepts only PTRSUB/INT_ADD;
                    // CPUI_PTRADD descendants are skipped. The cc:531-532
                    // PTRADD offset scaling below is therefore dead under
                    // the locked filter, exactly as in the oracle text.
                    if d_opc != OpCode::CPUI_PTRSUB && d_opc != OpCode::CPUI_INT_ADD {
                        continue;
                    }
                    // cc:528: in(0) must be vn and in(1) must be constant.
                    let in0_match = d.inrefs.first().map(|v| Arc::ptr_eq(v, vn)).unwrap_or(false);
                    if !in0_match {
                        continue;
                    }
                    let in1_const = d
                        .inrefs
                        .get(1)
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false);
                    if !in1_const {
                        continue;
                    }
                    let raw_off = d
                        .inrefs
                        .get(1)
                        .map(|v| v.read().unwrap().get_offset())
                        .unwrap_or(0);
                    let off = if d_opc == OpCode::CPUI_PTRADD {
                        let mult = d
                            .inrefs
                            .get(2)
                            .map(|v| v.read().unwrap().get_offset())
                            .unwrap_or(1);
                        raw_off.wrapping_mul(mult)
                    } else {
                        raw_off
                    };
                    if off != target_off {
                        continue;
                    }
                    // cc:535: duplist.push_back(op->getOut()).
                    if let Some(out) = &d.output {
                        duplist.push(out.clone());
                    }
                }
            }
        }
    }

    // Ghidra: constseq.cc:544 HeapSequence::findInitialStores
    /// Find STOREs with pointers derived from `base_pointer` and that are in
    /// the same basic block as the root STORE. The root STORE is NOT included.
    /// Faithful to `findInitialStores` (constseq.cc:544-573).
    ///
    /// Walks forward from `base_pointer` (and its duplicate bases) through
    /// PTRADD/COPY descendants, collecting STORE ops in the root's block whose
    /// pointer input equals the walked Varnode.
    pub fn find_initial_stores(
        &mut self,
        fd: &Funcdata,
        stores: &mut Vec<Arc<RwLock<PcodeOp>>>,
    ) {
        // cc:547-548: ptradds starts with findDuplicateBases output.
        let mut ptradds: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.find_duplicate_bases(&mut ptradds);

        let (root_block, root_seq) = {
            let r = self.base.root_op.read().unwrap();
            let rb = r.parent.as_ref().and_then(|w| w.upgrade());
            (rb, r.start.clone())
        };

        let mut pos = 0usize;
        while pos < ptradds.len() {
            let vn = ptradds[pos].clone();
            pos += 1;
            // cc:553-571: iterate over vn's descendants.
            let descendants: Vec<Arc<RwLock<PcodeOp>>> =
                vn.read().unwrap().descend_iter().collect();
            for op in descendants {
                let d = op.read().unwrap();
                let opc = d.opcode;
                if opc == OpCode::CPUI_PTRADD {
                    // cc:558-562: only PTRADDs whose input[0] is vn and whose
                    // input[2] (multiplier) == ptrAddMult extend the walk.
                    let in0_is_vn = d.inrefs.first().map(|v| Arc::ptr_eq(v, &vn)).unwrap_or(false);
                    if !in0_is_vn {
                        continue;
                    }
                    let mult_match = d
                        .inrefs
                        .get(2)
                        .map(|v| v.read().unwrap().get_offset() == self.ptr_add_mult)
                        .unwrap_or(false);
                    if !mult_match {
                        continue;
                    }
                    if let Some(out) = &d.output {
                        ptradds.push(out.clone());
                    }
                } else if opc == OpCode::CPUI_COPY {
                    // cc:564-566: COPYs extend the walk unconditionally.
                    if let Some(out) = &d.output {
                        ptradds.push(out.clone());
                    }
                } else if opc == OpCode::CPUI_STORE {
                    // cc:567-570: STORE in root's block, input[1] == vn, not root.
                    let in1_is_vn = d.inrefs.get(1).map(|v| Arc::ptr_eq(v, &vn)).unwrap_or(false);
                    if !in1_is_vn {
                        continue;
                    }
                    let same_block = match (&d.parent, &root_block) {
                        (Some(a), Some(b)) => a.upgrade().map(|x| Arc::ptr_eq(&x, b)).unwrap_or(false),
                        _ => false,
                    };
                    if !same_block {
                        continue;
                    }
                    if d.start == root_seq {
                        continue; // root STORE excluded
                    }
                    stores.push(op.clone());
                }
            }
        }
        let _ = fd; // Ghidra reads block via rootOp->getParent(); Rudra does the same.
    }

    // Ghidra: constseq.cc:583 HeapSequence::calcAddElements
    /// Recursively walk an INT_ADD tree from a given root, collecting offsets
    /// and non-constant elements. Faithful to `calcAddElements`
    /// (constseq.cc:583-595). Constant offsets are summed and returned; any
    /// non-constant Varnode encountered (or depth limit hit) is pushed to
    /// `non_const`. Recursion is depth-limited (Ghidra calls with maxDepth=3).
    pub fn calc_add_elements(
        vn: &Arc<RwLock<Varnode>>,
        non_const: &mut Vec<Arc<RwLock<Varnode>>>,
        max_depth: i32,
    ) -> u64 {
        let r = vn.read().unwrap();
        // cc:586-587: constant leaf returns its offset.
        if r.is_constant() {
            return r.get_offset();
        }
        // cc:588-591: non-constant leaf or non-INT_ADD def or depth exhausted.
        let def_op = r.get_def();
        drop(r);
        let def_op = match def_op {
            Some(d) => d,
            None => {
                non_const.push(vn.clone());
                return 0;
            }
        };
        let is_int_add = def_op.read().unwrap().opcode == OpCode::CPUI_INT_ADD;
        if !is_int_add || max_depth == 0 {
            non_const.push(vn.clone());
            return 0;
        }
        // cc:592-594: recurse into both inputs.
        let (in0, in1) = {
            let d = def_op.read().unwrap();
            (d.inrefs.first().cloned(), d.inrefs.get(1).cloned())
        };
        let mut res = 0u64;
        if let Some(i0) = in0 {
            res = res.wrapping_add(Self::calc_add_elements(&i0, non_const, max_depth - 1));
        }
        if let Some(i1) = in1 {
            res = res.wrapping_add(Self::calc_add_elements(&i1, non_const, max_depth - 1));
        }
        res
    }

    // Ghidra: constseq.cc:604 HeapSequence::calcPtraddOffset
    /// Calculate the byte offset and any non-constant additive elements
    /// between the given Varnode and `base_pointer`. Faithful to
    /// `calcPtraddOffset` (constseq.cc:604-627). Walks backward from `vn`
    /// through PTRADDs and COPYs, summing constant offsets (scaled by the
    /// PTRADD multiplier when it matches `ptr_add_mult`). Non-constant
    /// Varnodes encountered (that are not themselves the pointer) are passed
    /// back in `non_const`. Returns the summed offset in byte units.
    ///
    /// NOTE: this delegates to a free-function helper that takes `ptr_add_mult`
    /// and `store_space_word_size` as scalar parameters. The split lets callers
    /// that hold a `&mut self.field` borrow (e.g. `collect_store_ops` writing
    /// `self.non_const_adds`) invoke the analysis without an aliasing `&self`
    /// borrow — Rust's borrow checker forbids `self.x(&mut self.y)` even though
    /// the two fields are disjoint.
    pub fn calc_ptradd_offset(
        &self,
        vn: &Arc<RwLock<Varnode>>,
        non_const: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> u64 {
        Self::calc_ptradd_offset_inner(
            vn,
            non_const,
            self.ptr_add_mult,
            self.store_space.word_size(),
        )
    }

    /// Inner implementation of `calcPtraddOffset` taking scalar parameters so
    /// callers can avoid an `&self` borrow. See `calc_ptradd_offset` for the
    /// Ghidra-line attribution.
    // Ghidra: constseq.cc:604 HeapSequence::calcPtraddOffset
    fn calc_ptradd_offset_inner(
        vn: &Arc<RwLock<Varnode>>,
        non_const: &mut Vec<Arc<RwLock<Varnode>>>,
        ptr_add_mult: u64,
        store_space_word_size: usize,
    ) -> u64 {
        let mut res = 0u64;
        let mut cur = vn.clone();
        loop {
            let r = cur.read().unwrap();
            if !r.is_written() {
                break;
            }
            let def_op = match r.get_def() {
                Some(d) => d,
                None => break,
            };
            drop(r);
            let d = def_op.read().unwrap();
            let opc = d.opcode;
            if opc == OpCode::CPUI_PTRADD {
                // cc:612-618: PTRADD with matching multiplier.
                let mult = d
                    .inrefs
                    .get(2)
                    .map(|v| v.read().unwrap().get_offset())
                    .unwrap_or(1);
                if mult != ptr_add_mult {
                    break;
                }
                let idx_vn = match d.inrefs.get(1) {
                    Some(v) => v.clone(),
                    None => break,
                };
                let mut local_non_const: Vec<Arc<RwLock<Varnode>>> = Vec::new();
                let off = Self::calc_add_elements(&idx_vn, &mut local_non_const, 3);
                let off = off.wrapping_mul(mult);
                res = res.wrapping_add(off);
                non_const.extend(local_non_const);
                // cc:618: vn = op->getIn(0).
                let in0 = match d.inrefs.first() {
                    Some(v) => v.clone(),
                    None => break,
                };
                cur = in0;
            } else if opc == OpCode::CPUI_COPY {
                // cc:620-621: COPY just unwraps.
                let in0 = match d.inrefs.first() {
                    Some(v) => v.clone(),
                    None => break,
                };
                cur = in0;
            } else {
                // cc:623-624: any other op stops the walk.
                break;
            }
        }
        // cc:626: convert address units to byte units.
        address_to_byte_int(res, store_space_word_size)
    }

    // Ghidra: constseq.cc:636 HeapSequence::setsEqual
    /// Determine if two sets of Varnodes are equal. Faithful to `setsEqual`
    /// (constseq.cc:636-644). The sets are assumed sorted; returns true iff
    /// they contain the exact same Varnodes. Used by collectStoreOps to verify
    /// two STOREs share the same non-constant address components.
    pub fn sets_equal(
        op1: &[Arc<RwLock<Varnode>>],
        op2: &[Arc<RwLock<Varnode>>],
    ) -> bool {
        if op1.len() != op2.len() {
            return false;
        }
        for i in 0..op1.len() {
            if !Arc::ptr_eq(&op1[i], &op2[i]) {
                return false;
            }
        }
        true
    }

    // Ghidra: constseq.cc:648 HeapSequence::testValue
    /// Test if a STORE's value (input[2]) has the matching size for the
    /// sequence's character type. Faithful to `testValue` (constseq.cc:648-657).
    /// Returns false if the value is not constant or its size differs from
    /// `char_type->getSize()`. This is the FULL form missing from the inline
    /// apply_op path.
    pub fn test_value(&self, op: &Arc<RwLock<PcodeOp>>) -> bool {
        let r = op.read().unwrap();
        let vn = match r.inrefs.get(2) {
            Some(v) => v.clone(),
            None => return false,
        };
        drop(r);
        let vr = vn.read().unwrap();
        // cc:652-653: must be constant.
        if !vr.is_constant() {
            return false;
        }
        // cc:654-655: size must match charType->getSize().
        let char_size = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_size())
            .unwrap_or(1);
        if vr.get_size() != char_size {
            return false;
        }
        true
    }

    // Ghidra: constseq.cc:663 HeapSequence::collectStoreOps
    /// Walk forward from the base pointer to all STORE ops from that pointer,
    /// keeping track of the offset. The final set of STOREs all live in the
    /// same basic block as the root STORE and have offset >= the root's.
    /// Faithful to `collectStoreOps` (constseq.cc:663-690). Returns true if the
    /// minimum sequence size is collected.
    ///
    /// This is the FULL version: it computes `base_offset` via
    /// `calc_ptradd_offset` (cc:672), then for each initial STORE verifies the
    /// non-constant components match via `sets_equal` (cc:679), applies the
    /// wrap-mask relative offset (cc:678), bounds-checks against maxSize
    /// (cc:680-681), and tests the value via `test_value` (cc:682-683). The
    /// root STORE is appended last at offset 0 (cc:687).
    pub fn collect_store_ops(&mut self, fd: &Funcdata) -> bool {
        let mut init_stores: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        self.find_initial_stores(fd, &mut init_stores);
        // cc:668: need at least MINIMUM_SEQUENCE_LENGTH-1 siblings (+1 root).
        if init_stores.len() + 1 < MINIMUM_SEQUENCE_LENGTH as usize {
            return false;
        }
        let char_align = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1) as u64;
        // cc:670: maxSize = MAXIMUM_SEQUENCE_LENGTH * charType->getAlignSize().
        let max_size = MAXIMUM_SEQUENCE_LENGTH as u64 * char_align;
        // cc:671: wrapMask = calc_mask(storeSpace->getAddrSize()).
        let wrap_mask = crate::address::calc_mask(self.store_space.addr_size());
        // cc:672: baseOffset = calcPtraddOffset(rootOp->getIn(1), nonConstAdds).
        // Snapshot the scalar fields so we can mutably borrow non_const_adds
        // without aliasing `self` (see calc_ptradd_offset_inner doc comment).
        let root_ptr = {
            let r = self.base.root_op.read().unwrap();
            match r.inrefs.get(1) {
                Some(v) => v.clone(),
                None => return false,
            }
        };
        let pam = self.ptr_add_mult;
        let sws = self.store_space.word_size();
        self.base_offset = Self::calc_ptradd_offset_inner(
            &root_ptr,
            &mut self.non_const_adds,
            pam,
            sws,
        );
        // cc:674-686: walk each initial STORE.
        for op in &init_stores {
            let cur_ptr = match op.read().unwrap().inrefs.get(1) {
                Some(v) => v.clone(),
                None => continue,
            };
            let mut non_const_comp: Vec<Arc<RwLock<Varnode>>> = Vec::new();
            let cur_offset = self.calc_ptradd_offset(&cur_ptr, &mut non_const_comp);
            // cc:678: diff = (curOffset - baseOffset) & wrapMask.
            let diff = cur_offset.wrapping_sub(self.base_offset) & wrap_mask;
            if Self::sets_equal(&self.non_const_adds, &non_const_comp) {
                // cc:680-681: too far → root is not earliest or offsets span
                // more than maxSize.
                if diff >= max_size {
                    return false;
                }
                // cc:682-683: value must have matching form.
                if !self.test_value(op) {
                    return false;
                }
                // cc:684: moveOps.emplace_back(diff, op, -1).
                self.base.move_ops.push(WriteNode::new(diff, op.clone(), -1));
            }
        }
        // cc:687: root STORE at offset 0.
        self.base
            .move_ops
            .push(WriteNode::new(0, self.base.root_op.clone(), -1));
        // cc:689: return true (minimum size already checked above; Ghidra
        // checks >= MINIMUM_SEQUENCE_LENGTH implicitly via the caller).
        true
    }

    // Ghidra: constseq.cc:770 HeapSequence::gatherIndirectPairs
    /// Gather INDIRECT ops attached to the final sequence STOREs and their
    /// input/output Varnode pairs. Faithful to `gatherIndirectPairs`
    /// (constseq.cc:770-806).
    ///
    /// Walks the ops immediately preceding each STORE; chained INDIRECTs for a
    /// single storage location are collapsed to their initial input and final
    /// output. INDIRECTs whose output has a use outside another STORE INDIRECT
    /// produce a pair. Marks each gathered INDIRECT op so descendant scans can
    /// recognize STORE-side INDIRECTs, then clears the marks at the end.
    pub fn gather_indirect_pairs(
        &self,
        fd: &Funcdata,
        indirects: &mut Vec<Arc<RwLock<PcodeOp>>>,
        pairs: &mut Vec<IndirectPair>,
    ) {
        // cc:773-781: for each STORE, walk preceding INDIRECT chain via
        // PcodeOp::previousOp() (op.cc:344-353) — the immediately preceding
        // op within the same basic block, or None at the block head.
        for node in &self.base.move_ops {
            let mut prev = node
                .op
                .read()
                .unwrap()
                .previous_op_in_block(&fd.obank)
                .map(|p| p.0.clone());
            while let Some(p) = prev {
                let is_indirect = p.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
                if !is_indirect {
                    break;
                }
                // cc:777: mark the INDIRECT.
                p.write().unwrap().set_mark();
                // cc:778: indirects.push_back(op).
                indirects.push(p.clone());
                // cc:779: continue backward.
                prev = p
                    .read()
                    .unwrap()
                    .previous_op_in_block(&fd.obank)
                    .map(|n| n.0.clone());
            }
        }
        // cc:782-803: for each INDIRECT, check if its output has a non-INDIRECT use.
        for op in indirects.clone().iter() {
            let (out_vn, in_vn_initial) = {
                let r = op.read().unwrap();
                let out = match &r.output {
                    Some(o) => o.clone(),
                    None => continue,
                };
                let in0 = match r.inrefs.first() {
                    Some(v) => v.clone(),
                    None => continue,
                };
                (out, in0)
            };
            // cc:786-793: look for a read of outvn that is not by another
            // marked STORE-INDIRECT.
            let mut has_use = false;
            for use_op in out_vn.read().unwrap().descend_iter() {
                if !use_op.read().unwrap().is_mark() {
                    has_use = true;
                    break;
                }
            }
            if !has_use {
                continue;
            }
            // cc:795-800: trace in back to an input not defined by a marked
            // STORE-INDIRECT.
            let mut invn = in_vn_initial;
            loop {
                let (is_written, def, def_in0) = {
                    let g = invn.read().unwrap();
                    if !g.is_written() {
                        break;
                    }
                    let d = match g.get_def() {
                        Some(d) => d,
                        None => break,
                    };
                    let di0 = d.read().unwrap().inrefs.first().cloned();
                    (true, d, di0)
                };
                let _ = is_written;
                // cc:798: if (!defOp->isMark()) break;
                if !def.read().unwrap().is_mark() {
                    break;
                }
                // cc:799: invn = defOp->getIn(0).
                match def_in0 {
                    Some(next) => invn = next,
                    None => break,
                }
            }
            // cc:801: pairs.emplace_back(invn, outvn).
            pairs.push(IndirectPair::new(invn, out_vn));
        }
        // cc:804-805: clear marks.
        for op in indirects {
            op.write().unwrap().clear_mark();
        }
    }

    // Ghidra: constseq.cc:827 HeapSequence::deduplicatePairs
    /// Find and eliminate duplicate INDIRECT pairs. Faithful to
    /// `deduplicatePairs` (constseq.cc:827-864). INDIRECTs collected from
    /// different effect ops may share the same output storage; this finds any
    /// output Varnodes that share storage and replaces their reads with a
    /// single representative Varnode. Returns false on partial overlap or on
    /// same-storage-different-sources, in which case the transform must abort.
    pub fn deduplicate_pairs(
        &mut self,
        fd: &mut Funcdata,
        pairs: &mut Vec<IndirectPair>,
    ) -> bool {
        // cc:830: empty list is trivially deduplicated.
        if pairs.is_empty() {
            return true;
        }
        // cc:831-833: build a sort view (Rust sorts in place via indices).
        let mut order: Vec<usize> = (0..pairs.len()).collect();
        order.sort_by(|&a, &b| {
            IndirectPair::compare_output(&pairs[a], &pairs[b])
        });
        // cc:836-852: walk sorted pairs, classifying overlap with the head.
        let mut head_idx = order[0];
        let mut dup_count = 0usize;
        for &i in order.iter().skip(1) {
            let overlap = {
                let h = pairs[head_idx].out_vn.read().unwrap();
                let v = pairs[i].out_vn.read().unwrap();
                h.characterize_overlap(&v)
            };
            // cc:841-842: partial overlap → fail.
            if overlap == 1 {
                return false;
            }
            if overlap == 2 {
                // cc:843-848: identical storage; must come from same source.
                let same_source = match (&pairs[i].in_vn, &pairs[head_idx].in_vn) {
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    _ => false,
                };
                if !same_source {
                    return false;
                }
                pairs[i].mark_duplicate();
                dup_count += 1;
                // cc:848: keep the same head for the next iteration.
            } else {
                // cc:850-851: no overlap, advance head.
                head_idx = i;
            }
        }
        // cc:853-862: if any duplicates, replace their reads with the head's out.
        if dup_count > 0 {
            head_idx = order[0];
            for &i in order.iter().skip(1) {
                if pairs[i].is_duplicate() {
                    let head_out = pairs[head_idx].out_vn.clone();
                    let dup_out = pairs[i].out_vn.clone();
                    fd.total_replace(&dup_out, head_out);
                } else {
                    head_idx = i;
                }
            }
        }
        true
    }

    // Ghidra: constseq.cc:871 HeapSequence::removeStoreOps
    /// Remove all STORE ops from the basic block, unhooking INDIRECT pairs'
    /// outputs first so they survive the recursive destroy, then rebuilding
    /// the surviving INDIRECTs around the replacement CALLOTHER. Faithful to
    /// `removeStoreOps` (constseq.cc:871-894).
    pub fn remove_store_ops(
        &mut self,
        fd: &mut Funcdata,
        indirects: &[Arc<RwLock<PcodeOp>>],
        indirect_pairs: &[IndirectPair],
        replace_op: &crate::op::PcodeOpRef,
    ) {
        // cc:874-877: unhook output Varnodes of each pair we want to preserve.
        for pair in indirect_pairs {
            // pair.outVn->getDef() is the INDIRECT; unset its output so the
            // recursive destroy below does not kill the preserved outVn.
            let def = pair.out_vn.read().unwrap().get_def();
            if let Some(def_op) = def {
                fd.op_unset_output(&crate::op::PcodeOpRef(def_op));
            }
        }
        // cc:878-881: destroy each move op (STORE) recursively.
        let to_remove: Vec<crate::op::PcodeOpRef> = self
            .base
            .move_ops
            .iter()
            .map(|n| crate::op::PcodeOpRef(n.op.clone()))
            .collect();
        for op in &to_remove {
            fd.op_destroy_recursive(op);
        }
        // cc:882-884: destroy the original INDIRECT ops.
        for ind in indirects {
            fd.op_destroy(&crate::op::PcodeOpRef(ind.clone()));
        }
        // cc:885-893: rebuild a fresh INDIRECT around replaceOp for each
        // surviving (non-duplicate) pair.
        for pair in indirect_pairs {
            if pair.is_duplicate() {
                continue;
            }
            let addr = replace_op.0.read().unwrap().get_addr();
            let new_ind = fd.new_op(2, addr);
            fd.op_set_opcode(&new_ind, OpCode::CPUI_INDIRECT);
            // cc:889: opSetOutput(newInd, outVn).
            fd.op_set_output(&new_ind, pair.out_vn.clone());
            // cc:890: opSetInput(newInd, inVn, 0).
            if let Some(in_vn) = &pair.in_vn {
                fd.op_set_input(&new_ind, in_vn.clone(), 0);
            }
            // cc:891: opSetInput(newInd, newVarnodeIop(replaceOp), 1).
            let iop_vn = fd.new_varnode_iop(replace_op);
            fd.op_set_input(&new_ind, iop_vn, 1);
            // cc:892: opInsertBefore(newInd, replaceOp).
            fd.op_insert_before(&new_ind, replace_op);
        }
    }

    // Ghidra: constseq.cc:927 HeapSequence::transform
    /// Transform STOREs into a single CALLOTHER memcpy user-op. Faithful to
    /// `HeapSequence::transform` (constseq.cc:927-940). Gathers indirect
    /// pairs, deduplicates them (aborting on failure), builds the string-copy
    /// CALLOTHER, then removes the STORE ops. Returns false if any step fails.
    ///
    /// This is the STORE-path-specific transform; it layers the indirect-pair
    /// analysis on top of the shared `ArraySequence::build_string_copy` /
    /// `remove_store_ops` machinery. `dest_ptr_addr` is the destination
    /// pointer address passed through to `build_string_copy`.
    // Ghidra: constseq.cc:698 HeapSequence::buildStringCopy
    /// A built-in user-op that copies string data is created: destination is
    /// the base pointer (plus an index PTRADD when the root was offset from
    /// the base or non-constant adds participate), source is an internal
    /// string built from the byte array, third input the length constant.
    /// Faithful to `HeapSequence::buildStringCopy` (constseq.cc:698-762),
    /// including the length varnode typing via the registered user-op's
    /// input metadata (cc:757-758 `lenVn->updateType(inputTypeLocal(3))`).
    pub fn build_string_copy(&mut self, fd: &mut Funcdata) -> Option<crate::op::PcodeOpRef> {
        // cc:701: insertPoint = moveOps[0].op — earliest STORE in block order
        // (move_ops were sorted by checkInterference).
        let insert_point = crate::op::PcodeOpRef(self.base.move_ops.first()?.op.clone());
        let insert_addr = insert_point.0.read().unwrap().get_addr();
        // cc:702: charPtrType = rootOp->getIn(1)->getTypeReadFacing(rootOp).
        let char_ptr_type = {
            let ptr_vn = self.base.root_op.read().unwrap().inrefs.get(1)?.clone();
            let op_guard = self.base.root_op.read().unwrap();
            let ct = ptr_vn.read().unwrap().get_type_read_facing_op(&op_guard, 1);
            ct
        }?;
        // cc:703: numBytes = numElements * charType->getSize().
        let char_size = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_size())
            .unwrap_or(1);
        let num_bytes = self.base.num_elements.max(0) as usize * char_size;
        // cc:705-707: srcPtr = getInternalString(byteArray.data(), numBytes,
        //   charPtrType, insertPoint); null return aborts the transform.
        if self.base.byte_array.len() < num_bytes {
            return None;
        }
        let src_ptr = fd.get_internal_string(
            &self.base.byte_array[..num_bytes],
            &char_ptr_type,
            &insert_point,
        )?;
        // cc:708-748: destination pointer construction.
        let mut dest_ptr = self.base_pointer.clone()?;
        let base_ptr_size = dest_ptr.read().unwrap().get_size();
        let char_align = self
            .base
            .char_type
            .as_ref()
            .map(|t| t.get_align_size())
            .unwrap_or(1) as u64;
        if self.base_offset != 0 || !self.non_const_adds.is_empty() {
            // cc:711: intType = types->getBase(basePointer->getSize(), TYPE_INT)
            let int_type = fd
                .arch
                .as_ref()
                .and_then(|a| a.types.clone())
                .and_then(|types| {
                    types
                        .read()
                        .unwrap()
                        .get_base(base_ptr_size, crate::type_system::TypeMetatype::Int)
                });
            // cc:712-723: fold the non-constant index varnodes together.
            let mut index_vn: Option<Arc<RwLock<Varnode>>> = None;
            if !self.non_const_adds.is_empty() {
                index_vn = Some(self.non_const_adds[0].clone());
                for extra in self.non_const_adds.iter().skip(1) {
                    let add_op = fd.new_op(2, insert_addr);
                    fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
                    fd.op_set_input(&add_op, index_vn.clone()?, 0);
                    fd.op_set_input(&add_op, extra.clone(), 1);
                    let out = fd.new_unique_out(base_ptr_size, &add_op);
                    if let Some(t) = &int_type {
                        // cc:720: indexVn->updateType(intType) — the
                        // single-argument non-locking form.
                        out.write().unwrap().update_type(t.clone());
                    }
                    fd.op_insert_before(&add_op, &insert_point);
                    index_vn = Some(out);
                }
            }
            // cc:724-739: add in the (element-scaled) constant base offset.
            if self.base_offset != 0 {
                let num_el = self.base_offset / char_align.max(1);
                let cvn = fd.new_constant(base_ptr_size, num_el);
                if let Some(t) = &int_type {
                    // cc:727: cvn->updateType(intType) — non-locking form.
                    cvn.write().unwrap().update_type(t.clone());
                }
                index_vn = match index_vn {
                    None => Some(cvn),
                    Some(idx) => {
                        let add_op = fd.new_op(2, insert_addr);
                        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
                        fd.op_set_input(&add_op, idx, 0);
                        fd.op_set_input(&add_op, cvn, 1);
                        let out = fd.new_unique_out(base_ptr_size, &add_op);
                        if let Some(t) = &int_type {
                            // cc:736: indexVn->updateType(intType) —
                            // non-locking form.
                            out.write().unwrap().update_type(t.clone());
                        }
                        fd.op_insert_before(&add_op, &insert_point);
                        Some(out)
                    }
                };
            }
            // cc:740-747: PTRADD(basePointer, index, alignSize) typed charPtrType.
            let ptr_add = fd.new_op(3, insert_addr);
            fd.op_set_opcode(&ptr_add, OpCode::CPUI_PTRADD);
            let out = fd.new_unique_out(base_ptr_size, &ptr_add);
            let align_vn = fd.new_constant(base_ptr_size, char_align);
            fd.op_set_input(&ptr_add, dest_ptr.clone(), 0);
            fd.op_set_input(&ptr_add, index_vn?, 1);
            fd.op_set_input(&ptr_add, align_vn, 2);
            // cc:746: destPtr->updateType(charPtrType) — non-locking form.
            out.write().unwrap().update_type(char_ptr_type.clone());
            fd.op_insert_before(&ptr_add, &insert_point);
            dest_ptr = out;
        }
        // cc:749-751: builtInId = selectStringCopyFunction(index);
        //   glb->userops.registerBuiltin(builtInId) — with the DatatypeUserOp
        //   local types from the architecture's factory (userop.cc:449-478).
        let (builtin_id, length_index) = self.base.select_string_copy_function(fd);
        Self::register_builtin_typed(fd, builtin_id);
        // cc:752-760: CALLOTHER with 4 inputs, inserted before insertPoint.
        let copy_op = fd.new_op(4, insert_addr);
        fd.op_set_opcode(&copy_op, OpCode::CPUI_CALLOTHER);
        let id_vn = fd.new_constant(4, builtin_id as u64);
        fd.op_set_input(&copy_op, id_vn, 0);
        fd.op_set_input(&copy_op, dest_ptr, 1);
        fd.op_set_input(&copy_op, src_ptr, 2);
        let len_vn = fd.new_constant(4, length_index as u64);
        // cc:757-758: lenVn->updateType(copyOp->inputTypeLocal(3)) — the
        // registered DatatypeUserOp's slot-3 local type (int4), set via the
        // single-argument non-locking updateType form.
        if let Some(int4) = fd
            .arch
            .as_ref()
            .and_then(|a| a.userops.clone())
            .and_then(|uo| {
                uo.read()
                    .unwrap()
                    .get_input_local(builtin_id as i32, 3)
                    .cloned()
            })
        {
            len_vn.write().unwrap().update_type(int4);
        }
        fd.op_set_input(&copy_op, len_vn, 3);
        fd.op_insert_before(&copy_op, &insert_point);
        Some(copy_op)
    }

    /// `glb->userops.registerBuiltin(builtInId)` with the DatatypeUserOp
    /// local types exactly as userop.cc:449-478 constructs them: STRNCPY →
    /// char element, WCSNCPY → wide char, MEMCPY → void; pointer/int4
    /// component types from the architecture's TypeFactory. The default
    /// data-space word size is 1 for the locked x86 gcc corpus (ram).
    // Ghidra: userop.cc:432 UserOpManage::registerBuiltin (DatatypeUserOp local-type arms 449-478)
    fn register_builtin_typed(fd: &Funcdata, builtin_id: u32) {
        use crate::userop::{
            BUILTIN_MEMCPY, BUILTIN_STRNCPY, BUILTIN_WCSNCPY,
        };
        let Some(arch) = fd.arch.as_ref() else { return };
        let Some(types_arc) = arch.types.clone() else { return };
        let Some(userops) = arch.userops.clone() else { return };
        let mut factory = types_arc.write().unwrap();
        let ptr_size = factory.get_size_of_pointer().max(0) as usize;
        let element = match builtin_id {
            BUILTIN_STRNCPY => {
                let sz = factory.get_size_of_char().max(0) as usize;
                factory.get_type_char(sz).ok()
            }
            BUILTIN_WCSNCPY => {
                let sz = factory.get_size_of_wchar().max(0) as usize;
                factory.get_type_char(sz).ok()
            }
            BUILTIN_MEMCPY => Some(factory.get_type_void()),
            _ => None,
        };
        let Some(element) = element else { return };
        let ptr_type = factory.get_type_pointer(ptr_size, element, 1);
        let Some(int_type) = factory.get_base(4, crate::type_system::TypeMetatype::Int) else {
            return;
        };
        let _ = userops.write().unwrap().register_builtin_with_local_types(
            builtin_id,
            Some(ptr_type.clone()),
            vec![Some(ptr_type.clone()), Some(ptr_type), Some(int_type)],
        );
    }

    // Ghidra: constseq.cc:927 HeapSequence::transform
    /// The user-op representing the string move is created and all the STORE
    /// ops are removed. Faithful to `HeapSequence::transform`
    /// (constseq.cc:927-940): gather INDIRECT pairs, deduplicate (aborting on
    /// partial overlap / source mismatch), build the string-copy CALLOTHER,
    /// then remove the STORE ops around it. Returns false if any step fails.
    pub fn transform(&mut self, fd: &mut Funcdata) -> bool {
        // cc:930-932: gather indirect pairs.
        let mut indirects: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut indirect_pairs: Vec<IndirectPair> = Vec::new();
        self.gather_indirect_pairs(fd, &mut indirects, &mut indirect_pairs);
        // cc:933-934: deduplicate (abort on partial overlap / source mismatch).
        if !self.deduplicate_pairs(fd, &mut indirect_pairs) {
            return false;
        }
        // cc:935-937: build the CALLOTHER string copy.
        let callop = match self.build_string_copy(fd) {
            Some(op) => op,
            None => return false,
        };
        // cc:938: remove the STORE ops (rebuilds surviving INDIRECTs).
        self.remove_store_ops(fd, &indirects, &indirect_pairs, &callop);
        true
    }
}

/// Rule triggering on COPY ops to detect string copy sequences.
/// Corresponds to Ghidra's `RuleStringCopy` (constseq.hh:119).
pub struct RuleStringCopy;

impl RuleStringCopy {
    // Ghidra: constseq.cc:948 RuleStringCopy::new
    pub fn new() -> Self { Self }
}

impl Rule for RuleStringCopy {
    // Ghidra: constseq.cc:954 RuleStringCopy::applyOp
    fn apply_op(&self, op: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStringCopy::applyOp (constseq.cc:954-972): given
        // a root COPY of a constant character to an address-tied
        // char-printable Varnode, query the local scope for the containing
        // SymbolEntry, run the full StringSequence analysis, and replace
        // the COPY family with a single strncpy/wcsncpy/memcpy CALLOTHER.
        // cc:957: input must be constant.
        let in0 = match op.read().unwrap().inrefs.first() {
            Some(v) => v.clone(),
            None => return Ok(action_status::NO_CHANGE),
        };
        if !in0.read().unwrap().is_constant() {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:958-962: output varnode gates — char-printable, non-opaque,
        // address-tied.
        let out_vn = match op.read().unwrap().output.clone() {
            Some(o) => o,
            None => return Ok(action_status::NO_CHANGE),
        };
        let out_type = out_vn.read().unwrap().get_type();
        let Some(out_type) = out_type else {
            return Ok(action_status::NO_CHANGE);
        };
        if !out_type.is_char_print() {
            return Ok(action_status::NO_CHANGE);
        }
        if (out_type.get_flags()
            & crate::type_system::datatype::type_flags::OPAQUE_STRUCT)
            != 0
        {
            return Ok(action_status::NO_CHANGE);
        }
        if !out_vn.read().unwrap().is_addr_tied() {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:963-965: entry = data.getScopeLocal()->queryContainer(
        //   outvn->getAddr(), outvn->getSize(), op->getAddr()).
        // Ghidra's Scope::queryContainer (database.cc:1246) walks the local
        // scope then its parents; for the stack-space query the local leg is
        // the answering scope (the parent/global scopes hold only ram-space
        // entries). The ram leg is mirrored through the Database channel for
        // completeness (query_container_entry_parent_scope).
        let (out_space, out_off, out_size, op_usepoint) = {
            let g = out_vn.read().unwrap();
            let usepoint = op.read().unwrap().get_addr().as_u64();
            (g.get_space(), g.get_offset(), g.get_size(), usepoint)
        };
        let entry = fd
            .scope
            .as_ref()
            .and_then(|scope| {
                scope.find_container_entry(out_space, out_off, out_size as i64, Some(op_usepoint))
            })
            .or_else(|| {
                if out_space != crate::space::AddressSpace::Ram {
                    return None;
                }
                fd.query_container_entry_parent_scope(
                    crate::address::Address::new(out_off),
                    out_size as i32,
                    crate::address::Address::new(op_usepoint),
                )
                .map(|(_scope_id, entry_arc)| {
                    // Project the database SymbolEntry onto the LocalMapEntry
                    // shape the StringSequence constructor reads. The
                    // database leg is only reached for ram-space queries, so
                    // the projected space is Ram by construction.
                    let g = entry_arc.read().unwrap();
                    crate::varmap::LocalMapEntry {
                        sym: usize::MAX,
                        space: crate::space::AddressSpace::Ram,
                        start: g.get_first(),
                        size: g.size,
                        offset: g.offset,
                        extraflags: g.extraflags,
                        uselimit: Vec::new(),
                        // Projection seam: the database entry's frozen
                        // subsort is not read by the StringSequence
                        // constructor, so the minimum stands in.
                        subsort: <crate::varmap::EntrySubsort as crate::rangemap::RangeSubsort>::minimum(),
                    }
                })
            });
        let Some(entry) = entry else {
            return Ok(action_status::NO_CHANGE);
        };
        // entry->getSymbol()->getType() (cc:200).
        let sym_type = fd.scope.as_ref().and_then(|scope| {
            scope
                .symbols
                .get(entry.sym)
                .and_then(|ls| ls.dtype.clone())
        });
        // cc:966-971: StringSequence sequence(data,ct,entry,op,outvn->getAddr());
        //   isValid(); transform().
        let mut sequence = StringSequence::new(
            fd,
            out_type,
            &entry,
            sym_type,
            op.clone(),
            out_space,
            out_off,
        );
        if !sequence.base.is_valid() {
            return Ok(action_status::NO_CHANGE);
        }
        if !sequence.transform(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: constseq.cc:948 RuleStringCopy::getName
    fn get_name(&self) -> &str { "stringcopy" }
    // Ghidra: constseq.cc:942 RuleStringCopy::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_COPY] }
}

/// Rule triggering on STORE ops to detect heap string store sequences.
/// Corresponds to Ghidra's `RuleStringStore` (constseq.hh:130).
pub struct RuleStringStore;

impl RuleStringStore {
    // Ghidra: constseq.cc:980 RuleStringStore::new
    pub fn new() -> Self { Self }
}

impl Rule for RuleStringStore {
    // Ghidra: constseq.cc:986 RuleStringStore::applyOp
    fn apply_op(&self, op: &Arc<RwLock<PcodeOp>>, fd: &mut Funcdata) -> Result<i32> {
        // Faithful to RuleStringStore::applyOp (constseq.cc:986-1002): given
        // a root STORE of a constant character through a char-printable
        // pointer, run the full HeapSequence analysis and replace the STORE
        // family with a single strncpy/wcsncpy/memcpy CALLOTHER.
        let op_guard = op.read().unwrap();
        if op_guard.opcode != OpCode::CPUI_STORE || op_guard.inrefs.len() < 3 {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:989: value being stored (input[2]) must be a constant.
        let val_vn = op_guard.inrefs[2].clone();
        if !val_vn.read().unwrap().is_constant() {
            return Ok(action_status::NO_CHANGE);
        }
        // cc:990-995: pointer type gates — TYPE_PTR whose pointee is a
        // char-printable, non-opaque string element type.
        let ptr_vn = op_guard.inrefs[1].clone();
        let ptr_type = ptr_vn.read().unwrap().get_type_read_facing_op(&op_guard, 1);
        let Some(ptr_type) = ptr_type else {
            return Ok(action_status::NO_CHANGE);
        };
        let pointee = match ptr_type.as_ref() {
            Datatype::Pointer(p) => p.ptr_to.clone(),
            _ => return Ok(action_status::NO_CHANGE),
        };
        if !pointee.is_char_print() {
            return Ok(action_status::NO_CHANGE);
        }
        if (pointee.get_flags()
            & crate::type_system::datatype::type_flags::OPAQUE_STRUCT)
            != 0
        {
            return Ok(action_status::NO_CHANGE);
        }
        drop(op_guard);
        // cc:996-1001: HeapSequence sequence(data, ct, op); isValid();
        // transform(). new_heap mirrors the Ghidra constructor body
        // (constseq.cc:907-921) and leaves num_elements == 0 on failure.
        let mut sequence = HeapSequence::new(op.clone());
        sequence.base.char_type = Some(pointee);
        if !sequence.new_heap(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        if !sequence.base.is_valid() {
            return Ok(action_status::NO_CHANGE);
        }
        if !sequence.transform(fd) {
            return Ok(action_status::NO_CHANGE);
        }
        Ok(action_status::CHANGE)
    }

    // Ghidra: constseq.cc:980 RuleStringStore::getName
    fn get_name(&self) -> &str { "stringstore" }
    // Ghidra: constseq.cc:974 RuleStringStore::getOpList
    fn get_opcodes(&self) -> Vec<OpCode> { vec![OpCode::CPUI_STORE] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MINIMUM_SEQUENCE_LENGTH, 4);
        // constseq.cc:22: MAXIMUM_SEQUENCE_LENGTH = 0x20000.
        assert_eq!(MAXIMUM_SEQUENCE_LENGTH, 0x20000);
    }

    #[test]
    fn test_rule_names() {
        assert_eq!(RuleStringCopy::new().get_name(), "stringcopy");
        assert_eq!(RuleStringStore::new().get_name(), "stringstore");
    }

    /// One-byte char type helper for the byte-array tests (the factory char
    /// base shape: size 1, align 1).
    fn char1_type() -> Arc<Datatype> {
        Arc::new(Datatype::Base(crate::type_system::TypeBase::new(
            "char".to_string(),
            1,
            crate::type_system::TypeMetatype::Int,
        )))
    }

    fn push_copy_op(seq: &mut ArraySequence, offset: u64, ch: u8) {
        let op = Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(
                crate::address::Address::new(0x1000 + offset),
                0,
            ),
            OpCode::CPUI_COPY,
        )));
        let const_vn =
            Arc::new(RwLock::new(crate::varnode::Varnode::new_constant(ch as u64, 1)));
        op.write().unwrap().inrefs.push(const_vn);
        seq.move_ops.push(WriteNode::new(offset, op, 0));
    }

    /// formByteArray (constseq.cc:108-155) over six COPYs writing "Hello\0":
    /// the leading full-element run counts 5 characters plus the single null
    /// terminator, and the byte array holds the written bytes.
    #[test]
    fn test_form_byte_array_hello() {
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        seq.char_type = Some(char1_type());
        for (i, &ch) in b"Hello\0".iter().enumerate() {
            push_copy_op(&mut seq, i as u64, ch);
        }
        let count = seq.form_byte_array(6, 0, 0, false);
        assert_eq!(count, 6);
        assert_eq!(&seq.byte_array, b"Hello\0");
    }

    /// A run shorter than MINIMUM_SEQUENCE_LENGTH returns 0 (cc:143-144).
    #[test]
    fn test_form_byte_array_too_short() {
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        seq.char_type = Some(char1_type());
        for (i, &ch) in b"Hi\0".iter().enumerate() {
            push_copy_op(&mut seq, i as u64, ch);
        }
        assert_eq!(seq.form_byte_array(3, 0, 0, false), 0);
    }

    /// Ops beyond the contiguous run (offset >= count*alignSize) are dropped
    /// from move_ops (cc:145-152): the null terminator stops the count at 6,
    /// so an extra op at offset 6 must not survive.
    #[test]
    fn test_form_byte_array_truncates_extra_ops() {
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        seq.char_type = Some(char1_type());
        for (i, &ch) in b"Hello\0X".iter().enumerate() {
            push_copy_op(&mut seq, i as u64, ch);
        }
        let count = seq.form_byte_array(7, 0, 0, false);
        assert_eq!(count, 6);
        assert_eq!(seq.move_ops.len(), 6);
        assert_eq!(seq.move_ops.last().unwrap().offset, 5);
    }

    /// selectStringCopyFunction without an attached Architecture falls to
    /// BUILTIN_MEMCPY with the byte length (constseq.cc:173-174); with no
    /// char_type the element align defaults to 1 byte.
    #[test]
    fn test_select_string_copy_function_fallback() {
        use crate::userop::BUILTIN_MEMCPY;
        let fd = Funcdata::new("testsel", crate::address::Address::new(0x1000), 1);
        let mut seq = ArraySequence::new(Arc::new(RwLock::new(PcodeOp::new(
            crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0),
            OpCode::CPUI_COPY,
        ))));
        seq.num_elements = 5;
        let (id, len) = seq.select_string_copy_function(&fd);
        assert_eq!(id, BUILTIN_MEMCPY);
        assert_eq!(len, 5);
    }

    /// RuleStringStore::applyOp gates (constseq.cc:986-995): a STORE whose
    /// pointer carries no pointer data-type is rejected without change even
    /// when the stored value is a constant.
    #[test]
    fn test_rule_string_store_type_gate() {
        let mut fd = Funcdata::new("testgate", crate::address::Address::new(0x1000), 1);
        let store = fd.new_op(3, crate::address::Address::new(0x2000));
        fd.op_set_opcode(&store, OpCode::CPUI_STORE);
        let space_vn = fd.new_constant(8, 0);
        fd.op_set_input(&store, space_vn, 0);
        let ptr_vn = fd.new_constant(8, 0x3000);
        fd.op_set_input(&store, ptr_vn, 1);
        let val_vn = fd.new_constant(1, b'x' as u64);
        fd.op_set_input(&store, val_vn, 2);
        let res = RuleStringStore::new().apply_op(&store.0, &mut fd).unwrap();
        assert_eq!(res, action_status::NO_CHANGE);
    }
}
