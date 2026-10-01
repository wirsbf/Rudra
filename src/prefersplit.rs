//! Prefer-split records — faithful port of `prefersplit.hh` / `prefersplit.cc`
//! (631 lines).
//!
//! Infrastructure for designating registers that should be split into separate
//! pieces during decompilation. The `PreferSplitManager` applies splits based
//! on a list of `PreferSplitRecord` entries.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/prefersplit.{hh,cc}.

use crate::address::{calc_mask, Address};
use crate::funcdata::Funcdata;
use crate::op::PcodeOpRef;
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::Varnode;
use std::sync::{Arc, RwLock};

/// A record indicating that a specific storage location should be split into
/// two pieces. Faithful to `PreferSplitRecord` (prefersplit.hh:27).
#[derive(Debug, Clone)]
pub struct PreferSplitRecord {
    /// The storage location (space + offset + size) to split.
    pub storage_offset: u64,
    /// The address space of the storage.
    pub storage_space: AddressSpace,
    /// The size of the storage in bytes.
    pub storage_size: u32,
    /// Number of initial bytes (in address order) to split into the first
    /// piece.
    pub splitoffset: i32,
}

impl PreferSplitRecord {
    // Ghidra: prefersplit.hh:27 PreferSplitRecord::new
    /// Construct given storage details and split offset.
    pub fn new(offset: u64, space: AddressSpace, size: u32, splitoffset: i32) -> Self {
        Self {
            storage_offset: offset,
            storage_space: space,
            storage_size: size,
            splitoffset,
        }
    }

    // Ghidra: prefersplit.hh:27 PreferSplitRecord::lessThan
    /// Compare two records for sorting. Faithful to `operator<`
    /// (prefersplit.cc:23-31). Orders by space index, then size (descending),
    /// then offset.
    pub fn less_than(&self, op2: &PreferSplitRecord) -> bool {
        let s1 = self.storage_space.space_id();
        let s2 = op2.storage_space.space_id();
        if s1 != s2 {
            return s1 < s2;
        }
        if self.storage_size != op2.storage_size {
            return self.storage_size > op2.storage_size; // Bigger sizes come first.
        }
        self.storage_offset < op2.storage_offset
    }
}

// Ghidra: prefersplit.hh:27 PreferSplitRecord::initialize
/// Sort a vector of PreferSplitRecords. Faithful to `PreferSplitManager::initialize`
/// (prefersplit.cc:552-556).
pub fn initialize(records: &mut Vec<PreferSplitRecord>) {
    records.sort_by(|a, b| {
        if a.less_than(b) {
            std::cmp::Ordering::Less
        } else if b.less_than(a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

/// An instance of a split varnode being processed. Faithful to the private
/// nested class `PreferSplitManager::SplitInstance` (prefersplit.hh:34-42).
///
/// In Ghidra this holds a raw `Varnode*`; Rugra uses an `Arc` reference. The
/// `hi`/`lo` fields hold the computed most-/least-significant piece varnodes.
#[derive(Clone)]
pub struct SplitInstance {
    /// Number of initial bytes in the first piece.
    pub splitoffset: i32,
    /// The original varnode being split.
    pub vn: Arc<RwLock<Varnode>>,
    /// The most-significant piece (filled by `fillin_instance`).
    pub hi: Option<Arc<RwLock<Varnode>>>,
    /// The least-significant piece (filled by `fillin_instance`).
    pub lo: Option<Arc<RwLock<Varnode>>>,
}

impl std::fmt::Debug for SplitInstance {
    // Ghidra: prefersplit.hh:34 SplitInstance::fmt
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitInstance")
            .field("splitoffset", &self.splitoffset)
            .field("vn", &"<Varnode>")
            .field("hi", &self.hi.as_ref().map(|_| "<Varnode>"))
            .field("lo", &self.lo.as_ref().map(|_| "<Varnode>"))
            .finish()
    }
}

impl SplitInstance {
    // Ghidra: prefersplit.hh:34 SplitInstance::new
    /// Construct given the varnode reference and split offset. Faithful to the
    /// constructor (prefersplit.hh:41).
    pub fn new(vn: Arc<RwLock<Varnode>>, off: i32) -> Self {
        Self {
            splitoffset: off,
            vn,
            hi: None,
            lo: None,
        }
    }
}

/// Manages the splitting of varnodes based on a list of PreferSplitRecords.
/// Faithful to `PreferSplitManager` (prefersplit.hh:33-72).
pub struct PreferSplitManager {
    /// The split records describing which storage locations to split.
    /// (The oracle's `Funcdata *data` member is not stored: P6 — every
    /// fd-using method takes `fd: &mut Funcdata` per call, mirroring how
    /// the single owning `Heritage::heritage` pass holds fd across both
    /// split passes. Auto Send+Sync as a result.)
    records: Vec<PreferSplitRecord>,
    /// COPY ops of temporaries that need additional splitting
    /// (prefersplit.hh:45). Stored as `PcodeOpRef` to keep the Arc alive.
    tempsplits: Vec<PcodeOpRef>,
}

impl Default for PreferSplitManager {
    // Ghidra: prefersplit.hh:33 PreferSplitManager::default
    fn default() -> Self {
        Self::new()
    }
}

impl PreferSplitManager {
    // Ghidra: prefersplit.hh:33 PreferSplitManager::new
    /// Construct an empty manager.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            tempsplits: Vec::new(),
        }
    }

    // Ghidra: prefersplit.cc:529 PreferSplitManager::init
    /// Bind this manager's records list. Faithful to
    /// `PreferSplitManager::init` (prefersplit.cc:529-534: `data = fd;
    /// records = rec;`); the fd member is not stored (P6 — fd flows per
    /// call through `split`/`split_additional`), so only the records
    /// assignment remains. The records are sorted via `initialize`.
    pub fn init(&mut self, _fd: &mut Funcdata, rec: Vec<PreferSplitRecord>) {
        let mut rec = rec;
        initialize(&mut rec);
        self.records = rec;
    }

    // Ghidra: prefersplit.hh:33 PreferSplitManager::setRecords
    /// Set/replace the records list (sorted). Used when the manager is bound
    /// to a Funcdata only at split time.
    pub fn set_records(&mut self, records: Vec<PreferSplitRecord>) {
        let mut records = records;
        initialize(&mut records);
        self.records = records;
    }

    // Ghidra: prefersplit.hh:33 PreferSplitManager::numRecords
    /// Number of split records.
    pub fn num_records(&self) -> usize {
        self.records.len()
    }

    // Ghidra: prefersplit.hh:33 PreferSplitManager::records
    /// Get all records.
    pub fn records(&self) -> &[PreferSplitRecord] {
        &self.records
    }

    // Ghidra: prefersplit.hh:33 PreferSplitManager::findRecordVn
    /// Find the split record that applies to a varnode. Faithful to
    /// `findRecord(Varnode*)` (prefersplit.cc:536-550). Returns None if no
    /// matching record.
    pub fn find_record_vn(&self, vn: &Arc<RwLock<Varnode>>) -> Option<&PreferSplitRecord> {
        let vn_rg = vn.read().unwrap();
        self.find_record(vn_rg.space(), vn_rg.get_size() as u32, vn_rg.get_offset())
    }

    // Ghidra: prefersplit.cc:536 PreferSplitManager::findRecord
    /// Find the split record by storage details. Binary-searches the sorted
    /// records vector. Faithful to the `lower_bound` in `findRecord`.
    pub fn find_record(
        &self,
        space: AddressSpace,
        size: u32,
        offset: u64,
    ) -> Option<&PreferSplitRecord> {
        let mut lo = 0usize;
        let mut hi = self.records.len();
        let search_space = space.space_id();
        while lo < hi {
            let mid = (lo + hi) / 2;
            let rec = &self.records[mid];
            let rec_space = rec.storage_space.space_id();
            if rec_space < search_space
                || (rec_space == search_space && rec.storage_size > size)
                || (rec_space == search_space
                    && rec.storage_size == size
                    && rec.storage_offset < offset)
            {
                lo = mid + 1;
            } else if rec_space > search_space
                || (rec_space == search_space && rec.storage_size < size)
                || (rec_space == search_space
                    && rec.storage_size == size
                    && rec.storage_offset > offset)
            {
                hi = mid;
            } else {
                return Some(rec);
            }
        }
        None
    }

    // ---- Private helpers (faithful port of prefersplit.cc) ----

    // Ghidra: prefersplit.cc:33 PreferSplitManager::fillinInstance
    /// Define the varnode pieces of `inst`. Faithful to `fillinInstance`
    /// (prefersplit.cc:33-67). Computes hi/lo pieces based on endianness and,
    /// for constants, splits the constant value.
    fn fillin_instance(
        &mut self,
        fd: &mut Funcdata,
        inst: &mut SplitInstance,
        bigendian: bool,
        sethi: bool,
        setlo: bool,
    ) {
        let (losize, hisize, vn_offset, is_const, const_val) = {
            let vn_rg = inst.vn.read().unwrap();
            let vn_size = vn_rg.get_size() as i32;
            let losize = if bigendian {
                vn_size - inst.splitoffset
            } else {
                inst.splitoffset
            };
            let hisize = vn_size - losize;
            (
                losize,
                hisize,
                vn_rg.get_offset(),
                vn_rg.is_constant(),
                vn_rg.get_offset(),
            )
        };

        if is_const {
            let loval = const_val & calc_mask(losize as usize);
            let hival = (const_val >> (8 * losize as u64)) & calc_mask(hisize as usize);
            if setlo && inst.lo.is_none() {
                inst.lo = Some(fd.new_constant(losize as usize, loval));
            }
            if sethi && inst.hi.is_none() {
                inst.hi = Some(fd.new_constant(hisize as usize, hival));
            }
        } else if bigendian {
            if setlo && inst.lo.is_none() {
                let vn_arc = fd.vbank.create_with_space(
                    losize as usize,
                    inst.vn.read().unwrap().space(),
                    vn_offset + inst.splitoffset as u64,
                );
                inst.lo = Some(vn_arc);
            }
            if sethi && inst.hi.is_none() {
                let sp = inst.vn.read().unwrap().space();
                let vn_arc = fd
                    .vbank
                    .create_with_space(hisize as usize, sp, vn_offset);
                inst.hi = Some(vn_arc);
            }
        } else {
            if setlo && inst.lo.is_none() {
                let sp = inst.vn.read().unwrap().space();
                let vn_arc = fd
                    .vbank
                    .create_with_space(losize as usize, sp, vn_offset);
                inst.lo = Some(vn_arc);
            }
            if sethi && inst.hi.is_none() {
                let sp = inst.vn.read().unwrap().space();
                let vn_arc = fd.vbank.create_with_space(
                    hisize as usize,
                    sp,
                    vn_offset + inst.splitoffset as u64,
                );
                inst.hi = Some(vn_arc);
            }
        }
    }

    // Ghidra: prefersplit.cc:69 PreferSplitManager::createCopyOps
    /// Create COPY ops based on input `ininst` and output `outinst` to replace
    /// `op`. Faithful to `createCopyOps` (prefersplit.cc:69-87). Pushes the two
    /// new COPY ops onto `tempsplits`.
    fn create_copy_ops(
        &mut self,
        fd: &mut Funcdata,
        ininst: &SplitInstance,
        outinst: &SplitInstance,
        op: &PcodeOpRef,
        _istemp: bool,
    ) {
        let addr = op.0.read().unwrap().get_addr();

        let hiop = fd.new_op(1, addr);
        let loop_ = fd.new_op(1, addr);
        fd.op_set_opcode(&hiop, OpCode::CPUI_COPY);
        fd.op_set_opcode(&loop_, OpCode::CPUI_COPY);

        // Insert new COPYs immediately after the original operation.
        fd.op_insert_after(&loop_, op);
        fd.op_insert_after(&hiop, op);

        // Unset input so we can reassign free inputs to new ops.
        fd.op_unset_input(op, 0);

        // Outputs are the pieces of the original.
        if let Some(hi) = &outinst.hi {
            fd.op_set_output(&hiop, hi.clone());
        }
        if let Some(lo) = &outinst.lo {
            fd.op_set_output(&loop_, lo.clone());
        }
        // Inputs come from the (already-split) input instance.
        if let Some(hi) = &ininst.hi {
            fd.op_set_input(&hiop, hi.clone(), 0);
        }
        if let Some(lo) = &ininst.lo {
            fd.op_set_input(&loop_, lo.clone(), 0);
        }
        self.tempsplits.push(hiop);
        self.tempsplits.push(loop_);
    }

    // Ghidra: prefersplit.cc:89 PreferSplitManager::testDefiningCopy
    /// Check that `inst` defined by `def` (a COPY) is really splittable.
    /// Faithful to `testDefiningCopy` (prefersplit.cc:89-105). Returns
    /// `Some(istemp)` on success, `None` on failure.
    fn test_defining_copy(&self, inst: &SplitInstance, def: &PcodeOpRef) -> Option<bool> {
        let invn = def.0.read().unwrap().get_in(0).cloned()?;
        let invn_rg = invn.read().unwrap();
        if invn_rg.is_constant() {
            return Some(false);
        }
        let istemp = if invn_rg.space() != AddressSpace::Unique {
            // IPTR_INTERNAL check. Non-temporary inputs must match a record
            // with the same splitoffset and be free.
            let inrec = self.find_record_vn(&invn)?;
            if inrec.splitoffset != inst.splitoffset {
                return None;
            }
            if !invn_rg.is_free() {
                return None;
            }
            false
        } else {
            true
        };
        Some(istemp)
    }

    // Ghidra: prefersplit.cc:107 PreferSplitManager::splitDefiningCopy
    /// Do split of a prefered split varnode that is defined by a COPY.
    /// Faithful to `splitDefiningCopy` (prefersplit.cc:107-116).
    fn split_defining_copy(
        &mut self,
        fd: &mut Funcdata,
        inst: &mut SplitInstance,
        def: &PcodeOpRef,
        istemp: bool,
    ) {
        let invn = match def.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return,
        };
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let mut ininst = SplitInstance::new(invn, inst.splitoffset);
        self.fillin_instance(fd, inst, bigendian, true, true);
        self.fillin_instance(fd, &mut ininst, bigendian, true, true);
        self.create_copy_ops(fd, &ininst, inst, def, istemp);
    }

    // Ghidra: prefersplit.cc:118 PreferSplitManager::testReadingCopy
    /// Check that `inst` read by `readop` (a COPY) is really splittable.
    /// Faithful to `testReadingCopy` (prefersplit.cc:118-131).
    fn test_reading_copy(&self, inst: &SplitInstance, readop: &PcodeOpRef) -> Option<bool> {
        let outvn = readop.0.read().unwrap().get_out().cloned()?;
        let outvn_rg = outvn.read().unwrap();
        let istemp = if outvn_rg.space() != AddressSpace::Unique {
            let outrec = self.find_record_vn(&outvn)?;
            if outrec.splitoffset != inst.splitoffset {
                return None;
            }
            false
        } else {
            true
        };
        Some(istemp)
    }

    // Ghidra: prefersplit.cc:133 PreferSplitManager::splitReadingCopy
    /// Do split of varnode that is read by a COPY. Faithful to
    /// `splitReadingCopy` (prefersplit.cc:133-142).
    fn split_reading_copy(
        &mut self,
        fd: &mut Funcdata,
        inst: &mut SplitInstance,
        readop: &PcodeOpRef,
        istemp: bool,
    ) {
        let outvn = match readop.0.read().unwrap().get_out().cloned() {
            Some(v) => v,
            None => return,
        };
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let mut outinst = SplitInstance::new(outvn, inst.splitoffset);
        self.fillin_instance(fd, inst, bigendian, true, true);
        self.fillin_instance(fd, &mut outinst, bigendian, true, true);
        self.create_copy_ops(fd, inst, &outinst, readop, istemp);
    }

    // Ghidra: prefersplit.cc:144 PreferSplitManager::testZext
    /// Check that `inst` defined by ZEXT is really splittable. Faithful to
    /// `testZext` (prefersplit.cc:144-158).
    fn test_zext(&self, inst: &SplitInstance, op: &PcodeOpRef) -> bool {
        let invn = match op.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return false,
        };
        let invn_rg = invn.read().unwrap();
        if invn_rg.is_constant() {
            return true;
        }
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let vn_size = inst.vn.read().unwrap().get_size() as i32;
        let losize = if bigendian {
            vn_size - inst.splitoffset
        } else {
            inst.splitoffset
        };
        invn_rg.get_size() as i32 == losize
    }

    // Ghidra: prefersplit.cc:160 PreferSplitManager::splitZext
    /// Split an INT_ZEXT-defined varnode. Faithful to `splitZext`
    /// (prefersplit.cc:160-188). The low piece is the ZEXT input (or the
    /// constant split); the high piece is a constant 0 (or the high bits of
    /// the constant).
    fn split_zext(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance, op: &PcodeOpRef) {
        let invn = match op.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return,
        };
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let vn_size = inst.vn.read().unwrap().get_size() as i32;
        let (losize, hisize) = if bigendian {
            (vn_size - inst.splitoffset, inst.splitoffset)
        } else {
            (inst.splitoffset, vn_size - inst.splitoffset)
        };

        let (is_const, const_val) = {
            let r = invn.read().unwrap();
            (r.is_constant(), r.get_offset())
        };

        let mut ininst = SplitInstance::new(invn.clone(), inst.splitoffset);
        if is_const {
            let loval = const_val & calc_mask(losize as usize);
            let hival = (const_val >> (8 * losize as u64)) & calc_mask(hisize as usize);
            ininst.lo = Some(fd.new_constant(losize as usize, loval));
            ininst.hi = Some(fd.new_constant(hisize as usize, hival));
        } else {
            ininst.lo = Some(invn.clone());
            ininst.hi = Some(fd.new_constant(hisize as usize, 0));
        }

        self.fillin_instance(fd, inst, bigendian, true, true);
        self.create_copy_ops(fd, &ininst, inst, op, false);
    }

    // Ghidra: prefersplit.cc:190 PreferSplitManager::testPiece
    /// Check that `inst` defined by PIECE is really splittable. Faithful to
    /// `testPiece` (prefersplit.cc:190-200).
    fn test_piece(&self, inst: &SplitInstance, op: &PcodeOpRef) -> bool {
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let op_rg = op.0.read().unwrap();
        if bigendian {
            if let Some(in0) = op_rg.get_in(0) {
                if in0.read().unwrap().get_size() as i32 != inst.splitoffset {
                    return false;
                }
            } else {
                return false;
            }
        } else if let Some(in1) = op_rg.get_in(1) {
            if in1.read().unwrap().get_size() as i32 != inst.splitoffset {
                return false;
            }
        } else {
            return false;
        }
        true
    }

    // Ghidra: prefersplit.cc:202 PreferSplitManager::splitPiece
    /// Split a PIECE-defined varnode. Faithful to `splitPiece`
    /// (prefersplit.cc:202-227). The PIECE's two inputs already are the hi/lo
    /// pieces; we create COPY ops to forward them to the split outputs.
    fn split_piece(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance, op: &PcodeOpRef) {
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        let loin = match op.0.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return,
        };
        let hiin = match op.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return,
        };

        self.fillin_instance(fd, inst, bigendian, true, true);
        let addr = op.0.read().unwrap().get_addr();
        let hiop = fd.new_op(1, addr);
        let loop_ = fd.new_op(1, addr);
        fd.op_set_opcode(&hiop, OpCode::CPUI_COPY);
        fd.op_set_opcode(&loop_, OpCode::CPUI_COPY);
        if let Some(hi) = &inst.hi {
            fd.op_set_output(&hiop, hi.clone());
        }
        if let Some(lo) = &inst.lo {
            fd.op_set_output(&loop_, lo.clone());
        }
        fd.op_insert_after(&loop_, op);
        fd.op_insert_after(&hiop, op);
        fd.op_unset_input(op, 0);
        fd.op_unset_input(op, 1);

        // If the input is a constant, duplicate it (Ghidra clones constants so
        // each op has its own Varnode).
        let hiin_use = {
            let r = hiin.read().unwrap();
            if r.is_constant() {
                fd.new_constant(r.get_size(), r.get_offset())
            } else {
                hiin.clone()
            }
        };
        fd.op_set_input(&hiop, hiin_use, 0);
        let loin_use = {
            let r = loin.read().unwrap();
            if r.is_constant() {
                fd.new_constant(r.get_size(), r.get_offset())
            } else {
                loin.clone()
            }
        };
        fd.op_set_input(&loop_, loin_use, 0);
    }

    // Ghidra: prefersplit.cc:229 PreferSplitManager::testSubpiece
    /// Check that `inst` read by SUBPIECE is really splittable. Faithful to
    /// `testSubpiece` (prefersplit.cc:229-246).
    fn test_subpiece(&self, inst: &SplitInstance, op: &PcodeOpRef) -> bool {
        let vn_size = inst.vn.read().unwrap().get_size() as i32;
        let outvn_size = match op.0.read().unwrap().get_out() {
            Some(v) => v.read().unwrap().get_size() as i32,
            None => return false,
        };
        let suboff = match op.0.read().unwrap().get_in(1) {
            Some(c) => c.read().unwrap().get_offset() as i32,
            None => return false,
        };
        if suboff == 0 {
            if vn_size - inst.splitoffset != outvn_size {
                return false;
            }
        } else {
            if vn_size - suboff != inst.splitoffset {
                return false;
            }
            if outvn_size != inst.splitoffset {
                return false;
            }
        }
        true
    }

    // Ghidra: prefersplit.cc:248 PreferSplitManager::splitSubpiece
    /// Rewrite a SUBPIECE that extracts a logical piece into a COPY. Faithful
    /// to `splitSubpiece` (prefersplit.cc:248-263).
    fn split_subpiece(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance, op: &PcodeOpRef) {
        let suboff = op
            .0
            .read()
            .unwrap()
            .get_in(1)
            .map(|c| c.read().unwrap().get_offset() as i32)
            .unwrap_or(0);
        let grabbinglo = suboff == 0;
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        self.fillin_instance(fd, inst, bigendian, !grabbinglo, grabbinglo);
        fd.op_set_opcode(op, OpCode::CPUI_COPY);
        fd.op_remove_input(op, 1);
        let invn = if grabbinglo {
            inst.lo.clone()
        } else {
            inst.hi.clone()
        };
        if let Some(vn) = invn {
            fd.op_set_input(op, vn, 0);
        }
    }

    // Ghidra: prefersplit.cc:265 PreferSplitManager::testLoad
    /// Test if a LOAD-defined split is possible. Faithful to `testLoad`
    /// (prefersplit.cc:265-269), which always returns true.
    fn test_load(&self, _inst: &SplitInstance, _op: &PcodeOpRef) -> bool {
        true
    }

    // Ghidra: prefersplit.cc:271 PreferSplitManager::splitLoad
    /// Split a LOAD that defines the varnode into two LOADs. Faithful to
    /// `splitLoad` (prefersplit.cc:271-314).
    fn split_load(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance, op: &PcodeOpRef) {
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        self.fillin_instance(fd, inst, bigendian, true, true);

        let addr = op.0.read().unwrap().get_addr();
        let ptrvn = match op.0.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return,
        };
        let spaceid_vn = match op.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return,
        };

        let hiop = fd.new_op(2, addr);
        let loop_ = fd.new_op(2, addr);
        let addop = fd.new_op(2, addr);
        fd.op_set_opcode(&hiop, OpCode::CPUI_LOAD);
        fd.op_set_opcode(&loop_, OpCode::CPUI_LOAD);
        fd.op_set_opcode(&addop, OpCode::CPUI_INT_ADD);

        fd.op_insert_after(&loop_, op);
        fd.op_insert_after(&hiop, op);
        fd.op_insert_after(&addop, op);
        fd.op_unset_input(op, 1); // Free up ptrvn

        let ptrvn_size = ptrvn.read().unwrap().get_size();
        let addvn = fd.new_unique_out(ptrvn_size, &addop);
        fd.op_set_input(&addop, ptrvn.clone(), 0);
        let off_const = fd.new_constant(ptrvn_size, inst.splitoffset as u64);
        fd.op_set_input(&addop, off_const, 1);

        if let Some(hi) = &inst.hi {
            fd.op_set_output(&hiop, hi.clone());
        }
        if let Some(lo) = &inst.lo {
            fd.op_set_output(&loop_, lo.clone());
        }

        // Duplicate the spaceid constant into the two new LOADs.
        let (sid_size, sid_off) = {
            let r = spaceid_vn.read().unwrap();
            (r.get_size(), r.get_offset())
        };
        let sid_hi = fd.new_constant(sid_size, sid_off);
        fd.op_set_input(&hiop, sid_hi, 0);
        let sid_lo = fd.new_constant(sid_size, sid_off);
        fd.op_set_input(&loop_, sid_lo, 0);

        // Don't read a free varnode twice: re-create it if free.
        let ptrvn_use = recreate_if_free(fd, &ptrvn);

        if bigendian {
            fd.op_set_input(&hiop, ptrvn_use.clone(), 1);
            fd.op_set_input(&loop_, addvn, 1);
        } else {
            fd.op_set_input(&hiop, addvn, 1);
            fd.op_set_input(&loop_, ptrvn_use, 1);
        }
    }

    // Ghidra: prefersplit.cc:316 PreferSplitManager::testStore
    /// Test if a STORE reading the split varnode is splittable. Faithful to
    /// `testStore` (prefersplit.cc:316-320), which always returns true.
    fn test_store(&self, _inst: &SplitInstance, _op: &PcodeOpRef) -> bool {
        true
    }

    // Ghidra: prefersplit.cc:322 PreferSplitManager::splitStore
    /// Split a STORE into two STOREs, one for each piece. Faithful to
    /// `splitStore` (prefersplit.cc:322-365).
    fn split_store(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance, op: &PcodeOpRef) {
        let bigendian = inst.vn.read().unwrap().space().is_big_endian();
        self.fillin_instance(fd, inst, bigendian, true, true);

        let addr = op.0.read().unwrap().get_addr();
        let ptrvn = match op.0.read().unwrap().get_in(1).cloned() {
            Some(v) => v,
            None => return,
        };
        let spaceid_vn = match op.0.read().unwrap().get_in(0).cloned() {
            Some(v) => v,
            None => return,
        };

        let hiop = fd.new_op(3, addr);
        let loop_ = fd.new_op(3, addr);
        let addop = fd.new_op(2, addr);
        fd.op_set_opcode(&hiop, OpCode::CPUI_STORE);
        fd.op_set_opcode(&loop_, OpCode::CPUI_STORE);
        fd.op_set_opcode(&addop, OpCode::CPUI_INT_ADD);

        fd.op_insert_after(&loop_, op);
        fd.op_insert_after(&hiop, op);
        fd.op_insert_after(&addop, op);
        fd.op_unset_input(op, 1); // Free up ptrvn
        fd.op_unset_input(op, 2); // Free up inst

        let ptrvn_size = ptrvn.read().unwrap().get_size();
        let addvn = fd.new_unique_out(ptrvn_size, &addop);
        fd.op_set_input(&addop, ptrvn.clone(), 0);
        let off_const = fd.new_constant(ptrvn_size, inst.splitoffset as u64);
        fd.op_set_input(&addop, off_const, 1);

        if let Some(hi) = &inst.hi {
            fd.op_set_input(&hiop, hi.clone(), 2);
        }
        if let Some(lo) = &inst.lo {
            fd.op_set_input(&loop_, lo.clone(), 2);
        }

        let (sid_size, sid_off) = {
            let r = spaceid_vn.read().unwrap();
            (r.get_size(), r.get_offset())
        };
        let sid_hi = fd.new_constant(sid_size, sid_off);
        fd.op_set_input(&hiop, sid_hi, 0);
        let sid_lo = fd.new_constant(sid_size, sid_off);
        fd.op_set_input(&loop_, sid_lo, 0);

        let ptr_use = recreate_if_free(fd, &ptrvn);
        if bigendian {
            fd.op_set_input(&hiop, ptr_use.clone(), 1);
            fd.op_set_input(&loop_, addvn, 1);
        } else {
            fd.op_set_input(&hiop, addvn, 1);
            fd.op_set_input(&loop_, ptr_use, 1);
        }
    }

    // Ghidra: prefersplit.cc:367 PreferSplitManager::splitVarnode
    /// Test if `inst` can be readily split, and if so, do the split. Faithful
    /// to `splitVarnode` (prefersplit.cc:367-428). Returns true if split.
    fn split_varnode(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance) -> bool {
        let (is_written, has_no_descend) = {
            let vn_rg = inst.vn.read().unwrap();
            (vn_rg.is_written(), vn_rg.has_no_descend())
        };

        if is_written {
            if !has_no_descend {
                return false; // Already linked in
            }
            let def = match inst.vn.read().unwrap().get_def() {
                Some(d) => PcodeOpRef(d),
                None => return false,
            };
            let code = def.0.read().unwrap().opcode;
            let destroy_op = match code {
                OpCode::CPUI_COPY => {
                    let istemp = match self.test_defining_copy(inst, &def) {
                        Some(t) => t,
                        None => return false,
                    };
                    self.split_defining_copy(fd, inst, &def, istemp);
                    true
                }
                OpCode::CPUI_PIECE => {
                    if !self.test_piece(inst, &def) {
                        return false;
                    }
                    self.split_piece(fd, inst, &def);
                    true
                }
                OpCode::CPUI_LOAD => {
                    if !self.test_load(inst, &def) {
                        return false;
                    }
                    self.split_load(fd, inst, &def);
                    true
                }
                OpCode::CPUI_INT_ZEXT => {
                    if !self.test_zext(inst, &def) {
                        return false;
                    }
                    self.split_zext(fd, inst, &def);
                    true
                }
                _ => return false,
            };
            if destroy_op {
                fd.op_destroy(&def);
            }
            true
        } else {
            // Not written: must be free with a single descendant (loneDescend).
            if !inst.vn.read().unwrap().is_free() {
                return false;
            }
            let op = match inst.vn.read().unwrap().lone_descend() {
                Some(o) => PcodeOpRef(o),
                None => return false,
            };
            let code = op.0.read().unwrap().opcode;
            let destroy_op = match code {
                OpCode::CPUI_COPY => {
                    let istemp = match self.test_reading_copy(inst, &op) {
                        Some(t) => t,
                        None => return false,
                    };
                    self.split_reading_copy(fd, inst, &op, istemp);
                    true
                }
                OpCode::CPUI_SUBPIECE => {
                    if !self.test_subpiece(inst, &op) {
                        return false;
                    }
                    self.split_subpiece(fd, inst, &op);
                    return true; // Do not destroy op; it has been transformed.
                }
                OpCode::CPUI_STORE => {
                    if !self.test_store(inst, &op) {
                        return false;
                    }
                    self.split_store(fd, inst, &op);
                    true
                }
                _ => return false,
            };
            if destroy_op {
                fd.op_destroy(&op);
            }
            true
        }
    }

    // Ghidra: prefersplit.cc:430 PreferSplitManager::splitRecord
    /// Apply a single split record. Faithful to `splitRecord`
    /// (prefersplit.cc:430-449). Iterates over all varnodes at the record's
    /// storage location, splitting each one. Ghidra re-iterates after each
    /// successful split; Rugra loops until no matches remain.
    fn split_record(&mut self, fd: &mut Funcdata, rec: &PreferSplitRecord) {
        let addr = Address::new(rec.storage_offset);
        let size = rec.storage_size as usize;

        loop {
            let matches: Vec<Arc<RwLock<Varnode>>> = {
                fd.vbank
                    .loc_tree
                    .iter()
                    .filter(|v| {
                        let r = v.0.read().unwrap();
                        r.get_size() == size && r.get_offset() == addr.as_u64()
                    })
                    .map(|v| v.0.clone())
                    .collect()
            };
            if matches.is_empty() {
                break;
            }
            let mut any_split = false;
            for vn in matches {
                let mut inst = SplitInstance::new(vn, rec.splitoffset);
                if self.split_varnode(fd, &mut inst) {
                    any_split = true;
                }
            }
            if !any_split {
                break;
            }
        }
    }

    // Ghidra: prefersplit.cc:451 PreferSplitManager::testTemporary
    /// Test whether a temporary (defined via PIECE/LOAD/ZEXT and read via
    /// SUBPIECE/STORE) can be split as a unit. Faithful to `testTemporary`
    /// (prefersplit.cc:451-491).
    fn test_temporary(&self, inst: &SplitInstance) -> bool {
        let def = match inst.vn.read().unwrap().get_def() {
            Some(d) => PcodeOpRef(d),
            None => return false,
        };
        let code = def.0.read().unwrap().opcode;
        match code {
            OpCode::CPUI_PIECE => {
                if !self.test_piece(inst, &def) {
                    return false;
                }
            }
            OpCode::CPUI_LOAD => {
                if !self.test_load(inst, &def) {
                    return false;
                }
            }
            OpCode::CPUI_INT_ZEXT => {
                if !self.test_zext(inst, &def) {
                    return false;
                }
            }
            _ => return false,
        }
        // Each descendant must be a SUBPIECE or STORE that passes its test.
        let descends: Vec<PcodeOpRef> = inst
            .vn
            .read()
            .unwrap()
            .descend_iter()
            .map(PcodeOpRef)
            .collect();
        for readop in &descends {
            let rc = readop.0.read().unwrap().opcode;
            match rc {
                OpCode::CPUI_SUBPIECE => {
                    if !self.test_subpiece(inst, readop) {
                        return false;
                    }
                }
                OpCode::CPUI_STORE => {
                    if !self.test_store(inst, readop) {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    // Ghidra: prefersplit.cc:493 PreferSplitManager::splitTemporary
    /// Split a temporary varnode. Faithful to `splitTemporary`
    /// (prefersplit.cc:493-527). Splits the defining op, then each reader.
    fn split_temporary(&mut self, fd: &mut Funcdata, inst: &mut SplitInstance) {
        let def = match inst.vn.read().unwrap().get_def() {
            Some(d) => PcodeOpRef(d),
            None => return,
        };
        let code = def.0.read().unwrap().opcode;
        match code {
            OpCode::CPUI_PIECE => self.split_piece(fd, inst, &def),
            OpCode::CPUI_LOAD => self.split_load(fd, inst, &def),
            OpCode::CPUI_INT_ZEXT => self.split_zext(fd, inst, &def),
            _ => {}
        }

        // Process each descendant. Re-read the descend list each iteration
        // because split_subpiece/split_store may mutate it.
        loop {
            let readop = match inst.vn.read().unwrap().descend_iter().next() {
                Some(o) => PcodeOpRef(o),
                None => break,
            };
            let rc = readop.0.read().unwrap().opcode;
            match rc {
                OpCode::CPUI_SUBPIECE => self.split_subpiece(fd, inst, &readop),
                OpCode::CPUI_STORE => {
                    self.split_store(fd, inst, &readop);
                    fd.op_destroy(&readop);
                }
                _ => break,
            }
        }
        fd.op_destroy(&def);
    }

    // Ghidra: prefersplit.cc:558 PreferSplitManager::split
    /// The main split entry point. Faithful to `split`
    /// (prefersplit.cc:558-563). Applies every split record in turn.
    pub fn split(&mut self, fd: &mut Funcdata) {
        self.tempsplits.clear();
        let records: Vec<PreferSplitRecord> = self.records.clone();
        for rec in &records {
            self.split_record(fd, rec);
        }
    }

    // Ghidra: prefersplit.cc:565 PreferSplitManager::splitAdditional
    /// Split additional temporaries connected to the COPYs created by `split`.
    /// Faithful to `splitAdditional` (prefersplit.cc:565-629).
    pub fn split_additional(&mut self, fd: &mut Funcdata) {

        // Gather candidate ops: SUBPIECEs feeding into the tempsplit COPYs, and
        // PIECEs fed by the tempsplit COPY outputs.
        let mut defops: Vec<PcodeOpRef> = Vec::new();
        for op in self.tempsplits.clone() {
            if op.0.read().unwrap().is_dead() {
                continue;
            }
            // Look at the COPY's input.
            if let Some(invn) = op.0.read().unwrap().get_in(0).cloned() {
                let invn_rg = invn.read().unwrap();
                if invn_rg.is_written() {
                    let candidate = invn_rg.get_def().map(PcodeOpRef);
                    drop(invn_rg);
                    if let Some(defop) = candidate {
                        let (is_subpiece, in0vn) = {
                            let r = defop.0.read().unwrap();
                            (
                                r.opcode == OpCode::CPUI_SUBPIECE,
                                r.get_in(0).cloned(),
                            )
                        };
                        if is_subpiece {
                            if let Some(in0vn) = in0vn {
                                if in0vn.read().unwrap().space() == AddressSpace::Unique {
                                    defops.push(defop);
                                }
                            }
                        }
                    }
                }
            }
            // Look at the COPY's output descendants.
            if let Some(outvn) = op.0.read().unwrap().get_out().cloned() {
                let descends: Vec<PcodeOpRef> = outvn
                    .read()
                    .unwrap()
                    .descend_iter()
                    .map(PcodeOpRef)
                    .collect();
                for defop in descends {
                    let (is_piece, outvn2) = {
                        let r = defop.0.read().unwrap();
                        (r.opcode == OpCode::CPUI_PIECE, r.get_out().cloned())
                    };
                    if is_piece {
                        if let Some(outvn2) = outvn2 {
                            if outvn2.read().unwrap().space() == AddressSpace::Unique {
                                defops.push(defop);
                            }
                        }
                    }
                }
            }
        }

        for op in defops {
            if op.0.read().unwrap().is_dead() {
                continue;
            }
            let code = op.0.read().unwrap().opcode;
            if code == OpCode::CPUI_PIECE {
                let (vn, splitoff) = {
                    let op_rg = op.0.read().unwrap();
                    let outvn = match op_rg.get_out() {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    let bigendian = outvn.read().unwrap().space().is_big_endian();
                    let splitoff = if bigendian {
                        op_rg
                            .get_in(0)
                            .map(|v| v.read().unwrap().get_size() as i32)
                            .unwrap_or(0)
                    } else {
                        op_rg
                            .get_in(1)
                            .map(|v| v.read().unwrap().get_size() as i32)
                            .unwrap_or(0)
                    };
                    (outvn, splitoff)
                };
                let mut inst = SplitInstance::new(vn, splitoff);
                if self.test_temporary(&inst) {
                    self.split_temporary(fd, &mut inst);
                }
            } else if code == OpCode::CPUI_SUBPIECE {
                let (vn, splitoff) = {
                    let op_rg = op.0.read().unwrap();
                    let invn = match op_rg.get_in(0) {
                        Some(v) => v.clone(),
                        None => continue,
                    };
                    let suboff = op_rg
                        .get_in(1)
                        .map(|c| c.read().unwrap().get_offset() as i32)
                        .unwrap_or(0);
                    let bigendian = invn.read().unwrap().space().is_big_endian();
                    let vn_size = invn.read().unwrap().get_size() as i32;
                    let outsize = op_rg
                        .get_out()
                        .map(|v| v.read().unwrap().get_size() as i32)
                        .unwrap_or(0);
                    let splitoff = if bigendian {
                        if suboff == 0 {
                            vn_size - outsize
                        } else {
                            vn_size - suboff
                        }
                    } else if suboff == 0 {
                        outsize
                    } else {
                        suboff
                    };
                    (invn, splitoff)
                };
                let mut inst = SplitInstance::new(vn, splitoff);
                if self.test_temporary(&inst) {
                    self.split_temporary(fd, &mut inst);
                }
            }
        }
    }
}

// Ghidra: prefersplit.hh:33 PreferSplitManager::recreateIfFree
/// Helper that re-creates a pointer varnode if it is free, mirroring Ghidra's
/// `if (ptrvn->isFree()) ptrvn = data->newVarnode(...)` in splitLoad/splitStore.
/// Rugra's `VarnodeBank::create_with_space` produces a fresh varnode at the
/// same (space, offset, size); for non-free varnodes the original is returned.
fn recreate_if_free(
    fd: &mut Funcdata,
    ptrvn: &Arc<RwLock<Varnode>>,
) -> Arc<RwLock<Varnode>> {
    let (is_free, size, space, offset) = {
        let r = ptrvn.read().unwrap();
        (r.is_free(), r.get_size(), r.space(), r.get_offset())
    };
    if is_free {
        fd.vbank.create_with_space(size, space, offset)
    } else {
        ptrvn.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(offset: u64, space: AddressSpace, size: u32, split: i32) -> PreferSplitRecord {
        PreferSplitRecord::new(offset, space, size, split)
    }

    #[test]
    fn test_prefer_split_record_construction() {
        let r = make_record(0x100, AddressSpace::Register, 4, 2);
        assert_eq!(r.storage_offset, 0x100);
        assert_eq!(r.storage_space, AddressSpace::Register);
        assert_eq!(r.storage_size, 4);
        assert_eq!(r.splitoffset, 2);
    }

    #[test]
    fn test_prefer_split_record_ordering() {
        let r1 = make_record(0x100, AddressSpace::Register, 8, 4);
        let r2 = make_record(0x200, AddressSpace::Register, 4, 2);
        // Bigger sizes come first.
        assert!(r1.less_than(&r2));
        assert!(!r2.less_than(&r1));
    }

    #[test]
    fn test_prefer_split_record_ordering_offset() {
        let r1 = make_record(0x100, AddressSpace::Register, 4, 2);
        let r2 = make_record(0x200, AddressSpace::Register, 4, 2);
        assert!(r1.less_than(&r2));
    }

    #[test]
    fn test_initialize_sorts() {
        let mut records = vec![
            make_record(0x300, AddressSpace::Register, 4, 2),
            make_record(0x100, AddressSpace::Register, 8, 4),
            make_record(0x200, AddressSpace::Register, 4, 2),
        ];
        initialize(&mut records);
        // After sort: 8-byte at 0x100 first (bigger size), then 4-byte at 0x200,
        // then 4-byte at 0x300.
        assert_eq!(records[0].storage_offset, 0x100);
        assert_eq!(records[0].storage_size, 8);
        assert_eq!(records[1].storage_offset, 0x200);
        assert_eq!(records[2].storage_offset, 0x300);
    }

    #[test]
    fn test_find_record_exact() {
        let mut mgr = PreferSplitManager::new();
        mgr.set_records(vec![
            make_record(0x100, AddressSpace::Register, 8, 4),
            make_record(0x200, AddressSpace::Register, 4, 2),
        ]);
        let rec = mgr.find_record(AddressSpace::Register, 4, 0x200);
        assert!(rec.is_some());
        assert_eq!(rec.unwrap().splitoffset, 2);
    }

    #[test]
    fn test_find_record_miss() {
        let mut mgr = PreferSplitManager::new();
        mgr.set_records(vec![make_record(0x100, AddressSpace::Register, 8, 4)]);
        let rec = mgr.find_record(AddressSpace::Register, 4, 0x200);
        assert!(rec.is_none());
    }

    #[test]
    fn test_find_record_wrong_space() {
        let mut mgr = PreferSplitManager::new();
        mgr.set_records(vec![make_record(0x100, AddressSpace::Register, 8, 4)]);
        let rec = mgr.find_record(AddressSpace::Ram, 8, 0x100);
        assert!(rec.is_none());
    }

    #[test]
    fn test_set_records_sorts() {
        let mut mgr = PreferSplitManager::new();
        mgr.set_records(vec![
            make_record(0x300, AddressSpace::Register, 4, 2),
            make_record(0x100, AddressSpace::Register, 8, 4),
        ]);
        assert_eq!(mgr.records()[0].storage_size, 8);
        assert_eq!(mgr.records()[1].storage_size, 4);
        assert_eq!(mgr.num_records(), 2);
    }
}
