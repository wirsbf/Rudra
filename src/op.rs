//! P-code operation structures
//!
//! Corresponds to Ghidra's `op.hh`

use crate::address::{Address, SeqNum};
use crate::arena::{Arena, ArenaId, IdList, Linked, OpId, SeqNumKey};
use crate::opcodes::OpCode;
use crate::varnode::Varnode;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, Weak};

use crate::block::FlowBlock;

// Forward declarations/Stubs
pub mod stubs {
// use super::*;
    #[derive(Debug)]
    pub struct TypeOp;
}



/// Flags for PcodeOp properties (pcodeop_flags in Ghidra)
pub mod pcodeop_flags {
    pub const STARTBASIC: u32 = 1 << 0;
    pub const BRANCH: u32 = 1 << 1;
    pub const CALL: u32 = 1 << 2;
    pub const RETURNS: u32 = 1 << 3;
    pub const NOCOLLAPSE: u32 = 1 << 4;
    pub const DEAD: u32 = 1 << 5;
    pub const MARKER: u32 = 1 << 6;
    pub const BOOLOUTPUT: u32 = 1 << 7;
    pub const BOOLEAN_FLIP: u32 = 1 << 8;
    pub const FALLTHRU_TRUE: u32 = 1 << 9;
    pub const INDIRECT_SOURCE: u32 = 1 << 10;
    pub const CODEREF: u32 = 1 << 11;
    pub const STARTMARK: u32 = 1 << 12;
    pub const MARK: u32 = 1 << 13;
    pub const COMMUTATIVE: u32 = 1 << 14;
    pub const UNARY: u32 = 1 << 15;
    pub const BINARY: u32 = 1 << 16;
    pub const SPECIAL: u32 = 1 << 17;
    pub const TERNARY: u32 = 1 << 18;
    pub const RETURN_COPY: u32 = 1 << 19;
    pub const NONPRINTING: u32 = 1 << 20;
    pub const HALT: u32 = 1 << 21;
    pub const BADINSTRUCTION: u32 = 1 << 22;
    pub const UNIMPLEMENTED: u32 = 1 << 23;
    pub const NORETURN: u32 = 1 << 24;
    pub const MISSING: u32 = 1 << 25;
    pub const SPACEBASE_PTR: u32 = 1 << 26;
    pub const INDIRECT_CREATION: u32 = 1 << 27;
    pub const CALCULATED_BOOL: u32 = 1 << 28;
    pub const HAS_CALLSPEC: u32 = 1 << 29;
    pub const PTRFLOW: u32 = 1 << 30;
    pub const INDIRECT_STORE: u32 = 1 << 31;
}

/// PcodeOp additional flags (Ghidra `op.hh:108-120`). Stored in the
/// `addlflags: u32` field. These mirror Ghidra's bit values exactly.
pub mod op_addl_flags {
    /// special_prop (op.hh:109): "Does some special form of datatype
    /// propagation". Set by `Funcdata::replaceVolatile`
    /// (funcdata_varnode.cc:762) on a volatile read/write CALLOTHER whose
    /// original varnode was type-locked; read by
    /// `VolatileReadOp::getOutputLocal` (userop.cc:131) and
    /// `VolatileWriteOp::getInputLocal` (userop.cc:162).
    pub const SPECIAL_PROP: u32 = 0x1;
    pub const SPECIAL_PRINT: u32 = 0x2;
    pub const MODIFIED: u32 = 0x4;
    pub const WARNING: u32 = 0x8;
    pub const INCIDENTAL_COPY: u32 = 0x10;
    /// is_cpool_transformed (already used via 0x20 in mark_cpool_transformed).
    pub const IS_CPOOL_TRANSFORMED: u32 = 0x20;
    pub const STOP_TYPE_PROPAGATION: u32 = 0x40;
    pub const HOLD_OUTPUT: u32 = 0x80;
    pub const CONCAT_ROOT: u32 = 0x100;
    pub const NO_INDIRECT_COLLAPSE: u32 = 0x200;
    pub const STORE_UNMAPPED: u32 = 0x400;
}

pub mod branch_type {
    pub const NONE: u8 = 0;
    pub const BREAK: u8 = 1;
    pub const CONTINUE: u8 = 2;
    pub const GOTO: u8 = 3;
}

// Ghidra: typeop.hh:72 TypeOp::getFlags (opflags field, set per-ctor in typeop.cc)
/// Return the `opflags` value for `opc`, mirroring the constructor
/// `opflags = ...` assignments in Ghidra's `typeop.cc`. This is the
/// replacement for `TypeOp::getFlags()` which Rugra lacks (no TypeOp layer).
/// Faithful to typeop.cc constructor bodies (verified line-by-line).
pub fn opcode_flags(opc: OpCode) -> u32 {
    use pcodeop_flags::*;
    let binary = BINARY;
    let unary = UNARY;
    let ternary = TERNARY;
    let special = SPECIAL;
    let branch = BRANCH;
    let call = CALL;
    let coderef = CODEREF;
    let returns = RETURNS;
    let nocollapse = NOCOLLAPSE;
    let marker = MARKER;
    let booloutput = BOOLOUTPUT;
    let commutative = COMMUTATIVE;
    let has_callspec = HAS_CALLSPEC;
    let return_copy = RETURN_COPY;
    match opc {
        // typeop.cc:393 TypeOpCopy
        OpCode::CPUI_COPY => unary | nocollapse,
        // typeop.cc:436 TypeOpLoad
        OpCode::CPUI_LOAD => special | nocollapse,
        // typeop.cc:516 TypeOpStore
        OpCode::CPUI_STORE => special | nocollapse,
        // typeop.cc:586 TypeOpBranch
        OpCode::CPUI_BRANCH => special | branch | coderef | nocollapse,
        // typeop.cc:605 TypeOpCbranch
        OpCode::CPUI_CBRANCH => special | branch | coderef | nocollapse,
        // typeop.cc:649 TypeOpBranchind
        OpCode::CPUI_BRANCHIND => special | branch | nocollapse,
        // typeop.cc:663 TypeOpCall
        OpCode::CPUI_CALL => special | call | has_callspec | coderef | nocollapse,
        // typeop.cc:741 TypeOpCallind
        OpCode::CPUI_CALLIND => special | call | has_callspec | nocollapse,
        // typeop.cc:814 TypeOpCallother
        OpCode::CPUI_CALLOTHER => special | call | nocollapse,
        // typeop.cc:878 TypeOpReturn
        OpCode::CPUI_RETURN => special | returns | nocollapse | return_copy,
        // typeop.cc:927 TypeOpEqual
        OpCode::CPUI_INT_EQUAL => binary | booloutput | commutative,
        // typeop.cc:991 TypeOpNotEqual
        OpCode::CPUI_INT_NOTEQUAL => binary | booloutput | commutative,
        // typeop.cc:1018 TypeOpIntSless
        OpCode::CPUI_INT_SLESS => binary | booloutput,
        // typeop.cc:1044 TypeOpIntSlessEqual
        OpCode::CPUI_INT_SLESSEQUAL => binary | booloutput,
        // typeop.cc:1070 TypeOpIntLess
        OpCode::CPUI_INT_LESS => binary | booloutput,
        // typeop.cc:1094 TypeOpIntLessEqual
        OpCode::CPUI_INT_LESSEQUAL => binary | booloutput,
        // typeop.cc:1118 TypeOpIntZext
        OpCode::CPUI_INT_ZEXT => unary,
        // typeop.cc:1144 TypeOpIntSext
        OpCode::CPUI_INT_SEXT => unary,
        // typeop.cc:1170 TypeOpIntAdd
        OpCode::CPUI_INT_ADD => binary | commutative,
        // typeop.cc:1321 TypeOpIntSub
        OpCode::CPUI_INT_SUB => binary,
        // typeop.cc:1335 TypeOpIntCarry
        OpCode::CPUI_INT_CARRY => binary | commutative | booloutput,
        // typeop.cc:1351 TypeOpIntScarry
        OpCode::CPUI_INT_SCARRY => binary | commutative | booloutput,
        // typeop.cc:1367 TypeOpIntSborrow
        OpCode::CPUI_INT_SBORROW => binary | booloutput,
        // typeop.cc:1383 TypeOpInt2Comp
        OpCode::CPUI_INT_2COMP => unary,
        // typeop.cc:1397 TypeOpIntNegate
        OpCode::CPUI_INT_NEGATE => unary,
        // typeop.cc:1397 TypeOpIntXor
        OpCode::CPUI_INT_XOR => binary | commutative,
        // typeop.cc:1411 TypeOpIntAnd
        OpCode::CPUI_INT_AND => binary | commutative,
        // typeop.cc:1444 TypeOpIntOr
        OpCode::CPUI_INT_OR => binary | commutative,
        // typeop.cc:1505 TypeOpIntLeft
        OpCode::CPUI_INT_LEFT => binary,
        // typeop.cc:1530 TypeOpIntRight
        OpCode::CPUI_INT_RIGHT => binary,
        // typeop.cc:1555 TypeOpIntSright
        OpCode::CPUI_INT_SRIGHT => binary,
        // typeop.cc:1595 TypeOpIntMult
        OpCode::CPUI_INT_MULT => binary | commutative,
        // typeop.cc:1645 TypeOpIntDiv
        OpCode::CPUI_INT_DIV => binary,
        // typeop.cc:1659 TypeOpIntSdiv
        OpCode::CPUI_INT_SDIV => binary,
        // typeop.cc:1654 TypeOpIntRem
        OpCode::CPUI_INT_REM => binary,
        // typeop.cc:1674 TypeOpIntSrem
        OpCode::CPUI_INT_SREM => binary,
        // typeop.cc:1694 TypeOpBoolNegate
        OpCode::CPUI_BOOL_NEGATE => unary | booloutput,
        // typeop.cc:1722 TypeOpBoolXor
        OpCode::CPUI_BOOL_XOR => binary | commutative | booloutput,
        // typeop.cc:1730 TypeOpBoolAnd
        OpCode::CPUI_BOOL_AND => binary | commutative | booloutput,
        // typeop.cc:1738 TypeOpBoolOr
        OpCode::CPUI_BOOL_OR => binary | commutative | booloutput,
        // typeop.cc:1746 TypeOpFloatEqual
        OpCode::CPUI_FLOAT_EQUAL => binary | booloutput | commutative,
        // typeop.cc:1754 TypeOpFloatNotEqual
        OpCode::CPUI_FLOAT_NOTEQUAL => binary | booloutput | commutative,
        // typeop.cc:1762 TypeOpFloatLess
        OpCode::CPUI_FLOAT_LESS => binary | booloutput,
        // typeop.cc:1770 TypeOpFloatLessEqual
        OpCode::CPUI_FLOAT_LESSEQUAL => binary | booloutput,
        // typeop.cc:1778 TypeOpFloatNan
        OpCode::CPUI_FLOAT_NAN => unary | booloutput,
        // typeop.cc:1786 TypeOpFloatAdd
        OpCode::CPUI_FLOAT_ADD => binary | commutative,
        // typeop.cc:1794 TypeOpFloatDiv
        OpCode::CPUI_FLOAT_DIV => binary,
        // typeop.cc:1802 TypeOpFloatMult
        OpCode::CPUI_FLOAT_MULT => binary | commutative,
        // typeop.cc:1810 TypeOpFloatSub
        OpCode::CPUI_FLOAT_SUB => binary,
        // typeop.cc:1818 TypeOpFloatNeg
        OpCode::CPUI_FLOAT_NEG => unary,
        // typeop.cc:1826 TypeOpFloatAbs
        OpCode::CPUI_FLOAT_ABS => unary,
        // typeop.cc:1834 TypeOpFloatSqrt
        OpCode::CPUI_FLOAT_SQRT => unary,
        // typeop.cc:1842 TypeOpFloatTrunc
        OpCode::CPUI_FLOAT_TRUNC => unary,
        // typeop.cc:1907 TypeOpFloatCeil
        OpCode::CPUI_FLOAT_CEIL => unary,
        // typeop.cc:1915 TypeOpFloatFloor
        OpCode::CPUI_FLOAT_FLOOR => unary,
        // typeop.cc:1923 TypeOpFloatRound
        OpCode::CPUI_FLOAT_ROUND => unary,
        // typeop.cc:1931 TypeOpFloatFloat2Float
        OpCode::CPUI_FLOAT_FLOAT2FLOAT => unary,
        // typeop.cc:1939 TypeOpFloatInt2float
        OpCode::CPUI_FLOAT_INT2FLOAT => unary,
        // typeop.cc:1947 TypeOpMulti
        OpCode::CPUI_MULTIEQUAL => special | marker | nocollapse,
        // typeop.cc:1988 TypeOpIndirect
        OpCode::CPUI_INDIRECT => special | marker | nocollapse,
        // typeop.cc:2040 TypeOpPiece
        OpCode::CPUI_PIECE => binary,
        // typeop.cc:2119 TypeOpSubpiece
        OpCode::CPUI_SUBPIECE => binary,
        // typeop.cc:2212 TypeOpCast
        OpCode::CPUI_CAST => unary | special | nocollapse,
        // typeop.cc:2227 TypeOpPtradd
        OpCode::CPUI_PTRADD => ternary | nocollapse,
        // typeop.cc:2303 TypeOpPtrsub
        OpCode::CPUI_PTRSUB => binary | nocollapse,
        // typeop.cc:2393 TypeOpSegment
        OpCode::CPUI_SEGMENTOP => special | nocollapse,
        // typeop.cc:2447 TypeOpCpoolref
        OpCode::CPUI_CPOOLREF => special | nocollapse,
        // typeop.cc:2497 TypeOpNew
        OpCode::CPUI_NEW => special | call | nocollapse,
        // typeop.cc:2531 TypeOpInsert
        OpCode::CPUI_INSERT => ternary,
        // typeop.cc:2546 TypeOpExtract
        OpCode::CPUI_EXTRACT => ternary,
        // typeop.cc:2561 TypeOpPopcount
        OpCode::CPUI_POPCOUNT => unary,
        // typeop.cc:2568 TypeOpLzcount
        OpCode::CPUI_LZCOUNT => unary,
        // CPUI_MAX is a sentinel count, not a real opcode (opcodes.rs).
        // No TypeOp; return 0 (no flags).
        OpCode::CPUI_MAX => 0,
    }
}

/// Corresponds to Ghidra's `IopSpace` class in `op.hh`
pub struct IopSpace;

impl IopSpace {
    pub const NAME: &'static str = "iop";

    // Ghidra: op.cc:41 IopSpace::printRaw
    /// Print info about the op this address refers to, faithful to
    /// `IopSpace::printRaw(ostream &s,uintb offset)` (op.cc:41-59): the
    /// offset is reinterpreted as the `PcodeOp` it aliases
    /// (`(PcodeOp *)(uintp)offset`, op.cc:46 — the encoding
    /// `Funcdata::new_varnode_iop` produces); a non-branch op prints its
    /// `SeqNum` (`address.cc:32 operator<<`: `pc.printRaw` then `':'` then
    /// the uniq/time field in sticky-hex), and a branch op prints the
    /// non-fallthru target block as `code_` + the block start address's
    /// space shortcut + the block start address printRaw
    /// (`op->isFallthruTrue() ? bs->getOut(0) : bs->getOut(1)` when the
    /// parent block has two out edges, else `getOut(0)`).
    ///
    /// RESIDUAL `SPACE-IOP-PRINTRAW-0001` (see docs/TODO_BOARD.md): both
    /// terminal renders are blocked by the spaceless legacy address model —
    /// `SeqNum.addr` (non-branch form) and `BlockBasic::start_addr`
    /// (`block.rs`, flow.rs:1918 assigns the scalar form) are legacy
    /// `Address(u64)` with no space handle, so neither `pc.printRaw`'s
    /// width/wordsize scaling nor `getShortcut()` can be derived. Both
    /// unblock with the ADDRESS-0001 consumer migration (`src/address.rs`
    /// is currently leased by CSPEC-RANGEPROPS-0001). Until then this
    /// returns `None` for both forms; the
    /// `crate::space::AddrSpace::print_raw` Iop dispatch arm documents the
    /// same residual and falls back to the base form inline (kept decoupled
    /// so space.rs compiles standalone under registry-overlay runners
    /// pinned to older bases). When this lands, the dispatch arm starts
    /// calling this function in the same wave.
    pub fn print_raw(_offset: u64) -> Option<String> {
        None
    }
}

// RUGRA-GLUE: process-wide stand-in for Ghidra's NULL input-slot pointer.
// Ghidra's `PcodeOp` (op.cc:70-84, `inrefs(s)` vector-of-pointers ctor) and
// `PcodeOp::setNumInputs` (op.cc:290-296, resize + null every slot) represent
// an unlinked-but-still-counted slot as `(Varnode *)0`; `Funcdata::opUnsetInput`
// (funcdata_op.cc:91-98) leaves exactly that state behind, so a dead op keeps
// its `numInput()` slots as NULLs (observable in the oracle's debug/projection
// stream as one '-' per slot, op.cc:376 printDebug harness rendering). Rugra's
// `inrefs: Vec<Arc<RwLock<Varnode>>>` cannot hold NULL, so this detached,
// never-bank-resident size-0 Varnode stands in for the NULL pointer. ONE
// shared instance per process keeps `Arc::ptr_eq` between two NULL slots
// `true`, matching Ghidra's pointer-equality `inrefs[i] == vn` semantics
// (op.hh:166 getSlot). It carries no descendants, no create-index, and no
// bank side effects, so the `opSetInput` early-return on a fresh NULL slot
// (funcdata_op.cc:107) stays a no-op on it. (SB-ORD159-NULLSLOT-0001)
pub fn null_slot_sentinel() -> Arc<RwLock<Varnode>> {
    static SENTINEL: std::sync::OnceLock<Arc<RwLock<Varnode>>> = std::sync::OnceLock::new();
    SENTINEL
        .get_or_init(|| Arc::new(RwLock::new(Varnode::new(0, Address::new(0)))))
        .clone()
}

/// Represents a single P-code operation in the data flow graph
///
/// Corresponds to Ghidra's `PcodeOp` class in `op.hh`
#[derive(Debug)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub flags: u32,
    pub addlflags: u32,
    pub start: SeqNum,
    pub parent: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    pub output: Option<Arc<RwLock<Varnode>>>,
    pub inrefs: Vec<Arc<RwLock<Varnode>>>,
    pub branch_type: u8,
    /// Arena identity handle (PERF-ARENA-FLIP-0001 (a),
    /// ARENA_DESIGN §1.2/§2.5).
    ///
    /// RUGRA-GLUE: id-space stand-in for the oracle's three stored list
    /// iterators (op.hh:127-129 basiciter/insertiter/codeiter) — here it
    /// names the `PcodeOpTree` slot holding this op's denormalized SeqNum
    /// key copy, and will carry the seven bank chains when the Vec lists
    /// retire (W1(b)-(g), see docs/TODO_BOARD.md). `None` for ops never
    /// inserted through the bank (raw test fixtures).
    pub(crate) op_id: Option<OpId>,
}

impl PcodeOp {
    // RUGRA-GLUE: Rust ctor; Ghidra's PcodeOp constructor is private and only
    //   called via PcodeOpBank::create (op.hh:308). Rugra exposes PcodeOp::new
    //   because we don't have the same friend-class relationship to the bank.
    pub fn new(start: SeqNum, opcode: OpCode) -> Self {
        Self {
            opcode,
            flags: 0,
            addlflags: 0,
            start,
            parent: None,
            output: None,
            inrefs: Vec::new(),
            branch_type: branch_type::NONE,
            op_id: None,
        }
    }

    // Ghidra: op.hh:233 PcodeOp::code (returns the OpCode enum; Ghidra's
    //   getOpcode at :232 returns the TypeOp* behavior object).
    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    // Ghidra: op.hh:160 PcodeOp::getAddr
    pub fn get_addr(&self) -> Address {
        self.start.get_addr()
    }

    // Ghidra: op.hh:162 PcodeOp::getSeqNum
    pub fn get_seq_num(&self) -> &SeqNum {
        &self.start
    }

    // Ghidra: op.hh:161 PcodeOp::getTime
    /// Get the immutable creation identity for this operation.
    pub fn get_time(&self) -> u32 {
        self.start.get_time()
    }

    // Ghidra: op.hh:153 PcodeOp::numInput
    pub fn num_input(&self) -> usize {
        self.inrefs.len()
    }

    // Ghidra: op.hh:156 PcodeOp::getIn
    pub fn get_in(&self, slot: usize) -> Option<&Arc<RwLock<Varnode>>> {
        self.inrefs.get(slot)
    }

    // Ghidra: op.hh:166 PcodeOp::getSlot
    /// Return the input slot holding the given Varnode, or None if not found.
    /// Faithful to `PcodeOp::getSlot(const Varnode *vn)` (op.hh:166):
    ///   int4 i,n; n=inrefs.size(); for(i=0;i<n;++i) if (inrefs[i]==vn) break; return i;
    /// Ghidra returns n (out-of-range) when not found; we return Option<usize>.
    pub fn slot_of_input(&self, vn: &Arc<RwLock<Varnode>>) -> Option<usize> {
        self.inrefs.iter().position(|v| std::sync::Arc::ptr_eq(v, vn))
    }

    // Ghidra: op.hh:154 PcodeOp::getOut
    pub fn get_out(&self) -> Option<&Arc<RwLock<Varnode>>> {
        self.output.as_ref()
    }

    // Ghidra: op.hh:173 PcodeOp::isDead
    pub fn is_dead(&self) -> bool {
        (self.flags & pcodeop_flags::DEAD) != 0
    }

    // Ghidra: op.hh:175 PcodeOp::isCall
    pub fn is_call(&self) -> bool {
        (self.flags & pcodeop_flags::CALL) != 0
    }

    /// Is this op a source of a CPUI_INDIRECT (its output feeds an INDIRECT
    /// that tracks a memory side-effect)? Faithful to `PcodeOp::isIndirectSource`
    /// (op.hh:180). RuleEarlyRemoval must not remove such ops, or the INDIRECT
    /// is left referencing a dead varnode.
    // Ghidra: op.hh:202 PcodeOp::isIndirectSource
    pub fn is_indirect_source(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_SOURCE) != 0
    }

    /// Is this a marker op (MULTIEQUAL/INDIRECT)? Faithful to
    /// `PcodeOp::isMarker` (op.hh:185).
    // Ghidra: op.hh:178 PcodeOp::isMarker
    pub fn is_marker(&self) -> bool {
        (self.flags & pcodeop_flags::MARKER) != 0
    }

    // Ghidra: op.hh:190 PcodeOp::isMark
    /// Has this op been visited by the current algorithm? Faithful to
    /// `PcodeOp::isMark` (op.hh:190). Used by ancestorOpUse to trim cycles in
    /// MULTIEQUAL chains.
    pub fn is_mark(&self) -> bool {
        (self.flags & pcodeop_flags::MARK) != 0
    }
    // Ghidra: op.hh:234 PcodeOp::setMark
    pub fn set_mark(&mut self) {
        self.flags |= pcodeop_flags::MARK;
    }
    // Ghidra: op.hh:235 PcodeOp::clearMark
    pub fn clear_mark(&mut self) {
        self.flags &= !pcodeop_flags::MARK;
    }

    /// Does this op use a spacebase pointer? Faithful to `PcodeOp::usesSpacebasePtr`
    /// (op.hh:228). Set by heritage's discoverIndexedStackPointers when a STORE
    /// reads a stack-pointer-derived address. guardStores checks this to decide
    /// whether to build a Stack-space INDIRECT.
    // Ghidra: op.hh:228 PcodeOp::usesSpacebasePtr
    pub fn uses_spacebase_ptr(&self) -> bool {
        (self.flags & pcodeop_flags::SPACEBASE_PTR) != 0
    }

    /// Mark this op as using a spacebase pointer. Faithful to
    /// `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487).
    // Ghidra: op.hh:138 PcodeOp::setFlag(spacebase_ptr) (called by Funcdata::opMarkSpacebasePtr)
    pub fn mark_spacebase_ptr(&mut self) {
        self.flags |= pcodeop_flags::SPACEBASE_PTR;
    }

    /// Is this op's output a boolean? Faithful to `PcodeOp::isBoolOutput`
    /// (op.hh:190).
    // Ghidra: op.hh:184 PcodeOp::isBoolOutput
    pub fn is_bool_output(&self) -> bool {
        (self.flags & pcodeop_flags::BOOLOUTPUT) != 0
    }

    /// Is the CBRANCH's boolean sense flipped? Faithful to
    /// `PcodeOp::isBooleanFlip` (op.hh:210). When true, the CBRANCH takes
    /// the fallthru edge on a TRUE input (and branches on FALSE).
    // Ghidra: op.hh:191 PcodeOp::isBooleanFlip
    pub fn is_boolean_flip(&self) -> bool {
        (self.flags & pcodeop_flags::BOOLEAN_FLIP) != 0
    }

    /// Compare the control-flow order of this op and `bop`. Returns -1 if
    /// this op comes before bop, 1 if after, 0 if unordered. Faithful to
    /// `PcodeOp::compareOrder` (op.cc:778-790).
    // Ghidra: op.cc:778 PcodeOp::compareOrder
    pub fn compare_order(
        &self,
        bop: &PcodeOp,
    ) -> i32 {
        let p1 = self.parent.as_ref().and_then(|w| w.upgrade());
        let p2 = bop.parent.as_ref().and_then(|w| w.upgrade());
        match (p1, p2) {
            (Some(a), Some(b)) if Arc::ptr_eq(&a, &b) => {
                // Same block: compare SeqNum order.
                if self.start.get_order() < bop.start.get_order() { -1 } else { 1 }
            }
            (Some(a), Some(b)) => {
                let common = crate::block::BlockGraph::find_common_block(&a, &b);
                match common {
                    Some(c) if Arc::ptr_eq(&c, &a) => -1,
                    Some(c) if Arc::ptr_eq(&c, &b) => 1,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    /// Get the evaluation type flags (unary/binary/special/ternary). Faithful
    /// to `PcodeOp::getEvalType` (op.hh:169).
    // Ghidra: op.hh:169 PcodeOp::getEvalType
    pub fn get_eval_type(&self) -> u32 {
        self.flags
            & (pcodeop_flags::UNARY | pcodeop_flags::BINARY | pcodeop_flags::SPECIAL | pcodeop_flags::TERNARY)
    }

    /// Compute a hash for common-subexpression detection. Faithful to
    /// `PcodeOp::getCseHash` (op.cc:130-147). Returns 0 for non-unary/binary
    /// ops or COPY ops.
    // Ghidra: op.cc:130 PcodeOp::getCseHash
    pub fn get_cse_hash(&self) -> u64 {
        if (self.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return 0;
        }
        if self.opcode == OpCode::CPUI_COPY {
            return 0; // Let copy propagation deal with this.
        }
        let mut hash: u64 = ((self.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0) as u64) << 8)
            | self.opcode as u64;
        for i in 0..self.inrefs.len() {
            hash = (hash << 8) | (hash >> (std::mem::size_of::<u64>() * 8 - 8));
            let vn = &self.inrefs[i];
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_constant() {
                hash ^= vn_rg.get_offset();
            } else {
                hash ^= vn_rg.create_index as u64;
            }
        }
        hash
    }

    /// Do these two ops represent a common subexpression? Faithful to
    /// `PcodeOp::isCseMatch` (op.cc:153-171).
    // Ghidra: op.cc:153 PcodeOp::isCseMatch
    pub fn is_cse_match(&self, other: &PcodeOp) -> bool {
        if (self.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return false;
        }
        if (other.get_eval_type() & (pcodeop_flags::UNARY | pcodeop_flags::BINARY)) == 0 {
            return false;
        }
        let self_out_size = self.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        let other_out_size = other.output.as_ref().map(|v| v.read().unwrap().get_size()).unwrap_or(0);
        if self_out_size != other_out_size {
            return false;
        }
        if self.opcode != other.opcode {
            return false;
        }
        if self.opcode == OpCode::CPUI_COPY {
            return false; // Let copy propagation deal with this.
        }
        if self.inrefs.len() != other.inrefs.len() {
            return false;
        }
        for i in 0..self.inrefs.len() {
            let vn1 = &self.inrefs[i];
            let vn2 = &other.inrefs[i];
            if std::sync::Arc::ptr_eq(vn1, vn2) {
                continue;
            }
            let r1 = vn1.read().unwrap();
            let r2 = vn2.read().unwrap();
            if r1.is_constant() && r2.is_constant() && r1.get_offset() == r2.get_offset() {
                continue;
            }
            return false;
        }
        true
    }

    // Ghidra: op.hh:185 PcodeOp::isBranch
    pub fn is_branch(&self) -> bool {
        (self.flags & pcodeop_flags::BRANCH) != 0
    }

    /// Does the fallthru edge happen on the TRUE condition? Faithful to
    /// `PcodeOp::isFallthruTrue` (op.hh:193): `flags & fallthru_true`.
    // Ghidra: op.hh:193 PcodeOp::isFallthruTrue
    pub fn is_fallthru_true(&self) -> bool {
        (self.flags & pcodeop_flags::FALLTHRU_TRUE) != 0
    }

    /// Is this op's output a calculated boolean value? Faithful to
    /// `PcodeOp::isCalculatedBool` (op.hh:211).
    // Ghidra: op.hh:211 PcodeOp::isCalculatedBool
    pub fn is_calculated_bool(&self) -> bool {
        (self.flags & (pcodeop_flags::CALCULATED_BOOL | pcodeop_flags::BOOLOUTPUT)) != 0
    }

    /// Does this op consume/produce a pointer? Faithful to
    /// `PcodeOp::isPtrFlow` (op.hh:205).
    // Ghidra: op.hh:205 PcodeOp::isPtrFlow
    pub fn is_ptr_flow(&self) -> bool {
        (self.flags & pcodeop_flags::PTRFLOW) != 0
    }
    /// Mark this op as consuming/producing ptrs. Faithful to
    /// `PcodeOp::setPtrFlow` (op.hh:206).
    // Ghidra: op.hh:206 PcodeOp::setPtrFlow
    pub fn set_ptr_flow(&mut self) {
        self.flags |= pcodeop_flags::PTRFLOW;
    }

    /// Has this cpool op been checked for transforms? Faithful to
    /// `PcodeOp::isCpoolTransformed` (op.hh:213). Uses addlflags bit 0x20
    /// (Ghidra `is_cpool_transformed = 0x20`, op.hh:114).
    // Ghidra: op.hh:213 PcodeOp::isCpoolTransformed
    pub fn is_cpool_transformed(&self) -> bool {
        (self.addlflags & 0x20) != 0
    }
    /// Mark this cpool op as transformed. Faithful to
    /// `PcodeOp::setAdditionalFlag(is_cpool_transformed)` (op.hh:140/213).
    // Ghidra: op.hh:140 PcodeOp::setAdditionalFlag(is_cpool_transformed)
    pub fn mark_cpool_transformed(&mut self) {
        self.addlflags |= 0x20;
    }

    /// Does this op require special printing? (op.hh:208, addlflags 0x2)
    // Ghidra: op.hh:208 PcodeOp::doesSpecialPrinting
    pub fn does_special_printing(&self) -> bool {
        (self.addlflags & op_addl_flags::SPECIAL_PRINT) != 0
    }

    /// Does this op do a special form of datatype propagation? (op.hh:207,
    /// addlflags 0x1) — read by the volatile user-op local-type overrides
    /// (`VolatileReadOp::getOutputLocal` userop.cc:131,
    /// `VolatileWriteOp::getInputLocal` userop.cc:162); set only by
    /// `Funcdata::replaceVolatile` (funcdata_varnode.cc:762) when the
    /// replaced varnode was type-locked.
    // Ghidra: op.hh:207 PcodeOp::doesSpecialPropagation
    pub fn does_special_propagation(&self) -> bool {
        (self.addlflags & op_addl_flags::SPECIAL_PROP) != 0
    }

    /// Clear the stop-type-propagation flag. (op.hh:217, addlflags 0x40)
    // Ghidra: op.hh:217 PcodeOp::clearStopTypePropagation
    pub fn clear_stop_type_propagation(&mut self) {
        self.addlflags &= !op_addl_flags::STOP_TYPE_PROPAGATION;
    }
    // Ghidra: op.hh:215 PcodeOp::stopsTypePropagation
    pub fn stops_type_propagation(&self) -> bool {
        (self.addlflags & op_addl_flags::STOP_TYPE_PROPAGATION) != 0
    }

    /// Is this op marked to never be indirect-collapsed? (op.hh:223, addlflags 0x200)
    // Ghidra: op.hh:223 PcodeOp::noIndirectCollapse
    pub fn no_indirect_collapse(&self) -> bool {
        (self.addlflags & op_addl_flags::NO_INDIRECT_COLLAPSE) != 0
    }
    // Ghidra: op.hh:224 PcodeOp::setNoIndirectCollapse
    pub fn set_no_indirect_collapse(&mut self) {
        self.addlflags |= op_addl_flags::NO_INDIRECT_COLLAPSE;
    }

    // Ghidra: op.hh:220 PcodeOp::isPartialRoot
    /// Is this op's output the root of a CONCAT tree already visited by
    /// RulePieceStructure? Faithful to `PcodeOp::isPartialRoot`
    /// (op.hh:220): `(addlflags & concat_root) != 0` (concat_root = 0x100).
    /// The guard keeps the cleanup-pool rule from re-walking a tree it
    /// already restructured (ruleaction.cc:7628).
    pub fn is_partial_root(&self) -> bool {
        (self.addlflags & op_addl_flags::CONCAT_ROOT) != 0
    }
    // Ghidra: op.hh:221 PcodeOp::setPartialRoot
    /// Mark this op's output as the root of a visited CONCAT tree.
    /// Faithful to `PcodeOp::setPartialRoot` (op.hh:221).
    pub fn set_partial_root(&mut self) {
        self.addlflags |= op_addl_flags::CONCAT_ROOT;
    }

    // Ghidra: op.hh:179 PcodeOp::isIndirectCreation
    /// Return true if this op creates a varnode indirectly (an INDIRECT op
    /// marked as indirect_creation). Faithful to `PcodeOp::isIndirectCreation`
    /// (op.hh:179): `(flags & indirect_creation) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to detect call
    /// output creation.
    pub fn is_indirect_creation(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_CREATION) != 0
    }

    // Ghidra: op.hh:180 PcodeOp::isIndirectStore
    /// Return true if this INDIRECT is caused by a STORE. Faithful to
    /// `PcodeOp::isIndirectStore` (op.hh:180):
    ///   `(flags & indirect_store) != 0`.
    /// Used by AncestorRealistic::enterNode (INDIRECT case) to distinguish
    /// store-induced indirects from call-induced indirects.
    pub fn is_indirect_store(&self) -> bool {
        (self.flags & pcodeop_flags::INDIRECT_STORE) != 0
    }

    // Ghidra: op.hh:209 PcodeOp::isIncidentalCopy
    /// Return true if this COPY is incidental (a side-effect of a call).
    /// Faithful to `PcodeOp::isIncidentalCopy` (op.hh:209):
    ///   `(addlflags & incidental_copy) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY/SUBPIECE cases) and
    /// onlyOpUse to treat incidental copies as transparent.
    pub fn is_incidental_copy(&self) -> bool {
        (self.addlflags & op_addl_flags::INCIDENTAL_COPY) != 0
    }

    // Ghidra: op.hh:225 PcodeOp::isStoreUnmapped
    /// Is this STORE location supposed to be unmapped? Faithful to
    /// `PcodeOp::isStoreUnmapped` (op.hh:225):
    ///   `(addlflags & store_unmapped) != 0`.
    /// Used by AncestorRealistic::enterNode (COPY case) to reject stores
    /// flagged as unmapped.
    pub fn is_store_unmapped(&self) -> bool {
        (self.addlflags & op_addl_flags::STORE_UNMAPPED) != 0
    }

    // Ghidra: op.hh:174 PcodeOp::isAssignment
    /// Return true if this op has an output (i.e. produces a value).
    /// Faithful to `isAssignment` (op.hh:174).
    pub fn is_assignment(&self) -> bool {
        self.output.is_some()
    }

    // Ghidra: op.hh:189 PcodeOp::isFlowBreak
    /// Return true if this op breaks the flow of a basic block (branch/return).
    /// Faithful to `isFlowBreak` (op.hh:189).
    pub fn is_flow_break(&self) -> bool {
        (self.flags & (pcodeop_flags::BRANCH | pcodeop_flags::RETURNS)) != 0
    }

    // Ghidra: op.hh:195 PcodeOp::isInstructionStart
    /// Return true if this op is the first in its machine instruction.
    /// Faithful to `isInstructionStart` (op.hh:195).
    pub fn is_instruction_start(&self) -> bool {
        (self.flags & pcodeop_flags::STARTMARK) != 0
    }

    // Ghidra: op.cc:503 PcodeOp::collapseConstantSymbol
    /// Propagate symbol markup from inputs to a collapsed constant output.
    /// Faithful to `collapseConstantSymbol` (op.cc:503-540).
    pub fn collapse_constant_symbol(&self, new_const: &Arc<RwLock<crate::varnode::Varnode>>) {
        let copy_vn: Option<Arc<RwLock<crate::varnode::Varnode>>> = match self.opcode {
            OpCode::CPUI_SUBPIECE => {
                // cc:509: must be truncating from offset 0
                let off = self.inrefs.get(1).map(|v| v.read().unwrap().get_offset()).unwrap_or(1);
                if off != 0 { return; }
                self.inrefs.get(0).cloned()
            }
            OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_2COMP => {
                self.inrefs.get(0).cloned()
            }
            OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
                self.inrefs.get(0).cloned()
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR => {
                // cc:530: try in[0], fall back to in[1] if no symbol
                let v0 = self.inrefs.get(0).cloned();
                if let Some(v) = &v0 {
                    if v.read().unwrap().get_symbol_entry().is_some() {
                        v0
                    } else {
                        self.inrefs.get(1).cloned()
                    }
                } else {
                    self.inrefs.get(1).cloned()
                }
            }
            _ => return,
        };
        // cc:537: copyVn must have a symbol entry
        if let Some(cv) = copy_vn {
            if cv.read().unwrap().get_symbol_entry().is_some() {
                // copySymbolIfValid (varnode.cc:510) now takes the destination
                // Arc so its copySymbol tail can run the full cc:493-505 port
                // (high bookkeeping included) via copy_symbol_arc.
                crate::varnode::Varnode::copy_symbol_if_valid(new_const, &cv.read().unwrap());
            }
        }
    }

    // Ghidra: op.cc:276 PcodeOp::setOpcode
    /// Set opcode and update opcode-derived flags. Faithful to
    /// `setOpcode` (op.cc:276-285). Clears all opcode-derived flag bits,
    /// then sets them from the new opcode.
    pub fn set_opcode_flags(&mut self, opc: OpCode) {
        // cc:279-282: clear all opcode-derived flags (14 bits, including commutative)
        const OPC_FLAGS_MASK: u32 = pcodeop_flags::BRANCH | pcodeop_flags::CALL
            | pcodeop_flags::CODEREF | pcodeop_flags::COMMUTATIVE
            | pcodeop_flags::RETURNS | pcodeop_flags::NOCOLLAPSE | pcodeop_flags::MARKER
            | pcodeop_flags::BOOLOUTPUT | pcodeop_flags::UNARY
            | pcodeop_flags::BINARY | pcodeop_flags::TERNARY
            | pcodeop_flags::SPECIAL | pcodeop_flags::HAS_CALLSPEC
            | pcodeop_flags::RETURN_COPY;
        self.flags &= !OPC_FLAGS_MASK;
        self.opcode = opc;
        // cc:284: flags |= t_op->getFlags()
        // Rugra has no TypeOp; derive flags per typeop.cc constructors.
        let extra = opcode_flags(opc);
        self.flags |= extra;
    }

    // Ghidra: op.cc:178 PcodeOp::isMoveable
    /// Can this op be moved past `point`? Faithful to `isMoveable`
    /// (op.cc:178-271). Checks: same block, output not read before point,
    /// address-tied crossing rules, CALL crossing restrictions.
    /// The `bank` parameter is retained for call-site compatibility; Ghidra's
    /// method reads only `basiciter`/`parent` and no bank.
    pub fn is_moveable(&self, point: &PcodeOp, _bank: &PcodeOpBank) -> bool {
        if std::ptr::eq(self, point) { return true; }
        let eval_type = self.get_eval_type();
        // cc:183-187: special ops
        let moving_load = if eval_type == pcodeop_flags::SPECIAL {
            if self.opcode == OpCode::CPUI_LOAD {
                true
            } else {
                return false;
            }
        } else {
            false
        };
        // cc:189: same block check (Rugra: same parent)
        let self_parent = self.parent.as_ref().and_then(|w| w.upgrade());
        let point_parent = point.parent.as_ref().and_then(|w| w.upgrade());
        match (&self_parent, &point_parent) {
            (Some(a), Some(b)) => {
                if !Arc::ptr_eq(a, b) { return false; }
            }
            _ => return false,
        }
        // cc:190-200: output cannot be read before point in same block
        if let Some(out_vn) = &self.output {
            let point_order = point.start.get_order();
            for desc_weak in &out_vn.read().unwrap().descend {
                if let Some(read_op) = desc_weak.upgrade() {
                    let read_r = read_op.read().unwrap();
                    // Same parent?
                    let read_parent = read_r.parent.as_ref().and_then(|w| w.upgrade());
                    let same_parent = match (&read_parent, &self_parent) {
                        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                        _ => false,
                    };
                    if same_parent && read_r.start.get_order() <= point_order {
                        return false;
                    }
                }
            }
        }
        // cc:202-216: crossCalls = a normal op whose output and all inputs are
        // neither address-tied nor persist may be moved across a CALL.
        let mut cross_calls = false;
        if eval_type != pcodeop_flags::SPECIAL {
            if let Some(out_vn) = &self.output {
                let out_r = out_vn.read().unwrap();
                if !out_r.is_addr_tied() && !out_r.is_persist() {
                    let mut i = 0;
                    while i < self.inrefs.len() {
                        let vn = self.inrefs[i].read().unwrap();
                        if vn.is_addr_tied() || vn.is_persist() { break; }
                        i += 1;
                    }
                    if i == self.inrefs.len() { cross_calls = true; }
                }
            }
        }
        // cc:217-222: build tiedList = inputs that are address-tied.
        let mut tied_list: Vec<Arc<RwLock<Varnode>>> = Vec::new(); // addr-tied inputs
        for inref in &self.inrefs {
            let vn = inref.read().unwrap();
            if vn.is_addr_tied() { tied_list.push(inref.clone()); }
        }
        // cc:223-269: walk the ops between self and point in the same block,
        // in BlockBasic::ops (block) order:
        //   biter = basiciter; do { ++biter; op = *biter; <crossing checks> }
        //   while (biter != point->basiciter);
        // The walk examines every op strictly after self, up to and INCLUDING
        // point itself. The order source is the parent block's op list
        // (`basiciter`), NOT the bank alivelist: alivelist is markAlive
        // push_back order (op.cc:1022), which diverges from block order after
        // mid-block insertions (markers, replacement pairs) or
        // opUninsert/opInsert moves — walking it could skip a STORE/CALL that
        // sits between self and point in the block, or examine an op outside
        // the span (OP-ISMOVEABLE-WALKORDER-0001).
        // Oracle contract: point is strictly after self (both real call sites
        // pass the block's lastOp). Ghidra runs off the list end (undefined
        // behavior) when point precedes self; Rugra fails closed.
        let crossed_ops: Vec<PcodeOpRef> = {
            // Same-parent gate above guarantees Some; mirror Ghidra's
            // unconditional parent dereference via basiciter.
            let parent_arc = match &self_parent {
                Some(a) => a,
                None => return false,
            };
            let guard = parent_arc.read().unwrap();
            let bb = match guard.as_any().downcast_ref::<crate::block::BlockBasic>() {
                Some(bb) => bb,
                None => return false,
            };
            let self_idx = match self.basic_block_index(bb) {
                Some(i) => i,
                None => return false,
            };
            let point_idx = match point.basic_block_index(bb) {
                Some(i) => i,
                None => return false,
            };
            if point_idx <= self_idx {
                return false;
            }
            bb.ops[self_idx + 1..=point_idx].to_vec()
        };
        // cc:224: do { ++biter; op = *biter; ... } while(biter != point->basiciter);
        // First examined op is the op immediately after self (biter starts at
        // self, then ++biter); the last examined op is point (inclusive).
        for op_ref in &crossed_ops {
            let op = op_ref.0.read().unwrap();
            // cc:227-256: special op crossing rules
            if op.get_eval_type() == pcodeop_flags::SPECIAL {
                match op.opcode {
                    OpCode::CPUI_LOAD => {
                        // cc:229-233
                        if let Some(out_vn) = &self.output {
                            if out_vn.read().unwrap().is_addr_tied() { return false; }
                        }
                    }
                    OpCode::CPUI_STORE => {
                        // cc:234-243
                        if moving_load {
                            return false;
                        } else {
                            if !tied_list.is_empty() { return false; }
                            if let Some(out_vn) = &self.output {
                                if out_vn.read().unwrap().is_addr_tied() { return false; }
                            }
                        }
                    }
                    OpCode::CPUI_INDIRECT | OpCode::CPUI_SEGMENTOP | OpCode::CPUI_CPOOLREF => {
                        // cc:244-247: let through
                    }
                    OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_NEW => {
                        // cc:248-252
                        if !cross_calls { return false; }
                    }
                    _ => {
                        // cc:253-255
                        return false;
                    }
                }
            }
            // cc:257-268: output of the op we're crossing over
            if let Some(op_output) = &op.output {
                let op_out = op_output.read().unwrap();
                // cc:258-260
                if moving_load && op_out.is_addr_tied() { return false; }
                // cc:261-267
                for tied_weak in &tied_list {
                    let vn = tied_weak.read().unwrap();
                    // vn.overlap(*op_output) >= 0 (does op_output contain a piece of vn?)
                    if vn.overlap(&op_out) >= 0 { return false; }
                    // op_output.overlap(*vn) >= 0 (does vn contain a piece of op_output?)
                    if op_out.overlap(&vn) >= 0 { return false; }
                }
            }
            // The inclusive range ends at point; no SeqNum-based stop needed
            // (Ghidra's loop condition `biter != point->basiciter`).
        }
        true
    }

    // Ghidra: op.cc:389 PcodeOp::encode
    /// Encode this op as XML. Faithful to `encode` (op.cc:389-448).
    /// Rugra returns a String (no Encoder).
    pub fn encode(&self) -> String {
        let mut s = format!("<op code=\"{:?}\">", self.opcode);
        s += &format!("<seqnum>{:?}</seqnum>", self.start);
        if let Some(out) = &self.output {
            s += &format!("<addr ref=\"{}\"/>", out.read().unwrap().create_index);
        } else {
            s += "<void/>";
        }
        for vn in &self.inrefs {
            s += &format!("<addr ref=\"{}\"/>", vn.read().unwrap().create_index);
        }
        s += "</op>";
        s
    }

    // Ghidra: op.cc:376 PcodeOp::printDebug
    // Already implemented above as print_debug()

    // RUGRA-GLUE: borrow-safe resolution of this PcodeOp's `basiciter`
    // equivalent. Ghidra stores a `list<PcodeOp*>::iterator basiciter` inside
    // the op (op.hh:127), set by BlockBasic::insert (block.cc:2266) and used
    // by nextOp/previousOp. Rust cannot hold an iterator into the parent
    // block's Vec across Arc boundaries, so the position is recomputed by
    // PcodeOp object address. Ghidra identity is the raw `PcodeOp*`; the
    // stable address of `PcodeOp` inside its `Arc<RwLock<PcodeOp>>`
    // allocation is the exact analogue. Cost is O(block size) vs Ghidra O(1);
    // observable semantics (which op, which order) are identical.
    fn basic_block_index(&self, bb: &crate::block::BlockBasic) -> Option<usize> {
        let self_ptr = self as *const PcodeOp;
        bb.ops.iter().position(|r| {
            let guard = r.0.read().unwrap();
            (&*guard as *const PcodeOp) == self_ptr
        })
    }

    // Ghidra: op.cc:323 PcodeOp::nextOp
    /// Find the next op in sequence from this op. Usually in the same basic
    /// block; when this op is the block's last op, the search follows flow
    /// into successive blocks via out-edge 0, so long as the block has
    /// exactly 1 or 2 out edges (op.cc:333-337). Order is the parent block's
    /// op list (`basiciter`), NOT the alivelist mark-alive insertion order.
    /// The `bank` parameter is retained for call-site compatibility; Ghidra's
    /// method reads only `basiciter`/`parent` and no bank.
    pub fn next_op_in_flow(&self, _bank: &PcodeOpBank) -> Option<PcodeOpRef> {
        // cc:329-332: p = parent; iter = basiciter; iter++
        let parent_arc = self.parent.as_ref().and_then(|w| w.upgrade())?;
        let mut p = parent_arc;
        let mut index = {
            let guard = p.read().unwrap();
            let bb = guard
                .as_any()
                .downcast_ref::<crate::block::BlockBasic>()?;
            self.basic_block_index(bb)? + 1
        };
        loop {
            // cc:333/338: while (iter == p->endOp()) ... return *iter
            let candidate = {
                let guard = p.read().unwrap();
                let bb = guard
                    .as_any()
                    .downcast_ref::<crate::block::BlockBasic>()?;
                bb.ops.get(index).cloned()
            };
            let Some(next) = candidate else {
                // cc:334: if ((p->sizeOut() != 1)&&(p->sizeOut()!=2)) return 0
                let out_zero = {
                    let guard = p.read().unwrap();
                    let size_out = guard.size_out();
                    if size_out != 1 && size_out != 2 {
                        return None;
                    }
                    // cc:335: p = (BlockBasic *) p->getOut(0)
                    let bank = guard.bank();
                    guard.get_out(0).map(|edge| bank.expect_arc(edge.point))
                };
                p = out_zero?;
                // cc:336: iter = p->beginOp()
                index = 0;
                continue;
            };
            return Some(next);
        }
    }

    // Ghidra: op.cc:344 PcodeOp::previousOp
    /// Find the previous op that flowed uniquely into this op, if it exists.
    /// Searches no farther than the basic block containing this op: returns
    /// `None` at the block head (op.cc:349), otherwise the block-list
    /// predecessor (`basiciter - 1`, op.cc:350-352). Order is the parent
    /// block's op list, NOT the alivelist mark-alive insertion order.
    /// The `bank` parameter is retained for call-site compatibility; Ghidra's
    /// method reads only `basiciter`/`parent` and no bank. A dead/unattached
    /// op (parent None) returns `None` (Ghidra would read a stale iterator).
    pub fn previous_op_in_block(&self, _bank: &PcodeOpBank) -> Option<PcodeOpRef> {
        // cc:349: if (basiciter == parent->beginOp()) return (PcodeOp *)0
        // cc:350-352: iter = basiciter; iter--; return *iter
        let parent_arc = self.parent.as_ref().and_then(|w| w.upgrade())?;
        let guard = parent_arc.read().unwrap();
        let bb = guard
            .as_any()
            .downcast_ref::<crate::block::BlockBasic>()?;
        let index = self.basic_block_index(bb)?;
        if index == 0 {
            return None;
        }
        Some(bb.ops[index - 1].clone())
    }

    // Ghidra: op.cc:360 PcodeOp::target
    pub fn target_op(&self, bank: &PcodeOpBank) -> Option<PcodeOpRef> {
        let self_seq = &self.start;
        let mut found_self = false;
        for r in bank.iter_alive() {
            if &r.0.read().unwrap().start == self_seq { found_self = true; }
            if found_self && (r.0.read().unwrap().flags & pcodeop_flags::STARTMARK) != 0 {
                return Some(r.clone());
            }
        }
        None
    }

    // Ghidra: op.cc:115 PcodeOp::isCollapsible
    pub fn is_collapsible(&self) -> bool {
        if (self.flags & pcodeop_flags::NOCOLLAPSE) != 0 {
            return false;
        }
        if !self.is_assignment() {
            return false;
        }
        if self.inrefs.is_empty() {
            return false;
        }
        // All inputs must be constants.
        for inref in &self.inrefs {
            if !inref.read().unwrap().is_constant() {
                return false;
            }
        }
        // Output size must fit in u64 (sizeof(uintb) on 64-bit Ghidra).
        if let Some(out) = &self.output {
            if out.read().unwrap().get_size() > 8 {
                return false;
            }
        }
        true
    }

    // Ghidra: op.cc:290 PcodeOp::setNumInputs
    /// Set the number of input slots. All slots, regardless of the total
    /// being increased or decreased, are set to \e null.
    /// Faithful to `setNumInputs` (op.cc:290-296): `inrefs.resize(num)` then
    /// every slot null. The null slot is the shared `null_slot_sentinel`
    /// (Ghidra's `(Varnode *)0`), preserving slot count for unlinked ops.
    pub fn set_num_inputs(&mut self, num: usize) {
        self.inrefs.clear();
        self.inrefs.resize(num, null_slot_sentinel());
    }

    // Ghidra: op.cc:301 PcodeOp::removeInput
    /// Remove the input Varnode at `slot`. Subsequent slots shift down.
    /// Faithful to `removeInput` (op.cc:301-307).
    pub fn remove_input(&mut self, slot: usize) {
        if slot < self.inrefs.len() {
            self.inrefs.remove(slot);
        }
    }

    // Ghidra: op.cc:311 PcodeOp::insertInput
    /// Insert a new input slot at `slot`, shifting subsequent slots up.
    /// The new slot holds a placeholder that the caller must fill.
    /// Faithful to `insertInput` (op.cc:311-318). Same null-placeholder caveat
    /// as `set_num_inputs`.
    pub fn insert_input_slot(&mut self, slot: usize, placeholder: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        let slot = slot.min(self.inrefs.len());
        self.inrefs.insert(slot, placeholder);
    }

    // Ghidra: op.cc:93 PcodeOp::getRepeatSlot
    /// Given a Varnode that appears in multiple input slots, find the specific
    /// slot corresponding to the `count`-th occurrence (1-based). Returns -1 if
    /// not found. Faithful to `getRepeatSlot` (op.cc:93-111).
    pub fn get_repeat_slot(&self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, first_slot: usize, count: usize) -> i32 {
        // Walk input slots from first_slot+1, find the (count)-th occurrence.
        let mut recount = 1;
        for i in (first_slot + 1)..self.inrefs.len() {
            if std::sync::Arc::ptr_eq(&self.inrefs[i], vn) {
                recount += 1;
                if recount == count {
                    return i as i32;
                }
            }
        }
        -1
    }

    // Ghidra: op.cc:376 PcodeOp::printDebug
    /// Print a debug representation (address + raw op) to a string.
    /// Faithful to `printDebug` (op.cc:376-384). Rugra returns a String
    /// instead of writing to ostream.
    pub fn print_debug(&self) -> String {
        let mut s = String::new();
        s += &format!("{:?}: ", self.start);
        if self.is_dead() || self.parent.is_none() {
            s += "**";
        } else {
            s += &format!("{:?}", self.opcode);
            if let Some(out) = &self.output {
                let o = out.read().unwrap();
                s += &format!(" v({:?},{:#x})", o.address_space, o.loc.as_u64());
            }
            for inref in &self.inrefs {
                let i = inref.read().unwrap();
                s += &format!(" ({:?},{:#x})", i.address_space, i.loc.as_u64());
            }
        }
        s
    }

    // Ghidra: op.cc:450 PcodeOp::collapse
    /// Collapse constant inputs into a single result. Faithful to
    /// `collapse` (op.cc:450-472). Routes through the TypeOp evaluate
    /// bridge (`opcode->evaluateUnary/evaluateBinary`, typeop.hh:81-92 —
    /// `crate::typeop::evaluate_unary/evaluate_binary`), which delegates to
    /// the OpBehavior table incl. the FLOAT_* dispatch.
    /// Returns Some((result, marked_input)) or None if the evaluation threw
    /// (LowlevelError/EvaluationError — the caller's opMarkNoCollapse path).
    pub fn collapse(&self) -> Option<(u64, bool)> {
        use crate::typeop::{evaluate_unary, evaluate_binary};
        let eval_type = self.get_eval_type();
        let vn0 = self.inrefs.get(0)?;
        let vn0_r = vn0.read().unwrap();
        let marked_input = vn0_r.get_symbol_entry().is_some();
        let out_size = self.output.as_ref()?.read().unwrap().get_size();
        let vn0_size = vn0_r.get_size();
        let vn0_offset = vn0_r.get_offset();
        drop(vn0_r);
        match eval_type {
            x if (x & pcodeop_flags::UNARY) != 0 => {
                evaluate_unary(self.opcode, out_size, vn0_size, vn0_offset)
                    .map(|r| (r, marked_input))
            }
            x if (x & pcodeop_flags::BINARY) != 0 => {
                let vn1 = self.inrefs.get(1)?;
                let vn1_r = vn1.read().unwrap();
                let vn1_size = vn1_r.get_size();
                let vn1_offset = vn1_r.get_offset();
                let marked2 = vn1_r.get_symbol_entry().is_some();
                drop(vn1_r);
                evaluate_binary(self.opcode, out_size, vn0_size, vn0_offset, vn1_offset)
                    .map(|r| (r, marked_input || marked2))
            }
            _ => None,
        }
    }

    // Ghidra: op.cc:478 PcodeOp::executeSimple
    /// Execute the op on given input values. Faithful to `executeSimple`
    /// (op.cc:478-498). Returns Some(result) or None on eval error.
    pub fn execute_simple(&self, inputs: &[u64]) -> Option<u64> {
        use crate::opbehavior::{evaluate_unary, evaluate_binary, evaluate_ternary};
        let eval_type = self.get_eval_type();
        let out_size = self.output.as_ref()?.read().unwrap().get_size();
        let in0_size = self.inrefs.first()?.read().unwrap().get_size();
        match eval_type {
            x if (x & pcodeop_flags::UNARY) != 0 => {
                evaluate_unary(self.opcode, out_size, in0_size, inputs.get(0).copied()?)
            }
            x if (x & pcodeop_flags::BINARY) != 0 => {
                evaluate_binary(self.opcode, out_size, in0_size,
                    inputs.get(0).copied()?, inputs.get(1).copied()?)
            }
            x if (x & pcodeop_flags::TERNARY) != 0 => {
                evaluate_ternary(self.opcode, out_size, in0_size,
                    inputs.get(0).copied()?, inputs.get(1).copied()?, inputs.get(2).copied()?)
            }
            _ => None,
        }
    }

    // Ghidra: op.cc:547 PcodeOp::getNZMaskLocal
    /// Compute the non-zero mask for this op's output assuming the input
    /// masks are already defined. Faithful to `PcodeOp::getNZMaskLocal`
    /// (op.cc:547-771): `fullmask` derives from the output size; compare and
    /// boolean ops emit 1; MULTIEQUAL ORs its inputs (skipping looping edges
    /// when `cliploop`, op.cc:740-757); every unlisted opcode — including
    /// INT_NEGATE and INT_2COMP — falls to `default:` and emits `fullmask`
    /// (op.cc:766-768). Raw `>>`/`<<` sites that the oracle leaves unguarded
    /// use Rust `wrapping_shr`/`wrapping_shl`, mirroring the x86-64
    /// shift-count masking the locked oracle binary is built with; sites the
    /// oracle guards through `pcode_right`/`pcode_left` (address.hh:505-517)
    /// return 0 for shift counts >= 64 exactly like those helpers.
    ///
    /// Oracle `Varnode::getNZMask` (varnode.hh:231) is the raw field access
    /// `return nzm;`. Rugra's `Varnode::get_nz_mask` (varnode.rs) predates
    /// the calcNZMask wiring and substitutes a conservative approximation
    /// (constants -> offset, others -> calc_mask), so this method reads the
    /// stored field directly (`get_nzm`) exactly as the oracle does
    /// (consolidating `Varnode::get_nz_mask` itself is tracked by TODO
    /// FUNCDATA-CALCNZM-0003).
    pub fn get_nz_mask_local(&self, cliploop: bool) -> u64 {
        // pcode_right (address.hh:505-511).
        let pcode_right = |val: u64, sa: i32| -> u64 {
            if sa >= 64 { 0 } else { val >> sa }
        };
        // pcode_left (address.hh:514-518).
        let pcode_left = |val: u64, sa: i32| -> u64 {
            if sa >= 64 { 0 } else { val << sa }
        };
        // op.cc:553: size = output->getSize(); calcNZMask only calls in
        // with a live output (funcdata_varnode.cc:872-875 / cc:918).
        let out_size = match &self.output {
            Some(o) => o.read().unwrap().get_size(),
            None => return u64::MAX,
        };
        let inputs = self.inrefs.clone();
        let parent = self.parent.clone();
        let fullmask = crate::address::calc_mask(out_size); // op.cc:554
        let in_nzm = |i: usize| -> u64 {
            inputs
                .get(i)
                .map(|v| v.read().unwrap().get_nzm())
                .unwrap_or(fullmask)
        };
        let in_const = |i: usize| -> Option<u64> {
            let v = inputs.get(i)?;
            let r = v.read().unwrap();
            if r.is_constant() { Some(r.get_offset()) } else { None }
        };
        let in_size = |i: usize| -> usize {
            inputs.get(i).map(|v| v.read().unwrap().get_size()).unwrap_or(out_size)
        };
        match self.opcode {
            // op.cc:557-576: only 1 bit not guaranteed to be 0.
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
            | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
            | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN => 1,
            // op.cc:577-580
            OpCode::CPUI_COPY | OpCode::CPUI_INT_ZEXT => in_nzm(0),
            // op.cc:581-583
            OpCode::CPUI_INT_SEXT => {
                crate::rangeutil::sign_extend_size(in_nzm(0), in_size(0), out_size)
            }
            // op.cc:584-589
            OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR => {
                let resmask = in_nzm(0);
                if resmask != fullmask { resmask | in_nzm(1) } else { resmask }
            }
            // op.cc:590-594
            OpCode::CPUI_INT_AND => {
                let resmask = in_nzm(0);
                if resmask != 0 { resmask & in_nzm(1) } else { 0 }
            }
            // op.cc:595-603
            OpCode::CPUI_INT_LEFT => match in_const(1) {
                Some(sa) => pcode_left(in_nzm(0), sa as i32) & fullmask,
                None => fullmask,
            },
            // op.cc:604-632
            OpCode::CPUI_INT_RIGHT => match in_const(1) {
                Some(sa) => {
                    let sz1 = in_size(0);
                    let sa = sa as i32;
                    let mut resmask = pcode_right(in_nzm(0), sa);
                    if sz1 > 8 {
                        // op.cc:612-630: resmask did not hold the most
                        // significant bits of the mask.
                        if sa >= (8 * sz1) as i32 {
                            resmask = 0; // op.cc:614-615
                        } else if sa >= 64 {
                            // op.cc:616-620: full mask shifted over 64 bits.
                            resmask = crate::address::calc_mask(sz1 - 8);
                            resmask >>= sa - 64; // sa < 8*sz1 here
                        } else {
                            // op.cc:622-629: fill in the one bits from the
                            // part of the mask not originally calculated.
                            let tmp = 0u64.wrapping_sub(1).wrapping_shl(64 - sa as u32);
                            resmask |= tmp;
                        }
                    }
                    resmask
                }
                None => fullmask,
            },
            // op.cc:633-647
            OpCode::CPUI_INT_SRIGHT => match in_const(1) {
                Some(sa) if out_size <= 8 => {
                    let sa = sa as i32;
                    let resmask = in_nzm(0);
                    if (resmask & (fullmask ^ (fullmask >> 1))) == 0 {
                        // op.cc:639-641: sign bit known zero -> INT_RIGHT.
                        pcode_right(resmask, sa)
                    } else {
                        // op.cc:643-644: unknown new high bits.
                        pcode_right(resmask, sa)
                            | (fullmask.wrapping_shr(sa as u32) ^ fullmask)
                    }
                }
                _ => fullmask,
            },
            // op.cc:648-659
            OpCode::CPUI_INT_DIV => {
                let val = in_nzm(0);
                let mut resmask = crate::address::coveringmask(val);
                if in_const(1).is_some() {
                    // op.cc:651-658: dividing by a power of 2 is equivalent
                    // to a right shift.
                    let sa = crate::address::mostsigbit_set(in_nzm(1));
                    if sa != -1 {
                        resmask >>= sa; // sa in [0,63]
                    }
                }
                resmask
            }
            // op.cc:660-663: result is less than the modulus.
            OpCode::CPUI_INT_REM => {
                let val = in_nzm(1).wrapping_sub(1);
                crate::address::coveringmask(val)
            }
            // op.cc:664-668
            OpCode::CPUI_POPCOUNT => {
                let sz1 = in_nzm(0).count_ones() as i32; // popcount (address.cc:756)
                crate::address::coveringmask(sz1 as u64) & fullmask
            }
            // op.cc:669-672
            OpCode::CPUI_LZCOUNT => {
                crate::address::coveringmask((in_size(0) * 8) as u64) & fullmask
            }
            // op.cc:673-692
            OpCode::CPUI_SUBPIECE => {
                let sz1 = in_const(1).unwrap_or(0) as usize; // op.cc:675
                let mut resmask = in_nzm(0);
                if in_size(0) <= 8 {
                    if sz1 < 8 {
                        resmask >>= 8 * sz1; // op.cc:677-678
                    } else {
                        resmask = 0; // op.cc:680
                    }
                } else {
                    // op.cc:682-690: extended precision.
                    if sz1 < 8 {
                        resmask >>= 8 * sz1;
                        if sz1 > 0 {
                            resmask |= fullmask.wrapping_shl((8 * (8 - sz1)) as u32); // op.cc:686
                        }
                    } else {
                        resmask = fullmask; // op.cc:689
                    }
                }
                resmask & fullmask // op.cc:691
            }
            // op.cc:693-698
            OpCode::CPUI_PIECE => {
                let sa = in_size(1); // op.cc:694
                let resmask = in_nzm(0);
                let shifted = if sa < 8 { resmask << (8 * sa) } else { 0 };
                shifted | in_nzm(1)
            }
            // op.cc:699-731
            OpCode::CPUI_INT_MULT => {
                let val = in_nzm(0);
                let mut resmask = in_nzm(1);
                if out_size > 8 {
                    resmask = fullmask; // op.cc:702-704
                } else {
                    let sz1 = crate::address::mostsigbit_set(val); // op.cc:706
                    let sz2 = crate::address::mostsigbit_set(resmask); // op.cc:707
                    if sz1 == -1 || sz2 == -1 {
                        resmask = 0; // op.cc:708-710
                    } else {
                        let l1 = crate::address::leastsigbit_set(val); // op.cc:712
                        let l2 = crate::address::leastsigbit_set(resmask); // op.cc:713
                        let sa = l1 + l2; // op.cc:714
                        if sa >= (8 * out_size) as i32 {
                            resmask = 0; // op.cc:715-717
                        } else {
                            let w1 = sz1 - l1 + 1; // op.cc:719
                            let w2 = sz2 - l2 + 1; // op.cc:720
                            let mut total = w1 + w2; // op.cc:721
                            if w1 == 1 || w2 == 1 {
                                total -= 1; // op.cc:722-723
                            }
                            resmask = fullmask;
                            if total < (8 * out_size) as i32 {
                                resmask >>= (8 * out_size) as i32 - total; // op.cc:725-726
                            }
                            resmask = (resmask << sa) & fullmask; // op.cc:727
                        }
                    }
                }
                resmask
            }
            // op.cc:732-739
            OpCode::CPUI_INT_ADD => {
                let mut resmask = in_nzm(0);
                if resmask != fullmask {
                    resmask |= in_nzm(1);
                    resmask |= resmask << 1; // account for possible carries
                    resmask &= fullmask;
                }
                resmask
            }
            // op.cc:740-757
            OpCode::CPUI_MULTIEQUAL => {
                if inputs.is_empty() {
                    fullmask // op.cc:741-742
                } else {
                    let mut resmask = 0u64;
                    let parent = parent.as_ref().and_then(|w| w.upgrade());
                    for i in 0..inputs.len() {
                        if cliploop {
                            if let Some(p) = &parent {
                                if p.read().unwrap().is_loop_in(i) {
                                    continue; // op.cc:748-749
                                }
                            }
                        }
                        resmask |= in_nzm(i);
                    }
                    resmask
                }
            }
            // op.cc:758-765
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CPOOLREF => {
                if self.is_calculated_bool() {
                    1 // op.cc:762: output is strictly boolean
                } else {
                    fullmask
                }
            }
            // op.cc:766-768
            _ => fullmask,
        }
    }
}

/// Comparison for sorting PcodeOps in the bank
impl PartialEq for PcodeOp {
    // RUGRA-GLUE: Rust PartialEq impl; Ghidra orders PcodeOps by SeqNum via
    //   std::map<SeqNum,PcodeOp*> (PcodeOpTree, op.hh:280) and has no
    //   operator== on PcodeOp.
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl Eq for PcodeOp {}

impl PartialOrd for PcodeOp {
    // RUGRA-GLUE: delegates to Ord (see below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOp {
    // RUGRA-GLUE: Rust Ord impl mirroring Ghidra's SeqNum ordering used by
    //   PcodeOpTree (op.hh:280 std::map<SeqNum,PcodeOp*>).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

/// Wrapper for Arc<RwLock<PcodeOp>> for use in collections
#[derive(Debug, Clone)]
pub struct PcodeOpRef(pub Arc<RwLock<PcodeOp>>);

impl PartialEq for PcodeOpRef {
    // RUGRA-GLUE: Rust PartialEq impl for the Arc wrapper; Ghidra has no
    //   equivalent (uses raw PcodeOp* pointers).
    fn eq(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) { return true; }
        self.0.read().unwrap().eq(&other.0.read().unwrap())
    }
}

impl Eq for PcodeOpRef {}

impl PartialOrd for PcodeOpRef {
    // RUGRA-GLUE: delegates to Ord (see below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PcodeOpRef {
    // RUGRA-GLUE: Rust Ord impl for the Arc wrapper; delegates to the inner
    //   PcodeOp Ord (SeqNum ordering).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if Arc::ptr_eq(&self.0, &other.0) { return std::cmp::Ordering::Equal; }
        self.0.read().unwrap().cmp(&other.0.read().unwrap())
    }
}

/// Corresponds to Ghidra's `PieceNode` class in `op.hh`
pub struct PieceNode {
    pub piece_op: Weak<RwLock<PcodeOp>>,
    pub slot: i32,
    pub type_offset: i32,
    pub leaf: bool,
}

impl PieceNode {
    // Ghidra: op.hh:268 PieceNode::PieceNode (ctor)
    pub fn new(op: Weak<RwLock<PcodeOp>>, slot: i32, offset: i32) -> Self {
        Self {
            piece_op: op,
            slot,
            type_offset: offset,
            leaf: false,
        }
    }

    // Ghidra: op.hh:269 PieceNode::isLeaf
    pub fn is_leaf(&self) -> bool {
        self.leaf
    }

    // Ghidra: op.hh:270 PieceNode::getTypeOffset
    pub fn get_type_offset(&self) -> i32 {
        self.type_offset
    }

    // Ghidra: op.hh:271 PieceNode::getSlot
    pub fn get_slot(&self) -> i32 {
        self.slot
    }
}

// Ghidra: op.hh:280 PcodeOpTree (typedef map<SeqNum,PcodeOp*>)
/// SeqNum-keyed op tree — the oracle PcodeOpBank's native container form.
///
/// Key order = SeqNum::operator< (address.hh:154-158: `pc` then `uniq`),
/// projected POD as `SeqNumKey { pc: SpaceOff, uniq }` (src/arena.rs,
/// W0-frozen; the `order` field is excluded exactly as `SeqNum::operator<`
/// excludes it). The oracle's iterator is a std::map node iterator: `++`
/// is an O(1) amortized pointer walk and stays valid across insert/erase
/// (action.cc:871 `op_state++` inside ActionPool::apply, :884-885 loop).
/// Rust BTreeMap iterators cannot be held across the Rules' mutation, so
/// Rugra reconstructs the successor by strict-key range (action.rs
/// next_op_after, ACTIONLOOP-RESTART-0001).
///
/// **PERF-ARENA-FLIP-0001 (a) form** (ARENA_DESIGN §1.2): the map values
/// are typed [`OpId`] handles into a slot arena held by this tree; each
/// slot cell carries the op's [`PcodeOpRef`] plus a denormalized copy of
/// its SeqNum key — the id-space form of the oracle's stored map iterator
/// (`PcodeOp::start` is assigned exactly once at create; ffi.rs re-assigns
/// a value-identical SeqNum, so the key copy never drifts). The public
/// surface (insert/remove/contains/iter/range/find_op/target_lower_bound/
/// len/is_empty/clear + `&tree` IntoIterator) is unchanged, so every
/// consumer (action/heritage/merge/comment/coreaction + funcdata
/// forwarders) compiles and observes the identical SeqNum order.
///
/// PERF-ACTIONPOOL-ITER-0001 / OPTREE lane (2026-09-29): the prior form
/// was `BTreeSet<PcodeOpRef>`, whose `Ord for PcodeOpRef` takes one RwLock
/// read per compared side — every successor descent paid 2 locks × O(log n)
/// comparisons (VdbeExec pole: 5,648,144 advances × ~894ns = 5.05s, OPPPOOL
/// §0/§7). The oracle's dispatch mechanism cost over the same pool pass was
/// ~1.2s (OPPPOOL §2, 55-sample gdb profile), so the descent was a ~4×
/// implementation-level gap. This keyed form is the oracle-native shape.
///
/// Behavior-identity contract vs the previous `BTreeMap<SeqNum, PcodeOpRef>`
/// (OPTREE red line: output zero-change):
/// - **iteration order identical**: BTreeMap orders keys by SeqNumKey —
///   the exact projection `Ord for SeqNum` used ((addr, time); the SpaceOff
///   encoding mirrors Address::operator< null-first/index/offset).
/// - **insert dedup identical (keep-first)**: `entry(key)` keeps the stored
///   value when the key exists. (The oracle's `optree[seq] = op`, op.cc:945,
///   REPLACES on a duplicate key; duplicate keys are unreachable through
///   the bank's create paths — uniqid is monotonic and create_with_seq
///   advances it past every supplied time, op.cc:962-963 — so the
///   difference is unobservable in-bank.)
/// - **key staleness impossible on current paths**: the key is the SeqNum
///   (addr,time) snapshot taken at insert; (addr,time) is immutable after
///   creation (only `set_order` mutates the order field, which the
///   ordering excludes). ffi.rs:447 re-assigns `start` with a
///   value-identical SeqNum (same addr/time captured immediately before
///   create), so no in-place key mutation exists.
pub struct PcodeOpTree {
    /// Slot storage: one cell per bank-inserted op (the stored-iterator
    /// arena; cells survive `remove` — the deadandgone retention,
    /// op.cc:984-999 — and are reclaimed only by `clear`).
    arena: Arena<OpCell, OpId>,
    inner: BTreeMap<SeqNumKey, OpId>,
}

/// One arena slot of the op tree.
// RUGRA-GLUE: id-space stored-iterator cell — the oracle equivalent is the
// std::map node itself plus the op's stable pointer identity.
pub struct OpCell {
    op: PcodeOpRef,
    seq_key: SeqNumKey,
    /// Denormalized copy of `PcodeOp::opcode` — the stored-iterator read
    /// form of `op->code()` (op.hh:233, a plain field read in the oracle).
    /// Maintained at exactly the mutation sites of the source field:
    /// `PcodeOpTree::insert`/`slot_only` snapshot it at slot time (the
    /// opcode exists from construction) and `PcodeOpBank::change_opcode`
    /// (the op.cc:1005-1012 choke point behind `Funcdata::opSetOpcode`)
    /// updates it in the same statement that runs `set_opcode_flags`. No
    /// other production site writes `PcodeOp::opcode` (grepped: only
    /// RuleBxor2NotEqual wrote it directly and now routes through
    /// `op_set_opcode`, matching ruleaction.cc:272). PERF-ARENA-FLIP-0001
    /// (c): ActionPool::processOp's per-try `opc != op->code()` re-read
    /// (action.cc:846/853-857, 27.7M tries on the VdbeExec pole) resolves
    /// through this lock-free cell read instead of an RwLock round-trip.
    opcode: OpCode,
    // ---- op.hh:127-129 stored list iterators → id-space intrusive links
    // (ARENA_DESIGN §1.2). The insertiter pair (op.hh:128) threads the op
    // through whichever of deadlist/alivelist/deadandgone holds it; the
    // codeiter pair (op.hh:129) through whichever opcode list (if any).
    ins_prev: OpId,
    ins_next: OpId,
    code_prev: OpId,
    code_next: OpId,
}

// RUGRA-GLUE: link-field projection for the insert chain (the single
// oracle `insertiter`, op.hh:128, id-space form: one prev/next pair shared
// by the dead/alive/deadandgone chains — an op is in exactly one at a time,
// ARENA_DESIGN §1.2 freeze contract in arena.rs `Linked` docs).
/// Marker type projecting [`OpCell`]'s insertion-chain link pair.
pub struct InsLink;
impl Linked for InsLink {
    type Elem = OpCell;
    type Id = OpId;
    // RUGRA-GLUE: link-field accessors (stored iterator read).
    fn prev(t: &OpCell) -> OpId {
        t.ins_prev
    }
    // RUGRA-GLUE: link-field accessors (stored iterator read).
    fn next(t: &OpCell) -> OpId {
        t.ins_next
    }
    // RUGRA-GLUE: link-field accessors (chain surgery write).
    fn set_prev(t: &mut OpCell, id: OpId) {
        t.ins_prev = id;
    }
    // RUGRA-GLUE: link-field accessors (chain surgery write).
    fn set_next(t: &mut OpCell, id: OpId) {
        t.ins_next = id;
    }
}

// RUGRA-GLUE: link-field projection for the opcode chain (the single oracle
// `codeiter`, op.hh:129, id-space form: shared by
// storelist/loadlist/returnlist/useroplist — an op is in at most one).
/// Marker type projecting [`OpCell`]'s opcode-chain link pair.
pub struct CodeLink;
impl Linked for CodeLink {
    type Elem = OpCell;
    type Id = OpId;
    // RUGRA-GLUE: link-field accessors (stored iterator read).
    fn prev(t: &OpCell) -> OpId {
        t.code_prev
    }
    // RUGRA-GLUE: link-field accessors (stored iterator read).
    fn next(t: &OpCell) -> OpId {
        t.code_next
    }
    // RUGRA-GLUE: link-field accessors (chain surgery write).
    fn set_prev(t: &mut OpCell, id: OpId) {
        t.code_prev = id;
    }
    // RUGRA-GLUE: link-field accessors (chain surgery write).
    fn set_next(t: &mut OpCell, id: OpId) {
        t.code_next = id;
    }
}

impl PcodeOpTree {
    // RUGRA-GLUE: Rust ctor; Ghidra constructs PcodeOpTree as a plain
    //   member (op.hh:290, default map ctor).
    pub fn new() -> Self {
        Self {
            arena: Arena::new(),
            inner: BTreeMap::new(),
        }
    }

    // RUGRA-GLUE: POD key projection of a SeqNum — one short read lock per
    // call. SpaceOff mirrors Address::operator< (null base first, then
    // registry index, then offset; ARENA_DESIGN §2 single projection site).
    fn key_from_seq(seq: &SeqNum) -> SeqNumKey {
        SeqNumKey::new(
            crate::varnode::space_off_of_address(&seq.get_addr()),
            seq.get_time() as u64,
        )
    }

    // RUGRA-GLUE: snapshot of the op's SeqNum key (op.hh:280 map key;
    //   ordering address.hh:154).
    fn key_of(op: &PcodeOpRef) -> SeqNumKey {
        Self::key_from_seq(&op.0.read().unwrap().start)
    }

    // Ghidra: op.cc:941 PcodeOpBank::create (optree[op->getSeqNum()] = op, cc:945)
    /// Insert an op keyed by its SeqNum. Keep-first on a duplicate key,
    /// identical to the former BTreeSet<BTreeMap> insert. Returns true
    /// when newly inserted.
    pub fn insert(&mut self, op: PcodeOpRef) -> bool {
        // Single-guard snapshot of everything the cell denormalizes: the
        // SeqNum key projection, the stored op_id, and the opcode shadow
        // (one read lock where the former form took key_of + op_id reads
        // separately). The guard is bound to its own statement and dropped
        // before the writes below — holding a read guard into a same-thread
        // write is a guaranteed RwLock deadlock.
        let (seq_key, existing_id, opc) = {
            let o = op.0.read().unwrap();
            (Self::key_from_seq(&o.start), o.op_id, o.opcode)
        };
        // Slot the op (reuse its cell on re-insert; the SeqNum is
        // immutable so the key copy never drifts). Fresh cells enter the
        // arena with detached chain links (op.hh:127-129 iterators are
        // unset until the bank links the op).
        let id = if existing_id.is_some_and(|id| self.arena.contains(id)) {
            let id = existing_id.expect("checked by is_some_and");
            if let Some(cell) = self.arena.get_mut(id) {
                cell.seq_key = seq_key;
                cell.opcode = opc;
            }
            id
        } else {
            let id = self.arena.insert(OpCell {
                op: op.clone(),
                seq_key,
                opcode: opc,
                ins_prev: OpId::SENTINEL,
                ins_next: OpId::SENTINEL,
                code_prev: OpId::SENTINEL,
                code_next: OpId::SENTINEL,
            });
            op.0.write().unwrap().op_id = Some(id);
            id
        };
        match self.inner.entry(seq_key) {
            std::collections::btree_map::Entry::Occupied(_) => false,
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(id);
                true
            }
        }
    }

    // Ghidra: op.cc:989 PcodeOpBank::destroy (optree.erase, cc:995)
    /// Remove the op stored under its SeqNum key. Stored-key fast path
    /// (the cell's denormalized key copy — the oracle's stored-iterator
    /// erase), then the live-key path the former BTreeMap used; both hit
    /// the same entry on every in-bank input (keys are unique and
    /// immutable). The cell itself is retained (deadandgone semantics).
    pub fn remove(&mut self, op: &PcodeOpRef) -> bool {
        if let Some(id) = op.0.read().unwrap().op_id {
            if let Some(cell) = self.arena.get(id) {
                let stored_key = cell.seq_key;
                if let Some(rid) = self.inner.remove(&stored_key) {
                    if rid == id {
                        return true;
                    }
                    // The stored key routed to a different op's entry:
                    // restore before the live-key path so only `op`'s
                    // entry can be removed.
                    self.inner.insert(stored_key, rid);
                }
            }
        }
        self.inner.remove(&Self::key_of(op)).is_some()
    }

    // RUGRA-GLUE: BTreeSet<PcodeOpRef>::contains surface. Ord-equality
    //   against the stored element reduces to the SeqNum key being present
    //   (same result the keyed map reports).
    pub fn contains(&self, op: &PcodeOpRef) -> bool {
        self.inner.contains_key(&Self::key_of(op))
    }

    // Ghidra: op.cc:1194 PcodeOpBank::clear (op.cc:1205 optree.clear())
    pub fn clear(&mut self) {
        self.inner.clear();
        self.arena.clear();
    }

    // RUGRA-GLUE: size surface shared by BTreeSet/BTreeMap (op.cc:1194
    //   clear() observes the same cardinality).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    // Ghidra: op.hh:318 PcodeOpBank::empty (optree.empty())
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    // Ghidra: op.hh:324 PcodeOpBank::beginAll (optree.begin()) /
    //   op.hh:327 endAll (optree.end())
    /// All ops in SeqNum order — the beginAll()/endAll() pair as one
    /// iterator over the stored values.
    pub fn iter(&self) -> PcodeOpTreeIter<'_> {
        PcodeOpTreeIter { arena: &self.arena, ids: self.inner.values() }
    }

    // RUGRA-GLUE: translates a PcodeOpRef range bound to its SeqNumKey
    //   bound (one read lock per bound), so the tree descent itself runs on
    //   plain key compares with no locks.
    fn translate_bound(bound: std::ops::Bound<&PcodeOpRef>) -> std::ops::Bound<SeqNumKey> {
        match bound {
            std::ops::Bound::Included(op) => std::ops::Bound::Included(Self::key_of(op)),
            std::ops::Bound::Excluded(op) => std::ops::Bound::Excluded(Self::key_of(op)),
            std::ops::Bound::Unbounded => std::ops::Bound::Unbounded,
        }
    }

    // Ghidra: action.cc:822 ActionPool::processOp (op_state++ successor, cc:871)
    /// Strict-successor range in the tuple-bound form the dispatch pool
    /// uses (`range((Excluded(current), Unbounded))`, action.rs
    /// next_op_after) — the reconstruction of the oracle's O(1) map
    /// iterator `++` that stays valid across Rule mutation. The descent
    /// compares SeqNum values directly (oracle map key compares), no locks.
    pub fn range(
        &self,
        bounds: (std::ops::Bound<&PcodeOpRef>, std::ops::Bound<&PcodeOpRef>),
    ) -> PcodeOpTreeRange<'_> {
        let lower = Self::translate_bound(bounds.0);
        let upper = Self::translate_bound(bounds.1);
        PcodeOpTreeRange {
            arena: &self.arena,
            ids: self.inner.range((lower, upper)),
        }
    }

    // Ghidra: op.cc:1099 PcodeOpBank::findOp (optree.find(num), cc:1102)
    /// Exact-key find (O(log n)) — the oracle's map find.
    pub fn find_op(&self, seq: &SeqNum) -> Option<&PcodeOpRef> {
        self.inner
            .get(&Self::key_from_seq(seq))
            .and_then(|id| self.arena.get(*id).map(|cell| &cell.op))
    }

    // Ghidra: op.cc:1089 PcodeOpBank::target (optree.lower_bound, cc:1092)
    /// All ops at or after `addr` in tree order — the oracle's
    /// lower_bound(SeqNum(addr,0)) iteration; the first entry is exactly
    /// the former linear scan's first `start.addr >= addr` hit (tree order
    /// is (addr,time), time >= 0 always).
    pub fn target_lower_bound(&self, addr: Address) -> PcodeOpTreeRange<'_> {
        let lower = std::ops::Bound::Included(SeqNumKey::new(
            crate::varnode::space_off_of_address(&addr),
            0,
        ));
        PcodeOpTreeRange {
            arena: &self.arena,
            ids: self.inner.range((lower, std::ops::Bound::Unbounded)),
        }
    }

    // RUGRA-GLUE: resolve an OpId to its stored handle (the W1(b) god-object
    //   read API's underlying lookup; P1 pattern of ARENA_DESIGN §3.2).
    pub fn get_by_id(&self, id: OpId) -> Option<&PcodeOpRef> {
        self.arena.get(id).map(|cell| &cell.op)
    }

    // RUGRA-GLUE: id-space cursor support for ActionPool::op_state — the
    //   oracle retains a live `PcodeOpTree::const_iterator` (action.hh:265
    //   op_state) whose begin/`++` are O(1) pointer walks. The id-space
    //   reconstruction reads the CURRENT cell's denormalized seq_key
    //   (lock-free; no op guard) and asks the map for the strict successor
    //   — identical to `++` on a std::map iterator because the successor
    //   of key K in the live map is the first entry > K regardless of any
    //   erasures the Rules performed in between (the same argument
    //   ACTIONLOOP-RESTART-0001 made for the handle-keyed range).
    //   PERF-ARENA-FLIP-0001 (c): the former form re-read the current op's
    //   SeqNum under an RwLock guard per advance (5.6M advances on the
    //   VdbeExec pole) and cloned the successor's Arc.
    /// First map entry's id (beginOpAll), or `None` when the tree is empty.
    pub fn first_id(&self) -> Option<OpId> {
        self.inner.values().next().copied()
    }

    // RUGRA-GLUE: strict-successor reconstruction (same RUGRA-GLUE family
    //   as first_id above — the retained iterator's ++ in id space).
    /// Strict-successor id of `cur` in SeqNum order (the `++` of the
    /// oracle's retained map iterator); `None` at endOpAll.
    pub fn next_id_after(&self, cur: OpId) -> Option<OpId> {
        use std::ops::Bound::Excluded;
        let key = self.arena.get(cur)?.seq_key;
        self.inner
            .range((Excluded(key), std::ops::Bound::Unbounded))
            .next()
            .map(|(_, &id)| id)
    }

    // RUGRA-GLUE: stored-iterator opcode read — `op->code()` (op.hh:233)
    //   resolved through the cell's denormalized shadow, no lock. The
    //   shadow is maintained at the field's only mutation sites (see the
    //   OpCell::opcode field doc).
    /// The op's current opcode, read lock-free from the arena cell.
    pub fn opcode_by_id(&self, id: OpId) -> Option<OpCode> {
        self.arena.get(id).map(|cell| cell.opcode)
    }

    // RUGRA-GLUE: shared-borrow arena accessor — the bank chains live in
    //   arena cells, so PcodeOpBank iteration/navigation needs this (the
    //   oracle chains dereference the PcodeOp* directly; id-space chains
    //   resolve through the one arena both structures share, ARENA_DESIGN
    //   §1.2 OpArena).
    pub(crate) fn arena(&self) -> &Arena<OpCell, OpId> {
        &self.arena
    }

    // RUGRA-GLUE: exclusive-borrow arena accessor for chain surgery
    //   (PcodeOpBank splits its optree/list field borrows — ARENA_DESIGN
    //   §3.2 P3).
    pub(crate) fn arena_mut(&mut self) -> &mut Arena<OpCell, OpId> {
        &mut self.arena
    }

    // RUGRA-GLUE: slot a foreign op into the arena WITHOUT entering the
    //   SeqNum map — the bank-API replacement for the legacy test
    //   fixtures' bare `alivelist.push(PcodeOpRef(raw_arc))` bypasses.
    //   The op becomes chain-linkable while the optree map (and every
    //   map-derived observation: len/find/iteration) stays untouched,
    //   exactly as the bare push left it. Idempotent: a re-slot of an
    //   already-slotted op returns its existing handle.
    pub(crate) fn slot_only(&mut self, op: &PcodeOpRef) -> OpId {
        let (existing, opc, seq_key) = {
            let o = op.0.read().unwrap();
            (o.op_id, o.opcode, Self::key_from_seq(&o.start))
        };
        if let Some(id) = existing {
            if self.arena.contains(id) {
                return id;
            }
        }
        let id = self.arena.insert(OpCell {
            op: op.clone(),
            seq_key,
            opcode: opc,
            ins_prev: OpId::SENTINEL,
            ins_next: OpId::SENTINEL,
            code_prev: OpId::SENTINEL,
            code_next: OpId::SENTINEL,
        });
        op.0.write().unwrap().op_id = Some(id);
        id
    }
}

// RUGRA-GLUE: named value iterators — the BTreeMap::Values / ::Range
// surface without exposing OpId or the cell type in any public signature.
/// Forward iterator over [`PcodeOpTree`] values, in SeqNum order.
pub struct PcodeOpTreeIter<'a> {
    arena: &'a Arena<OpCell, OpId>,
    ids: std::collections::btree_map::Values<'a, SeqNumKey, OpId>,
}
impl<'a> Iterator for PcodeOpTreeIter<'a> {
    type Item = &'a PcodeOpRef;
    // RUGRA-GLUE: trait plumbing (advance follows the map value then
    // resolves the arena cell).
    fn next(&mut self) -> Option<Self::Item> {
        self.ids
            .next()
            .and_then(|id| self.arena.get(*id).map(|cell| &cell.op))
    }
    // RUGRA-GLUE: trait plumbing (size hint pass-through).
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

/// Bounded range iterator over [`PcodeOpTree`] values.
pub struct PcodeOpTreeRange<'a> {
    arena: &'a Arena<OpCell, OpId>,
    ids: std::collections::btree_map::Range<'a, SeqNumKey, OpId>,
}

impl<'a> Iterator for PcodeOpTreeRange<'a> {
    type Item = &'a PcodeOpRef;
    // RUGRA-GLUE: trait plumbing (advance follows the map value then
    // resolves the arena cell).
    fn next(&mut self) -> Option<Self::Item> {
        self.ids
            .next()
            .and_then(|(_, id)| self.arena.get(*id).map(|cell| &cell.op))
    }
    // RUGRA-GLUE: trait plumbing (size hint pass-through).
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}

impl Default for PcodeOpTree {
    // RUGRA-GLUE: Default = new() (clippy::new_without_default).
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OpChainIter — forward walk over one bank chain (PERF-ARENA-FLIP-0001 (b))
// ---------------------------------------------------------------------------

/// Which embedded link pair a chain walk follows.
// RUGRA-GLUE: the two stored iterator pairs (op.hh:128 insertiter vs
// op.hh:129 codeiter) select the chain family; the specific chain within
/// a family is fixed by the start node (its members thread one pair).
#[derive(Clone, Copy)]
enum ChainKind {
    Ins,
    Code,
}

/// Forward iterator over one membership chain, yielding `&PcodeOpRef` in
/// exact chain order — the oracle `list<PcodeOp*>::const_iterator` walk
/// (`beginOpAlive`/`beginOpDead`/`begin(OpCode)`, funcdata.hh:506-512 /
/// op.cc:1158). The advance follows the same stored next link the frozen
/// [`crate::arena::IdList`] chains thread; slot order is never observable
/// (ARENA_DESIGN §8.3).
pub struct OpChainIter<'a> {
    arena: &'a Arena<OpCell, OpId>,
    kind: ChainKind,
    cur: OpId,
}

impl<'a> OpChainIter<'a> {
    // RUGRA-GLUE: constructor over the insert-link family.
    fn ins(arena: &'a Arena<OpCell, OpId>, head: OpId) -> Self {
        OpChainIter { arena, kind: ChainKind::Ins, cur: head }
    }

    // RUGRA-GLUE: constructor over the code-link family.
    fn code(arena: &'a Arena<OpCell, OpId>, head: OpId) -> Self {
        OpChainIter { arena, kind: ChainKind::Code, cur: head }
    }

    // RUGRA-GLUE: empty walk (the former `[].iter()` end-sentinel stub).
    pub(crate) fn empty(arena: &'a Arena<OpCell, OpId>) -> Self {
        OpChainIter { arena, kind: ChainKind::Ins, cur: OpId::SENTINEL }
    }

    // RUGRA-GLUE: continue the walk from a raw member id (marker form).
    /// Iterate the insert-chain from `start` (inclusive) to the chain
    /// tail; the sentinel yields nothing.
    pub fn from_id(arena: &'a Arena<OpCell, OpId>, start: OpId) -> Self {
        OpChainIter { arena, kind: ChainKind::Ins, cur: start }
    }
}

impl<'a> Iterator for OpChainIter<'a> {
    type Item = &'a PcodeOpRef;

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (iterator advance =
    // stored next link dereference; end() is the sentinel).
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.is_sentinel() {
            return None;
        }
        let id = self.cur;
        let cell = self.arena.get(id).expect("bank chain node vanished while iterating");
        self.cur = match self.kind {
            ChainKind::Ins => cell.ins_next,
            ChainKind::Code => cell.code_next,
        };
        Some(&cell.op)
    }
}

impl std::iter::FusedIterator for OpChainIter<'_> {}

// RUGRA-GLUE: id-yielding companion of [`OpChainIter`] — the same stored-link
//   walk handing out the member [`OpId`] instead of the `&PcodeOpRef`
//   (PERF-ARENA-FLIP-0001 (c) P1 read-mode: Action/Rule worksets collect
//   plain Copy ids with no handle clone and no lock, and resolve elements
//   through `PcodeOpBank::op_by_id`/`opcode_of` at their use sites).
pub struct OpChainIdIter<'a> {
    arena: &'a Arena<OpCell, OpId>,
    kind: ChainKind,
    cur: OpId,
}

impl<'a> OpChainIdIter<'a> {
    // RUGRA-GLUE: constructor over the insert-link family.
    fn ins(arena: &'a Arena<OpCell, OpId>, head: OpId) -> Self {
        OpChainIdIter { arena, kind: ChainKind::Ins, cur: head }
    }

    // RUGRA-GLUE: constructor over the code-link family.
    fn code(arena: &'a Arena<OpCell, OpId>, head: OpId) -> Self {
        OpChainIdIter { arena, kind: ChainKind::Code, cur: head }
    }
}

impl<'a> Iterator for OpChainIdIter<'a> {
    type Item = OpId;

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (iterator advance =
    // stored next link dereference; end() is the sentinel).
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.is_sentinel() {
            return None;
        }
        let id = self.cur;
        let cell = self.arena.get(id).expect("bank chain node vanished while iterating");
        self.cur = match self.kind {
            ChainKind::Ins => cell.ins_next,
            ChainKind::Code => cell.code_next,
        };
        Some(id)
    }
}

impl std::iter::FusedIterator for OpChainIdIter<'_> {}

// RUGRA-GLUE: set-shaped Debug (the former derive printed the keyed map;
// consumers only ever see the element sequence).
impl std::fmt::Debug for PcodeOpTree {
    // RUGRA-GLUE: trait impl (Debug formatting; no Ghidra counterpart).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

// RUGRA-GLUE: IntoIterator on &PcodeOpTree so `for op in &bank.optree`
//   keeps the keyed-map surface at every existing call site
//   (heritage/merge/funcdata/comment/flow/ffi/align/examples).
impl<'a> IntoIterator for &'a PcodeOpTree {
    type Item = &'a PcodeOpRef;
    type IntoIter = PcodeOpTreeIter<'a>;
    // RUGRA-GLUE: trait-impl forwarder to iter().
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Container for managing P-code operations
///
/// Corresponds to Ghidra's `PcodeOpBank` class in `op.hh`
///
/// The seven membership chains are intrusive id chains (op.hh:291-297
/// `list<PcodeOp*>` mirrors): each op's arena cell carries the link pair
/// (the stored `insertiter`/`codeiter`, op.hh:128-129), so every move is
/// O(1) chain surgery — `markAlive`/`markDead` are the op.cc:1017-1034
/// erase+tail-insert pair, never an O(n) scan (PERF-ARENA-FLIP-0001 (b)).
pub struct PcodeOpBank {
    /// All operations sorted by sequence number (Ghidra optree).
    pub optree: PcodeOpTree,
    /// Chain of operations considered "alive" (Ghidra alivelist,
    /// op.hh:292) — iteration is `iter_alive()`, chain order.
    pub alivelist: IdList<InsLink>,
    /// Chain of operations considered "dead" (Ghidra deadlist, op.hh:291)
    /// — iteration is `iter_dead()`, chain order.
    pub deadlist: IdList<InsLink>,
    /// Chain of retired PcodeOps (Ghidra deadandgone, op.hh:297).
    /// PcodeOpBank::destroy removes the op from every index but KEEPS its
    /// allocation alive here until clear() — Ghidra's op.cc:984-999 comment:
    /// "The memory is not reclaimed until the whole container is destroyed,
    /// in case pointer references still exist. These will all still be
    /// marked as dead." The dangling references are the iop-space constants
    /// that encode `Arc::as_ptr` (Funcdata::get_op_from_const decodes them
    /// back into handles); without the retention, the freed chunk's tcache
    /// metadata overwrites the Arc counts/inrefs and a later fabricated
    /// handle double-drops garbage (HTTPD-FULL-SEGV: ap_content_length_filter
    /// SIGSEGV inside RuleIndirectCollapse's indop drop at the dead-indop
    /// totalReplace path).
    pub deadandgone: IdList<InsLink>,

    /// Chains of ops by specific opcode (Ghidra op.hh:293-296).
    /// Used for fast iteration over STORE/LOAD/RETURN/CALLOTHER ops.
    pub storelist: IdList<CodeLink>,
    pub loadlist: IdList<CodeLink>,
    pub returnlist: IdList<CodeLink>,
    pub useroplist: IdList<CodeLink>,

    /// Internal unique ID counter for sequence numbers (Ghidra uniqid).
    uniqid: u32,
}

// RUGRA-GLUE: set-shaped Debug (chain lengths only — IdList has no element
//   iteration without the arena, and debug formatting must not become an
//   API that exposes slot order).
impl std::fmt::Debug for PcodeOpBank {
    // RUGRA-GLUE: trait impl (Debug formatting; no Ghidra counterpart).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcodeOpBank")
            .field("optree", &self.optree)
            .field("alivelist", &self.alivelist.len())
            .field("deadlist", &self.deadlist.len())
            .field("deadandgone", &self.deadandgone.len())
            .field("storelist", &self.storelist.len())
            .field("loadlist", &self.loadlist.len())
            .field("returnlist", &self.returnlist.len())
            .field("useroplist", &self.useroplist.len())
            .finish()
    }
}

impl PcodeOpBank {
    // Ghidra: op.hh:304 PcodeOpBank::PcodeOpBank (ctor; uniqid = 0)
    pub fn new() -> Self {
        Self {
            optree: PcodeOpTree::new(),
            alivelist: IdList::new(),
            deadlist: IdList::new(),
            deadandgone: IdList::new(),
            storelist: IdList::new(),
            loadlist: IdList::new(),
            returnlist: IdList::new(),
            useroplist: IdList::new(),
            uniqid: 0,
        }
    }

    // RUGRA-GLUE: stored-iterator resolution — the op's own id is the
    //   oracle's stored `insertiter`/`codeiter` carrier (op.hh:127-129).
    //   Bank-created ops are always slotted (create inserts the optree
    //   cell first); adopt_alive_op slots foreign handles. Returns None
    //   for an unslotted handle, which chain surgery treats as "not in
    //   any chain" (the exact set the former ptr scans missed).
    fn slot_of(&self, op: &PcodeOpRef) -> Option<OpId> {
        let id = op.0.read().unwrap().op_id?;
        self.optree.arena().get(id)?;
        Some(id)
    }

    // RUGRA-GLUE: slot-of with adopt fallback — marks/moves on a foreign
    //   (unslotted) handle first give it a cell, then link it, matching
    //   the former Vec behavior where mark_alive/mark_dead pushed any
    //   passed op into the target list.
    fn slot_of_or_adopt(&mut self, op: &PcodeOpRef) -> OpId {
        if let Some(id) = self.slot_of(op) {
            return id;
        }
        self.optree.slot_only(op)
    }

    /// Create a new P-code operation and add it to the bank
    // Ghidra: op.hh:308 PcodeOpBank::create (op.cc:941-948)
    pub fn create(&mut self, opcode: OpCode, num_inputs: usize, addr: Address) -> PcodeOpRef {
        let seq = SeqNum::new(addr, self.uniqid);
        self.uniqid += 1;

        let mut op = PcodeOp::new(seq, opcode);
        // cc:944 PcodeOp(inputs,SeqNum): sets flags=0, opcode=null.
        // Rugra's PcodeOp::new takes an opcode, so we must apply TypeOp-derived
        // flags here (Ghidra defers this to a later setOpcode call). Without
        // this, get_eval_type() returns 0 for all arithmetic ops, breaking
        // collapse/execute_simple/get_cse_hash/is_moveable.
        op.set_opcode_flags(opcode);
        // Inputs will be populated later
        op.inrefs.reserve(num_inputs);

        let op_ref = PcodeOpRef(Arc::new(RwLock::new(op)));
        self.optree.insert(op_ref.clone());
        // Ghidra cc:941-948 PcodeOpBank::create allocates WITHOUT an
        // opcode; every op's opcode is later assigned via
        // Funcdata::opSetOpcode -> changeOpcode (op.cc:1005-1012), whose
        // addToCodeList (op.cc:881-900) registers STORE/LOAD/RETURN/
        // CALLOTHER ops into their opcode-specific lists exactly once, in
        // assignment order. Rugra's create() takes the opcode directly, so
        // the same registration must happen HERE to preserve Ghidra's
        // invariant that a code-list-worthy op is in its list from the
        // moment its opcode exists — otherwise ops born through this path
        // (e.g. inject_raw_ops) are invisible to begin_op(RETURN/LOAD/
        // STORE/CALLOTHER) consumers: ActionReturnRecovery's RETURN walk
        // (coreaction.cc:1919-1921) found zero RETURNs and every unlocked
        // return value in the httpd corpus collapsed to `return;` with a
        // void signature. change_opcode (op.cc:1005) still removes from the
        // old list before re-adding, so a later op_set_opcode on the same
        // op cannot double-register.
        self.add_to_code_list(&op_ref);
        // Ghidra cc:946-947: setFlag(dead) + insert into deadlist.
        // Rugra historically inserts into alivelist (treats create as alive).
        // Changing this to deadlist would break many callers that assume
        // create ⇒ alive; the dead/alive distinction is preserved via
        // mark_alive/mark_dead, so semantics are functionally equivalent.
        let id = self.slot_of(&op_ref).expect("create slots the op");
        let Self { optree, alivelist, .. } = self;
        alivelist.push_back(&mut optree.arena_mut(), id);
        op_ref
    }

    // Ghidra: op.cc:941 PcodeOpBank::create (op.cc:962-963 uniqid tail of the SeqNum form)
    /// CANON-DECLORDER-TRANSPORT-0001 form: `create` with an explicit
    /// SeqNum (the op.cc:957 clone-form's numbering) while keeping THIS
    /// bank's full create-side state — the TypeOp flags, the code-list
    /// registration, and the historical alivelist insertion (create ⇒
    /// alive; the mark_alive/mark_dead cycle preserves the dead/alive
    /// distinction — see `create`). The uniqid counter still advances
    /// past the supplied time (op.cc:962-963) so every later create stays
    /// above it, keeping pipeline-created op times later than all
    /// injected ones, exactly as the oracle's post-walk bank does.
    pub fn create_with_seq(&mut self, opcode: OpCode, num_inputs: usize, seq: crate::address::SeqNum) -> PcodeOpRef {
        if seq.get_time() >= self.uniqid {
            self.uniqid = seq.get_time() + 1;
        }
        let mut op = PcodeOp::new(seq, opcode);
        op.set_opcode_flags(opcode);
        op.inrefs.reserve(num_inputs);
        let op_ref = PcodeOpRef(Arc::new(RwLock::new(op)));
        self.optree.insert(op_ref.clone());
        self.add_to_code_list(&op_ref);
        let id = self.slot_of(&op_ref).expect("create slots the op");
        let Self { optree, alivelist, .. } = self;
        alivelist.push_back(&mut optree.arena_mut(), id);
        op_ref
    }

    // Ghidra: op.hh:313 PcodeOpBank::markAlive
    pub fn mark_alive(&mut self, op: PcodeOpRef) {
        if (op.0.read().unwrap().flags & pcodeop_flags::DEAD) == 0 {
            return;
        }
        op.0.write().unwrap().flags &= !pcodeop_flags::DEAD;
        // Ghidra op.cc:1017-1022 markAlive: deadlist.erase(op->insertiter)
        // is O(1) via the stored insertiter (op.cc:1019), then
        // alivelist.insert(end). The id-space link pair IS the stored
        // iterator: unlink + push_back is the same O(1) surgery with no
        // scan (PERF-ARENA-FLIP-0001 (b): the VARMAPOPCREATE retain floor
        // measured 207,611 passes / 5.58s is deleted with this rewrite).
        // The membership guard covers foreign handles (legacy fixtures
        // pass raw, never-linked ops): the oracle's erase happens through
        // the op's OWN stored iterator, which such an op does not have —
        // the former retain was a no-op there, and the guard is too.
        let id = self.slot_of_or_adopt(&op);
        let Self { optree, deadlist, alivelist, .. } = self;
        if deadlist.contains(optree.arena(), id) {
            deadlist.unlink(&mut optree.arena_mut(), id);
        }
        alivelist.push_back(&mut optree.arena_mut(), id);
    }

    // Ghidra: op.hh:314 PcodeOpBank::markDead
    pub fn mark_dead(&mut self, op: PcodeOpRef) {
        if (op.0.read().unwrap().flags & pcodeop_flags::DEAD) != 0 {
            return;
        }
        op.0.write().unwrap().flags |= pcodeop_flags::DEAD;
        // Ghidra op.cc:1028-1034 markDead: alivelist.erase(op->insertiter)
        // is O(1) via the stored insertiter (op.cc:1030), then
        // deadlist.insert(end). Same stored-iterator surgery as mark_alive
        // (membership guard: see mark_alive).
        let id = self.slot_of_or_adopt(&op);
        let Self { optree, deadlist, alivelist, .. } = self;
        if alivelist.contains(optree.arena(), id) {
            alivelist.unlink(&mut optree.arena_mut(), id);
        }
        deadlist.push_back(&mut optree.arena_mut(), id);
    }

    // Ghidra: op.cc:881 PcodeOpBank::addToCodeList
    /// Add op to opcode-specific list (STORE/LOAD/RETURN/CALLOTHER).
    /// Faithful to `addToCodeList` (op.cc:881-900): each arm is the
    /// `codeiter = list.insert(list.end(), op)` stored-iterator tail push.
    pub fn add_to_code_list(&mut self, op: &PcodeOpRef) {
        let opc = op.0.read().unwrap().opcode;
        if !matches!(
            opc,
            OpCode::CPUI_STORE
                | OpCode::CPUI_LOAD
                | OpCode::CPUI_RETURN
                | OpCode::CPUI_CALLOTHER
        ) {
            return;
        }
        let id = self.slot_of_or_adopt(op);
        let Self { optree, storelist, loadlist, returnlist, useroplist, .. } = self;
        let arena = &mut optree.arena_mut();
        match opc {
            OpCode::CPUI_STORE => storelist.push_back(arena, id),
            OpCode::CPUI_LOAD => loadlist.push_back(arena, id),
            OpCode::CPUI_RETURN => returnlist.push_back(arena, id),
            OpCode::CPUI_CALLOTHER => useroplist.push_back(arena, id),
            _ => unreachable!("guarded above"),
        }
    }

    // Ghidra: op.cc:905 PcodeOpBank::removeFromCodeList
    /// Remove op from its opcode-specific list.
    /// Faithful to `removeFromCodeList` (op.cc:905-924): each arm is the
    /// `list.erase(op->codeiter)` stored-iterator O(1) erase. An unslotted
    /// or unlinked op is a guarded no-op (the former retain found nothing).
    pub fn remove_from_code_list(&mut self, op: &PcodeOpRef) {
        let opc = op.0.read().unwrap().opcode;
        let Some(id) = self.slot_of(op) else { return };
        let Self { optree, storelist, loadlist, returnlist, useroplist, .. } = self;
        let arena = optree.arena();
        let member = match opc {
            OpCode::CPUI_STORE => storelist.contains(arena, id),
            OpCode::CPUI_LOAD => loadlist.contains(arena, id),
            OpCode::CPUI_RETURN => returnlist.contains(arena, id),
            OpCode::CPUI_CALLOTHER => useroplist.contains(arena, id),
            _ => return,
        };
        if !member {
            return;
        }
        let arena = &mut optree.arena_mut();
        match opc {
            OpCode::CPUI_STORE => storelist.unlink(arena, id),
            OpCode::CPUI_LOAD => loadlist.unlink(arena, id),
            OpCode::CPUI_RETURN => returnlist.unlink(arena, id),
            OpCode::CPUI_CALLOTHER => useroplist.unlink(arena, id),
            _ => unreachable!("guarded above"),
        }
    }

    // Ghidra: op.cc:926 PcodeOpBank::clearCodeLists
    pub fn clear_code_lists(&mut self) {
        let Self { optree, storelist, loadlist, returnlist, useroplist, .. } = self;
        let arena = &mut optree.arena_mut();
        storelist.clear(arena);
        loadlist.clear(arena);
        returnlist.clear(arena);
        useroplist.clear(arena);
    }

    // Ghidra: op.hh:312 PcodeOpBank::changeOpcode
    /// Change opcode: remove from old code list, set new opcode + flags, add to new list.
    /// Faithful to `changeOpcode` (op.cc:1005-1012). Ghidra guards the removal
    /// with `if (op->opcode != 0)`; Rugra's OpCode is non-nullable, so removal
    /// is unconditional when the op might have been in a list. cc:1010 calls
    /// `op->setOpcode(newopc)` which sets opcode + cached flags; Rugra uses
    /// `set_opcode_flags` for the same effect.
    pub fn change_opcode(&mut self, op: PcodeOpRef, new_opc: OpCode) {
        // cc:1008-1009: remove from old opcode's code list (uses current opcode).
        self.remove_from_code_list(&op);
        // cc:1010: op->setOpcode(newopc) — sets opcode + TypeOp-derived flags.
        op.0.write().unwrap().set_opcode_flags(new_opc);
        // Stored-iterator shadow update in the same statement position the
        // oracle's setOpcode writes the field (op.cc:1010): the cell's
        // denormalized opcode copy stays equal to `PcodeOp::opcode` at its
        // single choke point, so lock-free `opcode_by_id` reads (the pool
        // dispatch's per-try re-read, action.cc:846/853-857) observe the
        // same value a guarded read would.
        if let Some(id) = self.slot_of(&op) {
            if let Some(cell) = self.optree.arena_mut().get_mut(id) {
                cell.opcode = new_opc;
            }
        }
        // cc:1011: addToCodeList(op) — uses new opcode.
        self.add_to_code_list(&op);
    }

    // Ghidra: op.hh:311 PcodeOpBank::destroyDead
    pub fn destroy_dead(&mut self) {
        // cc:977-981: iterate the deadlist, destroy each op. cc:980 destroy()
        // erases it from optree/deadlist and RETIRES it into deadandgone —
        // the allocation stays valid until clear() so iop-encoded pointers
        // remain readable. The oracle walks with a live list iterator
        // (`op = *iter++` before `destroy(op)`); the id-space walk captures
        // each node's `ins_next` before destroying it, which is the same
        // stored-iterator advance (erase of the current node never disturbs
        // a successor handle).
        loop {
            let Some(cur) = self.deadlist.head() else { break };
            let next = self
                .optree
                .arena()
                .get(cur)
                .map(|cell| cell.ins_next);
            let Some(op) = self.optree.get_by_id(cur).cloned() else { break };
            self.destroy(op);
            if next.is_none_or(|id| id.is_sentinel()) {
                break;
            }
        }
    }

    // Ghidra: op.hh:310 PcodeOpBank::destroy
    pub fn destroy(&mut self, op: PcodeOpRef) {
        self.optree.remove(&op);
        // cc:992-996: Ghidra throws on a non-dead op and erases ONLY the
        // deadlist entry (via the stored insertiter). An op is in exactly one
        // of alivelist/deadlist (markAlive/markDead move it), so branching on
        // the dead flag reproduces the single-list erase without scanning
        // both lists per destroyed op (ActionDeadCode destroys in bulk).
        // Unlinked/unslotted ops fall through the guarded unlink no-ops
        // (the former retains found nothing) and still retire below.
        if let Some(id) = self.slot_of(&op) {
            let is_dead = op.0.read().unwrap().is_dead();
            let Self { optree, deadlist, alivelist, .. } = self;
            let arena = optree.arena();
            if is_dead {
                if deadlist.contains(arena, id) {
                    deadlist.unlink(&mut optree.arena_mut(), id);
                }
            } else if alivelist.contains(arena, id) {
                alivelist.unlink(&mut optree.arena_mut(), id);
            }
        }
        self.remove_from_code_list(&op);
        // cc:998: deadandgone.push_back(op) — retire, never free mid-run.
        let id = self.slot_of_or_adopt(&op);
        let Self { optree, deadandgone, .. } = self;
        deadandgone.push_back(&mut optree.arena_mut(), id);
    }

    // Ghidra: op.hh:320 PcodeOpBank::findOp
    // Ghidra: op.cc:1099 PcodeOpBank::findOp
    /// Find a PcodeOp by sequence number. Faithful to `findOp`
    /// (op.cc:1099-1105): map find on the SeqNum key, O(log n). (The prior
    /// form was a linear scan over the tree; the result is identical —
    /// keys are unique post-dedup and key equality (addr,time) is exactly
    /// the SeqNum PartialEq the scan used.)
    pub fn find_op(&self, seq: &SeqNum) -> Option<PcodeOpRef> {
        self.optree.find_op(seq).cloned()
    }

    // Ghidra: op.hh:303 PcodeOpBank::clear
    // Ghidra: op.cc:1194 PcodeOpBank::clear
    pub fn clear(&mut self) {
        // cc:1199-1204 walk the three membership chains, then cc:1206-1209
        // clear the tree and every chain. ALL SEVEN chains must be unlinked
        // BEFORE optree.clear() reclaims the arena slots — IdList surgery
        // needs live cells, including the opcode chains cleared via
        // clear_code_lists (the oracle deletes the pointed-to objects
        // first, then clears the now-dangling lists; the observable end
        // state is identical: every list empty, every slot freed, uniqid
        // reset).
        self.clear_code_lists();
        {
            let Self { optree, alivelist, deadlist, deadandgone, .. } = self;
            let arena = &mut optree.arena_mut();
            alivelist.clear(arena);
            deadlist.clear(arena);
            deadandgone.clear(arena);
        }
        self.optree.clear();
        self.uniqid = 0;
    }

    // Ghidra: op.hh:318 PcodeOpBank::empty
    pub fn is_empty(&self) -> bool {
        self.optree.is_empty()
    }

    // Ghidra: op.hh:307 PcodeOpBank::getUniqId
    pub fn get_uniqid(&self) -> u32 {
        self.uniqid
    }

    // Ghidra: op.cc:1039 PcodeOpBank::insertAfterDead
    /// Move op to right after prev in the dead list. Both must be dead.
    /// Faithful to `insertAfterDead` (op.cc:1039-1048): stored-iterator
    /// `deadlist.erase(op->insertiter)` then `deadlist.insert(++prev->insertiter, op)`
    /// — the id-space unlink + insert_after pair, O(1).
    pub fn insert_after_dead(&mut self, op: &PcodeOpRef, prev: &PcodeOpRef) {
        // cc:1042: verify both are dead.
        if !op.0.read().unwrap().is_dead() || !prev.0.read().unwrap().is_dead() {
            eprintln!("[OP] WARN: insertAfterDead on non-dead op");
            return;
        }
        let (Some(op_id), Some(prev_id)) = (self.slot_of(op), self.slot_of(prev)) else {
            return;
        };
        let Self { optree, deadlist, .. } = self;
        let arena = optree.arena();
        if !deadlist.contains(arena, op_id) || !deadlist.contains(arena, prev_id) {
            return;
        }
        let arena = &mut optree.arena_mut();
        deadlist.unlink(arena, op_id);
        deadlist.insert_after(arena, prev_id, op_id);
    }

    // Ghidra: op.cc:1056 PcodeOpBank::moveSequenceDead
    /// Move a sequence of ops to right after prev in the dead list.
    /// Faithful to `moveSequenceDead` (op.cc:1056-1065):
    /// `enditer = ++lastop->insertiter; previter = ++prev->insertiter;
    /// if (previter != firstop->insertiter) deadlist.splice(previter, deadlist,
    /// firstop->insertiter, enditer)` — the id-space splice_after carries
    /// both degenerate guards in the frozen arena primitive (the op.cc:1063
    /// already-in-place check, and the pos==last enditer no-op,
    /// CR-ARENACORE F1).
    pub fn move_sequence_dead(&mut self, firstop: &PcodeOpRef, lastop: &PcodeOpRef, prev: &PcodeOpRef) {
        let (Some(first_id), Some(last_id), Some(prev_id)) =
            (self.slot_of(firstop), self.slot_of(lastop), self.slot_of(prev))
        else {
            return;
        };
        let Self { optree, deadlist, .. } = self;
        let arena = optree.arena();
        if !deadlist.contains(arena, first_id)
            || !deadlist.contains(arena, last_id)
            || !deadlist.contains(arena, prev_id)
        {
            return;
        }
        // Mirror of the former index form's `last_idx < first_idx` bail:
        // walk forward from first and require reaching last before the
        // chain end (the splice precondition's contiguity half is checked
        // by the frozen IdList in debug builds).
        let mut cur = first_id;
        let mut ordered = false;
        while !cur.is_sentinel() {
            if cur == last_id {
                ordered = true;
                break;
            }
            cur = arena.get(cur).map(|cell| cell.ins_next).unwrap_or(OpId::SENTINEL);
        }
        if !ordered {
            return;
        }
        deadlist.splice_after(&mut optree.arena_mut(), prev_id, first_id, last_id);
    }

    // Ghidra: op.cc:1071 PcodeOpBank::markIncidentalCopy
    /// Mark COPY ops in the dead list range [firstop, lastop] as incidental.
    /// Faithful to `markIncidentalCopy` (op.cc:1071-1083): the bounded walk
    /// `[firstop->insertiter, ++lastop->insertiter)` flags every COPY —
    /// the id-space form walks ins_next from first, stopping after last
    /// (or at the chain end when last is never reached, the same list-end
    /// fallthrough the former whole-list walk had). `firstop` absent from
    /// the chain flags nothing.
    pub fn mark_incidental_copy(&mut self, firstop: &PcodeOpRef, lastop: &PcodeOpRef) {
        let (Some(first_id), Some(last_id)) = (self.slot_of(firstop), self.slot_of(lastop))
        else {
            return;
        };
        let arena = self.optree.arena();
        if !self.deadlist.contains(arena, first_id) {
            return;
        }
        let mut cur = first_id;
        loop {
            let Some(cell) = self.optree.arena().get(cur) else { break };
            let (is_copy, next) =
                ({ cell.op.0.read().unwrap().opcode == OpCode::CPUI_COPY }, cell.ins_next);
            if is_copy {
                cell.op.0.write().unwrap().addlflags |= crate::op::op_addl_flags::INCIDENTAL_COPY;
            }
            if cur == last_id {
                break;
            }
            if next.is_sentinel() {
                break;
            }
            cur = next;
        }
    }

    // Ghidra: op.cc:1089 PcodeOpBank::target
    /// Find the first PcodeOp at or after the given Address.
    /// Faithful to `target` (op.cc:1089-1097): lower_bound(SeqNum(addr,0))
    /// — the first tree entry at or after the key, in (addr,time) order.
    /// (Rugra returns the tree entry itself; the oracle additionally
    /// redirects through `(*iter).second->target()` — pre-existing shape,
    /// unchanged by OPTREE.)
    pub fn target(&self, addr: crate::address::Address) -> Option<PcodeOpRef> {
        self.optree.target_lower_bound(addr).next().cloned()
    }

    // Ghidra: op.cc:1110 PcodeOpBank::fallthru
    /// Find the fall-through op (next op in alive list after the given op).
    /// Faithful to `fallthru` (op.cc:1110-1144) in Rugra's pre-existing
    /// shape: the alive-arm of the oracle walk (an alive op's stored
    /// insertiter successor; the oracle's dead-arm uses block order via
    /// nextOp — Rugra's former alivelist scan returned None for dead ops,
    /// a divergence retained unchanged). The stored ins-link successor IS
    /// the former scan's "entry after the ptr match", O(1).
    pub fn fallthru(&self, op: &PcodeOpRef) -> Option<PcodeOpRef> {
        let id = self.slot_of(op)?;
        if !self.alivelist.contains(self.optree.arena(), id) {
            return None; // dead/unlinked: the former scan never matched
        }
        let next = self.optree.arena().get(id)?.ins_next;
        if next.is_sentinel() {
            return None;
        }
        self.optree.get_by_id(next).cloned()
    }

    // Ghidra: op.cc:1146 PcodeOpBank::begin(addr)
    /// Beginning of ops at the given address (sorted by SeqNum).
    /// Faithful to `begin(const Address&)` (op.cc:1146-1150).
    pub fn begin_addr(&self, addr: crate::address::Address) -> impl Iterator<Item = &PcodeOpRef> {
        self.optree.iter().filter(move |op| {
            op.0.read().unwrap().start.addr >= addr
        })
    }

    // Ghidra: op.cc:1152 PcodeOpBank::end(addr)
    /// End of ops at the given address.
    pub fn end_addr(&self, addr: crate::address::Address) -> impl Iterator<Item = &PcodeOpRef> {
        self.optree.iter().filter(move |op| {
            op.0.read().unwrap().start.addr > addr
        })
    }

    // Ghidra: op.cc:1158 PcodeOpBank::begin(OpCode)
    /// Beginning of ops with the given opcode (uses code lists).
    /// Faithful to `begin(OpCode)` (op.cc:1158-1174): STORE/LOAD/RETURN/
    /// CALLOTHER read their opcode chain; every other opcode yields the
    /// alivelist end (Rugra's former default arm returned the full
    /// alivelist — a divergence funcdata::begin_op_code already corrects
    /// locally; kept here so the surface is unchanged for direct callers).
    pub fn begin_op(&self, opc: OpCode) -> OpChainIter<'_> {
        match opc {
            OpCode::CPUI_STORE => self.iter_store(),
            OpCode::CPUI_LOAD => self.iter_load(),
            OpCode::CPUI_RETURN => self.iter_return(),
            OpCode::CPUI_CALLOTHER => self.iter_userop(),
            _ => self.iter_alive(),
        }
    }

    // Ghidra: op.cc:1176 PcodeOpBank::end(OpCode)
    /// End sentinel for ops with the given opcode.
    /// In Rust, begin_op returns an iterator that handles both begin+end.
    /// This method exists for API parity; use begin_op().chain(empty).
    pub fn end_op(&self, _opc: OpCode) -> OpChainIter<'_> {
        // In Rust, we use begin_op() iterator directly which covers the full list.
        // This stub returns an empty walk for API parity.
        OpChainIter::empty(self.optree.arena())
    }

    // Ghidra: op.cc:1089 PcodeOpBank::setUniqId
    /// Set the unique ID counter (for cloning).
    pub fn set_uniqid(&mut self, val: u32) {
        self.uniqid = val;
    }

    // Ghidra: op.cc:957 PcodeOpBank::create(int4,const SeqNum&)
    /// Create a PcodeOp with a specific SeqNum (for cloning).
    /// Faithful to `create(int4, const SeqNum&)` (op.cc:957-969): the
    /// dead-flag + deadlist tail push (cc:966-967) is the stored-iterator
    /// `insertiter = deadlist.insert(deadlist.end(), op)` form.
    pub fn create_seq(&mut self, num_inputs: usize, sq: crate::address::SeqNum) -> PcodeOpRef {
        if sq.get_time() >= self.uniqid {
            self.uniqid = sq.get_time() + 1;
        }
        let mut op = PcodeOp::new(sq, OpCode::CPUI_COPY);
        op.inrefs.reserve(num_inputs);
        op.flags |= pcodeop_flags::DEAD;
        let op_ref = PcodeOpRef(Arc::new(RwLock::new(op)));
        self.optree.insert(op_ref.clone());
        let id = self.slot_of(&op_ref).expect("create_seq slots the op");
        let Self { optree, deadlist, .. } = self;
        deadlist.push_back(&mut optree.arena_mut(), id);
        op_ref
    }

    // ====================================================================
    // Chain read API (PERF-ARENA-FLIP-0001 (b) — the former Vec consumers'
    // surface over the intrusive chains; funcdata.hh:506/512 beginOpAlive/
    // beginOpDead are the oracle precedent for begin()-style accessors)
    // ====================================================================

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (alivelist walk)
    /// Iterate the alive chain head→tail in exact chain order (the
    /// oracle alivelist order, op.hh:292).
    pub fn iter_alive(&self) -> OpChainIter<'_> {
        OpChainIter::ins(self.optree.arena(), self.alivelist.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: funcdata.hh:512 Funcdata::beginOpDead (deadlist walk)
    /// Iterate the dead chain head→tail in exact chain order (the
    /// oracle deadlist order, op.hh:291).
    pub fn iter_dead(&self) -> OpChainIter<'_> {
        OpChainIter::ins(self.optree.arena(), self.deadlist.head().unwrap_or(OpId::SENTINEL))
    }

    // RUGRA-GLUE: id-yielding alive-chain walk (PERF-ARENA-FLIP-0001 (c)
    //   workset collect form — chain order, zero locks, zero clones).
    /// Iterate the alive chain as plain [`OpId`]s in exact chain order.
    pub fn iter_alive_ids(&self) -> OpChainIdIter<'_> {
        OpChainIdIter::ins(
            self.optree.arena(),
            self.alivelist.head().unwrap_or(OpId::SENTINEL),
        )
    }

    // RUGRA-GLUE: id-yielding LOAD-chain walk (workset collect form).
    /// Iterate the LOAD chain as plain [`OpId`]s in chain order.
    pub fn iter_load_ids(&self) -> OpChainIdIter<'_> {
        OpChainIdIter::code(
            self.optree.arena(),
            self.loadlist.head().unwrap_or(OpId::SENTINEL),
        )
    }

    // RUGRA-GLUE: id-yielding RETURN-chain walk (workset collect form).
    /// Iterate the RETURN chain as plain [`OpId`]s in chain order.
    pub fn iter_return_ids(&self) -> OpChainIdIter<'_> {
        OpChainIdIter::code(
            self.optree.arena(),
            self.returnlist.head().unwrap_or(OpId::SENTINEL),
        )
    }

    // RUGRA-GLUE: marker-form dead walk — flow.cc:240 deleteRemainingOps
    //   walks `oiter` (a stored dead-list iterator) to `endDead()`; the
    //   id-space marker is the last surviving op's id.
    /// Iterate the dead chain from `marker`'s successor (or the head when
    /// the marker is `None`) to the tail.
    pub fn iter_dead_from(&self, marker: Option<OpId>) -> OpChainIter<'_> {
        let head = self.dead_after(marker).unwrap_or(OpId::SENTINEL);
        OpChainIter::from_id(self.optree.arena(), head)
    }

    // Ghidra: op.hh:297 PcodeOpBank deadandgone (retired chain walk)
    /// Iterate the retired (deadandgone) chain head→tail.
    pub fn iter_deadandgone(&self) -> OpChainIter<'_> {
        OpChainIter::ins(self.optree.arena(), self.deadandgone.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: op.cc:1158 PcodeOpBank::begin(CPUI_STORE) (storelist walk)
    /// Iterate the STORE chain head→tail in chain (registration) order.
    pub fn iter_store(&self) -> OpChainIter<'_> {
        OpChainIter::code(self.optree.arena(), self.storelist.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: op.cc:1158 PcodeOpBank::begin(CPUI_LOAD) (loadlist walk)
    /// Iterate the LOAD chain head→tail in chain (registration) order.
    pub fn iter_load(&self) -> OpChainIter<'_> {
        OpChainIter::code(self.optree.arena(), self.loadlist.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: op.cc:1158 PcodeOpBank::begin(CPUI_RETURN) (returnlist walk)
    /// Iterate the RETURN chain head→tail in chain (registration) order.
    pub fn iter_return(&self) -> OpChainIter<'_> {
        OpChainIter::code(self.optree.arena(), self.returnlist.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: op.cc:1158 PcodeOpBank::begin(CPUI_CALLOTHER) (useroplist walk)
    /// Iterate the CALLOTHER chain head→tail in chain (registration) order.
    pub fn iter_userop(&self) -> OpChainIter<'_> {
        OpChainIter::code(self.optree.arena(), self.useroplist.head().unwrap_or(OpId::SENTINEL))
    }

    // Ghidra: op.cc:1110 PcodeOpBank::fallthru (dead-arm iterator form)
    /// The dead-list successor of `op` (Ghidra's `++op->getInsertIter()`
    /// against `endDead()`, flow.cc:1390-1392) — O(1) via the stored
    /// ins-link. `None` when `op` is not in the dead chain or is last.
    pub fn dead_next(&self, op: &PcodeOpRef) -> Option<PcodeOpRef> {
        let id = self.slot_of(op)?;
        if !self.deadlist.contains(self.optree.arena(), id) {
            return None;
        }
        let next = self.optree.arena().get(id)?.ins_next;
        if next.is_sentinel() {
            return None;
        }
        self.optree.get_by_id(next).cloned()
    }

    // Ghidra: funcdata_block.cc:554 Funcdata::earlyJumpTableFail (--iter walk)
    /// The dead-list predecessor of `op` (Ghidra's `--iter` from the
    /// stored insertiter) — O(1) via the stored ins-link. `None` when
    /// `op` is not in the dead chain or is first.
    pub fn dead_prev(&self, op: &PcodeOpRef) -> Option<PcodeOpRef> {
        let id = self.slot_of(op)?;
        if !self.deadlist.contains(self.optree.arena(), id) {
            return None;
        }
        let prev = self.optree.arena().get(id)?.ins_prev;
        if prev.is_sentinel() {
            return None;
        }
        self.optree.get_by_id(prev).cloned()
    }

    // Ghidra: funcdata.hh:512 Funcdata::beginOpDead (head probe)
    /// First op of the dead chain (the former `deadlist.first()`).
    pub fn dead_head(&self) -> Option<PcodeOpRef> {
        let head = self.deadlist.head()?;
        self.optree.get_by_id(head).cloned()
    }

    // Ghidra: op.cc:1056 PcodeOpBank::moveSequenceDead (tail probe)
    /// Last op of the dead chain (the former `deadlist.last()`).
    pub fn dead_tail(&self) -> Option<PcodeOpRef> {
        let tail = self.deadlist.tail()?;
        self.optree.get_by_id(tail).cloned()
    }

    // RUGRA-GLUE: raw id forms of the head/tail probes — flow-time boundary
    //   markers are `Option<OpId>` (the oracle's stored list iterators,
    //   flow.cc:407 `oiter`), so the marker helpers below need ids, not
    //   resolved handles.
    /// Raw id of the dead chain head.
    pub fn dead_head_id(&self) -> Option<OpId> {
        self.deadlist.head()
    }

    /// Raw id of the dead chain tail.
    // RUGRA-GLUE: raw-handle probe (the id form of the tail walk above).
    pub fn dead_tail_id(&self) -> Option<OpId> {
        self.deadlist.tail()
    }

    /// Resolve a raw id to its stored handle (guarded stale-id lookup).
    // RUGRA-GLUE: id dereference — the oracle counterpart is the raw
    // pointer dereference itself (P1 read form, ARENA_DESIGN §3.2).
    pub fn op_by_id(&self, id: OpId) -> Option<&PcodeOpRef> {
        self.optree.get_by_id(id)
    }

    // RUGRA-GLUE: bank-level stored-iterator opcode read (delegates to the
    //   PcodeOpTree cell shadow; the pool dispatch's per-try re-read form,
    //   PERF-ARENA-FLIP-0001 (c)).
    /// The op's current opcode, read lock-free from the arena cell — the
    /// `op->code()` (op.hh:233) equivalent for id-holding callers.
    pub fn opcode_of(&self, id: OpId) -> Option<OpCode> {
        self.optree.opcode_by_id(id)
    }

    // RUGRA-GLUE: boundary-marker resolution — the id-space form of
    //   "the ops from position N to the end" (flow.cc:240 deleteRemainingOps
    //   walks `oiter` to `endDead()`; flow.cc:407/466 record the pre-lift
    //   tail and advance from it). `None` marker + non-empty chain = the
    //   whole chain (the list was empty when the marker was taken).
    /// The first dead-chain member strictly after the marker id (or the
    /// head when the marker is `None`).
    pub fn dead_after(&self, marker: Option<OpId>) -> Option<OpId> {
        match marker {
            None => self.deadlist.head(),
            Some(m) => {
                let cell = self.optree.arena().get(m)?;
                let next = cell.ins_next;
                if next.is_sentinel() { None } else { Some(next) }
            }
        }
    }

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (membership probes)
    /// True when `op` is a member of the dead chain.
    pub fn in_dead(&self, op: &PcodeOpRef) -> bool {
        self.slot_of(op).is_some_and(|id| self.deadlist.contains(self.optree.arena(), id))
    }

    /// True when `op` is a member of the alive chain.
    // RUGRA-GLUE: stored-iterator validity probe (oracle: `iter != end()`).
    pub fn in_alive(&self, op: &PcodeOpRef) -> bool {
        self.slot_of(op).is_some_and(|id| self.alivelist.contains(self.optree.arena(), id))
    }

    // RUGRA-GLUE: legacy flat-bank positional adapters (funcdata
    //   op_insert_before/op_insert_after GLUE branches) — chain-surgery
    //   forms of the former Vec::insert at a member's position. Each is a
    //   guarded no-op when the anchor is not an alive member (the former
    //   scans missed and the caller fell through to the tail).
    /// Insert `op` into the alive chain immediately before the member
    /// `follow` (the former alivelist positional insert at follow's index).
    /// `op` must be slotted and unlinked.
    pub fn alive_insert_before(&mut self, op: &PcodeOpRef, follow: &PcodeOpRef) {
        let (Some(id), Some(follow_id)) = (self.slot_of(op), self.slot_of(follow)) else {
            return;
        };
        let Self { optree, alivelist, .. } = self;
        let arena = optree.arena();
        if !alivelist.contains(arena, follow_id) || alivelist.contains(arena, id) {
            return;
        }
        alivelist.insert_before(&mut optree.arena_mut(), follow_id, id);
    }

    /// Insert `op` into the alive chain immediately after the member
    /// `previous` (the former alivelist positional insert at
    /// previous's index + 1). `op` must be slotted and unlinked.
    // RUGRA-GLUE: legacy flat-bank positional insert, chain form.
    pub fn alive_insert_after(&mut self, op: &PcodeOpRef, previous: &PcodeOpRef) {
        let (Some(id), Some(prev_id)) = (self.slot_of(op), self.slot_of(previous)) else {
            return;
        };
        let Self { optree, alivelist, .. } = self;
        let arena = optree.arena();
        if !alivelist.contains(arena, prev_id) || alivelist.contains(arena, id) {
            return;
        }
        alivelist.insert_after(&mut optree.arena_mut(), prev_id, id);
    }

    // RUGRA-GLUE: alive-chain tail push for the slotted-but-unlinked legacy
    //   state (the former `alivelist.insert(len, op)` fallthrough).
    /// Link the slotted, unlinked `op` at the alive chain tail.
    pub fn alive_push_back(&mut self, op: &PcodeOpRef) {
        let Some(id) = self.slot_of(op) else { return };
        let Self { optree, alivelist, .. } = self;
        alivelist.push_back(&mut optree.arena_mut(), id);
    }

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (--iter form)
    /// The alive-chain predecessor of `op` — O(1) via the stored ins-link.
    /// `None` when `op` is not an alive member or is first.
    pub fn alive_prev(&self, op: &PcodeOpRef) -> Option<PcodeOpRef> {
        let id = self.slot_of(op)?;
        if !self.alivelist.contains(self.optree.arena(), id) {
            return None;
        }
        let prev = self.optree.arena().get(id)?.ins_prev;
        if prev.is_sentinel() {
            return None;
        }
        self.optree.get_by_id(prev).cloned()
    }

    // RUGRA-GLUE: legacy flat-bank detach — the former
    //   `alivelist.retain(|x| !ptr_eq(x, op))` no-op-or-remove shape on the
    //   parentless-fixture paths (funcdata op_uninsert GLUE branch). Chain
    //   form: unlink when an alive member, otherwise nothing (a flag-less
    //   detach, no dead transition).
    /// Remove `op` from the alive chain when it is a member (no flag change).
    pub fn unlink_alive_if_member(&mut self, op: &PcodeOpRef) {
        let Some(id) = self.slot_of(op) else { return };
        let Self { optree, alivelist, .. } = self;
        if !alivelist.contains(optree.arena(), id) {
            return;
        }
        alivelist.unlink(&mut optree.arena_mut(), id);
    }

    // RUGRA-GLUE: cold positional bridge — the former `deadlist[index]` on
    //   paths where an index is still the natural currency (do_live_inject's
    //   historically index-driven walk). Walks from the head; strict form
    //   panics past the tail exactly like the former Vec index.
    /// The dead-chain member at `index` (0-based), or `None` past the tail.
    pub fn dead_at(&self, index: usize) -> Option<PcodeOpRef> {
        let id = self.dead_id_at(index)?;
        self.optree.get_by_id(id).cloned()
    }

    /// Raw id of the dead-chain member at `index` (0-based), or `None`.
    // RUGRA-GLUE: positional bridge (chain walk from the head).
    pub fn dead_id_at(&self, index: usize) -> Option<OpId> {
        let mut cur = self.deadlist.head()?;
        for _ in 0..index {
            let next = self.optree.arena().get(cur)?.ins_next;
            if next.is_sentinel() {
                return None;
            }
            cur = next;
        }
        Some(cur)
    }

    /// The dead-chain member at `index`, panicking past the tail (the
    /// former `deadlist[index]` out-of-bounds panic).
    // RUGRA-GLUE: positional bridge, strict form (Vec index panic parity).
    pub fn dead_at_strict(&self, index: usize) -> PcodeOpRef {
        self.dead_at(index).unwrap_or_else(|| {
            panic!("deadlist index {} out of bounds: len is {}", index, self.deadlist.len())
        })
    }

    // RUGRA-GLUE: bank-API replacement for the legacy test fixtures' bare
    //   `alivelist.push(PcodeOpRef(raw_arc))` list bypasses
    //   (PERF-ARENA-FLIP-0001 (b) task ③). Slots the foreign handle into
    //   the bank arena WITHOUT entering the SeqNum map (the optree map and
    //   every map-derived observation stay untouched, exactly as the bare
    //   push left them) and links it at the alivelist tail. An op already
    //   chained (e.g. newOp left it on the dead chain) is first unlinked —
    //   the former double-push left such an op in BOTH lists, a state the
    //   one-chain-per-op invariant (op.hh:128's single insertiter) cannot
    //   represent; the observable the fixtures relied on — the op visible
    //   at the alivelist tail — is exactly preserved.
    /// Slot a foreign (never bank-created) op handle and link it at the
    /// alive chain tail (relinking it away from any current chain).
    pub fn adopt_alive_op(&mut self, op: PcodeOpRef) {
        let id = self.optree.slot_only(&op);
        let Self { optree, deadlist, alivelist, deadandgone, .. } = self;
        let arena = optree.arena();
        if deadlist.contains(arena, id) {
            deadlist.unlink(&mut optree.arena_mut(), id);
        } else if alivelist.contains(arena, id) {
            alivelist.unlink(&mut optree.arena_mut(), id);
        } else if deadandgone.contains(arena, id) {
            deadandgone.unlink(&mut optree.arena_mut(), id);
        }
        alivelist.push_back(&mut optree.arena_mut(), id);
    }
}

impl Default for PcodeOpBank {
    // RUGRA-GLUE: Rust Default impl; Ghidra has no Default concept but the
    //   PcodeOpBank() ctor (op.hh:304) is the equivalent zero-initializer.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! Regression pins for OP-ISMOVEABLE-WALKORDER-0001.
    //!
    //! Ghidra `PcodeOp::isMoveable` (op.cc:223-269) walks the parent block's
    //! op list (`basiciter`): every op strictly after self up to and including
    //! point, in BlockBasic::ops (block) order. The bank alivelist is markAlive
    //! push_back order (op.cc:1022) and diverges from block order after
    //! mid-block insertions or opUninsert/opInsert moves. The fixtures below
    //! build exactly such divergent synthetic layouts and pin the block-order
    //! walk in both directions (missed violation / spurious violation).
    use super::*;
    use crate::block::BlockBasic;
    use crate::varnode::varnode_flags;

    struct WalkOrderFixture {
        block: Arc<RwLock<BlockBasic>>,
        bank: PcodeOpBank,
    }

    impl WalkOrderFixture {
        /// BlockBasic with self_ref set so `insert_op` assigns op.parent
        /// (block.cc:2266 setParent analogue) + a bank whose alivelist
        /// records creation order (Ghidra markAlive push_back).
        fn new() -> Self {
            let block = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
            let dyn_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = block.clone();
            block.write().unwrap().self_ref = Some(Arc::downgrade(&dyn_block));
            Self { block, bank: PcodeOpBank::new() }
        }

        fn create(&mut self, opcode: OpCode, num_inputs: usize) -> PcodeOpRef {
            self.bank.create(opcode, num_inputs, Address::new(0x1000))
        }

        fn insert_at(&self, index: usize, op: &PcodeOpRef) {
            self.block.write().unwrap().insert_op(index, op.clone());
        }
    }

    #[test]
    fn is_moveable_walks_block_order_missed_store() {
        // Block order [A(LOAD), C(STORE), B(point)]; alivelist (creation)
        // order [A, B, C]. The STORE sits between self and point in the
        // block but AFTER point in the alivelist. Oracle walks the block
        // list, hits STORE with movingLoad => not moveable (op.cc:234-236).
        // The pre-fix alivelist walk stopped at B and never examined C.
        let mut fx = WalkOrderFixture::new();
        let a = fx.create(OpCode::CPUI_LOAD, 2); // self: special, movingLoad
        let b = fx.create(OpCode::CPUI_INT_ADD, 2); // point
        let c = fx.create(OpCode::CPUI_STORE, 3); // violator
        fx.insert_at(0, &a);
        fx.insert_at(1, &c);
        fx.insert_at(2, &b);
        let a_g = a.0.read().unwrap();
        let b_g = b.0.read().unwrap();
        assert!(!a_g.is_moveable(&b_g, &fx.bank));
    }

    #[test]
    fn is_moveable_walks_block_order_no_spurious_crossing() {
        // Block order [F(STORE), D(self), E(point)]; alivelist order
        // [D, F, E]. The STORE sits BEFORE self in the block but between
        // self and point in the alivelist. Oracle walks the block list and
        // never examines F => moveable. The pre-fix alivelist walk examined
        // F (STORE with non-empty tiedList) and spuriously returned false.
        let mut fx = WalkOrderFixture::new();
        let d = fx.create(OpCode::CPUI_INT_ADD, 2); // self
        let f = fx.create(OpCode::CPUI_STORE, 3);
        let e = fx.create(OpCode::CPUI_INT_ADD, 2); // point
        fx.insert_at(0, &f);
        fx.insert_at(1, &d);
        fx.insert_at(2, &e);
        // addr-tied input on self => tiedList non-empty (op.cc:218-222)
        let mut vn = Varnode::new(4, Address::new(0));
        vn.set_flags(varnode_flags::ADDRTIED | varnode_flags::INSERT);
        d.0.write().unwrap().inrefs.push(Arc::new(RwLock::new(vn)));
        let d_g = d.0.read().unwrap();
        let e_g = e.0.read().unwrap();
        assert!(d_g.is_moveable(&e_g, &fx.bank));
    }

    #[test]
    fn is_moveable_examines_point_inclusive() {
        // Oracle do-while runs the body for biter == point->basiciter: the
        // point op itself IS examined (op.cc:224-269). Self is LOAD
        // (movingLoad), point IS the STORE directly after it in the block
        // (orders agree here) => false. Guards against an off-by-one that
        // would exclude point from the walked range.
        let mut fx = WalkOrderFixture::new();
        let a = fx.create(OpCode::CPUI_LOAD, 2);
        let b = fx.create(OpCode::CPUI_STORE, 3);
        fx.insert_at(0, &a);
        fx.insert_at(1, &b);
        let a_g = a.0.read().unwrap();
        let b_g = b.0.read().unwrap();
        assert!(!a_g.is_moveable(&b_g, &fx.bank));
    }

    #[test]
    fn is_moveable_adjacent_normal_ops_passes() {
        // No violating op between self and point => moveable. Both orders
        // agree; pins the baseline pass-through path of the walk.
        let mut fx = WalkOrderFixture::new();
        let a = fx.create(OpCode::CPUI_INT_ADD, 2);
        let b = fx.create(OpCode::CPUI_INT_ADD, 2);
        fx.insert_at(0, &a);
        fx.insert_at(1, &b);
        let a_g = a.0.read().unwrap();
        let b_g = b.0.read().unwrap();
        assert!(a_g.is_moveable(&b_g, &fx.bank));
    }

    #[test]
    fn is_moveable_point_before_self_fails_closed() {
        // Oracle contract: point is strictly after self (both real call
        // sites pass the block's lastOp). Ghidra would walk off the list end
        // (undefined behavior) when point precedes self; Rugra fails closed
        // with false instead of reproducing UB.
        let mut fx = WalkOrderFixture::new();
        let a = fx.create(OpCode::CPUI_INT_ADD, 2);
        let b = fx.create(OpCode::CPUI_INT_ADD, 2);
        fx.insert_at(0, &b);
        fx.insert_at(1, &a);
        let a_g = a.0.read().unwrap();
        let b_g = b.0.read().unwrap();
        assert!(!a_g.is_moveable(&b_g, &fx.bank));
    }
}

