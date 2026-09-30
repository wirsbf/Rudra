//! Reachability-based control flow tracking.
//!
//! Partial port of Ghidra's `FlowInfo` (flow.cc/flow.hh). Replaces Rugra's
//! linear-scan approach (disassemble → lift → inject_raw_ops) with
//! address-list-driven flow tracking that only decodes reachable code. The
//! remaining error, injection, override, jump-table, and block-generation
//! differences are tracked by `SLEIGH-FLOW-0001`.

use crate::address::Address;
use crate::block::{block_flags, BlockBasic, BlockGraph, FlowBlock};
use crate::disasm::sleigh_lift::SleighLifter;
use crate::funcdata::Funcdata;
use crate::op::pcodeop_flags;
use crate::opcodes::OpCode;
use crate::sleigh_ffi::SleighErrorKind;
use std::sync::{Arc, RwLock};

/// Flow-following option/property flag bits. Faithful to the anonymous enum
/// in flow.hh:60-74.
// Ghidra: flow.hh:60 FlowInfo::(anonymous enum)
pub mod flow_flags {
    /// Ignore/truncate flow into addresses out of the specified range.
    pub const IGNORE_OUTOFBOUNDS: u32 = 1;
    /// Treat unimplemented instructions as a NOP (no operation).
    pub const IGNORE_UNIMPLEMENTED: u32 = 2;
    /// Throw an exception for flow into addresses out of the specified range.
    pub const ERROR_OUTOFBOUNDS: u32 = 4;
    /// Throw an exception for flow into unimplemented instructions.
    pub const ERROR_UNIMPLEMENTED: u32 = 8;
    /// Throw an exception for flow into previously encountered data at a different cut.
    pub const ERROR_REINTERPRETED: u32 = 0x10;
    /// Throw an exception if too many instructions are encountered.
    pub const ERROR_TOOMANYINSTRUCTIONS: u32 = 0x20;
    /// Indicate we have encountered unimplemented instructions.
    pub const UNIMPLEMENTED_PRESENT: u32 = 0x40;
    /// Indicate we have encountered flow into unaccessible data.
    pub const BADDATA_PRESENT: u32 = 0x80;
    /// Indicate we have encountered flow out of the specified range.
    pub const OUTOFBOUNDS_PRESENT: u32 = 0x100;
    /// Indicate we have encountered reinterpreted data.
    pub const REINTERPRETED_PRESENT: u32 = 0x200;
    /// Indicate the maximum instruction threshold was reached.
    pub const TOOMANYINSTRUCTIONS_PRESENT: u32 = 0x400;
    /// Indicate a CALL was converted to a BRANCH and some code may be unreachable.
    pub const POSSIBLE_UNREACHABLE: u32 = 0x1000;
    /// Indicate flow is being generated to in-line (a function).
    pub const FLOW_FORINLINE: u32 = 0x2000;
    /// Indicate that any jump table recovery should record the table structure.
    pub const RECORD_JUMPLOADS: u32 = 0x4000;
}

/// Extension trait providing the `FuncCallSpecs` accessors that Ghidra's
/// `flow.cc` call-spec maintenance methods rely on but that Rugra's
/// `FuncCallSpecs` does not yet model. The audit (flow_audit.md item 2)
/// flags this as a "FuncCallSpecs gap": Ghidra's `FuncCallSpecs` carries
/// inject_id state, while Rugra's does not store it.
///
/// The flag accessors Ghidra inherits from `FuncProto` (`is_inline`,
/// `is_no_return`, `set_no_return`, `copy_flow_effects`) now live on
/// `FuncCallSpecs` itself (fspec.rs delegated surface, fspec.hh:1645
/// inheritance), populated by `FlowInfo::query_call`'s `copy_flow_effects`
/// (flow.cc:664) from the flow-visible per-callee prototype table. This
/// extension trait covers the remaining flow-local adapters:
/// `get_inject_id` returns the no-injection sentinel until the id is stored
/// (INJECT-0001); `get_op`, `get_name`, `set_paramshift`,
/// `cancel_inject_id`, `clear_entry_address` delegate to the existing
/// public fields/methods.
trait FuncCallSpecsExt {
    /// Flow-local adapter for `FuncCallSpecs::getInjectId` (fspec.hh). Returns -1
    /// (Ghidra's "no injection" sentinel) until the id is stored.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration because flow.cc calls FuncCallSpecs::getInjectId directly and has no flow-local interface.
    fn get_inject_id(&self) -> i32;
    /// Flow-local adapter for `FuncCallSpecs::getOp` (fspec.hh): the exact,
    /// non-owning call-op identity bound when the spec is constructed.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration upgrades the Weak counterpart of Ghidra's direct PcodeOp pointer.
    fn get_op(&self, fd: &Funcdata) -> Option<crate::op::PcodeOpRef>;
    /// Flow-local adapter for `FuncCallSpecs::getName` (fspec.hh): the callee name.
    /// Delegates to `FuncProto::get_name`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing the nested FuncProto name used where Ghidra inherits the accessor directly.
    fn get_name(&self) -> &str;
    /// Flow-local adapter for `FuncCallSpecs::setParamshift` (fspec.hh). Delegates to
    /// `FuncProto::param_shift`; leaves state unchanged when `shift == 0`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing nested FuncProto parameter shifting to flow-local code.
    fn set_paramshift(&mut self, shift: i32);
    /// Flow-local adapter for `FuncCallSpecs::cancelInjectId` (fspec.hh):
    /// delegates to the injection-state gap tracked by `INJECT-0001`.
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration exposing nested FuncProto injection cancellation to flow-local code.
    fn cancel_inject_id(&mut self);
    /// Flow-local adapter for `FuncCallSpecs::setAddress` (fspec.hh). Clears the entry
    /// address to cancel an indirect override (flow.cc:713).
    // RUGRA-GLUE: ANN-B; Rust extension-trait declaration representing Ghidra's setAddress(Address()) with Rugra's optional entry address.
    fn clear_entry_address(&mut self);
}

impl FuncCallSpecsExt for crate::fspec::FuncCallSpecs {
    // RUGRA-GLUE: ANN-B; INJECT-0001 compatibility fallback because Rugra FuncCallSpecs has no Ghidra injection-id field.
    fn get_inject_id(&self) -> i32 {
        // TODO(INJECT-0001): depends on FuncCallSpecs storing an inject id. -1 = none.
        -1
    }
    // RUGRA-GLUE: ANN-B; Rust upgrades the Weak counterpart of Ghidra's direct PcodeOp pointer.
    fn get_op(&self, fd: &Funcdata) -> Option<crate::op::PcodeOpRef> {
        self.find_call_op(fd)
    }
    // RUGRA-GLUE: ANN-B; Rust adapter reads the nested FuncProto field because Rugra FuncCallSpecs does not inherit Ghidra's name accessor.
    fn get_name(&self) -> &str {
        // FuncProto stores the callee name in a public `name` field; Rugra
        // has no FuncProto::get_name accessor, so we read the field directly.
        self.prototype.name.as_str()
    }
    // RUGRA-GLUE: ANN-B; Rust adapter forwards flow-local parameter shifting to the nested FuncProto object.
    fn set_paramshift(&mut self, shift: i32) {
        self.prototype.param_shift(shift);
    }
    // RUGRA-GLUE: ANN-B; INJECT-0001 adapter forwards flow-local injection cancellation to the nested FuncProto object.
    fn cancel_inject_id(&mut self) {
        self.prototype.cancel_inject_id();
    }
    // RUGRA-GLUE: ANN-B; CALLSPEC-0001 adapter encodes flow.cc's setAddress(Address()) as Option::None in Rugra.
    fn clear_entry_address(&mut self) {
        self.entry_addr = None;
    }
}

/// Record of a visited instruction (flow.hh:76-80 VisitStat).
#[derive(Clone, Debug)]
struct VisitStat {
    /// Sequence number of the first PcodeOp generated by this instruction,
    /// or `None` when the instruction produced no p-code (Ghidra keeps an
    /// INVALID `SeqNum`). The immutable `time` component is what
    /// `FlowInfo::target` (flow.cc:124) and `FlowInfo::updateTarget`
    /// (flow.cc:209, time-only `SeqNum::operator==`) compare.
    first_seq: Option<crate::address::SeqNum>,
    /// Instruction byte length (flow.hh:79 size).
    size: usize,
}

/// Result of `FlowInfo::findRelTarget` (flow.cc:149-179): either the
/// "properly internal" target op, or the machine fall-through address of the
/// next instruction (relative branch to the end of this instruction).
#[derive(Clone, Debug)]
pub enum RelativeTarget {
    /// `findRelTarget` found the target PcodeOp via its immutable SeqNum.
    Internal(crate::op::PcodeOpRef),
    /// The relative branch targets the next instruction; the machine address
    /// is passed back through Ghidra's `Address &res` out-parameter.
    Fallthru(Address),
}

/// One post-emission operation observation for [`FlowInfoSnapshot`]: the op
/// Arc plus its generation-time immutable `SeqNum::time`.
pub struct FlowOpSnapshot {
    /// The live op (Arc identity equals Ghidra's `PcodeOp*` identity).
    pub op: crate::op::PcodeOpRef,
    /// Immutable creation time (`SeqNum::uniq`); emitted separately because
    /// the op's mutable `order` field is rewritten by `BlockBasic::insert`.
    pub time: u32,
}

/// One visited-instruction observation (flow.hh:77-80 VisitStat).
pub struct FlowVisitedSnapshot {
    /// Machine instruction address (the `visited` map key).
    pub address: Address,
    /// Address component of the first op's SeqNum.
    pub first_seq_address: Address,
    /// Immutable time component of the first op's SeqNum.
    pub first_seq_time: u32,
    /// Instruction byte length.
    pub size: usize,
}

/// One Const-space relative BRANCH/CBRANCH resolution, mirroring the
/// `RelativeResolution` observation of the locked oracle fixture.
pub struct FlowRelativeSnapshot {
    /// The branch op.
    pub source: crate::op::PcodeOpRef,
    /// Resolved internal target op, when the branch is properly internal.
    pub target: Option<crate::op::PcodeOpRef>,
    /// Machine fall-through address, when the branch targets the next
    /// instruction.
    pub target_address: Option<Address>,
    /// `source->getTime() + input(0) offset` with uintm wrapping
    /// (flow.cc:153).
    pub computed_target_time: u32,
}

/// Post-`generateBlocks` observation of a `FlowInfo`, cloning only the
/// generation-time state an external fixture can serialize. Varnode
/// identities are intentionally NOT captured here: they are assigned later
/// from the live `Funcdata` bank Arcs (the SLEIGH callback `VarnodeData*`
/// identity never enters this model).
pub struct FlowInfoSnapshot {
    /// Ops in `PcodeOpBank` SeqNum natural order with immutable times.
    pub operations: Vec<FlowOpSnapshot>,
    /// Visited instructions sorted by Address.
    pub visited: Vec<FlowVisitedSnapshot>,
    /// Every Const-space relative BRANCH/CBRANCH resolution, in op order.
    pub relatives: Vec<FlowRelativeSnapshot>,
    /// Collected (source op, target op) edges in `block_edge1/2` order.
    pub raw_edges: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)>,
    /// `addrlist.size()` after generation.
    pub addrlist_count: usize,
    /// `unprocessed.size()` after generation.
    pub unprocessed_count: usize,
    /// `injectlist.size()` after generation.
    pub inject_count: usize,
    /// `tablelist.size()` after generation.
    pub table_count: usize,
    /// `insn_count`.
    pub instruction_count: u64,
    /// `insn_max`.
    pub instruction_max: u64,
    /// Flow flags (flow.hh:101).
    pub flags: u32,
    /// Flow range bounds.
    pub baddr: Address,
    pub eaddr: Address,
    /// Observed address extremes.
    pub minaddr: Address,
    pub maxaddr: Address,
}

/// Borrow-safe copy of the configuration and address-tracking state consumed
/// by Ghidra's `FlowInfo` cloning constructor.  The original C++ object keeps
/// references to its source `Funcdata`; Rust must release that mutable borrow
/// before a partial `Funcdata` can borrow the source for `truncated_flow`.
/// Operation, call-spec, and jump-table ownership is deliberately absent: the
/// mapped `Funcdata::truncated_flow` routine clones and rebinds those objects.
#[derive(Clone, Debug)]
pub struct TruncatedFlowState {
    pub(crate) unprocessed: Vec<Address>,
    pub(crate) addrlist: Vec<Address>,
    pub(crate) visited: std::collections::BTreeMap<u64, VisitStat>,
    pub(crate) insn_count: u64,
    pub(crate) insn_max: u64,
    pub(crate) baddr: u64,
    pub(crate) eaddr: u64,
    pub(crate) flags: u32,
    pub(crate) inline_head: Option<u64>,
    pub(crate) inline_base: std::collections::BTreeSet<u64>,
    /// Per-callee prototypes visible to `query_call` in the clone (see
    /// [`FlowInfo::callee_func_protos`]); Ghidra's clone shares the symbol
    /// database, so the table rides along.
    pub(crate) callee_func_protos: std::collections::BTreeMap<u64, crate::fspec::FuncProto>,
}

/// Reachability-based flow tracker corresponding to `FlowInfo`
/// (flow.hh:58-169). This type is still `MISMATCH`, not a complete port.
///
/// Phase 1 (`generate_ops`): Decode instructions following control flow
/// from the entry point, building a work-list of reachable addresses.
/// Phase 2 (`generate_blocks`): collect raw edges, move dead-list ops into
/// basic blocks one at a time, connect edges, and prune unreachable blocks.
///
/// The partial-flow cloning path is present, but its copied private state and
/// exceptional branches are not yet exhaustively covered. Remaining gaps
/// include complete jump-table expansion and inlineFlow/subfunction inlining.
pub struct FlowInfo<'a> {
    fd: &'a mut Funcdata,
    /// The SLEIGH translator is required while generating new instructions,
    /// but not by the cloning constructor used for a truncated flow.
    lifter: Option<&'a mut SleighLifter>,
    /// Work-list of addresses to process (LIFO stack). flow.hh:82 addrlist.
    addrlist: Vec<Address>,
    /// Addresses which are permanently unprocessed (flow.hh:87 unprocessed).
    unprocessed: Vec<Address>,
    /// Source/target P-code pairs collected before the dead-list operations
    /// are assigned to basic blocks (flow.hh:91-92 block_edge1/block_edge2).
    /// Rugra keeps each parallel-list entry together so alias identity and
    /// insertion order cannot drift between the two sides of an edge.
    block_edges: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)>,
    /// Visited instruction map (flow.hh:91 visited).
    /// Keyed by instruction address; value carries the first op's SeqNum
    /// (address + immutable time) and the instruction byte size, mirroring
    /// Ghidra's `VisitStat { SeqNum seqnum; int4 size; }` (flow.hh:77-80).
    visited: std::collections::BTreeMap<u64, VisitStat>,
    /// List of BRANCHIND ops (flow.hh:89 tablelist), filled by
    /// `xref_control_flow` (flow.cc:322) and drained by the jump-table loop
    /// in `generate_ops`.
    tablelist: Vec<crate::op::PcodeOpRef>,
    /// List of p-code ops that require injection (flow.hh:90 injectlist).
    /// Populated by `check_for_flow_modification` when a call site is inline
    /// and consumed by `inject_pcode`. RUGRA-GLUE: Ghidra stores `PcodeOp *`;
    /// we store `PcodeOpRef`. Entries are nulled after injection (flow.cc:1333).
    injectlist: Vec<Option<crate::op::PcodeOpRef>>,
    /// Instruction count limit (flow.hh:96 insn_max).
    insn_max: u64,
    /// Instruction count (flow.hh:95 insn_count).
    insn_count: u64,
    /// Flow range [baddr, eaddr).
    baddr: u64,
    eaddr: u64,
    /// Actual min/max address seen.
    minaddr: u64,
    maxaddr: u64,
    /// Boolean options for flow following (flow.hh:101 flags).
    flags: u32,
    /// First function in the in-lining chain (flow.hh:102 inline_head).
    /// Ghidra stores `Funcdata *`; Rugra stores the head function's base
    /// address so `inline_sub_function` can detect the top-level inline
    /// entry. `None` means no inlining is in progress.
    inline_head: Option<u64>,
    /// Active set of addresses for functions currently being in-lined
    /// (flow.hh:103 inline_recursion). Ghidra stores a pointer to an
    /// externally-owned `set<Address>`; Rugra owns the set directly.
    inline_recursion: std::collections::BTreeSet<u64>,
    /// Storage for addresses of functions that are in-lined (flow.hh:104
    /// inline_base). Backing store for `inline_recursion` at the top level.
    inline_base: std::collections::BTreeSet<u64>,
    /// Does the function have registered flow override instructions
    /// (flow.hh:100 flowoverride_present). This is cached when FlowInfo is
    /// constructed, exactly like Ghidra's `Override::hasFlowOverride()`
    /// query in both FlowInfo constructors.
    flowoverride_present: bool,
    /// Call-site op addresses whose `queryCall` (flow.cc:660) resolved a
    /// callee, keyed by the spec's `op_addr` (the CALL instruction address,
    /// one spec per call op).
    ///
    /// RUGRA-GLUE: Ghidra stores the resolved callee as a `Funcdata *` on
    /// each FuncCallSpecs (`fspecs.setFuncdata`, flow.cc:662), and
    /// `checkContainedCall` reads it via `fc->getFuncdata()` (flow.cc:1367).
    /// Rugra's `FuncCallSpecs` has no per-spec callee-Funcdata storage
    /// (fspec.rs gap), so this FlowInfo-side set carries the same
    /// "resolved" observation for the flow-time consumers
    /// (`check_contained_call`). Like Ghidra's spec-owned pointer, the set
    /// is written only by `query_call` during spec setup and read only
    /// within the same FlowInfo lifetime; entries for later-erased specs
    /// are inert.
    resolved_funcdata: std::collections::BTreeSet<u64>,
    /// The `FuncProto` of every callee `query_call` can resolve, keyed by
    /// the callee's entry address — the `funcp` observable of the
    /// `Funcdata` that Ghidra's
    /// `data.getScopeLocal()->getParent()->queryFunction(addr)`
    /// (flow.cc:660) returns. `query_call` reads it to drive
    /// `copy_flow_effects` (flow.cc:663-664); an absent entry means the
    /// callee carries no known flow effects, exactly like a Ghidra
    /// queryFunction miss on the funcp channel.
    ///
    /// RUGRA-GLUE: Ghidra holds the callee protos inside the symbol
    /// database's Funcdata objects (marked by the "Non-Returning Functions -
    /// Known" analyzer et al.); Rugra has no per-callee Funcdata at flow
    /// time, so the driver feeds the table through
    /// [`follow_flow_with_callee_protos`] (FLOW-NORETURN-DATA-0001 owns the
    /// production data source). The table is carried into truncated-flow
    /// clones like Ghidra's shared database.
    callee_func_protos: std::collections::BTreeMap<u64, crate::fspec::FuncProto>,
}

impl<'a> FlowInfo<'a> {
    // Ghidra: flow.cc:26 FlowInfo::FlowInfo(Funcdata &,PcodeOpBank &,BlockGraph &,vector<FuncCallSpecs *> &)
    pub fn new(fd: &'a mut Funcdata, lifter: &'a mut SleighLifter, baddr: u64, eaddr: u64) -> Self {
        let flowoverride_present = fd.localoverride.has_flow_override();
        Self {
            fd,
            lifter: Some(lifter),
            addrlist: Vec::new(),
            unprocessed: Vec::new(),
            block_edges: Vec::new(),
            visited: std::collections::BTreeMap::new(),
            tablelist: Vec::new(),
            injectlist: Vec::new(),
            insn_max: 100000, // Ghidra default max_instructions
            insn_count: 0,
            baddr,
            eaddr,
            minaddr: u64::MAX,
            maxaddr: 0,
            flags: 0,
            inline_head: None,
            inline_recursion: std::collections::BTreeSet::new(),
            inline_base: std::collections::BTreeSet::new(),
            flowoverride_present,
            resolved_funcdata: std::collections::BTreeSet::new(),
            callee_func_protos: std::collections::BTreeMap::new(),
        }
    }

    // Ghidra: flow.cc:52 FlowInfo::FlowInfo(Funcdata &,PcodeOpBank &,BlockGraph &,vector<FuncCallSpecs *> &,const FlowInfo *)
    /// Construct the flow controller for a partial clone.  Configuration and
    /// address-tracking containers are copied in their original order; the
    /// target function owns the already-cloned p-code/call/jump-table banks.
    fn from_truncated_state(fd: &'a mut Funcdata, state: &TruncatedFlowState) -> Self {
        let inline_base = if state.inline_head.is_some() {
            state.inline_base.clone()
        } else {
            std::collections::BTreeSet::new()
        };
        let inline_recursion = inline_base.clone();
        let base = fd.baseaddr.as_u64();
        let flowoverride_present = fd.localoverride.has_flow_override();
        Self {
            fd,
            lifter: None,
            addrlist: state.addrlist.clone(),
            unprocessed: state.unprocessed.clone(),
            block_edges: Vec::new(),
            visited: state.visited.clone(),
            tablelist: Vec::new(),
            injectlist: Vec::new(),
            insn_max: state.insn_max,
            insn_count: state.insn_count,
            baddr: state.baddr,
            eaddr: state.eaddr,
            minaddr: base,
            maxaddr: base,
            flags: state.flags,
            inline_head: state.inline_head,
            inline_recursion,
            inline_base,
            flowoverride_present,
            resolved_funcdata: std::collections::BTreeSet::new(),
            // The truncated clone sees the same queryFunction source as the
            // original flow (Ghidra's symbol database is shared); the table
            // travels through TruncatedFlowState for the same visibility.
            callee_func_protos: state.callee_func_protos.clone(),
        }
    }

    // RUGRA-GLUE: releases FlowInfo's mutable source Funcdata borrow before Funcdata::truncated_flow borrows that source immutably.
    /// Copy precisely the state read by Ghidra's FlowInfo cloning constructor.
    pub fn truncated_state(&self) -> TruncatedFlowState {
        TruncatedFlowState {
            unprocessed: self.unprocessed.clone(),
            addrlist: self.addrlist.clone(),
            visited: self.visited.clone(),
            insn_count: self.insn_count,
            insn_max: self.insn_max,
            baddr: self.baddr,
            eaddr: self.eaddr,
            flags: self.flags,
            inline_head: self.inline_head,
            inline_base: self.inline_base.clone(),
            callee_func_protos: self.callee_func_protos.clone(),
        }
    }

    // RUGRA-GLUE: no-lifter construction for recover_jump_tables_injected
    /// Construct the flow controller over a pre-loaded (batch-injected) op
    /// bank: same shape as the truncated clone constructor (`lifter: None`
    /// — no instruction generation happens), with the visited map
    /// synthesized from the bank and the full ram-space range the oracle
    /// harness passes `followFlow(code:0, code:highest)`.
    fn from_injected(
        fd: &'a mut Funcdata,
        visited: std::collections::BTreeMap<u64, VisitStat>,
    ) -> Self {
        let flowoverride_present = fd.localoverride.has_flow_override();
        let base = fd.baseaddr.as_u64();
        Self {
            fd,
            lifter: None,
            addrlist: Vec::new(),
            unprocessed: Vec::new(),
            block_edges: Vec::new(),
            visited,
            tablelist: Vec::new(),
            injectlist: Vec::new(),
            insn_max: 100000, // Ghidra default max_instructions
            insn_count: 0,
            baddr: 0,
            eaddr: u64::MAX,
            minaddr: base,
            maxaddr: base,
            flags: 0,
            inline_head: None,
            inline_recursion: std::collections::BTreeSet::new(),
            inline_base: std::collections::BTreeSet::new(),
            flowoverride_present,
            resolved_funcdata: std::collections::BTreeSet::new(),
            callee_func_protos: std::collections::BTreeMap::new(),
        }
    }

    // RUGRA-GLUE: Rust borrow-boundary helper for funcdata_op.cc:830-837; C++ constructs the stack FlowInfo directly inside Funcdata::truncatedFlow.
    pub(crate) fn finish_truncated_flow(
        fd: &'a mut Funcdata,
        state: &TruncatedFlowState,
    ) -> crate::error::Result<()> {
        let mut partial_flow = Self::from_truncated_state(fd, state);
        if partial_flow.has_inject() {
            partial_flow.inject_pcode();
        }
        partial_flow.clear_flags(!flow_flags::POSSIBLE_UNREACHABLE);
        partial_flow.generate_blocks()
    }

    /// Set the maximum instruction limit. Faithful to `setMaximumInstructions`.
    // Ghidra: flow.hh:148 FlowInfo::setMaximumInstructions
    pub fn set_max_instructions(&mut self, max: u64) {
        self.insn_max = max;
    }

    /// Establish the flow bounds. Faithful to inline `setRange`
    /// (flow.hh:145).
    // Ghidra: flow.hh:145 FlowInfo::setRange
    pub fn set_range(&mut self, b: u64, e: u64) {
        self.baddr = b;
        self.eaddr = e;
    }

    /// Enable a specific flow option. Faithful to inline `setFlags`
    /// (flow.hh:147).
    // Ghidra: flow.hh:147 FlowInfo::setFlags
    pub fn set_flags(&mut self, val: u32) {
        self.flags |= val;
    }

    /// Disable a specific flow option. Faithful to inline `clearFlags`
    /// (flow.hh:148).
    // Ghidra: flow.hh:148 FlowInfo::clearFlags
    pub fn clear_flags(&mut self, val: u32) {
        self.flags &= !val;
    }

    /// Get the number of bytes covered by the flow. Faithful to inline
    /// `getSize` (flow.hh:160).
    // Ghidra: flow.hh:160 FlowInfo::getSize
    pub fn get_size(&self) -> u64 {
        // Ghidra returns maxaddr - minaddr; Rugra uses u64 sentinel for "no min".
        if self.minaddr == u64::MAX {
            0
        } else {
            self.maxaddr.saturating_sub(self.minaddr)
        }
    }

    /// Has the given instruction (address) been seen in flow. Faithful to
    /// inline `seenInstruction` (flow.hh:108).
    // Ghidra: flow.hh:108 FlowInfo::seenInstruction
    pub fn seen_instruction(&self, addr: Address) -> bool {
        self.visited.contains_key(&addr.as_u64())
    }

    /// Are there possible unreachable ops. Faithful to inline
    /// `hasPossibleUnreachable` (flow.hh:105).
    // Ghidra: flow.hh:105 FlowInfo::hasPossibleUnreachable
    pub fn has_possible_unreachable(&self) -> bool {
        (self.flags & flow_flags::POSSIBLE_UNREACHABLE) != 0
    }

    /// Mark that there may be unreachable ops. Faithful to inline
    /// `setPossibleUnreachable` (flow.hh:106).
    // Ghidra: flow.hh:106 FlowInfo::setPossibleUnreachable
    pub fn set_possible_unreachable(&mut self) {
        self.flags |= flow_flags::POSSIBLE_UNREACHABLE;
    }

    /// Does this flow have injections. Faithful to inline `hasInject`
    /// (flow.hh:161).
    // Ghidra: flow.hh:161 FlowInfo::hasInject
    pub fn has_inject(&self) -> bool {
        // flow.hh:161: `return !injectlist.empty();` — any pending inject op.
        self.injectlist.iter().any(|o| o.is_some())
    }

    /// Does this flow have unimplemented instructions. Faithful to inline
    /// `hasUnimplemented` (flow.hh:162).
    // Ghidra: flow.hh:162 FlowInfo::hasUnimplemented
    pub fn has_unimplemented(&self) -> bool {
        (self.flags & flow_flags::UNIMPLEMENTED_PRESENT) != 0
    }

    /// Does this flow reach inaccessible data. Faithful to inline
    /// `hasBadData` (flow.hh:163).
    // Ghidra: flow.hh:163 FlowInfo::hasBadData
    pub fn has_bad_data(&self) -> bool {
        (self.flags & flow_flags::BADDATA_PRESENT) != 0
    }

    /// Does this flow flow out of bound. Faithful to inline `hasOutOfBounds`
    /// (flow.hh:164).
    // Ghidra: flow.hh:164 FlowInfo::hasOutOfBounds
    pub fn has_out_of_bounds(&self) -> bool {
        (self.flags & flow_flags::OUTOFBOUNDS_PRESENT) != 0
    }

    /// Does this flow reinterpret bytes. Faithful to inline `hasReinterpreted`
    /// (flow.hh:165).
    // Ghidra: flow.hh:165 FlowInfo::hasReinterpreted
    pub fn has_reinterpreted(&self) -> bool {
        (self.flags & flow_flags::REINTERPRETED_PRESENT) != 0
    }

    /// Does this flow have too many instructions. Faithful to inline
    /// `hasTooManyInstructions` (flow.hh:166).
    // Ghidra: flow.hh:166 FlowInfo::hasTooManyInstructions
    pub fn has_too_many_instructions(&self) -> bool {
        (self.flags & flow_flags::TOOMANYINSTRUCTIONS_PRESENT) != 0
    }

    /// Is this flow to be in-lined. Faithful to inline `isFlowForInline`
    /// (flow.hh:167).
    // Ghidra: flow.hh:167 FlowInfo::isFlowForInline
    pub fn is_flow_for_inline(&self) -> bool {
        (self.flags & flow_flags::FLOW_FORINLINE) != 0
    }

    /// Should jump table structure be recorded. Faithful to inline
    /// `doesJumpRecord` (flow.hh:168).
    // Ghidra: flow.hh:168 FlowInfo::doesJumpRecord
    pub fn does_jump_record(&self) -> bool {
        (self.flags & flow_flags::RECORD_JUMPLOADS) != 0
    }

    /// Clear any discovered flow properties. Faithful to `clearProperties`
    /// (flow.cc:78-83). Resets the presence flags and the instruction
    /// counter, preparing for a fresh pass over the function.
    // Ghidra: flow.cc:78 FlowInfo::clearProperties
    pub fn clear_properties(&mut self) {
        self.flags &= !(flow_flags::UNIMPLEMENTED_PRESENT
            | flow_flags::BADDATA_PRESENT
            | flow_flags::OUTOFBOUNDS_PRESENT);
        self.insn_count = 0;
    }

    /// Generate warning message or throw exception for given flow that is
    /// out of bounds. Faithful to `handleOutOfBounds` (flow.cc:519-540).
    /// Rugra does not throw — it logs a warning and sets the
    /// `OUTOFBOUNDS_PRESENT` flag unless `IGNORE_OUTOFBOUNDS` is set.
    // Ghidra: flow.cc:519 FlowInfo::handleOutOfBounds
    fn handle_out_of_bounds(&mut self, fromaddr: Address, toaddr: Address) {
        if (self.flags & flow_flags::IGNORE_OUTOFBOUNDS) != 0 {
            return;
        }
        let msg = format!(
            "Function flow out of bounds: {:#x} flows to {:#x}",
            fromaddr.as_u64(),
            toaddr.as_u64()
        );
        if (self.flags & flow_flags::ERROR_OUTOFBOUNDS) == 0 {
            // data.warning(msg, toaddr);
            eprintln!("[FLOW] {}: {}", self.fd.name, msg);
            if !self.has_out_of_bounds() {
                self.flags |= flow_flags::OUTOFBOUNDS_PRESENT;
                self.fd.warning_header("Function flows out of bounds");
            }
        } else {
            // Ghidra throws LowlevelError; Rugra logs at error level instead.
            eprintln!("[FLOW] ERROR: {}: {}", self.fd.name, msg);
        }
    }

    /// Generate warning message or exception for a reinterpreted address.
    /// Faithful to `reinterpreted` (flow.cc:606-629). A set of bytes is
    /// reinterpreted if there are at least two different interpretations of
    /// the bytes as instructions. Rugra logs and sets the
    /// `REINTERPRETED_PRESENT` flag instead of throwing.
    // Ghidra: flow.cc:606 FlowInfo::reinterpreted
    fn reinterpreted(&mut self, addr: Address) {
        // Find the previously visited instruction whose tail overlaps addr.
        let mut addr2: Option<u64> = None;
        for (&k, _stat) in self.visited.range(..=addr.as_u64()).rev() {
            addr2 = Some(k);
            break;
        }
        let addr2 = match addr2 {
            Some(a) => a,
            None => return, // Should never happen.
        };
        let msg = format!(
            "Instruction at ({:#x}) overlaps instruction at ({:#x})",
            addr.as_u64(),
            addr2
        );
        if (self.flags & flow_flags::ERROR_REINTERPRETED) != 0 {
            eprintln!("[FLOW] ERROR: {}: {}", self.fd.name, msg);
            return;
        }
        if (self.flags & flow_flags::REINTERPRETED_PRESENT) == 0 {
            self.flags |= flow_flags::REINTERPRETED_PRESENT;
            self.fd.warning_header(&msg);
        }
    }

    /// An artificial halt is a special form of RETURN op. Faithful to
    /// `artificialHalt` (flow.cc:592-601). The op is annotated with the
    /// desired type of artificial halt:
    ///   - badinstruction (`PcodeOp::badinstruction`)
    ///   - unimplemented (`PcodeOp::unimplemented`)
    ///   - missing/truncated (`PcodeOp::missing`)
    ///   - noreturn (`PcodeOp::noreturn`)
    /// Returns the new RETURN op. The op is left in the dead list (Ghidra
    /// inserts via `data.newOp`, which is dead until `opInsert`).
    // Ghidra: flow.cc:592 FlowInfo::artificialHalt
    fn artificial_halt(&mut self, addr: Address, flag: u32) -> crate::op::PcodeOpRef {
        let haltop = self.fd.new_op(1, addr);
        self.fd.op_set_opcode(&haltop, OpCode::CPUI_RETURN);
        let c = self.fd.new_constant(4, 1);
        self.fd.op_set_input(&haltop, c, 0);
        if flag != 0 {
            self.fd.op_mark_halt(&haltop, flag);
        }
        haltop
    }

    /// Test if the given p-code op is a member of an array. Faithful to
    /// `isInArray` (flow.cc:776-783). This is a static helper in Ghidra used
    /// by `recoverJumpTables` to dedup BRANCHIND ops that need to be retried.
    // Ghidra: flow.cc:776 FlowInfo::isInArray
    fn is_in_array(array: &[crate::op::PcodeOpRef], op: &crate::op::PcodeOpRef) -> bool {
        array.iter().any(|x| std::sync::Arc::ptr_eq(&x.0, &op.0))
    }

    /// Delete any remaining ops at the end of the instruction (because they
    /// have been predetermined to be dead). Faithful to `deleteRemainingOps`
    /// (flow.cc:240-248): Ghidra walks the raw dead list from `oiter` to
    /// `endDead()` calling `opDestroyRaw`, which destroys the op's
    /// input/output Varnodes and retires the op from the bank
    /// (funcdata_op.cc:253-261). `after` is the dead-chain marker of the
    /// last surviving op — the id-space form of `oiter` (the stored
    /// dead-list iterator, op.hh:128); `None` means "from the chain head".
    // Ghidra: flow.cc:240 FlowInfo::deleteRemainingOps
    fn delete_remaining_ops_after(&mut self, after: Option<crate::arena::OpId>) {
        // Snapshot the tail run so we can destroy without upsetting the
        // borrow checker (op_destroy_raw mutates the chain).
        let to_remove: Vec<crate::op::PcodeOpRef> = self
            .fd
            .obank
            .iter_dead_from(after)
            .cloned()
            .collect();
        for op in &to_remove {
            self.fd.op_destroy_raw(op);
        }
    }

    /// A function is in the EZ model if it is a straight-line leaf function.
    /// Faithful to `checkEZModel` (flow.cc:1157-1167). Returns true if this
    /// flow contains no CALL or BRANCH ops.
    // Ghidra: flow.cc:1157 FlowInfo::checkEZModel
    pub fn check_ez_model(&self) -> bool {
        for op_ref in self.fd.obank.iter_dead() {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_RETURN => return false,
                _ => {}
            }
        }
        true
    }

    /// Treat an indirect jump (BRANCHIND) whose jumptable could not be
    /// recovered as a CALLIND or RETURN instead. Faithful to
    /// `FlowInfo::truncateIndirectJump` (flow.cc:727-769).
    ///
    /// For `fail_return` the BRANCHIND becomes a RETURN. Otherwise it
    /// becomes a CALLIND with a callspec from `setup_callind_specs`
    /// (flow.cc:736); the `fail_callother` path marks that callspec
    /// no-return (`fc->setNoReturn(true)`, flow.cc:747) and installs the
    /// locked void internal prototype (`fc->setInternal(glb->defaultfp,
    /// void)` + input/output locks, flow.cc:757-763); the default
    /// path marks it a bad jump table. An artificial halt of the
    /// mode-determined type is inserted right after the op. `setBadJumpTable`
    /// (flow.cc:754) is wired since the fspec badjumptable data plane landed
    /// (CALLSPEC deb2b09b), its output consumer
    /// `ActionNameVars::lookForBadJumpTables` (coreaction.cc:2779-2803,
    /// UNRECOVERED_JUMPTABLE naming) rides the CSPEC2 lane.
    // Ghidra: flow.cc:727 FlowInfo::truncateIndirectJump
    pub fn truncate_indirect_jump(
        &mut self,
        op: &crate::op::PcodeOpRef,
        mode: crate::jumptable::RecoveryMode,
    ) {
        let addr = {
            let o = op.0.read().unwrap();
            o.get_addr()
        };
        if let crate::jumptable::RecoveryMode::FailReturn = mode {
            // flow.cc:730-732: turn the jump into a RETURN.
            self.fd.op_set_opcode(op, OpCode::CPUI_RETURN);
            // flow.cc:732: data.warning("Treating indirect jump as return").
            self.fd.warning("Treating indirect jump as return", addr);
            return;
        }
        // flow.cc:735: turn the jump into a CALLIND.
        self.fd.op_set_opcode(op, OpCode::CPUI_CALLIND);
        // flow.cc:736: setupCallindSpecs(op, NULL) — establish the callspec
        // (identity, query_call, flow-modification check).
        self.setup_callind_specs(op, None);
        // flow.cc:737: `FuncCallSpecs *fc = data.getCallSpecs(op)`.
        let fc_owner = find_callspec_for_op(self.fd, op);
        let (return_type, no_params) = match mode {
            // flow.cc:741-743: fail_thunk — plain call, fall-through halt.
            crate::jumptable::RecoveryMode::FailThunk => (0u32, false),
            crate::jumptable::RecoveryMode::FailCallother => {
                // flow.cc:745-749: the address was formed by CALLOTHER — the
                // truncated call never returns.
                if let Some(fc) = fc_owner.as_ref() {
                    // flow.cc:747: fc->setNoReturn(true).
                    fc.write().unwrap().set_no_return(true);
                }
                // flow.cc:748: data.warning("Does not return", op->getAddr()).
                self.fd.warning("Does not return", addr);
                (pcodeop_flags::NORETURN, true)
            }
            // flow.cc:751-755: default (fail_normal) — consider using a
            // special name for the switch variable.
            _ => {
                // flow.cc:754: fc->setBadJumpTable(true).
                if let Some(fc) = fc_owner.as_ref() {
                    fc.write().unwrap().set_bad_jump_table(true);
                }
                // flow.cc:755: data.warning("Treating indirect jump as call").
                self.fd.warning("Treating indirect jump as call", addr);
                (0u32, false)
            }
        };
        if no_params {
            // flow.cc:757-763: `if (!fc->hasModel()) { fc->setInternal(
            // glb->defaultfp, glb->types->getTypeVoid()); fc->setInputLock(
            // true); fc->setOutputLock(true); }` — the fail_callother
            // callspec becomes an internally-backed void prototype with both
            // locks, so ActionFuncLink::func_link_output's locked-void gate
            // (coreaction.cc:1540-1542, TYPE_VOID → no output varnode) keeps
            // the truncated CALLIND outputless and ActionActiveReturn never
            // activates (coreaction.cc:1770 isOutputActive check). The model
            // is the Architecture default (glb->defaultfp — not evalfp), and
            // setInternal's own `if (model == 0) setModel(m)` guard (fspec.cc
            // 3895-3897) keeps a pre-bound model untouched.
            if let Some(fc) = fc_owner.as_ref() {
                let mut f = fc.write().unwrap();
                if !f.prototype.has_model() {
                    let default_model = self.fd.get_arch().and_then(|a| a.defaultfp.clone());
                    let void_type = self
                        .fd
                        .get_arch()
                        .and_then(|a| {
                            a.types
                                .as_ref()
                                .and_then(|factory| factory.read().ok().map(|f| f.get_type_void()))
                        })
                        .unwrap_or_else(|| {
                            crate::type_system::typefactory::TypeFactory::shared_default()
                                .read()
                                .expect("shared type factory lock poisoned")
                                .get_type_void()
                        });
                    f.prototype.set_internal(default_model, void_type);
                    f.prototype.set_input_lock(true);
                    f.prototype.set_output_lock(true);
                }
            }
        }
        // flow.cc:765-767: create an artificial return right after the op
        // (data.opDeadInsertAfter — the funcdata.hh:460 dead-list wrapper,
        // mirroring the halt in checkForFlowModification).
        let truncop = self.artificial_halt(addr, return_type);
        self.fd.obank.insert_after_dead(&truncop, op);
    }

    /// Recover jumptables for the current set of BRANCHIND ops using existing
    /// flow. Faithful to `FlowInfo::recoverJumpTables`
    /// (flow.cc:1427-1458).
    ///
    /// Ghidra builds a fresh partial `Funcdata` for analysis, then walks every
    /// op in `tablelist` calling `data.recoverJumpTable(partial, op, this,
    /// mode)`. On failure it calls `truncateIndirectJump(op, mode)`; on a
    /// partial recovery it either defers the op to `notreached` (if more flow
    /// is coming) or marks the table complete. A LowlevelError escaping the
    /// staged recovery propagates to the caller exactly as the C++ throw
    /// escapes `recoverJumpTables` → `generateOps` → `followFlow`.
    // Ghidra: flow.cc:1427 FlowInfo::recoverJumpTables
    pub fn recover_jump_tables(
        &mut self,
        new_tables: &mut Vec<Option<Arc<RwLock<crate::jumptable::JumpTable>>>>,
        notreached: &mut Vec<crate::op::PcodeOpRef>,
    ) -> crate::error::Result<()> {
        // flow.cc:1430-1435: the partial Funcdata label is built from
        // tablelist[0]'s address (printRaw of a ram-space address is the
        // zero-padded 8-digit hex offset).
        let op0_addr = self.tablelist[0].0.read().unwrap().get_addr().as_u64();
        let nm = format!("{}@@jump@{:08x}", self.fd.get_name(), op0_addr);
        // flow.cc:1437: Funcdata partial(nm,nm,data.getScopeLocal()
        // ->getParent(),data.getAddress(),(FunctionSymbol *)0); — the partial
        // shares the architecture and entry address of the source function.
        let entry = *self.fd.get_address();
        let fd_size = self.fd.size;
        let arch = self.fd.get_arch().cloned();
        let mut partial = Funcdata::new(&nm, entry, fd_size);
        // RESIDMAP-PRINTBATCH-0001: the partial clone inherits the source
        // function's display image-base delta so its jumptable Lowlevel
        // warning texts (recover_addresses_classified, jumptable.cc:2629)
        // print the same oracle printRaw spelling as the parent.
        partial.display_image_base = self.fd.display_image_base;
        if let Some(arch) = arch {
            partial.set_arch(arch);
        }
        // Funcdata::truncatedFlow reads the source FlowInfo through this
        // snapshot (the C++ passes the FlowInfo pointer itself).
        let flow_state = self.truncated_state();

        let tablelist_len = self.tablelist.len();
        for i in 0..tablelist_len {
            let op = self.tablelist[i].clone();
            // flow.cc:1441-1442: mode is an out parameter of
            // data.recoverJumpTable(partial,op,this,mode).
            let mut mode = crate::jumptable::RecoveryMode::Success;
            let jt = self.fd.recover_jump_table(&mut partial, &op, &mut mode, &flow_state)?;
            match &jt {
                None => {
                    // Could not recover the jumptable (flow.cc:1443-1445):
                    // unless this flow is being inlined for something else,
                    // treat the indirect jump as a call/return.
                    if !self.is_flow_for_inline() {
                        eprintln!(
                            "[JUMPTABLE] recovery failed at 0x{:x} mode={:?} → truncate",
                            op.0.read().unwrap().get_addr().as_u64(),
                            mode
                        );
                        self.truncate_indirect_jump(&op, mode);
                    }
                }
                Some(jt) => {
                    if jt.read().unwrap().is_partial() {
                        // flow.cc:1447-1455: defer if more flow is coming and
                        // we have not already queued this op.
                        if tablelist_len > 1 && !Self::is_in_array(notreached, &op) {
                            notreached.push(op.clone());
                        } else {
                            // flow.cc:1454: jt->markComplete();
                            jt.write().unwrap().mark_complete();
                        }
                    }
                }
            }
            new_tables.push(jt);
        }
        Ok(())
    }

    /// Look for changes in control-flow near indirect jumps that were
    /// discovered after the jumptable recovery. Faithful to
    /// `FlowInfo::checkMultistageJumptables` (flow.cc:1408-1417): every
    /// `JumpTable` on `data` is consulted, and any table that
    /// `checkForMultistage` promotes has its indirect op pushed back onto
    /// `tablelist` so the generateOps do-while revisits it.
    // Ghidra: flow.cc:1408 FlowInfo::checkMultistageJumptables
    pub fn check_multistage_jumptables(&mut self) {
        // flow.cc:1412: int4 num = data.numJumpTables(); — the census is
        // fixed up front; only tablelist is appended in the loop body.
        let num = self.fd.jump_tables.len();
        for i in 0..num {
            let jt_arc = self.fd.jump_tables[i].clone();
            let promote = jt_arc.write().unwrap().check_for_multistage(self.fd);
            // flow.cc:1414-1415: if (jt->checkForMultistage(&data))
            //   tablelist.push_back(jt->getIndirectOp());
            if promote {
                if let Some(indirect) = jt_arc.read().unwrap().get_indirect_op() {
                    self.tablelist.push(crate::op::PcodeOpRef(indirect));
                }
            }
        }
    }

    /// If the given injected op is a CALL, CALLIND, or BRANCHIND, add
    /// references to it in the other flow tables. The BRANCHIND table slice
    /// corresponds to `FlowInfo::xrefInlinedBranch` (flow.cc:1053-1065); the
    /// CALL/CALLIND setup consumers remain `CALLSPEC-0001`/UNTESTED.
    ///
    /// For BRANCHIND, Ghidra calls `data.linkJumpTable(op)` and, if that
    /// returns NULL, pushes the op onto `tablelist` so it will be recovered
    /// later. Rugra does not yet have `Funcdata::linkJumpTable`, so we mirror
    /// the logic with a local `find_jump_table` lookup and push onto the
    /// returned work-list when no table is linked.
    // Ghidra: flow.cc:1053 FlowInfo::xrefInlinedBranch
    pub fn xref_inlined_branch(
        &mut self,
        op: &crate::op::PcodeOpRef,
    ) -> Vec<crate::op::PcodeOpRef> {
        let mut new_tablelist: Vec<crate::op::PcodeOpRef> = Vec::new();
        let code = op.0.read().unwrap().opcode;
        match code {
            OpCode::CPUI_CALL => {
                // flow.cc:1057 calls setupCallSpecs. The exact helper exists,
                // but this xref consumer remains unwired under CALLSPEC-0001.
            }
            OpCode::CPUI_CALLIND => {
                // flow.cc:1059 calls setupCallindSpecs. The exact helper exists,
                // but this xref consumer remains unwired under CALLSPEC-0001.
            }
            OpCode::CPUI_BRANCHIND => {
                // data.linkJumpTable(op) — flow.cc:1061. Rugra's equivalent is
                // find_jump_table; if none exists we queue the op for recovery.
                let linked = self.fd.find_jump_table(op).is_some();
                if !linked {
                    new_tablelist.push(op.clone());
                }
            }
            _ => {}
        }
        new_tablelist
    }

    /// Add any remaining un-followed addresses to the unprocessed list.
    /// Faithful to `FlowInfo::findUnprocessed` (flow.cc:850-863). For each
    /// address still on `addrlist`: if we have already seen it, Ghidra marks
    /// its target op as a basic-block start; otherwise it is appended to
    /// `unprocessed`.
    // Ghidra: flow.cc:850 FlowInfo::findUnprocessed
    pub fn find_unprocessed(&mut self) {
        // Snapshot addrlist so we can mutate self while iterating.
        let addrs: Vec<Address> = self.addrlist.drain(..).collect();
        for addr in addrs {
            if self.seen_instruction(addr) {
                // Ghidra: PcodeOp *op = target(*iter); data.opMarkStartBasic(op);
                if let Some(op) = self.target(addr) {
                    op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                }
            } else {
                self.unprocessed.push(addr);
            }
        }
    }

    /// Sort the unprocessed list and remove duplicates. Faithful to
    /// `FlowInfo::dedupUnprocessed` (flow.cc:866-885). Ghidra hand-rolls the
    /// dedup over a sorted vector; Rust's `sort` + `dedup` produce the same
    /// result because `Address: Ord`.
    // Ghidra: flow.cc:866 FlowInfo::dedupUnprocessed
    pub fn dedup_unprocessed(&mut self) {
        if self.unprocessed.is_empty() {
            return;
        }
        self.unprocessed.sort();
        self.unprocessed.dedup();
    }

    /// Generate a special-form RETURN (artificial halt) for every address in
    /// the unprocessed list. Faithful to `FlowInfo::fillinBranchStubs`
    /// (flow.cc:889-901). Each stub is marked as both a basic-block start and
    /// an instruction start.
    // Ghidra: flow.cc:889 FlowInfo::fillinBranchStubs
    pub fn fillin_branch_stubs(&mut self) {
        self.find_unprocessed();
        self.dedup_unprocessed();
        let stubs: Vec<Address> = self.unprocessed.iter().cloned().collect();
        for addr in &stubs {
            let op = self.artificial_halt(*addr, pcodeop_flags::MISSING);
            // Ghidra: data.opMarkStartBasic(op); data.opMarkStartInstruction(op);
            // Ghidra leaves the artificial halt raw/dead here and applies both
            // marks before splitBasic integrates it into a block.
            {
                let mut o = op.0.write().unwrap();
                o.flags |= pcodeop_flags::STARTBASIC;
                o.flags |= pcodeop_flags::STARTMARK;
            }
        }
    }

    /// Collect edges between basic blocks as (source_op, target_op) pairs.
    /// Faithful to `FlowInfo::collectEdges` (flow.cc:906-977).
    ///
    /// Edges are generated for:
    ///   - BRANCH: one edge to `branchTarget` (const-space relative branches
    ///     resolve through `findRelTarget`; machine-address branches through
    ///     `target`)
    ///   - CBRANCH: fallthru edge first, then the branch-target edge
    ///     (flow.cc:961-966)
    ///   - BRANCHIND: one edge per jump-table entry (de-duped via setMark,
    ///     with the mark run cleaned up exactly as in flow.cc:947-956)
    ///   - any other op: a fallthru edge when the next op starts a basic
    ///     block (or when this is the final op in the bank)
    // Ghidra: flow.cc:906 FlowInfo::collectEdges
    pub fn collect_edges(&mut self) -> Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)> {
        let mut edges: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)> = Vec::new();
        let dead: Vec<crate::op::PcodeOpRef> = self.fd.obank.iter_dead().cloned().collect::<Vec<_>>();

        for (idx, op_ref) in dead.iter().enumerate() {
            let code = op_ref.0.read().unwrap().opcode;
            // flow.cc:922-925: the boundary flag comes from the next op.
            let nextstart = match dead.get(idx + 1) {
                Some(next) => (next.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0,
                None => true, // end of list acts like a block boundary
            };
            match code {
                OpCode::CPUI_BRANCH => {
                    // flow.cc:927-932.
                    if let Some(targ) = self.branch_target(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                }
                OpCode::CPUI_BRANCHIND => {
                    // data.findJumpTable(op) — flow.cc:934. If there is no
                    // table we are doing partial flow analysis, assume no
                    // out-edges (flow.cc:935-937).
                    let op_addr = op_ref.0.read().unwrap().get_addr();
                    if let Some(jt_arc) =
                        self.fd.jump_tables.iter().find(|jt| {
                            jt.read().unwrap().get_op_address().as_u64() == op_addr.as_u64()
                        })
                    {
                        let jt = jt_arc.read().unwrap();
                        let num = jt.num_entries();
                        // De-dup targets within this BRANCHIND via setMark
                        // (flow.cc:941-946). We snapshot entries first.
                        let mut marked: Vec<crate::op::PcodeOpRef> = Vec::new();
                        for i in 0..num {
                            let addr = jt.get_address_by_index(i);
                            if let Some(targ) = self.target(addr) {
                                if targ.0.read().unwrap().is_mark() {
                                    continue;
                                }
                                targ.0.write().unwrap().set_mark();
                                marked.push(targ.clone());
                                edges.push((op_ref.clone(), targ));
                            }
                        }
                        // flow.cc:947-956: clean up exactly the marks set for
                        // this op's trailing edge run (every edge pushed
                        // above belongs to this op, so clearing `marked`
                        // matches Ghidra's backward walk).
                        for targ in &marked {
                            targ.0.write().unwrap().clear_mark();
                        }
                    }
                }
                OpCode::CPUI_RETURN => {
                    // No out-edge (flow.cc:958-959).
                }
                OpCode::CPUI_CBRANCH => {
                    // flow.cc:960-967: fallthru edge first, then branch edge.
                    if let Some(targ) = self.fallthru_op(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                    if let Some(targ) = self.branch_target(op_ref) {
                        edges.push((op_ref.clone(), targ));
                    }
                }
                _ => {
                    // flow.cc:968-974: fallthru edge if new basic block.
                    if nextstart {
                        if let Some(targ) = self.fallthru_op(op_ref) {
                            edges.push((op_ref.clone(), targ));
                        }
                    }
                }
            }
        }
        self.block_edges = edges.clone();
        edges
    }

    // ===================== Public control-flow target queries =====================
    // These mirror Ghidra's public `target`/`branchTarget`/`fallthruOp`/
    // `findRelTarget`/`updateTarget` API (flow.cc:88/115/149/187/204). The
    // audit (flow_audit.md item 8) flagged that Rugra downgraded these to
    // private (`target_op_*`/`fallthru_op`) and never exposed them; the
    // wrappers below restore the public surface so an action system can query
    // control-flow targets. The private helpers retain the original names so
    // existing call-sites (`collect_edges`, etc.) are unchanged.

    /// Return the first p-code op associated with the machine instruction at
    /// the given address. Faithful to `FlowInfo::target` (flow.cc:115-138).
    ///
    /// Ghidra looks the instruction up in `visited`, resolves the recorded
    /// first-op `SeqNum` through `obank.findOp`, and — when the instruction
    /// produced no p-code (INVALID SeqNum) — falls through to the next
    /// instruction. It throws `LowlevelError` when no op is ultimately
    /// found; Rugra returns `None` so callers can log/handle it.
    // Ghidra: flow.cc:115 FlowInfo::target
    pub fn target(&self, addr: Address) -> Option<crate::op::PcodeOpRef> {
        let mut cur = addr.as_u64();
        // flow.cc:120-131: walk visited, skipping no-op instructions.
        while let Some(stat) = self.visited.get(&cur) {
            match stat.first_seq {
                Some(seq) => {
                    // flow.cc:124: a valid SeqNum resolves directly.
                    if let Some(retop) = self.fd.obank.find_op(&seq) {
                        return Some(retop);
                    }
                    // flow.cc:126-127: valid SeqNum but the op is gone —
                    // Ghidra breaks out of the loop and throws.
                    break;
                }
                // flow.cc:129-130: no p-code for this instruction — visit the
                // fall-through address in case of a no-op.
                None => cur += stat.size as u64,
            }
        }
        None
    }

    /// Find the p-code op referred to by a BRANCH or CBRANCH input(0).
    /// Faithful to `FlowInfo::branchTarget` (flow.cc:187-199).
    ///
    /// A Const-space input(0) is a *relative* sequence-number offset and is
    /// resolved through `findRelTarget` (with a `target(res)` fallback for a
    /// branch to the next instruction); any other space is a normal machine
    /// address resolved through `target`.
    // Ghidra: flow.cc:187 FlowInfo::branchTarget
    pub fn branch_target(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        let in0 = op.0.read().unwrap().inrefs.get(0).cloned();
        let in0 = in0?;
        let (dest_space, dest_offset) = {
            let varnode = in0.read().unwrap();
            (varnode.get_space(), varnode.get_offset())
        };
        if dest_space.is_const() {
            // flow.cc:191-196: relative sequence number.
            match self.find_rel_target(op) {
                Ok(RelativeTarget::Internal(retop)) => Some(retop),
                Ok(RelativeTarget::Fallthru(res)) => self.target(res),
                // Ghidra throws LowlevelError("Bad relative branch...");
                // Rugra surfaces the failure to the caller.
                Err(_) => None,
            }
        } else {
            // flow.cc:198: normal address target.
            self.target(Address::new(dest_offset))
        }
    }

    /// Find the fallthru p-code op for a given op. Faithful to
    /// `FlowInfo::fallthruOp` (flow.cc:88-107, public non-const overload).
    // Ghidra: flow.cc:88 FlowInfo::fallthruOp
    pub fn fallthru_op_pub(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        self.fallthru_op(op)
    }

    /// Generate the target PcodeOp for a relative branch. Faithful to
    /// `FlowInfo::findRelTarget` (flow.cc:149-179).
    ///
    /// The branch input(0) is a Const-space Varnode holding the masked
    /// relative offset produced by `PcodeCacher::resolveRelatives`
    /// (sleigh.cc:120-134: `(labels[id] - calling_index) & calc_mask(size)`).
    /// The absolute target time is `op->getTime() + offset`; the op at that
    /// immutable SeqNum time is the "properly internal" target. If it does
    /// not exist, the op one time earlier must exist and the branch is
    /// really to the next instruction, whose machine address is passed back
    /// through `res`. Anything else is a corrupt relative branch (Ghidra
    /// throws `LowlevelError`; Rugra reports `Err`).
    // Ghidra: flow.cc:149 FlowInfo::findRelTarget
    pub fn find_rel_target(
        &self,
        op: &crate::op::PcodeOpRef,
    ) -> Result<RelativeTarget, String> {
        let (op_addr, op_time, dest_offset) = {
            let operation = op.0.read().unwrap();
            // Clone input(0) so the borrow of the op guard is released
            // before reading the varnode (Ghidra dereferences
            // `op->getIn(0)->getAddr()` in one expression).
            let in0 = operation
                .inrefs
                .get(0)
                .cloned()
                .ok_or_else(|| "relative branch has no input zero".to_string())?;
            let offset = in0.read().unwrap().get_offset();
            (operation.get_addr(), operation.get_time(), offset)
        };
        // flow.cc:153-157: absolute target time + exact SeqNum lookup.
        let id = op_time.wrapping_add(dest_offset as u32);
        let seqnum = crate::address::SeqNum::new(op_addr, id);
        if let Some(retop) = self.fd.obank.find_op(&seqnum) {
            return Ok(RelativeTarget::Internal(retop));
        }
        // flow.cc:159-172: check if the relative branch is really to the
        // next instruction — go back one sequence number.
        let seqnum1 = crate::address::SeqNum::new(op_addr, id.wrapping_sub(1));
        if let Some(retop) = self.fd.obank.find_op(&seqnum1) {
            let retop_addr = retop.0.read().unwrap().get_addr().as_u64();
            // flow.cc:164-168: visited.upper_bound(retop->getAddr()) then
            // step one predecessor; res = instruction start + size.
            if let Some((&instruction, stat)) =
                self.visited.range(..=retop_addr).next_back()
            {
                let res = instruction + stat.size as u64;
                if op_addr.as_u64() < res {
                    // flow.cc:170: indicate that res has the fallthru address.
                    return Ok(RelativeTarget::Fallthru(Address::new(res)));
                }
            }
        }
        Err(format!(
            "Bad relative branch at instruction : (ram,{:#x})",
            op_addr.as_u64()
        ))
    }

    /// Update the branch target for an inlined p-code op. Faithful to
    /// `FlowInfo::updateTarget` (flow.cc:204-212). When an op is replaced by
    /// the first op of an injected sequence, any visited-instruction entry
    /// whose first-op SeqNum equals the old op's must be repointed at the
    /// new op. Ghidra compares with `SeqNum::operator==`, which is
    /// *time-only* identity (address.hh:148).
    // Ghidra: flow.cc:204 FlowInfo::updateTarget
    pub fn update_target(
        &mut self,
        old_op: &crate::op::PcodeOpRef,
        new_op: &crate::op::PcodeOpRef,
    ) {
        let old_addr = old_op.0.read().unwrap().get_addr();
        let old_time = old_op.0.read().unwrap().get_time();
        // flow.cc:207-211: if the old op is the recorded first-op for its
        // address, replace the seqnum with the new op's seqnum.
        if let Some(stat) = self.visited.get_mut(&old_addr.as_u64()) {
            if stat.first_seq.map(|s| s.get_time()) == Some(old_time) {
                stat.first_seq = Some(new_op.0.read().unwrap().start);
            }
        }
    }

    // ===================== FuncCallSpecs maintenance =====================
    // These mirror Ghidra's call-spec lifecycle methods (flow.cc:636-723,
    // 1306-1318). Ghidra's Funcdata `qlst` owns stable heap allocations;
    // Rugra's `Vec<Arc<RwLock<FuncCallSpecs>>>` is the corresponding strong
    // owner container, while every reverse identity edge is Weak.

    /// Check for modifications to flow at a call site given the recovered
    /// FuncCallSpecs. This models the identity wiring and flow-editing shape of
    /// `FlowInfo::checkForFlowModification` (flow.cc:636-651), but inline and
    /// no-return state propagation remains `CALLSPEC-0001`. Returns true only
    /// when the currently modeled state marks the sub-function non-returning.
    ///
    /// If the call site is inline, its op is pushed onto `injectlist` so
    /// `inject_pcode` will expand it later (flow.cc:639-640). If it never
    /// returns, an artificial halt is inserted right after the call
    /// (flow.cc:642-644) and the method returns true.
    // Ghidra: flow.cc:636 FlowInfo::checkForFlowModification
    fn check_for_flow_modification(&mut self, fc_idx: usize) -> bool {
        let (is_inline, is_no_return, op_ref) = {
            let fc = match self.fd.get_call_specs(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let op_ref = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            (fc.is_inline(), fc.is_no_return(), op_ref)
        };
        if is_inline {
            // flow.cc:639-640: queue for inject_pcode.
            self.injectlist.push(Some(op_ref.clone()));
        }
        if is_no_return {
            // flow.cc:642-644: insert an artificial halt after the call.
            let addr = op_ref.0.read().unwrap().get_addr();
            let haltop = self.artificial_halt(addr, pcodeop_flags::NORETURN);
            // flow.cc:643: data.opDeadInsertAfter(haltop, op) — the thin
            // funcdata.hh:460 wrapper over obank.insertAfterDead. The halt
            // must stay in the dead list right after the CALL so
            // xref_control_flow's next iteration (Ghidra's `--oiter`,
            // flow.cc:337) processes it as the instruction's flow
            // terminator; the alive-list opInsertAfter would pull it out of
            // the dead list and the fall-through would be queued anyway.
            self.fd.obank.insert_after_dead(&haltop, &op_ref);
            if !is_inline {
                // flow.cc:645-646: warning only when not inline.
                self.fd.warning("Subroutine does not return", addr);
            }
            return true;
        }
        false
    }

    /// If there is an explicit target address for the given call site,
    /// attempt to look up the function and adjust information in the
    /// FuncCallSpecs call site object. Faithful to `FlowInfo::queryCall`
    /// (flow.cc:656-672).
    ///
    /// Ghidra calls `data.getScopeLocal()->getParent()->queryFunction(addr)`
    /// to resolve the callee's Funcdata; on a hit it runs
    /// `fspecs.setFuncdata(otherfunc)` (entry + display name) and, when the
    /// spec's model is not yet locked or the callee is inline, copies the
    /// callee's flow effects (`copyFlowEffects`, which carries the
    /// inline/no-return flags). The resolved callee is what makes
    /// `checkContainedCall`'s `fd != 0 continue` guard (flow.cc:1367-1368)
    /// skip calls whose entry was also traced by tail-jump flow — without
    /// it, every such legitimate call is misreported as a PIC construction.
    ///
    /// Rugra's front-end equivalent of `queryFunction` is the driver-seeded
    /// symbol table (`fd.symbol_table`, the same boundary the driver's
    /// CALLSPEC-DRIVER-0001 `link_call_specs` uses post-flow): a symbol at
    /// the entry address resolves the callee, `set_funcdata` copies the
    /// entry/display-name pair (fspec.cc:4949-4960 observable slice), and
    /// the resolution is recorded in `resolved_funcdata` for
    /// `check_contained_call`. The callee's `FuncProto` for
    /// `copy_flow_effects` comes from the flow-visible
    /// [`FlowInfo::callee_func_protos`] table — the `funcp` slice of the
    /// Funcdata `queryFunction` returns on the Ghidra side; its production
    /// data source (the driver-side known-noreturn name list) is
    /// FLOW-NORETURN-DATA-0001.
    // Ghidra: flow.cc:656 FlowInfo::queryCall
    fn query_call(&mut self, fc_idx: usize) {
        // flow.cc:659: `if (!fspecs.getEntryAddress().isInvalid())`.
        let entry = self.fd.get_call_specs(fc_idx).and_then(|fc| fc.entry_addr);
        let entry_addr = match entry {
            Some(a) => a,
            None => return, // Not a direct call (flow.cc:659 guard fails).
        };
        // flow.cc:660: `queryFunction(entry)` — the symbol-table lookup.
        let Some(callee_name) = self.fd.symbol_table.get(&entry_addr.as_u64()).cloned() else {
            return; // No function at this entry: nothing to resolve.
        };
        // flow.cc:660: `otherfunc->getFuncProto()` — the resolved callee's
        // prototype, taken out before the mutable spec borrow below. An
        // absent entry means queryFunction returned no funcp observable
        // (the callee carries no known flow effects).
        let callee_proto = self.callee_func_protos.get(&entry_addr.as_u64()).cloned();
        // Record the resolution for check_contained_call's flow.cc:1367
        // `fd != 0 continue` guard (RUGRA-GLUE: FlowInfo-side set stands in
        // for the per-spec Funcdata pointer Rugra's FuncCallSpecs lacks).
        if let Some(op_addr) = self
            .fd
            .get_call_specs(fc_idx)
            .map(|fc| fc.op_addr.as_u64())
        {
            self.resolved_funcdata.insert(op_addr);
        }
        if let Some(mut fc) = self.fd.get_call_specs_mut(fc_idx) {
            // flow.cc:662: `fspecs.setFuncdata(otherfunc)` — associate the
            // callee's entry address and display name with the callsite.
            fc.set_funcdata(&callee_name, entry_addr);
            if let Some(proto) = callee_proto.as_ref() {
                // flow.cc:663: `if (!fspecs.hasModel() || otherfunc->
                // getFuncProto().isInline())` — take the callee's flow
                // effects unless the callsite prototype was already
                // overridden with a full model (an inline callee always
                // forces the copy).
                if !fc.has_model() || proto.is_inline() {
                    // flow.cc:664: `fspecs.copyFlowEffects(...)` — one-way
                    // is_inline|no_return flag overwrite onto the callsite.
                    fc.copy_flow_effects(proto);
                }
            }
        }
    }

    /// Set up the identity/lifecycle slice of the FuncCallSpecs object for a
    /// new CALL call site. Corresponds to `FlowInfo::setupCallSpecs`
    /// (flow.cc:680-695); the remaining consumer work is `CALLSPEC-0001`.
    /// Returns true if the modeled flow checks discover a non-returning call.
    ///
    /// Ghidra allocates a new `FuncCallSpecs(op)`, rewrites input(0) to a
    /// call-specs varnode, appends to qlst, applies any prototype override,
    /// runs `queryCall`, performs an injection cycle-check against `fc`, and
    /// finally runs `checkForFlowModification`. Rugra constructs the spec
    /// directly, rewrites input(0) to Rugra's synthetic call-spec Varnode,
    /// appends to `self.fd.callspecs`, and runs the cycle check and
    /// flow-modification check. Prototype override application remains a
    /// `CALLSPEC-0001` gap.
    // Ghidra: flow.cc:680 FlowInfo::setupCallSpecs
    fn setup_call_specs(&mut self, op: &crate::op::PcodeOpRef, inject_fc: Option<usize>) -> bool {
        // flow.cc:683-684: new FuncCallSpecs(op) captures the direct target
        // before input(0) is replaced with the call-spec annotation.
        // fspec.cc:3778-3786 FuncProto::FuncProto(): the base-class default
        // constructor — flags = 0 (no input/output/model lock), model = null,
        // no parameters. `new FuncCallSpecs(op)` (fspec.cc:4924-4925) builds
        // exactly that state; it must NOT seed from the caller's own fd.funcp
        // (which may carry DWARF-locked storage), otherwise every unknown
        // callee inherits the caller's output lock and
        // ActionFuncLink::funcLinkOutput's locked-void path (coreaction.cc:1538)
        // suppresses active return recovery (coreaction.cc:1571-1572).
        let proto = default_call_spec_proto();
        let fc = crate::fspec::FuncCallSpecs::new_for_op(op, proto);
        let new_owner = Arc::new(RwLock::new(fc));
        // flow.cc:685: data.opSetInput(op, data.newVarnodeCallSpecs(res), 0).
        let call_spec_vn = self.fd.new_varnode_call_specs(&new_owner);
        self.fd.op_set_input(op, call_spec_vn, 0);
        // flow.cc:686: qlst.push_back(res), after the FSPEC annotation is
        // installed. The local Arc keeps the allocation alive until then.
        let new_idx = self.fd.add_call_specs_owner(new_owner);
        // flow.cc:688: data.getOverride().applyPrototype(data, *res).
        // TODO(CALLSPEC-0001): depends on Override::applyPrototype integration.
        self.query_call(new_idx);
        // flow.cc:690-693: injection cycle check.
        if let Some(fc_inject_idx) = inject_fc {
            let inject_entry = self
                .fd
                .get_call_specs(fc_inject_idx)
                .and_then(|f| f.entry_addr);
            let new_entry = self.fd.get_call_specs(new_idx).and_then(|f| f.entry_addr);
            let same = inject_entry == new_entry;
            if same {
                // flow.cc:692: don't allow recursion.
                if let Some(mut new_fc) = self.fd.get_call_specs_mut(new_idx) {
                    new_fc.cancel_inject_id();
                }
            }
        }
        // flow.cc:694.
        self.check_for_flow_modification(new_idx)
    }

    /// Set up the identity/lifecycle slice of the FuncCallSpecs object for a
    /// new indirect (CALLIND) call site. Corresponds to
    /// `FlowInfo::setupCallindSpecs` (flow.cc:704-723); override/prototype/query
    /// consumers remain `CALLSPEC-0001`. Returns true if the modeled flow
    /// checks discover a non-returning call.
    ///
    /// Ghidra's sequence applies an indirect override first, performs the
    /// injection-cycle cancellation, applies a prototype/query, and rewrites
    /// a resolved CALLIND to CALL (flow.cc:711-721). Rugra currently preserves
    /// the owner/identity order and modeled cancellation/direct rewrite while
    /// override, prototype, and query consumers remain `CALLSPEC-0001`.
    // Ghidra: flow.cc:704 FlowInfo::setupCallindSpecs
    fn setup_callind_specs(
        &mut self,
        op: &crate::op::PcodeOpRef,
        inject_fc: Option<usize>,
    ) -> bool {
        // fspec.cc:4924-4925 + fspec.cc:3778-3786: same default-constructed
        // FuncProto base as the direct CALL path — never the caller's own
        // (possibly DWARF-locked) fd.funcp.
        let proto = default_call_spec_proto();
        let fc = crate::fspec::FuncCallSpecs::new_for_op(op, proto);
        let new_idx = self.fd.add_call_specs(fc);
        // flow.cc:711: data.getOverride().applyIndirect(data, *res).
        // TODO(CALLSPEC-0001): depends on Override::applyIndirect integration.
        // flow.cc:712-713: cancel an indirect override if it matches the
        // injecting fc's entry address.
        if let Some(fc_inject_idx) = inject_fc {
            let inject_entry = self
                .fd
                .get_call_specs(fc_inject_idx)
                .and_then(|f| f.entry_addr);
            let new_entry = self.fd.get_call_specs(new_idx).and_then(|f| f.entry_addr);
            let same = inject_entry == new_entry;
            if same {
                // flow.cc:713: setAddress(Address()); clears the entry.
                if let Some(mut new_fc) = self.fd.get_call_specs_mut(new_idx) {
                    new_fc.clear_entry_address();
                }
            }
        }
        // flow.cc:714: applyPrototype.
        // TODO(CALLSPEC-0001): depends on Override::applyPrototype integration.
        self.query_call(new_idx);
        // flow.cc:717-721: if overridden to a direct call, rewrite CALLIND→CALL.
        let direct = self
            .fd
            .get_call_specs(new_idx)
            .map(|f| f.entry_addr.is_some())
            .unwrap_or(false);
        if direct {
            // flow.cc:719: data.opSetOpcode(op, CPUI_CALL).
            self.fd.op_set_opcode(op, OpCode::CPUI_CALL);
            // flow.cc:720: data.opSetInput(op, data.newVarnodeCallSpecs(res), 0).
            let owner = self
                .fd
                .get_call_specs_owner(new_idx)
                .expect("newly inserted callspec owner");
            let annotation = self.fd.new_varnode_call_specs(&owner);
            self.fd.op_set_input(op, annotation, 0);
        }
        // flow.cc:722.
        self.check_for_flow_modification(new_idx)
    }

    /// Remove the given call site from the list for this function. The covered
    /// exact-owner success path corresponds to `FlowInfo::deleteCallSpec`
    /// (flow.cc:1306-1318); the absent-owner error channel remains
    /// `CALLSPEC-0001`/UNTESTED because Rust currently panics instead of
    /// throwing `LowlevelError`.
    ///
    /// Ghidra scans `qlst` for the pointer, throws `LowlevelError` if absent,
    /// then `delete`s and erases. Rugra locates the same allocation with
    /// `Arc::ptr_eq`; a vector shift cannot retarget the identity.
    // Ghidra: flow.cc:1306 FlowInfo::deleteCallSpec
    fn delete_call_spec(&mut self, fc: Arc<RwLock<crate::fspec::FuncCallSpecs>>) {
        let Some(index) = self
            .fd
            .callspecs
            .iter()
            .position(|owned| Arc::ptr_eq(owned, &fc))
        else {
            panic!("Misplaced callspec");
        };
        // flow.cc:1316-1317: delete fc; qlst.erase(...).
        self.fd.callspecs.remove(index);
        // Consume the lookup handle too, so no strong owner survives this
        // call merely because Rust needed it to express pointer identity.
        drop(fc);
    }

    // ===================== Inline cloning (flow.cc:1043-1153) =====================

    /// Pull in-lining recursion information from another flow. Faithful to
    /// `FlowInfo::forwardRecursion` (flow.cc:1043-1048).
    ///
    /// Ghidra copies the `inline_recursion` pointer and `inline_head` pointer
    /// from the parent flow so that, when cloning an inline flow into `this`,
    /// the clone is informed of in-lining already performed. Rugra copies the
    /// head address and the recursion set contents (Rugra owns the set by
    /// value rather than via a pointer).
    // Ghidra: flow.cc:1043 FlowInfo::forwardRecursion
    pub fn forward_recursion(&mut self, op2: &FlowInfo<'_>) {
        // flow.cc:1046-1047: copy recursion state verbatim.
        self.inline_recursion = op2.inline_recursion.clone();
        self.inline_head = op2.inline_head;
    }

    /// Clone the given in-line flow into this flow using the hard model.
    /// Faithful to `FlowInfo::inlineClone` (flow.cc:1074-1099).
    ///
    /// Each PcodeOp from the inlined Funcdata is cloned into this flow
    /// preserving its original address; any RETURN op is replaced with a
    /// BRANCH to the return address (`retaddr`). After cloning, the flow
    /// tables (unprocessed, addrlist, visited) are merged from the inline
    /// flow, and any cloned call/branch op is cross-referenced via
    /// `xref_inlined_branch`.
    ///
    /// RUGRA-GLUE: Ghidra's clone path needs `data.cloneOp(op, seqnum)` and
    /// `data.newCodeRef(retaddr)`, neither of which is ported. Rugra emits a
    /// TODO and leaves the dead-list clone to a future partial-`Funcdata`
    /// clone implementation (flow_audit.md item 5). The flow-table merge and
    /// RETURN->BRANCH rewrite structure are preserved so the contract is
    /// visible.
    // Ghidra: flow.cc:1074 FlowInfo::inlineClone
    pub fn inline_clone(&mut self, inlineflow: &FlowInfo<'_>, retaddr: Address) {
        // flow.cc:1077-1091: walk inlineflow's dead ops, cloning each.
        // TODO: depends on partial-function clone (Funcdata::clone_op) and
        // Funcdata::new_code_ref. Rugra has no clone path yet, so we record
        // the gap and preserve the post-clone table merge below.
        let _ = retaddr; // would be used to build BRANCH targets (flow.cc:1083-1085).
        let mut new_tablelist: Vec<crate::op::PcodeOpRef> = Vec::new();
        // flow.cc:1089-1090: if a cloned op is call/branch, xref it.
        // With no clone available there are no new ops to xref; the loop is
        // structural and stays a no-op until clone_op lands.
        for op_ref in inlineflow.fd.obank.iter_dead() {
            let is_call_or_branch = {
                let o = op_ref.0.read().unwrap();
                (o.flags & (pcodeop_flags::CALL | pcodeop_flags::BRANCH)) != 0
            };
            if is_call_or_branch {
                // flow.cc:1090: xrefInlinedBranch(cloneop).
                let mut extra = self.xref_inlined_branch(op_ref);
                new_tablelist.append(&mut extra);
            }
        }
        let _ = new_tablelist;
        // flow.cc:1093-1097: merge flow tables from the inline flow.
        self.unprocessed
            .extend(inlineflow.unprocessed.iter().cloned());
        self.addrlist.extend(inlineflow.addrlist.iter().cloned());
        // Visited merge: Ghidra does visited.insert(...) over the map.
        for (&k, v) in &inlineflow.visited {
            self.visited.insert(k, v.clone());
        }
        // flow.cc:1098: do not copy inline_recursion / inline_head here.
    }

    /// Clone the given in-line flow into this flow using the EZ model.
    /// Faithful to `FlowInfo::inlineEZClone` (flow.cc:1108-1120).
    ///
    /// Only straight-line code is cloned (cloning stops at the first
    /// RETURN), and every cloned op is reassigned the fixed `calladdr`.
    /// Because Rugra has no clone path, this is a structural placeholder.
    // Ghidra: flow.cc:1108 FlowInfo::inlineEZClone
    pub fn inline_ezclone(&mut self, inlineflow: &FlowInfo<'_>, calladdr: Address) {
        // flow.cc:1112-1117: walk dead ops until RETURN, cloning with a
        // SeqNum rooted at calladdr.
        // TODO: depends on partial-function clone (Funcdata::clone_op) and
        // SeqNum reconstruction. With no clone path, no ops are cloned; the
        // flow tables are deliberately untouched (flow.cc:1118-1119).
        let _ = calladdr;
        let _ = inlineflow;
    }

    /// For in-lining using the hard model, make sure some restrictions are
    /// met. Faithful to `FlowInfo::testHardInlineRestrictions`
    /// (flow.cc:1133-1153). Returns the distinct return address via the
    /// out-parameter `retaddr`; returns true if the restrictions are met.
    ///
    /// Restrictions:
    ///   - Can only inline the function once (caller checks recursion set).
    ///   - There must be a p-code op to return to.
    ///   - There must be a distinct return address so RETURN can become BRANCH.
    // Ghidra: flow.cc:1133 FlowInfo::testHardInlineRestrictions
    pub fn test_hard_inline_restrictions(
        &mut self,
        inlinefd: &Funcdata,
        op: &crate::op::PcodeOpRef,
        retaddr: &mut Option<Address>,
    ) -> bool {
        // flow.cc:1136: if the inlined function is not noreturn, we need a
        // fallthrough op and a distinct return address. The callee's
        // no-return state is read off its FuncProto exactly as Ghidra reads
        // `inlinefd->getFuncProto().isNoReturn()`; the bit reaches the callee
        // proto through the driver-side known-noreturn data source
        // (FLOW-NORETURN-DATA-0001).
        let inline_noreturn = inlinefd.get_func_proto().is_no_return();
        if !inline_noreturn {
            // flow.cc:1137-1141: find the op after the call; if none, warn.
            let next_op = self.fallthru_op(op);
            let next_op = match next_op {
                Some(o) => o,
                None => {
                    // flow.cc:1139-1141: inline_head->warning(...).
                    self.fd.warning(
                        "No fallthrough prevents inlining here",
                        op.0.read().unwrap().get_addr(),
                    );
                    return false;
                }
            };
            // flow.cc:1143-1144: retaddr = nextop->getAddr().
            let ra = next_op.0.read().unwrap().get_addr();
            // flow.cc:1145-1148: if op's address == retaddr, the return
            // address is not distinct — warn and bail.
            if op.0.read().unwrap().get_addr().as_u64() == ra.as_u64() {
                self.fd.warning(
                    "Return address prevents inlining here",
                    op.0.read().unwrap().get_addr(),
                );
                return false;
            }
            // flow.cc:1149-1150: opMarkStartBasic(nextop) — the inlined jump
            // back starts a new basic block.
            {
                let mut no = next_op.0.write().unwrap();
                no.flags |= pcodeop_flags::STARTBASIC;
            }
            *retaddr = Some(ra);
        }
        true
    }

    // ===================== P-code injection (flow.cc:1177-1355) =====================

    /// Clone the architecture handles FlowInfo's injection path needs
    /// (`glb->userops` / `glb->pcodeinjectlib`, userop.hh / pcodeinject.hh).
    /// Returns None when either manager is absent — legacy callers and unit
    /// fixtures construct Funcdata without an Architecture.
    // RUGRA-GLUE: ARCH-GLUE — Ghidra reaches the managers through the raw
    // Architecture pointer; Rugra's Funcdata::arch is Option<Arc<..>>.
    fn arch_inject_sources(
        &self,
    ) -> Option<(
        std::sync::Arc<std::sync::RwLock<crate::userop::UserOpManage>>,
        std::sync::Arc<std::sync::RwLock<crate::pcodeinject::PcodeInjectLibrary>>,
    )> {
        let arch = self.fd.arch.as_ref()?;
        let userops = arch.userops.clone()?;
        let inject_lib = arch.pcodeinjectlib.clone()?;
        Some((userops, inject_lib))
    }

    /// Queue one op for injection (the flow.hh:90 `injectlist` push that
    /// `xrefControlFlow` performs for machine-lifted CALLOTHERs at
    /// flow.cc:345-347 and `checkForFlowModification` for inline call sites
    /// at flow.cc:639-640).
    ///
    /// RUGRA-GLUE: fixture-observation API (same category as `snapshot`).
    /// The locked x86-64 SLEIGH language declares no user-defined p-code ops,
    /// so no real instruction can emit a CALLOTHER on either side of the
    /// oracle; the Ghidra fixture seeds its private `injectlist` directly and
    /// the Rust fixture mirrors through this hook. Production flow code uses
    /// the xref/checkForFlowModification paths only.
    pub fn fixture_queue_inject(&mut self, op: &crate::op::PcodeOpRef) {
        self.injectlist.push(Some(op.clone()));
    }

    /// Inject the given payload into this flow. Faithful to
    /// `FlowInfo::doInjection` (flow.cc:1177-1208).
    ///
    /// The injected p-code replaces the given op, and the control-flow cross
    /// references are updated: the injected sequence is moved to right after
    /// the call, the original op is removed, and the target map is repointed
    /// at the first injected op.
    ///
    /// Ghidra's `payload->inject(icontext, emitter)` (flow.cc:1185) runs the
    /// payload template through `InjectPayloadSleigh::inject`, whose emitted
    /// ops land at the end of the dead list via `PcodeEmitFd::dump`
    /// (funcdata.cc:878). Rugra splits the same dataflow at the borrow
    /// boundary: `InjectPayload::inject` (pcodeinject.rs) resolves the
    /// template into raw ops, and `Funcdata::inject_raw_ops_single` — the
    /// `PcodeEmitFd::dump` port — appends them to the bank with the
    /// injection base address (Ghidra's `cacher.emit(con.baseaddr,&emit)`
    /// passes the base address for every injected op, sleigh.cc:139-144).
    // Ghidra: flow.cc:1177 FlowInfo::doInjection
    pub fn do_injection(
        &mut self,
        payload: &crate::pcodeinject::InjectPayload,
        icontext: &crate::pcodeinject::InjectContext,
        op: &crate::op::PcodeOpRef,
        inject_fc_idx: Option<usize>,
    ) {
        // flow.cc:1180-1183: remember the dead-list position before inject;
        // this becomes the first op appended by the payload. The id-space
        // marker is the pre-inject dead-chain tail (the oracle's stored
        // iterator form, op.hh:128) — the first injected op is its
        // successor.
        let inject_marker = self.fd.obank.dead_tail_id();
        // flow.cc:1185: payload->inject(icontext, emitter) — empty
        // injections throw LowlevelError("Empty injection: " + name)
        // (flow.cc:1188-1189); Rugra reports and bails like the rest of the
        // flow error paths.
        let raw_ops = match payload.inject(icontext) {
            Ok(ops) => ops,
            Err(message) => {
                eprintln!("[FLOW] {}: {}", self.fd.name, message);
                return;
            }
        };
        self.fd
            .inject_raw_ops_single(&raw_ops, Address::new(icontext.base_addr));
        let Some(first_id) = self.fd.obank.dead_after(inject_marker) else {
            eprintln!("[FLOW] {}: Empty injection: {}", self.fd.name, payload.name);
            return;
        };
        let firstop = self
            .fd
            .obank
            .op_by_id(first_id)
            .expect("dead_after returned a live chain member")
            .clone();

        // flow.cc:1186: startbasic = op->isBlockStart().
        let mut startbasic = (op.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0;

        // flow.cc:1192: xrefControlFlow(iter, startbasic, isfallthru, fc)
        // over the injected ops — the full op walk (basic-block starts,
        // callspecs, CALLOTHER chaining, dead-tail deletion).
        let (lastop, _) = self.xref_control_flow_at(Some(first_id), &mut startbasic, inject_fc_idx);

        // flow.cc:1194-1199: if the injected code does NOT fall thru, mark
        // the op after the call as the start of a basic block. Ghidra
        // advances the op's own dead-list insert iterator (`++iter` against
        // `getInsertIter()`), i.e. the immediate dead-list successor — not
        // `fallthruOp`. This runs BEFORE moveSequenceDead below.
        if startbasic {
            if let Some(next) = self.dead_list_next(op) {
                next.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
            }
        }

        // flow.cc:1201-1202: markIncidentalCopy(firstop, lastop) — guarded
        // by the payload's incidentalCopy attribute.
        if payload.is_incidental_copy() {
            if let Some(last) = &lastop {
                self.mark_incidental_copy_flow(&firstop, last);
            }
        }
        // flow.cc:1203: moveSequenceDead(firstop, lastop, op) — move the
        // injection to right after the call.
        if let Some(last) = &lastop {
            self.move_sequence_flow(&firstop, last, op);
        }
        // flow.cc:1205: updateTarget(op, firstop).
        self.update_target(op, &firstop);
        // flow.cc:1207: opDestroyRaw(op) — get rid of the original call.
        self.fd.op_destroy_raw(op);
    }

    /// Perform injection for a given user-defined (CALLOTHER) p-code op.
    /// Faithful to `FlowInfo::injectUserOp` (flow.cc:1212-1236).
    ///
    /// The op must already be established as a user defined op with an
    /// associated injection (UserOpType::Injected). The payload is resolved
    /// through the architecture's `UserOpManage` (CALLOTHER index in
    /// input(0) → InjectedUserOp inject id) and `PcodeInjectLibrary`, the
    /// `InjectContext` is filled from the op's operands (skipping the inject
    /// id slot), and `doInjection` performs the replacement.
    // Ghidra: flow.cc:1212 FlowInfo::injectUserOp
    pub fn inject_user_op(&mut self, op: &crate::op::PcodeOpRef) {
        // flow.cc:1215-1217: InjectedUserOp lookup by CALLOTHER index +
        // payload lookup by inject id (`glb->userops.getOp(...)` /
        // `glb->pcodeinjectlib->getPayload(userop->getInjectId())`).
        // Ghidra dereferences getOp() unconditionally (SLEIGH guarantees the
        // index); Rugra guards the Options and reports, per the flow error
        // policy (ARCH-GLUE: glb is `Funcdata::arch`).
        let Some((userops, inject_lib)) = self.arch_inject_sources() else {
            eprintln!(
                "[FLOW] {}: injectUserOp: architecture has no userops/pcodeinjectlib",
                self.fd.name
            );
            return;
        };
        let (index, inputs, output) = {
            let o = op.0.read().unwrap();
            let index = o
                .inrefs
                .first()
                .map(|vn| vn.read().unwrap().get_offset() as i32);
            let ins: Vec<crate::pcoderaw::VarnodeRaw> = o
                .inrefs
                .iter()
                .skip(1)
                .map(|vn| {
                    let v = vn.read().unwrap();
                    crate::pcoderaw::VarnodeRaw::new(v.get_space(), v.get_offset(), v.size)
                })
                .collect();
            let out = o.output.as_ref().map(|vn| {
                let v = vn.read().unwrap();
                crate::pcoderaw::VarnodeRaw::new(v.get_space(), v.get_offset(), v.size)
            });
            (index, ins, out)
        };
        let Some(index) = index else {
            eprintln!(
                "[FLOW] {}: injectUserOp: CALLOTHER without index input",
                self.fd.name
            );
            return;
        };
        // flow.cc:1215-1216: userop = userops.getOp(index) (must be
        // Injected); injectid = userop->getInjectId().
        let injectid = {
            let userops = userops.read().expect("lock poisoned");
            match userops.get_op(index) {
                Some(userop) if userop.is_injected() => userop.inject_id,
                _ => {
                    eprintln!(
                        "[FLOW] {}: injectUserOp: CALLOTHER index {} is not an injected userop",
                        self.fd.name, index
                    );
                    return;
                }
            }
        };
        // flow.cc:1216-1217: payload = pcodeinjectlib->getPayload(injectid).
        let payload = {
            let lib = inject_lib.read().expect("lock poisoned");
            match lib.get_payload_by_id(injectid) {
                Some(p) => p.clone(),
                None => {
                    eprintln!(
                        "[FLOW] {}: injectUserOp: no payload {} for CALLOTHER index {}",
                        self.fd.name, injectid, index
                    );
                    return;
                }
            }
        };
        // flow.cc:1218-1234: build the InjectContext from the op's operands.
        let mut icontext = crate::pcodeinject::InjectContext::new();
        // flow.cc:1219-1220: baseaddr/nextaddr = op->getAddr().
        let base = op.0.read().unwrap().get_addr().as_u64();
        icontext.base_addr = base;
        icontext.next_addr = base;
        // flow.cc:1221-1227: inputlist from op inputs (skip slot 0 = injectid).
        icontext.input_list = inputs;
        // flow.cc:1228-1234: output if present.
        if let Some(out) = output {
            icontext.output.push(out);
        }
        // flow.cc:1235: doInjection(payload, icontext, op, NULL).
        self.do_injection(&payload, &icontext, op, None);
    }

    /// P-code is generated for the sub-function and then woven into this
    /// flow at the call site. Faithful to `FlowInfo::inlineSubFunction`
    /// (flow.cc:1242-1277). Returns true if the inlining is successful.
    ///
    /// Ghidra sets up `inline_head` / `inline_recursion` on first entry,
    /// inserts the current function's address, refuses to inline a function
    /// already in the recursion set, then calls `data.inlineFlow(fd, *this,
    /// op)` and interprets its result (easy vs hard model). Rugra has no
    /// `inlineFlow` partial clone (flow_audit.md item 5), so the recursion
    /// bookkeeping is preserved and the actual clone is a documented TODO.
    // Ghidra: flow.cc:1242 FlowInfo::inlineSubFunction
    pub fn inline_sub_function(&mut self, fc_idx: usize) -> bool {
        // flow.cc:1245-1246: need the callee Funcdata.
        let (entry_addr, op_ref) = {
            let fc = match self.fd.get_call_specs(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let entry = match fc.entry_addr {
                Some(a) => a,
                None => return false, // flow.cc:1246: fd == NULL
            };
            let op_ref = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            (entry, op_ref)
        };
        // flow.cc:1248-1252: set up the head of inlining on first entry.
        if self.inline_head.is_none() {
            // flow.cc:1250: inline_head = &data (this flow's function).
            self.inline_head = Some(self.fd.baseaddr.as_u64());
            // flow.cc:1251: inline_recursion = &inline_base.
            // Rugra owns inline_recursion directly, so we copy inline_base in.
            self.inline_recursion = self.inline_base.clone();
        }
        // flow.cc:1253: insert current function's address.
        self.inline_recursion.insert(self.fd.baseaddr.as_u64());
        // flow.cc:1254-1258: refuse to re-inline a function already in the set.
        if self.inline_recursion.contains(&entry_addr.as_u64()) {
            self.fd
                .warning("Could not inline here", op_ref.0.read().unwrap().get_addr());
            return false;
        }
        // flow.cc:1260: data.inlineFlow(fd, *this, fc->getOp()).
        // TODO: depends on partial-function clone (Funcdata::inline_flow).
        // Rugra cannot perform the actual clone yet; we return false so the
        // caller (inject_pcode) treats the site as not-inlined and leaves
        // the CALL in place.
        let res = -1i32;
        if res < 0 {
            return false;
        }
        // flow.cc:1263-1271: easy vs hard model recursion bookkeeping.
        // (Unreachable until inline_flow lands.)
        // flow.cc:1273-1274: setPossibleUnreachable().
        self.set_possible_unreachable();
        true
    }

    /// Perform injection replacing the CALL at the given call site. Faithful
    /// to `FlowInfo::injectSubFunction` (flow.cc:1284-1303). Returns true to
    /// indicate the injection happened and the callspec should be deleted.
    ///
    /// The call site must be previously marked with the \e injection id
    /// (`fc->getInjectId()`); the payload comes from the architecture's
    /// `PcodeInjectLibrary`. Ghidra's `InjectContext` carries
    /// baseaddr/nextaddr = the call op's address and calladdr = the callee
    /// entry address; after `doInjection`, a nonzero `payload->getParamShift()`
    /// is passed to the LAST callspec (`qlst.back()->setParamshift`).
    // Ghidra: flow.cc:1284 FlowInfo::injectSubFunction
    pub fn inject_sub_function(
        &mut self,
        fc_idx: usize,
        payload: &crate::pcodeinject::InjectPayload,
    ) -> bool {
        // flow.cc:1287-1294: build the context from the callspec.
        let (op_ref, call_addr) = {
            let fc = match self.fd.get_call_specs(fc_idx) {
                Some(f) => f,
                None => return false,
            };
            let op = match fc.get_op(self.fd) {
                Some(o) => o,
                None => return false,
            };
            // An invalid entry address maps to offset 0 (Ghidra Address
            // default) — injectUserOp/injectSubFunction only feed it to
            // inst_dest substitutions.
            (op, fc.entry_addr.map(|a| a.as_u64()).unwrap_or(0))
        };
        let op_addr = op_ref.0.read().unwrap().get_addr().as_u64();
        let mut icontext = crate::pcodeinject::InjectContext::new();
        icontext.base_addr = op_addr;
        icontext.next_addr = op_addr;
        icontext.call_addr = call_addr;
        // flow.cc:1296: doInjection(payload, icontext, op, fc).
        self.do_injection(payload, &icontext, &op_ref, Some(fc_idx));
        // flow.cc:1299-1300: if the injection fills in the -paramshift-
        // field, pass it to the callspec of the injected call, which must be
        // last in the list.
        let paramshift = payload.get_paramshift();
        if paramshift != 0 {
            if let Some(last) = self.fd.callspecs.last() {
                let mut last = last.write().unwrap();
                last.set_paramshift(paramshift);
            }
        }
        // flow.cc:1302: return true — callspec should be deleted.
        true
    }

    /// Perform substitution on any op that requires injection. Faithful to
    /// `FlowInfo::injectPcode` (flow.cc:1327-1355).
    ///
    /// Walks `injectlist`, nullifying each entry as it goes so nothing is
    /// injected twice (flow.cc:1333); for each op:
    ///   - CALLOTHER -> `injectUserOp` (flow.cc:1334-1336)
    ///   - CALL/CALLIND -> the callspec from input(0)'s constant
    ///     (`FuncCallSpecs::getFspecFromConst`, flow.cc:1338); if inline:
    ///       - inject id >= 0 -> `injectSubFunction` + warningHeader +
    ///         `deleteCallSpec` (flow.cc:1340-1345)
    ///       - else -> `inlineSubFunction` + warningHeader + `deleteCallSpec`
    ///         (flow.cc:1347-1351)
    ///
    /// Rugra's temporary Iop annotation carries a typed Weak counterpart of
    /// `getFspecFromConst`; the fallback compares exact PcodeOp identity.
    /// Payload resolution goes through the
    /// architecture's `PcodeInjectLibrary` exactly like Ghidra's
    /// `glb->pcodeinjectlib`.
    // Ghidra: flow.cc:1327 FlowInfo::injectPcode
    pub fn inject_pcode(&mut self) {
        for slot in 0..self.injectlist.len() {
            // flow.cc:1331-1333: skip nulled entries, nullify as we go.
            let Some(op) = self.injectlist[slot].clone() else {
                continue;
            };
            self.injectlist[slot] = None;
            let code = op.0.read().unwrap().opcode;
            if code == OpCode::CPUI_CALLOTHER {
                // flow.cc:1334-1336: injectUserOp(op).
                self.inject_user_op(&op);
            } else {
                // flow.cc:1337-1338: CPUI_CALL or CPUI_CALLIND — resolve the
                // callspec from input(0)'s constant.
                let fc_owner = match find_callspec_for_op(self.fd, &op) {
                    Some(fc) => fc,
                    None => continue, // No matching callspec; nothing to do.
                };
                let Some(fc_idx) = self
                    .fd
                    .callspecs
                    .iter()
                    .position(|owned| Arc::ptr_eq(owned, &fc_owner))
                else {
                    continue;
                };
                let (is_inline, inject_id) = {
                    let fc = fc_owner.read().unwrap();
                    (fc.is_inline(), fc.get_inject_id())
                };
                // flow.cc:1339: if (!fc->isInline()) — nothing to do.
                if !is_inline {
                    continue;
                }
                if inject_id >= 0 {
                    // flow.cc:1340-1345: injectSubFunction + warningHeader
                    // ("Function: <name> replaced with injection: <fixup>")
                    // + deleteCallSpec.
                    let payload = self.arch_inject_sources().and_then(|(_u, lib)| {
                        let lib = lib.read().expect("lock poisoned");
                        lib.get_payload_by_id(inject_id).cloned()
                    });
                    let Some(payload) = payload else {
                        eprintln!(
                            "[FLOW] {}: injectPcode: no payload {} for inline call site",
                            self.fd.name, inject_id
                        );
                        continue;
                    };
                    if self.inject_sub_function(fc_idx, &payload) {
                        let fixup_name = self
                            .arch_inject_sources()
                            .map(|(_u, lib)| {
                                let lib = lib.read().expect("lock poisoned");
                                lib.get_call_fixup_name(inject_id)
                            })
                            .unwrap_or_default();
                        // RUGRA-GLUE: Rugra's FuncCallSpecs carries no name
                        // (Ghidra `fc->getName()`); the callspecs here are
                        // created during flow and unnamed until ActionFuncLink.
                        let fc_name = fc_owner
                            .read()
                            .unwrap()
                            .entry_addr
                            .map(|a| format!("sub_{:x}", a.as_u64()))
                            .unwrap_or_default();
                        self.fd.warning_header(&format!(
                            "Function: {} replaced with injection: {}",
                            fc_name, fixup_name
                        ));
                        self.delete_call_spec(fc_owner);
                    }
                } else {
                    // flow.cc:1347-1350: inlineSubFunction + warningHeader
                    // ("Inlined function: <name>") + deleteCallSpec.
                    if self.inline_sub_function(fc_idx) {
                        self.fd.warning_header("Inlined function");
                        self.delete_call_spec(fc_owner);
                    }
                }
            }
        }
        // flow.cc:1354: injectlist.clear().
        self.injectlist.clear();
    }

    /// Check if any of the calls this function makes are to already traced
    /// data-flow. If so, we change the CALL to a BRANCH and issue a warning.
    /// This situation is most likely due to a Position Indepent Code
    /// construction. Faithful to `FlowInfo::checkContainedCall`
    /// (flow.cc:1361-1405).
    ///
    /// For each remaining call spec (Ghidra's `qlst`, Rugra's
    /// `fd.callspecs` in creation order):
    ///   - skip when the callee resolved to a Funcdata (flow.cc:1367-1368);
    ///   - skip when the op is not a direct CPUI_CALL (flow.cc:1369-1370);
    ///   - find the greatest visited instruction at/below the call target;
    ///     no such entry (flow.cc:1375) or an entry whose byte range ends at
    ///     or before the target (flow.cc:1377-1378) skips the spec;
    ///   - a target exactly at a visited instruction start is a PIC
    ///     construction: emit the `Possible PIC construction` header warning,
    ///     rewrite the op to CPUI_BRANCH, mark the target op and the op
    ///     following the call as basic-block starts, restore the original
    ///     code-ref input, and erase the call spec (flow.cc:1379-1398);
    ///   - a target strictly inside a visited instruction only draws the
    ///     `Call to offcut address within same function` warning
    ///     (flow.cc:1400-1402).
    // Ghidra: flow.cc:1361 FlowInfo::checkContainedCall
    fn check_contained_call(&mut self) {
        // flow.cc:1364-1365: for(iter=qlst.begin();iter!=qlst.end();++iter).
        // Ghidra's qlst is the Funcdata-owned spec vector passed by
        // reference; Rugra indexes fd.callspecs directly, so the list
        // identity and traversal order are the same.
        let mut iter = 0usize;
        while iter != self.fd.callspecs.len() {
            // flow.cc:1366-1370: fetch the spec's callee Funcdata state and
            // call op before mutating anything below.
            let (resolved, call_op) = {
                let fc = self.fd.callspecs[iter].read().unwrap();
                // flow.cc:1367-1368: `Funcdata *fd = fc->getFuncdata();
                // if (fd != (Funcdata *)0) continue;` — queryCall's resolved
                // callee (flow.cc:662 setFuncdata). Rugra observes it via
                // the FlowInfo-side `resolved_funcdata` set keyed by this
                // spec's op address (see `query_call`).
                let resolved = self.resolved_funcdata.contains(&fc.op_addr.as_u64());
                (resolved, fc.get_op(self.fd))
            };
            // flow.cc:1367-1368: `if (fd != (Funcdata *)0) continue;`.
            if resolved {
                iter += 1;
                continue;
            }
            // flow.cc:1369: `PcodeOp *op = fc->getOp();` — Ghidra's stored
            // pointer is never null; Rugra upgrades the exact Weak PcodeOp
            // identity, so None is an invariant break.
            let Some(op) = call_op else {
                eprintln!(
                    "[FLOW] {}: checkContainedCall: call spec {} op missing from bank",
                    self.fd.name, iter
                );
                iter += 1;
                continue;
            };
            // flow.cc:1370: `if (op->code() != CPUI_CALL) continue;` — the
            // CURRENT opcode, so a CALLIND or an already-converted op skips.
            if op.0.read().unwrap().opcode != OpCode::CPUI_CALL {
                iter += 1;
                continue;
            }
            // flow.cc:1372: `const Address &addr(fc->getEntryAddress());`.
            // A CPUI_CALL always carries a direct target; Rugra models an
            // invalid entry as None. An invalid Address sorts before every
            // visited key, so Ghidra's upper_bound lands on begin() and the
            // flow.cc:1375 guard continues — None maps to the same skip.
            let entry_addr = self.fd.callspecs[iter].read().unwrap().entry_addr;
            let Some(addr) = entry_addr else {
                iter += 1;
                continue;
            };
            // flow.cc:1373-1378: `miter = visited.upper_bound(addr);`
            // `if (miter == visited.begin()) continue; --miter;`
            // `if (start + size <= addr) continue;` — the entry covering
            // check reduces to the greatest visited key <= addr (BTreeMap
            // range), matching Ghidra's upper_bound-then-decrement exactly.
            let covering_start: Option<u64> = {
                match self.visited.range(..=addr.as_u64()).next_back() {
                    // flow.cc:1375: upper_bound == begin — nothing at/below addr.
                    None => None,
                    Some((&start, stat)) => {
                        // flow.cc:1377-1378: the found instruction's bytes
                        // end at or before addr — target is beyond it.
                        if start + (stat.size as u64) <= addr.as_u64() {
                            None
                        } else {
                            Some(start)
                        }
                    }
                }
            };
            let Some(start) = covering_start else {
                iter += 1;
                continue;
            };
            if start == addr.as_u64() {
                // flow.cc:1379-1398: exact visited instruction start — PIC.
                // flow.cc:1380-1384: warningHeader("Possible PIC construction
                // at <opaddr>: Changing call to branch"). The op address
                // renders via Address::printRaw (flow.cc:1382) — Rugra's
                // Funcdata helper ports the AddrSpace::printRaw spelling
                // (0x + zero-pad + display base delta, RESIDMAP-PRINTBATCH
                // -0001), replacing the legacy spaceless Display form.
                let msg = format!(
                    "Possible PIC construction at {}: Changing call to branch",
                    self.fd.print_raw_code_addr(op.0.read().unwrap().get_addr().as_u64())
                );
                self.fd.warning_header(&msg);
                // flow.cc:1385: data.opSetOpcode(op,CPUI_BRANCH).
                self.fd.op_set_opcode(&op, OpCode::CPUI_BRANCH);
                // flow.cc:1386-1388: make sure target of new goto starts a
                // basic block (opMarkStartBasic = setFlag(startbasic),
                // funcdata.hh:480).
                match self.target(addr) {
                    Some(targ) => {
                        targ.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                    }
                    None => {
                        // Ghidra's FlowInfo::target throws LowlevelError
                        // (flow.cc:135) when no op is ultimately found; a
                        // visited instruction start with a valid SeqNum
                        // always resolves, so this is unreachable in practice.
                        // Rugra logs instead of panicking (same policy as
                        // delete_call_spec).
                        eprintln!(
                            "[FLOW] {}: checkContainedCall: target({:#x}) has no pcode",
                            self.fd.name,
                            addr.as_u64()
                        );
                    }
                }
                // flow.cc:1389-1393: make sure the following op starts a
                // basic block. Ghidra advances the op's dead-list insert
                // iterator; Rugra's alive list plays the dead list during
                // flow (creation order == SeqNum order).
                if let Some(next) = self.dead_list_next(&op) {
                    next.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                }
                // flow.cc:1394-1395: data.opSetInput(op,data.newCodeRef(addr),0)
                // — restore the original address as a code-ref annotation.
                let code_ref = self.fd.new_code_ref(addr);
                self.fd.op_set_input(&op, code_ref, 0);
                // flow.cc:1396-1397: iter = qlst.erase(iter); delete fc;
                self.fd.callspecs.remove(iter);
                // flow.cc:1398: `if (iter == qlst.end()) break;`.
                if iter == self.fd.callspecs.len() {
                    break;
                }
                // Fall through to the single for-header `++iter` below: it
                // advances past the successor of the erased spec, so the
                // call spec immediately following a converted one is NOT
                // examined on this pass. This quirk is load-bearing oracle
                // behavior and is deliberately reproduced (see fixture
                // case `multi`).
            } else {
                // flow.cc:1400-1402: target strictly inside a visited
                // instruction — offcut warning only, no op changes.
                let op_addr = op.0.read().unwrap().get_addr();
                self.fd
                    .warning("Call to offcut address within same function", op_addr);
            }
            // flow.cc:1365: for-header ++iter (fall-through of both arms).
            iter += 1;
        }
    }

    /// The op following `op` in the dead list (Ghidra: `++op->getInsertIter()`
    /// against `obank.endDead()`, flow.cc:1390-1392).
    // RUGRA-GLUE: the stored ins-link successor IS the stored iterator's
    // ++ form — O(1) via PcodeOpBank::dead_next (op.hh:128).
    fn dead_list_next(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        self.fd.obank.dead_next(op)
    }

    /// Move the injected op sequence [firstop, lastop] to immediately after
    /// `prev`. Faithful to `PcodeOpBank::moveSequenceDead` (op.cc:1056-1065)
    /// over the flow-time dead-list container.
    // RUGRA-GLUE: delegates to the bank's id-space splice_after — the
    // former flow-local drain/splice adapter duplicated the bank port;
    // the single implementation carries the op.cc:1063 degenerate guard
    // and the pos==last enditer no-op (CR-ARENACORE F1).
    fn move_sequence_flow(
        &mut self,
        firstop: &crate::op::PcodeOpRef,
        lastop: &crate::op::PcodeOpRef,
        prev: &crate::op::PcodeOpRef,
    ) {
        self.fd.obank.move_sequence_dead(firstop, lastop, prev);
    }

    /// Mark COPY ops in the injected range as incidental. Faithful to
    /// `PcodeOpBank::markIncidentalCopy` (op.cc:1071-1083) over the raw
    /// dead-list container (see `move_sequence_flow`).
    // RUGRA-GLUE: delegates to the bank's bounded ins-link walk (the
    // former flow-local pointer-range adapter duplicated the bank port).
    fn mark_incidental_copy_flow(
        &mut self,
        firstop: &crate::op::PcodeOpRef,
        lastop: &crate::op::PcodeOpRef,
    ) {
        self.fd.obank.mark_incidental_copy(firstop, lastop);
    }

    // ===================== Private target helpers =====================

    // Ghidra: flow.cc:88 FlowInfo::fallthruOp (private helper form)
    /// Find the fallthru p-code op for a given op. Faithful to
    /// `FlowInfo::fallthruOp` (flow.cc:88-107):
    ///   1. the next op in sequence is the fallthru when it belongs to the
    ///      same instruction (`!isInstructionStart()`);
    ///   2. otherwise the op's own instruction is located in `visited`
    ///      (`upper_bound` then one predecessor step, rejecting an
    ///      instruction that does not cover the op's address) and the
    ///      fallthru is the first op of the NEXT instruction via `target`.
    // RUGRA-GLUE: Ghidra walks a stored list iterator; the id-space stored
    // ins-link gives the successor in O(1) (op.hh:128).
    fn fallthru_op(&self, op: &crate::op::PcodeOpRef) -> Option<crate::op::PcodeOpRef> {
        // The op must be a dead-chain member (the former position scan's
        // miss returned None from here).
        if !self.fd.obank.in_dead(op) {
            return None;
        }
        // flow.cc:93-98: next in sequence within the same instruction.
        if let Some(next) = self.fd.obank.dead_next(op) {
            if (next.0.read().unwrap().flags & pcodeop_flags::STARTMARK) == 0 {
                return Some(next);
            }
        }
        // flow.cc:99-106: find the instruction containing this op.
        let op_addr = op.0.read().unwrap().get_addr().as_u64();
        let (&instruction, stat) = self.visited.range(..=op_addr).next_back()?;
        if op_addr >= instruction + stat.size as u64 {
            return None;
        }
        self.target(Address::new(instruction + stat.size as u64))
    }

    /// Split raw p-code ops up into basic blocks. Faithful port of
    /// `FlowInfo::splitBasic` (flow.cc:983-1017).
    ///
    /// Ops are moved (in bank order) into a new `BlockBasic` every time an
    /// op is marked `isBlockStart()`. The first op must be a block start
    /// (Ghidra throws otherwise). Per-block address ranges are recorded as
    /// `setBasicBlockRange(cur, start, stop)` where `stop` is the maximum op
    /// address seen in the block, and each insertion assigns the op's
    /// mutable `SeqNum::order` via `BlockBasic::insert`'s midpoint formula
    /// (block.cc:2258-2289): appending at the block end with no previous op
    /// uses `ordbefore=2`, `ordafter=ordbefore+0x1000000`, and
    /// `order = ordafter/2 + ordbefore/2`, keeping both the values and the
    /// integer-division semantics Ghidra uses ("Beware overflow").
    // Ghidra: flow.cc:983 FlowInfo::splitBasic
    pub fn split_basic(&mut self) -> crate::error::Result<()> {
        let dead: Vec<crate::op::PcodeOpRef> = self.fd.obank.iter_dead().cloned().collect::<Vec<_>>();
        if dead.is_empty() {
            return Ok(());
        }
        // flow.cc:993-995: first op must be marked as entry point.
        if (dead[0].0.read().unwrap().flags & pcodeop_flags::STARTBASIC) == 0 {
            return Err(crate::error::Error::Lowlevel(
                "First op not marked as entry point".to_string(),
            ));
        }
        // flow.cc:996-998: create the first block and register the official
        // entry point before later blocks are built.
        let mut start = dead[0].0.read().unwrap().get_addr();
        let mut stop = start;
        let mut current: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(self.fd.bblocks.get_size() as i32, start),
        ));
        self.fd.bblocks.add_block(current.clone());
        Self::set_start_block(&mut self.fd.bblocks, current.clone());
        let mut prev_order: Option<u32> = None;

        for (position, op_ref) in dead.iter().enumerate() {
            let op_flags = op_ref.0.read().unwrap().flags;
            // flow.cc:1001-1013: every later block-start op closes the
            // previous block's range and opens a new block; any other op
            // only extends the block's stop address.
            if position > 0 && (op_flags & pcodeop_flags::STARTBASIC) != 0 {
                // flow.cc:1003-1008: close the previous block's range and
                // open a new block at this op.
                Self::set_block_range(&current, start, stop);
                let op_addr = op_ref.0.read().unwrap().get_addr();
                start = op_addr;
                stop = start;
                current = Arc::new(RwLock::new(BlockBasic::new(
                    self.fd.bblocks.get_size() as i32,
                    op_addr,
                )));
                self.fd.bblocks.add_block(current.clone());
                prev_order = None;
            } else {
                // flow.cc:1010-1012: stop tracks the biggest address.
                let next_addr = op_ref.0.read().unwrap().get_addr();
                if stop < next_addr {
                    stop = next_addr;
                }
            }
            // funcdata_op.cc:157-158: data.opInsert first moves this one op
            // from dead to alive, then BlockBasic::insert sets parent/order.
            self.fd.obank.mark_alive(op_ref.clone());
            Self::block_insert_at_end(&current, op_ref, &mut prev_order);
        }
        // flow.cc:1016: close the final block's range.
        Self::set_block_range(&current, start, stop);
        Ok(())
    }

    /// `Funcdata::setBasicBlockRange(cur,start,stop)` (funcdata.hh:556,
    /// delegating to `BlockBasic::setInitialRange` at block.cc:2625-2631)
    /// adapter: replace the block's initial closed range while retaining both
    /// endpoints as complete `Address` values.
    // Ghidra: funcdata.hh:556 Funcdata::setBasicBlockRange
    fn set_block_range(
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        start: Address,
        stop: Address,
    ) {
        let mut guard = block.write().unwrap();
        if let Some(basic) = guard.as_any_mut().downcast_mut::<BlockBasic>() {
            basic.set_initial_range(start, stop);
        }
    }

    /// `BlockBasic::insert` at the block end (block.cc:2258-2289): set the
    /// parent, append the op, and assign the mutable `SeqNum::order` with
    /// the midpoint formula. Appending gives `ordbefore` = the previous
    /// op's order (or 2 for the block's first op) and
    /// `ordafter = ordbefore + 0x1000000` (with the ~0 saturation Ghidra
    /// applies when that overflows); `order = ordafter/2 + ordbefore/2`
    /// using integer division.
    // Ghidra: block.cc:2258 BlockBasic::insert (end-append order formula)
    fn block_insert_at_end(
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        op_ref: &crate::op::PcodeOpRef,
        prev_order: &mut Option<u32>,
    ) {
        op_ref.0.write().unwrap().parent = Some(Arc::downgrade(block));
        let mut guard = block.write().unwrap();
        if let Some(basic) = guard.as_any_mut().downcast_mut::<BlockBasic>() {
            basic.ops.push(op_ref.clone());
        }
        // block.cc:2286-2292 (BlockBasic::insert tail): inserting a branch
        // op sets f_switch_out for CPUI_BRANCHIND. The flag feeds
        // ActionDoNothing's switch-target guard (block.cc:2604-2613) and
        // the collapse rules' isSwitchOut tests; omitting it here let
        // do-nothing removal delete live switch-case blocks whose successor
        // is a join (sqlite3VdbeChangeP4's e43c0 arm), deshaping the
        // post-ActionReturnSplit rebuild's loop structuring.
        {
            let o = op_ref.0.read().unwrap();
            if o.is_branch() && o.opcode == OpCode::CPUI_BRANCHIND {
                if let Some(basic) = guard.as_any_mut().downcast_mut::<BlockBasic>() {
                    basic.set_flags(crate::block::block_flags::SWITCH_OUT);
                }
            }
        }
        // block.cc:2267-2283: midpoint order assignment.
        let ordbefore = prev_order.unwrap_or(2);
        let ordafter = if ordbefore > u32::MAX - 0x1000000 {
            u32::MAX
        } else {
            ordbefore + 0x1000000
        };
        let midpoint = (ordafter as u64 / 2 + ordbefore as u64 / 2) as u32;
        op_ref.0.write().unwrap().start.set_order(midpoint);
        *prev_order = Some(midpoint);
    }

    /// Generate edges between the basic blocks. Faithful to
    /// `FlowInfo::connectBasic` (flow.cc:1021-1037). Walks the collected
    /// (source, target) op pairs in their original insertion order and asks
    /// the block graph to add an edge between the parent blocks of each op.
    // Ghidra: flow.cc:1021 FlowInfo::connectBasic
    pub fn connect_basic(&mut self) {
        for (source_op, target_op) in self.block_edges.clone() {
            let source = source_op
                .0
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            let target = target_op
                .0
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let (Some(source), Some(target)) = (source, target) {
                self.fd.bblocks.add_edge(source, target);
            }
        }
    }

    /// Reorder a graph so `block` is first and transfer the official entry
    /// flag from the previous first block. This is the exact list/flag
    /// mutation performed by Ghidra's `BlockGraph::setStartBlock`.
    // Ghidra: block.cc:1625 BlockGraph::setStartBlock
    fn set_start_block(graph: &mut BlockGraph, block: Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        if graph.blocks.is_empty() {
            return;
        }

        let old_first = graph.blocks[0].clone();
        if (old_first.read().unwrap().get_flags() & block_flags::ENTRY_POINT) != 0 {
            if Arc::ptr_eq(&old_first, &block) {
                return;
            }
            let mut old_first = old_first.write().unwrap();
            if let Some(basic) = old_first.as_any_mut().downcast_mut::<BlockBasic>() {
                basic.flags &= !block_flags::ENTRY_POINT;
            }
        }

        let Some(position) = graph
            .blocks
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, &block))
        else {
            return;
        };
        if position != 0 {
            let start = graph.blocks.remove(position);
            graph.blocks.insert(0, start);
        }
        block.write().unwrap().set_flags(block_flags::ENTRY_POINT);
    }

    /// Generate basic blocks from the raw control-flow. Faithful to
    /// `FlowInfo::generateBlocks` (flow.cc:824-845). Order: fillinBranchStubs
    /// → collectEdges → splitBasic → connectBasic, then ensure the entry
    /// block has no incoming edges, and finally drop unreachable blocks if
    /// the flow flagged possible_unreachable.
    // Ghidra: flow.cc:824 FlowInfo::generateBlocks
    pub fn generate_blocks(&mut self) -> crate::error::Result<()> {
        // splitBasic cannot discover a valid entry after fillinBranchStubs
        // unless findUnprocessed is going to mark this exact first op.  Check
        // that post-fillin invariant without mutating addrlist, block_edges,
        // the op lifecycle, or the block graph so the LowlevelError is
        // transactional with respect to block generation.
        if let Some(first) = self.fd.obank.dead_head() {
            let starts_basic =
                (first.0.read().unwrap().flags & pcodeop_flags::STARTBASIC) != 0;
            let pending_mark = !starts_basic
                && self.addrlist.iter().any(|addr| {
                    self.seen_instruction(*addr)
                        && self
                            .target(*addr)
                            .is_some_and(|target| Arc::ptr_eq(&target.0, &first.0))
                });
            if !starts_basic && !pending_mark {
                return Err(crate::error::Error::Lowlevel(
                    "First op not marked as entry point".to_string(),
                ));
            }
        }
        self.fillin_branch_stubs();
        self.collect_edges();
        self.split_basic()?;
        self.connect_basic();
        // flow.cc:831-840: a loop back into the official entry would make it
        // a multi-entry node for dominance. Prepend an empty block, connect
        // it to the old entry, then transfer f_entry_point to the new block.
        if let Some(start) = self.fd.bblocks.get_block(0) {
            if start.read().unwrap().size_in() != 0 {
                let mut basic = BlockBasic::new(0, self.fd.baseaddr);
                basic.set_initial_range(self.fd.baseaddr, self.fd.baseaddr);
                let new_front: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(basic));
                self.fd.bblocks.add_block(new_front.clone());
                self.fd.bblocks.add_edge(new_front.clone(), start);
                Self::set_start_block(&mut self.fd.bblocks, new_front);
            }
        }
        if self.has_possible_unreachable() {
            // data.removeUnreachableBlocks(false,true) (flow.cc:844).
            self.fd.remove_unreachable_blocks(false, true);
        }
        Ok(())
    }

    /// Generate P-code ops by following control flow from the entry point.
    /// Faithful to `FlowInfo::generateOps` (flow.cc:785-822).
    /// Phase 2: jump-table recovery via recoverJumpTables.
    // Ghidra: flow.cc:785 FlowInfo::generateOps
    pub fn generate_ops(&mut self, entry: Address) -> crate::error::Result<()> {
        // flow.cc:790: clearProperties() resets the presence flags and the
        // instruction counter before tracing.
        self.clear_properties();
        // Seed with entry address (flow.cc:791).
        self.addrlist.push(entry);

        // Phase 1: linear flow tracking (flow.cc:792-793).
        while !self.addrlist.is_empty() {
            self.fallthru()?;
        }

        // flow.cc:794-795: after the initial fall-thru sweep, expand any
        // pending injections (CALLOTHER fixups from xrefControlFlow, inline
        // call sites from checkForFlowModification).
        if self.has_inject() {
            self.inject_pcode();
        }

        // Phase 2: jump-table recovery (flow.cc:796-821).
        // do { while(!tablelist.empty()) { recoverJumpTables → newAddress per
        // entry + fallthru } checkContainedCall(); checkMultistageJumptables();
        // notreached refill; injectPcode(); } while(!tablelist.empty()) —
        // the do-while body runs at least once, so checkContainedCall
        // executes even with no indirect jumps.
        let mut notreached: Vec<crate::op::PcodeOpRef> = Vec::new();
        let mut notreachcnt: usize = 0;
        loop {
            // flow.cc:797: for each jumptable found (tablelist is filled by
            // xref_control_flow on BRANCHIND, flow.cc:321-322).
            while !self.tablelist.is_empty() {
                let mut new_tables: Vec<Option<Arc<RwLock<crate::jumptable::JumpTable>>>> =
                    Vec::new();
                self.recover_jump_tables(&mut new_tables, &mut notreached)?;
                self.tablelist.clear();
                // flow.cc:801-810: for each recovered table, push every
                // entry address and trace the new flow.
                for jt in new_tables {
                    let Some(jt) = jt else { continue };
                    let (num, indirect_addr, entries) = {
                        let jt_rg = jt.read().unwrap();
                        let indirect_addr = jt_rg
                            .get_indirect_op()
                            .map(crate::op::PcodeOpRef)
                            .map(|op| op.0.read().unwrap().get_addr())
                            .unwrap_or(*self.fd.get_address());
                        (
                            jt_rg.num_entries(),
                            indirect_addr,
                            (0..jt_rg.num_entries())
                                .map(|i| jt_rg.get_address_by_index(i))
                                .collect::<Vec<Address>>(),
                        )
                    };
                    for addr in entries {
                        self.new_address(indirect_addr, addr);
                    }
                    if num > 0 {
                        eprintln!(
                            "[JUMPTABLE] recovered {} entries from indirect jump at 0x{:x}",
                            num,
                            indirect_addr.as_u64()
                        );
                    }
                    while !self.addrlist.is_empty() {
                        self.fallthru()?;
                    }
                }
            }

            // flow.cc:813: checkContainedCall(); — check for PIC
            // constructions. Runs on every do-while pass, including a first
            // pass with no jump tables.
            self.check_contained_call();
            // flow.cc:814: checkMultistageJumptables(); — promote
            // override-marked single-entry tables back onto tablelist
            // (JUMPTABLE-MULTISTAGE closed by JUMPTABLE-PIPELINE-0001).
            self.check_multistage_jumptables();

            // flow.cc:815-818: refill tablelist from unreached indirect ops.
            while notreachcnt < notreached.len() {
                self.tablelist.push(notreached[notreachcnt].clone());
                notreachcnt += 1;
            }
            // flow.cc:819-820: expand any injections queued by this pass
            // before the `!tablelist.empty()` loop condition.
            if self.has_inject() {
                self.inject_pcode();
            }
            // flow.cc:821: `while(!tablelist.empty())` — inlining or
            // multistage may have added new indirect branches.
            if self.tablelist.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Snapshot the generation-time state for external observation. The
    /// snapshot is taken after `generate_blocks` (the same phase the locked
    /// oracle fixture observes) and clones:
    ///   - the ops in `PcodeOpBank` SeqNum natural order with their
    ///     immutable `time` values;
    ///   - the exact `VisitStat` values (first-op SeqNum address/time and
    ///     instruction size);
    ///   - every Const-space relative BRANCH/CBRANCH resolution re-run
    ///     through `findRelTarget` in op order;
    ///   - the collected `(source, target)` raw edges as live Arcs.
    ///
    /// SLEIGH callback `VarnodeData*` identities are deliberately absent:
    /// post-emission Varnode identity is assigned later from the Funcdata
    /// bank Arcs by the consumer.
    // RUGRA-GLUE: fixture observation API; Ghidra's flow.cc has no snapshot
    // (the oracle fixture reads FlowInfo private fields directly instead).
    pub fn snapshot(&self) -> FlowInfoSnapshot {
        let operations: Vec<FlowOpSnapshot> = self
            .fd
            .obank
            .optree
            .iter()
            .map(|op| {
                let operation = op.0.read().unwrap();
                FlowOpSnapshot {
                    op: crate::op::PcodeOpRef(op.0.clone()),
                    time: operation.get_time(),
                }
            })
            .collect();
        let visited = self
            .visited
            .iter()
            .map(|(&address, stat)| {
                let invalid = crate::address::SeqNum::new(Address::new(0), 0);
                let seq = stat.first_seq.unwrap_or(invalid);
                FlowVisitedSnapshot {
                    address: Address::new(address),
                    first_seq_address: seq.get_addr(),
                    first_seq_time: seq.get_time(),
                    size: stat.size,
                }
            })
            .collect();
        let mut relatives = Vec::new();
        for snapshot_op in &operations {
            // CURLWIRE-CR-F1-A1 (LOCKFIX method): lift the opcode filter and
            // the first input Arc under one short guard, then release the
            // guard before `find_rel_target` re-locks this same op through
            // its call chain (flow.rs find_rel_target takes op.0.read at its
            // head) — std RwLock read-read reentrancy is not writer-fair.
            let first_input = {
                let operation = snapshot_op.op.0.read().unwrap();
                if !matches!(operation.opcode, OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH) {
                    None
                } else {
                    operation.inrefs.first().cloned()
                }
            };
            let Some(input) = first_input else {
                continue;
            };
            if !input.read().unwrap().get_space().is_const() {
                continue;
            }
            let offset = input.read().unwrap().get_offset();
            let computed_target_time = snapshot_op.time.wrapping_add(offset as u32);
            match self.find_rel_target(&snapshot_op.op) {
                Ok(RelativeTarget::Internal(target)) => relatives.push(FlowRelativeSnapshot {
                    source: snapshot_op.op.clone(),
                    target: Some(target),
                    target_address: None,
                    computed_target_time,
                }),
                Ok(RelativeTarget::Fallthru(address)) => relatives.push(FlowRelativeSnapshot {
                    source: snapshot_op.op.clone(),
                    target: None,
                    target_address: Some(address),
                    computed_target_time,
                }),
                // flow.cc:173-178: Ghidra would throw for a corrupt relative
                // branch; the snapshot surfaces the raw computed time with no
                // resolution so the divergence is observable.
                Err(_) => relatives.push(FlowRelativeSnapshot {
                    source: snapshot_op.op.clone(),
                    target: None,
                    target_address: None,
                    computed_target_time,
                }),
            }
        }
        FlowInfoSnapshot {
            operations,
            visited,
            relatives,
            raw_edges: self.block_edges.clone(),
            addrlist_count: self.addrlist.len(),
            unprocessed_count: self.unprocessed.len(),
            inject_count: self.injectlist.len(),
            table_count: self.tablelist.len(),
            instruction_count: self.insn_count,
            instruction_max: self.insn_max,
            flags: self.flags,
            baddr: Address::new(self.baddr),
            eaddr: Address::new(self.eaddr),
            minaddr: Address::new(self.minaddr),
            maxaddr: Address::new(self.maxaddr),
        }
    }

    // RUGRA-GLUE: 收集 raw/dead BRANCHIND ops（Ghidra 内联在 generateOps 的 tablelist 循环中）。
    /// Collect all raw BRANCHIND ops (for tablelist processing).
    fn collect_branchinds(&self) -> Vec<crate::op::PcodeOpRef> {
        self.fd
            .obank
            .iter_dead()
            .filter(|r| r.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_BRANCHIND)
            .map(|r| crate::op::PcodeOpRef(r.0.clone()))
            .collect()
    }

    // Ghidra: flow.cc:219 FlowInfo::newAddress
    /// Add a new address to the work-list (flow.cc:219-235). `from_addr` is
    /// the source branch's machine address (Ghidra passes the issuing
    /// `PcodeOp*`; it is used only for the out-of-bounds diagnostic).
    /// Mirrors Ghidra's behavior: out-of-bounds addresses are reported via
    /// `handleOutOfBounds` and pushed to `unprocessed`; already-seen targets
    /// get their target op marked as a basic-block start; anything else is
    /// queued on the LIFO work-list.
    fn new_address(&mut self, from_addr: Address, addr: Address) {
        let a = addr.as_u64();
        // flow.cc:222-226: range check + handleOutOfBounds.
        if a < self.baddr || self.eaddr < a {
            self.handle_out_of_bounds(from_addr, addr);
            self.unprocessed.push(addr);
            return;
        }
        // flow.cc:228-233: if already seen, mark the target op as a basic
        // block start.
        if self.seen_instruction(addr) {
            if let Some(op) = self.target(addr) {
                op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
            }
            return;
        }
        self.addrlist.push(addr);
    }

    /// Process sequential instructions from addrlist until a terminator
    /// or already-visited address is hit. Corresponds to `FlowInfo::fallthru`
    /// (flow.cc:545-580).
    // Ghidra: flow.cc:545 FlowInfo::fallthru
    fn fallthru(&mut self) -> crate::error::Result<()> {
        // Ghidra holds this boundary fixed while following a sequential
        // region. Recomputing it from the changing work-list can skip an
        // exact hit on a previously decoded branch target.
        let Some(mut bound) = self.set_fallthru_bound() else {
            return Ok(());
        };

        let mut start_basic = true;
        loop {
            let Some(curaddr) = self.addrlist.pop() else {
                break;
            };
            if !self.process_instruction(curaddr, &mut start_basic)? {
                break;
            }
            if self.addrlist.is_empty() {
                break;
            }

            let next = self.addrlist.last().unwrap().as_u64();
            if bound <= next {
                if bound == self.eaddr {
                    // flow.cc:563-567: the sequential successor is outside
                    // the permitted range. Preserve it as an unprocessed
                    // address for fillinBranchStubs().
                    self.handle_out_of_bounds(Address::new(self.eaddr), Address::new(next));
                    self.unprocessed.push(Address::new(next));
                    self.addrlist.pop();
                    return Ok(());
                }

                if bound == next {
                    // flow.cc:569-574: a control-flow op at the end of the
                    // just-decoded instruction can force the already-visited
                    // successor to begin a basic block.
                    if start_basic {
                        if let Some(op) = self.target(Address::new(next)) {
                            op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                        }
                    }
                    self.addrlist.pop();
                    break;
                }

                let Some(next_bound) = self.set_fallthru_bound() else {
                    return Ok(());
                };
                bound = next_bound;
            }
        }
        Ok(())
    }

    /// Check if the next address in addrlist is processable.
    /// Returns `None` if the pending address was already visited. Otherwise,
    /// returns the first visited instruction strictly above it, or `eaddr`.
    // Ghidra: flow.cc:489 FlowInfo::setFallthruBound
    fn set_fallthru_bound(&mut self) -> Option<u64> {
        let addr = self.addrlist.last()?.as_u64();

        // `visited.upper_bound(addr)` followed by one predecessor step is
        // Ghidra's exact lookup. An exact hit is a queued non-fallthrough
        // target that was decoded by another path in the meantime: mark the
        // target op before discarding the duplicate work-list address.
        if let Some((&instruction, stat)) = self.visited.range(..=addr).next_back() {
            if addr == instruction {
                if let Some(op) = self.target(Address::new(addr)) {
                    op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                }
                self.addrlist.pop();
                return None;
            }
            if addr < instruction.saturating_add(stat.size as u64) {
                self.reinterpreted(Address::new(addr));
            }
        }

        let bound = self
            .visited
            .range((std::ops::Bound::Excluded(addr), std::ops::Bound::Unbounded))
            .next()
            .map_or(self.eaddr, |(&instruction, _)| instruction);
        Some(bound)
    }

    /// Decode a single instruction, generate P-code, and analyze control flow.
    /// Returns true if execution falls through to the next instruction.
    /// Faithful port of `processInstruction` (flow.cc:383-482).
    ///
    /// Order of operations (flow.cc:408-480):
    ///   1. remember the alive-list position before emission;
    ///   2. `oneInstruction` runs the emitter, which appends the instruction's
    ///      ops (Rugra: `inject_raw_ops_single` = `PcodeEmitFd::dump`);
    ///   3. record `VisitStat { seqnum: first new op, size: step }` in
    ///      `visited` and update min/maxaddr;
    ///   4. mark the first new op as an instruction start and run
    ///      `xref_control_flow` over the new ops (which may delete some);
    ///   5. queue the machine fall-through address exactly once, only when
    ///      the instruction falls through.
    // Ghidra: flow.cc:383 FlowInfo::processInstruction
    fn process_instruction(
        &mut self,
        addr: Address,
        start_basic: &mut bool,
    ) -> crate::error::Result<bool> {
        // Instruction count limit (flow.cc:393-405). Ghidra throws when
        // error_toomanyinstructions is set; otherwise it truncates the flow
        // with an artificial halt and still enters the shared translation
        // tail. In particular, the dead-list boundary is captured after the
        // artificial halt, so xref begins at the subsequently lifted ops.
        if self.insn_count >= self.insn_max {
            if (self.flags & flow_flags::ERROR_TOOMANYINSTRUCTIONS) != 0 {
                return Err(crate::error::Error::Lowlevel(
                    "Flow exceeded maximum allowable instructions".to_string(),
                ));
            }
            self.artificial_halt(addr, pcodeop_flags::BADINSTRUCTION);
            self.fd
                .warning("Too many instructions -- Truncating flow here", addr);
            if !self.has_too_many_instructions() {
                self.flags |= flow_flags::TOOMANYINSTRUCTIONS_PRESENT;
                self.fd.warning_header(
                    "Exceeded maximum allowable instructions: Some flow is truncated",
                );
            }
        }
        self.insn_count += 1;

        // flow.cc:407-418: remember the dead-list boundary, then cache the
        // exact-address override before lifting. The constructor-level flag
        // avoids a map lookup when no override metadata exists. The
        // boundary marker is the pre-lift dead-chain tail id (the oracle's
        // stored-iterator form, op.hh:128) — the first lifted op is its
        // successor.
        let ops_before = self.fd.obank.dead_tail_id();
        let flowoverride = if self.flowoverride_present {
            self.fd.localoverride.get_flow_override(addr)
        } else {
            crate::override_rs::FlowOverride::None
        };

        // flow.cc:421: step = glb->translate->oneInstruction(emitter,curaddr).
        // The emitter appends the ops directly; errors map to artificial
        // halts with the unimplemented/bad-data flags (flow.cc:423-457).
        let step: usize;
        let lift_result = self
            .lifter
            .as_deref_mut()
            .expect("FlowInfo cloning constructor cannot generate instructions")
            .lift_instruction(addr.as_u64());
        match lift_result {
            Ok((instruction_length, raw_ops)) => {
                step = instruction_length;
                if !raw_ops.is_empty() {
                    self.fd.inject_raw_ops_single(&raw_ops, addr);
                }
            }
            Err(error) => {
                let ignored_unimplemented = error.kind == SleighErrorKind::Unimplemented
                    && (self.flags & flow_flags::IGNORE_UNIMPLEMENTED) != 0;
                if ignored_unimplemented {
                    // flow.cc:424-430: ignore as NOP, keep the step.
                    step = error
                        .instruction_length
                        .and_then(|length| usize::try_from(length).ok())
                        .filter(|length| *length != 0)
                        .unwrap_or(1);
                    if !self.has_unimplemented() {
                        self.flags |= flow_flags::UNIMPLEMENTED_PRESENT;
                        self.fd
                            .warning_header("Control flow ignored unimplemented instructions");
                    }
                } else {
                    // flow.cc:431-457: truncate the flow with an artificial
                    // halt (step = 1, "Pretend size 1").
                    let halt_flag = if error.kind == SleighErrorKind::Unimplemented {
                        self.flags |= flow_flags::UNIMPLEMENTED_PRESENT;
                        self.fd.warning_header(
                            "Control flow encountered unimplemented instructions",
                        );
                        pcodeop_flags::UNIMPLEMENTED
                    } else {
                        self.flags |= flow_flags::BADDATA_PRESENT;
                        self.fd
                            .warning_header("Control flow encountered bad instruction data");
                        pcodeop_flags::BADINSTRUCTION
                    };
                    step = 1;
                    self.artificial_halt(addr, halt_flag);
                    self.fd
                        .warning(&format!("{} - Truncating control flow here", error), addr);
                }
            }
        }
        self.finish_process_instruction(addr, step, ops_before, start_basic, flowoverride)
    }

    /// Shared tail of `processInstruction` (flow.cc:458-481): record the
    /// VisitStat, update address extremes, mark the first new op, xref the
    /// instruction's ops, and queue the machine fall-through.
    // Ghidra: flow.cc:383 FlowInfo::processInstruction (VisitStat/xref tail)
    fn finish_process_instruction(
        &mut self,
        addr: Address,
        step: usize,
        ops_before: Option<crate::arena::OpId>,
        start_basic: &mut bool,
        flowoverride: crate::override_rs::FlowOverride,
    ) -> crate::error::Result<bool> {
        // flow.cc:458-459: stat.size = step. The seqnum is filled in below
        // when the instruction produced at least one op (flow.cc:472).
        self.visited.insert(
            addr.as_u64(),
            VisitStat {
                first_seq: None,
                size: step,
            },
        );
        // flow.cc:461-464: update minimum and maximum address.
        let a = addr.as_u64();
        if a < self.minaddr {
            self.minaddr = a;
        }
        if a.saturating_add(step as u64) > self.maxaddr {
            self.maxaddr = a.saturating_add(step as u64);
        }

        // flow.cc:466-477: point at the first new op, record its SeqNum,
        // mark it as the instruction start, and xref the new ops.
        let mut isfallthru = true;
        if let Some(first_id) = self.fd.obank.dead_after(ops_before) {
            let first_op = self
                .fd
                .obank
                .op_by_id(first_id)
                .expect("dead_after returned a live chain member")
                .clone();
            let first_seq = first_op.0.read().unwrap().start;
            if let Some(stat) = self.visited.get_mut(&addr.as_u64()) {
                stat.first_seq = Some(first_seq);
            }
            first_op.0.write().unwrap().flags |= pcodeop_flags::STARTMARK;
            // flow.cc:474-475: the flow override rewrites the freshly lifted,
            // still-dead ops before xref interprets their control-flow. This
            // ordering is decisive for CALL_RETURN: xref creates a callspec
            // for the converted CALL and never queues its former jump target.
            if flowoverride != crate::override_rs::FlowOverride::None {
                self.fd.override_flow(addr, flowoverride)?;
            }
            isfallthru = self.xref_control_flow(Some(first_id), start_basic);
        }
        // flow.cc:479-480: only a fall-through instruction queues its
        // machine successor (exactly once).
        if isfallthru {
            self.addrlist
                .push(Address::new(addr.as_u64() + step as u64));
        }
        Ok(isfallthru)
    }

    /// Analyze the control-flow ops generated by the last instruction.
    /// Returns true if execution falls through. Faithful port of
    /// `xrefControlFlow` (flow.cc:264-372).
    ///
    /// `maxtime` tracks the deepest internal relative-branch target time
    /// (flow.cc:269). An unconditional BRANCH/BRANCHIND/RETURN whose own
    /// time is at or past `maxtime` cannot be jumped over, so the remaining
    /// ops of the instruction are deleted (flow.cc:314-334). A Const-space
    /// branch input is resolved relatively through `findRelTarget` and never
    /// enters the machine-address work list; only non-Const targets call
    /// `newAddress`.
    // Ghidra: flow.cc:264 FlowInfo::xrefControlFlow
    fn xref_control_flow(
        &mut self,
        ops_start: Option<crate::arena::OpId>,
        start_basic: &mut bool,
    ) -> bool {
        self.xref_control_flow_at(ops_start, start_basic, None).1
    }

    /// Full `xrefControlFlow` form used by both `processInstruction`
    /// (fc = None) and `doInjection` (fc = the injecting callspec, used for
    /// the recursion cycle check in `setupCallSpecs`/`setupCallindSpecs`,
    /// flow.cc:337/341). Returns the last processed op (Ghidra's return
    /// value, flow.cc:264-265 "the last processed PcodeOp (or NULL)") plus
    /// the instruction fall-through flag.
    // Ghidra: flow.cc:264 FlowInfo::xrefControlFlow
    fn xref_control_flow_at(
        &mut self,
        ops_start: Option<crate::arena::OpId>,
        start_basic: &mut bool,
        inject_fc: Option<usize>,
    ) -> (Option<crate::op::PcodeOpRef>, bool) {
        let mut isfallthru = false;
        // flow.cc:269: deepest internal relative branch.
        let mut maxtime: u32 = 0;
        // The walk is the oracle's dead-list iterator loop (flow.cc:269-352):
        // `iter` advances past each op before its arm runs, and arms that
        // truncate the instruction (BRANCH/BRANCHIND/RETURN at/after maxtime)
        // erase the remaining tail. The id-space cursor advances at the loop
        // tail by re-reading the current op's ins_next, so an arm-inserted op
        // (the no-return artificial halt right after a CALL) is seen next,
        // exactly as the former `index` pointed at it, and a truncated tail
        // leaves the successor as the sentinel, ending the walk.
        let mut cur = ops_start;
        let mut last_opcode: Option<OpCode> = None;
        let mut lastop: Option<crate::op::PcodeOpRef> = None;

        while let Some(id) = cur {
            let Some(op_ref) = self.fd.obank.op_by_id(id).cloned() else { break };
            let opcode = op_ref.0.read().unwrap().opcode;
            last_opcode = Some(opcode);
            lastop = Some(op_ref.clone());
            if *start_basic {
                // flow.cc:272-274.
                op_ref.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                *start_basic = false;
            }
            let truncate_tail = match opcode {
                OpCode::CPUI_CBRANCH => {
                    self.xref_conditional_branch(&op_ref, &mut maxtime, &mut isfallthru);
                    // flow.cc:294: the op after a conditional branch starts a
                    // basic block.
                    *start_basic = true;
                    false
                }
                OpCode::CPUI_BRANCH => {
                    self.xref_conditional_branch(&op_ref, &mut maxtime, &mut isfallthru);
                    // flow.cc:314-317: a BRANCH at/after the deepest forward
                    // relative target makes the rest of the instruction dead.
                    let truncating = op_ref.0.read().unwrap().get_time() >= maxtime;
                    // flow.cc:318: the op after an unconditional branch starts
                    // a basic block (unconditionally, also on the truncating
                    // path).
                    *start_basic = true;
                    truncating
                }
                OpCode::CPUI_BRANCHIND => {
                    // flow.cc:321-327: put off trying to recover the table;
                    // the following op starts a basic block.
                    self.tablelist.push(op_ref.clone());
                    let truncating =
                        op_ref.0.read().unwrap().get_time() >= maxtime;
                    *start_basic = true;
                    truncating
                }
                OpCode::CPUI_RETURN => {
                    // flow.cc:329-334.
                    let truncating =
                        op_ref.0.read().unwrap().get_time() >= maxtime;
                    *start_basic = true;
                    truncating
                }
                OpCode::CPUI_CALL => {
                    // flow.cc:336-338: if the sub-function never returns, an
                    // artificial halt was inserted directly after this call,
                    // so it must be xref'd too. The halt lands immediately
                    // after the call in the dead chain, so the loop tail's
                    // successor read processes it — Ghidra's `--oiter`.
                    self.setup_call_specs(&op_ref, inject_fc);
                    false
                }
                OpCode::CPUI_CALLIND => {
                    // flow.cc:340-342: same contract as CALL.
                    self.setup_callind_specs(&op_ref, inject_fc);
                    false
                }
                OpCode::CPUI_CALLOTHER => {
                    // flow.cc:344-348: an injected user-op goes on the
                    // injectlist. `glb->userops.getOp(op->getIn(0)->
                    // getOffset())->getType() == UserPcodeOp::injected` —
                    // Ghidra dereferences getOp() unconditionally; Rugra
                    // guards the Option (an unregistered index is simply not
                    // injected).
                    let index_const = op_ref
                        .0
                        .read()
                        .unwrap()
                        .inrefs
                        .first()
                        .map(|vn| vn.read().unwrap().get_offset() as i32);
                    if let Some(userop_index) = index_const {
                        if let Some((userops, _lib)) = self.arch_inject_sources() {
                            let userops = userops.read().expect("lock poisoned");
                            if userops
                                .get_op(userop_index)
                                .map(|u| u.is_injected())
                                .unwrap_or(false)
                            {
                                self.injectlist.push(Some(op_ref.clone()));
                            }
                        }
                    }
                    false
                }
                _ => false,
            };
            if truncate_tail {
                // The former `delete_remaining_ops_from(index); index = len`
                // pair: erase every chain member after this op and let the
                // successor read end the walk.
                self.delete_remaining_ops_after(Some(id));
                cur = None;
            } else {
                cur = self.fd.obank.dead_after(Some(id));
            }
        }

        // flow.cc:354-370: compute the instruction's fall-through.
        if isfallthru {
            // We have seen an explicit relative branch to end of instruction:
            // the next instruction starts a basic block.
            *start_basic = true;
        } else {
            match last_opcode {
                None => isfallthru = true, // No ops at all means a fallthru.
                Some(OpCode::CPUI_BRANCH)
                | Some(OpCode::CPUI_BRANCHIND)
                | Some(OpCode::CPUI_RETURN) => {}
                Some(_) => isfallthru = true,
            }
        }
        (lastop, isfallthru)
    }

    /// Shared BRANCH/CBRANCH target cross-reference (flow.cc:277-319): a
    /// Const-space input(0) is an intra-instruction relative branch whose
    /// target op (found via `findRelTarget`) is marked as a basic-block
    /// start and updates `maxtime`; a relative branch to the end of the
    /// instruction sets `isfallthru`; a non-Const input(0) is a machine
    /// address queued through `newAddress`.
    // Ghidra: flow.cc:264 FlowInfo::xrefControlFlow (CBRANCH/BRANCH cases)
    fn xref_conditional_branch(
        &mut self,
        op_ref: &crate::op::PcodeOpRef,
        maxtime: &mut u32,
        isfallthru: &mut bool,
    ) {
        let (dest_const, dest_offset, op_addr) = {
            let operation = op_ref.0.read().unwrap();
            let in0 = operation.inrefs.get(0).cloned();
            match in0 {
                Some(input) => {
                    let varnode = input.read().unwrap();
                    (varnode.get_space().is_const(), varnode.get_offset(), operation.get_addr())
                }
                None => return,
            }
        };
        if dest_const {
            // flow.cc:280-291 / 300-311: relative sequence number.
            match self.find_rel_target(op_ref) {
                Ok(RelativeTarget::Internal(destop)) => {
                    // flow.cc:284 / 304: make sure the target op is a basic
                    // block start and update maxtime.
                    destop.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
                    let newtime = destop.0.read().unwrap().get_time();
                    if newtime > *maxtime {
                        *maxtime = newtime;
                    }
                }
                Ok(RelativeTarget::Fallthru(_)) => {
                    // flow.cc:290 / 310: relative branch is to end of
                    // instruction.
                    *isfallthru = true;
                }
                Err(message) => {
                    // Ghidra throws LowlevelError (flow.cc:173-178); Rugra
                    // reports and truncates this instruction's flow.
                    eprintln!("[FLOW] {}: {}", self.fd.name, message);
                }
            }
        } else {
            // flow.cc:293 / 313: generate branch address.
            self.new_address(op_addr, Address::new(dest_offset));
        }
    }
}

/// Materialize the `FuncProto` base-class state that C++ `new
/// FuncCallSpecs(op)` (fspec.cc:4924-4925) gets implicitly via
/// `FuncProto::FuncProto()` (fspec.cc:3778-3786): flags = 0 — no input
/// lock, no output lock, no model lock — model = null, empty parameter
/// list. The call site's real signature arrives later through the
/// program-database boundary (the driver's locked-signature installs or
/// `ActionDefaultParams`, coreaction.cc:2311), and an unlocked void
/// prototype lets `ActionFuncLink::funcLinkOutput`'s else-branch
/// (coreaction.cc:1571-1572) start active return recovery for unknown
/// callees.
// RUGRA-GLUE: Rust needs an owned FuncProto value where C++ default-constructs the base class inline.
pub(crate) fn default_call_spec_proto() -> crate::fspec::FuncProto {
    crate::fspec::FuncProto::new(
        String::new(),
        std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
            crate::type_system::datatype::TypeBase::new(
                "void".to_string(),
                0,
                crate::type_system::TypeMetatype::Void,
            ),
        )),
    )
}

/// Entry point: follow flow from entry address, generating P-code ops and CFG.
/// Partial production entry corresponding to `Funcdata::followFlow`
/// (funcdata_op.cc:756-783).
///
/// Replaces the three-stage linear scan (disassemble → lift → inject_raw_ops)
/// with reachability-driven flow tracking.
// Ghidra: funcdata_op.cc:756 Funcdata::followFlow
pub fn follow_flow(
    fd: &mut Funcdata,
    lifter: &mut SleighLifter,
    entry: Address,
    eaddr: u64,
) -> crate::error::Result<()> {
    follow_flow_with_callee_protos(fd, lifter, entry, eaddr, &std::collections::BTreeMap::new())
}

/// [`follow_flow`] with the per-callee prototype table that stands in for
/// the `funcp` slice of the Funcdata objects Ghidra's `queryFunction`
/// (flow.cc:660) resolves from the symbol database. Entries keyed by callee
/// entry address feed `FlowInfo::query_call`'s `copy_flow_effects`
/// (flow.cc:663-664); an empty table leaves every call site's
/// inline/no-return flags untouched (the production data source — the
/// driver-side known-noreturn name list — is FLOW-NORETURN-DATA-0001).
// RUGRA-GLUE: Ghidra reaches the callee prototypes through the shared symbol database; Rugra's Funcdata owns no per-callee Funcdata at flow time, so the driver hands the table to the flow entry point.
pub fn follow_flow_with_callee_protos(
    fd: &mut Funcdata,
    lifter: &mut SleighLifter,
    entry: Address,
    eaddr: u64,
    callee_protos: &std::collections::BTreeMap<u64, crate::fspec::FuncProto>,
) -> crate::error::Result<()> {
    // Historical driver-bounded form (RUGRA-FLOW-MIRROR-0001): the
    // constraining range starts at the function entry. The full oracle
    // parameter form — followFlow(code:0, code:highest), regen_ghidra_golden
    // .py:388 ≡ oracle harness:315 — is [`follow_flow_range`].
    follow_flow_range(fd, lifter, entry.as_u64(), eaddr, callee_protos)
}

/// Flow entry mirroring the full `(baddr, eaddr)` parameter form of
/// `Funcdata::followFlow` (funcdata_op.cc:756-783): the caller supplies the
/// constraining range; the walk itself always seeds from the function's own
/// entry (`data.getAddress()`, flow.cc:791
/// `addrlist.push_back(data.getAddress())`). The golden-generation path and
/// the oracle single-function harness pass
/// `(Address(codeSpace, 0), Address(codeSpace, getHighest()))` — for the
/// x86-64 default ram space that is `(0, u64::MAX)` — so tail jumps into
/// lower code-space regions (PLT) are followed in-function and later
/// truncated through the jumptable fail_thunk path (jumptable.cc:2304-2320
/// → flow.cc:727/735 CALLIND + artificial halt).
// Ghidra: funcdata_op.cc:756 Funcdata::followFlow
pub fn follow_flow_range(
    fd: &mut Funcdata,
    lifter: &mut SleighLifter,
    baddr: u64,
    eaddr: u64,
    callee_protos: &std::collections::BTreeMap<u64, crate::fspec::FuncProto>,
) -> crate::error::Result<()> {
    // flow.cc:791: the walk starts at the function's own address, never at
    // baddr (baddr only constrains new-address targets, flow.cc:222).
    let entry = *fd.get_address();
    let mut flow = FlowInfo::new(fd, lifter, baddr, eaddr);
    flow.callee_func_protos = callee_protos.clone();
    flow.generate_ops(entry)?;
    // funcdata_op.cc:776: generateBlocks is responsible for the official
    // entry identity/flag, ordered edge replay, and synthetic entry creation.
    flow.generate_blocks()?;
    // funcdata_op.cc:777-778: `flags |= blocks_generated;
    // switchOverJumpTables(flow);` — map every recovered jump-table address
    // to its switch out-edge slot (JumpTable::switchOver, jumptable.cc:2528)
    // before the FlowInfo borrow ends. RUGRA-GLUE: associated-function form
    // (Funcdata is exclusively borrowed by this FlowInfo).
    {
        let fd_shared: &crate::funcdata::Funcdata = &*flow.fd;
        crate::funcdata::Funcdata::switch_over_jump_tables(fd_shared, &flow)?;
    }
    Ok(())
}

/// Post-load jump-table recovery for a driver that batch-injected its whole
/// op bank (`Funcdata::inject_raw_ops`), i.e. the linear-lift driver path
/// (HTTPD-MAIN-WARNUNREACH-JTEDGE-0001). Runs exactly the generateOps
/// phase-2 sequence of `Funcdata::followFlow` (funcdata_op.cc:771
/// `flow.generateOps()` — recovery happens there BEFORE `generateBlocks`,
/// flow.cc:792-821) plus the two generateBlocks-tail observables a fused
/// linear load could not produce: the per-entry switch out-edges
/// (collectEdges' BRANCHIND arm, flow.cc:933-957) and the switchOver map
/// (funcdata_op.cc:777-778 `switchOverJumpTables(flow)` ->
/// jumptable.cc:2528).
///
/// Adapter deltas against the oracle sequence, all consequences of the
/// caller's pre-lifted linear bank (the case bodies are already present;
/// the oracle would lift them via `newAddress` + `fallthru`, flow.cc:806-809):
///   * the ops are temporarily moved to the dead list (mark_dead/mark_alive
///     cycle) so `Funcdata::truncatedFlow` — Ghidra's partial-clone source,
///     which reads `obank.beginDead()` — sees the same "raw p-code on the
///     dead list, nothing alive yet" state the oracle has at recovery time;
///   * `newAddress`/`fallthru` are no-ops (every window instruction is
///     already lifted and in the synthesized `visited` map);
///   * block starts carry STARTBASIC (the xref walk's end-state, flow.cc
///     469-477/570-572 — Ghidra marks every block start; the batch inject
///     path never did), so the partial clone reproduces the source block
///     partition in its own generateBlocks;
///   * a table destination with no op in the injected window (outside the
///     symbol span the linear lift covered) cannot resolve; its edge and
///     its table's switchOver are skipped with a warning — the oracle
///     cannot hit this (it lifts every destination in-range).
///
/// Returns the number of newly recovered tables. `Err` propagates the
/// LowlevelError channel exactly as it escapes `recoverJumpTables` ->
/// `generateOps` -> `followFlow` in Ghidra.
// Ghidra: flow.cc:785 FlowInfo::generateOps
// Ghidra: flow.cc:219 FlowInfo::newAddress
/// Oracle case-destination split for the injected linear partition.
/// `FlowInfo::newAddress` (flow.cc:228-233) marks an already-seen jumptable
/// destination op STARTBASIC, and `FlowInfo::splitBasic` (flow.cc:996-1016)
/// then lands every marked op at the head of its own basic block whose
/// cover spans exactly its ops' addresses; the truncated head block keeps
/// the leading ops and gains a fall-thru edge (collectEdges' nextstart arm,
/// flow.cc:952-956, linked by connectBasic). The linear inject path builds
/// its block partition before jump-table recovery, so this helper performs
/// the equivalent split surgically on the existing graph: ops from the
/// destination op onward move to a new tail block that inherits the head's
/// out-edges (each paired incoming half re-pointed in place, so every
/// surviving edge keeps its slot and list order), and the head keeps the
/// leading ops with a fall-thru out-edge slot left for the caller to fill.
/// The tail is inserted directly after its head in the block list so the
/// address order splitBasic's dead-list walk produces is preserved.
/// Returns `(dest_block, head_block)`; `head_block` is `Some` only when a
/// split happened. `None` = the destination op has no parent block.
fn split_block_at_case_dest(
    fd: &mut Funcdata,
    targ_op: &crate::op::PcodeOpRef,
    switch_block: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
) -> Option<(
    Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>>,
)> {
    let parent = targ_op
        .0
        .read()
        .unwrap()
        .parent
        .as_ref()
        .and_then(std::sync::Weak::upgrade)?;
    // Locate the destination op in its parent; position 0 = already a
    // block head, nothing to split (the oracle's mark names an existing
    // partition boundary). The switch block itself is never a valid split
    // parent: a table entry naming the switch's own computation would move
    // the BRANCHIND out of the block the edge loop resolves it from.
    let split_index = {
        let parent_rg = parent.read().unwrap();
        let bb = parent_rg
            .as_any()
            .downcast_ref::<crate::block::BlockBasic>()?;
        bb.ops
            .iter()
            .position(|o| Arc::ptr_eq(&o.0, &targ_op.0))?
    };
    if split_index == 0 || Arc::ptr_eq(&parent, switch_block) {
        return Some((parent, None));
    }
    // flow.cc:230: data.opMarkStartBasic(op) — the observable mark the
    // oracle leaves on the destination op.
    targ_op.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
    // splitBasic's block creation (flow.cc:996/1005); repositioned below.
    let tail: Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> = fd.create_new_block();
    // splitBasic's per-block ranges (flow.cc:999-1016): the op walk keeps
    // `stop` monotonically growing, so the head keeps ops[..k] (last
    // address = ops[k-1]) and the tail spans ops[k..] starting at the
    // destination op's own address.
    let (moved, parent_outgoing) = {
        let mut parent_w = parent.write().unwrap();
        let pbb = parent_w
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("case-destination split requires BlockBasic parents");
        let head_stop = pbb.ops[split_index - 1].0.read().unwrap().get_addr();
        let moved = pbb.ops.split_off(split_index);
        let tail_stop = moved
            .last()
            .map(|o| o.0.read().unwrap().get_addr())
            .unwrap_or(head_stop);
        let dest_addr = targ_op.0.read().unwrap().get_addr();
        let parent_start = pbb.get_start_addr();
        pbb.set_initial_range(parent_start, head_stop);
        // SWITCH_OUT tracks the block holding a BRANCHIND (the flag
        // BlockBasic::insert maintains, block.cc:2292); recompute both
        // halves after the move.
        let parent_has_switch = pbb
            .ops
            .iter()
            .any(|o| o.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND);
        pbb.clear_flags(crate::block::block_flags::SWITCH_OUT);
        if parent_has_switch {
            pbb.set_flags(crate::block::block_flags::SWITCH_OUT);
        }
        let outgoing = std::mem::take(&mut pbb.outgoing);
        // (g) guard-shadow: mem::take empties the out-edge vector — push the
        // post-take sizes into the owning bank's cells.
        pbb.sync_bank_shadows();
        let mut tail_w = tail.write().unwrap();
        let tbb = tail_w
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("create_new_block yields BlockBasic");
        tbb.ops = moved.clone();
        tbb.set_initial_range(dest_addr, tail_stop);
        if tbb
            .ops
            .iter()
            .any(|o| o.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND)
        {
            tbb.set_flags(crate::block::block_flags::SWITCH_OUT);
        }
        (moved, outgoing)
    };
    // Re-parent the moved ops to the tail (BlockBasic::insert's parent
    // assignment, block.cc:2266 — add_block ran before the ops existed).
    let tail_weak = std::sync::Arc::downgrade(&tail);
    for op in &moved {
        op.0.write().unwrap().parent = Some(tail_weak.clone());
    }
    // The tail inherits the head's out-edges. Re-point each paired incoming
    // half in place: the reverse index still names the same outgoing slot
    // (the move preserves outgoing order), so both lists keep every
    // surviving edge's slot and order — the same end-state connectBasic
    // (flow.cc:1021-1037) produces for the oracle's edge list.
    let tail_id = fd.bblocks.bank.registered_id_of(&tail);
    for edge in &parent_outgoing {
        let target_arc = fd.bblocks.bank.expect_arc(edge.point);
        let mut target_w = target_arc.write().unwrap();
        let target_bb = target_w
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("basic-block graph edges connect BlockBasic nodes");
        let slot = edge.reverse_index as usize;
        if let Some(in_edge) = target_bb.incoming.get_mut(slot) {
            in_edge.point = tail_id;
        }
    }
    {
        let mut tail_w = tail.write().unwrap();
        let tbb = tail_w
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("create_new_block yields BlockBasic");
        tbb.outgoing = parent_outgoing;
        // (g) guard-shadow: wholesale out-edge inheritance — sync sizes.
        tbb.sync_bank_shadows();
    }
    // Insert the tail directly after its head so the block list keeps the
    // address order splitBasic's dead-list walk produces (the linear
    // partition is address-ordered, and the tail's range lies inside the
    // head's original range).
    if let Some(pos) = fd
        .bblocks
        .blocks
        .iter()
        .position(|b| Arc::ptr_eq(b, &parent))
    {
        if let Some(last) = fd.bblocks.blocks.pop() {
            if Arc::ptr_eq(&last, &tail) {
                fd.bblocks.blocks.insert(pos + 1, last);
            } else {
                fd.bblocks.blocks.push(last);
            }
        }
    }
    Some((tail, Some(parent)))
}

/// Post-load jump-table recovery for a driver that batch-injected its whole
/// op bank (`Funcdata::inject_raw_ops`), i.e. the linear-lift driver path
/// (HTTPD-MAIN-WARNUNREACH-JTEDGE-0001). Runs exactly the generateOps
/// phase-2 sequence of `Funcdata::followFlow` (funcdata_op.cc:771
/// `flow.generateOps()` — recovery happens there BEFORE `generateBlocks`,
/// flow.cc:792-821) plus the two generateBlocks-tail observables a fused
/// linear load could not produce: the per-entry switch out-edges
/// (collectEdges' BRANCHIND arm, flow.cc:933-957) and the switchOver map
/// (funcdata_op.cc:777-778 `switchOverJumpTables(flow)` ->
/// jumptable.cc:2528).
///
/// Adapter deltas against the oracle sequence, all consequences of the
/// caller's pre-lifted linear bank (the case bodies are already present;
/// the oracle would lift them via `newAddress` + `fallthru`, flow.cc:806-809):
///   * the ops are temporarily moved to the dead list (mark_dead/mark_alive
///     cycle) so `Funcdata::truncatedFlow` — Ghidra's partial-clone source,
///     which reads `obank.beginDead()` — sees the same "raw p-code on the
///     dead list, nothing alive yet" state the oracle has at recovery time;
///   * `newAddress`/`fallthru` are no-ops (every window instruction is
///     already lifted and in the synthesized `visited` map);
///   * block starts carry STARTBASIC (the xref walk's end-state, flow.cc
///     469-477/570-572 — Ghidra marks every block start; the batch inject
///     path never did), so the partial clone reproduces the source block
///     partition in its own generateBlocks;
///   * a table destination with no op in the injected window (outside the
///     symbol span the linear lift covered) cannot resolve; its edge and
///     its table's switchOver are skipped with a warning — the oracle
///     cannot hit this (it lifts every destination in-range).
///
/// Returns the number of newly recovered tables. `Err` propagates the
/// LowlevelError channel exactly as it escapes `recoverJumpTables` ->
/// `generateOps` -> `followFlow` in Ghidra.
// Ghidra: flow.cc:785 FlowInfo::generateOps
pub fn recover_jump_tables_injected(fd: &mut Funcdata) -> crate::error::Result<usize> {
    // Fast no-op guard: nothing to recover (flow.cc:796 `while(!tablelist
    // .empty())` never runs, flow.cc:813/814 are observation-level no-ops
    // without callspecs/tables). Keeps BRANCHIND-less functions byte-
    // identical: no flag writes, no dead/alive churn.
    let has_branchind = fd.obank.iter_alive().any(|op| {
        op.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND
    });
    if !has_branchind {
        return Ok(0);
    }

    // STARTBASIC on every existing block start — the observable end-state
    // of the xref walk the linear path skipped (flow.cc:469-477 marks each
    // visited instruction's first op; 570-572 marks queued branch targets).
    // `clone_op` copies STARTMARK|STARTBASIC (funcdata_op.cc:621-622), so
    // the partial clone's generateBlocks reproduces this block partition.
    for i in 0..fd.bblocks.get_size() {
        if let Some(block) = fd.bblocks.get_block(i) {
            if let Some(first) = block.read().unwrap().first_op() {
                first.0.write().unwrap().flags |= pcodeop_flags::STARTBASIC;
            }
        }
    }

    // Oracle recovery-time lifecycle state: every op on the dead list
    // (Ghidra's newOp allocates there, op.cc:941-948; markAlive happens in
    // splitBasic, flow.cc:1013 — i.e. only AFTER recovery). The batch
    // inject path creates ops alive, so cycle them dead in bank order
    // (= lift order = the deadlist order the follow-flow path has).
    let alive_snapshot: Vec<crate::op::PcodeOpRef> = fd.obank.iter_alive().cloned().collect::<Vec<_>>();
    for op in &alive_snapshot {
        fd.obank.mark_dead(op.clone());
    }

    // Synthesize the `visited` map (flow.hh:77-80) from the dead list: one
    // VisitStat per instruction address, first_seq = the first op of the
    // instruction in bank order. `size` is never consulted on this path —
    // FlowInfo::target only reads it when first_seq is None (the no-op
    // instruction walk, flow.cc:129-130), which cannot occur here.
    let mut visited: std::collections::BTreeMap<u64, VisitStat> =
        std::collections::BTreeMap::new();
    for op in fd.obank.iter_dead() {
        let (addr, seq) = {
            let o = op.0.read().unwrap();
            (o.get_addr().as_u64(), o.start)
        };
        visited
            .entry(addr)
            .or_insert(VisitStat {
                first_seq: Some(seq),
                size: 1,
            });
    }

    let entry = *fd.get_address();
    let mut flow = FlowInfo::from_injected(fd, visited);
    // Seed tablelist with every live BRANCHIND in bank order — the
    // work-list xref_control_flow fills during the walk (flow.cc:321-322
    // pushes each BRANCHIND the fallthru sweep xrefs).
    for op in flow.fd.obank.iter_dead() {
        if op.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND {
            flow.tablelist.push(op.clone());
        }
    }

    // generateOps phase 2 (flow.cc:796-821): recoverJumpTables -> (lift —
    // no-op here) -> checkContainedCall -> checkMultistageJumptables ->
    // notreached refill -> loop while tablelist non-empty.
    //
    // The recovery loop body is FlowInfo::recoverJumpTables
    // (flow.cc:1427-1458) inlined with ONE adapter delta: the partial
    // Funcdata runs on a commentdb-detached Architecture clone. In the
    // oracle the partial shares the source arch (Funcdata(nm,nm,
    // getScopeLocal()->getParent(),...) → shared commentdb), and its
    // "base"-grouped ActionUnreachable (coreaction.cc:5490 — present in
    // every strategy group, "jumptable" included) never fires because the
    // oracle's recovery-time op bank holds only the phase-1 flow-reachable
    // ops — case bodies are lifted by newAddress AFTER recovery
    // (flow.cc:804-809), so the partial has no orphan blocks. The linear
    // bank is pre-lifted, so THIS partial does carry the orphan case bodies
    // and its block removals would leak "Removing unreachable block"
    // warnings into the real function's output through the shared
    // commentdb (both Funcdatas warn at the same entry address). Detaching
    // the commentdb neutralizes exactly that adapter-artifact channel;
    // every other partial surface (loader for the table bytes, types,
    // userops, the per-stage ActionDatabase) is carried by the clone
    // unchanged, and real-fd warnings (truncateIndirectJump et al.) still
    // write through the real arch below.
    let mut notreached: Vec<crate::op::PcodeOpRef> = Vec::new();
    let mut notreachcnt: usize = 0;
    let mut recovered_count = 0usize;
    loop {
        while !flow.tablelist.is_empty() {
            let mut new_tables: Vec<Option<Arc<RwLock<crate::jumptable::JumpTable>>>> =
                Vec::new();
            // flow.cc:1430-1437: the partial label and the shared entry
            // address/size; the arch is the detached clone (adapter note
            // above).
            let op0_addr = flow.tablelist[0].0.read().unwrap().get_addr().as_u64();
            let nm = format!("{}@@jump@{:08x}", flow.fd.get_name(), op0_addr);
            let fd_size = flow.fd.size;
            let mut partial = Funcdata::new(&nm, entry, fd_size);
            partial.display_image_base = flow.fd.display_image_base;
            if let Some(arch) = flow.fd.get_arch() {
                let mut partial_arch = (**arch).clone();
                partial_arch.set_commentdb(std::sync::Arc::new(std::sync::RwLock::new(
                    crate::comment::CommentDatabaseInternal::new(),
                )));
                partial.set_arch(std::sync::Arc::new(partial_arch));
            }
            let flow_state = flow.truncated_state();
            let tablelist_len = flow.tablelist.len();
            // flow.cc:1439-1457: the per-BRANCHIND recovery sweep.
            for i in 0..tablelist_len {
                let op = flow.tablelist[i].clone();
                let mut mode = crate::jumptable::RecoveryMode::Success;
                let jt =
                    flow.fd
                        .recover_jump_table(&mut partial, &op, &mut mode, &flow_state)?;
                match &jt {
                    None => {
                        // flow.cc:1443-1445: unless inlining, treat the
                        // indirect jump as a call/return (real-fd mutation
                        // and real-fd warnings).
                        if !flow.is_flow_for_inline() {
                            eprintln!(
                                "[JUMPTABLE] recovery failed at 0x{:x} mode={:?} → truncate",
                                op.0.read().unwrap().get_addr().as_u64(),
                                mode
                            );
                            flow.truncate_indirect_jump(&op, mode);
                            // Adapter delta (BLOCKSTRUCT-TRUNC-SWITCHEMPTY-0001):
                            // the oracle contract runs truncateIndirectJump
                            // inside generateOps, BEFORE generateBlocks, so
                            // splitBasic's BlockBasic::insert (block.cc:2285-
                            // 2288) sees the post-truncation opcode
                            // (CALLIND/RETURN) and never sets f_switch_out on
                            // the truncated block — ruleBlockSwitch's cc:1652
                            // isSwitchOut gate then rejects the block and
                            // ruleBlockIfNoExit (cc:1481-1512, guard cc:1497)
                            // absorbs it as the no-exit if-clause, which is
                            // why canon prints `if (c) { ...; return; }` with
                            // no switch skeleton. The linear inject path
                            // builds blocks first (build_blocks_from_ops →
                            // insert_op sets SWITCH_OUT while the op is still
                            // BRANCHIND), so the flag is stale here after the
                            // opcode rewrite. Recompute it from the block's
                            // current opcodes to restore the oracle end-state
                            // (same recompute form as the case-dest split,
                            // see split_block_at_case_dest).
                            let parent_block = {
                                let o = op.0.read().unwrap();
                                o.parent.as_ref().and_then(std::sync::Weak::upgrade)
                            };
                            if let Some(parent) = parent_block {
                                let mut w = parent.write().unwrap();
                                if let Some(bb) = w
                                    .as_any_mut()
                                    .downcast_mut::<crate::block::BlockBasic>()
                                {
                                    let still_switch_out = bb.ops.iter().any(|o| {
                                        o.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND
                                    });
                                    if still_switch_out {
                                        bb.set_flags(crate::block::block_flags::SWITCH_OUT);
                                    } else {
                                        bb.clear_flags(crate::block::block_flags::SWITCH_OUT);
                                    }
                                }
                            }
                        }
                    }
                    Some(jt) => {
                        if jt.read().unwrap().is_partial() {
                            // flow.cc:1447-1455.
                            if tablelist_len > 1 && !FlowInfo::is_in_array(&notreached, &op) {
                                notreached.push(op.clone());
                            } else {
                                jt.write().unwrap().mark_complete();
                            }
                        }
                    }
                }
                new_tables.push(jt);
            }
            flow.tablelist.clear();
            for jt in new_tables {
                let Some(jt) = jt else { continue };
                let (num, indirect_addr) = {
                    let jt_rg = jt.read().unwrap();
                    let indirect_addr = jt_rg
                        .get_indirect_op()
                        .map(crate::op::PcodeOpRef)
                        .map(|op| op.0.read().unwrap().get_addr())
                        .unwrap_or(entry);
                    (jt_rg.num_entries(), indirect_addr)
                };
                if num > 0 {
                    eprintln!(
                        "[JUMPTABLE] recovered {} entries from indirect jump at 0x{:x}",
                        num,
                        indirect_addr.as_u64()
                    );
                    recovered_count += 1;
                }
                // flow.cc:804-809: newAddress per entry + fallthru lift —
                // no-op on the pre-lifted linear bank (case bodies exist).
            }
        }
        // flow.cc:813/814 (no-op without resolved callspecs / with no
        // override-marked tables, but kept for sequence parity).
        flow.check_contained_call();
        flow.check_multistage_jumptables();
        // flow.cc:815-818.
        while notreachcnt < notreached.len() {
            flow.tablelist.push(notreached[notreachcnt].clone());
            notreachcnt += 1;
        }
        // hasInject() is false on this path (no xref walk queued CALLOTHER
        // fixups), so flow.cc:819-820's injectPcode is skipped.
        if flow.tablelist.is_empty() {
            break;
        }
    }

    // Restore the inject-path live state: mark every dead-list op alive in
    // list order — the same bulk markAlive splitBasic performs when it
    // integrates ops into blocks (flow.cc:1013). Truncation halts created
    // during recovery were inserted positionally (insert_after_dead), so
    // the restored alivelist keeps SeqNum order.
    let dead_snapshot: Vec<crate::op::PcodeOpRef> = flow.fd.obank.iter_dead().cloned().collect::<Vec<_>>();
    for op in &dead_snapshot {
        flow.fd.obank.mark_alive(op.clone());
    }

    // Ghidra's splitBasic (flow.cc:996-1013) integrates EVERY dead-list op
    // into a basic block when generateBlocks runs; the linear path's blocks
    // predate recovery, so the only parent-less ops are the artificial
    // halts truncate_indirect_jump created via opDeadInsertAfter (flow.cc:
    // 766-767). insert_after_dead placed each immediately after its
    // truncated jump in the dead list, and that CALLIND — not a block
    // terminator — sits at its block's op tail (the original BRANCHIND was
    // the terminator), so each halt is appended right after it: the same
    // block/integration splitBasic produces in the oracle, where the
    // halting RETURN closes the block (canon ap_cfg_closefile: call +
    // `return uVar1;` in one branch).
    for i in 1..dead_snapshot.len() {
        let (halt_parentless, prev_parent) = {
            let halt = dead_snapshot[i].0.read().unwrap();
            let prev = dead_snapshot[i - 1].0.read().unwrap();
            (halt.parent.is_none(), prev.parent.clone())
        };
        if !halt_parentless {
            continue;
        }
        let Some(prev_block) = prev_parent.as_ref().and_then(std::sync::Weak::upgrade) else {
            continue;
        };
        let insert_at = {
            let blk = prev_block.read().unwrap();
            blk.get_ops()
                .iter()
                .position(|op| Arc::ptr_eq(&op.0, &dead_snapshot[i - 1].0))
                .map(|pos| pos + 1)
        };
        let Some(insert_at) = insert_at else { continue };
        prev_block
            .write()
            .unwrap()
            .insert_op(insert_at, dead_snapshot[i].clone());
    }

    // collectEdges' BRANCHIND arm (flow.cc:933-957) against the existing
    // block graph: for every live BRANCHIND's recovered table, one edge
    // per address-table entry in table order, de-duplicated per target op
    // (flow.cc:941-946's setMark run). The oracle lands every destination
    // on a block start via newAddress's STARTBASIC mark + splitBasic; the
    // linear partition predates recovery, so mid-block destinations are
    // split on the spot by split_block_at_case_dest before the edge lands
    // (JTEDGE-FUSED-DEST-SPLIT-0001).
    let mut unlinked_switch: std::collections::BTreeSet<u64> =
        std::collections::BTreeSet::new();
    for op in &dead_snapshot {
        let is_branchind = op.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND;
        if !is_branchind {
            continue;
        }
        let op_addr = op.0.read().unwrap().get_addr();
        let Some(jt_arc) = flow
            .fd
            .jump_tables
            .iter()
            .find(|jt| jt.read().unwrap().get_op_address().as_u64() == op_addr.as_u64())
            .cloned()
        else {
            // Recovery truncated this jump — no table to link (flow.cc:935
            // `jt == NULL` arm: no out-edges from partial-flow analysis).
            continue;
        };
        let switch_block = op
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let Some(switch_block) = switch_block else { continue };
        let entries: Vec<Address> = {
            let jt_rg = jt_arc.read().unwrap();
            (0..jt_rg.num_entries())
                .map(|i| jt_rg.get_address_by_index(i))
                .collect()
        };
        let mut linked_ops: Vec<crate::op::PcodeOpRef> = Vec::new();
        for addr in entries {
            let Some(targ_op) = flow.target(addr) else {
                eprintln!(
                    "[JUMPTABLE] destination 0x{:x} of switch at 0x{:x} has no p-code in the loaded window; edge skipped",
                    addr.as_u64(),
                    op_addr.as_u64()
                );
                unlinked_switch.insert(op_addr.as_u64());
                continue;
            };
            // flow.cc:228-233 + 996-1016: mark the destination op and land
            // it at a block head (no-op when it already is one).
            let Some((targ_block, head_block)) =
                split_block_at_case_dest(&mut flow.fd, &targ_op, &switch_block)
            else {
                continue;
            };
            // flow.cc:941-946: dedup per target op (setMark), in table
            // entry order — post-split each destination op heads its own
            // block, so this is the oracle's op-level dedup.
            if linked_ops.iter().any(|o| Arc::ptr_eq(&o.0, &targ_op.0)) {
                continue;
            }
            linked_ops.push(targ_op.clone());
            flow.fd.bblocks.add_edge(switch_block.clone(), targ_block.clone());
            // The head→tail fall-thru edge (oracle: collectEdges' nextstart
            // arm, flow.cc:952-956). connectBasic links it after the switch
            // edge — the dead-list walk reaches the BRANCHIND before the
            // case bodies — so append it in that order here too.
            if let Some(head_block) = head_block {
                flow.fd.bblocks.add_edge(head_block, targ_block);
            }
        }
    }

    // funcdata_op.cc:777-778: switchOverJumpTables(flow). Per-table error
    // tolerance: a table with a skipped destination cannot map every entry
    // to an out-edge (jumptable.cc:2545-2546 throws "Jumptable destination
    // not linked"), so its switchOver is skipped whole — the switch keeps
    // its case edges and degrades to goto form instead of aborting the
    // load. Fully linked tables (the oracle-invariant case) map exactly.
    let tables: Vec<Arc<RwLock<crate::jumptable::JumpTable>>> =
        flow.fd.jump_tables.clone();
    for jt in &tables {
        let op_addr = jt.read().unwrap().get_op_address().as_u64();
        if unlinked_switch.contains(&op_addr) {
            continue;
        }
        if let Err(err) = jt.write().unwrap().switch_over(&flow) {
            eprintln!(
                "[JUMPTABLE] switchOver skipped for table at 0x{:x}: {}",
                op_addr,
                err.message()
            );
        }
    }
    Ok(recovered_count)
}

// ===================== Injection helpers (RUGRA-GLUE) =====================
// These free functions bridge gaps between Rugra's current types and the
// Ghidra flow.cc call paths. They are file-local to flow.rs because this
// alignment task is constrained to editing src/flow.rs.

/// Resolve the stable callspec owner for an exact call op. The typed Weak on
/// input(0) is the fast path; Funcdata's fallback compares the bound PcodeOp
/// allocation, never an address or vector index.
// RUGRA-GLUE: ANN-B; Rust Arc owner form of FuncCallSpecs::getFspecFromConst plus exact PcodeOp fallback.
fn find_callspec_for_op(
    fd: &Funcdata,
    op: &crate::op::PcodeOpRef,
) -> Option<Arc<RwLock<crate::fspec::FuncCallSpecs>>> {
    fd.get_call_specs_of_op(op)
}

#[cfg(test)]
mod tests {
    /// SQLCENSUS-CHARSCAN-BREAKGUARD-0001 regression lock: the flow-build
    /// end-append clone of `BlockBasic::insert` must set f_switch_out when
    /// the appended op is a BRANCHIND (block.cc:2286-2292 tail — the flag
    /// ActionDoNothing's switch-target guard at block.cc:2604-2613 reads).
    /// The arm was previously omitted on this path, so jumptable dispatch
    /// bblocks built by follow_flow_range carried no flag and do-nothing
    /// removal deleted live switch-case arms whose successor is a join.
    #[test]
    fn test_block_insert_at_end_sets_switch_out_for_branchind() {
        let arch = crate::arch::Architecture::new();
        let mut fd = Funcdata::new("switchout_flag", Address::new(0x1000), 8);
        fd.set_arch(std::sync::Arc::new(arch));
        let block: std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        > = fd.create_new_block();
        // A BRANCHIND op (one 8-byte input varnode, no output — the
        // indirect-jump form SLEIGH emits for `jmp *reg`).
        let op = fd.new_op(1, Address::new(0x1000));
        fd.op_set_opcode(&op, OpCode::CPUI_BRANCHIND);
        let target_vn = fd.vbank.create_constant(8, 0x2000);
        fd.op_set_input(&op, target_vn, 0);
        {
            let rg = block.read().unwrap();
            assert_eq!(
                rg.get_flags() & crate::block::block_flags::SWITCH_OUT,
                0,
                "precondition: fresh block has no f_switch_out"
            );
        }
        let mut prev_order: Option<u32> = None;
        FlowInfo::block_insert_at_end(&block, &op, &mut prev_order);
        {
            let rg = block.read().unwrap();
            assert_ne!(
                rg.get_flags() & crate::block::block_flags::SWITCH_OUT,
                0,
                "BRANCHIND end-append must set f_switch_out (block.cc:2286-2292)"
            );
            assert_eq!(rg.size_out(), 0, "op append alone wires no edges");
        }
        // A non-BRANCHIND append must NOT set the flag (fresh block).
        let block2 = fd.create_new_block();
        let copy = fd.new_op(1, Address::new(0x1004));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        let copy_in = fd.vbank.create_constant(8, 5);
        fd.op_set_input(&copy, copy_in, 0);
        let mut prev_order2: Option<u32> = None;
        FlowInfo::block_insert_at_end(&block2, &copy, &mut prev_order2);
        let rg2 = block2.read().unwrap();
        assert_eq!(
            rg2.get_flags() & crate::block::block_flags::SWITCH_OUT,
            0,
            "COPY append must leave f_switch_out clear"
        );
    }
    use super::*;
    use crate::funcdata::Funcdata;
    use crate::opcodes::OpCode;
    use crate::space::AddressSpace;

    /// A null SLEIGH symbol lookup wrapped in PredefinedJumpSymbols — the
    /// language-instantiated stand-in parseInject requires.
    fn language_ready_injectlib() -> std::sync::Arc<
        std::sync::RwLock<crate::pcodeinject::PcodeInjectLibrary>,
    > {
        use crate::pcodeparse::{PredefinedJumpSymbols, SleighSymbolLookup};
        struct EmptyHost;
        impl SleighSymbolLookup for EmptyHost {
            fn find_symbol(&self, _name: &str) -> Option<crate::pcodeparse::SleighSymbol> {
                None
            }
        }
        let mut lib = crate::pcodeinject::PcodeInjectLibrary::new(0x200);
        lib.set_sleigh_lookup(std::sync::Arc::new(PredefinedJumpSymbols::new(EmptyHost)));
        std::sync::Arc::new(std::sync::RwLock::new(lib))
    }

    /// Register one injected CALLOTHER userop (index 0) whose payload is the
    /// given snippet, mirroring `UserOpManage::manualCallOtherFixup` +
    /// `InjectedUserOp` registration (userop.cc:621-646).
    fn register_injected_userop(
        arch: &mut crate::arch::Architecture,
        lib: &std::sync::Arc<
            std::sync::RwLock<crate::pcodeinject::PcodeInjectLibrary>,
        >,
        snippet: &str,
    ) {
        let injectid = lib
            .write()
            .expect("lock poisoned")
            .manual_call_other_fixup("inject_probe", "out", &["in0".to_string()], snippet)
            .expect("snippet compiles");
        let mut userops = crate::userop::UserOpManage::new();
        let index = userops.register_op(
            "inject_probe".to_string(),
            crate::userop::UserOpType::Injected,
        );
        userops.get_op_mut(index).expect("just registered").inject_id = injectid;
        arch.userops = Some(std::sync::Arc::new(std::sync::RwLock::new(userops)));
        arch.pcodeinjectlib = Some(lib.clone());
    }

    /// Build a CALLOTHER op (index 0, one 4-byte constant operand, output in
    /// the register space) at the given address, mirroring what SLEIGH
    /// emits for a user-defined p-code op.
    fn build_callother_op(fd: &mut Funcdata, addr: Address) -> crate::op::PcodeOpRef {
        let op = fd.new_op(2, addr);
        fd.op_set_opcode(&op, OpCode::CPUI_CALLOTHER);
        let id_vn = fd.vbank.create_constant(4, 0);
        fd.op_set_input(&op, id_vn, 0);
        let operand_vn = fd.vbank.create_constant(4, 0x20);
        fd.op_set_input(&op, operand_vn, 1);
        fd.new_varnode_out(4, Address::new(0x80), &op);
        op
    }

    /// flow.cc:344-348: a CALLOTHER whose userop descriptor is Injected goes
    /// on the injectlist during xrefControlFlow; a non-injected CALLOTHER
    /// and an unregistered index do not.
    #[test]
    fn test_xref_callother_fills_injectlist() {
        let mut arch = crate::arch::Architecture::new();
        let lib = language_ready_injectlib();
        register_injected_userop(&mut arch, &lib, "out = in0;");
        let mut fd = Funcdata::new("xref_probe", Address::new(0x1000), 8);
        fd.set_arch(std::sync::Arc::new(arch));
        let mut lifter = SleighLifter::new();
        let mut flow = FlowInfo::new(&mut fd, &mut lifter, 0x1000, 0x2000);
        let op = build_callother_op(flow.fd, Address::new(0x1000));
        let mut start_basic = true;
        let index = {
            // The CALLOTHER is the only op; xref from its own position.
            flow.fd.obank.dead_id_at(flow.fd.obank.deadlist.len() - 1)
        };
        flow.xref_control_flow(index, &mut start_basic);
        assert_eq!(
            flow.injectlist.len(),
            1,
            "injected CALLOTHER must land on the injectlist"
        );
        assert!(flow.has_inject());

        // A plain (unspecialized) CALLOTHER stays off the list.
        let mut arch2 = crate::arch::Architecture::new();
        let mut userops = crate::userop::UserOpManage::new();
        userops.register_op("plain".to_string(), crate::userop::UserOpType::Unspecialized);
        arch2.userops = Some(std::sync::Arc::new(std::sync::RwLock::new(userops)));
        arch2.pcodeinjectlib = Some(language_ready_injectlib());
        let mut fd2 = Funcdata::new("xref_plain", Address::new(0x1000), 8);
        fd2.set_arch(std::sync::Arc::new(arch2));
        let mut lifter2 = SleighLifter::new();
        let mut flow2 = FlowInfo::new(&mut fd2, &mut lifter2, 0x1000, 0x2000);
        let _op2 = build_callother_op(flow2.fd, Address::new(0x1000));
        let mut sb2 = true;
        let idx2 = flow2.fd.obank.dead_id_at(flow2.fd.obank.deadlist.len() - 1);
        flow2.xref_control_flow(idx2, &mut sb2);
        assert!(
            !flow2.has_inject(),
            "unspecialized CALLOTHER must not enter the injectlist"
        );
        let _ = op;
    }

    /// generateOps wiring (flow.cc:794-795): with a pending injection seeded
    /// before generation, the post-fallthru `hasInject()` gate expands it —
    /// the CALLOTHER is destroyed and replaced by the payload ops placed at
    /// its position.
    #[test]
    fn test_generate_ops_injection_wiring() {
        let image: Vec<u8> = vec![0x31, 0xc0, 0xc3]; // xor eax,eax ; ret
        let entry = 0x1000u64;
        let mut arch = crate::arch::Architecture::new();
        let lib = language_ready_injectlib();
        register_injected_userop(&mut arch, &lib, "out = in0 + 0x10:4;");
        let mut fd = Funcdata::new("inject_e2e", Address::new(entry), image.len() as i32);
        fd.set_arch(std::sync::Arc::new(arch));
        let mut lifter = SleighLifter::new();
        lifter
            .configure_x86_64(&image, entry)
            .expect("SLEIGH configured");
        // Pre-seed the CALLOTHER (fixture-observation hook): the locked
        // x86-64 SLEIGH language declares no user ops, so the machine-lifted
        // path cannot produce one; production flow gets here via
        // xrefControlFlow (flow.cc:344-348).
        let callother = build_callother_op(&mut fd, Address::new(entry));
        let mut flow = FlowInfo::new(&mut fd, &mut lifter, entry, entry + 0x100);
        flow.fixture_queue_inject(&callother);
        flow.generate_ops(Address::new(entry))
            .expect("flow generation succeeds");

        let opcodes: Vec<(OpCode, u64, u32)> = flow
            .fd
            .obank
            .iter_dead()
            .map(|r| {
                let o = r.0.read().expect("op read lock");
                (o.opcode, o.get_addr().as_u64(), o.get_time())
            })
            .collect();
        // The CALLOTHER itself must be gone (opDestroyRaw, flow.cc:1207).
        assert!(
            !opcodes.iter().any(|(c, _, _)| *c == OpCode::CPUI_CALLOTHER),
            "CALLOTHER must be destroyed by injectPcode"
        );
        // The payload's INT_ADD replaced it, carrying the injection base
        // address (cacher.emit passes baseaddr for every injected op).
        let add_index = opcodes
            .iter()
            .position(|(c, _, _)| *c == OpCode::CPUI_INT_ADD)
            .expect("injected INT_ADD present");
        assert_eq!(opcodes[add_index].1, entry);
        // The injected op sits before the machine ops of the first lifted
        // instruction (moveSequenceDead moved it after the CALLOTHER, which
        // preceded them, then the CALLOTHER was destroyed).
        assert_eq!(add_index, 0);
        // InjectContext substitution: INT_ADD input(1) is the 0x10 constant.
        let add_op = flow
            .fd
            .obank
            .dead_head()
            .expect("injected INT_ADD is the dead-chain head")
            .clone();
        {
            let o = add_op.0.read().expect("op read lock");
            assert_eq!(o.inrefs.len(), 2);
            let operand = o.inrefs[0].read().expect("vn read lock");
            assert_eq!((operand.get_offset(), operand.size), (0x20, 4));
            let constant = o.inrefs[1].read().expect("vn read lock");
            assert_eq!((constant.get_offset(), constant.size), (0x10, 4));
            let output = o.output.as_ref().expect("INT_ADD output").read().expect("vn read lock");
            assert_eq!(output.get_space(), AddressSpace::Register);
            assert_eq!(output.get_offset(), 0x80);
        }
        // The injectlist is drained (flow.cc:1354 clear inside injectPcode).
        assert!(!flow.has_inject());
    }
}
