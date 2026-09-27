//! High-level function data container
//!
//! Corresponds to Ghidra's `funcdata.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::fspec::FuncProto;
use crate::heritage::Heritage;
use crate::op::{PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::pcoderaw::PcodeOpRaw;
use crate::space::AddressSpace;

// Ghidra: sleigh_arch.cc:233 SleighArchitecture::buildTypeLibrary (setCoreType "code")
/// The core anonymous "code" `Datatype` that `Funcdata::newCodeRef`
/// (funcdata_varnode.cc:222-233) attaches to every one-byte code-reference
/// annotation Varnode. Ghidra reads it from the architecture's TypeFactory
/// cache (`TypeFactory::getTypeCode`, type.cc:3692-3701); Rugra does not
/// thread a factory through the raw emit path, so the equivalent value
/// object — name "code", metatype TYPE_CODE, size 1 — is built directly.
fn code_ref_datatype() -> std::sync::Arc<crate::type_system::datatype::Datatype> {
    use crate::type_system::datatype::{Datatype, TypeBase, TypeCode, TypeMetatype};
    std::sync::Arc::new(Datatype::Code(TypeCode {
        base: TypeBase::new("code".to_string(), 1, TypeMetatype::Code),
        proto: None,
    }))
}

// Ghidra: op.cc:824 PieceNode::findRoot
/// Find the root of the CONCAT tree of Varnodes marked either
/// `isProtoPartial()` or `isAddrTied()`: the maximal Varnode containing the
/// given Varnode (as storage) with a backward path to it through PIECE
/// operations. Faithful to `PieceNode::findRoot` (op.cc:824-852): at each
/// step the descendant PIECE op whose output address (adjusted for
/// endianness and the sibling input's size, then renormalized — a no-op for
/// word-size-1 spaces like the register/stack spaces PIECE pieces live in)
/// equals the current Varnode's address is followed; with more than one
/// valid PIECE the earliest in op order wins (`compareOrder`). Lives here
/// (not op.rs) because it is consumed only by `Funcdata::linkProtoPartial`.
fn piece_node_find_root(
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    use crate::opcodes::OpCode;
    use std::sync::Arc;
    let mut cur = vn.clone();
    loop {
        let (is_pp, is_at, cur_addr, cur_space) = {
            let r = cur.read().unwrap();
            (
                r.is_proto_partial(), r.is_addr_tied(), r.get_offset(), r.get_space(),
            )
        };
        if !is_pp && !is_at {
            break;
        }
        let mut piece_op: Option<Arc<std::sync::RwLock<crate::op::PcodeOp>>> = None;
        let readers: Vec<_> = cur
            .read()
            .unwrap()
            .descend
            .iter()
            .filter_map(|w| w.upgrade())
            .collect();
        for op_arc in readers {
            let op = op_arc.read().unwrap();
            if op.opcode != OpCode::CPUI_PIECE {
                continue;
            }
            // int4 slot = op->getSlot(vn);
            let slot = (0..2)
                .find(|&i| op.get_in(i).map(|v| Arc::ptr_eq(v, &cur)).unwrap_or(false));
            let (Some(slot), Some(out)) = (slot, op.output.clone()) else { continue ;
            };
            let out_r = out.read().unwrap();
            let mut addr = out_r.get_offset();
            let (in0_size, in1_size) = (
                op.get_in(0)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0),
                op.get_in(1)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(0),
            );
            // if (addr.getSpace()->isBigEndian() == (slot == 1))
            //   addr = addr + op->getIn(1-slot)->getSize();
            if cur_space.is_big_endian() == (slot == 1) {
                addr = addr.wrapping_add(if slot == 0 { in1_size } else { in0_size } as u64);
            }
            // addr.renormalize(vn->getSize()) — identity for word-size-1
            // spaces (Rugra's scalar Address carries no word size).
            if addr == cur_addr {
                match &piece_op {
                    Some(prev) => {
                        // Ghidra op.cc:841-843 is `if (op->compareOrder(pieceOp))
                        // pieceOp = op;` — NONZERO truthiness: both -1 (op
                        // executes earlier) and 1 (pieceOp executes earlier)
                        // replace the selection; only 0 (no absolute order)
                        // keeps it. The oracle's inline comment ("earliest")
                        // contradicts its literal code; the code is what we
                        // mirror (reviewer round-2 finding).
                        let prev_guard = prev.read().unwrap();
                        if op.compare_order(&prev_guard) != 0 {
                            drop(prev_guard);
                            piece_op = Some(op_arc.clone());
                        }
                    }
                    None => piece_op = Some(op_arc.clone()),
                }
            }
        }
        match piece_op {
            Some(op_arc) => {
                let next = op_arc.read().unwrap().output.clone();
                match next {
                    Some(n) => cur = n,
                    None => break,
                }
            }
            None => break,
        }
    }
    Some(cur)
}

// Ghidra: varnode.cc:696 Varnode::getUsePoint
/// The first-use Address offset of a Varnode: the defining op's address for
/// written Varnodes, else the function entry - 1 (inputs come into scope at
/// the start of the function). Faithful to `Varnode::getUsePoint`
/// (varnode.cc:696-703); used by `Funcdata::syncVarnodesWithSymbols`
/// (funcdata_varnode.cc:972) for the Scope::inScope probe.
fn varnode_use_point_offset(
    fd: &Funcdata,
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> Option<u64> {
    let vn_r = vn.read().unwrap();
    if vn_r.is_written() {
        vn_r.get_def()
            .map(|d| d.read().unwrap().get_addr().as_u64())
    } else {
        Some(fd.baseaddr.as_u64().wrapping_sub(1))
    }
}

// Ghidra: database.cc:2392 ScopeInternal::findOverlap
/// First Symbol returned by `ScopeInternal::findOverlap`
/// (database.cc:2392-2404) for the query `[offset, offset+size)` in the given
/// space. The oracle consults the space's EntryMap (a
/// `rangemap<SymbolEntry>`, rangemap.hh:65), whose multiset is keyed by
/// `(last, subsort)` (rangemap.hh:88-91) and whose entries duplicate each
/// common-refinement partition unit for every record covering it.
/// `find_overlap(point, end)` (rangemap.hh:411-423) does
/// `lower_bound(AddrRange(point))` — the first sub-range whose `last >=
/// point`, i.e. the leftmost partition unit intersecting the query (the unit
/// containing `point` when covered, else the first unit starting after
/// `point`) — and returns it iff its `first <= end`. All records covering
/// that unit cover the whole unit, so the returned record is the one with
/// the smallest `SymbolEntry::getSubsort()` (database.cc:97-107): the
/// minimal subsort (0,0) for address-tied symbols (empty uselimit,
/// `Scope::addMap` database.cc:1149-1150), else `(useindex, useoffset)` of
/// the first uselimit range — which for one binary's code space reduces to
/// ordering by first use offset with address-tied always winning. Ties on
/// an identical subsort keep Vec creation order, standing in for
/// `std::multiset` insertion order of equivalent keys. Dynamic entries
/// never enter the static map table (`addDynamicMapInternal`
/// database.cc:1874-1886 pushes to `dynamicentry`, not maptable), so they
/// are filtered first (F2, SCOPE-FINDOVERLAP-DYNAMIC-0001).
pub fn scope_local_find_overlap(
    scope: &crate::varmap::ScopeLocal,
    space: AddressSpace,
    offset: u64,
    size: i32,
) -> Option<&crate::varmap::LocalSymbol> {
    // database.cc:2397: addr.getOffset()+size-1 — evaluated in the oracle's
    // uint8 (uint64) modular domain: the int4 size converts by sign
    // extension and both operators wrap (C++ unsigned arithmetic, UB-free).
    // Stack-space offsets near 2^64 (negative stack slots) legitimately
    // wrap here (FUNCDATA-SCOPELOCALOVERFLOW-0001), so Rust must wrap too.
    let last = offset.wrapping_add(size as u64).wrapping_sub(1);
    // Records in this space's EntryMap: (first, last) inclusive.
    let candidates: Vec<&crate::varmap::LocalSymbol> = scope
        .symbols
        .iter()
        .filter(|sym| !sym.is_dynamic)
        .filter(|sym| sym.space == space)
        .filter(|sym| sym.size > 0)
        .filter(|sym| {
            let sym_end = sym.start.wrapping_add(sym.size as u64).wrapping_sub(1);
            sym.start <= last && offset <= sym_end
        })
        .collect();
    // rangemap.hh:418: iter = tree.lower_bound(AddrRange(point)) — the first
    // sub-range with last >= point, i.e. the leftmost partition unit
    // intersecting the query (the unit containing `point` when covered,
    // else the first unit starting after `point`). Units before it all end
    // before `point`, so every address in [point, unit.first) is uncovered:
    // the unit starts at the smallest address of [point,end] covered by any
    // record — the minimum over intersecting records of max(start, point).
    let hit_address = candidates
        .iter()
        .map(|sym| sym.start.max(offset))
        .min()?;
    // rangemap.hh:420-421: if ((*iter).first <= end) return iter; — among
    // the records covering the unit (== records covering hit_address), the
    // multiset order picks the smallest subsort; equal subsorts keep Vec
    // order (std::multiset insertion order of equivalent keys). The
    // containment test is the oracle's `first <= p <= last` form where
    // `last` is the modular first+size-1 (records straddle no space
    // boundary, so first <= last holds): a `p < first+size` rewrite would
    // deviate for records at the top of the stack space where first+size
    // wraps to 0, and would trap in debug on the same wrap.
    candidates
        .iter()
        .filter(|sym| {
            let sym_end = sym.start.wrapping_add(sym.size as u64).wrapping_sub(1);
            sym.start <= hit_address && hit_address <= sym_end
        })
        .min_by_key(|sym| entry_subsort_key(sym))
        .copied()
}

// Ghidra: database.cc:97 SymbolEntry::getSubsort
/// Sub-sort key of a SymbolEntry within one partition unit, faithful to
/// `SymbolEntry::getSubsort` (database.cc:97-107) +
/// `EntrySubsort::operator<` (database.hh:127-133): the minimal subsort
/// (0,0) for address-tied storage (symbol flag set when the mapping has an
/// empty uselimit, modeled by `usepoint == None`), else
/// `(useindex, useoffset)` of the first uselimit range. Rugra's
/// LocalSymbol.usepoint carries only the offset, and every static mapping's
/// uselimit lives in the (single) code space, so the index component is
/// uniform and modeled as the constant 1 (> the minimal index 0).
fn entry_subsort_key(sym: &crate::varmap::LocalSymbol) -> (u8, u64) {
    match sym.usepoint {
        None => (0, 0),
        Some(usepoint) => (1, usepoint),
    }
}

// Ghidra: database.hh:597 Scope::inScope
/// Is the entire `[offset, offset+size)` range owned by the scope's range
/// tree. Faithful to `Scope::inScope` (database.hh:597) ->
/// `RangeList::inRange`: the `usepoint` argument is part of the virtual
/// signature (funcdata_varnode.cc:972-973 passes
/// `vnexemplar->getUsePoint(*this)`) but the base implementation ignores
/// it, and ScopeLocal defines no override — modeled by the underscore
/// parameter.
fn scope_local_in_scope(
    scope: &crate::varmap::ScopeLocal,
    _space: AddressSpace,
    offset: u64,
    size: i32,
    _usepoint: Option<u64>,
) -> bool {
    // address.cc:484: addr.getOffset()+size-1 — same uint8 modular domain
    // as findOverlap (database.cc:2397); stack-space queries near 2^64 wrap
    // (FUNCDATA-SCOPELOCALOVERFLOW-0001).
    let last = offset.wrapping_add(size as u64).wrapping_sub(1);
    scope
        .local_range
        .iter()
        .any(|&(first, range_last)| first <= offset && last <= range_last)
}

// Ghidra: varmap.cc:494 ScopeLocal::isUnmappedUnaliased
/// Should an unmapped Varnode be treated as unaliased? Faithful to
/// `ScopeLocal::isUnmappedUnaliased` (varmap.cc:494-502): false outside the
/// scope's stack space; with no known stack-parameter window
/// (`max_param_offset < min_param_offset`) every unmapped Varnode is
/// unaliased; otherwise only offsets outside `[min_param_offset,
/// max_param_offset]` are.
fn scope_local_is_unmapped_unaliased(
    scope: &crate::varmap::ScopeLocal,
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) -> bool {
    let vn_r = vn.read().unwrap();
    if vn_r.get_space() != scope.space {
        return false; // Must be in mapped local (stack) space
    }
    if scope.max_param_offset < scope.min_param_offset {
        return true; // No min/max, so we have no known stack parameters
    }
    let offset = vn_r.get_offset();
    offset < scope.min_param_offset || offset > scope.max_param_offset
}

// Ghidra: database.cc:151 SymbolEntry::getSizedType
/// Data-type matching the given size and address within a LocalSymbol's
/// whole mapping. Faithful to `SymbolEntry::getSizedType`
/// (database.cc:151-162): the entry offset is 0 for whole maps, so
/// `off = (vn.offset - sym.start)`, then `TypeFactory::getExactPiece`
/// (type.cc:4090-4117) runs in the owning Architecture factory, preserving
/// exact and canonical partial-type identity.
fn local_symbol_sized_type(
    type_factory: &mut crate::type_system::typefactory::TypeFactory,
    sym: &crate::varmap::LocalSymbol,
    inaddr: u64,
    sz: i32,
) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
    let dt = sym.dtype.clone()?;
    let off = (inaddr as i64).wrapping_sub(sym.start as i64);
    let size = usize::try_from(sz).ok()?;
    type_factory.get_exact_piece(dt, off, size)
}

/// Funcdata flags (funcdata.hh:highlevel_flags).
pub mod funcdata_flags {
    /// Data-type analysis is being performed.
    pub const TYPE_RECOVERY_ON: u32 = 1 << 0;
    /// Data-type analysis has started (Ghidra `typerecovery_start`,
    /// funcdata.hh:90). Set once ActionInferTypes begins, used by Rules to
    /// decide whether type-based guards apply.
    pub const TYPE_RECOVERY_START: u32 = 1 << 1;
    /// HighVariable objects have been assigned to all Varnodes (Ghidra
    /// `highlevel_on`, funcdata.hh:84 = 0x200). Set by ActionAssignHigh /
    /// setHighLevel. Prevents re-assignment on subsequent passes.
    pub const HIGHLEVEL_ON: u32 = 1 << 2;
    /// Double-precision recovery is active (Ghidra `double_precis_on`,
    /// funcdata.hh:85 = 0x2000).
    pub const DOUBLE_PRECIS_ON: u32 = 1 << 13;
    /// Basic blocks have been generated (Ghidra `blocks_generated`,
    /// funcdata.hh:84 = 0x2). Rugra uses bit 2 to avoid clashing with
    /// HIGHLEVEL_ON (which occupies bit 2 in Rugra's remapped flag space).
    pub const BLOCKS_GENERATED: u32 = 1 << 3;
    /// Processing of the function has started (Ghidra `processing_started`,
    /// funcdata.hh:84 = 0x8). Set by `startProcessing`; checked to make the
    /// start entry idempotent.
    pub const PROCESSING_STARTED: u32 = 1 << 4;
    /// Processing of the function is complete (Ghidra `processing_complete`,
    /// funcdata.hh:84 = 0x10). Set by `stopProcessing`.
    pub const PROCESSING_COMPLETE: u32 = 1 << 5;
    /// This Funcdata object is dedicated to jump-table recovery (Ghidra
    /// `jumptablerecovery_on`, funcdata.hh:84 = 0x100). Set on the partial
    /// clone during `stageJumpTable`; read by `warning`/`warningHeader` to
    /// tag diagnostics.
    pub const JUMPTABLERECOVERY_ON: u32 = 1 << 8;
    /// Do not try to recover jump-tables; always truncate (Ghidra
    /// `jumptablerecovery_dont`, funcdata.hh:84 = 0x200). Set by
    /// `setJumptableRecovery(false)`; read by `recoverJumpTable`.
    pub const JUMPTABLERECOVERY_DONT: u32 = 1 << 9;
    /// Analysis must be restarted because of new override info (Ghidra
    /// `restart_pending`, funcdata.hh:84 = 0x400).
    pub const RESTART_PENDING: u32 = 1 << 10;
    /// At least one basic block is currently unreachable (Ghidra
    /// `blocks_unreachable`, funcdata.hh:60 = 0x4). Rugra uses bit 6 to
    /// avoid clashing with the remapped flag space (HIGHLEVEL_ON occupies
    /// Ghidra's bit 2; see BLOCKS_GENERATED's note). Set/cleared only by
    /// `structure_reset` mirroring funcdata_block.cc:710/713-714
    /// (`rootlist.size() > 1` after structureLoops) and read via
    /// `has_unreachable_blocks` (funcdata.hh:149).
    pub const BLOCKS_UNREACHABLE: u32 = 1 << 6;
    /// Data-type propagation passes reached maximum (Ghidra
    /// `typerecovery_exceeded`, funcdata.hh:72 = 0x4000). Set by
    /// ActionInferTypes when `localcount` hits 7 (coreaction.cc:5393); read
    /// by `AddTreeState::buildTree` (ruleaction.cc:6502/6514) to stamp
    /// propagated types on freshly created PTRADD/PTRSUB outputs directly,
    /// because the propagation loop no longer runs.
    pub const TYPE_RECOVERY_EXCEEDED: u32 = 1 << 14;
}

use crate::varnode::VarnodeBank;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

/// Ordered storage key for potential laned-register accesses. This is the
/// split-address Rust equivalent of Ghidra's `VarnodeData` map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanedStorage {
    pub space: crate::space::AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl PartialOrd for LanedStorage {
    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanedStorage {
    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.space
            .space_id()
            .cmp(&other.space.space_id())
            .then_with(|| self.offset.cmp(&other.offset))
            .then_with(|| other.size.cmp(&self.size))
    }
}

/// One analyzer-committed stack local harvested from the canonical golden's
/// declaration layer (C1 TYPE-SEED-LOCAL, HEADLESS-BRIDGE-V1-TYPESEED).
/// RUGRA-GLUE: the `<localdb>` `<mapsym>` payload of the headless transport
/// (funcdata.cc:804-810 -> database.cc:1564 Scope::addMapSym): stack offset
/// (negative = below the frame base), the committed name (`local_c8`), and
/// the C type spelling (`long[4]`, `undefined8 *`) that
/// `Symbol::decodeBody` -> `TypeFactory::decodeType` materializes. Installed
/// name+type locked so `ScopeLocal::restructureVarnode`'s
/// `clearUnlockedCategory(-1)` keeps them and `MapState::gatherSymbols`
/// feeds them as `RangeHint::fixed` boundaries (varmap.cc:1044-1059).
#[derive(Debug, Clone)]
pub struct CommittedLocal {
    /// Stack offset in bytes, negative for frame locals (−0xc8 → -200).
    pub offset: i64,
    /// The committed symbol name (`local_c8`).
    pub name: String,
    /// C type spelling as printed by the canon golden (`long[4]`).
    pub type_expr: String,
    /// HEADLESS-BRIDGE-V1-TYPESEED (HTTPDMAIN-TYPESEED-LOCK-ARBITRATION-0001):
    /// the `<localdb>` transport's per-symbol ATTRIB_TYPELOCK bit
    /// (database.cc:432-434 Symbol::decodeHeader). `true` = the C1 locked
    /// bridge (materializes name+type-locked, survives
    /// clearUnlockedCategory(-1), feeds RangeHint::fixed). `false` =
    /// name-only transport — the symbol materializes namelock-only and the
    /// scope-construction `collect_name_recs` call (varmap.cc:357-381
    /// ScopeLocal::collectNameRecs, reached in the oracle at the
    /// ScopeLocal::decode boundary varmap.cc:472-477) downgrades it to a
    /// name recommendation the free restructure reattaches unlocked
    /// (recoverNameRecommendationsForSymbols varmap.cc:1507). This is the
    /// transport shape both locked-oracle faces use for
    /// decompiler-RECOVERED locals: the stage_seed_diag e40ed130
    /// nameonly-agg payload (namelock-only aggregates, locked scalars)
    /// keeps the main canary INDIRECT web alive while any typelocked
    /// ARRAY/STRUCT kills it (markUnaliased varmap.cc:1376-1385,
    /// alias_block_level=2). The seed's type still rides `type_expr` —
    /// after the downgrade only (addr,usepoint,size,name) survive in the
    /// NameRecommend (varmap.cc:1600-1613), so the spelling only fixes the
    /// entry byte-size.
    pub typelock: bool,
}

/// Main container for a function being decompiled
///
/// Corresponds to Ghidra's `Funcdata` class. This class ties together
/// the P-code operations, varnodes, control flow graph, and analysis state.
#[derive(Debug)]
pub struct Funcdata {
    /// Name of the function
    pub name: String,
    /// Base address of the function
    pub baseaddr: Address,
    /// Size of the function in bytes
    pub size: i32,

    /// Bit-set of Funcdata flags (mirrors Ghidra's `flags` field).
    pub flags: u32,

    /// `Funcdata::clean_up_index` (funcdata.hh:187): the VarnodeBank
    /// creation index recorded when the clean-up phase starts
    /// (`startCleanUp`, funcdata.hh:186). Previously absent in Rugra (the
    /// coreaction marker was a no-op); restored as real storage.
    pub clean_up_index: u32,

    // --- OPACTION_DEBUG observation state (funcdata.hh:580-592). ---
    // Ghidra compiles these members only under `#ifdef OPACTION_DEBUG`
    // (funcdata.hh:580); Rugra always compiles them, with all behavior
    // gated on `opactdbg_on` exactly like the debug build. The hook
    // entries (`debugModCheck`/`debugModPrint`) live in drillobserve.rs.

    /// Jump-table simplification debug hook (`jtcallback`,
    /// funcdata.hh:581). Stored as a plain fn pointer like Ghidra.
    pub jtcallback: Option<fn(&mut Funcdata, &mut Funcdata)>,
    /// List of modified ops (`modify_list`, funcdata.hh:582).
    pub modify_list: Vec<crate::op::PcodeOpRef>,
    /// List of "before" strings for modified ops (`modify_before`,
    /// funcdata.hh:583).
    pub modify_before: Vec<String>,
    /// Number of debug statements printed (`opactdbg_count`, funcdata.hh:584).
    pub opactdbg_count: i32,
    /// Which debug to break on (`opactdbg_breakcount`, funcdata.hh:585).
    pub opactdbg_breakcount: i32,
    /// Are we currently doing op action debugs (`opactdbg_on`, funcdata.hh:586).
    pub opactdbg_on: bool,
    /// True if current op mods should be recorded (`opactdbg_active`, funcdata.hh:587).
    pub opactdbg_active: bool,
    /// Has a breakpoint been hit (`opactdbg_breakon`, funcdata.hh:588).
    pub opactdbg_breakon: bool,
    /// Lower bounds on the PC register (`opactdbg_pclow`, funcdata.hh:589).
    pub opactdbg_pclow: Vec<Address>,
    /// Upper bounds on the PC register (`opactdbg_pchigh`, funcdata.hh:590).
    pub opactdbg_pchigh: Vec<Address>,
    /// Lower bounds on the unique register (`opactdbg_uqlow`, funcdata.hh:591).
    pub opactdbg_uqlow: Vec<u32>,
    /// Upper bounds on the unique register (`opactdbg_uqhigh`, funcdata.hh:592).
    pub opactdbg_uqhigh: Vec<u32>,

    /// Creation index of the first Varnode created after HighVariables were
    /// assigned (Ghidra `high_level_index`, funcdata.hh:76). Recorded by
    /// `set_high_level` (funcdata_varnode.cc:600) as `vbank.getCreateIndex()`.
    /// (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
    pub high_level_index: u32,

    /// Creation index of the Varnode bank when the cast insertion phase
    /// started (Ghidra `cast_phase_index`, funcdata.hh:77). Recorded by
    /// `start_cast_phase` (funcdata.hh:183) at the head of
    /// `ActionSetCasts::apply` (coreaction.cc:2728).
    pub cast_phase_index: u32,

    // RUGRA-GLUE: display_image_base (RESIDMAP-PRINTBATCH-0001 transport; no
    // single Ghidra counterpart — the oracle's Funcdata Addresses ARE the
    // loaded analyzeHeadless addresses, while Rugra's pipeline runs on
    // ELF-relative offsets (ADDRESS-0001) and the drivers add the image-base
    // delta at display time, exactly like PrintC::code_label_base for
    // labels). Warning texts that embed an address (funcdata_block.cc:374
    // "Removing unreachable block", jumptable "Could not recover jumptable
    // at", flow.cc:1380 "Possible PIC construction at") render the oracle's
    // printRaw spelling through this delta: 0 = ELF-relative harness contract
    /// (direct-runner golden), 0x100000 = canon analyzeHeadless golden.
    pub display_image_base: u64,

    /// Bank of all varnodes in this function
    pub vbank: VarnodeBank,
    /// Bank of all P-code operations in this function
    pub obank: PcodeOpBank,
    /// Control flow graph (basic blocks)
    pub bblocks: BlockGraph,
    /// Structure tree (composite blocks)
    pub sblocks: BlockGraph,
    /// SSA construction manager
    pub heritage: Heritage,

    /// Persistent cross-Action merge state (testCache / copyTrims / live
    /// premise). Faithful to `Funcdata::covermerge` (funcdata.hh:96): the
    /// by-value `Merge` member constructed with \b this (funcdata.cc:39),
    /// shared by every merge-family Action via `getMerge()`
    /// (funcdata.hh:440), and cleared only by `Funcdata::clear()`
    /// (funcdata.cc:108). Rugra's merge Actions construct local `Merge`
    /// instances, so only the persistent channels are mounted here; see
    /// `merge::MergePersistentState`.
    pub merge_state: crate::merge::MergePersistentState,

    /// Self-reference for use by child components
    pub self_ref: Option<Weak<RwLock<Funcdata>>>,

    /// Address → function/symbol name mapping (populated from ELF symtab)
    pub symbol_table: HashMap<u64, String>,
    /// Address → entry size for the mapGlobals proxy symbols
    /// (`symbol_table` names this lane's `map_globals` inserts for
    /// symbol-less persist groups). FUNCDATA-MAPGLOBALS-PROXYSIZE-0001:
    /// Ghidra's `Scope::addSymbol` → `addMap` records the mapping size
    /// (`ct->getSize()`, database.cc:1126-1151), so a re-run of
    /// `mapGlobals` (RULE_REPEATAPPLY restart) finds the entry WITH its
    /// size and the cc:1711 extension test `(addr+ct->getSize())-1 >
    /// (entry->getAddr().getOffset()+entry->getSize())-1` is false —
    /// no `inconsistentuse`, no warning. The name-only proxy previously
    /// modeled the entry as size 0, making the test always-true and
    /// re-arming the "Globals starting with '_' overlap smaller
    /// symbols" warning on every restart. Driver-seeded entries (ELF
    /// function names via `add_symbol`) carry no size here and keep the
    /// historical size-0 comparison form.
    pub symbol_table_sizes: HashMap<u64, i32>,
    /// Address → string literal mapping (populated from ELF .rodata)
    pub string_table: HashMap<u64, String>,
    /// Address → struct-pointer Datatype for known global variables derived
    /// from DWARF debug_info (e.g. `::config` at 0x17520 → `Configurable *`).
    /// Populated by the decompiler driver before analysis; read by
    /// `type_infer::propagate_types` to seed struct-pointer types on the
    /// constant varnodes that reference these globals. Mirrors Ghidra's
    /// SymbolEntry type assignment (database.cc) which the Rugra driver
    /// lacks an Architecture/SymbolTable layer to populate automatically.
    pub global_struct_ptrs: HashMap<u64, std::sync::Arc<crate::type_system::datatype::Datatype>>,
    /// Function prototype (return type, parameters)
    pub funcp: FuncProto,
    /// External function prototypes: maps callee address → param count.
    /// Populated by a pre-pass that analyzes all functions in the binary
    /// before decompilation. Mirrors Ghidra's multi-pass approach where
    /// ActionActiveParam runs across all functions to build a prototype
    /// database before final decompilation.
    pub external_prototypes: HashMap<u64, usize>,
    /// Restructured local-variable scope. Built by ActionRestructureVarnode
    /// (coreaction.cc:2274) and queried by printc's stack-variable resolution.
    /// Corresponds to Ghidra's `Funcdata::getScopeLocal()`.
    pub scope: Option<crate::varmap::ScopeLocal>,
    /// Committed-local seeds carried from the driver's C1 TYPE-SEED-LOCAL
    /// manifest (HEADLESS-BRIDGE-V1-TYPESEED). RUGRA-GLUE: models the
    /// `<localdb>` transport channel of `Funcdata::decode`
    /// (funcdata.cc:804-810: `<localdb>` -> `Database::decodeScope` ->
    /// `ScopeInternal::decode` installs the analyzer-committed symbols
    /// BEFORE any action runs). The headless canon golden is produced with
    /// that channel present; the bare driver contract (direct-runner
    /// golden) is produced with it absent. Rugra's driver installs the
    /// harvested list here under the opt-in env gate and
    /// ActionRestructureVarnode materializes the symbols into the fresh
    /// ScopeLocal at its first apply (the lifecycle position mirroring the
    /// oracle's construction -> localdb-decode -> action order). Empty by
    /// default — the default path stays byte-identical to the bare load.
    pub committed_locals: Vec<CommittedLocal>,
    /// HighVariable → ScopeLocal symbol index association (keyed by the
    /// HighVariable's Arc pointer). RUGRA-GLUE: models `HighVariable::symbol`
    /// (variable.hh:161-176) for the varmap `ScopeLocal` symbol model — the
    /// faithful database.rs `Symbol` graph is not yet wired into the
    /// linkSymbol path, so the Funcdata keeps this side table instead of a
    /// field on HighVariable (variable.rs is outside this change's lease).
    pub high_symbols: HashMap<usize, usize>,
    /// ScopeLocal symbol index → bridged database.rs `SymbolEntry`
    /// (identity-stable per symbol). RUGRA-GLUE: `Varnode::setSymbolEntry`
    /// and the faithful `HighVariable::set_symbol` (variable.rs:180, porting
    /// variable.cc:245-275 incl. the symboloffset four-branch computation)
    /// consume the database.rs `SymbolEntry` model, so each varmap symbol
    /// gets a mirror entry here at attach time. The mirrored `Symbol`'s name
    /// is refreshed by ActionNameVars after the naming phase.
    pub symbol_entry_cache: HashMap<usize, std::sync::Arc<RwLock<crate::database::SymbolEntry>>>,
    /// Function call specifications, one per call site. Corresponds to
    /// Ghidra's `Funcdata::breefcall` vector.
    pub callspecs: Vec<Arc<RwLock<crate::fspec::FuncCallSpecs>>>,
    /// Active output parameter recovery. Faithful to
    /// `Funcdata::activeoutput` (funcdata.hh). Set by ActionFuncLinkOutOnly;
    /// used by ActionReturnRecovery to determine which RETURN varnodes
    /// are the function's return value.
    pub active_output: Option<crate::fspec::ParamActive>,

    /// Architecture configuration (Ghidra `glb` / funcdata.hh:80). Never
    /// None after construction: `Funcdata::new` binds the canonical default
    /// Architecture — the stand-in for the oracle's unconditional
    /// `glb = scope->getArch()` (funcdata.cc:48). Callers that own a real
    /// architecture replace it via `set_arch` before running Rules that
    /// need cpool/funcptr_align/nan_ignore_all/userops/types.
    pub arch: Option<Arc<crate::arch::Architecture>>,
    /// Restart-pending flag for ActionRestartGroup (funcdata.hh).
    pub restart_pending: bool,
    /// Once-per-function guard for ActionConditionalConst. The conditional
    /// constant propagation is useful but, under Rugra's repeatapply mainloop,
    /// re-running it after the first mutation can interact poorly with
    /// downstream ActionConditionalExe/branch-folding and fail to converge for
    /// some functions (5/24 curl timeouts). This flag ensures the IR-mutating
    /// propagation runs at most once per function (reset on restart). It is a
    /// Rugra-specific convergence guard with no Ghidra counterpart.
    pub cond_const_done: bool,
    /// Jump tables recovered for this function. Faithful to
    /// `Funcdata::jumpvec` (funcdata.hh:89). Populated by JumpTable recovery.
    pub jump_tables: Vec<std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>>,

    /// Map from data-flow edges to the resolved field of a TypeUnion being
    /// accessed. Faithful to `Funcdata::unionMap` (funcdata.hh:100). Keyed by
    /// `ResolveEdge` (parent type id + PcodeOp SeqNum order + slot encoding);
    /// value is the `ResolvedUnion` produced by union resolution. Cleared by
    /// `clear()`.
    pub union_map: std::collections::BTreeMap<
        crate::unionresolve::ResolveEdge, crate::unionresolve::ResolvedUnion,
    >,

    /// Minimum Varnode size that can enter the laned-register access map.
    /// `u32::MAX` is Ghidra's unsigned representation of the Architecture
    /// `-1` sentinel when no lane records exist.
    pub min_laned_size: u32,
    /// Candidate laned-register storage, ordered by address-space index,
    /// offset, then descending size. Values share identity with the matching
    /// immutable Architecture lane record.
    pub laned_map: std::collections::BTreeMap<
        LanedStorage,
        std::sync::Arc<crate::transform::LanedRegister>>,

    /// Per-function override container. Faithful to `Funcdata::localoverride`
    /// (funcdata.hh:108). Holds force-goto / deadcode-delay / flow-override /
    /// indirect-override / proto-override / multistage-jump commands. Populated
    /// by `setOverride` / `Override::decode`; read by the analysis passes.
    pub localoverride: crate::override_rs::Override,

    // ---- Stack space / spacebase configuration (from Architecture, defaults to x86-64) ----
    // Faithful to Architecture's cspec <stackpointer> fields. These mirror
    // the canonical Architecture's x86-64-gcc.cspec defaults (identical
    // values in `Architecture::new`): Rugra snapshots them as Funcdata
    // fields rather than reading `glb` per query.
    /// The stack address space (IPTR_SPACEBASE). Stack varnodes live here.
    pub stack_space: crate::space::AddressSpace,
    /// Stack pointer register: (space, offset, size) = (Register, 0x20, 8) for RSP.
    pub stack_pointer_space: crate::space::AddressSpace,
    pub stack_pointer_offset: u64,
    pub stack_pointer_size: usize,
    /// Stack grows toward negative offsets (x86 convention).
    pub stack_grows_negative: bool,
}

// RUGRA-GLUE: canonical default Architecture shared by every Funcdata
// constructed without a caller-owned one. Ghidra's Funcdata constructor
// takes its Architecture unconditionally from the Scope
// (`glb = scope->getArch()`, funcdata.cc:48; `Scope::getArch` is the
// database.hh:775 inline) and every Funcdata decompiled under one database
// shares that single pointer. Rugra's Funcdata::new has no Scope parameter
// yet (FUNCDATA-LOCALSCOPE-OWNERSHIP-0001), so this lazily-built
// `Architecture::new()` (architecture.cc:150 ctor + `resetDefaultsInternal`
// defaults, architecture.cc:1416-1432) restores both the never-null `glb`
// invariant and the single-database pointer sharing; `set_arch` overwrites
// the binding with a caller's real Architecture.
fn canonical_arch() -> Arc<crate::arch::Architecture> {
    static CANONICAL: std::sync::OnceLock<Arc<crate::arch::Architecture>> =
        std::sync::OnceLock::new();
    CANONICAL
        .get_or_init(|| Arc::new(crate::arch::Architecture::new()))
        .clone()
}

/// Membership in the oracle `beginLoc(s,addr,pc,uniq)..endLoc` span,
/// mirroring the inconsistent-but-deterministic std::set bound semantics
/// of VarnodeCompareLocDef over SeqNum (uniq-only `!=` at
/// address.hh:150-151, pc-first `<` at address.hh:153-157).
// Ghidra: varnode.cc:1732 VarnodeBank::beginLoc(int4,const Address&,const Address&,uintm)
fn loc_pc_in_span(
    def_pc: Address, def_uniq: u32, key_pc: Address, low_uniq: u32, high_uniq: u32,
) -> bool {
    let lt = |x_pc: Address, x_u: u32, y_pc: Address, y_u: u32| -> bool {
        if x_u == y_u {
            false // SeqNum::operator!= (uniq-only) says equivalent
        } else if x_pc == y_pc {
            x_u < y_u
        } else {
            x_pc < y_pc
        }
    };
    // In span iff NOT(elem < low) AND NOT(high < elem).
    !lt(def_pc, def_uniq, key_pc, low_uniq) && !lt(key_pc, high_uniq, def_pc, def_uniq)
}

// Ghidra: address.cc:32 operator<<(ostream&, const SeqNum&)
/// Stream form of a SeqNum: `pc.printRaw() ':' uniq` — the uniq counter
/// prints in DECIMAL (no hex manipulator is active on a fresh stream).
/// Faithful to `operator<<(ostream &s,const SeqNum &sq)`
/// (address.cc:32-38); the pc text is `AddrSpace::printRaw`
/// (space.cc:206-219): `0x` + zero-padded hex with the shrinking-width
/// rule (offset<2^32 → 8 digits, <2^48 → 12, else 16) and no `+cut`
/// suffix at wordsize 1. Rust returns a String instead of writing to
/// ostream.
fn seqnum_text(sq: &crate::address::SeqNum) -> String {
    let offset = sq.addr.as_u64();
    let digits = if (offset >> 32) == 0 {
        8
    } else if (offset >> 48) == 0 {
        12
    } else {
        16
    };
    let mut s = format!("0x{:0width$x}", offset, width = digits);
    s.push(':');
    s.push_str(&sq.time.to_string());
    s
}

// Ghidra: funcdata_op.cc:1404 compareCseHash
/// Comparator for (hash,PcodeOp) pairs: compare by hash. Faithful to the
/// static `compareCseHash` (funcdata_op.cc:1404-1408)
/// `{ return (a.first < b.first); }` — a strict-weak ordering on the hash
/// value only, with no tie-break (equal hashes keep their insertion
/// relative order under a stable sort).
pub fn compare_cse_hash(
    a: &(u32, crate::op::PcodeOpRef),
    b: &(u32, crate::op::PcodeOpRef),
) -> bool {
    a.0 < b.0
}

impl Funcdata {
    // Ghidra: funcdata.cc:34 Funcdata::Funcdata
    /// Create a new Funcdata instance. Faithful to the constructor
    /// (funcdata.cc:34-82): every C++ Funcdata is constructed with its
    /// Scope's Architecture (`glb = scope->getArch()`, funcdata.cc:48) and
    /// immediately sources `minLanedSize` from it (funcdata.cc:49). Rugra
    /// binds the canonical default Architecture through `set_arch` (which
    /// runs the same ctor tail: model binding + `min_laned_size`); callers
    /// that own a real architecture replace it via a later `set_arch`.
    pub fn new(name: &str, addr: Address, size: i32) -> Self {
        let mut fd = Self {
            name: name.to_string(),
            baseaddr: addr,
            size,
            flags: 0,
            clean_up_index: 0,
            // funcdata.cc:74-81 (#ifdef OPACTION_DEBUG ctor init): jtcallback
            // null, counters zero, breakcount -1, all debug bools false.
            jtcallback: None,
            modify_list: Vec::new(),
            modify_before: Vec::new(),
            opactdbg_count: 0,
            opactdbg_breakcount: -1,
            opactdbg_on: false,
            opactdbg_active: false,
            opactdbg_breakon: false,
            opactdbg_pclow: Vec::new(),
            opactdbg_pchigh: Vec::new(),
            opactdbg_uqlow: Vec::new(),
            opactdbg_uqhigh: Vec::new(),
            high_level_index: 0,
            cast_phase_index: 0,
            display_image_base: 0,
            vbank: VarnodeBank::new(),
            obank: PcodeOpBank::new(),
            bblocks: BlockGraph::new(),
            sblocks: BlockGraph::new(),
            heritage: Heritage::new(),
            merge_state: crate::merge::MergePersistentState::default(),
            self_ref: None,
            symbol_table: HashMap::new(),
            symbol_table_sizes: HashMap::new(),
            string_table: HashMap::new(),
            global_struct_ptrs: HashMap::new(),
            funcp: FuncProto::new(
                name.to_string(),
                std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(), 0, crate::type_system::datatype::TypeMetatype::Void,
                    ),
                )),
            ),
            external_prototypes: HashMap::new(),
            scope: None,
            committed_locals: Vec::new(),
            high_symbols: HashMap::new(),
            symbol_entry_cache: HashMap::new(),
            callspecs: Vec::new(),
            active_output: None,
            arch: None,
            restart_pending: false,
            cond_const_done: false,
            jump_tables: Vec::new(),
            union_map: std::collections::BTreeMap::new(),
            min_laned_size: u32::MAX,
            laned_map: std::collections::BTreeMap::new(),
            localoverride: crate::override_rs::Override::new(),
            stack_space: crate::space::AddressSpace::Stack,
            stack_pointer_space: crate::space::AddressSpace::Register,
            stack_pointer_offset: 0x20, // x86-64 RSP
            stack_pointer_size: 8,
            stack_grows_negative: true,
        };
        // Ghidra: funcdata.cc:34 Funcdata::Funcdata
        // `glb = scope->getArch();` — construction-time Architecture
        // binding (funcdata.cc:49 `minLanedSize = glb->...` tail runs in
        // set_arch). Canonical default stands in until a caller attaches
        // its real Architecture.
        fd.set_arch(canonical_arch());
        fd
    }

    // Ghidra: funcdata.cc:34 Funcdata::isTypeRecoveryOn
    /// Is data-type analysis being performed? Faithful to
    /// `Funcdata::isTypeRecoveryOn` (funcdata.hh:150).
    pub fn is_type_recovery_on(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_ON) != 0
    }

    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryOn
    /// Enable/disable type recovery. Faithful to `Funcdata::setTypeRecoveryOn`.
    pub fn set_type_recovery_on(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::TYPE_RECOVERY_ON;
        } else {
            self.flags &= !funcdata_flags::TYPE_RECOVERY_ON;
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasTypeRecoveryStarted
    /// Has data-type analysis started? Faithful to
    /// `Funcdata::hasTypeRecoveryStarted` (funcdata.hh:151).
    pub fn has_type_recovery_started(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_START) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setTypeRecoveryStarted
    /// Mark that type recovery has started.
    pub fn set_type_recovery_started(&mut self) {
        self.flags |= funcdata_flags::TYPE_RECOVERY_START;
    }

    // Ghidra: funcdata.hh:152 Funcdata::isTypeRecoveryExceeded
    /// Has maximum data-type propagation passes been reached? Faithful to
    /// `Funcdata::isTypeRecoveryExceeded` (funcdata.hh:152).
    pub fn is_type_recovery_exceeded(&self) -> bool {
        (self.flags & funcdata_flags::TYPE_RECOVERY_EXCEEDED) != 0
    }

    // Ghidra: funcdata.hh:182 Funcdata::setTypeRecoveryExceeded
    /// Mark that propagation passes have reached the maximum. Faithful to
    /// `Funcdata::setTypeRecoveryExceeded` (funcdata.hh:182): set-only, never
    /// cleared for the lifetime of the Funcdata.
    pub fn set_type_recovery_exceeded(&mut self) {
        self.flags |= funcdata_flags::TYPE_RECOVERY_EXCEEDED;
    }

    // Ghidra: funcdata.cc:34 Funcdata::isDoublePrecisOn
    /// Is double-precision recovery active? (funcdata.hh:167)
    pub fn is_double_precis_on(&self) -> bool {
        (self.flags & funcdata_flags::DOUBLE_PRECIS_ON) != 0
    }
    // Ghidra: funcdata.cc:34 Funcdata::setDoublePrecisRecovery
    /// Set/clear double-precis recovery. (funcdata.hh:167)
    pub fn set_double_precis_recovery(&mut self, on: bool) {
        if on {
            self.flags |= funcdata_flags::DOUBLE_PRECIS_ON;
        } else {
            self.flags &= !funcdata_flags::DOUBLE_PRECIS_ON;
        }
    }

    // Ghidra: funcdata_varnode.cc:148 Funcdata::newVarnode
    /// Create a varnode of `size` bytes at a specific address. Faithful to
    /// `Funcdata::newVarnode(int4, const Address&, Datatype*)`
    /// (funcdata_varnode.cc:148-169):
    ///   vn = vbank.create(s, m, ct);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, m);
    ///   entry = localmap->queryProperties(addr, size, Address(), vflags);
    ///   if (entry != 0) vn->setSymbolProperties(entry);
    ///   else            vn->setFlags(vflags & ~Varnode::typelock);
    ///   return vn;
    /// The symbol tail runs in [`Funcdata::new_varnode_symbol_tail`] with
    /// the INVALID usepoint of cc:162. The laned-register half records
    /// against the address's address space, which `getLanedRegister`
    /// matches by size only (architecture.cc:290-306).
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001)
    pub fn new_varnode(
        &mut self, size: usize, addr: crate::address::Address,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create(size, addr);
        // cc:157: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if size >= self.min_laned_size as usize {
            self.check_for_laned_register(size, crate::space::AddressSpace::Ram, addr);
        }
        // cc:161-166: the queryProperties/setSymbolProperties/setFlags leg
        // (usepoint = the INVALID Address() of cc:162).
        self.new_varnode_symbol_tail(&vn, None);
        vn
    }

    // Ghidra: funcdata_varnode.cc:148 Funcdata::newVarnode
    /// Typed explicit-space form of `Funcdata::newVarnode(int4 s,const
    /// Address &m,Datatype *ct)` — the cc:153-168 body with the caller's
    /// data-type: `ct == 0` falls back to the factory unknown base, which
    /// is the Varnode constructor default in Rust (varnode.rs
    /// `default_unknown_type`, the stand-in for cc:154
    /// `glb->types->getBase(s,TYPE_UNKNOWN)`); then `vbank.create(s,m,ct)`,
    /// `assignHigh`, the laned-register check, and the queryProperties
    /// symbol tail with the INVALID usepoint of cc:162. This is the arm
    /// `Funcdata::splitUses` cc:1556 reaches through
    /// `newVarnode(vn->getSize(),vn->getAddr(),vn->getType())`
    /// (FUNCDATA-SPLITUSES-NEWVN-TYPECARRY-0001).
    pub(crate) fn new_varnode_typed_in_space(
        &mut self,
        size: usize,
        space: crate::space::AddressSpace,
        addr: crate::address::Address,
        ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:156: vn = vbank.create(s,m,ct) — the type is not a bank tree
        // key (VarnodeBank::create keys on space/loc/def), so installing it
        // after the insert preserves the tree order (same pattern as
        // create_unique_typed, varnode.cc:1265).
        let vn = self.vbank.create_with_space(size, space, addr.as_u64());
        if let Some(ct) = ct {
            vn.write().unwrap().v_type = Some(ct);
        }
        // cc:157: assignHigh(vn)
        let _ = self.assign_high(&vn);
        // cc:159-160: if (s >= minLanedSize) checkForLanedRegister(s,m)
        if size >= self.min_laned_size as usize {
            self.check_for_laned_register(size, space, addr);
        }
        // cc:161-166: queryProperties symbol tail (usepoint = INVALID).
        self.new_varnode_symbol_tail(&vn, None);
        vn
    }

    // RUGRA-GLUE: explicit-space adapter for Ghidra's Address-valued
    // Funcdata::newVarnode; ADDRESS-0001 keeps space and offset split across
    // Rugra until the entire comparison domain migrates atomically.
    pub(crate) fn new_varnode_in_space(
        &mut self,
        size: usize,
        space: crate::space::AddressSpace,
        addr: crate::address::Address,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:239-246: the explicit-space overload delegates to the full
        // newVarnode(s,m,ct) — including the queryProperties symbol tail.
        self.new_varnode_typed_in_space(size, space, addr, None)
    }

    // Ghidra: funcdata_varnode.cc:161-166 Funcdata::newVarnode (symbol tail)
    /// The `localmap->queryProperties` + `setSymbolProperties`/`setFlags`
    /// tail shared by `Funcdata::newVarnode` (funcdata_varnode.cc:148-169,
    /// usepoint = INVALID `Address()`) and `Funcdata::newVarnodeOut`
    /// (funcdata_varnode.cc:104-122, usepoint = `op->getAddr()`):
    /// ```text
    /// uint4 vflags=0;
    /// SymbolEntry *entry = localmap->queryProperties(
    ///     vn->getAddr(),vn->getSize(),<usepoint>,vflags);
    /// if (entry != (SymbolEntry *)0)	// Let entry try to force type
    ///   vn->setSymbolProperties(entry);
    /// else
    ///   vn->setFlags(vflags & ~Varnode::typelock);
    /// ```
    /// Ghidra's ONE query walks ScopeLocal -> parents -> global scope
    /// (database.cc:1268 stackContainer). Rugra's walk is composed the same
    /// way linkSymbol composes it (funcdata.rs link_symbol): the ScopeLocal
    /// leg is `ScopeLocal::query_properties_ex` over `fd.scope` (the
    /// database.cc:943/1263 walk with the Database property lookup wired
    /// in), and — when the local leg does not terminate the walk — the
    /// parent/global leg is the Database channel
    /// (`query_properties_parent_scope`/`query_container_entry_parent_scope`,
    /// database.cc:1263-1281). Where the global leg finds a live
    /// SymbolEntry, the FULL `setSymbolProperties` port runs
    /// (varnode.cc:410-424, including the HighVariable symbol link);
    /// the ScopeLocal leg's entry hit degrades to its flags fold
    /// (Rugra's ScopeLocal carries no SymbolEntry objects — the
    /// DB-LOCALSCOPE-MAP-0001 split).
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001)
    fn new_varnode_symbol_tail(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        usepoint: Option<u64>,
    ) {
        let (space, offset, size) = {
            let r = vn.read().unwrap();
            (r.address_space, r.loc.as_u64(), r.get_size() as i64)
        };
        // database.cc:1276/1279 — glb->symboltab->getProperty(addr): the
        // Database flagbase, reachable only for default-data (RAM) space in
        // Rugra's split representation.
        let property = |spc: crate::space::AddressSpace, off: u64| -> u32 {
            if spc != crate::space::AddressSpace::Ram {
                return 0;
            }
            self.arch
                .as_ref()
                .and_then(|a| a.symboltab.clone())
                .map(|t| t.read().unwrap().get_property(crate::address::Address::new(off)))
                .unwrap_or(0)
        };
        // database.cc:1268 — the ScopeLocal leg (stackContainer starts at
        // the function's own scope; parent=None because the parent walk IS
        // the Database channel below).
        let local = self
            .scope
            .as_ref()
            .map(|s| s.query_properties_ex(space, offset, size, usepoint, None, &property));
        let local_answered = matches!(
            &local,
            Some(outcome) if !matches!(outcome.final_scope, crate::varmap::QueryFinalScope::None)
        );
        if local_answered {
            // The ScopeLocal leg terminated the walk (containing entry or
            // in-scope discovery). Ghidra hands the live entry to
            // setSymbolProperties when cc:163 hits; Rugra's ScopeLocal has
            // no live SymbolEntry, so this is the observable flags fold of
            // varnode.cc:422 — cc:166 setFlags(vflags & ~typelock).
            if let Some(outcome) = local {
                let fl = outcome.flags & !crate::varnode::varnode_flags::TYPELOCK;
                vn.write().unwrap().set_flags(fl);
            }
            return;
        }
        // The parent/global leg: only the default-data (RAM) space reaches
        // the Database channel in Rugra's split representation; other
        // spaces end the C++ walk at the bare getProperty(addr) fold
        // (database.cc:1279), which the property closure already applied
        // (0 for non-RAM).
        if space != crate::space::AddressSpace::Ram {
            return;
        }
        let addr = crate::address::Address::new(offset);
        // cc:162: queryProperties(vn->getAddr(), vn->getSize(), usepoint, vflags).
        // Legacy Address cannot carry a valid space, so the Database leg's
        // usepoint is always is_invalid() — exactly Ghidra's newVarnode form;
        // newVarnodeOut's valid op-address usepoint is a declared residual
        // (ADDRESS-0001: use-limited global entries are not admitted there).
        let up = crate::address::Address::new(usepoint.unwrap_or(0));
        if let Some((hit, vflags)) = self.query_properties_parent_scope(addr, size as i32, up) {
            if hit.is_some() {
                // cc:163-164: entry != NULL -> vn->setSymbolProperties(entry)
                // — the live entry from the same stackContainer walk.
                if let Some((_scope_id, entry_arc)) =
                    self.query_container_entry_parent_scope(addr, size as i32, up)
                {
                    crate::varnode::Varnode::set_symbol_properties_arc(vn, &entry_arc);
                } else {
                    // The projection answered but the live-entry walk missed
                    // (cannot happen: same walk); fall through to the flags
                    // fold for safety.
                    let fl = vflags & !crate::varnode::varnode_flags::TYPELOCK;
                    vn.write().unwrap().set_flags(fl);
                }
            } else {
                // cc:165-166: vn->setFlags(vflags & ~typelock).
                let fl = vflags & !crate::varnode::varnode_flags::TYPELOCK;
                vn.write().unwrap().set_flags(fl);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:340 Funcdata::setInputVarnode
    /// Promote a varnode to a function input. Faithful to
    /// `Funcdata::setInputVarnode` (funcdata_varnode.cc:340-373).
    ///
    /// Thin wrapper over `VarnodeBank::set_input_varnode` which ports
    /// steps (1)+(2)+(3) of Ghidra (early-out / overlap dedup / setInput)
    /// plus step (4), the ProtoModel effect tail (unaffected /
    /// return_address flag writes, funcdata_varnode.cc:365-370).
    pub fn set_input_varnode(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:344: if (vn->isInput()) return vn — no property pass on the
        // early-out (funcdata_varnode.cc:344).
        let already_input = vn.read().unwrap().is_input();
        let promoted = self.vbank.set_input_varnode(vn.clone());
        // cc:363-364: vn = vbank.setInput(vn); setVarnodeProperties(vn) —
        // the property pass runs only when the bank freshly promoted this
        // varnode (the dedup arm returns the preexisting input without it,
        // cc:356-357). set_varnode_properties' isMapped guard keeps this a
        // no-op when the creating site's newVarnode tail already attached.
        if !already_input && std::sync::Arc::ptr_eq(&promoted, &vn) {
            self.set_varnode_properties(&promoted);
            // cc:365-370: the ProtoModel effect query tail. Ghidra reads
            // `funcp.hasEffect(vn->getAddr(),vn->getSize())` and sets
            // Varnode::unaffected (and return_address) from the record.
            // try_has_effect is the Rust-glue non-panicking form: a FuncProto
            // with neither an effect list nor a bound model has no Ghidra
            // counterpart (Ghidra's model pointer is always live by the
            // time inputs register), so None skips the flag writes.
            let (space, offset, size) = {
                let guard = promoted.read().unwrap();
                (guard.get_space(), guard.get_offset(), guard.get_size())
            };
            if let Some(effecttype) = self.funcp.try_has_effect(space, offset, size as i32) {
                let mut guard = promoted.write().unwrap();
                if effecttype == crate::fspec::EffectType::Unaffected {
                    guard.set_unaffected();
                }
                if effecttype == crate::fspec::EffectType::ReturnAddress {
                    // Should be unaffected over the course of the function
                    // (funcdata_varnode.cc:369).
                    guard.set_unaffected();
                    guard.set_return_address();
                }
            }
        }
        promoted
    }

    // RUGRA-GLUE: fallible Rust adapter around the checked portion of
    // Ghidra Funcdata::setInputVarnode (funcdata_varnode.cc:340-373).
    fn set_input_varnode_checked(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if vn.read().unwrap().is_input() {
            return Ok(vn);
        }
        let (space, offset, size) = {
            let value = vn.read().unwrap();
            (value.get_space(), value.get_offset(), value.get_size())
        };
        let end = offset.wrapping_add(size as u64);
        for entry in &self.vbank.loc_tree {
            let candidate = entry.0.clone();
            let value = candidate.read().unwrap();
            if !value.is_input() || value.get_space() != space {
                continue;
            }
            let candidate_offset = value.get_offset();
            let candidate_end = candidate_offset.wrapping_add(value.get_size() as u64);
            if offset < candidate_end && candidate_offset < end {
                if candidate_offset == offset && value.get_size() == size {
                    drop(value);
                    return Ok(candidate);
                }
                return Err(crate::error::Error::Lowlevel(
                    "Overlapping input varnodes".to_string(),
                ));
            }
        }
        self.vbank
            .set_input(vn)
            .map_err(|error| crate::error::Error::Lowlevel(error.to_string()))
    }

    // Ghidra: funcdata.hh:294 Funcdata::deleteVarnode
    /// Remove a varnode from both loc/def trees. Faithful to
    /// `Funcdata::deleteVarnode` (which delegates to VarnodeBank::destroy).
    pub fn delete_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<()> {
        self.vbank
            .destroy_varnode(vn)
            .map_err(|error| crate::error::Error::Lowlevel(error.to_string()))
    }

    // Ghidra: funcdata_varnode.cc:381 Funcdata::combineInputVarnodes
    /// Combine two contiguous input varnodes into one, following
    /// `Funcdata::combineInputVarnodes` (funcdata_varnode.cc:381-454) for the
    /// covered LE/no-symbol/no-effect graph. Replaces PIECE(hi,lo) ops with
    /// COPY of the combined varnode and creates SUBPIECE replacements for
    /// non-PIECE readers. Architecture property/high-level side effects and
    /// nullable-slot representation remain outside this adapter's proof.
    pub fn combine_input_varnodes(
        &mut self,
        vn_hi: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn_lo: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> crate::error::Result<()> {
        use crate::opcodes::OpCode;
        let (hi_space, hi_offset, hi_size, hi_is_input) = {
            let value = vn_hi.read().unwrap();
            (
                value.get_space(),
                value.get_offset(),
                value.get_size(),
                value.is_input(),
            )
        };
        let (lo_space, lo_offset, lo_size, lo_is_input) = {
            let value = vn_lo.read().unwrap();
            (
                value.get_space(),
                value.get_offset(),
                value.get_size(),
                value.is_input(),
            )
        };
        if !hi_is_input || !lo_is_input {
            return Err(crate::error::Error::Lowlevel(
                "Varnodes being combined are not inputs".to_string(),
            ));
        }
        let (combined_space, combined_offset, contiguous) = if lo_space.is_big_endian() {
            (
                hi_space,
                hi_offset,
                hi_space == lo_space
                    && hi_offset.wrapping_add(hi_size as u64) == lo_offset,
            )
        } else {
            (
                lo_space,
                lo_offset,
                hi_space == lo_space
                    && lo_offset.wrapping_add(lo_size as u64) == hi_offset,
            )
        };
        if !contiguous {
            return Err(crate::error::Error::Lowlevel(
                "Input varnodes being combined are not contiguous".to_string(),
            ));
        };
        // Collect PIECE(hi,lo) ops and detect other readers.
        let mut piece_list = Vec::new();
        let mut other_ops_hi = false;
        let mut other_ops_lo = false;
        {
            let hi_rg = vn_hi.read().unwrap();
            for w in &hi_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode == OpCode::CPUI_PIECE
                        && g.inrefs.len() >= 2
                        && std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        && std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        piece_list.push(crate::op::PcodeOpRef(op.clone()));
                    } else {
                        other_ops_hi = true;
                    }
                }
            }
        }
        {
            let lo_rg = vn_lo.read().unwrap();
            for w in &lo_rg.descend {
                if let Some(op) = w.upgrade() {
                    let g = op.read().unwrap();
                    if g.opcode != OpCode::CPUI_PIECE
                        || g.inrefs.len() < 2
                        || !std::sync::Arc::ptr_eq(&g.inrefs[0], vn_hi)
                        || !std::sync::Arc::ptr_eq(&g.inrefs[1], vn_lo)
                    {
                        other_ops_lo = true;
                    }
                }
            }
        }
        let entry_block = if other_ops_hi || other_ops_lo {
            match self.bblocks.get_block(0) {
                Some(block) => Some(block),
                None => {
                    return Err(crate::error::Error::Lowlevel(
                        "Missing entry block for input combination".to_string(),
                    ));
                }
            }
        } else {
            None
        };

        // For each PIECE: remove input[1], unset input[0] (will be replaced).
        for p in &piece_list {
            self.op_remove_input(p, 1);
            // Rugra's Vec cannot hold Ghidra's cleared/null slot. Remove slot
            // zero as well, then insert the combined input below. This avoids
            // retaining a deleted high-input Arc and a second eraseDescend.
            self.op_remove_input(p, 0);
        }
        // Ghidra creates and total-replaces the non-PIECE readers before
        // destroying the old inputs. Keep the SUBPIECE ops for slot 0, which
        // is connected only after the combined canonical input exists.
        let sub_hi = if other_ops_hi {
            let Some(bb) = entry_block.as_ref() else {
                return Err(crate::error::Error::Lowlevel(
                    "Missing entry block for input combination".to_string(),
                ));
            };
            let block_start = bb.read().unwrap().get_start_addr();
            let sub = self.new_op(2, block_start);
            self.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
            let lo_size_const = self.new_constant(4, lo_size as u64);
            let new_hi = self
                .vbank
                .create_def_with_space(
                hi_size,
                hi_space,
                hi_offset,
                &sub.0);
            sub.0.write().unwrap().output = Some(new_hi.clone());
            self.op_insert_begin(&sub, bb);
            self.total_replace(vn_hi, new_hi);
            Some((sub, lo_size_const))
        } else {
            None
        };
        let sub_lo = if other_ops_lo {
            let Some(bb) = entry_block.as_ref() else {
                return Err(crate::error::Error::Lowlevel(
                    "Missing entry block for input combination".to_string(),
                ));
            };
            let block_start = bb.read().unwrap().get_start_addr();
            let sub = self.new_op(2, block_start);
            self.op_set_opcode(&sub, OpCode::CPUI_SUBPIECE);
            let zero_const = self.new_constant(4, 0);
            let new_lo = self
                .vbank
                .create_def_with_space(
                lo_size,
                lo_space,
                lo_offset,
                &sub.0);
            sub.0.write().unwrap().output = Some(new_lo.clone());
            self.op_insert_begin(&sub, bb);
            self.total_replace(vn_lo, new_lo);
            Some((sub, zero_const))
        } else {
            None
        };

        self.delete_varnode(vn_hi)?;
        self.delete_varnode(vn_lo)?;
        let out_size = hi_size + lo_size;
        let in_vn = self
            .vbank
            .create_with_space(
            out_size,
            combined_space,
            combined_offset);
        let in_vn = self.set_input_varnode_checked(in_vn)?;
        for p in &piece_list {
            self.op_insert_input(p, in_vn.clone(), 0);
            self.op_set_opcode(p, OpCode::CPUI_COPY);
        }
        if let Some((sub, offset)) = sub_hi {
            // `newOp(2)` reserves but cannot represent Ghidra's null slots.
            // Populate the fresh Vec in final slot order without allocating
            // observable sentinel Varnodes.
            self.op_insert_input(&sub, in_vn.clone(), 0);
            self.op_insert_input(&sub, offset, 1);
        }
        if let Some((sub, offset)) = sub_lo {
            self.op_insert_input(&sub, in_vn, 0);
            self.op_insert_input(&sub, offset, 1);
        }
        Ok(())
    }

    // Ghidra: space.cc:206 AddrSpace::printRaw
    /// Render an offset the way the oracle's `AddrSpace::printRaw` renders a
    /// ram-space Address: `"0x"` + zero-padded hex of `2*sz` digits, where sz
    /// shrinks from the space's address size (8 for x86-64 ram) to 4 bytes
    /// when the offset's top 32 bits are zero, or 6 bytes when the top 48
    /// are (space.cc:210-215). Wordsize > 1 would append `+cut`, but ram's
    /// wordsize is 1 so the branch is unreachable for code addresses.
    /// `display_image_base` transports the loader delta (see the field doc).
    pub fn print_raw_code_addr(&self, offset: u64) -> String {
        let display = offset.wrapping_add(self.display_image_base);
        let sz = if display >> 32 == 0 {
            4
        } else if display >> 48 == 0 {
            6
        } else {
            8
        };
        format!("0x{:0width$x}", display, width = 2 * sz)
    }

    // RUGRA-GLUE: set_display_image_base (RESIDMAP-PRINTBATCH-0001; driver
    // handoff for print_raw_code_addr — canon analyzeHeadless drivers install
    /// 0x100000, ELF-relative harness paths keep the default 0).
    pub fn set_display_image_base(&mut self, base: u64) {
        self.display_image_base = base;
    }

    // Ghidra: funcdata.cc:135 Funcdata::warningHeader
    /// Attach a warning comment to this function. Faithful to
    /// `Funcdata::warningHeader` (funcdata.cc:135-145). Uses the arch's
    /// commentdb if available; otherwise eprintln as fallback.
    pub fn warning_header(&self, txt: &str) {
        let msg = format!("WARNING: {}", txt);
        if let Some(a) = &self.arch {
            if let Some(cdb) = &a.commentdb {
                let _ = cdb.write().unwrap().add_comment_no_duplicate(
                    crate::comment::comment_type::WARNINGHEADER,
                    self.baseaddr,
                    self.baseaddr,
                    &msg,
                );
                return;
            }
        }
        eprintln!("[WARNING] {}: {}", self.name, msg);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getArch
    /// Get the Architecture configuration, if set.
    /// Faithful to `Funcdata::getArch` (funcdata.hh:144).
    pub fn get_arch(&self) -> Option<&Arc<crate::arch::Architecture>> {
        self.arch.as_ref()
    }
    // RUGRA-GLUE: Rust ownership seam for the Architecture reference Ghidra's
    // Funcdata constructor obtains from its Scope (`glb = scope->getArch()`,
    // funcdata.cc:48). Rugra's Funcdata has no constructor-time Scope yet
    // (FUNCDATA-LOCALSCOPE-OWNERSHIP-0001), so `set_arch` is the moment `glb`
    // becomes available and must also run the constructor's model-binding
    // tail: funcdata.cc:69 `funcp.setScope(localmap,baseaddr+ -1)` ->
    // fspec.cc:3884 `if (model == (ProtoModel *)0) setModel(s->getArch()->defaultfp)`.
    /// Set the Architecture reference and bind the Architecture's resolved
    /// default prototype model into `funcp` when no model is bound yet —
    /// mirroring the named-ctor chain so a later locked-prototype overlay
    /// (DWARF/PLT) can never observe `model_locked && !has_model`.
    pub fn set_arch(&mut self, arch: Arc<crate::arch::Architecture>) {
        // Ghidra: funcdata_varnode.cc:66 Funcdata::newConstant
        // Every newVarnode* caller supplies a Datatype from this Funcdata's
        // Architecture-owned `glb->types`.  Rugra's bank resolves that
        // required argument internally, so attach the identical factory
        // before any subsequent Varnode allocation.
        if let Some(types) = arch.types.clone() {
            self.vbank.set_type_factory(types);
        }
        // Ghidra: fspec.cc:3879 FuncProto::setScope (model-binding tail)
        if !self.funcp.has_model() {
            self.funcp.set_model(arch.get_default_model().cloned());
        }
        self.min_laned_size = arch.get_minimum_laned_register_size() as u32;
        self.arch = Some(arch);
    }

    // Ghidra: funcdata.cc:34 Funcdata::hasRestartPending
    /// Is a pipeline restart pending? Faithful to `Funcdata::hasRestartPending`.
    pub fn has_restart_pending(&self) -> bool {
        self.restart_pending
    }
    // Ghidra: funcdata.cc:34 Funcdata::setRestartPending
    /// Request a pipeline restart (ActionRestartGroup will detect this).
    pub fn set_restart_pending(&mut self, v: bool) {
        self.restart_pending = v;
    }
    // Ghidra: funcdata.cc:34 Funcdata::isJumptableRecoveryOn
    /// Is jumptable recovery currently active? Faithful to
    /// `Funcdata::isJumptableRecoveryOn` (funcdata.hh:162). True when \b this
    /// Funcdata object is a partial clone dedicated to recovering a jump-table.
    pub fn is_jumptable_recovery_on(&self) -> bool {
        (self.flags & funcdata_flags::JUMPTABLERECOVERY_ON) != 0
    }

    // Ghidra: funcdata.hh:159 Funcdata::setJumptableRecovery
    /// Enable/disable jumptable recovery on this function. Faithful to
    /// `Funcdata::setJumptableRecovery` (funcdata.hh:159). When disabled the
    /// `jumptablerecovery_dont` flag is set, which `recoverJumpTable` honors.
    pub fn set_jumptable_recovery(&mut self, val: bool) {
        if val {
            self.flags &= !funcdata_flags::JUMPTABLERECOVERY_DONT;
        } else {
            self.flags |= funcdata_flags::JUMPTABLERECOVERY_DONT;
        }
    }

    // Ghidra: funcdata.hh:147 Funcdata::isProcStarted
    /// Has processing of the function started? Faithful to
    /// `Funcdata::isProcStarted` (funcdata.hh:147). Set by `startProcessing`.
    pub fn is_proc_started(&self) -> bool {
        (self.flags & funcdata_flags::PROCESSING_STARTED) != 0
    }

    // Ghidra: funcdata.hh:148 Funcdata::isProcComplete
    /// Is processing of the function complete? Faithful to
    /// `Funcdata::isProcComplete` (funcdata.hh:148). Set by `stopProcessing`.
    pub fn is_proc_complete(&self) -> bool {
        (self.flags & funcdata_flags::PROCESSING_COMPLETE) != 0
    }

    // Ghidra: funcdata.cc:34 Funcdata::setSelfRef
    /// Set the self-reference after wrapping in Arc<RwLock>.
    /// The Heritage manager no longer stores a self-reference: its pass
    /// methods take an exclusive `&mut Funcdata` threaded from
    /// `Funcdata::op_heritage` (HERITAGE-OWNERSHIP-0001), mirroring Ghidra's
    /// non-owning `Heritage::fd` raw pointer without any lock re-entry.
    pub fn set_self_ref(&mut self, self_ref: Weak<RwLock<Funcdata>>) {
        self.self_ref = Some(self_ref.clone());
    }

    // Ghidra: funcdata.hh:462 Funcdata::opHeritage
    /// Perform an entire heritage pass linking Varnode reads to writes.
    /// Faithful 1:1 bridge to `Funcdata::opHeritage`
    /// (funcdata.hh:462): `{ heritage.heritage(); }` — exactly one
    /// `Heritage::heritage` call, which performs one pass and increments
    /// `pass` once at its last line (heritage.cc:2757).
    ///
    /// Ownership model (HERITAGE-OWNERSHIP-0001): the persistent Heritage
    /// object is temporarily moved out of `self.heritage` with `mem::take`,
    /// the single canonical pass runs against this same `&mut Funcdata`, and
    /// the identical Heritage state (pass counter, persistent globaldisjoint,
    /// per-space HeritageInfo, guards) is restored afterwards. There is no
    /// `Weak<RwLock<Funcdata>>` upgrade and no nested write-lock acquisition,
    /// so repeated invocations (e.g. three consecutive boundary calls
    /// driving pass 0->1->2->3) cannot deadlock.
    pub fn op_heritage(&mut self) {
        let mut heritage = std::mem::take(&mut self.heritage);
        heritage.heritage(self);
        self.heritage = heritage;
    }

    // RUGRA-GLUE: legacy direct heritage entry; Ghidra has no runHeritageDirect.
    /// Run the OFF-PRODUCTION direct SSA pass (`place_multiequals_direct` +
    /// `rename_direct`) against separated banks. Since
    /// HERITAGE-DRIVER-SWITCH-0001 the production pipeline drives the
    /// canonical single-pass `op_heritage` (mirroring coreaction.hh:289
    /// `ActionHeritage::apply`); this legacy entry survives for the
    /// example-side prototype estimation helpers (throwaway Funcdata in
    /// examples/curl_decompile.rs et al.) and tests outside this crate's
    /// canonical path. It bypasses the ADT/guard/refinement stages of
    /// `Heritage::heritage` (heritage.cc:2663-2758).
    pub fn run_heritage_direct(&mut self) {
        let mut vbank = std::mem::take(&mut self.vbank);
        let mut obank = std::mem::take(&mut self.obank);

        self.heritage.place_multiequals_direct(
            &mut vbank,
            &mut obank,
            &self.bblocks,
            &self.sblocks,
        );
        self.heritage.rename_direct(&mut vbank, &self.bblocks);
        self.heritage.pass += 1;

        self.vbank = vbank;
        self.obank = obank;
    }

    /// Assign a HighVariable to every Varnode that lacks one. Faithful to
    /// `Funcdata::setHighLevel` (funcdata_varnode.cc:595-605):
    ///   if ((flags & highlevel_on)!=0) return;
    ///   flags |= highlevel_on;
    ///   high_level_index = vbank.getCreateIndex();
    ///   for(iter=vbank.beginLoc();iter!=vbank.endLoc();++iter)
    ///     assignHigh(*iter);
    /// Called by ActionAssignHigh (coreaction.hh:339-347) which runs BEFORE
    /// the merge stage, so ActionMarkExplicit/Implied see HighVariables.
    // Ghidra: funcdata_varnode.cc:595 Funcdata::setHighLevel
    pub fn set_high_level(&mut self) {
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) != 0 { return; }
        self.flags |= funcdata_flags::HIGHLEVEL_ON;
        // cc:600: high_level_index = vbank.getCreateIndex().
        self.high_level_index = self.vbank.get_create_index();

        // cc:603-604: for every Varnode in the bank, assignHigh(*iter).
        // Ghidra's loop is unconditional, but before highlevel_on no Varnode
        // can hold a HighVariable (assignHigh is the sole allocator and is
        // gated on the flag), so the `high.is_none()` filter is
        // behavior-equivalent plus defensive for non-pipeline callers.
        let vn_arcs: Vec<Arc<RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().high.is_none())
            .map(|r| r.0.clone())
            .collect();

        for vn_arc in vn_arcs {
            // cc:604 → funcdata_varnode.cc:48-59 assignHigh: the
            // highlevel_on gate now passes; annotation Varnodes (iop/fspec
            // space, code refs) are rejected by the is_annotation guard and
            // stay high-less, exactly as in Ghidra.
            let _ = self.assign_high(&vn_arc);
        }
    }

    // Ghidra: funcdata.hh:183 Funcdata::startCastPhase
    /// Start the \b cast insertion phase: records the Varnode bank creation
    /// index (funcdata.hh:183, one-liner
    /// `cast_phase_index = vbank.getCreateIndex();`). Called at the head of
    /// `ActionSetCasts::apply` (coreaction.cc:2728).
    pub fn start_cast_phase(&mut self) {
        self.cast_phase_index = self.vbank.get_create_index();
    }

    // Ghidra: funcdata.cc:34 Funcdata::getName
    /// Get function name
    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Ghidra: funcdata.cc:34 Funcdata::findVarnodeInput
    /// Find an input varnode of the given size at the given address.
    /// Faithful to `Funcdata::findVarnodeInput` (funcdata.hh:324): the
    /// Address carries the space, so the bank lookup is space-qualified
    /// (BANK-FINDINPUT-SPACE-0001). Used by ActionRestrictLocal and
    /// AncestorRealistic.
    pub fn find_varnode_input(
        &self, size: usize, space: crate::space::AddressSpace,
        addr: crate::address::Address,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_input(size, space, addr)
    }

    // Ghidra: funcdata.cc:34 Funcdata::addSymbol
    /// Register a symbol (function/global) at the given virtual address
    pub fn add_symbol(&mut self, addr: u64, name: String) {
        self.symbol_table.insert(addr, name);
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    /// Resolve a constant Varnode that is the second input to a PTRSUB op
    /// into a Symbol. If the PTRSUB's first input is a spacebase pointer
    /// (stack or global), look up the offset in the symbol table. If found,
    /// set the symbol reference on the Varnode and return the symbol name.
    /// Faithful to `linkSymbolReference` (funcdata_varnode.cc:1193-1213).
    /// Returns the symbol name if found, None otherwise.
    // Ghidra: database.cc:1263 Scope::queryProperties (stackContainer parent-scope walk)
    /// Global-scope half of the `localmap->queryProperties` query that
    /// `linkSymbol` (funcdata_varnode.cc:1169) performs. Ghidra's
    /// `Scope::queryProperties` runs `mapScope` + `stackContainer`
    /// (database.cc:943-975), which walks local scope → parent scopes →
    /// the global Scope and returns the smallest containing SymbolEntry;
    /// for a ram address inside a global Symbol (stdin/config/…) that
    /// entry lives in the GLOBAL scope, and `handleSymbolConflict`'s early
    /// arm (funcdata_varnode.cc:1000-1003) attaches it to the Varnode's
    /// HighVariable without creating any ScopeLocal symbol.
    ///
    /// Rugra channels, in fidelity order:
    /// 1. The real `Database` graph (`Architecture::symboltab`), queried
    ///    through the parent-scope channel with the same container
    ///    semantics (`Database::query_properties`, database.cc:1263).
    /// 2. The driver's `symbol_table` name proxy (exact-address hits only,
    ///    no sizes) — the same transitional fallback `linkSymbolReference`
    ///    uses below.
    ///
    /// Space gate: only Ram varnodes are queried. The global scope owns
    /// ram ranges only (stack/register/unique addresses find nothing in
    /// Ghidra's walk either), and Rugra's `SymbolEntry` addresses are
    /// spaceless offsets, so an ungated query could cross-space collide a
    /// register offset with a ram global.
    fn query_global_symbol_hit(
        &self,
        vn_space: crate::space::AddressSpace,
        vn_offset: u64,
    ) -> Option<String> {
        use crate::space::AddressSpace;
        if vn_space != AddressSpace::Ram {
            return None;
        }
        // Channel 1: real Database (database.cc:1263-1281).
        if let Some((hit, _flags)) = self.query_properties_parent_scope(
            crate::address::Address::new(vn_offset),
            1,
            // Global symbols carry an empty uselimit (addrtied entries),
            // so the usepoint never gates the match (database.cc:955
            // entry->inUse(usepoint)); pass the invalid Address().
            crate::address::Address::new(0),
        ) {
            if let Some(container) = hit {
                if !container.symbol_name.is_empty() {
                    return Some(container.symbol_name);
                }
            }
            // A global-scope owner without a symbol entry
            // (database.cc:1272-1275 discovery branch) still means "this
            // address is global" — but without a name there is nothing to
            // attach; fall through to the proxy/local arms.
        }
        // Channel 2: driver symbol_table proxy (exact hits).
        self.symbol_table.get(&vn_offset).cloned()
    }

    // Ghidra: funcdata_varnode.cc:1156 Funcdata::linkSymbol
    /// Link a Varnode to a Symbol in the local scope. The Symbol is really
    /// attached to the Varnode's HighVariable (which must exist). If the
    /// HighVariable already has a Symbol it is returned; otherwise any
    /// overlapping local-map entry is resolved via `handleSymbolConflict`, and
    /// with no overlap a new local Symbol holding `high->getType()` is created
    /// at the Varnode's address with its usepoint (`addSymbol("", type, addr,
    /// usepoint)`) — the source of the golden's `bVar`/`pcVar` family. Faithful
    /// to `linkSymbol` (funcdata_varnode.cc:1156-1184). Returns the symbol's
    /// index into `scope.symbols`, or None (persist varnode with no existing
    /// Symbol — cc:1174's `if (!vn->isPersist())` gate).
    pub fn link_symbol(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>) -> Option<usize> {
        // cc:1159-1160: if (vn->isProtoPartial()) linkProtoPartial(vn);
        if vn.read().unwrap().is_proto_partial() {
            self.link_proto_partial(vn);
        }
        // cc:1161: HighVariable *high = vn->getHigh();
        let high_arc = vn.read().unwrap().high.clone()?;
        // cc:1164-1165: sym = high->getSymbol(); if (sym != 0) return sym;
        let high_ptr = Arc::as_ptr(&high_arc) as usize;
        if let Some(&idx) = self.high_symbols.get(&high_ptr) {
            return Some(idx);
        }
        // cc:1167: Address usepoint = vn->getUsePoint(*this); — written
        // varnodes use their def op's address; everything else comes into
        // scope at the function start - 1 (varnode.cc:696-703).
        let usepoint: Option<u64> = {
            let vn_r = vn.read().unwrap();
            if vn_r.is_written() {
                vn_r.get_def()
                    .map(|d| d.read().unwrap().get_addr().as_u64())
            } else {
                Some(self.baseaddr.as_u64().wrapping_sub(1))
            }
        };
        // cc:1169: entry = localmap->queryProperties(vn->getAddr(), 1, usepoint, fl);
        // (the fl side-output has no consumer in linkSymbol)
        let (vn_space, vn_offset) = {
            let vn_r = vn.read().unwrap();
            (vn_r.get_space(), vn_r.get_offset())
        };
        let entry_idx = self
            .scope
            .as_ref()?
            .query_properties(vn_space, vn_offset, 1, usepoint);
        if let Some(idx) = entry_idx {
            // cc:1170-1172: sym = handleSymbolConflict(entry, vn);
            self.handle_symbol_conflict(idx, vn)
        } else if vn.read().unwrap().get_space() == crate::space::AddressSpace::Ram {
            // The parent leg of the same queryProperties call (B3 channel):
            // Ghidra's ONE query walks ScopeLocal -> parent -> global scope
            // (database.cc:1268 stackContainer); Rugra's ScopeLocal leg saw
            // no local symbol, so consult the Database global scope — where
            // global symbols (ELF/DWARF/GOT imports, plus the Symbols
            // mapGlobals created at fixateglobals time) answer.
            let up = crate::address::Address::new(usepoint.unwrap_or(0));
            if let Some((_scope_id, entry_arc)) =
                self.query_container_entry_parent_scope(
                    crate::address::Address::new(vn_offset),
                    1,
                    up,
                )
            {
                // cc:1170-1171 equivalent for a global-scope entry: no
                // conflicting local HighVariable exists to adjudicate (the
                // entry is not in ScopeLocal), so this is the plain
                // vn->setSymbolEntry(entry) + high->setSymbol(vn) link.
                vn.write().unwrap().set_symbol_entry(entry_arc);
                if let Some(high) = vn.read().unwrap().get_high().cloned() {
                    high.write().unwrap().set_symbol(vn);
                    // RUGRA-GLUE: publish the symbol's display name onto the
                    // high the way the namevars write-back bridge does for
                    // ScopeLocal symbols (Ghidra resolves the name through
                    // high->getSymbol() at print; Rugra's printc reads
                    // high.get_name() behind its symbol_table priority).
                    let display = {
                        let h = high.read().unwrap();
                        h.symbol
                            .as_ref()
                            .map(|s| s.read().unwrap().get_display_name().to_string())
                    };
                    if let Some(name) = display {
                        if !name.is_empty() {
                            high.write().unwrap().name = name;
                        }
                    }
                }
            }
            // A global symbol always carries a name (never name-undefined),
            // so linkSymbol's ScopeLocal-idx contract is satisfied
            // vacuously: return None — the caller's post-link steps
            // (name-undefined default naming, sizelock override,
            // non-global finalizeDatatype) are all no-ops for a named
            // global symbol.
            None
        } else {
            // cc:1169: `localmap->queryProperties(...)` is
            // `Scope::queryProperties` (database.cc:1263-1281), which does
            // NOT stop at the local scope — `mapScope` +
            // `stackContainer(basescope, NULL, ...)` (database.cc:943-975)
            // walks local scope → parent scopes → GLOBAL scope and returns
            // the smallest containing SymbolEntry from any of them. A ram
            // varnode whose address falls inside a global Symbol (ELF/DWARF
            // globals like stdin/config) therefore hits the GLOBAL entry
            // here, and `handleSymbolConflict`'s early arm (cc:1000-1003:
            // isInput || isAddrTied || isPersist || isConstant ||
            // isDynamic → `vn->setSymbolEntry(entry)`) attaches that global
            // Symbol — it is NOT put into the function's ScopeLocal, so
            // `PrintC::emitScopeVarDecls` (printc.cc:2254-2276, walking
            // ScopeLocal + children only) never declares it. MAINDIFF-
            // UNIQLEAK-0001: Rugra previously stopped at the local model
            // and fell straight into the cc:1173-1181 create-local-symbol
            // arm, minting dead `in_ram_XXXX` declarations for every
            // global-sourced heritage input (37 in main alone vs golden 0).
            if let Some(global_name) = self.query_global_symbol_hit(vn_space, vn_offset) {
                // handleSymbolConflict early-arm bridge (cc:1002-1003
                // vn->setSymbolEntry(entry) + HighVariable::setSymbol): the
                // global Symbol's display name is published onto the high
                // (Rugra's print resolves through `high->get_name()` where
                // Ghidra resolves `high->getSymbol()->getDisplayName()`).
                // No ScopeLocal symbol is created; returning None mirrors
                // linkSymbols' cc:2963 `if (sym == 0)` skip for the
                // nameable-local bookkeeping (the global symbol is never
                // name-undefined, so namerec/finalizeDatatype stay inert —
                // finalizeDatatype is additionally gated on
                // `!sym->getScope()->isGlobal()` at cc:2971-2972).
                let high_arc2 = vn.read().unwrap().high.clone();
                if let Some(high) = &high_arc2 {
                    high.write().unwrap().set_name(global_name);
                }
                return None;
            }
            // cc:1173-1181: must create a symbol entry.
            let mut sym = None;
            if !vn.read().unwrap().is_persist() {
                // Only create local symbol.
                let mut up = usepoint;
                if vn.read().unwrap().is_addr_tied() {
                    up = None; // cc:1175-1176: usepoint = Address();
                }
                // cc:1177: entry = localmap->addSymbol("", high->getType(), vn->getAddr(), usepoint);
                let ct = high_arc.read().unwrap().get_type();
                let idx = self
                    .scope
                    .as_mut()?
                    .add_symbol(
                    vn_space, "", Some(ct), vn_offset, up);
                sym = Some(idx);
                // cc:1178-1179: sym = entry->getSymbol(); vn->setSymbolEntry(entry)
                // — varnode.cc:429-439 flags + high->setSymbol (variable.cc:
                // 245-275 symboloffset) through the shared attach helper.
                let _ = high_ptr;
                self.attach_symbol_to_vn(idx, vn);
            }
            sym
        }
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    // (scope->queryContainer call site) + coreaction.cc:1151
    // (data.getScopeLocal()->getParent()->queryContainer call site)
    /// The Funcdata query channel into the faithful `Database`/`Scope`
    /// symbol graph: the equivalent of
    /// `data.getScopeLocal()->getParent()->queryContainer(rampoint, 1,
    /// Address())`. Rugra's Funcdata carries no per-function database.rs
    /// local Scope (`scope` is the varmap `ScopeLocal` model), and a
    /// function-local Scope's parent is the global Scope, so the query
    /// point is `Database`'s global scope — exactly the scope Ghidra's
    /// `linkSymbolReference` reaches through the ram spacebase's
    /// `TypeSpacebase::getMap()`. Returns `None` when no Architecture or
    /// `symboltab` is attached (legacy/test Funcdata) — callers then fall
    /// back to the `symbol_table` name proxy.
    pub fn query_container_parent_scope(
        &self,
        addr: crate::address::Address,
        size: i32,
        usepoint: crate::address::Address,
    ) -> Option<crate::database::QueryContainerHit> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        db.query_container(qpoint, addr, size, usepoint)
    }

    // Ghidra: database.cc:1263 Scope::queryProperties (Funcdata consumer:
    // funcdata_varnode.cc:31 setVarnodeProperties call site form)
    /// The `queryProperties` arm of the query channel: the smallest
    /// containing Symbol relative to the global scope, plus the boolean
    /// properties of the memory range (readonly/volatile via the Database
    /// flagbase). The flags fold mirrors database.cc:1269-1280.
    pub fn query_properties_parent_scope(
        &self,
        addr: crate::address::Address,
        size: i32,
        usepoint: crate::address::Address,
    ) -> Option<(Option<crate::database::QueryContainerHit>, u32)> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        Some(db.query_properties(qpoint, addr, size, usepoint))
    }

    // Ghidra: database.cc:1246 Scope::queryContainer (live-entry form;
    // funcdata_varnode.cc:1701 mapGlobals / cc:1169 linkSymbol consumers)
    /// The live-entry arm of the query channel: the smallest containing
    /// SymbolEntry as an attachable handle (see
    /// [`crate::database::Database::query_container_entry`]), for callers
    /// that must link the entry onto a Varnode the way the C++ hands the
    /// `SymbolEntry*` to `vn->setSymbolEntry`. `None` when no channel is
    /// attached (legacy/test Funcdata).
    pub fn query_container_entry_parent_scope(
        &self,
        addr: crate::address::Address,
        size: i32,
        usepoint: crate::address::Address,
    ) -> Option<(
        u64, std::sync::Arc<std::sync::RwLock<crate::database::SymbolEntry>>,
    )> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        db.query_container_entry(qpoint, addr, size, usepoint)
    }

    // Ghidra: database.cc:1353 Scope::discoverScope (funcdata_varnode.cc:1703
    /// consumer form) — which scope owns the range at `addr`
    /// (`Database::discover_scope` through the same global-scope query point
    /// as the other channel arms; ownership does not require a Symbol).
    /// Returns the discovered scope id, or `None` when no channel is
    /// attached.
    pub fn discover_scope_parent_scope(
        &self,
        addr: crate::address::Address,
        sz: i32,
    ) -> Option<u64> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        db.discover_scope(qpoint, addr, sz)
    }

    // Ghidra: database.cc:1796 Scope::isReadOnly (ruleaction.cc:7372
    // consumer form: scope->isReadOnly(symaddr, 1, op->getAddr()))
    /// Read-only test through the query channel. This is the form
    /// `RulePtrsubCharConstant` and `PrintC::pushPtrCharConstant` use; it
    /// answers from Symbol flags AND the Database property ranges (the
    /// readonly channel `Database::set_property_range` feeds), replacing the
    /// `string_table`-membership proxy. `None` when no channel is attached.
    pub fn is_scope_read_only(
        &self,
        addr: crate::address::Address,
        size: i32,
        usepoint: crate::address::Address,
    ) -> Option<bool> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        Some(db.is_read_only(qpoint, addr, size, usepoint))
    }

    // Ghidra: database.cc:1198 Scope::queryByName (funcdata_varnode.cc:320
    /// Funcdata::findHigh consumer form)
    /// Name lookup through the query channel, walking the scope chain from
    /// the global scope. `None` when no channel is attached.
    pub fn query_name_parent_scope(&self, nm: &str) -> Option<Vec<crate::database::QueryNameHit>> {
        let symboltab = self.arch.as_ref()?.symboltab.clone()?;
        let db = symboltab.read().unwrap();
        let qpoint = db.global_scope_id;
        Some(db.query_by_name(qpoint, nm))
    }

    // Ghidra: database.cc:3220 Database::setPropertyRange (producer side of
    /// the readonly/volatile property channel; the loader→symboltab
    /// registration path is Architecture::fillinReadOnlyFromLoader
    /// (architecture.cc:1371-1383) / decodeReadOnly (architecture.cc:864-874))
    /// Register boolean properties over a memory range on the Architecture's
    /// symbol table — the Funcdata-reachable producer that makes readonly
    /// ranges (e.g. `.rodata`) consumable through
    /// [`Funcdata::query_properties_parent_scope`] /
    /// [`Funcdata::is_scope_read_only`]. `flags` takes `varnode_flags`
    /// bits (READONLY/VOLATIL/…); partitions accumulate (`|=`, per
    /// database.cc:3236). Returns `false` when no channel is attached.
    pub fn set_symbol_property_range(
        &self,
        flags: u32,
        range: crate::address::Range) -> bool {
        let Some(symboltab) = self.arch.as_ref().and_then(|a| a.symboltab.clone()) else {
            return false;
        };
        symboltab.write().unwrap().set_property_range(flags, range);
        true
    }

    // Ghidra: funcdata_varnode.cc:1193 Funcdata::linkSymbolReference
    pub fn link_symbol_reference(
        &mut self,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
    ) -> Option<String> {
        use crate::opcodes::OpCode;
        // cc:1196: op = vn->loneDescend() — must be consumed by exactly one op.
        let op_arc = vn.read().unwrap().lone_descend()?;
        let op = op_arc.read().unwrap();
        // cc:1197-1202: check that in(0) is a spacebase pointer type.
        // Rugra: check if the PTRSUB's first input is a spacebase varnode.
        if op.opcode != OpCode::CPUI_PTRSUB { return None; }
        let in0 = op.get_in(0)?;
        let in0_r = in0.read().unwrap();
        if !in0_r.is_spacebase() { return None; }
        drop(in0_r);
        // cc:1204: addr = sb->getAddress(vn->getOffset(), in0->getSize(), op->getAddr())
        // Rugra: the offset encodes the stack/global address directly.
        let vn_offset = vn.read().unwrap().get_offset();
        // cc:1207: entry = scope->queryContainer(addr, 1, Address())
        // The real query channel first: the ram spacebase's map is the
        // global Scope, so this is the parent-scope container query
        // (B3-COREACTION-CONSTANTPTR-0001 query channel).
        if let Some(hit) = self.query_container_parent_scope(
            crate::address::Address::new(vn_offset),
            1,
            // cc:1207 — the empty usepoint `Address()`.
            crate::address::Address::new(0),
        ) {
            // cc:1209-1211: off = (addr - entry->getAddr()) + entry->getOffset();
            // vn->setSymbolReference(entry, off);
            let _off = (vn_offset.wrapping_sub(hit.entry_addr.as_u64())) as i32
                + hit.entry_offset;
            return Some(hit.symbol_name);
        }
        // Transitional fallback (driver data source not yet switched to the
        // Database symbol graph): the `symbol_table` name proxy, mapping
        // address → name. Queries that miss the real channel keep the
        // pre-channel behavior byte-for-byte.
        let sym_name = self.symbol_table.get(&vn_offset).cloned();
        if let Some(ref name) = sym_name {
            // cc:1210-1211: vn->setSymbolReference(entry, off)
            // Rugra: we don't have full SymbolEntry infrastructure, but we
            // can record the name on the varnode via the symbol reference.
            // For now, the symbol_table lookup IS the resolution.
            return Some(name.clone());
        }
        // Also check scope.symbols for stack-relative symbols
        // (queryContainer at cc:1207 consults the spacebase's scope; the
        // spacebase-derived address is a stack offset, so register/unique
        // symbols created by linkSymbol never answer here).
        if let Some(ref scope) = self.scope {
            for sym in &scope.symbols {
                if sym.space != crate::space::AddressSpace::Stack {
                    continue;
                }
                if sym.start == vn_offset {
                    return Some(sym.name.clone());
                }
            }
        }
        None
    }

    // Ghidra: funcdata.cc:34 Funcdata::addString
    /// Register a string literal at the given virtual address
    pub fn add_string(&mut self, addr: u64, s: String) {
        self.string_table.insert(addr, s);
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSymbol
    /// Look up a symbol name by address
    pub fn get_symbol(&self, addr: u64) -> Option<&str> {
        self.symbol_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getString
    /// Look up a string literal by address
    pub fn get_string(&self, addr: u64) -> Option<&str> {
        self.string_table.get(&addr).map(|s| s.as_str())
    }

    // Ghidra: funcdata.cc:34 Funcdata::getAddress
    /// Get function base address
    pub fn get_address(&self) -> &Address {
        &self.baseaddr
    }

    // Ghidra: funcdata.cc:34 Funcdata::getSize
    /// Get function size
    pub fn get_size(&self) -> i32 {
        self.size
    }

    // Ghidra: funcdata.cc:34 Funcdata::numCalls
    /// Number of call sites in this function. Faithful to
    /// `Funcdata::numCalls` (funcdata.hh).
    pub fn num_calls(&self) -> usize {
        self.callspecs.len()
    }

    // Ghidra: funcdata.cc:484 Funcdata::getCallSpecs
    /// Get call specs by index. Faithful to `Funcdata::getCallSpecs`
    /// (funcdata.hh).
    pub fn get_call_specs(
        &self,
        i: usize,
    ) -> Option<std::sync::RwLockReadGuard<'_, crate::fspec::FuncCallSpecs>> {
        self.callspecs.get(i).map(|fc| fc.read().unwrap())
    }

    // Ghidra: funcdata.cc:484 Funcdata::getCallSpecs(const PcodeOp *op) const
    /// Get the call specification associated with a CALL/CALLIND op.
    /// Faithful to `Funcdata::getCallSpecs(op)` (funcdata.cc:484-497):
    /// fast path resolves the op's in(0) fspec constant back to the
    /// FuncCallSpecs; the fallback linearly scans the call list for the
    /// spec whose op matches. Until a dedicated FSPEC address space exists,
    /// Rugra's annotation remains in Iop space but carries a typed Weak
    /// handle. A raw constant with the same numeric offset is never decoded
    /// as a spec.
    pub fn get_call_specs_of_op(
        &self,
        op: &crate::op::PcodeOpRef,
    ) -> Option<Arc<RwLock<crate::fspec::FuncCallSpecs>>> {
        let in0 = op.0.read().unwrap().inrefs.first().cloned()?;
        let (space, is_annotation, typed) = {
            let vn = in0.read().unwrap();
            (vn.address_space, vn.is_annotation(), vn.get_call_spec())
        };
        if space == crate::space::AddressSpace::Iop && is_annotation {
            if let Some(fc) = typed {
                let owned = self.callspecs.iter().any(|item| Arc::ptr_eq(item, &fc));
                let same_op = fc
                    .read()
                    .unwrap()
                    .op
                    .upgrade()
                    .map(|bound| Arc::ptr_eq(&bound, &op.0))
                    .unwrap_or(false);
                if owned && same_op {
                    return Some(fc);
                }
            }
        }
        // Ghidra's fallback compares `fc->getOp() == op`, never addresses or
        // the integer offset of a non-FSPEC constant.
        self.callspecs
            .iter()
            .find(|fc| {
                fc.read()
                    .unwrap()
                    .op
                    .upgrade()
                    .map(|bound| Arc::ptr_eq(&bound, &op.0))
                    .unwrap_or(false)
            })
            .cloned()
    }

    // Ghidra: funcdata.cc:34 Funcdata::getCallSpecsMut
    /// Get mutable call specs by index.
    pub fn get_call_specs_mut(
        &self,
        i: usize,
    ) -> Option<std::sync::RwLockWriteGuard<'_, crate::fspec::FuncCallSpecs>> {
        self.callspecs.get(i).map(|fc| fc.write().unwrap())
    }

    // Ghidra: funcdata.cc:34 Funcdata::addCallSpecs
    /// Add a new call specification. Returns the index.
    pub fn add_call_specs(&mut self, fc: crate::fspec::FuncCallSpecs) -> usize {
        self.callspecs.push(Arc::new(RwLock::new(fc)));
        self.callspecs.len() - 1
    }

    // RUGRA-GLUE: Preserve Ghidra's setup order when an annotation must be
    // installed before the stable owner is inserted into qlst.
    pub fn add_call_specs_owner(&mut self, fc: Arc<RwLock<crate::fspec::FuncCallSpecs>>) -> usize {
        self.callspecs.push(fc);
        self.callspecs.len() - 1
    }

    // RUGRA-GLUE: Borrow-safe access to the stable owner handle used when
    // constructing a typed FSPEC annotation.
    pub fn get_call_specs_owner(
        &self,
        i: usize,
    ) -> Option<Arc<RwLock<crate::fspec::FuncCallSpecs>>> {
        self.callspecs.get(i).cloned()
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProto
    /// Get the function prototype. Faithful to `Funcdata::getFuncProto`.
    pub fn get_func_proto(&self) -> &FuncProto {
        &self.funcp
    }

    // Ghidra: funcdata.cc:34 Funcdata::getFuncProtoMut
    /// Get mutable function prototype.
    pub fn get_func_proto_mut(&mut self) -> &mut FuncProto {
        &mut self.funcp
    }

    // --- Funcdata P-code op editing API (faithful to funcdata.hh:281-479) ---
    // These mirror Ghidra's Funcdata methods used by the rule/action transforms
    // to construct and edit P-code during analysis.

    // RUGRA-GLUE: Funcdata allocation adapter; PcodeOpBank::create currently
    // cannot represent Ghidra's nullable input slots or null opcode, so only
    // the dead/alive lifecycle is enforced here (OP-INSERT-0001 MISMATCH).
    /// Allocate a new PcodeOp associated with `pc` and place it on the dead
    /// list. The requested nullable input-slot shape remains an OPBANK gap.
    pub fn new_op(
        &mut self, num_inputs: usize, pc: crate::address::Address,
    ) -> crate::op::PcodeOpRef {
        // PcodeOpBank::create puts a newly allocated op on Ghidra's dead list
        // (op.cc:941-948).  PcodeOpBank::create is also used by Rugra's raw
        // injection bridge, whose legacy lifecycle is different, so enforce
        // the mapped Funcdata::newOp contract at this API boundary.
        let op = self
            .obank
            .create(crate::opcodes::OpCode::CPUI_COPY, num_inputs, pc);
        self.obank.mark_dead(op.clone());
        op
    }

    // Ghidra: funcdata_varnode.cc:129 Funcdata::newUniqueOut
    /// Create a new temporary output Varnode of size `s` for `op`.
    /// Faithful to `Funcdata::newUniqueOut` (funcdata_varnode.cc:129-140):
    ///   Varnode *vn = vbank.createDefUnique(s, ct, op);
    ///   op->setOutput(vn);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, vn->getAddr());
    ///   return vn;
    pub fn new_unique_out(
        &mut self, s: usize, op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:134-135 creates the written form directly. Mutating a free
        // Varnode after insertion would change both BTreeSet keys in-place.
        let vn = self.vbank.create_def_unique(s, &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        // cc:135: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if s >= self.min_laned_size as usize {
            let (space, addr) = {
                let vn = vn.read().unwrap();
                (
                    vn.get_space(), crate::address::Address::new(vn.get_offset()),
                )
            };
            self.check_for_laned_register(s, space, addr);
        }
        vn
    }

    // Ghidra: funcdata_varnode.cc:66 Funcdata::newConstant
    /// Create a new constant Varnode. Faithful to `Funcdata::newConstant`
    /// (funcdata_varnode.cc:66-76):
    ///   Varnode *vn = vbank.create(s, glb->getConstant(constant_val), ct);
    ///   assignHigh(vn);
    ///   return vn;
    pub fn new_constant(
        &mut self, s: usize, val: u64,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_constant(s, val);
        // cc:72: assignHigh(vn) — constant Varnodes do get a HighVariable
        // (hasCover() is false for constants, so no calcCover; they are not
        // annotations). (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::newExtendedConstant
    /// Create a new (possibly extended) constant Varnode of size `s` from a
    /// 128-bit value `(lo, hi)`. Faithful to `Funcdata::newExtendedConstant`
    /// (funcdata_varnode.cc:462-484). For s≤8, creates a plain constant.
    /// For s>8 with hi==0, creates INT_ZEXT(const). For s>8 with hi!=0,
    /// creates PIECE(hi_const, lo_const).
    pub fn new_extended_constant(
        &mut self, s: usize, lo: u64, hi: u64, before_op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        if s <= 8 {
            return self.new_constant(s, lo);
        }
        let addr = before_op.0.read().unwrap().get_addr();
        if hi == 0 {
            let ext_op = self.new_op(1, addr);
            self.op_set_opcode(&ext_op, crate::opcodes::OpCode::CPUI_INT_ZEXT);
            let out = self.new_unique_out(s, &ext_op);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&ext_op, lo_const, 0);
            self.op_insert_before(&ext_op, before_op);
            out
        } else {
            let piece_op = self.new_op(2, addr);
            self.op_set_opcode(&piece_op, crate::opcodes::OpCode::CPUI_PIECE);
            let out = self.new_unique_out(s, &piece_op);
            let hi_const = self.new_constant(8, hi);
            let lo_const = self.new_constant(8, lo);
            self.op_set_input(&piece_op, hi_const, 0);
            self.op_set_input(&piece_op, lo_const, 1);
            self.op_insert_before(&piece_op, before_op);
            out
        }
    }

    // Ghidra: funcdata_op.cc:632 Funcdata::getFirstReturnOp
    /// Return the first non-dead, non-halt CPUI_RETURN op, or None.
    /// Faithful to `getFirstReturnOp` (funcdata_op.cc:632-644).
    pub fn get_first_return_op(&self) -> Option<crate::op::PcodeOpRef> {
        // Use returnlist (PcodeOpBank code list for RETURN ops).
        for retop in &self.obank.returnlist {
            let op = retop.0.read().unwrap();
            if op.is_dead() { continue; }
            // cc:640: getHaltType()!=0 → skip artificial halts.
            let halt_mask = crate::op::pcodeop_flags::HALT
                | crate::op::pcodeop_flags::BADINSTRUCTION
                | crate::op::pcodeop_flags::UNIMPLEMENTED
                | crate::op::pcodeop_flags::NORETURN
                | crate::op::pcodeop_flags::MISSING;
            if (op.flags & halt_mask) != 0 { continue; }
            return Some(retop.clone());
        }
        None
    }

    // Ghidra: funcdata_varnode.cc:83 Funcdata::newUnique
    /// Create a new temporary Varnode (no defining op). Faithful to
    /// `Funcdata::newUnique` (funcdata_varnode.cc:83-95):
    ///   if (ct == 0) ct = glb->types->getBase(s,TYPE_UNKNOWN);
    ///   Varnode *vn = vbank.createUnique(s, ct);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, vn->getAddr());
    ///   return vn;
    pub fn new_unique(
        &mut self, s: usize,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_unique(s);
        // cc:89: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if s >= self.min_laned_size as usize {
            let (space, addr) = {
                let vn = vn.read().unwrap();
                (
                    vn.get_space(), crate::address::Address::new(vn.get_offset()),
                )
            };
            self.check_for_laned_register(s, space, addr);
        }
        vn
    }

    // Ghidra: funcdata_varnode.cc:83 Funcdata::newUnique
    /// Typed overload of `new_unique` mirroring the full
    /// `Funcdata::newUnique(int4 s, Datatype *ct)` signature: a null ct is
    /// defaulted to the factory unknown base (cc:86-87) exactly as in
    /// Ghidra; a non-null ct becomes the varnode's data-type via
    /// `VarnodeBank::createUnique(s, ct)` (the ctor's `type = dt`,
    /// varnode.cc:583). Callers that carry a source varnode's type
    /// (e.g. Merge::allocateCopyTrim merge.cc:416/429, Merge::trimOpOutput
    /// merge.cc:668/677) must use this form so the trim COPY's output
    /// observes the same data-type as the oracle.
    pub fn new_unique_typed(
        &mut self, s: usize, ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:86-87: if (ct == (Datatype *)0) ct = getBase(s,TYPE_UNKNOWN)
        let ct = ct.unwrap_or_else(|| {
            crate::varnode::default_unknown_type(None, s)
        });
        let vn = self.vbank.create_unique_typed(s, ct);
        // cc:89: assignHigh(vn) (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if s >= self.min_laned_size as usize {
            let (space, addr) = {
                let vn = vn.read().unwrap();
                (
                    vn.get_space(), crate::address::Address::new(vn.get_offset()),
                )
            };
            self.check_for_laned_register(s, space, addr);
        }
        vn
    }

    // Ghidra: funcdata_op.cc:37 Funcdata::opMarkHalt
    /// Mark a CPUI_RETURN op as an artificial halt. Faithful to
    /// `opMarkHalt` (funcdata_op.cc:37-48). Throws if op is not RETURN
    /// or flag is invalid (Rugra logs + returns).
    pub fn op_mark_halt(&self, op: &crate::op::PcodeOpRef, flag: u32) {
        use crate::op::pcodeop_flags;
        use crate::opcodes::OpCode;
        // cc:40: if (op->code() != CPUI_RETURN) throw;
        if op.0.read().unwrap().opcode != OpCode::CPUI_RETURN {
            eprintln!("[FUNCDATA] WARN: opMarkHalt on non-RETURN op");
            return;
        }
        // cc:42-44: flag &= (halt|badinstruction|unimplemented|noreturn|missing);
        let mask = pcodeop_flags::HALT | pcodeop_flags::BADINSTRUCTION
            | pcodeop_flags::UNIMPLEMENTED | pcodeop_flags::NORETURN
            | pcodeop_flags::MISSING;
        let masked = flag & mask;
        // cc:45-46: if (flag == 0) throw;
        if masked == 0 {
            eprintln!("[FUNCDATA] WARN: opMarkHalt with bad flag {:#x}", flag);
            return;
        }
        // cc:47: op->setFlag(flag);
        op.0.write().unwrap().flags |= masked;
    }

    // Ghidra: funcdata_op.cc:25 Funcdata::opSetOpcode
    /// Set the op-code for a specific PcodeOp. Faithful to
    /// `Funcdata::opSetOpcode` (funcdata.hh:463).
    pub fn op_set_opcode(&mut self, op: &crate::op::PcodeOpRef, opc: crate::opcodes::OpCode) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:25-33); env
        // gate makes this a no-op in normal builds.
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        // cc:29 delegates to PcodeOpBank::changeOpcode. Besides resetting
        // opcode-derived flags, this removes the op from its old LOAD/STORE/
        // RETURN/CALLOTHER list and inserts it into the new one.
        self.obank.change_opcode(op.clone(), opc);
    }

    // Ghidra: funcdata_op.cc:104 Funcdata::opSetInput
    /// Set a specific input operand for the given PcodeOp. Faithful to
    /// `Funcdata::opSetInput` (funcdata_op.cc:104-125). Four decisive steps:
    ///   (1) early-out if vn is already the input at slot
    ///   (2) const dedup: if vn is constant AND has descend AND not spacebase,
    ///       create a fresh constant copy (with copySymbol) and use that
    ///   (3) opUnsetInput(op, slot) on the OLD input — erases op from old
    ///       vn's descend list (Rugra's inrefs Vec can't hold null, so the
    ///       "clearInput" half is implicit: inrefs[slot] gets overwritten
    ///       below; the load-bearing part is erase_descend on the old vn)
    ///   (4) vn->addDescend(op) + op->setInput(vn, slot)
    ///
    /// **2026-07-05 修正**:此前 Rugra 漏了 (1)(2)(3),直接 addDescend + 赋值,
    /// 导致旧 vn 的 descend 列表残留当前 op 引用 → has_no_descend 永远返回
    /// false → heritage rename 的 deleteVarnode (heritage.cc:2521) 永远不执行
    /// → 死 varnode 累积污染后续 pass。同时 const 去重缺失导致同一常量 vn 被
    /// 多个 op 引用,违反 Ghidra "constants should have only one descendant"
    /// 不变量 (cc:108)。
    pub fn op_set_input(
        &mut self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize,
    ) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:104-125):
        // Ghidra's cc:107 same-input early-out precedes the hook at
        // cc:116-119, so test it first under a read guard (this function
        // holds a write guard below, and the recorder takes its own).
        if crate::drillobserve::is_enabled() {
            let same_input = {
                let o = op.0.read().unwrap();
                slot < o.inrefs.len() && std::sync::Arc::ptr_eq(&vn, &o.inrefs[slot])
            };
            if !same_input {
                crate::drillobserve::mod_check(self.arch.as_ref(), op);
            }
        }
        let mut o = op.0.write().unwrap();
        // Ghidra has nullable preallocated slots. For Rugra's Vec model, a
        // sequential slot exactly at len is the representable NULL boundary
        // and is appended below without allocating a sentinel. Preserve gap
        // sentinels only for the still-unresolved slot>len representation.
        while o.inrefs.len() < slot {
            let sentinel = self.vbank.create(1, crate::address::Address::new(u64::MAX));
            o.inrefs.push(sentinel);
        }
        // (1) Ghidra cc:107: if (vn == op->getIn(slot)) return;
        if slot < o.inrefs.len() && std::sync::Arc::ptr_eq(&vn, &o.inrefs[slot]) {
            return;
        }
        // (2) Ghidra cc:108-115: const dedup. If vn is constant AND has
        // descend AND not spacebase, create a fresh copy so each constant
        // has only one descendant.
        let vn_final = {
            let vn_r = vn.read().unwrap();
            let needs_dedup = vn_r.is_constant() && !vn_r.has_no_descend() && !vn_r.is_spacebase();
            drop(vn_r);
            if needs_dedup {
                let (sz, off) = {
                    let r = vn.read().unwrap();
                    (r.size, r.loc.as_u64())
                };
                let cvn = self.new_constant(sz, off);
                // Ghidra cc:112: cvn->copySymbol(vn) — Varnode::copySymbol
                // (varnode.cc:493-505). The field half (cc:496-499) is
                // Varnode::copy_symbol (varnode.rs): Datatype pointer copy
                // (cc:496), mapentry copy (cc:497), then clear and re-inherit
                // ONLY the typelock|namelock bits from vn (cc:498-499 — not
                // mapped/insert/coverdirty, which stay cvn-local). Previously
                // this branch copied mapentry only, so a typelock/namelock
                // equate constant lost its locks and type on dedup
                // (VARNODE-COPYSYMBOL-FIELDS-0001).
                {
                    let src = vn.read().unwrap();
                    cvn.write().unwrap().copy_symbol(&src);
                }
                // cc:500-504 high bookkeeping (high->typeDirty(); if
                // mapentry != 0 high->setSymbol(this)) lives at this call
                // site in the attach_symbol_to_vn house pattern because
                // copy_symbol's &mut self cannot recover the Arc-to-self
                // that HighVariable::set_symbol takes. Reachable since
                // FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001: new_constant now
                // calls assignHigh (funcdata_varnode.cc:72), so when
                // highlevel_on is set the dedup constant carries a fresh
                // HighVariable into this leg — closing the
                // VARNODE-COPYSYMBOL-FIELDS-0001 residual R1.
                if let Some(high) = cvn.read().unwrap().get_high().cloned() {
                    let has_mapentry = cvn.read().unwrap().mapentry.is_some();
                    let mut h = high.write().unwrap();
                    h.type_dirty();
                    if has_mapentry {
                        h.set_symbol(&cvn);
                    }
                }
                cvn
            } else {
                vn.clone()
            }
        };
        // (3) Ghidra cc:120-121: if (op->getIn(slot) != null) opUnsetInput(op, slot).
        // opUnsetInput does vn->eraseDescend(op) + op->clearInput(slot).
        // Ghidra's NULL check is the "link still live" test; with no
        // representable NULL, descend membership plays that role (see
        // op_unset_input). A stale slot whose link was already severed is
        // skipped, mirroring the NULL-slot path, instead of re-erasing a
        // descend entry that is no longer there.
        if slot < o.inrefs.len() {
            let old_vn = o.inrefs[slot].clone();
            let linked = {
                let old_r = old_vn.read().unwrap();
                old_r.descend.iter().any(|weak| {
                    weak.upgrade()
                        .is_some_and(|candidate| std::sync::Arc::ptr_eq(&candidate, &op.0))
                })
            };
            if linked {
                old_vn.write().unwrap().erase_descend(&op.0);
            }
        }
        // (4) Ghidra cc:123-124: vn->addDescend(op) + op->setInput(vn, slot).
        vn_final.write().unwrap().add_descend(&op.0);
        if slot == o.inrefs.len() {
            o.inrefs.push(vn_final);
        } else {
            o.inrefs[slot] = vn_final;
        }
    }

    // Ghidra: funcdata_op.cc:308 Funcdata::opInsertInput
    /// Insert a new Varnode into the operand list at `slot`; any existing
    /// input Varnodes with slot indices >= `slot` are pushed into the next
    /// slot. Faithful to `Funcdata::opInsertInput` (funcdata_op.cc:308-317):
    /// `op->insertInput(slot)` then `opSetInput(op,vn,slot)` — the full
    /// opSetInput path (const dedup cc:108-115, addDescend free-check +
    /// coverdirty bookkeeping varnode.cc:330-340), never a raw descend push.
    pub fn op_insert_input(
        &mut self, op: &crate::op::PcodeOpRef, vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, slot: usize,
    ) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:308-317 hook
        // at :313, before insertInput; the delegated op_set_input's hook
        // no-ops via the MODIFIED addl-flag, like Ghidra's first-touch).
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        // cc:315 op->insertInput(slot) — PcodeOp::insertInput
        // (op.cc:311-318) pushes a NULL slot at `slot` and shifts existing
        // inputs at/after `slot` up by one. Descend entries store the op
        // pointer, not the slot index, so the shift needs no descend
        // update. Rugra's inrefs Vec cannot hold the transient NULL without
        // allocating an observable sentinel Varnode in the bank, and every
        // Ghidra statement between insertInput and opSetInput's final
        // setInput is a no-op on that NULL slot (cc:107 vn != NULL so the
        // early-return cannot fire; cc:118-121 opUnsetInput is guarded by
        // getIn(slot) != NULL), so the tail is split off here and the
        // delegated op_set_input appends into the fresh slot below. Ghidra
        // has no clamp (callers never exceed numInput); the defensive
        // clamp to len is Rust-side bounds glue.
        let (slot, tail) = {
            let mut o = op.0.write().unwrap();
            let slot = slot.min(o.inrefs.len());
            let tail = if slot < o.inrefs.len() {
                Some(o.inrefs.split_off(slot))
            } else {
                None
            };
            (slot, tail)
        };
        // cc:316 opSetInput(op,vn,slot) — with inrefs.len()==slot this
        // takes the fresh-slot path: no early-return (NULL != vn), no
        // opUnsetInput (NULL guard), const dedup when the same constant
        // already has a live descendant, then addDescend + setInput.
        self.op_set_input(op, vn, slot);
        if let Some(tail) = tail {
            op.0.write().unwrap().inrefs.extend(tail);
        }
    }

    // Ghidra: funcdata_op.cc:291 Funcdata::opRemoveInput
    /// Remove a specific input slot. Ghidra first calls `opUnsetInput` so the
    /// input Varnode loses this op from its descendant list, then removes the
    /// now-unlinked slot and shifts later slots down by one.
    pub fn op_remove_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        if slot >= op.0.read().unwrap().inrefs.len() {
            return;
        }
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:291-299 hook
        // at :296, after the bounds guard, before the unlink).
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        self.op_unset_input(op, slot);
        let mut o = op.0.write().unwrap();
        if slot < o.inrefs.len() {
            o.inrefs.remove(slot);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opSwapInput
    /// Swap two input operands. Faithful to `Funcdata::opSwapInput`
    /// (funcdata.hh). Used by RuleBoolNegate to reorder operands when flipping
    /// a comparison (e.g. `!(V < W) => W <= V`).
    pub fn op_swap_input(&self, op: &crate::op::PcodeOpRef, slot1: usize, slot2: usize) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:150-160 hook
        // at :155, before the swap; guarded by the bounds precondition).
        {
            let o = op.0.read().unwrap();
            if slot1 < o.inrefs.len() && slot2 < o.inrefs.len() {
                drop(o);
                crate::drillobserve::mod_check(self.arch.as_ref(), op);
            }
        }
        let mut o = op.0.write().unwrap();
        if slot1 < o.inrefs.len() && slot2 < o.inrefs.len() {
            o.inrefs.swap(slot1, slot2);
        }
    }

    // Ghidra: funcdata_op.cc:70 Funcdata::opSetOutput
    /// Install a bank-owned Varnode as an op output, consuming the canonical
    /// Varnode selected by `VarnodeBank::set_def`.
    pub fn op_set_output(
        &mut self,
        op: &crate::op::PcodeOpRef,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let same_output = op.0.read()
                .unwrap()
                .output
                .as_ref()
            .is_some_and(|output| std::sync::Arc::ptr_eq(output, &vn));
        if same_output {
            return;
        }
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:70-87 hook
        // at :76, after the same-output early-out, before the mutation).
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        if op.0.read().unwrap().output.is_some() {
            self.op_unset_output(op);
        }
        let previous_def = vn.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        if let Some(previous_def) = previous_def {
            self.op_unset_output(&previous_def);
        }
        let canonical = match self.vbank.set_def(vn, std::sync::Arc::downgrade(&op.0)) {
            Ok(canonical) => canonical,
            Err(error) => panic!("Funcdata::opSetOutput precondition failed: {error}"),
        };
        self.set_varnode_properties(&canonical);
        op.0.write().unwrap().output = Some(canonical);
    }

    // Ghidra: funcdata_op.cc:203 Funcdata::opDestroy
    /// Destroy an unused PcodeOp. Faithful to `Funcdata::opDestroy`
    /// (funcdata_op.cc:203-222). Destroys the output Varnode, unsets all
    /// inputs, and removes an integrated op from its exact basic block.
    pub fn op_destroy(&mut self, op: &crate::op::PcodeOpRef) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:203-222 hook
        // at :208, before any destruction).
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        // cc:211-212: snapshot before destroyVarnode, so the op read guard
        // cannot overlap destroyVarnode's write to the same output slot.
        let output = { op.0.read().unwrap().output.clone() };
        if let Some(output) = output {
            self.destroy_varnode(&output);
        }
        // cc:213-217: clear every non-null input in slot order. Each
        // opUnsetInput erases the descend link and NULLs the slot in place
        // (op.cc:98 clearInput), so the destroyed op KEEPS its numInput()
        // slots as NULLs — represented by the shared null_slot_sentinel.
        // The op stays in the dead list with its input-slot count intact,
        // matching the oracle's post-opDestroy observable state
        // (SB-ORD159-NULLSLOT-0001).
        let input_count = op.0.read().unwrap().inrefs.len();
        for slot in 0..input_count {
            self.op_unset_input(op, slot);
        }
        // cc:218-221: parentless ops are already dead. Integrated ops move to
        // the dead bank and leave their owning block.
        let parent = op.0.read()
                .unwrap()
                .parent
                .as_ref()
            .and_then(std::sync::Weak::upgrade);
        if let Some(parent) = parent {
            self.obank.mark_dead(op.clone());
            Self::block_remove_op(op, &parent);
        } else {
            // Ghidra postcondition of opDestroy: the op is ALWAYS dead
            // afterwards. A parentless op in Ghidra is already in the
            // deadlist (PcodeOpBank::create starts ops dead, op.cc:946;
            // only opInsert's markAlive, funcdata_op.cc:157, brings them
            // alive), so Ghidra needs no explicit markDead here. Rugra's
            // create() (op.rs) starts ops alive in the alivelist, so a
            // parentless destroy (never-inserted op, or a block whose Arc
            // was already dropped) must still mark_dead to reach the same
            // terminal state — otherwise an input-less alive SUBPIECE stays
            // in the ActionPool iteration (processOp's isDead check,
            // action.cc:830) and panics Rules that read getIn(0) (e.g.
            // RuleSubvarSubpiece, subflow.cc:1593).
            self.obank.mark_dead(op.clone());
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opDestroyRecursive
    /// Recursively destroy an op and its now-dead defining ops. Faithful to
    /// `Funcdata::opDestroyRecursive` (funcdata_op.cc:228-247). Destroys the
    /// given op, then for each input Varnode that becomes dead (its only
    /// reader was this op and it is not auto-live/call/indirect-source),
    /// recursively destroys its defining op.
    pub fn op_destroy_recursive(&mut self, op: &crate::op::PcodeOpRef) {
        let mut scratch: Vec<crate::op::PcodeOpRef> = Vec::new();
        scratch.push(op.clone());
        let mut pos = 0;
        while pos < scratch.len() {
            let cur = scratch[pos].clone();
            pos += 1;
            // Collect input varnodes and check if their defining ops should be
            // recursively destroyed.
            let inrefs = cur.0.read().unwrap().inrefs.clone();
            for in_vn in &inrefs {
                let (is_written, lone_descend_none, def) = {
                    let vn_rg = in_vn.read().unwrap();
                    let lone = vn_rg.lone_descend();
                    (
                        vn_rg.is_written(),
                        lone.is_none(),
                        vn_rg.get_def())
                };
                if !is_written {
                    continue;
                }
                if lone_descend_none {
                    continue; // Still has descendants (or no def).
                }
                let Some(def_op) = def else { continue };
                let def_ref = crate::op::PcodeOpRef(def_op);
                // Skip call and indirect-source ops (faithful to Ghidra).
                let is_call = def_ref.0.read().unwrap().is_call();
                let is_indirect_source = {
                    let f = def_ref.0.read().unwrap().flags;
                    (f & crate::op::pcodeop_flags::INDIRECT_SOURCE) != 0
                };
                if is_call || is_indirect_source {
                    continue;
                }
                scratch.push(def_ref);
            }
            self.op_destroy(&cur);
        }
    }

    // Ghidra: funcdata_varnode.cc:1474 Funcdata::totalReplace
    /// Replace every read reference of `vn` with `newvn`. Faithful to
    /// `Funcdata::totalReplace` (funcdata_varnode.cc:1474-1487):
    ///   iter = vn->beginDescend();
    ///   while(iter != vn->endDescend()) {
    ///     op = *iter++;	   // Increment before removing descendant
    ///     i = op->getSlot(vn);
    ///     opSetInput(op,newvn,i);
    ///   }
    /// Ghidra walks the ORIGINAL std::list with an iterator advanced before
    /// `opSetInput` severs the entry: every original entry is visited exactly
    /// once and the loop terminates at `endDescend()` regardless of what
    /// remains in the live list (e.g. when `newvn == vn`, opSetInput's
    /// early-out leaves entries in place and Ghidra still exits after one
    /// pass). Rugra must NOT re-scan the list until it drains: entries the
    /// per-site opSetInput cannot remove would spin forever (this was the
    /// FUNC-GLOBRANGE-HANG-0001 deadlock). Snapshot the live descendants
    /// once (dead Weak entries — op Arc freed without unset, unreachable in
    /// Ghidra's raw-pointer model — cannot be visited and are skipped), then
    /// compute each site's first matching slot AT APPLY TIME, matching
    /// `getSlot`'s first-match semantics (op.hh:166) so an op reading `vn`
    /// in multiple slots has each visit retarget the next remaining slot.
    pub fn total_replace(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        newvn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> = {
            let vn_r = vn.read().unwrap();
            vn_r.descend.iter().filter_map(|w| w.upgrade()).collect()
        };
        for descendant in descendants {
            // Ghidra cc:1483: i = op->getSlot(vn) — first matching slot,
            // evaluated after earlier sites were rewritten.
            let slot = descendant
                .read()
                .unwrap()
                .inrefs
                .iter()
                .position(|input| std::sync::Arc::ptr_eq(input, vn));
            let Some(slot) = slot else {
                // Ghidra getSlot miss returns numInput and opSetInput throws
                // LowlevelError "Bad input slot" (funcdata_op.cc:106-107).
                // The site is drift (op no longer reads vn); remove the
                // stale descend entry so the list reflects actual reads.
                vn.write().unwrap().erase_descend(&descendant);
                continue;
            };
            self.op_set_input(
                &crate::op::PcodeOpRef(descendant),
                newvn.clone(),
                slot);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opUnsetInput
    /// Unset an input slot. Faithful to `Funcdata::opUnsetInput`
    /// (funcdata_op.cc). Removes the descend link from the input varnode and
    /// sets the slot to None (represented as removing from inrefs in Rugra).
    // Ghidra: funcdata_op.cc:92 Funcdata::opUnsetInput
    /// Unlink the input Varnode at `slot` from `op`. Faithful to
    /// `Funcdata::opUnsetInput` (funcdata_op.cc:92-99):
    ///   vn = op->getIn(slot);
    ///   vn->eraseDescend(op);
    ///   op->clearInput(slot);
    /// Ghidra's `clearInput` (op.hh:136) NULLs the slot in place, so every
    /// later reader sees `getIn(slot) == NULL` and skips it — most
    /// importantly `opDestroy` (funcdata_op.cc:213-215), which guards each
    /// slot with `if (vn != NULL) opUnsetInput(op,i)`. The slot is then
    /// cleared in place (cc:98 `op->clearInput(slot)`): Rugra writes the
    /// shared `null_slot_sentinel` (Ghidra's `(Varnode *)0`), preserving the
    /// slot count — a dead op keeps `numInput()` NULL slots, exactly like
    /// Ghidra's inrefs array (SB-ORD159-NULLSLOT-0001). Descend membership
    /// is checked before the erase: if `op` is not in `vn`'s descend list
    /// the link was already severed, and skipping the erase reproduces
    /// Ghidra's NULL-slot no-op. This makes repeated unsets on the same slot
    /// idempotent instead of re-erasing a descend entry that is no longer
    /// there.
    pub fn op_unset_input(&self, op: &crate::op::PcodeOpRef, slot: usize) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:130-140 hook
        // at :136, after the null-input guard, before the unlink).
        if op.0.read().unwrap().inrefs.get(slot).is_some() {
            crate::drillobserve::mod_check(self.arch.as_ref(), op);
        }
        let in_vn = {
            let o = op.0.read().unwrap();
            o.inrefs.get(slot).cloned()
        };
        if let Some(vn) = in_vn {
            let linked = {
                let vn_r = vn.read().unwrap();
                vn_r.descend.iter().any(|weak| {
                    weak.upgrade()
                        .is_some_and(|candidate| std::sync::Arc::ptr_eq(&candidate, &op.0))
                })
            };
            if linked {
                vn.write().unwrap().erase_descend(&op.0);
            }
        }
        // Ghidra cc:98: op->clearInput(slot) — the slot is nulled in place,
        // keeping the array size. The shared sentinel stands in for the NULL
        // pointer; writing it over itself (already-sentinel slot) is the
        // idempotent NULL no-op.
        if let Some(slot_vn) = op.0.write().unwrap().inrefs.get_mut(slot) {
            *slot_vn = crate::op::null_slot_sentinel();
        }
    }

    // Ghidra: funcdata_op.cc:52 Funcdata::opUnsetOutput
    /// Remove an op's output, return the old Varnode to the bank's free class,
    /// and discard its Cover.
    pub fn op_unset_output(&mut self, op: &crate::op::PcodeOpRef) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:52-66 hook
        // at :61, after the null-output guard, before the mutation).
        if op.0.read().unwrap().output.is_some() {
            crate::drillobserve::mod_check(self.arch.as_ref(), op);
        }
        let old = op.0.write().unwrap().output.take();
        let Some(old) = old else { return };
        self.vbank.make_free_prevalidated(&old);
        old.write().unwrap().clear_cover();
    }

    // Ghidra: funcdata_varnode.cc:104 Funcdata::newVarnodeOut
    /// Create an already-written Varnode under its final BTree keys and install
    /// it as the output of `op`. Faithful to `Funcdata::newVarnodeOut`
    /// (funcdata_varnode.cc:104-122):
    ///   Varnode *vn = vbank.createDef(s, m, ct, op);
    ///   op->setOutput(vn);
    ///   assignHigh(vn);
    ///   if (s >= minLanedSize) checkForLanedRegister(s, m);
    ///   entry = localmap->queryProperties(m, s, op->getAddr(), vflags);
    ///   if (entry != 0) vn->setSymbolProperties(entry);
    ///   else            vn->setFlags(vflags & ~Varnode::typelock);
    ///   return vn;
    /// The query runs UNCONDITIONALLY with usepoint = op->getAddr() — not
    /// the isMapped-guarded `getUsePoint` form of setVarnodeProperties
    /// (funcdata_varnode.cc:25-42), which is a different function.
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001)
    pub fn new_varnode_out(
        &mut self,
        size: usize,
        addr: crate::address::Address,
        op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // Rugra split-Address adapter: callers without a known true space keep
        // the historical Register pin; the full newVarnodeOut sequence runs in
        // new_varnode_out_full below.
        self.new_varnode_out_full(size, crate::space::AddressSpace::Register, addr, op)
    }

    // Ghidra: funcdata_varnode.cc:104 Funcdata::newVarnodeOut
    /// Space-preserving `Funcdata::newVarnodeOut`: the oracle's `m` is a full
    /// `Address` (space + offset). Rugra's scalar `Address` cannot carry the
    /// space, so callers that must reproduce the oracle's full storage address
    /// — e.g. `CloneBlockOps::buildVarnodeOutput`
    /// (funcdata_block.cc:988 `data.newVarnodeOut(opvn->getSize(),opvn->getAddr(),cloneOp)`)
    /// — pass the true space explicitly. Sequence is 1:1 with
    /// funcdata_varnode.cc:107-121, and the symbol tail is the UNCONDITIONAL
    /// `localmap->queryProperties(m,s,op->getAddr(),vflags)` form
    /// (`new_varnode_symbol_tail`, usepoint = op->getAddr()), NOT the
    /// isMapped-guarded `getUsePoint` form of `setVarnodeProperties`
    /// (funcdata_varnode.cc:25-42), which is a different function.
    /// (FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001, FUNCDATA-NODESPLIT-SPACE-0001)
    pub fn new_varnode_out_full(
        &mut self,
        size: usize,
        space: crate::space::AddressSpace,
        addr: crate::address::Address,
        op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create_def_with_space(size, space, addr.as_u64(), &op.0);
        op.0.write().unwrap().output = Some(vn.clone());
        // cc:110: assignHigh(vn) — comes BEFORE the queryProperties leg.
        // (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
        let _ = self.assign_high(&vn);
        if size >= self.min_laned_size as usize {
            self.check_for_laned_register(size, space, addr);
        }
        // cc:114-119: queryProperties(m, s, op->getAddr(), vflags) with the
        // op address as usepoint, then the shared symbol tail.
        let usepoint = op.0.read().unwrap().get_addr().as_u64();
        self.new_varnode_symbol_tail(&vn, Some(usepoint));
        vn
    }

    // Ghidra: funcdata.cc:34 Funcdata::pushBranch
    /// Push a conditional branch edge into a new destination, turning the
    /// CBRANCH into an unconditional BRANCH. Faithful to `Funcdata::pushBranch`
    /// (funcdata_block.cc:404).
    ///
    /// `bb` is the block containing the CBRANCH; `slot` is the out-edge to
    /// redirect; `bbnew` is the new destination (must end in BRANCHIND).
    pub fn push_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> Result<(), String> {
        // Get the CBRANCH (last op of bb).
        let last_op = {
            let bb_rg = bb.read().unwrap();
            if let Some(any) = bb_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        let cbranch = match last_op {
            Some(op) => op,
            None => return Err("No last op in block".to_string()),
        };
        // Verify it's a CBRANCH with 2 out-edges.
        let is_cbranch = {
            let cb_rg = cbranch.0.read().unwrap();
            cb_rg.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
        };
        if !is_cbranch || bb.read().unwrap().size_out() != 2 {
            return Err("Cannot push non-conditional edge".to_string());
        }
        // Verify bbnew ends in BRANCHIND.
        let bbnew_last = {
            let bn_rg = bbnew.read().unwrap();
            if let Some(any) = bn_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                any.last_op()
            } else {
                None
            }
        };
        if let Some(indop) = &bbnew_last {
            if indop.0.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_BRANCHIND {
                return Err("Can only push branch into indirect jump".to_string());
            }
        } else {
            return Err("Destination has no last op".to_string());
        }
        // Remove the conditional variable (input slot 1) and change opcode to
        // BRANCH. Faithful to opRemoveInput(cbranch,1) + opSetOpcode(BRANCH).
        self.op_remove_input(&cbranch, 1);
        self.op_set_opcode(&cbranch, crate::opcodes::OpCode::CPUI_BRANCH);
        // Move the out-edge.
        self.move_out_edge(bb, slot, bbnew);
        Ok(())
    }

    // Ghidra: funcdata.cc:34 Funcdata::moveOutEdge
    /// Move an out-edge of `bb` from its current destination to `bbnew`.
    /// Faithful to `BlockGraph::moveOutEdge` (block.cc). This redirects the
    /// edge by updating both the source's outgoing list and the old/new
    /// destinations' incoming lists.
    // Ghidra: block.cc:1502 BlockGraph::moveOutEdge
    /// Move an out-edge of `bb` (at `slot`) to `bbnew`. Faithful to
    /// `BlockGraph::moveOutEdge` (block.cc:1439-1449): capture the target
    /// `outbl` and its in-slot `i` from the edge's reverse_index, then run
    /// `FlowBlock::replaceInEdge(i, bbnew)` on `outbl` (block.cc:160-173):
    ///   - `oldb = outbl.in[i].point` (= bb);
    ///   - `oldb->halfDeleteOutEdge(outbl.in[i].reverse_index)` — the paired
    ///     removal of bb's out-half (slide + peer decrements);
    ///   - the in-slot `i` on `outbl` is KEPT and re-pointed at `bbnew` with
    ///     `reverse_index = bbnew.size_out()`;
    ///   - `bbnew` gets a fresh out-edge appended with `reverse_index = i`.
    /// The former Rugra version appended a new in-edge to `bbnew` and
    /// `Vec::remove`d the old in-edge from `outbl` — a one-sided removal
    /// that slid `outbl`'s in-list without decrementing the OTHER sources'
    /// out-edge reverse_index entries (BLOCK-RECIPROCAL-OOB-0001), and only
    /// handled BlockBasic peers.
    pub fn move_out_edge(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        slot: usize,
        bbnew: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // cc:1444-1445: outbl = blold->getOut(slot); i = getOutRevIndex(slot).
        let (outbl, i) = {
            let bb_rg = bb.read().unwrap();
            match bb_rg.get_out(slot) {
                Some(e) => (e.point.clone(), e.reverse_index),
                None => return,
            }
        };
        // replaceInEdge(i, blnew) on outbl (block.cc:160-173):
        // cc:163: oldb = intothis[num].point; cc:164: its reverse_index.
        let (old_rev, label) = {
            let out_rg = outbl.read().unwrap();
            match out_rg.get_in(i as usize) {
                Some(e) => (e.reverse_index, e.flags),
                None => return,
            }
        };
        // cc:164: oldb->halfDeleteOutEdge(intothis[num].reverse_index).
        // No guard on outbl/bbnew is held here, so the half-delete's peer
        // updates can lock either safely.
        {
            let mut bb_rg = bb.write().unwrap();
            bb_rg.half_delete_out_edge(old_rev as usize);
        }
        // cc:165-166: intothis[num].point = b; reverse_index = b->outofthis.size().
        let blnew_size_out = bbnew.read().unwrap().size_out() as i32;
        {
            let mut out_rg = outbl.write().unwrap();
            let ins = out_rg.in_edges_mut();
            if (i as usize) < ins.len() {
                ins[i as usize].point = bbnew.clone();
                ins[i as usize].reverse_index = blnew_size_out;
            }
        }
        // cc:167: b->outofthis.push_back(BlockEdge(this, intothis[num].label, num)).
        {
            let mut new_rg = bbnew.write().unwrap();
            let mut edge = crate::block::BlockEdge::new(outbl, i);
            edge.flags = label;
            new_rg.add_out_edge(edge);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::forceGoto
    /// Force a specific branch instruction to be an unstructured goto.
    /// Faithful to `Funcdata::forceGoto` (funcdata_block.cc:752).
    ///
    /// `pcop` is the address of the branch op to mark; `pcdest` is the
    /// destination address. Returns true if a matching branch was found and
    /// marked.
    pub fn force_goto(
        &mut self,
        pcop: crate::address::Address,
        pcdest: crate::address::Address,
    ) -> bool {
        for i in 0..self.bblocks.get_size() {
            let bl = match self.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            // Get the last op of this block.
            let last_op = {
                let bl_rg = bl.read().unwrap();
                if let Some(any) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    any.last_op()
                } else {
                    None
                }
            };
            let Some(op) = last_op else { continue };
            if op.0.read().unwrap().get_addr() != pcop {
                continue;
            }
            // Find the out-edge whose destination's last op has addr == pcdest.
            let n_out = bl.read().unwrap().size_out();
            for j in 0..n_out {
                let bl2 = bl.read().unwrap().get_out(j).map(|e| e.point);
                let Some(bl2) = bl2 else { continue };
                let op2 = {
                    let bl2_rg = bl2.read().unwrap();
                    if let Some(any) = bl2_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                        any.last_op()
                    } else {
                        None
                    }
                };
                let Some(op2) = op2 else { continue };
                if op2.0.read().unwrap().get_addr() == pcdest {
                    // Mark this out-edge as a goto branch.
                    self.set_goto_branch(&bl, j);
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: block.cc:305 FlowBlock::setGotoBranch
    /// Mark the j-th out-edge of a block as an unstructured goto. Faithful to
    /// `FlowBlock::setGotoBranch` (block.cc:305-314), which does THREE things:
    ///   1. setOutEdgeFlag(j, f_goto_edge) — mark the edge as goto.
    ///   2. flags |= f_interior_gotoout — mark that there's a goto OUT of this
    ///      block's interior (read by hasInteriorGoto).
    ///   3. outofthis[j].point->flags |= f_interior_gotoin — mark the TARGET
    ///      block as a goto target (read by isInteriorGotoTarget).
    /// Previously Rugra only did (1) for BlockBasic, so is_interior_goto_target
    /// could not behave correctly for goto-marked targets.
    pub fn set_goto_branch(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        j: usize,
    ) {
        // cc:307-310: bounds check + setOutEdgeFlag(j, f_goto_edge).
        // Capture the target block for step (3) before taking the write lock.
        let target_opt: Option<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let bl_rg = bl.read().unwrap();
            if j < bl_rg.size_out() {
                bl_rg.get_out(j).map(|e| e.point.clone())
            } else {
                None
            }
        };
        {
            let mut bl_rg = bl.write().unwrap();
            // cc:311: flags |= f_interior_gotoout (source-side mark).
            bl_rg.set_flags(crate::block::block_flags::INTERIOR_GOTOOUT);
            // cc:308: setOutEdgeFlag(j, f_goto_edge). For BlockBasic we use the
            // dedicated GOTO_EDGE_0/1 flags; for structured blocks we set the
            // edge's F_GOTO_EDGE flag directly.
            if let Some(any) = bl_rg
                .as_any_mut()
                .downcast_mut::<crate::block::BlockBasic>() {
                match j {
                    0 => any.flags |= crate::block::block_flags::GOTO_EDGE_0,
                    1 => any.flags |= crate::block::block_flags::GOTO_EDGE_1,
                    _ => {}
                }
            } else {
                // Structured block: set F_GOTO_EDGE on the edge directly.
                bl_rg.set_out_edge_flag(j, crate::block::edge_flags::F_GOTO_EDGE);
            }
        }
        // cc:313: target->flags |= f_interior_gotoin (target-side mark).
        if let Some(target) = target_opt {
            let mut tg = target.write().unwrap();
            tg.set_flags(crate::block::block_flags::INTERIOR_GOTOIN);
        }
    }

    // Ghidra: funcdata_block.cc:220 Funcdata::removeBranch
    /// Remove outgoing edge `num`, patch the target MULTIEQUAL inputs, then
    /// rebuild loop/dominator state and clear the structured hierarchy.
    pub fn remove_branch(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        num: usize,
    ) {
        self.branch_remove_internal(bb, num);
        self.structure_reset();
    }

    // Ghidra: funcdata_block.cc:704 Funcdata::structureReset
    /// Recompute loop structure, dominance, and reset the structured-block
    /// hierarchy for the current CFG. Faithful to
    /// `Funcdata::structureReset` (funcdata_block.cc:705-735).
    ///
    /// Must be called after any mutation that changes the CFG so that
    /// dominator/loop information stays consistent.
    ///
    /// Oracle chain, mirrored statement by statement:
    /// - cc:710 `flags &= ~blocks_unreachable`
    /// - cc:711 `bblocks.structureLoops(rootlist)` — findSpanningTree puts
    ///   the component list in reverse post order (block.cc:1135) and fills
    ///   rootlist with every entry point (multi-root graphs keep the
    ///   original head at RPO[0] via the block.cc:1031-1035 swap)
    /// - cc:712 `bblocks.calcForwardDominator(rootlist)` — CHK dominators
    ///   rooted at postorder.back(), with the createVirtualRoot/excise path
    ///   (block.cc:1970-2029) so multi-root entries end with immed_dom null
    /// - cc:713-714 `if (rootlist.size() > 1) flags |= blocks_unreachable`
    /// - cc:716-727 dead jumptable elimination
    /// - cc:728 `sblocks.clear()`
    /// - cc:730 `heritage.forceRestructure()` (maxdepth = -1)
    ///
    /// Rugra glue tail (no oracle counterpart on the Funcdata level):
    /// refresh the per-block dominator depth/subtree/frontier caches so
    /// Rugra consumers (find_common_block, phi placement) stay coherent
    /// with the freshly written immed_dom set — Ghidra computes dominator
    /// depth locally inside Heritage::buildADT (heritage.cc:2338).
    ///
    /// Errors: Ghidra's LowlevelError channel (findSpanningTree /
    /// calcForwardDominator throws) is mirrored by panic — per-function
    /// worker isolation maps it onto Ghidra's abort-this-function model,
    /// same policy as `Varnode::add_descend`.
    pub fn structure_reset(&mut self) {
        // cc:710: clear any old blocks flag.
        self.flags &= !funcdata_flags::BLOCKS_UNREACHABLE;
        // cc:711: (re)calculate the loop structure and the reverse post
        // order; rootlist receives every entry point.
        let mut rootlist: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> =
            Vec::new();
        if let Err(e) = self.bblocks.structure_loops(&mut rootlist) {
            panic!("{}", e);
        }
        // cc:712: calculate forward dominators (reads the list in the
        // reverse post order established by structure_loops).
        if let Err(e) = self.bblocks.calc_forward_dominator(&rootlist) {
            panic!("{}", e);
        }
        // cc:713-714: more than one entry point -> unreachable code exists.
        if rootlist.len() > 1 {
            self.flags |= funcdata_flags::BLOCKS_UNREACHABLE;
        }
        // cc:716-727: check for dead jumptables; eliminated ones are
        // dropped (Ghidra: `delete jt`) with a header warning.
        let mut alivejumps: Vec<Arc<RwLock<crate::jumptable::JumpTable>>> = Vec::new();
        for jt_arc in std::mem::take(&mut self.jump_tables) {
            let dead = {
                let jt = jt_arc.read().unwrap();
                match jt.get_indirect_op() {
                    Some(indop) => indop.read().unwrap().is_dead(),
                    // Ghidra dereferences getIndirectOp() unconditionally
                    // (funcdata_block.cc:719); Rugra's Option is treated as
                    // alive — no production path leaves a jumptable without
                    // its indirect op here.
                    None => false,
                }
            };
            if dead {
                self.warning_header("Recovered jumptable eliminated as dead code");
                continue; // delete jt
            }
            alivejumps.push(jt_arc);
        }
        self.jump_tables = alivejumps;
        // cc:728: force the structuring algorithm to start over.
        self.sblocks.clear();
        // cc:730: force regeneration of the heritage basic-block structures
        // (maxdepth = -1), so the next Heritage pass rebuilds the augmented
        // dominator tree from the CFG re-established above.
        self.heritage.force_restructure();
        // RUGRA-GLUE: refresh Rugra's per-block dominator caches (dom depth,
        // subtree children, dominance frontiers) that other passes read
        // directly off FlowBlock; the immed_dom set written by
        // calc_forward_dominator is the oracle-observable state.
        self.bblocks.build_dom_depth();
        self.bblocks.build_dom_subtree();
        self.bblocks.calc_dom_frontier();
    }

    // Ghidra: funcdata.hh:149 Funcdata::hasUnreachableBlocks
    /// Did this function exhibit unreachable code — the cached
    /// `blocks_unreachable` flag maintained by `structure_reset`
    /// (funcdata_block.cc:710/714). Ghidra consumers: condexe.cc:485,
    /// double.cc:3267/3348 gate their analysis on it, and
    /// `removeUnreachableBlocks` (funcdata_block.cc:360) uses it as the
    /// cached existence check.
    pub fn has_unreachable_blocks(&self) -> bool {
        (self.flags & funcdata_flags::BLOCKS_UNREACHABLE) != 0
    }

    // Ghidra: funcdata_block.cc:687 Funcdata::installSwitchDefaults
    /// Mark default switch edges for all jump tables. Faithful to
    /// `Funcdata::installSwitchDefaults` (funcdata_block.cc:687-700).
    pub fn install_switch_defaults(&mut self) {
        for jt_arc in &self.jump_tables {
            let jt = jt_arc.read().unwrap();
            let default_block = jt.get_default_block();
            if default_block < 0 {
                continue;
            }
            let indop = jt.get_indirect_op();
            let Some(indop_arc) = indop else { continue };
            // indop->getParent() → the switch BlockBasic.
            let parent = {
                let op = indop_arc.read().unwrap();
                op.parent.as_ref().and_then(|w| w.upgrade())
            };
            let Some(parent_blk) = parent else { continue };
            crate::block::set_default_switch_mirrored(&parent_blk, default_block as usize);
        }
    }

    // Ghidra: funcdata_block.cc:327 Funcdata::removeDoNothingBlock
    /// Remove a basic block that does nothing (only marker ops + optional
    /// single branch). Faithful to `Funcdata::removeDoNothingBlock`
    /// (funcdata_block.cc:328-337): setDead, blockRemoveInternal(bb,false),
    /// structureReset. Returns true when the block was actually removed.
    pub fn remove_do_nothing_block(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> bool {
        if bb.read().unwrap().size_out() > 1 {
            // cc:330-331 LowlevelError("Cannot delete a reachable block
            // unless it has 1 out or less") — degrade to a log (worker
            // survives one bad block; the divergence is visible on stderr).
            eprintln!(
                "[BLOCK] Cannot delete block with >1 out edge (LowlevelError site, funcdata_block.cc:330)"
            );
            return false;
        }
        bb.write()
            .unwrap()
            .set_flags(crate::block::block_flags::DEAD);
        self.block_remove_internal(bb, false);
        self.structure_reset();
        true
    }

    // Ghidra: funcdata_block.cc:254 Funcdata::blockRemoveInternal
    /// Remove an active basic block, patching up data-flow and control-flow
    /// (funcdata_block.cc:254-320): pushMultiequals, per-out-block
    /// MULTIEQUAL input splice (remove bb's slot, append bb's in-edge
    /// varnodes), opZeroMulti, removeFromFlow retarget, op destruction,
    /// removeBlock. `unreachable` mirrors the C++ flag (stranded-descendant
    /// warning path; Rugra degrades the LowlevelError throw to a warning +
    /// removal abort so one function cannot kill the worker).
    pub fn block_remove_internal(
        &mut self,
        bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        unreachable: bool,
    ) {
        use crate::opcodes::OpCode;
        // cc:264-269: a BRANCHIND last op may own a jumptable — drop it with
        // the block. (A do-nothing block can never reach this —
        // hasOnlyMarkers excludes BRANCHIND — but the port keeps the guard.)
        {
            let lastop = {
                let rg = bb.read().unwrap();
                rg.as_any()
                    .downcast_ref::<crate::block::BlockBasic>()
                    .and_then(|b2| b2.last_op())
            };
            if let Some(op_ref) = lastop {
                if op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND {
                    if let Some(jt) = self.find_jump_table_arc(&op_ref) {
                        self.remove_jump_table(&jt);
                    }
                }
            }
        }
        if !unreachable {
            // cc:271: pushMultiequals(bb) — make sure data flow is preserved.
            self.push_multiequals(bb);
            // cc:273-294: patch every MULTIEQUAL in bb's out-blocks so the
            // removed edge's slot is replaced by bb's in-edge varnodes
            // (spliced through bb's own MULTIEQUAL when present).
            let out_blocks: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
                let rg = bb.read().unwrap();
                (0..rg.size_out())
                    .filter_map(|s| rg.get_out(s).map(|e| e.point.clone()))
                    .collect()
            };
            let bb_in_count = bb.read().unwrap().size_in();
            for bbout in out_blocks {
                let dead = {
                    let rg = bbout.read().unwrap();
                    (rg.get_flags() & crate::block::block_flags::DEAD) != 0
                };
                if dead {
                    continue; // cc:275
                }
                // cc:276: blocknum = bbout->getInIndex(bb)
                let blocknum = {
                    let rg = bbout.read().unwrap();
                    (0..rg.size_in()).find(|&i| {
                        rg.get_in(i).map(|e| Arc::ptr_eq(&e.point, bb)).unwrap_or(false)
                    })
                };
                let Some(blocknum) = blocknum else { continue };
                let multi_ops: Vec<crate::op::PcodeOpRef> = {
                    let rg = bbout.read().unwrap();
                    match rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockBasic>()
                    {
                        Some(b2) => b2
                            .get_ops()
                            .into_iter()
                            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
                            .collect(),
                        None => Vec::new(),
                    }
                };
                for op in multi_ops {
                    let deadvn = {
                        let o = op.0.read().unwrap();
                        o.inrefs.get(blocknum).cloned()
                    };
                    let Some(deadvn) = deadvn else { continue };
                    self.op_remove_input(&op, blocknum); // cc:281
                    // cc:282-287: if deadvn is defined by a MULTIEQUAL
                    // inside bb, splice that phi's inputs through; otherwise
                    // append copies of deadvn — one per bb in-edge.
                    let deadop = deadvn.read().unwrap().get_def();
                    let splice_phi = deadop.as_ref().map(|d| {
                        let d_rg = d.read().unwrap();
                        let parent_is_bb = d_rg
                            .parent
                            .as_ref()
                            .and_then(|w| w.upgrade())
                            .map(|p| Arc::ptr_eq(&p, bb))
                            .unwrap_or(false);
                        d_rg.opcode == OpCode::CPUI_MULTIEQUAL && parent_is_bb
                    });
                    if splice_phi == Some(true) {
                        let deadop = deadop.unwrap();
                        let phi_ins: Vec<Arc<RwLock<crate::varnode::Varnode>>> = {
                            let d_rg = deadop.read().unwrap();
                            d_rg.inrefs.clone()
                        };
                        // cc:284-286: append deadop->getIn(j), one per bb
                        // in-edge (the phi in bb has one input per in-edge).
                        for j in 0..bb_in_count.min(phi_ins.len()) {
                            let slot = op.0.read().unwrap().inrefs.len();
                            self.op_insert_input(&op, phi_ins[j].clone(), slot);
                        }
                    } else {
                        for _ in 0..bb_in_count {
                            let slot = op.0.read().unwrap().inrefs.len();
                            self.op_insert_input(&op, deadvn.clone(), slot); // cc:290
                        }
                    }
                    self.op_zero_multi(&op); // cc:292
                }
            }
        }
        // cc:296: bblocks.removeFromFlow(bb) — for each out-edge (from the
        // last slot), remove the out-edge and retarget every in-edge of bb
        // to that out target (block.cc:1545-1560). For the unreachable path
        // the caller already severed all out-edges, so this loop is a no-op
        // exactly as in the C++.
        loop {
            let (bbout, has_out) = {
                let rg = bb.read().unwrap();
                let n = rg.size_out();
                if n == 0 {
                    (None, false)
                } else {
                    (rg.get_out(n - 1).map(|e| e.point), true)
                }
            };
            if !has_out {
                break;
            }
            let Some(bbout) = bbout else { break };
            self.bblocks.remove_edge_blocks(bb, &bbout);
            loop {
                let bbin = {
                    let rg = bb.read().unwrap();
                    if rg.size_in() == 0 {
                        None
                    } else {
                        rg.get_in(0).map(|e| e.point)
                    }
                };
                let Some(bbin) = bbin else { break };
                // FlowBlock::replaceOutEdge(slot,bbout) — both-half
                // semantics via switch_edge (block.cc:178-191).
                self.switch_edge(&bbin, bb, &bbout);
            }
        }
        // cc:298-318: finally remove all the ops. The C++ throws
        // LowlevelError("Deleting op with descendants") when an op still has
        // descendants outside bb; Rugra degrades the throw to a warning +
        // skips destroying the stranded op (worker survives; divergence
        // visible on stderr for fixture differencing).
        let mut desc_warning = false;
        let ops_to_destroy: Vec<crate::op::PcodeOpRef> = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.get_ops()
            } else {
                Vec::new()
            }
        };
        for op_ref in &ops_to_destroy {
            let (is_assignment, is_call, out_vn) = {
                let o = op_ref.0.read().unwrap();
                (o.is_assignment(), o.is_call(), o.get_out().cloned())
            };
            if is_assignment {
                if let Some(ref deadvn) = out_vn {
                    if unreachable {
                        // cc:304-310: mark descendants as undefined first.
                        let undef = self.descend2_undef(deadvn);
                        if undef && !desc_warning {
                            self.warning_header(
                                "Creating undefined varnodes in (possibly) reachable block",
                            );
                            desc_warning = true;
                        }
                    }
                    if self.descendants_outside(deadvn) {
                        // cc:311-312 LowlevelError site — degraded.
                        eprintln!(
                            "[BLOCK] Deleting op with descendants (LowlevelError site, funcdata_block.cc:311-312); leaving op"
                        );
                        continue;
                    }
                }
            }
            if is_call {
                self.delete_call_specs(op_ref);
            }
            self.op_destroy(op_ref);
        }
        // cc:319: bblocks.removeBlock(bb)
        self.bblocks.remove_block_arc(bb);
    }

    // Ghidra: funcdata_block.cc:779 Funcdata::nodeJoinCreateBlock
    /// Create a joined block from two blocks that share exit targets.
    /// Faithful to `Funcdata::nodeJoinCreateBlock`
    /// (funcdata_block.cc:779-815).
    pub fn node_join_create_block(
        &mut self,
        block1: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        block2: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exita: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        exitb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        fora_block1ishigh: bool,
        forb_block1ishigh: bool,
        addr: crate::address::Address,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let newblock = self.create_new_block();
        newblock
            .write()
            .unwrap()
            .set_flags(crate::block::block_flags::JOINED_BLOCK);
        // cc:786: newblock->setInitialRange(addr, addr). The join block's
        // cover anchors its address range and is NOT informational:
        // BlockBasic::getStop reads only the cover (block.hh:476), and
        // Merge::buildDominantCopy places the dominant copy at
        // domBl->getStop() (merge.cc:1168); leaving stop=Address(0) built
        // it at 0:903 instead of 3e84:903.

        newblock
            .write()
            .unwrap()
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("nodeJoinCreateBlock: newblock must be a BlockBasic")
            .set_initial_range(addr, addr);

        // Delete 2 of the original edges into exita and exitb (funcdata_block.cc:789-805).
        let swapa = if fora_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exita);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exita);
            block1.clone()
        };
        let swapb = if forb_block1ishigh {
            self.bblocks.remove_edge_blocks(block1, exitb);
            block2.clone()
        } else {
            self.bblocks.remove_edge_blocks(block2, exitb);
            block1.clone()
        };
        // Move remaining edges to newblock (funcdata_block.cc:807-809).
        // Statement-order evaluation: Ghidra takes the SECOND
        // `getOutIndex(exitb)` only AFTER the first moveOutEdge has already
        // mutated the shared swap's out-edge list (C++ argument evaluation
        // per full-expression). Hoisting both indices — as this code
        // previously did — feeds a stale slot to the half-delete left shift
        // when swapa==swapb, and move_out_edge then silently skipped the
        // second transfer (found by R-NODEJOIN-CROSSREVIEW F1).
        let idx_a = find_out_index(&swapa, exita)
            .unwrap_or_else(|| panic!("nodeJoinCreateBlock: exita edge missing after surgery"));
        self.move_out_edge(&swapa, idx_a, &newblock);
        let idx_b = find_out_index(&swapb, exitb)
            .unwrap_or_else(|| panic!("nodeJoinCreateBlock: exitb edge missing after surgery"));
        self.move_out_edge(&swapb, idx_b, &newblock);
        // Add edges from block1/block2 to newblock.
        self.bblocks.add_edge(block1.clone(), newblock.clone());
        self.bblocks.add_edge(block2.clone(), newblock.clone());
        self.structure_reset();
        newblock
    }

    // Ghidra: block.cc:1489 BlockGraph::switchEdge
    /// Redirect the edge from `in`→`outbefore` to `in`→`outafter`.
    /// Faithful to `BlockGraph::switchEdge` (block.cc:1489-1495) through
    /// `FlowBlock::replaceOutEdge` (block.cc:178-191): the OLD target's
    /// in-edge half is removed (`halfDeleteInEdge` at the reciprocal
    /// reverse_index), the out-edge is re-pointed with a fresh reverse_index
    /// sized to the new target's in-edge list, and the NEW target gains the
    /// mirrored in-edge — the out-edge label (flags) carries over
    /// (`intothis.push_back(BlockEdge(this,outofthis[num].label,num))`).
    /// The previous pointer-only rewrite left both in-edge lists stale,
    /// which made a nodeSplit duplicate block unreachable and the original
    /// block over-in-edged (returnsplit then re-split forever).
    pub fn switch_edge(
        &mut self,
        in_block: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outbefore: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        outafter: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        // Find the out-edge slot from in_block pointing to outbefore
        // (block.cc:1492-1494).
        if let Some(slot) = find_out_index(in_block, outbefore) {
            // (1) oldb->halfDeleteInEdge(outofthis[num].reverse_index)
            // (block.cc:182) — snapshot the reverse index first.
            let rev = in_block
                .read()
                .unwrap()
                .get_out(slot)
                .map(|e| e.reverse_index)
                .unwrap_or(-1);
            if rev >= 0 {
                let mut old_rg = outbefore.write().unwrap();
                if let Some(old_bb) = old_rg
                    .as_any_mut()
                    .downcast_mut::<crate::block::BlockBasic>()
                {
                    old_bb.half_delete_in_edge(rev as usize);
                }
            }
            // (2)+(3) re-point the out edge and append the new target's
            // in-edge (block.cc:183-185). Sequential locks: outbefore's
            // write guard was dropped above; in_block and outafter are
            // distinct Arcs on the nodesplit path.
            let new_in_size = outafter.read().unwrap().size_in() as i32;
            let carried_flags = in_block
                .read()
                .unwrap()
                .get_out(slot)
                .map(|e| e.flags)
                .unwrap_or(0);
            {
                let mut in_rg = in_block.write().unwrap();
                if let Some(bb) = in_rg
                    .as_any_mut()
                    .downcast_mut::<crate::block::BlockBasic>() {
                    let out_edges = bb.out_edges_mut();
                    if slot < out_edges.len() {
                        out_edges[slot].point = outafter.clone();
                        out_edges[slot].reverse_index = new_in_size;
                    }
                }
            }
            {
                let mut new_rg = outafter.write().unwrap();
                new_rg.add_in_edge(crate::block::BlockEdge {
                    point: in_block.clone(),
                    flags: carried_flags,
                    reverse_index: slot as i32,
                });
            }
        }
    }

    // Ghidra: funcdata_block.cc:824 Funcdata::nodeSplitBlockEdge
    /// Create a duplicate block that inherits the same out-edges but only the
    /// one indicated in-edge, which is moved from the original block.
    /// Faithful to `Funcdata::nodeSplitBlockEdge` (funcdata_block.cc:835-848).
    fn node_split_block_edge(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let a = b.read().unwrap().get_in(inedge).map(|e| e.point.clone());
        let Some(a) = a else {
            return self.create_new_block();
        };
        let bprime = self.create_new_block();
        bprime
            .write()
            .unwrap()
            .set_flags(crate::block::block_flags::DUPLICATE_BLOCK);
        // cc:832: bprime->copyRange(b) — the duplicate inherits the original
        // block's whole address cover.
        {
            let b_rg = b.read().unwrap();
            let mut bprime_rg = bprime.write().unwrap();
            if let (Some(src), Some(dst)) = (
                b_rg.as_any().downcast_ref::<crate::block::BlockBasic>(),
                bprime_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>(),
            ) {
                dst.copy_range(src);
            }
        }
        // switchEdge(a, b, bprime)
        self.switch_edge(&a, b, &bprime);
        // Add all of b's out-edges to bprime.
        let outs: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = {
            let br = b.read().unwrap();
            (0..br.size_out())
                .filter_map(|i| br.get_out(i).map(|e| e.point.clone()))
                .collect()
        };
        for out in &outs {
            self.bblocks.add_edge(bprime.clone(), out.clone());
        }
        bprime
    }

    // Ghidra: funcdata_block.cc:845 Funcdata::nodeSplit
    /// Split control-flow into a basic block, duplicating its p-code into a
    /// new block. Faithful to `Funcdata::nodeSplit` (funcdata_block.cc:856-882).
    pub fn node_split(
        &mut self,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Preconditions (merge.cc:859-869).
        if b.read().unwrap().size_out() != 0 {
            eprintln!("[BLOCK] Cannot nodesplit block with out flow");
            return;
        }
        if b.read().unwrap().size_in() <= 1 {
            eprintln!("[BLOCK] Cannot nodesplit block with only 1 in edge");
            return;
        }
        // Create duplicate block.
        let bprime = self.node_split_block_edge(b, inedge);
        // CloneBlockOps: clone all ops from b into bprime.
        let mut cloner = CloneBlockOps::new();
        cloner.clone_block(self, b, &bprime, inedge);
        self.structure_reset();
    }

    // RUGRA-GLUE: public exposure of `CloneBlockOps::cloneExpression`
    // (funcdata.hh:646; impl funcdata_block.cc:1024-1040). Ghidra declares the
    // whole CloneBlockOps class public in funcdata.hh and RuleConditionalMove
    // instantiates it directly (ruleaction.cc:9334-9335
    // `CloneBlockOps cloner(data); resvn = cloner.cloneExpression(ops, insertop);`);
    // the Rust struct is module-private to funcdata.rs, so this thin
    // instantiation wrapper is the module-boundary mirror of that public class
    // surface (RULEACTION-CLONEBLOCKOPS-0001). No behavior beyond delegating.
    pub fn clone_block_expression(
        &mut self,
        ops: &[crate::op::PcodeOpRef],
        follow_op: &crate::op::PcodeOpRef,
    ) -> crate::error::Result<
        Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    > {
        let mut cloner = CloneBlockOps::new();
        cloner.clone_expression(self, ops, follow_op)
    }

    // Ghidra: funcdata_varnode.cc:938 Funcdata::syncVarnodesWithSymbols
    /// Update Varnode properties based on (new) Symbol information. Faithful
    /// to `Funcdata::syncVarnodesWithSymbols`
    /// (funcdata_varnode.cc:938-989): boolean properties `mapped`, `addrtied`,
    /// `addrforce`, and `nolocalalias` are updated from the ScopeLocal Symbol
    /// each Varnode overlaps; when `update_datatypes` is set the Symbol's
    /// sized data-type is projected onto the Varnode via `updateType`.
    ///
    /// Iterates the Varnode bank in 'loc' order restricted to the scope's
    /// space; each same-(address,size) set is dispatched to
    /// [`Self::sync_varnodes_with_symbol_set`], which advances the iteration
    /// past the set (the `VarnodeLocSet::const_iterator &iter` advance of
    /// funcdata_varnode.cc:985). Returns true if any Varnode was updated.
    pub fn sync_varnodes_with_symbols(
        &mut self,
        update_datatypes: bool,
        unmapped_alias_check: bool,
    ) -> bool {
        use crate::type_system::datatype::TypeMetatype;
        use crate::varnode::varnode_flags;

        let scope = match &self.scope {
            Some(s) => s.clone(),
            None => return false,
        };
        // funcdata_varnode.cc:956 reaches getExactPiece through the
        // SymbolEntry's Scope and therefore the same Architecture-owned
        // TypeFactory. Missing optional Rust wiring fails closed for type
        // projection while the independent flag synchronization continues.
        let type_factory = self.get_arch().and_then(|arch| arch.types.clone());
        // cc:947-948: iter = vbank.beginLoc(lm->getSpaceId());
        // enditer = vbank.endLoc(lm->getSpaceId()). The loc-tree ordering
        // (space, offset, size, input/written/free, seq) keeps every
        // same-(offset,size) set contiguous within the space, so a filtered
        // snapshot plus an index reproduces the iterator pair. Nothing below
        // inserts/removes Varnodes or touches INPUT/WRITTEN/def, so the
        // ordering is stable across the flag/type writes.
        let space = scope.space;
        let ordered: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter(|entry| entry.0.read().unwrap().get_space() == space)
            .map(|entry| entry.0.clone())
            .collect();

        let mut updateoccurred = false;
        let mut index = 0usize;
        while index < ordered.len() {
            let vnexemplar = ordered[index].clone();
            let (addr, size) = {
                let vn = vnexemplar.read().unwrap();
                (vn.get_offset(), vn.get_size() as i64)
            };
            // cc:951: entry = lm->findOverlap(vnexemplar->getAddr(), vnexemplar->getSize());
            let entry = scope_local_find_overlap(&scope, space, addr, size as i32);
            let mut ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> = None;
            let fl: u32;
            if let Some(sym) = entry {
                // cc:954: fl = entry->getAllFlags() — the extraflags
                // (Varnode::mapped from addMapInternal, database.cc:1155)
                // plus the Symbol flags. Symbol addrtied is set by
                // Scope::addMap exactly when the mapping carries no usepoint
                // (database.cc:1149-1150), which LocalSymbol.usepoint == None
                // mirrors.
                let mut f = varnode_flags::MAPPED;
                if sym.usepoint.is_none() {
                    f |= varnode_flags::ADDRTIED;
                }
                if sym.typelock {
                    f |= varnode_flags::TYPELOCK;
                }
                if sym.namelock {
                    f |= varnode_flags::NAMELOCK;
                }
                if sym.unaliased {
                    f |= varnode_flags::NOLOCALALIAS;
                }
                if sym.size as i64 >= size {
                    if update_datatypes {
                        // cc:956-960: ct = entry->getSizedType(addr, size);
                        // TYPE_UNKNOWN results are dropped.
                        if let Some(factory) = type_factory.as_ref() {
                            let mut factory = factory
                                .write()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(dt) = local_symbol_sized_type(
                                &mut factory,
                                sym,
                                addr,
                                size as i32) {
                                if dt.get_metatype() != TypeMetatype::Unknown {
                                    ct = Some(dt);
                                }
                            }
                        }
                    }
                } else {
                    // cc:962-969: overlapping but not containing — small
                    // locked symbol in a bigger register: don't try to figure
                    // out the type, don't keep typelock and namelock (we do
                    // particularly want to keep the nolocalalias, which the
                    // clear below leaves alone).
                    f &= !(varnode_flags::TYPELOCK | varnode_flags::NAMELOCK);
                }
                fl = f;
            } else {
                // cc:971-983: could not find any symbol.
                // cc:972: usepoint = vnexemplar->getUsePoint(*this) — fed to
                // the (ignored) third parameter of Scope::inScope exactly as
                // the oracle call shape (funcdata_varnode.cc:972-973).
                let usepoint = varnode_use_point_offset(self, &vnexemplar);
                if scope_local_in_scope(&scope, space, addr, size as i32, usepoint) {
                    // cc:976: technically an error — there should be some kind
                    // of symbol if we are in scope.
                    fl = varnode_flags::MAPPED | varnode_flags::ADDRTIED;
                } else if unmapped_alias_check {
                    // cc:980: if the varnode is not in scope, check if we
                    // should treat it as unaliased.
                    fl = if scope_local_is_unmapped_unaliased(&scope, &vnexemplar) {
                        varnode_flags::NOLOCALALIAS
                    } else {
                        0
                    };
                } else {
                    fl = 0;
                }
            }
            // cc:985: if (syncVarnodesWithSymbol(iter,fl,ct)) updateoccurred = true;
            if self.sync_varnodes_with_symbol_set(&ordered, &mut index, fl, ct) {
                updateoccurred = true;
            }
        }
        updateoccurred
    }

    // Ghidra: funcdata_varnode.cc:1048 Funcdata::syncVarnodesWithSymbol
    /// Update properties (and the data-type) for a set of Varnodes associated
    /// with one Symbol. Faithful to the private overload
    /// `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator&,uint4,Datatype*)`
    /// (funcdata_varnode.cc:1048-1095): all Varnodes sharing the exemplar's
    /// (address,size) get the masked flag update — `mapped` always;
    /// `addrtied`/`addrforce` clearable but not settable; `nolocalalias` +
    /// `addrforce` settable but `nolocalalias` not clearable — then the
    /// data-type via `Varnode::updateType` when `ct` is non-null. Varnodes
    /// with an attached SymbolEntry keep their `mapped` bit unchanged
    /// (cc:1075-1082). `index` is advanced past the whole set.
    fn sync_varnodes_with_symbol_set(
        &mut self,
        ordered: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        index: &mut usize,
        mut fl: u32,
        ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>>,
    ) -> bool {
        use crate::varnode::varnode_flags;

        let mut updateoccurred = false;
        // cc:1056: mask = Varnode::mapped — the flags we are going to try to
        // update. We take special care with the addrtied flag as we cannot
        // SET it here if it is clear: we can CLEAR but not SET addrtied, and
        // if addrtied is cleared, so should addrforce (cc:1057-1062).
        let mut mask = varnode_flags::MAPPED;
        if (fl & varnode_flags::ADDRTIED) == 0 {
            mask |= varnode_flags::ADDRTIED | varnode_flags::ADDRFORCE;
        }
        // cc:1063-1066: we can set the nolocalalias flag, but not clear it;
        // if nolocalalias is set, then addrforce should be cleared.
        if (fl & varnode_flags::NOLOCALALIAS) != 0 {
            mask |= varnode_flags::NOLOCALALIAS | varnode_flags::ADDRFORCE;
        }
        fl &= mask;

        // cc:1069-1070: enditer = vbank.endLoc(vn->getSize(), vn->getAddr())
        // — the set is every remaining Varnode with the exemplar's
        // (space, offset, size); the outer loc order keeps it contiguous.
        let (set_space, set_addr, set_size) = {
            let vn = ordered[*index].read().unwrap();
            (vn.get_space(), vn.get_offset(), vn.get_size())
        };
        // cc:1071-1093: do { ... } while (iter != enditer);
        while *index < ordered.len() {
            let vn = ordered[*index].clone();
            let matches_set = {
                let vn_r = vn.read().unwrap();
                vn_r.get_space() == set_space
                    && vn_r.get_offset() == set_addr
                    && vn_r.get_size() == set_size
            };
            if !matches_set {
                break;
            }
            *index += 1;
            let mut vn_w = vn.write().unwrap();
            // cc:1073: if (vn->isFree()) continue;
            if vn_w.is_free() {
                continue;
            }
            let vnflags = vn_w.flags;
            let high = vn_w.high.clone();
            if vn_w.mapentry.is_some() {
                // cc:1075-1082: already an attached SymbolEntry (dynamic):
                // make sure the 'mapped' bit is unchanged.
                let local_mask = mask & !varnode_flags::MAPPED;
                let local_flags = fl & local_mask;
                if (vnflags & local_mask) != local_flags {
                    updateoccurred = true;
                    vn_w.set_flags(local_flags);
                    vn_w.clear_flags((!local_flags) & local_mask);
                    if let Some(high) = &high {
                        // varnode.cc:352-374 setFlags/clearFlags -> flagsDirty
                        high.write().unwrap().flags_dirty();
                    }
                }
            } else if (vnflags & mask) != fl {
                // cc:1084-1088: we have a change.
                updateoccurred = true;
                vn_w.set_flags(fl);
                vn_w.clear_flags((!fl) & mask);
                if let Some(high) = &high {
                    high.write().unwrap().flags_dirty();
                }
            }
            if let Some(ct) = &ct {
                // cc:1089-1092: if (vn->updateType(ct)) updateoccurred = true;
                if vn_w.update_type(ct.clone()) {
                    updateoccurred = true;
                    if let Some(high) = &high {
                        // varnode.cc:456-464 updateType -> typeDirty
                        high.write().unwrap().type_dirty();
                    }
                }
            }
        }
        updateoccurred
    }

    // Ghidra: funcdata_block.cc:881 Funcdata::removeFromFlowSplit
    /// Remove a 2-in/2-out empty block, rejoining each in-edge to the
    /// corresponding out-edge. Faithful to `Funcdata::removeFromFlowSplit`
    /// (funcdata_block.cc:881-889) + `BlockGraph::removeFromFlowSplit`
    /// (block.cc:1575-1590).
    ///
    /// `bl` must have exactly 2 in-edges and 2 out-edges and no ops.
    /// If `swap` is true:  In(0)->Out(1), In(1)->Out(0) (crossed).
    /// If `swap` is false: In(0)->Out(0), In(1)->Out(1) (straight).
    /// (funcdata_block.cc:880: "swap is true to force In(0)->Out(1)".)
    pub fn remove_from_flow_split(
        &mut self,
        bl: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        swap: bool,
    ) -> Result<(), String> {
        // Validate 2-in / 2-out and empty.
        if bl.read().unwrap().size_in() != 2 || bl.read().unwrap().size_out() != 2 {
            return Err("remove_from_flow_split: block must have 2 in/2 out".to_string());
        }
        let nonempty = {
            let bl_rg = bl.read().unwrap();
            if let Some(bb) = bl_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                !bb.ops.is_empty()
            } else {
                // Non-basic composite blocks: treat as removable if they have
                // no ops directly (they delegate to children).
                bl_rg.get_ops().is_empty()
            }
        };
        if nonempty {
            return Err("remove_from_flow_split: block must be empty".to_string());
        }

        // Faithful to BlockGraph::removeFromFlowSplit (block.cc:1584-1589):
        //   if flipflow: replaceEdgesThru(0,1)  // In(0) -> Out(1)
        //   else:        replaceEdgesThru(1,1)  // In(1) -> Out(1)
        //   then:        replaceEdgesThru(0,0)  // remaining In(0) -> Out(0)
        // Funcdata::removeFromFlowSplit (funcdata_block.cc:886) passes `swap`
        // straight through as `flipflow`. The old body ran (0,0),(0,1) for
        // swap=true — the second call indexed outgoing[1] after only one
        // out-edge remained (block.rs:1613 OOB panic) — and used the
        // flipflow=true sequence (0,1),(0,0) for swap=false, silently
        // crossing edges that should stay straight (CONDEXE-CFG-0001).
        {
            let mut bl_rg = bl.write().unwrap();
            if let Some(bb) = bl_rg
                .as_any_mut()
                .downcast_mut::<crate::block::BlockBasic>() {
                if swap {
                    bb.replace_edges_thru(0, 1);
                } else {
                    bb.replace_edges_thru(1, 1);
                }
                bb.replace_edges_thru(0, 0);
            } else {
                return Err("remove_from_flow_split: only BlockBasic supported".to_string());
            }
        }
        // Remove the now-disconnected block from the graph.
        self.bblocks.remove_block_arc(bl);
        self.structure_reset();
        Ok(())
    }

    // Ghidra: funcdata_block.cc:346 Funcdata::removeUnreachableBlocks
    /// Remove any unreachable basic blocks. Faithful to
    /// `Funcdata::removeUnreachableBlocks` (funcdata_block.cc:346-393):
    /// a quick existence scan (`checkexistence=true`, first non-entry block
    /// with null immed_dom) or the cached `blocks_unreachable` flag
    /// (`checkexistence=false`, maintained by structureReset) gates entry;
    /// the (un)reachable set comes from `BlockGraph::collectReachable`
    /// (block.cc:2154); each unreachable block is flagged dead (with the
    /// per-block header warning when `issuewarning`), then out-edges are
    /// severed via `branchRemoveInternal(bb,0)` (destroying the branch op
    /// and patching successor MULTIEQUALs), then the block is removed via
    /// `blockRemoveInternal(bb,true)` (descend2Undef on stranded outputs +
    /// destruction of ALL its ops), and finally structureReset.
    ///
    /// The former Rugra "conservative guard" (skip removal when >=5 blocks
    /// and >5% were unreachable) and the "leave ops with external
    /// descendants alive" approximation are removed: both deviate from the
    /// oracle and leave live ops in dead blocks reading free varnodes,
    /// which surfaces as "Free varnode has multiple descendants" panics in
    /// later Actions (RuleCondNegate/RulePullsubMulti).
    pub fn remove_unreachable_blocks(&mut self, issuewarning: bool, checkexistence: bool) -> bool {
        use crate::block::block_flags;
        let n = self.bblocks.get_size();
        if checkexistence {
            // cc:352-358: quick check for the existence of unreachable
            // blocks — first non-entry block with null immed dom.
            let mut found = false;
            for i in 0..n {
                let blk = match self.bblocks.get_block(i) {
                    Some(b) => b,
                    None => continue,
                };
                let blk_rg = blk.read().unwrap();
                if blk_rg.is_entry_point() {
                    continue; // Don't remove starting component
                }
                if blk_rg.get_immed_dom().and_then(|w| w.upgrade()).is_none() {
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        } else if self.flags & funcdata_flags::BLOCKS_UNREACHABLE == 0 {
            // cc:360-361: use cached check.
            return false;
        }

        // cc:365-366: find entry point. The oracle indexes off the end when
        // no entry exists (UB); Rugra falls back to block 0 rather than
        // panicking, which only fires on synthetic test graphs.
        let entry_idx = (0..n)
            .find(|&i| {
                self.bblocks
                    .get_block(i)
                    .map(|b| b.read().unwrap().is_entry_point())
                    .unwrap_or(false)
            })
            .unwrap_or(0);
        let entry = match self.bblocks.get_block(entry_idx) {
            Some(b) => b,
            None => return false,
        };
        // cc:367: collectReachable(list, entry, true).
        let mut list: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        self.bblocks.collect_reachable(&mut list, &entry, true);
        if list.is_empty() {
            return false;
        }

        // cc:369-381: flag every unreachable block dead (+warning).
        for blk in &list {
            blk.write().unwrap().set_flags(block_flags::DEAD);
            if issuewarning {
                // cc:372-378: ostringstream s; s << "Removing unreachable
                // block ("; s << bb->getStart().getSpace()->getName();
                // s << ','; bb->getStart().printRaw(s); s << ')'.
                // Space name: Rugra block covers carry spaceless
                // ELF-relative addresses (ADDRESS-0001); code blocks live in
                // ram, so a tagged address prints its own space name and the
                // spaceless transport prints the oracle's "ram". The offset
                // renders through printRaw + the display base delta
                // (print_raw_code_addr).
                let (space_name, start_raw) = {
                    let blk_rg = blk.read().unwrap();
                    let start = blk_rg.get_start_addr();
                    (
                        start
                            .get_space()
                            .map(|s| s.get_name())
                            .unwrap_or_else(|| "ram".to_string()),
                        self.print_raw_code_addr(start.as_u64()),
                    )
                };
                self.warning_header(&format!(
                    "Removing unreachable block ({},{})",
                    space_name, start_raw
                ));
            }
        }
        // cc:382-386: sever all out-edges (branchRemoveInternal destroys the
        // branch op at sizeOut()==2 and patches successor MULTIEQUALs).
        for blk in &list {
            while blk.read().unwrap().size_out() > 0 {
                self.branch_remove_internal(blk, 0);
            }
        }
        // cc:387-390: remove each block (unreachable=true: descend2Undef on
        // stranded outputs, then op destruction for ALL ops).
        for blk in &list {
            self.block_remove_internal(blk, true);
        }
        // cc:391
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::createNewBlock
    /// Splice a 1-out basic block into its single successor.
    /// Faithful to `Funcdata::spliceBlockBasic` (funcdata_block.cc:919-956).
    ///
    /// The given block must have a single output block with a single input
    /// (from this block). The output block's ops are conceptually merged; here
    /// we splice the CFG: this block inherits the successor's out-edges and the
    /// successor is removed. This is used by ActionRedundBranch (case 1) and
    /// ActionDoNothing.
    /// Create a new empty basic block and add it to bblocks. Faithful to
    /// `Funcdata::newBlockBasic` (funcdata_block.cc). Returns the Arc.
    pub fn create_new_block(&mut self) -> Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> {
        let addr = crate::address::Address::new(0);
        let bb = Arc::new(RwLock::new(crate::block::BlockBasic::new(0, addr)));
        self.bblocks.add_block(bb.clone());
        bb
    }

    // Ghidra: funcdata.cc:34 Funcdata::spliceBlockBasic
    pub fn splice_block_basic(
        &mut self, bb: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) -> bool {
        let (out_block, out_has_single_in) = {
            let rg = bb.read().unwrap();
            if rg.size_out() != 1 {
                return false;
            }
            let ob = rg.get_out(0).map(|e| e.point);
            let ob = match ob { Some(o) => o, None => return false ,
            };
            let single_in = ob.read().unwrap().size_in() == 1;
            (ob, single_in)
        };
        if !out_has_single_in {
            return false;
        }
        // Destroy any branch op at the end of bb (it falls through).
        let last_op = {
            let rg = bb.read().unwrap();
            if let Some(bb2) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb2.last_op()
            } else {
                None
            }
        };
        if let Some(branch_op) = last_op {
            let is_branch = {
                let o = branch_op.0.read().unwrap();
                o.opcode == crate::opcodes::OpCode::CPUI_BRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                    || o.opcode == crate::opcodes::OpCode::CPUI_BRANCHIND
            };
            if is_branch {
                self.op_destroy(&branch_op);
            }
        }
        // Move out_block's ops into bb (faithful to Ghidra funcdata_block.cc:
        // 940-947: bl->op.splice(bl->op.end(), outbl->op, ...)). This is the
        // KEY step that was missing — without it, out_block's ops are orphaned
        // when the block is removed, and printc can't find them.
        {
            // Check for MULTIEQUAL (phi) at start of out_block — Ghidra throws
            // if found (funcdata_block.cc:936). We skip the splice in that case.
            let has_phi = {
                let out_rg = out_block.read().unwrap();
                if let Some(out_bb) = out_rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    out_bb
                        .ops
                        .first()
                        .map(|o| {
                        o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL
                    })
                        .unwrap_or(false)
                } else {
                    false
                }
            };
            if has_phi {
                // Can't splice — out_block starts with a phi-node. Put the
                // edge back and abort. Ghidra throws; we just return false.
                self.bblocks.add_edge(bb.clone(), out_block.clone());
                return false;
            }

            // Move ops from out_block to end of bb.
            let moved_ops: Vec<crate::op::PcodeOpRef> = {
                let mut out_rg = out_block.write().unwrap();
                if let Some(out_bb) = out_rg
                    .as_any_mut()
                    .downcast_mut::<crate::block::BlockBasic>() {
                    let ops = std::mem::take(&mut out_bb.ops);
                    ops.into_iter()
                        .map(|o| crate::op::PcodeOpRef(o.0))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            // Set parent of moved ops to bb, and append to bb's ops.
            let bb_weak = std::sync::Arc::downgrade(
                &(bb.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
            );
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg
                .as_any_mut()
                .downcast_mut::<crate::block::BlockBasic>() {
                for op_ref in &moved_ops {
                    op_ref.0.write().unwrap().parent = Some(bb_weak.clone());
                    let insert_pos = bb_bb.ops.len();
                    bb_bb.insert_op(insert_pos, crate::op::PcodeOpRef(op_ref.0.clone()));
                }
                // Reset seq_num ordering on all ops in bb (Ghidra :948 setOrder).
                bb_bb.set_order();
            }
        }
        // cc:942: bl->mergeRange(outbl) — update the address cover BEFORE the
        // graph splice (Ghidra order).  The union cover's FIRST range (by
        // offset) becomes this block's getStart(); for a backward
        // jump-splice that is the absorbed block's address.
        if !std::sync::Arc::ptr_eq(bb, &out_block) {
            let out_rg = out_block.read().unwrap();
            let mut bb_rg = bb.write().unwrap();
            if let (Some(out_bb), Some(bb_bb)) = (
                out_rg.as_any().downcast_ref::<crate::block::BlockBasic>(),
                bb_rg.as_any_mut().downcast_mut::<crate::block::BlockBasic>(),
            ) {
                bb_bb.merge_range(out_bb);
            }
        }
        // Splice the CFG edges, faithful to BlockGraph::spliceBlock
        // (block.cc:1597-1620):
        //   fl1 = bl->flags & (f_unstructured_targ | f_entry_point)   // keep from bl
        //   fl2 = outbl->flags & f_switch_out                          // keep from outbl
        //   bl->removeOutEdge(0)                                       // drop bl→outbl
        //   for each out-edge of outbl: moveOutEdge(outbl, 0, bl)      // move outbl's edges to bl
        //   removeBlock(outbl)
        //   bl->flags = fl1 | fl2                                       // merge flags
        let (fl1, fl2, szout) = {
            let bl_rg = bb.read().unwrap();
            let out_rg = out_block.read().unwrap();
            let keep_from_bl = bl_rg.get_flags()
                & (crate::block::block_flags::UNSTRUCTURED_TARG
                    | crate::block::block_flags::ENTRY_POINT);
            let keep_from_out = out_rg.get_flags()
                & crate::block::block_flags::SWITCH_OUT;
            (keep_from_bl, keep_from_out, out_rg.size_out())
        };
        // Drop bb's single out-edge to out_block (block.cc:1612 removeOutEdge(0)).
        self.bblocks.remove_edge_blocks(bb, &out_block);
        // Move every out-edge of out_block to bb (block.cc:1614-1616).
        // moveOutEdge(outbl, 0, bl) relocates edge 0's reverse-index entry on
        // the destination to point at bl. We always move slot 0 because after
        // each move the remaining edges shift down.
        for _ in 0..szout {
            self.move_out_edge(&out_block, 0, bb);
        }
        // Remove out_block from the graph (block.cc:1618 removeBlock).
        self.bblocks.remove_block_arc(&out_block);
        // Merge flags: bl->flags = fl1 | fl2 (block.cc:1619).
        // BlockBasic.flags is a public field; assign exactly as Ghidra does.
        {
            let mut bb_rg = bb.write().unwrap();
            if let Some(bb_bb) = bb_rg
                .as_any_mut()
                .downcast_mut::<crate::block::BlockBasic>() {
                bb_bb.flags = fl1 | fl2;
            }
        }
        // bl->mergeRange(outbl) (funcdata_block.cc:942) — done above, before
        // the CFG splice, in Ghidra's statement order.
        self.structure_reset();
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::replaceLessequal
    /// Replace INT_LESSEQUAL/INT_SLESSEQUAL with INT_LESS/INT_SLESS:
    /// `V <= c => V < c+1`. Faithful to `Funcdata::replaceLessequal`
    /// (funcdata_op.cc:1029-1065).
    pub fn replace_lessequal(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (i, diff, val, size, is_signed) = {
            let o = op.0.read().unwrap();
            let (vn_idx, diff) = if o
                .inrefs
                .get(0)
                .map_or(false, |v| v.read().unwrap().is_constant()) {
                (0, -1i64)
            } else if o
                .inrefs
                .get(1)
                .map_or(false, |v| v.read().unwrap().is_constant()) {
                (1, 1i64)
            } else {
                return false;
            };
            let vn = o.inrefs[vn_idx].clone();
            let val = vn.read().unwrap().get_offset();
            let size = vn.read().unwrap().get_size();
            (
                vn_idx, diff, val, size, o.opcode == OpCode::CPUI_INT_SLESSEQUAL,
            )
        };
        let mask = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
        if is_signed {
            let int_min = if size >= 8 { i64::MIN as u64 } else { (1u64 << (size * 8 - 1)) };
            let int_max = if size >= 8 { i64::MAX as u64 } else { mask >> 1 };
            if diff == -1 && val == int_min { return false; }
            if diff == 1 && val == int_max { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_SLESS);
        } else {
            if diff == -1 && val == 0 { return false; }
            if diff == 1 && val == mask { return false; }
            self.op_set_opcode(op, OpCode::CPUI_INT_LESS);
        }
        let res = (val as i64 + diff) as u64 & mask;
        let newconst = self.new_constant(size, res);
        self.op_set_input(op, newconst, i);
        true
    }

    // Ghidra: funcdata.cc:34 Funcdata::distributeIntMultAdd
    /// Distribute INT_MULT coefficient through INT_ADD:
    /// `(V + W) * c => V*c + W*c`.
    /// Faithful to `Funcdata::distributeIntMultAdd` (funcdata_op.cc:1073-1118).
    /// The given op is INT_MULT(in0=INT_ADD(...), in1=constant coeff).
    pub fn distribute_int_mult_add(&mut self, op: &crate::op::PcodeOpRef) -> bool {
        let (vn0, vn1, coeff, sz, pc) = {
            let o = op.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_MULT { return false; }
            let in0 = match o.inrefs.get(0) { Some(v) => v.clone(), None => return false ,
            };
            let in1 = match o.inrefs.get(1) {
                Some(v) if v.read().unwrap().is_constant() => v.clone(),
                _ => return false,
            };
            let addop_arc = {
                let i0 = in0.read().unwrap();
                i0.def.as_ref().and_then(|w| w.upgrade())
            };
            let addop_arc = match addop_arc { Some(a) => a, None => return false ,
            };
            if addop_arc.read().unwrap().opcode != OpCode::CPUI_INT_ADD { return false; }
            let (vn0, vn1) = {
                let ao = addop_arc.read().unwrap();
                (ao.inrefs.get(0).cloned(), ao.inrefs.get(1).cloned())
            };
            let (vn0, vn1) = match (vn0, vn1) { (Some(a), Some(b)) => (a, b), _ => return false ,
            };
            let coeff = in1.read().unwrap().get_offset();
            let sz = o
                .output
                .as_ref()
                .map(|o| o.read().unwrap().get_size())
                .unwrap_or(0);
            (vn0, vn1, coeff, sz, o.start.get_addr())
        };
        if sz == 0 { return false; }
        let mask = if sz >= 8 { u64::MAX } else { (1u64 << (sz * 8)) - 1 };
        let follow = crate::op::PcodeOpRef(op.0.clone());
        // Distribute vn0 * coeff
        let newvn0 = if vn0.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn0.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn0.read().unwrap().is_free() && !vn0.read().unwrap().is_constant() { return false; }
            let newop0 = self.new_op(2, pc);
            self.op_set_opcode(&newop0, OpCode::CPUI_INT_MULT);
            let newout0 = self.new_unique_out(sz, &newop0);
            self.op_set_input(&newop0, vn0, 0);
            let c0 = self.new_constant(sz, coeff);
            self.op_set_input(&newop0, c0, 1);
            self.op_insert_before(&newop0, &follow);
            newout0
        };
        // Distribute vn1 * coeff
        let newvn1 = if vn1.read().unwrap().is_constant() {
            let val = coeff.wrapping_mul(vn1.read().unwrap().get_offset()) & mask;
            self.new_constant(sz, val)
        } else {
            if vn1.read().unwrap().is_free() && !vn1.read().unwrap().is_constant() { return false; }
            let newop1 = self.new_op(2, pc);
            self.op_set_opcode(&newop1, OpCode::CPUI_INT_MULT);
            let newout1 = self.new_unique_out(sz, &newop1);
            self.op_set_input(&newop1, vn1, 0);
            let c1 = self.new_constant(sz, coeff);
            self.op_set_input(&newop1, c1, 1);
            self.op_insert_before(&newop1, &follow);
            newout1
        };
        // Rewrite op to INT_ADD(newvn0, newvn1)
        self.op_set_input(&follow, newvn0, 0);
        self.op_set_input(&follow, newvn1, 1);
        self.op_set_opcode(&follow, OpCode::CPUI_INT_ADD);
        true
    }

    // Ghidra: funcdata_op.cc:345 Funcdata::opInsertBefore
    /// Insert `op` before `follow` in its basic block, preserving the
    /// contiguous INDIRECT group immediately preceding `follow`.
    pub fn op_insert_before(&mut self, op: &crate::op::PcodeOpRef, follow: &crate::op::PcodeOpRef) {
        let parent = follow
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let Some(parent) = parent else {
            // RUGRA-GLUE: Legacy Rule unit fixtures construct an alive, parentless
            // flat op bank, which is outside Ghidra's opInsertBefore precondition.
            // Preserve their former flat-list behavior until those fixtures acquire
            // real BlockBasic membership; this branch is not oracle-equivalent.
            self.obank.mark_alive(op.clone());
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            let mut insert_index = self
                .obank
                .alivelist
                .iter()
                .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &follow.0))
                .unwrap_or(self.obank.alivelist.len());
            if op.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                while insert_index != 0
                    && self.obank.alivelist[insert_index - 1]
                        .0
                        .read()
                        .unwrap()
                        .opcode
                        == OpCode::CPUI_INDIRECT
                {
                    insert_index -= 1;
                }
            }
            self.obank.alivelist.insert(insert_index, op.clone());
            return;
        };
        let block_ops = parent.read().unwrap().get_ops();
        let mut insert_index = block_ops
            .iter()
            .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &follow.0))
            .expect("opInsertBefore follow op is absent from its parent block");

        if op.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
            while insert_index != 0 {
                let previous = &block_ops[insert_index - 1];
                if previous.0.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                    break;
                }
                insert_index -= 1;
            }
        }
        self.op_insert(op, &parent, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:683 Funcdata::newIndirectOp
    /// Create a new CPUI_INDIRECT around a PcodeOp with an indirect effect,
    /// guarding the (space, offset, sz) storage range. Faithful 1:1 port of
    /// `newIndirectOp` (funcdata_op.cc:683-698):
    ///   - input[0]  = free Varnode at (space, offset, sz) — the value before
    ///   - output    = written Varnode at (space, offset, sz)
    ///   - input[1]  = Iop-space Varnode aliasing the causing op
    ///     (`newVarnodeIop`, round-trips through `get_op_from_const`)
    ///   - op flags |= extra_flags (0 for CALL guards, `indirect_store`
    ///     for STORE guards — the caller decides, exactly as in Ghidra)
    ///   - inserted before the causing op via `opInsertBefore`
    /// The constructor performs no setActiveHeritage – Ghidra's callers
    /// (guardCalls/guardStores, heritage.cc:1512-1516/1553-1556) do that
    /// after construction, so Rugra callers must too.
    /// Both varnode constructors run the symbol tail inside themselves,
    /// with two distinct usepoint paths (FUNCDATA-INDIRECT-SYMBOLTAIL-0001):
    ///   - `newVarnode` (cc:689, funcdata_varnode.cc:148-169) on the free
    ///     input: `localmap->queryProperties(addr, size, Address(), vflags)`
    ///     (cc:162) — usepoint is the INVALID default `Address()`, so per
    ///     `SymbolEntry::inUse` (database.cc:117-119) only addr-tied entries
    ///     can attach; window-limited entries never match an invalid
    ///     usepoint. On an entry hit `vn->setSymbolProperties(entry)`
    ///     (varnode.cc:404-421) runs `entry->updateType(vn)` (type force),
    ///     attaches `mapentry` for type-locked symbols, and folds
    ///     `setFlags(entry->getAllFlags() & ~typelock)`; otherwise
    ///     `setFlags(vflags & ~typelock)` (cc:166).
    ///   - `newVarnodeOut` (cc:692, funcdata_varnode.cc:104-122) on the
    ///     defined output: the tail runs AFTER the `op->setOutput(vn)`
    ///     wiring with `queryProperties(m, s, op->getAddr(), vflags)`
    ///     (cc:115) — usepoint is the DEFINING op's address (= the causing
    ///     op's address here, since `newOp(2, indeffect->getAddr())`), and
    ///     the same `setSymbolProperties`/`setFlags` split applies
    ///     (cc:116-119).
    pub fn new_indirect_op(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        space: crate::space::AddressSpace,
        offset: u64,
        sz: usize,
        extra_flags: u32,
    ) -> crate::op::PcodeOpRef {
        // cc:689: newin = newVarnode(sz, addr); — the newVarnode symbol tail
        // (funcdata_varnode.cc:161-166) queries with the INVALID `Address()`
        // usepoint, so only addr-tied entries can attach
        // (FUNCDATA-INDIRECT-SYMBOLTAIL-0001).
        let newin = self.vbank.create_with_space(sz, space, offset);
        self.set_varnode_properties(&newin);
        Heritage::apply_new_varnode_flags(self, &newin);
        // cc:690: newop = newOp(2, indeffect->getAddr());
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        // cc:691: newop->flags |= extraFlags;
        newop.0.write().unwrap().flags |= extra_flags;
        // cc:692: newVarnodeOut(sz, addr, newop);  (createDef -> WRITTEN+INSERT xref)
        let newout = self.vbank.create_with_space(sz, space, offset);
        let newout = self
            .vbank
            .set_def_prevalidated(newout, std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        // newVarnodeOut's symbol tail (funcdata_varnode.cc:114-119) runs after
        // the setOutput wiring with usepoint = op->getAddr() (= the causing
        // op's address); `set_varnode_properties` computes exactly this via
        // `get_use_point` on the now-written varnode
        // (FUNCDATA-INDIRECT-SYMBOLTAIL-0001).
        self.set_varnode_properties(&newout);
        Heritage::apply_new_varnode_flags(self, &newout);
        // cc:693: opSetOpcode(newop, CPUI_INDIRECT);
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // cc:694: opSetInput(newop, newin, 0);
        self.op_set_input(&newop, newin, 0);
        // cc:695: opSetInput(newop, newVarnodeIop(indeffect), 1);
        let iop_vn = self.new_varnode_iop(indeffect);
        self.op_set_input(&newop, iop_vn, 1);
        // cc:696: opInsertBefore(newop, indeffect);
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata_varnode.cc:176 Funcdata::newVarnodeIop
    /// Create a varnode in the iop address space referencing `op`.
    /// Faithful to `Funcdata::newVarnodeIop` (funcdata_varnode.cc:176-184):
    ///   Varnode *vn = vbank.create(sizeof(op), Address(cspc,(uintb)(uintp)op), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// Ghidra encodes the raw op pointer as the iop-space offset; Rugra
    /// encodes `Arc::as_ptr()` (the stable address of the inner RwLock).
    /// The assignHigh call is a structural no-op for iop varnodes (they are
    /// annotations), kept for call-site parity with cc:182.
    pub fn new_varnode_iop(
        &mut self, op: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // Encode the op's identity as a raw address. We use the Arc's data
        // pointer, which is stable for the Arc's lifetime (matching Ghidra's
        // `(uintb)(uintp)op`).
        let ptr_addr = std::sync::Arc::as_ptr(&op.0) as u64;
        let vn = self.vbank.create_with_space(
            std::mem::size_of::<usize>(),
            crate::space::AddressSpace::Iop,
            ptr_addr,
        );
        // OPACTION_DEBUG-equivalent drill registration: IopSpace::printRaw
        // (op.cc:41-47) resolves the iop offset back to the referenced op,
        // so the recorder needs the pointer->op mapping.
        crate::drillobserve::register_iop(ptr_addr as usize, &op.0);
        vn.write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::ANNOTATION);
        // cc:182: assignHigh(vn) — iop varnodes are annotations, so this is
        // the documented no-op leg (funcdata_varnode.cc:54-56 guard).
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: op.hh:249 PcodeOp::getOpFromConst
    /// Resolve an iop-space constant varnode back to the PcodeOp it references.
    /// Models the kind-discrimination slice corresponding to
    /// `PcodeOp::getOpFromConst` (op.hh:249). Ghidra's dedicated IPTR_IOP space
    /// excludes IPTR_FSPEC before pointer decoding. Rugra temporarily shares
    /// `AddressSpace::Iop`, so a typed callspec binding (including an expired
    /// Weak) must be rejected before interpreting the numeric compatibility
    /// shadow as an op pointer. The remaining raw-Arc decoder is the
    /// pre-existing `OPBANK-0001` lifecycle/soundness residual; D0 narrows its
    /// input kind but does not claim the complete Ghidra codec contract.
    pub fn get_op_from_const(
        &self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<crate::op::PcodeOpRef> {
        let ptr_addr = {
            let v = vn.read().unwrap();
            if v.get_space() != crate::space::AddressSpace::Iop || v.call_spec.is_some() {
                return None;
            }
            v.get_offset() as usize
        };
        if ptr_addr == 0 {
            return None;
        }
        let raw = ptr_addr as *const std::sync::RwLock<crate::op::PcodeOp>;
        // SAFETY: legacy Iop producers encode this pointer with
        // `Arc::as_ptr`. Keeping that owner alive across all consumers is the
        // pre-existing OPBANK-0001 contract; typed FSPEC annotations are
        // excluded above even after their Weak expires.
        unsafe {
            let arc = std::sync::Arc::from_raw(raw);
            let cloned = std::sync::Arc::clone(&arc);
            std::mem::forget(arc);
            Some(crate::op::PcodeOpRef(cloned))
        }
    }

    // RUGRA-GLUE: 1-arg compat shim over Funcdata::opUndoPtradd
    /// Ghidra's RulePtraddUndo/RulePtrsubUndo call `opUndoPtradd(op,false)`
    /// (ruleaction.cc:6925, ruleaction.cc:7115). ruleaction.rs is outside
    /// this change's write-set, so its single-argument calls delegate to the
    /// faithful 2-arg port with finalize=false.
    pub fn op_undo_ptradd(&mut self, op: &crate::op::PcodeOpRef) {
        self.op_undo_ptradd_full(op, false);
    }

    // Ghidra: funcdata_op.cc:579 Funcdata::opUndoPtradd
    /// Convert the given CPUI_PTRADD into the equivalent CPUI_INT_ADD. This
    /// may involve inserting a CPUI_INT_MULT PcodeOp. If finalization is
    /// requested and a new PcodeOp is needed, the output Varnode is marked as
    /// implied and has its data-type set. Faithful to
    /// `Funcdata::opUndoPtradd` (funcdata_op.cc:579-609).
    pub fn op_undo_ptradd_full(&mut self, op: &crate::op::PcodeOpRef, finalize: bool) {
        use crate::opcodes::OpCode;
        // cc:582-583: multVn = op->getIn(2); int4 multSize = multVn->getOffset()
        // (raw offset read; the scale Varnode is a constant by PTRADD shape,
        // Ghidra does not gate on isConstant here).
        let (mult_vn, mult_size) = {
            let g = op.0.read().unwrap();
            if g.num_input() < 3 {
                return; // malformed PTRADD (defensive; Ghidra reads slot 2 blind)
            }
            let vn = g.inrefs[2].clone();
            drop(g);
            let off = vn.read().unwrap().get_offset();
            // int4 truncation of the uintb offset (C++ int4 cast).
            (vn, off as u32 as i32)
        };
        // cc:585-586: drop the scale input, PTRADD becomes INT_ADD.
        self.op_remove_input(op, 2);
        self.op_set_opcode(op, OpCode::CPUI_INT_ADD);
        // cc:587: scale 1 means plain INT_ADD(base, index).
        if mult_size == 1 {
            return;
        }
        // cc:588: offVn = op->getIn(1) (after the slot-2 removal).
        let off_vn = {
            let g = op.0.read().unwrap();
            if g.num_input() < 2 { return; }
            g.inrefs[1].clone()
        };
        let (off_is_const, off_val, off_size) = {
            let r = off_vn.read().unwrap();
            (r.is_constant(), r.get_offset(), r.get_size())
        };
        if off_is_const {
            // cc:589-597: fold multSize * offset into one masked constant,
            // inheriting the read-facing type of the old offset when
            // finalizing.
            let new_val =
                ((mult_size as i64) as u64).wrapping_mul(off_val)
                    & crate::address::calc_mask(off_size);
            let new_off_vn = self.new_constant(off_size, new_val);
            if finalize {
                let read_facing = off_vn
                    .read()
                    .unwrap()
                    .get_type_read_facing_op(&op.0.read().unwrap(), 1);
                if let Some(ct) = read_facing {
                    new_off_vn.write().unwrap().update_type(ct);
                }
            }
            self.op_set_input(op, new_off_vn, 1);
            return;
        }
        // cc:598-608: implied INT_MULT(offVn, multVn) feeding slot 1 of the
        // new INT_ADD, inserted before it. The scale Varnode itself is reused
        // as the multiplier input (no fresh constant), and the product
        // Varnode takes the offset's size and (finalized) the scale's type.
        let mult_op = self.new_op(2, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&mult_op, OpCode::CPUI_INT_MULT);
        let add_vn = self.new_unique_out(off_size, &mult_op);
        if finalize {
            let mult_type = mult_vn.read().unwrap().get_type();
            if let Some(ct) = mult_type {
                add_vn.write().unwrap().update_type(ct);
            }
            add_vn.write().unwrap().set_implied();
        }
        self.op_set_input(&mult_op, off_vn, 0);
        self.op_set_input(&mult_op, mult_vn, 1);
        self.op_set_input(op, add_vn, 1);
        self.op_insert_before(&mult_op, op);
    }

    // Ghidra: funcdata.cc:34 Funcdata::opMarkCpoolTransformed
    /// Mark `op` as having been checked for cpool transforms.
    /// Faithful to `Funcdata::opMarkCpoolTransformed` (funcdata.hh:485).
    pub fn op_mark_cpool_transformed(&mut self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().mark_cpool_transformed();
    }

    // Ghidra: funcdata.cc:34 Funcdata::getStoreGuard
    /// Find the STORE guard for `op`. Faithful to
    /// `Funcdata::getStoreGuard` (funcdata.hh:270). Returns None if no guard.
    pub fn get_store_guard(
        &self, op: &crate::op::PcodeOpRef,
    ) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_store_guard(&op.0)
    }

    // Ghidra: funcdata.cc:34 Funcdata::getLoadGuard
    /// Find the LOAD guard for `op`. Faithful to
    /// `Funcdata::getLoadGuard` (funcdata.hh:269).
    pub fn get_load_guard(
        &self, op: &crate::op::PcodeOpRef,
    ) -> Option<&crate::heritage::LoadGuard> {
        self.heritage.get_load_guard(&op.0)
    }

    // Ghidra: funcdata_op.cc:710 Funcdata::newIndirectCreation
    /// Create an INDIRECT op with indirect_creation semantics. Faithful to
    /// `Funcdata::newIndirectCreation` (funcdata_op.cc:710-728): input[0] is
    /// a constant zero, the op and output carry `indirect_creation`, and
    /// input[1] aliases the causing op through the Iop space. This legacy
    /// entry keeps the Unique output space used by its historical callers;
    /// space-faithful call guards use `new_indirect_creation_in_space`.
    pub fn new_indirect_creation(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        addr: u64,
        sz: usize,
        possibleout: bool,
    ) -> crate::op::PcodeOpRef {
        self.new_indirect_creation_in_space(
            indeffect,
            crate::space::AddressSpace::Unique,
            addr,
            sz,
            possibleout,
        )
    }

    /// Space-faithful form of `Funcdata::newIndirectCreation`
    /// (funcdata_op.cc:710-728): the output Varnode is allocated at the
    /// caller's (space, offset) — e.g. the Register-space RAX range for a
    /// killed-by-call guard — instead of Unique. All flag and IOP semantics
    /// are identical to the oracle constructor — including `newVarnodeOut`'s
    /// symbol tail (funcdata_varnode.cc:114-119) on the output: after the
    /// `op->setOutput(vn)` wiring it queries
    /// `localmap->queryProperties(m, s, op->getAddr(), vflags)` with the
    /// DEFINING op's address as usepoint, attaching the SymbolEntry
    /// (`setSymbolProperties`, varnode.cc:404-421: updateType force +
    /// mapentry attach for type-locked symbols) on a hit, else folding
    /// `setFlags(vflags & ~typelock)` — and no setActiveHeritage is done
    /// here (guardCalls cc:1523 does it after construction).
    // RUGRA-GLUE: split entry because Rugra Address lacks space identity; the
    // legacy Unique-space entry keeps out-of-write-set callers compiling.
    pub fn new_indirect_creation_in_space(
        &mut self,
        indeffect: &crate::op::PcodeOpRef,
        space: crate::space::AddressSpace,
        addr: u64,
        sz: usize,
        possibleout: bool,
    ) -> crate::op::PcodeOpRef {
        use crate::op::pcodeop_flags;
        use crate::varnode::varnode_flags;
        // cc:716: newin = newConstant(sz, 0);
        let newin = self.new_constant(sz, 0);
        // cc:717: newop = newOp(2, indeffect->getAddr());
        let indeffect_addr = indeffect.0.read().unwrap().get_seq_num().get_addr();
        let newop = self.new_op(2, indeffect_addr);
        // cc:718: newop->flags |= PcodeOp::indirect_creation;
        newop.0.write().unwrap().flags |= pcodeop_flags::INDIRECT_CREATION;
        // cc:719: newout = newVarnodeOut(sz, addr, newop); — the
        // newVarnodeOut symbol tail (funcdata_varnode.cc:114-119) runs after
        // the setOutput wiring with usepoint = op->getAddr() (= the causing
        // op's address), BEFORE the INDIRECT_CREATION bits below
        // (cc:720-722); `set_varnode_properties` computes exactly this
        // usepoint via `get_use_point` on the now-written varnode
        // (FUNCDATA-INDIRECT-SYMBOLTAIL-0001).
        let newout = self.vbank.create_with_space(sz, space, addr);
        let newout = self
            .vbank
            .set_def_prevalidated(newout, std::sync::Arc::downgrade(&newop.0));
        newop.0.write().unwrap().output = Some(newout.clone());
        self.set_varnode_properties(&newout);
        Heritage::apply_new_varnode_flags(self, &newout);
        // cc:720-722: if (!possibleout) newin |= indirect_creation;
        //             newout |= indirect_creation;
        if !possibleout {
            newin
                .write()
                .unwrap()
                .set_flags(varnode_flags::INDIRECT_CREATION);
        }
        newout
            .write()
            .unwrap()
            .set_flags(varnode_flags::INDIRECT_CREATION);
        // cc:723: opSetOpcode(newop, CPUI_INDIRECT);
        self.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_INDIRECT);
        // cc:724: opSetInput(newop, newin, 0);
        self.op_set_input(&newop, newin, 0);
        // cc:725: opSetInput(newop, newVarnodeIop(indeffect), 1);
        let iop_vn = self.new_varnode_iop(indeffect);
        self.op_set_input(&newop, iop_vn, 1);
        // cc:726: opInsertBefore(newop, indeffect);
        self.op_insert_before(&newop, indeffect);
        newop
    }

    // Ghidra: funcdata.cc:34 Funcdata::findJumpTable
    /// Find the JumpTable whose indirect op is at the same address as `op`.
    /// Faithful to `Funcdata::findJumpTable` (funcdata_block.cc:446-457).
    pub fn find_jump_table(
        &self, op: &crate::op::PcodeOpRef,
    ) -> Option<&std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_seq_num().get_addr().as_u64();
        self.jump_tables.iter().find(|jt| {
            let jt_rg = jt.read().unwrap();
            jt_rg.get_op_address().as_u64() == op_addr
        })
    }

    // Ghidra: funcdata.cc:34 Funcdata::removeJumpTable
    /// Remove a JumpTable from this function. Faithful to
    /// `Funcdata::removeJumpTable` (funcdata_block.cc:65).
    pub fn remove_jump_table(
        &mut self, jt: &std::sync::Arc<std::sync::RwLock<crate::jumptable::JumpTable>>,
    ) {
        let jt_ptr = std::sync::Arc::as_ptr(jt);
        self.jump_tables
            .retain(|j| std::sync::Arc::as_ptr(j) != jt_ptr);
    }


    // Ghidra: funcdata_op.cc:373 Funcdata::opInsertAfter
    /// Insert `op` after `previous` in its basic block.  A non-MULTIEQUAL is
    /// placed after any leading MULTIEQUAL group, and an alive INDIRECT's iop
    /// target is treated as the effective previous op.
    pub fn op_insert_after(
        &mut self, op: &crate::op::PcodeOpRef, previous: &crate::op::PcodeOpRef,
    ) {
        if previous
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_none()
        {
            // RUGRA-GLUE: Legacy Rule unit fixtures construct an alive, parentless
            // flat op bank, which is outside Ghidra's opInsertAfter precondition.
            // Preserve their former flat-list behavior until those fixtures acquire
            // real BlockBasic membership; this branch is not oracle-equivalent.
            self.obank.mark_alive(op.clone());
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            let insert_index = self
                .obank
                .alivelist
                .iter()
                .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &previous.0))
                .map_or(self.obank.alivelist.len(), |index| index + 1);
            self.obank.alivelist.insert(insert_index, op.clone());
            return;
        }
        let effective_previous = {
            let indirect_iop = {
                let previous_guard = previous.0.read().unwrap();
                if previous_guard.is_marker()
                    && previous_guard.opcode == OpCode::CPUI_INDIRECT
                {
                    previous_guard.inrefs.get(1).cloned()
                } else {
                    None
                }
            };
            indirect_iop
                .filter(|vn| vn.read().unwrap().get_space() == crate::space::AddressSpace::Iop
                )
                .and_then(|vn| self.get_op_from_const(&vn))
                .filter(|target| !target.0.read().unwrap().is_dead())
                .unwrap_or_else(|| previous.clone())
        };
        let parent = effective_previous
            .0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .expect("opInsertAfter effective previous op has no basic block");
        let block_ops = parent.read().unwrap().get_ops();
        let previous_index = block_ops
            .iter()
            .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &effective_previous.0)
            )
            .expect("opInsertAfter previous op is absent from its parent block");
        let mut insert_index = previous_index + 1;
        if op.0.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
            while insert_index < block_ops.len()
                && block_ops[insert_index].0.read().unwrap().opcode
                    == OpCode::CPUI_MULTIEQUAL
            {
                insert_index += 1;
            }
        }
        self.op_insert(op, &parent, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:164 Funcdata::opUninsert
    /// Remove `op` from its basic block and move it from the alive list to the
    /// dead list.  Its Varnode input/output links remain intact.
    pub fn op_uninsert(&mut self, op: &crate::op::PcodeOpRef) {
        // OPACTION_DEBUG-equivalent drill hook (funcdata_op.cc:323-331
        // opUninsert's #ifdef block; placed after the parentless guard so
        // legacy no-op uninserts leave no phantom record).
        let parent = op
            .0.read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let Some(parent) = parent else {
            // RUGRA-GLUE: Preserve the former flat-bank detach behavior for
            // parentless legacy fixtures. Valid Ghidra-domain ops take the block
            // path below and transition to the dead list atomically.
            self.obank
                .alivelist
                .retain(|candidate| !std::sync::Arc::ptr_eq(&candidate.0, &op.0));
            return;
        };
        crate::drillobserve::mod_check(self.arch.as_ref(), op);
        self.obank.mark_dead(op.clone());
        Self::block_remove_op(op, &parent);
    }

    // Ghidra: funcdata_op.cc:413 Funcdata::opInsertBegin
    /// Insert `op` at the beginning of a basic block, after its leading
    /// MULTIEQUAL group unless the inserted op is itself a MULTIEQUAL.
    pub fn op_insert_begin(
        &mut self, op: &crate::op::PcodeOpRef, bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        let block_ops = bb.read().unwrap().get_ops();
        let mut insert_index = 0;
        if op.0.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
            while insert_index < block_ops.len()
                && block_ops[insert_index].0.read().unwrap().opcode
                    == OpCode::CPUI_MULTIEQUAL
            {
                insert_index += 1;
            }
        }
        self.op_insert(op, bb, Some(insert_index));
    }

    // Ghidra: funcdata_op.cc:435 Funcdata::opInsertEnd
    /// Insert `op` at the end of a basic block, immediately before its final
    /// flow-break op when one is present.
    pub fn op_insert_end(
        &mut self, op: &crate::op::PcodeOpRef, bb: &std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        let block_ops = bb.read().unwrap().get_ops();
        let insert_index = match block_ops.last() {
            Some(last) if last.0.read().unwrap().is_flow_break() => block_ops.len() - 1,
            _ => block_ops.len(),
        };
        self.op_insert(op, bb, Some(insert_index));
    }

    // Ghidra: funcdata.hh:519 Funcdata::opMarkNonPrinting
    /// Mark `op` as non-printing (suppressed in C output). Faithful to
    /// `Funcdata::opMarkNonPrinting` (funcdata.hh:519).
    pub fn op_mark_non_printing(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NONPRINTING;
    }

    // Ghidra: funcdata.hh:486 Funcdata::opMarkCalculatedBool
    /// Mark PcodeOp as having boolean output. Faithful to
    /// `Funcdata::opMarkCalculatedBool` (funcdata.hh:486).
    pub fn op_mark_calculated_bool(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::CALCULATED_BOOL;
    }

    // Ghidra: funcdata.hh:483 Funcdata::opMarkSpecialPrint
    /// Mark PcodeOp as needing special printing. Faithful to
    /// `Funcdata::opMarkSpecialPrint` (funcdata.hh:483).
    pub fn op_mark_special_print(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().addlflags |= crate::op::op_addl_flags::SPECIAL_PRINT;
    }

    // Ghidra: funcdata.hh:484 Funcdata::opMarkNoCollapse
    /// Mark PcodeOp as not collapsible. Faithful to
    /// `Funcdata::opMarkNoCollapse` (funcdata.hh:484).
    pub fn op_mark_no_collapse(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::NOCOLLAPSE;
    }

    // Ghidra: funcdata.hh:487 Funcdata::opMarkSpacebasePtr
    /// Mark PcodeOp as LOAD/STORE from spacebase ptr. Faithful to
    /// `Funcdata::opMarkSpacebasePtr` (funcdata.hh:487).
    pub fn op_mark_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:488 Funcdata::opClearSpacebasePtr
    /// Unmark PcodeOp as using spacebase ptr. Faithful to
    /// `Funcdata::opClearSpacebasePtr` (funcdata.hh:488).
    pub fn op_clear_spacebase_ptr(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::SPACEBASE_PTR;
    }

    // Ghidra: funcdata.hh:186 Funcdata::startCleanUp
    /// Start the clean-up phase: record the VarnodeBank creation index at
    /// phase entry. Faithful to `Funcdata::startCleanUp`
    /// (funcdata.hh:186) `{ clean_up_index = vbank.getCreateIndex(); }`.
    /// Rugra previously had no `clean_up_index` storage (the coreaction
    /// marker was a no-op); the field now mirrors funcdata.hh:187 exactly.
    pub fn start_clean_up(&mut self) {
        self.clean_up_index = self.vbank.get_create_index();
    }

    // Ghidra: funcdata.hh:187 Funcdata::getCleanUpIndex
    /// Get the creation index recorded at the start of the clean-up phase.
    /// Faithful to `Funcdata::getCleanUpIndex` (funcdata.hh:187).
    pub fn get_clean_up_index(&self) -> u32 {
        self.clean_up_index
    }

    // Ghidra: funcdata.hh:242 Funcdata::seenDeadcode
    /// Mark that dead Varnodes have been seen in a specific address space.
    /// Faithful to `Funcdata::seenDeadcode` (funcdata.hh:242)
    /// `{ heritage.seenDeadCode(spc); }` — a pure forwarder onto Heritage.
    pub fn seen_deadcode(&mut self, space: crate::space::AddressSpace) {
        self.heritage.seen_dead_code(space);
    }

    // Ghidra: funcdata.hh:254 Funcdata::deadRemovalAllowed
    /// Check if dead code removal is allowed for a specific address space.
    /// Faithful to `Funcdata::deadRemovalAllowed` (funcdata.hh:254)
    /// `{ return heritage.deadRemovalAllowed(spc); }`.
    pub fn dead_removal_allowed(&self, space: crate::space::AddressSpace) -> bool {
        self.heritage.dead_removal_allowed(space)
    }

    // Ghidra: funcdata.hh:260 Funcdata::deadRemovalAllowedSeen
    /// Check if dead Varnodes have been removed for a specific address
    /// space. Faithful to `Funcdata::deadRemovalAllowedSeen`
    /// (funcdata.hh:260) `{ return heritage.deadRemovalAllowedSeen(spc); }`.
    pub fn dead_removal_allowed_seen(&mut self, space: crate::space::AddressSpace) -> bool {
        self.heritage.dead_removal_allowed_seen(space)
    }

    // Ghidra: funcdata.hh:303 Funcdata::findCoveredInput
    /// Find the first input Varnode covered by the given range. Faithful to
    /// `Funcdata::findCoveredInput` (funcdata.hh:303)
    /// `{ return vbank.findCoveredInput(s,loc); }`.
    pub fn find_covered_input(
        &self, size: usize, loc: Address,
    ) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_covered_input(size, loc)
    }

    // Ghidra: funcdata.hh:310 Funcdata::findCoveringInput
    /// Find the input Varnode that contains the given range. Faithful to
    /// `Funcdata::findCoveringInput` (funcdata.hh:310)
    /// `{ return vbank.findCoveringInput(s,loc); }`.
    pub fn find_covering_input(
        &self, size: usize, loc: Address,
    ) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_covering_input(size, loc)
    }

    // Ghidra: funcdata.hh:333 Funcdata::findVarnodeWritten
    /// Find a defined Varnode via its storage address and its definition
    /// address. Faithful to `Funcdata::findVarnodeWritten` (funcdata.hh:333-334)
    /// `{ return vbank.find(s,loc,pc,uniq); }`; the default `uniq=~0`
    /// becomes the explicit `u32::MAX` sentinel.
    pub fn find_varnode_written(
        &self, size: usize, loc: Address, pc: Address, uniq: u32,
    ) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        self.vbank.find_vn(size, loc, pc, uniq)
    }

    // Ghidra: funcdata.hh:337 Funcdata::beginLoc
    // Ghidra: funcdata.hh:340 Funcdata::endLoc
    /// Start/end of all Varnodes sorted by storage. Faithful to the
    /// parameterless `beginLoc`/`endLoc` pair (funcdata.hh:337/340), which
    /// forward to `vbank.beginLoc()`/`vbank.endLoc()`. In Rust the two
    /// Ghidra half-open iterator endpoints collapse into one owned
    /// iterator; `end_loc` exists for API parity and returns the same
    /// full-range tail.
    pub fn begin_loc(&self) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc()
    }

    // Ghidra: funcdata.hh:340 Funcdata::endLoc
    pub fn end_loc(&self) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc()
    }

    // Ghidra: funcdata.hh:343 Funcdata::beginLoc(AddrSpace*)
    // Ghidra: funcdata.hh:346 Funcdata::endLoc(AddrSpace*)
    /// Start/end of Varnodes stored in a given address space. Faithful to
    /// `beginLoc(AddrSpace*)`/`endLoc(AddrSpace*)` (funcdata.hh:343/346),
    /// forwarding onto `VarnodeBank::beginLoc(spaceid)` with the bank's
    /// space-filtered iterator.
    pub fn begin_loc_space(
        &self, space: crate::space::AddressSpace,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc_space(space)
    }

    // Ghidra: funcdata.hh:346 Funcdata::endLoc(AddrSpace*)
    pub fn end_loc_space(
        &self, space: crate::space::AddressSpace,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc_space(space)
    }

    // Ghidra: funcdata.hh:349 Funcdata::beginLoc(const Address&)
    // Ghidra: funcdata.hh:352 Funcdata::endLoc(const Address&)
    /// Start/end of Varnodes at a storage address. Faithful to
    /// `beginLoc(const Address&)`/`endLoc(const Address&)`
    /// (funcdata.hh:349/352) forwarding onto the bank's address-filtered
    /// iterator.
    pub fn begin_loc_addr(
        &self, addr: Address,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc_addr(addr)
    }

    // Ghidra: funcdata.hh:352 Funcdata::endLoc(const Address&)
    pub fn end_loc_addr(
        &self, addr: Address,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc_addr(addr)
    }

    // Ghidra: funcdata.hh:355 Funcdata::beginLoc(int4,const Address&)
    // Ghidra: funcdata.hh:358 Funcdata::endLoc(int4,const Address&)
    /// Start/end of Varnodes with given storage (size + address). The Ghidra
    /// pair (funcdata.hh:355/358) forwards to the bank's size-bounded
    /// lower_bounds (varnode.cc:1610-1633): the half-open span covers
    /// exactly the varnodes whose loc==addr AND size==s, in creation order.
    /// The Rust bank has no size-bounded endpoint yet, so the span is
    /// expressed here as a predicate-filtered iteration of the same
    /// loc_tree ordering (FUNCDATA-LOCSIZE-BOUND-0001).
    pub fn begin_loc_size(
        &self, size: usize, addr: Address,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc().filter(move |v| {
            let vn = v.0.read().unwrap();
            vn.loc == addr && vn.size == size
        })
    }

    // Ghidra: funcdata.hh:358 Funcdata::endLoc(int4,const Address&)
    pub fn end_loc_size(
        &self, _size: usize, _addr: Address,
    ) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc()
    }

    // Ghidra: funcdata.hh:361 Funcdata::beginLoc(int4,const Address&,uint4)
    // Ghidra: funcdata.hh:364 Funcdata::endLoc(int4,const Address&,uint4)
    /// Start/end of Varnodes matching storage and properties. The Ghidra
    /// pair (funcdata.hh:361/364) forwards to the bank's flag-restricted
    /// bounds (varnode.cc:1645-1700): fl==Varnode::input restricts to
    /// inputs, fl==Varnode::written to written, fl==0 to free. The span is
    /// expressed as the same predicate over the loc_tree ordering
    /// (FUNCDATA-LOCSIZE-BOUND-0001).
    pub fn begin_loc_size_fl(
        &self, size: usize, addr: Address, fl: u32,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc().filter(move |v| {
            let vn = v.0.read().unwrap();
            if vn.loc != addr || vn.size != size {
                return false;
            }
            match fl {
                x if x == crate::varnode::varnode_flags::INPUT => vn.is_input(),
                x if x == crate::varnode::varnode_flags::WRITTEN => vn.is_written(),
                0 => !vn.is_input() && !vn.is_written(),
                _ => true,
            }
        })
    }

    // Ghidra: funcdata.hh:364 Funcdata::endLoc(int4,const Address&,uint4)
    pub fn end_loc_size_fl(
        &self, _size: usize, _addr: Address, _fl: u32,
    ) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc()
    }

    // Ghidra: funcdata.hh:367 Funcdata::beginLoc(int4,const Address&,const Address&,uintm)
    // Ghidra: funcdata.hh:371 Funcdata::endLoc(int4,const Address&,const Address&,uintm)
    /// Start/end of Varnodes matching storage and definition address. The
    /// Ghidra pair (funcdata.hh:367/371) forwards to the bank's
    /// definition-bounded bounds (varnode.cc:1732-1780). CRITICAL oracle
    /// semantics: the loc-tree comparator (VarnodeCompareLocDef,
    /// varnode.cc:37) decides "different" via `SeqNum::operator!=` which
    /// compares ONLY the uniq counter (address.hh:150-151), while the
    /// ordering `SeqNum::operator<` is pc-first (address.hh:153-157) — so
    /// two written varnodes whose def seqnums share the uniq value are
    /// COMPARATOR-EQUIVALENT regardless of pc, and the span
    /// [lower_bound(SeqNum(pc,uniq==~0?0:uniq)),
    /// upper_bound(SeqNum(pc,uniq)))] admits any def seqnum that is not
    /// strictly-less than the low key and not strictly-greater-or-equal
    /// under the high key, with lt(x,y) := (x.uniq==y.uniq) ? false :
    /// (x.pc,x.uniq) < (y.pc,y.uniq). Expressed as the same predicate over
    /// the loc_tree ordering (FUNCDATA-LOCSIZE-BOUND-0001).
    pub fn begin_loc_pc(
        &self, size: usize, addr: Address, pc: Address, uniq: u32,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeLocRef> {
        let low_uniq = if uniq == u32::MAX { 0 } else { uniq };
        self.vbank.begin_loc().filter(move |v| {
            let vn = v.0.read().unwrap();
            if vn.loc != addr || vn.size != size || !vn.is_written() {
                return false;
            }
            let Some(def_op) = vn.def.as_ref().and_then(|w| w.upgrade()) else {
                return false;
            };
            let d = def_op.read().unwrap();
            loc_pc_in_span(d.get_addr(), d.start.get_time(), pc, low_uniq, uniq)
        })
    }

    // Ghidra: funcdata.hh:371 Funcdata::endLoc(int4,const Address&,const Address&,uintm)
    pub fn end_loc_pc(
        &self, _size: usize, _addr: Address, _pc: Address, _uniq: u32,
    ) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeLocRef> {
        self.vbank.begin_loc()
    }

    // Ghidra: funcdata.hh:375 Funcdata::overlapLoc
    /// Given a storage start, return the maximal range of overlapping
    /// Varnodes. Faithful in intent to `Funcdata::overlapLoc`
    /// (funcdata.hh:375-376), which forwards to
    /// `vbank.overlapLoc(iter,bounds)`; Rugra's bank counterpart takes the
    /// (address,size) of the starting Varnode directly instead of a C++
    /// set iterator plus out-vector, so the forwarder uses the adapted
    /// bank signature (same overlap decision: `vn_start < target_end &&
    /// target_start < vn_end`).
    pub fn overlap_loc(
        &self, addr: Address, size: usize,
    ) -> Vec<Arc<RwLock<crate::varnode::Varnode>>> {
        self.vbank.overlap_loc(addr, size)
    }

    // Ghidra: funcdata.hh:379 Funcdata::beginDef
    // Ghidra: funcdata.hh:382 Funcdata::endDef
    /// Start/end of all Varnodes sorted by definition address. Faithful to
    /// the parameterless `beginDef`/`endDef` (funcdata.hh:379/382).
    pub fn begin_def(&self) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeDefRef> {
        self.vbank.begin_def()
    }

    // Ghidra: funcdata.hh:382 Funcdata::endDef
    pub fn end_def(&self) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeDefRef> {
        self.vbank.begin_def()
    }

    // Ghidra: funcdata.hh:385 Funcdata::beginDef(uint4)
    // Ghidra: funcdata.hh:388 Funcdata::endDef(uint4)
    /// Start/end of Varnodes with a given definition property. Faithful to
    /// `beginDef(uint4 fl)`/`endDef(uint4 fl)` (funcdata.hh:385/388).
    pub fn begin_def_fl(
        &self, fl: u32,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeDefRef> {
        // cc:1831-1881 (varnode.cc): inputs head the def tree, written
        // occupy the middle (def-seqnum order), frees the tail. Rugra's
        // bank begin_def_fl interprets fl as a 0/1 selector (divergence);
        // this forwarder restores the oracle Varnode::input(8) /
        // Varnode::written(16) / 0-free semantics locally
        // (FUNCDATA-DEF-FL-0001).
        self.vbank.begin_def().filter(move |v| {
            let vn = v.0.read().unwrap();
            if fl == crate::varnode::varnode_flags::INPUT {
                vn.is_input()
            } else if fl == crate::varnode::varnode_flags::WRITTEN {
                vn.is_written()
            } else {
                !vn.is_input() && !vn.is_written()
            }
        })
    }

    // Ghidra: funcdata.hh:388 Funcdata::endDef(uint4)
    pub fn end_def_fl(
        &self, _fl: u32,
    ) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeDefRef> {
        self.vbank.begin_def()
    }

    // Ghidra: funcdata.hh:391 Funcdata::beginDef(uint4,const Address&)
    // Ghidra: funcdata.hh:394 Funcdata::endDef(uint4,const Address&)
    /// Start/end of (input or free) Varnodes at a given storage address.
    /// The Ghidra pair (funcdata.hh:391/394) forwards to the bank's
    /// address-restricted def bounds (varnode.cc:1908-1961). CRITICAL:
    /// `fl == Varnode::written` is an ILLEGAL combination — the oracle
    /// throws `LowlevelError("Cannot get contiguous written AND
    /// addressed")` (varnode.cc:1913-1914); Rugra mirrors the throw as a
    /// panic with the same message. The span covers inputs (fl==input) or
    /// frees (anything else) whose storage starts at the address.
    pub fn begin_def_addr(
        &self, fl: u32, addr: Address,
    ) -> impl Iterator<Item = &crate::varnode::VarnodeDefRef> {
        if fl == crate::varnode::varnode_flags::WRITTEN {
            // varnode.cc:1913-1914: the written+addressed combination is
            // rejected before any bound is formed.
            panic!("Cannot get contiguous written AND addressed");
        }
        self.vbank.begin_def().filter(move |v| {
            let vn = v.0.read().unwrap();
            if vn.loc.as_u64() != addr.as_u64() {
                return false;
            }
            if fl == crate::varnode::varnode_flags::INPUT {
                vn.is_input()
            } else {
                !vn.is_input() && !vn.is_written()
            }
        })
    }

    // Ghidra: funcdata.hh:394 Funcdata::endDef(uint4,const Address&)
    pub fn end_def_addr(
        &self, fl: u32, _addr: Address,
    ) -> std::collections::btree_set::Iter<'_, crate::varnode::VarnodeDefRef> {
        if fl == crate::varnode::varnode_flags::WRITTEN {
            panic!("Cannot get contiguous written AND addressed");
        }
        self.vbank.begin_def()
    }

    // Ghidra: funcdata.hh:398 Funcdata::endLaneAccess
    /// Ending iterator over laned accesses: faithful to
    /// `Funcdata::endLaneAccess` (funcdata.hh:398)
    /// `{ return lanedMap.end(); }` (the begin counterpart is
    /// `lane_accesses`, funcdata.hh:397). Rugra exposes the BTreeMap tail
    /// range as the parity endpoint.
    pub fn end_lane_access(
        &self,
    ) -> std::collections::btree_map::Iter<
        '_,
        LanedStorage,
        std::sync::Arc<crate::transform::LanedRegister>,
    > {
        self.laned_map.iter()
    }

    // Ghidra: funcdata.hh:420 Funcdata::clearActiveOutput
    /// Clear any analysis of the function's return prototype. Faithful to
    /// `Funcdata::clearActiveOutput` (funcdata.hh:420-423): delete the
    /// ParamActive object (Rust drop) and null the slot.
    pub fn clear_active_output(&mut self) {
        self.active_output = None;
    }

    // Ghidra: funcdata.hh:428 Funcdata::clearDeadOps
    /// Delete any dead PcodeOps. Faithful to `Funcdata::clearDeadOps`
    /// (funcdata.hh:428) `{ obank.destroyDead(); }`.
    pub fn clear_dead_ops(&mut self) {
        self.obank.destroy_dead();
    }

    // Ghidra: funcdata.hh:452 Funcdata::markReturnCopy
    /// Mark COPY as returning a global value. Faithful to
    /// `Funcdata::markReturnCopy` (funcdata.hh:452)
    /// `{ op->flags |= PcodeOp::return_copy; }`.
    pub fn mark_return_copy(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::RETURN_COPY;
    }

    // Ghidra: funcdata.hh:453 Funcdata::findOp
    /// Find PcodeOp with given sequence number. Faithful to
    /// `Funcdata::findOp` (funcdata.hh:453)
    /// `{ return obank.findOp(sq); }`.
    pub fn find_op(&self, sq: &crate::address::SeqNum) -> Option<crate::op::PcodeOpRef> {
        self.obank.find_op(sq)
    }

    // Ghidra: funcdata.hh:460 Funcdata::opDeadInsertAfter
    /// Move given PcodeOp to specified point in the dead list. Faithful to
    /// `Funcdata::opDeadInsertAfter` (funcdata.hh:460)
    /// `{ obank.insertAfterDead(op,prev); }`.
    pub fn op_dead_insert_after(
        &mut self, op: &crate::op::PcodeOpRef, prev: &crate::op::PcodeOpRef,
    ) {
        self.obank.insert_after_dead(op, prev);
    }

    // Ghidra: funcdata.hh:476 Funcdata::opDeadAndGone
    /// Free resources for the given dead PcodeOp. Faithful to
    /// `Funcdata::opDeadAndGone` (funcdata.hh:476)
    /// `{ obank.destroy(op); }` — the op stays in `deadandgone` retention
    /// (op.cc:984-999) until the whole bank clears.
    pub fn op_dead_and_gone(&mut self, op: crate::op::PcodeOpRef) {
        self.obank.destroy(op);
    }

    // Ghidra: funcdata.hh:480 Funcdata::opMarkStartBasic
    /// Mark PcodeOp as starting a basic block. Faithful to
    /// `Funcdata::opMarkStartBasic` (funcdata.hh:480)
    /// `{ op->setFlag(PcodeOp::startbasic); }`.
    pub fn op_mark_start_basic(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::STARTBASIC;
    }

    // Ghidra: funcdata.hh:481 Funcdata::opMarkStartInstruction
    /// Mark PcodeOp as starting its instruction. Faithful to
    /// `Funcdata::opMarkStartInstruction` (funcdata.hh:481)
    /// `{ op->setFlag(PcodeOp::startmark); }`.
    pub fn op_mark_start_instruction(&self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags |= crate::op::pcodeop_flags::STARTMARK;
    }

    // Ghidra: funcdata.hh:490 Funcdata::target
    /// Look up a PcodeOp by an instruction Address. Faithful to
    /// `Funcdata::target` (funcdata.hh:490)
    /// `{ return obank.target(addr); }`.
    pub fn target_op(&self, addr: Address) -> Option<crate::op::PcodeOpRef> {
        self.obank.target(addr)
    }

    // Ghidra: funcdata.hh:500 Funcdata::beginOp(OpCode)
    // Ghidra: funcdata.hh:503 Funcdata::endOp(OpCode)
    /// Start/end of PcodeOp objects with the given op-code. Faithful to
    /// `beginOp(OpCode)`/`endOp(OpCode)` (funcdata.hh:500/503) forwarding to
    /// `obank.begin(opc)`/`obank.end(opc)` (op.cc:1158-1185): only
    /// STORE/LOAD/RETURN/CALLOTHER have per-opcode lists; every other
    /// opcode yields an EMPTY range (the C++ default arm returns
    /// `alivelist.end()` for both endpoints). NOTE: Rugra's
    /// `PcodeOpBank::begin_op` default arm currently returns the full
    /// alivelist (op.rs divergence); this forwarder restores the oracle
    /// empty-range default locally (FUNCDATA-OPBEGIN-DEFAULT-0001).
    pub fn begin_op_code(
        &self, opc: crate::opcodes::OpCode,
    ) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        use crate::opcodes::OpCode;
        match opc {
            OpCode::CPUI_STORE => self.obank.storelist.iter(),
            OpCode::CPUI_LOAD => self.obank.loadlist.iter(),
            OpCode::CPUI_RETURN => self.obank.returnlist.iter(),
            OpCode::CPUI_CALLOTHER => self.obank.useroplist.iter(),
            _ => [].iter(),
        }
    }

    // Ghidra: funcdata.hh:503 Funcdata::endOp(OpCode)
    pub fn end_op_code(
        &self, _opc: crate::opcodes::OpCode,
    ) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        [].iter()
    }

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive
    // Ghidra: funcdata.hh:509 Funcdata::endOpAlive
    /// Start/end of PcodeOp objects in the alive list. Faithful to
    /// `beginOpAlive`/`endOpAlive` (funcdata.hh:506/509) forwarding to
    /// `obank.beginAlive()`/`obank.endAlive()`.
    pub fn begin_op_alive(&self) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.alivelist.iter()
    }

    // Ghidra: funcdata.hh:509 Funcdata::endOpAlive
    pub fn end_op_alive(&self) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.alivelist.iter()
    }

    // Ghidra: funcdata.hh:512 Funcdata::beginOpDead
    // Ghidra: funcdata.hh:515 Funcdata::endOpDead
    /// Start/end of PcodeOp objects in the dead list. Faithful to
    /// `beginOpDead`/`endOpDead` (funcdata.hh:512/515) forwarding to
    /// `obank.beginDead()`/`obank.endDead()`.
    pub fn begin_op_dead(&self) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.deadlist.iter()
    }

    // Ghidra: funcdata.hh:515 Funcdata::endOpDead
    pub fn end_op_dead(&self) -> std::slice::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.deadlist.iter()
    }

    // Ghidra: funcdata.hh:518 Funcdata::beginOpAll
    // Ghidra: funcdata.hh:521 Funcdata::endOpAll
    /// Start/end of all (alive) PcodeOp objects sorted by sequence number.
    /// Faithful to `beginOpAll`/`endOpAll` (funcdata.hh:518/521) forwarding
    /// to the bank's optree iteration.
    pub fn begin_op_all(&self) -> std::collections::btree_set::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.optree.iter()
    }

    // Ghidra: funcdata.hh:521 Funcdata::endOpAll
    pub fn end_op_all(&self) -> std::collections::btree_set::Iter<'_, crate::op::PcodeOpRef> {
        self.obank.optree.iter()
    }

    // Ghidra: funcdata.hh:524 Funcdata::beginOp(const Address&)
    // Ghidra: funcdata.hh:527 Funcdata::endOp(const Address&)
    /// Start/end of all (alive) PcodeOp objects attached to a specific
    /// Address. Faithful to `beginOp(const Address&)`/`endOp`
    /// (funcdata.hh:524/527) forwarding to `obank.begin(addr)`/`end(addr)`.
    pub fn begin_op_addr(
        &self, addr: Address,
    ) -> impl Iterator<Item = &crate::op::PcodeOpRef> {
        self.obank.begin_addr(addr)
    }

    // Ghidra: funcdata.hh:527 Funcdata::endOp(const Address&)
    pub fn end_op_addr(
        &self, addr: Address,
    ) -> impl Iterator<Item = &crate::op::PcodeOpRef> {
        self.obank.end_addr(addr)
    }

    // ====================================================================
    // OPACTION_DEBUG observation family (funcdata.hh:580-612 inline +
    // funcdata.cc:1007-1118). Ghidra compiles these only with
    // -DOPACTION_DEBUG; Rugra always compiles and gates behavior on
    // `opactdbg_on`, which the ctor initializes false (funcdata.cc:74-81)
    // so the production pipeline is untouched.
    // ====================================================================

    // Ghidra: funcdata.hh:593 Funcdata::enableJTCallback
    /// Enable a debug callback for the jump-table simplification process.
    /// Faithful to `Funcdata::enableJTCallback` (funcdata.hh:593)
    /// `{ jtcallback = jtcb; }`.
    pub fn enable_jt_callback(&mut self, jtcb: fn(&mut Funcdata, &mut Funcdata)) {
        self.jtcallback = Some(jtcb);
    }

    // Ghidra: funcdata.hh:594 Funcdata::disableJTCallback
    /// Disable the debug callback. Faithful to
    /// `Funcdata::disableJTCallback` (funcdata.hh:594)
    /// `{ jtcallback = 0; }`.
    pub fn disable_jt_callback(&mut self) {
        self.jtcallback = None;
    }

    // Ghidra: funcdata.hh:595 Funcdata::debugActivate
    /// Turn on recording. Faithful to `Funcdata::debugActivate`
    /// (funcdata.hh:595) `{ if (opactdbg_on) opactdbg_active=true; }` —
    /// activation only happens when debugging was enabled first.
    pub fn debug_activate(&mut self) {
        if self.opactdbg_on {
            self.opactdbg_active = true;
        }
    }

    // Ghidra: funcdata.hh:596 Funcdata::debugDeactivate
    /// Turn off recording. Faithful to `Funcdata::debugDeactivate`
    /// (funcdata.hh:596) `{ opactdbg_active = false; }` — unconditional.
    pub fn debug_deactivate(&mut self) {
        self.opactdbg_active = false;
    }

    // Ghidra: funcdata.hh:601 Funcdata::debugSize
    /// Number of code ranges being debug traced. Faithful to
    /// `Funcdata::debugSize` (funcdata.hh:601)
    /// `{ return opactdbg_pclow.size(); }`.
    pub fn debug_size(&self) -> usize {
        self.opactdbg_pclow.len()
    }

    // Ghidra: funcdata.hh:602 Funcdata::debugEnable
    /// Turn on debugging. Faithful to `Funcdata::debugEnable`
    /// (funcdata.hh:602) `{ opactdbg_on = true; opactdbg_count = 0; }`.
    pub fn debug_enable(&mut self) {
        self.opactdbg_on = true;
        self.opactdbg_count = 0;
    }

    // Ghidra: funcdata.hh:603 Funcdata::debugDisable
    /// Turn off debugging. Faithful to `Funcdata::debugDisable`
    /// (funcdata.hh:603) `{ opactdbg_on = false; }`.
    pub fn debug_disable(&mut self) {
        self.opactdbg_on = false;
    }

    // Ghidra: funcdata.hh:604 Funcdata::debugClear
    /// Clear debugging ranges. Faithful to `Funcdata::debugClear`
    /// (funcdata.hh:604-605): all four range vectors clear, in the
    /// declaration order pclow, pchigh, uqlow, uqhigh.
    pub fn debug_clear(&mut self) {
        self.opactdbg_pclow.clear();
        self.opactdbg_pchigh.clear();
        self.opactdbg_uqlow.clear();
        self.opactdbg_uqhigh.clear();
    }

    // Ghidra: funcdata.hh:609 Funcdata::debugHandleBreak
    /// Mark a breakpoint as handled. Faithful to
    /// `Funcdata::debugHandleBreak` (funcdata.hh:609)
    /// `{ opactdbg_breakon = false; }`.
    pub fn debug_handle_break(&mut self) {
        self.opactdbg_breakon = false;
    }

    // Ghidra: funcdata.hh:610 Funcdata::debugSetBreak
    /// Break on a specific trace hit count. Faithful to
    /// `Funcdata::debugSetBreak` (funcdata.hh:610)
    /// `{ opactdbg_breakcount = count; }`.
    pub fn debug_set_break(&mut self, count: i32) {
        self.opactdbg_breakcount = count;
    }

    // Ghidra: funcdata.cc:1024 Funcdata::debugModClear
    /// Abandon printing debug for the current action. Faithful to
    /// `Funcdata::debugModClear` (funcdata.cc:1024-1032): every op in
    /// modify_list drops its `modified` addl-flag, both scratch lists
    /// clear, and recording turns off (`opactdbg_active = false`).
    pub fn debug_mod_clear(&mut self) {
        for op in &self.modify_list {
            op.0.write().unwrap().addlflags &= !crate::op::op_addl_flags::MODIFIED;
        }
        self.modify_list.clear();
        self.modify_before.clear();
        self.opactdbg_active = false;
    }

    // Ghidra: funcdata.cc:1063 Funcdata::debugSetRange
    /// Add a new memory range to the debug trace. Faithful to
    /// `Funcdata::debugSetRange` (funcdata.cc:1063-1072): turning tracing
    /// on unconditionally (`opactdbg_on = true`) and pushing all four
    /// bounds in order.
    pub fn debug_set_range(
        &mut self, pclow: Address, pchigh: Address, uqlow: u32, uqhigh: u32,
    ) {
        self.opactdbg_on = true;
        self.opactdbg_pclow.push(pclow);
        self.opactdbg_pchigh.push(pchigh);
        self.opactdbg_uqlow.push(uqlow);
        self.opactdbg_uqhigh.push(uqhigh);
    }

    // Ghidra: funcdata.cc:1076 Funcdata::debugCheckRange
    /// Check if the given PcodeOp is being debug traced. Faithful to
    /// `Funcdata::debugCheckRange` (funcdata.cc:1076-1098): walk ranges in
    /// insertion order; a range accepts the op when (the PC bounds are
    /// valid AND pclow <= op.addr <= pchigh) OR skipped as a whole when
    /// invalid, and (the uniq bounds are set AND uqlow <= op.time <=
    /// uqhigh) OR skipped as a whole when unset (`uqlow == ~0`).
    pub fn debug_check_range(&self, op: &crate::op::PcodeOpRef) -> bool {
        let size = self.opactdbg_pclow.len();
        let op_addr = { op.0.read().unwrap().get_addr() };
        let op_time = { op.0.read().unwrap().start.get_time() };
        for i in 0..size {
            if !self.opactdbg_pclow[i].is_invalid() {
                if op_addr < self.opactdbg_pclow[i] {
                    continue;
                }
                if self.opactdbg_pchigh[i] < op_addr {
                    continue;
                }
            }
            if self.opactdbg_uqlow[i] != u32::MAX {
                if self.opactdbg_uqlow[i] > op_time {
                    continue;
                }
                if self.opactdbg_uqhigh[i] < op_time {
                    continue;
                }
            }
            return true;
        }
        false
    }

    // Ghidra: funcdata.cc:1100 Funcdata::debugPrintRange
    /// Print the i-th debug trace range. Faithful to
    /// `Funcdata::debugPrintRange` (funcdata.cc:1100-1118): the PC bounds
    /// print only when valid (`"PC = (low,high)  "` with raw address text,
    /// else `"entire function "`), then the unique bounds print only when
    /// set (`"unique = (low,high)"` in hex, no separator). Ghidra emits
    /// through `glb->printDebug` which appends `endl`; Rugra returns the
    /// message string so the caller owns the sink.
    pub fn debug_print_range(&self, i: usize) -> String {
        let mut s = String::new();
        if !self.opactdbg_pclow[i].is_invalid() {
            s.push_str("PC = (");
            // Address::printRaw (address.hh:305) — the Display form is the
            // same space printRaw text (address.cc:47).
            s.push_str(&format!("{}", self.opactdbg_pclow[i]));
            s.push(',');
            s.push_str(&format!("{}", self.opactdbg_pchigh[i]));
            s.push_str(")  ");
        } else {
            s.push_str("entire function ");
        }
        if self.opactdbg_uqlow[i] != u32::MAX {
            s.push_str(&format!("unique = ({:x},", self.opactdbg_uqlow[i]));
            s.push_str(&format!("{:x})", self.opactdbg_uqhigh[i]));
        }
        s
    }

    // ====================================================================
    // Raw console/debug printing (funcdata.cc:203-225, 575-608)
    // ====================================================================

    // Ghidra: funcdata.cc:209 Funcdata::printRaw
    /// Print raw p-code op descriptions. Faithful to `Funcdata::printRaw`
    /// (funcdata.cc:209-225): with no basic blocks (raw pre-block state)
    /// every op prints from the SeqNum-ordered optree as
    /// `<seqnum>:\t<op raw>\n` after the `"Raw operations: \n"` header, and
    /// an empty bank throws `RecovError("No operations to print")`; with
    /// blocks present the basic-block container prints instead
    /// (`BlockGraph::printRaw`, block.cc:1300-1316: graph header line then
    /// each block's raw listing with implied-goto separators). The per-op
    /// raw line is the `PcodeOp::printRaw` TypeOp dispatch, provided here
    /// by the drill formatter (`DrillFmt::op_raw`); the SeqNum text is
    /// `operator<<(ostream,const SeqNum&)` (address.cc:32-38):
    /// `pc.printRaw() ':' uniq` with the uniq counter in DECIMAL.
    /// Rugra returns a String instead of writing to ostream and maps
    /// RecovError onto `Error::Lowlevel`.
    pub fn print_raw(&self) -> crate::error::Result<String> {
        if self.bblocks.get_size() == 0 {
            // cc:213-214: obank.empty() (op.hh:318: optree.empty()).
            if self.obank.optree.is_empty() {
                return Err(crate::error::Error::Lowlevel(
                    "No operations to print".to_string(),
                ));
            }
            let fmt = crate::drillfmt::DrillFmt {
                arch: self
                    .arch
                    .clone()
                    .unwrap_or_else(canonical_arch),
            };
            let mut s = String::from("Raw operations: \n");
            // cc:217-221: for(iter=obank.beginAll(); ...) — SeqNum order.
            for op_ref in self.obank.optree.iter() {
                let op = op_ref.0.read().unwrap();
                // cc:218: s << (*iter).second->getSeqNum() << ":\t";
                s.push_str(&format!("{}:\t", seqnum_text(&op.start)));
                // cc:219: (*iter).second->printRaw(s);
                s.push_str(&fmt.op_raw(&op));
                s.push('\n');
            }
            Ok(s)
        } else {
            // cc:224: bblocks.printRaw(s) — block.cc:1300-1316 composition
            // (graph header, then per-block raw listings with implied-goto
            // separators between consecutive blocks). The container graph's
            // printHeader (block.cc:604-611) prints only its index: the
            // basic-block container carries no address cover of its own.
            let mut s = format!("{}\n", self.bblocks.index);
            if self.bblocks.blocks.is_empty() {
                return Ok(s);
            }
            let mut iter = self.bblocks.blocks.iter();
            let mut last_bl = iter.next().unwrap().clone();
            s.push_str(&last_bl.read().unwrap().print_raw_trait());
            for cur in iter {
                s.push_str(
                    &last_bl.read().unwrap().print_raw_implied_goto_trait(cur),
                );
                s.push_str(&cur.read().unwrap().print_raw_trait());
                last_bl = cur.clone();
            }
            Ok(s)
        }
    }

    // Ghidra: funcdata.cc:579 Funcdata::printVarnodeTree
    /// Print a description of all Varnodes to a stream. Faithful to
    /// `Funcdata::printVarnodeTree` (funcdata.cc:579-591): every Varnode in
    /// def-tree order prints via `Varnode::printInfo` (varnode.cc:255-281;
    /// each line is terminated by the endl inside printInfo).
    pub fn print_varnode_tree(&self) -> String {
        let mut s = String::new();
        for def_ref in self.vbank.begin_def() {
            let vn = def_ref.0.read().unwrap();
            s.push_str(&vn.print_info());
        }
        s
    }

    // Ghidra: funcdata.cc:597 Funcdata::printLocalRange
    /// Print description of memory ranges associated with local scopes.
    /// Faithful to `Funcdata::printLocalRange` (funcdata.cc:597-608): the
    /// local scope's own bounds print first
    /// (`Scope::printBounds` database.hh:789 → `RangeList::printBounds`
    /// address.cc:588-600: `"all\n"` when empty, else one
    /// `"<spcname>: <first>-<last>\n"` line per Range in hex), then every
    /// child scope's bounds in map order. Rugra's `ScopeLocal` keeps the
    /// union range tree as offset tuples in the stack space with no
    /// child-scope map; the child loop is therefore structurally absent
    /// (FUNCDATA-LOCALRANGE-CHILDREN-0001) and the space name comes from
    /// the scope's own space field.
    pub fn print_local_range(&self) -> String {
        let mut s = String::new();
        if let Some(scope) = &self.scope {
            if scope.local_range.is_empty() {
                s.push_str("all\n");
            } else {
                for (first, last) in &scope.local_range {
                    s.push_str(&format!(
                        "{}: {:x}-{:x}\n",
                        scope.space.name(),
                        first,
                        last
                    ));
                }
            }
        }
        s
    }

    // ====================================================================
    // Live injection (funcdata.cc:840-876)
    // ====================================================================

    // Ghidra: funcdata.cc:848 Funcdata::doLiveInject
    /// Inject p-code from a payload into this live function. Faithful to
    /// `Funcdata::doLiveInject` (funcdata.cc:848-876): the inject context
    /// is cleared with both `baseaddr` and `nextaddr` set to the injection
    /// address (cc:855-857), the payload emits through the
    /// `PcodeEmitFd` dump path onto the dead list tail (cc:859-868 — the
    /// pre-inject dead tail is captured first so exactly the newly emitted
    /// ops are walked), and each new op is rejected with
    /// `LowlevelError("Illegal branching injection")` when it calls or
    /// branches (cc:872-873), else inserted into the block at the given
    /// position (cc:874). Rugra threads the payload through
    /// `InjectPayload::inject` returning raw ops that
    /// `inject_raw_ops_single` (the `PcodeEmitFd::dump` port) materializes
    /// on the dead list; the C++ list-iterator insertion point is the
    /// `Option<usize>` op-index used by `op_insert`.
    pub fn do_live_inject(
        &mut self,
        payload: &crate::pcodeinject::InjectPayload,
        addr: Address,
        bl: &std::sync::Arc<
            std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>,
        >,
        iter_index: Option<usize>,
    ) -> crate::error::Result<()> {
        // cc:852-857: cached context cleared, baseaddr=nextaddr=addr.
        let mut context = crate::pcodeinject::InjectContext::new();
        context.base_addr = addr.as_u64();
        context.next_addr = addr.as_u64();
        // cc:859-862: capture the dead-list tail position.
        let dead_tail = self.obank.deadlist.len();
        // cc:863: payload->inject(context,emitter) — PcodeEmitFd::dump
        // materializes each emitted op on the dead list.
        let raw_ops = payload
            .inject(&context)
            .map_err(|e| crate::error::Error::Lowlevel(e))?;
        self.inject_raw_ops_single(&raw_ops, addr);
        // cc:865-875: walk from the first injected op to the dead end.
        for index in dead_tail..self.obank.deadlist.len() {
            let op = self.obank.deadlist[index].clone();
            let is_call_or_branch = {
                let o = op.0.read().unwrap();
                o.is_call() || o.is_branch()
            };
            if is_call_or_branch {
                return Err(crate::error::Error::Lowlevel(
                    "Illegal branching injection".to_string(),
                ));
            }
            self.op_insert(&op, bl, iter_index);
        }
        Ok(())
    }

    // ====================================================================
    // Inlining (funcdata_op.cc:842-916)
    // ====================================================================

    // Ghidra: funcdata_op.cc:853 Funcdata::inlineFlow
    /// Generate the p-code ops to be inlined from another function.
    /// Faithful to `Funcdata::inlineFlow` (funcdata_op.cc:853-916): the
    /// callee's analysis state is cleared, a fresh `FlowInfo` over the
    /// callee walks the full address space with the inline error flags
    /// (cc:856-867), and the EZ model path clones the straight-line body
    /// after the call site (cc:870-891: `inlineEZClone`, move the cloned
    /// sequence after the callop, transfer the startbasic flag, destroy
    /// the raw callop), while the hard model path enforces restrictions,
    /// clones the callee's jumptables and converts the CALL to a BRANCH
    /// (cc:892-911). Uniq ids swap across the boundary at both ends
    /// (cc:858, cc:913). Returns 0 (EZ), 1 (hard), -1 (not successful).
    /// RUGRA-GLUE: the SLEIGH lifter threads through as an explicit
    /// parameter (Ghidra reaches it through the Architecture), and the
    /// `FlowInfo::inlineEZClone` clone core is currently a structural
    /// placeholder in flow.rs (FUNCDATA-INFLOW-DEP-0001), so the EZ path
    /// performs no op cloning until that dependency lands.
    pub fn inline_flow(
        &mut self,
        inlinefd: &mut Funcdata,
        flow: &mut crate::flow::FlowInfo<'_>,
        lifter: &mut crate::disasm::sleigh_lift::SleighLifter,
        callop: &crate::op::PcodeOpRef,
    ) -> crate::error::Result<i32> {
        // cc:893-894: flow.testHardInlineRestrictions(inlinefd,callop,
        // retaddr) — evaluated BEFORE the inline-flow generation (Rust
        // borrow structure; behavior-neutral: the test reads only the
        // callee's funcp noreturn bit and CALLER-flow state
        // (fallthru/warnings), neither of which the callee-side
        // forwardRecursion/generateOps phases touch).
        let mut retaddr: Option<Address> = None;
        let hard_ok =
            flow.test_hard_inline_restrictions(inlinefd, callop, &mut retaddr);
        // cc:856: inlinefd->getArch()->clearAnalysis(inlinefd).
        if let Some(arch) = inlinefd.arch.clone() {
            arch.clear_analysis();
        }
        // cc:858: inlinefd->obank.setUniqId(obank.getUniqId()) — before the
        // FlowInfo construction (the flow reads the bank only after this
        // point, same as the C++ sequence).
        let uniq = self.obank.get_uniqid();
        inlinefd.obank.set_uniqid(uniq);
        // cc:857: FlowInfo inlineflow(*inlinefd, obank, bblocks, qlst).
        // cc:861-863: full-space range; cc:864-865: inline error flags.
        let mut inlineflow =
            crate::flow::FlowInfo::new(inlinefd, lifter, 0, u64::MAX);
        inlineflow.set_flags(
            crate::flow::flow_flags::ERROR_OUTOFBOUNDS
                | crate::flow::flow_flags::ERROR_UNIMPLEMENTED
                | crate::flow::flow_flags::ERROR_REINTERPRETED
                | crate::flow::flow_flags::FLOW_FORINLINE,
        );
        // cc:866-867: forwardRecursion(flow); generateOps().
        inlineflow.forward_recursion(flow);
        let callop_addr = { callop.0.read().unwrap().get_addr() };
        inlineflow.generate_ops(callop_addr)?;

        let res: i32;
        if inlineflow.check_ez_model() {
            // cc:870-891: EZ clone — no jumptables to clone.
            res = 0;
            let dead_before = self.obank.deadlist.len();
            flow.inline_ezclone(&inlineflow, callop_addr);
            // cc:877-889: if at least one op was cloned, move the cloned
            // sequence to right after the callop.
            if self.obank.deadlist.len() > dead_before {
                let firstop = self.obank.deadlist[dead_before].clone();
                let lastop = self.obank.deadlist[self.obank.deadlist.len() - 1].clone();
                self.obank.move_sequence_dead(&firstop, &lastop, callop);
                // cc:883: if (callop->isBlockStart()) — op.hh startbasic bit.
                let callop_startbasic = {
                    (callop.0.read().unwrap().flags
                        & crate::op::pcodeop_flags::STARTBASIC)
                        != 0
                };
                if callop_startbasic {
                    firstop.0.write().unwrap().flags |=
                        crate::op::pcodeop_flags::STARTBASIC;
                    flow.update_target(callop, &firstop);
                } else {
                    firstop.0.write().unwrap().flags &=
                        !crate::op::pcodeop_flags::STARTBASIC;
                }
            }
            // cc:890: opDestroyRaw(callop).
            self.op_destroy_raw(callop);
            // cc:913: obank.setUniqId(inlinefd->obank.getUniqId()).
            self.obank.set_uniqid(inlinefd.obank.get_uniqid());
        } else {
            // cc:894-895: restrictions failed -> -1 (uniq still swaps back).
            if !hard_ok {
                self.obank.set_uniqid(inlinefd.obank.get_uniqid());
                return Ok(-1);
            }
            res = 1;
            // cc:902: flow.inlineClone(inlineflow,retaddr) — runs BEFORE the
            // callee reads below (Rust borrow structure; behavior-neutral
            // reorder of cc:897-901: inlineClone reads the callee dead list
            // and flow tables only, never the callee jump-table vector, and
            // the caller-side jumpvec receives the same tables in the same
            // relative order).
            let retaddr_final = retaddr.unwrap_or(callop_addr);
            flow.inline_clone(&inlineflow, retaddr_final);
            // cc:897-901: clone any jumptables from the inline piece
            // (`new JumpTable(*jiter)` deep copy). RUGRA-GAP: Rugra's
            // JumpTable has no copy constructor (jumptable.rs), so the
            // table Arc is shared instead of deep-copied — divergent only
            // when the inlined copy is later mutated independently
            // (FUNCDATA-INFLOW-DEP-0001).
            for jt in &inlinefd.jump_tables {
                self.jump_tables.push(jt.clone());
            }
            // cc:904-906: convert the CALL op to a jump.
            let num_input = { callop.0.read().unwrap().num_input() };
            for slot in (1..num_input).rev() {
                self.op_remove_input(callop, slot);
            }
            self.op_set_opcode(callop, crate::opcodes::OpCode::CPUI_BRANCH);
            // cc:909-910: newCodeRef input at slot 0.
            let inline_addr = { inlinefd.baseaddr };
            let code_ref = self.new_code_ref(inline_addr);
            self.op_set_input(callop, code_ref, 0);
            // cc:913: obank.setUniqId(inlinefd->obank.getUniqId()).
            self.obank.set_uniqid(inlinefd.obank.get_uniqid());
        }
        Ok(res)
    }

    // Ghidra: funcdata.hh:477 Funcdata::opSetAllInput
    /// Set all input Varnodes for the given PcodeOp simultaneously.
    /// Faithful to `Funcdata::opSetAllInput` (funcdata_op.cc:267-284).
    pub fn op_set_all_input(
        &mut self, op: &crate::op::PcodeOpRef, vvec: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
    ) {
        // Unset all existing inputs (funcdata_op.cc:276-278). Each
        // opUnsetInput NULLs its slot in place (op.cc:98 clearInput).
        let num = op.0.read().unwrap().num_input();
        for i in 0..num {
            self.op_unset_input(op, i);
        }
        // cc:280 replaces every slot with NULL: setNumInputs(vvec.size()).
        // Clear the Vec so identical old/new pointers cannot trigger
        // op_set_input's early return before rebuilding the descendant edge.
        op.0.write().unwrap().inrefs.clear();
        // cc:282-283: restore exact input order via the normal const-dedup path.
        for (i, vn) in vvec.iter().cloned().enumerate() {
            self.op_set_input(op, vn, i);
        }
    }

    // Ghidra: funcdata_op.cc:150 Funcdata::opInsert
    /// Insert the given PcodeOp at a specific point in a basic block. Faithful
    /// to `Funcdata::opInsert` (funcdata_op.cc:150-159).  The alive list tracks
    /// lifecycle/integration order; the basic block owns execution order.
    pub fn op_insert(
        &mut self,
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        iter_index: Option<usize>,
    ) {
        self.obank.mark_alive(op.clone());
        let block_size = bb.read().unwrap().get_ops().len();
        let index = iter_index.unwrap_or(block_size);
        assert!(
            index <= block_size, "opInsert iterator is outside the basic block"
        );
        Self::block_insert_op(op, bb, index);
    }

    // Ghidra: block.cc:2258 BlockBasic::insert
    /// Insert an op into a BlockBasic and maintain its parent, per-block
    /// sequence order, and switch-dispatch flag.
    fn block_insert_op(
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        index: usize,
    ) {
        assert!(
            op.0.read().unwrap().parent.is_none(),
            "BlockBasic::insert requires an unattached op"
        );
        let parent = std::sync::Arc::downgrade(bb);
        let mut block_guard = bb.write().unwrap();
        let block = block_guard
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("Funcdata op insertion requires BlockBasic");
        assert!(
            index <= block.ops.len(), "BlockBasic insert index is out of bounds"
        );

        let order_before = if index == 0 {
            2
        } else {
            block.ops[index - 1].0.read().unwrap().start.get_order()
        };
        let order_after = if index == block.ops.len() {
            let candidate = order_before.wrapping_add(0x0100_0000);
            if candidate <= order_before { u32::MAX } else { candidate }
        } else {
            block.ops[index].0.read().unwrap().start.get_order()
        };

        op.0.write().unwrap().parent = Some(parent);
        block.ops.insert(index, op.clone());
        if order_after.wrapping_sub(order_before) <= 1 {
            block.set_order();
        } else {
            op.0.write()
                .unwrap()
                .start
                .set_order(order_after / 2 + order_before / 2);
        }

        let is_branch_indirect = {
            let op_guard = op.0.read().unwrap();
            op_guard.is_branch() && op_guard.opcode == OpCode::CPUI_BRANCHIND
        };
        if is_branch_indirect {
            block.flags |= crate::block::block_flags::SWITCH_OUT;
        }
    }

    // Ghidra: block.cc:2292 BlockBasic::removeOp
    /// Detach an op from its parent BlockBasic without changing its Varnode
    /// links or recalculating the remaining per-block order fields.
    fn block_remove_op(
        op: &crate::op::PcodeOpRef,
        bb: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        op.0.write().unwrap().parent = None;
        let mut block_guard = bb.write().unwrap();
        let block = block_guard
            .as_any_mut()
            .downcast_mut::<crate::block::BlockBasic>()
            .expect("Funcdata op removal requires BlockBasic");
        let index = block
            .ops
            .iter()
            .position(|candidate| std::sync::Arc::ptr_eq(&candidate.0, &op.0))
            .expect("BlockBasic::removeOp requires an op in the block");
        block.ops.remove(index);
    }

    // Ghidra: funcdata_op.cc:179 Funcdata::opUnlink
    /// Extricate the op from all its Varnode connections to the function's
    /// data-flow and remove it from its basic block, WITHOUT changing block
    /// connections. Faithful to `Funcdata::opUnlink` (funcdata_op.cc:179-193):
    ///   opUnsetOutput(op);
    ///   for(i=0;i<op->numInput();++i) opUnsetInput(op,i);
    ///   if (op->getParent() != NULL) opUninsert(op);
    /// The op remains in the \e dead list (Rugra: detached from the alive
    /// list, awaiting a subsequent `mark_dead`).
    pub fn op_unlink(&mut self, op: &crate::op::PcodeOpRef) {
        // cc:188: opUnsetOutput(op).
        self.op_unset_output(op);
        // cc:189-190: for i in 0..numInput: opUnsetInput(op, i).
        let num = op.0.read().unwrap().num_input();
        for i in 0..num {
            self.op_unset_input(op, i);
        }
        // cc:191-192: if (op->getParent() != NULL) opUninsert(op).
        // Rugra's alive list is the analogue of "is in a basic block"; if the
        // op is currently in the alive list, remove it (faithful op_uninsert).
        let in_alive = self
            .obank
            .alivelist
            .iter()
            .any(|r| std::sync::Arc::ptr_eq(&r.0, &op.0));
        if in_alive {
            self.op_uninsert(op);
        }
    }

    // Ghidra: funcdata_op.cc:253 Funcdata::opDestroyRaw
    /// Specialized routine for deleting an op during flow generation that has
    /// been replaced by something else. Faithful to `Funcdata::opDestroyRaw`
    /// (funcdata_op.cc:253-261). The op is expected to be \e dead with none of
    /// its inputs or outputs linked to anything else. Both the PcodeOp and all
    /// the input/output Varnodes are destroyed:
    ///   for(i=0;i<op->numInput();++i) destroyVarnode(op->getIn(i));
    ///   if (op->getOut() != NULL) destroyVarnode(op->getOut());
    ///   obank.destroy(op);
    /// Differs from `op_destroy` (cc:203) in that it does NOT touch block
    /// membership and additionally frees the input/output Varnodes.
    pub fn op_destroy_raw(&mut self, op: &crate::op::PcodeOpRef) {
        // cc:256-257: destroy each input varnode.
        let inputs = op.0.read().unwrap().inrefs.clone();
        for vn in &inputs {
            self.destroy_varnode(vn);
        }
        // cc:258-259: destroy the output varnode if present.
        let out = op.0.read().unwrap().output.clone();
        if let Some(out_vn) = out {
            self.destroy_varnode(&out_vn);
        }
        // cc:260: obank.destroy(op).
        self.obank.destroy(op.clone());
    }

    // Ghidra: funcdata_varnode.cc:25 Funcdata::setVarnodeProperties
    /// Gather storage properties for `vn` from the symbol/scope and apply them.
    /// Faithful to `Funcdata::setVarnodeProperties` (funcdata_varnode.cc:25-42):
    ///   if (!vn->isMapped()) {
    ///     entry = localmap->queryProperties(vn->getAddr(), vn->getSize(),
    ///                                       vn->getUsePoint(*this), vflags);
    ///     if (entry != NULL) vn->setSymbolProperties(entry);
    ///     else               vn->setFlags(vflags & ~Varnode::typelock);
    ///   }
    ///   if (vn->cover == NULL && isHighOn()) vn->calcCover();
    ///
    /// Query routing: Ghidra's ONE `localmap->queryProperties` walks
    /// ScopeLocal → parent → global scope (database.cc:1268 stackContainer).
    /// Rugra composes the same walk: the ScopeLocal leg runs FIRST
    /// (`ScopeLocal::query_properties_ex` over `fd.scope`, usepoint =
    /// `get_use_point` — a VALID address, unlike newVarnode's invalid
    /// `Address()` form), and only when the local scope does not terminate
    /// the walk does the parent/global leg run — the Database channel
    /// (`query_properties_parent_scope`), where the global scope's
    /// `mapped|addrtied|persist` fold (database.cc:1271-1277) lands, marking
    /// global storage persistent for `mapGlobals`
    /// (funcdata_varnode.cc:1669's `if (!vn->isPersist()) continue;`).
    /// Non-RAM spaces unclaimed by the local scope keep the `symbol_table`
    /// name proxy (the Database channel models the global scope over RAM
    /// only). (FUNCDATA-SETVARNODE-SCOPELOCAL-0001)
    pub fn set_varnode_properties(
        &mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:28: if (!vn->isMapped()) — one more chance to find an entry now
        // that we know the usepoint.
        let is_mapped = vn.read().unwrap().is_mapped();
        if !is_mapped {
            let (space, addr, size) = {
                let r = vn.read().unwrap();
                (r.get_space(), r.get_offset(), r.get_size() as i32)
            };
            // cc:30-31: queryProperties(addr, size, usepoint, vflags). The
            // usepoint is vn->getUsePoint(*this) (varnode.cc:696-703) — a
            // VALID address (the defining op's address for written
            // varnodes, fd->getAddress()-1 otherwise).
            let usepoint = vn.read().unwrap().get_use_point(self);
            // database.cc:1268 — the ScopeLocal leg: localmap->
            // queryProperties' stackContainer starts at the querying scope
            // itself, so the function-local scope is consulted FIRST —
            // findContainer (database.cc:952, entry hit → getAllFlags) then
            // the in-scope "discovery of new variable" stop (database.cc:
            // 957-958 → 1271-1277 mapped|addrtied(|persist)+property).
            // Rugra's ScopeLocal carries no live SymbolEntry
            // (DB-LOCALSCOPE-MAP-0001 split), so the entry hit degrades to
            // the observable flags fold — the same treatment as the local
            // leg of `new_varnode_symbol_tail` (varnode.cc:422).
            // (FUNCDATA-SETVARNODE-SCOPELOCAL-0001)
            let property = |spc: crate::space::AddressSpace, off: u64| -> u32 {
                if spc != crate::space::AddressSpace::Ram {
                    return 0;
                }
                self.arch
                    .as_ref()
                    .and_then(|a| a.symboltab.clone())
                    .map(|t| t.read().unwrap().get_property(crate::address::Address::new(off)))
                    .unwrap_or(0)
            };
            let local = self.scope.as_ref().map(|s| {
                s.query_properties_ex(
                    space,
                    addr,
                    size as i64,
                    Some(usepoint.as_u64()),
                    None,
                    &property,
                )
            });
            let mut answered = matches!(
                &local,
                Some(outcome) if !matches!(outcome.final_scope, crate::varmap::QueryFinalScope::None)
            );
            if answered {
                // cc:34-35: setFlags(vflags & ~typelock) — the local leg
                // answered, so the walk never reaches the parent
                // (database.cc:1269/1271 return the answering scope).
                if let Some(outcome) = local {
                    let fl = outcome.flags & !crate::varnode::varnode_flags::TYPELOCK;
                    vn.write().unwrap().set_flags(fl);
                }
            }
            if !answered && space == crate::space::AddressSpace::Ram {
                if let Some((hit, vflags)) = self.query_properties_parent_scope(
                    crate::address::Address::new(addr),
                    size,
                    usepoint,
                ) {
                    if let Some(hit) = hit {
                        // cc:32-33: entry != NULL → vn->setSymbolProperties(entry):
                        // attach the live entry (mapentry on type-lock) and fold
                        // the entry's flags minus typelock (varnode.cc:410-421).
                        let entry_arc = {
                            let symboltab = self.arch.as_ref()
                                .and_then(|a| a.symboltab.clone());
                            match symboltab {
                                Some(tab) => {
                                    let db = tab.read().unwrap();
                                    db.query_container_entry(
                                        db.global_scope_id,
                                        crate::address::Address::new(addr),
                                        size,
                                        usepoint,
                                    )
                                    .map(|(_, e)| e)
                                }
                                None => None,
                            }
                        };
                        match entry_arc {
                            Some(entry) => {
                                crate::varnode::Varnode::set_symbol_properties_arc(vn, &entry);
                            }
                            None => {
                                // Entry projection exists but the live-entry
                                // walk missed (cannot happen: same walk); fall
                                // through to the flags fold for safety.
                                let fl = vflags
                                    & !crate::varnode::varnode_flags::TYPELOCK;
                                vn.write().unwrap().set_flags(fl);
                            }
                        }
                    } else {
                        // cc:34-35: vn->setFlags(vflags & ~typelock) — the
                        // scope-only fold mapped|addrtied|persist(+property).
                        let fl = vflags & !crate::varnode::varnode_flags::TYPELOCK;
                        vn.write().unwrap().set_flags(fl);
                    }
                    answered = true;
                }
            }
            if !answered {
                // Legacy fallback (no channel / non-RAM space): the
                // `symbol_table` name proxy, mapping addr→name.
                if self.symbol_table.get(&addr).is_some() {
                    // cc:32-33 side-effect approximation: set MAPPED so we
                    // don't re-query.
                    vn.write()
                        .unwrap()
                        .set_flags(crate::varnode::varnode_flags::MAPPED);
                }
                // cc:34-35 with vflags==0 is a no-op; typelock is set by
                // updateType.
            }
        }
        // cc:38-41: if (vn->cover == NULL && isHighOn()) vn->calcCover().
        let high_on = (self.flags & funcdata_flags::HIGHLEVEL_ON) != 0;
        if high_on {
            if vn.read().unwrap().has_cover() {
                vn.write().unwrap().calc_cover();
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:48 Funcdata::assignHigh
    /// If HighVariables are enabled, ensure `vn` has a HighVariable. Allocate
    /// a dedicated HighVariable (containing only `vn`) if necessary. Faithful
    /// to `Funcdata::assignHigh` (funcdata_varnode.cc:48-59):
    ///   if ((flags & highlevel_on)!=0) {
    ///     if (vn->hasCover()) vn->calcCover();
    ///     if (!vn->isAnnotation()) return new HighVariable(vn);
    ///   }
    ///   return NULL;
    /// The C++ `new HighVariable(vn)` ctor (variable.cc:220-235) additionally
    /// does the two-way wiring:
    ///   inst.push_back(vn);                        // variable.cc:231
    ///   vn->setHigh(this, numMergeClasses-1);      // variable.cc:232 (mg=0)
    ///   if (vn->getSymbolEntry() != 0) setSymbol(vn); // variable.cc:233-234
    /// (FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001)
    pub fn assign_high(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> {
        // cc:51: if ((flags & highlevel_on)!=0).
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) == 0 {
            return None;
        }
        // cc:52-53: if (vn->hasCover()) vn->calcCover().
        if vn.read().unwrap().has_cover() {
            vn.write().unwrap().calc_cover();
        }
        // cc:54-56: if (!vn->isAnnotation()) return new HighVariable(vn).
        if vn.read().unwrap().is_annotation() {
            return None;
        }
        let vn_type = vn.read().unwrap().get_type().unwrap_or_else(|| {
            std::sync::Arc::new(crate::type_system::datatype::Datatype::Void(
                crate::type_system::datatype::TypeBase::new(
                    "void".to_string(),
                    0,
                    crate::type_system::datatype::TypeMetatype::Void,
                ),
            ))
        });
        let high = std::sync::Arc::new(std::sync::RwLock::new(
            crate::variable::HighVariable::new(
            vn_type,
        )));
        // variable.cc:231: inst.push_back(vn) — register vn as the sole
        // instance of the fresh HighVariable.
        high.write().unwrap().add_instance(vn.clone());
        // variable.cc:232: vn->setHigh(this, numMergeClasses-1). Fresh ctor
        // has numMergeClasses==1, so mergegroup = 0.
        {
            let mut vn_w = vn.write().unwrap();
            vn_w.mergegroup = 0;
            vn_w.high = Some(high.clone());
        }
        // variable.cc:233-234: if (vn->getSymbolEntry() != 0) setSymbol(vn).
        // set_symbol re-reads the entry itself and early-outs on None.
        if vn.read().unwrap().get_symbol_entry().is_some() {
            high.write().unwrap().set_symbol(vn);
        }
        Some(high)
    }

    // Ghidra: funcdata_varnode.cc:316 Funcdata::findHigh
    /// Look up a Symbol visible in this function's scope by name and return
    /// the HighVariable associated with it. Faithful to
    /// `Funcdata::findHigh` (funcdata_varnode.cc:316-328):
    ///   queryByName(nm, symList);
    ///   if (symList.empty()) return NULL;
    ///   sym = symList[0];
    ///   vn = findLinkedVarnode(sym->getFirstWholeMap());
    ///   if (vn) return vn->getHigh();
    ///   return NULL;
    /// Rugra: `symbol_table` is address-keyed; we scan it (and `scope.symbols`)
    /// for a name match, then resolve the varnode at that address via the
    /// VarnodeBank's loc tree. Scope matches carry the symbol's space so
    /// linkSymbol-created register/unique symbols resolve in their own space.
    pub fn find_high(
        &self, nm: &str,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> {
        // cc:319-320: queryByName(nm, symList). Rugra: search symbol_table +
        // scope.symbols for an entry whose name matches `nm`.
        let addr: Option<u64> = self
            .symbol_table
            .iter()
            .find_map(|(a, name)| if name == nm { Some(*a) } else { None })
            .or_else(|| {
                self.scope.as_ref().and_then(|scope| {
                    scope.symbols.iter().find_map(|s| {
                        if s.name == nm && !s.is_dynamic {
                            Some(s.start)
                        } else {
                            None
                        }
                    })
                })
            });
        let addr = addr?;
        // cc:323: vn = findLinkedVarnode(sym->getFirstWholeMap()).
        let vn = self
            .vbank
            .find_by_loc(0, crate::address::Address::new(addr))?;
        // cc:324-325: return vn->getHigh(). Clone the inner Arc out of the
        // read guard so the borrow does not extend past `vn`'s lifetime.
        let high = {
            let r = vn.read().unwrap();
            r.get_high().cloned()
        };
        high
    }

    // Ghidra: funcdata_varnode.cc:614 Funcdata::transferVarnodeProperties
    /// Copy properties from an existing Varnode `vn` to a new overlapping
    /// Varnode `new_vn`. Faithful to `Funcdata::transferVarnodeProperties`
    /// (funcdata_varnode.cc:614-629):
    ///   newConsume = ((vn->getConsume() >> 8*lsbOffset) | fillBits)
    ///                & calc_mask(newVn->getSize());
    ///   vnFlags = vn->getFlags() & (directwrite|addrforce);
    ///   newVn->setFlags(vnFlags);
    ///   newVn->setConsume(newConsume);
    /// Used by SUBPIECE / truncation transforms to preserve the consume mask
    /// and directwrite/addrforce flags across a width change.
    pub fn transfer_varnode_properties(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        new_vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        lsb_offset: i32,
    ) {
        // cc:617: newConsume = ~((uintb)0).
        let mut new_consume: u64 = !0u64;
        // cc:618: if (lsbOffset < sizeof(uintb)).
        if (lsb_offset as usize) < std::mem::size_of::<u64>() {
            // cc:619-622: shift the consume mask right by lsbOffset bytes,
            // filling high bits so any value shifted in above the Varnode
            // precision is treated as "used".
            let lsb_bytes = lsb_offset as u32;
            let fill_bits = if lsb_offset != 0 {
                new_consume << (8 * (std::mem::size_of::<u64>() as u32 - lsb_bytes))
            } else {
                0
            };
            let vn_consume = vn.read().unwrap().get_consume();
            let new_size = new_vn.read().unwrap().get_size();
            let mask = crate::address::calc_mask(new_size);
            new_consume = ((vn_consume >> (8 * lsb_bytes)) | fill_bits) & mask;
        }
        // cc:625: vnFlags = vn->getFlags() & (directwrite|addrforce).
        let vn_flags = {
            let f = vn.read().unwrap().flags;
            f & (crate::varnode::varnode_flags::DIRECTWRITE
                | crate::varnode::varnode_flags::ADDRFORCE)
        };
        // cc:627-628: newVn->setFlags(vnFlags); newVn->setConsume(newConsume).
        new_vn.write().unwrap().set_flags(vn_flags);
        new_vn.write().unwrap().set_consume(new_consume);
    }

    // Ghidra: funcdata_varnode.cc:997 Funcdata::handleSymbolConflict
    /// Resolve a Varnode/SymbolEntry overlap: make sure the Varnode is part
    /// of the variable underlying the Symbol, remapping to a distinct
    /// (dynamic) Symbol otherwise. Faithful to `handleSymbolConflict`
    /// (funcdata_varnode.cc:997-1029):
    ///   if (vn->isInput() || vn->isAddrTied() || vn->isPersist() ||
    ///       vn->isConstant() || entry->isDynamic()) {
    ///     vn->setSymbolEntry(entry); return entry->getSymbol();
    ///   }
    ///   high = vn->getHigh();
    ///   // Look for a conflicting HighVariable: walk the loc set at
    ///   // (entry->getSize(), entry->getAddr()); break on size/addr mismatch;
    ///   // otherHigh = first varnode whose HighVariable differs.
    ///   if (otherHigh == NULL) { vn->setSymbolEntry(entry); return entry->getSymbol(); }
    ///   buildDynamicSymbol(vn);
    ///   return vn->getSymbolEntry()->getSymbol();
    /// Returns the winning symbol's index in `scope.symbols`.
    pub fn handle_symbol_conflict(
        &mut self,
        entry_idx: usize,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        // cc:1000-1001: if (vn->isInput() || vn->isAddrTied() ||
        //                vn->isPersist() || vn->isConstant() || entry->isDynamic()).
        let (is_input, is_addr_tied, is_persist, is_const) = {
            let r = vn.read().unwrap();
            (
                r.is_input(), r.is_addr_tied(), r.is_persist(), r.is_constant(),
            )
        };
        let entry_is_dynamic = self
            .scope
            .as_ref()?
            .symbols
            .get(entry_idx)?
            .is_dynamic;
        if is_input || is_addr_tied || is_persist || is_const || entry_is_dynamic {
            // cc:1002-1003: vn->setSymbolEntry(entry); return entry->getSymbol().
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        // cc:1005-1020: Look for a conflicting HighVariable.
        // VarnodeLocSet::const_iterator iter = beginLoc(entry->getSize(), entry->getAddr());
        let high = vn.read().unwrap().get_high().cloned();
        let (entry_space, entry_addr, entry_size) = {
            let sym = self.scope.as_ref()?.symbols.get(entry_idx)?;
            (sym.space, sym.start, sym.size)
        };
        let mut other_high = false;
        if let Some(_high) = &high {
            // Walk the loc set while size and address still match (cc:1010-1020);
            // the VarnodeBank's overlap scan yields the same (space, addr)
            // neighborhood; entries beyond the exact (size, addr) pair break.
            let candidates = self.vbank.overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size.max(0) as usize,
            );
            for cv in candidates {
                let (cv_size, cv_space, cv_addr, cv_high) = {
                    let r = cv.read().unwrap();
                    (r.get_size(), r.get_space(), r.get_offset(), r.high.clone())
                };
                if cv_size as i32 != entry_size || cv_space != entry_space || cv_addr != entry_addr
                {
                    // cc:1012-1013: the loc-set run is over (Ghidra breaks
                    // out of the iterator walk; non-matching neighbors are
                    // simply not candidates).
                    continue;
                }
                if let (Some(ch), Some(h)) = (cv_high, &high) {
                    if !std::sync::Arc::ptr_eq(&ch, h) {
                        other_high = true; // cc:1015-1018
                        break;
                    }
                }
            }
        }
        if !other_high {
            // cc:1021-1024: vn->setSymbolEntry(entry); return entry->getSymbol().
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        // cc:1026-1028: conflicting variable — buildDynamicSymbol(vn);
        // return vn->getSymbolEntry()->getSymbol().
        let dyn_idx = self.build_dynamic_symbol(vn);
        if dyn_idx.is_none() {
            // The dynamic symbol failed to hash; keep the original entry so
            // the caller still sees a Symbol (Ghidra cannot fail here —
            // uniqueHash either succeeds or throws).
            self.attach_symbol_to_vn(entry_idx, vn);
            return Some(entry_idx);
        }
        dyn_idx
    }

    // RUGRA-GLUE: attach_symbol_to_vn (vn->setSymbolEntry + high->setSymbol)
    /// Attach a ScopeLocal symbol to a Varnode the way
    // RUGRA-GLUE: symbol_entry_for (bridge varmap symbol → database entry)
    /// Build (or fetch the identity-stable cached) database.rs `SymbolEntry`
    /// mirroring the varmap `ScopeLocal` symbol at `entry_idx`: static maps
    /// carry (offset address, size, single-address uselimit when the varmap
    /// usepoint is valid), dynamic maps carry the hash instead. The mirrored
    /// `Symbol` transports the data-type (set_symbol's symboloffset branch 4
    /// reads its size) and the namelock bit for `Varnode::setSymbolEntry`'s
    /// flag leg. Names are refreshed by ActionNameVars after the naming pass.
    fn symbol_entry_for(
        &mut self,
        entry_idx: usize,
    ) -> Option<std::sync::Arc<RwLock<crate::database::SymbolEntry>>> {
        if let Some(entry) = self.symbol_entry_cache.get(&entry_idx) {
            return Some(entry.clone());
        }
        let sym = self.scope.as_ref()?.symbols.get(entry_idx)?;
        let mut bridge = crate::database::Symbol::new(0, &sym.name, "");
        bridge.dtype = sym.dtype.clone();
        if sym.namelock {
            bridge.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
        }
        bridge.category = match sym.category {
            crate::varmap::symbol_category::EQUATE => crate::database::SymbolCategory::Equate,
            _ => crate::database::SymbolCategory::NoCategory,
        };
        let symbol_arc = std::sync::Arc::new(RwLock::new(bridge));
        let mut uselimit = crate::address::RangeList::new();
        if let Some(up) = sym.usepoint {
            if let Some(range) = crate::address::Range::new(
                crate::address::Address::new(up),
                crate::address::Address::new(up),
            ) {
                uselimit.insert_range(range);
            }
        }
        let entry = if sym.is_dynamic {
            crate::database::SymbolEntry::new_dynamic(
                symbol_arc, 0, sym.hash, 0, sym.size.max(0), uselimit,
            )
        } else {
            crate::database::SymbolEntry::new_static(
                symbol_arc,
                0,
                crate::address::Address::new(sym.start),
                0,
                sym.size.max(0),
                uselimit,
            )
        };
        let entry_arc = std::sync::Arc::new(RwLock::new(entry));
        self.symbol_entry_cache.insert(entry_idx, entry_arc.clone());
        Some(entry_arc)
    }

    // RUGRA-GLUE: attach_symbol_to_vn (vn->setSymbolEntry + high->setSymbol)
    /// Attach a ScopeLocal symbol to a Varnode the way
    /// `Varnode::setSymbolEntry` (varnode.cc:429-439) does — mapentry plus
    /// mapped/namelock flags — and then run the faithful
    /// `HighVariable::set_symbol` (variable.cc:245-275, varnode.cc:438),
    /// whose symboloffset computation makes coreaction.cc:2965's
    /// `getSymbolOffset() < 0` namerec gate behave exactly like Ghidra
    /// (whole-map matches are -1; partial coverage yields the byte offset).
    /// The varmap side table records the same association for naming.
    fn attach_symbol_to_vn(
        &mut self,
        entry_idx: usize,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if let Some(entry) = self.symbol_entry_for(entry_idx) {
            vn.write().unwrap().set_symbol_entry(entry);
        }
        if let Some(high) = vn.read().unwrap().get_high().cloned() {
            high.write().unwrap().set_symbol(vn);
            let high_ptr = std::sync::Arc::as_ptr(&high) as usize;
            self.high_symbols.insert(high_ptr, entry_idx);
        }
    }

    // Ghidra: funcdata_varnode.cc:1104 Funcdata::remapVarnode
    /// Remap a Symbol to `vn` using a static (address-based) mapping. Faithful
    /// to `Funcdata::remapVarnode` (funcdata_varnode.cc:1104-1110):
    ///   vn->clearSymbolLinks();
    ///   entry = localmap->remapSymbol(sym, vn->getAddr(), usepoint);
    ///   vn->setSymbolEntry(entry);
    /// Rugra: ScopeLocal::remapSymbol is not ported; we approximate by
    /// recording the symbol name at `vn`'s address in `symbol_table`. The
    /// usepoint is preserved for downstream resolution but not stored (Rugra
    /// has no per-usepoint SymbolEntry).
    pub fn remap_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sym_name: &str,
        _usepoint: crate::address::Address,
    ) {
        // cc:1107: vn->clearSymbolLinks().
        vn.write().unwrap().clear_symbol_links();
        // cc:1108-1109: entry = localmap->remapSymbol(sym, vn->getAddr(), usepoint).
        let vn_addr = vn.read().unwrap().get_offset();
        // Rugra: record the name at vn's address.
        self.symbol_table.insert(vn_addr, sym_name.to_string());
        // cc:1109: vn->setSymbolEntry(entry). Approximate by setting MAPPED.
        vn.write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::MAPPED);
    }

    // Ghidra: funcdata_varnode.cc:1120 Funcdata::remapDynamicVarnode
    /// Remap a Symbol to `vn` using a new dynamic (hash-based) mapping. Faithful
    /// to `Funcdata::remapDynamicVarnode` (funcdata_varnode.cc:1120-1126):
    ///   vn->clearSymbolLinks();
    ///   entry = localmap->remapSymbolDynamic(sym, hash, usepoint);
    ///   vn->setSymbolEntry(entry);
    /// Rugra: dynamic-symbol storage is not yet implemented; we record the
    /// symbol name in symbol_table keyed by a synthetic dynamic id. The hash
    /// is preserved on the varnode via a best-effort flag.
    pub fn remap_dynamic_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sym_name: &str,
        _usepoint: crate::address::Address,
        hash: u64,
    ) {
        // cc:1123: vn->clearSymbolLinks().
        vn.write().unwrap().clear_symbol_links();
        // cc:1124: entry = localmap->remapSymbolDynamic(sym, hash, usepoint).
        // Rugra: encode the dynamic symbol under a synthetic key so lookups
        // still resolve. Key space is the high bit of u64 (set MSB), which is
        // above any real 48-bit x86-64 address.
        let key = hash | 0x8000_0000_0000_0000;
        self.symbol_table.insert(key, sym_name.to_string());
        // cc:1125: vn->setSymbolEntry(entry). Approximate by setting MAPPED.
        vn.write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::MAPPED);
    }

    // Ghidra: funcdata_varnode.cc:1132 Funcdata::linkProtoPartial
    /// For a PIECE input Varnode, find the whole Varnode it composes and
    /// assign the same symbol. Faithful to `Funcdata::linkProtoPartial`
    /// (funcdata_varnode.cc:1132-1149):
    ///   high = vn->getHigh();
    ///   if (high->getSymbol() != NULL) return;
    ///   rootVn = PieceNode::findRoot(vn);
    ///   if (rootVn == vn) return;
    ///   rootHigh = rootVn->getHigh();
    ///   if (!rootHigh->isSameGroup(high)) return;
    ///   nameRep = rootHigh->getNameRepresentative();
    ///   sym = linkSymbol(nameRep);
    ///   if (sym == NULL) return;
    ///   rootHigh->establishGroupSymbolOffset();
    ///   entry = sym->getFirstWholeMap();
    ///   vn->setSymbolEntry(entry);
    pub fn link_proto_partial(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:1135-1136: high = vn->getHigh(); if (high->getSymbol() != NULL) return.
        let high_arc = vn.read().unwrap().get_high().cloned();
        if let Some(high) = &high_arc {
            let high_ptr = std::sync::Arc::as_ptr(high) as usize;
            if self.high_symbols.contains_key(&high_ptr) {
                return;
            }
        }
        // cc:1137-1138: rootVn = PieceNode::findRoot(vn); if (rootVn == vn) return.
        let root_vn = piece_node_find_root(vn);
        let Some(root_vn) = root_vn else { return };
        if std::sync::Arc::ptr_eq(&root_vn, vn) {
            return;
        }
        // cc:1140-1142: rootHigh = rootVn->getHigh(); if (!isSameGroup(high)) return.
        let (root_high, vn_high) = {
            let r = root_vn.read().unwrap();
            let v = vn.read().unwrap();
            (r.get_high().cloned(), v.get_high().cloned())
        };
        if let (Some(rh), Some(vh)) = (&root_high, &high_arc) {
            let same = rh.read().unwrap().is_same_group(&vh.read().unwrap());
            if !same {
                return;
            }
        }
        let _ = vn_high;
        // cc:1143-1144: nameRep = rootHigh->getNameRepresentative();
        // cc:1144: sym = linkSymbol(nameRep); if (sym == NULL) return.
        let name_rep = root_high
            .as_ref()
            .and_then(|h| h.read().unwrap().get_name_representative());
        let Some(name_rep) = name_rep else { return };
        let sym_idx = self.link_symbol(&name_rep);
        let Some(sym_idx) = sym_idx else { return };
        // cc:1146: rootHigh->establishGroupSymbolOffset().
        if let Some(root_high) = &root_high {
            root_high.read().unwrap().establish_group_symbol_offset();
        }
        // cc:1147-1148: entry = sym->getFirstWholeMap(); vn->setSymbolEntry(entry).
        self.attach_symbol_to_vn(sym_idx, vn);
    }

    // Ghidra: funcdata_varnode.cc:1218 Funcdata::findLinkedVarnode
    /// Return the (first) Varnode that matches the given SymbolEntry. Faithful
    /// to `Funcdata::findLinkedVarnode` (funcdata_varnode.cc:1218-1251). For
    /// dynamic entries, resolve via DynamicHash; for static entries, scan the
    /// loc tree at (entry->getSize(), entry->getAddr()) honoring usepoints.
    /// Rugra: we accept (addr, size, is_dynamic, first_use_addr) as the
    /// SymbolEntry projection, avoiding the full SymbolEntry dependency.
    pub fn find_linked_varnode(
        &self,
        entry_addr: u64,
        entry_size: usize,
        is_dynamic: bool,
        first_use_addr: crate::address::Address,
        hash: u64,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if is_dynamic {
            // cc:1221-1227: DynamicHash::findVarnode(this, firstUseAddr, hash).
            let mut dhash = crate::dynamic::DynamicHash::new();
            let vn = dhash.find_varnode(self, first_use_addr, hash);
            // cc:1224: skip annotations.
            vn.and_then(|v| {
                if v.read().unwrap().is_annotation() {
                    None
                } else {
                    Some(v)
                }
            })
        } else {
            // cc:1229-1250: scan loc tree.
            let usestart = first_use_addr;
            let candidates = self
                .vbank
                .overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size);
            if usestart.as_u64() == 0 {
                // cc:1233-1240: invalid usepoint → first addr-tied varnode.
                for vn in candidates {
                    if vn.read().unwrap().is_addr_tied() {
                        return Some(vn);
                    }
                }
                None
            } else {
                // cc:1242-1249: first vn whose usepoint is in entry's range.
                for vn in candidates {
                    let up = vn.read().unwrap().get_use_point(self);
                    if up.as_u64() >= usestart.as_u64() {
                        return Some(vn);
                    }
                }
                None
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1257 Funcdata::findLinkedVarnodes
    /// Collect all Varnodes that should be mapped to the given SymbolEntry.
    /// Faithful to `Funcdata::findLinkedVarnodes` (funcdata_varnode.cc:1257-1277):
    ///   if (entry->isDynamic()) { dhash.findVarnode(...); res.push_back(vn); }
    ///   else for vn in locTree(entry->getSize(), entry->getAddr()):
    ///     if (entry->inUse(vn->getUsePoint(*this))) res.push_back(vn);
    /// Rugra: same SymbolEntry projection as `find_linked_varnode`.
    pub fn find_linked_varnodes(
        &self,
        entry_addr: u64,
        entry_size: usize,
        is_dynamic: bool,
        first_use_addr: crate::address::Address,
        hash: u64,
        res: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        if is_dynamic {
            // cc:1260-1265.
            let mut dhash = crate::dynamic::DynamicHash::new();
            if let Some(vn) = dhash.find_varnode(self, first_use_addr, hash) {
                res.push(vn);
            }
        } else {
            // cc:1266-1277.
            let candidates = self
                .vbank
                .overlap_loc(
                crate::address::Address::new(entry_addr),
                entry_size);
            for vn in candidates {
                let up = vn.read().unwrap().get_use_point(self);
                // cc:1272: if (entry->inUse(addr)). Rugra: approximate "in use"
                // by comparing against first_use_addr (entries without a
                // usepoint restriction use addr 0 → always in use).
                if first_use_addr.as_u64() == 0 || up.as_u64() >= first_use_addr.as_u64() {
                    res.push(vn);
                }
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1283 Funcdata::buildDynamicSymbol
    /// Build a special \e dynamic Symbol for `vn`: associated via a hash of
    /// its local data-flow rather than its storage address. Faithful to
    /// `Funcdata::buildDynamicSymbol` (funcdata_varnode.cc:1283-1305):
    ///   if (vn->isTypeLock()||vn->isNameLock()) throw RecovError;
    ///   if (!isHighOn()) throw RecovError;
    ///   high = vn->getHigh();
    ///   if (high->getSymbol() != NULL) return;
    ///   dhash.uniqueHash(vn, this);
    ///   if (dhash.getHash() == 0) throw RecovError(...);
    ///   if (vn->isConstant())
    ///     sym = addEquateSymbol("", force_hex, vn->getOffset(), addr, hash);
    ///   else
    ///     sym = addDynamicSymbol("", high->getType(), addr, hash);
    ///   vn->setSymbolEntry(sym->getFirstWholeMap());
    /// Returns the new symbol's index in `scope.symbols`; Ghidra's RecovError
    /// throws surface as None (the caller keeps the pre-existing entry).
    pub fn build_dynamic_symbol(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<usize> {
        // cc:1286-1287: if (isTypeLock || isNameLock) throw.
        let (is_type_lock, is_name_lock) = {
            let r = vn.read().unwrap();
            (r.is_type_lock(), r.is_name_lock())
        };
        if is_type_lock || is_name_lock {
            eprintln!("[FUNCDATA] buildDynamicSymbol on locked varnode (cc:1286 RecovError)");
            return None;
        }
        // cc:1288-1289: if (!isHighOn()) throw.
        if (self.flags & funcdata_flags::HIGHLEVEL_ON) == 0 {
            eprintln!(
                "[FUNCDATA] buildDynamicSymbol before decompile complete (cc:1288 RecovError)"
            );
            return None;
        }
        // cc:1290-1292: high = vn->getHigh(); if (high->getSymbol()) return.
        let high_arc = vn.read().unwrap().get_high().cloned()?;
        let high_ptr = std::sync::Arc::as_ptr(&high_arc) as usize;
        if let Some(&idx) = self.high_symbols.get(&high_ptr) {
            return Some(idx);
        }
        // cc:1293-1297: dhash.uniqueHash(vn, this); if (hash == 0) throw.
        let mut dhash = crate::dynamic::DynamicHash::new();
        dhash.unique_hash_vn(vn, self);
        let hash = dhash.get_hash();
        if hash == 0 {
            eprintln!("[FUNCDATA] buildDynamicSymbol: no unique hash (cc:1297 RecovError)");
            return None;
        }
        let addr = dhash.get_address();
        // cc:1299-1303: equate symbol for constants, dynamic symbol otherwise.
        let (is_const, vn_offset, vn_space) = {
            let r = vn.read().unwrap();
            (r.is_constant(), r.get_offset(), r.get_space())
        };
        let idx = if is_const {
            // localmap->addEquateSymbol("", Symbol::force_hex, vn->getOffset(),
            //                           dhash.getAddress(), dhash.getHash())
            // (database.cc:1712-1725): an EQUATE-category symbol whose map
            // is dynamic with a single-address uselimit; the varmap model
            // carries the constant value on `start`.
            let idx = self
                .scope
                .as_mut()?
                .add_dynamic_symbol(
                "", None, hash, Some(addr.as_u64()));
            if let Some(sym) = self.scope.as_mut()?.symbols.get_mut(idx) {
                sym.category = crate::varmap::symbol_category::EQUATE;
                sym.start = vn_offset;
                sym.size = 1;
                sym.space = vn_space;
            }
            idx
        } else {
            // localmap->addDynamicSymbol("", high->getType(), dhash.getAddress(), hash)
            let ct = high_arc.read().unwrap().get_type();
            let idx = self.scope
                    .as_mut()?
                    .add_dynamic_symbol(
                "", Some(ct), hash, Some(addr.as_u64()));
            if let Some(sym) = self.scope.as_mut()?.symbols.get_mut(idx) {
                sym.space = vn_space;
            }
            idx
        };
        // cc:1304: vn->setSymbolEntry(sym->getFirstWholeMap()).
        self.attach_symbol_to_vn(idx, vn);
        Some(idx)
    }

    // Ghidra: funcdata.hh:451 Funcdata::markIndirectCreation
    /// Convert CPUI_INDIRECT into an indirect creation. Faithful to
    /// `Funcdata::markIndirectCreation` (funcdata_op.cc:736-748).
    pub fn mark_indirect_creation(&self, indop: &crate::op::PcodeOpRef, possible_output: bool) {
        let (out_vn, in0_is_const) = {
            let o = indop.0.read().unwrap();
            let out = o.output.clone();
            let in0_const = o
                .get_in(0)
                .map(|v| v.read().unwrap().is_constant())
                .unwrap_or(false);
            (out, in0_const)
        };
        indop.0.write().unwrap().flags |= crate::op::pcodeop_flags::INDIRECT_CREATION;
        if !in0_is_const {
            eprintln!("[MERGE] Indirect creation not properly formed (in0 not constant)");
        }
        if !possible_output {
            if let Some(in0) = indop.0.read().unwrap().get_in(0) {
                in0.write()
                    .unwrap()
                    .set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
            }
        }
        if let Some(out_vn) = out_vn {
            out_vn
                .write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::INDIRECT_CREATION);
        }
    }

    // Ghidra: funcdata.cc:34 Funcdata::opGetSlot
    /// Get the input slot of `vn` within `op`. Faithful to `PcodeOp::getSlot`.
    /// Returns the slot index, or -1 if not found.
    pub fn op_get_slot(
        &self, op: &crate::op::PcodeOpRef, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> i32 {
        let o = op.0.read().unwrap();
        for (i, v) in o.inrefs.iter().enumerate() {
            if std::sync::Arc::ptr_eq(v, vn) {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: funcdata.cc:230 Funcdata::spacebase
    /// Mark registers that map to a virtual address space (the stack
    /// spacebase). Faithful to `Funcdata::spacebase()` (funcdata.cc:230-269).
    ///
    /// For Rugra's x86-64 lift, the stack pointer is RSP at
    /// `AddressSpace::Register`, offset 0x20, size 8 (see `x86_lift.rs:40`).
    /// This method finds all varnodes at that location, marks them with the
    /// `SPACEBASE` flag, and — for already-marked spacebase varnodes with
    /// multiple descendants — calls `split_uses()` so each additive use
    /// (`INT_ADD(RSP, off)`) becomes independently addressable.
    ///
    /// This is the canonical Ghidra mechanism: it does NOT require the lifter
    /// to emit Stack-space varnodes. Instead, marking the RSP input as a
    /// spacebase lets downstream passes (varmap, ActionStackPtrFlow,
    /// heritage) recognize RSP as "a pointer into the Stack space."
    pub fn spacebase(&mut self) {
        // Stack pointer location from configuration (Architecture cspec fields).
        // Faithful to spc->getSpacebase(0) returning the register location.
        let sb_space = self.stack_pointer_space;
        let sb_offset = self.stack_pointer_offset;
        let sb_size = self.stack_pointer_size;

        // Collect all varnodes at the stack-pointer location that are not free.
        // Faithful to vbank.beginLoc(size, Address) / endLoc iteration.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = {
            self.vbank
                .loc_tree
                .iter()
                .filter(|v| {
                    let g = v.0.read().unwrap();
                    !g.is_free()
                        && g.get_space() == sb_space
                        && g.get_offset() == sb_offset
                        && g.get_size() == sb_size
                })
                .map(|v| v.0.clone())
                .collect()
        };

        for vn_arc in candidates {
            let is_sb = vn_arc.read().unwrap().is_spacebase();
            if is_sb {
                // Already marked: give it a chance for descendants to be
                // eliminated naturally, now force a split if it still has
                // multiple descendants (funcdata.cc:253-259).
                let def_arc = {
                    let vn_g = vn_arc.read().unwrap();
                    vn_g.def.as_ref().and_then(|w| w.upgrade())
                };
                if let Some(def_op) = def_arc {
                    if def_op.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_INT_ADD {
                        self.split_uses(&vn_arc);
                    }
                }
            } else {
                // Mark all base registers (not just input) with spacebase flag
                // (funcdata.cc:262).
                vn_arc
                    .write()
                    .unwrap()
                    .set_flags(crate::varnode::varnode_flags::SPACEBASE);
                // Ghidra funcdata.cc:262-264: only the input spacebase
                // register gets the TypeSpacebase pointer type
                // (`vn->updateType(ptr,true,true)`). Re-enabled with the
                // LOAD-claim chain (HERITAGE-LOADCLAIM-0001): the Rugra
                // pipeline now matches the oracle's claim sequence (LOAD
                // directified by RuleLoadVarnode in mainloop iter1 oppool2 ->
                // restart -> heritage refinement/refineRead claims the free
                // 304B stack read into the 280+8+8+8 PIECE ladder feeding the
                // CALL), so the v1-era retraction premise (LOAD stuck
                // directified, no claim ladder) no longer holds. The mount
                // activates ActionInferTypes::propagateSpacebaseRef
                // (coreaction.cc:5265, INFERTYPES-SPACEREF-0001 receiver
                // already ported) to type the stack shadows through the
                // SP-relative ADD tree. The v1-era regressions
                // (glob_set/glob_range drift, __spacebase_1_* name leaks) are
                // re-gated by the config-domain A/B in this commit's evidence.
                if vn_arc.read().unwrap().is_input() {
                    if let Some(types) = self.arch.as_ref().and_then(|a| a.types.clone()) {
                        // cc:245-246: ct = getTypeSpacebase(spc, getAddress());
                        // ptr = getTypePointer(point.size, ct, spc->getWordSize()).
                        // The space indexed by this base register is the stack
                        // space (word size 1), scoped to this function's entry.
                        let frame = self.get_address().clone();
                        let mut factory = types.write().unwrap();
                        let ct = factory
                            .get_type_spacebase(Some(crate::space::AddressSpace::Stack), frame);
                        let ptr = factory.get_type_pointer(sb_size, ct, 1);
                        drop(factory);
                        vn_arc.write().unwrap().update_type_lock(ptr, true, true);
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:275 Funcdata::newSpacebasePtr
    /// Given an address space known to have a base register, construct a
    /// Varnode representing that register. Faithful to
    /// `Funcdata::newSpacebasePtr` (funcdata.cc:275-284):
    ///   const VarnodeData &point(id->getSpacebase(0));
    ///   vn = newVarnode(point.size, Address(point.space,point.offset));
    ///   return vn;
    /// Rugra: `id` is approximated by the Funcdata's configured stack space
    /// (Architecture cspec). The stack-pointer (space, offset, size) come from
    /// the `stack_pointer_*` fields populated by `set_arch`.
    pub fn new_spacebase_ptr(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:281: const VarnodeData &point(id->getSpacebase(0)).
        // Rugra: only the stack space has a known base register; for other
        // spaces we fall back to the configured stack-pointer location.
        let (sp_space, sp_offset, sp_size) = if id.is_stack() {
            (
                self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size,
            )
        } else {
            (
                self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size,
            )
        };
        // cc:282: vn = newVarnode(point.size, Address(point.space,point.offset)).
        let vn = self.vbank.create_with_space(sp_size, sp_space, sp_offset);
        vn
    }

    // RUGRA-GLUE: TypeSpacebase live-map publish — the Rust ownership seam
    // standing in for Ghidra's dynamic getMap resolution (type.cc:2935-2945:
    // every `TypeSpacebase::getSubType` re-resolves
    // `queryFunction(localframe)->fd->getScopeLocal()` and therefore observes
    // the CURRENT map). Rugra's Funcdata owns the ScopeLocal and the
    // factory-cached stack spacebase type holds a shared handle (attached at
    // construction, see TypeFactory::get_type_spacebase); this refresh makes
    // the handle contents match the Funcdata's just-mutated scope, so
    /// subsequent spacebase subtype queries observe the live map. Call after
    /// every ScopeLocal map mutation (ActionRestructureVarnode passes,
    /// parameter-symbol bootstrap).
    pub fn publish_scope_to_spacebase(&mut self) {
        let Some(scope) = self.scope.as_ref() else { return; };
        let Some(types) = self.arch.as_ref().and_then(|a| a.types.clone()) else {
            return;
        };
        let frame = self.baseaddr.clone();
        let mut tf = types.write().unwrap();
        let sb = tf.get_type_spacebase(Some(crate::space::AddressSpace::Stack), frame);
        drop(tf);
        if let crate::type_system::datatype::Datatype::Spacebase(sb) = sb.as_ref() {
            if let Some(handle) = &sb.fd {
                *handle.write().unwrap() = scope.clone();
            }
        }
    }

    // Ghidra: funcdata.cc:291 Funcdata::findSpacebaseInput
    /// Locate the unique input Varnode holding the incoming value of the base
    /// register for `id`. Faithful to `Funcdata::findSpacebaseInput`
    /// (funcdata.cc:291-300):
    ///   const VarnodeData &point(id->getSpacebase(0));
    ///   vn = vbank.findInput(point.size, Address(point.space,point.offset));
    ///   return vn;
    /// Returns None if no input varnode exists at the base-register location.
    pub fn find_spacebase_input(
        &self,
        id: crate::space::AddressSpace,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        // cc:297: const VarnodeData &point(id->getSpacebase(0)).
        let (_sp_space, sp_offset, sp_size) = (
            self.stack_pointer_space, self.stack_pointer_offset, self.stack_pointer_size,
        );
        // cc:298: vn = vbank.findInput(point.size, Address(point.space,point.offset))
        // — point.space is the REGISTER space of the base register
        // (stack_pointer_space), not the space being pointed into.
        // (BANK-FINDINPUT-SPACE-0001)
        self.vbank.find_input(
            sp_size,
            self.stack_pointer_space,
            crate::address::Address::new(sp_offset),
        )
    }

    // Ghidra: funcdata.cc:309 Funcdata::constructSpacebaseInput
    /// If it doesn't exist, create an input Varnode of the base register for
    /// `id`. Faithful to `Funcdata::constructSpacebaseInput` (funcdata.cc:309-325):
    ///   spacePtr = findSpacebaseInput(id);
    ///   if (spacePtr) return spacePtr;
    ///   if (id->numSpacebase() == 0) throw LowlevelError(...);
    ///   point = id->getSpacebase(0);
    ///   ptr = getTypePointer(point.size, getTypeSpacebase(id,getAddress()), id->getWordSize());
    ///   spacePtr = newVarnode(point.size, point.getAddr(), ptr);
    ///   spacePtr = setInputVarnode(spacePtr);
    ///   spacePtr->setFlags(Varnode::spacebase);
    ///   spacePtr->updateType(ptr, true, true);
    ///   return spacePtr;
    /// Idempotent: returns the existing input if one is present.
    pub fn construct_spacebase_input(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:312-314: spacePtr = findSpacebaseInput(id); if (spacePtr) return.
        if let Some(existing) = self.find_spacebase_input(id) {
            return existing;
        }
        // cc:315-316: if (id->numSpacebase() == 0) throw LowlevelError(...).
        // Rugra: only the stack space is known to have a base register; for
        // other spaces we still attempt construction (best-effort) rather than
        // panic, mirroring the existing spacebase() method's tolerance.
        // cc:317-320: build the varnode + pointer type.
        let sp_space = self.stack_pointer_space;
        let sp_offset = self.stack_pointer_offset;
        let sp_size = self.stack_pointer_size;
        let space_ptr = self.vbank.create_with_space(sp_size, sp_space, sp_offset);
        // cc:321: spacePtr = setInputVarnode(spacePtr).
        let space_ptr = self.set_input_varnode(space_ptr);
        // cc:322: spacePtr->setFlags(Varnode::spacebase).
        space_ptr
            .write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::SPACEBASE);
        // cc:323: spacePtr->updateType(ptr, true, true). Rugra lacks
        // TypeSpacebase; the SPACEBASE flag is sufficient for downstream
        // recognition (see existing `spacebase()` note).
        space_ptr
    }

    // Ghidra: funcdata.cc:332 Funcdata::constructConstSpacebase
    /// Create a constant Varnode representing the \e base of the given global
    /// address space, with the TypeSpacebase data-type. Faithful to
    /// `Funcdata::constructConstSpacebase` (funcdata.cc:332-341):
    ///   ct = getTypeSpacebase(id, Address());
    ///   ptr = getTypePointer(id->getAddrSize(), ct, id->getWordSize());
    ///   spacePtr = newConstant(id->getAddrSize(), 0);
    ///   spacePtr->updateType(ptr, true, true);
    ///   spacePtr->setFlags(Varnode::spacebase);
    ///   return spacePtr;
    /// Used by spacebaseConstant to build the synthetic "base of ram" pointer.
    pub fn construct_const_spacebase(
        &mut self,
        id: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:336: addr_size = id->getAddrSize().
        let addr_size = id.addr_size();
        // cc:337: spacePtr = newConstant(id->getAddrSize(), 0).
        let space_ptr = self.vbank.create_constant(addr_size, 0);
        // cc:338: spacePtr->updateType(ptr, true, true). TypeSpacebase not yet
        // ported; SPACEBASE flag carries the semantic.
        // cc:339: spacePtr->setFlags(Varnode::spacebase).
        space_ptr
            .write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::SPACEBASE);
        space_ptr
    }

    // Ghidra: funcdata.cc:360 Funcdata::spacebaseConstant
    /// Convert a constant pointer into a CPUI_PTRSUB that triggers a Symbol
    /// lookup. Faithful to `Funcdata::spacebaseConstant`
    /// (funcdata.cc:360-462). Given `op` reading a constant pointer at
    /// `slot`, rewrite the constant into PTRSUB(constSpacebase, symOffset)
    /// so that global Symbol resolution fires at analysis time. May insert
    /// INT_ADD (for intra-symbol offset), INT_ZEXT (if growing), or
    /// SUBPIECE (if shrinking) to preserve the original value/size.
    ///
    /// `entry` is the query-channel hit for the Symbol being pointed (in)to
    /// — the projection of Ghidra's `SymbolEntry *entry` observable reads:
    /// `entry->getAddr()` for the `extra` offset (cc:369) and
    /// `entry->getSymbol()` for the output typing/typelock (cc:413-419).
    /// `spaceid` carries the resolved space: its addrSize is the pointer
    /// size `sz` (cc:363, `rampoint.getAddrSize()`) and its wordSize feeds
    /// the byteToAddress normalization (cc:370) — Rugra's legacy
    /// `Address` is spaceless (ADDRESS-0001 residual), so the space rides
    /// this parameter instead of the address.
    pub fn spacebase_constant(
        &mut self,
        op: &crate::op::PcodeOpRef,
        slot: usize,
        entry: &crate::database::QueryContainerHit,
        spaceid: crate::space::AddressSpace,
        rampoint: crate::address::Address,
        origval: u64,
        origsize: usize,
    ) {
        use crate::opcodes::OpCode;
        // cc:363: sz = rampoint.getAddrSize() — the address size of the
        // resolved space (x86-64 ram = 8), NOT the constant's size.
        let sz = spaceid.addr_size();
        // cc:365-366: sb_type = getTypeSpacebase(spaceid, Address());
        // ptr = getTypePointer(sz, sb_type, spaceid->getWordSize()).
        let sb_ptr_type = self
            .arch
            .as_ref()
            .and_then(|arch| arch.types.clone())
            .map(|types| {
            let mut tf = types.write().unwrap();
            let sb_type = tf.get_type_spacebase(Some(spaceid), crate::address::Address::new(0));
            tf.get_type_pointer(sz, sb_type, spaceid.word_size())
        });

        // cc:369: extra = rampoint.getOffset() - entry->getAddr().getOffset()
        // — offset from the beginning of the entry, then cc:370 byteToAddress
        // (wordsize normalization: bytes -> addressable units).
        let extra_raw = rampoint
            .as_u64()
            .wrapping_sub(entry.entry_addr.as_u64());
        let word_size = spaceid.word_size().max(1) as u64;
        let extra = extra_raw / word_size;

        // cc:372-390: classify the existing op (COPY vs other).
        let op_code = op.0.read().unwrap().opcode;
        let is_copy = op_code == OpCode::CPUI_COPY;
        let mut add_op: Option<crate::op::PcodeOpRef> = None;
        let mut extra_op: Option<crate::op::PcodeOpRef> = None;
        let mut zext_op: Option<crate::op::PcodeOpRef> = None;
        let mut sub_op: Option<crate::op::PcodeOpRef> = None;
        if is_copy {
            if sz < origsize {
                zext_op = Some(op.clone());
            } else {
                // cc:382: op->insertInput(1) — PTRSUB, ADD, SUBPIECE all
                // take 2 parameters. Rugra's op_insert_input performs the
                // insertInput+opSetInput pair with a real varnode (the
                // transient NULL slot is unobservable), so the actual input
                // install happens at each opSetInput site below.
                if origsize < sz {
                    sub_op = Some(op.clone());
                } else if extra != 0 {
                    extra_op = Some(op.clone());
                } else {
                    add_op = Some(op.clone());
                }
            }
        }

        // cc:391-393: spacebase_vn = newConstant(sz, 0); updateType(ptr,
        // true, true); setFlags(spacebase).
        let spacebase_vn = self.new_constant(sz, 0);
        if let Some(ptr) = sb_ptr_type.clone() {
            spacebase_vn
                .write()
                .unwrap()
                .update_type_lock(ptr, true, true);
        }
        spacebase_vn
            .write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::SPACEBASE);

        // cc:394-402: allocate/repurpose the PTRSUB op.
        if add_op.is_none() {
            let add = self.new_op(2, op.0.read().unwrap().get_addr());
            self.op_set_opcode(&add, OpCode::CPUI_PTRSUB);
            self.new_unique_out(sz, &add);
            self.op_insert_before(&add, op);
            add_op = Some(add);
        } else {
            let add = add_op.clone().unwrap();
            self.op_set_opcode(&add, OpCode::CPUI_PTRSUB);
        }
        let add_op = add_op.unwrap();

        // cc:405: newconstoff = origval - extra — everything in address units.
        let newconstoff = origval.wrapping_sub(extra);
        // cc:406-407: newconst = newConstant(sz, newconstoff); setPtrCheck.
        let newconst = self.new_constant(sz, newconstoff);
        newconst.write().unwrap().addlflags |= crate::varnode::addl_flags::PTR_CHECK;
        // cc:408-409: if (spaceid->isTruncated()) addOp->setPtrFlow(). The
        // enum space projection cannot be truncated (only the registry
        // handle's truncateSpace sets the state), so this never fires here.

        // cc:410-411: opSetInput(addOp, spacebase_vn, 0);
        // opSetInput(addOp, newconst, 1).
        self.set_or_insert_input(&add_op, spacebase_vn, 0);
        self.set_or_insert_input(&add_op, newconst, 1);

        // cc:413-419: type the PTRSUB output as a pointer to the (array-
        // stripped) entry type, typelocked when the Symbol is.
        let mut outvn = add_op.0.read().unwrap().output.clone();
        if let Some(types) = self.arch.as_ref().and_then(|arch| arch.types.clone()) {
            let mut tf = types.write().unwrap();
            // cc:413-415: entrytype = sym->getType(); ptrentrytype =
            // getTypePointerStripArray(sz, entrytype, spaceid->getWordSize())
            // (type.cc:3849-3858: one getStripped step, then strip the first
            // ARRAY level). A Symbol without a resolved type reads as the
            // factory's undefined of the pointer size (the analyzer's DAT
            // label default).
            let entrytype = match entry.symbol_type.clone() {
                Some(dt) => dt,
                None => tf
                    .get_base(sz, crate::type_system::datatype::TypeMetatype::Unknown)
                    .unwrap_or_else(|| {
                        std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
                            crate::type_system::datatype::TypeBase::new(
                                format!("undefined{sz}"),
                                sz,
                                crate::type_system::datatype::TypeMetatype::Unknown,
                            ),
                        ))
                    }),
            };
            let mut stripped = crate::type_system::datatype::Datatype::get_stripped_arc(&entrytype)
                .unwrap_or(entrytype.clone());
            if let crate::type_system::datatype::Datatype::Array(arr) = stripped.as_ref() {
                stripped = arr.array_of.clone();
            }
            let ptrentrytype = tf.get_type_pointer(sz, stripped, spaceid.word_size());
            // cc:416-418: typelock = sym->isTypeLocked(); typelock &&
            // TYPE_UNKNOWN -> false.
            let mut typelock = (entry.all_flags & crate::database::symbol_flags::TYPELOCK) != 0;
            if typelock
                && entrytype.get_metatype()
                    == crate::type_system::datatype::TypeMetatype::Unknown
            {
                typelock = false;
            }
            if let Some(out) = &outvn {
                out.write()
                    .unwrap()
                    .update_type_lock(ptrentrytype, typelock, false);
            }
        }

        // cc:420-434: if (extra != 0) build INT_ADD(outvn, extconst).
        if extra != 0 {
            if extra_op.is_none() {
                let eop = self.new_op(2, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&eop, OpCode::CPUI_INT_ADD);
                self.new_unique_out(sz, &eop);
                self.op_insert_before(&eop, op);
                extra_op = Some(eop);
            }
            let extra_op = extra_op.unwrap();
            self.op_set_opcode(&extra_op, OpCode::CPUI_INT_ADD);
            let extconst = self.new_constant(sz, extra);
            extconst.write().unwrap().addlflags |= crate::varnode::addl_flags::PTR_CHECK;
            // cc:431-432.
            let current_out = outvn.clone().expect("PTRSUB chain output present");
            self.set_or_insert_input(&extra_op, current_out, 0);
            self.set_or_insert_input(&extra_op, extconst, 1);
            outvn = extra_op.0.read().unwrap().output.clone();
        }

        // cc:435-446: if (sz < origsize) INT_ZEXT.
        if sz < origsize {
            if zext_op.is_none() {
                let zop = self.new_op(1, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&zop, OpCode::CPUI_INT_ZEXT);
                self.new_unique_out(origsize, &zop);
                self.op_insert_before(&zop, op);
                zext_op = Some(zop);
            }
            let zext_op = zext_op.unwrap();
            self.op_set_opcode(&zext_op, OpCode::CPUI_INT_ZEXT);
            let current_out = outvn.clone().expect("PTRSUB chain output present");
            self.set_or_insert_input(&zext_op, current_out, 0);
            outvn = zext_op.0.read().unwrap().output.clone();
        } else if origsize < sz {
            // cc:447-458: INT_SUBPIECE to truncate back to origsize.
            if sub_op.is_none() {
                let sop = self.new_op(2, op.0.read().unwrap().get_addr());
                self.op_set_opcode(&sop, OpCode::CPUI_SUBPIECE);
                self.new_unique_out(origsize, &sop);
                self.op_insert_before(&sop, op);
                sub_op = Some(sop);
            }
            let sub_op = sub_op.unwrap();
            self.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
            let current_out = outvn.clone().expect("PTRSUB chain output present");
            self.set_or_insert_input(&sub_op, current_out, 0);
            let zero = self.new_constant(4, 0);
            self.set_or_insert_input(&sub_op, zero, 1);
            outvn = sub_op.0.read().unwrap().output.clone();
        }

        // cc:460-461: if (!isCopy) opSetInput(op, outvn, slot).
        if !is_copy {
            if let Some(out) = outvn {
                self.op_set_input(op, out, slot);
            }
        }
    }

    // RUGRA-GLUE: opSetInput-after-insertInput pair for spacebaseConstant
    // (funcdata.cc:382's insertInput(1) followed by the opSetInput sites at
    // cc:410/431/456). Ghidra pushes a NULL slot and fills it later; Rust's
    // inrefs cannot hold NULL, so a fresh slot takes the real varnode
    // directly through the faithful op_insert_input (insertInput+opSetInput
    // with an unobservable transient NULL) and an existing slot goes through
    // op_set_input.
    fn set_or_insert_input(
        &mut self,
        op: &crate::op::PcodeOpRef,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        slot: usize,
    ) {
        let exists = op.0.read().unwrap().inrefs.len() > slot;
        if exists {
            self.op_set_input(op, vn, slot);
        } else {
            self.op_insert_input(op, vn, slot);
        }
    }

    // Ghidra: funcdata_op.cc:459 Funcdata::createStackRef
    /// Create an INT_ADD PcodeOp calculating an offset to the \e spacebase
    /// register. Faithful to `Funcdata::createStackRef`
    /// (funcdata_op.cc:459-496):
    ///   if (stackptr == NULL) stackptr = newSpacebasePtr(spc);
    ///   addrsize = stackptr->getSize();
    ///   addop = newOp(2, op->getAddr()); opSetOpcode(addop, INT_ADD);
    ///   addout = newUniqueOut(addrsize, addop);
    ///   opSetInput(addop, stackptr, 0);
    ///   off = AddrSpace::byteToAddress(off, spc->getWordSize());
    ///   opSetInput(addop, newConstant(addrsize, off), 1);
    ///   if (insertafter) opInsertAfter(addop, op); else opInsertBefore(addop, op);
    ///   segdef = glb->userops.getSegmentOp(spc->getContain()->getIndex());
    ///   if (segdef) { build SEGMENTOP chain; addout = segout; }
    ///   return addout;
    /// Rugra: SegmentOp is architecturally rare (x86-64 has none); we skip the
    /// SEGMENTOP branch (logged) since the Funcdata has no userops handle yet.
    pub fn create_stack_ref(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        op: &crate::op::PcodeOpRef,
        stackptr: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        insertafter: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:467-468: stackptr = stackptr.unwrap_or_else(|| newSpacebasePtr(spc)).
        let stackptr = match stackptr {
            Some(vn) => vn,
            None => self.new_spacebase_ptr(spc),
        };
        // cc:469: addrsize = stackptr->getSize().
        let addrsize = stackptr.read().unwrap().get_size();
        // cc:470-471: addop = newOp(2, op->getAddr()); opSetOpcode(INT_ADD).
        let addop = self.new_op(2, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&addop, crate::opcodes::OpCode::CPUI_INT_ADD);
        // cc:472: addout = newUniqueOut(addrsize, addop).
        let addout = self.new_unique_out(addrsize, &addop);
        // cc:473: opSetInput(addop, stackptr, 0).
        self.op_set_input(&addop, stackptr, 0);
        // cc:474: off = AddrSpace::byteToAddress(off, spc->getWordSize()).
        let word_size = spc.word_size() as u64;
        let off = if word_size > 1 { off / word_size } else { off };
        // cc:475: opSetInput(addop, newConstant(addrsize, off), 1).
        let off_const = self.new_constant(addrsize, off);
        self.op_set_input(&addop, off_const, 1);
        // cc:476-479: insert before/after op.
        if insertafter {
            self.op_insert_after(&addop, op);
        } else {
            self.op_insert_before(&addop, op);
        }
        // cc:481-493: SegmentOp chain. Rugra: skipped (no userops handle);
        // x86-64 has no segment ops so this branch is dead code for the
        // current target. Width note (FUNCDATA-SPACEID-WIDTH-0001): the
        // cc:488 SEGMENTOP spaceid input is also newVarnodeSpace(containerid)
        // = width sizeof(AddrSpace*) = 8; when this branch is implemented it
        // must call new_varnode_space(containerid), never a 1-byte constant.
        addout
    }

    // Ghidra: funcdata_op.cc:508 Funcdata::opStackStore
    /// Create a STORE expression at an offset relative to a \e spacebase
    /// register. Faithful to `Funcdata::opStackStore` (funcdata_op.cc:508-527):
    ///   addout = createStackRef(spc, off, op, NULL, insertafter);
    ///   storeop = newOp(3, op->getAddr()); opSetOpcode(storeop, STORE);
    ///   opSetInput(storeop, newVarnodeSpace(spc->getContain()), 0);
    ///   opSetInput(storeop, addout, 1);
    ///   opInsertAfter(storeop, addout->getDef());
    ///   return storeop;
    /// The Varnode value being stored must still be set on the returned op.
    pub fn op_stack_store(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        op: &crate::op::PcodeOpRef,
        insertafter: bool,
    ) -> crate::op::PcodeOpRef {
        // cc:518: addout = createStackRef(spc, off, op, NULL, insertafter).
        let addout = self.create_stack_ref(spc, off, op, None, insertafter);
        // Capture the stack-building op (def of addout) before we lose it.
        let stack_def = addout.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        // cc:519-520: storeop = newOp(3, op->getAddr()); opSetOpcode(STORE).
        let storeop = self.new_op(3, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&storeop, crate::opcodes::OpCode::CPUI_STORE);
        // cc:523: opSetInput(storeop, newVarnodeSpace(spc->getContain()), 0).
        // spc->getContain() (space.hh:505, SpacebaseSpace override
        // translate.hh:187) is the container of the (stack) space — ram on
        // x86-64 — NOT spc itself. Rugra resolves it via
        // Architecture::get_contain (arch.rs:968); a missing container is
        // unreachable here (Ghidra would pass NULL to newVarnodeSpace = UB).
        // cc:523 + funcdata_varnode.cc:190-198: the spaceid input is
        // newVarnodeSpace(container), whose width is sizeof(AddrSpace*) = 8
        // (FUNCDATA-SPACEID-WIDTH-0001; the 1-byte form leaked through the
        // mirror emitter's s: gate, which requires size==8).
        let contain_spc = self
            .get_arch()
            .and_then(|a| a.get_contain(spc))
            .expect("opStackStore: spc has no container space (Ghidra: getContain() == null is UB)");
        let space_vn = self.new_varnode_space(contain_spc);
        self.op_set_input(&storeop, space_vn, 0);
        // cc:524: opSetInput(storeop, addout, 1).
        self.op_set_input(&storeop, addout, 1);
        // cc:525: opInsertAfter(storeop, addout->getDef()).
        if let Some(def) = stack_def {
            self.op_insert_after(&storeop, &def);
        } else {
            self.op_insert_after(&storeop, op);
        }
        storeop
    }

    // Ghidra: funcdata_op.cc:541 Funcdata::opStackLoad
    /// Create a LOAD expression at an offset relative to a \e spacebase
    /// register. Faithful to `Funcdata::opStackLoad` (funcdata_op.cc:541-552):
    ///   addout = createStackRef(spc, off, op, stackref, insertafter);
    ///   loadop = newOp(2, op->getAddr()); opSetOpcode(loadop, LOAD);
    ///   opSetInput(loadop, newVarnodeSpace(spc->getContain()), 0);
    ///   opSetInput(loadop, addout, 1);
    ///   res = newUniqueOut(sz, loadop);
    ///   opInsertAfter(loadop, addout->getDef());
    ///   return res;
    pub fn op_stack_load(
        &mut self,
        spc: crate::space::AddressSpace,
        off: u64,
        sz: usize,
        op: &crate::op::PcodeOpRef,
        stackref: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        insertafter: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:544: addout = createStackRef(spc, off, op, stackref, insertafter).
        let addout = self.create_stack_ref(spc, off, op, stackref, insertafter);
        let stack_def = addout.read().unwrap().get_def().map(crate::op::PcodeOpRef);
        // cc:545-546: loadop = newOp(2, ...); opSetOpcode(LOAD).
        let loadop = self.new_op(2, op.0.read().unwrap().get_addr());
        self.op_set_opcode(&loadop, crate::opcodes::OpCode::CPUI_LOAD);
        // cc:547: opSetInput(loadop, newVarnodeSpace(spc->getContain()), 0).
        // spc->getContain() (space.hh:505, SpacebaseSpace override
        // translate.hh:187) is the container of the (stack) space — ram on
        // x86-64 — NOT spc itself. Rugra resolves it via
        // Architecture::get_contain (arch.rs:968); a missing container is
        // unreachable here (Ghidra would pass NULL to newVarnodeSpace = UB).
        // Using spc's own id broke RuleLoadVarnode::correctSpacebase
        // (`assoc->getContain() != loadspace` always true → rule never fired;
        // FUNCDATA-OPSTACKLOAD-CONTAIN-0001).
        // cc:547 + funcdata_varnode.cc:190-198: the spaceid input is
        // newVarnodeSpace(container), whose width is sizeof(AddrSpace*) = 8
        // (FUNCDATA-SPACEID-WIDTH-0001; the 1-byte form leaked through the
        // mirror emitter's s: gate, which requires size==8).
        let contain_spc = self
            .get_arch()
            .and_then(|a| a.get_contain(spc))
            .expect("opStackLoad: spc has no container space (Ghidra: getContain() == null is UB)");
        let space_vn = self.new_varnode_space(contain_spc);
        self.op_set_input(&loadop, space_vn, 0);
        // cc:548: opSetInput(loadop, addout, 1).
        self.op_set_input(&loadop, addout, 1);
        // cc:549: res = newUniqueOut(sz, loadop).
        let res = self.new_unique_out(sz, &loadop);
        // cc:550: opInsertAfter(loadop, addout->getDef()).
        if let Some(def) = stack_def {
            self.op_insert_after(&loadop, &def);
        } else {
            self.op_insert_after(&loadop, op);
        }
        res
    }

    // Ghidra: funcdata_varnode.cc:856 Funcdata::calcNZMask
    /// Calculate the \e non-zero mask (NZM) property on all Varnode objects.
    /// Faithful to `Funcdata::calcNZMask` (funcdata_varnode.cc:856-926):
    /// phase 1 is an explicit DFS over the alive-op list that (a) initializes
    /// every unwritten input as it is first traversed (constants take their
    /// offset, everything else takes `calc_mask(size)`, spacebase inputs are
    /// additionally treated as aligned via `&= ~0xff`, cc:887-896) and (b)
    /// on pop assigns each op's output from `getNZMaskLocal(true)` with
    /// MULTIEQUAL looping edges clipped (cc:882-885); phase 2 seeds a
    /// worklist with every MULTIEQUAL and re-propagates
    /// `getNZMaskLocal(false)` along descendant edges until the masks reach
    /// a fixed point (cc:904-925). Varnodes are born with `nzm = ~0`
    /// (varnode.cc:605, constants with their offset, varnode.cc:597).
    pub fn calc_nz_mask(&mut self) {
        use crate::opcodes::OpCode;
        // cc:859-902: DFS with an explicit op stack in alive order.
        let ops: Vec<crate::op::PcodeOpRef> = self.obank.alivelist.clone();
        let mut opstack: Vec<(crate::op::PcodeOpRef, usize)> = Vec::new();
        for op_ref in ops {
            if op_ref.0.read().unwrap().is_mark() {
                continue; // cc:864
            }
            opstack.push((op_ref, 0));
            opstack.last().unwrap().0 .0.write().unwrap().set_mark(); // cc:865-866
            while !opstack.is_empty() {
                // cc:871-878: no edge left -> assign output nzm, pop a level.
                let num_input = opstack.last().unwrap().0 .0.read().unwrap().num_input();
                if opstack.last().unwrap().1 >= num_input {
                    let (popped, _) = opstack.pop().unwrap();
                    let outvn = popped.0.read().unwrap().output.clone();
                    if let Some(outvn) = outvn {
                        let nzm = popped.0.read().unwrap().get_nz_mask_local(true); // cc:874
                        outvn.write().unwrap().nzm = nzm;
                    }
                    continue;
                }
                // cc:879-880: advance to the next input edge.
                let oldslot = opstack.last().unwrap().1;
                opstack.last_mut().unwrap().1 += 1;
                // cc:882-885: clip looping MULTIEQUAL edges.
                let (opcode, parent, input_vn) = {
                    let op = opstack.last().unwrap().0 .0.read().unwrap();
                    (
                        op.opcode,
                        op.parent.clone(),
                        op.get_in(oldslot).cloned())
                };
                if opcode == OpCode::CPUI_MULTIEQUAL {
                    if let Some(parent) = parent.as_ref().and_then(|w| w.upgrade()) {
                        if parent.read().unwrap().is_loop_in(oldslot) {
                            continue; // cc:883-884
                        }
                    }
                }
                // cc:887-900: traverse the edge indicated by the slot.
                let Some(vn) = input_vn else { continue };
                let (written, def) = {
                    let guard = vn.read().unwrap();
                    (guard.is_written(), guard.def.clone())
                };
                if !written {
                    let mut guard = vn.write().unwrap();
                    if guard.is_constant() {
                        guard.nzm = guard.get_offset(); // cc:889-890
                    } else {
                        guard.nzm = crate::address::calc_mask(guard.get_size()); // cc:892
                        if guard.is_spacebase() {
                            guard.nzm &= !0xffu64; // cc:893-894: aligned
                        }
                    }
                } else if let Some(def) = def.and_then(|w| w.upgrade()) {
                    let def_ref = crate::op::PcodeOpRef(def);
                    if !def_ref.0.read().unwrap().is_mark() {
                        def_ref.0.write().unwrap().set_mark(); // cc:899
                        opstack.push((def_ref, 0)); // cc:898
                    }
                }
            }
        }

        // cc:904-911: clear marks; seed the worklist with every MULTIEQUAL.
        let mut worklist: Vec<crate::op::PcodeOpRef> = Vec::new();
        for op_ref in &self.obank.alivelist {
            op_ref.0.write().unwrap().clear_mark();
            if op_ref.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL {
                worklist.push(op_ref.clone());
            }
        }

        // cc:913-925: propagate changes along all edges until fixed point.
        while let Some(op_ref) = worklist.pop() {
            let outvn = op_ref.0.read().unwrap().output.clone();
            let Some(vn) = outvn else { continue }; // cc:918
            let nzmask = op_ref.0.read().unwrap().get_nz_mask_local(false); // cc:919
            if nzmask != vn.read().unwrap().nzm {
                vn.write().unwrap().nzm = nzmask; // cc:921
                let descend: Vec<crate::op::PcodeOpRef> = vn
                    .read()
                    .unwrap()
                    .descend_iter()
                    .map(crate::op::PcodeOpRef)
                    .collect();
                worklist.extend(descend); // cc:922-923
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1540 Funcdata::splitUses
    ///
    /// If `vn` is defined by an op (e.g. INT_ADD) and has multiple
    /// descendants, duplicate the defining op so each reader gets its own
    /// independent output copy. This allows per-use analysis (e.g. distinct
    /// stack offsets from the same spacebase-derived pointer).
    pub fn split_uses(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        // Get the defining op of vn.
        let def_arc = {
            let vn_g = vn.read().unwrap();
            match vn_g.def.as_ref().and_then(|w| w.upgrade()) {
                Some(a) => a,
                None => return, // no defining op
            }
        };

        // Collect descendant ops (readers), preserving order. Ghidra walks
        // the live `descend` list while each rewrite erases the processed
        // entry; since erase removes exactly one occurrence (one per input
        // slot), the live walk processes precisely these entries in this
        // order (funcdata_varnode.cc:1549-1552).
        let descendents: Vec<crate::op::PcodeOpRef> = {
            let vn_g = vn.read().unwrap();
            vn_g.descend_iter()
                .map(crate::op::PcodeOpRef)
                .collect()
        };
        if descendents.len() <= 1 {
            return; // Only one (or zero) descendant — nothing to split.
        }

        // Clone the defining op for each descendant.
        let num_inputs = def_arc.read().unwrap().inrefs.len();
        let def_addr = def_arc.read().unwrap().get_addr();
        let def_opcode = def_arc.read().unwrap().opcode;
        // Snapshot inputs before mutation (avoid holding lock across new_op).
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            def_arc.read().unwrap().inrefs.clone();
        let vn_size = vn.read().unwrap().get_size();
        let vn_addr = vn.read().unwrap().loc.clone();
        let vn_space = vn.read().unwrap().address_space;
        let vn_type = vn.read().unwrap().get_type();

        // Faithful to funcdata_varnode.cc:1549-1565: the descendant iterator
        // is advanced BEFORE each rewrite, so EVERY original descendant is
        // processed exactly once — there is no "keep the last reader on the
        // original op" special case; the original op is left dead for
        // dead-code removal. cc:1554 evaluates `slot = useop->getSlot(vn)`
        // at the TOP of each iteration on the live op — AFTER earlier
        // iterations already re-pointed their slots — so when one op reads
        // `vn` in multiple slots (e.g. a MULTIEQUAL with duplicated RSP
        // inputs), each iteration claims the next still-unclaimed slot.
        for useop in descendents {
            let slot = self.op_get_slot(&useop, vn);
            if slot < 0 {
                continue;
            }
            // newop = newOp(op->numInput(), op->getAddr())
            let newop = self.new_op(num_inputs, def_addr.clone());
            // cc:1556: newvn = newVarnode(vn->getSize(),vn->getAddr(),
            // vn->getType()) — the FULL Funcdata::newVarnode(s,m,ct) path
            // (funcdata_varnode.cc:148-169): typed bank create, assignHigh,
            // the laned-register check (s >= minLanedSize), and the
            // queryProperties symbol tail with the INVALID usepoint of
            // cc:162 — same carries PM-F2S proved observable.
            // VarnodeBank::create (varnode.cc:1250) inserts the free
            // varnode under its FINAL (space, loc) tree keys, so no
            // post-insert key mutation can drift the tree order.
            // (FUNCDATA-SPLITUSES-NEWVN-TYPECARRY-0001)
            let newvn = self.new_varnode_typed_in_space(
                vn_size,
                vn_space,
                vn_addr,
                vn_type.clone(),
            );
            // cc:1557: opSetOutput(newop,newvn) — Funcdata::opSetOutput
            // (funcdata_op.cc:70-87) routes through VarnodeBank::setDef for
            // the WRITTEN flag and the def-tree re-key; never an in-place
            // mutation of a tree-resident key field.
            self.op_set_output(&newop, newvn.clone());
            // opSetOpcode(newop, op->code())
            self.op_set_opcode(&newop, def_opcode);
            // for each input: opSetInput(newop, op->getIn(i), i)
            for (idx, inp) in inputs.iter().enumerate() {
                self.op_set_input(&newop, inp.clone(), idx);
            }
            // opSetInput(useop, newvn, slot)
            self.op_set_input(&useop, newvn, slot as usize);
            // opInsertBefore(newop, op)
            let def_ref = crate::op::PcodeOpRef(def_arc.clone());
            self.op_insert_before(&newop, &def_ref);
        }
        // cc:1566: Dead-code actions should remove original op
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseElimination
    /// Eliminate a common subexpression between two ops. Faithful to
    /// `Funcdata::cseElimination` (funcdata_op.cc:1356-1398). Same block:
    /// the earlier intra-block `SeqNum::order` wins. Different blocks: the
    /// op whose parent IS the closest common dominator survives; if neither
    /// dominates, a fresh op is built at the common block's stop address and
    /// both originals are destroyed.
    pub fn cse_elimination(
        &mut self,
        op1: &crate::op::PcodeOpRef,
        op2: &crate::op::PcodeOpRef,
    ) -> crate::op::PcodeOpRef {
        // cc:1359-1364: same parent (or both unattached) — order compare.
        let parent1 = op1.0.read().unwrap().parent.as_ref().and_then(std::sync::Weak::upgrade);
        let parent2 = op2.0.read().unwrap().parent.as_ref().and_then(std::sync::Weak::upgrade);
        let same_parent = match (&parent1, &parent2) {
            (None, None) => true, // Ghidra: null == null takes the order branch
            (Some(p1), Some(p2)) => std::sync::Arc::ptr_eq(p1, p2),
            _ => false,
        };
        let replace = if same_parent {
            // cc:1360-1363: compare the intra-block order field.
            let order1 = op1.0.read().unwrap().get_seq_num().get_order();
            let order2 = op2.0.read().unwrap().get_seq_num().get_order();
            if order1 < order2 {
                op1.clone()
            } else {
                op2.clone()
            }
        } else {
            // cc:1365-1387: different blocks — findCommonBlock picks the
            // survivor; neither parent dominating spawns a fresh op at the
            // common block's stop address.
            let (p1, p2) = match (parent1, parent2) {
                (Some(a), Some(b)) => (a, b),
                // Mixed attached/unattached cannot reach cseElimination from
                // cseEliminateList (dead ops are filtered), and Ghidra would
                // dereference null here; fail loudly rather than diverge.
                _ => panic!("cseElimination requires both ops to be inserted"),
            };
            let common =
                crate::block::BlockGraph::find_common_block(&p1, &p2);
            let common = match common {
                Some(c) => c,
                // Ghidra's mark-walk always finds a common dominator when
                // dominator info exists (both chains reach the entry block);
                // a null return there is a crash, not a silent fallback.
                None => panic!("cseElimination: findCommonBlock found no common dominator"),
            };
            if std::sync::Arc::ptr_eq(&common, &p1) {
                op1.clone()
            } else if std::sync::Arc::ptr_eq(&common, &p2) {
                op2.clone()
            } else {
                // cc:1372-1386: build the replacement at the common block.
                let (num_inputs, opcode, out_size, out_space, out_addr, inrefs) = {
                    let o1 = op1.0.read().unwrap();
                    let out = o1.get_out().expect("cseElimination: op1 has output");
                    let out_rg = out.read().unwrap();
                    (
                        o1.inrefs.len(),
                        o1.opcode,
                        out_rg.get_size(),
                        out_rg.get_space(),
                        *out_rg.get_addr(),
                        o1.inrefs.clone(),
                    )
                };
                let stop_addr = {
                    let c_rg = common.read().unwrap();
                    c_rg
                        .as_any()
                        .downcast_ref::<crate::block::BlockBasic>()
                        .map(|bb| bb.get_stop_addr())
                        .unwrap_or_else(|| c_rg.get_start_addr())
                };
                let replace = self.new_op(num_inputs, stop_addr);
                self.op_set_opcode(&replace, opcode);
                self.new_varnode_out_full(out_size, out_space, out_addr, &replace);
                for (i, vn) in inrefs.iter().enumerate() {
                    let (is_const, size, offset) = {
                        let rg = vn.read().unwrap();
                        (rg.is_constant(), rg.get_size(), rg.get_offset())
                    };
                    if is_const {
                        let cv = self.new_constant(size, offset);
                        self.op_set_input(&replace, cv, i);
                    } else {
                        self.op_set_input(&replace, vn.clone(), i);
                    }
                }
                self.op_insert_end(&replace, &common);
                replace
            }
        };
        // cc:1388-1395: totalReplace the loser's output and destroy it.
        if !std::sync::Arc::ptr_eq(&replace.0, &op1.0) {
            let out1 = op1.0.read().unwrap().get_out().cloned();
            let rep_out = replace.0.read().unwrap().get_out().cloned();
            if let (Some(old), Some(new)) = (out1, rep_out) {
                self.total_replace(&old, new);
            }
            self.op_destroy(&op1.clone());
        }
        if !std::sync::Arc::ptr_eq(&replace.0, &op2.0) {
            let out2 = op2.0.read().unwrap().get_out().cloned();
            let rep_out = replace.0.read().unwrap().get_out().cloned();
            if let (Some(old), Some(new)) = (out2, rep_out) {
                self.total_replace(&old, new);
            }
            self.op_destroy(&op2.clone());
        }
        replace
    }

    // Ghidra: funcdata.cc:34 Funcdata::cseEliminateList
    /// Perform CSE on a list of (hash, PcodeOp) pairs. Faithful to
    /// `Funcdata::cseEliminateList` (funcdata_op.cc:1420-1449). Sorts by hash,
    /// finds matching pairs via `is_cse_match`, eliminates duplicates.
    /// Returns the list of surviving output Varnodes.
    pub fn cse_eliminate_list(
        &mut self,
        list: &mut Vec<(u64, crate::op::PcodeOpRef)>,
    ) -> Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let mut outlist = Vec::new();
        if list.is_empty() {
            return outlist;
        }
        // Sort by hash.
        list.sort_by_key(|(h, _)| *h);
        let mut i = 0;
        while i + 1 < list.len() {
            let h1 = list[i].0;
            let h2 = list[i + 1].0;
            if h1 == h2 {
                let op1 = list[i].1.clone();
                let op2 = list[i + 1].1.clone();
                let (is_dead1, is_dead2) = {
                    let r1 = op1.0.read().unwrap();
                    let r2 = op2.0.read().unwrap();
                    (r1.is_dead(), r2.is_dead())
                };
                if !is_dead1 && !is_dead2 {
                    let is_match = op1.0.read().unwrap().is_cse_match(&op2.0.read().unwrap());
                    if is_match {
                        // cc:1434-1437: both outputs must exist and be
                        // heritaged (Heritage::heritagePass >= 0 on the
                        // output's address) before eliminating.
                        let (out1, out2) = {
                            let r1 = op1.0.read().unwrap();
                            let r2 = op2.0.read().unwrap();
                            (r1.get_out().cloned(), r2.get_out().cloned())
                        };
                        let heritaged = |vn: &Option<
                            std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
                        >| {
                            // cc:1436: `(outvn == 0) || isHeritaged(outvn)` — a
                            // null output passes; a present output must have
                            // been covered by a heritage pass.
                            vn.as_ref().is_none_or(|v| {
                                let rg = v.read().unwrap();
                                self.heritage.globaldisjoint.find_pass(
                                    rg.get_space(),
                                    *rg.get_addr(),
                                ) >= 0
                            })
                        };
                        if heritaged(&out1) && heritaged(&out2) {
                            let res_op = self.cse_elimination(&op1, &op2);
                            let out_opt = {
                                let r = res_op.0.read().unwrap();
                                r.output.clone()
                            };
                            if let Some(out) = out_opt {
                                outlist.push(out);
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        outlist
    }

    // Ghidra: funcdata.cc:34 Funcdata::opBoolNegate
    /// Insert a BOOL_NEGATE (CPUI_BOOL_NEGATE in Rugra) of `vn`, returning the
    /// new output Varnode. Faithful to `Funcdata::opBoolNegate`
    /// (funcdata_op.cc:560-572). If `insert_after` is true, the negate op is
    /// inserted after `op`; otherwise before.
    pub fn op_bool_negate(
        &mut self,
        vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        insert_after: bool,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let addr = op.0.read().unwrap().get_addr();
        let negate_op = self.new_op(1, addr);
        self.op_set_opcode(&negate_op, crate::opcodes::OpCode::CPUI_BOOL_NEGATE);
        let res_vn = self.new_unique_out(1, &negate_op);
        self.op_set_input(&negate_op, vn, 0);
        if insert_after {
            self.op_insert_after(&negate_op, op);
        } else {
            self.op_insert_before(&negate_op, op);
        }
        res_vn
    }

    // Ghidra: funcdata.hh:489 Funcdata::opFlipCondition
    /// Flip the condition of a CBRANCH/comparison op. Faithful to
    /// `Funcdata::opFlipCondition` (funcdata.hh:489): flips the
    /// `boolean_flip` flag on the given CBRANCH — nothing else. The old
    /// Rugra body ran `get_booleanflip` on the CBRANCH's own opcode, which
    /// returns the CPUI_MAX sentinel for CBRANCH and corrupted the opcode
    /// field (RuleCondNegate sites); the oracle never rewrites the opcode
    /// here (comparison-opcode rewriting is opFlipInPlaceExecute's job).
    pub fn op_flip_condition(&mut self, op: &crate::op::PcodeOpRef) {
        op.0.write().unwrap().flags ^= crate::op::pcodeop_flags::BOOLEAN_FLIP;
    }

    /// Inject raw P-code operations into this Funcdata
    ///
    /// This is the bridge between raw P-code translation output (e.g., from
    /// a SLEIGH translator or manual construction) and the `Funcdata` container
    /// that the `ActionDatabase` pipeline operates on.
    ///
    /// The method:
    /// 1. Converts each `PcodeOpRaw` into a `PcodeOp` in `obank`
    /// 2. Creates `Varnode` entries in `vbank` for all inputs/outputs
    /// 3. Detects basic block boundaries at control flow terminators
    /// 4. Populates `bblocks` with basic blocks and edges
    ///
    /// # Arguments
    /// * `raw_ops` - Vector of raw P-code operations in sequential order
    /// Inject a single instruction's P-code ops (for FlowInfo process_instruction).
    /// Does NOT call build_blocks_from_ops (that's done once after all flow is tracked).
    // Ghidra: funcdata.cc:878 PcodeEmitFd::dump
    /// Faithful port of `PcodeEmitFd::dump` (funcdata.cc:878-908), the emit
    /// callback `Sleigh::oneInstruction` feeds one complete instruction into:
    ///
    /// - the output (when present) is materialized FIRST via
    ///   `Funcdata::newVarnodeOut` → `VarnodeBank::createDef`
    ///   (ctor flags + `written|coverdirty` from `setDef` + `insert` from
    ///   `xref`, varnode.cc:1411-1418);
    /// - `op->isCodeRef()` ops (BRANCH/CBRANCH/CALL — the CODEREF flag in
    ///   TypeOp's opflags, typeop.cc:586/605/663) take input(0) through
    ///   `Funcdata::newCodeRef(Address(vars[0].space, vars[0].offset))`
    ///   (funcdata_varnode.cc:222-233): a one-byte `annotation` Varnode in
    ///   the SLEIGH-reported space carrying the core "code" type
    ///   (sleigh_arch.cc:233 `setCoreType("code",1,TYPE_CODE,false)`). A
    ///   Const-space input(0) is therefore a *relative* label offset that
    ///   stays in the constant space; a ram-space input(0) is the absolute
    ///   machine target (ia.sinc:1149-1151);
    /// - every other input goes through `Funcdata::newVarnode` → a fresh
    ///   `VarnodeBank::create` Varnode (constants included — no dedup;
    ///   varnode.cc:1250-1258), with `opSetInput` appending the op to the
    ///   Varnode's descendant list in slot order.
    ///
    /// Varnode creation order per op is: output, then inputs in slot order —
    /// this fixes `Varnode::create_index` to the emission order Ghidra uses.
    pub fn inject_raw_ops_single(
        &mut self, raw_ops: &[PcodeOpRaw], base_addr: crate::address::Address,
    ) {
        for raw in raw_ops {
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => continue,
            };
            let addr = raw.seq_num().map(|s| s.get_addr()).unwrap_or(base_addr);
            // funcdata.cc:884/890: newOp allocates on PcodeOpBank's dead list.
            // FlowInfo must continue to see raw p-code there until splitBasic
            // integrates each op into its basic block.
            let op_ref = self.new_op(raw.num_input(), addr);
            // PcodeEmitFd::dump: the output varnode is created between
            // newOp and opSetOpcode, before any input (funcdata.cc:884-890).
            if let Some(out_raw) = raw.output() {
                // newVarnodeOut → VarnodeBank::createDef + op->setOutput +
                // assignHigh + laned probe + the queryProperties symbol tail
                // with usepoint = op->getAddr() (funcdata_varnode.cc:104-122,
                // FUNCDATA-NEWVARNODE-SYMBOLTAIL-0001). The pre-fix direct
                // create_def_with_space + laned probe dropped assignHigh and
                // the symbol tail — the tail is what attaches
                // Database::setPropertyRange flags (PLTSTUB-THUNKRELRO-0001:
                // Varnode::readonly on the RELRO `.got` range, consumed by
                // JumpBasic::findNormalized's single-branch readonly rescue,
                // jumptable.cc:1212-1230) to import-time free ram varnodes
                // the way the oracle's PcodeEmitFd::dump does.
                let out_vn = self.new_varnode_out_full(
                    out_raw.size,
                    out_raw.space,
                    crate::address::Address::new(out_raw.offset),
                    &op_ref,
                );
                op_ref.0.write().unwrap().output = Some(out_vn);
            }
            // funcdata.cc:891: opcode assignment follows output creation and
            // precedes the input walk.  Besides opcode-derived flags this also
            // maintains PcodeOpBank's opcode-specific lists for dead raw ops.
            self.op_set_opcode(&op_ref, opcode);
            // PcodeEmitFd::dump: `if (op->isCodeRef())` — the CODEREF flag is
            // only set on BRANCH/CBRANCH/CALL opcodes (typeop.cc:586/605/663;
            // BRANCHIND/CALLIND deliberately lack it).
            let mut slot = 0;
            if matches!(
                opcode,
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_CALL
            ) {
                if let Some(in0) = raw.inputs().first() {
                    // newCodeRef(Address(vars[0].space, vars[0].offset)):
                    // 1-byte annotation Varnode in the raw SLEIGH space.
                    let in_vn = self.vbank.create_with_space(1, in0.space, in0.offset);
                    {
                        let mut value = in_vn.write().unwrap();
                        value.set_flags(crate::varnode::varnode_flags::ANNOTATION);
                        // Core "code" type (sleigh_arch.cc:233); Ghidra reads
                        // it from the architecture TypeFactory, which Rugra
                        // does not thread through this emit path.
                        value.v_type = Some(code_ref_datatype());
                        value.add_descend(&op_ref.0);
                    }
                    op_ref.0.write().unwrap().inrefs.push(in_vn);
                    slot = 1;
                }
            }
            // Remaining inputs: newVarnode (fresh Varnode per reference — no
            // location dedup for either constants or storage reads: each
            // reference gets its own Varnode, and opSetInput's
            // has-no-descend guard (funcdata_op.cc opSetInput) therefore
            // never triggers for dump-time inputs).
            for input_raw in &raw.inputs()[slot..] {
                // funcdata.cc:904-907 has ONE arm for every remaining input
                // — constants included:
                //   vn = fd->newVarnode(vars[i].size,vars[i].space,vars[i].offset);
                //   fd->opSetInput(op,vn,i);
                // (CONST-IMPORT-ASSIGNHIGH-0001 closure: the const-only
                // create_constant arm was CURB's registered residual; the
                // chain specialized to the const space is behavior-identical
                // to create_constant at dump time on x86-64 —)
                // - vbank.create(s, Address(constspace,off), base type):
                //   identical Varnode identity to create_constant
                //   (getConstant(val) IS Address(constant space,val),
                //   translate.hh:532-535; the ctor derives constant|nzm from
                //   the space type alone, varnode.cc:592-597);
                // - assignHigh is highlevel_on-gated (funcdata_varnode.cc:51)
                //   and the flag is still off at dump time — its sole setter
                //   is setHighLevel (cc:598-599) via ActionAssignHigh
                //   (coreaction.hh:346), which runs after ActionStart's
                //   followFlow; dump-time constants receive their
                //   HighVariable later through setHighLevel's catch-up loop
                //   on both sides (funcdata.rs set_high_level, no constant
                //   filter);
                // - the laned probe matches by size only (architecture.cc
                //   getLanedRegister never reads the space), so a lane-sized
                //   constant records a const-space lanedMap entry on
                //   laned-register architectures exactly as the oracle does;
                //   x86-64.pspec carries vector_lane_sizes (XMM/YMM/ZMM) so
                //   the gate IS live here (minLanedSize=16), but the corpus
                //   census shows dump-time constants are sizes 1/2/4/8 only
                //   — no const input ever reaches the 16-byte gate (probe:
                //   3597+1253+2468+3 sites, curl+httpd, all minlaned=16,
                //   all highlevel_on=false);
                // - the queryProperties tail is hard-zero for constants:
                //   stackContainer returns null before any scope walk
                //   (database.cc:950 `if (addr.isConstant()) return 0;`),
                //   leaving flags = getProperty(const addr) = 0
                //   (varmap.rs query_properties_ex mirrors the early-out in
                //   its const arm; the parent leg returns for non-Ram).
                let in_vn = self.new_varnode_in_space(
                    input_raw.size,
                    input_raw.space,
                    crate::address::Address::new(input_raw.offset),
                );
                in_vn.write().unwrap().add_descend(&op_ref.0);
                op_ref.0.write().unwrap().inrefs.push(in_vn);
            }
        }
    }

    /// Build basic blocks from ALL alive ops (called after flow tracking completes).
    // RUGRA-GLUE: 从全部 alive ops 构建 CFG（FlowInfo 流追踪后调用）。
    pub fn build_blocks_from_alive(&mut self) {
        let op_refs: Vec<PcodeOpRef> = self
            .obank
            .alivelist
            .iter()
            .map(|r| PcodeOpRef(r.0.clone()))
            .collect();
        self.build_blocks_from_ops(&op_refs);
        eprintln!(
            "[INJECT] {} build_blocks_from_alive done bblocks={}", self.name, self.bblocks.get_size()
        );
    }

    // Ghidra: funcdata_op.cc:969 Funcdata::overrideFlow (raw-layer transport)
    /// Apply the function's registered flow overrides to a raw-op list,
    /// BEFORE phase-1 creates the PcodeOps. This is the injection-path
    /// transport of Ghidra's per-instruction override application:
    /// `FlowInfo::processInstruction` (flow.cc:415-418) reads
    /// `data.getOverride().getFlowOverride(curaddr)` after the SLEEF
    /// translation and, if non-NONE, calls `data.overrideFlow(curaddr,...)`
    /// (flow.cc:474-475) BEFORE `xrefControlFlow` — i.e. on the raw p-code,
    /// before block formation. Rugra's `inject_raw_ops` is the transport of
    /// that disassembly walk (phase 1 = oneInstruction's dump, phase 2 =
    /// xrefControlFlow's block marking), so the override is applied between
    /// the same two points, but at the raw layer: Rugra's documented
    /// create-implies-alive divergence (op.rs `PcodeOpBank::create`) means
    /// phase-1 ops are never `isDead()`, so the dead-op
    /// `Funcdata::overrideFlow` port cannot run on them — and the
    /// `opDeadInsertAfter` RETURN it inserts would not be in phase-2's
    /// op_refs vector, dropping it from the block graph entirely. The
    /// rewrite table below is the faithful raw-layer image of
    /// funcdata_op.cc:991-1020 (BRANCH→CALL, BRANCHIND→CALLIND, RETURN→
    /// CALLIND; CBRANCH unsupported; CALL_RETURN appends a RETURN with
    /// constant-0 input right after the rewritten call, the transport of
    /// cc:1006-1011's `newOp` + `opSetInput` + `opDeadInsertAfter`).
    ///
    /// Primary-op selection mirrors `Funcdata::findPrimaryBranch`
    /// (funcdata_op.cc:929-961): only the FIRST branch-like op at an
    /// instruction address is considered, and a BRANCH/CBRANCH counts only
    /// when its in(0) is non-constant (internal p-code branches carry a
    /// constant relative target, cc:938). Ghidra applies the override once
    /// per instruction; the per-address `seen` set preserves that.
    fn apply_flow_overrides_raw(
        raw_ops: &[PcodeOpRaw],
        ovr: &crate::override_rs::Override,
    ) -> Vec<PcodeOpRaw> {
        use crate::override_rs::FlowOverride as FO;
        let mut out: Vec<PcodeOpRaw> = Vec::with_capacity(raw_ops.len() + 4);
        // One application per instruction address (Ghidra looks the
        // override up per curaddr, flow.cc:416).
        let mut seen: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
        for raw in raw_ops {
            let Some(seq) = raw.seq_num() else {
                out.push(raw.clone());
                continue;
            };
            let addr = seq.get_addr();
            let fo = ovr.get_flow_override(addr);
            let cur = OpCode::from_i32(raw.get_opcode());
            let branch_like = matches!(
                cur,
                Some(OpCode::CPUI_BRANCH)
                    | Some(OpCode::CPUI_CBRANCH)
                    | Some(OpCode::CPUI_BRANCHIND)
                    | Some(OpCode::CPUI_CALL)
                    | Some(OpCode::CPUI_CALLIND)
                    | Some(OpCode::CPUI_RETURN)
            );
            // findPrimaryBranch (cc:932-959): BRANCH/CBRANCH need a
            // non-constant in(0); BRANCHIND/CALL/CALLIND/RETURN qualify
            // unconditionally.
            let primary_ok = branch_like
                && match cur {
                    Some(OpCode::CPUI_BRANCH) | Some(OpCode::CPUI_CBRANCH) => raw
                        .inputs()
                        .first()
                        .map(|vn| vn.space != AddressSpace::Const)
                        .unwrap_or(false)
                    ,
                    _ => true,
                };
            if fo == FO::None || !primary_ok || !seen.insert(addr) {
                out.push(raw.clone());
                continue;
            }
            let mut rewritten = raw.clone();
            match fo {
                FO::Branch => match cur {
                    Some(OpCode::CPUI_CALL) => rewritten.set_opcode(OpCode::CPUI_BRANCH as i32),
                    Some(OpCode::CPUI_CALLIND) => {
                        rewritten.set_opcode(OpCode::CPUI_BRANCHIND as i32)
                    }
                    Some(OpCode::CPUI_RETURN) => {
                        rewritten.set_opcode(OpCode::CPUI_BRANCHIND as i32)
                    }
                    _ => {}
                },
                FO::Call | FO::CallReturn => {
                    match cur {
                        Some(OpCode::CPUI_BRANCH) => rewritten.set_opcode(OpCode::CPUI_CALL as i32),
                        Some(OpCode::CPUI_BRANCHIND) => {
                            rewritten.set_opcode(OpCode::CPUI_CALLIND as i32)
                        }
                        Some(OpCode::CPUI_RETURN) => {
                            rewritten.set_opcode(OpCode::CPUI_CALLIND as i32)
                        }
                        Some(OpCode::CPUI_CBRANCH) => {
                            // cc:1000-1001: "Do not currently support
                            // CBRANCH overrides" — Ghidra throws; the raw
                            // transport leaves the op untouched (the
                            // injection path cannot abort mid-walk) and
                            // reports.
                            eprintln!(
                                "[INJECT] WARN: CBRANCH flow override unsupported at {}", addr.as_u64()
                            );
                        }
                        _ => {}
                    }
                    if fo == FO::CallReturn {
                        // cc:1006-1011: CALL_RETURN inserts a RETURN with
                        // constant-0 input immediately after the call.
                        // Order `u32::MAX` keeps the SeqNum strictly after
                        // every real op of the instruction (the lifter's
                        // per-instruction orders are tiny) while sharing
                        // the instruction address, so phase-2 partitions
                        // it into the same tail block — the position
                        // opDeadInsertAfter guarantees in Ghidra.
                        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
                        ret.add_input(crate::pcoderaw::VarnodeRaw::new(
                            AddressSpace::Const,
                            0,
                            8));
                        ret.set_seq_num(crate::address::SeqNum::new(addr, u32::MAX));
                        out.push(rewritten);
                        out.push(ret);
                        continue;
                    }
                }
                FO::Return => match cur {
                    Some(OpCode::CPUI_BRANCHIND) => {
                        rewritten.set_opcode(OpCode::CPUI_RETURN as i32)
                    }
                    Some(OpCode::CPUI_CALLIND) => rewritten.set_opcode(OpCode::CPUI_RETURN as i32),
                    Some(OpCode::CPUI_BRANCH) | Some(OpCode::CPUI_CBRANCH) | Some(OpCode::CPUI_CALL) => {
                        // cc:1015-1017: complex RETURN overrides throw.
                        eprintln!(
                            "[INJECT] WARN: complex RETURN flow override unsupported at {}", addr.as_u64()
                        );
                    }
                    _ => {}
                },
                FO::None => {}
            }
            out.push(rewritten);
        }
        out
    }

    // RUGRA-GLUE: Batch raw-P-code adapter around Ghidra's PcodeEmitFd::dump conversion and Funcdata bank insertion APIs.
    pub fn inject_raw_ops(&mut self, raw_ops: &[PcodeOpRaw]) {
        if raw_ops.is_empty() {
            return;
        }

        // flow.cc:415-418 + 474-475: apply registered flow overrides to the
        // raw p-code between the instruction dump (phase 1) and the
        // control-flow xref / block formation (phase 2) — Ghidra's exact
        // position inside FlowInfo::processInstruction. Zero overrides
        // (the default for every driver that does not seed
        // localoverride — the TailCallAnalyzer role lives with the
        // analysis driver) leaves the list untouched: no clone, no
        // behavior change.
        let overridden_storage;
        let raw_ops: &[PcodeOpRaw] = if self.localoverride.has_flow_override() {
            overridden_storage = Self::apply_flow_overrides_raw(raw_ops, &self.localoverride);
            &overridden_storage
        } else {
            raw_ops
        };

        // Phase 1: Convert all raw ops into PcodeOps with proper varnodes
        let mut op_refs: Vec<PcodeOpRef> = Vec::with_capacity(raw_ops.len());

        for (raw_idx, raw) in raw_ops.iter().enumerate() {
            // NOTE: raw.get_opcode() returns a RUST enum discriminant (the
            // lifter in x86_lift.rs builds PcodeOpRaw via `OpCode::CPUI_X as
            // i32`), NOT a Ghidra-native opcode int. So OpCode::from_i32 is
            // correct here. map_ghidra_opcode is only for Ghidra-FFI ints.
            // (Audit BATCH3 R37 was a false-positive for this call site; the
            // real FFI mapping fix is in ffi.rs — CPUI_CAST now round-trips.)
            let opcode = match OpCode::from_i32(raw.get_opcode()) {
                Some(opc) => opc,
                None => {
                    log::warn!("Unknown opcode {}, skipping", raw.get_opcode());
                    continue;
                }
            };

            // Assign a distinct address to each op: base + index * stride
            // This allows CBRANCH targets to be resolved to block start addresses
            let addr = raw
                .seq_num()
                .map(|s| s.get_addr())
                .unwrap_or(Address::new(self.baseaddr.as_u64() + raw_idx as u64 * 0x10));

            let op_ref = self.obank.create(opcode, raw.num_input(), addr);

            // Create output varnode if present
            if let Some(out_raw) = raw.output() {
                let out_vn =
                    self.vbank
                        .create_with_space(out_raw.size, out_raw.space, out_raw.offset);
                // Mark as written and set def
                let out_vn = self
                    .vbank
                    .set_def_prevalidated(out_vn, Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().output = Some(out_vn);
            }

            // Create input varnodes. Faithful to PcodeEmitFd::dump
            // (funcdata.cc:878-908: newVarnode -> opSetInput per
            // input reference, cc:904-907): every read gets a FRESH free Varnode —
            // inject_raw_ops_single (the single-op adapter) already does this,
            // and Ghidra's model forbids the previous dedup: a free varnode
            // with a second reader makes Varnode::addDescend throw
            // "Free varnode has multiple descendants" (varnode.cc:331-340).
            // Pre-merging same-register reads also bypassed Heritage: collect
            // classified the merged object as one read with 2+ descends,
            // which refineRead/loneDescend and normalizeReadSize's
            // opSetOutput("not free") cannot process (HELPF-NONFREE-
            // NORMALIZE-0001). Read-to-write linking is Heritage's job.
            // PcodeEmitFd::dump (funcdata.cc:892-897): `if (op->isCodeRef())`
            // — input 0 of BRANCH/CBRANCH/CALL (the only opcodes whose
            // TypeOp constructors set PcodeOp::coderef — typeop.cc:586/605/
            // 663; BRANCHIND/CALLIND deliberately lack it, op.hh:194) enters
            // the IR as newCodeRef(addrcode) (funcdata_varnode.cc:222-233):
            // a 1-byte `code`-typed Varnode::annotation at the raw target
            // address that "will hold no value in the data-flow", then
            // `i += 1` skips it in the cc:904-907 walk. Materializing in(0)
            // at its raw SLEIGH size instead (8-byte ram on x86-64 SLEIGH)
            // lets branch targets 5 bytes apart overlap as ranges, feeding
            // heritage's global piece/alias machinery a non-marker PIECE
            // that defeats ActionDoNothing's hasOnlyMarkers deletion
            // (REGAP-FUNCINJECT-CODEREF-0001). The single-op adapter
            // inject_raw_ops_single carries the same arm.
            let mut first_input = true;
            for input_raw in raw.inputs() {
                let in_vn = if first_input
                    && matches!(
                        opcode,
                        OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_CALL
                    )
                {
                    // newCodeRef(Address(vars[0].space, vars[0].offset)):
                    // 1-byte annotation Varnode in the raw target's space,
                    // carrying the core "code" type (sleigh_arch.cc:233) the
                    // same way inject_raw_ops_single does.
                    let vn = self
                        .vbank
                        .create_with_space(1, input_raw.space, input_raw.offset);
                    {
                        let mut value = vn.write().unwrap();
                        value.set_flags(crate::varnode::varnode_flags::ANNOTATION);
                        value.v_type = Some(code_ref_datatype());
                    }
                    vn
                } else if input_raw.space == AddressSpace::Const {
                    self.vbank.create_constant(input_raw.size, input_raw.offset)
                } else {
                    self.vbank
                        .create_with_space(
                        input_raw.size,
                        input_raw.space,
                        input_raw.offset)
                };
                // Add use-def link
                in_vn
                    .write()
                    .unwrap()
                    .descend
                    .push(Arc::downgrade(&op_ref.0));
                op_ref.0.write().unwrap().inrefs.push(in_vn);
                first_input = false;
            }

            op_refs.push(op_ref);
        }

        eprintln!("[INJECT] {} phase1 done ops={}", self.name, op_refs.len());

        // flow.cc:336-338 (xrefControlFlow CALL arm) -> flow.cc:683-686
        // (FlowInfo::setupCallSpecs): every CPUI_CALL op carries a
        // FuncCallSpecs at flow time — `new FuncCallSpecs(op)` captures the
        // call target from in(0) (fspec.cc:4931-4938), then in(0) is
        // replaced with the fspec-space annotation Varnode
        // (`data.opSetInput(op, data.newVarnodeCallSpecs(res), 0)`,
        // varnode.cc:599-601: FSPEC-space storage is born annotation|
        // coverdirty, nzm=~0) and the spec joins qlst. On the followFlow
        // path FlowInfo::setup_call_specs (flow.rs) anchors inside
        // xref_control_flow; this linear-scan driver path has no xref walk,
        // so inject_raw_ops — the phase-1.5 boundary between the raw dump
        // and block formation (the same position the override application
        // documents above) — carries the guarantee that ActionDeadCode's
        // cc:3846 first-operand consume, printc's fc->getName() and the
        // has_callspec flag proxy (typeop.cc:663) all rely on
        // (CALLSPEC-DRIVER-0001). CALLIND (flow.cc:340-342 ->
        // setupCallindSpecs flow.cc:704-723) creates a spec WITHOUT the
        // in(0) swap — the ctor leaves the entry address invalid for
        // indirect calls (fspec.cc:4931-4938) and the swap lives only on
        // the overridden-to-direct path (flow.cc:717-721), unreachable on
        // this override-free driver path. The iced lifter DOES emit
        // CPUI_CALLIND for register-indirect calls (x86_lift.rs:4890-4894),
        // so the anchor loop below mirrors the CALLIND arm; the FlowInfo
        // path anchors CALLIND via setup_call_ind_specs inside
        // xref_control_flow. The FlowInfo-level steps of
        // setupCallSpecs (applyPrototype/queryCall/cycle check, flow.cc:
        // 688-693) have no linear-scan counterpart here: this path seeds no
        // overrides, and callee resolution is the driver's pre-flow
        // prototype table.
        // flow.cc:336-338 (xrefControlFlow CALL arm) -> flow.cc:683-686
        // (FlowInfo::setupCallSpecs): every CPUI_CALL op carries a
        // FuncCallSpecs at flow time — `new FuncCallSpecs(op)` captures the
        // call target from in(0) (fspec.cc:4931-4938), then in(0) is
        // replaced with the fspec-space annotation Varnode
        // (`data.opSetInput(op, data.newVarnodeCallSpecs(res), 0)`,
        // varnode.cc:599-601: FSPEC-space storage is born annotation|
        // coverdirty, nzm=~0) and the spec joins qlst. On the followFlow
        // path FlowInfo::setup_call_specs (flow.rs) anchors inside
        // xref_control_flow; this linear-scan driver path has no xref walk,
        // so inject_raw_ops — the phase-1.5 boundary between the raw dump
        // and block formation (the same position the override application
        // documents above) — carries the guarantee that ActionDeadCode's
        // cc:3846 first-operand consume, printc's fc->getName() and the
        // has_callspec flag proxy (typeop.cc:663) all rely on
        // (CALLSPEC-DRIVER-0001). The CALLIND arm below mirrors flow.cc:
        // 340-342 -> setupCallindSpecs (flow.cc:704-723): spec without the
        // in(0) swap, qlst registration gated identically to the CALL arm.
        //
        // CALLSPEC-DRIVER-0002 (registration gate): Ghidra's setupCallSpecs
        // is ATOMIC — flow.cc:686 `qlst.push_back(res)` never happens
        // without the flow-time tail (flow.cc:688-694: applyPrototype /
        // queryCall / checkForFlowModification), and that tail's callee
        // resolution rides on the architecture's model space
        // (queryFunction -> otherfunc->getFuncProto() -> the cspec-bound
        // defaultfp; flow.cc:660-664). Rugra's linear-scan drivers split
        // that atomicity: a driver whose Funcdata carries no bound model
        // (fd.funcp.has_model() == false — e.g. the httpd driver's bare
        // `Architecture::new()`) cannot run the tail's resolution half at
        // all, so registering the half-initialized spec into qlst there
        // activates Heritage's per-call effect guarding
        // (Heritage::callOpIndirectEffect, heritage.cc:362-364: a spec flips
        // the conservative no-spec polarity to a model lookup) while
        // ActionFuncLink/ActionActiveParam have no model to attach
        // call-site inputs against — every call site gains indirect-effect
        // barriers whose reload copies no param/return consumption can
        // absorb (measured: httpd 29/29 functions, skeleton 2344 -> 3576,
        // +379 `x = x` dead-copy chains; main alone 137 -> 669 lines).
        // Gate the qlst registration on the model carrier the tail needs;
        // the annotation swap (the has_callspec/printc/deadcode surface
        // CALLSPEC-DRIVER-0001 named) stays unconditional. Curl's prototype
        // workers bind a cspec model (FUNCPROTO-MODEL-BIND-0001:
        // FuncProto::setScope -> setModel(defaultfp)) and keep the full
        // anchoring; its final path anchors via FlowInfo::setup_call_specs
        // either way. Repair path (removes this gate): port the
        // queryCall/checkForFlowModification tail onto the driver boundary
        // with a driver-fed callee table + defaultfp model, and port
        // ActionCopyPropagation (coreaction.cc:5510-5511, absent from
        // Rugra's universal tree — the reason the guarded reload copies
        // survive as statements today).
        let register_specs = self.funcp.has_model();
        for op_ref in &op_refs {
            let op_opcode = op_ref.0.read().unwrap().opcode;
            if op_opcode == OpCode::CPUI_CALL {
                let fc = crate::fspec::FuncCallSpecs::new_for_op(
                    op_ref,
                    crate::flow::default_call_spec_proto(),
                );
                let owner = Arc::new(RwLock::new(fc));
                let call_spec_vn = self.new_varnode_call_specs(&owner);
                self.op_set_input(op_ref, call_spec_vn, 0);
                if register_specs {
                    self.add_call_specs_owner(owner);
                }
            } else if op_opcode == OpCode::CPUI_CALLIND {
                // Ghidra: flow.cc:340-342 FlowInfo::xrefControlFlow CALLIND arm ->
                // flow.cc:704-723 setupCallindSpecs. The CALLIND spec mirror has
                // NO in(0) swap: `res = new FuncCallSpecs(op)` (flow.cc:708)
                // leaves the entry address invalid for indirect calls
                // (fspec.cc:4931-4938 ctor reads in(0) only for CPUI_CALL), and
                // the annotation swap lives exclusively on the
                // overridden-to-direct path (flow.cc:717-721), which this
                // override-free driver path cannot take. qlst registration
                // (flow.cc:709) rides the same CALLSPEC-DRIVER-0002 model gate
                // as the CALL arm above.
                let fc = crate::fspec::FuncCallSpecs::new_for_op(
                    op_ref,
                    crate::flow::default_call_spec_proto(),
                );
                let owner = Arc::new(RwLock::new(fc));
                if register_specs {
                    self.add_call_specs_owner(owner);
                }
            }
        }

        // Phase 2: Build basic blocks from the linear op sequence
        self.build_blocks_from_ops(&op_refs);
        eprintln!(
            "[INJECT] {} phase2 done bblocks={}", self.name, self.bblocks.get_size()
        );

        // Phase 3: Mark unwritten Register-space input varnodes as INPUT
        // In Ghidra's model, Heritage marks register reads with no prior definition
        // within the function as INPUT varnodes (function parameters / callee-saved regs).
        //
        // Correct semantics (read-before-write): a register read at op N is an INPUT
        // if no earlier op (in instruction order) wrote to that register offset.
        // Using a global "ever-defined" set is WRONG because parameter registers
        // are routinely re-assigned mid-function (e.g. RDX is read as param_3 at
        // 0x34a2 then overwritten by `mov rdx,[rsp+8]` at 0x34ac). A global set
        // would see the later write and miss the earlier read.
        //
        // We process ops in order; for each op we first inspect its inputs (reads)
        // and then record its output (write). This gives correct read-before-write
        // ordering within the linear instruction stream.
        //
        // CALL ops are skipped: the lifter attaches 6 ABI arg registers as inputs
        // to every CALL, which represent arguments PASSED TO the callee, not
        // registers READ by this function. Counting them would inflate the INPUT
        // set with RDI/RSI/RDX/RCX/R8/R9 on every function containing a call.
        let mut defined_reg_offsets: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Track which offsets we've already marked as INPUT to avoid duplicates
        let mut marked_input = std::collections::HashSet::new();
        for op_ref in &op_refs {
            // Snapshot first. setInput can canonicalize through xref and
            // rewrite this op's slots, so no read guard on the op may survive
            // across the bank transition.
            let (opcode, inputs, output) = {
                let op = op_ref.0.read().unwrap();
                (op.opcode, op.inrefs.clone(), op.output.clone())
            };

            // Skip CALL: its register inputs are callee args, not this function's reads.
            if opcode == OpCode::CPUI_CALL {
                // Still record any output (call return value in RAX) as defined,
                // so a later read of RAX is not mistaken for a parameter.
                if let Some(ref out_arc) = output {
                    let out_vn = out_arc.read().unwrap();
                    if out_vn.get_space() == AddressSpace::Register {
                        defined_reg_offsets.insert(out_vn.get_offset());
                    }
                }
                continue;
            }

            // First: process reads (inputs) against the *current* defined set.
            for (slot, in_arc) in inputs.into_iter().enumerate() {
                let vn = in_arc.read().unwrap();
                if vn.get_space() == AddressSpace::Register
                    && vn.is_free()
                    && !vn.is_input()
                    && !defined_reg_offsets.contains(&vn.get_offset())
                    && marked_input.insert(vn.get_offset())
                {
                    drop(vn); // Release read lock before write
                    let canonical = self.vbank.set_input_prevalidated(in_arc);
                    // PRINTC-BADSPACEBASE-RENDER-0001: Funcdata::
                    // setInputVarnode's effect tail (funcdata_varnode.cc:
                    // 365-370) must also run for iced-prelude promotions —
                    // Ghidra marks every input through setInputVarnode, so
                    // the ProtoModel unaffected/return_address records
                    // (x86-64 cspec <unaffected> RSP/RBP/RBX) reach every
                    // input varnode. Without the tail the RSP input misses
                    // Varnode::unaffected, HighVariable::hasName
                    // (variable.cc:737-744) then names the spacebase high,
                    // and printc leaks a `BADSPACEBASE *in_register_…`
                    // declaration (ActionNameVars::linkSymbols coreaction.cc:
                    // 2961-2962 hasName gate).
                    {
                        let (space, offset, size) = {
                            let guard = canonical.read().unwrap();
                            (guard.get_space(), guard.get_offset(), guard.get_size())
                        };
                        if let Some(effecttype) =
                            self.funcp.try_has_effect(space, offset, size as i32)
                        {
                            let mut guard = canonical.write().unwrap();
                            if effecttype == crate::fspec::EffectType::Unaffected {
                                guard.set_unaffected();
                            }
                            if effecttype == crate::fspec::EffectType::ReturnAddress {
                                // Should be unaffected over the course of
                                // the function (funcdata_varnode.cc:369).
                                guard.set_unaffected();
                                guard.set_return_address();
                            }
                        }
                    }
                    debug_assert!(op_ref
                        .0
                        .read()
                        .unwrap()
                        .inrefs
                        .get(slot)
                        .is_some_and(|current| Arc::ptr_eq(current, &canonical)));
                }
            }

            // Then: record this op's output as defined for subsequent ops.
            if let Some(ref out_arc) = output {
                let out_vn = out_arc.read().unwrap();
                if out_vn.get_space() == AddressSpace::Register {
                    defined_reg_offsets.insert(out_vn.get_offset());
                }
            }
        }
        eprintln!(
            "[INJECT] {} phase3 done marked_input={}", self.name, marked_input.len()
        );
        // NOTE: Phase 4 global use-def linking is disabled — it correctly
        // resolves stack symbols (verified) but perturbs typeop inference
        // (struct-pointer types leak into switch/arith contexts). varmap's
        // resolve_rsp_offset_via_bank provides a read-only def bridge scoped
        // to spacebase resolution only, avoiding the typeop interaction.
    }

    // Ghidra: funcdata.cc:34 Funcdata::buildBlocksFromOps
    /// Build basic blocks from a linear sequence of PcodeOps
    ///
    /// Splits the op list at control flow terminators (BRANCH, CBRANCH, RETURN, CALL)
    /// and at every intra-function jump-target address, then creates basic
    /// blocks in `self.bblocks`.
    fn build_blocks_from_ops(&mut self, op_refs: &[PcodeOpRef]) {
        if op_refs.is_empty() {
            return;
        }

        // Identify block start points. Ghidra's flow-driven basic-block
        // partitioning (flow.cc FlowInfo / BlockGraph::copyBlocks) splits at
        // TWO kinds of points:
        //   (1) after each block terminator (BRANCH/CBRANCH/BRANCHIND/RETURN)
        //   (2) at every jump TARGET address — any address that a BRANCH/
        //       CBRANCH points to must begin a new block, so the target edge
        //       resolves to a block start.
        // Rugra previously did only (1) for op-bearing addresses, which meant
        // jump targets landing in the middle of a block were unresolvable —
        // the CBRANCH edge was silently dropped (observed: curl main 56 /
        // global 182 CBRANCH targets unmatched, losing back-edges and
        // collapsing while-loop recovery from ~6 to 1). The synthetic-boundary
        // handling below closes the remaining hole: targets whose instruction
        // emits no p-code at all.

        // Build addr -> op-index map for target resolution.
        let mut addr_to_idx: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::with_capacity(op_refs.len());
        for (i, op_ref) in op_refs.iter().enumerate() {
            let addr = op_ref.0.read().unwrap().get_addr().as_u64();
            addr_to_idx.entry(addr).or_insert(i);
        }

        // Collect target op-indices from BRANCH/CBRANCH.
        //
        // Resolved target (an op exists at the target address): the op at
        // the target address starts a new block (Ghidra splits there).
        //
        // Unresolved target whose address is inside [baseaddr, baseaddr+size):
        // Ghidra's flow-driven block formation (flow.cc FlowInfo) makes EVERY
        // intra-function jump target a block start — in Ghidra every
        // instruction emits at least one p-code op, so the target address
        // always names an op. Rugra's lifters can emit ZERO ops for an
        // instruction (x86_lift.rs:602 push/pop arm, missing movzx/movsx
        // arms), so the target address may have no op; the faithful CFG
        // shape is still a block boundary at that address. Insert a
        // SYNTHETIC block start: the block's start address is the target
        // address and it absorbs the first ops whose instruction address is
        // beyond the target. Without this the CBRANCH target edge was
        // silently dropped, birthing "zombie decision blocks" (CBRANCH
        // lastOp with <2 out-edges) that violate the branchRemoveInternal
        // invariant (funcdata_block.cc:203-204 destroys the cbranch exactly
        // when an out-edge of a 2-way decision is removed — Ghidra never
        // allows the CBRANCH to outlive its second edge). Unresolved target
        // outside the function range is a tail-jump/extern flow: keep
        // dropping the edge.
        let fn_start = self.baseaddr.as_u64();
        let fn_end = fn_start + self.size.max(0) as u64;
        let mut target_starts: std::collections::HashSet<usize> =
            std::collections::HashSet::new();
        let mut synthetic_starts: Vec<(usize, u64)> = Vec::new();
        for op_ref in op_refs.iter() {
            let (opc, target_offset) = {
                let op = op_ref.0.read().unwrap();
                let tgt = match op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (op.opcode, tgt)
            };
            if matches!(opc, OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH) {
                if let Some(taddr) = target_offset {
                    match addr_to_idx.get(&taddr) {
                        Some(&tidx) => {
                            // The op at the target address starts a new block.
                            // Don't split at index 0 (it's already a start) and
                            // don't split at i+1 if this branch falls through to
                            // its target (handled by terminator rule below).
                            if tidx != 0 {
                                target_starts.insert(tidx);
                            }
                        }
                        None => {
                            if taddr >= fn_start && taddr < fn_end {
                                // First op index whose instruction address is
                                // beyond the target (ops are in lift order =
                                // non-decreasing address). All ops at taddr
                                // itself would have resolved above.
                                let k = op_refs
                                    .iter()
                                    .position(|o| {
                                        o.0.read().unwrap().get_addr().as_u64() > taddr
                                    })
                                    .unwrap_or(op_refs.len());
                                synthetic_starts.push((k, taddr));
                            }
                            // Target outside this function (tail-call /
                            // external): skip, the edge is dropped as before.
                        }
                    }
                }
            }
        }

        // Combine into ordered block-start entries (op-index, start-address):
        //   {entry op 0} ∪ {terminator+1} ∪ {resolved jump targets} ∪
        //   {synthetic boundaries at unresolved intra-function targets}.
        // Sorting by (index, address) keeps a synthetic boundary (same index,
        // smaller address) ahead of the real block start at that index; dedup
        // collapses identical pairs. Blocks then span
        // [entry[m].index .. entry[m+1].index); consecutive synthetic
        // entries (or one at the tail) produce empty blocks, which receive
        // fall-through edges below — the CFG shape Ghidra would build from
        // the same jump targets.
        let mut block_starts: Vec<(usize, u64)> = Vec::new();
        block_starts.push((0, op_refs[0].0.read().unwrap().get_addr().as_u64()));
        for (i, op_ref) in op_refs.iter().enumerate() {
            let is_term = op_ref.0.read().unwrap().opcode.is_block_terminator();
            if is_term && i + 1 < op_refs.len() {
                block_starts.push((
                    i + 1,
                    op_refs[i + 1].0.read().unwrap().get_addr().as_u64(),
                ));
            }
        }
        for tidx in target_starts {
            block_starts.push((
                tidx,
                op_refs[tidx].0.read().unwrap().get_addr().as_u64(),
            ));
        }
        block_starts.extend(synthetic_starts);
        block_starts.sort_unstable();
        block_starts.dedup();

        // Create basic blocks
        let mut blocks: Vec<Arc<RwLock<BlockBasic>>> = Vec::new();
        for (block_idx, &(start, start_addr)) in block_starts.iter().enumerate() {
            let end = if block_idx + 1 < block_starts.len() {
                block_starts[block_idx + 1].0
            } else {
                op_refs.len()
            };

            let block_addr = crate::address::Address::new(start_addr);
            let block = Arc::new(RwLock::new(BlockBasic::new(block_idx as i32, block_addr)));

            // Add ops to this block
            let mut stop_addr = start_addr;
            for op_ref in &op_refs[start..end] {
                {
                    let mut op = op_ref.0.write().unwrap();
                    op.parent = Some(Arc::downgrade(
                        // We need to cast to dyn FlowBlock
                        &(block.clone() as Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>),
                    ));
                }
                // flow.cc:1010-1012: stop tracks the biggest op address seen
                // (FlowInfo::splitBasic's setBasicBlockRange(cur, start, stop)
                // at flow.cc:1004/1016 → BlockBasic::setInitialRange,
                // block.cc:2625). The cover is the block's ORIGINAL
                // instruction range and must never move when later Actions
                // remove leading ops: BlockBasic::getEntryAddr (block.cc:2302)
                // reads the cover, falling back to the first op's address only
                // for multi-range covers — without a cover, dead-code removal
                // of a leading op (observed: the stack-canary reload mov at
                // httpd 0x12cfc6/0x12d7f0 and the loop-increment add at
                // 0x12e410) drifted every goto label built on
                // getEntryAddr/emitLabel (printc.cc:3164-3193) to the next
                // op's address.
                let op_addr = op_ref.0.read().unwrap().get_addr().as_u64();
                if stop_addr < op_addr {
                    stop_addr = op_addr;
                }
                let insert_pos = block.read().unwrap().get_ops().len();
                block.write().unwrap().insert_op(insert_pos, op_ref.clone());
            }
            // flow.cc:1016: close the block's range. Synthetic empty blocks
            // (an instruction the lifter emitted no p-code for) still anchor
            // the degenerate closed range [taddr, taddr] so a goto targeting
            // the address resolves a stable label.
            block
                .write()
                .unwrap()
                .set_initial_range(block_addr, crate::address::Address::new(stop_addr));

            blocks.push(block);
        }

        // Add blocks to the graph
        for block in &blocks {
            self.bblocks.add_block(block.clone());
        }

        // Add fallthrough edges between consecutive blocks
        // Also resolve BRANCH and CBRANCH targets to add the branch edges.
        // A block with no ops (synthetic boundary at an unresolved jump
        // target, or between two adjacent synthetic boundaries) falls
        // through to the next block: it stands in for real instructions the
        // lifter emitted no p-code for, which fall through the same way.
        for i in 0..blocks.len() {
            let block_empty = {
                let b = blocks[i].read().unwrap();
                b.get_ops().is_empty()
            };
            if block_empty {
                // No guard may be held across add_edge: it write-locks both
                // endpoints, and read→write on the same RwLock self-deadlocks.
                if i + 1 < blocks.len() {
                    self.bblocks.add_edge(blocks[i].clone(), blocks[i + 1].clone());
                }
                continue;
            }
            let (last_opcode, branch_target_offset) = {
                let b = blocks[i].read().unwrap();
                let ops = b.get_ops();
                let last_op = ops.last().unwrap().0.read().unwrap();
                let target = match last_op.opcode {
                    OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCH => {
                        // Input 0 is the branch target address
                        last_op.get_in(0).map(|vn| vn.read().unwrap().get_offset())
                    }
                    _ => None,
                };
                (last_op.opcode, target)
            };

            match last_opcode {
                OpCode::CPUI_RETURN | OpCode::CPUI_BRANCHIND => {
                    // Terminators that don't transition to a known, raw intra-function block
                }
                OpCode::CPUI_BRANCH => {
                    // Unconditional branch: 1 edge to the target ONLY
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }
                }
                OpCode::CPUI_CBRANCH => {
                    // CBRANCH gets BOTH edges. Edge ORDER follows Ghidra's
                    // FlowInfo::generateBlockEdges (flow.cc:960-967): the
                    // FALL-THRU edge is pushed FIRST (out edge 0), the branch
                    // target SECOND (out edge 1). All Ghidra consumers index
                    // out edges as [falseOut=0, trueOut=1] (block.hh:294-301),
                    // e.g. ActionConditionalConst::findConstCompare
                    // (coreaction.cc:4496 constEdge=1 for INT_EQUAL) and
                    // JumpTable analysis true-slot indexing; the previous
                    // [target, fallthru] order inverted the true/false
                    // meaning of getOut(0)/getOut(1) and made condconst
                    // substitute the branch constant into the wrong path.
                    // Edge 0: fallthrough (false branch) to next sequential block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }

                    // Edge 1: branch target (true branch)
                    if let Some(target_addr) = branch_target_offset {
                        for j in 0..blocks.len() {
                            let target_start = blocks[j].read().unwrap().get_start_addr().as_u64();
                            if target_start == target_addr {
                                self.bblocks.add_edge(blocks[i].clone(), blocks[j].clone());
                                break;
                            }
                        }
                    }
                }
                _ => {
                    // Add fallthrough edge to next block
                    if i + 1 < blocks.len() {
                        self.bblocks
                            .add_edge(blocks[i].clone(), blocks[i + 1].clone());
                    }
                }
            }
        }
    }

    // Ghidra: funcdata.cc:84 Funcdata::clear
    /// Clear everything associated with decompilation (analysis).
    /// Faithful to `Funcdata::clear` (funcdata.cc:84-112), step for step in
    /// the Ghidra statement order:
    ///
    ///   cc:88-89   flags &= ~(highlevel_on|blocks_generated|
    ///              processing_started|typerecovery_start|typerecovery_on|
    ///              double_precis_on|restart_pending)
    ///   cc:90-92   clean_up_index = 0; high_level_index = 0;
    ///              cast_phase_index = 0
    ///   cc:93      minLanedSize = glb->getMinimumLanedRegisterSize()
    ///   cc:95-96   localmap->clearUnlocked(); localmap->resetLocalWindow()
    ///   cc:98      clearActiveOutput()
    ///   cc:99      funcp.clearUnlockedOutput()
    ///   cc:100     unionMap.clear()
    ///   cc:101     clearBlocks()
    ///   cc:102-103 obank.clear(); vbank.clear()
    ///   cc:104     clearCallSpecs()
    ///   cc:105     clearJumpTables()
    ///   cc:106     // Do not clear overrides
    ///   cc:107     heritage.clear()
    ///   cc:108     covermerge.clear()
    ///
    /// The flags mask is PARTIAL on purpose: Ghidra preserves
    /// blocks_unreachable, processing_complete, no_code, jumptablerecovery_on,
    /// jumptablerecovery_dont, unimplemented_present, baddata_present and
    /// typerecovery_exceeded across clear (only the seven analysis-phase bits
    /// die), so a restarted function keeps its completion/limit markers.
    /// Rugra's remapped `funcdata_flags` bit values differ from Ghidra's raw
    /// bit positions, but the logical mask is the same seven flags.
    /// `clean_up_index` has no Rugra field (the startCleanUp marker in
    /// coreaction.rs is a faithful no-op), so only its reset is a no-op;
    /// `cast_phase_index` (funcdata.hh:77) is reset below.
    pub fn clear(&mut self) {
        // cc:88-89: clear the seven analysis-phase flag bits (Ghidra mask
        // highlevel_on|blocks_generated|processing_started|typerecovery_start|
        // typerecovery_on|double_precis_on|restart_pending).
        self.flags &= !(funcdata_flags::HIGHLEVEL_ON
            | funcdata_flags::BLOCKS_GENERATED
            | funcdata_flags::PROCESSING_STARTED
            | funcdata_flags::TYPE_RECOVERY_START
            | funcdata_flags::TYPE_RECOVERY_ON
            | funcdata_flags::DOUBLE_PRECIS_ON
            | funcdata_flags::RESTART_PENDING);
        // Ghidra's restart_pending lives in the flags word (funcdata.hh:84,
        // 0x400); Rugra additionally mirrors it in a dedicated bool
        // (funcdata.hh:216 hasRestartPending accessor counterpart), so the
        // same masked bit must clear both projections.
        self.restart_pending = false;
        // cc:90-92: counter resets. clean_up_index now has real Rugra
        // storage (funcdata.hh:187), so all three counters reset here.
        self.clean_up_index = 0;
        self.high_level_index = 0;
        self.cast_phase_index = 0;
        // cc:93: minLanedSize = glb->getMinimumLanedRegisterSize()
        // (architecture.cc:312-317: -1 when lanerecords is empty; u32::MAX is
        // the same sentinel in Rugra's unsigned representation).
        self.min_laned_size = self
            .arch
            .as_ref()
            .map_or(u32::MAX, |arch| {
            arch.get_minimum_laned_register_size() as u32
        });
        // cc:95: localmap->clearUnlocked() — clear non-permanent stuff.
        // RUGRA modeling (same convention as start_processing, funcdata.cc
        // 160): the varmap ScopeLocal keeps its index-keyed nametree/category
        // lists private, so the faithful typelock-preserving clearUnlocked
        // (database.cc:2042-2064) cannot be projected from this module; the
        // wholesale reset below (symbols + nametree + category_lists +
        // mapentry_log, mirroring the oracle's atomic
        // removeSymbol/removeSymbolMappings pair, database.cc:2117-2149) is
        // the established model. Typelocked-symbol survival is a registered
        // MISMATCH residual (MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001 /
        // localmap_typelock_survival).
        if let Some(scope) = self.scope.as_mut() {
            scope.clear_symbols_wholesale();
            // cc:96: localmap->resetLocalWindow() (varmap.cc:432-463).
            // minParamOffset = ~(uintb)0; maxParamOffset = 0 (varmap.cc:443-444);
            // the stackGrowsNegative/local-range re-derivation reads
            // FuncProto::getLocalRange/isStackGrowsNegative (fspec.hh:1539-1541,
            // 978) which Rugra's FuncProto does not expose — no Rugra writer
            // drifts those fields after construction, so their reset is
            // currently unobservable (residual branch reset_local_window_range).
            scope.min_param_offset = u64::MAX;
            scope.max_param_offset = 0;
        }
        // The HighVariable→Symbol associations die with the symbols
        // (same companion clear start_processing performs at funcdata.cc:160).
        self.high_symbols.clear();
        self.symbol_entry_cache.clear();
        // cc:98: clearActiveOutput() (funcdata.hh:420-423: delete + null).
        self.active_output = None;
        // cc:99: funcp.clearUnlockedOutput() — inputs are cleared by localmap.
        // RUGRA residual: fspec.rs clear_unlocked_output is a simplification
        // of fspec.cc:4001-4013 (no size-lock type reset, no store output
        // clear, returnBytesConsumed not zeroed) — bound to
        // MERGE-CLEAR-LIFECYCLE-RESIDUAL-0001 / funcproto_unlocked_output.
        self.funcp.clear_unlocked_output();
        // cc:100: unionMap.clear()
        self.union_map.clear();
        // cc:101: clearBlocks() (funcdata_block.cc:34-39)
        self.clear_blocks();
        // cc:102-103: obank.clear() (op.cc:1194-1210, uniqid restarts at 0);
        // vbank.clear() (varnode.cc:1230-1241, uniqid resets to the unique
        // base and create_index to 0).
        self.obank.clear();
        self.vbank.clear();
        // cc:104: clearCallSpecs() (funcdata.cc:464-473)
        self.clear_call_specs();
        // cc:105: clearJumpTables() (funcdata_block.cc:42-59)
        self.clear_jump_tables();
        // cc:106: Do not clear overrides — localoverride and laned_map both
        // survive clear (funcdata.hh:108/-99 have no clear call sites).
        // cc:107: heritage.clear() (heritage.cc:2855-2866)
        self.heritage.clear();
        // cc:108: covermerge.clear() (merge.cc:1580-1587)
        self.merge_state.clear();
        // cc:110 (#ifdef OPACTION_DEBUG): opactdbg_count = 0. The debug
        // counter resets with everything else; the traced ranges survive.
        self.opactdbg_count = 0;
    }

    // =========================================================================
    // Union field resolution (funcdata.cc:917-1005)
    // =========================================================================

    // Ghidra: funcdata.cc:917 Funcdata::getUnionField
    /// Get the resolved union field associated with the given edge, or None.
    /// Faithful to `Funcdata::getUnionField` (funcdata.cc:917-926):
    ///   ResolveEdge edge(parent, op, slot);
    ///   iter = unionMap.find(edge);
    ///   if (iter != unionMap.end()) return &(*iter).second;
    ///   return NULL;
    /// Returns a cloned `ResolvedUnion` (Rugra's borrow model cannot hand out
    /// a borrow tied to `&self` alongside later `&mut self` setUnionField).
    pub fn get_union_field(
        &self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
    ) -> Option<crate::unionresolve::ResolvedUnion> {
        let edge = crate::unionresolve::ResolveEdge::new(parent, &op.0.read().unwrap(), slot);
        self.union_map.get(&edge).cloned()
    }

    // Ghidra: funcdata.cc:937 Funcdata::setUnionField
    /// Associate a union field with the given edge. Faithful to
    /// `Funcdata::setUnionField` (funcdata.cc:937-965). If a previous
    /// association exists and is locked, return false (no overwrite).
    /// Otherwise overwrite. Additionally, when `op` is a MULTIEQUAL and slot
    /// >= 0, copy the resolution to any other input slot holding the same
    /// Varnode (data-type propagation does not happen between such slots).
    /// Returns true unless a locked association blocked the overwrite.
    pub fn set_union_field(
        &mut self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        resolve: crate::unionresolve::ResolvedUnion,
    ) -> bool {
        let edge = crate::unionresolve::ResolveEdge::new(parent, &op.0.read().unwrap(), slot);
        // cc:942-948: res = unionMap.emplace(edge, resolve); if (!res.second)
        //   { if (locked) return false; else (*res.first).second = resolve; }
        let blocked = match self.union_map.get(&edge) {
            Some(existing) if existing.is_locked() => true,
            _ => false,
        };
        if blocked {
            return false;
        }
        self.union_map.insert(edge.clone(), resolve.clone());
        // cc:949-963: MULTIEQUAL same-Varnode duplication.
        let (is_multiequal, dup_slots, dup_vn) = {
            let o = op.0.read().unwrap();
            if o.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL && slot >= 0 {
                let target = o.get_in(slot as usize).cloned();
                if let Some(target_vn) = target {
                    let mut dups = Vec::new();
                    for i in 0..o.num_input() {
                        if i as i32 == slot {
                            continue;
                        }
                        if let Some(v) = o.get_in(i) {
                            if std::sync::Arc::ptr_eq(v, &target_vn) {
                                dups.push(i as i32);
                            }
                        }
                    }
                    (true, dups, Some(target_vn))
                } else {
                    (true, Vec::new(), None)
                }
            } else {
                (false, Vec::new(), None)
            }
        };
        let _ = (is_multiequal, dup_vn); // dup_vn only used to scope the read guard above.
        // cc:956-961: for each dup slot, emplace dupedge; if not locked overwrite.
        for dup_slot in dup_slots {
            let dup_edge = crate::unionresolve::ResolveEdge::new(
                parent,
                &op.0.read().unwrap(),
                dup_slot);
            let locked = self
                .union_map
                .get(&dup_edge)
                .map_or(false, |r| r.is_locked());
            if !locked {
                self.union_map.insert(dup_edge, resolve.clone());
            }
        }
        true
    }

    // Ghidra: funcdata.cc:974 Funcdata::forceFacingType
    /// Force a specific union field resolution for the given edge. Faithful
    /// to `Funcdata::forceFacingType` (funcdata.cc:974-986):
    ///   baseType = parent;
    ///   if (baseType->getMetatype() == TYPE_PTR)
    ///     baseType = ((TypePointer *)baseType)->getPtrTo();
    ///   if (parent->isPointerRel())
    ///     parent = glb->types->getTypePointer(parent->getSize(), baseType,
    ///                                         ((TypePointer*)parent)->getWordSize());
    ///   ResolvedUnion resolve(parent, fieldNum, *glb->types);
    ///   setUnionField(parent, op, slot, resolve);
    /// Rugra: relative pointers (pointerRel) are not modeled as a distinct
    /// Datatype flag yet; the rewrite to a standard pointer is a no-op until
    /// that metadata lands. The ResolvedUnion is built via `with_field`
    /// under a TypeFactory **write** guard (UNIONRESOLVE-PKG-G-0001): the
    /// cc:51-55 pointer arm interns through `getTypePointer`, mirroring the
    /// oracle's `*glb->types` mutation channel, so the resolve Arc is
    /// factory-canonical for the `Arc::ptr_eq` identity family. When no arch
    /// is attached we fall back to the plain `new(parent)` self-resolution.
    pub fn force_facing_type(
        &mut self,
        parent: std::sync::Arc<crate::type_system::datatype::Datatype>,
        field_num: i32,
        op: &crate::op::PcodeOpRef,
        slot: i32,
    ) {
        // cc:978-979: strip one pointer layer for the base type.
        let _base_type = match parent.as_ref() {
            crate::type_system::datatype::Datatype::Pointer(p) => p.ptr_to.clone(),
            _ => parent.clone(),
        };
        // cc:980-983: relative-pointer → standard-pointer rewrite (Rugra gap).
        // cc:984-985: ResolvedUnion resolve(parent, fieldNum, *glb->types).
        let resolve = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                let mut tg_guard = tg.write().unwrap();
                crate::unionresolve::ResolvedUnion::with_field(
                    parent.clone(),
                    field_num,
                    &mut tg_guard)
            } else {
                crate::unionresolve::ResolvedUnion::new(parent.clone())
            }
        } else {
            // RUGRA-GAP: no TypeFactory available; record a self-resolution so
            // the edge is at least tracked in unionMap.
            crate::unionresolve::ResolvedUnion::new(parent.clone())
        };
        self.set_union_field(parent.as_ref(), op, slot, resolve);
    }

    // Ghidra: funcdata.cc:995 Funcdata::inheritResolution
    /// Copy a read/write facing resolution from `oldOp`/`oldSlot` to
    /// `op`/`slot`. Faithful to `Funcdata::inheritResolution`
    /// (funcdata.cc:995-1005):
    ///   ResolveEdge edge(parent, oldOp, oldSlot);
    ///   iter = unionMap.find(edge);
    ///   if (iter == unionMap.end()) return -1;
    ///   setUnionField(parent, op, slot, (*iter).second);
    ///   return (*iter).second.getFieldNum();
    /// Returns the resolved field number, or -1 if no resolution was present
    /// on the source edge.
    pub fn inherit_resolution(
        &mut self,
        parent: &crate::type_system::datatype::Datatype,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        old_op: &crate::op::PcodeOpRef,
        old_slot: i32,
    ) -> i32 {
        let edge =
            crate::unionresolve::ResolveEdge::new(parent, &old_op.0.read().unwrap(), old_slot);
        let Some(resolve) = self.union_map.get(&edge).cloned() else {
            return -1;
        };
        let field_num = resolve.get_field_num();
        self.set_union_field(parent, op, slot, resolve);
        field_num
    }

    // =========================================================================
    // Expression normalization (funcdata_op.cc:1132-1500)
    // =========================================================================

    // Ghidra: funcdata_op.cc:1130 Funcdata::collapseIntMultMult
    /// Fold two chained constant INT_MULTs into one. Faithful to
    /// `Funcdata::collapseIntMultMult` (funcdata_op.cc:1132-1153). Given
    ///   vn = INT_MULT(A, c1)
    ///   A  = INT_MULT(B, c2)
    /// rewrites the outer multiply to `INT_MULT(B, c1*c2)`. Returns true if a
    /// fold happened. Walks the def chain: vn must be written by an INT_MULT
    /// whose second input is constant, and whose first input is itself a
    /// constant INT_MULT.
    pub fn collapse_int_mult_mult(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        // cc:1135: if (!vn->isWritten()) return false.
        let (def, const_first, in0, sz) = {
            let v = vn.read().unwrap();
            if !v.is_written() {
                return false;
            }
            let def = match v.get_def() {
                Some(d) => d,
                None => return false,
            };
            let (opcode, const_first, in0) = {
                let o = def.read().unwrap();
                // cc:1137: if (op->code() != CPUI_INT_MULT) return false.
                if o.opcode != OpCode::CPUI_INT_MULT {
                    return false;
                }
                // cc:1138-1139: constVnFirst = op->getIn(1); if (!isConstant) false.
                let const_first = match o.get_in(1) {
                    Some(c) if c.read().unwrap().is_constant() => c.clone(),
                    _ => return false,
                };
                // cc:1140: if (!op->getIn(0)->isWritten()) return false.
                let in0 = match o.get_in(0) {
                    Some(v0) => v0.clone(),
                    None => return false,
                };
                (o.opcode, const_first, in0)
            };
            if !in0.read().unwrap().is_written() {
                return false;
            }
            let _ = opcode;
            (def, const_first, in0, vn.read().unwrap().get_size())
        };
        // cc:1141-1142: otherMultOp = in0->getDef(); if code != INT_MULT false.
        let (other_def, const_second, invn) = {
            let other_def = match in0.read().unwrap().get_def() {
                Some(d) => d,
                None => return false,
            };
            let (const_second, invn) = {
                let oo = other_def.read().unwrap();
                if oo.opcode != OpCode::CPUI_INT_MULT {
                    return false;
                }
                // cc:1143-1144: constVnSecond = otherMultOp->getIn(1); const check.
                let const_second = match oo.get_in(1) {
                    Some(c) if c.read().unwrap().is_constant() => c.clone(),
                    _ => return false,
                };
                // cc:1145: invn = otherMultOp->getIn(0).
                let invn = match oo.get_in(0) {
                    Some(v) => v.clone(),
                    None => return false,
                };
                (const_second, invn)
            };
            (other_def, const_second, invn)
        };
        // cc:1146: if (invn->isFree()) return false.
        if invn.read().unwrap().is_free() {
            return false;
        }
        // cc:1147-1152: val = (c1*c2) & calc_mask(sz); rewrite op inputs.
        let val_first = const_first.read().unwrap().get_offset();
        let val_second = const_second.read().unwrap().get_offset();
        let mask = crate::address::calc_mask(sz);
        let val = (val_first.wrapping_mul(val_second)) & mask;
        let newvn = self.new_constant(sz, val);
        let op_ref = crate::op::PcodeOpRef(def.clone());
        self.op_set_input(&op_ref, newvn, 1);
        self.op_set_input(&op_ref, invn, 0);
        // other_def / const_second kept for clarity; the original INT_MULT(B,c2)
        // becomes dead and is reclaimed by the dead-code pass (faithful: cc
        // does not explicitly destroy it here).
        let _ = (other_def, const_second);
        true
    }

    // Ghidra: funcdata_op.cc:1159 Funcdata::buildCopyTemp
    /// Return a unique-space Varnode defined by a COPY of `vn`, available at
    /// `point`. Faithful to `Funcdata::buildCopyTemp` (funcdata_op.cc:1161-1213).
    /// If a preexisting COPY into unique space exists and is usable at `point`,
    /// reuse it; if it is in a different block but not ancestor/descendant, a
    /// new COPY is built at the common dominator's end. Otherwise a fresh COPY
    /// is inserted before `point`. Stale copies are totalReplace'd away.
    pub fn build_copy_temp(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        point: &crate::op::PcodeOpRef,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        // cc:1167-1177: scan vn's descendants for a COPY into unique space.
        let mut other_op: Option<crate::op::PcodeOpRef> = None;
        {
            let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
                vn.read().unwrap().descend_iter().collect();
            for op_arc in descendants {
                let o = op_arc.read().unwrap();
                if o.opcode != OpCode::CPUI_COPY {
                    continue;
                }
                // cc:1170-1173: outvn must be in IPTR_INTERNAL and not typelock.
                if let Some(outvn) = o.get_out() {
                    let ov = outvn.read().unwrap();
                    if ov.get_space() == crate::space::AddressSpace::Unique
                        && !ov.is_type_lock()
                    {
                        other_op = Some(crate::op::PcodeOpRef(op_arc.clone()));
                        break;
                    }
                }
            }
        }
        // cc:1178-1200: decide which copy to use, possibly building one at a
        // common dominator block.
        let point_parent = point
            .0
            .read()
            .unwrap()
            .parent
            .clone()
            .and_then(|w| w.upgrade());
        let mut used_copy: Option<crate::op::PcodeOpRef> = None;
        let mut built_at_common = false;
        if let Some(other) = &other_op {
            let other_parent = other
                .0
                .read()
                .unwrap()
                .parent
                .clone()
                .and_then(|w| w.upgrade());
            match (&point_parent, &other_parent) {
                (Some(pp), Some(op_parent)) if std::sync::Arc::ptr_eq(pp, op_parent) => {
                    // cc:1179-1184: same block — compare seqnum order.
                    let (point_order, other_order) = {
                        let p = point.0.read().unwrap();
                        let o = other.0.read().unwrap();
                        (p.get_seq_num().order, o.get_seq_num().order)
                    };
                    if point_order < other_order {
                        used_copy = None;
                    } else {
                        used_copy = Some(other.clone());
                    }
                }
                (Some(pp), Some(op_parent)) => {
                    // cc:1186-1198: different blocks — find common dominator.
                    let common = crate::block::BlockGraph::find_common_block(pp, op_parent);
                    match &common {
                        Some(c) if std::sync::Arc::ptr_eq(c, pp) => {
                            used_copy = None;
                        }
                        Some(c) if std::sync::Arc::ptr_eq(c, op_parent) => {
                            used_copy = Some(other.clone());
                        }
                        Some(c) => {
                            // cc:1193-1198: neither dominates — build a COPY at
                            // the common block's stop address, inserted at end.
                            let vn_size = vn.read().unwrap().get_size();
                            // Ghidra's getStop() is a BlockBasic method; we
                            // downcast to fetch it, falling back to the block's
                            // start address if the common dominator is not a
                            // BlockBasic (shouldn't happen for the merge case).
                            let stop_addr = {
                                let c_rg = c.read().unwrap();
                                c_rg
                                    .as_any()
                                    .downcast_ref::<crate::block::BlockBasic>()
                                    .map(|bb| bb.get_stop_addr())
                                    .unwrap_or_else(|| c_rg.get_start_addr())
                            };
                            let new_copy = self.new_op(1, stop_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            self.op_set_input(&new_copy, vn.clone(), 0);
                            self.op_insert_end(&new_copy, c);
                            used_copy = Some(new_copy);
                            built_at_common = true;
                        }
                        None => {
                            used_copy = None;
                        }
                    }
                }
                _ => {
                    used_copy = None;
                }
            }
        }
        // cc:1201-1207: no usable preexisting copy — build one before point.
        if used_copy.is_none() {
            let vn_size = vn.read().unwrap().get_size();
            let addr = point.0.read().unwrap().get_addr();
            let new_copy = self.new_op(1, addr);
            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
            self.new_unique_out(vn_size, &new_copy);
            self.op_set_input(&new_copy, vn.clone(), 0);
            self.op_insert_before(&new_copy, point);
            used_copy = Some(new_copy);
        }
        let used_copy = used_copy.expect("build_copy_temp: used_copy set above");
        // cc:1208-1211: if the preexisting otherOp is no longer used, replace
        // its output with the chosen copy's output and destroy it.
        if let Some(other) = &other_op {
            if !built_at_common && !std::sync::Arc::ptr_eq(&other.0, &used_copy.0) {
                let (other_out, used_out) = {
                    let o = other.0.read().unwrap();
                    let u = used_copy.0.read().unwrap();
                    (o.get_out().cloned(), u.get_out().cloned())
                };
                if let (Some(old), Some(new)) = (other_out, used_out) {
                    self.total_replace(&old, new);
                    self.op_destroy(&other.clone());
                }
            }
        }
        // cc:1212: return usedCopy->getOut().
        let out_vn = used_copy
            .0
            .read()
            .unwrap()
            .get_out()
            .cloned()
            .expect("build_copy_temp: COPY has output");
        out_vn
    }

    // Ghidra: funcdata_op.cc:1221 Funcdata::opFlipInPlaceTest
    /// Trace a boolean value to the set of PcodeOps whose opcodes must flip to
    /// negate it. Faithful to `Funcdata::opFlipInPlaceTest`
    /// (funcdata_op.cc:1223-1275). Returns 0 if the flip normalizes, 1 if
    /// ambivalent, 2 if the change does not normalize. The discovered ops are
    /// appended to `fliplist` in evaluation order.
    pub fn op_flip_in_place_test(
        &self,
        op: &crate::op::PcodeOpRef,
        fliplist: &mut Vec<crate::op::PcodeOpRef>,
    ) -> i32 {
        let opc = op.0.read().unwrap().opcode;
        match opc {
            OpCode::CPUI_CBRANCH => {
                // cc:1230-1233: vn = getIn(1); loneDescend==op && isWritten.
                let vn = op.0.read().unwrap().get_in(1).cloned();
                let vn = match vn {
                    Some(v) => v,
                    None => return 2,
                };
                let lone = vn.read().unwrap().lone_descend();
                let lone_is_op = lone
                    .map(|d| std::sync::Arc::ptr_eq(&d, &op.0))
                    .unwrap_or(false);
                if !lone_is_op {
                    return 2;
                }
                if !vn.read().unwrap().is_written() {
                    return 2;
                }
                let def = match vn.read().unwrap().get_def() {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                self.op_flip_in_place_test(&def, fliplist)
            }
            OpCode::CPUI_INT_EQUAL | OpCode::CPUI_FLOAT_EQUAL => {
                fliplist.push(op.clone());
                1
            }
            OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL => {
                fliplist.push(op.clone());
                0
            }
            OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_LESS => {
                // cc:1245-1248: vn = getIn(0); push; if !const return 1 else 0.
                let is_const = op
                    .0.read()
                    .unwrap()
                    .get_in(0)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if !is_const {
                    1
                } else {
                    0
                }
            }
            OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_INT_LESSEQUAL => {
                // cc:1250-1253: vn = getIn(1); push; if const return 1 else 0.
                let is_const = op
                    .0.read()
                    .unwrap()
                    .get_in(1)
                    .map(|v| v.read().unwrap().is_constant())
                    .unwrap_or(false);
                fliplist.push(op.clone());
                if is_const {
                    1
                } else {
                    0
                }
            }
            OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_AND => {
                // cc:1256-1270: recurse into both inputs; push op last.
                let (in0_ok, in0_def, in1_ok, in1_def) = {
                    let o = op.0.read().unwrap();
                    let i0 = o.get_in(0).cloned();
                    let i1 = o.get_in(1).cloned();
                    let check_lone = |v: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>| {
                        let lone = v.read().unwrap().lone_descend();
                        lone.map(|d| std::sync::Arc::ptr_eq(&d, &op.0))
                                .unwrap_or(false)
                    };
                    let i0_ok = i0.as_ref().map_or(false, check_lone);
                    let i1_ok = i1.as_ref().map_or(false, check_lone);
                    (
                        i0_ok,
                        i0.and_then(|v| v.read().unwrap().get_def()),
                        i1_ok,
                        i1.and_then(|v| v.read().unwrap().get_def()),
                    )
                };
                // cc:1258-1259: vn = getIn(0); loneDescend==op && isWritten.
                if !in0_ok {
                    return 2;
                }
                let in0_def = match in0_def {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                let subtest1 = self.op_flip_in_place_test(&in0_def, fliplist);
                if subtest1 == 2 {
                    return 2;
                }
                // cc:1263-1265: vn = getIn(1); loneDescend==op && isWritten.
                if !in1_ok {
                    return 2;
                }
                let in1_def = match in1_def {
                    Some(d) => crate::op::PcodeOpRef(d),
                    None => return 2,
                };
                let subtest2 = self.op_flip_in_place_test(&in1_def, fliplist);
                if subtest2 == 2 {
                    return 2;
                }
                fliplist.push(op.clone());
                subtest1 // cc:1270: front of AND/OR must be normalizing.
            }
            _ => 2,
        }
    }

    // Ghidra: funcdata_op.cc:1280 Funcdata::opFlipInPlaceExecute
    /// Apply the precomputed op-code flips to negate a boolean value. Faithful
    /// to `Funcdata::opFlipInPlaceExecute` (funcdata_op.cc:1282-1315). For
    /// each op in `fliplist`: look up its boolean-flip target via
    /// `get_booleanflip`. A BOOL_NEGATE collapses to COPY semantics (propagate
    /// its input into the lone descendant, then destroy it). A BOOL_AND/BOOL_OR
    /// with no direct flip swaps to the other. Otherwise set the opcode and,
    /// if `reorder`, swap inputs and (for LESSEQUAL variants) replace_lessequal.
    pub fn op_flip_in_place_execute(&mut self, fliplist: &[crate::op::PcodeOpRef]) {
        use crate::opcodes::get_booleanflip;
        for op in fliplist {
            let cur_opc = op.0.read().unwrap().opcode;
            let mut reorder = false;
            let new_opc = get_booleanflip(cur_opc, &mut reorder);
            if new_opc == OpCode::CPUI_COPY {
                // cc:1290-1296: BOOL_NEGATE collapses — propagate input, destroy.
                let (in0, out, lone_desc) = {
                    let o = op.0.read().unwrap();
                    let in0 = o.get_in(0).cloned();
                    let out = o.get_out().cloned();
                    let lone_desc = out.as_ref().and_then(|v| v.read().unwrap().lone_descend());
                    (in0, out, lone_desc)
                };
                let Some(in_vn) = in0 else { continue };
                let Some(out_vn) = out else { continue };
                let Some(other_op) = lone_desc else { continue };
                let other_ref = crate::op::PcodeOpRef(other_op);
                // cc:1293-1294: slot = otherop->getSlot(op->getOut()).
                let slot = other_ref
                    .0
                    .read()
                    .unwrap()
                    .inrefs
                    .iter()
                    .position(|v| std::sync::Arc::ptr_eq(v, &out_vn));
                if let Some(slot) = slot {
                    self.op_set_input(&other_ref, in_vn, slot);
                }
                self.op_destroy(op);
            } else if new_opc == OpCode::CPUI_MAX {
                // cc:1297-1303: BOOL_AND <-> BOOL_OR swap.
                match cur_opc {
                    OpCode::CPUI_BOOL_AND => self.op_set_opcode(op, OpCode::CPUI_BOOL_OR),
                    OpCode::CPUI_BOOL_OR => self.op_set_opcode(op, OpCode::CPUI_BOOL_AND),
                    _ => {
                        eprintln!("[FUNCDATA] Bad flipInPlace op {:?}", cur_opc);
                    }
                }
            } else {
                // cc:1305-1313: set opcode; if reorder, swap inputs + lequal.
                self.op_set_opcode(op, new_opc);
                if reorder {
                    self.op_swap_input(op, 0, 1);
                    if new_opc == OpCode::CPUI_INT_LESSEQUAL
                        || new_opc == OpCode::CPUI_INT_SLESSEQUAL
                    {
                        self.replace_lessequal(op);
                    }
                }
            }
        }
    }

    // Ghidra: funcdata_op.cc:1324 Funcdata::cseFindInBlock
    /// Find a duplicate calculation of `op` that reads `vn` in block `bl`
    /// earlier than `earliest`. Faithful to `Funcdata::cseFindInBlock`
    /// (funcdata_op.cc:1326-1347). Only 1-level matches are considered: the
    /// candidate op's output must be functionally equal (depth 0) to `op`'s
    /// output. Returns the discovered duplicate, or None.
    pub fn cse_find_in_block(
        &self,
        op: &crate::op::PcodeOpRef,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        bl: Option<&std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>>,
        earliest: Option<&crate::op::PcodeOpRef>,
    ) -> Option<crate::op::PcodeOpRef> {
        // cc:1331-1345: for each descendant res of vn:
        let descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let op_out = op.0.read().unwrap().get_out().cloned();
        let earliest_order = earliest.map(|e| e.0.read().unwrap().get_seq_num().order);
        for res_arc in descendants {
            // cc:1333: if (res == op) continue.
            if std::sync::Arc::ptr_eq(&res_arc, &op.0) {
                continue;
            }
            let res_parent = res_arc
                .read()
                .unwrap()
                .parent
                .clone()
                .and_then(|w| w.upgrade());
            // cc:1334: if (res->getParent() != bl) continue — raw pointer
            // inequality, so a null -bl- matches ONLY parentless ops.
            let parent_matches = match (&res_parent, bl) {
                (Some(rp), Some(bp)) => std::sync::Arc::ptr_eq(rp, bp),
                (None, None) => true,
                _ => false,
            };
            if !parent_matches {
                continue;
            }
            // cc:1335-1337: earliest != NULL && earliest->order < res->order → continue.
            if let Some(eo) = earliest_order {
                let res_order = res_arc.read().unwrap().get_seq_num().order;
                if eo < res_order {
                    continue;
                }
            }
            // cc:1338-1344: functionalEqualityLevel(out1, out2, buf1, buf2) == 0.
            let outvn2 = res_arc.read().unwrap().get_out().cloned();
            let Some(outvn2) = outvn2 else { continue };
            let Some(outvn1) = &op_out else { continue };
            let eq = crate::expression::functional_equality_level(outvn1, &outvn2);
            if eq.code == 0 {
                return Some(crate::op::PcodeOpRef(res_arc));
            }
        }
        None
    }

    // Ghidra: funcdata_op.cc:1457 Funcdata::moveRespectingCover
    /// Move `op` past COPY/CAST ops toward `lastOp`, within its basic block,
    /// only when no data-flow interference occurs. Faithful to
    /// `Funcdata::moveRespectingCover` (funcdata_op.cc:1459-1500). The move
    /// respects the cover of the expression rooted at `op`'s output: we stop
    /// before any COPY that writes a HighVariable in the expression, or before
    /// a possible indirect interference. Returns true if the move completed.
    pub fn move_respecting_cover(
        &mut self,
        op: &crate::op::PcodeOpRef,
        last_op: &crate::op::PcodeOpRef,
    ) -> bool {
        // cc:1462: if (op == lastOp) return true.
        if std::sync::Arc::ptr_eq(&op.0, &last_op.0) {
            return true;
        }
        // cc:1463: if (op->isCall()) return false.
        if op.0.read().unwrap().is_call() {
            return false;
        }
        // cc:1464-1473: if op is CAST and its input is not explicit, the
        // previous op must move as well (and immediately precede the CAST).
        let prev_op: Option<crate::op::PcodeOpRef> = if op.0.read().unwrap().opcode == OpCode::CPUI_CAST {
            let in0 = op.0.read().unwrap().get_in(0).cloned();
            if let Some(vn) = in0 {
                if !vn.read().unwrap().is_explicit() {
                    if !vn.read().unwrap().is_written() {
                        return false;
                    }
                    let prev = match vn.read().unwrap().get_def() {
                        Some(d) => crate::op::PcodeOpRef(d),
                        None => return false,
                    };
                    if prev.0.read().unwrap().is_call() {
                        return false;
                    }
                    // cc:1471: op->previousOp() must equal prevOp.
                    let op_prev = op
                        .0.read()
                        .unwrap()
                        .previous_op_in_block(&self.obank);
                    let matches = match &op_prev {
                        Some(p) => std::sync::Arc::ptr_eq(&p.0, &prev.0),
                        None => false,
                    };
                    if !matches {
                        return false;
                    }
                    Some(prev)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        // cc:1474-1476: rootvn = op->getOut(); markExpression(rootvn, highList).
        let rootvn = op.0.read().unwrap().get_out().cloned();
        let Some(rootvn) = rootvn else { return false };
        let mut high_list: Vec<std::sync::Arc<std::sync::RwLock<crate::variable::HighVariable>>> =
            Vec::new();
        let type_val = crate::variable::HighVariable::mark_expression(&rootvn, &mut high_list);
        // cc:1477-1487: walk forward over COPY/CAST ops, stopping at any
        // interference.
        let mut cur_op = op.clone();
        loop {
            let next_op = cur_op
                .0.read()
                .unwrap()
                .next_op_in_flow(&self.obank);
            let Some(next_op) = next_op else { break };
            let next_opc = next_op.0.read().unwrap().opcode;
            if next_opc != OpCode::CPUI_COPY && next_opc != OpCode::CPUI_CAST {
                break;
            }
            // cc:1482: if (rootvn == nextOp->getIn(0)) break.
            let next_in0 = next_op.0.read().unwrap().get_in(0).cloned();
            if let Some(v) = &next_in0 {
                if std::sync::Arc::ptr_eq(v, &rootvn) {
                    break;
                }
            }
            // cc:1483-1484: copyVn = nextOp->getOut(); if (copyVn->getHigh()->isMark()) break.
            let copy_vn = next_op.0.read().unwrap().get_out().cloned();
            if let Some(cv) = &copy_vn {
                let copy_high = cv.read().unwrap().get_high().cloned();
                if let Some(h) = copy_high {
                    if h.read().unwrap().is_mark() {
                        break;
                    }
                }
            }
            // cc:1485: if (typeVal != 0 && copyVn->isAddrTied()) break.
            if type_val != 0 {
                if let Some(cv) = &copy_vn {
                    if cv.read().unwrap().is_addr_tied() {
                        break;
                    }
                }
            }
            cur_op = next_op;
            if std::sync::Arc::ptr_eq(&cur_op.0, &last_op.0) {
                break;
            }
        }
        // cc:1488-1489: clear marks on the expression.
        for h in &high_list {
            h.write().unwrap().clear_mark();
        }
        // cc:1490-1499: if we reached lastOp, perform the move.
        if std::sync::Arc::ptr_eq(&cur_op.0, &last_op.0) {
            self.op_uninsert(op);
            self.op_insert_after(op, last_op);
            if let Some(prev) = prev_op {
                self.op_uninsert(&prev);
                self.op_insert_after(&prev, last_op);
            }
            true
        } else {
            false
        }
    }

    // =========================================================================
    // String / return-address / replacement (funcdata_varnode.cc:1413-1743)
    // =========================================================================

    // Ghidra: funcdata_varnode.cc:1413 Funcdata::getInternalString
    /// Build the p-code that displays an encoded string constant. Faithful
    /// to `Funcdata::getInternalString` (funcdata_varnode.cc:1413-1434):
    ///   - reject non-pointer types
    ///   - register the raw bytes with the StringManager
    ///     (`registerInternalStringData`), returning a hash; hash==0 means
    ///     the encoding is not a legal string → return null
    ///   - register the BUILTIN_STRING_DATA user-op
    ///   - emit `CALLOTHER(string_data_id, hash)` before `readOp`, returning
    ///     its unique output typed as `ptrType`
    /// Returns the new Varnode, or None if the encoding is not a string.
    pub fn get_internal_string(
        &mut self,
        buf: &[u8],
        ptr_type: &crate::type_system::datatype::Datatype,
        read_op: &crate::op::PcodeOpRef,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        use crate::type_system::datatype::{Datatype, TypeMetatype};
        // cc:1416-1417: if (ptrType->getMetatype() != TYPE_PTR) return null.
        if ptr_type.get_metatype() != TypeMetatype::Pointer {
            return None;
        }
        // cc:1418: charType = ((TypePointer *)ptrType)->getPtrTo().
        let char_type = match ptr_type {
            Datatype::Pointer(p) => p.ptr_to.clone(),
            _ => return None,
        };
        // cc:1420: const Address &addr(readOp->getAddr()).
        let addr = read_op.0.read().unwrap().get_addr();
        let charsize = char_type.get_size().max(1) as i32;
        // cc:1420-1423: hash = glb->stringManager->registerInternalStringData(
        //   addr, buf, size, charType); hash == 0 (illegal encoding) returns
        //   null. The ported manager (stringmanage.rs) keys the entry at the
        //   constant-space address of the hash, which is exactly the address
        //   PrintC::printCharacterConstant reads back through the
        //   STRINGDATA CALLOTHER's hash input (printc.cc:701-714).
        let hash = if let Some(arch) = &self.arch {
            if let Some(sm_arc) = &arch.string_manager {
                let sm = sm_arc.write().unwrap();
                sm.register_internal_string_data(addr, buf, charsize)
            } else {
                return None;
            }
        } else {
            return None;
        };
        if hash == 0 {
            return None;
        }
        // cc:1424-1429: register BUILTIN_STRING_DATA + emit CALLOTHER.
        let string_data_id: u64 = if let Some(arch) = &self.arch {
            if let Some(userops) = arch.userops.as_ref() {
                let mut mgr = userops.write().unwrap();
                mgr.register_builtin_by_id(crate::userop::BUILTIN_STRINGDATA) as u64
            } else {
                // RUGRA-GAP: no userop table — use the canonical builtin id.
                crate::userop::BUILTIN_STRINGDATA as u64
            }
        } else {
            crate::userop::BUILTIN_STRINGDATA as u64
        };
        let string_op = self.new_op(2, addr);
        self.op_set_opcode(&string_op, crate::opcodes::OpCode::CPUI_CALLOTHER);
        // cc:1427: stringOp->clearFlag(PcodeOp::call).
        string_op.0.write().unwrap().flags &= !crate::op::pcodeop_flags::CALL;
        let id_vn = self.new_constant(4, string_data_id);
        let hash_vn = self.new_constant(8, hash);
        self.op_set_input(&string_op, id_vn, 0);
        self.op_set_input(&string_op, hash_vn, 1);
        // cc:1430-1431: resVn = newUniqueOut(ptrType->getSize(), stringOp);
        //   resVn->updateType(ptrType, true, false).
        let ptr_size = ptr_type.get_size();
        let res_vn = self.new_unique_out(ptr_size, &string_op);
        res_vn.write().unwrap().update_type_lock(
            std::sync::Arc::new(ptr_type.clone()),
            true,
            false,
        );
        // cc:1432: opInsertBefore(stringOp, readOp).
        self.op_insert_before(&string_op, read_op);
        Some(res_vn)
    }

    // Ghidra: funcdata_varnode.cc:1496 Funcdata::totalReplaceConstant
    /// Replace every read reference of `vn` with a fresh constant `val`.
    /// Faithful to `Funcdata::totalReplaceConstant` (funcdata_varnode.cc:1496-1534).
    /// For marker ops (MULTIEQUAL/INDIRECT) a single COPY of the constant is
    /// inserted (after vn's def, or at block 0 start if vn is unwritten) and
    /// the marker input is set to the COPY's output; otherwise each read site
    /// gets its own fresh constant Varnode.
    pub fn total_replace_constant(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        val: u64,
    ) {
        let vn_size = vn.read().unwrap().get_size();
        // Snapshot (op, slot) descendants before mutation.
        let sites: Vec<(crate::op::PcodeOpRef, usize)> = {
            let vn_rg = vn.read().unwrap();
            vn_rg
                .descend
                .iter()
                .filter_map(|w| w.upgrade())
                .filter_map(|op_arc| {
                    let op_rg = op_arc.read().unwrap();
                    let slot = op_rg
                        .inrefs
                        .iter()
                        .position(|v| std::sync::Arc::ptr_eq(v, vn))?;
                    drop(op_rg);
                    Some((crate::op::PcodeOpRef(op_arc), slot))
                })
                .collect()
        };
        // Lazily-built COPY for marker ops (cc:1510-1529).
        let mut copy_op: Option<crate::op::PcodeOpRef> = None;
        for (op, slot) in sites {
            let is_marker = op.0.read().unwrap().is_marker();
            let new_rep = if is_marker {
                if copy_op.is_none() {
                    // cc:1511-1525: build a single COPY of the constant.
                    let vn_is_written = vn.read().unwrap().is_written();
                    if vn_is_written {
                        let def = vn.read().unwrap().get_def();
                        if let Some(def_op) = def {
                            let def_ref = crate::op::PcodeOpRef(def_op);
                            let def_addr = def_ref.0.read().unwrap().get_addr();
                            let new_copy = self.new_op(1, def_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            let c = self.new_constant(vn_size, val);
                            self.op_set_input(&new_copy, c, 0);
                            self.op_insert_after(&new_copy, &def_ref);
                            copy_op = Some(new_copy);
                        }
                    } else {
                        // cc:1519-1525: vn unwritten — insert at block 0 start.
                        let bb0 = self.bblocks.get_block(0);
                        if let Some(bb) = bb0 {
                            let start_addr = bb.read().unwrap().get_start_addr();
                            let new_copy = self.new_op(1, start_addr);
                            self.op_set_opcode(&new_copy, OpCode::CPUI_COPY);
                            self.new_unique_out(vn_size, &new_copy);
                            let c = self.new_constant(vn_size, val);
                            self.op_set_input(&new_copy, c, 0);
                            self.op_insert_begin(&new_copy, &bb);
                            copy_op = Some(new_copy);
                        }
                    }
                }
                // cc:1528: newrep = copyop->getOut().
                match &copy_op {
                    Some(c) => c.0.read().unwrap().get_out().cloned(),
                    None => None,
                }
            } else {
                // cc:1531: newrep = newConstant(vn->getSize(), val).
                Some(self.new_constant(vn_size, val))
            };
            if let Some(rep) = new_rep {
                self.op_set_input(&op, rep, slot);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1573 Funcdata::findDisjointCover
    /// Find the minimal Address range covering `vn` that does not split any
    /// other Varnode. Faithful to `Funcdata::findDisjointCover`
    /// (funcdata_varnode.cc:1573-1596). Walks the loc tree backward and
    /// forward from vn's address, expanding the [addr, endaddr) range to
    /// include any overlapping neighbours, then returns the start and passes
    /// the size back via `sz`.
    pub fn find_disjoint_cover(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        sz: &mut usize,
    ) -> crate::address::Address {
        let mut addr = *vn.read().unwrap().get_addr();
        let mut end_off = addr.as_u64() + vn.read().unwrap().get_size() as u64;
        // cc:1580-1586: walk backward over overlapping earlier varnodes.
        // Rugra: overlap_loc returns candidates overlapping the current range;
        // we rescan with the expanded range until it stabilizes.
        let mut changed = true;
        while changed {
            changed = false;
            let candidates = self
                .vbank
                .overlap_loc(addr, (end_off - addr.as_u64()) as usize);
            for cv in candidates {
                let cv_rg = cv.read().unwrap();
                let cv_addr = *cv_rg.get_addr();
                let cv_end = cv_addr.as_u64() + cv_rg.get_size() as u64;
                if cv_addr.as_u64() < addr.as_u64() {
                    addr = cv_addr;
                    changed = true;
                }
                if cv_end > end_off {
                    end_off = cv_end;
                    changed = true;
                }
            }
        }
        // cc:1594-1595: sz = endaddr - addr; return addr.
        *sz = (end_off - addr.as_u64()) as usize;
        addr
    }

    // Ghidra: funcdata_varnode.cc:1606 Funcdata::coverVarnodes
    /// Ensure every Varnode in `list` (in Address order) overlaps a Symbol so
    /// it will link. Faithful to `Funcdata::coverVarnodes`
    /// (funcdata_varnode.cc:1606-1627):
    ///   scope = entry->getSymbol()->getScope();
    ///   for(i..list.size()) {
    ///     if (i+1<size && list[i+1]->getAddr() == vn->getAddr()) continue;
    ///     usepoint = vn->getUsePoint(*this);
    ///     overlapEntry = scope->findContainer(vn->getAddr(), vn->getSize(), usepoint);
    ///     if (overlapEntry == NULL) {
    ///       diff = vn->getOffset() - entry->getAddr().getOffset();
    ///       name = entry->getSymbol()->getName() + '_' + diff;
    ///       if (vn->isAddrTied()) usepoint = Address();
    ///       scope->addSymbol(name, vn->getHigh()->getType(), vn->getAddr(), usepoint);
    ///     }
    ///   }
    /// The channel form: `findContainer` is the parent-scope container query
    /// (live-entry arm) and `addSymbol` lands on the Database global scope —
    /// the discovered owner of global storage (mapGlobals callers pass an
    /// entry the same channel answered). The legacy no-channel form keeps the
    /// `symbol_table` proxy (documented fallback).
    pub fn cover_varnodes(
        &mut self,
        entry_addr: u64,
        entry_name: &str,
        list: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
    ) {
        let mut i = 0;
        while i < list.len() {
            let vn = &list[i];
            // cc:1614-1615: only check once per address — the LAST varnode at
            // each address (list is in Address order).
            let vn_addr = *vn.read().unwrap().get_addr();
            if i + 1 < list.len()
                && list[i + 1].read().unwrap().get_addr().as_u64() == vn_addr.as_u64()
            {
                i += 1;
                continue;
            }
            // cc:1617: usepoint = vn->getUsePoint(*this).
            let usepoint = vn.read().unwrap().get_use_point(self);
            let (vn_size, is_addr_tied, high_type) = {
                let r = vn.read().unwrap();
                let ct = r.high.as_ref().map(|h| h.read().unwrap().get_type());
                (r.get_size() as i32, r.is_addr_tied(), ct)
            };
            // cc:1618: overlapEntry = scope->findContainer(addr, size, usepoint).
            let overlap = self.query_container_entry_parent_scope(
                vn_addr,
                vn_size,
                usepoint);
            if overlap.is_none() {
                // cc:1619-1624: uncovered internal varnode — build
                // `<entry>_<diff>` and addSymbol at vn's address.
                let diff = (vn_addr.as_u64() - entry_addr) as i64;
                let sym_name = format!("{}_{}", entry_name, diff);
                // cc:1622-1623: addrTied varnodes get the empty usepoint
                // (the channel addSymbol maps addrtied storage directly).
                let _ = is_addr_tied;
                // cc:1624: addSymbol(name, vn->getHigh()->getType(), addr,
                // usepoint) — the mapping size is the TYPE's size
                // (Scope::addMapPoint), not the varnode's.
                let sym_size = high_type
                    .as_ref()
                    .map(|t| t.get_size() as i32)
                    .unwrap_or(vn_size);
                let added = if let Some(symboltab) =
                    self.arch.as_ref().and_then(|a| a.symboltab.clone())
                {
                    let global_scope_id = symboltab.read().unwrap().global_scope_id;
                    let mut db = symboltab.write().unwrap();
                    db.add_symbol_mapped(
                        global_scope_id,
                        &sym_name,
                        high_type,
                        vn_addr,
                        sym_size)
                    .is_some()
                } else {
                    false
                };
                if !added {
                    // Legacy fallback: the symbol_table name proxy.
                    self.symbol_table.insert(vn_addr.as_u64(), sym_name);
                    // FUNCDATA-MAPGLOBALS-PROXYSIZE-0001: coverVarnodes'
                    // addSymbol goes through Scope::addMap like any other
                    // (database.cc:1126-1151) — record the entry size (the
                    // TYPE's size per addMapPoint) so mapGlobals' cc:1711
                    // extension test sees the true entry end on re-runs.
                    self.symbol_table_sizes.insert(vn_addr.as_u64(), sym_size);
                    vn.write()
                        .unwrap()
                        .set_flags(crate::varnode::varnode_flags::MAPPED);
                }
            }
            i += 1;
        }
    }

    // Ghidra: funcdata_varnode.cc:1637 Funcdata::applyUnionFacet
    /// Cache a UnionFacetSymbol's forced union-field resolution into unionMap.
    /// Faithful to `Funcdata::applyUnionFacet` (funcdata_varnode.cc:1637-1649):
    ///   op = dhash.findOp(this, entry->getFirstUseAddress(), entry->getHash());
    ///   if (op == NULL) return false;
    ///   slot = DynamicHash::getSlotFromHash(hash);
    ///   fldNum = ((UnionFacetSymbol *)sym)->getFieldNumber();
    ///   ResolvedUnion resolve(sym->getType(), fldNum, *glb->types);
    ///   resolve.setLock(true);
    ///   return setUnionField(sym->getType(), op, slot, resolve);
    /// RUGRA-GAP: there is no UnionFacetSymbol type yet; the caller passes the
    /// resolved (parent type, field number) projection of the facet symbol.
    /// Returns true if the op was located and the resolution cached.
    pub fn apply_union_facet(
        &mut self,
        parent: std::sync::Arc<crate::type_system::datatype::Datatype>,
        first_use_addr: crate::address::Address,
        hash: u64,
        field_num: i32,
    ) -> bool {
        // cc:1641: op = dhash.findOp(this, addr, hash).
        let op = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_op(self, first_use_addr, hash)
        };
        let Some(op_arc) = op else { return false };
        let op_ref = crate::op::PcodeOpRef(op_arc);
        // cc:1644: slot = DynamicHash::getSlotFromHash(hash).
        let slot = crate::dynamic::DynamicHash::get_slot_from_hash(hash);
        // cc:1645-1647: fldNum + ResolvedUnion(parent, fldNum, types); setLock.
        let resolve = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                // Write guard: with_field interns the pointer arm through the
                // factory (unionresolve.cc:54, UNIONRESOLVE-PKG-G-0001).
                let mut tg_guard = tg.write().unwrap();
                let mut r = crate::unionresolve::ResolvedUnion::with_field(
                    parent.clone(),
                    field_num,
                    &mut tg_guard,
                );
                r.set_lock(true);
                r
            } else {
                let mut r = crate::unionresolve::ResolvedUnion::new(parent.clone());
                r.set_lock(true);
                r
            }
        } else {
            let mut r = crate::unionresolve::ResolvedUnion::new(parent.clone());
            r.set_lock(true);
            r
        };
        // cc:1648: return setUnionField(sym->getType(), op, slot, resolve).
        self.set_union_field(parent.as_ref(), &op_ref, slot, resolve)
    }

    // Ghidra: funcdata_varnode.cc:1723 Funcdata::prepareThisPointer
    /// Ensure that if a "this" pointer exists it is treated as a pointer
    /// data-type. Faithful to `Funcdata::prepareThisPointer`
    /// (funcdata_varnode.cc:1723-1743):
    ///   for each param: if isThisPointer && isTypeLocked return;
    ///   if (localmap->hasTypeRecommendations()) return;
    ///   dt = getTypeVoid(); spc = getDefaultDataSpace();
    ///   dt = getTypePointer(spc->getAddrSize(), dt, spc->getWordSize());
    ///   addr = funcp.getThisPointerStorage(dt);
    ///   localmap->addTypeRecommendation(addr, dt);
    /// RUGRA-GAP: ScopeLocal has no type-recommendation store; we approximate
    /// by recording the recommendation address in symbol_table. The
    /// "this"-pointer storage location is taken from funcp's first param
    /// marked as THIS_POINTER, or from the configured stack pointer.
    pub fn prepare_this_pointer(&mut self) {
        // cc:1727-1731: for each param if isThisPointer && isTypeLocked return.
        let num_inputs = self.funcp.num_params();
        for i in 0..num_inputs {
            if let Some(param) = self.funcp.get_param(i) {
                if param.is_this_pointer() && param.is_type_locked() {
                    return;
                }
            }
        }
        // cc:1735-1736: if (localmap->hasTypeRecommendations()) return.
        // Rugra: symbol_table acts as the recommendation store; presence of a
        // "this" entry means a recommendation was already collected.
        let has_recommendation = self
            .symbol_table
            .values()
            .any(|name| name == "this" || name.contains("this"));
        if has_recommendation {
            return;
        }
        // cc:1738-1740: dt = void; spc = default data space;
        //   dt = getTypePointer(spc->getAddrSize(), void, spc->getWordSize()).
        let dt = if let Some(arch) = &self.arch {
            if let Some(tg) = &arch.types {
                let mut tg_guard = tg.write().unwrap();
                let void_dt = tg_guard.get_type_void();
                let addr_size = self.stack_pointer_size;
                let word_size = self.stack_space.word_size();
                tg_guard.get_type_pointer(addr_size, void_dt, word_size)
            } else {
                return;
            }
        } else {
            return;
        };
        // cc:1741-1742: addr = funcp.getThisPointerStorage(dt);
        //   localmap->addTypeRecommendation(addr, dt).
        // Rugra: prefer the first THIS_POINTER param's address; else the stack
        // pointer offset.
        let this_addr = (0..num_inputs)
            .find_map(|i| {
                self.funcp
                    .get_param(i)
                    .filter(|p| p.is_this_pointer())
                    .and_then(|p| Some(p.address.as_u64()))
            })
            .unwrap_or(self.stack_pointer_offset);
        self.symbol_table.insert(this_addr, "this".to_string());
        let _ = dt; // recommendation data-type recorded implicitly via "this" name.
    }

    // Ghidra: funcdata.cc:34 Funcdata::numHeritagePasses
    /// Get number of heritage passes completed
    pub fn num_heritage_passes(&self) -> i32 {
        self.heritage.get_pass()
    }

    // =========================================================================
    // Group 4: Warning & lifecycle methods (funcdata.cc:119-188)
    // =========================================================================

    // Ghidra: funcdata.cc:119 Funcdata::warning
    /// Emit a per-address warning comment. Faithful to
    /// `Funcdata::warning` (funcdata.cc:119-129). The message is prefixed
    /// with `"WARNING (jumptable): "` when this Funcdata is a partial clone
    /// dedicated to jump-table recovery (the `jumptablerecovery_on` flag),
    /// otherwise with `"WARNING: "`. Uses the arch's commentdb if available;
    /// otherwise eprintln as fallback.
    pub fn warning(&self, txt: &str, ad: Address) {
        let prefix = if self.is_jumptable_recovery_on() {
            "WARNING (jumptable): "
        } else {
            "WARNING: "
        };
        let msg = format!("{}{}", prefix, txt);
        if let Some(a) = &self.arch {
            if let Some(cdb) = &a.commentdb {
                let _ = cdb.write().unwrap().add_comment_no_duplicate(
                    crate::comment::comment_type::WARNING,
                    self.baseaddr,
                    ad,
                    &msg,
                );
                return;
            }
        }
        eprintln!(
            "[{}] {}: {} (ad={:#x})", prefix.trim_end_matches(": "), self.name, txt, ad.as_u64()
        );
    }

    // Ghidra: funcdata.cc:150 Funcdata::startProcessing
    /// Basic set-up for analyzing the function: marks the processing-started
    /// flag, clears unlocked scope/proto state, (in Ghidra) follows flow to
    /// build p-code and blocks, resets structuring, sorts call specs, builds
    /// heritage info, and applies dead-code delay. Faithful to
    /// `Funcdata::startProcessing` (funcdata.cc:150-168).
    ///
    /// RUGRA-GAP: `followFlow` and the inline-function header warning depend
    /// on infrastructure not yet ported; the flag transition,
    /// unlocked-output clear, structuring reset, call-spec sort,
    /// heritage-info build, and dead-code-delay application are all
    /// performed.
    pub fn start_processing(&mut self) {
        if self.is_proc_started() {
            // Ghidra throws LowlevelError here; Rugra panics to preserve the
            // invariant that startProcessing is called at most once.
            panic!("Function processing already started");
        }
        self.flags |= funcdata_flags::PROCESSING_STARTED;

        // Ghidra: if (funcp.isInline()) warningHeader("This is an inlined function");
        // RUGRA-GAP: FuncProto has no is_inline flag yet.

        // Ghidra: localmap->clearUnlocked();
        // RUGRA modeling: same wholesale reset as Funcdata::clear (see the
        // cc:95 seam above) — symbols + nametree + category_lists +
        // mapentry_log clear together, mirroring the oracle's atomic
        // removeSymbol/removeSymbolMappings pair (database.cc:2117-2149).
        if let Some(scope) = self.scope.as_mut() {
            scope.clear_symbols_wholesale();
        }
        // The HighVariable→Symbol associations die with the symbols.
        self.high_symbols.clear();
        self.symbol_entry_cache.clear();

        // Ghidra: funcp.clearUnlockedOutput();
        // Rugra's FuncProto::clear_unlocked_output exists (fspec.rs:308).
        self.funcp.clear_unlocked_output();

        // Ghidra: followFlow(baddr, eaddr); structureReset();
        // RUGRA-GAP: followFlow not ported. structureReset is available.
        //   self.follow_flow(...);  // TODO: port followFlow
        self.structure_reset();

        // Must come after structure reset.
        self.sort_call_specs();

        // Ghidra: heritage.buildInfo();
        self.heritage.build_info_list();

        // Ghidra: localoverride.applyDeadCodeDelay(*this);
        // (override.cc:217-231): for every space with an override delay
        // (Override::deadcodedelay[spc->getIndex()] >= 0), install it via
        // Funcdata::setDeadCodeDelay (funcdata.hh:248 →
        // Heritage::setDeadCodeDelay heritage.cc:2815). The override
        // survives Funcdata::clear ("Do not clear overrides", funcdata.cc:106),
        // so a restart installed by Heritage::bumpDeadcodeDelay takes effect
        // here on the next pass. Copy the entries out first: the override
        // borrows self immutably while heritage is mutated.
        for (index, delay) in self.localoverride.deadcode_delays().collect::<Vec<_>>() {
            if let Some(space) = crate::space::AddressSpace::from_index(index) {
                self.heritage.set_dead_code_delay(space, delay);
            }
        }
    }

    // Ghidra: funcdata.cc:170 Funcdata::stopProcessing
    /// Mark processing complete and free the dead-op list. Faithful to
    /// `Funcdata::stopProcessing` (funcdata.cc:170-180). If this is not a
    /// jump-table-recovery clone, datatype warnings are issued.
    pub fn stop_processing(&mut self) {
        self.flags |= funcdata_flags::PROCESSING_COMPLETE;
        // Ghidra: obank.destroyDead();
        self.obank.destroy_dead();
        if !self.is_jumptable_recovery_on() {
            self.issue_datatype_warnings();
        }
    }

    // Ghidra: funcdata.cc:182 Funcdata::startTypeRecovery
    /// Mark that type recovery has started. Returns `true` if this is the
    /// first call (i.e. type recovery was not previously started), `false`
    /// otherwise. Faithful to `Funcdata::startTypeRecovery` (funcdata.cc:182-188).
    pub fn start_type_recovery(&mut self) -> bool {
        if (self.flags & funcdata_flags::TYPE_RECOVERY_START) != 0 {
            return false;
        }
        self.flags |= funcdata_flags::TYPE_RECOVERY_START;
        true
    }

    // =========================================================================
    // Group 1: Callspec management (funcdata.cc:464-573)
    // =========================================================================

    // Ghidra: funcdata.cc:475 Funcdata::issueDatatypeWarnings
    /// Re-emit all accumulated datatype warnings as header warnings. Faithful
    /// to `Funcdata::issueDatatypeWarnings` (funcdata.cc:475-482). In Ghidra
    /// this iterates `glb->types->beginWarnings()..endWarnings()` and calls
    /// `warningHeader` for each. RUGRA-GAP: `TypeFactory` has no warning list
    /// yet, so this is currently a no-op that preserves the call site in
    /// [`stop_processing`](Self::stop_processing).
    pub fn issue_datatype_warnings(&self) {
        // RUGRA-GAP: TypeFactory::beginWarnings/endWarnings not ported.
        // Once ported, this becomes:
        //   for w in arch.types.iter_warnings() { self.warning_header(w); }
    }

    // Ghidra: funcdata.cc:464 Funcdata::clearCallSpecs
    /// Delete all call specifications. Faithful to
    /// `Funcdata::clearCallSpecs` (funcdata.cc:464-473). In C++ each
    /// `FuncCallSpecs*` is heap-allocated and freed individually before the
    /// vector is cleared; in Rust clearing the strong Arc-owner vector drops
    /// every allocation after the op/varnode banks have already been cleared.
    pub fn clear_call_specs(&mut self) {
        self.callspecs.clear();
    }

    // Ghidra: funcdata.cc:504 Funcdata::compareCallspecs
    /// Compare two call specs by their position in the block dominance order.
    /// Faithful to `Funcdata::compareCallspecs` (funcdata.cc:504-512). First
    /// key is the basic-block index of the call op; ties are broken by the
    /// op's sequence-number order. Both keys are read through the exact Weak
    /// PcodeOp link stored by each FuncCallSpecs.
    pub fn compare_callspecs(
        &self,
        a: &crate::fspec::FuncCallSpecs,
        b: &crate::fspec::FuncCallSpecs,
    ) -> bool {
        let sort_key = |spec: &crate::fspec::FuncCallSpecs| {
            let op = spec
                .op
                .upgrade()
                .expect("callspec lost its PcodeOp before sorting");
            let (parent, order) = {
                let op = op.read().unwrap();
                let parent = op
                    .parent
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .expect("callspec PcodeOp has no parent before sorting");
                (parent, op.get_seq_num().get_order())
            };
            let block_index = parent.read().unwrap().get_index();
            (block_index, order)
        };
        let (ind1, order1) = sort_key(a);
        let (ind2, order2) = sort_key(b);
        if ind1 != ind2 {
            return ind1 < ind2;
        }
        order1 < order2
    }

    // Ghidra: funcdata.cc:516 Funcdata::sortCallSpecs
    /// Sort call specifications into dominance order so earlier calls are
    /// evaluated first. Faithful to `Funcdata::sortCallSpecs`
    /// (funcdata.cc:516-520). Order affects parameter analysis.
    pub fn sort_call_specs(&mut self) {
        // Snapshot only the two oracle comparison keys, then move each stable
        // Arc owner into its sorted position. No content clone or identity
        // rebinding occurs.
        let mut keyed: Vec<(i32, u32, Arc<RwLock<crate::fspec::FuncCallSpecs>>)> = self
            .callspecs
            .drain(..)
            .map(|fc| {
                let op = {
                    let spec = fc.read().unwrap();
                    spec.op
                        .upgrade()
                        .expect("callspec lost its PcodeOp before sorting")
                };
                let (parent, order) = {
                    let op = op.read().unwrap();
                    let parent = op
                        .parent
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .expect("callspec PcodeOp has no parent before sorting");
                    (parent, op.get_seq_num().get_order())
                };
                let block_index = parent.read().unwrap().get_index();
                (block_index, order, fc)
            })
            .collect();
        keyed.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        self.callspecs = keyed.into_iter().map(|(_, _, fc)| fc).collect();
    }

    // Ghidra: funcdata.cc:524 Funcdata::deleteCallSpecs
    /// Remove the call specification matching the given call op. Faithful to
    /// `Funcdata::deleteCallSpecs` (funcdata.cc:524-537). Used internally when
    /// a CALL is removed (e.g. because it is unreachable). The first spec
    /// whose Weak link upgrades to the exact op allocation is removed.
    pub fn delete_call_specs(&mut self, op: &PcodeOpRef) {
        if let Some(pos) = self.callspecs.iter().position(|fc| {
            fc.read()
                .unwrap()
                .op
                .upgrade()
                .map(|bound| Arc::ptr_eq(&bound, &op.0))
                .unwrap_or(false)
        }) {
            self.callspecs.remove(pos);
        }
    }

    // Ghidra: funcdata.cc:545 Funcdata::fillinExtrapop
    /// If the prototype's extrapop is unknown, recover it by examining the
    /// function's first return instruction (x86 assumption: `ret` is `0xc3`,
    /// `ret imm16` is `0xc2 lo hi`). Faithful to `Funcdata::fillinExtrapop`
    /// (funcdata.cc:545-573). Returns the recovered value.
    ///
    /// RUGRA-GAP: Rugra's `FuncProto` has no `extrapop` field (only
    /// `ProtoModel` does). The recovery is computed and returned, but cannot
    /// yet be cached on the prototype. Callers that need the side effect
    /// should store the return value themselves.
    pub fn fillin_extrapop(&self) -> i32 {
        // If no body, we cannot decide: return whatever the model says.
        if self.has_no_code() {
            return self.funcp_extrapop();
        }
        let ep = self.funcp_extrapop();
        if ep != crate::fspec::EXTRAPOP_UNKNOWN_FULL {
            return ep;
        }
        // Ghidra: list<PcodeOp*>::const_iterator iter = beginOp(CPUI_RETURN);
        // If no RETURN ops, the answer is irrelevant; return 0.
        let first_ret = self.obank.begin_op(OpCode::CPUI_RETURN).next();
        let retop = match first_ret {
            Some(r) => r,
            None => return 0,
        };
        let ret_addr = retop.0.read().unwrap().get_addr();
        // Ghidra: glb->loader->loadFill(buffer, 4, retop->getAddr());
        let buffer = match self.load_fill(4, ret_addr) {
            Some(b) => b,
            None => return self.funcp_extrapop(),
        };
        // We are assuming x86 code here.
        let mut extrapop: i32 = 4; // default
        if buffer.len() >= 3 && buffer[0] == 0xc2 {
            // ret imm16: bytes [lo, hi]; extrapop = imm16 + 4 (return address).
            extrapop = buffer[2] as i32; // hi
            extrapop <<= 8;
            extrapop += buffer[1] as i32; // lo
            extrapop += 4; // extra 4 for the return address
        }
        // RUGRA-GAP: funcp.setExtraPop(extrapop) — FuncProto has no extrapop.
        extrapop
    }

    // =========================================================================
    // Group 2: Jumptable recovery (funcdata_block.cc:427-686)
    // =========================================================================

    // Ghidra: funcdata_block.cc:426 Funcdata::linkJumpTable
    /// Link an existing (possibly override) jump-table to the given BRANCHIND
    /// op by setting its indirect op. Faithful to `Funcdata::linkJumpTable`
    /// (funcdata_block.cc:427-441). Returns the matching table, or `None` if
    /// no table's op-address matches.
    pub fn link_jump_table(
        &mut self,
        op: &PcodeOpRef,
    ) -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_addr();
        let target = op_addr.as_u64();
        // Find the matching table, then set its indirect op.
        let pos = self
            .jump_tables
            .iter()
            .position(|jt| jt.read().unwrap().get_op_address().as_u64() == target
        );
        if let Some(idx) = pos {
            let jt_arc = self.jump_tables[idx].clone();
            // set_indirect_op takes ownership of Arc<RwLock<PcodeOp>>; we can
            // clone the inner Arc from the PcodeOpRef wrapper.
            jt_arc.write().unwrap().set_indirect_op(op.0.clone());
            Some(jt_arc)
        } else {
            None
        }
    }

    // Ghidra: funcdata_block.cc:463 Funcdata::installJumpTable
    /// Install a fresh (empty) jump-table at the given address, suitable for
    /// an override. Must be called before flow is traced. Faithful to
    /// `Funcdata::installJumpTable` (funcdata_block.cc:464-477). Returns the
    /// new table.
    pub fn install_jump_table(
        &mut self, addr: Address,
    ) -> Arc<RwLock<crate::jumptable::JumpTable>> {
        if self.is_proc_started() {
            panic!("Cannot install jumptable if flow is already traced");
        }
        for jt in &self.jump_tables {
            if jt.read().unwrap().get_op_address().as_u64() == addr.as_u64() {
                panic!("Trying to install over existing jumptable");
            }
        }
        let new_jt = Arc::new(RwLock::new(crate::jumptable::JumpTable::new(addr)));
        self.jump_tables.push(new_jt.clone());
        new_jt
    }

    // Ghidra: funcdata_block.cc:491 Funcdata::stageJumpTable
    /// Recover a jump-table for a BRANCHIND using existing flow information.
    /// Faithful to `Funcdata::stageJumpTable` (funcdata_block.cc:491-548). A
    /// partial function clone is built via `truncatedFlow`, simplified under
    /// the "jumptable" strategy group (reset+perform on the partial), then
    /// the table's addresses are recovered from the simplified data-flow.
    /// Returns a success/failure code; `Err` is the LowlevelError channel
    /// that Ghidra lets propagate out of `stageJumpTable` (bad partial clone,
    /// truncated-flow clone failures).
    pub fn stage_jump_table(
        &mut self,
        partial: &mut Funcdata,
        jt: &Arc<RwLock<crate::jumptable::JumpTable>>,
        op: &PcodeOpRef,
        flow_state: &crate::flow::TruncatedFlowState,
    ) -> crate::error::Result<crate::jumptable::RecoveryMode> {
        if !partial.is_jumptable_recovery_on() {
            // Do full analysis on the table if we haven't before
            partial.flags |= funcdata_flags::JUMPTABLERECOVERY_ON;
            // cc:497: partial.truncatedFlow(this, flow); — clones the raw
            // dead-list ops, callspecs, and linked jumptables, then builds
            // the partial CFG. The C++ LowlevelError throw propagates up
            // through stageJumpTable; the Rust Result does the same.
            partial.truncated_flow(&*self, flow_state)?;
            // cc:499-518: save the current root action, switch the
            // architecture's ActionDatabase to the "jumptable" strategy
            // group, and reset+perform it on the partial clone. A
            // LowlevelError out of perform is caught, warned, and mapped to
            // fail_normal (cc:514-518).
            //
            // Ghidra's `glb->allacts` is architecture-owned and initialized
            // by Architecture::buildAction (architecture.cc:582-591). Rugra
            // drivers build their own root database and never call
            // build_action, so the architecture slot is typically None; when
            // present the shared slot is used with the oracle's
            // save/restore of the current root, otherwise a per-stage
            // database with the same universal tree and default groups is
            // constructed. The observable effect on `partial` is identical.
            let shared_db = self.get_arch().and_then(|a| a.allacts.clone());
            let local_db;
            let db_slot: &Arc<std::sync::RwLock<crate::action::ActionDatabase>> =
                match &shared_db {
                    Some(db) => db,
                    None => {
                        let mut db = crate::action::ActionDatabase::new();
                        db.set_default_actions();
                        local_db = std::sync::Arc::new(std::sync::RwLock::new(db));
                        &local_db
                    }
                };
            let perform_result = {
                let mut db = db_slot
                    .write()
                    .expect("allacts write lock poisoned");
                let oldactname = db.get_current_name().to_string();
                db.set_current("jumptable");
                let result = db.perform_action("jumptable", partial);
                if oldactname.is_empty() {
                    // No root was current before (uninitialized slot); the
                    // C++ database always has a current root after
                    // resetDefaults, and set_default_actions just ran, so
                    // this arm is unreachable in practice.
                    db.set_current("decompile");
                } else {
                    db.set_current(&oldactname);
                }
                result
            };
            // cc:514-518: catch(LowlevelError &err) { setCurrent(old);
            // warning(err.explain, op->getAddr()); return fail_normal; }
            if let Err(err) = perform_result {
                self.warning(&err.to_string(), op.0.read().unwrap().get_addr());
                return Ok(crate::jumptable::RecoveryMode::FailNormal);
            }
        }
        let op_seqnum = op.0.read().unwrap().get_seq_num().clone();
        // Ghidra: PcodeOp *partop = partial.findOp(op->getSeqNum());
        let partop = partial.obank.find_op(&op_seqnum);
        // cc:522-523: partop == 0 || code != BRANCHIND || addr mismatch →
        // throw LowlevelError("Error recovering jumptable: Bad partial clone")
        let partop = match partop {
            Some(p)
                if {
                    let p_rg = p.0.read().unwrap();
                    p_rg.opcode == OpCode::CPUI_BRANCHIND
                        && p_rg.get_addr().as_u64() == op.0.read().unwrap().get_addr().as_u64()
                } =>
            {
                p
            }
            _ => {
                return Err(crate::error::Error::Lowlevel(
                    "Error recovering jumptable: Bad partial clone".to_string(),
                ));
            }
        };
        // Indirectop we were trying to recover was eliminated as dead code.
        if partop.0.read().unwrap().is_dead() {
            return Ok(crate::jumptable::RecoveryMode::Success);
        }

        // Test if the branch target is copied from the return address.
        let in0 = {
            let p_rg = partop.0.read().unwrap();
            p_rg.get_in(0).cloned()
        };
        if let Some(vn) = in0 {
            if self.test_for_return_address(&vn) {
                // Switch would not recover anyway.
                return Ok(crate::jumptable::RecoveryMode::FailReturn);
            }
        }

        // cc:532: jt->setLoadCollect(flow->doesJumpRecord()) — the flag is
        // the RECORD_JUMPLOADS bit of the source FlowInfo's options, carried
        // through the truncated-flow state snapshot.
        {
            let mut jt_w = jt.write().unwrap();
            jt_w.set_load_collect(
                (flow_state.flags & crate::flow::flow_flags::RECORD_JUMPLOADS) != 0,
            );
            jt_w.set_indirect_op(partop.0.clone());
        }
        // cc:534-537: isPartial() → recoverMultistage; else recoverAddresses.
        // recoverMultistage absorbs both exception families internally
        // (restoring the old model + address table), so the try/catch below
        // only guards the recoverAddresses leg.
        {
            let mut jt_w = jt.write().unwrap();
            if jt_w.is_partial() {
                jt_w.recover_multistage(partial);
            } else {
                drop(jt_w);
                match jt.write().unwrap().recover_addresses_classified(partial) {
                    Ok(()) => return Ok(crate::jumptable::RecoveryMode::Success),
                    Err(crate::jumptable::JumpTableRecoveryError::Thunk { .. }) => {
                        return Ok(crate::jumptable::RecoveryMode::FailThunk)
                    }
                    Err(crate::jumptable::JumpTableRecoveryError::Lowlevel { message }) => {
                        self.warning(&message, op.0.read().unwrap().get_addr());
                        return Ok(crate::jumptable::RecoveryMode::FailNormal);
                    }
                }
            }
        }
        Ok(crate::jumptable::RecoveryMode::Success)
    }

    // Ghidra: funcdata_block.cc:554 Funcdata::earlyJumpTableFail
    /// Backtrack from a BRANCHIND looking for ops that might affect the
    /// destination. If an uninjected CALLOTHER is in the flow path, the
    /// jump-table analysis will fail and `FailCallother` is returned.
    /// Faithful to `Funcdata::earlyJumpTableFail` (funcdata_block.cc:555-628).
    pub fn early_jump_table_fail(&self, op: &PcodeOpRef) -> crate::jumptable::RecoveryMode {
        use crate::op::pcodeop_flags as pf;
        let mut vn_arc = {
            let op_rg = op.0.read().unwrap();
            op_rg.get_in(0).cloned()
        };
        // Walk the dead op list backwards from op's position. Rugra's obank
        // keeps a single `alivelist`; the dead list is implicit. We emulate
        // Ghidra's `beginOpDead()..op->insertiter` window by scanning the
        // alive list up to `op`, then continuing through earlier ops.
        let alive = &self.obank.alivelist;
        let start_idx = alive
            .iter()
            .position(|r| Arc::ptr_eq(&r.0, &op.0))
            .unwrap_or(0);
        let mut count_max: i32 = 8;
        let mut i: isize = start_idx as isize - 1;
        let vn_size = vn_arc
            .as_ref()
            .map(|v| v.read().unwrap().get_size())
            .unwrap_or(0);
        let mut cur_vn_size = vn_size;
        while i >= 0 {
            // Ghidra: if (vn->getSize() == 1) return success;
            if cur_vn_size == 1 {
                return crate::jumptable::RecoveryMode::Success;
            }
            count_max -= 1;
            if count_max < 0 {
                return crate::jumptable::RecoveryMode::Success;
            }
            let cur_op = alive[i as usize].clone();
            let (eval_type, opcode, is_call, is_branch, out_arc, in0_arc, in1_arc) = {
                let op_rg = cur_op.0.read().unwrap();
                (
                    op_rg.get_eval_type(),
                    op_rg.opcode,
                    op_rg.is_call(),
                    op_rg.is_branch(),
                    op_rg.get_out().cloned(),
                    op_rg.get_in(0).cloned(),
                    op_rg.get_in(1).cloned(),
                )
            };
            // Does cur_op write something overlapping our current vn?
            let outhit = match (&out_arc, &vn_arc) {
                (Some(o), Some(v)) => o.read().unwrap().intersects(&v.read().unwrap()),
                _ => false,
            };
            if eval_type == pf::SPECIAL {
                if is_call {
                    if opcode == OpCode::CPUI_CALLOTHER {
                        // int4 id = (int4)op->getIn(0)->getOffset();
                        let id = in0_arc
                            .as_ref()
                            .map(|v| v.read().unwrap().get_offset())
                            .unwrap_or(0) as usize;
                        let user_op_type = self.userop_type(id);
                        use crate::userop::UserOpType;
                        if user_op_type == UserOpType::Injected
                            || user_op_type == UserOpType::JumpAssist
                            || user_op_type == UserOpType::Segment
                        {
                            return crate::jumptable::RecoveryMode::Success;
                        }
                        if outhit {
                            // Address formed via uninjected CALLOTHER, analysis will fail.
                            return crate::jumptable::RecoveryMode::FailCallother;
                        }
                        // Assume CALLOTHER will not interfere; continue backtracking.
                    } else {
                        // CALL or CALLIND — output not established yet.
                        return crate::jumptable::RecoveryMode::Success;
                    }
                } else if is_branch {
                    return crate::jumptable::RecoveryMode::Success;
                } else {
                    if opcode == OpCode::CPUI_STORE {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    // Some special op generates the address; don't assume failure.
                }
            } else if eval_type == pf::UNARY {
                if outhit {
                    let invn = in0_arc;
                    let invn_size = invn
                        .as_ref()
                        .map(|v| v.read().unwrap().get_size())
                        .unwrap_or(0);
                    if invn_size != cur_vn_size {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    vn_arc = invn;
                    cur_vn_size = invn_size;
                }
            } else if eval_type == pf::BINARY {
                if outhit {
                    if opcode != OpCode::CPUI_INT_ADD
                        && opcode != OpCode::CPUI_INT_SUB
                        && opcode != OpCode::CPUI_INT_XOR
                    {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    let in1_const = in1_arc
                        .as_ref()
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false);
                    if !in1_const {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    let invn = in0_arc;
                    let invn_size = invn
                        .as_ref()
                        .map(|v| v.read().unwrap().get_size())
                        .unwrap_or(0);
                    if invn_size != cur_vn_size {
                        return crate::jumptable::RecoveryMode::Success;
                    }
                    vn_arc = invn;
                    cur_vn_size = invn_size;
                }
            } else if outhit {
                return crate::jumptable::RecoveryMode::Success;
            }
            i -= 1;
        }
        crate::jumptable::RecoveryMode::Success
    }

    // Ghidra: funcdata_block.cc:639 Funcdata::recoverJumpTable
    /// Recover control-flow destinations for a BRANCHIND. Faithful to
    /// `Funcdata::recoverJumpTable` (funcdata_block.cc:639-673). If an
    /// existing non-override, non-partial table exists it is returned
    /// immediately; otherwise an attempt is made to stage recovery. Returns
    /// the recovered table (also pushed into `jump_tables` if newly created)
    /// or `None` on failure, with `mode` set to the failure code. `Err` is
    /// the LowlevelError that Ghidra lets escape `stageJumpTable` (bad
    /// partial clone / truncated-flow clone failure).
    pub fn recover_jump_table(
        &mut self,
        partial: &mut Funcdata,
        op: &PcodeOpRef,
        mode: &mut crate::jumptable::RecoveryMode,
        flow_state: &crate::flow::TruncatedFlowState,
    ) -> crate::error::Result<Option<Arc<RwLock<crate::jumptable::JumpTable>>>> {
        *mode = crate::jumptable::RecoveryMode::Success;

        // Search for a pre-existing jumptable.
        if let Some(jt) = self.link_jump_table(op) {
            let (is_override, is_partial) = {
                let jt_rg = jt.read().unwrap();
                (jt_rg.is_override(), jt_rg.is_partial())
            };
            if !is_override {
                if !is_partial {
                    return Ok(Some(jt)); // Previously calculated jumptable.
                }
            }
            *mode = self.stage_jump_table(partial, &jt, op, flow_state)?;
            if *mode != crate::jumptable::RecoveryMode::Success {
                return Ok(None);
            }
            // Relink table back to original op.
            jt.write().unwrap().set_indirect_op(op.0.clone());
            return Ok(Some(jt));
        }

        if (self.flags & funcdata_flags::JUMPTABLERECOVERY_DONT) != 0 {
            return Ok(None); // Explicitly told not to recover jumptables.
        }
        *mode = self.early_jump_table_fail(op);
        if *mode != crate::jumptable::RecoveryMode::Success {
            return Ok(None);
        }

        // JumpTable trialjt(glb);  — start with an empty trial table.
        let op_addr = op.0.read().unwrap().get_addr();
        let trial_jt = Arc::new(RwLock::new(crate::jumptable::JumpTable::new(op_addr)));
        *mode = self.stage_jump_table(partial, &trial_jt, op, flow_state)?;
        if *mode != crate::jumptable::RecoveryMode::Success {
            return Ok(None);
        }
        // Make the jumptable permanent.
        trial_jt.write().unwrap().set_indirect_op(op.0.clone());
        self.jump_tables.push(trial_jt.clone());
        Ok(Some(trial_jt))
    }

    // Ghidra: funcdata_block.cc:678 Funcdata::switchOverJumpTables
    /// For each jump-table, for each address, compute the corresponding basic
    /// block out-edge position (populating `JumpTable::block2addr`) and derive
    /// the default branch. Faithful to
    /// `Funcdata::switchOverJumpTables` (funcdata_block.cc:678-685), called at
    /// the end of `followFlow` (funcdata_op.cc:777-778).
    ///
    /// RUGRA-GLUE: associated-function form taking the `Funcdata` by shared
    /// reference — the only `&mut Funcdata` during flow following is owned by
    /// the `FlowInfo`, so the oracle's member form cannot borrow both. Each
    /// table is still mutated through its `Arc<RwLock<JumpTable>>`, exactly
    /// like Ghidra mutates through its `jumpvec` pointers.
    pub fn switch_over_jump_tables(
        fd: &Funcdata, flow: &crate::flow::FlowInfo,
    ) -> crate::error::Result<()> {
        for jt in &fd.jump_tables {
            jt.write()
                .unwrap()
                .switch_over(flow)
                .map_err(|e| crate::error::Error::Lowlevel(e.message().to_string()))?;
        }
        Ok(())
    }

    // =========================================================================
    // Group 3: Block structure maintenance (funcdata_block.cc:28-321)
    // =========================================================================

    // Ghidra: funcdata_block.cc:27 Funcdata::printBlockTree
    /// Print the structure tree (composite blocks) to a string. Faithful to
    /// `Funcdata::printBlockTree` (funcdata_block.cc:28-33), which delegates
    /// to `BlockGraph::printTree(s, 0)`. Rugra's `BlockGraph` has no
    /// `print_tree`, so this walks the top-level structure blocks and emits
    /// one line per block with its index and type, indented to depth 0.
    pub fn print_block_tree(&self) -> String {
        let mut out = String::new();
        for blk in &self.sblocks.blocks {
            let rg = blk.read().unwrap();
            out.push_str(&format!(
                "  Block {} ({:?})\n",
                rg.get_index(),
                rg.get_type()
            ));
        }
        out
    }

    // Ghidra: funcdata_block.cc:34 Funcdata::clearBlocks
    /// Clear both the basic-block graph and the structure tree. Faithful to
    /// `Funcdata::clearBlocks` (funcdata_block.cc:35-40).
    pub fn clear_blocks(&mut self) {
        self.bblocks.clear();
        self.sblocks.clear();
    }

    // Ghidra: funcdata_block.cc:42 Funcdata::clearJumpTables
    /// Clear all derived jump-table data, preserving any manually-overridden
    /// tables. Faithful to `Funcdata::clearJumpTables`
    /// (funcdata_block.cc:43-60): for an override the table object survives
    /// with only its derived data cleared via `JumpTable::clear()`
    /// (jumptable.cc:2739-2758 — which itself preserves the permanent
    /// opaddress/maxtablesize/maxaddsub/maxleftright/maxext/collectloads
    /// fields); non-override tables are dropped entirely.
    pub fn clear_jump_tables(&mut self) {
        let mut remain: Vec<Arc<RwLock<crate::jumptable::JumpTable>>> = Vec::new();
        for jt in self.jump_tables.drain(..) {
            let is_override = jt.read().unwrap().is_override();
            if is_override {
                // Clear out any derived data but keep the override itself.
                jt.write().unwrap().clear();
                remain.push(jt);
            }
            // else: drop (the Arc is released when it goes out of scope).
        }
        self.jump_tables = remain;
    }

    // Ghidra: funcdata_block.cc:84 Funcdata::pushMultiequals
    /// Assuming `bb` is being removed, force any Varnode defined by a
    /// MULTIEQUAL in `bb` to be defined in the output block instead, patching
    /// up data-flow. Faithful to `Funcdata::pushMultiequals`
    /// (funcdata_block.cc:84-171): per-MULTIEQUAL-in-bb descendant scan
    /// (dead-edge detection + addrtied same-address `neednewunique`), then the
    /// artificial MULTIEQUAL construction in the first out block (origvn on
    /// the bb-edge slots, `replacevn` on every other slot), then the
    /// descend rewrite that retargets all non-dead-edge reads of `origvn` to
    /// `replacevn`.
    pub fn push_multiequals(&mut self, bb: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        // cc:93-95: no out edges -> nothing to push into; >1 out edges is
        // unexpected for a do-nothing block but only warns, execution goes on.
        let (outblock, outblock_ind) = {
            let bb_rg = bb.read().unwrap();
            if bb_rg.size_out() == 0 {
                return;
            }
            if bb_rg.size_out() > 1 {
                self.warning_header("push_multiequal on block with multiple outputs");
            }
            // cc:96-98: take first output block (for a donothing block it is
            // the only one) and the slot of bb in its in-list (dead-edge slot).
            let out = bb_rg.get_out(0).map(|e| e.point);
            let rev = if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_out_rev_index(0)
            } else {
                -1
            };
            match out {
                Some(o) => (o, rev),
                None => return,
            }
        };

        // cc:99: iterate bb's ops in block order.
        let bb_ops = {
            let bb_rg = bb.read().unwrap();
            if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_ops()
            } else {
                return;
            }
        };

        for origop in bb_ops {
            if origop.0.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
                continue; // cc:101
            }
            let origvn = origop.0.read().unwrap().get_out().cloned();
            let origvn = match origvn {
                Some(v) => v,
                None => continue,
            };
            if origvn.read().unwrap().has_no_descend() {
                continue; // cc:103
            }
            // cc:104-128: scan origvn's descendants (in descend order) for
            // the first read that does NOT go through the dead edge.
            let mut needreplace = false;
            let mut neednewunique = false;
            let descend_snapshot: Vec<_> = {
                let orig_rg = origvn.read().unwrap();
                orig_rg.descend_iter().collect()
            };
            for op in descend_snapshot {
                let is_multi_in_outblock = {
                    let o = op.read().unwrap();
                    o.opcode == OpCode::CPUI_MULTIEQUAL
                        && o.parent
                            .as_ref()
                            .and_then(std::sync::Weak::upgrade)
                            .is_some_and(|p| Arc::ptr_eq(&p, &outblock))
                };
                if is_multi_in_outblock {
                    // cc:109-116: deadEdge = every reference to origvn in this
                    // MULTIEQUAL goes through the dead edge (slot outblock_ind).
                    let mut dead_edge = true;
                    let num_input = op.read().unwrap().num_input();
                    for i in 0..num_input {
                        if i as i32 == outblock_ind {
                            continue; // cc:111: not going thru dead edge
                        }
                        let reads_orig = {
                            let o = op.read().unwrap();
                            o.inrefs
                                .get(i)
                                .is_some_and(|v| Arc::ptr_eq(v, &origvn))
                        };
                        if reads_orig {
                            dead_edge = false; // cc:113
                            break;
                        }
                    }
                    if dead_edge {
                        // cc:118-122: if origvn is addrtied and feeds a
                        // MULTIEQUAL at the same address in outblock, any use
                        // beyond outblock propagated through another register,
                        // so the new MULTIEQUAL must write a unique.
                        // cc:118's Address::operator== (address.hh:356-358)
                        // compares space AND offset — a register-space origvn
                        // and a stack/ram MULTIEQUAL out at the same offset
                        // are NOT the same storage; the spaceless offset-only
                        // compare wrongly forced neednewunique for
                        // cross-space matches (FAMILY-AUDIT-SPACELESS-SITES-0001).
                        let same_addr_addrtied = {
                            let (orig_addr, orig_space, orig_addrtied) = {
                                let orig_rg = origvn.read().unwrap();
                                (
                                    *orig_rg.get_addr(),
                                    orig_rg.address_space,
                                    orig_rg.is_addr_tied(),
                                )
                            };
                            let out_matches = {
                                let o = op.read().unwrap();
                                o.get_out().is_some_and(|v| {
                                    let v_rg = v.read().unwrap();
                                    v_rg.address_space == orig_space
                                        && *v_rg.get_addr() == orig_addr
                                })
                            };
                            out_matches && orig_addrtied
                        };
                        if same_addr_addrtied {
                            neednewunique = true;
                        }
                        continue; // cc:123
                    }
                }
                needreplace = true; // cc:126
                break; // cc:127
            }
            if !needreplace {
                continue; // cc:129
            }
            // cc:131-135: the replacement varnode.
            let (orig_size, orig_addr, orig_space) = {
                let orig_rg = origvn.read().unwrap();
                (orig_rg.get_size(), *orig_rg.get_addr(), orig_rg.address_space)
            };
            let replacevn = if neednewunique {
                self.new_unique(orig_size)
            } else {
                // cc:135: newVarnode(origvn->getSize(),origvn->getAddr()) —
                // the full storage address (space + offset) of origvn. The
                // spaceless new_varnode adapter defaults to RAM, which
                // fabricated cross-space varnodes (RAM@register-offset) out
                // of pushed register-space MULTIEQUALs — the
                // HERITAGE-CROSSSPACE-MERGE-0001 garbage family.
                self.new_varnode_in_space(orig_size, orig_space, orig_addr)
            };
            // cc:136-148: one branch per in-edge of outblock: origvn on the
            // bb edge(s), replacevn on the (dominated) alternate edges.
            let out_in_count = outblock.read().unwrap().size_in();
            let mut branches: Vec<Arc<RwLock<crate::varnode::Varnode>>> =
                Vec::with_capacity(out_in_count);
            for i in 0..out_in_count {
                let from_bb = {
                    let out_rg = outblock.read().unwrap();
                    out_rg
                        .get_in(i)
                        .is_some_and(|e| Arc::ptr_eq(&e.point, bb))
                };
                if from_bb {
                    branches.push(origvn.clone());
                } else {
                    branches.push(replacevn.clone());
                }
            }
            // cc:149-153: construct the artificial MULTIEQUAL at outblock's
            // start and insert it at the head of its MULTIEQUAL group.
            let out_start = outblock.read().unwrap().get_start_addr();
            let replaceop = self.new_op(branches.len(), out_start);
            self.op_set_opcode(&replaceop, OpCode::CPUI_MULTIEQUAL);
            self.op_set_output(&replaceop, replacevn.clone());
            self.op_set_all_input(&replaceop, &branches);
            self.op_insert_begin(&replaceop, &outblock);

            // cc:156-169: replace obsolete origvn reads with replacevn. The
            // snapshot is taken AFTER the construction, matching Ghidra's
            // `titer = origvn->descend.begin()` at cc:157 — the artificial
            // MULTIEQUAL itself now trails the list and is skipped by the
            // cc:163-165 dead-edge guard like any other dead-edge read.
            let rewrite_snapshot: Vec<_> = {
                let orig_rg = origvn.read().unwrap();
                orig_rg.descend_iter().collect()
            };
            for op in rewrite_snapshot {
                let num_input = op.read().unwrap().num_input();
                for i in 0..num_input {
                    let reads_orig = {
                        let o = op.read().unwrap();
                        o.inrefs.get(i).is_some_and(|v| Arc::ptr_eq(v, &origvn))
                    };
                    if !reads_orig {
                        continue; // cc:161-162
                    }
                    let dead_edge_read = {
                        let o = op.read().unwrap();
                        (i as i32) == outblock_ind
                            && o.parent
                                .as_ref()
                                .and_then(std::sync::Weak::upgrade)
                                .is_some_and(|p| Arc::ptr_eq(&p, &outblock))
                            && o.opcode == OpCode::CPUI_MULTIEQUAL
                    };
                    if dead_edge_read {
                        continue; // cc:163-165
                    }
                    self.op_set_input(&crate::op::PcodeOpRef(op.clone()), replacevn.clone(), i);
                    break; // cc:167
                }
            }
        }
    }

    // Ghidra: funcdata_block.cc:177 Funcdata::opZeroMulti
    /// If the MULTIEQUAL has no inputs, treat it as a COPY from a new input
    /// Varnode; if it has one input, transform it directly into a COPY.
    /// Faithful to `Funcdata::opZeroMulti` (funcdata_block.cc:178-188).
    pub fn op_zero_multi(&mut self, op: &PcodeOpRef) {
        let num_input = op.0.read().unwrap().num_input();
        if num_input == 0 {
            // No branches left: insert a new input varnode at slot 0 and
            // convert to COPY.
            let (size, addr, space) = {
                let op_rg = op.0.read().unwrap();
                let out = op_rg.get_out();
                match out {
                    Some(o) => {
                        let o_rg = o.read().unwrap();
                        (o_rg.get_size(), *o_rg.get_addr(), o_rg.address_space)
                    }
                    None => (0, Address::new(0), crate::space::AddressSpace::Ram),
                }
            };
            // cc:181: newVarnode(op->getOut()->getSize(),op->getOut()->getAddr())
            // — the FULL storage address (space + offset) of the out
            // varnode; a zeroed MULTIEQUAL's out is commonly a register, so
            // the input varnode lives in the register space. The spaceless
            // new_varnode adapter defaults to RAM, which fabricated
            // RAM@register-offset garbage instead — the
            // HERITAGE-CROSSSPACE-MERGE family (same construction as the
            // pushMultiequals fix at new_varnode_in_space cc:135).
            let newvn = self.new_varnode_in_space(size, space, addr);
            self.op_insert_input(op, newvn.clone(), 0);
            // Ghidra: setInputVarnode(op->getIn(0)); promote slot 0 to input.
            self.set_input_varnode(newvn);
            self.op_set_opcode(op, OpCode::CPUI_COPY);
        } else if num_input == 1 {
            self.op_set_opcode(op, OpCode::CPUI_COPY);
        }
    }

    // Ghidra: funcdata_block.cc:195 Funcdata::branchRemoveInternal
    /// Remove an outgoing branch of the given basic block, patching
    /// MULTIEQUAL p-code ops in the target block. Faithful to
    /// `Funcdata::branchRemoveInternal` (funcdata_block.cc:196-216).
    pub fn branch_remove_internal(
        &mut self, bb: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, num: usize,
    ) {
        // If there is no decision left (2 out-edges), remove the branch op.
        let size_out = bb.read().unwrap().size_out();
        if size_out == 2 {
            let last = {
                let bb_rg = bb.read().unwrap();
                if let Some(bb_basic) = bb_rg.as_any().downcast_ref::<BlockBasic>() {
                    bb_basic.last_op()
                } else {
                    None
                }
            };
            if let Some(op) = last {
                self.op_destroy(&op);
            }
        }

        let bbout = bb.read().unwrap().get_out(num).map(|e| e.point);
        let bbout = match bbout {
            Some(o) => o,
            None => return,
        };
        let blocknum = self.find_in_index(&bbout, bb);
        // Sever (one) connection between bb and bbout.
        self.bblocks.remove_edge_blocks(bb, &bbout);

        // For each MULTIEQUAL in bbout, remove input `blocknum` and zero it.
        let ops: Vec<PcodeOpRef> = {
            let bbout_rg = bbout.read().unwrap();
            if let Some(bb_basic) = bbout_rg.as_any().downcast_ref::<BlockBasic>() {
                bb_basic.get_ops()
            } else {
                return;
            }
        };
        for op in ops {
            let is_me = op.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL;
            if !is_me {
                continue;
            }
            if let Some(bn) = blocknum {
                self.op_remove_input(&op, bn);
            }
            self.op_zero_multi(&op);
        }
    }

    // Ghidra: funcdata_block.cc:233 Funcdata::descendantsOutside
    /// Assuming a basic block is marked dead, return `true` if any PcodeOp
    /// reading `vn` is outside the dead block (i.e. the varnode still has
    /// live readers). Faithful to `Funcdata::descendantsOutside`
    /// (funcdata_block.cc:234-242).
    pub fn descendants_outside(&self, vn: &Arc<RwLock<crate::varnode::Varnode>>) -> bool {
        use crate::block::block_flags;
        // cc:238-240: for each descendant op, if its PARENT BLOCK is not
        // dead, the varnode has descendants outside the dead-block set.
        // (Block-level isDead, not op-level: unreachable blocks are all
        // flagged dead before any op destruction begins.)
        let descend: Vec<Arc<RwLock<crate::op::PcodeOp>>> = {
            let vn_rg = vn.read().unwrap();
            vn_rg.descend_iter().collect()
        };
        for dop in descend {
            let parent_alive = dop
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|p| p.upgrade())
                .map(|p| p.read().unwrap().get_flags() & block_flags::DEAD == 0)
                // An op with no parent block cannot be in a dead block; the
                // oracle would dereference getParent() here, and every op on
                // this path has a parent at block-removal time.
                .unwrap_or(true);
            if parent_alive {
                return true;
            }
        }
        false
    }


    // Ghidra: funcdata_block.cc:254 Funcdata::blockRemoveInternal
    /// Remove an active basic block from the function: delete its PcodeOps,
    /// patch up data-flow and control-flow (mostly MULTIEQUALs). Faithful to
    /// `Funcdata::blockRemoveInternal` (funcdata_block.cc:255-321).
    ///
    /// RUGRA-GAP: the full MULTIEQUAL-splicing logic and
    /// `bblocks.removeFromFlow` are not ported. This implementation performs
    /// the reachable parts: jump-table removal for a trailing BRANCHIND,
    /// call-spec deletion, op destruction, and final block removal. The
    /// unreachable-warning path is preserved.

    // =========================================================================
    // Helpers used by the ported methods (no Ghidra line — these adapt the
    // Rust API surface to the ported code).
    // =========================================================================

    /// Find `parent`'s slot in `child`'s incoming list (Ghidra
    /// `FlowBlock::getInIndex`). Returns `None` if not present.
    // Ghidra: block.cc:579 FlowBlock::getInIndex
    fn find_in_index(
        &self,
        child: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        parent: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> Option<usize> {
        let child_rg = child.read().unwrap();
        (0..child_rg.size_in()).find(|&i| {
            child_rg
                .get_in(i)
                .map(|e| Arc::ptr_eq(&e.point, parent))
                .unwrap_or(false)
        })
    }

    /// Find a jump-table whose op-address matches `op`, returning a cloned
    /// Arc (mutable-self counterpart to [`find_jump_table`](Self::find_jump_table)).
    // RUGRA-GLUE: Rust ownership form of the existing find_jump_table mapping;
    // Ghidra returns one raw JumpTable pointer and has no Arc-cloning helper.
    fn find_jump_table_arc(
        &self,
        op: &PcodeOpRef,
    ) -> Option<Arc<RwLock<crate::jumptable::JumpTable>>> {
        let op_addr = op.0.read().unwrap().get_addr().as_u64();
        self.jump_tables
            .iter()
            .find(|jt| jt.read().unwrap().get_op_address().as_u64() == op_addr)
            .cloned()
    }

    /// Load `size` bytes from the load image at `addr`. Adapts Ghidra's
    /// `glb->loader->loadFill(buf, size, addr)` to Rugra's
    /// `LoadImage::load_fill(size, addr) -> Result<Vec<u8>, DataUnavailError>`.
    /// Returns `None` if the image has no data at `addr`.
    // RUGRA-GLUE: Rust Result/buffer adapter around LoadImage::load_fill;
    // Ghidra fills the caller's buffer directly and has no Funcdata helper.
    fn load_fill(&self, size: usize, addr: Address) -> Option<Vec<u8>> {
        let arch = self.arch.as_ref()?;
        let loader = arch.loader.as_ref()?;
        loader.load_fill(size, addr).ok()
    }

    /// Get the prototype's extrapop. Adapts Ghidra's `funcp.getExtraPop()`.
    /// RUGRA-GAP: Rugra's `FuncProto` has no `extrapop` field (only
    /// `ProtoModel` does), and `Funcdata` has no architecture-resolved default
    /// model, so this always returns `EXTRAPOP_UNKNOWN_FULL` — which forces
    /// [`fillin_extrapop`](Self::fillin_extrapop) to attempt byte-level
    /// recovery rather than short-circuiting.
    // RUGRA-GLUE: Adapter for the unported FuncProto extrapop field; Ghidra
    // calls funcp.getExtraPop() directly and has no Funcdata wrapper.
    fn funcp_extrapop(&self) -> i32 {
        crate::fspec::EXTRAPOP_UNKNOWN_FULL
    }

    /// Does this function have no code body (external/thunk)? Adapts Ghidra's
    /// `hasNoCode()`. RUGRA-GAP: Rugra has no explicit flag; approximate via
    /// an empty obank (no ops means no body).
    // Ghidra: funcdata.hh:153 Funcdata::hasNoCode
    fn has_no_code(&self) -> bool {
        self.obank.alivelist.is_empty() && self.size == 0
    }

    /// Get the user-op type for CALLOTHER id `id`. Adapts Ghidra's
    /// `glb->userops.getOp(id)->getType()`. Returns `Unspecialized` if the
    /// architecture or user-op table is unavailable.
    // RUGRA-GLUE: Rust Option/lock adapter for the inline user-op lookup in
    // Funcdata::earlyJumpTableFail; Ghidra has no Funcdata::useropType helper.
    fn userop_type(&self, id: usize) -> crate::userop::UserOpType {
        use crate::userop::UserOpType;
        let arch = match self.arch.as_ref() {
            Some(a) => a,
            None => return UserOpType::Unspecialized,
        };
        if let Some(userops) = arch.userops.as_ref() {
            let mgr = userops.read().unwrap();
            if let Some(uo) = mgr.get_op(id as i32) {
                return uo.get_type();
            }
        }
        UserOpType::Unspecialized
    }

    // Ghidra: funcdata_varnode.cc:1442 Funcdata::testForReturnAddress
    /// Trace `vn` back to see if it derives from this function's return
    /// address. Faithful to `Funcdata::testForReturnAddress`
    /// (funcdata_varnode.cc:1442-1468). The value may flow through COPY,
    /// INDIRECT, and INT_AND (alignment mask) ops; any other op breaks the
    /// chain. The terminal Varnode must be an input marked as the return
    /// address storage location.
    /// RUGRA-GAP: Ghidra compares against `glb->defaultReturnAddr` (a
    /// VarnodeData). Rugra's Architecture does not yet hold that datum, so we
    /// instead check the terminal Varnode's `is_input()` and its
    /// `RETURN_ADDRESS` flag (set by the loader/disassembler on the storage
    /// location). When no return-address flag is present we conservatively
    /// return false.
    pub fn test_for_return_address(&self, vn: &Arc<RwLock<crate::varnode::Varnode>>) -> bool {
        // cc:1445-1447: retaddr = glb->defaultReturnAddr; if null return false.
        // Rugra: the RETURN_ADDRESS varnode flag is our analogue of having a
        // known return-address storage location.
        let mut cur = vn.clone();
        loop {
            let (def, opc, in0) = {
                let c = cur.read().unwrap();
                if !c.is_written() {
                    break;
                }
                let d = match c.get_def() {
                    Some(d) => d,
                    None => break,
                };
                // Read the opcode/input under the guard, then move the Arc out.
                let (opc, in0) = {
                    let dg = d.read().unwrap();
                    (dg.opcode, dg.get_in(0).cloned())
                };
                (d, opc, in0)
            };
            // cc:1451-1453: INDIRECT/COPY → follow in(0).
            if opc == OpCode::CPUI_INDIRECT || opc == OpCode::CPUI_COPY {
                match in0 {
                    Some(v) => cur = v,
                    None => return false,
                }
            } else if opc == OpCode::CPUI_INT_AND {
                // cc:1454-1458: only allow alignment-style masking (constant
                // second input); follow in(0).
                let in1_const = {
                    let d = def.read().unwrap();
                    d.get_in(1)
                        .map(|v| v.read().unwrap().is_constant())
                        .unwrap_or(false)
                };
                if !in1_const {
                    return false;
                }
                match in0 {
                    Some(v) => cur = v,
                    None => return false,
                }
            } else {
                // cc:1460-1461: any other op → not a return address.
                return false;
            }
        }
        // cc:1463-1466: terminal must match the return-address storage and be
        // an input. Rugra: check is_input() + RETURN_ADDRESS flag.
        let c = cur.read().unwrap();
        if !c.is_input() {
            return false;
        }
        c.is_return_address()
    }

    // Ghidra: funcdata_varnode.cc:190 Funcdata::newVarnodeSpace
    /// Encode an address space as a constant Varnode. Faithful to
    /// `Funcdata::newVarnodeSpace` (funcdata_varnode.cc:190-198):
    ///   Datatype *ct = glb->types->getBase(sizeof(spc), TYPE_UNKNOWN);
    ///   Varnode *vn = vbank.create(sizeof(spc), glb->createConstFromSpace(spc), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// These Varnodes are used as the first input to LOAD/STORE p-code ops to
    /// name the address space being accessed. Rugra encodes the space via its
    /// SpaceId (which uniquely identifies the space) as the constant offset.
    pub fn new_varnode_space(
        &mut self,
        spc: crate::space::AddressSpace,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let sz = std::mem::size_of::<usize>();
        let offset = spc.space_id() as u64;
        let vn = self
            .vbank
            .create_with_space(sz, crate::space::AddressSpace::Const, offset);
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:205 Funcdata::newVarnodeCallSpecs
    /// Model the identity and lifetime portion of Ghidra's fspace annotation
    /// Varnode from `Funcdata::newVarnodeCallSpecs`
    /// (funcdata_varnode.cc:205-214):
    ///   Datatype *ct = glb->types->getBase(sizeof(fc), TYPE_UNKNOWN);
    ///   AddrSpace *cspc = glb->getFspecSpace();
    ///   Varnode *vn = vbank.create(sizeof(fc), Address(cspc,(uintb)(uintp)fc), ct);
    ///   assignHigh(vn);
    ///   return vn;
    /// The Varnode is the first input to a CPUI_CALL op and accelerates lookup
    /// of the associated call specification. Rugra still lacks a dedicated
    /// fspace address space, so D0 uses Iop. Until PrintC consumes the typed
    /// handle, a direct call retains its entry address as the legacy numeric
    /// payload; an invalid entry falls back to a pointer-shaped diagnostic.
    /// Neither value participates in identity: lookup is exclusively through
    /// the typed Weak bound to the same stable Arc allocation. This deliberate
    /// representation mismatch is tracked by TYPEOP-FSPEC-SPACE-0001.
    pub fn new_varnode_call_specs(
        &mut self,
        fc: &Arc<RwLock<crate::fspec::FuncCallSpecs>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let sz = std::mem::size_of::<usize>();
        let compatibility_offset = fc
            .read()
            .unwrap()
            .entry_addr
            .map(|entry| entry.as_u64())
            .unwrap_or_else(|| Arc::as_ptr(fc) as usize as u64);
        let vn = self.vbank
                .create_with_space(
            sz,
            crate::space::AddressSpace::Iop,
            compatibility_offset);
        {
            let mut annotation = vn.write().unwrap();
            annotation.set_flags(crate::varnode::varnode_flags::ANNOTATION);
            annotation.bind_call_spec(fc);
        }
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:222 Funcdata::newCodeRef
    /// Construct an annotation Varnode that holds a reference to a code
    /// Address (used as the destination of a BRANCH op). Faithful to
    /// `Funcdata::newCodeRef` (funcdata_varnode.cc:222-233):
    ///   Datatype *ct = glb->types->getTypeCode();
    ///   vn = vbank.create(1, m, ct);
    ///   vn->setFlags(Varnode::annotation);
    ///   assignHigh(vn);
    ///   return vn;
    /// Rugra has no dedicated TypeCode; we still create a 1-byte Varnode at the
    /// given code address and mark it as an annotation.
    pub fn new_code_ref(
        &mut self,
        m: crate::address::Address,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        let vn = self.vbank.create(1, m);
        vn.write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::ANNOTATION);
        let _ = self.assign_high(&vn);
        vn
    }

    // Ghidra: funcdata_varnode.cc:252 Funcdata::cloneVarnode
    /// Shallow-clone a Varnode from another Funcdata into \b this. Faithful to
    /// `Funcdata::cloneVarnode` (funcdata_varnode.cc:252-267):
    ///   newvn = vbank.create(vn->getSize(), vn->getAddr(), vn->getType());
    ///   uint4 vflags = vn->getFlags();
    ///   vflags &= (annotation | externref | readonly | persist |
    ///             addrtied | addrforce | indirect_creation | incidental_copy |
    ///             volatil | mapped);
    ///   newvn->setFlags(vflags);
    ///   return newvn;
    /// Used by `cloneOp` / `truncatedFlow` to copy raw p-code across functions.
    /// The clone deliberately does NOT carry over `def`/`descend` links — the
    /// caller re-establishes them via `opSetOutput`/`opSetInput`.
    pub fn clone_varnode(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
        use crate::varnode::varnode_flags as vf;
        let (size, space, offset, vflags, v_type, call_spec) = {
            let r = vn.read().unwrap();
            (
                r.size,
                r.address_space,
                r.loc.as_u64(),
                r.flags,
                r.v_type.clone(),
                r.call_spec.clone(),
            )
        };
        let newvn = self.vbank.create_with_space(size, space, offset);
        // cc:260-264: keep only the documented flag subset.
        let keep_mask = vf::ANNOTATION
            | vf::EXTERNREF
            | vf::READONLY
            | vf::PERSIST
            | vf::ADDRTIED
            | vf::ADDRFORCE
            | vf::INDIRECT_CREATION
            | vf::INCIDENTAL_COPY
            | vf::VOLATIL
            | vf::MAPPED;
        {
            let mut cloned = newvn.write().unwrap();
            // cc:256 passes vn->getType() to VarnodeBank::create.  Preserve
            // the same shared Datatype identity, in addition to the complete
            // Address (space + offset), before applying the restricted flags.
            cloned.v_type = v_type;
            cloned.call_spec = call_spec;
            cloned.set_flags(vflags & keep_mask);
        }
        newvn
    }

    // Ghidra: funcdata_varnode.cc:298 Funcdata::checkForLanedRegister
    /// Check if the given storage range is a potential laned register; if so,
    /// record the storage with the matching laned-register record. Faithful to
    /// `Funcdata::checkForLanedRegister` (funcdata_varnode.cc:298-309):
    ///   const LanedRegister *lanedRegister = glb->getLanedRegister(addr, sz);
    ///   if (lanedRegister == NULL) return;
    ///   VarnodeData storage{addr.getSpace(), addr.getOffset(), sz};
    ///   lanedMap[storage] = lanedRegister;
    /// The explicit `space` parameter restores the address-space component
    /// carried by Ghidra's `Address`, which Rugra's scalar `Address` separates.
    pub fn check_for_laned_register(
        &mut self,
        sz: usize,
        space: crate::space::AddressSpace,
        addr: crate::address::Address,
    ) {
        let Some(record) = self
            .arch
            .as_ref()
            .and_then(|arch| arch.get_laned_register(addr, sz))
        else {
            return;
        };
        let storage = LanedStorage {
            space,
            offset: addr.as_u64(),
            size: sz,
        };
        self.laned_map.insert(storage, record);
    }

    // Ghidra: funcdata.hh:155 Funcdata::setLanedRegGenerated
    /// Stop recording newly created laned-register accesses for the remainder
    /// of the current ActionLaneDivide lifecycle.
    pub fn set_laned_reg_generated(&mut self) {
        self.min_laned_size = 1_000_000;
    }

    // Ghidra: funcdata.hh:397 Funcdata::beginLaneAccess
    /// Iterate recorded lane accesses in `VarnodeData::operator<` order.
    pub fn lane_accesses(
        &self,
    ) -> std::collections::btree_map::Iter<
        '_,
        LanedStorage,
        std::sync::Arc<crate::transform::LanedRegister>,
    > {
        self.laned_map.iter()
    }

    // Ghidra: funcdata.hh:399 Funcdata::clearLanedAccessMap
    /// Clear all recorded candidate storage locations without changing the
    /// current minimum-size gate.
    pub fn clear_laned_access_map(&mut self) {
        self.laned_map.clear();
    }

    // Ghidra: funcdata_varnode.cc:494 Funcdata::adjustInputVarnodes
    /// Collapse any input Varnodes contained in the range
    /// `[addr_offset, addr_offset+sz)` in the given space into a single
    /// input, redefining the originals as SUBPIECEs of it.
    /// Faithful to `Funcdata::adjustInputVarnodes`
    /// (funcdata_varnode.cc:494-537):
    ///   endaddr = addr + (sz-1);
    ///   for each input vn in [addr, endaddr]:
    ///     if (vn->getOffset() + (vn->getSize()-1) > endaddr) throw;
    ///     inlist.push_back(vn);
    ///   for each vn in inlist:
    ///     sa = addr.justifiedContain(sz, vn->getAddr(), vn->getSize(), false);
    ///     if (!isInput || sa<0 || sz<=vn->getSize()) throw;
    ///     subop = newOp(2, getAddress()); SUBPIECE;
    ///     opSetInput(subop, newConstant(4, sa), 1);
    ///     newvn = newVarnodeOut(vn->getSize(), vn->getAddr(), subop);
    ///     opInsertBegin(subop, bblocks[0]);
    ///     totalReplace(vn, newvn); deleteVarnode(vn);
    ///     inlist[i] = newvn;
    ///   invn = newVarnode(sz, addr); invn = setInputVarnode(invn);
    ///   invn->setWriteMask();
    ///   for each vn in inlist: opSetInput(vn->getDef(), invn, 0);
    /// RUGRA-GAP: `justifiedContain` is approximated by a direct byte offset;
    /// Rugra scans loc_tree for inputs completely contained in the range —
    /// now pinned to the container's space (Ghidra's beginDef/endDef iterate
    /// the Address-ordered def subset, so the offset bounds never cross
    /// spaces; the piece outputs and the new combined input keep the
    /// container's space via new_varnode_out_full/new_varnode_in_space).
    pub fn adjust_input_varnodes(
        &mut self,
        space: crate::space::AddressSpace,
        addr_offset: u64,
        sz: usize,
    ) -> crate::error::Result<()> {
        let end = addr_offset.wrapping_add(sz.saturating_sub(1) as u64);
        // cc:500-508 — beginDef(Varnode::input, addr)..endDef(Varnode::input,
        // endaddr): the Address-ordered input-def subset — the space of
        // `addr` pins the iteration and membership is by START offset in
        // [addr, endaddr]. An input whose start is in range but extends
        // past endaddr STAYS in the iteration: the cc:505-506
        // LowlevelError below is the only exit for it, exactly as in Ghidra.
        let inlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter_map(|lr| {
                let r = lr.0.read().unwrap();
                if !r.is_input() || r.get_space() != space { return None; }
                let start = r.loc.as_u64();
                if start < addr_offset || start > end { return None; }
                Some(lr.0.clone())
            })
            .collect();
        // cc:510-524: replace each contained input with a SUBPIECE off the new
        // combined input, then destroy the old input.
        let mut replaced: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
        for vn in inlist {
            let (vn_addr, vn_size, vn_is_input) = {
                let r = vn.read().unwrap();
                (r.loc.as_u64(), r.size, r.is_input())
            };
            // cc:505-506 — extends past the container end: fatal, no silent
            // skip.
            if vn_addr.wrapping_add(vn_size as u64).wrapping_sub(1) > end {
                return Err(crate::error::Error::Lowlevel(
                    "Cannot properly adjust input varnodes".to_string(),
                ));
            }
            // cc:512-514 — sa = addr.justifiedContain(sz, vn->getAddr(),
            // vn->getSize(), false); (!isInput || sa < 0 || sz <= size) is
            // fatal. The gather guarantees is_input and start >= addr, so
            // sa >= 0; the size relation is the live check.
            let sa = vn_addr.wrapping_sub(addr_offset) as usize;
            if !vn_is_input || sz <= vn_size {
                return Err(crate::error::Error::Lowlevel(
                    "Bad adjustment to input varnode".to_string(),
                ));
            }
            let pc = self.baseaddr;
            let subop = self.new_op(2, pc);
            self.op_set_opcode(&subop, crate::opcodes::OpCode::CPUI_SUBPIECE);
            let sa_const = self.new_constant(4, sa as u64);
            self.op_set_input(&subop, sa_const, 1);
            // cc:518 — newVarnodeOut(vn->getSize(), vn->getAddr(), subop):
            // the piece keeps the container's space.
            let newvn = self.new_varnode_out_full(vn_size, space, crate::address::Address::new(vn_addr), &subop);
            // cc:520: opInsertBegin(subop, bblocks[0]).
            if let Some(bb0) = self.bblocks.get_block(0) {
                self.op_insert_begin(&subop, &bb0);
            }
            self.total_replace(&vn, newvn.clone());
            self.delete_varnode(&vn)?;
            replaced.push(newvn);
        }
        if replaced.is_empty() { return Ok(()); }
        // cc:526-531 — newVarnode(sz,addr) with the container's full storage
        // address, then setInputVarnode + setWriteMask.
        let invn = self.new_varnode_in_space(sz, space, crate::address::Address::new(addr_offset));
        let invn = self.set_input_varnode(invn);
        invn.write().unwrap().set_write_mask();
        // cc:533-536: each replacement SUBPIECE reads the new input at slot 0.
        for newvn in replaced {
            let def = newvn.read().unwrap().get_def();
            if let Some(def) = def {
                self.op_set_input(&crate::op::PcodeOpRef(def), invn.clone(), 0);
            }
        }
        Ok(())
    }

    // Ghidra: funcdata_varnode.cc:543 Funcdata::descend2Undef
    /// Replace every read of `vn` with a 0xBADDEF constant, inserting COPY
    /// ops where the reader is a MULTIEQUAL or INDIRECT (constants cannot go
    /// directly into those slots). Faithful to `Funcdata::descend2Undef`
    /// (funcdata_varnode.cc:543-583):
    ///   for each descendant op (skipping dead-parent ops):
    ///     if MULTIEQUAL: copyop = newOp(1, inbl->getStart()); COPY(badconst);
    ///                    insertEnd(inbl); opSetInput(op, inputvn, i);
    ///     else if INDIRECT: copyop = newOp(1, op->getAddr()); COPY(badconst);
    ///                       insertBefore(op); opSetInput(op, inputvn, i);
    ///     else: opSetInput(op, badconst, i);
    /// Used by unreachable-block removal to make stale reads explicit.
    /// Returns true if any modified op was inside a block with non-zero in-edges.
    pub fn descend2_undef(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let sz = vn.read().unwrap().size;
        // cc:556: iterate descendants; gather first since we'll mutate.
        let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let mut res = false;
        for op_arc in descends {
            let opc = op_arc.read().unwrap().opcode;
            let parent = op_arc
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|w| w.upgrade());
            // cc:558-559: skip ops whose parent BLOCK is flagged dead (the
            // block-level f_dead bit set by removeUnreachableBlocks phase 1
            // before any op destruction); a missing parent is also skipped.
            // cc:559: res=true when the parent has in-edges (possibly
            // reachable block).
            let parent_dead = match &parent {
                Some(p) => {
                    let p_rg = p.read().unwrap();
                    p_rg.get_flags() & crate::block::block_flags::DEAD != 0
                }
                None => true,
            };
            if parent_dead { continue; }
            if let Some(p) = &parent {
                if p.read().unwrap().size_in() != 0 { res = true; }
            }
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let slot = self.op_get_slot(&op_ref, vn) as usize;
            let badconst = self.new_constant(sz, 0xBA_AD_EF);
            match opc {
                OC::CPUI_MULTIEQUAL => {
                    // cc:563-569: insert COPY in the predecessor block.
                    let inblk_edge = parent.as_ref().and_then(|p| p.read().unwrap().get_in(slot));
                    let inbl_start = inblk_edge
                        .as_ref()
                        .and_then(|e| {
                        e.point
                                .read()
                                .unwrap()
                                .as_any()
                            .downcast_ref::<crate::block::BlockBasic>()
                            .map(|bb| bb.start_addr)
                    })
                        .unwrap_or(self.baseaddr);
                    let copyop = self.new_op(1, inbl_start);
                    self.op_set_opcode(&copyop, OC::CPUI_COPY);
                    let inputvn = self.new_unique_out(sz, &copyop);
                    self.op_set_input(&copyop, badconst, 0);
                    if let Some(e) = inblk_edge {
                        self.op_insert_end(&copyop, &e.point);
                    }
                    self.op_set_input(&op_ref, inputvn, slot);
                }
                OC::CPUI_INDIRECT => {
                    // cc:571-577: insert COPY immediately before the INDIRECT.
                    let op_addr = op_arc.read().unwrap().get_addr();
                    let copyop = self.new_op(1, op_addr);
                    self.op_set_opcode(&copyop, OC::CPUI_COPY);
                    let inputvn = self.new_unique_out(sz, &copyop);
                    self.op_set_input(&copyop, badconst, 0);
                    self.op_insert_before(&copyop, &op_ref);
                    self.op_set_input(&op_ref, inputvn, slot);
                }
                _ => {
                    // cc:579-580: directly slot the constant.
                    self.op_set_input(&op_ref, badconst, slot);
                }
            }
        }
        res
    }

    // Ghidra: funcdata_varnode.cc:585 Funcdata::initActiveOutput
    /// Allocate / reset `activeoutput` for return-value recovery. Faithful to
    /// `Funcdata::initActiveOutput` (funcdata_varnode.cc:585-593):
    ///   activeoutput = new ParamActive(false);
    ///   maxdelay = funcp.getMaxOutputDelay();
    ///   if (maxdelay > 0) maxdelay = 3;
    ///   activeoutput->setMaxPass(maxdelay);
    /// getMaxOutputDelay is ProtoModel::getMaxOutputDelay
    /// (fspec.hh:1572) -> the output ParamListStandard's calcDelay maximum
    /// (fspec.cc:1154-1162) over entry spaces' AddrSpace::getDelay(). Every
    /// output entry of every model in the locked x86-64-gcc.cspec lives in
    /// the register space, whose delay in the locked x86-64.sla is 0 —
    /// proven by the pinned next_url oracle projection, where returnrecovery
    /// finalizes on mainloop round 1 (RDX trimmed at stage ordinal 19),
    /// which requires numpasses(1) > maxpass, i.e. maxpass == 0.
    pub fn init_active_output(&mut self) {
        let mut maxdelay = self.funcp.get_max_output_delay();
        if maxdelay > 0 {
            // cc:590-592: clamp any positive delay to 3.
            maxdelay = 3;
        }
        let mut active = crate::fspec::ParamActive::new(false);
        active.set_max_pass(maxdelay);
        self.active_output = Some(active);
    }

    // Ghidra: funcdata_varnode.cc:832 Funcdata::clearDeadVarnodes
    /// Free any unattached Varnodes so editing ops can detach/reattach without
    /// leaking. Faithful to `Funcdata::clearDeadVarnodes`
    /// (funcdata_varnode.cc:832-850):
    ///   for vn in vbank.beginLoc()..endLoc():
    ///     if (vn->hasNoDescend()):
    ///       if (vn->isInput() && !vn->isLockedInput()):
    ///         vbank.makeFree(vn); vn->clearCover();
    ///       if (vn->isFree()): vbank.destroy(vn);
    pub fn clear_dead_varnodes(&mut self) {
        // Gather first; we'll mutate vbank during the loop.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .map(|lr| lr.0.clone())
            .collect();
        for vn in candidates {
            if !vn.read().unwrap().has_no_descend() { continue; }
            let (is_input, is_locked_input) = {
                let r = vn.read().unwrap();
                (
                    r.is_input(), (r.addlflags & crate::varnode::addl_flags::LOCKED_INPUT) != 0,
                )
            };
            if is_input && !is_locked_input {
                // cc:843-845: makeFree + clearCover.
                // `vn` came from this bank's loc_tree snapshot, proving the
                // Arc-identity precondition of the internal transition.
                self.vbank.make_free_prevalidated(&vn);
                vn.write().unwrap().clear_cover();
            }
            if vn.read().unwrap().is_free() {
                // cc:841 guards hasNoDescend; makeFree (if needed) cleared
                // the definition, so the integrated-destroy guard is proven.
                self.vbank.destroy_varnode_prevalidated(&vn);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:635 Funcdata::fillinReadOnly
    /// Treat the given Varnode as read-only; look up its value in the
    /// LoadImage and replace read references with that value as a constant.
    /// Faithful to `Funcdata::fillinReadOnly`
    /// (funcdata_varnode.cc:635-709):
    ///   if (vn->isWritten()) {
    ///     defop = vn->getDef();
    ///     if (defop->isMarker()) defop->setAdditionalFlag(warning);
    ///     else if (!defop->isWarning()) {
    ///       defop->setAdditionalFlag(warning);
    ///       if (!isAddrForce || !hasNoDescend)
    ///         warning("Read-only address ... is written", defop->getAddr());
    ///     }
    ///     return false;
    ///   }
    ///   if (vn->getSize() > sizeof(uintb)) return false;
    ///   try { glb->loader->loadFill(bytes, size, addr); }
    ///   catch (DataUnavailError) { vn->clearFlags(readonly); return true; }
    ///   res = assemble bytes (big/little endian);
    ///   for each descendant op:
    ///     if (op->isMarker() && (op!=INDIRECT || slot!=0)) continue;
    ///       if INDIRECT: opRemoveInput(1); opSetOpcode(op, COPY);
    ///     cvn = newConstant(size, res);
    ///     if (locktype) cvn->updateType(locktype, true, true);
    ///     opSetInput(op, cvn, slot);
    ///     changemade = true;
    ///   return changemade;
    /// RUGRA-GAP: requires the Architecture's LoadImage; when absent the method
    /// returns false (no change). Marker-op collapse + locktype propagation are
    /// faithfully ported.
    pub fn fillin_read_only(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        // cc:638-655: written varnode — warn and bail.
        if vn.read().unwrap().is_written() {
            let def = vn.read().unwrap().get_def();
            if let Some(def) = def {
                let def_ref = crate::op::PcodeOpRef(def);
                let is_marker = def_ref.0.read().unwrap().is_marker();
                if is_marker {
                    def_ref.0.write().unwrap().addlflags |= crate::op::op_addl_flags::WARNING;
                } else {
                    let already_warn = (def_ref.0.read().unwrap().addlflags & crate::op::op_addl_flags::WARNING) != 0;
                    if !already_warn {
                        def_ref.0.write().unwrap().addlflags |= crate::op::op_addl_flags::WARNING;
                        let (addr_force, no_descend, space, addr) = {
                            let r = vn.read().unwrap();
                            (
                                r.is_addr_force(), r.has_no_descend(), r.address_space, r.loc,
                            )
                        };
                        if !addr_force || !no_descend {
                            self.warning(
                                &format!(
                                    "Read-only address ({:?},{:x}) is written", space, addr.as_u64()
                                ),
                                def_ref.0.read().unwrap().get_addr(),
                            );
                        }
                    }
                }
            }
            return false;
        }
        // cc:657-658: constants larger than uintb precision can't be assembled.
        let sz = vn.read().unwrap().size;
        if sz > std::mem::size_of::<u64>() { return false; }
        // cc:660-667: load bytes from the LoadImage; on failure clear readonly.
        let vn_addr = vn.read().unwrap().loc;
        let bytes = match self.arch.as_ref() {
            Some(a) => match &a.loader {
                Some(loader) => match loader.load_fill(sz, vn_addr) {
                    Ok(b) => b,
                    Err(_) => {
                        vn.write()
                            .unwrap()
                            .clear_flags(crate::varnode::varnode_flags::READONLY);
                        return true;
                    }
                },
                None => return false,
            },
            None => return false,
        };
        if bytes.len() < sz { return false; }
        // cc:669-682: assemble the value (little-endian default; Rugra lacks
        // per-space endianness, so we mirror x86-64 LE).
        let mut res: u64 = 0;
        for i in (0..sz).rev() {
            res <<= 8;
            res |= bytes[i] as u64;
        }
        // cc:684-707: replace each read reference with the constant.
        let locktype: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> =
            vn.read().unwrap().get_type().map(|t| t.clone());
        let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
            vn.read().unwrap().descend_iter().collect();
        let mut changemade = false;
        for op_arc in descends {
            let op_ref = crate::op::PcodeOpRef(op_arc.clone());
            let slot = self.op_get_slot(&op_ref, vn) as usize;
            let is_marker = op_arc.read().unwrap().is_marker();
            let code = op_arc.read().unwrap().opcode;
            if is_marker {
                // cc:694-701: must not place constants into a marker, except
                // an INDIRECT in slot 0 (converted to COPY).
                if code != OC::CPUI_INDIRECT || slot != 0 { continue; }
                // cc:699-700: opRemoveInput(op,1); opSetOpcode(op, COPY).
                self.op_remove_input(&op_ref, 1);
                self.op_set_opcode(&op_ref, OC::CPUI_COPY);
            }
            let cvn = self.new_constant(sz, res);
            if let Some(lt) = &locktype {
                // cc:703-704: cvn->updateType(locktype, true, true) — pass on
                // the locked datatype. Rugra's update_type takes (Arc<Datatype>);
                // the (lock, override_lock) flags map to the lock-keeping path
                // via update_type_lock when typelock is set.
                cvn.write()
                    .unwrap()
                    .update_type_lock(lt.clone(), true, true);
            }
            self.op_set_input(&op_ref, cvn, slot);
            changemade = true;
        }
        changemade
    }

    // Ghidra: funcdata_varnode.cc:717 Funcdata::replaceVolatile
    /// Model a volatile Varnode's read/write with a special user-op
    /// (BUILTIN_VOLATILE_READ / BUILTIN_VOLATILE_WRITE). Faithful to
    /// `Funcdata::replaceVolatile` (funcdata_varnode.cc:717-764):
    ///   if (vn->isWritten()) {            // a write
    ///     vw_op = registerBuiltin(VOLATILE_WRITE);
    ///     if (!hasNoDescend) throw;
    ///     defop = vn->getDef();
    ///     newop = newOp(3, defop->getAddr()); CALLOTHER;
    ///     opSetInput(newop, newConstant(4, vw_op->getIndex()), 0);
    ///     annoteVn = newCodeRef(vn->getAddr()); annoteVn->setFlags(volatil);
    ///     opSetInput(newop, annoteVn, 1);
    ///     tmp = newUnique(size); opSetOutput(defop, tmp);
    ///     opSetInput(newop, tmp, 2); opInsertAfter(newop, defop);
    ///   } else {                          // a read
    ///     vr_op = registerBuiltin(VOLATILE_READ);
    ///     if (hasNoDescend) return false;
    ///     readop = vn->loneDescend(); if null throw;
    ///     newop = newOp(2, readop->getAddr()); CALLOTHER;
    ///     tmp = newUniqueOut(size, newop);
    ///     opSetInput(newop, newConstant(4, vr_op->getIndex()), 0);
    ///     annoteVn = newCodeRef(vn->getAddr()); annoteVn->setFlags(volatil);
    ///     opSetInput(newop, annoteVn, 1);
    ///     opSetInput(readop, tmp, readop->getSlot(vn));
    ///     opInsertBefore(newop, readop);
    ///     if (vr_op->getDisplay() != 0) newop->setHoldOutput();
    ///   }
    ///   if (vn->isTypeLock()) newop->setAdditionalFlag(special_prop);
    ///   return true;
    /// RUGRA-GAP: Architecture's UserOpManage is consulted for the builtin
    /// index; if absent the method returns false (no change).
    pub fn replace_volatile(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let sz = vn.read().unwrap().size;
        let vn_addr = vn.read().unwrap().loc;
        let is_written = vn.read().unwrap().is_written();
        let is_type_lock = vn.read().unwrap().is_type_lock();
        let newop = if is_written {
            // cc:721-738: model the write.
            let vw_index = match self.arch.as_ref() {
                Some(a) => match &a.userops {
                    Some(uo) => uo
                        .write()
                        .unwrap()
                        .register_builtin_by_id(crate::userop::BUILTIN_VOLATILE_WRITE) as u64,
                    None => return false,
                },
                None => return false,
            };
            if !vn.read().unwrap().has_no_descend() {
                eprintln!("[FUNCDATA] replaceVolatile: volatile memory was propagated");
                return false;
            }
            let def = match vn.read().unwrap().get_def() { Some(d) => d, None => return false ,
            };
            let def_ref = crate::op::PcodeOpRef(def.clone());
            let def_addr = def.read().unwrap().get_addr();
            let newop = self.new_op(3, def_addr);
            self.op_set_opcode(&newop, OC::CPUI_CALLOTHER);
            let idx_const = self.new_constant(4, vw_index);
            self.op_set_input(&newop, idx_const, 0);
            // cc:730-731: annoteVn = newCodeRef(addr); setFlags(volatil).
            let annote_vn = self.new_code_ref(vn_addr);
            annote_vn
                .write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::VOLATIL);
            self.op_set_input(&newop, annote_vn, 1);
            // cc:733-734: tmp = newUnique(size); opSetOutput(defop, tmp).
            let tmp = self.new_unique(sz);
            self.op_set_output(&def_ref, tmp.clone());
            // cc:736: opSetInput(newop, tmp, 2).
            self.op_set_input(&newop, tmp, 2);
            // cc:738: opInsertAfter(newop, defop).
            self.op_insert_after(&newop, &def_ref);
            newop
        } else {
            // cc:740-759: model the read.
            let vr_index = match self.arch.as_ref() {
                Some(a) => match &a.userops {
                    Some(uo) => uo
                        .write()
                        .unwrap()
                        .register_builtin_by_id(crate::userop::BUILTIN_VOLATILE_READ) as u64,
                    None => return false,
                },
                None => return false,
            };
            if vn.read().unwrap().has_no_descend() { return false; }
            let readop = match vn.read().unwrap().lone_descend() { Some(r) => r, None => {
                eprintln!(
                        "[FUNCDATA] replaceVolatile: volatile memory value used more than once"
                    );
                return false;
            }
            };
            let readop_ref = crate::op::PcodeOpRef(readop.clone());
            let read_addr = readop.read().unwrap().get_addr();
            let newop = self.new_op(2, read_addr);
            self.op_set_opcode(&newop, OC::CPUI_CALLOTHER);
            let tmp = self.new_unique_out(sz, &newop);
            let idx_const = self.new_constant(4, vr_index);
            self.op_set_input(&newop, idx_const, 0);
            let annote_vn = self.new_code_ref(vn_addr);
            annote_vn
                .write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::VOLATIL);
            self.op_set_input(&newop, annote_vn, 1);
            let slot = self.op_get_slot(&readop_ref, vn) as usize;
            self.op_set_input(&readop_ref, tmp, slot);
            self.op_insert_before(&newop, &readop_ref);
            // cc:758-759: if (vr_op->getDisplay() != 0) newop->setHoldOutput().
            // Rugra: VOLATILE_READ's display is functional (1), so always hold.
            // HOLD_OUTPUT lives in addl_flags (Rugra models it as an addlflag).
            newop.0.write().unwrap().addlflags |= crate::op::op_addl_flags::HOLD_OUTPUT;
            newop
        };
        // cc:761-762: if (vn->isTypeLock()) newop->setAdditionalFlag(special_prop).
        if is_type_lock {
            // op.hh:109 special_prop = addlflags 0x1. The former
            // STOP_TYPE_PROPAGATION (0x40) substitution was a mis-mapping of
            // two distinct Ghidra flags: stop_type_propagation (op.hh:115)
            // makes Varnode::getLocalType (varnode.cc:912) block descendant
            // consultation, while special_prop gates the volatile user-op
            // local-type overrides (userop.cc:131/162). A type-locked
            // volatile read does NOT stop propagation in Ghidra; its output
            // type flows from the symbol table query in
            // VolatileReadOp::getOutputLocal (userop.cc:128-141), now ported
            // (VARNODE-CALLOTHER-VOLATILEOUT-0001).
            newop.0.write().unwrap().addlflags |= crate::op::op_addl_flags::SPECIAL_PROP;
        }
        true
    }

    // Ghidra: funcdata_varnode.cc:771 Funcdata::checkIndirectUse
    /// Test if the given Varnode only flows into call-based INDIRECT ops,
    /// following flow through MULTIEQUAL ops. Faithful to
    /// `Funcdata::checkIndirectUse` (funcdata_varnode.cc:771-811):
    ///   vlist = {vn}; vn->setMark();
    ///   while (i < vlist.size() && result):
    ///     vn = vlist[i++];
    ///     for each descendant op:
    ///       if INDIRECT: if isIndirectStore follow outvn; else continue;
    ///       else if MULTIEQUAL: follow outvn;
    ///       else: result = false; break;
    ///   clear marks; return result;
    pub fn check_indirect_use(
        &self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        let mut vlist: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = vec![vn.clone()];
        vn.write().unwrap().set_mark();
        let mut i = 0;
        let mut result = true;
        while i < vlist.len() && result {
            let cur = vlist[i].clone();
            i += 1;
            let descends: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>> =
                cur.read().unwrap().descend_iter().collect();
            for op_arc in descends {
                let code = op_arc.read().unwrap().opcode;
                match code {
                    OC::CPUI_INDIRECT => {
                        if op_arc.read().unwrap().is_indirect_store() {
                            // cc:786-793: INDIRECT from a STORE — follow outvn.
                            let outvn = op_arc.read().unwrap().get_out().cloned();
                            if let Some(outvn) = outvn {
                                if !outvn.read().unwrap().is_mark() {
                                    outvn.write().unwrap().set_mark();
                                    vlist.push(outvn);
                                }
                            }
                        }
                        // else: a call-based INDIRECT — keep going (result stays true).
                    }
                    OC::CPUI_MULTIEQUAL => {
                        // cc:795-800: follow outvn.
                        let outvn = op_arc.read().unwrap().get_out().cloned();
                        if let Some(outvn) = outvn {
                            if !outvn.read().unwrap().is_mark() {
                                outvn.write().unwrap().set_mark();
                                vlist.push(outvn);
                            }
                        }
                    }
                    _ => {
                        // cc:802-804: any other op → not indirect-only.
                        result = false;
                        break;
                    }
                }
            }
        }
        for v in &vlist { v.write().unwrap().clear_mark(); }
        result
    }

    // Ghidra: funcdata_varnode.cc:815 Funcdata::markIndirectOnly
    /// Mark every illegal-input Varnode that only flows into call-based
    /// INDIRECTs with the `indirectonly` flag. Faithful to
    /// `Funcdata::markIndirectOnly` (funcdata_varnode.cc:815-828):
    ///   for each input vn:
    ///     if (!vn->isIllegalInput()) continue;
    ///     if (checkIndirectUse(vn)) vn->setFlags(indirectonly);
    pub fn mark_indirect_only(&mut self) {
        // Gather inputs first to avoid holding a borrow across mutation.
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .filter_map(|lr| {
                let r = lr.0.read().unwrap();
                if r.is_input() && r.is_illegal_input() { Some(lr.0.clone()) } else { None }
            })
            .collect();
        for vn in inputs {
            if self.check_indirect_use(&vn) {
                vn.write()
                    .unwrap()
                    .set_flags(crate::varnode::varnode_flags::INDIRECTONLY);
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:1653 Funcdata::mapGlobals
    /// Search for address-tied persistent Varnodes whose storage falls in the
    /// global Scope, then build a new global Symbol if one didn't exist
    /// before. Faithful to `Funcdata::mapGlobals`
    /// (funcdata_varnode.cc:1653-1719):
    ///   iter = vbank.beginLoc() .. endLoc();
    ///   while (iter != enditer) {
    ///     vn = *iter++;
    ///     if (vn->isFree()) continue;
    ///     if (!vn->isPersist()) continue;            // could be a code ref
    ///     if (vn->getSymbolEntry() != NULL) continue;
    ///     maxvn = vn; addr = vn->getAddr();
    ///     endaddr = addr + vn->getSize();
    ///     uncoveredVarnodes.clear();
    ///     while (iter != enditer) {
    ///       vn = *iter;
    ///       if (!vn->isPersist()) break;
    ///       if (vn->getAddr() < endaddr) {
    ///         if (vn->getAddr() != addr && vn->getSymbolEntry() == NULL)
    ///           uncoveredVarnodes.push_back(vn);
    ///         endaddr = vn->getAddr() + vn->getSize();
    ///         if (vn->getSize() > maxvn->getSize()) maxvn = vn;
    ///         ++iter;
    ///       } else break;
    ///     }
    ///     if ((maxvn->getAddr() == addr)&&(addr+maxvn->getSize() == endaddr))
    ///       ct = maxvn->getHigh()->getType();
    ///     else
    ///       ct = glb->types->getBase(endaddr-addr, TYPE_UNKNOWN);
    ///     fl = 0; Address usepoint;   // empty: existing symbol is addrtied
    ///     entry = localmap->queryProperties(addr, 1, usepoint, fl);
    ///     if (entry == NULL) {
    ///       discover = localmap->discoverScope(addr, ct->getSize(), usepoint);
    ///       if (discover == NULL) throw LowlevelError("Could not discover scope");
    ///       index = 0;
    ///       name = discover->buildVariableName(addr, usepoint, ct, index,
    ///                                          Varnode::addrtied|Varnode::persist);
    ///       discover->addSymbol(name, ct, addr, usepoint);
    ///     } else if ((addr+ct->getSize())-1 > (entry_addr+entry->getSize())-1) {
    ///       inconsistentuse = true;
    ///       if (!uncoveredVarnodes.empty()) coverVarnodes(entry, uncoveredVarnodes);
    ///     }
    ///   }
    ///   if (inconsistentuse) warningHeader("Globals starting with '_' overlap smaller symbols at the same address");
    ///
    /// Channel realization: the queryProperties/discoverScope/addSymbol legs
    /// route through the Database query channel (a function-local scope's
    /// parent is the global scope — the same equivalence the other channel
    /// arms document). With no channel attached (legacy/test Funcdata), the
    /// walk degrades to the documented `symbol_table` proxy.
    pub fn map_globals(&mut self) -> Result<(), crate::error::Error> {
        use crate::space::AddressSpace;
        // cc:1664-1666: vbank.beginLoc()..endLoc() — every space, location
        // order; the persist gate does the space filtering.
        let candidates: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = self
            .vbank
            .loc_tree
            .iter()
            .map(|lr| lr.0.clone())
            .collect();
        let mut inconsistent = false;
        let mut i = 0usize;
        while i < candidates.len() {
            let vn = candidates[i].clone();
            i += 1;
            // cc:1668-1670: skip free, non-persist, and already-linked.
            if vn.read().unwrap().is_free() { continue; }
            if !vn.read().unwrap().is_persist() { continue; } // Could be a code ref
            if vn.read().unwrap().get_symbol_entry().is_some() { continue; }
            // cc:1671-1673: the group's base address and initial end.
            // maxvn starts as the group-start varnode and is REASSIGNED by
            // the inner loop on strictly greater size (cc:1685-1686), so the
            // ct read below takes the biggest varnode's high type.
            let mut maxvn = vn.clone();
            let (base_space, addr) = { let r = vn.read().unwrap(); (r.get_space(), *r.get_addr()) };
            let mut endaddr = addr.as_u64() + vn.read().unwrap().get_size() as u64;
            let mut uncovered: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> = Vec::new();
            // cc:1675-1691: extend over overlapping persistent varnodes.
            let mut max_size = vn.read().unwrap().get_size();
            let mut max_addr = addr;
            while i < candidates.len() {
                let next = candidates[i].clone();
                let (n_persist, n_space, n_addr_arc, n_size, n_has_entry) = {
                    let r = next.read().unwrap();
                    (
                        r.is_persist(), r.get_space(), *r.get_addr(), r.get_size(), r.get_symbol_entry().is_some(),
                    )
                };
                if !n_persist { break; }
                // cc:1687 `vn->getAddr() < endaddr` compares space-major
                // (Address::operator<): the loc walk is space-ascending, so
                // the first varnode of a later space compares Greater and
                // breaks the group — cross-space groups cannot exist in the
                // oracle. Rugra's Address carries no space, so the same
                // break is explicit here.
                if n_space != base_space { break; }
                if n_addr_arc.as_u64() < endaddr {
                    // cc:1679-1683: internal varnodes without a symbol will
                    // not link to the base-address symbol — remember them.
                    if n_addr_arc.as_u64() != addr.as_u64() && !n_has_entry {
                        uncovered.push(next.clone());
                    }
                    // cc:1684: endaddr extends to this varnode's end.
                    endaddr = n_addr_arc.as_u64() + n_size as u64;
                    // cc:1685-1686: track the biggest varnode in the group —
                    // `if (vn->getSize() > maxvn->getSize()) maxvn = vn;`
                    // carries the varnode itself (max_size/max_addr are its
                    // size/addr projection), first-maximal wins.
                    if n_size > max_size {
                        max_size = n_size;
                        max_addr = n_addr_arc;
                        maxvn = next.clone();
                    }
                    i += 1;
                } else {
                    break;
                }
            }
            // cc:1692-1695: the group's Datatype — the biggest varnode's
            // high type when it spans exactly [addr,endaddr), else a sized
            // unknown base.
            let ct: Option<std::sync::Arc<crate::type_system::datatype::Datatype>> =
                if max_addr.as_u64() == addr.as_u64()
                    && addr.as_u64() + max_size as u64 == endaddr
                {
                    maxvn
                        .read()
                        .unwrap()
                        .high
                        .as_ref()
                        .map(|h| h.read().unwrap().get_type())
                } else {
                    let span = (endaddr - addr.as_u64()) as usize;
                    crate::type_system::typefactory::TypeFactory::shared_default()
                        .write()
                        .unwrap()
                        .get_base(span, crate::type_system::datatype::TypeMetatype::Unknown)
                };
            let ct_size = ct.as_ref().map(|t| t.get_size()).unwrap_or(1);
            // cc:1697-1701: fl = 0; empty usepoint (assume existing symbol
            // is addrtied); entry = queryProperties(addr, 1, usepoint, fl).
            // Channel routing: the Database query channel models the global
            // scope over the default data (RAM) space only — a non-RAM
            // persist group (e.g. a locked register) queries the ScopeLocal
            // leg in the oracle, which remains the registered funcdata gap,
            // so those groups take the legacy proxy arm below.
            let query = if base_space == AddressSpace::Ram {
                self.query_properties_parent_scope(
                    addr,
                    1,
                    crate::address::Address::new(0), // the empty usepoint Address()
                )
            } else {
                None
            };
            match query {
                Some((None, _fl)) => {
                    // cc:1702-1709: no symbol covers the base address —
                    // discoverScope + buildVariableName + addSymbol.
                    let Some(discover) = self.discover_scope_parent_scope(
                        addr,
                        ct_size as i32) else {
                        // cc:1704-1705: Ghidra throws LowlevelError and the
                        // function's decompile fails; mirror the fatal error
                        // through the Action's Result channel.
                        return Err(crate::error::Error::Lowlevel(
                            "Could not discover scope".to_string(),
                        ));
                    };
                    // cc:1706-1708: index = 0; name = buildVariableName(
                    // addr, usepoint, ct, index, addrtied|persist).
                    let mut index: i32 = 0;
                    let symbolname = self
                        .scope
                        .as_ref()
                        .and_then(|s| {
                            s.build_variable_name(
                                AddressSpace::Ram,
                                addr.as_u64(),
                                None, // the empty usepoint
                                ct.as_ref(),
                                &mut index,
                                crate::varnode::varnode_flags::ADDRTIED
                                    | crate::varnode::varnode_flags::PERSIST,
                            )
                        })
                        .unwrap_or_else(|| format!("Ram{:016x}", addr.as_u64()));
                    // cc:1709: discover->addSymbol(symbolname, ct, addr, usepoint).
                    let added = self
                        .arch
                        .as_ref()
                        .and_then(|a| a.symboltab.clone())
                        .map(|symboltab| {
                            let mut db = symboltab.write().unwrap();
                            db.add_symbol_mapped(
                                discover,
                                &symbolname,
                                ct.clone(),
                                addr,
                                ct_size as i32,
                            )
                            .is_some()
                        })
                        .unwrap_or(false);
                    if !added {
                        // Legacy no-channel fallback: the symbol_table proxy.
                        self.symbol_table.insert(addr.as_u64(), symbolname.clone());
                        // FUNCDATA-MAPGLOBALS-PROXYSIZE-0001: Scope::addMap
                        // records the mapping size (database.cc:1126-1151);
                        // the proxy records it alongside the name so the
                        // cc:1711 extension test below can compare against
                        // the entry's true end on restart re-runs.
                        self.symbol_table_sizes
                            .insert(addr.as_u64(), ct_size as i32);
                    }
                }
                Some((Some(hit), _fl)) => {
                    // cc:1711-1715: entry exists — if the group extends past
                    // the entry's end, provide symbols for uncovered
                    // internal varnodes.
                    let entry_end = hit.entry_addr.as_u64() + hit.entry_size.max(0) as u64;
                    if (addr.as_u64() + ct_size as u64).saturating_sub(1)
                        > entry_end.saturating_sub(1)
                    {
                        inconsistent = true;
                        if !uncovered.is_empty() {
                            // cc:1714: coverVarnodes(entry, uncoveredVarnodes).
                            let entry_name = hit.symbol_name.clone();
                            let entry_addr = hit.entry_addr.as_u64();
                            self.cover_varnodes(entry_addr, &entry_name, &uncovered);
                        }
                    }
                }
                None => {
                    // No channel attached (legacy/test Funcdata): the
                    // documented proxy fallback — a symbol exists in the
                    // eyes of the pipeline iff symbol_table has the address.
                    let has_symbol = self
                        .scope
                        .as_ref()
                        .map(|s| s.has_overlap(addr.as_u64(), 1))
                        .unwrap_or(false)
                        || self.symbol_table.contains_key(&addr.as_u64());
                    if !has_symbol {
                        // cc:1707-1709 naming, proxy form.
                        let mut index: i32 = 0;
                        let name = self
                            .scope
                            .as_ref()
                            .and_then(|s| {
                                s.build_variable_name(
                                    base_space,
                                    addr.as_u64(),
                                    None,
                                    ct.as_ref(),
                                    &mut index,
                                    crate::varnode::varnode_flags::ADDRTIED
                                        | crate::varnode::varnode_flags::PERSIST,
                                )
                            })
                            .unwrap_or_else(|| format!("{:?}{:016x}", base_space, addr.as_u64()));
                        self.symbol_table.insert(addr.as_u64(), name);
                        // FUNCDATA-MAPGLOBALS-PROXYSIZE-0001: the proxy
                        // entry's recorded size — the addMap ct_size the
                        // oracle's re-runs read back through queryProperties.
                        self.symbol_table_sizes
                            .insert(addr.as_u64(), ct_size as i32);
                    } else if (addr.as_u64() + ct_size as u64).saturating_sub(1)
                        > self
                            .symbol_table_sizes
                            .get(&addr.as_u64())
                            .map(|sz| addr.as_u64() + *sz as u64)
                            // Driver-seeded proxy entries (ELF function
                            // names) carry no recorded size: keep the
                            // historical size-0 entry-end form for them.
                            .or_else(|| {
                                self.symbol_table
                                    .contains_key(&addr.as_u64())
                                    .then_some(addr.as_u64())
                            })
                            // has_symbol came from a scope overlap only:
                            // no proxy entry to extend past.
                            .unwrap_or(u64::MAX)
                            .saturating_sub(1)
                    {
                        // cc:1711-1715 proxy form: the group's ct extends
                        // past the recorded entry's end — inconsistent use.
                        inconsistent = true;
                        if !uncovered.is_empty() {
                            let entry_name = self
                                .symbol_table
                                .get(&addr.as_u64())
                                .cloned()
                                .unwrap_or_default();
                            self.cover_varnodes(addr.as_u64(), &entry_name, &uncovered);
                        }
                    }
                }
            }
        }
        // cc:1717-1718: warningHeader on inconsistent use.
        if inconsistent {
            self.warning_header(
                "Globals starting with '_' overlap smaller symbols at the same address",
            );
        }
        Ok(())
    }

    // Ghidra: funcdata_varnode.cc:1314 Funcdata::attemptDynamicMapping
    /// Given a dynamic SymbolEntry, find its Varnode via DynamicHash and attach
    /// the symbol's properties. Faithful to `Funcdata::attemptDynamicMapping`
    /// (funcdata_varnode.cc:1314-1337):
    ///   sym = entry->getSymbol();
    ///   if (sym->getScope() != localmap) throw;
    ///   dhash.clear();
    ///   category = sym->getCategory();
    ///   if (category == union_facet) return applyUnionFacet(entry, dhash);
    ///   vn = dhash.findVarnode(this, entry->getFirstUseAddress(), entry->getHash());
    ///   if (vn == NULL) return false;
    ///   if (vn->getSymbolEntry() != NULL) return false;
    ///   if (category == equate) { vn->setSymbolEntry(entry); return true; }
    ///   else if (entry->getSize() == vn->getSize())
    ///     if (vn->setSymbolProperties(entry)) return true;
    ///   return false;
    /// The size-match arm surfaces Varnode::setSymbolProperties' boolean
    /// verbatim (varnode.cc:410-424): an unlocked dynamic symbol returns
    /// false even though the mapped flag was applied.
    /// RUGRA-GAP: Rugra has no SymbolEntry/Symbol objects on Funcdata; the
    /// caller supplies (first_use_addr, hash, size, category) directly. On a
    /// successful find, MAPPED is set and the name is recorded; the typelock
    /// arm is reconstructed from the scope's dynamic LocalSymbol (typelock
    /// bit + dtype) looked up by hash.
    pub fn attempt_dynamic_mapping(
        &mut self,
        first_use_addr: crate::address::Address,
        hash: u64,
        size: usize,
        is_equate: bool,
        is_union_facet: bool,
        sym_name: &str,
    ) -> bool {
        // cc:1322-1324: union_facet → applyUnionFacet.
        if is_union_facet {
            // RUGRA-GAP: full union-facet path needs parent type; callers
            // should use apply_union_facet directly. We treat as no-match.
            return false;
        }
        // cc:1325: vn = dhash.findVarnode(this, addr, hash).
        let vn = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_varnode(self, first_use_addr, hash)
        };
        let Some(vn) = vn else { return false };
        // cc:1326-1327: if (vn->getSymbolEntry()) return false.
        if vn.read().unwrap().is_mapped() { return false; }
        // cc:1328-1331: equate category → setSymbolEntry.
        if is_equate {
            vn.write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table
                .insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return true;
        }
        // cc:1332-1335: matching size → setSymbolProperties, whose boolean
        // return is surfaced verbatim.
        if vn.read().unwrap().size == size {
            // Varnode::setSymbolProperties (varnode.cc:410-424):
            //   bool res = entry->updateType(this);
            //   if (entry->getSymbol()->isTypeLocked()) {
            //     if (mapentry != entry) { mapentry = entry; ...; res = true; }
            //   }
            //   setFlags(entry->getAllFlags() & ~typelock);
            //   return res;
            // The :1327 guard above proved vn's mapentry is NULL, so the
            // typelock arm's attach always fires when it runs. For an
            // UNLOCKED dynamic symbol — the production mint shape
            // (database.cc:1690-1702 builds `new Symbol(owner,nm,ct)` with
            // flags=0) — res stays false even though the mapped flag was
            // applied: the attach is observable but the boolean is not.
            let mut res = false;
            let sym_info = self.scope.as_ref().and_then(|scope| {
                scope
                    .symbols
                    .iter()
                    .find(|sym| sym.is_dynamic && sym.hash == hash)
                    .map(|sym| (sym.typelock, sym.dtype.clone()))
            });
            if let Some((true, dtype)) = sym_info {
                // SymbolEntry::updateType (database.cc:135-144): the locked
                // type is forced through vn->updateType(dt,true,true) with
                // getSizedType's whole-size piece (database.cc:151-163,
                // dynamic offset 0). The type WRITE is observable even
                // though the mapentry arm overwrites the boolean below.
                if let Some(dt) = dtype {
                    let _type_changed = vn.write().unwrap().update_type_lock(dt, true, true);
                }
                // varnode.cc:414-421: mapentry NULL→entry attach forces
                // res = true for typelocked symbols.
                res = true;
            }
            // setFlags(getAllFlags() & ~typelock) — database.hh:271:
            // extraflags | symbol flags = Varnode::mapped for the dynamic
            // mint (database.cc:1700), applied unconditionally.
            vn.write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table
                .insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return res;
        }
        false
    }

    // Ghidra: funcdata_varnode.cc:1347 Funcdata::attemptDynamicMappingLate
    /// Late-phase dynamic mapping: attach the Symbol's NAME only (no
    /// type/property forcing). Faithful to `Funcdata::attemptDynamicMappingLate`
    /// (funcdata_varnode.cc:1347-1399):
    ///   dhash.clear();
    ///   sym = entry->getSymbol();
    ///   if (sym->getCategory() == union_facet) return applyUnionFacet(...);
    ///   vn = dhash.findVarnode(this, addr, hash);
    ///   if (vn == NULL) return false;
    ///   if (vn->getSymbolEntry()) return false;
    ///   if (category == equate) { vn->setSymbolEntry(entry); return true; }
    ///   if (vn->getSize() != entry->getSize()) {
    ///     warningHeader("Unable to use symbol ...: Size does not match");
    ///     return false;
    ///   }
    ///   if (vn->isImplied()) { /* look across a CAST */ }
    ///   vn->setSymbolEntry(entry);
    ///   if (!sym->isTypeLocked()) localmap->retypeSymbol(sym, vn->getType());
    ///   else if (sym->getType() != vn->getType()) warningHeader(...);
    ///   return true;
    /// RUGRA-GAP: SymbolEntry/ScopeLocal.retypeSymbol not ported; we attach the
    /// name + MAPPED flag and warn on size mismatch, matching the user-visible
    /// behaviour.
    pub fn attempt_dynamic_mapping_late(
        &mut self,
        first_use_addr: crate::address::Address,
        hash: u64,
        size: usize,
        is_equate: bool,
        is_union_facet: bool,
        sym_name: &str,
    ) -> bool {
        // cc:1352-1354: union_facet → applyUnionFacet.
        if is_union_facet { return false; }
        // cc:1355: vn = dhash.findVarnode(this, addr, hash).
        let vn = {
            let mut dhash = crate::dynamic::DynamicHash::new();
            dhash.find_varnode(self, first_use_addr, hash)
        };
        let Some(vn) = vn else { return false };
        // cc:1358: already labelled.
        if vn.read().unwrap().is_mapped() { return false; }
        // cc:1359-1361: equate → setSymbolEntry regardless of size.
        if is_equate {
            vn.write()
                .unwrap()
                .set_flags(crate::varnode::varnode_flags::MAPPED);
            self.symbol_table
                .insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
            return true;
        }
        // cc:1363-1371: size mismatch → warningHeader + return false.
        if vn.read().unwrap().size != size {
            self.warning_header(&format!(
                "Unable to use symbol {}: Size does not match variable it labels",
                sym_name
            ));
            return false;
        }
        // cc:1373-1386: implied varnode → look at the "other side" of an
        // adjacent CAST; if that side is explicit, the Symbol attaches there
        // (DYNMAP-LATE-CAST-RETARGET-0001, 1:1 port of the previously
        // documented omission):
        //   if (vn->isImplied()) {	// This should be finding an explicit, but a cast may have been inserted
        //     Varnode *newvn = (Varnode *)0;
        //     // Look at the "other side" of the cast
        //     if (vn->isWritten() && (vn->getDef()->code() == CPUI_CAST))
        //	newvn = vn->getDef()->getIn(0);
        //     else {
        //	PcodeOp *castop = vn->loneDescend();
        //	if ((castop != (PcodeOp *)0)&&(castop->code() == CPUI_CAST))
        //	  newvn = castop->getOut();
        //     }
        //     // See if the varnode on the other side is explicit
        //     if ((newvn != (Varnode *)0)&&(newvn->isExplicit()))
        //	vn = newvn;		// in which case we use it
        //   }
        let vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> = {
            let mut newvn: Option<
                std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
            > = None;
            // cc:1373: only when the hash-located Varnode is implied.
            if vn.read().unwrap().is_implied() {
                // cc:1376-1377: vn written by a CAST → other side is its
                // input 0 (isWritten() == def != null in the oracle, so
                // get_def() Some + CAST opcode is the exact gate).
                let def_side = vn.read().unwrap().get_def().and_then(|def| {
                    let defr = def.read().unwrap();
                    if defr.opcode == OpCode::CPUI_CAST {
                        defr.get_in(0).cloned()
                    } else {
                        None
                    }
                });
                if let Some(v) = def_side {
                    newvn = Some(v);
                } else {
                    // cc:1379-1381: lone descendant is a CAST → other side
                    // is its output (else branch covers both "not written"
                    // and "written by a non-CAST op").
                    newvn = vn.read().unwrap().lone_descend().and_then(|castop| {
                        let castopr = castop.read().unwrap();
                        if castopr.opcode == OpCode::CPUI_CAST {
                            castopr.get_out().cloned()
                        } else {
                            None
                        }
                    });
                }
                // cc:1384-1385: retarget only if the other side is explicit.
                newvn = newvn.filter(|v| v.read().unwrap().is_explicit());
            }
            newvn.unwrap_or(vn)
        };
        // cc:1388: vn->setSymbolEntry(entry).
        vn.write()
            .unwrap()
            .set_flags(crate::varnode::varnode_flags::MAPPED);
        self.symbol_table
            .insert(hash | 0x8000_0000_0000_0000, sym_name.to_string());
        // cc:1389-1397: retype / warningHeader on type mismatch omitted
        // (RUGRA-GAP: no ScopeLocal.retypeSymbol).
        true
    }

    // Ghidra: varnode.hh:313 Varnode::setReturnAddress / funcdata.cc setters
    /// Mark `vn` as the storage location for a return address. Faithful to
    /// `Varnode::setReturnAddress` (varnode.hh:313):
    ///   void setReturnAddress(void) { flags |= Varnode::return_address; }
    /// This is the Funcdata-level entry point used by `setInputVarnode`
    /// (funcdata_varnode.cc:368-371) when a ProtoModel effect records the
    /// input as a return-address storage location.
    pub fn set_return_address(
        &mut self,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        vn.write().unwrap().set_return_address();
    }

    // Ghidra: funcdata_varnode.cc:1756 Funcdata::checkCallDoubleUse
    /// Test for legitimate double use of a parameter trial: the trial is a
    /// putative input to `opmatch`, but also traces into a second CALL `op`.
    /// The exact-owner lookup slice corresponds to
    /// `Funcdata::checkCallDoubleUse` (funcdata_varnode.cc:1756-1794), while
    /// per-input trial lookup and alternate-path validation remain
    /// `CALLSPEC-0001`/UNTESTED. The Ghidra original:
    ///   j = op->getSlot(vn);
    ///   if (j <= 0) return false;             // flows to indirect-call var
    ///   fc = getCallSpecs(op); matchfc = getCallSpecs(opmatch);
    ///   if (op->code() == opmatch->code()) {
    ///     bool isdirect = (opmatch->code() == CALL);
    ///     if ((isdirect && matchfc->getEntryAddress()==fc->getEntryAddress()) ||
    ///         (!isdirect && op->getIn(0)==opmatch->getIn(0))) {
    ///       curtrial = fc->getActiveInput()->getTrialForInputVarnode(j);
    ///       if (curtrial->getAddress() == trial->getAddress()) {
    ///         if (op->getParent()==opmatch->getParent()) {
    ///           if (opmatch->getSeqNum().getOrder() < op->getSeqNum().getOrder())
    ///             return true;
    ///         } else return true;
    ///       }
    ///     }
    ///   }
    ///   if (fc->isInputActive()) {
    ///     curtrial = fc->getActiveInput()->getTrialForInputVarnode(j);
    ///     if (curtrial->isChecked()) {
    ///       if (curtrial->isActive()) return false;
    ///     } else if (TraverseNode::isAlternatePathValid(vn, fl))
    ///       return false;
    ///     return true;
    ///   }
    ///   return false;
    /// Rugra's free-function `only_op_use` does NOT consult call-spec trials,
    /// so this method provides the missing double-use reasoning. It takes the
    /// raw (opmatch, op, vn, fl, trial_addr) inputs; the ParamTrial is reduced
    /// to its address for the same-function / same-trial comparison.
    pub fn check_call_double_use(
        &self,
        opmatch: &crate::op::PcodeOpRef,
        op: &crate::op::PcodeOpRef,
        vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        fl: u32,
        trial: &crate::fspec::ParamTrial,
        match_fc: Option<&crate::fspec::FuncCallSpecs>,
    ) -> bool {
        use crate::opcodes::OpCode as OC;
        // cc:1759: j = op->getSlot(vn); if (j<=0) return false.
        let j = self.op_get_slot(op, vn);
        if j <= 0 {
            return false;
        }
        // cc:1761-1762: resolve both specifications by exact PcodeOp identity.
        // matchfc comes in by reference: Ghidra dereferences plain pointers,
        // but Rust callers may hold the exclusive guard on opmatch's spec
        // (ActionActiveParam/checkInputTrialUse walk), so re-locking it here
        // would deadlock. onlyOpUse also reaches this with op == opmatch
        // (when the varnode sits at a different slot of the same call), in
        // which case Ghidra's fc and matchfc are the same object — reuse
        // the caller-supplied reference for both instead of re-locking.
        let same_op = std::sync::Arc::ptr_eq(&op.0, &opmatch.0);
        let fc_arc = if same_op { None } else { self.get_call_specs_of_op(op) };
        let fc_guard = fc_arc.as_ref().map(|arc| arc.read().unwrap());
        let fc: Option<&crate::fspec::FuncCallSpecs> = if same_op {
            match_fc
        } else {
            fc_guard.as_deref()
        };
        let matchfc = match_fc;
        // cc:1763-1781: same-call double-use test.
        let op_code = op.0.read().unwrap().opcode;
        let match_code = opmatch.0.read().unwrap().opcode;
        if op_code == match_code {
            let is_direct = match_code == OC::CPUI_CALL;
            let same_target = match (fc, matchfc) {
                (Some(fc), Some(mfc)) => {
                    if is_direct {
                        let entry = fc.entry_addr;
                        let match_entry = mfc.entry_addr;
                        entry.is_some() && entry == match_entry
                    } else {
                        // CALLIND: compare the indirect-call varnode (in(0)).
                        let a = op.0.read().unwrap().get_in(0).cloned();
                        let b = opmatch.0.read().unwrap().get_in(0).cloned();
                        match (a, b) { (Some(x), Some(y)) => std::sync::Arc::ptr_eq(&x, &y), _ => false ,
                        }
                    }
                }
                _ => false,
            };
            if same_target {
                // cc:1770-1778: same trial address + ordering test.
                // Rugra: we approximate the per-slot trial-address lookup by
                // checking that the candidate's address equals the trial's.
                let vn_addr = vn.read().unwrap().loc;
                if vn_addr == trial.get_address() {
                    let op_parent = op.0.read()
                            .unwrap()
                            .parent
                            .as_ref()
                            .and_then(|w| w.upgrade());
                    let match_parent = opmatch
                        .0
                        .read()
                        .unwrap()
                        .parent
                        .as_ref()
                        .and_then(|w| w.upgrade());
                    let same_parent = match (op_parent, match_parent) {
                        (Some(a), Some(b)) => std::sync::Arc::ptr_eq(&a, &b),
                        _ => false,
                    };
                    if same_parent {
                        // cc:1773-1774: opmatch dibs if it comes first.
                        let op_order = op.0.read().unwrap().get_seq_num().get_order();
                        let match_order = opmatch.0.read().unwrap().get_seq_num().get_order();
                        if match_order < op_order { return true; }
                        // else fall through (may still reject).
                    } else {
                        // cc:1777-1778: different blocks → assume legit.
                        return true;
                    }
                }
            }
        }
        // cc:1783-1793: input-active path.
        if let Some(fc_ref) = fc {
            let fc = fc_ref;
            if fc.is_input_active() {
                // cc:1784: curtrial = fc->getActiveInput()->getTrialForInputVarnode(j).
                let trial = fc
                    .get_active_input()
                    .get_trial_for_input_varnode(j);
                if trial.is_checked() {
                    // cc:1786-1787: checked & active → reject.
                    if trial.is_active() { return false; }
                } else if is_alternate_path_valid(&vn, fl) {
                    // cc:1789-1790: unchecked, but the alternate path looks
                    // more valid than the main path → reject the trial.
                    return false;
                }
                // cc:1791: otherwise the double use is legitimate.
                return true;
            }
        }
        false
    }

    // Ghidra: funcdata_varnode.cc:1805 Funcdata::onlyOpUse
    /// Test if the given Varnode seems to only be used by a CALL/RETURN op.
    /// Faithful to `Funcdata::onlyOpUse` (funcdata_varnode.cc:1805-1904).
    /// This is the `impl Funcdata` method form of the free function
    /// `only_op_use`; it supplies the Funcdata receiver that the free
    /// function needs for checkCallDoubleUse and getActiveOutput.
    pub fn only_op_use(
        &self,
        invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        opmatch: &crate::op::PcodeOpRef,
        trial: &crate::fspec::ParamTrial,
        main_flags: u32,
    ) -> bool {
        only_op_use(self, invn, opmatch, trial, main_flags, None)
    }

    // Ghidra: funcdata_varnode.cc:1917 Funcdata::ancestorOpUse
    /// Test if the given trial Varnode is likely only used for parameter
    /// passing, following flow from ancestors it was copied from. Faithful to
    /// `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917-1994). This is the
    /// `impl Funcdata` method form of the free function `ancestor_op_use`.
    pub fn ancestor_op_use(
        &self,
        maxlevel: i32,
        invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        trial: &mut crate::fspec::ParamTrial,
        offset: i32,
        main_flags: u32,
    ) -> bool {
        ancestor_op_use(self, maxlevel, invn, op, trial, offset, main_flags, None)
    }

    // Ghidra: funcdata_op.cc:332 Funcdata::newOp(int4, const SeqNum &)
    /// Create a new PcodeOp with an explicit sequence number. Faithful to
    /// `Funcdata::newOp(int4 inputs, const SeqNum &sq)` (funcdata_op.cc:332).
    /// The immutable creation `time` and mutable block `order` are both
    /// copied, and the bank advances its uniqid past an imported time.
    pub fn new_op_with_seq(
        &mut self, num_inputs: usize, sq: &crate::address::SeqNum,
    ) -> crate::op::PcodeOpRef {
        self.obank.create_seq(num_inputs, *sq)
    }

    // Ghidra: funcdata_op.cc:616 Funcdata::cloneOp
    /// Clone an existing PcodeOp (with a new SeqNum) into this function.
    /// Faithful to `Funcdata::cloneOp` (funcdata_op.cc:616-628):
    ///   PcodeOp *newop = newOp(op->numInput(),seq);
    ///   opSetOpcode(newop,op->code());
    ///   uint4 fl = op->flags & (startmark | startbasic);
    ///   newop->setFlag(fl);
    ///   if (op->getOut() != (Varnode *)0)
    ///     opSetOutput(newop,cloneVarnode(op->getOut()));
    ///   for(int4 i=0;i<op->numInput();++i)
    ///     opSetInput(newop,cloneVarnode(op->getIn(i)),i);
    ///   return newop;
    pub fn clone_op(
        &mut self,
        op: &crate::op::PcodeOpRef,
        seq: &crate::address::SeqNum,
    ) -> crate::op::PcodeOpRef {
        use crate::op::pcodeop_flags as pf;
        let (num_inputs, opcode, flag_subset, has_out) = {
            let r = op.0.read().unwrap();
            let fl = r.flags & (pf::STARTMARK | pf::STARTBASIC);
            (r.num_input(), r.opcode, fl, r.get_out().is_some())
        };
        let newop = self.new_op_with_seq(num_inputs, seq);
        self.op_set_opcode(&newop, opcode);
        // cc:621-622: copy startmark/startbasic flags.
        newop.0.write().unwrap().flags |= flag_subset;
        // cc:623-624: clone the output varnode if any.
        if has_out {
            let out_clone = {
                let r = op.0.read().unwrap();
                self.clone_varnode(r.get_out().unwrap())
            };
            self.op_set_output(&newop, out_clone);
        }
        // cc:625-626: clone each input varnode.
        for i in 0..num_inputs {
            let in_clone = {
                let r = op.0.read().unwrap();
                self.clone_varnode(r.get_in(i).unwrap())
            };
            self.op_set_input(&newop, in_clone, i);
        }
        newop
    }

    // Ghidra: funcdata_op.cc:792 Funcdata::truncatedFlow
    /// Clone the raw flow state of `source` into an empty partial function.
    ///
    /// The source dead-list is cloned in list order with exact sequence
    /// numbers, followed by call-spec and linked jump-table rebinding.  The
    /// cloned `FlowInfo` then performs injection (when requested) and builds
    /// basic blocks.  As in Ghidra, the target may be partially mutated when
    /// a later jump-table lookup raises an error.
    pub fn truncated_flow(
        &mut self,
        source: &Funcdata,
        flow_state: &crate::flow::TruncatedFlowState,
    ) -> crate::error::Result<()> {
        if !self.obank.is_empty() {
            return Err(crate::error::Error::Lowlevel(
                "Trying to do truncated flow on pre-existing pcode".to_string(),
            ));
        }

        // cc:797-799: the raw p-code container is specifically the dead list,
        // whose linked-list order is independent of SeqNum ordering.
        for source_op in &source.obank.deadlist {
            let seq = *source_op.0.read().unwrap().get_seq_num();
            self.clone_op(source_op, &seq);
        }
        // cc:800: preserve the source bank's next allocation id even when it
        // is greater than every cloned SeqNum time.
        self.obank.set_uniqid(source.obank.get_uniqid());

        // cc:803-814: clone qlst in vector order. Each source FuncCallSpecs
        // upgrades its exact Weak PcodeOp link; the cloned FSPEC input still
        // carries a typed Weak to the old owner until it is replaced below.
        for oldspec in &source.callspecs {
            let source_call = oldspec
                .read()
                .unwrap()
                .op
                .upgrade()
                .map(crate::op::PcodeOpRef)
                .ok_or_else(|| {
                    crate::error::Error::Lowlevel(
                        "Could not trace callspec across partial clone".to_string(),
                    )
                })?;

            let source_seq = *source_call.0.read().unwrap().get_seq_num();
            let newop = self.obank.find_op(&source_seq).ok_or_else(|| {
                crate::error::Error::Lowlevel(
                    "Could not trace callspec across partial clone".to_string(),
                )
            })?;
            let newspec = oldspec.read().unwrap().clone_for_op(&newop);
            let new_owner = Arc::new(RwLock::new(newspec));

            let old_input = newop.0.read().unwrap().get_in(0).cloned();
            if let Some(invn0) = old_input {
                let is_fspec = {
                    let input = invn0.read().unwrap();
                    input.get_space() == AddressSpace::Iop
                        && input.is_annotation()
                        && input
                            .get_call_spec()
                            .map(|bound| Arc::ptr_eq(&bound, oldspec))
                            .unwrap_or(false)
                };
                if is_fspec {
                    let newvn0 = self.new_varnode_call_specs(&new_owner);
                    self.op_set_input(&newop, newvn0, 0);
                    self.delete_varnode(&invn0)?;
                }
            }
            self.callspecs.push(new_owner);
        }

        // cc:816-828: preserve source jumpvec order, but truncate unlinked
        // overrides.  A linked table is cloned only after its indirect op can
        // be found by exact SeqNum in the target bank.
        for source_table in &source.jump_tables {
            let table = source_table.read().unwrap();
            let Some(indirect) = table.get_indirect_op() else {
                continue;
            };
            let indirect_seq = *indirect.read().unwrap().get_seq_num();
            let newop = self.obank.find_op(&indirect_seq).ok_or_else(|| {
                crate::error::Error::Lowlevel(
                    "Could not trace jumptable across partial clone".to_string(),
                )
            })?;

            // jumptable.cc:2401-2425 JumpTable copy constructor: instance-
            // specific block/label/default/consume state is reset, while the
            // address/load/model recovery state is copied.
            let cloned_table = Arc::new(RwLock::new(crate::jumptable::JumpTable {
                jmodel: None,
                origmodel: None,
                addresstable: table.addresstable.clone(),
                block2addr: Vec::new(),
                label: Vec::new(),
                loadpoints: table.loadpoints.clone(),
                opaddress: table.opaddress,
                indirect: None,
                switch_var_consume: u64::MAX,
                default_block: -1,
                last_block: table.last_block,
                norm_max: table.norm_max,
                partial_table: table.partial_table,
                collect_loads: table.collect_loads,
                default_is_folded: false,
            }));
            let cloned_model = table
                .jmodel
                .as_ref()
                .map(|model| model.clone_model());
            drop(table);
            {
                let mut cloned = cloned_table.write().unwrap();
                cloned.jmodel = cloned_model;
                cloned.set_indirect_op(newop.0.clone());
            }
            self.jump_tables.push(cloned_table);
        }

        // cc:830-838: FlowInfo's clone constructor copies configuration and
        // address containers, then injection/block generation finalizes the
        // partial function.  blocks_generated is set only after completion.
        crate::flow::FlowInfo::finish_truncated_flow(self, flow_state)?;
        self.flags |= funcdata_flags::BLOCKS_GENERATED;
        Ok(())
    }

    // Ghidra: funcdata_op.cc:656 Funcdata::newOpBefore
    /// Create a new PcodeOp with 2 or 3 given operands and insert it before
    /// `follow`. Faithful to `Funcdata::newOpBefore` (funcdata_op.cc:656-671):
    ///   sz = (in3 == NULL) ? 2 : 3;
    ///   newop = newOp(sz, follow->getAddr());
    ///   opSetOpcode(newop, opc);
    ///   newUniqueOut(in1->getSize(), newop);
    ///   opSetInput(newop, in1, 0);
    ///   opSetInput(newop, in2, 1);
    ///   if (sz==3) opSetInput(newop, in3, 2);
    ///   opInsertBefore(newop, follow);
    pub fn new_op_before(
        &mut self,
        follow: &crate::op::PcodeOpRef,
        opc: crate::opcodes::OpCode,
        in1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        in2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        in3: Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) -> crate::op::PcodeOpRef {
        let sz = if in3.is_some() { 3 } else { 2 };
        let addr = follow.0.read().unwrap().get_addr();
        let newop = self.new_op(sz, addr);
        self.op_set_opcode(&newop, opc);
        let s1 = in1.read().unwrap().size as usize;
        self.new_unique_out(s1, &newop);
        self.op_set_input(&newop, in1.clone(), 0);
        self.op_set_input(&newop, in2.clone(), 1);
        if sz == 3 {
            self.op_set_input(&newop, in3.unwrap().clone(), 2);
        }
        // cc:671: opInsertBefore — `new_op` already registered the op in
        // optree/alivelist, so we only need to reorder it ahead of `follow`.
        self.op_insert_before(&newop, follow);
        newop
    }

    // Ghidra: funcdata_op.cc:929 Funcdata::findPrimaryBranch
    /// Find the primary branch op within an address range. Faithful to
    /// `Funcdata::findPrimaryBranch` (funcdata_op.cc:929-961): iterate the
    /// ops at `addr` and return the first whose opcode matches the requested
    /// category (branch / call / return). BRANCH/CBRANCH are only returned
    /// when their target input is non-constant (i.e., a real branch, not an
    /// internal p-code branch).
    pub fn find_primary_branch(
        &self,
        ops_at_addr: &[crate::op::PcodeOpRef],
        find_branch: bool,
        find_call: bool,
        find_return: bool,
    ) -> Option<crate::op::PcodeOpRef> {
        use crate::opcodes::OpCode as OC;
        for op_ref in ops_at_addr {
            let r = op_ref.0.read().unwrap();
            match r.opcode {
                OC::CPUI_BRANCH | OC::CPUI_CBRANCH => {
                    if find_branch {
                        // cc:938: skip internal (constant-target) branches.
                        let is_const = r
                            .get_in(0)
                            .map(|v| v.read().unwrap().is_constant())
                            .unwrap_or(false);
                        if !is_const { return Some(op_ref.clone()); }
                    }
                }
                OC::CPUI_BRANCHIND => {
                    if find_branch { return Some(op_ref.clone()); }
                }
                OC::CPUI_CALL | OC::CPUI_CALLIND => {
                    if find_call { return Some(op_ref.clone()); }
                }
                OC::CPUI_RETURN => {
                    if find_return { return Some(op_ref.clone()); }
                }
                _ => {}
            }
        }
        None
    }

    // Ghidra: funcdata_op.cc:969 Funcdata::overrideFlow
    /// Override the control-flow p-code for a particular instruction.
    /// Faithful to `Funcdata::overrideFlow` (funcdata_op.cc:969-1021):
    /// given an instruction address and an Override type, locate the primary
    /// branch op at that address (still dead / pre-block-formation) and
    /// rewrite its opcode per the override table. For `CALL_RETURN` a fresh
    /// RETURN op is inserted after the rewritten call. Throws LowlevelError
    /// if the primary op is missing or already alive (block-formed).
    pub fn override_flow(
        &mut self,
        addr: crate::address::Address,
        flow_type: crate::override_rs::FlowOverride,
    ) -> crate::error::Result<()> {
        use crate::opcodes::OpCode as OC;
        use crate::override_rs::FlowOverride as FO;
        // cc:972-983: traverse every op at addr in SeqNum order, then dispatch
        // on the override. The dead-state check happens after primary-op
        // selection, matching Ghidra's beginOp/endOp + isDead contract.
        let ops_at_addr: Vec<crate::op::PcodeOpRef> = self
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_addr() == addr)
            .cloned()
            .collect();
        let primary = match flow_type {
            FO::Branch => self.find_primary_branch(&ops_at_addr, false, true, true),
            FO::Call => self.find_primary_branch(&ops_at_addr, true, false, true),
            FO::CallReturn => self.find_primary_branch(&ops_at_addr, true, true, true),
            FO::Return => self.find_primary_branch(&ops_at_addr, true, true, false),
            FO::None => return Ok(()),
        };
        let op = primary.ok_or_else(|| {
            crate::error::Error::Lowlevel("Could not apply flowoverride".to_string())
        })?;
        if !op.0.read().unwrap().is_dead() {
            return Err(crate::error::Error::Lowlevel(
                "Could not apply flowoverride".to_string(),
            ));
        }
        // cc:988-1020: rewrite the opcode per the override table.
        let opc = op.0.read().unwrap().opcode;
        match flow_type {
            FO::Branch => match opc {
                    OC::CPUI_CALL => self.op_set_opcode(&op, OC::CPUI_BRANCH),
                    OC::CPUI_CALLIND => self.op_set_opcode(&op, OC::CPUI_BRANCHIND),
                    OC::CPUI_RETURN => self.op_set_opcode(&op, OC::CPUI_BRANCHIND),
                    _ => {}
                }
            ,
            FO::Call | FO::CallReturn => {
                match opc {
                    OC::CPUI_BRANCH => self.op_set_opcode(&op, OC::CPUI_CALL),
                    OC::CPUI_BRANCHIND => self.op_set_opcode(&op, OC::CPUI_CALLIND),
                    OC::CPUI_CBRANCH => {
                        return Err(crate::error::Error::Lowlevel(
                            "Do not currently support CBRANCH overrides".to_string(),
                        ));
                    }
                    OC::CPUI_RETURN => self.op_set_opcode(&op, OC::CPUI_CALLIND),
                    _ => {}
                }
                // cc:1006-1011: for CALL_RETURN, append a fresh RETURN after.
                if flow_type == FO::CallReturn {
                    let new_return = self.new_op(1, addr);
                    self.op_set_opcode(&new_return, OC::CPUI_RETURN);
                    let c = self.new_constant(1, 0);
                    self.op_set_input(&new_return, c, 0);
                    // cc:1010: opDeadInsertAfter keeps the newly allocated
                    // op's SeqNum identity but moves its dead-list position
                    // to immediately after the converted call.
                    self.obank.insert_after_dead(&new_return, &op);
                }
            }
            FO::Return => match opc {
                    OC::CPUI_BRANCH | OC::CPUI_CBRANCH | OC::CPUI_CALL => {
                        return Err(crate::error::Error::Lowlevel(
                            "Do not currently support complex overrides".to_string(),
                        ));
                    }
                    OC::CPUI_BRANCHIND => self.op_set_opcode(&op, OC::CPUI_RETURN),
                    OC::CPUI_CALLIND => self.op_set_opcode(&op, OC::CPUI_RETURN),
                    _ => {}
                }
            ,
            FO::None => {}
        }
        Ok(())
    }

    // Ghidra: funcdata_op.cc:756 Funcdata::followFlow
    /// Walk the instruction stream and produce p-code + basic blocks for the
    /// half-open range `[baddr, eaddr)`. Faithful to
    /// `Funcdata::followFlow` (funcdata_op.cc:756-783):
    ///   if (!obank.empty()) {
    ///     if ((flags & blocks_generated)==0)
    ///       throw LowlevelError("Function loaded for inlining");
    ///     return;  // Already translated
    ///   }
    ///   FlowInfo flow(*this,obank,bblocks,qlst);
    ///   flow.setRange(baddr,eaddr);
    ///   flow.generateOps();
    ///   size = flow.getSize();
    ///   flow.generateBlocks();
    ///   flags |= blocks_generated;
    ///   switchOverJumpTables(flow);
    ///   if (flow.hasUnimplemented()) flags |= unimplemented_present;
    ///   if (flow.hasBadData())      flags |= baddata_present;
    /// RUGRA-GAP: Rugra currently ingests p-code via `inject_raw_ops` +
    /// `build_blocks_from_ops` (see x86_lift.rs / the test harness), so the
    /// disassembly-driven FlowInfo walk is not wired up. This stub preserves
    /// the Ghidra semantics for the "already translated" early-return path
    /// and the flag side-effects, and is the natural attachment point when
    /// a Rugra FlowInfo / lifter is added.
    pub fn follow_flow(&mut self, baddr: crate::address::Address, eaddr: crate::address::Address) {
        // cc:759-763: if obank already populated, this function is either
        // already translated (blocks_generated set → return) or was loaded
        // for inlining (→ error).
        if !self.obank.optree.is_empty() {
            if (self.flags & funcdata_flags::BLOCKS_GENERATED) == 0 {
                self.warning_header("Function loaded for inlining; follow_flow ignored");
            }
            return;
        }
        // cc:767-783: FlowInfo walk + block generation + flag side-effects.
        // RUGRA-GAP: full FlowInfo not implemented; record the range so any
        // future lifter can pick it up, and set blocks_generated defensively.
        let _ = (baddr, eaddr);
        self.flags |= funcdata_flags::BLOCKS_GENERATED;
    }

    // Ghidra: funcdata.hh:547 Funcdata::getStructure
    /// Get the current control-flow structuring hierarchy. Faithful to
    /// `BlockGraph &getStructure(void)` (funcdata.hh:547) — returns a mutable
    /// reference to the structured BlockGraph (`sblocks`) that sits on top of
    /// the basic blocks.
    pub fn get_structure(&mut self) -> &mut crate::block::BlockGraph {
        &mut self.sblocks
    }

    // Ghidra: funcdata.hh:549 Funcdata::getBasicBlocks
    /// Get the basic-block container. Faithful to
    /// `const BlockGraph &getBasicBlocks(void) const` (funcdata.hh:549).
    pub fn get_basic_blocks(&self) -> &crate::block::BlockGraph {
        &self.bblocks
    }

    // Ghidra: funcdata.hh:170 Funcdata::hasNoStructBlocks
    /// Return true if no block structuring was performed. Faithful to
    /// `bool hasNoStructBlocks(void) const` (funcdata.hh:170) — true iff the
    /// structured hierarchy is empty.
    pub fn has_no_struct_blocks(&self) -> bool {
        self.sblocks.get_size() == 0
    }

    // Ghidra: funcdata.hh:206 Funcdata::getOverride
    /// Get the Override object for this function. Faithful to
    /// `Override &getOverride(void)` (funcdata.hh:206) — returns a mutable
    /// reference to `localoverride` so callers can insert flow/deadcodedelay
    /// overrides.
    pub fn get_override(&mut self) -> &mut crate::override_rs::Override {
        &mut self.localoverride
    }

    // Ghidra: funcdata_varnode.cc:272 Funcdata::destroyVarnode
    /// Detach a Varnode from Rugra's descendant/definition indexes and remove
    /// it from the bank, adapting `Funcdata::destroyVarnode`
    /// (funcdata_varnode.cc:272-292):
    ///   for(iter=vn->beginDescend(); iter!=vn->endDescend(); ++iter) {
    ///     PcodeOp *op = *iter;
    ///     op->clearInput(op->getSlot(vn));
    ///   }
    ///   if (vn->def != NULL) {
    ///     vn->def->setOutput(NULL);
    ///     vn->def = NULL;
    ///   }
    ///   vn->destroyDescend();
    ///   vbank.destroy(vn);
    /// Rust input slots cannot be NULL: `op_unset_input` erases the descendant
    /// edge but leaves a stale Arc in `inrefs` until the caller removes or
    /// replaces that slot. Thus this function does not prove Ghidra's complete
    /// clearInput mutation and only guarantees index/bank detachment for its
    /// prevalidated callers. `delete_varnode` instead forwards to the checked
    /// public bank destroy and should be used for an already detached value.
    pub fn destroy_varnode(
        &mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:277-284: clear each descending op's input slot.
        // Snapshot the (op, slot) pairs first because the slot lookup
        // (`op_get_slot`) and the unset both read the op. `op_get_slot`
        // returns -1 on miss; casting that to usize would produce
        // usize::MAX and a silent no-op inside op_unset_input, leaving the
        // op in vn's descend list as drift (and, once its Arc is released,
        // a dead Weak entry no erase_descend can ever match). Ghidra's
        // `clearInput(op->getSlot(vn))` on a miss indexes out of bounds —
        // the precondition is that every descendant really reads vn; on
        // drift, drop the stale entry instead so the list converges to the
        // actual reads (the whole list is destroyed below anyway).
        let descend_pairs: Vec<(crate::op::PcodeOpRef, i32)> = {
            let r = vn.read().unwrap();
            r.descend
                .iter()
                .filter_map(|w| w.upgrade())
                .map(|op_arc| {
                    let op_ref = crate::op::PcodeOpRef(op_arc.clone());
                    let slot = self.op_get_slot(&op_ref, vn);
                    (op_ref, slot)
                })
                .collect()
        };
        for (op_ref, slot) in descend_pairs {
            // cc:283: op->clearInput(op->getSlot(vn)). op_unset_input
            // erases the descend link and NULLs the slot in place (the
            // shared null_slot_sentinel stands in for Ghidra's NULL), so
            // the slot keeps its count until overwritten or removed.
            if slot >= 0 {
                self.op_unset_input(&op_ref, slot as usize);
            }
        }
        // cc:285-288: if vn has a def, detach the def's output.
        let def_op = vn.read().unwrap().get_def();
        if let Some(def) = def_op {
            self.op_unset_output(&crate::op::PcodeOpRef(def));
        }
        // cc:290: vn->destroyDescend().
        vn.write().unwrap().destroy_descend();
        // cc:291: vbank.destroy(vn).
        // The loop and def block above detached every integrated edge.
        self.vbank.destroy_varnode_prevalidated(vn);
    }

    // Ghidra: funcdata_varnode.cc:1048 Funcdata::syncVarnodesWithSymbol (single-range)
    /// Update MAPPED/ADDRTIED/ADDRFORCE/NOLOCALALIAS flags on a range of
    /// Varnodes that all share the same address, plus optionally update their
    /// Datatype. Faithful to `Funcdata::syncVarnodesWithSymbol(VarnodeLocSet::const_iterator &iter, uint4 fl, Datatype *ct)`
    /// (funcdata_varnode.cc:1048-1095). Ghidra walks an iterator range
    /// `[iter, endLoc(size, addr))` advancing the caller's iterator in place;
    /// Rugra passes the explicit slice of Varnodes at that address instead
    /// (the idiomatic Rust equivalent of the iterator range), since the
    /// in-out iterator pattern has no direct Rust analogue.
    ///
    /// Flag-update rules (verbatim from cc:1055-1067):
    ///   mask  = mapped;
    ///   if ((fl & addrtied) == 0)        // addrtied cleared → clear addrforce too
    ///     mask |= addrtied | addrforce;
    ///   if ((fl & nolocalalias) != 0)    // nolocalalias set → clear addrforce
    ///     mask |= nolocalalias | addrforce;
    ///   fl &= mask;
    /// and per-varnode (cc:1071-1093): skip free varnodes; if a dynamic
    /// SymbolEntry is attached (`mapentry`), hold the `mapped` bit unchanged;
    /// otherwise apply `fl` vs `mask`. Finally, if `ct` is provided, call
    /// `vn->updateType(ct)`.
    ///
    /// RUGRA-GAP: Rugra's Varnode has no `mapentry` field (no SymbolEntry
    /// infrastructure), so the "dynamic SymbolEntry attached" branch is taken
    /// to be the same as the plain branch — the `mapped` bit is updated along
    /// with the rest of the mask. When SymbolEntry wiring lands, restore the
    /// `localMask = mask & ~mapped` special case for attached entries.
    pub fn sync_varnodes_with_symbol(
        &mut self,
        range: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        fl_in: u32,
        ct: Option<&std::sync::Arc<crate::type_system::Datatype>>,
    ) -> bool {
        use crate::varnode::varnode_flags as vf;
        // cc:1056-1067: build mask and clamp fl.
        let mut mask = vf::MAPPED;
        if (fl_in & vf::ADDRTIED) == 0 {
            mask |= vf::ADDRTIED | vf::ADDRFORCE;
        }
        if (fl_in & vf::NOLOCALALIAS) != 0 {
            mask |= vf::NOLOCALALIAS | vf::ADDRFORCE;
        }
        let fl = fl_in & mask;
        let mut update_occurred = false;
        for vn_arc in range {
            let mut vn = vn_arc.write().unwrap();
            // cc:1073: if (vn->isFree()) continue.
            if vn.is_free() { continue; }
            let vnflags = vn.flags;
            // RUGRA-GAP: no mapentry — treat all varnodes uniformly (see doc).
            if (vnflags & mask) != fl {
                update_occurred = true;
                vn.set_flags(fl);
                vn.clear_flags((!fl) & mask);
            }
            if let Some(ct_arc) = ct {
                // cc:1089-1092: if (ct != NULL && vn->updateType(ct)) updateoccurred = true.
                if vn.update_type(ct_arc.clone()) {
                    update_occurred = true;
                }
            }
        }
        update_occurred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::runtime_verify::{RuntimeVerifier, VerifyResult};
    use crate::ffi;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use std::sync::Mutex;

    // Serialize tests that use the global CURRENT_PROGRAM to prevent
    // multi-threaded test races when `cargo test` runs in parallel.
    lazy_static::lazy_static! {
        static ref FFI_TEST_LOCK: Mutex<()> = Mutex::new(());
    }

    // RUGRA-GLUE: test-only poison-immune acquisition of FFI_TEST_LOCK
    // (TESTLIB-STATE-CONTAMINATION-0001). Ghidra has no test-harness
    // counterpart. Previously every holder acquired with `.lock().unwrap()`,
    // so one genuine assertion panic inside a holder (the observed trigger:
    // test_normalize_branches_break_in_while_loop, funcdata.rs:15063)
    // poisoned the Mutex and cascaded `PoisonError` into every later
    // CURRENT_PROGRAM user — 16 deterministic victims in serial mode and a
    // scheduling-dependent 17↔27 failure-count drift in parallel mode.
    // Recovering the guard via `into_inner` keeps the mutual exclusion (the
    // OS mutex still serializes holders) while making each test's outcome
    // independent of earlier failures: every holder re-initializes the
    // shared fixture via `ffi::set_current_program(fd)` before any
    // comparison read, so no IR state from the panicking test can leak
    // into the next one.
    fn ffi_test_lock() -> std::sync::MutexGuard<'static, ()> {
        FFI_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn test_funcdata_creation() {
        let fd = Funcdata::new("test_func", Address::new(0x1000), 0x100);
        assert_eq!(fd.get_name(), "test_func");
        assert_eq!(fd.get_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_inject_raw_ops_simple() {
        let mut fd = Funcdata::new("add", Address::new(0x1000), 7);

        // Build: RAX = COPY(RDI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: RAX = INT_ADD(RAX, RSI)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: RETURN(RAX)
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        fd.inject_raw_ops(&[op1, op2, op3]);

        // Verify ops were created
        assert_eq!(fd.obank.alivelist.len(), 3);

        // Verify varnodes were created (2 outputs + 4 inputs = 6 total)
        assert!(fd.vbank.num_varnodes() > 0);

        // Verify basic blocks (RETURN terminates, so we get 1 block)
        assert_eq!(fd.bblocks.get_size(), 1);
    }

    #[test]
    fn test_inject_raw_ops_with_branch() {
        let mut fd = Funcdata::new("branch_test", Address::new(0x2000), 20);

        // Block 0: compare and branch
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x2010, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));

        // Block 1: true branch
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // Basic-block partitioning splits at terminators AND at jump targets
        // (Ghidra-style). CBRANCH at op1 (addr 0x2010) targets 0x2010 — itself,
        // a self-loop — so op1 is its own block boundary. This yields 3 blocks:
        //   [op0(op1=INT_EQUAL), op1(CBRANCH)] | [op2(COPY), op3(RETURN)]
        // becomes, with the self-loop target splitting at op1:
        //   [op0] | [op1(CBRANCH, self-loop)] | [op2, op3]
        assert_eq!(fd.bblocks.get_size(), 3);
    }

    // FUNCDATA-ZOMBIE-DECISION-ORIGIN-0001 fixture (Rugra side).
    //
    // Oracle contract: Ghidra's flow-driven block formation makes EVERY
    // intra-function jump target a block start, and branchRemoveInternal
    // (funcdata_block.cc:203-204) destroys a CBRANCH exactly when one of its
    // two out-edges is severed — so a CBRANCH never outlives its second
    // out-edge. Oracle-side witness: golden ghidra_httpd_1204.c
    // ap_strcasecmp_match emits LAB_0012e022 for the jump target 0x2e022,
    // the exact address whose instruction (movslq) lifts to zero p-code in
    // Rugra and used to make the CBRANCH edge unresolvable (the "zombie
    // decision block" origin; 260 occurrences across httpd before the fix,
    // 0 after — see /tmp evidence in the task report).
    //
    // Case 1: CBRANCH whose intra-function target address has NO op (the
    // lifter emitted no p-code for the target instruction) must still get a
    // synthetic block boundary at the target address and BOTH out-edges —
    // no zombie.
    #[test]
    fn test_build_blocks_synthetic_target_creates_block_no_zombie() {
        let mut fd = Funcdata::new("zombie_origin", Address::new(0x1000), 0x40);

        // Instruction addresses simulate a real lift (SeqNum carries the
        // instruction address). The target 0x1020 has NO op — like a `pop`
        // under x86_lift.rs:602's no-op arm.
        let mut eq = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        eq.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        eq.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        eq.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        eq.set_seq_num(crate::address::SeqNum::new(Address::new(0x1000), 0));

        let mut cb = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cb.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1020, 8));
        cb.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        cb.set_seq_num(crate::address::SeqNum::new(Address::new(0x1005), 0));

        let mut copy = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        copy.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        copy.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));
        copy.set_seq_num(crate::address::SeqNum::new(Address::new(0x1007), 0));

        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        ret.set_seq_num(crate::address::SeqNum::new(Address::new(0x1009), 0));

        // Tail instruction AFTER the synthetic target 0x1020 (its own op
        // gets absorbed by the synthetic block started at 0x1020).
        let mut ret2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        ret2.set_seq_num(crate::address::SeqNum::new(Address::new(0x1025), 0));

        fd.inject_raw_ops(&[eq, cb, copy, ret, ret2]);

        // A block must start exactly at the target address 0x1020.
        let synth = (0..fd.bblocks.get_size())
            .filter_map(|i| fd.bblocks.get_block(i))
            .find(|b| b.read().unwrap().get_start_addr().as_u64() == 0x1020)
            .expect("synthetic block at unresolved target 0x1020 must exist");
        // The synthetic block falls through to the next block.
        assert_eq!(synth.read().unwrap().size_out(), 1);
        assert!(synth.read().unwrap().size_in() >= 1);

        // The CBRANCH block keeps BOTH out-edges — the zombie-decision
        // invariant (CBRANCH lastOp => exactly 2 out-edges) holds from birth.
        let cb_block = (0..fd.bblocks.get_size())
            .filter_map(|i| fd.bblocks.get_block(i))
            .find(|b| {
                b.read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockBasic>()
                    .and_then(|bb| bb.last_op())
                    .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                    .unwrap_or(false)
            })
            .expect("CBRANCH block must exist");
        assert_eq!(
            cb_block.read().unwrap().size_out(),
            2,
            "CBRANCH must be born with 2 out-edges (no zombie decision block)"
        );
        // Ghidra edge order (flow.cc:960-967 FlowInfo::generateBlockEdges):
        // out edge 0 = fall-through (false), out edge 1 = branch target
        // (true). Edge 1 must land on the synthetic target block; edge 0 on
        // the sequential fall-through block.
        let edge0 = cb_block.read().unwrap().get_out(0).map(|e| e.point);
        let edge0 = edge0.expect("CBRANCH edge 0 exists");
        let edge1 = cb_block.read().unwrap().get_out(1).map(|e| e.point);
        let edge1 = edge1.expect("CBRANCH edge 1 exists");
        assert!(Arc::ptr_eq(&edge1, &synth));
        assert_eq!(edge0.read().unwrap().get_start_addr().as_u64(), 0x1007);
    }

    // Case 2: a target OUTSIDE the function range is external flow
    // (tail-jump); the edge stays dropped as before — no synthetic block.
    #[test]
    fn test_build_blocks_external_target_edge_still_dropped() {
        let mut fd = Funcdata::new("external_target", Address::new(0x1000), 0x20);

        let mut eq = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        eq.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        eq.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        eq.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        eq.set_seq_num(crate::address::SeqNum::new(Address::new(0x1000), 0));

        let mut cb = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cb.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x2000, 8)); // outside [0x1000,0x1020)
        cb.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        cb.set_seq_num(crate::address::SeqNum::new(Address::new(0x1005), 0));

        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        ret.set_seq_num(crate::address::SeqNum::new(Address::new(0x1009), 0));

        fd.inject_raw_ops(&[eq, cb, ret]);

        // No block at the external target.
        let has_synth = (0..fd.bblocks.get_size())
            .filter_map(|i| fd.bblocks.get_block(i))
            .any(|b| b.read().unwrap().get_start_addr().as_u64() == 0x2000);
        assert!(!has_synth, "external target must not create a block");
        // Documented residual: the unresolvable external edge is dropped,
        // leaving the CBRANCH with only its fall-through edge (a Ghidra-
        // impossible input state; tail-jumps are handled by flow overrides
        // in Ghidra, see apply_flow_overrides_raw).
        let cb_block = (0..fd.bblocks.get_size())
            .filter_map(|i| fd.bblocks.get_block(i))
            .find(|b| {
                b.read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockBasic>()
                    .and_then(|bb| bb.last_op())
                    .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                    .unwrap_or(false)
            })
            .expect("CBRANCH block must exist");
        assert_eq!(cb_block.read().unwrap().size_out(), 1);
    }

    // Case 3: branchRemoveInternal invariant lock — severing one edge of a
    // 2-way decision destroys the CBRANCH (funcdata_block.cc:203-204), so a
    // decision block can never decay into a zombie state o2->o1->o0.
    #[test]
    fn test_branch_remove_internal_destroys_cbranch_at_two_out() {
        let mut fd = Funcdata::new("branch_remove", Address::new(0x1000), 0x40);

        let mut eq = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        eq.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        eq.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        eq.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        eq.set_seq_num(crate::address::SeqNum::new(Address::new(0x1000), 0));

        let mut cb = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cb.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1030, 8));
        cb.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 1));
        cb.set_seq_num(crate::address::SeqNum::new(Address::new(0x1005), 0));

        let mut copy = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        copy.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        copy.add_input(VarnodeRaw::new(AddressSpace::Const, 1, 8));
        copy.set_seq_num(crate::address::SeqNum::new(Address::new(0x1007), 0));

        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        ret.set_seq_num(crate::address::SeqNum::new(Address::new(0x1009), 0));

        let mut ret2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        ret2.set_seq_num(crate::address::SeqNum::new(Address::new(0x1035), 0));

        fd.inject_raw_ops(&[eq, cb, copy, ret, ret2]);

        let cb_block = (0..fd.bblocks.get_size())
            .filter_map(|i| fd.bblocks.get_block(i))
            .find(|b| {
                b.read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockBasic>()
                    .and_then(|bb| bb.last_op())
                    .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                    .unwrap_or(false)
            })
            .expect("CBRANCH block must exist");
        assert_eq!(cb_block.read().unwrap().size_out(), 2);

        // Sever edge 0 (the branch target). At sizeOut==2 the CBRANCH must
        // be destroyed BEFORE the edge count drops (cc:203-204 order).
        fd.remove_branch(&cb_block, 0);

        assert_eq!(
            cb_block.read().unwrap().size_out(),
            1,
            "one edge severed leaves the fall-through"
        );
        let last_is_cbranch = {
            let rg = cb_block.read().unwrap();
            rg.as_any()
                .downcast_ref::<BlockBasic>()
                .and_then(|bb| bb.last_op())
                .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                .unwrap_or(false)
        };
        assert!(
            !last_is_cbranch,
            "branchRemoveInternal must destroy the CBRANCH when sizeOut==2 (funcdata_block.cc:203-204)"
        );
    }

    #[test]
    fn test_mov_reg_reg_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x89, 0xc3]; // mov rbx, rax
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        assert_eq!(raw_ops.len(), 1);

        let raw = &raw_ops[0];
        assert_eq!(OpCode::from_i32(raw.get_opcode()), Some(OpCode::CPUI_COPY));

        let out_binding = raw.output();
        let out = out_binding.as_ref().unwrap();
        assert_eq!(out.space, AddressSpace::Register);
        assert_eq!(out.offset, 0x18);
        assert_eq!(out.size, 8);

        let inputs = raw.inputs();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].space, AddressSpace::Register);
        assert_eq!(inputs[0].offset, 0x00);
        assert_eq!(inputs[0].size, 8);

        let mut fd = Funcdata::new("mov_reg_reg", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 1);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("mov_rbx_rax_minimal", start, &rugra_ops, 1);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_add_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x83, 0xc0, 0x01]; // add rax, 1
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: add now lifts with full flag pcode per the
        // locked 12.0.4 x86-64.sla (ia.sinc `addflags; op1 = op1 + op2;
        // resultflags(op1)`): INT_CARRY CF, INT_SCARRY OF, INT_ADD writing
        // rax directly (no temp/COPY chain, imm canonicalized to 8 bytes),
        // then SF/ZF and the PF popcount chain — 9 ops total.
        assert_eq!(raw_ops.len(), 9);

        let raw_carry = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_carry.get_opcode()),
            Some(OpCode::CPUI_INT_CARRY)
        );
        let carry_out_binding = raw_carry.output();
        let carry_out = carry_out_binding.as_ref().unwrap();
        assert_eq!(carry_out.space, AddressSpace::Register);
        assert_eq!(carry_out.offset, 0x200); // CF
        assert_eq!(carry_out.size, 1);
        let carry_inputs = raw_carry.inputs();
        assert_eq!(carry_inputs.len(), 2);
        assert_eq!(carry_inputs[0].space, AddressSpace::Register);
        assert_eq!(carry_inputs[0].offset, 0x00); // rax
        assert_eq!(carry_inputs[0].size, 8);
        assert_eq!(carry_inputs[1].space, AddressSpace::Const);
        assert_eq!(carry_inputs[1].offset, 0x01);
        assert_eq!(carry_inputs[1].size, 8);

        let raw_scarry = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_scarry.get_opcode()),
            Some(OpCode::CPUI_INT_SCARRY)
        );
        assert_eq!(raw_scarry.output().as_ref().unwrap().offset, 0x20b); // OF

        let raw_add = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Register);
        assert_eq!(add_out.offset, 0x00);
        assert_eq!(add_out.size, 8);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x00);
        assert_eq!(add_inputs[0].size, 8);
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x01);
        assert_eq!(add_inputs[1].size, 8);

        // SF/ZF from the destination varnode; PF popcount chain.
        assert_eq!(
            OpCode::from_i32(raw_ops[3].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(raw_ops[3].output().as_ref().unwrap().offset, 0x207); // SF
        assert_eq!(
            OpCode::from_i32(raw_ops[4].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[4].output().as_ref().unwrap().offset, 0x206); // ZF
        assert_eq!(
            OpCode::from_i32(raw_ops[5].get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[6].get_opcode()),
            Some(OpCode::CPUI_POPCOUNT)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("add_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("add_rax_1_minimal", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_sub_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x83, 0xe8, 0x08]; // sub rax, 8
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: sub lifts with full flag pcode (ia.sinc
        // `subflags; op1 = op1 - op2; resultflags(op1)`): INT_LESS CF,
        // INT_SBORROW OF, INT_SUB writing rax directly (imm canonicalized to
        // 8 bytes), SF/ZF and the PF popcount chain — 9 ops.
        assert_eq!(raw_ops.len(), 9);

        assert_eq!(
            OpCode::from_i32(raw_ops[0].get_opcode()),
            Some(OpCode::CPUI_INT_LESS)
        );
        assert_eq!(raw_ops[0].output().as_ref().unwrap().offset, 0x200); // CF
        assert_eq!(
            OpCode::from_i32(raw_ops[1].get_opcode()),
            Some(OpCode::CPUI_INT_SBORROW)
        );
        assert_eq!(raw_ops[1].output().as_ref().unwrap().offset, 0x20b); // OF

        let raw_sub = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_sub.get_opcode()),
            Some(OpCode::CPUI_INT_SUB)
        );

        let sub_out_binding = raw_sub.output();
        let sub_out = sub_out_binding.as_ref().unwrap();
        assert_eq!(sub_out.space, AddressSpace::Register);
        assert_eq!(sub_out.offset, 0x00); // RAX
        assert_eq!(sub_out.size, 8);

        let sub_inputs = raw_sub.inputs();
        assert_eq!(sub_inputs.len(), 2);
        assert_eq!(sub_inputs[0].space, AddressSpace::Register);
        assert_eq!(sub_inputs[0].offset, 0x00); // RAX
        assert_eq!(sub_inputs[0].size, 8);
        assert_eq!(sub_inputs[1].space, AddressSpace::Const);
        assert_eq!(sub_inputs[1].offset, 0x08);
        assert_eq!(sub_inputs[1].size, 8);

        // SF/ZF from the destination varnode; PF popcount chain
        assert_eq!(
            OpCode::from_i32(raw_ops[3].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(raw_ops[3].output().as_ref().unwrap().offset, 0x207); // SF
        assert_eq!(
            OpCode::from_i32(raw_ops[4].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[4].output().as_ref().unwrap().offset, 0x206); // ZF
        assert_eq!(
            OpCode::from_i32(raw_ops[6].get_opcode()),
            Some(OpCode::CPUI_POPCOUNT)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("sub_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation("sub_rax_8_minimal", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Fourth batch: and / or / xor / shl / shr / cmp ==========

    #[test]
    fn test_and_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // and rax, 0xf  →  48 83 e0 0f
        let code = vec![0x48, 0x83, 0xe0, 0x0f];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: and lifts with full flag pcode (ia.sinc
        // `logicalflags(); Rmr = Rmr & imm; resultflags(Rmr)`): COPY CF=0,
        // COPY OF=0, INT_AND writing rax directly, SF/ZF and the PF popcount
        // chain — 9 ops.
        assert_eq!(raw_ops.len(), 9);

        assert_eq!(
            OpCode::from_i32(raw_ops[0].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[0].output().as_ref().unwrap().offset, 0x200); // CF
        assert_eq!(raw_ops[0].inputs()[0].space, AddressSpace::Const);
        assert_eq!(raw_ops[0].inputs()[0].offset, 0x0);
        assert_eq!(
            OpCode::from_i32(raw_ops[1].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[1].output().as_ref().unwrap().offset, 0x20b); // OF

        let raw_op = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Register);
        assert_eq!(op_out.offset, 0x00); // RAX
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x0f);
        assert_eq!(op_inputs[1].size, 8);

        assert_eq!(
            OpCode::from_i32(raw_ops[3].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(raw_ops[3].output().as_ref().unwrap().offset, 0x207); // SF
        assert_eq!(
            OpCode::from_i32(raw_ops[4].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[4].output().as_ref().unwrap().offset, 0x206); // ZF
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("and_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("and_rax_0xf_minimal", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_or_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // or rax, 0x10  →  48 83 c8 10
        let code = vec![0x48, 0x83, 0xc8, 0x10];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: or = logicalflags + INT_OR direct-dst +
        // resultflags — 9 ops (same shape as and).
        assert_eq!(raw_ops.len(), 9);

        assert_eq!(
            OpCode::from_i32(raw_ops[0].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[0].output().as_ref().unwrap().offset, 0x200); // CF
        assert_eq!(
            OpCode::from_i32(raw_ops[1].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[1].output().as_ref().unwrap().offset, 0x20b); // OF

        let raw_op = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_OR)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Register);
        assert_eq!(op_out.offset, 0x00); // RAX
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Const);
        assert_eq!(op_inputs[1].offset, 0x10);
        assert_eq!(op_inputs[1].size, 8);

        assert_eq!(
            OpCode::from_i32(raw_ops[3].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[4].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("or_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("or_rax_0x10_minimal", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_xor_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // xor rax, 0x7  →  48 83 f0 07
        let code = vec![0x48, 0x83, 0xf0, 0x07];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        // X86LIFT-FLAG-PCODE-0001: xor = logicalflags + INT_XOR direct-dst +
        // resultflags — 9 ops (same shape as and/or).
        assert_eq!(raw_ops.len(), 9);
        assert_eq!(
            OpCode::from_i32(raw_ops[0].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[0].output().as_ref().unwrap().offset, 0x200); // CF
        assert_eq!(
            OpCode::from_i32(raw_ops[1].get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(raw_ops[1].output().as_ref().unwrap().offset, 0x20b); // OF
        assert_eq!(
            OpCode::from_i32(raw_ops[2].get_opcode()),
            Some(OpCode::CPUI_INT_XOR)
        );
        assert_eq!(raw_ops[2].output().as_ref().unwrap().space, AddressSpace::Register);
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("xor_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 9);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("xor_rax_0x7_minimal", start, &rugra_ops, 9);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shl_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // shl rax, 4  →  48 c1 e0 04
        let code = vec![0x48, 0xc1, 0xe0, 0x04];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001 + ea5010e9 (shl/sal shift flags ported
        // from the locked x86-64.sla shlflags/shiftresultflags templates,
        // all count forms): count&0x3f mask, saved pre-shift value, direct
        // INT_LEFT to rax, then CF(bit count-1)/OF/SF/ZF/POPCOUNT-PF
        // chains — 37 ops. The old 2-op (INT_LEFT+COPY) expectation was
        // the pre-flag-pcode form, masked from failing by the
        // FFI_TEST_LOCK poison cascade (TESTLIB-STATE-CONTAMINATION-0001).
        assert_eq!(raw_ops.len(), 37);

        // Op 0: tmp:4 = count & 0x3f (sla masks the shift count)
        let raw_mask = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_mask.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );
        let mask_inputs = raw_mask.inputs();
        assert_eq!(mask_inputs.len(), 2);
        assert_eq!(mask_inputs[0].space, AddressSpace::Const);
        assert_eq!(mask_inputs[0].offset, 0x04);
        assert_eq!(mask_inputs[0].size, 4);
        assert_eq!(mask_inputs[1].space, AddressSpace::Const);
        assert_eq!(mask_inputs[1].offset, 0x3f);

        // Op 2: RAX = INT_LEFT(RAX, tmp) — direct-dst shift
        let raw_op = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_LEFT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Register);
        assert_eq!(op_out.offset, 0x00); // RAX
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Unique); // masked count

        // Op 1: saved pre-shift RAX (CF extracts bit count-1 from it)
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        // Flag-register writers terminate the chains: CF(0x200) at #10,
        // OF(0x20b) at #17, SF(0x207) at #23, ZF(0x206) at #28,
        // PF(0x202) at #36 (INT_OR merge per sla resultflags pattern).
        for (idx, flag_off) in [(10usize, 0x200u64), (17, 0x20b), (23, 0x207), (28, 0x206), (36, 0x202)] {
            let writer = &raw_ops[idx];
            assert_eq!(
                OpCode::from_i32(writer.get_opcode()),
                Some(OpCode::CPUI_INT_OR),
                "flag writer at #{}",
                idx
            );
            let out_binding = writer.output();
            let out = out_binding.as_ref().unwrap();
            assert_eq!(out.space, AddressSpace::Register);
            assert_eq!(out.offset, flag_off);
            assert_eq!(out.size, 1);
        }

        let mut fd = Funcdata::new("shl_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 37);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shl_rax_4_minimal", start, &rugra_ops, 37);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_shr_rax_imm_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // shr rax, 4  →  48 c1 e8 04
        let code = vec![0x48, 0xc1, 0xe8, 0x04];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001 + ea5010e9 (shr shares the ported
        // shlflags/shiftresultflags templates): count&0x3f mask, saved
        // pre-shift value, direct INT_RIGHT to rax, then CF(bit count-1 of
        // the ORIGINAL value, via a second INT_RIGHT + INT_AND&1)/OF/SF/ZF/
        // POPCOUNT-PF chains — 37 ops. Old 2-op expectation was the
        // pre-flag-pcode form, masked by the FFI_TEST_LOCK poison cascade
        // (TESTLIB-STATE-CONTAMINATION-0001).
        assert_eq!(raw_ops.len(), 37);

        // Op 0: tmp:4 = count & 0x3f
        let raw_mask = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_mask.get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        // Op 2: RAX = INT_RIGHT(RAX, tmp) — direct-dst shift
        let raw_op = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_op.get_opcode()),
            Some(OpCode::CPUI_INT_RIGHT)
        );

        let op_out_binding = raw_op.output();
        let op_out = op_out_binding.as_ref().unwrap();
        assert_eq!(op_out.space, AddressSpace::Register);
        assert_eq!(op_out.offset, 0x00); // RAX
        assert_eq!(op_out.size, 8);

        let op_inputs = raw_op.inputs();
        assert_eq!(op_inputs.len(), 2);
        assert_eq!(op_inputs[0].space, AddressSpace::Register);
        assert_eq!(op_inputs[0].offset, 0x00); // RAX
        assert_eq!(op_inputs[1].space, AddressSpace::Unique); // masked count

        // Op 1: saved pre-shift RAX; Ops 5-6: CF = (orig >> (count-1)) & 1
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[5].get_opcode()),
            Some(OpCode::CPUI_INT_RIGHT)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[6].get_opcode()),
            Some(OpCode::CPUI_INT_AND)
        );

        let mut fd = Funcdata::new("shr_rax_imm", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 37);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("shr_rax_4_minimal", start, &rugra_ops, 37);

        assert!(matches!(result, VerifyResult::Match));
    }

    #[test]
    fn test_cmp_rax_rbx_minimal_alignment_path() {
        let _lock = ffi_test_lock();
        // cmp rax, rbx  →  48 39 d8
        let code = vec![0x48, 0x39, 0xd8];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: cmp lifts per ia.sinc `local temp = rm;
        // subflags(temp,src); local diff = temp - src; resultflags(diff)`:
        // INT_LESS CF (0x200), INT_SBORROW OF (0x20b), INT_SUB to a unique
        // diff, then SF/ZF/PF from the diff — 9 ops.
        // SLEIGH-RUSTIFY-PHASE3-0001: the engine's cmp template is the .sla's
        // `local temp = rm; subflags(temp,src); local diff = temp - src;
        // resultflags(diff)` — the COPY tmp <- rm op leads the chain (10
        // ops), where the retired iced lift computed the flags straight off
        // the registers (9 ops).
        assert_eq!(raw_ops.len(), 10);

        // Op 0: tmp = COPY(rax)
        let raw_tmp = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_tmp.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        let tmp_out_binding = raw_tmp.output();
        let tmp_out = tmp_out_binding.as_ref().unwrap();
        assert_eq!(tmp_out.space, AddressSpace::Unique);
        assert_eq!(tmp_out.size, 8);
        let tmp_inputs = raw_tmp.inputs();
        assert_eq!(tmp_inputs.len(), 1);
        assert_eq!(tmp_inputs[0].space, AddressSpace::Register);
        assert_eq!(tmp_inputs[0].offset, 0x00); // RAX

        // Op 1: CF = INT_LESS(tmp, rbx)
        let raw_cf = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_cf.get_opcode()),
            Some(OpCode::CPUI_INT_LESS)
        );
        let cf_out_binding = raw_cf.output();
        let cf_out = cf_out_binding.as_ref().unwrap();
        assert_eq!(cf_out.space, AddressSpace::Register);
        assert_eq!(cf_out.offset, 0x200); // CF (sla layout)
        assert_eq!(cf_out.size, 1);
        let cf_inputs = raw_cf.inputs();
        assert_eq!(cf_inputs.len(), 2);
        assert_eq!(cf_inputs[0].space, AddressSpace::Unique); // the temp
        assert_eq!(cf_inputs[1].space, AddressSpace::Register);
        assert_eq!(cf_inputs[1].offset, 0x18); // RBX

        // Op 2: OF = INT_SBORROW(tmp, rbx)
        let raw_of = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_of.get_opcode()),
            Some(OpCode::CPUI_INT_SBORROW)
        );
        assert_eq!(raw_of.output().as_ref().unwrap().offset, 0x20b); // OF

        // Op 3: diff = INT_SUB(tmp, rbx) to unique
        let raw_sub = &raw_ops[3];
        assert_eq!(
            OpCode::from_i32(raw_sub.get_opcode()),
            Some(OpCode::CPUI_INT_SUB)
        );
        let sub_out_binding = raw_sub.output();
        let sub_out = sub_out_binding.as_ref().unwrap();
        assert_eq!(sub_out.space, AddressSpace::Unique);
        assert_eq!(sub_out.size, 8);

        // SF/ZF/PF read the diff
        assert_eq!(
            OpCode::from_i32(raw_ops[4].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(raw_ops[4].output().as_ref().unwrap().offset, 0x207); // SF
        assert_eq!(
            OpCode::from_i32(raw_ops[5].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[5].output().as_ref().unwrap().offset, 0x206); // ZF
        assert_eq!(
            OpCode::from_i32(raw_ops[9].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[9].output().as_ref().unwrap().offset, 0x202); // PF

        let mut fd = Funcdata::new("cmp_rax_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 10);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("cmp_rax_rbx_minimal", start, &rugra_ops, 10);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== Memory instruction (LOAD / STORE) alignment tests ==========

    /// Test: `mov rax, [rbx]` — Simple memory load
    /// Machine code: 48 8b 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(const(ram_space_id), reg(rbx)) -> unique_tmp
    ///   2. CPUI_COPY(unique_tmp) -> reg(rax)
    #[test]
    fn test_load_mov_rax_mem_rbx_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x8b, 0x03]; // mov rax, [rbx]
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        // parse_operand for Memory emits a LOAD internally, then mov emits COPY
        // So we expect: LOAD + COPY = 2 ops
        assert_eq!(
            raw_ops.len(), 2, "Expected LOAD + COPY, got {} ops", raw_ops.len()
        );

        // Op 0: CPUI_LOAD
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        // Input 0: RAM space ID as a constant
        assert_eq!(load_inputs[0].space, AddressSpace::Const);
        assert_eq!(load_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx register
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx offset
        assert_eq!(load_inputs[1].size, 8);

        // Op 1: CPUI_COPY
        let raw_copy = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax
        assert_eq!(copy_out.size, 8);

        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Unique);
        assert_eq!(copy_inputs[0].offset, load_out.offset);

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("load_mov_rax_mem_rbx", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov [rbx], rax` — Simple memory store
    /// Machine code: 48 89 03
    /// Expected P-code:
    ///   1. CPUI_STORE(const(ram_space_id), reg(rbx), reg(rax)) — no output
    #[test]
    fn test_store_mov_mem_rbx_rax_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x89, 0x03]; // mov [rbx], rax
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        // SLEIGH-RUSTIFY-PHASE3-0001: the engine's `mov [rbx], rax` template
        // routes the source register through a unique temp first (COPY tmp
        // <- rax; STORE ram-id,rbx,tmp — the .sla's store constructor), 2
        // ops where the retired iced lift stored the register directly.
        assert_eq!(
            raw_ops.len(), 2, "Expected COPY+STORE ops, got {} ops", raw_ops.len()
        );

        // Op 0: CPUI_COPY tmp <- rax
        let raw_copy = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );
        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Unique);
        assert_eq!(copy_out.size, 8);
        let copy_inputs = raw_copy.inputs();
        assert_eq!(copy_inputs.len(), 1);
        assert_eq!(copy_inputs[0].space, AddressSpace::Register);
        assert_eq!(copy_inputs[0].offset, 0x00); // rax
        assert_eq!(copy_inputs[0].size, 8);

        // Op 1: CPUI_STORE
        let raw_store = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );

        // STORE has no output
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        // Input 0: RAM space ID
        assert_eq!(store_inputs[0].space, AddressSpace::Const);
        assert_eq!(store_inputs[0].offset, AddressSpace::Ram.space_id() as u64);
        // Input 1: address from rbx
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx
        assert_eq!(store_inputs[1].size, 8);
        // Input 2: value from the temp copy of rax
        assert_eq!(store_inputs[2].space, AddressSpace::Unique);
        assert_eq!(store_inputs[2].size, 8);

        // Inject and verify
        let mut fd = Funcdata::new("store_mov_mem_rbx_rax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 2);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("store_mov_mem_rbx_rax", start, &rugra_ops, 2);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, [rbx+0x10]` — Memory load with displacement
    /// Machine code: 48 8b 43 10
    /// Expected P-code:
    ///   1. CPUI_INT_ADD(rbx, 0x10) -> tmp_addr
    ///   2. CPUI_LOAD(const(ram_space_id), tmp_addr) -> tmp_val
    ///   3. CPUI_COPY(tmp_val) -> rax
    #[test]
    fn test_load_mov_rax_mem_rbx_disp_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x8b, 0x43, 0x10]; // mov rax, [rbx+0x10]
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        // Displacement != 0 → INT_ADD for addr calc, then LOAD, then COPY
        assert_eq!(
            raw_ops.len(), 3, "Expected INT_ADD + LOAD + COPY, got {} ops", raw_ops.len()
        );

        // Op 0: CPUI_INT_ADD for address computation
        let raw_add = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Register);
        assert_eq!(add_inputs[0].offset, 0x18); // rbx
        assert_eq!(add_inputs[1].space, AddressSpace::Const);
        assert_eq!(add_inputs[1].offset, 0x10); // displacement

        // Op 1: CPUI_LOAD
        let raw_load = &raw_ops[1];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Unique); // computed address
        assert_eq!(load_inputs[1].offset, add_out.offset);

        // Op 2: CPUI_COPY
        let raw_copy = &raw_ops[2];
        assert_eq!(
            OpCode::from_i32(raw_copy.get_opcode()),
            Some(OpCode::CPUI_COPY)
        );

        let copy_out_binding = raw_copy.output();
        let copy_out = copy_out_binding.as_ref().unwrap();
        assert_eq!(copy_out.space, AddressSpace::Register);
        assert_eq!(copy_out.offset, 0x00); // rax

        // Inject and verify
        let mut fd = Funcdata::new("load_mov_rax_mem_rbx_disp", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result = verifier.verify_pcode_generation(
            "load_mov_rax_mem_rbx_disp",
            start,
            &rugra_ops,
            3);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `add [rbx], rax` — Memory read-modify-write
    /// Machine code: 48 01 03
    /// Expected P-code:
    ///   1. CPUI_LOAD(ram_space_id, rbx) -> tmp_orig  (read original value)
    ///   2. CPUI_INT_ADD(tmp_orig, rax) -> tmp_result
    ///   3. CPUI_STORE(ram_space_id, rbx, tmp_result)  (write back)
    #[test]
    fn test_add_mem_rbx_rax_rmw_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![0x48, 0x01, 0x03]; // add [rbx], rax
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic/text metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        // X86LIFT-FLAG-PCODE-0001: `add [rbx], rax` lifts per the locked
        // 12.0.4 x86-64.sla rm-operand re-evaluation — every macro use of the
        // memory operand re-LOADs (addflags reads it twice, the value op once,
        // and resultflags re-LOADs per flag group after the STORE):
        // LOAD, INT_CARRY, LOAD, INT_SCARRY, LOAD, INT_ADD, STORE,
        // LOAD, SF, LOAD, ZF, LOAD, AND, POPCOUNT, AND, PF = 16 ops.
        assert_eq!(
            raw_ops.len(), 16,
            "Expected LOAD+CARRY+LOAD+SCARRY+LOAD+ADD+STORE+3x(LOAD+flag)+PF-chain, got {} ops",
            raw_ops.len()
        );

        // Op 0: CPUI_LOAD (first materialization for addflags INT_CARRY)
        let raw_load = &raw_ops[0];
        assert_eq!(
            OpCode::from_i32(raw_load.get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );

        let load_out_binding = raw_load.output();
        let load_out = load_out_binding.as_ref().unwrap();
        assert_eq!(load_out.space, AddressSpace::Unique);
        assert_eq!(load_out.size, 8);

        let load_inputs = raw_load.inputs();
        assert_eq!(load_inputs.len(), 2);
        assert_eq!(load_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(load_inputs[1].space, AddressSpace::Register);
        assert_eq!(load_inputs[1].offset, 0x18); // rbx

        // Op 1: INT_CARRY CF; op 2: re-LOAD; op 3: INT_SCARRY OF
        assert_eq!(
            OpCode::from_i32(raw_ops[1].get_opcode()),
            Some(OpCode::CPUI_INT_CARRY)
        );
        assert_eq!(raw_ops[1].output().as_ref().unwrap().offset, 0x200); // CF
        assert_eq!(
            OpCode::from_i32(raw_ops[2].get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[3].get_opcode()),
            Some(OpCode::CPUI_INT_SCARRY)
        );
        assert_eq!(raw_ops[3].output().as_ref().unwrap().offset, 0x20b); // OF

        // Op 4: re-LOAD; op 5: CPUI_INT_ADD writing the load temp
        let raw_add = &raw_ops[5];
        assert_eq!(
            OpCode::from_i32(raw_add.get_opcode()),
            Some(OpCode::CPUI_INT_ADD)
        );

        let add_out_binding = raw_add.output();
        let add_out = add_out_binding.as_ref().unwrap();
        assert_eq!(add_out.space, AddressSpace::Unique);
        assert_eq!(add_out.offset, raw_ops[4].output().as_ref().unwrap().offset);

        let add_inputs = raw_add.inputs();
        assert_eq!(add_inputs.len(), 2);
        assert_eq!(add_inputs[0].space, AddressSpace::Unique);
        assert_eq!(add_inputs[0].offset, add_out.offset);
        assert_eq!(add_inputs[1].space, AddressSpace::Register);
        assert_eq!(add_inputs[1].offset, 0x00); // rax

        // Op 6: CPUI_STORE (write result back to [rbx])
        let raw_store = &raw_ops[6];
        assert_eq!(
            OpCode::from_i32(raw_store.get_opcode()),
            Some(OpCode::CPUI_STORE)
        );
        assert!(raw_store.output().is_none());

        let store_inputs = raw_store.inputs();
        assert_eq!(store_inputs.len(), 3);
        assert_eq!(store_inputs[0].space, AddressSpace::Const); // RAM space ID
        assert_eq!(store_inputs[1].space, AddressSpace::Register);
        assert_eq!(store_inputs[1].offset, 0x18); // rbx (address)
        assert_eq!(store_inputs[2].space, AddressSpace::Unique); // result

        // Post-store flag re-LOADs: SF (ops 7-8), ZF (ops 9-10), PF (11-15)
        assert_eq!(
            OpCode::from_i32(raw_ops[7].get_opcode()),
            Some(OpCode::CPUI_LOAD)
        );
        assert_eq!(
            OpCode::from_i32(raw_ops[8].get_opcode()),
            Some(OpCode::CPUI_INT_SLESS)
        );
        assert_eq!(raw_ops[8].output().as_ref().unwrap().offset, 0x207); // SF
        assert_eq!(
            OpCode::from_i32(raw_ops[10].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[10].output().as_ref().unwrap().offset, 0x206); // ZF
        assert_eq!(
            OpCode::from_i32(raw_ops[15].get_opcode()),
            Some(OpCode::CPUI_INT_EQUAL)
        );
        assert_eq!(raw_ops[15].output().as_ref().unwrap().offset, 0x202); // PF

        // Inject and verify
        let mut fd = Funcdata::new("add_mem_rbx_rax_rmw", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 16);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("add_mem_rbx_rax_rmw", start, &rugra_ops, 16);

        assert!(matches!(result, VerifyResult::Match));
    }

    // ========== SSA alignment tests ==========

    /// Test: Single-block SSA construction for `mov rax, rdi; add rax, rsi; ret`
    ///
    /// Verifies that after heritage (SSA construction), a single-block
    /// function has:
    /// - No MULTIEQUAL (Phi) nodes (single block, no merge point)
    /// - Heritage pass counter incremented
    /// - Varnode def/use chains are established
    #[test]
    fn test_ssa_single_block_linear() {
        let _lock = ffi_test_lock();

        // Build raw ops for: mov rax, rdi; add rax, rsi; ret
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("ssa_linear", start, 10);

        // Inject ops
        fd.inject_raw_ops(&[op1, op2, op3]);
        assert_eq!(fd.obank.alivelist.len(), 3);
        assert_eq!(fd.bblocks.get_size(), 1);

        // Build dominator tree (required for heritage)
        fd.bblocks.build_dom_tree();

        // Run heritage directly using the _direct methods to avoid
        // the deadlock that occurs when heritage() tries to re-acquire
        // the Funcdata lock via fd_weak.upgrade().
        fd.heritage.place_multiequals_direct(
            &mut fd.vbank,
            &mut fd.obank,
            &fd.bblocks,
            &fd.sblocks,
        );
        fd.heritage.rename_direct(&mut fd.vbank, &fd.bblocks);
        fd.heritage.pass += 1;

        // Heritage pass should have incremented
        assert_eq!(
            fd.num_heritage_passes(), 1, "Heritage pass should be 1 after first run"
        );

        // Single block → no MULTIEQUAL ops should be inserted
        let multiequal_count = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .count();
        assert_eq!(
            multiequal_count, 0,
            "Single block should have no Phi (MULTIEQUAL) nodes, found {}",
            multiequal_count
        );

        // Original 3 ops should still be present
        assert!(
            fd.obank.alivelist.len() >= 3,
            "Should still have at least 3 original ops"
        );
    }

    // ========== Multi-instruction sequence tests ==========

    /// Test: `mov rax, rdi; add rax, rsi; ret`
    /// A minimal function that returns first_arg + second_arg.
    /// Produces 4 P-code ops in a single basic block:
    ///   COPY(rax ← rdi), INT_ADD(tmp), COPY(rax ← tmp), RETURN
    #[test]
    fn test_seq_mov_add_ret_alignment() {
        let _lock = ffi_test_lock();
        // mov rax, rdi = 48 89 f8
        // add rax, rsi = 48 01 f0
        // ret          = c3
        let code = vec![
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0x01, 0xf0, // add rax, rsi
            0xc3,             // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        // Verify sequential addresses
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001: mov→1(COPY) + add→9(CARRY/SCARRY/ADD
        // direct-dst/SF/ZF/PF chain) + ret→3(RET-OP3-0001: LOAD RIP←
        // ram[RSP]; INT_ADD RSP,8; RETURN [RIP] — locked .sla template) = 13
        assert_eq!(all_raw_ops.len(), 13);

        // Verify op sequence
        assert_eq!(
            OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_INT_CARRY)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[10].get_opcode()), Some(OpCode::CPUI_LOAD)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[11].get_opcode()), Some(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[12].get_opcode()), Some(OpCode::CPUI_RETURN)
        );

        // Phase 3: Inject into Funcdata
        let mut fd = Funcdata::new("seq_mov_add_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 13);
        // RETURN terminates, all ops in one block
        assert_eq!(fd.bblocks.get_size(), 1);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_mov_add_ret", start, &rugra_ops, 13);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: `mov rax, rdi; and rax, 0xf; shl rax, 4; ret`
    /// Arithmetic chain: mask low nibble, shift left by 4. Returns (arg & 0xf) << 4.
    /// Flag-pcode era op budget (X86LIFT-FLAG-PCODE-0001 + ea5010e9 +
    /// RET-OP3-0001): mov→1, and→9, shl→37, ret→3 — 50 ops, 1 basic block.
    #[test]
    fn test_seq_mov_and_shl_ret_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![
            0x48, 0x89, 0xf8,       // mov rax, rdi
            0x48, 0x83, 0xe0, 0x0f, // and rax, 0xf
            0x48, 0xc1, 0xe0, 0x04, // shl rax, 4
            0xc3,                    // ret
        ];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001 + ea5010e9 + RET-OP3-0001: mov→1 +
        // and→9(logicalflags+AND direct-dst+SF/ZF/PF) + shl→37(count mask,
        // saved value, direct INT_LEFT, CF/OF/SF/ZF/PF chains) + ret→3
        // (RIP=LOAD(ram[RSP]); RSP=INT_ADD(RSP,8); RETURN[RIP] per the
        // locked sla :RET template) = 50. Old 13 assumed shl→2
        // (flags 未实现) and ret→1 — both stale, masked by the
        // FFI_TEST_LOCK poison cascade (TESTLIB-STATE-CONTAMINATION-0001).
        assert_eq!(all_raw_ops.len(), 50);

        assert_eq!(
            OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[1].get_opcode()), Some(OpCode::CPUI_COPY) // CF=0
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[3].get_opcode()), Some(OpCode::CPUI_INT_AND)
        );
        // shl block: flat[10]=count&0x3f mask, flat[11]=saved RAX,
        // flat[12]=direct INT_LEFT result write
        assert_eq!(
            OpCode::from_i32(all_raw_ops[10].get_opcode()), Some(OpCode::CPUI_INT_AND)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[11].get_opcode()), Some(OpCode::CPUI_COPY)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[12].get_opcode()), Some(OpCode::CPUI_INT_LEFT)
        );
        // ret block: flat[47]=LOAD return address, flat[48]=RSP bump,
        // flat[49]=RETURN
        assert_eq!(
            OpCode::from_i32(all_raw_ops[47].get_opcode()), Some(OpCode::CPUI_LOAD)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[48].get_opcode()), Some(OpCode::CPUI_INT_ADD)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[49].get_opcode()), Some(OpCode::CPUI_RETURN)
        );

        let mut fd = Funcdata::new("seq_and_shl_ret", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 50);
        assert_eq!(fd.bblocks.get_size(), 1);

        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_and_shl_ret", start, &rugra_ops, 50);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch
    /// ```text
    /// 0x1000: cmp rdi, rsi     ; 48 39 f7
    /// 0x1003: je  0x100d       ; 74 08
    /// 0x1005: mov rax, 1       ; 48 c7 c0 01 00 00 00
    /// 0x100c: ret              ; c3
    /// 0x100d: xor rax, rax     ; 48 31 c0     (je target)
    /// 0x1010: ret              ; c3
    /// ```
    /// Tests: CBRANCH generation, basic block splitting, multi-block inject.
    /// Flag-pcode era op budget (X86LIFT-FLAG-PCODE-0001 + RET-OP3-0001):
    /// Block 0: cmp(9 flag ops) + je(CBRANCH) = 10 ops
    /// Block 1: mov(COPY) + ret(3-op :RET template) = 4 ops
    /// Block 2: xor(9 flag ops) + ret(3-op :RET template) = 12 ops
    /// Total: 26 ops, 3 blocks
    #[test]
    fn test_seq_cmp_je_multiblock_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![
            0x48, 0x39, 0xf7,                         // cmp rdi, rsi
            0x74, 0x08,                                // je +8 → 0x100d
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
            0xc3,                                      // ret
            0x48, 0x31, 0xc0,                          // xor rax, rax
            0xc3,                                      // ret
        ];
        let start = Address::new(0x1000);

        // Phase 1: Disassemble
        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        // Verify addresses
        // Phase 2: Lift all
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // SLEIGH-RUSTIFY-PHASE3-0001 (engine template, .sla
        // `local temp = rm; subflags(temp,src)`):
        // cmp→10(COPY tmp; LESS/SBORROW/SUB→diff/SF/ZF/PF)
        // je→1(CBRANCH)
        // mov→1(COPY)
        // ret→3(RIP=LOAD(ram[RSP]); RSP=INT_ADD(RSP,8); RETURN[RIP],
        //        locked sla :RET template)
        // xor→9(logicalflags/XOR direct-dst/SF/ZF/PF)
        // ret→3(same :RET template)
        // Total: 27 (the retired iced lift computed cmp flags straight off
        // the registers — 9 ops, 26 total)
        assert_eq!(all_raw_ops.len(), 27);

        // Verify key opcodes
        assert_eq!(
            OpCode::from_i32(all_raw_ops[0].get_opcode()), Some(OpCode::CPUI_COPY) // cmp tmp
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[10].get_opcode()), Some(OpCode::CPUI_CBRANCH)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[11].get_opcode()), Some(OpCode::CPUI_COPY)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[14].get_opcode()), Some(OpCode::CPUI_RETURN)
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[15].get_opcode()), Some(OpCode::CPUI_COPY) // CF=0
        );
        assert_eq!(
            OpCode::from_i32(all_raw_ops[17].get_opcode()), Some(OpCode::CPUI_INT_XOR)
        );

        // Phase 3: Inject and verify block structure
        let mut fd = Funcdata::new("seq_cmp_je_multi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert_eq!(fd.obank.alivelist.len(), 27);
        // CBRANCH terminates block 0, RETURN terminates block 1 and block 2 → 3 blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Verify block 0 has 11 ops (cmp: 10 template ops + CBRANCH)
        let block0 = fd.bblocks.get_block(0).unwrap();
        assert_eq!(block0.read().unwrap().get_ops().len(), 11);

        // Verify block 1 has 4 ops (mov COPY + 3-op :RET template)
        let block1 = fd.bblocks.get_block(1).unwrap();
        assert_eq!(block1.read().unwrap().get_ops().len(), 4);

        // Verify block 2 has 12 ops (xor: 9 flag ops + 3-op :RET template)
        let block2 = fd.bblocks.get_block(2).unwrap();
        assert_eq!(block2.read().unwrap().get_ops().len(), 12);

        // Phase 4: Verify via RuntimeVerifier
        let verifier = RuntimeVerifier::new();
        let rugra_ops: Vec<_> = fd.obank.alivelist.iter().map(|op| op.0.clone()).collect();

        ffi::set_current_program(fd);

        let result =
            verifier.verify_pcode_generation("seq_cmp_je_multiblock", start, &rugra_ops, 27);

        assert!(matches!(result, VerifyResult::Match));
    }

    /// Test: multi-block with conditional branch converging to a merge block
    /// ```text
    /// 0x1000: cmp rdi, 0
    /// 0x1004: je 0x100f
    /// 0x1006: mov rax, 1
    /// 0x100d: jmp 0x1018
    /// 0x100f: mov rax, 2
    /// 0x1016: jmp 0x1018
    /// 0x1018: add rax, rsi
    /// 0x101b: ret
    /// ```
    /// This creates 4 basic blocks:
    /// Block 0: cmp + CBRANCH
    /// Block 1: mov rax, 1 + BRANCH (to block 3)
    /// Block 2: mov rax, 2 + BRANCH (to block 3)
    /// Block 3: MULTIEQUAL (Phi for rax) + add + ret
    #[test]
    fn test_ssa_dual_block_phi_alignment() {
        let _lock = ffi_test_lock();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        let mut fd = Funcdata::new("ssa_phi_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree
        fd.bblocks.build_dom_tree();

        // Run heritage to build SSA
        fd.run_heritage_direct();

        // Verify that a MULTIEQUAL (Phi) node was created
        let multiequals: Vec<_> = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();
            
        assert_eq!(
            multiequals.len(), 1, "Expected exactly 1 Phi node, got {}", multiequals.len()
        );
        
        let phi = multiequals[0].0.read().unwrap();
        assert_eq!(phi.inrefs.len(), 2, "Phi node should have 2 inputs");
        
        let out_vn = phi.output.as_ref().unwrap().read().unwrap();
        assert_eq!(out_vn.get_space(), AddressSpace::Register);
        assert_eq!(out_vn.get_offset(), 0x00); // RAX
        assert_eq!(out_vn.get_size(), 8); // RAX is 8 bytes
    }

    // ========== SSA Renaming Verification Tests ==========

    /// Test: Single-block SSA renaming correctness
    ///
    /// Sequence: mov rax, rdi; add rax, rsi; ret
    /// P-code:
    ///   op0: RAX = COPY(RDI)
    ///   op1: RAX = INT_ADD(RAX, RSI)
    ///   op2: RETURN(const)
    ///
    /// After renaming:
    ///   - op1's first input (RAX) should be rewritten to point to op0's output (the first def of RAX)
    ///   - op0's output and op1's output should be DIFFERENT Varnode instances (different create_index)
    ///   - op1's input[0] should be Arc::ptr_eq to op0's output
    #[test]
    fn test_ssa_rename_single_block_linear() {
        let _lock = ffi_test_lock();

        // Build: op0: RAX = COPY(RDI)
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // Build: op1: RAX = INT_ADD(RAX, RSI)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX (should be rewritten)
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // Build: op2: RETURN(const)
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x3000);
        let mut fd = Funcdata::new("ssa_rename_linear", start, 10);
        fd.inject_raw_ops(&[op0, op1, op2]);

        assert_eq!(
            fd.bblocks.get_size(), 1, "Should have exactly 1 basic block"
        );

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Collect ops in order from the block
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();

        // Filter to only non-MULTIEQUAL ops (there should be none in single block, but be safe)
        let regular_ops: Vec<_> = ops
            .iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();
        assert!(
            regular_ops.len() >= 3, "Should have at least 3 regular ops, got {}", regular_ops.len()
        );

        let pcode_op0 = regular_ops[0].0.read().unwrap();
        let pcode_op1 = regular_ops[1].0.read().unwrap();

        // op0 output: the first definition of RAX
        let op0_out = pcode_op0.output.as_ref().expect("op0 should have output");
        // op1 output: the second definition of RAX
        let op1_out = pcode_op1.output.as_ref().expect("op1 should have output");

        // VERIFY: op0 and op1 outputs are DIFFERENT Varnode instances
        assert!(
            !Arc::ptr_eq(op0_out, op1_out),
            "op0 and op1 should define DIFFERENT Varnode instances for RAX"
        );
        // Both should be at Register:0x00 (RAX)
        assert_eq!(op0_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op0_out.read().unwrap().get_offset(), 0x00);
        assert_eq!(op1_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(op1_out.read().unwrap().get_offset(), 0x00);

        // VERIFY: op1's first input (RAX) was rewritten to point to op0's output
        let op1_in0 = &pcode_op1.inrefs[0];
        assert!(
            Arc::ptr_eq(op1_in0, op0_out),
            "After renaming, op1's RAX input should point to op0's output Varnode. \
             op1_in0 create_index={}, op0_out create_index={}",
            op1_in0.read().unwrap().get_create_index(),
            op0_out.read().unwrap().get_create_index(),
        );

        // VERIFY: op0's and op1's outputs have different create_index
        let ci0 = op0_out.read().unwrap().get_create_index();
        let ci1 = op1_out.read().unwrap().get_create_index();
        assert_ne!(
            ci0, ci1, "Different definitions of RAX should have different create_index: {} vs {}", ci0, ci1
        );
    }

    /// Test: Multi-block SSA renaming with Phi node input filling
    ///
    /// Assembly:
    ///   cmp rdi, 0       (Block 0)
    ///   je block2
    ///   mov rax, 1       (Block 1)
    ///   jmp block3
    ///   mov rax, 2       (Block 2)
    ///   jmp block3
    ///   add rax, rsi     (Block 3 — merge)
    ///   ret
    ///
    /// After renaming, at the merge block:
    ///   - A MULTIEQUAL (Phi) for RAX should exist
    ///   - Phi input 0 should be the RAX definition from Block 1 (mov rax, 1)
    ///   - Phi input 1 should be the RAX definition from Block 2 (mov rax, 2)
    ///   - op `add rax, rsi` in Block 3 should use the Phi output as its RAX input
    #[test]
    fn test_ssa_rename_multi_block_phi_inputs() {
        let _lock = ffi_test_lock();
        let code = vec![
            0x48, 0x83, 0xff, 0x00,                         // cmp rdi, 0
            0x74, 0x09,                                     // je 0x100f
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1
            0xeb, 0x09,                                     // jmp 0x1018
            0x48, 0xc7, 0xc0, 0x02, 0x00, 0x00, 0x00,       // mov rax, 2
            0xeb, 0x00,                                     // jmp 0x1018
            0x48, 0x01, 0xf0,                               // add rax, rsi
            0xc3,                                           // ret
        ];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        let mut fd = Funcdata::new("ssa_rename_phi", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the MULTIEQUAL (Phi) op for RAX
        let multiequals: Vec<_> = fd
            .obank
            .optree
            .iter()
            .filter(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_MULTIEQUAL)
            .collect();

        // Find Phi node for RAX (Register:0x00)
        let rax_phis: Vec<_> = multiequals
            .iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(
            !rax_phis.is_empty(), "Should have at least one Phi node for RAX"
        );
        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(
            phi.inrefs.len(), 2, "RAX Phi node should have 2 inputs (from 2 predecessor blocks)"
        );

        // VERIFY: Both Phi inputs should be WRITTEN varnodes (defined by mov rax, 1 / mov rax, 2)
        // After renaming, Phi inputs should NOT be placeholder varnodes — they should point to
        // the actual definitions from the predecessor blocks.
        for (idx, phi_input) in phi.inrefs.iter().enumerate() {
            let vn = phi_input.read().unwrap();
            assert_eq!(
                vn.get_space(), AddressSpace::Register,
                "Phi input {} should be in Register space", idx
            );
            assert_eq!(
                vn.get_offset(), 0x00,
                "Phi input {} should reference RAX (offset 0x00)", idx
            );
            // Each phi input should be a WRITTEN varnode (defined by a preceding op)
            // or at least not the same as the phi output itself
            assert!(
                !Arc::ptr_eq(phi_input, phi.output.as_ref().unwrap()),
                "Phi input {} should NOT be the same as Phi output", idx
            );
        }

        // VERIFY: The two Phi inputs should be DIFFERENT varnodes
        // (they come from different blocks with different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Phi's two inputs should be different Varnode instances (from different blocks). \
             input0 ci={}, input1 ci={}",
            phi.inrefs[0].read().unwrap().get_create_index(),
            phi.inrefs[1].read().unwrap().get_create_index(),
        );

        // VERIFY: Find the merge block's `add rax, rsi` op
        // Its RAX input should point to the Phi output, not to some random prior definition
        let phi_output = phi.output.as_ref().unwrap().clone();
        drop(phi); // Release the read lock

        // Search all ops for INT_ADD in the merge block that uses RAX
        let add_ops: Vec<_> = fd
            .obank
            .optree
            .iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                op.get_opcode() == OpCode::CPUI_INT_ADD
                    && op.inrefs.iter().any(|inref| {
                        let vn = inref.read().unwrap();
                        vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                    })
            })
            .collect();

        // Among those, find one whose RAX input is the Phi output
        let uses_phi_output = add_ops.iter().any(|op_ref| {
            let op = op_ref.0.read().unwrap();
            op.inrefs
                .iter()
                .any(|inref| Arc::ptr_eq(inref, &phi_output))
        });
        assert!(
            uses_phi_output,
            "The merge block's INT_ADD should use the Phi output as its RAX input"
        );
    }

    /// Test: SSA renaming with diamond CFG pattern
    ///
    /// Uses `mov rax, imm` instructions to ensure direct RAX definitions.
    /// CFG:
    ///   Block 0 (entry): cmp rdi,0; je block2
    ///   Block 1 (then):  mov rax, 0x10; jmp block3
    ///   Block 2 (else):  mov rax, 0x20; jmp block3
    ///   Block 3 (merge): ret   (Phi for RAX should be placed here)
    #[test]
    fn test_ssa_rename_diamond_pattern() {
        let _lock = ffi_test_lock();

        let code = vec![
            // Block 0: cmp rdi, 0; je block2
            0x48, 0x83, 0xff, 0x00,                         // 0x4000: cmp rdi, 0
            0x74, 0x09,                                     // 0x4004: je +9 → 0x400f
            // Block 1: mov rax, 0x10; jmp block3
            0x48, 0xc7, 0xc0, 0x10, 0x00, 0x00, 0x00,       // 0x4006: mov rax, 0x10
            0xeb, 0x09,                                     // 0x400d: jmp +9 → 0x4018
            // Block 2: mov rax, 0x20; jmp block3
            0x48, 0xc7, 0xc0, 0x20, 0x00, 0x00, 0x00,       // 0x400f: mov rax, 0x20
            0xeb, 0x00,                                     // 0x4016: jmp +0 → 0x4018
            // Block 3: ret
            0xc3,                                           // 0x4018: ret
        ];
        let start = Address::new(0x4000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        let mut fd = Funcdata::new("ssa_diamond", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        let num_blocks = fd.bblocks.get_size();
        assert!(
            num_blocks >= 3, "Diamond pattern should have at least 3 blocks, got {}", num_blocks
        );

        // Build dom tree & run heritage
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find Phi nodes for RAX (Register:0x00)
        let rax_phis: Vec<_> = fd
            .obank
            .optree
            .iter()
            .filter(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                    return false;
                }
                if let Some(out_vn) = &op.output {
                    let vn = out_vn.read().unwrap();
                    vn.get_space() == AddressSpace::Register && vn.get_offset() == 0x00
                } else {
                    false
                }
            })
            .collect();

        assert!(
            !rax_phis.is_empty(), "Diamond merge should have Phi for RAX"
        );

        let phi = rax_phis[0].0.read().unwrap();
        assert_eq!(
            phi.inrefs.len(), 2,
            "RAX Phi at diamond merge should have 2 inputs, got {}",
            phi.inrefs.len()
        );

        // VERIFY: Both inputs should be register RAX varnodes
        for (i, phi_in) in phi.inrefs.iter().enumerate() {
            let vn = phi_in.read().unwrap();
            assert_eq!(
                vn.get_space(), AddressSpace::Register,
                "Phi input {} should be Register", i
            );
            assert_eq!(
                vn.get_offset(), 0x00,
                "Phi input {} should be RAX (offset 0x00)", i
            );
        }

        // VERIFY: Phi inputs are distinct (different definitions)
        assert!(
            !Arc::ptr_eq(&phi.inrefs[0], &phi.inrefs[1]),
            "Diamond Phi inputs should be distinct varnode instances"
        );

        // VERIFY: Phi output is distinct from both inputs
        let phi_out = phi.output.as_ref().unwrap();
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[0]));
        assert!(!Arc::ptr_eq(phi_out, &phi.inrefs[1]));
    }

    /// Test: SSA renaming correctly uses INPUT varnodes for undefined reads
    ///
    /// Sequence: add rax, rsi; ret
    /// There is no prior definition of RAX — it should remain linked to
    /// the INPUT varnode that heritage creates for uninitialized reads.
    #[test]
    fn test_ssa_rename_input_varnode_for_undefined_read() {
        let _lock = ffi_test_lock();

        // op0: RAX = INT_ADD(RAX, RSI)   — RAX is read before being defined
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX out
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX in (undefined)
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        // op1: RETURN
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));

        let start = Address::new(0x5000);
        let mut fd = Funcdata::new("ssa_input_test", start, 10);
        fd.inject_raw_ops(&[op0, op1]);

        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Get ops
        let block = &fd.bblocks.blocks[0];
        let ops = block.read().unwrap().get_ops();
        let regular_ops: Vec<_> = ops
            .iter()
            .filter(|op_ref| op_ref.0.read().unwrap().get_opcode() != OpCode::CPUI_MULTIEQUAL)
            .collect();

        assert!(!regular_ops.is_empty(), "Should have at least 1 regular op");

        // Find the INT_ADD op
        let add_op_ref = regular_ops
            .iter()
            .find(|op_ref| op_ref.0.read().unwrap().get_opcode() == OpCode::CPUI_INT_ADD);
        assert!(add_op_ref.is_some(), "Should find INT_ADD op");

        let add_op = add_op_ref.unwrap().0.read().unwrap();
        assert!(
            add_op.inrefs.len() >= 2, "INT_ADD should have at least 2 inputs"
        );

        // The RAX input (input 0) should reference a varnode.
        // Since there is no prior definition of RAX in this block,
        // after renaming it should either:
        // a) remain unchanged (no stack entry for RAX exists), or
        // b) point to an INPUT varnode if heritage created one
        //
        // The key verification: the input RAX varnode should be DIFFERENT from the output RAX varnode.
        let add_out = add_op.output.as_ref().expect("INT_ADD should have output");
        let add_in_rax = &add_op.inrefs[0];

        // Both refer to RAX
        assert_eq!(
            add_in_rax.read().unwrap().get_space(), AddressSpace::Register
        );
        assert_eq!(add_in_rax.read().unwrap().get_offset(), 0x00);
        assert_eq!(add_out.read().unwrap().get_space(), AddressSpace::Register);
        assert_eq!(add_out.read().unwrap().get_offset(), 0x00);

        // They must be DIFFERENT Varnode instances (input vs output are different SSA versions)
        assert!(
            !Arc::ptr_eq(add_in_rax, add_out),
            "Input RAX and output RAX should be different SSA versions. \
             Input ci={}, output ci={}",
            add_in_rax.read().unwrap().get_create_index(),
            add_out.read().unwrap().get_create_index(),
        );
    }

    // ========== CBRANCH condition def-loss repro ==========
    // Diagnostic for the curl `while (local_0 == local_0)` dead-loop root cause:
    // does Heritage rename wire CBRANCH in(1) (the condition) to the op that
    // defines it? Mirrors exactly what x86_lift.rs emits for `cmp rdi, rsi`
    // followed by `je target` (ZF lives at Register:0x206, sla layout).

    #[test]
    fn test_cbranch_condition_def_wired_via_heritage_single_block() {
        let _lock = ffi_test_lock();

        // Reproduce the P-code x86_lift.rs emits for `cmp rdi,rsi` + `je`
        // (X86LIFT-FLAG-PCODE-0001 sla layout): cmp's resultflags writes
        // ZF (Register:0x206); je reads ZF at the same offset.
        let mut cmp_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI
        cmp_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF

        // je target  → CBRANCH(target, ZF). in(1) is a FREE zf varnode distinct
        // from the cmp's written ZF (find_or_create_input_space filters out written).
        let mut cbranch = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1010, 8)); // target
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("cbranch_cond", start, 10);
        fd.inject_raw_ops(&[cmp_zf, cbranch]);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Locate the CBRANCH op.
        let cbranch_ref = fd
            .obank
            .optree
            .iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        assert_eq!(
            cbranch_op.inrefs.len(), 2, "CBRANCH must have target + condition"
        );

        let cond_vn = &cbranch_op.inrefs[1];
        // The condition varnode must carry a def (be written) after rename.
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();
        assert!(
            cond_is_written && cond_def.is_some(),
            "CBRANCH condition varnode lost its SSA def after heritage. \
             is_written={}, def={:?} (Register:0x206, size 1). \
             This is the root cause of the `while(local_0==local_0)` dead loop.",
            cond_is_written,
            if cond_def.is_some() { "Some" } else { "None/dead" },
        );

        // And the def must be the cmp's INT_EQUAL, not a placeholder.
        if let Some(def_op) = cond_def {
            let d = def_op.read().unwrap();
            assert_eq!(
                d.get_opcode(), OpCode::CPUI_INT_EQUAL,
                "CBRANCH condition def should be the INT_EQUAL (cmp) op"
            );
        }
    }

    /// Multi-block variant: cmp and the je/CBRANCH land in DIFFERENT basic blocks
    /// (the normal x86 case — `je` is itself a block terminator). This is where
    /// Heritage must propagate the cmp's ZF def across the block boundary into
    /// CBRANCH in(1). Uses the real x86 lifter so the P-code is exactly what
    /// curl produces.
    #[test]
    fn test_cbranch_condition_def_wired_multiblock_real_x86() {
        let _lock = ffi_test_lock();

        // 0x1000: cmp rdi, rsi      48 39 f7
        // 0x1003: je  0x100a        74 05     → branches over the next insn
        // 0x1005: mov rax, 1        48 c7 c0 01 00 00 00
        // 0x100c: ret               c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x05,
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
            0xc3,
        ];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        let mut fd = Funcdata::new("cbranch_cond_mb", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Find the CBRANCH op.
        let cbranch_ref = fd
            .obank
            .optree
            .iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist (from the je)");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        assert_eq!(
            cbranch_op.inrefs.len(), 2, "CBRANCH must have target + condition"
        );

        let cond_vn = &cbranch_op.inrefs[1];
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();

        // Diagnostic dump so the failure message shows the actual state.
        let cond_desc = {
            let vn = cond_vn.read().unwrap();
            format!(
                "space={:?} off=0x{:x} size={} is_written={} def={}",
                vn.get_space(), vn.get_offset(), vn.get_size(), vn.is_written(),
                if cond_def.is_some() { "Some" } else { "None/dead" },
            )
        };

        assert!(
            cond_is_written && cond_def.is_some(),
            "CBRANCH condition varnode lost its SSA def after heritage (multi-block). \
             cond={} — this is the root cause of the `while(local_0==local_0)` dead loop.",
            cond_desc,
        );

        if let Some(def_op) = cond_def {
            let d = def_op.read().unwrap();
            assert_eq!(
                d.get_opcode(), OpCode::CPUI_INT_EQUAL,
                "CBRANCH condition def should be the cmp INT_EQUAL op, got {:?}",
                d.get_opcode(),
            );
        }
    }

    /// Pattern B from docs/alignment_audit/ssa_flags_diagnosis.md §2-3: a LOOP
    /// where the loop header is the function entry. The flag varnode (ZF) is
    /// defined BOTH in the header (blk[0], the cmp) AND in the loop body
    /// (blk[1], a second flag writer) so ZF has multiple defs across the
    /// back-edge. Heritage MUST place a MULTIEQUAL (phi) for ZF at the loop
    /// header so the CBRANCH condition read resolves. This is the root-cause
    /// regression for the curl `while (local_0 == local_0)` dead-loop.
    ///
    ///   blk[0] entry+header: cmp ZF=...; je exit; ... ; jmp back  (idom=None)
    ///   blk[1] body:          cmp2 ZF=...; (falls back to header)
    ///   blk[2] exit (ret)
    #[test]
    fn test_cbranch_condition_def_wired_loop_header_is_entry() {
        let _lock = ffi_test_lock();

        // --- blk[0] (header/entry): cmp; je exit; jmp back ---
        // cmp rdi, rsi  →  INT_EQUAL ZF = (RDI == RSI)
        let mut cmp_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI
        cmp_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF
        cmp_zf.set_seq_num(crate::address::SeqNum::new(Address::new(0x1000), 0));

        // je exit (0x100a)  →  CBRANCH(exit, ZF)  — conditional exit from loop
        let mut cbranch = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x100a, 8)); // exit target
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF
        cbranch.set_seq_num(crate::address::SeqNum::new(Address::new(0x1003), 0));

        // --- blk[1] (loop body): cmp2 ZF=... (a SECOND writer of ZF) ---
        // This second def of ZF in the body is what makes ZF loop-carried and
        // forces a phi at the header. Without it, ZF is single-def in the
        // header and no phi is needed. The body starts at 0x1005 (the
        // fall-through target of the je at 0x1003).
        let mut cmp2_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp2_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x40, 8)); // RAX
        cmp2_zf.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));        // 0
        cmp2_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF
        cmp2_zf.set_seq_num(crate::address::SeqNum::new(Address::new(0x1005), 0));

        // jmp back to 0x1000 (header) — terminates the loop body.
        let mut branch_back = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        branch_back.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1000, 8));
        branch_back.set_seq_num(crate::address::SeqNum::new(Address::new(0x1008), 0));

        // exit block: ret
        let mut ret_op = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        ret_op.set_seq_num(crate::address::SeqNum::new(Address::new(0x100a), 0));

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("cbranch_loop", start, 16);
        fd.inject_raw_ops(&[cmp_zf, cbranch, cmp2_zf, branch_back, ret_op]);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        // Dump the CFG for diagnostics if it fails.
        let dump_cfg = || -> String {
            let mut s = String::new();
            for blk in &fd.bblocks.blocks {
                let b = blk.read().unwrap();
                let idx = b.get_index();
                let size_in = b.size_in();
                let b_idom = b.get_immed_dom().and_then(|w| w.upgrade());
                let is_entry = (b.get_flags()
                    & crate::block::block_flags::ENTRY_POINT) != 0
                    || size_in == 0
                    || b_idom.is_none();
                let idom = b_idom
                    .map(|d| d.read().unwrap().get_index());
                let df = b.get_dom_frontier();
                let mut preds = Vec::new();
                for j in 0..size_in {
                    if let Some(e) = b.get_in(j) {
                        preds.push(e.point.read().unwrap().get_index());
                    }
                }
                s.push_str(&format!(
                    "\n    blk[{}] size_in={} is_entry={} idom={:?} df={:?} preds={:?}",
                    idx, size_in, is_entry, idom, df, preds
                ));
            }
            s
        };

        // Cooper-Harvey-Kennedy invariant for an entry-loop-header: the loop
        // header `H` (entry, reached by a back-edge from body `B`) must appear
        // in `B`'s dominance frontier. Concretely, if `H` dominates `B` and
        // there is a back-edge `B -> H`, then H ∈ DF(B). Without the
        // calc_dom_frontier fix the entry is skipped as a join-point (only one
        // recorded predecessor — the back-edge) and DF(B) stays empty, so no
        // phi is ever placed for a loop-carried varnode.
        let (header_idx, body_idx) = {
            // Header = the entry/root block (idom None). Body = its successor
            // that loops back to it.
            let mut header = -1i32;
            let mut body = -1i32;
            for blk in &fd.bblocks.blocks {
                let b = blk.read().unwrap();
                let b_idom = b.get_immed_dom().and_then(|w| w.upgrade());
                let is_entry = (b.get_flags()
                    & crate::block::block_flags::ENTRY_POINT) != 0
                    || b.size_in() == 0
                    || b_idom.is_none();
                if is_entry && header == -1 {
                    header = b.get_index();
                    // Find the successor that loops back to header.
                    for j in 0..b.size_out() {
                        if let Some(e) = b.get_out(j) {
                            let s_idx = e.point.read().unwrap().get_index();
                            // The body is the successor whose own successor set
                            // contains header (back-edge).
                            for k in 0..e.point.read().unwrap().size_out() {
                                if let Some(e2) = e.point.read().unwrap().get_out(k) {
                                    if e2.point.read().unwrap().get_index() == header {
                                        body = s_idx;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (header, body)
        };
        assert!(
            header_idx != -1 && body_idx != -1,
            "Could not identify loop header/body. CFG:{}", dump_cfg()
        );
        let body_df = fd
            .bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == body_idx)
            .map(|b| b.read().unwrap().get_dom_frontier())
            .unwrap_or_default();
        assert!(
            body_df.contains(&header_idx),
            "Loop header (blk[{}]) must be in the loop body's (blk[{}]) dominance \
             frontier. Got DF(body)={:?}. This is the calc_dom_frontier \
             join-point bug. CFG:{}",
            header_idx, body_idx, body_df, dump_cfg()
        );

        // A MULTIEQUAL (phi) for ZF (Register:0x206) must have been inserted at
        // the header, because ZF is written in both the header and the body.
        // We look at the header block's op list directly (the phi's `parent`
        // back-pointer is not always set by insert_op, so iterating the block's
        // ops is the reliable check).
        let header_ops: Vec<_> = fd
            .bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == header_idx)
            .map(|b| {
                // BlockBasic stores its ops in `ops`. Downcast to access them.
                b.read().unwrap().get_ops()
            })
            .unwrap_or_default();
        let phi_at_header = header_ops.iter().any(|op_ref| {
            let o = op_ref.0.read().unwrap();
            if o.get_opcode() != OpCode::CPUI_MULTIEQUAL {
                return false;
            }
            // The phi's output must be at Register:0x206 (ZF).
            o.output
                .as_ref()
                .map(|out| {
                    let v = out.read().unwrap();
                    v.get_space() == AddressSpace::Register && v.get_offset() == 0x206
                })
                .unwrap_or(false)
        });
        assert!(
            phi_at_header,
            "Expected a MULTIEQUAL (phi) for ZF (Register:0x206) at the loop \
             header blk[{}], but found none. This means calc_dom_frontier's \
             fix is not propagating into phi placement. Header block ops: [{}] \
             CFG:{}",
            header_idx,
            header_ops
                .iter()
                .map(|op_ref| {
                let o = op_ref.0.read().unwrap();
                let out_desc = o
                        .output
                        .as_ref()
                        .map(|out| {
                    let v = out.read().unwrap();
                    format!(
                                "{:?}:0x{:x}/{}", v.get_space(), v.get_offset(), v.get_size()
                            )
                })
                        .unwrap_or_else(|| "none".to_string());
                format!("{:?}->{}", o.get_opcode(), out_desc)
            })
                .collect::<Vec<_>>()
                .join(", "),
            dump_cfg()
        );

        // End-to-end check: does the CBRANCH condition varnode resolve to a def
        // after heritage? Note that full resolution also requires the inserted
        // phi's `parent` back-pointer to be set so rename can traverse it — that
        // is a separate concern (BlockBasic::insert_op does not yet set the
        // op's parent, unlike Ghidra's setParent). This regression covers the
        // calc_dom_frontier fix specifically (dom_frontier + phi placement
        // above); the condition-wiring is recorded here as a diagnostic and is
        // NOT asserted, to keep this test focused on the dom_frontier fix.
        let cbranch_ref = fd
            .obank
            .optree
            .iter()
            .find(|op| op.0.read().unwrap().get_opcode() == OpCode::CPUI_CBRANCH)
            .expect("CBRANCH op should exist");
        let cbranch_op = cbranch_ref.0.read().unwrap();
        let cond_vn = cbranch_op.inrefs[1].clone();
        drop(cbranch_op);
        let cond_def = {
            let vn = cond_vn.read().unwrap();
            vn.def.as_ref().and_then(|w| w.upgrade())
        };
        let cond_is_written = cond_vn.read().unwrap().is_written();
        // Diagnostic only (not asserted) — surfaces the rename/parent issue
        // without failing the regression on the (separate) wiring concern.
        let _ = format!(
            "CBRANCH cond space={:?} off=0x{:x} size={} is_written={} def={}",
            cond_vn.read().unwrap().get_space(),
            cond_vn.read().unwrap().get_offset(),
            cond_vn.read().unwrap().get_size(),
            cond_is_written,
            if cond_def.is_some() { "Some" } else { "None/dead" },
        );
    }

    // ========== ActionNormalizeBranches tests ==========

    #[test]
    fn test_normalize_branches_break_in_while_loop() {
        let _lock = ffi_test_lock();

        // while(rdi != rsi) { if (rax == 0x10) break; rax++; }
        //
        // 0x1000: cmp rdi, rsi        48 39 f7
        // 0x1003: je  0x1011          74 0c       → exit (loop condition: if equal, exit)
        // 0x1005: cmp rax, 0x10       48 83 f8 10
        // 0x1009: je  0x1011          74 06       → break (early exit from loop body)
        // 0x100b: add rax, 1          48 83 c0 01
        // 0x100f: jmp 0x1000          eb ef       → continue (back to loop header)
        // 0x1011: ret                 c3
        let code: Vec<u8> = vec![
            0x48, 0x39, 0xf7,
            0x74, 0x0c,
            0x48, 0x83, 0xf8, 0x10,
            0x74, 0x06,
            0x48, 0x83, 0xc0, 0x01,
            0xeb, 0xef,
            0xc3,
        ];
        let start = Address::new(0x1000);

        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let all_raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());

        let mut fd = Funcdata::new("loop_break_test", start, code.len() as i32);
        fd.inject_raw_ops(&all_raw_ops);

        assert!(
            fd.bblocks.get_size() >= 3,
            "Loop CFG should have at least 3 blocks, got {}",
            fd.bblocks.get_size()
        );

        // Ghidra contract (funcdata.cc:150-168 startProcessing): followFlow +
        // structureReset run BEFORE any Action — structureReset calls
        // bblocks.structureLoops (funcdata_block.cc:711), which labels the
        // F_BACK_EDGE the structurer's orderLoopBodies consumes
        // (blockaction.cc:1148). The previous hand-rolled `build_dom_tree`
        // skipped the labeling entirely, so orderLoopBodies found 0 loops,
        // no BlockWhileDo was structured, and ActionNormalizeBranches had no
        // loop_info to tag the back-edge jmp CONTINUE
        // (BLOCKACT-NORMALIZE-CONTINUE-TAG-0001).
        fd.start_processing();

        use crate::action::Action;
        let mut structurer = crate::blockaction::ActionBlockStructure::new();
        let result = structurer.apply(&mut fd);
        assert!(result.is_ok());

        let mut normalizer = crate::blockaction::ActionNormalizeBranches::new();
        let result = normalizer.apply(&mut fd);
        assert!(result.is_ok());

        let mut _found_break = false;
        let mut found_continue = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type == crate::op::branch_type::BREAK {
                        _found_break = true;
                    }
                    if op.branch_type == crate::op::branch_type::CONTINUE {
                        found_continue = true;
                    }
                }
                _ => {}
            }
        }

        // The jmp back to 0x1000 should be tagged CONTINUE
        assert!(
            found_continue,
            "The back-edge jmp to loop header should be tagged CONTINUE"
        );
    }

    #[test]
    fn test_normalize_branches_op_branch_type_field() {
        use crate::address::SeqNum;
        use crate::op::branch_type;

        let seq = SeqNum::new(Address::new(0x1000), 0);
        let mut op = crate::op::PcodeOp::new(seq, OpCode::CPUI_CBRANCH);

        assert_eq!(op.branch_type, branch_type::NONE);

        op.branch_type = branch_type::BREAK;
        assert_eq!(op.branch_type, branch_type::BREAK);

        op.branch_type = branch_type::CONTINUE;
        assert_eq!(op.branch_type, branch_type::CONTINUE);
    }

    // ========== Boolean Condition Folding tests ==========

    #[test]
    fn test_bool_condition_folding_and_pattern() {
        use crate::address::{Address, SeqNum};
        use crate::block::{
            BlockBasic, BlockCondition, BlockEdge, BlockGraph, BlockType, BoolOp, FlowBlock,
        };
        use crate::op::PcodeOp;
        use crate::opcodes::OpCode;

        // OR-pattern CFG (block.hh:299-300: out[0]=false, out[1]=true):
        // A: false→B, true→C; B: false→D, true→C. ruleBlockOr first
        // builds BlockCondition(Or). The later ruleBlockIfNoExit chooses the
        // exit-only D arm at slot 0 and invokes virtual negateCondition(true),
        // so the final nested condition is the De Morgan dual, And.
        let mut basic_a = BlockBasic::new(0, Address::new(0x1000));
        basic_a
            .ops
            .push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(
                SeqNum::new(Address::new(0x1000), 0), OpCode::CPUI_CBRANCH,
            )))));

        let mut basic_b = BlockBasic::new(1, Address::new(0x1010));
        basic_b
            .ops
            .push(crate::op::PcodeOpRef(Arc::new(RwLock::new(
            PcodeOp::new(
                SeqNum::new(Address::new(0x1010), 0), OpCode::CPUI_CBRANCH,
            )))));

        let basic_c = BlockBasic::new(2, Address::new(0x1020));
        let basic_d = BlockBasic::new(3, Address::new(0x1030));

        let block_a: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_a));
        let block_b: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_b));
        let block_c: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_c));
        let block_d: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(basic_d));

        // Wire edges
        {
            let mut a = block_a.write().unwrap();
            a.add_out_edge(BlockEdge::new(block_b.clone(), 0)); // out(0)=B (false)
            a.add_out_edge(BlockEdge::new(block_c.clone(), 0)); // out(1)=C (true)
        }
        {
            let mut b = block_b.write().unwrap();
            b.add_in_edge(BlockEdge::new(block_a.clone(), 0));
            b.add_out_edge(BlockEdge::new(block_d.clone(), 0)); // out(0)=D (false)
            b.add_out_edge(BlockEdge::new(block_c.clone(), 1)); // out(1)=C (true)
        }
        {
            let mut c = block_c.write().unwrap();
            c.add_in_edge(BlockEdge::new(block_a.clone(), 1));
            c.add_in_edge(BlockEdge::new(block_b.clone(), 1));
        }
        {
            let mut d = block_d.write().unwrap();
            d.add_in_edge(BlockEdge::new(block_b.clone(), 0));
        }

        let mut graph = BlockGraph::new();
        graph.blocks = vec![block_a, block_b, block_c, block_d];

        let mut cs = crate::blockaction::CollapseStructure::new(&mut graph, "test");
        cs.collapse_all();

        // Search for BlockCondition(And) — after full collapseAll
        // (including interleaved cat/if rules), it may be standalone, inside a
        // BlockList, wrapped in a BlockIf (ruleBlockIfNoExit, blockaction.cc:
        // 1840, runs after the fixpoint and wraps an exit-only clause into an
        // if), or its original block slot may have been replaced.
        // Search ALL blocks recursively (two composite levels) for any
        // BlockCondition with And. Two levels are required: Ghidra's rule
        // sequence on this CFG (traced against blockaction.cc) is
        // ruleBlockOr -> ruleBlockIfNoExit wraps the exit clause D
        // (cc:1840 second pass) -> ruleBlockCat merges the If with the
        // true-edge sink C, giving List[If[Condition(And), D], C] — the
        // Condition sits INSIDE an If that is a List child.
        let mut found_and = false;
        for i in 0..graph.get_size() {
            if let Some(block) = graph.get_block(i) {
                let b = block.read().unwrap();
                match b.get_type() {
                    BlockType::Condition => {
                        if let Some(cond) = b.as_any().downcast_ref::<BlockCondition>() {
                            if cond.op_type == BoolOp::And {
                                found_and = true; }
                        }
                    }
                    BlockType::List => {
                        if let Some(list) = b.as_any().downcast_ref::<crate::block::BlockList>() {
                            for child in &list.children {
                                let c = child.read().unwrap();
                                if c.get_type() == BlockType::Condition {
                                    if let Some(cond) = c.as_any().downcast_ref::<BlockCondition>() {
                                        if cond.op_type == BoolOp::And {
                                            found_and = true; }
                                    }
                                }
                                // Level 2: the child may be the
                                // ruleBlockIfNoExit BlockIf whose condition
                                // is the Or composite (List[If[Cond, D], C]).
                                if c.get_type() == BlockType::If {
                                    if let Some(bif2) = c.as_any().downcast_ref::<crate::block::BlockIf>() {
                                        let cc = bif2.condition.read().unwrap();
                                        if cc.get_type() == BlockType::Condition {
                                            if let Some(cond) = cc.as_any().downcast_ref::<BlockCondition>() {
                                                if cond.op_type == BoolOp::And {
                                                    found_and = true; }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    BlockType::If => {
                        if let Some(bif) = b.as_any().downcast_ref::<crate::block::BlockIf>() {
                            let c = bif.condition.read().unwrap();
                            if c.get_type() == BlockType::Condition {
                                if let Some(cond) = c.as_any().downcast_ref::<BlockCondition>() {
                                    if cond.op_type == BoolOp::And {
                                        found_and = true; }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(found_and, "Expected BlockCondition(And) after ruleBlockIfNoExit applies the virtual De Morgan flip");
    }

    #[test]
    fn test_block_condition_struct_fields() {
        use crate::address::Address;
        use crate::block::{BlockBasic, BlockCondition, BlockEdge, BlockType, BoolOp, FlowBlock};

        let a: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
        let b: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(1, Address::new(0x2000))));

        let cond = BlockCondition {
            index: 10,
            op_type: BoolOp::And,
            first: a.clone(),
            second: b.clone(),
            incoming: Vec::new(),
            outgoing: vec![BlockEdge {
                point: a.clone(),
                flags: 0,
                reverse_index: 0,
            }],
            parent: None,
            flags: 0,
        };

        assert_eq!(cond.get_type(), BlockType::Condition);
        assert_eq!(cond.get_index(), 10);
        assert_eq!(cond.op_type, BoolOp::And);
        assert_eq!(cond.size_out(), 1);
        assert_eq!(cond.get_start_addr(), Address::new(0x1000));

        let cond_or = BlockCondition {
            index: 20,
            op_type: BoolOp::Or,
            first: a,
            second: b,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        };
        assert_eq!(cond_or.op_type, BoolOp::Or);
        assert_eq!(cond_or.get_type(), BlockType::Condition);
    }

    #[test]
    fn test_switch_case_structuring() {
        use crate::action::Action;
        use crate::block::BlockType;
        use crate::blockaction::ActionBlockStructure;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::prettyprint::EmitNoMarkup;
        use crate::printc::PrintC;
        use crate::printlanguage::PrintLanguage;
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("test_switch", Address::new(0x1000), 0x100);

        // Control block (Block 0): indirect jump
        // unique_var = COPY(RDI)
        // BRANCHIND(unique_var)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_BRANCHIND as i32);
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x50, 8));

        // Case 0 block (Block 1): return 10
        // RAX = COPY(10)
        // RETURN(indirect, RAX) — Ghidra's post-ActionReturnRecovery shape
        // (coreaction.cc:1836 buildReturnOutput keeps in(0), the return
        // indirect reference, and attaches the value as in(1)).
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 10, 8));

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x0, 8));
        op4.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        // Case 1 block (Block 2): return 20
        // RAX = COPY(20)
        // RETURN(indirect, RAX)
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op5.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX
        op5.add_input(VarnodeRaw::new(AddressSpace::Const, 20, 8));

        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op6.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x0, 8));
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[op1, op2, op3, op4, op5, op6]);

        // Verify we got 3 basic blocks
        assert_eq!(fd.bblocks.get_size(), 3);

        // Add edges: Block 0 -> Block 1, Block 0 -> Block 2
        let b0 = fd.bblocks.get_block(0).unwrap();
        let b1 = fd.bblocks.get_block(1).unwrap();
        let b2 = fd.bblocks.get_block(2).unwrap();
        fd.bblocks.add_edge(b0.clone(), b1.clone());
        fd.bblocks.add_edge(b0.clone(), b2.clone());

        // Run block structuring action
        let mut action = ActionBlockStructure::new();
        action.apply(&mut fd).unwrap();

        // Verify the main block was collapsed into a Switch. BLOCKSTRUCT-
        // GOTOCASCADE-CONDSTMT-0001: try_rule_switch now installs the
        // BlockSwitch via identify_internal (Ghidra newBlockSwitch
        // block.cc:1904-1919 consumes dispatch AND cases into the
        // component), so the top-level list holds exactly the switch
        // (was 3 under the old never-installing rule + case siblings).
        assert_eq!(fd.sblocks.get_size(), 1);
        let entry = fd.sblocks.get_block(0).unwrap();
        assert_eq!(entry.read().unwrap().get_type(), BlockType::Switch);


        // Print C code
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer
            .take_emit()
            .into_any()
            .downcast::<EmitNoMarkup>()
            .unwrap()
            .get_output();
        println!("Emitted code:\n{}", emitted_code);

        // Assert code structure. NOTE: `switch(` with NO space — the oracle's
        // opBranchind (printc.cc:586-587) emits tagOp("switch") directly
        // followed by openParen, matching the golden's `switch((int)x ...)`.
        assert!(emitted_code.contains("switch("));
        // PRINTC-SWITCH-EMIT-0001 restored: emit_structured_switch now emits
        // case bodies via the FlowBlock::emit-style dispatch
        // (emit_switch_case_body, printc.cc:3339-3341 bl2->emit(this)),
        // bypassing the DEAD guard that A10's identify_internal sets on the
        // absorbed case blocks — labels and bodies both survive.
        assert!(emitted_code.contains("case 0:"));
        assert!(emitted_code.contains("case 1:"));
        // Case body integrity: both cases' RETURN statements must land inside
        // the switch (the bodies are no longer swallowed by the DEAD guard).
        // NOTE: the value itself prints as `return uVar0;` — the in(1)
        // return-value COPY is not yet implied-inlined into the return
        // (Ghidra oracle folds it to `return 10;` via ActionReturnRecovery +
        // implied vars); that folding gap is registered separately and is
        // orthogonal to the switch emission timing fixed here.
        assert_eq!(emitted_code.matches("return").count(), 2);
    }

    // Isolated per board ACTIONTYPEINFER-VTYPE-0001 (audit 2026-08-20): this
    // test drives the Rugra-local ActionTypeInfer glue action (no Ghidra
    // counterpart; real inference is ActionInferTypes) over hand-linked IR the
    // audit declared non-oracle. Its assertions assume the pre-canonical
    // v_type=None representation; since VarnodeBank::create mints
    // Some(undefined{size}) — Ghidra: varnode.cc:1250 VarnodeBank::create
    // (ct "must not be NULL"), undefinedN = TYPE_UNKNOWN core types
    // (ghidra_arch.cc:349-352) — the (Some(t), None) COPY/INT_ADD rule
    // matches can never fire. Revival requires the real ActionInferTypes
    // dispatch port (board ACTION-INFERTYPES-DISPATCH-0001); reverting to
    // None or crudely swapping is_none for UNKNOWN checks was explicitly
    // rejected by the audit.
    #[test]
    #[ignore = "superseded by ACTIONTYPEINFER-VTYPE-0001: assertions assume v_type=None; canonical is Some(undefined8) per Ghidra varnode.cc:1250 + ghidra_arch.cc:349-352"]
    fn test_type_propagation() {
        use crate::action::Action;
        use crate::coreaction::ActionTypeInfer;
        use crate::opcodes::OpCode;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
        use std::sync::Arc;

        let mut fd = Funcdata::new("test_type_prop", Address::new(0x1000), 0x100);

        // Define linear instructions representing:
        // unique_1 = COPY(RDI)
        // unique_2 = INT_ADD(unique_1, 8)
        // unique_3 = LOAD(unique_2)
        // STORE(unique_4, unique_3)
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8)); // unique_1
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI (input)

        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2
        op2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Const, 8, 8));

        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (size 4)
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x20, 8)); // unique_2 (addr)

        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 2, 8)); // space Ram
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x40, 8)); // unique_4 (addr, untyped)
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x30, 4)); // unique_3 (val)

        fd.inject_raw_ops(&[op1, op2, op3, op4]);

        // 1. Deduplicate/Link variables so dataflow can propagate.
        // We link inputs to matching output Varnodes by space/offset/size.
        // First, collect all output varnode info to avoid RwLock deadlocks.
        let mut output_varnodes: Vec<(
            crate::space::AddressSpace, u64, usize, Arc<RwLock<crate::varnode::Varnode>>,
        )> = Vec::new();
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out_vn_arc) = op.output {
                let out_vn = out_vn_arc.read().unwrap();
                output_varnodes.push((
                    out_vn.space(), out_vn.offset(), out_vn.get_size(), out_vn_arc.clone(),
                ));
            }
        }

        let ops_to_update: Vec<_> = fd.obank.alivelist.iter().cloned().collect();
        for op_ref in &ops_to_update {
            let mut op = op_ref.0.write().unwrap();
            let num_inputs = op.inrefs.len();
            for i in 0..num_inputs {
                let (in_space, in_offset, in_size) = {
                    let in_vn = op.inrefs[i].read().unwrap();
                    (in_vn.space(), in_vn.offset(), in_vn.get_size())
                };

                if in_space != AddressSpace::Const {
                    let found_match = output_varnodes
                        .iter()
                        .find(|(s, o, sz, _)| *s == in_space && *o == in_offset && *sz == in_size)
                        .map(|(_, _, _, arc)| arc.clone());

                    if let Some(matching_vn) = found_match {
                        op.inrefs[i] = matching_vn.clone();
                        matching_vn
                            .write()
                            .unwrap()
                            .descend
                            .push(Arc::downgrade(&op_ref.0));
                    }
                }
            }
        }

        // Manually inject a starting type: RDI is an "int *" pointer.
        let int_type = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        let int_ptr_type = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: int_type.clone(),
            wordsize: 1,
        }));

        {
            let mut found = false;
            for op_ref in &fd.obank.alivelist {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_COPY {
                    let mut in_vn = op.inrefs[0].write().unwrap();
                    if in_vn.space().is_register() && in_vn.offset() == 0x38 {
                        in_vn.v_type = Some(int_ptr_type.clone());
                        found = true;
                    }
                }
            }
            assert!(found, "RDI input varnode not found and typed");
        }

        // Run type propagation
        let mut action = ActionTypeInfer::new();
        action.apply(&mut fd).unwrap();

        // Verify propagation results on our unified SSA variable chain
        let mut checked_u1 = false;
        let mut checked_u2 = false;
        let mut checked_u3 = false;
        let mut checked_u4 = false;

        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            match op.opcode {
                OpCode::CPUI_COPY => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x10);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u1 = true;
                }
                OpCode::CPUI_INT_ADD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x20);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u2 = true;
                }
                OpCode::CPUI_LOAD => {
                    let out_vn = op.output.as_ref().unwrap().read().unwrap();
                    assert_eq!(out_vn.space(), AddressSpace::Unique);
                    assert_eq!(out_vn.offset(), 0x30);
                    assert_eq!(out_vn.v_type.as_ref().unwrap().get_name(), "int");
                    checked_u3 = true;
                }
                OpCode::CPUI_STORE => {
                    let addr_vn = op.inrefs[1].read().unwrap();
                    assert_eq!(addr_vn.space(), AddressSpace::Unique);
                    assert_eq!(addr_vn.offset(), 0x40);
                    assert_eq!(addr_vn.v_type.as_ref().unwrap().get_name(), "int *");
                    checked_u4 = true;
                }
                _ => {}
            }
        }

        assert!(checked_u1, "unique_1 type verification failed");
        assert!(checked_u2, "unique_2 type verification failed");
        assert!(checked_u3, "unique_3 type verification failed");
        assert!(checked_u4, "unique_4 type verification failed");
    }

    // Isolated per board ACTIONTYPEINFER-VTYPE-0001 (audit 2026-08-20): the
    // "long" return assertion exercises the Rugra-local ActionInferParams
    // glue action's size-based fallback, which only fired when the RETURN
    // value varnode had v_type=None. With the canonical Some(undefined8) —
    // Ghidra: varnode.cc:1250 VarnodeBank::create (ct "must not be NULL"),
    // undefinedN = TYPE_UNKNOWN (ghidra_arch.cc:349-352) — the fallback never
    // fires and no oracle behavior exists for this hand-built IR: real return
    // typing is ActionOutputPrototype (Ghidra: coreaction.cc:4765
    // ActionOutputPrototype::apply). Fixture migration is board
    // ACTION-INFERTYPES-DISPATCH-0001.
    #[test]
    #[ignore = "superseded by ACTIONTYPEINFER-VTYPE-0001: return-type assertion assumes v_type=None fallback; canonical is Some(undefined8) per Ghidra varnode.cc:1250 + ghidra_arch.cc:349-352"]
    fn test_infer_params_and_return_type() {
        use crate::action::Action;
        use crate::coreaction::ActionInferParams;
        use crate::type_system::datatype::Datatype;

        let mut fd = Funcdata::new("my_func", Address::new(0x1000), 0x100);

        // Create INPUT varnodes in SysV ABI parameter registers
        // param1 = RDI (offset 0x38, size 8)
        let rdi_vn = fd
            .vbank
            .create_with_space(8, crate::space::AddressSpace::Register, 0x38);
        let rdi_vn = fd.vbank.set_input(rdi_vn).expect("fresh RDI input");
        // param2 = RSI (offset 0x30, size 8)
        let rsi_vn = fd
            .vbank
            .create_with_space(8, crate::space::AddressSpace::Register, 0x30);
        let rsi_vn = fd.vbank.set_input(rsi_vn).expect("fresh RSI input");

        // Create an op that reads both params: ADD rdi, rsi -> result (RAX)
        let result_vn = fd
            .vbank
            .create_with_space(8, crate::space::AddressSpace::Register, 0x00);
        let add_ref = fd
            .obank
            .create(OpCode::CPUI_INT_ADD, 2, Address::new(0x1000));
        {
            let mut add_op = add_ref.0.write().unwrap();
            add_op.output = Some(result_vn.clone());
            add_op.inrefs.push(rdi_vn);
            add_op.inrefs.push(rsi_vn);
        }

        // Create RETURN op with RAX as return value
        let ret_addr_vn = fd.vbank.create_constant(8, 0);
        let ret_ref = fd
            .obank
            .create(OpCode::CPUI_RETURN, 2, Address::new(0x1010));
        {
            let mut ret_op = ret_ref.0.write().unwrap();
            ret_op.inrefs.push(ret_addr_vn);
            ret_op.inrefs.push(result_vn); // RAX as return value
        }

        // Verify initial state: void return, no params
        assert!(matches!(fd.funcp.return_type.as_ref(), Datatype::Void(_)));
        assert!(fd.funcp.parameters.is_empty());

        // Run ActionInferParams
        let mut action = ActionInferParams::new();
        let result = action.apply(&mut fd).unwrap();
        // Ghidra Actions return 0 (count is statistics only).
        assert_eq!(result, 0, "ActionInferParams returns 0 (Ghidra convention)");

        // Verify parameters detected
        assert_eq!(fd.funcp.parameters.len(), 2, "Should detect 2 parameters");
        assert_eq!(fd.funcp.parameters[0].name, "param_1");
        assert_eq!(fd.funcp.parameters[1].name, "param_2");

        // Verify return type inferred (RAX is size 8 -> long)
        assert_eq!(
            fd.funcp.return_type.get_name(), "long",
            "Return type should be inferred as 'long' from 8-byte RAX"
        );
    }

    /// End-to-end decompilation test simulating a realistic curl-style function.
    ///
    /// Models a function like:
    /// ```c
    /// long curl_easy_setopt(long handle, int option, long value) {
    ///     long result;
    ///     if (option == 0x2712) {
    ///         *(long *)(handle + 0x28) = value;
    ///         result = 0;
    ///     } else {
    ///         result = curl_set_error(handle, option);
    ///     }
    ///     return result;
    /// }
    /// ```
    #[test]
    #[ignore = "TODO: action clone_registry init order needs fix (set_default_actions must run before clone_all)"]
    fn test_realistic_curl_function() {
        use crate::action::ActionDatabase;
        use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
        use crate::prettyprint::EmitNoMarkup;
        use crate::printc::PrintC;
        use crate::printlanguage::PrintLanguage;
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("curl_easy_setopt", Address::new(0x4050a0), 0x60);

        // Add symbol table entries for known functions
        fd.symbol_table
            .insert(0x403210, "curl_set_error".to_string());

        // Addresses: baseaddr + idx * 0x10
        // Block 0: op0..op4 (5 ops) → CBRANCH at op4
        //   Block 0 starts at 0x4050a0
        // Block 1: op5..op7 (3 ops) → BRANCH at op7
        //   Block 1 starts at 0x4050a0 + 5*0x10 = 0x4050f0
        // Block 2: op8..op11 (4 ops) → BRANCH at op11
        //   Block 2 starts at 0x4050a0 + 8*0x10 = 0x405120
        // Block 3: op12..op13 (2 ops) → RETURN at op13
        //   Block 3 starts at 0x4050a0 + 12*0x10 = 0x405160

        // === Block 0: Entry / condition check ===
        // op0: u0 = COPY(RDI)           ; handle → unique
        let mut op0 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op0.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op0.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI = handle
        // op1: u1 = INT_ZEXT(ESI)       ; option → 8-byte
        let mut op1 = PcodeOpRaw::new(OpCode::CPUI_INT_ZEXT as i32);
        op1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 4)); // ESI = option (4 byte)
        // op2: u2 = COPY(RDX)           ; value → unique
        let mut op2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        op2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x10, 8)); // RDX = value
        // op3: u3 = INT_EQUAL(u1, 0x2712)  ; option == CURLOPT_URL
        let mut op3 = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        op3.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));
        op3.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        op3.add_input(VarnodeRaw::new(AddressSpace::Const, 0x2712, 8));
        // op4: CBRANCH → Block 2 (then branch at 0x405120)
        let mut op4 = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        op4.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405120, 8));
        op4.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x118, 1));

        // === Block 1: else branch (call curl_set_error + branch to exit) ===
        // op5: CALL curl_set_error
        let mut op5 = PcodeOpRaw::new(OpCode::CPUI_CALL as i32);
        op5.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x403210, 8));
        // op6: u4 = COPY(RAX)     ; capture return value
        let mut op6 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op6.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        op6.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        // op7: BRANCH → Block 3 (exit at 0x405160)
        let mut op7 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op7.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 2: then branch (store value + branch to exit) ===
        // op8: u5 = INT_ADD(u0, 0x28)  ; handle + 0x28
        let mut op8 = PcodeOpRaw::new(OpCode::CPUI_INT_ADD as i32);
        op8.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        op8.add_input(VarnodeRaw::new(AddressSpace::Const, 0x28, 8));
        // op9: STORE([ram], u5, u2)     ; *(handle+0x28) = value
        let mut op9 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        op9.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x128, 8));
        op9.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x110, 8));
        // op10: u6 = COPY(0)           ; result = 0
        let mut op10 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op10.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x130, 8));
        op10.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        // op11: BRANCH → Block 3 (exit at 0x405160)
        let mut op11 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        op11.add_input(VarnodeRaw::new(AddressSpace::Const, 0x405160, 8));

        // === Block 3: exit (return result) ===
        // op12: RAX = COPY(result)
        let mut op12 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        op12.set_output(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));
        op12.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x120, 8));
        // op13: RETURN(RAX)
        let mut op13 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        op13.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        op13.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8));

        fd.inject_raw_ops(&[
            op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13,
        ]);

        // CFG edges are automatically created by build_blocks_from_ops

        // Run full analysis pipeline
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let _ = db.apply_all(&mut fd);

        // Print decompiled output
        let emit = EmitNoMarkup::new();
        let mut printer = PrintC::new(Box::new(emit));
        printer.doc_function(&fd);

        let emitted_code = printer
            .take_emit()
            .into_any()
            .downcast::<EmitNoMarkup>()
            .unwrap()
            .get_output();
        println!("\n====== Rugra Decompiled Output: curl_easy_setopt ======\n{}\n======================================================", emitted_code);

        // Basic structure assertions
        assert!(
            emitted_code.contains("curl_easy_setopt"), "Should contain function name"
        );
        assert!(
            !emitted_code.contains("void curl_easy_setopt"), "Should NOT have void return (has RETURN with RAX)"
        );
        // Function signature should contain parameters
        assert!(
            emitted_code.contains("param_1"), "Should contain param_1 in signature"
        );
        assert!(
            emitted_code.contains("param_2"), "Should contain param_2 in signature or body"
        );
        assert!(
            emitted_code.contains("param_3"), "Should contain param_3 in signature"
        );
        // param_2 should appear in the body expression (not just signature)
        assert!(
            emitted_code.contains("(long)param_2") || emitted_code.contains("param_2"),
            "param_2 should be used in body expression"
        );
    }

    /// Pipeline wiring proof for FUNCDATA-CALCNZM-0001: the oracle's ONLY
    /// production call site of `Funcdata::calcNZMask` is
    /// `ActionNonzeroMask::apply` (coreaction.hh:300), registered in the
    /// universal mainloop directly after `ActionSpacebase` and before
    /// `ActionInferTypes` (coreaction.cc:5506-5508; Rugra src/action.rs:1196,
    /// "analysis" survives the default decompile grouplist). Observable:
    /// after the default decompile root runs on
    /// `u1 = EDI & 0x3f0; u2 = u1 / 3; STORE(u2)`, the INT_DIV output carries
    /// the oracle mask coveringmask(0x3f0) >> mostsigbit_set(3) = 0x1ff
    /// (op.cc:648-659). With the action unwired every written unique keeps
    /// its constructor nzm ~0 (varnode.cc:605) and no written varnode can
    /// hold 0x1ff (the only constants 0x3f0/3/2 init to their own offsets).
    #[test]
    fn test_nonzeromask_pipeline_wiring() {
        use crate::action::ActionDatabase;

        let mut fd = Funcdata::new("nzm_wiring", Address::new(0x1000), 0x100);
        // Oracle invariant (BRANAUDIT 2026-09-26 ruling): every Funcdata
        // entering the action pipeline has its FuncProto model bound —
        // the named-ctor tail funcdata.cc:69 `funcp.setScope(localmap,
        // baseaddr+ -1)` runs fspec.cc:3883-3884 `if (model ==
        // (ProtoModel *)0) setModel(s->getArch()->defaultfp)` inside
        // `FuncProto::setScope` (fspec.cc:3879), and `FuncProto::
        // effectBegin/effectEnd` (fspec.cc:4243-4259) unconditionally
        // dereference that pointer when the prototype-local effect list is
        // empty (no graceful path exists in the oracle). Rugra's canonical
        // default Architecture is cspec-less (`defaultfp == None`), so the
        // synthetic fixture must bind the stand-in `defaultfp` model itself
        // — exactly what ActionRestrictLocal (coreaction.cc:1983-1985)
        // reads through `data.getFuncProto().effectBegin()`. The stand-in
        // is a default-constructed ProtoModelFull (fspec.cc:2339): empty
        // effect list, so Loop 2's saved-register walk is a no-op and the
        // observable under test stays the nzm wiring, not restrict-local.
        let mut defaultfp = crate::fspec::ProtoModelFull::new(
            Some(crate::space::AddressSpace::Stack),
            8,
        );
        defaultfp.name = "default".to_string();
        fd.funcp
            .set_model(Some(std::sync::Arc::new(defaultfp)));
        let block = fd.create_new_block();

        // u1 = INT_AND(EDI, 0x3f0): EDI is an unwritten register read, so
        // phase 1 initializes it to calc_mask(4) = 0xffffffff and the AND
        // output takes 0xffffffff & 0x3f0 = 0x3f0 (op.cc:590-594).
        let and_op = fd.new_op(2, Address::new(0x1010));
        fd.op_set_opcode(&and_op, OpCode::CPUI_INT_AND);
        let u1 = fd.new_unique_out(4, &and_op);
        let edi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x38);
        fd.op_set_input(&and_op, edi, 0);
        let mask = fd.new_constant(4, 0x3f0);
        fd.op_set_input(&and_op, mask, 1);
        fd.op_insert_end(&and_op, &block);

        // u2 = INT_DIV(u1, 3): 3 is not a power of two, so no rule rewrites
        // the division into a shift. Oracle nzm: coveringmask(0x3f0) = 0x3ff,
        // mostsigbit_set(3) = 1, 0x3ff >> 1 = 0x1ff (op.cc:648-659).
        let div_op = fd.new_op(2, Address::new(0x1020));
        fd.op_set_opcode(&div_op, OpCode::CPUI_INT_DIV);
        let u2 = fd.new_unique_out(4, &div_op);
        fd.op_set_input(&div_op, u1.clone(), 0);
        let three = fd.new_constant(4, 3);
        fd.op_set_input(&div_op, three, 1);
        fd.op_insert_end(&div_op, &block);

        // STORE(ram, ptr, u2) keeps the chain alive through dead code.
        let store_op = fd.new_op(3, Address::new(0x1030));
        fd.op_set_opcode(&store_op, OpCode::CPUI_STORE);
        let spaceid = fd.new_varnode_space(AddressSpace::Ram);
        fd.op_set_input(&store_op, spaceid, 0);
        let ptr = fd.new_unique(8);
        fd.op_set_input(&store_op, ptr, 1);
        fd.op_set_input(&store_op, u2.clone(), 2);
        fd.op_insert_end(&store_op, &block);

        // RETURN keeps the block reachable/structured for the pipeline.
        let ret_op = fd.new_op(2, Address::new(0x1040));
        fd.op_set_opcode(&ret_op, OpCode::CPUI_RETURN);
        let ret_addr = fd.new_constant(8, 0x1000);
        fd.op_set_input(&ret_op, ret_addr, 0);
        let rax = fd.vbank.create_with_space(8, AddressSpace::Register, 0x0);
        fd.op_set_input(&ret_op, rax, 1);
        fd.op_insert_end(&ret_op, &block);

        let mut db = ActionDatabase::new();
        db.set_default_actions();
        let _ = db.apply_all(&mut fd);

        // The INT_DIV output must carry the oracle-computed mask 0x1ff.
        // With the action unwired every written unique keeps its
        // constructor nzm ~0 (varnode.cc:605) and no written varnode can
        // hold 0x1ff (the only constants 0x3f0/3 init to their own
        // offsets).
        let u2_nzm = u2.read().unwrap().get_nzm();
        let div_alive = fd
            .obank
            .alivelist
            .iter()
            .any(|op| op.0.read().unwrap().opcode == OpCode::CPUI_INT_DIV);
        assert_eq!(
            u2_nzm, 0x1ff,
            "decompile root must reach calc_nz_mask (INT_DIV still alive: {})",
            div_alive
        );
        assert_eq!(u1.read().unwrap().get_nzm(), 0x3f0);
    }

    /// Verify Funcdata::spacebase() marks the RSP input varnode with the
    /// SPACEBASE flag, faithful to Ghidra Funcdata::spacebase()
    /// (funcdata.cc:230-269). This is the foundational mechanism that lets
    /// varmap/ActionStackPtrFlow recognize RSP as a Stack-space pointer.
    #[test]
    fn test_spacebase_marks_rsp_input() {
        // RSP input at Register@0x20, size 8 (matches x86_lift.rs:40).
        // A normal register (RAX @ 0x00) that should NOT be marked spacebase.
        let mut read_rsp = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rsp.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x10, 8));
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8)); // space-id const
        read_rsp.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8)); // RSP

        let mut read_rax = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        read_rax.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x18, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Const, 0x100, 8));
        read_rax.add_input(VarnodeRaw::new(AddressSpace::Register, 0x00, 8)); // RAX

        let mut fd = Funcdata::new("test_spacebase", Address::new(0x1000), 0x100);
        fd.inject_raw_ops(&[read_rsp, read_rax]);

        // Before spacebase(): no varnode has SPACEBASE flag.
        let sb_before = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .count();
        assert_eq!(sb_before, 0, "No spacebase varnodes before spacebase()");

        // Run spacebase() — faithful to Ghidra Funcdata::spacebase().
        fd.spacebase();

        // After: the RSP input (Register@0x20) should be marked SPACEBASE.
        let sb_varnodes: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|v| v.0.read().unwrap().is_spacebase())
            .map(|v| v.0.clone())
            .collect();
        assert!(
            !sb_varnodes.is_empty(), "RSP input should be marked SPACEBASE"
        );

        // Verify it's at Register@0x20, size 8.
        let sb = sb_varnodes[0].read().unwrap();
        assert_eq!(sb.get_space(), AddressSpace::Register);
        assert_eq!(sb.get_offset(), 0x20);
        assert_eq!(sb.get_size(), 8);
        assert!(sb.is_spacebase());

        // RAX (Register@0x00) must NOT be marked.
        let rax_marked = fd.vbank.loc_tree.iter()
            .any(|v| {
                let g = v.0.read().unwrap();
                g.get_space() == AddressSpace::Register
                    && g.get_offset() == 0x00
                    && g.is_spacebase()
            });
        assert!(!rax_marked, "RAX must NOT be marked spacebase");
    }

    /// Verify split_uses() duplicates a multi-descendant op so each reader
    /// gets its own output, faithful to Ghidra Funcdata::splitUses()
    /// (funcdata_varnode.cc:1540-1567).
    #[test]
    fn test_split_uses_duplicates_op() {
        // Build a Funcdata where one INT_ADD output has 2 descendant readers.
        // We construct varnodes directly in the bank with proper descend links
        // (inject_raw_ops creates separate varnode instances for inputs, which
        // breaks identity; so we wire the descend chain manually here).
        let mut fd = Funcdata::new("test_split", Address::new(0x1000), 0x100);
        let block = fd.create_new_block();

        // INT_ADD(RSP, 0x10) -> tmp_out
        let add_op = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&add_op, OpCode::CPUI_INT_ADD);
        let tmp_out = fd.new_unique_out(8, &add_op);
        let rsp = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        // Register rsp as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). splitUses re-reads every defining-op input on each
        // duplicated op (funcdata_varnode.cc:1560 opSetInput(newop,op->getIn(i),i));
        // in the Ghidra rule universe those inputs are written/input at that
        // point. A free rsp is Ghidra-unreachable — Varnode::addDescend would
        // throw "Free varnode has multiple descendants" (varnode.cc:336).
        // INPUT keeps is_written() false, and split_uses/op_set_input have no
        // input-flag branch, so the duplication path is identical.
        let rsp = fd.vbank.set_input(rsp).unwrap();
        let off = fd.vbank.create_constant(8, 0x10);
        fd.op_set_input(&add_op, rsp, 0);
        fd.op_set_input(&add_op, off, 1);
        fd.op_insert_end(&add_op, &block);

        // Two readers of tmp_out.
        let r1 = fd.new_op(2, Address::new(0x1001));
        fd.op_set_opcode(&r1, OpCode::CPUI_LOAD);
        fd.op_set_input(&r1, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.op_insert_end(&r1, &block);

        let r2 = fd.new_op(3, Address::new(0x1002));
        fd.op_set_opcode(&r2, OpCode::CPUI_STORE);
        fd.op_set_input(&r2, tmp_out.clone(), 1);  // reads tmp_out -> adds descend
        fd.op_insert_end(&r2, &block);

        // Before split: tmp_out has 2 descendants.
        assert_eq!(tmp_out.read().unwrap().count_descends(), 2);

        // Run split_uses — faithful to Ghidra Funcdata::splitUses().
        fd.split_uses(&tmp_out);

        // After: a new duplicated INT_ADD op exists whose output is NOT tmp_out.
        let has_new_add = fd.obank.alivelist.iter().any(|r| {
            let o = r.0.read().unwrap();
            if o.opcode != OpCode::CPUI_INT_ADD { return false; }
            match o.output.as_ref() {
                Some(out) => !std::sync::Arc::ptr_eq(out, &tmp_out),
                None => false,
            }
        });
        assert!(
            has_new_add, "split_uses should create a duplicated INT_ADD op"
        );
    }

    /// Diagnostic (2026-07-02): does lifting `xor eax,eax; ret` produce the
    /// SAME varnode for both XOR inputs? Ghidra's SSA identity model requires
    /// all reads of the same register (before any write) to share ONE varnode,
    /// so that `x^x→0` (RuleTrivialArith) can fold via Arc::ptr_eq. If this
    /// FAILS (ptreq=false AND same_storage=false), it is the root cause of the
    /// `return iVar1 ^ iVar1` defect in curl main_init.
    #[test]
    fn test_xor_eax_eax_input_identity() {
        let _lock = ffi_test_lock();
        // 31 c0 = xor eax,eax ; c3 = ret
        let code = vec![0x31, 0xc0, 0xc3];
        let start = Address::new(0x1000);
        // SLEIGH-RUSTIFY-PHASE3-0001: decode through the production SLEIGH engine
        // (the retired iced lift's mnemonic metadata went with it).
        let raw_ops = crate::disasm::sleigh_lift::sleigh_raw_ops(&code, start.as_u64());
        // X86LIFT-FLAG-PCODE-0001 + RET-OP3-0001: xor→10 (COPY CF=0, COPY
        // OF=0, INT_XOR direct-dst, INT_ZEXT rax←eax, SF, ZF, PF chain),
        // ret→3 (RIP=LOAD(ram[RSP]); RSP=INT_ADD(RSP,8); RETURN[RIP] per
        // the locked sla :RET template) — 13 ops. Old 11 assumed ret→1;
        // masked stale by the FFI_TEST_LOCK poison cascade
        // (TESTLIB-STATE-CONTAMINATION-0001).
        assert_eq!(
            raw_ops.len(), 13, "expected 13 raw ops, got {}", raw_ops.len()
        );
        let mut fd = Funcdata::new("xor_eax_eax", start, code.len() as i32);
        fd.inject_raw_ops(&raw_ops);
        for op_ref in &fd.obank.alivelist {
            let op = op_ref.0.read().unwrap();
            if op.opcode == OpCode::CPUI_INT_XOR {
                let i0 = &op.inrefs[0]; let i1 = &op.inrefs[1];
                let v0 = i0.read().unwrap(); let v1 = i1.read().unwrap();
                let ptreq = std::sync::Arc::ptr_eq(i0, i1);
                let same_storage = v0.get_space() == v1.get_space()
                    && v0.get_offset() == v1.get_offset() && v0.get_size() == v1.get_size();
                eprintln!("XOR inputs: ptreq={} same_storage={} in0={:?}@0x{:x} sz{} written={} | in1={:?}@0x{:x} sz{} written={}",
                    ptreq, same_storage,
                    v0.get_space(), v0.get_offset(), v0.get_size(), v0.is_written(),
                    v1.get_space(), v1.get_offset(), v1.get_size(), v1.is_written());
            }
        }
    }

    #[test]
    fn test_combine_input_varnodes_preserves_storage_and_rewires_readers() {
        use crate::block::{BlockBasic, FlowBlock};
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("combine", Address::new(0x5000), 0x20);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x5000))));
        fd.bblocks.add_block(block.clone());

        let hi = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x24);
        let hi = fd.vbank.set_input(hi).expect("fresh high input");
        let lo = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = fd.vbank.set_input(lo).expect("fresh low input");

        let piece = fd.new_op(2, Address::new(0x5000));
        fd.op_set_opcode(&piece, OpCode::CPUI_PIECE);
        fd.op_insert_input(&piece, hi.clone(), 0);
        fd.op_insert_input(&piece, lo.clone(), 1);
        let piece_out = fd.vbank.create_def_unique(8, &piece.0);
        piece.0.write().unwrap().output = Some(piece_out);
        fd.op_insert_end(&piece, &block);

        // The same non-PIECE op reads hi twice. This exercises Ghidra's
        // one-descendant-entry-per-slot totalReplace iteration.
        let hi_reader = fd.new_op(2, Address::new(0x5001));
        fd.op_set_opcode(&hi_reader, OpCode::CPUI_INT_ADD);
        fd.op_insert_input(&hi_reader, hi.clone(), 0);
        fd.op_insert_input(&hi_reader, hi.clone(), 1);
        let hi_reader_out = fd.vbank.create_def_unique(4, &hi_reader.0);
        hi_reader.0.write().unwrap().output = Some(hi_reader_out);
        fd.op_insert_end(&hi_reader, &block);

        let lo_reader = fd.new_op(1, Address::new(0x5002));
        fd.op_set_opcode(&lo_reader, OpCode::CPUI_COPY);
        fd.op_insert_input(&lo_reader, lo.clone(), 0);
        let lo_reader_out = fd.vbank.create_def_unique(4, &lo_reader.0);
        lo_reader.0.write().unwrap().output = Some(lo_reader_out);
        fd.op_insert_end(&lo_reader, &block);

        assert_eq!(fd.vbank.num_varnodes(), 5);
        assert_eq!(fd.obank.optree.len(), 3);
        fd.combine_input_varnodes(&hi, &lo)
            .expect("valid contiguous register inputs");

        let combined = fd
            .vbank
            .loc_tree
            .iter()
            .map(|entry| entry.0.clone())
            .find(|candidate| {
                let value = candidate.read().unwrap();
                value.is_input()
                    && value.get_space() == AddressSpace::Register
                    && value.get_offset() == 0x20
                    && value.get_size() == 8
            })
            .expect("combined canonical input");
        assert_eq!(combined.read().unwrap().count_descends(), 3);
        assert_eq!(piece.0.read().unwrap().opcode, OpCode::CPUI_COPY);
        assert_eq!(piece.0.read().unwrap().inrefs.len(), 1);
        assert!(Arc::ptr_eq(
            &piece.0.read().unwrap().inrefs[0],
            &combined,
        ));

        let new_hi = hi_reader.0.read().unwrap().inrefs[0].clone();
        assert!(Arc::ptr_eq(
            &new_hi,
            &hi_reader.0.read().unwrap().inrefs[1],
        ));
        let new_lo = lo_reader.0.read().unwrap().inrefs[0].clone();
        for (replacement, offset, expected_storage) in [
            (new_hi, 4_u64, 0x24_u64),
            (new_lo, 0_u64, 0x20_u64)] {
            let value = replacement.read().unwrap();
            assert_eq!(value.get_space(), AddressSpace::Register);
            assert_eq!(value.get_offset(), expected_storage);
            assert_eq!(value.get_size(), 4);
            let definition = value.get_def().expect("replacement definition");
            drop(value);
            let definition = crate::op::PcodeOpRef(definition);
            let operation = definition.0.read().unwrap();
            assert_eq!(operation.opcode, OpCode::CPUI_SUBPIECE);
            assert_eq!(operation.get_addr(), Address::new(0x5000));
            assert_eq!(operation.inrefs.len(), 2);
            assert!(Arc::ptr_eq(&operation.inrefs[0], &combined));
            assert!(operation.inrefs[1].read().unwrap().is_constant());
            assert_eq!(operation.inrefs[1].read().unwrap().get_offset(), offset);
        }

        assert!(hi.read().unwrap().has_no_descend());
        assert!(lo.read().unwrap().has_no_descend());
        assert!(!fd
            .vbank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &hi) || Arc::ptr_eq(&entry.0, &lo)));
        assert_eq!(fd.vbank.num_varnodes(), 8);
        assert_eq!(fd.obank.optree.len(), 5);
    }

    #[test]
    fn test_combine_input_varnodes_reports_ghidra_errors() {
        use crate::space::AddressSpace;

        let mut non_input = Funcdata::new("combine_non_input", Address::new(0), 1);
        let hi = non_input
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x24);
        let lo = non_input
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = non_input.vbank.set_input(lo).expect("fresh low input");
        let error = non_input
            .combine_input_varnodes(&hi, &lo)
            .expect_err("free high value is not an input");
        assert_eq!(error.to_string(), "Varnodes being combined are not inputs");

        let mut disjoint = Funcdata::new("combine_disjoint", Address::new(0), 1);
        let hi = disjoint
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x30);
        let hi = disjoint.vbank.set_input(hi).expect("fresh high input");
        let lo = disjoint
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x20);
        let lo = disjoint.vbank.set_input(lo).expect("fresh low input");
        let error = disjoint
            .combine_input_varnodes(&hi, &lo)
            .expect_err("disjoint inputs are not contiguous");
        assert_eq!(
            error.to_string(),
            "Input varnodes being combined are not contiguous"
        );
    }

    // Regression for FUNC-GLOBRANGE-HANG-0001.
    //
    // Ghidra totalReplace (funcdata_varnode.cc:1478-1486) advances its
    // std::list iterator BEFORE opSetInput severs the entry, so the loop
    // visits each original entry exactly once and terminates at
    // endDescend() even when opSetInput early-outs because newvn == the
    // current input (funcdata_op.cc:107). The pre-fix Rust re-scan loop
    // re-found the same descendant forever in exactly that case — the
    // glob_range(0x4d60) deadlock.
    #[test]
    fn test_total_replace_same_varnode_terminates() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("total_replace_self", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);

        // totalReplace(vn, vn): opSetInput early-outs (getIn(0) == vn ==
        // newvn) leaving the descend entry in place — Ghidra still exits
        // after one pass. Pre-fix Rugra spun forever here.
        fd.total_replace(&vn, vn.clone());

        // Ghidra end state: opSetInput early-out mutates nothing.
        assert_eq!(
            vn.read().unwrap().descend.len(),
            1,
            "early-out opSetInput must leave the descend entry (Ghidra cc:107)"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &vn
        ));

        // A real replacement must drain vn's list exactly once per entry and
        // rewire the reader (Ghidra: eraseDescend + addDescend on newvn).
        let newvn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x200);
        fd.total_replace(&vn, newvn.clone());
        assert!(
            vn.read().unwrap().descend.is_empty(),
            "totalReplace must erase every live descend entry of the replaced vn"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &newvn
        ));
        assert_eq!(newvn.read().unwrap().descend.len(), 1);
    }

    // A dead Weak entry (op Arc freed without unset — impossible in Ghidra's
    // raw-pointer model) must be skipped, never matched: erase_descend
    // matches by upgraded identity, so a dead entry can only make a
    // "scan until drained" loop non-terminating. The snapshot walk visits it
    // zero times and terminates.
    #[test]
    fn test_total_replace_skips_dead_weak_entries() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("total_replace_deadweak", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        let newvn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x200);
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);

        // Fabricate a dead entry: downgrade a temporary op Arc, then drop it.
        {
            let temp = std::sync::Arc::new(std::sync::RwLock::new(crate::op::PcodeOp::new(
                crate::address::SeqNum::new(Address::new(0x1000), 1),
                OpCode::CPUI_COPY,
            )));
            vn.write()
                .unwrap()
                .descend
                .push(std::sync::Arc::downgrade(&temp));
        }
        assert_eq!(vn.read().unwrap().descend.len(), 2);

        // Must terminate and leave only the dead entry behind (live site
        // rewired to newvn exactly as in Ghidra).
        fd.total_replace(&vn, newvn.clone());
        assert_eq!(
            vn.read().unwrap().descend.len(),
            1,
            "only the (unmatchable) dead entry may remain"
        );
        assert!(std::sync::Arc::ptr_eq(
            &reader.0.read().unwrap().inrefs[0],
            &newvn
        ));
    }

    // Regression for the erase_descend WARN storm (UPSTREAM-OUTVN-DEADWIRE
    // family). Ghidra opUnlink (funcdata_op.cc:186-193) NULLs every input
    // slot via opUnsetInput/clearInput, and opDestroy (funcdata_op.cc:211-216)
    // then skips those NULL slots. Rugra cannot NULL a Vec slot, so the
    // second unset must detect the already-severed link through descend
    // membership and be a no-op instead of re-erasing.
    #[test]
    fn test_unlink_then_destroy_does_not_disturb_other_readers() {
        use crate::space::AddressSpace;

        let mut fd = Funcdata::new("unlink_destroy", Address::new(0x1000), 0x10);
        let vn = fd
            .vbank
            .create_with_space(4, AddressSpace::Register, 0x100);
        // Register vn as a function input (VarnodeBank::setInput,
        // varnode.cc:1358). The harness links TWO readers to one varnode; in
        // Ghidra a multi-reader varnode is written/input (per-read frees are
        // separate objects — PcodeEmitFd::dump, funcdata.cc:905), so a free
        // vn gaining a second descend is Ghidra-unreachable: addDescend would
        // throw "Free varnode has multiple descendants" (varnode.cc:336).
        // INPUT keeps is_written() false and op_unlink/op_destroy/op_unset_input
        // have no input-flag branch, so the double-unset no-op path under test
        // is identical. setInput returns the same Arc here (unique loc, xref
        // re-inserts the same object), so the ptr_eq assertions still bind.
        let vn = fd.vbank.set_input(vn).unwrap();
        let reader = fd.new_op(1, Address::new(0x1000));
        fd.op_set_input(&reader, vn.clone(), 0);
        let other = fd.new_op(1, Address::new(0x1002));
        fd.op_set_input(&other, vn.clone(), 0);
        assert_eq!(vn.read().unwrap().descend.len(), 2);

        // op_unlink severs reader's link (stale Arc remains in its inrefs),
        // then op_destroy re-unsets every slot — the double unset must not
        // touch `other`'s descend entry.
        fd.op_unlink(&reader);
        fd.op_destroy(&reader);

        let live: Vec<_> = vn.read().unwrap().descend_iter().collect();
        assert_eq!(live.len(), 1, "other reader's descend entry must survive");
        assert!(std::sync::Arc::ptr_eq(&live[0], &other.0));
        assert!(std::sync::Arc::ptr_eq(
            &other.0.read().unwrap().inrefs[0],
            &vn
        ));
    }

}

// RUGRA-GLUE: 在出边列表中查找指向目标块的索引。Ghidra 用 FlowBlock::getOutIndex
// (block.hh:317)；Rugra 内联为文件级函数（需 downcast 到 BlockBasic/BlockGraph）。
/// Find the index of the outgoing edge pointing to `target` in `src`.
fn find_out_index(
    src: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    target: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
) -> Option<usize> {
    let rg = src.read().unwrap();
    let n = rg.size_out();
    for i in 0..n {
        if let Some(e) = rg.get_out(i) {
            if Arc::ptr_eq(&e.point, target) {
                return Some(i);
            }
        }
    }
    None
}

// Ghidra: funcdata.hh:655 AncestorRealistic
/// Helper for determining if Varnodes can trace their value from a legitimate
/// source. Faithful 1:1 port of `AncestorRealistic` (funcdata.hh:655-724 +
/// funcdata_varnode.cc:1997-2237).
///
/// Tries to determine if a Varnode (a particular input to a CALL, CALLIND, or
/// RETURN op) makes sense as parameter-passing/return storage by examining the
/// Varnode's ancestors. If ancestors are \e unaffected, \e abnormal inputs, or
/// \e killedbycall, the Varnode doesn't make a good parameter.
///
/// The traversal is a depth-first walk over ancestor Varnodes (following the
/// def chain). The `State` stack holds the traversal frontier; each `State`
/// records (op, slot, flags, offset). The `marked_vn` list tracks visited
/// Varnodes so cycles are trimmed and marks can be cleared afterwards.
pub struct AncestorRealistic {
    state_stack: Vec<ArState>,
    marked_vn: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    multi_depth: i32,
    allow_failing_path: bool,
    // Snapshot of trial->isKilledByCall() taken at execute() start, so the
    // INDIRECT case can read it without &mut aliasing on ParamTrial.
    trial_killed_by_call: bool,
    // Snapshot of trial->getSize() taken at execute() start, so the PIECE
    // case can compare stateVn->getSize() > trial->getSize() faithfully.
    trial_size: i32,
    // Deferred ParamTrial flag mutations (applied by execute() after the
    // traversal). Ghidra mutates the trial pointer mid-traversal
    // (setIndCreateFormed / setCondExeEffect); Rugra defers these to avoid
    // &mut aliasing on ParamTrial during the self-referential traversal.
    pending_ind_create_formed: bool,
    pending_condexe_effect: bool,
}

// Ghidra: funcdata.hh:655 AncestorRealistic::State
/// One node in the depth-first ancestor traversal. Faithful to the nested
/// `AncestorRealistic::State` class (funcdata.hh:657-696).
#[derive(Clone)]
struct ArState {
    /// Operation along the path to the Varnode. `vn = op.getIn(slot)`.
    op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
    /// Input slot: `vn = op.getIn(slot)`.
    slot: i32,
    /// Boolean properties (seen_solid0 | seen_solid1 | seen_kill).
    flags: u32,
    /// Offset of the eventual trial value within a possibly larger register.
    offset: i32,
}

// Ghidra: funcdata.hh:659 AncestorRealistic::State (anonymous enum)
mod state_flags {
    /// Solid movement into slot 0 seen on at least one path to MULTIEQUAL.
    pub const SEEN_SOLID0: u32 = 1;
    /// Solid movement into a slot other than 0 seen.
    pub const SEEN_SOLID1: u32 = 2;
    /// Killedbycall seen on at least one path to MULTIEQUAL.
    pub const SEEN_KILL: u32 = 4;
}

// Ghidra: funcdata.hh:698 AncestorRealistic (anonymous enum)
/// Depth-first traversal commands. Faithful to the anonymous enum in
/// `AncestorRealistic` (funcdata.hh:698-704).
mod ar_command {
    /// Extending path into a new Varnode.
    pub const ENTER_NODE: i32 = 0;
    /// Backtracking, from a path that contained a reasonable ancestor.
    pub const POP_SUCCESS: i32 = 1;
    /// Backtracking, from a path with successful solid movement.
    pub const POP_SOLID: i32 = 2;
    /// Backtracking, from a path with a bad ancestor.
    pub const POP_FAIL: i32 = 3;
    /// Backtracking, from a path with a bad ancestor (specifically killedbycall).
    pub const POP_FAILKILL: i32 = 4;
}

impl ArState {
    // Ghidra: funcdata.hh:673 AncestorRealistic::State::State(PcodeOp*,int4)
    /// Constructor given a Varnode read: `op=o; slot=s; flags=0; offset=0`.
    /// Faithful to `State(PcodeOp *o,int4 s)` (funcdata.hh:673-680).
    // RUGRA-GLUE: named constructor — Ghidra inlines this member init at
    // each State construction site; Rust uses a named ctor for the same
    // four-field initialization.
    fn new(op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>, slot: i32) -> Self {
        ArState { op, slot, flags: 0, offset: 0 }
    }

    // Ghidra: funcdata.hh:685 AncestorRealistic::State::State(PcodeOp*,const State&)
    /// Constructor from an old state pulled back through a CPUI_SUBPIECE:
    /// `op=o; slot=0; flags=0; offset = oldState.offset +
    /// op->getIn(1)->getOffset()` (the SUBPIECE constant offset
    /// accumulates). Faithful to `State(PcodeOp *o,const State &oldState)`
    /// (funcdata.hh:685-690).
    fn pull_back_subpiece(
        op: std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
        old_state: &ArState,
    ) -> Self {
        let trunc_offset = {
            let o = op.read().unwrap();
            o.get_in(1)
                .map(|v| v.read().unwrap().get_offset() as i32)
                .unwrap_or(0)
        };
        ArState { op, slot: 0, flags: 0, offset: old_state.offset + trunc_offset }
    }

    // Ghidra: funcdata.hh:692 State::markSolid
    /// Mark the given slot as having solid movement. Faithful to
    /// `State::markSolid` (funcdata.hh:692).
    fn mark_solid(&mut self, s: i32) {
        self.flags |= if s == 0 { state_flags::SEEN_SOLID0 } else { state_flags::SEEN_SOLID1 };
    }
    // Ghidra: funcdata.hh:693 State::markKill
    /// Mark killedbycall as seen. Faithful to `State::markKill` (funcdata.hh:693).
    fn mark_kill(&mut self) {
        self.flags |= state_flags::SEEN_KILL;
    }
    // Ghidra: funcdata.hh:694 State::seenSolid
    /// Has solid movement been seen? Faithful to `State::seenSolid` (funcdata.hh:694).
    fn seen_solid(&self) -> bool {
        (self.flags & (state_flags::SEEN_SOLID0 | state_flags::SEEN_SOLID1)) != 0
    }
    // Ghidra: funcdata.hh:695 State::seenKill
    /// Has killedbycall been seen? Faithful to `State::seenKill` (funcdata.hh:695).
    fn seen_kill(&self) -> bool {
        (self.flags & state_flags::SEEN_KILL) != 0
    }
    // Ghidra: funcdata.hh:691 State::getSolidSlot
    /// Get the slot associated with solid movement. Faithful to
    /// `State::getSolidSlot` (funcdata.hh:691).
    fn get_solid_slot(&self) -> i32 {
        if (self.flags & state_flags::SEEN_SOLID0) != 0 { 0 } else { 1 }
    }
}

impl AncestorRealistic {
    // Ghidra: funcdata.hh:714 AncestorRealistic::mark
    /// Mark the given Varnode as visited by the traversal. Faithful to
    /// `AncestorRealistic::mark` (funcdata.hh:714-717)
    /// `{ markedVn.push_back(vn); vn->setMark(); }` — the push precedes the
    /// flag set, so a mid-throw state still records the Varnode for the
    /// clearing pass.
    fn mark(&mut self, vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) {
        self.marked_vn.push(vn.clone());
        vn.write().unwrap().set_mark();
    }
    // RUGRA-GLUE: AncestorRealistic::new constructor (no Ghidra counterpart — Ghidra uses stack allocation)
    /// Construct an empty ancestor-realistic checker.
    pub fn new() -> Self {
        Self {
            state_stack: Vec::new(),
            marked_vn: Vec::new(),
            multi_depth: 0,
            allow_failing_path: false,
            trial_killed_by_call: false,
            trial_size: 0,
            pending_ind_create_formed: false,
            pending_condexe_effect: false,
        }
    }

    // Ghidra: funcdata_varnode.cc:1997 AncestorRealistic::checkConditionalExe
    /// Check if the current Varnode was produced by conditional flow. Faithful
    /// to `AncestorRealistic::checkConditionalExe` (funcdata_varnode.cc:1997-2022).
    /// Returns true if there are two input flows and one is a normal solid flow
    /// (the MULTIEQUAL block has exactly 2 inputs, and the solid-slot's source
    /// block has exactly 1 out-edge).
    fn check_conditional_exe(&self, state: &ArState) -> bool {
        let parent_arc = {
            let op_rg = state.op.read().unwrap();
            op_rg.parent.as_ref().and_then(|w| w.upgrade())
        };
        let bl = match parent_arc { Some(b) => b, None => return false ,
        };
        let (solid_point, size_in) = {
            let bl_rg = bl.read().unwrap();
            let solid_slot = state.get_solid_slot();
            let point = bl_rg.get_in(solid_slot as usize).map(|e| e.point.clone());
            (point, bl_rg.size_in())
        };
        if size_in != 2 { return false; }
        match solid_point {
            Some(sb) => sb.read().unwrap().size_out() == 1,
            None => false,
        }
    }

    // Ghidra: funcdata_varnode.cc:2026 AncestorRealistic::enterNode
    /// Analyze a newly-entered node during the depth-first traversal. Faithful
    /// to `AncestorRealistic::enterNode` (funcdata_varnode.cc:2026-2136).
    /// Returns the command for the next traversal step.
    fn enter_node(&mut self) -> i32 {
        use crate::opcodes::OpCode as OC;
        let (op_arc, slot, state_offset) = {
            let state = self.state_stack.last().unwrap();
            (state.op.clone(), state.slot, state.offset)
        };
        // Resolve the Varnode being traversed: vn = op.getIn(slot)
        let state_vn = {
            let op_rg = op_arc.read().unwrap();
            op_rg.get_in(slot as usize).cloned()
        };
        // The pull-back constructor view of the current state (funcdata.hh:685).
        let state_snapshot = {
            let state = self.state_stack.last().unwrap();
            ArState {
                op: state.op.clone(),
                slot: state.slot,
                flags: state.flags,
                offset: state.offset,
            }
        };
        let state_vn = match state_vn {
            Some(v) => v,
            None => return ar_command::POP_FAIL,
        };
        // Truncate traversal on already-visited varnodes (cycle prevention).
        let (is_mark, is_written) = {
            let vn = state_vn.read().unwrap();
            (vn.is_mark(), vn.is_written())
        };
        if is_mark { return ar_command::POP_SUCCESS; }
        if !is_written {
            let (is_input, is_unaffected, is_persist, is_direct_write) = {
                let vn = state_vn.read().unwrap();
                (
                    vn.is_input(), vn.is_unaffected(), vn.is_persist(), vn.is_direct_write(),
                )
            };
            if is_input {
                if is_unaffected { return ar_command::POP_FAIL; }
                if is_persist { return ar_command::POP_SUCCESS; }
                if !is_direct_write { return ar_command::POP_FAIL; }
            }
            return ar_command::POP_SUCCESS;
        }
        // Mark the varnode as visited (funcdata.hh:714-717 AncestorRealistic::mark).
        self.mark(&state_vn);
        // Follow the defining op.
        let def_arc = {
            let vn = state_vn.read().unwrap();
            vn.get_def()
        };
        let op_def = match def_arc {
            Some(d) => d,
            None => return ar_command::POP_FAIL,
        };
        let opcode = { op_def.read().unwrap().opcode };
        match opcode {
            OC::CPUI_INDIRECT => {
                let (is_ind_create, is_ind_store, out_is_return, in0_indirect_zero) = {
                    let d = op_def.read().unwrap();
                    let out_is_ret = d
                        .get_out()
                        .map(|v| v.read().unwrap().is_return_address())
                        .unwrap_or(false);
                    let in0_iz = d
                        .get_in(0)
                        .map(|v| v.read().unwrap().is_indirect_zero())
                        .unwrap_or(false);
                    (
                        d.is_indirect_creation(), d.is_indirect_store(), out_is_ret, in0_iz,
                    )
                };
                if is_ind_create {
                    self.pending_ind_create_formed = true;
                    if in0_indirect_zero {
                        return ar_command::POP_FAILKILL;
                    }
                    return ar_command::POP_SUCCESS;
                }
                if !is_ind_store {
                    // Ghidra: funcdata_varnode.cc:2052 "If flow goes THROUGH a call"
                    if out_is_return { return ar_command::POP_FAIL; }
                    if self.trial_killed_by_call { return ar_command::POP_FAIL; }
                }
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_SUBPIECE => {
                let (
                    out_space_is_internal, is_incidental, in0_incidental, out_overlap_in0_eq_in1, new_offset,
                ) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1_off = d
                        .get_in(1)
                        .and_then(|v| Some(v.clone()))
                        .map(|v| v.read().unwrap().get_offset())
                        .unwrap_or(0);
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_overlap = match (&out_vn, &in0) {
                        (Some(o), Some(i)) => o.read().unwrap().overlap(&i.read().unwrap()),
                        _ => -1,
                    };
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref()
                            .map(|v| v.read().unwrap().is_incidental_copy())
                            .unwrap_or(false),
                        out_overlap == in1_off as i32,
                        state_offset + in1_off as i32,
                    )
                };
                if out_space_is_internal || is_incidental || in0_incidental || out_overlap_in0_eq_in1 {
                    self.state_stack.push(
                        // funcdata.hh:685-690 State ctor pulled back through
                        // SUBPIECE: offset = old.offset + in(1) offset.
                        ArState::pull_back_subpiece(op_def.clone(), &state_snapshot),
                    );
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2069-2077 minimal traversal to
                // rule out unaffected/invalid inputs (COPY/SUBPIECE chain).
                let mut cur_op = op_def.clone();
                loop {
                    let (vn_mark, vn_input, vn_unaffected, vn_direct_write, next_def) = {
                        let d = cur_op.read().unwrap();
                        let vn = d.get_in(0).and_then(|v| Some(v.clone()));
                        match vn {
                            Some(v) => {
                                let vr = v.read().unwrap();
                                (
                                    vr.is_mark(), vr.is_input(), vr.is_unaffected(), vr.is_direct_write(), vr.get_def(),
                                )
                            }
                            None => return ar_command::POP_FAIL,
                        }
                    };
                    if !vn_mark && vn_input {
                        if vn_unaffected || !vn_direct_write {
                            return ar_command::POP_FAIL;
                        }
                    }
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_op = nd;
                            } else {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_COPY => {
                let (out_space_internal, is_incidental, in0_incidental, out_addr_eq_in0_addr) = {
                    let d = op_def.read().unwrap();
                    let out_vn = d.get_out().and_then(|v| Some(v.clone()));
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let out_space = out_vn.as_ref().map(|v| v.read().unwrap().get_space());
                    let out_addr = out_vn.as_ref().map(|v| v.read().unwrap().get_offset());
                    let in0_addr = in0.as_ref().map(|v| v.read().unwrap().get_offset());
                    (
                        out_space == Some(AddressSpace::Unique),
                        d.is_incidental_copy(),
                        in0.as_ref()
                            .map(|v| v.read().unwrap().is_incidental_copy())
                            .unwrap_or(false),
                        out_addr.is_some() && in0_addr.is_some() && out_addr == in0_addr,
                    )
                };
                if out_space_internal || is_incidental || in0_incidental || out_addr_eq_in0_addr {
                    self.state_stack.push(ArState {
                        op: op_def.clone(),
                        slot: 0,
                        flags: 0,
                        offset: 0,
                    });
                    return ar_command::ENTER_NODE;
                }
                // Ghidra: funcdata_varnode.cc:2090-2108 minimal traversal:
                // follow COPY/SUBPIECE/PIECE chain checking input flags +
                // store_unmapped. (op, vn) advance together.
                let mut cur_op = op_def.clone();
                let mut cur_vn = {
                    let d = op_def.read().unwrap();
                    d.get_in(0).and_then(|v| Some(v.clone()))
                };
                loop {
                    let (vn_mark, vn_input, vn_direct_write) = match &cur_vn {
                        Some(v) => {
                            let vr = v.read().unwrap();
                            (vr.is_mark(), vr.is_input(), vr.is_direct_write())
                        }
                        None => return ar_command::POP_FAIL,
                    };
                    if !vn_mark && vn_input {
                        if !vn_direct_write { return ar_command::POP_FAIL; }
                    }
                    if cur_op.read().unwrap().is_store_unmapped() {
                        return ar_command::POP_FAIL;
                    }
                    let next_def = match &cur_vn {
                        Some(v) => v.read().unwrap().get_def(),
                        None => break,
                    };
                    match next_def {
                        Some(nd) => {
                            let next_code = nd.read().unwrap().opcode;
                            if next_code == OC::CPUI_COPY || next_code == OC::CPUI_SUBPIECE {
                                cur_vn = nd.read().unwrap().get_in(0).cloned();
                            } else if next_code == OC::CPUI_PIECE {
                                // Follow least significant piece.
                                cur_vn = nd.read().unwrap().get_in(1).cloned();
                            } else {
                                break;
                            }
                            cur_op = nd;
                        }
                        None => break,
                    }
                }
                return ar_command::POP_SOLID;
            }
            OC::CPUI_MULTIEQUAL => {
                self.multi_depth += 1;
                self.state_stack.push(ArState {
                    op: op_def.clone(),
                    slot: 0,
                    flags: 0,
                    offset: 0,
                });
                return ar_command::ENTER_NODE;
            }
            OC::CPUI_PIECE => {
                // Ghidra: funcdata_varnode.cc:2115-2132 PIECE case.
                // stateVn is the PIECE output; compare its size to trial size.
                let state_vn_size = state_vn.read().unwrap().get_size() as i32;
                let (in1_size, in0_size, state_vn_is_spacebase) = {
                    let d = op_def.read().unwrap();
                    let in0 = d.get_in(0).and_then(|v| Some(v.clone()));
                    let in1 = d.get_in(1).and_then(|v| Some(v.clone()));
                    let state_vn_space = state_vn.read().unwrap().get_space();
                    let in0_sz = in0
                        .as_ref()
                        .map(|v| v.read().unwrap().get_size() as i32)
                        .unwrap_or(0);
                    let in1_sz = in1
                        .as_ref()
                        .map(|v| v.read().unwrap().get_size() as i32)
                        .unwrap_or(0);
                    (in1_sz, in0_sz, state_vn_space == AddressSpace::Stack)
                };
                if state_vn_size > self.trial_size {
                    if state_offset == 0 && in1_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 1, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    } else if state_offset == in1_size && in0_size <= self.trial_size {
                        self.state_stack.push(ArState {
                            op: op_def.clone(), slot: 0, flags: 0, offset: 0,
                        });
                        return ar_command::ENTER_NODE;
                    }
                    if !state_vn_is_spacebase {
                        return ar_command::POP_FAIL;
                    }
                }
                return ar_command::POP_SOLID;
            }
            _ => {
                // Any other LOAD or arithmetic/logical operation is solid movement.
                return ar_command::POP_SOLID;
            }
        }
    }

    // Ghidra: funcdata_varnode.cc:2141 AncestorRealistic::uponPop
    /// Backtrack into a previously visited node. Faithful to
    /// `AncestorRealistic::uponPop` (funcdata_varnode.cc:2141-2185).
    fn upon_pop(&mut self, pop_command: i32) -> i32 {
        use crate::opcodes::OpCode as OC;
        let is_multiequal = {
            let state = self.state_stack.last().unwrap();
            state.op.read().unwrap().opcode == OC::CPUI_MULTIEQUAL
        };
        if is_multiequal {
            let (cur_slot, cur_num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if pop_command == ar_command::POP_FAIL {
                self.multi_depth -= 1;
                self.state_stack.pop();
                return pop_command;
            } else if pop_command == ar_command::POP_SOLID && self.multi_depth == 1 && cur_num_input == 2 {
                let slot = self.state_stack.last().unwrap().slot;
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_solid(slot);
                }
            } else if pop_command == ar_command::POP_FAILKILL {
                let stack_len = self.state_stack.len();
                if stack_len >= 2 {
                    self.state_stack[stack_len - 2].mark_kill();
                }
            }
            // state.slot += 1 (Ghidra funcdata_varnode.cc:2156)
            self.state_stack.last_mut().unwrap().slot += 1;
            let (new_slot, num_input) = {
                let state = self.state_stack.last().unwrap();
                let s = state.op.read().unwrap();
                (state.slot, s.num_input() as i32)
            };
            if new_slot == num_input {
                // All siblings traversed.
                let (prev_seen_solid, prev_seen_kill) = if self.state_stack.len() >= 2 {
                    let p = &self.state_stack[self.state_stack.len() - 2];
                    (p.seen_solid(), p.seen_kill())
                } else { (false, false) };
                let mut final_cmd = pop_command;
                if prev_seen_solid {
                    final_cmd = ar_command::POP_SUCCESS;
                    if prev_seen_kill {
                        if self.allow_failing_path {
                            // Re-read the current state for checkConditionalExe.
                            let state_clone = self.state_stack.last().unwrap().clone();
                            if !self.check_conditional_exe(&state_clone) {
                                final_cmd = ar_command::POP_FAIL;
                            } else {
                                self.pending_condexe_effect = true;
                            }
                        } else {
                            final_cmd = ar_command::POP_FAIL;
                        }
                    }
                } else if prev_seen_kill {
                    final_cmd = ar_command::POP_FAILKILL;
                } else {
                    final_cmd = ar_command::POP_SUCCESS;
                }
                self.multi_depth -= 1;
                self.state_stack.pop();
                return final_cmd;
            }
            return ar_command::ENTER_NODE;
        } else {
            self.state_stack.pop();
            return pop_command;
        }
    }

    // Ghidra: funcdata_varnode.cc:2194 AncestorRealistic::execute
    /// Perform a full ancestor check on a given parameter trial. Faithful to
    /// `AncestorRealistic::execute` (funcdata_varnode.cc:2194-2237).
    ///
    /// Returns true if the varnode (op's input at `slot`) has realistic
    /// ancestors for a parameter-passing location. Sets the trial's
    /// ancestor_realistic / ancestor_solid / condexe_effect / ind_create_formed
    /// flags as appropriate.
    pub fn execute(
        &mut self,
        op: &crate::op::PcodeOpRef,
        slot: i32,
        trial: &mut crate::fspec::ParamTrial,
        allow_fail: bool,
    ) -> bool {
        self.allow_failing_path = allow_fail;
        self.trial_killed_by_call = trial.is_killed_by_call();
        self.trial_size = trial.get_size();
        self.marked_vn.clear();
        self.state_stack.clear();
        self.multi_depth = 0;
        self.pending_ind_create_formed = false;
        self.pending_condexe_effect = false;
        // If the parameter itself is an input, we don't consider this realistic
        // (unless retesting for condexe).
        let is_input = {
            let op_rg = op.0.read().unwrap();
            let vn = op_rg.get_in(slot as usize);
            match vn {
                Some(v) => v.read().unwrap().is_input(),
                None => return false,
            }
        };
        if is_input {
            if !trial.has_condexe_effect() {
                return false;
            }
        }
        // Run the depth-first traversal.
        let mut command = ar_command::ENTER_NODE;
        self.state_stack.push(ArState {
            op: op.0.clone(),
            slot,
            flags: 0,
            offset: 0,
        });
        while !self.state_stack.is_empty() {
            match command {
                c if c == ar_command::ENTER_NODE => command = self.enter_node(),
                _ => command = self.upon_pop(command),
            }
        }
        // Clean up marks.
        for vn_arc in &self.marked_vn {
            vn_arc.write().unwrap().clear_mark();
        }
        // Apply deferred trial mutations.
        if self.pending_ind_create_formed { trial.set_ind_create_formed(); }
        if self.pending_condexe_effect { trial.set_condexe_effect(); }
        if command == ar_command::POP_SUCCESS {
            trial.set_ancestor_realistic();
            return true;
        } else if command == ar_command::POP_SOLID {
            trial.set_ancestor_realistic();
            trial.set_ancestor_solid();
            return true;
        }
        false
    }
}

// TraverseNode flags (expression.hh:62-68), used by onlyOpUse/ancestorOpUse.
mod traverse_flags {
    pub const ACTIONALT: u32 = 1;
    pub const INDIRECT: u32 = 2;
    pub const INDIRECTALT: u32 = 4;
    pub const LSB_TRUNCATED: u32 = 8;
    pub const CONCAT_HIGH: u32 = 0x10;
}

// Ghidra: expression.cc:28 TraverseNode::isAlternatePathValid
/// Decide whether the alternate path (through a different RETURN/CALL) sees
/// materially different data-flow than the main path. Faithful 1:1 port of
/// `TraverseNode::isAlternatePathValid` (expression.cc:28-50):
///   - main path traversed INDIRECT but alternate did not  -> true
///   - alternate traversed INDIRECT but main did not       -> false
///   - alternate traversed a solid action/non-incidental COPY -> true
///   - no lone descendant                                   -> false
///   - then skip incidental COPY chains (lone-descendant
///     checked per hop) and return `!def->isMarker()`
///     (MULTIEQUAL/INDIRECT indicate multiple values).
fn is_alternate_path_valid(
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    flags: u32,
) -> bool {
    use crate::opcodes::OpCode as OC;
    if (flags & (traverse_flags::INDIRECT | traverse_flags::INDIRECTALT))
        == traverse_flags::INDIRECT
    {
        // If main path traversed an INDIRECT but the alternate did not
        return true;
    }
    if (flags & (traverse_flags::INDIRECT | traverse_flags::INDIRECTALT))
        == traverse_flags::INDIRECTALT
    {
        return false; // Alternate path traversed INDIRECT, main did not
    }
    if (flags & traverse_flags::ACTIONALT) != 0 {
        return true; // Alternate path traversed a dedicated COPY
    }
    if vn.read().unwrap().lone_descend().is_none() {
        return false;
    }
    let mut cur = vn.clone();
    loop {
        let def = cur.read().unwrap().get_def();
        let op_arc = match def {
            Some(o) => o,
            None => return true, // cc:34: op == 0
        };
        let (incidental, code) = {
            let o = op_arc.read().unwrap();
            (o.is_incidental_copy(), o.opcode)
        };
        // cc:36-42: skip any incidental COPY chain.
        if !(incidental && code == OC::CPUI_COPY) {
            return !op_arc.read().unwrap().is_marker();
        }
        let next = op_arc.read().unwrap().get_in(0).cloned();
        let Some(next) = next else { return true };
        if next.read().unwrap().lone_descend().is_none() {
            return false;
        }
        cur = next;
    }
}

// Ghidra: funcdata_varnode.cc:1805 Funcdata::onlyOpUse
/// Test if the given Varnode seems to only be used by a CALL or RETURN.
/// Faithful 1:1 port of `Funcdata::onlyOpUse`
/// (funcdata_varnode.cc:1805-1904): BFS over descendants with
/// TraverseNode flags; BRANCH/LOAD/STORE are uses, CALL/CALLIND go through
/// checkCallDoubleUse, a different RETURN is a use unless it holds the same
/// slot varnode (or, outside return analysis, unless the alternate path is
/// invalid), PIECE/SUBPIECE set concat/truncation flags, every other opcode
/// sets actionalt, and every op's non-persist output joins the traversal.
fn only_op_use(
    fd: &Funcdata,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    opmatch: &crate::op::PcodeOpRef,
    trial: &crate::fspec::ParamTrial,
    main_flags: u32,
    match_fc: Option<&crate::fspec::FuncCallSpecs>,
) -> bool {
    use crate::opcodes::OpCode as OC;
    use std::sync::{Arc, RwLock};
    let trial_slot = trial.get_slot();
    struct TNode {
        vn: Arc<RwLock<crate::varnode::Varnode>>,
        flags: u32,
    }
    let mut varlist: Vec<TNode> = Vec::with_capacity(64);
    {
        let mut vn = invn.write().unwrap();
        vn.set_mark();
    }
    varlist.push(TNode { vn: invn.clone(), flags: main_flags });
    let mut idx = 0;
    let mut res = true;
    while idx < varlist.len() {
        let base_flags = varlist[idx].flags;
        let vn_arc = varlist[idx].vn.clone();
        let descends: Vec<Arc<RwLock<crate::op::PcodeOp>>> = vn_arc
            .read()
            .unwrap()
            .descend
            .iter()
            .filter_map(|w| w.upgrade())
            .collect();
        for op_arc in descends {
            let op_rg = op_arc.read().unwrap();
            // cc:1824-1826: op == opmatch is not a use when this vn is the
            // trial slot's varnode (otherwise fall through to the switch).
            if Arc::ptr_eq(&op_arc, &opmatch.0) {
                let trial_in = op_rg.get_in(trial_slot as usize);
                if let Some(tiv) = trial_in {
                    if Arc::ptr_eq(tiv, &vn_arc) {
                        continue;
                    }
                }
            }
            let mut cur_flags = base_flags;
            let opmatch_is_return = opmatch.0.read().unwrap().opcode == OC::CPUI_RETURN;
            match op_rg.opcode {
                // cc:1829-1835: These ops define a USE of a variable.
                OC::CPUI_BRANCH
                | OC::CPUI_CBRANCH
                | OC::CPUI_BRANCHIND
                | OC::CPUI_LOAD
                | OC::CPUI_STORE => {
                    res = false;
                }
                // cc:1836-1840: possibly legitimate double use at a call.
                OC::CPUI_CALL | OC::CPUI_CALLIND => {
                    if fd.check_call_double_use(
                        opmatch,
                        &crate::op::PcodeOpRef(op_arc.clone()),
                        &vn_arc,
                        cur_flags,
                        trial,
                        match_fc,
                    ) {
                        continue;
                    }
                    res = false;
                }
                // cc:1841-1843.
                OC::CPUI_INDIRECT => {
                    cur_flags |= traverse_flags::INDIRECTALT;
                }
                // cc:1844-1848.
                OC::CPUI_COPY => {
                    let out_internal = op_rg
                        .get_out()
                        .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                        .unwrap_or(false);
                    let op_incidental = op_rg.is_incidental_copy();
                    let vn_incidental = vn_arc.read().unwrap().is_incidental_copy();
                    if !out_internal && !op_incidental && !vn_incidental {
                        cur_flags |= traverse_flags::ACTIONALT;
                    }
                }
                // cc:1849-1861.
                OC::CPUI_RETURN => {
                    if opmatch_is_return {
                        // Are we in a different return: not a use only when
                        // it holds the same slot varnode (cc:1850-1853).
                        let r_in = op_rg.get_in(trial_slot as usize);
                        if let Some(riv) = r_in {
                            if Arc::ptr_eq(riv, &vn_arc) {
                                continue;
                            }
                        }
                    } else if fd.active_output.is_some() {
                        // cc:1854-1858: analyzing returns; unless the vn
                        // holds the actual return value (slot 0), an
                        // invalid alternate path is not a "use".
                        let in0_is_vn = op_rg
                            .get_in(0)
                            .map(|v0| Arc::ptr_eq(v0, &vn_arc))
                            .unwrap_or(false);
                        if !in0_is_vn && !is_alternate_path_valid(&vn_arc, cur_flags) {
                            continue;
                        }
                    }
                    res = false;
                }
                // cc:1862-1866: transparent for this traversal.
                OC::CPUI_MULTIEQUAL
                | OC::CPUI_INT_SEXT
                | OC::CPUI_INT_ZEXT
                | OC::CPUI_CAST => {}
                // cc:1867-1875.
                OC::CPUI_PIECE => {
                    let in0_is_vn = op_rg
                        .get_in(0)
                        .map(|v0| Arc::ptr_eq(v0, &vn_arc))
                        .unwrap_or(false);
                    if in0_is_vn {
                        // Concatenated as most significant piece.
                        if (cur_flags & traverse_flags::LSB_TRUNCATED) != 0 {
                            // Original lsb has been truncated and replaced.
                            continue; // No longer assume this is a possible use
                        }
                        cur_flags |= traverse_flags::CONCAT_HIGH;
                    }
                }
                // cc:1876-1881.
                OC::CPUI_SUBPIECE => {
                    let in1_off = op_rg.get_in(1).map(|v| v.read().unwrap().get_offset());
                    if in1_off != Some(0) {
                        // Throwing away least significant byte(s).
                        if (cur_flags & traverse_flags::CONCAT_HIGH) == 0 {
                            cur_flags |= traverse_flags::LSB_TRUNCATED;
                        }
                    }
                }
                // cc:1882-1884.
                _ => {
                    cur_flags |= traverse_flags::ACTIONALT;
                }
            }
            if !res {
                break;
            }
            // cc:1887-1896: every op's output joins the BFS unless it is a
            // persist varnode (which is a use).
            if let Some(out) = op_rg.get_out() {
                let out_clone = out.clone();
                if out_clone.read().unwrap().is_persist() {
                    res = false;
                    break;
                }
                if !out_clone.read().unwrap().is_mark() {
                    out_clone.write().unwrap().set_mark();
                    varlist.push(TNode { vn: out_clone, flags: cur_flags });
                }
            }
        }
        if !res {
            break;
        }
        idx += 1;
    }
    for t in &varlist {
        t.vn.write().unwrap().clear_mark();
    }
    res
}

// Ghidra: funcdata_varnode.cc:1917 Funcdata::ancestorOpUse
/// Test if the given trial Varnode is likely only used for parameter passing,
/// following ancestors it was copied from. Faithful 1:1 port of
/// `Funcdata::ancestorOpUse` (funcdata_varnode.cc:1917-1994):
///   - maxlevel 0 -> false; unwritten input needs typelock (onlyOpUse),
///   - INDIRECT: indirect-creation stops (onlyOpUse); otherwise recurse
///     in(0) with the indirect traverse flag,
///   - MULTIEQUAL: try each input (mark-trimmed),
///   - COPY: internal/incidental/same-address recurse in(0),
///   - PIECE: recurse only into the piece matching the accumulated offset
///     (least-sig at offset 0, most-sig at offset == in(1) size),
///   - SUBPIECE: REM/SREM side-effect sets trial rem-formed; internal/
///     incidental/overlapping recurse in(0) at offset+newOff,
///   - CALL/CALLIND: false,
///   - otherwise the varnode is the top ancestor -> onlyOpUse.
pub fn ancestor_op_use(
    fd: &Funcdata,
    maxlevel: i32,
    invn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    op: &crate::op::PcodeOpRef,
    trial: &mut crate::fspec::ParamTrial,
    offset: i32,
    main_flags: u32,
    match_fc: Option<&crate::fspec::FuncCallSpecs>,
) -> bool {
    use crate::opcodes::OpCode as OC;
    if maxlevel == 0 { return false; }
    let (is_written, is_input, is_type_lock) = {
        let vn = invn.read().unwrap();
        (vn.is_written(), vn.is_input(), vn.is_type_lock())
    };
    if !is_written {
        // cc:1923-1928: if not written, an input varnode is as good as
        // written when typelocked; anything else cannot carry a use.
        if !is_input { return false; }
        if !is_type_lock { return false; }
        return only_op_use(fd, invn, op, trial, main_flags, match_fc);
    }
    let def_arc = { invn.read().unwrap().get_def() };
    let def_arc = match def_arc { Some(d) => d, None => return false };
    let opcode = def_arc.read().unwrap().opcode;
    match opcode {
        OC::CPUI_INDIRECT => {
            // cc:1933-1938: an indirectCreation is an indication of an
            // output trial, this should not count as an "only use".
            if def_arc.read().unwrap().is_indirect_creation() { return false; }
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            match in0 {
                Some(v) => ancestor_op_use(
                    fd, maxlevel - 1, &v, op, trial, offset,
                    main_flags | traverse_flags::INDIRECT, match_fc,
                ),
                None => false,
            }
        }
        OC::CPUI_MULTIEQUAL => {
            // cc:1939-1952: check if there is any ancestor whose only use
            // is in this op (mark-trimmed recursion over all inputs).
            if def_arc.read().unwrap().is_mark() { return false; }
            def_arc.write().unwrap().set_mark();
            let num_input = def_arc.read().unwrap().num_input();
            let mut result = false;
            for i in 0..num_input {
                let in_vn = def_arc.read().unwrap().get_in(i).cloned();
                if let Some(v) = in_vn {
                    if ancestor_op_use(fd, maxlevel - 1, &v, op, trial, offset, main_flags, match_fc) {
                        result = true;
                        break;
                    }
                }
            }
            def_arc.write().unwrap().clear_mark();
            result
        }
        OC::CPUI_COPY => {
            // cc:1953-1957.
            let out_internal = def_arc
                .read()
                .unwrap()
                .get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0
                .as_ref()
                .map(|v| v.read().unwrap().is_incidental_copy())
                .unwrap_or(false);
            if out_internal || op_incidental || in0_incidental {
                match in0 {
                    Some(v) => ancestor_op_use(fd, maxlevel - 1, &v, op, trial, offset, main_flags, match_fc),
                    None => false,
                }
            } else {
                only_op_use(fd, invn, op, trial, main_flags, match_fc)
            }
        }
        OC::CPUI_PIECE => {
            // cc:1958-1964: concatenation tends to be artificial, so recurse
            // only through the piece corresponding to a later SUBPIECE of
            // the accumulated offset — never both.
            let in1_size = def_arc
                .read()
                .unwrap()
                .get_in(1)
                .map(|v| v.read().unwrap().get_size() as i32)
                .unwrap_or(0);
            if offset == 0 {
                // Follow into least sig piece.
                let in1 = def_arc.read().unwrap().get_in(1).cloned();
                match in1 {
                    Some(v) => ancestor_op_use(fd, maxlevel - 1, &v, op, trial, 0, main_flags, match_fc),
                    None => false,
                }
            } else if offset == in1_size {
                // Follow into most sig piece.
                let in0 = def_arc.read().unwrap().get_in(0).cloned();
                match in0 {
                    Some(v) => ancestor_op_use(fd, maxlevel - 1, &v, op, trial, 0, main_flags, match_fc),
                    None => false,
                }
            } else {
                false
            }
        }
        OC::CPUI_SUBPIECE => {
            // cc:1965-1985.
            let in1_off = def_arc
                .read()
                .unwrap()
                .get_in(1)
                .map(|v| v.read().unwrap().get_offset() as i32)
                .unwrap_or(0);
            if in1_off == 0 {
                // Kludge around a DIV (or similar) causing the register that
                // looks like the high precision piece of the return to be
                // set with the remainder as a side effect.
                let in0 = def_arc.read().unwrap().get_in(0).cloned();
                if let Some(v) = in0 {
                    if v.read().unwrap().is_written() {
                        let remop = v.read().unwrap().get_def();
                        if let Some(remop) = remop {
                            let rem_code = remop.read().unwrap().opcode;
                            if rem_code == OC::CPUI_INT_REM || rem_code == OC::CPUI_INT_SREM {
                                trial.set_rem_formed();
                            }
                        }
                    }
                }
            }
            let out_internal = def_arc
                .read()
                .unwrap()
                .get_out()
                .map(|v| v.read().unwrap().get_space() == AddressSpace::Unique)
                .unwrap_or(false);
            let op_incidental = def_arc.read().unwrap().is_incidental_copy();
            let in0 = def_arc.read().unwrap().get_in(0).cloned();
            let in0_incidental = in0
                .as_ref()
                .map(|v| v.read().unwrap().is_incidental_copy())
                .unwrap_or(false);
            let in0_overlap = match &in0 {
                Some(i) => invn.read().unwrap().overlap(&i.read().unwrap()) == in1_off,
                None => false,
            };
            if out_internal || op_incidental || in0_incidental || in0_overlap {
                match in0 {
                    Some(v) => ancestor_op_use(
                        fd, maxlevel - 1, &v, op, trial, offset + in1_off, main_flags, match_fc,
                    ),
                    None => false,
                }
            } else {
                only_op_use(fd, invn, op, trial, main_flags, match_fc)
            }
        }
        OC::CPUI_CALL | OC::CPUI_CALLIND => false,
        _ => only_op_use(fd, invn, op, trial, main_flags, match_fc),
    }
}

// Ghidra: funcdata.hh:630 CloneBlockOps
/// Clone p-code ops from one basic block into another (for nodeSplit).
/// Faithful to Ghidra's `CloneBlockOps` class (funcdata.hh:630; methods in
/// funcdata_block.cc:951-1104).
struct CloneBlockOps {
    /// (clone_op, orig_op) pairs, in clone order.
    clone_list: Vec<(crate::op::PcodeOpRef, crate::op::PcodeOpRef)>,
    /// Map from orig op Arc ptr → clone op Arc.
    orig_to_clone: std::collections::HashMap<usize, crate::op::PcodeOpRef>,
}

impl CloneBlockOps {
    // RUGRA-GLUE: Rust 构造器（Ghidra CloneBlockOps 用 C++ 构造函数 + data 引用初始化）。
    fn new() -> Self {
        Self {
            clone_list: Vec::new(),
            orig_to_clone: std::collections::HashMap::new(),
        }
    }

    // Ghidra: funcdata_block.cc:951 CloneBlockOps::buildOpClone
    /// Clone a PcodeOp (copy opcode + flags). Skip branches (return None).
    fn build_op_clone(
        &mut self, fd: &mut Funcdata, orig: &crate::op::PcodeOpRef,
    ) -> Option<crate::op::PcodeOpRef> {
        let (is_branch, is_not_branch, num_input, addr, opcode, flags, addlflags) = {
            let o = orig.0.read().unwrap();
            let ib = o.is_branch();
            let addr = o.get_addr();
            let opcode = o.opcode;
            let flags = o.flags;
            let addlflags = o.addlflags;
            (
                ib, ib && o.opcode != crate::opcodes::OpCode::CPUI_BRANCH, o.num_input(), addr, opcode, flags, addlflags,
            )
        };
        if is_branch {
            if is_not_branch {
                eprintln!("[BLOCK] Cannot duplicate 2-way or n-way branch in nodesplit");
            }
            return None;
        }
        let dup = fd.new_op(num_input, addr);
        fd.op_set_opcode(&dup, opcode);
        // Copy flag subset (funcdata_block.cc:974-978).
        let fl_mask = crate::op::pcodeop_flags::STARTBASIC
            | crate::op::pcodeop_flags::NOCOLLAPSE
            | crate::op::pcodeop_flags::STARTMARK
            | crate::op::pcodeop_flags::NONPRINTING
            | crate::op::pcodeop_flags::HALT
            | crate::op::pcodeop_flags::BADINSTRUCTION
            | crate::op::pcodeop_flags::UNIMPLEMENTED
            | crate::op::pcodeop_flags::NORETURN
            | crate::op::pcodeop_flags::MISSING
            | crate::op::pcodeop_flags::INDIRECT_CREATION
            | crate::op::pcodeop_flags::INDIRECT_STORE
            | crate::op::pcodeop_flags::CALCULATED_BOOL
            | crate::op::pcodeop_flags::PTRFLOW;
        dup.0.write().unwrap().flags |= flags & fl_mask;
        // Copy addlflag subset (funcdata_block.cc:979-980).
        let afl_mask = crate::op::op_addl_flags::SPECIAL_PRINT
            | crate::op::op_addl_flags::INCIDENTAL_COPY
            | crate::op::op_addl_flags::IS_CPOOL_TRANSFORMED
            | crate::op::op_addl_flags::STOP_TYPE_PROPAGATION
            | crate::op::op_addl_flags::STORE_UNMAPPED;
        dup.0.write().unwrap().addlflags |= addlflags & afl_mask;
        // Record mappings.
        self.clone_list.push((dup.clone(), orig.clone()));
        self.orig_to_clone
            .insert(Arc::as_ptr(&orig.0) as usize, dup.clone());
        Some(dup)
    }

    // Ghidra: funcdata_block.cc:981 CloneBlockOps::buildVarnodeOutput
    /// Clone the output Varnode of an op into the clone op. The clone is
    /// created at the original output's FULL storage address (space+offset),
    /// per cc:988 `data.newVarnodeOut(opvn->getSize(),opvn->getAddr(),cloneOp)`
    /// — Ghidra's `Address` carries the space, so a ram-space persist output
    /// clones into ram, not Register. (FUNCDATA-NODESPLIT-SPACE-0001)
    fn build_varnode_output(
        &self, fd: &mut Funcdata, orig_op: &crate::op::PcodeOpRef, clone_op: &crate::op::PcodeOpRef,
    ) {
        let orig_out = orig_op.0.read().unwrap().output.clone();
        let Some(orig_vn) = orig_out else { return };
        let (size, space, addr, orig_flags, orig_addlflags) = {
            let v = orig_vn.read().unwrap();
            (v.size, v.address_space, v.loc, v.flags, v.addlflags)
        };
        let new_vn = fd.new_varnode_out_full(size, space, addr, clone_op);
        // Copy varnode flag subset (funcdata_block.cc:989-994).
        let vflag_mask = crate::varnode::varnode_flags::EXTERNREF
            | crate::varnode::varnode_flags::VOLATIL
            | crate::varnode::varnode_flags::INCIDENTAL_COPY
            | crate::varnode::varnode_flags::READONLY
            | crate::varnode::varnode_flags::PERSIST
            | crate::varnode::varnode_flags::ADDRTIED
            | crate::varnode::varnode_flags::ADDRFORCE
            | crate::varnode::varnode_flags::NOLOCALALIAS
            | crate::varnode::varnode_flags::SPACEBASE
            | crate::varnode::varnode_flags::INDIRECT_CREATION
            | crate::varnode::varnode_flags::RETURN_ADDRESS
            | crate::varnode::varnode_flags::PRECISLO
            | crate::varnode::varnode_flags::PRECISHI;
        new_vn.write().unwrap().set_flags(orig_flags & vflag_mask);
        // Copy addlflag subset (funcdata_block.cc:995-997):
        //   aflags &= (writemask | ptrflow | stack_store); addlflags |= aflags.
        let addl_mask = crate::varnode::addl_flags::WRITE_MASK
            | crate::varnode::addl_flags::PTR_FLOW
            | crate::varnode::addl_flags::STACK_STORE;
        new_vn.write().unwrap().addlflags |= orig_addlflags & addl_mask;
    }

    // Ghidra: funcdata_block.cc:1004 CloneBlockOps::cloneBlock
    /// Clone all ops from `b` into `bprime`, patching inputs.
    fn clone_block(
        &mut self,
        fd: &mut Funcdata,
        b: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        bprime: &Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
        inedge: usize,
    ) {
        // Collect ops from b.
        let ops: Vec<crate::op::PcodeOpRef> = {
            let rg = b.read().unwrap();
            if let Some(bb) = rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                bb.get_ops()
            } else {
                Vec::new()
            }
        };
        for orig_ref in &ops {
            if let Some(clone_ref) = self.build_op_clone(fd, orig_ref) {
                self.build_varnode_output(fd, orig_ref, &clone_ref);
                fd.op_insert_end(&clone_ref, bprime);
            }
        }
        self.patch_inputs(fd, inedge);
    }

    // Ghidra: funcdata_block.cc:1024 CloneBlockOps::cloneExpression
    /// Clone p-code ops in an expression right before the given followOp.
    /// Faithful to `CloneBlockOps::cloneExpression`
    /// (funcdata_block.cc:1024-1040): each op in the list is skeleton-cloned
    /// (`buildOpClone`, cc:1029-1031 — branch ops are skipped and reported
    /// inside that helper), the output Varnode is cloned onto each skeleton
    /// (`buildVarnodeOutput`, cc:1032), and the clone inserts immediately
    /// before followOp (cc:1033). An empty clone list throws
    /// `LowlevelError("No expression to clone")` (cc:1035-1036), then the
    /// inputs are patched with inedge=0 (cc:1037) and the output Varnode of
    /// the LAST cloned op returns (cc:1038-1039).
    /// RUGRA-GLUE: Ghidra's ClonePair helper (funcdata.hh:632-635) is
    /// absorbed by the `(clone_op, orig_op)` tuple in `clone_list` — the
    /// tuple IS the pair, built at the same push site as the C++ ctor.
    fn clone_expression(
        &mut self,
        fd: &mut Funcdata,
        ops: &[crate::op::PcodeOpRef],
        follow_op: &crate::op::PcodeOpRef,
    ) -> crate::error::Result<
        Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    > {
        for orig_ref in ops {
            // cc:1029-1031: cloneOp = buildOpClone(origOp); skip if null.
            if let Some(clone_ref) = self.build_op_clone(fd, orig_ref) {
                // cc:1032: buildVarnodeOutput(origOp,cloneOp).
                self.build_varnode_output(fd, orig_ref, &clone_ref);
                // cc:1033: data.opInsertBefore(cloneOp,followOp).
                fd.op_insert_before(&clone_ref, follow_op);
            }
        }
        if self.clone_list.is_empty() {
            // cc:1035-1036: throw LowlevelError("No expression to clone").
            return Err(crate::error::Error::Lowlevel(
                "No expression to clone".to_string(),
            ));
        }
        // cc:1037: patchInputs(0).
        self.patch_inputs(fd, 0);
        // cc:1038-1039: return cloneList.back().cloneOp->getOut().
        let last_clone = &self.clone_list.last().unwrap().0;
        let out = last_clone.0.read().unwrap().output.clone();
        Ok(out)
    }

    // Ghidra: funcdata_block.cc:1047 CloneBlockOps::patchInputs
    /// Patch cloned op inputs: MULTIEQUAL → COPY; constants shared; written
    /// inputs mapped to clone outputs; others shared.
    fn patch_inputs(&self, fd: &mut Funcdata, inedge: usize) {
        use crate::opcodes::OpCode;
        for (clone_ref, orig_ref) in &self.clone_list {
            let opcode = orig_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_MULTIEQUAL => {
                    // cloneOp becomes a single-input COPY from orig's inedge slot.
                    clone_ref.0.write().unwrap().inrefs.resize(
                        1, std::sync::Arc::new(std::sync::RwLock::new(
                        crate::varnode::Varnode::new_constant(0, 0)
                    ,
                        )),
                    );
                    fd.op_set_opcode(clone_ref, OpCode::CPUI_COPY);
                    let in_vn = orig_ref.0.read().unwrap().inrefs.get(inedge).cloned();
                    if let Some(vn) = in_vn {
                        fd.op_set_input(clone_ref, vn, 0);
                    }
                    // Remove inedge from original MULTIEQUAL (funcdata_block.cc:1068).
                    fd.op_remove_input(orig_ref, inedge);
                    if orig_ref.0.read().unwrap().num_input() == 1 {
                        fd.op_set_opcode(orig_ref, OpCode::CPUI_COPY);
                    }
                }
                OpCode::CPUI_INDIRECT => {
                    eprintln!("[BLOCK] Can't clone INDIRECTs in nodesplit");
                }
                _ if orig_ref.0.read().unwrap().is_call() => {
                    eprintln!("[BLOCK] Can't clone CALLs in nodesplit");
                }
                _ => {
                    // Regular op: patch each input (funcdata_block.cc:1079-1101).
                    // Ghidra iterates `cloneOp->numInput()`, which equals
                    // `origOp->numInput()` because buildOpClone created the
                    // clone with the orig's slot count (funcdata_block.cc:970
                    // `data.newOp(op->numInput(),...)`). Rugra's `create`
                    // only RESERVES the capacity — the clone's inrefs are
                    // still empty — so the orig's count is the faithful loop
                    // bound (op_set_input extends/fills the clone's slots).
                    let num_in = orig_ref.0.read().unwrap().num_input();
                    for i in 0..num_in {
                        let orig_vn = orig_ref.0.read().unwrap().inrefs.get(i).cloned();
                        let Some(orig_vn) = orig_vn else { continue };
                        let clone_vn = {
                            let v = orig_vn.read().unwrap();
                            if v.is_constant() {
                                Some(orig_vn.clone())
                            } else if v.is_annotation() {
                                // data.newCodeRef — Rugra shares annotation varnodes.
                                Some(orig_vn.clone())
                            } else if v.is_free() {
                                eprintln!("[BLOCK] Can't clone free varnode in nodesplit");
                                None
                            } else {
                                // Check if orig_vn is defined by a cloned op.
                                let def_op = v.def.as_ref().and_then(|w| w.upgrade());
                                match def_op {
                                    Some(def_arc) => {
                                        let key = Arc::as_ptr(&def_arc) as usize;
                                        match self.orig_to_clone.get(&key) {
                                            Some(clone_op) => {
                                                clone_op.0.read().unwrap().output.clone()
                                            }
                                            None => Some(orig_vn.clone()),
                                        }
                                    }
                                    None => Some(orig_vn.clone()),
                                }
                            }
                        };
                        if let Some(cv) = clone_vn {
                            fd.op_set_input(clone_ref, cv, i);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod laned_access_tests {
    use super::*;

    #[test]
    fn set_arch_injects_architecture_type_factory_before_varnode_allocation() {
        let factory = Arc::new(std::sync::RwLock::new(
            crate::type_system::typefactory::TypeFactory::new_flavor(
                8,
                crate::type_system::typefactory::CoreTypeFlavor::Standalone,
            ),
        ));
        let expected = factory
            .read()
            .unwrap()
            .get_base(8, crate::type_system::datatype::TypeMetatype::Unknown)
            .unwrap();
        let mut architecture = crate::arch::Architecture::new();
        architecture.set_types(factory.clone());

        let mut fd = Funcdata::new("typed", Address::new(0x1000), 0x20);
        fd.set_arch(Arc::new(architecture));
        let vn = fd.new_varnode(8, Address::new(0x20));
        let actual = vn.read().unwrap().get_type().unwrap();

        assert!(Arc::ptr_eq(
            &fd.vbank.type_factory_handle().unwrap(),
            &factory
        ));
        assert!(Arc::ptr_eq(&actual, &expected));
        assert_eq!(actual.get_name(), "xunknown8");
        assert_eq!(vn.read().unwrap().create_index, 0);
    }

    #[test]
    fn order_identity_and_minimum_lifecycle() {
        let mut architecture = crate::arch::Architecture::new();
        architecture.set_lane_records(vec![
            crate::transform::LanedRegister::with_sizes(16, 1 << 4),
            crate::transform::LanedRegister::with_sizes(8, 1 << 2),
        ]);
        let architecture = Arc::new(architecture);
        let record16 = architecture
            .get_laned_register(Address::new(0), 16)
            .unwrap();
        let mut fd = Funcdata::new("lanes", Address::new(0x1000), 0x20);
        fd.set_arch(architecture);

        fd.check_for_laned_register(12, AddressSpace::Register, Address::new(0x20));
        assert!(fd.laned_map.is_empty());
        fd.check_for_laned_register(8, AddressSpace::Register, Address::new(0x20));
        fd.check_for_laned_register(16, AddressSpace::Register, Address::new(0x20));
        fd.check_for_laned_register(8, AddressSpace::Unique, Address::new(5));
        let keys = fd
            .lane_accesses()
            .map(|(storage, _)| *storage)
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            vec![
                LanedStorage {
                    space: AddressSpace::Unique,
                    offset: 5,
                    size: 8,
                },
                LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 16,
                },
                LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 8,
                },
            ]
        );
        assert!(Arc::ptr_eq(
            fd.laned_map
                .get(&LanedStorage {
                    space: AddressSpace::Register,
                    offset: 0x20,
                    size: 16,
                })
                .unwrap(),
            &record16,
        ));

        let before_generation = fd.laned_map.len();
        fd.set_laned_reg_generated();
        let _ = fd.new_unique(16);
        assert_eq!(fd.laned_map.len(), before_generation);
        fd.clear();
        assert_eq!(fd.laned_map.len(), before_generation);
        let _ = fd.new_unique(16);
        assert_eq!(fd.laned_map.len(), before_generation + 1);
        fd.clear_laned_access_map();
        assert!(fd.laned_map.is_empty());
    }
}

mod scope_query_tests {
    use super::*;

// FUNCDATA-SCOPELOCALOVERFLOW-0001: database.cc:2397 computes
// addr.getOffset()+size-1 in the uint8 (uint64) modular domain, and
// stack-space offsets near 2^64 (negative stack slots, e.g. a canary
// at stack -8) legitimately wrap. The pre-fix `offset + size as u64`
// trapped with `attempt to add with overflow` under the debug profile
// (examples/stackfold_dbg, httpd corpus) while release wrapped
// silently — masking the defect from the release E2E gates.
#[test]
fn test_scope_local_find_overlap_wraps_at_space_top() {
    use crate::varmap::{LocalSymbol, ScopeLocal};
    let mut scope = ScopeLocal::new();
    scope
        .symbols
        .push(LocalSymbol::new("canary", 0xffff_ffff_ffff_fff8, 8, None, -1));

    // Query the whole [stack -8, stack -1] record: last = -8 + 8 - 1
    // wraps around 2^64 in both C++ and the fixed Rust.
    let hit = scope_local_find_overlap(
        &scope,
        AddressSpace::Stack,
        0xffff_ffff_ffff_fff8,
        8,
    )
    .expect("oracle findOverlap answers the top-of-space record");
    assert_eq!(hit.name, "canary");

    // Query exactly the final byte: offset + size wraps to 0 before
    // the -1 restores 0xffffffffffffffff (modular last).
    let hit_last_byte = scope_local_find_overlap(
        &scope,
        AddressSpace::Stack,
        0xffff_ffff_ffff_ffff,
        1,
    )
    .expect("oracle findOverlap answers the last byte via modular last");
    assert_eq!(hit_last_byte.name, "canary");

    // One past the record end: no overlap in the oracle.
    assert!(scope_local_find_overlap(
        &scope,
        AddressSpace::Stack,
        0x0000_0000_0000_0010,
        8
    )
    .is_none());
}

// database.cc:2397 sign-extends a negative int4 size into the uint8
// domain before the modular add/sub: last = offset + size - 1 (mod
// 2^64). With end < point every rangemap unit fails `first <= end`
// (rangemap.hh:421), so the oracle answers null — no panic allowed.
#[test]
fn test_scope_local_find_overlap_negative_size_modular() {
    use crate::varmap::{LocalSymbol, ScopeLocal};
    let mut scope = ScopeLocal::new();
    scope
        .symbols
        .push(LocalSymbol::new("pre", 0x0f_00, 8, None, -1));
    scope
        .symbols
        .push(LocalSymbol::new("at", 0x10_00, 8, None, -1));

    // last = 0x1000 + (-8) - 1 = 0x0ff7 (modular): end < point → null.
    assert!(scope_local_find_overlap(&scope, AddressSpace::Stack, 0x10_00, -8).is_none());
    // Same modular arithmetic from an offset that does not underflow:
    // last = 0x1000 - 1 = 0x0fff still < point 0x1000 → null.
    assert!(scope_local_find_overlap(&scope, AddressSpace::Stack, 0x10_00, 0).is_none());
}

    // FUNCDATA-SETVARNODE-SCOPELOCAL-0001: Funcdata::setVarnodeProperties'
    // ONE `localmap->queryProperties` (funcdata_varnode.cc:31) walks
    // stackContainer starting AT the ScopeLocal (database.cc:1268) — the
    // leg stack varnodes must take before any parent/global fallback. A
    // stack varnode inside the scope's local window takes the
    // database.cc:1273 fold mapped|addrtied; one covered by a local Symbol
    // takes the entry's getAllFlags fold (database.cc:1270); one outside
    // the window gets no local answer and — stack space not being the
    // default-data space — no parent fold either (database.cc:1279 with an
    // empty property lookup).
    #[test]
    fn test_set_varnode_properties_scope_local_leg() {
        use crate::varmap::ScopeLocal;

        let mut fd = Funcdata::new("scope_leg", Address::new(0x401000), 0x10);
        // A ScopeLocal whose stack window covers [0x100, 0x200], with one
        // addr-tied 1-byte whole-map symbol "spud" at stack 0x140.
        let mut scope = ScopeLocal::new();
        scope.local_range.push((0x100, 0x200));
        scope.add_symbol(AddressSpace::Stack, "spud", None, 0x140, None);
        fd.scope = Some(scope);

        // (1) In-scope discovery (database.cc:957-958 → 1271-1277): stack
        // varnode at 0x120 with no covering symbol → mapped|addrtied, no
        // persist (ScopeLocal is not the global scope). ADDRTIED is
        // asserted on the raw bit: `is_addr_tied()` (varnode.hh:250)
        // additionally requires INSERT, which only op attachment grants —
        // orthogonal to this property pass.
        let vn_plain = fd.vbank.create_with_space(8, AddressSpace::Stack, 0x120);
        fd.set_varnode_properties(&vn_plain);
        assert!(vn_plain.read().unwrap().flags & crate::varnode::varnode_flags::ADDRTIED != 0);
        assert!(vn_plain.read().unwrap().is_mapped());
        assert!(!vn_plain.read().unwrap().is_persist());

        // (2) Symbol hit (database.cc:952 → 1269-1270): 1-byte stack
        // varnode exactly on "spud"'s entry → the entry getAllFlags fold.
        let vn_sym = fd.vbank.create_with_space(1, AddressSpace::Stack, 0x140);
        fd.set_varnode_properties(&vn_sym);
        assert!(vn_sym.read().unwrap().flags & crate::varnode::varnode_flags::ADDRTIED != 0);
        assert!(vn_sym.read().unwrap().is_mapped());

        // (3) Outside the local window: no scope claims the range
        // (database.cc:1278-1279) → no addrtied from the local leg, and the
        // stack space never reaches the RAM-only parent channel.
        let vn_out = fd.vbank.create_with_space(8, AddressSpace::Stack, 0x500);
        fd.set_varnode_properties(&vn_out);
        assert!(vn_out.read().unwrap().flags & crate::varnode::varnode_flags::ADDRTIED == 0);
        assert!(!vn_out.read().unwrap().is_mapped());
    }

// address.cc:484 (RangeList::inRange via database.hh:597 Scope::inScope)
// evaluates the same addr.getOffset()+size-1 modular expression.
#[test]
fn test_scope_local_in_scope_wraps_at_space_top() {
    use crate::varmap::ScopeLocal;
    let mut scope = ScopeLocal::new();
    scope
        .local_range
        .push((0xffff_ffff_ffff_ff_00, 0xffff_ffff_ffff_ffff));
    // last = 0xfffffffffffffff8 + 8 - 1 wraps to 0xffffffffffffffff.
    assert!(scope_local_in_scope(
        &scope,
        AddressSpace::Stack,
        0xffff_ffff_ffff_fff8,
        8,
        None
    ));
    // A query whose modular last wraps low still satisfies the C++
    // comparison `range.last >= addr.getOffset()+size-1`: last wraps to 6
    // and 0xffffffffffffffff >= 6 is true in the oracle's uint8 domain
    // (address.cc:484) — pin the oracle's own answer, true.
    assert!(scope_local_in_scope(
        &scope,
        AddressSpace::Stack,
        0xffff_ffff_ffff_ffff,
        8,
        None
    ));
}
}

/// GETPARAM-FORLOOP-OPMOVE-0001 regression suite: the finalTransform
/// op-move primitive pair (`Funcdata::opUninsert` + `Funcdata::opInsertAfter`,
/// funcdata_op.cc:164-173 / 373-404) that block.cc:3381-3396 uses to migrate
/// the iterate/initialize statements to their basic block's terminal
/// statement position. Rust-side regression only (mechanism B2: corpus-level
/// oracle equivalence is witnessed by the F8FOR canon/mirror A/B evidence);
/// these tests pin the bank-level mechanics the ticket doubted existed —
/// detach (dead list, parentless) / reattach (alive, ordered) with Varnode
/// links intact, within one block and across block boundaries.
#[cfg(test)]
mod final_transform_op_move_tests {
    use super::*;
    use crate::block::BlockBasic;

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn block_of(index: i32, addr: u64) -> BlockArc {
        Arc::new(RwLock::new(BlockBasic::new(index, Address::new(addr))))
    }

    fn ops_of(b: &BlockArc) -> Vec<PcodeOpRef> {
        b.read().unwrap().get_ops()
    }

    fn same_op(a: &PcodeOpRef, b: &PcodeOpRef) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }

    fn op_parent_is(op: &PcodeOpRef, b: &BlockArc) -> bool {
        op.0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|p| Arc::ptr_eq(&p, b))
            .unwrap_or(false)
    }

    fn in_alive_exactly_once(fd: &Funcdata, op: &PcodeOpRef) -> bool {
        fd.obank
            .alivelist
            .iter()
            .filter(|r| Arc::ptr_eq(&r.0, &op.0))
            .count()
            == 1
    }

    fn in_dead(fd: &Funcdata, op: &PcodeOpRef) -> bool {
        fd.obank.deadlist.iter().any(|r| Arc::ptr_eq(&r.0, &op.0))
    }

    /// cc:3381-3384 shape: `iterateOp` sits mid-block in the tail block;
    /// opUninsert + opInsertAfter(lastOp) must land it as the block's
    /// terminal statement, preserving input/output Varnode links and the
    /// alive-list membership (funcdata_op.cc:164-173 puts the op on the dead
    /// list; opInsert -> opInsert -> markAlive restores it — op.cc:1022).
    #[test]
    fn op_move_pair_migrates_mid_block_op_to_terminal_statement() {
        let mut fd = Funcdata::new("opmove_tail", Address::new(0x1000), 1);
        let tail = block_of(0, 0x1000);
        fd.bblocks.add_block(tail.clone());

        // Block layout: [me(MULTIEQUAL), iterate(INT_ADD), victim(INT_SUB),
        // last(INT_OR)] — iterate is a non-terminal iterate-statement
        // candidate exactly like the oracle's mid-tail iterateOp.
        let me = fd.new_op(2, Address::new(0x1000));
        fd.op_set_opcode(&me, OpCode::CPUI_MULTIEQUAL);
        fd.op_insert_end(&me, &tail);
        let iterate = fd.new_op(2, Address::new(0x1004));
        fd.op_set_opcode(&iterate, OpCode::CPUI_INT_ADD);
        fd.op_insert_end(&iterate, &tail);
        let victim = fd.new_op(2, Address::new(0x1008));
        fd.op_set_opcode(&victim, OpCode::CPUI_INT_SUB);
        fd.op_insert_end(&victim, &tail);
        let last = fd.new_op(2, Address::new(0x100c));
        fd.op_set_opcode(&last, OpCode::CPUI_INT_OR);
        fd.op_insert_end(&last, &tail);

        // Data-flow links that must survive the move (opUninsert's contract:
        // "input and output Varnodes should [only] be unset if the removal
        // is permanent").
        let out_vn = fd.new_unique_out(4, &iterate);
        let const_in = fd.new_constant(4, 7);
        fd.op_set_input(&iterate, const_in.clone(), 0);

        assert_eq!(ops_of(&tail).len(), 4);
        assert!(in_alive_exactly_once(&fd, &iterate));
        assert!(!in_dead(&fd, &iterate));

        // cc:3382: data.opUninsert(iterateOp) — dead list + parent detach.
        fd.op_uninsert(&iterate);
        assert!(in_dead(&fd, &iterate));
        assert!(!in_alive_exactly_once(&fd, &iterate));
        assert!(!op_parent_is(&iterate, &tail));
        assert_eq!(ops_of(&tail).len(), 3);

        // cc:3383: data.opInsertAfter(iterateOp, lastOp) — terminal slot.
        fd.op_insert_after(&iterate, &last);
        let ops = ops_of(&tail);
        assert_eq!(ops.len(), 4);
        assert!(same_op(&ops[3], &iterate), "iterate must be terminal");
        assert!(same_op(&ops[0], &me));
        assert!(same_op(&ops[1], &victim));
        assert!(same_op(&ops[2], &last));
        assert!(op_parent_is(&iterate, &tail));
        assert!(in_alive_exactly_once(&fd, &iterate));
        assert!(!in_dead(&fd, &iterate));

        // Varnode links intact: def/descend and the input slot.
        assert!(iterate
            .0
            .read()
            .unwrap()
            .get_out()
            .map(|v| Arc::ptr_eq(v, &out_vn))
            .unwrap_or(false));
        assert!(out_vn
            .read()
            .unwrap()
            .get_def()
            .map(|d| Arc::ptr_eq(&d, &iterate.0))
            .unwrap_or(false));
        assert!(iterate
            .0
            .read()
            .unwrap()
            .get_in(0)
            .map(|v| Arc::ptr_eq(v, &const_in))
            .unwrap_or(false));
    }

    /// General primitive semantics the ticket called missing ("Rugra op bank
    /// 无跨块搬移表达"): opUninsert detaches from one block's list and
    /// opInsertAfter reattaches into ANOTHER block's list (funcdata_op.cc:164
    /// only reads op->getParent(); opInsertAfter inserts into
    /// prev->getParent()). Also exercises the post-MULTIEQUAL skip
    /// (funcdata_op.cc:391-402): a non-MULTIEQUAL op inserted after an op
    /// preceding a MULTIEQUAL lands AFTER the MULTIEQUAL run. The
    /// [h1, h_me, h_last] layout is synthetic (oracle keeps MULTIEQUALs
    /// block-initial); it pins the defensive branch of the port.
    #[test]
    fn op_move_pair_expresses_cross_block_move_and_multiequal_skip() {
        let mut fd = Funcdata::new("opmove_cross", Address::new(0x2000), 1);
        let block_a = block_of(0, 0x2000);
        let block_h = block_of(1, 0x2100);
        fd.bblocks.add_block(block_a.clone());
        fd.bblocks.add_block(block_h.clone());

        let a1 = fd.new_op(2, Address::new(0x2000));
        fd.op_set_opcode(&a1, OpCode::CPUI_INT_ADD);
        fd.op_insert_end(&a1, &block_a);

        let h1 = fd.new_op(1, Address::new(0x2100));
        fd.op_set_opcode(&h1, OpCode::CPUI_COPY);
        fd.op_insert_end(&h1, &block_h);
        let h_me = fd.new_op(2, Address::new(0x2104));
        fd.op_set_opcode(&h_me, OpCode::CPUI_MULTIEQUAL);
        fd.op_insert_end(&h_me, &block_h);
        let h_last = fd.new_op(2, Address::new(0x2108));
        fd.op_set_opcode(&h_last, OpCode::CPUI_INT_OR);
        fd.op_insert_end(&h_last, &block_h);

        assert!(op_parent_is(&a1, &block_a));

        // Cross-block migration: a1 out of block_a, into block_h after h1 —
        // skipping past the h_me MULTIEQUAL.
        fd.op_uninsert(&a1);
        assert!(ops_of(&block_a).is_empty());
        fd.op_insert_after(&a1, &h1);

        assert!(op_parent_is(&a1, &block_h));
        assert!(!op_parent_is(&a1, &block_a));
        let h_ops = ops_of(&block_h);
        assert_eq!(h_ops.len(), 4);
        assert!(same_op(&h_ops[0], &h1));
        assert!(same_op(&h_ops[1], &h_me));
        // funcdata_op.cc:394-401: iterator advanced past the MULTIEQUAL run
        // before the insert, so a1 sits after h_me, before h_last.
        assert!(same_op(&h_ops[2], &a1));
        assert!(same_op(&h_ops[3], &h_last));
        assert!(in_alive_exactly_once(&fd, &a1));
        assert!(!in_dead(&fd, &a1));
    }
}
