//! Liveness cover for varnodes
//!
//! Corresponds to Ghidra's `cover.hh`

use std::collections::BTreeMap;
use std::fmt;
/// Pointer-identity domain of one `CoverBlock` range boundary.
///
/// Ghidra's `CoverBlock` (cover.hh:75-96) stores its two range boundaries as
/// raw `const PcodeOp *` pointers with three special encodings:
///   - `(PcodeOp*)0` — very beginning of the block (`getUIndex` -> 0)
///   - `(PcodeOp*)1` — very end of the block   (`getUIndex` -> `~0`)
///   - `(PcodeOp*)2` — function-input marker   (`getUIndex` -> 0)
/// plus real PcodeOp pointers. Every set-membership comparison goes through
/// the `getUIndex` projection (cover.cc:29-49), but several methods ALSO
/// discriminate on the raw pointer identity itself:
///   - `empty()` is the pointer-level `start==0 && stop==0` (cover.hh:90-91)
///   - `boundary()` requires `start != (PcodeOp*)0` (cover.cc:137)
///   - `merge()` tests `stop==(PcodeOp*)1` for internal3/internal4
///     (cover.cc:162,165)
///   - the MULTIEQUAL-tip tests in `Cover::addRefPoint`/`addRefRecurse` call
///     `op->code()==CPUI_MULTIEQUAL` on the stored stop pointer
///     (cover.cc:547, 590-591)
/// Rudra models the pointer with this enum; the `getUIndex` projection is
/// cached in the public `CoverBlock::start`/`end` u32 fields.
// Ghidra: cover.hh:76-77 CoverBlock::start / CoverBlock::stop (pointer values)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverEndpoint {
    /// Ghidra `(const PcodeOp *)0`: very beginning of the block. getUIndex -> 0.
    Begin,
    /// Ghidra `(const PcodeOp *)1`: very end of the block. getUIndex -> ~0.
    EndMark,
    /// Ghidra `(const PcodeOp *)2`: function-input marker. getUIndex -> 0.
    InputMark,
    /// A real PcodeOp boundary, stored in the `getUIndex` projection domain:
    /// SeqNum order for ordinary ops, 0 for MULTIEQUAL markers (which
    /// "are considered very beginning", cover.cc:41-43). `multiequal` caches
    /// the marker-op identity Ghidra recovers from the raw pointer via
    /// `op->code()==CPUI_MULTIEQUAL`.
    Op { order: u32, multiequal: bool },
}

impl CoverEndpoint {
    /// The `getUIndex` comparison value of this endpoint.
    // Ghidra: cover.cc:29 CoverBlock::getUIndex
    pub fn u_index(self) -> u32 {
        match self {
            // Ghidra: case 0 -> 0, case 2 -> 0
            CoverEndpoint::Begin | CoverEndpoint::InputMark => 0,
            // Ghidra: case 1 -> ~((uintm)0)
            CoverEndpoint::EndMark => u32::MAX,
            // Ghidra: marker MULTIEQUAL -> 0 (stored), else -> SeqNum order
            CoverEndpoint::Op { order, .. } => order,
        }
    }

    /// Build the endpoint identity of a live PcodeOp, applying the marker
    /// rules of `CoverBlock::getUIndex` (cover.cc:29-49): MULTIEQUALs are
    /// considered very beginning (order collapses to 0, marker identity
    /// kept for the tip tests); INDIRECTs map to the order of the op they
    /// are indirect for, decoded from the Iop-space input(1) constant via
    /// the same `Arc::as_ptr` encoding `Funcdata::get_op_from_const`
    /// reads (OPBANK-0001 contract). This is load-bearing for merge
    /// boundary semantics: a call-guard INDIRECT that both defines a new
    /// global version and reads the previous version (as guard input, or
    /// as the guarded call's parameter-trial read) must put ALL those
    /// endpoints at the guarded call's order so the adjacent cover blocks
    /// only touch (intersect==1, allowed, merge.cc:1571) instead of
    /// overlapping (intersect==2 -> merge.cc:315 "Forced merge caused
    /// intersection").
    // Ghidra: cover.cc:29 CoverBlock::getUIndex
    pub fn from_op(op: &crate::op::PcodeOp) -> Self {
        if op.is_marker() {
            match op.get_opcode() {
                // Ghidra: MULTIEQUALs are considered very beginning
                crate::opcodes::OpCode::CPUI_MULTIEQUAL => {
                    CoverEndpoint::Op { order: 0, multiequal: true }
                }
                // Ghidra: INDIRECTs are considered to be at the location of
                // the op they are indirect for (cover.cc:41-43):
                //   PcodeOp::getOpFromConst(op->getIn(1)->getAddr())
                //     ->getSeqNum().getOrder()
                crate::opcodes::OpCode::CPUI_INDIRECT => {
                    if let Some(guarded_order) = indirect_target_order(op) {
                        CoverEndpoint::Op { order: guarded_order, multiequal: false }
                    } else {
                        // Unresolvable iop input (typed call_spec annotation
                        // or absent): keep the INDIRECT's own SeqNum order.
                        CoverEndpoint::Op {
                            order: op.get_seq_num().get_order(),
                            multiequal: false,
                        }
                    }
                }
                _ => CoverEndpoint::Op {
                    order: op.get_seq_num().get_order(),
                    multiequal: false,
                },
            }
        } else {
            // Ghidra: return op->getSeqNum().getOrder();
            CoverEndpoint::Op {
                order: op.get_seq_num().get_order(),
                multiequal: false,
            }
        }
    }
}

/// Resolve the SeqNum order of the op an INDIRECT marker is guarding,
/// mirroring `PcodeOp::getOpFromConst(op->getIn(1)->getAddr())->getSeqNum()
/// ->getOrder()` (cover.cc:41-43). Rudra's Iop-space constants encode the
/// target PcodeOp with `Arc::as_ptr` — the same legacy OPBANK-0001 encoding
/// `Funcdata::get_op_from_const` decodes; typed `call_spec` annotations are
/// excluded exactly like that function's guard.
// RUDRA-GLUE: pointer-decode helper for the Iop constant without Funcdata
fn indirect_target_order(op: &crate::op::PcodeOp) -> Option<u32> {
    let iop_vn = op.get_in(1)?;
    let (space, offset, typed) = {
        let v = iop_vn.read().ok()?;
        (v.get_space(), v.get_offset() as usize, v.call_spec.is_some())
    };
    if typed || space != crate::space::AddressSpace::Iop || offset == 0 {
        return None;
    }
    let raw = offset as *const std::sync::RwLock<crate::op::PcodeOp>;
    // SAFETY: OPBANK-0001 — the Iop producer encoded `Arc::as_ptr` and the
    // op bank keeps the owner alive for every consumer of the constant.
    let target = unsafe { &*raw };
    let order = target.read().ok()?.get_seq_num().get_order();
    Some(order)
}

/// Range of P-code ops within a single basic block where a varnode is alive
///
/// Corresponds to Ghidra's `CoverBlock` class. The range is interpreted on
/// the `getUIndex` circle: when `end < start` (and the block is not empty)
/// the covered set wraps through the end-of-block sentinel — the two-piece
/// (wrap-around) interval `[start, ~0] ∪ [0, end]` that Ghidra produces via
/// `merge`'s disjoint branch (cover.cc:175-181) and `addRefPoint`'s
/// not-contained `setEnd` (cover.cc:587). Every method below carries the
/// corresponding wrap-around branch of the Ghidra original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverBlock {
    /// Start of liveness — `getUIndex` projection of the Ghidra start
    /// pointer (SeqNum order domain). Kept `pub` for the order-domain
    /// observation layer; always equals `start_id.u_index()`.
    pub start: u32,
    /// End of liveness — `getUIndex` projection of the Ghidra stop pointer.
    /// `end < start` on a non-empty block encodes the two-piece wrap.
    pub end: u32,
    /// Pointer-identity domain of the Ghidra start pointer.
    start_id: CoverEndpoint,
    /// Pointer-identity domain of the Ghidra stop pointer.
    end_id: CoverEndpoint,
}

impl CoverBlock {
    // Ghidra: cover.hh:79 CoverBlock::CoverBlock
    /// Create an empty cover block (Ghidra: `start = 0; stop = 0;`).
    pub fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            start_id: CoverEndpoint::Begin,
            end_id: CoverEndpoint::Begin,
        }
    }

    // Ghidra: cover.hh:83 CoverBlock::clear
    /// Clear the cover block (Ghidra: `start = 0; stop = 0;`).
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    // Ghidra: cover.hh:86 CoverBlock::setBegin
    /// Set the start of liveness (order-domain convenience overload; see
    /// `set_begin_id` for the pointer-identity variant).
    pub fn set_begin(&mut self, s: u32) {
        self.set_begin_id(CoverEndpoint::Op { order: s, multiequal: false });
    }

    /// Reset start of range keeping the raw pointer identity. Faithful to
    /// `CoverBlock::setBegin` (cover.hh:86-87):
    /// `start = begin; if (stop==(const PcodeOp *)0) stop = (const PcodeOp *)1;`
    // Ghidra: cover.hh:86 CoverBlock::setBegin
    pub fn set_begin_id(&mut self, begin: CoverEndpoint) {
        self.start_id = begin;
        self.start = begin.u_index();
        if self.end_id == CoverEndpoint::Begin {
            self.set_end_id(CoverEndpoint::EndMark);
        }
    }

    // Ghidra: cover.hh:88 CoverBlock::setEnd
    /// Set the end of liveness (order-domain convenience overload; see
    /// `set_end_id` for the pointer-identity variant).
    pub fn set_end(&mut self, e: u32) {
        self.set_end_id(CoverEndpoint::Op { order: e, multiequal: false });
    }

    /// Reset end of range keeping the raw pointer identity. Faithful to
    /// `CoverBlock::setEnd` (cover.hh:88): `stop = end;`.
    // Ghidra: cover.hh:88 CoverBlock::setEnd
    pub fn set_end_id(&mut self, end: CoverEndpoint) {
        self.end_id = end;
        self.end = end.u_index();
    }

    /// Get the pointer-identity of the start boundary (Ghidra `getStart`).
    // Ghidra: cover.hh:81 CoverBlock::getStart
    pub fn get_start_id(&self) -> CoverEndpoint {
        self.start_id
    }

    /// Get the pointer-identity of the stop boundary (Ghidra `getStop`).
    // Ghidra: cover.hh:82 CoverBlock::getStop
    pub fn get_stop_id(&self) -> CoverEndpoint {
        self.end_id
    }

    // Ghidra: cover.hh:84 CoverBlock::setAll
    /// Mark the entire block as covered. Faithful to `CoverBlock::setAll`
    /// (cover.hh:84-85): Ghidra sets `start=(PcodeOp*)0` (begin-of-block
    /// sentinel) and `stop=(PcodeOp*)1` (end-of-block sentinel). In Rudra's
    /// u32-order projection, begin-of-block is order 0 and end-of-block is
    /// `u32::MAX` (the `~((uintm)0)` value returned by `getUIndex` for the
    /// sentinel-1 stop).
    pub fn set_all(&mut self) {
        self.start_id = CoverEndpoint::Begin;
        self.start = 0;
        self.end_id = CoverEndpoint::EndMark;
        self.end = u32::MAX;
    }

    // Ghidra: cover.hh:90 CoverBlock::empty
    /// Check if the cover block is empty. Faithful to `CoverBlock::empty`
    /// (cover.hh:90-91): Ghidra's pointer-level test
    /// `start==(PcodeOp*)0 && stop==(PcodeOp*)0`. The order-only predecessor
    /// used `start > end`, which wrongly classified the two-piece wrap
    /// (`ustop < ustart`, cover.cc:90-101) as empty.
    pub fn empty(&self) -> bool {
        self.start_id == CoverEndpoint::Begin && self.end_id == CoverEndpoint::Begin
    }

    // Ghidra: cover.cc:29 CoverBlock::getUIndex
    /// Get the comparison index for a PcodeOp. Faithful to
    /// `CoverBlock::getUIndex` (cover.cc:29-49). PcodeOp objects and
    /// CoverBlock start/stop boundaries have a natural ordering used to tell
    /// if a PcodeOp falls between boundary points and if CoverBlocks
    /// intersect; ordering is determined by comparing the values returned
    /// here.
    ///
    /// Maps the four Ghidra sentinel/boundary encodings to comparable u32:
    ///   - sentinel 0 (begin-of-block)        -> 0
    ///   - sentinel 1 (end-of-block)          -> u32::MAX   (~0)
    ///   - sentinel 2 (function input)        -> 0
    ///   - MULTIEQUAL marker op               -> 0  (very beginning)
    ///   - INDIRECT marker op                 -> order of the op it is indirect
    ///                                            for (decoded via
    ///                                            `PcodeOp::getOpFromConst` on
    ///                                            its iop input)
    ///   - normal op                          -> SeqNum::order
    ///
    /// Rudra's `CoverBlock` stores raw u32 orders directly (rather than
    /// `PcodeOp*` pointers), so the sentinel-to-order translation has already
    /// happened at `set_begin`/`set_end` time. This method is provided as a
    /// bridge so that other modules (Funcdata, merge, varmap) which in Ghidra
    /// call `CoverBlock::getUIndex(op)` can resolve the comparison index for a
    /// live `PcodeOp` without duplicating the marker/sentinel logic.
    pub fn get_u_index(op: &crate::op::PcodeOp) -> u32 {
        // Ghidra: switch(switchval) { case 0: return 0; case 1: return ~0; case 2: return 0; }
        // plus the marker rules; all folded into the endpoint constructor.
        CoverEndpoint::from_op(op).u_index()
    }

    // Ghidra: cover.cc:107 CoverBlock::contain
    /// Check if the cover block contains a specific point. Faithful to
    /// `CoverBlock::contain` (cover.cc:107-120), including the wrap-around
    /// branch: when the block's own range is two-piece (`ustart > ustop`)
    /// the covered set is `[ustart, ~0] ∪ [0, ustop]`, so the point is
    /// contained when `upoint <= ustop || upoint >= ustart`.
    pub fn contain(&self, point: u32) -> bool {
        // Ghidra: if (empty()) return false;
        if self.empty() {
            return false;
        }
        let upoint = point;
        let ustart = self.start;
        let ustop = self.end;
        // Ghidra: if (ustart<=ustop) return ((upoint>=ustart)&&(upoint<=ustop));
        //         return ((upoint<=ustop)||(upoint>=ustart));
        if ustart <= ustop {
            upoint >= ustart && upoint <= ustop
        } else {
            upoint <= ustop || upoint >= ustart
        }
    }

    /// Characterize where a point falls on the cover boundary.
    /// Faithful to `CoverBlock::boundary` (cover.cc:129-142).
    /// Returns:
    // Ghidra: cover.cc:129 CoverBlock::boundary
    ///   - 0 if point not on boundary
    ///   - 1 if on the tail (== stop)
    ///   - 2 if on the defining point (== start, and start is not the
    ///     begin-of-block sentinel — Ghidra's `start!=(const PcodeOp *)0`
    ///     pointer test)
    pub fn boundary(&self, point: u32) -> i32 {
        // Ghidra: if (empty()) return 0;
        if self.empty() {
            return 0;
        }
        let val = point;
        // Ghidra: if (getUIndex(start)==val) { if (start!=(const PcodeOp *)0) return 2; }
        if self.start == val && self.start_id != CoverEndpoint::Begin {
            return 2;
        }
        // Ghidra: if (getUIndex(stop)==val) return 1;
        if self.end == val {
            return 1;
        }
        0
    }

    // Ghidra: cover.cc:147 CoverBlock::merge
    /// Merge another cover block into this one. Faithful to
    /// `CoverBlock::merge` (cover.cc:147-184) including the two-piece
    /// handling: `internal1..4` use pointer-identity discriminators
    /// (`op2.stop==(PcodeOp*)1`, `stop==(PcodeOp*)1`), and the disjoint
    /// branch picks the earliest start together with the *other* interval's
    /// stop, which may legitimately leave `stop < start` (the wrap-around
    /// union on the getUIndex circle).
    pub fn merge(&mut self, other: &CoverBlock) {
        // Ghidra: if (op2.empty()) return; // Nothing to merge in
        if other.empty() {
            return;
        }
        // Ghidra: if (empty()) { start = op2.start; stop = op2.stop; return; }
        if self.empty() {
            self.start_id = other.start_id;
            self.start = other.start;
            self.end_id = other.end_id;
            self.end = other.end;
            return;
        }
        let ustart = self.start;
        let u2start = other.start;
        // Ghidra: internal4 = ((ustart==(uintm)0)&&(op2.stop==(const PcodeOp *)1));
        let internal4 = ustart == 0 && other.end_id == CoverEndpoint::EndMark;
        // Ghidra: internal1 = internal4 || op2.contain(start);
        let internal1 = internal4 || other.contain(ustart);
        // Ghidra: internal3 = ((u2start==0)&&(stop==(const PcodeOp *)1));
        let internal3 = u2start == 0 && self.end_id == CoverEndpoint::EndMark;
        // Ghidra: internal2 = internal3 || contain(op2.start);
        let internal2 = internal3 || self.contain(u2start);

        // Ghidra: if (internal1&&internal2)
        //           if ((ustart!=u2start)|| internal3 || internal4) {
        //             setAll(); return;
        //           }
        if internal1 && internal2 && (ustart != u2start || internal3 || internal4) {
            // Covered entire block
            self.set_all();
            return;
        }
        // Ghidra: if (internal1) start = op2.start; // Pick non-internal start
        if internal1 {
            self.start_id = other.start_id;
            self.start = other.start;
        } else if !internal2 {
            // Ghidra: else if ((!internal1)&&(!internal2)) { // Disjoint intervals
            //           if (ustart < u2start) stop = op2.stop; // Pick earliest start
            //           else start = op2.start;                // then take other stop
            //           return;
            //         }
            if ustart < u2start {
                self.end_id = other.end_id;
                self.end = other.end;
            } else {
                self.start_id = other.start_id;
                self.start = other.start;
            }
            return;
        }
        // Ghidra: if (internal3 || op2.contain(stop)) stop = op2.stop; // Pick non-internal stop
        if internal3 || other.contain(self.end) {
            self.end_id = other.end_id;
            self.end = other.end;
        }
    }

    // Ghidra: cover.cc:59 CoverBlock::intersect
    /// Characterize the intersection with another CoverBlock (non-destructive).
    /// Faithful to `CoverBlock::intersect` (cover.cc:59-102) across all four
    /// one-piece/two-piece quadrants. Returns:
    ///   - 0 no intersection
    ///   - 1 only boundary points intersect
    ///   - 2 a whole interval intersects
    pub fn intersect_char(&self, op2: &CoverBlock) -> i32 {
        if self.empty() || op2.empty() {
            return 0;
        }
        let ustart = self.start;
        let ustop = self.end;
        let u2start = op2.start;
        let u2stop = op2.end;
        if ustart <= ustop {
            if u2start <= u2stop {
                // Ghidra: both one-piece (cover.cc:73-79)
                if ustop <= u2start || u2stop <= ustart {
                    if ustart == u2stop || ustop == u2start {
                        return 1; // Boundary intersection
                    }
                    return 0; // No intersection
                }
            } else {
                // Ghidra: they are two-piece, we are one-piece (cover.cc:81-87):
                // we intersect only inside their complement gap (u2stop, u2start)
                if ustart >= u2stop && ustop <= u2start {
                    if ustart == u2stop || ustop == u2start {
                        return 1;
                    }
                    return 0;
                }
            }
        } else if u2start <= u2stop {
            // Ghidra: they are one piece, we are two-piece (cover.cc:91-97)
            if u2start >= ustop && u2stop <= ustart {
                if u2start == ustop || u2stop == ustart {
                    return 1;
                }
                return 0;
            }
        }
        // Ghidra: if both are two-pieces, then the intersection must be an
        // interval (cover.cc:99) — falls through to the interval result.
        2 // Interval intersection
    }

    // Ghidra: cover.cc:59 CoverBlock::intersect
    /// Intersect another cover block with this one
    // RUDRA-GLUE: Rust-side destructive set-intersection helper; Ghidra's
    // `CoverBlock::intersect` is the const characterization above and has no
    // mutating form. Defined for one-piece operands only; two-piece inputs
    /// are outside this helper's contract (no production caller passes them).
    pub fn intersect(&mut self, other: &CoverBlock) {
        if other.start > self.start {
            self.start = other.start;
            self.start_id = other.start_id;
        }
        if other.end < self.end {
            self.end = other.end;
            self.end_id = other.end_id;
        }
        if self.start > self.end {
            self.clear();
        }
    }
}

/// Write-side map surface the rebuild core needs from a block-index →
/// CoverBlock table. Two instantiations share the exact same algorithm:
/// the persistent `BTreeMap<i32, CoverBlock>` (Ghidra's
/// `map<int4,CoverBlock>`, cover.hh:109 — used by the cold entry points)
/// and the transient dense `RebuildScratch` used by `Cover::rebuild`
/// (see its doc comment for the equivalence argument).
// RUDRA-GLUE: table abstraction for the dense rebuild scratch (Ghidra has
// a single map form; the scratch is a pure representation flip with
/// identical key/value semantics).
trait CoverWriteTable {
    /// `cover[idx]` with `map::operator[]` default-insert semantics
    /// (cover.hh:109 + cover.cc:530/573's `cover[bl->getIndex()]`).
    // RUDRA-GLUE: table abstraction for the two map representations
    // (Ghidra has one map form; operator[] is inline at each site).
    fn entry_or_default(&mut self, idx: i32) -> &mut CoverBlock;
    /// `cover.clear()` (cover.hh:113, called from addDefPoint cover.cc:506).
    // RUDRA-GLUE: table abstraction (Ghidra calls map::clear inline).
    fn clear_table(&mut self);
}

impl CoverWriteTable for BTreeMap<i32, CoverBlock> {
    // RUDRA-GLUE: persistent-map arm — literal map::operator[]/map::clear.
    #[inline]
    fn entry_or_default(&mut self, idx: i32) -> &mut CoverBlock {
        self.entry(idx).or_insert_with(CoverBlock::new)
    }
    // RUDRA-GLUE: persistent-map arm of cover.clear().
    #[inline]
    fn clear_table(&mut self) {
        self.clear();
    }
}

/// Transient dense rebuild table for `Cover::rebuild` — the block-index
/// structure flip for the addRefRecurse expansion hot path.
///
/// `Cover::rebuild` (cover.cc:477-496) clears the map and re-inserts every
/// touched block through `cover[bl->getIndex()]` (cover.cc:530/573): on the
/// VdbeExec corpus that is 26.25M map touches per run, 91% of them read
/// hits on an average of ~46 live entries (probe evidence: rc_new 2.34M /
/// rc_hit 23.9M / rb_len avg 46.3). A `BTreeMap` lookup costs ~20ns there
/// versus the oracle's L1-resident RB-tree find (~6ns); a dense slot table
/// makes the same operator[] a bounds check plus an Option test.
///
/// Equivalence to the oracle's single map:
/// 1. **Same key/value semantics**: `entry_or_default` inserts an empty
///    `CoverBlock` for every touched index (operator[] default-constructs,
///    cover.hh:79) — `Some(slot)` after the rebuild is exactly the set of
///    keys the oracle map would hold, empty-present entries included (they
///    are observable through `print`/`compareTo`'s first key, cover.cc:233/
///    620-624, so presence is tracked exactly, not approximated by
///    `CoverBlock::empty`).
/// 2. **Copy-out**: at rebuild end every `Some` slot is moved into the
///    persistent `BTreeMap` in ascending index order — the identical final
///    map state the pre-flip code produced, so every read API (contain,
///    intersect*, merge, compareTo, Display) observes byte-identical data.
/// 3. **Lifetime**: the scratch is thread-local and reused across rebuilds
///    (29,683 dirty rebuilds on the corpus); `clear_table` resets slots
///    in place, keeping capacity. No state crosses a rebuild — the cover's
///    authoritative storage is still its own `BTreeMap`.
///
/// Negative indices never occur for bank-registered blocks (indices are
/// assigned at graph build), but `decode_header`/reverse-post-order windows
/// store -1 transiently (block.cc:1023-1030); those land in the `neg` side
/// map so no reachable input can panic or over-resize the dense vector.
// RUDRA-GLUE: dense transient table (Ghidra rebuilds its map in place; the
// flip is a Rust-side representation change with identical semantics).
struct RebuildScratch {
    slots: Vec<Option<CoverBlock>>,
    neg: BTreeMap<i32, CoverBlock>,
    /// True when every slot is known `None` — set by the copy-out walk
    /// (which `take()`s each entry), consumed by `clear_table` to skip the
    /// reset walk. Only set after a completed copy-out, so a rebuild that
    /// panicked midway leaves the flag false and the next `clear_table`
    /// still walks (fail-safe).
    slots_clean: bool,
}

impl RebuildScratch {
    // RUDRA-GLUE: scratch constructor (no Ghidra counterpart — the
    // oracle's map plays both roles).
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            neg: BTreeMap::new(),
            slots_clean: true,
        }
    }

    /// Copy every present entry into `out` in ascending index order,
    /// leaving the slot vector all-`None` (tracked via `slots_clean`).
    // RUDRA-GLUE: copy-out step (no Ghidra counterpart — the oracle
    /// builds its one map in place; this bridges scratch → persistent).
    fn copy_out(&mut self, out: &mut BTreeMap<i32, CoverBlock>) {
        out.clear();
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if let Some(cb) = slot.take() {
                out.insert(i as i32, cb);
            }
        }
        self.slots_clean = true;
        for (&k, cb) in self.neg.iter() {
            out.insert(k, cb.clone());
        }
    }
}

impl CoverWriteTable for RebuildScratch {
    // RUDRA-GLUE: dense-table arm of operator[] (bounds check + Option
    // slot insert replaces the RB-tree walk).
    #[inline]
    fn entry_or_default(&mut self, idx: i32) -> &mut CoverBlock {
        if idx < 0 {
            return self.neg.entry(idx).or_insert_with(CoverBlock::new);
        }
        let i = idx as usize;
        if i >= self.slots.len() {
            self.slots.resize(i + 1, None);
        }
        self.slots[i].get_or_insert_with(CoverBlock::new)
    }
    // RUDRA-GLUE: dense-table arm of cover.clear() — reset walk skipped
    // when the copy-out already left every slot None (slots_clean).
    fn clear_table(&mut self) {
        if !self.slots_clean {
            for slot in self.slots.iter_mut() {
                *slot = None;
            }
        }
        self.slots_clean = false;
        self.neg.clear();
    }
}

thread_local! {
    /// One dense rebuild scratch per decompile thread; see `RebuildScratch`.
    // RUDRA-GLUE: thread-local scratch reuse across rebuilds
    static REBUILD_SCRATCH: std::cell::RefCell<RebuildScratch> =
        std::cell::RefCell::new(RebuildScratch::new());
}

/// Full liveness cover of a varnode across multiple blocks
///
/// Corresponds to Ghidra's `Cover` class
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cover {
    /// Mapping from basic block index to the cover block for that block
    pub blocks: BTreeMap<i32, CoverBlock>,
}

impl Cover {
    // Ghidra: cover.hh:36 Cover::new
    /// Create a new empty cover
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }

    // Ghidra: cover.hh:36 Cover::clear
    /// Clear the cover
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    // Ghidra: cover.cc:253 Cover::getCoverBlock
    /// Return a representative CoverBlock describing how much of the given
    /// block is covered by this. Faithful to `Cover::getCoverBlock`
    /// (cover.cc:253-260): returns a reference to the CoverBlock for block
    /// `i`, or the global empty block if this cover does not touch block `i`.
    /// Rudra returns `Option<&CoverBlock>` rather than a reference to a global
    /// empty singleton; callers that need the Ghidra (empty-block) behavior
    /// should `.copied().unwrap_or_else(CoverBlock::new)`.
    pub fn get_cover_block(&self, i: i32) -> Option<&CoverBlock> {
        self.blocks.get(&i)
    }

    // Ghidra: cover.cc:223 Cover::compareTo
    /// Compare this Cover with another by comparing just the indices of the
    /// first blocks respectively that are partly covered. Faithful to
    /// `Cover::compareTo` (cover.cc:223-247). Returns -1, 0, or 1 if this
    /// Cover's first block has a smaller, equal, or bigger index than the
    /// other Cover's first block. An empty Cover compares as if its first
    /// block index were 1000000 (Ghidra's sentinel), so any non-empty Cover
    /// orders before an empty one.
    pub fn compare_to(&self, op2: &Cover) -> i32 {
        // Ghidra: if (iter==cover.end()) a = 1000000; else a = (*iter).first;
        // BTreeMap iteration is sorted, so .keys().next() is the minimum key.
        let a = self.blocks.keys().next().copied().unwrap_or(1000000);
        let b = op2.blocks.keys().next().copied().unwrap_or(1000000);
        if a < b {
            -1
        } else if a == b {
            0
        } else {
            1
        }
    }

    // Ghidra: cover.cc:501 Cover::addDefPoint
    /// Add a definition point to the cover. Order-domain convenience entry
    /// mirroring the def branch of `Cover::addDefPoint` (cover.cc:501-519):
    /// `block.setBegin(def); block.setEnd(def);` — the block is set to the
    /// single defining point.
    pub fn add_def_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        cb.set_begin(point);
        cb.set_end(point);
    }

    // Ghidra: cover.cc:565 Cover::addRefPoint
    /// Add a reference point to the cover. Order-domain convenience entry
    /// mirroring the endpoint update of `Cover::addRefPoint`
    /// (cover.cc:565-612) without its CFG recursion (this entry has no
    /// block-graph access): on an empty block `setEnd(ref)` leaves the
    /// begin sentinel as start; otherwise a not-contained ref extends the
    /// stop, which may wrap (`stop < start`, two-piece).
    pub fn add_ref_point(&mut self, block_idx: i32, point: u32) {
        let cb = self.blocks.entry(block_idx).or_insert_with(CoverBlock::new);
        if cb.empty() || !cb.contain(point) {
            cb.set_end(point);
        }
    }

    // Ghidra: cover.cc:413 Cover::contain
    /// Check if the cover contains a point within a block
    pub fn contain(&self, block_idx: i32, point: u32) -> bool {
        if let Some(cb) = self.blocks.get(&block_idx) {
            cb.contain(point)
        } else {
            false
        }
    }

    // Ghidra: cover.cc:441 Cover::containVarnodeDef
    /// Characterize where a Varnode's definition point falls relative to
    /// this cover. Faithful to `Cover::containVarnodeDef` (cover.cc:441-462).
    ///
    /// `is_input`: if true, the varnode has no defining op (it's a function
    /// input) — Ghidra uses op=(PcodeOp*)2 sentinel, blk=0.
    /// `block_idx`/`order`: the defining op's block and order (when not input).
    ///
    /// Returns:
    ///   - 0 = not contained (or block absent)
    ///   - 1 = contained, strictly internal (boundary==0)
    ///   - 2 = contained, on the defining-point boundary (boundary==2)
    ///   - 3 = contained, on the tail boundary (boundary==1)
    pub fn contain_varnode_def_at(&self, is_input: bool, block_idx: i32, order: u32) -> i32 {
        // Ghidra: if (op==0) { op=(PcodeOp*)2; blk=0; } else blk = op->getParent()->getIndex();
        // The (PcodeOp*)2 sentinel flows into contain/boundary, which compare
        // via getUIndex — mapping it to 0 (cover.cc:29-49). Match that
        // semantic value here so it agrees with add_def_point_full's stored
        // input endpoints.
        let (blk, point) = if is_input {
            (0i32, 0u32) // input marker: block 0, uindex-domain order 0
        } else {
            (block_idx, order)
        };
        let Some(cb) = self.blocks.get(&blk) else {
            return 0;
        };
        if cb.contain(point) {
            let boundtype = cb.boundary(point);
            match boundtype {
                0 => 1,
                2 => 2,
                _ => 3, // boundary==1 (tail)
            }
        } else {
            0
        }
    }

    // Ghidra: cover.cc:465 Cover::merge
    /// Merge another cover into this one
    pub fn merge(&mut self, other: &Cover) {
        for (idx, other_cb) in &other.blocks {
            let cb = self.blocks.entry(*idx).or_insert_with(CoverBlock::new);
            cb.merge(other_cb);
        }
    }

    // Ghidra: cover.cc:269 Cover::intersect
    /// Intersect another cover with this one
    pub fn intersect(&mut self, other: &Cover) {
        let mut keys_to_remove = Vec::new();
        for (idx, cb) in &mut self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                cb.intersect(other_cb);
                if cb.empty() {
                    keys_to_remove.push(*idx);
                }
            } else {
                keys_to_remove.push(*idx);
            }
        }
        for idx in keys_to_remove {
            self.blocks.remove(&idx);
        }
    }

    // Ghidra: cover.hh:36 Cover::intersects
    /// Non-mutating predicate: true iff this cover and `other` share at least
    /// one live point (boundary contact counts). Used by cover-based merging
    /// to decide whether two HighVariables are simultaneously live (and thus
    /// cannot share a name). Implemented on the two-piece-aware
    /// `CoverBlock::intersect_char` characterization.
    pub fn intersects(&self, other: &Cover) -> bool {
        for (idx, cb) in &self.blocks {
            if let Some(other_cb) = other.blocks.get(idx) {
                if cb.intersect_char(other_cb) != 0 {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: cover.cc:269 Cover::intersect
    /// Characterize the intersection with another Cover (non-destructive).
    /// Faithful to `Cover::intersect` (cover.cc:269-297). Returns:
    ///   - 0 no intersection
    ///   - 1 only boundary points intersect
    ///   - 2 a whole interval intersects
    pub fn intersect_char(&self, op2: &Cover) -> i32 {
        let mut res = 0i32;
        // Iterate both block maps in sorted order (BTreeMap iteration is sorted).
        let mut iter = self.blocks.iter();
        let mut iter2 = op2.blocks.iter();
        let mut cur = iter.next();
        let mut cur2 = iter2.next();
        loop {
            let (Some((k1, _)), Some((k2, _))) = (&cur, &cur2) else {
                return res;
            };
            if *k1 < *k2 {
                cur = iter.next();
            } else if *k1 > *k2 {
                cur2 = iter2.next();
            } else {
                // Same block in both covers.
                let newres = cur.unwrap().1.intersect_char(cur2.unwrap().1);
                if newres == 2 {
                    return 2;
                }
                if newres == 1 {
                    res = 1;
                }
                cur = iter.next();
                cur2 = iter2.next();
            }
        }
    }

    // Ghidra: cover.hh:36 Cover::intersectsExceptAt
    /// Like `intersects`, but ignores overlap at one specific point. Used by
    /// copy-merge: the COPY op itself reads the input and writes the output,
    /// so their covers always overlap at that single op — that overlap is the
    /// merge point itself and must not block merging. Any OTHER overlap means
    /// the two HighVariables are simultaneously live elsewhere and must not
    /// merge.
    pub fn intersects_except_at(
        &self,
        other: &Cover,
        exclude_block: i32,
        exclude_order: u32,
    ) -> bool {
        for (idx, cb) in &self.blocks {
            let Some(other_cb) = other.blocks.get(idx) else {
                continue;
            };
            let lo = std::cmp::max(cb.start, other_cb.start);
            let hi = std::cmp::min(cb.end, other_cb.end);
            if lo > hi {
                continue;
            }
            if *idx == exclude_block && lo <= exclude_order && exclude_order <= hi {
                // The overlap range includes the excluded point. If the range
                // contains any OTHER point, that's a real overlap.
                if hi > lo {
                    return true;
                }
                // Range is exactly {exclude_order} — no real overlap, continue.
            } else {
                return true;
            }
        }
        false
    }

    // Ghidra: cover.cc:307 Cover::intersectList
    /// Generate the list of blocks where this and `op2` intersect at or above
    /// the given characterization `level`. Faithful to
    /// `Cover::intersectList` (cover.cc:307-334). Iterates both block maps in
    /// sorted order (BTreeMap gives this for free) and, for each common block,
    /// appends its index to `listout` if `CoverBlock::intersect` returns a
    /// value >= `level`. Clears `listout` first, matching Ghidra.
    ///
    /// `level`: 1 = any intersection (boundary or interval), 2 = interval only.
    pub fn intersect_list(&self, op2: &Cover, level: i32) -> Vec<i32> {
        // Ghidra: listout.clear();
        let mut listout = Vec::new();
        let mut iter = self.blocks.iter();
        let mut iter2 = op2.blocks.iter();
        let mut cur = iter.next();
        let mut cur2 = iter2.next();
        loop {
            let (Some((k1, _)), Some((k2, _))) = (&cur, &cur2) else {
                break;
            };
            if *k1 < *k2 {
                cur = iter.next();
            } else if *k1 > *k2 {
                cur2 = iter2.next();
            } else {
                // Same block in both covers.
                // Ghidra: val = (*iter).second.intersect((*iter2).second);
                let val = cur.unwrap().1.intersect_char(cur2.unwrap().1);
                if val >= level {
                    listout.push(**k1);
                }
                cur = iter.next();
                cur2 = iter2.next();
            }
        }
        listout
    }

    // Ghidra: cover.cc:392 Cover::intersectByBlock
    /// Looking only at the given block, return:
    ///   - 0 if there is no intersection
    ///   - 1 if the only intersection is on a boundary point
    ///   - 2 if the intersection contains a range of p-code ops
    /// Faithful to `Cover::intersectByBlock` (cover.cc:392-406).
    pub fn intersect_by_block(&self, blk: i32, op2: &Cover) -> i32 {
        // Ghidra: iter = cover.find(blk); if (iter == cover.end()) return 0;
        let Some(cb1) = self.blocks.get(&blk) else {
            return 0;
        };
        let Some(cb2) = op2.blocks.get(&blk) else {
            return 0;
        };
        // Ghidra: return (*iter).second.intersect((*iter2).second);
        cb1.intersect_char(cb2)
    }

    /// Resolve the basic-block index of a PcodeOp via its `parent` weak ref.
    /// Returns None if the op has no parent (not yet inserted into a block).
    /// Used by `rebuild`/`add_ref_point_full` to bridge PcodeOp -> block index
    /// for the order-based cover API. (Ghidra inlines this as
    /// `op->getParent()->getIndex()`.)
    // RUDRA-GLUE: Rust ownership adapter; Ghidra keeps a PcodeOp pointer and
    // calls op->getParent()->getIndex() inline, so it has no standalone helper.
    fn block_index_of_op(op: &crate::op::PcodeOp) -> Option<i32> {
        let parent = op.parent.as_ref()?.upgrade()?;
        let idx = parent.read().unwrap().get_index();
        Some(idx)
    }

    // Ghidra: cover.cc:501 Cover::addDefPoint (op-based variant)
    /// Reset this Cover to the single point where `vn` is defined. Faithful
    /// to `Cover::addDefPoint` (cover.cc:501-519). Clears the cover first.
    /// `def` is the original Varnode's defining op. If it is absent and
    /// `is_input` is true, the input-varnode convention is block 0/order 2.
    pub(crate) fn add_def_point_full(
        &mut self,
        def: Option<&std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        is_input: bool,
    ) {
        Self::add_def_point_tbl(def, is_input, &mut self.blocks);
    }

    /// Table-generic core of `Cover::addDefPoint` (cover.cc:501-519): the
    /// same algorithm on either the persistent map or the dense rebuild
    /// scratch (`CoverWriteTable`).
    // RUDRA-GLUE: table-generic core for the dense rebuild scratch flip
    fn add_def_point_tbl<T: CoverWriteTable>(
        def: Option<&std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        is_input: bool,
        tbl: &mut T,
    ) {
        // Ghidra: cover.clear();
        tbl.clear_table();
        if let Some(def) = def {
            let def_rg = def.read().unwrap();
            // Ghidra: def->getParent()->getIndex()
            let blk = Self::block_index_of_op(&def_rg).unwrap_or(0);
            // Ghidra: CoverBlock &block(cover[blk]); block.setBegin(def); block.setEnd(def);
            // The endpoint keeps the full pointer identity: a MULTIEQUAL def
            // stores order 0 with its marker identity (getUIndex, cover.cc:41-43).
            let endpoint = CoverEndpoint::from_op(&def_rg);
            let cb = tbl.entry_or_default(blk);
            cb.set_begin_id(endpoint);
            cb.set_end_id(endpoint);
        } else if is_input {
            // Ghidra: CoverBlock &block(cover[0]);
            //         block.setBegin((const PcodeOp*)2); block.setEnd((const PcodeOp*)2);
            // The pointer sentinel 2 is the input marker; every set-membership
            // comparison goes through CoverBlock::getUIndex, which maps it to
            // 0 (cover.cc:29-49), but boundary/merge discriminate the raw
            // pointer identity, so the InputMark identity is kept.
            let cb = tbl.entry_or_default(0);
            cb.set_begin_id(CoverEndpoint::InputMark);
            cb.set_end_id(CoverEndpoint::InputMark);
        }
    }

    // Ghidra: cover.cc:565 Cover::addRefPoint (op-based variant)
    /// Add the read point `op` to this Cover, then recursively fill the cover
    /// backward through the control-flow predecessors of `op`'s block until
    /// existing cover is reached. Faithful to `Cover::addRefPoint`
    /// (cover.cc:565-612).
    ///
    /// `root` is the original Varnode passed to `rebuild`, even when `op` is a
    /// descendant of an implied output. It selects every exact-identity
    /// MULTIEQUAL input slot whose predecessor branch must be traversed.
    pub(crate) fn add_ref_point_full(
        &mut self,
        op_arc: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        scratch_roots: &mut Vec<crate::arena::BlockId>,
        scratch_stack: &mut Vec<(crate::arena::BlockId, i32)>,
    ) {
        Self::add_ref_point_tbl(op_arc, root, scratch_roots, scratch_stack, &mut self.blocks);
    }

    /// Table-generic core of `Cover::addRefPoint` (cover.cc:565-612): the
    /// same algorithm on either the persistent map or the dense rebuild
    /// scratch (`CoverWriteTable`). Only the target table differs — the
    /// guard sequence, endpoint bookkeeping and root selection are
    /// verbatim the persistent-map body.
    // RUDRA-GLUE: table-generic core for the dense rebuild scratch flip
    fn add_ref_point_tbl<T: CoverWriteTable>(
        op_arc: &std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        scratch_roots: &mut Vec<crate::arena::BlockId>,
        scratch_stack: &mut Vec<(crate::arena::BlockId, i32)>,
        tbl: &mut T,
    ) {
        let (order, endpoint, opcode, op_parent, matching_slots) = {
            let op = op_arc.read().unwrap();
            let opcode = op.get_opcode();
            let matching_slots = if opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                op.inrefs
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, input)| std::sync::Arc::ptr_eq(input, root).then_some(slot))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let endpoint = CoverEndpoint::from_op(&op);
            (
                endpoint.u_index(),
                endpoint,
                opcode,
                op.parent.as_ref().and_then(|parent| parent.upgrade()),
                matching_slots,
            )
        };
        let Some(bl_arc) = op_parent else { return };
        // One read guard fetches both the block index and the owning bank
        // (Ghidra inlines these as raw pointer derefs:
        // `ref->getParent()->getIndex()` and the `getIn` edge walk below).
        let (op_blk, bank) = {
            let rg = bl_arc.read().unwrap();
            (rg.get_index(), rg.bank())
        };

        // Ghidra: FlowBlock *bl = ref->getParent();
        //         CoverBlock &block(cover[bl->getIndex()]);
        // Single map access with map::operator[] semantics (default-insert
        // on absent key): the pre-insert emptiness classification the
        // recursive original reads off `cover[idx]` is identical whether
        // taken before the entry or on the freshly returned reference,
        // because nothing mutates the entry in between.
        let cb = tbl.entry_or_default(op_blk);
        let block_was_empty = cb.empty();

        if block_was_empty {
            // Ghidra: block.setEnd(ref);
            // The untouched start pointer remains the begin-of-block
            // sentinel (cover.hh:79 default), preserved in start_id.
            cb.set_end_id(endpoint);
        } else {
            // Ghidra: if (block.contain(ref)) { if (ref->code()!=MULTIEQUAL) return; }
            if cb.contain(order) {
                if opcode != crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                    return;
                }
                // Even if contained, a MULTIEQUAL may add new cover via a
                // different branch — fall through to the recurse step below.
            } else {
                // Ghidra: const PcodeOp *op = block.getStop();
                //         const PcodeOp *startop = block.getStart();
                //         block.setEnd(ref);
                //         ustop = CoverBlock::getUIndex(block.getStop());
                let old_stop = cb.get_stop_id();
                let startop = cb.get_start_id();
                cb.set_end_id(endpoint);
                let ustop = cb.end;
                // Ghidra: if (ustop >= CoverBlock::getUIndex(startop)) {
                //           if ((op!=0)&&(op!=2)&&(op->code()==CPUI_MULTIEQUAL)&&
                //               (startop==(const PcodeOp*)0)) { ...recurse... }
                //           return;
                //         }
                if ustop >= startop.u_index() {
                    // Infinitesimal MULTIEQUAL tip: the OLD stop was a
                    // MULTIEQUAL with startop at the block-begin sentinel —
                    // the block contains only a tip of cover through one
                    // branch of a MULTIEQUAL, so traverse through the other
                    // branches too (cover.cc:590-597).
                    if startop == CoverEndpoint::Begin
                        && matches!(
                            old_stop,
                            CoverEndpoint::Op {
                                multiequal: true,
                                ..
                            }
                        )
                    {
                        // Tip recursion (cover.cc:590-597): predecessor ids
                        // collected under one read guard, then expanded.
                        let mut roots = std::mem::take(scratch_roots);
                        roots.clear();
                        {
                            let rg = bl_arc.read().unwrap();
                            Self::collect_predecessor_ids(&rg, &mut roots);
                        }
                        Self::expand_roots_tbl(&bank, &mut roots, scratch_stack, tbl);
                        *scratch_roots = roots;
                    }
                    return;
                }
                // ustop < ustart: the new stop sits before the start on the
                // getUIndex circle — the block is now a two-piece wrap-around
                // range [start, ~0] ∪ [0, stop]. Ghidra does NOT return here;
                // it falls through to the bottom recursion so the reading
                // point's predecessors still get filled backward
                // (cover.cc:584-599).
            }
        }

        // Ghidra: if (ref->code() == CPUI_MULTIEQUAL) {
        //           for(j=0;j<ref->numInput();++j)
        //             if (ref->getIn(j)==vn) addRefRecurse(bl->getIn(j));
        //         } else for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
        let mut roots = std::mem::take(scratch_roots);
        roots.clear();
        if opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
            // Snapshot every exact-identity slot's predecessor id in ascending
            // order while the block is locked, then expand without carrying
            // the block guard into the recursion.
            {
                let rg = bl_arc.read().unwrap();
                for slot in matching_slots {
                    if let Some(edge) = rg.get_in_ref(slot) {
                        roots.push(edge.point);
                    }
                }
            }
        } else {
            {
                let rg = bl_arc.read().unwrap();
                Self::collect_predecessor_ids(&rg, &mut roots);
            }
        }
        Self::expand_roots_tbl(&bank, &mut roots, scratch_stack, tbl);
        *scratch_roots = roots;
    }

    /// Collect the predecessor block ids of `bl` (its in-edges' `point`
    /// targets) in ascending in-edge slot order. Mirrors Ghidra's
    /// `bl->getIn(j)` loop used by `Cover::addRefPoint`/`addRefRecurse`.
    /// Ids are `Copy`, so no handles are cloned out of the guard.
    // RUDRA-GLUE: Rust lock-release snapshot helper; Ghidra walks FlowBlock
    // incoming raw pointers inline in Cover::addRefPoint/addRefRecurse.
    fn collect_predecessor_ids(
        rg: &std::sync::RwLockReadGuard<'_, dyn crate::block::FlowBlock + Send + Sync>,
        out: &mut Vec<crate::arena::BlockId>,
    ) {
        let n = rg.size_in();
        for slot in 0..n {
            if let Some(edge) = rg.get_in_ref(slot) {
                out.push(edge.point);
            }
        }
    }

    /// Worklist half of `Cover::rebuild` (cover.cc:477-496): breadth-first
    /// walk over implied outputs, contributing one addRefPoint per reading
    /// op into `scratch` (the dense rebuild table). Extracted unchanged
    /// from the pre-flip rebuild body — only the addRefPoint target table
    /// is a parameter.
    // RUDRA-GLUE: worklist extraction for the dense rebuild scratch flip
    fn rebuild_worklist(
        &self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        root_descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        root_is_implied: bool,
        scratch: &mut RebuildScratch,
    ) {
        let mut path = Vec::new();
        let mut pos = 0usize;
        // Termination guard mirroring Ghidra's cover-based recursion bound:
        // Cover::addRefPoint/addRefRecurse (cover.cc:549-612) only extend
        // EMPTY or uncovered regions — a second visit to an already-covered
        // block returns without recursing, so implied-varnode chains can
        // never cycle. Rudra's explicit worklist has no such containment
        // signal, so an explicit visited set on the implied outputs is the
        // equivalent cycle bound (without it, mutually-reading implied
        // varnodes X->Y->X loop forever).
        let mut visited: rustc_hash::FxHashSet<usize> = rustc_hash::FxHashSet::default();
        let mut descendants = root_descendants.clone();
        // Scratch buffers reused across every addRefPoint of this rebuild:
        // predecessor-id roots and the expansion stack. Cleared (capacity
        // kept) per closure; contents never survive a call.
        let mut scratch_roots: Vec<crate::arena::BlockId> = Vec::new();
        let mut scratch_stack: Vec<(crate::arena::BlockId, i32)> = Vec::new();
        loop {
            for op_arc in descendants {
                // The original root, not `current`, is the addRefPoint identity.
                Self::add_ref_point_tbl(
                    &op_arc,
                    root,
                    &mut scratch_roots,
                    &mut scratch_stack,
                    scratch,
                );
                let output = op_arc.read().unwrap().get_out().cloned();
                if let Some(output) = output {
                    let is_implied = if std::sync::Arc::ptr_eq(&output, root) {
                        root_is_implied
                    } else {
                        output.read().unwrap().is_implied()
                    };
                    if is_implied {
                        let key = std::sync::Arc::as_ptr(&output) as usize;
                        if visited.insert(key) {
                            path.push(output);
                        }
                    }
                }
            }
            if pos >= path.len() {
                break;
            }
            let current = path[pos].clone();
            pos += 1;
            descendants = if std::sync::Arc::ptr_eq(&current, root) {
                root_descendants.clone()
            } else {
                let current_value = current.read().unwrap();
                current_value.descend_iter().collect::<Vec<_>>()
            };
        }
    }

    // Ghidra: cover.cc:477 Cover::rebuild
    /// Reset this Cover based on the def-use chain of a single Varnode.
    /// Faithful to `Cover::rebuild` (cover.cc:477-496). The cover is set to
    /// all p-code ops between the point where `vn` is defined and all the
    /// points where it is read. Implied outputs of reading ops are followed
    /// transitively (they are invisible in the final source, so their reads
    /// extend the cover of the originating Varnode).
    ///
    /// Walks the def-use chain breadth-first via a worklist (Ghidra's
    /// `vector<const Varnode *> path`), starting at `vn`. For each Varnode:
    ///   1. addDefPoint is called once for the root (this clears the cover and
    ///      plants the definition).
    ///   2. every descendant (reading) op contributes an addRefPoint.
    ///   3. if a reading op's output is non-null and implied, the output is
    ///      pushed onto the worklist so ITS readers also extend the cover.
    ///
    /// Because Rudra's internal cover stores `(block_idx, u32 order)` pairs,
    /// this entry point resolves each PcodeOp's block index and SeqNum order
    /// and delegates to the order-based `add_def_point`/`add_ref_point_full`.
    pub fn rebuild(
        &mut self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        let (definition, is_input, descendants, root_is_implied) = {
            let root_value = root.read().unwrap();
            (
                root_value.get_def(),
                root_value.is_input(),
                root_value.descend_iter().collect::<Vec<_>>(),
                root_value.is_implied(),
            )
        };
        self.rebuild_from_root_snapshot(
            root,
            definition,
            is_input,
            descendants,
            root_is_implied,
        );
    }

    // RUDRA-GLUE: lock-release adapter for Cover::rebuild; Ghidra's raw
    // Varnode pointer needs no snapshot when updateCover is called through a
    // mutable Rust RwLock guard.

    pub(crate) fn rebuild_from_root_snapshot(
        &mut self,
        root: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        definition: Option<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        is_input: bool,
        root_descendants: Vec<std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>>,
        root_is_implied: bool,
    ) {
        // The rebuild runs on the thread-local dense scratch table and
        // copies out into this Cover's persistent map at the end — the
        // block-index structure flip for the hot addRefRecurse expansion
        // (see RebuildScratch for the equivalence argument). Final map
        // state (keys, values, presence) is identical to building the map
        // directly.
        REBUILD_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            // Ghidra: vector<const Varnode *> path(1,vn); int4 pos = 0;
            // Ghidra: addDefPoint(vn);
            Self::add_def_point_tbl(definition.as_ref(), is_input, &mut *scratch);
            self.rebuild_worklist(root, root_descendants, root_is_implied, &mut scratch);
            // Copy-out: every Some slot (the exact operator[]-touched key
            // set, empty-present entries included) moves into the persistent
            // BTreeMap in ascending index order. The oracle map state after
            // rebuild is reproduced exactly.
            scratch.copy_out(&mut self.blocks);
        });
    }

    // Ghidra: cover.cc:524 Cover::addRefRecurse
    /// Fill in this Cover recursively from the given block backward until we
    /// run into existing cover. Faithful to `Cover::addRefRecurse`
    /// (cover.cc:524-558). If `bl` has no cover yet, mark the whole block
    /// covered (setAll) and recurse into every in-edge predecessor. If `bl`
    /// already has cover, extend its tail to the block bottom, and — when the
    /// existing cover is only an infinitesimal MULTIEQUAL tip (start==0,
    /// stop==0, defined by a MULTIEQUAL) — recurse through the in-edges so
    /// the other branches still get filled.
    pub fn add_ref_recurse(
        &mut self,
        bl: &std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
    ) {
        let (id, bank) = {
            let rg = bl.read().unwrap();
            (rg.bank_slot(), rg.bank())
        };
        let mut roots = vec![id];
        let mut stack = Vec::new();
        self.expand_roots(&bank, &mut roots, &mut stack);
    }

    // Ghidra: cover.cc:524 Cover::addRefRecurse
    /// Iterative single-stack expansion of `Cover::addRefRecurse`
    /// (cover.cc:524-558) over one addRefPoint/addRefRecurse root set —
    /// semantically identical to the oracle's literal per-in-edge recursion.
    /// Three equivalence pillars:
    ///
    /// 1. **Visit order**: roots are pushed in reverse so the pop order is
    ///    ascending root order, each predecessor's whole subtree finishes
    ///    before its siblings, and per-frame predecessors are pushed in
    ///    reverse slot order — the exact DFS preorder of the oracle's
    ///    `for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j))`
    ///    (cover.cc:535-536/551-552) applied to each root in ascending
    ///    order (the caller's for-j loop, cover.cc:595-611).
    /// 2. **Re-entry idempotence** (replaces the former per-closure visited
    ///    set): each frame mutates only its own block's CoverBlock entry,
    ///    and every MUTATING visit leaves `end == u32::MAX` (`setAll` →
    ///    stop sentinel 1, or the fill-to-bottom `setEnd((const PcodeOp *)1)`;
    ///    both map to ~0 via getUIndex, cover.cc:29-49), while the remaining
    ///    visits mutate nothing at all (two-piece wrap guard
    ///    `ustop < ustart`, or ustop already ~0). Hence a second entry into
    ///    an already-entered block fails both guards — `ustop != ~0` and
    ///    `ustop == 0` cannot hold simultaneously — so it can neither mutate
    ///    the map nor schedule further recursion: processing it again is the
    ///    oracle's own literal behavior (its recursion has no dedup either)
    ///    and is unobservable in the final Cover.
    /// 3. **Frame identity**: blocks travel as bank `BlockId`s (Copy), the
    ///    index resolves through the bank view's generation-checked shadow
    ///    (same value as `FlowBlock::getIndex`), and the block handle is
    ///    materialized only for frames that actually read in-edges.
    ///    No mutation can intervene inside one expansion closure (the
    ///    single-threaded-per-Funcdata premise of `update_cover_locked`),
    ///    so ids stay resolvable and the view's epoch check cannot fire.
    // RUDRA-GLUE: explicit id-stack worklist replaces the oracle's literal
    // recursion: giant-function CFG cones make the no-op re-entry frames
    // (DAG edge multiplicity) the dominant cost, and the id form keeps a
    // re-entry at one atomic index read plus one map lookup.
    fn expand_roots(
        &mut self,
        bank: &crate::block::BlockBank,
        roots: &mut Vec<crate::arena::BlockId>,
        stack: &mut Vec<(crate::arena::BlockId, i32)>,
    ) {
        Self::expand_roots_tbl(bank, roots, stack, &mut self.blocks);
    }

    /// Table-generic core of the iterative `addRefRecurse` expansion — the
    /// same single-stack DFS on either the persistent map or the dense
    /// rebuild scratch (`CoverWriteTable`). The hot per-frame map touch
    /// (`cover[bl->getIndex()]`, cover.cc:530) becomes a direct slot index
    /// on the scratch instantiation.
    // RUDRA-GLUE: table-generic core for the dense rebuild scratch flip
    fn expand_roots_tbl<T: CoverWriteTable>(
        bank: &crate::block::BlockBank,
        roots: &mut Vec<crate::arena::BlockId>,
        stack: &mut Vec<(crate::arena::BlockId, i32)>,
        tbl: &mut T,
    ) {
        let view = bank.hold();
        stack.clear();
        // Frames carry (id, index) pairs: the index is resolved ONCE at
        // push time through the bank shadow — the identical value
        // `bl->getIndex()` reads through the block guard — so a popped
        // frame needs no per-pop resolution. The no-publish premise below
        // (pillar 3) makes push-time and pop-time reads equal.
        for id in roots.iter().rev() {
            stack.push((*id, view.expect_index(*id)));
        }
        while let Some((id, bl_index)) = stack.pop() {
            // Ghidra: CoverBlock &block(cover[bl->getIndex()]);
            // operator[] default-constructs; entry().or_insert mirrors.
            let cb = tbl.entry_or_default(bl_index);

            if cb.empty() {
                // Ghidra: block.setAll();  // No cover encountered, fill in entire block
                cb.set_all();
                // Ghidra: for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
                // Reverse push keeps the pop order == ascending-slot DFS
                // preorder of the oracle recursion.
                push_predecessor_ids(&view, id, stack);
                continue;
            }

            // Ghidra: const PcodeOp *op = block.getStop();   (before setEnd)
            //         ustart = CoverBlock::getUIndex(block.getStart());
            //         ustop  = CoverBlock::getUIndex(op);
            let old_stop = cb.get_stop_id();
            let ustart = cb.start;
            let ustop = cb.end;
            // Ghidra: if ((ustop != ~((uintm)0))&&( ustop >= ustart))
            //           block.setEnd((const PcodeOp *)1); // Fill in to the bottom
            // A two-piece block (ustop < ustart) is deliberately left untouched:
            // its wrap-around range already reaches the block bottom.
            if ustop != u32::MAX && ustop >= ustart {
                cb.set_end_id(CoverEndpoint::EndMark);
            }

            // Ghidra: if ((ustop==(uintm)0)&&(block.getStart() == (const PcodeOp *)0)) {
            //           if ((op != (const PcodeOp *)0)&&(op->code()==CPUI_MULTIEQUAL)) {
            //             for(j=0;j<bl->sizeIn();++j) addRefRecurse(bl->getIn(j));
            //           }
            //         }
            // This block contains only an infinitesimal tip of cover through one
            // branch of a MULTIEQUAL; traverse through the other branches too.
            // start_id is the raw-pointer begin-sentinel test; old_stop carries
            // the MULTIEQUAL marker identity of the stored stop op.
            if ustop == 0 && cb.get_start_id() == CoverEndpoint::Begin {
                if matches!(
                    old_stop,
                    CoverEndpoint::Op {
                        multiequal: true,
                        ..
                    }
                ) {
                    push_predecessor_ids(&view, id, stack);
                }
            }
        }
    }
}

// RUDRA-GLUE: stack-push form of the predecessor walk for the iterative
// addRefRecurse expansion (Ghidra's `bl->getIn(j)` loop, cover.cc:535-536):
// pushes each in-edge's bank id (Copy) onto `stack` in DESCENDING slot
// order under ONE edge-table lock — the identical BlockId sequence the
// oracle's `bl->getIn(j)` pointers denote, without any handle clones,
// guard round-trips, or vtable dispatch per edge (wave 3: the in-vector
// mirror serves block.hh:304's non-virtual inline read form).
fn push_predecessor_ids(
    view: &crate::block::BlockBankView,
    id: crate::arena::BlockId,
    stack: &mut Vec<(crate::arena::BlockId, i32)>,
) {
    view.with_in_edges(id, |ins| {
        for edge in ins.iter().rev() {
            // Index resolved once at push (see expand_roots_tbl).
            stack.push((edge.point, view.expect_index(edge.point)));
        }
    });
}

impl fmt::Display for CoverBlock {
    // Ghidra: cover.cc:188 CoverBlock::print
    // RUDRA-GLUE: Ghidra prints the raw SeqNum of a real-op endpoint; the
    // projection model only keeps the order, so real ops print their decimal
    // order. Sentinel classification (begin/end) matches print's branches.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ep = |id: CoverEndpoint| -> String {
            match id {
                CoverEndpoint::Begin => "begin".to_string(),
                CoverEndpoint::EndMark => "end".to_string(),
                CoverEndpoint::InputMark => "begin".to_string(),
                CoverEndpoint::Op { order, multiequal } => {
                    if multiequal {
                        format!("{}(me)", order)
                    } else {
                        order.to_string()
                    }
                }
            }
        };
        if self.empty() {
            write!(f, "empty")
        } else {
            write!(f, "{}-{}", ep(self.start_id), ep(self.end_id))
        }
    }
}

impl fmt::Display for Cover {
    // Ghidra: cover.hh:36 Cover::fmt
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (i, (idx, cb)) in self.blocks.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "{}: {}", idx, cb)?;
        }
        write!(f, "}}")
    }
}

/// Alias for the owned PcodeOp reference type used throughout Rudra.
/// (Ghidra stores raw `PcodeOp*` in `opList`; Rudra stores the strong Arc.)
type OpArc = std::sync::Arc<std::sync::RwLock<crate::op::PcodeOp>>;

/// A set of PcodeOps that can be tested for Cover intersections.
///
/// Faithful to Ghidra's `class PcodeOpSet` (cover.hh:35-65). This is a set of
/// PcodeOp objects designed for quick intersection tests with a Cover. The set
/// is lazily constructed via its `populate()` method at the time the first
/// intersection test is needed. Once an intersection has been established
/// between a PcodeOp in this set and a Varnode Cover, `affects_test()` can do
/// secondary testing to determine if the intersection should prevent merging.
///
/// Ghidra models this as an abstract base class with two pure-virtual methods
/// (`populate`, `affectsTest`) and protected storage (`opList`, `blockStart`,
/// `is_pop`). Rudra splits it into:
///   - `PcodeOpSetImpl`: the trait subclass owners implement (populate +
///     affects_test), mirroring the virtual methods.
///   - `PcodeOpSet`: the owning struct that holds the shared storage and a
///     `Box<dyn PcodeOpSetImpl>` for the subclass logic. Interior mutability
///     (RwLock on the storage) lets `populate` (a `&self` trait method,
///     matching Ghidra's `void populate()` const-correctness on the base)
///     mutate the shared lists.
pub struct PcodeOpSet {
    /// Ops in this set, sorted on block index, then SeqNum::order.
    /// (Ghidra `vector<PcodeOp*> opList`.)
    op_list: std::sync::RwLock<Vec<OpArc>>,
    /// Index in `op_list` of the first op of each non-empty block.
    /// (Ghidra `vector<int4> blockStart`.)
    block_start: std::sync::RwLock<Vec<i32>>,
    /// Has the `populate` method been called? (Ghidra `bool is_pop`.)
    is_pop: std::sync::atomic::AtomicBool,
    /// Subclass: provides the lazy population and the secondary affects test.
    /// (Ghidra virtual dispatch.)
    owner: Box<dyn PcodeOpSetImpl>,
}

/// Subclass interface for `PcodeOpSet`. Faithful to the two pure-virtual
/// methods of Ghidra's `PcodeOpSet` (cover.hh:52,61).
pub trait PcodeOpSetImpl: std::fmt::Debug {
    /// Populate the PcodeOp object set. The override calls `add_op` for each
    /// PcodeOp it wants to add, then `finalize` to make the set ready for
    /// intersection tests. Faithful to `PcodeOpSet::populate` (cover.hh:52,
    /// pure-virtual). Receives `&mut PcodeOpSet` so it can call the protected
    /// `add_op`/`finalize` helpers.
    // Ghidra: cover.hh:52 PcodeOpSet::populate
    fn populate(&self, set: &mut PcodeOpSet);

    /// Secondary test that the given PcodeOp affects the Varnode. Called after
    /// an intersection of a PcodeOp in this set with a Varnode Cover has been
    /// determined. Allows the owner to make a final determination if merging
    /// should be prevented. Faithful to `PcodeOpSet::affectsTest`
    /// (cover.hh:61, pure-virtual). Returns true if merging should be
    /// prevented.
    // Ghidra: cover.hh:61 PcodeOpSet::affectsTest
    fn affects_test(
        &self,
        op: &crate::op::PcodeOp,
        vn: &crate::varnode::Varnode,
    ) -> bool;
}

impl std::fmt::Debug for PcodeOpSet {
    // RUDRA-GLUE: Rust Debug-trait implementation; Ghidra has no corresponding
    // PcodeOpSet debug formatter (Cover::print is a different API).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.op_list.read().unwrap().len();
        f.debug_struct("PcodeOpSet")
            .field("is_pop", &self.is_pop.load(std::sync::atomic::Ordering::Relaxed))
            .field("num_ops", &n)
            .field("owner", &self.owner)
            .finish()
    }
}

impl PcodeOpSet {
    // Ghidra: cover.hh:44 PcodeOpSet::PcodeOpSet
    /// Construct an empty PcodeOpSet with the given subclass owner.
    /// (Ghidra ctor: `PcodeOpSet(void) { is_pop = false; }`.)
    pub fn new(owner: Box<dyn PcodeOpSetImpl>) -> Self {
        Self {
            op_list: std::sync::RwLock::new(Vec::new()),
            block_start: std::sync::RwLock::new(Vec::new()),
            is_pop: std::sync::atomic::AtomicBool::new(false),
            owner,
        }
    }

    // Ghidra: cover.hh:41 PcodeOpSet::addOp
    /// Add a PcodeOp into the set. Faithful to `PcodeOpSet::addOp`
    /// (cover.hh:41, inline protected): `opList.push_back(op)`.
    pub fn add_op(&self, op: OpArc) {
        self.op_list.write().unwrap().push(op);
    }

    // Ghidra: cover.hh:45 PcodeOpSet::isPopulated
    /// Return true if this set is populated. Faithful to
    /// `PcodeOpSet::isPopulated` (cover.hh:45, inline).
    pub fn is_populated(&self) -> bool {
        self.is_pop.load(std::sync::atomic::Ordering::Relaxed)
    }

    // Ghidra: cover.hh:63 PcodeOpSet::clear
    /// Clear all PcodeOps in this. Faithful to `PcodeOpSet::clear`
    /// (cover.hh:63, inline):
    ///   `is_pop = false; opList.clear(); blockStart.clear();`
    pub fn clear(&self) {
        self.is_pop.store(false, std::sync::atomic::Ordering::Relaxed);
        self.op_list.write().unwrap().clear();
        self.block_start.write().unwrap().clear();
    }

    // Ghidra: cover.hh:52 PcodeOpSet::populate (dispatch)
    /// Lazily populate this set if not already populated. Faithful to the
    /// Ghidra call-site discipline: callers test `isPopulated()` then invoke
    /// the (virtual) `populate()`. Here the dispatch is to the boxed owner.
    pub fn populate(&mut self) {
        if !self.is_populated() {
            // Dispatch to the subclass, passing ourself so it can call
            // add_op/finalize. We temporarily move the owner out to avoid a
            // double-&mut borrow of self.
            let owner = std::mem::replace(&mut self.owner, Box::new(NoOpOwner));
            owner.populate(self);
            self.owner = owner;
        }
    }

    // Ghidra: cover.hh:61 PcodeOpSet::affectsTest (dispatch)
    /// Secondary affects test. Faithful to the virtual `affectsTest`.
    pub fn affects_test(
        &self,
        op: &crate::op::PcodeOp,
        vn: &crate::varnode::Varnode,
    ) -> bool {
        self.owner.affects_test(op, vn)
    }

    // Ghidra: cover.cc:627 PcodeOpSet::finalize
    /// Sort ops in the set into blocks. Faithful to `PcodeOpSet::finalize`
    /// (cover.cc:627-640): sorts `opList` with `compareByBlock`, then builds
    /// `blockStart` — the index of the first op of each new (strictly larger)
    /// block index. Sets `is_pop = true`.
    pub fn finalize(&self) {
        // Ghidra: sort(opList.begin(),opList.end(),compareByBlock);
        {
            let mut list = self.op_list.write().unwrap();
            // Stable sort isn't required (SeqNum orders ties), but Rust's
            // sort_by is stable which is harmless here.
            list.sort_by(|a, b| {
                // compareByBlock: block index first, then SeqNum order.
                let a_rg = a.read().unwrap();
                let b_rg = b.read().unwrap();
                let a_blk = Cover::block_index_of_op(&a_rg).unwrap_or(-1);
                let b_blk = Cover::block_index_of_op(&b_rg).unwrap_or(-1);
                match a_blk.cmp(&b_blk) {
                    std::cmp::Ordering::Equal => {
                        a_rg.get_seq_num().get_order().cmp(&b_rg.get_seq_num().get_order())
                    }
                    ord => ord,
                }
            });
        }
        // Ghidra: int4 blockNum = -1; for(i=0;i<opList.size();++i) {
        //           newBlockNum = opList[i]->getParent()->getIndex();
        //           if (newBlockNum > blockNum) { blockStart.push_back(i); blockNum = newBlockNum; }
        //         }
        let list = self.op_list.read().unwrap();
        let mut starts = self.block_start.write().unwrap();
        starts.clear();
        let mut block_num: i32 = -1;
        for (i, op) in list.iter().enumerate() {
            let op_rg = op.read().unwrap();
            let new_block_num = Cover::block_index_of_op(&op_rg).unwrap_or(block_num);
            if new_block_num > block_num {
                starts.push(i as i32);
                block_num = new_block_num;
            }
        }
        // Ghidra: is_pop = true;
        self.is_pop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    // Ghidra: cover.cc:646 PcodeOpSet::compareByBlock
    /// Compare PcodeOps for this set. Faithful to
    /// `PcodeOpSet::compareByBlock` (cover.cc:646-652): compare first by index
    /// of the containing basic blocks, then by SeqNum ordering within the
    /// block. Returns true if `a` should be ordered before `b`.
    pub fn compare_by_block(
        a: &crate::op::PcodeOp,
        b: &crate::op::PcodeOp,
    ) -> bool {
        // Ghidra: if (a->getParent() != b->getParent())
        //           return (a->getParent()->getIndex() < b->getParent()->getIndex());
        let a_blk = Cover::block_index_of_op(a).unwrap_or(-1);
        let b_blk = Cover::block_index_of_op(b).unwrap_or(-1);
        if a_blk != b_blk {
            return a_blk < b_blk;
        }
        // Ghidra: return a->getSeqNum().getOrder() < b->getSeqNum().getOrder();
        a.get_seq_num().get_order() < b.get_seq_num().get_order()
    }

    /// Number of ops currently in the set. (Ghidra uses `opList.size()`;
    /// Rudra exposes this as a method since `op_list` is private.)
    // RUDRA-GLUE: Rust visibility adapter for private RwLock storage; Ghidra
    // accesses PcodeOpSet::opList directly and has no getNumOps method.
    pub fn get_num_ops(&self) -> usize {
        self.op_list.read().unwrap().len()
    }

    /// Get the i-th op in the sorted set. (Ghidra indexes `opList[i]`
    /// directly; Rudra exposes a method since `op_list` is private.)
    // RUDRA-GLUE: Rust visibility/ownership adapter returning an Arc clone;
    // Ghidra indexes the protected opList vector directly.
    pub fn get_op(&self, i: usize) -> Option<OpArc> {
        self.op_list.read().unwrap().get(i).cloned()
    }

    /// Read-only access to the op list snapshot. Used by `Cover::intersect`
    /// (cover.cc:342) to walk the set.
    // RUDRA-GLUE: Rust lock-release snapshot for private RwLock storage;
    // Ghidra's friend Cover reads PcodeOpSet::opList directly.
    pub fn op_list_snapshot(&self) -> Vec<OpArc> {
        self.op_list.read().unwrap().clone()
    }

    /// Read-only access to the block-start index snapshot. Used by
    /// `Cover::intersect` (cover.cc:342) to delimit ops per block.
    // RUDRA-GLUE: Rust lock-release snapshot for private RwLock storage;
    // Ghidra's friend Cover reads PcodeOpSet::blockStart directly.
    pub fn block_start_snapshot(&self) -> Vec<i32> {
        self.block_start.read().unwrap().clone()
    }
}

/// Placeholder owner used only to temporarily satisfy the borrow checker while
/// the real owner is dispatched into `populate`. Never observed by callers.
#[derive(Debug, Default)]
struct NoOpOwner;

impl PcodeOpSetImpl for NoOpOwner {
    // RUDRA-GLUE: Borrow-checker placeholder used only during mem::replace;
    // Ghidra virtual dispatch never installs a temporary owner object.
    fn populate(&self, _set: &mut PcodeOpSet) {}
    // RUDRA-GLUE: Borrow-checker placeholder used only during mem::replace;
    // Ghidra virtual dispatch never invokes a temporary affectsTest method.
    fn affects_test(&self, _op: &crate::op::PcodeOp, _vn: &crate::varnode::Varnode) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_block_basic() {
        let mut cb = CoverBlock::new();
        assert!(cb.empty());

        cb.set_begin(10);
        cb.set_end(20);
        assert!(!cb.empty());
        assert!(cb.contain(15));
        assert!(!cb.contain(5));
        assert!(!cb.contain(25));
    }

    #[test]
    fn test_cover_merge() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 10);
        c1.add_ref_point(1, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 15);
        c2.add_ref_point(1, 25);
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        c1.merge(&c2);
        assert_eq!(c1.blocks.get(&1).unwrap().start, 10);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 25);
        assert_eq!(c1.blocks.get(&2).unwrap().start, 5);
        assert_eq!(c1.blocks.get(&2).unwrap().end, 10);
    }

    /// Disjoint-block covers must not intersect: the canonical safe-merge case.
    #[test]
    fn test_intersect_disjoint_blocks() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 5);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(2, 5);
        c2.add_ref_point(2, 10);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.is_empty(), "disjoint-block covers must not intersect");
    }

    /// Same-block non-overlapping ranges must yield empty intersection.
    #[test]
    fn test_intersect_disjoint_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 5);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        match tmp.blocks.get(&1) {
            None => {}
            Some(cb) => {
                assert!(cb.empty(), "disjoint same-block covers must yield empty CoverBlock, got {:?}", cb);
            }
        }
    }

    /// Overlapping same-block ranges must produce the tightened [max_start, min_end].
    #[test]
    fn test_intersect_overlapping_same_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 15);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        let cb = tmp.blocks.get(&1).expect("overlapping same-block covers must keep the block");
        assert!(!cb.empty(), "expected non-empty intersection, got {:?}", cb);
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 15);
    }

    /// Multi-block intersect keeps overlapping blocks (narrowed) and drops disjoint ones.
    #[test]
    fn test_intersect_partial_multi_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 20);
        c1.add_def_point(2, 1);
        c1.add_ref_point(2, 20);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 30);

        let mut tmp = c1.clone();
        tmp.intersect(&c2);
        assert!(tmp.blocks.contains_key(&1), "overlapping block must survive intersect");
        assert!(!tmp.blocks.contains_key(&2), "non-overlapping block must be dropped");
        let cb = tmp.blocks.get(&1).unwrap();
        assert_eq!(cb.start, 10);
        assert_eq!(cb.end, 20);
    }

    /// `intersects` is a non-mutating predicate; it must not alter either cover.
    #[test]
    fn test_intersects_predicate() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 10);

        let mut c2 = Cover::new();
        c2.add_def_point(1, 20);
        c2.add_ref_point(1, 30);

        let mut c3 = Cover::new();
        c3.add_def_point(1, 5);
        c3.add_ref_point(1, 15);

        assert!(!c1.intersects(&c2), "disjoint covers must not intersect");
        assert!(c1.intersects(&c3), "overlapping covers must intersect");

        assert_eq!(c1.blocks.get(&1).unwrap().start, 1);
        assert_eq!(c1.blocks.get(&1).unwrap().end, 10);
    }

    /// `set_all` must mark the whole block as covered (begin..end-of-block).
    /// Mirrors Ghidra `CoverBlock::setAll` (cover.hh:84): start=0 (begin),
    /// stop=u32::MAX (~0, the end-of-block sentinel returned by getUIndex).
    #[test]
    fn test_cover_block_set_all() {
        let mut cb = CoverBlock::new();
        assert!(cb.empty());
        cb.set_all();
        assert!(!cb.empty(), "set_all must produce a non-empty block");
        assert_eq!(cb.start, 0, "set_all start must be begin-of-block (0)");
        assert_eq!(cb.end, u32::MAX, "set_all end must be end-of-block (~0)");
        // Whole block covered: contains 0, mid-range, and u32::MAX.
        assert!(cb.contain(0));
        assert!(cb.contain(100));
        assert!(cb.contain(u32::MAX));
    }

    /// MARKIMPLIED2 (PERF-COVER-REBUILD-DENSE-0001): the dense
    /// `RebuildScratch` arm of `CoverWriteTable` must be observationally
    /// identical to the persistent `BTreeMap` arm — the equivalence the
    /// rebuild hot-path flip relies on. Same key/value/presence set after
    /// `copy_out`, empty-present entries included (observable through
    /// print/compareTo first key, cover.cc:620-624), negative-index side
    /// table merged and cleared between rebuilds.
    #[test]
    fn test_cover_write_table_arm_equivalence() {
        // The op sequence a rebuild performs: clear, default-insert +
        // mutate a spread of indices — including a key that is only
        // touched (default-constructed, never mutated = empty-present)
        // and a re-touched key (the 91% read-hit path).
        fn drive<T: CoverWriteTable>(tbl: &mut T) {
            tbl.clear_table();
            tbl.entry_or_default(0).set_all();
            tbl.entry_or_default(3).set_begin(7);
            tbl.entry_or_default(3).set_end(9);
            let _ = tbl.entry_or_default(5); // touched, never mutated
            tbl.entry_or_default(9).set_begin(4);
            tbl.entry_or_default(9).set_end(6);
            tbl.entry_or_default(9).set_end(11); // re-touch (read hit)
        }

        // Persistent arm: operator[]/clear on the BTreeMap directly.
        let mut map_arm: BTreeMap<i32, CoverBlock> = BTreeMap::new();
        drive(&mut map_arm);

        // Dense arm: identical sequence on the scratch, then copy_out.
        let mut scratch = RebuildScratch::new();
        drive(&mut scratch);
        let mut dense_out: BTreeMap<i32, CoverBlock> = BTreeMap::new();
        scratch.copy_out(&mut dense_out);

        // Identical final map: same key set (empty-present key 5 included),
        // same values, ascending iteration order on both sides.
        assert_eq!(map_arm, dense_out);
        assert!(
            dense_out.contains_key(&5),
            "empty-present key must survive copy_out"
        );
        assert_eq!(dense_out.get(&3).map(|cb| (cb.start, cb.end)), Some((7, 9)));
        assert_eq!(dense_out.get(&9).map(|cb| (cb.start, cb.end)), Some((4, 11)));

        // Reuse round 2 (29,683 dirty rebuilds on the corpus share one
        // thread-local scratch): clear_table must fully reset — the
        // copy-out walk already emptied every slot (slots_clean), so the
        // reset walk is skipped but the next round still starts empty.
        fn drive2<T: CoverWriteTable>(tbl: &mut T) {
            tbl.clear_table();
            tbl.entry_or_default(2).set_all();
        }
        drive2(&mut map_arm);
        drive2(&mut scratch);
        let mut dense_out2: BTreeMap<i32, CoverBlock> = BTreeMap::new();
        scratch.copy_out(&mut dense_out2);
        assert_eq!(map_arm, dense_out2);
        assert_eq!(dense_out2.len(), 1, "scratch reuse must not leak round-1 keys");

        // Negative indices (decode/RPO -1 windows, block.cc:1023-1030)
        // land in the side map, copy out, and clear between rebuilds —
        // zero panic paths, zero cross-rebuild state.
        scratch.clear_table();
        scratch.entry_or_default(-1).set_all();
        let mut neg_out: BTreeMap<i32, CoverBlock> = BTreeMap::new();
        scratch.copy_out(&mut neg_out);
        assert_eq!(neg_out.len(), 1);
        assert!(neg_out.contains_key(&-1));
        scratch.clear_table();
        let mut neg_out2: BTreeMap<i32, CoverBlock> = BTreeMap::new();
        scratch.copy_out(&mut neg_out2);
        assert!(neg_out2.is_empty(), "neg side map must clear between rebuilds");
    }

    /// `compare_to` orders Covers by the first covered block index. Empty
    /// Covers sort last (Ghidra's 1000000 sentinel). Faithful to
    /// `Cover::compareTo` (cover.cc:223-247).
    #[test]
    fn test_cover_compare_to() {
        let mut a = Cover::new();
        a.add_def_point(3, 1);
        a.add_ref_point(3, 10);
        let mut b = Cover::new();
        b.add_def_point(5, 1);
        b.add_ref_point(5, 10);
        let empty = Cover::new();

        assert_eq!(a.compare_to(&b), -1, "first-block 3 < 5");
        assert_eq!(b.compare_to(&a), 1, "first-block 5 > 3");
        let mut a2 = Cover::new();
        a2.add_def_point(3, 1);
        assert_eq!(a.compare_to(&a2), 0, "same first block -> 0");
        assert_eq!(a.compare_to(&empty), -1, "non-empty < empty (1000000)");
        assert_eq!(empty.compare_to(&a), 1, "empty > non-empty");
        assert_eq!(empty.compare_to(&Cover::new()), 0, "two empties equal");
    }

    /// `get_cover_block` returns the CoverBlock for a covered block, None
    /// otherwise. Mirrors Ghidra `Cover::getCoverBlock` returning the global
    /// empty block for uncovered blocks.
    #[test]
    fn test_get_cover_block() {
        let mut c = Cover::new();
        c.add_def_point(2, 5);
        c.add_ref_point(2, 9);
        assert!(c.get_cover_block(2).is_some());
        assert_eq!(c.get_cover_block(2).unwrap().start, 5);
        assert!(c.get_cover_block(7).is_none(), "uncovered block -> None");
    }

    /// `intersect_list` enumerates block indices where two Covers intersect
    /// at or above `level`. `intersect_by_block` gives the per-block
    /// characterization. Both faithful to cover.cc:307 / cover.cc:392.
    #[test]
    fn test_intersect_list_and_by_block() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 20);
        c1.add_def_point(2, 1);
        c1.add_ref_point(2, 20);
        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 30);
        // block 1 overlaps (interval), block 2 only in c1.

        // level 2 (interval only): only block 1 qualifies.
        let list = c1.intersect_list(&c2, 2);
        assert_eq!(list, vec![1], "interval-level list must be [1]");

        // level 1 (any intersection): still only block 1 (block 2 absent in c2).
        let list1 = c1.intersect_list(&c2, 1);
        assert_eq!(list1, vec![1]);

        // Per-block characterization.
        assert_eq!(c1.intersect_by_block(1, &c2), 2, "block 1 interval overlap");
        assert_eq!(c1.intersect_by_block(2, &c2), 0, "block 2 absent in c2");
        assert_eq!(c1.intersect_by_block(9, &c2), 0, "block 9 absent in both");
    }

    /// Boundary-touching intervals must yield level-1 (point) intersection,
    /// and `intersect_list(level=1)` must include such blocks while
    /// `intersect_list(level=2)` must exclude them.
    #[test]
    fn test_intersect_list_boundary() {
        let mut c1 = Cover::new();
        c1.add_def_point(1, 1);
        c1.add_ref_point(1, 10); // [1,10]
        let mut c2 = Cover::new();
        c2.add_def_point(1, 10);
        c2.add_ref_point(1, 20); // [10,20]: touches c1 at 10 only
        assert_eq!(c1.intersect_by_block(1, &c2), 1, "boundary touch -> level 1");
        assert_eq!(c1.intersect_list(&c2, 1), vec![1], "level 1 includes boundary");
        assert!(c1.intersect_list(&c2, 2).is_empty(), "level 2 excludes boundary");
    }
}
