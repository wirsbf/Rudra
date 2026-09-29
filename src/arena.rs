//! # Arena core — id-space storage for the Funcdata-owned object banks
//!
//! **Design authority**: `docs/alignment_docs/ARENA_DESIGN.md` (§1-§2, §8 red
//! lines). This module is the W0 spike of `PERF-ARENA-CORE-0001` (campaign
//! `PERF-ARENA-MIGRATION-0001`): the generic machinery W1 will use to replace
//! `Arc<RwLock<...>>` graph handles with typed generational indices, with
//! zero unsafe and zero locks.
//!
//! ## What this mirrors in the Ghidra oracle (12.0.4, e40ed130)
//!
//! Ghidra's decompiler stores PcodeOps / Varnodes / FlowBlocks as
//! `new`-allocated objects cross-referenced by raw pointers, owned by
//! per-function banks (`PcodeOpBank` op.hh:289, `VarnodeBank` varnode.hh:365).
//! Rust cannot store raw cross references safely, so the arena keeps the
//! objects in per-bank slot storage and hands out 8-byte typed ids
//! (`OpId`/`VnId`/`BlockId`) that play the role of the oracle's pointers,
//! plus a generation counter that mechanizes the oracle's dangling-pointer
//! guard discipline: `PcodeOpBank::destroy` (op.cc:989) keeps destroyed ops
//! readable precisely "in case pointer references still exist" — here, a
//! slot only becomes reusable after an explicit `remove`, and a stale id
//! then fails lookup (`None`) instead of silently aliasing a new object.
//!
//! ## Iteration-order red line (ARENA_DESIGN §2.4 / §8.3)
//!
//! **The physical order of arena slots never enters any API.** `Arena`
//! exposes no iteration; `slots`/`gens` are private. Every iterable order in
//! the oracle is carried by an explicit structure, and the arena mirrors
//! those structures exactly:
//!
//! | oracle structure | mirror in this module |
//! |---|---|
//! | 7× `list<PcodeOp*>` (op.hh:291-297) | [`IdList`] intrusive id chain |
//! | `map<SeqNum,PcodeOp*>` (op.hh:280) | `BTreeMap<SeqNumKey, OpId>` |
//! | loc/def trees (varnode.hh:52-55) | `BTreeMap<VnLocKey/VnDefKey, VnId>` |
//! | `vector<FlowBlock*>` (block.hh:366) | `Vec<BlockId>` |
//!
//! Order equality holds inductively: same initial structure × the same
//! structural operation at the same ported call site (anchored by
//! `// Ghidra:` citations) ⇒ same iteration order at every point in time.
//! Slot indices are private bookkeeping and must never be sorted, iterated,
//! or otherwise observed by consumer code.
//!
//! ## Red lines implemented here (ARENA_DESIGN §8)
//!
//! 1. Deletion preserves oracle list order — no swap-remove anywhere.
//! 2. Physical slot order is not in any API.
//! 3. `descend`/`inrefs` maintenance stays explicit (oracle erases
//!    deliberately, op.cc destroy / varnode.cc erase-descend sites) — stale
//!    ids yield `None`, they never substitute for the erase discipline
//!    (helper: [`descend_consistent`]).

use core::cmp::Ordering;
use core::marker::PhantomData;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// §2.1 typed id newtypes (u32 idx + u32 gen = 8B = oracle pointer width)
// ---------------------------------------------------------------------------

/// Identity + packing contract shared by all arena handle types.
///
/// RUGRA-GLUE: Rust-side container infrastructure — Ghidra has no counterpart
/// (the oracle identifies objects by raw pointer value). The generation
/// counter mechanizes the oracle's dangling-pointer discipline instead of
/// relying on "we promise not to look" comments (op.cc:984-987).
pub trait ArenaId: Copy + Eq + std::fmt::Debug {
    /// The list-end / "no node" handle. Index 0 is the reserved sentinel
    /// slot of every [`Arena`]; no allocation ever returns index 0.
    const SENTINEL: Self;

    // RUGRA-GLUE: constructor from raw parts (used by Arena::insert and by
    // the W1 iop-constant packing/unpacking that replaces Arc::as_ptr
    // encoding, ARENA_DESIGN §2.5).
    fn from_parts(idx: u32, gen: u32) -> Self;

    // RUGRA-GLUE: slot index accessor (private bookkeeping; never a sort key).
    fn idx(self) -> u32;

    // RUGRA-GLUE: generation accessor (dangling guard).
    fn gen(self) -> u32;

    // RUGRA-GLUE: true for the sentinel handle (index 0).
    fn is_sentinel(self) -> bool {
        self.idx() == 0
    }

    // RUGRA-GLUE: pack into a u64 for the iop-constant offset encoding
    // (ARENA_DESIGN §1.2: "OpId 打包进偏移"; the packed value never reaches
    // C output, exactly like the oracle's PcodeOp* cast, op.hh:249).
    fn to_bits(self) -> u64 {
        ((self.gen() as u64) << 32) | (self.idx() as u64)
    }

    // RUGRA-GLUE: unpack from a u64 (get_op_from_const mirror).
    fn from_bits(bits: u64) -> Self {
        Self::from_parts(bits as u32, (bits >> 32) as u32)
    }
}

macro_rules! arena_id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub struct $name {
            idx: u32,
            gen: u32,
        }

        impl ArenaId for $name {
            // RUGRA-GLUE: sentinel handle = reserved slot 0 (ARENA_DESIGN
            // §1.2: "哨兵 id=0 保留槽(= std::list end())").
            const SENTINEL: Self = Self { idx: 0, gen: 0 };

            // RUGRA-GLUE: raw-parts constructor (arena-internal + W1 iop
            // packing only).
            fn from_parts(idx: u32, gen: u32) -> Self {
                Self { idx, gen }
            }

            // RUGRA-GLUE: slot index (private bookkeeping).
            fn idx(self) -> u32 {
                self.idx
            }

            // RUGRA-GLUE: generation (dangling guard).
            fn gen(self) -> u32 {
                self.gen
            }
        }
    };
}

arena_id_type! {
    /// Handle to a `PcodeOp` slot in the op arena (op.hh:63 PcodeOp).
    OpId
}
arena_id_type! {
    /// Handle to a `Varnode` slot in the varnode arena (varnode.hh:73 Varnode).
    VnId
}
arena_id_type! {
    /// Handle to a `FlowBlock` slot in the block arena (block.hh:119 FlowBlock).
    BlockId
}
arena_id_type! {
    /// Handle to a `HighVariable` slot (variable.hh HighVariable;
    /// ARENA_DESIGN §3.2 keeps the HighVariable domain separate).
    HighId
}

// ---------------------------------------------------------------------------
// §2.2 Arena<T, Id> — Vec<slot> + free-list + generation
// ---------------------------------------------------------------------------

/// One slot of arena storage.
///
/// RUGRA-GLUE: Rust-side storage — the oracle equivalent is the C++ heap
/// allocation itself (`new PcodeOp`, op.cc:944) plus the "deadandgone keeps
/// the object alive" rule (op.cc:984-999). The `Reserved` variant marks the
/// sentinel slot 0, which is never allocated and never enters the free list.
enum Slot<T> {
    Occupied(T),
    Free { next_free: u32 },
    Reserved,
}

/// Free-list terminator ("no next free slot").
const FREE_END: u32 = u32::MAX;

// RUGRA-GLUE: generic slot storage with generational indices — replaces the
// oracle's new/delete allocator + dangling-pointer discipline. No iteration
// API exists on purpose: physical slot order must never be observable
/// (ARENA_DESIGN §2.4/§8.3).
pub struct Arena<T, Id: ArenaId> {
    slots: Vec<Slot<T>>,
    gens: Vec<u32>,
    free_head: Option<u32>,
    live: u32,
    _id: PhantomData<Id>,
}

impl<T, Id: ArenaId> Arena<T, Id> {
    /// Empty arena with the sentinel slot reserved (index 0).
    // RUGRA-GLUE: container constructor — no Ghidra counterpart.
    pub fn new() -> Self {
        let mut arena = Arena {
            slots: Vec::new(),
            gens: Vec::new(),
            free_head: None,
            live: 0,
            _id: PhantomData,
        };
        arena.slots.push(Slot::Reserved);
        arena.gens.push(0);
        arena
    }

    /// Empty arena with pre-reserved capacity (index 0 reserved).
    // RUGRA-GLUE: capacity hint — no Ghidra counterpart.
    pub fn with_capacity(cap: usize) -> Self {
        let mut arena = Arena {
            slots: Vec::with_capacity(cap + 1),
            gens: Vec::with_capacity(cap + 1),
            free_head: None,
            live: 0,
            _id: PhantomData,
        };
        arena.slots.push(Slot::Reserved);
        arena.gens.push(0);
        arena
    }

    /// Allocate a slot for `value` and return its handle.
    ///
    /// O(1). Reuses free-list slots (LIFO) so the allocation sequence is
    /// deterministic for a given operation sequence. The caller must
    /// initialize any embedded [`Links`] fields to [`Links::detached`]
    /// before linking the element into an [`IdList`] (a zeroed `Links`
    /// is already detached, so `Default`-style construction is safe).
    // RUGRA-GLUE: mirrors `new PcodeOp(...)` at the allocation level
    /// (op.cc:944) without the C++ heap.
    pub fn insert(&mut self, value: T) -> Id {
        let idx = match self.free_head {
            Some(i) => {
                let next = match self.slots[i as usize] {
                    Slot::Free { next_free } => next_free,
                    _ => panic!("arena free-list corruption at slot {}", i),
                };
                self.free_head = if next == FREE_END { None } else { Some(next) };
                self.slots[i as usize] = Slot::Occupied(value);
                i
            }
            None => {
                let i = self.slots.len() as u32;
                self.slots.push(Slot::Occupied(value));
                self.gens.push(0);
                i
            }
        };
        self.live += 1;
        Id::from_parts(idx, self.gens[idx as usize])
    }

    /// Free the slot behind `id`, returning the element.
    ///
    /// Returns `None` if `id` is stale (slot freed and possibly reused —
    /// generation mismatch), out of range, or the sentinel. The slot's
    /// generation is bumped, so **every previously issued handle for this
    /// slot now fails lookup** — this is the mechanized dangling guard
    /// (ARENA_DESIGN §2.1). The element must have been unlinked from every
    /// [`IdList`] first (removing a linked element corrupts chains, exactly
    /// as deleting a linked `PcodeOp` without going through
    /// `PcodeOpBank::destroy` does in the oracle).
    // RUGRA-GLUE: mirrors the reclaim half of the oracle lifecycle; the
    /// oracle only truly reclaims at bank clear/destruction (op.cc:984-999
    /// keeps deadandgone objects readable).
    pub fn remove(&mut self, id: Id) -> Option<T> {
        let i = id.idx() as usize;
        if i >= self.slots.len() || self.gens[i] != id.gen() {
            return None;
        }
        if !matches!(self.slots[i], Slot::Occupied(_)) {
            return None; // reserved sentinel slot or double-free via stale gen
        }
        let head = self.free_head.unwrap_or(FREE_END);
        let old = std::mem::replace(&mut self.slots[i], Slot::Free { next_free: head });
        self.gens[i] = self.gens[i].wrapping_add(1);
        self.free_head = Some(id.idx());
        self.live -= 1;
        match old {
            Slot::Occupied(v) => Some(v),
            _ => unreachable!("checked Occupied above"),
        }
    }

    /// Resolve `id` to a shared reference, or `None` if stale/unknown.
    ///
    /// Cost: one bounds check + one generation compare. `None` for a stale
    /// handle is the mechanized form of the oracle's dangling-pointer guard
    /// — callers treat it as "object gone", never as "silently another
    /// object".
    // RUGRA-GLUE: id dereference — the oracle counterpart is the raw
    // pointer dereference itself.
    pub fn get(&self, id: Id) -> Option<&T> {
        let i = id.idx() as usize;
        if i >= self.slots.len() || self.gens[i] != id.gen() {
            return None;
        }
        match &self.slots[i] {
            Slot::Occupied(v) => Some(v),
            _ => None,
        }
    }

    /// Resolve `id` to an exclusive reference, or `None` if stale/unknown.
    // RUGRA-GLUE: id dereference (mutable) — oracle raw pointer write path.
    pub fn get_mut(&mut self, id: Id) -> Option<&mut T> {
        let i = id.idx() as usize;
        if i >= self.slots.len() || self.gens[i] != id.gen() {
            return None;
        }
        match &mut self.slots[i] {
            Slot::Occupied(v) => Some(v),
            _ => None,
        }
    }

    /// True if `id` resolves to a live element.
    // RUGRA-GLUE: handle liveness check — oracle `ptr != (PcodeOp*)0` plus
    /// discipline; here it is exact.
    pub fn contains(&self, id: Id) -> bool {
        self.get(id).is_some()
    }

    /// Number of live (occupied) slots — the sentinel slot is not counted.
    ///
    /// This is a *count*, never an ordering: `Arena` deliberately exposes no
    /// iteration over slots (ARENA_DESIGN §2.4/§8.3).
    // RUGRA-GLUE: size bookkeeping (std::list::size / map::size analogue).
    pub fn len(&self) -> usize {
        self.live as usize
    }

    /// True if no live elements.
    // RUGRA-GLUE: emptiness check.
    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Drop every element and return all non-sentinel slots to the free
    /// list (ascending order, deterministic reuse).
    ///
    /// Generations are **bumped for the slots that were occupied**, so every
    /// handle issued before the clear is stale afterwards — a cleared arena
    /// can never alias old ids. Mirrors `PcodeOpBank::clear` /
    /// `VarnodeBank::clear` being the only point where the oracle truly
    /// reclaims (op.cc deadandgone note, varnode.cc:1250-1330 domain).
    // RUGRA-GLUE: bulk reclaim — oracle `clear()` + destructor.
    pub fn clear(&mut self) {
        for i in 0..self.slots.len() {
            if matches!(self.slots[i], Slot::Occupied(_)) {
                self.gens[i] = self.gens[i].wrapping_add(1);
                self.slots[i] = Slot::Free { next_free: FREE_END };
            }
        }
        // Re-chain the free list in ascending index order.
        let mut head: Option<u32> = None;
        let mut chain_end: u32 = FREE_END;
        for i in (1..self.slots.len()).rev() {
            if let Slot::Free { next_free } = &mut self.slots[i] {
                *next_free = chain_end;
                chain_end = i as u32;
                head = Some(i as u32);
            }
        }
        self.free_head = head;
        self.live = 0;
    }
}

impl<T, Id: ArenaId> Default for Arena<T, Id> {
    // RUGRA-GLUE: Default = new() (clippy::new_without_default).
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// §2.3 IdList — intrusive id doubly-linked chain (std::list isomorph)
// ---------------------------------------------------------------------------

/// One embedded prev/next link pair inside an element.
///
/// Layout-identical to the design's flat `ins_prev`/`ins_next` field pair
/// (ARENA_DESIGN §1.2); elements may use either form — [`Linked`] exposes
/// accessors, not a struct requirement.
///
/// A freshly created element must hold detached links before its first
/// `IdList` operation; `Links::detached()` (or all-zero fields — the
/// sentinel handle is `idx == 0, gen == 0`) is that state.
// Ghidra: op.hh:127 PcodeOp basiciter / op.hh:128 insertiter / op.hh:129
// codeiter — the three stored list iterators that locate the op inside its
// chains; the link pair is their id-space form (ARENA_DESIGN §1.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Links<Id: ArenaId> {
    pub prev: Id,
    pub next: Id,
}

impl<Id: ArenaId> Links<Id> {
    /// Detached state: not in any chain.
    // RUGRA-GLUE: initial state — the oracle equivalent is the stored
    // iterator being list end() / uninitialized before first insertion.
    pub const fn detached() -> Self {
        Links { prev: Id::SENTINEL, next: Id::SENTINEL }
    }

    /// True if both ends are the sentinel (fresh or unlinked).
    // RUGRA-GLUE: membership bookkeeping (cheap form; see IdList::contains
    // for the exact member test).
    pub fn is_detached(&self) -> bool {
        self.prev.is_sentinel() && self.next.is_sentinel()
    }
}

/// Projection of one embedded link pair out of an element type.
///
/// A single element type can host several independent chains (the op has
/// basic/insert/code chains, op.hh:127-129) by implementing this trait once
/// per zero-sized marker type:
///
/// ```ignore
/// struct InsLink;
/// impl Linked for InsLink {
///     type Elem = OpData;
///     type Id = OpId;
///     fn prev(t: &OpData) -> OpId { t.ins_prev }
///     fn next(t: &OpData) -> OpId { t.ins_next }
///     fn set_prev(t: &mut OpData, id: OpId) { t.ins_prev = id }
///     fn set_next(t: &mut OpData, id: OpId) { t.ins_next = id }
/// }
/// ```
///
/// **Shared-field discipline (freeze contract).** `alivelist` and
/// `deadlist` share the *same* link field (the oracle has a single
/// `insertiter`, op.hh:128, pointing into whichever of the two lists
/// currently holds the op). The oracle trusts that the iterator belongs to
/// the list being erased (every bank method does erase-from-old +
/// insert-into-new as one transition, op.cc:1017-1034); the id-space mirror
/// keeps the same discipline: **callers must only unlink from the list that
/// actually holds the element.** W1 bank layers must debug-assert the
/// lifecycle flag ↔ list consistency at each transition site (e.g.
/// `mark_alive` asserts `op.is_dead()`, mirroring the flag discipline the
/// oracle already relies on in `PcodeOpBank::destroy`, op.cc:992-993).
// Ghidra: op.hh:127 PcodeOp basiciter (stored-iterator discipline: the op
// itself carries its position in each chain — here as link fields).
pub trait Linked {
    type Elem;
    type Id: ArenaId;

    // RUGRA-GLUE: link-field projection accessors (the oracle stores raw
    // list iterators; Rust cannot, so the chain threads through fields).
    fn prev(elem: &Self::Elem) -> Self::Id;

    // RUGRA-GLUE: link-field projection accessors.
    fn next(elem: &Self::Elem) -> Self::Id;

    // RUGRA-GLUE: link-field projection accessors.
    fn set_prev(elem: &mut Self::Elem, id: Self::Id);

    // RUGRA-GLUE: link-field projection accessors.
    fn set_next(elem: &mut Self::Elem, id: Self::Id);
}

/// An intrusive doubly-linked chain of arena ids, head→tail.
///
/// Operation set is isomorphic to the `std::list<PcodeOp*>` chains of
/// `PcodeOpBank` (op.hh:291-297): `push_back`/`push_front` (insert at
/// end/begin), `insert_after`/`insert_before` (insert before an iterator),
/// `unlink` (erase, **O(1), order-preserving** — never swap-remove,
/// ARENA_DESIGN §2.3 red line), `splice_after` (same-list range splice) and
/// `clear`. Iteration follows the `next` chain from `head` — the exact order
/// of the mirrored C++ list.
// Ghidra: op.hh:291 PcodeOpBank deadlist (7× list<PcodeOp*> chains:
// deadlist/alivelist/storelist/loadlist/returnlist/useroplist/deadandgone,
// op.hh:291-297).
pub struct IdList<L: Linked> {
    head: L::Id,
    tail: L::Id,
    len: u32,
    _pd: PhantomData<fn() -> L>,
}

impl<L: Linked> IdList<L> {
    /// Empty chain (head = tail = sentinel).
    // RUGRA-GLUE: empty std::list construction.
    pub const fn new() -> Self {
        IdList { head: L::Id::SENTINEL, tail: L::Id::SENTINEL, len: 0, _pd: PhantomData }
    }

    /// Number of elements in the chain.
    // RUGRA-GLUE: std::list::size().
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if the chain is empty.
    // RUGRA-GLUE: std::list::empty().
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// First element of the chain, or `None` if empty.
    // RUGRA-GLUE: begin() != end() probe.
    pub fn head(&self) -> Option<L::Id> {
        if self.head.is_sentinel() { None } else { Some(self.head) }
    }

    /// Last element of the chain, or `None` if empty.
    // RUGRA-GLUE: rbegin() probe / --end().
    pub fn tail(&self) -> Option<L::Id> {
        if self.tail.is_sentinel() { None } else { Some(self.tail) }
    }

    /// Exact O(1) membership test: `id` is live and linked in *this* chain.
    ///
    /// A member is: live, and (has a real predecessor) or (has a real
    /// successor) or (is the head — the lone-element case whose two links
    /// are both the sentinel). A detached element fails all three.
    ///
    /// Caveat (freeze contract): an element linked into a *different* chain
    /// over the same shared link field is indistinguishable from a member
    /// without walking — same trust level as the oracle's stored iterator;
    /// see the [`Linked`] trait docs for the discipline.
    // RUGRA-GLUE: stored-iterator validity probe (oracle: `iter != end()`).
    pub fn contains(&self, arena: &Arena<L::Elem, L::Id>, id: L::Id) -> bool {
        let Some(elem) = arena.get(id) else { return false };
        let (p, n) = (L::prev(elem), L::next(elem));
        !p.is_sentinel() || !n.is_sentinel() || self.head == id
    }

    /// Insert `id` at the tail — `list.insert(list.end(), op)`.
    ///
    /// O(1). `id` must be live and not currently linked in this chain.
    // Ghidra: op.cc:941 PcodeOpBank::create (deadlist.insert(deadlist.end(),op)
    // tail push at op.cc:947; same form at op.cc:967/1022/1033/892/998).
    pub fn push_back(&mut self, arena: &mut Arena<L::Elem, L::Id>, id: L::Id) {
        let tail = self.tail;
        self.insert_after(arena, tail, id);
    }

    /// Insert `id` at the head — `list.push_front` / insert at begin().
    ///
    /// O(1). `id` must be live and not currently linked in this chain.
    // Ghidra: op.hh:291 PcodeOpBank deadlist (std::list push_front — part of
    // the isomorphic operation set; op chains are consumed begin→end,
    // funcdata.hh:506 beginOpAlive).
    pub fn push_front(&mut self, arena: &mut Arena<L::Elem, L::Id>, id: L::Id) {
        self.insert_after(arena, L::Id::SENTINEL, id);
    }

    /// Insert `id` immediately after `pos`.
    ///
    /// `pos == SENTINEL` means "before the head" (push_front). `pos`
    /// otherwise must be a live member of this chain. `id` must be live and
    /// detached. O(1), order-preserving. This is the generic form of the
    /// oracle's `insert(++prevIter, op)` tail/relative insertions.
    // Ghidra: op.cc:1039 PcodeOpBank::insertAfterDead (++previter then
    // insert before it, op.cc:1045-1047).
    pub fn insert_after(&mut self, arena: &mut Arena<L::Elem, L::Id>, pos: L::Id, id: L::Id) {
        debug_assert!(
            pos.is_sentinel() || self.contains(arena, pos),
            "insert_after: pos {:?} is not a member of this list",
            pos
        );
        debug_assert!(!self.contains(arena, id), "insert_after: id {:?} already linked", id);
        let next = if pos.is_sentinel() {
            self.head
        } else {
            L::next(arena.get(pos).expect("insert_after: pos vanished mid-surgery"))
        };
        {
            let elem = arena.get_mut(id).expect("insert_after: id not live");
            L::set_prev(elem, pos);
            L::set_next(elem, next);
        }
        if pos.is_sentinel() {
            self.head = id;
        } else {
            let elem = arena.get_mut(pos).expect("insert_after: pos vanished");
            L::set_next(elem, id);
        }
        if next.is_sentinel() {
            self.tail = id;
        } else {
            let elem = arena.get_mut(next).expect("insert_after: next vanished");
            L::set_prev(elem, id);
        }
        self.len += 1;
    }

    /// Insert `id` immediately before `pos`.
    ///
    /// `pos == SENTINEL` means "before end()" (push_back). O(1).
    // Ghidra: op.hh:291 PcodeOpBank deadlist (std::list insert(iter, op)
    // before-position form; driven by Funcdata::opInsertBefore through
    /// BlockBasic::insert on the basic chain).
    pub fn insert_before(&mut self, arena: &mut Arena<L::Elem, L::Id>, pos: L::Id, id: L::Id) {
        let prev = if pos.is_sentinel() {
            self.tail
        } else {
            L::prev(arena.get(pos).expect("insert_before: pos not live"))
        };
        self.insert_after(arena, prev, id);
    }

    /// Erase `id` from this chain — O(1), **order-preserving**.
    ///
    /// Neighbors stitch together exactly as `std::list::erase` does; the
    /// removed element is left detached. This is the primitive that makes
    /// `markAlive`/`markDead` O(1) chain surgery instead of the O(n)
    /// `retain` scan (ARENA_DESIGN §0.3: VARMAPOPCREATE measured
    /// 207,611 retain passes / 5.58s against oracle O(1) erase,
    /// op.cc:1020/1031).
    ///
    /// Contract: `id` must be a member of *this* chain (the stored-iterator
    /// discipline, see [`Linked`]). Debug builds assert membership; in
    /// release, unlinking a *detached* element is a guarded no-op (safer
    /// than the C++ UB); unlinking from the wrong chain is a contract
    /// violation and corrupts chains, as in the C++ original.
    // Ghidra: op.cc:1028 PcodeOpBank::markDead (alivelist.erase(insertiter)
    // at op.cc:1031; same erase form at op.cc:1020/996/1044/910-919).
    pub fn unlink(&mut self, arena: &mut Arena<L::Elem, L::Id>, id: L::Id) {
        let member = self.contains(arena, id);
        debug_assert!(member, "unlink: id {:?} is not a member of this list", id);
        if !member {
            return; // release safety net for detached nodes (C++ is UB here)
        }
        let (p, n) = {
            let elem = arena.get(id).expect("unlink: id not live");
            (L::prev(elem), L::next(elem))
        };
        if p.is_sentinel() {
            self.head = n;
        } else {
            let elem = arena.get_mut(p).expect("unlink: prev vanished mid-surgery");
            L::set_next(elem, n);
        }
        if n.is_sentinel() {
            self.tail = p;
        } else {
            let elem = arena.get_mut(n).expect("unlink: next vanished mid-surgery");
            L::set_prev(elem, p);
        }
        let elem = arena.get_mut(id).expect("unlink: id vanished mid-surgery");
        L::set_prev(elem, L::Id::SENTINEL);
        L::set_next(elem, L::Id::SENTINEL);
        self.len -= 1;
    }

    /// Move the contiguous inclusive range `[first ..= last]` so that
    /// `first` lands immediately after `pos` (same-list splice).
    ///
    /// `pos == SENTINEL` moves the range to the front. O(1). The chain
    /// length is unchanged. The degenerate case where the range already sits
    /// right after `pos` is a no-op, mirroring the oracle guard exactly.
    ///
    /// Contract: `first..=last` contiguous members of this chain, `pos` a
    /// member (or the sentinel) and **not inside** the moved range — the
    /// same requirement `std::list::splice` has; debug builds walk the range
    /// to verify.
    // Ghidra: op.cc:1056 PcodeOpBank::moveSequenceDead (splice(previter,
    // deadlist, firstop->insertiter, enditer) with the degenerate guard at
    // op.cc:1063).
    pub fn splice_after(
        &mut self,
        arena: &mut Arena<L::Elem, L::Id>,
        pos: L::Id,
        first: L::Id,
        last: L::Id,
    ) {
        if cfg!(debug_assertions) {
            self.debug_assert_range(arena, first, last, pos);
        }
        let first_prev = L::prev(arena.get(first).expect("splice_after: first not live"));
        let last_next = L::next(arena.get(last).expect("splice_after: last not live"));
        // Degenerate guard — op.cc:1063: moving to where it already is.
        let already_in_place = if pos.is_sentinel() {
            self.head == first
        } else {
            L::next(arena.get(pos).expect("splice_after: pos not live")) == first
        };
        if already_in_place {
            return;
        }
        // 1) Detach [first..=last] from its current position.
        if first_prev.is_sentinel() {
            self.head = last_next;
        } else {
            let elem = arena.get_mut(first_prev).expect("splice_after: first_prev vanished");
            L::set_next(elem, last_next);
        }
        if last_next.is_sentinel() {
            self.tail = first_prev;
        } else {
            let elem = arena.get_mut(last_next).expect("splice_after: last_next vanished");
            L::set_prev(elem, first_prev);
        }
        // 2) Re-attach immediately after pos. Both neighbor reads happen
        //    after the detach so a `pos` that was the range's trailing
        //    neighbor sees its post-detach successor.
        if pos.is_sentinel() {
            let old_head = self.head; // post-detach head
            let elem = arena.get_mut(first).expect("splice_after: first vanished");
            L::set_prev(elem, L::Id::SENTINEL);
            let elem = arena.get_mut(last).expect("splice_after: last vanished");
            L::set_next(elem, old_head);
            if old_head.is_sentinel() {
                self.tail = last;
            } else {
                let elem = arena.get_mut(old_head).expect("splice_after: old_head vanished");
                L::set_prev(elem, last);
            }
            self.head = first;
        } else {
            let pos_next = L::next(arena.get(pos).expect("splice_after: pos vanished"));
            let elem = arena.get_mut(first).expect("splice_after: first vanished");
            L::set_prev(elem, pos);
            let elem = arena.get_mut(last).expect("splice_after: last vanished");
            L::set_next(elem, pos_next);
            let elem = arena.get_mut(pos).expect("splice_after: pos vanished");
            L::set_next(elem, first);
            if pos_next.is_sentinel() {
                self.tail = last;
            } else {
                let elem = arena.get_mut(pos_next).expect("splice_after: pos_next vanished");
                L::set_prev(elem, last);
            }
        }
        // len unchanged: same-list move.
    }

    /// Unlink every element (each is left detached), O(n).
    // Ghidra: op.cc:926 PcodeOpBank::clearCodeLists (storelist.clear() …
    // useroplist.clear(), op.cc:929-932).
    pub fn clear(&mut self, arena: &mut Arena<L::Elem, L::Id>) {
        let mut cur = self.head;
        let mut steps = 0u32;
        while !cur.is_sentinel() {
            debug_assert!(steps <= self.len, "clear: cyclic chain detected");
            let next = L::next(arena.get(cur).expect("clear: node vanished"));
            let elem = arena.get_mut(cur).expect("clear: node vanished");
            L::set_prev(elem, L::Id::SENTINEL);
            L::set_next(elem, L::Id::SENTINEL);
            cur = next;
            steps += 1;
        }
        self.head = L::Id::SENTINEL;
        self.tail = L::Id::SENTINEL;
        self.len = 0;
    }

    /// Iterate the chain head→tail, yielding ids in exact chain order.
    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (list<PcodeOp*>::
    /// const_iterator walk over the bank chains; order = chain order).
    pub fn iter<'a>(&'a self, arena: &'a Arena<L::Elem, L::Id>) -> IdListIter<'a, L> {
        IdListIter { arena, cur: self.head, remaining: Some(self.len) }
    }

    /// Iterate starting at `start` (inclusive) to the tail. If `start` is
    /// the sentinel, yields nothing.
    // Ghidra: op.cc:1071 PcodeOpBank::markIncidentalCopy (iterates the
    /// insertiter range [firstop, lastop] — partial chain walks).
    pub fn iter_from<'a>(
        &'a self,
        arena: &'a Arena<L::Elem, L::Id>,
        start: L::Id,
    ) -> IdListIter<'a, L> {
        // remaining is unknown without walking to the tail — report no
        // exact size rather than lie (ExactSizeIterator is not implemented).
        IdListIter { arena, cur: start, remaining: None }
    }

    /// Iterate yielding `(&Elem, Id)` pairs in chain order.
    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (dereferenced iterator
    /// form — the P1 read pattern of ARENA_DESIGN §3.2).
    pub fn iter_items<'a>(
        &'a self,
        arena: &'a Arena<L::Elem, L::Id>,
    ) -> impl Iterator<Item = (&'a L::Elem, L::Id)> + 'a {
        self.iter(arena)
            .map(move |id| (arena.get(id).expect("chain node vanished"), id))
    }
}

impl<L: Linked> Default for IdList<L> {
    // RUGRA-GLUE: Default = new() (clippy::new_without_default).
    fn default() -> Self {
        Self::new()
    }
}

impl<L: Linked> IdList<L> {
    /// Debug-only range validation for `splice_after`: `first..=last` is a
    /// contiguous run of this chain and `pos` (when not the sentinel) is
    /// outside it.
    // RUGRA-GLUE: debug invariant walk — the oracle relies on std::list
    // splice preconditions being respected by construction; we check them.
    fn debug_assert_range(
        &self,
        arena: &Arena<L::Elem, L::Id>,
        first: L::Id,
        last: L::Id,
        pos: L::Id,
    ) {
        let mut cur = first;
        let mut steps = 0u32;
        while !cur.is_sentinel() {
            if !pos.is_sentinel() {
                debug_assert!(cur != pos, "splice_after: pos is inside the moved range");
            }
            if cur == last {
                return; // reached `last` along the chain: contiguous
            }
            cur = L::next(
                arena.get(cur).expect("splice_after: range node vanished"),
            );
            steps += 1;
            debug_assert!(
                steps <= self.len,
                "splice_after: [first..=last] is not contiguous in this list"
            );
        }
        debug_assert!(
            false,
            "splice_after: [first..=last] is not contiguous in this list (hit the list end before `last`)"
        );
    }
}

/// Head→tail chain iterator (yields ids).
// Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (list<PcodeOp*>::
// const_iterator; ++ follows the next pointer, end() is the sentinel).
pub struct IdListIter<'a, L: Linked> {
    arena: &'a Arena<L::Elem, L::Id>,
    cur: L::Id,
    remaining: Option<u32>,
}

impl<L: Linked> Iterator for IdListIter<'_, L> {
    type Item = L::Id;

    // Ghidra: funcdata.hh:506 Funcdata::beginOpAlive (iterator advance =
    // following the stored next link).
    fn next(&mut self) -> Option<L::Id> {
        if self.cur.is_sentinel() {
            return None;
        }
        let id = self.cur;
        let elem = self.arena.get(id).expect("chain node vanished while iterating");
        self.cur = L::next(elem);
        if let Some(r) = &mut self.remaining {
            *r = r.saturating_sub(1);
        }
        Some(id)
    }

    // RUGRA-GLUE: size hint (exact for iter(), unbounded for iter_from()).
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.remaining {
            Some(n) => (n as usize, Some(n as usize)),
            None => (0, None),
        }
    }
}

impl<L: Linked> std::iter::FusedIterator for IdListIter<'_, L> {}

// ---------------------------------------------------------------------------
// §2 tree key types — POD projections of the oracle's sorted structures
// ---------------------------------------------------------------------------

/// POD projection of `Address` for tree keys.
///
/// Ordering mirrors `Address::operator<` (address.hh:375): the null space
/// sorts first, the `(AddrSpace *)~0` upper sentinel sorts last, real spaces
/// order by `AddrSpace::getIndex()`, then by offset. Encoding: `space == 0`
/// is the null space, `space == u32::MAX` is the upper sentinel, real spaces
/// store `index + 1`. W1 must map `Address → SpaceOff` in exactly one
/// projection function (ARENA_DESIGN §5 R2 discipline).
// Ghidra: address.hh:375 Address::operator< (null first / ~0 last /
/// base->getIndex() then offset).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct SpaceOff {
    pub space: u32,
    pub offset: u64,
}

impl SpaceOff {
    /// The null-space address (sorts before every real address).
    // RUGRA-GLUE: encoding of Address's null AddrSpace*.
    pub const fn null() -> Self {
        SpaceOff { space: 0, offset: 0 }
    }

    /// True for the null-space projection.
    // RUGRA-GLUE: Address::isInvalid-style probe (null base).
    pub const fn is_null(&self) -> bool {
        self.space == 0
    }

    /// Projection of a real address: `AddrSpace::getIndex() + 1` (shifted
    /// past the null-space sentinel) with the raw offset.
    // RUGRA-GLUE: single real-space projection (index+1 shift keeps null
    /// first without a discriminant bit).
    pub const fn from_space_index(space_index: u32, offset: u64) -> Self {
        SpaceOff { space: space_index.wrapping_add(1), offset }
    }

    /// The `(AddrSpace *)~0` upper-sentinel address (sorts after every real
    /// address; used by iop-space style bounds).
    // RUGRA-GLUE: encoding of the ~0 AddrSpace* sentinel.
    pub const fn upper_sentinel(offset: u64) -> Self {
        SpaceOff { space: u32::MAX, offset }
    }
}

/// POD key of the op tree — `map<SeqNum, PcodeOp*>` (op.hh:280).
///
/// Ordering = `SeqNum::operator<` (address.hh:154): `pc` first, then `uniq`
/// (the unique time counter). The `order` field is deliberately **not**
/// part of the key — `SeqNum::operator<` never reads it (address.hh:154-158;
/// OPTREE lane verified the same projection).
// Ghidra: address.hh:154 SeqNum::operator< (pc then uniq; order excluded).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SeqNumKey {
    pub pc: SpaceOff,
    pub uniq: u64,
}

impl SeqNumKey {
    // RUGRA-GLUE: key constructor (SeqNum POD projection).
    pub const fn new(pc: SpaceOff, uniq: u64) -> Self {
        SeqNumKey { pc, uniq }
    }
}

/// Definition-state projection of varnode flags — the shared leading
/// component of both varnode tree comparators.
///
/// Variant order is **load-bearing**: it mirrors the unsigned `(f - 1)`
/// wraparound ranking of `VarnodeCompareLocDef` (varnode.cc:43) —
/// `input` (0x08) sorts before `written` (0x10), and `free` (0) sorts last
/// because `(uint4)(0-1)` is `0xFFFFFFFF`. Do not reorder the variants.
///
/// - `Input` — `input` flag set (varnode.hh:82): no further tiebreak fields
///   (inputs are unique per location in both trees).
/// - `Written` — `written` flag set (varnode.hh:83): tiebreak is the
///   defining op's SeqNum, projected POD as `(def_pc, def_uniq)`
///   (varnode.cc:45-46 / :70-71 read `a->getDef()->getSeqNum()` — the
///   cross-object read the key de-normalizes away, ARENA_DESIGN §1.3).
/// - `Free` — neither flag: tiebreak is `create_index` (varnode.cc:48-50).
// Ghidra: varnode.cc:34 VarnodeCompareLocDef::operator() (flag projection
// with the (f-1) wraparound ranking, varnode.cc:41-43).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum VnDefState {
    Input,
    Written { def_pc: SpaceOff, def_uniq: u64 },
    Free { create_index: u32 },
}

impl VnDefState {
    /// Single projection site from raw varnode flags (ARENA_DESIGN §5 R2:
    /// key construction must be concentrated in one function).
    ///
    /// `input` (0x08, varnode.hh:82) and `written` (0x10, varnode.hh:83) are
    /// mutually exclusive by the `VarnodeBank` state machine
    /// (`setInput`/`setDef`/`makeFree` transitions, varnode.hh:169+); the
    /// combination is unrepresentable here on purpose.
    // Ghidra: varnode.hh:82 varnode_flags input / varnode.hh:83 written
    // (mask used by varnode.cc:41-42).
    pub fn from_flags(flags: u32, def_seq: SeqNumKey, create_index: u32) -> VnDefState {
        const INPUT: u32 = 0x08; // varnode.hh:82
        const WRITTEN: u32 = 0x10; // varnode.hh:83
        match flags & (INPUT | WRITTEN) {
            INPUT => VnDefState::Input,
            WRITTEN => VnDefState::Written { def_pc: def_seq.pc, def_uniq: def_seq.uniq },
            0 => VnDefState::Free { create_index },
            _ => unreachable!("input|written both set: not producible by VarnodeBank"),
        }
    }

    /// Rank in the (f-1) ordering: 0 = input, 1 = written, 2 = free.
    ///
    /// Useful for constructing range bounds (the `beginDef(fl)` overload
    /// family, varnode.hh:401+).
    // RUGRA-GLUE: numeric rank of the variant ordering (range-scan helper).
    pub fn rank(&self) -> u8 {
        match self {
            VnDefState::Input => 0,
            VnDefState::Written { .. } => 1,
            VnDefState::Free { .. } => 2,
        }
    }
}

/// Location-then-definition key — `VarnodeCompareLocDef` (varnode.cc:34-53).
///
/// Derived lexicographic `Ord` over `(addr, size, state)` reproduces the
/// oracle comparator field-for-field:
/// addr (varnode.cc:39) → size (:40) → flag projection with the (f-1)
/// ranking (:41-43) → written: def SeqNum (:44-47) → free: create_index
/// (:48-50) → equal (:52). The `state` field carries both tiebreaks because
/// in the *loc* comparator they are only ever consulted after addr and size.
// Ghidra: varnode.cc:34 VarnodeCompareLocDef::operator() (loc_tree key,
// varnode.hh:52 VarnodeLocSet).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VnLocKey {
    pub addr: SpaceOff,
    pub size: i32,
    pub state: VnDefState,
}

impl VnLocKey {
    // RUGRA-GLUE: key constructor (loc-tree projection).
    pub const fn new(addr: SpaceOff, size: i32, state: VnDefState) -> Self {
        VnLocKey { addr, size, state }
    }
}

/// Definition-then-location key — `VarnodeCompareDefLoc` (varnode.cc:60-79).
///
/// Manual `Ord` because the oracle field order interleaves state fields with
/// location fields in a way derived ordering cannot express: flag projection
/// (:65-68) → written: def SeqNum, *falling through to addr on equality*
/// (:69-72) → addr (:73) → size (:74) → free: create_index, *after* addr and
/// size (:75-77). Both fallthroughs are pinned by unit tests against a
/// literal transcription of the C++.
// Ghidra: varnode.cc:60 VarnodeCompareDefLoc::operator() (def_tree key,
// varnode.hh:55 VarnodeDefSet).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VnDefKey {
    pub state: VnDefState,
    pub addr: SpaceOff,
    pub size: i32,
}

impl VnDefKey {
    // RUGRA-GLUE: key constructor (def-tree projection).
    pub const fn new(state: VnDefState, addr: SpaceOff, size: i32) -> Self {
        VnDefKey { state, addr, size }
    }
}

impl Ord for VnDefKey {
    // Ghidra: varnode.cc:60 VarnodeCompareDefLoc::operator() — transcribed
    // field-for-field: (f1!=f2 → (f-1) ranking) / (written → seq, equal seq
    // falls through) / addr / size / (free → create_index).
    fn cmp(&self, other: &Self) -> Ordering {
        let r1 = self.state.rank();
        let r2 = other.state.rank();
        if r1 != r2 {
            return r1.cmp(&r2); // varnode.cc:67
        }
        if r1 == 1 {
            // written: compare def SeqNum; equality falls through to addr.
            let a = match &self.state {
                VnDefState::Written { def_pc, def_uniq } => (*def_pc, *def_uniq),
                _ => unreachable!("rank 1 implies Written"),
            };
            let b = match &other.state {
                VnDefState::Written { def_pc, def_uniq } => (*def_pc, *def_uniq),
                _ => unreachable!("rank 1 implies Written"),
            };
            match a.cmp(&b) {
                Ordering::Equal => {} // varnode.cc:69-72 fallthrough
                ne => return ne,
            }
        }
        match self.addr.cmp(&other.addr) {
            Ordering::Equal => {}
            ne => return ne, // varnode.cc:73
        }
        match self.size.cmp(&other.size) {
            Ordering::Equal => {}
            ne => return ne, // varnode.cc:74
        }
        if r1 == 2 {
            // free: create_index tiebreak, after addr/size (varnode.cc:75-77).
            let a = match self.state {
                VnDefState::Free { create_index } => create_index,
                _ => unreachable!("rank 2 implies Free"),
            };
            let b = match other.state {
                VnDefState::Free { create_index } => create_index,
                _ => unreachable!("rank 2 implies Free"),
            };
            return a.cmp(&b);
        }
        Ordering::Equal // varnode.cc:78 (input: no further fields)
    }
}

impl PartialOrd for VnDefKey {
    // RUGRA-GLUE: PartialOrd consistent with the manual Ord above.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Tree-index form for the banks: `BTreeMap<PODKey, Id>` (op.hh:280 /
/// varnode.hh:52-55 mirrors). Key equality must imply element identity —
/// each element's key is unique by construction (def SeqNum / create_index
/// uniqueness), so a duplicate insert is a bug: debug-assert it, exactly as
/// the oracle's `set::insert` silently returning the existing element is a
/// "cannot happen" there.
///
/// **Slot-key-copy discipline (freeze contract, ARENA_DESIGN §1.3):** the
/// element keeps a copy of its current key; tree removals must use that
/// copy (the stored-iterator equivalent), and the key may only be
/// recomputed at the oracle's erase+reinsert sites (`xref`/`setDef`/
/// `setInput`/`makeFree`, varnode.cc).
// Ghidra: op.hh:280 PcodeOpTree (map<SeqNum,PcodeOp*>) — the tree-index
// pattern both banks use.
pub type KeyedTree<K, Id> = BTreeMap<K, Id>;

// ---------------------------------------------------------------------------
// descend / inrefs invariant helper (ARENA_DESIGN §5 R4)
// ---------------------------------------------------------------------------

/// Check the `descend` ↔ `inrefs` consistency invariant for one varnode:
/// every op id in the varnode's descend list must resolve in the op arena
/// and must hold this varnode in one of its input slots.
///
/// The oracle maintains `descend` by explicit `addDescend`/`eraseDescend`
/// calls and **erases entries when ops are destroyed** — it never relies on
/// dangling tolerance (varnode.hh:149). In the id world a missed erase is
/// *visible* (a stale id failing `get`), which this helper turns into a
/// debug-assertable predicate. W1 bank layers should call this from
/// debug builds at destroy sites; it is the mechanized guard for the
/// discipline the oracle enforces by code review.
// Ghidra: varnode.hh:149 Varnode::descend (list<PcodeOp*> of every op using
// this varnode as input; maintained explicitly by Funcdata/VarnodeBank).
pub fn descend_consistent<TOp, TVn>(
    ops: &Arena<TOp, OpId>,
    vns: &Arena<TVn, VnId>,
    vn: VnId,
    descend: impl Fn(&TVn) -> &[OpId],
    inrefs: impl Fn(&TOp) -> &[Option<VnId>],
) -> bool {
    let Some(v) = vns.get(vn) else { return false };
    descend(v).iter().all(|&op_id| match ops.get(op_id) {
        Some(op) => inrefs(op).contains(&Some(vn)),
        None => false,
    })
}

// ===========================================================================
// Tests — order-semantics gates (PERF-ARENA-CORE-0001 acceptance ①)
// ===========================================================================
//
// The load-bearing tests here are the differential ones: every IdList op is
// checked against a `std::list`-semantics model (VecDeque) under randomized
// operation sequences, and every tree key Ord is checked against a literal
// transcription of varnode.cc:34-79. Same operation sequence ⇒ same order,
// which is the ARENA_DESIGN §2.4 induction made executable.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::hint::black_box;
    use std::sync::{Arc, RwLock};

    /// Deterministic LCG — reproducible fuzz without external crates.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            ((self.next_u64() >> 16) as usize) % n.max(1)
        }
    }

    // ---- test element: the design §1.2 literal FLAT-field form ----------

    #[derive(Clone, Debug)]
    struct TestOp {
        label: u64,
        ins_prev: OpId,
        ins_next: OpId,
        basic_prev: OpId,
        basic_next: OpId,
        dead: bool,
    }

    impl TestOp {
        fn new(label: u64) -> Self {
            TestOp {
                label,
                ins_prev: OpId::SENTINEL,
                ins_next: OpId::SENTINEL,
                basic_prev: OpId::SENTINEL,
                basic_next: OpId::SENTINEL,
                dead: false,
            }
        }
    }

    #[derive(Copy, Clone)]
    struct InsL;
    #[derive(Copy, Clone)]
    struct BasicL;

    impl Linked for InsL {
        type Elem = TestOp;
        type Id = OpId;
        fn prev(t: &TestOp) -> OpId {
            t.ins_prev
        }
        fn next(t: &TestOp) -> OpId {
            t.ins_next
        }
        fn set_prev(t: &mut TestOp, id: OpId) {
            t.ins_prev = id;
        }
        fn set_next(t: &mut TestOp, id: OpId) {
            t.ins_next = id;
        }
    }

    impl Linked for BasicL {
        type Elem = TestOp;
        type Id = OpId;
        fn prev(t: &TestOp) -> OpId {
            t.basic_prev
        }
        fn next(t: &TestOp) -> OpId {
            t.basic_next
        }
        fn set_prev(t: &mut TestOp, id: OpId) {
            t.basic_prev = id;
        }
        fn set_next(t: &mut TestOp, id: OpId) {
            t.basic_next = id;
        }
    }

    type TestArena = Arena<TestOp, OpId>;

    fn ins_labels(list: &IdList<InsL>, arena: &TestArena) -> Vec<u64> {
        list.iter_items(arena).map(|(t, _)| t.label).collect()
    }

    fn basic_labels(list: &IdList<BasicL>, arena: &TestArena) -> Vec<u64> {
        list.iter_items(arena).map(|(t, _)| t.label).collect()
    }

    // ---- std::list semantics model helpers (VecDeque) --------------------

    fn model_insert_after<T: Copy>(m: &mut VecDeque<T>, at: Option<usize>, v: T) {
        let pos = match at {
            None => 0,
            Some(k) => k + 1,
        };
        m.insert(pos, v);
    }

    /// Move `[i..=j]` so it sits right after `after` (None = front).
    fn model_splice_after<T: Copy>(m: &mut VecDeque<T>, i: usize, j: usize, after: Option<usize>) {
        let range: Vec<T> = m.drain(i..=j).collect();
        let pos = match after {
            None => 0,
            Some(k) => {
                if k < i {
                    k + 1
                } else {
                    // k > j (k inside the range is excluded by the caller)
                    k - (j - i)
                }
            }
        };
        for (off, v) in range.into_iter().enumerate() {
            m.insert(pos + off, v);
        }
    }

    // =======================================================================
    // Arena core: allocation, generation guard, sentinel slot, clear
    // =======================================================================

    #[test]
    fn id_bits_roundtrip_and_sentinel() {
        let id = OpId::from_parts(0xDEAD_BEEF, 0x1234_5678);
        assert_eq!(OpId::from_bits(id.to_bits()), id);
        assert_eq!(id.idx(), 0xDEAD_BEEF);
        assert_eq!(id.gen(), 0x1234_5678);
        assert!(OpId::SENTINEL.is_sentinel());
        assert!(!id.is_sentinel());
        // Typed ids never compare equal across newtypes even with the same
        // bits — newtypes are distinct types by construction; this only
        // checks that the packing layout is the plain (idx, gen) pair.
        let vn = VnId::from_parts(id.idx(), id.gen());
        assert_eq!(vn.to_bits(), id.to_bits());
        assert_eq!(BlockId::from_parts(1, 2).to_bits(), (2u64 << 32) | 1);
        assert_eq!(HighId::SENTINEL.to_bits(), 0);
    }

    #[test]
    fn arena_basic_insert_remove_get() {
        let mut arena: Arena<u64, OpId> = Arena::new();
        assert!(arena.is_empty());
        let a = arena.insert(10);
        let b = arena.insert(20);
        assert_ne!(a, b);
        assert_eq!(arena.len(), 2);
        assert_eq!(arena.get(a), Some(&10));
        assert_eq!(arena.get(b), Some(&20));
        assert_eq!(arena.remove(a), Some(10));
        assert_eq!(arena.get(a), None);
        assert_eq!(arena.len(), 1);
        // unknown / sentinel / out-of-range handles
        assert_eq!(arena.get(OpId::SENTINEL), None);
        assert_eq!(arena.get(OpId::from_parts(999, 0)), None);
        assert_eq!(arena.remove(OpId::SENTINEL), None);
        // mutable access
        *arena.get_mut(b).unwrap() = 99;
        assert_eq!(arena.get(b), Some(&99));
        assert!(arena.contains(b));
        assert!(!arena.contains(a));
    }

    #[test]
    fn arena_gen_dangling_guard() {
        let mut arena: Arena<u64, VnId> = Arena::new();
        let id1 = arena.insert(1);
        assert_eq!(arena.remove(id1), Some(1));
        // stale handle: generation no longer matches
        assert_eq!(arena.get(id1), None);
        assert_eq!(arena.get_mut(id1), None);
        assert!(!arena.contains(id1));
        // slot reused under a NEW generation → old handle stays stale
        let id2 = arena.insert(2);
        assert_ne!(id1, id2);
        assert_eq!(id2.idx(), id1.idx(), "slot must be reused from the free list");
        assert_eq!(arena.get(id1), None, "stale handle must not alias the new object");
        assert_eq!(arena.get(id2), Some(&2));
        // double remove of the old handle is a None, not a free of id2's slot
        assert_eq!(arena.remove(id1), None);
        assert_eq!(arena.get(id2), Some(&2));
    }

    #[test]
    fn arena_sentinel_slot_never_allocated() {
        let mut arena: Arena<u64, BlockId> = Arena::new();
        let mut ids = Vec::new();
        for round in 0..50 {
            for i in 0..100 {
                let id = arena.insert(round * 100 + i);
                assert!(!id.is_sentinel(), "index 0 must never be allocated");
                assert_ne!(id.idx(), 0);
                ids.push(id);
            }
            for id in ids.drain(..) {
                arena.remove(id);
            }
        }
        assert_eq!(arena.len(), 0);
        assert_eq!(arena.get(BlockId::SENTINEL), None);
    }

    #[test]
    fn arena_clear_preserves_gen_monotonicity() {
        let mut arena: Arena<u64, OpId> = Arena::new();
        let old1 = arena.insert(1);
        let old2 = arena.insert(2);
        assert_eq!(arena.remove(old2), Some(2)); // freed before clear
        arena.clear();
        assert!(arena.is_empty());
        // every pre-clear handle is stale, freed-before-clear or not
        assert_eq!(arena.get(old1), None);
        assert_eq!(arena.get(old2), None);
        // new allocations reuse slots but never alias old handles
        let n1 = arena.insert(10);
        let n2 = arena.insert(20);
        assert_eq!(arena.get(old1), None);
        assert_eq!(arena.get(n1), Some(&10));
        assert_eq!(arena.get(n2), Some(&20));
        assert_ne!(n1, old1);
        assert_ne!(n2, old1);
    }

    // =======================================================================
    // IdList: order semantics vs the std::list model
    // =======================================================================

    #[test]
    fn list_push_and_iter_order() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        assert!(list.is_empty());
        let a = arena.insert(TestOp::new(1));
        let b = arena.insert(TestOp::new(2));
        let c = arena.insert(TestOp::new(3));
        list.push_back(&mut arena, a);
        list.push_front(&mut arena, b);
        list.push_back(&mut arena, c);
        assert_eq!(ins_labels(&list, &arena), vec![2, 1, 3]);
        assert_eq!(list.len(), 3);
        assert_eq!(list.head(), Some(b));
        assert_eq!(list.tail(), Some(c));
        // iterator yields ids in chain order and is exact + fused
        let ids: Vec<OpId> = list.iter(&arena).collect();
        assert_eq!(ids, vec![b, a, c]);
        let mut it = list.iter(&arena);
        assert_eq!(it.size_hint(), (3, Some(3)));
        assert_eq!(it.next(), Some(b));
        assert_eq!(it.size_hint(), (2, Some(2)));
        while it.next().is_some() {}
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None, "fused after exhaustion");
    }

    #[test]
    fn list_unlink_preserves_order_head_mid_tail_lone() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..6)
            .map(|i| {
                let id = arena.insert(TestOp::new(i));
                list.push_back(&mut arena, id);
                id
            })
            .collect();
        // mid unlink (label 3)
        list.unlink(&mut arena, ids[3]);
        assert_eq!(ins_labels(&list, &arena), vec![0, 1, 2, 4, 5]);
        // head unlink (label 0)
        list.unlink(&mut arena, ids[0]);
        assert_eq!(ins_labels(&list, &arena), vec![1, 2, 4, 5]);
        // tail unlink (label 5)
        list.unlink(&mut arena, ids[5]);
        assert_eq!(ins_labels(&list, &arena), vec![1, 2, 4]);
        assert_eq!(list.head(), Some(ids[1]));
        assert_eq!(list.tail(), Some(ids[4]));
        // unlink everything → empty → push again
        for id in [ids[1], ids[2], ids[4]] {
            list.unlink(&mut arena, id);
        }
        assert!(list.is_empty());
        assert_eq!(list.head(), None);
        assert_eq!(list.tail(), None);
        list.push_back(&mut arena, ids[0]);
        assert_eq!(ins_labels(&list, &arena), vec![0]);
        // lone-element unlink
        list.unlink(&mut arena, ids[0]);
        assert!(list.is_empty());
    }

    #[test]
    fn list_insert_after_before_forms() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..5).map(|i| arena.insert(TestOp::new(i))).collect();
        list.push_back(&mut arena, ids[0]);
        list.push_back(&mut arena, ids[1]);
        list.push_back(&mut arena, ids[2]); // [0,1,2]
        // insert after member
        list.insert_after(&mut arena, ids[1], ids[3]); // [0,1,3,2]
        assert_eq!(ins_labels(&list, &arena), vec![0, 1, 3, 2]);
        // insert before member
        list.insert_before(&mut arena, ids[2], ids[4]); // [0,1,3,4,2]
        assert_eq!(ins_labels(&list, &arena), vec![0, 1, 3, 4, 2]);
        // insert after SENTINEL = push_front
        let x = arena.insert(TestOp::new(9));
        list.insert_after(&mut arena, OpId::SENTINEL, x); // [9,0,1,3,4,2]
        assert_eq!(ins_labels(&list, &arena), vec![9, 0, 1, 3, 4, 2]);
        // insert before SENTINEL = push_back
        let y = arena.insert(TestOp::new(8));
        list.insert_before(&mut arena, OpId::SENTINEL, y); // [...,8]
        assert_eq!(ins_labels(&list, &arena), vec![9, 0, 1, 3, 4, 2, 8]);
        // insert into empty list via both sentinel forms (fresh elements:
        // ids[0]/x/y are linked in `list` — the shared link field cannot
        // host an element in two chains at once, see the Linked contract)
        let mut empty: IdList<InsL> = IdList::new();
        let z1 = arena.insert(TestOp::new(20));
        empty.insert_after(&mut arena, OpId::SENTINEL, z1);
        assert_eq!(ins_labels(&empty, &arena), vec![20]);
        empty.clear(&mut arena);
        let z2 = arena.insert(TestOp::new(21));
        empty.insert_before(&mut arena, OpId::SENTINEL, z2);
        assert_eq!(ins_labels(&empty, &arena), vec![21]);
    }

    #[test]
    fn list_splice_scripted() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..6).map(|i| arena.insert(TestOp::new(i))).collect();
        for id in &ids {
            list.push_back(&mut arena, *id);
        }
        // [0,1,2,3,4,5]
        // mid-range move: [3,4] after 1 → [0,1,3,4,2,5]
        list.splice_after(&mut arena, ids[1], ids[3], ids[4]);
        assert_eq!(ins_labels(&list, &arena), vec![0, 1, 3, 4, 2, 5]);
        // single element to front: [3] after SENTINEL → [3,0,1,4,2,5]
        list.splice_after(&mut arena, OpId::SENTINEL, ids[3], ids[3]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 0, 1, 4, 2, 5]);
        // range to tail: [0,1] after 5 → [3,4,2,5,0,1]
        list.splice_after(&mut arena, ids[5], ids[0], ids[1]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 4, 2, 5, 0, 1]);
        // already in place → no-op (op.cc:1063 guard)
        list.splice_after(&mut arena, ids[3], ids[4], ids[2]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 4, 2, 5, 0, 1]);
        // front no-op
        list.splice_after(&mut arena, OpId::SENTINEL, ids[3], ids[4]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 4, 2, 5, 0, 1]);
        // pos directly before the range → no-op (op.cc:1063 guard form)
        list.splice_after(&mut arena, ids[2], ids[5], ids[0]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 4, 2, 5, 0, 1]);
        // real move: [4,2] after tail 1 → [3,5,0,1,4,2]
        list.splice_after(&mut arena, ids[1], ids[4], ids[2]);
        assert_eq!(ins_labels(&list, &arena), vec![3, 5, 0, 1, 4, 2]);
        // len is preserved by every splice
        assert_eq!(list.len(), 6);
        // iter_from partial walk (markIncidentalCopy form, op.cc:1071-1083)
        let from4: Vec<u64> = list
            .iter_from(&arena, ids[4])
            .map(|id| arena.get(id).unwrap().label)
            .collect();
        assert_eq!(from4, vec![4, 2]);
    }

    #[test]
    fn list_clear_and_repush() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..5).map(|i| arena.insert(TestOp::new(i))).collect();
        for id in &ids {
            list.push_back(&mut arena, *id);
        }
        list.clear(&mut arena);
        assert!(list.is_empty());
        assert_eq!(list.head(), None);
        // cleared elements are detached and can be re-linked
        list.push_back(&mut arena, ids[4]);
        list.push_back(&mut arena, ids[0]);
        assert_eq!(ins_labels(&list, &arena), vec![4, 0]);
    }

    /// Randomized differential: IdList ops vs a VecDeque std::list model,
    /// same operation sequence ⇒ identical order after every single op.
    #[test]
    fn list_fuzz_matches_std_list_model() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let mut model: VecDeque<u64> = VecDeque::new();
        let mut live: Vec<OpId> = Vec::new(); // ids currently in the list
        let mut next_label = 0u64;
        let mut rng = Lcg::new(0xC0FFEE);

        for _step in 0..4000 {
            let n = model.len();
            let op = rng.below(100);
            match op {
                0..=19 if n < 120 => {
                    let id = arena.insert(TestOp::new(next_label));
                    list.push_back(&mut arena, id);
                    model.push_back(next_label);
                    live.push(id);
                    next_label += 1;
                }
                20..=29 if n < 120 => {
                    let id = arena.insert(TestOp::new(next_label));
                    list.push_front(&mut arena, id);
                    model.push_front(next_label);
                    live.insert(0, id); // mirror position: front
                    next_label += 1;
                }
                30..=49 if n > 0 => {
                    let i = rng.below(n);
                    let id = live.remove(i);
                    let l = model.remove(i).unwrap();
                    list.unlink(&mut arena, id);
                    assert_eq!(arena.get(id).unwrap().label, l);
                }
                50..=59 if n > 0 => {
                    // insert_after a random member (or at the front)
                    let at = if rng.below(4) == 0 { None } else { Some(rng.below(n)) };
                    let id = arena.insert(TestOp::new(next_label));
                    let pos = match at {
                        None => OpId::SENTINEL,
                        Some(k) => live[k],
                    };
                    list.insert_after(&mut arena, pos, id);
                    model_insert_after(&mut model, at, next_label);
                    // track insertion position in `live`
                    let at_idx = match at {
                        None => 0,
                        Some(k) => k + 1,
                    };
                    live.insert(at_idx, id);
                    next_label += 1;
                }
                60..=69 if n > 0 => {
                    // insert_before a random member (or at the back)
                    let before = if rng.below(4) == 0 { None } else { Some(rng.below(n)) };
                    let id = arena.insert(TestOp::new(next_label));
                    let pos = match before {
                        None => OpId::SENTINEL,
                        Some(k) => live[k],
                    };
                    list.insert_before(&mut arena, pos, id);
                    let at_idx = match before {
                        None => n,
                        Some(k) => k,
                    };
                    model.insert(at_idx, next_label);
                    live.insert(at_idx, id);
                    next_label += 1;
                }
                70..=89 if n >= 3 => {
                    // splice a contiguous range after a position outside it
                    let i = rng.below(n - 1);
                    let j = i + rng.below(n - i);
                    let after = if i == 0 && j == n - 1 {
                        None // whole-list range: only the front position exists
                    } else if rng.below(5) == 0 {
                        None // to front
                    } else {
                        loop {
                            let k = rng.below(n);
                            if k < i || k > j {
                                break Some(k);
                            }
                        }
                    };
                    let pos = match after {
                        None => OpId::SENTINEL,
                        Some(k) => live[k],
                    };
                    list.splice_after(&mut arena, pos, live[i], live[j]);
                    model_splice_after(&mut model, i, j, after);
                    let range: Vec<OpId> = live.drain(i..=j).collect();
                    let at_idx = match after {
                        None => 0,
                        Some(k) => {
                            if k < i {
                                k + 1
                            } else {
                                k - (j - i)
                            }
                        }
                    };
                    for (off, id) in range.into_iter().enumerate() {
                        live.insert(at_idx + off, id);
                    }
                }
                90..=94 if n > 0 => {
                    // unlink head
                    let id = live.remove(0);
                    model.pop_front();
                    list.unlink(&mut arena, id);
                }
                _ if n > 0 => {
                    // unlink tail
                    let id = live.pop().unwrap();
                    model.pop_back();
                    list.unlink(&mut arena, id);
                }
                _ => {}
            }
            // per-op differential check: chain order == model order
            let got: Vec<u64> = list.iter_items(&arena).map(|(t, _)| t.label).collect();
            let want: Vec<u64> = model.iter().copied().collect();
            assert_eq!(got, want, "order divergence from std::list model");
            assert_eq!(list.len(), model.len());
            assert_eq!(live.len(), model.len());
        }
    }

    // =======================================================================
    // op.cc lifecycle replay: PcodeOpBank semantics on the id chains
    // =======================================================================

    struct TestOpBank {
        arena: TestArena,
        deadlist: IdList<InsL>,
        alivelist: IdList<InsL>,
        deadandgone: IdList<InsL>,
        basiclist: IdList<BasicL>,
        next_label: u64,
    }

    impl TestOpBank {
        fn new() -> Self {
            TestOpBank {
                arena: TestArena::new(),
                deadlist: IdList::new(),
                alivelist: IdList::new(),
                deadandgone: IdList::new(),
                basiclist: IdList::new(),
                next_label: 0,
            }
        }

        /// op.cc:941-948 create: dead flag + deadlist tail push.
        fn create(&mut self) -> OpId {
            let id = self.arena.insert(TestOp::new(self.next_label));
            self.next_label += 1;
            self.arena.get_mut(id).unwrap().dead = true;
            self.deadlist.push_back(&mut self.arena, id);
            self.basiclist.push_back(&mut self.arena, id);
            id
        }

        /// op.cc:1017-1023 markAlive.
        fn mark_alive(&mut self, op: OpId) {
            assert!(
                self.arena.get(op).unwrap().dead,
                "markAlive on a non-dead op (insertiter discipline)"
            );
            self.deadlist.unlink(&mut self.arena, op);
            self.arena.get_mut(op).unwrap().dead = false;
            self.alivelist.push_back(&mut self.arena, op);
        }

        /// op.cc:1028-1034 markDead.
        fn mark_dead(&mut self, op: OpId) {
            assert!(
                !self.arena.get(op).unwrap().dead,
                "markDead on a non-alive op (insertiter discipline)"
            );
            self.alivelist.unlink(&mut self.arena, op);
            self.arena.get_mut(op).unwrap().dead = true;
            self.deadlist.push_back(&mut self.arena, op);
        }

        /// op.cc:1039-1048 insertAfterDead.
        fn insert_after_dead(&mut self, op: OpId, prev: OpId) {
            assert!(
                self.arena.get(op).unwrap().dead && self.arena.get(prev).unwrap().dead,
                "Dead move called on ops which aren't dead"
            );
            self.deadlist.unlink(&mut self.arena, op);
            self.deadlist.insert_after(&mut self.arena, prev, op);
        }

        /// op.cc:1056-1065 moveSequenceDead.
        fn move_sequence_dead(&mut self, first: OpId, last: OpId, prev: OpId) {
            self.deadlist
                .splice_after(&mut self.arena, prev, first, last);
        }

        /// op.cc:989-999 destroy (optree.erase omitted: no optree in the mock).
        fn destroy(&mut self, op: OpId) {
            assert!(
                self.arena.get(op).unwrap().dead,
                "Deleting integrated op"
            );
            self.deadlist.unlink(&mut self.arena, op);
            self.deadandgone.push_back(&mut self.arena, op);
        }

        /// op.cc:971-982 destroyDead.
        fn destroy_dead(&mut self) {
            while let Some(id) = self.deadlist.head() {
                self.destroy(id);
            }
        }

        fn labels_dead(&self) -> Vec<u64> {
            ins_labels(&self.deadlist, &self.arena)
        }
        fn labels_alive(&self) -> Vec<u64> {
            ins_labels(&self.alivelist, &self.arena)
        }
        fn labels_gone(&self) -> Vec<u64> {
            ins_labels(&self.deadandgone, &self.arena)
        }
        fn labels_basic(&self) -> Vec<u64> {
            basic_labels(&self.basiclist, &self.arena)
        }

        fn by_label(&self, l: u64) -> OpId {
            self.deadlist
                .iter_items(&self.arena)
                .chain(self.alivelist.iter_items(&self.arena))
                .chain(self.deadandgone.iter_items(&self.arena))
                .find(|(t, _)| t.label == l)
                .map(|(_, id)| id)
                .unwrap_or_else(|| panic!("no op with label {}", l))
        }

        /// Mechanized insertiter discipline: every dead-list member carries
        /// the dead flag and no alive-list member does (the W1 bank-layer
        /// guard for the shared ins-link field, see `Linked` docs).
        fn check_flag_consistency(&self) {
            for (t, _) in self.deadlist.iter_items(&self.arena) {
                assert!(t.dead, "dead-list member without dead flag");
            }
            for (t, _) in self.alivelist.iter_items(&self.arena) {
                assert!(!t.dead, "alive-list member with dead flag");
            }
        }
    }

    /// Scripted replay of the op.cc bank operations with hand-derived
    /// expected orders — the VARMAPOPCREATE-relevant sequence shapes
    /// (create/markAlive/markDead/insertAfterDead/moveSequenceDead/destroy).
    #[test]
    fn opcc_lifecycle_replay() {
        let mut bank = TestOpBank::new();
        let a = bank.create();
        let b = bank.create();
        let c = bank.create();
        let d = bank.create();
        assert_eq!(bank.labels_dead(), vec![0, 1, 2, 3]);
        assert_eq!(bank.labels_alive(), Vec::<u64>::new());
        bank.check_flag_consistency();

        bank.mark_alive(a); // dead=[1,2,3] alive=[0]
        assert_eq!(bank.labels_dead(), vec![1, 2, 3]);
        assert_eq!(bank.labels_alive(), vec![0]);
        bank.mark_alive(c); // dead=[1,3] alive=[0,2]
        assert_eq!(bank.labels_dead(), vec![1, 3]);
        assert_eq!(bank.labels_alive(), vec![0, 2]);
        bank.check_flag_consistency();

        let e = bank.create(); // dead=[1,3,4]
        assert_eq!(bank.labels_dead(), vec![1, 3, 4]);

        bank.mark_dead(a); // alive=[2] dead=[1,3,4,0]
        assert_eq!(bank.labels_alive(), vec![2]);
        assert_eq!(bank.labels_dead(), vec![1, 3, 4, 0]);
        bank.check_flag_consistency();

        bank.insert_after_dead(e, b); // move 4 after 1 → [1,4,3,0]
        assert_eq!(bank.labels_dead(), vec![1, 4, 3, 0]);
        bank.insert_after_dead(b, a); // move 1 after 0 → [4,3,0,1]
        assert_eq!(bank.labels_dead(), vec![4, 3, 0, 1]);

        let f = bank.create(); // dead=[4,3,0,1,5]
        assert_eq!(bank.labels_dead(), vec![4, 3, 0, 1, 5]);
        bank.mark_alive(d); // alive=[2,3] dead=[4,0,1,5]
        assert_eq!(bank.labels_alive(), vec![2, 3]);
        assert_eq!(bank.labels_dead(), vec![4, 0, 1, 5]);
        bank.mark_dead(c); // alive=[3] dead=[4,0,1,5,2]
        assert_eq!(bank.labels_dead(), vec![4, 0, 1, 5, 2]);
        bank.check_flag_consistency();

        // moveSequenceDead already in place → op.cc:1063 guard no-op
        bank.move_sequence_dead(bank.by_label(0), bank.by_label(1), bank.by_label(4));
        assert_eq!(bank.labels_dead(), vec![4, 0, 1, 5, 2]);
        // real move: [1,5] after tail 2 → [4,0,2,1,5]
        bank.move_sequence_dead(bank.by_label(1), bank.by_label(5), bank.by_label(2));
        assert_eq!(bank.labels_dead(), vec![4, 0, 2, 1, 5]);
        // to front: [2] before head
        bank.move_sequence_dead(bank.by_label(2), bank.by_label(2), OpId::SENTINEL);
        assert_eq!(bank.labels_dead(), vec![2, 4, 0, 1, 5]);

        // destroy keeps the object readable (deadandgone), op.cc:984-999
        bank.destroy(bank.by_label(1));
        assert_eq!(bank.labels_dead(), vec![2, 4, 0, 5]);
        assert_eq!(bank.labels_gone(), vec![1]);
        let gone_id = bank.by_label(1);
        assert!(bank.arena.get(gone_id).is_some(), "destroy must keep the slot readable");

        // destroyDead drains in order, op.cc:971-982
        bank.destroy_dead();
        assert_eq!(bank.labels_dead(), Vec::<u64>::new());
        assert_eq!(bank.labels_gone(), vec![1, 2, 4, 0, 5]);
        assert_eq!(bank.labels_alive(), vec![3]);

        // the basic chain (second link field) is untouched by the ins-chain
        // surgery above
        assert_eq!(bank.labels_basic(), vec![0, 1, 2, 3, 4, 5]);
        // f is still dead-list member? f=5 was destroyed by destroy_dead —
        // but the basic chain keeps every op, including dead-and-gone ones.
        assert!(bank.arena.get(f).is_some());
        bank.check_flag_consistency();
    }

    /// Randomized lifecycle (alive/dead share the ins links, deadandgone a
    /// third chain, basic a fourth) vs three VecDeque models — same op
    /// sequence ⇒ same chain orders at every step, plus the flag↔list
    /// consistency discipline of the shared link field.
    #[test]
    fn opcc_lifecycle_fuzz_vs_model() {
        let mut bank = TestOpBank::new();
        let mut rng = Lcg::new(0xBADC0DE);
        let mut dead_m: VecDeque<u64> = VecDeque::new();
        let mut alive_m: VecDeque<u64> = VecDeque::new();
        let mut gone_m: VecDeque<u64> = VecDeque::new();
        let mut basic_m: VecDeque<u64> = VecDeque::new();
        let mut by_label: HashMap<u64, OpId> = HashMap::new();

        for step in 0..6000 {
            let nd = dead_m.len();
            let na = alive_m.len();
            let nb = basic_m.len();
            let op = rng.below(100);
            match op {
                0..=24 => {
                    let id = bank.create();
                    let l = bank.arena.get(id).unwrap().label;
                    dead_m.push_back(l);
                    basic_m.push_back(l);
                    by_label.insert(l, id);
                }
                25..=39 if nd > 0 => {
                    let i = rng.below(nd);
                    let l = dead_m.remove(i).unwrap();
                    bank.mark_alive(by_label[&l]);
                    alive_m.push_back(l);
                }
                40..=54 if na > 0 => {
                    let i = rng.below(na);
                    let l = alive_m.remove(i).unwrap();
                    bank.mark_dead(by_label[&l]);
                    dead_m.push_back(l);
                }
                55..=64 if nd >= 2 => {
                    // insertAfterDead (op.cc:1039-1048)
                    let i_op = rng.below(nd);
                    let mut i_prev = rng.below(nd);
                    if i_prev == i_op {
                        i_prev = (i_prev + 1) % nd;
                    }
                    let l_prev = dead_m[i_prev];
                    let l_op = dead_m[i_op];
                    bank.insert_after_dead(by_label[&l_op], by_label[&l_prev]);
                    let l = dead_m.remove(i_op).unwrap();
                    let at = if i_prev < i_op { i_prev + 1 } else { i_prev };
                    dead_m.insert(at, l);
                }
                65..=79 if nd >= 3 => {
                    // moveSequenceDead (op.cc:1056-1065)
                    let i = rng.below(nd - 1);
                    let j = i + rng.below(nd - i);
                    let front = rng.below(5) == 0 || (i == 0 && j == nd - 1);
                    let k = if front {
                        None
                    } else {
                        loop {
                            let k = rng.below(nd);
                            if k < i || k > j {
                                break Some(k);
                            }
                        }
                    };
                    let prev = match k {
                        None => OpId::SENTINEL,
                        Some(k) => by_label[&dead_m[k]],
                    };
                    bank.move_sequence_dead(by_label[&dead_m[i]], by_label[&dead_m[j]], prev);
                    model_splice_after(&mut dead_m, i, j, k);
                }
                80..=89 if nd > 0 => {
                    // destroy (op.cc:989-999)
                    let i = rng.below(nd);
                    let l = dead_m.remove(i).unwrap();
                    bank.destroy(by_label[&l]);
                    gone_m.push_back(l);
                }
                90..=91 if nd > 0 && step % 53 == 0 => {
                    // destroyDead (op.cc:971-982): drain in order
                    while let Some(l) = dead_m.pop_front() {
                        gone_m.push_back(l);
                    }
                    bank.destroy_dead();
                }
                92..=96 if nb > 0 => {
                    // independent second chain: basic-list unlink
                    let i = rng.below(nb);
                    let l = basic_m.remove(i).unwrap();
                    bank.basiclist.unlink(&mut bank.arena, by_label[&l]);
                }
                _ => {}
            }
            // per-op differential checks
            assert_eq!(bank.labels_dead(), dead_m.iter().copied().collect::<Vec<_>>());
            assert_eq!(bank.labels_alive(), alive_m.iter().copied().collect::<Vec<_>>());
            assert_eq!(bank.labels_gone(), gone_m.iter().copied().collect::<Vec<_>>());
            assert_eq!(bank.labels_basic(), basic_m.iter().copied().collect::<Vec<_>>());
            assert_eq!(bank.deadlist.len(), dead_m.len());
            assert_eq!(bank.alivelist.len(), alive_m.len());
            assert_eq!(bank.deadandgone.len(), gone_m.len());
            if step % 37 == 0 {
                bank.check_flag_consistency();
            }
        }
        bank.check_flag_consistency();
        // final phase: full clear — lists first (discipline), then the arena;
        // every handle ever issued must go stale.
        bank.deadlist.clear(&mut bank.arena);
        bank.alivelist.clear(&mut bank.arena);
        bank.deadandgone.clear(&mut bank.arena);
        bank.basiclist.clear(&mut bank.arena);
        bank.arena.clear();
        for (_l, id) in by_label.iter() {
            assert!(
                bank.arena.get(*id).is_none(),
                "handle must be stale after arena clear"
            );
        }
        assert!(bank.arena.is_empty());
        // the bank still functions after a clear
        let id = bank.create();
        assert_eq!(bank.labels_dead(), vec![bank.arena.get(id).unwrap().label]);
    }

    // =======================================================================
    // Tree keys: pinned orderings + differential vs literal varnode.cc
    // =======================================================================

    #[derive(Clone, Copy, Debug)]
    struct TestVn {
        addr: SpaceOff,
        size: i32,
        flags: u32,
        def_seq: Option<SeqNumKey>, // Some iff written
        create_index: u32,
    }

    fn vn_state(v: &TestVn) -> VnDefState {
        VnDefState::from_flags(
            v.flags,
            v.def_seq.unwrap_or(SeqNumKey::new(SpaceOff::null(), 0)),
            v.create_index,
        )
    }
    fn vn_loc_key(v: &TestVn) -> VnLocKey {
        VnLocKey::new(v.addr, v.size, vn_state(v))
    }
    fn vn_def_key(v: &TestVn) -> VnDefKey {
        VnDefKey::new(vn_state(v), v.addr, v.size)
    }

    /// Literal transcription of varnode.cc:34-53 (VarnodeCompareLocDef).
    fn oracle_loc_def_less(a: &TestVn, b: &TestVn) -> bool {
        const INPUT: u32 = 0x08;
        const WRITTEN: u32 = 0x10;
        if a.addr != b.addr {
            return a.addr < b.addr; // varnode.cc:39
        }
        if a.size != b.size {
            return a.size < b.size; // varnode.cc:40
        }
        let f1 = a.flags & (INPUT | WRITTEN);
        let f2 = b.flags & (INPUT | WRITTEN);
        if f1 != f2 {
            return f1.wrapping_sub(1) < f2.wrapping_sub(1); // varnode.cc:41-43
        }
        if f1 == WRITTEN {
            let (da, db) = (a.def_seq.unwrap(), b.def_seq.unwrap());
            if da != db {
                return da < db; // varnode.cc:45-46
            }
        } else if f1 == 0 {
            return a.create_index < b.create_index; // varnode.cc:48-50
        }
        false // varnode.cc:52
    }

    /// Literal transcription of varnode.cc:60-79 (VarnodeCompareDefLoc).
    fn oracle_def_loc_less(a: &TestVn, b: &TestVn) -> bool {
        const INPUT: u32 = 0x08;
        const WRITTEN: u32 = 0x10;
        let f1 = a.flags & (INPUT | WRITTEN);
        let f2 = b.flags & (INPUT | WRITTEN);
        if f1 != f2 {
            return f1.wrapping_sub(1) < f2.wrapping_sub(1); // varnode.cc:67
        }
        if f1 == WRITTEN {
            let (da, db) = (a.def_seq.unwrap(), b.def_seq.unwrap());
            if da != db {
                return da < db; // varnode.cc:70-71
            }
        }
        if a.addr != b.addr {
            return a.addr < b.addr; // varnode.cc:73
        }
        if a.size != b.size {
            return a.size < b.size; // varnode.cc:74
        }
        if f1 == 0 {
            return a.create_index < b.create_index; // varnode.cc:75-77
        }
        false // varnode.cc:78
    }

    fn order_by_oracle<'a>(
        mut v: Vec<&'a TestVn>,
        less: fn(&TestVn, &TestVn) -> bool,
    ) -> Vec<&'a TestVn> {
        v.sort_by(|a, b| {
            if less(a, b) {
                Ordering::Less
            } else if less(b, a) {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });
        v
    }

    #[test]
    fn spaceoff_ordering_and_projection() {
        let null = SpaceOff::null();
        let real0 = SpaceOff::from_space_index(0, 5);
        let real1 = SpaceOff::from_space_index(1, 0);
        let upper = SpaceOff::upper_sentinel(0);
        assert!(null < real0);
        assert!(real0 < real1);
        assert!(real1 < upper);
        assert!(null.is_null());
        assert!(!real0.is_null());
        // same space → offset order
        assert!(SpaceOff::from_space_index(1, 7) < SpaceOff::from_space_index(1, 8));
        // projection shift: index 0 does not collide with the null space
        assert_ne!(real0.space, 0);
        assert_eq!(real0.space, 1);
        assert_eq!(real1.space, 2);
    }

    #[test]
    fn seqnum_key_ordering() {
        let pc1 = SpaceOff::from_space_index(1, 0x10);
        let pc2 = SpaceOff::from_space_index(1, 0x20);
        // pc dominates uniq (address.hh:154-158)
        assert!(SeqNumKey::new(pc1, 999) < SeqNumKey::new(pc2, 0));
        assert!(SeqNumKey::new(pc1, 5) < SeqNumKey::new(pc1, 7));
        assert_eq!(SeqNumKey::new(pc1, 5), SeqNumKey::new(pc1, 5));
    }

    #[test]
    fn vnloc_key_pinned_order() {
        let sp = |off: u64| SpaceOff::from_space_index(1, off);
        let def = |off: u64, uniq: u64| {
            VnDefState::Written { def_pc: sp(off), def_uniq: uniq }
        };
        let k_input = VnLocKey::new(sp(0x100), 4, VnDefState::Input);
        let k_written = VnLocKey::new(sp(0x100), 4, def(0x200, 5));
        let k_free9 = VnLocKey::new(sp(0x100), 4, VnDefState::Free { create_index: 9 });
        let k_free10 = VnLocKey::new(sp(0x100), 4, VnDefState::Free { create_index: 10 });
        let k_big = VnLocKey::new(sp(0x100), 8, VnDefState::Input);
        let k_a200 = VnLocKey::new(sp(0x200), 1, VnDefState::Free { create_index: 0 });
        let k_a300 = VnLocKey::new(sp(0x300), 1, VnDefState::Free { create_index: 0 });
        let kw_uniq3 = VnLocKey::new(sp(0x400), 4, def(0x100, 3));
        let kw_pc1 = VnLocKey::new(sp(0x400), 4, def(0x100, 9));
        let kw_pc2 = VnLocKey::new(sp(0x400), 4, def(0x500, 1));
        let mut keys = vec![
            k_input, k_written, k_free9, k_free10, k_big, k_a200, k_a300, kw_uniq3, kw_pc1, kw_pc2,
        ];
        keys.sort();
        let expected = vec![
            k_input, k_written, k_free9, k_free10, k_big, k_a200, k_a300, kw_uniq3, kw_pc1, kw_pc2,
        ];
        assert_eq!(keys, expected, "VnLocKey order must equal VarnodeCompareLocDef");
        // flag ranking: input < written < free at identical (addr,size)
        assert!(k_input < k_written);
        assert!(k_written < k_free9);
        // free tiebreak = create_index
        assert!(k_free9 < k_free10);
        // written tiebreak = def SeqNum (pc then uniq)
        assert!(kw_uniq3 < kw_pc1);
        assert!(kw_pc1 < kw_pc2);
        // input state has no tiebreak fields: two inputs at the same
        // (addr,size) are the same key (oracle set dedups them)
        assert_eq!(k_input, VnLocKey::new(sp(0x100), 4, VnDefState::Input));
    }

    #[test]
    fn vndef_key_pinned_order() {
        let sp = |off: u64| SpaceOff::from_space_index(1, off);
        let def = |off: u64, uniq: u64| {
            VnDefState::Written { def_pc: sp(off), def_uniq: uniq }
        };
        let di1 = VnDefKey::new(VnDefState::Input, sp(0x100), 4);
        let di2 = VnDefKey::new(VnDefState::Input, sp(0x100), 8);
        let di3 = VnDefKey::new(VnDefState::Input, sp(0x200), 1);
        let dw_a = VnDefKey::new(def(0x010, 9), sp(0x999), 9);
        let dw_b = VnDefKey::new(def(0x300, 1), sp(0x100), 4);
        let dw_c = VnDefKey::new(def(0x300, 1), sp(0x200), 1);
        let dw_d = VnDefKey::new(def(0x300, 2), sp(0x001), 1);
        let df_a = VnDefKey::new(VnDefState::Free { create_index: 9 }, sp(0x200), 4);
        let df_d = VnDefKey::new(VnDefState::Free { create_index: 10 }, sp(0x200), 4);
        let df_b = VnDefKey::new(VnDefState::Free { create_index: 1 }, sp(0x300), 1);
        let mut keys = vec![di3, df_b, dw_a, di1, dw_d, df_d, dw_b, di2, dw_c, df_a];
        keys.sort();
        let expected = vec![di1, di2, di3, dw_a, dw_b, dw_c, dw_d, df_a, df_d, df_b];
        assert_eq!(keys, expected, "VnDefKey order must equal VarnodeCompareDefLoc");
        // state group ordering: input < written < free (varnode.cc:67)
        assert!(di3 < dw_a, "input sorts before written regardless of addr");
        assert!(dw_d < df_b, "written sorts before free regardless of addr");
        // written with equal def SeqNum falls through to addr (varnode.cc:69-73)
        assert!(dw_b < dw_c, "equal def → addr decides");
        // def SeqNum dominates addr for written (varnode.cc:70-71)
        assert!(dw_a < dw_b, "smaller def pc sorts first even at larger addr");
        // free: addr/size dominate create_index (varnode.cc:73-77)
        assert!(df_a < df_b, "addr decides before create_index for frees");
        assert!(df_a < df_d, "same addr/size → create_index decides");
        // the loc/def mirror-image property: input@0x999 vs written@0x001
        let loc_input_hi = VnLocKey::new(sp(0x999), 8, VnDefState::Input);
        let loc_written_lo = VnLocKey::new(sp(0x001), 1, def(0x300, 1));
        assert!(loc_written_lo < loc_input_hi, "loc order: addr first");
        let def_input_hi = VnDefKey::new(VnDefState::Input, sp(0x999), 8);
        let def_written_lo = VnDefKey::new(def(0x300, 1), sp(0x001), 1);
        assert!(def_input_hi < def_written_lo, "def order: state first");
    }

    /// Differential fuzz: both key Ord impls vs literal transcriptions of
    /// varnode.cc:34-79, over randomized records, all pairs.
    #[test]
    fn vn_keys_differential_vs_oracle_comparator() {
        let mut rng = Lcg::new(0x5EED_0001);
        let mut def_uniq = 0u64;
        let mut create_index = 0u32;
        let mut records = Vec::new();
        for i in 0..400 {
            let kind = rng.below(3);
            let (flags, def_seq) = match kind {
                0 => (0x08u32, None), // input
                1 => {
                    def_uniq += 1;
                    (
                        0x10u32,
                        Some(SeqNumKey::new(
                            SpaceOff::from_space_index(rng.below(4) as u32, rng.next_u64() & 0xffff),
                            def_uniq,
                        )),
                    )
                }
                _ => (0x00u32, None), // free
            };
            create_index += 1;
            // inputs get unique locations (oracle inputs are unique per loc;
            // otherwise keys are unique via def_seq / create_index)
            let addr = if kind == 0 {
                SpaceOff::from_space_index(rng.below(4) as u32, ((i as u64) << 32) | (rng.next_u64() & 0xffff))
            } else {
                SpaceOff::from_space_index(rng.below(4) as u32, rng.next_u64() & 0xffff)
            };
            records.push(TestVn {
                addr,
                size: 1 + (rng.next_u64() % 16) as i32,
                flags: flags | ((rng.next_u64() as u32) & !0x18), // random noise bits outside the mask
                def_seq,
                create_index,
            });
        }
        for a in &records {
            for b in &records {
                let (ka, kb) = (vn_loc_key(a), vn_loc_key(b));
                assert_eq!(
                    ka < kb,
                    oracle_loc_def_less(a, b),
                    "VnLocKey Ord != VarnodeCompareLocDef for {:?} vs {:?}",
                    a,
                    b
                );
                assert_eq!(
                    ka == kb,
                    !oracle_loc_def_less(a, b) && !oracle_loc_def_less(b, a),
                    "VnLocKey equality != comparator equivalence"
                );
                let (ka, kb) = (vn_def_key(a), vn_def_key(b));
                assert_eq!(
                    ka < kb,
                    oracle_def_loc_less(a, b),
                    "VnDefKey Ord != VarnodeCompareDefLoc for {:?} vs {:?}",
                    a,
                    b
                );
                assert_eq!(
                    ka == kb,
                    !oracle_def_loc_less(a, b) && !oracle_def_loc_less(b, a),
                    "VnDefKey equality != comparator equivalence"
                );
            }
        }
    }

    /// BTreeMap (the tree-index form) iterates in exactly the oracle
    /// comparator order, independent of insertion order.
    #[test]
    fn vn_keys_btreemap_order_invariance() {
        let mut rng = Lcg::new(0x5EED_0002);
        let mut def_uniq = 0u64;
        let mut create_index = 0u32;
        let mut records: Vec<TestVn> = Vec::new();
        for i in 0..300 {
            let kind = rng.below(3);
            def_uniq += 1;
            create_index += 1;
            let (flags, def_seq) = match kind {
                0 => (0x08u32, None),
                1 => (
                    0x10u32,
                    Some(SeqNumKey::new(
                        SpaceOff::from_space_index(rng.below(3) as u32, rng.next_u64() & 0x0fff),
                        def_uniq,
                    )),
                ),
                _ => (0x00u32, None),
            };
            let addr = if kind == 0 {
                SpaceOff::from_space_index(rng.below(3) as u32, (i as u64) << 20)
            } else {
                SpaceOff::from_space_index(rng.below(3) as u32, rng.next_u64() & 0x0fff)
            };
            records.push(TestVn {
                addr,
                size: 1 + (rng.next_u64() % 8) as i32,
                flags,
                def_seq,
                create_index,
            });
        }
        // insertion order 1: as generated; order 2/3: shuffles
        let mut loc_map: KeyedTree<VnLocKey, u32> = KeyedTree::new();
        for r in &records {
            let key = vn_loc_key(r);
            assert!(
                !loc_map.contains_key(&key),
                "duplicate loc key — records must be key-unique"
            );
            loc_map.insert(key, r.create_index);
        }
        let mut shuffled = records.clone();
        let mut rng2 = Lcg::new(0x5EED_0003);
        for i in (1..shuffled.len()).rev() {
            let j = rng2.below(i + 1);
            shuffled.swap(i, j);
        }
        let mut loc_map2: KeyedTree<VnLocKey, u32> = KeyedTree::new();
        for r in &shuffled {
            loc_map2.insert(vn_loc_key(r), r.create_index);
        }
        let seq1: Vec<u32> = loc_map.values().copied().collect();
        let seq2: Vec<u32> = loc_map2.values().copied().collect();
        assert_eq!(seq1, seq2, "BTreeMap iteration must be insertion-order invariant");
        // and equal to the oracle-comparator sort of the records
        let mut sorted: Vec<&TestVn> = records.iter().collect();
        sorted = order_by_oracle(sorted, oracle_loc_def_less);
        let expected: Vec<u32> = sorted.iter().map(|r| r.create_index).collect();
        assert_eq!(seq1, expected, "BTreeMap order == VarnodeCompareLocDef order");
        // def tree likewise
        let mut def_map: KeyedTree<VnDefKey, u32> = KeyedTree::new();
        for r in &records {
            def_map.insert(vn_def_key(r), r.create_index);
        }
        let mut sorted: Vec<&TestVn> = records.iter().collect();
        sorted = order_by_oracle(sorted, oracle_def_loc_less);
        let expected: Vec<u32> = sorted.iter().map(|r| r.create_index).collect();
        let seq: Vec<u32> = def_map.values().copied().collect();
        assert_eq!(seq, expected, "BTreeMap order == VarnodeCompareDefLoc order");
    }

    /// Range-scan pattern: the beginLoc(s, addr) / endLoc(s, addr) prefix
    /// form (varnode.hh:401+ overload family) with pub-field key bounds.
    #[test]
    fn vn_loc_range_query_prefix_pattern() {
        let sp = |off: u64| SpaceOff::from_space_index(2, off);
        let mut map: KeyedTree<VnLocKey, u64> = KeyedTree::new();
        let mut insert = |addr_off: u64, size: i32, state: VnDefState, tag: u64| {
            map.insert(VnLocKey::new(sp(addr_off), size, state), tag);
        };
        insert(0x100, 4, VnDefState::Input, 1);
        insert(
            0x100,
            4,
            VnDefState::Written { def_pc: sp(0x900), def_uniq: 5 },
            2,
        );
        insert(
            0x100,
            4,
            VnDefState::Written { def_pc: sp(0x900), def_uniq: 9 },
            3,
        );
        insert(0x100, 4, VnDefState::Free { create_index: 7 }, 4);
        insert(0x100, 4, VnDefState::Free { create_index: 8 }, 5);
        insert(0x100, 8, VnDefState::Input, 6);
        insert(0x200, 4, VnDefState::Input, 7);
        // prefix (addr=0x100, size=4) → tags in state order
        let start = VnLocKey { addr: sp(0x100), size: 4, state: VnDefState::Input };
        let end = VnLocKey { addr: sp(0x100), size: 5, state: VnDefState::Input };
        let got: Vec<u64> = map.range(start..end).map(|(_, &t)| t).collect();
        assert_eq!(got, vec![1, 2, 3, 4, 5]);
        // whole-address prefix (addr=0x100, any size)
        let start = VnLocKey { addr: sp(0x100), size: i32::MIN, state: VnDefState::Input };
        let end = VnLocKey { addr: sp(0x101), size: i32::MIN, state: VnDefState::Input };
        let got: Vec<u64> = map.range(start..end).map(|(_, &t)| t).collect();
        assert_eq!(got, vec![1, 2, 3, 4, 5, 6]);
        // state-rank bound helper consistency
        assert!(VnDefState::Input.rank() < VnDefState::Written { def_pc: sp(0), def_uniq: 0 }.rank());
        assert!(
            VnDefState::Written { def_pc: sp(0), def_uniq: 0 }.rank()
                < VnDefState::Free { create_index: 0 }.rank()
        );
    }

    #[test]
    fn vn_state_from_flags_projection() {
        let def = SeqNumKey::new(SpaceOff::from_space_index(1, 0x40), 12);
        assert_eq!(VnDefState::from_flags(0x08, def, 3), VnDefState::Input);
        assert_eq!(
            VnDefState::from_flags(0x10, def, 3),
            VnDefState::Written { def_pc: def.pc, def_uniq: 12 }
        );
        assert_eq!(
            VnDefState::from_flags(0x00, def, 3),
            VnDefState::Free { create_index: 3 }
        );
        // flags outside the input|written mask are ignored (varnode.cc:41)
        assert_eq!(
            VnDefState::from_flags(0x08 | 0x20000 | 0x1000000, def, 3),
            VnDefState::Input
        );
        assert_eq!(
            VnDefState::from_flags(0x10 | 0x8000, def, 3),
            VnDefState::Written { def_pc: def.pc, def_uniq: 12 }
        );
    }

    #[test]
    #[should_panic(expected = "input|written both set")]
    fn vn_state_from_flags_rejects_impossible_combo() {
        let def = SeqNumKey::new(SpaceOff::null(), 0);
        let _ = VnDefState::from_flags(0x18, def, 0);
    }

    // =======================================================================
    // descend ↔ inrefs invariant helper (ARENA_DESIGN §5 R4)
    // =======================================================================

    #[derive(Clone, Debug)]
    struct MockOp {
        inrefs: Vec<Option<VnId>>,
    }
    #[derive(Clone, Debug)]
    struct MockVn {
        descend: Vec<OpId>,
    }

    #[test]
    fn descend_invariant_helper() {
        let mut ops: Arena<MockOp, OpId> = Arena::new();
        let mut vns: Arena<MockVn, VnId> = Arena::new();
        let vn = vns.insert(MockVn { descend: Vec::new() });
        let op1 = ops.insert(MockOp { inrefs: vec![Some(vn)] });
        let op2 = ops.insert(MockOp { inrefs: vec![None, Some(vn)] });
        let op3 = ops.insert(MockOp { inrefs: vec![None] }); // does not read vn
        // consistent
        vns.get_mut(vn).unwrap().descend = vec![op1, op2];
        assert!(descend_consistent(
            &ops,
            &vns,
            vn,
            |v| &v.descend,
            |o| &o.inrefs,
        ));
        // stale op id in descend → inconsistent (R4: the id form makes a
        // missed erase VISIBLE, unlike a Weak upgrade failure)
        vns.get_mut(vn).unwrap().descend = vec![op1, OpId::from_parts(9999, 0)];
        assert!(!descend_consistent(&ops, &vns, vn, |v| &v.descend, |o| &o.inrefs));
        // op that does not hold vn in inrefs → inconsistent
        vns.get_mut(vn).unwrap().descend = vec![op1, op3];
        assert!(!descend_consistent(&ops, &vns, vn, |v| &v.descend, |o| &o.inrefs));
        // unknown vn → false
        assert!(!descend_consistent(
            &ops,
            &vns,
            VnId::from_parts(4242, 0),
            |v| &v.descend,
            |o| &o.inrefs,
        ));
        // op removed from the arena while still in descend → inconsistent
        vns.get_mut(vn).unwrap().descend = vec![op1, op2];
        ops.remove(op2);
        assert!(!descend_consistent(&ops, &vns, vn, |v| &v.descend, |o| &o.inrefs));
    }

    // =======================================================================
    // debug-assertion gates (contract violations must fail loudly in debug)
    // =======================================================================

    #[cfg(all(test, debug_assertions))]
    #[test]
    #[should_panic(expected = "not a member of this list")]
    fn list_double_unlink_panics_in_debug() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let id = arena.insert(TestOp::new(1));
        list.push_back(&mut arena, id);
        list.unlink(&mut arena, id);
        list.unlink(&mut arena, id); // detached now
    }

    #[cfg(all(test, debug_assertions))]
    #[test]
    #[should_panic(expected = "already linked")]
    fn list_insert_member_twice_panics_in_debug() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let id = arena.insert(TestOp::new(1));
        list.push_back(&mut arena, id);
        list.push_back(&mut arena, id); // already a member
    }

    #[cfg(all(test, debug_assertions))]
    #[test]
    #[should_panic(expected = "pos is inside the moved range")]
    fn splice_position_inside_range_panics_in_debug() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..4).map(|i| arena.insert(TestOp::new(i))).collect();
        for id in &ids {
            list.push_back(&mut arena, *id);
        }
        list.splice_after(&mut arena, ids[2], ids[0], ids[3]); // 2 inside [0..3]
    }

    #[cfg(all(test, debug_assertions))]
    #[test]
    #[should_panic(expected = "not contiguous")]
    fn splice_non_contiguous_range_panics_in_debug() {
        let mut arena = TestArena::new();
        let mut list: IdList<InsL> = IdList::new();
        let ids: Vec<OpId> = (0..5).map(|i| arena.insert(TestOp::new(i))).collect();
        for id in &ids {
            list.push_back(&mut arena, *id);
        }
        // [0,1,2,3,4]: [0..=1] and [3..=4] are both contiguous, but
        // first=0, last=3 spans a gap? — 0..3 IS contiguous; use a wrap:
        // first=3, last=1 is not contiguous (walk 3→4→SENT hits the end)
        list.splice_after(&mut arena, ids[0], ids[3], ids[1]);
    }

    // =======================================================================
    // microbenches (numbers printed to stderr; only correctness asserted —
    // W1 performance anchors, ARENA_DESIGN §7)
    // =======================================================================

    #[test]
    fn micro_arena_vs_box_arc_alloc_throughput() {
        const BATCH: usize = 64;
        const ITERS: usize = 20_000;

        let mut arena: Arena<u64, OpId> = Arena::new();
        let t = std::time::Instant::now();
        let mut acc = 0u64;
        for _ in 0..ITERS {
            let mut keep = Vec::with_capacity(BATCH);
            for i in 0..BATCH {
                keep.push(arena.insert(i as u64));
            }
            acc = acc.wrapping_add(keep.len() as u64);
            for id in keep {
                arena.remove(id);
            }
        }
        let arena_ns = t.elapsed().as_nanos() as f64 / (ITERS * BATCH) as f64;

        let t = std::time::Instant::now();
        for _ in 0..ITERS {
            let mut keep = Vec::with_capacity(BATCH);
            for i in 0..BATCH {
                keep.push(Box::new(i as u64));
            }
            acc = acc.wrapping_add(keep.len() as u64);
            for b in keep {
                drop(b);
            }
        }
        let box_ns = t.elapsed().as_nanos() as f64 / (ITERS * BATCH) as f64;

        let t = std::time::Instant::now();
        for _ in 0..ITERS {
            let mut keep = Vec::with_capacity(BATCH);
            for i in 0..BATCH {
                keep.push(Arc::new(i as u64));
            }
            acc = acc.wrapping_add(keep.len() as u64);
            for a in keep {
                drop(a);
            }
        }
        let arc_ns = t.elapsed().as_nanos() as f64 / (ITERS * BATCH) as f64;

        // current-form proxy: Arc<RwLock<T>> clone + read guard + drop
        // (the per-access shape the campaign removes)
        let shared: Arc<RwLock<u64>> = Arc::new(RwLock::new(0));
        let t = std::time::Instant::now();
        for _ in 0..ITERS {
            for _ in 0..BATCH {
                let c = shared.clone();
                let g = c.read().unwrap();
                acc = acc.wrapping_add(*g);
            }
        }
        let arc_rwlock_ns = t.elapsed().as_nanos() as f64 / (ITERS * BATCH) as f64;

        assert!(black_box(acc) > 0);
        eprintln!(
            "[microbench arena] insert+remove per-op: arena={:.1}ns box={:.1}ns arc={:.1}ns | \
             Arc<RwLock> clone+read+drop={:.1}ns",
            arena_ns, box_ns, arc_ns, arc_rwlock_ns
        );
    }

    /// The mark_dead form: O(1) chain surgery vs the O(n) retain scan that
    /// VARMAPOPCREATE measured at 26.9µs mean over 32.6K elements
    /// (ARENA_DESIGN §0.3 / §7.1: expected ~100% elimination).
    #[test]
    fn micro_unlink_vs_retain_markdead_form() {
        const N: usize = 32_600; // VARMAPOPCREATE mean list size
        const OPS: usize = 300;

        let mut arena = TestArena::with_capacity(N);
        let mut list: IdList<InsL> = IdList::new();
        let mut ids = Vec::with_capacity(N);
        for i in 0..N {
            let id = arena.insert(TestOp::new(i as u64));
            list.push_back(&mut arena, id);
            ids.push(id);
        }
        // deterministic unique victims (stride coprime with N)
        let victims: Vec<OpId> = (0..OPS).map(|k| ids[(k * 977 + 123) % N]).collect();
        let t = std::time::Instant::now();
        for v in &victims {
            list.unlink(&mut arena, *v);
        }
        let unlink_ns = t.elapsed().as_nanos() as f64 / OPS as f64;
        assert_eq!(list.len(), N - OPS);

        let mut vec: Vec<u64> = (0..N as u64).collect();
        let t = std::time::Instant::now();
        for k in 0..OPS {
            let victim = ((k * 977 + 123) % N) as u64;
            vec.retain(|&x| x != victim);
        }
        let retain_ns = t.elapsed().as_nanos() as f64 / OPS as f64;
        assert_eq!(vec.len(), N - OPS);

        eprintln!(
            "[microbench arena] mark-dead form @ {} elems: IdList::unlink={:.0}ns/op \
             Vec::retain={:.0}ns/op ratio={:.0}x",
            N,
            unlink_ns,
            retain_ns,
            retain_ns / unlink_ns.max(0.001)
        );
    }
}
