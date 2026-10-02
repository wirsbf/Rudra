//! SSA construction and Heritage management
//!
//! Corresponds to Ghidra's `heritage.hh`

use crate::address::Address;
use crate::block::{BlockBasic, BlockGraph, FlowBlock};
use crate::funcdata::Funcdata;
use crate::op::{PcodeOp, PcodeOpBank, PcodeOpRef};
use crate::opcodes::OpCode;
use crate::space::AddressSpace;
use crate::varnode::{Varnode, VarnodeBank};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock, Weak};

/// Mapping from Address to size and pass information
/// Corresponds to Ghidra's `LocationMap`
#[derive(Debug)]
pub struct LocationMap {
    /// Heritaged addresses mapped to range size and pass number. Ghidra keys
    /// this map by a full `Address` (space + offset, heritage.hh:48
    /// `map<Address,SizePass>`; `Address::operator<` orders by space index
    /// then offset, and `Address::overlap` returns -1 for different spaces),
    /// so entries from different address spaces never merge or overlap.
    /// Rugra's `Address` is a bare offset, so the space identity is carried
    /// explicitly in the key tuple (HERITAGE-DRIVER-SWITCH-0001: cross-space
    /// offset collisions previously misclassified ranges as NEW/OLD).
    pub themap: BTreeMap<(AddressSpace, Address), SizePass>,
}

#[derive(Debug, Clone, Copy)]
pub struct SizePass {
    pub size: i32,
    pub pass: i32,
}

impl LocationMap {
    // Ghidra: heritage.hh:38 LocationMap::new
    pub fn new() -> Self {
        Self {
            themap: BTreeMap::new(),
        }
    }

    // Ghidra: heritage.cc:33 LocationMap::add
    /// Add a range to the disjoint cover, merging overlapping entries.
    /// Faithful to `LocationMap::add` (heritage.cc:34-71). Candidate entries
    /// are restricted to `space`'s contiguous sub-range, exactly mirroring
    /// Ghidra's `map<Address,...>` behaviour where `lower_bound`/`--iter` can
    /// land on another space's entry but `Address::overlap` then returns -1
    /// (different spaces never overlap) and the walk advances back into the
    /// query space.
    /// Returns the intersect code plus the (possibly merged) entry that
    /// the oracle's returned iterator addresses (its `first` address and
    /// `second.size`, heritage.cc:2710/2719/2722):
    ///   0 = no overlap with existing
    ///   1 = partial overlap (merged)
    ///   2 = completely contained in a previous (older) entry
    /// The entry bounds are exactly what a subsequent
    /// `entry_containing(space, addr)` finds: `add` just inserted (or
    /// selected, in the fully-contained case) that entry, and nothing
    /// mutates the map in between — returning it here removes the
    /// redundant upper_bound/back-up walk the driver used to re-locate it.
    pub fn add(
        &mut self, space: AddressSpace, mut addr: Address, mut size: i32, mut pass: i32,
    ) -> (i32, Address, i32) {
        use crate::address::Address as A;
        // Ghidra cc:37-41: iter = lower_bound(addr); if (iter != begin)
        // --iter; if the resulting entry does not overlap, ++iter. The
        // entry selected this way (possibly the lower_bound itself) is the
        // one the cc:43-57 containment/merge check runs on — advancing
        // past it into the merge loop instead lost the "completely
        // contained" classification for exact-start re-adds (prev must be
        // 2, not 1, so a later pass does not re-flag the range NEW).
        // Navigation uses the map's ordered range queries (the oracle's
        // lower_bound/iterator arithmetic, O(log n)); the former Vec-keys
        // snapshot made each add O(n) and the per-pass cover build O(n²).
        let mut intersect = 0;
        // lb1/lb2: first two same-space entries with key >= addr.
        let mut fwd = self.themap.range((space, addr)..);
        let lb1 = fwd
            .next()
            .filter(|(k, _)| k.0 == space)
            .map(|(k, v)| (k.1, *v));
        let lb2 = fwd
            .next()
            .filter(|(k, _)| k.0 == space)
            .map(|(k, v)| (k.1, *v));
        // prev: last same-space entry with key < addr (cc:38-39 --iter).
        let prev = self
            .themap
            .range(..(space, addr))
            .next_back()
            .filter(|(k, _)| k.0 == space)
            .map(|(k, v)| (k.1, *v));
        // Selected entry: prev when it exists, else lb1 (cc:39 iter==begin).
        let had_prev = prev.is_some();
        let mut selected = prev.or(lb1);
        // cc:40-41: if the selected entry does not overlap, advance one.
        if let Some((k_addr, k_sp)) = selected {
            if A::overlap(&addr, 0, k_addr, k_sp.size) == -1 {
                selected = if had_prev { lb1 } else { lb2 };
            }
        }
        // Ghidra cc:43-57: containment / first merge on the selected entry.
        if let Some((k_addr, k_sp)) = selected {
            let where_ = A::overlap(&addr, 0, k_addr, k_sp.size);
            if where_ != -1 {
                // Ghidra cc:46-49: completely contained?
                if where_ + size <= k_sp.size {
                    return if k_sp.pass < pass {
                        (2, k_addr, k_sp.size)
                    } else {
                        (0, k_addr, k_sp.size)
                    };
                }
                // Ghidra cc:50-56: merge — extend addr/size, take min pass.
                addr = k_addr;
                size = where_ + size;
                if k_sp.pass < pass {
                    intersect = 1;
                    pass = k_sp.pass;
                }
                self.themap.remove(&(space, k_addr));
            }
        }
        // Ghidra cc:58-66: continue merging subsequent overlapping entries.
        loop {
            let next = self
                .themap
                .range((space, addr)..)
                .next()
                .filter(|(k, _)| k.0 == space)
                .map(|(k, v)| (k.1, *v));
            let Some((k_addr, k_sp)) = next else { break };
            let where_ = A::overlap(&k_addr, 0, addr, size);
            if where_ == -1 {
                break;
            }
            if where_ + k_sp.size > size {
                size = where_ + k_sp.size;
            }
            if k_sp.pass < pass {
                intersect = 1;
                pass = k_sp.pass;
            }
            self.themap.remove(&(space, k_addr));
        }
        // Ghidra cc:67-70: insert merged entry.
        self.themap.insert((space, addr), SizePass { size, pass });
        (intersect, addr, size)
    }

    // Ghidra: heritage.cc:90 LocationMap::findPass
    /// Return the pass number when the given address was heritaged, or -1
    /// if it was not heritaged. Faithful to `findPass` (heritage.cc:91-100):
    /// upper_bound(addr), back up one, check overlap.
    pub fn find_pass(&self, space: AddressSpace, addr: Address) -> i32 {
        // Ghidra cc:94: upper_bound(addr) — first key > addr (within space;
        // entries of other spaces can never overlap this address).
        let keys: Vec<Address> = self
            .themap
            .keys()
            .filter(|k| k.0 == space && k.1 > addr)
            .map(|k| k.1)
            .collect();
        // Ghidra cc:95: if (iter == begin) return -1
        let prev_key = if keys.is_empty() {
            // No key > addr → use the last key (if any)
            self.themap
                .range((space, Address::new(0))..=(space, Address::new(u64::MAX)))
                .next_back()
                .map(|(k, _)| k.1)
        } else {
            // The key just before the first key > addr
            let first_after = keys[0];
            self.themap
                .range((space, Address::new(0))..(space, first_after))
                .next_back()
                .map(|(k, _)| k.1)
        };
        // Ghidra cc:97-98: if overlap != -1 return pass
        match prev_key {
            Some(k) => {
                let sp = self
                    .themap
                    .get(&(space, k))
                    .copied()
                    .unwrap_or(SizePass { size: 0, pass: -1 });
                if addr.overlap(0, k, sp.size) != -1 {
                    sp.pass
                } else {
                    -1
                }
            }
            None => -1,
        }
    }

    // Ghidra: heritage.cc:33 LocationMap::add
    // RUDRA-GLUE: adapter for the iterator returned by LocationMap::add.
    /// Locate the map entry containing `addr`. Ghidra's `LocationMap::add`
    /// returns an iterator to the (possibly merged) entry covering the added
    /// range; the driver then reads `(*liter).first` / `(*liter).second.size`
    /// (heritage.cc:2710/2719/2722). Rugra's `add` returns only the intersect
    /// code, so this upper_bound/back-up lookup recovers the same entry.
    /// Scans only `space`'s sub-range — entries in other spaces can never
    /// contain this address (Ghidra `Address::overlap` is -1 cross-space).
    pub fn entry_containing(&self, space: AddressSpace, addr: Address) -> Option<(Address, i32)> {
        // upper_bound(addr): first key > addr (within space), then back up one.
        let prev_key = {
            let first_after = self
                .themap
                .range((space, addr)..=(space, Address::new(u64::MAX)))
                .find(|(k, _)| k.1 > addr);
            match first_after {
                Some((k, _)) => {
                    // First key > addr exists; the candidate is the key before it.
                    self.themap
                        .range((space, Address::new(0))..*k)
                        .next_back()
                        .map(|(k2, _)| k2.1)?
                }
                None => {
                    // No key > addr; the candidate is the last key of this space.
                    self.themap
                        .range((space, Address::new(0))..=(space, Address::new(u64::MAX)))
                        .next_back()
                        .map(|(k2, _)| k2.1)?
                }
            }
        };
        let sp = self.themap.get(&(space, prev_key))?;
        if addr.overlap(0, prev_key, sp.size) != -1 {
            Some((prev_key, sp.size))
        } else {
            None
        }
    }

    // Ghidra: heritage.hh:38 LocationMap::clear
    pub fn clear(&mut self) {
        self.themap.clear();
    }
}

// Ghidra: heritage.hh:60 MemRange
/// A single address range in the heritage disjoint list.
/// Faithful to `MemRange` (heritage.hh:60-73).
#[derive(Debug, Clone)]
pub struct MemRange {
    pub addr: Address,
    pub size: i32,
    pub flags: u32,
    /// Address space of the range. Ghidra's `MemRange::addr` is a full
    /// space-carrying Address (heritage.hh:60); Rugra's `Address` is an
    /// offset-only scalar, so the space rides as an explicit field until
    /// ADDRESS-0001 lands.
    // RUDRA-GLUE: explicit-space mirror of the oracle Address identity.
    pub space: AddressSpace,
}

pub mod memrange_flags {
    pub const NEW_ADDRESSES: u32 = 1;
    pub const OLD_ADDRESSES: u32 = 2;
}

impl MemRange {
    // Ghidra: heritage.hh:70 MemRange::newAddresses
    pub fn new_addresses(&self) -> bool {
        (self.flags & memrange_flags::NEW_ADDRESSES) != 0
    }
    // Ghidra: heritage.hh:71 MemRange::oldAddresses
    pub fn old_addresses(&self) -> bool {
        (self.flags & memrange_flags::OLD_ADDRESSES) != 0
    }
    // Ghidra: heritage.hh:72 MemRange::clearProperty
    pub fn clear_property(&mut self, val: u32) {
        self.flags &= !val;
    }
}

// Ghidra: heritage.hh:80 TaskList
// RUDRA-GLUE: derive Debug for the Heritage Debug impl (Ghidra has no such need).
#[derive(Debug)]
/// A disjoint list of address ranges to be processed in SSA form.
/// Faithful to `TaskList` (heritage.hh:80-93).
pub struct TaskList {
    pub tasklist: Vec<MemRange>,
}

impl TaskList {
    // RUDRA-GLUE: Rust Default constructor for TaskList (Ghidra uses default list ctor)
    pub fn new() -> Self {
        Self { tasklist: Vec::new() ,
        }
    }

    // Ghidra: heritage.cc:108 TaskList::add
    /// Add a range to the list. If it overlaps the last range, extend it.
    /// Faithful to `add` (heritage.cc:109-124). The explicit space parameter
    /// mirrors Ghidra's space-carrying Address key.
    pub fn add(&mut self, space: AddressSpace, addr: Address, size: i32, fl: u32) {
        if let Some(last) = self.tasklist.last_mut() {
            if last.space == space {
                let over = Address::overlap(&addr, 0, last.addr, last.size);
                if over >= 0 {
                    let relsize = size + over;
                    if relsize > last.size {
                        last.size = relsize;
                    }
                    last.flags |= fl;
                    return;
                }
            }
        }
        self.tasklist.push(MemRange { addr, size, flags: fl, space ,
        });
    }

    // Ghidra: heritage.hh:89 TaskList::begin
    pub fn begin(&self) -> std::slice::Iter<'_, MemRange> {
        self.tasklist.iter()
    }

    // Ghidra: heritage.hh:90 TaskList::end
    pub fn end(&self) -> std::slice::Iter<'_, MemRange> {
        self.tasklist.iter()
    }

    // Ghidra: heritage.hh:91 TaskList::empty
    pub fn empty(&self) -> bool {
        self.tasklist.is_empty()
    }

    // Ghidra: heritage.hh:92 TaskList::clear
    pub fn clear(&mut self) {
        self.tasklist.clear();
    }
}

// Ghidra: heritage.hh:101 PriorityQueue
#[derive(Debug)]
pub struct PriorityQueue {
    pub queue: Vec<Vec<i32>>,
    pub curdepth: i32,
}

impl PriorityQueue {
    // Ghidra: heritage.hh:101 PriorityQueue::new
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            curdepth: -1,
        }
    }

    // Ghidra: heritage.cc:141 PriorityQueue::reset
    pub fn reset(&mut self, maxdepth: i32) {
        self.queue.clear();
        self.queue.resize_with((maxdepth + 1) as usize, Vec::new);
        self.curdepth = -1;
    }

    // Ghidra: heritage.cc:153 PriorityQueue::insert
    pub fn insert(&mut self, bl_idx: i32, depth: i32) {
        if depth > self.curdepth {
            self.curdepth = depth;
        }
        if depth >= 0 && (depth as usize) < self.queue.len() {
            self.queue[depth as usize].push(bl_idx);
        }
    }

    // Ghidra: heritage.cc:165 PriorityQueue::extract
    pub fn extract(&mut self) -> i32 {
        while self.curdepth >= 0 {
            if let Some(bl) = self.queue[self.curdepth as usize].pop() {
                return bl;
            }
            self.curdepth -= 1;
        }
        -1
    }

    // Ghidra: heritage.hh:101 PriorityQueue::empty
    pub fn empty(&self) -> bool {
        self.curdepth < 0
    }
}

/// Information about heritage status for a specific address space
/// Corresponds to Ghidra's `HeritageInfo`
#[derive(Debug, Clone, Copy)]
pub struct HeritageInfo {
    pub space: AddressSpace,
    pub delay: i32,
    pub deadcodedelay: i32,
    pub deadremoved: i32,
    pub load_guard_search: bool,
    pub warning_issued: bool,
    pub has_call_placeholders: bool,
}

impl HeritageInfo {
    // Ghidra: heritage.cc:179 HeritageInfo::HeritageInfo
    /// Construct per-space heritage info. Faithful to the Ghidra ctor
    /// (heritage.cc:180-204):
    ///   - delay/deadcodedelay from AddrSpace::getDelay()/getDeadcodeDelay()
    ///   - hasCallPlaceholders = (space type == IPTR_SPACEBASE) [Stack]
    ///   - deadremoved = 0
    ///   - loadGuardSearch = false
    /// Previously Rugra hard-coded delay=0/deadcodedelay=0/deadremoved=-1/
    /// load_guard_search=true, which broke the per-space staggered heritage
    /// timing and inverted the loadGuardSearch flag
    /// (Ghidra: false = search not yet performed).
    pub fn new(space: AddressSpace) -> Self {
        let (delay, deadcodedelay, has_call_placeholders) = if space.is_heritaged() {
            // Ghidra cc:195-199: space is heritaged.
            (
                space.get_delay(),
                space.get_deadcode_delay(),
                space.is_stack(), // IPTR_SPACEBASE → Stack
            )
        } else {
            // Ghidra cc:189-193: space not heritaged (Const/Iop/Join/etc).
            // delay/deadcodedelay still read from space, hasCallPlaceholders=false.
            (space.get_delay(), space.get_deadcode_delay(), false)
        };
        Self {
            space,
            delay,
            deadcodedelay,
            // Ghidra cc:201: deadremoved = 0 (was -1, broke removeRevisitedMarkers)
            deadremoved: 0,
            // Ghidra cc:203: loadGuardSearch = false (was true, inverted meaning)
            load_guard_search: false,
            warning_issued: false,
            has_call_placeholders,
        }
    }
// Ghidra: heritage.cc:205 HeritageInfo::reset
    /// Reset per-run state while preserving the space delays, including any
    /// dead-code-delay override installed before a restart.
    pub fn reset(&mut self) {
        self.deadremoved = 0;
        self.has_call_placeholders = self.space.is_heritaged() && self.space.is_stack();
        self.warning_issued = false;
        self.load_guard_search = false;
    }
}

/// Guard record for LOAD/STORE operations
/// Corresponds to Ghidra's `LoadGuard`
#[derive(Debug)]
pub struct LoadGuard {
    pub op: Weak<RwLock<PcodeOp>>,
    pub spc: AddressSpace,
    pub pointer_base: u64,
    pub minimum_offset: u64,
    pub maximum_offset: u64,
    pub step: i32,
    pub analysis_state: i32,
}

impl LoadGuard {
    // Ghidra: heritage.cc:818 LoadGuard::isGuarded
    /// Does this guard apply to the given address (space + offset range)?
    /// Faithful to `LoadGuard::isGuarded` (heritage.cc:819-826).
    pub fn is_guarded(&self, space: &crate::space::AddressSpace, offset: u64) -> bool {
        if space != &self.spc {
            return false;
        }
        if offset < self.minimum_offset {
            return false;
        }
        if offset > self.maximum_offset {
            return false;
        }
        true
    }

    // Ghidra: heritage.hh:142 LoadGuard::getMinimum
    /// Get minimum offset of the guarded range. (heritage.hh:164)
    pub fn get_minimum(&self) -> u64 {
        self.minimum_offset
    }

    // Ghidra: heritage.hh:142 LoadGuard::getMaximum
    /// Get maximum offset of the guarded range. (heritage.hh:165)
    pub fn get_maximum(&self) -> u64 {
        self.maximum_offset
    }

    // Ghidra: heritage.hh:142 LoadGuard::getOp
    /// Get the guarded op. (heritage.hh:161)
    pub fn get_op(&self) -> Option<std::sync::Arc<std::sync::RwLock<PcodeOp>>> {
        self.op.upgrade()
    }

    /// Initialize a fresh unanalyzed guard that initially protects the whole
    /// space. Faithful to `LoadGuard::set` (heritage.hh:159-161).
    ///
    /// Ghidra: `set(o,s,off) { op=o; spc=s; pointerBase=off; minimumOffset=0;
    /// maximumOffset=s->getHighest(); step=0; analysisState=0; }`.
    ///
    /// Rugra's `AddressSpace` is a flat enum without a per-space
    /// `getHighest()`, so we use a conservative all-space maximum
    /// (`u64::MAX`). This matches Ghidra's "guards everything until value-set
    /// analysis narrows it" semantics and keeps `is_guarded` permissive.
    pub fn set(
        &mut self,
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        spc: AddressSpace,
        off: u64,
    ) {
        self.op = std::sync::Arc::downgrade(op);
        self.spc = spc;
        self.pointer_base = off;
        self.minimum_offset = 0;
        self.maximum_offset = space_highest(spc);
        self.step = 0;
        self.analysis_state = 0;
    }

    // Ghidra: heritage.hh:142 LoadGuard::newUnanalyzed
    /// Build a fresh guard via `set` and return it. Convenience wrapper used
    /// by `guard_stores`/`guard_loads` (mirrors Ghidra's
    /// `loadGuard.emplace_back(); loadGuard.back().set(...)`).
    pub fn new_unanalyzed(
        op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
        spc: AddressSpace,
        off: u64,
    ) -> Self {
        let mut g = Self::default();
        g.set(op, spc, off);
        g
    }

    // Ghidra: heritage.cc:740 LoadGuard::establishRange
    /// Convert partial value-set analysis into the guard range.
    /// Faithful port of `LoadGuard::establishRange` (heritage.cc:740-785):
    /// empty/full/too-wide ranges keep `minimumOffset = pointerBase` with a
    /// 0x1000 size window; a converged range picks the left/right stable
    /// boundary (or pointerBase when unstable); the window is clamped to
    /// `spc->getHighest()`.
    ///
    /// GETPARAM-OPPOOL-COUNT-0001: this used to be a TODO(value-set-analysis)
    /// stub that kept the initial full-stack `[0, highest]` guard, which made
    /// `RuleIndirectCollapse`'s store-guard arm (ruleaction.cc:3203-3218)
    /// reject every stack INDIRECT (guard->isGuarded always true) — 6 missing
    /// rule applications at getparameter oppool1 ordinal 65.
    pub fn establish_range(&mut self, value_set: &crate::rangeutil::ValueSetRead) {
        // cc:743-744: const CircleRange &range; rangeSize = range.getSize()
        let range = value_set.get_range();
        let range_size = range.get_size();
        let mut size: u64;
        if range.is_empty() {
            // cc:746-749: minimumOffset = pointerBase; size = 0x1000;
            self.minimum_offset = self.pointer_base;
            size = 0x1000;
        } else if range.is_full() || range_size > 0xffffff {
            // cc:750-754: minimumOffset = pointerBase; size = 0x1000;
            //   analysisState = 1 (don't bother doing more analysis)
            self.minimum_offset = self.pointer_base;
            size = 0x1000;
            self.analysis_state = 1;
        } else {
            // cc:756: step = (rangeSize == 3) ? range.getStep() : 0
            self.step = if range_size == 3 { range.get_step() as i32 } else { 0 };
            size = 0x1000;
            if value_set.is_left_stable() {
                // cc:758-760: minimumOffset = range.getMin()
                self.minimum_offset = range.get_min();
            } else if value_set.is_right_stable() {
                // cc:761-770
                if self.pointer_base < range.get_end() {
                    self.minimum_offset = self.pointer_base;
                    size = range.get_end() - self.pointer_base;
                } else {
                    self.minimum_offset = range.get_min();
                    size = range_size.wrapping_mul(range.get_step());
                }
            } else {
                // cc:771-772: minimumOffset = pointerBase
                self.minimum_offset = self.pointer_base;
            }
        }
        // cc:774-784: clamp to spc->getHighest(). NOTE: uintb arithmetic in
        // C++ wraps: for a space whose highest is 2^64-1 and minimumOffset 0,
        // maxSize wraps to 0 and the window clamps back to highest (the
        // whole-space guard), which is the faithful outcome.
        let max = space_highest(self.spc);
        if self.minimum_offset > max {
            self.minimum_offset = max;
            self.maximum_offset = self.minimum_offset; // Something is seriously wrong
        } else {
            let max_size = (max - self.minimum_offset).wrapping_add(1);
            if size > max_size {
                size = max_size;
            }
            self.maximum_offset = self.minimum_offset.wrapping_add(size).wrapping_sub(1);
        }
    }

    // Ghidra: heritage.cc:787 LoadGuard::finalizeRange
    /// Convert final value-set analysis to the final guard range.
    /// Faithful port of `LoadGuard::finalizeRange` (heritage.cc:787-813):
    /// analysisState=1 unconditionally; a converged reasonable range (with
    /// the 0x100/0x10000 index-storage caveat) locks the guard at state 2
    /// with [range.getMin(), (range.getEnd()-1)&range.getMask()], demoted
    /// back to state 1 (full window to highest) when the mask overflows.
    pub fn finalize_range(&mut self, value_set: &crate::rangeutil::ValueSetRead) {
        // cc:790: analysisState = 1 in all cases
        self.analysis_state = 1;
        let range = value_set.get_range();
        let mut range_size = range.get_size();
        // cc:793-797: sizes that likely result from the storage size of the
        //   index are discarded unless iteration signs were seen
        if range_size == 0x100 || range_size == 0x10000 {
            if self.step == 0 {
                range_size = 0;
            }
        }
        // cc:798-808: converged to something reasonable
        if range_size > 1 && range_size < 0xffffff {
            self.analysis_state = 2; // definitive result
            if range_size > 2 {
                self.step = range.get_step() as i32;
            }
            self.minimum_offset = range.get_min();
            // NOTE: Don't subtract a whole step
            self.maximum_offset = range.get_end().wrapping_sub(1) & range.get_mask();
            if self.maximum_offset < self.minimum_offset {
                // Values extend into what is usually stack parameters
                self.maximum_offset = space_highest(self.spc);
                self.analysis_state = 1; // remove the lock, likely overflowed
            }
        }
        // cc:809-812: final clamps to spc->getHighest()
        if self.minimum_offset > space_highest(self.spc) {
            self.minimum_offset = space_highest(self.spc);
        }
        if self.maximum_offset > space_highest(self.spc) {
            self.maximum_offset = space_highest(self.spc);
        }
    }
}

impl Default for LoadGuard {
    // Ghidra: heritage.hh:142 LoadGuard::default
    fn default() -> Self {
        Self {
            op: Weak::default(),
            spc: AddressSpace::Ram,
            pointer_base: 0,
            minimum_offset: 0,
            maximum_offset: space_highest(AddressSpace::Ram),
            step: 0,
            analysis_state: 0,
        }
    }
}

// Ghidra: heritage.hh:216 Heritage::StackNode
/// Walk element for `Heritage::discoverIndexedStackPointers`
/// (heritage.hh:216-236 `StackNode`). `iter` is the index of the next
/// descendant to follow in `vn.descend` (standing in for the
/// `list<PcodeOp *>::const_iterator`).
struct StackWalkNode {
    vn: Arc<RwLock<Varnode>>,
    offset: u64,
    traversals: u32,
    iter: usize,
}

// cc:217-220 StackNode traversal bits (heritage.hh:217-220)
const STACK_WALK_NONCONSTANT_INDEX: u32 = 1;
const STACK_WALK_MULTIEQUAL: u32 = 2;

// Ghidra: heritage.hh:142 LoadGuard::spaceHighest
/// Conservative "highest addressable offset" for a space, standing in for
/// Ghidra's `AddrSpace::getHighest()`. Rugra spaces are 64-bit addressable
/// (`addr_size()==8`), so the all-ones value is the natural maximum and keeps
/// `is_guarded` permissive until value-set analysis narrows a range.
fn space_highest(_spc: AddressSpace) -> u64 {
    u64::MAX
}

/// Main Heritage class responsible for SSA construction
/// Corresponds to Ghidra's `Heritage` class
#[derive(Debug)]
pub struct Heritage {
    // RUDRA-GLUE: Ghidra's `Funcdata *fd` (heritage.hh:249) is a non-owning raw
    // pointer used re-entrantly by every pass helper. Rust cannot store an
    // aliasing mutable handle inside an object that Funcdata itself owns
    // (the former `Weak<RwLock<Funcdata>>` field re-entered the write lock and
    // could deadlock, per HERITAGE-DRIVER-0001). The exclusive `&mut Funcdata`
    // is now threaded explicitly through every pass method; the persistent
    // object is temporarily moved out of `Funcdata::heritage` by
    // `Funcdata::op_heritage` (mem::take) for the duration of one pass.
    pub globaldisjoint: LocationMap,
    /// Current-pass disjoint cover; cleared by `rename` (cc:2592).
    pub disjoint: TaskList,
    pub domchild: Vec<Vec<i32>>,
    pub augment: Vec<Vec<i32>>,
    pub flags: Vec<u32>,
    pub depth: Vec<i32>,
    pub maxdepth: i32,
    pub pass: i32,
    pub pq: PriorityQueue,
    pub merge: Vec<i32>,
    pub infolist: Vec<HeritageInfo>,
    pub load_guard: Vec<LoadGuard>,
    pub store_guard: Vec<LoadGuard>,
    pub load_copy_ops: Vec<Weak<RwLock<PcodeOp>>>,
}

impl Heritage {
    // Ghidra: heritage.cc:218 Heritage::Heritage
    /// Construct the heritage manager. Faithful to the Ghidra constructor
    /// (heritage.cc:218-224): `fd = data; pass = 0; maxdepth = -1;`.
    /// `maxdepth = -1` is load-bearing: it is the sentinel that makes the
    /// first `Heritage::heritage` pass rebuild the augmented dominator tree
    /// (heritage.cc:2676-2677). (Previously Rugra initialized `maxdepth = 0`,
    /// so the rebuild condition could never fire.)
    pub fn new() -> Self {
        Self {
            globaldisjoint: LocationMap::new(),
            disjoint: TaskList::new(),
            domchild: Vec::new(),
            augment: Vec::new(),
            flags: Vec::new(),
            depth: Vec::new(),
            maxdepth: -1,
            pass: 0,
            pq: PriorityQueue::new(),
            merge: Vec::new(),
            infolist: Vec::new(),
            load_guard: Vec::new(),
            store_guard: Vec::new(),
            load_copy_ops: Vec::new(),
        }
    }
}

impl Default for Heritage {
    // Ghidra: heritage.cc:219 Heritage::default
    fn default() -> Self {
        Self::new()
    }
}

impl Heritage {
    // Ghidra: heritage.hh:333 Heritage::forceRestructure
    /// Force regeneration of basic block structures. Faithful one-line port
    /// of `Heritage::forceRestructure` (heritage.hh:333):
    /// `void forceRestructure(void) { maxdepth = -1; }` — resetting the
    /// sentinel makes the next `Heritage::heritage` pass rebuild the
    /// augmented dominator tree (heritage.cc:2676-2677), so dominator-rooted
    /// state (domchild/depth/augment) is recomputed from the CFG as
    /// re-established by `Funcdata::structureReset`
    /// (funcdata_block.cc:712-730). Called from `structure_reset` at the
    /// oracle call site (funcdata_block.cc:730).
    pub fn force_restructure(&mut self) {
        self.maxdepth = -1;
    }
}

impl Heritage {
    // Ghidra: heritage.hh:257 Heritage::getInfo
    /// Look up the HeritageInfo for `space`. Faithful to `getInfo`
    /// (heritage.hh:257). Ghidra indexes infolist by spc->getIndex();
    /// Rugra scans by space match (infolist is small, ~6 entries).
    /// Auto-builds infolist if empty (buildInfoList cc:2650).
    pub fn get_info(&mut self, space: AddressSpace) -> &HeritageInfo {
        if self.infolist.is_empty() {
            self.build_info_list();
        }
        let idx = self.infolist.iter().position(|i| i.space == space);
        match idx {
            Some(i) => &mut self.infolist[i],
            None => {
                // Space not in infolist (shouldn't happen after build_info_list).
                // Append a fresh entry as fallback.
                self.infolist.push(HeritageInfo::new(space));
                self.infolist.last_mut().unwrap()
            }
        }
    }

    // Ghidra: heritage.cc:2650 Heritage::buildInfoList
    /// Build the compact per-space HeritageInfo projection in the locked x86
    /// manager order. Ghidra iterates every `manage->numSpaces()` slot; the
    /// missing FSPEC identity remains an explicit manager-model residual.
    pub fn build_info_list(&mut self) {
        if !self.infolist.is_empty() {
            return;
        }
        // Locked x86 space-index order, with the unmodeled FSPEC slot (5)
        // omitted from the compact enum projection.
        let spaces = [
            AddressSpace::Const,
            AddressSpace::Other(crate::space::SPACEID_OTHER),
            AddressSpace::Unique,
            AddressSpace::Ram,
            AddressSpace::Register,
            AddressSpace::Iop,
            AddressSpace::Join,
            AddressSpace::Stack,
        ];
        for sp in spaces {
            self.infolist.push(HeritageInfo::new(sp));
        }
    }

    // Ghidra: heritage.cc:2316 Heritage::buildADT
    /// Build the Augmented Dominator Tree. Faithful to `buildADT`
    /// (heritage.cc:2316-2385). Consumes the block dominator state populated
    /// upstream (Ghidra: `Funcdata::structureReset` -> `calcForwardDominator`;
    /// Rugra: `BlockGraph::build_dom_tree`) and constructs the Bilardi-Pingali
    /// augmentation.
    ///
    /// Algorithm (locked oracle lines):
    ///   1. cc:2329-2332 clear + resize augment/flags
    ///   2. cc:2334 buildDomTree(domchild) — assemble from immed_dom;
    ///      blocks with no immed_dom land in the dead bucket `size`
    ///   3. cc:2338 buildDomDepth(depth) — root depth 1, child = parent+1,
    ///      trailing sentinel depth[size]=0, maxdepth = maximum
    ///   4. cc:2339-2353 find up-edges (u != immed_dom(v)) and count b[]/t[]
    ///   5. cc:2354-2367 bottom-up pass: compute a[]/z[], mark boundary nodes
    ///   6. cc:2368-2374 z[0] = -1, then propagate z[] top-down
    ///   7. cc:2376-2384 build augment[] walking k = z[k]
    pub fn build_adt(&mut self, fd: &Funcdata) {
        let bblocks = &fd.bblocks;
        let size = bblocks.get_size();
        if size == 0 {
            return;
        }

        // cc:2329-2332: clear + resize (Ghidra leaves stale domchild to
        // buildDomTree, which clears/resizes itself).
        self.augment.clear();
        self.augment.resize(size, Vec::new());
        self.flags.clear();
        self.flags.resize(size, 0);

        // cc:2334: bblocks.buildDomTree(domchild). Faithful to
        // BlockGraph::buildDomTree (block.cc:2036-2051): child[immed_dom]
        // gets the block appended in list order; blocks whose immed_dom is
        // null land in the extra dead bucket at index `size`.
        self.domchild.clear();
        self.domchild.resize(size + 1, Vec::new());
        for i in 0..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let idom_idx = block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
            match idom_idx {
                Some(idx) if (idx as usize) < size => {
                    self.domchild[idx as usize].push(i as i32);
                }
                _ => {
                    // Null (or out-of-range) immediate dominator: dead bucket.
                    self.domchild[size].push(i as i32);
                }
            }
        }

        // cc:2338: bblocks.buildDomDepth(depth). Faithful to
        // BlockGraph::buildDomDepth (block.cc:2056-2075): iterate blocks in
        // list order; depth[i] = depth[immed_dom]+1, or 1 when the immediate
        // dominator is null; trailing sentinel depth[size] = 0; return max.
        let mut depth = vec![0i32; size + 1];
        let mut maxdepth = 0i32;
        for i in 0..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let idom_idx = block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
            depth[i] = match idom_idx {
                Some(idx) if (idx as usize) < size => depth[idx as usize] + 1,
                _ => 1,
            };
            if maxdepth < depth[i] {
                maxdepth = depth[i];
            }
        }
        depth[size] = 0;
        self.depth = depth;
        self.maxdepth = maxdepth;

        // cc:2339-2353: find up-edges + count b[]/t[].
        // For every dominator-tree child v of x, every in-edge u of v with
        // u != immed_dom(v) is an up-edge; b[u] counts edges ending at u,
        // t[x] counts edges starting under x.
        let mut b_count = vec![0i32; size]; // up-edges ending at node
        let mut t_count = vec![0i32; size]; // up-edges starting under node
        let mut upstart = Vec::new(); // up-edge source indices
        let mut upend = Vec::new(); // up-edge target indices

        for i in 0..size {
            for &cidx in &self.domchild[i] {
                let v = match bblocks.get_block(cidx as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let v_guard = v.read().unwrap();
                let v_idom = v_guard
                    .get_immed_dom()
                    .and_then(|w| w.upgrade())
                    .map(|dom| dom.read().unwrap().get_index());
                let v_sin = v_guard.size_in();
                for k in 0..v_sin {
                    let bank = v_guard.bank();
                    // (W2) shadow read: the up-edge test needs only the
                    // predecessor's index — bank-served (block.hh:160), no
                    // peer handle/lock (oracle reads `u != immed_dom(v)`
                    // as a pointer compare on field state).
                    let u_idx = match v_guard.get_in(k) {
                        Some(e) => bank.expect_index(e.point),
                        None => continue,
                    };
                    if Some(u_idx) != v_idom {
                        // Up-edge: u -> v (pointer identity in Ghidra;
                        // block indices are unique per graph in Rugra).
                        upstart.push(u_idx);
                        upend.push(cidx);
                        b_count[u_idx as usize] += 1;
                        t_count[i] += 1;
                    }
                }
            }
        }

        // cc:2354-2367: bottom-up a[]/z[] + boundary marking.
        let mut a_count = vec![0i32; size];
        let mut z = vec![0i32; size];
        for i in (0..size).rev() {
            let mut k_sum = 0i32;
            let mut l_sum = 0i32;
            for &cidx in &self.domchild[i] {
                let c = cidx as usize;
                if c < size {
                    k_sum += a_count[c];
                    l_sum += z[c];
                }
            }
            a_count[i] = b_count[i] - t_count[i] + k_sum;
            z[i] = 1 + l_sum;
            if self.domchild[i].is_empty() || z[i] > a_count[i] + 1 {
                self.flags[i] |= heritage_flags::BOUNDARY_NODE;
                z[i] = 1;
            }
        }

        // cc:2368: z[0] = -1
        if !z.is_empty() {
            z[0] = -1;
        }

        // cc:2369-2374: propagate z through boundary chains.
        for i in 1..size {
            let block = match bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let j = match block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
            {
                Some(dom) => dom.read().unwrap().get_index() as usize,
                None => continue,
            };
            if j < size && (self.flags[j] & heritage_flags::BOUNDARY_NODE) != 0 {
                z[i] = j as i32;
            } else if j < size {
                z[i] = z[j];
            }
        }

        // cc:2376-2384: build augment[] from up-edges.
        for idx in 0..upstart.len() {
            let v_idx = upend[idx];
            let v_block = match bblocks.get_block(v_idx as usize) {
                Some(b) => b,
                None => continue,
            };
            let mut j = v_block
                .read()
                .unwrap()
                .get_immed_dom()
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index())
                .unwrap_or(0);
            let mut k = upstart[idx];
            while j < k {
                if (k as usize) < self.augment.len() {
                    self.augment[k as usize].push(v_idx);
                }
                let zk = z.get(k as usize).copied().unwrap_or(0);
                if zk <= 0 || zk >= k {
                    // Path compression must strictly decrease k toward j.
                    break;
                }
                k = zk;
            }
        }
    }

    // Ghidra: heritage.cc:2394 Heritage::visitIncr
    /// Recursive phi-node placement using the ADT. Faithful to
    /// `visitIncr` (heritage.cc:2394-2428). Walks augment[vnode] and
    /// recurses into dom children (unless boundary node).
    pub fn visit_incr(&mut self, fd: &Funcdata, qnode_idx: i32, vnode_idx: i32) {
        let i = vnode_idx as usize;
        // cc:2404-2421: scan augment[i] for phi candidates.
        let aug_snapshot = self.augment.get(i).cloned().unwrap_or_default();
        for v_idx in aug_snapshot {
            let v_idom = fd
                .bblocks
                .get_block(v_idx as usize)
                .and_then(|b| b.read().unwrap().get_immed_dom())
                .and_then(|w| w.upgrade())
                .map(|dom| dom.read().unwrap().get_index());
            // cc:2408: if idom(v) < qnode (strict ancestor)
            if v_idom.map_or(false, |idom| idom < qnode_idx) {
                let k = v_idx as usize;
                if k < self.flags.len() {
                    // cc:2410-2413: merge if not merged_node
                    if (self.flags[k] & heritage_flags::MERGED_NODE) == 0 {
                        self.merge.push(k as i32);
                        self.flags[k] |= heritage_flags::MERGED_NODE;
                    }
                    // cc:2414-2417: mark + pq.insert if not mark_node
                    if (self.flags[k] & heritage_flags::MARK_NODE) == 0 {
                        self.flags[k] |= heritage_flags::MARK_NODE;
                        self.pq
                            .insert(v_idx, self.depth.get(k).copied().unwrap_or(0));
                    }
                }
            } else {
                break; // cc:2419-2420: augment is sorted, stop at first non-ancestor
            }
        }
        // cc:2422-2428: if vnode is not boundary, recurse into dom children.
        if i < self.flags.len() && (self.flags[i] & heritage_flags::BOUNDARY_NODE) == 0 {
            let children = self.domchild.get(i).cloned().unwrap_or_default();
            for child_idx in children {
                let c = child_idx as usize;
                if c < self.flags.len() && (self.flags[c] & heritage_flags::MARK_NODE) == 0 {
                    self.visit_incr(fd, qnode_idx, child_idx);
                }
            }
        }
    }

    // Ghidra: heritage.cc:2439 Heritage::calcMultiequals
    /// Calculate blocks that should contain MULTIEQUALs for one address range.
    /// Faithful to `calcMultiequals` (heritage.cc:2439-2466): consumes the
    /// normalized write Varnode list, derives each write's block from
    /// `write[i]->getDef()->getParent()` (cc:2449), always seeds block 0
    /// (cc:2455-2458), and clears mark/merged flags only after queue
    /// exhaustion (cc:2464-2465). A write whose defining op lost its parent
    /// block cannot occur in the locked oracle (cc:2449 would dereference
    /// it); Rust skips such an entry rather than indexing the flags array
    /// with an invalid block.
    pub fn calc_multiequals(&mut self, fd: &Funcdata, write: &[Arc<RwLock<Varnode>>]) {
        // cc:2442: pq.reset(maxdepth)
        self.pq.reset(self.maxdepth);
        // cc:2443: merge.clear()
        self.merge.clear();

        // cc:2448-2454: place write blocks into pq.
        for vn_arc in write {
            let vn = vn_arc.read().unwrap();
            let blk_idx = match vn
                .def
                .as_ref()
                .and_then(|w| w.upgrade())
                .and_then(|def| {
                def.read()
                    .unwrap()
                    .parent
                    .as_ref()
                    .and_then(|p| p.upgrade())
            })
            {
                Some(parent) => parent.read().unwrap().get_index(),
                None => continue,
            };
            let j = blk_idx as usize;
            if j < self.flags.len() && (self.flags[j] & heritage_flags::MARK_NODE) != 0 {
                continue; // Already in
            }
            self.pq
                .insert(blk_idx, self.depth.get(j).copied().unwrap_or(0));
            if j < self.flags.len() {
                self.flags[j] |= heritage_flags::MARK_NODE;
            }
        }
        // cc:2455-2458: ensure block 0 is in pq.
        if !self.flags.is_empty() && (self.flags[0] & heritage_flags::MARK_NODE) == 0 {
            self.pq.insert(0, self.depth.get(0).copied().unwrap_or(0));
            self.flags[0] |= heritage_flags::MARK_NODE;
        }

        // cc:2460-2463: main loop.
        while !self.pq.empty() {
            let bl = self.pq.extract();
            self.visit_incr(fd, bl, bl);
        }

        // cc:2464-2465: clear marks.
        for f in &mut self.flags {
            *f &= !(heritage_flags::MARK_NODE | heritage_flags::MERGED_NODE);
        }
    }

    // RUDRA-GLUE: Rugra-specific stack-store discovery; no 1:1 Ghidra function.
    /// Forward-descend the stack-pointer input varnode, mark STOREs whose
    /// pointer reaches it as spacebase users, and materialize stack-space
    /// INDIRECT writes for them. This is Rugra's approximation of the
    /// marking half of `Heritage::discoverIndexedStackPointers`
    /// (heritage.cc:985-1108) + `protectFreeStores` (heritage.cc:943-968,
    /// `opMarkSpacebasePtr`); it does not implement the indexed-pointer
    /// traversal states (HERITAGE-CALLGUARD-0001 residual family).
    /// Since HERITAGE-DRIVER-SWITCH-0001 the production ActionHeritage no
    /// longer calls this between passes: canonical placeMultiequals runs
    /// its own guard/stores logic per range. Remaining callers are the
    /// reprocessFreeStores approximation and tests.
    pub fn discover_and_guard_stack_stores_fd(fd: &mut Funcdata) {
        let (sp_space, sp_offset, sp_size) = (
            fd.stack_pointer_space,
            fd.stack_pointer_offset,
            fd.stack_pointer_size,
        );
        // Find the RSP input varnode (shared, with accumulated descend).
        let rsp_input: Option<Arc<RwLock<Varnode>>> = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|v| {
                let g = v.0.read().unwrap();
                g.get_space() == sp_space
                    && g.get_offset() == sp_offset
                    && g.get_size() == sp_size
                    && g.is_input()
            })
            .map(|v| v.0.clone())
            .next();
        let rsp_input = match rsp_input {
            Some(r) => {
                let nd = r.read().unwrap().descend.len();
                r
            }
            None => return,
        };

        // Forward-descend BFS from RSP input.
        let mut worklist: VecDeque<(Arc<RwLock<Varnode>>, i64)> = VecDeque::new();
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        worklist.push_back((rsp_input.clone(), 0));
        visited.insert(Arc::as_ptr(&rsp_input) as usize);

        let mut stores_to_guard: Vec<(Arc<RwLock<PcodeOp>>, i64)> = Vec::new();

        while let Some((vn, offset)) = worklist.pop_front() {
            let descendants: Vec<Arc<RwLock<PcodeOp>>> = {
                let g = vn.read().unwrap();
                g.descend.iter().filter_map(|w| w.upgrade()).collect()
            };
            for d in &descendants {
            }
            for desc_op in descendants {
                let op_guard = desc_op.read().unwrap();
                let opc = op_guard.opcode;
                match opc {
                    crate::opcodes::OpCode::CPUI_STORE => {
                        // STORE(space, addr, val). addr is inrefs[1].
                        if op_guard.inrefs.len() > 1 && Arc::ptr_eq(&op_guard.inrefs[1], &vn) {
                            stores_to_guard.push((desc_op.clone(), offset));
                            drop(op_guard);
                            desc_op.write().unwrap().mark_spacebase_ptr();
                        }
                    }
                    crate::opcodes::OpCode::CPUI_INT_ADD
                    | crate::opcodes::OpCode::CPUI_INT_SUB => {
                        if let Some(out) = &op_guard.output {
                            let other_idx = if Arc::ptr_eq(&op_guard.inrefs[0], &vn) {
                                1
                            } else {
                                0
                            };
                            if let Some(other) = op_guard.inrefs.get(other_idx) {
                                let other_g = other.read().unwrap();
                                if other_g.is_constant() {
                                    let delta = other_g.get_offset() as i64;
                                    let new_offset = if opc
                                        == crate::opcodes::OpCode::CPUI_INT_ADD
                                    {
                                        offset.wrapping_add(delta)
                                    } else {
                                        offset.wrapping_sub(delta)
                                    };
                                    let out_clone = out.clone();
                                    let out_ptr = Arc::as_ptr(&out_clone) as usize;
                                    drop(other_g);
                                    drop(op_guard);
                                    if visited.insert(out_ptr) {
                                        worklist.push_back((out_clone, new_offset));
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    crate::opcodes::OpCode::CPUI_COPY => {
                        if let Some(out) = &op_guard.output {
                            let out_clone = out.clone();
                            let out_ptr = Arc::as_ptr(&out_clone) as usize;
                            drop(op_guard);
                            if visited.insert(out_ptr) {
                                worklist.push_back((out_clone, offset));
                            }
                            continue;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Phase 2: build Stack INDIRECT ops for each discovered STORE.
        // Mirrors guardStores' constructor call (heritage.cc:1553-1556):
        // newIndirectOp(op, addr, size, PcodeOp::indirect_store) followed by
        // setActiveHeritage on input[0] and output.
        for (store_op, stack_off) in stores_to_guard {
            let sz = {
                let s = store_op.read().unwrap();
                s.inrefs
                    .get(2)
                    .map(|v| v.read().unwrap().get_size())
                    .unwrap_or(8)
            };
            let store_ref = crate::op::PcodeOpRef(store_op);
            let indop = fd.new_indirect_op(
                &store_ref,
                AddressSpace::Stack,
                stack_off as u64,
                sz,
                crate::op::pcodeop_flags::INDIRECT_STORE,
            );
            let (in0, out) = {
                let r = indop.0.read().unwrap();
                (r.get_in(0).cloned(), r.output.as_ref().cloned())
            };
            if let Some(vn) = in0 { vn.write().unwrap().set_active_heritage(); }
            if let Some(vn) = out { vn.write().unwrap().set_active_heritage(); }
        }
    }

    // Ghidra: heritage.cc:909 Heritage::generateLoadGuard
    /// Generate a guard record given an indexed LOAD into a stack space.
    /// Faithful to `generateLoadGuard` (heritage.cc:909-917): if the op is
    /// not already marked as a spacebase user, append an unanalyzed
    /// `LoadGuard` (pointerBase = the path's accumulated offset) and mark
    /// the op.
    fn generate_load_guard(
        &mut self,
        fd: &Funcdata,
        op: &Arc<RwLock<PcodeOp>>,
        spc: AddressSpace,
        node_offset: u64,
    ) {
        // cc:912: if (!op->usesSpacebasePtr())
        if !op.read().unwrap().uses_spacebase_ptr() {
            // cc:913-914: loadGuard.emplace_back(); loadGuard.back().set(op,spc,node.offset)
            self.load_guard
                .push(LoadGuard::new_unanalyzed(op, spc, node_offset));
            // cc:915: fd->opMarkSpacebasePtr(op)
            fd.op_mark_spacebase_ptr(&PcodeOpRef(op.clone()));
        }
    }

    // Ghidra: heritage.cc:926 Heritage::generateStoreGuard
    /// Generate a guard record given an indexed STORE to a stack space.
    /// Faithful to `generateStoreGuard` (heritage.cc:926-936): same
    /// !usesSpacebasePtr gate as `generate_load_guard`, appending into
    /// `storeGuard`.
    fn generate_store_guard(
        &mut self,
        fd: &Funcdata,
        op: &Arc<RwLock<PcodeOp>>,
        spc: AddressSpace,
        node_offset: u64,
    ) {
        if !op.read().unwrap().uses_spacebase_ptr() {
            self.store_guard
                .push(LoadGuard::new_unanalyzed(op, spc, node_offset));
            fd.op_mark_spacebase_ptr(&PcodeOpRef(op.clone()));
        }
    }

    // Ghidra: heritage.cc:944 Heritage::protectFreeStores
    /// Identify STORE ops that use a free pointer from the given address
    /// space. Faithful to `protectFreeStores` (heritage.cc:944-972): for
    /// every live STORE (bank order), follow the pointer input through
    /// COPY and INT_ADD(constant) chains to the base Varnode; if that base
    /// is free (neither written nor input, varnode.hh:238) and lives in
    /// \p space, mark the STORE as a spacebase user and append it to
    /// \p free_stores.
    pub fn protect_free_stores(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        free_stores: &mut Vec<Arc<RwLock<PcodeOp>>>,
    ) -> bool {
        let mut has_new = false;
        // cc:947-952: iterate beginOp(CPUI_STORE)..endOp, skipping dead ops.
        let store_arcs: Vec<Arc<RwLock<PcodeOp>>> = fd
            .obank
            .iter_store()
            .filter(|s| (s.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD) == 0)
            .map(|s| s.0.clone())
            .collect();
        for store_arc in store_arcs {
            // cc:954: vn = op->getIn(1)
            let mut vn = match store_arc.read().unwrap().get_in(1) {
                Some(v) => v.clone(),
                None => continue,
            };
            // cc:955-964: follow COPY / INT_ADD(constant) definitions.
            loop {
                let next_vn: Option<Arc<RwLock<Varnode>>> = {
                    let v = vn.read().unwrap();
                    if !v.is_written() {
                        break;
                    }
                    let def_op = match v.def.as_ref().and_then(|w| w.upgrade()) {
                        Some(d) => d,
                        None => break,
                    };
                    let d = def_op.read().unwrap();
                    match d.opcode {
                        // cc:958-959: COPY — follow in(0)
                        OpCode::CPUI_COPY => d.get_in(0).cloned(),
                        // cc:960-961: INT_ADD with constant second input — follow in(0)
                        OpCode::CPUI_INT_ADD
                            if d.get_in(1)
                                .map(|iv| iv.read().unwrap().is_constant())
                                .unwrap_or(false) =>
                        {
                            d.get_in(0).cloned()
                        }
                        // cc:962-963: any other definition ends the chase
                        _ => None,
                    }
                };
                match next_vn {
                    Some(next) => vn = next,
                    None => break,
                }
            }
            // cc:965-969: if (vn->isFree() && vn->getSpace() == spc)
            let is_free_in_space = {
                let v = vn.read().unwrap();
                !v.is_written() && !v.is_input() && v.address_space == space
            };
            if is_free_in_space {
                fd.op_mark_spacebase_ptr(&PcodeOpRef(store_arc.clone()));
                free_stores.push(store_arc);
                has_new = true;
            }
        }
        has_new
    }

    // Ghidra: heritage.cc:986 Heritage::discoverIndexedStackPointers
    /// Trace the input stack pointer to any indexed loads. Faithful to
    /// `discoverIndexedStackPointers` (heritage.cc:986-1102): an explicit
    /// depth-first walk (with Varnode marks preventing exponential
    /// ladders) over the data-flow reachable from the space's spacebase
    /// input. Constant `INT_ADD`s accumulate the offset, non-constant
    /// `INT_ADD`s and `MULTIEQUAL`s set traversal bits; a `LOAD`/`STORE`
    /// reached with a non-zero traversal mask generates a guard record
    /// (via `generate_load_guard`/`generate_store_guard`), a `STORE` with
    /// a zero mask is merely marked
    /// (cc:1082-1088). Returns \b true (and fills \p free_stores via
    /// `protectFreeStores`, cc:1099-1100) when the walk found
    /// spacebase-space dead-ends and \p check_free_stores is set.
    pub fn discover_indexed_stack_pointers(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        free_stores: &mut Vec<Arc<RwLock<PcodeOp>>>,
        check_free_stores: bool,
    ) -> bool {
        // cc:989-993: markedVn / path / unknownStackStorage.
        let mut marked_vn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut unknown_stack_storage = false;
        // cc:994: for(int4 i=0;i<spc->numSpacebase();++i). In the enum
        // space model only the Stack (spacebase) space has a spacebase
        // register, held by Funcdata's stack_pointer_* fields (RSP on
        // x86:LE:64).
        if space == AddressSpace::Stack {
            // cc:995-997: spInput = fd->findVarnodeInput(size, addr)
            let sp_input: Option<Arc<RwLock<Varnode>>> = fd
                .vbank
                .loc_tree
                .iter()
                .filter(|v| {
                    let g = v.0.read().unwrap();
                    g.is_input()
                        && g.get_space() == fd.stack_pointer_space
                        && g.get_offset() == fd.stack_pointer_offset
                        && g.get_size() == fd.stack_pointer_size
                })
                .map(|v| v.0.clone())
                .next();
            if let Some(sp_input) = sp_input {
                // cc:998: path.push_back(StackNode(spInput,0,0))
                let mut path: Vec<StackWalkNode> = vec![StackWalkNode {
                    vn: sp_input,
                    offset: 0,
                    traversals: 0,
                    iter: 0,
                }];
                // cc:999: while(!path.empty())
                while !path.is_empty() {
                    // cc:1001-1004: pop when this node's descendants are
                    // exhausted; otherwise fetch the next descendant op.
                    // (Dead weak refs have no Ghidra counterpart — the
                    // oracle's descend list only holds live ops.)
                    let next_op: Option<Arc<RwLock<PcodeOp>>> = {
                        let cur = path.last_mut().expect("path non-empty");
                        let descend: Vec<Weak<RwLock<PcodeOp>>> =
                            cur.vn.read().unwrap().descend.clone();
                        let mut found = None;
                        while cur.iter < descend.len() {
                            let weak = descend[cur.iter].clone();
                            cur.iter += 1;
                            if let Some(op) = weak.upgrade() {
                                found = Some(op);
                                break;
                            }
                        }
                        found
                    };
                    let op = match next_op {
                        Some(op) => op,
                        None => {
                            path.pop();
                            continue;
                        }
                    };
                    let (cur_vn, cur_offset, cur_traversals) = {
                        let cur = path.last().expect("path non-empty");
                        (cur.vn.clone(), cur.offset, cur.traversals)
                    };
                    // cc:1007: outVn = op->getOut()
                    let (out_vn, opcode) = {
                        let o = op.read().unwrap();
                        (o.output.clone(), o.opcode)
                    };
                    // cc:1008: if (outVn != 0 && outVn->isMark()) continue
                    if let Some(out) = &out_vn {
                        if out.read().unwrap().is_mark() {
                            continue;
                        }
                    }
                    // cc:1009-1094: switch(op->code())
                    match opcode {
                        OpCode::CPUI_INT_ADD => {
                            // cc:1012: otherVn = op->getIn(1-op->getSlot(curNode.vn))
                            let other_vn = {
                                let o = op.read().unwrap();
                                let slot = (0..o.num_input())
                                    .find(|&i| {
                                        o.get_in(i)
                                            .map(|v| Arc::ptr_eq(&v, &cur_vn))
                                            .unwrap_or(false)
                                    })
                                    .unwrap_or(0);
                                o.get_in(1 - slot).cloned()
                            };
                            let (new_offset, new_traversals) = match &other_vn {
                                Some(other) if other.read().unwrap().is_constant() => {
                                    // cc:1014: wrapOffset(offset + const)
                                    let add = other.read().unwrap().get_offset();
                                    (
                                        cur_offset.wrapping_add(add),
                                        cur_traversals,
                                    )
                                }
                                _ => (
                                    cur_offset,
                                    cur_traversals | STACK_WALK_NONCONSTANT_INDEX,
                                ),
                            };
                            Self::stack_walk_push(
                                &mut path,
                                &mut marked_vn,
                                &mut unknown_stack_storage,
                                space,
                                out_vn,
                                new_offset,
                                new_traversals,
                            );
                        }
                        OpCode::CPUI_SEGMENTOP => {
                            // cc:1038: only if the stackpointer comes in as
                            // the inner pointer (in(2)); then COPY semantics.
                            let is_inner = {
                                let o = op.read().unwrap();
                                o.get_in(2).map(|v| Arc::ptr_eq(&v, &cur_vn)).unwrap_or(false)
                            };
                            if is_inner {
                                Self::stack_walk_push(
                                    &mut path,
                                    &mut marked_vn,
                                    &mut unknown_stack_storage,
                                    space,
                                    out_vn,
                                    cur_offset,
                                    cur_traversals,
                                );
                            }
                        }
                        OpCode::CPUI_INDIRECT | OpCode::CPUI_COPY => {
                            // cc:1044: same offset and traversals.
                            Self::stack_walk_push(
                                &mut path,
                                &mut marked_vn,
                                &mut unknown_stack_storage,
                                space,
                                out_vn,
                                cur_offset,
                                cur_traversals,
                            );
                        }
                        OpCode::CPUI_MULTIEQUAL => {
                            // cc:1056: traversals |= multiequal
                            Self::stack_walk_push(
                                &mut path,
                                &mut marked_vn,
                                &mut unknown_stack_storage,
                                space,
                                out_vn,
                                cur_offset,
                                cur_traversals | STACK_WALK_MULTIEQUAL,
                            );
                        }
                        OpCode::CPUI_LOAD => {
                            // cc:1071-1073: if (curNode.traversals != 0)
                            // generateLoadGuard(curNode,op,spc)
                            if cur_traversals != 0 {
                                self.generate_load_guard(fd, &op, space, cur_offset);
                            }
                        }
                        OpCode::CPUI_STORE => {
                            // cc:1078: make sure the STORE pointer comes
                            // from our path
                            let is_pointer_input = {
                                let o = op.read().unwrap();
                                o.get_in(1).map(|v| Arc::ptr_eq(&v, &cur_vn)).unwrap_or(false)
                            };
                            if is_pointer_input {
                                if cur_traversals != 0 {
                                    // cc:1080: generateStoreGuard
                                    self.generate_store_guard(fd, &op, space, cur_offset);
                                } else {
                                    // cc:1087: fd->opMarkSpacebasePtr(op)
                                    fd.op_mark_spacebase_ptr(&PcodeOpRef(op.clone()));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // cc:1097-1098: clear marks
        for vn in &marked_vn {
            vn.write().unwrap().clear_mark();
        }
        // cc:1099-1101
        if unknown_stack_storage && check_free_stores {
            return self.protect_free_stores(fd, space, free_stores);
        }
        false
    }

    // RUDRA-GLUE: Rust helper factoring the shared push-or-dead-end tail of
    // the four discoverIndexedStackPointers switch cases (heritage.cc:1015-
    // 1022 / 1045-1051 / 1057-1063); Ghidra has no separate function.
    // A chain node with at least one live descendant is marked and pushed;
    // a chain dead-end whose output lives in the spacebase (stack) space
    // sets the unknownStackStorage flag.
    #[allow(clippy::too_many_arguments)]
    fn stack_walk_push(
        path: &mut Vec<StackWalkNode>,
        marked_vn: &mut Vec<Arc<RwLock<Varnode>>>,
        unknown_stack_storage: &mut bool,
        space: AddressSpace,
        out_vn: Option<Arc<RwLock<Varnode>>>,
        offset: u64,
        traversals: u32,
    ) {
        let out_vn = match out_vn {
            Some(o) => o,
            None => return,
        };
        // cc:1016/1026/1045/1057: nextNode.iter != nextNode.vn->endDescend()
        let has_live_descendant = out_vn
            .read()
            .unwrap()
            .descend
            .iter()
            .any(|w| w.upgrade().is_some());
        if has_live_descendant {
            // cc:1017-1019/1046-1048: outVn->setMark(); path.push_back
            out_vn.write().unwrap().set_mark();
            marked_vn.push(out_vn.clone());
            path.push(StackWalkNode {
                vn: out_vn,
                offset,
                traversals,
                iter: 0,
            });
        } else if out_vn.read().unwrap().address_space == space {
            // cc:1021-1022/1050-1051: outVn in a SPACEBASE-typed space
            // (the enum model's Stack) — unknown stack storage.
            *unknown_stack_storage = true;
        }
    }

    // ======================================================================
    // LoadGuard / StoreGuard population.
    //
    // These mirror Ghidra's `Heritage::guard*` family (heritage.cc:1157-1693)
    // together with `generateLoadGuard`/`generateStoreGuard`
    // (heritage.cc:910-935), which `discoverIndexedStackPointers` calls while
    // tracing the stack pointer. The Ghidra variants split responsibilities:
    //
    //   generateStoreGuard/generateLoadGuard -- create the LoadGuard record
    //       (op, spc, pointerBase) and `emplace_back` it into storeGuard/
    //       loadGuard. They are guarded by `!op->usesSpacebasePtr()` and call
    //       `fd->opMarkSpacebasePtr(op)`.
    //
    //   guardStores/guardLoads/guardCalls/guardReturns -- run during `guard()`
    //       (heritage.cc:1157) to build the INDIRECT/COPY ops that make SSA
    //       renaming see the memory effect, and (for guardLoads) to drop stale
    //       guard records.
    //
    // Rugra's pragmatic policy (per the alignment task) is to *populate* the
    // store_guard/load_guard Vecs so that `get_store_guard`/`get_load_guard`
    // return non-`None` and RuleActionShadowOp's store-alias check works. We
    // therefore implement the record-creation half faithfully and leave the
    // value-set-analysis refinement (establishRange/finalizeRange) as TODO.
    // ======================================================================

    /// Guard STORE ops in preparation for renaming.
    ///
    /// Faithful to `Heritage::guardStores` (heritage.cc:1539-1560) combined
    /// with `generateStoreGuard` (heritage.cc:927-935): for every live STORE
    /// that targets the stack space and was marked as using a spacebase
    /// pointer, create a `LoadGuard` record in `store_guard` (if not already
    /// present) and build a Stack-space INDIRECT so renaming sees the memory
    /// write.
    ///
    /// Differences from Ghidra: Ghidra's `guardStores` iterates by address
    /// range (`addr`/`size`) and creates the INDIRECT via `newIndirectOp`.
    /// Rugra does not yet drive guarding per disjoint memory range (the SSA
    /// pipeline calls this once per heritage pass), so we guard the *whole*
    /// stack space — i.e. every spacebase-marked STORE — which is the
    /// conservative superset and never under-protects. The full-range
    /// INDIRECTs are produced by `discover_and_guard_stack_stores_fd`; here we
    /// only ensure each such STORE has a guard record.
    // Ghidra: heritage.cc:1538 Heritage::guardStores
    pub fn guard_stores(&mut self, fd: &mut Funcdata) {
        // Snapshot of (op_arc, store_space, spc) for STOREs that need a guard
        // record. We collect under a read borrow so we can later mutate the
        // obank (mark_spacebase_ptr) without holding it.
        let mut to_guard: Vec<(
            std::sync::Arc<std::sync::RwLock<PcodeOp>>,
            AddressSpace)> = Vec::new();

        for op_ref in &fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            if op.opcode != crate::opcodes::OpCode::CPUI_STORE {
                continue;
            }
            if (op.flags & crate::op::pcodeop_flags::DEAD) != 0 {
                continue; // heritage.cc:1550
            }
            // STORE inputs: in[0]=space-id constant, in[1]=pointer, in[2]=value.
            // `getSpaceFromConst` on in[0] gives the target space. If a STORE
            // has no in[0] (malformed), skip it.
            let store_space = match op.inrefs.first() {
                Some(vn) => vn.read().unwrap().get_space(),
                None => continue,
            };
            // STORE space constants are encoded as Const-space varnodes whose
            // offset carries the space id (see space.rs SPACEID_*). Recover it.
            // Accept either the CONSTANT flag or a Const address space, since
            // both encodings appear (lifter uses the flag; manual construction
            // may set only the space).
            let target_space = op
                .inrefs
                .first()
                .and_then(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() || g.get_space().is_const() {
                        Some(AddressSpace::from_id(g.get_offset() as u8))
                    } else {
                        None
                    }
                })
                .unwrap_or(store_space);
            // heritage.cc:1552: a STORE is guarded if its target space is the
            //   container of `spc` AND usesSpacebasePtr(), OR if its target
            //   space == spc. Rugra's stack space has no separate "container"
            //   space, so we simply guard STOREs targeting the stack space that
            //   are spacebase-marked (the indexed case), plus any STORE the
            //   existing discovery already flagged.
            let is_stack = target_space.is_stack();
            if is_stack && op.uses_spacebase_ptr() {
                to_guard.push((op_ref.0.clone(), AddressSpace::Stack));
            }
        }

        // Create the guard records (dedup against existing entries — a STORE
        // may survive multiple heritage passes). Mirrors generateStoreGuard's
        // `!op->usesSpacebasePtr()` guard: once marked, we don't add a second
        // record for the same op.
        for (store_op, spc) in to_guard {
            if self.store_guard.iter().any(|g| match g.op.upgrade() {
                Some(g_op) => std::sync::Arc::ptr_eq(&g_op, &store_op),
                None => false,
            }) {
                continue;
            }
            let pointer_base = store_guard_pointer_base(&store_op, &fd);
            // generateStoreGuard marks the op spacebase again (idempotent).
            store_op.write().unwrap().mark_spacebase_ptr();
            self.store_guard
                .push(LoadGuard::new_unanalyzed(&store_op, spc, pointer_base));
        }
    }

    /// Guard LOAD ops in preparation for renaming.
    ///
    /// Faithful to `Heritage::guardLoads` (heritage.cc:1571-1602) combined
    /// with `generateLoadGuard` (heritage.cc:910-918): for every live LOAD
    /// reading from an indexed stack-space pointer, create a `LoadGuard`
    /// record in `load_guard` (if not already present). Mirrors Ghidra's
    /// validity pruning (`isValid`) by dropping records whose op is dead or no
    /// longer a LOAD.
    ///
    /// Differences from Ghidra: Ghidra inserts a `COPY` "guard" op before each
    /// guarded LOAD (heritage.cc:1591-1600) to force a specific address, and
    /// only guards LOADs whose indexed range intersects the heritage range.
    /// Rugra builds the guard records for all stack-pointer-indexed LOADs
    /// (conservative superset) and defers the COPY insertion to a future
    /// per-range driver. Value-set analysis is not run yet, so each guard
    /// initially protects the whole stack space.
    // Ghidra: heritage.cc:1570 Heritage::guardLoads
    pub fn guard_loads(&mut self, fd: &mut Funcdata) {
        // Prune stale load_guard records (heritage.cc:1581-1586 isValid check).
        self.load_guard.retain(|g| {
            let op = match g.op.upgrade() {
                Some(o) => o,
                None => return false,
            };
            let opg = op.read().unwrap();
            !((opg.flags & crate::op::pcodeop_flags::DEAD) != 0
                || opg.opcode != crate::opcodes::OpCode::CPUI_LOAD)
        });

        // Collect LOADs that read an indexed stack-space pointer.
        let mut to_guard: Vec<(
            std::sync::Arc<std::sync::RwLock<PcodeOp>>,
            AddressSpace)> = Vec::new();
        for op_ref in &fd.obank.optree {
            let op = op_ref.0.read().unwrap();
            if op.opcode != crate::opcodes::OpCode::CPUI_LOAD {
                continue;
            }
            if (op.flags & crate::op::pcodeop_flags::DEAD) != 0 {
                continue;
            }
            // LOAD inputs: in[0]=space-id constant, in[1]=pointer.
            let target_space = op
                .inrefs
                .first()
                .and_then(|v| {
                    let g = v.read().unwrap();
                    if g.is_constant() || g.get_space().is_const() {
                        Some(AddressSpace::from_id(g.get_offset() as u8))
                    } else {
                        None
                    }
                })
                .unwrap_or(AddressSpace::Ram);
            if !target_space.is_stack() {
                continue;
            }
            // generateLoadGuard only records a LOAD once (!usesSpacebasePtr)
            // and then marks it. We mirror that by skipping already-marked
            // LOADs for record creation below.
            to_guard.push((op_ref.0.clone(), AddressSpace::Stack));
        }

        for (load_op, spc) in to_guard {
            if self.load_guard.iter().any(|g| match g.op.upgrade() {
                Some(g_op) => std::sync::Arc::ptr_eq(&g_op, &load_op),
                None => false,
            }) {
                continue;
            }
            let pointer_base = load_guard_pointer_base(&load_op, &fd);
            load_op.write().unwrap().mark_spacebase_ptr();
            self.load_guard
                .push(LoadGuard::new_unanalyzed(&load_op, spc, pointer_base));
        }
    }

    // Ghidra: heritage.cc:1443 Heritage::guardCalls
    /// Guard CALL/CALLIND ops in preparation for the renaming algorithm.
    /// Faithful 1:1 port of `Heritage::guardCalls` (heritage.cc:1443-1527).
    ///
    /// For the given address range, decide what the data-flow effect is
    /// across each call site in the function. If an effect is unknown (or a
    /// return address), an INDIRECT op is added via `newIndirectOp`
    /// (prepopulating data-flow through the call); if the range is
    /// killed-by-call, an indirectly-created INDIRECT is added via
    /// `newIndirectCreation`. Any new INDIRECT output is appended to `write`
    /// in creation order — the same vector calcMultiequals consumes.
    ///
    /// Per cc:1451-1527 the loop order is callspec order (`i < numCalls`),
    /// and each callspec contributes at most one INDIRECT per range; the
    /// stack-spacebase translation (cc:1460-1465) rebases the query offset
    /// by the callspec's resolved stackoffset, disabling register trials
    /// entirely when the offset is unknown.
    pub fn guard_calls(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        space: AddressSpace,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1450: holdind = ((fl & Varnode::addrtied) != 0)
        let holdind = (fl & crate::varnode::varnode_flags::ADDRTIED) != 0;
        // cc:1451: for(int4 i=0;i<fd->numCalls();++i)
        for i in 0..fd.num_calls() {
            // cc:1452: fc = fd->getCallSpecs(i);
            // cc:1453-1456: if the call op is an assignment whose output IS
            // this exact range, this range is already the return value — no
            // guard is added for it.
            let call_op = match fd.get_call_specs(i).and_then(|fc| fc.find_call_op(fd)) {
                Some(op) => op,
                None => continue,
            };
            {
                let is_assignment = call_op.0.read().unwrap().is_assignment();
                if is_assignment {
                    let out_match = call_op.0.read().unwrap().output.as_ref().map(|vn| {
                        let v = vn.read().unwrap();
                        v.address_space == space && v.loc == addr && v.get_size() as i32 == size
                    });
                    if out_match == Some(true) {
                        continue;
                    }
                }
            }
            // cc:1457-1466: compute the callee-perspective address.
            //   spc = addr.getSpace(); off = addr.getOffset();
            //   if SPACEBASE and spacebase offset known:
            //     off = spc->wrapOffset(off - fc->getSpacebaseOffset())
            //   else if SPACEBASE unknown: tryregister = false
            let mut off = addr.as_u64();
            let mut tryregister = true;
            if space == AddressSpace::Stack {
                match fd.get_call_specs(i).map(|fc| fc.get_spacebase_offset()) {
                    Some(sb) if sb != crate::fspec::OFFSET_UNKNOWN => {
                        off = ((off as i128 - sb as i128).rem_euclid(1i128 << 64)) as u64;
                    }
                    _ => {
                        // cc:1464: do not attempt to register this stack loc
                        tryregister = false;
                    }
                }
            }
            // cc:1466: transAddr = Address(spc, off)
            // cc:1467: effecttype = fc->hasEffect(transAddr, size)
            let mut effecttype = fd
                .get_call_specs(i)
                .map(|fc| fc.has_effect(space, off, size))
                .unwrap_or(crate::fspec::EffectType::UnknownEffect);
            // cc:1468-1486: output-trial half.
            let mut possibleoutput = false;
            let is_output_active = fd
                .get_call_specs(i)
                .map(|fc| fc.is_output_active())
                .unwrap_or(false);
            if is_output_active && tryregister {
                // cc:1471: outputCharacter = fc->characterizeAsOutput(transAddr, size)
                let output_character = fd
                    .get_call_specs(i)
                    .map(|fc| fc.characterize_as_output(space, off, size))
                    .unwrap_or(0);
                if output_character != crate::fspec::containment::NO_CONTAINMENT {
                    // cc:1473-1474: auto-killed-by-call upgrade
                    if effecttype != crate::fspec::EffectType::KilledByCall
                        && fd
                            .get_call_specs(i)
                            .map(|fc| fc.is_auto_killed_by_call())
                            .unwrap_or(false)
                    {
                        effecttype = crate::fspec::EffectType::KilledByCall;
                    }
                    if output_character == crate::fspec::containment::CONTAINED_BY {
                        // cc:1476-1477: tryOutputOverlapGuard; if handled the
                        // range is unaffected — no additional guarding.
                        if self.try_output_overlap_guard(fd, i, space, addr, off, size, write) {
                            effecttype = crate::fspec::EffectType::Unaffected;
                        }
                    } else {
                        // cc:1480-1483: register as an output trial unless one
                        // already exists.
                        let already_trial = fd
                            .get_call_specs(i)
                            .map(|fc| {
                                fc.active_output
                                    .which_trial_in_space(
                                    space, Address::new(off), size,
                                )
                                    >= 0
                            })
                            .unwrap_or(true);
                        if !already_trial {
                            if let Some(mut fc) = fd.get_call_specs_mut(i) {
                                fc.active_output.register_trial_in_space(
                                    space,
                                    Address::new(off),
                                    size,
                                );
                            }
                            possibleoutput = true;
                        }
                    }
                }
            } else {
                // cc:1487-1494: stack-output-lock half.
                let is_stack_output_lock = fd
                    .get_call_specs(i)
                    .map(|fc| fc.is_stack_output_lock())
                    .unwrap_or(false);
                if is_stack_output_lock && tryregister {
                    let output_character = fd
                        .get_call_specs(i)
                        .map(|fc| fc.characterize_as_output(space, off, size))
                        .unwrap_or(0);
                    if output_character != crate::fspec::containment::NO_CONTAINMENT {
                        effecttype = crate::fspec::EffectType::UnknownEffect;
                        // cc:1491-1492: if (tryOutputStackGuard(fc, addr,
                        // transAddr, size, outputCharacter, write))
                        //   effecttype = EffectRecord::unaffected;
                        // The return storage is read from the call spec's
                        // proto-store output parameter inside the callee
                        // (cc:1407/cc:1410 getOutput()), not staged here.
                        if self.try_output_stack_guard(
                            fd, i, space, addr, off, size, output_character, write,
                        ) {
                            effecttype = crate::fspec::EffectType::Unaffected;
                        }
                    }
                }
            }
            // cc:1495-1509: input-trial half.
            let is_input_active = fd
                .get_call_specs(i)
                .map(|fc| fc.is_input_active())
                .unwrap_or(false);
            if is_input_active && tryregister {
                // cc:1496: inputCharacter = fc->characterizeAsInputParam(transAddr, size)
                let input_character = fd
                    .get_call_specs(i)
                    .map(|fc| fc.characterize_as_input_param(space, off, size))
                    .unwrap_or(0);
                if input_character == crate::fspec::containment::CONTAINS_JUSTIFIED {
                    // cc:1498-1505: call could use this whole range as an
                    // input parameter — register the trial and append the
                    // varnode as the call's last input.
                    let already_trial = fd
                        .get_call_specs(i)
                        .map(|fc| {
                            fc.active_input
                                .which_trial_in_space(space, Address::new(off), size)
                                >= 0
                        })
                        .unwrap_or(true);
                    if !already_trial {
                        if let Some(mut fc) = fd.get_call_specs_mut(i) {
                            fc.active_input
                                .register_trial_in_space(
                                space,
                                Address::new(off),
                                size);
                        }
                        // cc:1502-1504: vn = newVarnode(size, addr);
                        // setActiveHeritage; opInsertInput(op, vn, numInput()).
                        // R9-F2: newVarnode's property tail
                        // (funcdata_varnode.cc:148-165) applies the range
                        // flags before the caller's setActiveHeritage.
                        // heritage.cc:1502 routes through Funcdata::newVarnode,
                        // whose symbol tail attaches the typelocked global's
                        // DWARF type (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                        let vn = fd
                            .vbank
                            .create_with_space(size as usize, space, addr.as_u64());
                        fd.set_varnode_properties(&vn);
                        Heritage::apply_new_varnode_flags(fd, &vn);
                        vn.write().unwrap().set_active_heritage();
                        let num_in = call_op.0.read().unwrap().num_input();
                        fd.op_insert_input(&call_op, vn, num_in);
                    }
                } else if input_character == crate::fspec::containment::CONTAINED_BY {
                    // cc:1507-1508: call may use part of this range as an
                    // input parameter.
                    self.guard_call_overlapping_input(fd, i, space, addr, off, size);
                }
            }
            // cc:1510-1525: the guard itself, by final effect type. Neither
            // "unaffected" nor "reload" gets an INDIRECT.
            if effecttype == crate::fspec::EffectType::UnknownEffect
                || effecttype == crate::fspec::EffectType::ReturnAddress
            {
                // cc:1512: indop = fd->newIndirectOp(fc->getOp(), addr, size, 0)
                let indop = fd.new_indirect_op(&call_op, space, addr.as_u64(), size as usize, 0);
                // cc:1513-1515: setActiveHeritage on in[0] and out; push out.
                let (in0, outvn) = {
                    let r = indop.0.read().unwrap();
                    (r.get_in(0).cloned(), r.output.as_ref().cloned())
                };
                if let Some(vn) = in0 {
                    vn.write().unwrap().set_active_heritage();
                }
                if let Some(vn) = outvn {
                    vn.write().unwrap().set_active_heritage();
                    // cc:1516-1517: if (holdind) out->setAddrForce()
                    if holdind {
                        vn.write().unwrap().set_addr_force();
                    }
                    // cc:1518-1519: if return_address -> setReturnAddress()
                    if effecttype == crate::fspec::EffectType::ReturnAddress {
                        vn.write().unwrap().set_return_address();
                    }
                    write.push(vn);
                }
            } else if effecttype == crate::fspec::EffectType::KilledByCall {
                // cc:1521-1524: indirectly created value.
                let indop = fd.new_indirect_creation_in_space(
                    &call_op,
                    space,
                    addr.as_u64(),
                    size as usize,
                    possibleoutput,
                );
                // cc:1522-1524: out setActiveHeritage; push.
                let outvn = indop.0.read().unwrap().output.as_ref().cloned();
                if let Some(vn) = outvn {
                    vn.write().unwrap().set_active_heritage();
                    write.push(vn);
                }
            }
        }
    }


    // Ghidra: heritage.cc:1609 Heritage::guardReturnsOverlapping
    /// Guard data-flow at RETURN ops where the heritaged range properly
    /// contains the potential return storage. Faithful 1:1 port of
    /// `guardReturnsOverlapping` (heritage.cc:1609-1638): the biggest
    /// contained output storage of the function's own prototype is looked
    /// up, a trial is registered at the truncated address (BE offsets are
    /// re-derived from the range tail, cc:1620-1622), and every live
    /// non-halt RETURN gets a SUBPIECE that truncates a fresh full-range
    /// free read down to the return storage, inserted before the RETURN as
    /// its new last input (cc:1623-1637).
    pub fn guard_returns_overlapping(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
    ) {
        // cc:1615: if (!fd->getFuncProto().getBiggestContainedOutput(...)) return
        let Some((v_space, v_offset, v_size)) =
            fd.get_func_proto()
                .get_biggest_contained_output(space, addr.as_u64(), size)
        else {
            return;
        };
        let trunc_addr = Address::new(v_offset);
        // cc:1618-1619: active = fd->getActiveOutput();
        // active->registerTrial(truncAddr, vData.size)
        if let Some(active) = fd.active_output.as_mut() {
            active.register_trial_in_space(v_space, trunc_addr, v_size);
        }
        // cc:1620: offset = vData.offset - addr.getOffset() — number of
        // least significant bytes to truncate.
        let mut offset = v_offset.wrapping_sub(addr.as_u64()) as i64;
        // cc:1621-1622: BE re-derives from the most significant side.
        if v_space.is_big_endian() {
            offset = (size as i64 - v_size as i64) - offset;
        }
        // cc:1623-1637: every live non-halt RETURN, in op-list order
        // (fd->beginOp(CPUI_RETURN) .. endOp — creation order).
        let return_ops: Vec<PcodeOpRef> = fd.obank.iter_return().cloned().collect::<Vec<_>>();
        for op in return_ops {
            let (dead, halt) = {
                let r = op.0.read().unwrap();
                (
                    (r.flags & crate::op::pcodeop_flags::DEAD) != 0,
                    (r.flags
                        & (crate::op::pcodeop_flags::HALT
                            | crate::op::pcodeop_flags::BADINSTRUCTION
                            | crate::op::pcodeop_flags::UNIMPLEMENTED
                            | crate::op::pcodeop_flags::NORETURN
                            | crate::op::pcodeop_flags::MISSING))
                        != 0,
                )
            };
            if dead {
                continue; // cc:1626
            }
            if halt {
                continue; // cc:1627: special halt points cannot take return values
            }
            let (op_addr, num_input) = {
                let r = op.0.read().unwrap();
                (r.get_addr(), r.num_input())
            };
            // cc:1628: invn = fd->newVarnode(size, addr)
            let invn = fd
                .vbank
                .create_with_space(size as usize, space, addr.as_u64());
            // heritage.cc:1628 routes through Funcdata::newVarnode, whose
            // symbol tail attaches the typelocked global's DWARF type
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&invn);
            Heritage::apply_new_varnode_flags(fd, &invn);
            // cc:1629-1632: SUBPIECE(invn, offset)
            let sub_op = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&sub_op, invn.clone(), 0);
            // cc:1632: newConstant(4, offset)
            let off_const = fd.new_constant(4, offset as u64);
            fd.op_set_input(&sub_op, off_const, 1);
            // cc:1633: opInsertBefore(subOp, op)
            fd.op_insert_before(&sub_op, &op);
            // cc:1634: retVal = fd->newVarnodeOut(vData.size, truncAddr, subOp)
            let ret_val = fd.vbank.create_def_with_space(
                v_size as usize,
                v_space,
                trunc_addr.as_u64(),
                &sub_op.0,
            );
            sub_op.0.write().unwrap().output = Some(ret_val.clone());
            // heritage.cc:1634 routes through Funcdata::newVarnodeOut, whose
            // symbol tail (usepoint = op->getAddr(), mirrored by
            // get_use_point on the def set above) attaches a matching symbol
            // entry (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&ret_val);
            Heritage::apply_new_varnode_flags(fd, &ret_val);
            // cc:1635: invn->setActiveHeritage()
            invn.write().unwrap().set_active_heritage();
            // cc:1636: opInsertInput(op, retVal, op->numInput())
            fd.op_insert_input(&op, ret_val, num_input);
        }
    }

    // Ghidra: heritage.cc:1652 Heritage::guardReturns
    /// Guard global data-flow at RETURN ops in preparation for renaming.
    /// Faithful 1:1 port of `guardReturns` (heritage.cc:1652-1692):
    ///   (1) If the function's own output recovery is active
    ///       (`fd->getActiveOutput()`): the range is characterized against
    ///       the function prototype; `contained_by` routes to
    ///       `guardReturnsOverlapping` (SUBPIECE truncation), any other
    ///       containment registers a whole-range trial and appends a fresh
    ///       full-range free read as the RETURN's last input
    ///       (cc:1660-1674). Dead and halt RETURNs never take a value.
    ///   (2) If the range carries `Varnode::persist` (fl bit): every live
    ///       RETURN gets a return-copy — a COPY whose output is
    ///       address-forced and marked `PcodeOp::return_copy`, reading a
    ///       fresh full-range free read (cc:1676-1691). This second pass
    ///       deliberately does NOT skip halt RETURNs (only dead ones),
    ///       matching cc:1680.
    /// Ghidra's unused `write` parameter is omitted here.
    pub fn guard_returns(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        space: AddressSpace,
        addr: Address,
        size: i32,
    ) {
        // cc:1658-1675: output-trial half, only when active output exists.
        if fd.active_output.is_some() {
            // cc:1660: outputCharacter = fd->getFuncProto().characterizeAsOutput(addr, size)
            let output_character =
                fd.get_func_proto()
                    .characterize_as_output(space, addr.as_u64(), size);
            if output_character == crate::fspec::containment::CONTAINED_BY {
                // cc:1661-1662
                self.guard_returns_overlapping(fd, space, addr, size);
            } else if output_character != crate::fspec::containment::NO_CONTAINMENT {
                // cc:1664: active->registerTrial(addr, size)
                if let Some(active) = fd.active_output.as_mut() {
                    active.register_trial_in_space(space, addr, size);
                }
                let return_ops: Vec<PcodeOpRef> = fd.obank.iter_return().cloned().collect::<Vec<_>>();
                for op in return_ops {
                    let (dead, halt, num_input) = {
                        let r = op.0.read().unwrap();
                        (
                            (r.flags & crate::op::pcodeop_flags::DEAD) != 0,
                            (r.flags
                                & (crate::op::pcodeop_flags::HALT
                                    | crate::op::pcodeop_flags::BADINSTRUCTION
                                    | crate::op::pcodeop_flags::UNIMPLEMENTED
                                    | crate::op::pcodeop_flags::NORETURN
                                    | crate::op::pcodeop_flags::MISSING))
                                != 0,
                            r.num_input(),
                        )
                    };
                    if dead {
                        continue; // cc:1668
                    }
                    if halt {
                        continue; // cc:1669
                    }
                    // cc:1670-1672: invn = newVarnode(size,addr);
                    // setActiveHeritage; opInsertInput(op, invn, numInput())
                    let invn = fd
                        .vbank
                        .create_with_space(size as usize, space, addr.as_u64());
                    // heritage.cc:1670 newVarnode symbol tail
                    // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                    fd.set_varnode_properties(&invn);
                    Heritage::apply_new_varnode_flags(fd, &invn);
                    invn.write().unwrap().set_active_heritage();
                    fd.op_insert_input(&op, invn, num_input);
                }
            }
        }
        // cc:1676: if ((fl & Varnode::persist)==0) return
        if (fl & crate::varnode::varnode_flags::PERSIST) == 0 {
            return;
        }
        // cc:1677-1691: return-copy suffix on every live RETURN (halt
        // RETURNs included — only the dead check at cc:1680 applies).
        let return_ops: Vec<PcodeOpRef> = fd.obank.iter_return().cloned().collect::<Vec<_>>();
        for op in return_ops {
            let (dead, op_addr) = {
                let r = op.0.read().unwrap();
                (
                    (r.flags & crate::op::pcodeop_flags::DEAD) != 0, r.get_addr(),
                )
            };
            if dead {
                continue; // cc:1680
            }
            if std::env::var("RUGRA_HERITAGE_TRACE").is_ok() {
                eprintln!(
                    "[H-GRET] pass={} range={:#x}/{} return@{:#x}",
                    self.pass,
                    addr.as_u64(),
                    size,
                    op_addr.as_u64()
                );
            }
            // cc:1681: copyop = fd->newOp(1, op->getAddr())
            let copyop = fd.new_op(1, op_addr);
            // cc:1682: vn = fd->newVarnodeOut(size, addr, copyop)
            let vn = fd
                .vbank
                .create_def_with_space(
                size as usize,
                space,
                addr.as_u64(),
                &copyop.0);
            copyop.0.write().unwrap().output = Some(vn.clone());
            // heritage.cc:1682 routes through Funcdata::newVarnodeOut, whose
            // symbol tail runs after the setOutput wiring with usepoint =
            // op->getAddr() (get_use_point over the def set above)
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&vn);
            Heritage::apply_new_varnode_flags(fd, &vn);
            // cc:1683-1684: vn->setAddrForce(); vn->setActiveHeritage()
            vn.write().unwrap().set_addr_force();
            vn.write().unwrap().set_active_heritage();
            // cc:1685: opSetOpcode(copyop, CPUI_COPY)
            fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
            // cc:1686: fd->markReturnCopy(copyop) — funcdata.hh inline:
            // op->setFlag(PcodeOp::return_copy)
            copyop
                .0.write()
                .unwrap()
                .flags |= crate::op::pcodeop_flags::RETURN_COPY;
            // cc:1687-1689: invn = newVarnode(size,addr);
            // setActiveHeritage; opSetInput(copyop, invn, 0)
            let invn = fd
                .vbank
                .create_with_space(size as usize, space, addr.as_u64());
            // heritage.cc:1687 routes through Funcdata::newVarnode, whose
            // symbol tail attaches the typelocked global's DWARF type
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&invn);
            Heritage::apply_new_varnode_flags(fd, &invn);
            invn.write().unwrap().set_active_heritage();
            fd.op_set_input(&copyop, invn, 0);
            // cc:1690: opInsertBefore(copyop, op)
            fd.op_insert_before(&copyop, &op);
        }
    }

    // Ghidra: heritage.cc:382 Heritage::normalizeReadSize
    /// Normalize a read varnode whose size is < range size: create a SUBPIECE
    /// that extracts the full-size varnode, leaving the original as output.
    /// Faithful to `normalizeReadSize` (heritage.cc:383-401).
    pub fn normalize_read_size(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        op: &Arc<RwLock<PcodeOp>>,
        addr: Address,
        size: i32,
    ) -> Arc<RwLock<Varnode>> {
        // cc:390-391: newOp(2, op->getAddr()); opSetOpcode(SUBPIECE)
        let op_addr = op.read().unwrap().get_addr();
        let newop = fd.new_op(2, op_addr);
        fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
        // cc:392: vn1 = newVarnode(size, addr) — the new full-size free read.
        // R9-F2: newVarnode's property tail (funcdata_varnode.cc:148-165)
        // applies the range flags before the caller proceeds.
        let vn1 = fd.vbank.create_with_space(
            size as usize, vn.read().unwrap().address_space, addr.as_u64(),
        );
        // heritage.cc:391 routes through Funcdata::newVarnode, whose symbol
        // tail attaches the typelocked global's DWARF type before the flags
        // fold (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
        fd.set_varnode_properties(&vn1);
        Heritage::apply_new_varnode_flags(fd, &vn1);
        // cc:393: overlap = vn->overlap(addr, size) — endian-aware
        // (Varnode::overlap, varnode.cc:217-228). R9-F1: former inline
        // `saturating_sub` was an LE-only projection.
        let overlap = vn.read().unwrap().overlap_addr(addr, size as usize) as i64;
        // cc:394: vn2 = newConstant(addrSize, overlap) — the width is
        // addr.getAddrSize() of the range's space (4 for register on the
        // x86-64 oracle; SUBFLOW-SUBPIECE-WIDTH-0001). The heritage loop is
        // per-space, so vn's space is the range's space.
        let vn2 = fd.new_constant(
            vn.read().unwrap().address_space.addr_size(),
            overlap as u64,
        );
        // cc:395-396: opSetInput(newop, vn1, 0); opSetInput(newop, vn2, 1)
        fd.op_set_input(&newop, vn1.clone(), 0);
        fd.op_set_input(&newop, vn2, 1);
        // cc:397: opSetOutput(newop, vn) — old vn becomes SUBPIECE output.
        // Must go through Funcdata::op_set_output (funcdata_op.cc:70): the
        // previous direct `output = Some(vn)` assignment left vn.def unset,
        // so the "normalized" varnode stayed FREE in the bank, the driver
        // re-collected it every pass, and each pass re-normalized it with a
        // fresh SUBPIECE — the Heritage/DeadCode ping-pong that kept the
        // mainloop from converging (HERITAGE-DRIVER-SWITCH-0001).
        fd.op_set_output(&newop, vn.clone());
        // cc:398: newop->getOut()->setWriteMask() — the driver skips
        // writemasked varnodes (cc:2706), so the SUBPIECE output is never
        // re-collected as a heritage candidate.
        vn.write().unwrap().set_write_mask();
        // cc:399: opInsertBefore(newop, op)
        fd.op_insert_before(&newop, &PcodeOpRef(op.clone()));
        vn1
    }

    // Ghidra: heritage.cc:416 Heritage::normalizeWriteSize
    /// Normalize a write varnode whose size < range size. Faithful 1:1 port
    /// of `normalizeWriteSize` (heritage.cc:416-494):
    ///   (1) mostsigsize piece (cc:428-448): if the defining op is a CALL
    ///       whose `callOpIndirectEffect` on the piece fires, the piece is
    ///       an INDIRECT creation; otherwise a SUBPIECE of a new full-range
    ///       free read (`big`).
    ///   (2) overlap piece (cc:449-468): same CALL split for the low part.
    ///   (3) midvn (cc:470-482): `overlap != 0` PIECEs the original vn
    ///       (most significant) with leastvn (least significant); else the
    ///       original vn.
    ///   (4) bigout (cc:483-492): `mostsigsize != 0` PIECEs mostvn with
    ///       midvn; else midvn.
    ///   (5) the original vn is write-masked (cc:493) and the final
    ///       full-range Varnode is returned (cc:494) so `guard` can replace
    ///       the write-list entry (`*iter = vn =`, cc:1180).
    /// Big-endian `pieceaddr` selection mirrors cc:429-433/451-454 via the
    /// range space's endianness (Rugra Address is offset-only).
    pub fn normalize_write_size(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        space: AddressSpace,
        addr: Address,
        size: i32,
    ) -> Arc<RwLock<Varnode>> {
        let (vn_size, vn_loc) = {
            let r = vn.read().unwrap();
            (r.get_size() as i64, r.loc.as_u64())
        };
        let big_endian = space.is_big_endian();
        let addr_size = space.addr_size();
        // cc:425: op = vn->getDef() — a write varnode always has a definer.
        let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
            Some(d) => d,
            None => return vn.clone(),
        };
        let def_is_call = def_op.read().unwrap().is_call();
        // cc:426: overlap = vn->overlap(addr, size) — endian-aware
        // (Varnode::overlap, varnode.cc:217-228: BE counts the offset from
        // the least significant side). R9-F1: the former inline
        // `saturating_sub` was an LE-only projection; the faithful value now
        // routes through Varnode::overlap_addr's BE branch. The BE domain
        // itself remains UNTESTED (fixture corpus is LE; registered as
        // HERITAGE-BE-OVERLAP in the fixture metadata).
        let overlap = vn.read().unwrap().overlap_addr(addr, size as usize) as i64;
        // cc:427: mostsigsize = size - (overlap + vn->getSize())
        let mostsigsize = size as i64 - (overlap + vn_size);

        // cc:428-448: most significant piece.
        let mut mostvn: Option<Arc<RwLock<Varnode>>> = None;
        if mostsigsize != 0 {
            // cc:429-433: BE keeps the piece at the range start; LE moves it
            // past the original write.
            let piece_addr = if big_endian {
                addr
            } else {
                Address::new(addr.as_u64().wrapping_add((overlap + vn_size) as u64))
            };
            if def_is_call
                && self.call_op_indirect_effect(
                    fd,
                    space,
                    piece_addr,
                    mostsigsize as i32,
                    &def_op)
            {
                // cc:435: newIndirectCreation — don't create a new big read
                // if the write is from a CALL with an effect on the piece.
                let newop = fd.new_indirect_creation_in_space(
                    &PcodeOpRef(def_op.clone()),
                    space,
                    piece_addr.as_u64(),
                    mostsigsize as usize,
                    false,
                );
                mostvn = newop.0.read().unwrap().output.as_ref().cloned();
            } else {
                // cc:439-446: SUBPIECE of a new full-range free read.
                // Creation order mirrors the oracle: newOp, mostvn
                // (newVarnodeOut), big (newVarnode), then wiring.
                let op_addr = def_op.read().unwrap().get_addr();
                let newop = fd.new_op(2, op_addr);
                let most_out = fd.vbank.create_def_with_space(
                    mostsigsize as usize,
                    space,
                    piece_addr.as_u64(),
                    &newop.0,
                );
                newop.0.write().unwrap().output = Some(most_out.clone());
                // heritage.cc:440 routes through Funcdata::newVarnodeOut,
                // whose symbol tail (usepoint = op->getAddr()) runs after the
                // setOutput wiring (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                fd.set_varnode_properties(&most_out);
                Heritage::apply_new_varnode_flags(fd, &most_out);
                let big = fd
                    .vbank
                    .create_with_space(size as usize, space, addr.as_u64());
                // heritage.cc:441 routes through Funcdata::newVarnode, whose
                // symbol tail attaches the typelocked global's DWARF type
                // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                fd.set_varnode_properties(&big);
                Heritage::apply_new_varnode_flags(fd, &big);
                big.write().unwrap().set_active_heritage();
                fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
                fd.op_set_input(&newop, big, 0);
                // cc:445: newConstant(addr.getAddrSize(), overlap+vn->getSize())
                let off_const = fd.new_constant(addr_size, (overlap + vn_size) as u64);
                fd.op_set_input(&newop, off_const, 1);
                fd.op_insert_before(&newop, &PcodeOpRef(def_op.clone()));
                mostvn = Some(most_out);
            }
        }

        // cc:449-468: least significant (overlap) piece.
        let mut leastvn: Option<Arc<RwLock<Varnode>>> = None;
        if overlap != 0 {
            // cc:451-454: BE moves the piece above the range tail; LE keeps
            // it at the range start.
            let piece_addr = if big_endian {
                Address::new(addr.as_u64().wrapping_add((size as i64 - overlap) as u64))
            } else {
                addr
            };
            if def_is_call
                && self.call_op_indirect_effect(fd, space, piece_addr, overlap as i32, &def_op)
            {
                // cc:456: unless the CALL definitely has no effect on the
                // piece, take it from an INDIRECT creation.
                let newop = fd.new_indirect_creation_in_space(
                    &PcodeOpRef(def_op.clone()),
                    space,
                    piece_addr.as_u64(),
                    overlap as usize,
                    false,
                );
                leastvn = newop.0.read().unwrap().output.as_ref().cloned();
            } else {
                // cc:460-467: SUBPIECE of a new full-range free read with
                // truncation constant 0.
                let op_addr = def_op.read().unwrap().get_addr();
                let newop = fd.new_op(2, op_addr);
                let least_out =
                    fd.vbank
                        .create_def_with_space(
                    overlap as usize, space, piece_addr.as_u64(), &newop.0,
                );
                newop.0.write().unwrap().output = Some(least_out.clone());
                // heritage.cc:461 routes through Funcdata::newVarnodeOut,
                // whose symbol tail runs after the setOutput wiring
                // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                fd.set_varnode_properties(&least_out);
                Heritage::apply_new_varnode_flags(fd, &least_out);
                let big = fd
                    .vbank
                    .create_with_space(size as usize, space, addr.as_u64());
                // heritage.cc:462 routes through Funcdata::newVarnode, whose
                // symbol tail attaches the typelocked global's DWARF type
                // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                fd.set_varnode_properties(&big);
                Heritage::apply_new_varnode_flags(fd, &big);
                big.write().unwrap().set_active_heritage();
                fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
                fd.op_set_input(&newop, big, 0);
                // cc:466: newConstant(addr.getAddrSize(), 0)
                let off_const = fd.new_constant(addr_size, 0u64);
                fd.op_set_input(&newop, off_const, 1);
                fd.op_insert_before(&newop, &PcodeOpRef(def_op.clone()));
                leastvn = Some(least_out);
            }
        }

        // cc:470-482: midvn — PIECE the original write over the low piece.
        let midvn: Arc<RwLock<Varnode>> = if overlap != 0 {
            let op_addr = def_op.read().unwrap().get_addr();
            let newop = fd.new_op(2, op_addr);
            // cc:472-475: BE output address is the original vn's; LE is the
            // range start.
            let mid_addr = if big_endian {
                Address::new(vn_loc)
            } else {
                addr
            };
            let mid_out =
                fd.vbank
                    .create_def_with_space(
                (overlap + vn_size) as usize, space, mid_addr.as_u64(), &newop.0,
            );
            newop.0.write().unwrap().output = Some(mid_out.clone());
            // heritage.cc:473/475 route through Funcdata::newVarnodeOut,
            // whose symbol tail runs after the setOutput wiring
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&mid_out);
            Heritage::apply_new_varnode_flags(fd, &mid_out);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            // cc:477-478: vn is the most significant input.
            fd.op_set_input(&newop, vn.clone(), 0);
            fd.op_set_input(
                &newop, leastvn.clone().expect("overlap!=0 implies leastvn"), 1,
            );
            fd.op_insert_after(&newop, &PcodeOpRef(def_op.clone()));
            mid_out
        } else {
            vn.clone()
        };

        // cc:483-492: bigout — PIECE the high piece over midvn.
        let bigout: Arc<RwLock<Varnode>> = if mostsigsize != 0 {
            let op_addr = def_op.read().unwrap().get_addr();
            let newop = fd.new_op(2, op_addr);
            let big_out =
                fd.vbank
                    .create_def_with_space(size as usize, space, addr.as_u64(), &newop.0);
            newop.0.write().unwrap().output = Some(big_out.clone());
            // heritage.cc:485 routes through Funcdata::newVarnodeOut, whose
            // symbol tail runs after the setOutput wiring
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&big_out);
            Heritage::apply_new_varnode_flags(fd, &big_out);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            fd.op_set_input(
                &newop, mostvn.clone().expect("mostsigsize!=0 implies mostvn"), 0,
            );
            fd.op_set_input(&newop, midvn.clone(), 1);
            // cc:489: opInsertAfter(newop, midvn->getDef())
            let mid_def = midvn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            if let Some(mid_def) = mid_def {
                fd.op_insert_after(&newop, &PcodeOpRef(mid_def));
            } else {
                fd.op_insert_after(&newop, &PcodeOpRef(def_op.clone()));
            }
            big_out
        } else {
            midvn.clone()
        };

        // cc:493: the original small write is write-masked so the driver
        // never re-collects it (cc:2706).
        vn.write().unwrap().set_write_mask();
        // cc:494: return bigout — guard replaces the write-list entry.
        bigout
    }

    // Ghidra: heritage.cc:1156 Heritage::guard
    /// Guard a specific address range for heritage. Faithful to
    /// `Heritage::guard` (heritage.cc:1156-1199):
    ///   (1) For each read varnode: verify single descendent, normalizeReadSize,
    ///       setActiveHeritage.
    ///   (2) For each write varnode: normalizeWriteSize (the write-list entry
    ///       is replaced by the returned full-range Varnode, cc:1180),
    ///       setActiveHeritage.
    ///   (3) If addIndirects: queryProperties sets fl, then
    ///       guardCalls/guardReturns, and — gated on
    ///       `fd->getArch()->highPtrPossible(addr,size)` (cc:1194) —
    ///       guardStores/guardLoads.
    ///
    /// The read/write lists come from `collect` via `place_multiequals`
    /// (cc:2629). The `fl` query is `fd->getScopeLocal()->queryProperties`
    /// with an empty usepoint (cc:1191), modeled by
    /// [`Heritage::guard_query_properties`]. Ghidra throws
    /// LowlevelError("Free varnode with multiple reads") at cc:1171; Rugra
    /// keeps the file-wide stderr convention (no exception channel on the
    /// driver) and logs instead.
    pub fn guard_range(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
        add_indirects: bool,
        read: &mut Vec<Arc<RwLock<Varnode>>>,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        _inputvars: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // Ghidra cc:1165-1176: process read list.
        for vn_arc in read.iter_mut() {
            let descend_count: usize = {
                let vn_r = vn_arc.read().unwrap();
                vn_r.descend.iter().filter(|w| w.strong_count() > 0).count()
            };
            if descend_count == 0 {
                continue; // cc:1168-1169: removed by removeRevisitedMarkers
            }
            // cc:1171-1172: free varnode with multiple reads = error.
            // Rugra logs instead of throwing.
            if descend_count > 1 {
                eprintln!("[HERITAGE] WARN: free varnode with multiple reads");
            }
            // cc:1173-1174: normalizeReadSize if vn.size < size.
            let vn_size = vn_arc.read().unwrap().get_size() as i32;
            if vn_size < size {
                // Ghidra cc:1174: normalizeReadSize(vn, op, addr, size)
                let desc_op = vn_arc.read().unwrap().lone_descend();
                if let Some(read_op) = desc_op {
                    let new_vn = self.normalize_read_size(fd, vn_arc, &read_op, addr, size);
                    *vn_arc = new_vn;
                }
            }
            // cc:1175: setActiveHeritage.
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1178-1183: process write list.
        for vn_arc in write.iter_mut() {
            let vn_size = vn_arc.read().unwrap().get_size() as i32;
            if vn_size < size {
                // Ghidra cc:1180: *iter = vn = normalizeWriteSize(vn, addr, size)
                // — the entry is replaced by the returned full-range Varnode.
                let new_vn = self.normalize_write_size(fd, vn_arc, space, addr, size);
                *vn_arc = new_vn;
            }
            vn_arc.write().unwrap().set_active_heritage();
        }
        // Ghidra cc:1188-1198: addIndirects half.
        if add_indirects {
            // cc:1189-1191: fl = 0;
            // fd->getScopeLocal()->queryProperties(addr,size,Address(),fl)
            let fl = Heritage::guard_query_properties(fd, space, addr, size);
            // cc:1192: guardCalls(fl,addr,size,write)
            self.guard_calls(fd, fl, space, addr, size, write);
            // cc:1193: guardReturns(fl,addr,size,write)
            self.guard_returns(fd, fl, space, addr, size);
            // cc:1194-1197: if (fd->getArch()->highPtrPossible(addr,size)) {
            //   guardStores(addr,size,write); guardLoads(fl,addr,size,write); }
            // fd.get_arch() is None only on synthetic arch-less Funcdata
            // (tests); the oracle always dereferences the Architecture.
            let high_ptr_possible = fd
                .get_arch()
                .map(|a| a.high_ptr_possible(addr, size))
                .unwrap_or(true);
            if high_ptr_possible {
                self.guard_stores_range(fd, space, addr, size, write);
                self.guard_loads_range(fd, fl, space, addr, size, write);
            }
        }
    }

    // Ghidra: database.cc:1263 Scope::queryProperties
    /// Boolean properties of a memory range for the guard() addIndirects
    /// half, faithful to `Scope::queryProperties(addr,size,usepoint,fl)`
    /// (database.cc:1263-1281) as called from `Heritage::guard` with an
    /// empty usepoint (heritage.cc:1191) on `fd->getScopeLocal()`:
    ///   (1) smallest SymbolEntry CONTAINING the whole range (stackContainer
    ///       -> ScopeInternal::findContainer) -> `entry->getAllFlags()`;
    ///   (2) else if the range is in the scope's range tree -> `mapped |
    ///       addrtied` (+persist for a global scope; ScopeLocal never is) |
    ///       getProperty(addr);
    ///   (3) else -> getProperty(addr).
    /// The mapScope/stackContainer routing is projected as: a range in the
    /// local scope's own (stack) space hits (1)/(2); any other Ram-space
    /// range resolves — as in the oracle, where `Database::mapScope` hands
    /// it to the global scope and the walk terminates there — to the
    /// global-scope tail `mapped | addrtied | persist | getProperty(addr)`
    /// (see the (3) branch below). Residuals: a global SymbolEntry
    /// containing the range (branch (1) in the global scope) and
    /// register/unique-scope routing keep the flagbase-only tail; Rugra's
    /// ScopeLocal has no parent linkage (fixtures and the stack/register
    /// pipeline never rely on it).
    ///
    /// Flagbase space partitioning (HERITAGE-FLAGBASE-SPACELESS-0001): the
    /// oracle's `getProperty(addr)` tails (database.cc:1276/1279) read
    /// `flagbase.getValue(addr)` (database.hh:946) with the FULL
    /// space-qualified `Address`, and `Address::operator<`
    /// (address.hh:375-390) orders by space index BEFORE offset, so a
    /// property range installed in one space never covers an address of
    /// another: a Register/Unique/Stack-space lookup only ever sees the
    /// default partition (0 — the locked pspec carries zero `<volatile>`
    /// ranges, and loader-derived `<readonly>` ranges live in the RAM
    /// space, architecture.cc:1427 `readonlypropagate=false` aside). Rugra's
    /// `PartMap` is keyed by the legacy SPACELESS `Address` (only
    /// default-data RAM ranges are ever installed — the SYMDB driver's
    /// `set_property_range` calls), so consulting it from a non-Ram space
    /// can only cross-space collide (an R-only PT_LOAD at [0,0x29000)
    /// marking register/unique/stack offsets READONLY, whence
    /// ActionVarnodeProps' hasActionProperty branch
    /// (coreaction.cc:1318-1326) skipped the NZMask/consume removal of the
    /// flagged varnodes). The projection here therefore folds the oracle's
    /// per-space answer for the locked configuration: the flagbase is
    /// consulted ONLY for the Ram space (the funcdata.rs
    /// `query_properties_parent_scope` / ruleaction.rs consumer guard
    /// pattern); every other space folds 0. Residual: a pspec that ever
    /// installs non-Ram flagbase partitions needs the space-keyed flagbase
    /// first. The spaceless key form is a LOAD-BEARING cross-file
    /// convention (FLAGBASE-CR-F2): `Database::flagbase` keys and every
    /// query stay uniformly spaceless, enforced by debug_asserts at the
    /// PartMap get_value/split boundary (database.rs) — flipping either
    /// side to `with_space` addresses alone would silently reorder the
    /// map (`Address::cmp` sorts `None` before every `Some(_)` tag);
    /// both sides must migrate to space-tagged keys together at the
    /// ADDRESS-0001 phase-3 merge.
    // RUDRA-GLUE: static scope-local projection of the oracle's
    // fd->getScopeLocal()->queryProperties call; Funcdata owns ScopeLocal
    // by value (varmap.rs), not through the Database scope graph.
    pub fn guard_query_properties(
        fd: &Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
    ) -> u32 {
        use crate::varnode::varnode_flags;
        if size <= 0 {
            return 0;
        }
        if let Some(scope) = &fd.scope {
            let offset = addr.as_u64();
            let last = offset + size as u64 - 1;
            // (1) smallest containing non-dynamic symbol covering the WHOLE
            // range; ties broken by the entry subsort (usepoint-free first),
            // matching the multiset pick of stackContainer's findContainer.
            let mut best: Option<(&crate::varmap::LocalSymbol, (u8, u64))> = None;
            for sym in scope.symbols.iter().filter(|s| !s.is_dynamic) {
                if sym.space != space || sym.size <= 0 {
                    continue;
                }
                let sym_last = sym.start + sym.size as u64 - 1;
                if sym.start <= offset && last <= sym_last {
                    // database.cc:97 getSubsort: (0,0) for address-tied
                    // storage (usepoint == None), else (1, usepoint).
                    let subsort = match sym.usepoint {
                        None => (0u8, 0u64),
                        Some(u) => (1u8, u),
                    };
                    if best.map(|(_, b)| subsort < b).unwrap_or(true) {
                        best = Some((sym, subsort));
                    }
                }
            }
            if let Some((sym, _)) = best {
                // SymbolEntry::getAllFlags as computed by
                // sync_varnodes_with_symbols cc:954: mapped | addrtied when
                // the mapping carries no usepoint | typelock | namelock |
                // nolocalalias.
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
                return f;
            }
            // (2) in-scope discovery range -> mapped | addrtied (the local
            // scope is never global, database.cc:1273's persist is skipped).
            // The scope's RangeList carries the space identity
            // (Scope::inScope -> RangeList::inRange), so only the scope's
            // own (stack) space can hit this branch. The cc:1276 property
            // fold `flags |= getProperty(addr)` runs in the oracle with the
            // STACK-space Address — outside every RAM-space flagbase
            // partition (address.hh:375-390 space-index-first ordering),
            // i.e. the locked-pspec oracle value is 0 — and Rugra's
            // spaceless PartMap cannot express a stack-space query at all
            // (consulting it would cross-space collide with the RAM
            // readonly ranges), so the fold projects to 0 here.
            let in_scope = space == scope.space
                && scope
                    .local_range
                    .iter()
                    .any(|&(first, range_last)| first <= offset && last <= range_last);
            if in_scope {
                return varnode_flags::MAPPED | varnode_flags::ADDRTIED;
            }
        }
        // (3) oracle database.cc:1271-1276's finalscope tail: an address
        // outside the function-local scope routes through
        // `Database::mapScope` to its owning scope, and the
        // `stackContainer` walk terminates on the GLOBAL scope for the
        // default (ram) space — `finalscope != null` — so the oracle
        // returns `mapped | addrtied | persist | getProperty(addr)` for
        // global ranges. This is load-bearing for Heritage::guard
        // (heritage.cc:1451 `holdind = addrtied`, cc:1516-1517
        // `out->setAddrForce()`): the addr-force mark makes every guard
        // INDIRECT output `isAutoLive`, so ActionDeadCode's seeding loop
        // (coreaction.cc:3947-3950 pushConsumed on autolive outputs)
        // consumes the whole call-guard lattice and, through
        // propagateConsumed's marker cases, every global write feeding it.
        // Without this branch the write-only globals of the corpus (e.g.
        // getparameter's `config.timecond = TIMECOND_NONE`) lose their
        // lattice at the first removal-allowed deadcode pass and vanish
        // (GETPARAM-EMPTYELSE-0001). The register/unique/other-space
        // remainder falls to the (4) tail below, whose flagbase-only value
        // folds to the locked-pspec oracle answer 0.
        if space == AddressSpace::Ram {
            let mut f = varnode_flags::MAPPED
                | varnode_flags::ADDRTIED
                | varnode_flags::PERSIST;
            if let Some(a) = fd.get_arch() {
                if let Some(db) = a.symboltab.as_ref() {
                    f |= db.read().unwrap().get_property(addr);
                }
            }
            return f;
        }
        // (4) property flagbase only — for every space the walk above did
        // not claim (const/register/unique/join/iop, and stack outside the
        // discovery range). The oracle tail (database.cc:1278-1279) reads
        // `getProperty(addr)` with the full space-qualified Address: a
        // non-Ram address sorts in its own space-index region
        // (address.hh:375-390) and only ever sees the flagbase's default
        // partition — 0 under the locked pspec (zero `<volatile>` ranges;
        // loader-derived `<readonly>` ranges are RAM-space only), the
        // space-qualified answer CURB2's probe registered as the oracle
        // value. Rugra's PartMap is keyed by the spaceless legacy Address,
        // so a lookup here cross-space collides with the RAM readonly
        // ranges instead (parent c010bbb3 gated probe: 17 Register-space
        // varnodes at offsets 0x0-0xb8/0x110 across 26 functions falsely
        // READONLY; the consumers are ActionVarnodeProps' hasActionProperty
        // branch (coreaction.cc:1318 `continue`) skipping the NZMask/consume
        // removal, jumptable ispoint (jumptable.cc:441) rejecting the switch
        // variable, and the single-branch readonly rescue (jumptable.cc:1224)
        // feeding loader bytes as the table). Fold to the oracle's 0 (the
        // funcdata/ruleaction consumers' Ram-only guard pattern).
        // Residuals: a pspec installing non-Ram flagbase partitions needs
        // the space-keyed flagbase first; and an OPEN-TAILED Ram property
        // range (FLAGBASE-CR-F1 — a pspec/SYMDB range carrying `first`
        // with no `last`) breaks the fold's premise the other way: the
        // oracle parse fills `last = spc->getHighest()`
        // (address.cc:347-349), then `Range::getLastAddrOpen`
        // (address.cc:265-275) crosses to the NEXT space in order at
        // offset 0 (translate.cc:647-665) — or, past the final space,
        // returns the `~0`-sentinel base with offset 0, which
        // `isInvalid()` (null-base only, address.hh:285-287) does NOT
        // catch, so `Database::setPropertyRange` (database.cc:3229-3234)
        // takes the split branch and its walk-to-`flagbase.end()`
        // no-closing-split `else` stays defensive — leaving a non-zero
        // Ram tail partition [X, ram-top] whose only closing changepoint
        // lies OUTSIDE the Ram space. Rugra's spaceless mirror drops the
        // open form entirely (`Scope::decode_hole` defaults a missing
        // `last` to 0 and degrades the range to [0,0]; the legacy
        // `Range::get_last_addr_open` = `last.next()` has no
        // cross-space/sentinel machinery — a spaceless top would wrap to
        // 0 and install nothing), so branch (3)'s consult answers 0
        // where the oracle answers the property over the Ram tail
        // (non-Ram queries still see 0 in the oracle: the tail closes at
        // the next space's base). Trigger: a pspec carrying an
        // open-attribute property range.
        0
    }

    // Ghidra: funcdata_varnode.cc:148 Funcdata::newVarnode
    /// The property-flag tail of `Funcdata::newVarnode`
    /// (funcdata_varnode.cc:148-165) / `newVarnodeOut`
    /// (funcdata_varnode.cc:104-127): after creating the Varnode,
    /// `localmap->queryProperties(addr,size,Address(),vflags)` runs and —
    /// when no SymbolEntry is found — `vn->setFlags(vflags & ~typelock)`
    /// installs the range flags (persist from the property flagbase,
    /// mapped/addrtied for in-scope stack ranges).  This helper applies
    /// that tail to Varnodes created through the raw bank in the guard
    /// family and in rename's input promotion; the symbol-entry branch
    /// (setSymbolProperties) degrades to the entry-derived flags from
    /// [`Heritage::guard_query_properties`] (Rust ScopeLocal carries no
    /// SymbolEntry wiring on this path).
    // RUDRA-GLUE: bank-created varnodes have no Funcdata::newVarnode wrapper
    // in Rust; this is its observable flag tail.
    pub fn apply_new_varnode_flags(fd: &Funcdata, vn: &Arc<RwLock<Varnode>>) {
        let (space, offset, size) = {
            let r = vn.read().unwrap();
            (r.address_space, r.loc.as_u64(), r.get_size() as i32)
        };
        let fl = Heritage::guard_query_properties(fd, space, Address::new(offset), size);
        vn.write()
            .unwrap()
            .set_flags(fl & !crate::varnode::varnode_flags::TYPELOCK);
    }

    // Ghidra: heritage.cc:219 Heritage::guardAll (Rugra analogue)
    /// Run the guard phases against the whole stack space. This is the
    /// per-space analogue of Ghidra's guard() addIndirects half.
    /// Calls guard_range with empty read/write lists (Rugra's
    /// setActiveHeritage is done by rename_direct's marker).
    pub fn guard_all(&mut self, fd: &mut Funcdata) {
        let mut empty_read = Vec::new();
        let mut empty_write = Vec::new();
        let mut empty_input = Vec::new();
        self.guard_range(
            fd,
            AddressSpace::Stack,
            Address::new(0),
            0,
            true,
            &mut empty_read,
            &mut empty_write,
            &mut empty_input,
        );
    }

    // Ghidra: heritage.cc:2281 Heritage::processJoins
    /// Process join-space varnodes: split PIECE/SUBPIECE on free join varnodes.
    /// Faithful to `processJoins` (heritage.cc:2282-2314). Iterates Join-space
    /// varnodes. For free ones, calls splitJoinRead (which creates the
    /// piece varnodes in the real address space). For written ones whose
    /// piece-space delay == pass, calls splitJoinWrite (which creates
    /// SUBPIECE ops to reconstruct the join from pieces).
    ///
    /// Rugra's Join space is minimal (AddressSpace::Join enum, no JoinRecord
    /// infrastructure). Full implementation needs JoinRecord/JoinSpace from
    /// Ghidra architecture. This method is a documented stub that scans
    /// Join-space varnodes and logs them.
    // Ghidra: heritage.cc:618 Heritage::findAddressForces
    /// Mark the boundary of artificial ops from copy sinks. Faithful to
    /// `findAddressForces` (heritage.cc:619-667). Back-reachable COPY/
    /// MULTIEQUAL/INDIRECT-store ops with same address are "artificial";
    /// non-artificial ops are "forces" (address-forced boundary).
    pub fn find_address_forces(
        &self,
        fd: &mut Funcdata,
        copy_sinks: &mut Vec<Arc<RwLock<PcodeOp>>>,
        forces: &mut Vec<Arc<RwLock<PcodeOp>>>,
    ) {
        // cc:622-626: mark all sinks
        for op in copy_sinks.iter() {
            op.write().unwrap().set_mark();
        }
        // cc:629-666: back-reachability BFS
        let mut pos = 0;
        while pos < copy_sinks.len() {
            let op_arc = copy_sinks[pos].clone();
            pos += 1;
            let addr = match op_arc.read().unwrap().output.as_ref() {
                Some(o) => o.read().unwrap().loc,
                None => continue,
            };
            let num_in = op_arc.read().unwrap().num_input();
            for i in 0..num_in {
                let vn = match op_arc.read().unwrap().get_in(i) {
                    Some(v) => v.clone(), None => continue,
                };
                if !vn.read().unwrap().is_written() { continue; }
                // cc:637: if (vn->isAddrForce()) continue; — the walk stops
                // at already-address-forced varnodes. GETPARAM-OPPOOL-COUNT
                // -0001: this guard was annotated but not implemented, so
                // the walk pushed through addrforced chains and flagged
                // extra ops (e.g. COPY@3f3f:2a stack:fc40) into `forces`,
                // whose spurious ADDRFORCE then blocked RulePropagateCopy's
                // marker guard (ruleaction.cc:3948).
                if vn.read().unwrap().is_addr_force() { continue; }
                // cc:640: skip already marked
                let def_op = match vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                    Some(d) => d, None => continue,
                };
                if def_op.read().unwrap().is_mark() { continue; }
                def_op.write().unwrap().set_mark();
                let opc = def_op.read().unwrap().opcode;
                let mut is_artificial = false;
                if opc == OpCode::CPUI_COPY || opc == OpCode::CPUI_MULTIEQUAL {
                    is_artificial = true;
                    let n = def_op.read().unwrap().num_input();
                    for j in 0..n {
                        let in_vn = match def_op.read().unwrap().get_in(j) {
                            Some(v) => v.clone(), None => { is_artificial = false; break; }
                        };
                        if in_vn.read().unwrap().loc != addr {
                            is_artificial = false;
                            break;
                        }
                    }
                } else if opc == OpCode::CPUI_INDIRECT && def_op.read().unwrap().is_indirect_store() {
                    let in_vn = match def_op.read().unwrap().get_in(0) {
                        Some(v) => v.clone(), None => continue,
                    };
                    if in_vn.read().unwrap().loc == addr {
                        is_artificial = true;
                    }
                }
                if is_artificial {
                    copy_sinks.push(def_op.clone());
                } else {
                    forces.push(def_op.clone());
                }
            }
        }
    }

    // Ghidra: heritage.cc:674 Heritage::propagateCopyAway
    /// Eliminate a COPY sink, propagating input to all readers.
    /// Faithful to `propagateCopyAway` (heritage.cc:674-688).
    pub fn propagate_copy_away(&self, fd: &mut Funcdata, op: &PcodeOpRef) {
        // cc:678-685: follow COPY chain to earliest input
        let mut in_vn = match op.0.read().unwrap().get_in(0) {
            Some(v) => v.clone(), None => return,
        };
        loop {
            let def_op = in_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
            let def_op = match def_op { Some(d) => d, None => break ,
            };
            if def_op.read().unwrap().opcode != OpCode::CPUI_COPY { break; }
            let next_in = match def_op.read().unwrap().get_in(0) {
                Some(v) => v.clone(), None => break,
            };
            let same_address = {
                let next = next_in.read().unwrap();
                let current = in_vn.read().unwrap();
                next.address_space == current.address_space && next.loc == current.loc
            };
            if !same_address { break; }
            in_vn = next_in;
        }
        // cc:686: totalReplace(op->getOut(), inVn)
        let out_vn = match op.0.read().unwrap().output.as_ref() {
            Some(o) => o.clone(), None => return,
        };
        fd.total_replace(&out_vn, in_vn);
        // cc:687: fd->opDestroy(op).  This unlinks the op's Varnodes, moves
        // it to the bank's dead list, and removes it from its BlockBasic.
        fd.op_destroy(op);
    }

    // Ghidra: heritage.cc:695 Heritage::handleNewLoadCopies
    /// Mark load guard COPY boundaries and eliminate artificial COPYs.
    /// Faithful to `handleNewLoadCopies` (heritage.cc:696-731).
    pub fn handle_new_load_copies(&mut self, fd: &mut Funcdata) {
        if self.load_copy_ops.is_empty() { return; }
        // Upgrade Weak to Arc
        let sink_arcs: Vec<Arc<RwLock<PcodeOp>>> = self
            .load_copy_ops
            .iter()
            .filter_map(|w| w.upgrade())
            .collect();
        if sink_arcs.is_empty() { self.load_copy_ops.clear(); return; }
        let copy_sink_size = sink_arcs.len();
        let mut forces: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut all_sinks = sink_arcs.clone();
        self.find_address_forces(fd, &mut all_sinks, &mut forces);
        for force_op in &forces {
            if let Some(out_vn) = force_op.read().unwrap().output.as_ref() {
                let vn_addr = out_vn.read().unwrap().loc.as_u64();
                let in_range = self
                    .load_guard
                    .iter()
                    .any(|g| vn_addr >= g.minimum_offset && vn_addr <= g.maximum_offset
                );
                if in_range {
                    out_vn
                        .write()
                        .unwrap()
                        .set_flags(
                        crate::varnode::varnode_flags::ADDRFORCE);
                }
            }
            force_op.write().unwrap().clear_mark();
        }
        for i in 0..copy_sink_size {
            let op_ref = PcodeOpRef(sink_arcs[i].clone());
            self.propagate_copy_away(fd, &op_ref);
        }
        for i in copy_sink_size..all_sinks.len() {
            all_sinks[i].write().unwrap().clear_mark();
        }
        self.load_copy_ops.clear();
    }

    // Ghidra: heritage.cc:244 Heritage::removeRevisitedMarkers
    /// Remove previously-heritaged markers and convert them to SUBPIECE
    /// of a larger free Varnode. Faithful to `removeRevisitedMarkers`
    /// (heritage.cc:244-297): an INDIRECT marker is uninserted and
    /// reinserted AFTER the target of the INDIRECT (cc:265-273, the
    /// replacement INDIRECT keeps the address so the old output is
    /// addr-force cleared); a MULTIEQUAL marker is reinserted after ALL
    /// leading MULTIEQUALs in its block (cc:275-280); a return-form COPY
    /// is unlinked outright (cc:281-284). The converted op becomes
    /// SUBPIECE(big, offset) with a fresh active-heritage whole-range
    /// input (cc:285-294) and the original output is write-masked
    /// (cc:295).
    pub fn remove_revisited_markers(
        &mut self,
        fd: &mut Funcdata,
        remove: &[Arc<RwLock<Varnode>>],
        space: AddressSpace,
        addr: Address,
        size: i32,
    ) {
        // cc:247: HeritageInfo *info = getInfo(addr.getSpace()); — the
        // space of the heritaged RANGE (the caller's MemRange space), not
        // the space of the first removed varnode. The two coincide on
        // every oracle-reachable input (placeMultiequals cc:2626 guards
        // !removevars.empty() and collect()'s loc-tree window stays within
        // one space), but the derivation here mirrors the oracle form
        // directly: the range's space is authoritative.
        let info_idx = self.infolist.iter().position(|i| i.space == space);
        // cc:247-257: if deadremoved > 0, bump delay + one-time warning
        // header naming the revisited address in printRaw form.
        // AddrSpace::printRaw (space.cc:206-221): "0x" plus the offset
        // zero-filled to 2*addrsize hex digits, with the leading-zero
        // shrink rule (offset>>32==0 -> 4 bytes, else >>48==0 -> 6 for
        // 8-byte spaces); no space name.
        if let Some(idx) = info_idx {
            if self.infolist[idx].deadremoved > 0 {
                self.bump_deadcode_delay(fd, space);
                if !self.infolist[idx].warning_issued {
                    self.infolist[idx].warning_issued = true;
                    let mut sz = space.addr_size();
                    let off = addr.as_u64();
                    if sz > 4 {
                        if (off >> 32) == 0 {
                            sz = 4;
                        } else if (off >> 48) == 0 {
                            sz = 6;
                        }
                    }
                    let mut errmsg = String::from("Heritage AFTER dead removal. Revisit: ");
                    errmsg.push_str(&format!("0x{:0width$x}", off, width = 2 * sz));
                    fd.warning_header(&errmsg);
                }
            }
        }
        for vn_arc in remove {
            let vn_r = vn_arc.read().unwrap();
            let def_op = match vn_r.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d, None => continue,
            };
            let def_code = def_op.read().unwrap().opcode;
            let parent = def_op
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|p| p.upgrade());
            let Some(bl) = parent else { continue };
            drop(vn_r);
            let def_ref = PcodeOpRef(def_op.clone());
            // cc:265-280 resolve the reinsertion position as an ELEMENT
            // anchor captured on the PRE-removal block list — Ghidra's
            // `pos` is a list iterator that keeps pointing at the anchor
            // element across the opUninsert at cc:286, and opInsert
            // (cc:294) inserts before it. A numeric index computed on the
            // pre-removal list shifts by one after the removal (and can
            // exceed the shrunken list at the block tail, tripping the
            // opInsert range assert).
            //   - INDIRECT, dead/unresolvable target: cc:268-269 the
            //     anchor is the element after the INDIRECT itself.
            //   - INDIRECT, alive target: cc:270-272 the anchor is the
            //     element after the target op.
            //   - MULTIEQUAL: cc:275-280 the anchor is the first
            //     non-MULTIEQUAL element after the leading ME group.
            let bl_ops = bl.read().unwrap().get_ops();
            let self_pos = bl_ops.iter().position(|c| Arc::ptr_eq(&c.0, &def_op));
            let anchor: Option<crate::op::PcodeOpRef>;
            if def_code == OpCode::CPUI_INDIRECT {
                let target = {
                    let def_r = def_op.read().unwrap();
                    def_r.get_in(1).and_then(|iop_vn| {
                        let iv = iop_vn.read().unwrap();
                        if iv.get_space() == AddressSpace::Iop {
                            let raw = iv.get_offset() as usize
                                as *const std::sync::RwLock<PcodeOp>;
                            // Recover the aliased target op from the bank
                            // (Ghidra's PcodeOp::getOpFromConst round-trip).
                            fd.obank
                                .optree
                                .iter()
                                .find(|candidate| {
                                    std::sync::Arc::as_ptr(&candidate.0) as *const ()
                                        == raw as *const ()
                                })
                                .cloned()
                        } else {
                            None
                        }
                    })
                };
                let target_alive_pos = target.as_ref().and_then(|target_op| {
                    let target_dead =
                        (target_op.0.read().unwrap().flags & crate::op::pcodeop_flags::DEAD) != 0;
                    if target_dead {
                        return None;
                    }
                    bl_ops.iter().position(|c| Arc::ptr_eq(&c.0, &target_op.0))
                });
                let Some(self_pos) = self_pos else {
                    // The op is not in its parent block; the locked oracle
                    // dereferences a stale iterator here. Skip the op.
                    continue;
                };
                let anchor_pos = match target_alive_pos {
                    // cc:270-272: ++targetOp->getBasicIter()
                    Some(tp) => {
                        // If the target's immediate successor is the
                        // INDIRECT itself (about to be uninserted), the
                        // anchor degenerates to the INDIRECT's own
                        // successor — the element after the removed slot.
                        if tp + 1 == self_pos {
                            self_pos + 1
                        } else {
                            tp + 1
                        }
                    }
                    // cc:268-269: ++op->getBasicIter()
                    None => self_pos + 1,
                };
                anchor = bl_ops
                    .get(anchor_pos)
                    .map(|o| crate::op::PcodeOpRef(o.0.clone()));
                // cc:273: vn->clearAddrForce()
                vn_arc.write().unwrap().clear_addr_force();
            } else if def_code == OpCode::CPUI_MULTIEQUAL {
                let Some(self_pos) = self_pos else {
                    continue;
                };
                let mut pos = self_pos + 1;
                while pos < bl_ops.len()
                    && bl_ops[pos].0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL
                {
                    pos += 1;
                }
                anchor = bl_ops.get(pos).map(|o| crate::op::PcodeOpRef(o.0.clone()));
            } else {
                // cc:281-284: remove return form COPY
                fd.op_unlink(&def_ref);
                continue;
            }
            drop(bl_ops);
            // cc:285-286: offset = vn->overlap(addr,size); opUninsert(op)
            let vn_loc = vn_arc.read().unwrap().loc.as_u64();
            let offset = vn_loc.wrapping_sub(addr.as_u64());
            let vn_space = vn_arc.read().unwrap().address_space;
            fd.op_uninsert(&def_ref);
            // cc:288-291: big = newVarnode(size,addr); setActiveHeritage;
            // newInputs = [big, newConstant(4, offset)]
            let big = fd
                .vbank
                .create_with_space(size as usize, vn_space, addr.as_u64());
            // heritage.cc:288 routes through Funcdata::newVarnode, whose
            // symbol tail attaches the typelocked global's DWARF type
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&big);
            big.write().unwrap().set_active_heritage();
            let off_const = fd.new_constant(4, offset);
            // cc:292-293: opSetOpcode(SUBPIECE) + opSetAllInput
            fd.op_set_opcode(&def_ref, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&def_ref, big, 0);
            fd.op_set_input(&def_ref, off_const, 1);
            // cc:294: opInsert(op, bl, pos) — before the captured anchor
            // element, or at the end when the anchor is the list end.
            match anchor {
                Some(a) => {
                    fd.op_insert_before(&def_ref, &a);
                }
                None => {
                    fd.op_insert(&def_ref, &bl, None);
                }
            }
            // cc:295: vn->setWriteMask()
            vn_arc.write().unwrap().set_write_mask();
        }
    }

    // Ghidra: heritage.cc:1111 Heritage::reprocessFreeStores
    /// Revisit STOREs with free pointers now that a heritage pass has
    /// completed. Faithful 1:1 port of `reprocessFreeStores`
    /// (heritage.cc:1111-1141): clear the spacebase marks, rediscover, then
    /// for every STORE that no longer uses a spacebase pointer walk the
    /// contiguous INDIRECT group immediately before it and remove exactly
    /// the guards whose IOP input aliases this STORE and whose output lives
    /// in the guarded space (`totalReplace` + `opDestroy`).
    pub fn reprocess_free_stores(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        free_stores: &mut Vec<Arc<RwLock<PcodeOp>>>,
    ) {
        // cc:1114-1115: fd->opClearSpacebasePtr(freeStores[i])
        for op_arc in free_stores.iter() {
            fd.op_clear_spacebase_ptr(&PcodeOpRef(op_arc.clone()));
        }
        // cc:1117: discoverIndexedStackPointers(spc, freeStores, false)
        // — with checkFreeStores=false the walk only re-establishes the
        // spacebase marks (and any fresh guard records); it cannot append
        // to free_stores.
        let _ = self.discover_indexed_stack_pointers(fd, space, free_stores, false);
        // cc:1119-1140: remove the now-unnecessary INDIRECTs.
        for op_arc in free_stores.iter() {
            // cc:1124: if (op->usesSpacebasePtr()) continue
            if op_arc.read().unwrap().uses_spacebase_ptr() {
                continue;
            }
            // cc:1127-1128: indOp = op->previousOp() backward walk.
            let mut ind_op = op_arc
                .read()
                .unwrap()
                .previous_op_in_block(&fd.obank)
                .map(|r| r.0.clone());
            while let Some(ind_arc) = ind_op {
                // cc:1129: if (indOp->code() != CPUI_INDIRECT) break
                if ind_arc.read().unwrap().opcode != OpCode::CPUI_INDIRECT {
                    break;
                }
                // cc:1130-1131: iop input must be an Iop-space varnode.
                let iop_vn = ind_arc.read().unwrap().get_in(1).cloned();
                let iop_vn = match iop_vn {
                    Some(vn) if vn.read().unwrap().get_space() == AddressSpace::Iop => vn,
                    _ => break,
                };
                // cc:1132: if (op != PcodeOp::getOpFromConst(iopVn->getAddr())) break
                // — the IOP varnode must alias THIS store op.
                let aliased_op = fd.get_op_from_const(&iop_vn);
                let aliases_this = aliased_op
                    .as_ref()
                    .map(|r| Arc::ptr_eq(&r.0, op_arc))
                    .unwrap_or(false);
                if !aliases_this {
                    break;
                }
                // cc:1133: nextOp is read before any possible destroy.
                let next_op = ind_arc
                    .read()
                    .unwrap()
                    .previous_op_in_block(&fd.obank)
                    .map(|r| r.0.clone());
                // cc:1134-1137: remove guards whose output is in the space.
                let out_space = ind_arc
                    .read()
                    .unwrap()
                    .output
                    .as_ref()
                    .map(|o| o.read().unwrap().address_space);
                if out_space == Some(space) {
                    let (out_vn, in_vn) = {
                        let r = ind_arc.read().unwrap();
                        (r.output.as_ref().cloned(), r.get_in(0).cloned())
                    };
                    if let (Some(out), Some(inv)) = (out_vn, in_vn) {
                        fd.total_replace(&out, inv);
                    }
                    fd.op_destroy(&PcodeOpRef(ind_arc.clone()));
                }
                ind_op = next_op;
            }
        }
    }

    // Ghidra: heritage.cc:834 Heritage::analyzeNewLoadGuards
    /// Analyze new load/store guards using value-set analysis. Faithful port
    /// of `analyzeNewLoadGuards` (heritage.cc:834-900): collect the trailing
    /// runs of unanalyzed guards (load list first, then store list), build
    /// the ValueSetSolver over their pointer sinks, solve with WidenerNone,
    /// establishRange each, then (if any guard is still state 0) re-solve
    /// with WidenerFull and finalizeRange each.
    ///
    /// GETPARAM-OPPOOL-COUNT-0001: this used to be a documented stub
    /// claiming "Rugra lacks ValueSetSolver" — but src/rangeutil.rs ports the
    /// solver (establish_value_sets/solve/get_value_set_read +
    /// WidenerNone/WidenerFull). The stub kept every guard at the full-stack
    /// `[0, highest]` range, so RuleIndirectCollapse's store-guard arm
    /// (ruleaction.cc:3203-3218) never collapsed stack INDIRECTs.
    ///
    /// The solver's branch-condition constraint machinery
    /// (applyConstraints/constraintsFromCbranch/generateConstraints/
    /// generateRelativeConstraint, RANGEUTIL-CONSTGEN-0001) is implemented;
    /// constraints only ever narrow guard ranges.
    pub fn analyze_new_load_guards(&mut self, fd: &mut Funcdata) {
        // cc:837-846: nothingToDo — only the back of each list is checked
        let mut nothing_to_do = true;
        if self
            .load_guard
            .last()
            .is_some_and(|g| g.analysis_state == 0)
        {
            nothing_to_do = false;
        }
        if self
            .store_guard
            .last()
            .is_some_and(|g| g.analysis_state == 0)
        {
            nothing_to_do = false;
        }
        if nothing_to_do {
            return;
        }

        // cc:850-865: walk both lists back-to-front collecting the trailing
        // unanalyzed runs: reads <- guard.op, sinks <- guard.op->getIn(1)
        let mut sinks: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut reads: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut load_start = self.load_guard.len();
        while load_start > 0 {
            let g = &self.load_guard[load_start - 1];
            if g.analysis_state != 0 {
                break;
            }
            if let Some(op) = g.op.upgrade() {
                let ptr = op.read().unwrap().inrefs.get(1).cloned();
                if let Some(ptr) = ptr {
                    sinks.push(ptr);
                    reads.push(op);
                }
            }
            load_start -= 1;
        }
        let mut store_start = self.store_guard.len();
        while store_start > 0 {
            let g = &self.store_guard[store_start - 1];
            if g.analysis_state != 0 {
                break;
            }
            if let Some(op) = g.op.upgrade() {
                let ptr = op.read().unwrap().inrefs.get(1).cloned();
                if let Some(ptr) = ptr {
                    sinks.push(ptr);
                    reads.push(op);
                }
            }
            store_start -= 1;
        }

        // cc:866-869: stackSpc = arch->getStackSpace(); stackReg =
        //   fd->findSpacebaseInput(stackSpc) when a spacebase exists
        let stack_reg = fd.find_spacebase_input(AddressSpace::Stack);

        // cc:870-873: establishValueSets(sinks, reads, stackReg, false);
        //   solve(10000, WidenerNone)
        let mut solver = crate::rangeutil::ValueSetSolver::new();
        solver.establish_value_sets(&sinks, &reads, stack_reg, false);
        let widener_none = crate::rangeutil::WidenerNone::new();
        solver.solve(10000, &widener_none);

        // cc:876-887: establishRange each new guard; note if full analysis
        //   is still needed (any guard left at analysisState 0)
        let mut run_full_analysis = false;
        for idx in load_start..self.load_guard.len() {
            Self::establish_guard_range(&mut solver, &mut self.load_guard[idx]);
            if self.load_guard[idx].analysis_state == 0 {
                run_full_analysis = true;
            }
        }
        for idx in store_start..self.store_guard.len() {
            Self::establish_guard_range(&mut solver, &mut self.store_guard[idx]);
            if self.store_guard[idx].analysis_state == 0 {
                run_full_analysis = true;
            }
        }

        // cc:888-899: full widening pass + finalizeRange each new guard
        if run_full_analysis {
            let widener_full = crate::rangeutil::WidenerFull::new();
            solver.solve(10000, &widener_full);
            for idx in load_start..self.load_guard.len() {
                Self::finalize_guard_range(&mut solver, &mut self.load_guard[idx]);
            }
            for idx in store_start..self.store_guard.len() {
                Self::finalize_guard_range(&mut solver, &mut self.store_guard[idx]);
            }
        }
    }

    // RUDRA-GLUE: borrow-splitting helper — applies
    // LoadGuard::establishRange with the solver's ValueSetRead for the
    // guard op's SeqNum (cc:878/884). When the solver holds no read for the
    // op (dead-op skip inside establish_value_sets — Ghidra's raw-pointer
    // map find cannot miss for ops it was handed), the Ghidra-unreachable
    // fallback applies the full-range arm semantics (min=pointerBase,
    // size=0x1000, state=1) so the guard is analyzed once and conservatively.
    fn establish_guard_range(solver: &mut crate::rangeutil::ValueSetSolver, guard: &mut LoadGuard) {
        let seq = guard.op.upgrade().map(|op| op.read().unwrap().get_seq_num().clone());
        match seq.as_ref().and_then(|s| solver.get_value_set_read(s)) {
            Some(vsr) => guard.establish_range(vsr),
            None => {
                guard.minimum_offset = guard.pointer_base;
                guard.analysis_state = 1;
            }
        }
    }

    // RUDRA-GLUE: borrow-splitting helper — applies
    // LoadGuard::finalizeRange (cc:893/897); same dead-op fallback as
    // establish_guard_range keeps state 1 with the established range.
    fn finalize_guard_range(solver: &mut crate::rangeutil::ValueSetSolver, guard: &mut LoadGuard) {
        let seq = guard.op.upgrade().map(|op| op.read().unwrap().get_seq_num().clone());
        match seq.as_ref().and_then(|s| solver.get_value_set_read(s)) {
            Some(vsr) => guard.finalize_range(vsr),
            None => {
                guard.analysis_state = 1;
            }
        }
    }

    // Ghidra: heritage.cc:1210 Heritage::guardCallOverlappingInput
    /// Guard an address range that is larger than any single input
    /// parameter for the given call: construct a SUBPIECE that pulls out
    /// the potential parameter. Faithful 1:1 port of
    /// `guardCallOverlappingInput` (heritage.cc:1210-1235), including the
    /// callee→caller truncAddr translation (cc:1218-1219) and the
    /// registerTrial-before-opInsertInput order (cc:1231-1232).
    pub fn guard_call_overlapping_input(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
    ) {
        // cc:1215: if (fc->getBiggestContainedInputParam(transAddr, size, vData))
        let v_data = match fd
            .get_call_specs(fc_idx)
            .and_then(|fc| {
                fc.prototype
                    .get_biggest_contained_input_param(space, trans_offset, size)
            }) {
            Some(v) => v,
            None => return,
        };
        let (_v_space, v_offset, v_size) = v_data;
        // cc:1218-1219: truncAddr in caller perspective.
        let diff = v_offset.wrapping_sub(trans_offset);
        let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
        // cc:1220: if (active->whichTrial(truncAddr, size) < 0)
        let already_trial = fd
            .get_call_specs(fc_idx)
            .map(|fc| {
                fc.active_input
                    .which_trial_in_space(space, trunc_addr, size)
                    >= 0
            })
            .unwrap_or(true);
        if already_trial {
            return;
        }
        // cc:1221: truncateAmount = addr.justifiedContain(size, truncAddr, vData.size, false)
        // address.cc:138-141: with forceleft=false the heritage space's
        // endianness selects the distance — little-endian spaces count
        // from the range start (truncAddr - addr), big-endian from the
        // end (FSPEC-JUSTIFIED-ENDIAN-0002).
        let truncate_amount = crate::fspec::justified_contain_range(
            addr.as_u64(),
            size,
            trunc_addr.as_u64(),
            v_size,
            false,
            space.is_big_endian(),
        );
        // cc:1222-1223: subpieceOp = newOp(2, op->getAddr())
        let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
            Some(op) => op,
            None => return,
        };
        let op_addr = call_op.0.read().unwrap().get_addr();
        let subpiece_op = fd.new_op(2, op_addr);
        // cc:1224: opSetOpcode(subpieceOp, CPUI_SUBPIECE)
        fd.op_set_opcode(&subpiece_op, OpCode::CPUI_SUBPIECE);
        // cc:1225-1226: wholeVn = newVarnode(size, addr); setActiveHeritage
        let whole_vn = fd
            .vbank
            .create_with_space(size as usize, space, addr.as_u64());
        // heritage.cc:1225 routes through Funcdata::newVarnode, whose symbol
        // tail attaches the typelocked global's DWARF type
        // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
        fd.set_varnode_properties(&whole_vn);
        whole_vn.write().unwrap().set_active_heritage();
        fd.op_set_input(&subpiece_op, whole_vn, 0);
        // cc:1228: opSetInput(subpieceOp, newConstant(4, truncateAmount), 1)
        let off_const = fd.new_constant(4, truncate_amount as u64);
        fd.op_set_input(&subpiece_op, off_const, 1);
        // cc:1229: vn = newVarnodeOut(vData.size, truncAddr, subpieceOp) —
        // truncAddr = addr + diff lives in the guarded RANGE's space (the
        // oracle Address is space-qualified; the Register-pinned adapter
        // fabricated cross-space varnodes, HERITAGE-CROSSSPACE-MERGE-0001).
        let vn = fd.new_varnode_out_full(v_size as usize, space, trunc_addr, &subpiece_op);
        // cc:1230: opInsertBefore(subpieceOp, op)
        fd.op_insert_before(&subpiece_op, &call_op);
        // cc:1231: active->registerTrial(truncAddr, vData.size)
        if let Some(mut fc) = fd.get_call_specs_mut(fc_idx) {
            fc.active_input
                .register_trial_in_space(space, trunc_addr, v_size);
        }
        // cc:1232: opInsertInput(op, vn, op->numInput())
        let num_in = call_op.0.read().unwrap().num_input();
        fd.op_insert_input(&call_op, vn, num_in);
    }

    // Ghidra: heritage.cc:1248 Heritage::guardOutputOverlap
    /// Insert created INDIRECT ops to guard the output of a call when the
    /// guarded range properly contains the return storage. Faithful 1:1
    /// port of `guardOutputOverlap` (heritage.cc:1248-1282): the return
    /// storage becomes an indirectly created value (`newIndirectCreation`
    /// with possibleout=true), the front piece aliases the return-storage
    /// INDIRECT (not the call), the back piece aliases the call, and the
    /// pieces are recombined with PIECE ops inserted after the call.
    pub fn guard_output_overlap(
        &mut self,
        fd: &mut Funcdata,
        call_op: &crate::op::PcodeOpRef,
        space: AddressSpace,
        addr: Address,
        size: i32,
        ret_addr: Address,
        ret_size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1251-1252: front/back split sizes.
        let size_front = (ret_addr.as_u64().saturating_sub(addr.as_u64())) as i32;
        let size_back = size - ret_size - size_front;
        // cc:1253: the return storage itself is an indirect creation with
        // possibleout=true (a possible call output).
        let ind_op = fd.new_indirect_creation_in_space(
            call_op, space, ret_addr.as_u64(), ret_size as usize, true,
        );
        // cc:1254: vnCollect = indOp->getOut()
        let mut vn_collect = ind_op.0.read().unwrap().output.as_ref().cloned();
        // cc:1259/1272: both concat ops are created with indOp->getAddr() —
        // the address of the return-storage INDIRECT creation (which
        // newIndirectCreation derives from the causing op: the call), NOT
        // retAddr (the guarded range address). MATCHURL-CONCAT-SEQNUM-0001:
        // passing ret_addr gave the PIECE ops a register-space SeqNum pc
        // (e.g. 0x1200), flipping the projection's seqnum-sorted op order
        // at the heritage snapshot (first divergence: ordinal 12, op-idx 0).
        let ind_op_addr = ind_op.0.read().unwrap().get_addr();
        // cc:1273/1260 endianness: the locked oracle arch is x86:LE:64, so
        // retAddr.isBigEndian() == false (Rugra Address carries no space,
        // so the flag cannot be consulted dynamically; ADDRESS-0001).
        let big_endian = false;
        // cc:1256-1267: front piece (aliases the return-storage INDIRECT).
        if size_front != 0 {
            let ind_front = fd.new_indirect_creation_in_space(
                &ind_op, space, addr.as_u64(), size_front as usize, false,
            );
            let new_front = ind_front.0.read().unwrap().output.as_ref().cloned();
            let concat_front = fd.new_op(2, ind_op_addr);
            let slot_new = if big_endian { 0 } else { 1 };
            fd.op_set_opcode(&concat_front, OpCode::CPUI_PIECE);
            if let (Some(front_vn), Some(collect_vn)) = (&new_front, &vn_collect) {
                fd.op_set_input(&concat_front, front_vn.clone(), slot_new);
                fd.op_set_input(&concat_front, collect_vn.clone(), 1 - slot_new);
            }
            // cc:1264: vnCollect = fd->newVarnodeOut(sizeFront+retSize,addr,
            // concatFront) — the Address is the guarded RANGE's full storage
            // address (space + offset). The spaceless Register-pinned adapter
            // fabricated register-space varnodes at stack/ram range offsets
            // (HERITAGE-CROSSSPACE-MERGE-0001).
            vn_collect = Some(fd.new_varnode_out_full(
                (size_front + ret_size) as usize,
                space,
                addr,
                &concat_front,
            ));
            // cc:1265-1266: opInsertAfter(concatFront, callOp)
            fd.op_insert_after(&concat_front, call_op);
        }
        // cc:1268-1279: back piece (aliases the call).
        if size_back != 0 {
            let addr_back = Address::new(ret_addr.as_u64().wrapping_add(ret_size as u64));
            let ind_back = fd.new_indirect_creation_in_space(
                call_op, space, addr_back.as_u64(), size_back as usize, false,
            );
            let new_back = ind_back.0.read().unwrap().output.as_ref().cloned();
            let concat_back = fd.new_op(2, ind_op_addr);
            let slot_new = if big_endian { 1 } else { 0 };
            fd.op_set_opcode(&concat_back, OpCode::CPUI_PIECE);
            if let (Some(back_vn), Some(collect_vn)) = (&new_back, &vn_collect) {
                fd.op_set_input(&concat_back, back_vn.clone(), slot_new);
                fd.op_set_input(&concat_back, collect_vn.clone(), 1 - slot_new);
            }
            // cc:1277: vnCollect = fd->newVarnodeOut(size,addr,concatBack) —
            // the range's full storage address (space-qualified, see
            // cc:1264 note).
            vn_collect = Some(fd.new_varnode_out_full(size as usize, space, addr, &concat_back));
            // cc:1278: opInsertAfter(concatBack, insertPoint)
            // insertPoint is the call when no front piece ran, else the
            // front concat; the front concat was inserted directly after
            // the call, so inserting after the call keeps Ghidra's order
            // only for the no-front case. With a front piece Ghidra
            // inserts the back concat after concatFront.
            if size_front != 0 {
                // The front concat is the op immediately after the call.
                // Reuse op_insert_after chain: insert after concatFront.
                // (Resolve it as the op right after the call.)
                let next = {
                    let parent = call_op
                        .0
                        .read()
                        .unwrap()
                        .parent
                        .as_ref()
                        .and_then(|w| w.upgrade());
                    match parent {
                        Some(blk) => {
                            let ops = blk.read().unwrap().get_ops();
                            let pos = ops
                                .iter()
                                .position(|o| std::sync::Arc::ptr_eq(&o.0, &call_op.0));
                            pos.and_then(|p| ops.get(p + 1)).cloned()
                        }
                        None => None,
                    }
                };
                match next {
                    Some(follow) => fd.op_insert_after(&concat_back, &follow),
                    None => fd.op_insert_after(&concat_back, call_op),
                }
            } else {
                fd.op_insert_after(&concat_back, call_op);
            }
        }
        // cc:1280-1281: setActiveHeritage + append to write.
        if let Some(collect_vn) = vn_collect {
            collect_vn.write().unwrap().set_active_heritage();
            write.push(collect_vn);
        }
    }

    // Ghidra: heritage.cc:1292 Heritage::tryOutputOverlapGuard
    /// Try to guard an address range that is larger than the possible
    /// output storage for the given call. Faithful 1:1 port of
    /// `tryOutputOverlapGuard` (heritage.cc:1292-1309): the truncAddr
    /// translation, the trial lookup with the RANGE size (cc:1304) and the
    /// registration with the TRUNCATED size (cc:1307) are exact.
    pub fn try_output_overlap_guard(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        // cc:1298: if (!fc->getBiggestContainedOutput(transAddr, size, vData))
        let v_data = match fd
            .get_call_specs(fc_idx)
            .and_then(|fc| {
            fc.prototype
                .get_biggest_contained_output(space, trans_offset, size)
        })
        {
            Some(v) => v,
            None => {
                return false;
            }
        };
        let (_v_space, v_offset, v_size) = v_data;
        // cc:1301-1303: truncAddr in caller perspective.
        let diff = v_offset.wrapping_sub(trans_offset);
        let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
        // cc:1304: if (active->whichTrial(truncAddr, size) >= 0) return false
        let already_trial = fd
            .get_call_specs(fc_idx)
            .map(|fc| {
                fc.active_output
                    .which_trial_in_space(space, trunc_addr, size)
                    >= 0
            })
            .unwrap_or(true);
        if already_trial {
            return false;
        }
        // cc:1306: guardOutputOverlap(fc->getOp(), addr, size, truncAddr, vData.size, write)
        let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
            Some(op) => op,
            None => return false,
        };
        self.guard_output_overlap(
            fd, &call_op, space, addr, size, trunc_addr, v_size, write);
        // cc:1307: active->registerTrial(truncAddr, vData.size)
        if let Some(mut fc) = fd.get_call_specs_mut(fc_idx) {
            fc.active_output
                .register_trial_in_space(space, trunc_addr, v_size);
        }
        true
    }

    // Ghidra: heritage.cc:1538 Heritage::guardStores
    /// Guard STORE ops in preparation for the renaming algorithm. Faithful
    /// port of `guardStores` (heritage.cc:1538-1559): iterate the STORE
    /// opcode list in bank order, skip dead ops, and match the STORE's
    /// constant target space against the heritage range's space or its
    /// container (with `usesSpacebasePtr` required for the container case,
    /// cc:1551-1552). Each match produces one INDIRECT with the
    /// `indirect_store` flag whose output joins `write` in iteration order.
    pub fn guard_stores_range(
        &mut self,
        fd: &mut Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1544: container = spc->getContain() — for the enum-space model
        // only the Stack (spacebase) space has a container, which is Ram.
        // RUDRA-GLUE: enum AddressSpace exposes no getContain; this mirrors
        // the locked x86:LE:64 oracle's contain graph.
        let container: Option<AddressSpace> = match space {
            AddressSpace::Stack => Some(AddressSpace::Ram),
            _ => None,
        };
        // cc:1547-1548: iter=fd->beginOp(CPUI_STORE) .. endOp
        // One read guard per STORE covers the oracle's three field reads
        // (cc:1549 isDead, cc:1550 getIn(0), cc:1552 usesSpacebasePtr) plus
        // the const-space decode of the pointer varnode — same dead-filter,
        // same iteration order, same classification, same short-circuit.
        let store_matches: Vec<(
            std::sync::Arc<std::sync::RwLock<PcodeOp>>,
            Option<AddressSpace>,
            bool,
        )> = fd
            .obank
            .iter_store()
            .filter_map(|s| {
                let r = s.0.read().unwrap();
                if r.flags & crate::op::pcodeop_flags::DEAD != 0 {
                    return None;
                }
                let store_space = r.get_in(0).map(|vn| {
                    let vr = vn.read().unwrap();
                    if vr.is_constant() {
                        AddressSpace::from_id(vr.get_offset() as crate::space::SpaceId)
                    } else {
                        vr.address_space
                    }
                });
                Some((s.0.clone(), store_space, r.uses_spacebase_ptr()))
            })
            .collect();
        for (store_op, store_space, uses_sb) in store_matches {
            // cc:1550-1552: match against the range space or its container.
            let Some(store_space) = store_space else { continue ;
            };
            let matches = store_space == space || (container == Some(store_space) && uses_sb);
            if !matches {
                continue;
            }
            // cc:1553: indop = fd->newIndirectOp(op,addr,size,indirect_store)
            let indop = fd.new_indirect_op(
                &PcodeOpRef(store_op.clone()),
                space,
                addr.as_u64(),
                size as usize,
                crate::op::pcodeop_flags::INDIRECT_STORE,
            );
            // cc:1554-1556: setActiveHeritage on input[0] and output; push.
            let (invn, outvn) = {
                let ind_r = indop.0.read().unwrap();
                (ind_r.get_in(0).cloned(), ind_r.output.as_ref().cloned())
            };
            if let Some(vn) = invn {
                vn.write().unwrap().set_active_heritage();
            }
            if let Some(vn) = outvn {
                vn.write().unwrap().set_active_heritage();
                write.push(vn);
            }
        }
    }

    // Ghidra: heritage.cc:1570 Heritage::guardLoads
    /// Guard LOAD ops for a specific range. Faithful to `guardLoads`
    /// (heritage.cc:1570-1601): the fl/addrtied gate (cc:1576), the
    /// invalid-guard pruning during iteration (cc:1577-1586), the
    /// range-start window test (cc:1587-1589) and the per-LOAD COPY
    /// boundary insertion (cc:1590-1599, landed 2026-09-23 by
    /// SB-MATCHURL-ORD55-0001; the guard-window refinement feeding
    /// `handle_new_load_copies` is `analyze_new_load_guards`' real
    /// ValueSetSolver, GETPARAM-OPPOOL-COUNT-0001/RANGEUTIL-VSEMPTY-0001).
    /// The full placement/rename/propagate-away/addrforce chain is
    /// fixture-verified byte-identical against the locked oracle by
    /// tests/oracle/heritage_storeload_fwd_1204 (KUNABUGS-STORELOAD-FWD-0001).
    pub fn guard_loads_range(
        &mut self,
        fd: &mut Funcdata,
        fl: u32,
        space: AddressSpace,
        addr: Address,
        size: i32,
        _write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        // cc:1576: if ((fl & Varnode::addrtied)==0) return
        if (fl & crate::varnode::varnode_flags::ADDRTIED) == 0 {
            return;
        }
        // cc:1577-1586: prune guards that are no longer valid LOADs.
        self.load_guard.retain(|g| match g.op.upgrade() {
                Some(op) => {
                    let r = op.read().unwrap();
                    !(r.flags & crate::op::pcodeop_flags::DEAD != 0
                        || r.opcode != OpCode::CPUI_LOAD)
                }
                None => false,
            });
        // cc:1587: if (guardRec.spc != addr.getSpace()) continue
        // cc:1588-1589: if (addr.getOffset() < guardRec.minimumOffset)
        //                    continue;  if (addr.getOffset() >
        //                    guardRec.maximumOffset) continue;
        // The oracle tests the RANGE START offset against the guard window
        // (not a two-sided range intersection).
        let addr_offset = addr.as_u64();
        let guarded_ops: Vec<Arc<RwLock<PcodeOp>>> = self
            .load_guard
            .iter()
            .filter(|g| g.spc == space)
            .filter(|g| !(addr_offset < g.minimum_offset || addr_offset > g.maximum_offset))
            .filter_map(|g| g.op.upgrade())
            .collect();
        for load_op in guarded_ops {
            // cc:1590: copyop = fd->newOp(1,guardRec.op->getAddr())
            let load_addr = load_op.read().unwrap().get_addr();
            let copyop = fd.new_op(1, load_addr);
            // cc:1591-1593: vn = newVarnodeOut(size,addr,copyop);
            // setActiveHeritage; setAddrForce
            let vn = fd.new_varnode_out_full(size as usize, space, addr, &copyop);
            vn.write().unwrap().set_active_heritage();
            vn.write().unwrap().set_addr_force();
            // cc:1594: opSetOpcode(copyop,CPUI_COPY)
            fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
            // cc:1595-1596: invn = newVarnode(size,addr);
            // setActiveHeritage (heritage.cc:2638 routes through
            // Funcdata::newVarnode's symbol tail — HERITAGE-MULTIEQ-VNIN-
            // SYMBOLTAIL-0001 pattern)
            let invn = fd
                .vbank
                .create_with_space(size as usize, space, addr.as_u64());
            fd.set_varnode_properties(&invn);
            invn.write().unwrap().set_active_heritage();
            // cc:1597: opSetInput(copyop,invn,0)
            fd.op_set_input(&copyop, invn, 0);
            // cc:1598: opInsertBefore(copyop,guardRec.op)
            fd.op_insert_before(&copyop, &PcodeOpRef(load_op));
            // cc:1599: loadCopyOps.push_back(copyop)
            self.load_copy_ops.push(Arc::downgrade(&copyop.0));
        }
    }

    // Ghidra: heritage.cc:2118 Heritage::splitJoinRead
    /// Construct pieces for a \e join-space Varnode read by an operation:
    /// build a concatenation expression (PIECE ops) that constructs the
    /// Varnode out of the JoinRecord's pieces, one split level at a time.
    /// Faithful to `splitJoinRead` (heritage.cc:2118-2163). The joinrec
    /// comes from the caller (`processJoins`), exactly like the oracle.
    pub fn split_join_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        // cc:2121: op = vn->loneDescend(); // vn isFree, so loneDescend
        // must be non-null — the oracle dereferences unconditionally.
        // Rust mirrors with an early return (oracle would crash).
        let mut op = match vn.read().unwrap().lone_descend() {
            Some(op) => PcodeOpRef(op),
            None => return,
        };
        // cc:2122-2125: isPrimitive defaults true; a typelocked vn only
        // stays primitive when its type isPrimitiveWhole.
        let is_primitive = {
            let vnr = vn.read().unwrap();
            if vnr.is_type_lock() {
                vnr.get_type()
                    .map(|t| t.is_primitive_whole())
                    .unwrap_or(false)
            } else {
                true
            }
        };

        // cc:2127-2161: iterative PIECE-chain construction via split levels.
        let mut lastcombo: Vec<Arc<RwLock<Varnode>>> = vec![vn.clone()];
        let mut nextlev: Vec<Option<Arc<RwLock<Varnode>>>> = Vec::new();
        while lastcombo.len() < joinrec.num_pieces() {
            nextlev.clear();
            self.split_join_level(fd, &lastcombo, &mut nextlev, joinrec);

            for i in 0..lastcombo.len() {
                let curvn = lastcombo[i].clone();
                let mosthalf = match nextlev.get(2 * i) {
                    Some(Some(v)) => v.clone(),
                    _ => continue,
                };
                let leasthalf = match nextlev.get(2 * i + 1) {
                    // cc:2138: leasthalf == null → Varnode didn't get split
                    // this level.
                    Some(Some(v)) => v.clone(),
                    _ => continue,
                };
                // cc:2139-2144: concat = newOp(2,op->getAddr()); PIECE;
                // output=curvn; inputs most/least; insertBefore(op).
                let op_addr = op.0.read().unwrap().get_addr();
                let concat = fd.new_op(2, op_addr);
                fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
                // Must go through Funcdata::op_set_output (funcdata_op.cc:70):
                // the full def/descend wiring, matching opSetOutput.
                fd.op_set_output(&concat, curvn.clone());
                fd.op_set_input(&concat, mosthalf.clone(), 0);
                fd.op_set_input(&concat, leasthalf.clone(), 1);
                fd.op_insert_before(&concat, &op);
                if is_primitive {
                    // cc:2146-2147: precision flags trigger the
                    // "double precision" rules on the halves.
                    mosthalf.write().unwrap().set_precis_hi();
                    leasthalf.write().unwrap().set_precis_lo();
                } else {
                    // cc:2150: opMarkNoCollapse(concat)
                    fd.op_mark_no_collapse(&concat);
                }
                // cc:2152: op = concat — keep -op- as the earliest op in
                // the concatenation construction.
                op = concat;
            }

            lastcombo.clear();
            for curvn in nextlev.drain(..) {
                if let Some(v) = curvn {
                    lastcombo.push(v);
                }
            }
        }
    }

    // Ghidra: heritage.cc:2171 Heritage::splitJoinWrite
    /// Split a written \e join-space Varnode into specified pieces: build
    /// SUBPIECE expressions that construct the JoinRecord's pieces from
    /// the Varnode. Faithful to `splitJoinWrite` (heritage.cc:2171-2227).
    /// The joinrec comes from the caller (`processJoins`).
    pub fn split_join_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        // cc:2174: op = vn->getDef(); // vn cannot be free, either it has
        // def, or it is input — None mirrors the null-def input case.
        let mut op: Option<PcodeOpRef> = vn
            .read()
            .unwrap()
            .def
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(PcodeOpRef);
        // cc:2175: bb = fd->getBasicBlocks().getBlock(0)
        let bb0 = fd.bblocks.get_block(0);
        let is_input = vn.read().unwrap().is_input();
        // cc:2176-2178: isPrimitive defaults true; typelocked vns only
        // stay primitive when their type isPrimitiveWhole.
        let is_primitive = {
            let vnr = vn.read().unwrap();
            if vnr.is_type_lock() {
                vnr.get_type()
                    .map(|t| t.is_primitive_whole())
                    .unwrap_or(false)
            } else {
                true
            }
        };

        // cc:2180-2225: iterative SUBPIECE construction via split levels.
        let mut lastcombo: Vec<Arc<RwLock<Varnode>>> = vec![vn.clone()];
        let mut nextlev: Vec<Option<Arc<RwLock<Varnode>>>> = Vec::new();
        while lastcombo.len() < joinrec.num_pieces() {
            nextlev.clear();
            self.split_join_level(fd, &lastcombo, &mut nextlev, joinrec);
            for i in 0..lastcombo.len() {
                let curvn = lastcombo[i].clone();
                let mosthalf = match nextlev.get(2 * i) {
                    Some(Some(v)) => v.clone(),
                    _ => continue,
                };
                let leasthalf = match nextlev.get(2 * i + 1) {
                    // cc:2190: leasthalf == null → didn't split this level.
                    Some(Some(v)) => v.clone(),
                    _ => continue,
                };
                // cc:2192-2195: input bases anchor the SUBPIECE at block
                // 0's start; written bases at the definer's address.
                let leasthalf_size = leasthalf.read().unwrap().get_size() as u64;
                let split_addr = if is_input {
                    match bb0.as_ref() {
                        Some(bb) => bb.read().unwrap().get_start_addr(),
                        None => crate::address::Address::new(0),
                    }
                } else {
                    match op.as_ref() {
                        Some(o) => o.0.read().unwrap().get_addr(),
                        None => crate::address::Address::new(0),
                    }
                };
                // cc:2196-2199: SUBPIECE for mosthalf; the shift constant
                // is leasthalf's size (least significant run below most).
                let split = fd.new_op(2, split_addr);
                fd.op_set_opcode(&split, OpCode::CPUI_SUBPIECE);
                // opSetOutput(split,mosthalf) — full def wiring.
                fd.op_set_output(&split, mosthalf.clone());
                fd.op_set_input(&split, curvn.clone(), 0);
                let off_const = fd.new_constant(4, leasthalf_size);
                fd.op_set_input(&split, off_const, 1);
                // cc:2200-2203: null def (input) inserts at the head of
                // block 0; otherwise right after the running op.
                match op.as_ref() {
                    None => {
                        if let Some(bb) = bb0.as_ref() {
                            fd.op_insert_begin(&split, bb);
                        }
                    }
                    Some(o) => fd.op_insert_after(&split, o),
                }
                // cc:2204: op = split — keep -op- as the latest op in the
                // split construction.
                op = Some(split);

                // cc:2206-2211: SUBPIECE for leasthalf at shift 0,
                // inserted after the mosthalf SUBPIECE.
                let split2_addr = op
                    .as_ref()
                    .map(|o| o.0.read().unwrap().get_addr())
                    .unwrap_or_else(|| crate::address::Address::new(0));
                let split2 = fd.new_op(2, split2_addr);
                fd.op_set_opcode(&split2, OpCode::CPUI_SUBPIECE);
                fd.op_set_output(&split2, leasthalf.clone());
                fd.op_set_input(&split2, curvn.clone(), 0);
                let zero_const = fd.new_constant(4, 0u64);
                fd.op_set_input(&split2, zero_const, 1);
                if let Some(o) = op.as_ref() {
                    fd.op_insert_after(&split2, o);
                }
                if is_primitive {
                    // cc:2212-2214: precision flags trigger the
                    // "double precision" rules on the halves.
                    mosthalf.write().unwrap().set_precis_hi();
                    leasthalf.write().unwrap().set_precis_lo();
                }
                // cc:2216: op = split — latest op.
                op = Some(split2);
            }

            lastcombo.clear();
            for curvn in nextlev.drain(..) {
                if let Some(v) = curvn {
                    lastcombo.push(v);
                }
            }
        }
    }

    // Ghidra: heritage.cc:2067 Heritage::splitJoinLevel
    /// One level of Varnode splitting to match a JoinRecord: split all
    /// the pieces in \p lastcombo into \p nextlev (2 entries per input,
    /// pass-throughs get a null second entry to maintain the 2-1
    /// mapping). Faithful to `splitJoinLevel` (heritage.cc:2067-2109).
    pub fn split_join_level(
        &mut self,
        fd: &mut Funcdata,
        lastcombo: &[Arc<RwLock<Varnode>>],
        nextlev: &mut Vec<Option<Arc<RwLock<Varnode>>>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        let numpieces = joinrec.num_pieces();
        let mut recnum = 0;
        for curvn_arc in lastcombo {
            let curvn_size = curvn_arc.read().unwrap().get_size();
            // cc:2074-2078: a size exactly matching the current piece
            // passes through (null leasthalf). recnum < numpieces is an
            // invariant of the caller's while condition (each curvn
            // consumes at least one piece); the bound is panic-safety.
            if recnum < numpieces && curvn_size == joinrec.get_piece(recnum).size {
                nextlev.push(Some(curvn_arc.clone()));
                nextlev.push(None);
                recnum += 1;
            } else {
                // cc:2080-2089: accumulate piece sizes from recnum until
                // they sum to curvn's size; j ends one past the last
                // consumed piece (or numpieces when the record's tail is
                // consumed without an exact match — excluded by the
                // JoinRecord/unified size invariant).
                let mut sizeaccum = 0;
                let mut j = recnum;
                while j < numpieces {
                    sizeaccum += joinrec.get_piece(j).size;
                    if sizeaccum == curvn_size {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                // cc:2090: numinhalf = (j-recnum) / 2 — "Will be at least
                // 1" (oracle comment): the else arm means piece(recnum)
                // alone cannot equal curvn_size, so j moves at least one
                // full piece past recnum. The guard below is panic-safety
                // for the invariant-violating tail case only.
                let numinhalf = (j - recnum) / 2;
                if numinhalf == 0 {
                    nextlev.push(None);
                    nextlev.push(None);
                    continue;
                }
                // cc:2091-2093: accumulate the mosthalf size.
                let mut mh_size = 0;
                for k in 0..numinhalf {
                    mh_size += joinrec.get_piece(recnum + k).size;
                }
                // cc:2094-2097: a single-piece mosthalf takes the piece's
                // real storage; a multi-piece mosthalf is a fresh unique.
                let mosthalf = if numinhalf == 1 {
                    let p = joinrec.get_piece(recnum);
                    let vn = fd.vbank.create_with_space(p.size, p.space, p.offset);
                    // heritage.cc:2095: newVarnode's symbol tail on the
                    // piece (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                    fd.set_varnode_properties(&vn);
                    vn
                } else {
                    fd.new_unique(mh_size)
                };
                // cc:2098-2103: an exactly-two-piece remainder takes the
                // piece's real storage; otherwise a fresh unique.
                let lh_size = curvn_size - mh_size;
                let leasthalf = if j - recnum == 2 {
                    let p = joinrec.get_piece(recnum + 1);
                    let vn = fd.vbank.create_with_space(p.size, p.space, p.offset);
                    // heritage.cc:2100: newVarnode's symbol tail on the
                    // piece (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                    fd.set_varnode_properties(&vn);
                    vn
                } else {
                    fd.new_unique(lh_size)
                };
                nextlev.push(Some(mosthalf));
                nextlev.push(Some(leasthalf));
                recnum = j;
            }
        }
    }

    // Ghidra: heritage.cc:2235 Heritage::floatExtensionRead
    /// Create float truncation into a free lower precision \e join-space
    /// Varnode: define the lower precision Varnode as a FLOAT2FLOAT
    /// truncation of the record's full-precision piece. Faithful to
    /// `floatExtensionRead` (heritage.cc:2235-2246). The joinrec comes
    /// from the caller (`processJoins`); the isFloatExtension dispatch
    /// happens there (cc:2299), not here.
    pub fn float_extension_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        // cc:2239: op = vn->loneDescend(); // vn isFree, so loneDescend
        // must be non-null — the oracle dereferences unconditionally.
        let read_op = match vn.read().unwrap().lone_descend() {
            Some(op) => op,
            None => return,
        };
        // cc:2240: vdata = joinrec->getPiece(0) — float extensions have
        // exactly 1 piece.
        let vdata = joinrec.get_piece(0);
        // cc:2240: trunc = newOp(1, op->getAddr())
        let op_addr = read_op.read().unwrap().get_addr();
        let trunc = fd.new_op(1, op_addr);
        // cc:2241: bigvn = newVarnode(vdata.size,vdata.space,vdata.offset)
        let bigvn = fd
            .vbank
            .create_with_space(vdata.size, vdata.space, vdata.offset);
        // heritage.cc:2241 routes through Funcdata::newVarnode's
        // explicit-space overload, whose symbol tail runs on the piece
        // before the FLOAT2FLOAT wiring (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
        fd.set_varnode_properties(&bigvn);
        // cc:2242: opSetOpcode(FLOAT_FLOAT2FLOAT)
        fd.op_set_opcode(&trunc, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
        // cc:2243: opSetOutput(trunc, vn) — full def wiring.
        fd.op_set_output(&trunc, vn.clone());
        // cc:2244: opSetInput(trunc, bigvn, 0)
        fd.op_set_input(&trunc, bigvn, 0);
        // cc:2245: opInsertBefore(trunc, op)
        fd.op_insert_before(&trunc, &PcodeOpRef(read_op));
    }

    // Ghidra: heritage.cc:2255 Heritage::floatExtensionWrite
    /// Create float extension from a lower precision \e join-space
    /// Varnode: define the record's full-precision piece via a FLOAT2FLOAT
    /// extension of the Varnode. Faithful to `floatExtensionWrite`
    /// (heritage.cc:2255-2273). The joinrec comes from the caller
    /// (`processJoins`); the isFloatExtension dispatch happens there
    /// (cc:2308), not here.
    pub fn float_extension_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        joinrec: &crate::space::JoinRecord,
    ) {
        // cc:2258: op = vn->getDef() (null for input varnodes).
        let def_op = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        // cc:2259: bb = fd->getBasicBlocks().getBlock(0)
        let bb0 = fd.bblocks.get_block(0);
        let is_input = vn.read().unwrap().is_input();
        let vdata = joinrec.get_piece(0);
        // cc:2261-2264: input bases anchor at block 0's start; written
        // bases at the definer's address.
        let ext_addr = if is_input {
            match bb0.as_ref() {
                Some(bb) => bb.read().unwrap().get_start_addr(),
                None => Address::new(0),
            }
        } else {
            match &def_op {
                Some(op) => op.read().unwrap().get_addr(),
                None => Address::new(0),
            }
        };
        let ext = fd.new_op(1, ext_addr);
        // cc:2266: opSetOpcode(FLOAT_FLOAT2FLOAT)
        fd.op_set_opcode(&ext, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
        // cc:2267: newVarnodeOut(vdata.size, vdata.getAddr(), ext) — the
        // piece's own full storage address (space + offset, register space
        // for float pieces; the Register-pinned adapter happened to match
        // but is kept honest via the piece's own space,
        // HERITAGE-CROSSSPACE-MERGE-0001).
        let _out_vn = fd.new_varnode_out_full(
            vdata.size,
            vdata.space,
            crate::address::Address::new(vdata.offset),
            &ext,
        );
        // cc:2268: opSetInput(ext, vn, 0)
        fd.op_set_input(&ext, vn.clone(), 0);
        // cc:2269-2272: null def (input) inserts at the head of block 0
        // (opInsertBegin); otherwise right after the definer.
        match def_op {
            Some(op) => fd.op_insert_after(&ext, &PcodeOpRef(op)),
            None => {
                if let Some(bb) = bb0.as_ref() {
                    fd.op_insert_begin(&ext, bb);
                }
            }
        }
    }

    // Ghidra: heritage.cc:1322 Heritage::guardOutputOverlapStack
    /// Guard a stack range that contains the return value storage.
    /// Faithful to `guardOutputOverlapStack` (heritage.cc:1323-1376).
    /// Creates INDIRECT pieces for front/back + PIECE concat. The SUBPIECE
    /// truncate constants come from the endian-routed
    /// `Address::justifiedContain` calls (cc:1336/cc:1358 via
    /// `justified_contain_range`), and both PIECE concats insert after the
    /// running cc:1327 insert point (HERITAGE-GUARD-SUBPIECE-CONST-0001).
    pub fn guard_output_overlap_stack(
        &mut self,
        fd: &mut Funcdata,
        call_op: &Arc<RwLock<PcodeOp>>,
        addr: Address,
        size: i32,
        ret_addr: Address,
        ret_size: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let size_front = (ret_addr.as_u64().saturating_sub(addr.as_u64())) as i32;
        let size_back = size - ret_size - size_front;
        let op_addr = call_op.read().unwrap().get_addr();

        // cc:1329-1330: vnCollect = callOp->getOut() or
        // newVarnodeOut(retSize, retAddr, callOp) — retAddr is a full STACK
        // storage address on this path; the Register-pinned adapter
        // fabricated register-space varnodes at stack offsets
        // (HERITAGE-CROSSSPACE-MERGE-0001).
        let existing_out = call_op.read().unwrap().output.as_ref().cloned();
        let mut vn_collect = existing_out
            .unwrap_or_else(|| {
            fd.new_varnode_out_full(
                ret_size as usize,
                AddressSpace::Stack,
                ret_addr,
                &PcodeOpRef(call_op.clone()),
            )
        });
        // cc:1327: insertPoint = callOp — both PIECE concats insert after the
        // RUNNING insert point, not always after the call: cc:1349-1350
        // advances it to concatFront, so with both pieces present the back
        // concat lands after the front concat (cc:1371).
        let mut insert_point = PcodeOpRef(call_op.clone());

        // cc:1332-1352: front piece
        if size_front > 0 {
            let new_input = fd.vbank
                    .create_with_space(size as usize, AddressSpace::Stack, addr.as_u64());
            // heritage.cc:1332 routes through Funcdata::newVarnode, whose
            // symbol tail runs before setActiveHeritage
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&new_input);
            new_input.write().unwrap().set_active_heritage();
            let sub_piece = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_piece, OpCode::CPUI_SUBPIECE);
            // cc:1336: truncateAmount = addr.justifiedContain(size, addr,
            // sizeFront, false) — op2 == addr so the containment is
            // trivially exact and the guards never fire; address.cc:138-141
            // then routes on the range space's endianness: LE returns the
            // start distance 0, BE the end distance size - sizeFront. The
            // guarded range lives in the stack space, whose endianness is
            // the routing input (HERITAGE-GUARD-SUBPIECE-CONST-0001).
            let truncate_front = crate::fspec::justified_contain_range(
                addr.as_u64(),
                size,
                addr.as_u64(),
                size_front,
                false,
                AddressSpace::Stack.is_big_endian(),
            );
            let off_const = fd.new_constant(4, truncate_front as u64);
            fd.op_set_input(&sub_piece, new_input, 0);
            fd.op_set_input(&sub_piece, off_const, 1);
            let ind_front = fd.new_indirect_op(
                &PcodeOpRef(call_op.clone()), AddressSpace::Stack,
                addr.as_u64(), size_front as usize, 0,
            );
            // cc:1340: fd->opSetOutput(subPiece, indOpFront->getIn(0)) — the
            // INDIRECT's free in[0] varnode becomes the SUBPIECE's written
            // output. Must go through op_set_output for the full def wiring
            // (funcdata_op.cc:70-83: vbank setDef + setVarnodeProperties),
            // not a bare output field write that leaves the varnode free.
            let ind_front_in0 = ind_front.0.read().unwrap().get_in(0).cloned();
            if let Some(vn) = ind_front_in0 {
                fd.op_set_output(&sub_piece, vn);
            }
            fd.op_insert_before(&sub_piece, &PcodeOpRef(call_op.clone()));
            let new_front = ind_front
                .0
                .read()
                .unwrap()
                .output
                .as_ref()
                .cloned()
                .unwrap_or_else(|| fd.new_unique(size_front as usize));
            // cc:1344-1351: PIECE concat
            let concat = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
            // LE: newFront=slot1, vnCollect=slot0
            fd.op_set_input(&concat, new_front, 1);
            fd.op_set_input(&concat, vn_collect.clone(), 0);
            // cc:1348: vnCollect = fd->newVarnodeOut(sizeFront+retSize,addr,
            // concatFront) — stack-storage Address (see cc:1330 note).
            vn_collect = fd.new_varnode_out_full(
                (size_front + ret_size) as usize,
                AddressSpace::Stack,
                addr,
                &concat,
            );
            // cc:1349-1350: opInsertAfter(concatFront, insertPoint);
            // insertPoint = concatFront;
            fd.op_insert_after(&concat, &insert_point);
            insert_point = concat;
        }

        // cc:1353-1373: back piece
        if size_back > 0 {
            let addr_back = Address::new(ret_addr.as_u64().wrapping_add(ret_size as u64));
            let new_input = fd.vbank
                    .create_with_space(size as usize, AddressSpace::Stack, addr.as_u64());
            // heritage.cc:1353 routes through Funcdata::newVarnode, whose
            // symbol tail runs before setActiveHeritage
            // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&new_input);
            new_input.write().unwrap().set_active_heritage();
            let sub_piece = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_piece, OpCode::CPUI_SUBPIECE);
            // cc:1358: truncateAmount = addr.justifiedContain(size, addrBack,
            // sizeBack, false) with addrBack = retAddr + retSize — the LE
            // start distance is sizeFront + retSize (NOT 0), the BE end
            // distance is size - sizeFront - retSize - sizeBack = 0
            // (address.cc:138-141). HERITAGE-GUARD-SUBPIECE-CONST-0001: this
            // constant was wrongly hardcoded to the FRONT piece's LE value 0,
            // so SUBPIECE(whole, 0) extracted the front bytes instead of the
            // back piece.
            let truncate_back = crate::fspec::justified_contain_range(
                addr.as_u64(),
                size,
                addr_back.as_u64(),
                size_back,
                false,
                AddressSpace::Stack.is_big_endian(),
            );
            let off_const = fd.new_constant(4, truncate_back as u64);
            fd.op_set_input(&sub_piece, new_input, 0);
            fd.op_set_input(&sub_piece, off_const, 1);
            let ind_back = fd.new_indirect_op(
                &PcodeOpRef(call_op.clone()), AddressSpace::Stack,
                addr_back.as_u64(), size_back as usize, 0,
            );
            // cc:1362: fd->opSetOutput(subPiece, indOpBack->getIn(0)) — same
            // full def wiring as the front piece (funcdata_op.cc:70-83).
            let ind_back_in0 = ind_back.0.read().unwrap().get_in(0).cloned();
            if let Some(vn) = ind_back_in0 {
                fd.op_set_output(&sub_piece, vn);
            }
            fd.op_insert_before(&sub_piece, &PcodeOpRef(call_op.clone()));
            let new_back = ind_back
                .0
                .read()
                .unwrap()
                .output
                .as_ref()
                .cloned()
                .unwrap_or_else(|| fd.new_unique(size_back as usize));
            let concat = fd.new_op(2, op_addr);
            fd.op_set_opcode(&concat, OpCode::CPUI_PIECE);
            // LE: newBack=slot0, vnCollect=slot1
            fd.op_set_input(&concat, new_back, 0);
            fd.op_set_input(&concat, vn_collect.clone(), 1);
            // cc:1370: vnCollect = fd->newVarnodeOut(size,addr,concatBack) —
            // stack-storage Address (see cc:1330 note).
            vn_collect = fd.new_varnode_out_full(size as usize, AddressSpace::Stack, addr, &concat);
            // cc:1371: opInsertAfter(concatBack, insertPoint) — after the
            // front concat when one exists, else right after the call.
            fd.op_insert_after(&concat, &insert_point);
        }

        // cc:1374-1375
        vn_collect.write().unwrap().set_active_heritage();
        write.push(vn_collect);
    }

    // Ghidra: heritage.cc:1391 Heritage::tryOutputStackGuard
    /// Attempt to guard a stack range against a call with a locked stack
    /// output. Faithful port of both branches:
    ///  - `contained_by` (cc:1395-1405): the biggest contained output is
    ///    translated to the caller's perspective and guarded by
    ///    `guard_output_overlap_stack`.
    ///  - output-contains (cc:1406-1430): the call's output varnode is
    ///    created at the caller-perspective return address when missing
    ///    (cc:1413-1416), and when the range is smaller than the return
    ///    storage a SUBPIECE truncates the output down to the range
    ///    (cc:1417-1425) with the cc:1420 truncate constant — the FOURTH
    ///    justifiedContain touchpoint — routed through the endian-aware
    ///    `justified_contain_range`.
    ///
    /// The return storage is read from the call spec's proto-store output
    /// parameter exactly as the Ghidra original does (cc:1407
    /// `fc->getOutput()->getAddress()` / cc:1410 `getSize()`), through
    /// `FuncCallSpecs::get_output_storage` (the flat-store `outparam::addr`
    /// stand-in). Production reaches this function only through the
    /// `isStackOutputLock` gate (heritage.cc:1487), which
    /// ActionFuncLink::funcLinkOutput sets exclusively for a locked non-void
    /// output whose recorded storage is in the spacebase space
    /// (coreaction.cc:1546-1549) — so the storage is always present on the
    /// production path. A call spec without recorded storage (a state
    /// Ghidra cannot reach) conservatively reports `false`, keeping
    /// guardCalls' unknown_effect INDIRECT guard (the never-under-protect
    /// direction).
    pub fn try_output_stack_guard(
        &mut self,
        fd: &mut Funcdata,
        fc_idx: usize,
        space: AddressSpace,
        addr: Address,
        trans_offset: u64,
        size: i32,
        output_character: i32,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> bool {
        if output_character == crate::fspec::containment::CONTAINED_BY {
            // cc:1396-1400: if (!fc->getBiggestContainedOutput(...)) return false
            let v_data = match fd.get_call_specs(fc_idx).and_then(|fc| {
                fc.prototype
                    .get_biggest_contained_output(space, trans_offset, size)
            }) {
                Some(v) => v,
                None => return false,
            };
            let (_v_space, v_offset, v_size) = v_data;
            // cc:1400-1403: truncAddr in caller perspective.
            let diff = v_offset.wrapping_sub(trans_offset);
            let trunc_addr = Address::new(addr.as_u64().wrapping_add(diff));
            // cc:1403: guardOutputOverlapStack(callOp, addr, size, truncAddr, vData.size, write)
            let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
                Some(op) => op,
                None => return false,
            };
            self.guard_output_overlap_stack(
                fd,
                &call_op.0,
                addr,
                size,
                trunc_addr,
                v_size,
                write);
            return true;
        }
        // cc:1406: Reaching here, output exists and contains the heritage
        // range. retAddr = fc->getOutput()->getAddress();
        // retSize = fc->getOutput()->getSize() — both read from the call
        // spec's proto-store output parameter (the flat-store
        // `output_storage` + the return type's size,
        // `ParameterBasic::getSize()` = type->getSize(), fspec.hh:1176).
        // No recorded storage (unreachable in Ghidra: the cc:1487 gate
        // implies funcLinkOutput saw a spacebase outparam address,
        // coreaction.cc:1546-1549) keeps the conservative false fallback.
        let Some((ret_space, ret_storage_off)) = fd
            .get_call_specs(fc_idx)
            .and_then(|fc| fc.get_output_storage())
        else {
            return false;
        };
        let ret_size = fd
            .get_call_specs(fc_idx)
            .map(|fc| fc.prototype.return_type.get_size() as i32)
            .unwrap_or(0);
        // cc:1408-1409: diff = (int4)(addr.getOffset() -
        // transAddr.getOffset()); retAddr = retAddr + diff — translate the
        // output address to the caller's perspective.
        let diff = addr.as_u64().wrapping_sub(trans_offset);
        let ret_addr = Address::new(ret_storage_off.wrapping_add(diff));
        // cc:1411: outvn = callOp->getOut();
        let call_op = match fd.get_call_specs(fc_idx).and_then(|fc| fc.find_call_op(fd)) {
            Some(op) => op,
            None => return false,
        };
        let mut vn_final: Option<Arc<RwLock<Varnode>>> = None;
        // Bind the read guard's take into a `let` before the match: in
        // edition 2021 a match scrutinee temporary lives through the arms,
        // so an inline scrutinee would hold the read lock while
        // new_varnode_out_full takes the write lock on the same op (the
        // same self-deadlock guard_output_overlap_stack fixed at cc:1329).
        let existing_out = call_op.0.read().unwrap().output.as_ref().cloned();
        let outvn = match existing_out {
            Some(existing) => existing,
            None => {
                // cc:1413-1416: outvn = fd->newVarnodeOut(retSize, retAddr,
                // callOp); vnFinal = outvn. retAddr is the call spec's
                // output storage Address — carried with its own space
                // (oracle cc:1407 getOutput()->getAddress());
                // HERITAGE-CROSSSPACE-MERGE-0001.
                let created = fd.new_varnode_out_full(
                    ret_size as usize,
                    ret_space,
                    ret_addr,
                    &call_op,
                );
                vn_final = Some(created.clone());
                created
            }
        };
        if size < ret_size {
            // cc:1418-1419: subPiece = fd->newOp(2, callOp->getAddr());
            // opSetOpcode(subPiece, CPUI_SUBPIECE);
            let op_addr = call_op.0.read().unwrap().get_addr();
            let sub_piece = fd.new_op(2, op_addr);
            fd.op_set_opcode(&sub_piece, OpCode::CPUI_SUBPIECE);
            // cc:1420: truncateAmount = retAddr.justifiedContain(retSize,
            // addr, size, false) — the fourth justifiedContain touchpoint
            // (after cc:1336/cc:1358 in guardOutputOverlapStack and the
            // characterization reads in fspec.cc:4344). Container = the
            // caller-perspective return storage, contained = the guarded
            // range; address.cc:138-141 routes on retAddr's space
            // endianness, which is the spacebase (stack) space on this path
            // — the same space the caller passes in.
            let truncate_amount = crate::fspec::justified_contain_range(
                ret_addr.as_u64(),
                ret_size,
                addr.as_u64(),
                size,
                false,
                space.is_big_endian(),
            );
            // cc:1421-1422: opSetInput(subPiece, newConstant(4,
            // truncateAmount), 1); opSetInput(subPiece, outvn, 0).
            let off_const = fd.new_constant(4, truncate_amount as u64);
            fd.op_set_input(&sub_piece, off_const, 1);
            fd.op_set_input(&sub_piece, outvn, 0);
            // cc:1423: vnFinal = fd->newVarnodeOut(size, addr, subPiece) —
            // addr is the guarded RANGE's full storage address
            // (space-qualified, HERITAGE-CROSSSPACE-MERGE-0001).
            vn_final = Some(fd.new_varnode_out_full(size as usize, space, addr, &sub_piece));
            // cc:1424: fd->opInsertAfter(subPiece, callOp);
            fd.op_insert_after(&sub_piece, &call_op);
        }
        // cc:1426-1429: if (vnFinal != (Varnode *)0) { vnFinal->
        // setActiveHeritage(); write.push_back(vnFinal); }
        if let Some(vn_final) = vn_final {
            vn_final.write().unwrap().set_active_heritage();
            write.push(vn_final);
        }
        // cc:1430: return true;
        true
    }

    // Ghidra: heritage.cc:2571 Heritage::bumpDeadcodeDelay
    /// Increase the heritage delay for the given AddrSpace and request a
    /// restart. Faithful to `bumpDeadcodeDelay` (heritage.cc:2573-2582):
    /// the delay is installed through the Funcdata-local Override (which
    /// survives `Funcdata::clear`, funcdata.cc:106 "Do not clear overrides")
    /// and consumed by `Override::applyDeadCodeDelay` at the next
    /// `Funcdata::startProcessing` (funcdata.cc:166); the current pass's
    /// `HeritageInfo` is deliberately NOT mutated here. The restart itself
    /// is requested via `Funcdata::setRestartPending(true)` and executed by
    /// `ActionRestartGroup::apply` (action.cc:553-582; the Rugra-side
    /// restart-cycle gap is tracked by PIPE-RESTART-0001).
    pub fn bump_deadcode_delay(&mut self, fd: &mut Funcdata, space: AddressSpace) {
        // cc:2574-2575: if ((spc->getType() != IPTR_PROCESSOR)&&
        // (spc->getType() != IPTR_SPACEBASE)) return;
        // Locked x86-64 kinds: Ram/Register are IPTR_PROCESSOR, Stack is
        // IPTR_SPACEBASE.
        if !matches!(
            space, AddressSpace::Ram | AddressSpace::Register | AddressSpace::Stack
        ) {
            return;
        }
        // cc:2576-2577: if (spc->getDelay() != spc->getDeadcodeDelay())
        // return;  -- there is already a global delay
        if space.get_delay() != space.get_deadcode_delay() {
            return;
        }
        // cc:2578-2579: if (fd->getOverride().hasDeadcodeDelay(spc))
        // return;  -- a delay has already been installed (override.cc:92-103)
        let index = usize::try_from(space.get_index()).unwrap_or(usize::MAX);
        if fd
            .localoverride
            .has_deadcode_delay(index, space.get_deadcode_delay())
        {
            return;
        }
        // cc:2580: fd->getOverride().insertDeadcodeDelay(spc,
        // spc->getDeadcodeDelay()+1);  (override.cc:79-89)
        fd.localoverride
            .insert_deadcode_delay(index, space.get_deadcode_delay() + 1);
        // cc:2581: fd->setRestartPending(true);
        fd.set_restart_pending(true);
    }

    // Ghidra: heritage.cc:2047 Heritage::clearStackPlaceholders
    /// Clear spacebase-relative placeholder info for all call specs.
    /// Faithful to `clearStackPlaceholders` (heritage.cc:2048-2056).
    pub fn clear_stack_placeholders(&mut self, fd: &mut Funcdata, info_space: AddressSpace) {
        // cc:2051-2054: for each call, abortSpacebaseRelative.
        let num_calls = fd.num_calls();
        // Clone only the stable Arc handles.  This keeps exact PcodeOp
        // identity available while `abortSpacebaseRelative` mutates Funcdata;
        // no address lookup or by-value callspec move is involved.
        let callspecs = fd.callspecs.clone();
        debug_assert_eq!(num_calls, callspecs.len());
        for callspec in callspecs {
            let call_op = callspec
                .read()
                .unwrap()
                .op
                .upgrade()
                .map(crate::op::PcodeOpRef);
            if let Some(op_ref) = call_op {
                callspec
                    .write()
                    .unwrap()
                    .abort_spacebase_relative(fd, &op_ref);
            }
        }
        // cc:2055: info->hasCallPlaceholders = false
        let idx = self.infolist.iter().position(|i| i.space == info_space);
        if let Some(i) = idx {
            self.infolist[i].has_call_placeholders = false;
        }
    }

    // Ghidra: heritage.cc:507 Heritage::concatPieces
    /// Concatenate Varnode pieces into a PIECE chain. Faithful to
    /// `concatPieces` (heritage.cc:508-551). Returns the final output.
    pub fn concat_pieces(
        &self,
        fd: &mut Funcdata,
        vnlist: &[Arc<RwLock<Varnode>>],
        insert_op: Option<&PcodeOpRef>,
        final_vn: &Arc<RwLock<Varnode>>,
    ) -> Arc<RwLock<Varnode>> {
        if vnlist.is_empty() { return final_vn.clone(); }
        let mut preexist = vnlist[0].clone();
        let is_bigendian = false; // Rugra: x86-64 is little-endian
        // cc:512-525: with a null insertop the expression goes to the
        // start block's beginning (getStartBlock + beginOp), and the ops
        // carry the function address; otherwise the ops insert before
        // insertop in its own block.
        //
        // cc:516-518/546 anchor semantics: insertiter = bl->beginOp() is
        // captured ONCE before the loop and is an ELEMENT anchor — the
        // block's original first op X. std::list::insert(insertiter, op)
        // inserts BEFORE that element every round, so the pieces keep
        // creation order [P1, P2, ..., X]; with an empty block the anchor
        // is endOp and every piece appends at the end in creation order.
        // A fixed numeric index 0 per round would REVERSE the pieces
        // (each later piece landing before the earlier ones).
        let (null_anchor, op_addr): (Option<crate::op::PcodeOpRef>, Address) = match insert_op {
            Some(op) => {
                let addr = op.0.read().unwrap().get_addr();
                (None, addr)
            }
            None => {
                let start = fd.bblocks.get_block(0);
                let has_entry = start
                    .as_ref()
                    .map(|b| {
                        (b.read().unwrap().get_flags() & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    })
                    .unwrap_or(false);
                if !has_entry {
                    // Ghidra getStartBlock throws "No start block
                    // registered" (block.cc:1649-1655); keep the op
                    // unparented and surface the same condition.
                    eprintln!("[HERITAGE] WARN: No start block registered");
                }
                let anchor = if has_entry {
                    let bl = fd.bblocks.get_block(0).expect("entry checked above");
                    let first_op = bl.read().unwrap().get_ops().first().cloned();
                    first_op.map(|o| crate::op::PcodeOpRef(o.0.clone()))
                } else {
                    None
                };
                (anchor, *fd.get_address())
            }
        };
        for i in 1..vnlist.len() {
            let vn = &vnlist[i];
            let newop = fd.new_op(2, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_PIECE);
            let newvn = if i == vnlist.len() - 1 {
                // cc:532-535: final op outputs finalvn via opSetOutput
                fd.op_set_output(&newop, final_vn.clone());
                final_vn.clone()
            } else {
                let pre_size = preexist.read().unwrap().get_size();
                let vn_size = vn.read().unwrap().get_size();
                fd.new_unique_out(pre_size + vn_size, &newop)
            };
            if is_bigendian {
                fd.op_set_input(&newop, preexist.clone(), 0);
                fd.op_set_input(&newop, vn.clone(), 1);
            } else {
                fd.op_set_input(&newop, vn.clone(), 0);
                fd.op_set_input(&newop, preexist.clone(), 1);
            }
            match insert_op {
                Some(ins_op) => fd.op_insert_before(&newop, ins_op),
                None => {
                    if let Some(anchor) = &null_anchor {
                        // cc:546: insert before the fixed first-op anchor
                        // so the pieces keep creation order before X.
                        fd.op_insert_before(&newop, anchor);
                    } else if fd.bblocks.get_block(0).is_some()
                        && (fd.bblocks.get_block(0).unwrap().read().unwrap().get_flags()
                            & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    {
                        // cc:546 with an empty start block: the anchor is
                        // endOp; every piece appends at the end.
                        let bl = fd.bblocks.get_block(0).unwrap();
                        fd.op_insert(&newop, &bl, None);
                    }
                }
            }
            preexist = newvn;
        }
        preexist
    }

    // Ghidra: heritage.cc:563 Heritage::splitPieces
    /// Build SUBPIECE ops to define piece Varnodes from a whole-range Varnode.
    /// Faithful to `splitPieces` (heritage.cc:564-605).
    pub fn split_pieces(
        &self,
        fd: &mut Funcdata,
        vnlist: &[Arc<RwLock<Varnode>>],
        insert_op: Option<&PcodeOpRef>,
        addr: Address,
        size: i32,
        start_vn: &Arc<RwLock<Varnode>>,
    ) {
        let is_bigendian = false;
        let baseoff = if is_bigendian {
            addr.as_u64().wrapping_add(size as u64)
        } else {
            addr.as_u64()
        };
        // cc:567-588: with a null insertop the SUBPIECE ops go to the
        // start block's beginning (getStartBlock + beginOp) carrying the
        // function address; otherwise they insert AFTER the write
        // (++insertiter) in the write's own block, carrying its address.
        //
        // cc:582-587/602 anchor semantics: ++insertiter follows the
        // ELEMENT after the write (Y) — every piece inserts BEFORE Y, so
        // the order is [W, S1, S2, S3, Y] in creation order; if the write
        // is the block tail the anchor is endOp and pieces append at the
        // end. The null-insertop anchor is the start block's original
        // first op (same element-anchor rule as concatPieces cc:516-518).
        // A fixed numeric write-position+1 per round would REVERSE the
        // pieces (each later piece landing right after the write).
        enum InsertAnchor {
            /// cc:586 ++insertiter: insert before this element every round.
            Before(
                Option<crate::op::PcodeOpRef>, std::sync::Arc<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>,
            ),
            /// cc:579-581: null insertop — anchor on the start block's
            /// first element, or append at the end when it is empty.
            StartBlock,
            /// Unparented insertop (unreachable in the oracle, which
            /// dereferences getParent): no insertion.
            None,
        }
        let (anchor, op_addr) = match insert_op {
            Some(op) => {
                let (o_addr, parent) = {
                    let o = op.0.read().unwrap();
                    (o.get_addr(), o.parent.as_ref().and_then(|p| p.upgrade()))
                };
                match parent {
                    Some(bl) => {
                        let write_pos = {
                            let ops = bl.read().unwrap().get_ops();
                            ops.iter()
                                .position(|candidate| Arc::ptr_eq(&candidate.0, &op.0))
                        };
                        match write_pos {
                            Some(pos) => {
                                let next_elem = bl
                                    .read()
                                    .unwrap()
                                    .get_ops()
                                    .get(pos + 1)
                                    .map(|o| crate::op::PcodeOpRef(o.0.clone()));
                                (InsertAnchor::Before(next_elem, bl), o_addr)
                            }
                            // The locked oracle dereferences
                            // insertop->getParent() and reads its basic
                            // iterator; an op not in its own parent block
                            // cannot reach this path.
                            None => (InsertAnchor::None, o_addr),
                        }
                    }
                    None => (InsertAnchor::None, o_addr),
                }
            }
            None => {
                let start = fd.bblocks.get_block(0);
                let has_entry = start
                    .as_ref()
                    .map(|b| {
                        (b.read().unwrap().get_flags() & crate::block::block_flags::ENTRY_POINT)
                            != 0
                    })
                    .unwrap_or(false);
                if !has_entry {
                    eprintln!("[HERITAGE] WARN: No start block registered");
                }
                (InsertAnchor::StartBlock, *fd.get_address())
            }
        };
        // Resolve the start-block first-op element anchor once (M3: same
        // element-anchor rule as concatPieces; pieces keep creation order
        // before the original first op, or append at the end when empty).
        let start_anchor: Option<crate::op::PcodeOpRef> = match &anchor {
            InsertAnchor::StartBlock => fd.bblocks.get_block(0).and_then(|bl| {
                bl.read()
                    .unwrap()
                    .get_ops()
                    .first()
                    .map(|o| crate::op::PcodeOpRef(o.0.clone()))
            }),
            _ => None,
        };
        for vn_arc in vnlist {
            let vn_r = vn_arc.read().unwrap();
            let diff = if is_bigendian {
                baseoff.wrapping_sub(vn_r.loc.as_u64().wrapping_add(vn_r.get_size() as u64))
            } else {
                vn_r.loc.as_u64().wrapping_sub(baseoff)
            };
            drop(vn_r);
            let newop = fd.new_op(2, op_addr);
            fd.op_set_opcode(&newop, OpCode::CPUI_SUBPIECE);
            fd.op_set_input(&newop, start_vn.clone(), 0);
            let diff_const = fd.new_constant(4, diff);
            fd.op_set_input(&newop, diff_const, 1);
            // cc:601: fd->opSetOutput(newop, vn)
            fd.op_set_output(&newop, vn_arc.clone());
            match &anchor {
                InsertAnchor::Before(next_elem, bl) => match next_elem {
                    // cc:602: insert before the fixed element after the
                    // write — pieces keep creation order before Y.
                    Some(y) => {
                        fd.op_insert_before(&newop, y);
                    }
                    // Write is the block tail: the anchor is endOp, every
                    // piece appends at the end.
                    None => {
                        fd.op_insert(&newop, bl, None);
                    }
                },
                InsertAnchor::StartBlock => {
                    if let Some(y) = &start_anchor {
                        fd.op_insert_before(&newop, y);
                    } else if let Some(bl) = fd.bblocks.get_block(0) {
                        fd.op_insert(&newop, &bl, None);
                    }
                }
                InsertAnchor::None => {}
            }
        }
    }

    // Ghidra: heritage.cc:307 Heritage::collect
    /// Collect free reads, writes, and inputs in the given address range.
    /// Faithful to `collect` (heritage.cc:307-347): the four output
    /// vectors are cleared (cc:310-313), write-mask Varnodes are skipped
    /// (cc:326), a written Varnode whose def is a marker or return-form
    /// COPY is evidence of previous heritage — smaller than the range it
    /// goes to `remove` (cc:330-333), otherwise the range's
    /// new_addresses property is cleared (cc:334) — max write size is
    /// tracked (cc:336-337) and the written Varnode joins `write`
    /// (cc:338), a free Varnode with a descendant joins `read`
    /// (cc:340-341), and an input Varnode joins `input` (cc:342-343).
    ///
    /// Space-identity note: Ghidra scans beginLoc(memrange.addr) through
    /// endLoc(endaddr), which is confined to the MemRange's own address
    /// space (its Address carries the space); the probe-based live window
    /// below preserves exactly that — entries of other spaces never enter
    /// the iteration (HERITAGE-DRIVER-SWITCH-0001 space-key fix; the
    /// historical whole-bank offset filter misclassified cross-space
    /// collisions).
    ///
    /// Wraparound note (cc:317-320): when `memrange.addr + memrange.size`
    /// wraps past the top of the space (wrapped end offset < start offset),
    /// the oracle does NOT use beginLoc(endaddr) — it clamps the window end
    /// to endLoc(Address(space, getHighest())), i.e. the scan runs from
    /// start to the END of the space with no offset bound
    /// (HERITAGE-COLLECT-WRAPAROUND-0001).
    pub fn collect(
        &self,
        fd: &Funcdata,
        memrange: &mut MemRange,
        read: &mut Vec<Arc<RwLock<Varnode>>>,
        write: &mut Vec<Arc<RwLock<Varnode>>>,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
        remove: &mut Vec<Arc<RwLock<Varnode>>>,
    ) -> i32 {
        read.clear();
        write.clear();
        input.clear();
        remove.clear();
        let addr = memrange.addr;
        let size = memrange.size;
        // cc:315: uintb start = memrange.addr.getOffset();
        // cc:316: Address endaddr = memrange.addr + memrange.size —
        // Address::operator+ (address.hh:423) = wrapOffset(offset + size)
        // (space.hh:383), the int4->int8 sign-extending add taken modulo
        // the space size. Rugra spaces are 64-bit addressable (see
        // space_highest, heritage.hh:142 note), so wrapOffset is the
        // identity and the plain u64 wrapping add IS the oracle arithmetic
        // (`size as u64` sign-extends exactly like int4->int8).
        let start = addr.as_u64();
        let end_addr = start.wrapping_add(size as u64);
        // cc:317-320: Wraparound — the wrapped end offset fell below start
        // (the range crosses the top of the space). The oracle clamps
        // enditer to fd->endLoc(Address(space, space->getHighest())), which
        // (varnode.cc:1596-1602) is the lower bound at the NEXT space in
        // order: the window runs from start to the end of memrange's space.
        // Reachable only when a MemRange straddles the space top — a
        // varnode at offset == getHighest() with size > 1 entering the
        // disjoint cover at cc:2708-2710; for 8-byte spaces that means
        // offset 0xffffffffffffffff, which no real loader emits
        // (pre-existing divergence, not r2-introduced; single-point fixture
        // heritage_collect_wraparound_1204 pins the branch).
        let wrapped = end_addr < start;
        let mut maxsize: i32 = 0;
        // Ghidra cc:323-325: beginLoc(memrange.addr) .. endLoc(addr+size) —
        // LIVE ordered-window iteration over the bank's loc-set. Liveness is
        // load-bearing: refinement (refineRead/refineWrite/refineInput,
        // cc:1902-1906) creates piece varnodes earlier in this same
        // placeMultiequals walk, and the oracle's re-collect of the first
        // piece (cc:2615) plus every later piece's collect must see them —
        // an entry-frozen snapshot would hide the pieces for the whole pass
        // and, because the next pass classifies the range OLD
        // (addIndirects=false), the missed INDIRECTs would never be built
        // (review finding M1). Rugra's loc_tree is a
        // BTreeSet<VarnodeLocRef> whose Ord acquires varnode read locks
        // during comparison, so the RangeFrom bound is built from a
        // synthetic probe varnode: size 0 sorts before every same-offset
        // member, so `probe..` starts exactly at beginLoc(addr). The window
        // walk itself touches only window members (other spaces never
        // enter — space-major ordering mirrors VarnodeCompareLocDef), and
        // classification reads live flags, matching the oracle iterator.
        let probe = crate::varnode::VarnodeLocRef(std::sync::Arc::new(
            std::sync::RwLock::new(
            Varnode::new_with_space(
                0,
                memrange.space,
                addr.as_u64()),
        )));
        for entry in fd.vbank.loc_tree.range(probe..) {
            let vn_arc = entry.0.clone();
            let vn = vn_arc.read().unwrap();
            // cc:324: iterate beginLoc(memrange.addr) .. enditer. Both
            // enditer forms (beginLoc(endaddr), or the wraparound clamp at
            // the next space in order) live inside or at the far edge of
            // memrange's space, so the first foreign-space member ends the
            // monotone space-major walk.
            if vn.address_space != memrange.space {
                break;
            }
            // cc:321-322: non-wrapped window end is beginLoc(endaddr) —
            // the first varnode whose start offset >= endaddr. In the
            // wrapped case (cc:317-320) there is no offset bound: the
            // window extends to the end of the space.
            if !wrapped && vn.loc.as_u64() >= end_addr {
                break;
            }
            // cc:326: if (!vn->isWriteMask()) gates every classification
            if vn.is_write_mask() {
                continue;
            }
            if vn.is_written() {
                // cc:329: marker or return-form COPY = previous heritage
                let def_op = vn.def.as_ref().and_then(|w| w.upgrade());
                if let Some(def_op) = def_op {
                    let def_r = def_op.read().unwrap();
                    let prior_heritage = def_r.is_marker()
                        || (def_r.flags & crate::op::pcodeop_flags::RETURN_COPY) != 0;
                    if prior_heritage {
                        if vn.get_size() < size as usize {
                            remove.push(vn_arc.clone());
                            continue;
                        }
                        // cc:334: previous pass covered everything
                        memrange.clear_property(memrange_flags::NEW_ADDRESSES);
                    }
                }
                if vn.get_size() as i32 > maxsize {
                    maxsize = vn.get_size() as i32;
                }
                write.push(vn_arc.clone());
            } else if !vn.is_heritage_known() && !vn.has_no_descend() {
                read.push(vn_arc.clone());
            } else if vn.is_input() {
                input.push(vn_arc.clone());
            }
        }
        maxsize
    }

    // Ghidra: heritage.cc:1952 Heritage::guardInput
    /// Ensure input varnodes fill the entire range. Faithful to
    /// `guardInput` (heritage.cc:1952-2010): a single full-range input
    /// links in automatically (cc:1958); otherwise holes are filled with
    /// freshly promoted inputs (cc:1969-1992), every piece is
    /// write-masked (cc:1997-1998) and a final unified free Varnode of
    /// the whole range is built with concatPieces at the start block
    /// beginning and marked active heritage (cc:2008-2009).
    pub fn guard_input(
        &self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        input: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        if input.is_empty() { return; }
        // cc:1958: if single input fills everything, skip
        if input.len() == 1 && input[0].read().unwrap().get_size() == size as usize {
            return;
        }
        // cc:1962-1993: fill holes in the input range
        let mut i = 0;
        let mut cur = addr.as_u64();
        let end = addr.as_u64().wrapping_add(size as u64);
        let vn_space = input
            .first()
            .map(|v| v.read().unwrap().address_space)
            .unwrap_or(AddressSpace::Register);
        let mut newinput: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        while cur < end {
            if i < input.len() {
                let vn_off = input[i].read().unwrap().loc.as_u64();
                if vn_off > cur {
                    // cc:1973-1976: hole before this input — create the
                    // missing input piece.
                    let sz = (vn_off - cur) as usize;
                    let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                    // heritage.cc:1975 routes through Funcdata::newVarnode,
                    // whose symbol tail attaches the typelocked global's
                    // DWARF type (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                    fd.set_varnode_properties(&vn);
                    let promoted = fd.set_input_varnode(vn);
                    newinput.push(promoted);
                } else {
                    newinput.push(input[i].clone());
                    i += 1;
                }
            } else {
                // cc:1985-1988: tail hole after the last input.
                let sz = (end - cur) as usize;
                let vn = fd.vbank.create_with_space(sz, vn_space, cur);
                // heritage.cc:1986 routes through Funcdata::newVarnode,
                // whose symbol tail attaches the typelocked global's
                // DWARF type (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                fd.set_varnode_properties(&vn);
                let promoted = fd.set_input_varnode(vn);
                newinput.push(promoted);
            }
            cur = cur.wrapping_add(newinput.last().unwrap().read().unwrap().get_size() as u64);
        }
        // cc:1996: if only one piece, it links automatically
        if newinput.len() == 1 { return; }
        // cc:1997-1998: all pieces carry the write mask
        for vn in &newinput {
            vn.write().unwrap().set_write_mask();
        }
        // cc:2008-2009: newout = newVarnode(size, addr);
        // concatPieces(newinput, (PcodeOp *)0, newout)->setActiveHeritage()
        let space = newinput
            .first()
            .map(|v| v.read().unwrap().address_space)
            .unwrap_or(vn_space);
        let newout = fd
            .vbank
            .create_with_space(size as usize, space, addr.as_u64());
        // heritage.cc:2008 routes through Funcdata::newVarnode, whose symbol
        // tail attaches the typelocked global's DWARF type onto the unified
        // range read before concatPieces (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
        fd.set_varnode_properties(&newout);
        let unified = self.concat_pieces(fd, &newinput, None, &newout);
        unified.write().unwrap().set_active_heritage();
        // cc:1952-2010 never reassigns the caller's `input` vector; the
        // filled pieces live only in the local newinput consumed by the
        // concatenation above.
    }

    // Ghidra: heritage.cc:358 Heritage::callOpIndirectEffect
    /// Determine if the address range is affected by the given \e call p-code
    /// op. Faithful 1:1 port of `callOpIndirectEffect`
    /// (heritage.cc:358-370):
    ///   - CALL/CALLIND: look up the exact FuncCallSpecs owner of the op
    ///     (no spec -> assume indirect effect, cc:364) and return
    ///     `hasEffectTranslate(addr,size) != unaffected`;
    ///   - any other op reaching here (CALLOTHER/NEW, cc:367-369): assumed
    ///     to have no effect on -fd- variables except its own output, i.e.
    ///     \b false.
    /// The former version returned \b true for every branch (conservative
    /// pre-D0 stub); this port restores the oracle polarity so
    /// `normalizeWriteSize` picks INDIRECT creation vs SUBPIECE correctly.
    pub fn call_op_indirect_effect(
        &self,
        fd: &Funcdata,
        space: AddressSpace,
        addr: Address,
        size: i32,
        op: &Arc<RwLock<PcodeOp>>,
    ) -> bool {
        let opc = op.read().unwrap().opcode;
        if opc != OpCode::CPUI_CALL && opc != OpCode::CPUI_CALLIND {
            // cc:367-369: CALLOTHER/NEW — assume no effect except op->getOut().
            return false;
        }
        // cc:362-364: fc = fd->getCallSpecs(op); null -> assume indirect.
        match fd.get_call_specs_of_op(&PcodeOpRef(op.clone())) {
            None => true,
            // cc:365: return (fc->hasEffectTranslate(addr,size) != unaffected)
            Some(fc) => {
                fc.read()
                    .unwrap()
                    .has_effect_translate(space, addr.as_u64(), size)
                    != crate::fspec::EffectType::Unaffected
            }
        }
    }

    // Ghidra: heritage.cc:1704 Heritage::buildRefinement
    /// Build refinement array from varnode list. Faithful to
    /// `buildRefinement` (heritage.cc:1705-1715). Marks byte boundaries
    /// where varnodes start/end within the range [addr, addr+size).
    pub fn build_refinement(
        &self,
        refine: &mut [i32],
        addr: Address,
        vnlist: &[Arc<RwLock<Varnode>>],
    ) {
        for vn_arc in vnlist {
            let vn = vn_arc.read().unwrap();
            let diff = vn.loc.as_u64().saturating_sub(addr.as_u64()) as usize;
            let sz = vn.get_size();
            if diff < refine.len() {
                refine[diff] = 1;
            }
            if diff + sz < refine.len() {
                refine[diff + sz] = 1;
            }
        }
    }

    // Ghidra: heritage.cc:1733 Heritage::splitByRefinement
    /// Split a Varnode by the refinement array. Faithful to
    /// `splitByRefinement` (heritage.cc:1734-1754). Returns new
    /// Varnode pieces in `split` if the varnode crosses a refinement
    /// boundary; empty if already refined.
    pub fn split_by_refinement(
        &self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
        split: &mut Vec<Arc<RwLock<Varnode>>>,
    ) {
        let vn_r = vn.read().unwrap();
        let mut curaddr = vn_r.loc;
        let mut sz = vn_r.get_size() as i32;
        let vn_space = vn_r.address_space;
        drop(vn_r);
        let mut diff = curaddr.as_u64().saturating_sub(addr.as_u64()) as usize;
        if diff >= refine.len() { return; }
        let mut cutsz = refine[diff];
        if cutsz == 0 || sz <= cutsz { return; }
        loop {
            let piece = fd
                .vbank
                .create_with_space(cutsz as usize, vn_space, curaddr.as_u64());
            // heritage.cc:1742/1750 route through Funcdata::newVarnode, whose
            // symbol tail attaches a matching symbol entry on each refinement
            // piece (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
            fd.set_varnode_properties(&piece);
            split.push(piece);
            sz -= cutsz;
            if sz <= 0 { break; }
            curaddr = Address::new(curaddr.as_u64().wrapping_add(cutsz as u64));
            diff = curaddr.as_u64().saturating_sub(addr.as_u64()) as usize;
            if diff >= refine.len() { break; }
            cutsz = refine[diff];
            if cutsz > sz { cutsz = sz; }
        }
    }

    // Ghidra: heritage.cc:1772 Heritage::refineRead
    /// Split a free read Varnode based on the refinement, replacing it
    /// with a concatenation expression whose final output is a temporary
    /// unique. Faithful to `refineRead` (heritage.cc:1772-1787):
    /// splitByRefinement, newUnique(vn->getSize()), loneDescend slot,
    /// concatPieces(newvn, op, replacevn), opSetInput, and
    /// deleteVarnode when the consumed free has no remaining descendant
    /// (cc:1783-1786 throws "Refining non-free varnode" otherwise; Rust
    /// keeps the varnode and reports the violation on stderr).
    pub fn refine_read(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1778: replacevn = fd->newUnique(vn->getSize())
        let vn_size = vn.read().unwrap().get_size();
        let replacevn = fd.new_unique(vn_size);
        // cc:1779-1781: op = vn->loneDescend(); slot = op->getSlot(vn).
        // Bind the lone-descend result in its own statement: an `if let`
        // CONDITION temporary would hold vn's read guard for the whole
        // block, and op_set_input below re-locks the same Varnode for
        // write (opSetInput's eraseDescend path) — a same-thread
        // RwLock deadlock.
        let lone_desc = vn.read().unwrap().lone_descend();
        if let Some(read_op) = lone_desc {
            let read_ref = PcodeOpRef(read_op.clone());
            let num_input = read_op.read().unwrap().num_input();
            let slot = read_op
                .read()
                .unwrap()
                .inrefs
                .iter()
                .position(|v| Arc::ptr_eq(v, vn))
                .unwrap_or(num_input);
            // cc:1782: concatPieces(newvn, op, replacevn)
            self.concat_pieces(fd, &newvn, Some(&read_ref), &replacevn);
            // cc:1783: fd->opSetInput(op, replacevn, slot)
            if slot < num_input {
                fd.op_set_input(&read_ref, replacevn.clone(), slot);
            }
        }
        // cc:1784-1786: if (vn->hasNoDescend()) fd->deleteVarnode(vn);
        // else throw LowlevelError("Refining non-free varnode")
        if vn.read().unwrap().has_no_descend() {
            let _ = fd.delete_varnode(vn);
        } else {
            // Ghidra aborts the pass here; mirror the throw with the
            // oracle's exact text (mechanism-C M4 alignment).
            panic!("Refining non-free varnode");
        }
    }

    // Ghidra: heritage.cc:1806 Heritage::refineWrite
    /// Split a written Varnode based on the refinement: the write is
    /// redirected to a fresh temporary, SUBPIECE ops define each piece
    /// from that temporary, the original Varnode is total-replaced by
    /// the temporary and destroyed. Faithful to `refineWrite`
    /// (heritage.cc:1806-1818).
    pub fn refine_write(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1812: replacevn = fd->newUnique(vn->getSize())
        let vn_size = vn.read().unwrap().get_size();
        let (vn_loc, def_op) = {
            let r = vn.read().unwrap();
            (r.loc, r.def.as_ref().and_then(|w| w.upgrade()))
        };
        let Some(def_op) = def_op else { return };
        let def_ref = PcodeOpRef(def_op);
        let replacevn = fd.new_unique(vn_size);
        // cc:1814: fd->opSetOutput(def, replacevn)
        fd.op_set_output(&def_ref, replacevn.clone());
        // cc:1815: splitPieces(newvn, def, vn->getAddr(), vn->getSize(), replacevn)
        self.split_pieces(
            fd,
            &newvn,
            Some(&def_ref),
            vn_loc,
            vn_size as i32,
            &replacevn,
        );
        // cc:1816-1817: totalReplace + deleteVarnode
        fd.total_replace(vn, replacevn.clone());
        let _ = fd.delete_varnode(vn);
    }

    // Ghidra: heritage.cc:1836 Heritage::refineInput
    /// Split a known input Varnode based on the refinement. Faithful to
    /// `refineInput` (heritage.cc:1836-1844): the pieces are defined by
    /// SUBPIECE ops reading the original input (inserted at the start
    /// block beginning because insertop is null, cc:578-581) and the
    /// original input is write-masked (cc:1843). No new inputs are
    /// created and no input flags are mutated here.
    pub fn refine_input(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        addr: Address,
        refine: &[i32],
    ) {
        let mut newvn: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        self.split_by_refinement(&mut *fd, vn, addr, refine, &mut newvn);
        if newvn.is_empty() {
            return;
        }
        // cc:1842: splitPieces(newvn, (PcodeOp *)0, vn->getAddr(), vn->getSize(), vn)
        let (vn_loc, vn_size) = {
            let r = vn.read().unwrap();
            (r.loc, r.get_size() as i32)
        };
        self.split_pieces(fd, &newvn, None, vn_loc, vn_size, vn);
        // cc:1843: vn->setWriteMask()
        vn.write().unwrap().set_write_mask();
    }

    // Ghidra: heritage.cc:1857 Heritage::remove13Refinement
    /// Remove 1-byte/3-byte refinement patterns. Faithful to
    /// `remove13Refinement` (heritage.cc:1857-1880): walk the partition
    /// sizes left to right; a 1-3 or 3-1 adjacency is replaced by a
    /// single 4 at the position of the first element (the second
    /// element's start slot), and the walk continues from the end of the
    /// second element.
    pub fn remove13_refinement(&self, refine: &mut [i32]) {
        if refine.is_empty() {
            return;
        }
        let mut pos: usize = 0;
        let mut lastsize = refine[pos];
        pos = pos.saturating_add(lastsize.max(0) as usize);
        while pos < refine.len() {
            let cursize = refine[pos];
            if cursize == 0 {
                break;
            }
            if (lastsize == 1 && cursize == 3) || (lastsize == 3 && cursize == 1) {
                refine[pos - lastsize as usize] = 4;
                lastsize = 4;
                pos += cursize as usize;
            } else {
                lastsize = cursize;
                pos += lastsize as usize;
            }
        }
    }

    // Ghidra: heritage.cc:1890 Heritage::refinement
    /// Find the common refinement of all reads and writes in the address
    /// range, split them to match, and rewrite both the current-pass
    /// `disjoint` cover and the persistent `globaldisjoint` map.
    /// Faithful to `refinement` (heritage.cc:1890-1940):
    ///   - the refinement array carries the cc:1896 `size+1` fencepost,
    ///     which buildRefinement may mark at the range end and which is
    ///     popped (cc:1900) before the boundary-to-partition-size
    ///     conversion loop (cc:1901-1908);
    ///   - no non-trivial refinement (`lastpos == 0`, cc:1908) returns
    ///     `None` (Ghidra returns `disjoint.end()`);
    ///   - the original MemRange is erased and the pieces are spliced in
    ///     at the same position so the caller's index walk visits each
    ///     piece (cc:1921-1938); each piece is re-added to
    ///     `globaldisjoint` under the original entry's pass number
    ///     (cc:1922-1924);
    ///   - returns the index of the first inserted piece.
    pub fn refinement(
        &mut self,
        fd: &mut Funcdata,
        memidx: usize,
        readvars: &[Arc<RwLock<Varnode>>],
        writevars: &[Arc<RwLock<Varnode>>],
        inputvars: &[Arc<RwLock<Varnode>>],
    ) -> Option<usize> {
        let size = self.disjoint.tasklist[memidx].size;
        // cc:1894: if (size > 1024) return disjoint.end();
        if size > 1024 {
            return None;
        }
        let addr = self.disjoint.tasklist[memidx].addr;
        let space = self.disjoint.tasklist[memidx].space;
        // cc:1896: vector<int4> refine(size+1, 0) — with fencepost.
        let mut refine = vec![0i32; size as usize + 1];
        self.build_refinement(&mut refine, addr, readvars);
        self.build_refinement(&mut refine, addr, writevars);
        self.build_refinement(&mut refine, addr, inputvars);
        // cc:1900: refine.pop_back() — remove the fencepost.
        refine.pop();
        // cc:1901-1908: convert boundary points to partition sizes.
        let mut lastpos = 0usize;
        for curpos in 1..size as usize {
            if refine[curpos] != 0 {
                refine[lastpos] = (curpos - lastpos) as i32;
                lastpos = curpos;
            }
        }
        if lastpos == 0 {
            return None; // No non-trivial refinements
        }
        refine[lastpos] = size - lastpos as i32;
        // cc:1910: remove13Refinement(refine)
        self.remove13_refinement(&mut refine);
        // cc:1912-1917: split reads, writes, inputs along the refinement.
        for vn in readvars {
            self.refine_read(fd, vn, addr, &refine);
        }
        for vn in writevars {
            self.refine_write(fd, vn, addr, &refine);
        }
        for vn in inputvars {
            self.refine_input(fd, vn, addr, &refine);
        }
        // cc:1919-1938: alter the disjoint cover (locally and globally) to
        // reflect the refinement. The original entry is erased, the pieces
        // are inserted in its place, and each piece is re-added to
        // globaldisjoint under the erased entry's pass number.
        let flags = self.disjoint.tasklist[memidx].flags;
        let cur_pass = match self.globaldisjoint.themap.remove(&(space, addr)) {
            Some(sp) => sp.pass,
            // cc:1922-1923 dereferences globaldisjoint.find(addr); an
            // exact-key miss is unreachable for driver-fed ranges (the
            // driver adds the same (addr,size) to both structures before
            // placeMultiequals runs). Fall back to the current pass so a
            // drifted key cannot fabricate a wrong NEW classification.
            None => self.pass,
        };
        self.disjoint.tasklist.remove(memidx);
        let mut pieces: Vec<MemRange> = Vec::new();
        let mut cut = 0i32;
        let mut piece_addr = addr;
        while cut < size {
            let sz = refine[cut as usize];
            if sz <= 0 {
                // Partition walks always land on a partition start, where
                // the converted array holds a positive size; a zero here
                // means a corrupted refinement array, which the locked
                // oracle cannot produce (its cc:1926-1938 walk would
                // never terminate either). Terminate rather than spin.
                break;
            }
            pieces.push(MemRange {
                addr: piece_addr,
                size: sz,
                flags,
                space,
            });
            cut += sz;
            piece_addr = Address::new(piece_addr.as_u64().wrapping_add(sz as u64));
        }
        self.disjoint
            .tasklist
            .splice(memidx..memidx, pieces.into_iter());
        // cc:1929-1937: globaldisjoint.add per piece (same order). The
        // add() intersect code is discarded exactly as cc:1929-1935 does.
        cut = 0;
        piece_addr = addr;
        while cut < size {
            let sz = refine[cut as usize];
            if sz <= 0 {
                break;
            }
            let _ = self.globaldisjoint.add(space, piece_addr, sz, cur_pass);
            cut += sz;
            piece_addr = Address::new(piece_addr.as_u64().wrapping_add(sz as u64));
        }
        Some(memidx)
    }

    // Ghidra: heritage.cc:1890 Heritage::refinement
    /// Run refinement on the given range. Faithful to `refinement`
    /// (heritage.cc:1891-1951). Builds refinement from collected
    /// varnodes, removes 1/3 patterns, and applies to read/write/input.
    /// Returns Some(refined_iter) if refinement changed the range,
    /// None otherwise.
    pub fn run_refinement(
        &mut self,
        fd: &mut Funcdata,
        addr: Address,
        size: i32,
        readvars: &[Arc<RwLock<Varnode>>],
        writevars: &[Arc<RwLock<Varnode>>],
        inputvars: &[Arc<RwLock<Varnode>>],
    ) -> bool {
        let sz = size as usize;
        let mut refine = vec![0i32; sz];
        self.build_refinement(&mut refine, addr, readvars);
        self.build_refinement(&mut refine, addr, writevars);
        self.build_refinement(&mut refine, addr, inputvars);
        // cc:1898: remove13Refinement
        self.remove13_refinement(&mut refine);
        // Check if any refinement boundaries exist.
        let has_refine = refine.iter().any(|&v| v != 0);
        if !has_refine { return false; }
        // cc:1910-1950: apply refinement to read/write/input
        for vn in readvars {
            self.refine_read(fd, vn, addr, &refine);
        }
        for vn in writevars {
            self.refine_write(fd, vn, addr, &refine);
        }
        for vn in inputvars {
            self.refine_input(fd, vn, addr, &refine);
        }
        true
    }

    // Ghidra: heritage.cc:2281 Heritage::processJoins
    /// Split \e join-space Varnodes up into their real components.
    /// Faithful to `processJoins` (heritage.cc:2281-2313): for every
    /// Varnode in the join space, look up its JoinRecord and split it
    /// into the specified real components (PIECE chains for free reads,
    /// SUBPIECE pairs for writes at the piece space's heritage delay) so
    /// join-space addresses play no role in heritage.
    ///
    /// Iteration semantics: the oracle walks `beginLoc(joinspace)` to
    /// `endLoc(joinspace)` and breaks when a varnode outside the join
    /// space appears (mid-iteration insertions can land before enditer).
    /// None of the splits insert join-space varnodes (pieces live in
    /// their real spaces, constants in the const space), so the join
    /// subrange never grows — a loc-order snapshot of the join-space
    /// varnodes is observably equivalent to the oracle's guarded walk.
    ///
    /// Unlinked-join degradation (documented deviation, see
    /// HERITAGE-PJOINS-UNLINKED-0001): the oracle's findJoin
    /// (translate.cc:746-762) throws LowlevelError("Unlinked join
    /// address") when no JoinRecord covers the offset. Rugra's producer
    /// (coreaction.rs `return_join_address`, SPACEFIX lane) mints
    /// join-space offsets from a stateless hash with no findAddJoin
    /// registration, so a faithful throw would abort every function
    /// carrying those varnodes (httpd ap_init_vhost_config). Until the
    /// producer registers records (or stops minting unlinked joins —
    /// probe evidence shows the oracle creates no joins at all on this
    /// corpus), the miss is logged loudly and the varnode skipped.
    pub fn process_joins(&mut self, fd: &mut Funcdata) {
        // cc:2284-2288: iter = beginLoc(joinspace), enditer = endLoc.
        let join_vns: Vec<_> = fd
            .vbank
            .loc_tree
            .iter()
            .filter(|v| v.0.read().unwrap().address_space == AddressSpace::Join)
            .map(|v| v.0.clone())
            .collect();
        if join_vns.is_empty() {
            return;
        }
        for vn in join_vns {
            let vn_offset = vn.read().unwrap().loc.as_u64();
            let vn_size = vn.read().unwrap().get_size();
            // cc:2293: JoinRecord *joinrec = fd->getArch()->findJoin(...)
            // (throws "Unlinked join address" on a miss — degraded here,
            // see the function-level note above).
            let join_rec = match fd.get_arch() {
                Some(a) => a
                    .join_db
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .find_join(vn_offset)
                    .cloned(),
                None => None,
            };
            let join_rec = match join_rec {
                Some(r) => r,
                None => {
                    eprintln!(
                        "[HERITAGE] process_joins: unlinked join address join:0x{:x} \
                         (translate.cc:761 LowlevelError arm degraded; \
                         HERITAGE-PJOINS-UNLINKED-0001)",
                        vn_offset
                    );
                    continue;
                }
            };
            // cc:2294: piecespace = joinrec->getPiece(0).space
            let piecespace = join_rec.get_piece(0).space;
            // cc:2296-2297: unified size must match (oracle throws
            // "Joined varnode does not match size of record").
            if join_rec.get_unified().size != vn_size {
                eprintln!(
                    "[HERITAGE] process_joins: joined varnode does not match size \
                     of record join:0x{:x} vn_sz={} record_sz={} \
                     (heritage.cc:2297 LowlevelError arm degraded)",
                    vn_offset,
                    vn_size,
                    join_rec.get_unified().size
                );
                continue;
            }
            // cc:2298-2303: free varnodes split into PIECE reads now.
            if vn.read().unwrap().is_free() {
                if join_rec.is_float_extension() {
                    self.float_extension_read(fd, &vn, &join_rec);
                } else {
                    self.split_join_read(fd, &vn, &join_rec);
                }
            }

            // cc:2305-2306: HeritageInfo *info = getInfo(piecespace);
            // if (pass != info->delay) continue — the write split happens
            // exactly once, on the pass equal to the piece space's delay.
            let delay = self.get_info(piecespace).delay;
            if self.pass != delay {
                continue;
            }

            // cc:2308-2311: float extension or write split.
            if join_rec.is_float_extension() {
                self.float_extension_write(fd, &vn, &join_rec);
            } else {
                self.split_join_write(fd, &vn, &join_rec);
            }
        }
    }

    // Ghidra: heritage.cc:2663 Heritage::heritage
    /// One canonical Heritage pass, faithful to `Heritage::heritage`
    /// (heritage.cc:2663-2758), driven through an exclusive `&mut Funcdata`:
    ///   1. cc:2676-2677 if maxdepth == -1 (restructure forced) buildADT()
    ///   2. cc:2679 processJoins()
    ///   3. cc:2680-2683 pass 0: one local PreferSplitManager init+split
    ///   4. cc:2684-2748 per-space loop (ascending infolist order):
    ///      placeholders, one-time discovery, ordered Varnode scan feeding
    ///      persistent globaldisjoint + current-pass disjoint, warnings
    ///   5. cc:2749 placeMultiequals()
    ///   6. cc:2750 rename()
    ///   7. cc:2751-2752 reprocessFreeStores when discovery requested it
    ///   8. cc:2753-2754 analyzeNewLoadGuards + handleNewLoadCopies
    ///   9. cc:2755-2756 pass 0: splitAdditional on the SAME manager
    ///   10. cc:2757 pass += 1 exactly once
    ///
    /// Ownership boundary (HERITAGE-OWNERSHIP-0001): the persistent Heritage
    /// object no longer stores a `Weak<RwLock<Funcdata>>`; the caller
    /// (`Funcdata::op_heritage`) temporarily moves `self.heritage` out via
    /// `mem::take`, invokes this pass against the same `&mut Funcdata`, and
    /// restores it, so no nested lock acquisition can occur.
    pub fn heritage(&mut self, fd: &mut Funcdata) {
        // Ghidra cc:2676-2677: if (maxdepth == -1) buildADT();
        // maxdepth == -1 is the ctor/clear sentinel meaning "restructure
        // forced" — exactly one rebuild on the first pass after (re)reset.
        // Ghidra's buildADT consumes the dominator state produced upstream by
        // Funcdata::structureReset (calcForwardDominator); Rugra's equivalent
        // producer is BlockGraph::build_dom_tree.
        if self.maxdepth == -1 {
            fd.bblocks.build_dom_tree();
            self.build_adt(fd);
        }

        // Ghidra cc:2679: processJoins();
        self.process_joins(fd);

        // Ghidra cc:2674-2683: one local PreferSplitManager shared by
        // split (pass 0) and splitAdditional (end of pass 0). Rugra has no
        // architecture split records on x86-64 (empty vec mirrors the locked
        // fixture architecture and the x86:LE:64:default oracle), but the
        // single-instance lifetime is preserved.
        let mut splitmanage = crate::prefersplit::PreferSplitManager::new();
        if self.pass == 0 {
            splitmanage.init(fd, Vec::new());
            splitmanage.split(fd);
        }

        // Ghidra cc:2671-2673: pass-local freeStores vector shared by
        // discovery and reprocessFreeStores.
        let mut free_stores: Vec<Arc<RwLock<PcodeOp>>> = Vec::new();
        let mut reprocess_stack_count = 0;
        let mut stack_space = AddressSpace::Stack;

        // Ghidra cc:2684: for(int4 i=0;i<infolist.size();++i)
        // NOTE (1:1 with the oracle): `Heritage::heritage` does NOT build
        // the info list. It is built exactly once by
        // `Funcdata::startProcessing` (funcdata.cc:166 -> buildInfoList)
        // before the first ActionHeritage pass; iterating an empty
        // infolist therefore performs zero per-space stages, on both sides.
        for i in 0..self.infolist.len() {
            // cc:2686: if (!info->isHeritaged()) continue;
            if !self.infolist[i].space.is_heritaged() {
                continue;
            }
            // cc:2687: if (pass < info->delay) continue;
            if self.pass < self.infolist[i].delay {
                continue;
            }
            let space = self.infolist[i].space;
            // cc:2688-2689: if (info->hasCallPlaceholders)
            //   clearStackPlaceholders(info);
            if self.infolist[i].has_call_placeholders {
                self.clear_stack_placeholders(fd, space);
            }

            // cc:2691-2697: if (!info->loadGuardSearch) {
            //   info->loadGuardSearch = true;
            //   if (discoverIndexedStackPointers(info->space,freeStores,true))
            //     { reprocessStackCount += 1; stackSpace = info->space; } }
            if !self.infolist[i].load_guard_search {
                self.infolist[i].load_guard_search = true;
                if self.discover_indexed_stack_pointers(fd, space, &mut free_stores, true) {
                    reprocess_stack_count += 1;
                    stack_space = space;
                }
            }

            // cc:2698-2732: build disjoint ranges from this space's
            // Varnodes in VarnodeLocSet location order.
            let pass = self.pass;
            let deadremoved = self.infolist[i].deadremoved;
            let mut needwarning = false;
            let mut warnvn: Option<Arc<RwLock<Varnode>>> = None;
            let vns_in_space: Vec<(Arc<RwLock<Varnode>>, Address, i32)> = {
                let mut result = Vec::new();
                // cc:2699-2700: iter = fd->beginLoc(info->space);
                // enditer = fd->endLoc(info->space). The oracle's window is
                // a tree RANGE over the loc-set's space-major ordering — it
                // never touches other spaces' Varnodes. The equivalent
                // window here starts at a size-0 probe at the space's
                // offset floor (which sorts before every same-offset
                // member, the same beginLoc probe contract collect()
                // relies on) and ends at the first foreign-space member
                // (space-major walk). Scanning the whole tree per space —
                // re-reading every foreign varnode under its lock — is a
                // pure read-pattern divergence, not a different algorithm.
                let probe = crate::varnode::VarnodeLocRef(Arc::new(RwLock::new(
                    Varnode::new_with_space(0, space, 0),
                )));
                for entry in fd.vbank.loc_tree.range(probe..) {
                    let vn_arc = entry.0.clone();
                    let (in_space, skip, loc, size) = {
                        let vn = vn_arc.read().unwrap();
                        let skip = (!vn.is_written()
                            && vn.has_no_descend()
                            && !vn.is_unaffected()
                            && !vn.is_input())
                            || vn.is_write_mask();
                        (vn.address_space == space, skip, vn.loc, vn.get_size() as i32)
                    };
                    // Space-major walk: the first foreign-space member is
                    // the window's end (cc:2700 endLoc).
                    if !in_space {
                        break;
                    }
                    // cc:2704/2706: skip dead unused frees and write masks.
                    if skip {
                        continue;
                    }
                    result.push((vn_arc, loc, size));
                }
                result
            };
            for (vn_arc, vn_addr, vn_size) in vns_in_space {
                // cc:2708: LocationMap::iterator liter =
                //   globaldisjoint.add(vn->getAddr(),vn->getSize(),pass,prev);
                // (*liter).first / (*liter).second.size: the merged map
                // entry covering vn_addr — `add` returns the same iterator
                // position the oracle's map does, so the driver reads the
                // entry bounds straight from the return value (the former
                // `entry_containing` re-lookup was a pure redundancy).
                let (prev, m_addr, m_size) =
                    self.globaldisjoint.add(space, vn_addr, vn_size, pass);
                if prev == 0 {
                    // cc:2709-2710: all-new location (or intersecting with
                    // something new)
                    self.disjoint
                        .add(space, m_addr, m_size, memrange_flags::NEW_ADDRESSES);
                } else if prev == 2 {
                    // cc:2711: completely contained in range from previous pass
                    // cc:2712: if (vn->isHeritageKnown()) continue;
                    if vn_arc.read().unwrap().is_heritage_known() {
                        continue;
                    }
                    // cc:2713: if (vn->hasNoDescend()) continue;
                    if vn_arc.read().unwrap().has_no_descend() {
                        continue;
                    }
                    // cc:2714-2718: first deadremoval warning
                    if !needwarning
                        && deadremoved > 0
                        && !fd.is_jumptable_recovery_on()
                    {
                        needwarning = true;
                        self.bump_deadcode_delay(fd, vn_arc.read().unwrap().get_space());
                        warnvn = Some(vn_arc.clone());
                    }
                    // cc:2719
                    self.disjoint
                        .add(space, m_addr, m_size, memrange_flags::OLD_ADDRESSES);
                } else {
                    // cc:2721-2722: partially contained in old range, but
                    // may contain new stuff
                    self.disjoint.add(
                        space,
                        m_addr,
                        m_size,
                        memrange_flags::OLD_ADDRESSES | memrange_flags::NEW_ADDRESSES,
                    );
                    // cc:2723-2730
                    if !needwarning
                        && deadremoved > 0
                        && !fd.is_jumptable_recovery_on()
                    {
                        if vn_arc.read().unwrap().is_heritage_known() {
                            continue;
                        }
                        needwarning = true;
                        self.bump_deadcode_delay(fd, vn_arc.read().unwrap().get_space());
                        warnvn = Some(vn_arc.clone());
                    }
                }
            }

            // cc:2734-2747: warning header (issued once per space).
            if needwarning {
                if !self.infolist[i].warning_issued {
                    self.infolist[i].warning_issued = true;
                    let mut errmsg = String::from("Heritage AFTER dead removal. Example location: ");
                    let warn_ref = warnvn.expect("needwarning implies warnvn");
                    errmsg.push_str(&warn_ref.read().unwrap().print_raw());
                    if !warn_ref.read().unwrap().has_no_descend() {
                        let warnop = warn_ref
                            .read()
                            .unwrap()
                            .descend_iter()
                            .next()
                            .map(|op| op.read().unwrap().get_addr().as_u64());
                        if let Some(addr) = warnop {
                            errmsg.push_str(&format!(" : {addr:#x}"));
                        }
                    }
                    fd.warning_header(&errmsg);
                }
            }
        }

        // Ghidra cc:2749: placeMultiequals();
        self.place_multiequals(fd);

        // Ghidra cc:2750: rename();
        self.rename(fd);

        // Ghidra cc:2751-2752: if (reprocessStackCount > 0)
        //   reprocessFreeStores(stackSpace, freeStores);
        if reprocess_stack_count > 0 {
            self.reprocess_free_stores(fd, stack_space, &mut free_stores);
        }

        // Ghidra cc:2753: analyzeNewLoadGuards();
        self.analyze_new_load_guards(fd);

        // Ghidra cc:2754: handleNewLoadCopies();
        self.handle_new_load_copies(fd);

        // Ghidra cc:2755-2756: if (pass == 0) splitmanage.splitAdditional();
        if self.pass == 0 {
            splitmanage.split_additional(fd);
        }

        // Ghidra cc:2757: pass += 1;
        self.pass += 1;
    }

    // Ghidra: heritage.cc:2599 Heritage::placeMultiequals
    /// Place phi nodes using the ADT algorithm, faithful to
    /// `placeMultiequals` (heritage.cc:2599-2645): it walks the current
    /// `disjoint` cover in order, consumes `collect` per range
    /// (cc:2609), optionally refines a range larger than four bytes when
    /// no write spans it (cc:2610-2616), removes revisited markers
    /// (cc:2626-2627), fills input holes (cc:2628), guards the range
    /// (cc:2629), calculates the merge blocks (cc:2630) and inserts each
    /// MULTIEQUAL at the beginning of its merge block via opInsertBegin
    /// (cc:2631-2642). The ADT itself is built by the driver
    /// (`heritage`, cc:2676-2677), never here.
    ///
    /// The four output vectors are declared once outside the loop and
    /// cleared/reused by every `collect` call, exactly as cc:2603-2609.
    /// After a refinement, Ghidra reassigns the iterator to the first
    /// refined piece (`iter = refiter`, cc:2613), re-collects it
    /// (cc:2614), and the loop's `++iter` then visits the remaining
    /// pieces; the index-based Rust loop reproduces this by replacing
    /// the tasklist entry with its pieces and continuing at the first
    /// piece index.
    pub fn place_multiequals(&mut self, fd: &mut Funcdata) {
        let mut readvars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut writevars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut inputvars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let mut removevars: Vec<Arc<RwLock<Varnode>>> = Vec::new();

        let mut idx = 0usize;
        while idx < self.disjoint.tasklist.len() {
            // Ghidra cc:2609: max = collect(*iter, read, write, input, remove).
            // collect() takes the MemRange by reference and may clear its
            // new_addresses property (cc:334); mirror that in-place list
            // mutation by cloning, collecting, and writing the entry back.
            let mut memrange = self.disjoint.tasklist[idx].clone();
            let mut max = self.collect(
                fd,
                &mut memrange,
                &mut readvars,
                &mut writevars,
                &mut inputvars,
                &mut removevars,
            );
            self.disjoint.tasklist[idx] = memrange.clone();
            // Ghidra cc:2610-2616: refine ranges bigger than 4 bytes that
            // no single write fully spans, then re-collect the first piece.
            // collect's loc_tree window is LIVE (probe-based beginLoc), so
            // the pieces refinement just created are visible here and to
            // every later piece — matching the oracle's iterators
            // (review finding M1: an entry-frozen snapshot hid them).
            if memrange.size > 4 && max < memrange.size {
                if let Some(first_piece) =
                    self.refinement(fd, idx, &readvars, &writevars, &inputvars)
                {
                    idx = first_piece;
                    memrange = self.disjoint.tasklist[idx].clone();
                    max = self.collect(
                        fd,
                        &mut memrange,
                        &mut readvars,
                        &mut writevars,
                        &mut inputvars,
                        &mut removevars,
                    );
                    self.disjoint.tasklist[idx] = memrange.clone();
                }
            }
            // Ghidra cc:2617: const MemRange &memrange(*iter);
            let size = memrange.size;
            // Ghidra cc:2619-2625: skip ranges with no reads when there is
            // nothing to merge, or when the space is internal (unique) or
            // the range was already covered by a previous pass.
            if readvars.is_empty() {
                if writevars.is_empty() && inputvars.is_empty() {
                    idx += 1;
                    continue;
                }
                if memrange.space == AddressSpace::Unique || memrange.old_addresses() {
                    idx += 1;
                    continue;
                }
            }
            // Ghidra cc:2626-2627: removeRevisitedMarkers(remove, addr, size)
            // — the range's space (memrange.space) mirrors addr.getSpace().
            if !removevars.is_empty() {
                self.remove_revisited_markers(fd, &removevars, memrange.space, memrange.addr, size);
            }
            // Ghidra cc:2628: guardInput(addr, size, inputvars)
            self.guard_input(fd, memrange.addr, size, &mut inputvars);
            // Ghidra cc:2629: guard(addr, size, newAddresses(), read, write, input)
            self.guard_range(
                fd,
                memrange.space,
                memrange.addr,
                size,
                memrange.new_addresses(),
                &mut readvars,
                &mut writevars,
                &mut inputvars,
            );
            // Ghidra cc:2630: calcMultiequals(writevars)
            self.calc_multiequals(fd, &writevars);
            // Ghidra cc:2631-2642: create each MULTIEQUAL at the beginning
            // of its merge block. The op is allocated with sizeIn() inputs
            // at the block's start address, the output is a fresh
            // active-heritage write of the whole range, each input is a
            // fresh free Varnode of the range storage, and the op is
            // inserted at the block beginning (before any existing
            // leading MULTIEQUAL group only for non-MULTIEQUAL inserts —
            // funcdata_op.cc:413-421).
            for &blk_idx in self.merge.clone().iter() {
                let bl = match fd.bblocks.get_block(blk_idx as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let (blk_size_in, start_addr) = {
                    let b = bl.read().unwrap();
                    (b.size_in(), b.get_start_addr())
                };
                let multiop = fd.new_op(blk_size_in, start_addr);
                // cc:2634-2635: vnout = fd->newVarnodeOut(size, memrange.addr,
                // multiop); vnout->setActiveHeritage(). The oracle call runs
                // the full newVarnodeOut sequence — assignHigh + laned check
                // + localmap queryProperties tail (funcdata_varnode.cc:104-122)
                // — whose local leg folds mapped|addrtied for in-scope stack
                // storage. Rugra previously used the raw vbank constructor +
                // set_varnode_properties, which lacks the local-scope leg, so
                // heritage MULTIEQUAL outputs never became addr-tied and
                // RuleSubRight's overlap guard (ruleaction.cc:7265-7268)
                // missed SUBPIECE(ME,off) pairs
                // (SUBRIGHT-ADDRTIE-0001, VARGROUP-ABSORB-0001).
                let vnout = fd.new_varnode_out_full(
                    size as usize,
                    memrange.space,
                    crate::address::Address::new(memrange.addr.as_u64()),
                    &multiop,
                );
                vnout.write().unwrap().set_active_heritage();
                // cc:2636: opSetOpcode(multiop, CPUI_MULTIEQUAL)
                fd.op_set_opcode(&multiop, OpCode::CPUI_MULTIEQUAL);
                for j in 0..blk_size_in {
                    // cc:2638-2639: newVarnode(size, addr) + opSetInput
                    let vnin = fd
                        .vbank
                        .create_with_space(
                        size as usize, memrange.space, memrange.addr.as_u64(),
                    );
                    // heritage.cc:2638 routes through Funcdata::newVarnode,
                    // whose symbol tail (queryProperties -> setSymbolProperties,
                    // funcdata_varnode.cc:148-172) attaches the typelocked
                    // global type; the bare bank create left surviving phi
                    // inputs without a mapentry and broke read-only global
                    // typeflow (w-typeflow verified patch;
                    // HERITAGE-MULTIEQ-VNIN-SYMBOLTAIL-0001).
                    fd.set_varnode_properties(&vnin);
                    fd.op_set_input(&multiop, vnin, j);
                }
                // cc:2641: opInsertBegin(multiop, bl)
                fd.op_insert_begin(&multiop, &bl);
            }
            idx += 1;
        }
        // Ghidra cc:2644: merge.clear()
        self.merge.clear();
    }

    // RUDRA-GLUE: Rugra-specific dominance-frontier phi placement; Ghidra has no `placeMultiequalsDirect`.
    /// Insert Phi nodes directly using bank references. NOT the canonical
    /// algorithm: Ghidra's `placeMultiequals` (heritage.cc:2599-2645) derives
    /// merge blocks from the augmented dominator tree, not a dominance
    /// frontier. Since HERITAGE-DRIVER-SWITCH-0001 this is off the
    /// production path (ActionHeritage drives the canonical
    /// `Heritage::heritage`); it survives only for the legacy
    /// `Funcdata::run_heritage_direct` entry (example-side prototype
    /// estimation on throwaway Funcdata) and in-crate tests.
    pub fn place_multiequals_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        obank: &mut PcodeOpBank,
        bblocks: &crate::block::BlockGraph,
        _sblocks: &crate::block::BlockGraph,
    ) {

        // Standard SSA Phi node placement algorithm
        let mut worklist = VecDeque::new();
        let mut ever_on_worklist = std::collections::HashSet::new();
        let mut has_phi_node = std::collections::HashSet::new();

        let mut defs_by_loc: BTreeMap<(AddressSpace, Address), Vec<i32>> = BTreeMap::new();
        for vn_ref in &vbank.loc_tree {
            let vn = vn_ref.0.read().unwrap();
            let space = vn.get_space();
            let delay = self
                .infolist
                .iter()
                .find(|info| info.space == space)
                .map(|info| info.delay)
                .unwrap_or(0);

            if self.pass < delay {
                continue;
            }

            if vn.is_written() {
                if let Some(op_arc) = vn.def.as_ref().and_then(|w| w.upgrade()) {
                    let op = op_arc.read().unwrap();
                    // Skip if already a MULTIEQUAL (avoid redundant Phis in future passes)
                    if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                        continue;
                    }
                    if let Some(parent_arc) = op.parent.as_ref().and_then(|w| w.upgrade()) {
                        let block = parent_arc.read().unwrap();
                        if (block.get_flags() & crate::block::block_flags::DEAD) == 0 {
                            defs_by_loc
                                .entry((space, vn.loc))
                                .or_default()
                                .push(block.get_index());
                        }
                    }
                }
            } else if vn.is_input() {
                // Inputs act as definitions at the entry block
                let entry_block_idx = bblocks
                    .blocks
                    .iter()
                    .filter(|b| {
                        let block = b.read().unwrap();
                        block.size_in() == 0 && (block.get_flags() & crate::block::block_flags::DEAD) == 0
                    })
                    .map(|b| b.read().unwrap().get_index())
                    .next()
                    .unwrap_or(-1);
                if entry_block_idx != -1 {
                    defs_by_loc
                        .entry((space, vn.loc))
                        .or_default()
                        .push(entry_block_idx);
                }
            }
        }

        for ((space, addr), blocks) in defs_by_loc {
            worklist.clear();
            ever_on_worklist.clear();
            has_phi_node.clear();

            for &b_idx in &blocks {
                worklist.push_back(b_idx);
                ever_on_worklist.insert(b_idx);
            }

            while let Some(x_idx) = worklist.pop_front() {
                let df = bblocks
                    .blocks
                    .iter()
                    .find(|b| b.read().unwrap().get_index() == x_idx)
                    .map(|b| b.read().unwrap().get_dom_frontier())
                    .unwrap_or_default();

                // RUN-NONDETERM root cause: iterating the HashSet
                // directly makes the MULTIEQUAL creation order random per
                // process (std SipHash seeds). The canonical
                // Heritage::placeMultiequals does not use a dominance
                // frontier at all — it derives merge blocks through the
                // depth-ordered PriorityQueue/augment walk
                // (calcMultiequals cc:2439-2466 + visitIncr cc:2394-2428,
                // mirrored in calc_multiequals). Until the production
                // switch (HERITAGE-DRIVER-SWITCH-0001) replaces this
                // direct path, pin the iteration order deterministically
                // by block index (RUN-NONDETERM minimal fix, causally
                // verified 20/20 byte-identical).
                let mut df_sorted: Vec<i32> = df.into_iter().collect();
                df_sorted.sort_unstable();

                for y_idx in df_sorted {
                    if !has_phi_node.contains(&y_idx) {
                        self.insert_multiequal_direct(vbank, obank, bblocks, space, addr, y_idx);
                        has_phi_node.insert(y_idx);
                        if !ever_on_worklist.contains(&y_idx) {
                            ever_on_worklist.insert(y_idx);
                            worklist.push_back(y_idx);
                        }
                    }
                }
            }
        }
    }

    // RUDRA-GLUE: Borrow-safe extraction of one merge-block insertion from Heritage::placeMultiequals (heritage.cc:2631-2642).
    // (The former `insert_multiequal` Funcdata-bank adapter wrapper was removed with the production direct path in
    // HERITAGE-DRIVER-SWITCH-0001: it had no remaining callers.)

    // RUDRA-GLUE: Borrow-safe extraction of one merge-block insertion from Heritage::placeMultiequals (heritage.cc:2631-2642).
    fn insert_multiequal_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        obank: &mut PcodeOpBank,
        bblocks: &crate::block::BlockGraph,
        space: AddressSpace,
        addr: Address,
        block_idx: i32,
    ) {
        let block_arc = bblocks
            .blocks
            .iter()
            .find(|b| b.read().unwrap().get_index() == block_idx)
            .cloned();
        // Block may have been removed by dead-flow Actions — skip gracefully.
        let block_arc = match block_arc {
            Some(b) => b,
            None => return,
        };

        let (start_addr, num_in) = {
            let b = block_arc.read().unwrap();
            (b.get_start_addr(), b.size_in())
        };

        let op_ref = obank.create(crate::opcodes::OpCode::CPUI_MULTIEQUAL, num_in, start_addr);
        block_arc.write().unwrap().insert_op(0, op_ref.clone());
        // heritage.cc:2641 calls Funcdata::opInsertBegin
        // (funcdata_op.cc:413), which installs the parent/list membership.
        // This direct-bank adapter sets the equivalent parent back-pointer.
        op_ref.0.write().unwrap().parent = Some(std::sync::Arc::downgrade(&block_arc) as std::sync::Weak<std::sync::RwLock<dyn crate::block::FlowBlock + Send + Sync>>);

        // Query globaldisjoint LocationMap for precise size (keyed by
        // (space, offset); falls back to a vbank lookup, then 4 — see the
        // direct-route residual note in the fn doc below).
        let size = self
            .globaldisjoint
            .themap
            .get(&(space, addr))
            .map(|sp| sp.size)
            .unwrap_or_else(|| {
                // Fallback to searching vbank if not tracked
                vbank
                    .loc_tree
                    .iter()
                    .find(|vn| {
                        let vn_read = vn.0.read().unwrap();
                        vn_read.get_space() == space && vn_read.loc == addr
                    })
                    .map(|vn| vn.0.read().unwrap().size)
                    .unwrap_or(4) as i32
            }) as usize;

        let out_vn = vbank.create_with_space(size, space, addr.as_u64());
        let out_vn = vbank.set_def_prevalidated(out_vn, Arc::downgrade(&op_ref.0));

        {
            let mut op = op_ref.0.write().unwrap();
            op.output = Some(out_vn);
            // Initialize inrefs with placeholders so they can be filled by index
            for _ in 0..num_in {
                let placeholder = vbank.create_with_space(size, space, addr.as_u64());
                // heritage.cc:2638-2639 routes every placeholder through
                // Funcdata::opSetInput, so each slot contributes one
                // descendant entry before renameRecurse replaces it.
                placeholder.write().unwrap().add_descend(&op_ref.0);
                op.inrefs.push(placeholder);
            }
        }
    }

    // Ghidra: heritage.cc:2587 Heritage::rename
    /// Perform the renaming algorithm for the current set of address
    /// ranges. Faithful to `rename` (heritage.cc:2587-2593): one fresh
    /// VariableStack, renameRecurse rooted at block 0 ONLY (not "every
    /// entry-like block"), then `disjoint.clear()`.
    pub fn rename(&mut self, fd: &mut Funcdata) {
        let mut varstack: BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>> =
            BTreeMap::new();
        if let Some(bl0) = fd.bblocks.get_block(0) {
            self.rename_recurse(fd, bl0, &mut varstack);
        }
        // Ghidra cc:2592: disjoint.clear();
        self.disjoint.clear();
    }

    // Ghidra: heritage.cc:2479 Heritage::renameRecurse
    /// The heart of the renaming algorithm, faithful to `renameRecurse`
    /// (heritage.cc:2479-2562). From the given block, walk the dominance
    /// tree (iterative Enter/Leave work stack reproducing the recursive
    /// "children then pop" order). At each block:
    ///   - ONE pass over the ops in execution order (cc:2489): a
    ///     MULTIEQUAL skips only its input-replacement loop (cc:2491) but
    ///     still takes the common write-push tail (cc:2523-2529) at its
    ///     op position — no separate phi pre-pass;
    ///   - input slots ascending (cc:2493): skip heritage-known (cc:2495),
    ///     skip-and-keep non-active frees (cc:2496), clear active on
    ///     consumption (cc:2497), empty-stack input promotion
    ///     (cc:2499-2502), INDIRECT same-time stack deepening
    ///     (cc:2507-2516), replacement via Funcdata::opSetInput
    ///     (cc:2518) and deleteVarnode of the consumed free
    ///     (cc:2519-2520);
    ///   - write push (cc:2523-2529): output fetched after the op's read
    ///     replacement; active outputs are cleared and pushed;
    ///   - successor loop (cc:2531-2552): out-edges ascending, exact
    ///     reverse slot, successor's LEADING MULTIEQUAL group only
    ///     (cc:2536 break); phi inputs check isHeritageKnown ONLY
    ///     (cc:2538 — the old-marker skip that makes a phi cycle with an
    ///     already-written loop-carried input leave that input alone);
    ///     empty-stack promotion and deleteVarnode as above, with NO
    ///     activeHeritage check or clear on this path;
    ///   - dominator children in `domchild[index]` order (cc:2555);
    ///   - writelist popped in encounter order after all children
    ///     (cc:2558-2561).
    fn rename_recurse(
        &mut self,
        fd: &mut Funcdata,
        bl: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        varstack: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        // Iterative dominator-tree traversal using an explicit work stack:
        // Enter processes one block's ops/successors and schedules Leave
        // (pop) plus its dominator children; children are pushed in
        // reverse so they run in domchild order, and Leave runs after all
        // of them, reproducing the recursive cc:2553-2561 order without
        // unbounded Rust recursion.
        enum WorkItem {
            Enter(Arc<RwLock<dyn FlowBlock + Send + Sync>>),
            Leave(Vec<(AddressSpace, Address)>),
        }

        let mut work: Vec<WorkItem> = vec![WorkItem::Enter(bl)];
        // Guard against corrupt dominator graphs (which would grow the
        // work stack unboundedly); the locked oracle's domchild is a tree.
        let max_work = 100000usize;

        while let Some(item) = work.pop() {
            if work.len() > max_work {
                eprintln!(
                    "[WARN] Heritage rename work stack exceeded {} items, aborting",
                    max_work
                );
                break;
            }
            match item {
                WorkItem::Enter(block_arc) => {
                    let mut writelist: Vec<(AddressSpace, Address)> = Vec::new();

                    // cc:2489-2530: single pass over ops in execution order.
                    let ops = block_arc.read().unwrap().get_ops();
                    for op_ref in &ops {
                        let op_arc = op_ref.0.clone();
                        // One read guard for the opcode and input count (the
                        // oracle reads both fields off the same PcodeOp*).
                        let (op_is_multi, num_input) = {
                            let r = op_arc.read().unwrap();
                            (r.opcode == OpCode::CPUI_MULTIEQUAL, r.num_input())
                        };
                        if !op_is_multi {
                            // cc:2493-2521: replace reads with the stack top.
                            for slot in 0..num_input {
                                let vnin_arc = {
                                    let op_r = op_arc.read().unwrap();
                                    match op_r.inrefs.get(slot) {
                                        Some(v) => v.clone(),
                                        None => continue,
                                    }
                                };
                                // cc:2495-2496: not free / not being
                                // heritaged this round — the oracle reads
                                // both flag predicates off the same Varnode
                                // object; one read guard observes both.
                                let (heritage_known, active_heritage) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.is_heritage_known(), r.is_active_heritage())
                                };
                                if heritage_known {
                                    continue;
                                }
                                if !active_heritage {
                                    continue;
                                }
                                // cc:2497: consume the active mark
                                vnin_arc.write().unwrap().clear_active_heritage();
                                let key = {
                                    let vn_r = vnin_arc.read().unwrap();
                                    (vn_r.address_space, vn_r.loc)
                                };
                                let stack = varstack.entry(key).or_default();
                                // cc:2499-2505: empty stack → promote a new input.
                                let mut vnnew: Arc<RwLock<Varnode>>;
                                if stack.is_empty() {
                                    let (vn_size, vn_space, vn_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn =
                                        fd.vbank.create_with_space(vn_size, vn_space, vn_off);
                                    // heritage.cc:2500 routes through
                                    // Funcdata::newVarnode, whose symbol tail
                                    // (queryProperties -> setSymbolProperties,
                                    // funcdata_varnode.cc:161-166) attaches the
                                    // typelocked global's DWARF type onto the
                                    // promoted input; the bare bank create left
                                    // global reads (e.g. glob_expand's URLGlob*)
                                    // untyped so RulePtrArith never fired
                                    // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                                    fd.set_varnode_properties(&new_vn);
                                    Heritage::apply_new_varnode_flags(fd, &new_vn);
                                    let promoted = fd.set_input_varnode(new_vn);
                                    stack.push(promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    vnnew = stack.last().unwrap().clone();
                                }
                                // cc:2506-2517: INDIRECTs and their op really
                                // happen AT SAME TIME — if the stack top was
                                // written by an INDIRECT guarding THIS op, use
                                // the value beneath it on the stack.
                                let indirect_target_is_cur = {
                                    let vnnew_r = vnnew.read().unwrap();
                                    let mut hit = false;
                                    if vnnew_r.is_written() {
                                        if let Some(def_weak) =
                                            vnnew_r.def.as_ref().and_then(|w| w.upgrade())
                                        {
                                            let def_r = def_weak.read().unwrap();
                                            if def_r.opcode == OpCode::CPUI_INDIRECT {
                                                if let Some(iop_vn) = def_r.get_in(1) {
                                                    let iv = iop_vn.read().unwrap();
                                                    if iv.get_space() == AddressSpace::Iop {
                                                        let ptr_addr = iv.get_offset() as usize;
                                                        let raw = ptr_addr
                                                            as *const std::sync::RwLock<PcodeOp>;
                                                        if raw as *const ()
                                                            == std::sync::Arc::as_ptr(&op_arc)
                                                                as *const ()
                                                        {
                                                            hit = true;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    hit
                                };
                                if indirect_target_is_cur {
                                    if stack.len() == 1 {
                                        // cc:2509-2512: only the INDIRECT entry
                                        // on the stack — create a new input and
                                        // insert it at the bottom.
                                        let (vn_size, vn_space, vn_off) = {
                                            let r = vnin_arc.read().unwrap();
                                            (r.size, r.address_space, r.loc.as_u64())
                                        };
                                        let new_vn = fd
                                            .vbank
                                            .create_with_space(vn_size, vn_space, vn_off);
                                        // heritage.cc:2510 newVarnode symbol tail
                                        // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                                        fd.set_varnode_properties(&new_vn);
                                        Heritage::apply_new_varnode_flags(fd, &new_vn);
                                        let promoted = fd.set_input_varnode(new_vn);
                                        stack.insert(0, promoted.clone());
                                        vnnew = promoted;
                                    } else {
                                        // cc:2515-2516: vnnew = stack[stack.size()-2]
                                        vnnew = stack[stack.len() - 2].clone();
                                    }
                                }
                                // cc:2518: fd->opSetInput(op, vnnew, slot)
                                fd.op_set_input(&PcodeOpRef(op_arc.clone()), vnnew, slot);
                                // cc:2519-2520: delete the consumed free
                                if vnin_arc.read().unwrap().has_no_descend() {
                                    let _ = fd.delete_varnode(&vnin_arc);
                                }
                            }
                        }
                        // cc:2523-2529: push this op's write onto the stack.
                        let out_vn = op_arc.read().unwrap().output.clone();
                        if let Some(vnout) = out_vn {
                            if !vnout.read().unwrap().is_active_heritage() {
                                continue; // cc:2526: not a normalized write
                            }
                            vnout.write().unwrap().clear_active_heritage();
                            let key = {
                                let r = vnout.read().unwrap();
                                (r.address_space, r.loc)
                            };
                            varstack.entry(key).or_default().push(vnout.clone());
                            writelist.push(key);
                        }
                    }

                    // cc:2531-2552: fill phi inputs in successors.
                    let size_out = block_arc.read().unwrap().size_out();
                    let bank = block_arc.read().unwrap().bank();
                    for i in 0..size_out {
                        let (succ_arc, my_in_idx) = {
                            let blk_r = block_arc.read().unwrap();
                            match blk_r.get_out(i) {
                                Some(edge) => {
                                    (bank.expect_arc(edge.point), edge.reverse_index as usize)
                                }
                                None => continue,
                            }
                        };
                        let succ_ops = succ_arc.read().unwrap().get_ops();
                        for op_ref in succ_ops {
                            let op_arc = op_ref.0.clone();
                            if op_arc.read().unwrap().opcode != OpCode::CPUI_MULTIEQUAL {
                                break; // cc:2536: leading MULTIEQUALs only
                            }
                            let vnin_arc = {
                                let op_r = op_arc.read().unwrap();
                                match op_r.inrefs.get(my_in_idx) {
                                    Some(v) => v.clone(),
                                    None => continue,
                                }
                            };
                            // cc:2538: heritage-known phi inputs are skipped
                            // (old marker skip — a phi cycle whose incoming
                            // edge value is already written keeps it).
                            if vnin_arc.read().unwrap().is_heritage_known() {
                                continue;
                            }
                            let key = {
                                let vn_r = vnin_arc.read().unwrap();
                                (vn_r.address_space, vn_r.loc)
                            };
                            let stack = varstack.entry(key).or_default();
                            // cc:2539-2546: empty stack → input promotion.
                            let vnnew: Arc<RwLock<Varnode>>;
                            if stack.is_empty() {
                                let (vn_size, vn_space, vn_off) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.size, r.address_space, r.loc.as_u64())
                                };
                                let new_vn =
                                    fd.vbank.create_with_space(vn_size, vn_space, vn_off);
                                // heritage.cc:2540 newVarnode symbol tail
                                // (HERITAGE-PROMOTE-SYMBOLTAIL-0001).
                                fd.set_varnode_properties(&new_vn);
                                Heritage::apply_new_varnode_flags(fd, &new_vn);
                                let promoted = fd.set_input_varnode(new_vn);
                                stack.push(promoted.clone());
                                vnnew = promoted;
                            } else {
                                vnnew = stack.last().unwrap().clone();
                            }
                            // cc:2547: fd->opSetInput(multiop, vnnew, slot)
                            fd.op_set_input(&PcodeOpRef(op_arc.clone()), vnnew, my_in_idx);
                            // cc:2548-2549: delete the consumed free
                            if vnin_arc.read().unwrap().has_no_descend() {
                                let _ = fd.delete_varnode(&vnin_arc);
                            }
                        }
                    }

                    // cc:2553-2556: recurse to subtrees, in domchild order;
                    // cc:2557-2561: pop this block's writes after children.
                    let bl_idx = block_arc.read().unwrap().get_index();
                    work.push(WorkItem::Leave(writelist));
                    if let Some(children) = self.domchild.get(bl_idx as usize) {
                        for child in children.iter().rev() {
                            if let Some(child_arc) =
                                fd.bblocks.get_block(*child as usize)
                            {
                                work.push(WorkItem::Enter(child_arc));
                            }
                        }
                    }
                }
                WorkItem::Leave(writelist) => {
                    // cc:2558-2561: pop in encounter order.
                    for key in writelist {
                        if let Some(stack) = varstack.get_mut(&key) {
                            stack.pop();
                        }
                    }
                }
            }
        }
    }

    // RUDRA-GLUE: Direct-bank SSA driver around locked Heritage::rename/renameRecurse; it separates Rust-owned banks and its broader driver differences are documented.
    /// Perform SSA renaming directly using bank references.
    /// `vbank` is taken by &mut because heritage.cc:2501/2511 calls
    /// `fd->setInputVarnode` and cc:2520/2549 calls `fd->deleteVarnode`,
    /// both of which mutate the bank. Rugra ports these as
    /// `VarnodeBank::set_input_varnode` / `VarnodeBank::destroy_varnode`.
    /// Since HERITAGE-DRIVER-SWITCH-0001 this is off the production path
    /// (ActionHeritage drives canonical `Heritage::heritage`); remaining
    /// callers are `Funcdata::run_heritage_direct` (example-side prototype
    /// estimation on throwaway Funcdata) and in-crate tests.
    pub fn rename_direct(&mut self, vbank: &mut VarnodeBank, bblocks: &crate::block::BlockGraph) {
        // Mark all read+write varnodes as active heritage, faithful to
        // Ghidra's guard() (heritage.cc:1174/1181) which calls
        // setActiveHeritage on every varnode in the read AND write lists
        // of the disjoint ranges being heritaged this pass.
        //
        // Ghidra's read/write lists (from collect()) include both free
        // varnodes AND written varnodes at heritaged addresses — a written
        // varnode is a def that rename must push onto the stack (cc:2528
        // pushes vnout if isActiveHeritage). Without activeHeritage on
        // writes, rename skips pushing them → stack stays empty → empty-stack
        // input promotion (cc:2499-2502) creates a single shared input →
        // diamond merges lose per-branch distinctness.
        //
        // Rugra approximates Ghidra's per-range guard by marking every
        // non-constant, non-annotation varnode in the bank (free + written
        // + input). Inputs are harmless to mark because rename's
        // isHeritageKnown check (cc:2495/2538) skips them before checking
        // isActiveHeritage.
        for vn_ref in &vbank.loc_tree {
            let mut vn = vn_ref.0.write().unwrap();
            let is_known_side_effect = vn.is_constant() || vn.is_annotation();
            if !is_known_side_effect {
                vn.set_active_heritage();
            }
        }

        let mut stacks: BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>> = BTreeMap::new();

        // Push initial/input varnodes to stacks
        for vn_ref in &vbank.def_tree {
            let vn = vn_ref.0.read().unwrap();
            if vn.is_input() {
                stacks
                    .entry((vn.address_space, vn.loc))
                    .or_default()
                    .push(vn_ref.0.clone());
            }
        }

        // Find entry blocks
        let entry_blocks: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = bblocks
            .blocks
            .iter()
            .filter(|b| b.read().unwrap().size_in() == 0)
            .cloned()
            .collect();

        for entry in entry_blocks {
            self.visit_rename_direct(vbank, entry, &mut stacks);
        }
    }

    // RUDRA-GLUE: Borrow-safe adapter that temporarily separates Funcdata::vbank before the iterative renameRecurse adapter below.
    fn visit_rename(
        &mut self,
        fd: &mut Funcdata,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        let mut vbank = std::mem::take(&mut fd.vbank);
        self.visit_rename_direct(&mut vbank, block_arc, stacks);
        fd.vbank = vbank;
    }

    // Ghidra: heritage.cc:2479 Heritage::renameRecurse
    /// Iterative mapping of `Heritage::renameRecurse(BlockBasic *bl,
    /// VariableStack &varstack)` (heritage.cc:2479-2562). Broader direct-driver,
    /// global-active marking, type-copy, and graph-model differences remain
    /// documented and are not claimed equivalent here.
    ///
    /// **2026-07-05 修正**：补齐 3 个 load-bearing 语义（audit P0-4）：
    ///   (1) **empty-stack input promotion** (cc:2499-2502 / cc:2540-2543) —
    ///       当 stack 为空时，Ghidra 创建新 varnode 并 `setInputVarnode` 提升为
    ///       函数输入，push 到 stack。Rugra 此前静默跳过 → 自由读未被替换 →
    ///       SSA 不完整。
    ///   (2) **INDIRECT same-time stack-deepening** (cc:2507-2516) — 当 stack
    ///       顶的 vnnew 是 INDIRECT 写且其 target op 是当前 op 时，Ghidra 认为
    ///       "INDIRECT 和它的 op 同时发生"，深入 stack 一层（stack[size-2]）。
    ///       Rugra 此前完全缺失 → 栈指针 INDIRECT 配对的 op 得到错误的 SSA 名。
    ///   (3) **deleteVarnode of consumed frees** (cc:2519-2520 / cc:2548-2549) —
    ///       替换后若 `vnin->hasNoDescend()` 则 `fd->deleteVarnode(vnin)`。
    ///       Rugra 此前从不删除 → 死 varnode 留在 loc_tree，污染后续 pass。
    fn visit_rename_direct(
        &mut self,
        vbank: &mut VarnodeBank,
        block_arc: Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        stacks: &mut BTreeMap<(AddressSpace, Address), Vec<Arc<RwLock<Varnode>>>>,
    ) {
        // Iterative dominator-tree traversal using an explicit work stack.
        // Each entry is (block_to_process, defined_keys_for_pop_after_children).
        // This avoids deep recursion in the dominator tree (which caused stack
        // overflow when mainloop repeatapply re-runs Heritage on complex functions).

        // Work item: (block, phase) where phase 0 = process ops, phase 1 = pop.
        // We store defined_here alongside so we can pop after children.
        enum WorkItem {
            Enter(Arc<RwLock<dyn FlowBlock + Send + Sync>>),
            Leave(Vec<(AddressSpace, Address)>),
        }

        let mut work: Vec<WorkItem> = vec![WorkItem::Enter(block_arc)];
        // Guard against dom-tree cycles (which would grow the work stack unboundedly).
        let max_work = 100000usize;

        while let Some(item) = work.pop() {
            if work.len() > max_work {
                eprintln!(
                    "[WARN] Heritage rename work stack exceeded {} items, aborting", max_work
                );
                break;
            }
            match item {
                WorkItem::Enter(block_arc) => {
                    // Skip dead blocks.
                    if (block_arc.read().unwrap().get_flags() & crate::block::block_flags::DEAD) != 0 {
                        continue;
                    }

                    let mut defined_here: Vec<(AddressSpace, Address)> = Vec::new();

                    // 1. Process Phis (MULTIEQUAL) - only their outputs.
                    // Ghidra cc:2525-2530: push output if isActiveHeritage, clear flag.
                    let ops = block_arc.read().unwrap().get_ops();
                    for op_ref in &ops {
                        let op = op_ref.0.write().unwrap();
                        if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                            if let Some(out_vn) = &op.output {
                                let should_push = {
                                    let vn_read = out_vn.read().unwrap();
                                    vn_read.is_active_heritage()
                                };
                                if should_push {
                                    out_vn.write().unwrap().clear_active_heritage();
                                    let vn_read = out_vn.read().unwrap();
                                    let key = (vn_read.address_space, vn_read.loc);
                                    drop(vn_read);
                                    stacks.entry(key).or_default().push(out_vn.clone());
                                    defined_here.push(key);
                                }
                            }
                        }
                    }

                    // 2. Process regular Ops: replace reads, then push writes.
                    // Ghidra cc:2489-2530.
                    for op_ref in &ops {
                        let mut op = op_ref.0.write().unwrap();
                        if op.opcode == crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                            continue;
                        }

                        for i in 0..op.inrefs.len() {
                            let should_skip = {
                                let vn_read = op.inrefs[i].read().unwrap();
                                vn_read.is_heritage_known() || !vn_read.is_active_heritage()
                            };
                            if should_skip {
                                continue;
                            }
                            // Ghidra cc:2497: vnin->clearActiveHeritage();
                            let vnin_arc = op.inrefs[i].clone();
                            vnin_arc.write().unwrap().clear_active_heritage();
                            // Ghidra cc:2498: vector<Varnode *> &stack(varstack[vnin->getAddr()]);
                            let key = {
                                let vn_read = vnin_arc.read().unwrap();
                                (vn_read.address_space, vn_read.loc)
                            };
                            let stack = stacks.entry(key).or_default();
                            // Ghidra cc:2499-2505: empty-stack → promote to input.
                            // (SEMANTIC #1)
                            let mut vnnew: Arc<RwLock<Varnode>>;
                            if stack.is_empty() {
                                let (vnin_size, vnin_space, vnin_off) = {
                                    let r = vnin_arc.read().unwrap();
                                    (r.size, r.address_space, r.loc.as_u64())
                                };
                                let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                let promoted = vbank.set_input_varnode(new_vn);
                                stack.push(promoted.clone());
                                vnnew = promoted;
                            } else {
                                vnnew = stack.last().unwrap().clone();
                            }
                            // Ghidra cc:2507-2516: INDIRECT same-time deepening.
                            // (SEMANTIC #2) — vnnew is written by an INDIRECT
                            // whose iop-const input(1) points at the current op.
                            let indirect_target_is_cur = {
                                let vnnew_r = vnnew.read().unwrap();
                                let mut hit = false;
                                if vnnew_r.is_written() {
                                    if let Some(def_weak) = vnnew_r.def.as_ref().and_then(|w| w.upgrade()) {
                                        let def_r = def_weak.read().unwrap();
                                        if def_r.opcode == crate::opcodes::OpCode::CPUI_INDIRECT {
                                            if let Some(iop_vn) = def_r.get_in(1) {
                                                let iv = iop_vn.read().unwrap();
                                                if iv.get_space() == AddressSpace::Iop {
                                                    let ptr_addr = iv.get_offset() as usize;
                                                    let raw = ptr_addr as *const std::sync::RwLock<
                                                            crate::op::PcodeOp,
                                                        >;
                                                    if raw as *const () == std::sync::Arc::as_ptr(&op_ref.0) as *const () {
                                                        hit = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                hit
                            };
                            if indirect_target_is_cur {
                                if stack.len() == 1 {
                                    // cc:2509-2512: stack has only the INDIRECT entry;
                                    // create new input and insert at bottom.
                                    let (vnin_size, vnin_space, vnin_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                    let promoted = vbank.set_input_varnode(new_vn);
                                    stack.insert(0, promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    // cc:2515-2516: vnnew = stack[stack.size()-2]
                                    vnnew = stack[stack.len() - 2].clone();
                                }
                            }
                            // Ghidra cc:2518: fd->opSetInput(op, vnnew, slot);
                            // Preserve v_type from old varnode to new varnode
                            // so struct pointer types survive Heritage rename.
                            {
                                let old_vt = vnin_arc.read().unwrap().v_type.clone();
                                if old_vt.is_some() {
                                    vnnew.write().unwrap().v_type = old_vt;
                                }
                            }
                            if !Arc::ptr_eq(&vnin_arc, &vnnew) {
                                // funcdata_op.cc:120-124: opSetInput first
                                // consumes exactly this slot's old descendant,
                                // then adds the new edge before updating inrefs.
                                vnin_arc.write().unwrap().erase_descend(&op_ref.0);
                                vnnew.write().unwrap().add_descend(&op_ref.0);
                                op.inrefs[i] = vnnew.clone();
                            }
                            // Ghidra cc:2519-2520: if (vnin->hasNoDescend()) fd->deleteVarnode(vnin);
                            // (SEMANTIC #3)
                            if vnin_arc.read().unwrap().has_no_descend() {
                                // cc:2519 proves the value is detached; it was
                                // fetched from this bank's current SSA web.
                                vbank.destroy_varnode_prevalidated(&vnin_arc);
                            }
                        }

                        // Ghidra cc:2524-2530: push output if activeHeritage.
                        if let Some(out_vn) = &op.output {
                            let should_push = {
                                let vn_read = out_vn.read().unwrap();
                                vn_read.is_active_heritage()
                            };
                            if should_push {
                                out_vn.write().unwrap().clear_active_heritage();
                                let vn_read = out_vn.read().unwrap();
                                let key = (vn_read.address_space, vn_read.loc);
                                drop(vn_read);
                                stacks.entry(key).or_default().push(out_vn.clone());
                                defined_here.push(key);
                            }
                        }
                    }

                    // 3. Fill Phi inputs in successors.
                    // Ghidra cc:2531-2552: for each out-edge, walk successor's
                    // leading MULTIEQUALs and replace the matching input slot.
                    let size_out = block_arc.read().unwrap().size_out();
                    let bank = block_arc.read().unwrap().owner_bank();
                    if size_out > 0 && bank.is_none() {
                        panic!("phi-input fill on a block with out-edges but no bank");
                    }
                    for i in 0..size_out {
                        if let Some(edge) = block_arc.read().unwrap().get_out(i) {
                            let succ_arc = bank.as_ref().unwrap().expect_arc(edge.point);
                            let my_in_idx = edge.reverse_index as usize;

                            let succ_ops = succ_arc.read().unwrap().get_ops();
                            for op_ref in succ_ops {
                                let mut op = op_ref.0.write().unwrap();
                                if op.opcode != crate::opcodes::OpCode::CPUI_MULTIEQUAL {
                                    break; // Ghidra cc:2536: stop at first non-MULTIEQUAL
                                }
                                if my_in_idx >= op.inrefs.len() {
                                    continue;
                                }
                                let vnin_arc = op.inrefs[my_in_idx].clone();
                                let should_skip = {
                                    let vn_read = vnin_arc.read().unwrap();
                                    vn_read.is_heritage_known()
                                };
                                if should_skip {
                                    continue;
                                }
                                // Ghidra cc:2539-2546: empty-stack → input promotion.
                                // (SEMANTIC #1, phi-input variant)
                                let key = {
                                    let vn_read = vnin_arc.read().unwrap();
                                    (vn_read.address_space, vn_read.loc)
                                };
                                let stack = stacks.entry(key).or_default();
                                let vnnew: Arc<RwLock<Varnode>>;
                                if stack.is_empty() {
                                    let (vnin_size, vnin_space, vnin_off) = {
                                        let r = vnin_arc.read().unwrap();
                                        (r.size, r.address_space, r.loc.as_u64())
                                    };
                                    let new_vn = vbank.create_with_space(vnin_size, vnin_space, vnin_off);
                                    let promoted = vbank.set_input_varnode(new_vn);
                                    stack.push(promoted.clone());
                                    vnnew = promoted;
                                } else {
                                    vnnew = stack.last().unwrap().clone();
                                }
                                // Ghidra cc:2547: opSetInput(multiop, vnnew, slot)
                                if !Arc::ptr_eq(&vnin_arc, &vnnew) {
                                    vnin_arc.write().unwrap().erase_descend(&op_ref.0);
                                    vnnew.write().unwrap().add_descend(&op_ref.0);
                                    op.inrefs[my_in_idx] = vnnew.clone();
                                }
                                // Ghidra cc:2548-2549: deleteVarnode if no descend.
                                // (SEMANTIC #3, phi-input variant)
                                if vnin_arc.read().unwrap().has_no_descend() {
                                    // cc:2548 proves the value is detached;
                                    // the phi input is bank-owned by construction.
                                    vbank.destroy_varnode_prevalidated(&vnin_arc);
                                }
                            }
                        }
                    }

                    // 4. Schedule: Leave (pop) AFTER all children.
                    // Push Leave first (it will execute last due to LIFO).
                    let children = block_arc.read().unwrap().get_dom_children();
                    work.push(WorkItem::Leave(defined_here));
                    // Push children in reverse order so they process in original order.
                    for child in children.into_iter().rev() {
                        work.push(WorkItem::Enter(child));
                    }
                }
                WorkItem::Leave(defined_here) => {
                    // 5. Pop stacks (Ghidra cc:2558-2561).
                    for key in defined_here {
                        if let Some(stack) = stacks.get_mut(&key) {
                            stack.pop();
                        }
                    }
                }
            }
        }
    }

    // Ghidra: heritage.cc:219 Heritage::getPass
    pub fn get_pass(&self) -> i32 {
        self.pass
    }

    // Ghidra: heritage.cc:2779 Heritage::numHeritagePasses
    /// Get the number of heritage passes performed for a space.
    /// Faithful to `numHeritagePasses` (heritage.cc:2793-2801):
    ///   `return pass - info->delay;`
    /// Previously Rugra returned `self.pass` (ignoring per-space delay),
    /// which over-reported the pass count for Stack (delay=1).
    pub fn num_heritage_passes(&self, space: AddressSpace) -> i32 {
        let info = self.infolist.iter().find(|i| i.space == space);
        let delay = info.map_or(0, |i| i.delay);
        self.pass - delay
    }

    // Ghidra: heritage.cc:2829 Heritage::deadRemovalAllowed
    /// Check if dead code removal is allowed for a space.
    /// Faithful to `deadRemovalAllowed` (heritage.cc:2829-2841):
    ///   `return pass > info->deadcodedelay;`
    /// Previously Rugra returned const `true`, allowing dead-code removal
    /// on every pass including pass 0 — exactly the "Heritage AFTER dead
    /// removal" warning condition Ghidra prevents (cc:2728-2744).
    pub fn dead_removal_allowed(&self, space: AddressSpace) -> bool {
        let info = self.infolist.iter().find(|i| i.space == space);
        let deadcodedelay = info.map_or(0, |i| i.deadcodedelay);
        self.pass > deadcodedelay
    }

    // Ghidra: heritage.cc:2843 Heritage::deadRemovalAllowedSeen
    /// Check the per-space dead-code delay and, when removal is allowed,
    /// record that dead code has been removed from the space.
    pub fn dead_removal_allowed_seen(&mut self, space: AddressSpace) -> bool {
        if self.infolist.is_empty() {
            self.build_info_list();
        }
        let index = self
            .infolist
            .iter()
            .position(|info| info.space == space)
            .unwrap_or_else(|| {
                self.infolist.push(HeritageInfo::new(space));
                self.infolist.len() - 1
            });
        let allowed = self.pass > self.infolist[index].deadcodedelay;
        if allowed {
            self.infolist[index].deadremoved = 1;
        }
        allowed
    }

    // Ghidra: heritage.cc:2815 Heritage::setDeadCodeDelay
    /// Set dead code delay for a space. Faithful to `setDeadCodeDelay`
    /// (heritage.cc:2815-2822): `getInfo` indexes the infolist (heritage.hh:
    /// 257 `infolist[spc->getIndex()]`), a delay below the space's heritage
    /// delay is a LowlevelError ("Illegal deadcode delay setting"). Used by
    /// `Override::applyDeadCodeDelay` (via `Funcdata::startProcessing`)
    /// to install the bumped delay after a restart.
    pub fn set_dead_code_delay(&mut self, space: AddressSpace, delay: i32) {
        let idx = self.infolist.iter().position(|i| i.space == space);
        let Some(i) = idx else {
            // Ghidra's getInfo reads infolist[spc->getIndex()], which throws
            // (vector bounds) for a space without a HeritageInfo slot; every
            // heritaged locked-spec space has one, so this is unreachable in
            // the corpus. Mirror the throw as a panic (same convention as
            // Funcdata::start_processing's processing-started guard).
            panic!("Illegal deadcode delay setting");
        };
        // cc:2820-2821: if (delay < info->delay) throw
        // LowlevelError("Illegal deadcode delay setting");
        if delay < self.infolist[i].delay {
            panic!("Illegal deadcode delay setting");
        }
        // cc:2822: info->deadcodedelay = delay;
        self.infolist[i].deadcodedelay = delay;
    }

    // Ghidra: heritage.cc:2803 Heritage::getDeadCodeDelay
    /// Get dead code delay for a space. Faithful to `getDeadCodeDelay`
    /// (heritage.cc:2803-2813). Previously returned const 2.
    pub fn get_dead_code_delay(&self, space: AddressSpace) -> i32 {
        let info = self.infolist.iter().find(|i| i.space == space);
        info.map_or(space.get_deadcode_delay(), |i| i.deadcodedelay)
    }

    // Ghidra: heritage.cc:2791 Heritage::seenDeadCode
    /// Mark that dead code was seen (removed) for a space. Faithful to
    /// `seenDeadCode` (heritage.cc:2791-2801): `info->deadremoved = 1`.
    /// Previously Rugra was a no-op, so removeRevisitedMarkers/bumpDeadcodeDelay
    /// warning paths could never trigger.
    pub fn seen_dead_code(&mut self, space: AddressSpace) {
        let idx = self.infolist.iter().position(|i| i.space == space);
        if let Some(i) = idx {
            self.infolist[i].deadremoved = 1;
        }
    }

    // Ghidra: heritage.cc:2855 Heritage::clear
    /// Clear all non-permanent state. Faithful to `clear`
    /// (heritage.cc:2855-2870):
    ///   disjoint/globaldisjoint/domchild/augment/flags/depth/merge.clear()
    ///   clearInfoList(); loadGuard/storeGuard.clear();
    ///   maxdepth = -1; pass = 0;
    pub fn clear(&mut self) {
        // Ghidra cc:2859-2864
        self.disjoint.clear();
        self.globaldisjoint.clear();
        self.domchild.clear();
        self.augment.clear();
        self.flags.clear();
        self.depth.clear();
        self.merge.clear();
        // Ghidra cc:2865: clearInfoList() resets entries in place so delay
        // overrides survive a restart.
        for info in &mut self.infolist {
            info.reset();
        }
        // Ghidra cc:2866-2867
        self.load_guard.clear();
        self.store_guard.clear();
        // Ghidra cc:2868: maxdepth = -1
        self.maxdepth = -1;
        // Ghidra cc:2869: pass = 0
        self.pass = 0;
    }

    // Ghidra: heritage.cc:2762 Heritage::getStoreGuard
    /// Find the STORE guard matching `op`. Faithful to
    /// `Heritage::getStoreGuard` (heritage.hh:338). Linear scan of store_guard.
    pub fn get_store_guard(
        &self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    ) -> Option<&LoadGuard> {
        self.store_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }

    // Ghidra: heritage.cc:219 Heritage::getLoadGuard
    /// Find the LOAD guard matching `op`. Faithful to
    /// `Heritage::getLoadGuard` (heritage.hh:337).
    pub fn get_load_guard(
        &self, op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    ) -> Option<&LoadGuard> {
        self.load_guard.iter().find(|g| match g.op.upgrade() {
            Some(g_op) => std::sync::Arc::ptr_eq(&g_op, op),
            None => false,
        })
    }
}

// Ghidra: heritage.cc:219 Heritage::storeGuardPointerBase
/// Compute the `pointerBase` (stack-pointer base offset) recorded for a STORE
/// guard, mirroring the `StackNode.offset` that Ghidra's
/// `discoverIndexedStackPointers` threads into `generateStoreGuard`
/// (heritage.cc:927-932, 1077-1090).
///
/// The STORE pointer is `in[1]`. We follow INT_ADD(const)/INT_SUB(const)/COPY
/// definitions backward and accumulate the constant offset. If we cannot
/// resolve a constant offset (non-constant add, multiequal, or a free
/// varnode), we return 0, which matches Ghidra's `StackNode(spInput,0,0)`
/// starting offset and yields a maximally conservative guard.
fn store_guard_pointer_base(
    store_op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    _fd: &Funcdata,
) -> u64 {
    let g = store_op.read().unwrap();
    let ptr = match g.inrefs.get(1) {
        Some(v) => v.clone(),
        None => return 0,
    };
    drop(g);
    trace_const_stack_offset(&ptr)
}

// Ghidra: heritage.cc:219 Heritage::loadGuardPointerBase
/// Compute the `pointerBase` recorded for a LOAD guard. The LOAD pointer is
/// `in[1]`; see `store_guard_pointer_base` for the tracing strategy.
fn load_guard_pointer_base(
    load_op: &std::sync::Arc<std::sync::RwLock<PcodeOp>>,
    _fd: &Funcdata,
) -> u64 {
    let g = load_op.read().unwrap();
    let ptr = match g.inrefs.get(1) {
        Some(v) => v.clone(),
        None => return 0,
    };
    drop(g);
    trace_const_stack_offset(&ptr)
}

// Ghidra: heritage.cc:219 Heritage::traceConstStackOffset
/// Follow INT_ADD(const)/INT_SUB(const)/COPY chains backward from a pointer
/// varnode and accumulate the constant offset added to the stack pointer.
/// Returns 0 if the offset cannot be resolved to a single constant (the
/// conservative default, matching Ghidra's initial `StackNode.offset == 0`).
fn trace_const_stack_offset(ptr: &std::sync::Arc<std::sync::RwLock<Varnode>>) -> u64 {
    let mut cur = ptr.clone();
    let mut offset: u64 = 0;
    let mut hops = 0;
    loop {
        // Guard against pathological cycles.
        hops += 1;
        if hops > 64 {
            break;
        }
        let next = {
            let vn = cur.read().unwrap();
            if !vn.is_written() {
                return offset;
            }
            let def = match vn.def.as_ref().and_then(|w| w.upgrade()) {
                Some(o) => o,
                None => return offset,
            };
            let defg = def.read().unwrap();
            match defg.opcode {
                crate::opcodes::OpCode::CPUI_COPY => defg.inrefs.first().cloned(),
                crate::opcodes::OpCode::CPUI_INT_ADD
                | crate::opcodes::OpCode::CPUI_INT_SUB => {
                    // The other operand must be a constant.
                    let (a, b) = (
                        defg.inrefs.first().cloned(),
                        defg.inrefs.get(1).cloned());
                    let (other, _) = match (a, b) {
                        (Some(a), Some(b)) => {
                            if Arc::ptr_eq(&a, &cur) {
                                (Some(b), 0)
                            } else if Arc::ptr_eq(&b, &cur) {
                                (Some(a), 1)
                            } else {
                                return offset;
                            }
                        }
                        _ => return offset,
                    };
                    let other = match other {
                        Some(o) => o,
                        None => return offset,
                    };
                    let og = other.read().unwrap();
                    if !og.is_constant() {
                        return offset;
                    }
                    let delta = og.get_offset();
                    drop(og);
                    if defg.opcode == crate::opcodes::OpCode::CPUI_INT_ADD {
                        offset = offset.wrapping_add(delta);
                    } else {
                        offset = offset.wrapping_sub(delta);
                    }
                    defg.inrefs
                        .first()
                        .filter(|v| !Arc::ptr_eq(v, &cur))
                        .cloned()
                }
                _ => return offset,
            }
        };
        match next {
            Some(n) => cur = n,
            None => return offset,
        }
    }
    offset
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rename_replaces_regular_input_and_retires_old_varnode() {
        use crate::address::SeqNum;

        let mut bank = VarnodeBank::new();
        let old = bank.create_with_space(4, AddressSpace::Register, 0x40);
        old.write().unwrap().set_active_heritage();
        let canonical = bank.create_with_space(4, AddressSpace::Register, 0x40);
        let canonical = bank.set_input(canonical).expect("fresh input");

        let operation = PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1000), 1),
            OpCode::CPUI_COPY,
        ))));
        operation.0.write().unwrap().inrefs.push(old.clone());
        old.write().unwrap().add_descend(&operation.0);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x1000))));
        block.write().unwrap().insert_op(0, operation.clone());

        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x40)),
            vec![canonical.clone()],
        );
        Heritage::new().visit_rename_direct(&mut bank, block, &mut stacks);

        assert!(Arc::ptr_eq(
            &operation.0.read().unwrap().inrefs[0],
            &canonical,
        ));
        assert_eq!(canonical.read().unwrap().count_descends(), 1);
        assert!(old.read().unwrap().has_no_descend());
        assert!(!bank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &old)));
    }

    #[test]
    fn test_rename_same_arc_input_is_an_exact_noop() {
        use crate::address::SeqNum;

        let mut bank = VarnodeBank::new();
        let value = bank.create_with_space(4, AddressSpace::Register, 0x44);
        value.write().unwrap().set_active_heritage();
        let operation = PcodeOpRef(Arc::new(RwLock::new(PcodeOp::new(
            SeqNum::new(Address::new(0x1010), 2),
            OpCode::CPUI_COPY,
        ))));
        operation.0.write().unwrap().inrefs.push(value.clone());
        value.write().unwrap().add_descend(&operation.0);
        let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x1010))));
        block.write().unwrap().insert_op(0, operation.clone());
        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x44)),
            vec![value.clone()],
        );

        Heritage::new().visit_rename_direct(&mut bank, block, &mut stacks);

        assert!(Arc::ptr_eq(&operation.0.read().unwrap().inrefs[0], &value));
        assert_eq!(value.read().unwrap().count_descends(), 1);
        assert!(bank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, &value)));
    }

    #[test]
    fn test_inserted_phi_placeholders_have_edges_and_are_retired_per_slot() {
        let mut bank = VarnodeBank::new();
        let canonical = bank.create_with_space(4, AddressSpace::Register, 0x48);
        let canonical = bank.set_input(canonical).expect("fresh input");
        let mut op_bank = PcodeOpBank::new();
        let mut graph = BlockGraph::new();
        let pred0: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(0, Address::new(0x2000))));
        let pred1: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(1, Address::new(0x2010))));
        let join: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
            BlockBasic::new(2, Address::new(0x2020))));
        graph.add_block(pred0.clone());
        graph.add_block(pred1.clone());
        graph.add_block(join.clone());
        graph.add_edge(pred0.clone(), join.clone());
        graph.add_edge(pred1.clone(), join.clone());

        let mut heritage = Heritage::new();
        heritage.insert_multiequal_direct(
            &mut bank,
            &mut op_bank,
            &graph,
            AddressSpace::Register,
            Address::new(0x48),
            2,
        );
        let phi = join.read().unwrap().get_ops()[0].clone();
        let placeholders = phi.0.read().unwrap().inrefs.clone();
        assert_eq!(placeholders.len(), 2);
        assert!(placeholders
            .iter()
            .all(|value| value.read().unwrap().count_descends() == 1));

        let mut stacks = BTreeMap::new();
        stacks.insert(
            (AddressSpace::Register, Address::new(0x48)),
            vec![canonical.clone()],
        );
        heritage.visit_rename_direct(&mut bank, pred0, &mut stacks);
        assert!(Arc::ptr_eq(&phi.0.read().unwrap().inrefs[0], &canonical));
        assert!(Arc::ptr_eq(
            &phi.0.read().unwrap().inrefs[1],
            &placeholders[1],
        ));
        assert!(placeholders[0].read().unwrap().has_no_descend());
        assert_eq!(placeholders[1].read().unwrap().count_descends(), 1);

        heritage.visit_rename_direct(&mut bank, pred1, &mut stacks);
        assert!(phi
            .0
            .read()
            .unwrap()
            .inrefs
            .iter()
            .all(|value| Arc::ptr_eq(value, &canonical)));
        assert_eq!(canonical.read().unwrap().count_descends(), 2);
        for placeholder in placeholders {
            assert!(placeholder.read().unwrap().has_no_descend());
            assert!(!bank
                .loc_tree
                .iter()
                .any(|entry| Arc::ptr_eq(&entry.0, &placeholder)));
        }
    }

    #[test]
    fn test_location_map() {
        let mut lm = LocationMap::new();
        lm.add(AddressSpace::Register, Address::new(0x100), 4, 1);
        assert_eq!(lm.find_pass(AddressSpace::Register, Address::new(0x100)), 1);
        assert_eq!(
            lm.find_pass(AddressSpace::Register, Address::new(0x200)), -1
        );
    }

    /// HERITAGE-DRIVER-SWITCH-0001: Ghidra's LocationMap is keyed by a full
    /// Address (space + offset, heritage.hh:48), and `Address::overlap`
    /// returns -1 across spaces, so equal offsets in different spaces are
    /// disjoint entries. The bare-offset key previously merged them and
    /// misclassified the second space's range as OLD (prev==2).
    #[test]
    fn test_location_map_cross_space_keys_are_disjoint() {
        use crate::space::AddressSpace;
        let mut lm = LocationMap::new();
        // Register 0x30 heritaged in pass 1.
        assert_eq!(
            lm.add(AddressSpace::Register, Address::new(0x30), 8, 1).0,
            0
        );
        // A Stack varnode at the SAME offset must be NEW (prev==0), not
        // contained in the register entry (prev==2).
        assert_eq!(lm.add(AddressSpace::Stack, Address::new(0x30), 8, 2).0, 0);
        // Re-adding the register range at a later pass is contained (prev==2).
        assert_eq!(
            lm.add(AddressSpace::Register, Address::new(0x30), 8, 3).0,
            2
        );
        // Each space queries its own entry only.
        assert_eq!(lm.find_pass(AddressSpace::Register, Address::new(0x30)), 1);
        assert_eq!(lm.find_pass(AddressSpace::Stack, Address::new(0x30)), 2);
        // entry_containing never crosses spaces either.
        assert_eq!(
            lm.entry_containing(AddressSpace::Stack, Address::new(0x33)),
            Some((Address::new(0x30), 8))
        );
        assert_eq!(
            lm.entry_containing(AddressSpace::Unique, Address::new(0x33)), None
        );
    }

    #[test]
    fn test_priority_queue() {
        let mut pq = PriorityQueue::new();
        pq.reset(10);
        assert!(pq.empty());
    }

    #[test]
    fn test_heritage_creation() {
        let mut h = Heritage::new();
        assert_eq!(h.get_pass(), 0);
        // Locked-oracle delay model (MAINDIFF-UNIQLEAK-0001 / RCA-2): x86-64.sla
        // space table gives ram delay=1 (unique/register=0). The stack space is
        // NOT in the .sla; it is synthesized by addSpacebase
        // (architecture.cc:1013 → 559-570) with delay = ptrdata.space->getDelay()+1
        // (architecture.cc:565), where ptrdata.space is the stack-pointer
        // REGISTER space (delay 0), not the ram basespace — oracle
        // HeritageInfo dump: `stack:idx=8,type=IPTR_SPACEBASE,delay=1`
        // (RCA2_MAXPASS.md §4.3/§5; corrected in commit 6821e158).
        // getDeadCodeDelay reads infolist; build_info_list populates it.
        h.build_info_list();
        assert_eq!(h.get_dead_code_delay(AddressSpace::Ram), 1);
        // deadRemovalAllowed = (pass > deadcodedelay) = (0 > 1) = false.
        // (Ghidra prevents dead-code removal before any heritage pass.)
        assert!(!h.dead_removal_allowed(AddressSpace::Ram));
        // Stack has delay=1 (register(0)+1, architecture.cc:565; the old
        // "ram+1 = 2" reading asserted here pre-6821e158 was the misread
        // ptrdata.space → basespace, refuted by the oracle dump above).
        assert_eq!(h.get_dead_code_delay(AddressSpace::Stack), 1);
        // Register/unique have delay=0 (x86-64.sla).
        assert_eq!(h.get_dead_code_delay(AddressSpace::Register), 0);
        assert_eq!(h.get_dead_code_delay(AddressSpace::Unique), 0);
    }

    /// Build a STORE op targeting the stack space, mark it spacebase, and
    /// verify `guard_stores` records a `LoadGuard` for it. Mirrors Ghidra's
    /// `generateStoreGuard` (heritage.cc:927) + `guardStores` (heritage.cc:1539).
    #[test]
    fn test_guard_stores_populates_store_guard() {
        use crate::op::PcodeOpRef;
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let start = Address::new(0x1000);
        let mut fd = Funcdata::new("guard_stores", start, 0);

        // STORE(const(stack_space_id), ptr, val)
        let store = fd.obank.create(OpCode::CPUI_STORE, 3, start);
        // in[0]: const varnode carrying the Stack space id (getSpaceFromConst).
        // The lifter emits this with the CONSTANT flag + Const space.
        let space_const = fd
            .vbank
            .create_constant(8, AddressSpace::Stack.space_id() as u64);
        // in[1]: a (stack-pointer) pointer varnode.
        let ptr = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        // in[2]: the value varnode.
        let val = fd.vbank.create_with_space(8, AddressSpace::Ram, 0x1000);
        fd.op_set_input(&store, space_const, 0);
        fd.op_set_input(&store, ptr, 1);
        fd.op_set_input(&store, val, 2);
        // Mark the STORE as spacebase-indexed (as discoverIndexedStackPointers
        // would for an indexed stack STORE).
        store.0.write().unwrap().mark_spacebase_ptr();

        let mut h = Heritage::new();
        assert!(h.store_guard.is_empty());
        h.guard_stores(&mut fd);

        // Exactly one guard should be created.
        assert_eq!(h.store_guard.len(), 1, "guard_stores must record the STORE");
        let g = &h.store_guard[0];
        assert_eq!(g.spc, AddressSpace::Stack);
        assert_eq!(g.minimum_offset, 0); // initial guard protects the whole space
        assert_eq!(g.analysis_state, 0); // unanalyzed until value-set runs

        // get_store_guard must now return the record for this op.
        let found = h.get_store_guard(&store.0);
        assert!(
            found.is_some(), "get_store_guard must find the guarded STORE"
        );

        // Calling guard_stores again must NOT duplicate the record.
        h.guard_stores(&mut fd);
        assert_eq!(
            h.store_guard.len(), 1, "guard_stores must dedup across passes"
        );

        // A non-stack STORE (Ram target) must not be guarded.
        let ram_store = fd.obank.create(OpCode::CPUI_STORE, 3, start);
        let ram_const = fd
            .vbank
            .create_constant(8, AddressSpace::Ram.space_id() as u64);
        let ptr2 = fd.vbank.create_with_space(8, AddressSpace::Register, 0x28);
        let val2 = fd.vbank.create_with_space(8, AddressSpace::Ram, 0x2000);
        fd.op_set_input(&ram_store, ram_const, 0);
        fd.op_set_input(&ram_store, ptr2, 1);
        fd.op_set_input(&ram_store, val2, 2);
        ram_store.0.write().unwrap().mark_spacebase_ptr();
        let before = h.store_guard.len();
        h.guard_stores(&mut fd);
        assert_eq!(
            h.store_guard.len(), before, "non-stack STORE must not be guarded"
        );
        // PcodeOpRef must outlive the borrow checker usage above.
        let _ = PcodeOpRef(store.0.clone());
    }

    /// Build a LOAD op from the stack space (spacebase-marked) and verify
    /// `guard_loads` records a `LoadGuard` for it. Mirrors Ghidra's
    /// `generateLoadGuard` (heritage.cc:910) + `guardLoads` (heritage.cc:1571).
    #[test]
    fn test_guard_loads_populates_load_guard() {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let start = Address::new(0x2000);
        let mut fd = Funcdata::new("guard_loads", start, 0);

        // LOAD(const(stack_space_id), ptr)
        let load = fd.obank.create(OpCode::CPUI_LOAD, 2, start);
        let space_const = fd
            .vbank
            .create_constant(8, AddressSpace::Stack.space_id() as u64);
        let ptr = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
        fd.op_set_input(&load, space_const, 0);
        fd.op_set_input(&load, ptr, 1);
        load.0.write().unwrap().mark_spacebase_ptr();

        let mut h = Heritage::new();
        assert!(h.load_guard.is_empty());
        h.guard_loads(&mut fd);

        assert_eq!(h.load_guard.len(), 1, "guard_loads must record the LOAD");
        assert_eq!(h.load_guard[0].spc, AddressSpace::Stack);
        assert!(h.get_load_guard(&load.0).is_some());

        // Dedup: a second call must not re-add it.
        h.guard_loads(&mut fd);
        assert_eq!(h.load_guard.len(), 1);
    }

    /// `establish_range`/`finalize_range` against the empty-range
    /// ValueSetRead arm (heritage.cc:746-749): min=pointerBase with a
    /// 0x1000 window, analysisState stays 0 (establish) then 1 without a
    /// lock (finalize). GETPARAM-OPPOOL-COUNT-0001 turned the former stubs
    /// into the faithful ports.
    #[test]
    fn test_load_guard_range_establish_finalize() {
        use crate::space::AddressSpace;
        let mut g = LoadGuard::default();
        // Default guard protects the whole Ram space.
        assert_eq!(g.minimum_offset, 0);
        assert_eq!(g.maximum_offset, u64::MAX);
        assert_eq!(g.analysis_state, 0);

        let vsr = crate::rangeutil::ValueSetRead::new(); // empty range
        g.establish_range(&vsr);
        // cc:746-749 empty arm: minimumOffset = pointerBase (0), size 0x1000 —
        // but Ram's highest is 2^64-1, so uintb wraparound clamps the window
        // back to the whole space (faithful C++ semantics).
        assert_eq!(g.analysis_state, 0);
        assert_eq!(g.minimum_offset, 0);
        assert_eq!(g.maximum_offset, u64::MAX);
        assert!(g.is_guarded(&AddressSpace::Ram, 0x1234));

        g.finalize_range(&vsr);
        // cc:790 state=1; empty range never locks (rangeSize not in
        // (1,0xffffff)); min/max keep the established window.
        assert_eq!(g.analysis_state, 1);
        assert_eq!(g.minimum_offset, 0);
        assert_eq!(g.maximum_offset, u64::MAX);
        assert!(g.is_guarded(&AddressSpace::Ram, 0xffff));
        // A different space is never guarded.
        assert!(!g.is_guarded(&AddressSpace::Stack, 0x1234));
    }

    // HERITAGE-OWNERSHIP-0001: shared synthetic-graph builder for the
    // ownership-boundary regression tests.
    struct OwnershipGraph {
        fd: Funcdata,
        next_pc: u64,
    }

    impl OwnershipGraph {
        fn new(name: &str, base: u64) -> Self {
            OwnershipGraph {
                fd: Funcdata::new(name, Address::new(base), 0x20),
                next_pc: 0,
            }
        }

        fn block(&mut self, index: i32) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
            let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
                BlockBasic::new(index, Address::new(0x6000))));
            self.fd.bblocks.add_block(block.clone());
            block
        }

        fn op(&mut self, opcode: OpCode, inputs: usize) -> PcodeOpRef {
            let pc = Address::new(0x6000 + self.next_pc);
            self.next_pc += 1;
            let op = self.fd.new_op(inputs, pc);
            self.fd.op_set_opcode(&op, opcode);
            op
        }

        fn constant(&mut self, size: usize, value: u64) -> Arc<RwLock<Varnode>> {
            self.fd.new_constant(size, value)
        }

        fn free_register(&mut self, offset: u64, size: usize) -> Arc<RwLock<Varnode>> {
            self.fd
                .vbank
                .create_with_space(size, AddressSpace::Register, offset)
        }

        /// Written varnode at an explicit register address (the SLEIGH-style
        /// direct register write), modeled with the bank's def transition.
        fn written_register(
            &mut self,
            offset: u64,
            size: usize,
            op: &PcodeOpRef,
        ) -> Arc<RwLock<Varnode>> {
            let vn = self
                .fd
                .vbank
                .create_with_space(size, AddressSpace::Register, offset);
            let vn = self
                .fd
                .vbank
                .set_def_prevalidated(vn, Arc::downgrade(&op.0));
            op.0.write().unwrap().output = Some(vn.clone());
            vn
        }

        fn set_input(&mut self, op: &PcodeOpRef, vn: &Arc<RwLock<Varnode>>, slot: usize) {
            self.fd.op_set_input(op, vn.clone(), slot);
        }

        fn insert_end(
            &mut self, op: &PcodeOpRef, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        ) {
            self.fd.op_insert_end(op, block);
        }
    }

    // HERITAGE-OWNERSHIP-0001: the phi self-reference cycle graph (the cover
    // fixture slot2 topology with a genuine loop-carried def-use cycle:
    // m_out -> r -> t3 -> m slot 1).
    fn build_phi_cycle_graph(name: &str) -> Funcdata {
        let mut g = OwnershipGraph::new(name, 0x6000);
        let b0 = g.block(0);
        let b1 = g.block(1);
        let b2 = g.block(2);
        let b3 = g.block(3);
        g.fd.bblocks.add_edge(b0.clone(), b1.clone());
        g.fd.bblocks.add_edge(b1.clone(), b2.clone());
        g.fd.bblocks.add_edge(b2.clone(), b1.clone());
        g.fd.bblocks.add_edge(b2.clone(), b3.clone());

        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);

        let d0 = g.op(OpCode::CPUI_COPY, 1);
        g.set_input(&d0, &c8, 0);
        let _t0 = g.fd.new_unique_out(8, &d0);
        g.insert_end(&d0, &b0);

        let free = g.free_register(0x28, 8);
        let m = g.op(OpCode::CPUI_MULTIEQUAL, 2);
        g.set_input(&m, &free, 0);
        let m_out = g.written_register(0x28, 8, &m);
        let _ = m_out;

        let r = g.op(OpCode::CPUI_INT_ADD, 2);
        let t3 = g.written_register(0x28, 8, &r);
        g.set_input(&r, &m_out, 0);
        g.set_input(&r, &c4, 1);
        g.set_input(&m, &t3, 1);
        g.insert_end(&m, &b1);
        g.insert_end(&r, &b2);

        let o = g.op(OpCode::CPUI_INT_OR, 2);
        g.set_input(&o, &m_out, 0);
        g.set_input(&o, &c4, 1);
        let _t4 = g.fd.new_unique_out(8, &o);
        g.insert_end(&o, &b3);

        g.fd
    }

    // HERITAGE-OWNERSHIP-0001: three consecutive `Funcdata::op_heritage`
    // boundary calls (pass 0->1->2->3) on the same `&mut Funcdata` must
    // complete on a phi self-reference cycle graph. The pre-refactor nominal
    // `Heritage::heritage` re-entered the Funcdata write lock (once via the
    // driver and again inside the guard-calls block), which self-deadlocks;
    // the explicit-ownership pass has no lock to re-enter. The watchdog
    // thread makes a hang fail the test instead of wedging the runner.
    #[test]
    fn test_op_heritage_three_passes_survive_phi_cycle_without_deadlock() {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel::<(i32, i32)>();
        let handle = std::thread::spawn(move || {
            let mut fd = build_phi_cycle_graph("phi_cycle");
            fd.op_heritage();
            let p1 = fd.heritage.pass;
            let md1 = fd.heritage.maxdepth;
            fd.op_heritage();
            fd.op_heritage();
            let _ = tx.send((p1, md1));
            (fd.heritage.pass, fd.heritage.maxdepth)
        });

        let (p1, md1) = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("first op_heritage pass did not complete (deadlock regression)");
        let (pass, maxdepth) = handle
            .join()
            .expect("three op_heritage passes panicked (60s watchdog)");

        // One pass per boundary call: 0 -> 1 -> 2 -> 3.
        assert_eq!(p1, 1);
        assert_eq!(pass, 3);
        // Four-block dominator chain b0 > b1 > b2 > b3 has Ghidra depths
        // 1/2/3/4 (block.cc:2056 root depth 1), built exactly once (the
        // maxdepth == -1 rebuild fired on pass 1 only).
        assert_eq!(md1, 4);
        assert_eq!(maxdepth, 4);
    }

    // CANON-REGJUNK-INRAX-LIVEVAR-0001 + CANON-REGJUNK-XMM-EXTRAOUT-0001:
    // a register read shadowed by a CALL (whose output was attached the way
    // ActionFuncLink::funcLinkOutput attaches locked-proto returns,
    // coreaction.cc:1551) must bind to the CALL's output varnode under the
    // production single-pass heritage — never to a pre-promoted INPUT
    // varnode. The removed inject_raw_ops phase 3 promoted such reads to
    // inputs at inject time (before funclink attaches call outputs), which
    // Heritage::collect then classifies as INPUT (heritage.cc:342-343) and
    // can never rebind — producing `in_RAX` live-variable leaks (ap_field_
    // noparam) and non-collapsible `x^x` forms (ap_fini_vhost_config's
    // `pxor %xmm0,%xmm0`, whose RuleTrivialArith collapse,
    // ruleaction.cc:2362-2380, requires both input slots to be the SAME
    // varnode).
    #[test]
    fn test_call_shadowed_read_binds_to_call_output_under_heritage() {
        let mut g = OwnershipGraph::new("regjunk_callshadow", 0x7000);
        // Production heritage requires the per-space HeritageInfo list,
        // built exactly once by Funcdata::startProcessing
        // (funcdata.cc:166 -> Heritage::buildInfoList) before the first
        // ActionHeritage pass.
        g.fd.start_processing();
        let b0 = g.block(0);
        // CALL with an attached RAX output (the funclink locked-proto form).
        let call = g.op(OpCode::CPUI_CALL, 1);
        let target = g.constant(8, 0x1234);
        g.set_input(&call, &target, 0);
        let call_out = g.written_register(0x0, 8, &call); // RAX
        // The read directly after the call: RBX = COPY RAX
        // (the `mov %rax,%rbx` shape of ap_field_noparam@0x12dd50).
        let copy = g.op(OpCode::CPUI_COPY, 1);
        let free_rax = g.free_register(0x0, 8);
        g.set_input(&copy, &free_rax, 0);
        let _rbx = g.written_register(0x38, 8, &copy);
        g.insert_end(&call, &b0);
        g.insert_end(&copy, &b0);

        // Inject-time invariant: the read stays free — no linear-order
        // input pre-promotion.
        assert!(
            free_rax.read().unwrap().is_free(),
            "call-shadowed read must stay free at inject time"
        );
        assert!(!free_rax.read().unwrap().is_input());

        g.fd.op_heritage();

        // Heritage invariant: the read binds to the CALL's output varnode.
        let bound = copy
            .0
            .read()
            .unwrap()
            .get_in(0)
            .cloned()
            .expect("copy input present");
        assert!(
            Arc::ptr_eq(&bound, &call_out),
            "read after the call must bind to the call output, not an input varnode"
        );
        // And no INPUT varnode was fabricated at RAX by the promotion path
        // (only the entry-block-empty-stack shape may create inputs).
        let rax_input = g.fd.vbank.loc_tree.iter().any(|v| {
            let vn = v.0.read().unwrap();
            vn.is_input()
                && vn.get_space() == AddressSpace::Register
                && vn.get_offset() == 0x0
        });
        assert!(
            !rax_input,
            "heritage must not fabricate an in_RAX input when the call output reaches"
        );
    }

    // HERITAGE-OWNERSHIP-0001: explicit record of the behavioral difference
    // between the old production recipe (two direct place/rename passes with
    // an embedded ActionDeadCode sandwich and stack-store discovery between
    // them — src/coreaction.rs ActionHeritage::apply pre-refactor) and the
    // new canonical single-pass boundary. Ghidra runs ActionDeadCode as a
    // later sibling Action decided by the executor (coreaction.cc:5487-5504),
    // never inside Heritage; the new boundary therefore leaves an unread
    // (dead) write in place while the old recipe removes it. This test pins
    // that difference so the production switch (HERITAGE-DRIVER-SWITCH) must
    // account for DeadCode scheduling explicitly.
    #[test]
    fn test_op_heritage_leaves_deadcode_to_the_action_executor() {
        fn build(base: u64) -> Funcdata {
            let mut g = OwnershipGraph::new("deadcode_split", base);
            let b0 = g.block(0);
            let b1 = g.block(1);
            g.fd.bblocks.add_edge(b0.clone(), b1.clone());
            let c4 = g.constant(4, 7);

            // d1: writes register 0x30 from a free read (heritage work).
            // Per-read free instances: Ghidra's PcodeEmitFd::dump calls
            // newVarnode per input reference (funcdata.cc:905), so the same
            // register read at two pcs is TWO distinct free varnodes
            // (loc-tree frees are distinguished by createIndex,
            // VarnodeCompareLocDef). One free object with 2 readers is
            // Ghidra-unreachable — addDescend would throw "Free varnode has
            // multiple descendants" (varnode.cc:336). Both instances stay
            // free, so heritage still sees the same address-based read work.
            let free = g.free_register(0x30, 8);
            let d1 = g.op(OpCode::CPUI_INT_ADD, 2);
            g.set_input(&d1, &free, 0);
            g.set_input(&d1, &c4, 1);
            let _d1out = g.written_register(0x30, 8, &d1);
            g.insert_end(&d1, &b0);

            // r1: reads its own free instance of register 0x30 in the
            // successor block (independent per-read object, same loc).
            let free_r1 = g.free_register(0x30, 8);
            let r1 = g.op(OpCode::CPUI_INT_OR, 2);
            g.set_input(&r1, &free_r1, 0);
            g.set_input(&r1, &c4, 1);
            let _t3 = g.fd.new_unique_out(8, &r1);
            g.insert_end(&r1, &b1);

            // dead: an unread unique write that only a DeadCode action
            // removes.
            let dead = g.op(OpCode::CPUI_INT_MULT, 2);
            g.set_input(&dead, &c4, 0);
            g.set_input(&dead, &c4, 1);
            let _dead_out = g.fd.new_unique_out(8, &dead);
            g.insert_end(&dead, &b0);

            g.fd
        }

        let count_alive = |fd: &Funcdata| fd.obank.alivelist.len();

        // Old recipe: direct place/rename + embedded DeadCode + discovery +
        // a second direct pass (ActionHeritage::apply pre-refactor shape).
        let mut old_fd = build(0x6100);
        {
            let mut heritage = std::mem::take(&mut old_fd.heritage);
            heritage.place_multiequals_direct(
                &mut old_fd.vbank,
                &mut old_fd.obank,
                &old_fd.bblocks,
                &old_fd.sblocks,
            );
            heritage.rename_direct(&mut old_fd.vbank, &old_fd.bblocks);
            heritage.pass += 1;
            old_fd.heritage = heritage;
        }
        {
            use crate::action::Action;
            let mut dc = crate::coreaction::ActionDeadCode::new();
            let _ = dc.apply(&mut old_fd);
        }
        crate::heritage::Heritage::discover_and_guard_stack_stores_fd(&mut old_fd);
        {
            let mut heritage = std::mem::take(&mut old_fd.heritage);
            heritage.place_multiequals_direct(
                &mut old_fd.vbank,
                &mut old_fd.obank,
                &old_fd.bblocks,
                &old_fd.sblocks,
            );
            heritage.rename_direct(&mut old_fd.vbank, &old_fd.bblocks);
            heritage.pass += 1;
            old_fd.heritage = heritage;
        }

        // New boundary: three canonical single passes, no embedded DeadCode.
        let mut new_fd = build(0x6200);
        new_fd.op_heritage();
        new_fd.op_heritage();
        new_fd.op_heritage();

        // The recorded difference: the old sandwich removes the dead write,
        // the canonical boundary does not (DeadCode belongs to the executor).
        assert!(
            count_alive(&new_fd) > count_alive(&old_fd),
            "expected old embedded-DeadCode recipe to remove more ops than the canonical boundary: old={} new={}",
            count_alive(&old_fd),
            count_alive(&new_fd)
        );
        assert_eq!(new_fd.heritage.pass, 3);
    }

    // HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS: Rust-only regression test for
    // the no-recorded-storage arm — a call spec whose prototype never
    // recorded a proto-store output storage must conservatively return
    // false with an untouched write list so guardCalls keeps the
    // unknown_effect INDIRECT guard (the state is unreachable in Ghidra:
    // isStackOutputLock implies funcLinkOutput read a spacebase outparam
    // address, coreaction.cc:1546-1549). The oracle-verified recorded-
    // storage arm is covered bilaterally by tests/oracle/
    // heritage_tryoutput_1204 (contains projection + the new
    // production_entry_guardcalls case through guard_calls itself).
    #[test]
    fn test_try_output_stack_guard_none_storage_is_conservative_false() {
        use crate::block::BlockBasic;
        use crate::funcdata::Funcdata;

        let mut fd = Funcdata::new("nonestage", Address::new(0x7000), 0x20);
        let block: Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x7000))));
        fd.bblocks.add_block(block.clone());
        let call = fd.new_op(1, Address::new(0x7000));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        let target = fd.new_constant(8, 0x4000);
        fd.op_set_input(&call, target, 0);
        fd.op_insert_end(&call, &block);
        let fc = crate::fspec::FuncCallSpecs::new_for_op(
            &call,
            crate::fspec::FuncProto::new(
                String::new(),
                Arc::new(crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        crate::type_system::datatype::TypeMetatype::Void,
                    ),
                )),
            ),
        );
        let fc_idx = fd.add_call_specs(fc);

        let mut write: Vec<Arc<RwLock<Varnode>>> = Vec::new();
        let guarded = Heritage::new().try_output_stack_guard(
            &mut fd,
            fc_idx,
            AddressSpace::Stack,
            Address::new(0x1010),
            0x1000,
            4,
            crate::fspec::containment::CONTAINS_JUSTIFIED,
            &mut write,
        );

        assert!(!guarded);
        assert!(write.is_empty());
        // The call op is untouched: no output creation, no SUBPIECE.
        assert!(call.0.read().unwrap().output.is_none());
        assert_eq!(block.read().unwrap().get_ops().len(), 1);
    }

    // ---- processJoins regression tests (heritage.cc:2281-2313) ----
    // Rugra-side regression coverage only (mechanism B2: these do NOT
    // upgrade the oracle fixture status of processJoins — the producer
    // side still mints unlinked joins, see HERITAGE-PJOINS-UNLINKED-0001).

    fn pjoins_fixture_fd(
        with_record: bool,
    ) -> (Funcdata, Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>) {
        use crate::block::BlockBasic;
        use crate::space::{JoinDatabase, JoinRecord, VarnodeData};
        let mut arch = crate::arch::Architecture::new();
        if with_record {
            let mut join_db = JoinDatabase::new();
            // Mirror the oracle probe form for an RDX:RAX return pair:
            // pieces most-significant first, unified at join:0 size 16.
            join_db.records.push(JoinRecord {
                pieces: vec![
                    VarnodeData { space: AddressSpace::Register, offset: 0x10, size: 8 },
                    VarnodeData { space: AddressSpace::Register, offset: 0x0, size: 8 },
                ],
                unified: VarnodeData { space: AddressSpace::Join, offset: 0, size: 16 },
            });
            *arch
                .join_db
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = join_db;
        }
        let arch_arc = Arc::new(arch);
        let mut fd = Funcdata::new("pjoins", Address::new(0x5000), 0x20);
        fd.arch = Some(arch_arc);
        let block: Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
        fd.bblocks.add_block(block.clone());
        (fd, block)
    }

    #[test]
    fn test_process_joins_write_split_two_register_pieces() {
        let (mut fd, block) = pjoins_fixture_fd(true);
        // Written join varnode (PIECE output) reading like a return pair.
        let join_vn = fd.vbank.create_with_space(16, AddressSpace::Join, 0);
        let piece_def = fd.new_op(2, Address::new(0x5004));
        fd.op_set_opcode(&piece_def, OpCode::CPUI_PIECE);
        fd.op_set_output(&piece_def, join_vn.clone());
        let hi = fd.new_unique(8);
        let lo = fd.new_unique(8);
        fd.op_set_input(&piece_def, hi, 0);
        fd.op_set_input(&piece_def, lo, 1);
        fd.op_insert_end(&piece_def, &block);

        let mut heritage = Heritage::new();
        // Register-space delay is 0 and Heritage starts at pass 0, so the
        // write split must fire (heritage.cc:2305-2311).
        heritage.process_joins(&mut fd);

        let subpieces: Vec<_> = fd
            .obank
            .iter_alive()
            .filter(|op| op.0.read().unwrap().opcode == OpCode::CPUI_SUBPIECE)
            .cloned()
            .collect();
        assert_eq!(subpieces.len(), 2, "expected SUBPIECE pair");
        for sub in &subpieces {
            let op = sub.0.read().unwrap();
            assert!(
                Arc::ptr_eq(&op.get_in(0).unwrap(), &join_vn),
                "SUBPIECE reads the join varnode"
            );
        }
        // mosthalf SUBPIECE: shift = leasthalf size (8) -> Register:0x10
        // with precis_hi; leasthalf SUBPIECE: shift 0 -> Register:0x0 with
        // precis_lo (heritage.cc:2196-2214).
        let by_shift = |shift: u64| {
            subpieces
                .iter()
                .find(|op| {
                    op.0.read().unwrap().get_in(1).map(|c| {
                        c.read().unwrap().get_offset() == shift
                    }) == Some(true)
                })
                .map(|op| op.0.read().unwrap().output.clone().unwrap())
        };
        let most = by_shift(8).expect("shift-8 SUBPIECE");
        let least = by_shift(0).expect("shift-0 SUBPIECE");
        {
            let m = most.read().unwrap();
            assert_eq!((m.get_space(), m.get_offset(), m.get_size()), (AddressSpace::Register, 0x10, 8));
            assert!(m.is_precis_hi() && !m.is_precis_lo());
        }
        {
            let l = least.read().unwrap();
            assert_eq!((l.get_space(), l.get_offset(), l.get_size()), (AddressSpace::Register, 0x0, 8));
            assert!(l.is_precis_lo() && !l.is_precis_hi());
        }
    }

    #[test]
    fn test_process_joins_delay_guard_skips_write_split() {
        let (mut fd, block) = pjoins_fixture_fd(true);
        let join_vn = fd.vbank.create_with_space(16, AddressSpace::Join, 0);
        let piece_def = fd.new_op(2, Address::new(0x5004));
        fd.op_set_opcode(&piece_def, OpCode::CPUI_PIECE);
        fd.op_set_output(&piece_def, join_vn.clone());
        let hi = fd.new_unique(8);
        let lo = fd.new_unique(8);
        fd.op_set_input(&piece_def, hi, 0);
        fd.op_set_input(&piece_def, lo, 1);
        fd.op_insert_end(&piece_def, &block);

        let mut heritage = Heritage::new();
        heritage.pass = 2; // != register delay 0 -> skip (cc:2305-2306)
        heritage.process_joins(&mut fd);
        let subpieces = fd
            .obank
            .iter_alive()
            .filter(|op| op.0.read().unwrap().opcode == OpCode::CPUI_SUBPIECE)
            .count();
        assert_eq!(subpieces, 0, "pass != delay must skip the write split");
    }

    #[test]
    fn test_process_joins_unlinked_join_skips_without_record() {
        let (mut fd, block) = pjoins_fixture_fd(false);
        let join_vn = fd.vbank.create_with_space(16, AddressSpace::Join, 0);
        let piece_def = fd.new_op(2, Address::new(0x5004));
        fd.op_set_opcode(&piece_def, OpCode::CPUI_PIECE);
        fd.op_set_output(&piece_def, join_vn.clone());
        let hi = fd.new_unique(8);
        let lo = fd.new_unique(8);
        fd.op_set_input(&piece_def, hi, 0);
        fd.op_set_input(&piece_def, lo, 1);
        fd.op_insert_end(&piece_def, &block);

        let mut heritage = Heritage::new();
        // No JoinRecord: the oracle throws "Unlinked join address"
        // (translate.cc:761); the documented degradation skips the
        // varnode instead of aborting the run.
        heritage.process_joins(&mut fd);
        let subpieces = fd
            .obank
            .iter_alive()
            .filter(|op| op.0.read().unwrap().opcode == OpCode::CPUI_SUBPIECE)
            .count();
        assert_eq!(subpieces, 0);
    }

    #[test]
    fn test_process_joins_read_split_free_join_varnode() {
        let (mut fd, block) = pjoins_fixture_fd(true);
        // Free join varnode with a single reader: splitJoinRead builds
        // the PIECE chain defining it (heritage.cc:2119-2163).
        let join_vn = fd.vbank.create_with_space(16, AddressSpace::Join, 0);
        let reader = fd.new_op(1, Address::new(0x5008));
        fd.op_set_opcode(&reader, OpCode::CPUI_RETURN);
        fd.op_set_input(&reader, join_vn.clone(), 0);
        fd.op_insert_end(&reader, &block);

        let mut heritage = Heritage::new();
        heritage.process_joins(&mut fd);

        // Free read split happens before the delay guard, so both the
        // PIECE chain (this test) and later SUBPIECEs (write split, pass
        // 0 == delay) may exist. The join varnode must now be written by
        // a PIECE op.
        assert!(join_vn.read().unwrap().is_written());
        let def = join_vn
            .read()
            .unwrap()
            .def
            .as_ref()
            .and_then(|w| w.upgrade())
            .expect("def after splitJoinRead");
        assert_eq!(def.read().unwrap().opcode, OpCode::CPUI_PIECE);
        let most = def.read().unwrap().get_in(0).cloned().unwrap();
        let least = def.read().unwrap().get_in(1).cloned().unwrap();
        {
            let m = most.read().unwrap();
            assert_eq!((m.get_space(), m.get_offset(), m.get_size()), (AddressSpace::Register, 0x10, 8));
            assert!(m.is_precis_hi());
        }
        {
            let l = least.read().unwrap();
            assert_eq!((l.get_space(), l.get_offset(), l.get_size()), (AddressSpace::Register, 0x0, 8));
            assert!(l.is_precis_lo());
        }
    }
}

/// Flags for Heritage node properties
pub mod heritage_flags {
    pub const BOUNDARY_NODE: u32 = 1 << 0;
    pub const MARK_NODE: u32 = 1 << 1;
    pub const MERGED_NODE: u32 = 1 << 2;
}

/// Node in the SSA renaming stack
/// Corresponds to Ghidra's `Heritage::StackNode`
#[derive(Debug)]
pub struct StackNode {
    pub vn: Arc<RwLock<Varnode>>,
    pub offset: u64,
    pub traversals: u32,
}
