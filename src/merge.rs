//! High-level variable merging logic
//!
//! Corresponds to Ghidra's `merge.hh`. This module is responsible for
//! merging multiple SSA Varnodes into a single HighVariable.

use crate::cover::{Cover, CoverBlock};
use crate::funcdata::Funcdata;
use crate::space::{AddressSpace, SpaceType, SPACEID_OTHER};
use crate::type_system::{Datatype, TypeBase, TypeMetatype};
use crate::variable::{
    high_flags, high_internal_flags, HighVariable, VariableGroup, VariablePiece,
};
use crate::varnode::{Varnode, varnode_flags};
use anyhow::{anyhow, Result};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// One `(space, offset, size)` sub-range from Ghidra's `overlapLoc` bounds.
/// Members retain `VarnodeLocSet` order: input, then written definitions in
/// `SeqNum` order. `head_flags` records ONLY the first member's flags, per
/// `overlapLoc`'s gate accumulation: the initial read at varnode.cc:1798
/// (`flags = vn->getFlags()`) and each later OR at :1813
/// (`flags |= vn->getFlags()`) see only the FIRST varnode of each visited
/// exact-location run (the iterator jumps to `endLoc(size,addr,written)`
/// past every same-location member at :1800/:1815). Later members of the
/// same run never contribute to the gate — instrumented against the locked
/// oracle 12.0.4 (see tests/oracle/merge_overlaploc_1204.*).
#[derive(Debug)]
struct AddrTiedLocRange {
    space: AddressSpace,
    offset: u64,
    size: usize,
    head_flags: u32,
    members: Vec<Arc<RwLock<Varnode>>>,
}

/// Cached pairwise Cover-intersection results used by MergeType.
///
/// The cache is symmetric, exactly like `HighIntersectTest::highedgemap`.
/// MergeType's speculative guards reject address-tied variables before this
/// cache is queried, so for that closure the `StackAffectingOps`
/// call-crossing branch is unreachable — but the cache is shared by every
/// merge-family Action through the persistent mount (attach/detach), and the
/// required/copy merge closures DO query it with one address-tied and one
/// untied high (F-RESIDE: the helpf register-save slot webs vs the RSI
/// chain), so the general Ghidra `intersection` branch
/// (variable.cc:1186-1197) and its `StackAffectingOps` channel are ported
/// here in full (MIRATTR-F-RESIDE-0001).
#[derive(Default, Debug)]
struct MergeTypeIntersectCache {
    tests: BTreeMap<(usize, usize), bool>,
    /// `PcodeOpSet::opList` (cover.hh:38) of the `StackAffectingOps`
    /// channel: CALL ops plus guarded STORE ops, sorted by
    /// (block index, SeqNum order) once populated. Ghidra holds the
    /// `StackAffectingOps` object inside the `Merge` (merge.hh:85) and
    /// `HighIntersectTest` references it (variable.hh:258); the Rust cache
    /// owns it by value because the whole cache round-trips through the
    /// persistent mount at attach/detach, which carries the channel across
    /// Actions exactly like the by-reference C++ member.
    stack_affecting_ops: Vec<crate::op::PcodeOpRef>,
    /// `PcodeOpSet::blockStart` (cover.hh:39): index of the first op of each
    /// non-empty block in `stack_affecting_ops`.
    stack_affecting_block_start: Vec<usize>,
    /// `PcodeOpSet::is_pop` (cover.hh:40): the lazy-populate flag that
    /// `PcodeOpSet::clear` (cover.hh:63) resets.
    stack_affecting_populated: bool,
}

impl MergeTypeIntersectCache {
    // Ghidra: variable.cc:1045 HighIntersectTest::purgeHigh
    fn purge_high(&mut self, high: &Arc<RwLock<HighVariable>>) {
        let key = Arc::as_ptr(high) as usize;
        self.tests.retain(|(a, b), _| *a != key && *b != key);
    }

    // Ghidra: variable.cc:1148 HighIntersectTest::updateHigh
    // Dirty predicate = the oracle's flag protocol as observed at the test
    // gate. varnode.cc:352-361 Varnode::setFlags sets the member Varnode's
    // coverdirty AND synchronously calls high->coverDirty()
    // (variable.hh:275-281, + piece->markExtendCoverDirty). Since the
    // HIGHCOV lane (2026-09-25) the Rust set_flags/add_descend/
    // erase_descend/calc_cover carry that propagation half, so the flag
    // state at this gate matches the oracle.
    //
    // INTERSECTCACHE lane (2026-09-29): the former per-member COVERDIRTY
    // rescan (one RwLock read per instance per call — 6.05M calls / 2.55s
    // on sqlite3VdbeExec, 99.65% of calls finding nothing, and the
    // scan-rescue counter [instance dirty while the high flag is clean]
    // = 0 across 6,048,466 checks on VdbeExec plus all 1385 sqlite-corpus
    // children) was defense-in-depth for a state that is unreachable by
    // construction — the attach-hole audit (2026-09-29):
    //   - every COVERDIRTY SET on a member goes through Varnode::set_flags,
    //     whose coverdirty arm synchronously marks the ATTACHED high
    //     (varnode.cc:352-361 form);
    //   - every attach into a FRESH high is covered by HighVariable::new's
    //     initial dirty word (variable.cc:224 mirror, includes coverdirty);
    //   - every attach into an EXISTING high routes through
    //     HighVariable::merge_internal (dirty-either-side marks the
    //     survivor, variable.cc:660-663 mirror) or the merge.rs
    //     merge_instance_pair sites that set highflags COVERDIRTY directly;
    //   - the member-flag CLEAR arm (update_cover_locked/get_cover) can
    //     only lower the member-dirty predicate, never raise it, so it
    //     cannot re-open the hole.
    // With the hole closed, the flag-only check below is exactly the
    // oracle's updateHigh (variable.cc:1148-1156). The piece-high
    // freshness protocol note is preserved: is_cover_dirty already
    // consults extendcoverdirty (variable.hh:285-289 mirror), and the
    // former scan was already skipped for piece highs (EM2
    // non-convergence, tracked as MERGE-COPYNOISE-SPILLRESTORE-0001-R2).
    fn update_high(&mut self, high: &Arc<RwLock<HighVariable>>) -> bool {
        if !high.read().unwrap().is_cover_dirty() {
            return true;
        }
        // variable.cc:1153-1154: updateCover() then purgeHigh() — the purge
        // is UNCONDITIONAL in the oracle. blockIntersection's verdicts are
        // instance-level (copy-shadow pairs), so a pair result cached from a
        // different instance decomposition can disagree with a recomputation
        // even when the rebuilt union cover is bit-identical; gating the
        // purge on cover-identity (EM2 experiment) let stale cached verdicts
        // survive and produced wrong merges elsewhere (uStack_248/in_RDI
        // noise), so the gate is removed.
        update_high_cover(high);
        self.purge_high(high);
        false
    }

    // Ghidra: variable.cc:947 HighIntersectTest::gatherBlockVarnodes
    fn gather_block_varnodes(
        high: &Arc<RwLock<HighVariable>>,
        block: i32,
        cover: &Cover,
    ) -> Vec<Arc<RwLock<Varnode>>> {
        let instances = high.read().unwrap().instances.clone();
        instances
            .into_iter()
            .filter(|vn| {
                // variable.cc:951: vn->getCover() is the lazy rebuild read
                // (varnode.hh:202 → varnode.cc:233) — rebuild before reading
                // so a mid-pass coverdirty Varnode cannot feed its stale
                // cover into the block filter. No outer guard on vn is held
                // here (the instances Vec is owned), so the write lock taken
                // by update_cover_locked cannot re-enter.
                Varnode::update_cover_locked(vn);
                vn.read()
                    .unwrap()
                    .cover
                    .as_ref()
                    .map(|vn_cover| vn_cover.intersect_by_block(block, cover) > 1)
                    .unwrap_or(false)
            })
            .collect()
    }

    // Ghidra: variable.cc:968 HighIntersectTest::testBlockIntersection
    fn test_block_intersection(
        high: &Arc<RwLock<HighVariable>>,
        block: i32,
        cover: &Cover,
        relative_offset: i32,
        block_list: &[Arc<RwLock<Varnode>>],
    ) -> bool {
        let instances = high.read().unwrap().instances.clone();
        for vn in instances {
            // variable.cc:975: vn->getCover() lazy rebuild read — mirror the
            // oracle's getCover() so the first-stage cover filter sees the
            // same (fresh) cover the oracle filters on. update_high refreshes
            // `a`'s members only when a was dirty; the piece-intersection
            // highs routed here (interPiece->getHigh()) bypass updateHigh
            // entirely, so without this rebuild their instances could filter
            // on stale covers. No outer guard on vn is held (owned Vec).
            Varnode::update_cover_locked(&vn);
            let intersects_cover = vn
                .read()
                .unwrap()
                .cover
                .as_ref()
                .map(|vn_cover| vn_cover.intersect_by_block(block, cover) >= 2)
                .unwrap_or(false);
            if !intersects_cover {
                continue;
            }
            for other in block_list {
                let pair_intersects = {
                    // Borrow both covers instead of cloning: distinct
                    // Varnodes take independent read guards (same-Arc reads
                    // are also fine), and the deep BTreeMap clone per pair
                    // dominated the block-pair loop.
                    let vn_g = vn.read().unwrap();
                    let other_g = other.read().unwrap();
                    match (vn_g.cover.as_ref(), other_g.cover.as_ref()) {
                        (Some(a), Some(b)) => b.intersect_by_block(block, a) > 1,
                        _ => false,
                    }
                };
                if !pair_intersects {
                    continue;
                }
                if Arc::ptr_eq(&vn, other) {
                    continue;
                }
                let shadows = {
                    let vn_guard = vn.read().unwrap();
                    let other_guard = other.read().unwrap();
                    if vn_guard.size == other_guard.size {
                        vn_guard.copy_shadow(&other_guard)
                    } else {
                        vn_guard.partial_copy_shadow(&other_guard, relative_offset)
                    }
                };
                if !shadows {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: variable.cc:998 HighIntersectTest::blockIntersection
    fn block_intersection(
        a: &Arc<RwLock<HighVariable>>,
        b: &Arc<RwLock<HighVariable>>,
        block: i32,
        a_cover: &Cover,
        b_cover: &Cover,
    ) -> bool {
        let mut block_list = Self::gather_block_varnodes(b, block, a_cover);
        if Self::test_block_intersection(a, block, b_cover, 0, &block_list) {
            return true;
        }

        let a_piece = a.read().unwrap().piece.clone();
        if let Some(piece) = a_piece {
            let (base_offset, intersections) = {
                let piece = piece.read().unwrap();
                (piece.group_offset, piece.intersection.clone())
            };
            for intersection in intersections {
                let (offset, intersect_high) = {
                    let piece = intersection.read().unwrap();
                    (
                        piece.group_offset - base_offset,
                        piece.high.as_ref().and_then(|high| high.upgrade()),
                    )
                };
                if let Some(intersect_high) = intersect_high {
                    if Self::test_block_intersection(
                        &intersect_high,
                        block,
                        b_cover,
                        offset,
                        &block_list,
                    ) {
                        return true;
                    }
                }
            }
        }

        let b_piece = b.read().unwrap().piece.clone();
        if let Some(piece) = b_piece {
            let (b_base_offset, b_intersections) = {
                let piece = piece.read().unwrap();
                (piece.group_offset, piece.intersection.clone())
            };
            for b_intersection in b_intersections {
                let (b_offset, b_size, b_high) = {
                    let piece = b_intersection.read().unwrap();
                    (
                        piece.group_offset - b_base_offset,
                        piece.size,
                        piece.high.as_ref().and_then(|high| high.upgrade()),
                    )
                };
                let Some(b_high) = b_high else { continue };
                block_list = Self::gather_block_varnodes(&b_high, block, a_cover);
                if Self::test_block_intersection(a, block, b_cover, -b_offset, &block_list) {
                    return true;
                }
                let a_piece = a.read().unwrap().piece.clone();
                if let Some(a_piece) = a_piece {
                    let (a_base_offset, a_intersections) = {
                        let piece = a_piece.read().unwrap();
                        (piece.group_offset, piece.intersection.clone())
                    };
                    for a_intersection in a_intersections {
                        let (offset, a_size, a_high) = {
                            let piece = a_intersection.read().unwrap();
                            (
                                (piece.group_offset - a_base_offset) - b_offset,
                                piece.size,
                                piece.high.as_ref().and_then(|high| high.upgrade()),
                            )
                        };
                        if offset > 0 && offset >= b_size {
                            continue;
                        }
                        if offset < 0 && -offset >= a_size {
                            continue;
                        }
                        if let Some(a_high) = a_high {
                            if Self::test_block_intersection(
                                &a_high,
                                block,
                                &b_cover,
                                offset,
                                &block_list,
                            ) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    // Ghidra: variable.cc:1091 HighIntersectTest::moveIntersectTests
    fn move_intersect_tests(
        &mut self,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
    ) {
        let high1_key = Arc::as_ptr(high1) as usize;
        let high2_key = Arc::as_ptr(high2) as usize;
        let mut yes_intersect = Vec::new();
        let mut no_intersect = std::collections::HashSet::new();
        for ((a, b), intersects) in &self.tests {
            if *a != high2_key || *b == high1_key {
                continue;
            }
            if *intersects {
                yes_intersect.push(*b);
            } else {
                no_intersect.insert(*b);
            }
        }
        self.tests
            .retain(|(a, b), _| *a != high2_key && *b != high2_key);

        let stale_false: Vec<usize> = self
            .tests
            .iter()
            .filter_map(|((a, b), intersects)| {
                (*a == high1_key && !*intersects && !no_intersect.contains(b)).then_some(*b)
            })
            .collect();
        for other in stale_false {
            self.tests.remove(&(high1_key, other));
            self.tests.remove(&(other, high1_key));
        }
        for other in yes_intersect {
            self.tests.insert((high1_key, other), true);
            self.tests.insert((other, high1_key), true);
        }
    }

    // Ghidra: variable.hh:294 HighVariable::getCover (borrowed-read form)
    // — see the with_high_cover doc at module scope for the borrow/lock
    // analysis. (INTERSECTCACHE lane 2026-09-29.)
    fn with_high_cover_borrowed<T>(
        high: &Arc<RwLock<HighVariable>>,
        f: impl FnOnce(&Cover) -> T,
    ) -> T {
        with_high_cover(high, f)
    }

    // Ghidra: variable.cc:1166 HighIntersectTest::intersection
    fn intersection(
        &mut self,
        fd: &Funcdata,
        a: &Arc<RwLock<HighVariable>>,
        b: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if Arc::ptr_eq(a, b) {
            return false;
        }
        let a_clean = self.update_high(a);
        let b_clean = self.update_high(b);
        let a_key = Arc::as_ptr(a) as usize;
        let b_key = Arc::as_ptr(b) as usize;
        if a_clean && b_clean {
            if let Some(result) = self.tests.get(&(a_key, b_key)) {
                return *result;
            }
        }

        let mut result = false;
        Self::with_high_cover_borrowed(a, |a_cover| {
            Self::with_high_cover_borrowed(b, |b_cover| {
                for block in a_cover.intersect_list(b_cover, 2) {
                    if Self::block_intersection(a, b, block, a_cover, b_cover) {
                        result = true;
                        break;
                    }
                }
            })
        });
        // variable.cc:1186-1197: with no Cover-block intersection, if one
        // variable is address tied and the other isn't, the untied variable
        // must not cross any call that might affect the tied storage —
        // `testUntiedCallIntersection` decides via the StackAffectingOps set.
        if !result {
            let (a_tied, b_tied) = {
                // variable.hh:199 isAddrTied lazily re-derives flags
                // (updateFlags); the Rust accessors are raw, so refresh first.
                a.write().unwrap().update_flags();
                b.write().unwrap().update_flags();
                (a.read().unwrap().is_addr_tied(), b.read().unwrap().is_addr_tied())
            };
            if a_tied != b_tied {
                result = if a_tied {
                    self.test_untied_call_intersection(fd, a, b)
                } else {
                    self.test_untied_call_intersection(fd, b, a)
                };
            }
        }
        self.tests.insert((a_key, b_key), result);
        self.tests.insert((b_key, a_key), result);
        result
    }

    // Ghidra: variable.cc:1072 HighIntersectTest::testUntiedCallIntersection
    /// Test if the untied variable crosses any call that might affect the
    /// tied variable's storage. Faithful to `testUntiedCallIntersection`
    /// (variable.cc:1072-1083): globals (persist) need no test; a local
    /// with no possible aliases is only in scope where written; otherwise
    /// the untied cover is intersected with the lazily populated
    /// StackAffectingOps set (CALL ops + guarded STOREs).
    fn test_untied_call_intersection(
        &mut self,
        fd: &Funcdata,
        tied: &Arc<RwLock<HighVariable>>,
        untied: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        // variable.cc:1075: if (tied->isPersist()) return false;
        {
            let mut t = tied.write().unwrap();
            t.update_flags();
            if t.is_persist() {
                return false;
            }
        }
        // variable.cc:1077-1078: a local variable is only in scope if it
        // has aliases.
        let tied_vn = tied.read().unwrap().get_tied_varnode();
        let Some(tied_vn) = tied_vn else {
            return false;
        };
        if tied_vn.read().unwrap().has_no_local_alias() {
            return false;
        }
        // variable.cc:1079-1080: lazy populate of the affecting-op set.
        if !self.stack_affecting_populated {
            self.populate_stack_affecting(fd);
        }
        // variable.cc:1081: untied->getCover().intersect(affectingOps, vn)
        let untied_cover = high_cover(untied);
        let rep = tied_vn.read().unwrap();
        cover_intersects_op_set(self, fd, &untied_cover, &rep)
    }

    // Ghidra: merge.cc:63 StackAffectingOps::populate
    /// Populate the CALL + guarded-STORE op set. Faithful to
    /// `StackAffectingOps::populate` (merge.cc:63-76): every CALL op from
    /// the call specs, plus the STORE ops with a valid store guard, then
    /// `PcodeOpSet::finalize` (cover.cc:627-640) sorts by (block index,
    /// SeqNum order) and records the per-block start indices.
    fn populate_stack_affecting(&mut self, fd: &Funcdata) {
        use crate::opcodes::OpCode;
        for i in 0..fd.num_calls() {
            if let Some(fc) = fd.get_call_specs(i) {
                if let Some(op) = fc.op.upgrade() {
                    self.stack_affecting_ops.push(crate::op::PcodeOpRef(op));
                }
            }
        }
        for guard in &fd.heritage.store_guard {
            // heritage.hh:169 LoadGuard::isValid:
            // `!op->isDead() && op->code() == opc`.
            if let Some(op) = guard.get_op() {
                let live_store = {
                    let o = op.read().unwrap();
                    !o.is_dead() && o.opcode == OpCode::CPUI_STORE
                };
                if live_store {
                    self.stack_affecting_ops.push(crate::op::PcodeOpRef(op));
                }
            }
        }
        // Ghidra: cover.cc:627 PcodeOpSet::finalize
        self.stack_affecting_ops
            .sort_by(|a, b| Self::compare_by_block(a, b));
        self.stack_affecting_block_start.clear();
        let mut block_num: i64 = -1;
        for (i, op) in self.stack_affecting_ops.iter().enumerate() {
            let new_block_num = op
                .0
                .read()
                .unwrap()
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.read().unwrap().get_index() as i64)
                .unwrap_or(-1);
            if new_block_num > block_num {
                self.stack_affecting_block_start.push(i);
                block_num = new_block_num;
            }
        }
        self.stack_affecting_populated = true;
    }

    // Ghidra: cover.cc:646 PcodeOpSet::compareByBlock
    /// Order ops by parent block index, then SeqNum order. Faithful to
    /// `PcodeOpSet::compareByBlock` (cover.cc:646-652).
    fn compare_by_block(
        a: &crate::op::PcodeOpRef,
        b: &crate::op::PcodeOpRef,
    ) -> std::cmp::Ordering {
        let (a_block, a_order, b_block, b_order) = {
            let ao = a.0.read().unwrap();
            let bo = b.0.read().unwrap();
            let ab = ao
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.read().unwrap().get_index());
            let bb = bo
                .parent
                .as_ref()
                .and_then(|w| w.upgrade())
                .map(|p| p.read().unwrap().get_index());
            (ab, ao.get_seq_num().get_order(), bb, bo.get_seq_num().get_order())
        };
        // Ghidra compares the parent POINTERS first (same block object),
        // which is block identity; index equality is the same identity for
        // live ops. None (no parent) orders first by index sentinel -1.
        let a_idx = a_block.unwrap_or(-1);
        let b_idx = b_block.unwrap_or(-1);
        a_idx.cmp(&b_idx).then(a_order.cmp(&b_order))
    }

    // Ghidra: merge.cc:78 StackAffectingOps::affectsTest
    /// Secondary test after a Cover/op-set intersection is established.
    /// Faithful to `StackAffectingOps::affectsTest` (merge.cc:78-86): a
    /// STORE with no guard record affects everything; a guarded STORE only
    /// affects addresses within its guard range; CALL ops always affect.
    fn stack_affecting_test(
        &self,
        fd: &Funcdata,
        op: &crate::op::PcodeOpRef,
        rep: &Varnode,
    ) -> bool {
        use crate::opcodes::OpCode;
        if op.0.read().unwrap().opcode == OpCode::CPUI_STORE {
            match fd.heritage.get_store_guard(&op.0) {
                None => true,
                Some(guard) => guard.is_guarded(&rep.address_space, rep.get_offset()),
            }
        } else {
            // merge.cc:84: "We could conceivably do secondary testing of
            // CALL ops here" — the oracle returns true unconditionally.
            true
        }
    }

    // Ghidra: variable.hh:270 HighIntersectTest::clear
    fn clear(&mut self) {
        self.tests.clear();
    }

    // Ghidra: cover.hh:63 PcodeOpSet::clear
    /// Clear the StackAffectingOps channel: `is_pop = false`,
    /// `opList.clear()`, `blockStart.clear()` (cover.hh:63 expands
    /// `PcodeOpSet::clear` exactly so). Invoked by `Merge::clear`
    /// (merge.cc:1582 `stackAffectingOps.clear()`).
    fn clear_stack_affecting(&mut self) {
        self.stack_affecting_populated = false;
        self.stack_affecting_ops.clear();
        self.stack_affecting_block_start.clear();
    }
}

// Ghidra: cover.cc:342 Cover::intersect(const PcodeOpSet&, Varnode*)
/// Intersect a Cover with a populated PcodeOpSet. Faithful to
/// `Cover::intersect(const PcodeOpSet &opSet, Varnode *rep)`
/// (cover.cc:342-382): a merge-walk over the cover's blocks and the set's
/// block-starts; in a common block, an op strictly inside the covered
/// range (`contain` but not on the `boundary`) that passes the set's
/// `affectsTest` secondary test prevents the merge. Implemented as a free
/// function on the cache's channel because the Rust `Cover` (cover.rs) is
/// a plain value type and the walk needs the cache's op-set state.
fn cover_intersects_op_set(
    cache: &MergeTypeIntersectCache,
    fd: &Funcdata,
    cover: &Cover,
    rep: &Varnode,
) -> bool {
    let ops = &cache.stack_affecting_ops;
    let block_start = &cache.stack_affecting_block_start;
    if ops.is_empty() {
        return false;
    }
    let op_block = |op: &crate::op::PcodeOpRef| -> i32 {
        op.0
            .read()
            .unwrap()
            .parent
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(|p| p.read().unwrap().get_index())
            .unwrap_or(-1)
    };
    // cover.cc:344-347: setBlock/opIndex/setIndex seed from the first op.
    let mut set_block: usize = 0;
    let mut op_index = block_start[set_block];
    let mut set_index = op_block(&ops[op_index]);
    // cover.cc:348: cover.lower_bound(opSet.opList[0] block) — BTreeMap
    // keys are sorted, so the lower bound is the first key >= the seed.
    let first_set_index = op_block(&ops[0]);
    let mut cover_iter = cover
        .blocks
        .iter()
        .skip_while(|(&k, _)| k < first_set_index)
        .peekable();
    loop {
        // cover.cc:348-357: the cover iterator advances ONLY in the `<`
        // and `==` arms; the `>` arm advances the set side and re-tests the
        // same cover block (C++ does not touch coverIter there).
        let Some((&cover_index, cover_block)) = cover_iter.peek().copied() else {
            break;
        };
        if cover_index < set_index {
            // cover.cc:349-350: cover block below the set block — advance
            // the cover iterator only.
            cover_iter.next();
            continue;
        } else if cover_index > set_index {
            // cover.cc:351-356: advance the set block only; the same cover
            // block is re-tested against the new set block.
            set_block += 1;
            if set_block >= block_start.len() {
                break;
            }
            op_index = block_start[set_block];
            set_index = op_block(&ops[op_index]);
            continue;
        }
        // cover.cc:358-388: common block — scan the set's ops of this block
        // against the covered range; the cover iterator advances past this
        // block (post-increment at cover.cc:359).
        cover_iter.next();
        let mut op_max = ops.len();
        set_block += 1;
        if set_block < block_start.len() {
            op_max = block_start[set_block];
        }
        while op_index < op_max {
            let op = &ops[op_index];
            // cover.cc:369-376: contain(op) via getUIndex, boundary(op)==0,
            // then the secondary affectsTest.
            let point = crate::cover::CoverBlock::get_u_index(&op.0.read().unwrap());
            if cover_block.contain(point) && cover_block.boundary(point) == 0 {
                if cache.stack_affecting_test(fd, op, rep) {
                    return true;
                }
            }
            op_index += 1;
        }
        if set_block >= block_start.len() {
            break;
        }
    }
    false
}

// Ghidra: merge.cc:1001 mergeAdjacent local-type gate
/// Factory-canonical identity key for an op-local type. Ghidra's gate
/// compares `Datatype*` objects returned by `TypeOp::getOutputLocal` /
/// `getInputLocal` (op.hh:251-252), which are TypeFactory-canonical:
/// two such pointers are equal iff they are the same factory entry.
/// The entries reachable here are `getBase(size, metatype)`,
/// `getBaseNoChar(size, metatype)` (the same canonical entry as the plain
/// base at the same metatype+size, except for the registered 1-byte int,
/// type.cc:3619-3626), and `getTypeCode()`; `getTypePointer`
/// (CBRANCH slot 0) is unreachable because branch ops have no output for
/// mergeAdjacent to walk.
#[derive(Clone, Copy, Debug)]
enum LocalTypeKey {
    /// `TypeFactory::getBase(size, metatype)`.
    Base(TypeMetatype, usize),
    /// `TypeFactory::getBaseNoChar(size, metatype)` — returns the SAME
    /// canonical entry as the plain base except for the single
    /// `(size==1, TYPE_INT, type_nochar registered)` case (type.cc:3619-
    /// 3626); see `local_type_key_eq` below. Shift-amount slots
    /// (typeop.cc:1510-1516/1535-1541/1600-1606).
    BaseNoChar(TypeMetatype, usize),
    /// `TypeFactory::getTypeCode()` (INDIRECT slot 1, typeop.cc:1992-1998).
    TypeCode,
}

// Ghidra: type.cc:3619-3626 TypeFactory::getBaseNoChar
/// Canonical-pointer equality between two local-type keys, exactly as the
/// `ct != op->inputTypeLocal(i)` Datatype-pointer comparison
/// (merge.cc:1001) observes it. `getBaseNoChar(s, m)` returns the
/// distinguished `type_nochar` entry ONLY for `(s==1, TYPE_INT,
/// type_nochar registered)` (type.cc:3622-3623) and `getBase(s, m)`
/// otherwise — the very same pointer — so a `BaseNoChar` key equals the
/// plain `Base` at the same (metatype, size) except at the registered
/// 1-byte int. Whether the factory distinguishes that pair is
/// architecture state (the registered core-type set filled by
/// `TypeFactory::cacheCoreTypes`, type.cc:3200-3248), resolved per
/// mergeAdjacent walk by `factory_nochar_distinct` below.
fn local_type_key_eq(a: &LocalTypeKey, b: &LocalTypeKey, nochar_distinct: bool) -> bool {
    use TypeMetatype::Int;
    match (a, b) {
        (LocalTypeKey::BaseNoChar(m1, s1), LocalTypeKey::Base(m2, s2))
        | (LocalTypeKey::Base(m2, s2), LocalTypeKey::BaseNoChar(m1, s1)) => {
            *m1 == *m2 && *s1 == *s2 && !(*s1 == 1 && *m1 == Int && nochar_distinct)
        }
        (LocalTypeKey::Base(m1, s1), LocalTypeKey::Base(m2, s2))
        | (LocalTypeKey::BaseNoChar(m1, s1), LocalTypeKey::BaseNoChar(m2, s2)) => {
            *m1 == *m2 && *s1 == *s2
        }
        _ => false,
    }
}

// Ghidra: funcdata.hh:96 Funcdata::covermerge (member declaration)
/// Persistent cross-Action merge state, mounted as a `Funcdata` member.
///
/// Ghidra holds the whole `Merge` object as a by-value `Funcdata` member
/// (`Merge covermerge`, funcdata.hh:96), constructed with the Funcdata
/// (funcdata.cc:39 `covermerge(*this)`) and shared by every merge-family
/// Action through `data.getMerge()` (funcdata.hh:440), so its channels
/// survive from one Action to the next until `Funcdata::clear()`
/// (funcdata.cc:108 `covermerge.clear()`). The persistent channels are
/// exactly (merge.hh:83-88):
///   - `HighIntersectTest testCache` — cached pairwise HighVariable Cover
///     intersection results (variable.hh:257-271). A result computed by one
///     merge Action is reused by every later Action until the pair is purged
///     for a cover-dirty high (variable.cc:1148-1156) or `Merge::clear` runs.
///   - `vector<PcodeOp *> copyTrims` — COPY trims inserted by forced merges
///     (ActionMergeRequired, merge.cc:411-434) and consumed later by
///     ActionDominantCopy's `processCopyTrims` (coreaction.hh:1008).
///   - `vector<PcodeOp *> protoPartial` — no Rudra counterpart yet
///     (`Merge::group_partials` is a documented no-op).
///   - `StackAffectingOps stackAffectingOps` — ported inside the shared
///     `MergeTypeIntersectCache` (MIRATTR-F-RESIDE-0001): the CALL +
///     guarded-STORE op set lazily populated by
///     `HighIntersectTest::testUntiedCallIntersection`
///     (variable.cc:1080-1081) and consumed by the addrtied-vs-untied
///     branch of `HighIntersectTest::intersection` (variable.cc:1186-1197);
///     it rides the cache because the whole cache round-trips through this
///     mount at attach/detach, matching the C++ by-reference member's
///     cross-Action lifetime.
///
/// Rudra's merge Actions each construct a local `Merge::new()`
/// (coreaction.rs applies), so the persistent channels round-trip through
/// this mount at every Action-facing entry point (`Merge::attach`/
/// `Merge::detach`). `live_set` is RUDRA-GLUE: the premise channel standing
/// in for Ghidra's "iterate the live vbank" — Ghidra's vbank only retains
/// live varnodes, while Rudra's bank keeps dead leftovers, so the live
/// premise is captured once (at the first merge Action) and shared.
#[derive(Default, Debug)]
pub struct MergePersistentState {
    /// Cached pairwise Cover-intersection results shared across merge
    /// Actions (Ghidra merge.hh:86 `testCache`).
    test_cache: MergeTypeIntersectCache,
    /// COPY ops inserted to facilitate forced merges; consumed by
    /// `process_copy_trims` in a later Action (Ghidra merge.hh:87).
    copy_trims: Vec<crate::op::PcodeOpRef>,
    /// RUDRA-GLUE live-varnode premise (Ghidra premise = vbank contents).
    live_set: std::collections::HashSet<usize>,
    /// Roots of unmapped CONCAT trees (Ghidra merge.hh:88 `protoPartial`).
    /// Populated by `Merge::groupPartials` (merge.cc) and consumed by the
    /// proto-partial grouping pass; Rudra's `group_partials` is a documented
    /// no-op (MERGE-PROTOPARTIAL-GROUP-0001), so this channel is currently
    /// only deposited/observed by the clear-lifecycle fixture. `Merge::clear`
    /// (merge.cc:1582) empties it regardless.
    proto_partial: Vec<crate::op::PcodeOpRef>,
}

impl MergePersistentState {
    // Ghidra: merge.cc:1580 Merge::clear
    /// Clear cached intersection tests, pending COPY trims and the live
    /// premise. Faithful to `Merge::clear` (merge.cc:1580-1587), invoked by
    /// `Funcdata::clear` (funcdata.cc:108): the four Ghidra channels are
    /// testCache.clear() + copyTrims.clear() + protoPartial.clear() +
    /// stackAffectingOps.clear() (cover.hh:63 expands it to
    /// is_pop=false/opList.clear()/blockStart.clear()); live_set is the
    /// RUDRA-GLUE premise channel and dies with the same call.
    pub fn clear(&mut self) {
        self.test_cache.clear();
        // merge.cc:1582 stackAffectingOps.clear() -> cover.hh:63
        // PcodeOpSet::clear (is_pop=false, opList, blockStart).
        self.test_cache.clear_stack_affecting();
        self.copy_trims.clear();
        self.live_set.clear();
        self.proto_partial.clear();
    }

    // Ghidra: merge.cc:1549 Merge::registerProtoPartialRoot
    /// Register an unmapped CONCAT stack with the merge process. Faithful
    /// to `Merge::registerProtoPartialRoot` (merge.cc:1549-1553): the root
    /// Varnode's defining op (the final PIECE of the stack) is pushed onto
    /// the `protoPartial` list; `groupPartials` (merge.cc:967-976) later
    /// groups each still-alive partial root into a single variable. The
    /// Funcdata-mounted channel stands in for Ghidra's Funcdata-owned
    /// `Merge` object (rules register during the cleanup pool, long before
    /// any merge-family Action constructs its local `Merge`).
    pub fn register_proto_partial_root(&mut self, vn: &Arc<RwLock<crate::varnode::Varnode>>) {
        if let Some(def) = vn.read().unwrap().get_def() {
            self.proto_partial.push(crate::op::PcodeOpRef(def));
        }
    }

    // RUDRA-GLUE: fixture observability for the persistent channels; the
    // locked Ghidra fixture reads the same members via #define private public.
    /// Return (test_cache entries, pending copy_trims, live_set size).
    pub fn channel_sizes(&self) -> (usize, usize, usize) {
        (
            self.test_cache.tests.len(),
            self.copy_trims.len(),
            self.live_set.len(),
        )
    }

    // RUDRA-GLUE: fixture observability for the two channels whose production
    // population paths are not ported yet (group_partials no-op,
    // StackAffectingOps::populate unported). The clear-lifecycle fixture
    // deposits state here the way an earlier merge Action would, so the
    // bilateral oracle can observe `Merge::clear` emptying them.
    /// Return (proto_partial roots, stack_affecting_ops count, is_populated).
    pub fn channel_sizes_extended(&self) -> (usize, usize, bool) {
        (
            self.proto_partial.len(),
            self.test_cache.stack_affecting_ops.len(),
            self.test_cache.stack_affecting_populated,
        )
    }

    // RUDRA-GLUE: fixture deposit hooks (same premise as channel_sizes: the
    // locked C++ fixture writes the private members directly).
    /// Deposit `count` synthetic testCache entries.
    pub fn fixture_deposit_test_cache(&mut self, count: usize) {
        for i in 0..count {
            let key = 0x9000_0000_0000_0000usize + i;
            self.test_cache.tests.insert((key, key + 1), true);
        }
    }

    // RUDRA-GLUE: fixture deposit hook (same premise as channel_sizes: the
    // locked C++ fixture writes the private members directly).
    /// Deposit COPY-trim / proto-partial-root / stack-affecting ops.
    pub fn fixture_deposit_channels(
        &mut self,
        trims: Vec<crate::op::PcodeOpRef>,
        proto_roots: Vec<crate::op::PcodeOpRef>,
        stack_ops: Vec<crate::op::PcodeOpRef>,
    ) {
        self.copy_trims.extend(trims);
        self.proto_partial.extend(proto_roots);
        self.test_cache.stack_affecting_ops.extend(stack_ops);
        self.test_cache.stack_affecting_populated = true;
    }
}

// RUDRA-GLUE: borrowed-read of a high's cover (closure form of
// variable.hh:294 HighVariable::getCover for the intersection compute
// path, INTERSECTCACHE lane 2026-09-29). The oracle's `a->getCover()`
// (variable.cc:1181) hands out a const reference; the former by-value
// `high_cover` clone copied the whole `blocks` BTreeMap (35.2M CoverBlock
// nodes across 74,337 computes on sqlite3VdbeExec, ~0.37s). The helper
// holds exactly one read lock for the duration of `f` — the HighVariable's
// for plain highs, the piece's for piece-owning highs (same source the
// clone read) — with the same snapshot semantics: nothing inside the
// compute loop can mutate either cover (member rebuilds under gather/test
// touch Varnode covers only; internalCover/piece-cover writes happen in
// update_high_cover/merge paths, none of which run under this scope).
//
// Lock discipline (single-threaded-per-Funcdata pipeline, the standing
// precondition of update_cover_locked's NOTE): holding these read guards
// across block_intersection re-acquires a/b/piece READ locks (read-read
// reentrancy on the same thread, no writer can be queued) and Varnode
// WRITE locks in gather/test_block_intersection — disjoint locks, and no
// path from update_cover_locked back to any high/piece lock exists (that
// absence is precisely the documented lock-blocked clear-arm gap). The
// write locks of intersection's tied branch (update_flags/set_flags) run
// strictly after both closures return and the guards drop.
fn with_high_cover<T>(
    high: &Arc<RwLock<HighVariable>>,
    f: impl FnOnce(&Cover) -> T,
) -> T {
    let piece = high.read().unwrap().piece.clone();
    match piece {
        Some(piece) => {
            let guard = piece.read().unwrap();
            f(&guard.cover)
        }
        None => {
            let guard = high.read().unwrap();
            f(&guard.cover)
        }
    }
}

// Ghidra: variable.hh:294 HighVariable::getCover
/// Raw stored-cover read — the oracle getCover inline returns internalCover
/// with NO lazy update (variable.hh:294-300); its freshness contract is the
/// mutation-time propagation invariant (varnode.cc:352-360 setFlags →
/// high->coverDirty), which the Rust mutation half now carries (HIGHCOV
/// lane 2026-09-25: set_flags/add_descend/erase_descend/calc_cover), with
/// one lock-blocked leg remaining (update_cover_locked's clearFlags half —
/// see the NOTE in varnode.rs). Every raw reader of this helper MUST
/// therefore sit behind a refresh gate, mirroring the oracle's call
/// discipline:
///   - intersection() reads only after update_high on both operands
///     (variable.cc:1170-1181 ordering);
///   - compare_high_by_block is invoked only from merge_linear, which
///     refreshes every high via update_high before the sort
///     (merge.cc:280-282 ordering).
/// Do NOT add new readers of this helper outside that discipline
/// (MERGE-HIGHCOVER-PROPAGATION-0001).
fn high_cover(high: &Arc<RwLock<HighVariable>>) -> Cover {
    let piece = high.read().unwrap().piece.clone();
    if let Some(piece) = piece {
        return piece.read().unwrap().cover.clone();
    }
    high.read().unwrap().cover.clone()
}

// Ghidra: variable.cc:338 HighVariable::updateCover
/// Re-derive the high's cover. The oracle's `updateCover` routes plain highs
/// to `updateInternalCover` (variable.cc:324), whose member reads go through
/// `inst[i]->getCover()` (varnode.hh:202) — the LAZY per-member rebuild —
/// before merging; the member-rebuild leg is done explicitly here because
/// Rudra's `update_internal_cover` (variable.rs) reads the raw `cover` field.
/// Piece-owning highs route to the piece machinery (variable.cc:342-346);
/// the intersecting-high instance rebuild is a Rudra-side freshness
/// compensation for the piece walk (documented 2026-08-15,
/// COVER-REBUILD-SELFLOCK-0001) kept from the parent shape.
fn update_high_cover(high: &Arc<RwLock<HighVariable>>) {
    let instances = high.read().unwrap().instances.clone();
    for instance in instances {
        Varnode::update_cover_locked(&instance);
    }
    let piece = high.read().unwrap().piece.clone();
    let Some(piece) = piece else {
        high.write().unwrap().update_internal_cover();
        return;
    };

    crate::variable::VariablePiece::update_intersections(&piece);
    let intersecting_highs: Vec<Arc<RwLock<HighVariable>>> = piece
        .read()
        .unwrap()
        .intersection
        .iter()
        .filter_map(|intersection| {
            intersection
                .read()
                .unwrap()
                .high
                .as_ref()
                .and_then(|high| high.upgrade())
        })
        .collect();
    for intersecting_high in intersecting_highs {
        let instances = intersecting_high.read().unwrap().instances.clone();
        for instance in instances {
            Varnode::update_cover_locked(&instance);
        }
    }
    let mut owner = high.write().unwrap();
    crate::variable::VariablePiece::update_cover_read(&piece, &mut owner);
}

// Ghidra: merge.hh:152 Merge::compareHighByBlock
fn compare_high_by_block(
    a: &Arc<RwLock<HighVariable>>,
    b: &Arc<RwLock<HighVariable>>,
) -> Ordering {
    match high_cover(a).compare_to(&high_cover(b)) {
        result if result < 0 => return Ordering::Less,
        result if result > 0 => return Ordering::Greater,
        _ => {}
    }
    let instances = (
        a.read().unwrap().instances.first().cloned(),
        b.read().unwrap().instances.first().cloned(),
    );
    let (a_instance, b_instance) = match instances {
        (Some(a_instance), Some(b_instance)) => (a_instance, b_instance),
        (Some(_), None) => return Ordering::Less,
        (None, Some(_)) => return Ordering::Greater,
        (None, None) => return Ordering::Equal,
    };
    let (a_address, a_def) = {
        let instance = a_instance.read().unwrap();
        (
            (instance.address_space.space_id(), instance.loc),
            instance.get_def(),
        )
    };
    let (b_address, b_def) = {
        let instance = b_instance.read().unwrap();
        (
            (instance.address_space.space_id(), instance.loc),
            instance.get_def(),
        )
    };
    if a_address != b_address {
        return a_address.cmp(&b_address);
    }
    match (a_def, b_def) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a_def), Some(b_def)) => {
            let a_address = a_def.read().unwrap().get_addr();
            let b_address = b_def.read().unwrap().get_addr();
            a_address.cmp(&b_address)
        }
    }
}

/// Manages the process of merging Varnodes into HighVariables
///
/// Corresponds to Ghidra's `Merge` class. Groups SSA varnodes that
/// represent the same logical variable into `HighVariable` instances,
/// then assigns human-readable names to each group.
pub struct Merge {
    /// Counter for auto-naming unique/register variables
    var_counter: u32,
    /// Set of varnode Arc pointers that are still referenced by an alive op.
    /// Shared across merge Actions via the `Funcdata::merge_state` mount;
    /// captured at the first merge Action of a decompilation run and
    /// consulted by every loc_tree traversal so dead copy-prop/dead-code
    /// leftovers are excluded from HighVariables.
    live_set: std::collections::HashSet<usize>,
    /// COPY ops inserted to facilitate forced merges (snip trims).
    /// Faithful to Ghidra `Merge::copyTrims` (merge.hh:87). Populated by
    /// `snip_reads` (via `unify_address`→`eliminate_intersect`) during the
    /// forced-merge path. Consumed by `process_copy_trims`.
    copy_trims: Vec<crate::op::PcodeOpRef>,
    /// Pairwise Cover cache used by the same-type speculative merge pass.
    type_test_cache: MergeTypeIntersectCache,
    /// RUDRA-GLUE: nesting depth of `attach` on the current call stack.
    /// Only the outermost 0→1 transition takes the channels from the
    /// `Funcdata::merge_state` mount and only the 1→0 transition writes
    /// them back, so nested entry points (merge_all → merge_marker → …)
    /// are pure no-ops — exactly mirroring the single persistent Ghidra
    /// object (funcdata.hh:96) whose channels are always resident and can
    /// never be moved out from under an in-flight outer sequence.
    attach_depth: u32,
}

impl Merge {
    // Ghidra: merge.hh:83 Merge::new
    /// Create a new Merge instance
    pub fn new() -> Self {
        Self {
            var_counter: 0,
            live_set: std::collections::HashSet::new(),
            copy_trims: Vec::new(),
            type_test_cache: MergeTypeIntersectCache::default(),
            attach_depth: 0,
        }
    }

    // Ghidra: funcdata.hh:440 Funcdata::getMerge
    /// Attach the cross-Action persistent channels from the Funcdata mount.
    ///
    /// Ghidra's merge-family Actions all operate on the one persistent
    /// `Funcdata::covermerge` object via `data.getMerge()`
    /// (coreaction.hh:370/381/392/403/415/1008/1019), so `testCache`,
    /// `copyTrims` and the cover premises computed by an earlier Action are
    /// visible to every later Action. Rudra's merge Actions construct local
    /// `Merge::new()` instances, so each Action-facing entry point attaches
    /// at entry and detaches at exit, round-tripping the same channels
    /// through `Funcdata::merge_state`. Depth-counted: an inner attach while
    /// an outer sequence is in flight is a no-op (the channels are already
    /// resident on this instance), and the matching inner detach likewise
    /// only decrements. The live premise is captured on the outermost first
    /// use (Ghidra's premise is the live vbank itself).
    fn attach(&mut self, fd: &mut Funcdata) {
        if self.attach_depth > 0 {
            self.attach_depth += 1;
            return;
        }
        self.attach_depth = 1;
        self.type_test_cache = std::mem::take(&mut fd.merge_state.test_cache);
        self.copy_trims = std::mem::take(&mut fd.merge_state.copy_trims);
        self.live_set = std::mem::take(&mut fd.merge_state.live_set);
        if self.live_set.is_empty() {
            self.live_set = Self::live_varnode_set(fd);
        }
    }

    // Ghidra: funcdata.hh:440 Funcdata::getMerge
    /// Detach the cross-Action persistent channels back into the Funcdata
    /// mount, so the next merge Action observes the state this one produced.
    /// Depth-counted dual of `attach`: only the outermost detach writes the
    /// channels back; inner detaches are no-ops so an in-flight outer
    /// sequence (e.g. merge_all between merge_addr_tied and
    /// compute_varnode_covers) never loses the premise mid-run.
    fn detach(&mut self, fd: &mut Funcdata) {
        if self.attach_depth == 0 {
            return;
        }
        self.attach_depth -= 1;
        if self.attach_depth > 0 {
            return;
        }
        fd.merge_state.test_cache = std::mem::take(&mut self.type_test_cache);
        fd.merge_state.copy_trims = std::mem::take(&mut self.copy_trims);
        fd.merge_state.live_set = std::mem::take(&mut self.live_set);
    }

    // Ghidra: merge.cc:1580 Merge::clear
    /// Clear all existing HighVariables and reset merge state
    pub fn clear(&mut self, fd: &mut Funcdata) {
        for vn_ref in &fd.vbank.loc_tree {
            vn_ref.0.write().unwrap().high = None;
        }
        self.var_counter = 0;
        self.copy_trims.clear();
        self.type_test_cache.clear();
        // merge.cc:1582: stackAffectingOps.clear() (cover.hh:63).
        self.type_test_cache.clear_stack_affecting();
        self.live_set.clear();
        // clear() on an in-flight nested sequence would silently swallow an
        // attach/detach imbalance; assert balance instead so a leak surfaces
        // immediately (release builds keep the reset as a safety net).
        debug_assert!(
            self.attach_depth == 0,
            "Merge::clear called with unbalanced attach_depth = {}",
            self.attach_depth
        );
        self.attach_depth = 0;
        fd.merge_state.clear();
    }

    // Ghidra: merge.hh:83 Merge::liveVarnodeSet
    /// Decide whether a varnode should participate in merging.
    ///
    /// Faithful to the contract of Ghidra's merge: it operates on the
    /// post-optimization varnode set, so only varnodes still referenced by
    /// an alive op are merged. This is determined by collecting the set of
    /// varnodes referenced by any alive op's inputs or output, then testing
    /// membership — NOT by inspecting `vn.def`/`vn.descend`, which become
    /// unreliable after copy-propagation redirects edges and dead-code marks
    /// ops dead without pruning varnode-side links.
    ///
    /// Input varnodes (function parameters / entry values) are always live.
    fn live_varnode_set(fd: &Funcdata) -> std::collections::HashSet<usize> {
        use std::collections::HashSet;
        let mut live: HashSet<usize> = HashSet::new();
        // Collect varnodes referenced by any alive op (inrefs + output).
        for op_ref in fd.obank.iter_alive() {
            let op = op_ref.0.read().unwrap();
            if let Some(out) = &op.output {
                live.insert(std::sync::Arc::as_ptr(out) as usize);
            }
            for in_arc in &op.inrefs {
                live.insert(std::sync::Arc::as_ptr(in_arc) as usize);
            }
        }
        // Also include block-level ops (comparisons/booleans may live only in blocks).
        for i in 0..fd.bblocks.get_size() {
            if let Some(block_arc) = fd.bblocks.get_block(i) {
                let block = block_arc.read().unwrap();
                for op_ref in block.get_ops() {
                    let op = op_ref.0.read().unwrap();
                    if op.is_dead() {
                        continue;
                    }
                    if let Some(out) = &op.output {
                        live.insert(std::sync::Arc::as_ptr(out) as usize);
                    }
                    for in_arc in &op.inrefs {
                        live.insert(std::sync::Arc::as_ptr(in_arc) as usize);
                    }
                }
            }
        }
        live
    }

    // Ghidra: merge.hh:83 Merge::mergeAll
    /// Perform the full merging + naming pipeline.
    ///
    /// This mirrors the Ghidra merge action group (coreaction.cc:5718-5729)
    /// as a 9-step sequence, augmented with the Rudra-specific cover/naming
    /// plumbing. Step order:
    ///
    ///   1. MergeRequired   — mergeAddrTied + mergeMarker (required merges)
    ///   2. MarkExplicit    — (handled elsewhere by coreaction)
    ///   3. MarkImplied     — (handled elsewhere by coreaction)
    ///   4. MergeMultiEntry — multi-entry symbol merges
    ///   5. MergeCopy       — COPY input/output merges
    ///   6. DominantCopy    — dominant-copy selection
    ///   7. MergeAdjacent   — adjacent (input/output) speculative merges
    ///   8. MergeType       — same-type speculative merges
    ///   9. HideShadow      — shadow COPY consolidation
    ///  10. CopyMarker      — mark internal COPYs non-printing
    fn merge_all(&mut self, fd: &mut Funcdata) {
        // Attach the persistent Funcdata merge channels (Ghidra
        // ActionMergeType runs on the same `data.getMerge()` object warmed
        // by the earlier mergerequired/mergecopy/mergeadjacent Actions,
        // coreaction.hh:414).
        self.attach(fd);
        // Build the live varnode set once (post-dead-code): only varnodes
        // referenced by an alive op participate in HighVariables. This makes
        // high.instances authoritative for printc.
        self.live_set = Self::live_varnode_set(fd);

        // Step 1 (part a): MergeRequired — mergeAddrTied.
        self.merge_addr_tied(fd);

        // Ensure every varnode has a HighVariable before the marker pass.
        self.ensure_all_have_high(fd);

        // Step 1 (part b): MergeRequired — mergeMarker.
        // Force-merge MULTIEQUAL/INDIRECT input+output. groupPartials is a
        // faithful no-op (no CONCAT machinery).
        self.merge_required(fd);

        // Compute liveness covers for the live varnode population. The
        // oracle has no eager Merge pass here — covers rebuild lazily via
        // Varnode::getCover()/updateCover (varnode.cc:233) — this eager
        // materialization runs the identical Cover::rebuild product
        // (cover.cc:477) once, after required merges finalize the
        // instance sets the speculative passes will read.
        self.compute_varnode_covers(fd);

        // Step 4: MergeMultiEntry (faithful no-op without symbol machinery).
        self.merge_multi_entry(fd);

        // Step 5: MergeCopy — mergeOpcode(CPUI_COPY) (coreaction.cc:5722).
        // Required test + merge; cover intersection silently skips (no snip).
        self.merge_opcode(fd, crate::opcodes::OpCode::CPUI_COPY);

        // Step 6: DominantCopy — processCopyTrims (coreaction.cc:5723,
        // coreaction.hh:1008). Consumes the copy_trims filled by step 1's
        // forced-merge snip path (merge_addr_tied → allocate_copy_trim) and
        // replaces ≥2-COPY groups with a single dominant COPY, in copyTrims
        // first-seen order. See process_copy_trims.
        self.process_copy_trims(fd);

        // Step 7: MergeAdjacent.
        self.merge_adjacent(fd);

        // Step 8: MergeType.
        self.merge_by_datatype(fd);

        // Step 9: HideShadow (analysis-only; no data-flow rewrite yet).
        self.hide_shadows(fd);

        // Step 10: CopyMarker.
        self.mark_internal_copies(fd);

        // Sync HighVariable covers from member Varnode covers. Must run AFTER
        // all speculative merges finalize the instance sets so each
        // HighVariable's cover reflects all its members. ActionMarkImplied
        // (run later in the pipeline) reads VARNODE covers directly (lazily
        // rebuilt) and aggregates fresh inside inflate_test — it does not
        // depend on this stored product. The stored-field product is kept
        // materialized for the raw-gated readers (high_cover discipline,
        // MERGE-HIGHCOVER-PROPAGATION-0001).
        self.update_high_covers(fd);

        // NOTE (FUNCDATA-LINKSYMBOL-TYPED-0001): Ghidra's merge sequence
        // (coreaction.cc:5718-5729) has NO naming step — Merge has no
        // assignNames. Variable naming lives exclusively in
        // ActionNameVars::apply (coreaction.cc:2978-3000): linkSymbols →
        // namerec buildDefaultName loop → assignDefaultNames. The former
        // per-High `assign_names` (self-invented grammar walking the loc
        // tree) was removed; names now come from the ScopeLocal symbols.

        // Persist the accumulated channels for any later merge-family
        // Action (hide_shadows_of is invoked by ActionHideShadow after
        // ActionMergeType in the oracle order, coreaction.cc:5728).
        self.detach(fd);
    }

    // RUDRA-GLUE: wholesale post-merge cover sync. The oracle has no such
    /// pass — it maintains covers lazily (HighVariable::updateCover
    /// variable.cc:338 via HighIntersectTest::updateHigh variable.cc:1148,
    /// Varnode::getCover varnode.hh:202); Rudra materializes high.cover
    /// eagerly because downstream readers (markimplied's inflateTest fast
    /// path, varmap) read the stored field. Each high is synced through
    /// `update_high_cover` (the updateCover port), leaving the same
    /// invariant point the oracle reaches lazily: every cover clean and
    /// equal to the union of its members' current covers.
    fn update_high_covers(&mut self, fd: &mut Funcdata) {
        use std::collections::HashSet;
        let mut seen: HashSet<usize> = HashSet::new();
        let mut to_update: Vec<std::sync::Arc<std::sync::RwLock<HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let high_arc = {
                let vn = vn_ref.0.read().unwrap();
                vn.high.clone()
            };
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if seen.insert(ptr) {
                    to_update.push(ha);
                }
            }
        }
        for ha in to_update {
            update_high_cover(&ha);
        }
    }

    // Ghidra: merge.cc:1595 Merge::markImplied
    /// Mark a Varnode as implied. Faithful to Merge::markImplied
    /// (merge.cc:1594-1605): after setImplied, the def op's cover-having
    /// inputs are marked coverdirty because their covers traverse the
    /// now-implied root and must be rebuilt before any later read. Both the
    /// cc:1598 setImplied and the cc:1603 setFlags(coverdirty) route through
    /// varnode.rs set_implied/set_flags, which carry the full high
    /// notification (flagsDirty unconditional + coverDirty when the mask
    /// has it) — the observable state matches the oracle's calls one for
    /// one (HIGHCOV lane 2026-09-25; the inline propagation half added
    /// earlier, when set_flags lacked the arm, is now redundant and gone).
    pub fn mark_implied(vn: &Arc<RwLock<Varnode>>) {
        vn.write().unwrap().set_implied();
        let def = vn.read().unwrap().get_def();
        let Some(def) = def else { return };
        let inputs: Vec<std::sync::Arc<std::sync::RwLock<Varnode>>> = {
            let op = def.read().unwrap();
            (0..op.num_input())
                .filter_map(|i| op.get_in(i).cloned())
                .collect()
        };
        for input in inputs {
            let has_cover = input.read().unwrap().has_cover();
            if has_cover {
                // merge.cc:1603: defvn->setFlags(Varnode::coverdirty).
                input.write().unwrap().set_flags(varnode_flags::COVERDIRTY);
            }
        }
    }

    // Ghidra: merge.cc:1616 Merge::inflateTest
    /// Test if inflating a Varnode's Cover to cover `high` causes an intersection
    /// with any OTHER instance of the Varnode's own HighVariable.
    /// Faithful to Merge::inflateTest (merge.cc:1616).
    ///
    /// When a varnode is implied, its def op's inputs propagate farther (into
    /// the consumer). Each such input must not have its inflated cover intersect
    /// a sibling instance's cover — otherwise two SSA versions of the same
    /// logical variable would be simultaneously live at the implied site.
    ///
    /// Returns true if there IS an intersection (i.e. the varnode CANNOT be
    /// implied). `high` is the HighVariable being implied; `a` is an input
    /// varnode of `a`'s def op.
    pub fn inflate_test(
        a: &Arc<RwLock<Varnode>>,
        high: &crate::variable::HighVariable,
    ) -> bool {
        // Ghidra merge.cc:1616-1646 Merge::inflateTest.
        //   ahigh = a->getHigh();
        //   testCache.updateHigh(high);  (lazily rebuilds high->internalCover)
        //   for each instance b of ahigh:
        //     if (b->copyShadow(a)) continue;   // copy-chain shadow allowed
        //     if (2 == b->getCover()->intersect(high->internalCover)) return true;
        //   piece = ahigh->piece;
        //   if (piece != null) {
        //     piece->updateIntersections();
        //     for each intersecting otherPiece:
        //       off = otherPiece->getOffset() - piece->getOffset();
        //       for each instance b of otherHigh:
        //         if (b->partialCopyShadow(a, off)) continue;
        //         if (2 == b->getCover()->intersect(highCover)) return true;
        //   }
        //   return false;
        // The decisive semantic: only a WHOLE-INTERVAL intersection (== 2)
        // refuses implication; a boundary-only touch (== 1) is allowed. The
        // previous `intersects()` (any overlap) form made every SUBPIECE
        // field extraction explicit because the input shadow's read point
        // coincides with the piece's def point (a boundary touch).
        let a_high = a.read().unwrap().high.clone();
        let Some(ahigh_arc) = a_high else {
            return false; // a has no HighVariable — no intersection possible
        };
        let ahigh = ahigh_arc.read().unwrap();
        let high_instances: Vec<Arc<RwLock<Varnode>>> = high.instances.clone();
        // merge.cc:1621-1622: testCache.updateHigh(high); const Cover
        // &highCover(high->internalCover). The oracle's updateHigh
        // (variable.cc:1146) rebuilds internalCover only when the high is
        // dirty, relying on the invariant that EVERY mutation which dirties
        // a member Varnode cover also propagates coverDirty to the owning
        // high (varnode.cc:352-360 setFlags → high->coverDirty, fired by
        // addDescend/eraseDescend/calcCover). Rudra's mutation paths do not
        // all maintain that propagation (a rebuilt member cover leaves the
        // high "clean" with a stale stored aggregate — the
        // CANARY-EXPLICIT/loop-temp family: the PTRADD/PTRSUB for-header
        // temps' own covers end at their single COPY read, but the stored
        // high aggregate still ran to the block bottom, making
        // inflateTest see a whole-interval intersection where the oracle
        // sees a boundary touch and keeps the temp implied). Aggregate
        // fresh from the lazily-rebuilt member covers unconditionally:
        // the product equals the oracle's internalCover under its
        // maintained invariant, and can only be MORE current than the
        // stale stored form.
        let high_cover_fresh: Cover = {
            for inst_arc in &high_instances {
                // Oracle chain: updateHigh → updateCover → member getCover()
                // rebuild. NOTE LOCK DISCIPLINE: unlike refresh_cover_lazy,
                // this rebuild does NOT re-mark the high dirty across the
                // flag clear (varnode.cc:365-374) — the caller (coreaction
                // checkImpliedCover) holds a READ guard on this high for the
                // whole call, so a member back-pointer write on it would
                // self-deadlock. The always-fresh aggregation below makes
                // this path independent of the stored `high.cover` product
                // (whose staleness under missing dirty propagation is
                // registered as MERGE-HIGHCOVER-PROPAGATION-0001).
                Varnode::update_cover_locked(inst_arc);
            }
            let mut fresh = Cover::new();
            // variable.cc:329: gate the merge loop on inst[0]->hasCover().
            if high_instances
                .first()
                .map(|first| first.read().unwrap().has_cover())
                .unwrap_or(false)
            {
                for inst_arc in &high_instances {
                    if let Some(ic) = inst_arc.read().unwrap().cover.as_ref() {
                        fresh.merge(ic);
                    }
                }
            }
            fresh
        };
        // First loop: instances of a's HighVariable (merge.cc:1623-1632).
        // Snapshot the instance arcs, then drop the read guard BEFORE the
        // piece walk: update_intersections takes a WRITE lock on the owning
        // high (variable.rs), and read+write on the same RwLock from one
        // thread would deadlock (observed: pipeline hang at markimplied).
        let first_instances: Vec<Arc<RwLock<Varnode>>> = ahigh.instances.clone();
        let piece_arc = ahigh.piece.clone();
        drop(ahigh);
        for inst_arc in &first_instances {
            // merge.cc:1627: b->getCover() is the lazy rebuild read
            // (varnode.hh:202 → varnode.cc:233). No high-dirty propagation
            // here: the caller holds a read guard on the propagated high,
            // and this instance's high may be that same high (mergecopy
            // merges COPY in/out into one HighVariable) — a back-pointer
            // write would self-deadlock (see the high_cover_fresh note).
            Varnode::update_cover_locked(inst_arc);
            let inst = inst_arc.read().unwrap();
            // merge.cc:1626: if (b->copyShadow(a)) continue; — copy-chain
            // shadows hold the same value, their cover is shared with a.
            let a_g = a.read().unwrap();
            if inst.copy_shadow(&a_g) {
                continue;
            }
            drop(a_g);
            if let Some(ic) = inst.cover.as_ref() {
                if 2 == ic.intersect_char(&high_cover_fresh) {
                    return true;
                }
            }
        }
        // merge.cc:1633-1644: VariablePiece intersection walk.
        if let Some(piece_arc) = piece_arc {
            let other_pieces: Vec<Arc<RwLock<crate::variable::VariablePiece>>> = {
                crate::variable::VariablePiece::update_intersections(&piece_arc);
                let piece = piece_arc.read().unwrap();
                (0..piece.num_intersection())
                    .filter_map(|i| piece.get_intersection(i))
                    .collect()
            };
            let piece_offset = piece_arc.read().unwrap().group_offset;
            let a_vn_guard = a.read().unwrap();
            for other_arc in other_pieces {
                let (other_off, other_high_weak) = {
                    let p = other_arc.read().unwrap();
                    (p.group_offset, p.get_high())
                };
                let Some(other_high_arc) = other_high_weak.and_then(|w| w.upgrade()) else {
                    continue;
                };
                let off = other_off - piece_offset;
                let other_high = other_high_arc.read().unwrap();
                for inst_arc in &other_high.instances {
                    // merge.cc:1639: b->getCover() lazy rebuild read. No
                    // high-dirty propagation (caller-held read guard — see
                    // the merge.cc:1627 note).
                    Varnode::update_cover_locked(inst_arc);
                    let inst = inst_arc.read().unwrap();
                    // merge.cc:1640: partialCopyShadow allows SUBPIECE/PIECE
                    // derived shadows at the piece-relative offset.
                    if inst.partial_copy_shadow(&a_vn_guard, off) {
                        continue;
                    }
                    if let Some(ic) = inst.cover.as_ref() {
                        if 2 == ic.intersect_char(&high_cover_fresh) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    // Ghidra: merge.cc:609 Merge::mergeAddrTied
    /// Force the address-tied exact-location ranges in every maximal
    /// overlapping processor/spacebase cluster, then record the relative
    /// offsets of mixed-size ranges in a shared `VariableGroup`.
    pub fn merge_addr_tied(&mut self, fd: &mut Funcdata) {
        self.try_merge_addr_tied(fd)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    // RUDRA-GLUE: Result-bearing Rust exception channel for the C++
    // LowlevelError exits from mergeRangeMust/groupWith. The legacy Action
    // boundary above still adapts Err to panic until Action supports Result.
    pub fn try_merge_addr_tied(&mut self, fd: &mut Funcdata) -> Result<()> {
        self.attach(fd);

        let result = self.merge_addr_tied_inner(fd);
        self.detach(fd);
        result
    }

    // Ghidra: merge.cc:609 Merge::mergeAddrTied
    /// Result-bearing body, invoked with the persistent merge channels
    /// attached by `try_merge_addr_tied`.
    fn merge_addr_tied_inner(&mut self, fd: &mut Funcdata) -> Result<()> {
        let ranges = Self::addr_tied_location_ranges(fd);
        let mut cluster_start = 0usize;
        while cluster_start < ranges.len() {
            let cluster_space = ranges[cluster_start].space;
            let mut cluster_end = cluster_start + 1;
            let mut max_offset = Self::range_last_offset(&ranges[cluster_start]);
            while cluster_end < ranges.len() {
                let next = &ranges[cluster_end];
                if next.space != cluster_space || next.offset > max_offset {
                    break;
                }
                max_offset = max_offset.max(Self::range_last_offset(next));
                cluster_end += 1;
            }

            // Ghidra merge.cc:629-631 gates on overlapLoc's returned flags:
            // the union of HEAD-member flags across the runs the walk
            // visited (varnode.cc:1798 + :1813). Folding each range's
            // head_flags across this cluster reproduces that union because
            // the cluster extension rule (next.offset <= running maxOff)
            // matches the walk's continuation condition.
            let flags = ranges[cluster_start..cluster_end]
                .iter()
                .fold(0u32, |acc, range| acc | range.head_flags);
            if flags & varnode_flags::ADDRTIED != 0 {
                let members: Vec<Arc<RwLock<Varnode>>> = ranges[cluster_start..cluster_end]
                    .iter()
                    .flat_map(|range| range.members.iter().cloned())
                    .collect();
                self.unify_address(fd, &members);
                for range in &ranges[cluster_start..cluster_end] {
                    self.merge_range_must(fd, range)?;
                }
                if cluster_end - cluster_start > 1 {
                    let base_offset = ranges[cluster_start].offset;
                    let base_high = Self::required_high(&ranges[cluster_start].members[0])?;
                    for range in &ranges[cluster_start + 1..cluster_end] {
                        let high = Self::required_high(&range.members[0])?;
                        let offset = range.offset.wrapping_sub(base_offset) as i32;
                        Self::group_with_arcs(&high, offset, &base_high)?;
                    }
                }
            }
            cluster_start = cluster_end;
        }
        Ok(())
    }

    // RUDRA-GLUE: Rust's Varnode stores the legacy AddressSpace enum instead
    // of an AddrSpace handle. Map only variants whose locked constructor type
    // is recoverable; unknown Other ids fail closed rather than being guessed.
    fn is_addr_tied_merge_space(space: AddressSpace) -> bool {
        let space_type = match space {
            AddressSpace::Ram | AddressSpace::Register | AddressSpace::Overlay => {
                Some(SpaceType::Processor)
            }
            AddressSpace::Stack => Some(SpaceType::SpaceBase),
            AddressSpace::Const => Some(SpaceType::Constant),
            AddressSpace::Unique => Some(SpaceType::Internal),
            AddressSpace::Iop => Some(SpaceType::Iop),
            AddressSpace::Join => Some(SpaceType::Join),
            // OtherSpace::INDEX is 1 and both locked constructors use
            // IPTR_PROCESSOR (space.cc:390-404). Other ids lack a retained
            // AddrSpace::getType channel in the legacy enum representation.
            AddressSpace::Other(SPACEID_OTHER) => Some(SpaceType::Processor),
            AddressSpace::Other(_) => None,
        };
        matches!(space_type, Some(SpaceType::Processor | SpaceType::SpaceBase))
    }

    // Ghidra: varnode.cc:1791 VarnodeBank::overlapLoc
    /// Project `VarnodeLocSet` into the exact-location subranges consumed by
    /// `overlapLoc`. Every non-free bank member participates; member order
    /// remains the location-set order.
    fn addr_tied_location_ranges(fd: &Funcdata) -> Vec<AddrTiedLocRange> {
        let mut ranges: Vec<AddrTiedLocRange> = Vec::new();
        for loc_ref in &fd.vbank.loc_tree {
            let member = loc_ref.0.clone();
            let (space, offset, size, flags, eligible) = {
                let vn = member.read().unwrap();
                (vn.address_space, vn.loc.as_u64(), vn.size, vn.flags,
                 !vn.is_free() && Self::is_addr_tied_merge_space(vn.address_space))
            };
            if !eligible {
                continue;
            }
            if let Some(last) = ranges.last_mut() {
                if last.space == space && last.offset == offset && last.size == size {
                    // Only the run HEAD contributes gate flags (varnode.cc
                    // :1798/:1813); later same-location members are skipped
                    // by the endLoc(size,addr,written) jump at :1800/:1815.
                    last.members.push(member);
                    continue;
                }
            }
            ranges.push(AddrTiedLocRange {
                space,
                offset,
                size,
                head_flags: flags,
                members: vec![member],
            });
        }
        ranges
    }

    // RUDRA-GLUE: inclusive maxOff arithmetic from VarnodeBank::overlapLoc
    // (varnode.cc:1789/1808) on the Rust exact-location range projection.
    fn range_last_offset(range: &AddrTiedLocRange) -> u64 {
        range.offset.wrapping_add(range.size.wrapping_sub(1) as u64)
    }

    // RUDRA-GLUE: Rust Option adapter for Ghidra Varnode::getHigh(), whose
    // mergeAddrTied caller runs after Funcdata::setHighLevel.
    fn required_high(vn: &Arc<RwLock<Varnode>>) -> Result<Arc<RwLock<HighVariable>>> {
        vn.read().unwrap().high.clone()
            .ok_or_else(|| anyhow!("Requesting non-existent high-level"))
    }

    // Ghidra: merge.cc:301 Merge::mergeRangeMust
    /// Merge one exact `(space, offset, size)` range in location-set order.
    fn merge_range_must(&mut self, fd: &Funcdata, range: &AddrTiedLocRange) -> Result<()> {
        let first = &range.members[0];
        Self::merge_test_must(&first.read().unwrap())?;
        let high = Self::required_high(first)?;
        for (fail_idx, member) in range.members.iter().enumerate().skip(1) {
            let candidate = Self::required_high(member)?;
            if Arc::ptr_eq(&high, &candidate) {
                continue;
            }
            Self::merge_test_must(&member.read().unwrap())?;
                if !self.merge_required_result(fd, &high, &candidate)? {
                    // Registered debug TAG [MERGE-FAIL]/[MERGE-PAIR]
                    // (stderr, env-gated by RUDRA_MERGE_DIAG; registry:
                    // docs/api/merge.md "诊断 TAG 登记"). Dumps the failing
                    // (space,offset,size) group and every intersecting
                    // instance pair for forced-merge triage.
                    if std::env::var("RUDRA_MERGE_DIAG").is_ok() {
                        // Dump every intersecting instance pair between the
                        // accumulated high and the failing candidate high.
                        let dump: Vec<String> = range
                            .members
                            .iter()
                            .enumerate()
                            .map(|(idx, m)| {
                                let r = m.read().unwrap();
                                format!(
                                    "#{idx} {:?}/{:#x}/{} flags={:#x} def={:?} high_inst={}{}",
                                    r.get_space(),
                                    r.get_offset(),
                                    r.get_size(),
                                    r.flags,
                                    r.get_def().map(|d| {
                                        let dr = d.read().unwrap();
                                        format!("{:?}@{:#x}", dr.opcode, dr.get_addr().as_u64())
                                    }),
                                    r.high
                                        .as_ref()
                                        .map(|h| h.read().unwrap().num_instances())
                                        .unwrap_or(0),
                                    if idx == fail_idx { " *FAIL*" } else { "" },
                                )
                            })
                            .collect();
                        eprintln!(
                            "[MERGE-FAIL] range {:?}/{:#x}/{} members: {:?}",
                            range.space, range.offset, range.size, dump
                        );
                        let h_insts = high.read().unwrap().instances.clone();
                        let c_insts = candidate.read().unwrap().instances.clone();
                        for ia in &h_insts {
                            let a = ia.read().unwrap();
                            for ib in &c_insts {
                                let b = ib.read().unwrap();
                                if let (Some(ca), Some(cb)) = (a.cover.as_ref(), b.cover.as_ref())
                                {
                                    if ca.intersect_char(cb) > 1 {
                                        let a_readers: Vec<String> = a
                                            .descend
                                            .iter()
                                            .filter_map(|w| w.upgrade())
                                            .map(|o| {
                                                let or = o.read().unwrap();
                                                format!(
                                                    "{:?}@{:#x}/ord{}",
                                                    or.opcode,
                                                    or.get_addr().as_u64(),
                                                    or.get_seq_num().get_order()
                                                )
                                            })
                                            .collect();
                                        eprintln!(
                                            "[MERGE-PAIR] A def={:?} cover={} | B def={:?} cover={} | A readers={:?}",
                                            a.get_def().map(|d| d.read().unwrap().get_addr().as_u64()),
                                            ca,
                                            b.get_def().map(|d| d.read().unwrap().get_addr().as_u64()),
                                            cb,
                                            a_readers,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    return Err(anyhow!("Forced merge caused intersection"));
            }
        }
        Ok(())
    }

    // RUDRA-GLUE: Result-bearing specialization of Merge::merge for the
    // non-speculative mergeRangeMust caller. HighVariable::mergeInternal can
    // throw after speculative merge classes have been formed; keep that exit
    // ordered after the cached cover-intersection test, as in merge.cc:1569
    // followed by variable.cc:647-650.
    fn merge_required_result(
        &mut self,
        fd: &Funcdata,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
    ) -> Result<bool> {
        if Arc::ptr_eq(high1, high2) {
            return Ok(true);
        }
        if self.type_test_cache.intersection(fd, high1, high2) {
            return Ok(false);
        }
        self.type_test_cache.move_intersect_tests(high1, high2);
        let neither_grouped = high1.read().unwrap().piece.is_none()
            && high2.read().unwrap().piece.is_none();
        if neither_grouped {
            // variable.cc:631-650 mergeInternal mutates the survivor before
            // testing numMergeClasses and throwing. Preserve those partial
            // mutations on the Result path instead of preflighting the error.
            let inherited_symbol = {
                let second = high2.read().unwrap();
                if second.highflags & high_internal_flags::SYMBOLDIRTY == 0 {
                    second.symbol.clone().map(|symbol| (symbol, second.symbol_offset))
                } else {
                    None
                }
            };
            let invalid_merge_classes = {
                let mut first = high1.write().unwrap();
                first.highflags |= high_internal_flags::FLAGSDIRTY
                    | high_internal_flags::NAMEREPDIRTY
                    | high_internal_flags::TYPEDIRTY;
                if let Some((symbol, symbol_offset)) = inherited_symbol {
                    first.symbol = Some(symbol);
                    first.symbol_offset = symbol_offset;
                    first.highflags &= !high_internal_flags::SYMBOLDIRTY;
                }
                let second = high2.read().unwrap();
                first.num_merge_classes != 1 || second.num_merge_classes != 1
            };
            if invalid_merge_classes {
                return Err(anyhow!(
                    "Making a non-speculative merge after speculative merges have occurred"
                ));
            }
        }
        Ok(self.merge_highs(high1, high2, false))
    }

    // RUDRA-GLUE: allocate VariablePiece with the Arc/Weak ownership used by
    // Rust; Ghidra's VariablePiece ctor uses raw owning/back pointers.
    fn attach_group_piece(high: &Arc<RwLock<HighVariable>>, offset: i32,
                          group: &Arc<RwLock<VariableGroup>>) -> Result<Arc<RwLock<VariablePiece>>> {
        let size = high.read().unwrap().instances.first()
            .map(|vn| vn.read().unwrap().size as i32).unwrap_or(0);
        // Ghidra HighVariable::groupWith (variable.cc:574-605) always
        // allocates a VariablePiece in the one-sided group cases; it has no
        // duplicate/failure branch. Keep duplicate offsets legal here.
        let piece = Arc::new(RwLock::new(VariablePiece::new(
            Arc::downgrade(high), offset, size, Some(group.clone()))));
        group.write().unwrap().add_piece(piece.clone());
        high.write().unwrap().piece = Some(piece.clone());
        Ok(piece)
    }

    // Ghidra: variable.cc:571 HighVariable::groupWith
    /// Arc-aware form of `HighVariable::groupWith`, including all four group
    /// ownership cases and the `(offset,size)` duplicate exception.
    fn group_with_arcs(high: &Arc<RwLock<HighVariable>>, offset: i32,
                       other: &Arc<RwLock<HighVariable>>) -> Result<()> {
        let high_piece = high.read().unwrap().piece.clone();
        let other_piece = other.read().unwrap().piece.clone();
        match (high_piece, other_piece) {
            (None, None) => {
                let group = Arc::new(RwLock::new(VariableGroup::new()));
                let other_piece = Self::attach_group_piece(other, 0, &group)?;
                Self::attach_group_piece(high, offset, &group)?;
                VariablePiece::mark_intersection_dirty_read(&other_piece);
            }
            (None, Some(other_piece)) => {
                let (other_offset, group) = {
                    let piece = other_piece.read().unwrap();
                    (piece.group_offset, piece.group.clone()
                        .ok_or_else(|| anyhow!("VariablePiece has no VariableGroup"))?)
                };
                let other_clean = other.read().unwrap().highflags
                    & high_internal_flags::INTERSECTDIRTY == 0;
                if other_clean {
                    VariablePiece::mark_intersection_dirty_read(&other_piece);
                }
                high.write().unwrap().highflags |= high_internal_flags::INTERSECTDIRTY
                    | high_internal_flags::EXTENDCOVERDIRTY;
                Self::attach_group_piece(high, offset + other_offset, &group)?;
            }
            (Some(high_piece), None) => {
                let (high_offset, group) = {
                    let piece = high_piece.read().unwrap();
                    (piece.group_offset, piece.group.clone()
                        .ok_or_else(|| anyhow!("VariablePiece has no VariableGroup"))?)
                };
                let mut other_offset = high_offset - offset;
                if other_offset < 0 {
                    group.write().unwrap().adjust_offsets(-other_offset);
                    other_offset = 0;
                }
                let high_clean = high.read().unwrap().highflags
                    & high_internal_flags::INTERSECTDIRTY == 0;
                if high_clean {
                    VariablePiece::mark_intersection_dirty_read(&high_piece);
                }
                other.write().unwrap().highflags |= high_internal_flags::INTERSECTDIRTY
                    | high_internal_flags::EXTENDCOVERDIRTY;
                Self::attach_group_piece(other, other_offset, &group)?;
            }
            (Some(high_piece), Some(other_piece)) => {
                let (high_offset, high_group) = {
                    let piece = high_piece.read().unwrap();
                    (piece.group_offset, piece.group.clone()
                        .ok_or_else(|| anyhow!("VariablePiece has no VariableGroup"))?)
                };
                let (other_offset, other_group) = {
                    let piece = other_piece.read().unwrap();
                    (piece.group_offset, piece.group.clone()
                        .ok_or_else(|| anyhow!("VariablePiece has no VariableGroup"))?)
                };
                let offset_diff = other_offset + offset - high_offset;
                if offset_diff != 0 {
                    high_group.write().unwrap().adjust_offsets(offset_diff);
                }
                if Arc::ptr_eq(&high_group, &other_group) {
                    VariablePiece::mark_intersection_dirty_read(&other_piece);
                    return Ok(());
                }
                // variable.cc:599-604: adjust the target group's offsets,
                // then target.combineGroups(source) and mark dirty.
                // VariableGroup::combineGroups owns ordered PieceSet
                // transfer and source-group lifecycle semantics.
                let mut target = other_group.write().unwrap();
                let mut source = high_group.write().unwrap();
                target.combine_groups(&mut source);
                drop(source);
                drop(target);
                VariablePiece::mark_intersection_dirty_read(&other_piece);
            }
        }
        Ok(())
    }

    // Ghidra: merge.hh:83 Merge::ensureAllHaveHigh
    /// Ensure every varnode in the bank has a HighVariable.
    /// Varnodes not merged by `merge_addr_tied` get their own singleton HighVariable.
    fn ensure_all_have_high(&mut self, fd: &mut Funcdata) {
        // Faithful to ActionAssignHigh (coreaction.hh:339) /
        // Funcdata::setHighLevel (funcdata_varnode.cc:595): assign a
        // HighVariable to EVERY Varnode in loc_tree that lacks one. The prior
        // live_set filter diverged from Ghidra and left implied/CAST-output
        // varnodes without a HighVariable, forcing printc into uVar_{offset}.
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> = fd.vbank.loc_tree
            .iter()
            .filter(|r| r.0.read().unwrap().high.is_none())
            .map(|r| r.0.clone())
            .collect();

        for vn_arc in vn_arcs {
            let needs_high = {
                let vn = vn_arc.read().unwrap();
                vn.high.is_none()
            };
            if needs_high {
                let vn = vn_arc.read().unwrap();
                let dt = vn.v_type.clone().unwrap_or_else(|| {
                    Arc::new(Datatype::Base(TypeBase::new("undefined".to_string(), vn.size, TypeMetatype::Unknown)))
                });
                drop(vn);

                let high = Arc::new(RwLock::new(HighVariable::new(dt)));
                high.write().unwrap().add_instance(vn_arc.clone());
                vn_arc.write().unwrap().high = Some(high);
            }
        }
    }

    // Ghidra: merge.cc:255 Merge::mergeTestBasic
    /// Test whether a single Varnode can ever participate in merging.
    /// Faithful to `Merge::mergeTestBasic` (merge.cc:255-264).
    ///
    /// A Varnode is merge-eligible only if it:
    ///   - has a Cover (not constant/annotation/free),
    ///   - is not implied,
    ///   - is not a proto-partial (CONCAT piece), and
    ///   - is not a spacebase (stack/register pointer).
    fn merge_test_basic(vn: &Varnode) -> bool {
        if !vn.has_cover() {
            return false;
        }
        if vn.is_implied() {
            return false;
        }
        if vn.flags & varnode_flags::PROTO_PARTIAL != 0 {
            return false;
        }
        if vn.is_spacebase() {
            return false;
        }
        true
    }

    // Ghidra: merge.hh:83 Merge::mergeSpeculative
    /// Speculatively merge two HighVariables iff their cached Cover
    /// intersection test rejects them. Faithful to
    /// `Merge::merge(high1, high2, isspeculative)` (merge.cc:1565-1575):
    /// testCache.intersection (lazy cover build + cross-Action cache),
    /// moveIntersectTests, absorb instances, updateCover. This is the shared
    /// primitive behind merge_copy, merge_adjacent and merge_multi_entry: a
    /// merge is attempted, but skipped (returning false) if the two
    /// HighVariables are simultaneously live.
    ///
    /// Merge two HighVariables per `Merge::merge` (merge.cc:1565-1575):
    /// cached testCache intersection (with lazy cover build), then
    /// moveIntersectTests, then the shared HighVariable::merge absorption.
    /// `high1` is the SURVIVOR ("the second is merged into the first",
    /// merge.cc:1558); `isspeculative` selects separate merge classes
    /// (variable.cc:640-646) vs the single-class required merge (:648-654).
    fn merge_speculative(
        &mut self,
        fd: &Funcdata,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
        isspeculative: bool,
    ) -> bool {
        if Arc::ptr_eq(high1, high2) {
            return true; // Already merged (merge.cc:1568)
        }
        // merge.cc:1569: if (testCache.intersection(high1,high2)) return false;
        // The cached test lazily (re)builds the pair's covers via updateHigh
        // (variable.cc:1148-1156) and reuses results cached by any earlier
        // merge Action on the persistent Funcdata Merge object.
        if self.type_test_cache.intersection(fd, high1, high2) {
            return false;
        }
        // variable.cc:681: HighVariable::merge calls
        // testCache->moveIntersectTests(this,tv2) before absorbing instances.
        self.type_test_cache.move_intersect_tests(high1, high2);
        self.merge_highs(high1, high2, isspeculative)
    }

    // Ghidra: merge.cc:1565 Merge::merge (varnode-pair convenience)
    /// Varnode-pair form: `vn1`'s HighVariable is the survivor. Callers
    /// pass the oracle's (high_out, high_in) order — mergeOpcode
    /// (merge.cc:346, false), mergeAdjacent (:1010, true — output
    /// survives), mergeMultiEntry (:943, false — anchor survives),
    /// mergeOp (:766, false — output survives) and buildDominantCopy
    /// (variable.cc-side, true).
    fn merge_speculative_by_vn(
        &mut self,
        fd: &Funcdata,
        vn1: &Arc<RwLock<Varnode>>,
        vn2: &Arc<RwLock<Varnode>>,
        isspeculative: bool,
    ) -> bool {
        let (h1, h2) = {
            let v1 = vn1.read().unwrap();
            let v2 = vn2.read().unwrap();
            (v1.high.clone(), v2.high.clone())
        };
        let (Some(h1), Some(h2)) = (h1, h2) else {
            return false;
        };
        self.merge_speculative(fd, &h1, &h2, isspeculative)
    }

    // RUDRA-GLUE: merge_test — 快速预检查两个 Varnode 是否可能合并。
    /// 这是 mergeTestRequired (merge.cc:102) 的简化子集:只检查 space+size+
    /// const/annotation。Ghidra 的 mergeTestRequired 还检查 typelock 冲突、
    /// addrtied-different-address、input/persist/extrout、protopartial。
    /// Rudra 缺这些检查(简化),可能在罕见情况下允许 Ghidra 禁止的合并。
    /// 注意:此函数 NOT 对应 Ghidra merge.cc:1657 Merge::mergeTest(那是
    /// cover-intersection 测试,Rudra 的 merge_test_with_list 才是它的 port)。
    pub fn merge_test(&self, v1: &Varnode, v2: &Varnode) -> bool {
        use crate::varnode::varnode_flags;

        // Never merge constants or annotations
        if v1.flags & varnode_flags::CONSTANT != 0 || v2.flags & varnode_flags::CONSTANT != 0 {
            return false;
        }
        if v1.flags & varnode_flags::ANNOTATION != 0 || v2.flags & varnode_flags::ANNOTATION != 0 {
            return false;
        }

        // Must be same address space and size
        v1.address_space == v2.address_space && v1.size == v2.size
    }

    // Ghidra: merge.cc:102 Merge::mergeTestRequired
    /// Required-merge test between two HighVariables.
    /// Faithful to `Merge::mergeTestRequired` (merge.cc:102-166).
    ///
    /// This is a pure property test — it does NOT check Cover intersection
    /// (that is done by `merge()` itself, which returns false on overlap).
    /// It checks: typelock conflict, addrtied-different-address, input/persist
    /// conflicts, extrout, protopartial conflicts.
    ///
    /// VariablePiece-group and Symbol-mapping identity/offset checks from
    /// merge.cc:147-164 are included after the flag/type refresh above.
    pub fn merge_test_required(
        &self,
        high_out: &Arc<RwLock<HighVariable>>,
        high_in: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if Arc::ptr_eq(high_out, high_in) {
            return true; // Already merged
        }
        for high in [high_out, high_in] {
            let mut high = high.write().unwrap();
            high.update_flags();
            high.update_type();
            high.update_symbol();
        }
        let ho = high_out.read().unwrap();
        let hi = high_in.read().unwrap();
        // typelock: if both locked, types must match (merge.cc:107-109)
        if hi.is_type_locked() && ho.is_type_locked() {
            if !Arc::ptr_eq(&hi.v_type.get(), &ho.v_type.get()) {
                return false;
            }
        }
        // addrtied: both addrtied but different address -> forbid (merge.cc:111-116)
        if ho.is_addr_tied() && hi.is_addr_tied() {
            let addr_out = ho.get_tied_varnode().map(|v| {
                let v = v.read().unwrap();
                (v.address_space, v.loc)
            });
            let addr_in = hi.get_tied_varnode().map(|v| {
                let v = v.read().unwrap();
                (v.address_space, v.loc)
            });
            if let (Some(a_out), Some(a_in)) = (addr_out, addr_in) {
                if a_out != a_in {
                    return false;
                }
            }
        }
        // input/persist/extrout conflicts (merge.cc:118-134)
        if hi.is_input() {
            if ho.is_persist() {
                return false;
            }
            if ho.is_addr_tied() && !hi.is_addr_tied() {
                return false;
            }
        } else if hi.is_extra_out() {
            return false;
        }
        if ho.is_input() {
            if hi.is_persist() {
                return false;
            }
            if hi.is_addr_tied() && !ho.is_addr_tied() {
                return false;
            }
        } else if ho.is_extra_out() {
            return false;
        }
        // protopartial conflicts (merge.cc:136-146)
        if hi.is_proto_partial() {
            if ho.is_proto_partial() {
                return false;
            }
            if ho.is_input() {
                return false;
            }
            if ho.is_addr_tied() {
                return false;
            }
            if ho.is_persist() {
                return false;
            }
        }
        if ho.is_proto_partial() {
            if hi.is_input() {
                return false;
            }
            if hi.is_addr_tied() {
                return false;
            }
            if hi.is_persist() {
                return false;
            }
        }
        if let (Some(in_piece), Some(out_piece)) = (&hi.piece, &ho.piece) {
            let (in_group, in_size) = {
                let piece = in_piece.read().unwrap();
                (piece.group.clone(), piece.size)
            };
            let (out_group, out_size) = {
                let piece = out_piece.read().unwrap();
                (piece.group.clone(), piece.size)
            };
            let (Some(in_group), Some(out_group)) = (in_group, out_group) else {
                return false;
            };
            if Arc::ptr_eq(&in_group, &out_group) {
                return false;
            }
            let in_group_size = in_group.read().unwrap().size;
            let out_group_size = out_group.read().unwrap().size;
            if in_size != in_group_size && out_size != out_group_size {
                return false;
            }
        }
        if let (Some(in_symbol), Some(out_symbol)) = (&hi.symbol, &ho.symbol) {
            if !Arc::ptr_eq(in_symbol, out_symbol) {
                return false;
            }
            if hi.symbol_offset != ho.symbol_offset {
                return false;
            }
        }
        true
    }

    // Ghidra: merge.cc:175 Merge::mergeTestAdjacent
    fn merge_test_adjacent(
        &self,
        high_out: &Arc<RwLock<HighVariable>>,
        high_in: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if !self.merge_test_required(high_out, high_in) {
            return false;
        }
        let (both_name_locked, same_type, out_input, in_input, out_symbol, in_symbol, both_piece) = {
            let out = high_out.read().unwrap();
            let input = high_in.read().unwrap();
            (
                out.flags & high_flags::NAMELOCK != 0
                    && input.flags & high_flags::NAMELOCK != 0,
                Arc::ptr_eq(&out.v_type.get(), &input.v_type.get()),
                out.get_input_varnode(),
                input.get_input_varnode(),
                out.symbol.clone(),
                input.symbol.clone(),
                out.piece.is_some() && input.piece.is_some(),
            )
        };
        if both_name_locked || !same_type {
            return false;
        }
        for input in [out_input, in_input].into_iter().flatten() {
            let input = input.read().unwrap();
            if input.is_illegal_input() && input.flags & varnode_flags::INDIRECTONLY == 0 {
                return false;
            }
        }
        for symbol in [out_symbol, in_symbol].into_iter().flatten() {
            if symbol.read().unwrap().is_isolated() {
                return false;
            }
        }
        !both_piece
    }

    // Ghidra: merge.cc:220 Merge::mergeTestSpeculative
    fn merge_test_speculative(
        &self,
        high_out: &Arc<RwLock<HighVariable>>,
        high_in: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if !self.merge_test_adjacent(high_out, high_in) {
            return false;
        }
        let out = high_out.read().unwrap();
        let input = high_in.read().unwrap();
        !out.is_persist()
            && !input.is_persist()
            && !out.is_input()
            && !input.is_input()
            && !out.is_addr_tied()
            && !input.is_addr_tied()
    }

    // Ghidra: variable.cc:675 HighVariable::merge (absorption phase)
    /// Shared absorption phase of Ghidra's `HighVariable::merge`
    /// (variable.cc:675-712) as reached from `Merge::merge`
    /// (merge.cc:1571): moveIntersectTests has already run; perform the
    /// piece dispatch, `mergeInternal`, the moved-instance re-sort and the
    /// survivor cover update. `high1` is the survivor (Ghidra high1 — "the
    /// second is merged into the first", merge.cc:1558).
    fn merge_highs(
        &mut self,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
        isspeculative: bool,
    ) -> bool {
        let moved_instances = high2.read().unwrap().instances.clone();
        let first_piece = high1.read().unwrap().piece.clone();
        let second_piece = high2.read().unwrap().piece.clone();
        match (first_piece, second_piece) {
            (None, None) => {
                let mut first = high1.write().unwrap();
                let mut second = high2.write().unwrap();
                first.merge_internal(&mut second, isspeculative);
            }
            (Some(piece), None) => {
                crate::variable::VariablePiece::mark_extend_cover_dirty_read(&piece);
                let mut first = high1.write().unwrap();
                let mut second = high2.write().unwrap();
                first.merge_internal(&mut second, isspeculative);
            }
            (None, Some(_)) => {
                {
                    let mut first = high1.write().unwrap();
                    let mut second = high2.write().unwrap();
                    first.transfer_piece(&mut second);
                }
                let piece = high1.read().unwrap().piece.clone().unwrap();
                piece.write().unwrap().high = Some(Arc::downgrade(high1));
                crate::variable::VariablePiece::mark_extend_cover_dirty_read(&piece);
                let mut first = high1.write().unwrap();
                let mut second = high2.write().unwrap();
                first.merge_internal(&mut second, isspeculative);
            }
            (Some(piece1), Some(piece2)) => {
                // Oracle HighVariable::merge (variable.cc:699-711): both
                // HighVariables are part of separate VariableGroups.
                // variable.cc:700-701: a speculative merge here is a
                // LowlevelError ("Trying speculatively merge variables in
                // separate groups") — unreachable through Merge::merge
                // callers because mergeTestAdjacent (merge.cc:208-209)
                // rejects both-piece candidates for every speculative path.
                // Release builds keep the conservative skip (return false,
                // no data-flow change) rather than aborting the pipeline.
                if isspeculative {
                    debug_assert!(
                        false,
                        "Trying speculatively merge variables in separate groups (variable.cc:701)"
                    );
                    eprintln!("[MERGE] speculative both-piece merge rejected (variable.cc:701 guard)");
                    return false;
                }
                // variable.cc:702: piece->mergeGroups(tv2->piece, mergePairs)
                // — combine the two groups, collecting the colliding
                // (self-group high, op2-group high) pairs. The pair's second
                // high is detached from its piece inside merge_groups
                // (variable.cc:209) in preparation for the merge.
                let merge_pairs =
                    crate::variable::VariablePiece::merge_groups(&piece1, &piece2);
                // variable.cc:703-709: for each pair — moveIntersectTests,
                // then mergeInternal (isspeculative is false here).
                for (h1w, h2w) in merge_pairs {
                    if let (Some(h1), Some(h2)) = (h1w.upgrade(), h2w.upgrade()) {
                        if Arc::ptr_eq(&h1, &h2) {
                            continue;
                        }
                        self.type_test_cache.move_intersect_tests(&h1, &h2);
                        // variable.cc:648-654 (inside mergeInternal, the
                        // non-speculative arm): every tv2 instance is
                        // re-pointed at the survivor via
                        // `vn->setHigh(this, vn->getMergeGroup())`. Rudra's
                        // merge_internal delegates the vn.high write to the
                        // caller (RUDRA-GLUE ownership note above), so the
                        // pairs loop must snapshot h2's instances before the
                        // absorption and re-point them after, exactly like
                        // the moved_instances loop at the bottom of
                        // merge_highs. Without this, the cascade-detached
                        // op2-side highs survive as instance-owning ghosts:
                        // their varnodes keep pointing at a piece-less high,
                        // so ActionCopyMarker's PIECE/SUBPIECE same-group
                        // arms never fire and the CONCAT88 join chain prints
                        // as bare unique temps instead of partial-symbol
                        // LHS form.
                        let moved: Vec<Arc<RwLock<crate::varnode::Varnode>>> =
                            h2.read().unwrap().instances.clone();
                        {
                            let mut first = h1.write().unwrap();
                            let mut second = h2.write().unwrap();
                            first.merge_internal(&mut second, isspeculative);
                        }
                        for instance in moved {
                            instance.write().unwrap().high = Some(h1.clone());
                        }
                    }
                }
                // variable.cc:710: piece->markIntersectionDirty()
                crate::variable::VariablePiece::mark_intersection_dirty_read(&piece1);
                // variable.cc:711: HighVariable::merge returns WITHOUT the
                // plain mergeInternal absorption of tv2 into this — the
                // group cascade above is the whole effect. Merge::merge
                // (merge.cc:1565-1575) returns true after the void call.
                return true;
            }
        }
        let moved_keys: rustc_hash::FxHashSet<usize> = moved_instances
            .iter()
            .map(|instance| Arc::as_ptr(instance) as usize)
            .collect();
        // Decorate-sort-undecorate: compute each instance's full comparison
        // key (space, loc, moved) exactly once, then sort the decorated
        // pairs. The key sequence is identical to the former per-comparison
        // closure's, and Rust's sort_by is stable in both forms, so the
        // resulting permutation is bit-identical — without re-hashing the
        // moved-set and re-locking both instances O(n log n) times inside
        // the comparator.
        let mut high1_guard = high1.write().unwrap();
        let mut decorated: Vec<
            (
                (crate::space::SpaceId, crate::address::Address, bool),
                Arc<RwLock<Varnode>>,
            ),
        > = std::mem::take(&mut high1_guard.instances)
                .into_iter()
                .map(|instance| {
                    let moved = moved_keys.contains(&(Arc::as_ptr(&instance) as usize));
                    let (space_id, loc) = {
                        let vn = instance.read().unwrap();
                        (vn.address_space.space_id(), vn.loc)
                    };
                    ((space_id, loc, moved), instance)
                })
                .collect();
        decorated.sort_by(|a, b| a.0.cmp(&b.0));
        high1_guard.instances = decorated.into_iter().map(|(_, instance)| instance).collect();
        drop(high1_guard);
        for instance in moved_instances {
            instance.write().unwrap().high = Some(high1.clone());
        }
        update_high_cover(high1);
        true
    }

    // Ghidra: merge.cc:1565 Merge::merge
    /// The Merge::merge primitive for the same-type speculative pass
    /// (mergeLinear): cached intersection test, moveIntersectTests, then the
    /// shared absorption — speculative, keeping the moved instances in
    /// separate merge classes (variable.cc:640-646).
    fn merge_type_pair(
        &mut self,
        fd: &Funcdata,
        high1: &Arc<RwLock<HighVariable>>,
        high2: &Arc<RwLock<HighVariable>>,
    ) -> bool {
        if Arc::ptr_eq(high1, high2) {
            return true;
        }
        if self.type_test_cache.intersection(fd, high1, high2) {
            return false;
        }
        self.type_test_cache.move_intersect_tests(high1, high2);
        self.merge_highs(high1, high2, true)
    }

    // Ghidra: merge.cc:241 Merge::mergeTestMust
    /// Test if a Varnode that MUST be merged CAN be merged. Faithful to
    /// `Merge::mergeTestMust` (merge.cc:241-247). Ghidra throws rather than
    /// silently omitting an impossible forced merge.
    fn merge_test_must(vn: &Varnode) -> Result<()> {
        if vn.has_cover() && !vn.is_implied() {
            return Ok(());
        }
        Err(anyhow!("Cannot force merge of range"))
    }

    // Ghidra: merge.cc:1657 Merge::mergeTest
    /// Test if `high` can be added to the merge group `testlist` without
    /// causing a cover intersection. Faithful to `Merge::mergeTest(high, tmplist)`
    /// (merge.cc:1657-1669). Returns true and pushes high to testlist if no
    /// intersection; false otherwise.
    ///
    /// Ghidra consults `testCache.intersection(a, high)` — the cached
    /// HighIntersectTest pair test. Rudra routes through the same
    /// `type_test_cache` (MergeTypeIntersectCache::intersection,
    /// merge.rs — HighIntersectTest port with gather_block_varnodes +
    /// test_block_intersection). The former aggregate-cover approximation
    /// is retired: it reported "intersect" for every same-block character
    /// overlap even when the instance def/read timestamps never interleave,
    /// so mergeOp Phase 2 trims converged marker ops (the +8804-op
    /// mergerequired divergence measured by the sb-impliedfold lane).
    fn merge_test_with_list(
        &mut self,
        fd: &Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        testlist: &mut Vec<Arc<RwLock<HighVariable>>>,
    ) -> bool {
        // Ghidra: if (!high->hasCover()) return false;
        // Check any instance has cover.
        let has_cov = high.read().unwrap().instances.iter().any(|v| v.read().unwrap().has_cover());
        if !has_cov {
            return false;
        }
        // Ghidra merge.cc:1662-1666: `if (testCache.intersection(a,high))
        // return false;` — the CACHED HighIntersectTest pair test, i.e.
        // `intersectList(...,2)` block candidates resolved by
        // blockIntersection (gatherBlockVarnodes + testBlockIntersection,
        // variable.cc:998) with the testCache/moveIntersectTests lifecycle.
        // The previous coarse aggregate-cover `intersect_char > 0`
        // approximation returned "intersect" for every same-block
        // character overlap, so Merge::mergeOp Phase 2 failed on marker
        // ops whose instance def/read timestamps never actually interleave,
        // sending every such MULTIEQUAL/INDIRECT through the trim loop
        // (merge.cc:748-760) — the sb-impliedfold lane measured +8804 trim
        // COPYs in main vs the oracle's +45 (COPYPROBE mergerequired
        // census), which then surfaced as the print-side
        // `uVarX = uVarX` / spill-restore copy noise.
        for other in testlist.iter() {
            if self.type_test_cache.intersection(fd, other, high) {
                return false;
            }
        }
        testlist.push(high.clone());
        true
    }

    // Ghidra: merge.hh:83 Merge::mergeForce
    /// Force-merge two varnodes into the same HighVariable.
    ///
    /// If vn1 already has a HighVariable, add vn2 to it (or vice versa).
    /// If neither has one, create a new HighVariable for both.
    pub fn merge_force(&mut self, vn1: Arc<RwLock<Varnode>>, vn2: Arc<RwLock<Varnode>>) {
        let high1 = vn1.read().unwrap().high.clone();
        let high2 = vn2.read().unwrap().high.clone();

        match (high1, high2) {
            (Some(h1), Some(h2)) => {
                // Both already have HighVariables — merge h2 into h1
                if Arc::ptr_eq(&h1, &h2) {
                    return; // Already the same
                }
                let instances: Vec<Arc<RwLock<Varnode>>> = {
                    let h2_read = h2.read().unwrap();
                    h2_read.instances.clone()
                };
                let mut h1_guard = h1.write().unwrap();
                for inst in instances {
                    h1_guard.add_instance(inst.clone());
                    drop(h1_guard);
                    inst.write().unwrap().high = Some(h1.clone());
                    h1_guard = h1.write().unwrap();
                }
                // Ghidra variable.cc:660-663 (HighVariable::mergeInternal): an
                // absorbed high's cover must fold into the survivor's — the
                // instance set changed, so mark the cover dirty for the next
                // updateCover (merge.cc:1572) to rebuild the UNION. Without
                // this the survivor keeps its pre-merge single-instance cover
                // and intersection tests use a stale premise.
                h1_guard.highflags |= crate::variable::high_internal_flags::COVERDIRTY;
            }
            (Some(h1), None) => {
                let mut h1_guard = h1.write().unwrap();
                h1_guard.add_instance(vn2.clone());
                // Same mergeInternal cover-dirty side effect (variable.cc:660-663).
                h1_guard.highflags |= crate::variable::high_internal_flags::COVERDIRTY;
                drop(h1_guard);
                vn2.write().unwrap().high = Some(h1);
            }
            (None, Some(h2)) => {
                let mut h2_guard = h2.write().unwrap();
                h2_guard.add_instance(vn1.clone());
                // Same mergeInternal cover-dirty side effect (variable.cc:660-663).
                h2_guard.highflags |= crate::variable::high_internal_flags::COVERDIRTY;
                drop(h2_guard);
                vn1.write().unwrap().high = Some(h2);
            }
            (None, None) => {
                let vn1_read = vn1.read().unwrap();
                let dt = vn1_read.v_type.clone().unwrap_or_else(|| {
                    Arc::new(Datatype::Base(TypeBase::new("undefined".to_string(), vn1_read.size, TypeMetatype::Unknown)))
                });
                drop(vn1_read);

                let high = Arc::new(RwLock::new(HighVariable::new(dt)));
                high.write().unwrap().add_instance(vn1.clone());
                high.write().unwrap().add_instance(vn2.clone());
                vn1.write().unwrap().high = Some(high.clone());
                vn2.write().unwrap().high = Some(high);
            }
        }
    }


    // ------------------------------------------------------------------
    // 9-step merge sequence (coreaction.cc:5718-5729).
    // Each method below maps to one Ghidra `Merge::` method. The steps
    // are invoked in order by `merge_all`.
    // ------------------------------------------------------------------

    // Ghidra: merge.hh:83 Merge::mergeRequired
    /// Step 1: ActionMergeRequired (coreaction.hh:369).
    /// Faithful to `data.getMerge().mergeAddrTied(); groupPartials();
    /// mergeMarker();`. This is the initial *required* merge pass that
    /// runs before cover-based speculative merging.
    ///
    ///   - `mergeAddrTied`  — Rudra's `merge_addr_tied` already implements
    ///     the address-tied grouping (Ghidra merge.cc:609).
    ///   - `groupPartials`  — CONCAT-piece grouping (merge.cc:967). Rudra has
    ///     no CONCAT/partial-root machinery yet, so this is a no-op stub.
    ///   - `mergeMarker`    — force-merge MULTIEQUAL/INDIRECT input+output
    ///     Varnodes (merge.cc:889). Implemented below.
    pub fn merge_required(&mut self, fd: &mut Funcdata) {
        // mergeAddrTied: already implemented as merge_addr_tied. In Rudra's
        // pipeline merge_all calls merge_addr_tied separately; here we only
        // add the marker merge that address-tied alone does not cover.
        self.attach(fd);
        self.group_partials(fd);
        self.merge_marker(fd);
        self.detach(fd);
    }

    // Ghidra: merge.cc:967 Merge::groupPartials
    /// Group CONCAT-piece roots.  RulePieceStructure and
    /// SplitDatatype::buildOutConcats register each unmapped CONCAT root via
    /// `registerProtoPartialRoot`; this pass rebuilds the same VariableGroup
    /// before naming (merge.cc:967-976, 1374-1407). Candidates come from the
    /// registered `protoPartial` list in registration order — the
    /// registration sites are RulePieceStructure's root walk
    /// (ruleaction.cc:7697-7698) and splitCopy/splitLoad's
    /// buildOutConcats (subflow.cc:2601-2602).
    pub fn group_partials(&mut self, fd: &mut Funcdata) {
        use std::collections::HashSet;
        let candidates: Vec<_> = fd
            .merge_state
            .proto_partial
            .iter()
            .filter_map(|op_ref| {
                // Ghidra merge.cc:970-971: dead roots were consumed or
                // destroyed since registration.
                let op = op_ref.0.read().unwrap();
                if op.is_dead() {
                    return None;
                }
                // Ghidra merge.cc:972-973: only still-flagged partial roots.
                if !op.is_partial_root() {
                    return None;
                }
                op.output.clone()
            })
            .collect();
        let mut roots = HashSet::new();
        for candidate in candidates {
            let root = Self::partial_root(&candidate).unwrap_or(candidate);
            let key = std::sync::Arc::as_ptr(&root) as usize;
            if !roots.insert(key) { continue; }
            let Some(def) = root.read().unwrap().get_def() else { continue };
            if def.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_PIECE { continue; }
            let Some(root_high) = root.read().unwrap().get_high().cloned() else { continue };
            if root_high.read().unwrap().instances.len() != 1 { continue; }
            let mut pieces = Vec::new();
            // Ghidra merge.cc:1381-1387: baseOffset comes from the root's
            // symbol entry (0 without one); gatherPieces starts at
            // (baseOffset, baseOffset), and groupWith receives
            // getTypeOffset()-baseOffset (cc:1404).
            let base_offset = root
                .read()
                .unwrap()
                .get_symbol_entry()
                .map(|entry| entry.read().unwrap().get_offset())
                .unwrap_or(0);
            Self::gather_partial_pieces(&root, &crate::op::PcodeOpRef(def), base_offset, base_offset, &mut pieces);
            if pieces.iter().all(|(piece, _)| {
                let p = piece.read().unwrap();
                p.is_proto_partial() && p.get_high().map_or(false, |h| h.read().unwrap().instances.len() == 1)
            }) {
                for (piece, offset) in pieces {
                    if let Some(high) = piece.read().unwrap().get_high().cloned() {
                        let _ = Self::group_with_arcs(&high, offset - base_offset, &root_high);
                    }
                }
            } else {
                for (piece, _) in pieces { piece.write().unwrap().clear_proto_partial(); }
            }
        }
    }

    // Ghidra: op.cc:824 PieceNode::findRoot
    fn partial_root(vn: &Arc<RwLock<crate::varnode::Varnode>>) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        let mut current = vn.clone();
        loop {
            let (addr, current_space, descendants) = {
                let v = current.read().unwrap();
                (v.get_offset(), v.get_space(), v.descend_iter().collect::<Vec<_>>())
            };
            let mut next: Option<(Arc<RwLock<crate::varnode::Varnode>>, Arc<RwLock<crate::op::PcodeOp>>)> = None;
            for op in descendants {
                let o = op.read().unwrap();
                if o.opcode != crate::opcodes::OpCode::CPUI_PIECE { continue; }
                let Some(out) = o.output.clone() else { continue };
                let slot = (0..2).find(|&i| o.inrefs.get(i).map_or(false, |x| std::sync::Arc::ptr_eq(x, &current)));
                let Some(slot) = slot else { continue };
                let other_size = o.inrefs.get(1 - slot).map(|x| x.read().unwrap().get_size()).unwrap_or(0);
                let out_space = out.read().unwrap().get_space();
                let out_addr = out.read().unwrap().get_offset();
                let adjusted = if out_space.is_big_endian() == (slot == 1) { out_addr.wrapping_add(other_size as u64) } else { out_addr };
                if adjusted != addr { continue; }
                // Rust compare_order has the same polarity as C++:
                // negative means this op strictly precedes the prior one.
                let replace = match &next {
                    None => true,
                    Some((_, previous)) => o.compare_order(&previous.read().unwrap()) < 0,
                };
                if replace { next = Some((out, op.clone())); }
            }
            match next { Some((n, _)) => current = n, None => return Some(current) }
        }
    }

    // Ghidra: op.cc:801 PieceNode::isLeaf
    /// Determine if a Varnode is a leaf within the CONCAT tree rooted at
    /// `root`. Faithful to `PieceNode::isLeaf` (op.cc:801-817): a mapped
    /// varnode under a different symbol entry than the root (a), an
    /// unwritten varnode (b), a def that is not PIECE (c), a varnode
    /// without exactly one descendant (d), or an addr-tied varnode whose
    /// address does not line up with the root at `rel_offset` (e) all
    /// make the node a leaf. Checks (b)-(d) bound `gather_partial_pieces`'s
    /// recursion: without them a non-tree PIECE graph (e.g. an input
    /// defined by the very op reading it) recurses forever and overflows
    /// the worker stack (observed on curl `main` after
    /// FUNCDATA-OPSTACKLOAD-CONTAIN-0001 unlocked RuleLoadVarnode;
    /// MERGE-GATHERPIECES-ISLEAF-0001).
    fn piece_is_leaf(
        root: &Arc<RwLock<crate::varnode::Varnode>>,
        vn: &Arc<RwLock<crate::varnode::Varnode>>,
        rel_offset: i32,
    ) -> bool {
        // (a) vn->isMapped() && rootVn->getSymbolEntry() != vn->getSymbolEntry()
        let (vn_mapped, vn_entry) = {
            let v = vn.read().unwrap();
            (v.is_mapped(), v.get_symbol_entry())
        };
        if vn_mapped {
            let root_entry = root.read().unwrap().get_symbol_entry();
            let entries_differ = match (&root_entry, &vn_entry) {
                (Some(r), Some(v)) => !Arc::ptr_eq(r, v),
                (None, None) => false,
                _ => true,
            };
            if entries_differ {
                return true;
            }
        }
        // (b) !vn->isWritten()
        let def = { vn.read().unwrap().get_def() };
        let Some(def) = def else { return true };
        // (c) def->code() != CPUI_PIECE
        if def.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_PIECE {
            return true;
        }
        // (d) vn->loneDescend() == null
        if vn.read().unwrap().lone_descend().is_none() {
            return true;
        }
        // (e) vn->isAddrTied(): Address addr = rootVn->getAddr() + relOffset;
        //     if (vn->getAddr() != addr) return true;
        if vn.read().unwrap().is_addr_tied() {
            let (v_space, v_off, r_space, r_off) = {
                let v = vn.read().unwrap();
                let r = root.read().unwrap();
                (v.get_space(), v.get_offset(), r.get_space(), r.get_offset())
            };
            if v_space != r_space || v_off != r_off.wrapping_add_signed(rel_offset as i64) {
                return true;
            }
        }
        false
    }

    // Ghidra: op.cc:865 PieceNode::gatherPieces
    /// Build the CONCAT tree rooted at the given Varnode. Faithful to
    /// `PieceNode::gatherPieces` (op.cc:865-876): walk backwards through
    /// CPUI_PIECE operations recording each input with its offset within
    /// the root's data-type, recursing only when `PieceNode::isLeaf`
    /// (op.cc:871) reports the input is an interior tree node.
    fn gather_partial_pieces(
        root: &Arc<RwLock<crate::varnode::Varnode>>,
        op: &crate::op::PcodeOpRef,
        base_offset: i32,
        root_offset: i32,
        out: &mut Vec<(Arc<RwLock<crate::varnode::Varnode>>, i32)>,
    ) {
        let (big, inputs) = {
            let r = root.read().unwrap();
            let o = op.0.read().unwrap();
            (r.get_space().is_big_endian(), o.inrefs.clone())
        };
        if inputs.len() < 2 { return; }
        let sizes = [inputs[0].read().unwrap().get_size() as i32, inputs[1].read().unwrap().get_size() as i32];
        for slot in 0..2 {
            let offset = if big == (slot == 1) { base_offset + sizes[1 - slot] } else { base_offset };
            let piece = inputs[slot].clone();
            // Ghidra op.cc:871-874: bool res = isLeaf(rootVn,vn,offset-rootOffset);
            // stack.emplace_back(op,i,offset,res); if (!res) gatherPieces(...).
            let is_leaf = Self::piece_is_leaf(root, &piece, offset - root_offset);
            out.push((piece.clone(), offset));
            if !is_leaf {
                // isLeaf=false guarantees a written PIECE def (checks b and c).
                let nested = piece.read().unwrap().get_def()
                    .expect("gather_partial_pieces: isLeaf=false guarantees a PIECE def");
                Self::gather_partial_pieces(root, &crate::op::PcodeOpRef(nested), offset, root_offset, out);
            }
        }
    }

    // Ghidra: merge.cc:889 Merge::mergeMarker
    /// Step 1c: Force-merge input and output of MULTIEQUAL and INDIRECT
    /// marker ops. Faithful to `Merge::mergeMarker` (merge.cc:889-902).
    ///
    /// For each alive marker op (that is not an indirect-creation) we
    /// force-merge its output HighVariable with each input HighVariable via
    /// `merge_op`/`merge_indirect`, which snip data-flow with
    /// `trimOpInput`/`trimOpOutput` COPY insertions until cover restrictions
    /// resolve (merge.cc:719-772). Both-piece merges cascade through the
    /// VariableGroup machinery (`merge_highs` (Some,Some) arm,
    /// variable.cc:699-711).
    pub fn merge_marker(&mut self, fd: &mut Funcdata) {
        use crate::opcodes::OpCode;
        use crate::op::pcodeop_flags;

        self.attach(fd);

        // Collect marker ops (merge.cc:894-896).
        let marker_ops: Vec<crate::op::PcodeOpRef> = fd
            .obank
            .iter_alive()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                let is_marker_op = matches!(op.opcode, OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT);
                if !op.is_marker() && !is_marker_op {
                    return None;
                }
                if op.flags & pcodeop_flags::INDIRECT_CREATION != 0 {
                    return None;
                }
                drop(op);
                Some(crate::op::PcodeOpRef(op_ref.0.clone()))
            })
            .collect();

        // Ghidra merge.cc:897-901: INDIRECT → mergeIndirect, else → mergeOp.
        for op_ref in &marker_ops {
            let is_indirect = op_ref.0.read().unwrap().opcode == OpCode::CPUI_INDIRECT;
            if is_indirect {
                self.merge_indirect(fd, op_ref);
            } else {
                self.merge_op(fd, op_ref);
            }
        }

        self.detach(fd);
    }

    // Ghidra: merge.cc:908 Merge::mergeMultiEntry
    /// Step 4: ActionMergeMultiEntry (coreaction.hh:403).
    /// Faithful to `Merge::mergeMultiEntry` (merge.cc:908-963).
    ///
    /// Ghidra iterates `data.getScopeLocal()->beginMultiEntry()..endMultiEntry()`
    /// — the set of Symbols that own more than one SymbolEntry. For each such
    /// Symbol it gathers every linked Varnode (`findLinkedVarnodes`) and merges
    /// them all into one HighVariable so the multiple storage locations of a
    /// single logical variable are represented as one.
    ///
    /// Rudra does not yet build the `ScopeLocal` multi-entry registry
    /// (`beginMultiEntry`), but Varnodes *do* carry a `mapentry` back-pointer
    /// to their `SymbolEntry` (and through it to the owning `Symbol`). So we
    /// reconstruct the multi-entry grouping directly: group live, merge-eligible
    /// Varnodes by their owning Symbol's Arc identity, and for every Symbol
    /// that owns ≥ 2 distinct SymbolEntries (the `is_multi_entry` test,
    /// `whole_count > 1`), merge all its Varnodes into one HighVariable.
    ///
    /// Per-varnode merge attempts follow merge.cc:930-961 exactly:
    /// `testCache.updateHigh` on anchor and candidate, the
    /// `mergeTestRequired(high,newHigh)` gate, then
    /// `merge(high,newHigh,false)` (anchor survives) — each failure marks the
    /// Symbol via setMergeProblems (`dispflags |= MERGE_PROBLEMS`,
    /// database.hh:240) and the candidate via setUnmerged
    /// (variable.hh:168), counts a conflict, and the run closes with Ghidra's
    /// exact warningHeader text (merge.cc:950-961). Varnodes whose covers make
    /// them simultaneously live are left in separate HighVariables (merge
    /// returns false) rather than producing an incorrect union.
    pub fn merge_multi_entry(&mut self, fd: &mut Funcdata) {
        use crate::address::Address;
        use std::collections::HashMap;

        self.attach(fd);

        // Group live, merge-eligible Varnodes by owning Symbol (Arc pointer).
        // Each entry also records its SymbolEntry's address+size so we can
        // count DISTINCT whole-sized entries per Symbol — mirroring Ghidra's
        // `symbol->numEntries()` loop (merge.cc:916-928) which skips piece
        // entries whose size != the Symbol's whole type size.
        // The owning Symbol Arc is kept in the value (keyed by its ptr) so the
        // mergeTestRequired failure path can setMergeProblems on it.
        let mut by_symbol: HashMap<
            usize, // Symbol Arc ptr
            (
                Arc<RwLock<crate::database::Symbol>>,
                Vec<(Address, usize, Arc<RwLock<Varnode>>)>, // (entry addr, size, vn)
            ),
        > = HashMap::new();

        for vn_ref in &fd.vbank.loc_tree {
            let vn_arc = vn_ref.0.clone();
            // Resolve (symbol Arc, entry addr, entry size) or skip. A Varnode
            // with no mapentry is not a symbol storage location and never
            // participates in multi-entry merging.
            let (sym_arc, entry_addr, entry_size) = {
                let vn = vn_arc.read().unwrap();
                let live = vn.is_input()
                    || self.live_set.contains(&(std::sync::Arc::as_ptr(&vn_arc) as usize));
                if !live || !Self::merge_test_basic(&vn) {
                    continue;
                }
                let me = match vn.get_symbol_entry() {
                    Some(e) => e,
                    None => continue, // No symbol mapping: not a symbol entry.
                };
                let me = me.read().unwrap();
                (me.get_symbol(), me.addr, me.size as usize)
            };
            by_symbol
                .entry(std::sync::Arc::as_ptr(&sym_arc) as usize)
                .or_insert_with(|| (sym_arc.clone(), Vec::new()))
                .1
                .push((entry_addr, entry_size, vn_arc));
        }

        // For each Symbol group with ≥ 2 distinct whole-sized entries, merge
        // all its Varnodes into one HighVariable. Faithful to merge.cc:920-961
        // (the per-SymbolEntry loop that accumulates mergeList, then the
        // mergeTestRequired/merge loop with setMergeProblems/setUnmerged
        // accounting and the warningHeader report).
        // Ghidra iterates symbols in SymbolNameTree order — (name, nameDedup)
        // (database.hh:366-370); HashMap iteration is arbitrary, so collect
        // and sort by the same comparator for a deterministic traversal.
        let mut groups: Vec<(Arc<RwLock<crate::database::Symbol>>, Vec<(Address, usize, Arc<RwLock<Varnode>>)>)> =
            by_symbol
                .into_iter()
                .map(|(_, (sym, entries))| (sym, entries))
                .collect();
        groups.sort_by(|a, b| {
            let sa = a.0.read().unwrap();
            let sb = b.0.read().unwrap();
            (sa.name.clone(), sa.name_dedup).cmp(&(sb.name.clone(), sb.name_dedup))
        });
        for (sym_arc, group) in &groups {
            // Distinct entries (by addr) — Ghidra counts whole-sized entries.
            let distinct_entries: std::collections::HashSet<u64> = group
                .iter()
                .map(|(a, _, _)| a.as_u64())
                .collect();
            if distinct_entries.len() < 2 {
                continue; // Not multi-entry for this Symbol.
            }
            // Ghidra uses mergeList[0]->getHigh() as the merge anchor and
            // attempts merge(anchor, vn, false) for each subsequent vn. We
            // take the first vn as the anchor and merge each other vn's High.
            let group: Vec<Arc<RwLock<Varnode>>> =
                group.iter().map(|(_, _, vn)| vn.clone()).collect();
            // merge.cc:930-931: high = mergeList[0]->getHigh();
            // testCache.updateHigh(high);
            let Some(anchor_high) = group[0].read().unwrap().high.clone() else {
                continue;
            };
            self.type_test_cache.update_high(&anchor_high);
            let mut merge_count: i32 = 0;
            let mut conflict_count: i32 = 0;
            for vn_arc in group.iter().skip(1) {
                // merge.cc:933-935: newHigh = mergeList[i]->getHigh();
                // if (newHigh == high) continue; testCache.updateHigh(newHigh);
                let Some(new_high) = vn_arc.read().unwrap().high.clone() else {
                    continue;
                };
                if Arc::ptr_eq(&new_high, &anchor_high) {
                    continue; // Varnodes already merged
                }
                self.type_test_cache.update_high(&new_high);
                // merge.cc:936-941: required-test gate — on failure mark the
                // symbol and the unmerged high, count the conflict, continue.
                if !self.merge_test_required(&anchor_high, &new_high) {
                    sym_arc
                        .write()
                        .unwrap()
                        .dispflags |= crate::database::display_flags::MERGE_PROBLEMS;
                    new_high.write().unwrap().set_unmerged();
                    conflict_count += 1;
                    continue;
                }
                // merge.cc:942-947: attempt the (non-speculative) merge —
                // ANCHOR survives (merge(high, newHigh, false)); failure marks
                // the symbol/high and counts the conflict too.
                if !self.merge_speculative(fd, &anchor_high, &new_high, false) {
                    sym_arc
                        .write()
                        .unwrap()
                        .dispflags |= crate::database::display_flags::MERGE_PROBLEMS;
                    new_high.write().unwrap().set_unmerged();
                    conflict_count += 1;
                    continue;
                }
                merge_count += 1;
            }
            // merge.cc:950-961: report unfused symbols via warningHeader.
            // skipCount is always 0 here: Rudra reconstructs the symbol list
            // from Varnodes' mapentries, so SymbolEntries with no linked
            // Varnode (Ghidra's skipCount source) are invisible upstream of
            // this loop (no ScopeLocal multi-entry registry).
            let skip_count = 0;
            if skip_count != 0 || conflict_count != 0 {
                let mut msg = String::from("Unable to");
                if merge_count != 0 {
                    msg.push_str(" fully");
                }
                msg.push_str(" merge symbol: ");
                msg.push_str(sym_arc.read().unwrap().get_name());
                if skip_count > 0 {
                    msg.push_str(" -- Some instance varnodes not found.");
                }
                if conflict_count > 0 {
                    msg.push_str(" -- Some merges are forbidden");
                }
                fd.warning_header(&msg);
            }
        }
        self.detach(fd);
    }

    /// Step 5: ActionMergeCopy (coreaction.hh:392).
    /// Faithful to `Merge::mergeOpcode(CPUI_COPY)` (merge.cc:326-350).
    ///
    /// For each alive COPY op, try to merge each input HighVariable with the
    /// output HighVariable. The merge is *required* (Ghidra calls
    /// `mergeTestRequired` then a non-speculative `merge`), but a cover
    // Ghidra: merge.cc:326 Merge::mergeOpcode
    /// Try to merge the input and output Varnodes of every op with the given
    /// opcode. Faithful to `Merge::mergeOpcode` (merge.cc:326-350).
    ///
    /// Walks basic blocks in linear order; for each op matching `opc`, if
    /// `mergeTestBasic` passes for output and each input, and
    /// `mergeTestRequired` passes for their HighVariables, calls
    /// `merge(high_out, high_in, false)`. Cover intersection causes the merge
    /// to be silently skipped (merge() returns false) — NO snip, NO copyTrims.
    pub fn merge_opcode(&mut self, fd: &mut Funcdata, opc: crate::opcodes::OpCode) {
        self.attach(fd);

        let n_blocks = fd.bblocks.get_size();
        for i in 0..n_blocks {
            let bl = match fd.bblocks.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let ops: Vec<crate::op::PcodeOpRef> = {
                let bl_rg = bl.read().unwrap();
                bl_rg.get_ops()
            };
            for op_ref in &ops {
                let (vn1_arc, inputs): (Option<Arc<RwLock<Varnode>>>, Vec<Arc<RwLock<Varnode>>>) = {
                    let op = op_ref.0.read().unwrap();
                    if op.opcode != opc {
                        continue;
                    }
                    let out = op.output.clone();
                    let ins: Vec<Arc<RwLock<Varnode>>> =
                        op.inrefs.iter().cloned().collect();
                    (out, ins)
                };
                let Some(vn1_arc) = vn1_arc else { continue };
                // mergeTestBasic on output (merge.cc:341)
                if !Self::merge_test_basic(&vn1_arc.read().unwrap()) {
                    continue;
                }
                let high_out = {
                    let vn1 = vn1_arc.read().unwrap();
                    vn1.high.clone()
                };
                let Some(high_out) = high_out else { continue };
                // For each input: mergeTestBasic + mergeTestRequired + merge
                for vn2_arc in &inputs {
                    if !Self::merge_test_basic(&vn2_arc.read().unwrap()) {
                        continue;
                    }
                    let high_in = {
                        let vn2 = vn2_arc.read().unwrap();
                        vn2.high.clone()
                    };
                    let Some(high_in) = high_in else { continue };
                    // mergeTestRequired — pure property test, no cover check
                    let req_ok = self.merge_test_required(&high_out, &high_in);
                    if !req_ok {
                        continue;
                    }
                    // merge(high_out, high_in, false) — cover intersection
                    // returns false (skip), never snips (merge.cc:1565-1575).
                    // merge.cc:346: merge(vn1->getHigh(), vn2->getHigh(), false)
                    // — output-side survivor, required (non-speculative).
                    let _ = self.merge_speculative(fd, &high_out, &high_in, false);
                }
            }
        }

        self.detach(fd);
    }

    // RUDRA-GLUE: Funcdata::newUnique's assignHigh half (funcdata_varnode.cc:89).
    /// Ghidra's `Funcdata::newUnique` assigns a HighVariable to the fresh
    /// unique Varnode immediately (`vbank.createUnique` + `assignHigh`,
    /// funcdata_varnode.cc:88-89). Rudra's `Funcdata::new_unique` leaves the
    /// Varnode high-less, so the merge-family trim paths that allocate
    /// uniques (`allocate_copy_trim`, `build_dominant_copy`'s dominant COPY)
    /// wire the High here exactly as `set_high_level` does — otherwise the
    /// follow-up merges (mergeIndirect merge.cc:879, mergeOp :766,
    /// buildDominantCopy :1236) silently no-op on a None high, and mergeOp's
    /// phase-2 cover loop (:745) treats the trim input as a hard failure and
    /// over-trims.
    fn wire_unique_high(fd: &Funcdata, out_vn: &Arc<RwLock<Varnode>>) {
        if out_vn.read().unwrap().high.is_some() {
            return;
        }
        let dt = out_vn.read().unwrap().v_type.clone().unwrap_or_else(|| {
            std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
                crate::type_system::datatype::TypeBase::new(
                    "undefined".to_string(),
                    out_vn.read().unwrap().size,
                    crate::type_system::datatype::TypeMetatype::Unknown,
                ),
            ))
        });
        let high = Arc::new(RwLock::new(HighVariable::new(dt)));
        high.write().unwrap().add_instance(out_vn.clone());
        out_vn.write().unwrap().high = Some(high);
        let _ = fd;
    }

    // Ghidra: merge.cc:411 Merge::allocateCopyTrim
    /// Allocate COPY PcodeOp designed to trim an overextended Cover.
    /// Faithful to `Merge::allocateCopyTrim` (merge.cc:411-434).
    ///
    /// **Union resolution path omitted** (merge.cc:417-428): Ghidra resolves
    /// union field types via `inheritResolution`/`forceFacingType`/`getUnionField`.
    /// Rudra has no union-resolution infrastructure; this path is skipped
    /// (the COPY is created without union field forcing — conservative).
    /// The base data-type carry (cc:416 `ct = inVn->getType()` → cc:429
    /// `newUnique(inVn->getSize(),ct)`) is NOT part of that omission: the
    /// trim COPY's output varnode observes the input varnode's data-type.
    fn allocate_copy_trim(
        &mut self,
        fd: &mut Funcdata,
        in_vn: &Arc<RwLock<Varnode>>,
        addr: crate::address::Address,
        _trim_op: &crate::op::PcodeOpRef,
    ) -> crate::op::PcodeOpRef {
        let copy_op = fd.new_op(1, addr);
        fd.op_set_opcode(&copy_op, crate::opcodes::OpCode::CPUI_COPY);
        let size = in_vn.read().unwrap().size;
        // cc:416/429: ct = inVn->getType(); outVn = newUnique(size, ct)
        let ct = in_vn.read().unwrap().v_type.clone();
        // new_unique_typed returns a free Varnode with ct as its data-type.
        let out_vn = fd.new_unique_typed(size, ct);
        Self::wire_unique_high(fd, &out_vn);
        fd.op_set_output(&copy_op, out_vn);
        fd.op_set_input(&copy_op, in_vn.clone(), 0);
        self.copy_trims.push(copy_op.clone());
        copy_op
    }

    // Ghidra: merge.cc:443 Merge::snipReads
    /// Truncate the data-flow for `vn` by creating a COPY from `vn` into a new
    /// temporary Varnode, then replacing the reads of `vn` in `marked_ops`
    /// with reads of the temporary.
    /// Faithful to `Merge::snipReads` (merge.cc:443-480).
    fn snip_reads(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        marked_ops: &[crate::op::PcodeOpRef],
    ) {
        if marked_ops.is_empty() {
            return;
        }
        // Figure out where the copy is inserted (merge.cc:453-467).
        let (insert_begin_bb, after_op) = {
            let vn_rg = vn.read().unwrap();
            if vn_rg.is_input() {
                // Input varnode: insert at begin of block 0.
                let bb0 = fd.bblocks.get_block(0);
                (bb0, None::<crate::op::PcodeOpRef>)
            } else {
                // Defined varnode: insert after its def op (or after the op
                // causing the effect if def is INDIRECT).
                let def_arc = vn_rg.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(def) => {
                        let def_op = crate::op::PcodeOpRef(def.clone());
                        let after = {
                            let d = def.read().unwrap();
                            if d.opcode == crate::opcodes::OpCode::CPUI_INDIRECT {
                                // Snip must come after the op CAUSING the effect,
                                // not the INDIRECT itself (merge.cc:462-464).
                                // in(1) is an iop-space const varnode encoding the
                                // target op address; get_op_from_const resolves it.
                                d.get_in(1).and_then(|vn2| {
                                    fd.get_op_from_const(vn2)
                                })
                            } else {
                                Some(crate::op::PcodeOpRef(def.clone()))
                            }
                        };
                        (None, after.or(Some(def_op)))
                    }
                    None => {
                        // No def but not input: insert at block 0 begin.
                        let bb0 = fd.bblocks.get_block(0);
                        (bb0, None)
                    }
                }
            }
        };
        // pc = address of the insertion point (merge.cc:450/456/461).
        // cc:456 (input branch): pc = bl->getStart() — the insert-begin
        // block's start address. cc:461 (defined branch): pc = def's SeqNum
        // addr; for an INDIRECT def, newIndirectOp (funcdata_op.cc:691)
        // mints the INDIRECT with the effect op's addr, so after_op's addr
        // equals the def's addr on every reachable path.
        let pc = if let Some(ao) = &after_op {
            ao.0.read().unwrap().get_addr()
        } else {
            insert_begin_bb
                .as_ref()
                .map(|bb| bb.read().unwrap().get_start_addr())
                .unwrap_or_else(|| crate::address::Address::new(0))
        };
        let copyop = self.allocate_copy_trim(fd, vn, pc, &marked_ops[0]);
        // Insert the COPY into the P-code stream.
        if let Some(bb) = &insert_begin_bb {
            fd.op_insert_begin(&copyop, bb);
        } else if let Some(ao) = &after_op {
            fd.op_insert_after(&copyop, ao);
        }
        // Replace each marked op's read of vn with the COPY's output.
        let copy_out = copyop.0.read().unwrap().output.clone();
        let Some(copy_out) = copy_out else { return };
        for mop in marked_ops {
            let slot = {
                let m = mop.0.read().unwrap();
                // Find which input slot holds vn (by Arc ptr eq).
                m.inrefs.iter().position(|v| Arc::ptr_eq(v, vn))
            };
            if let Some(slot) = slot {
                fd.op_set_input(mop, copy_out.clone(), slot);
            }
        }
    }

    // Ghidra: merge.cc:489 Merge::eliminateIntersect
    /// For each reader of `vn`, check if its single-read cover intersects any
    /// other Varnode in `blocksort` (same storage). If so, mark the reader for
    /// snipping. Then call `snip_reads`.
    /// Faithful to `Merge::eliminateIntersect` (merge.cc:489-571).
    // RUDRA-GLUE: returns the marked-read count (Ghidra's eliminateIntersect
    // returns void) so the [UNIFY] diagnostic can print a direct marked=
    // field without re-deriving it; pure diagnostic return, callers ignore
    // it when RUDRA_MERGE_DIAG is unset.
    fn eliminate_intersect(
        &mut self,
        fd: &mut Funcdata,
        vn: &Arc<RwLock<Varnode>>,
        blocksort: &[BlockVarnode],
    ) -> usize {
        let marked_ops: Vec<crate::op::PcodeOpRef> = {
            // Collect descendant (reader) ops of vn.
            let descend: Vec<crate::op::PcodeOpRef> = {
                let v = vn.read().unwrap();
                v.descend.iter().filter_map(|w| w.upgrade()).map(|a| crate::op::PcodeOpRef(a)).collect()
            };
            let mut marked = Vec::new();
            for op_ref in &descend {
                let mut insertop = false;
                // Build a single-read cover: addDefPoint(vn) + addRefPoint(op,vn)
                // (merge.cc:501-505 `Cover single; single.addDefPoint(vn);
                // single.addRefPoint(op,vn)`). The op-based cover.cc entries
                // carry the marker/sentinel endpoint semantics (cover.cc:29-49
                // getUIndex, cover.cc:501-519 addDefPoint) and — decisive for
                // the INPUT varnode, whose single cover must reach from the
                // block-0 input sentinel back through every predecessor block
                // to the read — addRefPoint's CFG recursion (cover.cc:565-612
                // addRefPoint / cover.cc:524-558 addRefRecurse). The
                // order-domain add_def_point/add_ref_point entries express
                // neither: with them the single cover held only the read's
                // own block, guard defs in intermediate blocks were never
                // contained, reads the oracle snips stayed un-snipped, and
                // mergeRangeMust threw "Forced merge caused intersection"
                // (merge.cc:315).
                let mut single = Cover::new();
                let (vn_def, vn_is_input) = {
                    let v = vn.read().unwrap();
                    (v.def.as_ref().and_then(|w| w.upgrade()), v.is_input())
                };
                single.add_def_point_full(vn_def.as_ref(), vn_is_input);
                let mut scratch_roots = Vec::new();
                let mut scratch_stack = Vec::new();
                single.add_ref_point_full(&op_ref.0, vn, &mut scratch_roots, &mut scratch_stack);
                // Iterate over each block in the single-read cover.
                for (&blocknum, _cb) in &single.blocks {
                    let Some(mut slot) = BlockVarnode::find_front(blocknum, blocksort) else {
                        continue;
                    };
                    while slot < blocksort.len() {
                        if blocksort[slot].block_index != blocknum {
                            break;
                        }
                        let vn2_arc = blocksort[slot].vn.clone();
                        slot += 1;
                        if Arc::ptr_eq(&vn2_arc, vn) {
                            continue;
                        }
                        // boundtype = single.containVarnodeDef(vn2)
                        // (merge.cc:519 → cover.cc:441-462). The def point's
                        // comparison index goes through CoverBlock::getUIndex
                        // (cover.cc:29-49): MULTIEQUAL defs map to 0 (very
                        // beginning), INDIRECT defs to the order of the op
                        // they guard (PcodeOp::getOpFromConst(in(1))), normal
                        // ops to their own SeqNum order. varnode_def_loc's
                        // plain get_seq_num().order misses both marker rules.
                        let (blk2, ord2, is_in2) = {
                            let v2 = vn2_arc.read().unwrap();
                            match v2.def.as_ref().and_then(|w| w.upgrade()) {
                                Some(d) => {
                                    let dr = d.read().unwrap();
                                    let blk = dr
                                        .parent
                                        .as_ref()
                                        .and_then(|p| p.upgrade())
                                        .map(|p| p.read().unwrap().get_index())
                                        .unwrap_or(0);
                                    let ord = if dr.get_opcode()
                                        == crate::opcodes::OpCode::CPUI_INDIRECT
                                    {
                                        // cover.cc:41-43: INDIRECT marker →
                                        // guarded op's order. fd is in scope
                                        // here (unlike CoverEndpoint::from_op),
                                        // so resolve the exact target order.
                                        match dr.get_in(1).and_then(|c| fd.get_op_from_const(c)) {
                                            Some(t) => {
                                                t.0.read().unwrap().get_seq_num().get_order()
                                            }
                                            None => crate::cover::CoverBlock::get_u_index(&dr),
                                        }
                                    } else {
                                        crate::cover::CoverBlock::get_u_index(&dr)
                                    };
                                    (blk, ord, false)
                                }
                                None => (0, 0, v2.is_input()),
                            }
                        };
                        let boundtype = single.contain_varnode_def_at(is_in2, blk2, ord2);
                        if boundtype == 0 {
                            continue;
                        }
                        let overlaptype = {
                            let v = vn.read().unwrap();
                            let v2 = vn2_arc.read().unwrap();
                            v.characterize_overlap(&v2)
                        };
                        if overlaptype == 0 {
                            continue; // No storage overlap
                        }
                        if overlaptype == 1 {
                            // Partial overlap: check partialCopyShadow.
                            let off = {
                                let v = vn.read().unwrap();
                                let v2 = vn2_arc.read().unwrap();
                                (v.get_offset() as i64 - v2.get_offset() as i64) as i32
                            };
                            if vn.read().unwrap().partial_copy_shadow(&vn2_arc.read().unwrap(), off) {
                                continue;
                            }
                        }
                        // boundtype==2 / ==3 disambiguation (merge.cc:528-562):
                        // For boundtype==2, resolve same-place definitions by
                        // seqnum order; for boundtype==3 (tail), require
                        // addrforce + INDIRECT linkage. Conservative: treat as
                        // intersection (insertop=true) unless clearly not.
                        // This is a faithful-but-simplified subset; full
                        // disambiguation logic ported below.
                        if boundtype == 2 {
                            // merge.cc:528-541
                            let vn2_def = vn2_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                            let vn_def = vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                            let skip = match (vn2_def, vn_def) {
                                (None, None) => {
                                    // Both inputs: arbitrary order. Ghidra: if (vn < vn2) continue;
                                    // Compare by Arc pointer value as usize.
                                    (std::sync::Arc::as_ptr(vn) as usize)
                                        < (std::sync::Arc::as_ptr(&vn2_arc) as usize)
                                }
                                (None, Some(_)) => true,  // vn2 has no def, vn does → skip
                                (Some(_), None) => false,
                                (Some(d2), Some(d1)) => {
                                    d2.read().unwrap().get_seq_num().order
                                        < d1.read().unwrap().get_seq_num().order
                                }
                            };
                            if skip {
                                continue;
                            }
                        } else if boundtype == 3 {
                            // merge.cc:543-562 (full port; previously
                            // truncated at the addrforce check — the tail
                            // guards below sat on a dead path until the
                            // heritage guard's addrforce marking landed):
                            // a tail intersection only counts when vn2's
                            // write is an INDIRECT marking the READING op
                            // itself, and the INDIRECT's input does not
                            // shadow vn.
                            let vn2_def = {
                                let v2 = vn2_arc.read().unwrap();
                                if !v2.is_addr_force() {
                                    continue; // cc:549
                                }
                                v2.def.as_ref().and_then(|w| w.upgrade())
                            };
                            // cc:550 if (!vn2->isWritten()) continue;
                            let vn2_def = match vn2_def {
                                Some(d) => d,
                                None => continue,
                            };
                            // cc:551-552 if (indop->code() != CPUI_INDIRECT) continue;
                            if vn2_def.read().unwrap().opcode != crate::opcodes::OpCode::CPUI_INDIRECT {
                                continue;
                            }
                            // cc:554 The vn2 INDIRECT must be linked to the
                            // read op: op == PcodeOp::getOpFromConst(
                            //   indop->getIn(1)->getAddr()).
                            let ind_target = {
                                let d = vn2_def.read().unwrap();
                                d.get_in(1)
                                    .and_then(|c| fd.get_op_from_const(c))
                            };
                            let linked = ind_target
                                .map(|t| Arc::ptr_eq(&t.0, &op_ref.0))
                                .unwrap_or(false);
                            if !linked {
                                continue;
                            }
                            // cc:555-561 shadow checks against the
                            // INDIRECT's input (in(0)).
                            let ind_in0 = {
                                let d = vn2_def.read().unwrap();
                                d.get_in(0).cloned()
                            };
                            if let Some(shadow_vn) = ind_in0 {
                                if overlaptype != 1 {
                                    if vn.read().unwrap().copy_shadow(&shadow_vn.read().unwrap()) {
                                        continue;
                                    }
                                } else {
                                    let off = {
                                        let v = vn.read().unwrap();
                                        let v2 = vn2_arc.read().unwrap();
                                        (v.get_offset() as i64 - v2.get_offset() as i64) as i32
                                    };
                                    if vn
                                        .read()
                                        .unwrap()
                                        .partial_copy_shadow(&shadow_vn.read().unwrap(), off)
                                    {
                                        continue;
                                    }
                                }
                            }
                        }
                        insertop = true;
                        break;
                    }
                    if insertop {
                        break;
                    }
                }
                if insertop {
                    marked.push(op_ref.clone());
                }
            }
            marked
        };
        let marked_count = marked_ops.len();
        self.snip_reads(fd, vn, &marked_ops);
        marked_count
    }

    // Ghidra: merge.cc:581 Merge::unifyAddress
    /// Make sure all Varnodes with the same storage address and size can be
    /// merged. Any discovered intersection is snipped.
    /// Faithful to `Merge::unifyAddress` (merge.cc:581-601).
    fn unify_address(&mut self, fd: &mut Funcdata, group: &[Arc<RwLock<Varnode>>]) {
        // Build blocksort: BlockVarnode per non-free vn, sorted by block index.
        let mut blocksort: Vec<BlockVarnode> =
            group.iter().map(|a| BlockVarnode::set(a.clone())).collect();
        blocksort.sort();
        // eliminateIntersect for each vn in the group.
        let vns: Vec<Arc<RwLock<Varnode>>> = group.to_vec();
        for vn in &vns {
            let diag = std::env::var("RUDRA_MERGE_DIAG").is_ok()
                && vn.read().unwrap().get_space() == crate::space::AddressSpace::Ram;
            let pre_desc = if diag {
                vn.read()
                    .unwrap()
                    .descend
                    .iter()
                    .filter(|w| w.strong_count() > 0)
                    .count()
            } else {
                0
            };
            let pre_ops = if diag { fd.obank.optree.len() } else { 0 };
            let marked_count = self.eliminate_intersect(fd, vn, &blocksort);
            // Registered debug TAG [UNIFY] (stderr, env-gated by
            // RUDRA_MERGE_DIAG; registry: docs/api/merge.md "诊断 TAG
            // 登记"). One line per Ram varnode: readers, snipped readers
            // (marked), op-bank delta and flags. The marked= field is the
            // direct snip-read count, comparable 1:1 with the oracle's
            // [ORE-MARK] probe lines (one per marked op).
            if diag {
                let r = vn.read().unwrap();
                eprintln!(
                    "[UNIFY] vn@{:#x}/{} def={:?} descend={} marked={} ops_delta={} flags={:#x}",
                    r.get_offset(),
                    r.get_size(),
                    r.get_def().map(|d| {
                        let dr = d.read().unwrap();
                        format!("{:?}@{:#x}", dr.opcode, dr.get_addr().as_u64())
                    }),
                    pre_desc,
                    marked_count,
                    fd.obank.optree.len().saturating_sub(pre_ops),
                    r.flags,
                );
            }
        }
    }

    // Ghidra: merge.cc:692 Merge::trimOpInput
    /// Trim the input HighVariable of the given op so its Cover is tiny.
    /// Faithful to `Merge::trimOpInput` (merge.cc:692-712). Inserts a COPY
    /// (via allocateCopyTrim → fills copy_trims) before the op, replacing the
    /// slot input with the COPY's output.
    fn trim_op_input(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef, slot: usize) {
        use crate::opcodes::OpCode;
        // Determine pc (merge.cc:699-704).
        let (pc, multiequal_in_block) = {
            let o = op.0.read().unwrap();
            if o.opcode == OpCode::CPUI_MULTIEQUAL {
                // pc = parent->getIn(slot)->getStop()
                let in_block = o
                    .parent
                    .as_ref()
                    .and_then(|w| w.upgrade())
                    .and_then(|parent| {
                        let p = parent.read().unwrap();
                        let bank = p.bank();
                        p.get_in(slot).and_then(|e| Some(bank.expect_arc(e.point)))
                    });
                match &in_block {
                    Some(blk) => {
                        let rg = blk.read().unwrap();
                        match rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                            Some(bb) => (bb.get_stop_addr(), Some(blk.clone())),
                            None => (crate::address::Address::new(0), Some(blk.clone())),
                        }
                    }
                    None => (o.get_addr(), None),
                }
            } else {
                (o.get_addr(), None)
            }
        };
        let vn = {
            let o = op.0.read().unwrap();
            o.inrefs.get(slot).cloned()
        };
        let Some(vn) = vn else { return };
        let copyop = self.allocate_copy_trim(fd, &vn, pc, op);
        let copy_out = copyop.0.read().unwrap().output.clone();
        let Some(copy_out) = copy_out else { return };
        fd.op_set_input(op, copy_out, slot);
        if let Some(blk) = multiequal_in_block {
            fd.op_insert_end(&copyop, &blk);
        } else {
            fd.op_insert_before(&copyop, op);
        }
    }

    // Ghidra: merge.cc:656 Merge::trimOpOutput
    /// Trim the output HighVariable of the given op so its Cover is tiny.
    /// Faithful to `Merge::trimOpOutput` (merge.cc:656-682). Moves the op's
    /// output to a stubby unique, then creates a COPY after the op that
    /// reproduces the original output. Does NOT fill copy_trims (uses raw newOp).
    fn trim_op_output(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        // Determine afterop (merge.cc:663-666).
        let after_op = {
            let o = op.0.read().unwrap();
            if o.opcode == OpCode::CPUI_INDIRECT {
                o.get_in(1).and_then(|vn2| fd.get_op_from_const(vn2))
            } else {
                Some(crate::op::PcodeOpRef(op.0.clone()))
            }
        };
        let vn = {
            let o = op.0.read().unwrap();
            o.output.clone()
        };
        let Some(vn) = vn else { return };
        let op_addr = op.0.read().unwrap().get_addr();
        let copyop = fd.new_op(1, op_addr);
        fd.op_set_opcode(&copyop, OpCode::CPUI_COPY);
        // cc:668/677: Datatype *ct = vn->getType() (read BEFORE any
        // rewiring); uniq = data.newUnique(vn->getSize(),ct).
        let (size, ct) = {
            let v = vn.read().unwrap();
            (v.size, v.v_type.clone())
        };
        let uniq = fd.new_unique_typed(size, ct);
        // op output → uniq; copyop output → original vn; copyop input → uniq.
        fd.op_set_output(op, uniq.clone());
        fd.op_set_output(&copyop, vn);
        fd.op_set_input(&copyop, uniq, 0);
        if let Some(ao) = &after_op {
            fd.op_insert_after(&copyop, ao);
        }
    }

    // Ghidra: merge.cc:719 Merge::mergeOp
    /// Force-merge all input and output Varnodes for the given op.
    /// Faithful to `Merge::mergeOp` (merge.cc:719-772). Snips data-flow via
    /// trimOpInput/trimOpOutput until cover restrictions are resolved, then
    /// force-merges.
    fn merge_op(&mut self, fd: &mut Funcdata, op: &crate::op::PcodeOpRef) {
        use crate::opcodes::OpCode;
        let (max, high_out) = {
            let o = op.0.read().unwrap();
            let max = if o.opcode == OpCode::CPUI_INDIRECT { 1 } else { o.num_input() };
            let out_vn = o.output.clone();
            (max, out_vn)
        };
        let Some(out_vn) = high_out else { return };
        let high_out_arc = out_vn.read().unwrap().high.clone();
        let Some(high_out_arc) = high_out_arc else { return };

        // Phase 1: non-cover mergeTestRequired restrictions (merge.cc:730-741).
        // Both `op->getIn(i)` (cc:731) and `op->getIn(j)` (cc:737) are live
        // reads: a trim of an earlier slot replaces that slot's Varnode (and
        // its HighVariable, fresh via allocateCopyTrim's wire_unique_high)
        // mid-loop, so later slots must be tested against the POST-trim high,
        // not a pre-loop snapshot.
        for i in 0..max {
            let high_in = op.0.read().unwrap().inrefs.get(i).and_then(|v| v.read().unwrap().high.clone());
            let Some(high_in) = high_in else { continue };
            if !self.merge_test_required(&high_out_arc, &high_in) {
                self.trim_op_input(fd, op, i);
                continue;
            }
            // Check against earlier inputs (merge.cc:736-740).
            let mut conflict = false;
            for j in 0..i {
                let high_j = op.0.read().unwrap().inrefs.get(j).and_then(|v| v.read().unwrap().high.clone());
                if let Some(hj) = high_j {
                    if !self.merge_test_required(&hj, &high_in) {
                        conflict = true;
                        break;
                    }
                }
            }
            if conflict {
                self.trim_op_input(fd, op, i);
            }
        }

        // Phase 2: cover restriction test (merge.cc:743-761).
        // Re-read inputs (may have changed after trims).
        let inputs2: Vec<Arc<RwLock<Varnode>>> = op.0.read().unwrap().inrefs.iter().cloned().collect();
        let high_out_arc2 = out_vn.read().unwrap().high.clone();
        if let Some(ho) = high_out_arc2 {
            let mut testlist: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
            self.merge_test_with_list(fd, &ho, &mut testlist);
            let mut i = 0;
            for inp in inputs2.iter().take(max) {
                let high_in = inp.read().unwrap().high.clone();
                match high_in {
                    Some(hi) => {
                        if !self.merge_test_with_list(fd, &hi, &mut testlist) {
                            break;
                        }
                    }
                    None => break,
                }
                i += 1;
            }
            if i != max {
                // Cover restrictions: iteratively trim inputs.
                let mut nexttrim = 0;
                while nexttrim < max {
                    self.trim_op_input(fd, op, nexttrim);
                    testlist.clear();
                    self.merge_test_with_list(fd, &ho, &mut testlist);
                    let mut all_ok = true;
                    for k in 0..max {
                        let inp_k = op.0.read().unwrap().inrefs.get(k).cloned();
                        match inp_k {
                            Some(vn) => {
                                let hi = vn.read().unwrap().high.clone();
                                match hi {
                                    Some(h) => {
                                        if !self.merge_test_with_list(fd, &h, &mut testlist) {
                                            all_ok = false;
                                        }
                                    }
                                    None => {}
                                }
                            }
                            None => {}
                        }
                    }
                    if all_ok {
                        break;
                    }
                    nexttrim += 1;
                }
                if nexttrim == max {
                    self.trim_op_output(fd, op);
                }
            }
        }

        // Phase 3: real merge (merge.cc:763-771).
        for i in 0..max {
            let (ho, hi) = {
                let o = op.0.read().unwrap();
                let out = o.output.as_ref().and_then(|v| v.read().unwrap().high.clone());
                let inp = o.inrefs.get(i).and_then(|v| v.read().unwrap().high.clone());
                (out, inp)
            };
            match (ho, hi) {
                (Some(ho_arc), Some(hi_arc)) => {
                    if !self.merge_test_required(&ho_arc, &hi_arc) {
                        eprintln!("[MERGE] non-cover restriction violated despite trims");
                        continue;
                    }
                    // merge(high_out, high_in, false) — cover intersect → skip.
                    // merge.cc:766: merge(out->getHigh(), in->getHigh(), false).
                    let _ = self.merge_speculative(fd, &ho_arc, &hi_arc, false);
                }
                _ => {}
            }
        }
    }

    // Ghidra: merge.cc:783 Merge::collectInputs
    /// Collect (op, slot) pairs of Varnode instances of `high` (or of pieces in
    /// `high`'s VariableGroup) that are inputs to `op` and to the chain of
    /// INDIRECT ops immediately preceding it. Faithful to `Merge::collectInputs`
    /// (merge.cc:783-802): the walk starts at the effect op and continues over
    /// `previousOp` while that predecessor is an INDIRECT. Annotation inputs are
    /// skipped (merge.cc:792). Used by snip_output_interference.
    fn collect_inputs(
        &self,
        fd: &Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        op: &crate::op::PcodeOpRef,
    ) -> Vec<(crate::op::PcodeOpRef, usize)> {
        // merge.cc:786-788: group = high->piece ? high->piece->getGroup() : null
        let group = high
            .read()
            .unwrap()
            .piece
            .as_ref()
            .and_then(|p| p.read().unwrap().group.clone());
        let mut oplist = Vec::new();
        let mut cur = Some(op.clone());
        loop {
            // merge.cc:790-797: scan all input slots of the current op.
            let Some(o_ref) = cur else { break };
            let num = o_ref.0.read().unwrap().num_input();
            for i in 0..num {
                let Some(in_vn) = o_ref.0.read().unwrap().get_in(i).cloned() else {
                    continue;
                };
                let (is_annotation, test_high) = {
                    let vn = in_vn.read().unwrap();
                    (vn.is_annotation(), vn.high.clone())
                };
                if is_annotation {
                    continue;
                }
                // Ghidra: testHigh == high || (testHigh->piece != 0 &&
                // testHigh->piece->getGroup() == group)  (merge.cc:793-796).
                // A Varnode with no High in Rudra cannot match either arm.
                let Some(test_high) = test_high else { continue };
                if Arc::ptr_eq(&test_high, high) {
                    oplist.push((o_ref.clone(), i));
                    continue;
                }
                if let Some(group) = &group {
                    let same_group = test_high
                        .read()
                        .unwrap()
                        .piece
                        .as_ref()
                        .and_then(|p| p.read().unwrap().group.clone())
                        .map(|g| Arc::ptr_eq(&g, group))
                        .unwrap_or(false);
                    if same_group {
                        oplist.push((o_ref.clone(), i));
                    }
                }
            }
            // merge.cc:798-801: op = op->previousOp(); break when null or the
            // predecessor is not an INDIRECT.
            let prev = {
                let o = o_ref.0.read().unwrap();
                o.previous_op_in_block(&fd.obank)
            };
            cur = match prev {
                Some(p) if p.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_INDIRECT => {
                    Some(p)
                }
                _ => break,
            };
        }
        oplist
    }

    // Ghidra: merge.cc:811 Merge::snipOutputInterference
    /// Snip instances of the INDIRECT output's HighVariable that are also
    /// inputs to the underlying PcodeOp (the op causing the indirect effect).
    /// Faithful to `Merge::snipOutputInterference` (merge.cc:811-839): collect
    /// the offending (op, slot) reads via collectInputs, sort them grouped by
    /// HighVariable (PcodeOpNode::compareByHigh, expression.hh:54 — pointer
    /// order), allocate ONE COPY trim per distinct HighVariable (merge.cc:830
    /// NOTE: all inputs to the effect op that are instances of the output high
    /// must intersect, so they are traceable via COPY to the same root), insert
    /// it before the first read and redirect every read in the group to its
    /// output.
    fn snip_output_interference(&mut self, fd: &mut Funcdata, indop: &crate::op::PcodeOpRef) -> bool {
        // merge.cc:814: op = PcodeOp::getOpFromConst(indop->getIn(1)->getAddr())
        let effect_op = {
            let o = indop.0.read().unwrap();
            o.get_in(1).and_then(|vn| fd.get_op_from_const(vn))
        };
        let Some(effect_op) = effect_op else { return false };
        let out_high = {
            let o = indop.0.read().unwrap();
            o.output.as_ref().and_then(|v| v.read().unwrap().high.clone())
        };
        let Some(out_high) = out_high else { return false };
        // merge.cc:817-820
        let mut correctable = self.collect_inputs(fd, &out_high, &effect_op);
        if correctable.is_empty() {
            return false;
        }
        // merge.cc:822: sort by PcodeOpNode::compareByHigh — compares the
        // reads' HighVariables by POINTER identity (HighVariable* <). Rust
        // compares Arc allocation addresses; the sort is deterministic.
        correctable.sort_by(|a, b| {
            let high_ptr = |e: &(crate::op::PcodeOpRef, usize)| {
                e.0 .0
                    .read()
                    .unwrap()
                    .get_in(e.1)
                    .and_then(|v| v.read().unwrap().high.clone())
                    .map(|h| std::sync::Arc::as_ptr(&h) as usize)
                    .unwrap_or(0)
            };
            high_ptr(a).cmp(&high_ptr(b))
        });
        // merge.cc:823-837: one snip COPY per distinct HighVariable; every
        // read in the group is redirected to that COPY's output.
        let mut snipop: Option<crate::op::PcodeOpRef> = None;
        let mut cur_high: Option<usize> = None;
        for (insertop, slot) in correctable {
            let vn = insertop.0.read().unwrap().get_in(slot).cloned();
            let Some(vn) = vn else { continue };
            let vn_high = vn.read().unwrap().high.clone();
            let vn_high_ptr = vn_high
                .as_ref()
                .map(|h| std::sync::Arc::as_ptr(h) as usize);
            if vn_high_ptr != cur_high {
                // merge.cc:832-834
                let insert_addr = insertop.0.read().unwrap().get_addr();
                let snip = self.allocate_copy_trim(fd, &vn, insert_addr, &insertop);
                fd.op_insert_before(&snip, &insertop);
                snipop = Some(snip);
                cur_high = vn_high_ptr;
            }
            // merge.cc:836
            if let Some(snip) = &snipop {
                let snip_out = snip.0.read().unwrap().output.clone();
                if let Some(out) = snip_out {
                    fd.op_set_input(&insertop, out, slot);
                }
            }
        }
        true
    }

    // Ghidra: merge.cc:846 Merge::mergeIndirect
    /// Force-merge the input and output of an INDIRECT op. Faithful to
    /// `Merge::mergeIndirect` (merge.cc:846-882).
    ///
    /// If the output is NOT address forced, merge like a MULTIEQUAL
    /// (mergeOp, :850-853). Otherwise the value must be present at the address
    /// BEFORE the indirect effect op takes place (:843-844): first try
    /// `mergeTestRequired` + a merge with the INPUT HighVariable as the
    /// survivor — `merge(invn0->getHigh(), outvn->getHigh(), false)`
    /// (:857, INPUT side absorbs the output, opposite direction from
    /// mergeOp's output-survives merge). If that fails, snip reads of the
    /// output high that interfere with the effect op's inputs
    /// (snipOutputInterference, :862) and retry the merge (:864-867). As a
    /// last resort snip the INDIRECT itself with allocateCopyTrim (:871),
    /// redirect input 0 through the trim COPY, and re-merge; Ghidra throws
    /// LowlevelError "Unable to merge address forced indirect" if the final
    /// merge fails (:878-881) — Rudra logs to stderr instead of aborting the
    /// pipeline (established merge.rs throw policy, cf. merge_op :765-769).
    fn merge_indirect(&mut self, fd: &mut Funcdata, indop: &crate::op::PcodeOpRef) {
        // merge.cc:849-853: !isAddrForce → plain MULTIEQUAL-style mergeOp.
        let out_vn = indop.0.read().unwrap().output.clone();
        let Some(out_vn) = out_vn else { return };
        if !out_vn.read().unwrap().is_addr_force() {
            self.merge_op(fd, indop);
            return;
        }
        // merge.cc:855-859: first merge attempt — INPUT high survives.
        let invn0 = indop.0.read().unwrap().get_in(0).cloned();
        let Some(invn0) = invn0 else { return };
        let out_high = out_vn.read().unwrap().high.clone();
        let in_high = invn0.read().unwrap().high.clone();
        let (Some(out_high), Some(in_high)) = (out_high, in_high) else { return };
        if self.merge_test_required(&out_high, &in_high) {
            if self.merge_speculative(fd, &in_high, &out_high, false) {
                return;
            }
        }
        // merge.cc:860-868: snip output interference, then retry the merge.
        if self.snip_output_interference(fd, indop) {
            if self.merge_test_required(&out_high, &in_high) {
                if self.merge_speculative(fd, &in_high, &out_high, false) {
                    return;
                }
            }
        }
        // merge.cc:870-877: snip the INDIRECT itself.
        let indop_addr = indop.0.read().unwrap().get_addr();
        let newop = self.allocate_copy_trim(fd, &invn0, indop_addr, indop);
        // merge.cc:872-875: SymbolEntry union-resolution inheritance
        // (needsResolution) — omitted conservatively: Rudra has no
        // inheritResolution-on-trim infrastructure yet (same omission as
        // allocate_copy_trim, merge.cc:417-428).
        let newop_out = newop.0.read().unwrap().output.clone();
        if let Some(out) = newop_out {
            fd.op_set_input(indop, out, 0);
        }
        fd.op_insert_before(&newop, indop);
        // merge.cc:878-881: final merge attempt; Ghidra throws on failure.
        let in0_high = indop
            .0
            .read()
            .unwrap()
            .get_in(0)
            .and_then(|v| v.read().unwrap().high.clone());
        if let Some(in0_high) = in0_high {
            let out_high_now = out_vn.read().unwrap().high.clone();
            let ok = match out_high_now {
                Some(oh) => {
                    self.merge_test_required(&oh, &in0_high)
                        && self.merge_speculative(fd, &in0_high, &oh, false)
                }
                None => false,
            };
            if !ok {
                eprintln!("[MERGE] Unable to merge address forced indirect (merge.cc:881)");
            }
        }
    }

    // Ghidra: merge.cc:1045 Merge::compareCopyByInVarnode
    /// Sort comparator for COPY ops: by input Varnode (create index), then
    /// by parent block index, then by seqnum order. Faithful to
    /// `Merge::compareCopyByInVarnode` (merge.cc:1045-1057).
    fn compare_copy_by_in_varnode(
        op1: &crate::op::PcodeOpRef,
        op2: &crate::op::PcodeOpRef,
    ) -> std::cmp::Ordering {
        let (in1_ci, in2_ci, idx1, idx2, ord1, ord2) = {
            let a = op1.0.read().unwrap();
            let b = op2.0.read().unwrap();
            let in1 = a.get_in(0).map(|v| v.read().unwrap().create_index).unwrap_or(0);
            let in2 = b.get_in(0).map(|v| v.read().unwrap().create_index).unwrap_or(0);
            let i1 = a.parent.as_ref().and_then(|w| w.upgrade()).map(|p| p.read().unwrap().get_index()).unwrap_or(0);
            let i2 = b.parent.as_ref().and_then(|w| w.upgrade()).map(|p| p.read().unwrap().get_index()).unwrap_or(0);
            (in1, in2, i1, i2, a.get_seq_num().order, b.get_seq_num().order)
        };
        in1_ci.cmp(&in2_ci)
            .then_with(|| idx1.cmp(&idx2))
            .then_with(|| ord1.cmp(&ord2))
    }

    // Ghidra: merge.cc:1295 Merge::findAllIntoCopies
    /// Collect all COPY ops whose output is an instance of `high` and whose
    /// input comes from a different HighVariable. Faithful to
    /// `Merge::findAllIntoCopies` (merge.cc:1295-1309). If `filter_temps`,
    /// only COPYs whose output is in the internal (unique) space are kept.
    /// Result is sorted by `compare_copy_by_in_varnode`.
    fn find_all_into_copies(
        &self,
        high: &Arc<RwLock<HighVariable>>,
        filter_temps: bool,
    ) -> Vec<crate::op::PcodeOpRef> {
        let h = high.read().unwrap();
        let n = h.num_instances();
        let mut copy_ins: Vec<crate::op::PcodeOpRef> = Vec::new();
        for i in 0..n {
            let vn_arc = match h.get_instance(i) { Some(a) => a, None => continue };
            let (is_written, def_code_copy, in_high_diff, out_is_unique) = {
                let vn = vn_arc.read().unwrap();
                let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(d) => {
                        let def = d.read().unwrap();
                        let code_copy = def.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let in_high_diff = def.get_in(0).map(|inv| {
                            let inv_h = inv.read().unwrap().high.clone();
                            match inv_h {
                                Some(ih) => !Arc::ptr_eq(&ih, high),
                                None => true,
                            }
                        }).unwrap_or(true);
                        let out_unique = vn.address_space == crate::space::AddressSpace::Unique;
                        (true, code_copy, in_high_diff, out_unique)
                    }
                    None => (false, false, true, false),
                }
            };
            if !is_written || !def_code_copy || !in_high_diff {
                continue;
            }
            if filter_temps && !out_is_unique {
                continue;
            }
            // Get the def op as PcodeOpRef.
            let def_arc = vn_arc.read().unwrap().def.as_ref().and_then(|w| w.upgrade()).unwrap();
            copy_ins.push(crate::op::PcodeOpRef(def_arc));
        }
        drop(h);
        copy_ins.sort_by(Self::compare_copy_by_in_varnode);
        copy_ins
    }

    // Ghidra: merge.cc:1151 Merge::buildDominantCopy
    /// Replace a group of COPYs (from the same source) with a single dominant
    /// COPY at the common dominator block. Faithful to `buildDominantCopy`
    /// (merge.cc:1151-1238). Union-resolution path (:1170-1178) omitted.
    ///
    /// `high`: target HighVariable. `copy`: sorted COPY list. `pos`/`size`:
    /// the group of COPYs sharing the same input Varnode.
    fn build_dominant_copy(
        &mut self,
        fd: &mut Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        copy: &[crate::op::PcodeOpRef],
        pos: usize,
        size: usize,
    ) {
        // Collect parent blocks of the COPY group.
        let block_set: Vec<Arc<RwLock<dyn crate::block::FlowBlock + Send + Sync>>> = (0..size)
            .filter_map(|i| {
                let op = copy[pos + i].0.read().unwrap();
                op.parent.as_ref().and_then(|w| w.upgrade())
            })
            .collect();
        let Some(dom_bl) = crate::block::BlockGraph::find_common_block_n(&block_set) else {
            return;
        };
        let dom_bl_bb = dom_bl.read().unwrap();
        let dom_bl_any = dom_bl_bb.as_any().downcast_ref::<crate::block::BlockBasic>();
        // domCopy = copy[pos]; rootVn = domCopy->getIn(0); domVn = domCopy->getOut()
        let (root_vn, dom_copy_out, dom_copy_parent_ptr) = {
            let dc = copy[pos].0.read().unwrap();
            let rv = dc.get_in(0).cloned();
            let dv = dc.output.clone();
            let dp = dc.parent.as_ref().and_then(|w| w.upgrade());
            (rv, dv, dp)
        };
        let Some(root_vn) = root_vn else { return };
        // Determine if domCopy is already in domBl.
        let dom_in_dombl = match (&dom_copy_parent_ptr, dom_bl_any) {
            (Some(p), _) => Arc::ptr_eq(p, &dom_bl),
            _ => false,
        };
        drop(dom_bl_bb);
        let mut dom_copy_is_new = false;
        let mut dom_vn = dom_copy_out;
        let mut new_dom_copy: Option<crate::op::PcodeOpRef> = None;
        if !dom_in_dombl {
            // Build a new COPY at domBl (merge.cc:1167-1183).
            dom_copy_is_new = true;
            let stop_addr = {
                let rg = dom_bl.read().unwrap();
                match rg.as_any().downcast_ref::<crate::block::BlockBasic>() {
                    Some(bb) => bb.get_stop_addr(),
                    None => crate::address::Address::new(0),
                }
            };
            let new_op = fd.new_op(1, stop_addr);
            fd.op_set_opcode(&new_op, crate::opcodes::OpCode::CPUI_COPY);
            let sz = root_vn.read().unwrap().size;
            let uv = fd.new_unique(sz);
            // Ghidra data.newUnique assigns the High (funcdata_varnode.cc:89);
            // required for the :1236 merge of domVn's high below.
            Self::wire_unique_high(fd, &uv);
            fd.op_set_output(&new_op, uv.clone());
            fd.op_set_input(&new_op, root_vn.clone(), 0);
            fd.op_insert_end(&new_op, &dom_bl);
            dom_vn = Some(uv);
            new_dom_copy = Some(new_op);
        }
        let Some(dom_vn) = dom_vn else { return };
        // Build bCover = union of high's instances' covers, excluding COPY-from-shadow-of-rootVn.
        let mut b_cover = Cover::new();
        {
            let h = high.read().unwrap();
            for i in 0..h.num_instances() {
                let Some(vn_arc) = h.get_instance(i) else { continue };
                let skip = {
                    let vn = vn_arc.read().unwrap();
                    let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                    match def_arc {
                        Some(d) => {
                            let def = d.read().unwrap();
                            if def.opcode == crate::opcodes::OpCode::CPUI_COPY {
                                let in0 = def.get_in(0);
                                match in0 {
                                    Some(inv) => inv.read().unwrap().copy_shadow(&root_vn.read().unwrap()),
                                    None => false,
                                }
                            } else { false }
                        }
                        None => false,
                    }
                };
                if skip { continue; }
                let vn = vn_arc.read().unwrap();
                if let Some(c) = &vn.cover {
                    b_cover.merge(c);
                }
            }
        }
        // For each non-dom COPY, check if removable (aCover vs bCover).
        // Mark un-removable ones (Ghidra uses op->setMark).
        let mut marked: Vec<bool> = vec![false; size];
        let mut count = size as i32;
        for i in 0..size {
            let is_dom = match &new_dom_copy {
                Some(nd) => Arc::ptr_eq(&nd.0, &copy[pos + i].0),
                None => i == 0, // copy[pos] is the domCopy when not new
            };
            if is_dom { continue; }
            let (out_vn_arc, descends) = {
                let op = copy[pos + i].0.read().unwrap();
                let ov = op.output.clone();
                let ds: Vec<crate::op::PcodeOpRef> = if let Some(ref ova) = ov {
                    ova.read().unwrap().descend.iter()
                        .filter_map(|w| w.upgrade())
                        .map(|a| crate::op::PcodeOpRef(a))
                        .collect()
                } else { Vec::new() };
                (ov, ds)
            };
            let Some(out_vn_arc) = out_vn_arc else { continue };
            // aCover: addDefPoint(domVn) + addRefPoint(each reader of outVn)
            // (merge.cc:1202-1207), both via the full op-based entries:
            // endpoint identity (MULTIEQUAL order-0 marker, INDIRECT ->
            // guarded-op order, cover.cc:29-49) plus the backward CFG
            // recursion of addRefPoint (cover.cc:565-612), which fills
            // every block between each reader and the def point — the
            // order-domain entries silently dropped both.
            let mut a_cover = Cover::new();
            let mut scratch_roots = Vec::new();
            let mut scratch_stack = Vec::new();
            {
                let dv = dom_vn.read().unwrap();
                let def = dv.def.as_ref().and_then(|w| w.upgrade());
                let is_input = def.is_none() && dv.is_input();
                a_cover.add_def_point_full(def.as_ref(), is_input);
            }
            for d_ref in &descends {
                a_cover.add_ref_point_full(&d_ref.0, &out_vn_arc, &mut scratch_roots, &mut scratch_stack);
            }
            if b_cover.intersect_char(&a_cover) > 1 {
                count -= 1;
                marked[i] = true;
            }
        }
        // If count <= 1, mark all to skip (and destroy new domCopy if new).
        if count <= 1 {
            for i in 0..size { marked[i] = true; }
            count = 0;
            if dom_copy_is_new {
                if let Some(nd) = &new_dom_copy {
                    fd.op_destroy(nd);
                }
            }
        }
        // Replace non-marked COPYs: totalReplace(outVn, domVn) + opDestroy.
        for i in 0..size {
            if marked[i] { continue; }
            let (out_vn_arc, op_ref) = {
                let op = copy[pos + i].0.read().unwrap();
                (op.output.clone(), crate::op::PcodeOpRef(copy[pos + i].0.clone()))
            };
            if let Some(out_vn) = out_vn_arc {
                // Skip if outVn == domVn.
                let same = Arc::ptr_eq(&out_vn, &dom_vn);
                if !same {
                    // outVn->getHigh()->remove(outVn)
                    let h_idx = out_vn.read().unwrap().high.as_ref().and_then(|h| {
                        h.read().unwrap().instance_index(&out_vn)
                    });
                    if let Some(idx) = h_idx {
                        out_vn.read().unwrap().high.as_ref().unwrap().write().unwrap().remove_instance(idx);
                    }
                    fd.total_replace(&out_vn, dom_vn.clone());
                    fd.op_destroy(&op_ref);
                }
            }
        }
        // merge.cc:1235-1237: if (count > 0 && domCopyIsNew)
        //   high->merge(domVn->getHigh(), (HighIntersectTest *)0, true);
        // Direct HighVariable::merge with a NULL testCache: NO
        // testCache.intersection precheck (non-intersection was already
        // proven per-COPY via bCover/aCover above) and NO
        // moveIntersectTests. Rust merge_speculative would do both
        // (Merge::merge, merge.cc:1569-1571) — so call the HighVariable::merge
        // absorption port (merge_highs) directly. Its trailing
        // update_high_cover matches oracle content in the clean case
        // (dirty-gated no-op, variable.cc:327) and eagerly rebuilds in the
        // dirty case where Ghidra defers to the next lazy updateHigh —
        // identical rebuilt cover, earlier timing.
        if count > 0 && dom_copy_is_new {
            let dom_high = dom_vn.read().unwrap().high.clone();
            if let Some(dh) = dom_high {
                // variable.cc:678: if (tv2 == this) return;
                if !Arc::ptr_eq(high, &dh) {
                    let _ = self.merge_highs(high, &dh, true);
                }
            }
        }
    }

    // Ghidra: merge.cc:1316 Merge::processHighDominantCopy
    /// For the given HighVariable, find groups of COPYs from the same source
    /// and replace each group with a single dominant COPY. Faithful to
    /// `processHighDominantCopy` (merge.cc:1316-1337).
    fn process_high_dominant_copy(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) {
        let copy_ins = self.find_all_into_copies(high, true);
        if copy_ins.len() < 2 {
            return;
        }
        // Group by identical input Varnode (Arc ptr eq), call buildDominantCopy.
        let mut pos = 0usize;
        while pos < copy_ins.len() {
            let in_vn = {
                let op = copy_ins[pos].0.read().unwrap();
                op.get_in(0).cloned()
            };
            let Some(in_vn) = in_vn else { break; };
            let mut sz = 1usize;
            while pos + sz < copy_ins.len() {
                let next_in = {
                    let op = copy_ins[pos + sz].0.read().unwrap();
                    op.get_in(0).cloned()
                };
                match next_in {
                    Some(ni) if Arc::ptr_eq(&ni, &in_vn) => sz += 1,
                    _ => break,
                }
            }
            if sz > 1 {
                self.build_dominant_copy(fd, high, &copy_ins, pos, sz);
            }
            pos += sz;
        }
    }

    // Ghidra: merge.cc:1415 Merge::processCopyTrims
    /// Step 6 of the merge phase: ActionDominantCopy (coreaction.cc:5723;
    /// apply at coreaction.hh:1008 is exactly `data.getMerge().processCopyTrims()`).
    ///
    /// Walks the `copyTrims` list — COPY ops inserted by the snip machinery
    /// of the forced-merge path (`allocateCopyTrim`/`snipReads`, merge.cc:411,443;
    /// wired into `merge_addr_tied` since 2026-07-04) — to find
    /// HighVariables that received ≥ 2 such COPYs and calls
    /// `process_high_dominant_copy(high)` on each to replace them with a
    /// single dominant COPY.
    ///
    /// Traversal order mirrors merge.cc:1418-1435 exactly: first-seen order
    /// of the HighVariables within the copyTrims list (Ghidra pushes each
    /// high onto `multiCopy` at its first sighting, using the copy_in1 /
    /// copy_in2 HighVariable flags as the per-high ≥2 counter). The HashMap
    /// below is keyed-lookup only; iteration order is carried by the
    /// `first_seen` Vec. HashMap iteration here would randomize the dominant
    /// COPY op-insertion order per process (DETERM-COPYTRIM-0001,
    /// DETERM-DOMINANTCOPY-0001 — both AX/AZ nondeterminism sources).
    pub fn process_copy_trims(&mut self, fd: &mut Funcdata) {
        self.attach(fd);
        if self.copy_trims.is_empty() {
            self.detach(fd);
            return;
        }
        // Ghidra merge.cc:1420-1428: walk copyTrims in list order. First
        // sighting of a HighVariable pushes it onto multiCopy in first-seen
        // order and sets copy_in1; later sightings only set copy_in2 (the
        // "at least 2" mark).
        let mut first_seen: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        let mut counts: std::collections::HashMap<usize, u32> =
            std::collections::HashMap::new();
        for trim in &self.copy_trims {
            let out_high = {
                let t = trim.0.read().unwrap();
                t.output.as_ref().and_then(|o| {
                    let ov = o.read().unwrap();
                    ov.high.clone().map(|h| (std::sync::Arc::as_ptr(&h) as *const () as usize, h))
                })
            };
            if let Some((key, h)) = out_high {
                match counts.get_mut(&key) {
                    Some(count) => *count += 1, // later sighting: setCopyIn2 (merge.cc:1427)
                    None => {
                        counts.insert(key, 1); // first sighting: setCopyIn1 (merge.cc:1424)
                        first_seen.push(h); // multiCopy.push_back (merge.cc:1423)
                    }
                }
            }
        }
        // Ghidra merge.cc:1429: copyTrims.clear() — between the two loops.
        self.copy_trims.clear();
        // Ghidra merge.cc:1430-1435: for each high in multiCopy (first-seen)
        // order, process it if it received ≥ 2 COPYs (hasCopyIn2).
        for high in &first_seen {
            let key = std::sync::Arc::as_ptr(high) as *const () as usize;
            // Ghidra: if (high->hasCopyIn2()) processHighDominantCopy(high) (merge.cc:1432)
            if counts[&key] >= 2 {
                self.process_high_dominant_copy(fd, high);
            }
        }
        self.detach(fd);
    }

    // Ghidra: merge.cc:983 Merge::mergeAdjacent
    /// Step 9: ActionMergeAdjacent (coreaction.hh:381).
    /// Faithful to `Merge::mergeAdjacent` (merge.cc:983-1013).
    ///
    /// For each alive non-call op, try to merge each input HighVariable with
    /// the output HighVariable *speculatively*: only if the two have the
    /// same data-type, matching sizes, both pass `merge_test_basic`, and
    /// their covers do not intersect. This is a speculative (cover-guarded)
    /// merge — covers that overlap cause the merge to be skipped.
    pub fn merge_adjacent(&mut self, fd: &mut Funcdata) {
        self.attach(fd);

        // Ghidra merge.cc:999: ct = op->outputTypeLocal() — every local
        // type resolves through the architecture's TypeFactory, so the
        // (1, TYPE_INT) nochar distinction is factory registration state
        // (type.cc:3200-3248/3619-3626), fixed for the whole walk like the
        // factory it reads.
        let nochar_distinct = Self::factory_nochar_distinct(fd);

        // Gather (op, out, inputs) for every alive non-call op with a
        // cover-eligible output.
        let adjacent_pairs: Vec<(crate::op::PcodeOpRef, Arc<RwLock<Varnode>>, Vec<Arc<RwLock<Varnode>>>)> = fd
            .obank
            .iter_alive()
            .filter_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if op.is_dead() || op.is_call() {
                    return None;
                }
                let out = op.output.clone()?;
                let out_basic = {
                    drop(op);
                    let o = out.read().unwrap();
                    Self::merge_test_basic(&o)
                };
                if !out_basic {
                    return None;
                }
                // Re-read for inputs.
                let op = op_ref.0.read().unwrap();
                let ins: Vec<_> = op.inrefs.clone();
                drop(op);
                Some((crate::op::PcodeOpRef(op_ref.0.clone()), out, ins))
            })
            .collect();

        for (op_ref, out_vn, in_vns) in adjacent_pairs {
            let out_size = out_vn.read().unwrap().size;
            // Ghidra merge.cc:998-999: high_out = vn1->getHigh(); the
            // mergeTestAdjacent gate below needs the HighVariable.
            let high_out = out_vn.read().unwrap().high.clone();
            let Some(high_out) = high_out else { continue };
            for (slot_index, in_vn) in in_vns.into_iter().enumerate() {
                let (in_basic, in_size, in_written_or_input) = {
                    let v = in_vn.read().unwrap();
                    let basic = Self::merge_test_basic(&v);
                    // Ghidra: if ((vn2->getDef()==null)&&(!vn2->isInput())) continue;
                    let written_or_input = v.is_written() || v.is_input();
                    (basic, v.size, written_or_input)
                };
                if !in_basic || !in_written_or_input {
                    continue;
                }
                // Ghidra merge.cc:1001: only merge if the local types should
                // be the same (ct != op->inputTypeLocal(i) → skip).
                if !Self::adjacent_local_types_match(&op_ref, slot_index, nochar_distinct) {
                    continue;
                }
                if in_size != out_size {
                    continue;
                }
                // Ghidra merge.cc:1006-1007: mergeTestAdjacent gate — the
                // full required+namelock+type-identity+illegal-input+
                // isolated-symbol+piece guard chain (merge.cc:175-218).
                let high_in = in_vn.read().unwrap().high.clone();
                let Some(high_in) = high_in else { continue };
                if !self.merge_test_adjacent(&high_out, &high_in) {
                    continue;
                }
                // Speculative merge (merge.cc:1009-1010):
                // if (!testCache.intersection(high_in,high_out))
                //   merge(high_out,high_in,true); — the OUTPUT high
                // survives (merge.cc:1558: the second is merged into the
                // first).
                self.merge_speculative_by_vn(fd, &out_vn, &in_vn, true);
            }
        }

        self.detach(fd);
    }

    // Ghidra: merge.cc:1001 mergeAdjacent local-type gate
    /// Factory-canonical identity key for an op-local type. Ghidra's gate
    /// compares `Datatype*` objects returned by `TypeOp::getOutputLocal` /
    /// `getInputLocal` (op.hh:251-252), which are TypeFactory-canonical:
    /// two such pointers are equal iff they are the same factory entry.
    /// The entries reachable here are `getBase(size, metatype)`,
    /// `getBaseNoChar(size, metatype)` (the same canonical entry as the
    /// plain base at the same metatype+size, except for the registered
    /// 1-byte int, type.cc:3619-3626), and `getTypeCode()`; `getTypePointer` (CBRANCH slot 0) is unreachable
    /// because branch ops have no output for mergeAdjacent to walk.

    /// Per-opcode `(metaout, metain)` pairs from the TypeOp ctor table
    /// (typeop.cc: the `TypeOpBinary/Unary/Func(t, CPUI_*, ..., mout, min)`
    /// constructor arguments, typeop.hh:210-246 parameter order mout, min).
    /// Opcodes absent from the table use the TypeOp base local types
    /// `getBase(size, TYPE_UNKNOWN)` (typeop.cc:261-275) — COPY, LOAD,
    /// STORE, MULTIEQUAL, CBRANCH, BRANCH, RETURN, CAST, SEGMENTOP, and
    /// every op without a TypeOp subclass here.
    /// NOTE: this encodes the C-mode defaults; the Java-mode variants of
    /// selectJavaOperators (typeop.cc:118-140: ZEXT (INT,UNKNOWN), NEGATE/
    /// XOR/AND/OR (INT,INT), RIGHT (INT,INT)) are architecture-level state
    /// that Rudra does not model yet (UNTESTED).
    fn local_meta_pair(opcode: crate::opcodes::OpCode) -> Option<(TypeMetatype, TypeMetatype)> {
        use crate::opcodes::OpCode;
        use TypeMetatype::{Bool, Float, Int, Unknown, Uint};
        Some(match opcode {
            OpCode::CPUI_INT_EQUAL
            | OpCode::CPUI_INT_NOTEQUAL
            | OpCode::CPUI_INT_SLESS
            | OpCode::CPUI_INT_SLESSEQUAL
            | OpCode::CPUI_INT_SCARRY
            | OpCode::CPUI_INT_SBORROW => (Bool, Int),
            OpCode::CPUI_INT_LESS
            | OpCode::CPUI_INT_LESSEQUAL
            | OpCode::CPUI_INT_CARRY => (Bool, Uint),
            OpCode::CPUI_FLOAT_EQUAL
            | OpCode::CPUI_FLOAT_NOTEQUAL
            | OpCode::CPUI_FLOAT_LESS
            | OpCode::CPUI_FLOAT_LESSEQUAL
            | OpCode::CPUI_FLOAT_NAN => (Bool, Float),
            OpCode::CPUI_INT_ZEXT => (Uint, Uint),
            OpCode::CPUI_INT_SEXT
            | OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_INT_LEFT
            | OpCode::CPUI_INT_SRIGHT => (Int, Int),
            // typeop.cc:1913 TypeOpFunc(t,CPUI_FLOAT_TRUNC,"TRUNC",
            // TYPE_INT,TYPE_FLOAT) — no override, so the :1001 gate rejects
            // same-size float inputs.
            OpCode::CPUI_FLOAT_TRUNC => (Int, Float),
            OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_RIGHT
            | OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_REM => (Uint, Uint),
            OpCode::CPUI_BOOL_NEGATE
            | OpCode::CPUI_BOOL_XOR
            | OpCode::CPUI_BOOL_AND
            | OpCode::CPUI_BOOL_OR => (Bool, Bool),
            OpCode::CPUI_FLOAT_ADD
            | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_FLOAT_MULT
            | OpCode::CPUI_FLOAT_SUB
            | OpCode::CPUI_FLOAT_NEG
            | OpCode::CPUI_FLOAT_ABS
            | OpCode::CPUI_FLOAT_SQRT
            | OpCode::CPUI_FLOAT_FLOAT2FLOAT
            | OpCode::CPUI_FLOAT_CEIL
            | OpCode::CPUI_FLOAT_FLOOR
            | OpCode::CPUI_FLOAT_ROUND => (Float, Float),
            OpCode::CPUI_FLOAT_INT2FLOAT => (Float, Int),
            OpCode::CPUI_PIECE | OpCode::CPUI_SUBPIECE => (Unknown, Unknown),
            // typeop.cc:2529 (mout UNKNOWN, min INT) with the slot-0
            // override below.
            OpCode::CPUI_INSERT => (Unknown, Int),
            // typeop.cc:2544 (INT, INT) with the slot-0 override below.
            OpCode::CPUI_EXTRACT => (Int, Int),
            // typeop.cc:2559/2566 (INT, UNKNOWN).
            OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT => (Int, Unknown),
            _ => return None,
        })
    }

    // Ghidra: op.hh:251 PcodeOp::outputTypeLocal → TypeOp::getOutputLocal
    /// Resolve `op->outputTypeLocal()` to its canonical key (typeop.cc
    /// override table; base at :261-265).
    fn output_type_local_key(op: &crate::op::PcodeOpRef) -> LocalTypeKey {
        use crate::opcodes::OpCode;

        use TypeMetatype::{Int, Unknown};
        let (opcode, out_size) = {
            let o = op.0.read().unwrap();
            (o.opcode, o.output.as_ref().map(|v| v.read().unwrap().size))
        };
        let Some(out_size) = out_size else {
            return LocalTypeKey::Base(Unknown, 0);
        };
        match opcode {
            // typeop.cc:2238/2308 — "treat same as INT_ADD": every local
            // type is getBase(size, TYPE_INT) for both output and inputs.
            OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB => LocalTypeKey::Base(Int, out_size),
            // typeop.cc:2451-2459 — the constant-pool record type, or the
            // base UNKNOWN fallback (BOOL(1) for instance_of records).
            // Rudra has no cpool on the fixture path; the record lookup
            // degrades to the same base fallback until cpool lands.
            OpCode::CPUI_CPOOLREF => LocalTypeKey::Base(Unknown, out_size),
            // typeop.cc:865-872 — user-op metadata type or base UNKNOWN
            // fallback; Rudra's UserPcodeOp carries no Datatype metadata
            // yet (same fallback result).
            OpCode::CPUI_CALLOTHER => LocalTypeKey::Base(Unknown, out_size),
            _ => match Self::local_meta_pair(opcode) {
                Some((metaout, _)) => LocalTypeKey::Base(metaout, out_size),
                // TypeOp base default (typeop.cc:261-265), covering COPY,
                // LOAD, STORE, MULTIEQUAL, INDIRECT, CAST and the rest.
                None => LocalTypeKey::Base(Unknown, out_size),
            },
        }
    }

    // Ghidra: op.hh:252 PcodeOp::inputTypeLocal → TypeOp::getInputLocal
    /// Resolve `op->inputTypeLocal(slot)` to its canonical key (per-slot
    /// override table; base at :271-275).
    fn input_type_local_key(op: &crate::op::PcodeOpRef, slot: usize) -> LocalTypeKey {
        use crate::opcodes::OpCode;

        use TypeMetatype::{Int, Unknown};
        let (opcode, in_size) = {
            let o = op.0.read().unwrap();
            let size = o.inrefs.get(slot).map(|v| v.read().unwrap().size);
            (o.opcode, size)
        };
        let Some(in_size) = in_size else {
            return LocalTypeKey::Base(Unknown, 0);
        };
        match (opcode, slot) {
            // Shift-amount slots (typeop.cc:1510-1516 INT_LEFT, 1535-1541
            // INT_RIGHT, 1600-1606 INT_SRIGHT): getBaseNoChar(size, INT),
            // which equals the plain getBase(size, INT) except for the
            // registered 1-byte int (type.cc:3619-3626) — so the
            // merge.cc:1001 gate passes shift amounts of size != 1 and
            // rejects registered 1-byte int shift amounts.
            (OpCode::CPUI_INT_LEFT, 1)
            | (OpCode::CPUI_INT_RIGHT, 1)
            | (OpCode::CPUI_INT_SRIGHT, 1) => LocalTypeKey::BaseNoChar(Int, in_size),
            // typeop.cc:2535-2541 INSERT slot 0 / 2550-2556 EXTRACT slot 0:
            // getBase(size, TYPE_UNKNOWN) instead of the ctor metain.
            (OpCode::CPUI_INSERT, 0) | (OpCode::CPUI_EXTRACT, 0) => {
                LocalTypeKey::Base(Unknown, in_size)
            }
            // typeop.cc:1992-1998 INDIRECT: slot 0 is the base default,
            // slot 1 is the iop constant resolving to getTypeCode().
            (OpCode::CPUI_INDIRECT, 1) => LocalTypeKey::TypeCode,
            // typeop.cc:2232-2236 PTRADD / 2314-2318 PTRSUB: every input
            // slot is getBase(size, TYPE_INT).
            (OpCode::CPUI_PTRADD, _) | (OpCode::CPUI_PTRSUB, _) => {
                LocalTypeKey::Base(Int, in_size)
            }
            // typeop.cc:2465-2469 CPOOLREF inputs: getBase(size, TYPE_INT).
            (OpCode::CPUI_CPOOLREF, _) => LocalTypeKey::Base(Int, in_size),
            // CALLOTHER inputs (typeop.cc:855-862): user-op metadata or the
            // base UNKNOWN fallback (no Datatype metadata ported yet).
            (OpCode::CPUI_CALLOTHER, _) => LocalTypeKey::Base(Unknown, in_size),
            _ => match Self::local_meta_pair(opcode) {
                Some((_, metain)) => LocalTypeKey::Base(metain, in_size),
                None => LocalTypeKey::Base(Unknown, in_size),
            },
        }
    }

    // Ghidra: merge.cc:1001 mergeAdjacent local-type gate
    /// `if (ct != op->inputTypeLocal(i)) continue;` — compare the two
    /// factory-canonical keys for identity. Equal iff same factory entry
    /// (kind + metatype + size), with the registered 1-byte-int nochar
    /// distinction resolved from the effective TypeFactory
    /// (`factory_nochar_distinct`).
    fn adjacent_local_types_match(
        op: &crate::op::PcodeOpRef,
        slot: usize,
        nochar_distinct: bool,
    ) -> bool {
        local_type_key_eq(
            &Self::output_type_local_key(op),
            &Self::input_type_local_key(op, slot),
            nochar_distinct,
        )
    }

    // Ghidra: type.cc:3200-3248 TypeFactory::cacheCoreTypes
    /// Whether the effective TypeFactory distinguishes
    /// `getBaseNoChar(1, TYPE_INT)` from `getBase(1, TYPE_INT)` — i.e.
    /// whether the merge.cc:1001 pointer gate treats a 1-byte int shift
    /// amount as different from the 1-byte int output local type.
    ///
    /// `cacheCoreTypes` fills `type_nochar` from a registered core 1-byte
    /// non-ASCII TYPE_INT (type.cc:3220-3221), while an ASCII 1-byte char
    /// claims `typecache[1][TYPE_INT]` ("Char is preferred over other int
    /// types", type.cc:3225-3229); with no ASCII char registered the
    /// non-ASCII 1-byte int itself fills that cache slot
    /// (type.cc:3240-3242), making `getBase(1,TYPE_INT)` the very same
    /// pointer as `type_nochar` (equal). So the two pointers differ
    /// exactly when the factory registers BOTH a 1-byte char-print INT
    /// core type AND a non-char 1-byte INT core type — the production
    /// SLEIGH defaults ("char" + "int1", sleigh_arch.cc:204-241). With no
    /// such registrations `type_nochar` stays null (type.cc:3128) and
    /// `getBaseNoChar` falls through to the plain base (type.cc:3624).
    ///
    /// The result is derived from the two actual canonical factory entries,
    /// never from core-type names.  This preserves custom core names and the
    /// DatatypeSet/cache traversal decision made by `cache_core_types`.
    fn factory_nochar_distinct(fd: &Funcdata) -> bool {
        let Some(factory) = fd.get_arch().and_then(|arch| arch.types.clone()) else {
            // No attached factory = no core-type registration = null
            // type_nochar world (type.cc:3128): the gate falls through to
            // plain-base identity.
            return false;
        };
        // Ghidra's getBase/getBaseNoChar (type.cc:3619-3660) are non-const —
        // they may insert/canonicalize through findAdd — so the faithful
        // Result twins need a write guard. A LowlevelError from the oracle
        // path (e.g. an uninitialized alignment map, type.cc:3300-3302) is a
        // throw in Ghidra; the merge walk cannot propagate it, so it surfaces
        // as the explicit LowlevelError panic here.
        let mut factory = factory
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let base = factory
            .get_base_result(1, TypeMetatype::Int)
            .unwrap_or_else(|message| {
                panic!("LowlevelError (merge.cc:1001 getBase(1,TYPE_INT) gate): {message}")
            });
        let nochar = factory
            .get_base_no_char_result(1, TypeMetatype::Int)
            .unwrap_or_else(|message| {
                panic!("LowlevelError (merge.cc:1001 getBaseNoChar(1,TYPE_INT) gate): {message}")
            });
        !Arc::ptr_eq(&base, &nochar)
    }

    // Ghidra: merge.cc:359 Merge::mergeByDatatype
    /// Step 10: ActionMergeType (coreaction.hh:414).
    /// Faithful to `Merge::mergeByDatatype` (merge.cc:359-401).
    ///
    /// Groups all HighVariables (reachable from live varnodes) by exact
    /// data-type, then attempts to merge each group via a cover-guarded
    /// `mergeLinear`-style pass: each HighVariable is merged into the first
    /// HighVariable it has a disjoint cover with.
    pub fn merge_by_datatype(&mut self, fd: &mut Funcdata) {
        self.attach(fd);

        let mut high_list: std::collections::VecDeque<Arc<RwLock<HighVariable>>> =
            std::collections::VecDeque::new();
        for vn_ref in &fd.vbank.loc_tree {
            let high = {
                let vn = vn_ref.0.read().unwrap();
                if vn.is_free() || !Self::merge_test_basic(&vn) {
                    continue;
                }
                vn.high.clone()
            };
            let Some(high) = high else { continue };
            let mut high_guard = high.write().unwrap();
            if high_guard.is_mark() {
                continue;
            }
            high_guard.set_mark();
            drop(high_guard);
            high_list.push_back(high);
        }
        for high in &high_list {
            high.write().unwrap().clear_mark();
        }

        while !high_list.is_empty() {
            let first = high_list.pop_front().unwrap();
            first.write().unwrap().update_type();
            let datatype = first.read().unwrap().v_type.get();
            let mut group = vec![first];
            let remaining = high_list.len();
            for _ in 0..remaining {
                let high = high_list.pop_front().unwrap();
                high.write().unwrap().update_type();
                let same_type = {
                    let high = high.read().unwrap();
                    Arc::ptr_eq(&datatype, &high.v_type.get())
                };
                if same_type {
                    group.push(high);
                } else {
                    high_list.push_back(high);
                }
            }
            self.merge_linear(fd, &mut group);
        }

        self.detach(fd);
    }

    // Ghidra: merge.hh:110 Merge::mergeLinear
    /// Speculatively merge a list of same-type HighVariables as well as
    /// possible. Faithful to `Merge::mergeLinear` (merge.cc:272-292).
    ///
    /// Each HighVariable is merged with the first "stacked" HighVariable
    /// whose cover it does not intersect; if none is compatible it starts a
    /// new stack group. After a successful merge, the stacked head's cover
    /// snapshot is refreshed so subsequent tests reflect the union.
    fn merge_linear(&mut self, fd: &Funcdata, highvec: &mut Vec<Arc<RwLock<HighVariable>>>) {
        if highvec.len() <= 1 {
            return;
        }
        for high in highvec.iter() {
            self.type_test_cache.update_high(high);
        }
        highvec.sort_by(compare_high_by_block);

        let mut high_stack: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        for high in highvec.iter() {
            let mut merged = false;
            for output in &high_stack {
                if self.merge_test_speculative(output, high)
                    && self.merge_type_pair(fd, output, high)
                {
                    merged = true;
                    break;
                }
            }
            if !merged {
                high_stack.push(high.clone());
            }
        }
    }


    // Ghidra: merge.cc:1070 Merge::hideShadows
    /// Hide shadow varnodes for a single HighVariable by redirecting COPY
    /// inputs. Faithful to `Merge::hideShadows(high)` (merge.cc:1070-1100).
    /// Returns true if any data-flow rewrite was applied.
    ///
    /// For the given HighVariable, find instance Varnodes defined by a COPY
    /// from *outside* the HighVariable. If two are copyShadow of each other
    /// and one's cover contains the other's def, redirect the COPY input
    /// (opSetInput) — consolidating the shadow chain.
    pub fn hide_shadows_of(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) -> bool {
        self.attach(fd);
        let mut changed = false;
        // findSingleCopy: instances defined by a COPY whose input is NOT
            // part of the same HighVariable (merge.cc:1021-1036).
            let singlelist: Vec<Arc<RwLock<Varnode>>> = {
                let hg = high.read().unwrap();
                let mut acc = Vec::new();
                for inst_arc in &hg.instances {
                    let copy_pair = {
                        let inst = inst_arc.read().unwrap();
                        if !inst.is_written() {
                            None
                        } else {
                            // Get def op.
                            inst.def.as_ref().and_then(|w| w.upgrade())
                        }
                    };
                    let Some(def_op_arc) = copy_pair else { continue };
                    let (is_copy, in_high_same) = {
                        let def_op = def_op_arc.read().unwrap();
                        let is_copy = def_op.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let in_high_same = def_op
                            .inrefs
                            .get(0)
                            .map(|invn| {
                                let invn = invn.read().unwrap();
                                invn.high.as_ref().map(|h| Arc::ptr_eq(h, &high)).unwrap_or(false)
                            })
                            .unwrap_or(false);
                        (is_copy, in_high_same)
                    };
                    if is_copy && !in_high_same {
                        acc.push(inst_arc.clone());
                    }
                }
                acc
            };
            if singlelist.len() <= 1 {
                // Balance the attach above before leaving (same pattern as
                // process_copy_trims); otherwise the depth counter leaks +1
                // and the outermost detach can never write the channels back.
                self.detach(fd);
                return false;
            }
            // hideShadows pairs: for vn1,vn2 that are copyShadow of each
            // other, redirect one COPY's input to the other.
            // Faithful to merge.cc:1080-1098.
            let mut null_mask: Vec<bool> = vec![false; singlelist.len()];
            for i in 0..singlelist.len().saturating_sub(1) {
                if null_mask[i] {
                    continue;
                }
                let vn1 = &singlelist[i];
                for j in (i + 1)..singlelist.len() {
                    if null_mask[j] {
                        continue;
                    }
                    let vn2 = &singlelist[j];
                    // vn1->copyShadow(vn2) (merge.cc:1086)
                    let is_shadow = {
                        let v1 = vn1.read().unwrap();
                        let v2 = vn2.read().unwrap();
                        v1.copy_shadow(&v2)
                    };
                    if !is_shadow {
                        continue;
                    }
                    // vn2->getCover()->containVarnodeDef(vn1)==1 (merge.cc:1087)
                    let (v1_blk, v1_ord, v1_is_input) = varnode_def_loc(&vn1.read().unwrap());
                    // merge.cc:1087: vn2->getCover() is the lazy rebuild
                    // read (varnode.hh:202 → varnode.cc:233) — rebuild
                    // before reading so a mid-pass coverdirty instance
                    // cannot feed its stale cover into the boundary
                    // containment test (earlier op_set_input calls in this
                    // same double loop dirty vn1/vn2 via add_descend;
                    // discipline identical to gather_block_varnodes).
                    // MERGE-HIGHCOVER-PROPAGATION-0001 residual reader fix.
                    Varnode::update_cover_locked(vn2);
                    let vn2_covers_vn1 = vn2.read().unwrap()
                        .cover.as_ref().map(|c| c.contain_varnode_def_at(v1_is_input, v1_blk, v1_ord) == 1)
                        .unwrap_or(false);
                    if vn2_covers_vn1 {
                        // data.opSetInput(vn1->getDef(), vn2, 0) (merge.cc:1088)
                        let vn1_def = vn1.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                        if let Some(def_op) = vn1_def {
                            fd.op_set_input(&crate::op::PcodeOpRef(def_op), vn2.clone(), 0);
                            changed = true;
                        }
                        break;
                    }
                    // vn1->getCover()->containVarnodeDef(vn2)==1 (merge.cc:1092)
                    let (v2_blk, v2_ord, v2_is_input) = varnode_def_loc(&vn2.read().unwrap());
                    // merge.cc:1092: vn1->getCover() lazy rebuild read —
                    // same discipline as the vn2 read above.
                    Varnode::update_cover_locked(vn1);
                    let vn1_covers_vn2 = vn1.read().unwrap()
                        .cover.as_ref().map(|c| c.contain_varnode_def_at(v2_is_input, v2_blk, v2_ord) == 1)
                        .unwrap_or(false);
                    if vn1_covers_vn2 {
                        // data.opSetInput(vn2->getDef(), vn1, 0) (merge.cc:1093)
                        let vn2_def = vn2.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
                        if let Some(def_op) = vn2_def {
                            fd.op_set_input(&crate::op::PcodeOpRef(def_op), vn1.clone(), 0);
                            changed = true;
                        }
                        null_mask[j] = true; // singlelist[j] = null (merge.cc:1094)
                    }
                }
            }
        self.detach(fd);
        changed
    }

    // RUDRA-GLUE: 遍历所有 HighVariable 调 hide_shadows_of。Ghidra 在
    // ActionHideShadow::apply (coreaction.cc:4831) 内联此遍历；Rudra 的
    // merge_all 也调用此方法，故提取为函数。
    /// Iterate all HighVariables and apply hide_shadows_of to each.
    /// Used by merge_all (Ghidra's ActionHideShadow does this via its own
    /// apply calling hideShadows per high).
    pub fn hide_shadows(&mut self, fd: &mut Funcdata) {
        self.attach(fd);
        let mut high_ptrs: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut highs: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        for vn_ref in &fd.vbank.loc_tree {
            let (written, high_arc) = {
                let vn = vn_ref.0.read().unwrap();
                (vn.is_written(), vn.high.clone())
            };
            if !written {
                continue;
            }
            if let Some(ha) = high_arc {
                let ptr = std::sync::Arc::as_ptr(&ha) as usize;
                if high_ptrs.insert(ptr) {
                    highs.push(ha);
                }
            }
        }
        for high in highs {
            self.hide_shadows_of(fd, &high);
        }
        self.detach(fd);
    }

    // Ghidra: merge.cc:1271 Merge::shadowedVarnode
    /// Determine if the given Varnode is shadowed by another Varnode in the
    /// same HighVariable. Faithful to `Merge::shadowedVarnode` (merge.cc:1271-1285).
    /// Returns true if any other instance's cover fully intersects (==2) vn's cover.
    fn shadowed_varnode(&self, vn: &Arc<RwLock<Varnode>>) -> bool {
        let high = vn.read().unwrap().high.clone();
        let Some(high) = high else { return false };
        let vn_cover = match &vn.read().unwrap().cover {
            Some(c) => c.clone(),
            None => return false,
        };
        let h = high.read().unwrap();
        for inst in &h.instances {
            if Arc::ptr_eq(inst, vn) {
                continue;
            }
            if let Some(ic) = &inst.read().unwrap().cover {
                if vn_cover.intersect_char(ic) == 2 {
                    return true;
                }
            }
        }
        false
    }

    // Ghidra: merge.cc:1112 Merge::checkCopyPair
    /// Check if the given COPY PcodeOps are redundant. Faithful to
    /// `Merge::checkCopyPair` (merge.cc:1112-1136). domOp must dominate subOp's
    /// block; constructs a range cover and checks for intervening writes.
    fn check_copy_pair(
        &self,
        high: &Arc<RwLock<HighVariable>>,
        dom_op: &crate::op::PcodeOpRef,
        sub_op: &crate::op::PcodeOpRef,
    ) -> bool {
        // domBlock->dominates(subBlock) (merge.cc:1117)
        let (dom_blk, sub_blk) = {
            let d = dom_op.0.read().unwrap();
            let s = sub_op.0.read().unwrap();
            let db = d.parent.as_ref().and_then(|w| w.upgrade());
            let sb = s.parent.as_ref().and_then(|w| w.upgrade());
            (db, sb)
        };
        match (&dom_blk, &sub_blk) {
            (Some(db), Some(sb)) => {
                // Check db dominates sb (db is ancestor in dom tree).
                if !db.read().unwrap().dominates(sb) {
                    return false;
                }
            }
            _ => return false,
        }
        // Build range cover: addDefPoint(domOp->getOut()) + addRefPoint(subOp, subOp->getIn(0)).
        let (dom_out, sub_in0, in_vn) = {
            let d = dom_op.0.read().unwrap();
            let s = sub_op.0.read().unwrap();
            (d.output.clone(), s.inrefs.get(0).cloned(), d.inrefs.get(0).cloned())
        };
        let mut range = Cover::new();
        if let Some(dov) = &dom_out {
            let dv = dov.read().unwrap();
            let def = dv.def.as_ref().and_then(|w| w.upgrade());
            let is_input = def.is_none() && dv.is_input();
            range.add_def_point_full(def.as_ref(), is_input);
        }
        if let Some(siv) = &sub_in0 {
            // addRefPoint(subOp, subOp->getIn(0)) via the full op-based
            // entry (merge.cc:1121): endpoint identity + backward CFG
            // recursion, matching the oracle's intervening-write window.
            let mut scratch_roots = Vec::new();
            let mut scratch_stack = Vec::new();
            range.add_ref_point_full(&sub_op.0, siv, &mut scratch_roots, &mut scratch_stack);
        }
        // Look for high instances with intervening writes (merge.cc:1124-1134).
        let h = high.read().unwrap();
        for i in 0..h.num_instances() {
            let Some(inst) = h.get_instance(i) else { continue };
            let (written, def_code_copy, def_in_eq_invn, def_blk, def_ord) = {
                let vn = inst.read().unwrap();
                let def_arc = vn.def.as_ref().and_then(|w| w.upgrade());
                match def_arc {
                    Some(d) => {
                        let def = d.read().unwrap();
                        let cc = def.opcode == crate::opcodes::OpCode::CPUI_COPY;
                        let eq = def.inrefs.get(0).map(|v| {
                            match &in_vn {
                                Some(iv) => Arc::ptr_eq(v, iv),
                                None => false,
                            }
                        }).unwrap_or(false);
                        let blk = def.parent.as_ref().and_then(|w| w.upgrade())
                            .map(|p| p.read().unwrap().get_index()).unwrap_or(0);
                        // contain(op,1) maps the op through getUIndex
                        // (cover.cc:107-120): MULTIEQUAL->0, INDIRECT->
                        // guarded-op order — raw SeqNum order would leave
                        // the u_index domain.
                        (true, cc, eq, blk, crate::cover::CoverBlock::get_u_index(&def))
                    }
                    None => (false, false, false, 0, 0),
                }
            };
            if !written {
                continue;
            }
            // If write is COPY from same Varnode as domOp → skip (merge.cc:1128-1130).
            if def_code_copy && def_in_eq_invn {
                continue;
            }
            // range.contain(op, 1) — check if def is in range (merge.cc:1131).
            if range.contain(def_blk, def_ord) {
                return false; // Intervening write → not redundant.
            }
        }
        true
    }

    // Ghidra: merge.cc:1249 Merge::markRedundantCopies
    /// Mark redundant COPY ops as non-printing. Faithful to
    /// `Merge::markRedundantCopies` (merge.cc:1249-1265).
    fn mark_redundant_copies(
        &mut self,
        fd: &mut Funcdata,
        high: &Arc<RwLock<HighVariable>>,
        copy: &[crate::op::PcodeOpRef],
        pos: usize,
        size: usize,
    ) {
        for i in (1..size).rev() {
            let sub_op = &copy[pos + i];
            if sub_op.0.read().unwrap().is_dead() {
                continue;
            }
            for j in (0..i).rev() {
                let dom_op = &copy[pos + j];
                if dom_op.0.read().unwrap().is_dead() {
                    continue;
                }
                if self.check_copy_pair(high, dom_op, sub_op) {
                    fd.op_mark_non_printing(sub_op);
                    break;
                }
            }
        }
    }

    // Ghidra: merge.cc:1345 Merge::processHighRedundantCopy
    /// Mark COPY ops into the given HighVariable that are redundant.
    /// Faithful to `Merge::processHighRedundantCopy` (merge.cc:1345-1367).
    fn process_high_redundant_copy(&mut self, fd: &mut Funcdata, high: &Arc<RwLock<HighVariable>>) {
        let copy_ins = self.find_all_into_copies(high, false);
        if copy_ins.len() < 2 {
            return;
        }
        let mut pos = 0usize;
        while pos < copy_ins.len() {
            let in_vn = copy_ins[pos].0.read().unwrap().inrefs.get(0).cloned();
            let Some(in_vn) = in_vn else { break; };
            let mut sz = 1usize;
            while pos + sz < copy_ins.len() {
                let next = copy_ins[pos + sz].0.read().unwrap().inrefs.get(0).cloned();
                match next {
                    Some(n) if Arc::ptr_eq(&n, &in_vn) => sz += 1,
                    _ => break,
                }
            }
            if sz > 1 {
                self.mark_redundant_copies(fd, high, &copy_ins, pos, sz);
            }
            pos += sz;
        }
    }

    // Ghidra: merge.hh:134 Merge::markInternalCopies
    /// Step 12: ActionCopyMarker (coreaction.hh:1019).
    /// Faithful to `Merge::markInternalCopies` (merge.cc:1444-1542).
    ///
    /// Walks all alive ops:
    /// - COPY: if output.high==input.high → nonprinting; else accumulate
    ///   multi-copy highs + check shadowedVarnode for no-descend outputs.
    /// - PIECE/SUBPIECE: same-VariableGroup reassembly/truncation with
    ///   aligned piece offsets → nonprinting + inputs forced explicit
    ///   (merge.cc:1478-1528; the VariablePiece cascade wiring in
    ///   merge_highs keeps the operand highs grouped so these arms fire).
    /// Then processHighRedundantCopy for highs with ≥2 copy-ins.
    pub fn mark_internal_copies(&mut self, fd: &mut Funcdata) {
        use crate::op::pcodeop_flags;
        use crate::opcodes::OpCode;

        self.attach(fd);


        // Ghidra merge.cc:1455-1532: iterate alive ops.
        // Collect COPY decisions + track multi-copy highs.
        let mut multi_copy: Vec<Arc<RwLock<HighVariable>>> = Vec::new();
        let mut multi_copy_seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let copy_ops: Vec<crate::op::PcodeOpRef> = fd.obank.iter_alive()
            .map(|r| crate::op::PcodeOpRef(r.0.clone()))
            .collect();
        for op_ref in &copy_ops {
            let opcode = op_ref.0.read().unwrap().opcode;
            match opcode {
                OpCode::CPUI_COPY => {
                    let (out_vn, in_vn, same_high, out_high) = {
                        let op = op_ref.0.read().unwrap();
                        let out = op.output.clone();
                        let in0 = op.inrefs.get(0).cloned();
                        let (sh, oh) = match (&out, &in0) {
                            (Some(o), Some(i)) => {
                                let o_rg = o.read().unwrap();
                                let i_rg = i.read().unwrap();
                                let sh = match (&o_rg.high, &i_rg.high) {
                                    (Some(ho), Some(hi)) => Arc::ptr_eq(ho, hi),
                                    _ => false,
                                };
                                (sh, o_rg.high.clone())
                            }
                            _ => (false, None),
                        };
                        (out, in0, sh, oh)
                    };
                    if same_high {
                        // merge.cc:1461-1462: internal COPY → nonprinting.
                        fd.op_mark_non_printing(op_ref);
                    } else if let Some(h1) = out_high {
                        // merge.cc:1465-1470: accumulate multi-copy tracking.
                        let ptr = Arc::as_ptr(&h1) as usize;
                        if !multi_copy_seen.contains(&ptr) {
                            multi_copy_seen.insert(ptr);
                            multi_copy.push(h1.clone());
                        }
                        // merge.cc:1471-1475: shadowed no-descend output → nonprinting.
                        if let Some(ov) = &out_vn {
                            let no_descend = ov.read().unwrap().has_no_descend();
                            if no_descend && self.shadowed_varnode(ov) {
                                fd.op_mark_non_printing(op_ref);
                            }
                        }
                    }
                    let _ = in_vn;
                }
                // PIECE: output built out of pieces of itself (merge.cc:1478-1506).
                // All three highs carry VariablePieces in the SAME group, with
                // offsets consistent with the concat reconstruction →
                // nonprinting op + inputs forced explicit (internal PIECE ops
                // are hidden; the pieces print as their own statements).
                OpCode::CPUI_PIECE => {
                    let (v1, v2, v3) = {
                        let op = op_ref.0.read().unwrap();
                        (
                            op.output.clone(),
                            op.inrefs.get(0).cloned(),
                            op.inrefs.get(1).cloned(),
                        )
                    };
                    let (Some(v1), Some(v2), Some(v3)) = (&v1, &v2, &v3) else { continue ;
                    };
                    let p1 = v1.read().unwrap().high.clone()
                        .and_then(|h| h.read().unwrap().piece.clone());
                    let p2 = v2.read().unwrap().high.clone()
                        .and_then(|h| h.read().unwrap().piece.clone());
                    let p3 = v3.read().unwrap().high.clone()
                        .and_then(|h| h.read().unwrap().piece.clone());
                    let (Some(p1), Some(p2), Some(p3)) = (p1, p2, p3) else { continue };
                    // p1->getGroup() != p2/p3->getGroup() → break (cc:1486-1489).
                    let same_group = {
                        let g1 = p1.read().unwrap().get_group_arc();
                        let g2 = p2.read().unwrap().get_group_arc();
                        let g3 = p3.read().unwrap().get_group_arc();
                        match (g1, g2, g3) {
                            (Some(a), Some(b), Some(c)) => {
                                Arc::ptr_eq(&a, &b) && Arc::ptr_eq(&a, &c)
                            }
                            _ => false,
                        }
                    };
                    if !same_group { continue; }
                    // Little-endian (cc:1496-1499): p3->getOffset() == p1->getOffset()
                    // && p2->getOffset() == p1->getOffset() + v3->getSize().
                    // (Rudra targets x86-64 LE only; the BE arm mirrors cc:1492-1495.)
                    let (p1_off, p2_off, p3_off) = (
                        p1.read().unwrap().group_offset,
                        p2.read().unwrap().group_offset,
                        p3.read().unwrap().group_offset,
                    );
                    let v3_size = v3.read().unwrap().get_size() as i32;
                    if p3_off != p1_off { continue; }
                    if p2_off != p1_off + v3_size { continue; }
                    fd.op_mark_non_printing(op_ref);
                    // cc:1499-1506: inputs forced explicit (clearImplied+setExplicit).
                    if v2.read().unwrap().is_implied() {
                        v2.write().unwrap().clear_implied();
                        v2.write().unwrap().set_explicit();
                    }
                    if v3.read().unwrap().is_implied() {
                        v3.write().unwrap().clear_implied();
                        v3.write().unwrap().set_explicit();
                    }
                }
                // SUBPIECE: internal field extraction (merge.cc:1508-1528).
                // out and in highs share a group and the truncation offset
                // matches the piece-offset delta → nonprinting + in(0) explicit.
                OpCode::CPUI_SUBPIECE => {
                    let (v1, v2, val) = {
                        let op = op_ref.0.read().unwrap();
                        (
                            op.output.clone(),
                            op.inrefs.get(0).cloned(),
                            op.inrefs.get(1).map(|c| c.read().unwrap().get_offset() as i32),
                        )
                    };
                    let (Some(v1), Some(v2), Some(val)) = (v1, v2, val) else { continue };
                    let p1 = v1.read().unwrap().high.clone()
                        .and_then(|h| h.read().unwrap().piece.clone());
                    let p2 = v2.read().unwrap().high.clone()
                        .and_then(|h| h.read().unwrap().piece.clone());
                    let (Some(p1), Some(p2)) = (p1, p2) else { continue };
                    let same_group = {
                        let g1 = p1.read().unwrap().get_group_arc();
                        let g2 = p2.read().unwrap().get_group_arc();
                        match (g1, g2) {
                            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
                            _ => false,
                        }
                    };
                    if !same_group { continue; }
                    // Little-endian (cc:1521-1523): p2->getOffset() + val ==
                    // p1->getOffset(). (BE arm mirrors cc:1518-1520.)
                    let (p1_off, p2_off) = (
                        p1.read().unwrap().group_offset,
                        p2.read().unwrap().group_offset,
                    );
                    if p2_off + val != p1_off { continue; }
                    fd.op_mark_non_printing(op_ref);
                    if v2.read().unwrap().is_implied() {
                        v2.write().unwrap().clear_implied();
                        v2.write().unwrap().set_explicit();
                    }
                }
                _ => {}
            }
        }
        // merge.cc:1533-1538: processHighRedundantCopy for multi-copy highs.
        // Ghidra checks hasCopyIn2 (≥2); we process all in multi_copy (they
        // all had ≥1, and processHighRedundantCopy internally checks ≥2 via
        // findAllIntoCopies + group size).
        for high in &multi_copy {
            self.process_high_redundant_copy(fd, high);
        }
        self.detach(fd);
    }

    // Ghidra: varnode.cc:233 Varnode::updateCover
    /// Materialize `vn.cover` for every live/input varnode as the exact
    /// product of the oracle's lazy cover machinery. Ghidra has NO eager
    /// cover pass inside Merge: covers are allocated by `Varnode::calcCover`
    /// (varnode.cc:254-263) at assign time (`Funcdata::setVarnodeProperties`
    /// / `assignHigh`, funcdata_varnode.cc:38-41/52-53) and rebuilt lazily
    /// by `Varnode::updateCover` (varnode.cc:233-241) on the first
    /// `getCover()` read after any `coverdirty` mutation.
    ///
    /// The oracle Cover shape (cover.cc:477-496 `Cover::rebuild` +
    /// `addDefPoint`/`addRefPoint`/`addRefRecurse`, cover.cc:501-612):
    ///   - def block: `[def, end-of-block]` once any read lives elsewhere;
    ///     `[def, def]` point when there are no reads;
    ///   - every block on ANY predecessor path from a read back toward the
    ///     def is filled FULLY (`addRefRecurse` setAll + backward
    ///     recursion over `bl->getIn(j)`) — the cover is reconstructed by
    ///     walking the CFG BACKWARD from each read, never forward over
    ///     successors;
    ///   - a MULTIEQUAL read only pulls cover through the incoming edges
    ///     whose slot actually reads the varnode (cover.cc:604-607);
    ///   - input varnodes plant the input marker at block 0
    ///     (cover.cc:514-518).
    ///
    /// This pass runs the same rebuild eagerly at one pipeline point.
    /// `Cover::rebuild` is a pure function of the varnode's def/descendant/
    /// CFG state, so forcing the COVERDIRTY flag before rebuilding yields
    /// the oracle state even if a Rudra mutation path misses setting the
    /// flag (the oracle's own rebuild always clears it afterward).
    pub fn compute_varnode_covers(&mut self, fd: &mut Funcdata) {
        let vn_arcs: Vec<Arc<RwLock<Varnode>>> = fd.vbank.loc_tree
            .iter()
            .filter(|r| {
                let v = r.0.read().unwrap();
                v.is_input() || self.live_set.contains(&(std::sync::Arc::as_ptr(&r.0) as usize))
            })
            .map(|r| r.0.clone())
            .collect();

        for vn_arc in vn_arcs {
            // Ghidra: funcdata_varnode.cc:52-53 assignHigh /
            // :38-41 setVarnodeProperties — `if (vn->hasCover())
            // vn->calcCover();` (hasCover excludes constants/annotations).
            let materialize = {
                let mut vn = vn_arc.write().unwrap();
                if !vn.has_cover() {
                    false
                } else {
                    if vn.cover.is_none() {
                        vn.calc_cover();
                    }
                    // Ghidra: varnode.cc:352 setFlags — calcCover's own
                    // cc:261 setFlags(coverdirty) already fired the high
                    // notification (flagsDirty + coverDirty + piece walk);
                    // this re-fire mirrors the sweep's unconditional dirty
                    // intent (MERGE-COPYNOISE-SPILLRESTORE-0001) and is
                    // idempotent, like the oracle's repeated setFlags calls.
                    vn.set_flags(varnode_flags::COVERDIRTY);
                    true
                }
            };
            if materialize {
                // Ghidra: varnode.cc:233 Varnode::updateCover →
                // cover.cc:477 Cover::rebuild (backward fill through
                // predecessors, MULTIEQUAL slot precision, INDIRECT marker
                // ordering) — the faithful path already implemented by
                // Cover::rebuild_from_root_snapshot.
                Varnode::update_cover_locked(&vn_arc);
            }
        }
    }
}

// Ghidra: merge.hh:83 Merge::aggregateHighCover
fn aggregate_high_cover(high: &Arc<RwLock<HighVariable>>) -> Cover {
    let h = high.read().unwrap();
    aggregate_high_cover_from(&h)
}

// Ghidra: variable.cc:324 HighVariable::updateInternalCover (merge.hh:83 aggregateHighCoverFrom)
/// Aggregate (union) the covers of every instance in a borrowed HighVariable.
/// Used by the speculative-merge primitive and copy/adjacent/type passes to
/// test whether two HighVariables are simultaneously live.
///
/// Faithful to Ghidra's accessor chain `inst[i]->getCover()`
/// (varnode.hh:202), which lazily REBUILDS a dirty Varnode Cover before it
/// is read (varnode.cc:233 Varnode::updateCover → cover->rebuild). Reading
/// the raw `cover` field without the rebuild merges stale (post-calcCover,
/// pre-rebuild) empty Covers, which silently disables every cover-based
/// merge gate downstream (RULE-PROPCOPY-ADDRTIED-0001 root cause: the
/// MULTIEQUAL lane trim in Merge::mergeOp never fired).
fn aggregate_high_cover_from(high: &HighVariable) -> Cover {
    let mut agg = Cover::new();
    // Ghidra: variable.cc:329 gates the whole merge on inst[0]->hasCover().
    let first_has_cover = high
        .instances
        .first()
        .map(|first| first.read().unwrap().has_cover())
        .unwrap_or(false);
    if !first_has_cover {
        return agg;
    }
    for inst_arc in &high.instances {
        // Ghidra: inst[i]->getCover() — lazy rebuild (varnode.cc:233-241),
        // then merge the rebuilt instance cover. No high-dirty propagation
        // across the rebuild (varnode.cc:365-374): the wrapper holds a READ
        // guard on this high (aggregate_high_cover) and this instance's high
        // IS this high — a member back-pointer write would self-deadlock.
        Varnode::update_cover_locked(inst_arc);
        if let Some(inst) = inst_arc.read().unwrap().cover.as_ref() {
            agg.merge(inst);
        }
    }
    agg
}

/// Represents a varnode within a specific block for merging purposes.
/// Faithful to Ghidra `BlockVarnode` (merge.hh:32-41). Stores a Varnode
/// with the index of the BlockBasic that defines it; if the Varnode has no
/// defining PcodeOp it is assigned index 0.
#[derive(Clone)]
pub struct BlockVarnode {
    /// The varnode reference
    pub vn: Arc<RwLock<Varnode>>,
    /// Index of the block defining this varnode (0 if no def op)
    pub block_index: i32,
}

impl BlockVarnode {
    // Ghidra: merge.cc:24 BlockVarnode::set
    /// Set this as representing the given Varnode, resolving its defining
    /// block index. Faithful to `BlockVarnode::set` (merge.cc:24-33).
    pub fn set(vn: Arc<RwLock<Varnode>>) -> Self {
        let block_index = {
            let v = vn.read().unwrap();
            let def_op = v.def.as_ref().and_then(|w| w.upgrade());
            match def_op {
                Some(op_arc) => {
                    let op = op_arc.read().unwrap();
                    match op.parent.as_ref().and_then(|w| w.upgrade()) {
                        Some(blk) => blk.read().unwrap().get_index(),
                        None => 0,
                    }
                }
                None => 0, // No def op (input varnode) → index 0
            }
        };
        Self { vn, block_index }
    }

    // Ghidra: merge.cc:43 BlockVarnode::findFront
    /// Find the first BlockVarnode defined in the block of the given index.
    /// Faithful to `BlockVarnode::findFront` (merge.cc:43-61) — binary search
    /// on a list sorted by block_index. Returns the list position or None.
    pub fn find_front(blocknum: i32, list: &[BlockVarnode]) -> Option<usize> {
        if list.is_empty() {
            return None;
        }
        let mut min = 0usize;
        let mut max = list.len() - 1;
        while min < max {
            let cur = (min + max) / 2;
            let curblock = list[cur].block_index;
            if curblock >= blocknum {
                max = cur;
            } else {
                min = cur + 1;
            }
        }
        if list[min].block_index == blocknum {
            Some(min)
        } else {
            None
        }
    }
}

// RUDRA-GLUE: trait impls for BlockVarnode ordering — Ghidra uses C++
// operator< (merge.hh:37) comparing by block_index; Rust requires
// PartialEq/Eq/PartialOrd/Ord derives for sort().
impl PartialEq for BlockVarnode {
    // RUDRA-GLUE: Rust trait method for == (Ghidra has no explicit eq).
    fn eq(&self, other: &Self) -> bool {
        self.block_index == other.block_index
    }
}
impl Eq for BlockVarnode {}
impl PartialOrd for BlockVarnode {
    // RUDRA-GLUE: Rust trait method (Ghidra operator< is in Ord::cmp below).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.block_index.cmp(&other.block_index))
    }
}
impl Ord for BlockVarnode {
    // RUDRA-GLUE: corresponds to Ghidra operator< (merge.hh:37) by block_index.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block_index.cmp(&other.block_index)
    }
}

// RUDRA-GLUE: resolve Varnode→(block,order,is_input) for cover queries.
// Ghidra inlines this via vn->getDef()->getParent()->getIndex() etc.
// (merge.cc:452,519). Extracted as a helper for borrow-safety in Rust.
/// Resolve a Varnode's defining location: (block_index, order, is_input).
/// Used by `eliminate_intersect` to query cover containment. If the Varnode
/// has no defining op (is_input==true), returns (0, _, true).
fn varnode_def_loc(vn: &Varnode) -> (i32, u32, bool) {
    let def_arc = match vn.def.as_ref().and_then(|w| w.upgrade()) {
        Some(a) => a,
        None => return (0, 0, true), // input varnode
    };
    let def = def_arc.read().unwrap();
    let order = def.get_seq_num().order;
    let block = match def.parent.as_ref().and_then(|w| w.upgrade()) {
        Some(blk) => blk.read().unwrap().get_index(),
        None => 0,
    };
    (block, order, false)
}

// RUDRA-GLUE: resolve PcodeOp→(block,order) for cover ref-point queries.
// Ghidra inlines via op->getParent()->getIndex() + SeqNum::getOrder().
/// Resolve a PcodeOp's location: (block_index, order).
fn op_loc(op: &crate::op::PcodeOp) -> (i32, u32) {
    let order = op.get_seq_num().order;
    let block = match op.parent.as_ref().and_then(|w| w.upgrade()) {
        Some(blk) => blk.read().unwrap().get_index(),
        None => 0,
    };
    (block, order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use crate::opcodes::OpCode;
    use crate::pcoderaw::{PcodeOpRaw, VarnodeRaw};
    use crate::space::AddressSpace;

    /// Regression lock (MERGE-COPYTRIMS-CACHE-0001, S1W2 wave-3): the
    /// merge_highs (Some,Some) both-piece arm must run the
    /// variable.cc:699-711 group cascade (merge_groups pairs + per-pair
    /// moveIntersectTests/mergeInternal + markIntersectionDirty) and return
    /// true. The pre-fix arm unconditionally `return false`-ed (its
    /// "unreachable while group_partials is a no-op" premise was stale —
    /// group_partials is implemented and populates pieces), which silently
    /// dropped every both-piece required merge: vmprintf@sqlite mergecopy
    /// unique-input merges were 119/224 vs oracle 202/222, with the
    /// PIECE16-family CONCAT inputs at the 0xad58c phi failing in slots
    /// 91-104. After the fix the count is 202/224 (oracle 202/222).
    #[test]
    fn test_merge_highs_both_pieces_runs_group_cascade() {
        use crate::variable::{HighVariable, VariableGroup, VariablePiece};

        let dt = std::sync::Arc::new(crate::type_system::datatype::Datatype::Base(
            crate::type_system::datatype::TypeBase::new(
                "undefined8".to_string(),
                8,
                crate::type_system::datatype::TypeMetatype::Unknown,
            ),
        ));

        // Two highs, one 16B varnode instance each, each owning a 16B@0
        // VariablePiece in its own (separate) group — the vmprintf PIECE16
        // topology at the failing phi.
        let mk = |off: u64| {
            let vn = std::sync::Arc::new(std::sync::RwLock::new(Varnode::new_with_space(
                16,
                AddressSpace::Unique,
                off,
            )));
            let high = std::sync::Arc::new(std::sync::RwLock::new(HighVariable::new(dt.clone())));
            high.write().unwrap().add_instance(vn.clone());
            vn.write().unwrap().high = Some(high.clone());
            let group = std::sync::Arc::new(std::sync::RwLock::new(VariableGroup::new()));
            let piece = std::sync::Arc::new(std::sync::RwLock::new(VariablePiece::new(
                std::sync::Arc::downgrade(&high),
                0,
                16,
                None,
            )));
            piece.write().unwrap().group = Some(group.clone());
            group.write().unwrap().add_piece(piece.clone());
            high.write().unwrap().piece = Some(piece.clone());
            (high, group, piece)
        };
        let (h1, g1, p1) = mk(0x2000);
        let (h2, g2, p2) = mk(0x3000);

        let mut merge = Merge::new();
        let merged = merge.merge_highs(&h1, &h2, false);

        // Merge::merge returns true after HighVariable::merge (variable.cc:712).
        assert!(merged, "both-piece required merge must succeed via group cascade");
        // The two 16B@0 pieces matched (variable.cc:206-211): h2's piece was
        // detached from its high and removed from g2, and h2's instance was
        // absorbed into h1 via the pair's mergeInternal.
        assert!(h2.read().unwrap().piece.is_none(), "matched op2 piece must be detached");
        assert!(g2.read().unwrap().is_empty(), "op2 group must lose the matched piece");
        assert_eq!(h1.read().unwrap().num_instances(), 2, "instances must be absorbed");
        assert!(h1.read().unwrap().piece.is_some(), "survivor keeps its piece");
        // Group-merge flags dirtied (variable.cc:710 markIntersectionDirty).
        assert_ne!(
            h1.read().unwrap().highflags
                & crate::variable::high_internal_flags::INTERSECTDIRTY,
            0,
            "markIntersectionDirty must fire"
        );
        // The pair merge absorbed p2's high instance into h1 — p1 survives.
        assert!(!g1.read().unwrap().is_empty());
        let _ = (p1, p2);
        // variable.cc:648-654 (mergeInternal, non-speculative arm): every
        // absorbed instance is re-pointed at the survivor via
        // `vn->setHigh(this, vn->getMergeGroup())`. Regression lock for the
        // STACKSLOT2 fix: the cascade's pairs loop used to leave the
        // absorbed high's instances pointing at the ghost (piece-detached)
        // high, so ActionCopyMarker's same-group arms never fired and join
        // CONCAT88 chains printed as bare unique temps.
        for inst in h1.read().unwrap().instances.clone() {
            let high_ptr = inst
                .read()
                .unwrap()
                .high
                .as_ref()
                .map(|h| std::sync::Arc::as_ptr(h) as usize);
            let want = std::sync::Arc::as_ptr(&h1) as usize;
            assert_eq!(
                high_ptr,
                Some(want),
                "absorbed instance must re-point vn.high at the surviving high"
            );
        }
    }

    /// Rust compare_order polarity must match C++ compareOrder: only a
    /// strictly earlier candidate replaces the selected PIECE root.
    #[test]
    fn test_compare_order_selects_strictly_earlier_op() {
        let mut fd = Funcdata::new("compare_order", Address::new(0x7000), 0x20);
        let mut first = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        first.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        first.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8));
        let mut second = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        second.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x108, 8));
        second.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8));
        fd.inject_raw_ops(&[first, second]);
        let ops: Vec<_> = fd.obank.optree.iter().map(|r| r.0.clone()).collect();
        assert!(ops.len() >= 2, "two ordered ops should be present");
        let earlier = ops[0].read().unwrap();
        let later = ops[1].read().unwrap();
        assert_eq!(earlier.compare_order(&later), -1);
        assert_eq!(later.compare_order(&earlier), 1);
        // Selection rule used by partial_root: a later candidate cannot
        // replace the earlier one, while an earlier candidate can.
        assert!(!(later.compare_order(&earlier) < 0));
        assert!(earlier.compare_order(&later) < 0);
    }

    /// Two COPYs feeding the same register at different times should NOT
    /// merge if their covers overlap. Concretely:
    ///   t1 = COPY(RDI)   -- block 0
    ///   use(t1)
    ///   t2 = COPY(RSI)   -- block 0, after t1's use
    ///   use(t2)
    /// RDI and RSI both flow into t1/t2, but RDI and RSI are different
    /// parameters that are not copy-related — so they must keep separate
    /// HighVariables.
    #[test]
    fn test_merge_by_cover_keeps_independent_registers_separate() {
        let mut fd = Funcdata::new("independent", Address::new(0x2000), 0x80);

        let mut c1 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        c1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut c2 = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        c2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));
        c2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI

        fd.inject_raw_ops(&[c1, use1, c2]);
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        // RDI varnode and RSI varnode should NOT share a high (they're
        // not copy-related; nothing connects them).
        let rdi_vn = fd
            .vbank
            .loc_tree
            .iter()
            .find(|r| {
                let v = r.0.read().unwrap();
                v.address_space == AddressSpace::Register && v.loc == Address::new(0x38)
            })
            .map(|r| r.0.clone())
            .expect("RDI varnode should exist");
        let rsi_vn = fd
            .vbank
            .loc_tree
            .iter()
            .find(|r| {
                let v = r.0.read().unwrap();
                v.address_space == AddressSpace::Register && v.loc == Address::new(0x30)
            })
            .map(|r| r.0.clone())
            .expect("RSI varnode should exist");

        let rdi_high = rdi_vn.read().unwrap().high.clone().expect("RDI has high");
        let rsi_high = rsi_vn.read().unwrap().high.clone().expect("RSI has high");
        assert!(
            !Arc::ptr_eq(&rdi_high, &rsi_high),
            "RDI and RSI are independent parameters and must not share a HighVariable"
        );
    }

    /// `compute_varnode_covers` must materialize the oracle `Cover::rebuild`
    /// product (cover.cc:477-496): a def in b0 read in b2 through an empty
    /// intermediate b1 produces
    ///   b0: [def, end-of-block]   (addRefRecurse extends the stop, cc:542-543)
    ///   b1: full [begin, end]     (intermediate block setAll, cc:531-536)
    ///   b2: [begin, read]         (addRefPoint setEnd, cc:574-575)
    /// The pre-fix events approximation produced ONLY {b0: [def,MAX],
    /// b2: [0,read]} — the intermediate block never received cover.
    ///
    /// Layout (stride 0x10 per op):
    ///   b0 @0x1000: cmp; t=COPY(RDI); CBRANCH→0x1040
    ///   b1 @0x1030: BRANCH→0x1040        (pure intermediate block)
    ///   b2 @0x1040: STORE(...,t); RETURN  (read block)
    #[test]
    fn test_compute_varnode_covers_backfills_intermediate_blocks() {
        let mut fd = Funcdata::new("cover_backfill", Address::new(0x1000), 0x80);

        let mut cmp_zf = PcodeOpRaw::new(OpCode::CPUI_INT_EQUAL as i32);
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI
        cmp_zf.add_input(VarnodeRaw::new(AddressSpace::Register, 0x30, 8)); // RSI
        cmp_zf.set_output(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF

        let mut copy_t = PcodeOpRaw::new(OpCode::CPUI_COPY as i32);
        copy_t.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));
        copy_t.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        let mut cbranch = PcodeOpRaw::new(OpCode::CPUI_CBRANCH as i32);
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1040, 8)); // → b2
        cbranch.add_input(VarnodeRaw::new(AddressSpace::Register, 0x206, 1)); // ZF

        let mut goto_b2 = PcodeOpRaw::new(OpCode::CPUI_BRANCH as i32);
        goto_b2.add_input(VarnodeRaw::new(AddressSpace::Ram, 0x1040, 8)); // → b2

        let mut store = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        store.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8)); // RAM ptr
        store.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8)); // reads t

        let mut ret = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);

        fd.inject_raw_ops(&[cmp_zf, copy_t, cbranch, goto_b2, store, ret]);
        fd.bblocks.build_dom_tree();
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        // Locate t by (Unique, 0x100) — SSA/merge passes keep unique-space
        // identity stable.
        let t_vn = fd
            .vbank
            .loc_tree
            .iter()
            .find(|r| {
                let v = r.0.read().unwrap();
                v.address_space == AddressSpace::Unique
                    && v.loc.to_space_address().get_offset() == 0x100
                    && v.size == 8
            })
            .map(|r| r.0.clone())
            .expect("unique temp t should exist");

        let cover = t_vn
            .read()
            .unwrap()
            .cover
            .clone()
            .expect("t must have a materialized cover after compute_varnode_covers");
        let copy_op_def = t_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade());
        let (def_blk, def_order) = {
            let op_arc = copy_op_def.expect("t must keep its COPY def");
            let op = op_arc.read().unwrap();
            let blk_arc = op.parent.as_ref().and_then(|w| w.upgrade()).expect("def parent");
            let idx = blk_arc.read().unwrap().get_index();
            (idx, op.start.get_order())
        };

        // Exactly three blocks hold cover: the def block, the intermediate,
        // the read block.
        assert_eq!(
            cover.blocks.len(),
            3,
            "def + intermediate + read blocks must all hold cover (got {:?})",
            cover.blocks.keys().collect::<Vec<_>>()
        );

        // Def block: [def_order, MAX] — extended to end-of-block by
        // addRefRecurse (cover.cc:542-543).
        let def_cb = cover.blocks.get(&def_blk).expect("def block cover");
        assert_eq!(def_cb.start, def_order);
        assert_eq!(def_cb.end, u32::MAX, "def block extends to end-of-block");

        // Intermediate block (b1, the pure BRANCH block): FULL [0, MAX]
        // (cover.cc:531-536 setAll + predecessor recursion).
        let full_blocks: Vec<i32> = cover
            .blocks
            .iter()
            .filter(|(_, cb)| cb.start == 0 && cb.end == u32::MAX)
            .map(|(idx, _)| *idx)
            .collect();
        assert_eq!(
            full_blocks.len(),
            1,
            "exactly one intermediate block must be fully covered"
        );

        // Read block: [0, read_order] with read_order < MAX (the STORE).
        let read_blocks: Vec<(i32, u32)> = cover
            .blocks
            .iter()
            .filter(|(idx, cb)| **idx != def_blk && !(cb.start == 0 && cb.end == u32::MAX))
            .map(|(idx, cb)| (*idx, cb.end))
            .collect();
        assert_eq!(read_blocks.len(), 1, "exactly one read block");
        assert!(read_blocks[0].1 != u32::MAX, "read block ends at the read op, not end-of-block");
        assert!(read_blocks[0].1 > 0, "read block spans from begin to the read op");
    }

    /// `merge_marker` (ActionMergeRequired, merge.cc:889) must force-merge the
    /// input and output of a MULTIEQUAL (phi) op into the same HighVariable.
    ///
    /// Setup: a single-input MULTIEQUAL that forwards RDI into a unique temp,
    /// then the temp is used. Because MULTIEQUAL is a marker op, its input and
    /// output must share a HighVariable after the required-merge pass.
    #[test]
    fn test_merge_marker_unifies_multiequal_io() {
        let mut fd = Funcdata::new("phi_merge", Address::new(0x5000), 0x40);

        // u0 = MULTIEQUAL(RDI)
        let mut phi = PcodeOpRaw::new(OpCode::CPUI_MULTIEQUAL as i32);
        phi.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));
        phi.add_input(VarnodeRaw::new(AddressSpace::Register, 0x38, 8)); // RDI

        // use(u0)
        let mut store = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        store.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));
        store.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        fd.inject_raw_ops(&[phi, store]);
        // CANON-REGJUNK-INRAX-LIVEVAR-0001: inject_raw_ops no longer
        // pre-promotes register reads to INPUT (removed linear-scan phase
        // 3). This raw fixture injects a synthetic one-block MULTIEQUAL
        // (a shape SLEIGH never emits), so heritage's successor-edge pass
        // (heritage.cc:2531-2552) never sees a block boundary to bind the
        // phi input through; model the post-heritage state directly by
        // promoting the free register reads via setInputVarnode
        // (funcdata_varnode.cc:340-373), as renameRecurse would for an
        // empty reaching-def stack.
        {
            let reads: Vec<_> = fd
                .vbank
                .loc_tree
                .iter()
                .map(|v| v.0.clone())
                .collect();
            for vn in reads {
                let is_free_reg = {
                    let g = vn.read().unwrap();
                    g.get_space() == crate::space::AddressSpace::Register && g.is_free()
                };
                if is_free_reg {
                    let promoted = fd.set_input_varnode(vn.clone());
                    debug_assert!(Arc::ptr_eq(&promoted, &vn));
                }
            }
        }
        fd.run_heritage_direct();

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let phi_op = fd
            .obank
            .iter_alive()
            .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_MULTIEQUAL)
            .expect("MULTIEQUAL op should exist")
            .0
            .clone();
        let phi = phi_op.read().unwrap();
        let out_vn = phi.output.clone().expect("MULTIEQUAL output");
        let in_vn = phi.inrefs[0].clone();
        drop(phi);

        let out_high = out_vn.read().unwrap().high.clone().expect("phi out has high");
        let in_high = in_vn.read().unwrap().high.clone().expect("phi in has high");
        assert!(
            Arc::ptr_eq(&in_high, &out_high),
            "MULTIEQUAL input and output must share a HighVariable after merge_marker"
        );
    }

    /// `merge_multi_entry` (ActionMergeMultiEntry, merge.cc:908) must merge
    /// Varnodes mapped to distinct SymbolEntries of the same Symbol.
    ///
    /// Setup: two Unique-space temps `t1` and `t2` at different addresses,
    /// each carrying a `mapentry` pointing to a different SymbolEntry of the
    /// SAME Symbol (the multi-entry condition: ≥ 2 distinct whole-sized
    /// entries per Symbol). After `merge_all`, `t1` and `t2` must share one
    /// HighVariable because they are two storage locations of one logical
    /// variable.
    #[test]
    fn test_merge_multi_entry_unifies_symbol_entries() {
        use crate::database::{Symbol, SymbolEntry};
        use crate::address::RangeList;

        let mut fd = Funcdata::new("multi_entry", Address::new(0x6000), 0x80);

        // Two independent temps (different addresses) — nothing copy-related
        // links them, so only merge_multi_entry (via the shared Symbol) can
        // merge them.
        let mut def1 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8)); // RBX ptr
        def1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8)); // t1

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8)); // RSP addr
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8)); // store t1

        let mut def2 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x28, 8)); // RBP ptr
        def2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8)); // t2

        let mut use2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8)); // use t2

        fd.inject_raw_ops(&[def1, use1, def2, use2]);
        fd.run_heritage_direct();

        // Resolve the actual live Varnode objects (post-heritage the LOAD
        // outputs are the canonical t1/t2 instances). We grab them from the
        // defining LOAD ops' outputs — robust against loc_tree duplicate
        // entries that arise from raw injection.
        let loads: Vec<_> = fd
            .obank
            .iter_alive()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_LOAD)
            .map(|o| o.0.clone())
            .collect();
        assert_eq!(loads.len(), 2, "two LOAD ops expected");
        let t1 = {
            let l = loads[0].read().unwrap();
            l.output.clone().expect("LOAD1 output")
        };
        let t2 = {
            let l = loads[1].read().unwrap();
            l.output.clone().expect("LOAD2 output")
        };
        assert!(
            t1.read().unwrap().loc != t2.read().unwrap().loc,
            "t1 and t2 must be at distinct addresses"
        );

        // Build a single Symbol with two distinct SymbolEntries (multi-entry).
        let sym = Arc::new(RwLock::new(Symbol::new(0, "shared", "long")));
        let entry1 = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym.clone(),
            0,
            Address::new(0xAAA),
            0,
            8,
            RangeList::new(),
        )));
        let entry2 = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym.clone(),
            0,
            Address::new(0xBBB),
            0,
            8,
            RangeList::new(),
        )));

        // Attach entry1 → t1, entry2 → t2 (the canonical instances).
        t1.write().unwrap().mapentry = Some(entry1.clone());
        t2.write().unwrap().mapentry = Some(entry2.clone());

        let mut merge = Merge::new();
        merge.merge_all(&mut fd);

        let h1 = t1.read().unwrap().high.clone().expect("t1 has high");
        let h2 = t2.read().unwrap().high.clone().expect("t2 has high");
        assert!(
            Arc::ptr_eq(&h1, &h2),
            "multi-entry symbol's varnodes must share a HighVariable after merge_multi_entry"
        );
    }

    /// `merge_multi_entry` must NOT merge Varnodes whose SymbolEntries map to
    /// DIFFERENT Symbols (the single-entry case). Two temps each with their own
    /// one-entry Symbol should remain separate.
    #[test]
    fn test_merge_multi_entry_keeps_single_entry_symbols_separate() {
        use crate::database::{Symbol, SymbolEntry};
        use crate::address::RangeList;

        let mut fd = Funcdata::new("single_entry", Address::new(0x6050), 0x80);

        let mut def1 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x18, 8));
        def1.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut use1 = PcodeOpRaw::new(OpCode::CPUI_STORE as i32);
        use1.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Register, 0x20, 8));
        use1.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x100, 8));

        let mut def2 = PcodeOpRaw::new(OpCode::CPUI_LOAD as i32);
        def2.add_input(VarnodeRaw::new(AddressSpace::Const, 0, 8));
        def2.add_input(VarnodeRaw::new(AddressSpace::Register, 0x28, 8));
        def2.set_output(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        let mut use2 = PcodeOpRaw::new(OpCode::CPUI_RETURN as i32);
        use2.add_input(VarnodeRaw::new(AddressSpace::Unique, 0x200, 8));

        fd.inject_raw_ops(&[def1, use1, def2, use2]);
        // Production premise (Ghidra raw p-code): a LOAD's pointer input is
        // the stack spacebase register, which carries Varnode::spacebase and
        // is rejected by mergeTestBasic (merge.cc:255-264). The raw injector
        // cannot set varnode flags, so mirror the premise explicitly.
        for vn_ref in &fd.vbank.loc_tree {
            let mut vn = vn_ref.0.write().unwrap();
            if vn.address_space == AddressSpace::Register
                && (vn.get_offset() == 0x18 || vn.get_offset() == 0x28)
                && vn.size == 8
            {
                vn.flags |= crate::varnode::varnode_flags::SPACEBASE;
            }
        }
        fd.run_heritage_direct();

        // Resolve the canonical live Varnode objects via the defining LOAD ops.
        let loads: Vec<_> = fd
            .obank
            .iter_alive()
            .filter(|o| o.0.read().unwrap().opcode == OpCode::CPUI_LOAD)
            .map(|o| o.0.clone())
            .collect();
        assert_eq!(loads.len(), 2, "two LOAD ops expected");
        let t1 = {
            let l = loads[0].read().unwrap();
            l.output.clone().expect("LOAD1 output")
        };
        let t2 = {
            let l = loads[1].read().unwrap();
            l.output.clone().expect("LOAD2 output")
        };

        // Two DIFFERENT symbols, each with one entry (not multi-entry).
        let sym_a = Arc::new(RwLock::new(Symbol::new(0, "a", "long")));
        let sym_b = Arc::new(RwLock::new(Symbol::new(0, "b", "long")));
        let entry_a = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym_a,
            0,
            Address::new(0xAAA),
            0,
            8,
            RangeList::new(),
        )));
        let entry_b = Arc::new(RwLock::new(SymbolEntry::new_static(
            sym_b,
            0,
            Address::new(0xBBB),
            0,
            8,
            RangeList::new(),
        )));

        // Production premise (Ghidra pipeline order): ActionAssignHigh
        // (:5717) creates the HighVariables BEFORE ScopeLocal attaches
        // symbol entries, and the attach path marks the owning HighVariable
        // symbol-dirty so updateSymbol sees the entry (variable.cc:421-432).
        fd.set_high_level();
        t1.write().unwrap().set_symbol_entry(entry_a.clone());
        t2.write().unwrap().set_symbol_entry(entry_b.clone());
        for t in [&t1, &t2] {
            let high = t.read().unwrap().high.clone().expect("high after set_high_level");
            high.write().unwrap().highflags |=
                crate::variable::high_internal_flags::SYMBOLDIRTY;
        }

        let mut merge = Merge::new();
        let h1 = t1.read().unwrap().high.clone().expect("t1 has high");
        let h2 = t2.read().unwrap().high.clone().expect("t2 has high");
        assert!(
            !Arc::ptr_eq(&h1, &h2),
            "single-entry symbol varnodes must NOT be merged by merge_multi_entry"
        );
    }

    /// Regression-only checks (Rudra side; oracle proof lives in
    /// tests/oracle/merge_persistent_1204): `local_type_key_eq` mirrors
    /// getBaseNoChar canonical identity (type.cc:3619-3626) — the
    /// BaseNoChar/Base pair differs ONLY at (Int, 1) and ONLY when the
    /// factory registers both the ASCII 1-byte char and the non-ASCII
    /// 1-byte int (type.cc:3220-3242).
    #[test]
    fn test_local_type_key_eq_nochar_semantics() {
        use TypeMetatype::{Float, Int};

        let base_int1 = LocalTypeKey::Base(Int, 1);
        let nochar_int1 = LocalTypeKey::BaseNoChar(Int, 1);
        // Null-type_nochar world (type.cc:3624 fallthrough): same pointer.
        assert!(local_type_key_eq(&base_int1, &nochar_int1, false));
        assert!(local_type_key_eq(&nochar_int1, &base_int1, false));
        // Registered char+int1 world (type.cc:3622-3623): typecache[1][INT]
        // is the char, getBaseNoChar returns type_nochar — different.
        assert!(!local_type_key_eq(&base_int1, &nochar_int1, true));
        assert!(!local_type_key_eq(&nochar_int1, &base_int1, true));
        // Same-kind identity holds in both worlds.
        assert!(local_type_key_eq(&nochar_int1, &nochar_int1, true));
        assert!(local_type_key_eq(&base_int1, &base_int1, true));
        // Sizes != 1: getBaseNoChar IS getBase (type.cc:3624).
        assert!(local_type_key_eq(
            &LocalTypeKey::Base(Int, 4),
            &LocalTypeKey::BaseNoChar(Int, 4),
            true
        ));
        // Non-INT metatypes at size 1: the type_nochar guard needs
        // m == TYPE_INT (type.cc:3622).
        assert!(local_type_key_eq(
            &LocalTypeKey::Base(Float, 1),
            &LocalTypeKey::BaseNoChar(Float, 1),
            true
        ));
    }

    /// The nochar distinction is the effective factory's actual canonical
    /// identity relation. These tests cover no factory, the default single
    /// non-char INT1 (equal), and custom-named non-char+ASCII INT1 (distinct).
    /// Multiple non-char ordering is covered by typefactory_local_cache_1204.
    #[test]
    fn test_factory_nochar_distinct_registration_state() {
        let fd = Funcdata::new("nochar_null", Address::new(0x7100), 0x80);
        assert!(!Merge::factory_nochar_distinct(&fd));

        let mut fd_int1_only = Funcdata::new("nochar_int1", Address::new(0x7101), 0x80);
        let mut arch = crate::arch::Architecture::new();
        // Raw pre-bootstrap factory (type.cc:3106) + a single non-ASCII
        // "int1" core registration: since DEBUGPROTO-DWARF-CHAR-0001 the
        // DataOrg bootstrap itself supplies an ASCII char, so the charless
        // registration state must be built explicitly. The non-ASCII int
        // fills typecache[1][INT] itself and is picked as type_nochar
        // (type.cc:3240-3242), so getBase(1,INT) == type_nochar — NOT
        // distinct.
        let mut int1_factory = crate::type_system::typefactory::TypeFactory::raw();
        int1_factory
            .set_core_type_result("int1", 1, TypeMetatype::Int, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        int1_factory.cache_core_types();
        arch.set_types(std::sync::Arc::new(std::sync::RwLock::new(int1_factory)));
        fd_int1_only.set_arch(std::sync::Arc::new(arch));
        assert!(!Merge::factory_nochar_distinct(&fd_int1_only));

        let mut fd_char = Funcdata::new("nochar_char", Address::new(0x7102), 0x80);
        let mut arch = crate::arch::Architecture::new();
        let mut custom_factory = crate::type_system::typefactory::TypeFactory::new(8);
        custom_factory.clear();
        custom_factory
            .set_core_type_result("signed_byte_custom", 1, TypeMetatype::Int, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        custom_factory
            .set_core_type_result("ascii_glyph_custom", 1, TypeMetatype::Int, true)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        custom_factory.cache_core_types();
        let factory = std::sync::Arc::new(std::sync::RwLock::new(custom_factory));
        arch.set_types(factory);
        fd_char.set_arch(std::sync::Arc::new(arch));
        assert!(Merge::factory_nochar_distinct(&fd_char));
    }

}
