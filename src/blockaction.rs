//! Control flow structuring actions
//!
//! Corresponds to Ghidra's `blockaction.hh`

use crate::action::{action_status, Action};
use crate::address::Address;
use crate::block::{
    BlockBasic, BlockCondition, BlockGraph, BlockIf, BlockList, BlockMultiGoto, BlockSwitch,
    BlockWhileDo, BoolOp, FlowBlock,
};
use crate::error::Result;
use crate::funcdata::Funcdata;
use crate::opcodes::OpCode;
use std::sync::{Arc, RwLock};

/// Action for recovering high-level control flow structures
///
/// Corresponds to Ghidra's `ActionBlockStructure`. This action transforms
/// a flat basic block graph into a hierarchical structure of if, while,
/// and other high-level blocks.
pub struct ActionBlockStructure {
    /// CollapseStructure data-flow change count accumulated into the Action.
    pub count: i32,
}

impl ActionBlockStructure {
    // Ghidra: blockaction.hh:311 ActionBlockStructure::new
    /// Create a new ActionBlockStructure instance
    pub fn new() -> Self {
        Self { count: 0 }
    }
}

impl Action for ActionBlockStructure {
    // Ghidra: blockaction.cc:2169 ActionBlockStructure::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        // blockaction.cc:2173-2175: a populated structure is never rebuilt by
        // this Action. CFG mutators are responsible for structureReset.
        if fd.sblocks.get_size() != 0 {
            return Ok(action_status::NO_CHANGE);
        }

        // RUDRA-GLUE: env-gated (RUDRA_BS_TRACE=1) CFG signature dumper for
        // mainloop non-convergence triage; no Ghidra counterpart (debug-only).
        if std::env::var("RUDRA_BS_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            static ROUND: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let round = ROUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let sig = bs_trace_cfg_sig(&fd.bblocks);
            eprintln!("[BSTRACE] {} round={} pre  {}", fd.name, round, sig);
        }

        // blockaction.cc:2176 installs the default switch-edge labels on the
        // basic graph before buildCopy snapshots its ordered edge vectors.
        fd.install_switch_defaults();

        // TEMP PROBE (selectgoto lane): per-round basic-block CFG signature —
        // the counterpart of the oracle probe's GLM_BBSIG dump at
        // ActionBlockStructure::apply entry. Env-gated; default off.
        if std::env::var("RUDRA_BBSIG").is_ok() {
            static ROUND: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let round = ROUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut sig = String::new();
            for i in 0..fd.bblocks.get_size() {
                let Some(b) = fd.bblocks.get_block(i) else { continue };
                let rg = b.read().unwrap();
                let start = rg.get_start_addr().as_u64();
                let outs: Vec<String> = (0..rg.size_out())
                    .filter_map(|j| {
                        rg.get_out(j).map(|e| {
                            format!(
                                "{:#x}",
                                fd.bblocks
                                    .bank
                                    .expect_arc(e.point)
                                    .read()
                                    .unwrap()
                                    .get_start_addr()
                                    .as_u64()
                            )
                        })
                    })
                    .collect();
                sig.push_str(&format!("  bb{} {:#x} o={} -> [{}]\n", i, start, outs.len(), outs.join(",")));
            }
            let _ = std::fs::write(format!("{}.bbsig{}", fd.name, round), &sig);
        }

        // Build a copy of the basic block graph into the structure graph
        fd.sblocks.build_copy(&fd.bblocks);

        // Collapse structured patterns iteratively
        let mut collapse = CollapseStructure::new(&mut fd.sblocks, &fd.name)
            .with_jump_tables(fd.jump_tables.clone());
        collapse.collapse_all();
        self.count += collapse.get_change_count() as i32;

        // TEMP PROBE (selectgoto lane): dump the sblocks tree right after the
        // first collapseAll — the counterpart of the oracle probe's
        // post-collapse printTree dump (GLM_TREE1). Uncommitted-diagnostics.
        if std::env::var("RUDRA_TREE1").is_ok() {
            let mut out = String::new();
            for blk in &fd.sblocks.blocks {
                crate::block::print_tree_dbg(blk, 0, &mut out);
            }
            let n = std::fs::write(format!("{}.tree1", fd.name), &out);
            if let Err(e) = n {
                eprintln!("[TREE1] dump failed for {}: {}", fd.name, e);
            }
        }

        // RUDRA-GLUE: post-collapse witness for the RUDRA_BS_TRACE dumper.
        if std::env::var("RUDRA_BS_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            let sig = bs_trace_cfg_sig(&fd.bblocks);
            eprintln!("[BSTRACE] {} post  {}", fd.name, sig);
        }

        // RUDRA-GLUE: env-gated (RUDRA_BS_TREES=<prefix>) per-round
        // structured-tree dump — the counterpart of the oracle ladder
        // probe's per-perform printTree (diagnostic only, no pipeline
        // effect). One file per blockstructure application, ordered by a
        // process-global round counter.
        if let Ok(prefix) = std::env::var("RUDRA_BS_TREES") {
            static ROUND: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let round = ROUND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut tree_out = String::new();
            for blk in &fd.sblocks.blocks {
                crate::block::print_tree_dbg(blk, 0, &mut tree_out);
            }
            let _ = std::fs::write(format!("{}.{}", prefix, round), &tree_out);
        }

        // Ghidra blockaction.cc:2184: `count += collapse.getChangeCount();
        // return 0;` — the structurer NEVER feeds the repeatapply loop
        // (returning a change count here made Rudra's mainloop re-enter
        // forever once rules also reported changes).
        Ok(action_status::NO_CHANGE)
    }

    // RUDRA-GLUE: externalizes Ghidra's inherited protected Action::count
    // (blockaction.cc:2181 `count += collapse.getChangeCount()`) into the
    // Rust ActionState accumulator harvested by Action::perform.
    fn take_count_delta(&mut self) -> i32 {
        std::mem::take(&mut self.count)
    }

    // Ghidra: blockaction.hh:311 ActionBlockStructure::getName
    fn get_name(&self) -> &str {
        "blockstructure"
    }
}

// RUDRA-GLUE: env-gated (RUDRA_BS_TRACE=1) CFG signature helper for
// mainloop non-convergence triage; no Ghidra counterpart (debug-only).
fn bs_trace_cfg_sig(graph: &BlockGraph) -> String {
    let mut sig = format!("bbsize={}", graph.get_size());
    for i in 0..graph.get_size() {
        if let Some(b) = graph.get_block(i) {
            let r = b.read().unwrap();
            let addr = r
                .as_any()
                .downcast_ref::<BlockBasic>()
                .map(|bb| format!("{:x}", bb.get_start_addr().as_u64()))
                .unwrap_or_else(|| "-".to_string());
            sig.push_str(&format!(
                " {}#{}@{}<{}>i{}o{}",
                i,
                r.get_index(),
                addr,
                debug_type_name(&*r),
                r.size_in(),
                r.size_out()
            ));
            for s in 0..r.size_out() {
                if let Some(e) = r.get_out(s) {
                    let dst = graph.bank.expect_index(e.point);
                    sig.push_str(&format!(
                        "->{}{}",
                        dst,
                        if r.is_goto_out(s) { "G" } else { "" }
                    ));
                }
            }
            let cb = r
                .get_ops()
                .last()
                .map(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                .unwrap_or(false);
            if cb {
                sig.push('C');
                if let Some(o) = r.get_ops().last() {
                    let op = o.0.read().unwrap();
                    let (konst, val) = op
                        .get_in(1)
                        .map(|v| {
                            let vg = v.read().unwrap();
                            (vg.is_constant(), vg.get_offset())
                        })
                        .unwrap_or((false, 0));
                    let flip = (op.flags & crate::op::pcodeop_flags::BOOLEAN_FLIP) != 0;
                    sig.push_str(&format!("[cbr const={} val={:x} flip={}]", konst, val, flip));
                }
            }
            sig.push_str(&format!("F{:#x}", r.get_flags()));
        }
    }
    sig
}

// RUDRA-GLUE: short type tag for the env-gated RUDRA_BS_TRACE CFG signature
// dumper (downcast-based; the derived Debug impls recurse into children and can
// overflow the worker stack). Debug-only helper, no Ghidra counterpart.
fn debug_type_name(b: &dyn FlowBlock) -> String {
    let any = b.as_any();
    if any.is::<crate::block::BlockBasic>() {
        "Basic".into()
    } else if any.is::<crate::block::BlockCopy>() {
        "Copy".into()
    } else if any.is::<crate::block::BlockGraph>() {
        "Graph".into()
    } else if any.is::<crate::block::BlockList>() {
        "List".into()
    } else if any.is::<crate::block::BlockIf>() {
        "If".into()
    } else if any.is::<crate::block::BlockWhileDo>() {
        "WhileDo".into()
    } else if any.is::<crate::block::BlockDoWhile>() {
        "DoWhile".into()
    } else if any.is::<crate::block::BlockGoto>() {
        "Goto".into()
    } else if any.is::<crate::block::BlockCondition>() {
        "Condition".into()
    } else if any.is::<crate::block::BlockInfLoop>() {
        "InfLoop".into()
    } else if any.is::<crate::block::BlockSwitch>() {
        "Switch".into()
    } else {
        "Other".into()
    }
}

// Ghidra: block.cc:240 FlowBlock::setOutEdgeFlag (+ mirrored in-edge half,
// block.cc:245-247)
/// OR-set an edge label on the `j`-th outgoing edge of ANY concrete block
/// type and on the mirrored in-edge of the target. Ghidra's label lives in
/// the FlowBlock base's `outofthis`/`intothis` arrays, so one base-class
/// method covers every block type; Rudra's per-struct `outgoing`/`incoming`
/// Vecs historically required an explicit downcast per type. The shared
/// trait path now reaches every built-in edge owner; this local compatibility
/// form likewise keeps a goto mark observable to
/// ruleBlockGoto/ruleBlockProperIf/isDecisionOut and to TraceDAG's
/// isLoopDAGOut exclusion, exactly like the oracle
/// (BLOCKSTRUCT-NORETURN-DEADREGION-0001).
fn set_out_edge_flag_all_types(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    j: usize,
    label: u32,
) {
    // (target, reverse slot) captured first to avoid holding locks across blocks.
    let bank = bl.read().unwrap().bank();
    let mirror = bl
        .read()
        .unwrap()
        .get_out(j)
        .map(|e| (bank.expect_arc(e.point), e.reverse_index));
    {
        let mut w = bl.write().unwrap();
        if let Some(edge) = w.out_edges_mut().get_mut(j) {
            edge.flags |= label;
        }
        // (wave 3) label write on the out half — refresh the mirror under
        // the same guard.
        w.sync_out_edge_shadow();
    }
    // block.cc:245-247: the target's in-edge half of the label.
    if let Some((target, rev)) = mirror {
        let mut t = target.write().unwrap();
        let ri = rev as usize;
        if let Some(edge) = t.in_edges_mut().get_mut(ri) {
            edge.flags |= label;
        }
        // (wave 3) the target's in-half label — refresh under the guard.
        t.sync_in_edge_shadow();
    }
}

// Ghidra: block.cc:178 FlowBlock::replaceOutEdge (selfIdentify's external-src half, block.cc:910-912)
/// Retarget every outgoing edge of `bl` that currently points at the block
/// whose graph index is `old_idx` so it points at `new_block` instead.
/// Type-agnostic mirror of Ghidra's `otherbl->replaceOutEdge(j,this)`:
/// Ghidra's virtual edge arrays live on every FlowBlock, so the rewrite
/// lands for structured components (BlockList/BlockIf/...) exactly as for
/// BlockBasic. The previous BlockBasic-only rewrite left structured blocks'
/// stale edges pointing at consumed (DEAD) components, inflating the
/// sizeIn/sizeOut tests of downstream rules (ruleBlockCat's
/// `outblock->sizeIn() != 1`, blockaction.cc:1292).
pub(crate) fn rewrite_out_edges_to_idx(
    bank: &crate::block::BlockBankView,
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    old_idx: i32,
    new_point_id: crate::arena::BlockId,
) -> bool {
    let mut changed = false;
    let mut w = bl.write().unwrap();
    for edge in w.out_edges_mut() {
        // Snapshot-view read (zero-lock): the caller holds one
        // BlockBankView across the sweep and no publish happens inside it
        // (the rewrite only mutates edge fields), so the view stays fresh
        // — identical values to the per-read form.
        let target_index = bank.index(edge.point);
        let target_index = match target_index {
            Some(idx) => idx,
            None => continue,
        };
        if target_index == old_idx && edge.point != new_point_id {
            edge.point = new_point_id;
            changed = true;
        }
    }
    // (wave 3) edge points were retargeted — refresh the out mirror under
    // the same guard, ONLY when something actually changed (this rewrite
    // runs per boundary edge of every self-identify install — the no-op
    // calls are the overwhelming majority; syncing them was 95% of the
    // wave-3 write amplification on the VdbeExec corpus).
    if changed {
        w.sync_out_edge_shadow();
    }
    changed
}

// Ghidra: block.cc:160 FlowBlock::replaceInEdge (selfIdentify's external-dst half, block.cc:922-924)
/// Retarget every incoming edge of `bl` that currently comes from the block
/// whose graph index is `old_idx` so it comes from `new_block` instead.
/// Type-agnostic mirror of Ghidra's `otherbl->replaceInEdge(j,this)`.
pub(crate) fn rewrite_in_edges_to_idx(
    bank: &crate::block::BlockBankView,
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    old_idx: i32,
    new_point_id: crate::arena::BlockId,
) -> bool {
    let mut changed = false;
    let mut w = bl.write().unwrap();
    for edge in w.in_edges_mut() {
        // Snapshot-view read (zero-lock): see rewrite_out_edges_to_idx.
        let source_index = bank.index(edge.point);
        let source_index = match source_index {
            Some(idx) => idx,
            None => continue,
        };
        if source_index == old_idx && edge.point != new_point_id {
            edge.point = new_point_id;
            changed = true;
        }
    }
    // (wave 3) edge points were retargeted — refresh the in mirror under
    // the same guard, ONLY when something actually changed (see the out
    // half's note).
    if changed {
        w.sync_in_edge_shadow();
    }
    changed
}

// Ghidra: block.cc:525 FlowBlock::dedup (external half of selfIdentify's dedup)
/// Merge duplicate edges in `bl`'s in/out lists: keep the first edge to each
/// distinct block, OR the labels together, drop the rest — the semantics of
/// `FlowBlock::dedup`/`eliminateInDups`/`eliminateOutDups` (block.cc:447-501,
/// 525-539). Ghidra runs `this->dedup()` on the composite; its half-deletes
/// also clean the external counterpart halves, because Ghidra edges are
/// paired. Rudra's one-sided edge model needs the same dedup applied to the
/// external blocks that just had multiple edges retargeted onto the same
/// composite (e.g. both the outer condition's false-exit and the inner
/// clause's exit retarget onto the shared merge block, which must end with
/// exactly one in-edge from the composite so ruleBlockCat can chain it).
///
/// RUDRA-GLUE guard discipline: the oracle's eliminateInDups/eliminateOutDups
/// (block.cc:447-501) perform each duplicate's PAIRED half-deletes
/// synchronously — `halfDeleteInEdge(i)` here plus `bl->halfDeleteOutEdge(rev)`
/// on the peer — over raw pointers with no locking. The former port ran the
/// whole dedup under ONE `bl.write()` guard, so the peer-side half-delete (and
/// the sliding repairs that target `bl` from a peer's slide) hit a held lock
/// and either mis-routed the repair to the wrong block's list (the switch
/// goto-case unlock OOB crash) or deadlocked convergence. This orchestrator
/// keeps the oracle's exact per-duplicate semantics but takes ONE guard at a
/// time: `bl`'s guard covers only `bl`-side mutations, is dropped before the
/// peer-side half-delete runs, so every reciprocal repair (both directions,
/// including repairs back onto `bl`) executes synchronously exactly as in
/// Ghidra. The per-Funcdata graph rewrite is single-threaded, so no mutation
/// can interleave in the guard-drop windows.
pub(crate) fn dedup_edges_all_types(bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
    // Ghidra dedup (block.cc:530-535): findDups(intothis) → eliminateInDups
    // for each dup peer; clear; findDups(outofthis) → eliminateOutDups.
    let in_dups = find_dup_peers(bl, true);
    for peer in in_dups {
        eliminate_dup_pairs(bl, &peer, true);
    }
    let out_dups = find_dup_peers(bl, false);
    for peer in out_dups {
        eliminate_dup_pairs(bl, &peer, false);
    }
}

// Ghidra: block.cc:507 FlowBlock::findDups
/// Discover peer blocks that are the endpoint of 2+ edges in `bl`'s in- or
/// out-list (whichever `incoming` selects), using Ghidra's mark/mark2
/// protocol. Two behaviorally equivalent forms:
///
/// - **Snapshot fast path** (PERF-FINDDUP-0001 write-through read form): read
///   `bl`'s edge vector once from the bank edge shadow (`with_in/out_edges`)
///   and each peer's flags from the (g) guard shadow, then compute the dup
///   list purely. Valid exactly when every edge point arrives mark-clean —
///   then every f_mark/f_mark2 the lock protocol sets is one it later erases
///   (cc:521-522), so the protocol's net flags effect is identity and the
///   duplist is determined by the edge sequence alone (second-occurrence
///   order, cc:514-517). This is the oracle's own cost shape: findDups is a
///   direct-member-read loop over `ref` with no locks, no Arc materialization
///   and no allocation (block.cc:510-520); the shadows serve the same values
///   (12-byte POD mirrors refreshed at every mutation choke).
/// - **Lock protocol fallback**: any pre-set MARK/MARK2 on an edge point (a
///   foreign mark protocol mid-flight, or an unresolvable slot) voids the
///   no-op argument, so the exact historical lock protocol runs — peers take
///   transient write guards for the marks (no nesting: `bl` holds only read
///   guards), then erase them, cc:507-523 verbatim.
fn find_dup_peers(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    incoming: bool,
) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
    let bank = bl.read().unwrap().bank();
    let bl_id = bank.registered_id_of(bl);
    let view = bank.hold();
    // Fast path: the whole peer set of one edge list, from the write-through
    // shadows — one edge-table lock, plain atomic flag loads, no peer
    // materialization (the duplist is empty for ~97% of calls on the VdbeExec
    // profile, so the expect_arc below runs only for real duplicates).
    let fast = if incoming {
        bank.with_in_edges(bl_id, |edges| {
            dup_peers_from_snapshot(&view, edges)
        })
    } else {
        bank.with_out_edges(bl_id, |edges| {
            dup_peers_from_snapshot(&view, edges)
        })
    };
    if let Some(dups) = fast.flatten() {
        return dups.into_iter().map(|id| view.expect_arc(id)).collect();
    }
    // Slow path: a peer carries a pre-set mark (or the slot did not resolve)
    // — run the oracle's mark protocol under the exact historical locking.
    let edges: Vec<crate::block::BlockEdge> = {
        let g = bl.read().unwrap();
        if incoming {
            (0..g.size_in()).filter_map(|s| g.get_in(s)).collect()
        } else {
            (0..g.size_out()).filter_map(|s| g.get_out(s)).collect()
        }
    };
    // cc:507-523: mark peers on first sight (f_mark); a second sight with
    // f_mark already set is a duplicate (report once, f_mark2).
    let mut duplist: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
    for e in &edges {
        let peer_arc = view.expect_arc(e.point);
        let mut p = match peer_arc.try_write() {
            Ok(g) => g,
            Err(_) => {
                // The only contended peer under the single-guard discipline
                // is `bl` itself (a self loop whose guard we hold as a READ
                // here — try_write fails). Ghidra's findDups sees it like any
                // other peer; treat the address-equal peer through the same
                // mark protocol by skipping the lock (marks live on `bl`'s
                // state which we can re-take after the read guard drops —
                // simplified below by re-scanning self edges separately).
                continue;
            }
        };
        if p.get_flags() & crate::block::block_flags::MARK2 != 0 {
            continue;
        }
        if p.get_flags() & crate::block::block_flags::MARK != 0 {
            if !duplist.iter().any(|a| Arc::ptr_eq(a, &peer_arc)) {
                duplist.push(peer_arc.clone());
            }
            p.set_flags(crate::block::block_flags::MARK2);
        } else {
            p.set_flags(crate::block::block_flags::MARK);
        }
    }
    // Erase marks (cc:520-522) — same lock discipline.
    for e in &edges {
        if let Ok(mut p) = view.expect_arc(e.point).try_write() {
            p.clear_flags(
                crate::block::block_flags::MARK | crate::block::block_flags::MARK2,
            );
        }
    }
    // Self loops could not be marked through the lock; a parallel self-edge
    // pair (2+ edges pointing at `bl` itself) is reported directly
    // (optimistically — the eliminate scan below is a safe no-op when false).
    let self_count = edges.iter().filter(|e| e.point == bl_id).count();
    if self_count > 1 && !duplist.iter().any(|a| Arc::ptr_eq(a, bl)) {
        duplist.push(bl.clone());
    }
    duplist
}

// Ghidra: block.cc:507 FlowBlock::findDups
/// Pure duplicate computation over an edge-shadow snapshot — the fast-path
/// form of `find_dup_peers`'s mark protocol, valid iff every edge point
/// arrives free of f_mark/f_mark2 (see `find_dup_peers` for the no-op
/// argument). Returns `None` when the snapshot form cannot prove equivalence
/// (a pre-set mark, or an unresolvable slot): the caller falls back to the
/// exact lock protocol.
///
/// Push order is the oracle's second-occurrence order (cc:514-517: the push
/// happens at a point's SECOND sight — `count_before == 1` — and the
/// f_mark2 guard suppresses third and later sights). The inner count loop is
/// allocation-free on purpose: edge lists are a few slots long, and Ghidra's
/// own loop body is a direct member read with no allocation (block.cc:510).
fn dup_peers_from_snapshot(
    view: &crate::block::BlockBankView,
    edges: &[crate::block::BlockEdge],
) -> Option<Vec<crate::arena::BlockId>> {
    let marks = crate::block::block_flags::MARK | crate::block::block_flags::MARK2;
    // Guard: any pre-set mark voids the snapshot argument -> lock protocol.
    for e in edges {
        match view.flags(e.point) {
            Some(f) if f & marks == 0 => {}
            _ => return None,
        }
    }
    // Pure second-sight scan (no writes: the lock protocol's set-then-erase
    // pass cancels on mark-clean peers, cc:512-522).
    let mut dups: Vec<crate::arena::BlockId> = Vec::new();
    for (i, e) in edges.iter().enumerate() {
        let mut count_before = 0usize;
        for j in 0..i {
            if edges[j].point == e.point {
                count_before += 1;
            }
        }
        if count_before == 1 {
            dups.push(e.point);
        }
    }
    Some(dups)
}

// Ghidra: block.cc:446 FlowBlock::eliminateInDups / block.cc:475 FlowBlock::eliminateOutDups
/// Eliminate duplicate edges between `bl` and `peer` (`incoming` selects
/// duplicates in `bl`'s in-list — eliminateInDups — vs its out-list —
/// eliminateOutDups), keeping the first instance and OR-merging labels, with
/// the oracle's PAIRED half-deletes (cc:461-462 / cc:490-491). One guard at a
/// time: `bl`'s guard covers the label merge + this-side slide (the slide's
/// reciprocal repairs hit only free peers or `bl` itself — the self-loop arm);
/// the guard drops before the peer-side half-delete, so its repairs back onto
/// `bl` also run synchronously.
fn eliminate_dup_pairs(
    bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    peer: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    incoming: bool,
) {
    let self_loop = Arc::ptr_eq(bl, peer);
    let bank = bl.read().unwrap().bank();
    let peer_id = bank.registered_id_of(peer);
    loop {
        // Find the next (keep, dup) pair under bl's guard; perform bl-side
        // mutations; return the peer-side reciprocal slot for phase 2.
        let peer_phase: Option<i32> = {
            let mut g = bl.write().unwrap();
            let list: &mut Vec<crate::block::BlockEdge> = if incoming {
                g.in_edges_mut()
            } else {
                g.out_edges_mut()
            };
            let mut keep: Option<usize> = None;
            let mut dup: Option<(usize, u32, i32)> = None;
            for (i, e) in list.iter().enumerate() {
                if e.point == peer_id {
                    match keep {
                        None => keep = Some(i),
                        Some(_) => {
                            dup = Some((i, e.flags, e.reverse_index));
                            break;
                        }
                    }
                }
            }
            let Some((dup_slot, label, rev)) = dup else {
                return; // No more duplicates of this peer.
            };
            let keep_slot = keep.expect("duplicate without a kept instance");
            list[keep_slot].flags |= label;
            if incoming {
                g.half_delete_in_edge(dup_slot);
            } else {
                g.half_delete_out_edge(dup_slot);
            }
            if self_loop {
                // The peer is this block; the paired half-delete is also
                // this-side — done under the same guard (block.cc:461-462's
                // bl->halfDeleteOutEdge(rev) with bl == this).
                if incoming {
                    g.half_delete_out_edge(rev.max(0) as usize);
                } else {
                    g.half_delete_in_edge(rev.max(0) as usize);
                }
                None
            } else {
                Some(rev)
            }
        }; // bl's guard dropped here.
        match peer_phase {
            None => continue, // self-loop pair fully handled; scan for more.
            Some(rev) => {
                // Peer-side paired half-delete (block.cc:461-462 / 490-491)
                // with `bl` unlocked: repairs targeting `bl` are synchronous.
                let mut p = peer.write().unwrap();
                if incoming {
                    p.half_delete_out_edge(rev.max(0) as usize);
                } else {
                    p.half_delete_in_edge(rev.max(0) as usize);
                }
            }
        }
    }
}

// RUDRA-GLUE: 不变量修复 helper（Ghidra 无此独立函数——selfIdentify 经
// replaceOutEdge/replaceInEdge（block.cc:160-191, 910-924）在重定向时同步
// 两侧 reverse_index；Rudra 的 rewrite_out/in_edges_to_idx 只翻 e.point，
// 故按指针重结对复合块边界边以恢复 checkEdges() 不变量 block.cc:545-570，
// 一致状态下为 no-op，不引入与 oracle 可观测行为的分歧）。
pub(crate) fn resync_boundary_reverse_indices(bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
    // The pairing must be a BIJECTION: parallel edges between bl and one peer
    // (legitimate per selfIdentify's per-slot replace protocol, block.cc:910-
    // 924) each consume a distinct peer slot, in order. A first-match-only
    // pairing would point every parallel edge at the same peer slot and make
    // the subsequent paired dedup (block.cc:440-501) delete by stale slots.
    // In-edges: for slot i with source S, pair with S's occ-th out-slot that
    // points back at bl, where occ = number of S-sourced in-edges before i.
    let bank = bl.read().unwrap().bank();
    let bl_id = bank.registered_id_of(bl);
    let n_in = bl.read().unwrap().size_in();
    for i in 0..n_in {
        let (peer, occ) = {
            let r = bl.read().unwrap();
            let peer = match r.get_in(i) {
                Some(e) => bank.expect_arc(e.point),
                None => continue,
            };
            let peer_id = bank.registered_id_of(&peer);
            let mut occ = 0usize;
            for q in 0..i {
                if let Some(e) = r.get_in(q) {
                    if e.point == peer_id {
                        occ += 1;
                    }
                }
            }
            (peer, occ)
        };
        let j = if Arc::ptr_eq(&peer, bl) {
            let r = bl.read().unwrap();
            (0..r.size_out())
                .filter(|&k| {
                    r.get_out(k)
                        .map(|e| e.point == bl_id)
                        .unwrap_or(false)
                })
                .nth(occ)
        } else {
            let r = peer.read().unwrap();
            (0..r.size_out())
                .filter(|&k| {
                    r.get_out(k)
                        .map(|e| e.point == bl_id)
                        .unwrap_or(false)
                })
                .nth(occ)
        };
        let Some(j) = j else { continue };
        if !Arc::ptr_eq(&peer, bl) {
            let mut p = peer.write().unwrap();
            p.out_edges_mut()[j].reverse_index = i as i32;
            // (wave 3) reciprocal re-pairing — refresh the peer's out mirror.
            p.sync_out_edge_shadow();
        } else {
            let mut s = bl.write().unwrap();
            s.out_edges_mut()[j].reverse_index = i as i32;
            s.sync_out_edge_shadow();
        }
        {
            let mut s = bl.write().unwrap();
            s.in_edges_mut()[i].reverse_index = j as i32;
            s.sync_in_edge_shadow();
        }
    }
    // Out-edges: for slot k with target T, pair with T's occ-th in-slot that
    // points back at bl, where occ = number of T-targeted out-edges before k.
    let n_out = bl.read().unwrap().size_out();
    for k in 0..n_out {
        let (peer, occ) = {
            let r = bl.read().unwrap();
            let peer = match r.get_out(k) {
                Some(e) => bank.expect_arc(e.point),
                None => continue,
            };
            let peer_id = bank.registered_id_of(&peer);
            let mut occ = 0usize;
            for q in 0..k {
                if let Some(e) = r.get_out(q) {
                    if e.point == peer_id {
                        occ += 1;
                    }
                }
            }
            (peer, occ)
        };
        let m = if Arc::ptr_eq(&peer, bl) {
            let r = bl.read().unwrap();
            (0..r.size_in())
                .filter(|&q| {
                    r.get_in(q)
                        .map(|e| e.point == bl_id)
                        .unwrap_or(false)
                })
                .nth(occ)
        } else {
            let r = peer.read().unwrap();
            (0..r.size_in())
                .filter(|&q| {
                    r.get_in(q)
                        .map(|e| e.point == bl_id)
                        .unwrap_or(false)
                })
                .nth(occ)
        };
        let Some(m) = m else { continue };
        if !Arc::ptr_eq(&peer, bl) {
            let mut p = peer.write().unwrap();
            p.in_edges_mut()[m].reverse_index = k as i32;
            // (wave 3) reciprocal re-pairing — refresh the peer's in mirror.
            p.sync_in_edge_shadow();
        } else {
            let mut s = bl.write().unwrap();
            s.in_edges_mut()[m].reverse_index = k as i32;
            s.sync_in_edge_shadow();
        }
        {
            let mut s = bl.write().unwrap();
            s.out_edges_mut()[k].reverse_index = m as i32;
            s.sync_out_edge_shadow();
        }
    }
}

/// An edge considered for unstructuring (goto) by the loop-ordering pass.
/// Faithful to Ghidra's `FloatingEdge` (blockaction.hh). Records a (from, to)
/// block pair; the structurer may later mark the `from` out-edge as a goto.
#[derive(Clone, Debug)]
pub struct FloatingEdge {
    pub from_idx: i32,
    pub to_idx: i32,
}

impl FloatingEdge {
    // Ghidra: blockaction.cc:27 FloatingEdge::getCurrentEdge
    /// Re-resolve the edge against the current graph:
    ///   - cc:28-33: walk both endpoints up the collapse hierarchy
    ///     (`while(top->getParent() != graph) top = top->getParent();`) so an
    ///     endpoint absorbed by a composite resolves to that composite, whose
    ///     inherited boundary edges (selfIdentify) represent the same flow.
    ///   - cc:34-35: find the out-slot of the resolved top that targets the
    ///     resolved bottom; failure means the edge no longer exists.
    /// The previous port returned None whenever the source block carried the
    /// DEAD flag, dropping edges whose source was absorbed — diverging from
    /// the oracle exactly where selectGoto re-resolves leftover likelygoto
    /// entries after a collapse round.
    pub fn get_current_edge(&self, graph: &BlockGraph) -> Option<(i32, usize)> {
        let top = graph.resolve_to_graph_level(self.from_idx);
        let bottom = graph.resolve_to_graph_level(self.to_idx);
        let top_i = top as usize;
        if top_i >= graph.get_size() {
            return None;
        }
        let top_blk = graph.get_block(top_i)?;
        let top_r = top_blk.read().unwrap();
        for slot in 0..top_r.size_out() {
            if let Some(e) = top_r.get_out(slot) {
                let dst = graph.bank.expect_index(e.point);
                if dst == bottom {
                    return Some((top, slot));
                }
            }
        }
        None
    }
}

/// A natural loop detected during orderLoopBodies.
///
/// Faithful to Ghidra's `LoopBody` class (blockaction.cc:46-490). Holds the
/// loop head, tails (back-edge sources), exit block, exit edges, nesting
/// depth, and immediate container. The methods collect the loop body, pick a
/// single exit block, extend the body to dominated blocks, and label exit
/// edges for the TraceDAG pass.
pub struct LoopBody {
    /// Loop head (the back-edge target / loop entry).
    pub head: i32,
    /// Back-edge sources (tails). Multiple if the loop has several back-edges.
    pub tails: Vec<i32>,
    /// The chosen single exit block (may be -1 if none).
    pub exit_block: i32,
    /// Edges leaving the loop body (from, to) block indices.
    pub exit_edges: Vec<FloatingEdge>,
    /// Nesting depth (incremented by each containing loop).
    pub depth: i32,
    /// Immediately containing loop's HEAD block index (-1 = top-level). The
    /// oracle's `immed_container` is a LoopBody pointer (blockaction.hh:64);
    /// heads are unique after merge_identical_heads, so the head block index
    /// is the pointer's identity key and survives the depth sort.
    pub immed_container: i32,
    /// Number of head/tail nodes in the body (set by find_base).
    pub unique_count: usize,
}

impl LoopBody {
    // Ghidra: blockaction.hh:46 LoopBody::new
    pub fn new(head: i32, tail: i32) -> Self {
        Self {
            head,
            tails: vec![tail],
            exit_block: -1,
            exit_edges: Vec::new(),
            depth: 0,
            immed_container: -1,
            unique_count: 0,
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::addTail
    pub fn add_tail(&mut self, tail: i32) {
        self.tails.push(tail);
    }

    // Ghidra: blockaction.cc:119 LoopBody::findBase
    /// Collect all blocks reaching a tail without going through head.
    /// Faithful to `LoopBody::findBase` (blockaction.cc:119-144). Marks each
    /// collected block via set_mark. Returns the body block indices.
    pub fn find_base(&mut self, graph: &BlockGraph) -> Vec<i32> {
        let mut body: Vec<i32> = Vec::new();
        // Mark head.
        if let Some(h) = graph.get_block(self.head as usize) {
            h.write().unwrap().set_mark();
        }
        body.push(self.head);
        for &tail in &self.tails {
            if let Some(t) = graph.get_block(tail as usize) {
                if !t.read().unwrap().is_mark() {
                    t.write().unwrap().set_mark();
                    body.push(tail);
                }
            }
        }
        self.unique_count = body.len();
        // Walk backwards from each body node, marking reachable predecessors
        // (skipping goto/irreducible in-edges), until no new nodes.
        let mut i = 1;
        while i < body.len() {
            let cur = body[i];
            i += 1;
            if let Some(blk) = graph.get_block(cur as usize) {
                let preds: Vec<(usize, i32)> = {
                    let b = blk.read().unwrap();
                    let n = b.size_in();
                    (0..n)
                        .filter(|&k| !b.is_goto_in(k))
                        .filter_map(|k| {
                            b.get_in(k)
                                .map(|e| (k, graph.bank.expect_index(e.point)))
                        })
                        .collect()
                };
                for (_, pred_idx) in preds {
                    if let Some(pblk) = graph.get_block(pred_idx as usize) {
                        if !pblk.read().unwrap().is_mark() {
                            pblk.write().unwrap().set_mark();
                            body.push(pred_idx);
                        }
                    }
                }
            }
        }
        body
    }

    // Ghidra: blockaction.cc:150 LoopBody::extend
    /// Extend the body to blocks reachable ONLY from head (dominated by the
    /// loop entry), excluding the exit block. Faithful to `LoopBody::extend`
    /// (blockaction.cc:150-176). Uses visit_count to count in-edges.
    pub fn extend(&self, body: &mut Vec<i32>, graph: &BlockGraph) {
        let mut trial: Vec<i32> = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let bl = body[i];
            i += 1;
            let succs: Vec<(usize, i32)> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&j| !b.is_goto_out(j))
                        .filter_map(|j| {
                            b.get_out(j)
                                .map(|e| (j, graph.bank.expect_index(e.point)))
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (_, succ_idx) in succs {
                if succ_idx == self.exit_block {
                    continue;
                }
                let marked = graph
                    .get_block(succ_idx as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if marked {
                    continue;
                }
                let count = graph
                    .get_block(succ_idx as usize)
                    .map(|b| b.read().unwrap().get_visit_count())
                    .unwrap_or(0);
                if count == 0 {
                    trial.push(succ_idx);
                }
                if let Some(sblk) = graph.get_block(succ_idx as usize) {
                    sblk.write().unwrap().set_visit_count(count + 1);
                    // If all in-edges now accounted for, absorb into body.
                    let total_in = sblk.read().unwrap().size_in() as i32;
                    if count + 1 == total_in {
                        sblk.write().unwrap().set_mark();
                        body.push(succ_idx);
                    }
                }
            }
        }
        // Clear visit counts.
        for &t in &trial {
            if let Some(tblk) = graph.get_block(t as usize) {
                tblk.write().unwrap().set_visit_count(0);
            }
        }
    }

    // Ghidra: blockaction.cc:46 LoopBody::extendToContainer
    /// Backward-walk from this loop's head through the container's body,
    /// marking every block reachable via non-goto in-edges. Faithful to
    /// `LoopBody::extendToContainer` (blockaction.cc:46-74):
    ///   - cc:49-53: the container head, if unmarked, is marked, pushed,
    ///     and skipped as a backward-walk start (`i = 1`).
    ///   - cc:54-60: each unmarked container tail is marked and pushed
    ///     (backward walk DOES traverse from them).
    ///   - cc:61-71: if this loop's head differs from the container head,
    ///     its unmarked non-goto predecessors are marked and pushed.
    ///   - cc:73-83: BFS over the pushed body's non-goto in-edges, marking
    ///     every unmarked predecessor.
    /// Used by `find_exit`'s container arm (findExit cc:227-237) to force
    /// a subloop's exit block to lie inside its immediately containing loop.
    pub fn extend_to_container(
        &self,
        container_head: i32,
        container_tails: &[i32],
        body: &mut Vec<i32>,
        graph: &BlockGraph,
    ) {
        let mut i: usize = 0;
        // PERF-ARENA-FLIP-0001 (f) step 2: one snapshot view spans the walk
        // (only block marks are written below — no bank publish can happen),
        // so the per-in-edge peer index reads in the BFS are zero-lock.
        let bank = graph.bank.hold();
        // cc:49-53: container head — add if unmarked; never walk back from it.
        let head_marked = graph
            .get_block(container_head as usize)
            .map(|b| b.read().unwrap().is_mark())
            .unwrap_or(false);
        if !head_marked {
            if let Some(hblk) = graph.get_block(container_head as usize) {
                hblk.write().unwrap().set_mark();
            }
            body.push(container_head);
            i = 1;
        }
        // cc:54-60: container tails — add if unmarked; walk back from them.
        for &tail in container_tails {
            let marked = graph
                .get_block(tail as usize)
                .map(|b| b.read().unwrap().is_mark())
                .unwrap_or(false);
            if !marked {
                if let Some(tblk) = graph.get_block(tail as usize) {
                    tblk.write().unwrap().set_mark();
                }
                body.push(tail);
            }
        }
        // cc:61-71: this loop's head (already marked by find_base) — walk
        // back from it unless it IS the container head.
        if self.head != container_head {
            let ins: Vec<i32> = match graph.get_block(self.head as usize) {
                Some(hblk) => {
                    let b = hblk.read().unwrap();
                    let n = b.size_in();
                    (0..n)
                        .filter(|&k| !b.is_goto_in(k))
                        .filter_map(|k| b.get_in(k).map(|e| bank.expect_index(e.point)))
                        .collect()
                }
                None => Vec::new(),
            };
            for bl in ins {
                let marked = graph
                    .get_block(bl as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if marked {
                    continue;
                }
                if let Some(blk) = graph.get_block(bl as usize) {
                    blk.write().unwrap().set_mark();
                }
                body.push(bl);
            }
        }
        // cc:73-83: BFS — walk non-goto in-edges of every queued block.
        while i < body.len() {
            let curblock = body[i];
            i += 1;
            let ins: Vec<i32> = match graph.get_block(curblock as usize) {
                Some(blk) => {
                    let b = blk.read().unwrap();
                    let n = b.size_in();
                    (0..n)
                        .filter(|&k| !b.is_goto_in(k))
                        .filter_map(|k| b.get_in(k).map(|e| bank.expect_index(e.point)))
                        .collect()
                }
                None => Vec::new(),
            };
            for bl in ins {
                let marked = graph
                    .get_block(bl as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if marked {
                    continue;
                }
                if let Some(blk) = graph.get_block(bl as usize) {
                    blk.write().unwrap().set_mark();
                }
                body.push(bl);
            }
        }
    }

    // Ghidra: blockaction.cc:182 LoopBody::findExit
    /// Pick a single exit block. Faithful to `LoopBody::findExit`
    /// (blockaction.cc:182-239). Scans tail exits (cc:185-197), then body
    /// nodes' exits (cc:199-221). With no containing loop the first
    /// unmarked exit wins immediately (cc:191-195/208-212); with a
    /// container, candidates accumulate into trialexit and the winner is
    /// the first candidate inside the container's re-marked body
    /// (cc:227-237 via extendToContainer + clearMarks). `container` is the
    /// immediately containing loop's (head, tails) — the oracle's
    /// `immed_container` pointer resolved through the depth sort (heads are
    /// unique after mergeIdenticalHeads, so the head is the pointer's
    /// identity key).
    pub fn find_exit(&mut self, body: &[i32], graph: &BlockGraph, container: Option<(i32, Vec<i32>)>) {
        let mut trial_exit: Vec<i32> = Vec::new();
        // Exits from tails.
        for &tail in &self.tails {
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&i| !b.is_goto_out(i))
                        .filter_map(|i| b.get_out(i).map(|e| graph.bank.expect_index(e.point)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for cur in outs {
                let marked = graph
                    .get_block(cur as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if !marked {
                    if container.is_none() {
                        self.exit_block = cur;
                        return;
                    }
                    trial_exit.push(cur);
                }
            }
        }
        // Exits from middle body nodes (skip head/tail indices).
        for (i, &bl) in body.iter().enumerate() {
            if i > 0 && i < self.unique_count {
                continue;
            }
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&j| !b.is_goto_out(j))
                        .filter_map(|j| b.get_out(j).map(|e| graph.bank.expect_index(e.point)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for cur in outs {
                let marked = graph
                    .get_block(cur as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if !marked {
                    if container.is_none() {
                        self.exit_block = cur;
                        return;
                    }
                    trial_exit.push(cur);
                }
            }
        }
        self.exit_block = -1;
        if trial_exit.is_empty() {
            return;
        }
        // cc:227-237: if there is a containing loop, force exitblock to be
        // inside the containing loop. The container's body is re-marked via
        // extendToContainer (a backward walk from this loop's head through
        // the container's head/tails), and the first trial exit that falls
        // inside those marks wins; only the extension marks are cleared.
        // (The previous port approximated this with `trial_exit[0]`, which
        // could pick an exit OUTSIDE the container and desynchronized the
        // likely-goto ordering — BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001.)
        if let Some((chead, ctails)) = container {
            let mut extension: Vec<i32> = Vec::new();
            self.extend_to_container(chead, &ctails, &mut extension, graph);
            for &te in &trial_exit {
                let marked = graph
                    .get_block(te as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if marked {
                    self.exit_block = te;
                    break;
                }
            }
            clear_marks(&extension, graph);
        }
    }

    // Ghidra: blockaction.cc:245 LoopBody::orderTails
    /// Reorder tails so a tail with an edge to exit_block is first.
    /// Faithful to `LoopBody::orderTails` (blockaction.cc:245-264).
    pub fn order_tails(&mut self, graph: &BlockGraph) {
        if self.tails.len() <= 1 || self.exit_block == -1 {
            return;
        }
        let mut pref = None;
        for (idx, &tail) in self.tails.iter().enumerate() {
            let outs: Vec<i32> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter_map(|j| b.get_out(j).map(|e| graph.bank.expect_index(e.point)))
                        .collect()
                } else {
                    Vec::new()
                }
            };
            if outs.iter().any(|&o| o == self.exit_block) {
                pref = Some(idx);
                break;
            }
        }
        if let Some(prefidx) = pref {
            if prefidx != 0 {
                self.tails.swap(0, prefidx);
            }
        }
    }

    // Ghidra: blockaction.cc:270 LoopBody::labelExitEdges
    /// Label edges leaving the body. Faithful to `LoopBody::labelExitEdges`
    /// (blockaction.cc:270-320). Priority: middle-exit edges first, then head,
    /// then tails (reverse), then edges-to-exitblock last.
    pub fn label_exit_edges(&mut self, body: &[i32], graph: &BlockGraph) {
        let mut to_exit_block: Vec<i32> = Vec::new();
        // Middle nodes (non-head/tail).
        for &bl in body.iter().skip(self.unique_count) {
            let outs: Vec<(i32, i32)> = {
                if let Some(blk) = graph.get_block(bl as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&k| !b.is_goto_out(k))
                        .filter_map(|k| {
                            b.get_out(k)
                                .map(|e| (graph.bank.expect_index(e.point), k as i32))
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (tgt, _slot) in outs {
                if tgt == self.exit_block {
                    to_exit_block.push(bl);
                } else {
                    let marked = graph
                        .get_block(tgt as usize)
                        .map(|b| b.read().unwrap().is_mark())
                        .unwrap_or(false);
                    if !marked {
                        self.exit_edges.push(FloatingEdge {
                            from_idx: bl,
                            to_idx: tgt,
                        });
                    }
                }
            }
        }
        // Head exits.
        let head_outs: Vec<(i32, i32)> = {
            if let Some(blk) = graph.get_block(self.head as usize) {
                let b = blk.read().unwrap();
                let n = b.size_out();
                (0..n)
                    .filter(|&k| !b.is_goto_out(k))
                    .filter_map(|k| {
                        b.get_out(k)
                            .map(|e| (graph.bank.expect_index(e.point), k as i32))
                    })
                    .collect()
            } else {
                Vec::new()
            }
        };
        for (tgt, _slot) in head_outs {
            if tgt == self.exit_block {
                to_exit_block.push(self.head);
            } else {
                let marked = graph
                    .get_block(tgt as usize)
                    .map(|b| b.read().unwrap().is_mark())
                    .unwrap_or(false);
                if !marked {
                    self.exit_edges.push(FloatingEdge {
                        from_idx: self.head,
                        to_idx: tgt,
                    });
                }
            }
        }
        // Tail exits (reverse order).
        for &tail in self.tails.iter().rev() {
            if tail == self.head {
                continue;
            }
            let outs: Vec<(i32, i32)> = {
                if let Some(blk) = graph.get_block(tail as usize) {
                    let b = blk.read().unwrap();
                    let n = b.size_out();
                    (0..n)
                        .filter(|&k| !b.is_goto_out(k))
                        .filter_map(|k| {
                            b.get_out(k)
                                .map(|e| (graph.bank.expect_index(e.point), k as i32))
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            };
            for (tgt, _slot) in outs {
                if tgt == self.exit_block {
                    to_exit_block.push(tail);
                } else {
                    let marked = graph
                        .get_block(tgt as usize)
                        .map(|b| b.read().unwrap().is_mark())
                        .unwrap_or(false);
                    if !marked {
                        self.exit_edges.push(FloatingEdge {
                            from_idx: tail,
                            to_idx: tgt,
                        });
                    }
                }
            }
        }
        // Edges to exit block go last.
        for bl in to_exit_block {
            self.exit_edges.push(FloatingEdge {
                from_idx: bl,
                to_idx: self.exit_block,
            });
        }
    }

    // Ghidra: blockaction.cc:327 LoopBody::labelContainments
    /// Record contained subloops and set depth/immed_container.
    /// Faithful to `LoopBody::labelContainments` (blockaction.cc:327-358).
    pub fn label_containments(&mut self, body: &[i32], loop_order: &[LoopBody], self_idx: usize) {
        let mut contain: Vec<usize> = Vec::new();
        for &curblock in body {
            if curblock == self.head {
                continue;
            }
            // Find a subloop whose head == curblock.
            if let Some(sub_idx) = loop_order
                .iter()
                .position(|lb| lb.head == curblock && lb.head != self.head)
            {
                // Avoid matching self.
                if sub_idx != self_idx {
                    contain.push(sub_idx);
                }
            }
        }
        // We can't mutate other LoopBodies here (borrow); the caller updates
        // depth/immed_container based on containment. This method records which
        // subloops are contained; the depth bookkeeping is done in order_loop_bodies.
        let _ = contain;
    }

    // Ghidra: blockaction.cc:364 LoopBody::emitLikelyEdges
    /// Emit edges that exit this loop body to a likely-goto list, with proper
    /// priority: exit edges first (official exit edge held last among them),
    /// then back-edges (tails→head) in reverse tail order. Faithful to
    /// `LoopBody::emitLikelyEdges` (blockaction.cc:364-412):
    ///   - cc:367-371: resolve head and exitblock up the collapse hierarchy.
    ///   - cc:372-379: resolve each tail; if the exitblock was collapsed into
    ///     a tail, the loop no longer really has an exit (exitblock = null).
    ///   - cc:381-397: walk exit_edges in order, re-resolving each against the
    ///     live graph via getCurrentEdge (vanished edges are skipped); the
    ///     official exit edge (resolved target == exitblock) at the LAST
    ///     entry is held back.
    ///   - cc:398-409: emit the held exit edge right before the final
    ///     back-edge, then back-edges (tail→head) in reverse tail order.
    /// The resulting list orders candidate goto edges so the structurer
    /// prefers keeping the official loop exit structured and marks the others
    /// as goto.
    pub fn emit_likely_edges(&mut self, likely: &mut Vec<FloatingEdge>, graph: &BlockGraph) {
        // cc:367-371: resolve head and exitblock up the hierarchy.
        self.head = graph.resolve_to_graph_level(self.head);
        if self.exit_block >= 0 {
            self.exit_block = graph.resolve_to_graph_level(self.exit_block);
        }
        // cc:372-379: resolve tails; absorbed exitblock nulls the exit.
        for ti in 0..self.tails.len() {
            let tail = graph.resolve_to_graph_level(self.tails[ti]);
            self.tails[ti] = tail;
            if tail == self.exit_block {
                // If the exitblock was collapsed into the tail, we no longer
                // really have an exit.
                self.exit_block = -1;
            }
        }
        // cc:381-397: exit edges, holding off the official exit edge.
        let mut hold: Option<FloatingEdge> = None;
        let n = self.exit_edges.len();
        for (i, fe) in self.exit_edges.iter().enumerate() {
            // cc:388-390: re-resolve against the live graph; skip vanished.
            let Some((top_idx, slot)) = fe.get_current_edge(graph) else {
                continue;
            };
            let Some(top_blk) = graph.get_block(top_idx as usize) else {
                continue;
            };
            let out_idx = {
                let r = top_blk.read().unwrap();
                r.get_out(slot).map(|e| graph.bank.expect_index(e.point))
            };
            let Some(out_idx) = out_idx else { continue };
            // cc:391-397: last entry targeting the exitblock is held.
            if i == n.saturating_sub(1) && out_idx == self.exit_block {
                hold = Some(FloatingEdge {
                    from_idx: top_idx,
                    to_idx: out_idx,
                });
                break;
            }
            likely.push(FloatingEdge {
                from_idx: top_idx,
                to_idx: out_idx,
            });
        }
        // cc:398-409: back-edges in reverse tail order; the held exit edge
        // goes right before the final (first-tail) back-edge.
        let tails_len = self.tails.len();
        for (rev_i, &tail) in self.tails.clone().iter().rev().enumerate() {
            if rev_i == tails_len - 1 {
                if let Some(h) = hold.take() {
                    likely.push(h);
                }
            }
            // Any out-edge from this tail back to head is a back-edge.
            if let Some(blk) = graph.get_block(tail as usize) {
                let outs: Vec<i32> = {
                    let b = blk.read().unwrap();
                    let nn = b.size_out();
                    (0..nn)
                        .filter_map(|j| b.get_out(j).map(|e| graph.bank.expect_index(e.point)))
                        .collect()
                };
                for tgt in outs {
                    if tgt == self.head {
                        likely.push(FloatingEdge {
                            from_idx: tail,
                            to_idx: self.head,
                        });
                    }
                }
            }
        }
    }

    // Ghidra: blockaction.cc:94 LoopBody::update
    /// Update head/tails to the current graph view and return the loop's
    /// bottom (first tail not collapsed into head). Returns None if the loop
    /// has been fully collapsed (or head self-loops, returning Some(head)).
    /// Faithful to `LoopBody::update` (blockaction.cc:94-114):
    ///   - cc:95-96: `while(head->getParent() != graph) head = head->getParent();`
    ///     — resolve the head through the collapse hierarchy to a top-level
    ///     block. A head absorbed by a composite resolves to the composite.
    ///   - cc:97-103: same parent-chain walk per tail; the first tail that
    ///     does NOT resolve to (the resolved) head is the loop bottom — the
    ///     loop still exists even if its tail was absorbed by a composite,
    ///     because the composite holds the tail and is itself live.
    ///   - cc:104-112: all tails resolved into the head block — the loop is
    ///     fully collapsed; only a head self-loop edge keeps it alive.
    ///   - cc:113: return null otherwise.
    /// The previous port returned None as soon as a tail carried the DEAD
    /// flag, treating absorption as loop death. In the oracle an absorbed
    /// tail resolves to its live containing composite, so `updateLoopBody`
    /// (cc:1214-1216) sees the loop alive and selectGoto keeps consuming the
    /// remaining likelygoto entries. That divergence is what stranded the
    /// irreducible jumptable-neighborhood loops (TRI2-STRUCT-IRREDUCIBLE-
    /// TRACE-0001): the leftover candidate goto edges were dropped before
    /// being marked, the final TraceDAG found nothing, and selectGoto hit
    /// the cc:1275 LowlevelError site.
    pub fn update(&mut self, graph: &BlockGraph) -> Option<i32> {
        // cc:95-96: resolve head up the hierarchy.
        self.head = graph.resolve_to_graph_level(self.head);
        // cc:97-103: resolve each tail; first one that is not the head is
        // the bottom.
        for ti in 0..self.tails.len() {
            let bottom = graph.resolve_to_graph_level(self.tails[ti]);
            self.tails[ti] = bottom;
            if bottom != self.head {
                return Some(bottom); // Loop hasn't been fully collapsed yet
            }
        }
        // cc:104-109: check for head looping with itself.
        let head_i = self.head as usize;
        if head_i < graph.get_size() {
            if let Some(head_blk) = graph.get_block(head_i) {
                let head_r = head_blk.read().unwrap();
                for slot in 0..head_r.size_out() {
                    if let Some(e) = head_r.get_out(slot) {
                        if graph.bank.expect_index(e.point) == self.head {
                            return Some(self.head);
                        }
                    }
                }
            }
        }
        None
    }

    // Ghidra: blockaction.cc:416 LoopBody::setExitMarks
    /// Mark exit edges' source out-edges with f_loop_exit_edge. Faithful to
    /// `LoopBody::setExitMarks` (blockaction.cc:416-426). Re-resolves each
    /// exit edge against the live graph before marking.
    pub fn set_exit_marks(&self, graph: &mut BlockGraph) {
        for fe in &self.exit_edges {
            if let Some((top_idx, slot)) = fe.get_current_edge(graph) {
                if let Some(blk) = graph.get_block(top_idx as usize) {
                    // cc:424: setLoopExit(outedge) → setOutEdgeFlag — and
                    // Ghidra's FlowBlock::setOutEdgeFlag (block.cc:240-247)
                    // ALWAYS mirrors the label onto the target's in-edge
                    // half (`bbout->intothis[reverse_index].label |= lab`).
                    // The in-edge half is what isLoopDAGIn reads
                    // (block.hh:345, TraceDAG::checkOpen cc:828), so a
                    // non-mirroring set lets TraceDAG count loop-exit edges
                    // as openable DAG edges (BLOCKACT-CONDNEGATE-PARITY-0001:
                    // the 0x2df4b->0x2df8e loop-exit edge stayed "DAG",
                    // checkOpen(open) became miss, the bad-edge pick order
                    // diverged, and the LIT guard block 0x2df67 lost its
                    // oracle negate parity).
                    crate::block::set_out_edge_flag_mirrored(
                        &blk,
                        slot,
                        crate::block::edge_flags::F_LOOP_EXIT_EDGE,
                    );
                }
            }
        }
    }

    // Ghidra: blockaction.cc:430 LoopBody::clearExitMarks
    /// Clear f_loop_exit_edge on this loop's exit edges.
    pub fn clear_exit_marks(&self, graph: &mut BlockGraph) {
        for fe in &self.exit_edges {
            if let Some((top_idx, slot)) = fe.get_current_edge(graph) {
                if let Some(blk) = graph.get_block(top_idx as usize) {
                    // cc:432: clearLoopExit → clearOutEdgeFlag, which
                    // clears BOTH halves (block.cc:250-256) — mirror here
                    // so the set/clear brackets stay symmetric.
                    crate::block::clear_out_edge_flag_mirrored(
                        &blk,
                        slot,
                        crate::block::edge_flags::F_LOOP_EXIT_EDGE,
                    );
                }
            }
        }
    }
}

// Ghidra: blockaction.cc:446 LoopBody::mergeIdenticalHeads
/// Merge LoopBodies sharing the same head. Faithful to
/// `LoopBody::mergeIdenticalHeads` (blockaction.cc:446-467). Bodies with the
/// same head have their tails merged; subsumed bodies are marked (head=-1).
pub fn merge_identical_heads(loop_order: &mut Vec<LoopBody>) {
    if loop_order.is_empty() {
        return;
    }
    let mut i = 0;
    let mut j = 1;
    while j < loop_order.len() {
        if loop_order[j].head == loop_order[i].head {
            // Merge tail[0] of j into i; mark j subsumed.
            let tail = loop_order[j].tails[0];
            loop_order[i].add_tail(tail);
            loop_order[j].head = -1; // subsumed
        } else {
            i = j;
        }
        j += 1;
    }
    loop_order.retain(|lb| lb.head != -1);
}

// Ghidra: blockaction.cc:1039 LoopBody::clearMarks
/// Clear marks on a set of blocks. Faithful to `LoopBody::clearMarks`
/// (blockaction.cc:1039).
pub fn clear_marks(body: &[i32], graph: &BlockGraph) {
    for &bl in body {
        if let Some(blk) = graph.get_block(bl as usize) {
            blk.write().unwrap().clear_mark();
        }
    }
}

/// Structure for iteratively collapsing control flow patterns
///
/// Corresponds to Ghidra's `CollapseStructure` class.
/// Corresponds to Ghidra's `CollapseStructure` class.
/// Detects if-then, if-then-else, sequence, and while-do patterns
/// from a flat CFG and replaces them with structured `BlockIf`,
/// `BlockWhileDo`, and `BlockList` nodes.
pub struct CollapseStructure<'a> {
    graph: &'a mut BlockGraph,
    /// RUDRA-GLUE: internal fixpoint progress; Ghidra rules return bool instead
    /// of exposing a separate structural-mutation counter.
    structure_change_count: i32,
    /// Ghidra `CollapseStructure::dataflow_changecount`: only real condition
    /// data-flow flips contribute to ActionBlockStructure's inherited count.
    dataflow_change_count: i32,
    name: String,
    /// Immediate dominator map: idom[i] = index of i's immediate dominator.
    idom: std::collections::HashMap<i32, i32>,
    /// Loop bodies identified by orderLoopBodies: (head_idx, body_block_indices).
    /// Sorted by nesting depth (innermost first). Used by interleaved rules
    /// to prioritize structuring within loop bodies.
    loop_bodies: Vec<(i32, Vec<i32>)>,
    /// Block indices that are switch case bodies.
    /// from being pulled out of switch bodies.
    switch_case_indices: std::collections::HashSet<i32>,
    /// Rich loop analysis (Ghidra LoopBody), built by order_loop_bodies.
    /// Holds head/tails/exit_block/exit_edges/depth for each natural loop,
    /// sorted deepest-nesting-first. Used for nested-loop structuring and
    /// exit-edge labeling.
    loop_order: std::collections::VecDeque<LoopBody>,
    // --- B5/B6: Ghidra selectGoto state machine fields (blockaction.hh:89-95) ---
    /// finaltrace: true once a TraceDAG over the whole DAG found no likely
    /// goto edges (blockaction.cc:1196,1248). Prevents repeating the trace.
    finaltrace: bool,
    /// likelygoto: list of (top,bottom) block-index edges selected as goto
    /// candidates by TraceDAG (blockaction.hh:92). Re-resolved against the
    /// live graph each iteration via get_current_edge.
    likelygoto: Vec<FloatingEdge>,
    /// likelyiter: current position in likelygoto (blockaction.hh:93).
    likelyiter: usize,
    /// likelylistfull: true once likelygoto is fully populated for the
    /// current loop/DAG (blockaction.hh:94).
    likelylistfull: bool,
    /// loopbodyiter: current position in loop_order being processed by
    /// update_loop_body (blockaction.hh:89). -1 = not started.
    loopbodyiter: i32,
    /// Ghidra-equivalent graph LIST order over Rudra's flat-Vec slots (see
    /// `virtual_list`). Ghidra's collapse graph physically removes consumed
    /// nodes (identifyInternal, block.cc:953-960) and every newBlock*
    /// factory appends the composite at the END (addBlock, block.cc:862-875
    /// `list.push_back`); every position-order consumer iterates that
    /// mutating list, including its skip side effects: when a rule consumes
    /// the visited block plus its list neighbors, the survivors shift left
    /// under the already-incremented scan index and get skipped until the
    /// next fixpoint pass (collapseInternal cc:1783-1784 `index += 1`
    /// happens BEFORE the rules run). Rudra keeps blocks at fixed slots
    /// (zombies via absorbed_into), so this Vec mirrors the oracle's list
    /// exactly: initialized to the copy graph's order, identify_internal
    /// removes consumed entries and pushes the install slot at the end.
    virtual_list: Vec<i32>,
    /// Jumptables of the function under collapse, for the BlockSwitch ctor
    /// (`jump = ind->getJumptable()`, block.cc:3488 — the oracle resolves
    /// the BRANCHIND last-op through Funcdata::findJumpTable, block.cc:637;
    /// Rudra passes the Arc list in because CollapseStructure has no
    /// Funcdata back-pointer).
    jump_tables: Vec<Arc<RwLock<crate::jumptable::JumpTable>>>,
    /// (BLOCKSTRUCT2) candidate slots for update_switch_case_reference —
    /// every top-level BlockSwitch ever installed (seeded once at
    /// construction, pushed at each ruleBlockSwitch fire). The oracle pays
    /// nothing here (its caseblocks hold stable FlowBlock pointers,
    /// block.cc:3495 `curcase.block = bl`; Rudra re-points case Arcs when a
    /// case body's slot is re-wrapped, and the previous full-graph O(n)
    /// scan per fire — 13.9K fires × ~2.6K blocks on the giant function —
    /// reduced to this O(#switches) superset. Stale slots (later installs
    /// overwrote them) are filtered by the authoritative type check in the
    /// scan, so the registry is only ever a superset of the live switches
    /// the old scan found; first-match-in-slot-order semantics preserved by
    /// taking the minimum holding slot).
    switch_slots: Vec<usize>,
}

impl<'a> CollapseStructure<'a> {
    // RUDRA-GLUE: owning-graph bank handle for edge-endpoint resolution
    // (BlockEdge.point is the bank id form; ARENA_DESIGN §1.5 value flip).
    fn graph_bank(&self) -> &crate::block::BlockBank {
        &self.graph.bank
    }

    // Ghidra: blockaction.cc:1870 CollapseStructure::CollapseStructure
    pub fn new(graph: &'a mut BlockGraph, name: &str) -> Self {
        // The initial Ghidra list order = the copy graph's block order
        // (slots 0..n); identify_internal mutates it thereafter.
        let n = graph.get_size() as i32;
        // (BLOCKSTRUCT2) seed the switch registry with any hand-installed
        // top-level switches (bare fixtures install composites directly;
        // production graphs here are fresh build_copy copies with none).
        let switch_slots: Vec<usize> = graph
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.read().unwrap().get_type() == crate::block::BlockType::Switch)
            .map(|(i, _)| i)
            .collect();
        Self {
            graph,
            structure_change_count: 0,
            dataflow_change_count: 0,
            name: name.to_string(),
            switch_case_indices: std::collections::HashSet::new(),
            idom: std::collections::HashMap::new(),
            loop_bodies: Vec::new(),
            loop_order: std::collections::VecDeque::new(),
            finaltrace: false,
            likelygoto: Vec::new(),
            likelyiter: 0,
            likelylistfull: false,
            loopbodyiter: -1,
            virtual_list: (0..n).collect(),
            jump_tables: Vec::new(),
            switch_slots,
        }
    }

    // RUDRA-GLUE: builder supplying Funcdata::jump_tables for the BlockSwitch
    // ctor lookup (Ghidra reaches them through the FlowBlock Funcdata
    // back-pointer, block.cc:637; Rudra composites carry none).
    /// Attach the function's jumptables so new BlockSwitch components can
    /// hold their table (block.cc:3488 ctor semantics).
    pub fn with_jump_tables(
        mut self, jts: Vec<Arc<RwLock<crate::jumptable::JumpTable>>>,
    ) -> Self {
        self.jump_tables = jts;
        self
    }

    // (The `virtual_list` field IS the Ghidra list-order mirror — see its
    // doc comment. Entries are always LIVE slots: identify_internal removes
    // the consumed entries (plus the install slot's old occupant) and pushes
    // the install slot at the end, so iteration needs no extra consumed
    // filtering — exactly Ghidra's mutating `list` semantics, including the
    // shift-past-the-scan-index skips.)

    // Ghidra: blockaction.cc:1768 CollapseStructure::collapseInternal
    /// Run the 8-rule fixpoint + IfNoExit/CaseFallthru second pass, optionally
    /// targeting a single block (targetbl). Faithful to `collapseInternal`
    /// (blockaction.cc:1768-1851): outer do-while(fullchange), inner fixpoint
    /// do-while(change) running ruleBlockGoto/Cat/ProperIf/IfElse/WhileDo/
    /// DoWhile/InfLoop/Switch per block, then second pass IfNoExit+CaseFallthru.
    ///
    /// When `target_idx` is Some, Ghidra runs the inner loop on just that
    /// block ONCE (cc:1786-1791: `bl = targetbl; change = true; targetbl =
    /// NULL; index = getSize()`), forcing another full-graph pass through
    /// the inner do-while(change). When None, iterates all blocks
    /// (cc:1782-1785). The target is consumed after its single visit — the
    /// previous port kept re-selecting it every fixpoint round, so the
    /// full-graph follow-up pass (where Ghidra cat-chains the goto-wrapped
    /// component into its neighbors) never ran and selectGoto had to mark
    /// every edge (BLOCKSTRUCT-NORETURN-DEADREGION-0001).
    /// Returns isolated_count (blocks with sizeIn==0 && sizeOut==0).
    fn collapse_internal(&mut self, target_idx: Option<i32>) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let max_iterations = self.graph.get_size() * 3 + 4;
        let mut iterations = 0;
        let mut isolated_count;
        let mut target_idx = target_idx;
        'fullchange: loop {
            if std::time::Instant::now() > deadline {
                break;
            }
            // RUDRA-GLUE: per-pass bank adoption sweep. Composite installs
            // enter the graph by Vec slot assignment (identify_internal and
            // the factory rewrites), which bypasses add_block; adopting every
            // current Vec member keeps their bank cells + identity-map entries
            // fresh so edge twins resolve on the shadow path (idempotent,
            // O(n) per pass, no observable effect — pure bank bookkeeping).
            // Bulk form: one identity read lock covers the whole sweep's
            // idempotence probes (PERF-ARENA-FLIP-0001 (f) step 2b — the
            // per-member id_of was ~25M ids-lock acquisitions on the giant
            // function; identify_internal's entry adopt makes fresh entries
            // rare).
            self.graph.bank.adopt_bulk(&self.graph.blocks);
            // Outer fullchange iteration cap: prevents the IfNoExit/CaseFallthru
            // second pass from repeatedly triggering (each creates a structure,
            // bumping structure_change_count, re-entering the outer loop) without
            // converging. The inner fixpoint has its own max_iterations; this
            // bounds the outer fullchange loop.
            if iterations >= max_iterations * 4 {
                break;
            }
            // Inner fixpoint: 8 rules per block until no change.
            loop {
                if std::time::Instant::now() > deadline {
                    break;
                }
                let change_before = self.structure_change_count;
                isolated_count = 0;
                // cc:1776-1811: the scan walks Ghidra's MUTATING list by
                // position: `index += 1` BEFORE the rules run, consumed
                // blocks removed (identifyInternal), composites appended
                // (addBlock), bound re-evaluated (`index <
                // graph.getSize()`). Walking `virtual_list` (which
                // identify_internal retains/pushes in exactly that pattern)
                // reproduces the oracle's semantics 1:1, including the
                // shift-skips: a rule consuming the visited block plus its
                // list neighbors shifts survivors left past the incremented
                // index, deferring them to the next fixpoint pass.
                let mut idx: usize = 0;
                while idx < self.virtual_list.len() {
                    // (BLOCKSTRUCT2) deadline granularity = per fixpoint
                    // pass (the pass-head check above); the oracle has no
                    // deadline at all (blockaction.cc:1771-1833 — the list
                    // walk is unclocked), and the per-visit clock read ran
                    // ~4M times on the giant function for a guard the
                    // corpus never trips. A pass is itself bounded (list
                    // length × 9 rules), so pass-head checking preserves
                    // the safety bound while restoring the oracle's
                    // unclocked inner walk.
                    // cc:1786-1791: targetbl mode — visit the target ONCE and
                    // end the sweep (Ghidra `index = graph.getSize()` AFTER
                    // the rule, so the re-read len ends the pass); the forced
                    // change re-runs the inner loop over the whole graph.
                    if let Some(t) = target_idx.take() {
                        if let Some(tb) = self.graph.get_block(t as usize) {
                            self.apply_rules_to_block(t as usize, &tb);
                        }
                        idx = self.virtual_list.len();
                        continue;
                    }
                    let slot = self.virtual_list[idx] as usize;
                    idx += 1;
                    // w-rc4 probe (RUDRA_BS_VISIT=1): mirror oracle
                    // BS_ORACLE_VISIT — per-visit position/slot dump.
                    // (Read once per process — the per-visit std::env::var
                    // (env lock + alloc) ran ~4M times on VdbeExec; env is
                    // immutable at runtime, decision value identical.)
                    static BS_VISIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
                    if *BS_VISIT.get_or_init(|| {
                        std::env::var("RUDRA_BS_VISIT")
                            .map(|v| v == "1")
                            .unwrap_or(false)
                    }) {
                        if let Some(b) = self.graph.get_block(slot) {
                            let r = b.read().unwrap();
                            let addr = match r
                                .as_any()
                                .downcast_ref::<crate::block::BlockCopy>()
                            {
                                Some(bc) => {
                                    bc.original.read().unwrap().get_start_addr().as_u64()
                                }
                                None => crate::block::front_leaf(&b)
                                    .map(|l| l.read().unwrap().get_start_addr().as_u64())
                                    .unwrap_or(0),
                            };
                            eprintln!(
                                "[BLOCKSTRUCT] {} visit pos={} idx={} ty={:?} i={} o={} @ {:#x}",
                                self.name,
                                idx - 1,
                                slot,
                                r.get_type(),
                                r.size_in(),
                                r.size_out(),
                                addr
                            );
                        }
                    }
                    let block = match self.graph.get_block(slot) {
                        Some(b) => b,
                        None => continue,
                    };
                    // cc:1792-1795: completely collapsed block → isolated.
                    // (BLOCKSTRUCT2) the isolated checks + rule dispatch are
                    // one pass inside apply_rules_to_block (single fetch,
                    // single view — the former visit-loop copy was the
                    // oracle's ONE getBlock + sizeIn/sizeOut read done
                    // twice).
                    // Ghidra collapseInternal (cc:1781-1833) applies the
                    // rules to EVERY graph member — collapsed components are
                    // first-class subjects of ruleBlockCat/Goto/... (e.g. a
                    // BlockIf falling into the next block cat-merges into a
                    // BlockList). The previous Basic/Copy-only gate left
                    // structured remainders split into multiple top-level
                    // components where the oracle produces one.
                    if self.apply_rules_to_block(slot, &block) {
                        isolated_count += 1;
                    }
                }
                // VDBEXEC-REFRESH-TAIL-0001: refresh_switch_cases removed from
                // this per-fixpoint-round position (LANE VDBEXEC 2026-09-28):
                // on giant functions it ran 12701× (VdbeExec drill, ~68.5s of
                // the 159s single-pole) while its output — the CASE_BODY flag
                // set + switch_case_indices — has NO in-collapse consumer on
                // the default 5-step path (all rule pre-guards removed by
                // TRI2-STRUCT-*; structure_loops_first is 7-phase-only and
                // reads the flags before any refresh ever ran). The only live
                // consumer is printc's case_body_indices collection at print
                // time (printc.rs:12572), which reads the FINAL flag state, so
                // the refresh moved to collapse_all_5step/collapse_all tail
                // (before finalize_structure) — computed on the identical
                // final graph state (no mutation between the old last
                // inner-round refresh and the new call site: the second-pass
                // scan matched nothing to exit, the selectGoto loop only
                // re-checks isolated_count). Behavior-identical final state,
                // O(rounds × graph recompute) → O(1) per collapseAll.
                iterations += 1;
                if self.structure_change_count == change_before || iterations >= max_iterations {
                    break;
                }
            }
            // cc:1835-1848: second pass — per-block INTERLEAVED IfNoExit +
            // CaseFallthru scan, first success breaks (the outer fullchange
            // loop re-runs the inner fixpoint). The oracle's loop body is
            //   if (ruleBlockIfNoExit(bl)) { fullchange = true; break; }
            //   if (ruleCaseFallthru(bl))  { fullchange = true; break; }
            // for each bl in list order — the fallthru rule is tried on the
            // SAME block before advancing to the next one. The previous
            // shape (ifnoexit across all blocks first, then a batch pass)
            // both reordered the oracle's decision sequence and ran an
            // invented batch fallthru that never fired on the pre-formation
            // graph (BLOCKSTRUCT-SWITCH-CASEFALLTHRU-0001).
            //
            // BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001 note kept: the oracle
            // runs ruleBlockIfNoExit for every function (cc:1840);
            // switch-clause safety comes from the rule's own isSwitchOut
            // guard (cc:1497), which try_rule_if_no_exit checks via
            // switch_case_indices/CASE_BODY.
            let mut fullchange = false;
            if std::time::Instant::now() <= deadline {
                // cc:1838-1848: position-order scan over Ghidra's list,
                // first match breaks (the outer fullchange loop re-runs).
                // (BLOCKSTRUCT2) index walk over the LIVE list — the oracle
                // reads `graph.getBlock(index)` with a re-evaluated bound;
                // the clone was borrow-workaround only (a fire breaks the
                // scan immediately, so no mutation is ever observed
                // mid-scan; index+bound reread is the oracle's exact form).
                // One pass-level view spans the scan (fires break before
                // any further view read; misses publish nothing).
                let bank = self.graph.bank.hold();
                let mut sp_idx: usize = 0;
                while sp_idx < self.virtual_list.len() {
                    let slot = self.virtual_list[sp_idx] as usize;
                    sp_idx += 1;
                    let Some(block) = self.graph.get_block(slot) else {
                        continue;
                    };
                    let self_id = self.graph.bank.registered_id_of(&block);
                    if self.try_rule_if_no_exit(slot, &block, self_id, &bank) {
                        fullchange = true;
                        break;
                    }
                    if self.try_rule_case_fallthru(slot, &block, self_id, &bank) {
                        fullchange = true;
                        break;
                    }
                }
            }
            if !fullchange {
                break 'fullchange;
            }
        }
        // Final isolated_count.
        let mut count = 0;
        for i in 0..self.graph.get_size() {
            if let Some(blk) = self.graph.get_block(i) {
                let r = blk.read().unwrap();
                if self.is_consumed(r.get_index()) {
                    count += 1;
                } else if r.size_in() == 0 && r.size_out() == 0 {
                    count += 1;
                }
            }
        }
        count
    }

    // Ghidra: blockaction.cc:1877 CollapseStructure::collapseAll
    /// Faithful 5-step port of collapseAll (blockaction.cc:1877-1893):
    ///   1. finaltrace=false; graph.clearVisitCount(); orderLoopBodies (cc:1880-1884)
    ///   2. collapseConditions (cc:1886)
    ///   3. collapseInternal(NULL) (cc:1888)
    ///   4. while (isolated < graph.getSize()) { selectGoto; collapseInternal(targetbl) } (cc:1889-1892)
    ///   5. finalize — Rudra's DEAD sweep (replaces Ghidra's incremental
    ///      identifyInternal list compaction, block.cc:953-960)
    ///
    /// BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001: the previous default path ran
    /// `apply_loop_exit_marks` + `run_tracedag` (batch-marking EVERY likely
    /// goto edge at once) + `collapse_loops`/`collapse_switches`/
    /// `structure_loops_first` BEFORE collapseInternal, then a bounded
    /// goto-cascade with `select_and_mark_goto` fallbacks. None of that is in
    /// the oracle: Ghidra marks goto edges ONE per selectGoto call (cc:1890)
    /// with a full collapseInternal between marks, and the per-loop TraceDAG
    /// only runs lazily inside updateLoopBody when structuring gets stuck.
    /// The upfront batch marking was the root cause of the
    /// parseconfig.constprop.0 cascade (41 blocks / 21 likely-goto edges /
    /// 10 cascade rounds / 8 DEAD).
    pub fn collapse_all_5step(&mut self) {
        // cc:1879-1884: finaltrace = false; graph.clearVisitCount();
        // orderLoopBodies(). The clear occurs at the start of
        // order_loop_bodies immediately before it consumes copied labels.
        self.finaltrace = false;
        self.likelygoto.clear();
        self.likelyiter = 0;
        self.likelylistfull = false;
        // cc:1187: loopbodyiter = loopbody.begin(). The previous -1 start
        // made `(-1) as usize` huge in update_loop_body, skipping the loop
        // walk entirely so the per-loop TraceDAG never ran.
        self.loopbodyiter = 0;
        self.order_loop_bodies();
        // cc:1886: collapseConditions (fixpoint ruleBlockOr).
        self.collapse_conditions();
        // RUDRA-GLUE: bank adoption sweep for composites installed by
        // order_loop_bodies/collapse_conditions before the first pass (the
        // per-pass sweep inside collapse_internal covers everything after).
        for bl in &self.graph.blocks {
            self.graph.bank.adopt(bl);
        }
        // cc:1888: collapseInternal(NULL).
        let mut isolated = self.collapse_internal(None);
        // cc:1889-1892: the selectGoto loop. Ghidra has no deadline, round
        // cap, progress guard, or batch cascade — selectGoto marks ONE edge
        // and collapseInternal(targetbl) re-structures before the next mark.
        while isolated < self.graph.get_size() as i32 {
            let target = self.select_goto();
            let prev_isolated = isolated;
            isolated = self.collapse_internal(target);
            // cc:1275: Ghidra throws LowlevelError("Could not finish
            // collapsing block structure") when selectGoto+clipExtraRoots
            // can't produce a mark. Rudra degrades to a log + stop so one
            // function can't kill the process; the divergence is visible in
            // stderr for fixture differencing.
            if isolated == prev_isolated && target.is_none() {
                eprintln!(
                    "[BLOCKSTRUCT] {}: selectGoto exhausted (LowlevelError site, blockaction.cc:1275)",
                    self.name
                );
                break;
            }
        }
        // VDBEXEC-REFRESH-TAIL-0001: single end-of-collapseAll
        // refresh_switch_cases (see collapse_internal note) — computes the
        // CASE_BODY flag set on the final pre-finalize graph state, exactly
        // what the old last per-round refresh saw.
        self.refresh_switch_cases();
        // Finalize: DEAD-sweep + reindex (Rudra model of Ghidra
        // identifyInternal's list compaction, block.cc:953-960), required
        // for downstream emit (printc emitBlockGraph).
        self.finalize_structure();
    }

    // Ghidra: blockaction.cc:1877 CollapseStructure::collapseAll selectGoto loop
    /// The cc:1889-1892 selectGoto loop as a reusable tail for the legacy
    /// 7-phase path (which previously ended in the invented batch cascade).
    fn select_goto_loop(&mut self) {
        let mut isolated = self.collapse_internal(None);
        while isolated < self.graph.get_size() as i32 {
            let target = self.select_goto();
            let prev_isolated = isolated;
            isolated = self.collapse_internal(target);
            if isolated == prev_isolated && target.is_none() {
                eprintln!(
                    "[BLOCKSTRUCT] {}: selectGoto exhausted (LowlevelError site, blockaction.cc:1275)",
                    self.name
                );
                break;
            }
        }
    }

    /// Collapse all structured patterns until fixpoint
    ///
    /// Corresponds to Ghidra's `CollapseStructure::collapseAll`
    // Ghidra: blockaction.cc:1877 CollapseStructure::collapseAll
    pub fn collapse_all(&mut self) {
        // Default: the Ghidra-faithful 5-step collapseAll (blockaction.cc:1877-
        // 1893), verified to produce identical output to the legacy 7-phase
        // path AND pass all 953 unit tests (after reconciling the while-break
        // and switch structure routes via collapse_loops + collapse_switches).
        // curl: 24/24 defects=0 numbering=485 (identical to 7-phase).
        // httpd: 29/29 decompile, 27/29 gcc-clean (same as 7-phase baseline).
        // Set RUDRA_7PHASE=1 to use the legacy 7-phase path instead.
        if !std::env::var("RUDRA_7PHASE")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            self.collapse_all_5step();
            return;
        }
        // Step 1: Order loop bodies (Ghidra's orderLoopBodies)
        self.order_loop_bodies();
        // BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001: removed the upfront
        // `apply_loop_exit_marks` + `run_tracedag` batch-marking steps —
        // Ghidra sets exit marks ONLY inside updateLoopBody's per-loop trace
        // window (cc:1231, cleared at cc:1245) and marks goto edges ONE per
        // selectGoto call. The tail select_goto_loop (cc:1889-1892) now does
        // all goto marking for this path too.

        // Step 1b: Structure WhileDo loops (innermost-first) before phase1, so
        // loop heads are preserved as BlockWhileDo instead of being consumed
        // by phase1's collapse_conditions.
        self.structure_loops_first();

        let max_iterations = self.graph.get_size() * 3 + 4;
        let mut iterations = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // First pass: collapse sequences and conditions in the traditional
        // phase-based approach (existing behavior).
        let phase1_start = self.structure_change_count;
        loop {
            if std::time::Instant::now() > deadline {
                eprintln!("[COLLAPSE] {} deadline hit iter={}", self.name, iterations);
                break;
            }
            let pre_count = self.structure_change_count;

            self.collapse_loops();
            if std::time::Instant::now() > deadline {
                break;
            }
            // Faithful WhileDo rule (blockaction.cc:1518-1549): runs every
            // phase iteration like Ghidra's collapseInternal interleaves it.
            // Picks up loops whose break-edges were marked goto by TraceDAG.
            let size_snapshot = self.graph.get_size();
            for wi in 0..size_snapshot {
                if std::time::Instant::now() > deadline {
                    break;
                }
                // Use try_rule_while_do (the interleaved-phase version that
                // accepts BlockList clauses via count_non_structural_in_edges),
                // not rule_block_while_do (which has stricter is_goto_out checks).
                if let Some(wblk) = self.graph.get_block(wi) {
                    // Fresh dispatch-level snapshot (a fire in an earlier
                    // iteration published; this dispatch's reads must see it).
                    let bank = self.graph.bank.hold();
                    let wid = self.graph.bank.registered_id_of(&wblk);
                    self.try_rule_while_do(wi, &wblk, wid, &bank);
                }
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            self.collapse_conditions();
            // collapse_bool_conditions removed (B8): it was a hand-rolled
            // duplicate of ruleBlockOr (try_rule_or), which the fixpoint
            // collapse_conditions above now handles correctly via the factory.
            // Ghidra collapseInternal rules (cc:1797-1828) — try per-block.
            // These are the Ghidra-faithful rule methods that eventually
            // replace the self-invented phase methods above.
            let rule_size = self.graph.get_size();
            for ri in 0..rule_size {
                if std::time::Instant::now() > deadline {
                    break;
                }
                if let Some(rblk) = self.graph.get_block(ri) {
                    let bank = self.graph.bank.hold();
                    let rid = self.graph.bank.registered_id_of(&rblk);
                    self.try_rule_or(ri, &rblk, rid, &bank);
                }
            }
            for ri in 0..rule_size {
                if std::time::Instant::now() > deadline {
                    break;
                }
                if let Some(rblk) = self.graph.get_block(ri) {
                    // Fresh dispatch-level snapshot (see the while_do loop above).
                    let bank = self.graph.bank.hold();
                    let rid = self.graph.bank.registered_id_of(&rblk);
                    self.try_rule_inf_loop(ri, &rblk, rid, &bank);
                }
            }
            // Switch detection LAST (after loops/conditions/sequences), matching
            // Ghidra's collapseInternal order where ruleBlockSwitch runs after
            // cat/proper_if/if_else/while_do/do_while. This lets loop/if structuring
            // consume blocks before switch detection, producing if/while instead of
            // switch when the control flow is structurable.
            //
            // R15 (2026-07-02): `collapse_cbranch_cascades` DISABLED. It was
            // fabricated logic with NO Ghidra counterpart — Ghidra's
            // ruleBlockSwitch (blockaction.cc:1649) fires ONLY on isSwitchOut()
            // blocks, and f_switch_out is set exclusively by CPUI_BRANCHIND
            // (block.cc:2286). Ghidra NEVER forms a switch from CBRANCH
            // if/else-if chains. Rudra's cascade function did, producing ~16/18
            // spurious switches (curl: switch 18 vs Ghidra's 2). The CBRANCH
            // chains are now structured as nested BlockIf via the try_rule_*
            // rules, exactly as Ghidra's collapseInternal does. (Audit: BATCH2 R15.)
            // self.collapse_cbranch_cascades();
            self.collapse_case_fallthru();
            self.collapse_sequences();
            // R17 (2026-09-25): `collapse_switches` RETIRED
            // (BLOCKACTION-COLLAPSESWITCH-ISEEXIT-0001). Ghidra has NO
            // phase1 switch pre-installer — LoopBody has no collapseSwitches
            // method and blockaction.hh:46 is the class declaration line;
            // the ONLY BlockSwitch install point in the oracle is
            // CollapseStructure::ruleBlockSwitch (blockaction.cc:1649-1723)
            // → newBlockSwitch (cc:1904-1919) → grabCaseBasic, running at
            // collapseInternal maturity where cc:1697-1708's invariant holds
            // (each case sizeOut<=1; sizeOut==1 iff the edge is to the
            // formal exitblock) — that invariant is what makes addCase's
            // isexit=(bl->sizeOut()==1) (block.cc:3513-3514) sound. This
            // phase1 pre-pass fired ~2 pipeline stages earlier, where the
            // case bodies' out-edges still pointed at the next case/merge
            // block, so the same capture over-fired: instrumented oracle
            // run (stage_isexit_1204, locked e40ed130, httpd main
            // entry=0x2b820) shows the final tree with isexit=1 on exactly
            // 2/18 cases (0x2ba9f, 0x2bdcd), while this pre-installer's
            // collection-loop capture produced 14/17 true (12 oracle-wrong
            // bits; the hardcoded vec![false] it replaced was wrong on the
            // same 2). try_rule_switch's capture at rule time is
            // address-keyed oracle-exact 16/16 on the same fixture. After
            // retirement the switch is installed by the rule chain
            // (select_goto_loop → collapse_internal → try_rule_switch),
            // which is Ghidra's own architecture. Default 5-step path never
            // called this pre-pass. (Audit: COLLAPSEFIX R17.)
            // self.collapse_switches();
            self.refresh_switch_cases();

            iterations += 1;
            if self.structure_change_count == pre_count || iterations >= max_iterations {
                break;
            }
        }
        eprintln!(
            "[COLLAPSE] {} phase1 done changes={} iter={}",
            self.name,
            self.structure_change_count - phase1_start,
            iterations
        );

        // Second phase: Ghidra-style interleaved rule application.
        // Repeatedly try rules on each block until a full pass makes no change.
        // This handles cases where applying cat-merge to one pair unlocks a
        // condition match that was previously blocked by intermediate blocks.
        let pre_interleaved_count = self.structure_change_count;
        let interleaved_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // Refresh switch case tracking — skip if no switches (saves time + avoids
        // dominator recomputation side-effects on simple test CFGs)
        let has_switch = (0..self.graph.get_size()).any(|i| {
            self.graph.get_block(i).map_or(false, |b| {
                b.read().unwrap().get_type() == crate::block::BlockType::Switch
            })
        });
        if has_switch {
            self.refresh_switch_cases();
        }
        // Detect if this function contains any BlockSwitch. if_no_exit is only
        // safe to enable when there are no switches (no case labels to extract).
        // Functions with switches (e.g. httpd main with 8 switches) keep
        // if_no_exit disabled to avoid case label extraction issues.
        let has_switch = {
            let mut found = false;
            for i in 0..self.graph.get_size() {
                if let Some(blk) = self.graph.get_block(i) {
                    if blk.read().unwrap().get_type() == crate::block::BlockType::Switch {
                        found = true;
                        break;
                    }
                }
            }
            found
        };
        // Ghidra collapseInternal (blockaction.cc:1776-1849): outer do-while
        // (fullchange) wraps an inner fixpoint do-while (8 rules per block),
        // then a second pass applies ruleBlockIfNoExit + ruleCaseFallthru
        // (cc:1837-1848) — applied only after the inner loop converges, because
        // "applying IfNoExit too early can cause other (preferable) rules to
        // miss" (cc:1835). The second pass breaks on the first match and
        // re-runs the inner loop. B9: wrap the inner interleaved loop in this
        // outer fullchange loop + second pass.
        let mut fullchange;
        'fullchange: loop {
            if std::time::Instant::now() > interleaved_deadline {
                break;
            }
            loop {
                if std::time::Instant::now() > interleaved_deadline {
                    break;
                }
                let pre_count = self.structure_change_count;
                let size = self.graph.get_size();
                for i in 0..size {
                    if std::time::Instant::now() > interleaved_deadline {
                        break;
                    }
                    let block = match self.graph.get_block(i) {
                        Some(b) => b,
                        None => continue,
                    };
                    let bt = block.read().unwrap().get_type();

                    // For Basic/Copy blocks: apply rules directly
                    if bt == crate::block::BlockType::Basic || bt == crate::block::BlockType::Copy {
                        self.apply_rules_to_block(i, &block);
                        continue;
                    }

                    // For BlockList: recursively apply rules to children
                    if bt == crate::block::BlockType::List {
                        let children = {
                            let b = block.read().unwrap();
                            match b.as_any().downcast_ref::<BlockList>() {
                                Some(bl) => bl.children.clone(),
                                None => continue,
                            }
                        };
                        self.apply_rules_to_children(&children);
                        continue;
                    }

                    // For BlockSwitch: recursively apply rules to case bodies
                    if bt == crate::block::BlockType::Switch {
                        let cases_and_default = {
                            let b = block.read().unwrap();
                            match b.as_any().downcast_ref::<BlockSwitch>() {
                                Some(sw) => {
                                    let mut all = sw.cases.clone();
                                    if let Some(ref dc) = sw.default_case {
                                        all.push(dc.clone());
                                    }
                                    all
                                }
                                None => continue,
                            }
                        };
                        self.apply_rules_to_children(&cases_and_default);
                        continue;
                    }
                }
                iterations += 1;
                self.refresh_switch_cases();
                if self.structure_change_count == pre_count || iterations >= max_iterations {
                    break;
                }
            }
            // cc:1835-1848: second pass — IfNoExit + CaseFallthru, applied only
            // after the inner loop converged. Break on first match, re-run inner.
            // "Applying IfNoExit rule too early can cause other (preferable) rules
            // to miss. Only apply if nothing else can apply."
            fullchange = false;
            if std::time::Instant::now() <= interleaved_deadline {
                // ruleBlockIfNoExit (cc:1840): per-block, break on first match.
                // Skip when the function has switches: case-label extraction is
                // unsafe mid-structuring (Rudra-specific guard, see has_switch).
                if !has_switch {
                    let s2 = self.graph.get_size();
                    let mut j: usize = 0;
                    while j < s2 {
                        let Some(jblk) = self.graph.get_block(j) else {
                            j += 1;
                            continue;
                        };
                        let bank = self.graph.bank.hold();
                        let jid = self.graph.bank.registered_id_of(&jblk);
                        if self.try_rule_if_no_exit(j, &jblk, jid, &bank) {
                            fullchange = true;
                            break;
                        }
                        j += 1;
                    }
                }
                // ruleCaseFallthru (cc:1844): Rudra's collapse_case_fallthru is
                // batch (processes all switches at once); run it once here and
                // treat any change as a fullchange trigger.
                if !fullchange && self.collapse_case_fallthru() {
                    fullchange = true;
                }
            }
            if !fullchange {
                break 'fullchange;
            }
        }
        eprintln!(
            "[COLLAPSE] {} interleaved done blocks={} iter={}",
            self.name,
            self.graph.get_size(),
            iterations
        );
        // BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001: replaced the invented batch
        // goto cascade with the oracle's selectGoto loop (cc:1889-1892).
        self.select_goto_loop();
        // VDBEXEC-REFRESH-TAIL-0001: single end-of-collapseAll
        // refresh_switch_cases (see collapse_internal note) — final-state
        // parity for the legacy path; structure_loops_first read the flags
        // before any refresh ever ran in either shape.
        self.refresh_switch_cases();
        // Final sweep: physically remove DEAD-flagged blocks from the top-level
        // blocks[] array, faithful to Ghidra identifyInternal's list=newlist
        // (block.cc:953-960). In Ghidra, identifyInternal removes consumed nodes
        // from the parent BlockGraph's list at structuring time; Rudra instead
        // marks them DEAD (blockaction.rs:2363) and leaves them in the array.
        // This final sweep collapses the array to only the surviving roots and
        // structured blocks, giving the CFT (control flow tree) single-ownership
        // property that printc's emitBlockGraph tree traversal relies on
        // (printc.cc:2746). Survivors KEEP their collapse-era indices (the
        // oracle's list=newlist never re-indexes; see finalize_structure).
        self.finalize_structure();
    }

    // Ghidra: blockaction.hh:46 LoopBody::finalizeStructure
    /// Remove consumed (absorbed) blocks from the top-level structure graph.
    /// Faithful to Ghidra's identifyInternal list compaction (block.cc:953-960:
    /// `list = newlist`), applied as a single final sweep rather than
    /// incrementally. Membership is the absorbed_into parent record — NOT
    /// block_flags::DEAD (identifyInternal never sets f_dead; that flag is
    /// exclusively Funcdata's dead basic-block removal, funcdata_block.cc:333/
    /// 370, whose blocks must SURVIVE this sweep for their own bookkeeping).
    ///
    /// After this, `graph.get_size()` returns only the count of surviving
    /// roots + structured blocks. Survivors keep their collapse-era indices
    /// (install-time min-slot values = min over component subtree, the
    /// oracle's addBlock invariant, block.cc:866-873) — the identity
    /// compareFinalOrder and scopeBreak's break-vs-goto equality tests are
    /// defined over. Edges are unaffected (they use Arc pointer identity,
    /// not indices).
    fn finalize_structure(&mut self) {
        let before = self.graph.get_size();
        let before_consumed = (0..before)
            .filter(|&i| {
                self.graph.get_block(i).map_or(false, |b| {
                    let idx = b.read().unwrap().get_index();
                    self.is_consumed(idx)
                })
            })
            .count();
        // Retain only top-level blocks (not absorbed into a composite),
        // preserving relative order (emitBlockGraph emits in list order,
        // matching Ghidra's preorder).
        let consumed = std::mem::take(&mut self.graph.absorbed_into);
        self.graph.blocks.retain(|b| {
            let idx = b.read().unwrap().get_index();
            !consumed.contains_key(&idx)
        });
        self.graph.absorbed_into = consumed;
        // Ghidra's identifyInternal compaction (`list = newlist`,
        // block.cc:953-960) NEVER touches FlowBlock::index: survivors keep
        // the indices assigned during collapse, which by addBlock's
        // min-tracking (block.cc:866-873: `index = min(index,
        // bl->index)`) equal the MINIMUM basic-block index over each
        // survivor's component subtree — a composite shares the index of
        // its entry leaf. That shared value is the identity the final-tree
        // index comparisons run on: FlowBlock::compareFinalOrder
        // (block.cc:709/731, orderBlocks' sort key) and scopeBreak's
        // `gototarget->getIndex() == curloopexit` (block.cc:2872/3082) /
        // `bl->getIndex() == curexit` (block.cc:3621) — break-vs-goto
        // reclassification holds exactly when the goto target IS (or is
        // the entry of) the loop/switch sibling that follows in the same
        // list. The former re-index-to-compacted-position loop here broke
        // that identity (MCENSUS3-SWITCH-BREAKGOTO-EMIT-0001: sibling
        // composite got list position 1 while its entry leaf kept the
        // collapse-era index 10, so every loop-exit if-goto compared
        // unequal and printed `goto code_rXXXX;` where the oracle prints
        // `break;`), so it is removed: survivors keep their install-time
        // min-slot indices (blockaction.rs identify_internal's new_idx =
        // min over consumed ∪ install), which is the same invariant
        // addBlock maintains in the oracle.
        let after = self.graph.get_size();
        eprintln!(
            "[BLOCKSTRUCT] {} finalize_structure: {} -> {} (removed {} consumed)",
            self.name, before, after, before_consumed
        );
    }

    // Ghidra: block.cc:953-960 BlockGraph::identifyInternal (list compaction)
    /// Top-level membership test replacing Ghidra's incremental list
    /// compaction. Ghidra's identifyInternal rebuilds `list` without the
    /// identified nodes (block.cc:953-960), so every list walk
    /// (collapseInternal's `graph.getBlock(index)`, blockaction.cc:1781-
    /// 1833) only ever visits top-level blocks. Rudra's flat `blocks` Vec
    /// keeps every node at its slot, so the equivalent observable test is
    /// the absorbed_into parent record (written by identify_internal /
    /// the sequence-merge pass): a block with an absorbed_into entry is a
    /// component inside some composite and must be invisible to rules.
    /// NEVER use block_flags::DEAD for this: Ghidra's f_dead is exclusively
    /// Funcdata's dead basic-block removal (funcdata_block.cc:333/370),
    /// not a structuring state.
    fn is_consumed(&self, idx: i32) -> bool {
        self.graph.absorbed_into.contains_key(&idx)
    }

    // RUDRA-GLUE: (BLOCKSTRUCT2) entry-guard pair through the dispatch view
    /// The cc entry-guard reads every rule starts with — `bl->sizeOut()`
    /// and `bl->isSwitchOut()` (e.g. cc:1289-1290 cat, cc:1384-1385
    /// properIf, cc:1421-1422 ifElse, cc:1427-1429 ifGoto, cc:1453+ goto,
    /// cc:1519-1520 whileDo, cc:1556-1557 doWhile, cc:1590 infLoop,
    /// cc:1652-1653 switch) — resolved through the bank view shadows
    /// (block.hh:312-313/165 mirrored by the sync_bank_shadows choke). The
    /// SENTINEL form (bare fixtures, never adopted) falls back to the block
    /// guard reads — byte-identical values either way.
    #[inline]
    fn entry_size_out_switch_out(
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_id: crate::arena::BlockId,
        bank: &crate::block::BlockBankView,
    ) -> (usize, bool) {
        if self_id != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL {
            (
                bank.expect_size_out(self_id),
                bank.expect_flags(self_id) & crate::block::block_flags::SWITCH_OUT != 0,
            )
        } else {
            let b = block.read().unwrap();
            (b.size_out(), b.is_switch_out())
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::applyRulesToBlock
    /// Apply interleaved rules to a single block at graph index i.
    /// Returns `true` when the block counts as isolated (cc:1792-1795:
    /// completely collapsed or no edges at all) — the caller's
    /// isolated_count accounting.
    fn apply_rules_to_block(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) -> bool {
        // Skip blocks consumed by an earlier identify_internal (Ghidra: they
        // are no longer in the graph list, block.cc:953-960). These blocks
        // keep only their component-to-component edges, so they can't match
        // any rule — and matching them would corrupt the graph (e.g. a loop
        // head absorbed into a composite mid-structuring).
        // PERF-ARENA-FLIP-0001 (f) step 2b: ONE snapshot view spans the whole
        // dispatch. Read-phase discipline: a rule that fires (its
        // identify_internal adopts = the only publish on this path) returns
        // true IMMEDIATELY (bs_try!), so no view read ever follows a
        // publish; rules that return false never published.
        let bank = self.graph.bank.hold();
        // (BLOCKSTRUCT2) entry checks through the view shadows (registered
        // form — the graph members are always adopted: build_copy adopts
        // the copies, identify_internal adopts each composite at install);
        // SENTINEL (bare fixtures) falls back to the block guard reads,
        // byte-identical. This deduplicates the visit loop's former second
        // fetch+guard pass — the oracle reads getBlock + the two size
        // fields once per visit (blockaction.cc:1779-1795).
        let self_id = self.graph.bank.registered_id_of(block);
        if self_id != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL {
            if self.is_consumed(bank.expect_index(self_id)) {
                return true;
            }
            if bank.expect_size_in(self_id) == 0 && bank.expect_size_out(self_id) == 0 {
                // Orphaned block (no edges at all). Ghidra's collapseInternal
                // also skips rules on completely isolated blocks
                // (blockaction.cc:1792-1795).
                return true;
            }
        } else {
            let r = block.read().unwrap();
            if self.is_consumed(r.get_index()) {
                return true;
            }
            if r.size_in() == 0 && r.size_out() == 0 {
                return true;
            }
        }
        // Ghidra collapseInternal order (blockaction.cc:1797-1828): goto FIRST,
        // then cat, proper_if, if_else, while_do, do_while, inf_loop, switch.
        // Running goto first ensures continue/break edges are consumed (wrapped
        // as BlockIfGoto/BlockGoto) BEFORE while_do tries to match the body,
        // which reduces clause size_in so WhileDo can form.
        // (RUDRA_RULE2 read once per process: env is immutable at runtime and
        // the per-visit std::env::var (env lock + alloc) ran 4M+ times on
        // giant functions — pure Rust bookkeeping the oracle has no
        // counterpart for; the decision value is identical.)
        static RULE2: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let rule2 = *RULE2.get_or_init(|| std::env::var("RUDRA_RULE2").is_ok());
        macro_rules! bs_try {
            ($f:ident) => {
                if self.$f(i, block, self_id, &bank) {
                    if rule2 {
                        eprintln!("[RRULE2] FIRE {} blk{}", stringify!($f), i);
                    }
                    return false;
                }
            };
        }
        bs_try!(try_rule_if_goto);
        bs_try!(try_rule_goto);
        bs_try!(try_rule_cat);
        bs_try!(try_rule_proper_if);
        bs_try!(try_rule_if_else);
        bs_try!(try_rule_while_do);
        bs_try!(try_rule_do_while);
        // Ghidra cc:1821: ruleBlockInfLoop (between do_while and switch)
        bs_try!(try_rule_inf_loop);
        // Ghidra cc:1825: ruleBlockSwitch (last in collapseInternal)
        bs_try!(try_rule_switch);
        false
    }

    // Ghidra: blockaction.hh:46 LoopBody::applyRulesToChildren
    /// Apply interleaved rules recursively to children of a structured block.
    /// For each child: if it's Basic/Copy, find its graph index and apply rules.
    /// If it's BlockList, recurse into its children.
    fn apply_rules_to_children(&mut self, children: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>]) {
        for child in children {
            let bt = child.read().unwrap().get_type();
            match bt {
                crate::block::BlockType::Basic | crate::block::BlockType::Copy => {
                    let child_idx = child.read().unwrap().get_index() as usize;
                    if child_idx < self.graph.get_size() {
                        self.apply_rules_to_block(child_idx, child);
                    }
                }
                crate::block::BlockType::List => {
                    let sub_children = {
                        let b = child.read().unwrap();
                        match b.as_any().downcast_ref::<BlockList>() {
                            Some(bl) => bl.children.clone(),
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&sub_children);
                }
                crate::block::BlockType::Switch => {
                    let sub_children = {
                        let b = child.read().unwrap();
                        match b.as_any().downcast_ref::<BlockSwitch>() {
                            Some(sw) => {
                                let mut all = sw.cases.clone();
                                if let Some(ref dc) = sw.default_case {
                                    all.push(dc.clone());
                                }
                                all
                            }
                            None => continue,
                        }
                    };
                    self.apply_rules_to_children(&sub_children);
                }
                _ => {}
            }
        }
    }

    // Ghidra: blockaction.cc:1193 CollapseStructure::updateLoopBody
    /// Advance the loopbodyiter over loop_order, building a per-loop TraceDAG
    /// and populating likelygoto. Returns true if likelygoto has entries to
    /// consume; false if all loops exhausted and no likely gotos remain.
    /// Faithful to `updateLoopBody` (blockaction.cc:1193-1253):
    ///   - cc:1196-1198: if finaltrace already set, return false.
    ///   - cc:1201-1221: walk loopbodyiter; for each LoopBody call update().
    ///     If a bottom survives AND equals the head → single-node self-loop:
    ///     the loop edge itself is the only likelygoto (cc:1206-1213).
    ///     Otherwise break while the loop still exists and its likelygoto
    ///     list still has entries (cc:1214-1216).
    ///   - cc:1222-1223: current list not exhausted → return true.
    ///   - cc:1226-1232: NEW trace. With a loop: TraceDAG rooted ONLY at
    ///     looptop, finish=loopbottom, and setExitMarks BEFORE the trace
    ///     (cc:1231) — this bounds the DAG to the loop body.
    ///   - cc:1233-1239: without a loop: roots = every sizeIn==0 block.
    ///   - cc:1240-1246: initialize + pushBranches; then emitLikelyEdges
    ///     APPENDS the LoopBody's exit/back edges (priority order) and the
    ///     exit marks are cleared.
    ///   - cc:1247-1250: no loop and no gotos found → finaltrace, false.
    ///
    /// BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001: the previous port ignored the
    /// loop for the trace itself (it always ran the whole-DAG
    /// generate_likely_gotos and merely appended LoopBody edges AFTERWARDS,
    /// with setExitMarks applied after the trace — a no-op). The trace must
    /// be loop-restricted (root=looptop only, finish=loopbottom, exit marks
    /// live during the trace), otherwise the DAG walks the whole function and
    /// marks interior structured edges as likely gotos.
    fn update_loop_body(&mut self) -> bool {
        let trace = std::env::var("RUDRA_TRACE_SELECTGOTO").is_ok();
        if self.finaltrace {
            return false; // cc:1196-1198
        }
        let mut loopbottom: i32 = -1;
        let mut looptop: i32 = -1;
        // cc:1201-1221: advance loopbodyiter over loop_order (innermost
        // first — loop_order is sorted deepest-nesting-first).
        while (self.loopbodyiter as usize) < self.loop_order.len() {
            let lb_idx = self.loopbodyiter as usize;
            let loopbottom_opt = self.loop_order[lb_idx].update(self.graph);
            if let Some(bottom) = loopbottom_opt {
                looptop = self.loop_order[lb_idx].head;
                loopbottom = bottom;
                if bottom == looptop {
                    // cc:1206-1213: single node looping back to itself — if
                    // sizeout were 1 or 2 the loop would have collapsed, so
                    // the node is likely a switch; mark the loop edge goto.
                    self.likelygoto.clear();
                    self.likelygoto.push(FloatingEdge {
                        from_idx: looptop,
                        to_idx: looptop,
                    });
                    self.likelyiter = 0;
                    self.likelylistfull = true;
                    return true;
                }
                if !self.likelylistfull || self.likelyiter < self.likelygoto.len() {
                    break; // cc:1214-1216: loop still exists
                }
            }
            self.loopbodyiter += 1; // cc:1218-1221
            self.likelylistfull = false;
            loopbottom = -1;
        }
        // cc:1222-1223
        if self.likelylistfull && self.likelyiter < self.likelygoto.len() {
            if trace {
                eprintln!(
                    "[SELECTGOTO] {} updateLoopBody: REMAINDER iter={}/{} (cc:1222)",
                    self.name, self.likelyiter, self.likelygoto.len()
                );
            }
            return true;
        }

        // cc:1226: generate likely gotos for a new inner loop or the DAG.
        self.likelygoto.clear();
        let mut edges: Vec<crate::tracedag::FloatingEdge> = Vec::new();
        if loopbottom != -1 {
            let lb_idx = self.loopbodyiter as usize;
            // cc:1229-1231: trace from the top of the loop ONLY, with the
            // loop bottom as finish block, and exit marks bounding the DAG.
            self.loop_order[lb_idx].set_exit_marks(self.graph);
            {
                let mut tracer = crate::tracedag::TraceDAG::new(self.graph);
                tracer.add_root(looptop);
                tracer.set_finish_block(loopbottom);
                tracer.initialize();
                tracer.push_branches();
                edges = tracer.likely_goto.clone();
            } // tracer's immutable graph borrow ends before clear_exit_marks
              // cc:1244: emitLikelyEdges APPENDS the LoopBody's prioritized
              // exit/back edges after the trace-produced ones.
            let mut lb_edges: Vec<FloatingEdge> = Vec::new();
            self.loop_order[lb_idx].emit_likely_edges(&mut lb_edges, self.graph);
            for fe in lb_edges {
                edges.push(crate::tracedag::FloatingEdge {
                    top: fe.from_idx,
                    bottom: fe.to_idx,
                });
            }
            // cc:1245: clear the marks — they exist only for the trace.
            self.loop_order[lb_idx].clear_exit_marks(self.graph);
        } else {
            // cc:1233-1239: no loop — trace the final DAG from all roots.
            // Ghidra collects roots in LIST position order (getBlock(i) over
            // the mutating list) and feeds them to TraceDAG in that order;
            // the root order paces pushBranches and BadEdgeScore
            // tie-breaking. virtual_list entries are live slots only.
            let step = std::env::var("RUDRA_GOTOSTEP").is_ok();
            let mut roots: Vec<i32> = Vec::new();
            let vlist = self.virtual_list.clone();
            for &slot in &vlist {
                if let Some(b) = self.graph.get_block(slot as usize) {
                    if b.read().unwrap().size_in() == 0 {
                        if step {
                            eprintln!("[RROOT] blk{} (vslot {})", slot, slot);
                        }
                        roots.push(slot);
                    }
                }
            }
            if roots.is_empty() {
                edges = Vec::new();
            } else {
                let mut tracer = crate::tracedag::TraceDAG::new(self.graph);
                for r in roots {
                    tracer.add_root(r);
                }
                tracer.initialize();
                tracer.push_branches();
                edges = tracer.likely_goto.clone();
            }
        }
        // cc:1242
        self.likelylistfull = true;
        if std::env::var("RUDRA_IRRED_DBG")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            eprintln!(
                "[IRRED] {} trace done loopbottom={} edges={:?}",
                self.name,
                loopbottom,
                edges.iter().map(|e| (e.top, e.bottom)).collect::<Vec<_>>()
            );
        }
        if loopbottom == -1 && edges.is_empty() {
            // cc:1247-1250: no loops left and the trace found no gotos.
            if std::env::var("RUDRA_IRRED_DBG")
                .map(|v| v == "1")
                .unwrap_or(false)
            {
                let n_live = (0..self.graph.get_size())
                    .filter(|&i| {
                        self.graph
                            .get_block(i)
                            .map(|b| {
                                let idx = b.read().unwrap().get_index();
                                !self.is_consumed(idx)
                            })
                            .unwrap_or(false)
                    })
                    .count();
                eprintln!(
                    "[IRRED] {} finaltrace residual graph (live={}):",
                    self.name, n_live
                );
                for i in 0..self.graph.get_size() {
                    let Some(b) = self.graph.get_block(i) else {
                        continue;
                    };
                    let r = b.read().unwrap();
                    if self.is_consumed(r.get_index()) {
                        continue;
                    }
                    let outs: Vec<String> = (0..r.size_out())
                        .filter_map(|j| {
                            r.get_out(j).map(|e| {
                                format!("{}(L{:x})", self.graph_bank().expect_index(e.point), e.flags)
                            })
                        })
                        .collect();
                    let ins: Vec<String> = (0..r.size_in())
                        .filter_map(|j| {
                            r.get_in(j).map(|e| {
                                format!("{}(L{:x})", self.graph_bank().expect_index(e.point), e.flags)
                            })
                        })
                        .collect();
                    eprintln!(
                        "[IRRED]   blk{} in=[{}] out=[{}] ty={:?} fl={:#x}",
                        r.get_index(),
                        ins.join(","),
                        outs.join(","),
                        r.get_type(),
                        r.get_flags()
                    );
                }
            }
            self.finaltrace = true;
            return false;
        }
        self.likelygoto = edges
            .iter()
            .map(|fe| FloatingEdge {
                from_idx: fe.top,
                to_idx: fe.bottom,
            })
            .collect();
        if trace {
            eprintln!(
                "[SELECTGOTO] {} updateLoopBody: REGEN loopiter={} looptop={} loopbottom={} list={:?}",
                self.name,
                self.loopbodyiter,
                looptop,
                loopbottom,
                self.likelygoto
                    .iter()
                    .map(|e| (e.from_idx, e.to_idx))
                    .collect::<Vec<_>>()
            );
        }
        self.likelyiter = 0;
        true
    }

    // Ghidra: blockaction.cc:1260 CollapseStructure::selectGoto
    /// Pick one edge from likelygoto, re-resolve against the live graph, and
    /// mark it as goto via setGotoBranch. Returns the source block index, or
    /// None when the likelygoto lists are exhausted (then Ghidra falls back
    /// to clipExtraRoots — cc:1274 — and throws LowlevelError if that finds
    /// nothing; Rudra logs and lets the caller stop, see the cc:1275 site in
    /// collapse_all_5step). Faithful to `selectGoto` (blockaction.cc:1260-1277).
    fn select_goto(&mut self) -> Option<i32> {
        let trace = std::env::var("RUDRA_TRACE_SELECTGOTO").is_ok();
        while self.update_loop_body() {
            while self.likelyiter < self.likelygoto.len() {
                let fe = self.likelygoto[self.likelyiter].clone();
                self.likelyiter += 1;
                // cc:1266: getCurrentEdge re-resolves against live graph.
                if let Some((startbl_idx, outedge)) = fe.get_current_edge(self.graph) {
                    // cc:1269: setGotoBranch(outedge).
                    if trace {
                        eprintln!(
                            "[SELECTGOTO] {} pick entry #{}: {} -> {} resolved as blk{} outedge={}",
                            self.name,
                            self.likelyiter - 1,
                            fe.from_idx,
                            fe.to_idx,
                            startbl_idx,
                            outedge
                        );
                        let tgt = self
                            .graph
                            .get_block(startbl_idx as usize)
                            .and_then(|b| b.read().unwrap().get_out(outedge).map(|e| e.point))
                            .map(|t| self.graph.bank.expect_index(t))
                            .unwrap_or(-1);
                        let src_addr = self
                            .graph
                            .get_block(startbl_idx as usize)
                            .map(|b| crate::block::dbg_front_leaf_start_addr(&b))
                            .unwrap_or(0);
                        eprintln!(
                            "[SELECTGOTO] {} mark goto: block #{} @ {:#x} outedge={} -> #{}",
                            self.name, startbl_idx, src_addr, outedge, tgt
                        );
                    }
                    if let Some(blk) = self.graph.get_block(startbl_idx as usize) {
                        self.set_goto_branch_on_block(&blk, outedge);
                    }
                    return Some(startbl_idx);
                } else if trace {
                    eprintln!(
                        "[SELECTGOTO] {} skip entry #{}: {} -> {} (getCurrentEdge NULL)",
                        self.name,
                        self.likelyiter - 1,
                        fe.from_idx,
                        fe.to_idx
                    );
                }
            }
        }
        // cc:1274-1276: clipExtraRoots fallback. Ghidra throws
        // LowlevelError("Could not finish collapsing block structure") when
        // this returns false; the caller-side break (collapse_all_5step)
        // mirrors the abort without killing the process.
        if !self.clip_extra_roots() {
            eprintln!(
                "[BLOCKSTRUCT] {}: selectGoto: clipExtraRoots found nothing (cc:1275 LowlevelError site)",
                self.name
            );
        }
        None
    }

    // Ghidra: block.cc:305 FlowBlock::setGotoBranch (via selectGoto cc:1269)
    /// Mark the j-th out-edge of `bl` as an unstructured goto. Faithful to
    /// `FlowBlock::setGotoBranch` (block.cc:305-313):
    ///   - `setOutEdgeFlag(i, f_goto_edge)` — the label is applied to the
    ///     out edge AND mirrored onto the target's in-edge (block.cc:240-247);
    ///     this is what makes isGotoIn/isLoopDAGIn see the goto on the
    ///     target side (the previous port only set block-level flags, so
    ///     TraceDAG counted goto in-edges as DAG edges → stuck traces →
    ///     extra bad-edge selections).
    ///   - `flags |= f_interior_gotoout` on the source.
    ///   - `outofthis[i].point->flags |= f_interior_gotoin` on the target.
    /// Rudra additionally records GOTO_EDGE_0/GOTO_EDGE_1 block flags for
    /// BlockBasic (is_goto_out consults them as the f_goto_edge equivalent).
    fn set_goto_branch_on_block(
        &mut self,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        j: usize,
    ) {
        // Capture target for INTERIOR_GOTOIN before write lock.
        let target_opt = {
            let r = bl.read().unwrap();
            if j < r.size_out() {
                r.get_out(j).map(|e| self.graph_bank().expect_arc(e.point))
            } else {
                None
            }
        };
        // cc:306: setOutEdgeFlag(i, f_goto_edge) — mirrored on both halves.
        // Ghidra's label lives in the FlowBlock base's edge arrays, so the
        // write lands for EVERY block type (BlockList/BlockIf/... components
        // included). This compatibility helper explicitly visits every
        // concrete edge owner, matching the now trait-wide mirrored helper
        // and preserving the historical dead-region fix.
        set_out_edge_flag_all_types(bl, j, crate::block::edge_flags::F_GOTO_EDGE);
        // cc:311-312: interior goto flags (Rudra block-level flag names).
        // The GOTO_EDGE_0/1 mirror flags are set for EVERY block type (they
        // live in the shared FlowBlock flags word), matching the oracle's
        // type-agnostic edge label; the previous BlockBasic-only downcast
        // left goto marks on structured blocks (BlockCondition etc.)
        // invisible to try_rule_if_goto, stalling collapseInternal.
        {
            let mut w = bl.write().unwrap();
            w.set_flags(crate::block::block_flags::INTERIOR_GOTOOUT);
            let bit = match j {
                0 => crate::block::block_flags::GOTO_EDGE_0,
                1 => crate::block::block_flags::GOTO_EDGE_1,
                _ => 0,
            };
            if bit != 0 {
                let cur = w.get_flags();
                w.set_flags(cur | bit);
            }
        }
        if let Some(target) = target_opt {
            target
                .write()
                .unwrap()
                .set_flags(crate::block::block_flags::INTERIOR_GOTOIN);
        }
    }

    // Ghidra: block.hh:347 FlowBlock::isGotoOut (label-based form)
    /// Type-agnostic goto-edge test: the oracle's isGotoOut reads the edge
    /// LABEL (f_goto_edge|f_irreducible) which exists on every block type;
    /// Rudra's trait default only implements it for BlockBasic. Rules that
    /// gate on goto edges (ruleBlockGoto/ProperIf/WhileDo/IfElse) must see
    /// goto marks on structured blocks too.
    fn out_edge_is_goto(b: &dyn FlowBlock, slot: usize) -> bool {
        // Reference read of the edge label (oracle reads
        // outofthis[i].label directly, block.hh:301) — no BlockEdge clone.
        if let Some(e) = b.get_out_ref(slot) {
            if e.flags
                & (crate::block::edge_flags::F_GOTO_EDGE
                    | crate::block::edge_flags::F_IRREDUCIBLE_EDGE)
                != 0
            {
                return true;
            }
        }
        // The GOTO_EDGE_0/GOTO_EDGE_1 block-level mirrors live in the shared
        // FlowBlock flags word, so every block type (BlockList, BlockIf, ...)
        // can be read directly — the previous fall-through to
        // `is_goto_out(slot)` hit the trait default (false for everything
        // but BlockBasic), making goto marks on structured components
        // invisible to the rules and to the TraceDAG re-selection loop
        // (BLOCKSTRUCT-NORETURN-DEADREGION-0001).
        let f = b.get_flags();
        if slot == 0 && (f & crate::block::block_flags::GOTO_EDGE_0) != 0 {
            return true;
        }
        if slot == 1 && (f & crate::block::block_flags::GOTO_EDGE_1) != 0 {
            return true;
        }
        b.is_goto_out(slot) // BlockBasic block-level mirror flags
    }

    // RUDRA-GLUE: Ghidra's goto mark lives on the edge label itself
    // (outofthis[i].label, written by setGotoBranch block.cc:305-313), so
    // removeEdge (block.cc:1469-1481) removes the mark together with the
    // edge and the surviving edges' marks are untouched. Rudra ADDITIONALLY
    // mirrors the mark in the slot-indexed GOTO_EDGE_0/GOTO_EDGE_1 block
    // flags (see set_goto_branch_on_block) for BlockBasic::is_goto_out —
    // those mirrors are slot-indexed and do NOT follow edge removal: after
    // newBlockMultiGoto peels a goto edge, the surviving edges shift slots
    // and a stale mirror falsely marks whichever edge moved into the
    // vacated slot. Re-derive the mirrors from the authoritative per-edge
    // F_GOTO_EDGE labels after every peel removal so the two channels stay
    // equivalent (MSTRUCT-SWITCHGOTO-SELECTGOTO-0001: glob_set/glob_word
    // round-2/3 collapse — the stale GOTO_EDGE_1 peeled the dispatch's
    // default edge right after the dispatch→4d04 peel, cascading through
    // checkSwitchSkips into a degenerate 0-case switch).
    fn resync_goto_edge_mirrors(bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>) {
        let mut w = bl.write().unwrap();
        let f = w.get_flags();
        if f
            & (crate::block::block_flags::GOTO_EDGE_0
                | crate::block::block_flags::GOTO_EDGE_1)
            == 0
        {
            return; // no mirrors to resync — edge labels are authoritative
        }
        let g0 = w
            .get_out(0)
            .map(|e| e.flags & crate::block::edge_flags::F_GOTO_EDGE != 0)
            .unwrap_or(false);
        let g1 = w
            .get_out(1)
            .map(|e| e.flags & crate::block::edge_flags::F_GOTO_EDGE != 0)
            .unwrap_or(false);
        // set_flags is OR-semantics (Ghidra setFlag, block.hh:155
        // `flags |= fl`), so dropping stale mirror bits requires
        // clear_flags (Ghidra clearFlag, block.hh:156 `flags &= ~fl`).
        w.clear_flags(
            crate::block::block_flags::GOTO_EDGE_0
                | crate::block::block_flags::GOTO_EDGE_1,
        );
        if g0 {
            w.set_flags(crate::block::block_flags::GOTO_EDGE_0);
        }
        if g1 {
            w.set_flags(crate::block::block_flags::GOTO_EDGE_1);
        }
    }

    // Ghidra: block.hh:336 FlowBlock::isDecisionOut
    /// Decision edge test (cc:336): the edge is neither irreducible, back,
    /// nor goto. Used by ruleBlockProperIf (cc:1395) and ruleBlockIfElse
    /// (cc:1423-1424) to refuse structuring across unstructured edges.
    fn out_edge_is_decision(b: &dyn FlowBlock, slot: usize) -> bool {
        match b.get_out_ref(slot) {
            Some(e) => {
                e.flags
                    & (crate::block::edge_flags::F_IRREDUCIBLE_EDGE
                        | crate::block::edge_flags::F_BACK_EDGE
                        | crate::block::edge_flags::F_GOTO_EDGE)
                    == 0
            }
            None => false,
        }
    }

    // RUDRA-GLUE: (IDENTIFY) view form of the second-tier guard reads
    /// Bank-view twin of `out_edge_is_goto` — the oracle's `isGotoOut(i)`
    /// (block.hh:347, a non-virtual `outofthis[i].label & (f_irreducible|
    /// f_goto_edge)` load) served without the block RwLock/vtable: the edge
    /// label comes from the wave-3 edge shadow (`expect_out_edge`) and the
    /// GOTO_EDGE_0/1 slot mirrors from the (g) flags shadow. Channel
    /// completeness (CR-BLOCKSTRUCT2 §2-B): every `is_goto_out` impl in the
    /// tree reads exactly these two channels — the trait default reads the
    /// edge label only, BlockBasic additionally reads the GOTO_EDGE_0/1
    /// mirror bits in the same flags word the shadow serves — so the view
    /// form returns identical values for every block type.
    #[inline]
    fn view_out_edge_is_goto(
        bank: &crate::block::BlockBankView,
        id: crate::arena::BlockId,
        slot: usize,
    ) -> bool {
        if let Some(e) = bank.expect_out_edge(id, slot) {
            if e.flags
                & (crate::block::edge_flags::F_GOTO_EDGE
                    | crate::block::edge_flags::F_IRREDUCIBLE_EDGE)
                != 0
            {
                return true;
            }
        }
        let f = bank.expect_flags(id);
        if slot == 0 && (f & crate::block::block_flags::GOTO_EDGE_0) != 0 {
            return true;
        }
        if slot == 1 && (f & crate::block::block_flags::GOTO_EDGE_1) != 0 {
            return true;
        }
        false
    }

    // RUDRA-GLUE: (IDENTIFY) view form of the second-tier guard reads
    /// Bank-view twin of `out_edge_is_decision`'s label test (block.hh:336
    /// `isDecisionOut`: the edge is neither irreducible, back, nor goto) —
    /// applied to an already-fetched edge-label word, so a caller that read
    /// the edge twin once (point + flags together) pays no second shadow
    /// read. `false` for a missing edge is the caller's None arm.
    #[inline]
    fn edge_label_is_decision(flags: u32) -> bool {
        flags
            & (crate::block::edge_flags::F_IRREDUCIBLE_EDGE
                | crate::block::edge_flags::F_BACK_EDGE
                | crate::block::edge_flags::F_GOTO_EDGE)
            == 0
    }

    // Ghidra: block.cc:880 BlockGraph::forceOutputNum
    /// While the block has fewer than `target` out-edges, append a SELF edge
    /// labeled f_loop_edge|f_back_edge on both halves
    /// (`addInEdge(this, f_loop_edge|f_back_edge)`, block.cc:888). This is
    /// how the newBlock* factories (block.cc:1710/1744/1768/1791/1812/1831/
    /// 1850/1867/1882) preserve a back-edge that identifyInternal
    /// internalized — e.g. a cat chain whose tail branches back into the
    /// chain: the composite's external out-count is then below the tail's
    /// pre-merge count, and the restored self loop/back edge is what lets
    /// ruleBlockDoWhile (cc:1555) absorb the latch.
    fn force_output_num(
        bank: &crate::block::BlockBank,
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        target: usize,
    ) {
        // Self-edge twins resolve through the bank map: reading `bl` here
        // would deadlock against the write guard below (self-loop edges).
        let bl_id = bank.registered_id_of(bl);
        let mut w = bl.write().unwrap();
        while w.size_out() < target {
            // addInEdge (block.cc:73-80): each half's reverse_index is the
            // peer list's size BEFORE its push — computed here for both
            // halves up front, exactly as the oracle does with one call.
            let out_slot = w.size_out() as i32;
            let in_slot = w.size_in() as i32;
            let lab = crate::block::edge_flags::F_LOOP_EDGE
                | crate::block::edge_flags::F_BACK_EDGE;
            w.add_out_edge(crate::block::BlockEdge {
                point: bl_id,
                flags: lab,
                reverse_index: in_slot,
            });
            w.add_in_edge(crate::block::BlockEdge {
                point: bl_id,
                flags: lab,
                reverse_index: out_slot,
            });
        }
    }

    // Ghidra: block.cc:1204 BlockGraph::forceFalseEdge
    /// Ensure the composite's out(0) is `out0` — the pre-merge out(0) of the
    /// last component, captured before identifyInternal. If out0 is one of
    /// the merged `components` (oracle: `out0->getParent() == this`,
    /// block.cc:1209), it was internalized and the composite's self edge
    /// plays its role, so require out(0) == self instead. Swaps the two out
    /// edges otherwise (FlowBlock::swapEdges, block.cc:1212-1213). The
    /// caller guards sizeOut==2 (block.cc:1769), mirroring the oracle's
    /// LowlevelError precondition.
    fn force_false_edge_composite(
        bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        out0: Option<&Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        components: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
    ) {
        let Some(out0) = out0 else { return };
        let bank = bl.read().unwrap().bank();
        let bl_id = bank.registered_id_of(bl);
        let out0_id = bank.registered_id_of(out0);
        let target_self = components.iter().any(|c| Arc::ptr_eq(c, out0));
        let need_swap = {
            let r = bl.read().unwrap();
            if r.size_out() != 2 {
                return;
            }
            match r.get_out(0) {
                Some(e) => {
                    if target_self {
                        e.point != bl_id
                    } else {
                        e.point != out0_id
                    }
                }
                None => return,
            }
        };
        if need_swap {
            bl.write().unwrap().swap_edges();
        }
    }

    // Ghidra: blockaction.cc:1148 CollapseStructure::orderLoopBodies
    /// Consume the copied back-edge labels and order the natural-loop bodies.
    /// Mirrors Ghidra's `CollapseStructure::orderLoopBodies`; label discovery
    /// already happened on the source graph before `buildCopy`.
    fn order_loop_bodies(&mut self) {
        self.loop_bodies.clear();
        // ActionBlockStructure calls installSwitchDefaults() and then
        // buildCopy() (blockaction.cc:2176-2177). BlockGraph::newBlockCopy
        // copies the permanent graph's edge labels, index, numdesc, flags,
        // and immediate dominator, while the BlockCopy constructor resets
        // visitcount to zero (block.cc:1681-1692), so the copy
        // already carries the exact structureLoops result. Ghidra's
        // CollapseStructure::orderLoopBodies only scans those copied
        // F_BACK_EDGE labels (blockaction.cc:1126-1188); recomputing
        // structureLoops here would clear and reorder them, and could erase
        // the DEFAULTSWITCH label installed immediately before buildCopy.
        //
        // Ghidra collapseAll head (blockaction.cc:1882-1884): finaltrace =
        // false; graph.clearVisitCount(); orderLoopBodies(). TraceDAG starts
        // from the cleared counts, so reset exactly where the oracle does.
        for i in 0..self.graph.get_size() {
            if let Some(b) = self.graph.get_block(i) {
                b.write().unwrap().set_visit_count(0);
            }
        }
        // Dominators are still needed elsewhere (switch-case detection,
        // LoopBody helpers), so keep them up to date.
        self.compute_dominators();
        let size = self.graph.get_size();

        // w-rc4 probe (RUDRA_BS_TRACE=1): mirror oracle collapseAll_entry
        // graph dump (block idx/addr/in/out with edge labels) for seam diffing.
        if std::env::var("RUDRA_BS_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            eprintln!("[BLOCKSTRUCT] {} collapseAll_entry nblocks={}", self.name, size);
            let addr_of = |idx: i32| -> u64 {
                match self.graph.get_block(idx as usize) {
                    Some(b) => {
                        let blk = b.read().unwrap();
                        let base = if blk.get_type() == crate::block::BlockType::Copy {
                            blk.sub_block(0)
                        } else {
                            None
                        };
                        match base {
                            Some(orig) => orig
                                .read()
                                .unwrap()
                                .get_start_addr()
                                .to_space_address()
                                .get_offset(),
                            None => blk
                                .get_start_addr()
                                .to_space_address()
                                .get_offset(),
                        }
                    }
                    None => 0,
                }
            };
            for i in 0..size {
                let Some(b) = self.graph.get_block(i) else {
                    continue;
                };
                let r = b.read().unwrap();
                let mut line = format!(
                    "[BLOCKSTRUCT]   blk#{} @{:x} ty={:?} in=",
                    r.get_index(),
                    addr_of(r.get_index()),
                    r.get_type()
                );
                for j in 0..r.size_in() {
                    if let Some(e) = r.get_in(j) {
                        line.push_str(&format!(
                            "{:x}{}{} ",
                            crate::arena::ArenaId::to_bits(e.point),
                            if r.is_back_edge_in(j) { "B" } else { "" },
                            if r.is_goto_in(j) { "G" } else { "" }
                        ));
                    }
                }
                line.push_str(" out=");
                for j in 0..r.size_out() {
                    if let Some(e) = r.get_out(j) {
                        line.push_str(&format!(
                            "{:x}{}{} ",
                            crate::arena::ArenaId::to_bits(e.point),
                            if r.is_back_edge_out(j) { "B" } else { "" },
                            if r.is_goto_out(j) { "G" } else { "" }
                        ));
                    }
                }
                eprintln!("{}", line);
            }
        }

        // Diagnostic: dominator coverage + back-edge scan (RUDRA_LOOP_DEBUG=1)
        let loop_dbg = std::env::var("RUDRA_LOOP_DEBUG")
            .map(|v| v == "1")
            .unwrap_or(false);
        if loop_dbg {
            let idom_count = self.idom.len();
            let entry = (0..size).find(|&i| {
                self.graph
                    .get_block(i)
                    .map_or(false, |b| b.read().unwrap().size_in() == 0)
            });
            // Count F_BACK_EDGE-labelled edges (the spanning-tree result).
            let mut back_edges = 0;
            let mut back_examples: Vec<(i32, i32)> = Vec::new();
            for i in 0..size {
                let block = match self.graph.get_block(i) {
                    Some(b) => b,
                    None => continue,
                };
                let b = block.read().unwrap();
                let src = b.get_index();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        let tgt = self.graph_bank().expect_index(b.get_out(slot).unwrap().point);
                        back_edges += 1;
                        if back_examples.len() < 8 {
                            back_examples.push((src, tgt));
                        }
                    }
                }
            }
            eprintln!("[LOOPDBG] {} size={} entry={:?} idom_entries={}/{} dfs_back_edges={} examples={:?}",
                self.name, size, entry, idom_count, size, back_edges, back_examples);
        }

        // Find all back-edges (via F_BACK_EDGE labels) and create loop bodies.
        // Faithful to labelLoops (blockaction.cc:1126-1142): for each block,
        // scan out-edges; a back edge `(src -> tgt)` makes `tgt` the loop
        // head and `src` a loop tail. The scan order is Ghidra's LIST
        // position order (cc:1129 `graph.getBlock(i)`); loopbody records are
        // created in that order and the later stable depth sort
        // (orderLoopBodies cc:1175) keeps creation order among equal-depth
        // loops — walk virtual_list to reproduce it.
        let vlist = self.virtual_list.clone();
        for &i in &vlist {
            let block = match self.graph.get_block(i as usize) {
                Some(b) => b,
                None => continue,
            };
            let (src_idx, back_targets): (i32, Vec<i32>) = {
                let b = block.read().unwrap();
                let src = b.get_index();
                let mut tgts = Vec::new();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        if let Some(e) = b.get_out(slot) {
                            tgts.push(self.graph_bank().expect_index(e.point));
                        }
                    }
                }
                (src, tgts)
            };
            for tgt_idx in back_targets {
                // w-rc4 probe (RUDRA_BS_TRACE=1): mirror oracle labelLoops
                // print (head/tail start addresses) for two-sided diffing.
                if std::env::var("RUDRA_BS_TRACE")
                    .map(|v| v == "1")
                    .unwrap_or(false)
                {
                    let addr_of = |idx: i32| -> u64 {
                        match self.graph.get_block(idx as usize) {
                            Some(b) => {
                                let blk = b.read().unwrap();
                                let base = if blk.get_type() == crate::block::BlockType::Copy {
                                    blk.sub_block(0)
                                } else {
                                    None
                                };
                                match base {
                                    Some(orig) => orig
                                        .read()
                                        .unwrap()
                                        .get_start_addr()
                                        .to_space_address()
                                        .get_offset(),
                                    None => blk
                                        .get_start_addr()
                                        .to_space_address()
                                        .get_offset(),
                                }
                            }
                            None => 0,
                        }
                    };
                    eprintln!(
                        "[BLOCKSTRUCT] {} labelLoops head@{:x} tail@{:x}",
                        self.name,
                        addr_of(tgt_idx),
                        addr_of(src_idx)
                    );
                }
                let body = self.collect_loop_body(tgt_idx, src_idx, size);
                if !body.is_empty() {
                    self.loop_bodies.push((tgt_idx, body));
                }
            }
        }

        // Sort by body size (smallest = innermost first)
        self.loop_bodies.sort_by_key(|(_, body)| body.len());
        eprintln!(
            "[COLLAPSE] {} orderLoopBodies: {} loops found",
            self.name,
            self.loop_bodies.len()
        );
        for (head, body) in &self.loop_bodies {
            eprintln!(
                "[COLLAPSE] {} loop head={} bodysize={}",
                self.name,
                head,
                body.len()
            );
        }

        // ---- Rich LoopBody pipeline (Ghidra blockaction.cc:1148-1188) ----
        // Build LoopBody records from the back-edges, then run the full
        // find_base / merge / label_containments / find_exit / order_tails /
        // extend / label_exit_edges pipeline. This populates self.loop_order
        // with nesting depth, exit blocks, and exit edges for nested-loop
        // structuring.
        self.run_order_loop_bodies_pipeline(size);
    }

    // RUDRA-GLUE: Rust helper splitting Ghidra CollapseStructure::orderLoopBodies (blockaction.cc:1148)
    /// Run the full Ghidra LoopBody analysis pipeline on the detected
    /// back-edges. Faithful to `CollapseStructure::orderLoopBodies`
    /// (blockaction.cc:1148-1188).
    fn run_order_loop_bodies_pipeline(&mut self, size: usize) {
        // Step 1: build LoopBody records (one per back-edge), keyed by head.
        let mut loop_order: Vec<LoopBody> = Vec::new();
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let (src_idx, back_targets): (i32, Vec<i32>) = {
                let b = block.read().unwrap();
                let src = b.get_index();
                let mut tgts = Vec::new();
                for slot in 0..b.size_out() {
                    if b.is_back_edge_out(slot) {
                        if let Some(edge) = b.get_out(slot) {
                            tgts.push(self.graph_bank().expect_index(edge.point));
                        }
                    }
                }
                (src, tgts)
            };
            for tgt in back_targets {
                if let Some(existing) = loop_order.iter_mut().find(|lb| lb.head == tgt) {
                    existing.add_tail(src_idx);
                } else {
                    loop_order.push(LoopBody::new(tgt, src_idx));
                }
            }
        }
        if loop_order.is_empty() {
            self.loop_order.clear();
            return;
        }
        // Step 2: merge identical heads (already deduped above, but run for
        // completeness — merge_identical_heads is idempotent on unique heads).
        merge_identical_heads(&mut loop_order);
        // Sort by (head index, first tail index) — Ghidra compare_ends.
        loop_order.sort_by(|a, b| {
            a.head
                .cmp(&b.head)
                .then_with(|| a.tails[0].cmp(&b.tails[0]))
        });
        // Step 3: label containments (set depth + immed_container).
        // Snapshot head list for containment checks.
        let n = loop_order.len();
        for i in 0..n {
            let body = loop_order[i].find_base(self.graph);
            // Count contained subloops.
            let mut contain: Vec<usize> = Vec::new();
            for &curblock in &body {
                if curblock == loop_order[i].head {
                    continue;
                }
                if let Some(sub_idx) = loop_order.iter().position(|lb| lb.head == curblock) {
                    if sub_idx != i {
                        contain.push(sub_idx);
                    }
                }
            }
            // Increment depth of contained subloops.
            for &sub_idx in &contain {
                loop_order[sub_idx].depth += 1;
            }
            // Set immed_container to the deepest container seen so far.
            // The oracle stores the container's LoopBody POINTER (survives
            // the step-4 depth sort); Rudra stores the container's HEAD
            // block index — unique after merge_identical_heads — so the
            // reference stays valid across the sort (BLOCKSTRUCT-COLLAPSE-
            // RESIDUAL-0001: the previous positional index went stale).
            let my_depth = loop_order[i].depth;
            let my_head = loop_order[i].head;
            for &sub_idx in &contain {
                let cur_container_head = loop_order[sub_idx].immed_container;
                let replace = if cur_container_head == -1 {
                    true
                } else {
                    // cc: labelContainments: (lb->immed_container->depth < depth)
                    match loop_order.iter().find(|lb| lb.head == cur_container_head) {
                        Some(c) => c.depth < my_depth,
                        None => true,
                    }
                };
                if replace {
                    loop_order[sub_idx].immed_container = my_head;
                }
            }
            clear_marks(&body, self.graph);
        }
        // Step 4: sort by nesting depth (deepest first). Ghidra uses stable
        // sort on depth.
        loop_order.sort_by(|a, b| b.depth.cmp(&a.depth));
        // Step 5: for each loop, find_base / find_exit / order_tails / extend /
        // label_exit_edges. find_exit needs its container's (head, tails);
        // resolve via the head-keyed snapshot (the oracle reads the
        // immed_container pointer here).
        let containers_by_head: std::collections::HashMap<i32, Vec<i32>> = loop_order
            .iter()
            .map(|lb| (lb.head, lb.tails.clone()))
            .collect();
        for lb in loop_order.iter_mut() {
            let mut body = lb.find_base(self.graph);
            let container = if lb.immed_container != -1 {
                containers_by_head.get(&lb.immed_container).cloned()
            } else {
                None
            };
            lb.find_exit(&body, self.graph, container.map(|t| (lb.immed_container, t)));
            lb.order_tails(self.graph);
            lb.extend(&mut body, self.graph);
            lb.label_exit_edges(&body, self.graph);
            clear_marks(&body, self.graph);
        }
        // Store into the VecDeque for updateLoopBody-style iteration.
        self.loop_order = loop_order.into_iter().collect();
        if std::env::var("RUDRA_IRRED_DBG")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            for (i, lb) in self.loop_order.iter().enumerate() {
                eprintln!(
                    "[IRRED] {} loop_order[{}] head={} tails={:?} depth={} exit={} exit_edges={:?}",
                    self.name,
                    i,
                    lb.head,
                    lb.tails,
                    lb.depth,
                    lb.exit_block,
                    lb.exit_edges
                        .iter()
                        .map(|e| (e.from_idx, e.to_idx))
                        .collect::<Vec<_>>()
                );
            }
        }
        eprintln!(
            "[COLLAPSE] {} LoopBody pipeline: {} loops, depths={}",
            self.name,
            self.loop_order.len(),
            self.loop_order
                .iter()
                .map(|lb| lb.depth)
                .collect::<Vec<_>>()
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    // Ghidra: blockaction.hh:46 LoopBody::collectLoopBody
    /// Collect all blocks in a natural loop body.
    /// Body = {head} + all blocks that can reach tail without going through head.
    fn collect_loop_body(&self, head: i32, tail: i32, size: usize) -> Vec<i32> {
        let mut body = std::collections::HashSet::new();
        body.insert(head);
        body.insert(tail);
        // BFS backward from tail, stopping at head
        let mut queue = vec![tail];
        while let Some(cur) = queue.pop() {
            if cur == head {
                continue;
            }
            let i = cur as usize;
            if i >= size {
                continue;
            }
            if let Some(blk) = self.graph.get_block(i) {
                let b = blk.read().unwrap();
                for slot in 0..b.size_in() {
                    if let Some(edge) = b.get_in(slot) {
                        let pred_idx = self.graph_bank().expect_index(edge.point);
                        if body.insert(pred_idx) {
                            queue.push(pred_idx);
                        }
                    }
                }
            }
        }
        body.into_iter().collect()
    }

    // Ghidra: blockaction.hh:46 LoopBody::isInLoopBody
    /// Check if a block index is inside any identified loop body.
    fn is_in_loop_body(&self, idx: i32) -> bool {
        self.loop_bodies.iter().any(|(_, body)| body.contains(&idx))
    }

    // Ghidra: blockaction.hh:46 LoopBody::structureLoopsFirst
    /// Structure detected WhileDo loops (innermost-first) BEFORE phase1 runs,
    /// so loop heads are preserved as BlockWhileDo instead of being consumed
    /// by phase1's collapse_conditions. Only the clean WhileDo pattern
    /// (head=CBR, body=Basic/Copy with single back-edge to head) is structured.
    fn structure_loops_first(&mut self) {
        if self.loop_bodies.is_empty() {
            return;
        }
        let loops = self.loop_bodies.clone();
        for (head_idx, _body) in &loops {
            let head_idx = *head_idx;
            let hi = head_idx as usize;
            if hi >= self.graph.get_size() {
                continue;
            }
            let head_blk = match self.graph.get_block(hi) {
                Some(b) => b,
                None => continue,
            };
            let cond_idx = {
                let h = head_blk.read().unwrap();
                if self.is_consumed(h.get_index()) {
                    continue;
                }
                if !matches!(
                    h.get_type(),
                    crate::block::BlockType::Basic | crate::block::BlockType::Copy
                ) {
                    continue;
                }
                if h.size_out() != 2 {
                    continue;
                }
                let has_cbranch = h.get_ops().last().map_or(false, |o| {
                    o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_CBRANCH
                });
                if !has_cbranch {
                    continue;
                }
                h.get_index()
            };
            let is_dowhile = {
                let h = head_blk.read().unwrap();
                (0..h.size_out()).any(|s| {
                    h.get_out(s)
                        .map_or(false, |e| self.graph_bank().expect_index(e.point) == cond_idx)
                })
            };
            if is_dowhile {
                continue;
            }
            let body_info = {
                let h = head_blk.read().unwrap();
                let mut found = None;
                for s in 0..h.size_out() {
                    if let Some(e) = h.get_out(s) {
                        // (W2) shadow reads: body_idx via the bank index
                        // shadow; the loops_back scan takes ONE peer guard
                        // for the deep get_out walk (block.hh:160/312).
                        let bank = self.graph_bank();
                        let body_idx = bank.expect_index(e.point);
                        if body_idx == cond_idx {
                            continue;
                        }
                        let body_blk = bank.expect_arc(e.point);
                        let loops_back = {
                            let bd = body_blk.read().unwrap();
                            (0..bd.size_out()).any(|bs| {
                                bd.get_out(bs).map_or(false, |be| {
                                    self.graph_bank().expect_index(be.point) == cond_idx
                                })
                            })
                        };
                        if loops_back {
                            found = Some((body_blk, body_idx, e.point));
                            break;
                        }
                    }
                }
                found
            };
            if let Some((body_blk, body_idx, body_point)) = body_info {
                // (W2) shadow reads: type/flags/index all guard-served
                // (block.hh:184/165/160) — no peer lock for the ok-check.
                let bank = self.graph_bank();
                let body_ok = matches!(
                    bank.btype_of(body_point),
                    Some(crate::block::BlockType::Basic) | Some(crate::block::BlockType::Copy)
                ) && bank.expect_flags(body_point) & crate::block::block_flags::CASE_BODY == 0
                    && !self.is_consumed(body_idx);
                if !body_ok {
                    continue;
                }
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockWhileDo {
                        owner_bank: std::sync::Weak::new(),
                        bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                        index: cond_idx,
                        condition: head_blk.clone(),
                        body: body_blk.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                        for_init: None,
                        for_iter: None,
                        initialize_op: None,
                        iterate_op: None,
                        loop_def: None,
                        overflow_syntax: false,
                    }));
                self.identify_internal(&while_block, &[body_idx], hi);
                self.structure_change_count += 1;
                eprintln!(
                    "[COLLAPSE] {} structure_loops_first WhileDo head={} body={}",
                    self.name, cond_idx, body_idx
                );
            }
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::isStructuredChild
    /// Check if a block index is a sub-component of any structured block
    /// (BlockCondition.first/second, BlockIf.condition/if_body/else_body,
    /// BlockWhileDo.condition/body, etc.). These blocks should not be
    /// processed by interleaved rules or goto cascade.
    fn is_structured_child(&self, idx: i32, size: usize) -> bool {
        use crate::block::{BlockCondition, BlockDoWhile, BlockIf, BlockList, BlockWhileDo};
        for i in 0..size {
            let blk = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let b = blk.read().unwrap();
            match b.get_type() {
                crate::block::BlockType::Condition => {
                    if let Some(bc) = b.as_any().downcast_ref::<BlockCondition>() {
                        if bc.first.read().unwrap().get_index() == idx {
                            return true;
                        }
                        if bc.second.read().unwrap().get_index() == idx {
                            return true;
                        }
                    }
                }
                crate::block::BlockType::If => {
                    if let Some(bi) = b.as_any().downcast_ref::<BlockIf>() {
                        if bi.condition.read().unwrap().get_index() == idx {
                            return true;
                        }
                        if bi.if_body.read().unwrap().get_index() == idx {
                            return true;
                        }
                        if let Some(ref eb) = bi.else_body {
                            if eb.read().unwrap().get_index() == idx {
                                return true;
                            }
                        }
                    }
                }
                crate::block::BlockType::WhileDo => {
                    if let Some(wd) = b.as_any().downcast_ref::<BlockWhileDo>() {
                        if wd.condition.read().unwrap().get_index() == idx {
                            return true;
                        }
                        if wd.body.read().unwrap().get_index() == idx {
                            return true;
                        }
                    }
                }
                crate::block::BlockType::DoWhile => {
                    if let Some(dw) = b.as_any().downcast_ref::<BlockDoWhile>() {
                        if dw.condition.read().unwrap().get_index() == idx {
                            return true;
                        }
                    }
                }
                crate::block::BlockType::List => {
                    if let Some(bl) = b.as_any().downcast_ref::<BlockList>() {
                        for child in &bl.children {
                            if child.read().unwrap().get_index() == idx {
                                return true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    // Ghidra: blockaction.cc:1108 CollapseStructure::clipExtraRoots
    /// Ghidra's clipExtraRoots (blockaction.cc:1108-1121): find distinct
    /// control-flow roots (sizeIn==0, index > 0 — the canonical root 0 is
    /// skipped), and for the subset of blocks ONLY reachable from that root
    /// (onlyReachableFromRoot cc:1041-1067), mark their exiting edges as
    /// goto via setGotoBranch (markExitsAsGotos cc:1070-1090). Handles
    /// irreducible cross-over edges. Returns true if any cross-over edges
    /// were found (counted per EDGE to a non-body target — Ghidra re-counts
    /// already-goto edges, which keeps the collapseAll loop progressing
    /// while try_rule_goto consumes the marked blocks).
    fn clip_extra_roots(&mut self) -> bool {
        // cc:1111 `for(i=1;i<graph.getSize();++i)` — list position order,
        // skipping position 0 (the canonical root). First cross-over root
        // wins and returns, so the ORDER decides which disjoint subset gets
        // its exits marked. Walk virtual_list (Ghidra's mutating list),
        // skipping the first entry.
        let vlist = self.virtual_list.clone();
        for &slot in vlist.iter().skip(1) {
            let root_idx = slot;
            let root_blk = match self.graph.get_block(root_idx as usize) {
                Some(b) => b,
                None => continue,
            };
            {
                let r = root_blk.read().unwrap();
                if r.size_in() != 0 {
                    continue;
                }
                // cc:1080: no type gate — Ghidra processes ANY sizeIn==0
                // block, including structured composites (a wrapped
                // BlockGoto/BlockList can be a cross-over root).
            }
            // cc:1041-1067 onlyReachableFromRoot: collect blocks reachable
            // only from root (visitcount reaches sizeIn exactly).
            let mut body: Vec<i32> = vec![root_idx];
            let mut in_body: std::collections::HashSet<i32> = std::collections::HashSet::new();
            in_body.insert(root_idx);
            let mut visit_count: std::collections::HashMap<i32, i32> =
                std::collections::HashMap::new();
            let mut i = 0;
            while i < body.len() {
                let cur = body[i];
                i += 1;
                let cur_blk = match self.graph.get_block(cur as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let c = cur_blk.read().unwrap();
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        let nxt = self.graph_bank().expect_index(e.point);
                        if in_body.contains(&nxt) {
                            continue;
                        }
                        let count = visit_count.entry(nxt).or_insert(0);
                        *count += 1;
                        // (g) guard-shadow: pure sizeIn guard — bank cell read.
                        let nxt_in = self.graph_bank().expect_size_in(e.point) as i32;
                        if *count == nxt_in {
                            in_body.insert(nxt);
                            body.push(nxt);
                        }
                    }
                }
            }
            // cc:1070-1090 markExitsAsGotos: every out-edge of a body block
            // to a non-body target is marked goto (setGotoBranch semantics);
            // count is per edge.
            let mut changecount = 0;
            let mut mark_jobs: Vec<(i32, usize)> = Vec::new();
            for &bidx in &body {
                let bb = match self.graph.get_block(bidx as usize) {
                    Some(b) => b,
                    None => continue,
                };
                let b = bb.read().unwrap();
                for slot in 0..b.size_out() {
                    if let Some(e) = b.get_out(slot) {
                        let t = self.graph_bank().expect_index(e.point);
                        if in_body.contains(&t) {
                            continue;
                        }
                        mark_jobs.push((bidx, slot));
                    }
                }
            }
            for (bidx, slot) in mark_jobs {
                if let Some(bb) = self.graph.get_block(bidx as usize) {
                    // Full setGotoBranch (block.cc:305-313): edge label
                    // f_goto_edge mirrored on both halves + interior flags,
                    // same as selectGoto's marking.
                    let blk = bb.clone();
                    self.set_goto_branch_on_block(&blk, slot);
                    changecount += 1;
                }
            }
            if changecount > 0 {
                eprintln!(
                    "[COLLAPSE] {} clipExtraRoots: root={} body={} gotos={}",
                    self.name,
                    root_idx,
                    body.len(),
                    changecount
                );
                self.structure_change_count += changecount;
                return true;
            }
        }
        false
    }

    // Ghidra: blockaction.hh:46 LoopBody::computeDominators
    fn compute_dominators(&mut self) {
        self.idom.clear();
        let size = self.graph.get_size();
        if size == 0 {
            return;
        }

        // Find entry block (size_in == 0)
        let entry = (0..size).find(|&i| {
            self.graph
                .get_block(i)
                .map_or(false, |b| b.read().unwrap().size_in() == 0)
        });
        let entry = match entry {
            Some(e) => e,
            None => return,
        };

        // Build predecessor lists
        let mut preds: Vec<Vec<i32>> = vec![Vec::new(); size];
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let b = block.read().unwrap();
            for slot in 0..b.size_out() {
                if let Some(edge) = b.get_out(slot) {
                    let tgt = self.graph_bank().expect_index(edge.point) as usize;
                    if tgt < size {
                        preds[tgt].push(i as i32);
                    }
                }
            }
        }

        // Initialize: idom[entry] = entry, all others = -1 (undefined)
        let mut idom_arr: Vec<i32> = vec![-1; size];
        idom_arr[entry] = entry as i32;

        // Iterative fixpoint
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..size {
                if i == entry {
                    continue;
                }
                // Find first processed predecessor
                let mut new_idom = -1i32;
                for &p in &preds[i] {
                    if idom_arr[p as usize] != -1 {
                        if new_idom == -1 {
                            new_idom = p;
                        } else {
                            // intersect(p, new_idom)
                            let mut b1 = p;
                            let mut b2 = new_idom;
                            while b1 != b2 {
                                while b1 > b2 {
                                    b1 = idom_arr[b1 as usize];
                                    if b1 == -1 {
                                        break;
                                    }
                                }
                                while b2 > b1 {
                                    b2 = idom_arr[b2 as usize];
                                    if b2 == -1 {
                                        break;
                                    }
                                }
                                if b1 == -1 || b2 == -1 {
                                    break;
                                }
                            }
                            new_idom = if b1 != -1 { b1 } else { new_idom };
                        }
                    }
                }
                if new_idom != -1 && new_idom != idom_arr[i] {
                    idom_arr[i] = new_idom;
                    changed = true;
                }
            }
        }

        for (i, &d) in idom_arr.iter().enumerate() {
            if d != -1 && d != i as i32 {
                self.idom.insert(i as i32, d);
            }
        }
    }

    // RUDRA-GLUE: dominator lookup over the structuring graph's block
    // indices; Ghidra has no LoopBody::dominatesIdx (blockaction.hh:46 is
    // the LoopBody class decl with no such member) — Rudra computes
    // idoms locally to back refresh_switch_cases case-body detection.
    /// Check if block index `a` dominates block index `b`.
    fn dominates_idx(&self, a: i32, b: i32) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        let mut steps = 0;
        while let Some(&d) = self.idom.get(&cur) {
            if d == a {
                return true;
            }
            cur = d;
            steps += 1;
            if steps > 10000 {
                break;
            } // safety
        }
        false
    }

    // RUDRA-GLUE: interleaved-rule case-body bookkeeping; Ghidra has no
    // LoopBody::refreshSwitchCases and no f_case_body flag (block.hh:88-106
    // enum tops out at f_duplicate_block=0x40000) — this tracks Rudra's
    // switch_case_indices so interleaved rules avoid pulling case labels
    // out of switch bodies. Clear/set must use clear_flags/set_flags
    // (FlowBlock::clearFlag/setFlag semantics: `&= ~fl` / `|= fl`).
    /// Collect indices of all switch case body blocks. Scans both BlockSwitch
    /// nodes and CBRANCH cascade chains (which produce switch-like structures
    /// using BlockIf nodes). Interleaved rules use this to avoid pulling case
    /// labels out of switch bodies.
    fn refresh_switch_cases(&mut self) {
        self.switch_case_indices.clear();
        self.compute_dominators(); // Build dominator tree for precise case body detection
        let size = self.graph.get_size();
        // Clear CASE_BODY flag on all blocks first
        for i in 0..size {
            if let Some(blk) = self.graph.get_block(i) {
                let mut b = blk.write().unwrap();
                b.clear_flags(crate::block::block_flags::CASE_BODY);
            }
        }
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let b = block.read().unwrap();
            let bt = b.get_type();
            // BlockSwitch: collect its case + default bodies
            if bt == crate::block::BlockType::Switch {
                if let Some(bs) = b.as_any().downcast_ref::<crate::block::BlockSwitch>() {
                    for case in &bs.cases {
                        self.switch_case_indices
                            .insert(case.read().unwrap().get_index());
                    }
                    if let Some(ref dc) = bs.default_case {
                        self.switch_case_indices
                            .insert(dc.read().unwrap().get_index());
                    }
                }
            }
            drop(b);
            // CBRANCH cascade: detect by checking if this block is the head of a
            // chain of CBRANCH blocks where the taken target (out edge 1) is a
            // case body. Mark all such taken targets.
            // (This catches the cascade switches that collapse_cbranch_cascades
            // couldn't fully merge, or that were created as BlockIf chains.)
        }
        // Detect CBRANCH cascade chains: a sequence of CBRANCH blocks connected
        // via fallthrough (out[0]), where each has a taken target (out[1]).
        // A chain of 2+ such blocks is a cascade switch; all taken targets are
        // case bodies and must not be structurally extracted.
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }
            if b.size_out() != 2 {
                continue;
            }
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |o| {
                o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }
            // Check if fallthrough (out[0]) leads to another CBRANCH (cascade)
            let ft_point = match b.get_out(0) {
                Some(e) => e.point,
                None => {
                    continue;
                }
            };
            let fallthrough = self.graph_bank().expect_arc(ft_point);
            // (W2) shadow read: the sizeOut guard is bank-served
            // (block.hh:312); only the ops probe takes the peer lock.
            let ft_is_cbranch = if self.graph_bank().expect_size_out(ft_point) != 2 {
                false
            } else {
                let ft_ops = fallthrough.read().unwrap().get_ops();
                ft_ops.last().map_or(false, |o| {
                    o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                })
            };
            if !ft_is_cbranch {
                continue;
            }
            // This is a cascade head. Walk the chain and mark all taken targets.
            let mut current = block.clone();
            let mut visited = std::collections::HashSet::new();
            loop {
                let cur_idx = current.read().unwrap().get_index();
                if !visited.insert(cur_idx) {
                    break;
                } // cycle guard
                let c = current.read().unwrap();
                if c.size_out() != 2 {
                    break;
                }
                let c_ops = c.get_ops();
                let c_has_cbranch = c_ops.last().map_or(false, |o| {
                    o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                });
                if !c_has_cbranch {
                    break;
                }
                // Mark taken target (out[1]) as a case body
                if let Some(taken_edge) = c.get_out(1) {
                    let tidx = self.graph_bank().expect_index(taken_edge.point);
                    self.switch_case_indices.insert(tidx);
                    // CASE_BODY flag set after the loop to avoid write-in-read deadlock
                }
                // Follow fallthrough (out[0])
                let next = match c.get_out(0) {
                    Some(e) => self.graph_bank().expect_arc(e.point),
                    None => break,
                };
                drop(c);
                current = next;
            }
        }
        // Dominator-based case body expansion: for each case body, add all
        // blocks it dominates (the case body sub-tree). This is precise —
        // only blocks truly inside the case body (on all paths from case entry)
        // are marked, unlike BFS which over-marks through fallthrough chains.
        let case_bodies: Vec<i32> = self.switch_case_indices.iter().copied().collect();
        for blk_idx in 0..size as i32 {
            // Check if this block is dominated by any case body
            for &case_idx in &case_bodies {
                if self.dominates_idx(case_idx, blk_idx) {
                    self.switch_case_indices.insert(blk_idx);
                    break;
                }
            }
        }
        // Set CASE_BODY flag on all collected case body blocks (batch, no
        // nested lock issues since we iterate by index)
        for &idx in &self.switch_case_indices {
            let i = idx as usize;
            if i < size {
                if let Some(blk) = self.graph.get_block(i) {
                    let mut b = blk.write().unwrap();
                    let new_flags = b.get_flags() | crate::block::block_flags::CASE_BODY;
                    b.set_flags(new_flags);
                }
            }
        }
    }

    // Ghidra: block.cc:940 BlockGraph::identifyInternal
    /// Ghidra's identifyInternal: collapse consumed blocks into a structured block.
    /// Faithful port of BlockGraph::identifyInternal + selfIdentify (block.cc:940, 895).
    /// Steps:
    /// 1. Install new_block at install_idx (replaces the cond block).
    /// 2. self_identify: for each consumed block, copy its boundary edges
    ///    (edges to/from non-consumed blocks) onto new_block, and rewrite
    ///    external blocks' edges to point to new_block. This gives new_block
    ///    correct size_in/size_out so subsequent rules can match against it.
    /// 3. Dedup new_block's edges.
    /// 4. Strip each component's external edge halves (Ghidra's replace*Edge
    ///    half-deletes, block.cc:160-191, move them onto the composite) and
    ///    record the containment in absorbed_into (Ghidra: addBlock sets the
    ///    component's `parent` to the composite, block.hh:78 / block.cc:873).
    ///    Components keep their component-to-component (internal) edges and
    ///    are NEVER flagged f_dead — Ghidra's identifyInternal (block.cc:940-
    ///    963) sets no flag on them; f_dead is exclusively Funcdata's dead
    ///    basic-block removal (funcdata_block.cc:333/370). The equivalent of
    ///    Ghidra's incremental `list = newlist` compaction (block.cc:953-960)
    ///    is the absorbed_into membership test (see is_consumed).
    pub fn identify_internal(
        &mut self,
        new_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        consumed_indices: &[i32],
        install_idx: usize,
    ) {
        let size = self.graph.get_size();
        // (BLOCKSTRUCT2) membership probe = linear scan of the consumed
        // slice (oracle form: setMark on the nodes themselves, block.cc:
        // 944-952 — zero allocation; the consumed sets are small (2-6
        // entries typical) and the previous std HashSet cost a RandomState
        // build + allocation + SipHash per fire, ~14K fires on the giant
        // function).
        let is_consumed_idx = |idx: i32| consumed_indices.contains(&idx);
        // Register the composite FIRST: every id minted below (boundary
        // pushes, external rewrites) must resolve through the graph bank in
        // the SAME pass — deferring registration to the pass-boundary adopt
        // scan would hand those sites SENTINEL ids (idempotent when the
        // caller already adopted).
        self.graph.bank.adopt(new_block);
        // PERF-ARENA-FLIP-0001 (f) step 2: one snapshot view spans the whole
        // identify — the entry adopt above is the ONLY publish on this path
        // (the later adopts are idempotent no-ops on already-registered
        // members, and set_block_index writes the in-place index shadow
        // without publishing), so every read below through `bank` is
        // zero-lock and value-identical to the per-read form. The hoisted
        // `new_point_id` replaces the per-rewrite-call identity lookup (the
        // (e)-handoff-① surface: these two rewrites carried ~300M lock
        // acquisitions on the giant function).
        let bank = self.graph.bank.hold();
        let new_point_id = self.graph.bank.registered_id_of(new_block);

        // --- selfIdentify: capture boundary edges BEFORE overwriting install_idx ---
        // Ghidra's selfIdentify reads the consumed nodes' edges while they still
        // exist. We must read the cond block (at install_idx) before replacing it
        // with new_block, so capture all boundary edges first.
        let mut new_in: Vec<crate::block::BlockEdge> = Vec::new();
        let mut new_out: Vec<crate::block::BlockEdge> = Vec::new();
        // External blocks whose edge lists were (or will be) retargeted onto
        // new_block — deduped once at the end, mirroring the external half of
        // Ghidra selfIdentify's final dedup() (block.cc:930).
        let mut touched: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        // (IDENTIFY) oracle-form peer retarget sets for the install block's
        // external boundary — selfIdentify (block.cc:902-929) walks each
        // component's intothis/outofthis and replace*Edge's exactly the
        // adjacent peers; the reciprocal halves of these edges are the ONLY
        // graph members whose edge lists can point at install_idx (edges are
        // paired), which is precisely the set the former 0..size sweep
        // matched. Sources of install's external IN edges (their OUT halves
        // get replaceOutEdge'd onto the composite) and targets of install's
        // external OUT edges (their IN halves get replaceInEdge'd).
        let mut install_ext_sources: Vec<crate::arena::BlockId> = Vec::new();
        let mut install_ext_targets: Vec<crate::arena::BlockId> = Vec::new();

        // Capture external in-edges of the install_idx block (cond/head).
        // These are in-edges whose source is NOT in consumed_set AND NOT the
        // install_idx block itself (self-loop) AND NOT the new_block (avoid
        // double-counting). Without this, WhileDo loops whose head was at
        // install_idx become unreachable (only self-loop preds remain).
        // NOTE: do NOT capture out-edges of install_idx here — the head's
        // out-edges go to consumed clauses (internal) or merge blocks (already
        // captured via the consumed blocks' boundary out-edges). Capturing them
        // here would double-count and break httpd.
        if install_idx < size {
            if let Some(cb) = self.graph.get_block(install_idx) {
                let c = cb.read().unwrap();
                for slot in 0..c.size_in() {
                    if let Some(e) = c.get_in(slot) {
                        // (W2) shadow read: src_idx via the bank index shadow
                        // (block.hh:160) — the pre-W2 try_read guard's only
                        // failure mode was same-thread lock recursion, which
                        // the shadow form cannot hit; Ghidra reads the index
                        // field directly (block.cc:907 `otherbl->parent`).
                        let src_idx = bank.expect_index(e.point);
                        // Exclude: consumed blocks, install_idx itself (self-loop),
                        // and the new_block (not yet installed, but guard anyway).
                        if !is_consumed_idx(src_idx) && src_idx != install_idx as i32 {
                            // cc:924 replaceInEdge keeps the peer's edge label:
                            // BlockEdge(this, outofthis[num].label, num). The
                            // inherited in-edge carries the same half's flags.
                            new_in.push(crate::block::BlockEdge {
                                point: e.point,
                                flags: e.flags,
                                reverse_index: -1,
                            });
                            // (IDENTIFY) oracle-form peer retarget set: Ghidra's
                            // selfIdentify walks the component's intothis and
                            // replaceOutEdge's exactly these external sources
                            // (block.cc:905-915) — it never scans the whole
                            // graph. Recorded here so the install swap below
                            // rewrites the same peer set without the O(size)
                            // sweep (the sweep was the Rudra slot-model's
                            // blanket compensation, ~1200 slots x 2 write
                            // locks per fire on the giant function).
                            install_ext_sources.push(e.point);
                        }
                    }
                }
            }
        }

        // Capture the install block's external OUT edges too (Ghidra: the
        // install block is a consumed node; its boundary outs belong to the
        // new component — e.g. a WhileDo head's false-exit). Skipping them
        // (the old "do NOT capture out-edges of install_idx" note) stranded
        // the exit edge and re-shaped loops as infinite loops.
        if install_idx < size {
            if let Some(cb) = self.graph.get_block(install_idx) {
                let c = cb.read().unwrap();
                let mut install_ext_out = false;
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        // (W2) shadow read: dst_idx via the bank index shadow.
                        let dst_idx = bank.expect_index(e.point);
                        if !is_consumed_idx(dst_idx) && dst_idx != install_idx as i32 {
                            // cc:910 replaceOutEdge keeps the peer's edge label
                            // (block.cc:188 BlockEdge(this, outofthis[num].label,
                            // num) on the in-half) — flags carry over.
                            new_out.push(crate::block::BlockEdge {
                                point: e.point,
                                flags: e.flags,
                                reverse_index: -1,
                            });
                            install_ext_out = true;
                            // (IDENTIFY) oracle-form peer retarget set: the
                            // external targets of the install block's out
                            // edges, replaceInEdge'd by selfIdentify
                            // (block.cc:916-927) — see the in-half note above.
                            install_ext_targets.push(e.point);
                        }
                    }
                }
                // cc:925-926: the install block is a component in Ghidra's
                // -nodes- set, so selfIdentify's `if (mybl->isSwitchOut())
                // setFlag(f_switch_out)` applies to it as well — e.g. an
                // inf_loop absorbing a BRANCHIND dispatch block (whose case
                // edges are external out edges) must keep the composite a
                // switch-out, or downstream rules mis-structure the case
                // edges as plain decision edges.
                if install_ext_out && c.get_flags() & crate::block::block_flags::SWITCH_OUT != 0 {
                    new_block
                        .write()
                        .unwrap()
                        .set_flags(crate::block::block_flags::SWITCH_OUT);
                }
            }
        }

        for &c_idx in consumed_indices {
            let ci = c_idx as usize;
            if ci >= size {
                continue;
            }
            // The install block is captured by the install-capture phases
            // above; factories that consume the block at its own install
            // slot (newBlockGoto/newBlockDoWhile pass nodes={bl} with bl at
            // install_idx) must not walk it twice — a second walk would
            // duplicate every boundary edge, and the duplicate's unpaired
            // reverse_index then makes the paired dedup half-delete a peer
            // slot by stale index (halfDeleteOutEdge pops the peer's LAST
            // edge when fed a -1 slot).
            if ci == install_idx {
                continue;
            }
            // cc:951: ident->flags |= ((*iter)->flags & (f_interior_gotoout |
            // f_interior_gotoin)) — the composite inherits interior-goto
            // marks from every consumed component.
            {
                if let Some(cb) = self.graph.get_block(ci) {
                    let cf = cb.read().unwrap().get_flags()
                        & (crate::block::block_flags::INTERIOR_GOTOOUT
                            | crate::block::block_flags::INTERIOR_GOTOIN);
                    if cf != 0 {
                        new_block.write().unwrap().set_flags(cf);
                    }
                }
            }
            // Collect this consumed block's boundary edges.
            // IN-edges: source not in consumed set → boundary incoming.
            let (in_boundary, out_boundary, c_switch_out): (
                Vec<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, u32)>,
                Vec<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, u32)>,
                bool,
            ) = {
                let cb = match self.graph.get_block(ci) {
                    Some(b) => b,
                    None => continue,
                };
                let c = cb.read().unwrap();
                let mut ib = Vec::new();
                let mut ob = Vec::new();
                for slot in 0..c.size_in() {
                    if let Some(e) = c.get_in(slot) {
                        // (W2) shadow read: src_idx via the bank index shadow.
                        let src_idx = bank.expect_index(e.point);
                        // Ghidra selfIdentify: the install block is part of
                        // the consumed node set (identifyInternal's -nodes-),
                        // so edges between it and other consumed blocks are
                        // INTERNAL to the new component.
                        if !is_consumed_idx(src_idx) && src_idx != install_idx as i32 {
                            ib.push((bank.expect_arc(e.point), e.flags));
                        }
                    }
                }
                for slot in 0..c.size_out() {
                    if let Some(e) = c.get_out(slot) {
                        // (W2) shadow read: dst_idx via the bank index shadow.
                        let dst_idx = bank.expect_index(e.point);
                        if !is_consumed_idx(dst_idx) && dst_idx != install_idx as i32 {
                            ob.push((bank.expect_arc(e.point), e.flags));
                        }
                    }
                }
                let c_switch_out = c.get_flags() & crate::block::block_flags::SWITCH_OUT != 0;
                (ib, ob, c_switch_out)
            };
            // cc:925-926 (selfIdentify's outofthis loop): `if
            // (mybl->isSwitchOut()) setFlag(f_switch_out);` — inside the
            // external-edge branch, i.e. a component that is itself a
            // switch dispatch (BRANCHIND, block.cc:2287) AND has at least
            // one EXTERNAL out edge propagates f_switch_out to the
            // composite. A fully-internal dispatch does not.
            if c_switch_out && !out_boundary.is_empty() {
                new_block
                    .write()
                    .unwrap()
                    .set_flags(crate::block::block_flags::SWITCH_OUT);
            }
            // Add boundary edges to new_block (record the external block).
            // Labels carry over per replaceInEdge/replaceOutEdge (block.cc:172,
            // 188). Duplicates are NOT collapsed here: the oracle's selfIdentify
            // pushes one composite half per redirected peer slot and collapses
            // them only in the final paired dedup() (block.cc:930) — see the
            // dedup note below identify_internal.
            for (src, fl) in &in_boundary {
                new_in.push(crate::block::BlockEdge {
                    point: self.graph.bank.registered_id_of(src),
                    flags: *fl,
                    reverse_index: -1,
                });
            }
            for (dst, fl) in &out_boundary {
                new_out.push(crate::block::BlockEdge {
                    point: self.graph.bank.registered_id_of(dst),
                    flags: *fl,
                    reverse_index: -1,
                });
            }
            // Rewrite external blocks' edges to point to new_block, mirroring
            // Ghidra selfIdentify's replaceOutEdge/replaceInEdge (block.cc:
            // 910-912, 922-924). This keeps parent CBRANCH out-edges and
            // merge-block in-edges consistent when their clause/source is
            // consumed elsewhere. Type-agnostic (Ghidra's edge arrays live on
            // every FlowBlock); the previous BlockBasic-only rewrite left
            // structured blocks with stale edges to consumed components,
            // inflating sizeIn/sizeOut for downstream rules.
            for (src, _) in &in_boundary {
                let s_any = src.clone();
                // Avoid self-loop: don't rewrite new_block's own edge
                if std::sync::Arc::ptr_eq(&s_any, new_block) {
                    continue;
                }
                touched.push(s_any.clone());
                rewrite_out_edges_to_idx(&bank, &s_any, c_idx, new_point_id);
            }
            for (dst, _) in &out_boundary {
                let d_any = dst.clone();
                if std::sync::Arc::ptr_eq(&d_any, new_block) {
                    continue;
                }
                touched.push(d_any.clone());
                rewrite_in_edges_to_idx(&bank, &d_any, c_idx, new_point_id);
            }
        }

        // NOTE (block.cc:930 selfIdentify's dedup): the oracle does NOT
        // deduplicate the inherited edges at capture time. Each redirected
        // peer slot contributes one composite half, so the composite may
        // legitimately hold duplicate edges to one external block (e.g. a
        // proper-if where BOTH the cond's false branch and the clause's exit
        // target the merge block). Those duplicates are collapsed ONLY by
        // the paired dedup() below, whose eliminateInDups/eliminateOutDups
        // half-delete the peer's duplicate slot together with the composite's
        // duplicate half. The previous unilateral `retain` here under-counted
        // the composite side, so the peer's later paired dedup deleted the
        // composite's ONLY remaining edge — the root cause of composites
        // ending with sizeOut==0, truncated TraceDAG walks and the
        // "selectGoto exhausted" dead-loop (TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001).

        // Install the collected boundary edges onto new_block (downcast to a
        // concrete block type that owns incoming/outgoing vectors).
        {
            let mut nb = new_block.write().unwrap();
            let nref = nb.as_any_mut();
            // BlockIf / BlockList / BlockWhileDo / BlockDoWhile / BlockGoto / BlockSwitch
            // all expose incoming/outgoing via as_any_mut. Try the common ones.
            if let Some(bif) = nref.downcast_mut::<crate::block::BlockIf>() {
                bif.incoming = new_in;
                bif.outgoing = new_out;
            } else if let Some(blist) = nref.downcast_mut::<crate::block::BlockList>() {
                blist.incoming = new_in;
                blist.outgoing = new_out;
            } else if let Some(bwd) = nref.downcast_mut::<crate::block::BlockWhileDo>() {
                bwd.incoming = new_in;
                bwd.outgoing = new_out;
            } else if let Some(bdw) = nref.downcast_mut::<crate::block::BlockDoWhile>() {
                bdw.incoming = new_in;
                bdw.outgoing = new_out;
            } else if let Some(bgt) = nref.downcast_mut::<crate::block::BlockGoto>() {
                bgt.incoming = new_in;
                bgt.outgoing = new_out;
            } else if let Some(bcond) = nref.downcast_mut::<crate::block::BlockCondition>() {
                bcond.incoming = new_in;
                bcond.outgoing = new_out;
            } else if let Some(binf) = nref.downcast_mut::<crate::block::BlockInfLoop>() {
                binf.incoming = new_in;
                binf.outgoing = new_out;
            } else if let Some(bmg) = nref.downcast_mut::<crate::block::BlockMultiGoto>() {
                // Ghidra newBlockMultiGoto (block.cc:1738): identifyInternal(
                // ret,[bl]) runs the same selfIdentify edge transfer as every
                // other composite — the multigoto inherits the wrapped
                // switch block's external in/out boundary edges (and its
                // f_switch_out via the cc:925-926 propagation above), which
                // ruleBlockSwitch (cc:1652) and checkSwitchSkips then read.
                bmg.incoming = new_in;
                bmg.outgoing = new_out;
            } else if let Some(bsw) = nref.downcast_mut::<crate::block::BlockSwitch>() {
                // Ghidra newBlockSwitch (block.cc:1913): identifyInternal(ret,cs)
                // runs the same selfIdentify edge transfer as every other
                // composite — the switch block's incoming/outgoing are the
                // dispatch's external in-edge and the case/exit boundary
                // out-edges. The missing arm left every BlockSwitch composite
                // with sizeIn==0/sizeOut==0 (one-sided edges: pred kept its
                // out-half, exit kept its in-half), so ruleBlockCat rejected
                // the chain (cc:1300 `outblock->sizeIn() != 1`) and selectGoto
                // exhausted at the residual 3-block graph (TRI2-STRUCT-
                // IRREDUCIBLE-TRACE-0001, glob_set 19->3 live).
                bsw.incoming = new_in;
                bsw.outgoing = new_out;
            }
            // (g) guard-shadow: wholesale boundary-edge assignment (lengths
            // 0 -> |new_in|/|new_out|; the composite was adopted at the
            // identify entry, so its cells exist and must follow).
            nb.sync_bank_shadows();
            // (wave 3) the edge mirrors refresh with the same choke.
            nb.sync_edge_shadows();
        }

        // NOW install new_block at install_idx (replaces the cond block).
        // Done AFTER self_identify captured the cond block's boundary edges.
        // IMPORTANT: after replacing, retarget every other block's edges that
        // pointed at the old install block (index == install_idx, which the
        // old block and new_block share) to new_block. The index-based
        // rewrite covers every block type uniformly (Ghidra's selfIdentify
        // walks the install block as a component — block.cc:940-963 passes
        // the cond in -nodes- — so its external neighbors are retargeted like
        // any consumed component's).
        // NOW install new_block at install_idx (replaces the cond block).
        // Done AFTER self_identify captured the cond block's boundary edges.
        // IMPORTANT: after replacing, retarget every other block's edges that
        // pointed at the old install block (index == install_idx, which the
        // old block and new_block share) to new_block. The index-based
        // rewrite covers every block type uniformly (Ghidra's selfIdentify
        // walks the install block as a component — block.cc:940-963 passes
        // the cond in -nodes- — so its external neighbors are retargeted like
        // any consumed component's).
        let mut old_install: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
        if install_idx < size {
            // cc:951 (install block is in Ghidra's -nodes- set): the
            // composite inherits its interior-goto marks too.
            {
                let cf = self.graph.blocks[install_idx].read().unwrap().get_flags()
                    & (crate::block::block_flags::INTERIOR_GOTOOUT
                        | crate::block::block_flags::INTERIOR_GOTOIN);
                if cf != 0 {
                    new_block.write().unwrap().set_flags(cf);
                }
            }
            old_install = Some(self.graph.blocks[install_idx].clone());
            self.graph.blocks[install_idx] = new_block.clone();
            self.graph.bank.adopt(&new_block);
            // (IDENTIFY) oracle-form install-peer retarget: rewrite exactly
            // the install block's external boundary peers (selfIdentify
            // block.cc:902-929 walks each component's edge lists and
            // replace*Edge's the adjacent peers — never a graph sweep).
            // Coverage equivalence with the former `for gi in 0..size`
            // sweep: Rudra edges are paired halves, so {blocks whose out-edge
            // resolves to install_idx} == {sources of install's in-edges} and
            // {blocks whose in-edge resolves from install_idx} == {targets
            // of install's out-edges}; the capture filters
            // (!is_consumed_idx && != install_idx) are the sweep's skip
            // predicates verbatim; nothing between capture and here mutates
            // an install_idx-targeting edge (the consumed-loop rewrites
            // match c_idx != install_idx only). Component-to-component
            // edges are excluded on both forms (block.cc:905-928 never
            // rewrites an internal edge).
            for src_id in &install_ext_sources {
                let s_any = bank.expect_arc(*src_id);
                // Avoid self-loop: don't rewrite new_block's own edge
                // (new_block holds no install_idx-pointing edges at capture
                // time; the guard keeps the old sweep's exact predicate).
                if std::sync::Arc::ptr_eq(&s_any, new_block) {
                    continue;
                }
                if rewrite_out_edges_to_idx(&bank, &s_any, install_idx as i32, new_point_id) {
                    touched.push(s_any);
                }
            }
            for dst_id in &install_ext_targets {
                let d_any = bank.expect_arc(*dst_id);
                if std::sync::Arc::ptr_eq(&d_any, new_block) {
                    continue;
                }
                if rewrite_in_edges_to_idx(&bank, &d_any, install_idx as i32, new_point_id) {
                    touched.push(d_any);
                }
            }
        }

        // Re-pair the composite's boundary reverse indices by pointer. The
        // oracle's replace*Edge protocol (block.cc:160-191, invoked from
        // selfIdentify block.cc:910-924) sets both halves' reverse_index at
        // retarget time; Rudra's rewrite_* only flips e.point, so this pass
        // restores Ghidra's checkEdges() invariant (block.cc:545-570) before
        // the paired dedup reads the recorded slots. The pairing is a
        // BIJECTION: parallel edges to one peer consume distinct peer slots
        // in order, mirroring the oracle's per-slot replace protocol.
        resync_boundary_reverse_indices(new_block);

        // Ghidra selfIdentify ends with dedup() (block.cc:930) run ON THE
        // COMPOSITE ONLY: its paired half-deletes collapse the external
        // duplicates created when several consumed components (or the
        // install block plus a component) each had an edge to the same
        // external block. The composite's dedup is what removes the peer's
        // duplicate slot (eliminateInDups/eliminateOutDups, block.cc:440-501).
        dedup_edges_all_types(new_block);
        // The touched external blocks may still carry duplicate slots from
        // the index-based rewrite above (their dedup is a no-op once the
        // composite's paired dedup has cleaned them — kept as an invariant
        // guard for the rewrite model's residual states).
        for ext in &touched {
            dedup_edges_all_types(ext);
        }

        // Ghidra selfIdentify moves each component's EXTERNAL edge halves
        // onto the composite (the replace*Edge half-deletes, block.cc:160-191):
        // after identification a component keeps only its component-to-
        // component (internal) edges. Mirror that for every component — the
        // consumed set plus the install block — instead of blanket-clearing,
        // so per-component in/out counts match the oracle (internal edges
        // like cond->clause stay; external ones like clause->merge move to
        // the composite). Components are NOT flagged DEAD: identifyInternal
        // (block.cc:940-963) sets no flag; containment is recorded in
        // absorbed_into (Ghidra: addBlock sets `parent`, block.cc:873),
        // which is_consumed/finalize_structure use in place of Ghidra's
        // incremental list compaction (block.cc:953-960).
        {
            let is_component = |idx: i32| is_consumed_idx(idx) || idx == install_idx as i32;
            // (W2) shadow reads: component membership via the bank index
            // shadow — the peer lock/vtable round-trip is gone and the
            // self-loop arm keeps its edge exactly as before.
            let strip_external = |bl: &Arc<RwLock<dyn FlowBlock + Send + Sync>>| {
                let mut w = bl.write().unwrap();
                // (W2) shadow reads: the component test reads the bank index
                // shadow (block.hh:160) — no peer lock. The old try_read's
                // failure arm (unwrap_or(true) = keep) fired on self-loops,
                // where the shadow form also keeps the edge (both endpoints
                // are components), matching Ghidra's direct parent compare
                // (block.cc:907).
                w.in_edges_mut()
                    .retain(|edge| is_component(bank.expect_index(edge.point)));
                w.out_edges_mut()
                    .retain(|edge| is_component(bank.expect_index(edge.point)));
                // (g) guard-shadow: the retains change edge LENGTHS; push
                // the post-strip sizes into the owning bank's cells. (wave 3)
                // the edge mirrors refresh with the same choke.
                w.sync_bank_shadows();
                w.sync_edge_shadows();
            };
            if let Some(oi) = &old_install {
                strip_external(oi);
            }
            for &idx in consumed_indices {
                let i = idx as usize;
                if i < size && i != install_idx {
                    if let Some(cb) = self.graph.get_block(i) {
                        strip_external(&cb);
                        // Record the containment (Ghidra: the consumed node's
                        // `parent` becomes the new composite via addBlock,
                        // block.hh:78 / block.cc:873). Self-mappings (a
                        // component consumed at its own install slot — the
                        // composite now owns that index) are skipped: they
                        // would poison membership walks that treat any key
                        // as "not top-level".
                        self.graph.absorbed_into.insert(idx, install_idx as i32);
                    }
                }
            }
        }

        // Ghidra addBlock min-tracking (block.cc:866-873): identifyInternal
        // calls `ident->addBlock(node)` for every absorbed node, and
        // BlockGraph::addBlock maintains `index = min(index, bl->index)` —
        // the composite's index is the MINIMUM over its component indices
        // (empirically confirmed on the oracle: WhileDo cond=79/clause=78
        // produces composite idx=78, all cond<clause wraps produce
        // idx=cond). Rudra's slot model installs the composite at the
        // cond/head slot, which equals the min for every wrap whose head
        // holds the smallest index; for the reversed case (a component at
        // a lower index than the head — e.g. the NPat2R9 WhileDo
        // cond=79/clause=78 wrap) park the min-slot component in the
        // vacated install slot and label the composite with the min index,
        // so every index-keyed consumer (FloatingEdge::get_current_edge
        // resolution, TraceDAG BadEdgeScore ordering, LoopBody head/tail
        // updates) sees the oracle's identity.
        let new_idx: usize = consumed_indices
            .iter()
            .copied()
            .filter(|&idx| (idx as usize) < size)
            .chain(std::iter::once(install_idx as i32))
            .min()
            .unwrap_or(install_idx as i32) as usize;
        if new_idx != install_idx && new_idx < size && install_idx < size {
            let parked = self.graph.blocks[new_idx].clone();
            self.graph.blocks[new_idx] = new_block.clone();
            self.graph.bank.adopt(&new_block);
            self.graph.blocks[install_idx] = parked.clone();
            self.graph.bank.adopt(&parked);
            // Shadow-mirrored index writes (bank single choke point).
            self.graph.set_block_index(&new_block, new_idx as i32);
            self.graph.set_block_index(&parked, install_idx as i32);
            // Re-map containment to the composite's final index. Entries
            // recorded above against install_idx now target new_idx (this
            // also path-compresses older chains that pointed at a
            // previously-installed composite occupying install_idx). The
            // pre-swap min-slot key described the parked component's OLD
            // slot; after parking it lives at install_idx.
            let stale_keys: Vec<i32> = self.graph.absorbed_into.keys().copied().collect();
            for k in stale_keys {
                if let std::collections::hash_map::Entry::Occupied(mut e) =
                    self.graph.absorbed_into.entry(k)
                {
                    if *e.get() == install_idx as i32 {
                        e.insert(new_idx as i32);
                    }
                }
            }
            self.graph.absorbed_into.remove(&(new_idx as i32));
            self.graph
                .absorbed_into
                .insert(install_idx as i32, new_idx as i32);
        }

        // Ghidra addBlock(ret) (block.cc:862-875) appends the composite at
        // the END of the graph list, after identifyInternal removed the
        // components (block.cc:953-960, including the install slot's old
        // occupant — it is a component like any other). Mirror that on the
        // virtual list: drop the consumed entries and the install slot, then
        // push the install slot (now the composite) at the end, so every
        // position-order scan walks the oracle's exact list layout.
        self.virtual_list
            .retain(|&s| !is_consumed_idx(s) && s != install_idx as i32 && s != new_idx as i32);
        self.virtual_list.push(new_idx as i32);
    }

    // Ghidra: block.cc:1780 BlockGraph::newBlockCondition
    /// Factory: build a BlockCondition collapsing b1 (cond) + b2 (orblock),
    /// mirroring Ghidra newBlockCondition (block.cc:1780-1794). Computes opc
    /// from edge relation (b1's false-out == b2 → OR, else AND) exactly as
    /// Ghidra does via getFalseOut(). Calls identifyInternal for edge
    /// inheritance. The new block is installed at install_idx (replacing b1's
    /// slot). Returns the new BlockCondition Arc.
    ///
    /// Key Ghidra semantics:
    ///  - opc = (b1->getFalseOut() == b2) ? CPUI_INT_OR : CPUI_INT_AND
    ///  - forceOutputNum(2) + forceFalseEdge(b2->getOut(0)) preserve the
    ///    condition's 2 outputs with the false-edge being b2's fallthrough.
    ///    Rudra's BlockCondition tracks false-edge as outgoing[0]; the
    ///    identifyInternal boundary capture preserves this when b1's out[0]
    ///    is b2 (the consumed orblock), and b2's out[0] (out0) becomes the
    ///    condition's out[0].
    fn new_block_condition(
        &mut self,
        b1: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        b2: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        install_idx: usize,
    ) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        // cc:1783: const FlowBlock *out0 = b2->getOut(0);
        let out0 = b2.read().unwrap().get_out(0).map(|e| self.graph_bank().expect_arc(e.point));
        // cc:1785: opc = (b1->getFalseOut() == b2) ? INT_OR : INT_AND
        // Ghidra getFalseOut() = outofthis[0].point, purely positional
        // (block.hh:299, never reads BOOLEAN_FLIP). Rudra's flow construction
        // (flow.rs:920-928, flow.cc:960-967) pushes the fallthru edge first,
        // so out[0] is the false path in both implementations and
        // get_false_out(cbranch) now returns exactly out[0] — the polarity
        // below matches block.cc:1785 one-to-one.
        // Find b1's terminal CBRANCH op.
        let b1_cbranch = {
            let b1r = b1.read().unwrap();
            b1r.get_ops()
                .last()
                .filter(|op_ref| op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                .cloned()
        };
        let bool_op = match &b1_cbranch {
            Some(cb) => {
                let (bank, false_out) = {
                    let b1r = b1.read().unwrap();
                    (b1r.bank(), b1r.get_false_out(cb))
                };
                let b2_id = bank.registered_id_of(b2);
                match false_out {
                    Some(fb) if fb == b2_id => BoolOp::Or,
                    _ => BoolOp::And,
                }
            }
            None => BoolOp::And, // No CBRANCH (structured block); default And.
        };
        let cond_idx = b1.read().unwrap().get_index();
        let cond_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockCondition {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: cond_idx,
                op_type: bool_op,
                first: b1.clone(),
                second: b2.clone(),
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        let b2_idx = b2.read().unwrap().get_index();
        // cc:1789: identifyInternal(ret, {b1, b2}). Rudra: b1 is at install_idx
        // (handled by identify_internal's install_idx capture), b2 is consumed.
        self.identify_internal(&cond_block, &[b2_idx], install_idx);
        // cc:1791-1792: forceOutputNum(2) + forceFalseEdge(out0). Rudra's
        // BlockCondition has exactly 2 outputs after identifyInternal; the
        // false-edge (out[0]) should be out0 (b2's fallthrough). If identify
        // didn't preserve it, fix up: ensure out[0] is out0.
        if let Some(out0_ref) = &out0 {
            let mut cb = cond_block.write().unwrap();
            if let Some(bc) = cb.as_any_mut().downcast_mut::<BlockCondition>() {
                // Ensure exactly 2 outputs; if out[0] isn't out0, swap.
                if bc.outgoing.len() >= 1 {
                    let out0_is_first = bc.outgoing[0].point == self.graph_bank().registered_id_of(&out0_ref);
                    if !out0_is_first && bc.outgoing.len() >= 2 {
                        // forceFalseEdge delegates to FlowBlock::swapEdges,
                        // preserving reciprocal slots and f_flip_path.
                        <BlockCondition as FlowBlock>::swap_edges(bc);
                    }
                }
            }
        }
        self.update_switch_case_reference(cond_idx, &cond_block);
        self.structure_change_count += 1;
        eprintln!(
            "[BLOCKSTRUCT] {:?} condition at block {} (b1={}, b2={})",
            bool_op,
            install_idx,
            b1.read().unwrap().get_index(),
            b2.read().unwrap().get_index()
        );
        cond_block
    }

    // Ghidra: block.cc:1822 BlockGraph::newBlockIf
    /// Factory: build a BlockIf (if-then, no else) collapsing cond + tc.
    /// Mirrors Ghidra newBlockIf (block.cc:1822-1833). identifyInternal +
    /// forceOutputNum(1). Installed at install_idx (replacing cond).
    fn new_block_if(
        &mut self,
        cond: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        tc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        install_idx: usize,
    ) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        let cond_idx = cond.read().unwrap().get_index();
        let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(BlockIf {
            owner_bank: std::sync::Weak::new(),
            bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
            index: cond_idx,
            condition: cond.clone(),
            if_body: tc.clone(),
            else_body: None,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            goto_target: None,
            goto_type: crate::block::goto_type::GOTO_GOTO,
            flags: 0,
        }));
        let tc_idx = tc.read().unwrap().get_index();
        // cc:1829: identifyInternal(ret, {cond, tc}). cond at install_idx.
        self.identify_internal(&if_block, &[tc_idx], install_idx);
        self.update_switch_case_reference(cond_idx, &if_block);
        self.structure_change_count += 1;
        if_block
    }

    // Ghidra: block.cc:1840 BlockGraph::newBlockIfElse
    /// Factory: build a Block If (if-then-else) collapsing cond + tc + fc.
    /// Mirrors Ghidra newBlockIfElse (block.cc:1840-1852). identifyInternal +
    /// forceOutputNum(1). Installed at install_idx (replacing cond).
    fn new_block_if_else(
        &mut self,
        cond: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        tc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        fc: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        install_idx: usize,
    ) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        let cond_idx = cond.read().unwrap().get_index();
        let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(BlockIf {
            owner_bank: std::sync::Weak::new(),
            bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
            index: cond_idx,
            condition: cond.clone(),
            if_body: tc.clone(),
            else_body: Some(fc.clone()),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            goto_target: None,
            goto_type: crate::block::goto_type::GOTO_GOTO,
            flags: 0,
        }));
        let tc_idx = tc.read().unwrap().get_index();
        let fc_idx = fc.read().unwrap().get_index();
        // cc:1848: identifyInternal(ret, {cond, tc, fc}). cond at install_idx.
        self.identify_internal(&if_block, &[tc_idx, fc_idx], install_idx);
        self.update_switch_case_reference(cond_idx, &if_block);
        self.structure_change_count += 1;
        if_block
    }

    // Ghidra: block.cc:1889 BlockGraph::newBlockInfLoop
    /// Factory: build a BlockInfLoop collapsing a self-looping body block.
    /// Mirrors Ghidra newBlockInfLoop (block.cc:1889-1898): identifyInternal
    /// with nodes={body}, addBlock, NO forceOutputNum (inf loop has 0 out).
    /// The body is consumed (moved into the BlockInfLoop). Installed at
    /// install_idx (replacing body's slot).
    fn new_block_inf_loop(
        &mut self,
        body: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        install_idx: usize,
    ) -> Arc<RwLock<dyn FlowBlock + Send + Sync>> {
        let body_idx = body.read().unwrap().get_index();
        let inf_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(crate::block::BlockInfLoop {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: body_idx,
                body: body.clone(),
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        // cc:1895: identifyInternal(ret, {body}). body at install_idx.
        // Pass empty consumed_indices: the body sits at install_idx and is
        // handled by identify_internal's install_idx capture. No additional
        // consumed blocks (the self-loop edge is internal).
        self.identify_internal(&inf_block, &[], install_idx);
        self.update_switch_case_reference(body_idx, &inf_block);
        self.structure_change_count += 1;
        eprintln!(
            "[BLOCKSTRUCT] inf loop at block {} (body={})",
            install_idx,
            body.read().unwrap().get_index()
        );
        inf_block
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleCat
    /// Ghidra's ruleBlockCat (blockaction.cc:1284): concatenate a chain of
    /// blocks into a single BlockList. Faithful port with chain extension.
    /// bl must have 1 out-edge to outblock, outblock has 1 in-edge, and bl must
    /// be the START of a chain (its in-edge source has >1 out OR bl has >1 in).
    /// Then extend the chain while each link has 1 out, 1 in, no switch, no goto.
    fn try_rule_cat(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank_view: &crate::block::BlockBankView) -> bool {
        let size = self.graph.get_size();
        // One bank-view guard spans this rule's read phases (the per-try
        // peer reads below run millions of times per giant function; NLL
        // ends the borrow before the first &mut self fire path).
        // bl->sizeOut() != 1 — NO type gate: Ghidra's ruleBlockCat
        // (cc:1284-1314) runs on any graph member; structured components
        // (BlockIf, BlockCondition, ...) cat-merge like basic blocks.
        // (BLOCKSTRUCT2) entry pair through the view — no guard opened on
        // the common exit paths (cc:1289-1290).
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank_view);
            if size_out != 1 {
                return false;
            }
            // cc:1290: bl->isSwitchOut() — the f_switch_out dispatch flag.
            if switch_out {
                return false;
            }
        }
        // bl must be the START of a chain: (sizeIn==1 && getIn(0)->sizeOut==1) → false
        // i.e. bl is a chain start if it has multiple in-edges, OR its sole
        // predecessor has multiple out-edges (bl is a branch target).
        // (IDENTIFY) second-tier guards through the view: cc:1291-1295 are
        // inline field loads in the oracle (sizeIn/getOut/isDecisionOut,
        // block.hh:312-313/301/336). The registered form reads them from the
        // bank shadows (in-edge twin + size cells + edge label) with no
        // block RwLock and no vtable; SENTINEL (bare fixtures) keeps the
        // guard-read form, byte-identical.
        let first_next_point;
        if self_id != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL {
            let block_idx = bank_view.expect_index(self_id);
            if bank_view.expect_size_in(self_id) == 1 {
                if let Some(in_edge) = bank_view.expect_in_edge(self_id, 0) {
                    // (g) guard-shadow: pure sizeOut guard on the peer —
                    // served from the bank cell (no Arc clone/peer lock).
                    let pred_out = bank_view.expect_size_out(in_edge.point);
                    if pred_out == 1 {
                        return false;
                    } // not start of chain
                }
            }
            // bl->getOut(0) == bl → no looping; cc:1295 decision test on
            // the same edge half.
            let out_edge = match bank_view.expect_out_edge(self_id, 0) {
                Some(e) => e,
                None => return false,
            };
            if bank_view.expect_index(out_edge.point) == block_idx {
                return false;
            }
            // cc:1295: `if (!bl->isDecisionOut(0)) return false;` — the
            // chain entry edge must be a plain forward edge (not goto, not
            // a loop bottom back-edge); block.hh:336 label test.
            if !Self::edge_label_is_decision(out_edge.flags) {
                return false;
            }
            first_next_point = out_edge.point;
        } else {
            let b = block.read().unwrap();
            let block_idx = b.get_index();
            if b.size_in() == 1 {
                if let Some(in_edge) = b.get_in_ref(0) {
                    // (g) guard-shadow: pure sizeOut guard on the peer —
                    // served from the bank cell (no Arc clone/peer lock).
                    let pred_out = bank_view.expect_size_out(in_edge.point);
                    if pred_out == 1 {
                        return false;
                    } // not start of chain
                }
            }
            // bl->getOut(0) == bl → no looping
            let out_edge = match b.get_out_ref(0) {
                Some(e) => e,
                None => return false,
            };
            if bank_view.expect_index(out_edge.point) == block_idx {
                return false;
            }
            // cc:1295: `if (!bl->isDecisionOut(0)) return false;` — the
            // chain entry edge must be a plain forward edge (not goto, not
            // a loop bottom back-edge).
            if !Self::out_edge_is_decision(&*b, 0) {
                return false;
            }
            first_next_point = out_edge.point;
        }

        // Build the cat chain, cc:1298-1310 structure: nodes = [bl,
        // outblock] unconditionally (outblock already passed its sizeIn==1 /
        // !switchOut checks above), then extend while the CURRENT chain tail
        // has exactly one out-edge whose target also has sizeIn==1 —
        // checking the tail's isDecisionOut (a goto edge or a loop bottom
        // stops the chain). The first link is pushed without a decision
        // check on the outblock itself: bl's own out-edge was already
        // checked, and the link may legitimately be a halt block with no
        // out-edges at all (BLOCKSTRUCT-NORETURN-DEADREGION-0001 — the
        // previous off-by-one-link check never let a halt tail enter the
        // chain, so the goto-wrapped component never cat-merged and the
        // selectGoto loop had to mark every remaining edge).
        let mut nodes: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        nodes.push(block.clone());
        // outblock = bl->getOut(0) — capture after the entry guards.
        // (W3) the chain walk carries only edge POINTS (ids); every guard
        // on the walk is a bank shadow read (sizeIn/sizeOut/flags/out-edge
        // label), and the handles materialize at fire below — the miss
        // path (chain break) resolves nothing.
        // (IDENTIFY) first_next_point was captured inside the guard block
        // above (out_edge.point) — no second read lock.
        // cc:1294/1296: nothing else may hit the first link; a switch
        // dispatch block must be resolved first.
        if bank_view.expect_size_in(first_next_point) != 1 {
            return false;
        }
        if bank_view.expect_flags(first_next_point) & crate::block::block_flags::SWITCH_OUT != 0 {
            return false;
        }
        let mut chain_points: Vec<crate::arena::BlockId> = Vec::new();
        chain_points.push(first_next_point);

        // cc:1302: while(outblock->sizeOut()==1) { ... }
        // (g) guard-shadow: nextIdx/sizeIn/flags are pure guard reads —
        // served from the bank cells (the chain head's index is
        // loop-invariant under the read-phase discipline: no publish
        // happens inside this loop, cc:1302-1310 only reads).
        // (IDENTIFY) head_idx through the view (block.hh:160 shadow) —
        // same value as the block guard read, without the second RwLock.
        let head_idx = if self_id
            != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL
        {
            bank_view.expect_index(self_id)
        } else {
            nodes[0].read().unwrap().get_index()
        };
        let mut cur_point = first_next_point;
        loop {
            if bank_view.expect_size_out(cur_point) != 1 {
                break;
            }
            let cur_edge = match bank_view.expect_out_edge(cur_point, 0) {
                Some(e) => e,
                None => break,
            };
            let next_point = cur_edge.point;
            let next_idx = bank_view.expect_index(next_point);
            // cc:1304: outbl2 == bl → no looping (compare against the chain head).
            if next_idx == head_idx {
                break;
            }
            let n_in = bank_view.expect_size_in(next_point);
            let n_flags = bank_view.expect_flags(next_point);
            // cc:1305: outbl2->sizeIn() != 1 → break (nothing else may hit it)
            if n_in != 1 {
                break;
            }
            // cc:1306: `if (!outblock->isDecisionOut(0)) break;` — the
            // CURRENT tail's out-edge must be a plain forward edge. (W3)
            // decision label via the edge shadow (block.hh:336 inline);
            // (IDENTIFY) same edge half as next_point — one shadow read.
            if !Self::edge_label_is_decision(cur_edge.flags) {
                break;
            }
            // cc:1307: outbl2->isSwitchOut() → break
            if n_flags & crate::block::block_flags::SWITCH_OUT != 0 {
                break;
            }
            // cc:1308-1309: extend the chain.
            chain_points.push(next_point);
            cur_point = next_point;
            // Safety: limit chain length
            if chain_points.len() > 64 {
                break;
            }
        }

        // Need at least 2 nodes to form a cat
        if chain_points.len() < 1 {
            return false;
        }

        // (W3) fire path: materialize the chain handles once (the head is
        // already in `nodes`); `first_next` keeps the first link's handle
        // for the historical uses below.
        for p in &chain_points {
            nodes.push(bank_view.expect_arc(*p));
        }
        let first_next = nodes[1].clone();

        // Ghidra newBlockList (block.cc:1762-1764): capture the LAST chain
        // node's out-edge count — and its out(0) when binary — BEFORE
        // identifyInternal. A tail out-edge that points back into the chain
        // becomes internal to the composite; forceOutputNum(outforce) below
        // must still resurrect it as a composite self loop/back edge, and
        // forceFalseEdge(out0) must preserve which branch was the false
        // (fall-through) path. Captured here because identify_internal
        // deletes/rewrites the tail's edge halves.
        let (outforce, out0) = {
            let last = nodes.last().unwrap().read().unwrap();
            let n = last.size_out();
            (
                n,
                if n == 2 {
                    last.get_out(0).map(|e| bank_view.expect_arc(e.point))
                } else {
                    None
                },
            )
        };

        // Consume all nodes except the first (block stays at install_idx=i).
        // Ghidra newBlockList(nodes) passes ALL nodes to identifyInternal; here
        // block sits at install_idx so we consume nodes[1..].
        let block_idx = block.read().unwrap().get_index();
        let consumed: Vec<i32> = nodes[1..]
            .iter()
            .map(|n| n.read().unwrap().get_index())
            .collect();
        // Release the bank view before the &mut self fire path (the read
        // phases above are done; NLL alone cannot prove it across the loop).
        drop(bank_view);
        let list_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockList::new(block_idx, nodes.clone())));
        self.identify_internal(&list_block, &consumed, i);
        // Ghidra newBlockList (block.cc:1768-1770): forceOutputNum(outforce)
        // + forceFalseEdge(out0) when binary. The force step is what keeps a
        // chain-internal back-edge alive: identifyInternal moved it inside
        // the composite, leaving the composite with fewer external outs than
        // the tail had — forceOutputNum appends the composite self
        // loop/back edge (block.cc:888) so ruleBlockDoWhile (cc:1555) can
        // absorb the latch (the do-while absorption chain:
        // goto/if_goto → cat → dowhile on the @321a/@3225/@28ec/@28f7
        // duplicated-address latch pairs).
        Self::force_output_num(&self.graph.bank, &list_block, outforce);
        if list_block.read().unwrap().size_out() == 2 {
            Self::force_false_edge_composite(&list_block, out0.as_ref(), &nodes);
        }
        self.update_switch_case_reference(block_idx, &list_block);
        self.structure_change_count += 1;
        true
    }

    // Ghidra: blockaction.hh:46 LoopBody::updateSwitchCaseReference
    /// Update any BlockSwitch that has `old_idx` as a case body to point to `new_block`.
    /// This ensures switch case bodies that get structured into BlockIf/BlockList
    /// are correctly referenced by their owning BlockSwitch.
    fn update_switch_case_reference(
        &mut self,
        old_idx: i32,
        new_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) {
        // (BLOCKSTRUCT2) O(#switches) candidate scan over the registry (a
        // superset of the live top-level switches — seeded at construction,
        // pushed at each switch fire; stale slots filtered by the type
        // check). The previous form cloned every graph member's Arc and
        // opened a read guard per block per fire (13.9K fires × ~2.6K
        // blocks on the giant function ≈ 0.5s). Semantics preserved
        // exactly: the first switch in SLOT order that holds the case
        // (minimum holding slot — the old scan's break-at-first) is the one
        // re-pointed.
        let mut target_slot: Option<usize> = None;
        for &slot in &self.switch_slots {
            let Some(block) = self.graph.blocks.get(slot) else {
                continue;
            };
            let holds_case = {
                let b = block.read().unwrap();
                if b.get_type() != crate::block::BlockType::Switch {
                    continue;
                }
                let Some(sw) = b.as_any().downcast_ref::<BlockSwitch>() else {
                    continue;
                };
                let in_cases = sw
                    .cases
                    .iter()
                    .any(|c| c.read().unwrap().get_index() == old_idx);
                let in_default = sw
                    .default_case
                    .as_ref()
                    .map_or(false, |d| d.read().unwrap().get_index() == old_idx);
                in_cases || in_default
            };
            if !holds_case {
                continue;
            }
            if target_slot.is_none_or(|t| slot < t) {
                target_slot = Some(slot);
            }
        }
        let Some(target_slot) = target_slot else {
            return;
        };
        let block = self.graph.blocks[target_slot].clone();
        // Swap the case reference IN PLACE. The oracle never rebuilds a
        // composite when a case body is re-wrapped: its caseblocks hold
        // FlowBlock pointers that stay valid across identifyInternal
        // (block.cc:940-963 never touches sibling composites), and the
        // enclosing BlockSwitch keeps its own boundary edges, flags and
        // metadata untouched. The previous whole-struct rebuild here
        // re-created the switch with `incoming: Vec::new()` /
        // `outgoing: Vec::new()` / `flags: 0`, destroying the
        // composite's boundary out-edges - FloatingEdge::get_current_edge
        // (blockaction.cc:27-38) then failed to re-resolve a still-live
        // (switch->exit) record against the graph (selectGoto silently
        // skipped the entry: oracle record #43 (21->39) on
        // sqlite3ExprIsConstant), and the slot swap also discarded the
        // graph.blocks[i] Arc identity that peers' edge halves point at.
        // In-place mutation keeps the Arc, its bank id, its boundary
        // edges and its flags: only the case/default pointer moves.
        {
            let mut w = block.write().unwrap();
            if let Some(sw) = w.as_any_mut().downcast_mut::<BlockSwitch>() {
                for c in sw.cases.iter_mut() {
                    if c.read().unwrap().get_index() == old_idx {
                        *c = new_block.clone();
                    }
                }
                if let Some(d) = sw.default_case.as_mut() {
                    if d.read().unwrap().get_index() == old_idx {
                        *d = new_block.clone();
                    }
                }
            }
            // Case-reference swap only - no edge-length or index change,
            // so the bank/edge shadow invariants are unaffected.
        }
        eprintln!(
            "[COLLAPSE] {} updated BlockSwitch case {} → BlockIf",
            self.name, old_idx
        );
    }

    // Ghidra: blockaction.hh:46 LoopBody::countNonStructuralInEdges
    /// Count in-edges that are NOT from switch dispatch blocks.
    /// Switch dispatch edges come from BlockSwitch nodes or CBRANCH cascade
    /// members (blocks whose taken edge targets a CASE_BODY block).
    /// These structural edges should not prevent proper_if/if_else matching.
    fn count_non_structural_in_edges(
        &self,
        bank: &crate::block::BlockBankView,
        clause_id: crate::arena::BlockId,
    ) -> usize {
        let total = bank.expect_size_in(clause_id);
        let mut structural = 0;
        // Hot path: per-edge peer reads go through the caller's dispatch
        // snapshot view (block.hh:160/184 field reads) — no peer RwLock, no
        // vtable, no per-scan view mintage. Edges with unresolved twins
        // (SENTINEL: bare test fixtures) fall back to the original guard
        // read, byte-identical. (W3) the in-edge list itself comes from
        // the edge shadow under one lock (block.hh:304 inline read form).
        bank.with_in_edges(clause_id, |ins| {
            for in_edge in ins {
                let mut resolved_by_shadow = false;
                if let Some(pred_btype) = bank.btype(in_edge.point) {
                    // Edge from BlockSwitch control → structural
                    if pred_btype == crate::block::BlockType::Switch {
                        structural += 1;
                        continue;
                    }
                    if let Some(pred_index) = bank.index(in_edge.point) {
                        resolved_by_shadow = true;
                        // NOTE: no switch_case_indices arm — Ghidra's guard is plain
                        // `clauseblock->sizeIn() != 1` (cc:1391/cc:1428 etc.) with no
                        // notion of cascade members. The invented arm counted the
                        // refreshSwitchCases CBRANCH-chain marks (no oracle
                        // counterpart) as "structural", so every else-if chain the
                        // cascade walker touched was rejected by proper_if/if_else/
                        // do_while — leaving the chain uncollapsible and selectGoto
                        // to exhaust (TRI2-STRUCT-IRREDUCIBLE-TRACE-0001,
                        // glob_range residual 1→2→3→9 with properif-legal shapes).
                        // Edge from a consumed component (already absorbed by a
                        // composite; Ghidra removed it from the list, block.cc:953-
                        // 960) → structural
                        if self.is_consumed(pred_index) {
                            structural += 1;
                        }
                    }
                }
                if !resolved_by_shadow {
                    // Stale-id fallback (unreachable while the single-bank
                    // invariant holds): bank discriminant/shadow reads, the
                    // pre-bank guard form's equivalents (block.hh:184/160).
                    // The old expect_arc panicked on stale ids; expect_index
                    // keeps the same panic profile.
                    let bank = self.graph_bank();
                    if bank.btype_of(in_edge.point) == Some(crate::block::BlockType::Switch) {
                        structural += 1;
                        continue;
                    }
                    if self.is_consumed(bank.expect_index(in_edge.point)) {
                        structural += 1;
                    }
                }
            }
        });
        total - structural
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleProperIf
    /// ruleBlockProperIf: detect if-then pattern (generalized Triangle).
    /// A CBRANCH block with 2 out-edges, where one out-edge block (clause)
    /// has 1 in and 1 out, and its out-edge points to the other branch.
    fn try_rule_proper_if(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // PERF-ARENA-FLIP-0001 (f) step 2: guard-phase snapshot view (the
        // fire path at the tail takes no view reads).
        // (BLOCKSTRUCT2) cc:1384-1385 entry pair through the view — the
        // branch-block miss path (sizeOut!=2) never opens a guard.
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }
            if switch_out {
                return false;
            }
        }
        // (IDENTIFY) second-tier guards through the view: after the entry
        // pair passes, the oracle's remaining reads (cc:1386-1398) are all
        // non-virtual inline loads — getOut/getIndex label+index fields and
        // the isGotoOut/isDecisionOut label tests (block.hh:299-347). The
        // registered form serves every one from the bank shadows (edge
        // twins + index/flags cells) with no block RwLock and no vtable;
        // SENTINEL (bare fixtures, never adopted) keeps the guard-read form,
        // byte-identical values either way.
        let (_cond_idx, true_point, false_point, true_idx, false_idx, decision_out) =
            if self_id != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL {
                let cond_idx = bank.expect_index(self_id);
                let te = match bank.expect_out_edge(self_id, 0) {
                    Some(e) => e,
                    None => return false,
                };
                let fe = match bank.expect_out_edge(self_id, 1) {
                    Some(e) => e,
                    None => return false,
                };
                let true_idx = bank.expect_index(te.point);
                let false_idx = bank.expect_index(fe.point);
                // cc:1386-1387: `if (bl->getOut(0)==bl) ... getOut(1)==bl`
                // — no self loops.
                if true_idx == cond_idx || false_idx == cond_idx {
                    return false;
                }
                // cc:1388-1389: isGotoOut(0)/isGotoOut(1) — view form
                // (label + GOTO_EDGE_0/1 mirrors; see view_out_edge_is_goto).
                if Self::view_out_edge_is_goto(bank, self_id, 0) {
                    return false;
                }
                if Self::view_out_edge_is_goto(bank, self_id, 1) {
                    return false;
                }
                // cc:1395 pre-capture: isDecisionOut per out edge
                // (block.hh:336 label test on the fetched halves).
                let d0 = Self::edge_label_is_decision(te.flags);
                let d1 = Self::edge_label_is_decision(fe.flags);
                (cond_idx, te.point, fe.point, true_idx, false_idx, [d0, d1])
            } else {
                let b = block.read().unwrap();
                let cond_idx = b.get_index();
                let read_idx = |b: &dyn FlowBlock, slot: usize| -> Option<i32> {
                    b.get_out_ref(slot).and_then(|e| match bank.index(e.point) {
                        Some(i) => Some(i),
                        // Stale/unresolved ids cannot occur while the single-bank
                        // invariant holds; resolve-or-panic mirrors the view read.
                        None => Some(bank.expect_index(e.point)),
                    })
                };
                let out0_idx = read_idx(&*b, 0);
                let out1_idx = read_idx(&*b, 1);
                let self_loop = out0_idx == Some(cond_idx) || out1_idx == Some(cond_idx);
                // Reference reads of out[0]/out[1] (oracle getOut, block.hh:301)
                // — the miss path carries only the edge POINTS (ids); handles
                // materialize at fire (W3: millions of miss reads per fire).
                let (true_point, false_point) = match (b.get_out_ref(0), b.get_out_ref(1)) {
                    (Some(te), Some(fe)) => (te.point, fe.point),
                    _ => return false,
                };
                let true_idx = match bank.index(b.get_out_ref(0).unwrap().point) {
                    Some(i) => i,
                    None => bank.expect_index(true_point),
                };
                let false_idx = match bank.index(b.get_out_ref(1).unwrap().point) {
                    Some(i) => i,
                    None => bank.expect_index(false_point),
                };
                if self_loop {
                    return false;
                }
                if Self::out_edge_is_goto(&*b, 0) {
                    return false;
                }
                if Self::out_edge_is_goto(&*b, 1) {
                    return false;
                }
                // cc:1395 pre-capture: isDecisionOut per out edge (the read guard on
                // `b` is dropped below but the decision flags are edge labels).
                let decision_out = [
                    Self::out_edge_is_decision(&*b, 0),
                    Self::out_edge_is_decision(&*b, 1),
                ];
                drop(b);
                (cond_idx, true_point, false_point, true_idx, false_idx, decision_out)
            };

        // NOTE: no switch_case_indices/CASE_BODY pre-guard here — Ghidra's
        // ruleBlockProperIf has no such check (the clause guard is
        // isSwitchOut, added in the dir loop below per cc:1394).

        // Try both directions (i=0: true clause, i=1: false clause).
        // (W3) the direction loop walks ids + bank shadows; the captured
        // points select the clause/merge roles.
        for dir in 0..2 {
            let clause_point = if dir == 0 { true_point } else { false_point };
            let merge_idx = if dir == 0 { false_idx } else { true_idx };

            // (IDENTIFY) guard order: the oracle checks the cheap inline
            // field loads first and its plain `clauseblock->sizeIn() != 1`
            // (cc:1392) last-ish; Rudra's sizeIn equivalent —
            // count_non_structural_in_edges, the consumed-component/switch
            // compensation — is the one expensive guard here (edge-shadow
            // walk + per-edge membership), so it runs LAST. Every guard in
            // this loop is a pure read and the fire condition is their
            // conjunction, so the order cannot change which dirs fire.
            if bank.expect_size_out(clause_point) != 1 {
                continue;
            }
            // cc:1394: `if (clauseblock->isSwitchOut()) continue;` — don't
            // use a switch (possibly with goto edges) as the if clause.
            if bank.expect_flags(clause_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                continue;
            }
            // cc:1395: `if (!bl->isDecisionOut(i)) continue;` — don't use a
            // loopbottom/exit/goto edge as the clause edge (captured before
            // the `b` guard was dropped).
            if !decision_out[dir] {
                continue;
            }
            // cc:1396: `if (clauseblock->isGotoOut(0)) continue;` — no
            // unstructured jumps out of the clause. (W3) goto label via the
            // edge shadow (block.hh:347 inline label read).
            if bank
                .expect_out_edge(clause_point, 0)
                .map(|e| e.flags & (crate::block::edge_flags::F_GOTO_EDGE | crate::block::edge_flags::F_IRREDUCIBLE_EDGE) != 0)
                .unwrap_or(false)
            {
                continue;
            }
            // Note: we no longer skip switch case body blocks here — the DEAD flag
            // and orphan case label removal handle case label integrity at emit time.
            // Removing this guard allows CBRANCH blocks inside case bodies to be
            // structured into BlockIf, which is what we need for control-flow recovery.
            let target_idx = match bank.expect_out_edge(clause_point, 0) {
                Some(e) => bank.expect_index(e.point),
                None => continue,
            };
            if target_idx != merge_idx {
                continue;
            }
            // Count non-structural in-edges: ignore edges from switch dispatch blocks.
            // Switch dispatch edges come from BlockSwitch control blocks or CBRANCH
            // cascade members. We check if any in-edge source is a BlockSwitch or
            // a block we know is a switch dispatch (marked CASE_BODY or is a cascade
            // member whose taken edge targets this clause).
            let non_structural_in = self.count_non_structural_in_edges(bank, clause_point);
            if non_structural_in != 1 {
                continue;
            }

            // Match found: clause → merge. Create BlockIf via factory
            // (block.cc:1822 newBlockIf). cond at install_idx=i, clause consumed.
            // blockaction.cc:1400-1403 mutates the condition itself. This
            // virtual call must reach BlockList/BlockCondition as well as a
            // leaf BlockBasic before BlockIf is constructed.
            if dir == 0 && block.write().unwrap().negate_condition(true) {
                self.dataflow_change_count += 1;
            }
            // (W3) fire path: the clause handle materializes once.
            let clause = bank.expect_arc(clause_point);
            self.new_block_if(&block, &clause, i);
            return true;
        }
        false
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleIfNoExit
    /// ruleBlockIfNoExit: detect if-then where the clause has NO out-edge
    /// (ends with RETURN/exit). The clause doesn't merge back — it exits.
    /// Mirrors Ghidra's ruleBlockIfNoExit (blockaction.cc:1481).
    /// Protected against switch case extraction via switch_case_indices.
    fn try_rule_if_no_exit(
        &mut self,
        i: usize,
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_id: crate::arena::BlockId,
        bank: &crate::block::BlockBankView,
    ) -> bool {
        // PERF-ARENA-FLIP-0001 (f) step 2: guard-phase snapshot view (the
        // fire path at the tail takes no view reads).
        // (BLOCKSTRUCT2) cc:1481-1490 entry guards through the caller's
        // pass-level view — re-held after every fire (the only publishes on
        // this path are the fire's identify adopts, and the scan breaks at
        // the first fire).
        // Ghidra's rule is purely topological (no CBRANCH-op gate): the
        // polarity of a real CBRANCH lives in the data flip, and structured
        // condition components (BlockCondition) legitimately match here.
        // (The old `let ops = b.get_ops()` probe here cloned the whole op
        // list of the underlying BlockBasic per try with the result unused —
        // deleted.)
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }

            // cc:1487-1490: `if (bl->isSwitchOut()) return false; if
            // (bl->getOut(0)==bl) return false; if (bl->getOut(1)==bl)
            // return false; if (bl->isGotoOut(0)) return false; if
            // (bl->isGotoOut(1)) return false;` — no switch dispatch, no
            // self loops, no unstructured branches out of the condition.
            if switch_out {
                return false;
            }
        }
        let b = block.read().unwrap();
        let cond_idx = b.get_index();
        // RUDRA-GLUE: bank-view self-loop checks (edge twins' index
        // shadows; unresolved twins fall back to the guard read).
            let self_loop = (0..2).any(|slot| {
                b.get_out_ref(slot).map_or(false, |e| {
                    match bank.index(e.point) {
                        Some(i) => i == cond_idx,
                        None => bank.expect_index(e.point) == cond_idx,
                    }
                })
            });
            if self_loop {
                return false;
            }
        if Self::out_edge_is_goto(&*b, 0) {
            return false;
        }
        if Self::out_edge_is_goto(&*b, 1) {
            return false;
        }

        // NOTE: the invented switch_case_indices/CASE_BODY pre-guards are
        // gone (same family as the cascade-member guard deleted in a9d68f77):
        // Ghidra guards the clause only via isSwitchOut + isDecisionOut
        // inside the loop (cc:1500-1501). The cascade marks wrongly rejected
        // exit clauses of CBRANCH chains, leaving the graph stuck at the
        // "selectGoto exhausted" dead-loop (TRI2-STRUCT-SELECTGOTO-SELFLOOP-0001).

        let (true_point, false_point) = match (b.get_out_ref(0), b.get_out_ref(1)) {
            (Some(te), Some(fe)) => (te.point, fe.point),
            _ => return false,
        };
        // cc:1501: `if (!bl->isDecisionOut(i)) continue;` — pre-captured
        // before the read guard drops (edge labels live on the halves).
        let decision_out = [
            Self::out_edge_is_decision(&*b, 0),
            Self::out_edge_is_decision(&*b, 1),
        ];
        drop(b);

        for dir in 0..2 {
            // (W3) clause miss path via shadows (cc:1495-1497 reads only);
            // the handle materializes at fire. (The old `c_idx` capture was
            // a dead read — the fire path installs at `i`, wave-2's
            // try_rule_if_goto dead-read deletion precedent.)
            let clause_point = if dir == 0 { true_point } else { false_point };
            if bank.expect_size_in(clause_point) != 1 {
                continue;
            }
            if bank.expect_size_out(clause_point) != 0 {
                continue;
            } // Must have no out-edge (RETURN/exit)
              // cc:1500: `if (clauseblock->isSwitchOut()) continue;`
            if bank.expect_flags(clause_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                continue;
            }
            // cc:1501: `if (!bl->isDecisionOut(i)) continue;`
            if !decision_out[dir] {
                continue;
            }

            // blockaction.cc:1504-1507 records polarity in the condition and
            // its edge state before constructing BlockIf.
            if dir == 0 && block.write().unwrap().negate_condition(true) {
                self.dataflow_change_count += 1;
            }
            // (W3) fire path: the clause handle materializes once.
            let clause = bank.expect_arc(clause_point);
            // Create BlockIf via factory (block.cc:1822 newBlockIf).
            self.new_block_if(&block, &clause, i);
            return true;
        }
        false
    }

    // Ghidra: blockaction.cc:1416 CollapseStructure::ruleBlockIfElse
    /// ruleBlockIfElse: detect if-then-else pattern (cc:1416-1444).
    /// Mirrors the oracle guard-for-guard: binary condition that is not a
    /// switch dispatch (cc:1422), both out edges are plain decision edges
    /// (cc:1423-1424 — no irreducible/back/goto edge labels), each clause
    /// has exactly 1 in / 1 out (cc:1428-1432), the clauses exit to the
    /// same block which is not the condition itself (cc:1433-1435), and
    /// neither clause is a switch dispatch nor has an unstructured jump out
    /// (cc:1437-1440).
    fn try_rule_if_else(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // (BLOCKSTRUCT2) cc:1421-1422 entry pair through the view.
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            } // cc:1421 Must be binary condition
            if switch_out {
                return false;
            } // cc:1422: `if (bl->isSwitchOut()) return false;`
        }
        let b = block.read().unwrap();
        // cc:1423-1424: `if (!bl->isDecisionOut(0)) return false; if
        // (!bl->isDecisionOut(1)) return false;` — refuse structuring
        // across unstructured/loopback edges (block.hh:336: decision =
        // not irreducible, not back, not goto).
        if !Self::out_edge_is_decision(&*b, 0) {
            return false;
        }
        if !Self::out_edge_is_decision(&*b, 1) {
            return false;
        }

        let cond_idx = b.get_index();
        // cc:1426-1427: `tc = bl->getTrueOut(); fc = bl->getFalseOut();`
        // — getTrueOut() = out[1], getFalseOut() = out[0] positionally
        // (block.hh:299-300; flow.rs:1045 pushes the fallthru edge first,
        // so out[0] is the false path in both implementations). The old
        // port read out[0] into the tc slot and out[1] into the fc slot,
        // printing the FALSE-path clause under `if` — inverted C vs the
        // oracle, which never negates here (cc:1442 newBlockIfElse(bl,tc,fc)
        // with no negateCondition). (W3) the clause miss path reads
        // ids + shadows; handles materialize at fire.
        let tc_point = match b.get_out(1) {
            Some(e) => e.point,
            None => return false,
        };
        let fc_point = match b.get_out(0) {
            Some(e) => e.point,
            None => return false,
        };
        drop(b);

        // cc:1428-1429: nothing else must hit either clause.
        // cc:1431-1432: only one exit from each clause.
        {
            if bank.expect_size_in(tc_point) != 1 || bank.expect_size_in(fc_point) != 1 {
                return false;
            }
            if bank.expect_size_out(tc_point) != 1 || bank.expect_size_out(fc_point) != 1 {
                return false;
            }
            // cc:1433-1434: `outblock = tc->getOut(0); if (outblock == bl)
            // return false;` — no loops (the common merge must not be the
            // condition block itself).
            let t_out0 = match bank.expect_out_edge(tc_point, 0) {
                Some(e) => bank.expect_index(e.point),
                None => return false,
            };
            if t_out0 == cond_idx {
                return false;
            }
            // cc:1435: `if (outblock != fc->getOut(0)) return false;` —
            // clauses must exit to the same place.
            let f_out0 = match bank.expect_out_edge(fc_point, 0) {
                Some(e) => bank.expect_index(e.point),
                None => return false,
            };
            if t_out0 != f_out0 {
                return false;
            }
            // cc:1437-1438: `if (tc->isSwitchOut()) return false; if
            // (fc->isSwitchOut()) return false;` — don't use a switch
            // (possibly with goto edges) as a clause.
            if bank.expect_flags(tc_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                return false;
            }
            if bank.expect_flags(fc_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                return false;
            }
            // cc:1439-1440: `if (tc->isGotoOut(0)) return false; if
            // (fc->isGotoOut(0)) return false;` — no unstructured jumps
            // out of either clause (label-based, works on structured
            // components too). (W3) goto label via the edge shadow
            // (block.hh:347 inline label read).
            if bank
                .expect_out_edge(tc_point, 0)
                .map(|e| e.flags & (crate::block::edge_flags::F_GOTO_EDGE | crate::block::edge_flags::F_IRREDUCIBLE_EDGE) != 0)
                .unwrap_or(false)
            {
                return false;
            }
            if bank
                .expect_out_edge(fc_point, 0)
                .map(|e| e.flags & (crate::block::edge_flags::F_GOTO_EDGE | crate::block::edge_flags::F_IRREDUCIBLE_EDGE) != 0)
                .unwrap_or(false)
            {
                return false;
            }
        }

        // (W3) fire path: clause handles materialize once.
        let tc = bank.expect_arc(tc_point);
        let fc = bank.expect_arc(fc_point);
        // Create BlockIf (if-then-else) via factory (block.cc:1840
        // newBlockIfElse: nodes = {cond, tc, fc}, forceOutputNum(1), no
        // condition negation).
        self.new_block_if_else(&block, &tc, &fc, i);
        true
    }

    // Ghidra: blockaction.cc:1450 CollapseStructure::ruleBlockGoto
    /// ruleBlockGoto, the sizeout==2 newBlockIfGoto case (cc:1460-1467):
    /// for the first out edge marked goto — if the TRUE edge (out[1]) is not
    /// the goto one, negateCondition so that it becomes the true edge, then
    /// wrap the block in an if-goto (newBlockIfGoto, block.cc:1799-1816:
    /// gotoTarget = getOut(1), forceFalseEdge(getOut(0)), removeEdge(true)).
    /// The previous implementation only accepted a goto on edge 1; goto
    /// marks landing on edge 0 (which the Ghidra
    /// TraceDAG/selectGoto freely produces) never structured, leaving the
    /// CBRANCH orphaned as a bare conditional statement.
    /// The sizeout==1 newBlockGoto case lives in try_rule_goto; the
    /// isSwitchOut → newBlockMultiGoto case (cc:1456-1458) is routed here and
    /// in try_rule_goto ahead of the sizeout dispatch (see new_block_multigoto).
    fn try_rule_if_goto(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // (BLOCKSTRUCT2) cc:1427-1429 entry pair through the view.
        {
            let (size_out, _) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }
        }
        let b = block.read().unwrap();
        // First goto-marked out edge (cc:1454-1455, isGotoOut on the edge
        // label — works for structured blocks like BlockCondition too).
        let goto_slot = if Self::out_edge_is_goto(&*b, 1) {
            1
        } else if Self::out_edge_is_goto(&*b, 0) {
            0
        } else {
            return false;
        };

        // cc:1456-1458: the isSwitchOut arm precedes the sizeout==2 arm in
        // the oracle's single ruleBlockGoto loop — a two-out switch block
        // with a goto edge goes to newBlockMultiGoto, never newBlockIfGoto
        // (which would swallow the switch dispatch as an if). The multigoto
        // edge index is the oracle loop's FIRST goto edge (lowest slot,
        // cc:1454), not the negate-preferring slot computed above.
        if b.get_flags() & crate::block::block_flags::SWITCH_OUT != 0 {
            let first_goto = if Self::out_edge_is_goto(&*b, 0) {
                0
            } else {
                goto_slot
            };
            drop(b);
            self.new_block_multigoto(i, first_goto);
            eprintln!(
                "[COLLAPSE] {} ruleBlockGoto: multigoto peeled 2-out switch edge {}",
                self.name, first_goto
            );
            return true;
        }

        // Ghidra's ruleBlockGoto (cc:1450-1475) is purely topological: no
        // CBRANCH requirement — newBlockIfGoto legitimately wraps structured
        // conditions (e.g. a BlockCondition) whose polarity lives in the
        // data flip. The previous CBRANCH gate left goto marks on such
        // blocks unconsumed, stalling collapseAll.
        let cond_idx = b.get_index();
        drop(b);

        // cc:1461-1464: `if (!bl->isGotoOut(1)) negateCondition(true)` — the
        // true branch must be the goto branch. out[0] is the fall-through
        // (false) path, so a slot==0 goto needs the real data flip
        // (BOOLEAN_FLIP + swapEdges, block.cc:2351), which also swaps the two
        // out edges: after it, getOut(1) is the goto target and getOut(0)
        // the fall-through, exactly the layout newBlockIfGoto expects.
        if goto_slot != 1 {
            if block.write().unwrap().negate_condition(true) {
                self.dataflow_change_count += 1;
            }
            // swap_edges (block.cc:218-233) swaps whole BlockEdge structs, so
            // the f_goto_edge EDGE label follows the moved edge — but Rudra's
            // block-level GOTO_EDGE_0/GOTO_EDGE_1 mirror flags do not follow.
            // Swap them here so is_goto_out (block.rs:1514, checks both) keeps
            // reporting the moved goto edge at its new slot, exactly as the
            // oracle's edge label does.
            let mut w = block.write().unwrap();
            let f = w.get_flags();
            let g0 = f & crate::block::block_flags::GOTO_EDGE_0 != 0;
            let g1 = f & crate::block::block_flags::GOTO_EDGE_1 != 0;
            let mut nf = f & !(crate::block::block_flags::GOTO_EDGE_0
                | crate::block::block_flags::GOTO_EDGE_1);
            if g1 {
                nf |= crate::block::block_flags::GOTO_EDGE_0;
            }
            if g0 {
                nf |= crate::block::block_flags::GOTO_EDGE_1;
            }
            w.set_flags(nf);
            drop(w);
        }

        // Post-negation edge layout (cc:1465 + block.cc:1799-1816).
        // (W2) the former body handle/index capture here was dead code —
        // removed; only the goto target handle survives.
        let goto_target = match block.read().unwrap().get_out(1) {
            Some(e) => self.graph_bank().expect_arc(e.point),
            None => return false,
        };

        // NOTE: no switch_case_indices guard on the body here — Ghidra's
        // ruleBlockGoto (cc:1446-1471) has no case-body pre-guard. The old
        // invented guard (`refreshSwitchCases` cascade marking) rejected
        // IfGoto wraps whose body was a CBRANCH-chain taken target — exactly
        // the jumptable-neighborhood loop heads — leaving selectGoto's goto
        // marks unconsumed and driving the cc:1275 exhausted path
        // (TRI2-STRUCT-IRREDUCIBLE-TRACE-0001). refreshSwitchCases has no
        // oracle counterpart at all.

        // Create BlockIf in newBlockIfGoto style (Ghidra block.cc:1799-1816):
        // - Only [cond] is consumed (body stays external as an out-edge)
        // - goto_target stores the unstructured goto edge target
        // - if_body is a placeholder (condition) — the real body is the
        //   external out[0] edge, preserved by identify_internal
        let if_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(BlockIf {
            owner_bank: std::sync::Weak::new(),
            bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
            index: cond_idx,
            condition: block.clone(),
            if_body: block.clone(), // placeholder; real body is external out-edge
            else_body: None,
            goto_target: Some(goto_target.clone()),
            goto_type: crate::block::goto_type::GOTO_GOTO,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));
        // Only consume [cond] (at install_idx=i). The body_block stays external.
        // identify_internal inherits cond's out-edges (body + goto_target) onto
        // the new BlockIf, so it has 2 out-edges.
        self.identify_internal(&if_block, &[], i);
        self.update_switch_case_reference(cond_idx, &if_block);
        // Faithful to Ghidra newBlockIfGoto: removeEdge(ret, ret->getTrueOut())
        // (block.cc:1814). BlockGraph::removeEdge is a FULL bilateral removal
        // (block.cc:1469-1481: find the slot in end->intothis, then
        // removeInEdge = halfDeleteInEdge + peer halfDeleteOutEdge), so the
        // target's in-edge AND the if_block's out-edge disappear together and
        // every surviving edge's reciprocal reverse_index stays consistent.
        // The former one-sided retain pair left stale reciprocal indices
        // (BLOCK-RECIPROCAL-OOB-0001).
        self.graph.remove_edge_blocks(&if_block, &goto_target);
        self.structure_change_count += 1;
        true
    }

    // Ghidra: block.cc:1720 BlockGraph::newBlockMultiGoto
    /// Faithful port of `BlockGraph::newBlockMultiGoto(bl, outedge)`
    /// (block.cc:1720-1753), invoked by ruleBlockGoto's isSwitchOut arm
    /// (blockaction.cc:1456-1458): peel the goto-marked out edge of a switch
    /// block out of the structured graph view.
    ///
    /// Oracle order (all four decisive semantics, see
    /// docs/alignment_docs/BLOCKMULTIGOTO_M1_SEMANTICS.md §A):
    ///   - `targetbl`/`isdefaultedge` captured BEFORE any mutation (cc:1724-
    ///     1725) — removeEdge below erases the edge and its label;
    ///   - already-t_multigoto: addEdge → removeEdge → (default) setDefaultGoto
    ///     (cc:1726-1732);
    ///   - fresh wrap: new BlockMultiGoto → origSizeOut captured BEFORE
    ///     identifyInternal (cc:1735) → identifyInternal(ret,[bl]) → addBlock
    ///     → addEdge(targetbl) → `if (targetbl != bl)` { `if (ret->sizeOut() !=
    ///     origSizeOut)` forceOutputNum(ret->sizeOut()+1) — restore a self
    ///     edge collapsed by identifyInternal; removeEdge(ret,targetbl) } →
    ///     (default) setDefaultGoto (cc:1733-1751);
    ///   - a self goto edge (targetbl == bl) is absorbed by identifyInternal
    ///     and NOT explicitly removed (cc:1748 comment).
    /// BlockMultiGoto::addEdge only records the target in `gotoedges` — no
    /// graph edge is created (block.hh:580), so removeEdge takes out the
    /// identifyInternal-inherited structured edge (bilateral, block.cc:1469).
    /// Public for the bilateral BLOCKSTRUCT-MULTIGOTO-0001 fixture (direct
    /// call, mirroring the oracle fixture's graph.newBlockMultiGoto).
    pub fn new_block_multigoto(&mut self, i: usize, outedge: usize) {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return,
        };
        // cc:1724-1725: FlowBlock *targetbl = bl->getOut(outedge);
        //          bool isdefaultedge = bl->isDefaultBranch(outedge);
        let (target, isdefaultedge, already_multigoto, orig_size_out, idx) = {
            let b = block.read().unwrap();
            let target = b.get_out(outedge).map(|e| self.graph_bank().expect_arc(e.point));
            let isdefaultedge = b.is_default_branch(outedge);
            let already = b.get_type() == crate::block::BlockType::MultiGoto;
            // cc:1735: origSizeOut must reflect the block BEFORE the wrap —
            // for the already-multigoto path the size comparison never runs,
            // so reading it here for both paths is harmless.
            let so = b.size_out();
            (target, isdefaultedge, already, so, b.get_index())
        };
        let Some(targetbl) = target else {
            return;
        };
        if already_multigoto {
            // cc:1726-1732: "Already one goto edge from this same block, we
            // add to existing structure" — ret = (BlockMultiGoto*)bl.
            {
                let mut mg = block.write().unwrap();
                if let Some(m) = mg.as_any_mut().downcast_mut::<BlockMultiGoto>() {
                    // cc:1728: ret->addEdge(targetbl);
                    m.add_goto_edge(targetbl.clone());
                }
            }
            // cc:1729: removeEdge(ret,targetbl);
            self.graph.remove_edge_blocks(&block, &targetbl);
            // RUDRA-GLUE: the peeled edge carried the goto mark on its
            // label (removed with the edge, as in the oracle); the
            // slot-indexed block mirrors must be re-derived or the edge
            // that shifts into the vacated slot inherits a false goto.
            Self::resync_goto_edge_mirrors(&block);
            if isdefaultedge {
                // cc:1730-1731: ret->setDefaultGoto();
                let mut mg = block.write().unwrap();
                if let Some(m) = mg.as_any_mut().downcast_mut::<BlockMultiGoto>() {
                    m.set_default_goto();
                }
            }
            // The caller (ruleBlockGoto cc:1450-1458 arm) returns true after
            // this mutation-only path, so Ghidra's collapseInternal re-enters
            // the scan (change=true) and ruleBlockSwitch fires on the very
            // next pass. Rudra's inner loop infers that change bool from a
            // structure_change_count delta, so this arm must bump it like
            // the fresh-wrap arm below does: without the bump the loop
            // declares a false fixpoint right after peeling the edge, the
            // freshly marked switch skip-edges starve, and selectGoto picks
            // foreign edges (getparameter blockstructure count 27 vs 26,
            // second multigoto on block 29 starving ruleBlockSwitch,
            // 2026-09-23).
            self.structure_change_count += 1;
            return;
        }
        // cc:1734: ret = new BlockMultiGoto(bl); — the constructor discards
        // bl (components arrive via identifyInternal), so the wrapped block
        // is held explicitly (getBlock(0) = wrapped), like BlockGoto::wrapped.
        let mg_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockMultiGoto {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: idx,
                flags: 0,
                parent: None,
                gotoedges: Vec::new(),
                defaultswitch: false,
                wrapped: Some(block.clone()),
                incoming: Vec::new(),
                outgoing: Vec::new(),
            }));
        // cc:1736-1739: nodes=[bl]; identifyInternal(ret,nodes); addBlock(ret).
        // identify_internal inherits the boundary edges AND propagates
        // f_switch_out (selfIdentify cc:925-926), keeping the multigoto a
        // switch block for ruleBlockSwitch (cc:1652).
        self.identify_internal(&mg_block, &[idx], i);
        // RUDRA-GLUE: keep any enclosing BlockSwitch's case references live
        // across the slot replacement (same glue as try_rule_goto /
        // try_rule_if_goto; Ghidra needs none — its caseblocks hold
        // FlowBlock pointers that survive identifyInternal).
        self.update_switch_case_reference(idx, &mg_block);
        // cc:1740: ret->addEdge(targetbl);
        {
            let mut mg = mg_block.write().unwrap();
            if let Some(m) = mg.as_any_mut().downcast_mut::<BlockMultiGoto>() {
                m.add_goto_edge(targetbl.clone());
            }
        }
        // cc:1741-1747: `if (targetbl != bl)` — pointer identity against the
        // ORIGINAL block (captured before the wrap), not the composite.
        if !Arc::ptr_eq(&targetbl, &block) {
            // cc:1742-1745: fewer out edges after identifyInternal ⟺ a self
            // edge was collapsed (switch out edges are already deduped);
            // forceOutputNum(sizeOut()+1) restores that self edge — it is
            // NOT the goto edge.
            let cur_size_out = mg_block.read().unwrap().size_out();
            if cur_size_out != orig_size_out {
                Self::force_output_num(&self.graph.bank, &mg_block, cur_size_out + 1);
            }
            // cc:1746: removeEdge(ret,targetbl); — remove the structured edge
            // to the goto target (bilateral, block.cc:1469-1481).
            self.graph.remove_edge_blocks(&mg_block, &targetbl);
            // RUDRA-GLUE: keep the slot-indexed goto mirrors consistent with
            // the surviving edge labels after the peel removal (the fresh
            // wrap starts mirror-free; this is defensive parity with the
            // already-multigoto path above).
            Self::resync_goto_edge_mirrors(&mg_block);
        }
        // else — the goto edge is a self edge and was removed by
        // identifyInternal (cc:1748).
        if isdefaultedge {
            // cc:1749-1750: ret->setDefaultGoto();
            let mut mg = mg_block.write().unwrap();
            if let Some(m) = mg.as_any_mut().downcast_mut::<BlockMultiGoto>() {
                m.set_default_goto();
            }
        }
        self.structure_change_count += 1;
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleGoto
    /// Ghidra ruleBlockGoto (blockaction.cc:1450), pure-goto branch (size_out==1).
    /// A block whose single out-edge is marked as goto (GOTO_EDGE_0) becomes a
    /// BlockGoto. This lets clip_extra_roots / select_and_mark_goto consumed:
    /// without it, goto-marked single-out blocks never get structured and the
    /// goto-cascade loops forever. Mirrors Ghidra newBlockGoto(bl): wrap bl in a
    /// BlockGoto storing the goto target, consume [bl], forceOutputNum(1).
    /// The BlockGoto behaves as a single node so surrounding cat/if rules can
    /// merge it; at emit time it renders the block's ops followed by a goto.
    ///
    /// Ghidra's ruleBlockGoto is purely topological — no block-type gate: a
    /// goto-marked single-out BlockList/BlockIf/... component (already
    /// collapsed by earlier rounds) is wrapped too. The previous Basic-only
    /// gate left such marks unconsumed, so selectGoto re-marked the same
    /// edge forever (the my_get_line/glob_word non-convergence,
    /// BLOCKSTRUCT-NORETURN-DEADREGION-0001).
    fn try_rule_goto(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // cc:1453-1455: `sizeout` captured before the scan; the loop finds the
        // FIRST goto-marked out edge (lowest slot wins). isGotoOut works on
        // every block type (edge label or the block-level GOTO_EDGE_0/1
        // mirrors) and on every slot >= 0 — a peeled switch can still have
        // dozens of live out edges with a goto mark on any of them.
        // (BLOCKSTRUCT2) the whole miss scan runs through the view: edge
        // labels via the edge-shadow table, the slot mirrors via the flags
        // shadow — the same two channels out_edge_is_goto reads through the
        // guard (its trailing trait call adds nothing beyond them: the
        // BlockBasic impl reads these same GOTO_EDGE_0/1 flag bits).
        // SENTINEL (bare fixture) keeps the guard form, byte-identical.
        let (idx, size_out, goto_edge, switch_out) = if self_id
            != <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL
        {
            let size_out = bank.expect_size_out(self_id);
            let flags = bank.expect_flags(self_id);
            let mut goto_edge: Option<usize> = None;
            for j in 0..size_out {
                let edge_goto = bank.out_edge(self_id, j).is_some_and(|e| {
                    e.flags
                        & (crate::block::edge_flags::F_GOTO_EDGE
                            | crate::block::edge_flags::F_IRREDUCIBLE_EDGE)
                        != 0
                });
                let mirror = (j == 0 && flags & crate::block::block_flags::GOTO_EDGE_0 != 0)
                    || (j == 1 && flags & crate::block::block_flags::GOTO_EDGE_1 != 0);
                if edge_goto || mirror {
                    goto_edge = Some(j);
                    break;
                }
            }
            if goto_edge.is_none() {
                return false;
            }
            (
                bank.expect_index(self_id),
                size_out,
                goto_edge,
                flags & crate::block::block_flags::SWITCH_OUT != 0,
            )
        } else {
            let b = block.read().unwrap();
            let size_out = b.size_out();
            let mut goto_edge: Option<usize> = None;
            for j in 0..size_out {
                if Self::out_edge_is_goto(&*b, j) {
                    goto_edge = Some(j);
                    break;
                }
            }
            if goto_edge.is_none() {
                return false;
            }
            let switch_out =
                b.get_flags() & crate::block::block_flags::SWITCH_OUT != 0;
            (b.get_index(), size_out, goto_edge, switch_out)
        };
        // cc:1456-1458: `if (bl->isSwitchOut()) { graph.newBlockMultiGoto(bl,i);
        // return true; }` — the isSwitchOut arm runs FIRST, ahead of the
        // sizeout==2/1 dispatch, so a switch block's goto edge is peeled into
        // a BlockMultiGoto no matter how many out edges remain
        // (BLOCKSTRUCT-MULTIGOTO-0001).
        if switch_out {
            let peeled_target_addr = block
                .read()
                .unwrap()
                .get_out(goto_edge.unwrap())
                .and_then(|e| {
                    crate::block::front_leaf(&bank.expect_arc(e.point))
                        .map(|l| crate::block::dbg_front_leaf_start_addr(&l))
                })
                .unwrap_or(0);
            self.new_block_multigoto(i, goto_edge.unwrap());
            eprintln!(
                "[COLLAPSE] {} ruleBlockGoto: multigoto peeled switch edge {} -> @{:#x}",
                self.name,
                goto_edge.unwrap(),
                peeled_target_addr
            );
            return true;
        }
        // Pure-goto case: size_out==1 with GOTO_EDGE_0. (size_out==2 with
        // GOTO_EDGE_1 is handled by try_rule_if_goto as newBlockIfGoto;
        // size_out>2 non-switch matches no arm — the oracle loop falls
        // through every remaining isGotoOut edge and returns false.)
        if size_out != 1 {
            return false;
        }
        if !Self::out_edge_is_goto(&*block.read().unwrap(), 0) {
            return false;
        }
        let goto_target = block.read().unwrap().get_out(0).map(|e| self.graph_bank().expect_arc(e.point));
        let goto_target = match goto_target {
            Some(t) => t,
            None => return false,
        };

        // Ghidra newBlockGoto (block.cc:1702-1713), in oracle order:
        //   1. cc:1705 `BlockGoto *ret = new BlockGoto(bl->getOut(0));`
        //      — capture the target BEFORE identifyInternal/removeEdge can
        //      destroy the out-edge; stored as the live dyn Arc (target_dyn)
        //      so getIndex (scopeBreak cc:2872) and getFrontLeaf (gotoPrints
        //      cc:2886) read the same object the oracle's pointer would.
        //   2. cc:1706-1708 `identifyInternal(ret,[bl])` — bl becomes the
        //      BlockGoto's single list component (getBlock(0) = wrapped);
        //      Rust holds it via the `wrapped` field so it survives
        //      identify_internal replacing its graph slot.
        //   3. cc:1709 `addBlock(ret)` — the install at slot i below.
        //   4. cc:1710 `forceOutputNum(1)` — after identify the composite
        //      inherits exactly one out-edge (to the target), so this is a
        //      no-op; modeled implicitly.
        //   5. cc:1711 `removeEdge(ret, ret->getOut(0))` — the bilateral
        //      removal below, leaving sizeOut==0 for downstream rules.
        // The legacy typed `goto_target` stays None: the collapse graph's
        // leaves are BlockCopy nodes whose originals are dyn-coerced, so a
        // shared-identity typed Arc is not recoverable; the frozen printc
        // emit path reads target_dyn once PRINTC-GOTOPRINTS-0001 lands.
        let goto_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(crate::block::BlockGoto {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: idx,
                flags: 0,
                parent: None,
                goto_target: None,
                target_dyn: Some(goto_target.clone()),
                wrapped: Some(block.clone()),
                goto_type: crate::block::goto_type::GOTO_GOTO,
                prints_precomputed: false,
                incoming: Vec::new(),
                outgoing: Vec::new(),
            }));
        // Consume the original block (at i). identify_internal captures its
        // boundary edges onto the BlockGoto so it has correct size_in for
        // further merging.
        self.identify_internal(&goto_block, &[idx], i);
        self.update_switch_case_reference(idx, &goto_block);
        // Faithful to Ghidra newBlockGoto: forceOutputNum(1) +
        // removeEdge(ret, ret->getOut(0)) (block.cc:1710-1711). The wrapped
        // component is single-out (the pure-goto rule precondition), so the
        // BlockGoto inherits exactly one out-edge (to the goto target);
        // removing it bilaterally (BlockGraph::removeEdge, block.cc:1469:
        // removeInEdge = halfDeleteInEdge + peer halfDeleteOutEdge) makes the
        // BlockGoto a sink for downstream rules (ruleBlockIfNoExit's
        // sizeOut()==0 clause test, ruleBlockCat) while keeping the target's
        // in-list and every reciprocal reverse_index consistent. The former
        // one-sided retain/clear pair left stale reciprocal indices
        // (BLOCK-RECIPROCAL-OOB-0001).
        self.graph.remove_edge_blocks(&goto_block, &goto_target);
        self.structure_change_count += 1;
        let la = crate::block::front_leaf(&goto_block)
            .map(|l| crate::block::dbg_front_leaf_start_addr(&l))
            .unwrap_or(0);
        eprintln!(
            "[COLLAPSE] {} ruleBlockGoto: wrapped block {} @{:#x} (size_out={})",
            self.name, idx, la, size_out
        );
        true
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleWhileDo
    /// ruleBlockWhileDo: detect while(cond) { body } pattern.
    /// A CBRANCH block with 2 out-edges, where one out-edge (clause) has
    /// size_in==1, size_out==1, and its single out-edge loops back to the
    /// CBRANCH block. Mirrors Ghidra's ruleBlockWhileDo (blockaction.cc:1518).
    fn try_rule_while_do(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // PERF-ARENA-FLIP-0001 (f) step 2: guard-phase snapshot view (the
        // fire path at the tail takes no view reads).
        // (BLOCKSTRUCT2) cc:1519-1520 entry pair through the view.
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }
            // cc:1525: `if (bl->isSwitchOut()) return false;` — f_switch_out
            // (BRANCHIND dispatch, set by build_copy per block.cc:2286), not the
            // invented CASE_BODY cascade marks.
            if switch_out {
                return false;
            }
        }
        let b = block.read().unwrap();
        // cc:1526-1528: `if (bl->getOut(0)==bl) return false; if (bl->getOut(1)==bl)
        // return false; if (bl->isInteriorGotoTarget()) return false;`
        let cond_idx_pre = b.get_index();
        // RUDRA-GLUE: bank-view self-loop checks (edge twins' index
        // shadows; unresolved twins fall back to the guard read).
            let self_loop = (0..2).any(|slot| {
                b.get_out_ref(slot).map_or(false, |e| {
                    match bank.index(e.point) {
                        Some(i) => i == cond_idx_pre,
                        None => bank.expect_index(e.point) == cond_idx_pre,
                    }
                })
            });
            if self_loop {
                return false;
            }
        if b.is_interior_goto_target() {
            return false;
        }
        // cc:1529-1530: neither branch may be unstructured.
        if Self::out_edge_is_goto(&*b, 0) {
            return false;
        }
        if Self::out_edge_is_goto(&*b, 1) {
            return false;
        }

        let cond_idx = b.get_index();
        for slot in 0..2 {
            // (W3) edge-shadow read: the clause miss path is pure
            // sizeIn/sizeOut/flags/out-edge reads (cc:1533-1536) — all
            // bank-served; the clause handle resolves only on the fire
            // path below (millions of miss steps vs one fire).
            let clause_point = match b.get_out(slot) {
                Some(e) => e.point,
                None => continue,
            };
            // cc:1533: `if (clauseblock->sizeIn() != 1) continue;` — plain
            // sizeIn, exactly as the oracle. The former
            // count_non_structural_in_edges (invented arm: edges from
            // switch dispatches and absorbed components discounted) accepted
            // clauses the oracle rejects; with the composite model now
            // faithful (min-index install + boundary-edge strip), stale
            // component edges no longer leak into live blocks and the plain
            // count is both correct and aligned.
            let clause_in = bank.expect_size_in(clause_point);
            if clause_in != 1 {
                continue;
            }
            if bank.expect_size_out(clause_point) != 1 {
                continue;
            }
            // cc:1534: `if (clauseblock->isSwitchOut()) continue;`
            if bank.expect_flags(clause_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                continue;
            }
            // Clause must loop back to the condition block
            let back_idx = match bank.expect_out_edge(clause_point, 0) {
                Some(e) => bank.expect_index(e.point),
                None => continue,
            };
            if back_idx != cond_idx {
                continue;
            }
            // Found while-do: cond block + clause (body) that loops back
            let clause_idx = bank.expect_index(clause_point);
            // cc:1538-1542: `bool overflow = bl->isComplex(); if ((i==0)!=overflow)
            // { if (bl->negateCondition(true)) dataflow_changecount += 1; }` —
            // the clause must be the TRUE out of bl unless overflow syntax is
            // used. out[0] is the fall-through/false path (block.hh:299), so a
            // slot==0 clause requires negating the condition (the real data
            // flip: BOOLEAN_FLIP + swapEdges, block.cc:2351). The old code
            // computed `negated = slot == 1` (inverted) and then DISCARDED it
            // (`let _ = negated`), so while guards were emitted with the
            // wrong polarity whenever the loop body sat on the fall-through
            // edge — the parseconfig.constprop.0 `while (in_RBP == 0)` vs
            // oracle `line != 0x0` symptom.
            let overflow = b.is_complex();
            drop(b);
            if (slot == 0) != overflow {
                if block.write().unwrap().negate_condition(true) {
                    self.dataflow_change_count += 1;
                }
            }
            // (W3) fire path: the clause handle materializes here (once
            // per fired rule), not on the miss path.
            let clause = bank.expect_arc(clause_point);
            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(crate::block::BlockWhileDo {
                    owner_bank: std::sync::Weak::new(),
                    bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                    index: cond_idx,
                    condition: block.clone(),
                    body: clause,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                    for_init: None,
                    for_iter: None,
                    initialize_op: None,
                    iterate_op: None,
                    loop_def: None,
                    overflow_syntax: overflow,
                }));
            // Ghidra newBlockWhileDo: identifyInternal([cond, cl]) + forceOutputNum(1).
            // Consume the body clause; self_identify captures its boundary edges.
            self.identify_internal(&while_block, &[clause_idx], i);
            self.update_switch_case_reference(cond_idx, &while_block);
            self.structure_change_count += 1;
            return true;
        }
        false
    }

    // Ghidra: blockaction.hh:46 LoopBody::tryRuleDoWhile
    /// ruleBlockDoWhile: detect do { body } while(cond) pattern.
    /// A CBRANCH block where one out-edge loops back to itself.
    /// Mirrors Ghidra's ruleBlockDoWhile (blockaction.cc:1555).
    fn try_rule_do_while(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // (BLOCKSTRUCT2) cc:1556-1557 entry pair through the view.
        {
            let (size_out, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }
            // cc:1561: `if (bl->isSwitchOut()) return false;` — f_switch_out
            // (BRANCHIND dispatch, set by build_copy per block.cc:2286), not the
            // invented CASE_BODY cascade marks.
            if switch_out {
                return false;
            }
        }
        let b = block.read().unwrap();
        // cc:1562-1563: `if (bl->isGotoOut(0)) return false; if
        // (bl->isGotoOut(1)) return false;` — a do/while whose back-edge or
        // exit edge is already marked unstructured must stay a goto (the
        // label-based test also sees marks on structured components).
        if Self::out_edge_is_goto(&*b, 0) {
            return false;
        }
        if Self::out_edge_is_goto(&*b, 1) {
            return false;
        }

        let cond_idx = b.get_index();
        // RUDRA-GLUE: bank-view guard — one read guard for the slot scan;
        // the target is only compared here (oracle getOut, block.hh:301).
        // Unresolved twins fall back to the guard read. Scoped so the view
        // drops before the &mut self fire path.
        let back_slot = {
            (0..2).find(|&slot| {
                b.get_out_ref(slot).map_or(false, |e| {
                    match bank.index(e.point) {
                        Some(i) => i == cond_idx,
                        None => bank.expect_index(e.point) == cond_idx,
                    }
                })
            })
        };
        let Some(slot) = back_slot else {
            return false;
        };
        drop(b);

        // cc:1566-1569: `if (i==0) { if (bl->negateCondition(true))
        // dataflow_changecount += 1; }` — a do-while must loop on the
        // TRUE condition. out[0] is the fall-through/false path
        // (block.hh:299), so a slot==0 back-edge requires the real data
        // flip (BOOLEAN_FLIP + swapEdges, block.cc:2351). The old port
        // omitted this, inverting do-while guards.
        if slot == 0 {
            if block.write().unwrap().negate_condition(true) {
                self.dataflow_change_count += 1;
            }
        }

        // Found do-while: this block loops back on itself
        let do_while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(crate::block::BlockDoWhile {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: cond_idx,
                condition: block.clone(),
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        // Ghidra newBlockDoWhile(condcl): identifyInternal([condcl]).
        // The condcl block is consumed so its boundary edges (entry from
        // outside the loop, exit to the fallthrough) are captured onto the
        // new BlockDoDoWhile. condcl sits at install_idx=i.
        self.identify_internal(&do_while_block, &[cond_idx], i);
        self.update_switch_case_reference(cond_idx, &do_while_block);
        self.structure_change_count += 1;
        true
    }

    // Ghidra: blockaction.hh:46 LoopBody::dominates
    fn dominates(
        &self,
        dom: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        node: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> bool {
        let dom_idx = dom.read().unwrap().get_index();
        let mut curr = node.clone();
        let max_depth = 1000; // Safety limit to prevent infinite traversal
        for _ in 0..max_depth {
            if curr.read().unwrap().get_index() == dom_idx {
                return true;
            }
            let immed_dom = curr.read().unwrap().get_immed_dom();
            match immed_dom {
                Some(weak_parent) => {
                    if let Some(parent) = weak_parent.upgrade() {
                        curr = parent;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }
        false
    }

    // Ghidra: blockaction.cc:1321 CollapseStructure::ruleBlockOr
    /// Try to fold an AND/OR short-circuit condition. Faithful to
    /// `ruleBlockOr` (blockaction.cc:1321-1371): detects two CBRANCH
    /// blocks sharing a clause exit, creates BlockCondition.
    pub fn try_rule_or(
        &mut self,
        i: usize,
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_id: crate::arena::BlockId,
        bank: &crate::block::BlockBankView,
    ) -> bool {
        // PERF-ARENA-FLIP-0001 (f) step 2: guard-phase snapshot view — hot
        // (BLOCKSTRUCT2) cc:1327-1330 entry guards through the caller's
        // pass-level view (re-held after every fire in the fixpoint loop).
        {
            let (size_out, _) = Self::entry_size_out_switch_out(block, self_id, bank);
            if size_out != 2 {
                return false;
            }
        }
        let b = block.read().unwrap();
        if b.is_goto_out(0) {
            return false;
        }
        if b.is_goto_out(1) {
            return false;
        }
        if b.is_switch_out() {
            return false;
        }
        // (W3) the block's own bank id, hoisted before the guard — the
        // self/peer comparisons below are pure id equality (oracle pointer
        // equality, one identity lookup per rule invocation).
        // (BLOCKSTRUCT2) the dispatch's own registered_id_of result is the
        // same value — no re-lookup.
        let block_point = self_id;

        for ii in 0..2 {
            // (W3) orblock handle resolves once (the is_complex guard below
            // is a virtual deep read); the clause/other-out comparisons are
            // pure id equality — no handles, no guards (oracle pointer
            // equality on getOut results, cc:1345-1353).
            let or_point = match b.get_out(ii) {
                Some(e) => e.point,
                None => continue,
            };
            // cc:1336: cannot be same block
            if or_point == block_point {
                continue;
            }
            let orblock = bank.expect_arc(or_point);
            let or = orblock.read().unwrap();
            // cc:1337-1342
            if or.size_in() != 1 {
                continue;
            }
            if or.size_out() != 2 {
                continue;
            }
            if or.is_interior_goto_target() {
                continue;
            }
            if or.is_switch_out() {
                continue;
            }
            if b.is_back_edge_out(ii) {
                continue;
            }
            if or.is_complex() {
                continue;
            }
            drop(or);
            // cc:1345: clauseblock is the other out of bl
            let clause_point = match b.get_out(1 - ii) {
                Some(e) => e.point,
                None => continue,
            };
            if clause_point == block_point {
                continue;
            }
            if clause_point == or_point {
                continue;
            }
            // cc:1348-1352: clauseblock must match one of orblock's outs
            let mut j_found: Option<usize> = None;
            for j in 0..2 {
                let or_out_point = orblock
                    .read()
                    .unwrap()
                    .get_out(j)
                    .map(|e| e.point);
                if let Some(oo) = or_out_point {
                    if oo == clause_point {
                        j_found = Some(j);
                        break;
                    }
                }
            }
            let j = match j_found {
                Some(j) => j,
                None => continue,
            };
            // cc:1353: orblock's other out must not loop back to bl
            let or_other_point = orblock
                .read()
                .unwrap()
                .get_out(1 - j)
                .map(|e| e.point);
            if let Some(oo) = or_other_point {
                if oo == block_point {
                    continue;
                }
            }
            drop(b);

            // cc:1358-1365: negate conditions to make OR pattern canonical.
            //   i==1: orblock must be the FALSE out of bl → negate bl so its
            //         true-out becomes the orblock edge.
            //   j==0: clauseblock must be the TRUE out of orblock → negate orblock.
            // negateCondition returns true when the underlying CBRANCH flip
            // toggled (dataflow change) — this is the only state tallied by
            // Ghidra's dataflow_changecount.
            if ii == 1 {
                if block.write().unwrap().negate_condition(true) {
                    self.dataflow_change_count += 1;
                }
            }
            if j == 0 {
                if orblock.write().unwrap().negate_condition(true) {
                    self.dataflow_change_count += 1;
                }
            }

            // cc:1367 + block.cc:1780: graph.newBlockCondition(bl, orblock)
            // The factory computes opc via getFalseOut()==b2 (block.cc:1785),
            // matching the post-negation edge state. After our ii==1 negation
            // of bl, bl's false-out (edge 0) is orblock → OR.
            self.new_block_condition(&block, &orblock, i);
            return true;
        }
        false
    }

    // Ghidra: blockaction.cc:1579 CollapseStructure::ruleBlockInfLoop
    /// Try to structure an infinite loop. Faithful to `ruleBlockInfLoop`
    /// (blockaction.cc:1579-1593):
    ///   - sizeOut == 1 (single out edge)
    ///   - !isGotoOut(0) (not a goto)
    ///   - getOut(0) == bl (falls into itself)
    ///   - newBlockInfLoop(bl)
    pub fn try_rule_inf_loop(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // (BLOCKSTRUCT2) cc:1582 entry sizeOut through the view.
        {
            let (sizeout, _) = Self::entry_size_out_switch_out(block, self_id, bank);
            if sizeout != 1 {
                return false;
            }
        }
        // cc:1589: not a goto
        if block.read().unwrap().is_goto_out(0) {
            return false;
        }
        // cc:1590: must fall into itself
        let out_idx = block
            .read()
            .unwrap()
            .get_out(0)
            .map(|e| bank.expect_index(e.point));
        if out_idx != Some(i as i32) {
            return false;
        }
        // cc:1591: graph.newBlockInfLoop(bl). Creates the BlockInfLoop node
        // wrapping the self-looping body, installed at i.
        self.new_block_inf_loop(&block, i);
        true
    }

    // Ghidra: blockaction.cc:1649 CollapseStructure::ruleBlockSwitch
    /// Try to structure a switch (BRANCHIND) block. Faithful to
    /// `ruleBlockSwitch` (blockaction.cc:1649-1723):
    ///   (1) isSwitchOut guard
    ///   (2) Find exitblock (obvious: sizeIn>1/sizeOut>1/self-loop;
    ///       fallback: first out with output)
    ///   (3) Validate all cases: no goto in/out, sizeIn==1, sizeOut<=1,
    ///       out must go to exitblock, no nested switch
    ///   (4) checkSwitchSkips — mark skip-to-exit case edges as gotos
    ///   (5) newBlockSwitch(cases, hasExit)
    // Ghidra: blockaction.cc:1607 CollapseStructure::checkSwitchSkips
    /// Faithful port of `CollapseStructure::checkSwitchSkips`
    /// (blockaction.cc:1607-1647):
    ///   - cc:1608: no exitblock -> nothing to check (build the switch).
    ///   - cc:1610-1628: scan the switch's out-edges — `anyskiptoexit` = a
    ///     NON-default edge straight to the exitblock; `defaultnottoexit` =
    ///     a default edge that does NOT go to the exitblock.
    ///   - cc:1630-1635: a t_multigoto switch block's recorded default goto
    ///     (BlockMultiGoto::hasDefaultGoto) also sets defaultnottoexit —
    ///     the peeled default edge is invisible to the cc:1617-1626 edge
    ///     scan, so the multigoto's flag is the only remaining witness.
    ///   - cc:1628-1636: without both flags there is nothing to mark.
    ///   - cc:1637-1643: mark every NON-default edge that goes straight to
    ///     the exitblock as a goto branch; return false so ruleBlockSwitch
    ///     reports "matched but adds gotos" and collapseInternal re-runs
    ///     (wrapping the newly marked edges) before the switch is built.
    /// `isDefaultBranch` reads the mirrored F_DEFAULTSWITCH_EDGE label
    /// (block.hh:320), installed by Funcdata::switchOver (funcdata_block.cc:
    /// 697 setDefaultSwitch(jt->getDefaultBlock())) — Rudra's equivalent
    /// wiring is funcdata.rs set_default_switch_mirrored.
    fn check_switch_skips(&mut self, switch_idx: usize, exitblock: Option<i32>) -> bool {
        // PERF-ARENA-FLIP-0001 (f) step 2: guard-phase snapshot view — hot
        let bank = self.graph.bank.hold();
        // cc:1608: if (exitblock == 0) return true;
        let Some(exit_idx) = exitblock else {
            return true;
        };
        let block = match self.graph.get_block(switch_idx) {
            Some(b) => b,
            None => return true,
        };
        let sizeout = block.read().unwrap().size_out();
        // cc:1612-1623: scan for the two flags.
        let mut defaultnottoexit = false;
        let mut anyskiptoexit = false;
        for edgenum in 0..sizeout {
            let (tgt_idx, is_default) = {
                let r = block.read().unwrap();
                match r.get_out(edgenum) {
                    Some(e) => (
                        bank.expect_index(e.point),
                        r.is_default_branch(edgenum),
                    ),
                    None => continue,
                }
            };
            if tgt_idx == exit_idx {
                if !is_default {
                    anyskiptoexit = true;
                }
            } else if is_default {
                defaultnottoexit = true;
            }
        }
        // cc:1628: no skip edges to the exit -> build the switch.
        if !anyskiptoexit {
            return true;
        }
        // cc:1630-1635: `if ((!defaultnottoexit)&&(switchbl->getType() ==
        // FlowBlock::t_multigoto)) { BlockMultiGoto *multibl =
        // (BlockMultiGoto *)switchbl; if (multibl->hasDefaultGoto())
        //   defaultnottoexit = true; }` — a default edge peeled off the
        // switch as an unstructured goto is invisible to the edge scan
        // above (removeEdge took it out), but its default-ness still means
        // "default does not go to the exit", enabling the skip marking.
        if !defaultnottoexit {
            let is_multigoto_default = {
                let r = block.read().unwrap();
                r.get_type() == crate::block::BlockType::MultiGoto
                    && r
                        .as_any()
                        .downcast_ref::<BlockMultiGoto>()
                        .map_or(false, |m| m.has_default_goto())
            };
            if is_multigoto_default {
                defaultnottoexit = true;
            }
        }
        // cc:1636: no default elsewhere -> build the switch.
        if !defaultnottoexit {
            return true;
        }
        // cc:1637-1643: mark non-default skip-to-exit edges as goto branches.
        let mut marked = false;
        for edgenum in 0..sizeout {
            let (tgt_idx, is_default) = {
                let r = block.read().unwrap();
                match r.get_out(edgenum) {
                    Some(e) => (
                        bank.expect_index(e.point),
                        r.is_default_branch(edgenum),
                    ),
                    None => continue,
                }
            };
            if tgt_idx == exit_idx && !is_default {
                self.set_goto_branch_on_block(&block, edgenum);
                marked = true;
            }
        }
        let _ = marked;
        // cc:1644: return false — "We match, but have special condition that
        // adds gotos" (blockaction.cc:1712).
        false
    }

    // Ghidra: blockaction.cc:1729 CollapseStructure::ruleCaseFallthru
    /// Faithful port of `ruleCaseFallthru` (blockaction.cc:1725-1762): look
    /// for a switch case that falls through to another switch case, starting
    /// from the (pre-formation) switch dispatch block. A case body with
    /// sizeIn<=2 and exactly one out-edge, whose target has sizeIn==2 (the
    /// other in-edge being the switch itself) and sizeOut<=1, is a fallthru
    /// candidate; every candidate's out(0) is marked goto
    /// (`setGotoBranch(0)`). At most one nonfallthru exit is allowed.
    ///
    /// The rule marks edges but builds NO structure; the next first-pass
    /// `ruleBlockGoto` wrap removes the marked edge, dropping the shared
    /// target's sizeIn so `ruleBlockSwitch`'s fallback exit resolution can
    /// succeed WITHOUT peeling a real case edge. BLOCKSTRUCT-SWITCH-
    /// CASEFALLTHRU-0001: the previous batch `collapse_case_fallthru` only
    /// inspected ALREADY-FORMED BlockSwitch composites, so on the stuck
    /// pre-formation graph it never fired; selectGoto then peeled the
    /// switch's case edge and the tail region landed outside the loop
    /// (glob_set: `goto LAB_00104c20` + `code_r0x00104c7c` back-edge family).
    fn try_rule_case_fallthru(
        &mut self,
        i: usize,
        block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        self_id: crate::arena::BlockId,
        bank: &crate::block::BlockBankView,
    ) -> bool {
        // cc:1732: if (!bl->isSwitchOut()) return false;
        // (BLOCKSTRUCT2) entry isSwitchOut through the caller's pass-level
        // view — the non-switch miss opens no guard (this rule runs once per
        // block per fullchange round).
        {
            let (_, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if !switch_out {
                return false;
            }
        }
        let sizeout = block.read().unwrap().size_out();
        let mut nonfallthru = 0usize;
        let mut fallthru: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        for j in 0..sizeout {
            let cur_point = match block.read().unwrap().get_out(j) {
                Some(e) => e.point,
                None => continue,
            };
            let curbl = bank.expect_arc(cur_point);
            // cc:1739: cannot exit to itself (pointer identity).
            if Arc::ptr_eq(&curbl, &block) {
                return false;
            }
            // (W2) shadow reads: the sizeIn/sizeOut guard pair is bank-served
            // (block.hh:312-313) — cc:1740 checks below read no peer lock.
            let (cur_sin, cur_sout) =
                (bank.expect_size_in(cur_point), bank.expect_size_out(cur_point));
            // cc:1740: sizeIn>2 OR sizeOut>1 counts as a (the at most one)
            // nonfallthru exit.
            if cur_sin > 2 || cur_sout > 1 {
                nonfallthru += 1;
            } else if cur_sout == 1 {
                // cc:1743-1748: candidate whose single out-edge lands on a
                // block shared only with the switch itself.
                let target_edge = {
                    let r = curbl.read().unwrap();
                    r.get_out(0).map(|e| (bank.expect_arc(e.point), e.point, e.reverse_index))
                };
                if let Some((target, tgt_point, inslot)) = target_edge {
                    // (W2) shadow reads: the target size guard pair (cc:1744).
                    let (tgt_sin, tgt_sout) =
                        (bank.expect_size_in(tgt_point), bank.expect_size_out(tgt_point));
                    if tgt_sin == 2 && tgt_sout <= 1 {
                        // cc:1745: inslot = curbl->getOutRevIndex(0) — the
                        // in-slot this edge occupies on the target; the
                        // OTHER in-edge must be the switch block itself.
                        if inslot == 0 || inslot == 1 {
                            let other = target
                                .read()
                                .unwrap()
                                .get_in((1 - inslot) as usize)
                                .map(|e| bank.expect_arc(e.point));
                            if let Some(other) = other {
                                if Arc::ptr_eq(&other, &block) {
                                    fallthru.push(curbl.clone());
                                }
                            }
                        }
                    }
                }
            }
            // cc:1750: can have at most 1 other exit block — checked DURING
            // the scan, so a second nonfallthru out aborts before any
            // marking happens.
            if nonfallthru > 1 {
                return false;
            }
        }
        // cc:1752: no fallthru candidates → nothing to do.
        if fallthru.is_empty() {
            return false;
        }
        // cc:1755-1759: mark each candidate's out(0) as goto, in discovery
        // order (setGotoBranch writes the f_goto_edge label on both edge
        // halves plus the interior goto flags).
        for curbl in &fallthru {
            self.set_goto_branch_on_block(curbl, 0);
        }
        true
    }

    // Ghidra: blockaction.cc:1649 CollapseStructure::ruleBlockSwitch
    /// Try to find a switch structure: find the exitblock, validate all
    /// cases converge, run checkSwitchSkips, then build the BlockSwitch.
    pub fn try_rule_switch(&mut self, i: usize, block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>, self_id: crate::arena::BlockId, bank: &crate::block::BlockBankView) -> bool {
        // (RUDRA_IRRED_DBG read once per process: this rule runs ~4M times
        // on giant functions and the per-try std::env::var (env lock +
        // alloc) was pure Rust bookkeeping; env is immutable at runtime,
        // decision value identical.)
        static IRRED_SW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let irred_sw = *IRRED_SW
            .get_or_init(|| std::env::var("RUDRA_IRRED_DBG").map(|v| v == "1").unwrap_or(false));
        // Ghidra cc:1652: if (!bl->isSwitchOut()) return false;
        // (BLOCKSTRUCT2) entry isSwitchOut through the view — the non-switch
        // miss (99%+ of tries) opens no guard.
        {
            let (_, switch_out) = Self::entry_size_out_switch_out(block, self_id, bank);
            if !switch_out {
                return false;
            }
        }
        let sizeout = block.read().unwrap().size_out();
        if irred_sw {
            let r = block.read().unwrap();
            let outs: Vec<String> = (0..r.size_out())
                .filter_map(|j| {
                    r.get_out(j).map(|e| {
                        // (W2) shadow read: index via the bank (debug face).
                        format!(
                            "{}@{:#x}(L{:x})",
                            self.graph_bank().expect_index(e.point),
                            crate::block::dbg_front_leaf_start_addr(
                                &self.graph_bank().expect_arc(e.point)
                            ),
                            e.flags
                        )
                    })
                })
                .collect();
            eprintln!(
                "[IRRED-SW] try blk{} fn={} ty={:?} fl={:#x} sizeout={} out=[{}]",
                r.get_index(),
                self.name,
                r.get_type(),
                r.get_flags(),
                r.size_out(),
                outs.join(",")
            );
        }

        // Ghidra cc:1656-1671: Find "obvious" exitblock.
        let mut exitblock: Option<i32> = None;
        for j in 0..sizeout {
            let cur_point = match block.read().unwrap().get_out(j) {
                Some(e) => e.point,
                None => continue,
            };
            // (W2) shadow reads: idx + the sizeIn/sizeOut guard pair
            // (cc:1659/1663/1667) — the whole scan is bank-served (the old
            // form resolved each target's Arc only to read its fields).
            let cur_idx = self.graph_bank().expect_index(cur_point);
            // cc:1659: self-loop (exit back to top)
            if cur_idx == i as i32 {
                exitblock = Some(cur_idx);
                break;
            }
            let (cur_sin, cur_sout) = (
                self.graph_bank().expect_size_in(cur_point),
                self.graph_bank().expect_size_out(cur_point),
            );
            if cur_sout > 1 {
                exitblock = Some(cur_idx);
                break;
            }
            if cur_sin > 1 {
                exitblock = Some(cur_idx);
                break;
            }
        }

        if exitblock.is_none() {
            // Ghidra cc:1672-1690: fallback — find first out with an output.
            for j in 0..sizeout {
                let cur_point = match block.read().unwrap().get_out(j) {
                    Some(e) => e.point,
                    None => continue,
                };
                let curbl = self.graph_bank().expect_arc(cur_point);
                let bank = self.graph_bank();
                // (W2) shadow read: cur_idx for the debug face.
                let cur_idx = bank.expect_index(cur_point);
                // cc:1679: In cannot be a goto
                if curbl.read().unwrap().is_goto_in(0) {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} fallback cc:1679 goto-in case blk{}",
                            i, cur_idx
                        );
                    }
                    return false;
                }
                // cc:1680: Must resolve nested switch first
                // (W2) shadow read: f_switch_out via the flags shadow
                // (block.hh:165).
                if bank.expect_flags(cur_point) & crate::block::block_flags::SWITCH_OUT != 0 {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} fallback cc:1680 nested switch blk{}",
                            i, cur_idx
                        );
                    }
                    return false;
                }
                // (W2) shadow read: sizeOut (block.hh:312).
                let cur_sout = bank.expect_size_out(cur_point);
                if cur_sout == 1 {
                    if curbl.read().unwrap().is_goto_out(0) {
                        if irred_sw {
                            eprintln!(
                                "[IRRED-SW] reject blk{} fallback cc:1682 goto-out case blk{}",
                                i, cur_idx
                            );
                        }
                        return false;
                    }
                    let out_idx = curbl
                        .read()
                        .unwrap()
                        .get_out(0)
                        .map(|e| self.graph_bank().expect_index(e.point));
                    match (exitblock, out_idx) {
                        (Some(e), Some(o)) if e != o => {
                            if irred_sw {
                                eprintln!("[IRRED-SW] reject blk{} fallback cc:1684 exit mismatch {} vs {}", i, e, o);
                            }
                            return false;
                        }
                        (None, Some(o)) => exitblock = Some(o),
                        _ => {}
                    }
                }
            }
        } else {
            // Ghidra cc:1692-1708: validate with determined exitblock.
            let exit_idx = exitblock.unwrap();
            if irred_sw {
                eprintln!("[IRRED-SW] blk{} obvious exit={}", i, exit_idx);
            }
            let exit_block = match self.graph.get_block(exit_idx as usize) {
                Some(b) => b,
                None => return false,
            };
            // cc:1693-1694: no in gotos to exitblock
            for k in 0..exit_block.read().unwrap().size_in() {
                if exit_block.read().unwrap().is_goto_in(k) {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1694 exit blk{} goto-in slot {}",
                            i, exit_idx, k
                        );
                    }
                    return false;
                }
            }
            // cc:1695-1696: no out gotos from exitblock
            for k in 0..exit_block.read().unwrap().size_out() {
                if exit_block.read().unwrap().is_goto_out(k) {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1696 exit blk{} goto-out slot {}",
                            i, exit_idx, k
                        );
                    }
                    return false;
                }
            }
            for j in 0..sizeout {
                let cur_point = match block.read().unwrap().get_out(j) {
                    Some(e) => e.point,
                    None => continue,
                };
                let curbl = self.graph_bank().expect_arc(cur_point);
                let bank = self.graph_bank();
                // (W2) shadow reads: idx + sizeIn/sizeOut guards
                // (cc:1700/1702) bank-served; the goto-label reads stay on
                // the peer (edge flags are not shadowed).
                let cur_idx = bank.expect_index(cur_point);
                if cur_idx == exit_idx {
                    continue;
                }
                // cc:1700: case can only have switch fall into it
                let cur_sin = bank.expect_size_in(cur_point);
                if cur_sin > 1 {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1700 case blk{} size_in={}",
                            i, cur_idx, cur_sin
                        );
                    }
                    return false;
                }
                // cc:1701: in cannot be goto
                if curbl.read().unwrap().is_goto_in(0) {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1701 case blk{} goto-in",
                            i, cur_idx
                        );
                    }
                    return false;
                }
                // cc:1702: at most 1 exit from case
                let cur_sout = bank.expect_size_out(cur_point);
                if cur_sout > 1 {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1702 case blk{} size_out={}",
                            i, cur_idx, cur_sout
                        );
                    }
                    return false;
                }
                if cur_sout == 1 {
                    if curbl.read().unwrap().is_goto_out(0) {
                        if irred_sw {
                            eprintln!(
                                "[IRRED-SW] reject blk{} cc:1704 case blk{} goto-out",
                                i, cur_idx
                            );
                        }
                        return false;
                    }
                    let out_idx = curbl
                        .read()
                        .unwrap()
                        .get_out(0)
                        .map(|e| self.graph_bank().expect_index(e.point));
                    if out_idx != Some(exit_idx) {
                        if irred_sw {
                            eprintln!(
                                "[IRRED-SW] reject blk{} cc:1705 case blk{} out={:?} != exit {}",
                                i, cur_idx, out_idx, exit_idx
                            );
                        }
                        return false;
                    }
                }
                // cc:1707: nested switch must resolve first
                if curbl.read().unwrap().is_switch_out() {
                    if irred_sw {
                        eprintln!(
                            "[IRRED-SW] reject blk{} cc:1707 case blk{} nested switch",
                            i, cur_idx
                        );
                    }
                    return false;
                }
            }
        }

        // Ghidra cc:1711-1712: checkSwitchSkips — mark skip-to-exit case
        // edges as unstructured gotos when the switch has a formal default
        // elsewhere, and let collapseInternal wrap them before building the
        // BlockSwitch (returning true = "a change was made", cc:1712).
        if !self.check_switch_skips(i, exitblock) {
            // cc:1711-1712 returns true having only set goto edge marks
            // (no structure mutation). Ghidra's collapseInternal sets its
            // local change=true from the rule's RETURN VALUE and rescans
            // immediately, so ruleBlockGoto consumes the fresh marks in
            // the next pass. Rudra's inner loop models that change bool as
            // a structure_change_count delta, so this mark-only arm must
            // bump it: without the bump the loop declares a false fixpoint
            // right after marking, the skip-edge gotos starve, and
            // selectGoto picks foreign edges instead (getparameter
            // blockstructure count 27 vs 26, first selectGoto divergence
            // at the (131,133)/(131,15) entries, 2026-09-23). This bumps
            // structure_change_count only — dataflow_change_count stays
            // untouched, exactly like the oracle's arm.
            self.structure_change_count += 1;
            return true;
        }

        // Ghidra cc:1714-1721: build cases list and create BlockSwitch. The
        // oracle's -cs- vector includes the dispatch block (cs[0]) because
        // identifyInternal consumes it; Rudra's BlockSwitch keeps the
        // dispatch in the `control` field and `cases` holds ONLY the case
        // bodies (aligned with case_values, which printc indexes jointly).
        // cc:3515 (addCase): isdefault = switchbl->isDefaultBranch(outindex)
        // — the out-edge installSwitchDefaults marked (the most-hit table
        // target, switchOver cc:2552-2568) is the formal default; Rudra
        // routes it to the separate default_case slot (Ghidra keeps it in
        // caseblocks tagged isdefault; printc.cc:3140-3145 prints `default:`
        // without labels either way).
        let switch_basic = crate::block::front_leaf(&block).and_then(|leaf| {
            let r = leaf.read().unwrap();
            r.as_any()
                .downcast_ref::<crate::block::BlockCopy>()
                .map(|c| c.original.clone())
        });
        let mut cases: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        let mut default_case: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
        // cc:3515 addCase isdefault: the default's construction-order index
        // in the oracle's caseblocks, recorded at whichever diversion site
        // pushes it (regular scan or the t_multigoto peel arm).
        let mut default_construct_index: Option<usize> = None;
        // cc:3513-3514 (addCase): isexit = (bl->sizeOut() == 1) for gt==0
        // cases — captured HERE, before identify_internal consumes the case
        // blocks (selfIdentify's replaceInEdge half-deletes their external
        // out-edge halves, block.cc:160-173, so post-consumption sizeOut is
        // 0 and the flag is not re-derivable at print time). gt!=0 (the
        // multigoto arm, appended below) sets isexit=false (cc:3512).
        let mut case_isexit: Vec<bool> = Vec::new();
        let mut default_isexit = false;
        let exit_idx = exitblock;
        for j in 0..sizeout {
            let cur_point = match block.read().unwrap().get_out(j) {
                Some(e) => e.point,
                None => continue,
            };
            let curbl = self.graph_bank().expect_arc(cur_point);
            // (W2) shadow reads: idx + the isexit sizeOut probe bank-served.
            let cur_idx = self.graph_bank().expect_index(cur_point);
            if Some(cur_idx) == exit_idx {
                continue;
            }
            // cc:3506-3515 (addCase): the case's coordinates resolve on the
            // UNDERLYING basic-block graph — `inindex =
            // basicbl->getInIndex(switchbl)`, `outindex =
            // basicbl->getInRevIndex(inindex)`, `isdefault =
            // switchbl->isDefaultBranch(outindex)` — never on the
            // structured graph's slot index j: newBlockMultiGoto peels
            // goto-marked dispatch edges out of the structured out list
            // (removeEdge, block.cc:1746), shifting every later slot down,
            // so a slot-indexed isDefaultBranch(j) would read the ORIGINAL
            // edge flags against SHIFTED targets. Observed: httpd main's
            // post-peel slot 1 held case 0x43's block while orig slot 1 was
            // the peeled default — 0x43 got diverted into the default slot
            // and its case vanished (BLOCKACTION-SWITCH-CASE-GOTO-WRAP-0001
            // symptom family). switch_case_basic_coords performs the same
            // basic-graph in-edge walk.
            let (is_default_edge, _outindex, _basic) =
                Self::switch_case_basic_coords(&switch_basic, &curbl);
            // (W2) shadow read: isexit sizeOut probe (cc:3512).
            let isexit_flag = self.graph_bank().expect_size_out(cur_point) == 1;
            if irred_sw {
                eprintln!(
                    "[IRRED-SW] capture fn={} case blk{} addr={:#x} isdefault={} isexit={} (size_out={})",
                    self.name,
                    cur_idx,
                    crate::block::dbg_front_leaf_start_addr(&curbl),
                    is_default_edge,
                    isexit_flag,
                    self.graph_bank().expect_size_out(cur_point)
                );
            }
            if is_default_edge {
                default_case = Some(curbl);
                default_isexit = isexit_flag;
                // cc:3515 addCase isdefault: the oracle pushes the default
                // as an ordinary caseblocks member HERE, at the scan
                // position — record that construction index (the
                // pre-finalizePrinting consumers' merged order must place
                // the default exactly here).
                default_construct_index = Some(cases.len());
                continue;
            }
            case_isexit.push(isexit_flag);
            cases.push(curbl);
        }

        // Create BlockSwitch node (Ghidra cc:1721: graph.newBlockSwitch).
        let ctrl_idx = block.read().unwrap().get_index();
        let mut case_values: Vec<Vec<u64>> = Vec::new();
        let mut index_varnode = None;
        let mut branchind_addr: Option<u64> = None;
        {
            let b = block.read().unwrap();
            for op_ref in &b.get_ops() {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_BRANCHIND && !op.inrefs.is_empty() {
                    index_varnode = Some(op.inrefs[0].clone());
                    // block.cc:630-639 FlowBlock::getJumptable reads the
                    // block's lastOp (the BRANCHIND) for findJumpTable.
                    branchind_addr = Some(op.get_seq_num().get_addr().as_u64());
                    break;
                }
            }
            for j in 0..sizeout {
                case_values.push(vec![j as u64]);
            }
        }
        // cc:1912 + cc:3488 + cc:3524: grabCaseBasic's CaseOrder recording
        // (basicblock/outindex/casemap/chain) and the ctor jumptable
        // resolution, both running "before the identifyInternal" like the
        // oracle.
        let (jump, case_order, default_order) =
            self.grab_case_order(&block, &cases, default_case.as_ref(), branchind_addr);
        let num_regular_cases = cases.len();
        // Ghidra newBlockSwitch (block.cc:1904-1919): identifyInternal(ret, cs)
        // consumes the dispatch block AND the case blocks into the component
        // (cs[0] is the switch block itself), forceOutputNum(1) when there is
        // an exit, and f_switch_out is cleared on the component. The previous
        // code built the BlockSwitch and DROPPED it without installing — the
        // removed collapse_switches pre-pass was the only real installer.
        let has_exit = exit_idx.is_some();
        let switch_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
            Arc::new(RwLock::new(BlockSwitch {
                owner_bank: std::sync::Weak::new(),
                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                index: ctrl_idx,
                control: block.clone(),
                cases,
                default_case,
                // cc:3510-3511 addCase: every regular case carries gototype 0
                // (only the multigoto arm appends f_goto_goto, cc:3552) — the
                // parallel array must be cases-length from construction.
                case_gototypes: vec![0; num_regular_cases],
                default_gototype: 0,
                // cc:3513-3514 addCase: isexit captured pre-consumption
                // (see the collection loop above).
                case_isexit,
                default_isexit,
                default_construct_index,
                jump,
                case_order,
                default_label: None,
                default_order,
                case_values,
                index_varnode,
                incoming: Vec::new(),
                outgoing: Vec::new(),
                parent: None,
                flags: 0,
            }));
        // Consume the case bodies (dispatch sits at install_idx=i).
        let case_consumed: Vec<i32> = {
            let sb = switch_block.read().unwrap();
            let sref = sb.as_any().downcast_ref::<BlockSwitch>().unwrap();
            let mut v = Vec::new();
            for case in &sref.cases {
                let ci = case.read().unwrap().get_index();
                if ci as usize != i {
                    v.push(ci);
                }
            }
            // cc:1714-1720: the oracle's -cs- vector holds EVERY out block
            // except the exitblock — including the DEFAULT case (Ghidra
            // keeps it in caseblocks tagged isdefault via addCase, cc:3515;
            // identifyInternal consumes it like any other component). The
            // previous collection skipped Rudra's default_case slot, leaving
            // the default body a top-level block whose dispatch->default
            // edge stayed external on the composite — the switch then
            // carried a spurious second out edge, ruleBlockInfLoop (needs
            // the single self fall-through) could not match, and a DoWhile
            // layer wrapped the loop instead (glob_set `do { do {` family).
            if let Some(d) = &sref.default_case {
                let di = d.read().unwrap().get_index();
                if di as usize != i {
                    v.push(di);
                }
            }
            v
        };
        self.identify_internal(&switch_block, &case_consumed, i);
        self.update_switch_case_reference(ctrl_idx, &switch_block);
        // (BLOCKSTRUCT2) registry push: the installed switch's graph slot
        // (identify installs at the min consumed slot — resolve by pointer
        // identity, the authoritative slot).
        if let Some(sw_slot) = self
            .graph
            .blocks
            .iter()
            .position(|b| Arc::ptr_eq(b, &switch_block))
        {
            self.switch_slots.push(sw_slot);
        }
        // Ghidra newBlockSwitch cc:1912: grabCaseBasic runs "before the
        // identifyInternal" but only RECORDS FlowBlock pointers — the oracle's
        // caseblocks hold components and gotoedge targets alike, and
        // consuming the components does not invalidate pointers. Rust cannot
        // append into the pre-install literal before identify_internal
        // consumes `cases` (the multigoto's gotoedge targets must NOT be
        // consumed — they stay in the surrounding graph exactly as in the
        // oracle, where cs excludes them), so the recording is appended to
        // the installed switch here: same pointers, same order (regular
        // cases from the out-edge scan above, then the multigoto arm's
        // f_goto_goto cases, block.cc:3548-3553).
        {
            let control_is_multigoto =
                block.read().unwrap().get_type() == crate::block::BlockType::MultiGoto;
            if control_is_multigoto {
                // cc:3548-3553: `if (cs[0]->getType() == t_multigoto) { ... for
                // (i=0;i<numgoto;++i) addCase(switchbl, gotoedgeblock->getGoto(i),
                // f_goto_goto); }` — each peeled goto edge target is re-added
                // as a case with gototype f_goto_goto (its body is NOT part
                // of the switch; the emitter prints the case label + a goto
                // statement, printc.cc:3334-3337).
                let switch_basic = crate::block::front_leaf(&block).and_then(|leaf| {
                    let r = leaf.read().unwrap();
                    r.as_any()
                        .downcast_ref::<crate::block::BlockCopy>()
                        .map(|c| c.original.clone())
                });
                let gotoedges: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
                    let r = block.read().unwrap();
                    r.as_any()
                        .downcast_ref::<BlockMultiGoto>()
                        .map(|m| m.gotoedges.clone())
                        .unwrap_or_default()
                };
                let numgoto = gotoedges.len();
                let mut sw = switch_block.write().unwrap();
                let sw_ref = sw.as_any_mut().downcast_mut::<BlockSwitch>().unwrap();
                sw_ref.case_gototypes = vec![0; sw_ref.cases.len()];
                // CR-GLOBATTR F1: the grab-time virtual default index —
                // `case_order.len()` BEFORE this arm pushes the re-added
                // goto cases. Chains recorded by grab_case_order against
                // the default point at THIS index.
                let grab_order_len = sw_ref.case_order.len();
                // case_isexit keeps its pre-consumption captures; only the
                // appended goto-arm cases below set their own (cc:3512).
                for target in gotoedges {
                    let (isdefault, outindex, basic) =
                        Self::switch_case_basic_coords(&switch_basic, &target);
                    if isdefault {
                        // The oracle's addCase tags this case isdefault (it
                        // prints `default:`); Rudra's BlockSwitch holds the
                        // default in its own slot. The oracle still records
                        // the CaseOrder entry; Rudra's separate default slot
                        // never prints labels for it, so no order record is
                        // needed (documented divergence, block.rs).
                        sw_ref.default_case = Some(target);
                        sw_ref.default_gototype = crate::block::goto_type::GOTO_GOTO;
                        // cc:3512: gt != 0 → isexit = false.
                        sw_ref.default_isexit = false;
                        // cc:3548-3553 append order: the oracle pushes this
                        // peeled-goto default into caseblocks at the CURRENT
                        // append position (regular cases + the preceding
                        // multigoto goto pushes). Record it — the out-edge
                        // rank heuristic cannot reconstruct the peel order
                        // (TRACEDAG-ROUND3-BBLOCK-MERGE-0001 root).
                        sw_ref.default_construct_index = Some(sw_ref.cases.len());
                    } else {
                        sw_ref.cases.push(target);
                        sw_ref
                            .case_gototypes
                            .push(crate::block::goto_type::GOTO_GOTO);
                        // cc:3512: gt != 0 → isexit = false.
                        sw_ref.case_isexit.push(false);
                        // Placeholder label coordinate = the basic-level
                        // out-edge slot (the oracle's real labels come from
                        // the jumptable index map in finalizePrinting,
                        // block.cc:3556-3591 — JUMPTABLE-TABLEAPI-0001).
                        sw_ref
                            .case_values
                            .push(outindex.map(|j| vec![j as u64]).unwrap_or_default());
                        // cc:3495 addCase for the goto arm: the CaseOrder
                        // record with basicblock/outindex (chain stays -1 —
                        // the arm is appended after the chain-fill loop).
                        sw_ref.case_order.push(crate::block::CaseOrder::placeholder(
                            basic,
                            outindex.map(|j| j as i32).unwrap_or(-1),
                        ));
                    }
                }
                // CR-GLOBATTR F1 remap: the g pushed entries occupy indices
                // [grab_order_len, grab_order_len+g) of case_order, so
                // finalize_case_labels' extended view places the virtual
                // default at index grab_order_len+g — one past the LAST
                // re-added case (the oracle's layout: the multigoto append
                // lands after every cs-collected member, default included,
                // block.cc:3548-3553). Any chain recorded against the
                // grab-time default index must shift by g or it silently
                // retargets the FIRST re-added case. Correct-by-construction
                // guards: (a) the re-added entries never enter grab's
                // casemap (their placeholders keep chain=-1 and the arm
                // registers no casemap slot), so chain==grab_order_len can
                // only be a grab-time default link; (b) regular-to-regular
                // links are < grab_order_len and stay; (c)
                // default_order.chain targets regular indices only (<
                // grab_order_len) or -1, never the default's own index.
                let appended = sw_ref.case_order.len() - grab_order_len;
                if appended > 0 {
                    let remapped = Self::remap_default_chain_indices(
                        &mut sw_ref.case_order,
                        grab_order_len,
                        appended,
                    );
                    // Post-condition invariant: after the shift, no chain
                    // points at grab_order_len — that slot now holds the
                    // first re-added case, which never participates in a
                    // fall-thru chain (chain=-1 from its placeholder).
                    debug_assert!(
                        sw_ref
                            .case_order
                            .iter()
                            .all(|co| co.chain != grab_order_len as i32),
                        "default chain remap left a stale link at the re-added case slot"
                    );
                    if std::env::var("RUDRA_BS_DUMP")
                        .map(|v| v == "1" || v == "2")
                        .unwrap_or(false)
                    {
                        eprintln!(
                            "[BLOCKSTRUCT] multigoto arm: case_order {} -> {} (+{} re-added), default chain links remapped k -> k+g: {}",
                            grab_order_len,
                            sw_ref.case_order.len(),
                            appended,
                            remapped
                        );
                    }
                }
                let _ = numgoto;
            }
        }
        // cc:1916-1917: forceOutputNum(1) when there is an exit (identify's
        // boundary capture already yields exactly the exit edge); clear
        // f_switch_out on the component — clearFlag is `flags &= ~fl`
        // (block.hh:156), NOT setFlag (`flags |= fl`, block.hh:155). This
        // clear is what lets ruleBlockSwitch's cc:1652 isSwitchOut gate
        // reject re-entry on the installed Switch component.
        {
            let mut sw = switch_block.write().unwrap();
            sw.clear_flags(crate::block::block_flags::SWITCH_OUT);
        }
        let _ = has_exit;
        self.structure_change_count += 1;
        eprintln!(
            "[BLOCKSTRUCT] switch structured at block {} ({} cases, exit={:?})",
            ctrl_idx, sizeout, exit_idx
        );
        true
    }

    // Ghidra: block.cc:3495 BlockSwitch::addCase
    /// The basic-level case coordinates `addCase` computes (block.cc:3506-
    /// 3515) for the multigoto goto-case arm: `inindex =
    /// basicbl->getInIndex(switchbl)` on the UNDERLYING basic-block graph —
    /// `switchbl` is newBlockSwitch cc:1912's `leafbl->subBlock(0)`, i.e. the
    /// switch's basic block whose edges the structured-graph removeEdge
    /// never touched — then `outindex = basicbl->getInRevIndex(inindex)` and
    /// `isdefault = switchbl->isDefaultBranch(outindex)` reading the basic
    /// edge label (installSwitchDefaults, funcdata_block.cc:687, lands on the
    /// basic graph; buildCopy duplicates labels into the copy graph, so both
    /// sides agree). Returns `(isdefault, basic out-edge slot, case basic
    /// block)` — the basic block is `CaseOrder::basicblock` (block.hh:757).
    fn switch_case_basic_coords(
        switch_basic: &Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        case_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    ) -> (bool, Option<usize>, Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>) {
        let Some(switch_basic) = switch_basic else {
            return (false, None, None);
        };
        // cc:3500: const FlowBlock *basicbl = bl->getFrontLeaf()->subBlock(0);
        let case_basic = crate::block::front_leaf(case_block).and_then(|leaf| {
            let r = leaf.read().unwrap();
            r.as_any()
                .downcast_ref::<crate::block::BlockCopy>()
                .map(|c| c.original.clone())
        });
        let Some(case_basic) = case_basic else {
            return (false, None, None);
        };
        // cc:3506: int4 inindex = basicbl->getInIndex(switchbl);
        let rev = {
            let cb = case_basic.read().unwrap();
            let bank = cb.bank();
            let switch_id = bank.registered_id_of(switch_basic);
            let mut found = None;
            for slot in 0..cb.size_in() {
                if let Some(e) = cb.get_in(slot) {
                    if e.point == switch_id {
                        // cc:3509: curcase.outindex = basicbl->getInRevIndex(inindex);
                        found = Some(e.reverse_index);
                        break;
                    }
                }
            }
            found
        };
        // Ghidra throws LowlevelError("Case block has become detached from
        // switch") at inindex==-1 (cc:3507-3508); the multigoto path cannot
        // detach (basic edges persist), so None degrades to "no coords".
        let Some(rev) = rev else {
            return (false, None, Some(case_basic));
        };
        let outindex = if rev >= 0 {
            Some(rev as usize)
        } else {
            None
        };
        // cc:3515: curcase.isdefault = switchbl->isDefaultBranch(curcase.outindex);
        let isdefault = match outindex {
            Some(j) => switch_basic.read().unwrap().is_default_branch(j),
            None => false,
        };
        (isdefault, outindex, Some(case_basic))
    }

    // Ghidra: block.cc:3524 BlockSwitch::grabCaseBasic
    /// The CaseOrder recording half of `grabCaseBasic` (cc:3527-3546): for
    /// each regular case component, resolve `CaseOrder::basicblock`
    /// (`bl->getFrontLeaf()->subBlock(0)`, cc:3500) and `outindex`
    /// (cc:3506-3509) on the underlying basic graph, build the casemap from
    /// out-edge slot to case index (cc:3527/3532), then fill the fall-thru
    /// `chain` links (cc:3536-3546) for case components already wrapped as
    /// BlockGoto: the goto target's basic block, when it is another switch
    /// case, links `chain = casemap[rev]`. Also resolves the ctor jumptable
    /// (`jump = ind->getJumptable()`, block.cc:3488 via FlowBlock::
    /// getJumptable block.cc:630-639: the BRANCHIND last-op looked up
    /// against Funcdata's tables by op address). The multigoto goto-arm
    /// (cc:3548-3553) is appended by the caller. RUDRA-GLUE: method on
    /// CollapseStructure because the jumptables live on Funcdata, which the
    /// oracle reaches through its FlowBlock back-pointer. pub for the
    /// bilateral blockstruct_switch_label_1204 fixture (the only Rust-visible
    /// production entry for the CaseOrder recording, mirroring the oracle
    /// fixture's grabCaseBasic call).
    pub fn grab_case_order(
        &self,
        switch_block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        cases: &[Arc<RwLock<dyn FlowBlock + Send + Sync>>],
        default_case: Option<&Arc<RwLock<dyn FlowBlock + Send + Sync>>>,
        branchind_addr: Option<u64>,
    ) -> (
        Option<Arc<RwLock<crate::jumptable::JumpTable>>>,
        Vec<crate::block::CaseOrder>,
        Option<crate::block::CaseOrder>,
    ) {
        // block.cc:3488 + block.cc:630-639: jump = ind->getJumptable().
        let jump = branchind_addr.and_then(|addr| {
            self.jump_tables
                .iter()
                .find(|jt| jt.read().unwrap().get_op_address().as_u64() == addr)
                .cloned()
        });
        // cc:1912: switchbl = leafbl->subBlock(0) — the switch's basic block.
        let switch_basic = crate::block::front_leaf(switch_block).and_then(|leaf| {
            let r = leaf.read().unwrap();
            r.as_any()
                .downcast_ref::<crate::block::BlockCopy>()
                .map(|c| c.original.clone())
        });
        let casemap_len = switch_basic
            .as_ref()
            .map(|b| b.read().unwrap().size_out())
            .unwrap_or(0);
        // cc:3527: vector<int4> casemap(switchbl->sizeOut(),-1);
        let mut casemap: Vec<i32> = vec![-1; casemap_len];
        let mut order: Vec<crate::block::CaseOrder> = Vec::with_capacity(cases.len());
        for (i, case) in cases.iter().enumerate() {
            let (_, outindex, basic) =
                Self::switch_case_basic_coords(&switch_basic, case);
            if let (Some(rev), Some(basic)) = (outindex, &basic) {
                let _ = basic;
                // cc:3532: casemap[caseblocks[i-1].outindex] = i-1;
                if rev < casemap.len() {
                    casemap[rev] = i as i32;
                }
            }
            // cc:3498-3505 addCase init: label=0, depth=0, chain=-1.
            order.push(crate::block::CaseOrder::placeholder(
                basic,
                outindex.map(|r| r as i32).unwrap_or(-1),
            ));
        }
        // cc:3529-3533's loop adds EVERY component in cs as an ordinary
        // caseblocks member — including the formal default (only the
        // isdefault flag from addCase cc:3515 distinguishes it). Rudra
        // routes the default body to the separate default_case slot, so
        // its CaseOrder lives as the VIRTUAL entry at index cases.len():
        // registered in the same casemap so a regular case's fall-thru
        // chain (cc:3544) can link to it, and carrying its own chain link
        // for the exotic default-falls-into-another-case shape.
        let mut default_order: Option<crate::block::CaseOrder> = default_case.and_then(|def| {
            let (_, outindex, basic) = Self::switch_case_basic_coords(&switch_basic, def);
            if outindex.is_none() && basic.is_none() {
                // Coordinates unresolvable — no casemap entry, no chain
                // target; finalize_case_labels' legacy fallback places
                // this default (the oracle's addCase would have thrown
                // LowlevelError, cc:3507-3508).
                return None;
            }
            if let Some(rev) = outindex {
                if rev < casemap.len() {
                    casemap[rev] = cases.len() as i32;
                }
            }
            Some(crate::block::CaseOrder::placeholder(
                basic,
                outindex.map(|r| r as i32).unwrap_or(-1),
            ))
        });
        // cc:3536-3546: fall-thru chaining — all fall-thru blocks are plain
        // gotos at this point; the goto target resolves to another case's
        // basic block via its in-edge from the switch block. The walk
        // covers the virtual default entry too: a default component that
        // is itself a BlockGoto into another case links its chain the
        // same way.
        let mut chain_targets: Vec<(usize, crate::block::BlockType)> = cases
            .iter()
            .map(|c| c.read().unwrap().get_type())
            .enumerate()
            .collect();
        if default_order.is_some() {
            if let Some(def) = default_case {
                chain_targets.push((cases.len(), def.read().unwrap().get_type()));
            }
        }
        for (i, ty) in chain_targets {
            if ty != crate::block::BlockType::Goto {
                continue;
            }
            let case = if i < cases.len() {
                cases[i].clone()
            } else if i == cases.len() {
                default_case.map(|d| d.clone()).unwrap()
            } else {
                continue;
            };
            // cc:3540: targetbl = ((BlockGoto *)casebl)->getGotoTarget();
            let target = {
                let r = case.read().unwrap();
                r.as_any()
                    .downcast_ref::<crate::block::BlockGoto>()
                    .and_then(|g| g.target_dyn.clone())
            };
            let Some(target) = target else {
                continue;
            };
            // cc:3541: basicbl = targetbl->getFrontLeaf()->subBlock(0);
            let target_basic = crate::block::front_leaf(&target).and_then(|leaf| {
                let r = leaf.read().unwrap();
                r.as_any()
                    .downcast_ref::<crate::block::BlockCopy>()
                    .map(|c| c.original.clone())
            });
            let Some(target_basic) = target_basic else {
                continue;
            };
            let Some(switch_basic) = &switch_basic else {
                continue;
            };
            // cc:3542: inindex = basicbl->getInIndex(switchbl);
            let rev = {
                let tb = target_basic.read().unwrap();
                // The target basic is the ORIGINAL bblocks block (op-parent
                // chain under the copy); its in-edges carry bblocks ids, so
                // the switch basic resolves in the TARGET's own bank.
                let bank = tb.bank();
                let switch_id = bank.registered_id_of(switch_basic);
                let mut found = None;
                for slot in 0..tb.size_in() {
                    if let Some(e) = tb.get_in(slot) {
                        if e.point == switch_id {
                            found = Some(e.reverse_index);
                            break;
                        }
                    }
                }
                found
            };
            // cc:3543: if (inindex == -1) continue; — goto target is not
            // another switch case.
            let Some(rev) = rev else {
                continue;
            };
            if rev >= 0 && (rev as usize) < casemap.len() {
                // cc:3544: curcase.chain = casemap[basicbl->getInRevIndex(inindex)];
                let chain = casemap[rev as usize];
                if i < cases.len() {
                    order[i].chain = chain;
                } else if let Some(def_order) = default_order.as_mut() {
                    def_order.chain = chain;
                }
            }
        }
        (jump, order, default_order)
    }

    // RUDRA-GLUE: index bookkeeping for Rudra's separate-default storage
    // shape — no single Ghidra counterpart function. The oracle's
    // grabCaseBasic appends the multigoto re-added cases AFTER every
    // cs-collected member (block.cc:3548-3553 lands after the chain-fill
    // loop cc:3536-3546, and the default IS a cs-collected member), so in
    // the oracle's flat caseblocks vector the default simply keeps its
    // grab-time index and chains stay valid. Rudra stores the default in
    // its own slot and finalize_case_labels materializes it as the virtual
    // entry at `case_order.len()` (after the re-added cases), so chains
    // recorded against the grab-time virtual index k must shift by the
    // appended count g once the multigoto arm has pushed. Shifts
    // `chain == k` to `chain == k + g` and returns how many links moved.
    fn remap_default_chain_indices(
        case_order: &mut [crate::block::CaseOrder],
        grab_order_len: usize,
        appended: usize,
    ) -> usize {
        let old_default_index = grab_order_len as i32;
        let new_default_index = (grab_order_len + appended) as i32;
        let mut moved = 0;
        for co in case_order.iter_mut() {
            if co.chain == old_default_index {
                co.chain = new_default_index;
                moved += 1;
            }
        }
        moved
    }

    // Ghidra: blockaction.hh:46 LoopBody::collapseLoops
    fn collapse_loops(&mut self) {
        self.graph.build_dom_tree();

        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }

            let mut true_is_backedge = false;
            let mut false_is_backedge = false;
            let mut true_target = None;
            let mut false_target = None;

            if b.size_out() == 2 {
                let ops = b.get_ops();
                let has_cbranch = ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                });

                if has_cbranch {
                    if let Some(true_edge) = b.get_out(0) {
                        true_target = Some(self.graph_bank().expect_arc(true_edge.point));
                        if self.dominates(&self.graph_bank().expect_arc(true_edge.point), &block) {
                            true_is_backedge = true;
                        }
                    }
                    if let Some(false_edge) = b.get_out(1) {
                        false_target = Some(self.graph_bank().expect_arc(false_edge.point));
                        if self.dominates(&self.graph_bank().expect_arc(false_edge.point), &block) {
                            false_is_backedge = true;
                        }
                    }
                }
            }

            let cond_idx = b.get_index();
            drop(b);

            if true_is_backedge && !false_is_backedge {
                if let Some(tb) = true_target {
                    if tb.read().unwrap().get_index() == cond_idx {
                        let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(crate::block::BlockDoWhile {
                                owner_bank: std::sync::Weak::new(),
                                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                                index: cond_idx,
                                condition: block.clone(),
                                incoming: Vec::new(),
                                outgoing: Vec::new(),
                                parent: None,
                                flags: 0,
                            }));
                        replacements.push((i, while_block));
                        self.structure_change_count += 1;
                        continue;
                    }
                }
            } else if false_is_backedge && !true_is_backedge {
                if let Some(fb) = false_target {
                    if fb.read().unwrap().get_index() == cond_idx {
                        let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(crate::block::BlockDoWhile {
                                owner_bank: std::sync::Weak::new(),
                                bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                                index: cond_idx,
                                condition: block.clone(),
                                incoming: Vec::new(),
                                outgoing: Vec::new(),
                                parent: None,
                                flags: 0,
                            }));
                        replacements.push((i, while_block));
                        self.structure_change_count += 1;
                        continue;
                    }
                }
            }

            // Simple While-Do check (A -> B -> A)
            if !true_is_backedge && !false_is_backedge {
                let b = block.read().unwrap();
                if b.size_out() == 2 {
                    if let (Some(te), Some(fe)) = (b.get_out(0), b.get_out(1)) {
                        let tb = self.graph_bank().expect_arc(te.point);
                        let _fb = self.graph_bank().expect_arc(fe.point);
                        drop(b);

                        // (W2) shadow reads: the sizeIn/sizeOut gate
                        // (cc: while-body shape) bank-served — the peer lock
                        // only serves the deep get_out walk.
                        if self.graph_bank().expect_size_out(te.point) == 1
                            && self.graph_bank().expect_size_in(te.point) == 1
                        {
                            if let Some(out_edge) = tb.read().unwrap().get_out(0) {
                                if self.graph_bank().expect_index(out_edge.point) == cond_idx {
                                    let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                        Arc::new(RwLock::new(BlockWhileDo {
                                            owner_bank: std::sync::Weak::new(),
                                            bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                                            index: cond_idx,
                                            condition: block.clone(),
                                            body: tb.clone(),
                                            incoming: Vec::new(),
                                            outgoing: Vec::new(),
                                            parent: None,
                                            flags: 0,
                                            for_init: None,
                                            for_iter: None,
                                            initialize_op: None,
                                            iterate_op: None,
                                            loop_def: None,
                                            overflow_syntax: false,
                                        }));
                                    replacements.push((i, while_block));
                                    self.structure_change_count += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Natural loop detection: find latch blocks with unconditional
        // BRANCH back to a dominating header (header has CBRANCH with 2 out).
        // This handles multi-block loop bodies that the simple A→B→A check misses.
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }
            if b.size_out() != 1 {
                continue;
            }

            let ops = b.get_ops();
            let has_branch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCH
            });
            if !has_branch {
                continue;
            }

            let target_edge = match b.get_out(0) {
                Some(e) => e,
                None => continue,
            };
            let latch_idx = b.get_index();
            drop(b);

            if !self.dominates(&self.graph_bank().expect_arc(target_edge.point), &block) {
                continue;
            }

            let header = self.graph_bank().expect_arc(target_edge.point);
            // (W2) shadow read: header_idx via the bank index shadow.
            let header_idx = self.graph_bank().expect_index(target_edge.point);

            if replacements
                .iter()
                .any(|(idx, _)| *idx == header_idx as usize)
            {
                continue;
            }
            if replacements
                .iter()
                .any(|(idx, _)| *idx == latch_idx as usize)
            {
                continue;
            }

            let header_has_cbranch = {
                let h = header.read().unwrap();
                if h.size_out() != 2 {
                    continue;
                }
                let ops = h.get_ops();
                ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                })
            };
            if !header_has_cbranch {
                continue;
            }

            let h = header.read().unwrap();
            let out0 = self.graph_bank().expect_arc(h.get_out(0).unwrap().point);
            let out1 = self.graph_bank().expect_arc(h.get_out(1).unwrap().point);
            let (out0_point, out1_point) =
                (h.get_out(0).unwrap().point, h.get_out(1).unwrap().point);
            drop(h);

            // (W2) shadow reads: out indexes via the bank (block.hh:160).
            let out0_idx = self.graph_bank().expect_index(out0_point);
            let out1_idx = self.graph_bank().expect_index(out1_point);

            let (body_entry, _exit_block) =
                if out0_idx == header_idx as i32 || out1_idx == latch_idx {
                    (out1.clone(), out0.clone())
                } else {
                    (out0.clone(), out1.clone())
                };

            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockWhileDo {
                    owner_bank: std::sync::Weak::new(),
                    bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                    index: header_idx,
                    condition: header.clone(),
                    body: body_entry,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                    for_init: None,
                    for_iter: None,
                    initialize_op: None,
                    iterate_op: None,
                    loop_def: None,
                    overflow_syntax: false,
                }));
            replacements.push((header_idx as usize, while_block));
            self.structure_change_count += 1;
        }

        // CBRANCH-latch loop detection: find blocks ending with CBRANCH
        // where one outgoing edge is a back-edge to a dominating header.
        // This handles do-while and while-do patterns where the latch
        // itself contains the loop condition (common in real binaries).
        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            if replacements.iter().any(|(idx, _)| *idx == i) {
                continue;
            }

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }
            if b.size_out() != 2 {
                continue;
            }

            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }

            let out0_edge = match b.get_out(0) {
                Some(e) => e,
                None => continue,
            };
            let out1_edge = match b.get_out(1) {
                Some(e) => e,
                None => continue,
            };

            let latch_idx = b.get_index();
            let out0_target = self.graph_bank().expect_arc(out0_edge.point);
            let out1_target = self.graph_bank().expect_arc(out1_edge.point);
            drop(b);

            let out0_is_backedge = self.dominates(&out0_target, &block);
            let out1_is_backedge = self.dominates(&out1_target, &block);

            // Exactly one edge should be a back-edge
            if out0_is_backedge == out1_is_backedge {
                continue;
            }

            let (header, _exit) = if out0_is_backedge {
                (out0_target.clone(), out1_target.clone())
            } else {
                (out1_target.clone(), out0_target.clone())
            };

            let header_idx = header.read().unwrap().get_index();

            if replacements
                .iter()
                .any(|(idx, _)| *idx == header_idx as usize)
            {
                continue;
            }

            // If latch == header, this is a self-loop do-while
            // (already handled in Phase 1 above, but catch any missed ones)
            if header_idx == latch_idx {
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockDoWhile {
                        owner_bank: std::sync::Weak::new(),
                        bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                        index: latch_idx,
                        condition: block.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                replacements.push((i, while_block));
                self.structure_change_count += 1;
                continue;
            }

            // Header is a different block from latch — this is a multi-block
            // loop where the latch contains the condition.
            // Check if header has a CBRANCH (while-do with condition at top AND bottom).
            // If header is a simple fall-through, it's a do-while with the
            // condition at the latch.
            let header_out_count = header.read().unwrap().size_out();

            if header_out_count <= 1 {
                // Header is a simple block → do-while with condition at latch
                let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(crate::block::BlockDoWhile {
                        owner_bank: std::sync::Weak::new(),
                        bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                        index: header_idx,
                        condition: block.clone(),
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                replacements.push((header_idx as usize, while_block));
                self.structure_change_count += 1;
            } else {
                // Header has CBRANCH too → while-do pattern:
                // header decides entry, latch decides repeat.
                // Use header as condition block, latch's block as body end.
                let h = header.read().unwrap();
                let (h_out0, h_out0_point) = match h.get_out(0) {
                    Some(e) => (Some(self.graph_bank().expect_arc(e.point)), Some(e.point)),
                    None => (None, None),
                };
                let (h_out1, _) = match h.get_out(1) {
                    Some(e) => (Some(self.graph_bank().expect_arc(e.point)), Some(e.point)),
                    None => (None, None),
                };
                drop(h);

                // Determine which of header's exits leads into the loop body
                let body_entry = if let (Some(ref ho0), Some(ho0_point)) = (&h_out0, h_out0_point) {
                    // (W2) shadow read: index via the bank (block.hh:160).
                    let ho0_idx = self.graph_bank().expect_index(ho0_point);
                    if ho0_idx == latch_idx || self.dominates(&block, ho0) {
                        h_out0.clone()
                    } else {
                        h_out1.clone()
                    }
                } else {
                    h_out1.clone()
                };

                if let Some(body) = body_entry {
                    let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                        Arc::new(RwLock::new(BlockWhileDo {
                            owner_bank: std::sync::Weak::new(),
                            bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                            index: header_idx,
                            condition: header.clone(),
                            body,
                            incoming: Vec::new(),
                            outgoing: Vec::new(),
                            parent: None,
                            flags: 0,
                            for_init: None,
                            for_iter: None,
                            initialize_op: None,
                            iterate_op: None,
                            loop_def: None,
                            overflow_syntax: false,
                        }));
                    replacements.push((header_idx as usize, while_block));
                    self.structure_change_count += 1;
                }
            }
        }

        for (idx, replacement) in replacements {
            if idx < self.graph.blocks.len() {
                                self.graph.bank.adopt(&replacement);
                self.graph.blocks[idx] = replacement;
            }
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::ruleBlockWhileDo
    /// Try to structure a WhileDo loop at block index `i`. Faithful to
    /// `CollapseStructure::ruleBlockWhileDo` (blockaction.cc:1518-1549).
    ///
    /// Ghidra's rule: bl has 2 out-edges (binary condition); for each out-edge
    /// i, the clauseblock must (a) have sizeIn()==1, (b) have sizeOut()==1,
    /// (c) not be a switch-out, and (d) its single out-edge must loop back to
    /// bl. Crucially, bl must NOT be `isGotoOut` on either edge — but break
    /// edges that were marked goto by selectGoto/TraceDAG are excluded, which
    /// is exactly how loops WITH breaks get structured (the break edge is the
    /// non-clause out-edge, marked goto so it's skipped here).
    ///
    /// Returns true if a WhileDo was created.
    fn rule_block_while_do(&mut self, i: usize) -> bool {
        let block = match self.graph.get_block(i) {
            Some(b) => b,
            None => return false,
        };
        // Collect candidate clause block without holding the read lock across
        // mutations (identify_internal needs write access).
        let candidate: Option<(
            (Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32),
            Option<crate::arena::BlockId>,
        )> = {
            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                return false;
            }
            if b.size_out() != 2 {
                return false;
            } // Must be binary condition
              // No switch-out (blockaction.cc:1525): head must not end in a switch.
            if b.get_ops().last().map_or(false, |o| {
                o.0.read().unwrap().opcode == crate::opcodes::OpCode::CPUI_BRANCHIND
            }) {
                return false;
            }
            let cond_idx = b.get_index();
            // No loop-at-this-point: out(i) != bl (blockaction.cc:1526-1527)
            for slot in 0..2 {
                if let Some(e) = b.get_out(slot) {
                    if self.graph_bank().expect_index(e.point) == cond_idx {
                        return false;
                    }
                }
            }
            // Faithful to blockaction.cc:1528-1530: in Ghidra, ruleBlockGoto has
            // already consumed break-edges (wrapped as BlockIfGoto) before
            // ruleBlockWhileDo runs, so neither edge is goto. In Rudra's staged
            // approach, the break-edge may still be marked goto on the loop head.
            // So we do NOT bail on goto edges here; instead we find the NON-goto
            // clause below. (isInteriorGotoTarget omitted — Rudra does not track it.)
            // Find the clause: out-edge slot whose target has sizeIn==1,
            // sizeOut==1, not switch-out, and loops back to bl (cc:1531-1547).
            let mut found: Option<(Arc<RwLock<dyn FlowBlock + Send + Sync>>, i32)> = None;
            let mut found_point: Option<crate::arena::BlockId> = None;
            for slot in 0..2 {
                // Skip goto-marked edges (break-edges): they should not be
                // structured as the loop body.
                if b.is_goto_out(slot) {
                    continue;
                }
                let clause_edge = match b.get_out(slot) {
                    Some(e) => e,
                    None => continue,
                };
                let clauseblock = self.graph_bank().expect_arc(clause_edge.point);
                // (W2) shadow reads: the sizeIn/sizeOut/type guards
                // (cc:1533-1535) bank-served; only the deep get_out walk
                // takes the peer lock.
                {
                    let bank = self.graph_bank();
                    if bank.expect_size_in(clause_edge.point) != 1 {
                        continue;
                    } // Nothing else must hit clause
                    if bank.expect_size_out(clause_edge.point) != 1 {
                        continue;
                    } // Only one way out of clause
                    if bank.btype_of(clause_edge.point) == Some(crate::block::BlockType::Switch) {
                        continue;
                    } // not switch-out
                }
                let loops_back = {
                    let cb = clauseblock.read().unwrap();
                    match cb.get_out(0) {
                        Some(e) => self.graph_bank().expect_index(e.point) == cond_idx,
                        None => false,
                    }
                };
                if loops_back {
                    // Clause must loop back to bl — found a WhileDo.
                    found = Some((clauseblock, cond_idx));
                    found_point = Some(clause_edge.point);
                    break;
                }
            }
            found.map(|t| (t, found_point))
        };

        if let Some(((clauseblock, cond_idx), Some(clause_point))) = candidate {
            // (W2) shadow read: body_idx via the bank index shadow.
            let body_idx = self.graph_bank().expect_index(clause_point);
            let while_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(crate::block::BlockWhileDo {
                    owner_bank: std::sync::Weak::new(),
                    bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                    index: cond_idx,
                    condition: block.clone(),
                    body: clauseblock,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                    for_init: None,
                    for_iter: None,
                    initialize_op: None,
                    iterate_op: None,
                    loop_def: None,
                    overflow_syntax: false,
                }));
            if i < self.graph.blocks.len() {
                self.graph.blocks[i] = while_block.clone();
                self.graph.bank.adopt(&while_block);
            }
            self.identify_internal(&while_block, &[body_idx], i);
            self.structure_change_count += 1;
            eprintln!(
                "[COLLAPSE] {} ruleBlockWhileDo head={} body={}",
                self.name, cond_idx, body_idx
            );
            return true;
        }
        false
    }
    // Ghidra: blockaction.hh:46 LoopBody::collapseConditions
    ///
    /// **Triangle** (if-then, no else):
    /// ```text
    ///     A (CBRANCH, 2-out)
    ///    / \
    ///   B   C
    ///    \ /
    ///     C  (B has 1 out → C)
    /// ```
    ///
    /// **Diamond** (if-then-else):
    /// ```text
    ///     A (CBRANCH, 2-out)
    ///    / \
    ///   B   C
    ///    \ /
    ///     D  (both B and C have 1 out → D)
    /// ```
    // Ghidra: blockaction.cc:1854 CollapseStructure::collapseConditions
    /// Run ruleBlockOr on every block. Faithful to `collapseConditions`
    /// (blockaction.cc:1854-1865): simply iterates all blocks and calls
    /// ruleBlockOr on each. Previously Rudra had a self-invented
    /// triangle/diamond detection algorithm here.
    // Ghidra: blockaction.cc:1854 CollapseStructure::collapseConditions
    /// Faithful to `collapseConditions` (blockaction.cc:1854-1865): a do-while
    /// fixpoint loop that repeatedly scans all blocks calling ruleBlockOr
    /// (try_rule_or) until no change. A single pass misses OR-chains of
    /// length >2; the fixpoint ensures transitive collapsing
    /// (e.g. ((a||b)||c) requires 2 passes).
    fn collapse_conditions(&mut self) {
        loop {
            let mut change = false;
            // cc:1858-1864: position-order scan over Ghidra's mutating list
            // (the `i < graph.getSize()` bound re-evaluates as Or-condition
            // composites are appended at the end and their components
            // removed). Walk virtual_list; the retained/pushed entries track
            // the oracle's list exactly.
            // (BLOCKSTRUCT2) pass-level view, re-held after every fire (the
            // fire's identify adopt publishes; the oracle's fixpoint keeps
            // scanning and so does this loop — the re-hold keeps every
            // subsequent read on a fresh epoch).
            let mut i: usize = 0;
            let mut bank = self.graph.bank.hold();
            while i < self.virtual_list.len() {
                let slot = self.virtual_list[i] as usize;
                i += 1;
                let Some(block) = self.graph.get_block(slot) else {
                    continue;
                };
                let self_id = self.graph.bank.registered_id_of(&block);
                if self.try_rule_or(slot, &block, self_id, &bank) {
                    change = true;
                    bank = self.graph.bank.hold();
                }
            }
            if !change {
                break;
            }
        }
    }

    // RUDRA-GLUE: collapse_bool_conditions (superseded; was self-invented duplicate of ruleBlockOr)
    /// DEPRECATED (B8): this was a hand-rolled duplicate of Ghidra's
    /// ruleBlockOr (blockaction.cc:1321) implemented via raw edge inspection
    /// and deferred replacement collection. It is now superseded by
    /// collapse_conditions (the fixpoint ruleBlockOr loop) which uses the
    /// new_block_condition factory for correct opc/edge handling. Kept as a
    /// thin delegate so any future caller routes through the faithful path.
    fn collapse_bool_conditions(&mut self) {
        self.collapse_conditions();
    }

    // Ghidra: blockaction.hh:46 LoopBody::collapseSequences
    /// Collapse linear sequences: when block A has exactly 1 out → block B,
    /// and B has exactly 1 in (from A), merge them into a `BlockList`.
    fn collapse_sequences(&mut self) {
        let size = self.graph.get_size();
        let mut merged: Vec<bool> = vec![false; size];

        for i in 0..size {
            if merged[i] {
                continue;
            }

            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }
            if b.size_out() != 1 {
                continue;
            }

            let succ_edge = match b.get_out(0) {
                Some(e) => e,
                None => continue,
            };
            let succ = self.graph_bank().expect_arc(succ_edge.point);
            // (W2) shadow read: succ_idx via the bank index shadow.
            let succ_idx = self.graph_bank().expect_index(succ_edge.point) as usize;
            drop(b);

            if succ_idx >= size || merged[succ_idx] || succ_idx == i {
                continue;
            }

            // (W2) shadow read: the successor's sizeIn==1 gate bank-served
            // (block.hh:313).
            if self.graph_bank().expect_size_in(succ_edge.point) != 1 {
                continue;
            }

            // Sequence match: merge block[i] and block[succ_idx] into BlockList
            // The BlockList's out-edges come from the LAST child's out-edges
            // (the sequence continues from where the last block ends).
            let succ_outs: Vec<crate::block::BlockEdge> = {
                let s = succ.read().unwrap();
                (0..s.size_out())
                    .filter_map(|slot| s.get_out(slot))
                    .collect()
            };
            let block_idx_val = block.read().unwrap().get_index();
            let mut list_bl = BlockList::new(block_idx_val, vec![block.clone(), succ.clone()]);
            list_bl.outgoing = succ_outs;
            let list_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(list_bl));

                        self.graph.bank.adopt(&list_block);
            self.graph.blocks[i] = list_block;
            merged[succ_idx] = true;
            // Record the containment (Ghidra: identifyInternal removes the
            // consumed node from the parent's list, block.cc:953-960, and
            // addBlock sets its `parent` to the composite, block.hh:78) so
            // subsequent collapse passes (collapse_loops, collapse_conditions,
            // etc.) skip it via the is_consumed membership test. NO f_dead
            // flag: identifyInternal never sets one. Do NOT clear_edges —
            // BlockList.children[1] still holds succ's Arc and the edges are
            // needed if succ is itself structured later. finalize_structure
            // physically removes consumed blocks at the end of collapse_all.
            self.graph
                .absorbed_into
                .insert(succ_idx as i32, block_idx_val);
            self.structure_change_count += 1;
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::collapseSwitches
    /// Phase1 switch pre-installer. DISABLED (2026-09-25, R17,
    /// BLOCKACTION-COLLAPSESWITCH-ISEEXIT-0001): Ghidra has no such
    /// pre-pass — the annotation target is the LoopBody class line, no
    /// collapseSwitches method exists; the oracle's ONLY BlockSwitch
    /// install point is CollapseStructure::ruleBlockSwitch
    /// (blockaction.cc:1649-1723) at collapseInternal maturity, where
    /// addCase's isexit=(bl->sizeOut()==1) (block.cc:3513-3514) is sound
    /// because every case's remaining out-edge goes to the formal
    /// exitblock. This pre-pass fired earlier, where the same read
    /// over-fired (14/17 true vs the oracle tree's 2/18 on the httpd main
    /// fixture, address-keyed; the previous hardcoded vec![false] was
    /// wrong on the same 2). Switches now install only via
    /// try_rule_switch (whose capture is oracle-exact 16/16 on the same
    /// fixture). Kept for reference like the R15 cascade; do not
    /// re-enable without re-validating against an instrumented oracle
    /// run.
    fn collapse_switches(&mut self) {
        let size = self.graph.get_size();
        let mut replacements: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> = Vec::new();

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();

            // Check if block contains BRANCHIND
            let ops = b.get_ops();
            let has_branchind = ops
                .iter()
                .any(|op_ref| op_ref.0.read().unwrap().opcode == OpCode::CPUI_BRANCHIND);
            if !has_branchind {
                continue;
            }

            // If any out-edge is marked as goto (by TraceDAG), skip switch
            // formation — the control flow should be structured as if/goto.
            let flags = b.get_flags();
            if flags
                & (crate::block::block_flags::GOTO_EDGE_0 | crate::block::block_flags::GOTO_EDGE_1)
                != 0
            {
                continue;
            }

            let size_out = b.size_out();
            if size_out < 1 {
                continue;
            }

            let mut index_varnode = None;
            let mut branchind_addr: Option<u64> = None;
            for op_ref in &ops {
                let op = op_ref.0.read().unwrap();
                if op.opcode == OpCode::CPUI_BRANCHIND && !op.inrefs.is_empty() {
                    index_varnode = Some(op.inrefs[0].clone());
                    // block.cc:3488 ctor jumptable lookup input.
                    branchind_addr = Some(op.get_seq_num().get_addr().as_u64());
                    break;
                }
            }

            let mut cases = Vec::new();
            let mut case_values = Vec::new();
            let mut default_case: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = None;
            // cc:3515 addCase isdefault: the default's construction-order
            // caseblocks index, recorded at the diversion site.
            let mut default_construct_index: Option<usize> = None;
            // cc:3513-3514 (addCase): isexit = (bl->sizeOut() == 1) for gt==0
            // cases — captured at collection time in the same form as the
            // rule path (try_rule_switch's loop). RETIRED-WITH-CAPTURE
            // (BLOCKACTION-COLLAPSESWITCH-ISEEXIT-0001): oracle
            // instrumentation (stage_isexit_1204, locked e40ed130) proved
            // this capture is only sound at ruleBlockSwitch maturity,
            // where cc:1697-1708's invariant (case sizeOut==1 iff its edge
            // is to the formal exitblock) holds — at this pre-pass's
            // earlier firing point the case bodies' out-edges still point
            // at the next case/merge block, so the same read over-fired
            // 14/17 true against the oracle tree's 2/18 (httpd main,
            // address-keyed). The call site is disabled; see the R17 note
            // there. The capture is kept so a re-enabled pre-pass cannot
            // regress to the previous hardcoded vec![false].
            let mut case_isexit: Vec<bool> = Vec::new();
            let mut default_isexit = false;
            // cc:3515 (addCase): the installSwitchDefaults-marked out-edge is
            // the formal default — route to the separate default_case slot.
            let switch_basic_orig = crate::block::front_leaf(&block).and_then(|leaf| {
                let r = leaf.read().unwrap();
                r.as_any()
                    .downcast_ref::<crate::block::BlockCopy>()
                    .map(|c| c.original.clone())
            });
            for j in 0..size_out {
                if let Some(edge) = b.get_out(j) {
                    // (g) guard-shadow: pure sizeOut guard — bank cell read.
                    let isexit_flag = self.graph_bank().expect_size_out(edge.point) == 1;
                    let is_default_edge = switch_basic_orig
                        .as_ref()
                        .map(|sb| sb.read().unwrap().is_default_branch(j))
                        .unwrap_or(false);
                    if is_default_edge {
                        default_case = Some(self.graph_bank().expect_arc(edge.point));
                        default_isexit = isexit_flag;
                        // cc:3515 addCase isdefault: construction-order
                        // index of this default in the oracle caseblocks
                        // (the out-edge scan position).
                        default_construct_index = Some(cases.len());
                        continue;
                    }
                    case_isexit.push(isexit_flag);
                    cases.push(self.graph_bank().expect_arc(edge.point));
                    case_values.push(vec![j as u64]);
                }
            }

            let ctrl_idx = b.get_index();
            drop(b);

            // block.cc:3524 grabCaseBasic CaseOrder recording + block.cc:3488
            // ctor jumptable resolution for this installer path too.
            let (jump, case_order, default_order) =
                self.grab_case_order(&block, &cases, default_case.as_ref(), branchind_addr);
            let num_cases_here = cases.len();

            let switch_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockSwitch {
                    owner_bank: std::sync::Weak::new(),
                    bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                    index: ctrl_idx,
                    control: block.clone(),
                    cases,
                    default_case,
                    // cc:3510-3511 addCase: regular cases carry gototype 0.
                    case_gototypes: vec![0; num_cases_here],
                    default_gototype: 0,
                    // cc:3513-3514 addCase: isexit captured at collection
                    // time (see the collection loop above).
                    case_isexit,
                    default_isexit,
                    default_construct_index,
                    jump,
                    case_order,
                default_label: None,
                    default_order,
                    case_values,
                    index_varnode,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));

            replacements.push((i, switch_block));
            self.structure_change_count += 1;
        }

        for (idx, replacement) in replacements {
            if idx < self.graph.blocks.len() {
                                self.graph.bank.adopt(&replacement);
                self.graph.blocks[idx] = replacement;
            }
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::collapseCbranchCascades
    /// Collapse CBRANCH cascades into `BlockSwitch`.
    ///
    /// Detects chains of blocks where each block ends with CBRANCH comparing
    /// the same variable to a different constant, implementing a switch-case
    /// via comparison cascades (cmp+je chains from GCC -O2).
    ///
    /// Pattern:
    ///   Block A: cmp var, K1 → je case1, fallthrough B
    ///   Block B: cmp var, K2 → je case2, fallthrough C
    ///   Block C: cmp var, K3 → je case3, fallthrough D (default)
    ///   case1, case2, case3 all → merge_point
    ///
    /// Fabricated logic with NO Ghidra counterpart. Ghidra's `ruleBlockSwitch`
    /// (blockaction.cc:1649) fires ONLY on isSwitchOut() blocks (set by
    /// CPUI_BRANCHIND), NEVER forming a switch from CBRANCH if/else-if chains.
    /// This function did the latter and produced ~16/18 spurious switches.
    /// DISABLED (blockaction.rs:695). Kept for reference; do not rename to
    /// rule_block_switch — that would falsely imply Ghidra correspondence.
    fn collapse_cbranch_cascades(&mut self) {
        use crate::opcodes::OpCode;

        let size = self.graph.get_size();
        let mut consumed: Vec<bool> = vec![false; size];
        let mut replacements: Vec<(usize, Vec<usize>, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> =
            Vec::new();

        for i in 0..size {
            if consumed[i] {
                continue;
            }
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };

            let b = block.read().unwrap();
            if b.get_type() != crate::block::BlockType::Basic
                && b.get_type() != crate::block::BlockType::Copy
            {
                continue;
            }
            if b.size_out() != 2 {
                continue;
            }

            // Check if this block ends with CBRANCH
            let ops = b.get_ops();
            let has_cbranch = ops.last().map_or(false, |op_ref| {
                op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
            });
            if !has_cbranch {
                continue;
            }

            // If CBRANCH has goto-marked edges (by TraceDAG), skip cascade
            // switch formation — control flow should be structured as if/goto.
            let cflags = b.get_flags();
            if cflags
                & (crate::block::block_flags::GOTO_EDGE_0 | crate::block::block_flags::GOTO_EDGE_1)
                != 0
            {
                continue;
            }

            // Get the taken target (case body) — edge 1
            let taken_block = match b.get_out(1) {
                Some(e) => self.graph_bank().expect_arc(e.point),
                None => continue,
            };
            drop(b);

            // Walk the fallthrough chain collecting consecutive CBRANCH blocks
            let mut chain: Vec<(usize, Arc<RwLock<dyn FlowBlock + Send + Sync>>)> =
                vec![(i, block.clone())];
            let mut case_bodies: Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> = vec![taken_block];
            let mut case_values: Vec<u64> = Vec::new();

            // Try to get case value for first block
            let first_ops = self.graph.blocks[i].read().unwrap().get_ops();
            case_values.push(self.get_cbranch_case_info(&first_ops).unwrap_or(0));

            let mut current_idx = i;
            let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
            visited.insert(i);
            loop {
                let current_block = match self.graph.get_block(current_idx) {
                    Some(b) => b,
                    None => break,
                };
                let cb = current_block.read().unwrap();
                if cb.size_out() != 2 {
                    break;
                }

                // Fallthrough = edge 0
                let fallthrough_edge = match cb.get_out(0) {
                    Some(e) => e,
                    None => break,
                };
                let next_block = self.graph_bank().expect_arc(fallthrough_edge.point);
                // (W2) shadow read: next_idx via the bank index shadow.
                let next_idx =
                    self.graph_bank().expect_index(fallthrough_edge.point) as usize;
                drop(cb);

                if visited.contains(&next_idx) {
                    break;
                }
                visited.insert(next_idx);

                if next_idx >= size || consumed[next_idx] || next_idx == current_idx {
                    break;
                }

                // Check if next block also has CBRANCH
                let nb = next_block.read().unwrap();
                // Stop cascade at structured blocks (WhileDo/DoWhile/If/etc) —
                // they are not part of a CBRANCH cascade and including them
                // produces duplicate case_values.
                let nb_type = nb.get_type();
                if nb_type != crate::block::BlockType::Basic
                    && nb_type != crate::block::BlockType::Copy
                {
                    break;
                }
                if nb.size_out() != 2 {
                    // Try following this non-CBRANCH block's single outgoing edge
                    // (skip over case body blocks in the chain)
                    if nb.size_out() == 1 {
                        if let Some(skip_edge) = nb.get_out(0) {
                            // (W2) shadow read: skip_idx via the bank index
                            // shadow.
                            let skip_idx =
                                self.graph_bank().expect_index(skip_edge.point) as usize;
                            let skip_block = self.graph_bank().expect_arc(skip_edge.point);
                            drop(nb);
                            if skip_idx < size && !consumed[skip_idx] && skip_idx != next_idx {
                                let sb = skip_block.read().unwrap();
                                if sb.size_out() == 2 {
                                    let skip_ops = sb.get_ops();
                                    let skip_has_cb = skip_ops.last().map_or(false, |op_ref| {
                                        op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                                    });
                                    if skip_has_cb {
                                        if let Some(skip_taken) = sb.get_out(1) {
                                            let st = self.graph_bank().expect_arc(skip_taken.point);
                                            drop(sb);
                                            let skip_block_ops = self.graph.blocks[skip_idx]
                                                .read()
                                                .unwrap()
                                                .get_ops();
                                            let cv = self
                                                .get_cbranch_case_info(&skip_block_ops)
                                                .unwrap_or(chain.len() as u64);
                                            chain.push((skip_idx, skip_block.clone()));
                                            case_bodies.push(st);
                                            case_values.push(cv);
                                            current_idx = skip_idx;
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
                let next_ops = nb.get_ops();
                let next_has_cbranch = next_ops.last().map_or(false, |op_ref| {
                    op_ref.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH
                });
                if !next_has_cbranch {
                    break;
                }

                // Get case body (taken = edge 1)
                let next_taken = match nb.get_out(1) {
                    Some(e) => self.graph_bank().expect_arc(e.point),
                    None => break,
                };
                drop(nb);

                // Get case value
                let next_block_ops = self.graph.blocks[next_idx].read().unwrap().get_ops();
                let case_val = self
                    .get_cbranch_case_info(&next_block_ops)
                    .unwrap_or(chain.len() as u64);

                chain.push((next_idx, next_block.clone()));
                case_bodies.push(next_taken);
                case_values.push(case_val);
                current_idx = next_idx;
            }

            // Need at least 3 comparisons to form a switch
            if chain.len() < 3 {
                continue;
            }

            // The last comparison's fallthrough is the default case
            let last_block = &chain.last().unwrap().1;
            let lb = last_block.read().unwrap();
            let default_case = lb.get_out(0).map(|e| self.graph_bank().expect_arc(e.point));
            drop(lb);

            // Build index_varnode by scanning all chain blocks for a valid
            // comparison. The first block is preferred, but CBRANCH cascades
            // sometimes have a non-standard head (e.g. a range guard) while
            // later blocks use the canonical INT_EQUAL pattern. Walking the
            // whole chain mirrors Ghidra's approach of finding the common
            // compared operand across all case blocks.
            let mut index_varnode: Option<Arc<RwLock<crate::varnode::Varnode>>> = None;
            for (chain_block_idx, _) in &chain {
                let chain_ops = self.graph.blocks[*chain_block_idx]
                    .read()
                    .unwrap()
                    .get_ops();
                if let Some(vn) = self.find_compared_varnode(&chain_ops) {
                    index_varnode = Some(vn);
                    break;
                }
            }
            // Fallback: if no block yielded a clean comparison chain, scan
            // every chain block for ANY comparison op with a non-const
            // operand. In a CBRANCH cascade every case compares the same
            // variable, so any non-const operand of any INT_* comparison in
            // any chain block is a valid switch index.
            if index_varnode.is_none() {
                for (chain_block_idx, _) in &chain {
                    let chain_ops = self.graph.blocks[*chain_block_idx]
                        .read()
                        .unwrap()
                        .get_ops();
                    for op_ref in chain_ops.iter() {
                        let op = op_ref.0.read().unwrap();
                        match op.opcode {
                            crate::opcodes::OpCode::CPUI_INT_EQUAL
                            | crate::opcodes::OpCode::CPUI_INT_NOTEQUAL
                            | crate::opcodes::OpCode::CPUI_INT_LESS
                            | crate::opcodes::OpCode::CPUI_INT_SLESS
                            | crate::opcodes::OpCode::CPUI_INT_LESSEQUAL
                            | crate::opcodes::OpCode::CPUI_INT_SLESSEQUAL => {
                                if op.inrefs.len() >= 2 {
                                    let i0 = op.inrefs[0].read().unwrap();
                                    let i1 = op.inrefs[1].read().unwrap();
                                    if i1.get_space() != crate::space::AddressSpace::Const {
                                        index_varnode = Some(op.inrefs[1].clone());
                                        break;
                                    } else if i0.get_space() != crate::space::AddressSpace::Const {
                                        index_varnode = Some(op.inrefs[0].clone());
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if index_varnode.is_some() {
                        break;
                    }
                }
            }

            // Create BlockSwitch
            let ctrl_idx = chain[0].1.read().unwrap().get_index();
            let case_vals: Vec<Vec<u64>> = case_values.iter().map(|v| vec![*v]).collect();

            let switch_block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                Arc::new(RwLock::new(BlockSwitch {
                    owner_bank: std::sync::Weak::new(),
                    bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                    index: ctrl_idx,
                    control: chain[0].1.clone(),
                    cases: case_bodies.clone(),
                    default_case,
                    case_gototypes: Vec::new(),
                    default_gototype: 0,
                    case_isexit: Vec::new(),
                    default_isexit: false,
                    jump: None,
                    case_order: Vec::new(),
                    default_label: None,
                    default_order: None,
                    default_construct_index: None,
                    case_values: case_vals,
                    index_varnode,
                    incoming: Vec::new(),
                    outgoing: Vec::new(),
                    parent: None,
                    flags: 0,
                }));

            let consumed_indices: Vec<usize> = chain.iter().map(|(idx, _)| *idx).collect();
            for &idx in &consumed_indices {
                consumed[idx] = true;
            }

            // Also consume the case body blocks
            for body in &case_bodies {
                let body_idx = body.read().unwrap().get_index() as usize;
                if body_idx < size {
                    consumed[body_idx] = true;
                }
            }
            if let Some(ref def) = switch_block
                .read()
                .unwrap()
                .as_any()
                .downcast_ref::<BlockSwitch>()
                .and_then(|s| s.default_case.as_ref())
            {
                let def_idx = def.read().unwrap().get_index() as usize;
                if def_idx < size {
                    consumed[def_idx] = true;
                }
            }

            replacements.push((i, consumed_indices, switch_block));
            self.structure_change_count += 1;
        }

        // Apply replacements
        for (primary_idx, extra_indices, replacement) in replacements {
            if primary_idx < self.graph.blocks.len() {
                self.graph.bank.adopt(&replacement);
            self.graph.bank.adopt(&replacement);
            self.graph.blocks[primary_idx] = replacement;
                for &idx in &extra_indices[1..] {
                    if idx < self.graph.blocks.len() {
                        // Don't clobber already-structured blocks (WhileDo/DoWhile/If/etc)
                        // created by structure_loops_first — only replace Basic/Copy blocks.
                        let is_structured = {
                            let b = self.graph.blocks[idx].read().unwrap();
                            let t = b.get_type();
                            t != crate::block::BlockType::Basic
                                && t != crate::block::BlockType::Copy
                        };
                        if is_structured {
                            continue;
                        }
                        // Create empty placeholder with valid index (no ops, no edges)
                        let placeholder: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                            Arc::new(RwLock::new(BlockBasic::new(idx as i32, Address::new(0))));
                        self.graph.bank.adopt(&placeholder);
                        self.graph.blocks[idx] = placeholder;
                    }
                }
            }
        }
    }

    // Ghidra: blockaction.hh:46 LoopBody::collapseCaseFallthru
    /// ruleCaseFallthru: absorb fallthrough successor blocks into switch case
    /// bodies. When a case body block doesn't end with RETURN/BREAK, its
    /// out-edge target is a "fallthrough" successor. If that successor has
    /// a single in-edge (from this case body), merge it into a BlockList.
    /// Mirrors Ghidra's ruleCaseFallthru (blockaction.cc:1707).
    fn collapse_case_fallthru(&mut self) -> bool {
        use crate::block::block_flags;
        let size = self.graph.get_size();
        let mut any_change = false;

        for i in 0..size {
            let block = match self.graph.get_block(i) {
                Some(b) => b,
                None => continue,
            };
            let bt = {
                let b = block.read().unwrap();
                b.get_type()
            };
            if bt != crate::block::BlockType::Switch {
                continue;
            }

            // Read case body indices and check for fallthrough
            let (case_indices, default_idx) = {
                let b = block.read().unwrap();
                let sw = match b.as_any().downcast_ref::<BlockSwitch>() {
                    Some(s) => s,
                    None => continue,
                };
                let ci: Vec<i32> = sw
                    .cases
                    .iter()
                    .map(|c| c.read().unwrap().get_index())
                    .collect();
                let di = sw
                    .default_case
                    .as_ref()
                    .map(|d| d.read().unwrap().get_index());
                (ci, di)
            };

            // For each case, build fallthrough chain and create BlockList
            let mut new_cases: Vec<Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>>> = Vec::new();
            for &case_idx in &case_indices {
                let case_body = match self.graph.get_block(case_idx as usize) {
                    Some(b) => b,
                    None => {
                        new_cases.push(None);
                        continue;
                    }
                };
                let chain =
                    self.build_fallthrough_chain(&case_body, size, i, &case_indices, default_idx);
                if chain.len() > 1 {
                    let lb: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                        Arc::new(RwLock::new(crate::block::BlockList::new(case_idx, chain)));
                    new_cases.push(Some(lb));
                    self.structure_change_count += 1;
                    any_change = true;
                } else {
                    new_cases.push(None);
                }
            }

            // Build default fallthrough chain
            let new_default: Option<Arc<RwLock<dyn FlowBlock + Send + Sync>>> =
                if let Some(di) = default_idx {
                    let def_body = match self.graph.get_block(di as usize) {
                        Some(b) => Some(b),
                        None => None,
                    };
                    if let Some(db) = def_body {
                        let chain =
                            self.build_fallthrough_chain(&db, size, i, &case_indices, default_idx);
                        if chain.len() > 1 {
                            let lb: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                                Arc::new(RwLock::new(crate::block::BlockList::new(di, chain)));
                            self.structure_change_count += 1;
                            any_change = true;
                            Some(lb)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Apply changes to BlockSwitch by replacing it
            if new_cases.iter().any(|c| c.is_some()) || new_default.is_some() {
                let b = block.read().unwrap();
                let sw = match b.as_any().downcast_ref::<BlockSwitch>() {
                    Some(s) => s,
                    None => continue,
                };
                let mut new_case_list = Vec::new();
                for (idx, nc) in new_cases.iter().enumerate() {
                    if let Some(ref lb) = nc {
                        new_case_list.push(lb.clone());
                    } else {
                        new_case_list.push(sw.cases[idx].clone());
                    }
                }
                let new_def = new_default.or_else(|| sw.default_case.clone());
                let ctrl_idx = sw.index;
                let ctrl = sw.control.clone();
                let cgt = sw.case_gototypes.clone();
                let dgt = sw.default_gototype;
                let cie = sw.case_isexit.clone();
                let die = sw.default_isexit;
                let cv = sw.case_values.clone();
                let iv = sw.index_varnode.clone();
                let jmpz = sw.jump.clone();
                let jo = sw.case_order.clone();
                let jdo = sw.default_order.clone();
                drop(b);

                let new_sw: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
                    Arc::new(RwLock::new(BlockSwitch {
                        owner_bank: std::sync::Weak::new(),
                        bank_slot: <crate::arena::BlockId as crate::arena::ArenaId>::SENTINEL,
                        index: ctrl_idx,
                        control: ctrl,
                        cases: new_case_list,
                        default_case: new_def,
                        case_gototypes: cgt,
                        default_gototype: dgt,
                        case_isexit: cie,
                        default_isexit: die,
                        jump: jmpz,
                        case_order: jo,
                        default_label: None,
                        default_order: jdo,
                        default_construct_index: None,
                        case_values: cv,
                        index_varnode: iv,
                        incoming: Vec::new(),
                        outgoing: Vec::new(),
                        parent: None,
                        flags: 0,
                    }));
                self.graph.bank.adopt(&new_sw);
                self.graph.blocks[i] = new_sw;
            }
        }
        any_change
    }

    // Ghidra: blockaction.hh:46 LoopBody::buildFallthroughChain
    fn build_fallthrough_chain(
        &self,
        start: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        size: usize,
        switch_idx: usize,
        case_indices: &[i32],
        default_idx: Option<i32>,
    ) -> Vec<Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
        use crate::block::block_flags;
        let mut chain = vec![start.clone()];
        let mut current = start.clone();
        loop {
            let cur = current.read().unwrap();
            if cur.get_flags() & block_flags::RETURN_TERMINAL != 0 {
                break;
            }
            if cur.size_out() == 0 {
                break;
            }
            let succ_edge = match cur.get_out(0) {
                Some(e) => e,
                None => break,
            };
            let succ = self.graph_bank().expect_arc(succ_edge.point);
            // (W2) shadow reads: idx/sizeIn/type gates bank-served
            // (block.hh:160/313/184).
            let succ_idx = self.graph_bank().expect_index(succ_edge.point);
            drop(cur);
            if succ_idx as usize >= size || succ_idx as usize == switch_idx {
                break;
            }
            if case_indices.contains(&succ_idx) {
                break;
            }
            if default_idx == Some(succ_idx) {
                break;
            }
            if self.graph_bank().expect_size_in(succ_edge.point) != 1 {
                break;
            }
            let st = self.graph_bank().btype_of(succ_edge.point);
            if st != Some(crate::block::BlockType::Basic)
                && st != Some(crate::block::BlockType::Copy)
            {
                break;
            }
            if chain
                .iter()
                .any(|b| b.read().unwrap().get_index() == succ_idx)
            {
                break;
            }
            chain.push(succ.clone());
            current = succ;
        }
        chain
    }

    // Ghidra: blockaction.hh:46 LoopBody::getCbranchComparedVar
    ///
    /// Handles two patterns:
    /// 1. Direct: CBRANCH(_, INT_EQUAL(var, const))
    /// 2. x86 flag: CBRANCH(_, ZF) where ZF = INT_EQUAL(INT_SUB(var, const), 0)
    ///
    /// Uses space+offset matching (SSA-safe).
    fn get_cbranch_compared_var(
        &self,
        ops: &[crate::op::PcodeOpRef],
    ) -> Option<(crate::space::AddressSpace, u64)> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH {
            return None;
        }
        if cb.inrefs.len() < 2 {
            return None;
        }

        let cond_vn = cb.inrefs[1].read().unwrap();
        let cond_space = cond_vn.get_space();
        let cond_offset = cond_vn.get_offset();
        let cond_size = cond_vn.get_size();
        drop(cond_vn);
        drop(cb);

        // Search backwards for the op that produces the condition (by space+offset+size)
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let out_vn = out.read().unwrap();
                if out_vn.get_space() == cond_space
                    && out_vn.get_offset() == cond_offset
                    && out_vn.get_size() == cond_size
                {
                    drop(out_vn);
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                            if op.inrefs.len() >= 2 {
                                let in0 = op.inrefs[0].read().unwrap();
                                let in1 = op.inrefs[1].read().unwrap();
                                if in1.get_space() == AddressSpace::Const
                                    && in0.get_space() != AddressSpace::Const
                                {
                                    if in1.get_offset() == 0 {
                                        // x86 cmp: INT_EQUAL(INT_SUB(var, const), 0)
                                        let s = in0.get_space();
                                        let o = in0.get_offset();
                                        let sz = in0.get_size();
                                        drop(in0);
                                        drop(in1);
                                        return self.find_sub_source(ops, s, o, sz);
                                    }
                                    return Some((in0.get_space(), in0.get_offset()));
                                } else if in0.get_space() == AddressSpace::Const
                                    && in1.get_space() != AddressSpace::Const
                                {
                                    if in0.get_offset() == 0 {
                                        let s = in1.get_space();
                                        let o = in1.get_offset();
                                        let sz = in1.get_size();
                                        drop(in0);
                                        drop(in1);
                                        return self.find_sub_source(ops, s, o, sz);
                                    }
                                    return Some((in1.get_space(), in1.get_offset()));
                                }
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        None
    }

    // Ghidra: blockaction.hh:46 LoopBody::findSubSource
    /// Helper: find INT_SUB(var, const) producing target varnode, return (var_space, var_offset).
    fn find_sub_source(
        &self,
        ops: &[crate::op::PcodeOpRef],
        ts: crate::space::AddressSpace,
        to: u64,
        tsz: usize,
    ) -> Option<(crate::space::AddressSpace, u64)> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const
                            && i0.get_space() != AddressSpace::Const
                        {
                            return Some((i0.get_space(), i0.get_offset()));
                        } else if i0.get_space() == AddressSpace::Const
                            && i1.get_space() != AddressSpace::Const
                        {
                            return Some((i1.get_space(), i1.get_offset()));
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    // Ghidra: blockaction.hh:46 LoopBody::getCbranchCaseInfo
    /// Extract the constant case value from a CBRANCH comparison.
    fn get_cbranch_case_info(&self, ops: &[crate::op::PcodeOpRef]) -> Option<u64> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH {
            return None;
        }
        if cb.inrefs.len() < 2 {
            return None;
        }
        let cv = cb.inrefs[1].read().unwrap();
        let cs = cv.get_space();
        let co = cv.get_offset();
        let csz = cv.get_size();
        drop(cv);
        drop(cb);

        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == cs && ov.get_offset() == co && ov.get_size() == csz {
                    drop(ov);
                    match op.opcode {
                        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                            if op.inrefs.len() >= 2 {
                                let i0 = op.inrefs[0].read().unwrap();
                                let i1 = op.inrefs[1].read().unwrap();
                                if i1.get_space() == AddressSpace::Const
                                    && i0.get_space() != AddressSpace::Const
                                {
                                    if i1.get_offset() == 0 {
                                        let s = i0.get_space();
                                        let o = i0.get_offset();
                                        let sz = i0.get_size();
                                        drop(i0);
                                        drop(i1);
                                        return self.find_sub_constant(ops, s, o, sz);
                                    }
                                    return Some(i1.get_offset());
                                } else if i0.get_space() == AddressSpace::Const
                                    && i1.get_space() != AddressSpace::Const
                                {
                                    if i0.get_offset() == 0 {
                                        let s = i1.get_space();
                                        let o = i1.get_offset();
                                        let sz = i1.get_size();
                                        drop(i0);
                                        drop(i1);
                                        return self.find_sub_constant(ops, s, o, sz);
                                    }
                                    return Some(i0.get_offset());
                                }
                            }
                        }
                        _ => {}
                    }
                    break;
                }
            }
        }
        None
    }

    // Ghidra: blockaction.hh:46 LoopBody::findSubConstant
    /// Helper: extract constant from INT_SUB producing target varnode.
    fn find_sub_constant(
        &self,
        ops: &[crate::op::PcodeOpRef],
        ts: crate::space::AddressSpace,
        to: u64,
        tsz: usize,
    ) -> Option<u64> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const {
                            return Some(i1.get_offset());
                        }
                        if i0.get_space() == AddressSpace::Const {
                            return Some(i0.get_offset());
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    // Ghidra: blockaction.hh:46 LoopBody::findComparedVarnode
    /// Find the actual varnode being compared for switch index display.
    ///
    /// Walks backwards from the CBRANCH's condition varnode. If the
    /// condition is defined directly by a comparison (INT_EQUAL etc.),
    /// returns the non-const operand. If it is defined by BOOL_NEGATE
    /// or COPY, chases through that op to find the underlying comparison.
    /// This handles cascades where the original comparison is negated or
    /// copied before being consumed by CBRANCH.
    fn find_compared_varnode(
        &self,
        ops: &[crate::op::PcodeOpRef],
    ) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;

        let cbranch_op = ops.last()?;
        let cb = cbranch_op.0.read().unwrap();
        if cb.opcode != OpCode::CPUI_CBRANCH {
            return None;
        }
        if cb.inrefs.len() < 2 {
            return None;
        }
        let cv = cb.inrefs[1].read().unwrap();
        let cs = cv.get_space();
        let co = cv.get_offset();
        let csz = cv.get_size();
        drop(cv);
        drop(cb);

        // Chase through COPY/BOOL_NEGATE/MULTIEQUAL to find the comparison.
        // Bound the chase depth to avoid pathological loops.
        let mut target = (cs, co, csz);
        for _ in 0..4 {
            let def_op = ops.iter().rev().find_map(|op_ref| {
                let op = op_ref.0.read().unwrap();
                if let Some(ref out) = op.output {
                    let ov = out.read().unwrap();
                    if ov.get_space() == target.0
                        && ov.get_offset() == target.1
                        && ov.get_size() == target.2
                    {
                        return Some(op_ref.clone());
                    }
                }
                None
            })?;

            let def = def_op.0.read().unwrap();
            match def.opcode {
                OpCode::CPUI_INT_EQUAL
                | OpCode::CPUI_INT_NOTEQUAL
                | OpCode::CPUI_INT_LESS
                | OpCode::CPUI_INT_SLESS
                | OpCode::CPUI_INT_LESSEQUAL
                | OpCode::CPUI_INT_SLESSEQUAL => {
                    if def.inrefs.len() >= 2 {
                        let i0 = def.inrefs[0].read().unwrap();
                        let i1 = def.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const
                            && i0.get_space() != AddressSpace::Const
                        {
                            if i1.get_offset() == 0 {
                                let s = i0.get_space();
                                let o = i0.get_offset();
                                let sz = i0.get_size();
                                drop(i0);
                                drop(i1);
                                return self.find_sub_var_vn(ops, s, o, sz);
                            }
                            drop(i0);
                            drop(i1);
                            return Some(def.inrefs[0].clone());
                        } else if i0.get_space() == AddressSpace::Const
                            && i1.get_space() != AddressSpace::Const
                        {
                            if i0.get_offset() == 0 {
                                let s = i1.get_space();
                                let o = i1.get_offset();
                                let sz = i1.get_size();
                                drop(i0);
                                drop(i1);
                                return self.find_sub_var_vn(ops, s, o, sz);
                            }
                            drop(i0);
                            drop(i1);
                            return Some(def.inrefs[1].clone());
                        }
                    }
                    return None;
                }
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL => {
                    if def.inrefs.is_empty() {
                        return None;
                    }
                    let src = def.inrefs[0].read().unwrap();
                    target = (src.get_space(), src.get_offset(), src.get_size());
                    drop(src);
                }
                _ => return None,
            }
        }
        None
    }

    // Ghidra: blockaction.hh:46 LoopBody::findSubVarVn
    /// Helper: find the non-const varnode input of INT_SUB producing target.
    fn find_sub_var_vn(
        &self,
        ops: &[crate::op::PcodeOpRef],
        ts: crate::space::AddressSpace,
        to: u64,
        tsz: usize,
    ) -> Option<Arc<RwLock<crate::varnode::Varnode>>> {
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        for op_ref in ops.iter().rev() {
            let op = op_ref.0.read().unwrap();
            if let Some(ref out) = op.output {
                let ov = out.read().unwrap();
                if ov.get_space() == ts && ov.get_offset() == to && ov.get_size() == tsz {
                    drop(ov);
                    if op.opcode == OpCode::CPUI_INT_SUB && op.inrefs.len() >= 2 {
                        let i0 = op.inrefs[0].read().unwrap();
                        let i1 = op.inrefs[1].read().unwrap();
                        if i1.get_space() == AddressSpace::Const {
                            drop(i0);
                            drop(i1);
                            return Some(op.inrefs[0].clone());
                        } else if i0.get_space() == AddressSpace::Const {
                            drop(i0);
                            drop(i1);
                            return Some(op.inrefs[1].clone());
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    // Ghidra: blockaction.hh:224 CollapseStructure::getChangeCount
    pub fn get_change_count(&self) -> i32 {
        self.dataflow_change_count
    }
}

/// Action for performing final transformations on the block structure
///
/// Corresponds to Ghidra's `ActionFinalStructure`.
/// Tags remaining unstructured branches as GOTO and removes unreachable
/// ops that follow unconditional BRANCH or RETURN within a basic block.
pub struct ActionFinalStructure;

impl ActionFinalStructure {
    // Ghidra: blockaction.hh:324 ActionFinalStructure::new
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionFinalStructure {
    // Ghidra: blockaction.cc:2186 ActionFinalStructure::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        use crate::op::branch_type;

        // Ghidra blockaction.cc:2186-2197: this action runs five wired graph
        // calls (orderBlocks/finalizePrinting/scopeBreak/markUnstructured/
        // markLabelBumpUp) and unconditionally returns 0. It never touches
        // the protected `count` member, so the fixture-observed count/apply/
        // res triple must stay 0 even when graph/IR mutations occur below.

        // Ghidra blockaction.cc:2191: graph.orderBlocks(); — sort the
        // top-level structure list with FlowBlock::compareFinalOrder
        // (block.cc:709): entry block (index 0) first, blocks whose lastOp()
        // is a RETURN last, otherwise ascending index; a single-element list
        // skips the sort (block.hh:431). This runs BEFORE finalizePrinting
        // so that scopeBreak's next-sibling fall-thru (block.cc:1277-1287),
        // gotoPrints' next-in-flow successor (block.cc:2881-2890) and
        // emitBlockGraph's emission order all observe the final printing
        // order. Rudra previously kept finalize_structure's survivor (slot)
        // order, which is not the oracle's compareFinalOrder permutation:
        // return-ending top-level blocks stayed interleaved instead of
        // moving to the tail.
        fd.sblocks.order_blocks();

        // Ghidra blockaction.cc:2113's finalTransform sweep (BlockWhileDo
        // for-loop formation, block.cc:3356-3396) does NOT run here: its
        // oracle slot is ActionStructureTransform at pipeline :5715, before
        // the merge group (:5717-:5729) and ActionSetCasts (:5735) — see
        // the SLOT CONTRACT on ActionStructureTransform::apply in
        // coreaction.rs (INITEXTRACT-PIPE-SLOT-0001). The former
        // :5736 relocation (HTTPDMAIN-F8-FORLOOP-0001 lane write-set
        // freeze, claimed behaviorally unobservable) ran the sweep AFTER
        // setcasts had wrapped raw LOAD iterates in CPUI_CASTs, flipping
        // the isMoveable gate (block.cc:3197) and converting while loops
        // the oracle keeps as while (ap_fini_vhost_config DAT_001a0828,
        // oracle drill fixture 2026-09-28). Restored to :5715.
        crate::block::BlockGraph::finalize_printing_graph(fd);

        // Ghidra blockaction.cc:2192: graph.finalizePrinting(data); —
        // BlockGraph::finalizePrinting (block.cc:1364) recurses the tree and
        // runs BlockSwitch::finalizePrinting (block.cc:3556-3592) on every
        // switch component: the fall-thru depth passes, the chain-root label
        // fill via JumpTable::numIndicesByBlock/getIndexByBlock/
        // getLabelByIndex, the CaseOrder::compare stable sort, and the
        // case_values materialization that printc's emit_structured_switch
        // reads. It also runs BlockWhileDo::finalizePrinting (block.cc:3403)
        // on every while-do loop: the for-loop statement extraction
        // (testTerminal/testIterateForm + opMarkNonPrinting) that feeds
        // printc's emit_for_loop. (Called once above, together with the
        // :2113 finalTransform sweep.)

        // Ghidra blockaction.cc:2193: graph.scopeBreak(-1,-1);
        // Walk the structure tree (sblocks) reclassifying any unstructured
        // goto whose target is the enclosing loop's exit as f_break_goto, so
        // emitBlockGoto (printc.cc:2766) prints `break;` instead of
        // `goto code_r0x...;`. This is the entry point for goto→break/continue
        // conversion; without it, every BlockGoto keeps its default
        // f_goto_goto and emits a `code_r0x` label.
        fd.sblocks.scope_break(-1, -1);
        // gotoPrints transport (block.cc:2881-2890 evaluated tree-wide):
        // Ghidra reads `getParent()->nextFlowAfter(this)` lazily at
        // markUnstructured/emit time; Rudra composites cannot sit in a
        // BlockGraph::blocks list (no parent wiring), so the identical
        // comparison (front_leaf(target) != next-in-flow successor,
        // block.cc:1335-1353) is evaluated once here — after scopeBreak,
        // before markUnstructured, the oracle's own first evaluation point —
        // and stored on BlockGoto::prints_precomputed for both consumers
        // (markUnstructured's cc:2861 gate and printc's emitBlockGoto
        // cc:2775).
        fd.sblocks.compute_goto_prints();
        // Ghidra blockaction.cc:2194: graph.markUnstructured();
        // Recurse the structure tree marking, for each unconverted
        // (f_goto_goto) goto / if-goto / switch-case-goto, its target block's
        // front leaf with f_unstructured_targ. Only blocks carrying this flag
        // get a `code_r0x` label in emitLabelStatement (printc.cc:3198-3214) —
        // loop backedges and structured-branch targets never do. Without this
        // call, Rudra's label emission fell back to a coarse scan of every
        // BRANCH/CBRANCH target (printc.rs goto_targets) and emitted dozens of
        // spurious unreferenced labels.
        fd.sblocks.mark_unstructured();

        // Ghidra blockaction.cc:2195: graph.markLabelBumpUp(false); // Fix up
        // labeling — recurse the structure tree setting f_label_bumpup on
        // every loop's front (condition/body) chain (BlockWhileDo/
        // BlockDoWhile/BlockInfLoop force `true` down their list[0] chain,
        // block.cc:3316/3426/3454; the incoming bump stays false everywhere
        // else, so non-loop composites never set the flag).
        // PrintC::emitAnyLabelStatement (printc.cc:3222) consumes it: a
        // flagged block's label statement is skipped because the enclosing
        // loop construct prints it at the construct entry — this is what
        // keeps a goto-into-loop-header label OUT of the `while (...)`
        // condition parens / inside the `do {` body and lands it before the
        // loop keyword line.
        fd.sblocks.mark_label_bump_up(false);

        // Tag untagged BRANCH/CBRANCH as GOTO (break/continue already tagged
        // by ActionNormalizeBranches). No `count +=` here: Ghidra's goto
        // tagging lives in structure/markUnstructured, which never counts.
        for op_ref in fd.obank.iter_alive() {
            let mut op = op_ref.0.write().unwrap();
            if op.branch_type != branch_type::NONE {
                continue;
            }
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    op.branch_type = branch_type::GOTO;
                }
                _ => {}
            }
        }

        // RUDRA-GLUE: retire post-terminator ops. The oracle action has no
        // counterpart here (blockaction.cc:2186-2197 only runs the five graph
        // calls); in Ghidra such ops never exist in the first place — a
        // BlockBasic's op list ends at its terminator (blocks are split at
        // every branch during flow generation, funcdata_block.cc), and flow
        // following never marks ops past an unconditional BRANCH/RETURN
        // alive. Where Rudra's loader still leaves ops in a block after its
        // unconditional BRANCH/RETURN, this glue retires them via the
        // oracle's canonical kill path, Funcdata::opUninsert
        // (funcdata_op.cc:164-173): PcodeOpBank::markDead (op.cc:1028-1034 —
        // alive-list removal + `dead` flag set + dead-list append) plus
        // BlockBasic::removeOp (block.cc:2292-2297 — parent cleared + block
        // op-list removal). The former glue walked the alive list with an
        // address-continuity proxy, which fired on ops of the NEXT
        // (address-adjacent) block — killing live dataflow ops — and only
        // spliced the alive list, leaving retired ops `is_dead() == false`
        // and in their blocks, so block walkers (printc, dump census) still
        // observed them while every alive-list consumer was blind
        // (BLOCKACTION-ALIVELIST-GLUE-0001).
        let mut dead_ops: Vec<crate::op::PcodeOpRef> = Vec::new();
        for block_idx in 0..fd.bblocks.get_size() {
            let Some(block_arc) = fd.bblocks.get_block(block_idx) else {
                continue;
            };
            let ops = block_arc.read().unwrap().get_ops();
            let mut hit_terminator = false;
            for op_ref in ops.iter() {
                let op = op_ref.0.read().unwrap();
                if hit_terminator {
                    dead_ops.push(op_ref.clone());
                    continue;
                }
                match op.opcode {
                    OpCode::CPUI_BRANCH | OpCode::CPUI_RETURN => {
                        hit_terminator = true;
                    }
                    _ => {}
                }
            }
        }

        // Like the GOTO tagging above, this cleanup is printing/IR glue with
        // no `count +=` counterpart in the oracle action. op_uninsert mutates
        // block op lists, so ops are collected first and retired only after
        // the walk completes.
        for op in dead_ops {
            fd.op_uninsert(&op);
        }

        // Ghidra blockaction.cc:2196: unconditional `return 0` — never
        // reports a change through the count state machine.
        Ok(action_status::NO_CHANGE)
    }

    // Ghidra: blockaction.hh:324 ActionFinalStructure::getName
    fn get_name(&self) -> &str {
        "finalstructure"
    }
}

/// Action for normalizing branches (e.g., converting goto to break/continue)
///
/// Corresponds to Ghidra's `ActionNormalizeBranches`
pub struct ActionNormalizeBranches;

impl ActionNormalizeBranches {
    // Ghidra: blockaction.hh:284 ActionNormalizeBranches::new
    /// Create a new ActionNormalizeBranches instance
    pub fn new() -> Self {
        Self
    }
}

impl Action for ActionNormalizeBranches {
    // Ghidra: blockaction.cc:2117 ActionNormalizeBranches::apply
    fn apply(&mut self, fd: &mut Funcdata) -> Result<i32> {
        let mut changed = 0;
        let size = fd.sblocks.get_size();

        // Collect loop header/exit/condition triples from structured blocks
        // at ANY nesting depth. A WhileDo/DoWhile nested inside a BlockList
        // (loop body chained: head -> ... -> tail -> head) is invisible to a
        // top-level-only scan, leaving its back-edge jmp untagged
        // (BLOCKACT-NORMALIZE-CONTINUE-TAG-0001).
        //
        // The traversal is Ghidra's structure-tree walk pattern
        // (ActionPreferComplement, blockaction.cc:2143-2164): a vec-based BFS
        // seeded with the root graph's components; copy/basic children are
        // not descended (they hold no nested composites), every other child
        // is pushed. The break/continue classification this feeds mirrors
        // Ghidra's own scopeBreak (block.cc:1270-1288), which reaches every
        // composite via virtual dispatch, not just the top level.
        struct LoopInfo {
            header_addr: crate::address::Address,
            exit_addr: Option<crate::address::Address>,
            /// Condition block resolved to the live original (BlockCopy
            /// unwrapped), for op-parent identity checks.
            cond_orig: std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>,
        }

        let resolve_orig = |blk: &std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>|
         -> std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>> {
            let r = blk.read().unwrap();
            if r.get_type() == crate::block::BlockType::Copy {
                if let Some(orig) = r.sub_block(0) {
                    return orig;
                }
            }
            blk.clone()
        };

        // RUDRA-GLUE: child enumeration for the composite kinds the walk
        // descends (Ghidra's t_copy/t_basic skip, blockaction.cc:2158). Rust
        // trait objects do not virtual-dispatch subBlock for these kinds, so
        // downcast per type — the same enumeration is_structured_child uses.
        let structured_children =
            |b: &dyn FlowBlock| -> Vec<std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>> {
                use crate::block::{
                    BlockCondition, BlockDoWhile, BlockGoto, BlockIf, BlockInfLoop, BlockList,
                    BlockSwitch, BlockWhileDo,
                };
                let mut out: Vec<std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>> =
                    Vec::new();
                match b.get_type() {
                    crate::block::BlockType::Condition => {
                        if let Some(bc) = b.as_any().downcast_ref::<BlockCondition>() {
                            out.push(bc.first.clone());
                            out.push(bc.second.clone());
                        }
                    }
                    crate::block::BlockType::If => {
                        if let Some(bi) = b.as_any().downcast_ref::<BlockIf>() {
                            out.push(bi.condition.clone());
                            out.push(bi.if_body.clone());
                            if let Some(ref eb) = bi.else_body {
                                out.push(eb.clone());
                            }
                        }
                    }
                    crate::block::BlockType::WhileDo => {
                        if let Some(wd) = b.as_any().downcast_ref::<BlockWhileDo>() {
                            out.push(wd.condition.clone());
                            out.push(wd.body.clone());
                        }
                    }
                    crate::block::BlockType::DoWhile => {
                        if let Some(dw) = b.as_any().downcast_ref::<BlockDoWhile>() {
                            out.push(dw.condition.clone());
                        }
                    }
                    crate::block::BlockType::InfLoop => {
                        if let Some(il) = b.as_any().downcast_ref::<BlockInfLoop>() {
                            out.push(il.body.clone());
                        }
                    }
                    crate::block::BlockType::Goto => {
                        if let Some(bg) = b.as_any().downcast_ref::<BlockGoto>() {
                            if let Some(ref wrapped) = bg.wrapped {
                                out.push(wrapped.clone());
                            }
                        }
                    }
                    crate::block::BlockType::List => {
                        if let Some(bl) = b.as_any().downcast_ref::<BlockList>() {
                            out.extend(bl.children.iter().cloned());
                        }
                    }
                    crate::block::BlockType::Switch => {
                        if let Some(bs) = b.as_any().downcast_ref::<BlockSwitch>() {
                            out.push(bs.control.clone());
                            out.extend(bs.cases.iter().cloned());
                            if let Some(ref dc) = bs.default_case {
                                out.push(dc.clone());
                            }
                        }
                    }
                    _ => {}
                }
                out
            };

        let mut loop_info: Vec<LoopInfo> = Vec::new();
        let mut queue: Vec<std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>> = Vec::new();
        for i in 0..size {
            if let Some(b) = fd.sblocks.get_block(i) {
                queue.push(b);
            }
        }
        let mut pos = 0;
        while pos < queue.len() {
            let block = queue[pos].clone();
            pos += 1;

            let block_type = block.read().unwrap().get_type();

            // Children to descend into (Ghidra cc:2154-2161 skips t_copy /
            // t_basic). Collected per composite kind via downcast; Rust's
            // trait objects do not virtual-dispatch subBlock for these.
            let children: Vec<std::sync::Arc<RwLock<dyn FlowBlock + Send + Sync>>> = {
                let b: std::sync::RwLockReadGuard<'_, dyn FlowBlock + Send + Sync> =
                    block.read().unwrap();
                match block_type {
                    crate::block::BlockType::Copy | crate::block::BlockType::Basic => Vec::new(),
                    _ => structured_children(&*b),
                }
            };

            match block_type {
                crate::block::BlockType::WhileDo => {
                    let block_read = block.read().unwrap();
                    if let Some(wd) = block_read.as_any().downcast_ref::<BlockWhileDo>() {
                        // The condition member of the collapse graph is a
                        // BlockCopy (or Basic) whose default get_start_addr
                        // is 0 and whose edges were rewired onto the
                        // composite by identifyInternal — resolve to the
                        // live original, which keeps the bblocks entry
                        // address and the original out-edges (body / exit).
                        let cond_orig = resolve_orig(&wd.condition);
                        let header_addr =
                            crate::address::Address::new(crate::block::front_leaf_start_addr(
                                &wd.condition,
                            ));

                        // The exit block is the out-edge of the ORIGINAL
                        // condition block that does NOT point at the body
                        // front leaf.
                        let exit_addr = {
                            let cond = cond_orig.read().unwrap();
                            if cond.size_out() >= 2 {
                                let body_u =
                                    crate::block::front_leaf_start_addr(&wd.body);
                                let out0_addr = cond
                                    .get_out(0)
                                    .map(|e| {
                                        crate::block::front_leaf_start_addr(
                                            &fd.sblocks.bank.expect_arc(e.point),
                                        )
                                    });
                                let out1_addr = cond
                                    .get_out(1)
                                    .map(|e| {
                                        crate::block::front_leaf_start_addr(
                                            &fd.sblocks.bank.expect_arc(e.point),
                                        )
                                    });

                                if out0_addr == Some(body_u) {
                                    out1_addr
                                } else {
                                    out0_addr
                                }
                            } else {
                                None
                            }
                        }
                        .map(crate::address::Address::new);

                        loop_info.push(LoopInfo {
                            header_addr,
                            exit_addr,
                            cond_orig,
                        });
                    }
                }
                crate::block::BlockType::DoWhile => {
                    let block_read = block.read().unwrap();
                    if let Some(dwd) = block_read
                        .as_any()
                        .downcast_ref::<crate::block::BlockDoWhile>()
                    {
                        let cond_orig = resolve_orig(&dwd.condition);
                        // Do-while: the condition block IS the loop tail.
                        // Its CBRANCH targets the loop head (back edge); the
                        // OTHER out-edge of the original is the exit. Slot
                        // order is not fixed, so identify the head from the
                        // cbranch target and take the non-head edge as exit.
                        let header_addr = {
                            let cond = cond_orig.read().unwrap();
                            cond.get_ops()
                                .iter()
                                .rev()
                                .find(|o| o.0.read().unwrap().opcode == OpCode::CPUI_CBRANCH)
                                .and_then(|o| {
                                    let op = o.0.read().unwrap();
                                    op.inrefs
                                        .first()
                                        .map(|vn| vn.read().unwrap().get_offset())
                                })
                                .map(crate::address::Address::new)
                                .unwrap_or_else(|| {
                                    crate::address::Address::new(
                                        crate::block::front_leaf_start_addr(
                                            &dwd.condition,
                                        ),
                                    )
                                })
                        };
                        let header_u = header_addr.as_u64();
                        let exit_addr = {
                            let cond = cond_orig.read().unwrap();
                            (0..cond.size_out())
                                .map(|s| {
                                    cond.get_out(s)
                                        .map(|e| {
                                            crate::block::front_leaf_start_addr(
                                                &fd.sblocks.bank.expect_arc(e.point),
                                            )
                                        })
                                        .unwrap_or(u64::MAX)
                                })
                                .find(|&a| a != header_u)
                                .filter(|&a| a != u64::MAX)
                        }
                        .map(crate::address::Address::new);

                        loop_info.push(LoopInfo {
                            header_addr,
                            exit_addr,
                            cond_orig,
                        });
                    }
                }
                _ => {}
            }

            queue.extend(children);
        }

        if loop_info.is_empty() {
            return Ok(action_status::NO_CHANGE);
        }

        // Walk ALL ops and tag BRANCH/CBRANCH that target loop headers or exits
        for op_ref in fd.obank.iter_alive() {
            let mut op = op_ref.0.write().unwrap();
            match op.opcode {
                OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH => {
                    if op.branch_type != crate::op::branch_type::NONE {
                        continue;
                    }
                    // The loop's own condition test (the cbranch living in the
                    // WhileDo/DoWhile condition block) never tags: Ghidra
                    // consumes it as the `while (...)` / `do ... while (...)`
                    // syntax (BlockWhileDo/BlockDoWhile emit reads the
                    // condition's cbranch; scopeBreak never visits it as a
                    // goto). Identify it by op-parent identity against the
                    // resolved original condition block — the previous
                    // op-addr == header-addr check only matched single-op
                    // headers and mistagged the loop test of any header with
                    // leading non-branch ops.
                    let op_cond_parent = op
                        .parent
                        .as_ref()
                        .and_then(|w| w.upgrade())
                        .map(|p| resolve_orig(&p));

                    // Input[0] is the branch target address varnode
                    let target_addr = match op.inrefs.get(0) {
                        Some(vn_arc) => vn_arc.read().unwrap().get_offset(),
                        None => continue,
                    };

                    for li in &loop_info {
                        if let Some(ref parent_orig) = op_cond_parent {
                            if std::sync::Arc::ptr_eq(parent_orig, &li.cond_orig) {
                                continue;
                            }
                        }
                        if target_addr == li.header_addr.as_u64() {
                            op.branch_type = crate::op::branch_type::CONTINUE;
                            changed += 1;
                            break;
                        }
                        if let Some(ref exit) = li.exit_addr {
                            if target_addr == exit.as_u64() {
                                op.branch_type = crate::op::branch_type::BREAK;
                                changed += 1;
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if changed > 0 {
            Ok(action_status::CHANGE)
        } else {
            Ok(action_status::NO_CHANGE)
        }
    }

    // Ghidra: blockaction.hh:284 ActionNormalizeBranches::getName
    fn get_name(&self) -> &str {
        "normalizebranches"
    }
}

#[cfg(test)]
mod loopbody_tests {
    use super::*;
    use crate::address::Address;
    use crate::block::BlockBasic;

    #[test]
    fn action_block_structure_externalizes_inherited_count() {
        let mut action = ActionBlockStructure::new();
        action.count = 7;

        assert_eq!(Action::take_count_delta(&mut action), 7);
        assert_eq!(Action::take_count_delta(&mut action), 0);
    }

    // Ghidra: blockaction.hh:284 ActionNormalizeBranches::buildLoopCfg
    /// Build a tiny CFG: 0→1→2→1 (loop), with 2 also →3 (exit).
    /// head=1, tail=2, body={1,2}, exit=3.
    fn build_loop_cfg() -> BlockGraph {
        let mut g = BlockGraph::new();
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0,
            Address::new(0x100),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1,
            Address::new(0x110),
        )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2,
            Address::new(0x120),
        )));
        let b3 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            3,
            Address::new(0x130),
        )));
        for b in [&b0, &b1, &b2, &b3] {
            g.add_block(b.clone());
        }
        g.add_edge(b0.clone(), b1.clone());
        g.add_edge(b1.clone(), b2.clone());
        g.add_edge(b2.clone(), b1.clone()); // back-edge
        g.add_edge(b2.clone(), b3.clone()); // exit edge
        g
    }

    #[test]
    fn test_loopbody_find_base() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        // Body = head(1) + tail(2). Block 0 reaches 2 only via head, so not in body.
        assert!(body.contains(&1));
        assert!(body.contains(&2));
        assert!(!body.contains(&0));
        assert_eq!(lb.unique_count, 2);
        // Clear marks.
        clear_marks(&body, &g);
        assert!(!g.get_block(1).unwrap().read().unwrap().is_mark());
    }

    #[test]
    fn test_loopbody_find_exit() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g, None);
        // Exit should be block 3 (the only out-of-body target from tail 2).
        assert_eq!(lb.exit_block, 3);
        clear_marks(&body, &g);
    }

    #[test]
    fn test_loopbody_label_exit_edges() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g, None);
        lb.order_tails(&g);
        lb.label_exit_edges(&body, &g);
        // The 2→3 edge should be recorded (as an edge to exit_block).
        assert!(lb
            .exit_edges
            .iter()
            .any(|e| e.from_idx == 2 && e.to_idx == 3));
        clear_marks(&body, &g);
    }

    #[test]
    fn test_floating_edge_clone() {
        let e = FloatingEdge {
            from_idx: 1,
            to_idx: 3,
        };
        let e2 = e.clone();
        assert_eq!(e.from_idx, e2.from_idx);
        assert_eq!(e.to_idx, e2.to_idx);
    }

    #[test]
    fn test_merge_identical_heads() {
        let mut order = vec![
            LoopBody::new(1, 2),
            LoopBody::new(1, 4), // same head as first → merge
            LoopBody::new(5, 6),
        ];
        merge_identical_heads(&mut order);
        // After merge: 2 distinct heads (1 with 2 tails, 5).
        assert_eq!(order.len(), 2);
        assert_eq!(order[0].head, 1);
        assert_eq!(order[0].tails.len(), 2);
        assert_eq!(order[1].head, 5);
    }

    /// emit_likely_edges appends exit edges and back-edges in priority order.
    #[test]
    fn test_emit_likely_edges() {
        let g = build_loop_cfg();
        let mut lb = LoopBody::new(1, 2);
        let body = lb.find_base(&g);
        lb.find_exit(&body, &g, None);
        lb.order_tails(&g);
        lb.label_exit_edges(&body, &g);
        let mut likely: Vec<FloatingEdge> = Vec::new();
        lb.emit_likely_edges(&mut likely, &g);
        // The 2→3 exit edge and the 2→1 back-edge should both appear.
        assert!(
            likely.iter().any(|e| e.from_idx == 2 && e.to_idx == 3),
            "exit edge 2->3 missing: {:?}",
            likely
        );
        assert!(
            likely.iter().any(|e| e.from_idx == 2 && e.to_idx == 1),
            "back-edge 2->1 missing: {:?}",
            likely
        );
        clear_marks(&body, &g);
    }

    /// FlowBlock loop-exit mark primitives work end to end.
    #[test]
    fn test_loop_exit_mark_primitives() {
        let g = build_loop_cfg();
        // Mark block 2's out-edge to 3 as loop-exit.
        let blk2 = g.get_block(2).unwrap();
        let slot = {
            let b = blk2.read().unwrap();
            (0..b.size_out())
                .find(|&k| {
                    b.get_out(k)
                        .map(|e| g.bank.expect_index(e.point) == 3)
                        .unwrap_or(false)
                })
                .unwrap()
        };
        blk2.write().unwrap().set_loop_exit(slot);
        // is_goto_out should now be true (loop_exit is in the goto-class set).
        // Note: is_goto_out checks F_GOTO|F_IRREDUCIBLE, NOT loop_exit;
        // is_loop_dag_out (in tracedag) checks the full set. Here we verify
        // the loop_exit flag persists on the edge.
        let flags = blk2.read().unwrap().get_out(slot).unwrap().flags;
        assert!(flags & crate::block::edge_flags::F_LOOP_EXIT_EDGE != 0);
        // Clear it.
        blk2.write().unwrap().clear_loop_exit(slot);
        let flags2 = blk2.read().unwrap().get_out(slot).unwrap().flags;
        assert!(flags2 & crate::block::edge_flags::F_LOOP_EXIT_EDGE == 0);
    }

    /// Verify is_goto_out reads block-level GOTO_EDGE_0/GOTO_EDGE_1 flags.
    /// This is the fix that connects TraceDAG's goto marking (which sets
    /// block flags) to ruleBlockWhileDo's isGotoOut checks.
    #[test]
    fn test_is_goto_out_reads_block_flags() {
        let mut g = BlockGraph::new();
        let b0 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            0,
            Address::new(0x100),
        )));
        let b1 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            1,
            Address::new(0x110),
        )));
        let b2 = std::sync::Arc::new(std::sync::RwLock::new(BlockBasic::new(
            2,
            Address::new(0x120),
        )));
        for b in [&b0, &b1, &b2] {
            g.add_block(b.clone());
        }
        g.add_edge(b0.clone(), b1.clone());
        g.add_edge(b0.clone(), b2.clone());

        // Before marking: neither edge is goto.
        assert!(!b0.read().unwrap().is_goto_out(0));
        assert!(!b0.read().unwrap().is_goto_out(1));

        // Mark out-edge 1 as goto (block-level flag, like run_tracedag does).
        b0.write()
            .unwrap()
            .set_flags(crate::block::block_flags::GOTO_EDGE_1);

        // Now is_goto_out(1) must return true; is_goto_out(0) stays false.
        assert!(!b0.read().unwrap().is_goto_out(0), "edge 0 not goto");
        assert!(
            b0.read().unwrap().is_goto_out(1),
            "edge 1 is goto via block flag"
        );
    }
}

#[cfg(test)]
mod multigoto_defaultchain_tests {
    use super::CollapseStructure;
    use crate::block::CaseOrder;

    fn co(chain: i32) -> CaseOrder {
        CaseOrder { basicblock: None, label: 0, depth: 0, chain, outindex: -1 }
    }

    // CR-GLOBATTR F1: the multigoto arm's re-added cases occupy
    // [k, k+g) after grab_case_order recorded the virtual default at k —
    // chains against k must shift to k+g; everything else is untouched.
    #[test]
    fn remap_shifts_only_default_links() {
        // k=3 regular entries, one chain link to the default (==3), one
        // regular-to-regular link (==1), one -1; arm appends g=2.
        let mut order = vec![co(3), co(1), co(-1)];
        let moved = CollapseStructure::remap_default_chain_indices(&mut order, 3, 2);
        assert_eq!(moved, 1);
        assert_eq!(order[0].chain, 5, "default link shifts k -> k+g");
        assert_eq!(order[1].chain, 1, "regular-to-regular link untouched");
        assert_eq!(order[2].chain, -1, "no-chain untouched");
    }

    #[test]
    fn remap_moves_multiple_default_links() {
        let mut order = vec![co(2), co(2), co(0), co(-1)];
        let moved = CollapseStructure::remap_default_chain_indices(&mut order, 2, 3);
        assert_eq!(moved, 2);
        assert_eq!(order[0].chain, 5);
        assert_eq!(order[1].chain, 5);
        assert_eq!(order[2].chain, 0, "chain 0 is a regular link, untouched");
        assert_eq!(order[3].chain, -1);
    }

    #[test]
    fn remap_no_links_is_noop() {
        // Dormant shape: no case falls into the default (both corpora).
        let mut order = vec![co(1), co(-1), co(0)];
        let moved = CollapseStructure::remap_default_chain_indices(&mut order, 3, 2);
        assert_eq!(moved, 0);
        assert_eq!((order[0].chain, order[1].chain, order[2].chain), (1, -1, 0));
    }

    // MCENSUS3-SWITCH-BREAKGOTO-EMIT-0001: the composite-sibling break
    // conversion. Production path (build_copy → structure_loops →
    // collapse_all → the ActionFinalStructure tail scopeBreak) over a
    // loop whose exit is a COMPOSITE (if/else) — the sqlite
    // sqlite3FtsUnicodeFold emission shape, where the loop-body if-goto
    // targets the composite sibling that follows the loop.
    //
    // Oracle semantics under test (block.cc:866-873 addBlock min-tracking
    // + 1270-1288 BlockGraph::scopeBreak + 3075-3084 BlockIf::scopeBreak):
    // the sibling composite shares the index of its entry leaf, so
    // `gototarget->getIndex() == curloopexit` holds and the if-goto is
    // reclassified f_break_goto (prints `break;`). The former
    // finalize_structure survivor re-index to compacted positions broke
    // the same equality whenever the following sibling was a composite
    // whose entry index differed from its list position (the corpus's
    // inner-target sites: sqlite 26 functions, e.g. sqlite3FtsUnicodeFold
    // target 0x5a696 idx 10 vs sibling list position 1).
    #[test]
    fn test_scopebreak_composite_sibling_min_index() {
        use crate::address::Address;
        use crate::block::{
            BlockBasic, BlockGraph, BlockIf, BlockType, FlowBlock, goto_type,
        };
        type BlockRef =
            std::sync::Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
        // CFG (FtsUnicodeFold binary-search tail shape): entry if with a
        // RETURN arm, then a loop whose body if-goto targets the ENTRY
        // LEAF of the composite sibling that follows the loop — the
        // oracle's sqlite3FtsUnicodeFold shape [entry, loop,
        // exit-composite], where the loop-exit sibling comparison runs
        // over a component list (BlockGraph::scopeBreak feeds each child
        // the following entry's index, block.cc:1277-1287).
        // Edges: 0→{1 loop-path, 9 return}; 1→{2 body,5 loop-exit};
        // 2→{1 backedge,5 goto-to-loop-exit}; 5→{6 then,7 else}; 6→8;
        // 7→8. Non-contiguous leaf indices (realistic rpost-carried
        // values).
        let mut bblocks = BlockGraph::new();
        let mut graph = BlockGraph::new();
        let idxs = [0, 1, 2, 5, 6, 7, 8, 9];
        let leaves: Vec<BlockRef> = idxs
            .iter()
            .map(|&idx| {
                let leaf: BlockRef = std::sync::Arc::new(std::sync::RwLock::new(
                    BlockBasic::new(idx, Address::new(0x1000 + idx as u64 * 0x10)),
                ));
                bblocks.add_block(leaf.clone());
                leaf
            })
            .collect();
        let (b0, b1, b2, b5, b6, b7, b8, b9) = (
            &leaves[0],
            &leaves[1],
            &leaves[2],
            &leaves[3],
            &leaves[4],
            &leaves[5],
            &leaves[6],
            &leaves[7],
        );
        for (a, b) in [
            (b0, b1),
            (b0, b9),
            (b1, b2),
            (b1, b5),
            (b2, b1),
            (b2, b5),
            (b5, b6),
            (b5, b7),
            (b6, b8),
            (b7, b8),
        ] {
            bblocks.add_edge(a.clone(), b.clone());
        }
        graph.build_copy(&bblocks);
        let mut rootlist: Vec<BlockRef> = Vec::new();
        graph.structure_loops(&mut rootlist).expect("structure_loops");
        let mut collapse = CollapseStructure::new(&mut graph, "swbreak_test");
        collapse.collapse_all();
        // ActionFinalStructure head: orderBlocks (block.hh:430) then the
        // scopeBreak tail (blockaction.cc:2191-2193).
        graph.order_blocks();
        graph.scope_break(-1, -1);

        // (1) addBlock min invariant (block.cc:866-873): EVERY composite's
        // index is the minimum over its component subtree — the identity
        // compareFinalOrder (block.cc:709/731) and scopeBreak's
        // `gototarget->getIndex() == curloopexit` (block.cc:2872/3082) /
        // `bl->getIndex() == curexit` (block.cc:3621) equality tests run
        // on. The former finalize_structure re-index to compacted list
        // positions broke this (MCENSUS3-SWITCH-BREAKGOTO-EMIT-0001).
        fn subtree_min(bl: &BlockRef) -> i32 {
            let r = bl.read().unwrap();
            let own = r.get_index();
            let mut m = own;
            for c in BlockGraph::component_list_dyn(bl) {
                m = m.min(subtree_min(&c));
            }
            m
        }
        fn assert_min_invariant(bl: &BlockRef, depth: usize) {
            if depth > 12 {
                return;
            }
            let idx = bl.read().unwrap().get_index();
            assert_eq!(
                idx,
                subtree_min(bl),
                "composite index must equal subtree min (addBlock min-tracking)"
            );
            for c in BlockGraph::component_list_dyn(bl) {
                assert_min_invariant(&c, depth + 1);
            }
        }
        let top = graph.blocks.clone();
        assert!(!top.is_empty());
        for t in &top {
            assert_min_invariant(t, 0);
        }

        // (2) the composite-sibling break conversion: over every component
        // list, for each (loop, following-sibling) adjacent pair, every
        // goto carrier inside the loop whose target index equals the
        // sibling's index (i.e. the target IS the sibling's entry leaf)
        // must hold f_break_goto (block.cc:3075-3084 BlockIf::scopeBreak /
        // 2866-2874 BlockGoto::scopeBreak) — this is the `break;` the
        // oracle prints where the pre-fix Rudra printed `goto code_rXXXX;`
        // + a spurious label.
        fn collect_carriers(
            bl: &BlockRef,
            out: &mut Vec<BlockRef>,
            depth: usize,
        ) {
            if depth > 12 {
                return;
            }
            let bt = bl.read().unwrap().get_type();
            let carrier = match bt {
                BlockType::If => bl
                    .read()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<BlockIf>()
                    .map(|i| i.goto_target.is_some())
                    .unwrap_or(false),
                BlockType::Goto => true,
                _ => false,
            };
            if carrier {
                out.push(bl.clone());
            }
            for c in BlockGraph::component_list_dyn(bl) {
                collect_carriers(&c, out, depth + 1);
            }
        }
        fn is_loop(bt: BlockType) -> bool {
            matches!(
                bt,
                BlockType::WhileDo | BlockType::DoWhile | BlockType::InfLoop
            )
        }
        fn check_sibling_pairs(bl: &BlockRef, saw: &mut bool, depth: usize) {
            if depth > 12 {
                return;
            }
            let children = BlockGraph::component_list_dyn(bl);
            for pair in children.windows(2) {
                let (a, b) = (&pair[0], &pair[1]);
                if !is_loop(a.read().unwrap().get_type()) {
                    continue;
                }
                let sibling_idx = b.read().unwrap().get_index();
                let mut carriers = Vec::new();
                collect_carriers(a, &mut carriers, 0);
                for c in &carriers {
                    let r = c.read().unwrap();
                    let (gt, target): (u32, Option<BlockRef>) =
                        match r.get_type() {
                            BlockType::Goto => {
                                let bg = r
                                    .as_any()
                                    .downcast_ref::<crate::block::BlockGoto>()
                                    .unwrap();
                                (bg.get_goto_type(), bg.target_dyn.clone())
                            }
                            _ => {
                                let bi = r
                                    .as_any()
                                    .downcast_ref::<BlockIf>()
                                    .unwrap();
                                (bi.goto_type, bi.goto_target.clone())
                            }
                        };
                    let Some(target) = target else { continue };
                    let tidx = target.read().unwrap().get_index();
                    if tidx == sibling_idx {
                        // scopeBreak must have converted it (or it can
                        // never print as a bare goto).
                        assert_eq!(
                            gt,
                            goto_type::BREAK_GOTO,
                            "loop-exit goto targeting the following sibling's entry must convert to f_break_goto"
                        );
                        *saw = true;
                    }
                }
            }
            for c in children {
                check_sibling_pairs(&c, saw, depth + 1);
            }
        }
        let mut saw_conversion = false;
        for t in &top {
            check_sibling_pairs(t, &mut saw_conversion, 0);
        }
        assert!(
            saw_conversion,
            "the synthetic loop-exit goto must hit the sibling-entry conversion"
        );
    }
}

#[cfg(test)]
mod finddup_tests {
    use super::*;
    use crate::address::Address;
    use crate::arena::{ArenaId, BlockId};
    use crate::block::block_flags;
    use crate::block::{BlockBasic, BlockGraph};
    use std::sync::{Arc, RwLock};

    type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

    fn basic(idx: i32, addr: u64) -> BlockArc {
        Arc::new(RwLock::new(BlockBasic::new(idx, Address::new(addr))))
    }

    // PERF-FINDDUP-0001: the snapshot fast path must return the lock
    // protocol's exact duplist (second-occurrence order, third sight not
    // re-pushed, cc:514-517) and leave every peer mark-clean afterwards
    // (the set-then-erase pass cancels, cc:521-522).
    #[test]
    fn dup_peers_snapshot_matches_lock_protocol() {
        let mut g = BlockGraph::new();
        let a = basic(0, 0x100);
        let b = basic(1, 0x200);
        let c = basic(2, 0x300);
        g.add_block(a.clone());
        g.add_block(b.clone());
        g.add_block(c.clone());
        // b's in-list: [a, c, a, a, c] — a dups at slot 2, c dups at slot 4;
        // a's third sight (slot 3) must not re-push.
        g.add_edge(a.clone(), b.clone());
        g.add_edge(c.clone(), b.clone());
        g.add_edge(a.clone(), b.clone());
        g.add_edge(a.clone(), b.clone());
        g.add_edge(c.clone(), b.clone());

        let dups = find_dup_peers(&b, true);
        assert_eq!(dups.len(), 2, "one push per duplicated peer");
        assert!(
            Arc::ptr_eq(&dups[0], &a),
            "second-occurrence order: a dups first (slot 2)"
        );
        assert!(
            Arc::ptr_eq(&dups[1], &c),
            "second-occurrence order: c dups second (slot 4)"
        );
        // Net-zero marks: the protocol's set-then-erase cancels.
        assert_eq!(a.read().unwrap().get_flags() & (block_flags::MARK | block_flags::MARK2), 0);
        assert_eq!(c.read().unwrap().get_flags() & (block_flags::MARK | block_flags::MARK2), 0);

        // The snapshot helper alone agrees on the same edge list.
        let view = g.bank.hold();
        let id_a = g.bank.id_of(&a).unwrap();
        let id_c = g.bank.id_of(&c).unwrap();
        let edges: Vec<crate::block::BlockEdge> = vec![
            crate::block::BlockEdge::new(id_a, 0),
            crate::block::BlockEdge::new(id_c, 0),
            crate::block::BlockEdge::new(id_a, 0),
            crate::block::BlockEdge::new(id_a, 0),
            crate::block::BlockEdge::new(id_c, 0),
        ];
        assert_eq!(
            dup_peers_from_snapshot(&view, &edges),
            Some(vec![id_a, id_c]),
            "snapshot form: same order, third sight suppressed"
        );

        // Unique edges: empty duplist, fast form taken.
        let dups_out = find_dup_peers(&b, false);
        assert!(dups_out.is_empty(), "out-list has no dups");
    }

    // A pre-set MARK voids the snapshot argument: the helper must return
    // None (fallback), and the fallback lock protocol must behave exactly
    // like the oracle — the pre-marked peer is reported as a duplicate on
    // its FIRST sight (cc:514: f_mark already set ⇒ dup) and every mark,
    // including the pre-set one, is erased by the second pass (cc:521-522).
    #[test]
    fn dup_peers_falls_back_on_preset_mark() {
        let mut g = BlockGraph::new();
        let a = basic(0, 0x100);
        let b = basic(1, 0x200);
        let c = basic(2, 0x300);
        g.add_block(a.clone());
        g.add_block(b.clone());
        g.add_block(c.clone());
        g.add_edge(a.clone(), b.clone());
        g.add_edge(c.clone(), b.clone());
        g.add_edge(a.clone(), b.clone());
        c.write().unwrap().set_flags(block_flags::MARK);

        let view = g.bank.hold();
        let id_a = g.bank.id_of(&a).unwrap();
        let id_c = g.bank.id_of(&c).unwrap();
        let edges: Vec<crate::block::BlockEdge> = vec![
            crate::block::BlockEdge::new(id_a, 0),
            crate::block::BlockEdge::new(id_c, 0),
            crate::block::BlockEdge::new(id_a, 0),
        ];
        assert_eq!(
            dup_peers_from_snapshot(&view, &edges),
            None,
            "pre-set mark forces the lock-protocol fallback"
        );

        let dups = find_dup_peers(&b, true);
        assert_eq!(dups.len(), 2);
        assert!(Arc::ptr_eq(&dups[0], &c), "pre-marked c reports at first sight");
        assert!(Arc::ptr_eq(&dups[1], &a));
        // Oracle net effect: the erase pass clears the pre-set mark too.
        assert_eq!(c.read().unwrap().get_flags() & (block_flags::MARK | block_flags::MARK2), 0);
        assert_eq!(a.read().unwrap().get_flags() & (block_flags::MARK | block_flags::MARK2), 0);
    }

    // Parallel self edges: the block itself is its own dup peer (the oracle
    // marks `this` like any other point, block.cc:512-519).
    #[test]
    fn dup_peers_self_loop_parallel_edges() {
        let mut g = BlockGraph::new();
        let b = basic(0, 0x100);
        g.add_block(b.clone());
        g.add_edge(b.clone(), b.clone());
        g.add_edge(b.clone(), b.clone());
        let dups = find_dup_peers(&b, true);
        assert_eq!(dups.len(), 1);
        assert!(Arc::ptr_eq(&dups[0], &b));
        assert_eq!(b.read().unwrap().get_flags() & (block_flags::MARK | block_flags::MARK2), 0);
    }

    // An unresolvable point id (sentinel/stale) also falls back rather than
    // answering from an unreadable slot.
    #[test]
    fn dup_peers_snapshot_rejects_unresolvable_point() {
        let g = BlockGraph::new();
        let view = g.bank.hold();
        let edges = vec![crate::block::BlockEdge::new(BlockId::SENTINEL, 0)];
        assert_eq!(dup_peers_from_snapshot(&view, &edges), None);
    }
}
