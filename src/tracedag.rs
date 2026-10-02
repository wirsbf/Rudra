//! Ghidra TraceDAG port (blockaction.cc:499-1014).
//!
//! Traces the control-flow graph to find "likely unstructured edges" — edges
//! that prevent structured control-flow recovery. Once marked as goto, the
//! remaining flow can be structured as if/while instead of switch.
//!
//! This is the main algorithm behind Ghidra's selectGoto. It builds a DAG of
//! active traces from the function roots, pushes them forward, and when a
//! node can't be opened (not all in-edges traced), selects the worst edge
//! (via BadEdgeScore) to mark as an unstructured goto.
//!
//! BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001 rewrite: the previous port deviated
//! from the oracle at five decisive points, all of which inflated the number
//! of likely-goto edges (the parseconfig.constprop.0 over-marking cascade):
//!   1. selectBadEdge siblingedge comparison was INVERTED (blockaction.cc:621
//!      "A bigger sibling edge is less likely to be the bad edge" — the max
//!      scan must keep the SMALLER siblingedge; the old code kept the bigger).
//!   2. BadEdgeScore::distance used |depth_a - depth_b| instead of the
//!      BranchPoint::distance common-ancestor walk (blockaction.cc:509-536).
//!   3. openBranch's no-paths case removed the parent trace from the active
//!      list; Ghidra keeps terminal traces ACTIVE until their BranchPoint
//!      retires ("Do NOT remove from active list", blockaction.cc:670, and
//!      openBranch cc:844-851 returns parent->activeiter).
//!   4. removeTrace's remove-path did not delete the trace from the parent's
//!      paths vector nor shift the pathouts above it (cc:673-686), so
//!      checkRetirement's `pathout != 0` / `!isActive()` guards were blocked
//!      forever → the trace got stuck → extra selectBadEdge rounds.
//!   5. push_branches always restarted at position 0; Ghidra resumes at the
//!      iterator returned by retireBranch/openBranch (cc:1000-1011).
//! Also removed the invented `graph.get_size() < 10` skip (no oracle gate).

use crate::block::BlockGraph;
use std::sync::Arc;
use std::sync::RwLock;

/// A floating (likely goto) edge: (source_block_idx, dest_block_idx).
#[derive(Clone, Debug)]
pub struct FloatingEdge {
    pub top: i32,
    pub bottom: i32,
}

// Ghidra: blockaction.cc:555 TraceDAG::BranchPoint
/// A node in the control-flow graph with multiple outgoing edges in the DAG.
/// `top_block_idx == -1` encodes Ghidra's virtual root BranchPoint
/// (`top == (FlowBlock *)0`).
struct BranchPoint {
    /// Parent BranchPoint index (None for the virtual root).
    parent: Option<usize>,
    /// Depth of BranchPoints from the root.
    depth: usize,
    /// Index (of the out edge from the parent) of the path along which this lies.
    pathout: usize,
    /// Toggle-able mark used by markPath/distance (blockaction.cc:509-517).
    ismark: bool,
    /// The FlowBlock (graph index) at this branch point (-1 = virtual root).
    top_block_idx: i32,
    /// BlockTrace indices for each path out of this BranchPoint.
    paths: Vec<usize>,
}

// Ghidra: blockaction.cc:586 TraceDAG::BlockTrace
/// A trace of a single path out of a BranchPoint.
struct BlockTrace {
    /// Parent BranchPoint for which this is a path.
    top_bp: usize,
    /// Index of the out-edge path (relative to the parent BranchPoint).
    pathout: usize,
    /// Current node being traversed (-1 = null, e.g. virtual root bottom).
    bottom_block_idx: i32,
    /// Next node this trace will try to push into (-1 = null).
    dest_block_idx: i32,
    /// If >1, the edge to dest is "virtual", lumping multiple edges.
    edgelump: i32,
    /// f_active (blockaction.hh:125): this trace is active.
    active: bool,
    /// f_terminal: all paths from this point exit.
    terminal: bool,
    /// BranchPoint this trace derived (opened into), if any
    /// (blockaction.hh:135 derivedbp; needed by removeTrace's pathout shift).
    derived_bp: Option<usize>,
    /// Tombstone for traces deleted by remove_trace (Ghidra `delete trace`).
    deleted: bool,
    /// Position in `active_slots` (Ghidra `activeiter`). Invalid when !active.
    slot: usize,
}

// Ghidra: blockaction.hh:146 TraceDAG::BadEdgeScore
/// Record for scoring a BlockTrace for suitability as an unstructured branch
/// (all fields owned, mirroring the value-style C++ struct).
struct BadEdgeScore {
    /// Putative exit block for the BlockTrace (cc:148 exitproto).
    exitproto: i32,
    /// The active BlockTrace being considered (cc:149).
    trace: usize,
    /// Minimum distance crossed by this and any other trace sharing the
    /// same exit block; -1 = not yet computed (cc:150).
    distance: i32,
    /// 1 if the destination has no exit, 0 otherwise (cc:151).
    terminal: i32,
    /// Number of active traces with the same BranchPoint and exit (cc:152).
    siblingedge: i32,
}

/// TraceDAG: the main tracer.
pub struct TraceDAG<'a> {
    graph: &'a BlockGraph,
    branch_points: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    /// std::list<BlockTrace*> emulation: slot order == list order; None = a
    /// removed hole (Ghidra erase keeps the relative order of the rest, and
    /// push_back appends at the end). Holes are never reused so stored slot
    /// indices stay valid across removals.
    active_slots: Vec<Option<usize>>,
    /// Number of active BlockTrace objects (Ghidra `activecount`).
    active_count: usize,
    /// Roots (entry blocks).
    roots: Vec<i32>,
    /// The likely goto edges discovered.
    pub likely_goto: Vec<FloatingEdge>,
    /// Visit-count tracking: visit_count[block_idx] = count. Faithful to
    /// Ghidra's FlowBlock::visitcount (block.hh:125), only incremented by
    /// remove_trace (matching removeTrace blockaction.cc:661) and read by
    /// check_open (cc:824). Ghidra resets it via clearVisitCount (cc:940);
    /// the per-instance Vec — zeroed over [0, graph.get_size()) at
    /// construction, matching every block's visitcount==0 field state —
    /// makes that reset implicit. Only dest >= 0 indices are ever touched.
    visit_count: Vec<i32>,
    /// Finish block: only the root trace can open it (Ghidra finishblock,
    /// blockaction.cc:822-823).
    finish_block_idx: Option<i32>,
}

impl<'a> TraceDAG<'a> {
    // RUDRA-GLUE: new (constructor; Ghidra TraceDAG::TraceDAG blockaction.cc:951)
    pub fn new(graph: &'a BlockGraph) -> Self {
        Self {
            graph,
            branch_points: Vec::new(),
            traces: Vec::new(),
            active_slots: Vec::new(),
            active_count: 0,
            roots: Vec::new(),
            likely_goto: Vec::new(),
            // All-zero visit counts ≡ Ghidra's freshly clearVisitCount'ed
            // blocks (every FlowBlock starts a trace with visitcount 0).
            visit_count: vec![0i32; graph.get_size()],
            finish_block_idx: None,
        }
    }

    // RUDRA-GLUE: add_root (blockaction.hh:177 TraceDAG::addRoot)
    pub fn add_root(&mut self, root_idx: i32) {
        self.roots.push(root_idx);
    }

    // RUDRA-GLUE: size_out (block accessor via graph index)
    fn size_out(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_out()
        } else {
            0
        }
    }

    // RUDRA-GLUE: get_out (block accessor via graph index)
    fn get_out(&self, idx: i32, slot: usize) -> Option<i32> {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            r.get_out(slot)
                .map(|e| self.graph.bank.expect_index(e.point))
        } else {
            None
        }
    }

    // RUDRA-GLUE: size_in (block accessor via graph index)
    fn size_in(&self, idx: i32) -> usize {
        if let Some(b) = self.graph.get_block(idx as usize) {
            b.read().unwrap().size_in()
        } else {
            0
        }
    }

    // Ghidra: block.hh:342 FlowBlock::isLoopDAGOut
    /// Is the i-th out-edge of `idx` a loop-DAG edge (traceable)?
    /// `(label & (f_irreducible|f_back_edge|f_loop_exit_edge|f_goto_edge))==0`.
    fn is_loop_dag_out(&self, idx: i32, slot: usize) -> bool {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            let flags = r.get_out(slot).map(|e| e.flags).unwrap_or(0);
            use crate::block::edge_flags::*;
            (flags & (F_IRREDUCIBLE_EDGE | F_BACK_EDGE | F_LOOP_EXIT_EDGE | F_GOTO_EDGE)) == 0
        } else {
            false
        }
    }

    // Ghidra: block.hh:345 FlowBlock::isLoopDAGIn
    /// Is the i-th in-edge of `idx` a loop-DAG edge? Same four-flag mask.
    fn is_loop_dag_in(&self, idx: i32, slot: usize) -> bool {
        if let Some(b) = self.graph.get_block(idx as usize) {
            let r = b.read().unwrap();
            let flags = r.get_in(slot).map(|e| e.flags).unwrap_or(0);
            use crate::block::edge_flags::*;
            (flags & (F_IRREDUCIBLE_EDGE | F_BACK_EDGE | F_LOOP_EXIT_EDGE | F_GOTO_EDGE)) == 0
        } else {
            false
        }
    }

    // Ghidra: blockaction.hh:180 TraceDAG::setFinishBlock
    pub fn set_finish_block(&mut self, idx: i32) {
        self.finish_block_idx = Some(idx);
    }

    // Ghidra: blockaction.cc:967 TraceDAG::initialize
    /// Create the initial (virtual) BranchPoint and a BlockTrace per root.
    pub fn initialize(&mut self) {
        // Root BranchPoint (virtual, top == null → top_block_idx == -1).
        self.branch_points.push(BranchPoint {
            parent: None,
            depth: 0,
            pathout: 0,
            ismark: false,
            top_block_idx: -1,
            paths: Vec::new(),
        });
        let root_bp = 0;
        let roots = self.roots.clone();
        for &root_blk in &roots {
            // BlockTrace(rootBranch, rootBranch->paths.size(), rootlist[i])
            // — virtual root trace: bottom == null (cc:603-613).
            let trace_idx = self.traces.len();
            self.traces.push(BlockTrace {
                top_bp: root_bp,
                pathout: self.branch_points[root_bp].paths.len(),
                bottom_block_idx: -1,
                dest_block_idx: root_blk,
                edgelump: 1,
                active: false,
                terminal: false,
                derived_bp: None,
                deleted: false,
                slot: 0,
            });
            self.branch_points[root_bp].paths.push(trace_idx);
            self.insert_active(trace_idx);
        }
    }

    // Ghidra: blockaction.cc:509 TraceDAG::BranchPoint::markPath
    /// Toggle ismark on this BranchPoint and every ancestor up to the root.
    /// markPath is called twice (mark, then un-mark) around distance walks.
    fn mark_path(&mut self, bp: usize) {
        let mut cur = Some(bp);
        while let Some(i) = cur {
            self.branch_points[i].ismark = !self.branch_points[i].ismark;
            cur = self.branch_points[i].parent;
        }
    }

    // Ghidra: blockaction.cc:524 TraceDAG::BranchPoint::distance
    /// Distance = edges up to the common ancestor plus edges down to op2,
    /// assuming this->'s path to the root is currently marked. If no common
    /// ancestor is marked, `depth + op2->depth + 1` (cc:535).
    fn bp_distance(&self, a: usize, b: usize) -> i32 {
        let mut cur = Some(b);
        while let Some(i) = cur {
            if self.branch_points[i].ismark {
                return (self.branch_points[a].depth as i32 - self.branch_points[i].depth as i32)
                    + (self.branch_points[b].depth as i32 - self.branch_points[i].depth as i32);
            }
            cur = self.branch_points[i].parent;
        }
        self.branch_points[a].depth as i32 + self.branch_points[b].depth as i32 + 1
    }

    // Ghidra: blockaction.cc:786 TraceDAG::insertActive
    fn insert_active(&mut self, trace_idx: usize) {
        self.active_slots.push(Some(trace_idx));
        self.traces[trace_idx].slot = self.active_slots.len() - 1;
        self.traces[trace_idx].active = true;
        self.active_count += 1;
    }

    // Ghidra: blockaction.cc:798 TraceDAG::removeActive
    fn remove_active(&mut self, trace_idx: usize) {
        self.active_slots[self.traces[trace_idx].slot] = None;
        self.traces[trace_idx].active = false;
        self.active_count -= 1;
    }

    // RUDRA-GLUE: begin_slot (std::list activetrace.begin() equivalent)
    /// First occupied slot, or None for an empty list.
    fn begin_slot(&self) -> Option<usize> {
        self.active_slots.iter().position(|s| s.is_some())
    }

    // RUDRA-GLUE: next_slot (std::list iterator++ equivalent)
    /// Next occupied slot strictly after `s`, scanning to the end of the
    /// list; None when the iterator would reach end().
    fn next_slot(&self, s: usize) -> Option<usize> {
        (s + 1..self.active_slots.len()).find(|&i| self.active_slots[i].is_some())
    }

    // Ghidra: blockaction.cc:810 TraceDAG::checkOpen
    /// Verify the given BlockTrace can push into its destnode. A node can be
    /// opened only if all incoming loop-DAG edges have been traced (or
    /// removed as gotos: visitcount).
    fn check_open(&self, trace_idx: usize) -> bool {
        let trace = &self.traces[trace_idx];
        if trace.terminal {
            return false; // cc:813: already been opened
        }
        let bp = &self.branch_points[trace.top_bp];
        let mut isroot = false;
        if bp.depth == 0 {
            if trace.bottom_block_idx < 0 {
                return true; // cc:816-818: artificial root always opens
            }
            isroot = true;
        }
        let dest = trace.dest_block_idx;
        if dest < 0 {
            return false;
        }
        // cc:822-823: designated exit — only the root can open it.
        if !isroot && self.finish_block_idx == Some(dest) {
            return false;
        }
        // cc:824-832: count loop-DAG in-edges; all must be <= ignored count.
        // One get_block + one read guard serves sizeIn and every in-edge
        // flag read (get_in_ref): oracle reads `intothis[i].label` inline
        // (isLoopDAGIn block.hh:345) with a single `bl` pointer — the
        // per-edge re-lock/re-clone of the per-accessor form (12.2M edge
        // visits on VdbeExec) is Rudra-side constant only.
        use crate::block::edge_flags::{
            F_BACK_EDGE, F_GOTO_EDGE, F_IRREDUCIBLE_EDGE, F_LOOP_EXIT_EDGE,
        };
        let vc = self.visit_count[dest as usize];
        let ignore = trace.edgelump + vc;
        let mut count = 0i32;
        if let Some(b) = self.graph.get_block(dest as usize) {
            let r = b.read().unwrap();
            let sin = r.size_in();
            for i in 0..sin {
                if let Some(e) = r.get_in_ref(i) {
                    if (e.flags
                        & (F_IRREDUCIBLE_EDGE | F_BACK_EDGE | F_LOOP_EXIT_EDGE | F_GOTO_EDGE))
                        == 0
                    {
                        count += 1;
                        if count > ignore {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    // Ghidra: blockaction.cc:866 TraceDAG::checkRetirement
    /// Check whether this trace's BranchPoint can retire: only the first
    /// sibling (pathout==0) checks; all paths must be active; terminal paths
    /// are skipped; non-terminal destnodes must all be equal (that node is
    /// returned as the exit block). Root BranchPoint: all paths must be
    /// active AND terminal; returns Some(-1) (Ghidra leaves exitblock unset).
    fn check_retirement(&self, trace_idx: usize) -> Option<i32> {
        let trace = &self.traces[trace_idx];
        if trace.pathout != 0 {
            return None; // cc:869: only the first sibling checks
        }
        let bp_idx = trace.top_bp;
        let bp = &self.branch_points[bp_idx];
        if bp.depth == 0 {
            // cc:871-878: special conditions for the root branch point.
            for &pidx in &bp.paths {
                if !self.traces[pidx].active || !self.traces[pidx].terminal {
                    return None;
                }
            }
            return Some(-1);
        }
        // cc:879-889: non-root — all paths terminal or to the same exit node.
        let mut exit_block: i32 = -1;
        for &pidx in &bp.paths {
            let pt = &self.traces[pidx];
            if !pt.active {
                return None;
            }
            if pt.terminal {
                continue;
            }
            if exit_block == pt.dest_block_idx {
                continue;
            }
            if exit_block >= 0 {
                return None;
            }
            exit_block = pt.dest_block_idx;
        }
        Some(exit_block)
    }

    // Ghidra: blockaction.cc:839 TraceDAG::openBranch
    /// Given that a trace can be opened into its destnode, create a new
    /// BranchPoint there (with sub-traces per loop-DAG out edge,
    /// BranchPoint::createTraces cc:499-507). Returns the slot the caller
    /// must resume from:
    ///   - no new paths: the PARENT stays active and terminal (cc:844-851
    ///     returns parent->activeiter — "Do NOT remove from active list");
    ///   - otherwise the first child's slot (cc:857).
    fn open_branch(&mut self, trace_idx: usize) -> Option<usize> {
        let dest = self.traces[trace_idx].dest_block_idx;
        let top_bp = self.traces[trace_idx].top_bp;
        let parent_depth = self.branch_points[top_bp].depth;
        let parent_pathout = self.traces[trace_idx].pathout;

        let new_bp_idx = self.branch_points.len();
        self.branch_points.push(BranchPoint {
            parent: Some(top_bp),
            depth: parent_depth + 1,
            pathout: parent_pathout,
            ismark: false,
            top_block_idx: dest,
            paths: Vec::new(),
        });

        // createTraces (cc:499-507): one BlockTrace per loop-DAG out edge.
        let size_out = self.size_out(dest);
        for eo in 0..size_out {
            if !self.is_loop_dag_out(dest, eo) {
                continue;
            }
            if let Some(target) = self.get_out(dest, eo) {
                let new_trace_idx = self.traces.len();
                self.traces.push(BlockTrace {
                    top_bp: new_bp_idx,
                    pathout: self.branch_points[new_bp_idx].paths.len(),
                    bottom_block_idx: dest,
                    dest_block_idx: target,
                    edgelump: 1,
                    active: false,
                    terminal: false,
                    derived_bp: None,
                    deleted: false,
                    slot: 0,
                });
                self.branch_points[new_bp_idx].paths.push(new_trace_idx);
            }
        }

        if self.branch_points[new_bp_idx].paths.is_empty() {
            // cc:844-851: no new traces — return immediately to the parent
            // trace, marking it terminal but KEEPING it in the active list
            // (its BranchPoint retires later via checkRetirement, which
            // skips terminal-but-active paths).
            self.traces[trace_idx].derived_bp = None; // delete newbranch
            self.traces[trace_idx].terminal = true;
            self.traces[trace_idx].bottom_block_idx = -1;
            self.traces[trace_idx].dest_block_idx = -1;
            self.traces[trace_idx].edgelump = 0;
            return Some(self.traces[trace_idx].slot); // parent->activeiter
        }
        // cc:853-857: deactivate parent, activate children.
        self.traces[trace_idx].derived_bp = Some(new_bp_idx);
        self.remove_active(trace_idx);
        let first = self.branch_points[new_bp_idx].paths[0];
        let child_paths = self.branch_points[new_bp_idx].paths.clone();
        for pidx in child_paths {
            self.insert_active(pidx);
        }
        Some(self.traces[first].slot)
    }

    // Ghidra: blockaction.cc:900 TraceDAG::retireBranch
    /// Retire a BranchPoint: remove all its child traces from the active
    /// list and update the parent trace (bottom/destnode/edgelump, or
    /// terminal when all children were terminal), then re-activate it.
    /// Returns the slot to resume from (root → begin; else parent's slot).
    fn retire_branch(&mut self, bp_idx: usize, exit_block: i32) -> Option<usize> {
        let parent_trace_idx: Option<usize>;
        let edgeout_bl: i32;
        let edgelump_sum: i32;

        {
            let bp = &self.branch_points[bp_idx];
            // Non-root BranchPoints are always constructed from a parent
            // trace (cc:565-574), so `bp->parent` is only null for the root.
            parent_trace_idx = bp.parent.map(|p| self.branch_points[p].paths[bp.pathout]);
            let mut sum = 0i32;
            let mut ebl: i32 = -1;
            let paths = bp.paths.clone();
            for &pidx in &paths {
                let pt = &self.traces[pidx];
                if !pt.terminal {
                    sum += pt.edgelump;
                    if ebl < 0 {
                        ebl = pt.bottom_block_idx;
                    }
                }
            }
            edgelump_sum = sum;
            edgeout_bl = ebl;
            for &pidx in &paths {
                self.remove_active(pidx);
            }
        }

        if bp_idx == 0 {
            // cc:915-916: root — this is all there is to do.
            return self.begin_slot();
        }

        if let Some(pti) = parent_trace_idx {
            let pt = &mut self.traces[pti];
            pt.derived_bp = None; // cc:920: derived branchpoint is gone
            if edgeout_bl < 0 {
                // cc:921-926: all traces were terminal.
                pt.terminal = true;
                pt.bottom_block_idx = -1;
                pt.dest_block_idx = -1;
                pt.edgelump = 0;
            } else {
                // cc:927-931
                pt.bottom_block_idx = edgeout_bl;
                pt.dest_block_idx = exit_block;
                pt.edgelump = edgelump_sum;
            }
            self.insert_active(pti); // cc:932
            return Some(self.traces[pti].slot);
        }
        self.begin_slot()
    }

    // Ghidra: blockaction.cc:656 TraceDAG::removeTrace
    /// Add the trace's edge to likelygoto, bump the destnode visitcount, and
    /// either mark the trace terminal (it moved past its root branch — it
    /// STAYS ACTIVE, cc:665-672) or delete the path from its BranchPoint,
    /// shifting every trace above it down one slot (cc:673-686).
    fn remove_trace(&mut self, trace_idx: usize) {
        let bottom = self.traces[trace_idx].bottom_block_idx;
        let dest = self.traces[trace_idx].dest_block_idx;
        let edgelump = self.traces[trace_idx].edgelump;

        // cc:660: Create goto record.
        self.likely_goto.push(FloatingEdge { top: bottom, bottom: dest });
        // cc:661: Ignore edge(s) when deciding whether destnode can open.
        if dest >= 0 {
            self.visit_count[dest as usize] += edgelump;
        }

        let top_bp = self.traces[trace_idx].top_bp;
        let bp_top = self.branch_points[top_bp].top_block_idx;

        if bottom != bp_top {
            // cc:665-672: trace has moved past the root branch — terminal,
            // do NOT remove from the active list.
            self.traces[trace_idx].terminal = true;
            self.traces[trace_idx].bottom_block_idx = -1;
            self.traces[trace_idx].dest_block_idx = -1;
            self.traces[trace_idx].edgelump = 0;
            return;
        }

        // cc:673-686: remove the path from the BranchPoint; the root branch
        // will be marked as a goto.
        self.remove_active(trace_idx);
        let pathout = self.traces[trace_idx].pathout;
        let size = self.branch_points[top_bp].paths.len();
        for i in (pathout + 1)..size {
            // Move every trace above this pathout down one slot.
            let movedtrace = self.branch_points[top_bp].paths[i];
            self.traces[movedtrace].pathout -= 1;
            if let Some(dbp) = self.traces[movedtrace].derived_bp {
                self.branch_points[dbp].pathout -= 1;
            }
            self.branch_points[top_bp].paths[i - 1] = movedtrace;
        }
        self.branch_points[top_bp].paths.pop();
        self.traces[trace_idx].deleted = true; // delete trace
    }

    // Ghidra: blockaction.cc:617 TraceDAG::BadEdgeScore::compareFinal
    /// compareFinal(this, op2) == true ⇔ `this` is LESS likely to be the bad
    /// edge than op2 (blockaction.cc:616). Order: bigger siblingedge → less
    /// likely bad; terminal=0 → less likely bad; smaller distance → less
    /// likely bad; smaller depth → less likely bad.
    fn cmp_final_less_likely_bad(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> bool {
        if a.siblingedge != b.siblingedge {
            // cc:621: a bigger sibling edge is less likely to be the bad edge
            return b.siblingedge < a.siblingedge;
        }
        if a.terminal != b.terminal {
            return a.terminal < b.terminal;
        }
        if a.distance != b.distance {
            return a.distance < b.distance;
        }
        return self.branch_points[self.traces[a.trace].top_bp].depth
            < self.branch_points[self.traces[b.trace].top_bp].depth;
    }

    // Ghidra: blockaction.cc:694 TraceDAG::processExitConflict
    /// For each trace in [start, end): mark its BranchPoint's path to the
    /// root (markPath), then against every other trace in the group count a
    /// sibling edge when both come from the same BranchPoint and take the
    /// minimum BranchPoint::distance; finally un-mark (markPath toggles).
    fn process_exit_conflict(&mut self, list: &mut [BadEdgeScore], start: usize, end: usize) {
        for a in start..end {
            let startbp = self.traces[list[a].trace].top_bp;
            self.mark_path(startbp); // cc:705: mark path to root
            for b in (a + 1)..end {
                let iterbp = self.traces[list[b].trace].top_bp;
                if startbp == iterbp {
                    // cc:707-710: edge coming from the same BranchPoint.
                    list[a].siblingedge += 1;
                    list[b].siblingedge += 1;
                }
                let dist = self.bp_distance(startbp, iterbp); // cc:711
                // cc:713-717: distance is symmetric — update both minimums.
                if list[a].distance == -1 || list[a].distance > dist {
                    list[a].distance = dist;
                }
                if list[b].distance == -1 || list[b].distance > dist {
                    list[b].distance = dist;
                }
            }
            self.mark_path(startbp); // cc:720: unmark the path
        }
    }

    // Ghidra: blockaction.cc:730 TraceDAG::selectBadEdge
    /// Score every active non-terminal non-virtual trace (BadEdgeScore),
    /// sort by (exitproto index, branchpoint top index, pathout) for grouping
    /// (operator< cc:635-651), run processExitConflict per same-exit group,
    /// then scan for the trace MOST likely to be the bad edge
    /// (cc:772-782: maxiter advances whenever compareFinal(maxiter, iter)).
    fn select_bad_edge(&mut self) -> usize {
        let mut badedgelist: Vec<BadEdgeScore> = Vec::new();
        for &s in &self.active_slots {
            let idx = match s {
                Some(i) => i,
                None => continue,
            };
            let trace = &self.traces[idx];
            if trace.terminal {
                continue; // cc:736
            }
            let bp = &self.branch_points[trace.top_bp];
            // cc:737-738: never remove virtual edges (root bp with no bottom).
            if bp.top_block_idx < 0 && trace.bottom_block_idx < 0 {
                continue;
            }
            let dest = trace.dest_block_idx;
            badedgelist.push(BadEdgeScore {
                trace: idx,
                exitproto: dest,
                distance: -1,
                siblingedge: 0,
                terminal: if self.size_out(dest) == 0 { 1 } else { 0 },
            });
        }

        if badedgelist.is_empty() {
            // Unreachable under the oracle invariants (a stuck trace set
            // always contains a non-terminal non-virtual trace: virtual root
            // edges always pass checkOpen cc:816-818, and all-terminal
            // BranchPoints retire first). Deref guard mirrors list::begin().
            return self.active_slots.iter().find_map(|s| *s).unwrap_or(usize::MAX);
        }

        // cc:747: badedgelist.sort() — operator< groups by exit block, then
        // branch point, then path index. Rust sort_by is stable; the
        // comparator below is a total order on the same three keys.
        badedgelist.sort_by(|x, y| {
            let xi = x.exitproto;
            let yi = y.exitproto;
            if xi != yi {
                return xi.cmp(&yi);
            }
            let xbp = self.branch_points[self.traces[x.trace].top_bp].top_block_idx;
            let ybp = self.branch_points[self.traces[y.trace].top_bp].top_block_idx;
            if xbp != ybp {
                return xbp.cmp(&ybp);
            }
            self.traces[x.trace].pathout.cmp(&self.traces[y.trace].pathout)
        });

        // cc:749-770: find runs of traces to the same exit node and run
        // processExitConflict (cc:694-724) on each run of length > 1.
        let mut start = 0usize;
        while start < badedgelist.len() {
            let mut iter = start + 1;
            while iter < badedgelist.len()
                && badedgelist[iter].exitproto == badedgelist[start].exitproto
            {
                iter += 1;
            }
            if iter - start > 1 {
                self.process_exit_conflict(&mut badedgelist, start, iter);
            }
            start = iter;
        }

        // cc:772-782: linear max — maxiter starts at begin() and advances to
        // iter whenever compareFinal(maxiter, iter) (maxiter less likely bad).
        let mut maxiter = 0usize;
        for k in 1..badedgelist.len() {
            if self.cmp_final_less_likely_bad(&badedgelist[maxiter], &badedgelist[k]) {
                maxiter = k;
            }
        }
        badedgelist[maxiter].trace
    }

    // Ghidra: blockaction.cc:983 TraceDAG::pushBranches
    /// Main algorithm: push traces forward, marking bad edges as goto.
    pub fn push_branches(&mut self) {
        let step = std::env::var("RUDRA_GOTOSTEP").is_ok();
        // RUDRA_IRRED_DBG read once per process (SPEEDPROF-TRACEDAG-CONST-0001):
        // the four branch sites below fire once per loop EVENT (~1.41M on
        // VdbeExec) and std::env::var takes the global env lock + allocates;
        // a OnceLock bool is the identical observable (env is immutable
        // during the run). Same form as blockaction.rs IRRED_SW.
        static IRRED_SW: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let irred_dbg = *IRRED_SW
            .get_or_init(|| std::env::var("RUDRA_IRRED_DBG").map(|v| v == "1").unwrap_or(false));
        let mut missed: usize = 0;
        let mut current: Option<usize> = self.begin_slot();
        // Ghidra: blockaction.cc:983-1015 TraceDAG::pushBranches — the loop
        // has NO iteration cap; termination is structural (back/loop-exit
        // edges are excluded by isLoopDAGOut/In, and the missed>=activecount
        // fallback removes one non-terminal trace per pass, strictly
        // shrinking the candidate set). The former 5000-iter diagnostic
        // ceiling fired on sqlite3Pragma's final-trace round (~11.2k oracle
        // events, GIANTS-GA1-PRAGMADISPATCH-0001), truncating the likelygoto
        // list mid-walk and splitting the shared 40-case dispatch 19/21
        // instead of the oracle's 40/0; removed as unfaithful glue.
        while self.active_count > 0 {
            // cc:991-992: wrap to begin when the iterator reached end().
            if current.is_none() {
                current = self.begin_slot();
            }
            let curtrace = match current.and_then(|s| self.active_slots[s]) {
                Some(t) => t,
                None => continue, // unreachable when active_count > 0
            };
            if step {
                let t = &self.traces[curtrace];
                eprintln!(
                    "[RSTEP] act={} miss={} cur=(blk{},blk{})",
                    self.active_count, missed, t.bottom_block_idx, t.dest_block_idx
                );
            }
            if missed >= self.active_count {
                // cc:994-999: could not push any trace further — pick an
                // edge to be unstructured and restart from the beginning.
                let bad = self.select_bad_edge();
                if step {
                    let t = &self.traces[bad];
                    eprintln!(
                        "[RSTEP]   BADPICK blk{} -> blk{}",
                        t.bottom_block_idx, t.dest_block_idx
                    );
                }
                if irred_dbg {
                    let t = &self.traces[bad];
                    eprintln!("[TD] BADEDGE trace#{} ({}->{}) edgelump={}", bad, t.bottom_block_idx, t.dest_block_idx, t.edgelump);
                }
                self.remove_trace(bad);
                current = self.begin_slot();
                missed = 0;
            } else if let Some(exit_block) = self.check_retirement(curtrace) {
                // cc:1000-1003: resume at the iterator returned by retireBranch.
                if step {
                    eprintln!("[RSTEP]   RETIRE");
                }
                let bp_idx = self.traces[curtrace].top_bp;
                if irred_dbg {
                    let t = &self.traces[curtrace];
                    eprintln!("[TD] RETIRE trace#{} bp{} exit={} t.bot={} t.dest={} t.lump={}",
                        curtrace, bp_idx, exit_block, t.bottom_block_idx, t.dest_block_idx, t.edgelump);
                }
                current = self.retire_branch(bp_idx, exit_block);
                missed = 0;
            } else if self.check_open(curtrace) {
                // cc:1004-1007: resume at the iterator returned by openBranch.
                if step {
                    eprintln!("[RSTEP]   OPEN");
                }
                if irred_dbg {
                    let t = &self.traces[curtrace];
                    eprintln!("[TD] OPEN trace#{} t.bot={} t.dest={} t.lump={}",
                        curtrace, t.bottom_block_idx, t.dest_block_idx, t.edgelump);
                }
                current = self.open_branch(curtrace);
                missed = 0;
            } else {
                // cc:1008-1011
                if irred_dbg {
                    let t = &self.traces[curtrace];
                    let dest = t.dest_block_idx;
                    let sin = if dest >= 0 { self.size_in(dest) } else { 0 };
                    let vc = if dest >= 0 {
                        self.visit_count[dest as usize]
                    } else {
                        0
                    };
                    let mut ldag = 0;
                    for s2 in 0..sin {
                        if self.is_loop_dag_in(dest, s2) {
                            ldag += 1;
                        }
                    }
                    eprintln!("[TD] STALL trace#{} dest={} lump={} vc={} loopDAG_in={} total_in={}",
                        curtrace, dest, t.edgelump, vc, ldag, sin);
                }
                missed += 1;
                current = self.next_slot(current.unwrap());
            }
        }
    }

    // RUDRA-GLUE: run (initialize + pushBranches driver)
    /// Run the full TraceDAG: initialize, push branches, return likely goto edges.
    pub fn run(mut self) -> Vec<FloatingEdge> {
        self.initialize();
        self.push_branches();
        self.likely_goto
    }
}

// RUDRA-GLUE: generate_likely_gotos (Ghidra CollapseStructure::updateLoopBody
// whole-DAG branch, blockaction.cc:1233-1239: roots = every sizeIn==0 block).
/// Generate likely goto edges for a function's control-flow graph (no loop
/// restriction). Returns (source, dest) edges to consider as unstructured.
/// NOTE: the collapse pipeline inlines this in update_loop_body so the root
/// collection can walk the CollapseStructure's virtual list order (Ghidra's
/// mutating list has composites appended at the end); this free function
/// walks physical slot order and is kept only as a standalone helper.
pub fn generate_likely_gotos(graph: &BlockGraph) -> Vec<FloatingEdge> {
    // Find root blocks (size_in == 0). No size gate: the oracle traces any
    // graph (the previous `< 10` skip was invented, no oracle counterpart).
    // Consumed slots are skipped — Ghidra's list never contains components
    // that were folded into a composite (identifyInternal, block.cc:953-960),
    // and a stripped zombie can otherwise surface as a phantom sizeIn==0
    // root and poison the trace.
    let roots: Vec<i32> = (0..graph.get_size())
        .filter_map(|i| {
            graph.get_block(i).and_then(|b| {
                let r = b.read().unwrap();
                if r.size_in() == 0 && !graph.absorbed_into.contains_key(&r.get_index()) {
                    Some(r.get_index())
                } else {
                    None
                }
            })
        })
        .collect();

    if roots.is_empty() {
        return Vec::new();
    }

    let mut tdag = TraceDAG::new(graph);
    for r in roots {
        tdag.add_root(r);
    }
    tdag.run()
}
