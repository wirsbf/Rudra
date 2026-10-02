//! SAILR enhancement layer — the RegionIdentifier port.
//!
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr/analyses/decompiler/region_identifier.py + graph_region.py / kuna p7_regions kuna_regionid.rs)
//!
//! Port of angr's `RegionIdentifier`: an analysis-only pass that collapses a
//! *private copy* of a function's control-flow graph into a nested
//! [`GraphRegion`] tree.  This module is **not** part of upstream Ghidra and is
//! **not** wired into the default (faithful blockaction) structuring path.
//!
//! # Pipeline position (Phase 1: analysis only)
//!
//! `pick_connected_component → make_supergraph → (cyclic phase: find loop
//! headers, refine loop bodies, abstract cyclic regions) → (acyclic phase:
//! postdom-climbing region formation with incremental dominators) → top region`.
//!
//! # Input seam
//!
//! The identifier builds its working graph from a generic CFG projection —
//! [`RegionIdentifier::build_from_cfg`] takes per-block `(addr, branchy)`
//! facts plus the edge list and an entry address.  Phase 2's adapter will
//! drive this seam from `Funcdata::bblocks` (one node per basic block keyed
//! on its start address, one edge per CFG out-edge, `branchy` precomputed
//! from the block's tail op); Phase 1 drives it from synthetic test CFGs.
//!
//! # Determinism
//!
//! Iteration order, tie-breakers, and the panic-mode/guard-cap heuristics are
//! preserved from the reference.  Guard caps exist only to turn a mis-port
//! into an error instead of a hang; they are computed in 64-bit so they stay
//! inert for any real graph.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};

use crate::sailr::graph::{
    dfs_back_edges, dfs_postorder_deterministic, dominates, immediate_dominators,
    quasi_topological_sort, subgraph_between_nodes, IncrementalDominators, NodeKind, NodePool,
    NodeSet, RegionGraph, RegionId, RegionNodeId,
};

/// Fixpoint iteration cap: `~2*n^2`, computed in 64-bit.  Turns a mis-ported
/// guard into an error instead of a hang.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regionid.rs kuna_guard_cap)
fn guard_cap(num_nodes: i32) -> i64 {
    let n = num_nodes as i64;
    2 * n * n + 64
}

/// One identified region: port of angr's `GraphRegion` (read-only subset).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py GraphRegion / kuna p7_regions kuna_regionid.rs KunaGraphRegion)
#[derive(Debug, Clone, Default)]
pub struct GraphRegion {
    head: Option<RegionNodeId>,
    wrapper: Option<RegionNodeId>,
    graph: RegionGraph,
    has_succs: bool,
    successors: NodeSet,
    graph_with_successors: RegionGraph,
    has_full: bool,
    full_graph: RegionGraph,
    cyclic: bool,
    cyclic_ancestor: bool,
}

impl GraphRegion {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py head property / kuna p7_regions getHead)
    /// Entry node (`None` only before the identifier fills it).
    pub fn get_head(&self) -> Option<RegionNodeId> {
        self.head
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions getWrapper)
    /// Wrapper node in the parent graph.
    pub fn get_wrapper(&self) -> Option<RegionNodeId> {
        self.wrapper
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py graph property / kuna p7_regions getGraph)
    /// Internal subgraph.
    pub fn get_graph(&self) -> &RegionGraph {
        &self.graph
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py successors / kuna p7_regions hasSuccessorInfo)
    /// Is successor info present?
    pub fn has_successor_info(&self) -> bool {
        self.has_succs
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py successors / kuna p7_regions getSuccessors)
    /// External successors.
    pub fn get_successors(&self) -> &NodeSet {
        &self.successors
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions getGraphWithSuccessors)
    /// Subgraph + frontier.
    pub fn get_graph_with_successors(&self) -> &RegionGraph {
        &self.graph_with_successors
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions hasFullGraph)
    /// Is the full loop graph present? (cyclic regions only)
    pub fn has_full_graph(&self) -> bool {
        self.has_full
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions getFullGraph)
    /// Full loop graph (all edges among loop nodes incl. entries/exits).
    pub fn get_full_graph(&self) -> &RegionGraph {
        &self.full_graph
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py cyclic / kuna p7_regions isCyclic)
    /// Does the region contain a loop?
    pub fn is_cyclic(&self) -> bool {
        self.cyclic
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions hasCyclicAncestor)
    /// Is some ancestor region cyclic?
    pub fn has_cyclic_ancestor(&self) -> bool {
        self.cyclic_ancestor
    }
}

/// One identified cyclic (loop) region, projected onto basic-block start
/// addresses for the structurer: `head_addr` is the loop head's start
/// address, `body` every basic-block start address inside the loop
/// (recursively resolved through nested regions/multi-nodes), `exits` every
/// loop-successor block start address (the angr `GraphRegion.successors`
/// frontier).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py successors + region_identifier.py _refine_loop / kuna p7_regions KunaCyclicLoop)
#[derive(Debug, Clone)]
pub struct CyclicLoop {
    pub head_addr: u64,
    pub body: BTreeSet<u64>,
    pub exits: BTreeSet<u64>,
}

/// Callback interface for walking the blocks of a region tree:
/// `visit_block` fires once per leaf block in deterministic region order
/// (merged chains expand to their members); `enter_region`/`exit_region`
/// bracket each nested region.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions KunaRegionVisitor)
pub trait RegionVisitor {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions enterRegion)
    /// Called before a region's nodes.
    fn enter_region(&mut self, _region: &GraphRegion) {}

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions exitRegion)
    /// Called after a region's nodes.
    fn exit_region(&mut self, _region: &GraphRegion) {}

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions visitBlock)
    /// Called for each leaf block: `(external block payload, addr)`.
    fn visit_block(&mut self, block: Option<usize>, addr: u64);
}

/// The region identification analysis (port of angr's `RegionIdentifier`).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr/analyses/decompiler/region_identifier.py RegionIdentifier / kuna p7_regions KunaRegionIdentifier)
pub struct RegionIdentifier {
    pool: NodePool,
    region_pool: Vec<GraphRegion>,
    next_ident: u32,
    largest_successor_tree_outside_loop: bool,
    refine_loops_with_single_successor: bool,
    complete_successors: bool,
    has_entry_addr: bool,
    entry_addr: u64,
    work_graph: RegionGraph,
    start_node: Option<RegionNodeId>,
    loop_headers: Vec<RegionNodeId>,
    node_order: BTreeMap<RegionNodeId, (i32, i32)>,
    top_region: Option<RegionId>,
    regions_by_block_addrs: Vec<Vec<u64>>,
    computed: bool,
}

impl Default for RegionIdentifier {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: Default boilerplate, no reference counterpart)
    fn default() -> Self {
        RegionIdentifier::new()
    }
}

impl RegionIdentifier {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py __init__ defaults / kuna p7_regions new)
    /// Construct a fresh identifier.
    pub fn new() -> RegionIdentifier {
        RegionIdentifier {
            pool: NodePool::new(),
            region_pool: Vec::new(),
            next_ident: 0,
            largest_successor_tree_outside_loop: true, // angr default
            refine_loops_with_single_successor: false, // angr default
            complete_successors: false,                // angr default
            has_entry_addr: false,
            entry_addr: 0,
            work_graph: RegionGraph::new(),
            start_node: None,
            loop_headers: Vec::new(),
            node_order: BTreeMap::new(),
            top_region: None,
            regions_by_block_addrs: Vec::new(),
            computed: false,
        }
    }

    //
    // Options / inputs
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py largest_successor_tree_outside_loop option / kuna p7_regions set*)
    /// Set option (before compute).
    pub fn set_largest_successor_tree_outside_loop(&mut self, val: bool) {
        self.largest_successor_tree_outside_loop = val;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py refine_loops_with_single_successor option / kuna p7_regions set*)
    /// Set option (before compute).
    pub fn set_refine_loops_with_single_successor(&mut self, val: bool) {
        self.refine_loops_with_single_successor = val;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py complete_successors option / kuna p7_regions set*)
    /// Set option (before compute).
    pub fn set_complete_successors(&mut self, val: bool) {
        self.complete_successors = val;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py entry addr / kuna p7_regions setEntryAddr)
    /// Set the entry address.
    pub fn set_entry_addr(&mut self, addr: u64) {
        self.has_entry_addr = true;
        self.entry_addr = addr;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions newNode)
    /// Allocate a pooled node.
    fn new_node(&mut self, kind: NodeKind, addr: u64) -> RegionNodeId {
        let id = self.pool.make(kind, addr, self.next_ident);
        self.next_ident += 1;
        id
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions newRegion)
    /// Allocate a pooled region.
    fn new_region(&mut self) -> RegionId {
        let id = RegionId(self.region_pool.len() as u32);
        self.region_pool.push(GraphRegion::default());
        id
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions region)
    /// Borrow a region payload.
    pub fn region(&self, id: RegionId) -> &GraphRegion {
        &self.region_pool[id.0 as usize]
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions addSyntheticBlock)
    /// Input B: add a synthetic test node.
    pub fn add_synthetic_block(&mut self, addr: u64) -> RegionNodeId {
        let n = self.new_node(NodeKind::Block, addr);
        self.work_graph.add_node(&self.pool, n);
        n
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions addSyntheticEdge)
    /// Input B: add a synthetic test edge.
    pub fn add_synthetic_edge(&mut self, a: RegionNodeId, b: RegionNodeId) {
        self.work_graph.add_edge(&self.pool, a, b);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py input graph / kuna p7_regions buildFromBlockGraph)
    ///
    /// Input A seam (the Phase 2 adapter point): build the working graph from
    /// a generic CFG projection — one node per block keyed on its start
    /// address (carrying the external block index as payload and the
    /// precomputed "ends with BRANCHIND/CBRANCH" predicate), one edge per CFG
    /// out-edge, entry address set from `entry`.  Must run on a fresh
    /// identifier (before `compute`); the working graph must be empty.
    ///
    /// * `blocks[i] = (addr, external_index, branchy)` — `external_index` is
    ///   an opaque payload (Phase 2: the bblocks `BlockId`); `branchy` is the
    ///   precomputed multi-way-branch predicate the supergraph merge consults.
    /// * `edges` — pairs of block *indices* into `blocks`.
    pub fn build_from_cfg(
        &mut self,
        blocks: &[(u64, usize, bool)],
        edges: &[(usize, usize)],
        entry: u64,
    ) -> Result<()> {
        if self.work_graph.num_nodes() != 0 {
            return Err(anyhow!(
                "sailr regionid: build_from_cfg on a non-empty working graph"
            ));
        }
        if blocks.is_empty() {
            return Err(anyhow!(
                "sailr regionid: build_from_cfg on an empty block list"
            ));
        }
        let mut node: Vec<RegionNodeId> = Vec::with_capacity(blocks.len());
        for &(addr, ext, branchy) in blocks.iter() {
            let n = self.new_node(NodeKind::Block, addr);
            {
                let nm = self.pool.get_mut(n);
                nm.set_block(ext);
                nm.set_branchy(branchy);
            }
            self.work_graph.add_node(&self.pool, n);
            node.push(n);
        }
        for &(a, b) in edges.iter() {
            if a >= node.len() || b >= node.len() {
                return Err(anyhow!("sailr regionid: edge index out of range"));
            }
            self.work_graph.add_edge(&self.pool, node[a], node[b]);
        }
        self.set_entry_addr(entry);
        Ok(())
    }

    //
    // Driver
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py analyze / kuna p7_regions compute)
    /// Run the analysis; returns the top-level region id.
    pub fn compute(&mut self) -> Result<RegionId> {
        if self.computed {
            return self
                .top_region
                .ok_or_else(|| anyhow!("sailr regionid: top region missing"));
        }
        self.computed = true;
        if self.work_graph.num_nodes() == 0 {
            return Err(anyhow!("sailr regionid: empty input graph"));
        }
        let mut g = std::mem::take(&mut self.work_graph);
        self.pick_connected_component(&mut g);
        self.make_supergraph(&mut g)?;
        self.start_node = Some(self.get_start_node(&g)?);
        self.compute_node_order(&g)?;
        let top = self.make_regions(&mut g)?;
        self.work_graph = g;
        self.top_region = Some(top);
        self.build_regions_by_block_addrs();
        Ok(top)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions getTopRegion)
    /// Result (None before compute).
    pub fn get_top_region(&self) -> Option<RegionId> {
        self.top_region
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_regions_by_block_addrs / kuna p7_regions getRegionsByBlockAddrs)
    /// Flat region lists (each inner vec = one region's leaf block addrs).
    pub fn get_regions_by_block_addrs(&self) -> &[Vec<u64>] {
        &self.regions_by_block_addrs
    }

    //
    // Connected component / supergraph
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _pick_one_connected_component / kuna p7_regions pickConnectedComponent)
    /// Keep one weakly connected component: the entry component if the entry
    /// address is known, else the largest.
    fn pick_connected_component(&self, g: &mut RegionGraph) {
        let mut all_nodes: Vec<RegionNodeId> = Vec::new();
        g.get_nodes(&mut all_nodes);
        let mut components: Vec<Vec<RegionNodeId>> = Vec::new();
        let mut assigned: BTreeSet<RegionNodeId> = BTreeSet::new();
        for &start in all_nodes.iter() {
            if assigned.contains(&start) {
                continue;
            }
            let mut comp: Vec<RegionNodeId> = vec![start];
            assigned.insert(start);
            let mut pos = 0usize;
            while pos < comp.len() {
                let cur = comp[pos];
                pos += 1;
                let succs: Vec<RegionNodeId> = g.get_succs(cur).unwrap_or(&[]).to_vec();
                for s in succs {
                    if !assigned.contains(&s) {
                        assigned.insert(s);
                        comp.push(s);
                    }
                }
                let preds: Vec<RegionNodeId> = g.get_preds(cur).unwrap_or(&[]).to_vec();
                for p in preds {
                    if !assigned.contains(&p) {
                        assigned.insert(p);
                        comp.push(p);
                    }
                }
            }
            components.push(comp);
        }
        if components.len() <= 1 {
            return;
        }

        let mut chosen: i64 = -1;
        let mut largest: usize = 0;
        for i in 0..components.len() {
            if components[i].len() > components[largest].len() {
                largest = i;
            }
            if self.has_entry_addr && chosen < 0 {
                for &n in components[i].iter() {
                    if self.pool.get(n).get_addr() == self.entry_addr {
                        chosen = i as i64;
                        break;
                    }
                }
                if chosen >= 0 {
                    break; // stop scanning once the entry component is found
                }
            }
        }
        let chosen = if chosen < 0 { largest } else { chosen as usize };

        let mut keep: BTreeSet<RegionNodeId> = BTreeSet::new();
        for &n in components[chosen].iter() {
            keep.insert(n);
        }
        for &n in all_nodes.iter() {
            if !keep.contains(&n) {
                g.remove_node(n);
            }
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _block_ends_with_indirect_jump_or_call / kuna p7_regions endsWithBranchindOrCbranch)
    /// Does the node (or a multi-node's last member) end with a multi-way
    /// branch?  Read from the precomputed predicate parked by the input seam.
    fn ends_with_branchind_or_cbranch(&self, n: RegionNodeId) -> bool {
        let node = self.pool.get(n);
        let last = if node.is_multi() {
            match node.get_chain().last() {
                Some(&m) => m,
                None => return false,
            }
        } else {
            n
        };
        let last_node = self.pool.get(last);
        if last_node.get_kind() != NodeKind::Block {
            return false;
        }
        last_node.ends_with_branchind_or_cbranch()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _merge_nodes(force_multinode=True) / kuna p7_regions mergeNodes)
    /// Merge `a -> b` into a `Multi` node (always force_multinode — the only
    /// caller is the supergraph).
    fn merge_nodes(
        &mut self,
        g: &mut RegionGraph,
        a: RegionNodeId,
        b: RegionNodeId,
    ) -> Result<RegionNodeId> {
        let mut in_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        g.in_edges(a, &mut in_e)?;
        let mut out_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        g.out_edges(b, &mut out_e)?;

        let mut members: Vec<RegionNodeId> = Vec::new();
        for &src in &[a, b] {
            let node = self.pool.get(src);
            if node.is_multi() {
                for &m in node.get_chain() {
                    members.push(m);
                }
            } else if node.get_kind() == NodeKind::Block {
                members.push(src);
            } else {
                return Err(anyhow!("sailr regionid: cannot merge non-block node"));
            }
        }

        let addr = self.pool.get(members[0]).get_addr();
        let m = self.new_node(NodeKind::Multi, addr);
        self.pool.get_mut(m).set_chain(members);

        g.remove_node(a);
        g.remove_node(b);
        g.add_node(&self.pool, m);
        for (mut src, _dst) in in_e {
            if src == b {
                src = m; // b -> a back edge becomes a self loop
            }
            g.add_edge(&self.pool, src, m);
        }
        for (_src, mut dst) in out_e {
            if dst == a {
                dst = m; // b -> a forward arm of a 2-cycle
            }
            g.add_edge(&self.pool, m, dst);
        }
        Ok(m)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_supergraph / kuna p7_regions makeSupergraph)
    /// Merge single-out -> single-in chains to a fixpoint.  The entry node is
    /// never merged INTO; a node ending with a multi-way branch is never
    /// merged into either (the switch/cbranch boundary survives).
    fn make_supergraph(&mut self, g: &mut RegionGraph) -> Result<()> {
        let mut entry_node: Option<RegionNodeId> = None;
        if self.has_entry_addr {
            for key in g.node_keys() {
                if key.addr == self.entry_addr {
                    entry_node = Some(key.id);
                    break;
                }
            }
        }
        loop {
            let mut merged = false;
            let mut edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
            g.all_edges(&mut edges);
            for (src, dst) in edges {
                if let Some(en) = entry_node {
                    if dst == en {
                        continue; // the entry node must never be merged INTO
                    }
                }
                if g.size_out(src)? == 1
                    && g.size_in(dst)? == 1
                    && src != dst
                    && !self.ends_with_branchind_or_cbranch(dst)
                {
                    let m = self.merge_nodes(g, src, dst)?;
                    if entry_node == Some(src) {
                        entry_node = Some(m);
                    }
                    merged = true;
                    break;
                }
            }
            if !merged {
                break; // clean pass over all edges: fixpoint
            }
        }
        Ok(())
    }

    //
    // Node lookup / ordering plumbing
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _get_start_node / kuna p7_regions getStartNode)
    /// First in-degree-0 node (or entry-addr node).
    fn get_start_node(&self, g: &RegionGraph) -> Result<RegionNodeId> {
        for key in g.node_keys() {
            if g.get_preds(key.id)?.is_empty() {
                return Ok(key.id);
            }
        }
        if self.has_entry_addr {
            for key in g.node_keys() {
                if key.addr == self.entry_addr {
                    return Ok(key.id);
                }
            }
        }
        Err(anyhow!("sailr regionid: cannot find the start node from the graph"))
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions getEntryNode)
    /// Node with the entry address (or None).
    fn get_entry_node(&self, g: &RegionGraph) -> Option<RegionNodeId> {
        if !self.has_entry_addr {
            return None;
        }
        for key in g.node_keys() {
            if key.addr == self.entry_addr {
                return Some(key.id);
            }
        }
        None
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions nodeByAddr)
    /// First node with the given address.
    fn node_by_addr(&self, g: &RegionGraph, addr: u64) -> Result<RegionNodeId> {
        for key in g.node_keys() {
            if key.addr == addr {
                return Ok(key.id);
            }
        }
        Err(anyhow!("sailr regionid: no node with the requested address"))
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py node ordering / kuna p7_regions computeNodeOrder)
    /// Fill `node_order` via quasi-topological sort.
    fn compute_node_order(&mut self, g: &RegionGraph) -> Result<()> {
        let mut sorted: Vec<RegionNodeId> = Vec::new();
        quasi_topological_sort(&self.pool, g, &mut sorted)?;
        self.node_order.clear();
        for (i, &n) in sorted.iter().enumerate() {
            self.node_order.insert(n, (i as i32, 0));
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions orderOf)
    /// The order pair of a node, or an error if missing.
    fn order_of(&self, n: RegionNodeId) -> Result<(i32, i32)> {
        self.node_order
            .get(&n)
            .copied()
            .ok_or_else(|| anyhow!("sailr regionid: node missing from node order"))
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _sort_nodes_by_order / kuna p7_regions sortByNodeOrder)
    /// Sort by `node_order` (stable).
    fn sort_by_node_order(&self, nodes: &mut [RegionNodeId]) -> Result<()> {
        for &n in nodes.iter() {
            self.order_of(n)?;
        }
        let mut err: Option<anyhow::Error> = None;
        nodes.sort_by(|&a, &b| match (self.order_of(a), self.order_of(b)) {
            (Ok(oa), Ok(ob)) => oa.cmp(&ob),
            _ => {
                if err.is_none() {
                    err = Some(anyhow!("sailr regionid: node missing from node order"));
                }
                std::cmp::Ordering::Equal
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _slice_graph + self-loop hack / kuna p7_regions sliceGraph)
    /// `slice_graph` (+ self-loop hack: an infinite self-loop slices to
    /// nothing; keep the body).
    fn slice_graph(
        &self,
        g: &RegionGraph,
        node: RegionNodeId,
        frontier: &NodeSet,
        include_frontier: bool,
        res: &mut RegionGraph,
    ) -> Result<()> {
        subgraph_between_nodes(&self.pool, g, node, frontier, include_frontier, res)?;
        if res.num_nodes() == 0 && g.has_edge(node, node) {
            res.add_edge(&self.pool, node, node);
        }
        Ok(())
    }

    //
    // Cyclic phase
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _find_loop_headers / kuna p7_regions findLoopHeaders)
    /// Back-edge targets, in `node_order`.
    fn find_loop_headers(&self, g: &RegionGraph, res: &mut Vec<RegionNodeId>) -> Result<()> {
        let start = self
            .start_node
            .ok_or_else(|| anyhow!("sailr regionid: no start node"))?;
        let mut back_edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        dfs_back_edges(&self.pool, g, start, &mut back_edges)?;
        let mut head_set: NodeSet = NodeSet::new();
        for (_src, dst) in back_edges {
            head_set.insert(self.pool.key(dst));
        }
        res.clear();
        for k in head_set.iter() {
            res.push(k.id);
        }
        self.sort_by_node_order(res)?;
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _find_initial_loop_nodes / kuna p7_regions findInitialLoopNodes)
    /// Initial loop nodes: natural-loop slice from `head` to its latches, then
    /// switch-case expansion (a node with >2 non-self successors pulls in
    /// successors whose predecessors all sit inside the slice already).
    fn find_initial_loop_nodes(
        &self,
        g: &RegionGraph,
        head: RegionNodeId,
        res: &mut NodeSet,
    ) -> Result<()> {
        let start = self
            .start_node
            .ok_or_else(|| anyhow!("sailr regionid: no start node"))?;
        let mut back_edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        dfs_back_edges(&self.pool, g, start, &mut back_edges)?;
        let mut latching: NodeSet = NodeSet::new();
        for (src, dst) in back_edges {
            if dst == head {
                latching.insert(self.pool.key(src));
            }
        }
        let mut loop_sub = RegionGraph::new();
        let mut idom_map: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
        immediate_dominators(&self.pool, g, start, &mut idom_map)?;
        if latching.iter().all(|lk| dominates(&idom_map, head, lk.id)) {
            // Reducible: the natural loop (nodes on a path from head to a
            // latch; a latch reachable only through another latch stays in
            // the body).
            loop_sub = self.natural_loop_subgraph(g, head, &latching)?;
        } else {
            // Retreating edges of an irreducible region (e.g. a goto into
            // the middle of a loop body): slice from the head to the
            // latching nodes without walking past them, keeping the
            // pseudo-loop small.
            self.slice_graph(g, head, &latching, true, &mut loop_sub)?;
        }

        // Switch-case expansion.
        let mut guard: i64 = 0;
        let guard_max = guard_cap(g.num_nodes());
        loop {
            guard += 1;
            if guard > guard_max {
                return Err(anyhow!("sailr regionid: initial loop nodes did not converge"));
            }
            let mut updated = false;
            let mut snap: Vec<RegionNodeId> = Vec::new();
            loop_sub.get_nodes(&mut snap);
            for node in snap {
                let mut nonself: Vec<RegionNodeId> = Vec::new();
                for &s in g.get_succs(node)? {
                    if s != node {
                        nonself.push(s);
                    }
                }
                if nonself.len() as i32 > 2 {
                    for succ in nonself {
                        if loop_sub.has_edge(node, succ) {
                            continue;
                        }
                        let mut all_in = true;
                        for &p in g.get_preds(succ)? {
                            if !loop_sub.contains_node(p) {
                                all_in = false;
                                break;
                            }
                        }
                        if all_in {
                            updated = true;
                            loop_sub.add_edge(&self.pool, node, succ);
                        }
                    }
                }
            }
            if !updated {
                break;
            }
        }

        res.clear();
        for key in loop_sub.node_keys() {
            res.insert(*key);
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _natural_loop_subgraph)
    ///
    /// The subgraph induced by the natural loop of `head`: head plus every
    /// node on a path from head to a latching node.  Latching nodes are
    /// expanded too, so a latch reachable only through another latch stays
    /// in the body.
    fn natural_loop_subgraph(
        &self,
        g: &RegionGraph,
        head: RegionNodeId,
        latching: &NodeSet,
    ) -> Result<RegionGraph> {
        // Nodes that reach a latching node without passing through head.
        let mut reaches_latch: BTreeSet<RegionNodeId> =
            latching.iter().map(|k| k.id).collect();
        let mut queue: std::collections::VecDeque<RegionNodeId> =
            latching.iter().map(|k| k.id).collect();
        while let Some(node) = queue.pop_front() {
            if node == head {
                continue;
            }
            for &p in g.get_preds(node)? {
                if !reaches_latch.contains(&p) {
                    reaches_latch.insert(p);
                    queue.push_back(p);
                }
            }
        }

        // Among them, nodes reachable from head.
        let mut loop_nodes: BTreeSet<RegionNodeId> = BTreeSet::new();
        loop_nodes.insert(head);
        let mut queue: std::collections::VecDeque<RegionNodeId> =
            std::collections::VecDeque::new();
        queue.push_back(head);
        while let Some(node) = queue.pop_front() {
            for &succ in g.get_succs(node)? {
                if reaches_latch.contains(&succ) && !loop_nodes.contains(&succ) {
                    loop_nodes.insert(succ);
                    queue.push_back(succ);
                }
            }
        }

        let mut sub = RegionGraph::new();
        sub.add_node(&self.pool, head);
        for &node in loop_nodes.iter() {
            for &succ in g.get_succs(node)? {
                if loop_nodes.contains(&succ) {
                    sub.add_edge(&self.pool, node, succ);
                }
            }
        }
        Ok(sub)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _refine_loop / kuna p7_regions refineLoop)
    /// Refine the loop body/exit split in three stages:
    /// 1. absorb single-in-degree, at-most-single-out exit nodes;
    /// 2. absorb dominated exit candidates whose preds are all in the loop;
    /// 3. zero exits left — pull the largest single-owner successor tree back
    ///    OUT of the loop and make its root the exit.
    fn refine_loop(
        &self,
        g: &RegionGraph,
        head: RegionNodeId,
        loop_nodes: &mut NodeSet,
        exit_nodes: &mut NodeSet,
    ) -> Result<()> {
        if (self.refine_loops_with_single_successor && exit_nodes.is_empty())
            || (!self.refine_loops_with_single_successor && exit_nodes.len() <= 1)
        {
            return Ok(());
        }

        let initial_exit_nodes = exit_nodes.clone();

        // Stage 1: absorb single-in-degree, at-most-single-out exit nodes.
        let mut guard: i64 = 0;
        let guard_max = guard_cap(g.num_nodes());
        loop {
            guard += 1;
            if guard > guard_max {
                return Err(anyhow!("sailr regionid: loop refinement (stage 1) did not converge"));
            }
            let mut added_any = false;
            let snap: Vec<crate::sailr::graph::NodeKey> = exit_nodes.iter().copied().collect();
            for ek in snap {
                let exit_node = ek.id;
                if g.size_in(exit_node)? == 1 && g.size_out(exit_node)? <= 1 {
                    added_any = true;
                    loop_nodes.insert(ek);
                    for &s in g.get_succs(exit_node)? {
                        let sk = self.pool.key(s);
                        if !loop_nodes.contains(&sk) {
                            exit_nodes.insert(sk);
                        }
                    }
                    exit_nodes.remove(&ek);
                }
            }
            if !added_any {
                break;
            }
        }
        if exit_nodes.len() <= 1 {
            return Ok(());
        }

        // Stage 2: absorb dominated exit candidates whose preds are all in the loop.
        let mut idom_map: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
        immediate_dominators(&self.pool, g, head, &mut idom_map)?;

        let mut sorted_exits: Vec<RegionNodeId> = exit_nodes.iter().map(|k| k.id).collect();
        self.sort_by_node_order(&mut sorted_exits)?;
        let mut have_new_exits = true;
        let mut side_graph = RegionGraph::new();
        let mut guard: i64 = 0;
        while sorted_exits.len() > 1 && have_new_exits {
            guard += 1;
            if guard > guard_max {
                return Err(anyhow!("sailr regionid: loop refinement (stage 2) did not converge"));
            }
            let mut cand_order: Vec<RegionNodeId> = Vec::new();
            {
                let snap = sorted_exits.clone();
                for n in snap {
                    let mut all_preds_in = true;
                    for &p in g.get_preds(n)? {
                        if p != n && !loop_nodes.contains(&self.pool.key(p)) {
                            all_preds_in = false;
                            break;
                        }
                    }
                    if all_preds_in && dominates(&idom_map, head, n) {
                        cand_order.push(n);
                    }
                }
            }
            // Union of every candidate's would-be new exits (computed BEFORE any
            // candidate is absorbed — the per-candidate sets are deliberately
            // stale).
            let mut all_new_exit_candidates: NodeSet = NodeSet::new();
            for &c in cand_order.iter() {
                for &s in g.get_succs(c)? {
                    let sk = self.pool.key(s);
                    if !loop_nodes.contains(&sk) {
                        all_new_exit_candidates.insert(sk);
                    }
                }
            }
            // Progress guard: if every candidate is itself a new-exit candidate,
            // absorbing none would loop forever — clear the veto set.
            let mut all_vetoed = true;
            for &c in cand_order.iter() {
                if !all_new_exit_candidates.contains(&self.pool.key(c)) {
                    all_vetoed = false;
                    break;
                }
            }
            if all_vetoed {
                all_new_exit_candidates.clear();
            }
            // Absorb the surviving candidates.
            let mut new_exit_nodes: NodeSet = NodeSet::new();
            for &n in cand_order.iter() {
                if all_new_exit_candidates.contains(&self.pool.key(n)) {
                    continue;
                }
                loop_nodes.insert(self.pool.key(n));
                if let Some(pos) = sorted_exits.iter().position(|&x| x == n) {
                    sorted_exits.remove(pos);
                }
                for &s in g.get_succs(n)? {
                    // Recomputed LIVE.
                    let sk = self.pool.key(s);
                    if !loop_nodes.contains(&sk) {
                        new_exit_nodes.insert(sk);
                        side_graph.add_edge(&self.pool, n, s);
                    }
                }
            }
            have_new_exits = !new_exit_nodes.is_empty();
            for nk in new_exit_nodes.iter() {
                if !sorted_exits.contains(&nk.id) {
                    sorted_exits.push(nk.id);
                }
            }
            self.sort_by_node_order(&mut sorted_exits)?;
        }
        exit_nodes.clear();
        for &n in sorted_exits.iter() {
            exit_nodes.insert(self.pool.key(n));
        }
        let exit_keys: Vec<crate::sailr::graph::NodeKey> = exit_nodes.iter().copied().collect();
        for ek in exit_keys {
            loop_nodes.remove(&ek);
        }

        // Stage 3: zero exits left — pull the LARGEST single-owner successor
        // tree back OUT of the loop and make its root the exit.
        if self.largest_successor_tree_outside_loop && exit_nodes.is_empty() {
            let mut initial_exit_to_new: BTreeMap<crate::sailr::graph::NodeKey, NodeSet> =
                BTreeMap::new();
            let mut newnode_to_initial_exits: BTreeMap<crate::sailr::graph::NodeKey, NodeSet> =
                BTreeMap::new();
            for ek in initial_exit_nodes.iter() {
                let initial_exit = ek.id;
                if !side_graph.contains_node(initial_exit) {
                    continue;
                }
                let mut seen: BTreeSet<RegionNodeId> = BTreeSet::new();
                seen.insert(initial_exit);
                let mut queue: Vec<RegionNodeId> = vec![initial_exit];
                let mut pos = 0usize;
                while pos < queue.len() {
                    let cur = queue[pos];
                    pos += 1;
                    let succs = side_graph.get_sorted_succs(&self.pool, cur)?;
                    for s in succs {
                        if seen.contains(&s) {
                            continue;
                        }
                        seen.insert(s);
                        let sk = self.pool.key(s);
                        initial_exit_to_new.entry(*ek).or_default().insert(sk);
                        newnode_to_initial_exits.entry(sk).or_default().insert(*ek);
                        queue.push(s);
                    }
                }
            }
            let inverse_snapshot: Vec<(crate::sailr::graph::NodeKey, Vec<crate::sailr::graph::NodeKey>)> =
                newnode_to_initial_exits
                    .iter()
                    .map(|(k, v)| (*k, v.iter().copied().collect()))
                    .collect();
            for (newnode, owners) in inverse_snapshot {
                for owner in owners {
                    initial_exit_to_new.entry(owner).or_default().insert(newnode);
                }
            }
            // Drop subtrees with more than one out-of-tree predecessor.
            let mut drop_list: Vec<crate::sailr::graph::NodeKey> = Vec::new();
            for (exit_key, subtree) in initial_exit_to_new.iter() {
                let mut subtree_preds: BTreeSet<RegionNodeId> = BTreeSet::new();
                for sk in subtree.iter() {
                    for &p in g.get_preds(sk.id)? {
                        if !subtree.contains(&self.pool.key(p)) {
                            subtree_preds.insert(p);
                        }
                    }
                    if subtree_preds.len() > 1 {
                        break;
                    }
                }
                if subtree_preds.len() > 1 {
                    drop_list.push(*exit_key);
                }
            }
            for d in drop_list {
                initial_exit_to_new.remove(&d);
            }

            if !initial_exit_to_new.is_empty() {
                let mut max_size: i32 = -1;
                let mut max_count: i32 = 0;
                let mut max_exit: Option<crate::sailr::graph::NodeKey> = None;
                for (exit_key, subtree) in initial_exit_to_new.iter() {
                    let sz = subtree.len() as i32;
                    if sz > max_size {
                        max_size = sz;
                        max_count = 1;
                        max_exit = Some(*exit_key);
                    } else if sz == max_size {
                        max_count += 1;
                    }
                }
                if max_count == 1 {
                    let max_exit = max_exit.unwrap();
                    let subtree = initial_exit_to_new[&max_exit].clone();
                    let mut all_single_owner = true;
                    for sk in subtree.iter() {
                        match newnode_to_initial_exits.get(sk) {
                            Some(owners) if owners.len() == 1 => {}
                            _ => {
                                all_single_owner = false;
                                break;
                            }
                        }
                    }
                    if all_single_owner {
                        for sk in subtree.iter() {
                            loop_nodes.remove(sk);
                        }
                        loop_nodes.remove(&max_exit);
                        exit_nodes.insert(max_exit);
                    }
                }
            }
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_cyclic_region / kuna p7_regions makeCyclicRegion)
    ///
    /// Identify one cyclic (loop) region at `head`.  Returns `None` when the
    /// loop contains another (still-unstructured) header.
    fn make_cyclic_region(
        &mut self,
        head: RegionNodeId,
        g: &mut RegionGraph,
    ) -> Result<Option<RegionId>> {
        let original_entry = self.get_entry_node(g);

        let mut initial_loop_nodes: NodeSet = NodeSet::new();
        self.find_initial_loop_nodes(g, head, &mut initial_loop_nodes)?;

        // Make sure no OTHER loop header is contained in this loop (address
        // compare).
        let head_addr = self.pool.get(head).get_addr();
        for nk in initial_loop_nodes.iter() {
            if self.pool.get(nk.id).get_addr() == head_addr {
                continue;
            }
            if self.loop_headers.contains(&nk.id) {
                return Ok(None);
            }
        }

        let mut normal_entries: NodeSet = NodeSet::new();
        for &p in g.get_preds(head)? {
            if !initial_loop_nodes.contains(&self.pool.key(p)) {
                normal_entries.insert(self.pool.key(p));
            }
        }
        let mut abnormal_entries: NodeSet = NodeSet::new();
        for nk in initial_loop_nodes.iter() {
            if nk.id == head {
                continue;
            }
            for &p in g.get_preds(nk.id)? {
                if !initial_loop_nodes.contains(&self.pool.key(p)) {
                    abnormal_entries.insert(self.pool.key(p));
                }
            }
        }
        let mut initial_exit_nodes: NodeSet = NodeSet::new();
        for nk in initial_loop_nodes.iter() {
            for &s in g.get_succs(nk.id)? {
                if !initial_loop_nodes.contains(&self.pool.key(s)) {
                    initial_exit_nodes.insert(self.pool.key(s));
                }
            }
        }

        let mut refined_loop_nodes = initial_loop_nodes.clone();
        let mut refined_exit_nodes = initial_exit_nodes;
        self.refine_loop(g, head, &mut refined_loop_nodes, &mut refined_exit_nodes)?;

        // (Omitted from the analysis-only port: `_ensure_jump_at_loop_exit_ends`
        // and `force_loop_single_exit` — both rewrite AIL jump statements for
        // the structurer; the structurer gets the refined body/exit split via
        // `cyclic_loops()` instead.)

        let mut normal_exit: Option<RegionNodeId> = None;
        let mut abnormal_exits: NodeSet = NodeSet::new();
        if refined_exit_nodes.len() > 1 {
            // The reference uses a (non-deterministic) dfs postorder here; the
            // port substitutes the deterministic variant — a strict
            // improvement with identical semantics.
            let mut postorder: Vec<RegionNodeId> = Vec::new();
            dfs_postorder_deterministic(&self.pool, g, head, &mut postorder)?;
            let mut po_idx: BTreeMap<RegionNodeId, i32> = BTreeMap::new();
            for (i, &n) in postorder.iter().enumerate() {
                po_idx.insert(n, i as i32);
            }
            let mut keyed: Vec<(i32, RegionNodeId)> = Vec::new();
            for ek in refined_exit_nodes.iter() {
                let pi = po_idx.get(&ek.id).copied().ok_or_else(|| {
                    anyhow!("sailr regionid: exit node not reachable from loop head")
                })?;
                keyed.push((pi, ek.id));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            normal_exit = Some(keyed[0].1);
            for k in keyed.iter().skip(1) {
                abnormal_exits.insert(self.pool.key(k.1));
            }
        } else if refined_exit_nodes.len() == 1 {
            normal_exit = Some(refined_exit_nodes.iter().next().unwrap().id);
        }

        let region = self.abstract_cyclic_region(
            g,
            &refined_loop_nodes,
            head,
            &normal_entries,
            &abnormal_entries,
            normal_exit,
            &abnormal_exits,
        )?;

        if let Some(oe) = original_entry {
            let r = &self.region_pool[region.0 as usize];
            // The region's internal graph absorbed the entry node.
            if r.graph.contains_node(oe) && r.head != Some(oe) {
                // Head node absorbed the entry; update tracked entry.
                self.has_entry_addr = true;
                self.entry_addr = head_addr;
            }
        }
        Ok(Some(region))
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _abstract_cyclic_region / kuna p7_regions abstractCyclicRegion)
    /// Build the region payload (subgraph / graph_with_successors / full
    /// graph), collapse the loop nodes out of `g` and splice in the wrapper.
    #[allow(clippy::too_many_arguments)]
    fn abstract_cyclic_region(
        &mut self,
        g: &mut RegionGraph,
        loop_nodes: &NodeSet,
        head: RegionNodeId,
        normal_entries: &NodeSet,
        abnormal_entries: &NodeSet,
        normal_exit: Option<RegionNodeId>,
        abnormal_exits: &NodeSet,
    ) -> Result<RegionId> {
        let region_id = self.new_region();
        let head_addr = self.pool.get(head).get_addr();
        let wrapper = self.new_node(NodeKind::Region, head_addr);
        self.pool.get_mut(wrapper).set_region(region_id);
        {
            let region = &mut self.region_pool[region_id.0 as usize];
            region.head = Some(head);
            region.cyclic = true;
            region.wrapper = Some(wrapper);
            region.has_full = true;
        }

        let mut subgraph = RegionGraph::new();
        let mut full_graph = RegionGraph::new();
        let mut region_outedges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        let mut delayed_edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();

        for nk in loop_nodes.iter() {
            let node = nk.id;
            subgraph.add_node(&self.pool, node);
            let mut in_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
            g.in_edges(node, &mut in_e)?;
            let mut out_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
            g.out_edges(node, &mut out_e)?;
            for (src, dst) in in_e {
                full_graph.add_edge(&self.pool, src, dst);
                if loop_nodes.contains(&self.pool.key(src)) {
                    subgraph.add_edge(&self.pool, src, dst);
                } else if normal_entries.contains(&self.pool.key(src))
                    || abnormal_entries.contains(&self.pool.key(src))
                {
                    delayed_edges.push((src, wrapper));
                } else {
                    return Err(anyhow!("sailr regionid: inconsistent cyclic region in-edge"));
                }
            }
            for (src, dst) in out_e {
                full_graph.add_edge(&self.pool, src, dst);
                if loop_nodes.contains(&self.pool.key(dst)) {
                    subgraph.add_edge(&self.pool, src, dst);
                } else if Some(dst) == normal_exit || abnormal_exits.contains(&self.pool.key(dst)) {
                    region_outedges.push((node, dst));
                    delayed_edges.push((wrapper, dst));
                } else {
                    return Err(anyhow!("sailr regionid: inconsistent cyclic region out-edge"));
                }
            }
        }

        // graph_with_successors = subgraph + region out-edges + frontier.
        let mut gws = subgraph.clone();
        for (a, b) in region_outedges.iter() {
            gws.add_edge(&self.pool, *a, *b);
        }
        let mut successors: NodeSet = NodeSet::new();
        if let Some(ne) = normal_exit {
            successors.insert(self.pool.key(ne));
        }
        for ak in abnormal_exits.iter() {
            successors.insert(*ak);
        }
        // Edges among the successors themselves.
        let succ_list: Vec<crate::sailr::graph::NodeKey> = successors.iter().copied().collect();
        for s0 in succ_list.iter() {
            for s1 in succ_list.iter() {
                if s0.id != s1.id && g.has_edge(s0.id, s1.id) {
                    gws.add_edge(&self.pool, s0.id, s1.id);
                }
            }
        }

        {
            let region = &mut self.region_pool[region_id.0 as usize];
            region.graph = subgraph;
            region.full_graph = full_graph;
            region.has_succs = true;
            region.graph_with_successors = gws;
            region.successors = successors;
        }

        // Collapse the loop nodes out of g and splice in the wrapper.
        for nk in loop_nodes.iter() {
            g.remove_node(nk.id);
        }
        g.add_node(&self.pool, wrapper);
        for (a, b) in delayed_edges {
            g.add_edge(&self.pool, a, b);
        }

        let order = self
            .order_of(head)
            .map_err(|_| anyhow!("sailr regionid: loop head missing from node order"))?;
        self.node_order.insert(wrapper, order);
        Ok(region_id)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_regions / kuna p7_regions makeRegions)
    /// Cyclic phase (iteratively find and make loop regions) followed by the
    /// acyclic phase over each cyclic region's body and the residual graph.
    fn make_regions(&mut self, g: &mut RegionGraph) -> Result<RegionId> {
        let mut structured_loop_headers: BTreeSet<RegionNodeId> = BTreeSet::new();
        let mut new_regions: Vec<RegionId> = Vec::new();

        let mut guard: i64 = 0;
        let guard_max = guard_cap(g.num_nodes());
        loop {
            // Outer: iteratively find and make loop regions.
            guard += 1;
            if guard > guard_max {
                return Err(anyhow!("sailr regionid: cyclic phase did not converge"));
            }
            let mut headers = std::mem::take(&mut self.loop_headers);
            self.find_loop_headers(g, &mut headers)?;
            self.loop_headers = headers;
            if self.loop_headers.is_empty() {
                break;
            }
            loop {
                // Inner: find all loops.
                guard += 1;
                if guard > guard_max {
                    return Err(anyhow!("sailr regionid: cyclic phase did not converge"));
                }
                let mut restart = false;
                self.start_node = Some(self.get_start_node(g)?);
                let mut headers = std::mem::take(&mut self.loop_headers);
                self.find_loop_headers(g, &mut headers)?;
                self.loop_headers = headers;
                if self.loop_headers.is_empty() {
                    break;
                }
                let snap = self.loop_headers.clone();
                for i in (0..snap.len()).rev() {
                    let node = snap[i];
                    if structured_loop_headers.contains(&node) {
                        continue;
                    }
                    if !g.contains_node(node) {
                        continue;
                    }
                    let region = self.make_cyclic_region(node, g)?;
                    match region {
                        None => {
                            // Failed (nested header): remove from the LIVE
                            // header list so later attempts no longer see it.
                            if let Some(pos) = self.loop_headers.iter().position(|&x| x == node) {
                                self.loop_headers.remove(pos);
                            }
                        }
                        Some(r) => {
                            new_regions.push(r);
                            structured_loop_headers.insert(node);
                            restart = true;
                            break;
                        }
                    }
                }
                if restart {
                    continue;
                }
                break;
            }
        }

        // Acyclic phase: process each cyclic region's body, then the residual
        // graph (the residual is represented as region==None and routed at g).
        for widx in 0..=new_regions.len() {
            let is_top = widx == new_regions.len();
            let region_id: Option<RegionId> = if is_top { None } else { Some(new_regions[widx]) };

            let mut sub: RegionGraph = if is_top {
                std::mem::take(g)
            } else {
                std::mem::take(&mut self.region_pool[region_id.unwrap().0 as usize].graph)
            };
            let mut secondary: Option<RegionGraph> = if !is_top {
                let r = &self.region_pool[region_id.unwrap().0 as usize];
                if r.has_succs {
                    Some(r.graph_with_successors.clone())
                } else {
                    None
                }
            } else {
                None
            };
            let cyc = if is_top {
                false
            } else {
                self.region_pool[region_id.unwrap().0 as usize].cyclic
            };
            let mut head: RegionNodeId = if is_top {
                self.get_start_node(&sub)?
            } else {
                self.region_pool[region_id.unwrap().0 as usize]
                    .head
                    .ok_or_else(|| anyhow!("sailr regionid: region has no head"))?
            };

            let mut failed_region_attempts: BTreeSet<(RegionNodeId, RegionNodeId)> = BTreeSet::new();
            let mut inner_guard: i64 = 0;
            loop {
                let made = self.make_acyclic_region(
                    head,
                    &mut sub,
                    secondary.as_mut(),
                    &mut failed_region_attempts,
                    cyc,
                )?;
                if !made {
                    break;
                }
                inner_guard += 1;
                if inner_guard > guard_max {
                    return Err(anyhow!("sailr regionid: acyclic phase did not converge"));
                }
                if !sub.contains_node(head) {
                    let addr = self.pool.get(head).get_addr();
                    head = self.node_by_addr(&sub, addr)?;
                }
            }
            let addr = self.pool.get(head).get_addr();
            head = self.node_by_addr(&sub, addr)?;

            // Write the (possibly collapsed) graph + secondary back.
            if is_top {
                *g = sub;
            } else {
                let rid = region_id.unwrap();
                self.region_pool[rid.0 as usize].graph = sub;
                if let Some(sec) = secondary {
                    self.region_pool[rid.0 as usize].graph_with_successors = sec;
                }
                self.region_pool[rid.0 as usize].head = Some(head);
            }
        }

        if g.num_nodes() == 1 {
            let res = g.node_keys().next().unwrap().id;
            if let Some(r) = self.pool.get(res).get_region() {
                return Ok(r);
            }
        }
        let new_head = self.get_start_node(g)?;
        let top = self.new_region();
        {
            let region = &mut self.region_pool[top.0 as usize];
            region.head = Some(new_head);
            region.graph = g.clone();
            region.has_succs = false;
            region.cyclic = false;
        }
        Ok(top)
    }

    //
    // Acyclic phase
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _check_region / kuna p7_regions checkRegion)
    /// Pure predicate over dominance frontiers: is `start_node..end_node` a
    /// proper single-entry region (no edge enters or leaves the middle)?
    fn check_region(
        &self,
        g: &RegionGraph,
        start_node: RegionNodeId,
        end_node: RegionNodeId,
        doms: &mut IncrementalDominators,
    ) -> Result<bool> {
        if !doms.dominates(start_node, end_node) {
            let early_start_frontier = doms.df(&self.pool, g, start_node)?;
            for it in early_start_frontier.iter() {
                if it.id != start_node && it.id != end_node {
                    return Ok(false);
                }
            }
        }

        let end_frontier = doms.df(&self.pool, g, end_node)?;
        for it in end_frontier.iter() {
            if doms.dominates(start_node, it.id) && it.id != end_node {
                return Ok(false); // An edge enters the region
            }
        }

        let start_frontier = doms.df(&self.pool, g, start_node)?;
        for it in start_frontier.iter() {
            let node = it.id;
            if node == start_node || node == end_node {
                continue;
            }
            if !end_frontier.contains(it) {
                return Ok(false); // An edge leaves the region
            }
            for &p in g.get_preds(node)? {
                if doms.dominates(start_node, p) && !doms.dominates(end_node, p) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _compute_region / kuna p7_regions computeRegion)
    /// Slice the region: DFS from `node` stopping at the frontier; build the
    /// subgraph and its with-successors extension.  Returns a region id only
    /// when the subgraph has more than one node.
    fn compute_region(
        &mut self,
        g: &RegionGraph,
        node: RegionNodeId,
        frontier: &NodeSet,
        dummy_endnode: Option<RegionNodeId>,
        cyclic_ancestor: bool,
    ) -> Result<Option<RegionId>> {
        let mut subgraph = RegionGraph::new();
        let mut frontier_edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        let mut stack: Vec<RegionNodeId> = vec![node];
        let mut traversed: BTreeSet<RegionNodeId> = BTreeSet::new();

        while let Some(cur) = stack.pop() {
            // LIFO, like Python list.pop().
            if frontier.contains(&self.pool.key(cur)) {
                continue;
            }
            if traversed.contains(&cur) {
                continue;
            }
            traversed.insert(cur);
            subgraph.add_node(&self.pool, cur);
            for &succ in g.get_succs(cur)? {
                if Some(succ) == dummy_endnode {
                    continue;
                }
                if frontier.contains(&self.pool.key(succ)) {
                    frontier_edges.push((cur, succ));
                    continue;
                }
                subgraph.add_edge(&self.pool, cur, succ);
                if traversed.contains(&succ) {
                    continue;
                }
                stack.push(succ);
            }
        }

        let mut real_frontier: NodeSet = NodeSet::new();
        for fk in frontier.iter() {
            if Some(fk.id) != dummy_endnode {
                real_frontier.insert(*fk);
            }
        }

        if subgraph.num_nodes() > 1 {
            let region_id = self.new_region();
            let mut gws = subgraph.clone();
            for (a, b) in frontier_edges {
                if Some(b) != dummy_endnode {
                    gws.add_edge(&self.pool, a, b);
                }
            }
            let region = &mut self.region_pool[region_id.0 as usize];
            region.head = Some(node);
            region.graph = subgraph;
            region.has_succs = true;
            region.successors = real_frontier;
            region.graph_with_successors = gws;
            region.cyclic = false;
            region.cyclic_ancestor = cyclic_ancestor;
            return Ok(Some(region_id));
        }
        Ok(None)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _region_in_edges / kuna p7_regions regionInEdges)
    /// In-edges of a region: the in-edges of its head (if still in `g`).
    fn region_in_edges(
        &self,
        g: &RegionGraph,
        region_id: RegionId,
        res: &mut Vec<(RegionNodeId, RegionNodeId)>,
    ) -> Result<()> {
        let head = self.region_pool[region_id.0 as usize]
            .head
            .ok_or_else(|| anyhow!("sailr regionid: region has no head"))?;
        if g.contains_node(head) {
            g.in_edges(head, res)?;
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _region_out_edges / kuna p7_regions regionOutEdges)
    /// Member->outside edges re-sourced at the region's wrapper node.
    fn region_out_edges(
        &self,
        g: &RegionGraph,
        region_id: RegionId,
        res: &mut Vec<(RegionNodeId, RegionNodeId)>,
    ) -> Result<()> {
        let wrapper = self.region_pool[region_id.0 as usize]
            .wrapper
            .ok_or_else(|| anyhow!("sailr regionid: region has no wrapper"))?;
        let member_keys: Vec<crate::sailr::graph::NodeKey> = self.region_pool[region_id.0 as usize]
            .graph
            .node_keys()
            .copied()
            .collect();
        for mk in member_keys {
            let member = mk.id;
            if !g.contains_node(member) {
                continue;
            }
            let succs: Vec<RegionNodeId> = g.get_succs(member)?.to_vec();
            for s in succs {
                if self.region_pool[region_id.0 as usize].graph.contains_node(s) {
                    continue;
                }
                res.push((wrapper, s));
            }
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _abstract_acyclic_region / kuna p7_regions abstractAcyclicRegion)
    /// Replace a region's member nodes in `g` (and the secondary graph) with
    /// its wrapper, re-pointing in/out edges and frontier edges.
    fn abstract_acyclic_region(
        &mut self,
        g: &mut RegionGraph,
        region_id: RegionId,
        frontier: &NodeSet,
        dummy_endnode: Option<RegionNodeId>,
        secondary_graph: Option<&mut RegionGraph>,
    ) -> Result<()> {
        if self.region_pool[region_id.0 as usize].wrapper.is_none() {
            let head = self.region_pool[region_id.0 as usize]
                .head
                .ok_or_else(|| anyhow!("sailr regionid: region has no head"))?;
            let addr = self.pool.get(head).get_addr();
            let w = self.new_node(NodeKind::Region, addr);
            self.pool.get_mut(w).set_region(region_id);
            self.region_pool[region_id.0 as usize].wrapper = Some(w);
        }
        let wrapper = self.region_pool[region_id.0 as usize].wrapper.unwrap();

        let mut in_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        self.region_in_edges(g, region_id, &mut in_e)?;
        let mut out_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        self.region_out_edges(g, region_id, &mut out_e)?;

        let mut nodes_set: NodeSet = NodeSet::new();
        {
            let members: Vec<RegionNodeId> = {
                let mut v = Vec::new();
                self.region_pool[region_id.0 as usize].graph.get_nodes(&mut v);
                v
            };
            for m in members {
                nodes_set.insert(self.pool.key(m));
                if Some(m) != dummy_endnode {
                    g.remove_node(m);
                }
            }
        }
        g.add_node(&self.pool, wrapper);

        // node_order[wrapper] = min over members (lexicographic pair).
        let mut first = true;
        let mut mn: (i32, i32) = (0, 0);
        for nk in nodes_set.iter() {
            let o = self
                .order_of(nk.id)
                .map_err(|_| anyhow!("sailr regionid: region member missing from node order"))?;
            if first || o < mn {
                mn = o;
                first = false;
            }
        }
        self.node_order.insert(wrapper, mn);

        for (src, _dst) in in_e {
            if !nodes_set.contains(&self.pool.key(src)) {
                g.add_edge(&self.pool, src, wrapper);
            }
        }
        for (_src, dst) in out_e {
            if !nodes_set.contains(&self.pool.key(dst)) {
                g.add_edge(&self.pool, wrapper, dst);
            }
        }
        for fk in frontier.iter() {
            if Some(fk.id) != dummy_endnode {
                g.add_edge(&self.pool, wrapper, fk.id);
            }
        }

        if let Some(sec) = secondary_graph {
            let empty_frontier = NodeSet::new();
            self.abstract_acyclic_region(sec, region_id, &empty_frontier, None, None)?;
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _update_graph / kuna p7_regions replaceRegionInGraph)
    /// Replace the region's nodes in the scratch dominator graph (no frontier
    /// edges) with the wrapper.
    fn replace_region_in_graph(
        &mut self,
        g: &mut RegionGraph,
        region_id: RegionId,
        replaced_nodes: &NodeSet,
    ) -> Result<()> {
        let wrapper = self.region_pool[region_id.0 as usize]
            .wrapper
            .ok_or_else(|| anyhow!("sailr regionid: region has no wrapper"))?;
        let mut in_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        self.region_in_edges(g, region_id, &mut in_e)?;
        let mut out_e: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        self.region_out_edges(g, region_id, &mut out_e)?;
        for rk in replaced_nodes.iter() {
            g.remove_node(rk.id);
        }
        g.add_node(&self.pool, wrapper);
        for (a, _b) in in_e {
            g.add_edge(&self.pool, a, wrapper);
        }
        for (_a, b) in out_e {
            g.add_edge(&self.pool, wrapper, b);
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_acyclic_region / kuna p7_regions makeAcyclicRegion)
    ///
    /// One round of acyclic region formation over `graph` from `head`:
    /// postdom-climbing over the deterministic postorder, checking candidate
    /// (node, postdom) frontiers, collapsing hits, and patching the
    /// incremental dominators.
    fn make_acyclic_region(
        &mut self,
        head: RegionNodeId,
        graph: &mut RegionGraph,
        mut secondary_graph: Option<&mut RegionGraph>,
        failed_region_attempts: &mut BTreeSet<(RegionNodeId, RegionNodeId)>,
        cyclic: bool,
    ) -> Result<bool> {
        let mut head_inedges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        graph.in_edges(head, &mut head_inedges)?;

        // If no head in-edges, the scratch graph IS graph; otherwise it is a
        // private copy with head in-edges cut.
        let mut local_copy: Option<RegionGraph> = None;
        if !head_inedges.is_empty() {
            let mut lc = graph.clone();
            for (a, b) in head_inedges.iter() {
                lc.remove_edge(*a, *b);
            }
            local_copy = Some(lc);
        }

        // Compute endnodes against gc.
        let mut endnodes: Vec<RegionNodeId> = Vec::new();
        {
            let gc: &RegionGraph = local_copy.as_ref().unwrap_or(graph);
            for key in gc.node_keys() {
                if gc.get_succs(key.id)?.is_empty() {
                    endnodes.push(key.id);
                }
            }
        }
        if endnodes.is_empty() {
            return Ok(false);
        }

        let mut add_dummy = false;
        if endnodes.len() > 1 {
            add_dummy = true;
        } else if !head_inedges.is_empty() {
            // Lone end node that is NOT a predecessor of head (in the ORIGINAL
            // graph) still needs the dummy.
            let is_pred = graph.get_preds(head)?.iter().any(|&p| p == endnodes[0]);
            if !is_pred {
                add_dummy = true;
            }
        }

        let mut gc_owned: RegionGraph = match local_copy {
            Some(lc) => lc,
            None => graph.clone(),
        };

        let mut dummy: Option<RegionNodeId> = None;
        if add_dummy {
            let d = self.new_node(NodeKind::Dummy, !0u64);
            for &en in endnodes.iter() {
                gc_owned.add_edge(&self.pool, en, d);
            }
            endnodes.clear();
            endnodes.push(d);
            dummy = Some(d);
        }

        let mut doms = IncrementalDominators::new(&self.pool, &gc_owned, head, false)?;
        let mut postdoms = IncrementalDominators::new(&self.pool, &gc_owned, endnodes[0], true)?;

        let mut region_created = false;
        let mut postorder_snap: Vec<RegionNodeId> = Vec::new();
        dfs_postorder_deterministic(&self.pool, &gc_owned, head, &mut postorder_snap)?;
        let gc_differs = !head_inedges.is_empty() || add_dummy;

        for &node in postorder_snap.iter() {
            if Some(node) == dummy {
                continue;
            }
            if cyclic && node == head {
                continue;
            }
            if !gc_owned.contains_node(node) {
                continue;
            }

            let out_degree = gc_owned.size_out(node)?;
            if out_degree == 0 {
                // The root of the region hierarchy should always be a region;
                // wrap a lone, isolated non-region leaf.
                if gc_owned.size_in(node)? == 0 && !self.pool.get(node).is_region() {
                    let r = self.new_region();
                    {
                        let region = &mut self.region_pool[r.0 as usize];
                        region.head = Some(node);
                        region.graph.add_node(&self.pool, node);
                        region.has_succs = false;
                        region.cyclic = false;
                        region.cyclic_ancestor = cyclic;
                    }
                    let empty_frontier = NodeSet::new();
                    self.abstract_acyclic_region(
                        graph,
                        r,
                        &empty_frontier,
                        None,
                        secondary_graph.as_deref_mut(),
                    )?;
                }
                continue;
            }

            let mut postdom_node = postdoms.idom(node);
            while let Some(pdn) = postdom_node {
                let attempt = (node, pdn);
                if !failed_region_attempts.contains(&attempt)
                    && self.check_region(&gc_owned, node, pdn, &mut doms)?
                {
                    let mut frontier: NodeSet = NodeSet::new();
                    frontier.insert(self.pool.key(pdn));
                    let region =
                        self.compute_region(&gc_owned, node, &frontier, dummy, cyclic)?;
                    if let Some(region_id) = region {
                        // Backpatch graph_with_successors from the parent's
                        // secondary graph.
                        if let Some(sec) = secondary_graph.as_deref() {
                            self.backpatch_secondary(region_id, sec, &gc_owned)?;
                        }

                        self.abstract_acyclic_region(
                            graph,
                            region_id,
                            &frontier,
                            dummy,
                            secondary_graph.as_deref_mut(),
                        )?;
                        region_created = true;
                        let mut replaced_nodes: NodeSet = NodeSet::new();
                        {
                            let mut members = Vec::new();
                            self.region_pool[region_id.0 as usize]
                                .graph
                                .get_nodes(&mut members);
                            for m in members {
                                replaced_nodes.insert(self.pool.key(m));
                            }
                        }
                        if gc_differs {
                            self.replace_region_in_graph(
                                &mut gc_owned,
                                region_id,
                                &replaced_nodes,
                            )?;
                        } else {
                            gc_owned = graph.clone();
                        }
                        let wrapper = self.region_pool[region_id.0 as usize].wrapper.unwrap();
                        let rhead = self.region_pool[region_id.0 as usize].head.unwrap();
                        doms.graph_updated(&self.pool, wrapper, &replaced_nodes, rhead)?;
                        postdoms.graph_updated(&self.pool, wrapper, &replaced_nodes, rhead)?;
                        break; // continue the post-order traversal
                    }
                }

                failed_region_attempts.insert(attempt);
                if !doms.dominates(node, pdn) {
                    break;
                }
                if postdoms.idom(pdn) == Some(pdn) {
                    break;
                }
                postdom_node = postdoms.idom(pdn);
            }
        }
        Ok(region_created)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py l.809-833 graph_with_successors backpatch / kuna p7_regions backpatchSecondary)
    /// Backpatch a child region's `graph_with_successors` from the parent's
    /// secondary graph.
    fn backpatch_secondary(
        &mut self,
        region_id: RegionId,
        secondary_graph: &RegionGraph,
        gc: &RegionGraph,
    ) -> Result<()> {
        let snap: Vec<RegionNodeId> = {
            let mut v = Vec::new();
            self.region_pool[region_id.0 as usize]
                .graph_with_successors
                .get_nodes(&mut v);
            v
        };
        for nn in snap {
            if !secondary_graph.contains_node(nn) {
                continue;
            }
            let osuccs: Vec<RegionNodeId> = secondary_graph.get_succs(nn)?.to_vec();
            for succ in osuccs {
                if self.complete_successors {
                    if !self.region_pool[region_id.0 as usize]
                        .graph_with_successors
                        .has_edge(nn, succ)
                    {
                        self.region_pool[region_id.0 as usize]
                            .graph_with_successors
                            .add_edge(&self.pool, nn, succ);
                        self.region_pool[region_id.0 as usize]
                            .successors
                            .insert(self.pool.key(succ));
                    }
                } else if !gc.contains_node(succ) {
                    self.region_pool[region_id.0 as usize]
                        .graph_with_successors
                        .add_edge(&self.pool, nn, succ);
                    self.region_pool[region_id.0 as usize]
                        .successors
                        .insert(self.pool.key(succ));
                }
            }
        }
        // Add edges between successors.
        let succ_list: Vec<crate::sailr::graph::NodeKey> = self.region_pool[region_id.0 as usize]
            .successors
            .iter()
            .copied()
            .collect();
        for s0 in succ_list.iter() {
            for s1 in succ_list.iter() {
                if s0.id != s1.id && secondary_graph.has_edge(s0.id, s1.id) {
                    self.region_pool[region_id.0 as usize]
                        .graph_with_successors
                        .add_edge(&self.pool, s0.id, s1.id);
                }
            }
        }
        Ok(())
    }

    //
    // Outputs
    //

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _make_regions_by_block_addrs / kuna p7_regions buildRegionsByBlockAddrs)
    /// Flat per-region block-address lists, breadth-first over the region tree.
    fn build_regions_by_block_addrs(&mut self) {
        self.regions_by_block_addrs.clear();
        let top = match self.top_region {
            Some(t) => t,
            None => return,
        };
        let mut work_list: Vec<RegionId> = vec![top];
        let mut seen_regions: BTreeSet<RegionId> = BTreeSet::new();
        while !work_list.is_empty() {
            let mut children_regions: Vec<RegionId> = Vec::new();
            for &region_id in work_list.iter() {
                let mut children_blocks: Vec<u64> = Vec::new();
                let member_keys: Vec<crate::sailr::graph::NodeKey> = self.region_pool
                    [region_id.0 as usize]
                    .graph
                    .node_keys()
                    .copied()
                    .collect();
                for mk in member_keys {
                    let node = self.pool.get(mk.id);
                    if node.get_kind() == NodeKind::Block {
                        children_blocks.push(node.get_addr());
                    } else if node.is_multi() {
                        for &m in node.get_chain() {
                            children_blocks.push(self.pool.get(m).get_addr());
                        }
                    } else if node.is_region() {
                        if let Some(sub) = node.get_region() {
                            if !seen_regions.contains(&sub) {
                                children_regions.push(sub);
                                let sub_head = self.region_pool[sub.0 as usize].head.unwrap();
                                children_blocks.push(self.pool.get(sub_head).get_addr());
                                seen_regions.insert(sub);
                            }
                        }
                    }
                    // Dummy: skip (never appears in region graphs).
                }
                if !children_blocks.is_empty() {
                    self.regions_by_block_addrs.push(children_blocks);
                }
            }
            work_list = children_regions;
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions walkRegionBlocks)
    /// Walk one region: `enter_region`, leaves (chains expand), nested regions,
    /// `exit_region`.
    pub fn walk_region_blocks<V: RegionVisitor>(
        &self,
        region_id: RegionId,
        visitor: &mut V,
    ) {
        let region = &self.region_pool[region_id.0 as usize];
        visitor.enter_region(region);
        let member_keys: Vec<crate::sailr::graph::NodeKey> =
            region.graph.node_keys().copied().collect();
        for mk in member_keys {
            let node = self.pool.get(mk.id);
            if node.is_region() {
                if let Some(sub) = node.get_region() {
                    self.walk_region_blocks(sub, visitor);
                }
            } else if node.is_multi() {
                let chain: Vec<RegionNodeId> = node.get_chain().to_vec();
                for m in chain {
                    let mn = self.pool.get(m);
                    visitor.visit_block(mn.get_block(), mn.get_addr());
                }
            } else if node.get_kind() == NodeKind::Block {
                visitor.visit_block(node.get_block(), node.get_addr());
            }
        }
        let region = &self.region_pool[region_id.0 as usize];
        visitor.exit_region(region);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions walkBlocks)
    /// Walk the whole tree.
    pub fn walk_blocks<V: RegionVisitor>(&self, visitor: &mut V) -> Result<()> {
        let top = self
            .top_region
            .ok_or_else(|| anyhow!("sailr regionid: compute() has not run"))?;
        self.walk_region_blocks(top, visitor);
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions nodeAddr)
    /// Read a node's address (console/diagnostic surface).
    pub fn node_addr(&self, id: RegionNodeId) -> u64 {
        self.pool.get(id).get_addr()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions collectLeafAddrs)
    /// Collect every leaf-block start address reachable under `node`,
    /// recursing through multi chains and region wrappers.
    fn collect_leaf_addrs(&self, node: RegionNodeId, out: &mut BTreeSet<u64>) {
        let n = self.pool.get(node);
        match n.get_kind() {
            NodeKind::Block => {
                out.insert(n.get_addr());
            }
            NodeKind::Multi => {
                for &m in n.get_chain() {
                    out.insert(self.pool.get(m).get_addr());
                }
            }
            NodeKind::Region => {
                if let Some(sub) = n.get_region() {
                    let member_ids: Vec<RegionNodeId> = {
                        let mut v = Vec::new();
                        self.region_pool[sub.0 as usize].graph.get_nodes(&mut v);
                        v
                    };
                    for m in member_ids {
                        self.collect_leaf_addrs(m, out);
                    }
                }
            }
            NodeKind::Dummy => {}
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py refined loop body + GraphRegion.successors / kuna p7_regions cyclicLoops)
    ///
    /// Expose the identified **cyclic** (loop) regions for the structurer:
    /// for each cyclic region, the loop head's start address, every
    /// basic-block start address in its loop body, and every exit (successor)
    /// block start address.  Only available after `compute` has run.
    pub fn cyclic_loops(&self) -> Vec<CyclicLoop> {
        let mut res = Vec::new();
        for region in self.region_pool.iter() {
            if !region.cyclic {
                continue;
            }
            let head_addr = match region.head {
                Some(h) => self.pool.get(h).get_addr(),
                None => continue,
            };
            let mut body: BTreeSet<u64> = BTreeSet::new();
            let body_members: Vec<RegionNodeId> = {
                let mut v = Vec::new();
                region.graph.get_nodes(&mut v);
                v
            };
            for m in body_members {
                self.collect_leaf_addrs(m, &mut body);
            }
            let mut exits: BTreeSet<u64> = BTreeSet::new();
            for sk in region.successors.iter() {
                exits.insert(self.pool.get(sk.id).get_addr());
            }
            res.push(CyclicLoop { head_addr, body, exits });
        }
        res
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions renderTreeWith)
    /// Render the nested region tree deterministically (diagnostic surface):
    /// one `region head=0x.. nodes=N [cyclic]` line per region, `block 0x..`
    /// per leaf block, 2-space indent per depth.
    pub fn render_tree(&self) -> String {
        let mut os = String::new();
        if let Some(top) = self.top_region {
            self.render_region(top, 0, &mut os);
        }
        os
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions renderRegion)
    /// Recursive helper for [`RegionIdentifier::render_tree`].
    fn render_region(&self, region_id: RegionId, depth: usize, os: &mut String) {
        let region = &self.region_pool[region_id.0 as usize];
        for _ in 0..depth {
            os.push_str("  ");
        }
        os.push_str("region head=0x");
        let head_addr = region
            .get_head()
            .map(|h| self.pool.get(h).get_addr())
            .unwrap_or(0);
        os.push_str(&format!("{head_addr:x}"));
        os.push_str(" nodes=");
        os.push_str(&region.graph.num_nodes().to_string());
        if region.is_cyclic() {
            os.push_str(" cyclic");
        }
        os.push('\n');
        let member_keys: Vec<crate::sailr::graph::NodeKey> =
            region.graph.node_keys().copied().collect();
        for mk in member_keys {
            let node = self.pool.get(mk.id);
            if node.is_region() {
                if let Some(sub) = node.get_region() {
                    self.render_region(sub, depth + 1, os);
                }
            } else if node.is_multi() {
                let chain: Vec<RegionNodeId> = node.get_chain().to_vec();
                for m in chain {
                    for _ in 0..depth + 1 {
                        os.push_str("  ");
                    }
                    os.push_str("block 0x");
                    os.push_str(&format!("{:x}", self.pool.get(m).get_addr()));
                    os.push('\n');
                }
            } else if node.get_kind() == NodeKind::Block {
                for _ in 0..depth + 1 {
                    os.push_str("  ");
                }
                os.push_str("block 0x");
                os.push_str(&format!("{:x}", node.get_addr()));
                os.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test visitor: collects every leaf block address (in walk order) and,
    /// for each cyclic region, the head address plus the addresses visited
    /// inside it (depth-tracked bucketing into the innermost cyclic region).
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions tests KunaTestCollector)
    #[derive(Default)]
    struct Collector {
        addrs: Vec<u64>,
        /// (head addr, sorted body block addrs) for every cyclic region.
        cyclics: Vec<(u64, Vec<u64>)>,
        /// Stack of (is_cyclic, head addr, body accumulator) for open regions.
        stack: Vec<(bool, u64, Vec<u64>)>,
    }

    impl RegionVisitor for Collector {
        fn enter_region(&mut self, region: &GraphRegion) {
            let cyclic = region.is_cyclic();
            self.stack.push((cyclic, u64::MAX, Vec::new()));
        }
        fn exit_region(&mut self, _region: &GraphRegion) {
            if let Some((cyclic, head, body)) = self.stack.pop() {
                if cyclic {
                    let mut sorted = body.clone();
                    sorted.sort_unstable();
                    self.cyclics.push((head, sorted));
                }
            }
        }
        fn visit_block(&mut self, _block: Option<usize>, addr: u64) {
            self.addrs.push(addr);
            for frame in self.stack.iter_mut() {
                if frame.1 == u64::MAX {
                    frame.1 = addr; // first block seen = region head (walk order)
                }
                if frame.0 {
                    frame.2.push(addr);
                }
            }
        }
    }

    fn sorted(v: &[u64]) -> Vec<u64> {
        let mut r = v.to_vec();
        r.sort_unstable();
        r
    }

    /// a diamond `1 -> 2 -> {3,4} -> 5 -> 6` (angr
    /// `test_region_identifier_0` shape).
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr test_region_identifier_0 / kuna regionid_diamond0)
    #[test]
    fn regionid_diamond0() {
        let mut ri = RegionIdentifier::new();
        let n1 = ri.add_synthetic_block(1);
        let n2 = ri.add_synthetic_block(2);
        let n3 = ri.add_synthetic_block(3);
        let n4 = ri.add_synthetic_block(4);
        let n5 = ri.add_synthetic_block(5);
        let n6 = ri.add_synthetic_block(6);
        ri.add_synthetic_edge(n1, n2);
        ri.add_synthetic_edge(n2, n3);
        ri.add_synthetic_edge(n2, n4);
        ri.add_synthetic_edge(n3, n5);
        ri.add_synthetic_edge(n4, n5);
        ri.add_synthetic_edge(n5, n6);

        let top = ri.compute().unwrap();
        let region = ri.region(top);
        // The angr assertion: the top-level region graph has exactly two
        // nodes.
        assert_eq!(region.get_graph().num_nodes(), 2);
        let head = region.get_head().unwrap();
        assert_eq!(ri.node_addr(head), 1);
        assert!(!region.is_cyclic());

        // Exactly one of the two top-level nodes is a sub-region.
        let mut region_count = 0;
        for key in region.get_graph().node_keys() {
            if ri.pool.get(key.id).is_region() {
                region_count += 1;
            }
        }
        assert_eq!(region_count, 1);

        // The recursive walker covers every input block exactly once.
        let mut col = Collector::default();
        ri.walk_blocks(&mut col).unwrap();
        assert_eq!(col.addrs.len(), 6);
        let got = sorted(&col.addrs);
        for i in 0..6 {
            assert_eq!(got[i], (i + 1) as u64);
        }
        assert_eq!(col.cyclics.len(), 0);
    }

    /// Two stacked half-diamonds (angr `test_region_identifier_1` shape).
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr test_region_identifier_1 / kuna regionid_diamond1)
    #[test]
    fn regionid_diamond1() {
        let mut ri = RegionIdentifier::new();
        let mut nodes = [RegionNodeId(0); 9];
        for (i, slot) in nodes.iter_mut().enumerate().take(9).skip(1) {
            *slot = ri.add_synthetic_block(i as u64);
        }
        ri.add_synthetic_edge(nodes[1], nodes[2]);
        ri.add_synthetic_edge(nodes[2], nodes[3]);
        ri.add_synthetic_edge(nodes[3], nodes[4]);
        ri.add_synthetic_edge(nodes[2], nodes[4]);
        ri.add_synthetic_edge(nodes[4], nodes[5]);
        ri.add_synthetic_edge(nodes[5], nodes[6]);
        ri.add_synthetic_edge(nodes[6], nodes[7]);
        ri.add_synthetic_edge(nodes[5], nodes[7]);
        ri.add_synthetic_edge(nodes[7], nodes[8]);

        let top = ri.compute().unwrap();
        assert_eq!(ri.region(top).get_graph().num_nodes(), 2);

        let mut col = Collector::default();
        ri.walk_blocks(&mut col).unwrap();
        assert_eq!(col.addrs.len(), 8);
        let got = sorted(&col.addrs);
        for i in 0..8 {
            assert_eq!(got[i], (i + 1) as u64);
        }
    }

    /// `1 -> 2 -> 3 -> 4` with a back edge `3 -> 2` (loop body `{2,3}`).
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna regionid_loop)
    #[test]
    fn regionid_loop() {
        let mut ri = RegionIdentifier::new();
        let n1 = ri.add_synthetic_block(1);
        let n2 = ri.add_synthetic_block(2);
        let n3 = ri.add_synthetic_block(3);
        let n4 = ri.add_synthetic_block(4);
        ri.add_synthetic_edge(n1, n2);
        ri.add_synthetic_edge(n2, n3);
        ri.add_synthetic_edge(n3, n2);
        ri.add_synthetic_edge(n3, n4);

        let top = ri.compute().unwrap();
        assert!(!ri.region(top).is_cyclic());

        // Exactly one cyclic region, headed at address 2, containing {2,3}.
        let mut col = Collector::default();
        ri.walk_blocks(&mut col).unwrap();
        assert_eq!(col.cyclics.len(), 1);
        let (loop_head, loop_addrs) = &col.cyclics[0];
        assert_eq!(*loop_head, 2);
        assert_eq!(loop_addrs.len(), 2);
        assert_eq!(loop_addrs[0], 2);
        assert_eq!(loop_addrs[1], 3);

        // regions_by_block_addrs contains the loop body {2,3} as its own
        // region.
        let rbba = ri.get_regions_by_block_addrs();
        let found = rbba
            .iter()
            .any(|r| {
                let s = sorted(r);
                s.len() == 2 && s[0] == 2 && s[1] == 3
            });
        assert!(found);

        // Whole-tree walk covers every block exactly once.
        assert_eq!(col.addrs.len(), 4);
        let got = sorted(&col.addrs);
        for i in 0..4 {
            assert_eq!(got[i], (i + 1) as u64);
        }
    }

    /// The cyclic_loops projection: loop head/body/exits projected onto
    /// block addresses for the structurer.
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna cyclicLoops projection)
    #[test]
    fn regionid_cyclic_loops_projection() {
        let mut ri = RegionIdentifier::new();
        let n1 = ri.add_synthetic_block(1);
        let n2 = ri.add_synthetic_block(2);
        let n3 = ri.add_synthetic_block(3);
        let n4 = ri.add_synthetic_block(4);
        ri.add_synthetic_edge(n1, n2);
        ri.add_synthetic_edge(n2, n3);
        ri.add_synthetic_edge(n3, n2);
        ri.add_synthetic_edge(n3, n4);
        let _ = ri.compute().unwrap();

        let loops = ri.cyclic_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].head_addr, 2);
        assert_eq!(loops[0].body, [2u64, 3].into_iter().collect());
        assert_eq!(loops[0].exits, [4u64].into_iter().collect());
    }

    /// The build_from_cfg seam (the Phase 2 adapter input): a diamond built
    /// over the generic CFG projection behaves identically to the synthetic
    /// input, and the `branchy` predicate parks on the node.
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna build_from_block_graph tests)
    #[test]
    fn regionid_build_from_cfg_diamond() {
        let blocks: Vec<(u64, usize, bool)> =
            vec![(0x1000, 0, true), (0x1100, 1, false), (0x1200, 2, false), (0x1300, 3, false)];
        let edges: Vec<(usize, usize)> =
            vec![(0, 1), (0, 2), (1, 3), (2, 3)];
        let mut ri = RegionIdentifier::new();
        ri.build_from_cfg(&blocks, &edges, 0x1000).unwrap();
        let top = ri.compute().unwrap();

        let region = ri.region(top);
        assert_eq!(region.get_graph().num_nodes(), 2);
        let head = region.get_head().unwrap();
        assert_eq!(ri.node_addr(head), 0x1000);
        assert!(!region.is_cyclic());

        let mut col = Collector::default();
        ri.walk_blocks(&mut col).unwrap();
        assert_eq!(col.addrs.len(), 4);
        assert_eq!(sorted(&col.addrs), vec![0x1000, 0x1100, 0x1200, 0x1300]);
    }

    /// build_from_cfg rejects a non-empty working graph and an empty block
    /// list, and reports out-of-range edges.
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna build_from_block_graph_rejects_non_empty)
    #[test]
    fn regionid_build_from_cfg_validation() {
        let mut ri = RegionIdentifier::new();
        ri.add_synthetic_block(0x10);
        let blocks: Vec<(u64, usize, bool)> = vec![(0x1000, 0, false)];
        assert!(ri.build_from_cfg(&blocks, &[], 0x1000).is_err());

        let mut ri2 = RegionIdentifier::new();
        assert!(ri2.build_from_cfg(&[], &[], 0x1000).is_err());

        let mut ri3 = RegionIdentifier::new();
        assert!(ri3.build_from_cfg(&blocks, &[(0, 7)], 0x1000).is_err());
    }

    /// A multi-exit loop: the refinement absorbs dominated single-out exits
    /// into the body and keeps the structural exit frontier.
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr _refine_loop stage 1-2)
    #[test]
    fn regionid_multi_exit_loop() {
        // 1 -> 2; 2 -> 3 (true); 2 -> 6 (false, exit); 3 -> 4 (true);
        // 3 -> 2 (false, back edge); 4 -> 5; 5 -> 2 (back edge); 6 end.
        // Loop {2,3,4,5} with exits {6}.
        let mut ri = RegionIdentifier::new();
        for a in 1..=6 {
            ri.add_synthetic_block(a);
        }
        let n = |a: u64| RegionNodeId((a - 1) as u32);
        ri.add_synthetic_edge(n(1), n(2));
        ri.add_synthetic_edge(n(2), n(3));
        ri.add_synthetic_edge(n(2), n(6));
        ri.add_synthetic_edge(n(3), n(4));
        ri.add_synthetic_edge(n(3), n(2));
        ri.add_synthetic_edge(n(4), n(5));
        ri.add_synthetic_edge(n(5), n(2));
        let _ = ri.compute().unwrap();

        let loops = ri.cyclic_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].head_addr, 2);
        assert!(loops[0].body.contains(&3));
        assert!(loops[0].body.contains(&4));
        assert!(loops[0].body.contains(&5));
        assert!(!loops[0].body.contains(&6));
        assert!(loops[0].exits.contains(&6));
    }
}
