//! SAILR enhancement layer — graph substrate for the RegionIdentifier port.
//!
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr/analyses/decompiler/region_identifier.py graph utilities / kuna p7_regions kuna_regiongraph.rs)
//!
//! This module is **not** part of upstream Ghidra and is **not** wired into the
//! default (faithful blockaction) structuring path.  It provides the mutable,
//! deterministic digraph machinery that [`crate::sailr::region_id`] (the port of
//! angr's `RegionIdentifier`) collapses while identifying single-entry regions.
//! The decompiler's own `BlockGraph` cannot serve: region identification
//! destructively merges and replaces nodes, and the basic-block graph must never
//! be mutated by this analysis-only pass.
//!
//! # Determinism model
//!
//! angr's Python relies on dict insertion order in several places; the port
//! replaces that with a single global strict weak order over nodes — the
//! `(addr, ident)` lexicographic key ([`NodeKey`]) — and every iterated
//! container (map/set/sort) is keyed on it, so iteration order is stable and
//! matches angr's address-sorted behavior.  "Membership only" sets are
//! `BTreeSet<RegionNodeId>` keyed by raw id (never iterated in an
//! output-affecting way).
//!
//! # Arena model
//!
//! The C++/Python uses node pointers; here a [`RegionNodeId`] (a `u32` index
//! into a [`NodePool`]) replaces the pointer.  Pointer identity is id equality.
//! The pool's allocation index is independent of the node's `ident` field (the
//! `KunaNodeOrder` tiebreaker), exactly as in the reference port.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};

/// Opaque handle to a collapsed region payload (owned by the
/// [`crate::sailr::region_id::RegionIdentifier`]'s region pool).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr graph_region.py GraphRegion / kuna p7_regions kuna_regiongraph.rs RegionPayloadId)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionId(pub u32);

/// What a [`RegionNode`] is.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr TNode = Block | MultiNode | GraphRegion / kuna p7_regions kuna_regiongraph.rs NodeKind)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Leaf: one basic block (real CFG block or synthetic test node).
    Block,
    /// Merged single-out -> single-in chain (angr `MultiNode`).
    Multi,
    /// Wrapper for a collapsed region (angr `GraphRegion`).
    Region,
    /// Dummy end node fabricated by acyclic-region identification
    /// (angr `Block(-1, -1)`).
    Dummy,
}

/// A node handle in the region-identification working graph.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py / kuna p7_regions kuna_regiongraph.rs KunaRegionNode)
#[derive(Debug, Clone)]
pub struct RegionNode {
    kind: NodeKind,
    /// Sort address (block start / first chain member / region head).
    addr: u64,
    /// Creation index: deterministic tiebreaker for equal addresses.
    ident: u32,
    /// External payload: the index of the CFG block this node wraps
    /// (`None` for synthetic test nodes).  Phase 2's adapter will store the
    /// bblocks `BlockId` here; Phase 1 keeps it an opaque index.
    block: Option<usize>,
    /// `Multi` members in execution order.
    chain: Vec<RegionNodeId>,
    /// `Region` payload.
    region: Option<RegionId>,
    /// Does the wrapped block end with a multi-way branch
    /// (BRANCHIND/CBRANCH)?  Precomputed by the input adapter so the analysis
    /// never needs to touch the live op bank.
    branchy: bool,
}

impl RegionNode {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py node construction / kuna p7_regions kuna_regiongraph.rs KunaRegionNode::new)
    /// Construct a bare node; the pool fills payload fields after allocation.
    pub fn new(kind: NodeKind, addr: u64, ident: u32) -> RegionNode {
        RegionNode {
            kind,
            addr,
            ident,
            block: None,
            chain: Vec::new(),
            region: None,
            branchy: false,
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getKind)
    /// Get the node kind.
    pub fn get_kind(&self) -> NodeKind {
        self.kind
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getAddr)
    /// Get the sort address.
    pub fn get_addr(&self) -> u64 {
        self.addr
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getIdent)
    /// Get the creation index.
    pub fn get_ident(&self) -> u32 {
        self.ident
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getBlock)
    /// External block payload (may be `None`).
    pub fn get_block(&self) -> Option<usize> {
        self.block
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs setBlock)
    /// Set the external block payload.
    pub fn set_block(&mut self, block: usize) {
        self.block = Some(block);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr region_identifier.py _block_ends_with_indirect_jump_or_call / kuna p7_regions kuna_regiongraph.rs branchy)
    /// Does the wrapped block end with a multi-way branch?  (Precomputed
    /// predicate parked by the input adapter.)
    pub fn ends_with_branchind_or_cbranch(&self) -> bool {
        self.branchy
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs setBranchy)
    /// Record the multi-way-branch predicate for a real block.
    pub fn set_branchy(&mut self, branchy: bool) {
        self.branchy = branchy;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getChain)
    /// `Multi` members in execution order.
    pub fn get_chain(&self) -> &[RegionNodeId] {
        &self.chain
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs setChain)
    /// Set the member chain.
    pub fn set_chain(&mut self, chain: Vec<RegionNodeId>) {
        self.chain = chain;
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getRegion)
    /// `Region` payload.
    pub fn get_region(&self) -> Option<RegionId> {
        self.region
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs setRegion)
    /// Set the region payload.
    pub fn set_region(&mut self, region: RegionId) {
        self.region = Some(region);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs isRegion)
    /// Is this a collapsed region?
    pub fn is_region(&self) -> bool {
        self.kind == NodeKind::Region
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs isMulti)
    /// Is this a merged chain?
    pub fn is_multi(&self) -> bool {
        self.kind == NodeKind::Multi
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs isDummy)
    /// Is this the dummy end node?
    pub fn is_dummy(&self) -> bool {
        self.kind == NodeKind::Dummy
    }
}

/// Arena id of a [`RegionNode`] (replaces the reference port's node pointer).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs KunaNodeId)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionNodeId(pub u32);

/// The global deterministic strict weak order over region nodes: compare
/// `(addr, ident)` lexicographically.  Every container the reference iterates
/// is keyed on this struct so iteration order matches exactly.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr sorted-by-addr iteration / kuna p7_regions kuna_regiongraph.rs KunaNodeKey+KunaNodeOrder)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeKey {
    /// Primary sort key.
    pub addr: u64,
    /// Tiebreaker (unique creation index).
    pub ident: u32,
    /// Arena id, never compared (total-order safety net only).
    pub id: RegionNodeId,
}

/// The owning pool for [`RegionNode`] handles.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs KunaNodePool)
#[derive(Debug, Clone, Default)]
pub struct NodePool {
    nodes: Vec<RegionNode>,
}

impl NodePool {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs KunaNodePool::new)
    /// An empty pool.
    pub fn new() -> NodePool {
        NodePool { nodes: Vec::new() }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: `new KunaRegionNode(...)` / kuna p7_regions kuna_regiongraph.rs alloc)
    /// Allocate a node, returning its id.
    pub fn alloc(&mut self, node: RegionNode) -> RegionNodeId {
        let id = RegionNodeId(self.nodes.len() as u32);
        self.nodes.push(node);
        id
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs make)
    /// Allocate a fresh node from `(kind, addr, ident)`.
    pub fn make(&mut self, kind: NodeKind, addr: u64, ident: u32) -> RegionNodeId {
        self.alloc(RegionNode::new(kind, addr, ident))
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs get)
    /// Borrow a node.
    pub fn get(&self, id: RegionNodeId) -> &RegionNode {
        &self.nodes[id.0 as usize]
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs get_mut)
    /// Borrow a node mutably.
    pub fn get_mut(&mut self, id: RegionNodeId) -> &mut RegionNode {
        &mut self.nodes[id.0 as usize]
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs key)
    /// The ordered key for `id`.
    pub fn key(&self, id: RegionNodeId) -> NodeKey {
        let n = self.get(id);
        NodeKey { addr: n.addr, ident: n.ident, id }
    }
}

/// Deterministically iterable node set (keyed by [`NodeKey`]).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs KunaNodeSet)
pub type NodeSet = BTreeSet<NodeKey>;

/// Adjacency record for one node (in/out lists preserve edge insertion order,
/// mirroring the networkx adjacency-dict insertion order the reference sees).
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs Adjacency)
#[derive(Debug, Clone, Default)]
struct Adjacency {
    preds: Vec<RegionNodeId>,
    succs: Vec<RegionNodeId>,
}

/// A mutable directed graph over [`RegionNodeId`] handles (the networkx
/// `DiGraph` analog).  Nodes carry insertion-ordered predecessor/successor
/// lists, edges are deduplicated on insert, self-loops are supported, and
/// whole-graph node iteration is in `(addr, ident)` order.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr networkx DiGraph usage / kuna p7_regions kuna_regiongraph.rs KunaRegionGraph)
#[derive(Debug, Clone, Default)]
pub struct RegionGraph {
    nodes: BTreeMap<NodeKey, Adjacency>,
    keyof: BTreeMap<RegionNodeId, NodeKey>,
}

impl RegionGraph {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs new)
    /// An empty graph.
    pub fn new() -> RegionGraph {
        RegionGraph { nodes: BTreeMap::new(), keyof: BTreeMap::new() }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs containsNode)
    /// Is the node in the graph?
    pub fn contains_node(&self, n: RegionNodeId) -> bool {
        self.keyof.contains_key(&n)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs addNodeKeyed)
    /// Add a node, with its ordered key (idempotent).
    pub fn add_node_keyed(&mut self, key: NodeKey) {
        self.nodes.entry(key).or_default();
        self.keyof.insert(key.id, key);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs addNode)
    /// Add a node by id, consulting the pool for its key.
    pub fn add_node(&mut self, pool: &NodePool, n: RegionNodeId) {
        self.add_node_keyed(pool.key(n));
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs keyOf)
    /// Look up a node's stored key.
    fn key_of(&self, n: RegionNodeId) -> Option<NodeKey> {
        self.keyof.get(&n).copied()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs removeNode)
    /// Remove node and all incident edges (self-loop safe).
    pub fn remove_node(&mut self, n: RegionNodeId) {
        let key = match self.key_of(n) {
            Some(k) => k,
            None => return,
        };
        let preds = self.nodes[&key].preds.clone();
        for p in preds {
            if p == n {
                continue;
            }
            let pk = self.keyof[&p];
            let ps = &mut self.nodes.get_mut(&pk).unwrap().succs;
            if let Some(pos) = ps.iter().position(|&x| x == n) {
                ps.remove(pos);
            }
        }
        let succs = self.nodes[&key].succs.clone();
        for s in succs {
            if s == n {
                continue;
            }
            let sk = self.keyof[&s];
            let sp = &mut self.nodes.get_mut(&sk).unwrap().preds;
            if let Some(pos) = sp.iter().position(|&x| x == n) {
                sp.remove(pos);
            }
        }
        self.nodes.remove(&key);
        self.keyof.remove(&n);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs hasEdge)
    /// Does edge a->b exist?
    pub fn has_edge(&self, a: RegionNodeId, b: RegionNodeId) -> bool {
        let key = match self.key_of(a) {
            Some(k) => k,
            None => return false,
        };
        self.nodes[&key].succs.contains(&b)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs addEdge)
    /// Add edge (idempotent, auto-adds endpoints).
    pub fn add_edge(&mut self, pool: &NodePool, a: RegionNodeId, b: RegionNodeId) {
        if self.has_edge(a, b) {
            return;
        }
        let ak = pool.key(a);
        let bk = pool.key(b);
        self.add_node_keyed(ak);
        self.add_node_keyed(bk);
        self.nodes.get_mut(&ak).unwrap().succs.push(b);
        self.nodes.get_mut(&bk).unwrap().preds.push(a);
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs removeEdge)
    /// Remove edge if present.
    pub fn remove_edge(&mut self, a: RegionNodeId, b: RegionNodeId) {
        if let Some(ak) = self.key_of(a) {
            let succs = &mut self.nodes.get_mut(&ak).unwrap().succs;
            if let Some(pos) = succs.iter().position(|&x| x == b) {
                succs.remove(pos);
            }
        }
        if let Some(bk) = self.key_of(b) {
            let preds = &mut self.nodes.get_mut(&bk).unwrap().preds;
            if let Some(pos) = preds.iter().position(|&x| x == a) {
                preds.remove(pos);
            }
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs sizeIn)
    /// In-degree (error if the node is not in the graph).
    pub fn size_in(&self, n: RegionNodeId) -> Result<i32> {
        let key = self
            .key_of(n)
            .ok_or_else(|| anyhow!("sailr regiongraph: sizeIn of node not in graph"))?;
        Ok(self.nodes[&key].preds.len() as i32)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs sizeOut)
    /// Out-degree (error if the node is not in the graph).
    pub fn size_out(&self, n: RegionNodeId) -> Result<i32> {
        let key = self
            .key_of(n)
            .ok_or_else(|| anyhow!("sailr regiongraph: sizeOut of node not in graph"))?;
        Ok(self.nodes[&key].succs.len() as i32)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getPreds)
    /// In-neighbors in insertion order.
    pub fn get_preds(&self, n: RegionNodeId) -> Result<&[RegionNodeId]> {
        let key = self
            .key_of(n)
            .ok_or_else(|| anyhow!("sailr regiongraph: getPreds of node not in graph"))?;
        Ok(&self.nodes[&key].preds)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getSuccs)
    /// Out-neighbors in insertion order.
    pub fn get_succs(&self, n: RegionNodeId) -> Result<&[RegionNodeId]> {
        let key = self
            .key_of(n)
            .ok_or_else(|| anyhow!("sailr regiongraph: getSuccs of node not in graph"))?;
        Ok(&self.nodes[&key].succs)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getSortedSuccs)
    /// Out-neighbors in `(addr, ident)` order.
    pub fn get_sorted_succs(
        &self,
        pool: &NodePool,
        n: RegionNodeId,
    ) -> Result<Vec<RegionNodeId>> {
        let mut res: Vec<RegionNodeId> = self.get_succs(n)?.to_vec();
        res.sort_by(|&a, &b| pool.key(a).cmp(&pool.key(b)));
        Ok(res)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs inEdges)
    /// Snapshot in-edges.
    pub fn in_edges(&self, n: RegionNodeId, res: &mut Vec<(RegionNodeId, RegionNodeId)>) -> Result<()> {
        for &p in self.get_preds(n)? {
            res.push((p, n));
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs outEdges)
    /// Snapshot out-edges.
    pub fn out_edges(&self, n: RegionNodeId, res: &mut Vec<(RegionNodeId, RegionNodeId)>) -> Result<()> {
        for &s in self.get_succs(n)? {
            res.push((n, s));
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs allEdges)
    /// Snapshot all edges (node-major deterministic order).
    pub fn all_edges(&self, res: &mut Vec<(RegionNodeId, RegionNodeId)>) {
        for (key, adj) in self.nodes.iter() {
            for &s in adj.succs.iter() {
                res.push((key.id, s));
            }
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs getNodes)
    /// Snapshot all nodes in `(addr, ident)` order.
    pub fn get_nodes(&self, res: &mut Vec<RegionNodeId>) {
        for key in self.nodes.keys() {
            res.push(key.id);
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs induced)
    /// Build induced subgraph copy.
    pub fn induced(&self, pool: &NodePool, keep: &NodeSet, res: &mut RegionGraph) {
        for key in keep.iter() {
            if !self.contains_node(key.id) {
                continue;
            }
            res.add_node_keyed(*key);
        }
        for key in keep.iter() {
            if !self.contains_node(key.id) {
                continue;
            }
            let succs: Vec<RegionNodeId> = self.nodes[key].succs.clone();
            for s in succs {
                if keep.contains(&pool.key(s)) {
                    res.add_edge(pool, key.id, s);
                }
            }
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs buildReversed)
    /// Build edge-reversed copy, same node set.
    pub fn build_reversed(&self, pool: &NodePool, res: &mut RegionGraph) {
        for key in self.nodes.keys() {
            res.add_node_keyed(*key);
        }
        let mut edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        for (key, adj) in self.nodes.iter() {
            for &s in adj.succs.iter() {
                edges.push((s, key.id));
            }
        }
        for (a, b) in edges {
            res.add_edge(pool, a, b);
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs nodeKeys)
    /// Begin deterministic node iteration (keys in `(addr, ident)` order).
    pub fn node_keys(&self) -> impl Iterator<Item = &NodeKey> {
        self.nodes.keys()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs iterAdj)
    /// Iterate nodes with their adjacency in `(addr, ident)` order.
    fn iter_adj(&self) -> impl Iterator<Item = (&NodeKey, &Adjacency)> {
        self.nodes.iter()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs numNodes)
    /// Number of nodes.
    pub fn num_nodes(&self) -> i32 {
        self.nodes.len() as i32
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs numEdges)
    /// Number of edges.
    pub fn num_edges(&self) -> i32 {
        let mut count = 0;
        for adj in self.nodes.values() {
            count += adj.succs.len() as i32;
        }
        count
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs clear)
    /// Remove all nodes and edges.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.keyof.clear();
    }
}

//
// DFS utilities
//

/// Find back edges via iterative DFS.  Children are visited in `(addr, ident)`
/// order; each `(source, target)` pair where `target` is on the current DFS
/// stack-path is reported, in discovery order.  Appends to `res`.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr analyses/decompiler/region_identifier.py dfs_back_edges / kuna p7_regions kuna_regiongraph.rs kuna_dfs_back_edges)
pub fn dfs_back_edges(
    pool: &NodePool,
    g: &RegionGraph,
    start: RegionNodeId,
    res: &mut Vec<(RegionNodeId, RegionNodeId)>,
) -> Result<()> {
    if !g.contains_node(start) {
        return Ok(());
    }
    let mut visited: BTreeSet<RegionNodeId> = BTreeSet::new();
    let mut finished: BTreeSet<RegionNodeId> = BTreeSet::new();
    struct Frame {
        node: RegionNodeId,
        children: Vec<RegionNodeId>,
        cursor: i32,
    }
    let mut stack: Vec<Frame> = Vec::new();
    stack.push(Frame { node: start, children: g.get_sorted_succs(pool, start)?, cursor: 0 });
    while !stack.is_empty() {
        let node = stack.last().unwrap().node;
        visited.insert(node);
        let (cursor, children_len) = {
            let frame = stack.last().unwrap();
            (frame.cursor, frame.children.len() as i32)
        };
        if cursor < children_len {
            let child = stack.last().unwrap().children[cursor as usize];
            stack.last_mut().unwrap().cursor += 1;
            if visited.contains(&child) {
                if !finished.contains(&child) {
                    res.push((node, child)); // Back edge
                }
            } else if !finished.contains(&child) {
                let children = g.get_sorted_succs(pool, child)?;
                stack.push(Frame { node: child, children, cursor: 0 });
            }
        } else {
            finished.insert(node);
            stack.pop();
        }
    }
    Ok(())
}

/// Deterministic DFS post-order from a source node.  Successors are pushed in
/// ascending `(addr, ident)` order so the largest-addressed successor is
/// explored first (matches the reference exactly).  Appends to `res`.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr analyses/utils/graph.py dfs_postorder_nodes_deterministic / kuna p7_regions kuna_regiongraph.rs kuna_dfs_postorder_deterministic)
pub fn dfs_postorder_deterministic(
    pool: &NodePool,
    g: &RegionGraph,
    source: RegionNodeId,
    res: &mut Vec<RegionNodeId>,
) -> Result<()> {
    let mut visited: BTreeSet<RegionNodeId> = BTreeSet::new();
    let mut stack: Vec<(RegionNodeId, bool)> = Vec::new();
    stack.push((source, true));
    while let Some(entry) = stack.pop() {
        if entry.1 && !visited.contains(&entry.0) {
            visited.insert(entry.0);
            stack.push((entry.0, false));
            let succs = g.get_sorted_succs(pool, entry.0)?;
            for s in succs {
                if !visited.contains(&s) {
                    stack.push((s, true));
                }
            }
        } else if !entry.1 {
            res.push(entry.0);
        }
    }
    Ok(())
}

//
// Quasi-topological sort
//

/// BFS shortest path length between two nodes; -1 if unreachable.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr networkx shortest_path_length usage in GraphUtils._append_scc / kuna p7_regions kuna_regiongraph.rs kunaShortestPathLength)
fn shortest_path_length(g: &RegionGraph, a: RegionNodeId, b: RegionNodeId) -> Result<i32> {
    if a == b {
        return Ok(0);
    }
    let mut dist: BTreeMap<RegionNodeId, i32> = BTreeMap::new();
    let mut queue: Vec<RegionNodeId> = Vec::new();
    dist.insert(a, 0);
    queue.push(a);
    let mut pos = 0;
    while pos < queue.len() {
        let cur = queue[pos];
        pos += 1;
        let d = dist[&cur];
        let succs: Vec<RegionNodeId> = g.get_succs(cur)?.to_vec();
        for s in succs {
            if dist.contains_key(&s) {
                continue;
            }
            if s == b {
                return Ok(d + 1);
            }
            dist.insert(s, d + 1);
            queue.push(s);
        }
    }
    Ok(-1)
}

/// Edge sort key: `src.addr + dst.addr` in arbitrary precision.  Native `u128`
/// gives the exact same total order the reference's big-int sum produces.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr GraphUtils._sort_edge / kuna p7_regions kuna_regiongraph.rs KunaEdgeSum)
fn edge_sum_key(
    pool: &NodePool,
    a: (RegionNodeId, RegionNodeId),
) -> u128 {
    let a0 = pool.get(a.0).get_addr() as u128;
    let a1 = pool.get(a.1).get_addr() as u128;
    a0 + a1
}

/// Quasi-topological sort of all nodes: collapse non-trivial SCCs to
/// placeholders, topologically sort the condensation, and expand each SCC
/// recursively after picking its loop head.  Appends the ordered nodes to
/// `res`.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr GraphUtils.quasi_topological_sort_nodes + _append_scc / kuna p7_regions kuna_regiongraph.rs kuna_quasi_topo_sort)
pub fn quasi_topological_sort(
    pool: &NodePool,
    g: &RegionGraph,
    res: &mut Vec<RegionNodeId>,
) -> Result<()> {
    let num_nodes = g.num_nodes();
    if num_nodes == 0 {
        return Ok(());
    }
    if num_nodes == 1 {
        res.push(g.node_keys().next().unwrap().id);
        return Ok(());
    }
    let num_nodes = num_nodes as usize;

    // --- Find non-trivial strongly connected components (iterative Tarjan) ---
    let mut node_list: Vec<RegionNodeId> = Vec::new();
    g.get_nodes(&mut node_list);
    let mut node_index: BTreeMap<RegionNodeId, i32> = BTreeMap::new();
    for (i, &n) in node_list.iter().enumerate() {
        node_index.insert(n, i as i32);
    }

    let mut tarjan_index: Vec<i32> = vec![-1; num_nodes];
    let mut tarjan_low: Vec<i32> = vec![0; num_nodes];
    let mut on_stack: Vec<bool> = vec![false; num_nodes];
    let mut scc_of: Vec<i32> = vec![-1; num_nodes];
    let mut scc_members: Vec<Vec<i32>> = Vec::new();
    {
        let mut counter: i32 = 0;
        let mut scc_stack: Vec<i32> = Vec::new();
        struct TFrame {
            node: i32,
            child: i32,
        }
        for root in 0..num_nodes as i32 {
            if tarjan_index[root as usize] != -1 {
                continue;
            }
            let mut stack: Vec<TFrame> = Vec::new();
            stack.push(TFrame { node: root, child: 0 });
            tarjan_index[root as usize] = counter;
            tarjan_low[root as usize] = counter;
            counter += 1;
            scc_stack.push(root);
            on_stack[root as usize] = true;
            while !stack.is_empty() {
                let fr_node = stack.last().unwrap().node;
                let fr_child = stack.last().unwrap().child;
                let succs: &[RegionNodeId] = g.get_succs(node_list[fr_node as usize])?;
                if (fr_child as usize) < succs.len() {
                    let w = node_index[&succs[fr_child as usize]];
                    stack.last_mut().unwrap().child += 1;
                    if tarjan_index[w as usize] == -1 {
                        tarjan_index[w as usize] = counter;
                        tarjan_low[w as usize] = counter;
                        counter += 1;
                        scc_stack.push(w);
                        on_stack[w as usize] = true;
                        stack.push(TFrame { node: w, child: 0 });
                    } else if on_stack[w as usize]
                        && tarjan_index[w as usize] < tarjan_low[fr_node as usize]
                    {
                        tarjan_low[fr_node as usize] = tarjan_index[w as usize];
                    }
                } else {
                    let v = fr_node;
                    stack.pop();
                    if let Some(parent_frame) = stack.last() {
                        let parent = parent_frame.node;
                        if tarjan_low[v as usize] < tarjan_low[parent as usize] {
                            tarjan_low[parent as usize] = tarjan_low[v as usize];
                        }
                    }
                    if tarjan_low[v as usize] == tarjan_index[v as usize] {
                        scc_members.push(Vec::new());
                        let new_scc = (scc_members.len() - 1) as i32;
                        loop {
                            let w = scc_stack.pop().unwrap();
                            on_stack[w as usize] = false;
                            scc_members.last_mut().unwrap().push(w);
                            scc_of[w as usize] = new_scc;
                            if w == v {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = &scc_of;

    // Keep only SCCs with more than one node; sort by (size, min addr, min ident).
    let mut big_sccs: Vec<i32> = Vec::new();
    for (i, mem) in scc_members.iter().enumerate() {
        if mem.len() > 1 {
            big_sccs.push(i as i32);
        }
    }
    let mut scc_min_addr: Vec<u64> = vec![0; scc_members.len()];
    let mut scc_min_ident: Vec<u32> = vec![0; scc_members.len()];
    for &bs in big_sccs.iter() {
        let mem = &scc_members[bs as usize];
        let mut mn = pool.get(node_list[mem[0] as usize]).get_addr();
        let mut mi = pool.get(node_list[mem[0] as usize]).get_ident();
        for &m in mem.iter().skip(1) {
            let a = pool.get(node_list[m as usize]).get_addr();
            let id = pool.get(node_list[m as usize]).get_ident();
            if a < mn || (a == mn && id < mi) {
                mn = a;
                mi = id;
            }
        }
        scc_min_addr[bs as usize] = mn;
        scc_min_ident[bs as usize] = mi;
    }
    // Stable insertion sort by (size, minaddr, minident) — small, deterministic.
    for i in 1..big_sccs.len() {
        let key = big_sccs[i];
        let mut j = i as i32 - 1;
        while j >= 0 {
            let other = big_sccs[j as usize];
            let greater: bool = if scc_members[other as usize].len() != scc_members[key as usize].len() {
                scc_members[other as usize].len() > scc_members[key as usize].len()
            } else if scc_min_addr[other as usize] != scc_min_addr[key as usize] {
                scc_min_addr[other as usize] > scc_min_addr[key as usize]
            } else {
                scc_min_ident[other as usize] > scc_min_ident[key as usize]
            };
            if !greater {
                break;
            }
            big_sccs[(j + 1) as usize] = other;
            j -= 1;
        }
        big_sccs[(j + 1) as usize] = key;
    }
    let mut comp_index: Vec<i32> = vec![-1; num_nodes];
    for (i, &bs) in big_sccs.iter().enumerate() {
        let mem = &scc_members[bs as usize];
        for &m in mem.iter() {
            comp_index[m as usize] = i as i32;
        }
    }

    // --- Build the collapsed (condensation-like) graph over integer ids ---
    let num_place = big_sccs.len();
    let total_ids = num_nodes + num_place + 1;
    let root_id = (num_nodes + num_place) as i32;
    let mut id_present: Vec<bool> = vec![false; total_ids];
    let mut id_succs: Vec<Vec<i32>> = vec![Vec::new(); total_ids];
    let mut id_in_degree: Vec<i32> = vec![0; total_ids];
    let mut id_succ_set: Vec<BTreeSet<i32>> = vec![BTreeSet::new(); total_ids];

    let mut edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
    g.all_edges(&mut edges);
    edges.sort_by_key(|&e| edge_sum_key(pool, e));
    for (efirst, esecond) in edges {
        let src_idx = node_index[&efirst];
        let dst_idx = node_index[&esecond];
        let src = if comp_index[src_idx as usize] >= 0 {
            (num_nodes as i32) + comp_index[src_idx as usize]
        } else {
            src_idx
        };
        let dst = if comp_index[dst_idx as usize] >= 0 {
            (num_nodes as i32) + comp_index[dst_idx as usize]
        } else {
            dst_idx
        };
        if src == dst {
            id_present[src as usize] = true;
            continue;
        }
        id_present[src as usize] = true;
        id_present[dst as usize] = true;
        if !id_succ_set[src as usize].contains(&dst) {
            id_succ_set[src as usize].insert(dst);
            id_succs[src as usize].push(dst);
            id_in_degree[dst as usize] += 1;
        }
    }
    // Add loners: nodes with no in or out edges at all.
    for i in 0..num_nodes {
        if g.size_out(node_list[i])? == 0 && g.size_in(node_list[i])? == 0 {
            id_present[i] = true;
        }
    }

    // Sort key for ids in the collapsed graph: root first, then
    // (addr, isPlaceholder, ident).  Returns true if a < b.
    let id_less = |a: i32, b: i32| -> bool {
        if a == root_id || b == root_id {
            return a == root_id && b != root_id;
        }
        let addr_a = if a >= num_nodes as i32 {
            scc_min_addr[big_sccs[(a - num_nodes as i32) as usize] as usize]
        } else {
            pool.get(node_list[a as usize]).get_addr()
        };
        let addr_b = if b >= num_nodes as i32 {
            scc_min_addr[big_sccs[(b - num_nodes as i32) as usize] as usize]
        } else {
            pool.get(node_list[b as usize]).get_addr()
        };
        if addr_a != addr_b {
            return addr_a < addr_b;
        }
        let place_a = a >= num_nodes as i32;
        let place_b = b >= num_nodes as i32;
        if place_a != place_b {
            return place_b; // Real node before placeholder on addr tie
        }
        if place_a {
            return scc_min_ident[big_sccs[(a - num_nodes as i32) as usize] as usize]
                < scc_min_ident[big_sccs[(b - num_nodes as i32) as usize] as usize];
        }
        pool.get(node_list[a as usize]).get_ident() < pool.get(node_list[b as usize]).get_ident()
    };

    // Heads of the collapsed graph.
    let mut heads: Vec<i32> = Vec::new();
    for i in 0..(total_ids - 1) {
        if id_present[i] && id_in_degree[i] == 0 {
            heads.push(i as i32);
        }
    }
    let head: i32;
    if heads.len() > 1 {
        head = root_id;
        id_present[root_id as usize] = true;
        for &h in heads.iter() {
            id_succs[root_id as usize].push(h);
        }
    } else if heads.len() == 1 {
        head = heads[0];
    } else {
        return Err(anyhow!("sailr regiongraph: collapsed graph has no head"));
    }

    // Deterministic DFS postorder over the collapsed integer graph.
    let mut postorder: Vec<i32> = Vec::new();
    {
        let mut visited: Vec<bool> = vec![false; total_ids];
        let mut stack: Vec<(i32, bool)> = Vec::new();
        stack.push((head, true));
        while let Some(entry) = stack.pop() {
            if entry.1 && !visited[entry.0 as usize] {
                visited[entry.0 as usize] = true;
                stack.push((entry.0, false));
                let mut succs: Vec<i32> = id_succs[entry.0 as usize].clone();
                for i in 1..succs.len() {
                    let key = succs[i];
                    let mut j = i as i32 - 1;
                    while j >= 0 && id_less(key, succs[j as usize]) {
                        succs[(j + 1) as usize] = succs[j as usize];
                        j -= 1;
                    }
                    succs[(j + 1) as usize] = key;
                }
                for &s in succs.iter() {
                    if !visited[s as usize] {
                        stack.push((s, true));
                    }
                }
            } else if !entry.1 {
                postorder.push(entry.0);
            }
        }
    }

    // Walk in REVERSE postorder, expanding placeholders recursively.
    for i in (0..postorder.len()).rev() {
        let id = postorder[i];
        if id == root_id {
            continue;
        }
        if id >= num_nodes as i32 {
            let mem = &scc_members[big_sccs[(id - num_nodes as i32) as usize] as usize];
            let mut scc: NodeSet = NodeSet::new();
            for &m in mem.iter() {
                scc.insert(pool.key(node_list[m as usize]));
            }
            append_scc(pool, g, res, &scc)?;
        } else {
            res.push(node_list[id as usize]);
        }
    }
    Ok(())
}

/// Expand one SCC into the ordered list: pick the loop head (the successor of
/// the latest already-ordered node whose total pairwise distance is minimal,
/// else the minimum-key member), cut its in-edges, and recurse; huge dense
/// SCCs first strip back edges in panic mode.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr GraphUtils._append_scc / kuna p7_regions kuna_regiongraph.rs kuna_append_scc)
fn append_scc(
    pool: &NodePool,
    g: &RegionGraph,
    ordered: &mut Vec<RegionNodeId>,
    scc: &NodeSet,
) -> Result<()> {
    let mut loop_head: Option<RegionNodeId> = None;

    // Find the first node (scanning ordered backwards) with successors in the
    // SCC.
    for i in (0..ordered.len()).rev() {
        let parent = ordered[i];
        let mut scc_succs: Vec<RegionNodeId> = Vec::new();
        {
            let mut seen: NodeSet = NodeSet::new();
            let succs: Vec<RegionNodeId> = g.get_succs(parent)?.to_vec();
            for s in succs {
                let sk = pool.key(s);
                if scc.contains(&sk) && !seen.contains(&sk) {
                    seen.insert(sk);
                    scc_succs.push(s);
                }
            }
        }
        if scc_succs.len() == 1 {
            loop_head = Some(scc_succs[0]);
            break;
        }
        if scc_succs.len() > 1 {
            // Pick the successor with the lowest total pairwise distance; on a
            // distance tie the LAST one (in addr order) wins, matching the
            // reference's dict-inversion {v: k} semantics.
            scc_succs.sort_by(|&a, &b| pool.key(a).cmp(&pool.key(b)));
            let mut dist_to_node: BTreeMap<i32, RegionNodeId> = BTreeMap::new();
            for &j in scc_succs.iter() {
                let mut total: i32 = 0;
                for &k in scc_succs.iter() {
                    if k == j {
                        continue;
                    }
                    let d = shortest_path_length(g, j, k)?;
                    if d < 0 {
                        return Err(anyhow!(
                            "sailr regiongraph: SCC members not mutually reachable"
                        ));
                    }
                    total += d;
                }
                dist_to_node.insert(total, j);
            }
            loop_head = Some(*dist_to_node.values().next().unwrap());
            break;
        }
    }

    let loop_head = match loop_head {
        Some(lh) => lh,
        None => scc.iter().next().unwrap().id,
    };

    let mut subgraph = RegionGraph::new();
    g.induced(pool, scc, &mut subgraph);
    {
        let mut head_in: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        subgraph.in_edges(loop_head, &mut head_in)?;
        for (a, b) in head_in {
            subgraph.remove_edge(a, b);
        }
    }

    // Panic mode: huge dense SCCs converge too slowly one-node-at-a-time.
    const PANIC_THRESHOLD: i32 = 3000;
    if subgraph.num_nodes() > PANIC_THRESHOLD
        && (subgraph.num_edges() as f64) > (subgraph.num_nodes() as f64) * 1.4
    {
        let mut back_edges: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        dfs_back_edges(pool, &subgraph, loop_head, &mut back_edges)?;
        back_edges.sort_by_key(|&e| edge_sum_key(pool, e));
        for (a, b) in back_edges {
            subgraph.remove_edge(a, b);
            if (subgraph.num_edges() as f64) <= (subgraph.num_nodes() as f64) * 1.4 {
                break;
            }
        }
    }

    quasi_topological_sort(pool, &subgraph, ordered)
}

//
// subgraph_between_nodes
//

/// Slice of `g` from `source` up to (optionally including) `frontier`: copy the
/// graph, cut edges into `source`, BFS forward keeping only paths that can
/// still reach the frontier, then iteratively prune dangling nodes.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr subgraph_between_nodes / kuna p7_regions kuna_regiongraph.rs kuna_subgraph_between_nodes)
pub fn subgraph_between_nodes(
    pool: &NodePool,
    g: &RegionGraph,
    source: RegionNodeId,
    frontier: &NodeSet,
    include_frontier: bool,
    res: &mut RegionGraph,
) -> Result<()> {
    if !g.contains_node(source) {
        return Err(anyhow!("sailr regiongraph: slice source not in graph"));
    }
    for fk in frontier.iter() {
        if !g.contains_node(fk.id) {
            return Err(anyhow!("sailr regiongraph: slice frontier node not in graph"));
        }
    }

    let mut graph = g.clone();
    {
        let mut src_in: Vec<(RegionNodeId, RegionNodeId)> = Vec::new();
        graph.in_edges(source, &mut src_in)?;
        for (a, b) in src_in {
            graph.remove_edge(a, b);
        }
    }

    // One reverse BFS from the frontier set: which nodes can still reach it?
    let mut can_reach: BTreeSet<RegionNodeId> = BTreeSet::new();
    {
        let mut queue: Vec<RegionNodeId> = Vec::new();
        for fk in frontier.iter() {
            if !can_reach.contains(&fk.id) {
                can_reach.insert(fk.id);
                queue.push(fk.id);
            }
        }
        let mut pos = 0;
        while pos < queue.len() {
            let cur = queue[pos];
            pos += 1;
            let preds: Vec<RegionNodeId> = graph.get_preds(cur)?.to_vec();
            for p in preds {
                if !can_reach.contains(&p) {
                    can_reach.insert(p);
                    queue.push(p);
                }
            }
        }
    }

    // Forward FIFO BFS from source, adding edges to the slice.
    {
        let mut queue: Vec<RegionNodeId> = Vec::new();
        let mut traversed: BTreeSet<RegionNodeId> = BTreeSet::new();
        queue.push(source);
        let mut pos = 0;
        while pos < queue.len() {
            let node = queue[pos];
            pos += 1;
            if traversed.contains(&node) {
                continue;
            }
            traversed.insert(node);
            let succs: Vec<RegionNodeId> = graph.get_succs(node)?.to_vec();
            for succ in succs {
                if res.has_edge(node, succ) {
                    continue;
                }
                res.add_edge(pool, node, succ);
                if traversed.contains(&succ) {
                    continue;
                }
                if frontier.contains(&pool.key(succ)) {
                    continue;
                }
                if can_reach.contains(&succ) {
                    queue.push(succ);
                }
            }
        }
    }

    // Iteratively prune dangling interior nodes.
    loop {
        let mut to_remove: Vec<RegionNodeId> = Vec::new();
        for (key, adj) in res.iter_adj() {
            let n = key.id;
            if n == source {
                continue;
            }
            if frontier.contains(key) {
                continue;
            }
            if adj.succs.is_empty() || adj.preds.is_empty() {
                to_remove.push(n);
            }
        }
        if to_remove.is_empty() {
            break;
        }
        for n in to_remove {
            res.remove_node(n);
        }
    }

    if !include_frontier {
        for fk in frontier.iter() {
            if res.contains_node(fk.id) {
                res.remove_node(fk.id);
            }
        }
    }
    Ok(())
}

//
// Dominators
//

/// Immediate dominators of all nodes reachable from `start`
/// (Cooper-Harvey-Kennedy over a deterministic reverse post-order).
/// Unreachable nodes are absent from `idom`; `idom[start] == start`.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: networkx immediate_dominators analog / kuna p7_regions kuna_regiongraph.rs kuna_immediate_dominators)
pub fn immediate_dominators(
    pool: &NodePool,
    g: &RegionGraph,
    start: RegionNodeId,
    idom: &mut BTreeMap<RegionNodeId, RegionNodeId>,
) -> Result<()> {
    let mut postorder: Vec<RegionNodeId> = Vec::new();
    dfs_postorder_deterministic(pool, g, start, &mut postorder)?;
    let mut po_num: BTreeMap<RegionNodeId, i32> = BTreeMap::new();
    for (i, &n) in postorder.iter().enumerate() {
        po_num.insert(n, i as i32);
    }

    idom.insert(start, start);
    let mut changed = true;
    while changed {
        changed = false;
        for i in (0..postorder.len()).rev() {
            let b = postorder[i];
            if b == start {
                continue;
            }
            let mut new_idom: Option<RegionNodeId> = None;
            let preds: Vec<RegionNodeId> = g.get_preds(b)?.to_vec();
            for pred in preds {
                if !po_num.contains_key(&pred) {
                    continue; // Unreachable predecessor
                }
                if !idom.contains_key(&pred) {
                    continue; // Not yet processed
                }
                if new_idom.is_none() {
                    new_idom = Some(pred);
                    continue;
                }
                // intersect(pred, new_idom)
                let mut f1 = pred;
                let mut f2 = new_idom.unwrap();
                while f1 != f2 {
                    while po_num[&f1] < po_num[&f2] {
                        f1 = idom[&f1];
                    }
                    while po_num[&f2] < po_num[&f1] {
                        f2 = idom[&f2];
                    }
                }
                new_idom = Some(f1);
            }
            if let Some(ni) = new_idom {
                let prev = idom.get(&b).copied();
                if prev != Some(ni) {
                    idom.insert(b, ni);
                    changed = true;
                }
            }
        }
    }
    Ok(())
}

/// Does `dominator` dominate `node` under the idom map?
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils.graph.dominates / kuna p7_regions kuna_regiongraph.rs kuna_dominates)
pub fn dominates(
    idom: &BTreeMap<RegionNodeId, RegionNodeId>,
    dominator: RegionNodeId,
    node: RegionNodeId,
) -> bool {
    let mut n: Option<RegionNodeId> = Some(node);
    while let Some(cur) = n {
        if cur == dominator {
            return true;
        }
        n = match idom.get(&cur) {
            Some(&d) if d != cur => Some(d),
            _ => None,
        };
    }
    false
}

//
// IncrementalDominators
//

/// Incrementally maintained (post-)dominators with dominance frontiers.
/// The graph must only ever change by replacing a set of nodes with a single
/// new node ([`IncrementalDominators::graph_updated`]), exactly as in the
/// reference.  Frontiers are computed lazily on first
/// [`df`](IncrementalDominators::df) use and patched incrementally afterwards.
// RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py IncrementalDominators / kuna p7_regions kuna_regiongraph.rs KunaIncrementalDominators)
pub struct IncrementalDominators {
    start: RegionNodeId,
    post: bool,
    doms: BTreeMap<RegionNodeId, RegionNodeId>,
    dfs_valid: bool,
    dfs: BTreeMap<RegionNodeId, NodeSet>,
    inverted_valid: bool,
    inverted_dom_tree: BTreeMap<RegionNodeId, Vec<RegionNodeId>>,
}

impl IncrementalDominators {
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py IncrementalDominators.__init__ / kuna p7_regions kuna_regiongraph.rs new)
    /// Build over `graph` rooted at `start` (`is_post` computes post-dominators).
    pub fn new(
        pool: &NodePool,
        graph: &RegionGraph,
        start: RegionNodeId,
        is_post: bool,
    ) -> Result<IncrementalDominators> {
        let mut me = IncrementalDominators {
            start,
            post: is_post,
            doms: BTreeMap::new(),
            dfs_valid: false,
            dfs: BTreeMap::new(),
            inverted_valid: false,
            inverted_dom_tree: BTreeMap::new(),
        };
        let doms = me.compute_doms(pool, graph)?;
        me.doms = doms;
        Ok(me)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py init_doms / kuna p7_regions kuna_regiongraph.rs computeDoms)
    /// Compute doms from scratch.
    fn compute_doms(
        &self,
        pool: &NodePool,
        graph: &RegionGraph,
    ) -> Result<BTreeMap<RegionNodeId, RegionNodeId>> {
        let mut res: BTreeMap<RegionNodeId, RegionNodeId> = BTreeMap::new();
        if self.post {
            let mut rev = RegionGraph::new();
            graph.build_reversed(pool, &mut rev);
            immediate_dominators(pool, &rev, self.start, &mut res)?;
        } else {
            immediate_dominators(pool, graph, self.start, &mut res)?;
        }
        res.insert(self.start, self.start);
        Ok(res)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py init_dfs / kuna p7_regions kuna_regiongraph.rs computeDfs)
    /// Compute frontiers from scratch: walk every node with >= 2
    /// direction-predecessors, climbing the dom chain.
    fn compute_dfs(
        &self,
        pool: &NodePool,
        graph: &RegionGraph,
    ) -> Result<BTreeMap<RegionNodeId, NodeSet>> {
        let mut res: BTreeMap<RegionNodeId, NodeSet> = BTreeMap::new();
        let dom_keys: Vec<RegionNodeId> = self.doms_in_order(pool);
        for u in dom_keys {
            if !graph.contains_node(u) {
                continue;
            }
            let preds: Vec<RegionNodeId> = if self.post {
                graph.get_succs(u)?.to_vec()
            } else {
                graph.get_preds(u)?.to_vec()
            };
            if preds.len() < 2 {
                continue;
            }
            let du = self.doms[&u];
            for v0 in preds {
                if !self.doms.contains_key(&v0) {
                    continue;
                }
                let mut v = v0;
                while v != du {
                    res.entry(v).or_default().insert(pool.key(u));
                    match self.doms.get(&v) {
                        Some(&nx) => v = nx,
                        None => {
                            return Err(anyhow!(
                                "sailr regiongraph: broken dom chain in initDfs"
                            ))
                        }
                    }
                }
            }
        }
        Ok(res)
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs domsInOrder)
    /// `doms` keys in `(addr, ident)` order (deterministic iteration).
    fn doms_in_order(&self, pool: &NodePool) -> Vec<RegionNodeId> {
        let mut v: Vec<RegionNodeId> = self.doms.keys().copied().collect();
        v.sort_by(|&a, &b| pool.key(a).cmp(&pool.key(b)));
        v
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py update_inverted_domtree / kuna p7_regions kuna_regiongraph.rs updateInvertedDomtree)
    /// Build the inverted tree if not yet built.
    fn update_inverted_domtree(&mut self, pool: &NodePool) {
        if self.inverted_valid {
            return;
        }
        self.inverted_valid = true;
        for u in self.doms_in_order(pool) {
            let d = self.doms[&u];
            self.inverted_dom_tree.entry(d).or_default().push(u);
        }
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py idom / kuna p7_regions kuna_regiongraph.rs idom)
    /// Immediate dominator (`None` if absent).
    pub fn idom(&self, n: RegionNodeId) -> Option<RegionNodeId> {
        self.doms.get(&n).copied()
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py df / kuna p7_regions kuna_regiongraph.rs df)
    /// Dominance frontier (empty set if absent).
    pub fn df(
        &mut self,
        pool: &NodePool,
        graph: &RegionGraph,
        n: RegionNodeId,
    ) -> Result<NodeSet> {
        if !self.dfs_valid {
            self.dfs_valid = true;
            self.dfs = self.compute_dfs(pool, graph)?;
        }
        Ok(self.dfs.get(&n).cloned().unwrap_or_default())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py dominates / kuna p7_regions kuna_regiongraph.rs dominates)
    /// Does `dominator` (post-)dominate `n`?
    pub fn dominates(&self, dominator: RegionNodeId, n: RegionNodeId) -> bool {
        let mut cur: Option<RegionNodeId> = Some(n);
        while let Some(c) = cur {
            if c == dominator {
                return true;
            }
            cur = match self.idom(c) {
                Some(d) if c != d => Some(d),
                _ => None,
            };
        }
        false
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py graph_updated / kuna p7_regions kuna_regiongraph.rs graphUpdated)
    /// Patch after nodes were replaced by `new_node`.
    pub fn graph_updated(
        &mut self,
        pool: &NodePool,
        new_node: RegionNodeId,
        replaced_nodes: &NodeSet,
        replaced_head: RegionNodeId,
    ) -> Result<()> {
        self.update_inverted_domtree(pool);

        // Climb out of the replaced set to find the new node's dominator.
        let mut new_dom = *self
            .doms
            .get(&replaced_head)
            .ok_or_else(|| anyhow!("sailr regiongraph: replaced head has no dominator"))?;
        while replaced_nodes.contains(&pool.key(new_dom)) && new_dom != self.start {
            new_dom = *self
                .doms
                .get(&new_dom)
                .ok_or_else(|| anyhow!("sailr regiongraph: broken dom chain in graphUpdated"))?;
        }
        if replaced_nodes.contains(&pool.key(self.start)) {
            self.start = new_node;
        }
        if replaced_nodes.contains(&pool.key(new_dom)) {
            new_dom = new_node;
        }

        // Re-point all dominatees of replaced nodes at the new node.
        let mut new_node_doms: Vec<RegionNodeId> = Vec::new();
        for ri in replaced_nodes.iter() {
            if let Some(dtees) = self.inverted_dom_tree.get(&ri.id) {
                let dtees = dtees.clone();
                for d in dtees {
                    self.doms.insert(d, new_node);
                    new_node_doms.push(d);
                }
            }
        }
        self.doms.insert(new_node, new_dom);

        if self.dfs_valid {
            if let Some(hi) = self.dfs.get(&replaced_head).cloned() {
                self.dfs.insert(new_node, hi);
            }
            for ri in replaced_nodes.iter() {
                let rn = ri.id;
                self.dfs.remove(&rn);
                let rk = pool.key(rn);
                let nk = pool.key(new_node);
                for fset in self.dfs.values_mut() {
                    if fset.remove(&rk) {
                        fset.insert(nk);
                    }
                }
            }
        }

        // Keep the inverted dom tree up to date.
        self.inverted_dom_tree.entry(new_dom).or_default().push(new_node);
        self.inverted_dom_tree.insert(new_node, new_node_doms);
        for ri in replaced_nodes.iter() {
            let rn = ri.id;
            if let Some(&d) = self.doms.get(&rn) {
                self.doms.remove(&rn);
                let lst = self.inverted_dom_tree.get_mut(&d).unwrap();
                let mut found = false;
                if let Some(pos) = lst.iter().position(|&x| x == rn) {
                    lst.remove(pos);
                    found = true;
                }
                if !found {
                    return Err(anyhow!(
                        "sailr regiongraph: inverted dom tree inconsistent"
                    ));
                }
            }
            self.inverted_dom_tree.remove(&rn);
        }
        Ok(())
    }

    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: angr utils/doms.py _debug_check / kuna p7_regions kuna_regiongraph.rs verify)
    /// Recompute from scratch and compare (debug verification).
    pub fn verify(&self, pool: &NodePool, graph: &RegionGraph) -> Result<()> {
        let true_doms = self.compute_doms(pool, graph)?;
        if true_doms.len() != self.doms.len() {
            return Err(anyhow!("sailr regiongraph: incremental dominators diverged (size)"));
        }
        for (k, v) in true_doms.iter() {
            match self.doms.get(k) {
                Some(dv) if dv == v => {}
                _ => return Err(anyhow!("sailr regiongraph: incremental dominators diverged")),
            }
        }
        if self.dfs_valid {
            let true_dfs = self.compute_dfs(pool, graph)?;
            if true_dfs.len() != self.dfs.len() {
                return Err(anyhow!("sailr regiongraph: incremental frontiers diverged (size)"));
            }
            for (k, v) in true_dfs.iter() {
                match self.dfs.get(k) {
                    Some(dv) if dv == v => {}
                    _ => return Err(anyhow!("sailr regiongraph: incremental frontiers diverged")),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: a pool plus sequential ident allocation, building test
    /// graphs keyed by address (mirrors the reference port's Builder).
    // RUDRA-GLUE: SAILR enhancement layer (enhanced-track, no Ghidra counterpart; ref: kuna p7_regions kuna_regiongraph.rs tests Builder)
    struct Builder {
        pool: NodePool,
        next_ident: u32,
    }

    impl Builder {
        fn new() -> Builder {
            Builder { pool: NodePool::new(), next_ident: 0 }
        }

        fn node(&mut self, addr: u64) -> RegionNodeId {
            let id = self.next_ident;
            self.next_ident += 1;
            self.pool.make(NodeKind::Block, addr, id)
        }

        fn graph(
            &self,
            edges: &[(RegionNodeId, RegionNodeId)],
            extra: &[RegionNodeId],
        ) -> RegionGraph {
            let mut g = RegionGraph::new();
            for &n in extra {
                g.add_node(&self.pool, n);
            }
            for &(a, b) in edges {
                g.add_edge(&self.pool, a, b);
            }
            g
        }

        fn set(&self, ids: &[RegionNodeId]) -> NodeSet {
            let mut s = NodeSet::new();
            for &i in ids {
                s.insert(self.pool.key(i));
            }
            s
        }
    }

    #[test]
    fn node_order_addr_then_ident() {
        let mut b = Builder::new();
        let n0 = b.node(0x100); // ident 0
        let n1 = b.node(0x100); // ident 1, same addr
        let n2 = b.node(0x080); // lower addr
        let g = b.graph(&[], &[n0, n1, n2]);
        let mut nodes = Vec::new();
        g.get_nodes(&mut nodes);
        // (addr, ident) order: 0x080/2, 0x100/0, 0x100/1.
        assert_eq!(nodes, vec![n2, n0, n1]);
    }

    #[test]
    fn edge_dedup_and_self_loop() {
        let mut b = Builder::new();
        let a = b.node(0x10);
        let c = b.node(0x20);
        let mut g = b.graph(&[(a, c), (a, c)], &[]); // duplicate
        assert_eq!(g.num_edges(), 1);
        g.add_edge(&b.pool, a, a); // self-loop
        assert!(g.has_edge(a, a));
        assert_eq!(g.size_out(a).unwrap(), 2);
        assert_eq!(g.size_in(a).unwrap(), 1);
        g.remove_node(a);
        assert!(!g.contains_node(a));
        assert_eq!(g.size_in(c).unwrap(), 0);
    }

    #[test]
    fn sorted_succs_determinism() {
        let mut b = Builder::new();
        let s = b.node(0x00);
        let hi = b.node(0x300);
        let lo = b.node(0x100);
        let mid = b.node(0x200);
        let g = b.graph(&[(s, hi), (s, lo), (s, mid)], &[]);
        assert_eq!(g.get_succs(s).unwrap(), &[hi, lo, mid]);
        assert_eq!(g.get_sorted_succs(&b.pool, s).unwrap(), vec![lo, mid, hi]);
    }

    #[test]
    fn back_edges_simple_loop() {
        // a -> b -> c -> b (back edge c->b); plus c -> d
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let g = b.graph(&[(a, bb), (bb, c), (c, bb), (c, d)], &[]);
        let mut be = Vec::new();
        dfs_back_edges(&b.pool, &g, a, &mut be).unwrap();
        assert_eq!(be, vec![(c, bb)]);
    }

    #[test]
    fn back_edges_self_loop() {
        let mut b = Builder::new();
        let a = b.node(0x10);
        let c = b.node(0x20);
        let g = b.graph(&[(a, c), (c, c)], &[]);
        let mut be = Vec::new();
        dfs_back_edges(&b.pool, &g, a, &mut be).unwrap();
        assert_eq!(be, vec![(c, c)]);
    }

    #[test]
    fn postorder_deterministic_diamond() {
        // a -> b, a -> c, b -> d, c -> d
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let g = b.graph(&[(a, bb), (a, c), (bb, d), (c, d)], &[]);
        let mut po = Vec::new();
        dfs_postorder_deterministic(&b.pool, &g, a, &mut po).unwrap();
        // Successors pushed ascending => largest (c@0x30) explored first.
        assert_eq!(po, vec![d, c, bb, a]);
        assert_eq!(*po.last().unwrap(), a);
    }

    #[test]
    fn topo_sort_acyclic_is_reverse_postorder() {
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let g = b.graph(&[(a, bb), (bb, c)], &[]);
        let mut order = Vec::new();
        quasi_topological_sort(&b.pool, &g, &mut order).unwrap();
        assert_eq!(order, vec![a, bb, c]);
    }

    #[test]
    fn topo_sort_with_scc() {
        // a -> b -> c -> b (SCC {b,c}); c -> d.  Head of the SCC is b.
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let g = b.graph(&[(a, bb), (bb, c), (c, bb), (c, d)], &[]);
        let mut order = Vec::new();
        quasi_topological_sort(&b.pool, &g, &mut order).unwrap();
        assert_eq!(order.len(), 4);
        assert_eq!(order[0], a);
        let pos_b = order.iter().position(|&x| x == bb).unwrap();
        let pos_c = order.iter().position(|&x| x == c).unwrap();
        let pos_d = order.iter().position(|&x| x == d).unwrap();
        assert!(pos_b < pos_c, "loop head b before c");
        assert!(pos_c < pos_d, "scc before d");
    }

    #[test]
    fn immediate_dominators_diamond() {
        // a -> b, a -> c, b -> d, c -> d.  idom(d) == a.
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let g = b.graph(&[(a, bb), (a, c), (bb, d), (c, d)], &[]);
        let mut idom = BTreeMap::new();
        immediate_dominators(&b.pool, &g, a, &mut idom).unwrap();
        assert_eq!(idom[&a], a);
        assert_eq!(idom[&bb], a);
        assert_eq!(idom[&c], a);
        assert_eq!(idom[&d], a);
        assert!(dominates(&idom, a, d));
        assert!(!dominates(&idom, bb, d));
    }

    #[test]
    fn subgraph_between_nodes_basic() {
        // a -> b -> c -> e ; a -> d -> e ; b -> f (dead-end, pruned).
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let e = b.node(0x50);
        let f = b.node(0x60);
        let g = b.graph(&[(a, bb), (bb, c), (c, e), (a, d), (d, e), (bb, f)], &[]);
        let frontier = b.set(&[e]);
        let mut res = RegionGraph::new();
        subgraph_between_nodes(&b.pool, &g, a, &frontier, true, &mut res).unwrap();
        assert!(!res.contains_node(f));
        assert!(res.contains_node(e));
        assert!(res.contains_node(a));

        let mut res2 = RegionGraph::new();
        subgraph_between_nodes(&b.pool, &g, a, &frontier, false, &mut res2).unwrap();
        assert!(!res2.contains_node(e));
    }

    #[test]
    fn subgraph_between_nodes_errors() {
        let mut b = Builder::new();
        let a = b.node(0x10);
        let c = b.node(0x20);
        let orphan = b.node(0x99);
        let g = b.graph(&[(a, c)], &[]);
        let empty = NodeSet::new();
        assert!(subgraph_between_nodes(&b.pool, &g, orphan, &empty, true, &mut RegionGraph::new()).is_err());
        let bad_front = b.set(&[orphan]);
        assert!(subgraph_between_nodes(&b.pool, &g, a, &bad_front, true, &mut RegionGraph::new()).is_err());
    }

    #[test]
    fn incremental_dominators_match_scratch() {
        // a -> b, a -> c, b -> d, c -> d, d -> e.
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let e = b.node(0x50);
        let g = b.graph(&[(a, bb), (a, c), (bb, d), (c, d), (d, e)], &[]);
        let dom = IncrementalDominators::new(&b.pool, &g, a, false).unwrap();
        assert_eq!(dom.idom(a), Some(a));
        assert_eq!(dom.idom(d), Some(a));
        assert_eq!(dom.idom(e), Some(d));
        dom.verify(&b.pool, &g).unwrap();
        assert!(dom.dominates(a, e));
        assert!(!dom.dominates(bb, e));
    }

    #[test]
    fn incremental_dominators_frontier() {
        // Classic diamond: df(b) and df(c) are both {d}.
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let g = b.graph(&[(a, bb), (a, c), (bb, d), (c, d)], &[]);
        let mut dom = IncrementalDominators::new(&b.pool, &g, a, false).unwrap();
        let dfb = dom.df(&b.pool, &g, bb).unwrap();
        let dfc = dom.df(&b.pool, &g, c).unwrap();
        assert_eq!(dfb, b.set(&[d]));
        assert_eq!(dfc, b.set(&[d]));
        dom.verify(&b.pool, &g).unwrap();
    }

    #[test]
    fn incremental_dominators_patch_after_merge() {
        // Collapse a single-entry/single-exit sub-chain into one node and
        // patch; the result must equal a from-scratch computation on the
        // updated graph.
        //   before: a -> b -> c -> d -> e
        //   merge {b,c} -> m (replaced_head = b)
        //   after:  a -> m -> d -> e
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let d = b.node(0x40);
        let e = b.node(0x50);
        let g = b.graph(&[(a, bb), (bb, c), (c, d), (d, e)], &[]);
        let mut dom = IncrementalDominators::new(&b.pool, &g, a, false).unwrap();
        let _ = dom.df(&b.pool, &g, bb).unwrap();

        let m = b.node(0x20); // same addr as the replaced head b
        let g2 = b.graph(&[(a, m), (m, d), (d, e)], &[]);

        let replaced = b.set(&[bb, c]);
        dom.graph_updated(&b.pool, m, &replaced, bb).unwrap();

        assert_eq!(dom.idom(a), Some(a));
        assert_eq!(dom.idom(m), Some(a));
        assert_eq!(dom.idom(d), Some(m));
        assert_eq!(dom.idom(e), Some(d));
        assert_eq!(dom.idom(bb), None); // folded into m
        assert_eq!(dom.idom(c), None);
        dom.verify(&b.pool, &g2).unwrap();
    }

    #[test]
    fn post_dominators_reversed() {
        // a -> b -> c, computing post-dominators rooted at c (the sink).
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let g = b.graph(&[(a, bb), (bb, c)], &[]);
        let dom = IncrementalDominators::new(&b.pool, &g, c, true).unwrap();
        assert_eq!(dom.idom(c), Some(c));
        assert_eq!(dom.idom(bb), Some(c));
        assert_eq!(dom.idom(a), Some(bb));
        dom.verify(&b.pool, &g).unwrap();
    }

    #[test]
    fn induced_and_reversed_copies() {
        let mut b = Builder::new();
        let a = b.node(0x10);
        let bb = b.node(0x20);
        let c = b.node(0x30);
        let g = b.graph(&[(a, bb), (bb, c), (a, c)], &[]);

        let keep = b.set(&[a, bb]);
        let mut ind = RegionGraph::new();
        g.induced(&b.pool, &keep, &mut ind);
        assert_eq!(ind.num_nodes(), 2);
        assert!(ind.has_edge(a, bb));
        assert!(!ind.has_edge(a, c));

        let mut rev = RegionGraph::new();
        g.build_reversed(&b.pool, &mut rev);
        assert!(rev.has_edge(bb, a));
        assert!(rev.has_edge(c, bb));
        assert!(rev.has_edge(c, a));
        assert_eq!(rev.num_nodes(), 3);
    }
}
