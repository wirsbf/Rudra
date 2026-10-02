// BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 Rust comparand for locked Ghidra 12.0.4.
//
// Mirrors block_identify_internal_1204.cc case-for-case through
// CollapseStructure::identify_internal (the BlockGraph::identifyInternal +
// selfIdentify + dedup port, block.cc:940-963 / 895-931 / 525-539) and
// emits the same complete raw state: composite children order, parent
// ownership, raw flags (components are NEVER f_dead), boundary edge
// slots/labels/reverse indices, peer retargets, parallel-edge dedup label
// merge, flag propagation, internal-edge retention.
//
// Top-level positions are normalized to sorted membership: Ghidra appends
// the composite at the list end (block.cc:1695), Rugra installs it at the
// first component's slot — the registered model divergence outside this
// fixture's covered projection.  All other observations are raw.

use std::sync::{Arc, RwLock};

use rudra::block::{block_flags as bf, BlockEdge, BlockGraph, BlockList, BlockType, FlowBlock};
use rudra::blockaction::CollapseStructure;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

#[derive(Debug)]
struct BaseProbe {
    index: i32,
    flags: u32,
    incoming: Vec<BlockEdge>,
    outgoing: Vec<BlockEdge>,
}

impl BaseProbe {
    fn new() -> Self {
        Self {
            index: 0,
            flags: 0,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }
    }
}

impl FlowBlock for BaseProbe {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn get_index(&self) -> i32 {
        self.index
    }

    fn set_index(&mut self, index: i32) {
        self.index = index;
    }

    fn get_type(&self) -> BlockType {
        BlockType::Plain
    }

    fn get_flags(&self) -> u32 {
        self.flags
    }

    fn set_flags(&mut self, flags: u32) {
        self.flags |= flags;
    }

    fn clear_flags(&mut self, flags: u32) {
        self.flags &= !flags;
    }

    fn size_in(&self) -> usize {
        self.incoming.len()
    }

    fn size_out(&self) -> usize {
        self.outgoing.len()
    }

    fn get_in(&self, slot: usize) -> Option<BlockEdge> {
        self.incoming.get(slot).cloned()
    }

    fn get_out(&self, slot: usize) -> Option<BlockEdge> {
        self.outgoing.get(slot).cloned()
    }

    fn out_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.outgoing
    }

    fn in_edges_mut(&mut self) -> &mut Vec<BlockEdge> {
        &mut self.incoming
    }

    fn add_in_edge(&mut self, edge: BlockEdge) {
        self.incoming.push(edge);
    }

    fn add_out_edge(&mut self, edge: BlockEdge) {
        self.outgoing.push(edge);
    }

    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        None
    }
}

fn probe(index: i32) -> BlockRef {
    let b: BlockRef = Arc::new(RwLock::new(BaseProbe::new()));
    b.write().unwrap().set_index(index);
    b
}

fn set_label(b: &BlockRef, outgoing: bool, slot: usize, label: u32) {
    let mut g = b.write().unwrap();
    let probe = g.as_any_mut().downcast_mut::<BaseProbe>().unwrap();
    if outgoing {
        probe.outgoing[slot].flags = label;
    } else {
        probe.incoming[slot].flags = label;
    }
}

/// BlockGraph::add_edge mirrors FlowBlock::addInEdge's append ordering and
/// reciprocal slot assignment (self/parallel edges included); mirrored label
/// assignment reproduces the C++ fixture's symmetric addLabeledEdge.
fn wire(graph: &mut BlockGraph, from: &BlockRef, to: &BlockRef, label: u32) {
    graph.add_edge(from.clone(), to.clone());
    let out_slot = from.read().unwrap().size_out() - 1;
    let in_slot = to.read().unwrap().size_in() - 1;
    set_label(from, true, out_slot, label);
    set_label(to, false, in_slot, label);
}

#[derive(Default)]
struct Names {
    blocks: Vec<(BlockRef, String)>,
}

impl Names {
    fn add(&mut self, b: &BlockRef, name: &str) {
        self.blocks.push((b.clone(), name.to_string()));
    }

    fn block(&self, b: Option<&BlockRef>) -> String {
        let Some(b) = b else {
            return "null".to_string();
        };
        self.blocks
            .iter()
            .find(|(c, _)| Arc::ptr_eq(c, b))
            .map_or_else(|| "?".to_string(), |(_, n)| n.clone())
    }

    /// Children of the composite in -nodes- order (Ghidra BlockGraph::list,
    /// block.hh:359; Rugra's BlockList.children holds the same Arc nodes).
    fn children(&self, composite: &BlockRef) -> Vec<BlockRef> {
        let g = composite.read().unwrap();
        g.as_any()
            .downcast_ref::<BlockList>()
            .map(|l| l.children.clone())
            .unwrap_or_default()
    }

    /// Parent ownership mirror of Ghidra FlowBlock::getParent (block.hh:78):
    /// a component of the composite resolves to the composite, a top-level
    /// block to the graph itself.
    fn parent(&self, b: &BlockRef, composite: &BlockRef, graph_blocks: &[BlockRef]) -> String {
        for c in &self.children(composite) {
            if Arc::ptr_eq(c, b) {
                return self.block(Some(composite));
            }
        }
        for g in graph_blocks {
            if Arc::ptr_eq(g, b) {
                return "G".to_string();
            }
        }
        "?".to_string()
    }

    fn sorted_members(&self, blocks: &[BlockRef]) -> String {
        let mut names: Vec<String> = blocks.iter().map(|b| self.block(Some(b))).collect();
        names.sort();
        format!("[{}]", names.join(","))
    }
}

fn edge_list(b: &BlockRef, outgoing: bool, names: &Names) -> String {
    let g = b.read().unwrap();
    let n = if outgoing { g.size_out() } else { g.size_in() };
    let mut parts: Vec<String> = Vec::new();
    for slot in 0..n {
        let e = if outgoing { g.get_out(slot) } else { g.get_in(slot) };
        if let Some(e) = e {
            // Decimal label formatting mirrors the C++ fixture's fresh
            // ostringstream inside edgeList (its own decimal stream state).
            parts.push(format!(
                "{}:{}:{}",
                names.block(Some(&e.point)),
                e.reverse_index,
                e.flags
            ));
        }
    }
    format!("[{}]", parts.join(","))
}

/// Reciprocal-consistency mirror of FlowBlock::checkEdges (block.cc:545-570).
fn edges_consistent(b: &BlockRef) -> bool {
    let g = b.read().unwrap();
    for i in 0..g.size_in() {
        let Some(e) = g.get_in(i) else { continue };
        let peer = e.point.read().unwrap();
        let rev = e.reverse_index;
        if rev < 0 || peer.size_out() as i32 <= rev {
            return false;
        }
        let Some(pe) = peer.get_out(rev as usize) else { return false };
        if !Arc::ptr_eq(&pe.point, b) || pe.reverse_index != i as i32 {
            return false;
        }
    }
    for i in 0..g.size_out() {
        let Some(e) = g.get_out(i) else { continue };
        let peer = e.point.read().unwrap();
        let rev = e.reverse_index;
        if rev < 0 || peer.size_in() as i32 <= rev {
            return false;
        }
        let Some(pe) = peer.get_in(rev as usize) else { return false };
        if !Arc::ptr_eq(&pe.point, b) || pe.reverse_index != i as i32 {
            return false;
        }
    }
    true
}

/// Top-level members (non-consumed) in slot order plus their count — the
/// observable Ghidra's incremental list compaction (block.cc:953-960)
/// maintains; membership comes from the absorbed_into parent record.
fn top_members(graph: &BlockGraph) -> Vec<BlockRef> {
    let consumed = &graph.absorbed_into;
    let mut out = Vec::new();
    for i in 0..graph.get_size() {
        if let Some(b) = graph.get_block(i) {
            let idx = b.read().unwrap().get_index();
            if !consumed.contains_key(&idx) {
                out.push(b);
            }
        }
    }
    out
}

fn flags_of(b: &BlockRef) -> String {
    format!("{:x}", b.read().unwrap().get_flags())
}

fn dead(b: &BlockRef) -> u32 {
    (b.read().unwrap().get_flags() & bf::DEAD != 0) as u32
}

// Case 1: plain cat identify (newBlockList, block.cc:1758-1774).
fn case_cat_basic() {
    let p = probe(0);
    let a = probe(1);
    let b = probe(2);
    let c = probe(3);
    let q = probe(4);
    let mut graph = BlockGraph::new();
    for blk in [&p, &a, &b, &c, &q] {
        graph.blocks.push((*blk).clone());
    }
    wire(&mut graph, &p, &a, 0x21);
    wire(&mut graph, &a, &b, 0x0);
    wire(&mut graph, &b, &c, 0x0);
    wire(&mut graph, &c, &q, 0x42);

    // newBlockList({A,B}): A is the install block (Ghidra nodes[0]), B the
    // consumed component — the try_rule_cat split of Ghidra's -nodes-.
    let w: BlockRef = Arc::new(RwLock::new(BlockList::new(1, vec![a.clone(), b.clone()])));
    {
        let mut collapse = CollapseStructure::new(&mut graph, "identify_fixture");
        collapse.identify_internal(&w, &[2], 1);
    }

    let mut names = Names::default();
    names.add(&p, "P");
    names.add(&a, "A");
    names.add(&b, "B");
    names.add(&c, "C");
    names.add(&q, "Q");
    names.add(&w, "W");

    let members = top_members(&graph);
    println!(
        "case=cat_basic|top_members={}|graph_size={}|w_index={}|w_children={}|parent_A={}|parent_B={}|parent_P={}|flags_A={}|flags_B={}|flags_W={}|dead_A={}|dead_B={}|w_in={}|w_out={}|a_in={}|a_out={}|b_in={}|b_out={}|p_out={}|c_in={}|c_out={}|q_in={}|consistent_W={}|consistent_P={}|consistent_C={}|consistent_A={}|consistent_B={}",
        names.sorted_members(&members),
        members.len(),
        w.read().unwrap().get_index(),
        names.sorted_members(&names.children(&w)),
        names.parent(&a, &w, &graph.blocks),
        names.parent(&b, &w, &graph.blocks),
        names.parent(&p, &w, &graph.blocks),
        flags_of(&a),
        flags_of(&b),
        flags_of(&w),
        dead(&a),
        dead(&b),
        edge_list(&w, false, &names),
        edge_list(&w, true, &names),
        edge_list(&a, false, &names),
        edge_list(&a, true, &names),
        edge_list(&b, false, &names),
        edge_list(&b, true, &names),
        edge_list(&p, true, &names),
        edge_list(&c, false, &names),
        edge_list(&c, true, &names),
        edge_list(&q, false, &names),
        edges_consistent(&w) as u32,
        edges_consistent(&p) as u32,
        edges_consistent(&c) as u32,
        edges_consistent(&a) as u32,
        edges_consistent(&b) as u32,
    );
}

// Case 2: parallel boundary edges through one peer; selfIdentify's dedup
// (block.cc:930) merges duplicate halves, keeps the first slot, ORs labels.
fn case_parallel_dedup() {
    let p = probe(0);
    let a = probe(1);
    let b = probe(2);
    let m = probe(3);
    let mut graph = BlockGraph::new();
    for blk in [&p, &a, &b, &m] {
        graph.blocks.push((*blk).clone());
    }
    wire(&mut graph, &p, &a, 0x1);
    wire(&mut graph, &a, &b, 0x0);
    wire(&mut graph, &a, &m, 0x5);
    wire(&mut graph, &b, &m, 0x9);

    let w: BlockRef = Arc::new(RwLock::new(BlockList::new(1, vec![a.clone(), b.clone()])));
    {
        let mut collapse = CollapseStructure::new(&mut graph, "identify_fixture");
        collapse.identify_internal(&w, &[2], 1);
    }

    let mut names = Names::default();
    names.add(&p, "P");
    names.add(&a, "A");
    names.add(&b, "B");
    names.add(&m, "M");
    names.add(&w, "W");

    println!(
        "case=parallel_dedup|w_children={}|parent_A={}|parent_B={}|dead_A={}|dead_B={}|w_in={}|w_out={}|m_in={}|a_out={}|b_out={}|consistent_W={}|consistent_M={}",
        names.sorted_members(&names.children(&w)),
        names.parent(&a, &w, &graph.blocks),
        names.parent(&b, &w, &graph.blocks),
        dead(&a),
        dead(&b),
        edge_list(&w, false, &names),
        edge_list(&w, true, &names),
        edge_list(&m, false, &names),
        edge_list(&a, true, &names),
        edge_list(&b, true, &names),
        edges_consistent(&w) as u32,
        edges_consistent(&m) as u32,
    );
}

// Case 3: flag propagation (f_switch_out needs an external out edge,
// block.cc:925-926; f_interior_goto* OR from every component, block.cc:951).
fn case_flag_propagation() {
    let p = probe(0);
    let a = probe(1);
    let b = probe(2);
    let s = probe(3);
    let x = probe(4);
    let y = probe(5);
    let mut graph = BlockGraph::new();
    for blk in [&p, &a, &b, &s, &x, &y] {
        graph.blocks.push((*blk).clone());
    }
    wire(&mut graph, &p, &a, 0x0);
    wire(&mut graph, &a, &x, 0x0);
    wire(&mut graph, &y, &b, 0x0);
    wire(&mut graph, &a, &b, 0x0);
    wire(&mut graph, &b, &s, 0x0);

    a.write().unwrap().set_flags(bf::SWITCH_OUT);
    b.write().unwrap().set_flags(bf::SWITCH_OUT | bf::INTERIOR_GOTOIN);
    s.write().unwrap().set_flags(bf::INTERIOR_GOTOOUT);

    let w: BlockRef = Arc::new(RwLock::new(BlockList::new(
        1,
        vec![a.clone(), b.clone(), s.clone()],
    )));
    {
        let mut collapse = CollapseStructure::new(&mut graph, "identify_fixture");
        collapse.identify_internal(&w, &[2, 3], 1);
    }

    let mut names = Names::default();
    names.add(&p, "P");
    names.add(&a, "A");
    names.add(&b, "B");
    names.add(&s, "S");
    names.add(&x, "X");
    names.add(&y, "Y");
    names.add(&w, "W");

    let wf = w.read().unwrap().get_flags();
    println!(
        "case=flag_propagation|flags_W={:x}|switch_out_W={}|interior_gotoout_W={}|interior_gotoin_W={}|dead_S={}|parent_S={}|w_out={}|w_in={}|consistent_W={}|consistent_X={}|consistent_Y={}",
        wf,
        (wf & bf::SWITCH_OUT != 0) as u32,
        (wf & bf::INTERIOR_GOTOOUT != 0) as u32,
        (wf & bf::INTERIOR_GOTOIN != 0) as u32,
        dead(&s),
        names.parent(&s, &w, &graph.blocks),
        edge_list(&w, true, &names),
        edge_list(&w, false, &names),
        edges_consistent(&w) as u32,
        edges_consistent(&x) as u32,
        edges_consistent(&y) as u32,
    );
}

// Case 4: self edge inside the consumed set stays component-internal.
fn case_self_edge_internal() {
    let a = probe(0);
    let b = probe(1);
    let c = probe(2);
    let mut graph = BlockGraph::new();
    for blk in [&a, &b, &c] {
        graph.blocks.push((*blk).clone());
    }
    wire(&mut graph, &a, &a, 0x0);
    wire(&mut graph, &a, &b, 0x0);
    wire(&mut graph, &b, &c, 0x7);

    let w: BlockRef = Arc::new(RwLock::new(BlockList::new(0, vec![a.clone(), b.clone()])));
    {
        let mut collapse = CollapseStructure::new(&mut graph, "identify_fixture");
        collapse.identify_internal(&w, &[1], 0);
    }

    let mut names = Names::default();
    names.add(&a, "A");
    names.add(&b, "B");
    names.add(&c, "C");
    names.add(&w, "W");

    println!(
        "case=self_edge_internal|a_in={}|a_out={}|w_in={}|w_out={}|dead_A={}|parent_A={}|consistent_A={}|consistent_W={}",
        edge_list(&a, false, &names),
        edge_list(&a, true, &names),
        edge_list(&w, false, &names),
        edge_list(&w, true, &names),
        dead(&a),
        names.parent(&a, &w, &graph.blocks),
        edges_consistent(&a) as u32,
        edges_consistent(&w) as u32,
    );
}

fn main() {
    println!(
        "schema=1|fixture=BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b|overall=MISMATCH|covered_projection=MATCH"
    );
    case_cat_basic();
    case_parallel_dedup();
    case_flag_propagation();
    case_self_edge_internal();
}
