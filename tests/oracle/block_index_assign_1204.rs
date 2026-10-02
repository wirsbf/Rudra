// BLOCK-INDEX-ASSIGN-0001: Rudra comparand for the locked Ghidra 12.0.4
// BlockGraph::findSpanningTree (block.cc:1009-1136) oracle.  Mirrors
// tests/oracle/block_index_assign_1204.cc case for case: the same synthetic
// control-flow graphs are built through the production BlockGraph APIs
// (add_block/add_edge) and the complete post-call state is printed in the
// shared observation format.

use std::sync::{Arc, RwLock, Weak};

use rudra::address::Address;
use rudra::block::{edge_flags as ef, BlockBasic, BlockGraph, FlowBlock};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn flags_text(label: u32) -> String {
    let mut out = String::new();
    if label & ef::F_GOTO_EDGE != 0 { out.push('g'); }
    if label & ef::F_LOOP_EDGE != 0 { out.push('l'); }
    // Rudra's F_DEFAULTSWITCH_EDGE shares bit 7 with F_TREE_EDGE (pre-existing
    // edge_flags collision). Within this projection bit 7 can only be a tree
    // label: findSpanningTree wipes every edge label at the start of each pass
    // and never sets default-switch labels.
    if label & ef::F_DEFAULTSWITCH_EDGE != 0 && label & ef::F_TREE_EDGE == 0 { out.push('d'); }
    if label & ef::F_IRREDUCIBLE_EDGE != 0 { out.push('i'); }
    if label & ef::F_TREE_EDGE != 0 { out.push('t'); }
    if label & ef::F_FORWARD_EDGE != 0 { out.push('f'); }
    if label & ef::F_CROSS_EDGE != 0 { out.push('c'); }
    if label & ef::F_BACK_EDGE != 0 { out.push('b'); }
    if label & ef::F_LOOP_EXIT_EDGE != 0 { out.push('x'); }
    if out.is_empty() { out.push('-'); }
    out
}

struct Graph {
    graph: BlockGraph,
    created: Vec<BlockRef>,
    base: u64,
}

impl Graph {
    fn new(base: u64) -> Self {
        Graph { graph: BlockGraph::new(), created: Vec::new(), base }
    }

    fn make_block(&mut self) -> BlockRef {
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            0,
            Address::new(self.base),
        )));
        self.graph.add_block(bl.clone());
        self.created.push(bl.clone());
        bl
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.graph.add_edge(from.clone(), to.clone());
    }

    fn name(&self, bl: &BlockRef) -> String {
        for (i, cand) in self.created.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("b{}", i);
            }
        }
        "b?".to_string()
    }

    fn observe(&self, case_name: &str, preorder: &[BlockRef], rootlist: &[BlockRef]) {
        let pre: Vec<String> = preorder.iter().map(|b| self.name(b)).collect();
        let roots: Vec<String> = rootlist.iter().map(|b| self.name(b)).collect();
        let list: Vec<String> = self.graph.blocks.iter().map(|b| self.name(b)).collect();
        let mut indices_ok = true;
        let mut seen = vec![false; self.created.len()];
        let mut blocks = String::from("[");
        for (i, bl) in self.created.iter().enumerate() {
            if i != 0 { blocks.push(';'); }
            let g = bl.read().unwrap();
            blocks.push_str(&format!(
                "{}:index={},visit={},desc={},copy=",
                self.name(bl),
                g.get_index(),
                g.get_visit_count(),
                g.get_num_desc()
            ));
            let copy: Weak<RwLock<dyn FlowBlock + Send + Sync>> = match g.get_copy_map() {
                Some(w) => w,
                None => {
                    blocks.push_str("null");
                    continue;
                }
            };
            drop(g);
            match copy.upgrade() {
                Some(arc) if Arc::ptr_eq(&arc, bl) => blocks.push_str("self"),
                Some(arc) => blocks.push_str(&format!("other:{}", self.name(&arc))),
                None => blocks.push_str("null"),
            }
        }
        blocks.push(']');
        for bl in &self.created {
            let idx = bl.read().unwrap().get_index();
            if idx < 0 || idx as usize >= self.created.len() || seen[idx as usize] {
                indices_ok = false;
            } else {
                seen[idx as usize] = true;
            }
        }
        if seen.iter().any(|s| !s) { indices_ok = false; }
        let mut outedges = String::from("[");
        let mut first = true;
        for bl in &self.created {
            let g = bl.read().unwrap();
            for s in 0..g.size_out() {
                if let Some(e) = g.get_out(s) {
                    if !first { outedges.push(';'); }
                    first = false;
                    outedges.push_str(&format!(
                        "{}!{}>{}:{}",
                        self.name(bl),
                        s,
                        self.name(&e.point),
                        flags_text(e.flags)
                    ));
                }
            }
        }
        outedges.push(']');
        let mut inedges = String::from("[");
        first = true;
        for bl in &self.created {
            let g = bl.read().unwrap();
            for s in 0..g.size_in() {
                if let Some(e) = g.get_in(s) {
                    if !first { inedges.push(';'); }
                    first = false;
                    inedges.push_str(&format!(
                        "{}@{}<{}:{}",
                        self.name(bl),
                        s,
                        self.name(&e.point),
                        flags_text(e.flags)
                    ));
                }
            }
        }
        inedges.push(']');
        println!(
            "case={}|preorder=[{}]|roots=[{}]|list=[{}]|blocks={}|out={}|in={}|indices_ok={}",
            case_name,
            pre.join(","),
            roots.join(","),
            list.join(","),
            blocks,
            outedges,
            inedges,
            if indices_ok { 1 } else { 0 }
        );
    }
}

fn main() {
    println!("schema=1|fixture=BLOCK-INDEX-ASSIGN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=empty_graph_early_return
    {
        let mut g = Graph::new(0x4f00);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("empty_graph_early_return", &preorder, &rootlist);
    }

    // case=single_block
    {
        let mut g = Graph::new(0x4f80);
        let _b0 = g.make_block();
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("single_block", &preorder, &rootlist);
    }

    // case=single_entry_dag_corrupt_reset
    {
        let mut g = Graph::new(0x5000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b0, &b3);
        b1.write().unwrap().set_index(99);
        b1.write().unwrap().set_visit_count(5);
        b1.write().unwrap().set_copy_map(Some(Arc::downgrade(&b0)));
        b2.write().unwrap().set_num_desc(77);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("single_entry_dag_corrupt_reset", &preorder, &rootlist);
    }

    // case=multi_entry_rootlist_swap
    {
        let mut g = Graph::new(0x5100);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b2);
        g.edge(&b1, &b2);
        g.edge(&b2, &b3);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("multi_entry_rootlist_swap", &preorder, &rootlist);
    }

    // case=no_root_assume_first_loop
    {
        let mut g = Graph::new(0x5200);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b0);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("no_root_assume_first_loop", &preorder, &rootlist);
    }

    // case=unreachable_extraroots_twopass
    {
        let mut g = Graph::new(0x5300);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b2, &b3);
        g.edge(&b3, &b2);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("unreachable_extraroots_twopass", &preorder, &rootlist);
    }

    // case=stale_root_machinery
    {
        let mut g = Graph::new(0x5400);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b3);
        g.edge(&b1, &b0);
        g.edge(&b2, &b1);
        g.edge(&b2, &b2);
        g.edge(&b4, &b4);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("stale_root_machinery", &preorder, &rootlist);
    }

    // case=irreducible_prelabel_wiped
    {
        let mut g = Graph::new(0x5500);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        {
            // Pre-label both halves the way Ghidra's setOutEdgeFlag does.
            let (target, rev) = {
                let g0 = b0.read().unwrap();
                let e = g0.get_out(0).unwrap();
                (e.point.clone(), e.reverse_index)
            };
            b0.write().unwrap().set_out_edge_flag(0, ef::F_IRREDUCIBLE_EDGE | ef::F_BACK_EDGE);
            target.write().unwrap().set_in_edge_flag(rev as usize, ef::F_IRREDUCIBLE_EDGE | ef::F_BACK_EDGE);
        }
        {
            let (target, rev) = {
                let g1 = b1.read().unwrap();
                let e = g1.get_out(0).unwrap();
                (e.point.clone(), e.reverse_index)
            };
            b1.write().unwrap().set_out_edge_flag(0, ef::F_GOTO_EDGE | ef::F_LOOP_EXIT_EDGE);
            target.write().unwrap().set_in_edge_flag(rev as usize, ef::F_GOTO_EDGE | ef::F_LOOP_EXIT_EDGE);
        }
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        g.graph.find_spanning_tree(&mut preorder, &mut rootlist).expect("spanning tree");
        g.observe("irreducible_prelabel_wiped", &preorder, &rootlist);
    }
}
