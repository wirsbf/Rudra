// BLOCK-FINDIRREDUCIBLE-0001: Rudra comparand for the locked Ghidra 12.0.4
// BlockGraph::findIrreducible (block.cc:1147-1199) oracle.  Mirrors
// tests/oracle/block_findirreducible_1204.cc case for case: the same
// synthetic control-flow graphs are built through the production BlockGraph
// APIs (add_block/add_edge), find_spanning_tree + find_irreducible (or the
// full structure_loops driver) run, and the complete post-call state is
// printed in the shared observation format.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{edge_flags as ef, BlockBasic, BlockGraph, FlowBlock};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn flags_text(label: u32) -> String {
    let mut out = String::new();
    if label & ef::F_GOTO_EDGE != 0 { out.push('g'); }
    if label & ef::F_LOOP_EDGE != 0 { out.push('l'); }
    // Rudra's F_DEFAULTSWITCH_EDGE shares bit 7 with F_TREE_EDGE
    // (pre-existing edge_flags collision). Within this projection bit 7 can
    // only be a tree label: findSpanningTree wipes every edge label at the
    // start of each pass and neither pass ever sets default-switch labels.
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

    // Uniform post-call projection shared by both call paths. `rebuild_text`
    // and `cnt_text` are "-" for the structure_loops case (not observable
    // from outside the driver).
    fn observe(
        &self,
        case_name: &str,
        rebuild_text: &str,
        cnt_text: &str,
        preorder: &[BlockRef],
        rootlist: &[BlockRef],
    ) {
        let pre: Vec<String> = preorder.iter().map(|b| self.name(b)).collect();
        let roots: Vec<String> = rootlist.iter().map(|b| self.name(b)).collect();
        let list: Vec<String> = self.graph.blocks.iter().map(|b| self.name(b)).collect();
        let mut blocks = String::from("[");
        for (i, bl) in self.created.iter().enumerate() {
            if i != 0 { blocks.push(';'); }
            let g = bl.read().unwrap();
            blocks.push_str(&format!(
                "{}:index={},visit={},desc={},mark={},copy=",
                self.name(bl),
                g.get_index(),
                g.get_visit_count(),
                g.get_num_desc(),
                if g.is_mark() { 1 } else { 0 },
            ));
            let copy = match g.get_copy_map() {
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
            "case={}|rebuild={}|cnt={}|pre=[{}]|roots=[{}]|list=[{}]|blocks={}|out={}|in={}",
            case_name,
            rebuild_text,
            cnt_text,
            pre.join(","),
            roots.join(","),
            list.join(","),
            blocks,
            outedges,
            inedges,
        );
    }

    // find_spanning_tree + find_irreducible path (block.cc:2203-2204 shape).
    fn run_pair(&mut self, case_name: &str) {
        let mut preorder: Vec<BlockRef> = Vec::new();
        let mut rootlist: Vec<BlockRef> = Vec::new();
        self.graph
            .find_spanning_tree(&mut preorder, &mut rootlist)
            .expect("spanning tree");
        let mut irreduciblecount: i32 = 0;
        let needrebuild = self.graph.find_irreducible(&preorder, &mut irreduciblecount);
        self.observe(
            case_name,
            if needrebuild { "1" } else { "0" },
            &irreduciblecount.to_string(),
            &preorder,
            &rootlist,
        );
    }
}

fn main() {
    println!("schema=1|fixture=BLOCK-FINDIRREDUCIBLE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=reducible_diamond_zero_marks
    {
        let mut g = Graph::new(0x5f00);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b0, &b3);
        g.run_pair("reducible_diamond_zero_marks");
    }

    // case=self_loop_head_skipped
    {
        let mut g = Graph::new(0x5f80);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b1);
        g.edge(&b1, &b2);
        g.run_pair("self_loop_head_skipped");
    }

    // case=classic_two_entry
    {
        let mut g = Graph::new(0x6000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.run_pair("classic_two_entry");
    }

    // case=parallel_edges_double_count
    {
        let mut g = Graph::new(0x6080);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b0, &b2);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.run_pair("parallel_edges_double_count");
    }

    // case=nested_irreducible_find_reuse
    {
        let mut g = Graph::new(0x6100);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b3, &b2);
        g.edge(&b2, &b4);
        g.edge(&b4, &b1);
        g.run_pair("nested_irreducible_find_reuse");
    }

    // case=multi_root_cross_to_irreducible
    {
        let mut g = Graph::new(0x6180);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b3, &b2);
        g.run_pair("multi_root_cross_to_irreducible");
    }

    // case=structure_loops_reducible_endtoend
    {
        let mut g = Graph::new(0x6200);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.edge(&b2, &b3);
        g.edge(&b3, &b2);
        g.edge(&b3, &b4);
        let mut rootlist: Vec<BlockRef> = Vec::new();
        g.graph.structure_loops(&mut rootlist).expect("structure loops");
        let preorder: Vec<BlockRef> = Vec::new();
        g.observe("structure_loops_reducible_endtoend", "-", "-", &preorder, &rootlist);
    }
}
