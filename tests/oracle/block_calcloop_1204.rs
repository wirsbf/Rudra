// BLOCK-CALCLOOP-0001: Rugra comparand for the locked Ghidra 12.0.4
// BlockGraph::calcLoop (block.cc:2104-2147) oracle.  Mirrors
// tests/oracle/block_calcloop_1204.cc case for case: the same synthetic
// control-flow graphs are built through the production BlockGraph APIs
// (add_block/add_edge), calc_loop runs directly (fresh unlabeled edges) or
// the full structure_loops / structure_loops+calc_forward_dominator chain
// drives the failsafe path, and the complete post-call state is printed in
// the shared observation format.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{edge_flags as ef, block_flags as bf, BlockBasic, BlockGraph, FlowBlock};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn flags_text(label: u32) -> String {
    let mut out = String::new();
    if label & ef::F_GOTO_EDGE != 0 { out.push('g'); }
    if label & ef::F_LOOP_EDGE != 0 { out.push('l'); }
    // Rugra's F_DEFAULTSWITCH_EDGE shares bit 7 with F_TREE_EDGE
    // (pre-existing edge_flags collision). Within this projection bit 7 can
    // only be a tree label: the spanning tree wipes every edge label at the
    // start of each pass and no pass here sets default-switch labels.
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

    // Uniform post-call projection shared by every call path. `extra`
    // carries the per-case driver annotation, mirroring the C++ fixture.
    // `full_state` gates the copymap/numdesc projection: FlowBlock's
    // user-provided constructor (block.cc:61-69) leaves copymap and numdesc
    // indeterminate until findSpanningTree initializes them, so the direct
    // calcLoop cases print "-" (heap noise is not algorithm output).
    fn observe(&self, case_name: &str, extra: &str, full_state: bool) {
        let list: Vec<String> = self.graph.blocks.iter().map(|b| self.name(b)).collect();
        let mut blocks = String::from("[");
        for (i, bl) in self.created.iter().enumerate() {
            if i != 0 { blocks.push(';'); }
            let g = bl.read().unwrap();
            let flags = g.get_flags();
            blocks.push_str(&format!(
                "{}:index={},visit={},desc={},mark={},mark2={},copy=",
                self.name(bl),
                g.get_index(),
                g.get_visit_count(),
                if full_state { g.get_num_desc().to_string() } else { "-".to_string() },
                if flags & bf::MARK != 0 { 1 } else { 0 },
                if flags & bf::MARK2 != 0 { 1 } else { 0 },
            ));
            let (dom_weak, copy_weak) = {
                let dom = g.get_immed_dom();
                (dom, g.get_copy_map())
            };
            drop(g);
            if !full_state {
                blocks.push('-');
            } else {
                match copy_weak.and_then(|w| w.upgrade()) {
                    Some(arc) if Arc::ptr_eq(&arc, bl) => blocks.push_str("self"),
                    Some(arc) => blocks.push_str(&format!("other:{}", self.name(&arc))),
                    None => blocks.push_str("null"),
                }
            }
            match dom_weak.and_then(|w| w.upgrade()) {
                Some(arc) => blocks.push_str(&format!(",dom={}", self.name(&arc))),
                None => blocks.push_str(",dom=null"),
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
            "case={}|extra={}|list=[{}]|blocks={}|out={}|in={}",
            case_name,
            extra,
            list.join(","),
            blocks,
            outedges,
            inedges,
        );
    }

    // Rootlist projection for the structure_loops chains (funcdata_block.cc:
    // 711-713: calcForwardDominator input + blocks_unreachable decision).
    fn observe_roots(&self, case_name: &str, extra: &str, rootlist: &[BlockRef]) {
        let roots: Vec<String> = rootlist.iter().map(|b| self.name(b)).collect();
        println!(
            "case={}_roots|extra={}|roots=[{}]|unreachable={}",
            case_name,
            extra,
            roots.join(","),
            if rootlist.len() > 1 { 1 } else { 0 },
        );
    }
}

fn main() {
    println!("schema=1|fixture=BLOCK-CALCLOOP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=reducible_backedge_labeled
    {
        let mut g = Graph::new(0x6300);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.graph.calc_loop();
        g.observe("reducible_backedge_labeled", "direct:1", false);
    }

    // case=nested_loops_inner_outer
    {
        let mut g = Graph::new(0x6340);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b3);
        g.edge(&b3, &b2);
        g.edge(&b3, &b4);
        g.edge(&b4, &b1);
        g.graph.calc_loop();
        g.observe("nested_loops_inner_outer", "direct:1", false);
    }

    // case=self_loop_then_child
    {
        let mut g = Graph::new(0x6380);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b1);
        g.edge(&b1, &b2);
        g.graph.calc_loop();
        g.observe("self_loop_then_child", "direct:1", false);
    }

    // case=calc_loop_twice_loopout_skip
    {
        let mut g = Graph::new(0x63c0);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.graph.calc_loop();
        g.graph.calc_loop();
        g.observe("calc_loop_twice_loopout_skip", "direct:2", false);
    }

    // case=visited_truncate_no_label
    {
        let mut g = Graph::new(0x6400);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b3, &b1);
        g.graph.calc_loop();
        g.observe("visited_truncate_no_label", "direct:1", false);
    }

    // case=irreducible_endtoend_calcloop
    {
        let mut g = Graph::new(0x6440);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        let mut rootlist: Vec<BlockRef> = Vec::new();
        g.graph.structure_loops(&mut rootlist).expect("structure loops");
        g.observe("irreducible_endtoend_calcloop", "loops", true);
        g.observe_roots("irreducible_endtoend_calcloop", "loops", &rootlist);
    }

    // case=structure_reset_chain_dominator
    {
        let mut g = Graph::new(0x6480);
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
        let mut rootlist: Vec<BlockRef> = Vec::new();
        g.graph.structure_loops(&mut rootlist).expect("structure loops");
        g.graph.calc_forward_dominator(&rootlist).expect("forward dominator");
        g.observe("structure_reset_chain_dominator", "reset", true);
        g.observe_roots("structure_reset_chain_dominator", "reset", &rootlist);
    }
}
