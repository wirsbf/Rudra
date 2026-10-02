// BLOCKSTRUCT-NORETURN-DEADREGION-0001: Rudra comparand for the locked
// Ghidra 12.0.4 CollapseStructure::collapseAll dead-region oracle
// (blockaction.cc:1877-1893). Mirrors tests/oracle/blockstruct_deadregion_
// 1204.cc case for case: the same synthetic graphs (halt sinks inside and
// after a loop body, the canary if-halt shape, a mid-function halt whose
// trailing region stays reachable through a second entry) are built through
// the production BlockGraph APIs (add_block/add_edge),
// CollapseStructure::collapse_all runs (the 5-step faithful path), and the
// post-run state prints in the shared observation format (top-level list,
// structure tree, per-vertex surviving out-edge labels / flip flag /
// listed flag).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{
    edge_flags as ef, block_flags as bf, BlockBasic, BlockGraph, BlockType, FlowBlock,
};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn flags_text(label: u32) -> String {
    let mut out = String::new();
    if label & ef::F_GOTO_EDGE != 0 { out.push('g'); }
    if label & ef::F_LOOP_EDGE != 0 { out.push('l'); }
    if label & ef::F_IRREDUCIBLE_EDGE != 0 { out.push('i'); }
    if label & ef::F_TREE_EDGE != 0 { out.push('t'); }
    if label & ef::F_BACK_EDGE != 0 { out.push('b'); }
    if out.is_empty() { out.push('-'); }
    out
}

// FlowBlock::typeToName (block.cc:671-703) — note t_if prints "properif".
fn type_name(bt: BlockType) -> &'static str {
    match bt {
        BlockType::Plain => "plain",
        BlockType::Basic => "basic",
        BlockType::Graph => "graph",
        BlockType::Copy => "copy",
        BlockType::Goto => "goto",
        BlockType::MultiGoto => "multigoto",
        BlockType::Condition => "cond",
        BlockType::List => "list",
        BlockType::If => "properif",
        BlockType::WhileDo => "whiledo",
        BlockType::DoWhile => "dowhile",
        BlockType::Switch => "switch",
        BlockType::InfLoop => "infloop",
    }
}

struct Graph {
    graph: BlockGraph,
    created: Vec<BlockRef>,
}

impl Graph {
    fn new() -> Self {
        Graph { graph: BlockGraph::new(), created: Vec::new() }
    }

    fn make_block(&mut self) -> BlockRef {
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            0,
            Address::new(0x1000),
        )));
        self.graph.add_block(bl.clone());
        self.created.push(bl.clone());
        bl
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.graph.add_edge(from.clone(), to.clone());
    }

    fn name_of(&self, bl: &BlockRef, toplist: &[BlockRef]) -> String {
        for (i, cand) in self.created.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("b{}", i);
            }
        }
        for (i, cand) in toplist.iter().enumerate() {
            if Arc::ptr_eq(cand, bl) {
                return format!("c{}", i);
            }
        }
        "b?".to_string()
    }

    fn dump_tree(&self, bl: &BlockRef, toplist: &[BlockRef], depth: usize) {
        let r = bl.read().unwrap();
        for _ in 0..depth {
            print!("  ");
        }
        print!("{}", type_name(r.get_type()));
        if r.get_type() == BlockType::If {
            if let Some(bif) = r.as_any().downcast_ref::<rudra::block::BlockIf>() {
                if bif.goto_target.is_some() {
                    // The C++ side prints the resolved target name; Rudra's
                    // BlockIf keeps the Arc, resolve via index scan.
                    let target = bif.goto_target.clone().unwrap();
                    print!(" gototarget={}", self.name_of(&target, toplist));
                }
            }
        }
        if r.get_flags() & bf::INTERIOR_GOTOOUT != 0 { print!(" gotoout=1"); }
        if r.get_flags() & bf::FLIP_PATH != 0 { print!(" flip=1"); }
        println!(" in={} out={}", r.size_in(), r.size_out());
        if r.get_type() == BlockType::Goto {
            return;
        }
        let children: Vec<BlockRef> = match r.get_type() {
            BlockType::List => r
                .as_any()
                .downcast_ref::<rudra::block::BlockList>()
                .map(|b| b.children.clone())
                .unwrap_or_default(),
            BlockType::If => {
                let mut v = Vec::new();
                if let Some(bi) = r.as_any().downcast_ref::<rudra::block::BlockIf>() {
                    v.push(bi.condition.clone());
                    v.push(bi.if_body.clone());
                    if let Some(ref eb) = bi.else_body {
                        v.push(eb.clone());
                    }
                }
                v
            }
            BlockType::WhileDo => r
                .as_any()
                .downcast_ref::<rudra::block::BlockWhileDo>()
                .map(|b| vec![b.condition.clone(), b.body.clone()])
                .unwrap_or_default(),
            BlockType::DoWhile => r
                .as_any()
                .downcast_ref::<rudra::block::BlockDoWhile>()
                .map(|b| vec![b.condition.clone()])
                .unwrap_or_default(),
            BlockType::Condition => r
                .as_any()
                .downcast_ref::<rudra::block::BlockCondition>()
                .map(|b| vec![b.first.clone(), b.second.clone()])
                .unwrap_or_default(),
            BlockType::InfLoop => r
                .as_any()
                .downcast_ref::<rudra::block::BlockInfLoop>()
                .map(|b| vec![b.body.clone()])
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        drop(r);
        for child in children {
            self.dump_tree(&child, toplist, depth + 1);
        }
    }

    fn run(&mut self, case_name: &str) {
        // CollapseStructure::collapseAll via the public 5-step driver; the
        // entry state (structure_loops labels) is established inside
        // order_loop_bodies exactly as the oracle's run() does via
        // structureLoops.
        let mut collapse = rudra::blockaction::CollapseStructure::new(
            &mut self.graph,
            case_name,
        );
        collapse.collapse_all();

        // ---- observation (mirrors the C++ fixture byte for byte) ----
        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        println!("case {}", case_name);
        print!("list=");
        for (i, bl) in toplist.iter().enumerate() {
            if i != 0 { print!(","); }
            let bt = bl.read().unwrap().get_type();
            print!("c{}({})", i, type_name(bt));
        }
        println!();
        for bl in toplist.iter() {
            self.dump_tree(bl, &toplist, 0);
        }
        for (i, bl) in self.created.iter().enumerate() {
            let r = bl.read().unwrap();
            let listed = toplist.iter().any(|t| Arc::ptr_eq(t, bl));
            print!("b{} listed={} out=[", i, if listed { 1 } else { 0 });
            for j in 0..r.size_out() {
                if j != 0 { print!(" "); }
                let label = r.get_out(j).map(|e| e.flags).unwrap_or(0);
                print!("{}:{}", j, flags_text(label));
            }
            println!("] flip={}", if r.get_flags() & bf::FLIP_PATH != 0 { 1 } else { 0 });
        }
        println!("end");
    }
}

fn main() {
    {
        // 1. noret_halt_loop_body: the E2E glob_word 19-block topology.
        let mut g = Graph::new();
        let mut b: Vec<BlockRef> = Vec::new();
        for _ in 0..19 {
            b.push(g.make_block());
        }
        let edges: [(usize, usize); 23] = [
            (0, 11), (0, 1),
            (1, 2), (1, 12),
            (2, 4), (2, 3),
            (3, 8),
            (4, 6), (4, 5),
            (5, 10),
            (6, 9), (6, 7),
            (7, 8),
            (9, 10),
            (10, 1), (10, 12),
            (11, 12),
            (12, 14), (12, 13),
            (14, 16), (14, 15),
            (16, 18), (16, 17),
        ];
        for (from, to) in edges {
            g.edge(&b[from], &b[to]);
        }
        g.run("noret_halt_loop_body");
    }
    {
        // 2. canary_if_halt
        let mut g = Graph::new();
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.run("canary_if_halt");
    }
    {
        // 3. partial_reachable_after_halt
        let mut g = Graph::new();
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b4);
        g.edge(&b4, &b2);
        g.edge(&b2, &b3);
        g.run("partial_reachable_after_halt");
    }
}
