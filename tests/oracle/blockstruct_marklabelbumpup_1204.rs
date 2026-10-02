//! BLOCKSTRUCT-MARKLABELBUMPUP-0001: Rudra comparand for the locked
//! Ghidra 12.0.4 markLabelBumpUp oracle (block.cc:1258-1268
//! BlockGraph::markLabelBumpUp; loop overrides block.cc:3316-3322 /
//! 3426-3432 / 3454-3460; call site blockaction.cc:2195
//! `graph.markLabelBumpUp(false)` — the ActionFinalStructure fifth graph
//! call).
//!
//! Mirrors tests/oracle/blockstruct_marklabelbumpup_1204.cc case for
//! case: the same synthetic graphs (BlockBasic leaves snapshotted into
//! BlockCopy nodes by build_copy — the ActionBlockStructure production
//! shape, blockaction.cc:2177) are structured through the production
//! CollapseStructure::collapse_all, the reduced ActionFinalStructure tail
//! runs (scope_break(-1,-1) then mark_unstructured, cc:2193-2194), then
//! `mark_label_bump_up(false)` — the call under test — projects the
//! f_label_bumpup flag lattice over the whole tree.
//!
//! Observation lines are sorted before printing (both sides): the two
//! collapse implementations install composites at different list slots
//! (registered normalization, same scheme as the scopebreak fixture);
//! the per-node (type, bump, kids) facts are order-free.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{
    BlockBasic, BlockGraph, BlockType, FlowBlock, block_flags,
};
use rudra::blockaction::CollapseStructure;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn type_name(bt: BlockType) -> &'static str {
    match bt {
        BlockType::Plain => "plain",
        BlockType::Basic => "basic",
        BlockType::Graph => "graph",
        BlockType::Copy => "copy",
        BlockType::Goto => "goto",
        BlockType::MultiGoto => "multigoto",
        BlockType::List => "list",
        BlockType::Condition => "condition",
        BlockType::If => "properif",
        BlockType::WhileDo => "whiledo",
        BlockType::DoWhile => "dowhile",
        BlockType::Switch => "switch",
        BlockType::InfLoop => "infloop",
    }
}

struct Graph {
    /// The basic-block graph (ActionBlockStructure's input,
    /// blockaction.cc:2177 `data.getBasicBlocks()`).
    bblocks: BlockGraph,
    /// The structure graph the collapse runs on (`data.getStructure()`).
    graph: BlockGraph,
    base: u64,
    made: u64,
}

impl Graph {
    fn new(base: u64) -> Self {
        Graph { bblocks: BlockGraph::new(), graph: BlockGraph::new(), base, made: 0 }
    }

    /// Production shape: ActionBlockStructure's buildCopy
    /// (blockaction.cc:2177) snapshots the basic-block graph into
    /// BlockCopy nodes, so every tree path bottoms out at a copy.
    fn make_block(&mut self) -> BlockRef {
        let leaf: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            self.made as i32,
            Address::new(self.base + self.made * 0x10),
        )));
        self.made += 1;
        self.bblocks.add_block(leaf.clone());
        leaf
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.bblocks.add_edge(from.clone(), to.clone());
    }

    fn run(&mut self, case_name: &str) {
        // Production rule path: buildCopy snapshot (blockaction.cc:2177)
        // then CollapseStructure::collapse_all, then the reduced
        // ActionFinalStructure tail (cc:2193-2195): scopeBreak,
        // markUnstructured, and the call under test markLabelBumpUp(false).
        self.graph.build_copy(&self.bblocks);
        let mut rootlist: Vec<BlockRef> = Vec::new();
        if let Err(e) = self.graph.structure_loops(&mut rootlist) {
            eprintln!("structure_loops failed: {}", e);
        }
        let mut collapse =
            CollapseStructure::new(&mut self.graph, case_name);
        collapse.collapse_all();

        self.graph.scope_break(-1, -1);
        self.graph.compute_goto_prints();
        self.graph.mark_unstructured();
        // blockaction.cc:2195: graph.markLabelBumpUp(false); // Fix up
        // labeling — the call under test.
        self.graph.mark_label_bump_up(false);

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        for root in &toplist {
            collect(root, &mut lines, 0);
        }
        lines.sort();
        println!("case {}", case_name);
        println!("roots={}", toplist.len());
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }
}

/// DFS over the structured tree emitting one `type=<t> bump=<0|1> kids=<n>`
/// line per node (kids = component-list size; copies/basics have 0).
fn collect(bl: &BlockRef, out: &mut Vec<String>, depth: usize) {
    if depth > 8 {
        return;
    }
    let r = bl.read().unwrap();
    let kids = BlockGraph::component_list_dyn(bl).len();
    let bump = if r.get_flags() & block_flags::LABEL_BUMPUP != 0 { 1 } else { 0 };
    out.push(format!(
        "type={} bump={} kids={}",
        type_name(r.get_type()),
        bump,
        kids
    ));
    for child in BlockGraph::component_list_dyn(bl) {
        collect(&child, out, depth + 1);
    }
}

fn main() {
    // Case 1: plain while-do. b1 is the condition, b2 the body, b3 the exit.
    //   b0 -> b1 ; b1 -> b2 (true) ; b1 -> b3 (false) ; b2 -> b1 (back)
    {
        let mut g = Graph::new(0x1000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b1);
        g.run("whiledo_simple");
    }
    // Case 2: plain do-while. b1 the body, b2 the bottom, b3 the exit.
    //   b0 -> b1 ; b1 -> b2 ; b2 -> b1 (back) ; b2 -> b3 (exit)
    {
        let mut g = Graph::new(0x2000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.edge(&b2, &b3);
        g.run("dowhile_simple");
    }
    // Case 3: infinite loop. b1's only out edge returns to itself.
    //   b0 -> b1 ; b1 -> b1 (back, no exit)
    {
        let mut g = Graph::new(0x3000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b1);
        g.run("infloop_simple");
    }
    // Case 4: WhileDo at the FRONT of a DoWhile body (the next_url shape
    // without the unstructured edge). The dowhile forces `true` down its
    // single body component; the body's first child (the whiledo) receives
    // `true` through the list and KEEPS its own flag.
    //   b0 -> b1 (while cond) ; b1 -> b2 (body) ; b1 -> b3 (while exit)
    //   b2 -> b1 (back) ; b3 -> b4 (do bottom) ; b4 -> b1 (do back)
    //   b4 -> b5 (exit)
    {
        let mut g = Graph::new(0x4000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        let b5 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b1);
        g.edge(&b3, &b4);
        g.edge(&b4, &b1);
        g.edge(&b4, &b5);
        g.run("nested_loops_front");
    }
    // Case 5: straight line, no loops — control: nothing flagged.
    //   b0 -> b1 -> b2
    {
        let mut g = Graph::new(0x5000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.run("straight_line");
    }
}
