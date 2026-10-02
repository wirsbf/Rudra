//! BLOCKACTION-SCOPEBREAK-GOTOTYPE-0001: Rugra comparand for the locked
//! Ghidra 12.0.4 scopeBreak goto_type oracle (block.hh:88-91; block.cc:
//! 1270-1288 BlockGraph::scopeBreak, 2866-2874 BlockGoto::scopeBreak,
//! 2856-2864 BlockGoto::markUnstructured, 3075-3084 BlockIf::scopeBreak,
//! 3067-3073 BlockIf::markUnstructured, 3324-3330 BlockWhileDo::scopeBreak,
//! 3434-3439 BlockDoWhile::scopeBreak; blockaction.cc:2186-2197
//! ActionFinalStructure tail).
//!
//! Mirrors tests/oracle/blockstruct_scopebreak_gototype_1204.cc case for
//! case: the same synthetic graphs (BlockBasic leaves wrapped in BlockCopy,
//! the ActionBlockStructure buildCopy shape, blockaction.cc:2177) are built
//! through the production BlockGraph APIs, driven through
//! CollapseStructure::collapse_all (the production ruleBlockGoto path),
//! then the ActionFinalStructure tail runs — scope_break(-1,-1) THEN
//! mark_unstructured() — and every tree-resident BlockGoto or
//! goto_target-carrying BlockIf prints its observation line.
//!
//! Disproof record (why this fixture exists): the curl next_url
//! `goto X; X:` residual was hypothesised to be a missing scopeBreak
//! goto_type conversion. Case nested_two_level_goto is the next_url shape
//! (WhileDo nested in DoWhile, body jumps to the DoWhile exit): the oracle
//! KEEPS gototype=f_goto_goto there (only the innermost loop's exit is
//! converted, block.cc:2872/3082) and golden ghidra_curl_1204.c next_url
//! keeps `goto LAB_001050e7;` with the label after both loops. The
//! `goto X; X:` text defect was a printc label-anchoring bug instead
//! (GOTO-LABEL-UNPRINTED-0001 discovery ledger), fixed separately.
//!
//! Lines are sorted before printing: Rugra installs composites at the
//! consumed slot while the oracle appends to the parent list, so tree
//! ORDER is a registered normalization on both sides — the per-goto facts
//! (form, body/target node types, gototype, target front-leaf marking)
//! are order-free. Identity is deliberately reduced to node types: the
//! collapse creates fresh BlockCopy nodes whose indices differ between
//! the tree builders.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{
    BlockBasic, BlockGoto, BlockIf, BlockGraph, BlockType, FlowBlock, block_flags,
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
    /// BlockCopy nodes, so every tree path bottoms out at a copy and
    /// mark_unstructured's front-leaf marking (block.cc:1236 markCopyBlock)
    /// has a non-null front leaf. Edges live on the ORIGINAL basics;
    /// build_copy mirrors and rewires them copy-to-copy (block.rs
    /// build_copy = block.cc:1647-1698 buildCopy).
    fn make_block(&mut self) -> BlockRef {
        // Production basics carry unique indices (Funcdata bblock
        // creation); scopeBreak's curloopexit comparison and the loop
        // finder both read getIndex(), so fixture leaves mirror that.
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
        // then CollapseStructure::collapse_all (ruleBlockGoto wraps
        // goto-marked edges inside), then the ActionFinalStructure tail:
        // scopeBreak(-1,-1) first (blockaction.cc:2193), markUnstructured
        // second (cc:2194).
        self.graph.build_copy(&self.bblocks);
        // blockaction.cc's own entry state: structureLoops labels the
        // graph (spanning tree + loop/goto edge labels, block.cc:2197-
        // 2215) BEFORE CollapseStructure runs (the .cc comparand calls the
        // same pair; Rugra's collapse_all re-runs orderLoopBodies
        // internally on the labeled graph, mirroring collapseInternal).
        let mut rootlist: Vec<BlockRef> = Vec::new();
        if let Err(e) = self.graph.structure_loops(&mut rootlist) {
            eprintln!("structure_loops failed: {}", e);
        }
        let mut collapse =
            CollapseStructure::new(&mut self.graph, case_name);
        collapse.collapse_all();

        // ActionFinalStructure tail: scopeBreak (cc:2193), then the
        // gotoPrints transport (blockaction.rs:7254 — Rugra evaluates the
        // lazy cc:2881-2890 comparison tree-wide here), then
        // markUnstructured (cc:2194).
        self.graph.scope_break(-1, -1);
        self.graph.compute_goto_prints();
        self.graph.mark_unstructured();

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut total_goto = 0;
        for root in &toplist {
            let mut found = Vec::new();
            collect_gotos(root, &mut found, 0);
            for g in found {
                total_goto += 1;
                lines.push(observe(&g));
            }
        }
        lines.sort();
        println!("case {}", case_name);
        println!("gotos={}", total_goto);
        for l in lines {
            println!("{}", l);
        }
        println!("end");
    }
}

/// DFS collecting every tree-resident unstructured-branch carrier:
/// BlockGoto (t_goto) and BlockIf with a goto_target (newBlockIfGoto form).
fn collect_gotos(bl: &BlockRef, out: &mut Vec<BlockRef>, depth: usize) {
    if depth > 8 {
        return;
    }
    let bt = bl.read().unwrap().get_type();
    let is_carrier = match bt {
        BlockType::Goto => true,
        BlockType::If => bl
            .read()
            .unwrap()
            .as_any()
            .downcast_ref::<BlockIf>()
            .map(|i| i.goto_target.is_some())
            .unwrap_or(false),
        _ => false,
    };
    if is_carrier {
        out.push(bl.clone());
    }
    for child in BlockGraph::component_list_dyn(bl) {
        collect_gotos(&child, out, depth + 1);
    }
}

fn observe(bl: &BlockRef) -> String {
    let r = bl.read().unwrap();
    match r.get_type() {
        BlockType::Goto => {
            let bg = r.as_any().downcast_ref::<BlockGoto>().unwrap();
            let body_ty = bg
                .wrapped
                .as_ref()
                .map(|w| w.read().unwrap().get_type())
                .unwrap_or(BlockType::Plain);
            let (target_ty, targmark) = bg
                .target_dyn
                .as_ref()
                .map(target_facts)
                .unwrap_or(("none".to_string(), 0));
            format!(
                "blockgoto body={} target={} gototype={} targ_unstructured={}",
                type_name(body_ty),
                target_ty,
                bg.get_goto_type(),
                targmark
            )
        }
        BlockType::If => {
            let bi = r.as_any().downcast_ref::<BlockIf>().unwrap();
            let body_ty = bi.condition.read().unwrap().get_type();
            let (target_ty, targmark) =
                bi.goto_target.as_ref().map(target_facts).unwrap_or((
                    "none".to_string(),
                    0,
                ));
            format!(
                "ifgoto body={} target={} gototype={} targ_unstructured={}",
                type_name(body_ty),
                target_ty,
                bi.goto_type,
                targmark
            )
        }
        _ => "unknown".to_string(),
    }
}

/// Target node type name + front-leaf f_unstructured_targ bit (the leaf
/// markCopyBlock writes, block.cc:1236; Rugra's mark_unstructured marks the
/// same front leaf via mark_front_leaf).
fn target_facts(t: &BlockRef) -> (String, u32) {
    let tr = t.read().unwrap();
    let ty = type_name(tr.get_type()).to_string();
    drop(tr);
    let mark = front_leaf_flag(t);
    (ty, mark)
}

fn front_leaf_flag(t: &BlockRef) -> u32 {
    match rudra::block::front_leaf(t) {
        Some(leaf) => {
            let l = leaf.read().unwrap();
            if (l.get_flags() & block_flags::UNSTRUCTURED_TARG) != 0 {
                1
            } else {
                0
            }
        }
        None => 0,
    }
}

fn main() {
    // Case 1 "loop_exit_goto": WhileDo whose body block jumps to the loop's
    // own exit block. Expect ifgoto gototype=2 (f_break_goto), target
    // unmarked.
    {
        let mut g = Graph::new(0x1000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b4);
        g.edge(&b2, &b1);
        g.edge(&b2, &b4);
        g.run("loop_exit_goto");
    }
    // Case 2 "nested_two_level_goto" (the next_url shape): WhileDo nested
    // in a DoWhile; the WhileDo body jumps past BOTH loops to the DoWhile
    // exit. Expect ifgoto gototype=1 (f_goto_goto — NOT converted), target
    // MARKED f_unstructured_targ.
    {
        let mut g = Graph::new(0x6000);
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
        g.edge(&b2, &b5);
        g.edge(&b3, &b4);
        g.edge(&b4, &b1);
        g.edge(&b4, &b5);
        g.run("nested_two_level_goto");
    }
    // Case 3 "dowhile_body_goto": unconditional-branch goto out of a
    // DoWhile body to the DoWhile's exit. Expect gototype=2
    // (f_break_goto), target unmarked.
    {
        let mut g = Graph::new(0xb000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b1);
        g.edge(&b2, &b3);
        g.run("dowhile_body_goto");
    }
    // Case 4 "forward_exit_goto": a plain goto skipping over one block in a
    // straight-line region. The oracle structures it away entirely
    // (gotos=0); Rugra must match the count.
    {
        let mut g = Graph::new(0xf000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b4 = g.make_block();
        let b5 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b4);
        g.edge(&b2, &b4);
        g.edge(&b4, &b5);
        g.run("forward_exit_goto");
    }
}
