// MAIN-RC2-BLOCKGOTO-WRAPPED-0001: Rudra comparand for the locked Ghidra
// 12.0.4 BlockGoto lifecycle oracle (block.hh:547-565, block.cc:1702-1713
// newBlockGoto / 2856-2916 markUnstructured+scopeBreak+gotoPrints). Mirrors
// tests/oracle/blockstruct_blockgoto_wrapped_1204.cc case for case: the same
// synthetic graphs are built through the production BlockGraph APIs, driven
// through CollapseStructure::collapse_all (the production ruleBlockGoto
// path), then the ActionFinalStructure tail (scopeBreak(-1,-1) +
// [Rudra-only transport] compute_goto_prints) runs, and every tree-resident
// BlockGoto prints its observation line. Lines are sorted before printing:
// Rudra installs composites at the consumed slot while the oracle appends to
// the parent list (block.cc:953-960 + cc:874), so top-level ORDER is a
// registered normalization on both sides — the per-goto facts (wrapped
// component identity/type, gototarget index/type, gototype, gotoPrints,
// out-degree) are order-free.
//
// Synthetic leaves are BlockBasic on this side and `Vertex : FlowBlock`
// (t_basic) on the oracle side; both getFrontLeaf implementations return
// null/None for a basic leaf (block.cc:344-348 loop needs t_copy), so the
// gotoPrints observation on these graphs exercises the comparison plumbing
// with the same null-degeneracy on both sides (documented normalization).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, BlockGoto, BlockGraph, BlockType, FlowBlock};

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
    graph: BlockGraph,
    created: Vec<BlockRef>,
    base: u64,
}

impl Graph {
    fn new(base: u64) -> Self {
        Graph { graph: BlockGraph::new(), created: Vec::new(), base }
    }

    fn make_block(&mut self) -> BlockRef {
        // Index 0 for every vertex, mirroring the oracle's FlowBlock ctor
        // (block.cc:61-67: index = 0) — the goto_cascade fixture's scheme.
        // Identity in observations comes from name labels, not indexes.
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            0,
            Address::new(self.base + (self.created.len() as u64) * 0x10),
        )));
        self.graph.add_block(bl.clone());
        self.created.push(bl.clone());
        bl
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.graph.add_edge(from.clone(), to.clone());
    }

    /// Index-identity label for any block: creation id for synthetic
    /// vertices (bN), top-level slot for composites (cN) — mirrors the C++
    /// nameOf. Composites carry the min component index (identifyInternal
    /// addBlock min rule / the Rust install-slot index), so `index=` is the
    /// order-free identity observation.
    fn label_of(&self, bl: &BlockRef, toplist: &[BlockRef]) -> String {
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
        format!("t{}", bl.read().unwrap().get_index())
    }

    fn run(&mut self, case_name: &str) {
        // Production rule path: the same entry state as the goto_cascade
        // fixture (structure_loops labels), then collapse_all —
        // ruleBlockGoto fires inside, wrapping goto-marked single-out
        // blocks in BlockGoto.
        let mut collapse =
            rudra::blockaction::CollapseStructure::new(&mut self.graph, case_name);
        collapse.collapse_all();

        // ActionFinalStructure tail (blockaction.cc:2193): scopeBreak first;
        // Rudra then evaluates the gotoPrints comparison tree-wide (the
        // oracle computes it lazily per gotoPrints() call below).
        self.graph.scope_break(-1, -1);
        self.graph.compute_goto_prints();

        let toplist: Vec<BlockRef> = self.graph.blocks.clone();
        let mut lines: Vec<String> = Vec::new();
        let mut total_goto = 0;
        for root in &toplist {
            let mut found = Vec::new();
            collect_gotos(root, &mut found, 0);
            for g in found {
                total_goto += 1;
                lines.push(self.observe(&g, &toplist));
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

    fn observe(&self, g: &BlockRef, toplist: &[BlockRef]) -> String {
        let r = g.read().unwrap();
        let bg = r.as_any().downcast_ref::<BlockGoto>().unwrap();
        // block.cc:1705-1708: gototarget captured pre-removeEdge; the
        // wrapped block is the single list component (getBlock(0)).
        let wrapped_name = bg
            .wrapped
            .as_ref()
            .map(|w| {
                let wr = w.read().unwrap();
                format!("{}:{}", self.label_of(w, toplist), type_name(wr.get_type()))
            })
            .unwrap_or_else(|| "none".to_string());
        let target_name = bg
            .target_dyn
            .as_ref()
            .map(|t| {
                let tr = t.read().unwrap();
                format!("{}:{}", self.label_of(t, toplist), type_name(tr.get_type()))
            })
            .unwrap_or_else(|| "none".to_string());
        format!(
            "goto idx={} sizein={} sizeout={} wrapped={} target={} gototype={} prints={}",
            r.get_index(),
            r.size_in(),
            r.size_out(),
            wrapped_name,
            target_name,
            bg.get_goto_type(),
            if bg.goto_prints() { 1 } else { 0 }
        )
    }
}

/// DFS collecting every tree-resident BlockGoto (depth-capped like the C++
/// dumpTree walk; synthetic trees are shallow).
fn collect_gotos(bl: &BlockRef, out: &mut Vec<BlockRef>, depth: usize) {
    if depth > 8 {
        return;
    }
    if bl.read().unwrap().get_type() == BlockType::Goto {
        out.push(bl.clone());
    }
    for child in rudra::block::BlockGraph::component_list_dyn(bl) {
        collect_gotos(&child, out, depth + 1);
    }
}

fn main() {
    // Case 1 (probe shape "D_double_back"): b0→b1→b2→{b0,b3}, b3→b1 —
    // the oracle leaves one pure BlockGoto (wrapped = the b3 basic,
    // gototarget = b0, TGTIDX per the probe run).
    {
        let mut g = Graph::new(0x1000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b0);
        g.edge(&b2, &b3);
        g.edge(&b3, &b1);
        g.run("double_back_goto");
    }
    // Case 2 (probe shape "E_loop_exit_conflict"): b0→b1, b1→{b2,b3},
    // b2→{b1,b4}, b3→b4, b4→b1 — the oracle leaves TWO BlockGotos, one
    // wrapping a properif composite and one wrapping a list composite
    // (locks composite wrapping, not just basic leaves).
    {
        let mut g = Graph::new(0x6000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b4 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b1);
        g.edge(&b2, &b4);
        g.edge(&b3, &b4);
        g.edge(&b4, &b1);
        g.run("loop_exit_conflict_gotos");
    }
}
