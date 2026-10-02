// BLOCKACTION-DOWHILE-ABSORB-0001: Rudra comparand for the locked Ghidra
// 12.0.4 CollapseStructure::collapseAll oracle (blockaction.cc:1877-1893).
// Mirrors tests/oracle/blockstruct_dowhile_absorb_1204.cc case for case:
// the same synthetic graphs are built through the production BlockGraph
// APIs (add_block/add_edge), CollapseStructure::collapse_all runs (the
// 5-step faithful path), and the post-run state prints in the shared
// observation format (top-level list, structure tree, per-vertex
// surviving out-edge labels / flip flag / listed flag).
//
// The covered semantic is the newBlockList force step (block.cc:1758-1774):
// forceOutputNum(outforce) resurrects a chain-internal back-edge as a
// composite SELF edge (f_loop_edge|f_back_edge, block.cc:880-889) so
// ruleBlockDoWhile (cc:1555) can absorb the latch, and forceFalseEdge
// (block.cc:1204-1217) preserves the false branch (out0 internal -> self).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{
    edge_flags as ef, block_flags as bf, BlockBasic, BlockCondition, BlockDoWhile, BlockGraph,
    BlockIf, BlockInfLoop, BlockList, BlockType, BlockWhileDo, FlowBlock,
};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn flags_text(label: u32) -> String {
    let mut out = String::new();
    if label & ef::F_GOTO_EDGE != 0 { out.push('g'); }
    if label & ef::F_LOOP_EDGE != 0 { out.push('l'); }
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

// FlowBlock::typeToName (block.cc:671-703) — note t_if prints "properif".
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
        // Unique index AND address per block: Rudra's collapse model keys
        // block identity on FlowBlock::get_index() (Ghidra uses parent
        // pointers), and loop discovery keys on addresses — all-zero
        // indices/addresses make every self-loop test vacuously true.
        let idx = self.created.len() as i32;
        let bl: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            idx,
            Address::new(self.base + (idx as u64) * 0x10),
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

    fn run(&mut self, case_name: &str) {
        // ActionBlockStructure entry state (cc:2177-2180): the structure
        // copy inherits spanning-tree/back-edge labels; reproduce by
        // running structure_loops on the graph first, exactly as the C++
        // fixture's run() does via structureLoops + clearVisitCount.
        let mut rootlist: Vec<BlockRef> = Vec::new();
        let _ = self.graph.structure_loops(&mut rootlist);
        // clearVisitCount (cc:2181) is folded into order_loop_bodies on the
        // Rudra side (see collapse_all_5step cc:1879-1884 note).

        // CollapseStructure::collapseAll via the public 5-step driver.
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
        for (i, bl) in toplist.iter().enumerate() {
            let r = bl.read().unwrap();
            print!(
                "c{} type={} gotoout={} out=[",
                i,
                type_name(r.get_type()),
                if r.get_flags() & bf::INTERIOR_GOTOOUT != 0 { 1 } else { 0 }
            );
            for j in 0..r.size_out() {
                if j != 0 { print!(" "); }
                let label = r.get_out(j).map(|e| e.flags).unwrap_or(0);
                let target = r.get_out(j).map(|e| e.point.clone());
                let tname = match target {
                    Some(t) => self.name_of(&t, &toplist),
                    None => "b?".to_string(),
                };
                print!("{}:{}->{}", j, flags_text(label), tname);
            }
            println!("]");
            drop(r);
            println!("tree c{}:", i);
            self.dump_tree(bl, &toplist, 1);
        }
        for (i, bl) in self.created.iter().enumerate() {
            let r = bl.read().unwrap();
            print!("b{} out=[", i);
            for j in 0..r.size_out() {
                if j != 0 { print!(" "); }
                let label = r.get_out(j).map(|e| e.flags).unwrap_or(0);
                print!("{}:{}", j, flags_text(label));
            }
            println!(
                "] flip={} listed={}",
                if r.get_flags() & bf::FLIP_PATH != 0 { 1 } else { 0 },
                if toplist.iter().any(|t| Arc::ptr_eq(t, bl)) { 1 } else { 0 }
            );
        }
        println!("end");
    }

    // Recursive structure-tree projection mirroring the C++ dumpTree: child
    // order is the factory node order. BlockGoto children are NOT dumped
    // (Rudra's newBlockGoto wraps in place — documented normalization on
    // both sides).
    fn dump_tree(&self, bl: &BlockRef, toplist: &[BlockRef], depth: usize) {
        let r = bl.read().unwrap();
        for _ in 0..depth { print!("  "); }
        print!("{}", type_name(r.get_type()));
        let (bt, flags) = (r.get_type(), r.get_flags());
        if bt == BlockType::If {
            if let Some(bi) = r.as_any().downcast_ref::<BlockIf>() {
                if let Some(ref gt) = bi.goto_target {
                    print!(" gototarget={}", self.name_of(gt, toplist));
                }
            }
        }
        if flags & bf::INTERIOR_GOTOOUT != 0 { print!(" gotoout=1"); }
        if flags & bf::FLIP_PATH != 0 { print!(" flip=1"); }
        println!();
        if bt == BlockType::Goto {
            return;
        }
        let children: Vec<BlockRef> = match bt {
            BlockType::List => r
                .as_any()
                .downcast_ref::<BlockList>()
                .map(|b| b.children.clone())
                .unwrap_or_default(),
            BlockType::If => {
                let mut v = Vec::new();
                if let Some(bi) = r.as_any().downcast_ref::<BlockIf>() {
                    v.push(bi.condition.clone());
                    // IfGoto normalization: newBlockIfGoto (block.cc:1799-
                    // 1816) installs ONLY the condition in the composite
                    // (nodes={cond}); the body stays external as the single
                    // structured out-edge. Rudra's BlockIf keeps a
                    // non-Option if_body placeholder (= the condition
                    // itself) for the if-goto wrap — do not dump it (same
                    // spirit as the BlockGoto children normalization).
                    if bi.goto_target.is_none() {
                        v.push(bi.if_body.clone());
                        if let Some(ref eb) = bi.else_body {
                            v.push(eb.clone());
                        }
                    }
                }
                v
            }
            BlockType::WhileDo => r
                .as_any()
                .downcast_ref::<BlockWhileDo>()
                .map(|b| vec![b.condition.clone(), b.body.clone()])
                .unwrap_or_default(),
            BlockType::DoWhile => r
                .as_any()
                .downcast_ref::<BlockDoWhile>()
                .map(|b| vec![b.condition.clone()])
                .unwrap_or_default(),
            BlockType::Condition => r
                .as_any()
                .downcast_ref::<BlockCondition>()
                .map(|b| vec![b.first.clone(), b.second.clone()])
                .unwrap_or_default(),
            BlockType::InfLoop => r
                .as_any()
                .downcast_ref::<BlockInfLoop>()
                .map(|b| vec![b.body.clone()])
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        drop(r);
        for child in children {
            self.dump_tree(&child, toplist, depth + 1);
        }
    }
}

fn main() {
    // Optional argv[1] filter: run a single named case (debug convenience).
    let filter = std::env::args().nth(1);
    macro_rules! case {
        ($name:expr, $body:block) => {
            if filter.is_none() || filter.as_deref() == Some($name) $body
        };
    }
    case!("latch_pair_goto_dowhile", {
        // 1. latch_pair_goto_dowhile — the main @321a topology: head exits
        // to body + shared target, latch exits to target + back to head.
        let mut g = Graph::new(0x1000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b2, &b1);
        g.run("latch_pair_goto_dowhile");
    });
    case!("chain_tail_backedge_dowhile", {
        // 2. chain_tail_backedge_dowhile — no goto: straight chain whose
        // tail branches back into the chain; cat + forceOutputNum + dowhile.
        let mut g = Graph::new(0x2000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b1, &b2);
        g.edge(&b2, &b3);
        g.edge(&b2, &b1);
        g.run("chain_tail_backedge_dowhile");
    });
    case!("tail_out0_internal_flip", {
        // 3. tail_out0_internal_flip — tail's out(0) points back INTO the
        // chain: forceFalseEdge's parent==this arm + slot-0 dowhile negate.
        let mut g = Graph::new(0x3000);
        let b0 = g.make_block();
        let b1 = g.make_block();
        let b2 = g.make_block();
        let b3 = g.make_block();
        let b9 = g.make_block();
        g.edge(&b0, &b1);
        g.edge(&b0, &b9);
        g.edge(&b1, &b2);
        g.edge(&b2, &b1);
        g.edge(&b2, &b3);
        g.run("tail_out0_internal_flip");
    });
}
