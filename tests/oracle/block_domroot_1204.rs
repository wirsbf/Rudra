// HTTPD-ADDDESCEND-THROW-0001 fixture — Rust side.
//
// Mirrors tests/oracle/block_domroot_1204.cc line for line against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Exercises BlockGraph::structure_loops (block.cc:2194 -> findSpanningTree
// block.cc:1009-1136, the public 1:1 port that reorders the component list
// to reverse post order) followed by calc_forward_dominator
// (block.cc:1954-2032), plus the side-effect-free build_dom_tree entry
// (local-RPO path used by the non-reordering callers) asserted to produce
// the identical immediate-dominator set.
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, BlockGraph, FlowBlock};

type BlockArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct CaseGraph {
    graph: BlockGraph,
    blocks: Vec<BlockArc>,
    names: Vec<String>,
}

impl CaseGraph {
    fn add(&mut self, name: &str) -> BlockArc {
        // Mirrors the oracle fixture's graph.newBlock() + internal addBlock:
        // one plain block appended to the component vector.
        let bl: BlockArc = Arc::new(RwLock::new(BlockBasic::new(
            self.blocks.len() as i32,
            Address::new(0x1000 + (self.blocks.len() as u64) * 0x10),
        )));
        self.graph.add_block(bl.clone());
        self.blocks.push(bl.clone());
        self.names.push(name.to_string());
        bl
    }

    fn edge(&mut self, from: &BlockArc, to: &BlockArc) {
        self.graph.add_edge(from.clone(), to.clone());
    }

    fn label_of(&self, bl: &BlockArc) -> String {
        let ptr = Arc::as_ptr(bl) as *const () as usize;
        for (i, b) in self.blocks.iter().enumerate() {
            if Arc::as_ptr(b) as *const () as usize == ptr {
                return self.names[i].clone();
            }
        }
        "?".to_string()
    }
}

fn idom_label(cg: &CaseGraph, bl: &BlockArc) -> String {
    let dom = bl.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
    match dom {
        Some(d) => cg.label_of(&d),
        None => "NULL".to_string(),
    }
}

fn run_case(title: &str, mut cg: CaseGraph) {
    println!("{}", title);

    // Oracle chain: structureLoops(rootlist) + calcForwardDominator(rootlist).
    let mut rootlist: Vec<BlockArc> = Vec::new();
    cg.graph.structure_loops(&mut rootlist).expect("structure_loops");
    cg.graph
        .calc_forward_dominator(&rootlist)
        .expect("calc_forward_dominator");

    print!("rpo:");
    for i in 0..cg.graph.get_size() {
        let bl = cg.graph.get_block(i).expect("block");
        let idx = bl.read().unwrap().get_index();
        print!(" {}({})", cg.label_of(&bl), idx);
    }
    println!();

    print!("rootlist:");
    for r in &rootlist {
        print!(" {}", cg.label_of(r));
    }
    println!();

    for i in 0..cg.graph.get_size() {
        let bl = cg.graph.get_block(i).expect("block");
        println!("idom {}: {}", cg.label_of(&bl), idom_label(&cg, &bl));
    }
}

/// Build an identical fresh copy of the case (same vector order, same edge
/// insertion order) and run the non-reordering build_dom_tree entry,
/// asserting the immediate-dominator set matches the oracle chain's result
/// (this is the entry heritage/coreaction/blockaction glue callers use).
fn assert_build_dom_tree_matches(
    title: &str,
    edges: &[(usize, usize)],
    nblk: usize,
    expected: &[(usize, &str)], // (block ordinal, expected idom label or "NULL")
    name_of: &dyn Fn(usize) -> String,
) {
    let mut cg = CaseGraph {
        graph: BlockGraph::new(),
        blocks: Vec::new(),
        names: (0..nblk).map(|i| format!("B{}", i)).collect(),
    };
    for i in 0..nblk {
        let name = name_of(i);
        cg.names[i] = name;
        let bl: BlockArc = Arc::new(RwLock::new(BlockBasic::new(
            i as i32,
            Address::new(0x1000 + (i as u64) * 0x10),
        )));
        cg.graph.add_block(bl.clone());
        cg.blocks.push(bl);
    }
    for (f, t) in edges {
        let from = cg.blocks[*f].clone();
        let to = cg.blocks[*t].clone();
        cg.graph.add_edge(from, to);
    }
    cg.graph.build_dom_tree();

    let label_by_ptr: HashMap<usize, String> = cg
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (Arc::as_ptr(b) as *const () as usize, cg.names[i].clone()))
        .collect();
    let mut mismatches = Vec::new();
    for &(ordinal, expect) in expected {
        let bl = &cg.blocks[ordinal];
        let dom = bl.read().unwrap().get_immed_dom().and_then(|w| w.upgrade());
        let got = match dom {
            Some(d) => label_by_ptr
                .get(&(Arc::as_ptr(&d) as *const () as usize))
                .cloned()
                .unwrap_or_else(|| "?".to_string()),
            None => "NULL".to_string(),
        };
        if got != expect {
            mismatches.push(format!(
                "{}: idom({}) = {} expected {}",
                title, cg.names[ordinal], got, expect
            ));
        }
    }
    if !mismatches.is_empty() {
        panic!("build_dom_tree divergence: {:?}", mismatches);
    }
    // Silent on success: stdout stays byte-identical to the oracle fixture.
    // The parity coverage itself is registered in the metadata.
    let _ = title;
}

fn main() {
    {
        let mut cg = CaseGraph {
            graph: BlockGraph::new(),
            blocks: Vec::new(),
            names: Vec::new(),
        };
        let e = cg.add("E");
        let a = cg.add("A");
        let b = cg.add("B");
        cg.add("O1");
        cg.add("O2");
        cg.edge(&e, &a);
        cg.edge(&a, &b);
        run_case("case A: multi-root trailing orphans", cg);
    }
    {
        let mut cg = CaseGraph {
            graph: BlockGraph::new(),
            blocks: Vec::new(),
            names: Vec::new(),
        };
        let e = cg.add("E");
        let a = cg.add("A");
        let e2 = e.clone();
        cg.edge(&e, &a);
        cg.edge(&a, &e2);
        run_case("case B: single root with back-edge into entry", cg);
    }
    {
        // Edge insertion order fixes the in-edge order of M as [R0, R1],
        // which the "first processed predecessor" scan (block.cc:1995-1999)
        // reads.
        let mut cg = CaseGraph {
            graph: BlockGraph::new(),
            blocks: Vec::new(),
            names: Vec::new(),
        };
        let r0 = cg.add("R0");
        let m = cg.add("M");
        let x = cg.add("X");
        let r1 = cg.add("R1");
        cg.edge(&r0, &m);
        cg.edge(&r1, &m);
        cg.edge(&m, &x);
        run_case("case C: cross-root merge (virtual-root index alias)", cg);
    }
    {
        let mut cg = CaseGraph {
            graph: BlockGraph::new(),
            blocks: Vec::new(),
            names: Vec::new(),
        };
        let x = cg.add("X");
        let y = cg.add("Y");
        let x2 = x.clone();
        cg.edge(&x, &y);
        cg.edge(&y, &x2);
        run_case("case D: pure cycle, no root candidate", cg);
    }

    // Parity of the non-reordering entry against the same expectations.
    assert_build_dom_tree_matches(
        "case A",
        &[(0, 1), (1, 2)],
        5,
        &[(0, "NULL"), (1, "E"), (2, "A"), (3, "NULL"), (4, "NULL")],
        &|i| ["E", "A", "B", "O1", "O2"][i].to_string(),
    );
    assert_build_dom_tree_matches(
        "case B",
        &[(0, 1), (1, 0)],
        2,
        &[(0, "NULL"), (1, "E")],
        &|i| ["E", "A"][i].to_string(),
    );
    assert_build_dom_tree_matches(
        "case C",
        &[(0, 1), (3, 1), (1, 2)],
        4,
        &[(0, "NULL"), (1, "R0"), (2, "M"), (3, "NULL")],
        &|i| ["R0", "M", "X", "R1"][i].to_string(),
    );
    assert_build_dom_tree_matches(
        "case D",
        &[(0, 1), (1, 0)],
        2,
        &[(0, "NULL"), (1, "X")],
        &|i| ["X", "Y"][i].to_string(),
    );
}
