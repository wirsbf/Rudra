// BLOCK-STRUCTURED-NEGATE-0001: Rugra comparand for the locked Ghidra
// 12.0.4 FlowBlock/BlockList/BlockCondition negateCondition fixture.
//
// This mirrors block_structured_negate_1204.cc case-for-case and emits the
// same complete raw state.  Fixed construction names are the only pointer
// normalization; edge order, both half-edge labels/reverse indices, raw block
// flags, boolean opcode, child dispatch arguments, and returns are preserved.

use std::sync::{Arc, RwLock};

use rudra::block::{
    block_flags as bf, edge_flags as ef, set_out_edge_flag_mirrored, BlockCondition, BlockEdge,
    BlockGraph, BlockList, BlockType, BoolOp, FlowBlock,
};
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
    // No negate_condition override: flow/self/parallel cases exercise the
    // production FlowBlock trait default corresponding to block.cc:294.
}

#[derive(Debug)]
struct FixedProbe {
    index: i32,
    flags: u32,
    incoming: Vec<BlockEdge>,
    outgoing: Vec<BlockEdge>,
    fixed_return: bool,
    calls: Vec<bool>,
}

impl FixedProbe {
    fn new(fixed_return: bool) -> Self {
        Self {
            index: 0,
            flags: 0,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            fixed_return,
            calls: Vec::new(),
        }
    }
}

impl FlowBlock for FixedProbe {
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

    fn negate_condition(&mut self, toporbottom: bool) -> bool {
        self.calls.push(toporbottom);
        self.fixed_return
    }
}

fn base_probe() -> BlockRef {
    Arc::new(RwLock::new(BaseProbe::new()))
}

fn fixed_probe(fixed_return: bool) -> BlockRef {
    Arc::new(RwLock::new(FixedProbe::new(fixed_return)))
}

fn wire(from: &BlockRef, to: &BlockRef, label: u32) {
    // BlockGraph::add_edge mirrors FlowBlock::addInEdge's append ordering and
    // reciprocal slot assignment, including self/parallel edges.
    let mut graph = BlockGraph::new();
    graph.add_edge(from.clone(), to.clone());
    let slot = from.read().unwrap().size_out() - 1;
    set_out_edge_flag_mirrored(from, slot, label);
}

fn name_of(block: &BlockRef, nodes: &[(&str, BlockRef)]) -> String {
    for (name, candidate) in nodes {
        if Arc::ptr_eq(block, candidate) {
            return (*name).to_string();
        }
    }
    "?".to_string()
}

fn calls_of(block: &BlockRef) -> String {
    let guard = block.read().unwrap();
    let Some(probe) = guard.as_any().downcast_ref::<FixedProbe>() else {
        return "-".to_string();
    };
    let calls = probe
        .calls
        .iter()
        .map(|call| if *call { "T" } else { "F" })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{calls}]")
}

fn opcode_of(block: &BlockRef) -> String {
    let guard = block.read().unwrap();
    let Some(condition) = guard.as_any().downcast_ref::<BlockCondition>() else {
        return "-".to_string();
    };
    match condition.op_type {
        BoolOp::And => "39:and".to_string(),
        BoolOp::Or => "40:or".to_string(),
    }
}

fn bool_results(results: &[bool]) -> String {
    let values = results
        .iter()
        .map(|result| if *result { "T" } else { "F" })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn observe(case_name: &str, top: &BlockRef, nodes: &[(&str, BlockRef)], results: &[bool]) {
    let node_text = nodes
        .iter()
        .map(|(name, block)| {
            format!(
                "{}:flags=0x{:08x},calls={}",
                name,
                block.read().unwrap().get_flags(),
                calls_of(block),
            )
        })
        .collect::<Vec<_>>()
        .join(";");

    let mut outgoing = Vec::new();
    for (name, block) in nodes {
        let edges = {
            let guard = block.read().unwrap();
            (0..guard.size_out())
                .filter_map(|slot| guard.get_out(slot).map(|edge| (slot, edge)))
                .collect::<Vec<_>>()
        };
        for (slot, edge) in edges {
            outgoing.push(format!(
                "{}!{}>{}:label=0x{:08x},rev={}",
                name,
                slot,
                name_of(&edge.point, nodes),
                edge.flags,
                edge.reverse_index,
            ));
        }
    }

    let mut incoming = Vec::new();
    for (name, block) in nodes {
        let edges = {
            let guard = block.read().unwrap();
            (0..guard.size_in())
                .filter_map(|slot| guard.get_in(slot).map(|edge| (slot, edge)))
                .collect::<Vec<_>>()
        };
        for (slot, edge) in edges {
            incoming.push(format!(
                "{}@{}<{}:label=0x{:08x},rev={}",
                name,
                slot,
                name_of(&edge.point, nodes),
                edge.flags,
                edge.reverse_index,
            ));
        }
    }

    println!(
        "case={}|result={}|top={}|op={}|nodes=[{}]|out=[{}]|in=[{}]",
        case_name,
        bool_results(results),
        name_of(top, nodes),
        opcode_of(top),
        node_text,
        outgoing.join(";"),
        incoming.join(";"),
    );
}

fn run_flow(case_name: &str, toporbottom: bool, count: usize) {
    let top = base_probe();
    let false_target = base_probe();
    let true_target = base_probe();
    top.write().unwrap().set_flags(bf::MARK | bf::LABEL_BUMPUP);
    wire(&top, &false_target, ef::F_GOTO_EDGE | ef::F_TREE_EDGE);
    wire(&top, &true_target, ef::F_CROSS_EDGE | ef::F_LOOP_EXIT_EDGE);
    let results = (0..count)
        .map(|_| top.write().unwrap().negate_condition(toporbottom))
        .collect::<Vec<_>>();
    observe(
        case_name,
        &top,
        &[
            ("top", top.clone()),
            ("f", false_target),
            ("t", true_target),
        ],
        &results,
    );
}

fn run_parallel() {
    let top = base_probe();
    let target = base_probe();
    top.write().unwrap().set_flags(bf::MARK);
    wire(&top, &target, ef::F_GOTO_EDGE);
    wire(&top, &target, ef::F_LOOP_EXIT_EDGE);
    let result = top.write().unwrap().negate_condition(true);
    observe(
        "flow_parallel_true",
        &top,
        &[("top", top.clone()), ("p", target)],
        &[result],
    );
}

fn run_self() {
    let top = base_probe();
    top.write().unwrap().set_flags(bf::MARK);
    wire(&top, &top, ef::F_LOOP_EDGE);
    wire(&top, &top, ef::F_IRREDUCIBLE_EDGE);
    let result = top.write().unwrap().negate_condition(true);
    observe("flow_self_true", &top, &[("top", top.clone())], &[result]);
}

fn run_list(case_name: &str, toporbottom: bool, count: usize, child_return: bool) {
    let first = fixed_probe(false);
    let last = fixed_probe(child_return);
    let false_target = base_probe();
    let true_target = base_probe();
    let list: BlockRef = Arc::new(RwLock::new(BlockList::new(
        0,
        vec![first.clone(), last.clone()],
    )));
    list.write().unwrap().set_flags(bf::MARK | bf::LABEL_BUMPUP);
    wire(&list, &false_target, ef::F_DEFAULTSWITCH_EDGE);
    wire(&list, &true_target, ef::F_BACK_EDGE | ef::F_LOOP_EXIT_EDGE);
    let results = (0..count)
        .map(|_| list.write().unwrap().negate_condition(toporbottom))
        .collect::<Vec<_>>();
    observe(
        case_name,
        &list,
        &[
            ("list", list.clone()),
            ("c0", first),
            ("c1", last),
            ("f", false_target),
            ("t", true_target),
        ],
        &results,
    );
}

fn run_condition(
    case_name: &str,
    opcode: BoolOp,
    toporbottom: bool,
    count: usize,
    first_return: bool,
    second_return: bool,
) {
    let first = fixed_probe(first_return);
    let second = fixed_probe(second_return);
    let false_target = base_probe();
    let true_target = base_probe();
    let condition: BlockRef = Arc::new(RwLock::new(BlockCondition {
        index: 0,
        op_type: opcode,
        first: first.clone(),
        second: second.clone(),
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));
    condition
        .write()
        .unwrap()
        .set_flags(bf::MARK | bf::LABEL_BUMPUP);
    wire(&condition, &false_target, ef::F_FORWARD_EDGE);
    wire(
        &condition,
        &true_target,
        ef::F_GOTO_EDGE | ef::F_LOOP_EXIT_EDGE,
    );
    let results = (0..count)
        .map(|_| condition.write().unwrap().negate_condition(toporbottom))
        .collect::<Vec<_>>();
    observe(
        case_name,
        &condition,
        &[
            ("cond", condition.clone()),
            ("c0", first),
            ("c1", second),
            ("f", false_target),
            ("t", true_target),
        ],
        &results,
    );
}

fn run_collapse_cat_counter() {
    let mut graph = BlockGraph::new();
    graph.index = 0;
    let first = base_probe();
    let second = base_probe();
    let third = base_probe();
    first.write().unwrap().set_index(0);
    second.write().unwrap().set_index(1);
    third.write().unwrap().set_index(2);
    // Match the C++ fixture's direct ordered ownership: parent remains null
    // in the isolated initial graph; production factories establish their
    // own containment during collapse.
    graph.blocks.push(first.clone());
    graph.blocks.push(second.clone());
    graph.blocks.push(third.clone());
    wire(&first, &second, 0);
    wire(&second, &third, 0);
    let count = {
        let mut collapse = CollapseStructure::new(&mut graph, "counter_cat");
        collapse.collapse_all();
        collapse.get_change_count()
    };
    println!(
        "case=collapse_cat_counter_zero|count={}|graph_size={}|cond_calls=-",
        count,
        graph.get_size(),
    );
}

fn run_collapse_proper_if_counter() {
    let mut graph = BlockGraph::new();
    graph.index = 0;
    let condition = fixed_probe(true);
    let clause = base_probe();
    let merge = base_probe();
    condition.write().unwrap().set_index(0);
    clause.write().unwrap().set_index(1);
    merge.write().unwrap().set_index(2);
    graph.blocks.push(condition.clone());
    graph.blocks.push(clause.clone());
    graph.blocks.push(merge.clone());
    // Slot 0 is the clause. try_rule_proper_if must negate it, count the
    // virtual true return once, and still complete the structural collapse.
    wire(&condition, &clause, 0);
    wire(&condition, &merge, 0);
    wire(&clause, &merge, 0);
    let count = {
        let mut collapse = CollapseStructure::new(&mut graph, "counter_proper_if");
        collapse.collapse_all();
        collapse.get_change_count()
    };
    println!(
        "case=collapse_proper_if_counter_one|count={}|graph_size={}|cond_calls={}",
        count,
        graph.get_size(),
        calls_of(&condition),
    );
}

fn main() {
    println!(
        "schema=1|fixture=BLOCK-STRUCTURED-NEGATE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    run_flow("flow_top_false", false, 1);
    run_flow("flow_top_true", true, 1);
    run_flow("flow_double_true_roundtrip", true, 2);
    run_parallel();
    run_self();
    run_list("list_top_false_child_true", false, 1, true);
    run_list("list_top_true_child_true", true, 1, true);
    run_list("list_double_true_roundtrip", true, 2, false);
    run_condition(
        "condition_and_top_false",
        BoolOp::And,
        false,
        1,
        true,
        false,
    );
    run_condition("condition_or_top_true", BoolOp::Or, true, 1, false, true);
    run_condition(
        "condition_double_true_roundtrip",
        BoolOp::And,
        true,
        2,
        false,
        false,
    );
    run_collapse_cat_counter();
    run_collapse_proper_if_counter();
}
