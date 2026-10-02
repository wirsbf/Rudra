// BLOCK-BUILDCOPY-STATE-0001 Rust comparand for locked Ghidra 12.0.4.
use rudra::address::{Address, SeqNum};
use rudra::block::{block_flags, BlockBasic, BlockEdge, BlockGraph, BlockType, FlowBlock};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use std::sync::{Arc, RwLock, Weak};

type FlowArc = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

#[derive(Default)]
struct Names {
    blocks: Vec<(FlowArc, String)>,
    ops: Vec<(PcodeOpRef, String)>,
}

impl Names {
    fn add_block(&mut self, block: &FlowArc, name: impl Into<String>) {
        self.blocks.push((block.clone(), name.into()));
    }

    fn add_op(&mut self, op: &PcodeOpRef, name: impl Into<String>) {
        self.ops.push((op.clone(), name.into()));
    }

    fn block(&self, block: Option<&FlowArc>) -> String {
        let Some(block) = block else {
            return "null".to_string();
        };
        self.blocks
            .iter()
            .find(|(candidate, _)| Arc::ptr_eq(candidate, block))
            .map_or_else(|| "?".to_string(), |(_, name)| name.clone())
    }

    fn weak_block(&self, block: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) -> String {
        self.block(block.and_then(|weak| weak.upgrade()).as_ref())
    }

    fn op(&self, op: Option<&PcodeOpRef>) -> String {
        let Some(op) = op else {
            return "null".to_string();
        };
        self.ops
            .iter()
            .find(|(candidate, _)| Arc::ptr_eq(&candidate.0, &op.0))
            .map_or_else(|| "?".to_string(), |(_, name)| name.clone())
    }
}

#[derive(Debug)]
struct ProbeBasic {
    index: i32,
    flags: u32,
    incoming: Vec<BlockEdge>,
    outgoing: Vec<BlockEdge>,
    ops: Vec<PcodeOpRef>,
    split: Option<FlowArc>,
    complex: bool,
    immed_dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    copy_map: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>,
    visit_count: i32,
    num_desc: i32,
}

impl ProbeBasic {
    fn new(index: i32) -> Self {
        Self {
            index,
            flags: 0,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            ops: Vec::new(),
            split: None,
            complex: false,
            immed_dom: None,
            copy_map: None,
            visit_count: 0,
            num_desc: -1,
        }
    }
}

impl FlowBlock for ProbeBasic {
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
        BlockType::Basic
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

    fn get_ops(&self) -> Vec<PcodeOpRef> {
        self.ops.clone()
    }

    fn first_op(&self) -> Option<PcodeOpRef> {
        self.ops.first().cloned()
    }

    fn last_op(&self) -> Option<PcodeOpRef> {
        self.ops.last().cloned()
    }

    fn get_split_point(&self) -> Option<FlowArc> {
        self.split.clone()
    }

    fn is_complex(&self) -> bool {
        self.complex
    }

    fn get_parent(&self) -> Option<Arc<RwLock<BlockGraph>>> {
        None
    }

    fn get_immed_dom(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.immed_dom.clone()
    }

    fn set_immed_dom(&mut self, dom: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.immed_dom = dom;
    }

    fn get_copy_map(&self) -> Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>> {
        self.copy_map.clone()
    }

    fn set_copy_map(&mut self, copy: Option<Weak<RwLock<dyn FlowBlock + Send + Sync>>>) {
        self.copy_map = copy;
    }

    fn get_visit_count(&self) -> i32 {
        self.visit_count
    }

    fn set_visit_count(&mut self, count: i32) {
        self.visit_count = count;
    }

    fn get_num_desc(&self) -> i32 {
        self.num_desc
    }

    fn set_num_desc(&mut self, count: i32) {
        self.num_desc = count;
    }
}

fn make_basic(graph: &mut BlockGraph, names: &mut Names, name: &str, index: i32) -> FlowArc {
    let concrete = Arc::new(RwLock::new(BlockBasic::new(index, Address::new(0))));
    let block: FlowArc = concrete;
    graph.add_block(block.clone());
    names.add_block(&block, name);
    block
}

fn set_state(block: &FlowArc, visit: i32, num_desc: i32, flags: u32, immed_dom: Option<&FlowArc>) {
    let mut block = block.write().expect("block write");
    block.clear_flags(u32::MAX);
    block.set_flags(flags);
    block.set_visit_count(visit);
    block.set_num_desc(num_desc);
    block.set_immed_dom(immed_dom.map(Arc::downgrade));
    block.set_copy_map(None);
}

fn add_labeled_edge(graph: &mut BlockGraph, source: &FlowArc, target: &FlowArc, label: u32) {
    let out_slot = source.read().expect("source read").size_out();
    let in_slot = target.read().expect("target read").size_in();
    graph.add_edge(source.clone(), target.clone());
    if Arc::ptr_eq(source, target) {
        let mut block = source.write().expect("self edge write");
        block.out_edges_mut()[out_slot].flags = label;
        block.in_edges_mut()[in_slot].flags = label;
    } else {
        source.write().expect("source write").out_edges_mut()[out_slot].flags = label;
        target.write().expect("target write").in_edges_mut()[in_slot].flags = label;
    }
}

fn edge_list(edges: &[BlockEdge], names: &Names) -> String {
    format!(
        "[{}]",
        edges
            .iter()
            .map(|edge| format!(
                "{}:{}:{}",
                names.block(Some(&edge.point)),
                edge.reverse_index,
                edge.flags
            ))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn slotted_edge_list(edges: &[BlockEdge], names: &Names) -> String {
    format!(
        "[{}]",
        edges
            .iter()
            .enumerate()
            .map(|(slot, edge)| format!(
                "{slot}>{}:{}:{}",
                names.block(Some(&edge.point)),
                edge.reverse_index,
                edge.flags
            ))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn op_list(block: &FlowArc, names: &Names) -> String {
    let ops = block.read().expect("block read").get_ops();
    format!(
        "[{}]",
        ops.iter()
            .enumerate()
            .map(|(slot, op)| {
                let (time, order, parent) = {
                    let op = op.0.read().expect("op read");
                    (
                        op.start.get_time(),
                        op.start.get_order(),
                        op.parent.as_ref().and_then(Weak::upgrade),
                    )
                };
                format!(
                    "{slot}>{}:time={time}:order={order}:parent={}",
                    names.op(Some(op)),
                    names.block(parent.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn reciprocal(block: &FlowArc, edges: &[BlockEdge], outgoing: bool) -> bool {
    for (slot, edge) in edges.iter().enumerate() {
        if edge.reverse_index < 0 {
            return false;
        }
        let reverse = {
            let peer = edge.point.read().expect("peer read");
            if outgoing {
                peer.get_in(edge.reverse_index as usize)
            } else {
                peer.get_out(edge.reverse_index as usize)
            }
        };
        let Some(reverse) = reverse else {
            return false;
        };
        if !Arc::ptr_eq(&reverse.point, block)
            || reverse.reverse_index != slot as i32
            || reverse.flags != edge.flags
        {
            return false;
        }
    }
    true
}

fn type_name(block_type: BlockType) -> &'static str {
    match block_type {
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

fn block_state(block: &FlowArc, names: &Names, include_copy_map: bool) -> String {
    let (block_type, index, flags, visit, num_desc, idom, copy_map, incoming, outgoing) = {
        let block = block.read().expect("block read");
        let incoming = (0..block.size_in())
            .map(|slot| block.get_in(slot).expect("in edge"))
            .collect::<Vec<_>>();
        let outgoing = (0..block.size_out())
            .map(|slot| block.get_out(slot).expect("out edge"))
            .collect::<Vec<_>>();
        (
            block.get_type(),
            block.get_index(),
            block.get_flags(),
            block.get_visit_count(),
            block.get_num_desc(),
            block.get_immed_dom(),
            block.get_copy_map(),
            incoming,
            outgoing,
        )
    };
    let mut result = format!(
        "type={},index={index},flags={flags},visit={visit},numdesc={num_desc},idom={}",
        type_name(block_type),
        names.weak_block(idom)
    );
    if include_copy_map {
        result.push_str(&format!(",copymap={}", names.weak_block(copy_map)));
    }
    result.push_str(&format!(
        ",in={},out={},in_ok={},out_ok={}",
        edge_list(&incoming, names),
        edge_list(&outgoing, names),
        i32::from(reciprocal(block, &incoming, false)),
        i32::from(reciprocal(block, &outgoing, true))
    ));
    result
}

fn list_state(graph: &BlockGraph, names: &Names) -> String {
    format!(
        "[{}]",
        graph
            .blocks
            .iter()
            .map(|block| names.block(Some(block)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn observe_copy(case_name: &str, copy: &FlowArc, names: &Names) {
    let (sub0, sub7) = {
        let copy = copy.read().expect("copy read");
        (copy.sub_block(0), copy.sub_block(7))
    };
    println!(
        "case={case_name}|phase=copy|block={}|{},sub0={},sub7={}",
        names.block(Some(copy)),
        block_state(copy, names, false),
        names.block(sub0.as_ref()),
        names.block(sub7.as_ref())
    );
}

fn incoming_order_6_2() {
    let mut source = BlockGraph::new();
    let mut names = Names::default();
    let indices = [70, 11, 52, 34, 26, 63, 45, 18];
    let original = indices
        .iter()
        .enumerate()
        .map(|(ordinal, index)| make_basic(&mut source, &mut names, &format!("s{ordinal}"), *index))
        .collect::<Vec<_>>();
    let flags = [
        block_flags::ENTRY_POINT | block_flags::MARK,
        block_flags::DUPLICATE_BLOCK,
        block_flags::JOINED_BLOCK | block_flags::MARK2,
        block_flags::LABEL_BUMPUP,
        block_flags::UNSTRUCTURED_TARG,
        block_flags::DONOTHING_LOOP,
        block_flags::INTERIOR_GOTOOUT,
        block_flags::INTERIOR_GOTOIN,
    ];
    let idoms = [
        None,
        Some(0),
        Some(0),
        Some(1),
        Some(2),
        Some(2),
        Some(0),
        Some(6),
    ];
    for ordinal in 0..original.len() {
        set_state(
            &original[ordinal],
            90 + ordinal as i32,
            300 + ordinal as i32,
            flags[ordinal],
            idoms[ordinal].map(|index| &original[index]),
        );
    }
    add_labeled_edge(&mut source, &original[6], &original[4], 0x81);
    add_labeled_edge(&mut source, &original[2], &original[4], 0x102);
    add_labeled_edge(&mut source, &original[0], &original[1], 0x10);
    add_labeled_edge(&mut source, &original[1], &original[3], 0x21);
    add_labeled_edge(&mut source, &original[1], &original[5], 0x42);
    add_labeled_edge(&mut source, &original[1], &original[6], 0x84);
    add_labeled_edge(&mut source, &original[1], &original[7], 0x108);
    add_labeled_edge(&mut source, &original[7], &original[5], 0x49);

    let mut target = BlockGraph::new();
    target.build_copy(&source);
    let copies = target.blocks.clone();
    for (ordinal, copy) in copies.iter().enumerate() {
        names.add_block(copy, format!("c{ordinal}"));
    }
    println!(
        "case=incoming_order_6_2|phase=graph|source_list={}|target_list={}|source_index={}|target_index={}",
        list_state(&source, &names),
        list_state(&target, &names),
        source.index,
        target.index
    );
    for (ordinal, block) in original.iter().enumerate() {
        println!(
            "case=incoming_order_6_2|phase=source|block=s{ordinal}|{}",
            block_state(block, &names, true)
        );
    }
    for copy in &copies {
        observe_copy("incoming_order_6_2", copy, &names);
    }
}

fn append_prefix_untouched() {
    let mut source = BlockGraph::new();
    let mut names = Names::default();
    let original = (0..3)
        .map(|ordinal| {
            make_basic(
                &mut source,
                &mut names,
                &format!("s{ordinal}"),
                31 + ordinal,
            )
        })
        .collect::<Vec<_>>();
    set_state(&original[0], 41, 51, block_flags::ENTRY_POINT, None);
    set_state(&original[1], 42, 52, block_flags::MARK, Some(&original[0]));
    set_state(
        &original[2],
        43,
        53,
        block_flags::DUPLICATE_BLOCK,
        Some(&original[1]),
    );
    add_labeled_edge(&mut source, &original[2], &original[1], 0x62);
    add_labeled_edge(&mut source, &original[0], &original[2], 0x23);

    let mut target = BlockGraph::new();
    let p0 = make_basic(&mut target, &mut names, "p0", 901);
    let p1 = make_basic(&mut target, &mut names, "p1", 902);
    set_state(&p0, 71, 81, block_flags::JOINED_BLOCK, None);
    set_state(&p1, 72, 82, block_flags::LABEL_BUMPUP, Some(&p0));
    p0.write()
        .expect("p0 write")
        .set_copy_map(Some(Arc::downgrade(&p1)));
    p1.write()
        .expect("p1 write")
        .set_copy_map(Some(Arc::downgrade(&p0)));
    add_labeled_edge(&mut target, &p1, &p0, 0x141);
    println!(
        "case=append_prefix_untouched|phase=before|target_list={}",
        list_state(&target, &names)
    );
    println!(
        "case=append_prefix_untouched|phase=prefix_before|block=p0|{}",
        block_state(&p0, &names, true)
    );
    println!(
        "case=append_prefix_untouched|phase=prefix_before|block=p1|{}",
        block_state(&p1, &names, true)
    );

    target.build_copy(&source);
    let copies = target.blocks[2..].to_vec();
    for (ordinal, copy) in copies.iter().enumerate() {
        names.add_block(copy, format!("c{ordinal}"));
    }
    println!(
        "case=append_prefix_untouched|phase=after|target_list={}|target_index={}",
        list_state(&target, &names),
        target.index
    );
    println!(
        "case=append_prefix_untouched|phase=prefix_after|block=p0|{}",
        block_state(&p0, &names, true)
    );
    println!(
        "case=append_prefix_untouched|phase=prefix_after|block=p1|{}",
        block_state(&p1, &names, true)
    );
    for (ordinal, block) in original.iter().enumerate() {
        println!(
            "case=append_prefix_untouched|phase=source|block=s{ordinal}|{}",
            block_state(block, &names, true)
        );
    }
    for copy in &copies {
        observe_copy("append_prefix_untouched", copy, &names);
    }
}

fn token_with_opcode(time: u32, opcode: OpCode) -> PcodeOpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(0), time), opcode);
    op.set_opcode_flags(opcode);
    PcodeOpRef(Arc::new(RwLock::new(op)))
}

fn token(time: u32) -> PcodeOpRef {
    token_with_opcode(time, OpCode::CPUI_COPY)
}

fn live_delegate() {
    let op0 = token(0);
    let op1 = token(1);
    let op2 = token(2);
    let mut names = Names::default();
    names.add_op(&op0, "op0");
    names.add_op(&op1, "op1");
    names.add_op(&op2, "op2");

    let mut source = BlockGraph::new();
    let probe: FlowArc = Arc::new(RwLock::new(ProbeBasic::new(401)));
    source.add_block(probe.clone());
    names.add_block(&probe, "s0");
    let split = make_basic(&mut source, &mut names, "s1", 402);
    set_state(&probe, 99, 77, block_flags::MARK, Some(&split));
    set_state(&split, 98, 76, block_flags::DUPLICATE_BLOCK, Some(&probe));
    {
        let mut probe_guard = probe.write().expect("probe write");
        let probe_state = probe_guard
            .as_any_mut()
            .downcast_mut::<ProbeBasic>()
            .expect("ProbeBasic");
        probe_state.ops = vec![op0.clone(), op1.clone()];
        probe_state.split = Some(split.clone());
        probe_state.complex = false;
    }

    let mut target = BlockGraph::new();
    target.build_copy(&source);
    let copy = target.blocks[0].clone();
    let split_copy = target.blocks[1].clone();
    names.add_block(&copy, "c0");
    names.add_block(&split_copy, "c1");
    observe_live("before", &copy, &names);

    {
        let mut probe_guard = probe.write().expect("probe write");
        let probe_state = probe_guard
            .as_any_mut()
            .downcast_mut::<ProbeBasic>()
            .expect("ProbeBasic");
        probe_state.ops = vec![op2.clone()];
        probe_state.split = None;
        probe_state.complex = true;
    }
    observe_live("after", &copy, &names);
}

fn observe_live(phase: &str, copy: &FlowArc, names: &Names) {
    let (block_type, sub0, sub7, exit, first, last, complex, split) = {
        let copy = copy.read().expect("copy read");
        (
            copy.get_type(),
            copy.sub_block(0),
            copy.sub_block(7),
            copy.get_exit_leaf_trait(),
            copy.first_op(),
            copy.last_op(),
            copy.is_complex(),
            copy.get_split_point(),
        )
    };
    println!(
        "case=live_delegate|phase={phase}|block=c0|type={}|sub0={}|sub7={}|exit_self={}|first={}|last={}|complex={}|split={}",
        type_name(block_type),
        names.block(sub0.as_ref()),
        names.block(sub7.as_ref()),
        i32::from(exit.as_ref().is_some_and(|leaf| Arc::ptr_eq(leaf, copy))),
        names.op(first.as_ref()),
        names.op(last.as_ref()),
        i32::from(complex),
        names.block(split.as_ref())
    );
}

fn blockbasic_insert_end() {
    let op0 = token_with_opcode(10, OpCode::CPUI_COPY);
    let op1 = token_with_opcode(11, OpCode::CPUI_COPY);
    let op2 = token_with_opcode(12, OpCode::CPUI_BRANCHIND);
    let mut graph = BlockGraph::new();
    let mut names = Names::default();
    let block = make_basic(&mut graph, &mut names, "s0", 501);
    names.add_op(&op0, "op0");
    names.add_op(&op1, "op1");
    names.add_op(&op2, "op2");

    println!(
        "case=blockbasic_insert_end|phase=before|block=s0|ops={}|flags={}",
        op_list(&block, &names),
        block.read().expect("block read").get_flags()
    );
    {
        let mut block = block.write().expect("block write");
        let basic = block
            .as_any_mut()
            .downcast_mut::<BlockBasic>()
            .expect("BlockBasic");
        basic.add_op(op0);
        basic.add_op(op1);
        basic.add_op(op2);
    }
    let (flags, last) = {
        let block = block.read().expect("block read");
        (block.get_flags(), block.last_op())
    };
    println!(
        "case=blockbasic_insert_end|phase=after|block=s0|ops={}|flags={flags}|switch_out={}|last={}",
        op_list(&block, &names),
        i32::from(flags & block_flags::SWITCH_OUT != 0),
        names.op(last.as_ref())
    );
}

fn observe_parallel_remove(phase: &str, source: &FlowArc, target: &FlowArc, names: &Names) {
    let source_out = {
        let source = source.read().expect("source read");
        (0..source.size_out())
            .map(|slot| source.get_out(slot).expect("source out edge"))
            .collect::<Vec<_>>()
    };
    let target_in = {
        let target = target.read().expect("target read");
        (0..target.size_in())
            .map(|slot| target.get_in(slot).expect("target in edge"))
            .collect::<Vec<_>>()
    };
    println!(
        "case=parallel_remove_after_swap|phase={phase}|src_out={}|dst_in={}|src_flags={}|src_ok={}|dst_ok={}",
        slotted_edge_list(&source_out, names),
        slotted_edge_list(&target_in, names),
        source.read().expect("source read").get_flags(),
        i32::from(reciprocal(source, &source_out, true)),
        i32::from(reciprocal(target, &target_in, false))
    );
}

fn parallel_remove_after_swap() {
    let mut graph = BlockGraph::new();
    let mut names = Names::default();
    let source = make_basic(&mut graph, &mut names, "s0", 601);
    let target = make_basic(&mut graph, &mut names, "d0", 602);
    add_labeled_edge(&mut graph, &source, &target, 0x31);
    add_labeled_edge(&mut graph, &source, &target, 0x62);

    observe_parallel_remove("before", &source, &target, &names);
    source.write().expect("source write").swap_edges();
    observe_parallel_remove("swapped", &source, &target, &names);
    graph.remove_edge_blocks(&source, &target);
    observe_parallel_remove("removed", &source, &target, &names);
}

fn main() {
    println!(
        "schema=1|fixture=BLOCK-BUILDCOPY-STATE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b|overall=MISMATCH|covered_projection=MATCH"
    );
    incoming_order_6_2();
    append_prefix_untouched();
    live_delegate();
    blockbasic_insert_end();
    parallel_remove_after_swap();
}
