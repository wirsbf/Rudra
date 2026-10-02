use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, BlockDoWhile, BlockGraph, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn make_op(opcode: OpCode, index: u32) -> PcodeOp {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(index as u64), index), opcode);
    op.set_opcode_flags(opcode);
    op
}

fn make_call_block(target: u64, index: i32) -> DynBlock {
    let mut op = make_op(OpCode::CPUI_CALL, index as u32);
    op.inrefs.push(Arc::new(RwLock::new(Varnode::new_with_space(
        8,
        AddressSpace::Const,
        target,
    ))));
    let mut block = BlockBasic::new(index, Address::new(index as u64));
    block.add_op(PcodeOpRef(Arc::new(RwLock::new(op))));
    Arc::new(RwLock::new(block))
}

fn graph_visit_order() -> Vec<u64> {
    let targets = [17_u64, 3, 29];
    let mut graph = BlockGraph::new();
    for (index, target) in targets.iter().copied().enumerate() {
        graph.add_block(make_call_block(target, index as i32));
    }

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.emit_block_graph(&graph);
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC block-graph fixture must retain EmitNoMarkup");
    let output = emit.debug_get_output_ref();

    let mut positions = targets
        .iter()
        .copied()
        .map(|target| {
            let name = format!("FUN_{target:x}");
            let position = output
                .find(&name)
                .unwrap_or_else(|| panic!("missing {name} in {output:?}"));
            (position, target)
        })
        .collect::<Vec<_>>();
    positions.sort_by_key(|(position, _)| *position);
    positions.into_iter().map(|(_, target)| target).collect()
}

fn make_do_while() -> DynBlock {
    let mut branch = make_op(OpCode::CPUI_CBRANCH, 1);
    branch
        .inrefs
        .push(Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Const,
            0x1000,
        ))));
    branch
        .inrefs
        .push(Arc::new(RwLock::new(Varnode::new_with_space(
            1,
            AddressSpace::Const,
            1,
        ))));
    let mut condition = BlockBasic::new(0, Address::new(0x1000));
    condition.add_op(PcodeOpRef(Arc::new(RwLock::new(branch))));
    let condition: DynBlock = Arc::new(RwLock::new(condition));
    Arc::new(RwLock::new(BlockDoWhile {
        index: 0,
        condition,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }))
}

fn doc_function_dowhile_visits() -> usize {
    let mut function = Funcdata::new("blockgraph_probe", Address::new(0x1000), 1);
    function.sblocks.add_block(make_do_while());

    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.doc_function_inherent(&function);
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC doc-function fixture must retain EmitNoMarkup");
    emit.debug_get_output_ref().matches("do ").count()
}

fn main() {
    let visits = graph_visit_order();
    println!(
        "visit_order={}",
        visits
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("visit_count={}", visits.len());
    println!("dowhile_visits={}", doc_function_dowhile_visits());
}
