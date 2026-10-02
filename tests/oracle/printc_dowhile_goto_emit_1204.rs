// PRINTC-NESTED-DOWHILE-EMIT-0001: Rudra side of the locked Ghidra 12.0.4
// PrintC::emitBlockDoWhile body-emission + emitBlockGoto wrapped-emission
// bilateral fixture (printc.cc:3081-3083 body dispatch; printc.cc:2771
// wrapped dispatch; while tail cc:3088-3093). Mirrors
// printc_dowhile_goto_emit_1204.cc case for case: hand-built BlockDoWhile
// (body = BlockList [RETURN, BlockIf{CBRANCH, RETURN, RETURN}, latch
// CBRANCH]) driven through PrintC::emit_block_graph — the same
// emit_block_structured / emit_flow_block dispatch the main pipeline uses —
// with a fresh EmitNoMarkup, so the observation is exactly the emission
// bytes.
//
// The two cases lock the structured emission forms:
//   1. dowhile_structured_body — do { return 10; if (7) {...} else {...} } while (5);
//      the body properif renders (a flat op walk drops it) and the latch
//      CBRANCH re-emits as the while tail.
//   2. goto_wrapped_dowhile — the same loop inside a BlockGoto; the wrapped
//      structured block must emit `do {` (a flat walk collapses it to
//      single-iteration statements — the main else-if arm residual this
//      fixture locks). goto_target = RET tail, goto_type = GOTO_GOTO,
//      prints_precomputed = false (parent-null arm, block.cc:2889) so no
//      formal goto statement prints on either side.

use rudra::address::{Address, SeqNum};
use rudra::block::{
    BlockBasic, BlockDoWhile, BlockGoto, BlockGraph, BlockIf, BlockList,
};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

type BlockArc = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;

// Const-space varnode of the given byte size (the oracle fixture uses
// 1-byte bool constants for CBRANCH conditions and 4-byte int constants
// for RETURN values).
fn const_varnode(size: usize, value: u64) -> Arc<RwLock<Varnode>> {
    Arc::new(RwLock::new(Varnode::new_with_space(size, AddressSpace::Const, value)))
}

fn make_op(index: u32, opcode: OpCode) -> PcodeOpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(index as u64), index), opcode);
    op.set_opcode_flags(opcode);
    PcodeOpRef(Arc::new(RwLock::new(op)))
}

// CBRANCH with in(0) = code placeholder, in(1) = 1-byte const(value).
fn make_cbranch(op_index: u32, value: u64) -> PcodeOpRef {
    let op = make_op(op_index, OpCode::CPUI_CBRANCH);
    {
        let mut o = op.0.write().unwrap();
        o.inrefs.push(const_varnode(1, 0x1000));
        o.inrefs.push(const_varnode(1, value));
    }
    op
}

// 2-input RETURN: in(0) = placeholder indirect slot, in(1) = 4-byte
// const(value) — the oracle's post-ActionReturnRecovery shape.
fn make_return(op_index: u32, value: u64) -> PcodeOpRef {
    let op = make_op(op_index, OpCode::CPUI_RETURN);
    {
        let mut o = op.0.write().unwrap();
        o.inrefs.push(const_varnode(1, 0x1000));
        o.inrefs.push(const_varnode(4, value));
    }
    op
}

fn basic_block(index: i32, ops: Vec<PcodeOpRef>) -> Arc<RwLock<BlockBasic>> {
    let mut block = BlockBasic::new(index, Address::new(0x1000 + index as u64 * 0x10));
    block.ops = ops;
    Arc::new(RwLock::new(block))
}

// Build the case-1 graph shape: body = list
// [ RET 10, properif(cond CBRANCH(7), RET 20, RET 30), latch CBRANCH(5) ];
// returns the graph (rooted at the DoWhile) and the RET tail basic used as
// the goto target in case 2.
fn build_dowhile() -> (BlockGraph, BlockArc, Arc<RwLock<BlockBasic>>) {
    let stmt = basic_block(1, vec![make_return(2, 10)]);
    let ifcond = basic_block(2, vec![make_cbranch(3, 7)]);
    let ifb = basic_block(3, vec![make_return(4, 20)]);
    let elseb = basic_block(4, vec![make_return(5, 30)]);
    let latch = basic_block(5, vec![make_cbranch(6, 5)]);
    let tail = basic_block(6, vec![make_return(7, 50)]);

    let ifblk: BlockArc = Arc::new(RwLock::new(BlockIf {
        index: 7,
        condition: ifcond,
        if_body: ifb,
        else_body: Some(elseb),
        goto_target: None,
        goto_type: 0,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));
    let stmt_arc: BlockArc = stmt.clone();
    let latch_arc: BlockArc = latch;
    let body: BlockArc = Arc::new(RwLock::new(BlockList {
        index: 8,
        children: vec![stmt_arc, ifblk, latch_arc],
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));

    let dw: BlockArc = Arc::new(RwLock::new(BlockDoWhile {
        index: 9,
        condition: body,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));

    let mut graph = BlockGraph::new();
    graph.add_block(dw.clone());
    (graph, dw, tail)
}

fn render(graph: &BlockGraph) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.emit_block_graph(graph);
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture must retain EmitNoMarkup");
    emit.debug_get_output_ref().to_owned()
}

fn to_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn emit_case(name: &str, raw: &str, hex: bool) {
    if hex {
        println!("{name}={}", to_hex(raw));
    } else {
        println!("{name}={raw}");
    }
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");

    // 1. dowhile_structured_body
    {
        let (graph, _, _) = build_dowhile();
        emit_case("dowhile_structured_body", &render(&graph), raw);
    }

    // 2. goto_wrapped_dowhile: the case-1 DoWhile wrapped by a BlockGoto
    // (goto_target = RET tail, GOTO_GOTO, parent None + prints_precomputed
    // false = the oracle's null-parent gotoPrints arm — no formal goto
    // statement on either side).
    {
        let (_, dw, tail) = build_dowhile();
        let tail_dyn: BlockArc = tail.clone();
        let goto_arc: BlockArc = Arc::new(RwLock::new(BlockGoto {
            index: 10,
            flags: 0,
            parent: None,
            goto_target: Some(tail),
            target_dyn: Some(tail_dyn),
            wrapped: Some(dw),
            goto_type: rudra::block::goto_type::GOTO_GOTO,
            prints_precomputed: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }));
        let mut graph = BlockGraph::new();
        graph.add_block(goto_arc);
        emit_case("goto_wrapped_dowhile", &render(&graph), raw);
    }
}
