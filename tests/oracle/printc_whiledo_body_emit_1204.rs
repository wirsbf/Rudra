// MAIN-RC3-STRUCTURED-EMIT-0001: Rugra side of the locked Ghidra 12.0.4
// PrintC::emitBlockWhileDo body-emission bilateral fixture (printc.cc:
// 3061-3062 body dispatch; emitForLoop cc:2994-2995 body; overflow arm
// cc:3017-3044). Mirrors printc_whiledo_body_emit_1204.cc case for case:
// hand-built BlockWhileDo (BlockBasic condition with CBRANCH const +
// BlockList body [RETURN, BlockIf{CBRANCH, RETURN, RETURN}]) driven
// through PrintC::emit_block_graph — the same emit_block_structured
// dispatch the main pipeline uses — with a fresh EmitNoMarkup, so the
// observation is exactly the whiledo emission bytes.
//
// The three cases lock the structured body form:
//   1. whiledo_structured_body  — while (3) { return 10; if (7) {...} else {...} }
//   2. forloop_structured_body  — for (; 3; 5) { <same body> }
//   3. overflow_structured_body — while( true ) { if (3) break; <same body> }

use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, BlockGraph, BlockIf, BlockList, BlockWhileDo};
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

fn basic_block(index: i32, ops: Vec<PcodeOpRef>) -> BlockArc {
    let mut block = BlockBasic::new(index, Address::new(0x1000 + index as u64 * 0x10));
    block.ops = ops;
    Arc::new(RwLock::new(block))
}

// Build the shared graph shape: condition CBRANCH(3); body = list
// [ RET 10, properif(cond CBRANCH(7), RET 20, RET 30) ].
fn build_whiledo() -> (BlockGraph, BlockArc) {
    let cond = basic_block(0, vec![make_cbranch(1, 3)]);
    let stmt = basic_block(1, vec![make_return(2, 10)]);
    let ifcond = basic_block(2, vec![make_cbranch(3, 7)]);
    let ifb = basic_block(3, vec![make_return(4, 20)]);
    let elseb = basic_block(4, vec![make_return(5, 30)]);

    let ifblk: BlockArc = Arc::new(RwLock::new(BlockIf {
        index: 5,
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
    let stmt_arc = stmt.clone();
    let body: BlockArc = Arc::new(RwLock::new(BlockList {
        index: 6,
        children: vec![stmt_arc, ifblk],
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));

    let wd: BlockArc = Arc::new(RwLock::new(BlockWhileDo {
        index: 7,
        condition: cond,
        body,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
        for_init: None,
        for_iter: None,
        initialize_op: None,
        iterate_op: None,
        loop_def: None,
        overflow_syntax: false,
    }));

    let mut graph = BlockGraph::new();
    graph.add_block(wd.clone());
    (graph, wd)
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
        println!("{name}={}", raw);
    }
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");

    // 1. whiledo_structured_body
    {
        let (graph, _) = build_whiledo();
        emit_case("whiledo_structured_body", &render(&graph), raw);
    }

    // 2. forloop_structured_body: for_init empty string (oracle null init
    // slot), for_iter "5" (oracle iterateOp = CBRANCH const 5 rendered
    // through emitExpression in the iterate slot).
    {
        let (graph, wd) = build_whiledo();
        {
            let mut guard = wd.write().unwrap();
            let w = guard
                .as_any_mut()
                .downcast_mut::<BlockWhileDo>()
                .expect("block 7 must be the BlockWhileDo");
            w.for_init = Some(String::new());
            w.for_iter = Some("5".to_string());
        }
        emit_case("forloop_structured_body", &render(&graph), raw);
    }

    // 3. overflow_structured_body: f_whiledo_overflow — the compact
    // while( true ) header + if(cond) break; arm.
    {
        let (graph, wd) = build_whiledo();
        {
            let mut guard = wd.write().unwrap();
            let w = guard
                .as_any_mut()
                .downcast_mut::<BlockWhileDo>()
                .expect("block 7 must be the BlockWhileDo");
            w.overflow_syntax = true;
        }
        emit_case("overflow_structured_body", &render(&graph), raw);
    }
}
