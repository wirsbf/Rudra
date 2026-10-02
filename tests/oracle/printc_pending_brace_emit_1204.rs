// PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001: Rudra side of the locked Ghidra
// 12.0.4 PrintC::emitBlockIf PendingBrace bilateral fixture (printc.cc:
// 2878-2948 + prettyprint.hh:102/443-457/1129-1137). Mirrors
// printc_pending_brace_emit_1204.cc case for case: hand-built 3-component
// parent BlockIf (condition CBRANCH const, then RETURN, else = child
// BlockIf) driven through PrintC::emit_block_graph with either an
// EmitPrettyPrint (cases 1-2, the production emitter per printlanguage.cc:
// 69) or an EmitNoMarkup (case 3), locking:
//   1. elseif_stmtcond_pretty — child condition [RET 21, CBRANCH 9]: the
//      pending brace FIRES at the condition statement's tagLine ->
//      `else {` + `return 21;` + newline `if (9) {` + deferred close.
//   2. elseif_emptycond_pretty — child condition [CBRANCH 9] only:
//      nothing fires the brace -> cancel + spaces(1) -> `else if (9) {`.
//   3. elseif_stmtcond_nomarkup — case-1 graph with EmitNoMarkup: the
//      slot stays pending (hh:557 never fires) -> statements inline after
//      `else`, spaces(1) merges the `if` onto the statement's line, and
//      no deferred close.

use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, BlockGraph, BlockIf};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::{Emit, EmitNoMarkup, EmitPrettyPrint};
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

type BlockArc = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;

fn const_varnode(size: usize, value: u64) -> Arc<RwLock<Varnode>> {
    Arc::new(RwLock::new(Varnode::new_with_space(size, AddressSpace::Const, value)))
}

fn make_op(index: u32, opcode: OpCode) -> PcodeOpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(index as u64), index), opcode);
    op.set_opcode_flags(opcode);
    PcodeOpRef(Arc::new(RwLock::new(op)))
}

fn make_cbranch(op_index: u32, value: u64) -> PcodeOpRef {
    let op = make_op(op_index, OpCode::CPUI_CBRANCH);
    {
        let mut o = op.0.write().unwrap();
        o.inrefs.push(const_varnode(1, 0x1000));
        o.inrefs.push(const_varnode(1, value));
    }
    op
}

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

// Parent properif(condA CBRANCH 3, thenA RET 20, else = child properif).
// stmt_in_cond: child condition = [RET 21, CBRANCH 9] vs [CBRANCH 9].
fn build_pending_brace(stmt_in_cond: bool) -> BlockGraph {
    let conda = basic_block(0, vec![make_cbranch(1, 3)]);
    let thena = basic_block(1, vec![make_return(2, 20)]);
    let condb = if stmt_in_cond {
        basic_block(2, vec![make_return(3, 21), make_cbranch(4, 9)])
    } else {
        basic_block(2, vec![make_cbranch(4, 9)])
    };
    let thenb = basic_block(3, vec![make_return(5, 40)]);

    let child: BlockArc = Arc::new(RwLock::new(BlockIf {
        index: 4,
        condition: condb,
        if_body: thenb,
        else_body: None,
        goto_target: None,
        goto_type: 0,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));

    let parent: BlockArc = Arc::new(RwLock::new(BlockIf {
        index: 5,
        condition: conda,
        if_body: thena,
        else_body: Some(child),
        goto_target: None,
        goto_type: 0,
        incoming: Vec::new(),
        outgoing: Vec::new(),
        parent: None,
        flags: 0,
    }));

    let mut graph = BlockGraph::new();
    graph.add_block(parent);
    graph
}

fn render_pretty(graph: &BlockGraph) -> String {
    // docFunction (printc.cc:2651/2664) opens the emitter's function group
    // before any block emission — EmitPrettyPrint's indent stack needs that
    // root group (token commit reads indentstack.last()). The group prints
    // no bytes, so the observation is the bare if-emission stream.
    let mut emitter = EmitPrettyPrint::new();
    emitter.begin_function();
    let mut printer = PrintC::new(Box::new(emitter));
    printer.emit_block_graph(graph);
    let mut emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .expect("PrintC fixture must retain EmitPrettyPrint");
    emit.end_function();
    emit.get_output()
}

fn render_nomarkup(graph: &BlockGraph) -> String {
    let mut emitter = EmitNoMarkup::new();
    emitter.begin_function();
    let mut printer = PrintC::new(Box::new(emitter));
    printer.emit_block_graph(graph);
    let mut emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture must retain EmitNoMarkup");
    emit.end_function();
    emit.flush();
    emit.debug_get_output_ref().to_owned()
}

fn to_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn emit_case(name: &str, raw_text: &str, hex: bool) {
    if hex {
        println!("{name}={}", to_hex(raw_text));
    } else {
        println!("{name}={raw_text}");
    }
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");

    // 1. elseif_stmtcond_pretty
    {
        let graph = build_pending_brace(true);
        emit_case("elseif_stmtcond_pretty", &render_pretty(&graph), raw);
    }

    // 2. elseif_emptycond_pretty
    {
        let graph = build_pending_brace(false);
        emit_case("elseif_emptycond_pretty", &render_pretty(&graph), raw);
    }

    // 3. elseif_stmtcond_nomarkup
    {
        let graph = build_pending_brace(true);
        emit_case("elseif_stmtcond_nomarkup", &render_nomarkup(&graph), raw);
    }
}
