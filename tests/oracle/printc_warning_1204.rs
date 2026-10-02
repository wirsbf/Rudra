// PRINTC-WARNING-COMMENT-0001: Rudra comparand for the locked Ghidra 12.0.4
// PrintC warning-comment emission oracle (setupFunctionList ->
// emitCommentFuncHeader / setupBlockList -> emitCommentGroup per statement
// -> emitCommentGroup(NULL) tail -> emitLineComment delimiters + absolute
// indent).
//
// Mirrors tests/oracle/printc_warning_1204.cc construction step-for-step:
// same block graphs (indexes from find_spanning_tree over the chain), same
// op creation/insertion order (fixing SeqNum::uniq), same
// Funcdata::warning/warning_header production channel into the
// Architecture commentdb, same protocol call sequence.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, BlockGraph, FlowBlock};
use rudra::comment::CommentDatabaseInternal;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::{space_flags, AddrSpace, SpaceType};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn ram_space() -> AddrSpace {
    AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    )
}

fn fixture_arch() -> Arc<Architecture> {
    // A bare Architecture carrying only the commentdb: Funcdata::warning /
    // warning_header (funcdata.rs, faithful to funcdata.cc:119/135) route
    // through arch.commentdb, and setup_function_comments (printc.cc:2650)
    // reads the same database — the identical production channel the C++
    // fixture drives through glb->commentdb.
    let mut arch = Architecture::new();
    arch.set_commentdb(Arc::new(RwLock::new(CommentDatabaseInternal::new())));
    Arc::new(arch)
}

fn new_op(fd: &mut Funcdata, off: u64, bb: &BlockRef) -> rudra::op::PcodeOpRef {
    let op = fd.new_op(0, Address::with_space(&ram_space(), off));
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    fd.op_insert_end(&op, bb);
    op
}

// Drive the docFunction/emitBlockBasic comment protocol over one function
// and return the raw EmitNoMarkup bytes (mirrors run_protocol in the C++
// fixture): header drain, then per block the setup_block_comment_list
// window, one emit_comment_group landmark per op (insertion order), and the
// emit_comment_group(None) tail.
fn run_protocol(mut printer: PrintC, fd: &Funcdata, blocks: &[BlockRef]) -> String {
    printer.setup_function_comments(fd);
    printer.emit_comment_func_header(fd);
    for bb in blocks {
        let ops = bb.read().unwrap().get_ops();
        printer.setup_block_comment_list(bb.read().unwrap().get_index());
        for op in &ops {
            printer.emit_comment_group(Some(op));
        }
        printer.emit_comment_group(None);
    }
    let emit = printer.take_emit();
    let eno = emit
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture emitter type");
    eno.debug_get_output_ref().to_string()
}

fn report(case_id: &str, emission: &str) {
    println!("case={case_id}|len={}|emit=<<<{}>>>", emission.len(), emission);
}

fn main() {
    println!("schema=1|fixture=PRINTC-WARNING-COMMENT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    let ram = ram_space();
    let addr = |off: u64| Address::with_space(&ram, off);

    // ---- case clean: no comments anywhere ----
    {
        let arch = fixture_arch();
        let fad = addr(0x8000);
        let mut fd = Funcdata::new("clean", fad, 0x10);
        fd.set_arch(arch.clone());
        let mut graph = BlockGraph::new();
        let bb: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0x8000))));
        graph.add_block(bb.clone());
        // Rudra has no block cover: range projects as [start_addr, last-op
        // addr]; the C++ side pins setBasicBlockRange to the same bounds.
        let _ = new_op(&mut fd, 0x8000, &bb);
        let _ = new_op(&mut fd, 0x8004, &bb);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        graph.find_spanning_tree(&mut preorder, &mut rootlist).unwrap();
        let printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        let emission = run_protocol(printer, &fd, &[bb]);
        report("clean", &emission);
    }

    // ---- case noreturn: one inline warning at the call op ----
    {
        let arch = fixture_arch();
        let fad = addr(0x9000);
        let mut fd = Funcdata::new("noreturn", fad, 0x20);
        fd.set_arch(arch.clone());
        let mut graph = BlockGraph::new();
        let bb0: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0x9000))));
        let bb1: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0x9008))));
        graph.add_block(bb0.clone());
        graph.add_block(bb1.clone());
        graph.add_edge(bb0.clone(), bb1.clone());
        let _ = new_op(&mut fd, 0x9000, &bb0);
        let _ = new_op(&mut fd, 0x9006, &bb0);
        let call = new_op(&mut fd, 0x9008, &bb1);
        let _ = new_op(&mut fd, 0x900a, &bb1);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        graph.find_spanning_tree(&mut preorder, &mut rootlist).unwrap();
        // flow.rs check_for_flow_modification channel (flow.cc:646):
        // fd.warning("Subroutine does not return", op->getAddr()) — writes
        // "WARNING: Subroutine does not return" at the call address.
        let call_addr = call.0.read().unwrap().get_addr();
        fd.warning("Subroutine does not return", call_addr);
        let printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        let emission = run_protocol(printer, &fd, &[bb0, bb1]);
        report("noreturn", &emission);
    }

    // ---- case multi: header warning + two inline warnings ----
    {
        let arch = fixture_arch();
        let fad = addr(0xa000);
        let mut fd = Funcdata::new("multi", fad, 0x20);
        fd.set_arch(arch.clone());
        let mut graph = BlockGraph::new();
        let bb0: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0xa000))));
        let bb1: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0xa008))));
        let bb2: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, addr(0xa00c))));
        graph.add_block(bb0.clone());
        graph.add_block(bb1.clone());
        graph.add_block(bb2.clone());
        graph.add_edge(bb0.clone(), bb1.clone());
        graph.add_edge(bb1.clone(), bb2.clone());
        let _ = new_op(&mut fd, 0xa000, &bb0);
        let _ = new_op(&mut fd, 0xa006, &bb0);
        let call1 = new_op(&mut fd, 0xa008, &bb1);
        let _ = new_op(&mut fd, 0xa00a, &bb1);
        let call2 = new_op(&mut fd, 0xa00c, &bb2);
        let _ = new_op(&mut fd, 0xa00e, &bb2);
        let mut preorder = Vec::new();
        let mut rootlist = Vec::new();
        graph.find_spanning_tree(&mut preorder, &mut rootlist).unwrap();
        // funcdata.rs warning_header (funcdata.cc:135) -> warningheader@fad.
        fd.warning_header(
            "Unknown calling convention -- yet parameter storage is locked",
        );
        // Two noreturn warnings at two distinct call blocks, each at its
        // block's first-op address (the curl golden form;
        // add_comment_no_duplicate keeps both because the addresses differ).
        let call1_addr = call1.0.read().unwrap().get_addr();
        fd.warning("Subroutine does not return", call1_addr);
        let call2_addr = call2.0.read().unwrap().get_addr();
        fd.warning("Subroutine does not return", call2_addr);
        let printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        let emission = run_protocol(printer, &fd, &[bb0, bb1, bb2]);
        report("multi", &emission);
    }
}
