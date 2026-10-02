//! FUNCDATA-CALCNZM-0001 Rudra comparand: Funcdata::calc_nz_mask
//! (funcdata_varnode.cc:856-926) bilateral fixture against the locked
//! Ghidra 12.0.4 oracle. Mirrors tests/oracle/funcdata_calcnzm_1204.cc
//! scenario-for-scenario; every printed value must byte-match the oracle.

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type Vn = Arc<RwLock<Varnode>>;

fn new_function(name: &str) -> Funcdata {
    Funcdata::new(name, Address::new(0x5000), 0x100)
}

fn new_output_op(
    fd: &mut Funcdata,
    block: &Block,
    opcode: OpCode,
    pc: u64,
    inputs: usize,
    output_size: usize,
    at_begin: bool,
) -> (rudra::op::PcodeOpRef, Vn) {
    let op = fd.new_op(inputs, Address::new(pc));
    fd.op_set_opcode(&op, opcode);
    let output = fd.new_unique_out(output_size, &op);
    if at_begin {
        fd.op_insert_begin(&op, block);
    } else {
        fd.op_insert_end(&op, block);
    }
    (op, output)
}

fn nzm(vn: &Vn) -> u64 {
    vn.read().unwrap().get_nzm()
}

/// init: phase-1 unwritten-input initialization (cc:887-896) — constant
/// offset, calc_mask for register inputs, ~0xff alignment for spacebase
/// inputs — plus COPY propagation of each initialized mask.
fn run_init() {
    let mut fd = new_function("calcnzm");
    let block = fd.create_new_block();
    // Constant input: nzm = offset (cc:889-890).
    let (cp_c, out_c) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x5010, 1, 4, false);
    let c = fd.new_constant(4, 0x3f0);
    fd.op_set_input(&cp_c, c, 0);
    // Unwritten register input: nzm = calc_mask(4) (cc:892).
    let (cp_r, out_r) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x5011, 1, 4, false);
    let edi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x38);
    let edi = fd.set_input_varnode(edi);
    fd.op_set_input(&cp_r, edi, 0);
    // Spacebase input: nzm = calc_mask(8) & ~0xff (cc:892-894), marked by
    // Funcdata::spacebase at Rudra's configured stack pointer (Register@0x20,
    // the x86-64 default; the C++ twin marks Register@0 — only the nzm value
    // is observed, which is identical).
    let (cp_s, out_s) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x5012, 1, 8, false);
    let sp = fd.vbank.create_with_space(8, AddressSpace::Register, 0x20);
    let sp = fd.set_input_varnode(sp);
    fd.op_set_input(&cp_s, sp.clone(), 0);
    fd.spacebase();
    fd.calc_nz_mask();
    let in_c = cp_c.0.read().unwrap().inrefs[0].clone();
    let in_r = cp_r.0.read().unwrap().inrefs[0].clone();
    println!(
        "init|const={:#x}|reg={:#x}|sb={:#x}|sbflag={}|outs={:#x},{:#x},{:#x}",
        nzm(&in_c),
        nzm(&in_r),
        nzm(&sp),
        u8::from(sp.read().unwrap().is_spacebase()),
        nzm(&out_c),
        nzm(&out_r),
        nzm(&out_s),
    );
}

/// andcopy: INT_AND mask convergence (op.cc:590-594) + two-deep COPY chain.
fn run_and_copy() {
    let mut fd = new_function("calcnzm");
    let block = fd.create_new_block();
    let (and_op, u1) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_AND, 0x5020, 2, 4, false);
    let edi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x38);
    let edi = fd.set_input_varnode(edi);
    fd.op_set_input(&and_op, edi, 0);
    let mask = fd.new_constant(4, 0x3f0);
    fd.op_set_input(&and_op, mask, 1);
    let (copy1, c1) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x5021, 1, 4, false);
    fd.op_set_input(&copy1, u1.clone(), 0);
    let (copy2, c2) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x5022, 1, 4, false);
    fd.op_set_input(&copy2, c1.clone(), 0);
    fd.calc_nz_mask();
    println!("andcopy|and={:#x}|c1={:#x}|c2={:#x}", nzm(&u1), nzm(&c1), nzm(&c2));
}

/// piece: PIECE concatenation (op.cc:693-698).
fn run_piece() {
    let mut fd = new_function("calcnzm");
    let block = fd.create_new_block();
    let (piece, out) = new_output_op(&mut fd, &block, OpCode::CPUI_PIECE, 0x5030, 2, 4, false);
    let hi = fd.new_constant(2, 0x1122);
    fd.op_set_input(&piece, hi, 0);
    let lo = fd.new_constant(2, 0x3344);
    fd.op_set_input(&piece, lo, 1);
    fd.calc_nz_mask();
    println!("piece|out={:#x}", nzm(&out));
}

/// div: the sc6 shape y = y/64 (op.cc:648-659) plus non-power-of-two,
/// non-constant denominators and INT_REM (op.cc:660-663).
fn run_div() {
    let mut fd = new_function("calcnzm");
    let block = fd.create_new_block();
    let edi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x38);
    let edi = fd.set_input_varnode(edi);
    let esi = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
    let esi = fd.set_input_varnode(esi);
    // y1 = EDI & 0xffff.
    let (and_op, y1) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_AND, 0x5040, 2, 4, false);
    fd.op_set_input(&and_op, edi.clone(), 0);
    let ffff = fd.new_constant(4, 0xffff);
    fd.op_set_input(&and_op, ffff, 1);
    // d64 = y1 / 64.
    let (d64, d64_out) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_DIV, 0x5041, 2, 4, false);
    fd.op_set_input(&d64, y1.clone(), 0);
    let c64 = fd.new_constant(4, 64);
    fd.op_set_input(&d64, c64, 1);
    // dfull = EDI / 64.
    let (dfull, dfull_out) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_DIV, 0x5042, 2, 4, false);
    fd.op_set_input(&dfull, edi.clone(), 0);
    let c64b = fd.new_constant(4, 64);
    fd.op_set_input(&dfull, c64b, 1);
    // dodd = EDI / 3.
    let (dodd, dodd_out) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_DIV, 0x5043, 2, 4, false);
    fd.op_set_input(&dodd, edi.clone(), 0);
    let c3 = fd.new_constant(4, 3);
    fd.op_set_input(&dodd, c3, 1);
    // dvar = EDI / ESI (non-constant denominator).
    let (dvar, dvar_out) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_DIV, 0x5044, 2, 4, false);
    fd.op_set_input(&dvar, edi, 0);
    fd.op_set_input(&dvar, esi, 1);
    // rem = EDI % 0x100.
    let (rem, rem_out) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_REM, 0x5045, 2, 4, false);
    let edi2 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x38);
    let edi2 = fd.set_input_varnode(edi2);
    fd.op_set_input(&rem, edi2, 0);
    let c100 = fd.new_constant(4, 0x100);
    fd.op_set_input(&rem, c100, 1);
    fd.calc_nz_mask();
    println!(
        "div|y1={:#x}|d64={:#x}|dfull={:#x}|dodd={:#x}|dvar={:#x}|rem={:#x}",
        nzm(&y1),
        nzm(&d64_out),
        nzm(&dfull_out),
        nzm(&dodd_out),
        nzm(&dvar_out),
        nzm(&rem_out),
    );
}

/// loopor: MULTIEQUAL loop clipping + phase-2 worklist fixed point with an
/// INT_LEFT on the loop-carried edge.
fn run_loop_or() {
    let mut fd = new_function("calcnzm");
    let b1 = fd.create_new_block();
    let b2 = fd.create_new_block();
    fd.bblocks.add_edge(b1.clone(), b2.clone());
    fd.bblocks.add_edge(b2.clone(), b2.clone());
    rudra::block::set_out_edge_flag_mirrored(
        &b2,
        0,
        rudra::block::edge_flags::F_LOOP_EDGE,
    );
    // Creation order (== alive order): shift, then phi.
    let (shift, shift_out) = new_output_op(&mut fd, &b2, OpCode::CPUI_INT_LEFT, 0x5050, 2, 4, false);
    let (phi, phi_out) = new_output_op(&mut fd, &b2, OpCode::CPUI_MULTIEQUAL, 0x5051, 2, 4, true);
    let cffff = fd.new_constant(4, 0xffff);
    fd.op_set_input(&phi, cffff, 0);
    fd.op_set_input(&phi, shift_out.clone(), 1);
    fd.op_set_input(&shift, phi_out.clone(), 0);
    let c8 = fd.new_constant(4, 8);
    fd.op_set_input(&shift, c8, 1);
    fd.calc_nz_mask();
    let b2g = b2.read().unwrap();
    println!(
        "loopor|loopin={},{}|phi={:#x}|shift={:#x}",
        u8::from(b2g.is_loop_in(0)),
        u8::from(b2g.is_loop_in(1)),
        nzm(&phi_out),
        nzm(&shift_out),
    );
}

/// loopand: the precision observable of clipping — INT_AND on the
/// loop-carried edge reaches a strictly tighter fixed point when the
/// looping edge is labeled than when it is not.
fn build_loop_and_graph(fd: &mut Funcdata, with_loop_edge: bool) -> (Vn, Vn) {
    let b1 = fd.create_new_block();
    let b2 = fd.create_new_block();
    fd.bblocks.add_edge(b1.clone(), b2.clone());
    fd.bblocks.add_edge(b2.clone(), b2.clone());
    if with_loop_edge {
        rudra::block::set_out_edge_flag_mirrored(
            &b2,
            0,
            rudra::block::edge_flags::F_LOOP_EDGE,
        );
    }
    // Creation order: and, then phi.
    let (and_op, and_out) = new_output_op(fd, &b2, OpCode::CPUI_INT_AND, 0x5060, 2, 4, false);
    let (phi, phi_out) = new_output_op(fd, &b2, OpCode::CPUI_MULTIEQUAL, 0x5061, 2, 4, true);
    let cff00 = fd.new_constant(4, 0xff00);
    fd.op_set_input(&phi, cff00, 0);
    fd.op_set_input(&phi, and_out.clone(), 1);
    fd.op_set_input(&and_op, phi_out.clone(), 0);
    let cf0f0 = fd.new_constant(4, 0xf0f0);
    fd.op_set_input(&and_op, cf0f0, 1);
    (phi_out, and_out)
}

fn run_loop_and() {
    let mut fd = new_function("calcnzm");
    let (phi_a, and_a) = build_loop_and_graph(&mut fd, true);
    fd.calc_nz_mask();
    print!("loopand|clipped={:#x},{:#x}", nzm(&phi_a), nzm(&and_a));
    let mut fd = new_function("calcnzm");
    let (phi_b, and_b) = build_loop_and_graph(&mut fd, false);
    fd.calc_nz_mask();
    println!("|plain={:#x},{:#x}", nzm(&phi_b), nzm(&and_b));
}

fn main() {
    run_init();
    run_and_copy();
    run_piece();
    run_div();
    run_loop_or();
    run_loop_and();
}
