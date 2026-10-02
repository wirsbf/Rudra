//! RULE-SUBCOMMUTE-SDIV-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for the RuleSubCommute INT_SDIV/INT_SREM arm
//! (ruleaction.cc:4570-4602 + cancelExtensions cc:4483-4512 +
//! shortenExtension cc:4463-4472).
//!
//! Mirrors `rule_subcommute_sdiv_1204.cc` case-for-case (same names, same
//! observation format):
//!   case=<name>|sub_apply=<0/1>|passes=<n>
//!     op=<opcode#>|nin=<k>|in0=<c|w|o>|in0_size|in0_off>|out_size
//!   endcase
//!
//! After the single RuleSubCommute application the harness runs a bounded
//! RulePropagateCopy + RuleSubCancel + RuleCollapseConstants fixpoint in
//! sequence order — the oppool chain that folds the commuted short
//! division (RuleSubCancel turns SUB168(SEXT816(x),0) into COPY(x), cc
//! ruleaction.cc:5102-5199).
//!
//! Modes: `normal` (golden diff), `trap_sdiv`/`trap_srem` (INT64_MIN / -1:
//! the fold reaches the division opbehavior — Rust panics where the oracle
//! takes SIGFPE; form comparison only, KUNASDIV precedent).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::{RuleCollapseConstants, RulePropagateCopy, RuleSubCancel, RuleSubCommute};
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type VnRef = Arc<RwLock<Varnode>>;

fn constant_input(fd: &mut Funcdata, value: u64, size: usize) -> VnRef {
    fd.new_constant(size, value)
}

fn register_input(fd: &mut Funcdata, off: u64, size: usize) -> VnRef {
    let vn = fd
        .vbank
        .create_with_space(size, AddressSpace::Register, off);
    fd.vbank.set_input(vn).expect("set_input")
}

fn print_op_line(op: &rudra::op::PcodeOpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    // Ghidra's destroyed/mislinked slots read as null (op.cc:98 clearInput);
    // Rugra's shared null_slot_sentinel is the same observable — render as `_`.
    let in0 = g.get_in(0).filter(|v| {
        !std::sync::Arc::ptr_eq(*v, &rudra::op::null_slot_sentinel())
    });
    if let Some(in0) = in0 {
        let i = in0.read().unwrap();
        let cls = if i.is_constant() {
            'c'
        } else if i.is_written() {
            'w'
        } else {
            'o'
        };
        line += &format!("|in0={cls}|{}|0x{:x}", i.get_size(), i.get_offset());
    } else {
        line += "|in0=_|0|0x0";
    }
    let out_size = g
        .output
        .as_ref()
        .map(|v| v.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|{out_size}");
    println!("{line}");
}

fn dump_case_window(fd: &Funcdata, lo: u64, hi: u64) {
    for op in fd.begin_op_all() {
        let a = op.0.read().unwrap().get_addr().to_space_address().get_offset();
        if a < lo || hi < a {
            continue;
        }
        print_op_line(op);
    }
}

// One application of RuleSubCommute, then the bounded propagate+subcancel+
// collapse fixpoint in sequence order. Mirrors runChain in the .cc.
fn run_chain(fd: &mut Funcdata, name: &str, sub_op: &rudra::op::PcodeOpRef) {
    let sub_commute = RuleSubCommute::new();
    let apply = sub_commute.apply_op(&sub_op.0, fd).expect("subcommute apply");
    let propagate = RulePropagateCopy::new();
    let sub_cancel = RuleSubCancel::new();
    let collapse = RuleCollapseConstants::new();
    let mut passes = 0;
    for _pass in 0..8 {
        let mut changed = false;
        let snapshot: Vec<rudra::op::PcodeOpRef> =
            fd.begin_op_all().map(|o| o.clone()).collect();
        for op in snapshot {
            if op.0.read().unwrap().is_dead() {
                continue;
            }
            if propagate.apply_op(&op.0, fd).expect("propagate") != 0 {
                changed = true;
            }
            if op.0.read().unwrap().is_dead() {
                continue;
            }
            // RuleSubCancel registers CPUI_SUBPIECE only (ruleaction.cc:5116);
            // the ActionPool filters by getOpList, so the harness must too.
            if op.0.read().unwrap().opcode == OpCode::CPUI_SUBPIECE
                && sub_cancel.apply_op(&op.0, fd).expect("subcancel") != 0
            {
                changed = true;
            }
            if op.0.read().unwrap().is_dead() {
                continue;
            }
            if collapse.apply_op(&op.0, fd).expect("collapse") != 0 {
                changed = true;
            }
        }
        passes += 1;
        if !changed {
            break;
        }
    }
    println!("case={name}|sub_apply={apply}|passes={passes}");
}

// ---- case builders (mirror the .cc builders 1:1) --------------------------

fn both_sext_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    in0_val: u64,
    in1_val: u64,
    ext_in_size: usize,
    long_size: usize,
    out_size: usize,
    offset: u64,
    constant_inputs: bool,
    reg_off: u64,
) -> rudra::op::PcodeOpRef {
    let ext_ins: Vec<VnRef> = (0..2)
        .map(|slot| {
            let val = if slot == 0 { in0_val } else { in1_val };
            if constant_inputs {
                constant_input(fd, val, ext_in_size)
            } else {
                register_input(fd, reg_off + 0x8 * slot as u64, ext_in_size)
            }
        })
        .collect();
    let mut ext_ops = Vec::new();
    for slot in 0..2 {
        let ext_op = fd.new_op(1, Address::new(base + 0x10 * (slot as u64 + 1)));
        fd.op_set_opcode(&ext_op, OpCode::CPUI_INT_SEXT);
        fd.new_unique_out(long_size, &ext_op);
        fd.op_set_input(&ext_op, ext_ins[slot].clone(), 0);
        fd.op_insert_end(&ext_op, block);
        ext_ops.push(ext_op);
    }
    let longform = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(long_size, &longform);
    fd.op_set_input(
        &longform,
        ext_ops[0].0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    fd.op_set_input(
        &longform,
        ext_ops[1].0.read().unwrap().output.as_ref().unwrap().clone(),
        1,
    );
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(out_size, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let off_const = fd.new_constant(4, offset);
    fd.op_set_input(&sub_op, off_const, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

fn const_divisor_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    in0_val: u64,
    ext_in_size: usize,
    divisor: u64,
    const_size: usize,
    long_size: usize,
    out_size: usize,
) -> rudra::op::PcodeOpRef {
    let ext_op = fd.new_op(1, Address::new(base + 0x10));
    fd.op_set_opcode(&ext_op, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(long_size, &ext_op);
    let c_arg = constant_input(fd, in0_val, ext_in_size);
    fd.op_set_input(&ext_op, c_arg, 0);
    fd.op_insert_end(&ext_op, block);
    let longform = fd.new_op(2, Address::new(base + 0x20));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(long_size, &longform);
    fd.op_set_input(
        &longform,
        ext_op.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let c_arg = constant_input(fd, divisor, const_size);
    fd.op_set_input(&longform, c_arg, 1);
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(out_size, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let zero_off = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero_off, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

fn zext_in0_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    in0_val: u64,
    in1_val: u64,
) -> rudra::op::PcodeOpRef {
    let zext0 = fd.new_op(1, Address::new(base + 0x10));
    fd.op_set_opcode(&zext0, OpCode::CPUI_INT_ZEXT);
    fd.new_unique_out(16, &zext0);
    let c_arg = constant_input(fd, in0_val, 8);
    fd.op_set_input(&zext0, c_arg, 0);
    fd.op_insert_end(&zext0, block);
    let sext1 = fd.new_op(1, Address::new(base + 0x20));
    fd.op_set_opcode(&sext1, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(16, &sext1);
    let c_arg = constant_input(fd, in1_val, 8);
    fd.op_set_input(&sext1, c_arg, 0);
    fd.op_insert_end(&sext1, block);
    let longform = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(16, &longform);
    fd.op_set_input(
        &longform,
        zext0.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    fd.op_set_input(
        &longform,
        sext1.0.read().unwrap().output.as_ref().unwrap().clone(),
        1,
    );
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(8, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let zero_off = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero_off, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

fn copy_in1_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    in0_val: u64,
    in1_val: u64,
) -> rudra::op::PcodeOpRef {
    let sext0 = fd.new_op(1, Address::new(base + 0x10));
    fd.op_set_opcode(&sext0, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(16, &sext0);
    let c_arg = constant_input(fd, in0_val, 8);
    fd.op_set_input(&sext0, c_arg, 0);
    fd.op_insert_end(&sext0, block);
    let copy1 = fd.new_op(1, Address::new(base + 0x20));
    fd.op_set_opcode(&copy1, OpCode::CPUI_COPY);
    fd.new_unique_out(16, &copy1);
    let c_arg = constant_input(fd, in1_val, 16);
    fd.op_set_input(&copy1, c_arg, 0);
    fd.op_insert_end(&copy1, block);
    let longform = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(16, &longform);
    fd.op_set_input(
        &longform,
        sext0.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    fd.op_set_input(
        &longform,
        copy1.0.read().unwrap().output.as_ref().unwrap().clone(),
        1,
    );
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(8, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let zero_off = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero_off, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

fn reg_in1_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    in0_val: u64,
    reg_off: u64,
) -> rudra::op::PcodeOpRef {
    let sext0 = fd.new_op(1, Address::new(base + 0x10));
    fd.op_set_opcode(&sext0, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(16, &sext0);
    let c_arg = constant_input(fd, in0_val, 8);
    fd.op_set_input(&sext0, c_arg, 0);
    fd.op_insert_end(&sext0, block);
    let longform = fd.new_op(2, Address::new(base + 0x20));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(16, &longform);
    fd.op_set_input(
        &longform,
        sext0.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let reg_arg = register_input(fd, reg_off, 8);
    fd.op_set_input(&longform, reg_arg, 1);
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(8, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let zero_off = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero_off, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

fn unequal_partial_case(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    opc: OpCode,
    base: u64,
    reg_off: u64,
) -> rudra::op::PcodeOpRef {
    let ext0 = fd.new_op(1, Address::new(base + 0x10));
    fd.op_set_opcode(&ext0, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(16, &ext0);
    let reg_arg = register_input(fd, reg_off, 4);
    fd.op_set_input(&ext0, reg_arg, 0);
    fd.op_insert_end(&ext0, block);
    let ext1 = fd.new_op(1, Address::new(base + 0x20));
    fd.op_set_opcode(&ext1, OpCode::CPUI_INT_SEXT);
    fd.new_unique_out(16, &ext1);
    let reg_arg = register_input(fd, reg_off + 0x8, 8);
    fd.op_set_input(&ext1, reg_arg, 0);
    fd.op_insert_end(&ext1, block);
    let longform = fd.new_op(2, Address::new(base + 0x30));
    fd.op_set_opcode(&longform, opc);
    fd.new_unique_out(16, &longform);
    fd.op_set_input(
        &longform,
        ext0.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    fd.op_set_input(
        &longform,
        ext1.0.read().unwrap().output.as_ref().unwrap().clone(),
        1,
    );
    fd.op_insert_end(&longform, block);
    let sub_op = fd.new_op(2, Address::new(base + 0x40));
    fd.op_set_opcode(&sub_op, OpCode::CPUI_SUBPIECE);
    fd.new_unique_out(4, &sub_op);
    fd.op_set_input(
        &sub_op,
        longform.0.read().unwrap().output.as_ref().unwrap().clone(),
        0,
    );
    let zero_off = fd.new_constant(4, 0);
    fd.op_set_input(&sub_op, zero_off, 1);
    fd.op_insert_end(&sub_op, block);
    sub_op
}

#[derive(Clone, Copy)]
struct CaseSpec {
    name: &'static str,
    base: u64,
    kind: u8,
    opc: u8,
    in0: u64,
    in1: u64,
    ext_in_size: usize,
    const_size: usize,
    long_size: usize,
    out_size: usize,
    offset: u64,
    reg_off: u64,
}

fn opc_of(spec: &CaseSpec) -> OpCode {
    if spec.opc == 0 {
        OpCode::CPUI_INT_SDIV
    } else {
        OpCode::CPUI_INT_SREM
    }
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(block.clone());

    let cases: Vec<CaseSpec> = vec![
        CaseSpec { name: "sdiv_written_fold", base: 0x500000, kind: 0, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "srem_written_fold", base: 0x500100, kind: 0, opc: 1, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_pos_divisor", base: 0x500200, kind: 0, opc: 0, in0: 100, in1: 7, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_w4_sext_written", base: 0x500300, kind: 0, opc: 0, in0: 0xfffffff9, in1: 100, ext_in_size: 4, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_const_fit_w4", base: 0x500400, kind: 2, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 4, const_size: 8, long_size: 8, out_size: 4, offset: 0, reg_off: 0 },
        CaseSpec { name: "srem_const_fit_w4", base: 0x500500, kind: 2, opc: 1, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 4, const_size: 8, long_size: 8, out_size: 4, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_const_sign_mismatch", base: 0x500600, kind: 2, opc: 0, in0: 100, in1: 0x00000000ffffff80, ext_in_size: 4, const_size: 8, long_size: 8, out_size: 4, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_const_high_bits", base: 0x500700, kind: 2, opc: 0, in0: 100, in1: 0x100000080, ext_in_size: 4, const_size: 8, long_size: 8, out_size: 4, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_offset_nonzero", base: 0x500800, kind: 7, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 8, reg_off: 0 },
        CaseSpec { name: "sdiv_in0_zext", base: 0x500900, kind: 3, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_in1_copy", base: 0x500a00, kind: 4, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_in1_reginput", base: 0x500b00, kind: 5, opc: 0, in0: 100, in1: 0, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0x240 },
        CaseSpec { name: "sdiv_partial_equal", base: 0x500c00, kind: 1, opc: 0, in0: 0, in1: 0, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 4, offset: 0, reg_off: 0x200 },
        CaseSpec { name: "srem_partial_equal", base: 0x500d00, kind: 1, opc: 1, in0: 0, in1: 0, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 4, offset: 0, reg_off: 0x230 },
        CaseSpec { name: "sdiv_partial_const_ext", base: 0x500e00, kind: 0, opc: 0, in0: 100, in1: 0xfffffffffffffff9, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 4, offset: 0, reg_off: 0 },
        CaseSpec { name: "sdiv_partial_unequal", base: 0x500f00, kind: 6, opc: 0, in0: 0, in1: 0, ext_in_size: 0, const_size: 0, long_size: 16, out_size: 4, offset: 0, reg_off: 0x260 },
    ];

    let mode = std::env::args().nth(1).unwrap_or_default();
    let run_cases: Vec<CaseSpec> = if mode == "trap_sdiv" || mode == "trap_srem" {
        let opc = if mode == "trap_sdiv" { 0 } else { 1 };
        vec![CaseSpec { name: "trap", base: 0x600000, kind: 0, opc, in0: 0x8000000000000000, in1: 0xffffffffffffffff, ext_in_size: 8, const_size: 0, long_size: 16, out_size: 8, offset: 0, reg_off: 0 }]
    } else if mode == "normal" {
        cases
    } else {
        eprintln!("unknown mode: {mode}");
        std::process::exit(2);
    };

    for spec in run_cases {
        let base = spec.base;
        let sub_op = match spec.kind {
            0 => both_sext_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.in1,
                                spec.ext_in_size, spec.long_size, spec.out_size, spec.offset,
                                true, spec.reg_off),
            1 => both_sext_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.in1,
                                spec.ext_in_size, spec.long_size, spec.out_size, spec.offset,
                                false, spec.reg_off),
            2 => const_divisor_case(&mut fd, &block, opc_of(&spec), base, spec.in0,
                                    spec.ext_in_size, spec.in1, spec.const_size, spec.long_size,
                                    spec.out_size),
            3 => zext_in0_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.in1),
            4 => copy_in1_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.in1),
            5 => reg_in1_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.reg_off),
            6 => unequal_partial_case(&mut fd, &block, opc_of(&spec), base, spec.reg_off),
            7 => both_sext_case(&mut fd, &block, opc_of(&spec), base, spec.in0, spec.in1,
                                spec.ext_in_size, spec.long_size, spec.out_size, spec.offset,
                                true, spec.reg_off),
            _ => unreachable!("kind"),
        };
        // case= line printed by run_chain (single combined line, .cc format).
        run_chain(&mut fd, spec.name, &sub_op);
        dump_case_window(&fd, base, base + 0x80);
        println!("endcase");
    }
}

fn main() {
    run();
}
