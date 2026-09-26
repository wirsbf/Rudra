//! RULE-BOOLEANDEDUP-ISMATCH-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for `RuleBooleanDedup::applyOp` pairing/flipped-form semantics —
//! `isMatch` (ruleaction.cc:2817-2831 -> BooleanMatch::evaluate,
//! expression.cc:111-216), WORKPKG-UNMAP-RULEADJ-0013.
//!
//! Mirrors `rule_booleandedup_ismatch_1204.cc` case-for-case (same names,
//! same observation format):
//!   case=<name>|bd_apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
//!   endcase
//!
//! Witness value: pair (0,3) and (1,2) cases lock the leftO/rightO "other
//! input" slot selection (oracle leftO = op0's 1-ai, rightO = op1's 5-bi);
//! complement folds lock the isflipped forms (COPY(#0)/COPY(#1)/mixed OR).

use std::sync::{Arc, RwLock};

use rugra::action::Rule;
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;
use rugra::ruleaction::RuleBooleanDedup;
use rugra::varnode::Varnode;

type VnRef = Arc<RwLock<Varnode>>;
type OpRef = rugra::op::PcodeOpRef;

fn vn_class(vn: Option<&VnRef>) -> char {
    match vn {
        None => '_',
        Some(v) => {
            let v = v.read().unwrap();
            if v.is_constant() {
                'c'
            } else if v.is_written() {
                'w'
            } else {
                'o'
            }
        }
    }
}

fn print_op_line(op: &OpRef) {
    let g = op.0.read().unwrap();
    let addr = g.get_addr().to_space_address().get_offset();
    let mut line = format!("  op={}@0x{:x}|nin={}", g.opcode as i32, addr, g.num_input());
    let sentinel = rugra::op::null_slot_sentinel();
    for i in 0..2 {
        let vn = g.get_in(i).filter(|v| !Arc::ptr_eq(*v, &sentinel));
        match vn {
            Some(v) => {
                let r = v.read().unwrap();
                line += &format!(
                    "|in{i}={}|{}|0x{:x}",
                    vn_class(Some(&v)),
                    r.get_size(),
                    r.get_offset()
                );
            }
            None => line += &format!("|in{i}=_|0|0x0"),
        }
    }
    let out_size = g
        .output
        .as_ref()
        .map(|v| v.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|out={out_size}");
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

struct Atoms {
    a: VnRef,
    b: VnRef,
    c: VnRef,
    d: VnRef,
    na: VnRef,
    nb: VnRef,
}

/// Builds the per-case atoms in a fixed construction order so unique-space
/// offsets are deterministic: x1..x4 COPYs, A..D INT_LESS, nA/nB BOOL_NEGATE.
fn build_atoms(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    b: u64,
) -> Atoms {
    let xvals: [u64; 4] = [0x11, 0x22, 0x33, 0x44];
    let cvals: [u64; 4] = [5, 7, 9, 11];
    let mut xs: Vec<VnRef> = Vec::new();
    for k in 0..4 {
        let w = fd.new_op(1, Address::new(b + 0x10 + 0x4 * k as u64));
        fd.op_set_opcode(&w, OpCode::CPUI_COPY);
        let x = fd.new_unique_out(8, &w);
        let c = fd.new_constant(8, xvals[k]);
        fd.op_set_input(&w, c, 0);
        fd.op_insert_end(&w, block);
        xs.push(x);
    }
    let mut less: Vec<VnRef> = Vec::new();
    for k in 0..4 {
        let l = fd.new_op(2, Address::new(b + 0x20 + 0x4 * k as u64));
        fd.op_set_opcode(&l, OpCode::CPUI_INT_LESS);
        let out = fd.new_unique_out(1, &l);
        fd.op_set_input(&l, xs[k].clone(), 0);
        let c = fd.new_constant(8, cvals[k]);
        fd.op_set_input(&l, c, 1);
        fd.op_insert_end(&l, block);
        less.push(out);
    }
    let n1 = fd.new_op(1, Address::new(b + 0x30));
    fd.op_set_opcode(&n1, OpCode::CPUI_BOOL_NEGATE);
    let na = fd.new_unique_out(1, &n1);
    fd.op_set_input(&n1, less[0].clone(), 0);
    fd.op_insert_end(&n1, block);
    let n2 = fd.new_op(1, Address::new(b + 0x34));
    fd.op_set_opcode(&n2, OpCode::CPUI_BOOL_NEGATE);
    let nb = fd.new_unique_out(1, &n2);
    fd.op_set_input(&n2, less[1].clone(), 0);
    fd.op_insert_end(&n2, block);
    Atoms {
        a: less[0].clone(),
        b: less[1].clone(),
        c: less[2].clone(),
        d: less[3].clone(),
        na,
        nb,
    }
}

fn bool_pair(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    addr: u64,
    opc: OpCode,
    l: VnRef,
    r: VnRef,
) -> OpRef {
    let op = fd.new_op(2, Address::new(addr));
    fd.op_set_opcode(&op, opc);
    fd.new_unique_out(1, &op);
    fd.op_set_input(&op, l, 0);
    fd.op_set_input(&op, r, 1);
    fd.op_insert_end(&op, block);
    op
}

const NAMES: [&str; 12] = [
    "dedup_and",
    "dedup_or",
    "cross_and_or",
    "flip_and0",
    "flip_or1",
    "flip_or_mixed",
    "flip_or_mixed_swap",
    "demorgan",
    "pair_03",
    "pair_12",
    "uncorr",
    "flip_and_mixed_rej",
];

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x7000))));
    fd.bblocks.add_block(block.clone());

    for ci in 0..12u64 {
        let b = 0x710000 + 0x100 * ci;
        let at = build_atoms(&mut fd, &block, b);
        let (op0, op1, central) = match ci {
            0 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.a.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
            1 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_OR, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_OR, at.a.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            2 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.a.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            3 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.na.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
            4 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_OR, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_OR, at.na.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            5 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_OR, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.na.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            6 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.na.clone(), at.c.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_OR, at.a.clone(), at.b.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            7 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_OR, at.na.clone(), at.nb.clone()),
                OpCode::CPUI_BOOL_OR,
            ),
            8 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.c.clone(), at.a.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
            9 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.c.clone(), at.b.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
            10 => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_AND, at.c.clone(), at.d.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
            _ => (
                bool_pair(&mut fd, &block, b + 0x40, OpCode::CPUI_BOOL_AND, at.a.clone(), at.b.clone()),
                bool_pair(&mut fd, &block, b + 0x44, OpCode::CPUI_BOOL_OR, at.na.clone(), at.c.clone()),
                OpCode::CPUI_BOOL_AND,
            ),
        };
        let op0_out = op0.0.read().unwrap().output.as_ref().unwrap().clone();
        let op1_out = op1.0.read().unwrap().output.as_ref().unwrap().clone();
        let central_op = bool_pair(&mut fd, &block, b + 0x48, central, op0_out, op1_out);
        let rule = RuleBooleanDedup::new();
        let apply = rule.apply_op(&central_op.0, &mut fd).expect("dedup apply");
        println!("case={}|bd_apply={apply}", NAMES[ci as usize]);
        dump_case_window(&fd, b, b + 0x100);
        println!("endcase");
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "normal" {
        eprintln!("unknown mode: {mode}");
        std::process::exit(2);
    }
    run();
}
