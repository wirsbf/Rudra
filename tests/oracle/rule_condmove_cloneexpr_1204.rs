//! RULEACTION-CLONEBLOCKOPS-0001: Rugra side of the locked 12.0.4 oracle
//! fixture for `RuleConditionalMove::constructBool` (ruleaction.cc:9328-9341)
//! driving the compareOp sort (ruleaction.hh:1433) and
//! `CloneBlockOps::cloneExpression` (funcdata_block.cc:1024-1040) on the
//! non-const BOOL_AND/BOOL_OR rewrite paths.
//!
//! Mirrors `rule_condmove_cloneexpr_1204.cc` case-for-case (same names,
//! same observation format):
//!   case=<name>|apply=<0/1>
//!     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<size>|0x<off>|in1=...|out=<n>
//!   endcase
//!
//! Boolean producers are comparison ops (INT_LESS/INT_EQUAL/INT_SLESS):
//! their opcode ctor flags carry `booloutput` on both sides, which the
//! checkBoolean gate (cc:9259-9276) requires. Cloned ops reuse the
//! original op address (buildOpClone → `Funcdata::newOp(numInput, addr)`,
//! funcdata_block.cc:970) and the cloned output reuses the original output
//! storage (`CloneBlockOps::buildVarnodeOutput` →
//! `Funcdata::new_varnode_out_full(size, space, origAddr, cloneOp)`,
//! funcdata_block.cc:988).

use std::sync::{Arc, RwLock};

use rugra::action::Rule;
use rugra::address::Address;
use rugra::arch::Architecture;
use rugra::block::{BlockBasic, FlowBlock};
use rugra::funcdata::Funcdata;
use rugra::opcodes::OpCode;
use rugra::ruleaction::RuleConditionalMove;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn vn_class(vn: Option<&Arc<RwLock<rugra::varnode::Varnode>>>) -> char {
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

fn print_op_line(op: &rugra::op::PcodeOpRef) {
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
                    "|in{}={}|{}|0x{:x}",
                    i,
                    vn_class(Some(v)),
                    r.get_size(),
                    r.get_offset()
                );
            }
            None => {
                line += &format!("|in{}=_|0|0x0", i);
            }
        }
    }
    let out_size = g
        .output
        .as_ref()
        .map(|o| o.read().unwrap().get_size() as i64)
        .unwrap_or(-1);
    line += &format!("|out={}\n", out_size);
    print!("{}", line);
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

/// Build a 1-byte boolean comparison op at `addr` inside `blk` reading two
/// constants. Comparison opcodes carry `booloutput` via `opcode_flags`
/// (typeop.cc ctor opflags), which `op_set_opcode` copies onto the op —
/// the checkBoolean gate requires it.
fn build_bool_op(
    fd: &mut Funcdata,
    blk: &BlockRef,
    addr: Address,
    opc: OpCode,
    cv0: u64,
    cv1: u64,
) -> rugra::op::PcodeOpRef {
    let op = fd.new_op(2, addr);
    fd.op_set_opcode(&op, opc);
    let out = fd.new_unique_out(1, &op);
    let c0 = fd.new_constant(1, cv0);
    fd.op_set_input(&op, c0, 0);
    let c1 = fd.new_constant(1, cv1);
    fd.op_set_input(&op, c1, 1);
    fd.op_insert_end(&op, blk);
    let _ = out;
    op
}

fn run() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    fd.set_arch(Arc::new(architecture));

    let case_names = [
        "clone_or_root_in0",
        "clone_and_negate",
        "clone_via_root_in1",
        "no_clone_pre_branch",
        "reject_no_cbranch",
    ];

    let rule = RuleConditionalMove::new();
    for ci in 0..5usize {
        let base = 0x830000 + 0x100 * ci as u64;
        let root: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base))));
        let bb: BlockRef = Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base + 0x70))));
        fd.bblocks.add_block(root.clone());
        fd.bblocks.add_block(bb.clone());
        let mut bool0 = None;
        let mut bool1 = None;
        let mut cond_vn = None;

        if ci == 0 || ci == 1 || ci == 4 {
            // root(=inblock0) --out0--> b1 --out1--> bb; b1 --> bb.
            let b1: BlockRef =
                Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base + 0x50))));
            fd.bblocks.add_block(b1.clone());
            fd.bblocks.add_edge(root.clone(), b1.clone()); // root out0 = b1
            fd.bblocks.add_edge(root.clone(), bb.clone()); // root out1 = bb, bb in0 = root
            fd.bblocks.add_edge(b1.clone(), bb.clone()); // bb in1 = b1
            let b0op = build_bool_op(&mut fd, &root, Address::new(base + 0x10), OpCode::CPUI_INT_LESS, 1, 0);
            bool0 = b0op.0.read().unwrap().output.clone();
            if ci == 1 {
                // BOOL_NEGATE(bool0) in root; CBRANCH cond = negate output.
                let neg = fd.new_op(1, Address::new(base + 0x18));
                fd.op_set_opcode(&neg, OpCode::CPUI_BOOL_NEGATE);
                fd.new_unique_out(1, &neg);
                fd.op_set_input(&neg, bool0.clone().unwrap(), 0);
                fd.op_insert_end(&neg, &root);
                cond_vn = neg.0.read().unwrap().output.clone();
            } else {
                cond_vn = bool0.clone();
            }
            let b1op = build_bool_op(&mut fd, &b1, Address::new(base + 0x50), OpCode::CPUI_INT_EQUAL, 0, 1);
            bool1 = b1op.0.read().unwrap().output.clone();
        } else if ci == 2 {
            // root --out0--> b0 --out1--> bb; b0 --> bb (bb in0 = b0,
            // bb in1 = root).
            let b0: BlockRef =
                Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base + 0x50))));
            fd.bblocks.add_block(b0.clone());
            fd.bblocks.add_edge(root.clone(), b0.clone()); // root out0 = b0
            fd.bblocks.add_edge(b0.clone(), bb.clone()); // bb in0 = b0
            fd.bblocks.add_edge(root.clone(), bb.clone()); // root out1 = bb, bb in1 = root
            let b1op = build_bool_op(&mut fd, &root, Address::new(base + 0x10), OpCode::CPUI_INT_EQUAL, 1, 0);
            bool1 = b1op.0.read().unwrap().output.clone();
            let b0op = build_bool_op(&mut fd, &b0, Address::new(base + 0x50), OpCode::CPUI_INT_SLESS, 0, 1);
            bool0 = b0op.0.read().unwrap().output.clone();
            cond_vn = bool1.clone();
        } else {
            // p0 --> root; root --out0--> b1 --out1--> bb; b1 --> bb.
            // Both booleans formed in p0 (before the branch).
            let p0: BlockRef =
                Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base))));
            let b1: BlockRef =
                Arc::new(RwLock::new(BlockBasic::new(0, Address::new(base + 0x50))));
            fd.bblocks.add_block(p0.clone());
            fd.bblocks.add_block(b1.clone());
            fd.bblocks.add_edge(p0.clone(), root.clone());
            fd.bblocks.add_edge(root.clone(), b1.clone());
            fd.bblocks.add_edge(root.clone(), bb.clone());
            fd.bblocks.add_edge(b1.clone(), bb.clone());
            let b0op = build_bool_op(&mut fd, &p0, Address::new(base + 0x08), OpCode::CPUI_INT_LESS, 1, 0);
            bool0 = b0op.0.read().unwrap().output.clone();
            let b1op = build_bool_op(&mut fd, &p0, Address::new(base + 0x0c), OpCode::CPUI_INT_EQUAL, 0, 1);
            bool1 = b1op.0.read().unwrap().output.clone();
            cond_vn = bool0.clone();
        }

        // Root terminator: CBRANCH(cond) for cases 0-3, INT_ADD for case 4.
        if ci != 4 {
            let cbr = fd.new_op(2, Address::new(base + 0x30));
            fd.op_set_opcode(&cbr, OpCode::CPUI_CBRANCH);
            let target = fd.new_constant(8, base + 0x70);
            fd.op_set_input(&cbr, target, 0);
            fd.op_set_input(&cbr, cond_vn.unwrap(), 1);
            fd.op_insert_end(&cbr, &root);
        } else {
            let tail = fd.new_op(2, Address::new(base + 0x30));
            fd.op_set_opcode(&tail, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(1, &tail);
            fd.op_set_input(&tail, cond_vn.unwrap(), 0);
            let one = fd.new_constant(1, 1);
            fd.op_set_input(&tail, one, 1);
            fd.op_insert_end(&tail, &root);
        }

        // MULTIEQUAL(bool0, bool1) in bb.
        let multi = fd.new_op(2, Address::new(base + 0x70));
        fd.op_set_opcode(&multi, OpCode::CPUI_MULTIEQUAL);
        fd.new_unique_out(1, &multi);
        fd.op_set_input(&multi, bool0.unwrap(), 0);
        fd.op_set_input(&multi, bool1.unwrap(), 1);
        fd.op_insert_end(&multi, &bb);

        let apply = rule.apply_op(&multi.0, &mut fd).unwrap();
        println!("case={}|apply={}", case_names[ci], apply);
        dump_case_window(&fd, base, base + 0x80);
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
