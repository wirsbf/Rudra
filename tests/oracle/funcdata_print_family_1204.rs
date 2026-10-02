// FUNCDATA-PRINT-0001 bilateral fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_print_family_1204.cc case for case against
// the locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// print_raw (no-blocks branch + empty-bank error), print_local_range
// (empty + installed window), print_varnode_tree (def-order projection).
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::varmap::ScopeLocal;

fn main() {
    let mut fd = Funcdata::new("print_family", Address::new(0x5000), 0x20);
    let b0: Arc<RwLock<BlockBasic>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(b0.clone());
    let b0_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = b0.clone();

    // One alive COPY with output+input, one dead ADD (raw pre-block state).
    let copy = fd.new_op(1, Address::new(0x5010));
    fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
    fd.op_insert_end(&copy, &b0_dyn);
    fd.op_mark_start_instruction(&copy);
    fd.new_varnode_out_full(8, rudra::space::AddressSpace::Ram, Address::new(0x1000), &copy);
    let src = fd.new_varnode(8, Address::new(0x2000));
    fd.op_set_input(&copy, src, 0);
    let add = fd.new_op(2, Address::new(0x5020));
    fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);

    // case=print_raw_ops: the no-blocks raw text. A SECOND Funcdata holds
    // the ops with no basic block so print_raw takes the "Raw operations:"
    // branch (funcdata.cc:212-222).
    {
        let mut fd3 = Funcdata::new("print_noblocks", Address::new(0x7000), 0x20);
        let copy3 = fd3.new_op(1, Address::new(0x7010));
        fd3.op_set_opcode(&copy3, OpCode::CPUI_COPY);
        fd3.op_mark_start_instruction(&copy3);
        fd3.new_varnode_out_full(
            8,
            rudra::space::AddressSpace::Ram,
            Address::new(0x1100),
            &copy3,
        );
        let src3 = fd3.new_varnode(8, Address::new(0x2200));
        fd3.op_set_input(&copy3, src3, 0);
        let add3 = fd3.new_op(2, Address::new(0x7020));
        fd3.op_set_opcode(&add3, OpCode::CPUI_INT_ADD);
        let text = fd3.print_raw().unwrap_or_else(|e| format!("<err {e}>"));
        println!("case=print_raw_ops|begin\n{text}|end");
    }

    // case=print_raw_empty: empty bank maps RecovError onto Lowlevel.
    {
        let mut fd2 = Funcdata::new("print_empty", Address::new(0x6000), 0x20);
        let outcome = match fd2.print_raw() {
            Ok(_) => "no-throw".to_string(),
            Err(err) => err.to_string(),
        };
        println!("case=print_raw_empty|{outcome}");
    }

    // case=print_local_range: the fresh-ctor window (the oracle Funcdata
    // ctor runs resetLocalWindow over the default model, fspec.cc:2278/2303;
    // Rugra requires the explicit install — FUNCDATA-LOCALSCOPE-OWNERSHIP
    // -0001) then the same explicit stack window.
    {
        let mut scope = ScopeLocal::new();
        scope.space = rudra::space::AddressSpace::Stack;
        scope.local_range = vec![
            (0, 511),
            (0xFFFFFFFFFFFFFFFF - 999999, 0xFFFFFFFFFFFFFFFF),
        ];
        fd.scope = Some(scope);
        let ctor_text = fd.print_local_range();
        let window_text = fd.print_local_range();
        println!(
            "case=print_local_range|ctor_begin\n{ctor_text}|ctor_end|window_begin\n{window_text}|window_end"
        );
    }

    // case=print_varnode_tree: def-order iteration projected as the count
    // plus per-varnode def-class (input/written/free), keeping the full
    // print_info text out of the comparison (varnode.rs residual:
    // FUNCDATA-VARNODE-PRINTINFO-0001).
    {
        let _text = fd.print_varnode_tree();
        let mut count = 0usize;
        let mut classes: Vec<&'static str> = Vec::new();
        for def_ref in fd.begin_def() {
            let vn = def_ref.0.read().unwrap();
            if vn.is_input() {
                classes.push("i");
            } else if vn.is_written() {
                classes.push("w");
            } else {
                classes.push("f");
            }
            count += 1;
        }
        println!(
            "case=print_varnode_tree|count={count}|classes={}",
            classes.join(",")
        );
    }
}
