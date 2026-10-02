// FUNCDATA-FWD-MUTATE-0001 bilateral fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_fwd_mutate_1204.cc case for case against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Exercises the Funcdata mutation forwarder family: mark_return_copy,
// op_mark_start_basic, op_mark_start_instruction, op_dead_insert_after,
// op_dead_and_gone, init_active_output/clear_active_output, clear_dead_ops.
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_INT_SUB => "INT_SUB",
        OpCode::CPUI_INT_MULT => "INT_MULT",
        _ => "OTHER",
    }
}

fn main() {
    let mut fd = Funcdata::new("fwd_mutate", Address::new(0x5000), 0x20);
    let b0: Arc<RwLock<BlockBasic>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x5000))));
    fd.bblocks.add_block(b0.clone());
    let b0_dyn: Arc<RwLock<dyn FlowBlock + Send + Sync>> = b0.clone();

    // case=mark_flags: the three flag-bit setters, projected as raw hex
    // flag words before/after each mutation.
    {
        let copy = fd.new_op(1, Address::new(0x5010));
        fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
        fd.op_insert_end(&copy, &b0_dyn);
        let b0 = { copy.0.read().unwrap().flags }
            & rudra::op::pcodeop_flags::RETURN_COPY
            != 0;
        fd.mark_return_copy(&copy);
        let b1 = { copy.0.read().unwrap().flags }
            & rudra::op::pcodeop_flags::RETURN_COPY
            != 0;
        fd.op_mark_start_basic(&copy);
        let b2 = { copy.0.read().unwrap().flags }
            & rudra::op::pcodeop_flags::STARTBASIC
            != 0;
        fd.op_mark_start_instruction(&copy);
        let b3 = { copy.0.read().unwrap().flags }
            & rudra::op::pcodeop_flags::STARTMARK
            != 0;
        println!(
            "case=mark_flags|ret_copy0={}|ret_copy1={}|block_start={}|instr_start={}",
            b0 as u8, b1 as u8, b2 as u8, b3 as u8
        );
    }

    // case=dead_insert: op_dead_insert_after reorders the dead list.
    {
        fn dead_order(fd: &Funcdata) -> String {
            fd.begin_op_dead()
                .map(|op| opcode_name(op.0.read().unwrap().opcode))
                .collect::<Vec<_>>()
                .join(",")
        }
        let d1 = fd.new_op(1, Address::new(0x6010));
        fd.op_set_opcode(&d1, OpCode::CPUI_INT_ADD);
        let d2 = fd.new_op(1, Address::new(0x6020));
        fd.op_set_opcode(&d2, OpCode::CPUI_INT_SUB);
        // Creation order puts d1 before d2; move d1 after d2.
        fd.op_dead_insert_after(&d1, &d2);
        let order = dead_order(&fd);
        // And back.
        fd.op_dead_insert_after(&d2, &d1);
        let order2 = dead_order(&fd);
        println!("case=dead_insert|swapped={order}|restored={order2}");
    }

    // case=dead_and_gone: destroy moves the op to retention and drops
    // every index (optree shrinks).
    {
        let d3 = fd.new_op(1, Address::new(0x6030));
        fd.op_set_opcode(&d3, OpCode::CPUI_INT_MULT);
        let optree_before = fd.begin_op_all().count();
        let dead_before = fd.begin_op_dead().count();
        fd.op_dead_and_gone(d3);
        let optree_after = fd.begin_op_all().count();
        let dead_after = fd.begin_op_dead().count();
        println!(
            "case=dead_and_gone|optree_before={optree_before}|optree_after={optree_after}|dead_before={dead_before}|dead_after={dead_after}"
        );
    }

    // case=active_output: init_active_output installs the ParamActive
    // recovery object; clear_active_output drops it.
    {
        fd.init_active_output();
        let present = fd.active_output.is_some();
        fd.clear_active_output();
        let cleared = fd.active_output.is_some();
        println!(
            "case=active_output|present={}|cleared={}",
            present as u8, cleared as u8
        );
    }

    // case=clear_dead_ops: clear_dead_ops empties the dead list.
    {
        let d4 = fd.new_op(2, Address::new(0x6040));
        fd.op_set_opcode(&d4, OpCode::CPUI_INT_OR);
        let dead_before = fd.begin_op_dead().count();
        fd.clear_dead_ops();
        let dead_after = fd.begin_op_dead().count();
        println!("case=clear_dead_ops|dead_before={dead_before}|dead_after={dead_after}");
    }
}
