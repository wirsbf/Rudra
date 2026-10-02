// VARNODE-ADDDESCEND-THROW-0001 (op_insert_input 收编子项) fixture — Rust side.
//
// Mirrors tests/oracle/funcdata_op_insert_input_1204.cc line for line against
// the locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Funcdata::op_insert_input is the port of Funcdata::opInsertInput
// (funcdata_op.cc:308-317): slot expansion (PcodeOp::insertInput op.cc:311-318)
// followed by the FULL op_set_input path — const dedup, addDescend free-check
// (the panic channel of Ghidra's LowlevelError, caught via catch_unwind with a
// silenced hook so stderr stays empty) and coverdirty bookkeeping.
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::varnode::Varnode;

fn catch_insert_input_error(
    fd: &mut Funcdata,
    op: &PcodeOpRef,
    vn: &Arc<RwLock<Varnode>>,
    slot: usize,
) -> String {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fd.op_insert_input(op, vn.clone(), slot);
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(()) => String::new(),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic payload".to_string()),
    }
}

/// Read a Varnode tolerating lock poisoning: the caught op_insert_input panic
/// unwinds through the held write guard, poisoning the RwLock — a Rust
/// unwinding-lock artifact with no Ghidra counterpart; the underlying Varnode
/// state is exactly what the oracle observes after its caught LowlevelError.
fn read_vn(vn: &Arc<RwLock<Varnode>>) -> std::sync::RwLockReadGuard<'_, Varnode> {
    vn.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn count_descends(vn: &Arc<RwLock<Varnode>>) -> usize {
    read_vn(vn).count_descends()
}

fn in_offset(op: &PcodeOpRef, slot: usize) -> u64 {
    op.0.read().unwrap().inrefs[slot].read().unwrap().get_offset()
}

fn main() {
    let mut fd = Funcdata::new("insert_input", Address::new(0x5000), 0x20);

    // shift: [reg] -> insert zero-const at 0 -> [zero, reg].
    let sub = fd.new_op(0, Address::new(0x5010));
    fd.op_set_opcode(&sub, OpCode::CPUI_INT_SUB);
    let reg_vn = fd.new_varnode(8, Address::new(0x4444));
    fd.op_insert_input(&sub, reg_vn.clone(), 0);
    let zero_vn = fd.new_constant(8, 0);
    fd.op_insert_input(&sub, zero_vn.clone(), 0);
    println!(
        "shift:numInput={},in0={:x},in1={:x},regdesc={},zeroflags={}",
        sub.0.read().unwrap().num_input(),
        in_offset(&sub, 0),
        in_offset(&sub, 1),
        count_descends(&reg_vn),
        zero_vn.read().unwrap().flags,
    );

    // middle: [a] -> append b at len -> [a,b] -> insert c at 1 -> [a,c,b].
    let add = fd.new_op(0, Address::new(0x5020));
    fd.op_set_opcode(&add, OpCode::CPUI_INT_ADD);
    let a_vn = fd.new_varnode(8, Address::new(0x1110));
    let b_vn = fd.new_varnode(8, Address::new(0x1118));
    fd.op_insert_input(&add, a_vn, 0);
    fd.op_insert_input(&add, b_vn.clone(), 1);
    let c_vn = fd.new_constant(8, 0x2222);
    fd.op_insert_input(&add, c_vn, 1);
    println!(
        "middle:numInput={},in0={:x},in1={:x},in2={:x},bdesc={}",
        add.0.read().unwrap().num_input(),
        in_offset(&add, 0),
        in_offset(&add, 1),
        in_offset(&add, 2),
        count_descends(&b_vn),
    );

    // same_vn: input Varnode in two slots of one op -> two descend entries.
    let twice = fd.new_op(0, Address::new(0x5030));
    fd.op_set_opcode(&twice, OpCode::CPUI_INT_ADD);
    let iv = fd.new_varnode(8, Address::new(0x2300));
    let iv = fd.set_input_varnode(iv);
    fd.op_insert_input(&twice, iv.clone(), 0);
    fd.op_insert_input(&twice, iv.clone(), 1);
    {
        let op = twice.0.read().unwrap();
        println!(
            "same_vn:numInput={},slot0_same={},slot1_same={},desc={}",
            op.num_input(),
            u8::from(op.get_in(0).is_some_and(|v| Arc::ptr_eq(v, &iv))),
            u8::from(op.get_in(1).is_some_and(|v| Arc::ptr_eq(v, &iv))),
            count_descends(&iv),
        );
    }

    // const_dedup: shared constant cloned on the second insert (cc:108-115).
    let k1 = fd.new_op(0, Address::new(0x5040));
    fd.op_set_opcode(&k1, OpCode::CPUI_COPY);
    let k2 = fd.new_op(0, Address::new(0x5041));
    fd.op_set_opcode(&k2, OpCode::CPUI_COPY);
    let k_vn = fd.new_constant(4, 0x33);
    fd.op_insert_input(&k1, k_vn.clone(), 0);
    let before = fd.vbank.num_varnodes();
    fd.op_insert_input(&k2, k_vn.clone(), 0);
    let after = fd.vbank.num_varnodes();
    {
        let k2_in0 = k2.0.read().unwrap().inrefs[0].clone();
        println!(
            "const_dedup:distinct={},offset={:x},origdesc={},clonedesc={},vndelta={}",
            u8::from(!Arc::ptr_eq(&k2_in0, &k_vn)),
            read_vn(&k2_in0).get_offset(),
            count_descends(&k_vn),
            count_descends(&k2_in0),
            after - before,
        );
    }

    // free_first + free_second_throw: free Varnode's second insert panics
    // (Ghidra: LowlevelError) inside op_set_input->add_descend before
    // push/flags.
    let f1 = fd.new_op(0, Address::new(0x5050));
    fd.op_set_opcode(&f1, OpCode::CPUI_COPY);
    let f2 = fd.new_op(0, Address::new(0x5051));
    fd.op_set_opcode(&f2, OpCode::CPUI_COPY);
    let free_vn = fd.new_varnode(8, Address::new(0x2200));
    fd.op_insert_input(&f1, free_vn.clone(), 0);
    println!(
        "free_first:desc={},flags={}",
        count_descends(&free_vn),
        read_vn(&free_vn).flags,
    );
    let free_error = catch_insert_input_error(&mut fd, &f2, &free_vn, 0);
    println!(
        "free_second_throw:error={free_error},desc={},flags={}",
        count_descends(&free_vn),
        read_vn(&free_vn).flags,
    );
}
