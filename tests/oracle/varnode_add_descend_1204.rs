// VARNODE-ADDDESCEND-THROW-0001 fixture — Rust side.
//
// Mirrors tests/oracle/varnode_add_descend_1204.cc line for line against the
// locked oracle (Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b).
// Varnode::add_descend is the port of Varnode::addDescend (varnode.cc:330-340):
// the LowlevelError throw is modeled as a panic with the identical message,
// caught here via catch_unwind so both sides print the same observation line.
use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::{varnode_flags, VarnodeBank};

fn catch_add_descend_error(vn: &Arc<RwLock<rudra::varnode::Varnode>>, op: &Arc<RwLock<PcodeOp>>) -> String {
    // The C++ side catches LowlevelError; Rudra's counterpart channel is a
    // panic with the identical message text. Silence the default hook so the
    // runner's empty-stderr contract holds, then extract the payload.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vn.write().unwrap().add_descend(op);
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

/// Read a Varnode tolerating lock poisoning. The caught add_descend panic
/// unwinds through the held write guard, which poisons the RwLock — a Rust
/// unwinding-lock artifact with no Ghidra counterpart (C++ has no locks);
/// the underlying Varnode state is exactly what the oracle observes after
/// its caught LowlevelError.
fn read_vn(vn: &Arc<RwLock<rudra::varnode::Varnode>>) -> std::sync::RwLockReadGuard<'_, rudra::varnode::Varnode> {
    vn.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn main() {
    // Same Standalone core-type flavor as the locked oracle fixture so
    // bank-allocated unknown types match (see varnode_init_1204.rs).
    // A caught add_descend panic poisons that Varnode's RwLock (Rust
    // unwinding-lock artifact, no Ghidra counterpart), and the poisoned
    // Varnode stays in the bank's loc_tree where later insertions would
    // read it via the Ord comparator. Each case therefore uses a fresh
    // bank; the observations (count/flags/order per Varnode) are
    // bank-neutral, so the C++ side's single bank prints identical lines.
    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let new_bank = || {
        let mut bank = VarnodeBank::new();
        bank.set_type_factory(type_factory.clone());
        bank
    };

    let op1 = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1000), 1),
        OpCode::CPUI_COPY,
    )));
    let op2 = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1010), 2),
        OpCode::CPUI_COPY,
    )));

    // free_first + free_second_throw (varnode.cc:333-339).
    let mut bank = new_bank();
    let free_vn = bank.create_with_space(8, AddressSpace::Register, 0x80);
    free_vn.write().unwrap().add_descend(&op1);
    {
        let value = free_vn.read().unwrap();
        println!(
            "free_first:count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    let free_error = catch_add_descend_error(&free_vn, &op2);
    {
        let value = read_vn(&free_vn);
        println!(
            "free_second_throw:error={free_error},count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    drop(bank);

    // spacebase_exempt (varnode.cc:334 `!isSpacebase()` guard).
    let mut bank = new_bank();
    let spacebase_vn = bank.create_with_space(8, AddressSpace::Register, 0x88);
    spacebase_vn
        .write()
        .unwrap()
        .set_flags(varnode_flags::SPACEBASE);
    spacebase_vn.write().unwrap().add_descend(&op1);
    spacebase_vn.write().unwrap().add_descend(&op2);
    {
        let value = spacebase_vn.read().unwrap();
        println!(
            "spacebase_exempt:count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    drop(bank);

    // written_accumulate.
    let mut bank = new_bank();
    let defop = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1020), 3),
        OpCode::CPUI_COPY,
    )));
    let written_vn = bank.create_def_with_space(8, AddressSpace::Register, 0x90, &defop);
    written_vn.write().unwrap().add_descend(&op1);
    written_vn.write().unwrap().add_descend(&op2);
    {
        let value = written_vn.read().unwrap();
        println!(
            "written_accumulate:count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    drop(bank);

    // input_accumulate.
    let mut bank = new_bank();
    let input_vn = bank.create_with_space(8, AddressSpace::Register, 0x98);
    let input_vn = bank.set_input(input_vn).expect("fresh input");
    input_vn.write().unwrap().add_descend(&op1);
    input_vn.write().unwrap().add_descend(&op2);
    {
        let value = input_vn.read().unwrap();
        println!(
            "input_accumulate:count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    drop(bank);

    // const_second_throw: constants are free by the isFree() test and get no
    // addDescend exemption.
    let mut bank = new_bank();
    let const_vn = bank.create_constant(4, 0x1234);
    const_vn.write().unwrap().add_descend(&op1);
    let const_error = catch_add_descend_error(&const_vn, &op2);
    {
        let value = read_vn(&const_vn);
        println!(
            "const_second_throw:error={const_error},count={},flags={}",
            value.count_descends(),
            value.flags
        );
    }
    drop(bank);

    // order: descend iteration preserves push order. Rust's SeqNum::new
    // mirrors the C++ 2-arg ctor's `uniq`/time identity (address.hh:130).
    print!("order:written=");
    for op in written_vn.read().unwrap().descend_iter() {
        print!("{},", op.read().unwrap().get_seq_num().time);
    }
    println!();
}
