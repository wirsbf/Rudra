//! Rust twin of `varnode_getusepoint_1204.cc`.
//!
//! The covered projection invokes the production `Varnode::get_use_point`
//! on four equivalent IR states and emits the same record grammar as the
//! locked Ghidra 12.0.4 fixture: the written leg (defining op address) and
//! the free/input legs (`fd.getAddress() + -1` sentinel), including the
//! ram:0 underflow wrap through `AddrSpace::wrap_offset`.

use std::sync::Arc;

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, SpaceRegistry, SpaceType};

fn space_name(addr: &Address) -> String {
    match addr.get_space() {
        Some(space) => space.get_name(),
        None => "-".to_string(),
    }
}

fn emit_use_point(case_name: &str, leg: &str, use_point: &Address) {
    println!(
        "case={case_name}|leg={leg}|space={}|usepoint=0x{:x}",
        space_name(use_point),
        use_point.as_u64(),
    );
}

fn fixture_ram() -> AddrSpace {
    let mut registry = SpaceRegistry::new();
    registry
        .insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .expect("ram space insert");
    registry.get_space_by_name("ram").expect("ram space handle")
}

fn main() {
    let ram = fixture_ram();

    let mut fd = Funcdata::new("fx", Address::with_space(&ram, 0x1000), 0x20);
    let block = fd.create_new_block();

    // written_def: the unique out of a COPY at ram:0x2000.
    let defop = fd.new_op(1, Address::with_space(&ram, 0x2000));
    fd.op_set_opcode(&defop, OpCode::CPUI_COPY);
    let written = fd.new_unique_out(4, &defop);
    let seven = fd.new_constant(4, 7);
    fd.op_set_input(&defop, seven, 0);
    fd.op_insert_end(&defop, &block);
    emit_use_point(
        "written_def",
        "written",
        &written.read().unwrap().get_use_point(&fd),
    );

    // input_param: a function input varnode.
    let inputvn = fd.vbank.create_with_space(4, rudra::space::AddressSpace::Register, 0x40);
    let inputvn = fd.set_input_varnode(inputvn);
    emit_use_point(
        "input_param",
        "input",
        &inputvn.read().unwrap().get_use_point(&fd),
    );

    // free_vn: constructed but never written nor marked input.
    let freevn = fd.vbank.create_with_space(4, rudra::space::AddressSpace::Register, 0x50);
    emit_use_point("free_vn", "free", &freevn.read().unwrap().get_use_point(&fd));

    // zero_base: underflow wrap through the ram space.
    let mut fd2 = Funcdata::new("fz", Address::with_space(&ram, 0), 0x20);
    let freevn2 = fd2.vbank.create_with_space(4, rudra::space::AddressSpace::Register, 0x60);
    emit_use_point("zero_base", "free", &freevn2.read().unwrap().get_use_point(&fd2));

    // Keep the ram handle alive alongside fd/fd2 (both borrow its tag).
    let _keep: Arc<()> = Arc::new(());
    let _ = &ram;
}
