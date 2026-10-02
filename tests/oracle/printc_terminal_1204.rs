use rudra::address::{Address, SeqNum};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

fn make_op(opcode: OpCode, index: u32) -> PcodeOpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(index as u64), index), opcode);
    op.set_opcode_flags(opcode);
    if opcode == OpCode::CPUI_CBRANCH {
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_with_space(
            8,
            AddressSpace::Const,
            0x1000,
        ))));
        op.inrefs.push(Arc::new(RwLock::new(Varnode::new_with_space(
            1,
            AddressSpace::Const,
            1,
        ))));
    }
    PcodeOpRef(Arc::new(RwLock::new(op)))
}

fn render(opcodes: &[OpCode], suppress_branch: bool) -> String {
    let ops = opcodes
        .iter()
        .enumerate()
        .map(|(index, opcode)| make_op(*opcode, index as u32))
        .collect::<Vec<_>>();
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.emit_block_basic_rpn(&ops, suppress_branch);
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC fixture must retain EmitNoMarkup");
    emit.debug_get_output_ref().to_owned()
}

fn to_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn emit_case(name: &str, opcodes: &[OpCode], suppress_branch: bool, raw: bool) {
    let output = render(opcodes, suppress_branch);
    if raw {
        println!("{name}={}", to_hex(&output));
    } else {
        println!("{name}={}", output.matches(';').count());
    }
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");
    emit_case("cbranch_visible", &[OpCode::CPUI_CBRANCH], false, raw);
    emit_case("cbranch_suppressed", &[OpCode::CPUI_CBRANCH], true, raw);
    emit_case("branch_visible", &[OpCode::CPUI_BRANCH], false, raw);
    emit_case("return_suppressed", &[OpCode::CPUI_RETURN], true, raw);
    emit_case(
        "mixed_visible",
        &[OpCode::CPUI_RETURN, OpCode::CPUI_CBRANCH],
        false,
        raw,
    );
    emit_case(
        "mixed_suppressed",
        &[OpCode::CPUI_RETURN, OpCode::CPUI_CBRANCH],
        true,
        raw,
    );
}
