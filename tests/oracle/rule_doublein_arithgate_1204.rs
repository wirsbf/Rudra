//! Rust twin of `rule_doublein_arithgate_1204.cc`.
//!
//! The covered projection invokes the production RuleDoubleIn directly on
//! ten equivalent IR graphs and emits the same record grammar as the
//! locked Ghidra 12.0.4 fixture: the whole-def arithmetic gate of
//! attemptMarking. INT_ADD/INT_MULT/INT_2COMP wholes are marked;
//! INT_OR/INT_XOR/INT_AND/INT_NEGATE/INT_LEFT/INT_ZEXT wholes are
//! rejected (logical/shift/no-flag opcodes per the oracle's
//! `addlflags` table in typeop.cc); the offset-mismatch case is rejected
//! by the offset==vn->getSize() precondition (double.cc:3227).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::double_precis::RuleDoubleIn;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

struct CaseIr {
    whole_def: rudra::op::PcodeOpRef,
    whole: VarnodeRef,
    hi_sub: rudra::op::PcodeOpRef,
    hi: VarnodeRef,
    lo_sub: rudra::op::PcodeOpRef,
    lo: VarnodeRef,
}

// Builds: 2-byte register inputs a,b; whole = <defop>(a[,b]) at 0x2000
// (2-byte unique output); SUBPIECE(whole,1) -> 1-byte hi at 0x2010;
// SUBPIECE(whole,0) -> 1-byte lo at 0x2020.
fn build_case(fd: &mut Funcdata, shape: &str) -> CaseIr {
    let block = fd.create_new_block();

    let a = fd.vbank.create_with_space(2, rudra::space::AddressSpace::Register, 0x40);
    let a = fd.set_input_varnode(a);
    let b = fd.vbank.create_with_space(2, rudra::space::AddressSpace::Register, 0x50);
    let b = fd.set_input_varnode(b);

    let whole_def = match shape {
        "int_zext_whole" => {
            // ZEXT reads a 1-byte input; give the case its own 1-byte input.
            let a1 =
                fd.vbank.create_with_space(1, rudra::space::AddressSpace::Register, 0x60);
            let a1 = fd.set_input_varnode(a1);
            let op = fd.new_op(1, Address::new(0x2000));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_ZEXT);
            fd.op_set_input(&op, a1, 0);
            op
        }
        "int_negate_whole" | "int_2comp_whole" => {
            let op = fd.new_op(1, Address::new(0x2000));
            fd.op_set_opcode(
                &op,
                if shape == "int_negate_whole" {
                    OpCode::CPUI_INT_NEGATE
                } else {
                    OpCode::CPUI_INT_2COMP
                },
            );
            fd.op_set_input(&op, a, 0);
            op
        }
        "int_left_whole" => {
            let op = fd.new_op(2, Address::new(0x2000));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_LEFT);
            fd.op_set_input(&op, a, 0);
            let one = fd.new_constant(2, 1);
            fd.op_set_input(&op, one, 1);
            op
        }
        _ => {
            let op = fd.new_op(2, Address::new(0x2000));
            let opc = match shape {
                "int_mult_whole" => OpCode::CPUI_INT_MULT,
                "int_or_whole" => OpCode::CPUI_INT_OR,
                "int_xor_whole" => OpCode::CPUI_INT_XOR,
                "int_and_whole" => OpCode::CPUI_INT_AND,
                _ => OpCode::CPUI_INT_ADD,
            };
            fd.op_set_opcode(&op, opc);
            fd.op_set_input(&op, a, 0);
            fd.op_set_input(&op, b, 1);
            op
        }
    };
    let whole = fd.new_unique_out(2, &whole_def);
    fd.op_insert_end(&whole_def, &block);

    let hi_sub = fd.new_op(2, Address::new(0x2010));
    fd.op_set_opcode(&hi_sub, OpCode::CPUI_SUBPIECE);
    let hi = fd.new_unique_out(1, &hi_sub);
    fd.op_set_input(&hi_sub, whole.clone(), 0);
    let off1 = fd.new_constant(4, 1);
    fd.op_set_input(&hi_sub, off1, 1);
    fd.op_insert_end(&hi_sub, &block);

    let lo_sub = fd.new_op(2, Address::new(0x2020));
    fd.op_set_opcode(&lo_sub, OpCode::CPUI_SUBPIECE);
    let lo = fd.new_unique_out(1, &lo_sub);
    fd.op_set_input(&lo_sub, whole.clone(), 0);
    let off0 = fd.new_constant(4, 0);
    fd.op_set_input(&lo_sub, off0, 1);
    fd.op_insert_end(&lo_sub, &block);

    CaseIr {
        whole_def,
        whole,
        hi_sub,
        hi,
        lo_sub,
        lo,
    }
}

fn run_case(type_factory: &Arc<RwLock<TypeFactory>>, case_name: &str, shape: &str) {
    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.vbank.set_type_factory(type_factory.clone());
    let ir = build_case(&mut fd, shape);
    // The rule target is the hi SUBPIECE (offset==vn size) except the
    // offset_mismatch case, which aims the rule at the lo SUBPIECE.
    let aim_lo = case_name == "offset_mismatch";
    let target: &rudra::op::PcodeOpRef = if aim_lo { &ir.lo_sub } else { &ir.hi_sub };
    let target_out: &VarnodeRef = if aim_lo { &ir.lo } else { &ir.hi };
    let sibling_out: &VarnodeRef = if aim_lo { &ir.hi } else { &ir.lo };
    let result = RuleDoubleIn::new()
        .apply_op(&target.0, &mut fd)
        .expect("RuleDoubleIn apply");
    println!(
        "case={case_name}|res={result}|target_precis_hi={}|sibling_precis_lo={}|alive={}",
        usize::from(target_out.read().unwrap().is_precis_hi()),
        usize::from(sibling_out.read().unwrap().is_precis_lo()),
        fd.obank.alivelist.len(),
    );
    let _ = &ir.whole_def;
    let _ = &ir.whole;
}

fn main() {
    let opcodes = RuleDoubleIn::new().get_opcodes();
    println!(
        "getoplist:count={},opcode={}",
        opcodes.len(),
        opcodes.first().map_or(-1, |opcode| *opcode as i32),
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    run_case(&type_factory, "int_add_whole", "int_add_whole");
    run_case(&type_factory, "int_mult_whole", "int_mult_whole");
    run_case(&type_factory, "int_2comp_whole", "int_2comp_whole");
    run_case(&type_factory, "int_or_whole", "int_or_whole");
    run_case(&type_factory, "int_xor_whole", "int_xor_whole");
    run_case(&type_factory, "int_and_whole", "int_and_whole");
    run_case(&type_factory, "int_negate_whole", "int_negate_whole");
    run_case(&type_factory, "int_left_whole", "int_left_whole");
    run_case(&type_factory, "int_zext_whole", "int_zext_whole");
    run_case(&type_factory, "offset_mismatch", "int_add_whole");
}
