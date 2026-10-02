use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::op::{pcodeop_flags, PcodeOp};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varmap::gather_offset;
use rudra::varnode::{varnode_flags, Varnode};

fn count_descendants(vn: &Arc<RwLock<Varnode>>) -> usize {
    vn.read()
        .unwrap()
        .descend
        .iter()
        .filter(|weak| weak.upgrade().is_some())
        .count()
}

fn dump_state(
    label: &str,
    phase: &str,
    output: &Arc<RwLock<Varnode>>,
    op: &Arc<RwLock<PcodeOp>>,
    inputs: &[Arc<RwLock<Varnode>>],
) {
    let output_guard = output.read().unwrap();
    let op_guard = op.read().unwrap();
    let output_type = output_guard.get_type().expect("fixture output type");
    assert_eq!(output_type.get_metatype(), TypeMetatype::Unknown);
    print!(
        "{label}|{phase}|out_unique={}|out_offset={}|out_size={}|out_flags={}|out_consumed={}|out_nzm={}|def_alias={}|output_alias={}|out_type_present=1|out_type_name={}|out_type_size={}|out_type_metatype=unknown|opcode={}|inputs={}|dead={}|eval={}|commutative={}|seq_offset={}|seq_order={}",
        u8::from(output_guard.is_unique()),
        output_guard.get_offset(),
        output_guard.get_size(),
        output_guard.flags,
        output_guard.get_consume(),
        output_guard.get_nzm(),
        u8::from(
            output_guard
                .get_def()
                .map(|definition| Arc::ptr_eq(&definition, op))
                .unwrap_or(false)
        ),
        u8::from(
            op_guard
                .output
                .as_ref()
                .map(|candidate| Arc::ptr_eq(candidate, output))
                .unwrap_or(false)
        ),
        output_type.get_name(),
        output_type.get_size(),
        op_guard.opcode as u32,
        op_guard.inrefs.len(),
        u8::from(op_guard.is_dead()),
        op_guard.get_eval_type(),
        u8::from((op_guard.flags & pcodeop_flags::COMMUTATIVE) != 0),
        op_guard.get_addr().as_u64(),
        op_guard.get_seq_num().get_order(),
    );
    for (index, input) in inputs.iter().enumerate() {
        let input_guard = input.read().unwrap();
        let input_type = input_guard.get_type().expect("fixture input type");
        assert_eq!(input_type.get_metatype(), TypeMetatype::Unknown);
        print!(
            "|in{index}_constant={}|in{index}_offset={}|in{index}_size={}|in{index}_flags={}|in{index}_consumed={}|in{index}_nzm={}|in{index}_slot_alias={}|in{index}_descendants={}|in{index}_type_present=1|in{index}_type_name={}|in{index}_type_size={}|in{index}_type_metatype=unknown|in{index}_type_alias_out={}",
            u8::from(input_guard.is_constant()),
            input_guard.get_offset(),
            input_guard.get_size(),
            input_guard.flags,
            input_guard.get_consume(),
            input_guard.get_nzm(),
            u8::from(Arc::ptr_eq(&op_guard.inrefs[index], input)),
            count_descendants(input),
            input_type.get_name(),
            input_type.get_size(),
            u8::from(Arc::ptr_eq(&input_type, &output_type)),
        );
    }
    if inputs.len() == 2 {
        let input0_type = inputs[0].read().unwrap().get_type().unwrap();
        let input1_type = inputs[1].read().unwrap().get_type().unwrap();
        print!(
            "|input_alias={}|input_type_alias={}",
            u8::from(Arc::ptr_eq(&inputs[0], &inputs[1])),
            u8::from(Arc::ptr_eq(&input0_type, &input1_type)),
        );
    }
    println!();
}

fn make_op(opcode: OpCode, pc: u64, inputs: &[Arc<RwLock<Varnode>>]) -> Arc<RwLock<PcodeOp>> {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), 0), opcode);
    op.flags = pcodeop_flags::DEAD
        | match opcode {
            OpCode::CPUI_COPY => pcodeop_flags::UNARY | pcodeop_flags::NOCOLLAPSE,
            OpCode::CPUI_INT_ADD => pcodeop_flags::BINARY | pcodeop_flags::COMMUTATIVE,
            _ => unreachable!("fixture only constructs COPY and INT_ADD"),
        };
    op.inrefs = inputs.to_vec();
    Arc::new(RwLock::new(op))
}

fn attach(
    size: usize,
    offset: u64,
    opcode: OpCode,
    pc: u64,
    datatype: &Arc<Datatype>,
    inputs: &[Arc<RwLock<Varnode>>],
) -> (Arc<RwLock<Varnode>>, Arc<RwLock<PcodeOp>>) {
    let output = Arc::new(RwLock::new(Varnode::new_with_space(
        size,
        AddressSpace::Unique,
        offset,
    )));
    let op = make_op(opcode, pc, inputs);
    {
        let mut output_guard = output.write().unwrap();
        output_guard.set_flags(varnode_flags::WRITTEN | varnode_flags::COVERDIRTY);
        output_guard.def = Some(Arc::downgrade(&op));
        output_guard.v_type = Some(datatype.clone());
        output_guard.consumed = u64::MAX;
        output_guard.nzm = u64::MAX;
    }
    op.write().unwrap().output = Some(output.clone());
    for input in inputs {
        input.write().unwrap().add_descend(&op);
    }
    (output, op)
}

fn constant(value: u64, size: usize, datatype: &Arc<Datatype>) -> Arc<RwLock<Varnode>> {
    let mut varnode = Varnode::new_constant(value, size);
    // Fixture input adapter: construct the exact Ghidra Varnode constructor
    // state independently of Rugra's separately tracked VARNODE-INIT wave.
    varnode.consumed = u64::MAX;
    varnode.nzm = value;
    varnode.v_type = Some(datatype.clone());
    Arc::new(RwLock::new(varnode))
}

fn run_copy(label: &str, size: usize, value: u64) {
    let datatype = Arc::new(Datatype::Base(TypeBase::new(
        "fixture_unknown".to_string(),
        size,
        TypeMetatype::Unknown,
    )));
    let input = constant(value, size, &datatype);
    let inputs = vec![input];
    let (output, op) = attach(size, 0x2000, OpCode::CPUI_COPY, 0x1000, &datatype, &inputs);
    dump_state(label, "before", &output, &op, &inputs);
    let result = gather_offset(&output);
    println!("{label}|result=0x{result:x}");
    dump_state(label, "after", &output, &op, &inputs);
}

fn run_add(label: &str, size: usize, left: u64, right: u64) {
    let datatype = Arc::new(Datatype::Base(TypeBase::new(
        "fixture_unknown".to_string(),
        size,
        TypeMetatype::Unknown,
    )));
    let input0 = constant(left, size, &datatype);
    let input1 = constant(right, size, &datatype);
    let inputs = vec![input0, input1];
    let (output, op) = attach(size, 0x2100, OpCode::CPUI_INT_ADD, 0x1100, &datatype, &inputs);
    dump_state(label, "before", &output, &op, &inputs);
    let result = gather_offset(&output);
    println!("{label}|result=0x{result:x}");
    dump_state(label, "after", &output, &op, &inputs);
}

fn main() {
    run_copy("copy8_all_bits", 8, 0xfedcba9876543210);
    run_add("add8_wrap", 8, 0xfffffffffffffff0, 0x35);
    run_add("add7_mask", 7, 0x00fffffffffffff0, 0x35);
}
