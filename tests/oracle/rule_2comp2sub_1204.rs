//! Rust twin of `rule_2comp2sub_1204.cc`.
//!
//! The covered projection invokes the production Rule2Comp2Sub directly on
//! five equivalent IR graphs and emits the same record grammar as the locked
//! Ghidra 12.0.4 fixture: the lone-INT_ADD gate, both rewrite orientations
//! (`V + -W` and `-W + V`), and the three reject shapes (non-ADD lone
//! consumer, no descendant, two descendants).

use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::ruleaction::Rule2Comp2Sub;
use rudra::space::AddressSpace;
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;
type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

#[derive(Clone, Copy)]
struct UseOp<'a> {
    op: Option<&'a PcodeOpRef>,
}

impl<'a> UseOp<'a> {
    fn none() -> Self {
        UseOp { op: None }
    }
}

fn emit_use(
    use_op: &UseOp,
    v: &VarnodeRef,
    w: &VarnodeRef,
    out2c: &VarnodeRef,
) {
    let Some(op) = use_op.op else {
        print!("|use=-");
        return;
    };
    let guard = op.0.read().unwrap();
    print!(
        "|use_opcode={},in0_is_v={},in1_is_w={},in0_is_out2c={},in1_is_out2c={}",
        guard.opcode as i32,
        usize::from(guard
            .inrefs
            .get(0)
            .is_some_and(|candidate| Arc::ptr_eq(candidate, v))),
        usize::from(guard
            .inrefs
            .get(1)
            .is_some_and(|candidate| Arc::ptr_eq(candidate, w))),
        usize::from(guard
            .inrefs
            .get(0)
            .is_some_and(|candidate| Arc::ptr_eq(candidate, out2c))),
        usize::from(guard
            .inrefs
            .get(1)
            .is_some_and(|candidate| Arc::ptr_eq(candidate, out2c))),
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_state(
    case_name: &str,
    stage: &str,
    result: &str,
    fd: &Funcdata,
    block: &BlockRef,
    twocomp: &PcodeOpRef,
    use1: &UseOp,
    use2: &UseOp,
    v: &VarnodeRef,
    w: &VarnodeRef,
    out2c: &VarnodeRef,
    out2c_freed: bool,
) {
    let twocomp_guard = twocomp.0.read().unwrap();
    print!(
        "case={case_name}|stage={stage}|result={result}|twocomp_opcode={}|twocomp_dead={}",
        twocomp_guard.opcode as i32,
        usize::from(twocomp_guard.is_dead()),
    );
    drop(twocomp_guard);
    emit_use(use1, v, w, out2c);
    emit_use(use2, v, w, out2c);
    let out2c_desc = if out2c_freed {
        "-".to_string()
    } else {
        out2c.read().unwrap().count_descends().to_string()
    };
    println!(
        "|v_desc={}|w_desc={}|out2c_desc={}|alive={}|dead={}|block_ops={}",
        v.read().unwrap().count_descends(),
        w.read().unwrap().count_descends(),
        out2c_desc,
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        block.read().unwrap().get_ops().len(),
    );
}

struct CaseIr {
    block: BlockRef,
    v: VarnodeRef,
    w: VarnodeRef,
    twocomp: PcodeOpRef,
    out2c: VarnodeRef,
    use1: Option<PcodeOpRef>,
    use2: Option<PcodeOpRef>,
}

fn build_case(fd: &mut Funcdata, shape: &str) -> CaseIr {
    let block = fd.create_new_block();
    let v = fd.vbank.create_with_space(4, AddressSpace::Register, 0x40);
    let v = fd.set_input_varnode(v);
    let w = fd.vbank.create_with_space(4, AddressSpace::Register, 0x50);
    let w = fd.set_input_varnode(w);

    let twocomp = fd.new_op(2, Address::new(0x2000));
    fd.op_set_opcode(&twocomp, OpCode::CPUI_INT_2COMP);
    let out2c = fd.new_unique_out(4, &twocomp);
    fd.op_set_input(&twocomp, w.clone(), 0);
    fd.op_insert_end(&twocomp, &block);

    let mut use1 = None;
    let mut use2 = None;
    match shape {
        "add_in1" => {
            // ADD(V, 2COMP(W))
            let op = fd.new_op(2, Address::new(0x2010));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(4, &op);
            fd.op_set_input(&op, v.clone(), 0);
            fd.op_set_input(&op, out2c.clone(), 1);
            fd.op_insert_end(&op, &block);
            use1 = Some(op);
        }
        "add_in0" => {
            // ADD(2COMP(W), V)
            let op = fd.new_op(2, Address::new(0x2010));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(4, &op);
            fd.op_set_input(&op, out2c.clone(), 0);
            fd.op_set_input(&op, v.clone(), 1);
            fd.op_insert_end(&op, &block);
            use1 = Some(op);
        }
        "mult_lone" => {
            // MULT(2COMP(W), 2)
            let op = fd.new_op(2, Address::new(0x2010));
            fd.op_set_opcode(&op, OpCode::CPUI_INT_MULT);
            fd.new_unique_out(4, &op);
            fd.op_set_input(&op, out2c.clone(), 0);
            let two = fd.new_constant(4, 2);
            fd.op_set_input(&op, two, 1);
            fd.op_insert_end(&op, &block);
            use1 = Some(op);
        }
        "two_adds" => {
            // Two ADDs read the 2COMP out.
            let op1 = fd.new_op(2, Address::new(0x2010));
            fd.op_set_opcode(&op1, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(4, &op1);
            fd.op_set_input(&op1, out2c.clone(), 0);
            fd.op_set_input(&op1, v.clone(), 1);
            fd.op_insert_end(&op1, &block);
            let op2 = fd.new_op(2, Address::new(0x2020));
            fd.op_set_opcode(&op2, OpCode::CPUI_INT_ADD);
            fd.new_unique_out(4, &op2);
            fd.op_set_input(&op2, v.clone(), 0);
            fd.op_set_input(&op2, out2c.clone(), 1);
            fd.op_insert_end(&op2, &block);
            use1 = Some(op1);
            use2 = Some(op2);
        }
        _ => {} // "none": the 2COMP out has no descendants.
    }

    CaseIr {
        block,
        v,
        w,
        twocomp,
        out2c,
        use1,
        use2,
    }
}

fn run_case(type_factory: &Arc<RwLock<TypeFactory>>, case_name: &str, shape: &str) {
    let mut fd = Funcdata::new("fx", Address::new(0x1000), 0x20);
    fd.vbank.set_type_factory(type_factory.clone());
    let ir = build_case(&mut fd, shape);
    let use1_borrow: Option<&PcodeOpRef> = ir.use1.as_ref();
    let use2_borrow: Option<&PcodeOpRef> = ir.use2.as_ref();
    let use1 = use1_borrow.map_or_else(UseOp::none, |op| UseOp { op: Some(op) });
    let use2 = use2_borrow.map_or_else(UseOp::none, |op| UseOp { op: Some(op) });

    emit_state(
        case_name,
        "before",
        "na",
        &fd,
        &ir.block,
        &ir.twocomp,
        &use1,
        &use2,
        &ir.v,
        &ir.w,
        &ir.out2c,
        false,
    );
    let result = Rule2Comp2Sub::new()
        .apply_op(&ir.twocomp.0, &mut fd)
        .expect("Rule2Comp2Sub apply");
    emit_state(
        case_name,
        "after",
        &result.to_string(),
        &fd,
        &ir.block,
        &ir.twocomp,
        &use1,
        &use2,
        &ir.v,
        &ir.w,
        &ir.out2c,
        result != 0,
    );
}

fn main() {
    let opcodes = Rule2Comp2Sub::new().get_opcodes();
    println!(
        "getoplist:count={},opcode={}",
        opcodes.len(),
        opcodes.first().map_or(-1, |opcode| *opcode as i32),
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    run_case(&type_factory, "v_plus_negw", "add_in1");
    run_case(&type_factory, "negw_plus_v", "add_in0");
    run_case(&type_factory, "nonadd_lone", "mult_lone");
    run_case(&type_factory, "no_descend", "none");
    run_case(&type_factory, "two_descend", "two_adds");
}
