// PRINTC-INTNOT-TOKEN-0001: Rugra comparand for the locked Ghidra 12.0.4
// PrintC unary-prefix operator token-order oracle
// (GLOBWORD-C4-INTNOT-TOKEN-0001).
//
// Mirrors tests/oracle/printc_intnot_token_1204.cc case-for-case: every
// case builds the same constant-leaf expression graph (same opcodes, same
// implied flags, same uint4 constant types) and drives the production
// emitExpression port — PrintC::emit_expression_rpn — on the top-level op,
// which has NO output so only the bare operator/operand token stream is
// emitted.  This locks the PrintLanguage::opUnary semantics
// (printlanguage.cc:566-573: pushOp + pushVn, never a direct emit) against
// eager-emission regressions of the kind that produced the illegal-C
// `0xfefefeff~ & *puVar10` form (oracle: `... & ~*puVar10`).
//
// Cases:
//   intnot_deref   AND(ADD(LOAD(0x20), 0xfefefeff), NEGATE(LOAD(0x20)))
//   intnot_const   NEGATE(0x10)
//   int2comp_const INT_2COMP(0x10)
//   intnot_left    OR(NEGATE(0x30), ADD(0x11, 0x22))
//   intnot_addright ADD(0x11, NEGATE(0x10))

use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::printc::PrintC;
use rudra::prettyprint::EmitNoMarkup;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::{varnode_flags, Varnode};
use rudra::variable::HighVariable;

type VnRef = Arc<RwLock<Varnode>>;
type OpRef = Arc<RwLock<PcodeOp>>;

fn uint4() -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        "uint4".to_string(),
        4,
        TypeMetatype::Uint,
    )))
}

/// Constant-space leaf typed uint4 with a uint4 HighVariable — the twin of
/// the C++ fixture's `newConstant` + `updateType(uint4)` + `setHighLevel`
/// state (pushVnExplicit reads the HIGH type, printlanguage.cc:226).
fn constant4(val: u64) -> VnRef {
    let mut vn = Varnode::new_with_space(4, AddressSpace::Const, val);
    vn.v_type = Some(uint4());
    let mut high = HighVariable::new(uint4());
    high.name = String::new();
    vn.high = Some(Arc::new(RwLock::new(high)));
    Arc::new(RwLock::new(vn))
}

/// Unique-space implied output typed uint4 — the twin of the C++ fixture's
/// `newUniqueOut` + `updateType` + `setImplied` (the defining op is inlined
/// at the use site by PrintLanguage::recurse, printlanguage.cc:526-533).
fn implied_out4(unique_off: u64) -> VnRef {
    let mut vn = Varnode::new_with_space(4, AddressSpace::Unique, unique_off);
    vn.v_type = Some(uint4());
    let mut high = HighVariable::new(uint4());
    high.name = String::new();
    vn.high = Some(Arc::new(RwLock::new(high)));
    vn.set_flags(varnode_flags::IMPLIED);
    Arc::new(RwLock::new(vn))
}

/// LOAD whose address input is the constant `addr` (opLoad only pushes
/// in(1), printc.cc:487-489; in(0) is a never-printed placeholder).
fn load_of(addr: u64, pc: u64, time: u32) -> (VnRef, OpRef) {
    let spaceid = {
        let mut vn = Varnode::new_with_space(8, AddressSpace::Const, 3);
        let mut high = HighVariable::new(Arc::new(Datatype::Base(
            TypeBase::new("xunknown8".to_string(), 8, TypeMetatype::Unknown),
        )));
        high.name = String::new();
        vn.high = Some(Arc::new(RwLock::new(high)));
        Arc::new(RwLock::new(vn))
    };
    let out = implied_out4(0x9000 + time as u64);
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), time), OpCode::CPUI_LOAD);
    op.set_opcode_flags(OpCode::CPUI_LOAD);
    op.inrefs.push(spaceid);
    op.inrefs.push(constant4(addr));
    op.output = Some(out.clone());
    let op_arc = Arc::new(RwLock::new(op));
    out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
    (out, op_arc)
}

fn unary_op(opc: OpCode, in0: &VnRef, pc: u64, time: u32) -> (VnRef, OpRef) {
    let out = implied_out4(0xa000 + time as u64);
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), time), opc);
    op.set_opcode_flags(opc);
    op.inrefs.push(in0.clone());
    op.output = Some(out.clone());
    let op_arc = Arc::new(RwLock::new(op));
    out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
    (out, op_arc)
}

fn binary_op(opc: OpCode, in0: &VnRef, in1: &VnRef, pc: u64, time: u32) -> (VnRef, OpRef) {
    let out = implied_out4(0xb000 + time as u64);
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), time), opc);
    op.set_opcode_flags(opc);
    op.inrefs.push(in0.clone());
    op.inrefs.push(in1.clone());
    op.output = Some(out.clone());
    let op_arc = Arc::new(RwLock::new(op));
    out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
    (out, op_arc)
}

/// Top-level op with NO output: emit_expression_rpn skips the assignment
/// arm (printc.cc:2471-2476) and emits only the token stream.
fn top_no_out(opc: OpCode, inputs: Vec<VnRef>, pc: u64, time: u32) -> OpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), time), opc);
    op.set_opcode_flags(opc);
    op.inrefs = inputs;
    Arc::new(RwLock::new(op))
}

fn render(top: &OpRef) -> String {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    {
        let op = top.read().unwrap();
        printer.emit_expression_rpn(top, &op);
    }
    let emit = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("fixture must retain EmitNoMarkup");
    emit.get_output()
}

fn main() {
    println!(
        "schema=1|fixture=PRINTC-INTNOT-TOKEN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    let mut time: u32 = 0;
    let mut next_time = || {
        time += 1;
        time
    };
    let pc = 0x1000u64;

    // NOTE: Varnode.def is a Weak<PcodeOp> (varnode.rs:500) — every defining
    // op Arc must outlive the render call or the implied-def upgrade in
    // rpn_recurse fails and the operand is silently dropped (printc.rs
    // get_def()-None arm). The `_op*` bindings keep the Arcs alive to the
    // end of this scope; the C++ side's Funcdata obank holds its ops.

    // intnot_deref: AND(ADD(LOAD(0x20), 0xfefefeff), NEGATE(LOAD(0x20)))
    let (load_a, _op_load_a) = load_of(0x20, pc, next_time());
    let (add, _op_add) = binary_op(
        OpCode::CPUI_INT_ADD,
        &load_a,
        &constant4(0xfefefeff),
        pc,
        next_time(),
    );
    let (load_b, _op_load_b) = load_of(0x20, pc, next_time());
    let (neg, _op_neg) = unary_op(OpCode::CPUI_INT_NEGATE, &load_b, pc, next_time());
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![add.clone(), neg.clone()],
        pc,
        next_time(),
    );
    println!("case=intnot_deref|text={}", render(&top));

    // intnot_const: NEGATE(0x10)
    let top = top_no_out(
        OpCode::CPUI_INT_NEGATE,
        vec![constant4(0x10)],
        pc,
        next_time(),
    );
    println!("case=intnot_const|text={}", render(&top));

    // int2comp_const: INT_2COMP(0x10)
    let top = top_no_out(
        OpCode::CPUI_INT_2COMP,
        vec![constant4(0x10)],
        pc,
        next_time(),
    );
    println!("case=int2comp_const|text={}", render(&top));

    // intnot_left: OR(NEGATE(0x30), ADD(0x11, 0x22))
    let (neg, _op_neg) = unary_op(
        OpCode::CPUI_INT_NEGATE,
        &constant4(0x30),
        pc,
        next_time(),
    );
    let (add, _op_add) = binary_op(
        OpCode::CPUI_INT_ADD,
        &constant4(0x11),
        &constant4(0x22),
        pc,
        next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_OR,
        vec![neg.clone(), add.clone()],
        pc,
        next_time(),
    );
    println!("case=intnot_left|text={}", render(&top));

    // intnot_addright: ADD(0x11, NEGATE(0x10))
    let (neg, _op_neg) = unary_op(
        OpCode::CPUI_INT_NEGATE,
        &constant4(0x10),
        pc,
        next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_ADD,
        vec![constant4(0x11), neg.clone()],
        pc,
        next_time(),
    );
    println!("case=intnot_addright|text={}", render(&top));
}
