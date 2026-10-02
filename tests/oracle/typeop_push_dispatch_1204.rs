// MIGW1-TYPEOP-PUSH-0002: Rudra comparand for the locked Ghidra 12.0.4
// per-op TypeOp::push dispatch oracle (W-2026-09-26-MIGW1-TYPEOP-0002).
//
// Mirrors tests/oracle/typeop_push_dispatch_1204.cc case-for-case: every
// case builds the same constant-leaf expression graph (same opcodes, same
// implied flags, same base types) and drives the production
// PrintC::emit_expression_rpn on the top-level op, which has NO output so
// only the bare operator/operand token stream is emitted.  Implied
// sub-expression outputs dispatch through rpn_recurse ->
// crate::typeop::push_opcode_rpn — the Rust twin of printlanguage.cc:532's
// `defOp->getOpcode()->push(this, defOp, op)` virtual hop — into the
// per-op PrintC virtuals (op_int_equal..op_lzcount, printc.hh:283-344
// anchors).
//
// 57 cases: 31 opBinary tokens, 3 opUnary tokens, 12 opFunc names,
// ZEXT/SEXT cast-vs-func pairs, the full opBoolNegate three-branch chain
// (plain boolean_not / negatetoken flip / double-negation cancellation),
// FLOAT_INT2FLOAT / FLOAT_FLOAT2FLOAT / FLOAT_TRUNC typecast forms, the
// SUBPIECE opFunc fallback, and opPtradd's plain binary_plus form.

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

fn base_typed(name: &str, size: usize, meta: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        name.to_string(),
        size,
        meta,
    )))
}

fn uint1() -> Arc<Datatype> {
    base_typed("uint1", 1, TypeMetatype::Uint)
}
fn int1() -> Arc<Datatype> {
    base_typed("int1", 1, TypeMetatype::Int)
}
fn uint4() -> Arc<Datatype> {
    base_typed("uint4", 4, TypeMetatype::Uint)
}
fn int4() -> Arc<Datatype> {
    base_typed("int4", 4, TypeMetatype::Int)
}
fn float8() -> Arc<Datatype> {
    base_typed("float8", 8, TypeMetatype::Float)
}
fn uint8() -> Arc<Datatype> {
    base_typed("uint8", 8, TypeMetatype::Uint)
}

/// Constant-space leaf typed via a HighVariable — the twin of the C++
/// fixture's `newConstant` + `updateType(dt)` + `setHighLevel`.
fn constant_typed(val: u64, size: usize, dt: Arc<Datatype>) -> VnRef {
    let mut vn = Varnode::new_with_space(size, AddressSpace::Const, val);
    vn.v_type = Some(dt.clone());
    let mut high = HighVariable::new(dt);
    high.name = String::new();
    vn.high = Some(Arc::new(RwLock::new(high)));
    Arc::new(RwLock::new(vn))
}

fn constant4(val: u64) -> VnRef {
    constant_typed(val, 4, uint4())
}

/// Unique-space implied output — the twin of the C++ fixture's
/// `newUniqueOut` + `updateType` + `setImplied` (the defining op is
/// inlined at the use site by the rpn_recurse drain).
fn implied_out(unique_off: u64, size: usize, dt: Arc<Datatype>) -> VnRef {
    let mut vn = Varnode::new_with_space(size, AddressSpace::Unique, unique_off);
    vn.v_type = Some(dt.clone());
    let mut high = HighVariable::new(dt);
    high.name = String::new();
    vn.high = Some(Arc::new(RwLock::new(high)));
    // WRITTEN mirrors the C++ def-presence form of isWritten()
    // (varnode.hh: getDef() != 0) — Rudra transports it as a flag, and
    // check_print_negation's is_written gate (printc.cc:2391) reads it.
    vn.set_flags(varnode_flags::IMPLIED | varnode_flags::WRITTEN);
    Arc::new(RwLock::new(vn))
}

fn unary_op(
    opc: OpCode,
    in0: &VnRef,
    out: VnRef,
    pc: u64,
    time: u32,
) -> OpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(pc), time), opc);
    op.set_opcode_flags(opc);
    op.inrefs.push(in0.clone());
    op.output = Some(out.clone());
    let op_arc = Arc::new(RwLock::new(op));
    out.write().unwrap().def = Some(Arc::downgrade(&op_arc));
    op_arc
}

fn binary_op(opc: OpCode, in0: &VnRef, in1: &VnRef, pc: u64, time: u32) -> (VnRef, OpRef) {
    let out = implied_out(0xb000 + time as u64, 4, uint4());
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

struct Ctx {
    pc: u64,
    time: u32,
}

impl Ctx {
    fn next_time(&mut self) -> u32 {
        self.time += 1;
        self.time
    }
}

fn main() {
    println!(
        "schema=1|fixture=MIGW1-TYPEOP-PUSH-0002|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    let mut ctx = Ctx { pc: 0x1000, time: 0 };
    let pc = 0x1000u64;

    // NOTE: Varnode.def is a Weak<PcodeOp> — every defining op Arc must
    // outlive the render call (same discipline as
    // printc_intnot_token_1204.rs).  The `_op*`/`_keep*` bindings hold them.

    // ---- opBinary one-liners (printc.hh:283-321) ----
    let bin_cases: &[(&str, OpCode)] = &[
        ("bin_int_equal", OpCode::CPUI_INT_EQUAL),
        ("bin_int_not_equal", OpCode::CPUI_INT_NOTEQUAL),
        ("bin_int_less", OpCode::CPUI_INT_LESS),
        ("bin_int_sless", OpCode::CPUI_INT_SLESS),
        ("bin_int_lessequal", OpCode::CPUI_INT_LESSEQUAL),
        ("bin_int_slessequal", OpCode::CPUI_INT_SLESSEQUAL),
        ("bin_int_add", OpCode::CPUI_INT_ADD),
        ("bin_int_sub", OpCode::CPUI_INT_SUB),
        ("bin_int_and", OpCode::CPUI_INT_AND),
        ("bin_int_or", OpCode::CPUI_INT_OR),
        ("bin_int_xor", OpCode::CPUI_INT_XOR),
        ("bin_int_left", OpCode::CPUI_INT_LEFT),
        ("bin_int_right", OpCode::CPUI_INT_RIGHT),
        ("bin_int_sright", OpCode::CPUI_INT_SRIGHT),
        ("bin_int_mult", OpCode::CPUI_INT_MULT),
        ("bin_int_div", OpCode::CPUI_INT_DIV),
        ("bin_int_sdiv", OpCode::CPUI_INT_SDIV),
        ("bin_int_rem", OpCode::CPUI_INT_REM),
        ("bin_int_srem", OpCode::CPUI_INT_SREM),
        ("bin_bool_and", OpCode::CPUI_BOOL_AND),
        ("bin_bool_or", OpCode::CPUI_BOOL_OR),
        ("bin_bool_xor", OpCode::CPUI_BOOL_XOR),
        ("bin_float_equal", OpCode::CPUI_FLOAT_EQUAL),
        ("bin_float_not_equal", OpCode::CPUI_FLOAT_NOTEQUAL),
        ("bin_float_less", OpCode::CPUI_FLOAT_LESS),
        ("bin_float_lessequal", OpCode::CPUI_FLOAT_LESSEQUAL),
        ("bin_float_add", OpCode::CPUI_FLOAT_ADD),
        ("bin_float_div", OpCode::CPUI_FLOAT_DIV),
        ("bin_float_mult", OpCode::CPUI_FLOAT_MULT),
        ("bin_float_sub", OpCode::CPUI_FLOAT_SUB),
    ];
    for (name, opc) in bin_cases {
        let (c0, c1) = match opc {
            OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_FLOAT_DIV
            | OpCode::CPUI_FLOAT_SUB => (0x22u64, 0x11u64),
            _ => (0x11u64, 0x22u64),
        };
        let top = top_no_out(
            *opc,
            vec![constant4(c0), constant4(c1)],
            pc,
            ctx.next_time(),
        );
        println!("case={}|text={}", name, render(&top));
    }

    // ---- opUnary one-liners (printc.hh:296-297/322) ----
    let un_cases: &[(&str, OpCode)] = &[
        ("un_int_2comp", OpCode::CPUI_INT_2COMP),
        ("un_int_negate", OpCode::CPUI_INT_NEGATE),
        ("un_float_neg", OpCode::CPUI_FLOAT_NEG),
    ];
    for (name, opc) in un_cases {
        let top = top_no_out(*opc, vec![constant4(0x10)], pc, ctx.next_time());
        println!("case={}|text={}", name, render(&top));
    }

    // ---- opFunc one-liners (printc.hh:293-295/317/323-324/328-330/333/343-344) ----
    let func_bin_cases: &[(&str, OpCode)] = &[
        ("func_int_carry", OpCode::CPUI_INT_CARRY),
        ("func_int_scarry", OpCode::CPUI_INT_SCARRY),
        ("func_int_sborrow", OpCode::CPUI_INT_SBORROW),
    ];
    for (name, opc) in func_bin_cases {
        let top = top_no_out(
            *opc,
            vec![constant4(0x11), constant4(0x22)],
            pc,
            ctx.next_time(),
        );
        println!("case={}|text={}", name, render(&top));
    }
    let func_un_cases: &[(&str, OpCode)] = &[
        ("func_float_nan", OpCode::CPUI_FLOAT_NAN),
        ("func_float_abs", OpCode::CPUI_FLOAT_ABS),
        ("func_float_sqrt", OpCode::CPUI_FLOAT_SQRT),
        ("func_float_ceil", OpCode::CPUI_FLOAT_CEIL),
        ("func_float_floor", OpCode::CPUI_FLOAT_FLOOR),
        ("func_float_round", OpCode::CPUI_FLOAT_ROUND),
    ];
    for (name, opc) in func_un_cases {
        let top = top_no_out(*opc, vec![constant4(0x10)], pc, ctx.next_time());
        println!("case={}|text={}", name, render(&top));
    }

    // func_piece (binary opFunc, table position after float_round to mirror
    // the C++ case table order): CONCAT44(0x11, 0x22).
    let top = top_no_out(
        OpCode::CPUI_PIECE,
        vec![constant4(0x11), constant4(0x22)],
        pc,
        ctx.next_time(),
    );
    println!("case=func_piece|text={}", render(&top));

    let func_tail_cases: &[(&str, OpCode)] = &[
        ("func_popcount", OpCode::CPUI_POPCOUNT),
        ("func_lzcount", OpCode::CPUI_LZCOUNT),
    ];
    for (name, opc) in func_tail_cases {
        let top = top_no_out(*opc, vec![constant4(0x10)], pc, ctx.next_time());
        println!("case={}|text={}", name, render(&top));
    }

    // ---- printc.cc:786 opIntZext / printc.cc:799 opIntSext ----
    // Same-size in/out defeats the cast recognizers -> ZEXT44/SEXT44
    // opFunc; the widening forms are recognized casts, read by an INT_AND.
    let z = implied_out(0xa000 + ctx.time as u64 + 1, 4, uint4());
    let _op_z = unary_op(
        OpCode::CPUI_INT_ZEXT,
        &constant4(0x10),
        z.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![z, constant_typed(0x22, 8, uint8())],
        pc,
        ctx.next_time(),
    );
    println!("case=zext_same|text={}", render(&top));

    // zext_hide: PTRADD reader — isExtensionCastImplied's unconditional
    // PTRADD arm (cast.cc:263-264 -> true) hides the recognized extension
    // on both sides; opPtradd renders `0x10 + 0x22`.
    let z = implied_out(0xa050 + ctx.time as u64 + 1, 4, uint4());
    let _op_z = unary_op(
        OpCode::CPUI_INT_ZEXT,
        &constant_typed(0x10, 1, uint1()),
        z.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_PTRADD,
        vec![z, constant4(0x22), constant4(0x0)],
        pc,
        ctx.next_time(),
    );
    println!("case=zext_hide|text={}", render(&top));

    let z = implied_out(0xa100 + ctx.time as u64 + 1, 4, uint4());
    let _op_z = unary_op(
        OpCode::CPUI_INT_ZEXT,
        &constant_typed(0x10, 1, uint1()),
        z.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![z, constant_typed(0x22, 8, uint8())],
        pc,
        ctx.next_time(),
    );
    println!("case=zext_widen|text={}", render(&top));

    let s = implied_out(0xa200 + ctx.time as u64 + 1, 4, int4());
    let _op_s = unary_op(
        OpCode::CPUI_INT_SEXT,
        &constant_typed(0x10, 4, int4()),
        s.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![s, constant_typed(0x22, 8, uint8())],
        pc,
        ctx.next_time(),
    );
    println!("case=sext_same|text={}", render(&top));

    let s = implied_out(0xa300 + ctx.time as u64 + 1, 4, int4());
    let _op_s = unary_op(
        OpCode::CPUI_INT_SEXT,
        &constant_typed(0x10, 1, int1()),
        s.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![s, constant_typed(0x22, 8, uint8())],
        pc,
        ctx.next_time(),
    );
    println!("case=sext_widen|text={}", render(&top));

    // ---- printc.cc:814-828 opBoolNegate full decision chain ----
    // Branch 3: non-flippable constant input -> boolean_not.
    let top = top_no_out(
        OpCode::CPUI_BOOL_NEGATE,
        vec![constant4(0x10)],
        pc,
        ctx.next_time(),
    );
    println!("case=boolneg_plain|text={}", render(&top));

    // Branch 2: implied INT_EQUAL input -> negatetoken flip -> `!=`.
    let (eq, _op_eq) = binary_op(
        OpCode::CPUI_INT_EQUAL,
        &constant4(0x11),
        &constant4(0x22),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_BOOL_NEGATE,
        vec![eq],
        pc,
        ctx.next_time(),
    );
    println!("case=boolneg_flip|text={}", render(&top));

    // Branch 1 under branch 2: double negation cancels -> `==`.
    let (eq, _op_eq) = binary_op(
        OpCode::CPUI_INT_EQUAL,
        &constant4(0x11),
        &constant4(0x22),
        pc,
        ctx.next_time(),
    );
    let inner = implied_out(0xa400 + ctx.time as u64 + 1, 4, uint4());
    let _op_inner = unary_op(
        OpCode::CPUI_BOOL_NEGATE,
        &eq,
        inner.clone(),
        pc,
        ctx.next_time(),
    );
    let top = top_no_out(
        OpCode::CPUI_BOOL_NEGATE,
        vec![inner],
        pc,
        ctx.next_time(),
    );
    println!("case=boolneg_double|text={}", render(&top));

    // ---- printc.cc:830 opFloatInt2Float + printc.hh:326-327 cast forms ----
    let conversions: &[(&str, OpCode)] = &[
        ("float_int2float", OpCode::CPUI_FLOAT_INT2FLOAT),
        ("float_float2float", OpCode::CPUI_FLOAT_FLOAT2FLOAT),
        ("float_trunc", OpCode::CPUI_FLOAT_TRUNC),
    ];
    for (name, opc) in conversions {
        let c = implied_out(0xa500 + ctx.time as u64 + 1, 4, uint4());
        let _op_c = unary_op(*opc, &constant4(0x10), c.clone(), pc, ctx.next_time());
        let top = top_no_out(
            OpCode::CPUI_INT_AND,
            vec![c, constant4(0x22)],
            pc,
            ctx.next_time(),
        );
        println!("case={}|text={}", name, render(&top));
    }

    // ---- printc.cc:872-877 opSubpiece opFunc fallback ----
    // NONZERO truncation offset defeats isSubpieceCast at its first guard
    // (cast.cc "if (offset != 0) return false") -> SUB48 opFunc arm; the
    // float-metatype 8-byte output mirrors the C++ fixture's float8 base.
    let sub = implied_out(0xa600 + ctx.time as u64 + 1, 8, float8());
    let _op_sub = {
        let mut op =
            PcodeOp::new(SeqNum::new(Address::new(pc), ctx.next_time()), OpCode::CPUI_SUBPIECE);
        op.set_opcode_flags(OpCode::CPUI_SUBPIECE);
        op.inrefs.push(constant4(0x11223344));
        op.inrefs.push(constant4(0x1));
        op.output = Some(sub.clone());
        let op_arc = Arc::new(RwLock::new(op));
        sub.write().unwrap().def = Some(Arc::downgrade(&op_arc));
        op_arc
    };
    let top = top_no_out(
        OpCode::CPUI_INT_AND,
        vec![sub, constant4(0x22)],
        pc,
        ctx.next_time(),
    );
    println!("case=subpiece_trunc|text={}", render(&top));

    // ---- printc.cc:880-893 opPtradd plain binary_plus form ----
    let top = top_no_out(
        OpCode::CPUI_PTRADD,
        vec![constant4(0x11), constant4(0x22), constant4(0x0)],
        pc,
        ctx.next_time(),
    );
    println!("case=ptradd_plain|text={}", render(&top));
}
