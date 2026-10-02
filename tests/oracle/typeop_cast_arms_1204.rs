// WORKPKG-UNMAP-TYPEOP-0001: current-Rugra comparand for the locked Ghidra
// getInputCast/getOutputToken virtual-dispatch arms fixture
// (typeop_cast_arms_1204.cc).
//
// Every case drives the production TypeOp trait arms through the same
// op shapes the oracle fixture builds (typed varnodes, foreign highs,
// implied ZEXT outputs, struct truncation fields, iop constants) and prints
// the identical key=value records.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeField, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::typeop::TypeOp;
use rudra::typeop::{
    TypeOpCallother, TypeOpCbranch, TypeOpFloatInt2Float, TypeOpIndirect, TypeOpIntCarry,
    TypeOpIntLessEqual, TypeOpIntLeft, TypeOpIntRem, TypeOpIntRight, TypeOpIntScarry,
    TypeOpIntSdiv, TypeOpIntSborrow, TypeOpIntSless, TypeOpIntSright, TypeOpIntSext,
    TypeOpIntZext, TypeOpPiece, TypeOpPtradd, TypeOpSegment, TypeOpSubpiece,
};
use rudra::varnode::Varnode;

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state (the same
/// configure_factory the TYPEOP-LOCALTYPE-DISPATCH-0001 fixture pins):
/// `TypeFactory::raw()`, the x86-64-gcc.cspec `<size_alignment_map>`,
/// `setupSizes` defaults, and the `buildCoreTypes` default core set.
fn configure_factory() -> TypeFactory {
    let mut factory = TypeFactory::raw();

    let alignment_map = element("size_alignment_map", &[]);
    for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("16", "16")] {
        alignment_map
            .write()
            .unwrap()
            .add_child(element("entry", &[("size", size), ("alignment", alignment)]));
    }
    let organization = element("data_organization", &[]);
    organization.write().unwrap().add_child(alignment_map);
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut organization_decoder = TreeDecoder::new(organization, registry.clone());
    factory.decode_data_organization(&mut organization_decoder);

    let core_types: &[(&str, usize, TypeMetatype, bool)] = &[
        ("void", 1, TypeMetatype::Void, false),
        ("bool", 1, TypeMetatype::Bool, false),
        ("uint1", 1, TypeMetatype::Uint, false),
        ("uint2", 2, TypeMetatype::Uint, false),
        ("uint4", 4, TypeMetatype::Uint, false),
        ("uint8", 8, TypeMetatype::Uint, false),
        ("int1", 1, TypeMetatype::Int, false),
        ("int2", 2, TypeMetatype::Int, false),
        ("int4", 4, TypeMetatype::Int, false),
        ("int8", 8, TypeMetatype::Int, false),
        ("float4", 4, TypeMetatype::Float, false),
        ("float8", 8, TypeMetatype::Float, false),
        ("float10", 10, TypeMetatype::Float, false),
        ("float16", 16, TypeMetatype::Float, false),
        ("xunknown1", 1, TypeMetatype::Unknown, false),
        ("xunknown2", 2, TypeMetatype::Unknown, false),
        ("xunknown4", 4, TypeMetatype::Unknown, false),
        ("xunknown8", 8, TypeMetatype::Unknown, false),
        ("code", 1, TypeMetatype::Code, false),
        ("char", 1, TypeMetatype::Int, true),
        ("wchar2", 2, TypeMetatype::Int, true),
        ("wchar4", 4, TypeMetatype::Int, true),
    ];
    for (name, size, meta, chartp) in core_types {
        factory
            .set_core_type_result(name, *size, *meta, *chartp)
            .unwrap_or_else(|message| panic!("core registration {name}: {message}"));
    }
    factory.cache_core_types();

    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });
    factory
}

fn ghidra_metatype(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::PartialUnion => 0,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::Union => 3,
        TypeMetatype::Struct => 4,
        TypeMetatype::Enum => 5,
        TypeMetatype::Array => 7,
        TypeMetatype::Pointer => 9,
        TypeMetatype::Float => 10,
        TypeMetatype::Code => 11,
        TypeMetatype::Bool => 12,
        TypeMetatype::Uint => 13,
        TypeMetatype::Int => 14,
        TypeMetatype::Unknown => 15,
        TypeMetatype::Spacebase => 16,
        TypeMetatype::Void => 17,
    }
}

/// Byte projection of `Datatype::printRaw` for the bounded result set the
/// cast arms can return (TypeBase/TypePointer/TypeCode): type.cc:139-146
/// prints the name (or `unkbyte<size>`), type.cc TypeCode::printRaw prints
/// `code()`, and the pointer form appends `" *"`.
fn ghidra_print_raw(datatype: &Datatype) -> String {
    if let Datatype::Pointer(pointer) = datatype {
        return format!("{} *", ghidra_print_raw(&pointer.ptr_to));
    }
    if matches!(datatype, Datatype::Code(_)) {
        return "code()".to_string();
    }
    let name = datatype.get_name().to_string();
    if !name.is_empty() {
        name
    } else {
        format!("unkbyte{}", datatype.get_size())
    }
}

fn emit_case(name: &str, ct: Option<Arc<Datatype>>) {
    match ct {
        Some(datatype) => {
            println!("case.{name}.result_type={}", ghidra_print_raw(&datatype));
            println!(
                "case.{name}.result_meta={}",
                ghidra_metatype(datatype.get_metatype())
            );
            println!("case.{name}.result_size={}", datatype.get_size());
        }
        None => {
            println!("case.{name}.result_type=NONE");
            println!("case.{name}.result_meta=NONE");
            println!("case.{name}.result_size=NONE");
        }
    }
}

/// A HighVariable whose derived type is `dt` (the fixture equivalent of the
/// oracle's `new HighVariable(vn)` / foreign-carrier attachments).
fn high_of(dt: Arc<Datatype>) -> Arc<RwLock<rudra::variable::HighVariable>> {
    Arc::new(RwLock::new(rudra::variable::HighVariable::new(dt)))
}

fn set_vtype(vn: &Arc<RwLock<Varnode>>, dt: Option<Arc<Datatype>>) {
    vn.write().unwrap().v_type = dt;
}

fn attach_foreign_high(vn: &Arc<RwLock<Varnode>>, dt: Arc<Datatype>) {
    vn.write().unwrap().high = Some(high_of(dt));
}

fn main() {
    let factory = Arc::new(RwLock::new(configure_factory()));
    let mut fd = Funcdata::new("typeop_cast_arms_fixture", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(factory.clone());

    let base = |size: usize, meta: TypeMetatype| -> Arc<Datatype> {
        factory
            .read()
            .unwrap()
            .get_base(size, meta)
            .expect("canonical base type")
    };
    let int4 = base(4, TypeMetatype::Int);
    let uint4 = base(4, TypeMetatype::Uint);
    let int1 = base(1, TypeMetatype::Int);
    let uint1 = base(1, TypeMetatype::Uint);
    let bool1 = base(1, TypeMetatype::Bool);
    let float4 = base(4, TypeMetatype::Float);
    let char_t = factory
        .read()
        .unwrap()
        .get_type_char(1)
        .expect("canonical char");
    let pointer = |to: Arc<Datatype>| -> Arc<Datatype> {
        factory
            .write()
            .unwrap()
            .get_type_pointer(8, to, 1)
    };
    let char_pointer = pointer(char_t.clone());
    let int_pointer = pointer(int4.clone());

    println!("fixture=WORKPKG-UNMAP-TYPEOP-0001.cast_arms");
    println!("architecture=x86:LE:64:default:gcc");

    // Detached fd: the union consults see an empty resolution map exactly
    // like the oracle's fresh Funcdata. `&fd` is taken fresh per call (a
    // short-lived shared borrow), mirroring the oracle's stable Funcdata*
    // pass-through.

    // --- Ordering comparisons -----------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x500010));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SLESS);
        let a = fd.new_varnode(4, Address::new(0x1000));
        set_vtype(&a, Some(int4.clone()));
        let b = fd.new_varnode(4, Address::new(0x1010));
        set_vtype(&b, Some(uint4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        fd.op_set_input(&op, b.clone(), 1);
        let out = fd.new_varnode(1, Address::new(0x2000));
        fd.op_set_output(&op, out);
        let sless = TypeOpIntSless::new(factory.clone());
        emit_case("sless_slot0_int_cur", sless.get_input_cast(&op, 0, &fd));
        emit_case("sless_slot1_uint_cur", sless.get_input_cast(&op, 1, &fd));
    }
    {
        let op = fd.new_op(2, Address::new(0x500020));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_LESSEQUAL);
        let a = fd.new_varnode(4, Address::new(0x1020));
        set_vtype(&a, Some(uint4.clone()));
        let b = fd.new_varnode(4, Address::new(0x1030));
        set_vtype(&b, Some(int4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        fd.op_set_input(&op, b.clone(), 1);
        let out = fd.new_varnode(1, Address::new(0x2010));
        fd.op_set_output(&op, out);
        let lessequal = TypeOpIntLessEqual::new(factory.clone());
        emit_case(
            "lessequal_slot0_uint_cur",
            lessequal.get_input_cast(&op, 0, &fd),
        );
        emit_case(
            "lessequal_slot1_int_cur",
            lessequal.get_input_cast(&op, 1, &fd),
        );
    }
    {
        let op = fd.new_op(2, Address::new(0x500030));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SLESS);
        let a = fd.new_varnode(1, Address::new(0x1040));
        set_vtype(&a, Some(int1.clone()));
        let b = fd.new_varnode(1, Address::new(0x1050));
        set_vtype(&b, Some(bool1.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        fd.op_set_input(&op, b.clone(), 1);
        let out = fd.new_varnode(1, Address::new(0x2020));
        fd.op_set_output(&op, out);
        let sless = TypeOpIntSless::new(factory.clone());
        emit_case(
            "sless_slot0_promotion_forced",
            sless.get_input_cast(&op, 0, &fd),
        );
    }

    // --- Extensions ---------------------------------------------------------
    {
        let op = fd.new_op(1, Address::new(0x500040));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ZEXT);
        let a = fd.new_varnode(1, Address::new(0x1060));
        set_vtype(&a, Some(int1.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let out = fd.new_varnode(4, Address::new(0x2030));
        fd.op_set_output(&op, out);
        let zext = TypeOpIntZext::new(factory.clone());
        emit_case("zext_slot0_int1_cur", zext.get_input_cast(&op, 0, &fd));
    }
    {
        let op = fd.new_op(1, Address::new(0x500050));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ZEXT);
        let a = fd.new_varnode(4, Address::new(0x1070));
        set_vtype(&a, Some(uint4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let out = fd.new_varnode(8, Address::new(0x2040));
        fd.op_set_output(&op, out);
        let zext = TypeOpIntZext::new(factory.clone());
        emit_case("zext_slot0_uint4_cur", zext.get_input_cast(&op, 0, &fd));
    }
    {
        let op = fd.new_op(1, Address::new(0x500060));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SEXT);
        let a = fd.new_varnode(4, Address::new(0x1080));
        set_vtype(&a, Some(uint4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let out = fd.new_varnode(8, Address::new(0x2050));
        fd.op_set_output(&op, out);
        let sext = TypeOpIntSext::new(factory.clone());
        emit_case("sext_slot0_uint4_cur", sext.get_input_cast(&op, 0, &fd));
    }

    // --- Shifts -------------------------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x500070));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_RIGHT);
        let a = fd.new_varnode(4, Address::new(0x1090));
        set_vtype(&a, Some(uint4.clone()));
        let shift_amount = fd.new_constant(1, 3);
        attach_foreign_high(&shift_amount, int1.clone());
        fd.op_set_input(&op, a.clone(), 0);
        fd.op_set_input(&op, shift_amount, 1);
        let out = fd.new_varnode(4, Address::new(0x2060));
        fd.op_set_output(&op, out);
        let right = TypeOpIntRight::new(factory.clone());
        emit_case("right_slot0_uint4_cur", right.get_input_cast(&op, 0, &fd));
        emit_case("right_slot1_base_arm", right.get_input_cast(&op, 1, &fd));
    }
    {
        let op = fd.new_op(2, Address::new(0x500080));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SRIGHT);
        let a = fd.new_varnode(1, Address::new(0x10a0));
        set_vtype(&a, Some(bool1.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let amount = fd.new_constant(1, 2);
        fd.op_set_input(&op, amount, 1);
        let out = fd.new_varnode(1, Address::new(0x2070));
        fd.op_set_output(&op, out);
        let sright = TypeOpIntSright::new(factory.clone());
        emit_case(
            "sright_slot0_promotion_forced",
            sright.get_input_cast(&op, 0, &fd),
        );
    }

    // --- Divide/remainder ----------------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x500090));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SDIV);
        let a = fd.new_varnode(4, Address::new(0x10b0));
        set_vtype(&a, Some(uint4.clone()));
        let b = fd.new_varnode(4, Address::new(0x10c0));
        set_vtype(&b, Some(int4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        fd.op_set_input(&op, b.clone(), 1);
        let out = fd.new_varnode(4, Address::new(0x2080));
        fd.op_set_output(&op, out);
        let sdiv = TypeOpIntSdiv::new(factory.clone());
        emit_case("sdiv_slot0_uint_cur", sdiv.get_input_cast(&op, 0, &fd));
        emit_case("sdiv_slot1_int_cur", sdiv.get_input_cast(&op, 1, &fd));
    }
    {
        let op = fd.new_op(2, Address::new(0x5000a0));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_REM);
        let a = fd.new_varnode(4, Address::new(0x10d0));
        set_vtype(&a, Some(uint4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let divisor = fd.new_constant(4, 7);
        fd.op_set_input(&op, divisor, 1);
        let out = fd.new_varnode(4, Address::new(0x2090));
        fd.op_set_output(&op, out);
        let rem = TypeOpIntRem::new(factory.clone());
        emit_case("rem_slot0_uint_cur", rem.get_input_cast(&op, 0, &fd));
    }

    // --- FLOAT_INT2FLOAT ------------------------------------------------------
    {
        let op = fd.new_op(1, Address::new(0x5000b0));
        fd.op_set_opcode(&op, OpCode::CPUI_FLOAT_INT2FLOAT);
        let a = fd.new_varnode(4, Address::new(0x10e0));
        set_vtype(&a, Some(int4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let out = fd.new_varnode(8, Address::new(0x20a0));
        fd.op_set_output(&op, out);
        let i2f = TypeOpFloatInt2Float::new(factory.clone());
        emit_case("i2f_slot0_int_cur", i2f.get_input_cast(&op, 0, &fd));
    }
    {
        let op = fd.new_op(1, Address::new(0x5000c0));
        fd.op_set_opcode(&op, OpCode::CPUI_FLOAT_INT2FLOAT);
        let a = fd.new_varnode(4, Address::new(0x10f0));
        set_vtype(&a, Some(uint4.clone()));
        fd.op_set_input(&op, a.clone(), 0);
        let out = fd.new_varnode(8, Address::new(0x20b0));
        fd.op_set_output(&op, out);
        let i2f = TypeOpFloatInt2Float::new(factory.clone());
        emit_case("i2f_slot0_uint_cur", i2f.get_input_cast(&op, 0, &fd));
    }
    {
        let op = fd.new_op(1, Address::new(0x5000d0));
        fd.op_set_opcode(&op, OpCode::CPUI_FLOAT_INT2FLOAT);
        let a = fd.new_constant(4, 0x7f);
        attach_foreign_high(&a, uint4.clone());
        fd.op_set_input(&op, a, 0);
        let out = fd.new_varnode(8, Address::new(0x20c0));
        fd.op_set_output(&op, out);
        let i2f = TypeOpFloatInt2Float::new(factory.clone());
        emit_case(
            "i2f_slot0_const_low_highbit",
            i2f.get_input_cast(&op, 0, &fd),
        );
    }
    {
        let op = fd.new_op(1, Address::new(0x5000e0));
        fd.op_set_opcode(&op, OpCode::CPUI_FLOAT_INT2FLOAT);
        let a = fd.new_constant(4, 0x80000000);
        attach_foreign_high(&a, uint4.clone());
        fd.op_set_input(&op, a, 0);
        let out = fd.new_varnode(8, Address::new(0x20d0));
        fd.op_set_output(&op, out);
        let i2f = TypeOpFloatInt2Float::new(factory.clone());
        emit_case(
            "i2f_slot0_const_high_highbit",
            i2f.get_input_cast(&op, 0, &fd),
        );
    }
    {
        // absorbZext: implied INT_ZEXT output feeding the conversion.
        let zext_op = fd.new_op(1, Address::new(0x5000f0));
        fd.op_set_opcode(&zext_op, OpCode::CPUI_INT_ZEXT);
        let zext_in = fd.new_varnode(4, Address::new(0x1120));
        set_vtype(&zext_in, Some(uint4.clone()));
        let zext_out = fd.new_varnode(8, Address::new(0x1130));
        fd.op_set_input(&zext_op, zext_in, 0);
        fd.op_set_output(&zext_op, zext_out.clone());
        zext_out.write().unwrap().set_implied();

        let op = fd.new_op(1, Address::new(0x500100));
        fd.op_set_opcode(&op, OpCode::CPUI_FLOAT_INT2FLOAT);
        fd.op_set_input(&op, zext_out, 0);
        let out = fd.new_varnode(8, Address::new(0x20e0));
        fd.op_set_output(&op, out);
        let i2f = TypeOpFloatInt2Float::new(factory.clone());
        emit_case("i2f_slot0_absorb_zext", i2f.get_input_cast(&op, 0, &fd));
    }

    // --- PTRADD slot 0 --------------------------------------------------------
    {
        let op = fd.new_op(3, Address::new(0x500110));
        fd.op_set_opcode(&op, OpCode::CPUI_PTRADD);
        let a = fd.new_varnode(8, Address::new(0x1140));
        set_vtype(&a, Some(int_pointer.clone()));
        attach_foreign_high(&a, char_pointer.clone());
        fd.op_set_input(&op, a, 0);
        let index = fd.new_constant(8, 2);
        fd.op_set_input(&op, index, 1);
        let scale = fd.new_constant(1, 4);
        fd.op_set_input(&op, scale, 2);
        let out = fd.new_varnode(8, Address::new(0x20f0));
        fd.op_set_output(&op, out);
        let ptradd = TypeOpPtradd::new(factory.clone());
        emit_case("ptradd_slot0_align_diff", ptradd.get_input_cast(&op, 0, &fd));

        let b = fd.new_varnode(8, Address::new(0x1150));
        set_vtype(&b, Some(int_pointer.clone()));
        attach_foreign_high(&b, int_pointer.clone());
        fd.op_set_input(&op, b, 0);
        emit_case(
            "ptradd_slot0_align_equal",
            ptradd.get_input_cast(&op, 0, &fd),
        );

        let c = fd.new_varnode(4, Address::new(0x1160));
        set_vtype(&c, Some(int4.clone()));
        attach_foreign_high(&c, char_pointer.clone());
        fd.op_set_input(&op, c, 0);
        emit_case(
            "ptradd_slot0_nonptr_vntype",
            ptradd.get_input_cast(&op, 0, &fd),
        );

        let d = fd.new_varnode(8, Address::new(0x1170));
        set_vtype(&d, Some(int_pointer.clone()));
        fd.op_set_input(&op, d, 0);
        let index_const = fd.new_constant(8, 2);
        attach_foreign_high(&index_const, int4.clone());
        fd.op_set_input(&op, index_const, 1);
        emit_case("ptradd_slot1_base_arm", ptradd.get_input_cast(&op, 1, &fd));
    }

    // --- Never-cast arms ------------------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x500120));
        fd.op_set_opcode(&op, OpCode::CPUI_PIECE);
        let a = fd.new_varnode(4, Address::new(0x1180));
        set_vtype(&a, Some(int4.clone()));
        let b = fd.new_varnode(4, Address::new(0x1190));
        set_vtype(&b, Some(uint4.clone()));
        fd.op_set_input(&op, a, 0);
        fd.op_set_input(&op, b, 1);
        let out = fd.new_varnode(8, Address::new(0x2100));
        fd.op_set_output(&op, out);
        let piece = TypeOpPiece::new(factory.clone());
        emit_case("piece_slot0_never", piece.get_input_cast(&op, 0, &fd));
        emit_case("piece_slot1_never", piece.get_input_cast(&op, 1, &fd));
    }
    {
        let op = fd.new_op(2, Address::new(0x500130));
        fd.op_set_opcode(&op, OpCode::CPUI_SUBPIECE);
        let a = fd.new_varnode(8, Address::new(0x11a0));
        set_vtype(&a, Some(uint4.clone()));
        fd.op_set_input(&op, a, 0);
        let shift = fd.new_constant(1, 0);
        fd.op_set_input(&op, shift, 1);
        let out = fd.new_varnode(4, Address::new(0x2110));
        fd.op_set_output(&op, out);
        let subpiece = TypeOpSubpiece::new(factory.clone());
        emit_case("subpiece_slot0_never", subpiece.get_input_cast(&op, 0, &fd));
    }
    {
        let op = fd.new_op(3, Address::new(0x500140));
        fd.op_set_opcode(&op, OpCode::CPUI_SEGMENTOP);
        let a = fd.new_varnode(8, Address::new(0x11b0));
        set_vtype(&a, Some(int4.clone()));
        fd.op_set_input(&op, a, 0);
        let base_const = fd.new_constant(8, 0);
        fd.op_set_input(&op, base_const, 1);
        let c = fd.new_varnode(8, Address::new(0x11c0));
        set_vtype(&c, Some(int_pointer.clone()));
        fd.op_set_input(&op, c, 1);
        let out = fd.new_varnode(8, Address::new(0x2120));
        fd.op_set_output(&op, out);
        let segment = TypeOpSegment::new(factory.clone());
        emit_case("segment_slot0_never", segment.get_input_cast(&op, 0, &fd));
        emit_case("segment_slot2_never", segment.get_input_cast(&op, 2, &fd));
    }

    // --- getOutputToken families ----------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x500150));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_LEFT);
        let a = fd.new_varnode(1, Address::new(0x11d0));
        set_vtype(&a, Some(bool1.clone()));
        fd.op_set_input(&op, a, 0);
        let amount = fd.new_constant(1, 3);
        fd.op_set_input(&op, amount, 1);
        let out = fd.new_varnode(1, Address::new(0x2130));
        fd.op_set_output(&op, out);
        let left = TypeOpIntLeft::new(factory.clone());
        emit_case("left_token_bool_in", left.get_output_token_in_fd(&op, &fd));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_RIGHT);
        let right = TypeOpIntRight::new(factory.clone());
        emit_case("right_token_bool_in", right.get_output_token_in_fd(&op, &fd));
        let b = fd.new_varnode(4, Address::new(0x11e0));
        set_vtype(&b, Some(int4.clone()));
        fd.op_set_input(&op, b, 0);
        let out4 = fd.new_varnode(4, Address::new(0x2140));
        fd.op_set_output(&op, out4);
        emit_case("right_token_int_in", right.get_output_token_in_fd(&op, &fd));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SRIGHT);
        let sright = TypeOpIntSright::new(factory.clone());
        emit_case("sright_token_int_in", sright.get_output_token_in_fd(&op, &fd));
    }
    {
        let op = fd.new_op(2, Address::new(0x500160));
        fd.op_set_opcode(&op, OpCode::CPUI_PIECE);
        let a = fd.new_varnode(4, Address::new(0x11f0));
        let b = fd.new_varnode(4, Address::new(0x1200));
        fd.op_set_input(&op, a, 0);
        fd.op_set_input(&op, b, 1);
        let out = fd.new_varnode(8, Address::new(0x2150));
        set_vtype(&out, Some(int4.clone()));
        attach_foreign_high(&out, int4.clone());
        fd.op_set_output(&op, out);
        let piece = TypeOpPiece::new(factory.clone());
        emit_case("piece_token_int_out", piece.get_output_token_in_fd(&op, &fd));
        let out2 = fd.new_varnode(8, Address::new(0x2160));
        set_vtype(&out2, Some(float4.clone()));
        attach_foreign_high(&out2, float4.clone());
        fd.op_set_output(&op, out2);
        emit_case("piece_token_float_out", piece.get_output_token_in_fd(&op, &fd));
    }
    {
        // Struct with alpha:int4@0 and beta:float4@8 (16 bytes, align 4).
        factory
            .write()
            .unwrap()
            .create_struct("typeop_cast_fixture_struct");
        let fields = vec![
            TypeField {
                name: "alpha".to_string(),
                offset: 0,
                type_ptr: int4.clone(),
            },
            TypeField {
                name: "beta".to_string(),
                offset: 8,
                type_ptr: float4.clone(),
            },
        ];
        // The oracle uses the fixed-size form `setFields(fd, 16, 4, 0)`
        // (type.cc:3479); set_fields_sized is its twin.
        let record = factory
            .write()
            .unwrap()
            .set_fields_sized("typeop_cast_fixture_struct", fields, 16, 4)
            .expect("fixture struct fields");

        let op = fd.new_op(2, Address::new(0x500170));
        fd.op_set_opcode(&op, OpCode::CPUI_SUBPIECE);
        let a = fd.new_varnode(16, Address::new(0x1210));
        set_vtype(&a, Some(record.clone()));
        fd.op_set_input(&op, a, 0);
        let shift0 = fd.new_constant(1, 0);
        fd.op_set_input(&op, shift0, 1);
        let out = fd.new_varnode(4, Address::new(0x2170));
        attach_foreign_high(&out, base(4, TypeMetatype::Unknown));
        fd.op_set_output(&op, out);
        let subpiece = TypeOpSubpiece::new(factory.clone());
        emit_case(
            "subpiece_token_struct_field",
            subpiece.get_output_token_in_fd(&op, &fd),
        );
        // Gap (lsb=4): no field -> def-facing unknown -> the int base.
        let outg = fd.new_varnode(4, Address::new(0x2175));
        attach_foreign_high(&outg, base(4, TypeMetatype::Unknown));
        fd.op_set_output(&op, outg);
        let shift4 = fd.new_constant(1, 4);
        fd.op_set_input(&op, shift4, 1);
        emit_case(
            "subpiece_token_gap_intbase",
            subpiece.get_output_token_in_fd(&op, &fd),
        );
        // Def-facing float output wins over the int base.
        let outf = fd.new_varnode(4, Address::new(0x2180));
        set_vtype(&outf, Some(float4.clone()));
        attach_foreign_high(&outf, float4.clone());
        fd.op_set_output(&op, outf);
        emit_case(
            "subpiece_token_deffacing_float",
            subpiece.get_output_token_in_fd(&op, &fd),
        );
    }
    {
        let op = fd.new_op(3, Address::new(0x500180));
        fd.op_set_opcode(&op, OpCode::CPUI_SEGMENTOP);
        let a = fd.new_varnode(8, Address::new(0x1220));
        let c = fd.new_varnode(8, Address::new(0x1230));
        set_vtype(&c, Some(int_pointer.clone()));
        fd.op_set_input(&op, a, 0);
        let base_const = fd.new_constant(8, 0);
        fd.op_set_input(&op, base_const, 1);
        fd.op_set_input(&op, c, 2);
        let out = fd.new_varnode(8, Address::new(0x2190));
        fd.op_set_output(&op, out);
        let segment = TypeOpSegment::new(factory.clone());
        emit_case("segment_token_in2", segment.get_output_token_in_fd(&op, &fd));
    }

    // --- getOperatorName -------------------------------------------------------
    {
        let op = fd.new_op(1, Address::new(0x500190));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ZEXT);
        let a = fd.new_varnode(1, Address::new(0x1240));
        fd.op_set_input(&op, a, 0);
        let out = fd.new_varnode(4, Address::new(0x21a0));
        fd.op_set_output(&op, out);
        let op_view = op.0.read().unwrap();
        let name = TypeOpIntZext::new(factory.clone()).get_operator_name(&op_view);
        println!("case.zext_name={name}");
        drop(op_view);
        let name = TypeOpIntSext::new(factory.clone()).get_operator_name(&op.0.read().unwrap());
        println!("case.sext_name={name}");
    }
    {
        let op = fd.new_op(2, Address::new(0x5001a0));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_CARRY);
        let a = fd.new_varnode(4, Address::new(0x1250));
        let b = fd.new_varnode(4, Address::new(0x1260));
        fd.op_set_input(&op, a, 0);
        fd.op_set_input(&op, b, 1);
        let op_view = op.0.read().unwrap();
        println!(
            "case.carry_name={}",
            TypeOpIntCarry::new(factory.clone()).get_operator_name(&op_view)
        );
        println!(
            "case.scarry_name={}",
            TypeOpIntScarry::new(factory.clone()).get_operator_name(&op_view)
        );
        println!(
            "case.sborrow_name={}",
            TypeOpIntSborrow::new(factory.clone()).get_operator_name(&op_view)
        );
    }
    {
        let op = fd.new_op(2, Address::new(0x5001b0));
        fd.op_set_opcode(&op, OpCode::CPUI_PIECE);
        let a = fd.new_varnode(4, Address::new(0x1270));
        let b = fd.new_varnode(4, Address::new(0x1280));
        fd.op_set_input(&op, a, 0);
        fd.op_set_input(&op, b, 1);
        let out = fd.new_varnode(8, Address::new(0x21b0));
        fd.op_set_output(&op, out);
        let op_view = op.0.read().unwrap();
        println!(
            "case.piece_name={}",
            TypeOpPiece::new(factory.clone()).get_operator_name(&op_view)
        );
        drop(op_view);
        fd.op_set_opcode(&op, OpCode::CPUI_SUBPIECE);
        let shift = fd.new_constant(1, 0);
        fd.op_set_input(&op, shift, 1);
        println!(
            "case.subpiece_name={}",
            TypeOpSubpiece::new(factory.clone()).get_operator_name(&op.0.read().unwrap())
        );
    }

    // --- getInputLocal specials --------------------------------------------------
    {
        let op = fd.new_op(2, Address::new(0x5001c0));
        fd.op_set_opcode(&op, OpCode::CPUI_CBRANCH);
        let target = fd.new_code_ref(Address::new(0x600000));
        fd.op_set_input(&op, target, 0);
        let cond = fd.new_varnode(1, Address::new(0x1290));
        set_vtype(&cond, Some(bool1.clone()));
        fd.op_set_input(&op, cond, 1);
        let cbranch = TypeOpCbranch::new(factory.clone());
        emit_case("cbranch_local_slot0", cbranch.get_input_local(&op.0.read().unwrap(), 0));
        emit_case("cbranch_local_slot1", cbranch.get_input_local(&op.0.read().unwrap(), 1));
    }
    {
        let iop_target = fd.new_op(1, Address::new(0x600100));
        fd.op_set_opcode(&iop_target, OpCode::CPUI_STORE);

        let op = fd.new_op(2, Address::new(0x5001d0));
        fd.op_set_opcode(&op, OpCode::CPUI_INDIRECT);
        let value = fd.new_varnode(4, Address::new(0x12a0));
        set_vtype(&value, Some(int4.clone()));
        fd.op_set_input(&op, value, 0);
        let iop = fd.new_varnode_iop(&iop_target);
        fd.op_set_input(&op, iop, 1);
        let indirect = TypeOpIndirect::new(factory.clone());
        emit_case(
            "indirect_local_slot0",
            indirect.get_input_local_in_fd(&op, 0, &fd),
        );
        emit_case(
            "indirect_local_slot1",
            indirect.get_input_local_in_fd(&op, 1, &fd),
        );
    }
    {
        let op = fd.new_op(2, Address::new(0x5001e0));
        fd.op_set_opcode(&op, OpCode::CPUI_CALLOTHER);
        let index = fd.new_constant(1, 120);
        fd.op_set_input(&op, index, 0);
        let arg = fd.new_varnode(4, Address::new(0x12b0));
        fd.op_set_input(&op, arg, 1);
        let callother = TypeOpCallother::new(factory.clone());
        emit_case(
            "callother_local_slot0",
            callother.get_input_local_in_fd(&op, 0, &fd),
        );
        emit_case(
            "callother_local_slot1",
            callother.get_input_local_in_fd(&op, 1, &fd),
        );
    }
}
