// TYPEOP-LOCALBASE-DEFAULTS-0001: current-Rugra comparand for the locked
// Ghidra TypeOp base-class getOutputLocal/getInputLocal defaults and the
// TypeOpCall constructor opflags.
//
// Every observation goes through the production TypeOpManager dispatch table
// built with the same TypeFactory allocation the fixture Architecture uses,
// so the base-default cases exercise the shared `base_local_type` helper
// through the `local_type_factory` provider hook exactly as production would.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::typeop::{TypeOp, TypeOpManager};

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state the C++ fixture
/// observes (same bootstrap as tests/oracle/typeop_local_type_1204.rs):
/// `TypeFactory::raw()`, the x86-64-gcc.cspec `<size_alignment_map>`
/// (entries 1,2,4,8,16), `setup_sizes` defaults for a 64-bit stack pointer,
/// and the `SleighArchitecture::buildCoreTypes` default core set.
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

    // sleigh_arch.cc:215-236 order preserved.
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

fn emit_bool(key: &str, value: bool) {
    println!("{key}={}", if value { 1 } else { 0 });
}

fn factory_base(
    factory: &Arc<RwLock<TypeFactory>>,
    size: usize,
    metatype: TypeMetatype,
) -> Arc<Datatype> {
    factory
        .read()
        .unwrap()
        .get_base(size, metatype)
        .expect("fixture canonical base type")
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

/// Byte projection of `Datatype::printRaw` for the bounded result set these
/// cases can return (TypeBase and TypePointer): type.cc:139-146 prints the
/// name or `unkbyte<size>` for every non-pointer type, and type.cc:910-916
/// appends `" *"` for pointers (factory pointer products carry no spaceid,
/// so there is no suffix beyond that).
fn ghidra_print_raw(datatype: &Datatype) -> String {
    if let Datatype::Pointer(pointer) = datatype {
        return format!("{} *", ghidra_print_raw(&pointer.ptr_to));
    }
    let name = datatype.get_name().to_string();
    if !name.is_empty() {
        name
    } else {
        format!("unkbyte{}", datatype.get_size())
    }
}

fn emit_result(name: &str, slot: i32, size: usize, actual: &Option<Arc<Datatype>>) {
    println!("case.{name}.slot={slot}");
    println!("case.{name}.operand_size={size}");
    match actual.as_ref() {
        Some(datatype) => {
            println!("case.{name}.result_type={}", ghidra_print_raw(datatype));
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

fn identity(actual: &Option<Arc<Datatype>>, expected: &Arc<Datatype>) -> bool {
    actual.as_ref().is_some_and(|datatype| Arc::ptr_eq(datatype, expected))
}

/// Input-local observation through the production dispatch table; the
/// expected fallback is getBase(op.get_in(slot).size, UNKNOWN).
fn emit_input_case(
    name: &str,
    typeop: &dyn TypeOp,
    op: &PcodeOp,
    slot: usize,
    type_factory: &Arc<RwLock<TypeFactory>>,
) {
    let size = op
        .get_in(slot)
        .expect("fixture input slot")
        .read()
        .unwrap()
        .get_size();
    let actual = typeop.get_input_local(op, slot);
    let repeat = typeop.get_input_local(op, slot);
    emit_result(name, slot as i32, size, &actual);
    let fallback = factory_base(type_factory, size, TypeMetatype::Unknown);
    emit_bool(
        &format!("case.{name}.base_identity"),
        identity(&actual, &fallback),
    );
    emit_bool(
        &format!("case.{name}.repeat_identity"),
        match (actual.as_ref(), repeat.as_ref()) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        },
    );
}

/// Output-local observation through the production dispatch table; the
/// expected fallback is getBase(op.get_out().size, UNKNOWN).
fn emit_output_case(
    name: &str,
    typeop: &dyn TypeOp,
    op: &PcodeOp,
    type_factory: &Arc<RwLock<TypeFactory>>,
) {
    let size = op
        .get_out()
        .expect("fixture output varnode")
        .read()
        .unwrap()
        .get_size();
    let actual = typeop.get_output_local(op);
    let repeat = typeop.get_output_local(op);
    emit_result(name, -1, size, &actual);
    let fallback = factory_base(type_factory, size, TypeMetatype::Unknown);
    emit_bool(
        &format!("case.{name}.base_identity"),
        identity(&actual, &fallback),
    );
    emit_bool(
        &format!("case.{name}.repeat_identity"),
        match (actual.as_ref(), repeat.as_ref()) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        },
    );
}

/// ZEXT/SEXT metatype-derivation observation. Both sides derive the local
/// type as getBase(size, metain/metaout) with UINT (ZEXT) / INT (SEXT)
/// (typeop.cc:1115/:1141 constructors driving TypeOpFunc::get*Local at
/// typeop.cc:365/:371); the fixture pins the post-PRINTC-CAST-OPNAME-0001-M1
/// state where the Rugra macro family resolves through the constructor-
/// registered metatype pair instead of echoing the opposite varnode's v_type.
fn emit_metatype_case(
    name: &str,
    typeop: &dyn TypeOp,
    op: &PcodeOp,
    slot: i32,
    meta: TypeMetatype,
    type_factory: &Arc<RwLock<TypeFactory>>,
) {
    let (actual, size) = if slot < 0 {
        let size = op
            .get_out()
            .expect("fixture output varnode")
            .read()
            .unwrap()
            .get_size();
        (typeop.get_output_local(op), size)
    } else {
        let size = op
            .get_in(slot as usize)
            .expect("fixture input slot")
            .read()
            .unwrap()
            .get_size();
        (typeop.get_input_local(op, slot as usize), size)
    };
    emit_result(name, slot, size, &actual);
    let meta_base = factory_base(type_factory, size, meta);
    let unknown_base = factory_base(type_factory, size, TypeMetatype::Unknown);
    emit_bool(
        &format!("case.{name}.meta_identity"),
        identity(&actual, &meta_base),
    );
    emit_bool(
        &format!("case.{name}.base_identity"),
        identity(&actual, &unknown_base),
    );
}

fn main() {
    let mut factory = configure_factory();

    let void_type = factory.get_type_void();
    let char_type = factory
        .get_type_char_named("char")
        .expect("canonical char type");
    let char_pointer = factory.get_type_pointer(8, char_type, 1);

    let type_factory = Arc::new(RwLock::new(factory));
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());

    let mut fd = Funcdata::new("typeop_localbase_fixture", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(type_factory.clone());

    // Production dispatch table built exactly like TypeOpManager::new does.
    let manager = TypeOpManager::new(type_factory.clone());

    println!("fixture=TYPEOP-LOCALBASE-DEFAULTS-0001");
    println!("architecture={}", architecture.archid);

    // ---- TypeOpCall constructor opflags (typeop.cc:663) ----
    let call_typeop = manager
        .get_op(OpCode::CPUI_CALL)
        .expect("registered CALL TypeOp");
    let call_flags = call_typeop.get_flags();
    println!("flags.call.hex={:x}", call_flags);
    println!("flags.call.decimal={}", call_flags);
    emit_bool(
        "flags.call.special",
        call_flags & rudra::op::pcodeop_flags::SPECIAL != 0,
    );
    emit_bool(
        "flags.call.call_bit",
        call_flags & rudra::op::pcodeop_flags::CALL != 0,
    );
    emit_bool(
        "flags.call.has_callspec",
        call_flags & rudra::op::pcodeop_flags::HAS_CALLSPEC != 0,
    );
    emit_bool(
        "flags.call.coderef",
        call_flags & rudra::op::pcodeop_flags::CODEREF != 0,
    );
    emit_bool(
        "flags.call.nocollapse",
        call_flags & rudra::op::pcodeop_flags::NOCOLLAPSE != 0,
    );
    emit_bool(
        "flags.call.commutative_clear",
        call_flags & rudra::op::pcodeop_flags::COMMUTATIVE == 0,
    );

    // ---- BRANCH: base defaults on the coderef input ----
    {
        let branch_typeop = manager
            .get_op(OpCode::CPUI_BRANCH)
            .expect("registered BRANCH TypeOp");
        let target = fd.new_code_ref(Address::new(0x600100));
        let op = fd.new_op(1, Address::new(0x500100));
        fd.op_set_opcode(&op, OpCode::CPUI_BRANCH);
        fd.op_set_input(&op, target, 0);
        let call = op.0.read().unwrap();
        emit_input_case("branch_input0", branch_typeop, &call, 0, &type_factory);
    }

    // ---- BRANCHIND: base defaults on a 4-byte constant input ----
    {
        let branchind_typeop = manager
            .get_op(OpCode::CPUI_BRANCHIND)
            .expect("registered BRANCHIND TypeOp");
        let target = fd.new_constant(4, 0x1234);
        let op = fd.new_op(1, Address::new(0x500110));
        fd.op_set_opcode(&op, OpCode::CPUI_BRANCHIND);
        fd.op_set_input(&op, target, 0);
        let call = op.0.read().unwrap();
        emit_input_case("branchind_input0", branchind_typeop, &call, 0, &type_factory);
    }

    // ---- SEGMENTOP: base defaults incl. a non-standard 3-byte operand ----
    {
        let segment_typeop = manager
            .get_op(OpCode::CPUI_SEGMENTOP)
            .expect("registered SEGMENTOP TypeOp");
        let spaceid = fd.new_constant(4, 0);
        let offset3 = fd.new_constant(3, 0x112233);
        let base = fd.new_constant(8, 0);
        let out = fd.new_varnode(3, Address::new(0x300));
        let op = fd.new_op(3, Address::new(0x500120));
        fd.op_set_opcode(&op, OpCode::CPUI_SEGMENTOP);
        fd.op_set_input(&op, spaceid, 0);
        fd.op_set_input(&op, offset3, 1);
        fd.op_set_input(&op, base, 2);
        fd.op_set_output(&op, out);
        let call = op.0.read().unwrap();
        emit_input_case(
            "segment_input1_size3",
            segment_typeop,
            &call,
            1,
            &type_factory,
        );
        emit_output_case("segment_output_size3", segment_typeop, &call, &type_factory);
    }

    // ---- CAST: "we don't care what types are cast" -> base defaults ----
    {
        let cast_typeop = manager
            .get_op(OpCode::CPUI_CAST)
            .expect("registered CAST TypeOp");
        let input0 = fd.new_constant(4, 0xaabbccdd);
        let out = fd.new_varnode(4, Address::new(0x400));
        let op = fd.new_op(1, Address::new(0x500130));
        fd.op_set_opcode(&op, OpCode::CPUI_CAST);
        fd.op_set_input(&op, input0, 0);
        fd.op_set_output(&op, out);
        let call = op.0.read().unwrap();
        emit_input_case("cast_input0", cast_typeop, &call, 0, &type_factory);
        emit_output_case("cast_output", cast_typeop, &call, &type_factory);
    }

    // ---- ZEXT/SEXT: TypeOpFunc metain/metaout derivation (UINT vs INT) ----
    {
        let zext_typeop = manager
            .get_op(OpCode::CPUI_INT_ZEXT)
            .expect("registered ZEXT TypeOp");
        let input0 = fd.new_constant(1, 0x7f);
        let out = fd.new_varnode(4, Address::new(0x500));
        let op = fd.new_op(1, Address::new(0x500140));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_ZEXT);
        fd.op_set_input(&op, input0, 0);
        fd.op_set_output(&op, out);
        let call = op.0.read().unwrap();
        emit_metatype_case("zext_input0", zext_typeop, &call, 0, TypeMetatype::Uint, &type_factory);
        emit_metatype_case("zext_output", zext_typeop, &call, -1, TypeMetatype::Uint, &type_factory);
    }
    {
        let sext_typeop = manager
            .get_op(OpCode::CPUI_INT_SEXT)
            .expect("registered SEXT TypeOp");
        let input0 = fd.new_constant(1, 0x80);
        let out = fd.new_varnode(4, Address::new(0x510));
        let op = fd.new_op(1, Address::new(0x500150));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SEXT);
        fd.op_set_input(&op, input0, 0);
        fd.op_set_output(&op, out);
        let call = op.0.read().unwrap();
        emit_metatype_case("sext_input0", sext_typeop, &call, 0, TypeMetatype::Int, &type_factory);
        emit_metatype_case("sext_output", sext_typeop, &call, -1, TypeMetatype::Int, &type_factory);
    }

    // ---- CALL without a FSPEC annotation: TypeOpCall explicit fallbacks
    // resolve through the TypeOp base defaults (typeop.cc:696/:729). ----
    {
        let target = fd.new_code_ref(Address::new(0x600160));
        let out = fd.new_varnode(8, Address::new(0x600));
        let op = fd.new_op(1, Address::new(0x500160));
        fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        fd.op_set_input(&op, target, 0);
        fd.op_set_output(&op, out);
        let call = op.0.read().unwrap();
        emit_input_case("call_input0_nofspec", call_typeop, &call, 0, &type_factory);
        emit_output_case("call_output_nofspec", call_typeop, &call, &type_factory);
    }

    // ---- CALL with one locked parameter: D1 behavior must not regress ----
    {
        let mut prototype =
            FuncProto::new("typeop_localbase_fixture".to_string(), void_type.clone());
        let mut locked_ptr = ProtoParameter::new(
            "locked_ptr".to_string(),
            char_pointer.clone(),
            Address::new(0x00),
        );
        locked_ptr.flags |= protoparam_flags::TYPE_LOCKED;
        prototype.add_parameter(locked_ptr);

        let target = fd.new_code_ref(Address::new(0x600170));
        let input1 = fd.new_constant(8, 0x7180);
        let op = fd.new_op(2, Address::new(0x500170));
        fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        fd.op_set_input(&op, target, 0);
        let callspec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
        let callspec_owner = fd
            .get_call_specs_owner(callspec_index)
            .expect("fixture callspec owner");
        let fspec = fd.new_varnode_call_specs(&callspec_owner);
        fd.op_set_input(&op, fspec, 0);
        fd.op_set_input(&op, input1, 1);

        let call = op.0.read().unwrap();
        let actual = call_typeop.get_input_local(&call, 1);
        let repeat = call_typeop.get_input_local(&call, 1);
        emit_result("call_input1_locked", 1, 8, &actual);
        let fallback = factory_base(&type_factory, 8, TypeMetatype::Unknown);
        emit_bool(
            "case.call_input1_locked.param_identity",
            identity(&actual, &char_pointer),
        );
        emit_bool(
            "case.call_input1_locked.base_identity",
            identity(&actual, &fallback),
        );
        emit_bool(
            "case.call_input1_locked.repeat_identity",
            match (actual.as_ref(), repeat.as_ref()) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            },
        );
    }
}
