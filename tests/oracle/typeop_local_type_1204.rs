// TYPEOP-LOCALTYPE-DISPATCH-0001: current-Rudra comparand for the locked
// Ghidra TypeOpCall::getInputLocal fixture.
//
// This deliberately exercises the production TypeOpCall trait method.  The
// callspec is installed in Funcdata and represented by the same Iop/typed-Weak
// annotation that Funcdata::new_varnode_call_specs currently produces.  The
// Architecture, VarnodeBank, and TypeOpCall share one TypeFactory allocation,
// so fallback and selected parameter results can be checked by Arc identity.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::SpaceType;
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::typeop::{TypeOp, TypeOpCall};

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state the C++ fixture
/// observes: `TypeFactory::raw()`, the x86-64-gcc.cspec
/// `<size_alignment_map>` (entries 1,2,4,8,16 — alignMap[0] stays -1 exactly
/// like `TypeFactory::decodeAlignmentMap`, type.cc:4619-4641), `setupSizes`
/// defaults for a 64-bit stack pointer, and the
/// `SleighArchitecture::buildCoreTypes` default core set (sleigh_arch.cc:204-
/// 238) that x86-64-gcc.cspec selects by shipping no `<coretypes>` element.
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

fn option_identity(actual: Option<&Arc<Datatype>>, expected: &Arc<Datatype>) -> bool {
    actual.is_some_and(|datatype| Arc::ptr_eq(datatype, expected))
}

fn repeat_identity(left: Option<&Arc<Datatype>>, right: Option<&Arc<Datatype>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
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

/// Byte projection of `Datatype::printRaw` for the bounded result set
/// `TypeOpCall::get_input_local` can return (TypeBase and TypePointer):
/// type.cc:139-146 prints the name or `unkbyte<size>` for every non-pointer
/// type (including structs), and type.cc:910-916 appends `" *"` for pointers
/// with no spaceid suffix.  The Rudra `Datatype::print_raw` struct/array
/// spellings diverge from this oracle projection, so the fixture emits the
/// locked printRaw semantics directly.
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

fn emit_case(
    name: &str,
    typeop: &TypeOpCall,
    op: &PcodeOp,
    slot: usize,
    expected: &Arc<Datatype>,
    param: Option<&ProtoParameter>,
    fallback: &Arc<Datatype>,
) {
    let actual = typeop.get_input_local(op, slot);
    let repeat = typeop.get_input_local(op, slot);
    println!("case.{name}.slot={slot}");
    println!(
        "case.{name}.input_size={}",
        op.get_in(slot)
            .expect("fixture input slot")
            .read()
            .unwrap()
            .size
    );
    emit_bool(&format!("case.{name}.param_present"), param.is_some());
    emit_bool(
        &format!("case.{name}.param_locked"),
        param.is_some_and(ProtoParameter::is_type_locked),
    );
    emit_bool(
        &format!("case.{name}.param_this"),
        param.is_some_and(ProtoParameter::is_this_pointer),
    );
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
    emit_bool(
        &format!("case.{name}.expected_identity"),
        option_identity(actual.as_ref(), expected),
    );
    emit_bool(
        &format!("case.{name}.param_identity"),
        param.is_some_and(|parameter| option_identity(actual.as_ref(), &parameter.data_type)),
    );
    emit_bool(
        &format!("case.{name}.fallback_identity"),
        option_identity(actual.as_ref(), fallback),
    );
    emit_bool(
        &format!("case.{name}.repeat_identity"),
        repeat_identity(actual.as_ref(), repeat.as_ref()),
    );
}

fn callspec_identity(
    fd: &Funcdata,
    expected: &Arc<RwLock<FuncCallSpecs>>,
    op: &PcodeOpRef,
) -> bool {
    fd.get_call_specs_of_op(op)
        .is_some_and(|actual| Arc::ptr_eq(expected, &actual))
}

fn snapshot_param(
    fd: &Funcdata,
    callspec_index: usize,
    parameter_index: usize,
) -> Option<ProtoParameter> {
    fd.get_call_specs(callspec_index)
        .and_then(|callspec| callspec.prototype.get_param(parameter_index).cloned())
}

fn main() {
    let mut factory = configure_factory();

    let void_type = factory.get_type_void();
    let char_type = factory
        .get_type_char_named("char")
        .expect("canonical char type");
    let char_pointer = factory.get_type_pointer(8, char_type, 1);
    let int4_type = factory
        .get_base(4, TypeMetatype::Int)
        .expect("canonical int4 type");
    let uint8_type = factory
        .get_base(8, TypeMetatype::Uint)
        .expect("canonical uint8 type");
    let oversize_type = factory.get_array(uint8_type, 2);
    let object_type = factory.create_struct("typeop_call_fixture_object");
    let object_pointer = factory.get_type_pointer(8, object_type, 1);
    let plain_pointer = factory.get_type_pointer(8, int4_type.clone(), 1);

    let mut prototype = FuncProto::new("typeop_call_local_fixture".to_string(), void_type.clone());
    let mut locked_ptr = ProtoParameter::new(
        "locked_ptr".to_string(),
        char_pointer.clone(),
        Address::new(0x00),
    );
    locked_ptr.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_ptr);
    let mut locked_small = ProtoParameter::new(
        "locked_small".to_string(),
        int4_type.clone(),
        Address::new(0x08),
    );
    locked_small.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_small);
    prototype.add_parameter(ProtoParameter::new(
        "unlocked_int".to_string(),
        int4_type.clone(),
        Address::new(0x10),
    ));
    let mut locked_void = ProtoParameter::new(
        "locked_void".to_string(),
        void_type.clone(),
        Address::new(0x18),
    );
    locked_void.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_void);
    let mut locked_oversize = ProtoParameter::new(
        "locked_oversize".to_string(),
        oversize_type.clone(),
        Address::new(0x20),
    );
    locked_oversize.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(locked_oversize);
    let mut this_struct = ProtoParameter::new(
        "this_struct".to_string(),
        object_pointer.clone(),
        Address::new(0x28),
    );
    this_struct.flags |= protoparam_flags::THIS_POINTER;
    prototype.add_parameter(this_struct);
    let mut this_plain =
        ProtoParameter::new("this_plain".to_string(), plain_pointer, Address::new(0x30));
    this_plain.flags |= protoparam_flags::THIS_POINTER;
    prototype.add_parameter(this_plain);

    let type_factory = Arc::new(RwLock::new(factory));
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());

    let mut fd = Funcdata::new("typeop_call_local_fixture", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(type_factory.clone());
    let call_target = fd.new_constant(8, 0x500080);
    let input1 = fd.new_constant(8, 0x7180);
    let input2 = fd.new_constant(8, 0x11223344);
    let input3 = fd.new_constant(4, 0x55667788);
    let input4 = fd.new_constant(8, 0);
    let input5 = fd.new_constant(8, 0x99a8);
    let input6 = fd.new_constant(8, 0xc1d8);
    let input7 = fd.new_constant(8, 0xea40);
    let input8 = fd.new_constant(1, 0x7f);

    let op = fd.new_op(9, Address::new(0x500010));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    fd.op_set_input(&op, call_target, 0);
    fd.op_set_input(&op, input1, 1);
    fd.op_set_input(&op, input2, 2);
    fd.op_set_input(&op, input3, 3);
    fd.op_set_input(&op, input4, 4);
    fd.op_set_input(&op, input5, 5);
    fd.op_set_input(&op, input6, 6);
    fd.op_set_input(&op, input7, 7);
    fd.op_set_input(&op, input8, 8);

    let callspec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
    let callspec_owner = fd
        .get_call_specs_owner(callspec_index)
        .expect("fixture callspec owner");
    let fspec_primary = fd.new_varnode_call_specs(&callspec_owner);
    let fspec_alias = fd.new_varnode_call_specs(&callspec_owner);
    let callspec_bits = fspec_primary.read().unwrap().get_offset();
    let constant_mimic = fd.new_constant(std::mem::size_of::<usize>(), callspec_bits);
    let constant_mimic_has_no_handle = constant_mimic.read().unwrap().get_call_spec().is_none();
    let constant_mimic_op = fd.new_op(1, Address::new(0x500010));
    fd.op_set_opcode(&constant_mimic_op, OpCode::CPUI_CALL);
    fd.op_set_input(&constant_mimic_op, constant_mimic.clone(), 0);
    fd.op_set_input(&op, fspec_primary.clone(), 0);

    println!("fixture=TYPEOP-LOCALTYPE-DISPATCH-0001.call_input");
    println!("architecture={}", architecture.archid);
    println!("representation.fspec_name=iop");
    println!("representation.fspec_type={}", SpaceType::Iop as u32);
    println!(
        "representation.constant_type={}",
        SpaceType::Constant as u32
    );
    emit_bool(
        "representation.primary_roundtrip",
        callspec_identity(&fd, &callspec_owner, &op),
    );
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias.clone();
    }
    emit_bool(
        "representation.alias_roundtrip",
        callspec_identity(&fd, &callspec_owner, &op),
    );
    emit_bool(
        "representation.alias_distinct_varnode",
        !Arc::ptr_eq(&fspec_primary, &fspec_alias),
    );
    let (primary_space, primary_offset) = {
        let primary = fspec_primary.read().unwrap();
        (primary.get_space(), primary.get_offset())
    };
    let (alias_space, alias_offset) = {
        let alias = fspec_alias.read().unwrap();
        (alias.get_space(), alias.get_offset())
    };
    let constant_offset = constant_mimic.read().unwrap().get_offset();
    emit_bool(
        "representation.alias_same_address",
        primary_space == alias_space && primary_offset == alias_offset,
    );
    emit_bool(
        "representation.constant_same_offset",
        constant_offset == primary_offset,
    );
    emit_bool(
        "representation.constant_not_fspec",
        constant_mimic_has_no_handle && fd.get_call_specs_of_op(&constant_mimic_op).is_none(),
    );
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_primary.clone();
    }

    let typeop = TypeOpCall::new(
        architecture
            .types
            .as_ref()
            .expect("Architecture-owned TypeFactory")
            .clone(),
    );
    let parameters = (0..7)
        .map(|index| snapshot_param(&fd, callspec_index, index))
        .collect::<Vec<_>>();
    {
        let call = op.0.read().unwrap();
        emit_case(
            "slot0_target",
            &typeop,
            &call,
            0,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            None,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "locked_ptr_equal",
            &typeop,
            &call,
            1,
            &char_pointer,
            parameters[0].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "locked_small_fits",
            &typeop,
            &call,
            2,
            &int4_type,
            parameters[1].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "unlocked_param",
            &typeop,
            &call,
            3,
            &factory_base(&type_factory, 4, TypeMetatype::Unknown),
            parameters[2].as_ref(),
            &factory_base(&type_factory, 4, TypeMetatype::Unknown),
        );
        emit_case(
            "locked_void",
            &typeop,
            &call,
            4,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            parameters[3].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "locked_oversize",
            &typeop,
            &call,
            5,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            parameters[4].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "unlocked_this_struct",
            &typeop,
            &call,
            6,
            &object_pointer,
            parameters[5].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "unlocked_this_plain",
            &typeop,
            &call,
            7,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            parameters[6].as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
        emit_case(
            "missing_param",
            &typeop,
            &call,
            8,
            &factory_base(&type_factory, 1, TypeMetatype::Unknown),
            None,
            &factory_base(&type_factory, 1, TypeMetatype::Unknown),
        );
    }

    fd.get_call_specs_mut(callspec_index)
        .unwrap()
        .prototype
        .parameters[0]
        .flags &= !protoparam_flags::TYPE_LOCKED;
    let unlocked_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "locked_ptr_after_unlock",
            &typeop,
            &call,
            1,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            unlocked_parameter.as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
    }
    fd.get_call_specs_mut(callspec_index)
        .unwrap()
        .prototype
        .parameters[0]
        .flags |= protoparam_flags::TYPE_LOCKED;
    let relocked_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "locked_ptr_after_relock",
            &typeop,
            &call,
            1,
            &char_pointer,
            relocked_parameter.as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
    }

    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = fspec_alias;
    }
    let alias_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "fspec_alias",
            &typeop,
            &call,
            1,
            &char_pointer,
            alias_parameter.as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
    }
    {
        let mut call = op.0.write().unwrap();
        call.inrefs[0] = constant_mimic;
    }
    let constant_parameter = snapshot_param(&fd, callspec_index, 0);
    {
        let call = op.0.read().unwrap();
        emit_case(
            "constant_same_offset",
            &typeop,
            &call,
            1,
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
            constant_parameter.as_ref(),
            &factory_base(&type_factory, 8, TypeMetatype::Unknown),
        );
    }
}
