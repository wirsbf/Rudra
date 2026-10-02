//! DATATYPE-TYPEORDER-0001 Rugra comparand for locked Ghidra 12.0.4.

use rudra::fspec::{ProtoModelFull, ProtoParameter};
use rudra::space::{space_flags, AddrSpace, SpaceType};
use rudra::type_system::datatype::{
    type_flags, Datatype, TypeArray, TypeBase, TypeCode, TypeEnum, TypeField, TypeMetatype,
    TypePartialEnum, TypePartialStruct, TypePartialUnion, TypePointer, TypeSpacebase,
    TypeStruct, TypeUnion,
};
use rudra::type_system::typefactory::TypeFactory;
use rudra::{Address, AddressSpace, FuncProto};
use std::collections::BTreeMap;
use std::sync::Arc;

fn signum(value: i32) -> i32 {
    value.signum()
}

fn base(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(
        name.to_string(),
        size,
        metatype,
    )))
}

fn pointer(ptr_to: Arc<Datatype>) -> Datatype {
    Datatype::Pointer(TypePointer::new(8, ptr_to, 1))
}

fn structure(name: &str, size: usize, fields: Vec<TypeField>, incomplete: bool) -> Arc<Datatype> {
    let mut type_base = TypeBase::new(name.to_string(), size, TypeMetatype::Struct);
    if incomplete {
        type_base.flags |= type_flags::TYPE_INCOMPLETE;
    }
    if fields.len() == 1 && fields[0].type_ptr.get_size() == size {
        type_base.flags |= type_flags::NEEDS_RESOLUTION;
    }
    Arc::new(Datatype::Struct(TypeStruct {
        base: type_base,
        fields,
    }))
}

fn emit_order(key: &str, left: &Datatype, right: &Datatype) {
    println!("{key}={}", signum(left.type_order(right)));
}

fn emit_bool_order(key: &str, left: &Datatype, right: &Datatype) {
    println!("{key}={}", signum(left.type_order_bool(right)));
}

fn main() {
    let unknown4 = base("unknown4", 4, TypeMetatype::Unknown);
    let int4 = base("int4", 4, TypeMetatype::Int);
    let int4_alias = base("different_name_same_shape", 4, TypeMetatype::Int);
    let int8 = base("int8", 8, TypeMetatype::Int);
    let uint4 = base("uint4", 4, TypeMetatype::Uint);
    let bool1 = base("bool1", 1, TypeMetatype::Bool);
    let bool1_copy = base("bool1_copy", 1, TypeMetatype::Bool);

    let one_field = vec![TypeField {
        name: "a".to_string(),
        offset: 0,
        type_ptr: int4.clone(),
    }];
    let two_fields = vec![
        TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        },
        TypeField {
            name: "b".to_string(),
            offset: 4,
            type_ptr: uint4.clone(),
        },
    ];
    let incomplete_struct = structure("Incomplete", 0, Vec::new(), true);
    let one_field_struct = structure("One", 4, one_field.clone(), false);
    let two_field_struct = structure("Two", 8, two_fields.clone(), false);

    let ptr_unknown = pointer(unknown4.clone());
    let ptr_int = pointer(int4.clone());
    let ptr_incomplete = pointer(incomplete_struct);
    let ptr_one_field = pointer(one_field_struct.clone());
    let ptr_two_field = pointer(two_field_struct);

    println!("identity.same={}", signum(int4.type_order(int4.as_ref())));
    println!(
        "submeta.unknown={}",
        Datatype::get_submeta(unknown4.as_ref()) as i32
    );
    println!(
        "submeta.int={}",
        Datatype::get_submeta(int4.as_ref()) as i32
    );
    println!(
        "submeta.uint={}",
        Datatype::get_submeta(uint4.as_ref()) as i32
    );
    println!(
        "submeta.bool={}",
        Datatype::get_submeta(bool1.as_ref()) as i32
    );
    println!(
        "submeta.ptr_unknown={}",
        Datatype::get_submeta(&ptr_unknown) as i32
    );
    println!(
        "submeta.ptr_incomplete_struct={}",
        Datatype::get_submeta(&ptr_incomplete) as i32
    );
    println!(
        "submeta.ptr_one_field_struct={}",
        Datatype::get_submeta(&ptr_one_field) as i32
    );
    println!(
        "submeta.ptr_one_field_needs_resolution={}",
        u8::from(ptr_one_field.needs_resolution())
    );
    println!(
        "submeta.ptr_two_field_struct={}",
        Datatype::get_submeta(&ptr_two_field) as i32
    );

    emit_order("order.ptr_unknown", &ptr_unknown, unknown4.as_ref());
    emit_order("order.int_unknown", int4.as_ref(), unknown4.as_ref());
    emit_order("order.uint_unknown", uint4.as_ref(), unknown4.as_ref());
    emit_order("order.bool_unknown", bool1.as_ref(), unknown4.as_ref());
    emit_order("order.int_uint", int4.as_ref(), uint4.as_ref());
    emit_order("order.int4_int8", int4.as_ref(), int8.as_ref());
    emit_order("order.name_ignored", int4.as_ref(), int4_alias.as_ref());
    emit_bool_order("bool_order.bool_int", bool1.as_ref(), int4.as_ref());
    emit_bool_order("bool_order.int_bool", int4.as_ref(), bool1.as_ref());
    emit_bool_order(
        "bool_order.distinct_bool",
        bool1.as_ref(),
        bool1_copy.as_ref(),
    );
    emit_bool_order("bool_order.same_bool", bool1.as_ref(), bool1.as_ref());

    let ptr_uint = pointer(uint4.clone());
    emit_order("recursive.ptr_int_uint", &ptr_int, &ptr_uint);
    let mut cutoff_left = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let mut cutoff_right = match pointer(uint4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    cutoff_left.base.id = 7;
    cutoff_right.base.id = 9;
    println!(
        "recursive.level0_id={}",
        signum(cutoff_left.compare(&cutoff_right, 0))
    );
    println!(
        "recursive.level1_target={}",
        signum(cutoff_left.compare(&cutoff_right, 1))
    );

    let struct_one = TypeStruct {
        base: TypeBase::new("S1".to_string(), 8, TypeMetatype::Struct),
        fields: one_field.clone(),
    };
    let struct_two = TypeStruct {
        base: TypeBase::new("S2".to_string(), 8, TypeMetatype::Struct),
        fields: two_fields,
    };
    println!(
        "tie.struct_more_fields={}",
        signum(struct_two.compare(&struct_one, 10))
    );
    let struct_name_b = TypeStruct {
        base: TypeBase::new("S3".to_string(), 8, TypeMetatype::Struct),
        fields: vec![TypeField {
            name: "b".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        }],
    };
    println!(
        "tie.struct_field_name={}",
        signum(struct_one.compare(&struct_name_b, 10))
    );
    let struct_unknown = TypeStruct {
        base: TypeBase::new("S4".to_string(), 8, TypeMetatype::Struct),
        fields: vec![TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: unknown4.clone(),
        }],
    };
    println!(
        "tie.struct_field_metatype={}",
        signum(struct_one.compare(&struct_unknown, 10))
    );

    let mut values_a = BTreeMap::new();
    values_a.insert(1, "A".to_string());
    let mut enum_a_base = TypeBase::new("EA".to_string(), 4, TypeMetatype::Int);
    enum_a_base.flags |= type_flags::ENUMTYPE;
    let enum_a = TypeEnum {
        base: enum_a_base,
        values: values_a,
    };
    let mut values_b = BTreeMap::new();
    values_b.insert(2, "A".to_string());
    let mut enum_b_base = TypeBase::new("EB".to_string(), 4, TypeMetatype::Int);
    enum_b_base.flags |= type_flags::ENUMTYPE;
    let enum_b = TypeEnum {
        base: enum_b_base,
        values: values_b,
    };
    println!("tie.enum_value={}", signum(enum_a.compare(&enum_b, 10)));

    let dep_same_a = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let dep_same_b = match pointer(int4.clone()) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let int4_copy = base("int4_copy", 4, TypeMetatype::Int);
    let dep_distinct = match pointer(int4_copy) {
        Datatype::Pointer(pointer) => pointer,
        _ => unreachable!(),
    };
    let dep_forward = dep_same_a.compare_dependency(&dep_distinct);
    let dep_reverse = dep_distinct.compare_dependency(&dep_same_a);
    println!(
        "dependency.same_target={}",
        signum(dep_same_a.compare_dependency(&dep_same_b))
    );
    println!(
        "dependency.distinct_target_nonzero={}",
        u8::from(dep_forward != 0)
    );
    println!(
        "dependency.distinct_target_antisymmetric={}",
        u8::from(signum(dep_forward) == -signum(dep_reverse))
    );

    let ptr_uint_datatype = Datatype::Pointer(TypePointer::new(8, uint4.clone(), 1));
    let ptr_int_datatype = Datatype::Pointer(TypePointer::new(8, int4.clone(), 1));
    println!(
        "base_api.compare_pointer={}",
        signum(ptr_int_datatype.compare(&ptr_uint_datatype))
    );
    let dep_target_copy = base("dep_target_copy", 4, TypeMetatype::Int);
    let dep_pointer_copy = Datatype::Pointer(TypePointer::new(8, dep_target_copy, 1));
    let base_dep_forward = ptr_int_datatype.compare_dependency(&dep_pointer_copy);
    let base_dep_reverse = dep_pointer_copy.compare_dependency(&ptr_int_datatype);
    println!(
        "base_api.dependency_pointer_nonzero={}",
        u8::from(base_dep_forward != 0)
    );
    println!(
        "base_api.dependency_pointer_antisymmetric={}",
        u8::from(signum(base_dep_forward) == -signum(base_dep_reverse))
    );

    let mut array_base = TypeBase::new("A1".to_string(), 4, TypeMetatype::Array);
    array_base.flags |= type_flags::NEEDS_RESOLUTION;
    let array_one = Arc::new(Datatype::Array(TypeArray {
        base: array_base,
        array_of: int4.clone(),
        num_elements: 1,
    }));
    let array_pointer = Datatype::Pointer(TypePointer::new(8, array_one, 1));
    println!(
        "pointer_state.array_flag={}",
        u8::from(array_pointer.is_pointer_to_array())
    );
    println!(
        "pointer_state.array_needs_resolution={}",
        u8::from(array_pointer.needs_resolution())
    );
    let mut union_base = TypeBase::new("U".to_string(), 4, TypeMetatype::Union);
    union_base.flags |= type_flags::NEEDS_RESOLUTION;
    let union_type = Arc::new(Datatype::Union(TypeUnion {
        base: union_base,
        fields: vec![TypeField {
            name: "a".to_string(),
            offset: 0,
            type_ptr: int4.clone(),
        }],
    }));
    let union_pointer = Datatype::Pointer(TypePointer::new(8, union_type, 1));
    println!(
        "pointer_state.union_submeta={}",
        union_pointer.get_submeta() as i32
    );
    println!(
        "pointer_state.union_needs_resolution={}",
        u8::from(union_pointer.needs_resolution())
    );
    let pointer_to_union_pointer =
        Datatype::Pointer(TypePointer::new(8, Arc::new(union_pointer.clone()), 1));
    println!(
        "pointer_state.pointer_needs_resolution={}",
        u8::from(pointer_to_union_pointer.needs_resolution())
    );
    let mut core_int_base = TypeBase::new("core_int".to_string(), 4, TypeMetatype::Int);
    core_int_base.flags |= type_flags::CORETYPE;
    let core_int = Arc::new(Datatype::Base(core_int_base));
    let core_pointer = Datatype::Pointer(TypePointer::new(8, core_int, 1));
    println!(
        "pointer_state.core_inherited={}",
        u8::from(core_pointer.is_coretype())
    );

    let pointer_no_space = Datatype::Pointer(TypePointer::new(8, int4.clone(), 1));
    let pointer_ram =
        Datatype::Pointer(TypePointer::new_with_space(int4.clone(), AddressSpace::Ram));
    let pointer_register = Datatype::Pointer(TypePointer::new_with_space(
        int4.clone(),
        AddressSpace::Register,
    ));
    println!(
        "pointer_space.present_before_none={}",
        signum(pointer_ram.compare(&pointer_no_space))
    );
    println!(
        "pointer_space.ram_before_register={}",
        signum(pointer_ram.compare(&pointer_register))
    );
    println!(
        "pointer_space.dependency_ranking={}",
        signum(pointer_ram.compare_dependency(&pointer_register))
    );

    let rel_parent = one_field_struct.clone();
    let formal_rel = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        rel_parent.clone(),
        4,
    ));
    let mut ephemeral_pointer =
        TypePointer::new_relative(8, unknown4.clone(), 1, rel_parent.clone(), 4);
    let stripped = Arc::new(Datatype::Pointer(TypePointer::new(8, unknown4.clone(), 1)));
    ephemeral_pointer.mark_ephemeral(stripped.clone());
    let ephemeral_rel = Datatype::Pointer(ephemeral_pointer);
    println!(
        "pointer_rel.formal_submeta={}",
        formal_rel.get_submeta() as i32
    );
    println!(
        "pointer_rel.ephemeral_submeta={}",
        ephemeral_rel.get_submeta() as i32
    );
    println!(
        "pointer_rel.formal_has_stripped={}",
        u8::from((formal_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    println!(
        "pointer_rel.ephemeral_has_stripped={}",
        u8::from((ephemeral_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    let (formal_parent, formal_offset) = match &formal_rel {
        Datatype::Pointer(pointer) => (
            pointer.get_parent().expect("relative parent"),
            pointer.get_byte_offset().expect("relative offset"),
        ),
        _ => unreachable!(),
    };
    println!(
        "pointer_rel.parent_identity={}",
        u8::from(Arc::ptr_eq(formal_parent, &rel_parent))
    );
    println!("pointer_rel.parent_name={}", formal_parent.get_name());
    println!("pointer_rel.parent_size={}", formal_parent.get_size());
    println!(
        "pointer_rel.parent_needs_resolution={}",
        u8::from(formal_parent.needs_resolution())
    );
    println!("pointer_rel.byte_offset={formal_offset}");
    println!(
        "pointer_rel.stripped_identity={}",
        u8::from(match &ephemeral_rel {
            Datatype::Pointer(pointer) => pointer
                .get_stripped_pointer()
                .map(|candidate| Arc::ptr_eq(candidate, &stripped))
                .unwrap_or(false),
            _ => false,
        })
    );
    println!(
        "pointer_rel.formal_before_ephemeral={}",
        signum(formal_rel.compare(&ephemeral_rel))
    );
    let formal_int_rel = Datatype::Pointer(TypePointer::new_relative(
        8,
        int4.clone(),
        1,
        rel_parent.clone(),
        4,
    ));
    let mut ephemeral_int_pointer =
        TypePointer::new_relative(8, int4.clone(), 1, rel_parent.clone(), 4);
    ephemeral_int_pointer.mark_ephemeral(Arc::new(Datatype::Pointer(TypePointer::new(
        8,
        int4.clone(),
        1,
    ))));
    let ephemeral_int_rel = Datatype::Pointer(ephemeral_int_pointer);
    println!(
        "pointer_rel.stripped_tie={}",
        signum(formal_int_rel.compare(&ephemeral_int_rel))
    );
    let rel_offset_eight = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        rel_parent,
        8,
    ));
    println!(
        "pointer_rel.dependency_offset={}",
        signum(formal_rel.compare_dependency(&rel_offset_eight))
    );
    let other_rel_parent = structure("OtherRelParent", 4, one_field.clone(), false);
    let rel_other_parent = Datatype::Pointer(TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        other_rel_parent,
        4,
    ));
    let rel_parent_forward = formal_rel.compare_dependency(&rel_other_parent);
    let rel_parent_reverse = rel_other_parent.compare_dependency(&formal_rel);
    println!(
        "pointer_rel.dependency_parent_nonzero={}",
        u8::from(rel_parent_forward != 0)
    );
    println!(
        "pointer_rel.dependency_parent_antisymmetric={}",
        u8::from(signum(rel_parent_forward) == -signum(rel_parent_reverse))
    );

    let unicode1 = Datatype::Base(TypeBase::new_unicode(
        "unicode1".to_string(),
        1,
        TypeMetatype::Int,
    ));
    let char1 = Datatype::Base(TypeBase::new_char("char1".to_string(), TypeMetatype::Int));
    println!("unicode.direct_submeta={}", unicode1.get_submeta() as i32);
    println!("unicode.char_submeta={}", char1.get_submeta() as i32);
    println!(
        "unicode.before_char={}",
        signum(unicode1.type_order(&char1))
    );

    let void_type = Arc::new(Datatype::Void(TypeBase::new(
        "void".to_string(),
        0,
        TypeMetatype::Void,
    )));
    let mut model = ProtoModelFull::new(None, 8);
    model.name = "fixture_model".to_string();
    let model = Arc::new(model);
    let make_proto = |constructor: bool, destructor: bool, has_this: bool| {
        let mut proto = FuncProto::new(String::new(), void_type.clone());
        proto.set_model(Some(model.clone()));
        proto.set_constructor(constructor);
        proto.set_destructor(destructor);
        proto.set_has_thisptr(has_this);
        Arc::new(proto)
    };
    let code_plain = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, false, false)),
    });
    let code_constructor = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(true, false, false)),
    });
    let code_destructor = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, true, false)),
    });
    let code_this = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(make_proto(false, false, true)),
    });
    let code_no_model = Datatype::Code(TypeCode {
        base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
        proto: Some(Arc::new(FuncProto::new(String::new(), void_type.clone()))),
    });
    println!(
        "code_model.absent_after_present={}",
        signum(code_no_model.compare(&code_plain))
    );
    println!(
        "code_flags.plain_constructor={}",
        signum(code_plain.compare(&code_constructor))
    );
    println!(
        "code_flags.constructor_destructor={}",
        signum(code_constructor.compare(&code_destructor))
    );
    println!(
        "code_flags.same_model_name={}",
        u8::from(match (&code_plain, &code_this) {
            (Datatype::Code(left), Datatype::Code(right)) => left
                .proto
                .as_ref()
                .zip(right.proto.as_ref())
                .map(|(left, right)| left.get_model_name() == right.get_model_name())
                .unwrap_or(false),
            _ => false,
        })
    );
    println!(
        "code_flags.plain_this={}",
        signum(code_plain.compare(&code_this))
    );

    let ram_handle = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        AddressSpace::Ram.space_id() as i32,
        0,
        0,
        0,
    );
    let invalid_frame = Address::new(0);
    let valid_zero_frame = Address::with_space(&ram_handle, 0);
    let valid_one_frame = Address::with_space(&ram_handle, 1);
    let make_spacebase = |spaceid, frame| {
        Datatype::Spacebase(TypeSpacebase {
            base: TypeBase::new(String::new(), 0, TypeMetatype::Spacebase),
            address: frame,
            fd: None,
            spaceid,
            localframe: frame,
            scope: None,
        })
    };
    let spacebase_invalid = make_spacebase(Some(AddressSpace::Ram), invalid_frame);
    let spacebase_valid_zero = make_spacebase(Some(AddressSpace::Ram), valid_zero_frame);
    let spacebase_register = make_spacebase(Some(AddressSpace::Register), valid_zero_frame);
    let spacebase_valid_one = make_spacebase(Some(AddressSpace::Ram), valid_one_frame);
    println!(
        "spacebase.invalid_spaceless={}",
        u8::from(match &spacebase_invalid {
            Datatype::Spacebase(spacebase) => spacebase.is_invalid(),
            _ => false,
        })
    );
    println!(
        "spacebase.valid_zero={}",
        u8::from(match &spacebase_valid_zero {
            Datatype::Spacebase(spacebase) => !spacebase.is_invalid(),
            _ => false,
        })
    );
    let space_forward = spacebase_valid_zero.compare_dependency(&spacebase_register);
    let space_reverse = spacebase_register.compare_dependency(&spacebase_valid_zero);
    println!(
        "spacebase.space_identity_nonzero={}",
        u8::from(space_forward != 0)
    );
    println!(
        "spacebase.space_identity_antisymmetric={}",
        u8::from(signum(space_forward) == -signum(space_reverse))
    );
    println!(
        "spacebase.localframe_order={}",
        signum(spacebase_valid_zero.compare_dependency(&spacebase_valid_one))
    );
    println!(
        "spacebase.global_shortcut={}",
        signum(spacebase_invalid.compare_dependency(&spacebase_valid_zero))
    );

    let mut factory = TypeFactory::new(8);
    let factory_int = factory.get_base(4, TypeMetatype::Int).expect("factory int");
    let factory_plain_pointer = factory.get_type_pointer(4, factory_int.clone(), 2);
    println!(
        "factory_gap.ordinary_pointer_is_ptrrel={}",
        u8::from((factory_plain_pointer.get_flags() & type_flags::IS_PTRREL) != 0)
    );
    let factory_parent = one_field_struct;
    let factory_unknown = factory
        .get_base(4, TypeMetatype::Unknown)
        .expect("factory unknown");
    let factory_rel = factory.get_type_pointer_rel(factory_unknown, factory_parent, 4);
    println!(
        "factory_gap.ephemeral_rel_has_stripped={}",
        u8::from((factory_rel.get_flags() & type_flags::HAS_STRIPPED) != 0)
    );
    println!(
        "factory_gap.ephemeral_rel_submeta={}",
        factory_rel.get_submeta() as i32
    );
    let factory_array = factory.get_array(factory_int.clone(), 1);
    let factory_array_pointer = factory.get_ptr(factory_array);
    println!(
        "factory_gap.array_pointer_flag={}",
        u8::from(factory_array_pointer.is_pointer_to_array())
    );
    let factory_core_pointer = factory.get_ptr(factory_int);
    println!(
        "factory_gap.core_pointer_inherited={}",
        u8::from(factory_core_pointer.is_coretype())
    );
    let factory_unicode1 = factory.get_type_unicode(1);
    println!(
        "factory_gap.unicode1_submeta={}",
        factory_unicode1.get_submeta() as i32
    );

    // TypeCode varargs / model-name / parameter-count / parameter-type /
    // return-type / level-id residual matrix.
    let make_pieces =
        |dotdotdot: bool, params: &[Arc<Datatype>], out: Arc<Datatype>| -> Arc<FuncProto> {
            let mut proto = FuncProto::new(String::new(), out);
            proto.set_model(Some(model.clone()));
            proto.is_dotdotdot = dotdotdot;
            for (index, param) in params.iter().enumerate() {
                proto.add_parameter(ProtoParameter::new(
                    format!("p{index}"),
                    param.clone(),
                    Address::new(0),
                ));
            }
            Arc::new(proto)
        };
    let make_code = |proto: Arc<FuncProto>| {
        Datatype::Code(TypeCode {
            base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
            proto: Some(proto),
        })
    };
    let code_param_plain =
        make_code(make_pieces(false, &[int4.clone()], void_type.clone()));
    let code_param_varargs =
        make_code(make_pieces(true, &[int4.clone()], void_type.clone()));
    let code_param_none = make_code(make_pieces(false, &[], void_type.clone()));
    let code_param_uint =
        make_code(make_pieces(false, &[uint4.clone()], void_type.clone()));
    let code_return_int = make_code(make_pieces(false, &[int4.clone()], int8.clone()));
    println!(
        "code2.varargs_plain_first={}",
        signum(code_param_plain.compare_at_level(&code_param_varargs, 10))
    );
    println!(
        "code2.param_count_zero_vs_one={}",
        signum(code_param_none.compare_at_level(&code_param_plain, 10))
    );
    println!(
        "code2.param_count_one_vs_zero={}",
        signum(code_param_plain.compare_at_level(&code_param_none, 10))
    );
    println!(
        "code2.param_type_recursion={}",
        signum(code_param_plain.compare_at_level(&code_param_uint, 10))
    );
    println!(
        "code2.return_type_recursion={}",
        signum(code_param_plain.compare_at_level(&code_return_int, 10))
    );
    let make_named_model = |name: &str| {
        let mut named = ProtoModelFull::new(None, 8);
        named.name = name.to_string();
        Arc::new(named)
    };
    let make_named_code = |name: &str| {
        let mut proto = FuncProto::new(String::new(), void_type.clone());
        proto.set_model(Some(make_named_model(name)));
        Arc::new(proto)
    };
    let code_model_a = make_code(make_named_code("fixture_a"));
    let code_model_b = make_code(make_named_code("fixture_b"));
    println!(
        "code2.model_name_differs={}",
        signum(code_model_a.compare_at_level(&code_model_b, 10))
    );
    let mut code_id_low = make_code(make_pieces(false, &[int4.clone()], void_type.clone()));
    let mut code_id_high = make_code(make_pieces(false, &[int4.clone()], void_type.clone()));
    if let Datatype::Code(low) = &mut code_id_low {
        low.base.id = 5;
    }
    if let Datatype::Code(high) = &mut code_id_high {
        high.base.id = 9;
    }
    println!(
        "code2.level0_id={}",
        signum(code_id_low.compare_at_level(&code_id_high, 0))
    );
    let int_param_copy = base("int_param_copy", 4, TypeMetatype::Int);
    let code_dep_param_a =
        make_code(make_pieces(false, &[int4.clone()], void_type.clone()));
    let code_dep_param_b =
        make_code(make_pieces(false, &[int_param_copy.clone()], void_type.clone()));
    let code_param_dep_forward = code_dep_param_a.compare_dependency(&code_dep_param_b);
    let code_param_dep_reverse = code_dep_param_b.compare_dependency(&code_dep_param_a);
    println!(
        "code2.deep_equal_distinct_params={}",
        signum(code_dep_param_a.compare_at_level(&code_dep_param_b, 10))
    );
    println!(
        "code2.dependency_distinct_param_nonzero={}",
        u8::from(code_param_dep_forward != 0)
    );
    println!(
        "code2.dependency_distinct_param_antisymmetric={}",
        u8::from(signum(code_param_dep_forward) == -signum(code_param_dep_reverse))
    );
    let void_out_a = Arc::new(Datatype::Void(TypeBase::new(
        "void_a".to_string(),
        0,
        TypeMetatype::Void,
    )));
    let void_out_b = Arc::new(Datatype::Void(TypeBase::new(
        "void_b".to_string(),
        0,
        TypeMetatype::Void,
    )));
    let code_dep_out_a =
        make_code(make_pieces(false, &[int4.clone()], void_out_a));
    let code_dep_out_b =
        make_code(make_pieces(false, &[int4.clone()], void_out_b));
    let code_out_dep_forward = code_dep_out_a.compare_dependency(&code_dep_out_b);
    let code_out_dep_reverse = code_dep_out_b.compare_dependency(&code_dep_out_a);
    println!(
        "code2.deep_equal_distinct_output={}",
        signum(code_dep_out_a.compare_at_level(&code_dep_out_b, 10))
    );
    println!(
        "code2.dependency_distinct_output_nonzero={}",
        u8::from(code_out_dep_forward != 0)
    );
    println!(
        "code2.dependency_distinct_output_antisymmetric={}",
        u8::from(signum(code_out_dep_forward) == -signum(code_out_dep_reverse))
    );

    // Array / Union / Partial compare and dependency matrices.
    let make_array = |element: Arc<Datatype>, count: usize| -> TypeArray {
        let mut array_base = TypeBase::new(
            String::new(),
            element.get_size() * count,
            TypeMetatype::Array,
        );
        if count == 1 {
            array_base.flags |= type_flags::NEEDS_RESOLUTION;
        }
        TypeArray {
            base: array_base,
            array_of: element,
            num_elements: count,
        }
    };
    let array_int_one = make_array(int4.clone(), 1);
    let array_int_two = make_array(int4.clone(), 2);
    let array_uint_one = make_array(uint4.clone(), 1);
    let array_elem_copy = base("array_elem_copy", 4, TypeMetatype::Int);
    let array_int_copy_one = make_array(array_elem_copy, 1);
    println!(
        "array2.compare_elem_differs={}",
        signum(array_int_one.compare(&array_uint_one, 10))
    );
    println!(
        "array2.compare_size={}",
        signum(array_int_two.compare(&array_int_one, 10))
    );
    let mut array_id_low = make_array(int4.clone(), 1);
    let mut array_id_high = make_array(int4.clone(), 1);
    array_id_low.base.id = 5;
    array_id_high.base.id = 9;
    println!(
        "array2.compare_level0_id={}",
        signum(array_id_low.compare(&array_id_high, 0))
    );
    println!(
        "array2.dependency_size={}",
        signum(array_int_one.compare_dependency(&array_int_two))
    );
    let array_dep_forward = array_int_one.compare_dependency(&array_int_copy_one);
    let array_dep_reverse = array_int_copy_one.compare_dependency(&array_int_one);
    println!(
        "array2.dependency_distinct_elem_nonzero={}",
        u8::from(array_dep_forward != 0)
    );
    println!(
        "array2.dependency_distinct_elem_antisymmetric={}",
        u8::from(signum(array_dep_forward) == -signum(array_dep_reverse))
    );

    let field = |name: &str, offset: usize, type_ptr: Arc<Datatype>| TypeField {
        name: name.to_string(),
        offset,
        type_ptr,
    };
    let make_union = |name: &str, fields: Vec<TypeField>| TypeUnion {
        base: TypeBase::new(name.to_string(), 4, TypeMetatype::Union),
        fields,
    };
    let union_name_a = make_union("UA", vec![field("a", 0, int4.clone())]);
    let union_name_b = make_union("UB", vec![field("b", 0, int4.clone())]);
    let union_uint = make_union("UU", vec![field("a", 0, uint4.clone())]);
    let mut union_id_low = make_union("UI", vec![field("a", 0, int4.clone())]);
    let mut union_id_high = make_union("UI2", vec![field("a", 0, int4.clone())]);
    union_id_low.base.id = 5;
    union_id_high.base.id = 9;
    let union_field_copy = make_union("UC", vec![field("a", 0, int_param_copy.clone())]);
    println!(
        "union2.compare_field_name={}",
        signum(union_name_a.compare(&union_name_b, 10))
    );
    println!(
        "union2.compare_field_metatype={}",
        signum(union_name_a.compare(&union_uint, 10))
    );
    println!(
        "union2.compare_level0_id={}",
        signum(union_id_low.compare(&union_id_high, 0))
    );
    let union_dep_forward = union_name_a.compare_dependency(&union_field_copy);
    let union_dep_reverse = union_field_copy.compare_dependency(&union_name_a);
    println!(
        "union2.dependency_distinct_field_nonzero={}",
        u8::from(union_dep_forward != 0)
    );
    println!(
        "union2.dependency_distinct_field_antisymmetric={}",
        u8::from(signum(union_dep_forward) == -signum(union_dep_reverse))
    );

    let struct_offset_zero = TypeStruct {
        base: TypeBase::new("SO0".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 0, int4.clone())],
    };
    let struct_offset_two = TypeStruct {
        base: TypeBase::new("SO2".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 2, int4.clone())],
    };
    println!(
        "struct2.compare_field_offset={}",
        signum(struct_offset_zero.compare(&struct_offset_two, 10))
    );
    let struct_ptr_field_int = TypeStruct {
        base: TypeBase::new("SP1".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("p", 0, Arc::new(ptr_int.clone()))],
    };
    let struct_ptr_field_uint = TypeStruct {
        base: TypeBase::new("SP2".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("p", 0, Arc::new(ptr_uint_datatype.clone()))],
    };
    println!(
        "struct2.compare_deep_pointer_field={}",
        signum(struct_ptr_field_int.compare(&struct_ptr_field_uint, 10))
    );
    let mut struct_id_low = TypeStruct {
        base: TypeBase::new("SI".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 0, int4.clone())],
    };
    let mut struct_id_high = TypeStruct {
        base: TypeBase::new("SI2".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 0, int4.clone())],
    };
    struct_id_low.base.id = 5;
    struct_id_high.base.id = 9;
    println!(
        "struct2.compare_level0_id={}",
        signum(struct_id_low.compare(&struct_id_high, 0))
    );
    let struct_dep_offset_four = TypeStruct {
        base: TypeBase::new("SD4".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 4, int4.clone())],
    };
    println!(
        "struct2.dependency_field_offset={}",
        signum(struct_offset_zero.compare_dependency(&struct_dep_offset_four))
    );
    let struct_field_copy = TypeStruct {
        base: TypeBase::new("SC".to_string(), 8, TypeMetatype::Struct),
        fields: vec![field("a", 0, int_param_copy.clone())],
    };
    let struct_dep_forward = struct_offset_zero.compare_dependency(&struct_field_copy);
    let struct_dep_reverse = struct_field_copy.compare_dependency(&struct_offset_zero);
    println!(
        "struct2.dependency_distinct_field_nonzero={}",
        u8::from(struct_dep_forward != 0)
    );
    println!(
        "struct2.dependency_distinct_field_antisymmetric={}",
        u8::from(signum(struct_dep_forward) == -signum(struct_dep_reverse))
    );

    let make_partial_struct = |container: &Arc<Datatype>, offset: i64| TypePartialStruct {
        base: {
            let mut partial_base =
                TypeBase::new(String::new(), 4, TypeMetatype::PartialStruct);
            partial_base.flags |= type_flags::HAS_STRIPPED;
            partial_base
        },
        container: container.clone(),
        offset,
        stripped: Some(unknown4.clone()),
    };
    // Mirror Ghidra's structOne/structTwo (size 8, 1 vs 2 int/uint fields).
    let partial_container_one_field = structure(
        "PartialContainerOne",
        8,
        vec![field("a", 0, int4.clone())],
        false,
    );
    let partial_container_two_fields = structure(
        "PartialContainerTwo",
        8,
        vec![
            field("a", 0, int4.clone()),
            field("b", 4, uint4.clone()),
        ],
        false,
    );
    let partial_offset_zero = make_partial_struct(&partial_container_one_field, 0);
    let partial_offset_four = make_partial_struct(&partial_container_one_field, 4);
    println!(
        "partialstruct2.compare_offset={}",
        signum(partial_offset_zero.compare(&partial_offset_four, 10))
    );
    let partial_container_two = make_partial_struct(&partial_container_two_fields, 0);
    println!(
        "partialstruct2.compare_container={}",
        signum(partial_offset_zero.compare(&partial_container_two, 10))
    );
    let mut partial_id_low = make_partial_struct(&partial_container_one_field, 0);
    let mut partial_id_high = make_partial_struct(&partial_container_one_field, 0);
    partial_id_low.base.id = 5;
    partial_id_high.base.id = 9;
    println!(
        "partialstruct2.compare_level0_id={}",
        signum(partial_id_low.compare(&partial_id_high, 0))
    );
    println!(
        "partialstruct2.dependency_same_container={}",
        signum(partial_offset_zero.compare_dependency(&partial_id_low))
    );
    println!(
        "partialstruct2.dependency_offset={}",
        signum(partial_offset_zero.compare_dependency(&partial_offset_four))
    );
    let partial_container_copy = structure(
        "PartialContainerOneCopy",
        8,
        vec![field("a", 0, int4.clone())],
        false,
    );
    let partial_container_copy_piece = make_partial_struct(&partial_container_copy, 0);
    let partial_struct_dep_forward =
        partial_offset_zero.compare_dependency(&partial_container_copy_piece);
    let partial_struct_dep_reverse =
        partial_container_copy_piece.compare_dependency(&partial_offset_zero);
    println!(
        "partialstruct2.dependency_distinct_container_nonzero={}",
        u8::from(partial_struct_dep_forward != 0)
    );
    println!(
        "partialstruct2.dependency_distinct_container_antisymmetric={}",
        u8::from(signum(partial_struct_dep_forward) == -signum(partial_struct_dep_reverse))
    );

    let make_enum = |name: &str, key: u64| {
        let mut enum_base = TypeBase::new(name.to_string(), 4, TypeMetatype::Int);
        enum_base.flags |= type_flags::ENUMTYPE;
        let mut values = BTreeMap::new();
        values.insert(key, "A".to_string());
        TypeEnum {
            base: enum_base,
            values,
        }
    };
    let make_enum_unsigned = |name: &str, key: u64| {
        let mut enum_base = TypeBase::new(name.to_string(), 4, TypeMetatype::Uint);
        enum_base.flags |= type_flags::ENUMTYPE;
        let mut values = BTreeMap::new();
        values.insert(key, "A".to_string());
        TypeEnum {
            base: enum_base,
            values,
        }
    };
    let partial_enum_parent_a = Arc::new(Datatype::Enum(make_enum("EA", 1)));
    let partial_enum_parent_b = Arc::new(Datatype::Enum(make_enum("EB", 2)));
    let partial_enum_parent_copy = Arc::new(Datatype::Enum(make_enum("EAC", 1)));
    let make_partial_enum = |parent: &Arc<Datatype>, offset: i64| TypePartialEnum {
        base: {
            let mut partial_base =
                TypeBase::new(String::new(), 1, TypeMetatype::PartialEnum);
            partial_base.flags |= type_flags::HAS_STRIPPED | type_flags::ENUMTYPE;
            partial_base
        },
        parent: parent.clone(),
        offset,
        stripped: Some(unknown4.clone()),
    };
    let partial_enum_offset_zero = make_partial_enum(&partial_enum_parent_a, 0);
    let partial_enum_offset_one = make_partial_enum(&partial_enum_parent_a, 1);
    println!(
        "partialenum2.compare_offset={}",
        signum(partial_enum_offset_zero.compare(&partial_enum_offset_one, 10))
    );
    let partial_enum_parent_b_piece = make_partial_enum(&partial_enum_parent_b, 0);
    println!(
        "partialenum2.compare_parent={}",
        signum(partial_enum_offset_zero.compare(&partial_enum_parent_b_piece, 10))
    );
    let mut partial_enum_id_low = make_partial_enum(&partial_enum_parent_a, 0);
    let mut partial_enum_id_high = make_partial_enum(&partial_enum_parent_a, 0);
    partial_enum_id_low.base.id = 5;
    partial_enum_id_high.base.id = 9;
    println!(
        "partialenum2.compare_level0_id={}",
        signum(partial_enum_id_low.compare(&partial_enum_id_high, 0))
    );
    println!(
        "partialenum2.dependency_same_parent={}",
        signum(partial_enum_offset_zero.compare_dependency(&partial_enum_id_low))
    );
    println!(
        "partialenum2.dependency_offset={}",
        signum(partial_enum_offset_zero.compare_dependency(&partial_enum_offset_one))
    );
    let partial_enum_parent_copy_piece = make_partial_enum(&partial_enum_parent_copy, 0);
    let partial_enum_dep_forward =
        partial_enum_offset_zero.compare_dependency(&partial_enum_parent_copy_piece);
    let partial_enum_dep_reverse =
        partial_enum_parent_copy_piece.compare_dependency(&partial_enum_offset_zero);
    println!(
        "partialenum2.dependency_distinct_parent_nonzero={}",
        u8::from(partial_enum_dep_forward != 0)
    );
    println!(
        "partialenum2.dependency_distinct_parent_antisymmetric={}",
        u8::from(signum(partial_enum_dep_forward) == -signum(partial_enum_dep_reverse))
    );

    let partial_union_container = Arc::new(Datatype::Union(make_union(
        "U",
        vec![field("a", 0, int4.clone())],
    )));
    let partial_union_container_two = Arc::new(Datatype::Union(make_union(
        "U2F",
        vec![field("a", 0, int4.clone()), field("b", 0, uint4.clone())],
    )));
    let partial_union_container_copy = Arc::new(Datatype::Union(make_union(
        "Ucopy",
        vec![field("a", 0, int4.clone())],
    )));
    let make_partial_union = |container: &Arc<Datatype>, offset: i64| TypePartialUnion {
        base: {
            let mut partial_base =
                TypeBase::new(String::new(), 4, TypeMetatype::PartialUnion);
            partial_base.flags |=
                type_flags::NEEDS_RESOLUTION | type_flags::HAS_STRIPPED;
            partial_base
        },
        container: container.clone(),
        offset,
        stripped: Some(unknown4.clone()),
    };
    let partial_union_offset_zero = make_partial_union(&partial_union_container, 0);
    let partial_union_offset_four = make_partial_union(&partial_union_container, 4);
    println!(
        "partialunion2.compare_offset={}",
        signum(partial_union_offset_zero.compare(&partial_union_offset_four, 10))
    );
    let partial_union_container_two_piece =
        make_partial_union(&partial_union_container_two, 0);
    println!(
        "partialunion2.compare_container={}",
        signum(
            partial_union_offset_zero.compare(&partial_union_container_two_piece, 10)
        )
    );
    let mut partial_union_id_low = make_partial_union(&partial_union_container, 0);
    let mut partial_union_id_high = make_partial_union(&partial_union_container, 0);
    partial_union_id_low.base.id = 5;
    partial_union_id_high.base.id = 9;
    println!(
        "partialunion2.compare_level0_id={}",
        signum(partial_union_id_low.compare(&partial_union_id_high, 0))
    );
    println!(
        "partialunion2.dependency_same_container={}",
        signum(partial_union_offset_zero.compare_dependency(&partial_union_id_low))
    );
    println!(
        "partialunion2.dependency_offset={}",
        signum(
            partial_union_offset_zero.compare_dependency(&partial_union_offset_four)
        )
    );
    let partial_union_container_copy_piece =
        make_partial_union(&partial_union_container_copy, 0);
    let partial_union_dep_forward =
        partial_union_offset_zero.compare_dependency(&partial_union_container_copy_piece);
    let partial_union_dep_reverse =
        partial_union_container_copy_piece.compare_dependency(&partial_union_offset_zero);
    println!(
        "partialunion2.dependency_distinct_container_nonzero={}",
        u8::from(partial_union_dep_forward != 0)
    );
    println!(
        "partialunion2.dependency_distinct_container_antisymmetric={}",
        u8::from(signum(partial_union_dep_forward) == -signum(partial_union_dep_reverse))
    );

    // same-kind AddrSpace identity: two raw IPTR_PROCESSOR spaces sharing an
    // index cannot be distinguished by pointer identity in Rugra's enum model.
    let dup_space_a = AddrSpace::new_space(
        SpaceType::Processor,
        "dup_a",
        false,
        8,
        1,
        0xA5,
        space_flags::HASPHYSICAL,
        2,
        3,
    );
    let dup_space_b = AddrSpace::new_space(
        SpaceType::Processor,
        "dup_b",
        false,
        8,
        1,
        0xB6,
        space_flags::HASPHYSICAL,
        2,
        3,
    );
    let same_kind_a =
        make_spacebase(Some(AddressSpace::Other(0xA5)), Address::with_space(&dup_space_a, 0));
    let same_kind_b =
        make_spacebase(Some(AddressSpace::Other(0xB6)), Address::with_space(&dup_space_b, 0));
    let same_kind_a2 =
        make_spacebase(Some(AddressSpace::Other(0xA5)), Address::with_space(&dup_space_a, 0));
    let same_kind_forward = same_kind_a.compare_dependency(&same_kind_b);
    let same_kind_reverse = same_kind_b.compare_dependency(&same_kind_a);
    println!(
        "sksp.distinct_index_nonzero={}",
        u8::from(same_kind_forward != 0)
    );
    println!(
        "sksp.distinct_index_antisymmetric={}",
        u8::from(signum(same_kind_forward) == -signum(same_kind_reverse))
    );
    println!(
        "sksp.same_object_equal={}",
        signum(same_kind_a.compare_dependency(&same_kind_a))
    );
    println!(
        "sksp.same_index_distinct_object_nonzero={}",
        u8::from(same_kind_a.compare_dependency(&same_kind_a2) != 0)
    );
    let make_ptr_dup = |space: AddressSpace| {
        let mut pointer = TypePointer::new(8, int4.clone(), 1);
        pointer.base.pointer_space = Some(space);
        Datatype::Pointer(pointer)
    };
    let ptr_dup_space_a = make_ptr_dup(AddressSpace::Other(0xA5));
    let ptr_dup_space_a2 = make_ptr_dup(AddressSpace::Other(0xA5));
    println!(
        "ptr_same_kind.same_index_quirk={}",
        signum(ptr_dup_space_a.compare_at_level(&ptr_dup_space_a2, 10))
    );

    // Exhaustive 24-value sub-metatype runtime ordering matrix.
    let matrix_one_field_struct = structure(
        "OneMatrix",
        4,
        vec![field("a", 0, int4.clone())],
        false,
    );
    let matrix_two_field_struct = structure(
        "TwoMatrix",
        8,
        vec![
            field("a", 0, int4.clone()),
            field("b", 4, uint4.clone()),
        ],
        false,
    );
    let matrix_union = Arc::new(Datatype::Union(make_union(
        "UMatrix",
        vec![field("a", 0, int4.clone())],
    )));
    let mut matrix_rel_unk = TypePointer::new_relative(
        8,
        unknown4.clone(),
        1,
        matrix_one_field_struct.clone(),
        4,
    );
    matrix_rel_unk.mark_ephemeral(Arc::new(Datatype::Pointer(TypePointer::new(
        8,
        unknown4.clone(),
        1,
    ))));
    let matrix_types: Vec<Datatype> = vec![
        Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)),
        make_spacebase(Some(AddressSpace::Ram), valid_zero_frame),
        base("unknown_matrix", 4, TypeMetatype::Unknown).as_ref().clone(),
        Datatype::PartialStruct(TypePartialStruct {
            base: {
                let mut partial_base =
                    TypeBase::new(String::new(), 4, TypeMetatype::PartialStruct);
                partial_base.flags |= type_flags::HAS_STRIPPED;
                partial_base
            },
            container: matrix_two_field_struct.clone(),
            offset: 0,
            stripped: Some(unknown4.clone()),
        }),
        Datatype::Base(TypeBase::new_char("cs1".to_string(), TypeMetatype::Int)),
        Datatype::Base(TypeBase::new_char("cu1".to_string(), TypeMetatype::Uint)),
        base("int_matrix", 4, TypeMetatype::Int).as_ref().clone(),
        base("uint_matrix", 4, TypeMetatype::Uint).as_ref().clone(),
        Datatype::Enum(make_enum("ES", 1)),
        Datatype::PartialEnum(TypePartialEnum {
            base: {
                let mut partial_base =
                    TypeBase::new(String::new(), 1, TypeMetatype::PartialEnum);
                partial_base.flags |= type_flags::HAS_STRIPPED | type_flags::ENUMTYPE;
                partial_base
            },
            parent: partial_enum_parent_a.clone(),
            offset: 0,
            stripped: Some(unknown4.clone()),
        }),
        Datatype::Enum(make_enum_unsigned("EU", 1)),
        Datatype::Base(TypeBase::new_unicode(
            "ws2".to_string(),
            2,
            TypeMetatype::Int,
        )),
        Datatype::Base(TypeBase::new_unicode(
            "wu2".to_string(),
            2,
            TypeMetatype::Uint,
        )),
        base("bool_matrix", 1, TypeMetatype::Bool).as_ref().clone(),
        Datatype::Code(TypeCode {
            base: TypeBase::new(String::new(), 1, TypeMetatype::Code),
            proto: None,
        }),
        base("float_matrix", 4, TypeMetatype::Float).as_ref().clone(),
        Datatype::Pointer(matrix_rel_unk),
        pointer(int4.clone()),
        Datatype::Pointer(TypePointer::new_relative(
            8,
            int4.clone(),
            1,
            matrix_one_field_struct.clone(),
            4,
        )),
        pointer(matrix_two_field_struct.clone()),
        Datatype::Array(make_array(int4.clone(), 1)),
        matrix_two_field_struct.as_ref().clone(),
        matrix_union.as_ref().clone(),
        Datatype::PartialUnion(make_partial_union(&matrix_union, 0)),
    ];
    for (index, matrix_type) in matrix_types.iter().enumerate() {
        println!(
            "matrix.submeta_{:02}={}",
            23 - index,
            matrix_type.get_submeta() as i32
        );
    }
    for index in 0..23 {
        println!(
            "matrix.order_{:02}_{:02}={}",
            23 - index,
            22 - index,
            signum(matrix_types[index].compare_at_level(&matrix_types[index + 1], 10))
        );
    }
    let mut matrix_violations = 0;
    for i in 0..24 {
        for j in (i + 1)..24 {
            if signum(matrix_types[i].compare_at_level(&matrix_types[j], 10)) != 1 {
                matrix_violations += 1;
            }
        }
    }
    println!("matrix.total_order_violations={matrix_violations}");
}
