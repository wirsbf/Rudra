//! TYPEFACTORY-EXACTPIECE-0001 Rust comparand.
//!
//! This is deliberately a direct TypeFactory fixture.  It must call the
//! production `TypeFactory::get_exact_piece` API with the same type graph as
//! `typefactory_exactpiece_1204.cc`; copying the walk into a fixture-local or
//! subflow-local helper would not test the mapped Ghidra owner.
//!
//! Baseline 8c223a9 does not expose `get_exact_piece`, so this standalone
//! fixture is expected not to compile until TYPEFACTORY-EXACTPIECE-0001 is
//! implemented.  The baseline `get_array` also multiplies the raw element
//! size rather than `get_align_size`; the final `odd3_array3` record makes
//! that independent mismatch visible.  Neither gap is normalized away.
//!
//! `TYPEFIELD-IDENT-REPRESENTATION-0001` remains explicit: locked TypeField
//! stores declaration-order `ident` values, while Rust TypeField has no such
//! member. The bounded target closure never reads it, so this fixture makes no
//! whole-TypeStruct same-input claim.

use std::sync::{Arc, RwLock};

use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::type_system::datatype::{Datatype, TypeField, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

fn configure_factory() -> TypeFactory {
    // Match the C++ TypeFactory constructor: no convenience core bootstrap.
    let mut factory = TypeFactory::raw();

    let alignment_map = element("size_alignment_map", &[]);
    for (size, alignment) in [
        ("0", "1"),
        ("1", "1"),
        ("2", "2"),
        ("3", "2"),
        ("4", "4"),
        ("8", "8"),
        ("16", "8"),
        ("32", "8"),
    ] {
        alignment_map.write().unwrap().add_child(element(
            "entry",
            &[("size", size), ("alignment", alignment)],
        ));
    }
    let organization = element("data_organization", &[]);
    organization.write().unwrap().add_child(alignment_map);
    let registry = Arc::new(RwLock::new(IdRegistry::new()));
    let mut organization_decoder = TreeDecoder::new(organization, registry.clone());
    factory.decode_data_organization(&mut organization_decoder);
    factory.setup_sizes(&SizeArchInputs {
        stack_spacebase_size: Some(8),
        default_data_space_addr_size: 8,
        default_size: 8,
        far_pointer: None,
    });

    let enum_config = element("enum", &[("size", "8"), ("signed", "false")]);
    let mut enum_decoder = TreeDecoder::new(enum_config, registry);
    factory.parse_enum_config(&mut enum_decoder);

    // The only core entry on either side. It makes the >10-byte unknown-base
    // conversion deterministic without introducing TypeFactory::new's broad
    // convenience core set.
    factory
        .set_core_type_result("undefined1", 1, TypeMetatype::Unknown, false)
        .expect("undefined1 core registration");
    factory.cache_core_types();
    factory
}

fn field(name: &str, offset: usize, datatype: Arc<Datatype>) -> TypeField {
    TypeField {
        name: name.to_string(),
        offset,
        type_ptr: datatype,
    }
}

fn install_struct(
    factory: &mut TypeFactory,
    name: &str,
    fields: Vec<TypeField>,
    size: usize,
    alignment: usize,
) -> Arc<Datatype> {
    // Drop the create_struct return Arc before set_fields_sized so the
    // factory-owned Arc is the object mutated by Arc::make_mut.
    factory.create_struct(name);
    factory
        .set_fields_sized(name, fields, size, alignment)
        .expect("fixture struct exists")
}

fn install_union_sized(
    factory: &mut TypeFactory,
    name: &str,
    fields: Vec<TypeField>,
    size: usize,
    alignment: usize,
) -> Arc<Datatype> {
    factory.get_type_union(name);
    // Candidate symmetric API for Ghidra's TypeFactory::setFields union
    // overload. Baseline 8c223a9 lacks it and cannot represent an explicit
    // union alignment through set_union_fields.
    factory
        .set_union_fields_sized(name, fields, size, alignment)
        .expect("fixture sized union exists")
}

fn ghidra_metatype_number(metatype: TypeMetatype) -> i32 {
    match metatype {
        TypeMetatype::PartialUnion => 0,
        TypeMetatype::PartialStruct => 1,
        TypeMetatype::PartialEnum => 2,
        TypeMetatype::Union => 3,
        TypeMetatype::Struct => 4,
        TypeMetatype::Enum => 6,
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

fn plain_kind(datatype: &Datatype) -> &'static str {
    match datatype {
        Datatype::PartialStruct(_) => "partial_struct",
        Datatype::PartialUnion(_) => "partial_union",
        Datatype::PartialEnum(_) => "partial_enum",
        Datatype::Enum(_) => "enum",
        Datatype::Struct(_) => "struct",
        Datatype::Union(_) => "union",
        Datatype::Array(_) => "array",
        Datatype::Base(base) => match base.metatype {
            TypeMetatype::Uint => "uint",
            TypeMetatype::Int => "int",
            TypeMetatype::Unknown => "unknown",
            _ => "other",
        },
        _ => "other",
    }
}

fn short_shape(datatype: &Arc<Datatype>) -> String {
    format!("{}:{}", plain_kind(datatype), datatype.get_size())
}

fn shape(datatype: Option<&Arc<Datatype>>) -> String {
    let Some(datatype) = datatype else {
        return "null".to_string();
    };
    match datatype.as_ref() {
        Datatype::PartialStruct(part) => format!(
            "partial_struct:{}@{}/parent={}",
            datatype.get_size(),
            part.get_offset(),
            short_shape(part.get_parent()),
        ),
        Datatype::PartialUnion(part) => format!(
            "partial_union:{}@{}/parent={}",
            datatype.get_size(),
            part.get_offset(),
            short_shape(part.get_parent_union()),
        ),
        Datatype::PartialEnum(part) => format!(
            "partial_enum:{}@{}/parent={}",
            datatype.get_size(),
            part.get_offset(),
            short_shape(part.get_parent()),
        ),
        Datatype::Array(array) => format!(
            "array:{}x{}/elem={}",
            datatype.get_size(),
            array.num_elements,
            short_shape(&array.array_of),
        ),
        _ => short_shape(datatype),
    }
}

fn option_identity(left: Option<&Arc<Datatype>>, right: Option<&Arc<Datatype>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn emit_piece(
    factory: &mut TypeFactory,
    case_name: &str,
    input: &Arc<Datatype>,
    offset: i64,
    size: usize,
    expected: Option<&Arc<Datatype>>,
    direct: Option<&Arc<Datatype>>,
) {
    // Candidate API fixed by this bilateral fixture.  It is absent on the
    // pinned baseline and must be implemented on TypeFactory itself.
    let first = factory.get_exact_piece(input.clone(), offset, size);
    let repeat = factory.get_exact_piece(input.clone(), offset, size);
    let direct_same = direct.map_or_else(
        || "na".to_string(),
        |direct| {
            if option_identity(first.as_ref(), Some(direct)) {
                "1".to_string()
            } else {
                "0".to_string()
            }
        },
    );
    println!(
        "piece|case={case_name}|input={}|offset={offset}|size={size}|result={}|same_input={}|same_expected={}|repeat_same={}|direct_same={direct_same}",
        shape(Some(input)),
        shape(first.as_ref()),
        if option_identity(first.as_ref(), Some(input)) { 1 } else { 0 },
        if option_identity(first.as_ref(), expected) { 1 } else { 0 },
        if option_identity(first.as_ref(), repeat.as_ref()) { 1 } else { 0 },
    );
}

fn emit_piece_with_subtype(
    factory: &mut TypeFactory,
    case_name: &str,
    input: &Arc<Datatype>,
    offset: i64,
    size: usize,
    expected: Option<&Arc<Datatype>>,
    subtype_offset: i64,
) {
    let (subtype, subtype_newoff) = Datatype::get_sub_type_arc(input, subtype_offset);
    let first = factory.get_exact_piece(input.clone(), offset, size);
    let repeat = factory.get_exact_piece(input.clone(), offset, size);
    println!(
        "piece_subtype|case={case_name}|input={}|offset={offset}|size={size}|result={}|same_input={}|same_expected={}|repeat_same={}|direct_same=na|subtype_offset={subtype_offset}|subtype={}|subtype_newoff={subtype_newoff}",
        shape(Some(input)),
        shape(first.as_ref()),
        if option_identity(first.as_ref(), Some(input)) {
            1
        } else {
            0
        },
        if option_identity(first.as_ref(), expected) {
            1
        } else {
            0
        },
        if option_identity(first.as_ref(), repeat.as_ref()) {
            1
        } else {
            0
        },
        shape(subtype.as_ref()),
    );
}

fn array_element(array: &Arc<Datatype>) -> Arc<Datatype> {
    match array.as_ref() {
        Datatype::Array(array) => array.array_of.clone(),
        _ => panic!("fixture expected array"),
    }
}

fn array_count(array: &Arc<Datatype>) -> usize {
    match array.as_ref() {
        Datatype::Array(array) => array.num_elements,
        _ => 0,
    }
}

fn emit_array_policy(
    factory: &mut TypeFactory,
    case_name: &str,
    input: &Arc<Datatype>,
    expected_element: &Arc<Datatype>,
    contrast_element: Option<&Arc<Datatype>>,
    typedef_target_same: Option<bool>,
) {
    let array = factory.get_array(input.clone(), 2);
    let repeat = factory.get_array(input.clone(), 2);
    let expected_array = factory.get_array(expected_element.clone(), 2);
    let contrast_array = contrast_element.map(|element| factory.get_array(element.clone(), 2));
    let actual_element = array_element(&array);
    let typedef_target_same = typedef_target_same.map_or_else(
        || "na".to_string(),
        |same| {
            if same {
                "1".to_string()
            } else {
                "0".to_string()
            }
        },
    );
    let array_same_contrast = contrast_array.as_ref().map_or_else(
        || "na".to_string(),
        |contrast| {
            if Arc::ptr_eq(&array, contrast) {
                "1".to_string()
            } else {
                "0".to_string()
            }
        },
    );
    println!(
        "array_policy|case={case_name}|input={}|input_ghidra_metatype_code={}|input_submeta={}|input_id={}|input_is_core={}|input_is_enum={}|input_is_variable_length={}|input_is_incomplete={}|input_is_pointer_to_array={}|input_has_stripped={}|input_needs_resolution={}|input_alignment={}|input_align_size={}|input_name_empty={}|input_display_name_empty={}|typedef_target_same={typedef_target_same}|element={}|element_same_input={}|element_same_expected={}|array_same_expected={}|array_same_contrast={array_same_contrast}|array_size={}|array_alignment={}|array_align_size={}|array_name_empty={}|array_display_name_empty={}|repeat_same={}",
        shape(Some(input)),
        ghidra_metatype_number(input.get_metatype()),
        input.get_submeta() as i32,
        input.get_id(),
        if input.is_coretype() { 1 } else { 0 },
        if input.is_enum_type() { 1 } else { 0 },
        if input.is_variable_length() { 1 } else { 0 },
        if input.is_incomplete() { 1 } else { 0 },
        if input.is_pointer_to_array() { 1 } else { 0 },
        if input.has_stripped() { 1 } else { 0 },
        if input.needs_resolution() { 1 } else { 0 },
        input.get_alignment(),
        input.get_align_size(),
        if input.get_name().is_empty() { 1 } else { 0 },
        if input.get_display_name().is_empty() { 1 } else { 0 },
        shape(Some(&actual_element)),
        if Arc::ptr_eq(&actual_element, input) { 1 } else { 0 },
        if Arc::ptr_eq(&actual_element, expected_element) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&array, &expected_array) { 1 } else { 0 },
        array.get_size(),
        array.get_alignment(),
        array.get_align_size(),
        if array.get_name().is_empty() { 1 } else { 0 },
        if array.get_display_name().is_empty() { 1 } else { 0 },
        if Arc::ptr_eq(&array, &repeat) { 1 } else { 0 },
    );
}

struct CompositeDependencies {
    old_element: Arc<Datatype>,
    snapshot_size: usize,
    snapshot_alignment: usize,
    snapshot_align_size: usize,
    snapshot_incomplete: bool,
    snapshot_id: u64,
    snapshot_display_name: String,
    array: Arc<Datatype>,
    pointer: Arc<Datatype>,
    partial: Arc<Datatype>,
    typedef_type: Arc<Datatype>,
    union_parent: bool,
}

fn pointer_target(pointer: &Arc<Datatype>) -> Arc<Datatype> {
    match pointer.as_ref() {
        Datatype::Pointer(pointer) => pointer.ptr_to.clone(),
        _ => panic!("fixture expected pointer dependency"),
    }
}

fn partial_parent(partial: &Arc<Datatype>) -> Arc<Datatype> {
    match partial.as_ref() {
        Datatype::PartialStruct(partial) => partial.get_parent().clone(),
        Datatype::PartialUnion(partial) => partial.get_parent_union().clone(),
        _ => panic!("fixture expected partial dependency"),
    }
}

fn emit_composite_array_layout(
    factory: &mut TypeFactory,
    case_name: &str,
    dependencies: &CompositeDependencies,
    element: &Arc<Datatype>,
    count: usize,
) {
    let post_same_factory = factory
        .find_by_name(element.get_name())
        .is_some_and(|found| Arc::ptr_eq(&found, element));
    let array = factory.get_array(element.clone(), count);
    let repeat = factory.get_array(element.clone(), count);
    let dependency_array_old_repeat = factory.get_array(dependencies.old_element.clone(), 2);
    let dependency_array_post = factory.get_array(element.clone(), 2);
    let dependency_pointer_old_repeat =
        factory.get_type_pointer(8, dependencies.old_element.clone(), 1);
    let dependency_pointer_post = factory.get_type_pointer(8, element.clone(), 1);
    let dependency_partial_old_repeat = if dependencies.union_parent {
        factory.get_type_partial_union(dependencies.old_element.clone(), 0, 1)
    } else {
        factory.get_type_partial_struct(dependencies.old_element.clone(), 0, 1)
    };
    let dependency_partial_post = if dependencies.union_parent {
        factory.get_type_partial_union(element.clone(), 0, 1)
    } else {
        factory.get_type_partial_struct(element.clone(), 0, 1)
    };
    let dependency_array_element = array_element(&dependencies.array);
    let dependency_pointer_target = pointer_target(&dependencies.pointer);
    let dependency_partial_parent = partial_parent(&dependencies.partial);
    let dependency_typedef_target = factory
        .get_typedef_target(dependencies.typedef_type.get_name())
        .cloned()
        .expect("fixture typedef dependency target");
    let dependency_typedef_factory = factory
        .find_by_name(dependencies.typedef_type.get_name())
        .expect("fixture typedef dependency canonical object");
    println!(
        "array_layout|case={case_name}|pre_same_post={}|post_same_factory={}|pre_size={}|pre_alignment={}|pre_align_size={}|pre_incomplete={}|pre_id={}|pre_display_name={}|old_after_size={}|old_after_alignment={}|old_after_align_size={}|old_after_incomplete={}|old_after_id={}|old_after_display_name={}|post_size={}|post_alignment={}|post_align_size={}|post_incomplete={}|post_id={}|post_display_name={}|dep_array_size={}|dep_array_element_same_old={}|dep_array_element_same_post={}|dep_array_element_size={}|dep_array_element_alignment={}|dep_array_element_align_size={}|dep_array_element_incomplete={}|dep_array_old_repeat_same={}|dep_array_post_same={}|dep_pointer_target_same_old={}|dep_pointer_target_same_post={}|dep_pointer_target_size={}|dep_pointer_target_alignment={}|dep_pointer_target_align_size={}|dep_pointer_target_incomplete={}|dep_pointer_submeta={}|dep_pointer_is_core={}|dep_pointer_is_enum={}|dep_pointer_is_variable_length={}|dep_pointer_is_incomplete={}|dep_pointer_is_pointer_to_array={}|dep_pointer_has_stripped={}|dep_pointer_needs_resolution={}|dep_pointer_old_repeat_same={}|dep_pointer_post_same={}|dep_partial_parent_same_old={}|dep_partial_parent_same_post={}|dep_partial_parent_size={}|dep_partial_parent_alignment={}|dep_partial_parent_align_size={}|dep_partial_parent_incomplete={}|dep_partial_old_repeat_same={}|dep_partial_post_same={}|dep_typedef_target_same_old={}|dep_typedef_target_same_post={}|dep_typedef_target_size={}|dep_typedef_target_alignment={}|dep_typedef_target_align_size={}|dep_typedef_target_incomplete={}|dep_typedef_same_factory={}|dep_typedef_size={}|dep_typedef_alignment={}|dep_typedef_align_size={}|dep_typedef_incomplete={}|dep_typedef_id={}|dep_typedef_display_name={}|dep_typedef_factory_size={}|dep_typedef_factory_alignment={}|dep_typedef_factory_align_size={}|dep_typedef_factory_incomplete={}|dep_typedef_factory_id={}|dep_typedef_factory_display_name={}|element={}|element_ghidra_metatype_code={}|element_submeta={}|element_id={}|element_is_core={}|element_is_enum={}|element_is_variable_length={}|element_is_incomplete={}|element_is_pointer_to_array={}|element_has_stripped={}|element_needs_resolution={}|element_size={}|element_alignment={}|element_align_size={}|element_name_empty={}|element_display_name_empty={}|array_size={}|array_alignment={}|array_align_size={}|elements={}|array_element_same_input={}|array_name_empty={}|array_display_name_empty={}|factory_repeat_same={}",
        if Arc::ptr_eq(&dependencies.old_element, element) {
            1
        } else {
            0
        },
        if post_same_factory { 1 } else { 0 },
        dependencies.snapshot_size,
        dependencies.snapshot_alignment,
        dependencies.snapshot_align_size,
        if dependencies.snapshot_incomplete { 1 } else { 0 },
        dependencies.snapshot_id,
        dependencies.snapshot_display_name,
        dependencies.old_element.get_size(),
        dependencies.old_element.get_alignment(),
        dependencies.old_element.get_align_size(),
        if dependencies.old_element.is_incomplete() { 1 } else { 0 },
        dependencies.old_element.get_id(),
        dependencies.old_element.get_display_name(),
        element.get_size(),
        element.get_alignment(),
        element.get_align_size(),
        if element.is_incomplete() { 1 } else { 0 },
        element.get_id(),
        element.get_display_name(),
        dependencies.array.get_size(),
        if Arc::ptr_eq(&dependency_array_element, &dependencies.old_element) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_array_element, element) {
            1
        } else {
            0
        },
        dependency_array_element.get_size(),
        dependency_array_element.get_alignment(),
        dependency_array_element.get_align_size(),
        if dependency_array_element.is_incomplete() { 1 } else { 0 },
        if Arc::ptr_eq(&dependencies.array, &dependency_array_old_repeat) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependencies.array, &dependency_array_post) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_pointer_target, &dependencies.old_element) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_pointer_target, element) {
            1
        } else {
            0
        },
        dependency_pointer_target.get_size(),
        dependency_pointer_target.get_alignment(),
        dependency_pointer_target.get_align_size(),
        if dependency_pointer_target.is_incomplete() { 1 } else { 0 },
        dependencies.pointer.get_submeta() as i32,
        if dependencies.pointer.is_coretype() { 1 } else { 0 },
        if dependencies.pointer.is_enum_type() { 1 } else { 0 },
        if dependencies.pointer.is_variable_length() { 1 } else { 0 },
        if dependencies.pointer.is_incomplete() { 1 } else { 0 },
        if dependencies.pointer.is_pointer_to_array() { 1 } else { 0 },
        if dependencies.pointer.has_stripped() { 1 } else { 0 },
        if dependencies.pointer.needs_resolution() {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependencies.pointer, &dependency_pointer_old_repeat) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependencies.pointer, &dependency_pointer_post) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_partial_parent, &dependencies.old_element) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_partial_parent, element) {
            1
        } else {
            0
        },
        dependency_partial_parent.get_size(),
        dependency_partial_parent.get_alignment(),
        dependency_partial_parent.get_align_size(),
        if dependency_partial_parent.is_incomplete() { 1 } else { 0 },
        if Arc::ptr_eq(&dependencies.partial, &dependency_partial_old_repeat) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependencies.partial, &dependency_partial_post) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_typedef_target, &dependencies.old_element) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&dependency_typedef_target, element) {
            1
        } else {
            0
        },
        dependency_typedef_target.get_size(),
        dependency_typedef_target.get_alignment(),
        dependency_typedef_target.get_align_size(),
        if dependency_typedef_target.is_incomplete() { 1 } else { 0 },
        if Arc::ptr_eq(&dependencies.typedef_type, &dependency_typedef_factory) {
            1
        } else {
            0
        },
        dependencies.typedef_type.get_size(),
        dependencies.typedef_type.get_alignment(),
        dependencies.typedef_type.get_align_size(),
        if dependencies.typedef_type.is_incomplete() { 1 } else { 0 },
        dependencies.typedef_type.get_id(),
        dependencies.typedef_type.get_display_name(),
        dependency_typedef_factory.get_size(),
        dependency_typedef_factory.get_alignment(),
        dependency_typedef_factory.get_align_size(),
        if dependency_typedef_factory.is_incomplete() {
            1
        } else {
            0
        },
        dependency_typedef_factory.get_id(),
        dependency_typedef_factory.get_display_name(),
        shape(Some(element)),
        ghidra_metatype_number(element.get_metatype()),
        element.get_submeta() as i32,
        element.get_id(),
        if element.is_coretype() { 1 } else { 0 },
        if element.is_enum_type() { 1 } else { 0 },
        if element.is_variable_length() { 1 } else { 0 },
        if element.is_incomplete() { 1 } else { 0 },
        if element.is_pointer_to_array() { 1 } else { 0 },
        if element.has_stripped() { 1 } else { 0 },
        if element.needs_resolution() { 1 } else { 0 },
        element.get_size(),
        element.get_alignment(),
        element.get_align_size(),
        if element.get_name().is_empty() { 1 } else { 0 },
        if element.get_display_name().is_empty() { 1 } else { 0 },
        array.get_size(),
        array.get_alignment(),
        array.get_align_size(),
        array_count(&array),
        if Arc::ptr_eq(&array_element(&array), element) { 1 } else { 0 },
        if array.get_name().is_empty() { 1 } else { 0 },
        if array.get_display_name().is_empty() { 1 } else { 0 },
        if Arc::ptr_eq(&array, &repeat) { 1 } else { 0 },
    );
}

fn main() {
    let mut factory = configure_factory();

    let uint2 = factory
        .get_base_result(2, TypeMetatype::Uint)
        .expect("uint2");
    let uint4 = factory
        .get_base_result(4, TypeMetatype::Uint)
        .expect("uint4");
    let uint8 = factory
        .get_base_result(8, TypeMetatype::Uint)
        .expect("uint8");
    let odd3 = factory
        .get_base_result(3, TypeMetatype::Uint)
        .expect("odd uint3");

    let inner = install_struct(
        &mut factory,
        "fixture_exact_inner8",
        vec![field("lo", 0, uint4.clone()), field("hi", 4, uint4.clone())],
        8,
        4,
    );
    let outer = install_struct(
        &mut factory,
        "fixture_exact_outer24",
        vec![
            field("head", 0, uint4.clone()),
            field("inner", 8, inner.clone()),
            field("tail", 16, uint8.clone()),
        ],
        24,
        8,
    );
    let union8 = install_union_sized(
        &mut factory,
        "fixture_exact_union8",
        vec![
            field("wide", 0, uint8.clone()),
            field("narrow", 0, uint4.clone()),
        ],
        8,
        8,
    );
    let enum8 = factory
        .get_type_enum_result("fixture_exact_enum8")
        .expect("configured uint enum8");
    let uint4_array3 = factory.get_array(uint4.clone(), 3);
    let odd3_array3 = factory.get_array(odd3.clone(), 3);
    let inner_part6 = factory.get_type_partial_struct(inner.clone(), 0, 6);

    emit_piece(
        &mut factory,
        "whole_struct",
        &outer,
        0,
        24,
        Some(&outer),
        None,
    );
    emit_piece(
        &mut factory,
        "nested_struct",
        &outer,
        8,
        8,
        Some(&inner),
        None,
    );
    emit_piece(
        &mut factory,
        "nested_leaf",
        &outer,
        12,
        4,
        Some(&uint4),
        None,
    );
    emit_piece(
        &mut factory,
        "contained_scalar_partial",
        &outer,
        9,
        2,
        None,
        None,
    );
    emit_piece(
        &mut factory,
        "scalar_negative_exact",
        &uint4,
        -1,
        4,
        Some(&uint4),
        None,
    );

    let cross = factory.get_type_partial_struct(inner.clone(), 2, 4);
    emit_piece(
        &mut factory,
        "cross_field",
        &inner,
        2,
        4,
        Some(&cross),
        Some(&cross),
    );
    let hole = factory.get_type_partial_struct(outer.clone(), 4, 4);
    emit_piece(
        &mut factory,
        "struct_hole",
        &outer,
        4,
        4,
        Some(&hole),
        Some(&hole),
    );
    emit_piece(&mut factory, "beyond_end", &outer, 22, 4, None, None);

    emit_piece(
        &mut factory,
        "whole_union",
        &union8,
        0,
        8,
        Some(&union8),
        None,
    );
    let part_union = factory.get_type_partial_union(union8.clone(), 1, 4);
    emit_piece(
        &mut factory,
        "partial_union",
        &union8,
        1,
        4,
        Some(&part_union),
        Some(&part_union),
    );

    emit_piece(&mut factory, "whole_enum", &enum8, 0, 8, Some(&enum8), None);
    let part_enum = factory.get_type_partial_enum(enum8.clone(), 2, 4);
    emit_piece(
        &mut factory,
        "partial_enum",
        &enum8,
        2,
        4,
        Some(&part_enum),
        Some(&part_enum),
    );

    emit_piece(
        &mut factory,
        "whole_array",
        &uint4_array3,
        0,
        12,
        Some(&uint4_array3),
        None,
    );
    emit_piece(
        &mut factory,
        "array_element",
        &uint4_array3,
        4,
        4,
        Some(&uint4),
        None,
    );
    let array_cross = factory.get_type_partial_struct(uint4_array3.clone(), 3, 2);
    emit_piece(
        &mut factory,
        "array_cross_stride",
        &uint4_array3,
        3,
        2,
        Some(&array_cross),
        Some(&array_cross),
    );

    emit_piece(
        &mut factory,
        "partialstruct_whole",
        &inner_part6,
        0,
        6,
        Some(&inner_part6),
        Some(&inner_part6),
    );
    emit_piece(
        &mut factory,
        "partialstruct_nested",
        &inner_part6,
        0,
        4,
        Some(&uint4),
        None,
    );
    emit_piece(
        &mut factory,
        "partialstruct_cross",
        &inner_part6,
        2,
        4,
        None,
        None,
    );
    let narrow_part = factory.get_type_partial_struct(inner.clone(), 0, 2);
    emit_piece_with_subtype(
        &mut factory,
        "partialstruct_descent_null",
        &narrow_part,
        0,
        1,
        None,
        0,
    );

    let odd_array_repeat = factory.get_array(odd3.clone(), 3);
    let odd_piece = factory.get_exact_piece(odd3_array3.clone(), 4, 3);
    let odd_piece_repeat = factory.get_exact_piece(odd3_array3.clone(), 4, 3);
    println!(
        "array_layout|case=odd3_array3|element={}|element_ghidra_metatype_code={}|element_submeta={}|element_id={}|element_is_core={}|element_is_enum={}|element_is_variable_length={}|element_is_incomplete={}|element_is_pointer_to_array={}|element_has_stripped={}|element_needs_resolution={}|element_size={}|element_alignment={}|element_align_size={}|element_name_empty={}|element_display_name_empty={}|array_size={}|array_alignment={}|array_align_size={}|elements={}|array_element_same_input={}|array_name_empty={}|array_display_name_empty={}|factory_repeat_same={}|piece={}|piece_expected_same={}|piece_repeat_same={}",
        shape(Some(&odd3)),
        ghidra_metatype_number(odd3.get_metatype()),
        odd3.get_submeta() as i32,
        odd3.get_id(),
        if odd3.is_coretype() { 1 } else { 0 },
        if odd3.is_enum_type() { 1 } else { 0 },
        if odd3.is_variable_length() { 1 } else { 0 },
        if odd3.is_incomplete() { 1 } else { 0 },
        if odd3.is_pointer_to_array() { 1 } else { 0 },
        if odd3.has_stripped() { 1 } else { 0 },
        if odd3.needs_resolution() { 1 } else { 0 },
        odd3.get_size(),
        odd3.get_alignment(),
        odd3.get_align_size(),
        if odd3.get_name().is_empty() { 1 } else { 0 },
        if odd3.get_display_name().is_empty() { 1 } else { 0 },
        odd3_array3.get_size(),
        odd3_array3.get_alignment(),
        odd3_array3.get_align_size(),
        match odd3_array3.as_ref() {
            Datatype::Array(array) => array.num_elements,
            _ => 0,
        },
        if Arc::ptr_eq(&array_element(&odd3_array3), &odd3) {
            1
        } else {
            0
        },
        if odd3_array3.get_name().is_empty() { 1 } else { 0 },
        if odd3_array3.get_display_name().is_empty() { 1 } else { 0 },
        if Arc::ptr_eq(&odd3_array3, &odd_array_repeat) { 1 } else { 0 },
        shape(odd_piece.as_ref()),
        if option_identity(odd_piece.as_ref(), Some(&odd3)) { 1 } else { 0 },
        if option_identity(odd_piece.as_ref(), odd_piece_repeat.as_ref()) { 1 } else { 0 },
    );

    let typedef4 = factory.get_typedef("fixture_exact_u4_alias", uint4.clone());
    let typedef_target_same = factory
        .get_typedef_target("fixture_exact_u4_alias")
        .is_some_and(|target| Arc::ptr_eq(target, &uint4));
    emit_array_policy(
        &mut factory,
        "typedef_preserve",
        &typedef4,
        &typedef4,
        Some(&uint4),
        Some(typedef_target_same),
    );

    // Size 12 crosses the shared max_basetype_size=10 threshold, so the
    // stripped fallback is itself undefined1[12].
    let partial_element = factory.get_type_partial_struct(outer.clone(), 0, 12);
    let partial_stripped =
        Datatype::get_stripped_arc(&partial_element).expect("PartialStruct stripped fallback");
    emit_array_policy(
        &mut factory,
        "partialstruct_strip",
        &partial_element,
        &partial_stripped,
        None,
        None,
    );

    let typedef_partial =
        factory.get_typedef("fixture_exact_partial_alias", partial_element.clone());
    let typedef_partial_target_same = factory
        .get_typedef_target("fixture_exact_partial_alias")
        .is_some_and(|target| Arc::ptr_eq(target, &partial_element));
    emit_array_policy(
        &mut factory,
        "typedef_partialstruct_strip",
        &typedef_partial,
        &partial_stripped,
        Some(&partial_element),
        Some(typedef_partial_target_same),
    );

    let parent_pointer = factory.get_type_pointer(8, inner.clone(), 1);
    let relative_element = factory.get_type_pointer_rel_ephemeral(parent_pointer, uint4.clone(), 4);
    let plain_pointer = Datatype::get_stripped_arc(&relative_element)
        .expect("ephemeral PointerRel stripped pointer");
    emit_array_policy(
        &mut factory,
        "pointerrel_strip",
        &relative_element,
        &plain_pointer,
        None,
        None,
    );

    let align_struct_pre = factory.create_struct("fixture_exact_align_struct6");
    let align_struct_dependencies = CompositeDependencies {
        old_element: align_struct_pre.clone(),
        snapshot_size: align_struct_pre.get_size(),
        snapshot_alignment: align_struct_pre.get_alignment(),
        snapshot_align_size: align_struct_pre.get_align_size(),
        snapshot_incomplete: align_struct_pre.is_incomplete(),
        snapshot_id: align_struct_pre.get_id(),
        snapshot_display_name: align_struct_pre.get_display_name().to_string(),
        array: factory.get_array(align_struct_pre.clone(), 2),
        pointer: factory.get_type_pointer(8, align_struct_pre.clone(), 1),
        partial: factory.get_type_partial_struct(align_struct_pre.clone(), 0, 1),
        typedef_type: factory.get_typedef(
            "fixture_exact_align_struct6_alias",
            align_struct_pre.clone(),
        ),
        union_parent: false,
    };
    let align_struct = factory
        .set_fields_sized(
            "fixture_exact_align_struct6",
            vec![
                field("wide", 0, uint4.clone()),
                field("tail", 4, uint2.clone()),
            ],
            6,
            1,
        )
        .expect("fixture explicit-align struct exists");
    emit_composite_array_layout(
        &mut factory,
        "explicit_align_struct",
        &align_struct_dependencies,
        &align_struct,
        3,
    );

    let align_union_pre = factory.get_type_union("fixture_exact_align_union4");
    let align_union_dependencies = CompositeDependencies {
        old_element: align_union_pre.clone(),
        snapshot_size: align_union_pre.get_size(),
        snapshot_alignment: align_union_pre.get_alignment(),
        snapshot_align_size: align_union_pre.get_align_size(),
        snapshot_incomplete: align_union_pre.is_incomplete(),
        snapshot_id: align_union_pre.get_id(),
        snapshot_display_name: align_union_pre.get_display_name().to_string(),
        array: factory.get_array(align_union_pre.clone(), 2),
        pointer: factory.get_type_pointer(8, align_union_pre.clone(), 1),
        partial: factory.get_type_partial_union(align_union_pre.clone(), 0, 1),
        typedef_type: factory
            .get_typedef("fixture_exact_align_union4_alias", align_union_pre.clone()),
        union_parent: true,
    };
    let align_union = factory
        .set_union_fields_sized(
            "fixture_exact_align_union4",
            vec![
                field("wide", 0, uint4.clone()),
                field("narrow", 0, uint2.clone()),
            ],
            4,
            1,
        )
        .expect("fixture explicit-align union exists");
    emit_composite_array_layout(
        &mut factory,
        "explicit_align_union",
        &align_union_dependencies,
        &align_union,
        3,
    );

    let single_array = factory.get_array(uint4.clone(), 1);
    let single_repeat = factory.get_array(uint4.clone(), 1);
    println!(
        "array_ctor|case=array_size1_needsres|size={}|alignment={}|align_size={}|elements={}|element_same={}|needs_resolution={}|name_empty={}|display_name_empty={}|repeat_same={}",
        single_array.get_size(),
        single_array.get_alignment(),
        single_array.get_align_size(),
        array_count(&single_array),
        if Arc::ptr_eq(&array_element(&single_array), &uint4) {
            1
        } else {
            0
        },
        if single_array.needs_resolution() { 1 } else { 0 },
        if single_array.get_name().is_empty() { 1 } else { 0 },
        if single_array.get_display_name().is_empty() { 1 } else { 0 },
        if Arc::ptr_eq(&single_array, &single_repeat) {
            1
        } else {
            0
        },
    );

    let same_total_a = factory.get_array(uint2.clone(), 4);
    let same_total_b = factory.get_array(uint4.clone(), 2);
    let same_total_a_repeat = factory.get_array(uint2.clone(), 4);
    let same_total_b_repeat = factory.get_array(uint4.clone(), 2);
    println!(
        "array_identity|case=same_total_distinct_elements|a_size={}|b_size={}|same_total={}|a_element_same={}|b_element_same={}|arrays_same={}|a_repeat_same={}|b_repeat_same={}",
        same_total_a.get_size(),
        same_total_b.get_size(),
        if same_total_a.get_size() == same_total_b.get_size() {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&array_element(&same_total_a), &uint2) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&array_element(&same_total_b), &uint4) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&same_total_a, &same_total_b) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&same_total_a, &same_total_a_repeat) {
            1
        } else {
            0
        },
        if Arc::ptr_eq(&same_total_b, &same_total_b_repeat) {
            1
        } else {
            0
        },
    );

    let part_enum_stripped =
        Datatype::get_stripped_arc(&part_enum).expect("PartialEnum stripped fallback");
    emit_array_policy(
        &mut factory,
        "partialenum_strip",
        &part_enum,
        &part_enum_stripped,
        None,
        None,
    );
    let part_union_stripped =
        Datatype::get_stripped_arc(&part_union).expect("PartialUnion stripped fallback");
    emit_array_policy(
        &mut factory,
        "partialunion_strip",
        &part_union,
        &part_union_stripped,
        None,
        None,
    );

    let negative_direct = factory.get_type_partial_struct(outer.clone(), -1, 4);
    emit_piece(
        &mut factory,
        "negative_offset",
        &outer,
        -1,
        4,
        Some(&negative_direct),
        Some(&negative_direct),
    );
    let zero_direct = factory.get_type_partial_struct(outer.clone(), 4, 0);
    emit_piece(
        &mut factory,
        "zero_size_hole",
        &outer,
        4,
        0,
        Some(&zero_direct),
        Some(&zero_direct),
    );
}
