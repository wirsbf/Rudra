//! TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001 Rust comparand.
//!
//! This is deliberately a direct TypeFactory fixture.  It must call the
//! production `TypeFactory::down_chain_virtual` entry with the same type
//! graph as `typefactory_downchain_virtual_1204.cc`; copying the dispatch
//! into a fixture-local helper would not test the mapped virtual call site.
//!
//! The 25-case manifest covers the plain `TypePointer::downChain` body
//! (type.cc:1084-1121) and the `TypePointerRel` override (type.cc:2656-2672)
//! through the dispatcher: field hits, hole/null descents, off==0 and
//! off==size boundaries, negative-encoded wrap, the enum branch, multi-level
//! array chains with carried accumulators, and plain/relative routing
//! discrimination.  Identity is emitted as Arc-equality predicates only.
//!
//! Bounded input domain: no field/element type carries a stripped state and
//! the alternate-pointer-size truncate path never fires, so
//! `getTypePointerStripArray`'s hasStripped pre-strip (type.cc:3851-3852)
//! and `calcTruncate` are not observable in this projection; they remain
//! registered residuals, not normalized differences.

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

    // The only core entry on either side (identical to the exactpiece
    // baseline bootstrap).
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

fn plain_kind(datatype: &Datatype) -> &'static str {
    match datatype {
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

fn shape(datatype: &Arc<Datatype>) -> String {
    match datatype.as_ref() {
        Datatype::Array(array) => format!(
            "array:{}x{}/elem={}",
            datatype.get_size(),
            array.num_elements,
            short_shape(&array.array_of),
        ),
        _ => short_shape(datatype),
    }
}

fn pointer_shape(datatype: Option<&Arc<Datatype>>) -> String {
    let Some(datatype) = datatype else {
        return "null".to_string();
    };
    match datatype.as_ref() {
        Datatype::Pointer(pointer) => {
            if let Some(state) = &pointer.base.pointer_rel {
                format!(
                    "ptrrel:{}->{}+{}@{}",
                    pointer.base.size,
                    short_shape(&pointer.ptr_to),
                    state.offset,
                    short_shape(&state.parent),
                )
            } else {
                format!("ptr:{}->{}", pointer.base.size, shape(&pointer.ptr_to))
            }
        }
        _ => "null".to_string(),
    }
}

fn same_as_input(observed: Option<&Arc<Datatype>>, input: &Arc<Datatype>) -> u8 {
    match observed {
        Some(observed) if Arc::ptr_eq(observed, input) => 1,
        _ => 0,
    }
}

struct DownchainState {
    result: Option<Arc<Datatype>>,
    par: Option<Arc<Datatype>>,
    par_off: i64,
    off: i64,
}

fn emit_downchain_step(
    factory: &mut TypeFactory,
    case_name: &str,
    input: &Arc<Datatype>,
    off_in: i64,
    allow_wrap: bool,
    par_in: Option<Arc<Datatype>>,
    par_off_in: i64,
) -> DownchainState {
    let mut off = off_in;
    let mut par = par_in;
    let mut par_off = par_off_in;
    let result = factory.down_chain_virtual(input, &mut off, &mut par, &mut par_off, allow_wrap);
    println!(
        "downchain|case={}|input={}|off_in={}|wrap={}|result={}|off_out={}|par={}|par_off={}|result_same_input={}|par_same_input={}",
        case_name,
        pointer_shape(Some(input)),
        off_in,
        if allow_wrap { 1 } else { 0 },
        pointer_shape(result.as_ref()),
        off,
        pointer_shape(par.as_ref()),
        par_off,
        same_as_input(result.as_ref(), input),
        same_as_input(par.as_ref(), input),
    );
    DownchainState {
        result,
        par,
        par_off,
        off,
    }
}

fn emit_downchain(
    factory: &mut TypeFactory,
    case_name: &str,
    input: &Arc<Datatype>,
    off_in: i64,
    allow_wrap: bool,
) -> DownchainState {
    emit_downchain_step(factory, case_name, input, off_in, allow_wrap, None, -999)
}

fn main() {
    let mut factory = configure_factory();

    let uint4 = factory
        .get_base_result(4, TypeMetatype::Uint)
        .expect("uint4");
    let uint8 = factory
        .get_base_result(8, TypeMetatype::Uint)
        .expect("uint8");

    let inner = install_struct(
        &mut factory,
        "fixture_dcv_inner8",
        vec![field("lo", 0, uint4.clone()), field("hi", 4, uint4.clone())],
        8,
        4,
    );
    let progress = install_struct(
        &mut factory,
        "fixture_dcv_progress24",
        vec![
            field("head", 0, uint4.clone()),
            field("inner", 8, inner.clone()),
            field("total", 16, uint8.clone()),
        ],
        24,
        8,
    );
    let holed = install_struct(
        &mut factory,
        "fixture_dcv_holed12",
        vec![field("head", 0, uint4.clone()), field("tail", 8, uint4.clone())],
        12,
        4,
    );
    let inners3 = factory.get_array(inner.clone(), 3);
    let inners3x2 = factory.get_array(inners3.clone(), 2);
    let holder = install_struct(
        &mut factory,
        "fixture_dcv_holder24",
        vec![field("elems", 0, inners3.clone())],
        24,
        4,
    );
    let enum8 = factory
        .get_type_enum_result("fixture_dcv_enum8")
        .expect("configured uint enum8");

    let pd_pointer = factory.get_type_pointer(8, progress.clone(), 1);
    let holed_pointer = factory.get_type_pointer(8, holed.clone(), 1);
    let arr_pointer = factory.get_type_pointer(8, inners3.clone(), 1);
    let arr2_pointer = factory.get_type_pointer(8, inners3x2.clone(), 1);
    let holder_pointer = factory.get_type_pointer(8, holder.clone(), 1);
    let uint4_pointer = factory.get_type_pointer(8, uint4.clone(), 1);
    let enum_pointer = factory.get_type_pointer(8, enum8.clone(), 1);

    let rel_total = factory.get_type_pointer_rel_ephemeral(pd_pointer.clone(), uint8.clone(), 16);
    let rel_inner = factory.get_type_pointer_rel_ephemeral(pd_pointer.clone(), inner.clone(), 8);
    let rel_hole = factory.get_type_pointer_rel_ephemeral(holed_pointer.clone(), uint4.clone(), 4);
    let rel_first = factory.get_type_pointer_rel_ephemeral(pd_pointer.clone(), uint4.clone(), 0);

    // Plain struct descents (TypePointer::downChain, type.cc:1084).
    emit_downchain(&mut factory, "pd_field_hit", &pd_pointer, 16, false);
    emit_downchain(&mut factory, "pd_field_inner", &pd_pointer, 8, false);
    emit_downchain(&mut factory, "pd_field_mid", &pd_pointer, 2, false);
    emit_downchain(&mut factory, "pd_hole_null", &pd_pointer, 5, false);
    emit_downchain(&mut factory, "pd_off0", &pd_pointer, 0, false);
    // off==size boundary: wrap denied returns NULL before any mutation.
    emit_downchain(&mut factory, "pd_off_size_nowrap", &pd_pointer, 24, false);
    // off==size with wrap folds back to zero and returns this pointer.
    emit_downchain(&mut factory, "pd_off_size_wrap", &pd_pointer, 24, true);
    // Negative-encoded offsets (PTRSUB-style deny vs INT_ADD-style wrap).
    emit_downchain(&mut factory, "pd_negative_nowrap", &pd_pointer, -4, false);
    emit_downchain(&mut factory, "pd_negative_wrap", &pd_pointer, -4, true);

    // Array descents: element identity, strip vs preserve, nesting.
    emit_downchain(&mut factory, "array_elem", &arr_pointer, 12, false);
    emit_downchain(&mut factory, "array_strip_contrast", &holder_pointer, 0, false);
    emit_downchain(&mut factory, "array_preserve_nested", &arr2_pointer, 8, false);

    // Two propagateAddIn2Out-style chain steps with carried accumulators.
    let step1 = emit_downchain(&mut factory, "chain_step1", &arr_pointer, 12, false);
    emit_downchain_step(
        &mut factory,
        "chain_step2",
        step1.result.as_ref().expect("step1 produced a component pointer"),
        step1.off,
        false,
        step1.par.clone(),
        step1.par_off,
    );

    // Hole descent returning NULL with the container still recorded.
    emit_downchain(&mut factory, "holed_hole_null", &holed_pointer, 6, false);

    // Scalar pointee: base getSubType is NULL; wrap folds to this pointer.
    emit_downchain(&mut factory, "uint4_plain_null", &uint4_pointer, 0, false);
    emit_downchain(&mut factory, "uint4_off_size_wrap", &uint4_pointer, 4, true);

    // Enumeration branch (type.cc:1102-1107).
    emit_downchain(&mut factory, "enum_into_uint1", &enum_pointer, 3, false);

    // Relative-pointer dispatch (TypePointerRel::downChain, type.cc:2656).
    emit_downchain(&mut factory, "rel_total_field", &rel_total, 0, false);
    // relOff==0 && offset!=0 returns the parent pointer and leaves the
    // accumulators untouched (type.cc:2669-2670).
    emit_downchain(&mut factory, "rel_recover_parent", &rel_total, -16, false);
    emit_downchain(&mut factory, "rel_out_of_parent", &rel_total, 8, false);
    // Deferred plain call on the relative pointer itself: par = this (rel).
    emit_downchain(&mut factory, "rel_defer_field", &rel_inner, 4, false);
    // relOff inside the parent hole: the recursive plain call returns NULL
    // and the rel override passes it through (type.cc:2671, no fallback).
    emit_downchain(&mut factory, "rel_tail_null", &rel_hole, 2, false);
    // off==ptrto->getSize() falls out of the deferral guard into the
    // parent-relative path (contrast with rel_defer_field).
    emit_downchain(&mut factory, "rel_defer_boundary", &rel_inner, 8, false);
    // Routing discrimination: same scalar ptrto, plain yields NULL while
    // the relative pointer reaches the parent's first field.
    emit_downchain(&mut factory, "route_rel_first", &rel_first, 0, false);
}
