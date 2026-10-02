/*
 * Rugra comparand for DATATYPE-PRINTRAW-0001, the bilateral twin of
 * tests/oracle/datatype_printraw_1204.cc.
 *
 * Exercises src/type_system/datatype.rs print_raw under the same
 * anchors (locked oracle e40ed13014025f82488b1f8f7bca566894ac376b):
 *
 *   Datatype::printRaw          type.cc:139-146   base fallback (name / unkbyte<size>)
 *   TypePointer::printRaw       type.cc:910-918   ptrto, " *", optional "(<spacename>)"
 *   TypeArray::printRaw         type.cc:1204-1209 arrayof, " [<arraysize>]"
 *   TypePartialEnum::printRaw   type.cc:2264-2269 parent, "[off=<off>,sz=<size>]"
 *   TypePartialStruct::printRaw type.cc:2356-2361 container, "[off=<off>,sz=<size>]"
 *   TypePartialUnion::printRaw  type.cc:2433-2438 container, "[off=<off>,sz=<size>]"
 *   TypePointerRel::printRaw    type.cc:2597-2606 ptrto, " *+", offset, "[", parent, "]"
 *   TypeCode::printRaw          type.cc:2772-2780 name-or-"funcptr", "()"
 *
 * Construction notes (same-input discipline):
 *  - The C++ twin constructs every subclass through its public
 *    type.hh constructors; this twin mirrors those constructors with
 *    Rust literals / TypePointer::new* / TypePartial*::new.  Unobserved
 *    ctor flag bits (enumtype / type_incomplete / needs_resolution /
 *    coretype) are mirrored for state parity even though print_raw
 *    never reads them.
 *  - The named TypeCode case mirrors the (private)
 *    TypeFactory::getTypeCode(const string&) body (type.cc:3711-3719)
 *    on both sides, because type.hh has no public named TypeCode
 *    constructor and the private factory is unreachable from the C++
 *    fixture.
 *  - TypeSpacebase address fields carry no printRaw observables; the
 *    literal mirrors C++ Address(ram, 0x1000) with the Rust Address
 *    value API.
 */

use std::collections::BTreeMap;
use std::sync::Arc;

use rudra::address::Address;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    type_flags, Datatype, TypeArray, TypeBase, TypeCode, TypeEnum, TypeMetatype, TypePartialEnum,
    TypePartialStruct, TypePartialUnion, TypePointer, TypeSpacebase, TypeStruct, TypeUnion,
};

fn emit(id: &str, dt: &Datatype) {
    println!("case={}|[{}]|", id, dt.print_raw());
}

fn base_named() -> Datatype {
    Datatype::Base(TypeBase::new("myint".to_string(), 4, TypeMetatype::Int))
}

fn base_unnamed(size: usize) -> Datatype {
    Datatype::Base(TypeBase::new(String::new(), size, TypeMetatype::Unknown))
}

fn array_of(element: Arc<Datatype>, num_elements: usize) -> Datatype {
    // Mirrors the inline C++ ctor TypeArray::TypeArray (type.hh:937-946):
    // size = n * ao->getAlignSize(), alignment inherited from the
    // element (standalone unaligned elements: alignSize == size).
    let size = element.get_align_size() * num_elements;
    let mut base = TypeBase::new(String::new(), size, TypeMetatype::Array);
    base.alignment = element.get_alignment() as i32;
    base.align_size = size;
    if num_elements == 1 {
        base.flags |= type_flags::NEEDS_RESOLUTION;
    }
    Datatype::Array(TypeArray { base, array_of: element, num_elements })
}

fn struct_incomplete() -> Datatype {
    // Mirrors C++ TypeStruct() (type.hh:518): Datatype(0,-1,TYPE_STRUCT)
    // with type_incomplete.
    let mut base = TypeBase::new(String::new(), 0, TypeMetatype::Struct);
    base.flags |= type_flags::TYPE_INCOMPLETE;
    Datatype::Struct(TypeStruct { base, fields: Vec::new() })
}

fn union_incomplete() -> Datatype {
    // Mirrors C++ TypeUnion() (type.hh:551): Datatype(0,-1,TYPE_UNION)
    // with type_incomplete | needs_resolution.
    let mut base = TypeBase::new(String::new(), 0, TypeMetatype::Union);
    base.flags |= type_flags::TYPE_INCOMPLETE | type_flags::NEEDS_RESOLUTION;
    Datatype::Union(TypeUnion { base, fields: Vec::new() })
}

fn enum_dt(name: &str) -> Datatype {
    // Mirrors C++ TypeEnum(int4,type_metatype,const string&) (type.hh:490-492):
    // TYPE_INT metatype with the enumtype flag.
    let mut base = TypeBase::new(name.to_string(), 4, TypeMetatype::Int);
    base.flags |= type_flags::ENUMTYPE;
    Datatype::Enum(TypeEnum { base, values: BTreeMap::new() })
}

fn void_default() -> Datatype {
    // Mirrors C++ TypeVoid() (type.hh:389): name "void", size 0,
    // coretype flag.
    let mut base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
    base.flags |= type_flags::CORETYPE;
    Datatype::Void(base)
}

fn main() {
    // ---- base-class fallback (type.cc:139-146) ----
    emit("base_named", &base_named());
    emit("base_unnamed", &base_unnamed(5));
    emit("base_unnamed_zero", &base_unnamed(0));
    emit("void_default", &void_default());
    emit("enum_named", &enum_dt("Col"));
    emit("enum_unnamed", &enum_dt(""));
    emit("struct_incomplete", &struct_incomplete());
    emit("union_incomplete", &union_incomplete());
    let spacebase_ram = {
        // Mirrors C++ TypeSpacebase(AddrSpace*, const Address&,
        // Architecture*) (type.hh:735-736): Datatype(0,1,TYPE_SPACEBASE),
        // name empty, spaceid = the ram space.
        let mut base = TypeBase::new(String::new(), 0, TypeMetatype::Spacebase);
        base.alignment = 1;
        base.align_size = 0;
        Datatype::Spacebase(TypeSpacebase {
            base,
            address: Address::new(0x1000),
            fd: None,
            spaceid: Some(AddressSpace::Ram),
            localframe: Address::new(0x1000),
            scope: None,
        })
    };
    emit("spacebase_ram", &spacebase_ram);
    // Mirrors C++ TypeSpacebase(Architecture*) (type.hh:733): spaceid
    // null.
    emit("spacebase_nospace", &Datatype::Spacebase(TypeSpacebase::new_global(Address::new(0x1000))));

    // ---- TypePointer::printRaw (type.cc:910-918) ----
    let myint = Arc::new(base_named());
    let unnamed5 = Arc::new(base_unnamed(5));
    let ptr_plain = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&myint), 1)));
    emit("ptr_plain", &ptr_plain);
    let ptr_to_unnamed = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&unnamed5), 1)));
    emit("ptr_to_unnamed", &ptr_to_unnamed);
    // Mirrors C++ TypePointer(Datatype*,AddrSpace*) (type.hh:415-418).
    let ptr_space_ram =
        Arc::new(Datatype::Pointer(TypePointer::new_with_space(Arc::clone(&myint), AddressSpace::Ram)));
    emit("ptr_space_ram", &ptr_space_ram);
    let ptr_space_stack = Arc::new(Datatype::Pointer(TypePointer::new_with_space(
        Arc::clone(&myint),
        AddressSpace::Stack,
    )));
    emit("ptr_space_stack", &ptr_space_stack);
    let ptr_chain = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&ptr_plain), 1)));
    emit("ptr_chain", &ptr_chain);
    let ptr_wordsize4 = Arc::new(Datatype::Pointer(TypePointer::new(4, Arc::clone(&myint), 4)));
    emit("ptr_wordsize4", &ptr_wordsize4);

    // ---- TypeArray::printRaw (type.cc:1204-1209) ----
    let array_int3 = Arc::new(array_of(Arc::clone(&myint), 3));
    emit("array_int3", &array_int3);
    let array_unnamed = Arc::new(array_of(Arc::new(base_unnamed(7)), 4));
    emit("array_unnamed", &array_unnamed);
    let array_of_ptr = Arc::new(array_of(Arc::clone(&ptr_plain), 3));
    emit("array_of_ptr", &array_of_ptr);
    let ptr_to_array = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&array_int3), 1)));
    emit("ptr_to_array", &ptr_to_array);
    let array_of_array = Arc::new(array_of(Arc::clone(&array_int3), 2));
    emit("array_of_array", &array_of_array);

    // ---- TypeCode::printRaw (type.cc:2772-2780) ----
    let code_anon = Arc::new(Datatype::Code(TypeCode::new()));
    emit("code_anon", &code_anon);
    // Mirror of the C++ twin's FixtureCode: the (private)
    // TypeFactory::getTypeCode(const string&) body (type.cc:3711-3719),
    // built directly here because the C++ side cannot call the private
    // factory either.
    let mut named = TypeCode::new();
    named.base.name = "mycode".to_string();
    named.base.display_name = "mycode".to_string();
    named.base.id = Datatype::hash_name("mycode");
    named.base.flags &= !type_flags::TYPE_INCOMPLETE; // markComplete (type.hh:202)
    let code_named = Arc::new(Datatype::Code(named));
    emit("code_named", &code_named);
    let ptr_to_code = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&code_anon), 1)));
    emit("ptr_to_code", &ptr_to_code);

    // ---- TypePartial*::printRaw (type.cc:2264/2356/2433) ----
    let strip = Arc::new(Datatype::Base(TypeBase::new(
        "undefined4".to_string(),
        4,
        TypeMetatype::Unknown,
    )));
    let partial_struct = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        Arc::clone(&array_int3),
        4,
        4,
        Some(Arc::clone(&strip)),
    )));
    emit("partial_struct", &partial_struct);
    let partial_struct_neg = Arc::new(Datatype::PartialStruct(TypePartialStruct::new(
        Arc::clone(&array_int3),
        -3,
        4,
        Some(Arc::clone(&strip)),
    )));
    emit("partial_struct_negoff", &partial_struct_neg);
    let partial_enum = Arc::new(Datatype::PartialEnum(TypePartialEnum::new(
        Arc::new(enum_dt("Col")),
        1,
        2,
        Some(Arc::clone(&strip)),
    )));
    emit("partial_enum", &partial_enum);
    let partial_union = Arc::new(Datatype::PartialUnion(TypePartialUnion::new(
        Arc::new(union_incomplete()),
        0,
        8,
        Some(Arc::clone(&strip)),
    )));
    emit("partial_union", &partial_union);

    // ---- TypePointerRel::printRaw (type.cc:2597-2606) ----
    let ptrrel_zero = Arc::new(Datatype::Pointer(TypePointer::new_relative(
        8,
        Arc::clone(&myint),
        1,
        Arc::clone(&array_int3),
        0,
    )));
    emit("ptrrel_zero", &ptrrel_zero);
    let ptrrel_off16 = Arc::new(Datatype::Pointer(TypePointer::new_relative(
        8,
        Arc::clone(&myint),
        1,
        Arc::clone(&array_int3),
        16,
    )));
    emit("ptrrel_off16", &ptrrel_off16);
    let ptrrel_neg = Arc::new(Datatype::Pointer(TypePointer::new_relative(
        8,
        Arc::clone(&myint),
        1,
        Arc::clone(&array_int3),
        -8,
    )));
    emit("ptrrel_neg", &ptrrel_neg);
    let ptr_to_ptrrel = Arc::new(Datatype::Pointer(TypePointer::new(8, Arc::clone(&ptrrel_zero), 1)));
    emit("ptr_to_ptrrel", &ptr_to_ptrrel);
}
