// VARNODE-LOCALTYPE-RESOLUTION-0001: current-Rudra comparand for the locked
// Ghidra Varnode::getLocalType (varnode.cc:900-936) oracle projection,
// including the def-side stop_type_propagation early return and the
// "NULL local type" LowlevelError channel.
//
// Every observation calls the production `Varnode::get_local_type` (the
// full port in src/varnode.rs) on the same bank-managed varnodes the C++
// fixture observes, with the same Architecture TypeFactory allocation.

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state the C++ fixture
/// observes (same bootstrap as tests/oracle/typeop_localbase_defaults_1204.rs):
/// `TypeFactory::raw()`, the x86-64-gcc.cspec `<size_alignment_map>`,
/// `setup_sizes` defaults for a 64-bit stack pointer, and the
/// `SleighArchitecture::buildCoreTypes` default core set.
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
/// cases can return (TypeBase, TypePointer, TypeUnion, TypeCode): type.cc:
/// 139-146 prints the name or `unkbyte<size>`, type.cc:910-916 appends
/// `" *"` for pointers, type.cc:2772-2780 appends `"()"` for code types
/// (name or `funcptr` when anonymous).
fn ghidra_print_raw(datatype: &Datatype) -> String {
    if let Datatype::Pointer(pointer) = datatype {
        return format!("{} *", ghidra_print_raw(&pointer.ptr_to));
    }
    let name = datatype.get_name().to_string();
    let base = if !name.is_empty() {
        name
    } else if datatype.get_metatype() == TypeMetatype::Code {
        // type.cc:2777-2778: anonymous code type prints "funcptr".
        "funcptr".to_string()
    } else {
        format!("unkbyte{}", datatype.get_size())
    };
    if datatype.get_metatype() == TypeMetatype::Code {
        format!("{base}()")
    } else {
        base
    }
}

/// One getLocalType observation: resolved type projection plus the blockup
/// out-parameter the caller initialized to false (coreaction.cc:5020).
fn emit_case(name: &str, ct: &Option<Arc<Datatype>>, blockup: bool) {
    match ct.as_ref() {
        Some(datatype) => {
            println!("case.{name}.result_type={}", ghidra_print_raw(datatype));
            println!(
                "case.{name}.result_meta={}",
                ghidra_metatype(datatype.get_metatype())
            );
            println!("case.{name}.result_size={}", datatype.get_size());
        }
        None => {
            println!("case.{name}.result_type=NULL");
            println!("case.{name}.result_meta=NULL");
            println!("case.{name}.result_size=NULL");
        }
    }
    emit_bool(&format!("case.{name}.blockup"), blockup);
}

fn identity(actual: &Option<Arc<Datatype>>, expected: &Arc<Datatype>) -> bool {
    actual.as_ref().is_some_and(|datatype| Arc::ptr_eq(datatype, expected))
}

/// Wire a two-input comparison reader op (INT_LESS / INT_SLESS) reading
/// `vn` at slot 0, in op_set_input call order = descend insertion order.
fn wire_compare_reader(
    fd: &mut Funcdata,
    opcode: OpCode,
    op_addr: u64,
    vn: &Arc<RwLock<rudra::varnode::Varnode>>,
    other_off: u64,
) {
    let other = fd.new_varnode(4, Address::new(other_off));
    let op = fd.new_op(2, Address::new(op_addr));
    fd.op_set_opcode(&op, opcode);
    fd.op_set_input(&op, vn.clone(), 0);
    fd.op_set_input(&op, other, 1);
}

/// Wire a CALL reader whose locked param-0 type is `param_type`, reading
/// `vn` at slot 1.
fn wire_call_reader(
    fd: &mut Funcdata,
    op_addr: u64,
    param_name: &str,
    param_type: Arc<Datatype>,
    void_type: Arc<Datatype>,
    vn: &Arc<RwLock<rudra::varnode::Varnode>>,
) {
    let op = fd.new_op(2, Address::new(op_addr));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let mut prototype = FuncProto::new(
        "varnode_localtype_res_fixture".to_string(),
        void_type.clone(),
    );
    let mut param = ProtoParameter::new(
        param_name.to_string(),
        param_type.clone(),
        Address::new(0x00),
    );
    param.flags |= protoparam_flags::TYPE_LOCKED;
    prototype.add_parameter(param);
    let target = fd.new_code_ref(Address::new(op_addr + 0x100000));
    fd.op_set_input(&op, target, 0);
    let callspec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
    let callspec_owner = fd
        .get_call_specs_owner(callspec_index)
        .expect("fixture callspec owner");
    let fspec = fd.new_varnode_call_specs(&callspec_owner);
    fd.op_set_input(&op, fspec, 0);
    fd.op_set_input(&op, vn.clone(), 1);
}

/// Wire a CALL def whose callspec output is typelocked to `output_type`
/// (Ghidra `FuncCallSpecs::setOutput` with `ParameterPieces::typelock`),
/// producing `out` — the def-side seed path through
/// `TypeOpCall::getOutputLocal` (typeop.cc:732-735). Returns the callspec
/// owner so cases can observe `isOutputLocked`.
fn wire_call_def(
    fd: &mut Funcdata,
    op_addr: u64,
    output_name: &str,
    output_type: Arc<Datatype>,
    out: &Arc<RwLock<rudra::varnode::Varnode>>,
) -> Arc<RwLock<rudra::fspec::FuncCallSpecs>> {
    let op = fd.new_op(1, Address::new(op_addr));
    fd.op_set_opcode(&op, OpCode::CPUI_CALL);
    let mut prototype = FuncProto::new(output_name.to_string(), output_type.clone());
    prototype.set_output_lock(true);
    let target = fd.new_code_ref(Address::new(op_addr + 0x100000));
    fd.op_set_input(&op, target, 0);
    let callspec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
    let callspec_owner = fd
        .get_call_specs_owner(callspec_index)
        .expect("fixture callspec owner");
    let fspec = fd.new_varnode_call_specs(&callspec_owner);
    fd.op_set_input(&op, fspec, 0);
    fd.op_set_output(&op, out.clone());
    callspec_owner
}

fn main() {
    let mut factory = configure_factory();

    let void_type = factory.get_type_void();
    let char_type = factory
        .get_type_char_named("char")
        .expect("canonical char type");
    let char_pointer = factory.get_type_pointer(8, char_type, 1);
    let int4_type = factory.get_base(4, TypeMetatype::Int).expect("int4");
    let int8_base = factory.get_base(8, TypeMetatype::Int).expect("int8");
    let int_pointer = factory.get_type_pointer(8, int4_type.clone(), 1);
    let struct_a = factory.create_struct("structA");
    let struct_b = factory.create_struct("structB");
    let union_type = factory.get_type_union("unionU");

    let type_factory = Arc::new(RwLock::new(factory));
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());

    let mut fd = Funcdata::new("varnode_localtype_res_fixture", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(type_factory.clone());

    println!("fixture=VARNODE-LOCALTYPE-RESOLUTION-0001");
    println!("architecture={}", architecture.archid);

    // ---- def_only: PTRSUB output, no readers ----
    {
        let in0 = fd.new_varnode(8, Address::new(0x100));
        let offset = fd.new_constant(4, 0x10);
        let out = fd.new_varnode(4, Address::new(0x300));
        let op = fd.new_op(2, Address::new(0x500100));
        fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&op, in0, 0);
        fd.op_set_input(&op, offset, 1);
        fd.op_set_output(&op, out.clone());
        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("def_only resolves");
        emit_case("def_only", &ct, blockup);
        emit_bool("case.def_only.int4_identity", identity(&ct, &int4_type));
        let mut repeat_blockup = false;
        let repeat = out
            .read()
            .unwrap()
            .get_local_type(&mut repeat_blockup, &type_factory, None)
            .expect("def_only repeat resolves");
        emit_bool(
            "case.def_only.repeat_identity",
            match (ct.as_ref(), repeat.as_ref()) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            },
        );
    }

    // ---- def_stop: PTRSUB def with stop_type_propagation (op.hh:216) +
    // INT_LESS reader that must never be consulted. ----
    {
        let in0 = fd.new_varnode(8, Address::new(0x110));
        let offset = fd.new_constant(4, 0x10);
        let out = fd.new_varnode(4, Address::new(0x310));
        let op = fd.new_op(2, Address::new(0x500110));
        fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&op, in0, 0);
        fd.op_set_input(&op, offset, 1);
        fd.op_set_output(&op, out.clone());
        op.0.write().unwrap().addlflags |=
            rudra::op::op_addl_flags::STOP_TYPE_PROPAGATION;
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_LESS, 0x500118, &out, 0x311);

        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("def_stop resolves");
        emit_case("def_stop", &ct, blockup);
        emit_bool(
            "case.def_stop.stops_flag",
            op.0.read().unwrap().stops_type_propagation(),
        );
        emit_bool("case.def_stop.int4_identity", identity(&ct, &int4_type));
        let uint4 = type_factory
            .read()
            .unwrap()
            .get_base(4, TypeMetatype::Uint)
            .expect("uint4");
        emit_bool(
            "case.def_stop.uint_not_consulted",
            !identity(&ct, &uint4),
        );
    }

    // ---- def_nostop: identical graph without STOP -> uint4 wins the merge.
    // ----
    {
        let in0 = fd.new_varnode(8, Address::new(0x120));
        let offset = fd.new_constant(4, 0x10);
        let out = fd.new_varnode(4, Address::new(0x320));
        let op = fd.new_op(2, Address::new(0x500120));
        fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&op, in0, 0);
        fd.op_set_input(&op, offset, 1);
        fd.op_set_output(&op, out.clone());
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_LESS, 0x500128, &out, 0x321);

        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("def_nostop resolves");
        emit_case("def_nostop", &ct, blockup);
        let uint4 = type_factory
            .read()
            .unwrap()
            .get_base(4, TypeMetatype::Uint)
            .expect("uint4");
        emit_bool("case.def_nostop.uint_identity", identity(&ct, &uint4));
    }

    // ---- readers_min: INT_LESS then INT_SLESS. ----
    {
        let vn = fd.new_varnode(4, Address::new(0x330));
        let vn = fd.set_input_varnode(vn);
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_LESS, 0x500130, &vn, 0x331);
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_SLESS, 0x500138, &vn, 0x332);
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("readers_min_uint_first resolves");
        emit_case("readers_min_uint_first", &ct, blockup);
        let uint4 = type_factory
            .read()
            .unwrap()
            .get_base(4, TypeMetatype::Uint)
            .expect("uint4");
        emit_bool("case.readers_min_uint_first.uint_identity", identity(&ct, &uint4));
    }
    // ---- readers_min reversed insertion: INT_SLESS then INT_LESS. ----
    {
        let vn = fd.new_varnode(4, Address::new(0x340));
        let vn = fd.set_input_varnode(vn);
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_SLESS, 0x500140, &vn, 0x341);
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_LESS, 0x500148, &vn, 0x342);
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("readers_min_int_first resolves");
        emit_case("readers_min_int_first", &ct, blockup);
        let uint4 = type_factory
            .read()
            .unwrap()
            .get_base(4, TypeMetatype::Uint)
            .expect("uint4");
        emit_bool("case.readers_min_int_first.uint_identity", identity(&ct, &uint4));
    }

    // ---- ptr_pointee_replace: CALL(char*) then CALL(int4*) — the pointee
    // descent of TypePointer::compare (type.cc:951) makes int4* strictly
    // smaller than char*, so it replaces the first-seen char*. ----
    {
        let vn = fd.new_varnode(8, Address::new(0x350));
        let vn = fd.set_input_varnode(vn);
        wire_call_reader(
            &mut fd,
            0x500150,
            "locked_charptr",
            char_pointer.clone(),
            void_type.clone(),
            &vn,
        );
        wire_call_reader(
            &mut fd,
            0x500158,
            "locked_intptr",
            int_pointer.clone(),
            void_type.clone(),
            &vn,
        );
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("ptr_pointee_replace resolves");
        emit_case("ptr_pointee_replace", &ct, blockup);
        emit_bool(
            "case.ptr_pointee_replace.intptr_identity",
            identity(&ct, &int_pointer),
        );
        emit_bool(
            "case.ptr_pointee_replace.charptr_replaced",
            !identity(&ct, &char_pointer),
        );
        // int4* is strictly smaller than char* (pointee descent, type.cc:951).
        emit_bool(
            "case.ptr_pointee_replace.pointee_descent",
            char_pointer.type_order(&int_pointer) > 0,
        );
    }
    // ---- tie_structs_ab: CALL(structA) then CALL(structB) — two distinct
    // empty structures compare 0 (type.cc:1742-1780): a genuine tie, the
    // first-encountered struct survives. ----
    {
        let vn = fd.new_varnode(8, Address::new(0x360));
        let vn = fd.set_input_varnode(vn);
        wire_call_reader(
            &mut fd,
            0x500160,
            "locked_structa",
            struct_a.clone(),
            void_type.clone(),
            &vn,
        );
        wire_call_reader(
            &mut fd,
            0x500168,
            "locked_structb",
            struct_b.clone(),
            void_type.clone(),
            &vn,
        );
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("tie_structs_ab resolves");
        emit_case("tie_structs_ab", &ct, blockup);
        emit_bool(
            "case.tie_structs_ab.structa_identity",
            identity(&ct, &struct_a),
        );
        emit_bool(
            "case.tie_structs_ab.tie_typeorder",
            struct_a.type_order(&struct_b) == 0,
        );
    }
    // ---- tie_structs_ba: CALL(structB) then CALL(structA). ----
    {
        let vn = fd.new_varnode(8, Address::new(0x368));
        let vn = fd.set_input_varnode(vn);
        wire_call_reader(
            &mut fd,
            0x500190,
            "locked_structb",
            struct_b.clone(),
            void_type.clone(),
            &vn,
        );
        wire_call_reader(
            &mut fd,
            0x500198,
            "locked_structa",
            struct_a.clone(),
            void_type.clone(),
            &vn,
        );
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("tie_structs_ba resolves");
        emit_case("tie_structs_ba", &ct, blockup);
        emit_bool(
            "case.tie_structs_ba.structb_identity",
            identity(&ct, &struct_b),
        );
    }

    // ---- tie_def_reader_ab / tie_def_reader_ba: the def is a CALL whose
    // callspec output is typelocked to one empty struct (the TypeOpCall::
    // getOutputLocal seed, typeop.cc:732-735); the sole reader is a CALL
    // locked to the OTHER empty struct. The def seed (cc:911) and the reader
    // candidate (cc:924) have typeOrder 0; cc:926-927 seeds ct from the def
    // FIRST and cc:929-930 replaces only on strictly smaller, so the DEF
    // seed survives the tie in both orderings — the def-output-first
    // competition structure (R19 D2 review advice 1 coverage).
    // ----
    {
        let out = fd.new_varnode(8, Address::new(0x3A0));
        let def_spec =
            wire_call_def(&mut fd, 0x5001A0, "locked_out_structa", struct_a.clone(), &out);
        wire_call_reader(
            &mut fd,
            0x5001A8,
            "locked_structb",
            struct_b.clone(),
            void_type.clone(),
            &out,
        );
        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("tie_def_reader_ab resolves");
        emit_case("tie_def_reader_ab", &ct, blockup);
        emit_bool(
            "case.tie_def_reader_ab.def_structa_identity",
            identity(&ct, &struct_a),
        );
        emit_bool(
            "case.tie_def_reader_ab.reader_structb_not_winner",
            !identity(&ct, &struct_b),
        );
        emit_bool(
            "case.tie_def_reader_ab.def_output_locked",
            def_spec.read().unwrap().is_output_locked(),
        );
    }
    {
        let out = fd.new_varnode(8, Address::new(0x3B0));
        wire_call_def(&mut fd, 0x5001B0, "locked_out_structb", struct_b.clone(), &out);
        wire_call_reader(
            &mut fd,
            0x5001B8,
            "locked_structa",
            struct_a.clone(),
            void_type.clone(),
            &out,
        );
        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("tie_def_reader_ba resolves");
        emit_case("tie_def_reader_ba", &ct, blockup);
        emit_bool(
            "case.tie_def_reader_ba.def_structb_identity",
            identity(&ct, &struct_b),
        );
        emit_bool(
            "case.tie_def_reader_ba.reader_structa_not_winner",
            !identity(&ct, &struct_a),
        );
        emit_bool(
            "case.tie_def_reader_ba.tie_typeorder",
            struct_a.type_order(&struct_b) == 0,
        );
    }

    // ---- callind_slot0: input varnode read by a CALLIND at slot 0 — the
    // delegated TypeOpCallind::getInputLocal branch (typeop.cc:752-756): a
    // pointer to the code type, sized by the input and worded by the op's
    // own (code) space. The legacy spaceless op address has no wordsize, so
    // the branch's hardwired-1 fallback applies (x86-64 code spaces are
    // wordsize 1 on the oracle side). ----
    {
        let vn = fd.new_varnode(8, Address::new(0x3C0));
        let vn = fd.set_input_varnode(vn);
        let op = fd.new_op(1, Address::new(0x5001C0));
        fd.op_set_opcode(&op, OpCode::CPUI_CALLIND);
        fd.op_set_input(&op, vn.clone(), 0);
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("callind_slot0 resolves");
        emit_case("callind_slot0", &ct, blockup);
        let code_pointer = {
            let mut factory = type_factory.write().unwrap();
            let code_type = factory.get_type_code();
            factory.get_type_pointer(8, code_type, 1)
        };
        emit_bool(
            "case.callind_slot0.codeptr_identity",
            identity(&ct, &code_pointer),
        );
    }

    // ---- path_beats_int: CALL(char*) vs INT_SLESS(int8). ----
    {
        let vn = fd.new_varnode(8, Address::new(0x370));
        let vn = fd.set_input_varnode(vn);
        wire_call_reader(
            &mut fd,
            0x500170,
            "locked_charptr",
            char_pointer.clone(),
            void_type.clone(),
            &vn,
        );
        // 8-byte INT_SLESS reader: other operand 8 bytes.
        let other = fd.new_varnode(8, Address::new(0x371));
        let op = fd.new_op(2, Address::new(0x500178));
        fd.op_set_opcode(&op, OpCode::CPUI_INT_SLESS);
        fd.op_set_input(&op, vn.clone(), 0);
        fd.op_set_input(&op, other, 1);
        let mut blockup = false;
        let ct = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("path_beats_int resolves");
        emit_case("path_beats_int", &ct, blockup);
        emit_bool(
            "case.path_beats_int.charptr_identity",
            identity(&ct, &char_pointer),
        );
        emit_bool(
            "case.path_beats_int.int8_not_winner",
            !identity(&ct, &int8_base),
        );
    }

    // ---- typelock_union: locked union returned directly. ----
    {
        let in0 = fd.new_varnode(8, Address::new(0x180));
        let offset = fd.new_constant(4, 0x10);
        let out = fd.new_varnode(4, Address::new(0x380));
        let op = fd.new_op(2, Address::new(0x500180));
        fd.op_set_opcode(&op, OpCode::CPUI_PTRSUB);
        fd.op_set_input(&op, in0, 0);
        fd.op_set_input(&op, offset, 1);
        fd.op_set_output(&op, out.clone());
        out.write()
            .unwrap()
            .update_type_lock(union_type.clone(), true, false);
        wire_compare_reader(&mut fd, OpCode::CPUI_INT_LESS, 0x500188, &out, 0x381);
        let mut blockup = false;
        let ct = out.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        let ct = ct.expect("typelock_union resolves");
        emit_case("typelock_union", &ct, blockup);
        emit_bool(
            "case.typelock_union.identity",
            identity(&ct, &union_type),
        );
        emit_bool(
            "case.typelock_union.is_locked",
            out.read().unwrap().is_type_lock(),
        );
    }

    // ---- null_local_type: no def, no readers -> Err("NULL local type"). ---
    {
        let vn = fd.new_varnode(4, Address::new(0x390));
        let mut blockup = false;
        let result = vn.read().unwrap().get_local_type(&mut blockup, &type_factory, None);
        match result {
            Ok(ct) => emit_case("null_local_type", &ct, blockup),
            Err(error) => {
                println!("case.null_local_type.error={error}");
                emit_bool("case.null_local_type.blockup", blockup);
            }
        }
    }
}
