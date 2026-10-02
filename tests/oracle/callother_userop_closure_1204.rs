// TYPEOP-CALLOTHER-USEROP-CLOSURE-0001: current-Rudra comparand for the
// locked Ghidra 12.0.4 PcodeOp -> TypeOpCallother -> UserOpManage caller
// closure oracle (typeop.cc:855-873), including the TypeOp base canonical
// TYPE_UNKNOWN fallback for metadata-less descriptors and DatatypeUserOp's
// slot-minus-one input mapping (userop.cc:76-83).
//
// Every observation calls the production `Varnode::get_local_type` /
// `op_output_type_local` / `op_input_type_local` entry points (src/varnode.rs)
// on the same Funcdata-built ops the C++ fixture observes, threading the
// Architecture-owned `UserOpManage` handle through the new `userops`
// parameter (Ghidra's `tlst->getArch()->userops` edge).

use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::funcdata::Funcdata;
use rudra::marshal::{Element, IdRegistry, TreeDecoder};
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{SizeArchInputs, TypeFactory};
use rudra::userop::{UserOpManage, UserOpType, BUILTIN_MEMCPY};

fn element(name: &str, attributes: &[(&str, &str)]) -> Arc<RwLock<Element>> {
    let mut element = Element::new();
    element.set_name(name);
    for (key, value) in attributes {
        element.add_attribute(key, value);
    }
    Arc::new(RwLock::new(element))
}

/// Mirror of the locked BfdArchitecture TypeFactory state the C++ fixture
/// observes (same bootstrap as tests/oracle/varnode_localtype_res_1204.rs):
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
/// cases can return (TypeBase, TypePointer): type.cc:139-146 prints the name
/// or `unkbyte<size>`, type.cc:910-916 appends `" *"` for pointers.
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

/// One closure observation: resolved type projection plus the blockup
/// out-parameter as getLocalType callers initialize it (false,
/// coreaction.cc:5020). Direct op_output_type_local/op_input_type_local
/// observations pass false because the TypeOp query cannot touch blockup.
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

fn main() {
    let mut factory = configure_factory();

    let void_type = factory.get_type_void();
    let void_pointer = factory.get_type_pointer(8, void_type.clone(), 1);
    let int4_type = factory.get_base(4, TypeMetatype::Int).expect("int4");
    let unknown4 = factory.get_base(4, TypeMetatype::Unknown).expect("xunknown4");
    let unknown2 = factory.get_base(2, TypeMetatype::Unknown).expect("xunknown2");
    let unknown1 = factory.get_base(1, TypeMetatype::Unknown).expect("xunknown1");

    let type_factory = Arc::new(RwLock::new(factory));

    // Production registration paths into one Architecture-owned manager:
    // register_builtin_with_local_types mirrors registerBuiltin(BUILTIN_MEMCPY)
    // (userop.cc:449-457: out=void*, in0..1=void*, in2=int4) with canonical
    // factory Arcs; register_op mirrors the UnspecializedPcodeOp
    // registration whose base virtuals return no metadata (userop.hh:101/108).
    let mut userops = UserOpManage::new();
    userops
        .register_builtin_with_local_types(
            BUILTIN_MEMCPY,
            Some(void_pointer.clone()),
            vec![
                Some(void_pointer.clone()),
                Some(void_pointer.clone()),
                Some(int4_type.clone()),
            ],
        )
        .unwrap_or_else(|message| panic!("builtin_memcpy registration: {message}"));
    let metadataless_index = userops.register_op(
        "metadataless".to_string(),
        UserOpType::Unspecialized,
    );
    let userops_arc = Arc::new(RwLock::new(userops));

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());
    architecture.set_userops(userops_arc.clone());

    let mut fd = Funcdata::new("callother_userop_closure_fixture", Address::new(0x500000), 0x100);
    fd.vbank.set_type_factory(type_factory.clone());

    println!("fixture=TYPEOP-CALLOTHER-USEROP-CLOSURE-0001");
    println!("architecture={}", architecture.archid);

    {
        let manager = userops_arc.read().unwrap();
        let memcpy_descriptor = manager
            .get_op(BUILTIN_MEMCPY as i32)
            .expect("builtin_memcpy descriptor");
        println!("memcpy.type={}", memcpy_descriptor.get_type() as i32);
        emit_bool(
            "memcpy.manager_same",
            std::ptr::eq(
                manager.get_op(BUILTIN_MEMCPY as i32).map(std::ptr::from_ref).unwrap_or(std::ptr::null()),
                std::ptr::from_ref(memcpy_descriptor),
            ),
        );
        emit_bool(
            "memcpy.out_identity",
            memcpy_descriptor
                .get_output_local()
                .is_some_and(|ct| Arc::ptr_eq(ct, &void_pointer)),
        );

        let metadataless = manager
            .get_op(metadataless_index)
            .expect("metadataless descriptor");
        println!("metadataless.type={}", metadataless.get_type() as i32);
        emit_bool(
            "metadataless.manager_same",
            std::ptr::eq(
                manager.get_op(metadataless_index).map(std::ptr::from_ref).unwrap_or(std::ptr::null()),
                std::ptr::from_ref(metadataless),
            ),
        );
    }

    let userops_thread = Some(&userops_arc);

    // ---- memcpy closure: 5-input CALLOTHER (slot 0 = BUILTIN_MEMCPY index
    // constant; slots 1/2 = 8-byte operands; slot 3 = 4-byte size; slot 4 =
    // 1-byte extra operand so the past-the-end fallback has a real varnode).
    // ----
    let memcpy_op = fd.new_op(5, Address::new(0x500100));
    fd.op_set_opcode(&memcpy_op, OpCode::CPUI_CALLOTHER);
    let memcpy_index = fd.new_constant(4, BUILTIN_MEMCPY as u64);
    fd.op_set_input(&memcpy_op, memcpy_index, 0);
    let reader_source = fd.new_varnode(8, Address::new(0x110));
    let reader_vn = fd.set_input_varnode(reader_source);
    fd.op_set_input(&memcpy_op, reader_vn.clone(), 1);
    let memcpy_in2 = fd.new_varnode(8, Address::new(0x111));
    fd.op_set_input(&memcpy_op, memcpy_in2, 2);
    let memcpy_in3 = fd.new_varnode(4, Address::new(0x112));
    fd.op_set_input(&memcpy_op, memcpy_in3, 3);
    let memcpy_in4 = fd.new_varnode(1, Address::new(0x113));
    fd.op_set_input(&memcpy_op, memcpy_in4, 4);
    let memcpy_out = fd.new_varnode(8, Address::new(0x300));
    fd.op_set_output(&memcpy_op, memcpy_out.clone());

    // Def side through the production caller: get_local_type seeds from the
    // def op's outputTypeLocal (varnode.cc:910-911) -> TypeOpCallother::
    // getOutputLocal (typeop.cc:865-873) -> DatatypeUserOp::getOutputLocal
    // (userop.cc:70-74) -> the registered void*.
    {
        let mut blockup = false;
        let ct = memcpy_out
            .read()
            .unwrap()
            .get_local_type(&mut blockup, &type_factory, userops_thread)
            .expect("memcpy_def resolves");
        emit_case("memcpy_def", &ct, blockup);
        emit_bool("case.memcpy_def.voidptr_identity", identity(&ct, &void_pointer));
    }
    // Direct PcodeOp::outputTypeLocal (op.hh:251) on the same op.
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_output_type_local(&op, &type_factory, userops_thread)
        };
        emit_case("memcpy_out_direct", &ct, false);
        emit_bool(
            "case.memcpy_out_direct.voidptr_identity",
            identity(&ct, &void_pointer),
        );
    }
    // Slot 0 (the CALLOTHER index constant): slot-1 = -1 -> no metadata
    // (userop.cc:79-82) -> TypeOp base default getBase(4,TYPE_UNKNOWN)
    // (typeop.cc:271-275).
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 0, &type_factory, userops_thread)
        };
        emit_case("memcpy_in0", &ct, false);
        emit_bool("case.memcpy_in0.unknown4_identity", identity(&ct, &unknown4));
    }
    // Slots 1..3: the registered void*/void*/int4 metadata.
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 1, &type_factory, userops_thread)
        };
        emit_case("memcpy_in1", &ct, false);
        emit_bool("case.memcpy_in1.voidptr_identity", identity(&ct, &void_pointer));
    }
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 2, &type_factory, userops_thread)
        };
        emit_case("memcpy_in2", &ct, false);
        emit_bool("case.memcpy_in2.voidptr_identity", identity(&ct, &void_pointer));
    }
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 3, &type_factory, userops_thread)
        };
        emit_case("memcpy_in3", &ct, false);
        emit_bool("case.memcpy_in3.int4_identity", identity(&ct, &int4_type));
    }
    // Slot 4 is past the fixed inputs: slot-1 = 3 >= inTypes.len() = 3 ->
    // no metadata -> base default over the 1-byte slot-4 varnode.
    {
        let ct = {
            let op = memcpy_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 4, &type_factory, userops_thread)
        };
        emit_case("memcpy_in4", &ct, false);
        emit_bool("case.memcpy_in4.unknown1_identity", identity(&ct, &unknown1));
    }
    // Reader side through the production caller: the slot-1 operand varnode
    // has no def; get_local_type walks its single descendant (varnode.cc:
    // 918-932) -> inputTypeLocal(1) -> the registered void*.
    {
        let mut blockup = false;
        let ct = reader_vn
            .read()
            .unwrap()
            .get_local_type(&mut blockup, &type_factory, userops_thread)
            .expect("memcpy_reader resolves");
        emit_case("memcpy_reader", &ct, blockup);
        emit_bool(
            "case.memcpy_reader.voidptr_identity",
            identity(&ct, &void_pointer),
        );
    }

    // ---- metadataless closure: 2-input CALLOTHER whose slot-0 constant
    // picks the UnspecializedPcodeOp. Every query takes the TypeOp base
    // default.
    // ----
    let plain_op = fd.new_op(2, Address::new(0x500200));
    fd.op_set_opcode(&plain_op, OpCode::CPUI_CALLOTHER);
    let plain_index = fd.new_constant(4, metadataless_index as u64);
    fd.op_set_input(&plain_op, plain_index, 0);
    let plain_reader_source = fd.new_varnode(4, Address::new(0x120));
    let plain_reader_vn = fd.set_input_varnode(plain_reader_source);
    fd.op_set_input(&plain_op, plain_reader_vn.clone(), 1);
    let plain_out = fd.new_varnode(2, Address::new(0x310));
    fd.op_set_output(&plain_op, plain_out.clone());

    {
        let mut blockup = false;
        let ct = plain_out
            .read()
            .unwrap()
            .get_local_type(&mut blockup, &type_factory, userops_thread)
            .expect("metadataless_def resolves");
        emit_case("metadataless_def", &ct, blockup);
        emit_bool(
            "case.metadataless_def.unknown2_identity",
            identity(&ct, &unknown2),
        );
    }
    {
        let ct = {
            let op = plain_op.0.read().unwrap();
            rudra::varnode::op_output_type_local(&op, &type_factory, userops_thread)
        };
        emit_case("metadataless_out_direct", &ct, false);
        emit_bool(
            "case.metadataless_out_direct.unknown2_identity",
            identity(&ct, &unknown2),
        );
    }
    {
        let ct = {
            let op = plain_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 0, &type_factory, userops_thread)
        };
        emit_case("metadataless_in0", &ct, false);
        emit_bool(
            "case.metadataless_in0.unknown4_identity",
            identity(&ct, &unknown4),
        );
    }
    {
        let ct = {
            let op = plain_op.0.read().unwrap();
            rudra::varnode::op_input_type_local(&op, 1, &type_factory, userops_thread)
        };
        emit_case("metadataless_in1", &ct, false);
        emit_bool(
            "case.metadataless_in1.unknown4_identity",
            identity(&ct, &unknown4),
        );
    }
    {
        let mut blockup = false;
        let ct = plain_reader_vn
            .read()
            .unwrap()
            .get_local_type(&mut blockup, &type_factory, userops_thread)
            .expect("metadataless_reader resolves");
        emit_case("metadataless_reader", &ct, blockup);
        emit_bool(
            "case.metadataless_reader.unknown4_identity",
            identity(&ct, &unknown4),
        );
    }
}
