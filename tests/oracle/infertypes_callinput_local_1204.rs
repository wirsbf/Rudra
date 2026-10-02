// INFERTYPES-CALLINPUT-LOCAL-0001 (TYPEOP-LOCALTYPE-DISPATCH-0001 D2):
// current-Rudra comparand for the locked Ghidra CALL/CALLIND input
// local-type seeding oracle (ActionInferTypes::buildLocaltypes via the
// TypeOp local dispatch). Case matrix mirrors
// tests/oracle/infertypes_callinput_local_1204.cc byte for byte.

use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::coreaction::ActionInferTypes;
use rudra::fspec::{protoparam_flags, FuncCallSpecs, FuncProto, ProtoParameter};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};
use rudra::type_system::datatype::{Datatype, TypeMetatype};
use rudra::type_system::typefactory::{CoreTypeFlavor, SizeArchInputs, TypeFactory};
use rudra::typeop::{TypeOp, TypeOpCall, TypeOpCallind};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

/// Ghidra metatype2string spellings (type.cc:238-310). The Rust Debug
/// spelling of TypeMetatype::Pointer is "pointer", Ghidra prints "ptr", so
/// the fixture emits the locked oracle spellings directly.
fn element(
    name: &str,
    attributes: &[(&str, &str)],
) -> Arc<RwLock<rudra::marshal::Element>> {
    let mut node = rudra::marshal::Element::new();
    node.set_name(name);
    for (key, value) in attributes {
        node.add_attribute(key, value);
    }
    Arc::new(RwLock::new(node))
}

fn ghidra_meta_name(metatype: TypeMetatype) -> &'static str {
    match metatype {
        TypeMetatype::PartialUnion => "partunion",
        TypeMetatype::PartialStruct => "partstruct",
        TypeMetatype::PartialEnum => "partenum",
        TypeMetatype::Union => "union",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Enum => "enum_int",
        TypeMetatype::Array => "array",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Float => "float",
        TypeMetatype::Code => "code",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Int => "int",
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Spacebase => "spacebase",
        TypeMetatype::Void => "void",
    }
}

fn type_token(datatype: &Option<Arc<Datatype>>) -> String {
    match datatype {
        None => "null".to_string(),
        Some(datatype) => format!(
            "{}{}",
            ghidra_meta_name(datatype.get_metatype()),
            datatype.get_size()
        ),
    }
}

struct Observed {
    label: &'static str,
    vn: VarnodeRef,
}

struct CallResult {
    op: PcodeOpRef,
    spec_index: usize,
    arg: VarnodeRef,
}

fn type_snapshot(cells: &[Observed]) -> String {
    cells
        .iter()
        .map(|cell| {
            format!("{}:{}", cell.label, type_token(&cell.vn.read().unwrap().v_type))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn snapshot_types(cells: &[Observed]) -> Vec<Option<Arc<Datatype>>> {
    cells
        .iter()
        .map(|cell| cell.vn.read().unwrap().v_type.clone())
        .collect()
}

fn same_before(cells: &[Observed], before: &[Option<Arc<Datatype>>]) -> String {
    cells
        .iter()
        .zip(before.iter())
        .map(|(cell, before)| {
            let current = cell.vn.read().unwrap().v_type.clone();
            let same = match (&current, before) {
                (Some(current), Some(before)) => Arc::ptr_eq(current, before),
                (None, None) => true,
                _ => false,
            };
            format!("{}:{}", cell.label, u8::from(same))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn types_stable(cells: &[Observed], first: &[Option<Arc<Datatype>>]) -> bool {
    cells.iter().zip(first.iter()).all(|(cell, first)| {
        let current = cell.vn.read().unwrap().v_type.clone();
        match (&current, first) {
            (Some(current), Some(first)) => Arc::ptr_eq(current, first),
            (None, None) => true,
            _ => false,
        }
    })
}

fn op_label<'a>(labels: &'a [(PcodeOpRef, &'a str)], op: &PcodeOpRef) -> &'a str {
    labels
        .iter()
        .find(|(labelled, _)| Arc::ptr_eq(&labelled.0, &op.0))
        .map(|(_, label)| *label)
        .unwrap_or("?")
}

fn descendant_order(labels: &[(PcodeOpRef, &str)], source: &VarnodeRef) -> String {
    source
        .read()
        .unwrap()
        .descend_iter()
        .map(|op| op_label(labels, &PcodeOpRef(op)))
        .collect::<Vec<_>>()
        .join(",")
}

fn block_order(labels: &[(PcodeOpRef, &str)], block: &Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>) -> String {
    block
        .read()
        .unwrap()
        .get_ops()
        .iter()
        .map(|op| op_label(labels, op))
        .collect::<Vec<_>>()
        .join(",")
}

fn def_token(vn: &VarnodeRef) -> &'static str {
    match vn.read().unwrap().get_def() {
        Some(_) => "def",
        None => "input",
    }
}

fn callspecs_resolve(fd: &Funcdata, sites: &[(PcodeOpRef, usize)]) -> bool {
    sites.iter().all(|(op, index)| {
        fd.get_call_specs_of_op(op)
            .is_some_and(|actual| match fd.get_call_specs_owner(*index) {
                Some(owner) => Arc::ptr_eq(&actual, &owner),
                None => false,
            })
    })
}

struct Probe {
    token: String,
    identity: bool,
}

fn probe_call_input(
    type_factory: &Arc<RwLock<TypeFactory>>,
    op: &PcodeOpRef,
    slot: usize,
    expected: &Arc<Datatype>,
) -> Probe {
    let typeop = TypeOpCall::new(type_factory.clone());
    let guard = op.0.read().unwrap();
    let actual = typeop.get_input_local(&guard, slot);
    drop(guard);
    probe_project(actual, expected)
}

fn probe_callind_input(
    type_factory: &Arc<RwLock<TypeFactory>>,
    op: &PcodeOpRef,
    slot: usize,
    fd: &Funcdata,
    expected: &Arc<Datatype>,
) -> Probe {
    let typeop = TypeOpCallind::new(type_factory.clone());
    let actual = typeop.get_input_local_in_fd(op, slot, fd);
    probe_project(actual, expected)
}

fn probe_project(actual: Option<Arc<Datatype>>, expected: &Arc<Datatype>) -> Probe {
    match actual {
        Some(datatype) => Probe {
            token: type_token(&Some(datatype.clone())),
            identity: Arc::ptr_eq(&datatype, expected),
        },
        None => Probe {
            token: "null".to_string(),
            identity: false,
        },
    }
}

fn locked_parameter(name: &str, data_type: Arc<Datatype>, flags: u32) -> ProtoParameter {
    let mut parameter = ProtoParameter::new(name.to_string(), data_type, Address::new(0x0));
    parameter.flags |= flags;
    parameter
}

fn ram_address_space() -> AddrSpace {
    AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    )
}

fn main() {
    println!(
        "schema=1|fixture=INFERTYPES-CALLINPUT-LOCAL-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let (void_type, int4_type, int8_type, uint8_type, unknown4_type, object_pointer, code_pointer) = {
        let mut factory = type_factory.write().unwrap();
        // Mirror of the oracle's `types->decodeDataOrganization(...)` with the
        // x86-64-gcc <size_alignment_map> (entries 1,2,4,8,16; index 0 stays
        // -1). The setupSizes default map's alignMap[0]=0 divides by zero on
        // the first size-0 structure canonicalization, so both sides install
        // the decoded map instead (same recipe as the pinned D1 fixture).
        let alignment_map = element("size_alignment_map", &[]);
        for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8"), ("16", "16")] {
            alignment_map
                .write()
                .unwrap()
                .add_child(element("entry", &[("size", size), ("alignment", alignment)]));
        }
        let organization = element("data_organization", &[]);
        organization.write().unwrap().add_child(alignment_map);
        let registry = Arc::new(RwLock::new(rudra::marshal::IdRegistry::new()));
        let mut organization_decoder = rudra::marshal::TreeDecoder::new(organization, registry);
        factory.decode_data_organization(&mut organization_decoder);
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let void_type = factory.get_type_void();
        let int4_type = factory.get_base(4, TypeMetatype::Int).expect("int4");
        let int8_type = factory.get_base(8, TypeMetatype::Int).expect("int8");
        let uint8_type = factory.get_base(8, TypeMetatype::Uint).expect("uint8");
        let unknown4_type = factory.get_base(4, TypeMetatype::Unknown).expect("unknown4");
        let object_type = factory.create_struct("FixtureObject");
        let object_pointer = factory.get_type_pointer(8, object_type, 1);
        let code_type = factory.get_type_code();
        let code_pointer = factory.get_type_pointer(8, code_type, 1);
        (
            void_type,
            int4_type,
            int8_type,
            uint8_type,
            unknown4_type,
            object_pointer,
            code_pointer,
        )
    };

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());
    let mut fd = Funcdata::new("callinput_fixture", Address::new(0x5000), 0x40);
    fd.vbank.set_type_factory(type_factory.clone());
    fd.set_arch(Arc::new(architecture));
    let block = fd.create_new_block();
    let ram = ram_address_space();

    let mut labels: Vec<(PcodeOpRef, &str)> = Vec::new();
    let mut sites: Vec<(PcodeOpRef, usize)> = Vec::new();
    let mut site_counter = 0x5010u64;

    // makeCall mirror (callspec_identity_lifecycle_1204.cc:120-131 +
    // typeop_local_type_1204.rs D1 construction).
    let mut make_call = |fd: &mut Funcdata,
                         label: &'static str,
                         arg_size: usize,
                         arg_offset: u64,
                         param_type: Arc<Datatype>,
                         param_flags: u32,
                         shared_arg: Option<VarnodeRef>|
     -> CallResult {
        let op = fd.new_op(2, Address::with_space(&ram, site_counter));
        site_counter += 1;
        fd.op_set_opcode(&op, OpCode::CPUI_CALL);
        let arg = match shared_arg {
            Some(shared) => shared,
            None => {
                let arg = fd.vbank.create_with_space(arg_size, AddressSpace::Register, arg_offset);
                fd.set_input_varnode(arg.clone());
                arg
            }
        };
        fd.op_set_input(&op, arg.clone(), 1);
        let mut prototype =
            FuncProto::new(format!("spec_{label}"), void_type.clone());
        prototype.add_parameter(locked_parameter(
            "param0",
            param_type,
            param_flags,
        ));
        let spec_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op, prototype));
        let owner = fd
            .get_call_specs_owner(spec_index)
            .expect("fixture callspec owner");
        let fspec_varnode = fd.new_varnode_call_specs(&owner);
        fd.op_set_input(&op, fspec_varnode, 0);
        fd.op_insert_end(&op, &block);
        labels.push((op.clone(), label));
        sites.push((op.clone(), spec_index));
        CallResult {
            op,
            spec_index,
            arg,
        }
    };

    let c1 = make_call(
        &mut fd,
        "C1",
        4,
        0x400,
        int4_type.clone(),
        protoparam_flags::TYPE_LOCKED,
        None,
    );
    // C1 output: type-locked callspec output seeds the CALL output varnode.
    let out1 = fd.new_unique_out(8, &c1.op);
    if let Some(mut spec) = fd.get_call_specs_mut(c1.spec_index) {
        spec.prototype.output_type_locked = true;
        spec.prototype.return_type = object_pointer.clone();
    }

    let c2 = make_call(
        &mut fd,
        "C2",
        4,
        0x410,
        int8_type.clone(),
        protoparam_flags::TYPE_LOCKED,
        None,
    );
    let c3 = make_call(
        &mut fd,
        "C3",
        8,
        0x420,
        object_pointer.clone(),
        protoparam_flags::THIS_POINTER,
        None,
    );
    let c4 = make_call(
        &mut fd,
        "C4",
        4,
        0x430,
        void_type.clone(),
        protoparam_flags::TYPE_LOCKED,
        None,
    );

    // C5: CALLIND — spec resolved through Funcdata::get_call_specs_of_op,
    // input 0 is the real code-pointer varnode (no fspec annotation).
    let op5 = fd.new_op(2, Address::with_space(&ram, 0x5020));
    fd.op_set_opcode(&op5, OpCode::CPUI_CALLIND);
    let p5 = fd.vbank.create_with_space(8, AddressSpace::Register, 0x440);
    fd.set_input_varnode(p5.clone());
    fd.op_set_input(&op5, p5.clone(), 0);
    let a5 = fd.vbank.create_with_space(4, AddressSpace::Register, 0x450);
    fd.set_input_varnode(a5.clone());
    fd.op_set_input(&op5, a5.clone(), 1);
    let mut prototype5 = FuncProto::new("spec_C5".to_string(), void_type.clone());
    prototype5.add_parameter(locked_parameter(
        "param0",
        int8_type.clone(),
        protoparam_flags::TYPE_LOCKED,
    ));
    let spec5_index = fd.add_call_specs(FuncCallSpecs::new_for_op(&op5, prototype5));
    fd.op_insert_end(&op5, &block);

    let c6a = make_call(
        &mut fd,
        "C6A",
        8,
        0x460,
        object_pointer.clone(),
        protoparam_flags::TYPE_LOCKED,
        None,
    );
    // C6B reuses C6A's argument varnode: the shared argument feeds both
    // calls, C6A bound first so the descendant order is C6A,C6B.
    let _c6b = make_call(
        &mut fd,
        "C6B",
        8,
        0x460,
        uint8_type.clone(),
        protoparam_flags::TYPE_LOCKED,
        Some(c6a.arg.clone()),
    );

    let c8 = make_call(
        &mut fd,
        "C8",
        4,
        0x470,
        int4_type.clone(),
        0,
        None,
    );
    // C5 registration deferred past the last make_call call so the closure's
    // labels/sites borrows end first; both vectors are lookup tables, their
    // insertion order is never observed.
    labels.push((op5.clone(), "C5"));
    sites.push((op5.clone(), spec5_index));

    let cells = vec![
        Observed { label: "A1", vn: c1.arg.clone() },
        Observed { label: "A2", vn: c2.arg.clone() },
        Observed { label: "A3", vn: c3.arg.clone() },
        Observed { label: "A4", vn: c4.arg.clone() },
        Observed { label: "A5", vn: a5.clone() },
        Observed { label: "P5", vn: p5.clone() },
        Observed { label: "A6", vn: c6a.arg.clone() },
        Observed { label: "A8", vn: c8.arg.clone() },
        Observed { label: "OUT1", vn: out1.clone() },
    ];

    let order = block_order(&labels, &block);
    let a6_descendants = descendant_order(&labels, &c6a.arg);
    let defs = cells
        .iter()
        .map(|cell| format!("{}:{}", cell.label, def_token(&cell.vn)))
        .collect::<Vec<_>>()
        .join(",");
    let probe_c1 = probe_call_input(&type_factory, &c1.op, 1, &int4_type);
    let probe_c2 = probe_call_input(&type_factory, &c2.op, 1, &unknown4_type);
    let probe_c5s0 = probe_callind_input(&type_factory, &op5, 0, &fd, &code_pointer);
    let probe_c5s1 = probe_callind_input(&type_factory, &op5, 1, &fd, &int8_type);
    let probe_c8 = probe_call_input(&type_factory, &c8.op, 1, &unknown4_type);
    println!(
        "pre|types={}|defs={defs}|block_order={order}|a6_descendants={a6_descendants}|callspecs={}|dispatch=C1:{}/{},C2:{}/{},C5S0:{}/{},C5S1:{}/{},C8:{}/{}",
        type_snapshot(&cells),
        u8::from(callspecs_resolve(&fd, &sites)),
        probe_c1.token,
        u8::from(probe_c1.identity),
        probe_c2.token,
        u8::from(probe_c2.identity),
        probe_c5s0.token,
        u8::from(probe_c5s0.identity),
        probe_c5s1.token,
        u8::from(probe_c5s1.identity),
        probe_c8.token,
        u8::from(probe_c8.identity),
    );
    println!(
        "case7|status=UNTESTED|scope=stop-up-three-layer|note=PcodeOp.stop_type_propagation+Varnode.stop_uppropagation+propagateTypeEdge gate out of D2 lease (VARNODE-STOPUP-FLAGS-0001)"
    );
    io::stdout().flush().expect("flush pre-action state");

    let pre_types = snapshot_types(&cells);
    fd.start_type_recovery();
    let mut action = ActionInferTypes::new();
    action.reset(&mut fd);
    let first_result = catch_unwind(AssertUnwindSafe(|| action.apply(&mut fd)));
    let first_return = match first_result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase=after_pre|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase=after_pre|what=panic");
            std::process::exit(1);
        }
    };
    let first_types = snapshot_types(&cells);
    println!(
        "pass1|return={first_return}|exception=none|types={}|same_before={}|block_order_stable={}|a6_descendants_stable={}|callspecs={}",
        type_snapshot(&cells),
        same_before(&cells, &pre_types),
        u8::from(block_order(&labels, &block) == order),
        u8::from(descendant_order(&labels, &c6a.arg) == a6_descendants),
        u8::from(callspecs_resolve(&fd, &sites)),
    );

    let second_result = catch_unwind(AssertUnwindSafe(|| action.apply(&mut fd)));
    let second_return = match second_result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            println!("exception|phase=after_pass1|what={error}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("exception|phase=after_pass1|what=panic");
            std::process::exit(1);
        }
    };
    println!(
        "pass2|return={second_return}|exception=none|types={}|same_before={}|types_stable={}|block_order_stable={}|a6_descendants_stable={}|callspecs={}",
        type_snapshot(&cells),
        same_before(&cells, &first_types),
        u8::from(types_stable(&cells, &first_types)),
        u8::from(block_order(&labels, &block) == order),
        u8::from(descendant_order(&labels, &c6a.arg) == a6_descendants),
        u8::from(callspecs_resolve(&fd, &sites)),
    );
}
