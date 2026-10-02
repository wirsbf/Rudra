// INFERTYPES-SETTLE-0001: ActionInferTypes interning/settling fixture (Rust
// twin of tests/oracle/infertypes_settle_1204.cc).
//
// Mirrors the oracle fixture op-for-op: the float-conversion chain feeding a
// 4->8 FLOAT_FLOAT2FLOAT widener plus the type-locked struct pointer driving
// LOAD/STORE pointer propagation edges. Applies ActionInferTypes eight times
// and prints the byte-comparable per-round type table with Arc-identity
// stability against the previous round — the settle observable the oracle
// gets from TypeFactory-interned Datatypes and that Rudra gets from
// canonicalize_temp_type routing every temp type through the factory.
//
// Rust-only regression guard (not printed, no oracle counterpart): the
// action's local_count must stay below the 7-pass "not settling" cap
// (coreaction.cc:5390-5392) for this graph.
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::coreaction::ActionInferTypes;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{
    metatype2string, Datatype, TypeBase, TypeField, TypeMetatype, TypeStruct,
};
use rudra::type_system::typefactory::{CoreTypeFlavor, TypeFactory};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

struct RoundCell {
    label: &'static str,
    target: VarnodeRef,
    prev: Option<Arc<Datatype>>,
}

fn round_snapshot(cells: &[RoundCell]) -> String {
    let mut parts = Vec::new();
    for cell in cells {
        let target = cell.target.read().unwrap();
        let datatype = target.get_type().expect("cell typed");
        let same_prev = cell
            .prev
            .as_ref()
            .map(|previous| Arc::ptr_eq(previous, &datatype))
            .unwrap_or(false) as u8;
        parts.push(format!(
            "{}:{}{}/same_prev={same_prev}",
            cell.label,
            metatype2string(datatype.get_metatype()),
            datatype.get_size()
        ));
    }
    parts.join(",")
}

fn main() {
    println!(
        "schema=1|fixture=INFERTYPES-SETTLE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    let type_factory = Arc::new(RwLock::new(TypeFactory::new_flavor(
        8,
        CoreTypeFlavor::Standalone,
    )));
    let (progress, progress_pointer) = {
        let mut factory = type_factory.write().unwrap();
        let long_type = factory
            .get_base(8, TypeMetatype::Int)
            .expect("canonical int8");
        let progress = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("ProgressData".into(), 16, TypeMetatype::Struct),
            fields: vec![
                TypeField {
                    name: "total".into(),
                    offset: 0,
                    type_ptr: long_type.clone(),
                },
                TypeField {
                    name: "prev".into(),
                    offset: 8,
                    type_ptr: long_type,
                },
            ],
        }));
        let pointer = factory.get_ptr(progress.clone());
        (progress, pointer)
    };
    let _ = &progress;

    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default:gcc".to_string();
    architecture.set_types(type_factory.clone());
    let mut fd = Funcdata::new("infertypes_settle", Address::new(0x5000), 0x40);
    fd.vbank.set_type_factory(type_factory.clone());
    fd.set_arch(Arc::new(architecture));
    let block = fd.create_new_block();

    // An 8-byte int input feeding the float chain.
    let counter = fd.vbank.create_with_space(4, AddressSpace::Register, 0x100);
    let counter = fd.set_input_varnode(counter);

    // f2 = FLOAT_FLOAT2FLOAT(INT2FLOAT(counter) * const) : 4 -> 8 widening.
    let int2float = fd.new_op(1, Address::new(0x5000));
    fd.op_set_opcode(&int2float, OpCode::CPUI_FLOAT_INT2FLOAT);
    fd.op_set_input(&int2float, counter.clone(), 0);
    let float4 = fd.new_unique_out(4, &int2float);
    fd.op_insert_end(&int2float, &block);

    let fmul = fd.new_op(2, Address::new(0x5002));
    fd.op_set_opcode(&fmul, OpCode::CPUI_FLOAT_MULT);
    fd.op_set_input(&fmul, float4.clone(), 0);
    let scale = fd.new_constant(4, 0x3f800000);
    fd.op_set_input(&fmul, scale, 1);
    let product4 = fd.new_unique_out(4, &fmul);
    fd.op_insert_end(&fmul, &block);

    let f2f = fd.new_op(1, Address::new(0x5004));
    fd.op_set_opcode(&f2f, OpCode::CPUI_FLOAT_FLOAT2FLOAT);
    fd.op_set_input(&f2f, product4.clone(), 0);
    let double8 = fd.new_unique_out(8, &f2f);
    fd.op_insert_end(&f2f, &block);

    // Type-locked struct pointer driving LOAD/STORE pointer propagation.
    let pointer = fd.vbank.create_with_space(8, AddressSpace::Register, 0x180);
    let pointer = fd.set_input_varnode(pointer);
    pointer
        .write()
        .unwrap()
        .update_type_lock(progress_pointer.clone(), true, false);

    let load = fd.new_op(2, Address::new(0x5006));
    fd.op_set_opcode(&load, OpCode::CPUI_LOAD);
    let ram_id = fd.new_constant(4, AddressSpace::Ram.space_id() as u64);
    fd.op_set_input(&load, ram_id.clone(), 0);
    fd.op_set_input(&load, pointer.clone(), 1);
    let loaded8 = fd.new_unique_out(8, &load);
    fd.op_insert_end(&load, &block);

    let store = fd.new_op(3, Address::new(0x5008));
    fd.op_set_opcode(&store, OpCode::CPUI_STORE);
    fd.op_set_input(&store, ram_id, 0);
    fd.op_set_input(&store, pointer.clone(), 1);
    fd.op_set_input(&store, double8.clone(), 2);
    fd.op_insert_end(&store, &block);

    let mut cells: Vec<RoundCell> = Vec::new();
    for (label, target) in [
        ("counter", &counter),
        ("float4", &float4),
        ("product4", &product4),
        ("double8", &double8),
        ("pointer", &pointer),
        ("loaded8", &loaded8),
    ] {
        cells.push(RoundCell {
            label,
            target: target.clone(),
            prev: target.read().unwrap().get_type(),
        });
    }
    println!("pre|types={}", round_snapshot(&cells));

    fd.start_type_recovery();
    let mut action = ActionInferTypes::new();
    action.reset(&mut fd);
    for round in 1..=8 {
        let result = action
            .apply(&mut fd)
            .unwrap_or_else(|error| panic!("apply round {round} failed: {error}"));
        println!(
            "round{round}|return={result}|types={}",
            round_snapshot(&cells)
        );
        for cell in &mut cells {
            cell.prev = cell.target.read().unwrap().get_type();
        }
    }
    // Rust-only settle guard: local_count must stay below the 7-pass cap.
    assert!(
        action.local_count < 7,
        "ActionInferTypes did not settle: local_count={}",
        action.local_count
    );
}
