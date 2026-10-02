use std::sync::Arc;

use rudra::address::{Address, SeqNum};
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeMetatype, TypePointer};
use rudra::type_system::TypeBase;
use rudra::typeop::{TypeOp, TypeOpLoad, TypeOpStore};
use rudra::varnode::Varnode;
use std::sync::RwLock;

fn pointer_to(pointee: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(String::new(), 8, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

fn main() {
    let progress = Arc::new(Datatype::Base(TypeBase::new(
        "ProgressData".into(),
        32,
        TypeMetatype::Struct,
    )));
    let progress_ptr = pointer_to(progress.clone());
    let int4_type = Arc::new(Datatype::Base(TypeBase::new(
        "int4".into(),
        4,
        TypeMetatype::Int,
    )));
    let int4_ptr = pointer_to(int4_type.clone());

    let make_vn = |size, offset, datatype: Arc<Datatype>| {
        let mut varnode = Varnode::new(size, Address::new(offset));
        varnode.v_type = Some(datatype);
        Arc::new(RwLock::new(varnode))
    };
    let progress_source = make_vn(8, 0x100, progress_ptr.clone());
    let int4_source = make_vn(8, 0x108, int4_ptr.clone());
    let value16 = make_vn(
        16,
        0x200,
        Arc::new(Datatype::Base(TypeBase::new(
            "value16".into(),
            16,
            TypeMetatype::Unknown,
        ))),
    );
    let value4 = make_vn(
        4,
        0x210,
        Arc::new(Datatype::Base(TypeBase::new(
            "value4".into(),
            4,
            TypeMetatype::Unknown,
        ))),
    );
    let value32 = make_vn(
        32,
        0x220,
        Arc::new(Datatype::Base(TypeBase::new(
            "value32".into(),
            32,
            TypeMetatype::Unknown,
        ))),
    );
    let value16_type = value16.read().unwrap().v_type.clone().unwrap();
    let value4_type = value4.read().unwrap().v_type.clone().unwrap();
    let value32_type = value32.read().unwrap().v_type.clone().unwrap();
    let space_constant = make_vn(
        8,
        0,
        Arc::new(Datatype::Base(TypeBase::new(
            "space".into(),
            8,
            TypeMetatype::Unknown,
        ))),
    );
    let mut load = PcodeOp::new(SeqNum::new(Address::new(0), 0), OpCode::CPUI_LOAD);
    load.inrefs.push(space_constant.clone());
    load.inrefs.push(progress_source.clone());
    let mut load_result = |target: &Arc<RwLock<Varnode>>| {
        load.output = Some(target.clone());
        TypeOpLoad.propagate_type(&progress_ptr, &load, 1, -1)
    };
    let load16 = load_result(&value16);
    let load4 = load_result(&value4);
    let load32 = load_result(&value32);
    load.inrefs[1] = int4_source.clone();
    load.output = Some(value4.clone());
    let load_int4 = TypeOpLoad.propagate_type(&int4_ptr, &load, 1, -1);

    let store_result = |target: Arc<RwLock<Varnode>>, time| {
        let mut store = PcodeOp::new(SeqNum::new(Address::new(0), time), OpCode::CPUI_STORE);
        store.inrefs.push(space_constant.clone());
        store.inrefs.push(progress_source.clone());
        store.inrefs.push(target);
        let result = TypeOpStore.propagate_type(&progress_ptr, &store, 1, 2);
        (result, store)
    };
    let (store16, store16_op) = store_result(value16.clone(), 1);
    let (store4, store4_op) = store_result(value4.clone(), 2);
    let (store32, store32_op) = store_result(value32.clone(), 3);

    let mut spacebase_load = PcodeOp::new(SeqNum::new(Address::new(0), 4), OpCode::CPUI_LOAD);
    spacebase_load.inrefs.push(space_constant.clone());
    spacebase_load.inrefs.push(int4_source.clone());
    let spacebase_output = make_vn(4, 0x230, int4_type.clone());
    spacebase_output
        .write()
        .unwrap()
        .set_flags(rudra::varnode::varnode_flags::SPACEBASE);
    spacebase_load.output = Some(spacebase_output);
    let load_spacebase = TypeOpLoad.propagate_type(&int4_type, &spacebase_load, -1, 1);

    println!("fixture=TYPE-PTRWIDTH-PTRSUB-0001");
    println!("load_struct32_deref16_null={}", load16.is_none() as u8);
    println!("load_struct32_deref4_null={}", load4.is_none() as u8);
    println!(
        "load_struct32_deref32_identity={}",
        load32
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress)) as u8
    );
    println!("store_struct32_deref16_null={}", store16.is_none() as u8);
    println!("store_struct32_deref4_null={}", store4.is_none() as u8);
    println!(
        "store_struct32_deref32_identity={}",
        store32
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress)) as u8
    );
    println!(
        "load_int4_deref4_identity={}",
        load_int4
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &int4_type)) as u8
    );
    println!(
        "source_type_alias={}",
        progress_source
            .read()
            .unwrap()
            .v_type
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &progress_ptr)) as u8
    );
    println!(
        "load_args_attached={}",
        (Arc::ptr_eq(&load.inrefs[1], &int4_source)
            && load
                .output
                .as_ref()
                .is_some_and(|output| Arc::ptr_eq(output, &value4))) as u8
    );
    println!(
        "store_args_attached={}",
        (Arc::ptr_eq(&store16_op.inrefs[1], &progress_source)
            && Arc::ptr_eq(&store16_op.inrefs[2], &value16)) as u8
    );
    println!(
        "load_spacebase_source_null={}",
        load_spacebase.is_none() as u8
    );
    println!(
        "target_types_unchanged={}",
        (value16
            .read()
            .unwrap()
            .v_type
            .as_ref()
            .is_some_and(|datatype| Arc::ptr_eq(datatype, &value16_type))
            && value4
                .read()
                .unwrap()
                .v_type
                .as_ref()
                .is_some_and(|datatype| Arc::ptr_eq(datatype, &value4_type))
            && value32
                .read()
                .unwrap()
                .v_type
                .as_ref()
                .is_some_and(|datatype| Arc::ptr_eq(datatype, &value32_type))) as u8
    );
    println!(
        "shared_space_alias={}",
        (Arc::ptr_eq(&load.inrefs[0], &space_constant)
            && Arc::ptr_eq(&store16_op.inrefs[0], &space_constant)
            && Arc::ptr_eq(&store4_op.inrefs[0], &space_constant)
            && Arc::ptr_eq(&store32_op.inrefs[0], &space_constant)) as u8
    );
}
