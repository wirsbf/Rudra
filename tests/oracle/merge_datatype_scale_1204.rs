//! MERGE-DATATYPE-SCALE-0001 Rugra comparand for full-loc MergeType.

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::cover::Cover;
use rudra::funcdata::Funcdata;
use rudra::merge::Merge;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::variable::HighVariable;
use rudra::varnode::{varnode_flags, Varnode};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

fn point_cover(value: &Arc<RwLock<Varnode>>, operation: &PcodeOpRef) {
    let order = operation.0.read().unwrap().get_seq_num().order;
    let mut cover = Cover::new();
    cover.add_def_point(0, order);
    cover.add_ref_point(0, order);
    let mut value = value.write().unwrap();
    value.cover = Some(Box::new(cover));
    value.clear_flags(varnode_flags::COVERDIRTY);
}

fn make_written(
    fd: &mut Funcdata,
    block: &Arc<RwLock<dyn FlowBlock + Send + Sync>>,
    space: AddressSpace,
    offset: u64,
    pc: u64,
    datatype: Arc<Datatype>,
) -> Arc<RwLock<Varnode>> {
    let operation = fd.new_op(0, Address::new(pc));
    fd.op_set_opcode(&operation, OpCode::CPUI_COPY);
    let value = fd
        .vbank
        .create_def_with_space(4, space, offset, &operation.0);
    value.write().unwrap().update_type(datatype);
    operation.0.write().unwrap().output = Some(value.clone());
    fd.op_insert_end(&operation, block);
    point_cover(&value, &operation);
    value
}

fn instance_spaces(high: &Arc<RwLock<HighVariable>>) -> String {
    high.read()
        .unwrap()
        .instances
        .iter()
        .map(|value| value.read().unwrap().address_space.space_id().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn run_scale(free_count: usize) {
    let mut fd = Funcdata::new("merge_scale", Address::new(0x8000), 0x100);
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x8000))));
    fd.bblocks.add_block(block.clone());

    let common = Arc::new(Datatype::Base(TypeBase::new(
        "uint4".to_string(),
        4,
        TypeMetatype::Uint,
    )));
    let identity_a = Arc::new(Datatype::Base(TypeBase::new(
        "identity_same".to_string(),
        4,
        TypeMetatype::Uint,
    )));
    let identity_b = Arc::new(Datatype::Base(TypeBase::new(
        "identity_same".to_string(),
        4,
        TypeMetatype::Uint,
    )));
    let tie_type = Arc::new(Datatype::Base(TypeBase::new(
        "same_address_tie".to_string(),
        4,
        TypeMetatype::Uint,
    )));

    let mut free_values = Vec::new();
    for index in 0..free_count {
        let value = fd.vbank.create_with_space(
            4,
            AddressSpace::Register,
            0x1000 + index as u64 * 8,
        );
        value.write().unwrap().update_type(common.clone());
        free_values.push(value);
    }

    let unique_value = make_written(
        &mut fd,
        &block,
        AddressSpace::Unique,
        0x30,
        0x8000,
        common.clone(),
    );
    let ram_value = make_written(
        &mut fd,
        &block,
        AddressSpace::Ram,
        0x20,
        0x8001,
        common.clone(),
    );
    let register_value = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x10,
        0x8002,
        common.clone(),
    );
    let implied = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x40,
        0x8003,
        common.clone(),
    );
    implied.write().unwrap().set_implied();
    let proto_partial = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x50,
        0x8004,
        common.clone(),
    );
    proto_partial.write().unwrap().set_proto_partial();
    let spacebase = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x60,
        0x8005,
        common,
    );
    spacebase
        .write()
        .unwrap()
        .set_flags(varnode_flags::SPACEBASE);
    let type_a = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x70,
        0x8006,
        identity_a,
    );
    let type_b = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x80,
        0x8007,
        identity_b,
    );
    let tie_first = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x90,
        0x8008,
        tie_type.clone(),
    );
    let tie_second = make_written(
        &mut fd,
        &block,
        AddressSpace::Register,
        0x90,
        0x8009,
        tie_type,
    );

    fd.set_high_level();
    let expected_survivor = unique_value.read().unwrap().high.clone().unwrap();
    let expected_tie_survivor = tie_first.read().unwrap().high.clone().unwrap();
    Merge::new().merge_by_datatype(&mut fd);

    let free_highs: HashSet<usize> = free_values
        .iter()
        .map(|value| {
            let high = value.read().unwrap().high.clone().unwrap();
            Arc::as_ptr(&high) as usize
        })
        .collect();
    let free_singletons = free_values.iter().all(|value| {
        value
            .read()
            .unwrap()
            .high
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .instances
            .len()
            == 1
    });
    let merged = unique_value.read().unwrap().high.clone().unwrap();
    let legal_merged = [ram_value.clone(), register_value.clone()].iter().all(|value| {
        let high = value.read().unwrap().high.clone().unwrap();
        Arc::ptr_eq(&merged, &high)
    });
    let filters_singleton = [implied, proto_partial, spacebase].iter().all(|value| {
        value
            .read()
            .unwrap()
            .high
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .instances
            .len()
            == 1
    });
    let type_identity_separate = {
        let a = type_a.read().unwrap().high.clone().unwrap();
        let b = type_b.read().unwrap().high.clone().unwrap();
        !Arc::ptr_eq(&a, &b)
    };
    let same_address_stable = {
        let high = tie_first.read().unwrap().high.clone().unwrap();
        let second_high = tie_second.read().unwrap().high.clone().unwrap();
        let instances = high.read().unwrap().instances.clone();
        Arc::ptr_eq(&high, &expected_tie_survivor)
            && Arc::ptr_eq(&high, &second_high)
            && instances.len() == 2
            && Arc::ptr_eq(&instances[0], &tie_first)
            && Arc::ptr_eq(&instances[1], &tie_second)
    };
    let mut observed = HashSet::new();
    let marks_clear = fd.vbank.loc_tree.iter().all(|entry| {
        let high = entry.0.read().unwrap().high.clone().unwrap();
        let key = Arc::as_ptr(&high) as usize;
        !observed.insert(key) || !high.read().unwrap().is_mark()
    });
    let groups = (
        unique_value.read().unwrap().mergegroup,
        ram_value.read().unwrap().mergegroup,
        register_value.read().unwrap().mergegroup,
    );
    println!(
        "scale={free_count},free_highs={},free_singletons={},legal_merged={},sorted_survivor_unique={},legal_instances={},instance_spaces={},merge_groups={}/{}/{},filters_singleton={},type_identity_separate={},same_address_stable={},marks_clear={}",
        free_highs.len(),
        u8::from(free_singletons),
        u8::from(legal_merged),
        u8::from(Arc::ptr_eq(&merged, &expected_survivor)),
        merged.read().unwrap().instances.len(),
        instance_spaces(&merged),
        groups.0,
        groups.1,
        groups.2,
        u8::from(filters_singleton),
        u8::from(type_identity_separate),
        u8::from(same_address_stable),
        u8::from(marks_clear),
    );
}

fn main() {
    for free_count in [1usize, 2, 32, 1024] {
        run_scale(free_count);
    }
}
