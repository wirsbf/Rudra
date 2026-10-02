use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::graph::dump_dataflow_graph_string;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::{Datatype, TypeBase, TypeMetatype};
use rudra::unionresolve::ResolveEdge;
use rudra::variable::HighVariable;
use std::sync::{Arc, RwLock};

fn main() {
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> =
        Arc::new(RwLock::new(BlockBasic::new(0, Address::new(0x1000))));
    fd.bblocks.add_block(block.clone());

    let first = fd.new_op(0, Address::new(0x1000));
    let middle = fd.new_op(0, Address::new(0x1000));
    let last = fd.new_op(0, Address::new(0x1000));
    fd.op_set_opcode(&first, OpCode::CPUI_COPY);
    fd.op_set_opcode(&middle, OpCode::CPUI_COPY);
    fd.op_set_opcode(&last, OpCode::CPUI_COPY);
    let first_out = fd.vbank.create_def_with_space(
        4,
        AddressSpace::Register,
        0x20,
        &first.0,
    );
    first.0.write().unwrap().output = Some(first_out.clone());
    let middle_out = fd.vbank.create_def_with_space(
        4,
        AddressSpace::Register,
        0x20,
        &middle.0,
    );
    middle.0.write().unwrap().output = Some(middle_out.clone());

    let first_identity: SeqNum = first.0.read().unwrap().start;
    let middle_identity: SeqNum = middle.0.read().unwrap().start;
    let first_time = first_identity.get_time();
    let middle_time = middle_identity.get_time();
    let same_time_other_address = SeqNum::new(Address::new(0x2000), first_time);
    fd.op_insert_end(&first, &block);
    fd.op_insert_end(&middle, &block);
    fd.op_insert_end(&last, &block);

    for _ in 0..70 {
        let padding = fd.new_op(0, Address::new(0x1000));
        fd.op_set_opcode(&padding, OpCode::CPUI_COPY);
        fd.op_insert_before(&padding, &middle);
    }
    fd.op_uninsert(&first);
    fd.op_insert_end(&first, &block);

    let first_seq = first.0.read().unwrap().start;
    let middle_seq = middle.0.read().unwrap().start;
    let first_lookup = fd.obank.find_op(&first_identity).unwrap();
    let middle_lookup = fd.obank.find_op(&middle_identity).unwrap();
    let first_vn = fd
        .vbank
        .find_vn(4, Address::new(0x20), Address::new(0x1000), first_time)
        .unwrap();
    let middle_vn = fd
        .vbank
        .find_vn(4, Address::new(0x20), Address::new(0x1000), middle_time)
        .unwrap();
    let optree = fd
        .obank
        .optree
        .iter()
        .map(|op| op.0.read().unwrap().get_time().to_string())
        .collect::<Vec<_>>()
        .join(",");

    println!(
        "time_order={}:{},{}:{}",
        first_seq.get_time(),
        first_seq.get_order(),
        middle_seq.get_time(),
        middle_seq.get_order()
    );
    println!(
        "identity={},{}",
        u8::from(first_identity == first_seq),
        u8::from(middle_identity == middle_seq)
    );
    println!(
        "cross_address={},{}",
        u8::from(first_identity.same_identity(&same_time_other_address)),
        u8::from(first_identity < same_time_other_address)
    );
    println!(
        "lookup={},{}",
        u8::from(Arc::ptr_eq(&first_lookup.0, &first.0)),
        u8::from(Arc::ptr_eq(&middle_lookup.0, &middle.0))
    );
    println!(
        "varnode_lookup={},{}",
        u8::from(Arc::ptr_eq(&first_vn, &first_out)),
        u8::from(Arc::ptr_eq(&middle_vn, &middle_out))
    );
    println!("optree_prefix={}", &optree[..5]);
    println!(
        "order_relation={}",
        u8::from(first_seq.get_order() < middle_seq.get_order())
    );

    let graph_dump = dump_dataflow_graph_string(&fd);
    let op_start = graph_dump.find("//START:opnodes").unwrap();
    let op_end = graph_dump[op_start..].find("*END_COLUMNS").unwrap() + op_start;
    let op_section = &graph_dump[op_start..op_end];
    println!(
        "graph_time={},{}",
        u8::from(op_section.contains(&format!("\no{} ", first_time))),
        u8::from(graph_dump.contains(&format!("\no{} v", first_time)))
    );
    let parent_type = Datatype::Base(TypeBase::new(
        "xunknown4".to_string(),
        4,
        TypeMetatype::Unknown,
    ));
    let first_guard = first.0.read().unwrap();
    let middle_guard = middle.0.read().unwrap();
    let first_slot_one = ResolveEdge::new(&parent_type, &first_guard, 1);
    let middle_slot_zero = ResolveEdge::new(&parent_type, &middle_guard, 0);
    let first_slot_zero = ResolveEdge::new(&parent_type, &first_guard, 0);
    println!(
        "resolve_order={},{}",
        u8::from(first_slot_one < middle_slot_zero),
        u8::from(first_slot_zero < middle_slot_zero)
    );
    drop(first_guard);
    drop(middle_guard);
    println!(
        "compare_name={},{}",
        u8::from(HighVariable::compare_name(
            &first_out.read().unwrap(),
            &middle_out.read().unwrap()
        )),
        u8::from(HighVariable::compare_name(
            &middle_out.read().unwrap(),
            &first_out.read().unwrap()
        ))
    );
    fd.op_destroy(&first);
    println!(
        "destroy_identity={},{}",
        u8::from(
            fd.vbank
                .find_vn(4, Address::new(0x20), Address::new(0x1000), first_time)
                .is_none()
        ),
        u8::from(
            fd.vbank
                .find_vn(4, Address::new(0x20), Address::new(0x1000), middle_time)
                .is_some_and(|found| Arc::ptr_eq(&found, &middle_out))
        )
    );
}
