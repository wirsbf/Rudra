use std::sync::{Arc, RwLock};

use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::TypeMetatype;
use rudra::varnode::{varnode_flags, Varnode, VarnodeBank};

fn dump_varnode(label: &str, vn: &Varnode) {
    let datatype = vn.get_type().expect("VarnodeBank must attach a datatype");
    assert_eq!(datatype.get_metatype(), TypeMetatype::Unknown);
    let def = vn.get_def();
    let (def_addr, def_order) = def
        .as_ref()
        .map(|op| {
            let op = op.read().unwrap();
            (op.get_addr().as_u64(), op.get_seq_num().order)
        })
        .unwrap_or((0, 0));
    println!(
        "{label}:space={},space_id={},offset={},size={},flags={},type={},metatype=unknown,type_size={},type_id={},type_inheritable={},type_core={},def={},def_addr={},def_order={},has_cover={},cover_object={},create={},descendants={},consumed={},nzm={}",
        vn.get_space().name(),
        vn.get_space().space_id(),
        vn.get_offset(),
        vn.get_size(),
        vn.flags,
        datatype.get_name(),
        datatype.get_size(),
        datatype.get_id(),
        datatype.get_inheritable(),
        u8::from(datatype.is_coretype()),
        u8::from(def.is_some()),
        def_addr,
        def_order,
        u8::from(vn.has_cover()),
        u8::from(vn.cover.is_some()),
        vn.get_create_index(),
        vn.count_descends(),
        vn.get_consume(),
        vn.get_nzm(),
    );
}

fn class_code(vn: &Varnode) -> char {
    if vn.is_input() {
        'I'
    } else if vn.is_written() {
        'W'
    } else {
        'F'
    }
}

fn operation_label(
    op: &Arc<RwLock<PcodeOp>>,
    piece: &Arc<RwLock<PcodeOp>>,
    hi_reader: &Arc<RwLock<PcodeOp>>,
    lo_reader: &Arc<RwLock<PcodeOp>>,
    sub_hi: &Arc<RwLock<PcodeOp>>,
    sub_lo: &Arc<RwLock<PcodeOp>>,
) -> &'static str {
    if Arc::ptr_eq(op, piece) {
        "piece"
    } else if Arc::ptr_eq(op, hi_reader) {
        "hi_reader"
    } else if Arc::ptr_eq(op, lo_reader) {
        "lo_reader"
    } else if Arc::ptr_eq(op, sub_hi) {
        "sub_hi"
    } else if Arc::ptr_eq(op, sub_lo) {
        "sub_lo"
    } else {
        "unknown"
    }
}

fn run_combine_fixture() {
    let mut fd = Funcdata::new("combine", Address::new(0x5000), 0x20);
    let block: Arc<RwLock<dyn FlowBlock + Send + Sync>> = Arc::new(RwLock::new(
        BlockBasic::new(0, Address::new(0x5000)),
    ));
    fd.bblocks.add_block(block.clone());

    let hi = fd
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x24);
    let hi = fd.vbank.set_input(hi).expect("fresh high input");
    let lo = fd
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x20);
    let lo = fd.vbank.set_input(lo).expect("fresh low input");

    let piece = fd.new_op(2, Address::new(0x5000));
    fd.op_set_opcode(&piece, OpCode::CPUI_PIECE);
    fd.op_insert_input(&piece, hi.clone(), 0);
    fd.op_insert_input(&piece, lo.clone(), 1);
    let piece_out = fd.vbank.create_def_unique(8, &piece.0);
    piece.0.write().unwrap().output = Some(piece_out);
    fd.op_insert_end(&piece, &block);

    let hi_reader = fd.new_op(2, Address::new(0x5001));
    fd.op_set_opcode(&hi_reader, OpCode::CPUI_INT_ADD);
    fd.op_insert_input(&hi_reader, hi.clone(), 0);
    fd.op_insert_input(&hi_reader, hi.clone(), 1);
    let hi_reader_out = fd.vbank.create_def_unique(4, &hi_reader.0);
    hi_reader.0.write().unwrap().output = Some(hi_reader_out);
    fd.op_insert_end(&hi_reader, &block);

    let lo_reader = fd.new_op(1, Address::new(0x5002));
    fd.op_set_opcode(&lo_reader, OpCode::CPUI_COPY);
    fd.op_insert_input(&lo_reader, lo.clone(), 0);
    let lo_reader_out = fd.vbank.create_def_unique(4, &lo_reader.0);
    lo_reader.0.write().unwrap().output = Some(lo_reader_out);
    fd.op_insert_end(&lo_reader, &block);

    let bank_before = fd.vbank.num_varnodes();
    let ops_before = fd.obank.optree.len();
    fd.combine_input_varnodes(&hi, &lo)
        .expect("valid contiguous register inputs");

    let combined = piece.0.read().unwrap().inrefs[0].clone();
    let new_hi = hi_reader.0.read().unwrap().inrefs[0].clone();
    let new_lo = lo_reader.0.read().unwrap().inrefs[0].clone();
    let sub_hi = new_hi.read().unwrap().get_def().expect("high replacement def");
    let sub_lo = new_lo.read().unwrap().get_def().expect("low replacement def");
    let old_input_edges = fd
        .obank
        .optree
        .iter()
        .map(|operation| {
            operation
                .0
                .read()
                .unwrap()
                .inrefs
                .iter()
                .filter(|input| {
                    let value = input.read().unwrap();
                    value.is_input()
                        && value.get_space() == AddressSpace::Register
                        && value.get_size() == 4
                        && matches!(value.get_offset(), 0x20 | 0x24)
                })
                .count()
        })
        .sum::<usize>();
    let old_input_bank = fd
        .vbank
        .loc_tree
        .iter()
        .filter(|entry| {
            let value = entry.0.read().unwrap();
            value.is_input()
                && value.get_space() == AddressSpace::Register
                && value.get_size() == 4
                && matches!(value.get_offset(), 0x20 | 0x24)
        })
        .count();
    let bank_combined = fd
        .vbank
        .loc_tree
        .iter()
        .map(|entry| entry.0.clone())
        .find(|candidate| {
            let value = candidate.read().unwrap();
            value.is_input()
                && value.get_space() == AddressSpace::Register
                && value.get_offset() == 0x20
                && value.get_size() == 8
        })
        .expect("combined bank member");
    let combined_desc = combined
        .read()
        .unwrap()
        .descend_iter()
        .map(|operation| {
            operation_label(
                &operation,
                &piece.0,
                &hi_reader.0,
                &lo_reader.0,
                &sub_hi,
                &sub_lo,
            )
        })
        .collect::<Vec<_>>()
        .join("/");
    let block_order = block
        .read()
        .unwrap()
        .get_ops()
        .iter()
        .map(|operation| {
            operation_label(
                &operation.0,
                &piece.0,
                &hi_reader.0,
                &lo_reader.0,
                &sub_hi,
                &sub_lo,
            )
        })
        .collect::<Vec<_>>()
        .join("/");
    let combined_value = combined.read().unwrap();
    let new_hi_value = new_hi.read().unwrap();
    let new_lo_value = new_lo.read().unwrap();
    let sub_hi_value = sub_hi.read().unwrap();
    let sub_lo_value = sub_lo.read().unwrap();
    println!(
        "combine_valid:bank={bank_before}->{},ops={ops_before}->{},piece_copy={},piece_inputs={},piece_canonical={},old_input_edges={old_input_edges},old_input_bank={old_input_bank},combined={}/{}/{}/{}/{}/{},combined_desc={combined_desc},hi_reader_slots={}{},hi={}/{}/{}/{}/{},sub_hi={}/{}/{}/{},lo_reader_slot={},lo={}/{}/{}/{}/{},sub_lo={}/{}/{}/{},block_order={block_order}",
        fd.vbank.num_varnodes(),
        fd.obank.optree.len(),
        u8::from(piece.0.read().unwrap().opcode == OpCode::CPUI_COPY),
        piece.0.read().unwrap().inrefs.len(),
        u8::from(Arc::ptr_eq(&combined, &bank_combined)),
        combined_value.get_space().name(),
        combined_value.get_space().space_id(),
        combined_value.get_offset(),
        combined_value.get_size(),
        combined_value.flags,
        combined_value.get_create_index(),
        u8::from(Arc::ptr_eq(&hi_reader.0.read().unwrap().inrefs[0], &new_hi)),
        u8::from(Arc::ptr_eq(&hi_reader.0.read().unwrap().inrefs[1], &new_hi)),
        new_hi_value.get_space().name(),
        new_hi_value.get_space().space_id(),
        new_hi_value.get_offset(),
        new_hi_value.get_size(),
        new_hi_value.count_descends(),
        sub_hi_value.get_addr().as_u64(),
        sub_hi_value.inrefs.len(),
        u8::from(Arc::ptr_eq(&sub_hi_value.inrefs[0], &combined)),
        sub_hi_value.inrefs[1].read().unwrap().get_offset(),
        u8::from(Arc::ptr_eq(&lo_reader.0.read().unwrap().inrefs[0], &new_lo)),
        new_lo_value.get_space().name(),
        new_lo_value.get_space().space_id(),
        new_lo_value.get_offset(),
        new_lo_value.get_size(),
        new_lo_value.count_descends(),
        sub_lo_value.get_addr().as_u64(),
        sub_lo_value.inrefs.len(),
        u8::from(Arc::ptr_eq(&sub_lo_value.inrefs[0], &combined)),
        sub_lo_value.inrefs[1].read().unwrap().get_offset(),
    );

    let mut non_input = Funcdata::new("combine_noninput", Address::new(0x6000), 1);
    let hi = non_input
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x24);
    let lo = non_input
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x20);
    let lo = non_input.vbank.set_input(lo).expect("fresh low input");
    let noninput_error = non_input
        .combine_input_varnodes(&hi, &lo)
        .expect_err("free high value is not an input");

    let mut disjoint = Funcdata::new("combine_disjoint", Address::new(0x7000), 1);
    let hi = disjoint
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x30);
    let hi = disjoint.vbank.set_input(hi).expect("fresh high input");
    let lo = disjoint
        .vbank
        .create_with_space(4, AddressSpace::Register, 0x20);
    let lo = disjoint.vbank.set_input(lo).expect("fresh low input");
    let disjoint_error = disjoint
        .combine_input_varnodes(&hi, &lo)
        .expect_err("disjoint inputs are not contiguous");
    println!(
        "combine_errors:noninput={noninput_error},disjoint={disjoint_error}"
    );
}

fn main() {
    // The locked oracle drives SleighArchitecture's standalone buildCoreTypes
    // (xunknownN names); mirror that registration flavor so bank-allocated
    // unknown types byte-match the oracle projections.
    let mut bank = VarnodeBank::new();
    bank.set_type_factory(std::sync::Arc::new(std::sync::RwLock::new(
        rudra::type_system::typefactory::TypeFactory::new_flavor(
            8,
            rudra::type_system::typefactory::CoreTypeFlavor::Standalone,
        ),
    )));
    let defop = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1000), 0),
        OpCode::CPUI_COPY,
    )));

    let defined = bank.create_def_with_space(8, AddressSpace::Register, 0x20, &defop);
    let free = bank.create_with_space(8, AddressSpace::Register, 0x38);
    let constant = bank.create_constant(4, 0x1234);
    let input = bank.create_with_space(8, AddressSpace::Register, 0x30);
    let input = bank.set_input(input).expect("fresh input");
    let annotation = bank.create_with_space(8, AddressSpace::Iop, 0x99);
    let unique0 = bank.create_unique(8);
    let unique1 = bank.create_unique(4);
    let set_def_source = bank.create_with_space(8, AddressSpace::Register, 0x28);
    let set_def_valid = bank
        .set_def(set_def_source.clone(), Arc::downgrade(&defop))
        .expect("fresh setDef input");

    dump_varnode("defined", &defined.read().unwrap());
    dump_varnode("free", &free.read().unwrap());
    dump_varnode("constant", &constant.read().unwrap());
    dump_varnode("input", &input.read().unwrap());
    dump_varnode("annotation", &annotation.read().unwrap());
    dump_varnode("unique0", &unique0.read().unwrap());
    dump_varnode("unique1", &unique1.read().unwrap());
    let set_def_guard = set_def_valid.read().unwrap();
    println!(
        "set_def_valid:canonical_self={},flags={},def={},create={}",
        u8::from(Arc::ptr_eq(&set_def_valid, &set_def_source)),
        set_def_guard.flags,
        u8::from(
            set_def_guard
                .get_def()
                .is_some_and(|op| Arc::ptr_eq(&op, &defop))
        ),
        set_def_guard.get_create_index(),
    );
    drop(set_def_guard);
    let defined_type = defined.read().unwrap().get_type().unwrap();
    let free_type = free.read().unwrap().get_type().unwrap();
    let input_type = input.read().unwrap().get_type().unwrap();
    let annotation_type = annotation.read().unwrap().get_type().unwrap();
    let unique0_type = unique0.read().unwrap().get_type().unwrap();
    let set_def_type = set_def_valid.read().unwrap().get_type().unwrap();
    let constant_type = constant.read().unwrap().get_type().unwrap();
    let unique1_type = unique1.read().unwrap().get_type().unwrap();
    println!(
        "type_identity:size8={}{}{}{}{},size4={}",
        u8::from(Arc::ptr_eq(&defined_type, &free_type)),
        u8::from(Arc::ptr_eq(&defined_type, &input_type)),
        u8::from(Arc::ptr_eq(&defined_type, &annotation_type)),
        u8::from(Arc::ptr_eq(&defined_type, &unique0_type)),
        u8::from(Arc::ptr_eq(&defined_type, &set_def_type)),
        u8::from(Arc::ptr_eq(&constant_type, &unique1_type)),
    );

    let (raw_start, raw_stop, input_flags_after) = {
        let mut value = input.write().unwrap();
        value.calc_cover();
        let (start, stop) = {
            let cover = value.get_cover().expect("input cover");
            let block = cover.blocks.get(&0).expect("input cover block zero");
            (block.start, block.end)
        };
        (start, stop, value.flags)
    };
    println!(
        "input_cover:object=1,raw_start={raw_start},raw_stop={raw_stop},semantic_start={raw_start},semantic_stop={raw_stop},flags_after={input_flags_after}"
    );

    let count_before_create_def_duplicate = bank.num_varnodes();
    let defined_duplicate = bank.create_def_with_space(8, AddressSpace::Register, 0x20, &defop);
    println!(
        "create_def_duplicate:canonical={},bank_delta={}",
        u8::from(Arc::ptr_eq(&defined_duplicate, &defined)),
        bank.num_varnodes() as isize - count_before_create_def_duplicate as isize,
    );

    let canonical = bank.create_with_space(8, AddressSpace::Register, 0x50);
    let canonical = bank.set_input(canonical).expect("fresh canonical input");
    let duplicate = bank.create_with_space(8, AddressSpace::Register, 0x50);
    duplicate
        .write()
        .unwrap()
        .set_flags(varnode_flags::SPACEBASE);
    let reader = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1010), 1),
        OpCode::CPUI_INT_ADD,
    )));
    reader.write().unwrap().inrefs = vec![duplicate.clone(), duplicate.clone()];
    duplicate.write().unwrap().add_descend(&reader);
    duplicate.write().unwrap().add_descend(&reader);
    let canonical_return = bank
        .set_input(duplicate.clone())
        .expect("duplicate input canonicalizes");
    let reader_guard = reader.read().unwrap();
    let slot0 = reader_guard
        .get_in(0)
        .is_some_and(|vn| Arc::ptr_eq(vn, &canonical));
    let slot1 = reader_guard
        .get_in(1)
        .is_some_and(|vn| Arc::ptr_eq(vn, &canonical));
    drop(reader_guard);
    let descendants: Vec<_> = canonical.read().unwrap().descend_iter().collect();
    println!(
        "xref_duplicate:canonical={},slot0={},slot1={},descendants={},descend_order={}",
        u8::from(Arc::ptr_eq(&canonical_return, &canonical)),
        u8::from(slot0),
        u8::from(slot1),
        descendants.len(),
        u8::from(descendants.iter().all(|op| Arc::ptr_eq(op, &reader))),
    );

    let guard_constant = bank.create_constant(4, 0x55);
    let input_nonfree_error = bank
        .set_input(canonical.clone())
        .expect_err("input is not free")
        .to_string();
    let input_constant_error = bank
        .set_input(guard_constant.clone())
        .expect_err("constant input")
        .to_string();
    let def_nonfree_error = bank
        .set_def(canonical.clone(), Arc::downgrade(&defop))
        .expect_err("defined input")
        .to_string();
    let def_constant_error = bank
        .set_def(guard_constant, Arc::downgrade(&defop))
        .expect_err("constant output")
        .to_string();
    println!(
        "checked_guards:input_nonfree={},input_constant={},def_nonfree={},def_constant={}",
        input_nonfree_error, input_constant_error, def_nonfree_error, def_constant_error,
    );

    let made_free = bank.create_def_with_space(8, AddressSpace::Register, 0x58, &defop);
    let count_before_make_free = bank.num_varnodes();
    bank.make_free(&made_free).expect("bank-owned Varnode");
    let made_free_guard = made_free.read().unwrap();
    println!(
        "make_free:flags={},def={},free={},bank_delta={}",
        made_free_guard.flags,
        u8::from(made_free_guard.get_def().is_some()),
        u8::from(made_free_guard.is_free()),
        bank.num_varnodes() as isize - count_before_make_free as isize,
    );
    drop(made_free_guard);

    let destroy_free = bank.create_with_space(8, AddressSpace::Register, 0x60);
    let count_before_destroy = bank.num_varnodes();
    bank.destroy_varnode(&destroy_free)
        .expect("detached bank-owned Varnode");
    let destroy_free_delta = bank.num_varnodes() as isize - count_before_destroy as isize;
    let destroy_defined =
        bank.create_def_with_space(8, AddressSpace::Register, 0x68, &defop);
    let destroy_def_error = bank
        .destroy_varnode(&destroy_defined)
        .expect_err("defined Varnode is integrated")
        .to_string();
    let destroy_descendant = bank.create_with_space(8, AddressSpace::Register, 0x70);
    let destroy_reader = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x1020), 2),
        OpCode::CPUI_COPY,
    )));
    destroy_reader
        .write()
        .unwrap()
        .inrefs
        .push(destroy_descendant.clone());
    destroy_descendant
        .write()
        .unwrap()
        .add_descend(&destroy_reader);
    let destroy_desc_error = bank
        .destroy_varnode(&destroy_descendant)
        .expect_err("read Varnode is integrated")
        .to_string();
    println!(
        "destroy:free_delta={destroy_free_delta},def_error={destroy_def_error},desc_error={destroy_desc_error}"
    );

    let mut order_bank = VarnodeBank::new();
    order_bank.set_type_factory(std::sync::Arc::new(std::sync::RwLock::new(
        rudra::type_system::typefactory::TypeFactory::new_flavor(
            8,
            rudra::type_system::typefactory::CoreTypeFlavor::Standalone,
        ),
    )));
    let order_op = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x2000), 2),
        OpCode::CPUI_COPY,
    )));
    let class_input = order_bank.create_with_space(8, AddressSpace::Register, 0xa0);
    order_bank
        .set_input(class_input)
        .expect("fresh class input");
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xa0, &order_op);
    order_bank.create_with_space(8, AddressSpace::Register, 0xa0);
    let loc_classes: String = order_bank
        .begin_loc()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.get_space() == AddressSpace::Register && value.get_offset() == 0xa0)
                .then_some(class_code(&value))
        })
        .collect();
    let def_classes: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.get_space() == AddressSpace::Register && value.get_offset() == 0xa0)
                .then_some(class_code(&value))
        })
        .collect();
    println!("class_order:loc={loc_classes},def={def_classes}");

    let written_op_late = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x3000), 9),
        OpCode::CPUI_COPY,
    )));
    let written_op_early = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x3000), 3),
        OpCode::CPUI_COPY,
    )));
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xb0, &written_op_late);
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xb0, &written_op_early);
    let written_pc_late = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x4000), 4),
        OpCode::CPUI_COPY,
    )));
    let written_pc_early = Arc::new(RwLock::new(PcodeOp::new(
        SeqNum::new(Address::new(0x3500), 5),
        OpCode::CPUI_COPY,
    )));
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xb4, &written_pc_late);
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xb4, &written_pc_early);
    let free_early = order_bank.create_with_space(8, AddressSpace::Register, 0xb8);
    let free_late = order_bank.create_with_space(8, AddressSpace::Register, 0xb8);
    let free_early_index = free_early.read().unwrap().get_create_index();
    let free_late_index = free_late.read().unwrap().get_create_index();
    let written_loc: String = order_bank
        .begin_loc()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_written() && value.get_offset() == 0xb0).then(|| {
                char::from(
                    b'0' + value
                        .get_def()
                        .expect("written")
                        .read()
                        .unwrap()
                        .get_seq_num()
                        .order as u8,
                )
            })
        })
        .collect();
    let written_def: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_written() && value.get_offset() == 0xb0).then(|| {
                char::from(
                    b'0' + value
                        .get_def()
                        .expect("written")
                        .read()
                        .unwrap()
                        .get_seq_num()
                        .order as u8,
                )
            })
        })
        .collect();
    let written_pc_loc: String = order_bank
        .begin_loc()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_written() && value.get_offset() == 0xb4).then(|| {
                if value
                    .get_def()
                    .expect("written")
                    .read()
                    .unwrap()
                    .get_addr()
                    .as_u64()
                    == 0x3500
                {
                    'E'
                } else {
                    'L'
                }
            })
        })
        .collect();
    let written_pc_def: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_written() && value.get_offset() == 0xb4).then(|| {
                if value
                    .get_def()
                    .expect("written")
                    .read()
                    .unwrap()
                    .get_addr()
                    .as_u64()
                    == 0x3500
                {
                    'E'
                } else {
                    'L'
                }
            })
        })
        .collect();
    let free_loc: String = order_bank
        .begin_loc()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_free() && value.get_offset() == 0xb8).then_some(
                if value.get_create_index() == free_early_index {
                    'E'
                } else {
                    'L'
                },
            )
        })
        .collect();
    let free_def: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_free() && value.get_offset() == 0xb8).then_some(
                if value.get_create_index() == free_early_index {
                    'E'
                } else {
                    'L'
                },
            )
        })
        .collect();
    println!(
        "tie_breaks:written_loc={written_loc},written_def={written_def},written_pc_loc={written_pc_loc},written_pc_def={written_pc_def},free_loc={free_loc},free_def={free_def},free_distinct={}",
        u8::from(free_early_index != free_late_index),
    );

    for space in [
        AddressSpace::Const,
        AddressSpace::Other(1),
        AddressSpace::Unique,
        AddressSpace::Ram,
        AddressSpace::Register,
        AddressSpace::Stack,
        AddressSpace::Join,
        AddressSpace::Iop,
    ] {
        order_bank.create_with_space(8, space, 0xc0);
    }
    let space_order = order_bank
        .begin_loc()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.get_offset() == 0xc0).then_some(value.get_space().space_id().to_string())
        })
        .collect::<Vec<_>>()
        .join(",");
    println!("space_order={space_order}");

    let ram_input = order_bank.create_with_space(8, AddressSpace::Ram, 0xd0);
    order_bank.set_input(ram_input).expect("fresh RAM input");
    let register_input = order_bank.create_with_space(8, AddressSpace::Register, 0xd0);
    order_bank
        .set_input(register_input)
        .expect("fresh register input");
    order_bank.create_def_with_space(8, AddressSpace::Ram, 0xd8, &order_op);
    order_bank.create_def_with_space(8, AddressSpace::Register, 0xd8, &order_op);
    let input_storage_order: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_input() && value.get_offset() == 0xd0)
                .then_some(char::from(b'0' + value.get_space().space_id()))
        })
        .collect();
    let written_storage_order: String = order_bank
        .begin_def()
        .filter_map(|entry| {
            let value = entry.0.read().unwrap();
            (value.is_written() && value.get_offset() == 0xd8)
                .then_some(char::from(b'0' + value.get_space().space_id()))
        })
        .collect();
    println!("def_storage_order:input={input_storage_order},written={written_storage_order}");

    let unknown8_identity = defined_type;
    bank.clear();
    let after_clear = bank.create_unique(8);
    let after_clear_guard = after_clear.read().unwrap();
    println!(
        "after_clear:offset={},create={},type_same={}",
        after_clear_guard.get_offset(),
        after_clear_guard.get_create_index(),
        u8::from(Arc::ptr_eq(
            &after_clear_guard.get_type().unwrap(),
            &unknown8_identity,
        )),
    );
    drop(after_clear_guard);
    run_combine_fixture();
}
