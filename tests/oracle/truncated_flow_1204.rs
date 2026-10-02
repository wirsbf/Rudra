//! Rust side of the locked Ghidra 12.0.4 `Funcdata::truncatedFlow` fixture.
//!
//! The runner supplies the exact ELF symbol addresses used by the C++ side.
//! Construction, list reordering, callspec binding, jump-table state, and
//! exception injection mirror `truncated_flow_1204.cc` one-for-one.

use rudra::address::Address;
use rudra::block::BlockBasic;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::FlowInfo;
use rudra::fspec::FuncCallSpecs;
use rudra::funcdata::Funcdata;
use rudra::jumptable::{JumpModel, JumpModelTrivial, JumpTable, NormMax};
use rudra::op::{pcodeop_flags, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, AddressSpace, SpaceType};
use std::env;
use std::error::Error;
use std::sync::{Arc, RwLock};

fn parse_address(value: &str) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_str_radix(value.trim_start_matches("0x"), 16)?)
}

fn list_times(ops: &[PcodeOpRef]) -> String {
    let values: Vec<_> = ops
        .iter()
        .map(|op| op.0.read().expect("op read lock").get_time().to_string())
        .collect();
    format!("[{}]", values.join(","))
}

fn varnode_token(vn: Option<&Arc<RwLock<rudra::varnode::Varnode>>>) -> String {
    let Some(vn) = vn else {
        return "none".to_string();
    };
    let vn = vn.read().expect("varnode read lock");
    if vn.get_space() == AddressSpace::Iop && vn.is_annotation() {
        return "fspec".to_string();
    }
    let name = match vn.get_space() {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    };
    format!("{}:0x{:x}", name, vn.get_offset())
}

fn configure_table(table: &Arc<RwLock<JumpTable>>, indirect: Option<&PcodeOpRef>, base: u64) {
    {
        let mut jt = table.write().expect("jump-table write lock");
        jt.addresstable = vec![Address::new(base + 0x10), Address::new(base + 0x20)];
        jt.label = vec![7, 9];
        jt.switch_var_consume = 0x55;
        jt.default_block = 3;
        jt.last_block = 7;
        jt.norm_max = NormMax {
            addsub: 4,
            leftright: 5,
            ext: 6,
        };
        jt.partial_table = true;
        jt.collect_loads = true;
        jt.default_is_folded = true;
        if let Some(op) = indirect {
            jt.set_indirect_op(op.0.clone());
        }
    }
    let current: Box<dyn JumpModel> = Box::new(JumpModelTrivial::new(table.clone()));
    let original: Box<dyn JumpModel> = Box::new(JumpModelTrivial::new(table.clone()));
    let mut jt = table.write().expect("jump-table write lock");
    jt.jmodel = Some(current);
    jt.origmodel = Some(original);
}

fn flow_state(fd: &mut Funcdata, max_instructions: Option<u64>) -> rudra::flow::TruncatedFlowState {
    let mut lifter = SleighLifter::new();
    let mut flow = FlowInfo::new(fd, &mut lifter, 0, u64::MAX);
    if let Some(maximum) = max_instructions {
        flow.set_max_instructions(maximum);
        flow.set_flags(
            rudra::flow::flow_flags::POSSIBLE_UNREACHABLE
                | rudra::flow::flow_flags::ERROR_UNIMPLEMENTED,
        );
    }
    flow.truncated_state()
}

fn build_success_source(name: &str, source_addr: u64, callee_addr: u64) -> Funcdata {
    let mut source = Funcdata::new(name, Address::new(source_addr), 1);

    let call = source.new_op(1, Address::new(source_addr));
    source.op_set_opcode(&call, OpCode::CPUI_CALL);
    let code_ref = source.new_code_ref(Address::new(callee_addr));
    source.op_set_input(&call, code_ref, 0);
    call.0.write().expect("call write lock").flags |= pcodeop_flags::STARTMARK;
    let callspec = Arc::new(RwLock::new(FuncCallSpecs::new_for_op(
        &call,
        source.funcp.clone(),
    )));
    {
        let mut callspec = callspec.write().expect("callspec write lock");
        callspec.entry_addr = Some(Address::new(callee_addr));
        callspec.set_spacebase_offset(0x1234);
    }
    let annotation = source.new_varnode_call_specs(&callspec);
    source.op_set_input(&call, annotation, 0);
    source.add_call_specs_owner(callspec);

    let copy = source.new_op(1, Address::new(source_addr));
    source.op_set_opcode(&copy, OpCode::CPUI_COPY);
    let stack_input = source.vbank.create_with_space(8, AddressSpace::Stack, 0x28);
    source.op_set_input(&copy, stack_input, 0);
    source.new_varnode_out(8, Address::new(0x40), &copy);
    copy.0.write().expect("copy write lock").flags |=
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK;

    let return_op = source.new_op(0, Address::new(source_addr));
    source.op_set_opcode(&return_op, OpCode::CPUI_RETURN);
    return_op.0.write().expect("return write lock").flags |= pcodeop_flags::STARTMARK;
    source.obank.insert_after_dead(&call, &copy);

    let spare = source.new_op(0, Address::new(source_addr));
    source.op_set_opcode(&spare, OpCode::CPUI_COPY);
    source.obank.destroy(spare);

    let unlinked = Arc::new(RwLock::new(JumpTable::new(Address::new(
        source_addr + 0x30,
    ))));
    configure_table(&unlinked, None, source_addr);
    source.jump_tables.push(unlinked);
    let linked = Arc::new(RwLock::new(JumpTable::new(Address::new(source_addr))));
    configure_table(&linked, Some(&copy), source_addr);
    source.jump_tables.push(linked);
    source
}

fn build_range_source(name: &str, source_addr: u64, code_space: &AddrSpace) -> Funcdata {
    let base = Address::with_space(code_space, source_addr);
    let mut source = Funcdata::new(name, base, 1);

    let first = source.new_op(0, base);
    source.op_set_opcode(&first, OpCode::CPUI_COPY);
    first.0.write().expect("first write lock").flags |=
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK;

    let maximum = source.new_op(0, Address::with_space(code_space, source_addr + 0x40));
    source.op_set_opcode(&maximum, OpCode::CPUI_COPY);
    maximum.0.write().expect("maximum write lock").flags |= pcodeop_flags::STARTMARK;

    let last = source.new_op(0, Address::with_space(code_space, source_addr + 0x20));
    source.op_set_opcode(&last, OpCode::CPUI_RETURN);
    last.0.write().expect("last write lock").flags |= pcodeop_flags::STARTMARK;
    source
}

fn print_range(source: &Funcdata, target: &Funcdata, code_space: &AddrSpace) {
    let block = target.bblocks.blocks[0]
        .read()
        .expect("range block read lock");
    let basic = block
        .as_any()
        .downcast_ref::<BlockBasic>()
        .expect("range clone must produce BlockBasic");
    let start = block.get_start_addr();
    let stop = basic.get_stop_addr();
    let base = Address::with_space(code_space, source.baseaddr.as_u64());
    let expected_stop = Address::with_space(code_space, source.baseaddr.as_u64() + 0x40);
    let last = Address::with_space(code_space, source.baseaddr.as_u64() + 0x20);
    let start_space_same = match (start.get_space(), base.get_space()) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };
    let stop_space_same = match (stop.get_space(), base.get_space()) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    };
    let op_deltas: Vec<_> = block
        .get_ops()
        .iter()
        .map(|op| {
            let op = op.0.read().expect("range op read lock");
            (op.get_addr().as_u64() as i64 - source.baseaddr.as_u64() as i64).to_string()
        })
        .collect();
    println!(
        "case=block_range blocks={} alive={} dead={} start_valid={} stop_valid={} start_space_same={} stop_space_same={} start_exact={} stop_exact={} stop_not_last={} start_delta={} stop_delta={} op_deltas=[{}]",
        target.bblocks.blocks.len(),
        target.obank.alivelist.len(),
        target.obank.deadlist.len(),
        usize::from(start.get_space().is_some()),
        usize::from(stop.get_space().is_some()),
        usize::from(start_space_same),
        usize::from(stop_space_same),
        usize::from(start == base),
        usize::from(stop == expected_stop),
        usize::from(stop != last),
        start.as_u64() as i64 - source.baseaddr.as_u64() as i64,
        stop.as_u64() as i64 - source.baseaddr.as_u64() as i64,
        op_deltas.join(","),
    );
}

fn print_table(table: &Arc<RwLock<JumpTable>>, base: u64) {
    let jt = table.read().expect("jump-table read lock");
    let addrs: Vec<_> = jt
        .addresstable
        .iter()
        .map(|address| (address.as_u64() as i64 - base as i64).to_string())
        .collect();
    let model = jt.jmodel.as_ref();
    let indirect_time = jt
        .get_indirect_op()
        .map(|op| op.read().expect("indirect op read lock").get_time() as i32)
        .unwrap_or(-1);
    println!(
        "jumptable entries={} addrs=[{}] labels={} model={} override={} orig={} consume={} default={} last={} norm={}/{}/{} partial={} collect={} folded={} indirect_time={}",
        jt.addresstable.len(),
        addrs.join(","),
        usize::from(!jt.label.is_empty()),
        usize::from(model.is_some()),
        usize::from(model.is_some_and(|value| value.is_override())),
        usize::from(jt.origmodel.is_some()),
        jt.get_switch_var_consume(),
        jt.get_default_block(),
        jt.last_block,
        jt.norm_max.addsub,
        jt.norm_max.leftright,
        jt.norm_max.ext,
        usize::from(jt.partial_table),
        usize::from(jt.collect_loads),
        usize::from(jt.has_folded_default()),
        indirect_time,
    );
}

fn print_success(source: &Funcdata, target: &Funcdata) {
    println!("case=success");
    println!(
        "source dead_times={} uniq={}",
        list_times(&source.obank.deadlist),
        source.obank.get_uniqid()
    );
    println!(
        "target alive_times={} dead_times={} uniq={}",
        list_times(&target.obank.alivelist),
        list_times(&target.obank.deadlist),
        target.obank.get_uniqid()
    );

    for (index, op_ref) in target.obank.optree.iter().enumerate() {
        let op = op_ref.0.read().expect("op read lock");
        println!(
            "op={} time={} order={} opcode={} startbasic={} startmark={} in0={} out={}",
            index,
            op.get_time(),
            op.get_seq_num().get_order(),
            op.opcode.name(),
            usize::from((op.flags & pcodeop_flags::STARTBASIC) != 0),
            usize::from((op.flags & pcodeop_flags::STARTMARK) != 0),
            varnode_token(op.get_in(0)),
            varnode_token(op.get_out()),
        );
    }

    let newspec = target.callspecs[0].clone();
    let callop = {
        let newspec = newspec.read().expect("target callspec read lock");
        newspec
            .find_call_op(target)
            .expect("target callspec must resolve its call op")
    };
    let (call_time, fspec_self) = {
        let call = callop.0.read().expect("call read lock");
        let fspec_self = call.get_in(0).is_some_and(|input| {
            let input = input.read().expect("callspec input read lock");
            input.get_space() == AddressSpace::Iop
                && input.is_annotation()
                && input
                    .get_call_spec()
                    .is_some_and(|owner| Arc::ptr_eq(&owner, &newspec))
        });
        (call.get_time(), fspec_self)
    };
    let fspec_varnodes = target
        .vbank
        .loc_tree
        .iter()
        .filter(|entry| {
            let value = entry.0.read().expect("varnode read lock");
            value.get_space() == AddressSpace::Iop && value.is_annotation()
        })
        .count();
    let (entry, stackoffset, extrapop) = {
        let newspec = newspec.read().expect("target callspec read lock");
        (
            newspec.entry_addr.expect("direct callspec entry").as_u64(),
            newspec.get_spacebase_offset(),
            newspec.prototype.get_extra_pop(),
        )
    };
    println!(
        "callspecs={} new={} op_time={} fspec_self={} varnodes={} fspec_varnodes={} entry_delta={} stackoffset={} extrapop={}",
        target.callspecs.len(),
        usize::from(!Arc::ptr_eq(&source.callspecs[0], &newspec)),
        call_time,
        usize::from(fspec_self),
        target.vbank.num_varnodes(),
        fspec_varnodes,
        entry as i64 - source.baseaddr.as_u64() as i64,
        stackoffset,
        extrapop,
    );

    println!("jumptables={}", target.jump_tables.len());
    print_table(&target.jump_tables[0], source.baseaddr.as_u64());
    let source_table = source.jump_tables[1]
        .read()
        .expect("source table read lock");
    let target_table = target.jump_tables[0]
        .read()
        .expect("target table read lock");
    let table_new = !Arc::ptr_eq(&source.jump_tables[1], &target.jump_tables[0]);
    let indirect_new = match (
        source_table.get_indirect_op(),
        target_table.get_indirect_op(),
    ) {
        (Some(left), Some(right)) => !Arc::ptr_eq(&left, &right),
        _ => false,
    };
    let model_new = match (&source_table.jmodel, &target_table.jmodel) {
        (Some(left), Some(right)) => {
            let left = &**left as *const dyn JumpModel as *const ();
            let right = &**right as *const dyn JumpModel as *const ();
            left != right
        }
        _ => false,
    };
    println!(
        "jumptable_identity table_new={} indirect_new={} model_new={}",
        usize::from(table_new),
        usize::from(indirect_new),
        usize::from(model_new)
    );
    drop(target_table);
    drop(source_table);

    println!("blocks={}", target.bblocks.blocks.len());
    for (index, block) in target.bblocks.blocks.iter().enumerate() {
        let block = block.read().expect("block read lock");
        let values: Vec<_> = block
            .get_ops()
            .iter()
            .map(|op| {
                let op = op.0.read().expect("block op read lock");
                format!("{}:{}", op.get_time(), op.get_seq_num().get_order())
            })
            .collect();
        println!("block={} times=[{}]", index, values.join(","));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 11 {
        return Err(
            "usage: truncated_flow_1204 SOURCE TARGET CALLEE NONEMPTY ERROR_SOURCE ERROR_TARGET ENTRY_SOURCE ENTRY_TARGET RANGE_SOURCE RANGE_TARGET".into(),
        );
    }
    let source_addr = parse_address(&args[1])?;
    let target_addr = parse_address(&args[2])?;
    let callee_addr = parse_address(&args[3])?;
    let nonempty_addr = parse_address(&args[4])?;
    let error_source_addr = parse_address(&args[5])?;
    let error_target_addr = parse_address(&args[6])?;
    let entry_source_addr = parse_address(&args[7])?;
    let entry_target_addr = parse_address(&args[8])?;
    let range_source_addr = parse_address(&args[9])?;
    let range_target_addr = parse_address(&args[10])?;

    let mut source = build_success_source("truncated_flow_source", source_addr, callee_addr);
    let state = flow_state(&mut source, Some(77));
    let mut target = Funcdata::new("truncated_flow_target", Address::new(target_addr), 1);
    target.truncated_flow(&source, &state)?;
    print_success(&source, &target);

    let code_space = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        4,
        space_flags::HASPHYSICAL,
        0,
        0,
    );
    let mut range_source = build_range_source(
        "truncated_flow_range_source",
        range_source_addr,
        &code_space,
    );
    let range_state = flow_state(&mut range_source, None);
    let mut range_target = Funcdata::new(
        "truncated_flow_range_target",
        Address::with_space(&code_space, range_target_addr),
        1,
    );
    range_target.truncated_flow(&range_source, &range_state)?;
    print_range(&range_source, &range_target, &code_space);

    let mut nonempty = Funcdata::new("truncated_flow_nonempty", Address::new(nonempty_addr), 1);
    nonempty.new_op(0, Address::new(nonempty_addr));
    let nonempty_error = nonempty
        .truncated_flow(&source, &state)
        .expect_err("nonempty target must fail")
        .to_string();
    println!(
        "case=nonempty error={} ops={} dead={} blocks={}",
        nonempty_error,
        nonempty.obank.get_uniqid(),
        nonempty.obank.deadlist.len(),
        nonempty.bblocks.blocks.len()
    );

    let mut error_source = Funcdata::new(
        "truncated_flow_error_source",
        Address::new(error_source_addr),
        1,
    );
    let kept = error_source.new_op(0, Address::new(error_source_addr));
    error_source.op_set_opcode(&kept, OpCode::CPUI_RETURN);
    kept.0.write().expect("kept write lock").flags |=
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK;
    let missing = error_source.new_op(0, Address::new(error_source_addr));
    error_source.op_set_opcode(&missing, OpCode::CPUI_COPY);
    error_source.obank.mark_alive(missing.clone());
    let first_table = Arc::new(RwLock::new(JumpTable::new(Address::new(error_source_addr))));
    first_table
        .write()
        .expect("first table write lock")
        .set_indirect_op(kept.0.clone());
    error_source.jump_tables.push(first_table);
    let missing_table = Arc::new(RwLock::new(JumpTable::new(Address::new(error_source_addr))));
    missing_table
        .write()
        .expect("missing table write lock")
        .set_indirect_op(missing.0.clone());
    error_source.jump_tables.push(missing_table);
    let error_state = flow_state(&mut error_source, None);
    let mut error_target = Funcdata::new(
        "truncated_flow_error_target",
        Address::new(error_target_addr),
        1,
    );
    let jump_error = error_target
        .truncated_flow(&error_source, &error_state)
        .expect_err("missing indirect clone must fail")
        .to_string();
    println!(
        "case=missing_jumptable error={} all={} dead={} alive={} uniq={} jumptables={} blocks={}",
        jump_error,
        error_target.obank.optree.len(),
        error_target.obank.deadlist.len(),
        error_target.obank.alivelist.len(),
        error_target.obank.get_uniqid(),
        error_target.jump_tables.len(),
        error_target.bblocks.blocks.len(),
    );

    let mut entry_source = Funcdata::new(
        "truncated_flow_entry_source",
        Address::new(entry_source_addr),
        1,
    );
    let entry_op = entry_source.new_op(0, Address::new(entry_source_addr));
    entry_source.op_set_opcode(&entry_op, OpCode::CPUI_RETURN);
    entry_op.0.write().expect("entry op write lock").flags |= pcodeop_flags::STARTMARK;
    let entry_state = flow_state(&mut entry_source, None);
    let mut entry_target = Funcdata::new(
        "truncated_flow_entry_target",
        Address::new(entry_target_addr),
        1,
    );
    println!(
        "case=missing_entry before_all={} before_dead={} before_alive={} before_uniq={} before_varnodes={} before_callspecs={} before_jumptables={} before_blocks={} before_generated={}",
        entry_target.obank.optree.len(),
        entry_target.obank.deadlist.len(),
        entry_target.obank.alivelist.len(),
        entry_target.obank.get_uniqid(),
        entry_target.vbank.num_varnodes(),
        entry_target.callspecs.len(),
        entry_target.jump_tables.len(),
        entry_target.bblocks.blocks.len(),
        usize::from(
            (entry_target.flags & rudra::funcdata::funcdata_flags::BLOCKS_GENERATED) != 0
        ),
    );
    let entry_error = match entry_target.truncated_flow(&entry_source, &entry_state) {
        Err(rudra::Error::Lowlevel(message)) => message,
        Err(other) => return Err(format!("unexpected missing-entry error: {other}").into()),
        Ok(()) => return Err("missing entry marker must fail".into()),
    };
    let entry_clone = entry_target.obank.deadlist.first().cloned();
    let (
        first_time,
        first_order,
        first_opcode,
        first_dead,
        first_parent,
        first_startbasic,
        first_startmark,
    ) = if let Some(op_ref) = entry_clone {
        let op = op_ref.0.read().expect("entry clone read lock");
        (
            op.get_time() as i64,
            op.get_seq_num().get_order() as i64,
            op.opcode.name(),
            usize::from(op.is_dead()),
            usize::from(op.parent.is_some()),
            usize::from((op.flags & pcodeop_flags::STARTBASIC) != 0),
            usize::from((op.flags & pcodeop_flags::STARTMARK) != 0),
        )
    } else {
        (-1, -1, "none", 0, 0, 0, 0)
    };
    println!(
        "case=missing_entry error={} all={} dead={} alive={} uniq={} varnodes={} callspecs={} jumptables={} blocks={} generated={} first_time={} first_order={} first_opcode={} first_dead={} first_parent={} first_startbasic={} first_startmark={}",
        entry_error,
        entry_target.obank.optree.len(),
        entry_target.obank.deadlist.len(),
        entry_target.obank.alivelist.len(),
        entry_target.obank.get_uniqid(),
        entry_target.vbank.num_varnodes(),
        entry_target.callspecs.len(),
        entry_target.jump_tables.len(),
        entry_target.bblocks.blocks.len(),
        usize::from(
            (entry_target.flags & rudra::funcdata::funcdata_flags::BLOCKS_GENERATED) != 0
        ),
        first_time,
        first_order,
        first_opcode,
        first_dead,
        first_parent,
        first_startbasic,
        first_startmark,
    );
    Ok(())
}
