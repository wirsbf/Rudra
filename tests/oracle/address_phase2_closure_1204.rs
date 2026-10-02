//! Rugra comparand for ADDRESS-PHASE2-CLOSURE-0001.
//!
//! This intentionally uses only public, production-reachable APIs.  In
//! particular it does not recreate FlowInfo::newAddress outside FlowInfo;
//! the combined cross-space visited state remains explicitly UNTESTED.

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::flow::FlowInfo;
use rudra::funcdata::Funcdata;
use rudra::op::{pcodeop_flags, PcodeOpBank, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::{space_flags, AddrSpace, SpaceType};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

type DynBlock = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn address_token(address: Address) -> String {
    match address.get_space() {
        Some(space) => format!(
            "{}@{}:{:#x}:invalid={}",
            space.get_name(),
            space.get_index(),
            address.as_u64(),
            u8::from(address.is_invalid())
        ),
        None => format!("invalid:{:#x}", address.as_u64()),
    }
}

fn op_key(op: &PcodeOpRef) -> usize {
    Arc::as_ptr(&op.0) as usize
}

fn op_label(labels: &HashMap<usize, String>, op: Option<&PcodeOpRef>) -> String {
    let Some(op) = op else { return "null".to_string() };
    labels.get(&op_key(op)).cloned().unwrap_or_else(|| {
        format!("T{}", op.0.read().expect("op read lock").get_time())
    })
}

fn list_token<'a>(
    labels: &HashMap<usize, String>,
    ops: impl IntoIterator<Item = &'a PcodeOpRef>,
) -> String {
    let values = ops
        .into_iter()
        .map(|op| op_label(labels, Some(op)))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

fn print_membership(
    case_name: &str,
    phase: &str,
    bank: &PcodeOpBank,
    labels: &HashMap<usize, String>,
) {
    println!(
        "case={case_name} record=membership phase={phase} uniq={} optree={} alive={} dead={}",
        bank.get_uniqid(),
        list_token(labels, bank.optree.iter()),
        list_token(labels, bank.iter_alive()),
        list_token(labels, bank.iter_dead()),
    );
}

fn parent_ordinal(blocks: Option<&[DynBlock]>, op: &PcodeOpRef) -> String {
    let parent = op
        .0
        .read()
        .expect("op read lock")
        .parent
        .as_ref()
        .and_then(std::sync::Weak::upgrade);
    let Some(parent) = parent else { return "null".to_string() };
    let Some(blocks) = blocks else { return "present".to_string() };
    blocks
        .iter()
        .position(|block| Arc::ptr_eq(block, &parent))
        .map_or_else(|| "-1".to_string(), |index| index.to_string())
}

fn print_op(
    case_name: &str,
    phase: &str,
    label: &str,
    op: &PcodeOpRef,
    bank: &PcodeOpBank,
    labels: &HashMap<usize, String>,
    blocks: Option<&[DynBlock]>,
) {
    let target = op
        .0
        .read()
        .expect("op read lock")
        .target_op(bank);
    let value = op.0.read().expect("op read lock");
    println!(
        "case={case_name} record=op phase={phase} id={label} addr={} time={} order={} dead={} startmark={} startbasic={} parent={} target={}",
        address_token(value.get_addr()),
        value.get_time(),
        value.get_seq_num().get_order(),
        u8::from(value.is_dead()),
        u8::from(value.is_instruction_start()),
        u8::from((value.flags & pcodeop_flags::STARTBASIC) != 0),
        parent_ordinal(blocks, op),
        op_label(labels, target.as_ref()),
    );
}

fn print_bank_target(
    bank: &PcodeOpBank,
    query: Address,
    labels: &HashMap<usize, String>,
) {
    let lower = bank
        .optree
        .iter()
        .find(|op| op.0.read().expect("op read lock").get_addr() >= query);
    let target = bank.target(query);
    println!(
        "case=bank_spaces record=bank_target query={} lower_bound={} final={}",
        address_token(query),
        op_label(labels, lower),
        op_label(labels, target.as_ref()),
    );
}

fn add_bank_op(
    bank: &mut PcodeOpBank,
    labels: &mut HashMap<usize, String>,
    label: &str,
    address: Address,
) -> PcodeOpRef {
    let op = bank.create(OpCode::CPUI_COPY, 0, address);
    labels.insert(op_key(&op), label.to_string());
    op
}

fn run_bank(ram: &AddrSpace, overlay: &AddrSpace, stack: &AddrSpace) {
    let mut bank = PcodeOpBank::new();
    let mut labels = HashMap::new();
    let s0 = add_bank_op(&mut bank, &mut labels, "S0", Address::with_space(stack, 0x1000));
    let r0 = add_bank_op(&mut bank, &mut labels, "R0", Address::with_space(ram, 0x1000));
    let r1 = add_bank_op(&mut bank, &mut labels, "R1", Address::with_space(ram, 0x1000));
    let o0 = add_bank_op(&mut bank, &mut labels, "O0", Address::with_space(overlay, 0x1000));
    s0.0.write().expect("op write lock").flags |= pcodeop_flags::STARTMARK;
    r0.0.write().expect("op write lock").flags |= pcodeop_flags::STARTMARK;
    o0.0.write().expect("op write lock").flags |= pcodeop_flags::STARTMARK;

    print_membership("bank_spaces", "create", &bank, &labels);
    print_op("bank_spaces", "create", "S0", &s0, &bank, &labels, None);
    print_op("bank_spaces", "create", "R0", &r0, &bank, &labels, None);
    print_op("bank_spaces", "create", "R1", &r1, &bank, &labels, None);
    print_op("bank_spaces", "create", "O0", &o0, &bank, &labels, None);
    for query in [
        Address::with_space(ram, 0x1000),
        Address::with_space(ram, 0x1001),
        Address::with_space(overlay, 0x1000),
        Address::with_space(overlay, 0x1001),
        Address::with_space(stack, 0x1000),
        Address::with_space(stack, 0x1001),
    ] {
        print_bank_target(&bank, query, &labels);
    }

    for op in [&s0, &r0, &r1, &o0] {
        bank.mark_alive(op.clone());
    }
    print_membership("bank_spaces", "mark_alive", &bank, &labels);
    let outcome = catch_unwind(AssertUnwindSafe(|| bank.destroy(s0.clone())));
    println!(
        "case=bank_spaces record=destroy_alive id=S0 outcome={}",
        if outcome.is_ok() { "ok" } else { "panic" }
    );
    print_membership("bank_spaces", "destroy_alive", &bank, &labels);
}

fn add_split_op(
    data: &mut Funcdata,
    labels: &mut HashMap<usize, String>,
    label: &str,
    address: Address,
    flags: u32,
) -> PcodeOpRef {
    let op = data.obank.create(OpCode::CPUI_COPY, 0, address);
    op.0.write().expect("op write lock").flags |= flags;
    labels.insert(op_key(&op), label.to_string());
    op
}

fn ordinal_of(blocks: &[DynBlock], needle: &DynBlock) -> i32 {
    blocks
        .iter()
        .position(|block| Arc::ptr_eq(block, needle))
        .map_or(-1, |index| index as i32)
}

fn print_split_block(
    case_name: &str,
    ordinal: usize,
    block: &DynBlock,
    labels: &HashMap<usize, String>,
) {
    let guard = block.read().expect("block read lock");
    let basic = guard
        .as_any()
        .downcast_ref::<BlockBasic>()
        .expect("basic block");
    println!(
        "case={case_name} record=block ordinal={ordinal} entry=UNAVAILABLE start={} stop={} cover_count=UNAVAILABLE cover=UNAVAILABLE ops={}",
        address_token(basic.get_start_addr()),
        address_token(basic.get_stop_addr()),
        list_token(labels, basic.ops.iter()),
    );
}

fn run_split(ram: &AddrSpace, overlay: &AddrSpace, stack: &AddrSpace) {
    let mut data = Funcdata::new("split_spaces", Address::with_space(ram, 0x1000), 4);
    let mut labels = HashMap::new();
    let r0 = add_split_op(
        &mut data,
        &mut labels,
        "R0",
        Address::with_space(ram, 0x1000),
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK,
    );
    let o0 = add_split_op(
        &mut data,
        &mut labels,
        "O0",
        Address::with_space(overlay, 0x1000),
        pcodeop_flags::STARTMARK,
    );
    let s0 = add_split_op(
        &mut data,
        &mut labels,
        "S0",
        Address::with_space(stack, 0x1000),
        pcodeop_flags::STARTBASIC | pcodeop_flags::STARTMARK,
    );
    let s1 = add_split_op(
        &mut data,
        &mut labels,
        "S1",
        Address::with_space(stack, 0x1001),
        pcodeop_flags::STARTMARK,
    );
    print_membership("split_spaces", "before", &data.obank, &labels);
    let mut lifter = SleighLifter::new();
    {
        let mut flow = FlowInfo::new(&mut data, &mut lifter, 0x1000, 0x1002);
        flow.split_basic();
    }
    print_membership("split_spaces", "after", &data.obank, &labels);
    let blocks = data.bblocks.blocks.clone();
    let entry = data.bblocks.get_start_block();
    println!(
        "case=split_spaces record=summary blocks={} entry_ordinal={}",
        blocks.len(),
        entry.as_ref().map_or(-1, |block| ordinal_of(&blocks, block)),
    );
    for (ordinal, block) in blocks.iter().enumerate() {
        print_split_block("split_spaces", ordinal, block, &labels);
    }
    print_op("split_spaces", "after", "R0", &r0, &data.obank, &labels, Some(&blocks));
    print_op("split_spaces", "after", "O0", &o0, &data.obank, &labels, Some(&blocks));
    print_op("split_spaces", "after", "S0", &s0, &data.obank, &labels, Some(&blocks));
    print_op("split_spaces", "after", "S1", &s1, &data.obank, &labels, Some(&blocks));
}

fn run_malformed_split(ram: &AddrSpace) {
    let mut data = Funcdata::new(
        "split_missing_start",
        Address::with_space(ram, 0x2000),
        1,
    );
    let mut labels = HashMap::new();
    add_split_op(
        &mut data,
        &mut labels,
        "M0",
        Address::with_space(ram, 0x2000),
        pcodeop_flags::STARTMARK,
    );
    let mut lifter = SleighLifter::new();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut flow = FlowInfo::new(&mut data, &mut lifter, 0x2000, 0x2001);
        flow.split_basic();
    }));
    println!(
        "case=split_missing_start record=exception outcome={} blocks={}",
        if outcome.is_ok() { "ok" } else { "panic" },
        data.bblocks.get_size(),
    );
    print_membership("split_missing_start", "after", &data.obank, &labels);
}

fn print_flow_block(case_name: &str, ordinal: usize, block: &DynBlock) {
    let guard = block.read().expect("block read lock");
    let basic = guard
        .as_any()
        .downcast_ref::<BlockBasic>()
        .expect("basic block");
    let ops = basic
        .ops
        .iter()
        .map(|op| {
            let value = op.0.read().expect("op read lock");
            format!(
                "T{}:{}:order={}:parent={ordinal}",
                value.get_time(),
                address_token(value.get_addr()),
                value.get_seq_num().get_order(),
            )
        })
        .collect::<Vec<_>>();
    println!(
        "case={case_name} record=flow_block block={ordinal} entry=UNAVAILABLE start={} stop={} cover_count=UNAVAILABLE cover=UNAVAILABLE ops=[{}]",
        address_token(basic.get_start_addr()),
        address_token(basic.get_stop_addr()),
        ops.join(","),
    );
}

fn run_flow(space_name: &str, space: &AddrSpace, image: &[u8]) {
    let case_name = format!("flow_{space_name}");
    let entry = Address::with_space(space, 0);
    println!(
        "case={case_name} record=run mode=independent entry={}",
        address_token(entry)
    );
    let mut lifter = SleighLifter::new();
    if let Err(error) = lifter.configure_x86_64(image, 0) {
        println!("case={case_name} record=exception outcome=configure:{error}");
        return;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut data = Funcdata::new(&case_name, entry, image.len() as i32);
        let mut flow = FlowInfo::new(&mut data, &mut lifter, 0, image.len() as u64);
        flow.set_flags(32);
        flow.set_max_instructions(100_000);
        flow.generate_ops(entry);
        let target1 = flow.target(entry);
        let target2 = flow.target(entry);
        let generated = flow.snapshot();
        let alive = generated
            .operations
            .iter()
            .filter(|record| !record.op.0.read().expect("op read lock").is_dead())
            .count();
        let dead = generated.operations.len() - alive;
        print!(
            "case={case_name} record=generated visited={} instructions={} flags={} alive={alive} dead={dead} target_repeat_same={} first=",
            generated.visited.len(),
            generated.instruction_count,
            generated.flags,
            u8::from(match (&target1, &target2) {
                (Some(left), Some(right)) => Arc::ptr_eq(&left.0, &right.0),
                (None, None) => true,
                _ => false,
            }),
        );
        if let Some(first) = target1.as_ref() {
            let first = first.0.read().expect("op read lock");
            println!("T{}:{}", first.get_time(), address_token(first.get_addr()));
        } else {
            println!("null");
        }
        for visited in &generated.visited {
            print!(
                "case={case_name} record=visited addr={} size={} first_seq=",
                address_token(visited.address),
                visited.size,
            );
            if visited.first_seq_address.is_invalid() {
                println!("invalid");
            } else {
                println!(
                    "{}:T{}",
                    address_token(visited.first_seq_address),
                    visited.first_seq_time,
                );
            }
        }
        flow.generate_blocks();
        drop(flow);
        let blocks = data.bblocks.blocks.clone();
        let entry_block = data.bblocks.get_start_block();
        println!(
            "case={case_name} record=blocks count={} entry_ordinal={}",
            blocks.len(),
            entry_block
                .as_ref()
                .map_or(-1, |block| ordinal_of(&blocks, block)),
        );
        for (ordinal, block) in blocks.iter().enumerate() {
            print_flow_block(&case_name, ordinal, block);
        }
    }));
    println!(
        "case={case_name} record=exception outcome={}",
        if outcome.is_ok() { "none" } else { "panic" }
    );
}

fn main() {
    const IMAGE: &[u8] = &[0x75, 0x01, 0x90, 0xc3];
    let ram = AddrSpace::new_space(
        SpaceType::Processor,
        "ram",
        false,
        8,
        1,
        3,
        space_flags::HASPHYSICAL,
        0,
        0,
    );
    let stack = AddrSpace::new_spacebase_space("stack", 8, 8, &ram, 1, true, false);
    let overlay = AddrSpace::new_overlay_space("code_overlay", 9, &ram);
    println!(
        "record=header fixture=ADDRESS-PHASE2-CLOSURE-0001 architecture=x86:LE:64:default compiler_spec=gcc input=750190c3 ram={} overlay={} stack={} flow_options=32 max_instructions=100000",
        ram.get_index(),
        overlay.get_index(),
        stack.get_index(),
    );
    run_bank(&ram, &overlay, &stack);
    run_split(&ram, &overlay, &stack);
    run_malformed_split(&ram);
    run_flow("ram", &ram, IMAGE);
    run_flow("code_overlay", &overlay, IMAGE);
    run_flow("stack", &stack, IMAGE);
    println!(
        "record=coverage combined_cross_space_visited=UNTESTED reason=FlowInfo_state_is_per_run_and_private_newAddress_is_not_shadowed"
    );
}
