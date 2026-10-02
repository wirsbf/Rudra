//! TRANSFORM-MULTIEQUAL-INSERT-0001 Rudra comparand.

use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::pcodeop_flags;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::transform::TransformManager;
use rudra::varnode::varnode_flags;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

fn snapshot(fd: &Funcdata, block: &Block) -> String {
    let ops = block.read().unwrap().get_ops();
    let op_index: HashMap<usize, usize> = ops
        .iter()
        .enumerate()
        .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index))
        .collect();
    let mut vars: Vec<Arc<RwLock<Varnode>>> = Vec::new();
    let mut var_index: HashMap<usize, usize> = HashMap::new();
    for op in &ops {
        let (output, inputs) = {
            let op = op.0.read().unwrap();
            (op.get_out().cloned(), op.inrefs.clone())
        };
        for varnode in output.into_iter().chain(inputs) {
            // Size-0 detached sentinels model Ghidra's NULL input slots and
            // survive only in pre-placeInputs partial state.
            if varnode.read().unwrap().get_size() == 0 {
                continue;
            }
            let pointer = Arc::as_ptr(&varnode) as usize;
            if let std::collections::hash_map::Entry::Vacant(entry) = var_index.entry(pointer) {
                entry.insert(vars.len());
                vars.push(varnode);
            }
        }
    }
    let var_name = |varnode: Option<&Arc<RwLock<Varnode>>>| {
        varnode.map_or_else(
            || "_".to_string(),
            |varnode| format!("v{}", var_index[&(Arc::as_ptr(varnode) as usize)]),
        )
    };
    let mut output = String::new();
    output.push_str("ops[");
    for (index, op) in ops.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        let op = op.0.read().unwrap();
        let parent = op
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .filter(|parent| Arc::ptr_eq(parent, block))
            .map_or(-1, |parent| parent.read().unwrap().get_index());
        write!(
            output,
            "o{index}:{}/t{}/r{}/p{parent}/I{}/o{}/i",
            op.opcode as i32,
            op.start.get_time(),
            op.start.get_order(),
            u8::from((op.flags & pcodeop_flags::INDIRECT_CREATION) != 0),
            var_name(op.get_out()),
        )
        .unwrap();
        for (slot, input) in op.inrefs.iter().enumerate() {
            if slot != 0 {
                output.push(',');
            }
            if input.read().unwrap().get_size() == 0 {
                output.push('_');
            } else {
                output.push_str(&var_name(Some(input)));
            }
        }
    }
    output.push_str("]vars[");
    for (index, varnode) in vars.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        let varnode = varnode.read().unwrap();
        write!(
            output,
            "v{index}:c{}/s{}/sp{}/k{}",
            varnode.create_index,
            varnode.get_size(),
            varnode.get_space().space_id(),
            u8::from(varnode.is_constant()),
        )
        .unwrap();
        if varnode.is_constant() {
            write!(output, ":{}", varnode.get_offset()).unwrap();
        }
        write!(
            output,
            "/x{}",
            u8::from((varnode.flags & varnode_flags::INDIRECT_CREATION) != 0)
        )
        .unwrap();
        output.push_str("/d");
        let definition = varnode.get_def();
        match definition
            .as_ref()
            .and_then(|op| op_index.get(&(Arc::as_ptr(op) as usize)))
        {
            Some(index) => write!(output, "o{index}").unwrap(),
            None => output.push('_'),
        }
        output.push_str("/u");
        for (use_index, descendant) in varnode.descend_iter().enumerate() {
            if use_index != 0 {
                output.push(',');
            }
            match op_index.get(&(Arc::as_ptr(&descendant) as usize)) {
                Some(index) => write!(output, "o{index}").unwrap(),
                None => output.push('x'),
            }
        }
    }
    write!(
        output,
        "]count={},{},{},{},{},{}",
        ops.len(),
        vars.len(),
        fd.obank.alivelist.len(),
        fd.obank.deadlist.len(),
        fd.obank.optree.len(),
        fd.vbank.num_varnodes(),
    )
    .unwrap();
    output
}

fn new_function(name: &str, address: u64) -> (Funcdata, Block) {
    let mut fd = Funcdata::new(name, Address::new(address), 0);
    let block = fd.create_new_block();
    (fd, block)
}

fn new_anchor(fd: &mut Funcdata, block: &Block, address: u64) -> PcodeOpRef {
    let op = fd.new_op(0, Address::new(address));
    fd.op_set_opcode(&op, OpCode::CPUI_COPY);
    fd.op_insert_end(&op, block);
    op
}

fn wire(
    manager: &mut TransformManager,
    op: usize,
    inputs: usize,
    output_size: i32,
    value_base: u64,
) {
    let output = manager.new_unique(output_size);
    manager.op_set_output(op, output);
    for slot in 0..inputs {
        let input = manager.new_constant(output_size, 0, value_base + slot as u64);
        manager.op_set_input(op, input, slot);
    }
}

// wire() without the output placeholder: for preexisting ops (their real
// output is untouched) and for the output==nullptr createReplacement branch.
fn wire_inputs(manager: &mut TransformManager, op: usize, inputs: usize, size: i32, value_base: u64) {
    for slot in 0..inputs {
        let input = manager.new_constant(size, 0, value_base + slot as u64);
        manager.op_set_input(op, input, slot);
    }
}

fn anchor_state(anchor: &PcodeOpRef) -> (u8, u8) {
    let anchor_guard = anchor.0.read().unwrap();
    (
        u8::from(anchor_guard.is_dead()),
        u8::from(
            anchor_guard
                .parent
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_none(),
        ),
    )
}

fn emit(label: &str, fd: &Funcdata, block: &Block, anchor: &PcodeOpRef) {
    let (dead, detached) = anchor_state(anchor);
    println!("{label}|after={}|anchor={dead},{detached}", snapshot(fd, block));
}

fn run_replace(name: &str, address: u64, label: &str, opcode: OpCode, inputs: usize) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x8000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let first = manager.new_op_replace(inputs, opcode, anchor.clone());
    wire(&mut manager, first, inputs, 2, 0x10);
    let second = manager.new_op_replace(inputs, opcode, anchor.clone());
    wire(&mut manager, second, inputs, 2, 0x20);
    manager.apply(&mut fd);
    emit(label, &fd, &block, &anchor);
}

fn run_follow(name: &str, address: u64, label: &str, opcode: OpCode, inputs: usize) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    let first = manager.new_op(inputs, opcode, follow);
    wire(&mut manager, first, inputs, 2, 0x40);
    let second = manager.new_op(inputs, opcode, follow);
    wire(&mut manager, second, inputs, 2, 0x50);
    manager.apply(&mut fd);
    emit(label, &fd, &block, &anchor);
}

// TransformOp::createReplacement op_preexisting arm: opcode retarget plus
// input shrink (3 -> 1), clear, and grow (1 -> 3) on two already-inserted ops.
fn run_preexisting(name: &str, address: u64) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x8000);
    let shrink = fd.new_op(3, Address::new(0x8100));
    fd.op_set_opcode(&shrink, OpCode::CPUI_INT_AND);
    let shrink_out = fd.new_unique_out(4, &shrink);
    fd.op_set_output(&shrink, shrink_out);
    for slot in 0..3 {
        let input = fd.new_constant(4, 0xa0 + slot as u64);
        fd.op_set_input(&shrink, input, slot);
    }
    fd.op_insert_end(&shrink, &block);
    let grow = fd.new_op(1, Address::new(0x8200));
    fd.op_set_opcode(&grow, OpCode::CPUI_INT_OR);
    let grow_out = fd.new_unique_out(4, &grow);
    fd.op_set_output(&grow, grow_out);
    let grow_input = fd.new_constant(4, 0xb0);
    fd.op_set_input(&grow, grow_input, 0);
    fd.op_insert_end(&grow, &block);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let shrink_op = manager.new_preexisting_op(1, OpCode::CPUI_INT_XOR, shrink.clone());
    wire_inputs(&mut manager, shrink_op, 1, 4, 0x10);
    let grow_op = manager.new_preexisting_op(3, OpCode::CPUI_INT_SUB, grow.clone());
    wire_inputs(&mut manager, grow_op, 3, 4, 0x20);
    manager.apply(&mut fd);
    emit("preexisting_ops", &fd, &block, &anchor);
}

// Nested follow chain top -> mid -> follow: pass 2 inserts mid first
// (MULTIEQUAL at block begin) then top (COPY before mid).
fn run_nested_follow(name: &str, address: u64) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    let mid = manager.new_op(2, OpCode::CPUI_MULTIEQUAL, follow);
    wire(&mut manager, mid, 2, 2, 0x40);
    let top = manager.new_op(1, OpCode::CPUI_COPY, mid);
    wire(&mut manager, top, 1, 2, 0x50);
    manager.apply(&mut fd);
    emit("nested_follow", &fd, &block, &anchor);
}

// inheritIndirect + specialHandling -> markIndirectCreation flag projection.
fn run_indirect(name: &str, address: u64, label: &str, possible_output: bool) {
    let (mut fd, block) = new_function(name, address);
    let ind_op = fd.new_op(2, Address::new(0x9100));
    fd.op_set_opcode(&ind_op, OpCode::CPUI_INDIRECT);
    let ind_out = fd.new_unique_out(4, &ind_op);
    fd.op_set_output(&ind_op, ind_out);
    let ind_in0 = fd.new_constant(4, 0);
    fd.op_set_input(&ind_op, ind_in0, 0);
    let ind_in1 = fd.new_constant(4, 0x99);
    fd.op_set_input(&ind_op, ind_in1, 1);
    fd.op_insert_end(&ind_op, &block);
    fd.mark_indirect_creation(&ind_op, possible_output);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    let newind = manager.new_op(2, OpCode::CPUI_INDIRECT, follow);
    manager.new_ops[newind].inherit_indirect(&ind_op);
    wire(&mut manager, newind, 2, 2, 0x60);
    manager.apply(&mut fd);
    emit(label, &fd, &block, &anchor);
}

// Misaligned piece throw: preserve_address_override mirrors the
// MisalignManager subclass; apply() panics with the LowlevelError message and
// the pre-exception partial state is snapshotted.
fn run_piece_error(name: &str, address: u64) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x8000);
    let big = fd.new_varnode(4, Address::new(0x2000));
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    manager.set_preserve_address_override(|_, _, _| true);
    let rep = manager.new_op_replace(2, OpCode::CPUI_INT_ADD, anchor.clone());
    wire(&mut manager, rep, 2, 2, 0x10);
    manager.new_piece(big, 8, 4);
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        manager.apply(&mut fd);
    }));
    std::panic::set_hook(previous_hook);
    let message = match result {
        Ok(()) => String::new(),
        Err(payload) => payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default(),
    };
    let (dead, detached) = anchor_state(&anchor);
    println!(
        "piece_error|msg={message}|after={}|anchor={dead},{detached}",
        snapshot(&fd, &block)
    );
}

// createReplacement with output == nullptr: replacement ops with no output.
fn run_output_null(name: &str, address: u64) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    let _bare = manager.new_op(0, OpCode::CPUI_COPY, follow);
    let bare_phi = manager.new_op(2, OpCode::CPUI_MULTIEQUAL, follow);
    wire_inputs(&mut manager, bare_phi, 2, 2, 0x70);
    manager.apply(&mut fd);
    emit("output_null", &fd, &block, &anchor);
}

// SeqNum midpoint exhaustion: 25 MULTIEQUAL begin-insertions force
// BlockBasic::setOrder renumbering.
fn run_seqnum(name: &str, address: u64) {
    let (mut fd, block) = new_function(name, address);
    let anchor = new_anchor(&mut fd, &block, 0x9000);
    let mut manager = TransformManager::new();
    manager.init(&mut fd);
    let follow = manager.new_op_replace(1, OpCode::CPUI_COPY, anchor.clone());
    wire(&mut manager, follow, 1, 2, 0x30);
    for i in 0..25u64 {
        let extra = manager.new_op(2, OpCode::CPUI_MULTIEQUAL, follow);
        wire(&mut manager, extra, 2, 2, 0x100 + i);
    }
    manager.apply(&mut fd);
    emit("seqnum_renumber", &fd, &block, &anchor);
}

fn main() {
    run_replace("GetStr", 0x36d0, "replace_phi", OpCode::CPUI_MULTIEQUAL, 2);
    run_follow(
        "main_free",
        0x4970,
        "follow_phi",
        OpCode::CPUI_MULTIEQUAL,
        2,
    );
    run_replace("hugehelp", 0x4a00, "replace_copy", OpCode::CPUI_COPY, 1);
    run_follow("main_init", 0x4960, "follow_copy", OpCode::CPUI_COPY, 1);
    run_preexisting("my_fwrite", 0x3460);
    run_nested_follow("myprogress", 0x34d0);
    run_indirect("my_get_token", 0x3720, "indirect_zero", false);
    run_indirect("my_get_line", 0x3840, "indirect_possible", true);
    run_piece_error("helpf", 0x3980);
    run_output_null("glob_word", 0x4a60);
    run_seqnum("glob_set", 0x4bc0);
}
