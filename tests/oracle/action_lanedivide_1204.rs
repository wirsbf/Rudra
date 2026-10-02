//! ACTION-LANEDIVIDE-0001 Rugra comparand.
//!
//! Drives the real `ActionLaneDivide` (rudra::coreaction) through the
//! public `Action::perform` state machine, mirroring the locked-oracle
//! C++ fixture observation for observation.

use rudra::action::{Action, ActionState, action_flags};
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::coreaction::ActionLaneDivide;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::transform::LanedRegister;
use rudra::varnode::Varnode;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, RwLock};

type Block = Arc<RwLock<dyn FlowBlock + Send + Sync>>;

struct GraphProjection {
    ops: Vec<PcodeOpRef>,
    op_index: HashMap<usize, usize>,
    vars: Vec<Arc<RwLock<Varnode>>>,
    var_index: HashMap<usize, usize>,
}

impl GraphProjection {
    fn new(block: &Block) -> Self {
        let ops = block.read().unwrap().get_ops();
        let op_index = ops
            .iter()
            .enumerate()
            .map(|(index, op)| (Arc::as_ptr(&op.0) as usize, index))
            .collect();
        let mut result = Self {
            ops,
            op_index,
            vars: Vec::new(),
            var_index: HashMap::new(),
        };
        for op_index in 0..result.ops.len() {
            let (output, inputs) = {
                let op = result.ops[op_index].0.read().unwrap();
                (op.get_out().cloned(), op.inrefs.clone())
            };
            result.touch(output);
            for input in inputs {
                result.touch(Some(input));
            }
        }
        result
    }

    fn touch(&mut self, varnode: Option<Arc<RwLock<Varnode>>>) {
        let Some(varnode) = varnode else { return };
        let pointer = Arc::as_ptr(&varnode) as usize;
        if self.var_index.contains_key(&pointer) {
            return;
        }
        self.var_index.insert(pointer, self.vars.len());
        self.vars.push(varnode);
    }

    fn var_name(&self, varnode: Option<&Arc<RwLock<Varnode>>>) -> String {
        let Some(varnode) = varnode else {
            return "_".to_string();
        };
        self.var_index
            .get(&(Arc::as_ptr(varnode) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("v{index}"))
    }

    fn op_name(&self, op: Option<&Arc<RwLock<rudra::op::PcodeOp>>>) -> String {
        let Some(op) = op else {
            return "_".to_string();
        };
        self.op_index
            .get(&(Arc::as_ptr(op) as usize))
            .map_or_else(|| "x".to_string(), |index| format!("o{index}"))
    }

    fn render(&self, fd: &Funcdata, block: &Block) -> String {
        let mut output = String::new();
        output.push_str("ops[");
        for (index, op) in self.ops.iter().enumerate() {
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
                "o{index}:{}@{}/t{}/r{}/d{}/p{parent}/o{}/i",
                op.opcode as i32,
                op.get_addr().as_u64(),
                op.start.get_time(),
                op.start.get_order(),
                u8::from(op.is_dead()),
                self.var_name(op.get_out()),
            )
            .unwrap();
            for (slot, input) in op.inrefs.iter().enumerate() {
                if slot != 0 {
                    output.push(',');
                }
                output.push_str(&self.var_name(Some(input)));
            }
        }
        output.push_str("]vars[");
        for (index, varnode) in self.vars.iter().enumerate() {
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
                "/f{}/n{}/w{}/d{}/u",
                u8::from(varnode.is_free()),
                u8::from(varnode.is_input()),
                u8::from(varnode.is_written()),
                self.op_name(varnode.get_def().as_ref()),
            )
            .unwrap();
            for (use_index, descendant) in varnode.descend_iter().enumerate() {
                if use_index != 0 {
                    output.push(',');
                }
                output.push_str(&self.op_name(Some(&descendant)));
            }
        }
        write!(
            output,
            "]count={},{},{},{},{},{}",
            self.ops.len(),
            self.vars.len(),
            fd.obank.alivelist.len(),
            fd.obank.deadlist.len(),
            fd.obank.optree.len(),
            fd.vbank.num_varnodes(),
        )
        .unwrap();
        output
    }
}

fn snapshot(fd: &Funcdata, block: &Block) -> String {
    GraphProjection::new(block).render(fd, block)
}

fn new_output_op(
    fd: &mut Funcdata,
    block: &Block,
    opcode: OpCode,
    pc: u64,
    inputs: usize,
    output_size: usize,
) -> (PcodeOpRef, Arc<RwLock<Varnode>>) {
    let op = fd.new_op(inputs, Address::new(pc));
    fd.op_set_opcode(&op, opcode);
    let output = fd.new_unique_out(output_size, &op);
    fd.op_insert_end(&op, block);
    (op, output)
}

fn lane_map(fd: &Funcdata, architecture: &Architecture) -> String {
    fd.lane_accesses()
        .map(|(storage, record)| {
            let identity = architecture
                .lane_records
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, record))
                .map_or(-1, |index| index as i32);
            format!(
                "{}:{}:{}=r{}:{}:{}",
                storage.space.space_id(),
                storage.offset,
                storage.size,
                identity,
                record.get_whole_size(),
                record.get_size_bit_mask(),
            )
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn new_function(name: &str, address: u64, architecture: &Arc<Architecture>) -> (Funcdata, Block) {
    let mut fd = Funcdata::new(name, Address::new(address), 0);
    fd.set_arch(architecture.clone());
    let block = fd.create_new_block();
    (fd, block)
}

fn run_piece(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_free", 0x4970, architecture);
    let (piece, root) = new_output_op(&mut fd, &block, OpCode::CPUI_PIECE, 0x5000, 2, 4);
    let high_input = fd.new_constant(2, 0x1122);
    let low_input = fd.new_constant(2, 0x3344);
    fd.op_set_input(&piece, high_input, 0);
    fd.op_set_input(&piece, low_input, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5001, 2, 2);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let (high, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5002, 2, 2);
    fd.op_set_input(&high, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&high, two, 1);
    let map_before = lane_map(&fd, architecture);
    let ir_before = snapshot(&fd, &block);
    let mut action = ActionLaneDivide::new();
    let mut state = ActionState::new(action_flags::RULE_ONCEPERFUNC);
    let ret1 = action
        .perform(&mut fd, &mut state)
        .expect("first perform");
    let map_after = lane_map(&fd, architecture);
    let ir_after = snapshot(&fd, &block);
    fd.check_for_laned_register(16, AddressSpace::Register, Address::new(0x77));
    let map_requeued = lane_map(&fd, architecture);
    let ret2 = action
        .perform(&mut fd, &mut state)
        .expect("second perform");
    let map_after_second = lane_map(&fd, architecture);
    let ir_after_second = snapshot(&fd, &block);
    println!(
        "piece|ret1={ret1}|count={}|status={}|map={map_before}>{map_after}|requeued={map_requeued}|ret2={ret2}|map2={map_after_second}|status2={}|count2={}|irStable={}|before={ir_before}|after={ir_after}",
        state.count,
        state.status,
        state.status,
        state.count,
        u8::from(ir_after == ir_after_second),
    );
}

fn run_failure(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_init", 0x4960, architecture);
    let (multiply, root) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_MULT, 0x7000, 2, 16);
    let left = fd.new_constant(16, 0x1122334455667788);
    let right = fd.new_constant(16, 0x99aabbccddeeff00);
    fd.op_set_input(&multiply, left, 0);
    fd.op_set_input(&multiply, right, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x7001, 2, 2);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let map_before = lane_map(&fd, architecture);
    let ir_before = snapshot(&fd, &block);
    let mut action = ActionLaneDivide::new();
    let mut state = ActionState::new(action_flags::RULE_ONCEPERFUNC);
    let ret1 = action
        .perform(&mut fd, &mut state)
        .expect("failure perform");
    let map_after = lane_map(&fd, architecture);
    let ir_after = snapshot(&fd, &block);
    println!(
        "failure|ret1={ret1}|count={}|status={}|map={map_before}>{map_after}|irSame={}|before={ir_before}|after={ir_after}",
        state.count,
        state.status,
        u8::from(ir_before == ir_after),
    );
}

fn main() {
    let mut architecture = Architecture::new();
    architecture.set_lane_records(vec![
        LanedRegister::with_sizes(4, 1 << 2),
        LanedRegister::with_sizes(16, 1 << 8),
    ]);
    let architecture = Arc::new(architecture);
    // Project the normalized mode-2 default lane size (what
    // process_varnode actually consumes, mirroring coreaction.cc:566-569),
    // not the raw pointer size: the C++ oracle reads a spec-configured
    // TypeFactory while this comparand drives a bare Architecture whose
    // TypeFactory is unconfigured; the !=4 normalization maps both to the
    // same default lane.
    let mut default_size = architecture
        .types
        .as_ref()
        .map(|types| types.read().unwrap().get_size_of_pointer())
        .unwrap_or(0);
    if default_size != 4 {
        default_size = 8;
    }
    println!(
        "arch|default={default_size}|min={}|sizes={},{}",
        architecture.get_minimum_laned_register_size(),
        architecture.lane_records[0].get_whole_size(),
        architecture.lane_records[1].get_whole_size(),
    );
    run_piece(&architecture);
    run_failure(&architecture);
}
