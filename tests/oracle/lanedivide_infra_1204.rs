//! LANEDIVIDE-INFRA-0001 Rudra comparand.

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::subflow::LaneDivide;
use rudra::transform::{LaneDescription, LanedRegister};
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
    /// Constants naming a space for a LOAD/STORE (SpaceId encoded in Rudra,
    /// AddrSpace pointer in the oracle; observed as the resolved index).
    spaceid_constants: std::collections::HashSet<usize>,
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
            spaceid_constants: std::collections::HashSet::new(),
        };
        for op_index in 0..result.ops.len() {
            let (output, inputs, opcode) = {
                let op = result.ops[op_index].0.read().unwrap();
                (op.get_out().cloned(), op.inrefs.clone(), op.opcode)
            };
            if matches!(opcode, OpCode::CPUI_STORE | OpCode::CPUI_LOAD) && !inputs.is_empty() {
                result
                    .spaceid_constants
                    .insert(Arc::as_ptr(&inputs[0]) as usize);
            }
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
                "o{index}:{}@{}/t{}/r{}/d{}/c{}/p{parent}/o{}/i",
                op.opcode as i32,
                op.get_addr().as_u64(),
                op.start.get_time(),
                op.start.get_order(),
                u8::from(op.is_dead()),
                u8::from(op.is_indirect_creation()),
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
            let varnode_ptr = Arc::as_ptr(varnode) as usize;
            let varnode = varnode.read().unwrap();
            let space = varnode.get_space();
            write!(
                output,
                "v{index}:c{}/s{}/",
                varnode.create_index,
                varnode.get_size(),
            )
            .unwrap();
            if matches!(space, AddressSpace::Iop) {
                output.push_str("si/k0");
            } else {
                write!(output, "sp{}/k{}", space.space_id(), u8::from(varnode.is_constant())).unwrap();
            }
            if varnode.is_constant() {
                if self.spaceid_constants.contains(&varnode_ptr) {
                    write!(
                        output,
                        ":s{}",
                        AddressSpace::from_id(varnode.get_offset() as rudra::space::SpaceId)
                            .space_id()
                    )
                    .unwrap();
                } else if !matches!(space, AddressSpace::Iop) {
                    write!(output, ":{}", varnode.get_offset()).unwrap();
                }
            }
            write!(
                output,
                "/f{}/t{}/q{}/n{}/w{}/d{}/u",
                u8::from(varnode.is_free()),
                u8::from(varnode.is_type_lock()),
                u8::from(varnode.is_indirect_creation()),
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
    at_begin: bool,
) -> (PcodeOpRef, Arc<RwLock<Varnode>>) {
    let op = fd.new_op(inputs, Address::new(pc));
    fd.op_set_opcode(&op, opcode);
    let output = fd.new_unique_out(output_size, &op);
    if at_begin {
        fd.op_insert_begin(&op, block);
    } else {
        fd.op_insert_end(&op, block);
    }
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

fn run_lane_map(architecture: &Arc<Architecture>) {
    let lookup_a = architecture
        .get_laned_register(Address::new(0x10), 16)
        .unwrap();
    let lookup_b = architecture
        .get_laned_register(Address::new(0xdead), 16)
        .unwrap();
    println!(
        "arch|min={}|sizes={},{}|lookup16={}:{}|same={}|missing12={}",
        architecture.get_minimum_laned_register_size(),
        architecture.lane_records[0].get_whole_size(),
        architecture.lane_records[1].get_whole_size(),
        lookup_a.get_whole_size(),
        lookup_a.get_size_bit_mask(),
        u8::from(Arc::ptr_eq(&lookup_a, &lookup_b)),
        u8::from(
            architecture
                .get_laned_register(Address::new(0), 12)
                .is_none()
        ),
    );

    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
    fd.set_arch(architecture.clone());
    let initial = fd.laned_map.len();
    fd.check_for_laned_register(12, AddressSpace::Register, Address::new(0x20));
    let after_miss = fd.laned_map.len();
    fd.check_for_laned_register(8, AddressSpace::Register, Address::new(0x20));
    fd.check_for_laned_register(16, AddressSpace::Register, Address::new(0x20));
    fd.check_for_laned_register(8, AddressSpace::Unique, Address::new(5));
    let before = lane_map(&fd, architecture);
    let before_generated = fd.laned_map.len();
    fd.set_laned_reg_generated();
    let suppressed = fd.new_op(0, Address::new(0x4100));
    let _ = fd.new_varnode_out(16, Address::new(0x40), &suppressed);
    let after_generated = fd.laned_map.len();
    fd.clear();
    let after_clear = fd.laned_map.len();
    let recorded = fd.new_op(0, Address::new(0x4101));
    let _ = fd.new_varnode_out(16, Address::new(0x40), &recorded);
    let after_reset = lane_map(&fd, architecture);
    fd.clear_laned_access_map();
    println!(
        "map|miss_delta={}|before={before}|generated_delta={}|clear_preserved={after_clear}|reset={after_reset}|explicit_clear={}",
        after_miss - initial,
        after_generated - before_generated,
        fd.laned_map.len(),
    );
}

fn new_function(name: &str, address: u64, architecture: &Arc<Architecture>) -> (Funcdata, Block) {
    let mut fd = Funcdata::new(name, Address::new(address), 0);
    fd.set_arch(architecture.clone());
    let block = fd.create_new_block();
    (fd, block)
}

fn run_piece(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_free", 0x4970, architecture);
    let (piece, root) = new_output_op(&mut fd, &block, OpCode::CPUI_PIECE, 0x5000, 2, 4, false);
    let high_input = fd.new_constant(2, 0x1122);
    let low_input = fd.new_constant(2, 0x3344);
    fd.op_set_input(&piece, high_input, 0);
    fd.op_set_input(&piece, low_input, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let (high, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x5002, 2, 2, false);
    fd.op_set_input(&high, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&high, two, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let mark = root.read().unwrap().is_mark();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "piece|trace={}|mark={}|before={before}|after={after}|old={},{},{},{},{},{}",
        u8::from(traced),
        u8::from(mark),
        u8::from(piece.0.read().unwrap().is_dead()),
        u8::from(piece.0.read().unwrap().get_out().is_none()),
        low.0.read().unwrap().opcode as i32,
        low.0.read().unwrap().num_input(),
        high.0.read().unwrap().opcode as i32,
        high.0.read().unwrap().num_input(),
    );
}

fn run_multiequal(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("hugehelp", 0x4a00, architecture);
    let (phi, root) = new_output_op(
        &mut fd,
        &block,
        OpCode::CPUI_MULTIEQUAL,
        0x6000,
        2,
        4,
        true,
    );
    let left = fd.new_constant(4, 0x11223344);
    let right = fd.new_constant(4, 0x55667788);
    fd.op_set_input(&phi, left, 0);
    fd.op_set_input(&phi, right, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x6001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let (high, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x6002, 2, 2, false);
    fd.op_set_input(&high, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&high, two, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let mark = root.read().unwrap().is_mark();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "multiequal|trace={}|mark={}|before={before}|after={after}|old={},{},{},{},{},{}",
        u8::from(traced),
        u8::from(mark),
        u8::from(phi.0.read().unwrap().is_dead()),
        u8::from(phi.0.read().unwrap().get_out().is_none()),
        low.0.read().unwrap().opcode as i32,
        low.0.read().unwrap().num_input(),
        high.0.read().unwrap().opcode as i32,
        high.0.read().unwrap().num_input(),
    );
}

fn run_failure(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("main_init", 0x4960, architecture);
    let (multiply, root) = new_output_op(
        &mut fd,
        &block,
        OpCode::CPUI_INT_MULT,
        0x7000,
        2,
        4,
        false,
    );
    let left = fd.new_constant(4, 3);
    let right = fd.new_constant(4, 7);
    fd.op_set_input(&multiply, left, 0);
    fd.op_set_input(&multiply, right, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x7001, 2, 2, false);
    fd.op_set_input(&low, root.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    let after = snapshot(&fd, &block);
    println!(
        "failure|trace={}|same={}|mark={}|before={before}|after={after}",
        u8::from(traced),
        u8::from(before == after),
        u8::from(root.read().unwrap().is_mark()),
    );
}

fn new_store_op(fd: &mut Funcdata, block: &Block, pc: u64) -> PcodeOpRef {
    let op = fd.new_op(3, Address::new(pc));
    fd.op_set_opcode(&op, OpCode::CPUI_STORE);
    fd.op_insert_end(&op, block);
    op
}

fn run_subpiece_terminator(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("glob_range", 0x4d60, architecture);
    let (copy, root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8000, 1, 8, false);
    let input = fd.new_constant(8, 0x0102_0304_0506_0708);
    fd.op_set_input(&copy, input, 0);
    let (mid, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8001, 2, 1, false);
    fd.op_set_input(&mid, root.clone(), 0);
    let four = fd.new_constant(4, 4);
    fd.op_set_input(&mid, four, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(8, 2), true);
    let traced = divide.do_trace();
    let mark = root.read().unwrap().is_mark();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    let (mid_dead, mid_code, mid_inputs, mid_const, mid_offset, mid_size) = {
        let op = mid.0.read().unwrap();
        let input1 = op.get_in(1).cloned().unwrap();
        let (input1_const, input1_offset) = {
            let input1 = input1.read().unwrap();
            (u8::from(input1.is_constant()), input1.get_offset() as i64)
        };
        let input0 = op.get_in(0).cloned().unwrap();
        let input0_size = input0.read().unwrap().get_size();
        (
            u8::from(op.is_dead()),
            op.opcode as i32,
            op.num_input(),
            input1_const,
            input1_offset,
            input0_size,
        )
    };
    println!(
        "subpiece|trace={}|mark={}|before={before}|after={after}|old={}|mid={},{},{},{},{},{}",
        u8::from(traced),
        u8::from(mark),
        u8::from(copy.0.read().unwrap().is_dead()),
        mid_dead,
        mid_code,
        mid_inputs,
        mid_const,
        mid_offset,
        mid_size,
    );
}

fn run_store(architecture: &Arc<Architecture>) {
    let ram_index = rudra::space::SPACEID_RAM as u64;
    let (mut fd, block) = new_function("glob_set", 0x4bc0, architecture);
    let (copy, root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8100, 1, 4, false);
    let value = fd.new_constant(4, 0x1122_3344);
    fd.op_set_input(&copy, value, 0);
    let (pointer_copy, pointer) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8101, 1, 8, false);
    let pointer_input = fd.new_constant(8, 0x1000);
    fd.op_set_input(&pointer_copy, pointer_input, 0);
    let store_a = new_store_op(&mut fd, &block, 0x8102);
    let space_a = fd.new_varnode_space(AddressSpace::Ram);
    fd.op_set_input(&store_a, space_a, 0);
    fd.op_set_input(&store_a, pointer, 1);
    fd.op_set_input(&store_a, root.clone(), 2);
    let store_b = new_store_op(&mut fd, &block, 0x8103);
    let space_b = fd.new_varnode_space(AddressSpace::Ram);
    fd.op_set_input(&store_b, space_b, 0);
    let pointer_b = fd.new_constant(8, 0x2000);
    fd.op_set_input(&store_b, pointer_b, 1);
    fd.op_set_input(&store_b, root.clone(), 2);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    let (store_count, add_count) = {
        let block_ref = block.read().unwrap();
        let mut store_count = 0;
        let mut add_count = 0;
        for op in block_ref.get_ops() {
            let op = op.0.read().unwrap();
            if op.is_dead() {
                continue;
            }
            match op.opcode {
                OpCode::CPUI_STORE => store_count += 1,
                OpCode::CPUI_INT_ADD => add_count += 1,
                _ => {}
            }
        }
        (store_count, add_count)
    };
    println!(
        "store|trace={}|sp={ram_index}|before={before}|after={after}|old={},{},{}|split={store_count},{add_count}",
        u8::from(traced),
        u8::from(copy.0.read().unwrap().is_dead()),
        u8::from(store_a.0.read().unwrap().is_dead()),
        u8::from(store_b.0.read().unwrap().is_dead()),
    );
}

fn run_load(architecture: &Arc<Architecture>) {
    let ram_index = rudra::space::SPACEID_RAM as u64;
    let (mut fd, block) = new_function("glob_url", 0x4f70, architecture);
    let (load, root) = new_output_op(&mut fd, &block, OpCode::CPUI_LOAD, 0x8200, 2, 4, false);
    let space_input = fd.new_varnode_space(AddressSpace::Ram);
    fd.op_set_input(&load, space_input, 0);
    let pointer = fd.new_constant(8, 0x3000);
    fd.op_set_input(&load, pointer, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root.clone(), LaneDescription::uniform(4, 2), false);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    let load_count = {
        let block_ref = block.read().unwrap();
        block_ref
            .get_ops()
            .iter()
            .filter(|op| {
                let op = op.0.read().unwrap();
                !op.is_dead() && op.opcode == OpCode::CPUI_LOAD
            })
            .count()
    };
    println!(
        "load|trace={}|sp={ram_index}|before={before}|after={after}|old={}|split={load_count}",
        u8::from(traced),
        u8::from(load.0.read().unwrap().is_dead()),
    );
}

fn run_right_shift(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("glob_word", 0x4a60, architecture);
    let (copy, source) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8300, 1, 8, false);
    let input = fd.new_constant(8, 0x0102_0304_0506_0708);
    fd.op_set_input(&copy, input, 0);
    let (shift, root) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_RIGHT, 0x8301, 2, 8, false);
    fd.op_set_input(&shift, source, 0);
    let amount = fd.new_constant(4, 16);
    fd.op_set_input(&shift, amount, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root, LaneDescription::uniform(8, 2), false);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "rightshift|trace={}|before={before}|after={after}|old={},{}",
        u8::from(traced),
        u8::from(copy.0.read().unwrap().is_dead()),
        u8::from(shift.0.read().unwrap().is_dead()),
    );
}

fn run_left_shift(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("match_url", 0x5220, architecture);
    let (copy, source) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8400, 1, 8, false);
    let input = fd.new_constant(8, 0x1122_3344_5566_7788);
    fd.op_set_input(&copy, input, 0);
    let (shift, root) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_LEFT, 0x8401, 2, 8, false);
    fd.op_set_input(&shift, source, 0);
    let amount = fd.new_constant(4, 16);
    fd.op_set_input(&shift, amount, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root, LaneDescription::uniform(8, 2), false);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "leftshift|trace={}|before={before}|after={after}|old={},{}",
        u8::from(traced),
        u8::from(copy.0.read().unwrap().is_dead()),
        u8::from(shift.0.read().unwrap().is_dead()),
    );
}

fn run_zext(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("my_fwrite", 0x3460, architecture);
    let (copy, source) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8500, 1, 4, false);
    let input = fd.new_constant(4, 0xaabb_ccdd);
    fd.op_set_input(&copy, input, 0);
    let (zext, root) = new_output_op(&mut fd, &block, OpCode::CPUI_INT_ZEXT, 0x8501, 1, 8, false);
    fd.op_set_input(&zext, source, 0);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root, LaneDescription::uniform(8, 2), false);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "zext|trace={}|before={before}|after={after}|old={},{}",
        u8::from(traced),
        u8::from(copy.0.read().unwrap().is_dead()),
        u8::from(zext.0.read().unwrap().is_dead()),
    );
}

fn run_indirect(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("myprogress", 0x34d0, architecture);

    let clobber_a = new_store_op(&mut fd, &block, 0x8600);
    let space_a = fd.new_varnode_space(AddressSpace::Ram);
    fd.op_set_input(&clobber_a, space_a, 0);
    let pointer_a = fd.new_constant(8, 0x4000);
    fd.op_set_input(&clobber_a, pointer_a, 1);
    let value_a = fd.new_constant(4, 0x99);
    fd.op_set_input(&clobber_a, value_a, 2);
    let (indirect_a, root_a) = new_output_op(&mut fd, &block, OpCode::CPUI_INDIRECT, 0x8601, 2, 4, false);
    let indirect_input_a = fd.new_constant(4, 0x1122_3344);
    fd.op_set_input(&indirect_a, indirect_input_a, 0);
    let iop_a = fd.new_varnode_iop(&clobber_a);
    fd.op_set_input(&indirect_a, iop_a, 1);
    fd.mark_indirect_creation(&indirect_a, false);

    let clobber_b = new_store_op(&mut fd, &block, 0x8602);
    let space_b = fd.new_varnode_space(AddressSpace::Ram);
    fd.op_set_input(&clobber_b, space_b, 0);
    let pointer_b = fd.new_constant(8, 0x4100);
    fd.op_set_input(&clobber_b, pointer_b, 1);
    let value_b = fd.new_constant(4, 0x88);
    fd.op_set_input(&clobber_b, value_b, 2);
    let (indirect_b, root_b) = new_output_op(&mut fd, &block, OpCode::CPUI_INDIRECT, 0x8603, 2, 4, false);
    let indirect_input_b = fd.new_constant(4, 0x5566_7788);
    fd.op_set_input(&indirect_b, indirect_input_b, 0);
    let iop_b = fd.new_varnode_iop(&clobber_b);
    fd.op_set_input(&indirect_b, iop_b, 1);
    fd.mark_indirect_creation(&indirect_b, true);

    let before = snapshot(&fd, &block);
    let flag_a = u8::from(root_a.read().unwrap().is_indirect_creation());
    let flag_b = u8::from(root_b.read().unwrap().is_indirect_creation());
    let mut divide_a =
        LaneDivide::new(&mut fd, root_a, LaneDescription::uniform(4, 2), false);
    let traced_a = divide_a.do_trace();
    if traced_a {
        divide_a.apply(&mut fd);
    }
    let middle = snapshot(&fd, &block);
    let mut divide_b =
        LaneDivide::new(&mut fd, root_b, LaneDescription::uniform(4, 2), false);
    let traced_b = divide_b.do_trace();
    if traced_b {
        divide_b.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    let (indirect_count, flagged_count) = {
        let block_ref = block.read().unwrap();
        let mut indirect_count = 0;
        let mut flagged_count = 0;
        for op in block_ref.get_ops() {
            let op = op.0.read().unwrap();
            if op.is_dead() {
                continue;
            }
            if op.opcode == OpCode::CPUI_INDIRECT {
                indirect_count += 1;
                if op.is_indirect_creation() {
                    flagged_count += 1;
                }
            }
        }
        (indirect_count, flagged_count)
    };
    println!(
        "indirect|trace={},{}|before={before}|middle={middle}|after={after}|old={},{}|flagA={flag_a}|flagB={flag_b}|split={indirect_count},{flagged_count}",
        u8::from(traced_a),
        u8::from(traced_b),
        u8::from(indirect_a.0.read().unwrap().is_dead()),
        u8::from(indirect_b.0.read().unwrap().is_dead()),
    );
}

fn run_restricted_window(architecture: &Arc<Architecture>) {
    let (mut fd, block) = new_function("next_url", 0x4ff0, architecture);
    let (copy, root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8700, 1, 8, false);
    let input = fd.new_constant(8, 0x0102_0304_0506_0708);
    fd.op_set_input(&copy, input, 0);
    let (mid, middle) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8701, 2, 4, false);
    fd.op_set_input(&mid, root.clone(), 0);
    let two = fd.new_constant(4, 2);
    fd.op_set_input(&mid, two, 1);
    let (tail, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8702, 2, 1, false);
    fd.op_set_input(&tail, middle.clone(), 0);
    let tail_offset = fd.new_constant(4, 2);
    fd.op_set_input(&tail, tail_offset, 1);
    let (low, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8703, 2, 2, false);
    fd.op_set_input(&low, middle.clone(), 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&low, zero, 1);
    let before = snapshot(&fd, &block);
    let mut divide = LaneDivide::new(&mut fd, root, LaneDescription::uniform(8, 2), true);
    let traced = divide.do_trace();
    if traced {
        divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    let (tail_dead, tail_code, tail_inputs, low_dead, low_code, low_inputs) = {
        let tail = tail.0.read().unwrap();
        let low = low.0.read().unwrap();
        (
            u8::from(tail.is_dead()),
            tail.opcode as i32,
            tail.num_input(),
            u8::from(low.is_dead()),
            low.opcode as i32,
            low.num_input(),
        )
    };
    println!(
        "window|trace={}|before={before}|after={after}|old={},{}|tail={},{},{}|low={},{},{}",
        u8::from(traced),
        u8::from(copy.0.read().unwrap().is_dead()),
        u8::from(mid.0.read().unwrap().is_dead()),
        tail_dead,
        tail_code,
        tail_inputs,
        low_dead,
        low_code,
        low_inputs,
    );
}

fn run_typelock(architecture: &Arc<Architecture>) {
    let types = architecture
        .types
        .clone()
        .expect("type factory installed in main");
    let int_type = types
        .read()
        .unwrap()
        .get_base(4, rudra::type_system::datatype::TypeMetatype::Int)
        .expect("int4 base type");
    let struct_type = types.write().unwrap().create_struct("lanepair");
    let uint_type = types
        .read()
        .unwrap()
        .get_base(1, rudra::type_system::datatype::TypeMetatype::Uint)
        .expect("uint1 base type");
    let array_type = types.write().unwrap().get_array(uint_type, 4);

    let (mut fd, block) = new_function("progressbarinit", 0x49a0, architecture);
    let int_input = fd.new_unique(4);
    int_input.write().unwrap().update_type_lock(int_type, true, false);
    let (int_copy, int_root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8800, 1, 4, false);
    fd.op_set_input(&int_copy, int_input.clone(), 0);
    let (int_reader, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8801, 2, 2, false);
    fd.op_set_input(&int_reader, int_root.clone(), 0);
    let zero1 = fd.new_constant(4, 0);
    fd.op_set_input(&int_reader, zero1, 1);

    let struct_input = fd.new_unique(4);
    struct_input
        .write()
        .unwrap()
        .update_type_lock(struct_type, true, false);
    let (struct_copy, struct_root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8802, 1, 4, false);
    fd.op_set_input(&struct_copy, struct_input.clone(), 0);
    let (struct_reader, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8803, 2, 2, false);
    fd.op_set_input(&struct_reader, struct_root.clone(), 0);
    let zero2 = fd.new_constant(4, 0);
    fd.op_set_input(&struct_reader, zero2, 1);

    let array_input = fd.new_unique(4);
    array_input
        .write()
        .unwrap()
        .update_type_lock(array_type, true, false);
    let (array_copy, array_root) = new_output_op(&mut fd, &block, OpCode::CPUI_COPY, 0x8804, 1, 4, false);
    fd.op_set_input(&array_copy, array_input.clone(), 0);
    let (array_reader, _) = new_output_op(&mut fd, &block, OpCode::CPUI_SUBPIECE, 0x8805, 2, 2, false);
    fd.op_set_input(&array_reader, array_root.clone(), 0);
    let zero3 = fd.new_constant(4, 0);
    fd.op_set_input(&array_reader, zero3, 1);

    let before = snapshot(&fd, &block);
    let mut int_divide =
        LaneDivide::new(&mut fd, int_root.clone(), LaneDescription::uniform(4, 2), false);
    let traced_int = int_divide.do_trace();
    let after_int = snapshot(&fd, &block);
    let mut struct_divide =
        LaneDivide::new(&mut fd, struct_root.clone(), LaneDescription::uniform(4, 2), false);
    let traced_struct = struct_divide.do_trace();
    let after_struct = snapshot(&fd, &block);
    let mut array_divide =
        LaneDivide::new(&mut fd, array_root, LaneDescription::uniform(4, 2), false);
    let traced_array = array_divide.do_trace();
    if traced_array {
        array_divide.apply(&mut fd);
    }
    let after = snapshot(&fd, &block);
    println!(
        "typelock|trace={},{},{}|same={},{}|mark={},{}|lock={},{},{}|before={before}|afterInt={after_int}|afterStruct={after_struct}|after={after}",
        u8::from(traced_int),
        u8::from(traced_struct),
        u8::from(traced_array),
        u8::from(before == after_int),
        u8::from(after_int == after_struct),
        u8::from(int_root.read().unwrap().is_mark()),
        u8::from(struct_root.read().unwrap().is_mark()),
        u8::from(int_input.read().unwrap().is_type_lock()),
        u8::from(struct_input.read().unwrap().is_type_lock()),
        u8::from(array_input.read().unwrap().is_type_lock()),
    );
}

fn main() {
    let mut architecture = Architecture::new();
    architecture.set_lane_records(vec![
        LanedRegister::with_sizes(8, 1 << 2),
        LanedRegister::with_sizes(16, (1 << 4) | (1 << 8)),
    ]);
    let _ = architecture.ensure_types();
    let architecture = Arc::new(architecture);
    run_lane_map(&architecture);
    run_piece(&architecture);
    run_multiequal(&architecture);
    run_failure(&architecture);
    run_subpiece_terminator(&architecture);
    run_store(&architecture);
    run_load(&architecture);
    run_right_shift(&architecture);
    run_left_shift(&architecture);
    run_zext(&architecture);
    run_indirect(&architecture);
    run_restricted_window(&architecture);
    run_typelock(&architecture);
}
