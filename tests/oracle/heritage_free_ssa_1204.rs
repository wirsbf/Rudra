// HERITAGE-FREE-SSA-FIXTURE-0001
//
// Rust comparand for tests/oracle/heritage_free_ssa_1204.cc.  The four cases
// are driven through the same public Funcdata construction APIs and the
// canonical `op_heritage` boundary.  Object pointers are represented only by
// first-seen alias ids; block order, op order, input slot order, alias
// relations, flags, definitions and descendant counts remain observable.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type OpRef = Arc<RwLock<PcodeOp>>;
type VnRef = Arc<RwLock<Varnode>>;

fn read_op(op: &OpRef) -> RwLockReadGuard<'_, PcodeOp> {
    op.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read_vn(vn: &VnRef) -> RwLockReadGuard<'_, Varnode> {
    vn.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn opcode_name(opcode: OpCode) -> &'static str {
    match opcode {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_INT_ADD => "INT_ADD",
        OpCode::CPUI_INT_OR => "INT_OR",
        OpCode::CPUI_INDIRECT => "INDIRECT",
        OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
        _ => "OTHER",
    }
}

fn before_state(vn: &VnRef) -> String {
    let value = read_vn(vn);
    format!(
        "free={},desc={},flags={:x},active={},known={},def={}",
        u8::from(value.is_free()),
        value.count_descends(),
        value.flags,
        u8::from(value.is_active_heritage()),
        u8::from(value.is_heritage_known()),
        if value.get_def().is_some() {
            "set"
        } else {
            "none"
        },
    )
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_pc: u64,
    ops: Vec<(OpRef, &'static str, usize)>,
    blocks: Vec<(BlockRef, &'static str)>,
    aliases: HashMap<usize, usize>,
    next_alias: usize,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Self {
            fd: Funcdata::new(name, Address::new(base), 0x40),
            base,
            next_pc: 0,
            ops: Vec::new(),
            blocks: Vec::new(),
            aliases: HashMap::new(),
            next_alias: 0,
        }
    }

    fn block(&mut self, name: &'static str) -> BlockRef {
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
            self.blocks.len() as i32,
            Address::new(0),
        )));
        self.fd.bblocks.add_block(block.clone());
        self.blocks.push((block.clone(), name));
        block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let op = self
            .fd
            .new_op(inputs, Address::new(self.base + self.next_pc));
        self.next_pc += 1;
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name, inputs));
        op.0
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn free_reg(&mut self, offset: u64, size: usize) -> VnRef {
        self.fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset)
    }

    fn reg_out(&mut self, op: &OpRef, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd.op_set_output(&PcodeOpRef(op.clone()), vn);
        read_op(op).output.clone().expect("written register output")
    }

    fn unique_out(&mut self, op: &OpRef, size: usize) -> VnRef {
        self.fd.new_unique_out(size, &PcodeOpRef(op.clone()))
    }

    fn input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_set_input(&PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn append(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(&PcodeOpRef(op.clone()), block);
    }

    fn prepare(&mut self) {
        let mut preorder = Vec::new();
        let mut roots = Vec::new();
        self.fd
            .bblocks
            .find_spanning_tree(&mut preorder, &mut roots)
            .expect("find_spanning_tree");
        self.fd.bblocks.build_dom_tree();
        self.fd.heritage.build_info_list();
    }

    fn op_name(&self, op: &OpRef) -> &'static str {
        for (candidate, name, _) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        if read_op(op).opcode == OpCode::CPUI_MULTIEQUAL {
            "phi"
        } else {
            "unknown"
        }
    }

    fn declared_inputs(&self, op: &OpRef) -> usize {
        self.ops
            .iter()
            .find(|(candidate, _, _)| Arc::ptr_eq(candidate, op))
            .map(|(_, _, count)| *count)
            .unwrap_or_else(|| read_op(op).inrefs.len())
    }

    fn block_name(&self, block: &BlockRef) -> &'static str {
        self.blocks
            .iter()
            .find(|(candidate, _)| Arc::ptr_eq(candidate, block))
            .map(|(_, name)| *name)
            .unwrap_or("unknown")
    }

    fn alias(&mut self, vn: &VnRef) -> usize {
        let key = Arc::as_ptr(vn) as usize;
        if let Some(alias) = self.aliases.get(&key) {
            return *alias;
        }
        let alias = self.next_alias;
        self.next_alias += 1;
        self.aliases.insert(key, alias);
        alias
    }

    fn vn_state(&mut self, vn: Option<&VnRef>) -> String {
        let Some(vn) = vn else {
            return "null".to_string();
        };
        let alias = self.alias(vn);
        let value = read_vn(vn);
        let storage = if value.is_constant() {
            format!("C{}:{:x}", value.get_size(), value.get_offset())
        } else {
            match value.get_space() {
                AddressSpace::Register => {
                    format!("R{:x}:{}", value.get_offset(), value.get_size())
                }
                AddressSpace::Unique => format!("U{}", value.get_size()),
                AddressSpace::Iop => format!("IOP{}", value.get_size()),
                space => format!(
                    "{}:{:x}:{}",
                    space.name(),
                    value.get_offset(),
                    value.get_size()
                ),
            }
        };
        let class = if value.is_constant() {
            'C'
        } else if value.is_annotation() {
            'A'
        } else if value.is_input() {
            'I'
        } else if value.is_written() {
            'W'
        } else {
            'F'
        };
        let desc = value.count_descends();
        let flags = value.flags;
        let active = value.is_active_heritage();
        let known = value.is_heritage_known();
        let def = value.get_def();
        drop(value);
        let def_name = def.map(|op| self.op_name(&op)).unwrap_or("-");
        format!(
            "a{alias}:{storage}:{class}:d{desc}:f{flags:x}:act{}:known{}:def{def_name}",
            u8::from(active),
            u8::from(known),
        )
    }

    fn order(&mut self) -> String {
        let mut block_parts = Vec::new();
        for index in 0..self.fd.bblocks.get_size() {
            let Some(block) = self.fd.bblocks.get_block(index) else {
                continue;
            };
            let block_name = self.block_name(&block);
            let block_index = block.read().unwrap().get_index();
            let ops = block.read().unwrap().get_ops();
            let mut op_parts = Vec::new();
            for op_ref in ops {
                let op = op_ref.0;
                let name = self.op_name(&op);
                let (opcode, output, inputs) = {
                    let value = read_op(&op);
                    (value.opcode, value.output.clone(), value.inrefs.clone())
                };
                let mut part = format!(
                    "{name}.{}{{out={}",
                    opcode_name(opcode),
                    self.vn_state(output.as_ref()),
                );
                let slots = self.declared_inputs(&op).max(inputs.len());
                for slot in 0..slots {
                    part.push_str(&format!(",s{slot}={}", self.vn_state(inputs.get(slot)),));
                }
                part.push('}');
                op_parts.push(part);
            }
            block_parts.push(format!(
                "{block_name}#{block_index}=[{}]",
                op_parts.join(",")
            ));
        }
        block_parts.join(";")
    }

    fn in_bank(&self, needle: &VnRef) -> bool {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .any(|entry| Arc::ptr_eq(&entry.0, needle))
    }

    fn free_with_reader(&self) -> usize {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .filter(|entry| {
                let value = read_vn(&entry.0);
                !value.is_constant()
                    && !value.is_annotation()
                    && value.is_free()
                    && !value.has_no_descend()
            })
            .count()
    }
}

fn catch_input_error(fd: &mut Funcdata, op: &OpRef, vn: &VnRef) -> String {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fd.op_set_input(&PcodeOpRef(op.clone()), vn.clone(), 0);
    }));
    std::panic::set_hook(previous_hook);
    match result {
        Ok(()) => "none".to_string(),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_else(|| "non-string panic payload".to_string()),
    }
}

fn main() {
    println!(
        "schema=1|fixture=HERITAGE-FREE-SSA-FIXTURE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );

    {
        let mut g = Graph::new("single_free_promotion", 0x6100);
        let entry = g.block("entry");
        let read = g.op("read", OpCode::CPUI_COPY, 1);
        let old_free = g.free_reg(0x100, 8);
        g.input(&read, &old_free, 0);
        g.unique_out(&read, 8);
        g.append(&read, &entry);
        let pre = before_state(&old_free);
        g.prepare();
        g.fd.op_heritage();
        let promoted = read_op(&read).inrefs[0].clone();
        let new_state = g.vn_state(Some(&promoted));
        let order = g.order();
        println!(
            "case=single_free_promotion|pre={pre}|pass={}|old_bank={}|new={new_state}|new_is_old={}|free_with_reader={}|order={order}",
            g.fd.num_heritage_passes(),
            u8::from(g.in_bank(&old_free)),
            u8::from(Arc::ptr_eq(&promoted, &old_free)),
            g.free_with_reader(),
        );
    }

    {
        let mut g = Graph::new("double_descendant", 0x6200);
        let entry = g.block("entry");
        let first = g.op("first", OpCode::CPUI_COPY, 1);
        let second = g.op("second", OpCode::CPUI_COPY, 1);
        g.append(&first, &entry);
        g.append(&second, &entry);
        let free_vn = g.free_reg(0x110, 8);
        g.input(&first, &free_vn, 0);
        let pre = before_state(&free_vn);
        let error = catch_input_error(&mut g.fd, &second, &free_vn);
        let post = before_state(&free_vn);
        let first_alias = read_op(&first)
            .inrefs
            .first()
            .is_some_and(|input| Arc::ptr_eq(input, &free_vn));
        let second_null = read_op(&second).inrefs.is_empty();
        let order = g.order();
        println!(
            "case=double_descendant_error|pre={pre}|error={error}|post={post}|first_alias={}|second_null={}|bank={}|order={order}",
            u8::from(first_alias),
            u8::from(second_null),
            u8::from(g.in_bank(&free_vn)),
        );
    }

    {
        let mut g = Graph::new("indirect_simultaneous", 0x6300);
        let entry = g.block("entry");
        let prior = g.op("prior", OpCode::CPUI_COPY, 1);
        let c21 = g.constant(8, 0x21);
        g.input(&prior, &c21, 0);
        let prior_out = g.reg_out(&prior, 0x120, 8);
        g.append(&prior, &entry);
        let target = g.op("target", OpCode::CPUI_INT_ADD, 2);
        let old_free = g.free_reg(0x120, 8);
        g.input(&target, &old_free, 0);
        let c22 = g.constant(8, 0x22);
        g.input(&target, &c22, 1);
        g.unique_out(&target, 8);
        let ind = g.op("ind", OpCode::CPUI_INDIRECT, 2);
        g.input(&ind, &prior_out, 0);
        let iop = g.fd.new_varnode_iop(&PcodeOpRef(target.clone()));
        g.input(&ind, &iop, 1);
        let ind_out = g.reg_out(&ind, 0x120, 8);
        g.append(&ind, &entry);
        g.append(&target, &entry);
        let pre = before_state(&old_free);
        g.prepare();
        g.fd.op_heritage();
        let target_in = read_op(&target).inrefs[0].clone();
        let target_state = g.vn_state(Some(&target_in));
        let order = g.order();
        println!(
            "case=indirect_simultaneous|pre={pre}|pass={}|old_bank={}|target_in={target_state}|alias_prior={}|alias_indirect={}|prior_desc={}|ind_desc={}|free_with_reader={}|order={order}",
            g.fd.num_heritage_passes(),
            u8::from(g.in_bank(&old_free)),
            u8::from(Arc::ptr_eq(&target_in, &prior_out)),
            u8::from(Arc::ptr_eq(&target_in, &ind_out)),
            read_vn(&prior_out).count_descends(),
            read_vn(&ind_out).count_descends(),
            g.free_with_reader(),
        );
    }

    {
        let mut g = Graph::new("loop_phi_reverse_slot", 0x6400);
        let entry = g.block("entry");
        let header = g.block("header");
        let body = g.block("body");
        let exit = g.block("exit");
        g.edge(&entry, &header);
        g.edge(&header, &body);
        g.edge(&header, &exit);
        g.edge(&body, &header);
        let init = g.op("init", OpCode::CPUI_COPY, 1);
        let c1 = g.constant(8, 1);
        g.input(&init, &c1, 0);
        let init_out = g.reg_out(&init, 0x130, 8);
        g.append(&init, &entry);
        let mut old_reads = Vec::new();
        let head_read = g.op("head_read", OpCode::CPUI_INT_OR, 2);
        old_reads.push(g.free_reg(0x130, 8));
        g.input(&head_read, old_reads.last().unwrap(), 0);
        let c2 = g.constant(8, 2);
        g.input(&head_read, &c2, 1);
        g.unique_out(&head_read, 8);
        g.append(&head_read, &header);
        let step = g.op("step", OpCode::CPUI_INT_ADD, 2);
        old_reads.push(g.free_reg(0x130, 8));
        g.input(&step, old_reads.last().unwrap(), 0);
        let c3 = g.constant(8, 3);
        g.input(&step, &c3, 1);
        let step_out = g.reg_out(&step, 0x130, 8);
        g.append(&step, &body);
        let exit_read = g.op("exit_read", OpCode::CPUI_COPY, 1);
        old_reads.push(g.free_reg(0x130, 8));
        g.input(&exit_read, old_reads.last().unwrap(), 0);
        g.unique_out(&exit_read, 8);
        g.append(&exit_read, &exit);
        let pre = old_reads
            .iter()
            .enumerate()
            .map(|(index, vn)| format!("r{index}{{{}}}", before_state(vn)))
            .collect::<Vec<_>>()
            .join(";");
        g.prepare();
        g.fd.op_heritage();
        let phi = header
            .read()
            .unwrap()
            .get_ops()
            .into_iter()
            .find(|op| read_op(&op.0).opcode == OpCode::CPUI_MULTIEQUAL)
            .map(|op| op.0);
        let mut slot_parts = Vec::new();
        if let Some(phi_ref) = &phi {
            let phi_inputs = read_op(phi_ref).inrefs.clone();
            for (slot, input) in phi_inputs.iter().enumerate() {
                let pred = header
                    .read()
                    .unwrap()
                    .get_in(slot)
                    .expect("phi predecessor")
                    .point
                    .clone();
                let pred_name = g.block_name(&pred);
                let state = g.vn_state(Some(input));
                slot_parts.push(format!(
                    "s{slot}<pred={pred_name},in={state},is_init={},is_step={}>",
                    u8::from(Arc::ptr_eq(input, &init_out)),
                    u8::from(Arc::ptr_eq(input, &step_out)),
                ));
            }
        }
        let removed = old_reads.iter().filter(|vn| !g.in_bank(vn)).count();
        let phi_out = phi.as_ref().and_then(|op| read_op(op).output.clone());
        let head_alias_phi = phi_out
            .as_ref()
            .is_some_and(|out| Arc::ptr_eq(&read_op(&head_read).inrefs[0], out));
        let body_alias_phi = phi_out
            .as_ref()
            .is_some_and(|out| Arc::ptr_eq(&read_op(&step).inrefs[0], out));
        let exit_alias_phi = phi_out
            .as_ref()
            .is_some_and(|out| Arc::ptr_eq(&read_op(&exit_read).inrefs[0], out));
        let order = g.order();
        println!(
            "case=loop_phi_reverse_slot|pre={pre}|pass={}|phi={}|slots={}|head_alias_phi={}|body_alias_phi={}|exit_alias_phi={}|old_removed={removed}/{}|free_with_reader={}|order={order}",
            g.fd.num_heritage_passes(),
            u8::from(phi.is_some()),
            slot_parts.join(";"),
            u8::from(head_alias_phi),
            u8::from(body_alias_phi),
            u8::from(exit_alias_phi),
            old_reads.len(),
            g.free_with_reader(),
        );
    }
}
