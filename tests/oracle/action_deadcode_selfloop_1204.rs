use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rudra::action::Action;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::coreaction::ActionDeadCode;
use rudra::funcdata::Funcdata;
use rudra::op::{op_addl_flags, PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{addl_flags, Varnode};

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    fd: Funcdata,
    blocks: Vec<BlockRef>,
    block_names: HashMap<usize, String>,
    ops: Vec<PcodeOpRef>,
    op_names: HashMap<usize, String>,
    varnodes: Vec<VarnodeRef>,
    varnode_names: HashMap<usize, String>,
}

impl Fixture {
    fn new(heritage_pass: i32) -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        fd.heritage.build_info_list();
        fd.heritage.pass = heritage_pass;
        Self {
            fd,
            blocks: Vec::new(),
            block_names: HashMap::new(),
            ops: Vec::new(),
            op_names: HashMap::new(),
            varnodes: Vec::new(),
            varnode_names: HashMap::new(),
        }
    }

    fn block_key(block: &BlockRef) -> usize {
        Arc::as_ptr(block) as *const () as usize
    }

    fn op_key(op: &PcodeOpRef) -> usize {
        Arc::as_ptr(&op.0) as usize
    }

    fn op_arc_key(op: &Arc<RwLock<PcodeOp>>) -> usize {
        Arc::as_ptr(op) as usize
    }

    fn varnode_key(vn: &VarnodeRef) -> usize {
        Arc::as_ptr(vn) as usize
    }

    fn block_name(&self, block: Option<&BlockRef>) -> &str {
        block
            .and_then(|value| self.block_names.get(&Self::block_key(value)))
            .map(String::as_str)
            .unwrap_or("-")
    }

    fn op_name(&self, op: &PcodeOpRef) -> &str {
        self.op_names
            .get(&Self::op_key(op))
            .expect("registered operation")
    }

    fn op_arc_name(&self, op: &Arc<RwLock<PcodeOp>>) -> &str {
        self.op_names
            .get(&Self::op_arc_key(op))
            .expect("registered operation")
    }

    fn varnode_name(&self, vn: &VarnodeRef) -> &str {
        self.varnode_names
            .get(&Self::varnode_key(vn))
            .expect("registered varnode")
    }

    fn remember_op(&mut self, op: PcodeOpRef, name: &str) {
        let key = Self::op_key(&op);
        if self.op_names.insert(key, name.to_string()).is_none() {
            self.ops.push(op);
        }
    }

    fn remember_varnode(&mut self, vn: VarnodeRef, name: &str) {
        let key = Self::varnode_key(&vn);
        if self.varnode_names.insert(key, name.to_string()).is_none() {
            self.varnodes.push(vn);
        }
    }

    fn make_block(&mut self, name: &str) -> BlockRef {
        let block = self.fd.create_new_block();
        self.block_names
            .insert(Self::block_key(&block), name.to_string());
        self.blocks.push(block.clone());
        block
    }

    fn add_edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn make_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_constant(&mut self, name: &str, size: usize, value: u64) -> VarnodeRef {
        let vn = self.fd.new_constant(size, value);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_space(&mut self, name: &str, space: AddressSpace) -> VarnodeRef {
        let vn = self.fd.new_varnode_space(space);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_free(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.remember_varnode(vn.clone(), name);
        vn
    }

    fn make_op(
        &mut self,
        name: &str,
        opcode: OpCode,
        inputs: usize,
        output_size: usize,
    ) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x4c20));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name);
        if output_size != 0 {
            let output = self.fd.new_unique_out(output_size, &op);
            self.remember_varnode(output, &format!("{name}_out"));
        }
        op
    }

    fn output(op: &PcodeOpRef) -> VarnodeRef {
        op.0
            .read()
            .unwrap()
            .output
            .clone()
            .expect("fixture output")
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: VarnodeRef, slot: usize) {
        self.fd.op_set_input(op, vn, slot);
    }

    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn live_ops(&self) -> HashSet<usize> {
        self.fd
            .obank
            .optree
            .iter()
            .map(Self::op_key)
            .collect()
    }

    fn live_varnodes(&self) -> HashSet<usize> {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .map(|vn| Self::varnode_key(&vn.0))
            .collect()
    }

    fn space_name(space: AddressSpace) -> &'static str {
        match space {
            AddressSpace::Const => "const",
            AddressSpace::Register => "register",
            AddressSpace::Stack => "stack",
            AddressSpace::Unique => "unique",
            AddressSpace::Iop => "iop",
            AddressSpace::Join => "join",
            AddressSpace::Ram => "ram",
            _ => "other",
        }
    }

    fn op_list(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter()
            .map(|op| self.op_name(op).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn block_state(&self) -> String {
        self.blocks
            .iter()
            .map(|block| {
                let guard = block.read().unwrap();
                let incoming = (0..guard.size_in())
                    .map(|slot| {
                        let edge = guard.get_in(slot).expect("incoming edge");
                        self.block_name(Some(&edge.point)).to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let outgoing = (0..guard.size_out())
                    .map(|slot| {
                        let edge = guard.get_out(slot).expect("outgoing edge");
                        self.block_name(Some(&edge.point)).to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{}{{index={},in=[{}],out=[{}],ops=[{}]}}",
                    self.block_name(Some(block)),
                    guard.get_index(),
                    incoming,
                    outgoing,
                    self.op_list(&guard.get_ops()),
                )
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn op_state(&self, op: &PcodeOpRef, live: &HashSet<usize>) -> String {
        if !live.contains(&Self::op_key(op)) {
            return format!("{}{{present=0}}", self.op_name(op));
        }
        let guard = op.0.read().unwrap();
        let parent = guard.parent.as_ref().and_then(std::sync::Weak::upgrade);
        let inputs = guard
            .inrefs
            .iter()
            .map(|vn| self.varnode_name(vn).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let output = guard
            .output
            .as_ref()
            .map(|vn| self.varnode_name(vn).to_string())
            .unwrap_or_else(|| "-".to_string());
        format!(
            "{}{{present=1,opc={},flags={:x},addl={:x},dead={},indirect={},parent={},addr={:x},time={},order={},inputs=[{}],output={}}}",
            self.op_name(op),
            guard.opcode as i32,
            guard.flags,
            guard.addlflags,
            u8::from(guard.is_dead()),
            u8::from(guard.is_indirect_source()),
            self.block_name(parent.as_ref()),
            guard.get_addr().as_u64(),
            guard.get_seq_num().get_time(),
            guard.get_seq_num().get_order(),
            inputs,
            output,
        )
    }

    fn varnode_state(&self, vn: &VarnodeRef, live: &HashSet<usize>) -> String {
        if !live.contains(&Self::varnode_key(vn)) {
            return format!("{}{{present=0}}", self.varnode_name(vn));
        }
        let guard = vn.read().unwrap();
        let def = guard
            .get_def()
            .map(|op| self.op_arc_name(&op).to_string())
            .unwrap_or_else(|| "-".to_string());
        let mut occurrences: HashMap<usize, usize> = HashMap::new();
        let descendants = guard
            .descend
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|op| {
                let key = Self::op_arc_key(&op);
                let occurrence = occurrences.entry(key).or_insert(0);
                let slot = {
                    let op_guard = op.read().unwrap();
                    op_guard
                        .inrefs
                        .iter()
                        .enumerate()
                        .filter(|(_, input)| Arc::ptr_eq(input, vn))
                        .nth(*occurrence)
                        .map(|(slot, _)| slot)
                        .expect("descendant input occurrence")
                };
                *occurrence += 1;
                format!("{}.{}", self.op_arc_name(&op), slot)
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}{{present=1,space={},size={},offset={:x},flags={:x},addl={:x},consume={:x},vac={},lis={},input={},written={},autolive={},free={},cover={},coverobj={},locbank={},defbank={},def={},desc=[{}]}}",
            self.varnode_name(vn),
            Self::space_name(guard.address_space),
            guard.get_size(),
            guard.get_offset(),
            guard.flags,
            guard.addlflags,
            guard.get_consume(),
            u8::from((guard.addlflags & addl_flags::VAC_CONSUME) != 0),
            u8::from((guard.addlflags & addl_flags::LIS_CONSUME) != 0),
            u8::from(guard.is_input()),
            u8::from(guard.is_written()),
            u8::from(guard.is_auto_live()),
            u8::from(guard.is_free()),
            u8::from(guard.has_cover()),
            u8::from(guard.cover.is_some()),
            u8::from(self.fd.vbank.loc_tree.iter().any(|entry| Arc::ptr_eq(&entry.0, vn))),
            u8::from(self.fd.vbank.def_tree.iter().any(|entry| Arc::ptr_eq(&entry.0, vn))),
            def,
            descendants,
        )
    }

    fn dead_removed(&self) -> String {
        [
            ("register", AddressSpace::Register),
            ("unique", AddressSpace::Unique),
            ("stack", AddressSpace::Stack),
        ]
        .iter()
        .map(|(name, space)| {
            let value = self
                .fd
                .heritage
                .infolist
                .iter()
                .find(|info| info.space == *space)
                .map(|info| info.deadremoved)
                .unwrap_or(-1);
            format!("{name}:{value}")
        })
        .collect::<Vec<_>>()
        .join(",")
    }

    fn dump(&self, case_name: &str, stage: &str, result: &str, count: i32) {
        let live_ops = self.live_ops();
        let live_varnodes = self.live_varnodes();
        let op_states = self
            .ops
            .iter()
            .map(|op| self.op_state(op, &live_ops))
            .collect::<Vec<_>>()
            .join(";");
        let varnode_states = self
            .varnodes
            .iter()
            .map(|vn| self.varnode_state(vn, &live_varnodes))
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "case={case_name}|stage={stage}|result={result}|count={count}|heritage={}|allowed=[register:{},unique:{}]|seen=[{}]|blocks=[{}]|alive=[{}]|dead=[{}]|ops=[{}]|varnodes=[{}]",
            self.fd.heritage.pass,
            u8::from(self.fd.heritage.dead_removal_allowed(AddressSpace::Register)),
            u8::from(self.fd.heritage.dead_removal_allowed(AddressSpace::Unique)),
            self.dead_removed(),
            self.block_state(),
            self.op_list(&self.fd.obank.alivelist),
            self.op_list(&self.fd.obank.deadlist),
            op_states,
            varnode_states,
        );
    }

    fn clear_consume(&self) {
        for vn in &self.fd.vbank.loc_tree {
            let mut guard = vn.0.write().unwrap();
            guard.set_consume(0);
            guard.addlflags &= !(addl_flags::VAC_CONSUME | addl_flags::LIS_CONSUME);
        }
    }

    fn worklist_state(&self, worklist: &[VarnodeRef]) -> String {
        worklist
            .iter()
            .map(|vn| self.varnode_name(vn).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn trace(&self, case_name: &str, event: &str, worklist: &[VarnodeRef], popped: &str) {
        let live = self.live_varnodes();
        let states = self
            .varnodes
            .iter()
            .map(|vn| self.varnode_state(vn, &live))
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "trace={case_name}|event={event}|popped={popped}|work=[{}]|varnodes=[{}]",
            self.worklist_state(worklist),
            states,
        );
    }
}

fn apply_and_dump(mut fixture: Fixture, case_name: &str) {
    let mut action = ActionDeadCode::new();
    fixture.dump(case_name, "before", "na", 0);
    let result = action.apply(&mut fixture.fd).expect("ActionDeadCode::apply");
    let count = action.take_count_delta();
    fixture.dump(case_name, "after", &result.to_string(), count);
}

fn run_ordinary_chain() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let x = f.make_input("x", 8, 0x40);
    x.write().unwrap().addlflags |= addl_flags::LOCKED_INPUT;
    let first = f.make_op("first", OpCode::CPUI_COPY, 1, 8);
    let second = f.make_op("second", OpCode::CPUI_COPY, 1, 8);
    f.set_input(&first, x, 0);
    f.set_input(&second, Fixture::output(&first), 0);
    f.insert_end(&first, &block);
    f.insert_end(&second, &block);
    apply_and_dump(f, "ordinary_chain_no_seed");
}

fn run_self_loop() {
    let mut f = Fixture::new(1);
    assert!(f.fd.funcp.set_return_bytes_consumed(1));
    let left = f.make_block("b0");
    let right = f.make_block("b1");
    let loop_block = f.make_block("b2");
    f.add_edge(&left, &loop_block);
    f.add_edge(&right, &loop_block);
    f.add_edge(&loop_block, &loop_block);
    let x = f.make_input("x", 8, 0x40);
    let return_target = f.make_constant("return_target", 8, 0);
    let phi = f.make_op("phi", OpCode::CPUI_MULTIEQUAL, 3, 8);
    let ret = f.make_op("ret", OpCode::CPUI_RETURN, 2, 0);
    f.set_input(&phi, x.clone(), 0);
    f.set_input(&phi, x, 1);
    f.set_input(&phi, Fixture::output(&phi), 2);
    f.set_input(&ret, return_target, 0);
    f.set_input(&ret, Fixture::output(&phi), 1);
    f.insert_end(&phi, &loop_block);
    f.insert_end(&ret, &loop_block);
    apply_and_dump(f, "selfloop_repeated_live");
}

fn run_two_phi_cycle() {
    let mut f = Fixture::new(1);
    assert!(f.fd.funcp.set_return_bytes_consumed(1));
    let entry = f.make_block("b0");
    let loop_block = f.make_block("b1");
    f.add_edge(&entry, &loop_block);
    f.add_edge(&loop_block, &loop_block);
    let x = f.make_input("x", 8, 0x40);
    let y = f.make_input("y", 8, 0x50);
    let return_target = f.make_constant("return_target", 8, 0);
    let a = f.make_op("a", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let b = f.make_op("b", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let ret = f.make_op("ret", OpCode::CPUI_RETURN, 2, 0);
    f.set_input(&a, x.clone(), 0);
    f.set_input(&a, Fixture::output(&b), 1);
    f.set_input(&b, y, 0);
    f.set_input(&b, Fixture::output(&a), 1);
    f.set_input(&ret, return_target, 0);
    f.set_input(&ret, Fixture::output(&a), 1);
    f.insert_end(&a, &loop_block);
    f.insert_end(&b, &loop_block);
    f.insert_end(&ret, &loop_block);
    apply_and_dump(f, "two_phi_cycle_live");
}

fn run_autolive() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let auto_input = f.make_input("auto_input", 8, 0x40);
    {
        let mut input = auto_input.write().unwrap();
        input.addlflags |= addl_flags::LOCKED_INPUT;
        input.set_auto_live_hold();
    }
    let x = f.make_input("x", 8, 0x50);
    let dead = f.make_op("dead", OpCode::CPUI_COPY, 1, 8);
    let held = f.make_op("held", OpCode::CPUI_COPY, 1, 8);
    Fixture::output(&held)
        .write()
        .unwrap()
        .set_auto_live_hold();
    f.set_input(&dead, auto_input, 0);
    f.set_input(&held, x, 0);
    f.insert_end(&dead, &block);
    f.insert_end(&held, &block);
    apply_and_dump(f, "autolive_input_output");
}

fn run_call() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let userop = f.make_constant("userop", 4, 0);
    let argument = f.make_input("argument", 8, 0x40);
    let call = f.make_op("call", OpCode::CPUI_CALLOTHER, 2, 8);
    call.0.write().unwrap().addlflags |= op_addl_flags::HOLD_OUTPUT;
    f.set_input(&call, userop, 0);
    f.set_input(&call, argument, 1);
    f.insert_end(&call, &block);
    apply_and_dump(f, "callother_without_spec_hold_output");
}

fn run_dead_call_output() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let userop = f.make_constant("userop", 4, 0);
    let argument = f.make_input("argument", 8, 0x40);
    let call = f.make_op("call", OpCode::CPUI_CALLOTHER, 2, 8);
    Fixture::output(&call).write().unwrap().calc_cover();
    f.set_input(&call, userop, 0);
    f.set_input(&call, argument, 1);
    f.insert_end(&call, &block);
    apply_and_dump(f, "callother_dead_output_unset_only");
}

fn run_direct_unset_output() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let x = f.make_input("x", 8, 0x40);
    let copy = f.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    Fixture::output(&copy).write().unwrap().calc_cover();
    f.set_input(&copy, x, 0);
    f.insert_end(&copy, &block);
    f.dump("direct_op_unset_output", "before", "na", 0);
    f.fd.op_unset_output(&copy);
    f.dump("direct_op_unset_output", "after", "0", 0);
}

fn run_direct_set_output() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let copy = f.make_op("copy", OpCode::CPUI_COPY, 0, 0);
    let output = f.make_free("free_out", 8, 0x60);
    f.insert_end(&copy, &block);
    f.fd.op_set_output(&copy, output);
    f.dump("direct_op_set_output", "before", "na", 0);
    f.fd.op_unset_output(&copy);
    f.dump("direct_op_set_output", "after", "0", 0);
}

fn run_direct_new_varnode_out() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let copy = f.make_op("copy", OpCode::CPUI_COPY, 0, 0);
    f.insert_end(&copy, &block);
    let output = f.fd.new_varnode_out(8, Address::new(0x70), &copy);
    f.remember_varnode(output, "new_out");
    f.dump("direct_new_varnode_out", "before", "na", 0);
    f.fd.op_unset_output(&copy);
    f.dump("direct_new_varnode_out", "after", "0", 0);
}

fn run_load(pass: i32, name: &str) {
    let mut f = Fixture::new(pass);
    let block = f.make_block("b0");
    let space = f.make_space("space", AddressSpace::Ram);
    let address = f.make_constant("address", 8, 0x1234);
    let load = f.make_op("load", OpCode::CPUI_LOAD, 2, 8);
    f.set_input(&load, space, 0);
    f.set_input(&load, address, 1);
    f.insert_end(&load, &block);
    apply_and_dump(f, name);
}

fn run_helper_trace() {
    let mut f = Fixture::new(1);
    let block = f.make_block("b0");
    let x = f.make_input("x", 8, 0x40);
    let y = f.make_input("y", 8, 0x50);
    let direct = f.make_op("direct", OpCode::CPUI_MULTIEQUAL, 3, 8);
    let a = f.make_op("a", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let b = f.make_op("b", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let direct_out = Fixture::output(&direct);
    let a_out = Fixture::output(&a);
    let b_out = Fixture::output(&b);
    f.set_input(&direct, x.clone(), 0);
    f.set_input(&direct, direct_out.clone(), 1);
    f.set_input(&direct, direct_out.clone(), 2);
    f.set_input(&a, x.clone(), 0);
    f.set_input(&a, b_out.clone(), 1);
    f.set_input(&b, y, 0);
    f.set_input(&b, a_out.clone(), 1);
    f.insert_end(&direct, &block);
    f.insert_end(&a, &block);
    f.insert_end(&b, &block);

    let mut worklist = Vec::new();
    f.clear_consume();
    f.trace("helper_unwritten_input", "initial", &worklist, "-");
    ActionDeadCode::push_consumed(0, &x, &mut worklist);
    f.trace("helper_unwritten_input", "push_zero", &worklist, "-");
    ActionDeadCode::push_consumed(0, &x, &mut worklist);
    f.trace(
        "helper_unwritten_input",
        "push_zero_duplicate",
        &worklist,
        "-",
    );

    worklist.clear();
    f.clear_consume();
    f.trace("helper_direct_selfloop", "initial", &worklist, "-");
    ActionDeadCode::push_consumed(0, &direct_out, &mut worklist);
    f.trace("helper_direct_selfloop", "push_zero", &worklist, "-");
    ActionDeadCode::push_consumed(0, &direct_out, &mut worklist);
    f.trace(
        "helper_direct_selfloop",
        "push_zero_duplicate",
        &worklist,
        "-",
    );
    ActionDeadCode::push_consumed(0xff, &direct_out, &mut worklist);
    f.trace("helper_direct_selfloop", "grow_pending", &worklist, "-");
    ActionDeadCode::propagate_consumed(&f.fd, &mut worklist);
    f.trace("helper_direct_selfloop", "pop", &worklist, "direct_out");

    worklist.clear();
    f.clear_consume();
    f.trace("helper_two_phi_growth", "initial", &worklist, "-");
    ActionDeadCode::push_consumed(1, &a_out, &mut worklist);
    f.trace("helper_two_phi_growth", "seed_a_1", &worklist, "-");
    ActionDeadCode::propagate_consumed(&f.fd, &mut worklist);
    f.trace("helper_two_phi_growth", "pop_a", &worklist, "a_out");
    ActionDeadCode::push_consumed(2, &a_out, &mut worklist);
    f.trace("helper_two_phi_growth", "grow_a_2", &worklist, "-");
    ActionDeadCode::propagate_consumed(&f.fd, &mut worklist);
    f.trace(
        "helper_two_phi_growth",
        "pop_a_lifo",
        &worklist,
        "a_out",
    );
    ActionDeadCode::propagate_consumed(&f.fd, &mut worklist);
    f.trace("helper_two_phi_growth", "pop_b", &worklist, "b_out");
}

fn main() {
    run_ordinary_chain();
    run_self_loop();
    run_two_phi_cycle();
    run_autolive();
    run_call();
    run_dead_call_output();
    run_direct_unset_output();
    run_direct_set_output();
    run_direct_new_varnode_out();
    run_load(1, "last_chance_load_pass1");
    run_load(2, "last_chance_load_pass2_gate");
    run_helper_trace();
}
