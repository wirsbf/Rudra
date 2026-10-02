//! Rugra twin of `tests/oracle/rule_store_varnode_spacebase_1204.cc`.
//!
//! PRINTC-INPUTREG-DEADSTORE-0001: drives `RuleStoreVarnode` / `RuleLoadVarnode`
//! (ruleaction.cc:4277/4319) over the same spacebase-chain case family as the
//! locked Ghidra 12.0.4 oracle fixture and prints the identical stable
//! observation format: per case, the real rule-call result plus the
//! post-application op state (opcode, input count, slot-0/slot-1 varnode
//! observations, output varnode and its stack-store flag). Unique-space
//! offsets and raw space-id constants are not observed, matching the C++
//! side's deliberate blind spots.

use std::sync::Arc;
use std::sync::RwLock;

use rudra::action::Rule;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::ruleaction::{RuleLoadVarnode, RuleStoreVarnode};
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

fn space_name(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    }
}

fn opcode_name(code: OpCode) -> &'static str {
    // Ghidra's OpCode::getName() display strings for the opcodes this
    // fixture observes (op.cc get_opname table).
    match code {
        OpCode::CPUI_INT_ADD => "+",
        OpCode::CPUI_COPY => "copy",
        OpCode::CPUI_STORE => "store",
        OpCode::CPUI_LOAD => "load",
        _ => "OTHER",
    }
}

/// Stable observation of one varnode (or '-' for absent).
fn vn_state(vn: Option<&Arc<RwLock<Varnode>>>) -> String {
    let Some(vn) = vn else { return "-".to_string() };
    let v = vn.read().unwrap();
    if v.is_constant() {
        return format!("const:{}", v.get_size());
    }
    let spc = v.get_space();
    if spc == AddressSpace::Unique {
        let def_name = v
            .get_def()
            .map(|d| opcode_name(d.read().unwrap().opcode))
            .unwrap_or("nodef");
        return format!("unique:def={}", def_name);
    }
    format!("{}:{:x}:{}", space_name(spc), v.get_offset(), v.get_size())
}

fn op_state(op: &Arc<RwLock<rudra::op::PcodeOp>>) -> String {
    let o = op.read().unwrap();
    let out_obs = match o.get_out() {
        Some(out) => format!("{},ss={}", vn_state(Some(&out)),
            if out.read().unwrap().addlflags & rudra::varnode::addl_flags::STACK_STORE != 0 { 1 } else { 0 }),
        None => "-,ss=0".to_string(),
    };
    format!("{},ins={},a0={},a1={},out={}",
        opcode_name(o.opcode), o.inrefs.len(),
        vn_state(o.get_in(0)), vn_state(o.get_in(1)), out_obs)
}

fn dump(case_name: &str, result: i32, op: &Arc<RwLock<rudra::op::PcodeOp>>) {
    println!("case={}|result={}|op={}", case_name, result, op_state(op));
}

/// Per-case builder mirroring the C++ Fixture helper.
struct Fixture<'a> {
    fd: &'a mut Funcdata,
}

impl<'a> Fixture<'a> {
    fn make_input(&mut self, size: usize, spc: AddressSpace, offset: u64) -> Arc<RwLock<Varnode>> {
        let vn = self.fd.vbank.create_with_space(size, spc, offset);
        self.fd.set_input_varnode(vn.clone())
    }

    fn make_op(&mut self, opcode: OpCode, inputs: usize, output_size: usize)
        -> (rudra::op::PcodeOpRef, Option<Arc<RwLock<Varnode>>>) {
        let op = self.fd.new_op(inputs, Address::new(0x1000));
        self.fd.op_set_opcode(&op, opcode);
        let out = if output_size > 0 {
            Some(self.fd.new_unique_out(output_size, &op))
        } else {
            None
        };
        self.fd.obank.adopt_alive_op(op.clone());
        (op, out)
    }

    fn set_input(&mut self, op: &rudra::op::PcodeOpRef, vn: &Arc<RwLock<Varnode>>, slot: usize) {
        self.fd.op_set_input(op, vn.clone(), slot);
    }
}

/// markSpacebase twin: run the real Funcdata::spacebase flagging pass
/// (funcdata.cc:230-269) and assert the stack-pointer input got the flag.
fn mark_spacebase(fd: &mut Funcdata, rsp: &Arc<RwLock<Varnode>>) {
    fd.spacebase();
    if !rsp.read().unwrap().is_spacebase() {
        panic!("fixture stack pointer did not get the spacebase flag");
    }
}

fn run_store_add_case(fd: &mut Funcdata, name: &str, loadspace: AddressSpace,
                      chain_kind: i32, chain_const: u64) {
    let mut fixture = Fixture { fd };
    let v = fixture.make_input(8, AddressSpace::Register, 0x100);
    let rsp = fixture.make_input(8, AddressSpace::Register, 0x20);
    let addr: Arc<RwLock<Varnode>> = match chain_kind {
        0 => rsp.clone(),
        1 | 2 => {
            let (add, out) = fixture.make_op(OpCode::CPUI_INT_ADD, 2, 8);
            if chain_kind == 1 {
                fixture.set_input(&add, &rsp, 0);
                let c = fixture.fd.vbank.create_constant(8, chain_const);
                fixture.set_input(&add, &c, 1);
            } else {
                let c = fixture.fd.vbank.create_constant(8, chain_const);
                fixture.set_input(&add, &c, 0);
                fixture.set_input(&add, &rsp, 1);
            }
            out.unwrap()
        }
        3 => {
            let (inner, inner_out) = fixture.make_op(OpCode::CPUI_INT_ADD, 2, 8);
            fixture.set_input(&inner, &rsp, 0);
            let c1 = fixture.fd.vbank.create_constant(8, chain_const);
            fixture.set_input(&inner, &c1, 1);
            let (outer, outer_out) = fixture.make_op(OpCode::CPUI_INT_ADD, 2, 8);
            fixture.set_input(&outer, &inner_out.unwrap(), 0);
            let c2 = fixture.fd.vbank.create_constant(8, 8);
            fixture.set_input(&outer, &c2, 1);
            outer_out.unwrap()
        }
        _ => {
            let (cp, out) = fixture.make_op(OpCode::CPUI_COPY, 1, 8);
            fixture.set_input(&cp, &rsp, 0);
            out.unwrap()
        }
    };
    mark_spacebase(fixture.fd, &rsp);

    let (store, _) = fixture.make_op(OpCode::CPUI_STORE, 3, 0);
    let sid = fixture.fd.vbank.create_constant(8, loadspace.space_id() as u64);
    fixture.set_input(&store, &sid, 0);
    fixture.set_input(&store, &addr, 1);
    fixture.set_input(&store, &v, 2);

    let rule = RuleStoreVarnode::new();
    let result = rule.apply_op(&store.0, fixture.fd).unwrap();
    dump(name, result, &store.0);
}

fn run_load_add_case(fd: &mut Funcdata, name: &str, loadspace: AddressSpace, chain_const: u64) {
    let mut fixture = Fixture { fd };
    let rsp = fixture.make_input(8, AddressSpace::Register, 0x20);
    let (add, add_out) = fixture.make_op(OpCode::CPUI_INT_ADD, 2, 8);
    fixture.set_input(&add, &rsp, 0);
    let c = fixture.fd.vbank.create_constant(8, chain_const);
    fixture.set_input(&add, &c, 1);
    mark_spacebase(fixture.fd, &rsp);

    let (load, _) = fixture.make_op(OpCode::CPUI_LOAD, 2, 8);
    let sid = fixture.fd.vbank.create_constant(8, loadspace.space_id() as u64);
    fixture.set_input(&load, &sid, 0);
    fixture.set_input(&load, &add_out.unwrap(), 1);

    let rule = RuleLoadVarnode::new();
    let result = rule.apply_op(&load.0, fixture.fd).unwrap();
    dump(name, result, &load.0);
}

fn run_store_non_spacebase_case(fd: &mut Funcdata, name: &str, loadspace: AddressSpace) {
    let mut fixture = Fixture { fd };
    let v = fixture.make_input(8, AddressSpace::Register, 0x100);
    let rax = fixture.make_input(8, AddressSpace::Register, 0x0);
    let (add, add_out) = fixture.make_op(OpCode::CPUI_INT_ADD, 2, 8);
    fixture.set_input(&add, &rax, 0);
    let c = fixture.fd.vbank.create_constant(8, 8);
    fixture.set_input(&add, &c, 1);

    let (store, _) = fixture.make_op(OpCode::CPUI_STORE, 3, 0);
    let sid = fixture.fd.vbank.create_constant(8, loadspace.space_id() as u64);
    fixture.set_input(&store, &sid, 0);
    fixture.set_input(&store, &add_out.unwrap(), 1);
    fixture.set_input(&store, &v, 2);

    let rule = RuleStoreVarnode::new();
    let result = rule.apply_op(&store.0, fixture.fd).unwrap();
    dump(name, result, &store.0);
}

fn main() {
    // The locked x86-64 gcc architecture facts mirrored by the BfdArchitecture
    // oracle side: stack record register:20:8, contain(stack)=ram.
    let arch = Arc::new(Architecture::new());
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(arch.clone());

    let contain = arch.get_contain(AddressSpace::Stack)
        .map(space_name)
        .unwrap_or("-");
    println!("stack_contain={}|sb_record={}:{:x}:{}",
        contain, space_name(arch.stack_pointer_space),
        arch.stack_pointer_offset, arch.stack_pointer_size);

    let ram = AddressSpace::Ram;
    let stack = AddressSpace::Stack;

    run_store_add_case(&mut fd, "store_sbinput_off0", ram, 0, 0);
    run_store_add_case(&mut fd, "store_sbinput_add", ram, 1, 0xfffffffffffffff8);
    run_store_add_case(&mut fd, "store_sbinput_swap", ram, 2, 0x18);
    run_store_add_case(&mut fd, "store_contain_mismatch", stack, 1, 8);
    run_store_add_case(&mut fd, "store_written_base", ram, 3, 0xfffffffffffffff8);
    run_store_add_case(&mut fd, "store_copy_wrapped", ram, 4, 0);
    run_load_add_case(&mut fd, "load_sbinput_add", ram, 0x40);
    run_store_non_spacebase_case(&mut fd, "store_non_spacebase", ram);
}
