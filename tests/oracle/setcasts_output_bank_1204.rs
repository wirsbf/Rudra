// VARNODE-BANK-KEY-LIVE-0001: Rugra comparand for the locked Ghidra 12.0.4
// VarnodeBank::makeFree / setInput / setDef / xref key-lifecycle oracle.
// Mirrors tests/oracle/setcasts_output_bank_1204.cc case for case: the same
// def-use graphs are built through the production Funcdata APIs and the
// complete bank state (both tree iteration orders, per-Varnode membership
// counts, classification flags, defining SeqNum order) is printed in the
// shared observation format.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;

fn class_of(vn: &VnRef) -> char {
    let flags = vn.read().unwrap().flags;
    let class = flags & (varnode_flags::INPUT | varnode_flags::WRITTEN);
    if class == varnode_flags::INPUT {
        'i'
    } else if class == varnode_flags::WRITTEN {
        'w'
    } else {
        'f'
    }
}

fn space_token(vn: &VnRef) -> &'static str {
    match vn.read().unwrap().address_space {
        AddressSpace::Const => "const",
        AddressSpace::Register => "register",
        _ => "other",
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    names: Vec<(VnRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            names: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        block
    }

    fn make_op(&mut self, opcode: OpCode, inputs: usize) -> PcodeOpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        op
    }

    fn constant(&mut self, name: &'static str, size: usize, value: u64) -> VnRef {
        let vn = self.fd.new_constant(size, value);
        self.names.push((vn.clone(), name));
        vn
    }

    fn input(&mut self, name: &'static str, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.names.push((vn.clone(), name));
        self.fd.vbank.set_input(vn).expect("fresh input varnode")
    }

    // Bank-managed free Varnode in the register space; mirrors
    // Funcdata::newVarnode(s, Address(reg, off)).
    fn reg_free(&mut self, name: &'static str, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.names.push((vn.clone(), name));
        vn
    }

    fn name_of(&self, vn: &VnRef) -> &'static str {
        for (candidate, name) in &self.names {
            if Arc::ptr_eq(candidate, vn) {
                return name;
            }
        }
        "?"
    }

    fn loc_text(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for entry in self.fd.vbank.loc_tree.iter() {
            if !first {
                out.push(',');
            }
            first = false;
            let vn = &entry.0;
            let value = vn.read().unwrap();
            out.push_str(&format!(
                "{}.{}.{:x}.{}.{}.{}",
                self.name_of(vn),
                space_token(vn),
                value.loc.as_u64(),
                value.size,
                class_of(vn),
                value.create_index,
            ));
        }
        out.push(']');
        out
    }

    fn def_text(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for entry in self.fd.vbank.def_tree.iter() {
            if !first {
                out.push(',');
            }
            first = false;
            let vn = &entry.0;
            let value = vn.read().unwrap();
            let class = class_of(vn);
            let order = value
                .get_def()
                .map(|def| def.read().unwrap().get_seq_num().get_order().to_string())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "{}.{}.{}.{}.{:x}.{}.{}",
                self.name_of(vn),
                class,
                order,
                space_token(vn),
                value.loc.as_u64(),
                value.size,
                value.create_index,
            ));
        }
        out.push(']');
        out
    }

    fn loc_members(&self, vn: &VnRef) -> usize {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .filter(|entry| Arc::ptr_eq(&entry.0, vn))
            .count()
    }

    fn def_members(&self, vn: &VnRef) -> usize {
        self.fd
            .vbank
            .def_tree
            .iter()
            .filter(|entry| Arc::ptr_eq(&entry.0, vn))
            .count()
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: &VnRef, slot: usize) {
        self.fd.op_set_input(op, vn.clone(), slot);
    }

    fn set_output(&mut self, op: &PcodeOpRef, vn: &VnRef) {
        self.fd.op_set_output(op, vn.clone());
    }

    fn unset_output(&mut self, op: &PcodeOpRef) {
        self.fd.op_unset_output(op);
    }

    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }
}

fn main() {
    println!("schema=1|fixture=VARNODE-BANK-KEY-LIVE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=opsetoutput_swap: castOutput-semantics output swap through the
    // production Funcdata::opSetOutput chain (opUnsetOutput -> makeFree ->
    // setDef), twice.
    {
        let mut g = Graph::new("opsetoutput_swap", 0x5800);
        let b0 = g.make_block(0);
        let c8 = g.constant("c8", 8, 5);
        let c4 = g.constant("c4", 4, 7);
        let i0 = g.input("i0", 0x80, 4);
        let a = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&a, &c8, 0);
        let out1 = g.reg_free("out1", 0x100, 4);
        g.set_output(&a, &out1);
        g.insert_end(&a, &b0);
        let b = g.make_op(OpCode::CPUI_INT_ADD, 2);
        g.set_input(&b, &i0, 0);
        g.set_input(&b, &c4, 1);
        g.insert_end(&b, &b0);
        let loc0 = g.loc_text();
        let def0 = g.def_text();
        g.set_output(&b, &out1);
        let loc1 = g.loc_text();
        let def1 = g.def_text();
        g.set_output(&a, &out1);
        let loc2 = g.loc_text();
        let def2 = g.def_text();
        let out1_written = u8::from(out1.read().unwrap().is_written());
        let out1_insert =
            u8::from(out1.read().unwrap().flags & varnode_flags::INSERT != 0);
        let out1_def2 = out1
            .read()
            .unwrap()
            .get_def()
            .expect("out1 written after rebind")
            .read()
            .unwrap()
            .get_seq_num()
            .get_order();
        println!(
            "case=opsetoutput_swap|loc0={loc0}|def0={def0}|loc1={loc1}|def1={def1}|loc2={loc2}|def2={def2}|out1_members={},{},{},{},{},{}|out1_written={out1_written}|out1_insert={out1_insert}|out1_def2={out1_def2}",
            g.loc_members(&out1),
            g.def_members(&out1),
            g.loc_members(&out1),
            g.def_members(&out1),
            g.loc_members(&out1),
            g.def_members(&out1),
        );
    }

    // case=makefree_inplace_key_drift: hand-built def wiring mutates the
    // key-relevant fields in place while the Varnode is tree-resident, then
    // opUnsetOutput -> makeFree must erase this exact object and reinsert
    // it as free.  The pad Varnode (created before out2 at a higher offset)
    // makes the stale tree position observable.
    {
        let mut g = Graph::new("makefree_inplace_key_drift", 0x5900);
        let b0 = g.make_block(0);
        let c8 = g.constant("c8", 8, 5);
        let d2 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&d2, &c8, 0);
        g.insert_end(&d2, &b0);
        let _pad = g.reg_free("pad", 0x180, 4);
        let out2 = g.reg_free("out2", 0x120, 4);
        let loc0 = g.loc_text();
        let def0 = g.def_text();
        {
            // Hand-built wiring exactly like Rugra's unit-test fixtures:
            // the op's output slot and the Varnode's def/written
            // classification are assigned IN PLACE (the Varnode::setDef
            // analogue of varnode.cc:394-401), bypassing
            // VarnodeBank::setDef's erase-reinsert.
            d2.0.write().unwrap().output = Some(out2.clone());
            let mut value = out2.write().unwrap();
            value.def = Some(Arc::downgrade(&d2.0));
            value.set_flags(varnode_flags::WRITTEN | varnode_flags::COVERDIRTY);
        }
        let loc1 = g.loc_text();
        let def1 = g.def_text();
        // Funcdata::opUnsetOutput -> VarnodeBank::makeFree(out2): the legal
        // path under key drift (erase of this exact object).
        g.fd.op_unset_output(&d2);
        let loc2 = g.loc_text();
        let def2 = g.def_text();
        let snapshot = out2.read().unwrap();
        let out2_free = u8::from(snapshot.is_free());
        let out2_insert = u8::from(snapshot.flags & varnode_flags::INSERT != 0);
        let out2_input = u8::from(snapshot.is_input());
        drop(snapshot);
        println!(
            "case=makefree_inplace_key_drift|loc0={loc0}|def0={def0}|loc1={loc1}|def1={def1}|loc2={loc2}|def2={def2}|out2_free={out2_free}|out2_insert={out2_insert}|out2_input={out2_input}|out2_members={},{},{},{},{},{}",
            g.loc_members(&out2),
            g.def_members(&out2),
            g.loc_members(&out2),
            g.def_members(&out2),
            g.loc_members(&out2),
            g.def_members(&out2),
        );
    }

    // case=destroy_after_transitions: after write/free/rebind transitions
    // both trees must still remove the Varnode (opDestroy ->
    // destroyVarnode -> VarnodeBank::destroy).
    {
        let mut g = Graph::new("destroy_after_transitions", 0x5a00);
        let b0 = g.make_block(0);
        let c8 = g.constant("c8", 8, 5);
        let e = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&e, &c8, 0);
        let out3 = g.reg_free("out3", 0x140, 4);
        g.set_output(&e, &out3);
        g.insert_end(&e, &b0);
        let loc0 = g.loc_text();
        let def0 = g.def_text();
        g.unset_output(&e);
        let loc1 = g.loc_text();
        let def1 = g.def_text();
        let snapshot = out3.read().unwrap();
        let free1 = u8::from(snapshot.is_free());
        let insert1 = u8::from(snapshot.flags & varnode_flags::INSERT != 0);
        drop(snapshot);
        let members1 = (g.loc_members(&out3), g.def_members(&out3));
        g.set_output(&e, &out3); // rebind after the free window
        let written2 = u8::from(out3.read().unwrap().is_written());
        g.fd.op_destroy(&e); // destroyVarnode(out3) -> VarnodeBank::destroy
        let loc2 = g.loc_text();
        let def2 = g.def_text();
        println!(
            "case=destroy_after_transitions|loc0={loc0}|def0={def0}|loc1={loc1}|def1={def1}|out3_free1={free1}|out3_insert1={insert1}|out3_members1={},{}|out3_written2={written2}|loc2={loc2}|def2={def2}|out3_members2={},{}",
            members1.0,
            members1.1,
            g.loc_members(&out3),
            g.def_members(&out3),
        );
    }

    // case=rebind_same_output_noop: opSetOutput early-returns when the new
    // output is already the op's output; trees unchanged.
    {
        let mut g = Graph::new("rebind_same_output_noop", 0x5b00);
        let b0 = g.make_block(0);
        let c8 = g.constant("c8", 8, 5);
        let f = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&f, &c8, 0);
        let out4 = g.reg_free("out4", 0x160, 4);
        g.set_output(&f, &out4);
        g.insert_end(&f, &b0);
        let loc0 = g.loc_text();
        let def0 = g.def_text();
        let def0_order = out4
            .read()
            .unwrap()
            .get_def()
            .expect("out4 written")
            .read()
            .unwrap()
            .get_seq_num()
            .get_order();
        g.set_output(&f, &out4); // same-output early return
        let loc1 = g.loc_text();
        let def1 = g.def_text();
        let def1_order = out4
            .read()
            .unwrap()
            .get_def()
            .expect("out4 still written")
            .read()
            .unwrap()
            .get_seq_num()
            .get_order();
        println!(
            "case=rebind_same_output_noop|loc0={loc0}|def0={def0}|loc1={loc1}|def1={def1}|out4_def0={def0_order}|out4_def1={def1_order}|out4_members={},{},{},{}",
            g.loc_members(&out4),
            g.def_members(&out4),
            g.loc_members(&out4),
            g.def_members(&out4),
        );
    }
}
