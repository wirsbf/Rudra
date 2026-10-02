// COVER-REBUILD-SELFLOCK-0001: Rugra comparand for the locked Ghidra 12.0.4
// Varnode::updateCover / Cover::rebuild oracle.  Mirrors
// tests/oracle/cover_rebuild_1204.cc case for case: the same synthetic
// def-use/CFG graphs are built through the production Funcdata APIs and the
// complete rebuilt Cover, coverdirty lifecycle, and descendant list are
// printed in the shared observation format.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::varnode::{varnode_flags, Varnode};

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = Arc<std::sync::RwLock<PcodeOp>>;

fn endpoint(value: u32) -> String {
    if value == 0 {
        "b".to_string()
    } else if value == u32::MAX {
        "e".to_string()
    } else {
        value.to_string()
    }
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    ops: Vec<(OpRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            ops: Vec::new(),
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

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
    }

    fn make_op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.0.clone(), name));
        op.0.clone()
    }

    fn unique_out(&mut self, size: usize, op: &OpRef) -> VnRef {
        self.fd
            .new_unique_out(size, &rudra::op::PcodeOpRef(op.clone()))
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn input(&mut self, offset: u64, size: usize) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        self.fd.vbank.set_input(vn).expect("fresh input varnode")
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd.op_insert_input(
            &rudra::op::PcodeOpRef(op.clone()),
            vn.clone(),
            slot,
        );
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd
            .op_insert_end(&rudra::op::PcodeOpRef(op.clone()), block);
    }

    fn label_of(&self, op: &OpRef) -> &'static str {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(candidate, op) {
                return name;
            }
        }
        "unknown"
    }

    fn cover_text(root: &VnRef) -> String {
        let value = root.read().unwrap();
        let Some(cover) = value.cover.as_deref() else {
            return "[null]".to_string();
        };
        let mut out = String::from("[");
        let mut first = true;
        for (index, block) in cover.blocks.iter() {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&format!("{}:{}-{}", index, endpoint(block.start), endpoint(block.end)));
        }
        out.push(']');
        out
    }

    fn observe(&self, case_name: &str, root: &VnRef) {
        let dirty_before =
            (root.read().unwrap().flags & varnode_flags::COVERDIRTY != 0) as u8;
        Varnode::update_cover_locked(root);
        let dirty_after =
            (root.read().unwrap().flags & varnode_flags::COVERDIRTY != 0) as u8;
        Varnode::update_cover_locked(root);
        let snapshot = root.read().unwrap();
        let def_order = snapshot
            .get_def()
            .map(|def| def.read().unwrap().get_seq_num().get_order().to_string())
            .unwrap_or_else(|| "-".to_string());
        let mut desc = String::from("[");
        let mut first = true;
        for op in snapshot.descend_iter() {
            if !first {
                desc.push(',');
            }
            first = false;
            desc.push_str(self.label_of(&op));
        }
        desc.push(']');
        let mut slots = String::from("[");
        first = true;
        for op in snapshot.descend_iter() {
            let op_value = op.read().unwrap();
            for (slot, input) in op_value.inrefs.iter().enumerate() {
                if Arc::ptr_eq(input, root) {
                    if !first {
                        slots.push(',');
                    }
                    first = false;
                    slots.push_str(&format!("{}.{}", self.label_of(&op), slot));
                }
            }
        }
        slots.push(']');
        let mut orders = String::from("[");
        let mut first = true;
        for (op, name) in &self.ops {
            if !first {
                orders.push(',');
            }
            first = false;
            orders.push_str(&format!("{}={}", name, op.read().unwrap().get_seq_num().get_order()));
        }
        orders.push(']');
        println!(
            "case={case_name}|dirty_before={dirty_before}|dirty_after={dirty_after}|has_cover={}|cover_object={}|input={}|written={}|implied={}|def_order={def_order}|desc={desc}|slots={slots}|orders={orders}|cover={}",
            u8::from(snapshot.has_cover()),
            u8::from(snapshot.cover.is_some()),
            u8::from(snapshot.is_input()),
            u8::from(snapshot.is_written()),
            u8::from(snapshot.is_implied()),
            Self::cover_text(root),
        );
    }
}

fn main() {
    println!("schema=1|fixture=COVER-REBUILD-SELFLOCK-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    // case=input_root
    {
        let mut g = Graph::new("input_root", 0x5000);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let i0 = g.input(0x28, 4);
        let c4 = g.constant(4, 7);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&r1, &i0, 0);
        g.set_input(&r1, &c4, 1);
        g.unique_out(4, &r1);
        g.insert_end(&r1, &b1);
        i0.write().unwrap().calc_cover();
        g.observe("input_root", &i0);
    }

    // case=phi_predecessor_fill
    {
        let mut g = Graph::new("phi_predecessor_fill", 0x5100);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b2, &b1);
        let i0 = g.input(0x30, 4);
        let i1 = g.input(0x34, 4);
        let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 2);
        g.set_input(&m, &i1, 0);
        g.set_input(&m, &i0, 1);
        g.unique_out(4, &m);
        g.insert_end(&m, &b1);
        i0.write().unwrap().calc_cover();
        g.observe("phi_predecessor_fill", &i0);
    }

    // case=defined_linear
    {
        let mut g = Graph::new("defined_linear", 0x5200);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let c8 = g.constant(8, 0x1122334455667788);
        let c4 = g.constant(4, 7);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_OR, 2);
        g.set_input(&r1, &root, 0);
        g.set_input(&r1, &c4, 1);
        g.unique_out(8, &r1);
        g.insert_end(&r1, &b0);
        let r2 = g.make_op("r2", OpCode::CPUI_INT_MULT, 2);
        g.set_input(&r2, &root, 0);
        g.set_input(&r2, &c4, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b1);
        root.write().unwrap().calc_cover();
        g.observe("defined_linear", &root);
    }

    // case=slot2_selfref_double
    {
        let mut g = Graph::new("slot2_selfref_double", 0x5300);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b0, &b3);
        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&r1, &root, 0);
        g.set_input(&r1, &c4, 1);
        let t1 = g.unique_out(8, &r1);
        g.insert_end(&r1, &b1);
        let r2 = g.make_op("r2", OpCode::CPUI_INT_XOR, 2);
        g.set_input(&r2, &root, 0);
        g.set_input(&r2, &root, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b2);
        let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 3);
        g.set_input(&m, &t1, 0);
        g.set_input(&m, &root, 1);
        g.set_input(&m, &root, 2);
        g.unique_out(8, &m);
        g.insert_end(&m, &b3);
        root.write().unwrap().calc_cover();
        g.observe("slot2_selfref_double", &root);
    }

    // case=slot2_single
    {
        let mut g = Graph::new("slot2_single", 0x5400);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b0, &b3);
        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_ADD, 2);
        g.set_input(&r1, &root, 0);
        g.set_input(&r1, &c4, 1);
        let t1 = g.unique_out(8, &r1);
        g.insert_end(&r1, &b1);
        let r2 = g.make_op("r2", OpCode::CPUI_INT_XOR, 2);
        g.set_input(&r2, &root, 0);
        g.set_input(&r2, &c4, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b2);
        let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 3);
        g.set_input(&m, &t1, 0);
        g.set_input(&m, &c4, 1);
        g.set_input(&m, &root, 2);
        g.unique_out(8, &m);
        g.insert_end(&m, &b3);
        root.write().unwrap().calc_cover();
        g.observe("slot2_single", &root);
    }

    // case=implied_chain
    {
        let mut g = Graph::new("implied_chain", 0x5500);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        g.edge(&b0, &b1);
        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_AND, 2);
        g.set_input(&r1, &root, 0);
        g.set_input(&r1, &c4, 1);
        let t1 = g.unique_out(8, &r1);
        g.insert_end(&r1, &b0);
        t1.write().unwrap().flags |= varnode_flags::IMPLIED;
        let r2 = g.make_op("r2", OpCode::CPUI_INT_OR, 2);
        g.set_input(&r2, &t1, 0);
        g.set_input(&r2, &c4, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b1);
        root.write().unwrap().calc_cover();
        g.observe("implied_chain", &root);
    }

    // case=implied_multiequal_reader
    {
        let mut g = Graph::new("implied_multiequal_reader", 0x5800);
        let b0 = g.make_block(0);
        let b1 = g.make_block(1);
        let b2 = g.make_block(2);
        let b3 = g.make_block(3);
        g.edge(&b0, &b1);
        g.edge(&b0, &b2);
        g.edge(&b1, &b3);
        g.edge(&b2, &b3);
        g.edge(&b0, &b3);
        let c8 = g.constant(8, 5);
        let c4 = g.constant(4, 7);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        let r1 = g.make_op("r1", OpCode::CPUI_INT_AND, 2);
        g.set_input(&r1, &root, 0);
        g.set_input(&r1, &c4, 1);
        let t1 = g.unique_out(8, &r1);
        g.insert_end(&r1, &b1);
        t1.write().unwrap().flags |= varnode_flags::IMPLIED;
        let r2 = g.make_op("r2", OpCode::CPUI_INT_XOR, 2);
        g.set_input(&r2, &root, 0);
        g.set_input(&r2, &c4, 1);
        g.unique_out(8, &r2);
        g.insert_end(&r2, &b2);
        // No slot of m holds root: only the implied intermediate t1 and
        // constants. Cover::rebuild passes the ROOT to addRefPoint even when
        // descending from the implied t1 (cover.cc:490), so the MULTIEQUAL
        // slot match at cover.cc:606 must find no slot and recurse through
        // no predecessor.
        let m = g.make_op("m", OpCode::CPUI_MULTIEQUAL, 3);
        g.set_input(&m, &t1, 0);
        g.set_input(&m, &c4, 1);
        g.set_input(&m, &c4, 2);
        g.unique_out(8, &m);
        g.insert_end(&m, &b3);
        root.write().unwrap().calc_cover();
        g.observe("implied_multiequal_reader", &root);
    }

    // case=dirty_flag_cycle
    {
        let mut g = Graph::new("dirty_flag_cycle", 0x5600);
        let b0 = g.make_block(0);
        let c8 = g.constant(8, 5);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        root.write().unwrap().calc_cover();
        g.observe("dirty_flag_cycle", &root);
    }

    // case=no_cover_object
    {
        let mut g = Graph::new("no_cover_object", 0x5700);
        let b0 = g.make_block(0);
        let c8 = g.constant(8, 5);
        let d = g.make_op("d", OpCode::CPUI_COPY, 1);
        g.set_input(&d, &c8, 0);
        let root = g.unique_out(8, &d);
        g.insert_end(&d, &b0);
        root.write().unwrap().flags |= varnode_flags::COVERDIRTY;
        g.observe("no_cover_object", &root);
    }
}
