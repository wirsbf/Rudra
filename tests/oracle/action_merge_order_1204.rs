// PIPE-MERGETYPE-ORDER-0001: Rugra comparand for the locked Ghidra 12.0.4
// post-cleanup action order oracle (coreaction.cc:5712-5738).  Mirrors
// tests/oracle/action_merge_order_1204.cc: the real default pipeline root is
// built through `build_default_pipeline` (the single construction path behind
// ActionDatabase::set_default_actions), the ordered child sequence after the
// cleanup pool is printed, each child is driven through the exact perform()
// call ActionGroup::apply makes, and the complete IR projection is printed
// before and after the sequence in the shared observation format.

use std::sync::{Arc, RwLock};

use rudra::action::{build_default_pipeline, ActionRestartGroup};
use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOp;
use rudra::opcodes::OpCode;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<Varnode>>;
type OpRef = Arc<RwLock<PcodeOp>>;

fn op_name(opcode: OpCode) -> String {
    // Ghidra get_opname prints without the CPUI_ prefix (op.cc get_opname).
    format!("{:?}", opcode).trim_start_matches("CPUI_").to_string()
}

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    ops: Vec<(OpRef, &'static str)>,
    vns: Vec<(VnRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            ops: Vec::new(),
            vns: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(RwLock::new(BlockBasic::new(
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

    fn unique_out(&mut self, name: &'static str, size: usize, op: &OpRef) -> VnRef {
        let vn = self
            .fd
            .new_unique_out(size, &rudra::op::PcodeOpRef(op.clone()));
        self.vns.push((vn.clone(), name));
        vn
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
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

    fn ir_text(&self) -> String {
        let mut vns = String::from("[");
        let mut first = true;
        for (vn_arc, name) in &self.vns {
            let vn = vn_arc.read().unwrap();
            if !first {
                vns.push(',');
            }
            first = false;
            let hi = vn
                .high
                .as_ref()
                .map(|h| h.read().unwrap().instances.len() as i32)
                .unwrap_or(-1);
            vns.push_str(&format!(
                "{name}:in={},wr={},ex={},im={},hi={hi}",
                u8::from(vn.is_input()),
                u8::from(vn.is_written()),
                u8::from(vn.is_explicit()),
                u8::from(vn.is_implied()),
            ));
        }
        vns.push(']');
        let mut ops = String::from("[");
        let mut first = true;
        for (op_arc, name) in &self.ops {
            let op = op_arc.read().unwrap();
            if !first {
                ops.push(',');
            }
            first = false;
            ops.push_str(&format!(
                "{}={}/{}",
                name,
                op_name(op.opcode),
                op.get_seq_num().get_order()
            ));
        }
        ops.push(']');
        let high_ptr = |vn: &VnRef| vn.read().unwrap().high.as_ref().map(Arc::as_ptr);
        let merge_temps = match (high_ptr(&self.vns[0].0), high_ptr(&self.vns[1].0)) {
            (Some(a), Some(b)) if a == b => 1,
            _ => 0,
        };
        format!("vns={vns}|ops={ops}|merge_temps={merge_temps}")
    }
}

fn main() {
    println!("schema=1|fixture=PIPE-MERGETYPE-ORDER-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let mut root: ActionRestartGroup = build_default_pipeline();
    let names: Vec<String> = root.child_names().into_iter().map(String::from).collect();
    let start = names
        .iter()
        .position(|n| *n == "prefercomplement")
        .expect("post-cleanup sequence missing");
    let seq: Vec<&str> = names[start..].iter().map(|s| s.as_str()).collect();
    println!("seq={}", seq.join(","));

    // Minimal Funcdata whose only legal speculative merge is the two
    // same-Datatype 8-byte written temporaries with disjoint covers.  The
    // temporaries are defined from constants so MergeAdjacent's
    // mergeTestBasic gate (merge.cc:255) rejects every input on both sides
    // without any size trick that would trigger cast insertion.
    let mut g = Graph::new("merge_order", 0x6000);
    let b0 = g.make_block(0);
    let b1 = g.make_block(1);
    let b2 = g.make_block(2);
    g.edge(&b0, &b1);
    g.edge(&b0, &b2);
    let ct8: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
        "long".to_string(),
        8,
        TypeMetatype::Int,
    )));
    let c8a = g.constant(8, 5);
    let c8b = g.constant(8, 7);
    let r1 = g.make_op("r1", OpCode::CPUI_INT_ADD, 2);
    g.set_input(&r1, &c8a, 0);
    g.set_input(&r1, &c8b, 1);
    let t1 = g.unique_out("t1", 8, &r1);
    t1.write().unwrap().v_type = Some(ct8.clone());
    g.insert_end(&r1, &b1);
    let r2 = g.make_op("r2", OpCode::CPUI_INT_XOR, 2);
    g.set_input(&r2, &c8a, 0);
    g.set_input(&r2, &c8b, 1);
    let t2 = g.unique_out("t2", 8, &r2);
    t2.write().unwrap().v_type = Some(ct8.clone());
    g.insert_end(&r2, &b2);

    println!("pre|{}", g.ir_text());

    // Drive each post-cleanup child through the exact perform() call
    // ActionGroup::apply makes, in tree order.
    for index in start..names.len() {
        let res = root.perform_child(index, &mut g.fd).expect("child perform");
        let state = root.child_state(index).expect("child state");
        println!(
            "act={}|status={}|count={}|lcount={}|tests={}|apply={}|res={}",
            names[index], state.status, state.count, state.lcount, state.count_tests,
            state.count_apply, res
        );
    }

    println!("post|{}", g.ir_text());
}
