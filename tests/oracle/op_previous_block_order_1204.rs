use std::collections::HashMap;
use std::sync::Arc;

use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;

// Fixture mirroring op_previous_block_order_1204.cc: PcodeOp::previousOp
// (op.cc:344) and PcodeOp::nextOp (op.cc:323) must follow the parent block's
// op-list order (basiciter), never the alivelist mark-alive append order.
struct Fixture {
    fd: Funcdata,
    b1: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b2: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b3: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b4: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b5: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b6: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    b7: Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    probe_order: Vec<PcodeOpRef>,
    names: HashMap<usize, &'static str>,
}

impl Fixture {
    fn new() -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 74);
        let b1 = fd.create_new_block();
        let b2 = fd.create_new_block();
        let b3 = fd.create_new_block();
        let b4 = fd.create_new_block();
        let b5 = fd.create_new_block();
        let b6 = fd.create_new_block();
        let b7 = fd.create_new_block();
        Self {
            fd,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
            probe_order: Vec::new(),
            names: HashMap::new(),
        }
    }

    fn make(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x1000));
        self.fd.op_set_opcode(&op, opcode);
        self.names.insert(Arc::as_ptr(&op.0) as usize, name);
        self.probe_order.push(op.clone());
        op
    }

    fn name(&self, op: &PcodeOpRef) -> String {
        self.names
            .get(&(Arc::as_ptr(&op.0) as usize))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn order(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter()
            .filter_map(|op| self.names.get(&(Arc::as_ptr(&op.0) as usize)).copied())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn block_order(&self, block: &Arc<std::sync::RwLock<dyn rudra::block::FlowBlock + Send + Sync>>) -> String {
        self.order(&block.read().unwrap().get_ops())
    }

    fn attached(&self, op: &PcodeOpRef) -> bool {
        op.0.read().unwrap().parent.is_some()
    }

    fn probe_previous(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for op in &self.probe_order {
            if !self.attached(op) {
                continue; // dead/unattached is undefined for previousOp
            }
            let prev = op.0.read().unwrap().previous_op_in_block(&self.fd.obank);
            let label = match prev {
                Some(p) => self.name(&p),
                None => "null".to_string(),
            };
            parts.push(format!("{}:{}", self.name(op), label));
        }
        parts.join(",")
    }

    fn probe_next(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for op in &self.probe_order {
            if !self.attached(op) {
                continue;
            }
            let next = op.0.read().unwrap().next_op_in_flow(&self.fd.obank);
            let label = match next {
                Some(n) => self.name(&n),
                None => "null".to_string(),
            };
            parts.push(format!("{}:{}", self.name(op), label));
        }
        parts.join(",")
    }

    fn dump(&self, stage: &str) {
        let b1_out = self.b1.read().unwrap().size_out();
        let b4_out = self.b4.read().unwrap().size_out();
        println!(
            "{stage}|b1={}|alive={}|prev={}|next={}|b1_out={b1_out}|b4_out={b4_out}",
            self.block_order(&self.b1),
            self.order(&self.fd.obank.alivelist),
            self.probe_previous(),
            self.probe_next(),
        );
    }
}

fn main() {
    let mut fixture = Fixture::new();
    let head = fixture.make("head", OpCode::CPUI_COPY, 0);
    let mid = fixture.make("mid", OpCode::CPUI_STORE, 3);
    let ind1 = fixture.make("ind1", OpCode::CPUI_INDIRECT, 2);
    let tail = fixture.make("tail", OpCode::CPUI_COPY, 0);
    let ind2 = fixture.make("ind2", OpCode::CPUI_INDIRECT, 2);
    let succ_head = fixture.make("succ_head", OpCode::CPUI_COPY, 0);
    let alt_head = fixture.make("alt_head", OpCode::CPUI_COPY, 0);
    let multi_out = fixture.make("multi_out", OpCode::CPUI_COPY, 0);
    let zero1 = fixture.fd.new_constant(8, 0);
    fixture.fd.op_set_input(&ind1, zero1, 0);
    let mid_iop1 = fixture.fd.new_varnode_iop(&mid);
    fixture.fd.op_set_input(&ind1, mid_iop1, 1);
    let zero2 = fixture.fd.new_constant(8, 0);
    fixture.fd.op_set_input(&ind2, zero2, 0);
    let mid_iop2 = fixture.fd.new_varnode_iop(&mid);
    fixture.fd.op_set_input(&ind2, mid_iop2, 1);

    fixture.fd.op_insert_end(&head, &fixture.b1);
    fixture.fd.op_insert_end(&mid, &fixture.b1);
    fixture.dump("base");

    fixture.fd.op_insert_before(&ind1, &mid);
    fixture.dump("guard1");

    fixture.fd.op_insert_end(&tail, &fixture.b1);
    fixture.fd.op_insert_before(&ind2, &ind1);
    fixture.dump("guard2");

    fixture.fd.op_insert_end(&succ_head, &fixture.b2);
    fixture.fd.op_insert_end(&alt_head, &fixture.b3);
    fixture.fd.op_insert_end(&multi_out, &fixture.b4);
    fixture.fd.bblocks.add_edge(fixture.b1.clone(), fixture.b2.clone());
    fixture.fd.bblocks.add_edge(fixture.b1.clone(), fixture.b3.clone());
    fixture.fd.bblocks.add_edge(fixture.b4.clone(), fixture.b5.clone());
    fixture.fd.bblocks.add_edge(fixture.b4.clone(), fixture.b6.clone());
    fixture.fd.bblocks.add_edge(fixture.b4.clone(), fixture.b7.clone());
    fixture.dump("edges");

    fixture.fd.op_uninsert(&ind1);
    fixture.dump("uninsert");
}
