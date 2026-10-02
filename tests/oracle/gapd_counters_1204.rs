// GAPD-COUNTERS-1204: Rugra comparand for the locked Ghidra 12.0.4 counter
// oracle (coreaction.cc:3020-3021 / 3434 + action.cc:362).  Mirrors
// tests/oracle/gapd_counters_1204.cc: the real default pipeline root is
// built through `build_default_pipeline` (the single construction path
// behind ActionDatabase::set_default_actions), and the merge-group children
// assignhigh..markimplied are driven in tree order through the exact
// perform_child() call ActionGroup::apply makes, with each child's panic
// channel caught the way the oracle fixture catches LowlevelError.
//
// The prestate holds two same-size written Varnodes at stack:0x200 created
// through the raw bank — m2 (COPY output, addrtied gate installed at build
// time) and m1 (COPY output, raw) — plus unique outputs q2/q1 (no
// descendants), z1 (INT_MULT of two constants, one descendant) and w1 (no
// descendants).  mergerequired force-merges the gated exact-location
// cluster into a 2-instance HighVariable, markexplicit must mark m1
// explicit through the numInstances rule (COREACTION-BASEEXPLICIT-NUMINST-
// 0001), and markimplied's perform must return the candidate count 1
// (COREACTION-MARKIMPLIED-COUNT-0001).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, RwLock};

use rudra::action::{build_default_pipeline, ActionRestartGroup};
use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::op::PcodeOpRef;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
use rudra::varnode::varnode_flags;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<RwLock<rudra::varnode::Varnode>>;
type OpRef = Arc<RwLock<rudra::op::PcodeOp>>;

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    vns: Vec<(VnRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
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

    fn make_op(&mut self, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        op.0.clone()
    }

    fn constant(&mut self, size: usize, value: u64) -> VnRef {
        self.fd.new_constant(size, value)
    }

    fn set_input(&mut self, op: &OpRef, vn: &VnRef, slot: usize) {
        self.fd
            .op_insert_input(&PcodeOpRef(op.clone()), vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(&PcodeOpRef(op.clone()), block);
    }

    // Mirror of the oracle fixture's Graph::stackVarnode (raw
    // vbank.create — no newVarnode property tail, matching the
    // heritage-style free-varnode creation paths).  The addrtied gate for
    // m2 is installed at build time, reproducing the production arrival of
    // the property before the merge group runs.
    fn stack_varnode(&mut self, size: usize, offset: u64, ct: &Arc<Datatype>) -> VnRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Stack, offset);
        vn.write().unwrap().v_type = Some(ct.clone());
        vn
    }

    fn track(&mut self, vn: &VnRef, name: &'static str) {
        self.vns.push((vn.clone(), name));
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
                "{name}:in={},wr={},ex={},im={},at={},hi={hi}",
                u8::from(vn.is_input()),
                u8::from(vn.is_written()),
                u8::from(vn.is_explicit()),
                u8::from(vn.is_implied()),
                u8::from(vn.is_addr_tied()),
            ));
        }
        vns.push(']');
        format!("vns={vns}")
    }
}

fn main() {
    println!("schema=1|fixture=GAPD-COUNTERS-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let mut root: ActionRestartGroup = build_default_pipeline();
    let names: Vec<String> = root.child_names().into_iter().map(String::from).collect();
    let start = names
        .iter()
        .position(|n| n == "assignhigh")
        .expect("merge-group sequence missing assignhigh");
    let stop_exclusive = names
        .iter()
        .position(|n| n == "markimplied")
        .expect("merge-group sequence missing markimplied")
        + 1;
    let seq: Vec<&str> = names[start..stop_exclusive].iter().map(|s| s.as_str()).collect();
    println!("seq={}", seq.join(","));

    // Minimal Funcdata mirroring the oracle prestate: stack address 0x200
    // holds m2 (COPY output, addrtied gate) and m1 (COPY output, raw) in
    // one exact-location range; m2 is created FIRST so its def SeqNum sorts
    // before m1's.  Covers [r0..r1] and [r2..r3] are disjoint, so the
    // forced merge at mergerequired builds the 2-instance HighVariable
    // without snipping.  z1 is the sole markimplied candidate.
    let mut g = Graph::new("gapd_counters", 0x6000);
    let b0 = g.make_block(0);
    let ct4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(),
        4,
        TypeMetatype::Int,
    )));

    let c9 = g.constant(4, 9);
    let r0 = g.make_op(OpCode::CPUI_COPY, 1);
    g.set_input(&r0, &c9, 0);
    let m2 = g.stack_varnode(4, 0x200, &ct4);
    g.fd.op_set_output(&PcodeOpRef(r0.clone()), m2.clone());
    // Gate the exact-location cluster: the addrtied property production
    // installs on in-scope stack locals before the merge group runs.
    m2.write().unwrap().flags |= varnode_flags::ADDRTIED;
    g.insert_end(&r0, &b0);

    let c2 = g.constant(4, 2);
    let r1 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    g.set_input(&r1, &m2, 0);
    g.set_input(&r1, &c2, 1);
    let q2 = g.fd.new_unique_out(4, &PcodeOpRef(r1.clone()));
    q2.write().unwrap().v_type = Some(ct4.clone());
    g.insert_end(&r1, &b0);

    let c5 = g.constant(4, 5);
    let r2 = g.make_op(OpCode::CPUI_COPY, 1);
    g.set_input(&r2, &c5, 0);
    let m1 = g.stack_varnode(4, 0x200, &ct4);
    g.fd.op_set_output(&PcodeOpRef(r2.clone()), m1.clone());
    g.insert_end(&r2, &b0);

    let c1 = g.constant(4, 1);
    let r3 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    g.set_input(&r3, &m1, 0);
    g.set_input(&r3, &c1, 1);
    let q1 = g.fd.new_unique_out(4, &PcodeOpRef(r3.clone()));
    q1.write().unwrap().v_type = Some(ct4.clone());
    g.insert_end(&r3, &b0);

    let c3 = g.constant(4, 3);
    let c4 = g.constant(4, 4);
    let r4 = g.make_op(OpCode::CPUI_INT_MULT, 2);
    g.set_input(&r4, &c3, 0);
    g.set_input(&r4, &c4, 1);
    let z1 = g.fd.new_unique_out(4, &PcodeOpRef(r4.clone()));
    z1.write().unwrap().v_type = Some(ct4.clone());
    g.insert_end(&r4, &b0);

    let c8 = g.constant(4, 8);
    let r5 = g.make_op(OpCode::CPUI_INT_OR, 2);
    g.set_input(&r5, &z1, 0);
    g.set_input(&r5, &c8, 1);
    let w1 = g.fd.new_unique_out(4, &PcodeOpRef(r5.clone()));
    w1.write().unwrap().v_type = Some(ct4.clone());
    g.insert_end(&r5, &b0);

    g.track(&m2, "m2");
    g.track(&m1, "m1");
    g.track(&q2, "q2");
    g.track(&q1, "q1");
    g.track(&z1, "z1");
    g.track(&w1, "w1");

    println!("pre|{}", g.ir_text());

    // Drive the merge-group children assignhigh..markimplied through the
    // exact perform_child() call ActionGroup::apply makes, catching the
    // panic channel the way the oracle catches LowlevelError.  The decisive
    // observations are act=markexplicit|res=5 (m1 explicit via the
    // numInstances rule) and act=markimplied|res=1 (z1 popped once and
    // implied).
    let mut verdict = "PIPELINE-OK";
    for index in start..stop_exclusive {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            root.perform_child(index, &mut g.fd)
        }));
        let (res, exc) = match outcome {
            Ok(Ok(value)) => (value, "none".to_string()),
            Ok(Err(error)) => {
                // Rust Result error channel (mirrors the oracle's
                // LowlevelError text surface).
                (0, format!("{error}"))
            }
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic".to_string());
                (0, message)
            }
        };
        println!("act={}|res={res}|exc={exc}", names[index]);
        if exc != "none" {
            verdict = "PIPELINE-THREW";
            break;
        }
    }

    println!("post|{}", g.ir_text());
    println!("verdict={verdict}");
}
