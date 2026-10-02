// MERGE-FORCEMERGE-PANIC-0001: Rugra comparand for the locked Ghidra
// 12.0.4 merge action survival oracle (coreaction.cc:5717-5727 /
// coreaction.hh:414).  Mirrors tests/oracle/merge_forcepanic_1204.cc: the
// real default pipeline root is built through `build_default_pipeline`
// (the single construction path behind ActionDatabase::set_default_actions),
// the merge-group children assignhigh..mergetype are driven in tree order
// through the exact perform_child() call ActionGroup::apply makes, with
// each child's panic channel caught the way the oracle fixture catches
// LowlevelError.  The prestate holds two same-size written Varnodes at
// stack:0x100 created through the raw bank (a1 COPY output, s1 SUBPIECE
// output feeding INT_ADD) — the cluster is ungated at mergerequired, so
// the only mergeAddrTied pass skips it; after markimplied marks s1
// implied, the ADDRTIED|MAPPED property is installed on a1 mid-sequence
// (the ActionDynamicSymbols setSymbolProperties arrival timing of the
// real regression).  ActionMergeType must then still complete without
// panic: Ghidra's mergetype runs mergeByDatatype only (coreaction.hh:414)
// and never re-enters mergeAddrTied after markimplied
// (MERGE-FORCEMERGE-PANIC-0001).

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
    // heritage-style free-varnode creation paths; the ADDRTIED|MAPPED
    // property arrives mid-sequence below, reproducing the arrival
    // timing of the real regression).
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
    println!("schema=1|fixture=MERGE-FORCEMERGE-PANIC-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

    let mut root: ActionRestartGroup = build_default_pipeline();
    let names: Vec<String> = root.child_names().into_iter().map(String::from).collect();
    let start = names
        .iter()
        .position(|n| n == "assignhigh")
        .expect("merge-group sequence missing assignhigh");
    let stop_exclusive = names
        .iter()
        .position(|n| n == "mergetype")
        .expect("merge-group sequence missing mergetype")
        + 1;
    let seq: Vec<&str> = names[start..stop_exclusive].iter().map(|s| s.as_str()).collect();
    println!("seq={}", seq.join(","));

    // Minimal Funcdata mirroring the oracle prestate: stack address 0x100
    // holds a1 (COPY output, addrtied) and s1 (SUBPIECE output feeding
    // INT_ADD) in one exact-location range; r0 < r1 < r2 in one block so
    // the first mergeAddrTied force-merge succeeds without intersection.
    let mut g = Graph::new("merge_forcepanic", 0x6000);
    let b0 = g.make_block(0);
    let ct4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
        "int".to_string(),
        4,
        TypeMetatype::Int,
    )));

    let c4x = g.constant(4, 5);
    let r0 = g.make_op(OpCode::CPUI_COPY, 1);
    g.set_input(&r0, &c4x, 0);
    let a1 = g.stack_varnode(4, 0x100, &ct4);
    g.fd.op_set_output(&PcodeOpRef(r0.clone()), a1.clone());
    g.insert_end(&r0, &b0);

    let c8a = g.constant(8, 0x11223344);
    let c1 = g.constant(1, 0);
    let r1 = g.make_op(OpCode::CPUI_SUBPIECE, 2);
    g.set_input(&r1, &c8a, 0);
    g.set_input(&r1, &c1, 1);
    let s1 = g.stack_varnode(4, 0x100, &ct4);
    g.fd.op_set_output(&PcodeOpRef(r1.clone()), s1.clone());
    g.insert_end(&r1, &b0);

    let c4b = g.constant(4, 7);
    let r2 = g.make_op(OpCode::CPUI_INT_ADD, 2);
    g.set_input(&r2, &s1, 0);
    g.set_input(&r2, &c4b, 1);
    let t2 = g
        .fd
        .new_unique_out(4, &PcodeOpRef(r2.clone()));
    t2.write().unwrap().v_type = Some(ct4.clone());
    g.insert_end(&r2, &b0);

    g.track(&a1, "a1");
    g.track(&s1, "s1");
    g.track(&t2, "t2");

    println!("pre|{}", g.ir_text());

    // Drive the merge-group children through the exact perform_child()
    // call ActionGroup::apply makes, catching the panic channel the way
    // the oracle catches LowlevelError.  Every act line must show
    // exc=none: merge_addr_tied runs only inside mergerequired (before
    // markimplied), and mergetype runs merge_by_datatype only.
    let mut verdict = "PIPELINE-OK";
    let mid = names
        .iter()
        .position(|n| n == "mergeadjacent")
        .expect("merge-group sequence missing mergeadjacent");
    for index in start..stop_exclusive {
        if index == mid {
            // Install the addrtied|mapped property on a1 mid-sequence,
            // exactly as ActionDynamicSymbols' setSymbolProperties lands
            // it between markimplied and mergeadjacent in the real
            // pipeline.  Both sides perform the identical installation.
            a1.write().unwrap().flags |= varnode_flags::ADDRTIED | varnode_flags::MAPPED;
            println!("install=addrtied:mapped:a1");
        }
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
