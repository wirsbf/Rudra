// MERGE-OVERLAPLOC-FLAGUNION-1204: Rugra comparand for the locked Ghidra
// 12.0.4 overlapLoc flag-union gate oracle (varnode.cc:1791-1819 +
// merge.cc:629). Mirrors tests/oracle/merge_overlaploc_1204.cc: the real
// default pipeline root is built through `build_default_pipeline` (the
// single construction path behind ActionDatabase::set_default_actions),
// and the merge-group children assignhigh..markimplied are driven in tree
// order through the exact perform_child() call ActionGroup::apply makes,
// with each child's panic channel caught the way the oracle fixture
// catches LowlevelError.
//
// Positive case "cross_run_head_union": run 1 head a@0x200 (raw), non-head
// member b@0x200 (addrtied), run 2 head c@0x202 (addrtied, overlapping).
// overlapLoc's gate unions HEAD flags across runs — c's addrtied counts,
// b's does not — so the cluster is force-merged: a+b share one 2-instance
// HighVariable, c stays separate.
//
// Negative case "same_loc_later_member_no_gate": only a non-head
// same-location member carries addrtied; the gate must fail and no merge
// happens (the endLoc(size,addr,written) jump skips every same-location
// member, so its flags are never read).

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
    // heritage-style free-varnode creation paths). The addrtied gates are
    // installed at build time, reproducing the production arrival of the
    // property before the merge group runs.
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

    fn same_text(&self) -> String {
        let mut out = String::from("same=");
        let mut first = true;
        for i in 0..self.vns.len() {
            for j in (i + 1)..self.vns.len() {
                if !first {
                    out.push(';');
                }
                first = false;
                let same = {
                    let a = self.vns[i].0.read().unwrap();
                    let b = self.vns[j].0.read().unwrap();
                    match (&a.high, &b.high) {
                        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                        (None, None) => true,
                        _ => false,
                    }
                };
                out.push_str(&format!("{}~{}={}", self.vns[i].1, self.vns[j].1, u8::from(same)));
            }
        }
        out
    }
}

fn main() {
    println!("schema=1|fixture=MERGE-OVERLAPLOC-FLAGUNION-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");

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

    // ---- Positive case: cross-run head union gates the cluster ----
    {
        let mut g = Graph::new("cross_run_head_union", 0x6000);
        let b0 = g.make_block(0);
        let ct4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(),
            4,
            TypeMetatype::Int,
        )));

        let c7 = g.constant(4, 7);
        let r0 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&r0, &c7, 0);
        let a = g.stack_varnode(4, 0x200, &ct4);
        g.fd.op_set_output(&PcodeOpRef(r0.clone()), a.clone());
        g.insert_end(&r0, &b0);

        let c5 = g.constant(4, 5);
        let r1 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&r1, &c5, 0);
        let b = g.stack_varnode(4, 0x200, &ct4);
        g.fd.op_set_output(&PcodeOpRef(r1.clone()), b.clone());
        // Non-head member gate — must NOT count toward the cluster gate.
        b.write().unwrap().flags |= varnode_flags::ADDRTIED;
        g.insert_end(&r1, &b0);

        let c3 = g.constant(4, 3);
        let r2 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&r2, &c3, 0);
        let c = g.stack_varnode(4, 0x202, &ct4);
        g.fd.op_set_output(&PcodeOpRef(r2.clone()), c.clone());
        // Run-2 head gate — MUST count toward the cluster gate.
        c.write().unwrap().flags |= varnode_flags::ADDRTIED;
        g.insert_end(&r2, &b0);

        g.track(&a, "a");
        g.track(&b, "b");
        g.track(&c, "c");

        println!("case=cross_run_head_union|pre|{}|{}", g.ir_text(), g.same_text());
        let mut verdict = "PIPELINE-OK";
        // rule_onceperfunc children latch STATUS_END after the first
        // perform (action.cc:352-356); reset each child's executor state
        // for this Funcdata exactly as ActionRestartGroup::reset cascades
        // (action.cc:408-416) so the second case runs the real apply
        // bodies.
        for index in start..stop_exclusive {
            if let Some(state) = root.child_state_mut(index) {
                state.reset_for_function();
            }
        }
        for index in start..stop_exclusive {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                root.perform_child(index, &mut g.fd)
            }));
            let (res, exc) = match outcome {
                Ok(Ok(value)) => (value, "none".to_string()),
                Ok(Err(error)) => (0, format!("{error}")),
                Err(payload) => {
                    let message = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "panic".to_string());
                    (0, message)
                }
            };
            println!("case=cross_run_head_union|act={}|res={res}|exc={exc}", names[index]);
            if exc != "none" {
                verdict = "PIPELINE-THREW";
                break;
            }
        }
        println!("case=cross_run_head_union|post|{}|{}", g.ir_text(), g.same_text());
        println!("case=cross_run_head_union|verdict={verdict}");
    }

    // ---- Negative case: same-location later member does NOT gate ----
    {
        let mut g = Graph::new("same_loc_later_member_no_gate", 0x7000);
        let b0 = g.make_block(0);
        let ct4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(),
            4,
            TypeMetatype::Int,
        )));

        let c7 = g.constant(4, 7);
        let r0 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&r0, &c7, 0);
        let a = g.stack_varnode(4, 0x200, &ct4);
        g.fd.op_set_output(&PcodeOpRef(r0.clone()), a.clone());
        g.insert_end(&r0, &b0);

        let c5 = g.constant(4, 5);
        let r1 = g.make_op(OpCode::CPUI_COPY, 1);
        g.set_input(&r1, &c5, 0);
        let b = g.stack_varnode(4, 0x200, &ct4);
        g.fd.op_set_output(&PcodeOpRef(r1.clone()), b.clone());
        // Later member only — must NOT gate the cluster.
        b.write().unwrap().flags |= varnode_flags::ADDRTIED;
        g.insert_end(&r1, &b0);

        g.track(&a, "a");
        g.track(&b, "b");

        println!("case=same_loc_later_member_no_gate|pre|{}|{}", g.ir_text(), g.same_text());
        let mut verdict = "PIPELINE-OK";
        // Reset the latched STATUS_END from the first case so every child
        // applies to this second, independent Funcdata.
        for index in start..stop_exclusive {
            if let Some(state) = root.child_state_mut(index) {
                state.reset_for_function();
            }
        }
        for index in start..stop_exclusive {
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                root.perform_child(index, &mut g.fd)
            }));
            let (res, exc) = match outcome {
                Ok(Ok(value)) => (value, "none".to_string()),
                Ok(Err(error)) => (0, format!("{error}")),
                Err(payload) => {
                    let message = payload
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_else(|| "panic".to_string());
                    (0, message)
                }
            };
            println!("case=same_loc_later_member_no_gate|act={}|res={res}|exc={exc}", names[index]);
            if exc != "none" {
                verdict = "PIPELINE-THREW";
                break;
            }
        }
        println!("case=same_loc_later_member_no_gate|post|{}|{}", g.ir_text(), g.same_text());
        println!("case=same_loc_later_member_no_gate|verdict={verdict}");
    }
}
