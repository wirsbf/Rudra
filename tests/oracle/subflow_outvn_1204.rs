// SUBFLOW-OUTVN-UNWRAP-0001: Rugra comparand for the locked Ghidra 12.0.4
// SubvariableFlow::traceForwardSext / traceForward createLink outvn oracle.
// Mirrors tests/oracle/subflow_outvn_1204.cc case for case: the same
// sub-variable data-flows are built through the production Funcdata APIs and
// the production SubvariableFlow analysis is run, printing the shared
// observation format.
//
// For the None-precondition cases the comparand additionally enforces the
// convergence contract with internal assertions (doTrace must abort and the
// IR must be untouched): the locked oracle cannot run doTrace on that state
// because traceForwardSext's merged COPY/MULTIEQUAL/INT_* case passes the
// null outvn pointer into createLink (subflow.cc:895), whose
// setReplacement dereferences it (subflow.cc:70).  The assertions keep the
// shared stdout byte-comparable while pinning the Rust-side behavior.

use std::sync::Arc;

use rudra::address::Address;
use rudra::block::{BlockBasic, FlowBlock};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::subflow::SubvariableFlow;
use rudra::varnode::Varnode;

type BlockRef = Arc<std::sync::RwLock<dyn FlowBlock + Send + Sync>>;
type VnRef = Arc<std::sync::RwLock<Varnode>>;
type OpRef = rudra::op::PcodeOpRef;

struct Graph {
    fd: Funcdata,
    base: u64,
    next_offset: u64,
    blocks: Vec<BlockRef>,
    ops: Vec<(OpRef, &'static str)>,
}

impl Graph {
    fn new(name: &str, base: u64) -> Self {
        Graph {
            fd: Funcdata::new(name, Address::new(base), 0x20),
            base,
            next_offset: 0,
            blocks: Vec::new(),
            ops: Vec::new(),
        }
    }

    fn make_block(&mut self, index: i32) -> BlockRef {
        let block: BlockRef = Arc::new(std::sync::RwLock::new(BlockBasic::new(
            index,
            Address::new(self.base),
        )));
        self.fd.bblocks.add_block(block.clone());
        self.blocks.push(block.clone());
        block
    }

    fn make_op(&mut self, name: &'static str, opcode: OpCode, inputs: usize) -> OpRef {
        let pc = Address::new(self.base + self.next_offset);
        self.next_offset += 1;
        let op = self.fd.new_op(inputs, pc);
        self.fd.op_set_opcode(&op, opcode);
        self.ops.push((op.clone(), name));
        op
    }

    fn unique_out(&mut self, size: usize, op: &OpRef) -> VnRef {
        self.fd.new_unique_out(size, op)
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
        self.fd.op_insert_input(op, vn.clone(), slot);
    }

    fn insert_end(&mut self, op: &OpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn label_of(&self, op: &OpRef) -> Option<&'static str> {
        for (candidate, name) in &self.ops {
            if Arc::ptr_eq(&candidate.0, &op.0) {
                return Some(name);
            }
        }
        None
    }

    fn opcode_name(code: OpCode) -> &'static str {
        match code {
            OpCode::CPUI_COPY => "COPY",
            OpCode::CPUI_MULTIEQUAL => "MULTIEQUAL",
            OpCode::CPUI_INT_NEGATE => "INT_NEGATE",
            OpCode::CPUI_INT_XOR => "INT_XOR",
            OpCode::CPUI_INT_OR => "INT_OR",
            OpCode::CPUI_INT_AND => "INT_AND",
            OpCode::CPUI_INT_SEXT => "INT_SEXT",
            OpCode::CPUI_INT_ZEXT => "INT_ZEXT",
            OpCode::CPUI_SUBPIECE => "SUBPIECE",
            _ => "OTHER",
        }
    }

    fn vn_text(vn: Option<&VnRef>) -> String {
        let Some(vn) = vn else {
            return "null".to_string();
        };
        let value = vn.read().unwrap();
        if value.is_constant() {
            format!("c{}:{}", value.get_offset(), value.get_size())
        } else if value.get_space().name() == "unique" {
            format!("u:{}", value.get_size())
        } else {
            format!(
                "{}{}:{}",
                value.get_space().name(),
                value.get_offset(),
                value.get_size()
            )
        }
    }

    fn ops_text(&self) -> String {
        let mut out = String::from("[");
        let mut first = true;
        for block in &self.blocks {
            let block_guard = block.read().unwrap();
            let basic = block_guard
                .as_any()
                .downcast_ref::<BlockBasic>()
                .expect("basic block");
            for op in &basic.ops {
                if !first {
                    out.push(',');
                }
                first = false;
                let guard = op.0.read().unwrap();
                match self.label_of(op) {
                    Some(name) => out.push_str(name),
                    None => {
                        out.push_str("new_");
                        out.push_str(Self::opcode_name(guard.opcode));
                    }
                }
                out.push('=');
                out.push_str(Self::opcode_name(guard.opcode));
                out.push('(');
                for i in 0..guard.num_input() {
                    if i != 0 {
                        out.push(' ');
                    }
                    out.push_str(&Self::vn_text(guard.get_in(i)));
                }
                out.push_str(")->");
                out.push_str(&Self::vn_text(guard.get_out()));
            }
        }
        out.push(']');
        out
    }

    fn desc_text(&self, root: &VnRef) -> String {
        let mut desc = String::from("[");
        let mut first = true;
        for op in root.read().unwrap().descend_iter() {
            if !first {
                desc.push(',');
            }
            first = false;
            let op_ref = rudra::op::PcodeOpRef(op);
            match self.label_of(&op_ref) {
                Some(name) => desc.push_str(name),
                None => desc.push_str("new"),
            }
        }
        desc.push(']');
        desc
    }

    fn op_count(&self) -> usize {
        let mut count = 0usize;
        for block in &self.blocks {
            let block_guard = block.read().unwrap();
            if let Some(basic) = block_guard.as_any().downcast_ref::<BlockBasic>() {
                count += basic.ops.len();
            }
        }
        count
    }
}

// Shared builder for the sext-mode graphs (RuleSubvarSentry entry shape).
// Returns (root=out4, target op, target output).
struct SextGraph {
    root: VnRef,
    top: OpRef,
    tout4: VnRef,
    graph: Graph,
}

fn build_sext_graph(case_name: &str, base: u64, target_code: OpCode) -> SextGraph {
    let mut g = Graph::new(case_name, base);
    let b0 = g.make_block(0);
    let in1 = g.input(0x28, 1);
    let sextop = g.make_op("sext", OpCode::CPUI_INT_SEXT, 1);
    g.set_input(&sextop, &in1, 0);
    let out4 = g.unique_out(4, &sextop);
    g.insert_end(&sextop, &b0);

    let unary = matches!(target_code, OpCode::CPUI_COPY | OpCode::CPUI_INT_NEGATE);
    let target_inputs = if unary { 1 } else { 2 };
    let top = g.make_op("t", target_code, target_inputs);
    g.set_input(&top, &out4, 0);
    if target_code == OpCode::CPUI_MULTIEQUAL {
        g.set_input(&top, &out4, 1);
    } else if !unary {
        // 0xffffff80 passes setReplacement's sign-extension check
        // (subflow.cc:82-88) while exercising the binary input createLink
        // path in sext mode.
        let c = g.constant(4, 0xffffff80);
        g.set_input(&top, &c, 1);
    }
    let tout4 = g.unique_out(4, &top);
    g.insert_end(&top, &b0);

    let sub = g.make_op("sub", OpCode::CPUI_SUBPIECE, 2);
    g.set_input(&sub, &tout4, 0);
    let cz = g.constant(8, 0);
    g.set_input(&sub, &cz, 1);
    let pul1 = g.unique_out(1, &sub);
    g.insert_end(&sub, &b0);

    let use_op = g.make_op("use", OpCode::CPUI_COPY, 1);
    g.set_input(&use_op, &pul1, 0);
    g.unique_out(1, &use_op);
    g.insert_end(&use_op, &b0);

    SextGraph {
        root: out4,
        top,
        tout4,
        graph: g,
    }
}

fn run_sext_some(case_name: &str, target_code: OpCode) {
    let built = build_sext_graph(case_name, 0x6000, target_code);
    let mut g = built.graph;
    let out4 = built.root.clone();
    let mut subflow =
        SubvariableFlow::new(&mut g.fd, out4.clone(), 0xff, false, true, false);
    let traced = subflow.do_trace(&g.fd);
    if traced {
        subflow.do_replacement(&mut g.fd);
    }
    let ops = g.ops_text();
    println!("case={}|traced={}|ops={}", case_name, traced as u8, ops);
}

fn run_sext_none(case_name: &str, target_code: OpCode) {
    let built = build_sext_graph(case_name, 0x6100, target_code);
    let mut g = built.graph;
    let out4 = built.root.clone();
    let top = built.top.clone();
    let tout4 = built.tout4.clone();
    let before_ops = g.op_count();
    let before_desc = g.desc_text(&out4);

    // Production Funcdata::opUnsetOutput path (funcdata_op.cc:52-66).
    g.fd.op_unset_output(&top);

    let t_out_null = top.0.read().unwrap().get_out().is_none() as u8;
    let t_alive = {
        let guard = top.0.read().unwrap();
        !guard.is_dead()
            && guard
                .parent
                .as_ref()
                .map(|p| p.upgrade().is_some())
                .unwrap_or(false)
    } as u8;
    let tout4_written = tout4.read().unwrap().is_written() as u8;

    // Convergence contract: the merged COPY/MULTIEQUAL/INT_* case of
    // trace_forward_sext must abort the trace when the reader op has no
    // output, instead of panicking on the former unwrap (see TODO
    // SUBFLOW-OUTVN-UNWRAP-0001).  Enforced by assertion only so the shared
    // stdout stays byte-comparable with the locked oracle state line.
    let mut subflow = SubvariableFlow::new(&mut g.fd, out4.clone(), 0xff, false, true, false);
    let traced = subflow.do_trace(&g.fd);
    assert!(
        !traced,
        "case={}: do_trace must abort on null outvn",
        case_name
    );
    let after_desc = g.desc_text(&out4);
    assert_eq!(
        before_desc, after_desc,
        "case={}: failed trace must not rewire readers",
        case_name
    );
    assert_eq!(
        before_ops,
        g.op_count(),
        "case={}: failed trace must not alter the op layout",
        case_name
    );

    println!(
        "case={}|t_out_null={}|t_alive={}|tout4_written={}|root_desc={}|oracle_run=0|oracle_reason=traceForwardSext_null_outvn_deref_subflow_cc_895_to_70",
        case_name, t_out_null, t_alive, tout4_written, before_desc
    );
}

fn run_plain_some(case_name: &str, target_code: OpCode) {
    let mut g = Graph::new(case_name, 0x6200);
    let b0 = g.make_block(0);
    let root = g.input(0x30, 4);

    let unary = matches!(target_code, OpCode::CPUI_COPY);
    let target_inputs = if unary { 1 } else { 2 };
    let top = g.make_op("t", target_code, target_inputs);
    g.set_input(&top, &root, 0);
    if !unary {
        let value: u64 = if target_code == OpCode::CPUI_INT_OR {
            0x100
        } else {
            0xff
        };
        let c = g.constant(4, value);
        g.set_input(&top, &c, 1);
    }
    let tout4 = g.unique_out(4, &top);
    g.insert_end(&top, &b0);

    let sub = g.make_op("sub", OpCode::CPUI_SUBPIECE, 2);
    g.set_input(&sub, &tout4, 0);
    let cz = g.constant(8, 0);
    g.set_input(&sub, &cz, 1);
    let pul1 = g.unique_out(1, &sub);
    g.insert_end(&sub, &b0);

    let use_op = g.make_op("use", OpCode::CPUI_COPY, 1);
    g.set_input(&use_op, &pul1, 0);
    g.unique_out(1, &use_op);
    g.insert_end(&use_op, &b0);

    let mut subflow = SubvariableFlow::new(&mut g.fd, root, 0xff, true, false, false);
    let traced = subflow.do_trace(&g.fd);
    if traced {
        subflow.do_replacement(&mut g.fd);
    }
    let ops = g.ops_text();
    println!("case={}|traced={}|ops={}", case_name, traced as u8, ops);
}

fn main() {
    println!(
        "schema=1|fixture=SUBFLOW-OUTVN-UNWRAP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
    );
    run_sext_some("sext_some_copy", OpCode::CPUI_COPY);
    run_sext_some("sext_some_multiequal", OpCode::CPUI_MULTIEQUAL);
    run_sext_some("sext_some_int_negate", OpCode::CPUI_INT_NEGATE);
    run_sext_some("sext_some_int_xor", OpCode::CPUI_INT_XOR);
    run_sext_some("sext_some_int_or", OpCode::CPUI_INT_OR);
    run_sext_some("sext_some_int_and", OpCode::CPUI_INT_AND);
    run_sext_none("sext_none_copy", OpCode::CPUI_COPY);
    run_sext_none("sext_none_multiequal", OpCode::CPUI_MULTIEQUAL);
    run_sext_none("sext_none_int_negate", OpCode::CPUI_INT_NEGATE);
    run_sext_none("sext_none_int_xor", OpCode::CPUI_INT_XOR);
    run_sext_none("sext_none_int_or", OpCode::CPUI_INT_OR);
    run_sext_none("sext_none_int_and", OpCode::CPUI_INT_AND);
    run_plain_some("plain_some_copy", OpCode::CPUI_COPY);
    run_plain_some("plain_some_int_or", OpCode::CPUI_INT_OR);
    run_plain_some("plain_some_int_and", OpCode::CPUI_INT_AND);
}
