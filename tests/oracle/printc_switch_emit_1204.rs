// PRINTC-SWITCH-EMIT-0001: Rugra side of the locked Ghidra 12.0.4
// PrintC::emitBlockSwitch + emitSwitchCase bilateral fixture
// (printc.cc:3313-3353 / 3129-3158). Mirrors printc_switch_emit_1204.cc:
// hand-built BlockSwitch (control block + case blocks + case_values +
// optional default) driven through PrintC::emit_block_graph — the same
// emit_block_structured dispatch the main pipeline uses — with a fresh
// EmitNoMarkup, so the observation is exactly the switch emission bytes.
//
// Case bodies are 2-input RETURNs (in(0) = placeholder indirect slot,
// in(1) = const value) matching the oracle's post-ActionReturnRecovery
// shape. The switch variable is a const-space varnode (value 3, int type)
// so both sides render the header expression through their constant paths.

use rudra::address::{Address, SeqNum};
use rudra::block::{BlockBasic, BlockGraph, BlockSwitch};
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;
use std::sync::{Arc, RwLock};

type BlockArc = Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>;

fn const_varnode(value: u64) -> Arc<RwLock<Varnode>> {
    Arc::new(RwLock::new(Varnode::new_with_space(4, AddressSpace::Const, value)))
}

fn make_op(index: u32, opcode: OpCode) -> PcodeOpRef {
    let mut op = PcodeOp::new(SeqNum::new(Address::new(index as u64), index), opcode);
    op.set_opcode_flags(opcode);
    PcodeOpRef(Arc::new(RwLock::new(op)))
}

// 2-input RETURN: in(0) = placeholder indirect slot (never read), in(1) =
// the const return value.
fn make_return(op: &PcodeOpRef, value: u64) {
    let mut o = op.0.write().unwrap();
    o.inrefs.push(const_varnode(0x1000));
    o.inrefs.push(const_varnode(value));
}

fn basic_block(index: i32, ops: Vec<PcodeOpRef>) -> BlockArc {
    let mut block = BlockBasic::new(index, Address::new(0x1000 + index as u64 * 0x10));
    block.ops = ops;
    Arc::new(RwLock::new(block))
}

struct SwitchBuild {
    head: BlockArc,
    cases: Vec<BlockArc>,
    default_case: Option<BlockArc>,
    case_values: Vec<Vec<u64>>,
    index_varnode: Arc<RwLock<Varnode>>,
}

impl SwitchBuild {
    fn new(switch_var_value: u64) -> Self {
        let index_varnode = const_varnode(switch_var_value);
        let branchind = make_op(0, OpCode::CPUI_BRANCHIND);
        branchind.0.write().unwrap().inrefs.push(index_varnode.clone());
        let head = basic_block(0, vec![branchind]);
        SwitchBuild {
            head,
            cases: Vec::new(),
            default_case: None,
            case_values: Vec::new(),
            index_varnode,
        }
    }

    fn add_case(&mut self, values: Vec<u64>, ret_value: u64, op_index: u32) -> BlockArc {
        let ret = make_op(op_index, OpCode::CPUI_RETURN);
        make_return(&ret, ret_value);
        let block = basic_block(self.cases.len() as i32 + 1, vec![ret]);
        self.cases.push(block.clone());
        self.case_values.push(values);
        block
    }

    fn add_empty_case(&mut self, values: Vec<u64>) -> BlockArc {
        let block = basic_block(self.cases.len() as i32 + 1, Vec::new());
        self.cases.push(block.clone());
        self.case_values.push(values);
        block
    }

    fn add_default(&mut self, ret_value: u64) {
        let ret = make_op(95, OpCode::CPUI_RETURN);
        make_return(&ret, ret_value);
        let block = basic_block(90, vec![ret]);
        self.default_case = Some(block);
    }

    fn render(&self) -> String {
        let switch: BlockArc = Arc::new(RwLock::new(BlockSwitch {
            index: 0,
            control: self.head.clone(),
            cases: self.cases.clone(),
            default_case: self.default_case.clone(),
            jump: None,
            case_gototypes: vec![0; self.cases.len()],
            default_gototype: 0,
            case_order: Vec::new(),
            case_isexit: vec![false; self.cases.len()],
            default_isexit: false,
            default_label: None,
            default_order: None,
            case_values: self.case_values.clone(),
            index_varnode: Some(self.index_varnode.clone()),
            incoming: Vec::new(),
            outgoing: Vec::new(),
            parent: None,
            flags: 0,
        }));
        let mut graph = BlockGraph::new();
        graph.add_block(switch);
        let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        printer.emit_block_graph(&graph);
        let emit = printer
            .take_emit()
            .into_any()
            .downcast::<EmitNoMarkup>()
            .expect("PrintC fixture must retain EmitNoMarkup");
        emit.debug_get_output_ref().to_owned()
    }
}

fn to_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// Same structural normalization as the .cc side: switch(E), verbatim
// case/default labels, body statements reduced to kind with indent kept.
fn summarize(text: &str) -> String {
    let mut out = String::new();
    for line in text.split('\n') {
        let body = line.trim_start_matches(' ');
        let indent = line.len() - body.len();
        let pad = " ".repeat(indent);
        if body.starts_with("switch") {
            out.push_str(&format!("{pad}switch(E)\n"));
        } else if body.starts_with("case ") || body == "default:" {
            out.push_str(line);
            out.push('\n');
        } else if body == "break;" {
            out.push_str(&format!("{pad}break\n"));
        } else if body.starts_with("return") {
            out.push_str(&format!("{pad}return\n"));
        } else if body.contains(" = ") {
            out.push_str(&format!("{pad}assign\n"));
        } else if !body.is_empty() {
            out.push_str(&format!("{pad}other\n"));
        }
    }
    out
}

fn emit_case(name: &str, raw: &str, hex: bool) {
    if hex {
        println!("{name}={}", to_hex(raw));
    } else {
        println!("{name}={}", summarize(raw));
    }
}

fn main() {
    let raw = std::env::args().nth(1).as_deref() == Some("--raw");

    // 1. two_case_return
    {
        let mut s = SwitchBuild::new(3);
        s.add_case(vec![0], 10, 1);
        s.add_case(vec![1], 20, 2);
        emit_case("two_case_return", &s.render(), raw);
    }

    // 2. single_case_default
    {
        let mut s = SwitchBuild::new(3);
        s.add_case(vec![5], 60, 1);
        s.add_default(7);
        emit_case("single_case_default", &s.render(), raw);
    }

    // 3. multi_label_first
    {
        let mut s = SwitchBuild::new(3);
        s.add_case(vec![2, 3], 10, 1);
        s.add_case(vec![9], 20, 2);
        emit_case("multi_label_first", &s.render(), raw);
    }

    // 4. break_exit_form: first case has an empty body flowing to the
    // formal exit (isexit=true, not last) — the explicit break.
    {
        let mut s = SwitchBuild::new(3);
        s.add_empty_case(vec![0]);
        s.add_case(vec![1], 30, 2);
        s.add_case(vec![2], 40, 3);
        emit_case("break_exit_form", &s.render(), raw);
    }
}
