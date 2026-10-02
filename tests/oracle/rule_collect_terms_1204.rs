use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleCollectTerms;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    fd: Funcdata,
    block: Arc<RwLock<dyn rudra::block::FlowBlock + Send + Sync>>,
    ops: Vec<PcodeOpRef>,
    op_names: HashMap<usize, String>,
    varnodes: Vec<VarnodeRef>,
    varnode_names: HashMap<usize, String>,
    next_op: usize,
    next_varnode: usize,
}

impl Fixture {
    fn new() -> Self {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        assert_eq!(fd.name, "GetStr");
        assert_eq!(fd.baseaddr.as_u64(), 0x36d0);
        assert_eq!(fd.size, 0);
        let block = fd.create_new_block();
        Self {
            fd,
            block,
            ops: Vec::new(),
            op_names: HashMap::new(),
            varnodes: Vec::new(),
            varnode_names: HashMap::new(),
            next_op: 0,
            next_varnode: 0,
        }
    }

    fn op_key(op: &PcodeOpRef) -> usize {
        Arc::as_ptr(&op.0) as usize
    }

    fn op_arc_key(op: &Arc<RwLock<PcodeOp>>) -> usize {
        Arc::as_ptr(op) as usize
    }

    fn varnode_key(vn: &VarnodeRef) -> usize {
        Arc::as_ptr(vn) as usize
    }

    fn remember_op(&mut self, op: PcodeOpRef, name: String) {
        let key = Self::op_key(&op);
        if self.op_names.insert(key, name).is_none() {
            self.ops.push(op);
        }
    }

    fn remember_varnode(&mut self, vn: VarnodeRef, name: String) {
        let key = Self::varnode_key(&vn);
        if self.varnode_names.insert(key, name).is_none() {
            self.varnodes.push(vn);
        }
    }

    fn op_name(&self, op: &PcodeOpRef) -> &str {
        self.op_names
            .get(&Self::op_key(op))
            .expect("registered fixture op")
    }

    fn op_arc_name(&self, op: &Arc<RwLock<PcodeOp>>) -> &str {
        self.op_names
            .get(&Self::op_arc_key(op))
            .expect("registered fixture op")
    }

    fn varnode_name(&self, vn: &VarnodeRef) -> &str {
        self.varnode_names
            .get(&Self::varnode_key(vn))
            .expect("registered fixture varnode")
    }

    fn discover(&mut self) {
        let block_ops = self.block.read().unwrap().get_ops();
        for op in &block_ops {
            if !self.op_names.contains_key(&Self::op_key(op)) {
                let name = format!("n{}", self.next_op);
                self.next_op += 1;
                self.remember_op(op.clone(), name);
            }
        }
        for op in &block_ops {
            let op_name = self.op_name(op).to_string();
            let (output, inputs) = {
                let op = op.0.read().unwrap();
                (op.output.clone(), op.inrefs.clone())
            };
            if let Some(output) = output {
                if !self.varnode_names.contains_key(&Self::varnode_key(&output)) {
                    self.remember_varnode(output, format!("{op_name}_out"));
                }
            }
            for input in inputs {
                if !self.varnode_names.contains_key(&Self::varnode_key(&input)) {
                    let name = format!("g{}", self.next_varnode);
                    self.next_varnode += 1;
                    self.remember_varnode(input, name);
                }
            }
        }
    }

    fn make_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember_varnode(vn.clone(), name.to_string());
        vn
    }

    fn make_constant(&mut self, name: &str, size: usize, value: u64) -> VarnodeRef {
        let vn = self.fd.new_constant(size, value);
        self.remember_varnode(vn.clone(), name.to_string());
        vn
    }

    fn make_op(
        &mut self,
        name: &str,
        opcode: OpCode,
        inputs: usize,
        output_size: usize,
    ) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x1000));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name.to_string());
        let output = self.fd.new_unique_out(output_size, &op);
        self.remember_varnode(output, format!("{name}_out"));
        op
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: VarnodeRef, slot: usize) {
        self.fd.op_set_input(op, vn, slot);
    }

    fn insert_end(&mut self, op: &PcodeOpRef) {
        self.fd.op_insert_end(op, &self.block.clone());
    }

    fn op_list(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter()
            .map(|op| self.op_name(op).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn op_state(&self, op: &PcodeOpRef) -> String {
        let op_guard = op.0.read().unwrap();
        let parent = op_guard
            .parent
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map(|parent| parent.read().unwrap().get_index())
            .unwrap_or(-1);
        let inputs = op_guard
            .inrefs
            .iter()
            .map(|vn| self.varnode_name(vn).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let output = op_guard
            .output
            .as_ref()
            .map(|vn| self.varnode_name(vn).to_string())
            .unwrap_or_else(|| "-".to_string());
        format!(
            "{}{{opc={},dead={},parent={},order={},inputs=[{}],output={}}}",
            self.op_name(op),
            op_guard.opcode as i32,
            u8::from(op_guard.is_dead()),
            parent,
            op_guard.start.get_order(),
            inputs,
            output,
        )
    }

    fn varnode_state(&self, vn: &VarnodeRef) -> String {
        let vn_guard = vn.read().unwrap();
        let space = vn_guard.get_space();
        let offset = if space == AddressSpace::Unique {
            "tmp".to_string()
        } else {
            format!("{:x}", vn_guard.get_offset())
        };
        let definition = vn_guard
            .def
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map(|op| self.op_arc_name(&op).to_string())
            .unwrap_or_else(|| "-".to_string());
        let descendants = vn_guard
            .descend
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|op| {
                let slot = op
                    .read()
                    .unwrap()
                    .inrefs
                    .iter()
                    .position(|input| Arc::ptr_eq(input, vn))
                    .expect("descendant retains input varnode");
                format!("{}.{}", self.op_arc_name(&op), slot)
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}{{space={},size={},offset={},constant={},input={},written={},free={},def={},desc=[{}]}}",
            self.varnode_name(vn),
            space.name(),
            vn_guard.get_size(),
            offset,
            u8::from(vn_guard.is_constant()),
            u8::from(vn_guard.is_input()),
            u8::from(vn_guard.is_written()),
            u8::from(vn_guard.is_free()),
            definition,
            descendants,
        )
    }

    fn dump(&mut self, case_name: &str, stage: &str, result: &str) {
        self.discover();
        let block_ops = self.block.read().unwrap().get_ops();
        let op_states = block_ops
            .iter()
            .map(|op| self.op_state(op))
            .collect::<Vec<_>>()
            .join(";");
        let varnode_states = self
            .varnodes
            .iter()
            .map(|vn| self.varnode_state(vn))
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "case={case_name}|stage={stage}|result={result}|block=[{}]|alive=[{}]|dead=[{}]|ops=[{}]|varnodes=[{}]",
            self.op_list(&block_ops),
            self.op_list(&self.fd.obank.alivelist),
            self.op_list(&self.fd.obank.deadlist),
            op_states,
            varnode_states,
        );
    }
}

fn run_like_case(name: &str, size: usize, coef0: u64, coef1: u64) {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", size, 0x40);
    let mult0 = fixture.make_op("mult0", OpCode::CPUI_INT_MULT, 2, size);
    let mult1 = fixture.make_op("mult1", OpCode::CPUI_INT_MULT, 2, size);
    let root = fixture.make_op("root", OpCode::CPUI_INT_ADD, 2, size);
    let constant0 = fixture.make_constant("coef0", size, coef0);
    let constant1 = fixture.make_constant("coef1", size, coef1);

    fixture.set_input(&mult0, x.clone(), 0);
    fixture.set_input(&mult0, constant0, 1);
    fixture.set_input(&mult1, x, 0);
    fixture.set_input(&mult1, constant1, 1);
    let mult0_out = mult0.0.read().unwrap().output.clone().unwrap();
    let mult1_out = mult1.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&root, mult0_out, 0);
    fixture.set_input(&root, mult1_out, 1);
    fixture.insert_end(&mult0);
    fixture.insert_end(&mult1);
    fixture.insert_end(&root);

    fixture.dump(name, "before", "na");
    let result = RuleCollectTerms::new()
        .apply_op(&root.0, &mut fixture.fd)
        .expect("RuleCollectTerms like-term case");
    fixture.dump(name, "after", &result.to_string());
}

fn run_constant_case(name: &str, size: usize, inner_value: u64, root_value: u64) {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", size, 0x40);
    // Keep creation and fixture-identity registration order identical on both
    // sides. Ghidra's termOrder deliberately compares any two constants equal.
    let root_constant = fixture.make_constant("root_const", size, root_value);
    let inner_constant = fixture.make_constant("inner_const", size, inner_value);
    let inner = fixture.make_op("inner", OpCode::CPUI_INT_ADD, 2, size);
    let root = fixture.make_op("root", OpCode::CPUI_INT_ADD, 2, size);

    fixture.set_input(&inner, x, 0);
    fixture.set_input(&inner, inner_constant, 1);
    let inner_out = inner.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&root, inner_out, 0);
    fixture.set_input(&root, root_constant, 1);
    fixture.insert_end(&inner);
    fixture.insert_end(&root);

    fixture.dump(name, "before", "na");
    let result = RuleCollectTerms::new()
        .apply_op(&root.0, &mut fixture.fd)
        .expect("RuleCollectTerms constant case");
    fixture.dump(name, "after", &result.to_string());
}

fn main() {
    run_like_case("like_nonoverflow", 8, 2, 3);
    run_like_case("like_storage_wrap", 1, 0xff, 2);
    run_like_case("like_uintb_wrap", 8, u64::MAX, 2);
    run_like_case("like_zero", 1, 0xff, 1);
    run_constant_case("constant_nonoverflow", 8, 3, 5);
    run_constant_case("constant_storage_wrap", 1, 0xff, 2);
    run_constant_case("constant_uintb_wrap", 8, u64::MAX, 2);
}
