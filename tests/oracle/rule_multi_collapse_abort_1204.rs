use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::funcdata::Funcdata;
use rudra::op::{op_addl_flags, pcodeop_flags, PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RuleMultiCollapse;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct Fixture {
    fd: Funcdata,
    blocks: Vec<BlockRef>,
    block_names: HashMap<usize, String>,
    ops: Vec<PcodeOpRef>,
    op_names: HashMap<usize, String>,
    varnodes: Vec<VarnodeRef>,
    varnode_names: HashMap<usize, String>,
    next_op: usize,
    next_varnode: usize,
}

impl Fixture {
    fn new() -> Self {
        let fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        assert_eq!(fd.name, "GetStr");
        assert_eq!(fd.baseaddr.as_u64(), 0x36d0);
        assert_eq!(fd.size, 0);
        Self {
            fd,
            blocks: Vec::new(),
            block_names: HashMap::new(),
            ops: Vec::new(),
            op_names: HashMap::new(),
            varnodes: Vec::new(),
            varnode_names: HashMap::new(),
            next_op: 0,
            next_varnode: 0,
        }
    }

    fn block_key(block: &BlockRef) -> usize {
        Arc::as_ptr(block) as *const () as usize
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

    fn block_name(&self, block: Option<&BlockRef>) -> &str {
        block
            .and_then(|block| self.block_names.get(&Self::block_key(block)))
            .map(String::as_str)
            .unwrap_or("-")
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

    fn discover(&mut self) -> HashSet<usize> {
        let current_ops = self.fd.obank.optree.iter().cloned().collect::<Vec<_>>();
        for op in current_ops {
            if !self.op_names.contains_key(&Self::op_key(&op)) {
                let name = format!("n{}", self.next_op);
                self.next_op += 1;
                self.remember_op(op, name);
            }
        }

        let current_varnodes = self
            .fd
            .vbank
            .loc_tree
            .iter()
            .map(|vn| vn.0.clone())
            .collect::<Vec<_>>();
        let live = current_varnodes
            .iter()
            .map(Self::varnode_key)
            .collect::<HashSet<_>>();
        for vn in current_varnodes {
            if !self.varnode_names.contains_key(&Self::varnode_key(&vn)) {
                let name = format!("g{}", self.next_varnode);
                self.next_varnode += 1;
                self.remember_varnode(vn, name);
            }
        }
        live
    }

    fn make_block(&mut self, name: &str) -> BlockRef {
        let block = self.fd.create_new_block();
        self.block_names
            .insert(Self::block_key(&block), name.to_string());
        self.blocks.push(block.clone());
        block
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

    fn make_space(&mut self, name: &str, space: AddressSpace) -> VarnodeRef {
        let vn = self.fd.new_varnode_space(space);
        self.remember_varnode(vn.clone(), name.to_string());
        vn
    }

    fn add_edge(&mut self, from: &BlockRef, to: &BlockRef) {
        self.fd.bblocks.add_edge(from.clone(), to.clone());
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

    fn output(op: &PcodeOpRef) -> VarnodeRef {
        op.0
            .read()
            .unwrap()
            .output
            .clone()
            .expect("fixture op output")
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: VarnodeRef, slot: usize) {
        self.fd.op_set_input(op, vn, slot);
    }

    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) {
        self.fd.op_insert_end(op, block);
    }

    fn op_list(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter()
            .map(|op| self.op_name(op).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn all_op_list(&self) -> String {
        self.fd
            .obank
            .optree
            .iter()
            .map(|op| self.op_name(op).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn block_states(&self) -> String {
        self.blocks
            .iter()
            .map(|block| {
                let guard = block.read().unwrap();
                let incoming = (0..guard.size_in())
                    .map(|slot| {
                        let edge = guard.get_in(slot).expect("fixture incoming edge");
                        self.block_name(Some(&edge.point)).to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let outgoing = (0..guard.size_out())
                    .map(|slot| {
                        let edge = guard.get_out(slot).expect("fixture outgoing edge");
                        self.block_name(Some(&edge.point)).to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{}{{index={},in=[{}],out=[{}],ops=[{}]}}",
                    self.block_name(Some(block)),
                    guard.get_index(),
                    incoming,
                    outgoing,
                    self.op_list(&guard.get_ops()),
                )
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    fn op_state(&self, op: &PcodeOpRef) -> String {
        let guard = op.0.read().unwrap();
        let parent = guard.parent.as_ref().and_then(std::sync::Weak::upgrade);
        let inputs = guard
            .inrefs
            .iter()
            .map(|vn| self.varnode_name(vn).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let output = guard
            .output
            .as_ref()
            .map(|vn| self.varnode_name(vn).to_string())
            .unwrap_or_else(|| "-".to_string());
        format!(
            "{}{{opc={},dead={},mark={},marker={},commutative={},modified={},parent={},addr={:x},time={},order={},inputs=[{}],output={}}}",
            self.op_name(op),
            guard.opcode as i32,
            u8::from(guard.is_dead()),
            u8::from(guard.is_mark()),
            u8::from(guard.is_marker()),
            u8::from((guard.flags & pcodeop_flags::COMMUTATIVE) != 0),
            u8::from((guard.addlflags & op_addl_flags::MODIFIED) != 0),
            self.block_name(parent.as_ref()),
            guard.start.get_addr().as_u64(),
            guard.start.get_time(),
            guard.start.get_order(),
            inputs,
            output,
        )
    }

    fn descendant_slot(
        vn: &VarnodeRef,
        op: &Arc<RwLock<PcodeOp>>,
        mut occurrence: usize,
    ) -> usize {
        for (slot, input) in op.read().unwrap().inrefs.iter().enumerate() {
            if !Arc::ptr_eq(input, vn) {
                continue;
            }
            if occurrence == 0 {
                return slot;
            }
            occurrence -= 1;
        }
        panic!("descendant has no matching occurrence slot")
    }

    fn varnode_state(&self, vn: &VarnodeRef, live: &HashSet<usize>) -> String {
        if !live.contains(&Self::varnode_key(vn)) {
            return format!("{}{{present=0}}", self.varnode_name(vn));
        }

        let guard = vn.read().unwrap();
        let is_load_space = guard.descend.iter().filter_map(std::sync::Weak::upgrade).any(|op| {
            let op = op.read().unwrap();
            op.opcode == OpCode::CPUI_LOAD
                && op.inrefs.first().is_some_and(|input| Arc::ptr_eq(input, vn))
        });
        let definition = guard
            .def
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map(|op| self.op_arc_name(&op).to_string())
            .unwrap_or_else(|| "-".to_string());
        let mut occurrences = HashMap::<usize, usize>::new();
        let descendants = guard
            .descend
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|op| {
                let key = Self::op_arc_key(&op);
                let occurrence = occurrences.entry(key).or_insert(0);
                let slot = Self::descendant_slot(vn, &op, *occurrence);
                *occurrence += 1;
                format!("{}.{}", self.op_arc_name(&op), slot)
            })
            .collect::<Vec<_>>()
            .join(",");
        let offset = if is_load_space {
            format!("spaceid:{}", AddressSpace::from_id(guard.get_offset() as u8).name())
        } else {
            format!("{:x}", guard.get_offset())
        };
        format!(
            "{}{{present=1,space={},size={},offset={},create={},flags={:x},mark={},constant={},input={},written={},free={},heritage={},def={},desc=[{}]}}",
            self.varnode_name(vn),
            guard.get_space().name(),
            guard.get_size(),
            offset,
            guard.get_create_index(),
            guard.flags,
            u8::from(guard.is_mark()),
            u8::from(guard.is_constant()),
            u8::from(guard.is_input()),
            u8::from(guard.is_written()),
            u8::from(guard.is_free()),
            u8::from(guard.is_heritage_known()),
            definition,
            descendants,
        )
    }

    fn varnode_loc_list(&self) -> String {
        self.fd
            .vbank
            .loc_tree
            .iter()
            .map(|vn| self.varnode_name(&vn.0).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn varnode_def_list(&self) -> String {
        self.fd
            .vbank
            .def_tree
            .iter()
            .map(|vn| self.varnode_name(&vn.0).to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn dump(&mut self, case_name: &str, stage: &str, result: &str) {
        let live = self.discover();
        let op_states = self
            .ops
            .iter()
            .map(|op| self.op_state(op))
            .collect::<Vec<_>>()
            .join(";");
        let varnode_states = self
            .varnodes
            .iter()
            .map(|vn| self.varnode_state(vn, &live))
            .collect::<Vec<_>>()
            .join(";");
        println!(
            "case={case_name}|stage={stage}|result={result}|blocks=[{}]|all=[{}]|alive=[{}]|dead=[{}]|loads=[{}]|stores=[{}]|returns=[{}]|userops=[{}]|ops=[{}]|vloc=[{}]|vdef=[{}]|varnodes=[{}]",
            self.block_states(),
            self.all_op_list(),
            self.op_list(&self.fd.obank.alivelist),
            self.op_list(&self.fd.obank.deadlist),
            self.op_list(&self.fd.obank.loadlist),
            self.op_list(&self.fd.obank.storelist),
            self.op_list(&self.fd.obank.returnlist),
            self.op_list(&self.fd.obank.useroplist),
            op_states,
            self.varnode_loc_list(),
            self.varnode_def_list(),
            varnode_states,
        );
    }
}

fn apply_and_dump(mut fixture: Fixture, name: &str, root: &PcodeOpRef) {
    fixture.dump(name, "before", "na");
    let result = RuleMultiCollapse::new()
        .apply_op(&root.0, &mut fixture.fd)
        .expect("RuleMultiCollapse fixture case");
    fixture.dump(name, "after", &result.to_string());
}

// RULE-MULTICOLLAPSE-ABORT-0001 case: a constant branch plus an input
// branch. functionalEquality(const, input) is -1 and an unwritten input is
// not a MULTIEQUAL, so the rule must report no change (mirrors
// rule_multi_collapse_abort_1204.cc runConstNonconstMix).
fn run_const_nonconst_mix_no_change() {
    let mut fixture = Fixture::new();
    let block = fixture.make_block("b0");
    let c0a = fixture.make_constant("c0a", 1, 0);
    let x = fixture.make_input("x", 8, 0x40);
    let root = fixture.make_op("root", OpCode::CPUI_MULTIEQUAL, 2, 1);
    let use_op = fixture.make_op("use", OpCode::CPUI_COPY, 1, 1);
    fixture.set_input(&root, c0a, 0);
    fixture.set_input(&root, x, 1);
    fixture.set_input(&use_op, Fixture::output(&root), 0);
    fixture.insert_end(&root, &block);
    fixture.insert_end(&use_op, &block);
    apply_and_dump(fixture, "const_nonconst_mix_no_change", &root);
}

// RULE-MULTICOLLAPSE-ABORT-0001 case: functional-equality collapse whose
// skiplist holds a nested MULTIEQUAL. Processing skiplist entry zero
// destroys the root through the CSE substitute while entry one still has to
// re-read defining_branch.get_def() (ruleaction.cc:3306 is inside the
// skiplist loop). The defining branch's defining op must stay alive across
// the mid-loop op_destroy calls (mirrors rule_multi_collapse_abort_1204.cc
// runFuncEqSkiplistDefPreserved).
fn run_func_eq_skiplist_def_preserved() {
    let mut fixture = Fixture::new();
    let left = fixture.make_block("b0");
    let right = fixture.make_block("b1");
    let merge = fixture.make_block("b2");
    fixture.add_edge(&left, &merge);
    fixture.add_edge(&right, &merge);
    let x = fixture.make_input("x", 8, 0x40);
    let left_constant = fixture.make_constant("left_const", 8, 5);
    let right_constant = fixture.make_constant("right_const", 8, 5);
    let third_constant = fixture.make_constant("third_const", 8, 5);
    let cse_constant = fixture.make_constant("cse_const", 8, 5);
    let left_add = fixture.make_op("left_add", OpCode::CPUI_INT_ADD, 2, 8);
    let right_add = fixture.make_op("right_add", OpCode::CPUI_INT_ADD, 2, 8);
    let third_add = fixture.make_op("third_add", OpCode::CPUI_INT_ADD, 2, 8);
    let nested = fixture.make_op("nested", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let root = fixture.make_op("root", OpCode::CPUI_MULTIEQUAL, 2, 8);
    let cse = fixture.make_op("cse", OpCode::CPUI_INT_ADD, 2, 8);
    let nested_use = fixture.make_op("nested_use", OpCode::CPUI_COPY, 1, 8);
    let root_use = fixture.make_op("root_use", OpCode::CPUI_COPY, 1, 8);
    fixture.set_input(&left_add, x.clone(), 0);
    fixture.set_input(&left_add, left_constant, 1);
    fixture.set_input(&right_add, x.clone(), 0);
    fixture.set_input(&right_add, right_constant, 1);
    fixture.set_input(&third_add, x.clone(), 0);
    fixture.set_input(&third_add, third_constant, 1);
    fixture.set_input(&nested, Fixture::output(&left_add), 0);
    fixture.set_input(&nested, Fixture::output(&third_add), 1);
    fixture.set_input(&root, Fixture::output(&nested), 0);
    fixture.set_input(&root, Fixture::output(&right_add), 1);
    fixture.set_input(&cse, x, 0);
    fixture.set_input(&cse, cse_constant, 1);
    fixture.set_input(&nested_use, Fixture::output(&nested), 0);
    fixture.set_input(&root_use, Fixture::output(&root), 0);
    fixture.insert_end(&left_add, &left);
    fixture.insert_end(&right_add, &right);
    fixture.insert_end(&third_add, &right);
    fixture.insert_end(&nested, &merge);
    fixture.insert_end(&root, &merge);
    fixture.insert_end(&cse, &merge);
    fixture.insert_end(&nested_use, &merge);
    fixture.insert_end(&root_use, &merge);
    apply_and_dump(fixture, "func_eq_skiplist_def_preserved", &root);
}

// RULE-MULTICOLLAPSE-ABORT-0001 case: the abort shape. A MULTIEQUAL whose
// branches are two DISTINCT same-valued constant objects makes the locked
// oracle dereference null at ruleaction.cc:3306 (observed as SIGSEGV by the
// forked C++ fixture). Rugra must NOT abort here: constant-value identity
// is the level-0 equality proof (expression.cc:409-412), so the collapse
// proceeds on the absolute path exactly as Ghidra's cc:3279/cc:3334 does
// for an identical constant object (mirrors rule_multi_collapse_abort_1204.cc
// runConstPairDistinct; the oracle's crash observation is recorded there).
fn run_const_pair_distinct_objects() {
    let mut fixture = Fixture::new();
    let block = fixture.make_block("b0");
    let c0a = fixture.make_constant("c0a", 1, 0);
    let c0b = fixture.make_constant("c0b", 1, 0);
    let root = fixture.make_op("root", OpCode::CPUI_MULTIEQUAL, 2, 1);
    let use_op = fixture.make_op("use", OpCode::CPUI_COPY, 1, 1);
    fixture.set_input(&root, c0a, 0);
    fixture.set_input(&root, c0b, 1);
    fixture.set_input(&use_op, Fixture::output(&root), 0);
    fixture.insert_end(&root, &block);
    fixture.insert_end(&use_op, &block);
    apply_and_dump(fixture, "const_pair_distinct_objects", &root);
}

fn main() {
    run_const_nonconst_mix_no_change();
    run_func_eq_skiplist_def_preserved();
    run_const_pair_distinct_objects();
}
