use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::block::FlowBlock;
use rudra::expression::{functional_equality, functional_equality_level, AddExpression};
use rudra::funcdata::Funcdata;
use rudra::op::{op_addl_flags, pcodeop_flags, PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RulePushMulti;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type BlockRef = Arc<RwLock<dyn FlowBlock + Send + Sync>>;
type VarnodeRef = Arc<RwLock<Varnode>>;

struct EqualityCase {
    fd: Funcdata,
    names: HashMap<usize, String>,
    next_register: u64,
}

impl EqualityCase {
    fn new() -> Self {
        Self {
            fd: Funcdata::new("GetStr", Address::new(0x36d0), 0),
            names: HashMap::new(),
            next_register: 0x100,
        }
    }

    fn key(vn: &VarnodeRef) -> usize {
        Arc::as_ptr(vn) as usize
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) -> VarnodeRef {
        self.names.insert(Self::key(&vn), name.to_string());
        vn
    }

    fn name(&self, vn: &VarnodeRef) -> &str {
        self.names.get(&Self::key(vn)).expect("registered equality varnode")
    }

    fn input(&mut self, name: &str, size: usize) -> VarnodeRef {
        let vn = self.fd.vbank.create_with_space(
            size,
            AddressSpace::Register,
            self.next_register,
        );
        self.next_register += 0x10;
        let vn = self.fd.set_input_varnode(vn);
        self.remember(vn, name)
    }

    fn free_varnode(&mut self, name: &str, size: usize) -> VarnodeRef {
        let vn = self.fd.vbank.create_with_space(
            size,
            AddressSpace::Register,
            self.next_register,
        );
        self.next_register += 0x10;
        self.remember(vn, name)
    }

    fn constant(&mut self, name: &str, size: usize, value: u64) -> VarnodeRef {
        let vn = self.fd.new_constant(size, value);
        self.remember(vn, name)
    }

    fn space(&mut self, name: &str, space: AddressSpace) -> VarnodeRef {
        let vn = self.fd.new_varnode_space(space);
        self.remember(vn, name)
    }

    fn op(
        &mut self,
        name: &str,
        opcode: OpCode,
        inputs: Vec<VarnodeRef>,
        output_size: usize,
        address: u64,
    ) -> VarnodeRef {
        let op = self.fd.new_op(inputs.len(), Address::new(address));
        self.fd.op_set_opcode(&op, opcode);
        for (slot, input) in inputs.into_iter().enumerate() {
            self.fd.op_set_input(&op, input, slot);
        }
        let output = self.fd.new_unique_out(output_size, &op);
        self.remember(output, &format!("{name}_out"))
    }

    fn ordinary_op(&mut self, name: &str, opcode: OpCode, inputs: Vec<VarnodeRef>) -> VarnodeRef {
        self.op(name, opcode, inputs, 8, 0x1000)
    }

    fn observe(&mut self, case_name: &str, vn1: &VarnodeRef, vn2: &VarnodeRef) {
        let sentinel10 = self.constant("sentinel10", 8, 0xf10);
        let sentinel11 = self.constant("sentinel11", 8, 0xf11);
        let sentinel20 = self.constant("sentinel20", 8, 0xf20);
        let sentinel21 = self.constant("sentinel21", 8, 0xf21);
        let mut res1 = [sentinel10.clone(), sentinel11.clone()];
        let mut res2 = [sentinel20.clone(), sentinel21.clone()];

        let result = functional_equality_level(vn1, vn2);
        assert!(result.pairs.len() <= 2, "raw output buffer overflow");
        if result.code > 0 {
            assert!(result.pairs.len() >= result.code as usize, "positive-prefix contract");
        }
        for (slot, (left, right)) in result.pairs.iter().enumerate() {
            res1[slot] = left.clone();
            res2[slot] = right.clone();
        }
        let equal = functional_equality(vn1, vn2);
        println!(
            "fel|case={case_name}|code={}|equal={}|written={}{}{}{}|res1=[{},{}]|res2=[{},{}]",
            result.code,
            u8::from(equal),
            u8::from(!Arc::ptr_eq(&res1[0], &sentinel10)),
            u8::from(!Arc::ptr_eq(&res1[1], &sentinel11)),
            u8::from(!Arc::ptr_eq(&res2[0], &sentinel20)),
            u8::from(!Arc::ptr_eq(&res2[1], &sentinel21)),
            self.name(&res1[0]),
            self.name(&res1[1]),
            self.name(&res2[0]),
            self.name(&res2[1]),
        );
    }

    fn observe_add_expression(&self, case_name: &str, vn1: &VarnodeRef, vn2: &VarnodeRef) {
        let mut expr1 = AddExpression::new();
        let mut expr2 = AddExpression::new();
        expr1.gather_two_terms_root(vn1);
        expr2.gather_two_terms_root(vn2);
        println!(
            "addexpr|case={case_name}|equivalent={}",
            u8::from(expr1.is_equivalent(&expr2))
        );
    }
}

fn run_equality_cases() {
    {
        let mut f = EqualityCase::new();
        let same = f.input("same", 8);
        f.observe("early_same_pointer", &same, &same);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.constant("left", 8, 7);
        let right = f.constant("right", 8, 7);
        f.observe("early_constants_equal", &left, &right);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.constant("left", 8, 7);
        let right = f.constant("right", 8, 8);
        f.observe("early_constants_unequal", &left, &right);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.input("left", 4);
        let right = f.input("right", 8);
        f.observe("early_size_mismatch", &left, &right);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.free_varnode("left", 8);
        let right = f.free_varnode("right", 8);
        f.observe("early_free", &left, &right);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.input("left", 4);
        let right = f.input("right", 4);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ZEXT, vec![left]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_COPY, vec![right]);
        f.observe("guard_opcode", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![a, b]);
        f.observe("guard_arity", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_MULTIEQUAL, vec![a]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_MULTIEQUAL, vec![b]);
        f.observe("guard_marker", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let target1 = f.constant("target1", 8, 0x1111);
        let target2 = f.constant("target2", 8, 0x2222);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_CALL, vec![target1]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_CALL, vec![target2]);
        f.observe("guard_call", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let pointer = f.input("pointer", 8);
        let left_space = f.space("left_space", AddressSpace::Ram);
        let right_space = f.space("right_space", AddressSpace::Ram);
        let op1 = f.op(
            "op1",
            OpCode::CPUI_LOAD,
            vec![left_space, pointer.clone()],
            8,
            0x1000,
        );
        let op2 = f.op(
            "op2",
            OpCode::CPUI_LOAD,
            vec![right_space, pointer],
            8,
            0x1001,
        );
        f.observe("guard_load_address", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let base = f.input("base", 8);
        let index = f.input("index", 8);
        let elsize1 = f.constant("elsize1", 8, 4);
        let elsize2 = f.constant("elsize2", 8, 8);
        let op1 = f.ordinary_op(
            "op1",
            OpCode::CPUI_PTRADD,
            vec![base.clone(), index.clone(), elsize1],
        );
        let op2 = f.ordinary_op("op2", OpCode::CPUI_PTRADD, vec![base, index, elsize2]);
        f.observe("guard_ptradd_slot2", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let shared = f.input("shared", 4);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ZEXT, vec![shared.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ZEXT, vec![shared]);
        f.observe("unary_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.input("left", 4);
        let right = f.input("right", 4);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ZEXT, vec![left]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ZEXT, vec![right]);
        f.observe("unary_contingent", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let shared = f.input("shared", 4);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ZEXT, vec![shared.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ZEXT, vec![shared]);
        f.observe_add_expression("unary_structural_equal", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let shared0 = f.input("shared0", 8);
        let shared1 = f.input("shared1", 8);
        let inputs = vec![shared0, shared1];
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_SUB, inputs.clone());
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_SUB, inputs);
        f.observe("binary_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let shared = f.input("shared", 8);
        let left = f.input("left", 8);
        let right = f.input("right", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_SUB, vec![shared.clone(), left]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_SUB, vec![shared, right]);
        f.observe("binary_slot0_exact_slot1_contingent", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let shared = f.input("shared", 8);
        let left = f.constant("left_const", 8, 1);
        let right = f.constant("right_const", 8, 2);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_SUB, vec![shared.clone(), left]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_SUB, vec![shared, right]);
        f.observe("binary_slot0_exact_slot1_impossible", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let left = f.input("left", 8);
        let right = f.input("right", 8);
        let shared = f.input("shared", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_SUB, vec![left, shared.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_SUB, vec![right, shared]);
        f.observe("binary_slot0_contingent_slot1_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let c = f.input("c", 8);
        let d = f.input("d", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_SUB, vec![a, b]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_SUB, vec![c, d]);
        f.observe("noncomm_both_contingent", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a.clone(), b.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![b, a]);
        f.observe("comm_cross_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let c = f.input("c", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a.clone(), b]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![c, a]);
        f.observe("comm1_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let c = f.input("c", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a, b.clone()]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![b, c]);
        f.observe("comm2_exact", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a = f.input("a", 8);
        let b = f.input("b", 8);
        let c = f.input("c", 8);
        let d = f.input("d", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a, b]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![c, d]);
        f.observe("comm_original_preferred", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a4 = f.input("a4", 4);
        let b8 = f.input("b8", 8);
        let c4 = f.input("c4", 4);
        let d8 = f.input("d8", 8);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a4, b8]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![c4, d8]);
        f.observe("comm_cross_impossible_original_valid", &op1, &op2);
    }
    {
        let mut f = EqualityCase::new();
        let a4 = f.input("a4", 4);
        let b8 = f.input("b8", 8);
        let c8 = f.input("c8", 8);
        let d4 = f.input("d4", 4);
        let op1 = f.ordinary_op("op1", OpCode::CPUI_INT_ADD, vec![a4, b8]);
        let op2 = f.ordinary_op("op2", OpCode::CPUI_INT_ADD, vec![c8, d4]);
        f.observe("comm_final_res2_swap", &op1, &op2);
    }
}

struct RuleFixture {
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

impl RuleFixture {
    fn new() -> Self {
        Self {
            fd: Funcdata::new("GetStr", Address::new(0x36d0), 0),
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

    fn block_key(block: &BlockRef) -> usize { Arc::as_ptr(block) as *const () as usize }
    fn op_key(op: &PcodeOpRef) -> usize { Arc::as_ptr(&op.0) as usize }
    fn op_arc_key(op: &Arc<RwLock<PcodeOp>>) -> usize { Arc::as_ptr(op) as usize }
    fn varnode_key(vn: &VarnodeRef) -> usize { Arc::as_ptr(vn) as usize }

    fn remember_op(&mut self, op: PcodeOpRef, name: String) {
        if self.op_names.insert(Self::op_key(&op), name).is_none() { self.ops.push(op); }
    }

    fn remember_varnode(&mut self, vn: VarnodeRef, name: String) {
        if self.varnode_names.insert(Self::varnode_key(&vn), name).is_none() { self.varnodes.push(vn); }
    }

    fn block_name(&self, block: Option<&BlockRef>) -> &str {
        block.and_then(|value| self.block_names.get(&Self::block_key(value)))
            .map(String::as_str).unwrap_or("-")
    }

    fn op_name(&self, op: &PcodeOpRef) -> &str {
        self.op_names.get(&Self::op_key(op)).expect("registered rule op")
    }

    fn op_arc_name(&self, op: &Arc<RwLock<PcodeOp>>) -> &str {
        self.op_names.get(&Self::op_arc_key(op)).expect("registered rule op arc")
    }

    fn varnode_name(&self, vn: &VarnodeRef) -> &str {
        self.varnode_names.get(&Self::varnode_key(vn)).expect("registered rule varnode")
    }

    fn discover(&mut self) -> HashSet<usize> {
        let current_ops = self.fd.obank.optree.iter().cloned().collect::<Vec<_>>();
        for op in current_ops {
            if !self.op_names.contains_key(&Self::op_key(&op)) {
                let name = format!("n{}", self.next_op); self.next_op += 1;
                self.remember_op(op, name);
            }
        }
        let current_varnodes = self.fd.vbank.loc_tree.iter().map(|vn| vn.0.clone()).collect::<Vec<_>>();
        let live = current_varnodes.iter().map(Self::varnode_key).collect::<HashSet<_>>();
        for vn in current_varnodes {
            if !self.varnode_names.contains_key(&Self::varnode_key(&vn)) {
                let name = format!("g{}", self.next_varnode); self.next_varnode += 1;
                self.remember_varnode(vn, name);
            }
        }
        live
    }

    fn block(&mut self, name: &str) -> BlockRef {
        let block = self.fd.create_new_block();
        self.block_names.insert(Self::block_key(&block), name.to_string());
        self.blocks.push(block.clone()); block
    }

    fn edge(&mut self, from: &BlockRef, to: &BlockRef) { self.fd.bblocks.add_edge(from.clone(), to.clone()); }

    fn input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self.fd.vbank.create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember_varnode(vn.clone(), name.to_string()); vn
    }

    fn op(&mut self, name: &str, opcode: OpCode, inputs: usize, output_size: usize, address: u64) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(address));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name.to_string());
        let output = self.fd.new_unique_out(output_size, &op);
        self.remember_varnode(output, format!("{name}_out")); op
    }

    fn output(op: &PcodeOpRef) -> VarnodeRef {
        op.0.read().unwrap().output.clone().expect("rule op output")
    }

    fn set_input(&mut self, op: &PcodeOpRef, vn: VarnodeRef, slot: usize) { self.fd.op_set_input(op, vn, slot); }
    fn insert_end(&mut self, op: &PcodeOpRef, block: &BlockRef) { self.fd.op_insert_end(op, block); }

    fn op_list(&self, ops: &[PcodeOpRef]) -> String {
        ops.iter().map(|op| self.op_name(op).to_string()).collect::<Vec<_>>().join(",")
    }

    fn all_op_list(&self) -> String {
        self.fd.obank.optree.iter().map(|op| self.op_name(op).to_string()).collect::<Vec<_>>().join(",")
    }

    fn block_states(&self) -> String {
        self.blocks.iter().map(|block| {
            let guard = block.read().unwrap();
            let incoming = (0..guard.size_in()).map(|slot| {
                let edge = guard.get_in(slot).expect("incoming edge"); self.block_name(Some(&edge.point)).to_string()
            }).collect::<Vec<_>>().join(",");
            let outgoing = (0..guard.size_out()).map(|slot| {
                let edge = guard.get_out(slot).expect("outgoing edge"); self.block_name(Some(&edge.point)).to_string()
            }).collect::<Vec<_>>().join(",");
            format!("{}{{index={},in=[{}],out=[{}],ops=[{}]}}",
                self.block_name(Some(block)), guard.get_index(), incoming, outgoing, self.op_list(&guard.get_ops()))
        }).collect::<Vec<_>>().join(";")
    }

    fn op_state(&self, op: &PcodeOpRef) -> String {
        let guard = op.0.read().unwrap();
        let parent = guard.parent.as_ref().and_then(std::sync::Weak::upgrade);
        let inputs = guard.inrefs.iter().map(|vn| self.varnode_name(vn).to_string()).collect::<Vec<_>>().join(",");
        let output = guard.output.as_ref().map(|vn| self.varnode_name(vn).to_string()).unwrap_or_else(|| "-".to_string());
        format!("{}{{opc={},dead={},marker={},commutative={},modified={},parent={},addr={:x},time={},order={},inputs=[{}],output={}}}",
            self.op_name(op), guard.opcode as i32, u8::from(guard.is_dead()),
            u8::from(guard.is_marker()),
            u8::from((guard.flags & pcodeop_flags::COMMUTATIVE) != 0),
            u8::from((guard.addlflags & op_addl_flags::MODIFIED) != 0),
            self.block_name(parent.as_ref()), guard.start.get_addr().as_u64(), guard.start.get_time(),
            guard.start.get_order(), inputs, output)
    }

    fn descendant_slot(vn: &VarnodeRef, op: &Arc<RwLock<PcodeOp>>, mut occurrence: usize) -> usize {
        for (slot, input) in op.read().unwrap().inrefs.iter().enumerate() {
            if !Arc::ptr_eq(input, vn) { continue; }
            if occurrence == 0 { return slot; }
            occurrence -= 1;
        }
        panic!("descendant slot is absent")
    }

    fn varnode_state(&self, vn: &VarnodeRef, live: &HashSet<usize>) -> String {
        if !live.contains(&Self::varnode_key(vn)) { return format!("{}{{present=0}}", self.varnode_name(vn)); }
        let guard = vn.read().unwrap();
        let definition = guard.def.as_ref().and_then(std::sync::Weak::upgrade)
            .map(|op| self.op_arc_name(&op).to_string()).unwrap_or_else(|| "-".to_string());
        let mut occurrences = HashMap::<usize, usize>::new();
        let descendants = guard.descend.iter().filter_map(std::sync::Weak::upgrade).map(|op| {
            let key = Self::op_arc_key(&op);
            let occurrence = occurrences.entry(key).or_insert(0);
            let slot = Self::descendant_slot(vn, &op, *occurrence); *occurrence += 1;
            format!("{}.{}", self.op_arc_name(&op), slot)
        }).collect::<Vec<_>>().join(",");
        format!("{}{{present=1,space={},size={},offset={:x},create={},flags={:x},consume={:x},nzm={:x},def={},desc=[{}]}}",
            self.varnode_name(vn), guard.get_space().name(), guard.get_size(), guard.get_offset(),
            guard.get_create_index(), guard.flags, guard.get_consume(), guard.get_nzm(), definition, descendants)
    }

    fn varnode_loc_list(&self) -> String {
        self.fd.vbank.loc_tree.iter().map(|vn| self.varnode_name(&vn.0).to_string()).collect::<Vec<_>>().join(",")
    }

    fn varnode_def_list(&self) -> String {
        self.fd.vbank.def_tree.iter().map(|vn| self.varnode_name(&vn.0).to_string()).collect::<Vec<_>>().join(",")
    }

    fn dump(&mut self, stage: &str, result: &str) {
        let live = self.discover();
        let op_states = self.ops.iter().map(|op| self.op_state(op)).collect::<Vec<_>>().join(";");
        let varnode_states = self.varnodes.iter().map(|vn| self.varnode_state(vn, &live)).collect::<Vec<_>>().join(";");
        println!(
            "rule|case=parseconfig_unary_zext|stage={stage}|result={result}|blocks=[{}]|all=[{}]|alive=[{}]|dead=[{}]|ops=[{}]|vloc=[{}]|vdef=[{}]|varnodes=[{}]",
            self.block_states(), self.all_op_list(), self.op_list(&self.fd.obank.alivelist),
            self.op_list(&self.fd.obank.deadlist), op_states, self.varnode_loc_list(),
            self.varnode_def_list(), varnode_states,
        );
    }
}

fn run_rule_caller() {
    let mut f = RuleFixture::new();
    let left = f.block("b0");
    let right = f.block("b1");
    let merge = f.block("b2");
    f.edge(&left, &merge); f.edge(&right, &merge);
    let left_input = f.input("left_input", 4, 0x40);
    let right_input = f.input("right_input", 4, 0x50);
    let left_zext = f.op("left_zext", OpCode::CPUI_INT_ZEXT, 1, 8, 0x3d99);
    let right_zext = f.op("right_zext", OpCode::CPUI_INT_ZEXT, 1, 8, 0x3e1f);
    let root = f.op("root", OpCode::CPUI_MULTIEQUAL, 2, 8, 0x3da0);
    let use_op = f.op("use", OpCode::CPUI_COPY, 1, 8, 0x3da1);
    f.set_input(&left_zext, left_input, 0); f.set_input(&right_zext, right_input, 0);
    f.set_input(&root, RuleFixture::output(&left_zext), 0);
    f.set_input(&root, RuleFixture::output(&right_zext), 1);
    f.set_input(&use_op, RuleFixture::output(&root), 0);
    f.insert_end(&left_zext, &left); f.insert_end(&right_zext, &right);
    f.insert_end(&root, &merge); f.insert_end(&use_op, &merge);
    f.dump("before", "na");
    let result = RulePushMulti::new().apply_op(&root.0, &mut f.fd).expect("RulePushMulti caller fixture");
    f.dump("after", &result.to_string());
}

fn main() {
    run_equality_cases();
    run_rule_caller();
}
