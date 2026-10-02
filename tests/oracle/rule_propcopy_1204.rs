use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RulePropagateCopy;
use rudra::space::AddressSpace;
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

/// Rust-side twin of tests/oracle/rule_propcopy_1204.cc. Every case mirrors
/// the Ghidra fixture case-for-case, and the projections print the same
/// record grammar so the runner can diff the two stdouts byte for byte.
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
            .get(&Self::varnode_key(&vn))
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

    /// Funcdata::newUnique (funcdata_varnode.cc:83-95) never crosses
    /// VarnodeBank::xref, so the result carries no insert/constant/annotation
    /// flag and is_heritage_known() is false (varnode.hh:298).
    fn make_free_unique(&mut self, name: &str, size: usize) -> VarnodeRef {
        let vn = self.fd.new_unique(size);
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

    /// Op without the default unique output, for scenarios whose outputs must
    /// live at a real register address (RULE-PROPCOPY-ADDRTIED-0001).
    fn make_bare_op(&mut self, name: &str, opcode: OpCode, inputs: usize) -> PcodeOpRef {
        let op = self.fd.new_op(inputs, Address::new(0x1000));
        self.fd.op_set_opcode(&op, opcode);
        self.remember_op(op.clone(), name.to_string());
        op
    }

    /// Funcdata::newVarnodeOut (funcdata_varnode.cc:104-121) attaches a
    /// written varnode at the given register-space address and xrefs it into
    /// the bank.
    fn set_register_output(
        &mut self,
        op: &PcodeOpRef,
        name: &str,
        size: usize,
        offset: u64,
    ) -> VarnodeRef {
        let vn = self.fd.new_varnode_out(size, Address::new(offset), op);
        self.remember_varnode(vn.clone(), name.to_string());
        vn
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

fn run_reader_propagate_slot0() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let x2 = fixture.make_input("x2", 8, 0x48);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let reader = fixture.make_op("reader", OpCode::CPUI_INT_ADD, 2, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, x, 0);
    fixture.set_input(&reader, copy_out, 0);
    fixture.set_input(&reader, x2, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&reader);

    fixture.dump("reader_propagate_slot0", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&reader.0, &mut fixture.fd)
        .expect("RulePropagateCopy reader_propagate_slot0");
    fixture.dump("reader_propagate_slot0", "after", &result.to_string());
}

fn run_slot_scan_unwritten_const() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let c = fixture.make_constant("c", 8, 0x9d);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let reader = fixture.make_op("reader", OpCode::CPUI_INT_ADD, 2, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, x, 0);
    fixture.set_input(&reader, c, 0);
    fixture.set_input(&reader, copy_out, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&reader);

    fixture.dump("slot_scan_unwritten_const", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&reader.0, &mut fixture.fd)
        .expect("RulePropagateCopy slot_scan_unwritten_const");
    fixture.dump("slot_scan_unwritten_const", "after", &result.to_string());
}

fn run_slot_scan_noncopy_def() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let x2 = fixture.make_input("x2", 8, 0x48);
    let sub = fixture.make_op("sub", OpCode::CPUI_INT_SUB, 2, 8);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let reader = fixture.make_op("reader", OpCode::CPUI_INT_ADD, 2, 8);

    let sub_out = sub.0.read().unwrap().output.clone().unwrap();
    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&sub, x.clone(), 0);
    fixture.set_input(&sub, x2, 1);
    fixture.set_input(&copyop, x, 0);
    fixture.set_input(&reader, sub_out, 0);
    fixture.set_input(&reader, copy_out, 1);
    fixture.insert_end(&sub);
    fixture.insert_end(&copyop);
    fixture.insert_end(&reader);

    fixture.dump("slot_scan_noncopy_def", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&reader.0, &mut fixture.fd)
        .expect("RulePropagateCopy slot_scan_noncopy_def");
    fixture.dump("slot_scan_noncopy_def", "after", &result.to_string());
}

fn run_free_input_guard() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let f = fixture.make_free_unique("f", 8);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let reader = fixture.make_op("reader", OpCode::CPUI_INT_ADD, 2, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, f, 0);
    fixture.set_input(&reader, copy_out, 0);
    fixture.set_input(&reader, x, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&reader);

    fixture.dump("free_input_guard", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&reader.0, &mut fixture.fd)
        .expect("RulePropagateCopy free_input_guard");
    fixture.dump("free_input_guard", "after", &result.to_string());
}

fn run_return_copy_guard() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let ret = fixture.make_op("ret", OpCode::CPUI_RETURN, 1, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, x, 0);
    fixture.set_input(&ret, copy_out, 0);
    fixture.insert_end(&copyop);
    fixture.insert_end(&ret);

    fixture.dump("return_copy_guard", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&ret.0, &mut fixture.fd)
        .expect("RulePropagateCopy return_copy_guard");
    fixture.dump("return_copy_guard", "after", &result.to_string());
}

fn run_marker_constant_guard() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let c = fixture.make_constant("c", 8, 0x7b);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let phi = fixture.make_op("phi", OpCode::CPUI_MULTIEQUAL, 2, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, c, 0);
    fixture.set_input(&phi, copy_out, 0);
    fixture.set_input(&phi, x, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&phi);

    fixture.dump("marker_constant_guard", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&phi.0, &mut fixture.fd)
        .expect("RulePropagateCopy marker_constant_guard");
    fixture.dump("marker_constant_guard", "after", &result.to_string());
}

/// marker_addrtied_merge_guard: the W4 cmov shape. A MULTIEQUAL (marker)
/// whose output lives at register 0x200 merges slot0 = COPY(register 0x200
/// output) of register input 0x100 against slot1 = register input 0x180.
/// cc:3949-3951 skips the propagation only when BOTH the COPY input and the
/// phi output are addr-tied at different addresses; this case records the
/// natural (unmapped) flag state both sides produce before symbol mapping,
/// plus the rule result.
fn run_marker_addrtied_merge_guard() {
    let mut fixture = Fixture::new();
    let src = fixture.make_input("src", 8, 0x100);
    let old = fixture.make_input("old", 8, 0x180);
    let copyop = fixture.make_bare_op("copy", OpCode::CPUI_COPY, 1);
    let copyout = fixture.set_register_output(&copyop, "copy_out", 8, 0x200);
    let phi = fixture.make_bare_op("phi", OpCode::CPUI_MULTIEQUAL, 2);
    let phiout = fixture.set_register_output(&phi, "phi_out", 8, 0x200);

    fixture.set_input(&copyop, src.clone(), 0);
    fixture.set_input(&phi, copyout.clone(), 0);
    fixture.set_input(&phi, old, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&phi);

    let flags = addrtied_flags_string(&src, &copyout, &phiout);
    fixture.dump("marker_addrtied_merge_guard", "before", &flags);
    let result = RulePropagateCopy::new()
        .apply_op(&phi.0, &mut fixture.fd)
        .expect("RulePropagateCopy marker_addrtied_merge_guard");
    fixture.dump(
        "marker_addrtied_merge_guard",
        "after",
        &format!("r={result},{flags}"),
    );
}

/// marker_addrforce_guard: identical cmov shape, but the COPY output (the
/// phi slot-0 input) is marked addr-force through the public setAddrForce
/// API, so cc:3948 ("Don't propagate if we are keeping the COPY anyway")
/// must refuse the propagation. Result must be 0; the COPY stays intact.
fn run_marker_addrforce_guard() {
    let mut fixture = Fixture::new();
    let src = fixture.make_input("src", 8, 0x100);
    let old = fixture.make_input("old", 8, 0x180);
    let copyop = fixture.make_bare_op("copy", OpCode::CPUI_COPY, 1);
    let copyout = fixture.set_register_output(&copyop, "copy_out", 8, 0x200);
    let phi = fixture.make_bare_op("phi", OpCode::CPUI_MULTIEQUAL, 2);
    let phiout = fixture.set_register_output(&phi, "phi_out", 8, 0x200);

    fixture.set_input(&copyop, src.clone(), 0);
    fixture.set_input(&phi, copyout.clone(), 0);
    fixture.set_input(&phi, old, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&phi);

    copyout.write().unwrap().set_addr_force();

    let flags = addrtied_flags_string(&src, &copyout, &phiout);
    fixture.dump("marker_addrforce_guard", "before", &flags);
    let result = RulePropagateCopy::new()
        .apply_op(&phi.0, &mut fixture.fd)
        .expect("RulePropagateCopy marker_addrforce_guard");
    fixture.dump(
        "marker_addrforce_guard",
        "after",
        &format!("r={result},{flags}"),
    );
}

fn addrtied_flags_string(src: &VarnodeRef, copyout: &VarnodeRef, phiout: &VarnodeRef) -> String {
    format!(
        "src_at={},copyout_at={},phiout_at={}",
        u8::from(src.read().unwrap().is_addr_tied()),
        u8::from(copyout.read().unwrap().is_addr_tied()),
        u8::from(phiout.read().unwrap().is_addr_tied()),
    )
}

fn run_multi_reader_bookkeeping() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let x2 = fixture.make_input("x2", 8, 0x48);
    let sub = fixture.make_op("sub", OpCode::CPUI_INT_SUB, 2, 8);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let r1 = fixture.make_op("r1", OpCode::CPUI_INT_SUB, 2, 8);
    let r2 = fixture.make_op("r2", OpCode::CPUI_INT_OR, 2, 8);

    let sub_out = sub.0.read().unwrap().output.clone().unwrap();
    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&sub, x.clone(), 0);
    fixture.set_input(&sub, x2.clone(), 1);
    fixture.set_input(&copyop, x, 0);
    fixture.set_input(&r1, copy_out.clone(), 0);
    fixture.set_input(&r1, x2, 1);
    fixture.set_input(&r2, sub_out, 0);
    fixture.set_input(&r2, copy_out, 1);
    fixture.insert_end(&sub);
    fixture.insert_end(&copyop);
    fixture.insert_end(&r1);
    fixture.insert_end(&r2);

    fixture.dump("multi_reader_bookkeeping", "before", "na");
    let result1 = RulePropagateCopy::new()
        .apply_op(&r1.0, &mut fixture.fd)
        .expect("RulePropagateCopy multi_reader_bookkeeping r1");
    fixture.dump("multi_reader_bookkeeping", "after_r1", &result1.to_string());
    let result2 = RulePropagateCopy::new()
        .apply_op(&r2.0, &mut fixture.fd)
        .expect("RulePropagateCopy multi_reader_bookkeeping r2");
    fixture.dump("multi_reader_bookkeeping", "after_r2", &result2.to_string());
}

fn run_constant_dedup_bookkeeping() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x40);
    let c = fixture.make_constant("c", 8, 0x1234);
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);
    let reader = fixture.make_op("reader", OpCode::CPUI_INT_ADD, 2, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, c, 0);
    fixture.set_input(&reader, copy_out, 0);
    fixture.set_input(&reader, x, 1);
    fixture.insert_end(&copyop);
    fixture.insert_end(&reader);

    fixture.dump("constant_dedup_bookkeeping", "before", "na");
    let result = RulePropagateCopy::new()
        .apply_op(&reader.0, &mut fixture.fd)
        .expect("RulePropagateCopy constant_dedup_bookkeeping");
    fixture.dump("constant_dedup_bookkeeping", "after", &result.to_string());
}

fn run_self_defined_throw() {
    let mut fixture = Fixture::new();
    let copyop = fixture.make_op("copy", OpCode::CPUI_COPY, 1, 8);

    let copy_out = copyop.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&copyop, copy_out, 0);
    fixture.insert_end(&copyop);

    fixture.dump("self_defined_throw", "before", "na");
    let result = match RulePropagateCopy::new().apply_op(&copyop.0, &mut fixture.fd) {
        Ok(_) => "no_throw".to_string(),
        Err(rudra::Error::Lowlevel(message)) => format!("throw:{message}"),
        Err(other) => format!("throw_unexpected:{other}"),
    };
    fixture.dump("self_defined_throw", "after", &result);
}

fn main() {
    run_reader_propagate_slot0();
    run_slot_scan_unwritten_const();
    run_slot_scan_noncopy_def();
    run_free_input_guard();
    run_return_copy_guard();
    run_marker_constant_guard();
    run_marker_addrtied_merge_guard();
    run_marker_addrforce_guard();
    run_multi_reader_bookkeeping();
    run_constant_dedup_bookkeeping();
    run_self_defined_throw();
}
