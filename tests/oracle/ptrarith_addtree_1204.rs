use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rudra::action::Rule;
use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::op::{PcodeOp, PcodeOpRef};
use rudra::opcodes::OpCode;
use rudra::ruleaction::RulePtrArith;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeField, TypeMetatype, TypePointer, TypeStruct};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<RwLock<Varnode>>;

/// Deterministic data-types mirroring the BfdArchitecture TypeFactory side:
/// `uint8` (8-byte unsigned), `int8` (8-byte signed) and
/// `struct PtrarithStruct { uint8 first @0; uint8 second @8; }` (size 16,
/// align 8, matching types->setFields(..., 16, 8, 0)).
fn uint8_type() -> Arc<Datatype> {
    let mut base = TypeBase::new("ulong".to_string(), 8, TypeMetatype::Uint);
    base.alignment = 8;
    base.align_size = 8;
    Arc::new(Datatype::Base(base))
}

fn int8_type() -> Arc<Datatype> {
    let mut base = TypeBase::new("long".to_string(), 8, TypeMetatype::Int);
    base.alignment = 8;
    base.align_size = 8;
    Arc::new(Datatype::Base(base))
}

fn two_field_struct() -> Arc<Datatype> {
    let uint8 = uint8_type();
    let mut base = TypeBase::new("PtrarithStruct".to_string(), 16, TypeMetatype::Struct);
    base.alignment = 8;
    base.align_size = 16;
    Arc::new(Datatype::Struct(TypeStruct {
        base,
        fields: vec![
            TypeField { name: "first".to_string(), offset: 0, type_ptr: uint8.clone() },
            TypeField { name: "second".to_string(), offset: 8, type_ptr: uint8 },
        ],
    }))
}

/// Pointer to `base_type` in byte units (wordsize 1), mirroring
/// `types->getTypePointer(baseType->getSize(), baseType, 1)`.
fn pointer_to(base_type: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer::new(
        base_type.get_size(),
        base_type,
        1,
    )))
}

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

    fn start_type_recovery(&mut self) {
        self.fd.set_type_recovery_started();
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

    fn type_tag(&self, vn: &VarnodeRef) -> String {
        let vn_guard = vn.read().unwrap();
        match vn_guard.get_type() {
            // Ghidra's Varnode constructor assigns a sized TYPE_UNKNOWN
            // default (glb->types->getBase(sz, TYPE_UNKNOWN)); Rudra leaves
            // v_type absent, which is the same observation.
            None => format!("unknown:{}", vn_guard.get_size()),
            Some(ct) => {
                let metatype = match ct.get_metatype() {
                    TypeMetatype::Pointer => "ptr",
                    TypeMetatype::Struct => "struct",
                    TypeMetatype::Array => "array",
                    TypeMetatype::Int => "int",
                    TypeMetatype::Uint => "uint",
                    TypeMetatype::Unknown => "unknown",
                    _ => "other",
                };
                format!("{metatype}:{}", ct.get_size())
            }
        }
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
        let type_tag = self.type_tag(vn);
        format!(
            "{}{{space={},size={},offset={},constant={},input={},written={},free={},def={},type={},desc=[{}]}}",
            self.varnode_name(vn),
            space.name(),
            vn_guard.get_size(),
            offset,
            u8::from(vn_guard.is_constant()),
            u8::from(vn_guard.is_input()),
            u8::from(vn_guard.is_written()),
            u8::from(vn_guard.is_free()),
            definition,
            type_tag,
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

/// Mirror of the C++ runAddLoadCase: typed base pointer input, INT_ADD with a
/// constant, and a LOAD consuming the INT_ADD output as its pointer. The LOAD
/// space constant uses the fixed sentinel 1 (its value is never consulted by
/// RulePtrArith).
fn run_add_load_case(name: &str, base_type: Arc<Datatype>, add_constant: u64, start_recovery: bool) {
    let mut fixture = Fixture::new();
    let pointer_type = pointer_to(base_type);

    let ptr = fixture.make_input("ptr", 8, 0x40);
    ptr.write().unwrap().update_type(pointer_type);
    let add = fixture.make_op("add", OpCode::CPUI_INT_ADD, 2, 8);
    let constant = fixture.make_constant("off", 8, add_constant);
    let load = fixture.make_op("load", OpCode::CPUI_LOAD, 2, 8);

    fixture.set_input(&add, ptr, 0);
    fixture.set_input(&add, constant, 1);
    let space_const = fixture.fd.vbank.create_constant(8, 1);
    fixture.set_input(&load, space_const, 0);
    let add_out = add.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&load, add_out, 1);
    fixture.insert_end(&add);
    fixture.insert_end(&load);
    if start_recovery {
        fixture.start_type_recovery();
    }

    fixture.dump(name, "before", "na");
    let result = RulePtrArith::new()
        .apply_op(&add.0, &mut fixture.fd)
        .expect("RulePtrArith AddTree case");
    fixture.dump(name, "after", &result.to_string());
}

/// Mirror of the C++ runUntypedCase: an int-typed base never passes the
/// applyOp pointer-slot search.
fn run_untyped_case(name: &str) {
    let mut fixture = Fixture::new();
    let ptr = fixture.make_input("ptr", 8, 0x40);
    ptr.write().unwrap().update_type(int8_type());
    let add = fixture.make_op("add", OpCode::CPUI_INT_ADD, 2, 8);
    let constant = fixture.make_constant("off", 8, 0x38);
    let load = fixture.make_op("load", OpCode::CPUI_LOAD, 2, 8);

    fixture.set_input(&add, ptr, 0);
    fixture.set_input(&add, constant, 1);
    let space_const = fixture.fd.vbank.create_constant(8, 1);
    fixture.set_input(&load, space_const, 0);
    let add_out = add.0.read().unwrap().output.clone().unwrap();
    fixture.set_input(&load, add_out, 1);
    fixture.insert_end(&add);
    fixture.insert_end(&load);
    fixture.start_type_recovery();

    fixture.dump(name, "before", "na");
    let result = RulePtrArith::new()
        .apply_op(&add.0, &mut fixture.fd)
        .expect("RulePtrArith untyped case");
    fixture.dump(name, "after", &result.to_string());
}

fn main() {
    run_add_load_case("recovery_not_started", uint8_type(), 0x38, false);
    run_untyped_case("untyped_base_no_chg");
    run_add_load_case("ptradd8_load", uint8_type(), 0x38, true);
    run_add_load_case("ptrsub_struct_load", two_field_struct(), 8, true);
    run_add_load_case("charpp_nonmult_no_chg", uint8_type(), 0x3a, true);
}
