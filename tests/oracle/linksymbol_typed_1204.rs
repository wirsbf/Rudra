// Locked Ghidra 12.0.4 Funcdata::linkSymbol / ActionNameVars typed-symbol
// oracle for FUNCDATA-LINKSYMBOL-TYPED-0001 (Rust side).
//
// Mirrors tests/oracle/linksymbol_typed_1204.cc record-for-record: each case
// builds the same minimal SSA-shaped body (register-space temporaries
// written by p-code ops at the same explicit addresses, plus one input),
// runs ActionNameVars::apply, and dumps the per-HighVariable symbol
// projection (name, data-type, entry storage, dynamic flag, usepoint).
//
// Arc addresses are identity keys only. Dynamic-symbol hashes are internal
// identities and are not part of the record.

use std::sync::Arc;

use rudra::action::Action;
use rudra::address::Address;
use rudra::coreaction::{ActionNameVars, ActionRestructureVarnode};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
use rudra::varnode::{varnode_flags, Varnode};

type VarnodeRef = Arc<std::sync::RwLock<Varnode>>;

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

fn pointer_to(pointee: Arc<Datatype>, size: usize) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(format!("{} *", pointee.get_name()), size, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

struct Fixture {
    fd: Funcdata,
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
        Self { fd, varnodes: Vec::new(), names: Vec::new() }
    }

    fn remember(&mut self, vn: VarnodeRef, name: &str) {
        self.varnodes.push(vn);
        self.names.push(name.to_string());
    }

    fn make_written(&mut self, name: &str, size: usize, offset: u64, pc: u64) -> VarnodeRef {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let input = self.fd.new_constant(size, 0x2a);
        self.fd.op_set_input(&op, input, 0);
        let vn = self.fd.new_varnode_out(size, Address::new(offset), &op);
        // Give the temporary a reader so it has SSA use edges (mirrors the
        // C++ fixture's use op at pc + 0x10 with a unique-space output).
        let use_op = self.fd.new_op(1, Address::new(pc + 0x10));
        self.fd.op_set_opcode(&use_op, OpCode::CPUI_COPY);
        self.fd.op_set_input(&use_op, vn.clone(), 0);
        let _ = self.fd.new_unique_out(size, &use_op);
        self.remember(vn.clone(), name);
        vn
    }

    fn make_input(&mut self, name: &str, size: usize, offset: u64) -> VarnodeRef {
        let vn = self
            .fd
            .vbank
            .create_with_space(size, AddressSpace::Register, offset);
        let vn = self.fd.set_input_varnode(vn);
        self.remember(vn.clone(), name);
        vn
    }

    fn set_type(&self, vn: &VarnodeRef, ct: Arc<Datatype>) {
        vn.write().unwrap().v_type = Some(ct);
    }

    /// Ghidra type_metatype numeric values (type.hh:79-99) for the record.
    fn ghidra_metatype(dt: &Datatype) -> i32 {
        match dt.get_metatype() {
            TypeMetatype::Void => 17,
            TypeMetatype::Spacebase => 16,
            TypeMetatype::Unknown => 15,
            TypeMetatype::Int => 14,
            TypeMetatype::Uint => 13,
            TypeMetatype::Bool => 12,
            TypeMetatype::Code => 11,
            TypeMetatype::Float => 10,
            TypeMetatype::Pointer => 9,
            TypeMetatype::Array => 7,
            TypeMetatype::Enum => 5, // Ghidra ENUM_INT/ENUM_UINT family
            TypeMetatype::Struct => 4,
            TypeMetatype::Union => 3,
            TypeMetatype::PartialEnum => 2,
            TypeMetatype::PartialStruct => 1,
            TypeMetatype::PartialUnion => 0,
        }
    }

    fn type_tag(dt: Option<&Arc<Datatype>>) -> String {
        match dt {
            None => "mt=-1,sz=0,pnb=".to_string(),
            Some(dt) => {
                let mut pnb = String::new();
                dt.print_name_base(&mut pnb);
                format!(
                    "mt={},sz={},pnb={}",
                    Self::ghidra_metatype(dt),
                    dt.get_size(),
                    pnb
                )
            }
        }
    }

    fn entry_dump(&self, high_ptr: usize) -> String {
        let sym_idx = self.fd.high_symbols.get(&high_ptr).copied();
        let scope = match self.fd.scope.as_ref() {
            Some(s) => s,
            None => return "name=none".to_string(),
        };
        match sym_idx {
            None => "none".to_string(),
            Some(idx) => {
                let sym = &scope.symbols[idx];
                let usept = match sym.usepoint {
                    None => "invalid".to_string(),
                    Some(u) => format!("{:x}", u),
                };
                format!(
                    "name={},typ={},cat={},spc={},off={:x},esz={},dyn={},usept={}",
                    sym.name,
                    Self::type_tag(sym.dtype.as_ref()),
                    sym.category,
                    if sym.is_dynamic { "none" } else { sym.space.name() },
                    if sym.is_dynamic { 0 } else { sym.start },
                    sym.size,
                    if sym.is_dynamic { 1 } else { 0 },
                    usept
                )
            }
        }
    }

    fn dump(&self, case: &str, stage: &str) {
        let mut high_dump = String::from("list=[");
        let mut first = true;
        for (vn, name) in self.varnodes.iter().zip(self.names.iter()) {
            let (high_arc, soff) = {
                let vn_r = vn.read().unwrap();
                let high = vn_r.high.clone();
                match &high {
                    Some(h) => {
                        let soff = h.read().unwrap().get_symbol_offset();
                        (Some(h.clone()), soff)
                    }
                    None => (None, -1),
                }
            };
            if !first {
                high_dump.push(';');
            }
            first = false;
            match high_arc {
                Some(h) => {
                    let ptr = Arc::as_ptr(&h) as usize;
                    high_dump.push_str(&format!(
                        "{{{},sym={{{}}},soff={}}}",
                        name,
                        self.entry_dump(ptr),
                        soff
                    ));
                }
                None => high_dump.push_str(&format!("{{{},sym=none,soff=-1}}", name)),
            }
        }
        high_dump.push(']');

        let mut vn_dump = String::from("list=[");
        let mut first = true;
        for (vn, name) in self.varnodes.iter().zip(self.names.iter()) {
            let vn_r = vn.read().unwrap();
            if !first {
                vn_dump.push(';');
            }
            first = false;
            vn_dump.push_str(&format!(
                "{{{},mapped={},input={},persist={}}}",
                name,
                if (vn_r.flags & varnode_flags::MAPPED) != 0 { 1 } else { 0 },
                if vn_r.is_input() { 1 } else { 0 },
                if vn_r.is_persist() { 1 } else { 0 },
            ));
        }
        vn_dump.push(']');

        println!(
            "case={}|stage={}|highs=[{}]|varnodes=[{}]",
            case, stage, high_dump, vn_dump
        );
    }

    fn run(&mut self, case: &str) {
        // Ghidra's Funcdata carries its ScopeLocal from the symbol table;
        // ActionRestructureVarnode builds the equivalent (empty for a body
        // with no stack varnodes) and installs the register-name table.
        ActionRestructureVarnode::new().apply(&mut self.fd).unwrap();
        self.fd.set_high_level();
        self.dump(case, "before");
        ActionNameVars::new().apply(&mut self.fd).unwrap();
        self.dump(case, "after");
    }
}

fn run_typed_temporaries() {
    let mut fixture = Fixture::new();
    let b = fixture.make_written("b", 1, 0x48, 0x1000);
    fixture.set_type(&b, base_type("bool", 1, TypeMetatype::Bool));
    let c = fixture.make_written("c", 1, 0x50, 0x1010);
    fixture.set_type(&c, base_type("char", 1, TypeMetatype::Int));
    let i = fixture.make_written("i", 4, 0x58, 0x1020);
    fixture.set_type(&i, base_type("int4", 4, TypeMetatype::Int));
    let pc = fixture.make_written("pc", 8, 0x60, 0x1030);
    fixture.set_type(&pc, pointer_to(base_type("char", 1, TypeMetatype::Int), 8));
    fixture.run("typed_temporaries");
}

fn run_partial_coverage() {
    let mut fixture = Fixture::new();
    let whole = fixture.make_written("whole", 4, 0x70, 0x36cf);
    fixture.set_type(&whole, base_type("int4", 4, TypeMetatype::Int));
    let piece = fixture.make_input("piece", 1, 0x71);
    fixture.set_type(&piece, base_type("char", 1, TypeMetatype::Int));
    fixture.run("partial_coverage");
}

fn run_irregular_input() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x08);
    fixture.set_type(&x, base_type("int8", 8, TypeMetatype::Int));
    fixture.run("irregular_input");
}

fn main() {
    run_typed_temporaries();
    run_irregular_input();
    run_partial_coverage();
}
