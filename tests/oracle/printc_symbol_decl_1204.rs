// Locked Ghidra 12.0.4 PrintC::emitLocalVarDecls / emitScopeVarDecls /
// emitVarDecl oracle for PRINTC-SYMBOL-DECL-0001 (Rust side).
//
// Mirrors tests/oracle/printc_symbol_decl_1204.cc record-for-record: each
// case builds the same minimal SSA-shaped body (register-space temporaries
// written by p-code ops at the same explicit addresses, plus one input),
// runs ActionNameVars::apply, snapshots the finished ScopeLocal exactly like
// PrintC::doc_function does (snapshot_local_scope), drives
// emit_local_var_decls, and records the captured declaration text with the
// identical transport normalization (outer whitespace stripped, inner line
// breaks replaced with '~').
//
// Arc addresses are identity keys only. The $$undef name is pinned by
// rename_symbol so no counter leaks into the record.

use std::sync::Arc;

use rudra::action::Action;
use rudra::address::Address;
use rudra::coreaction::{ActionNameVars, ActionRestructureVarnode};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypeMetatype, TypePointer};
use rudra::varmap::symbol_category;
use rudra::varnode::Varnode;

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

    /// ScopeLocal symbol index linked to a remembered high (via the
    /// Funcdata::high_symbols side table) — the analogue of the C++ side's
    /// `high->getSymbol()`.
    fn symbol_index_for(&self, name: &str) -> usize {
        for (vn, vn_name) in self.varnodes.iter().zip(self.names.iter()) {
            if vn_name != name {
                continue;
            }
            let high = vn.read().unwrap().high.clone();
            if let Some(high) = high {
                let ptr = Arc::as_ptr(&high) as usize;
                if let Some(&idx) = self.fd.high_symbols.get(&ptr) {
                    return idx;
                }
            }
        }
        panic!("no linked symbol for high {}", name);
    }

    /// Captured decl text, transport-normalized identically on both sides.
    fn render_decls(&mut self, case: &str) {
        let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
        printer.snapshot_local_scope(&self.fd);
        printer.emit_local_var_decls();
        let emit = printer.take_emit();
        let text = emit
            .into_any()
            .downcast::<EmitNoMarkup>()
            .expect("PrintC returned an unexpected emitter type")
            .debug_get_output_ref()
            .to_string();
        let trimmed = text.trim_matches(|c: char| c == '\n' || c == ' ' || c == '\r');
        let joined = trimmed.replace('\n', "~");
        println!("case={}|stage=decls|text={}", case, joined);
    }

    fn run(&mut self, case: &str) {
        ActionRestructureVarnode::new().apply(&mut self.fd).unwrap();
        self.fd.set_high_level();
        ActionNameVars::new().apply(&mut self.fd).unwrap();
        self.render_decls(case);
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

fn run_irregular_input() {
    let mut fixture = Fixture::new();
    let x = fixture.make_input("x", 8, 0x08);
    fixture.set_type(&x, base_type("int8", 8, TypeMetatype::Int));
    fixture.run("irregular_input");
}

fn run_dynamic_symbol() {
    let mut fixture = Fixture::new();
    let i = fixture.make_written("i", 4, 0x58, 0x1020);
    fixture.set_type(&i, base_type("int4", 4, TypeMetatype::Int));
    ActionRestructureVarnode::new().apply(&mut fixture.fd).unwrap();
    fixture.fd.set_high_level();
    ActionNameVars::new().apply(&mut fixture.fd).unwrap();
    // addDynamicSymbol("uVar9", uint4, usepoint=0x36d0, hash=0x1234)
    // (database.cc:1690) — the dynamic-list entry shape.
    if let Some(scope) = fixture.fd.scope.as_mut() {
        scope.add_dynamic_symbol(
            "uVar9",
            Some(base_type("uint4", 4, TypeMetatype::Uint)),
            0x1234,
            Some(0x36d0),
        );
    }
    fixture.render_decls("dynamic_symbol");
}

fn run_undef_and_category() {
    let mut fixture = Fixture::new();
    let i = fixture.make_written("i", 4, 0x48, 0x1020);
    fixture.set_type(&i, base_type("int4", 4, TypeMetatype::Int));
    let x = fixture.make_input("x", 8, 0x08);
    fixture.set_type(&x, base_type("int8", 8, TypeMetatype::Int));
    ActionRestructureVarnode::new().apply(&mut fixture.fd).unwrap();
    fixture.fd.set_high_level();
    ActionNameVars::new().apply(&mut fixture.fd).unwrap();
    // setCategory(sym, function_parameter, -1) on the input's symbol.
    let idx = fixture.symbol_index_for("x");
    if let Some(scope) = fixture.fd.scope.as_mut() {
        scope.set_category(idx, symbol_category::FUNCTION_PARAMETER, -1);
        // addSymbol("", int8, register:0x90, usepoint 0x36d0) then pin the
        // $$undef name so no counter leaks into the record.
        let uidx = scope.add_symbol(
            AddressSpace::Register,
            "",
            Some(base_type("int8", 8, TypeMetatype::Int)),
            0x90,
            Some(0x36d0),
        );
        scope.rename_symbol(uidx, "$$undef0000000a");
    }
    fixture.render_decls("undef_and_category");
}

fn main() {
    run_typed_temporaries();
    run_irregular_input();
    run_dynamic_symbol();
    run_undef_and_category();
}
