// VARMAP-LOCALWINDOW-0001: Rudra comparand for the locked Ghidra 12.0.4
// authoritative local-window oracle.  Mirrors
// tests/oracle/varmap_localwindow_1204.cc case for case: the same default
// prototype windows (negative-growth 8-byte stack), the same synthetic
// stack Varnodes (COPY of a constant) and spacebase pointer chains
// (INT_SUB of the stack pointer consumed by a non-additive op), the same
// production call sequence (reset_local_window → build via
// restructure_varnode → build_variable_name), and the same symbol-entry
// and naming projections.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::fspec::ProtoModelFull;
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeBase, TypePointer};
use rudra::type_system::typefactory::TypeFactory;
use rudra::type_system::TypeMetatype;
use rudra::varmap::ScopeLocal;
use rudra::varnode::varnode_flags;

struct LocalWindowScope {
    fd: Funcdata,
    scope: ScopeLocal,
    model: Arc<ProtoModelFull>,
}

impl LocalWindowScope {
    fn new(name: &str, fd_off: u64) -> Self {
        // The default model carries the default windows of a negative-growth
        // 8-byte stack (ProtoModelFull::new mirrors the ProtoModel default
        // constructor, fspec.cc:2339-2353).
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        model.name = "lw_default".to_string();
        let model = Arc::new(model);
        let mut arch = Architecture::new();
        let mut proto_models: BTreeMap<String, Arc<ProtoModelFull>> = BTreeMap::new();
        proto_models.insert("lw_default".to_string(), model.clone());
        arch.proto_models = proto_models;
        arch.defaultfp = Some(model.clone());
        let mut fd = Funcdata::new(name, Address::new(fd_off), 0x20);
        fd.set_arch(Arc::new(arch));
        // FuncProto::setModel (fspec.cc:4472) binds the model by identity and
        // records its name for the registry lookup the bridges perform.
        fd.get_func_proto_mut().set_model(Some(model.clone()));
        let mut scope = ScopeLocal::new();
        // funcdata.cc:70 installs the scope window right after construction.
        scope.reset_local_window(&fd);
        Self { fd, scope, model }
    }

    fn int_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("int".into(), 4, TypeMetatype::Int)))
    }
    fn char_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("char".into(), 1, TypeMetatype::Int)))
    }
    fn long_t() -> Arc<Datatype> {
        Arc::new(Datatype::Base(TypeBase::new("long".into(), 8, TypeMetatype::Int)))
    }

    /// A written stack Varnode at `off` holding `ct`, defined by COPY of a
    /// constant — the shape heritage leaves for every stack slot (the
    /// gatherVarnodes CPUI_COPY path, varmap.cc:1198-1199).
    fn stack_copy(&mut self, off: u64, ct: Arc<Datatype>, pc: u64) {
        let op = self.fd.new_op(1, Address::new(pc));
        self.fd.op_set_opcode(&op, OpCode::CPUI_COPY);
        let cnst = self.fd.new_constant(ct.get_size(), 0x1234);
        self.fd.op_set_input(&op, cnst, 0);
        let vn = self
            .fd
            .vbank
            .create_with_space(ct.get_size(), AddressSpace::Stack, off);
        vn.write().unwrap().v_type = Some(ct);
        self.fd.op_set_output(&op, vn);
    }

    /// The gatherOpen shape: an input stack-pointer Varnode (Rudra's RSP is
    /// the Register-space input at offset 0x20), an INT_SUB by `delta` whose
    /// result is typed as a pointer to `pt`, and a non-additive consumer
    /// marking the additive root (AliasChecker::gatherAdditiveBase).
    fn spacebase_pointer_sub(&mut self, delta: u64, pt: Arc<Datatype>, pc: u64) {
        let sp = self
            .fd
            .vbank
            .create_with_space(8, AddressSpace::Register, 0x20);
        self.fd.set_input_varnode(sp.clone());
        let sub = self.fd.new_op(2, Address::new(pc));
        self.fd.op_set_opcode(&sub, OpCode::CPUI_INT_SUB);
        self.fd.op_set_input(&sub, sp, 0);
        let cnst = self.fd.new_constant(8, delta);
        self.fd.op_set_input(&sub, cnst, 1);
        let ptr = self.fd.new_unique(8);
        self.fd.op_set_output(&sub, ptr.clone());
        let pt_ptr = Arc::new(Datatype::Pointer(TypePointer {
            base: TypeBase::new("int *".into(), 8, TypeMetatype::Pointer),
            ptr_to: pt,
            wordsize: 0,
        }));
        ptr.write().unwrap().v_type = Some(pt_ptr);
        let eq = self.fd.new_op(2, Address::new(pc + 8));
        self.fd.op_set_opcode(&eq, OpCode::CPUI_INT_EQUAL);
        let other = self.fd.new_unique(8);
        self.fd.op_set_input(&eq, other, 1);
        self.fd.op_set_input(&eq, ptr, 0);
    }

    fn symbols_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for sym in &self.scope.symbols {
            let type_name = match sym.dtype.as_deref() {
                Some(Datatype::Array(a)) => {
                    format!("{}[{}]", a.array_of.get_name(), a.num_elements)
                }
                Some(dt) => dt.get_name().to_string(),
                None => "?".to_string(),
            };
            parts.push(format!("{:x}:{}:{}", sym.start, sym.size, type_name));
        }
        parts.join(";")
    }
}

fn pairs_text(pairs: &[(u64, u64)]) -> String {
    pairs
        .iter()
        .map(|&(first, last)| format!("{:x}-{:x}", first, last))
        .collect::<Vec<_>>()
        .join(";")
}

// case=default_windows
fn run_default_windows() {
    let t = LocalWindowScope::new("default_windows", 0x9000);
    let param: Vec<(u64, u64)> = t
        .model
        .paramrange
        .ranges()
        .iter()
        .map(|r| (r.get_first().as_u64(), r.get_last().as_u64()))
        .collect();
    println!(
        "case=default_windows|grow={}|local={}|param={}|union={}",
        if t.scope.stack_grows_negative { 1 } else { 0 },
        pairs_text(&t.scope.proto_local_range),
        pairs_text(&param),
        pairs_text(&t.scope.local_range),
    );
}

// case=gate_and_symbols
fn run_gate_and_symbols() {
    let mut t = LocalWindowScope::new("gate_and_symbols", 0x9100);
    t.stack_copy(0xfffffffffff0bdc0, LocalWindowScope::char_t(), 0x1000); // window first byte
    t.stack_copy(0xfffffffffff0bdbf, LocalWindowScope::char_t(), 0x1008); // one byte below
    t.stack_copy(0xffffffffffff8000, LocalWindowScope::int_t(), 0x1010); // mid negative local
    t.stack_copy(0x0, LocalWindowScope::int_t(), 0x1018); // parameter region
    t.stack_copy(0x1ff, LocalWindowScope::int_t(), 0x1020); // parameter region
    t.stack_copy(0xfffffffffffffff8, LocalWindowScope::long_t(), 0x1028); // spans to the last byte
    t.scope.restructure_varnode(&t.fd);
    println!("case=gate_and_symbols|symbols=[{}]", t.symbols_text());
}

// case=open_array
fn run_open_array() {
    let mut t = LocalWindowScope::new("open_array", 0x9200);
    t.spacebase_pointer_sub(0x1010, LocalWindowScope::int_t(), 0x1100);
    t.stack_copy(0xfffffffffffffff8, LocalWindowScope::long_t(), 0x1110);
    t.scope.restructure_varnode(&t.fd);
    let open_to_fixed = t.symbols_text();

    let mut t2 = LocalWindowScope::new("open_endpoint_bound", 0x9300);
    t2.spacebase_pointer_sub(0x10, LocalWindowScope::int_t(), 0x1200);
    t2.scope.restructure_varnode(&t2.fd);
    println!(
        "case=open_array|open_to_fixed=[{}]|open_to_endpoint=[{}]",
        open_to_fixed,
        t2.symbols_text(),
    );
}

// case=naming_branches
fn run_naming_branches() {
    let t = LocalWindowScope::new("naming_branches", 0x9400);
    let int_t = LocalWindowScope::int_t();
    let call = |scope: &ScopeLocal, off: u64| -> String {
        let mut index = 1;
        scope
            .build_variable_name(
                AddressSpace::Stack,
                off,
                None,
                Some(&int_t),
                &mut index,
                varnode_flags::ADDRTIED,
            )
            .unwrap()
    };
    let names = [
        call(&t.scope, 0xffffffffffffff10),
        call(&t.scope, 0x10),
        call(&t.scope, 0x1ff),
        call(&t.scope, 0x200),
        call(&t.scope, 0xfffffffffff0bdc0),
    ]
    .join(";");
    println!("case=naming_branches|names={}", names);
}

// Keep the shared factory alive for the symbol-entry type identity domain
// (restructure_varnode resolves the same process-canonical factory when no
// Architecture factory is attached).
fn _factory_anchor() -> Arc<RwLock<TypeFactory>> {
    TypeFactory::shared_default()
}

fn main() {
    println!("schema=1|fixture=VARMAP-LOCALWINDOW-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b");
    run_default_windows();
    run_gate_and_symbols();
    run_open_array();
    run_naming_branches();
}
