// PTRSUB-TYPED-DECL-RESIDUAL-0001: locked Ghidra 12.0.4 PrintC declarator
// oracle (Rust side).
//
// Mirrors tests/oracle/printc_anonymous_pointer_decl_1204.cc record-for-
// record: the same 14 stage=start/startonly projections of pushTypeStart/
// pushTypeEnd around an identifier atom (the emitVarDecl call sequence,
// printc.cc:2502-2505) and the same 4 stage=decls production walks
// (ActionNameVars + emit_local_var_decls), with identical transport
// normalization (outer whitespace stripped, inner line breaks replaced
// with '~').
//
// The C++ side constructs factory ANONYMOUS pointers/arrays (empty name)
// on a self-contained FixtureArchitecture; the Rust side builds the
// equivalent Arc<Datatype> shapes directly: TypePointer::new (empty base
// name), anonymous TypeArray literals, TypeCode with/without a FuncProto,
// and the four genericTypeName bases (anonymous TypeBase).

use std::sync::Arc;

use rudra::action::Action;
use rudra::coreaction::{ActionNameVars, ActionRestructureVarnode};
use rudra::funcdata::Funcdata;
use rudra::opcodes::OpCode;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printc::PrintC;
use rudra::address::Address;
use rudra::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeCode, TypeField, TypeMetatype, TypePointer, TypeStruct,
};
use rudra::fspec::{FuncProto, ProtoParameter};
use rudra::varnode::Varnode;

type VarnodeRef = Arc<std::sync::RwLock<Varnode>>;

fn base_type(name: &str, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(name.to_string(), size, metatype)))
}

fn anon_base(size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    Arc::new(Datatype::Base(TypeBase::new(String::new(), size, metatype)))
}

/// Factory-anonymous pointer: TypePointer::new leaves the base name empty
/// (the C++ side's getTypePointer(8, base, 1)).
fn anon_ptr_to(pointee: Arc<Datatype>) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer::new(8, pointee, 1)))
}

/// NAMED pointer (the C++ side's getTypePointer(8, base, 1, "char *")):
/// buildTypeStack stops at the named layer.
fn named_ptr_to(pointee: Arc<Datatype>, name: &str) -> Arc<Datatype> {
    Arc::new(Datatype::Pointer(TypePointer {
        base: TypeBase::new(name.to_string(), 8, TypeMetatype::Pointer),
        ptr_to: pointee,
        wordsize: 1,
    }))
}

/// Factory-anonymous array of `n` elements (getTypeArray(n, base)).
fn anon_array_of(n: usize, element: Arc<Datatype>) -> Arc<Datatype> {
    let size = n * element.get_size();
    Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new(String::new(), size, TypeMetatype::Array),
        array_of: element,
        num_elements: n,
    }))
}

struct Fixture {
    fd: Funcdata,
    varnodes: Vec<VarnodeRef>,
    names: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        // The C++ side's makeFuncdata: Funcdata ctor attaches the default
        // ScopeLocal for a named function (funcdata.cc:57-71) at 0x36d0.
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

    fn set_type(&self, vn: &VarnodeRef, ct: Arc<Datatype>) {
        vn.write().unwrap().v_type = Some(ct);
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

fn normalize(text: &str) -> String {
    let trimmed = text.trim_matches(|c: char| c == '\n' || c == ' ' || c == '\r');
    trimmed.replace('\n', "~")
}

/// stage=start: pushTypeStart(ct,false) + Atom("x") + pushTypeEnd(ct) — the
/// emitVarDecl call sequence (printc.cc:2502-2505).
fn render_start(case: &str, ct: &Arc<Datatype>) {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.debug_render_type_decl(ct, "x");
    let emit = printer.take_emit();
    let text = emit
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC returned an unexpected emitter type")
        .debug_get_output_ref()
        .to_string();
    println!("case={}|stage=start|text={}", case, normalize(&text));
}

/// stage=startonly: pushTypeStart(ct,false) alone — for the proto-less
/// anonymous TypeCode, whose pushTypeEnd pair hangs Ghidra 12.0.4
/// (printc.cc:337-339 never advances ct).
fn render_start_only(case: &str, ct: &Arc<Datatype>) {
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    printer.debug_render_type_start_only(ct);
    let emit = printer.take_emit();
    let text = emit
        .into_any()
        .downcast::<EmitNoMarkup>()
        .expect("PrintC returned an unexpected emitter type")
        .debug_get_output_ref()
        .to_string();
    println!("case={}|stage=startonly|text={}", case, normalize(&text));
}

fn char_type() -> Arc<Datatype> {
    base_type("char", 1, TypeMetatype::Int)
}

fn fixture_list_struct() -> Arc<Datatype> {
    // The C++ side's FixtureStruct("fixture_list", fields, 8, 8): one
    // pointer field, complete, named.
    let next = anon_ptr_to(base_type("uint8", 8, TypeMetatype::Uint));
    Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new("fixture_list".to_string(), 8, TypeMetatype::Struct),
        fields: vec![TypeField {
            name: "next".to_string(),
            offset: 0,
            type_ptr: next,
        }],
    }))
}

fn run_anon_ptr_char(fixture: &mut Fixture) {
    let ptr = anon_ptr_to(char_type());
    render_start("anon_ptr_char", &ptr);
    let pc = fixture.make_written("pc", 8, 0x60, 0x1030);
    fixture.set_type(&pc, anon_ptr_to(char_type()));
    fixture.run("anon_ptr_char");
}

fn run_anon_ptr_multi(fixture: &mut Fixture) {
    let uint2 = base_type("uint2", 2, TypeMetatype::Uint);
    let outer = anon_ptr_to(anon_ptr_to(uint2));
    render_start("anon_ptr_multi", &outer);
    let ppu = fixture.make_written("ppu", 8, 0x60, 0x1030);
    fixture.set_type(&ppu, outer);
    fixture.run("anon_ptr_multi");
}

fn run_anon_ptr_struct(fixture: &mut Fixture) {
    let structure = fixture_list_struct();
    let ptr = anon_ptr_to(structure);
    render_start("anon_ptr_struct", &ptr);
    let ps = fixture.make_written("ps", 8, 0x60, 0x1030);
    fixture.set_type(&ps, anon_ptr_to(fixture_list_struct()));
    fixture.run("anon_ptr_struct");
}

fn run_named_ptr_contrast() {
    render_start("named_ptr_contrast", &named_ptr_to(char_type(), "char *"));
}

fn run_anon_array_int(fixture: &mut Fixture) {
    let array = anon_array_of(16, base_type("int4", 4, TypeMetatype::Int));
    render_start("anon_array_int", &array);
    let a = fixture.make_written("a", 16, 0x60, 0x1030);
    fixture.set_type(&a, anon_array_of(16, base_type("int4", 4, TypeMetatype::Int)));
    fixture.run("anon_array_int");
}

fn run_anon_ptr_array_elem() {
    let array = anon_array_of(16, base_type("int4", 4, TypeMetatype::Int));
    render_start("anon_ptr_array_elem", &anon_ptr_to(array));
}

fn run_anon_array_ptr_elem() {
    let element = anon_ptr_to(base_type("int4", 4, TypeMetatype::Int));
    render_start("anon_array_ptr_elem", &anon_array_of(2, element));
}

fn run_anon_base_generics() {
    render_start("anon_base_int", &anon_base(4, TypeMetatype::Int));
    render_start("anon_base_uint", &anon_base(8, TypeMetatype::Uint));
    render_start("anon_base_unknown", &anon_base(1, TypeMetatype::Unknown));
    render_start("anon_base_float", &anon_base(4, TypeMetatype::Float));
}

fn run_anon_code() {
    // Proto-less anonymous TypeCode: startonly (the pair hangs the oracle).
    let noproto = Arc::new(Datatype::Code(TypeCode::new()));
    render_start_only("anon_code_noproto", &noproto);

    // int4(void) prototype (the C++ side's getTypeCode(pieces) with an
    // empty intypes list).
    let mut proto = FuncProto::new(String::new(), base_type("int4", 4, TypeMetatype::Int));
    proto.set_input_lock(true);
    proto.set_output_lock(true);
    let mut with_proto = TypeCode::new();
    with_proto.proto = Some(Arc::new(proto));
    render_start("anon_code_proto", &Arc::new(Datatype::Code(with_proto)));

    // int4(char *, int4): the FixtureTypeCode::setPieces shape — an
    // anonymous char* param and a named int4 param, comma-joined.
    let mut params = FuncProto::new(String::new(), base_type("int4", 4, TypeMetatype::Int));
    params.add_parameter(ProtoParameter::new(
        "param0".to_string(),
        anon_ptr_to(char_type()),
        Address::new(0),
    ));
    params.add_parameter(ProtoParameter::new(
        "param1".to_string(),
        base_type("int4", 4, TypeMetatype::Int),
        Address::new(8),
    ));
    params.set_input_lock(true);
    params.set_output_lock(true);
    let mut with_params = TypeCode::new();
    with_params.proto = Some(Arc::new(params));
    render_start("anon_code_params", &Arc::new(Datatype::Code(with_params)));
}

fn main() {
    // The C++ side reuses ONE Funcdata across the four decls cases with
    // fd.clear() before each; the Rust side mirrors with a fresh Fixture
    // per case (Rugra's Funcdata has no clear(); the C++ clear() resets
    // exactly the per-case state a fresh construction starts from).
    let mut fixture = Fixture::new();
    run_anon_ptr_char(&mut fixture);
    let mut fixture = Fixture::new();
    run_anon_ptr_multi(&mut fixture);
    let mut fixture = Fixture::new();
    run_anon_ptr_struct(&mut fixture);
    run_named_ptr_contrast();
    let mut fixture = Fixture::new();
    run_anon_array_int(&mut fixture);
    run_anon_ptr_array_elem();
    run_anon_array_ptr_elem();
    run_anon_base_generics();
    run_anon_code();
}
