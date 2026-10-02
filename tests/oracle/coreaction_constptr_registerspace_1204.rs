//! Rugra twin of `tests/oracle/coreaction_constptr_registerspace_1204.cc`.
//!
//! HTTPDMAIN-F4-WEBTYPE-0001: pins the register-space filter of
//! `Architecture::cacheAddrSpaceProperties` (architecture.cc:680) — the
//! x86-64-gcc cspec `<global><register name="MXCSR"/></global>` range must
//! apply to the global scope but must NOT enter `infer_ptr_spaces` — plus
//! the two ActionConstantPtr behaviors it gates: an 8-byte constant at a
//! container symbol converts to PTRSUB with a charPrint-pointee pointer
//! output, while the 4-byte flag-web constant at the SAME address stays a
//! bare constant (no inferPtrSpaces member passes the size gate; a register
//! member with addrSize 4 would pass and mis-type the int web char*, the
//! httpd main `pcVar4 = "ptemp"` vs `int iVar3 = 0x17a422` family).
//!
//! The Rust side drives the production channel: the real
//! `sleigh_specs/x86-64-gcc.cspec` bytes through
//! `Architecture::parse_compiler_config` (the `<global>` ingestion that
//! reaches `add_to_global_scope`), a `Database`-backed symboltab whose
//! global scope carries the char[6] container symbol, and the real
//! `ActionConstantPtr::apply` — printing the identical stable observation
//! format as the C++ side (opcode enum spellings, constant
//! size+offset, spacebase flags, output size and type metatype; unique-space
//! offsets are deliberately not observed — allocation-only temporaries).

use std::sync::Arc;
use std::sync::RwLock;

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::Architecture;
use rudra::coreaction::ActionConstantPtr;
use rudra::database::Database;
use rudra::funcdata::Funcdata;
use rudra::marshal::DocumentStorage;
use rudra::opcodes::OpCode;
use rudra::space::AddressSpace;
use rudra::type_system::datatype::{Datatype, TypeArray, TypeBase, TypeMetatype};
use rudra::varnode::Varnode;

const SYMBOL_ADDR: u64 = 0x4e000;
const MISS_ADDR: u64 = 0x4f001;

fn space_name(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "other",
    }
}

fn opcode_name(code: OpCode) -> &'static str {
    match code {
        OpCode::CPUI_COPY => "COPY",
        OpCode::CPUI_PTRSUB => "PTRSUB",
        OpCode::CPUI_INT_EQUAL => "INT_EQUAL",
        _ => "OTHER",
    }
}

fn meta_name(dt: &Datatype) -> &'static str {
    match dt.get_metatype() {
        TypeMetatype::Void => "void",
        TypeMetatype::Unknown => "unknown",
        TypeMetatype::Int => "int",
        TypeMetatype::Uint => "uint",
        TypeMetatype::Bool => "bool",
        TypeMetatype::Code => "code",
        TypeMetatype::Float => "float",
        TypeMetatype::Pointer => "ptr",
        TypeMetatype::Array => "array",
        TypeMetatype::Struct => "struct",
        TypeMetatype::Spacebase => "spacebase",
        _ => "other",
    }
}

/// Stable observation of one varnode (or '-' for absent). Unique-space
/// offsets are deliberately NOT observed (allocation-only temporaries).
fn vn_state(vn: Option<&Arc<RwLock<Varnode>>>) -> String {
    let Some(vn) = vn else { return "-".to_string() };
    let v = vn.read().unwrap();
    if v.is_constant() {
        return format!("const:{}:0x{:x}", v.get_size(), v.get_offset());
    }
    let mut out = format!("{}:{}", space_name(v.get_space()), v.get_size());
    if v.is_spacebase() {
        out.push_str(":sb");
    }
    out
}

/// Stable observation of the output's data-type.
fn type_state(vn: Option<&Arc<RwLock<Varnode>>>) -> String {
    let Some(vn) = vn else { return "-".to_string() };
    let v = vn.read().unwrap();
    let dt = match v.get_type() {
        Some(dt) => dt,
        None => return "unknown".to_string(),
    };
    let mut out = meta_name(&dt).to_string();
    if let Datatype::Pointer(p) = dt.as_ref() {
        out.push_str(if p.ptr_to.is_char_print() {
            ":charprint"
        } else {
            ":other"
        });
    }
    out
}

fn op_state(op: &rudra::op::PcodeOpRef) -> String {
    let o = op.0.read().unwrap();
    let mut out = format!(
        "{}|ins={}|in0={}",
        opcode_name(o.opcode),
        o.inrefs.len(),
        vn_state(o.get_in(0))
    );
    if o.inrefs.len() > 1 {
        out.push_str(&format!("|in1={}", vn_state(o.get_in(1))));
    }
    out.push_str(&format!(
        "|out={}|type={}",
        vn_state(o.output.as_ref()),
        type_state(o.output.as_ref())
    ));
    out
}

/// The minimal SpecQuery host the cspec <global> ingestion consults — the
/// same name resolution the curl/httpd drivers' WorkerSpecHost answers
/// with (spec_space_by_name): ram/stack/register plus the MXCSR register
/// varnode (the exact register offset is unobservable in this fixture's
/// output — only infer_ptr_spaces membership and action behavior are
/// printed).
struct FixtureHost;

impl rudra::arch::SpecQuery for FixtureHost {
    fn get_register(&self, _name: &str) -> Option<rudra::fspec::VarnodeData> {
        Some(rudra::fspec::VarnodeData {
            space: AddressSpace::Register,
            offset: 0x1c0,
            size: 4,
        })
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        match name {
            "ram" => Some(AddressSpace::Ram),
            "stack" => Some(AddressSpace::Stack),
            "register" => Some(AddressSpace::Register),
            "unique" => Some(AddressSpace::Unique),
            "const" => Some(AddressSpace::Const),
            "other" | "OTHER" => Some(AddressSpace::Other(1)),
            _ => None,
        }
    }
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        match spc {
            AddressSpace::Unique | AddressSpace::Register => 0xffff_ffff,
            _ => u64::MAX,
        }
    }
}

impl rudra::pcodeparse::SleighSymbolLookup for FixtureHost {
    fn find_symbol(&self, name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
        // The cspec's pcode snippets reference the GPR set (RIP/RSP/RBP/…)
        // with their real SLEIGH sizes; every symbol resolves to a register
        // varnode of the correct size (the injected bodies are never
        // executed or observed by this fixture).
        let (offset, size): (u64, usize) = match name {
            "RAX" => (0x0, 8),
            "RCX" => (0x8, 8),
            "RDX" => (0x10, 8),
            "RBX" => (0x18, 8),
            "RSP" => (0x20, 8),
            "RBP" => (0x28, 8),
            "RSI" => (0x30, 8),
            "RDI" => (0x38, 8),
            "R8" => (0x40, 8),
            "R9" => (0x48, 8),
            "R10" => (0x50, 8),
            "R11" => (0x58, 8),
            "R12" => (0x60, 8),
            "R13" => (0x68, 8),
            "R14" => (0x70, 8),
            "R15" => (0x78, 8),
            "RIP" => (0x288, 8),
            "MXCSR" => (0x1c0, 4),
            _ => return None,
        };
        Some(rudra::pcodeparse::SleighSymbol {
            name: name.to_string(),
            kind: rudra::pcodeparse::SleightSymbolKind::Varnode(
                rudra::varnode::VarnodeData { space: AddressSpace::Register, offset, size },
            ),
        })
    }
}

/// One constptr case mirroring the C++ runCase: COPY(Const(size, addr))
/// whose output feeds an INT_EQUAL with a register input (the httpd
/// flag-web form). Runs the real ActionConstantPtr::apply.
fn run_case(fd: &mut Funcdata, name: &str, const_size: usize, addr: u64) {
    fd.clear();

    let other = {
        let vn = fd
            .vbank
            .create_with_space(const_size, AddressSpace::Register, 0x100);
        fd.set_input_varnode(vn)
    };

    let copy = fd.new_op(1, Address::new(0x1000));
    fd.op_set_opcode(&copy, OpCode::CPUI_COPY);
    fd.new_unique_out(const_size, &copy);
    let const_vn = fd.new_constant(const_size, addr);
    fd.op_set_input(&copy, const_vn, 0);
    fd.obank.adopt_alive_op(copy.clone());

    let cmp = fd.new_op(2, Address::new(0x1000));
    fd.op_set_opcode(&cmp, OpCode::CPUI_INT_EQUAL);
    fd.new_unique_out(1, &cmp);
    let copy_out = copy.0.read().unwrap().output.clone().unwrap();
    fd.op_set_input(&cmp, copy_out, 0);
    fd.op_set_input(&cmp, other, 1);
    fd.obank.adopt_alive_op(cmp.clone());

    fd.set_type_recovery_started();
    let mut action = ActionConstantPtr::new();
    action.apply(fd).unwrap();

    println!("case={}|result=0|op={}", name, op_state(&copy));
}

fn main() {
    // Production cspec ingestion: the real x86-64-gcc.cspec bytes through
    // parse_compiler_config — the <global> decode that reaches
    // Architecture::add_to_global_scope (the `<range space="ram"/>` member
    // and the `<register name="MXCSR"/>` member).
    let cspec_bytes = std::fs::read("sleigh_specs/x86-64-gcc.cspec")
        .expect("unable to read compiler spec (run from repo root)");
    let mut store = DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .expect("compiler spec parse failed");
    let root = doc.root.clone().expect("compiler spec has no root element");
    assert_eq!(root.read().unwrap().name, "compiler_spec");
    store.register_tag(&root);

    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    // The parse_compiler_config prerequisites the drivers wire first: the
    // pcode-inject library (with the symbol lookup the snippet compiler
    // needs) and the userop manager.
    let host = Arc::new(FixtureHost);
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(0x364_400);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
    arch.userops = Some(Arc::new(std::sync::RwLock::new(
        rudra::userop::UserOpManage::new(),
    )));
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .expect("compiler config ingestion failed");

    // Database-backed symboltab with the char[6] container symbol at
    // SYMBOL_ADDR (Scope::addSymbol, database.cc:1530).
    let db = Arc::new(RwLock::new(Database::new(false)));
    arch.symboltab = Some(db.clone());
    let types = arch.ensure_types();
    let char_t = types
        .write()
        .unwrap()
        .get_type_char(1)
        .expect("char type resolution failed");
    let arr_t = Arc::new(Datatype::Array(TypeArray {
        base: TypeBase::new("char[6]".to_string(), 6, TypeMetatype::Array),
        array_of: char_t,
        num_elements: 6,
    }));
    {
        let mut db_w = db.write().unwrap();
        let global = db_w.global_scope_id;
        db_w.add_symbol_mapped(
            global,
            "ptemp_sim",
            Some(arr_t),
            Address::new(SYMBOL_ADDR),
            6,
        );
    }

    // Observation 1: the inference list (cacheAddrSpaceProperties register
    // filter, architecture.cc:680).
    let names: Vec<&str> = arch
        .infer_ptr_spaces
        .iter()
        .map(|s| space_name(*s))
        .collect();
    println!("inferptr_spaces={}", names.join(","));

    let arch_arc = Arc::new(arch);
    let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0);
    fd.set_arch(arch_arc.clone());

    run_case(&mut fd, "constptr_sz8_container", 8, SYMBOL_ADDR);
    run_case(&mut fd, "constptr_sz4_container", 4, SYMBOL_ADDR);
    run_case(&mut fd, "constptr_sz8_nocontainer", 8, MISS_ADDR);
}
