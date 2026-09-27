//! CALLSPEC-COPY-0001: Rust side of the locked Ghidra 12.0.4 oracle for the
//! `ActionDefaultParams` prototype-copy channel (coreaction.cc:2311-2337).
//! Ingests the same production x86-64-gcc.cspec bytes through the real
//! marshal `DocumentStorage` text parser, drives
//! `Architecture::parse_compiler_config`, then runs the REAL library
//! `ActionDefaultParams::apply` over a caller Funcdata whose three call
//! sites mirror the C++ fixture's arms
//! (tests/oracle/callspec_copy_1204.cc):
//!   - COPY: the queryCall boundary stored the callee's platform-recovered
//!     locked prototype (`FuncCallSpecs::set_callee_proto` — the
//!     `setFuncdata`/`getFuncProto` observable slice), so the copy arm
//!     transfers model/extrapop/flag word/cloned store (cc:2323
//!     `fc->copy`, fspec.cc:3789) and the matching-model tail leaves the
//!     copied default-matching model alone;
//!   - COPY_LOCKEDMISMATCH: a model-locked callee on MSABI keeps it
//!     (cc:2325 `!fc->isModelLocked()` gate);
//!   - NOFUNC: no callee -> `setInternal(evalfp, void)` (cc:2327-2328).
//!
//! Rust mapping notes (documented divergences, none observable in this
//! projection): the C++ fixture inlines the arm per site because the
//! oracle's `qlst` is private (populated only by FlowInfo); this side runs
//! the production `ActionDefaultParams::apply` through the library `Action`
//! trait on a real Funcdata with the sites registered via
//! `Funcdata::add_call_specs`.

use rugra::address::Address;
use rugra::arch::{Architecture, SpecQuery};
use rugra::coreaction::ActionDefaultParams;
use rugra::action::Action as _;
use rugra::fspec::{FuncCallSpecs, FuncProto, VarnodeData};
use rugra::funcdata::Funcdata;
use rugra::marshal::DocumentStorage;
use rugra::pcodeparse::{SleighSymbol, SleighSymbolLookup, SleightSymbolKind};
use rugra::sleigh_ffi::{set_sla_path, SleighCtx};
use rugra::space::AddressSpace;
use rugra::userop::{UserOpManage, UserOpType};

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

/// Locked x86-64 address-space facts (name/highest), mirroring the oracle's
/// `AddrSpaceManager` enumeration (evidence: the cspec text-ingest fixture's
/// SPACE projection on the same spec set — same table as
/// funcproto_model_bind_1204.rs).
const SPACES: [(&str, u64); 9] = [
    ("const", u64::MAX),
    ("OTHER", u64::MAX),
    ("unique", 0xffff_ffff),
    ("ram", u64::MAX),
    ("register", 0xffff_ffff),
    ("fspec", u64::MAX),
    ("iop", u64::MAX),
    ("join", 0xffff_ffff),
    ("stack", u64::MAX),
];

/// `Translate::getUniqueStart(Translate::INJECT)` for the locked x86-64 .sla.
const UNIQUE_INJECT_BASE: u64 = 0x364_400;

fn space_name_of(spc: AddressSpace) -> &'static str {
    match spc {
        AddressSpace::Const => "const",
        AddressSpace::Other(_) => "OTHER",
        AddressSpace::Unique => "unique",
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Stack => "stack",
        AddressSpace::Iop => "iop",
        AddressSpace::Join => "join",
        AddressSpace::Overlay => "overlay",
    }
}

/// Ghidra's `type_metatype` numeric values (type.hh:79-98) — the projection
/// prints the oracle's discriminants, not Rust's private enum ordering.
fn ghidra_metatype(meta: rugra::type_system::datatype::TypeMetatype) -> i32 {
    use rugra::type_system::datatype::TypeMetatype;
    match meta {
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
        TypeMetatype::Struct => 4,
        TypeMetatype::Union => 3,
        TypeMetatype::Enum => 6,
        TypeMetatype::PartialStruct => 1,
        _ => 0,
    }
}

/// The language host: registers from the real .sla, spaces from the locked
/// x86-64 table (same shape as funcproto_model_bind_1204.rs).
struct Host {
    registers: BTreeMap<String, VarnodeData>,
}

impl SpecQuery for Host {
    fn get_register(&self, name: &str) -> Option<VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        match name {
            "ram" => Some(AddressSpace::Ram),
            "stack" => Some(AddressSpace::Stack),
            "register" => Some(AddressSpace::Register),
            "OTHER" | "other" => Some(AddressSpace::Other(1)),
            "unique" => Some(AddressSpace::Unique),
            "const" => Some(AddressSpace::Const),
            _ => None,
        }
    }
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        let name = space_name_of(spc);
        SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

impl SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        self.registers.get(name).map(|vd| SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Varnode(rugra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

fn void_type() -> Arc<rugra::type_system::datatype::Datatype> {
    rugra::type_system::TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_type_void()
}

/// Build a callee's platform-recovered locked prototype through the real
/// `setPieces` channel (fspec.cc:3843-3852 lock tail).
fn locked_callee_proto(
    name: &str,
    default_model: &Arc<rugra::fspec::ProtoModelFull>,
    out_type: Arc<rugra::type_system::datatype::Datatype>,
    in_types: Vec<Arc<rugra::type_system::datatype::Datatype>>,
    in_names: Vec<&str>,
) -> FuncProto {
    let mut proto = FuncProto::new(name.to_string(), out_type.clone());
    // pieces.model = 0 keeps the constructor-bound default model
    // (the oracle callee Funcdata binds defaultfp through setScope).
    proto.set_model(Some(default_model.clone()));
    let pieces = rugra::grammar::PrototypePieces {
        model: None,
        name: name.to_string(),
        out_type: Some(out_type),
        in_types,
        in_names: in_names.iter().map(|s| s.to_string()).collect(),
        first_var_arg_slot: -1,
    };
    proto.set_pieces(&pieces);
    proto
}

fn print_callsite_state(
    out: &mut String,
    tag: &str,
    fc: &FuncCallSpecs,
    default_model: &Arc<rugra::fspec::ProtoModelFull>,
) {
    use rugra::type_system::datatype::Datatype;
    out.push_str(&format!("{}_NUMPARAMS|{}\n", tag, fc.prototype.num_params()));
    for (i, param) in fc.prototype.parameters.iter().enumerate() {
        out.push_str(&format!(
            "{}_PARAM|{}|{}|{}|{}|{}|{}|{}|{}|0x{:x}|{}\n",
            tag,
            i,
            param.name,
            i32::from(param.is_type_locked()),
            i32::from(param.is_name_locked()),
            type_display_name(&param.data_type),
            param.data_type.get_size(),
            ghidra_metatype(param.data_type.get_metatype()),
            space_name_of(param.address_space),
            param.address.as_u64(),
            8, // ProtoParameter storage size: pointers are address-sized
        ));
    }
    let out_param_type = type_display_name(&fc.prototype.return_type);
    out.push_str(&format!(
        "{}_OUT|{}|{}|{}\n",
        tag,
        out_param_type,
        fc.prototype.return_type.get_size(),
        i32::from(fc.prototype.is_output_locked())
    ));
    out.push_str(&format!(
        "{}_INLOCK|{}\n",
        tag,
        i32::from(fc.prototype.is_input_locked())
    ));
    out.push_str(&format!(
        "{}_MODELLOCK|{}\n",
        tag,
        i32::from(fc.prototype.is_model_locked())
    ));
    out.push_str(&format!(
        "{}_MODEL|{}|{}|{}|{}\n",
        tag,
        i32::from(fc.prototype.has_model()),
        i32::from(fc.prototype.has_matching_model(default_model)),
        fc.prototype.get_model_name(),
        fc.prototype.get_extra_pop()
    ));
    out.push_str(&format!("{}_NAME|{}\n", tag, fc.prototype.name));
}

/// The anonymous-pointer spelling the oracle prints: `getTypePointer(s,pt,ws)`
/// leaves the name EMPTY (type.hh:836, the grammar.cc:2402-2411 declarator
/// path) — exactly like the C++ fixture's `param->getType()->getName()`.
fn type_display_name(t: &Arc<rugra::type_system::datatype::Datatype>) -> String {
    use rugra::type_system::datatype::Datatype;
    match t.as_ref() {
        Datatype::Void(b) | Datatype::Base(b) => b.name.clone(),
        Datatype::Pointer(p) => p.base.name.clone(),
        Datatype::Struct(s) => s.base.name.clone(),
        _ => String::new(),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: callspec_copy_1204 <cspec> <sla>".to_string());
    }
    let cspec_bytes =
        fs::read(&args[1]).map_err(|e| format!("failed to read {}: {}", args[1], e))?;

    // Text ingestion through the real marshal DocumentStorage
    // (MARSHAL-XML-TEXT-0001), registered under the compiler_spec tag.
    let mut store = DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|e| format!("cspec parse failed: {}", e))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "cspec has no root element".to_string())?;
    if root.read().map_err(|_| "poisoned lock")?.name != "compiler_spec" {
        return Err("cspec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);

    // Registers from the real .sla.
    set_sla_path(&args[2]);
    let sleigh = SleighCtx::new().ok_or_else(|| "SleighCtx::new failed".to_string())?;
    let mut registers = BTreeMap::new();
    for index in 0..sleigh.num_registers() {
        if let Some((name, space, offset, size)) = sleigh.register_info(index) {
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            registers.insert(
                name,
                VarnodeData {
                    space: AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
    }

    let host = Arc::new(Host { registers });

    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    let mut inject_lib = rugra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(RwLock::new(inject_lib)));
    let mut userops = UserOpManage::new();
    userops.register_op("segment".to_string(), UserOpType::Unspecialized);
    arch.userops = Some(Arc::new(RwLock::new(userops)));

    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|e| format!("parse_compiler_config failed: {}", e))?;

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");
    let default_model = arch
        .defaultfp
        .clone()
        .ok_or_else(|| "No default prototype specified".to_string())?;
    out.push_str(&format!("ARCH_DEFAULTFP|{}\n", default_model.get_name()));

    // The recovered-signature types: a char* output and a two-parameter
    // input list (char*, struct FILE*) through the shared factory interning
    // paths (getTypeChar, get_type_pointer_default — the anonymous-pointer
    // declarator form, grammar.cc:2402-2411).
    let factory = rugra::type_system::TypeFactory::shared_default();
    let chartype = factory
        .read()
        .unwrap()
        .get_type_char(1)
        .map_err(|e| format!("get_type_char failed: {}", e))?;
    let charptr = factory.write().unwrap().get_type_pointer_default(chartype.clone());
    // The oracle's `TypeFactory::getTypeStruct("FILE")` (type.cc:3914) mints
    // an empty incomplete struct; the shared factory has no public struct
    // interning API, so the fixture materializes the same empty shape
    // directly (name FILE, size 0, no fields — only pointer-hood matters
    // for storage assignment).
    let filestruct = Arc::new(rugra::type_system::datatype::Datatype::Struct(
        rugra::type_system::datatype::TypeStruct {
            base: rugra::type_system::datatype::TypeBase::new(
                "FILE".to_string(),
                0,
                rugra::type_system::datatype::TypeMetatype::Struct,
            ),
            fields: Vec::new(),
        },
    ));
    let fileptr = factory.write().unwrap().get_type_pointer_default(filestruct);

    // CALLEE 1: default-matching locked signature.
    let callee1 = locked_callee_proto(
        "fixture_callee_copy",
        &default_model,
        charptr.clone(),
        vec![charptr.clone(), fileptr],
        vec!["fixture_buf", "fixture_fp"],
    );
    out.push_str(&format!(
        "CALLEE_LOCKED|{}|{}|{}|{}|{}\n",
        callee1.num_params(),
        i32::from(callee1.is_input_locked()),
        i32::from(callee1.is_output_locked()),
        i32::from(callee1.is_model_locked()),
        callee1.get_model_name()
    ));

    // CALLEE 2: model-locked on a foreign model (MSABI).
    let mut callee2 = locked_callee_proto(
        "fixture_callee_msabi",
        &default_model,
        charptr.clone(),
        vec![charptr],
        vec!["fixture_only"],
    );
    let msabi = arch
        .proto_models
        .get("MSABI")
        .cloned()
        .ok_or_else(|| "MSABI model missing from x86-64-gcc.cspec".to_string())?;
    callee2.set_model(Some(msabi));

    // CALLER: a Funcdata with three CALLIND-shape call sites.
    let arch_arc = Arc::new(arch);
    let mut caller = Funcdata::new("fixture_caller", Address::new(0x601000), 1);
    caller.set_arch(arch_arc.clone());

    // fc1: the queryCall boundary resolved callee1 (flow.cc:662 slice).
    let mut fc1 = FuncCallSpecs::new(Address::new(0x601100), FuncProto::new(String::new(), void_type()));
    fc1.set_funcdata("fixture_callee_copy", Address::new(0x600000));
    fc1.set_callee_proto(Arc::new(callee1));
    // fc2: queryCall resolved the MSABI-locked callee2.
    let mut fc2 = FuncCallSpecs::new(Address::new(0x601200), FuncProto::new(String::new(), void_type()));
    fc2.set_funcdata("fixture_callee_msabi", Address::new(0x600100));
    fc2.set_callee_proto(Arc::new(callee2));
    // fc3: no callee -> setInternal arm.
    let fc3 = FuncCallSpecs::new(Address::new(0x601300), FuncProto::new(String::new(), void_type()));

    caller.add_call_specs(fc1);
    caller.add_call_specs(fc2);
    caller.add_call_specs(fc3);

    // The REAL production ActionDefaultParams::apply over the caller.
    let mut action = ActionDefaultParams::new();
    action
        .apply(&mut caller)
        .map_err(|e| format!("ActionDefaultParams::apply failed: {}", e))?;

    for (tag, index) in [
        ("COPY", 0usize),
        ("COPY_LOCKEDMISMATCH", 1),
        ("NOFUNC", 2),
    ] {
        let owner = caller
            .get_call_specs_owner(index)
            .ok_or_else(|| format!("callsite {} missing", index))?;
        let fc = owner.read().unwrap();
        print_callsite_state(&mut out, tag, &fc, &default_model);
    }

    out.push_str("DONE\n");

    let mut stdout = std::io::stdout();
    stdout
        .write_all(out.as_bytes())
        .map_err(|e| format!("stdout write failed: {}", e))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error);
            ExitCode::FAILURE
        }
    }
}
