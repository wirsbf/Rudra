//! FUNCPROTO-MODEL-BIND-0001: Rust side of the locked Ghidra 12.0.4
//! prototype-model binding oracle.  Ingests the same production
//! x86-64-gcc.cspec bytes through the real marshal `DocumentStorage` text
//! parser, drives `Architecture::parse_compiler_config`, and prints the same
//! binding-chain projections the C++ fixture prints
//! (tests/oracle/funcproto_model_bind_1204.cc) so the runner can diff the
//! two byte for byte.
//!
//! Rust mapping notes (documented divergences, none observable in this
//! projection): Rudra's `Funcdata::new` has no constructor-time Scope
//! (FUNCDATA-LOCALSCOPE-OWNERSHIP-0001), so the named-ctor binding chain
//! `Funcdata::Funcdata -> funcp.setScope -> setModel(defaultfp)`
//! (funcdata.cc:48-69, fspec.cc:3879-3884) is ported onto
//! `Funcdata::set_arch`, which is the moment the Architecture reference
//! (`glb`) becomes available.

use rudra::address::Address;
use rudra::arch::{Architecture, SpecQuery};
use rudra::fspec::{EffectType, FuncCallSpecs, FuncProto, VarnodeData};
use rudra::funcdata::Funcdata;
use rudra::marshal::DocumentStorage;
use rudra::pcodeparse::{SleighSymbol, SleighSymbolLookup, SleightSymbolKind};
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;
use rudra::userop::{UserOpManage, UserOpType};

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

/// Locked x86-64 address-space facts (name/highest), mirroring the oracle's
/// `AddrSpaceManager` enumeration (evidence: the cspec text-ingest fixture's
/// SPACE projection on the same spec set).
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

/// `Translate::getUniqueStart(Translate::INJECT)` for the locked x86-64 .sla
/// (0x200 + the .sla unique base; locked oracle fact).
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

/// The language host: registers from the real .sla, spaces from the locked
/// x86-64 table.
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
            kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

fn effect_code(effect: EffectType) -> i32 {
    effect as i32
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: funcproto_model_bind_1204 <cspec> <sla>".to_string());
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
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
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
    // Reference prototype holding the default model, for Arc-identity probes
    // (Ghidra compares `model == defaultfp` pointers directly).
    let mut reference = FuncProto::new(String::new(), void_type());
    reference.set_model(Some(default_model.clone()));

    // Architecture-side resolution (architecture.cc:1337-1347).
    out.push_str(&format!("ARCH_DEFAULTFP|{}\n", default_model.get_name()));
    out.push_str(&format!("ARCH_DEFAULTFP_EXTRAPOP|{}\n", default_model.extrapop));
    out.push_str(&format!(
        "THISCALL_ALIAS|{}\n",
        i32::from(arch.proto_models.contains_key("__thiscall"))
    ));

    // setDefaultModel print-flag side effect (architecture.cc:323-330,
    // rework regression 1): the resolved default is FORCED not to print;
    // a non-default model keeps the constructor default (true,
    // fspec.cc:2352); re-defaulting flips previous back to true and the
    // new one to false.
    {
        out.push_str(&format!(
            "PRINTFLAG|{}|{}\n",
            default_model.get_name(),
            i32::from(default_model.print_in_decl())
        ));
        if let Some(msabi) = arch.proto_models.get("MSABI") {
            out.push_str(&format!(
                "PRINTFLAG|MSABI|{}\n",
                i32::from(msabi.print_in_decl())
            ));
        }
        arch.set_default_model("MSABI");
        if let Some(new_default) = arch.defaultfp.as_ref() {
            out.push_str(&format!(
                "PRINTFLAG|{}|{}\n",
                new_default.get_name(),
                i32::from(new_default.print_in_decl())
            ));
        }
        if let Some(stdcall) = arch.proto_models.get("__stdcall") {
            out.push_str(&format!(
                "PRINTFLAG|__stdcall|{}\n",
                i32::from(stdcall.print_in_decl())
            ));
        }
        // Restore the production default for the observations below.
        arch.set_default_model("__stdcall");
    }

    // Named Funcdata constructor chain, ported onto set_arch (the `glb`
    // availability moment): the model must bind before anything else runs.
    let arch_arc = Arc::new(arch);
    let mut fd = Funcdata::new("fixture_model_bind", Address::new(0x600000), 1);
    fd.set_arch(arch_arc.clone());
    out.push_str(&format!(
        "CTOR_BIND|{}|{}|{}|{}\n",
        i32::from(fd.funcp.has_model()),
        i32::from(fd.funcp.shares_model_with(&reference)),
        fd.funcp.get_model_name(),
        fd.funcp.get_extra_pop()
    ));

    // External locked-prototype overlay (the DWARF/signature boundary lock
    // tail): input/output/model locks on the already-bound prototype.
    fd.funcp.set_input_lock(true);
    fd.funcp.set_output_lock(true);
    fd.funcp.set_model_lock(true);
    out.push_str(&format!(
        "OVERLAY_LOCK|{}|{}|{}|{}|{}\n",
        i32::from(fd.funcp.has_model()),
        i32::from(fd.funcp.shares_model_with(&reference)),
        i32::from(fd.funcp.is_model_locked()),
        i32::from(fd.funcp.is_input_locked()),
        i32::from(fd.funcp.is_output_locked())
    ));

    // Unnamed Funcdata constructor path (funcdata.cc:55-56): no scope attach,
    // no model — until the ActionPrototypeTypes bind (coreaction.cc:4615-4619).
    {
        let mut fd2 = Funcdata::new("", Address::new(0x600100), 0);
        out.push_str(&format!(
            "CTOR_UNNAMED|{}\n",
            i32::from(fd2.funcp.has_model())
        ));
        let evalfp = arch_arc
            .evalfp_current
            .clone()
            .unwrap_or_else(|| default_model.clone());
        if !fd2.funcp.is_model_locked() && !fd2.funcp.shares_model_with(&reference) {
            fd2.funcp.set_model(Some(evalfp));
        }
        out.push_str(&format!(
            "PROTOTYPE_TYPES_BIND|{}|{}|{}\n",
            i32::from(fd2.funcp.shares_model_with(&reference)),
            fd2.funcp.get_model_name(),
            fd2.funcp.get_extra_pop()
        ));
    }

    // Call-site chain: a fresh FuncCallSpecs starts modelless; the
    // ActionDefaultParams else-branch (coreaction.cc:2327-2328) binds the
    // evaluation model via setInternal (fspec.cc:3891-3898).
    {
        let mut fc = FuncCallSpecs::new(Address::new(0x601000), FuncProto::new(String::new(), void_type()));
        fc.entry_addr = None;
        out.push_str(&format!(
            "CALLSPEC_PRE|{}\n",
            i32::from(fc.prototype.has_model())
        ));
        let evalfp = arch_arc
            .evalfp_called
            .clone()
            .unwrap_or_else(|| default_model.clone());
        fc.prototype.set_internal(Some(evalfp), void_type());
        out.push_str(&format!(
            "CALLSPEC_POST|{}|{}|{}|{}\n",
            i32::from(fc.prototype.has_model()),
            i32::from(fc.prototype.shares_model_with(&reference)),
            fc.prototype.get_model_name(),
            fc.prototype.get_extra_pop()
        ));

        // hasEffect (fspec.cc:4234) against the compiler-spec-declared
        // effects. Register offsets come from the same .sla the oracle reads.
        for name in ["RAX", "RBX", "RSP", "RCX"] {
            let vd = host
                .get_register(name)
                .ok_or_else(|| format!("register {} missing from the .sla", name))?;
            out.push_str(&format!(
                "EFFECT|{}|0x{:x}|{}|{}\n",
                name,
                vd.offset,
                vd.size,
                effect_code(fc.has_effect(vd.space, vd.offset, vd.size))
            ));
        }
        out.push_str(&format!(
            "EFFECT|stack|0x0|8|{}\n",
            effect_code(fc.has_effect(AddressSpace::Stack, 0, 8))
        ));
        out.push_str(&format!(
            "EFFECT|stack|0x100|8|{}\n",
            effect_code(fc.has_effect(AddressSpace::Stack, 0x100, 8))
        ));

        // Locked-guard observation (rework regression 2, coreaction.cc:2318-2328
        // guards): a bound-then-locked callspec survives a second
        // ActionDefaultParams pass untouched — the outer hasModel() guard
        // skips both the setModel override (cc:2325 requires
        // !isModelLocked()) and setInternal, so the model identity and
        // extrapop are unchanged.
        fc.prototype.set_model_lock(true);
        {
            let evalfp2 = arch_arc
                .evalfp_called
                .clone()
                .unwrap_or_else(|| default_model.clone());
            if !fc.prototype.has_model() {
                fc.prototype.set_internal(Some(evalfp2), void_type());
            }
        }
        out.push_str(&format!(
            "CALLSPEC_REBIND|{}|{}|{}|{}\n",
            i32::from(fc.prototype.has_model()),
            i32::from(fc.prototype.shares_model_with(&reference)),
            fc.prototype.get_model_name(),
            fc.prototype.get_extra_pop()
        ));
    }

    out.push_str("DONE\n");
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(out.as_bytes());
    let _ = stdout.flush();
    Ok(())
}

// RUDRA-GLUE: fixture-local canonical void type, the same construction
// Funcdata::new uses for its default FuncProto return type (funcdata.rs).
fn void_type() -> std::sync::Arc<rudra::type_system::datatype::Datatype> {
    std::sync::Arc::new(rudra::type_system::datatype::Datatype::Void(
        rudra::type_system::datatype::TypeBase::new(
            "void".to_string(),
            0,
            rudra::type_system::datatype::TypeMetatype::Void,
        ),
    ))
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
