//! PLTSTUB-WARNLOSS-0001 seeding-layer bilateral oracle projection (Rugra
//! comparand).
//!
//! Mirrors `debugproto_unknown_model_1204.cc` case for case.  The Ghidra side
//! builds the locked platform signatures through the oracle's own
//! composition (`createUnknownModel` + `FuncProto::setPieces`); this side
//! builds them through Rugra's native front-end adapters —
//! `LibcSignatureTable::locked_proto` for the generic_clib entries and
//! `DebugPrototypeDatabase::apply` for the DWARF entries — and then runs the
//! same `ActionPrototypeWarnings` port, reading the filed warning headers
//! back from the architecture comment database.  The compiler specification
//! and register table come from the same locked x86-64-gcc `.cspec`/`.sla`
//! bytes; the DWARF cases use the locked curl fixture binary.

use rudra::action::Action;
use rudra::address::Address;
use rudra::arch::{Architecture, SpecQuery};
use rudra::comment::CommentDatabaseInternal;
use rudra::coreaction::ActionPrototypeWarnings;
use rudra::debugproto::{DebugPrototypeDatabase, LibcSignatureTable};
use rudra::fspec::{FuncProto, VarnodeData};
use rudra::funcdata::Funcdata;
use rudra::marshal::DocumentStorage;
use rudra::pcodeinject::PcodeInjectLibrary;
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

const UNIQUE_INJECT_BASE: u64 = 0x364_400;

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
            "register" => Some(AddressSpace::Register),
            "stack" => Some(AddressSpace::Stack),
            "OTHER" | "other" => Some(AddressSpace::Other(1)),
            "unique" => Some(AddressSpace::Unique),
            "const" => Some(AddressSpace::Const),
            _ => None,
        }
    }

    fn space_highest(&self, space: AddressSpace) -> u64 {
        match space {
            AddressSpace::Unique | AddressSpace::Register | AddressSpace::Join => 0xffff_ffff,
            _ => u64::MAX,
        }
    }

    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

impl SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<SleighSymbol> {
        self.registers.get(name).map(|data| SleighSymbol {
            name: name.to_string(),
            kind: SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: data.space,
                offset: data.offset,
                size: data.size.max(0) as usize,
            }),
        })
    }
}

fn load_architecture(cspec_path: &str, sla_path: &str) -> Result<Arc<Architecture>, String> {
    let cspec =
        fs::read(cspec_path).map_err(|error| format!("failed to read {cspec_path}: {error}"))?;
    let mut documents = DocumentStorage::new();
    let document = documents
        .parse_document(&cspec)
        .map_err(|error| format!("cspec parse failed: {error}"))?;
    let root = document
        .root
        .clone()
        .ok_or_else(|| "cspec has no root element".to_string())?;
    documents.register_tag(&root);

    set_sla_path(sla_path);
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
    let mut architecture = Architecture::new();
    architecture.archid = "x86:LE:64:default".to_string();
    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ①: the decompiler-side comment
    // database must exist before Actions file warning headers (oracle
    // Architecture::init builds it; the production driver installs the same
    // CommentDatabaseInternal before cspec parsing).
    architecture.commentdb = Some(Arc::new(RwLock::new(CommentDatabaseInternal::new())));
    let mut inject = PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject.set_sleigh_lookup(host.clone());
    architecture.pcodeinjectlib = Some(Arc::new(RwLock::new(inject)));
    let mut userops = UserOpManage::new();
    userops.register_op("segment".to_string(), UserOpType::Unspecialized);
    architecture.userops = Some(Arc::new(RwLock::new(userops)));
    architecture
        .parse_compiler_config(&mut documents, host.as_ref(), 8)
        .map_err(|error| format!("parse_compiler_config failed: {error}"))?;
    Ok(Arc::new(architecture))
}

fn storage_field(storage: Option<(AddressSpace, u64)>) -> String {
    match storage {
        Some((space, offset)) => format!("{}@0x{:x}", space.name(), offset),
        None => "none".to_string(),
    }
}

fn dump_proto(out: &mut String, label: &str, proto: &FuncProto, model_extrapop: i32) {
    // A zero-size (void) output has no storage on either side.
    let ret_storage = if proto.return_type.get_size() == 0 {
        "none".to_string()
    } else {
        storage_field(proto.output_storage)
    };
    out.push_str(&format!(
        "{label}|name={}|unknown={}|printInDecl={}|hasModel={}|extrapop={}|modelExtraPop={}|modellock={}|inlock={}|outlock={}|params={}|retsize={}|retStorage={}\n",
        proto.get_model_name(),
        i32::from(proto.is_model_unknown()),
        i32::from(proto.print_model_in_decl()),
        i32::from(proto.has_model()),
        proto.get_extra_pop(),
        model_extrapop,
        i32::from(proto.is_model_locked()),
        i32::from(proto.is_input_locked()),
        i32::from(proto.is_output_locked()),
        proto.num_params(),
        proto.return_type.get_size(),
        ret_storage,
    ));
    for (index, param) in proto.parameters.iter().enumerate() {
        out.push_str(&format!(
            "{label}|param|{}|{}|{}@0x{:x}|size={}|typelock={}\n",
            index,
            param.name,
            param.address_space.name(),
            param.address.as_u64(),
            param.data_type.get_size(),
            i32::from(param.is_type_locked()),
        ));
    }
}

fn dump_warnings(out: &mut String, label: &str, arch: &Architecture, base: Address) {
    let mut count = 0usize;
    if let Some(cdb) = &arch.commentdb {
        for comment in cdb.read().expect("commentdb read lock")
            .comments_for_function(base)
        {
            out.push_str(&format!(
                "{label}|warn|{}|type={}|{}\n",
                count,
                comment.get_type(),
                comment.get_text(),
            ));
            count += 1;
        }
    }
    out.push_str(&format!("{label}|warncount|{count}\n"));
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err("usage: debugproto_unknown_model_1204 CSPEC SLA CURLBIN".to_string());
    }
    let architecture = load_architecture(&args[1], &args[2])?;
    let default_model = architecture
        .get_default_model()
        .cloned()
        .ok_or_else(|| "missing default prototype model".to_string())?;
    let model_extrapop = default_model.extrapop;

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");
    out.push_str(&format!(
        "ARCH_DEFAULT|{}|extrapop={}\n",
        default_model.get_name(),
        model_extrapop,
    ));
    // No compiler spec declares the reserved "unknown" name (mirrors
    // Architecture::getModel miss before createUnknownModel).
    out.push_str(&format!(
        "UNKNOWN_PRE|{}\n",
        i32::from(architecture.proto_models.get("unknown").is_some()),
    ));

    // ---- Case A: generic_clib locked signature on a PLT thunk (free):
    // void(void*), unknown calling convention. ----
    let table = LibcSignatureTable::default();
    {
        let mut fd = Funcdata::new("free", Address::new(0x600000), 1);
        fd.set_arch(architecture.clone());
        let carrier = fd.funcp.clone();
        let proto = table
            .locked_proto("free", &carrier, None)
            .map_err(|error| format!("free signature rejected: {error}"))?
            .ok_or_else(|| "free missing from the libc table".to_string())?;
        // The unknown-identity semantics (the Rust sentinel counterpart of
        // the oracle's UnknownProtoModel observation): reserved name,
        // unknown flag, not printed in declarations, extrapop following the
        // default-cloned behavior, behavior Arc shared with the carrier.
        out.push_str(&format!(
            "UNKNOWN_POST|name={}|isUnknown={}|printInDecl={}|extrapop={}|behaviorDefault={}\n",
            proto.get_model_name(),
            i32::from(proto.is_model_unknown()),
            i32::from(proto.print_model_in_decl()),
            proto.get_extra_pop(),
            i32::from(proto.shares_model_with(&carrier)),
        ));
        fd.funcp = proto;
        ActionPrototypeWarnings::new()
            .apply(&mut fd)
            .map_err(|error| error.to_string())?;
        dump_proto(&mut out, "PLT_FREE", &fd.funcp, model_extrapop);
        dump_warnings(&mut out, "PLT_FREE", &architecture, fd.baseaddr);
    }

    // ---- Case A2: generic_clib void-list entry (__ctype_b_loc):
    // ushort **(), unknown calling convention, locked void input. ----
    {
        let mut fd = Funcdata::new("__ctype_b_loc", Address::new(0x600100), 1);
        fd.set_arch(architecture.clone());
        let carrier = fd.funcp.clone();
        let proto = table
            .locked_proto("__ctype_b_loc", &carrier, None)
            .map_err(|error| format!("__ctype_b_loc signature rejected: {error}"))?
            .ok_or_else(|| "__ctype_b_loc missing from the libc table".to_string())?;
        fd.funcp = proto;
        ActionPrototypeWarnings::new()
            .apply(&mut fd)
            .map_err(|error| error.to_string())?;
        dump_proto(&mut out, "PLT_CTYPE", &fd.funcp, model_extrapop);
        dump_warnings(&mut out, "PLT_CTYPE", &architecture, fd.baseaddr);
    }

    // ---- DWARF half: the real curl-fixture debug prototypes. ----
    let curl_bytes =
        fs::read(&args[3]).map_err(|error| format!("failed to read {}: {error}", args[3]))?;
    let debug_db = DebugPrototypeDatabase::parse_elf(&curl_bytes)
        .map_err(|error| format!("DWARF prototypes: {error}"))?;

    // ---- Case B: void-signature DWARF function (main_init @ 0x4960):
    // 4-byte return, no parameters, unknown calling convention. ----
    {
        let mut fd = Funcdata::new("main_init", Address::new(0x4960), 8);
        fd.set_arch(architecture.clone());
        debug_db
            .apply(&mut fd)
            .map_err(|error| format!("main_init prototype rejected: {error}"))?;
        ActionPrototypeWarnings::new()
            .apply(&mut fd)
            .map_err(|error| error.to_string())?;
        dump_proto(&mut out, "DWARF_VOID", &fd.funcp, model_extrapop);
        dump_warnings(&mut out, "DWARF_VOID", &architecture, fd.baseaddr);
    }

    // ---- Case C: parameterized DWARF function (GetStr @ 0x36d0):
    // int(char*,char*) with the resolved default model — no warning. ----
    {
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0x4a);
        fd.set_arch(architecture.clone());
        debug_db
            .apply(&mut fd)
            .map_err(|error| format!("GetStr prototype rejected: {error}"))?;
        ActionPrototypeWarnings::new()
            .apply(&mut fd)
            .map_err(|error| error.to_string())?;
        dump_proto(&mut out, "DWARF_PARAMS", &fd.funcp, model_extrapop);
        dump_warnings(&mut out, "DWARF_PARAMS", &architecture, fd.baseaddr);
    }

    out.push_str("DONE\n");
    std::io::stdout()
        .write_all(out.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
