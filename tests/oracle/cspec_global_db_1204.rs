//! CSPEC-GLOBAL-DB-0001: Rust side of the locked Ghidra 12.0.4
//! global-scope Database write-path oracle (CSPEC-GLOBAL-APPLY-0001 B2
//! fixture).  Ingests the same production x86-64-gcc.cspec bytes through
//! the real marshal `DocumentStorage` text parser, drives
//! `Architecture::parse_compiler_config` (whose `add_to_global_scope` /
//! `add_other_space` write the cspec `<global>` + OTHER triples into the
//! constructor symbol table's global scope), and prints the same
//! Database-side observations the C++ fixture prints
//! (tests/oracle/cspec_global_db_1204.cc) so the runner can diff the two
//! byte for byte:
//!   - DBTREE: the global scope's space-keyed ownership tree
//!     (`Scope::printBounds`, address.cc:283/588 form),
//!   - QPROP: `Database::query_properties_spaced` folds at the same
//!     (space, offset, size) probe grid (database.cc:1263-1281).

use rudra::arch::{Architecture, SpecQuery};
use rudra::fspec::VarnodeData;
use rudra::marshal::DocumentStorage;
use rudra::sleigh_ffi::{set_sla_path, SleighCtx};
use rudra::space::AddressSpace;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write as _;
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

/// Locked x86-64 address-space facts (the same table the text-ingest
/// fixture mirrors): name → highest offset.
const SPACE_HIGHEST: [(&str, u64); 9] = [
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

/// Unique-space inject base (locked x86-64 .sla fact).
const UNIQUE_INJECT_BASE: u64 = 0x364_400;

fn space_of(name: &str) -> Option<AddressSpace> {
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

struct Host {
    registers: BTreeMap<String, VarnodeData>,
}

impl rudra::pcodeparse::SleighSymbolLookup for Host {
    fn find_symbol(&self, name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
        self.registers.get(name).map(|vd| rudra::pcodeparse::SleighSymbol {
            name: name.to_string(),
            kind: rudra::pcodeparse::SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                space: vd.space,
                offset: vd.offset,
                size: vd.size.max(0) as usize,
            }),
        })
    }
}

impl SpecQuery for Host {
    fn get_register(&self, name: &str) -> Option<VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<AddressSpace> {
        space_of(name)
    }
    fn space_highest(&self, spc: AddressSpace) -> u64 {
        let name = match spc {
            AddressSpace::Ram => "ram",
            AddressSpace::Stack => "stack",
            AddressSpace::Register => "register",
            AddressSpace::Other(_) => "OTHER",
            AddressSpace::Unique => "unique",
            AddressSpace::Const => "const",
            AddressSpace::Iop => "iop",
            AddressSpace::Join => "join",
            AddressSpace::Overlay => "overlay",
        };
        SPACE_HIGHEST
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, h)| *h)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        UNIQUE_INJECT_BASE
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: cspec_global_db_1204 <cspec> <sla>".to_string());
    }
    let cspec_bytes =
        fs::read(&args[1]).map_err(|e| format!("failed to read {}: {}", args[1], e))?;
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

    // Registers from the real .sla (the cspec register range resolves
    // through the register table, architecture.cc:829-831).
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

    // The Architecture with the injection library (SLEIGH lookup installed
    // like PcodeInjectLibrarySleigh's slgh member) — the <callfixup>
    // snippets compile through it during parse.
    let mut arch = Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(RwLock::new(inject_lib)));
    let mut userops = rudra::userop::UserOpManage::new();
    userops.register_op("segment".to_string(), rudra::userop::UserOpType::Unspecialized);
    arch.userops = Some(Arc::new(RwLock::new(userops)));
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|e| format!("parse_compiler_config failed: {}", e))?;

    let mut out = String::new();
    out.push_str("SCHEMA|1\n");

    let symboltab = arch
        .symboltab
        .as_ref()
        .ok_or("constructor symboltab missing")?
        .clone();
    let db = symboltab.read().map_err(|_| "poisoned lock")?;
    let global_scope_id = db.global_scope_id;

    // DBTREE: the global scope's ownership tree through the public
    // printBounds (address.cc:588 form, `all` suppressed like the C++
    // fixture's line filter).
    {
        let global = db
            .get_global_scope()
            .ok_or("global scope missing")?;
        let bounds = global.print_bounds();
        for line in bounds.lines() {
            if line == "all" {
                continue;
            }
            out.push_str(&format!("DBTREE|{}\n", line));
        }
    }

    // QPROP: the same probe grid as the C++ fixture. Ram probes sit in
    // the pinned curl binary's sole PF_W segment so no loader-readonly
    // property participates on either side.
    let probes: [(&str, u64, i32); 8] = [
        ("ram", 0x17000, 8),
        ("ram", 0x18000, 1),
        ("register", 0x1094, 4),
        ("register", 0x1080, 2),
        ("register", 0x1096, 2),
        ("unique", 0x100, 4),
        ("OTHER", 0x10, 1),
        ("const", 0x5, 1),
    ];
    for (space_name, offset, size) in probes {
        let spc = space_of(space_name).ok_or("unknown probe space")?;
        let (hit, flags) = db.query_properties_spaced(
            global_scope_id,
            spc,
            offset,
            size,
            rudra::address::Address::new(0), // the invalid-usepoint form
        );
        out.push_str(&format!(
            "QPROP|{}|0x{:x}|{}|0x{:x}|{}\n",
            space_name,
            offset,
            size,
            flags,
            if hit.is_some() { 1 } else { 0 }
        ));
    }

    let mut stdout = std::io::stdout();
    stdout
        .write_all(out.as_bytes())
        .map_err(|e| format!("stdout write failed: {}", e))?;
    stdout.flush().map_err(|e| format!("stdout flush failed: {}", e))?;
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
