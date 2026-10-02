//! Single-function decompiler entry point for the alignment diff gate.
//!
//! Decompile ONE function from a binary and print it with the same
//! `/* ---- 0xADDR: NAME (SIZE bytes) ---- */` header format that
//! tests/golden/ uses, so tools/align_check.py can diff Rudra output
//! against a Ghidra golden slice token-for-token.
//!
//! Usage:
//!   cargo run --release --example rudra_decompile_func -- <binary> <name_or_addr>
//!   cargo run --release --example rudra_decompile_func -- examples/curl my_fwrite
//!   cargo run --release --example rudra_decompile_func -- examples/curl 0x3460
//!
//! Output goes to stdout (the C text only), diagnostic logs to stderr.
//! Exit code 0 on success, 1 if the function is not found.

use goblin::Object;
use std::collections::HashMap;
use std::fs;

use rudra::action::ActionDatabase;
use rudra::address::Address;
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::prettyprint::EmitNoMarkup;
use rudra::printlanguage::PrintLanguage;

/// Resolve a target specifier (name or hex address) to (vaddr, size, file_offset).
/// name lookup scans syms + dynsyms; addr parse accepts 0x.. or bare hex.
fn resolve_target(
    elf: &goblin::elf::Elf,
    spec: &str,
) -> Option<(u64, usize, u64, String)> {
    // Try as address first.
    let as_addr = spec
        .strip_prefix("0x")
        .or_else(|| spec.strip_prefix("0X"))
        .unwrap_or(spec);
    if let Ok(addr) = u64::from_str_radix(as_addr, 16) {
        for sym in elf.syms.iter() {
            if sym.st_value == addr && sym.st_size != 0 {
                if let Some(off) = file_offset_for(elf, sym.st_value) {
                    return Some((addr, sym.st_size as usize, off, spec.to_string()));
                }
            }
        }
    }
    // Name lookup (syms + dynsyms). Return the first match.
    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .or_else(|| elf.dynstrtab.get_at(sym.st_name));
        if let Some(n) = name {
            if n == spec {
                if let Some(off) = file_offset_for(elf, sym.st_value) {
                    return Some((sym.st_value, sym.st_size as usize, off, n.to_string()));
                }
            }
        }
    }
    None
}

fn file_offset_for(elf: &goblin::elf::Elf, vaddr: u64) -> Option<u64> {
    for header in elf.section_headers.iter() {
        if vaddr >= header.sh_addr && vaddr < header.sh_addr + header.sh_size {
            return Some(header.sh_offset + (vaddr - header.sh_addr));
        }
    }
    None
}

fn build_tables(
    elf: &goblin::elf::Elf,
    buffer: &[u8],
) -> (HashMap<u64, String>, HashMap<u64, String>) {
    let mut symbol_table: HashMap<u64, String> = HashMap::new();
    let mut string_table: HashMap<u64, String> = HashMap::new();

    for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
        if sym.st_value != 0 {
            if let Some(name) = elf
                .strtab
                .get_at(sym.st_name)
                .or_else(|| elf.dynstrtab.get_at(sym.st_name))
            {
                if !name.is_empty() {
                    symbol_table.insert(sym.st_value, name.to_string());
                }
            }
        }
    }
    // PLT thunks → symbol names so calls resolve.
    let mut plt_sec_base = 0u64;
    let mut plt_base = 0u64;
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".plt" {
                plt_base = header.sh_addr;
            } else if name == ".plt.sec" {
                plt_sec_base = header.sh_addr;
            }
        }
    }
    let (base, offset_start) = if plt_sec_base != 0 {
        (plt_sec_base, 0u64)
    } else if plt_base != 0 {
        (plt_base, 1u64)
    } else {
        (0, 0)
    };
    if base != 0 {
        for (i, reloc) in elf.pltrelocs.iter().enumerate() {
            let plt_addr = base + 16 * (i as u64 + offset_start);
            if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbol_table.insert(plt_addr, name.to_string());
                    }
                }
            }
        }
    }
    // .rodata C-strings.
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".rodata" {
                let start = header.sh_offset as usize;
                let end = std::cmp::min(start + header.sh_size as usize, buffer.len());
                let rodata = &buffer[start..end];
                let base_vaddr = header.sh_addr;
                let mut i = 0;
                while i < rodata.len() {
                    if rodata[i].is_ascii_graphic() || rodata[i] == b' ' || rodata[i] == b'\n' {
                        let str_start = i;
                        while i < rodata.len() && rodata[i] != 0 {
                            i += 1;
                        }
                        let str_len = i - str_start;
                        let va = base_vaddr + str_start as u64;
                        if str_len >= 4 {
                            let s = String::from_utf8_lossy(&rodata[str_start..str_start + str_len]);
                            let clean: String = s.chars().filter(|c| c.is_ascii()).collect();
                            if !clean.is_empty() {
                                string_table.insert(va, clean);
                            }
                        }
                    }
                    i += 1;
                }
                break;
            }
        }
    }
    (symbol_table, string_table)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <binary> <name_or_addr>\n  e.g. {} examples/curl my_fwrite",
            args[0], args[0]
        );
        std::process::exit(1);
    }
    let binary_path = &args[1];
    let target_spec = &args[2];

    // Run on a big-stack thread (ActionGroup.perform can recurse deep).
    // run_main returns a plain String error so the closure is Send.
    let bp = binary_path.clone();
    let ts = target_spec.clone();
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || run_main(&bp, &ts))
        .expect("Failed to spawn stack thread");
    match child.join().expect("Worker thread panicked") {
        Ok(()) => Ok(()),
        Err(msg) => Err(format!("{}", msg).into()),
    }
}

fn run_main(binary_path: &str, target_spec: &str) -> Result<(), String> {
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(e) => e,
        _ => {
            eprintln!("[!] not an ELF binary: {}", binary_path);
            std::process::exit(1);
        }
    };

    let (target_addr, func_size, file_offset, func_name) =
        match resolve_target(elf, target_spec) {
            Some(t) => t,
            None => {
                eprintln!(
                    "[!] function '{}' not found in {} (tried addr + name lookup)",
                    target_spec, binary_path
                );
                std::process::exit(1);
            }
        };

    let (symbol_table, string_table) = build_tables(elf, &buffer);
    let code_bytes = &buffer[file_offset as usize..file_offset as usize + func_size];

    // SLEIGH-RUSTIFY-PHASE3-0001: canon-contract linear walk (padding NOP
    // filter) — the retired iced lift + per-op SeqNum stamping is now the
    // shared SLEIGH walk (lift_instruction stamps SeqNum(addr, 0) itself).
    let raw_ops = rudra::disasm::sleigh_lift::sleigh_raw_ops_skip_nops(code_bytes, target_addr);

    // Build Funcdata, run full pipeline.
    let mut fd = Funcdata::new(&func_name, Address::new(target_addr), func_size as i32);
    for (&addr, n) in &symbol_table {
        fd.add_symbol(addr, n.clone());
    }
    for (&addr, s) in &string_table {
        fd.add_string(addr, s.clone());
    }
    // Ghidra: architecture.cc:1391-1414 Architecture::init builds the
    // TypeFactory unconditionally (buildTypegrp at :1398); every Funcdata
    // observes `data.getArch()->types` — Funcdata::spacebase
    // (funcdata.cc:245-264) needs it to typelock the input stack pointer
    // (TYPEPROP-NONSETTLING-HTTPD-0001; same note as the httpd/curl
    // drivers). Minimal single-function wiring: bare Architecture + the
    // locked cspec's data_organization (architecture.cc:1269) +
    // setupSizes (:1350).
    {
        let mut arch = rudra::arch::Architecture::new();
        // HTTPD-DRIVER-ARCH-INIT-0001 (single-function leg): install the
        // Architecture::init items the curl worker builds
        // (curl_decompile.rs:1877-1900) — archid, register_xref, commentdb —
        // alongside the TypeFactory below. SLEIGH register catalog: same
        // enumeration as the curl worker (B3-VARMAP-REGNAME-0001):
        // getAllRegisters -> varnode_xref (sleighbase.cc:182-186), the table
        // Architecture::get_register_name (sleighbase.cc:144-168) walks for
        // ScopeLocal::buildVariableName's register queries.
        let sleigh = rudra::sleigh_ffi::SleighCtx::new()
            .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
        let mut register_xref: Vec<(i32, u64, i32, String)> = Vec::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            register_xref.push((space, offset, size, name.to_string()));
        }
        // SleighArchitecture::resolveArchitecture (sleigh_arch.cc:322-341)
        // establishes archid from the target ("x86:LE:64:default" for the
        // locked x86-64 corpus).
        arch.archid = "x86:LE:64:default".to_string();
        arch.set_register_xref(register_xref);
        // Ghidra: sleigh_arch.cc:241-245 SleighArchitecture::buildCommentDB,
        // called by Architecture::init at architecture.cc:1400 before any
        // Funcdata exists (UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ①).
        // Funcdata::warningHeader (funcdata.cc:135-145) then stores into
        // this database instead of falling back to stderr, and
        // PrintC::docFunction's setupFunctionList (printc.cc:2650) emits the
        // stored header comments — the comment channel every oracle run
        // uses.
        arch.set_commentdb(std::sync::Arc::new(std::sync::RwLock::new(
            rudra::comment::CommentDatabaseInternal::new(),
        )));
        let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
            .map_err(|e| format!("unable to read compiler spec: {e}"))?;
        let mut store = rudra::marshal::DocumentStorage::new();
        let doc = store
            .parse_document(&cspec_bytes)
            .map_err(|e| format!("compiler spec parse failed: {e}"))?;
        let root = doc
            .root
            .clone()
            .ok_or_else(|| "compiler spec has no root element".to_string())?;
        let data_org = root
            .read()
            .map_err(|_| "compiler spec element lock poisoned".to_string())?
            .children
            .iter()
            .find(|child| {
                child
                    .read()
                    .map(|element| element.name == "data_organization")
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| "compiler spec has no data_organization".to_string())?;
        let mut types = rudra::type_system::typefactory::TypeFactory::new(8);
        let registry = std::sync::Arc::new(std::sync::RwLock::new(
            rudra::marshal::IdRegistry::new(),
        ));
        let mut decoder = rudra::marshal::TreeDecoder::new(data_org, registry);
        types.decode_data_organization(&mut decoder);
        types.setup_sizes(&rudra::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        arch.set_types(std::sync::Arc::new(std::sync::RwLock::new(types)));
        fd.set_arch(std::sync::Arc::new(arch));
    }
    fd.inject_raw_ops(&raw_ops);
    let fd_arc = std::sync::Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .unwrap()
        .set_self_ref(std::sync::Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fdw = fd_arc.write().unwrap();
        let _ = db.perform_action("decompile", &mut fdw);
    }

    // Print with the golden header format. Rudra uses relative addresses;
    // align_check.py handles the 0x100000 offset to Ghidra's absolute addrs.
    let mut printer = PrintC::new(Box::new(EmitNoMarkup::new()));
    {
        let fdr = fd_arc.read().unwrap();
        printer.doc_function(&fdr);
    }
    let buf = printer
        .take_emit()
        .into_any()
        .downcast::<EmitNoMarkup>()
        .unwrap();
    let body = buf.get_output();
    println!(
        "/* ---- 0x{:x}: {} ({} bytes) ---- */",
        target_addr, func_name, func_size
    );
    println!("{}", body);
    Ok(())
}
