//! GENSMOKE-0001: bare generalization driver for arbitrary ELF x86-64
//! binaries (third-binary smoke lane).
//!
//! Purpose: run Rugra's decompiler over a NEVER-TUNED binary with the bare
//! native face only — no seed manifests, no DWARF prototype imports, no
//! libc signature table, no string table, no data symbols: exactly the
//! symbol data Ghidra's console-mode BfdArchitecture derives on its own
//! (readLoaderSymbols + LoadImageBfd's BSF_FUNCTION filter, plus the
//! x86-64 psABI .plt.sec/.plt <-> .rela.plt JUMP_SLOT stub mapping the
//! supplementary golden runner registers). The output uses the
//! `/* ---- 0xADDR: NAME (SIZE bytes) ---- */` block format the golden
//! differential tooling expects, with base-0 PIE addresses (the
//! direct-runner tier convention).
//!
//! Function discovery mirrors tools/regen_ghidra_golden.py FIXTURE_CPP
//! (golden_dump_1204.cc) 1:1 so "same input" holds for the smoke diff:
//!   1. static .symtab FUNC symbols in defined sections;
//!   2. .dynsym FUNC symbols in defined sections;
//!   3. PLT stubs: .plt.sec[i] <-> .rela.plt[i] (16-byte stride), or
//!      .plt+16*(i+1) when .plt.sec is absent, JUMP_SLOT relocations only;
//!   4. dedup by address (first registration wins: static, dynamic, PLT);
//!   5. sort by (offset, name).
//!
//! Usage (run from the repo root — sleigh_specs/ is CWD-relative):
//!   cargo run --profile fast-release --example gen_decompile -- <binary>
//!   cargo run --profile fast-release --example gen_decompile -- <binary> --list
//!   cargo run --profile fast-release --example gen_decompile -- <binary> --one <index>
//!
//! Env:
//!   RUGRA_GEN_MIRROR         inert (historical): flow always uses the
//!                             direct-runner oracle range (0, u64::MAX) —
//!                             followFlow(code:0, code:highest),
//!                             funcdata.cc:163 startProcessing. Formerly
//!                             toggled the driver-bounded [entry, MAX) form
//!                             (BINSWEEP-JTDEST-UNLINKED-0001 root cause).
//!   RUGRA_GEN_TIMEOUT_SECS   per-function child timeout in all-mode
//!                             (default 60; 0 = unlimited). The `timeout`
//!                             wrapper also carries --kill-after=30s so a
//!                             SIGTERM-immune child is force-killed at the
//!                             deadline instead of wedging `timeout` in
//!                             waitpid. The coordinator itself watches each
//!                             child with a wall cap of TIMEOUT+150s and,
//!                             after a child exit, a short pipe-close grace
//!                             followed by a /proc fd scan that SIGKILLs any
//!                             process still holding the child's stdout or
//!                             stderr pipe (GEN-DRIVER-STALL-0001: std's
//!                             Command::output() polls with timeout=-1 and
//!                             blocks forever when a surviving descendant of
//!                             a dead child keeps a write end open).
//!   RUGRA_GEN_ONLY=<name>    all-mode: decompile only the named function
//!
//! All-mode decompiles each function in an isolated child process
//! (`--one <index>`), mirroring the oracle golden generator's hermetic
//! per-function "one" mode: a panic or hang in one function cannot take
//! down the corpus run, and each function sees a fresh Architecture.

use goblin::Object;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use std::os::fd::AsRawFd as _;

use rugra::action::ActionDatabase;
use rugra::address::Address;
use rugra::disasm::sleigh_lift::SleighLifter;
use rugra::funcdata::Funcdata;
use rugra::printc::PrintC;
use rugra::printlanguage::PrintLanguage;
use rugra::prettyprint::EmitPrettyPrint;

const R_X86_64_GLOB_DAT: u32 = 1;
const R_X86_64_JUMP_SLOT: u32 = 7;
const PT_LOAD: u32 = 1;

// RUGRA-GLUE: one discovered decompilable unit (address, name, size).
#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

// RUGRA-GLUE: mirror of golden_dump_1204.cc registerFunctionSymbol +
// registerBfdFunctionSymbols + registerPltStubs + collectFunctions: BFD
// static/dynamic FUNC symbols, PLT JUMP_SLOT stubs, dedup by address,
// (offset, name) order.
fn discover_functions(elf: &goblin::elf::Elf) -> Vec<GenFunction> {
    let mut by_addr: HashMap<u64, GenFunction> = HashMap::new();
    let mut register = |vaddr: u64, name: String, size: usize| {
        by_addr.entry(vaddr).or_insert_with(|| GenFunction {
            vaddr,
            name,
            size,
        });
    };
    // 1. static .symtab FUNC symbols (defined sections only — the BFD
    //    loader's und-section skip).
    for sym in elf.syms.iter() {
        if sym.st_shndx == 0 || !sym.is_function() {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                register(sym.st_value, name.to_string(), sym.st_size as usize);
            }
        }
    }
    // 2. .dynsym FUNC symbols (defined sections only).
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == 0 || !sym.is_function() {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                register(sym.st_value, name.to_string(), sym.st_size as usize);
            }
        }
    }
    // 3. PLT stubs: the x86-64 psABI .plt.sec[i] <-> .rela.plt[i] mapping
    //    (16-byte stride; .plt+16*(i+1) when .plt.sec is absent),
    //    JUMP_SLOT relocations only.
    let mut plt_sec_base = 0u64;
    let mut plt_sec_size = 0u64;
    let mut plt_base = 0u64;
    let mut plt_size = 0u64;
    for header in elf.section_headers.iter() {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".plt.sec" {
                plt_sec_base = header.sh_addr;
                plt_sec_size = header.sh_size;
            } else if name == ".plt" {
                plt_base = header.sh_addr;
                plt_size = header.sh_size;
            }
        }
    }
    for (index, reloc) in elf.pltrelocs.iter().enumerate() {
        if reloc.r_type != R_X86_64_JUMP_SLOT {
            continue;
        }
        let stub = if plt_sec_base != 0 && plt_sec_size >= (index as u64 + 1) * 16 {
            plt_sec_base + 16 * index as u64
        } else if plt_base != 0 && plt_size >= (index as u64 + 2) * 16 {
            plt_base + 16 * (index as u64 + 1)
        } else {
            continue;
        };
        if let Some(sym) = elf.dynsyms.get(reloc.r_sym) {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    register(stub, name.to_string(), 16);
                }
            }
        }
    }
    let mut functions: Vec<GenFunction> = by_addr.into_values().collect();
    functions.sort_by(|left, right| {
        left.vaddr
            .cmp(&right.vaddr)
            .then_with(|| left.name.cmp(&right.name))
    });
    functions
}

// RUGRA-GLUE: PT_LOAD vaddr-keyed memory image with the ELF loader's
// import relocations applied (GLOB_DAT/JUMP_SLOT slots hold the
// EXTERNAL-block slot address of the undefined import, RELATIVE entries
// are identity at base 0) — the image contract the curl worker
// established (PLTSTUB-THUNKRELRO-0001) generalized to any ELF.
fn memory_image_bytes(elf: &goblin::elf::Elf, buffer: &[u8]) -> Vec<u8> {
    let mut top = 0usize;
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            top = top.max((ph.p_vaddr as usize).saturating_add(ph.p_memsz as usize));
        }
    }
    let mut image = vec![0u8; top];
    for ph in elf.program_headers.iter() {
        if ph.p_type == PT_LOAD {
            let vaddr = ph.p_vaddr as usize;
            let src = buffer
                .get(
                    ph.p_offset as usize
                        ..(ph.p_offset as usize).saturating_add(ph.p_filesz as usize),
                )
                .unwrap_or(&[]);
            let dst_end = vaddr.saturating_add(src.len()).min(top);
            if vaddr < dst_end {
                image[vaddr..dst_end].copy_from_slice(&src[..dst_end - vaddr]);
            }
        }
    }
    // EXTERNAL-block slot table: one 8-byte slot per undefined .dynsym
    // import in symbol order, after the last SHF_ALLOC section
    // page-aligned up (the Ghidra ELF importer's linkage block).
    const SHF_ALLOC: u64 = 0x2;
    let external_base = elf
        .section_headers
        .iter()
        .filter(|header| (header.sh_flags & SHF_ALLOC) != 0)
        .map(|header| header.sh_addr.saturating_add(header.sh_size))
        .max()
        .unwrap_or(0)
        .div_ceil(0x1000)
        * 0x1000;
    let mut external_slot_of: HashMap<&str, u64> = HashMap::new();
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        if sym.st_shndx == 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    external_slot_of.insert(name, external_base + 8 * index as u64);
                }
            }
        }
    }
    let apply_import_reloc = |image: &mut [u8],
                                  reloc_type: u32,
                                  reloc_sym: usize,
                                  reloc_offset: u64| {
        if reloc_type != R_X86_64_GLOB_DAT && reloc_type != R_X86_64_JUMP_SLOT {
            return;
        }
        let Some(sym) = elf.dynsyms.get(reloc_sym) else {
            return;
        };
        if sym.st_shndx != 0 {
            return; // Defined symbols keep their file values.
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            return;
        };
        let Some(&slot) = external_slot_of.get(name) else {
            return;
        };
        let offset = reloc_offset as usize;
        if let Some(bytes) = image.get_mut(offset..offset + 8) {
            bytes.copy_from_slice(&slot.to_le_bytes());
        }
    };
    for reloc in elf.pltrelocs.iter() {
        apply_import_reloc(&mut image, reloc.r_type, reloc.r_sym, reloc.r_offset);
    }
    for reloc in elf.dynrelas.iter() {
        apply_import_reloc(&mut image, reloc.r_type, reloc.r_sym, reloc.r_offset);
    }
    image
}

// FUNCPROTO-MODEL-BIND-0001 (gen-driver copy): locked x86-64 address-space
// facts shared by the spec host (index-ordered like the oracle's
// AddrSpaceManager enumeration — only name/highest are consulted by the
// parse). Mirrors curl_decompile.rs SPEC_SPACES.
const SPEC_SPACES: [(&str, u64); 9] = [
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

// FUNCPROTO-MODEL-BIND-0001 (gen-driver copy): `Translate::getUniqueStart
// (Translate::INJECT)` for the locked x86-64 .sla.
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

// FUNCPROTO-MODEL-BIND-0001 (gen-driver copy): language host for the
// driver-side compiler-spec parse — registers from the real .sla, spaces
// from the locked table.
struct GenSpecHost {
    registers: HashMap<String, rugra::fspec::VarnodeData>,
}

fn spec_space_by_name(name: &str) -> Option<rugra::space::AddressSpace> {
    use rugra::space::AddressSpace;
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

impl rugra::arch::SpecQuery for GenSpecHost {
    fn get_register(&self, name: &str) -> Option<rugra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rugra::space::AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: rugra::space::AddressSpace) -> u64 {
        let name = match spc {
            rugra::space::AddressSpace::Const => "const",
            rugra::space::AddressSpace::Other(_) => "OTHER",
            rugra::space::AddressSpace::Unique => "unique",
            rugra::space::AddressSpace::Ram => "ram",
            rugra::space::AddressSpace::Register => "register",
            rugra::space::AddressSpace::Stack => "stack",
            rugra::space::AddressSpace::Iop => "iop",
            rugra::space::AddressSpace::Join => "join",
            rugra::space::AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        SPEC_UNIQUE_INJECT_BASE
    }
}

impl rugra::pcodeparse::SleighSymbolLookup for GenSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rugra::pcodeparse::SleighSymbol> {
        self.registers
            .get(name)
            .map(|vd| rugra::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: rugra::pcodeparse::SleightSymbolKind::Varnode(rugra::varnode::VarnodeData {
                    space: vd.space,
                    offset: vd.offset,
                    size: vd.size.max(0) as usize,
                }),
            })
    }
}

// RUGRA-GLUE: bare Architecture for the generalization lane — the same
// init sequence the curl worker installs (archid, SLEIGH register_xref,
// commentdb, single shared TypeFactory with the locked cspec's
// data_organization + setup_sizes, inject library + userops, pspec
// context/register decode, parse_compiler_config establishing defaultfp,
// loader-backed string manager), with NO corpus-specific symbol graph.
// Ghidra: architecture.cc:1391-1414 Architecture::init completes
// parseCompilerConfig (defaultfp, architecture.cc:1239-1351) before any
// Funcdata is constructed (Funcdata::Funcdata -> funcp.setScope ->
// setModel(defaultfp), funcdata.cc:48-69).
// PERF-DUAL-SLEIGH-INIT-0001: also returns the engine instance the
// register catalog was enumerated from, so run_one's lifter adopts it
// (SleighLifter::from_ctx) — the oracle's ONE translator per Architecture
// (sleigh_arch.cc:174 buildTranslator reuse) instead of a second
// x86-64.sla deserialization.
fn build_architecture(
    loader: Option<Arc<dyn rugra::loadimage::LoadImage>>,
) -> Result<(Arc<rugra::arch::Architecture>, rugra::sleigh_ffi::SleighCtx), String> {
    let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    let sleigh = rugra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let mut registers: HashMap<String, rugra::fspec::VarnodeData> = HashMap::new();
    let mut register_xref: Vec<(i32, u64, i32, String)> = Vec::new();
    for index in 0..sleigh.num_registers() {
        let Some((name, space, offset, size)) = sleigh.register_info(index) else {
            continue;
        };
        let Ok(space_id) = u8::try_from(space) else {
            continue;
        };
        register_xref.push((space, offset, size, name.to_string()));
        registers.insert(
            name.to_string(),
            rugra::fspec::VarnodeData {
                space: rugra::space::AddressSpace::from_id(space_id),
                offset,
                size,
            },
        );
    }
    let host = Arc::new(GenSpecHost { registers });
    let mut store = rugra::marshal::DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "compiler spec has no root element".to_string())?;
    if root
        .read()
        .map_err(|_| "compiler spec element lock poisoned".to_string())?
        .name
        != "compiler_spec"
    {
        return Err("compiler spec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);
    let mut arch = rugra::arch::Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    arch.set_register_xref(register_xref);
    arch.set_commentdb(Arc::new(std::sync::RwLock::new(
        rugra::comment::CommentDatabaseInternal::new(),
    )));
    // architecture.cc:1398 buildTypegrp (single shared TypeFactory).
    let types = rugra::type_system::typefactory::TypeFactory::shared_default();
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
    let registry = Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
    let mut decoder = rugra::marshal::TreeDecoder::new(data_org, registry);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .decode_data_organization(&mut decoder);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .setup_sizes(&rugra::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
    arch.set_types(Arc::clone(&types));
    let mut inject_lib = rugra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
    arch.userops = Some(Arc::new(std::sync::RwLock::new(
        rugra::userop::UserOpManage::new(),
    )));
    // ARCH-CONTEXT-TRACKED-0001 (gen-driver copy): parseProcessorConfig
    // before parseCompilerConfig (architecture.cc:639->641); the locked
    // x86-64.pspec <context_data> + <register_data> children.
    let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
        .map_err(|error| format!("unable to read processor spec: {error}"))?;
    let pspec_doc = store
        .parse_document(&pspec_bytes)
        .map_err(|error| format!("processor spec parse failed: {error}"))?;
    let pspec_root = pspec_doc
        .root
        .clone()
        .ok_or_else(|| "processor spec has no root element".to_string())?;
    {
        let children: Vec<_> = pspec_root
            .read()
            .map_err(|_| "processor spec element lock poisoned".to_string())?
            .children
            .iter()
            .map(|child| {
                child
                    .read()
                    .map(|element| element.name.clone())
                    .unwrap_or_default()
            })
            .collect();
        for (position, name) in children.iter().enumerate() {
            let child = pspec_root
                .read()
                .map_err(|_| "processor spec element lock poisoned".to_string())?
                .children
                .get(position)
                .cloned()
                .ok_or_else(|| "processor spec child vanished".to_string())?;
            match name.as_str() {
                "context_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
                    let mut decoder =
                        rugra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_context_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
                }
                "register_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rugra::marshal::IdRegistry::new()));
                    let mut decoder =
                        rugra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_register_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec register_data decode failed: {error}"))?;
                }
                _ => {}
            }
        }
    }
    // architecture.cc:1239-1351 parseCompilerConfig — establishes the
    // prototype models and defaultfp (the FUNCPROTO-MODEL-BIND-0001 chain).
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    // architecture.cc:1391-1414: buildLoader precedes buildStringManager.
    if let Some(loader) = loader {
        arch.loader = Some(loader);
        arch.build_string_manager();
    }
    Ok((Arc::new(arch), sleigh))
}

// RUGRA-GLUE: hermetic single-function decompile, the shape the oracle
// golden_dump_1204 "one" mode drives (BfdArchitecture init, followFlow,
// universal action, PrintC docFunction) on Rugra's side.
fn run_one(binary_path: &str, functions: &[GenFunction], index: usize) -> Result<(), String> {
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("not an ELF binary".to_string()),
    };
    let target = &functions[index];
    let image = memory_image_bytes(elf, &buffer);

    let loader: Arc<dyn rugra::loadimage::LoadImage> = Arc::new(
        rugra::loadimage::RawLoadImage::from_bytes(
            binary_path.rsplit('/').next().unwrap_or("gen"),
            0,
            image.clone(),
        ),
    );
    let (arch, sleigh_ctx) = build_architecture(Some(loader))?;

    let func_size =
        i32::try_from(target.size).map_err(|_| format!("function {} is too large", target.name))?;
    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
    fd.set_arch(arch);
    // The full BFD function-symbol face (this is the ONLY symbol channel:
    // bare native face — no data symbols, no strings, no seeds).
    for function in functions {
        fd.add_symbol(function.vaddr, function.name.clone());
    }

    // PERF-DUAL-SLEIGH-INIT-0001: adopt the register-catalog engine as the
    // lifter instead of re-deserializing x86-64.sla — the oracle builds ONE
    // Sleigh translator per Architecture (sleigh_arch.cc:174 buildTranslator
    // reuses the languageindex instance; architecture.cc:627 initializes it
    // once) and reads both the register catalog (SleighBase::getAllRegisters,
    // sleighbase.cc:182) and every decode from that single instance. The
    // catalog leg above only enumerated registers (no image, no context
    // default, no decode), so configure_x86_64 below observes exactly the
    // fresh-engine state a second SleighCtx::new() would have produced.
    let mut sleigh = SleighLifter::from_ctx(sleigh_ctx);
    sleigh
        .configure_x86_64(&image, 0)
        .map_err(|error| format!("failed to configure SLEIGH: {error}"))?;

    let empty_protos = std::collections::BTreeMap::new();
    // Oracle flow contract: followFlow(code:0, code:highest). Every Ghidra
    // production entry — Funcdata::startProcessing (funcdata.cc:163-164),
    // the GUI, and the direct-runner golden harness (regen_ghidra_golden.py
    // :388) — bounds flow at the whole address space, never at the function
    // body. The historical driver-bounded form (baddr = function entry)
    // stranded jump-table destinations below the entry as unlinked
    // (BINSWEEP-JTDEST-UNLINKED-0001: python3.10 string-formatting switches
    // recover far-away case targets that a lower bound rejects as
    // out-of-bounds). Both the former mirror and bare arms now run the one
    // oracle range.
    rugra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        .map_err(|error| format!("flow generation failed for {}: {error}", target.name))?;

    let fd_arc = Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .map_err(|_| "Funcdata write lock poisoned".to_string())?
        .set_self_ref(Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    // PIPE-RESTART-0001 (chain ②): install the driver-owned raw-flow
    // regeneration callback for the oracle's restart cycle (action.cc:574
    // clearAnalysis → second-pass ActionStart → startProcessing →
    // followFlow, funcdata.cc:157-163). Rugra's flow generation lives at
    // the driver boundary, so the configured SLEIGH lifter moves into the
    // callback (no second holder during the pipeline — pass 1 completed
    // above); a restart re-runs the same flow contract the first pass
    // used: the bare-face full-space followFlow(code:0, code:highest)
    // with no callee protos (gen has no mirror/bounded split — the single
    // contract in the flow comment above covers both passes). Installed
    // on the derived "decompile" root that perform_action actually runs.
    let restart_lifter = Arc::new(std::sync::Mutex::new(sleigh));
    let restart_protos = empty_protos.clone();
    db.set_restart_flow(
        "decompile",
        Arc::new(move |restart_fd| {
            let mut lifter = restart_lifter.lock().map_err(|_| {
                rugra::Error::from("restart SLEIGH lifter lock poisoned".to_string())
            })?;
            rugra::flow::follow_flow_range(
                restart_fd,
                &mut lifter,
                0,
                u64::MAX,
                &restart_protos,
            )
        }),
    );
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during analysis".to_string())?;
        db.perform_action("decompile", &mut fd_write)
            .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
    }

    // GEN-CODEPTR-SYMBOLIZE-0001: the print-side function-symbol channel.
    // The oracle's golden harness registers every BFD function symbol into
    // the Architecture's symboltab before printing
    // (regen_ghidra_golden.py:219-231 registerFunctionSymbol →
    // scope->addFunction(address, basename)), so PrintC::pushPtrCodeConstant
    // (printc.cc:1730-1742) resolves pointer-to-code constants through
    // glb->symboltab->getGlobalScope()->queryFunction and prints the
    // function display name instead of the default `(code *)0xVAL` arm
    // (printc.cc:1806-1814). Rugra's mechanism pieces are all present
    // (push_ptr_code_constant → query_global_function →
    // Scope::query_function_addr) but the gen driver never installed a
    // symboltab, so the PrintC snapshot taken in doc_function
    // (fd.arch.symboltab) was always None and every code-pointer constant
    // missed the query. Install a print-only Database carrying the full
    // function registry on a cloned Architecture — the
    // CURL-CODEREF-SYMBOLIZE-0001 precedent (curl_decompile.rs:6894-6924):
    // the action phase above already ran on the original arch (this swap is
    // print-only, zero action-phase drift), and the Funcdata name proxy
    // (fd.symbol_table, fed by add_symbol above) supplies the display
    // names for the entry addresses the query returns. Consume size 1 =
    // glb->min_funcsymbol_size default (database.cc:1626). discover_functions
    // is address-unique (static → dynamic → PLT first-wins or_insert_with),
    // matching the golden's queryFunction dedup (first registration wins).
    let mut print_symbol_db = rugra::database::Database::new(false);
    {
        let db_scope = print_symbol_db
            .get_global_scope_mut()
            .ok_or_else(|| "print symbol DB has no global scope".to_string())?;
        for function in functions {
            db_scope.add_function(Address::new(function.vaddr), &function.name, 1);
        }
    }
    eprintln!(
        "[PREPASS] GEN-CODEPTR-SYMBOLIZE-0001 print DB: {} function symbols",
        functions.len()
    );
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during print DB install".to_string())?;
        if let Some(a) = fd_write.arch.clone() {
            let mut print_arch = (*a).clone();
            print_arch.set_symboltab(std::sync::Arc::new(std::sync::RwLock::new(
                print_symbol_db,
            )));
            fd_write.arch = Some(std::sync::Arc::new(print_arch));
        }
    }

    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    {
        let fd_read = fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned during printing".to_string())?;
        printer.doc_function(&fd_read);
    }
    let output_buffer = printer
        .take_emit()
        .into_any()
        .downcast::<EmitPrettyPrint>()
        .map_err(|_| "PrintC returned an unexpected emitter type".to_string())?;
    let c_code = output_buffer.get_output();
    println!(
        "/* ---- 0x{:x}: {} ({} bytes) ---- */",
        target.vaddr,
        target.name,
        fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned".to_string())?
            .get_size()
    );
    println!("{}", c_code.trim_end());
    // PERF-DUAL-SLEIGH-INIT-0001 load-count gate: report this process's
    // full .sla deserializations when asked (default silent — the canon and
    // mirror protocols see no extra output line).
    if std::env::var("RUGRA_SLEIGH_LOAD_REPORT").is_ok_and(|value| value != "0") {
        eprintln!(
            "[GEN] sleigh engine loads={}",
            rugra::sleigh_ffi::engine_load_count()
        );
    }
    Ok(())
}

fn load_functions(binary_path: &str) -> Result<Vec<GenFunction>, String> {
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("not an ELF binary".to_string()),
    };
    Ok(discover_functions(elf))
}

// ---------------------------------------------------------------------------
// GEN-DRIVER-STALL-0001: all-mode child supervision.
//
// RUGRA-GLUE: pure driver infrastructure — the oracle golden generator is a
// C++ harness with its own OS plumbing; there is no decompiler counterpart
// to match here. The mechanism being guarded against (verified in the
// locked toolchain's std source, 1.96.0-nightly):
//
//   sys/process/mod.rs output()      -> spawn -> read_output() -> wait()
//   sys/process/unix/common.rs:632   -> poll(fds, 2, /*timeout=*/ -1)
//
// read_output blocks in poll(2) indefinitely until BOTH stdout and stderr
// hit EOF, and EOF only arrives when every write-end holder is gone. The
// all-mode tree is coordinator -> `timeout` -> `--one`, so any death pattern
// that strands a write-end holder — `timeout` SIGKILLed by the OOM killer
// while its monitored child lives on, a descendant reparented to init when
// the direct child dies first — parks the coordinator in poll forever at
// 0 CPU with no visible children (the exact intermittent-stall signature
// observed twice on the sqlite corpus runs). run_capped_output below keeps
// Command::output()'s capture face (stdin null, both pipes read to EOF,
// status via wait4) and adds the missing caps: a wall-clock ceiling with
// process-tree SIGKILL, and a post-exit grace followed by a /proc fd scan
// that SIGKILLs whoever still holds the pipes. On the normal path nothing
// observable changes: same fds, same bytes, same status.
// ---------------------------------------------------------------------------

// SIGKILL from <signal.h>, declared locally to avoid adding a libc crate
// dependency to the example (std already links libc).
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

fn sigkill(pid: u32) {
    let _ = unsafe { kill(pid as i32, 9) };
}

// `timeout --kill-after` margin and the coordinator wall cap on top of the
// per-function deadline (deadline + kill-after + slack).
const TIMEOUT_KILL_AFTER_SECS: u64 = 30;
const WALL_CAP_SLACK_SECS: u64 = 120;

// After the direct child exits, the pipes must EOF within this grace in the
// normal path (EOF lands at exit; the grace only absorbs pipe-buffer
// draining). Missing that deadline means a holder outlived the child.
const STALL_GRACE: Duration = Duration::from_secs(10);
// Re-check window after the holders have been SIGKILLed.
const STALL_KILL_RECHECK: Duration = Duration::from_secs(5);
// Idle between try_wait polls; wakes are event-driven in the normal path
// (pipe EOF arrives on the channel at child death), so this only bounds
// the post-EOF reap latency and the wall-cap check resolution.
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn pipe_inode(fd: std::os::fd::RawFd) -> Option<u64> {
    std::fs::metadata(format!("/proc/self/fd/{fd}"))
        .ok()
        .map(|meta| {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        })
}

// RUGRA-GLUE: one /proc snapshot of (ppid, pid) edges under `root`,
// deepest-first. Killing deepest-first means no not-yet-killed descendant
// can be reparented out of the walk while we are killing its ancestors.
fn descendant_pids(root: u32) -> Vec<u32> {
    let mut table: Vec<(u32, u32)> = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // "pid (comm) state ppid ..." — comm may contain spaces and
        // parentheses, so anchor on the LAST ')' of field 2.
        let Some(rest) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.1.split_whitespace();
        let _state = fields.next();
        let Some(ppid) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        table.push((ppid, pid));
    }
    let mut frontier = vec![root];
    let mut found: Vec<u32> = Vec::new();
    while let Some(current) = frontier.pop() {
        for &(ppid, pid) in table.iter() {
            if ppid == current && pid != root {
                found.push(pid);
                frontier.push(pid);
            }
        }
    }
    found.reverse();
    found
}

fn kill_tree(pid: u32) {
    for victim in descendant_pids(pid) {
        sigkill(victim);
    }
    // Root last: while it lives its descendants remain reachable by ppid.
    sigkill(pid);
}

fn process_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|comm| comm.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

// RUGRA-GLUE: SIGKILL every foreign process still holding an end of one of
// our pipes, found by matching "pipe:[inode]" fd symlinks in /proc. This is
// the only reach a coordinator has into holders that were reparented away
// when the direct child died before them — the observed stall topology.
// Only processes that inherited the write end from our own child can match
// the inode, so concurrent lanes' drivers are never collateral.
fn kill_pipe_holders(inodes: &[u64]) -> Vec<(u32, String)> {
    let me = std::process::id();
    let mut killed = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return killed;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(rest) = target.strip_prefix("pipe:[") else {
                continue;
            };
            let Some(ino) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(ino) = ino.parse::<u64>() else {
                continue;
            };
            if inodes.contains(&ino) {
                sigkill(pid);
                killed.push((pid, process_comm(pid)));
                break;
            }
        }
    }
    killed
}

// RUGRA-GLUE: Command::output() with the same capture face (stdin null,
// stdout/stderr piped and read to EOF, exit status via wait4) plus a
// wall-clock cap with tree-kill escalation. Normal-path bytes and status
// are identical to std's output(); the escalation arms only fire when the
// direct child is dead (or cap-blown) and something still holds a pipe.
fn run_capped_output(
    mut command: Command,
    wall_cap: Option<Duration>,
) -> std::io::Result<std::process::Output> {
    use std::io::ErrorKind;
    use std::io::Read;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Instant;

    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn()?;
    let pid = child.id();
    let stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let pipe_inodes: Vec<u64> = [stdout_pipe.as_raw_fd(), stderr_pipe.as_raw_fd()]
        .into_iter()
        .filter_map(pipe_inode)
        .collect();
    // Readers stream into shared buffers so partial output survives even
    // if a holder wedges a reader past every escalation (D state).
    let stdout_buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stderr_buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (done_tx, done_rx) = mpsc::channel::<bool>();
    fn spawn_reader<R: Read + Send + 'static>(
        mut pipe: R,
        buffer: Arc<std::sync::Mutex<Vec<u8>>>,
        done_tx: mpsc::Sender<bool>,
    ) {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 16384];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        buffer
                            .lock()
                            .expect("child output buffer lock")
                            .extend_from_slice(&chunk[..read]);
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = done_tx.send(true);
        });
    }
    spawn_reader(stdout_pipe, Arc::clone(&stdout_buffer), done_tx.clone());
    spawn_reader(stderr_pipe, Arc::clone(&stderr_buffer), done_tx.clone());
    drop(done_tx);

    let started = Instant::now();
    let mut readers_done = 0usize;
    let mut tree_killed = false;
    let status;
    'supervise: loop {
        if readers_done < 2 {
            match done_rx.recv_timeout(CHILD_POLL_INTERVAL) {
                Ok(_) => readers_done += 1,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    readers_done = 2;
                }
            }
        } else {
            std::thread::sleep(CHILD_POLL_INTERVAL);
        }
        if let Some(exit_status) = child.try_wait()? {
            status = exit_status;
            break 'supervise;
        }
        if let Some(cap) = wall_cap {
            let elapsed = started.elapsed();
            if !tree_killed && elapsed > cap {
                eprintln!(
                    "[GEN-STALL] wall cap {cap:?} exceeded for pid {pid} ({}); killing its process tree",
                    process_comm(pid)
                );
                kill_tree(pid);
                tree_killed = true;
            } else if tree_killed && elapsed > cap + STALL_KILL_RECHECK {
                // SIGKILL delivered but the child will not die (D state).
                // Fail loud instead of polling forever; a zombie may linger
                // until the coordinator exits.
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!("child pid {pid} survived SIGKILL past the wall cap"),
                ));
            }
        }
    }

    // Post-exit drain: EOF must follow the last write-end holder. Normal
    // path already delivered both readers above; this grace catches pipe
    // contents still buffered, and a miss means a holder outlived the child.
    let mut received = readers_done.min(2);
    if received < 2 {
        let deadline = Instant::now() + STALL_GRACE;
        while received < 2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match done_rx.recv_timeout(remaining) {
                Ok(_) => received += 1,
                Err(_) => break,
            }
        }
    }
    if received < 2 {
        let holders = kill_pipe_holders(&pipe_inodes);
        if !holders.is_empty() {
            let victims = holders
                .iter()
                .map(|(pid, comm)| format!("{pid}({comm})"))
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!(
                "[GEN-STALL] pid {pid} exited with {} pipe(s) still open; SIGKILLed holder(s): {victims}",
                2 - received
            );
        }
        let deadline = Instant::now() + STALL_KILL_RECHECK;
        while received < 2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match done_rx.recv_timeout(remaining) {
                Ok(_) => received += 1,
                Err(_) => break,
            }
        }
        if received < 2 {
            eprintln!(
                "[GEN-STALL] pid {pid} pipe holders survived SIGKILL; continuing with partial capture"
            );
        }
    }
    let stdout_bytes = std::mem::take(
        &mut *stdout_buffer.lock().expect("stdout buffer lock"),
    );
    let stderr_bytes = std::mem::take(
        &mut *stderr_buffer.lock().expect("stderr buffer lock"),
    );
    Ok(std::process::Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    })
}


fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: {} <binary> [--list | --one <index>]\n  env: RUGRA_GEN_MIRROR=1 RUGRA_GEN_TIMEOUT_SECS=<n> RUGRA_GEN_ONLY=<name>",
            args[0]
        );
        std::process::exit(1);
    }
    let binary_path = args[1].clone();
    let functions = match load_functions(&binary_path) {
        Ok(functions) => functions,
        Err(error) => {
            eprintln!("[GEN] discovery failed: {error}");
            std::process::exit(1);
        }
    };
    if functions.is_empty() {
        eprintln!("[GEN] no function symbols discovered in {}", binary_path);
        std::process::exit(1);
    }
    eprintln!(
        "[GEN] {} functions discovered in {} (static+dynamic FUNC + PLT JUMP_SLOT stubs)",
        functions.len(),
        binary_path
    );

    if args.iter().any(|arg| arg == "--list") {
        for (index, function) in functions.iter().enumerate() {
            eprintln!("[GEN] {:>3} 0x{:>8x} {:>6} {}", index, function.vaddr, function.size, function.name);
        }
        return;
    }
    if let Some(position) = args.iter().position(|arg| arg == "--one") {
        let index: usize = args[position + 1]
            .parse()
            .unwrap_or_else(|_| panic!("--one needs a function index"));
        if index >= functions.len() {
            panic!("index {index} out of range ({} functions)", functions.len());
        }
        // Big-stack thread: ActionGroup::perform can recurse deep.
        let child = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn({
                let bp = binary_path.clone();
                let fns = functions.clone();
                move || run_one(&bp, &fns, index)
            })
            .expect("failed to spawn stack thread");
        match child.join().expect("worker thread panicked") {
            Ok(()) => {}
            Err(message) => {
                eprintln!("[GEN] --one failed: {message}");
                std::process::exit(1);
            }
        }
        return;
    }

    // all-mode: isolated child per function (hermetic "one" mirror),
    // `timeout`-wrapped when RUGRA_GEN_TIMEOUT_SECS > 0. The wrapper also
    // carries --kill-after so a SIGTERM-immune child is SIGKILLed at the
    // deadline instead of wedging `timeout` in waitpid, and the coordinator
    // supervises each child through run_capped_output (GEN-DRIVER-STALL-0001:
    // wall cap + post-exit pipe-holder kill; normal path byte-identical to
    // Command::output()).
    let timeout_secs: u64 = std::env::var("RUGRA_GEN_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let wall_cap = (timeout_secs > 0).then(|| {
        Duration::from_secs(
            timeout_secs + TIMEOUT_KILL_AFTER_SECS + WALL_CAP_SLACK_SECS,
        )
    });
    let only = std::env::var("RUGRA_GEN_ONLY").ok();
    let only_addr = only
        .as_deref()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u64::from_str_radix(value, 16).ok());
    let exe = std::env::current_exe().expect("current_exe");
    let mirror_env = std::env::var("RUGRA_GEN_MIRROR").ok();
    let mut ok_count = 0usize;
    for (index, function) in functions.iter().enumerate() {
        if let Some(name) = only.as_deref() {
            if name != function.name && only_addr != Some(function.vaddr) {
                continue;
            }
        }
        let mut command = if timeout_secs > 0 {
            let mut wrapped = Command::new("timeout");
            wrapped
                .arg(format!("--kill-after={TIMEOUT_KILL_AFTER_SECS}s"))
                .arg(format!("{}s", timeout_secs));
            wrapped.arg(&exe).arg(&binary_path).arg("--one").arg(index.to_string());
            wrapped
        } else {
            let mut plain = Command::new(&exe);
            plain.arg(&binary_path).arg("--one").arg(index.to_string());
            plain
        };
        if let Some(mirror) = mirror_env.as_ref() {
            command.env("RUGRA_GEN_MIRROR", mirror);
        }
        let output = match run_capped_output(command, wall_cap) {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                println!(
                    "/* ---- 0x{:x}: {} STALL: child unkillable past wall cap ({error}) ---- */",
                    function.vaddr, function.name
                );
                continue;
            }
            Err(error) => {
                panic!("spawn failed for {}: {error}", function.name);
            }
        };
        let status = output.status;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if status.success() && stdout.contains("/* ----") {
            print!("{}", stdout);
            if !stdout.ends_with('\n') {
                println!();
            }
            ok_count += 1;
        } else if status.code().is_some_and(|code| code == 124) {
            println!(
                "/* ---- 0x{:x}: {} TIMEOUT (>{}s) ---- */",
                function.vaddr, function.name, timeout_secs
            );
        } else if stderr.contains("panicked") {
            let reason = stderr
                .lines()
                .rev()
                .find(|line| line.contains("panicked") || line.starts_with("Error"))
                .unwrap_or("panicked");
            println!(
                "/* ---- 0x{:x}: {} PANICKED: {} ---- */",
                function.vaddr, function.name, reason
            );
        } else {
            let reason = stderr
                .lines()
                .rev()
                .find(|line| line.starts_with("[GEN] --one failed"))
                .map(|line| line.trim_start_matches("[GEN] --one failed: "))
                .unwrap_or("nonzero exit");
            println!(
                "/* ---- 0x{:x}: {} ERROR: {} ---- */",
                function.vaddr, function.name, reason
            );
        }
    }
    eprintln!("[GEN] ok={}/{} functions", ok_count, functions.len());
}
