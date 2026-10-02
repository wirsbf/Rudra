//! PAREVAL lane Phase-1 PoC (PAREVAL-PHASE1-POC-0001): in-process
//! multi-function thread-parallel decompilation — determinism gate plus
//! speedup measurement.
//!
//! Contract (see docs/alignment_docs/PARALLELIZATION_DESIGN_2026-09-26.md):
//!   * Per-function decompile inputs are IDENTICAL to the bin_sweep
//!     bare-native face (GENSMOKE-0001 verbatim: BFD function discovery,
//!     PT_LOAD image + import relocations, bare Architecture, full default
//!     action pipeline, PrintC pretty face). The ONLY parameterization is
//!     the TypeFactory source under measurement:
//!       - isolated : fresh `TypeFactory::new(8)` per function
//!                    (rudra_decompile_func.rs shape)
//!       - shared   : process-global `TypeFactory::shared_default()`
//!                    singleton (bin_sweep shape) — the PKGG contention
//!                    surface
//!   * Determinism protocol ("parallel = observation-neutral"): for every
//!     function, the printed C text from the PARALLEL arms must be
//!     BYTE-IDENTICAL to the SERIAL arm, and parallel-run-1 must be
//!     byte-identical to parallel-run-2. Panic functions must panic with
//!     the same message+location in every arm. The process exit code is 0
//!     iff the whole matrix is green (usable as a verify gate).
//!   * Nothing here changes decompile semantics; the driver only schedules
//!     whole-function jobs onto threads (one-Architecture-per-worker
//!     thread discipline, SPACE-0001).
//!
//! Phases per factory mode: serial (one 256MB-stack thread, all functions
//! in index order) → parallel run 1 (K worker threads, dynamic queue) →
//! parallel run 2 (fresh worker threads, same jobs).
//!
//! Usage (run from the repo root — sleigh_specs/ is CWD-relative):
//!   cargo run --profile fast-release --example pareval_poc -- \
//!       examples/curl --workers 8 --max-funcs 31 \
//!       --out-dir /dev/shm/rudra-tests/pareval/run-curl
//!   # screening pass (builds the deterministic skip list for corpora with
//!   # known non-terminating functions — RuleDivChain PORT-DEFECT):
//!   cargo run --profile fast-release --example pareval_poc -- \
//!       /tmp/sqlite3 --screen --max-funcs 48
//!   # then rerun with --skip <hanging indexes> (watchdog kill outside)

use goblin::Object;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use rudra::action::ActionDatabase;
use rudra::address::Address;
use rudra::disasm::sleigh_lift::SleighLifter;
use rudra::funcdata::Funcdata;
use rudra::printc::PrintC;
use rudra::printlanguage::PrintLanguage;
use rudra::prettyprint::EmitPrettyPrint;

const R_X86_64_GLOB_DAT: u32 = 1;
const R_X86_64_JUMP_SLOT: u32 = 7;
const PT_LOAD: u32 = 1;
const STACK_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_FUNCS: usize = 24;
const DEFAULT_WORKERS: usize = 8;

// ===========================================================================
// Function discovery + memory image — bin_sweep.rs verbatim (GENSMOKE-0001)
// ===========================================================================

#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

fn discover_functions(elf: &goblin::elf::Elf) -> Vec<GenFunction> {
    let mut by_addr: HashMap<u64, GenFunction> = HashMap::new();
    let mut register = |vaddr: u64, name: String, size: usize| {
        by_addr.entry(vaddr).or_insert_with(|| GenFunction {
            vaddr,
            name,
            size,
        });
    };
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
                if !name.is_empty() && !name.starts_with('_') {
                    register(stub, name.to_string(), 16);
                }
            }
        }
    }
    let mut functions: Vec<GenFunction> = by_addr.into_values().collect();
    functions.sort_by(|a, b| a.vaddr.cmp(&b.vaddr));
    functions
}

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

// ===========================================================================
// Spec host — bin_sweep.rs verbatim (FUNCPROTO-MODEL-BIND-0001 driver copy)
// ===========================================================================

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

fn spec_space_by_name(name: &str) -> Option<rudra::space::AddressSpace> {
    use rudra::space::AddressSpace;
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

struct SweepSpecHost {
    registers: HashMap<String, rudra::fspec::VarnodeData>,
}

impl rudra::arch::SpecQuery for SweepSpecHost {
    fn get_register(&self, name: &str) -> Option<rudra::fspec::VarnodeData> {
        self.registers.get(name).copied()
    }
    fn space_by_name(&self, name: &str) -> Option<rudra::space::AddressSpace> {
        spec_space_by_name(name)
    }
    fn space_highest(&self, spc: rudra::space::AddressSpace) -> u64 {
        let name = match spc {
            rudra::space::AddressSpace::Const => "const",
            rudra::space::AddressSpace::Other(_) => "OTHER",
            rudra::space::AddressSpace::Unique => "unique",
            rudra::space::AddressSpace::Ram => "ram",
            rudra::space::AddressSpace::Register => "register",
            rudra::space::AddressSpace::Stack => "stack",
            rudra::space::AddressSpace::Iop => "iop",
            rudra::space::AddressSpace::Join => "join",
            rudra::space::AddressSpace::Overlay => "OTHER",
        };
        SPEC_SPACES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, highest)| *highest)
            .unwrap_or(u64::MAX)
    }
    fn unique_inject_base(&self) -> u64 {
        0x364_400
    }
}

impl rudra::pcodeparse::SleighSymbolLookup for SweepSpecHost {
    fn find_symbol(&self, name: &str) -> Option<rudra::pcodeparse::SleighSymbol> {
        self.registers
            .get(name)
            .map(|vd| rudra::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: rudra::pcodeparse::SleightSymbolKind::Varnode(rudra::varnode::VarnodeData {
                    space: vd.space,
                    offset: vd.offset,
                    size: vd.size.max(0) as usize,
                }),
            })
    }
}

// ===========================================================================
// Architecture build — bin_sweep build_architecture verbatim except the
// TypeFactory source is parameterized (the measurement axis).
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
enum FactoryMode {
    /// Fresh `TypeFactory::new(8)` per function (rudra_decompile_func shape).
    Isolated,
    /// Process-global `TypeFactory::shared_default()` (bin_sweep shape).
    Shared,
}

impl FactoryMode {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "isolated" => Some(FactoryMode::Isolated),
            "shared" => Some(FactoryMode::Shared),
            _ => None,
        }
    }
}

// PERF-DUAL-SLEIGH-INIT-0001: also returns the register-catalog engine so
// decompile_one's lifter adopts it (SleighLifter::from_ctx) — the oracle's
// ONE translator per Architecture (sleigh_arch.cc:174 buildTranslator
// reuse), not a second x86-64.sla deserialization. The per-function arch
// rebuild itself is PAREVAL-ARCH-BUILD-COST-0001 scope (separate seam).
fn build_architecture(
    loader: Option<std::sync::Arc<dyn rudra::loadimage::LoadImage>>,
    mode: FactoryMode,
) -> Result<
    (
        std::sync::Arc<rudra::arch::Architecture>,
        rudra::sleigh_ffi::SleighCtx,
    ),
    String,
> {
    use std::sync::Arc;
    let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    let sleigh = rudra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    let mut registers: HashMap<String, rudra::fspec::VarnodeData> = HashMap::new();
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
            rudra::fspec::VarnodeData {
                space: rudra::space::AddressSpace::from_id(space_id),
                offset,
                size,
            },
        );
    }
    let host = Arc::new(SweepSpecHost { registers });
    let mut store = rudra::marshal::DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    let root = doc
        .root
        .clone()
        .ok_or_else(|| "compiler spec has no root element".to_string())?;
    if root
        .read()
        .map_err(|_| "cspec element lock poisoned".to_string())?
        .name
        != "compiler_spec"
    {
        return Err("compiler spec root is not compiler_spec".to_string());
    }
    store.register_tag(&root);
    let mut arch = rudra::arch::Architecture::new();
    arch.archid = "x86:LE:64:default".to_string();
    arch.set_register_xref(register_xref);
    arch.set_commentdb(Arc::new(std::sync::RwLock::new(
        rudra::comment::CommentDatabaseInternal::new(),
    )));
    // --- measurement axis: where does the TypeFactory live? ---
    let types = match mode {
        FactoryMode::Shared => rudra::type_system::typefactory::TypeFactory::shared_default(),
        FactoryMode::Isolated => Arc::new(std::sync::RwLock::new(
            rudra::type_system::typefactory::TypeFactory::new(8),
        )),
    };
    let data_org = root
        .read()
        .map_err(|_| "cspec element lock poisoned".to_string())?
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
    let registry = Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
    let mut decoder = rudra::marshal::TreeDecoder::new(data_org, registry);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .decode_data_organization(&mut decoder);
    types
        .write()
        .map_err(|_| "cspec factory lock poisoned".to_string())?
        .setup_sizes(&rudra::type_system::typefactory::SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
    arch.set_types(Arc::clone(&types));
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(0x364_400);
    inject_lib.set_sleigh_lookup(host.clone());
    arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject_lib)));
    arch.userops = Some(Arc::new(std::sync::RwLock::new(
        rudra::userop::UserOpManage::new(),
    )));
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
            .map_err(|_| "pspec element lock poisoned".to_string())?
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
                .map_err(|_| "pspec element lock poisoned".to_string())?
                .children
                .get(position)
                .cloned()
                .ok_or_else(|| "processor spec child vanished".to_string())?;
            match name.as_str() {
                "context_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
                    let mut decoder = rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_context_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
                }
                "register_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
                    let mut decoder = rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_register_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec register_data decode failed: {error}"))?;
                }
                _ => {}
            }
        }
    }
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    if let Some(loader) = loader {
        arch.loader = Some(loader);
        arch.build_string_manager();
    }
    Ok((Arc::new(arch), sleigh))
}

// ===========================================================================
// Per-function decompile (bin_sweep run_one shape, but returns the FULL
// printed C text + per-stage timings for the contention profile).
// ===========================================================================

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Outcome {
    Ok {
        bytes_len: usize,
        text: String,
        arch_us: u128,
        flow_us: u128,
        act_us: u128,
        print_us: u128,
        total_us: u128,
    },
    Err {
        stage: String,
        msg: String,
    },
    Panic {
        stage: String,
        msg: String,
        location: String,
    },
}

thread_local! {
    static LAST_PANIC_LOC: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

fn install_panic_hook() {
    panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}", loc.file(), loc.line()))
            .unwrap_or_else(|| "unknown".to_string());
        LAST_PANIC_LOC.with(|slot| *slot.borrow_mut() = Some(location.clone()));
        eprintln!("[POC-PANIC] {}", location);
    }));
}

/// One whole-function job. Everything (Architecture, Funcdata, SLEIGH
/// lifter) is created and dropped on the calling thread — the
/// one-Architecture-per-worker discipline (SPACE-0001: Address space tags
/// are thread-scoped and never cross threads).
fn decompile_one(
    image: &[u8],
    image_name: &str,
    target: &GenFunction,
    functions: &[GenFunction],
    mode: FactoryMode,
) -> Outcome {
    LAST_PANIC_LOC.with(|slot| *slot.borrow_mut() = None);
    let started = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let t_arch = Instant::now();
        let loader: std::sync::Arc<dyn rudra::loadimage::LoadImage> =
            std::sync::Arc::new(rudra::loadimage::RawLoadImage::from_bytes(
                image_name,
                0,
                image.to_vec(),
            ));
        let (arch, sleigh_ctx) = match build_architecture(Some(loader), mode) {
            Ok(built) => built,
            Err(msg) => return Outcome::Err {
                stage: "arch".to_string(),
                msg,
            },
        };
        let arch_us = t_arch.elapsed().as_micros();

        let t_flow = Instant::now();
        let func_size = match i32::try_from(target.size) {
            Ok(size) => size,
            Err(_) => {
                return Outcome::Err {
                    stage: "size".to_string(),
                    msg: format!("function {} is too large", target.name),
                }
            }
        };
        let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
        fd.set_arch(arch);
        for function in functions {
            fd.add_symbol(function.vaddr, function.name.clone());
        }
        // PERF-DUAL-SLEIGH-INIT-0001: adopt the register-catalog engine
        // (single .sla load per function build; oracle sleigh_arch.cc:174
        // buildTranslator reuses the one translator). Read-only catalog leg.
        let mut sleigh = SleighLifter::from_ctx(sleigh_ctx);
        if let Err(error) = sleigh.configure_x86_64(image, 0) {
            return Outcome::Err {
                stage: "sleigh".to_string(),
                msg: format!("failed to configure SLEIGH: {error}"),
            };
        }
        let empty_protos = std::collections::BTreeMap::new();
        if let Err(error) = rudra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        {
            return Outcome::Err {
                stage: "flow".to_string(),
                msg: format!("flow generation failed for {}: {error}", target.name),
            };
        }
        let flow_us = t_flow.elapsed().as_micros();

        let t_act = Instant::now();
        let mut db = ActionDatabase::new();
        db.set_default_actions();
        if let Err(error) = db.perform_action("decompile", &mut fd) {
            return Outcome::Err {
                stage: "actions".to_string(),
                msg: format!("action pipeline failed for {}: {error}", target.name),
            };
        }
        let act_us = t_act.elapsed().as_micros();

        let t_print = Instant::now();
        let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
        printer.set_rpn_enabled(true);
        printer.doc_function(&fd);
        let output_buffer = printer
            .take_emit()
            .into_any()
            .downcast::<EmitPrettyPrint>()
            .expect("PrintC returned an unexpected emitter type");
        let c_code = output_buffer.get_output();
        let print_us = t_print.elapsed().as_micros();
        let text = c_code.trim_end().to_string();
        Outcome::Ok {
            bytes_len: text.len(),
            text,
            arch_us,
            flow_us,
            act_us,
            print_us,
            total_us: started.elapsed().as_micros(),
        }
    }));
    match result {
        Ok(outcome) => outcome,
        Err(payload) => {
            let msg = if let Some(text) = payload.downcast_ref::<String>() {
                text.clone()
            } else if let Some(text) = payload.downcast_ref::<&str>() {
                (*text).to_string()
            } else {
                "non-string panic payload".to_string()
            };
            let location = LAST_PANIC_LOC
                .with(|slot| slot.borrow().clone())
                .unwrap_or_else(|| "unknown".to_string());
            Outcome::Panic {
                stage: "pipeline".to_string(),
                msg,
                location,
            }
        }
    }
}

// ===========================================================================
// Phase drivers: serial (one thread) and parallel (K workers, dynamic queue)
// ===========================================================================

struct SharedJob {
    image: Arc<Vec<u8>>,
    image_name: String,
    functions: Vec<GenFunction>,
    mode: FactoryMode,
}

fn run_serial(jobs: &[usize], shared: &SharedJob) -> Vec<Outcome> {
    let mut out = Vec::with_capacity(jobs.len());
    for &idx in jobs {
        out.push(decompile_one(
            &shared.image,
            &shared.image_name,
            &shared.functions[idx],
            &shared.functions,
            shared.mode,
        ));
    }
    out
}

fn run_parallel(
    jobs: &[usize],
    shared: Arc<SharedJob>,
    workers: usize,
) -> std::io::Result<Vec<Outcome>> {
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs.to_vec())));
    // Completion-ordered slots carrying the job index; results are
    // reordered by index after join so completion order can never leak
    // into the comparison.
    let results: Arc<Mutex<Vec<Option<IndexedOutcome>>>> =
        Arc::new(Mutex::new((0..jobs.len()).map(|_| None).collect()));
    let next = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(workers);
    for worker in 0..workers {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        let shared = Arc::clone(&shared);
        let next = Arc::clone(&next);
        let handle = thread::Builder::new()
            .stack_size(STACK_BYTES)
            .name(format!("par-w{}", worker))
            .spawn(move || loop {
                let job = {
                    let mut guard = queue.lock().unwrap();
                    guard.pop_front()
                };
                let Some(idx) = job else {
                    break;
                };
                let slot = next.fetch_add(1, Ordering::SeqCst);
                let outcome = decompile_one(
                    &shared.image,
                    &shared.image_name,
                    &shared.functions[idx],
                    &shared.functions,
                    shared.mode,
                );
                let mut guard = results.lock().unwrap();
                guard[slot] = Some(IndexedOutcome { idx, outcome });
            })?;
        handles.push(handle);
    }
    for handle in handles {
        handle.join().expect("parallel worker panicked outside catch_unwind");
    }
    let mut by_idx: Vec<IndexedOutcome> = results
        .lock()
        .unwrap()
        .drain(..)
        .map(|slot| slot.expect("worker dropped a result"))
        .collect();
    by_idx.sort_by_key(|entry| entry.idx);
    Ok(by_idx.into_iter().map(|entry| entry.outcome).collect())
}

/// Carries the job index through the completion-ordered result slots.
#[derive(Clone)]
struct IndexedOutcome {
    idx: usize,
    outcome: Outcome,
}

// ===========================================================================
// Comparison matrix (the determinism gate)
// ===========================================================================

fn outcome_signature(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Ok { bytes_len, .. } => format!("ok:{}", bytes_len),
        Outcome::Err { stage, msg } => format!("err:{}:{}", stage, msg),
        Outcome::Panic { stage, msg, location } => {
            format!("panic:{}:{}:{}", stage, location, msg)
        }
    }
}

fn texts_equal(a: &Outcome, b: &Outcome) -> Option<bool> {
    match (a, b) {
        (Outcome::Ok { text: ta, .. }, Outcome::Ok { text: tb, .. }) => Some(ta == tb),
        _ => None,
    }
}

// ===========================================================================
// Reporting
// ===========================================================================

#[derive(Serialize)]
struct FuncRecord {
    idx: usize,
    name: String,
    vaddr: u64,
    size: usize,
    serial_sig: String,
    par1_sig: String,
    par2_sig: String,
    serial_vs_par1: String,
    serial_vs_par2: String,
    par1_vs_par2: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial_total_us: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    par1_total_us: Option<u128>,
}

#[derive(Serialize)]
struct ModeReport {
    mode: FactoryMode,
    workers: usize,
    jobs: usize,
    serial_wall_us: u128,
    par1_wall_us: u128,
    par2_wall_us: u128,
    speedup: f64,
    serial_cpu_us: u128,
    par1_cpu_us: u128,
    ok_functions: usize,
    err_functions: usize,
    panic_functions: usize,
    matrix: Vec<FuncRecord>,
    stage_profile: StageProfile,
}

#[derive(Serialize, Default)]
struct StageProfile {
    /// Sums over ok functions, per arm.
    serial_arch_us: u128,
    serial_flow_us: u128,
    serial_act_us: u128,
    serial_print_us: u128,
    par1_arch_us: u128,
    par1_flow_us: u128,
    par1_act_us: u128,
    par1_print_us: u128,
}

fn collect_stage(profile: &mut StageProfile, arm: u8, outcome: &Outcome) {
    if let Outcome::Ok {
        arch_us,
        flow_us,
        act_us,
        print_us,
        ..
    } = outcome
    {
        if arm == 0 {
            profile.serial_arch_us += arch_us;
            profile.serial_flow_us += flow_us;
            profile.serial_act_us += act_us;
            profile.serial_print_us += print_us;
        } else {
            profile.par1_arch_us += arch_us;
            profile.par1_flow_us += flow_us;
            profile.par1_act_us += act_us;
            profile.par1_print_us += print_us;
        }
    }
}

fn fmt_us(us: u128) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1e6)
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1e3)
    } else {
        format!("{}us", us)
    }
}

fn write_text_dir(dir: &Path, arm: &str, functions: &[GenFunction], jobs: &[usize], outcomes: &[Outcome]) {
    fs::create_dir_all(dir).ok();
    // Results are indexed by JOB position (outcomes[slot] == jobs[slot]'s
    // outcome); the file name must use the JOB's function, not the slot
    // number, or skip-list runs mislabel the audit files.
    for (slot, outcome) in outcomes.iter().enumerate() {
        let idx = jobs[slot];
        if let Outcome::Ok { text, .. } = outcome {
            let path = dir.join(format!("f{:03}_{}.{}.c", idx, functions[idx].name, arm));
            fs::write(path, text).ok();
        }
    }
}

// ===========================================================================
// main
// ===========================================================================

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        return Err(format!(
            "usage: {} <binary> [--workers K] [--max-funcs N] [--modes isolated,shared] \
             [--skip 1,2] [--screen] [--out-dir DIR]",
            argv.first().map(String::as_str).unwrap_or("pareval_poc")
        ));
    }
    let mut args = Args {
        binary: argv[1].clone(),
        workers: DEFAULT_WORKERS,
        max_funcs: DEFAULT_MAX_FUNCS,
        modes: vec![FactoryMode::Isolated, FactoryMode::Shared],
        skip: Vec::new(),
        screen: false,
        out_dir: PathBuf::from("/dev/shm/rudra-tests/pareval/poc-out"),
    };
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--workers" => {
                i += 1;
                args.workers = argv
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--workers needs a number")?;
            }
            "--max-funcs" => {
                i += 1;
                args.max_funcs = argv
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--max-funcs needs a number")?;
            }
            "--modes" => {
                i += 1;
                let raw = argv.get(i).ok_or("--modes needs a list")?;
                args.modes = raw
                    .split(',')
                    .map(FactoryMode::parse)
                    .collect::<Option<Vec<_>>>()
                    .ok_or("--modes entries must be isolated|shared")?;
            }
            "--skip" => {
                i += 1;
                let raw = argv.get(i).ok_or("--skip needs a list")?;
                args.skip = raw
                    .split(',')
                    .map(|v| v.parse().map_err(|_| "bad --skip entry".to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "--screen" => args.screen = true,
            "--out-dir" => {
                i += 1;
                args.out_dir = PathBuf::from(argv.get(i).ok_or("--out-dir needs a path")?);
            }
            other => return Err(format!("unknown flag {}", other)),
        }
        i += 1;
    }
    Ok(args)
}

struct Args {
    binary: String,
    workers: usize,
    max_funcs: usize,
    modes: Vec<FactoryMode>,
    skip: Vec<usize>,
    screen: bool,
    out_dir: PathBuf,
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{}", msg);
            std::process::exit(2);
        }
    };
    install_panic_hook();

    let buffer = match fs::read(&args.binary) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("cannot read {}: {}", args.binary, error);
            std::process::exit(2);
        }
    };
    let obj = match Object::parse(&buffer) {
        Ok(obj) => obj,
        Err(error) => {
            eprintln!("cannot parse {}: {}", args.binary, error);
            std::process::exit(2);
        }
    };
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => {
            eprintln!("not an ELF binary: {}", args.binary);
            std::process::exit(2);
        }
    };
    let image = Arc::new(memory_image_bytes(elf, &buffer));
    let image_name = args
        .binary
        .rsplit('/')
        .next()
        .unwrap_or("corpus")
        .to_string();
    let mut functions = discover_functions(elf);
    if functions.is_empty() {
        eprintln!("no functions discovered in {}", args.binary);
        std::process::exit(2);
    }
    // Deterministic selection: largest first, ties by address (bin_sweep
    // --max-funcs shape), then execute in address order.
    functions.sort_by(|a, b| {
        b.size
            .cmp(&a.size)
            .then(a.vaddr.cmp(&b.vaddr))
            .then(a.name.cmp(&b.name))
    });
    functions.truncate(args.max_funcs);
    functions.sort_by(|a, b| a.vaddr.cmp(&b.vaddr).then(a.name.cmp(&b.name)));
    // Drop skipped indexes (post-selection index space).
    let jobs: Vec<usize> = (0..functions.len())
        .filter(|idx| !args.skip.contains(idx))
        .collect();
    eprintln!(
        "[POC] corpus={} functions={} jobs={} workers={} modes={:?} skip={:?}",
        args.binary,
        functions.len(),
        jobs.len(),
        args.workers,
        args.modes,
        args.skip
    );
    fs::create_dir_all(&args.out_dir).ok();

    // Screening mode: serial-only, JSONL progress for an external watchdog.
    if args.screen {
        let mut out = fs::File::create(args.out_dir.join("screen.jsonl")).expect("screen file");
        for &idx in &jobs {
            let started = Instant::now();
            let outcome = decompile_one(&image, &image_name, &functions[idx], &functions, FactoryMode::Isolated);
            let record = serde_json::json!({
                "idx": idx,
                "name": functions[idx].name,
                "vaddr": functions[idx].vaddr,
                "fn_size": functions[idx].size,
                "signature": outcome_signature(&outcome),
                "wall_us": started.elapsed().as_micros(),
            });
            writeln!(out, "{}", record).ok();
            out.flush().ok();
        }
        eprintln!("[POC] screen complete: {}", args.out_dir.join("screen.jsonl").display());
        return;
    }

    // Warmup (smallest job, discarded): warms the .sla file cache and the
    // allocator so arm-to-arm comparisons are not dominated by first-touch.
    if let Some(&warm) = jobs.last() {
        eprintln!("[POC] warmup f{} {}", warm, functions[warm].name);
        let _ = decompile_one(&image, &image_name, &functions[warm], &functions, FactoryMode::Isolated);
    }

    let mut reports: Vec<ModeReport> = Vec::new();
    let mut gate_green = true;
    for mode in args.modes {
        let shared = Arc::new(SharedJob {
            image: Arc::clone(&image),
            image_name: image_name.clone(),
            functions: functions.clone(),
            mode,
        });
        // ---- serial arm (one big-stack thread) ----
        let serial_shared = Arc::clone(&shared);
        let serial_jobs = jobs.clone();
        let serial_thread = thread::Builder::new()
            .stack_size(STACK_BYTES)
            .name("serial".to_string())
            .spawn(move || run_serial(&serial_jobs, &serial_shared))
            .expect("spawn serial thread");
        let t_serial = Instant::now();
        let serial = serial_thread.join().expect("serial thread panicked");
        let serial_wall = t_serial.elapsed().as_micros();

        // ---- parallel arms (fresh worker threads each run) ----
        let par_shared = Arc::clone(&shared);
        let t_par1 = Instant::now();
        let par1 = run_parallel(&jobs, par_shared, args.workers).expect("spawn parallel workers");
        let par1_wall = t_par1.elapsed().as_micros();
        let par_shared = Arc::clone(&shared);
        let t_par2 = Instant::now();
        let par2 = run_parallel(&jobs, par_shared, args.workers).expect("spawn parallel workers");
        let par2_wall = t_par2.elapsed().as_micros();

        // ---- persist per-arm texts (audit surface) ----
        let mode_dir = args.out_dir.join(match mode {
            FactoryMode::Isolated => "isolated",
            FactoryMode::Shared => "shared",
        });
        write_text_dir(&mode_dir.join("serial"), "serial", &functions, &jobs, &serial);
        write_text_dir(&mode_dir.join("par1"), "par1", &functions, &jobs, &par1);
        write_text_dir(&mode_dir.join("par2"), "par2", &functions, &jobs, &par2);

        // ---- determinism matrix ----
        let mut stage_profile = StageProfile::default();
        let mut records = Vec::with_capacity(jobs.len());
        let mut ok_count = 0;
        let mut err_count = 0;
        let mut panic_count = 0;
        let mut serial_cpu = 0u128;
        let mut par1_cpu = 0u128;
        for (slot, &idx) in jobs.iter().enumerate() {
            let s = &serial[slot];
            let p1 = &par1[slot];
            let p2 = &par2[slot];
            let sig_s = outcome_signature(s);
            let sig_1 = outcome_signature(p1);
            let sig_2 = outcome_signature(p2);
            let cmp_sp1 = match (texts_equal(s, p1), sig_s == sig_1) {
                (Some(true), _) => "identical",
                (Some(false), _) => "TEXT-MISMATCH",
                (None, true) => "status-identical",
                (None, false) => "STATUS-MISMATCH",
            };
            let cmp_sp2 = match (texts_equal(s, p2), sig_s == sig_2) {
                (Some(true), _) => "identical",
                (Some(false), _) => "TEXT-MISMATCH",
                (None, true) => "status-identical",
                (None, false) => "STATUS-MISMATCH",
            };
            let cmp_12 = match (texts_equal(p1, p2), sig_1 == sig_2) {
                (Some(true), _) => "identical",
                (Some(false), _) => "TEXT-MISMATCH",
                (None, true) => "status-identical",
                (None, false) => "STATUS-MISMATCH",
            };
            if cmp_sp1 != "identical" && cmp_sp1 != "status-identical" {
                gate_green = false;
            }
            if cmp_sp2 != "identical" && cmp_sp2 != "status-identical" {
                gate_green = false;
            }
            if cmp_12 != "identical" && cmp_12 != "status-identical" {
                gate_green = false;
            }
            collect_stage(&mut stage_profile, 0, s);
            collect_stage(&mut stage_profile, 1, p1);
            if let Outcome::Ok { total_us, .. } = s {
                serial_cpu += total_us;
            }
            if let Outcome::Ok { total_us, .. } = p1 {
                par1_cpu += total_us;
            }
            match s {
                Outcome::Ok { .. } => ok_count += 1,
                Outcome::Err { .. } => err_count += 1,
                Outcome::Panic { .. } => panic_count += 1,
            }
            records.push(FuncRecord {
                idx,
                name: functions[idx].name.clone(),
                vaddr: functions[idx].vaddr,
                size: functions[idx].size,
                serial_sig: sig_s,
                par1_sig: sig_1,
                par2_sig: sig_2,
                serial_vs_par1: cmp_sp1.to_string(),
                serial_vs_par2: cmp_sp2.to_string(),
                par1_vs_par2: cmp_12.to_string(),
                serial_total_us: match s {
                    Outcome::Ok { total_us, .. } => Some(*total_us),
                    _ => None,
                },
                par1_total_us: match p1 {
                    Outcome::Ok { total_us, .. } => Some(*total_us),
                    _ => None,
                },
            });
        }
        let speedup = serial_wall as f64 / par1_wall.max(1) as f64;
        eprintln!(
            "[POC] mode={:?} jobs={} ok/err/panic={}/{}/{} serial={} par1={} par2={} speedup={:.2}x",
            mode,
            jobs.len(),
            ok_count,
            err_count,
            panic_count,
            fmt_us(serial_wall),
            fmt_us(par1_wall),
            fmt_us(par2_wall),
            speedup
        );
        reports.push(ModeReport {
            mode,
            workers: args.workers,
            jobs: jobs.len(),
            serial_wall_us: serial_wall,
            par1_wall_us: par1_wall,
            par2_wall_us: par2_wall,
            speedup,
            serial_cpu_us: serial_cpu,
            par1_cpu_us: par1_cpu,
            ok_functions: ok_count,
            err_functions: err_count,
            panic_functions: panic_count,
            matrix: records,
            stage_profile,
        });
    }

    let summary = serde_json::json!({
        "binary": args.binary,
        "workers": args.workers,
        "gate_green": gate_green,
        "reports": reports,
    });
    let summary_path = args.out_dir.join("matrix.json");
    fs::write(&summary_path, serde_json::to_string_pretty(&summary).expect("serialize summary"))
        .expect("write matrix.json");
    println!(
        "[POC] gate={} matrix={}",
        if gate_green { "GREEN" } else { "RED" },
        summary_path.display()
    );
    for report in &reports {
        println!(
            "[POC] mode={:?} speedup={:.2}x serial={} par1={} ({} workers)",
            report.mode,
            report.speedup,
            fmt_us(report.serial_wall_us),
            fmt_us(report.par1_wall_us),
            report.workers,
        );
    }
    if gate_green {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
