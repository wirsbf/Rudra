//! PHASE1-LAND lane (PAREVAL-PHASE1-LAND-0001): production in-process
//! multi-function thread-parallel decompilation driver.
//!
//! This is the productionized form of the PAREVAL PoC
//! (examples/pareval_poc.rs — same lane's measurement harness). The
//! contract is unchanged (docs/alignment_docs/
//! PARALLELIZATION_DESIGN_2026-09-26.md §2):
//!
//!   * Per-function decompile inputs are IDENTICAL to the bin_sweep /
//!     gen_decompile bare-native face (GENSMOKE-0001 verbatim: BFD
//!     function discovery, PT_LOAD image + import relocations, bare
//!     Architecture, full default action pipeline, PrintC pretty face).
//!   * Whole-function jobs are NEVER migrated between threads: each job's
//!     Architecture, Funcdata, SLEIGH lifter and Address space tags are
//!     created and consumed on one worker thread (the
//!     one-Architecture-per-worker discipline, SPACE-0001 — thread-local
//!     SPACE_TAG_TABLE cannot resolve cross-thread). Only
//!     `(vaddr, name, size)` goes in and `String` C text comes out.
//!   * A fresh Architecture (with its own commentdb) is built per
//!     function: reusing one across functions leaks warning comments
//!     between functions (design doc §1.3#3).
//!   * Workers get a 256MB stack (ActionGroup::perform deep recursion).
//!   * Dynamic queue (largest-first enqueue) for load balancing; results
//!     are re-ordered by function index so completion order can never
//!     leak into the output.
//!   * --jobs 1 degenerates to the serial shape (single worker thread,
//!     index order) — the parallel driver IS the serial driver at N=1.
//!
//! Output layout (deterministic, comparable function-by-function against
//! any serial run of the same face):
//!   <out-dir>/<run-name>/f<NNN>_<name>.c   one file per function,
//!                                           NNN = zero-padded function
//!                                           index (address-sorted order)
//!   <out-dir>/<run-name>/manifest.jsonl    per-function record:
//!                                           index/name/vaddr/size/status/
//!                                           bytes/md5/wall_us
//!   <out-dir>/<run-name>/run.json           run-level record: corpus,
//!                                           jobs, counts, wall_us, commit
//!
//! The determinism gate (tools/verify_parallel_determinism.sh) runs this
//! driver at --jobs 1 and --jobs N over the same corpus and requires
//! byte-identical per-function outputs ("parallel = observation-neutral",
//! design doc §2.2). Non-Ok outcomes (err/panic) are recorded with a
//! stable signature and compared as signatures.
//!
//! Usage (run from the repo root — sleigh_specs/ is CWD-relative):
//!   cargo run --profile fast-release --example parallel_decompile -- \
//!       examples/curl --jobs 8 --out-dir /dev/shm/rugra-tests/phaseland
//!   # full corpus (all discovered functions, no cap):
//!   cargo run --profile fast-release --example parallel_decompile -- \
//!       /tmp/sqlite3 --jobs 8 --max-funcs all
//!
//! No cross-thread timeout: a pathological function (PATHOSLOW-
//!      DIVCHAIN-0001 residual slow tail) holds its worker until it
//!      finishes. Hard per-function timeouts on such corpora remain the
//!      bin_sweep per-child-process form's job.

use goblin::Object;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
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
const DEFAULT_JOBS: usize = 1;

// ===========================================================================
// Function discovery + memory image — bin_sweep.rs / gen_decompile.rs /
// pareval_poc.rs verbatim (GENSMOKE-0001: the bare-native BFD face).
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
// Architecture build — bin_sweep build_architecture verbatim. The
// TypeFactory is the process-global shared_default() singleton, exactly
// the bin_sweep / gen_decompile production shape (PAREVAL-TF-SINGLETON-
// WIRING-0001 will re-own it per-Architecture later; until then the
// production driver must match the existing serial drivers' factory
// domain so parallel-vs-serial comparisons stay apples-to-apples).
// ===========================================================================

fn build_architecture(
    loader: Option<std::sync::Arc<dyn rudra::loadimage::LoadImage>>,
) -> Result<std::sync::Arc<rudra::arch::Architecture>, String> {
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
    let types = rudra::type_system::typefactory::TypeFactory::shared_default();
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
    Ok(Arc::new(arch))
}

// ===========================================================================
// Per-function decompile (bin_sweep run_one shape, returning the full
// printed C text). Everything here runs on the calling worker thread.
// ===========================================================================

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
enum Outcome {
    Ok {
        bytes_len: usize,
        text: String,
        wall_us: u128,
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

impl Outcome {
    /// Stable comparison signature: Ok compares by exact byte length (the
    /// gate does the full byte compare on disk), non-Ok by message.
    fn signature(&self) -> String {
        match self {
            Outcome::Ok { bytes_len, .. } => format!("ok:{}", bytes_len),
            Outcome::Err { stage, msg } => format!("err:{}:{}", stage, msg),
            Outcome::Panic { stage, msg, location } => {
                format!("panic:{}:{}:{}", stage, location, msg)
            }
        }
    }

    fn status_name(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "ok",
            Outcome::Err { .. } => "err",
            Outcome::Panic { .. } => "panic",
        }
    }
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
        eprintln!("[PAR-PANIC] {}", location);
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
) -> Outcome {
    LAST_PANIC_LOC.with(|slot| *slot.borrow_mut() = None);
    let started = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let loader: std::sync::Arc<dyn rudra::loadimage::LoadImage> =
            std::sync::Arc::new(rudra::loadimage::RawLoadImage::from_bytes(
                image_name,
                0,
                image.to_vec(),
            ));
        let arch = match build_architecture(Some(loader)) {
            Ok(arch) => arch,
            Err(msg) => {
                return Outcome::Err {
                    stage: "arch".to_string(),
                    msg,
                }
            }
        };

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
        // The full BFD function-symbol face (the ONLY symbol channel:
        // bare native face — no data symbols, no strings, no seeds).
        for function in functions {
            fd.add_symbol(function.vaddr, function.name.clone());
        }
        let mut sleigh = SleighLifter::new();
        if let Err(error) = sleigh.configure_x86_64(image, 0) {
            return Outcome::Err {
                stage: "sleigh".to_string(),
                msg: format!("failed to configure SLEIGH: {error}"),
            };
        }
        let empty_protos = std::collections::BTreeMap::new();
        // Oracle flow contract: followFlow(code:0, code:highest) — the
        // direct-runner range every production driver uses
        // (BINSWEEP-JTDEST-UNLINKED-0001).
        if let Err(error) = rudra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        {
            return Outcome::Err {
                stage: "flow".to_string(),
                msg: format!("flow generation failed for {}: {error}", target.name),
            };
        }

        let fd_arc = Arc::new(std::sync::RwLock::new(fd));
        if let Ok(mut guard) = fd_arc.write() {
            guard.set_self_ref(Arc::downgrade(&fd_arc));
        }

        let mut db = ActionDatabase::new();
        db.set_default_actions();
        {
            let Ok(mut fd_write) = fd_arc.write() else {
                return Outcome::Err {
                    stage: "actions".to_string(),
                    msg: "Funcdata write lock poisoned during analysis".to_string(),
                };
            };
            if let Err(error) = db.perform_action("decompile", &mut fd_write) {
                return Outcome::Err {
                    stage: "actions".to_string(),
                    msg: format!("action pipeline failed for {}: {error}", target.name),
                };
            }
        }

        let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
        printer.set_rpn_enabled(true);
        {
            let Ok(fd_read) = fd_arc.read() else {
                return Outcome::Err {
                    stage: "print".to_string(),
                    msg: "Funcdata read lock poisoned during printing".to_string(),
                };
            };
            printer.doc_function(&fd_read);
        }
        let output_buffer = printer
            .take_emit()
            .into_any()
            .downcast::<EmitPrettyPrint>()
            .expect("PrintC returned an unexpected emitter type");
        let c_code = output_buffer.get_output();
        let text = c_code.trim_end().to_string();
        Outcome::Ok {
            bytes_len: text.len(),
            text,
            wall_us: started.elapsed().as_micros(),
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
// Worker pool: K big-stack threads over a shared dynamic queue. Results
// are collected into completion-ordered slots carrying the job index and
// reordered by index after join, so completion order can never leak into
// the output. --jobs 1 uses the same code path (one worker, index
// order): the serial shape IS the degenerate parallel shape.
// ===========================================================================

struct SharedCorpus {
    image: Arc<Vec<u8>>,
    image_name: String,
    functions: Vec<GenFunction>,
}

fn run_pool(jobs: &[usize], shared: Arc<SharedCorpus>, workers: usize) -> std::io::Result<Vec<Outcome>> {
    let queue = Arc::new(Mutex::new(VecDeque::from(jobs.to_vec())));
    let results: Arc<Mutex<Vec<Option<(usize, Outcome)>>>> =
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
                );
                let mut guard = results.lock().unwrap();
                guard[slot] = Some((idx, outcome));
            })?;
        handles.push(handle);
    }
    for handle in handles {
        handle.join().expect("worker panicked outside catch_unwind");
    }
    let mut by_idx: Vec<(usize, Outcome)> = results
        .lock()
        .unwrap()
        .drain(..)
        .map(|slot| slot.expect("worker dropped a result"))
        .collect();
    by_idx.sort_by_key(|entry| entry.0);
    Ok(by_idx.into_iter().map(|entry| entry.1).collect())
}

// ===========================================================================
// Output: per-function C files + manifest, indexed by function position
// in the address-sorted selection (stable across runs of the same corpus
// and cap, and directly comparable run-to-run / serial-vs-parallel).
// ===========================================================================

fn md5_hex(data: &[u8]) -> String {
    // Minimal MD5 (RFC 1321) — the manifest digest column. Kept local to
    // avoid a new dependency; only used for evidence records, never for
    // the gate itself (the gate byte-compares the files).
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14,
        20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
        16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;
    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&a0.to_le_bytes());
    out.extend_from_slice(&b0.to_le_bytes());
    out.extend_from_slice(&c0.to_le_bytes());
    out.extend_from_slice(&d0.to_le_bytes());
    out.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// ===========================================================================
// Run-level typedef preamble extraction. PrintC guards the Ghidra-style
// typedef block behind a PROCESS-WIDE latch (printc.rs TYPEDEFS_EMITTED,
// "once per decompiled file" — in a multi-function single-process run the
// process IS the file), so exactly one function's printed text per run
// starts with this fixed block, and WHICH function carries it depends on
// print order (serial: first index; parallel: first completion). The
// block is a process artifact, not per-function output: the canonical
// gates normalize it away (compare_ghidra.py:109/141 — "the preamble is
// invisible to all four gates"). The production driver therefore strips
// the exact block from the per-function text and persists it ONCE per
// run as typedef_preamble.c, so per-function files are the pure,
// order-independent function documents and the determinism gate can
// byte-compare them directly.
//
// Byte-exact boundary: the preamble PROPER is 215 bytes ending with a
// single "\n" (its own closing tag_line). The "\n" that follows belongs
// to the FUNCTION document — docFunction's cc:2653 `emit->tagLine()`
// writes one leading newline for EVERY function (EmitPrettyPrint tagLine
// is an unconditional endl), carrier or not. Stripping 216 bytes would
// eat the carrier's own leading newline and make its text position-
// dependent again; stripping exactly the 215-byte preamble leaves every
// function's text uniformly "\n" + body in both arms. If an upstream
// printc edit changes the block, strip_prefix stops matching and the
// gate reports the byte diff — the constant then needs the same update.
// ===========================================================================

const TYPEDEF_PREAMBLE: &str = "\ntypedef unsigned char byte;\n\
     typedef unsigned long undefined;\n\
     typedef unsigned short undefined2;\n\
     typedef unsigned long undefined4;\n\
     typedef unsigned long long undefined8;\n\
     typedef struct { char _anon[256]; } _struct;\n";

fn strip_typedef_preamble(text: &str) -> (&str, bool) {
    match text.strip_prefix(TYPEDEF_PREAMBLE) {
        Some(rest) => (rest, true),
        None => (text, false),
    }
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Serialize)]
struct FuncRecord {
    idx: usize,
    name: String,
    vaddr: u64,
    size: usize,
    status: &'static str,
    signature: String,
    bytes: Option<usize>,
    md5: Option<String>,
    wall_us: Option<u128>,
}

#[derive(Serialize)]
struct RunRecord {
    binary: String,
    image_name: String,
    jobs: usize,
    workers: usize,
    discovered: usize,
    selected: usize,
    ok: usize,
    err: usize,
    panic: usize,
    wall_us: u128,
    commit: String,
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok().map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

// ===========================================================================
// CLI
// ===========================================================================

struct Args {
    binary: String,
    jobs: usize,
    max_funcs: usize, // usize::MAX = all
    skip: Vec<usize>,
    out_dir: PathBuf,
    run_name: Option<String>,
    quiet: bool,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        return Err(format!(
            "usage: {} <binary> [--jobs N] [--max-funcs N|all] [--skip 1,2] \
             [--out-dir DIR] [--name RUN] [--quiet]",
            argv.first().map(String::as_str).unwrap_or("parallel_decompile")
        ));
    }
    let mut args = Args {
        binary: argv[1].clone(),
        jobs: DEFAULT_JOBS,
        max_funcs: DEFAULT_MAX_FUNCS,
        skip: Vec::new(),
        out_dir: PathBuf::from("/dev/shm/rugra-tests/phaseland/parallel-out"),
        run_name: None,
        quiet: false,
    };
    if let Ok(jobs) = std::env::var("RUDRA_PAR_JOBS") {
        args.jobs = jobs.parse().map_err(|_| "RUDRA_PAR_JOBS must be a number")?;
    }
    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--jobs" | "-j" => {
                i += 1;
                args.jobs = argv
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--jobs needs a positive number")?;
                if args.jobs == 0 {
                    return Err("--jobs must be >= 1 (1 = serial shape)".to_string());
                }
            }
            "--max-funcs" => {
                i += 1;
                let raw = argv.get(i).ok_or("--max-funcs needs a value")?;
                args.max_funcs = if raw == "all" {
                    usize::MAX
                } else {
                    raw.parse().map_err(|_| "bad --max-funcs value")?
                };
            }
            "--skip" => {
                i += 1;
                let raw = argv.get(i).ok_or("--skip needs a list")?;
                args.skip = raw
                    .split(',')
                    .map(|v| v.parse().map_err(|_| "bad --skip entry".to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "--out-dir" => {
                i += 1;
                args.out_dir = PathBuf::from(argv.get(i).ok_or("--out-dir needs a path")?);
            }
            "--name" => {
                i += 1;
                args.run_name = Some(argv.get(i).ok_or("--name needs a value")?.clone());
            }
            "--quiet" => args.quiet = true,
            other => return Err(format!("unknown flag {}", other)),
        }
        i += 1;
    }
    Ok(args)
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
    let discovered = functions.len();
    // Deterministic selection: largest first, ties by address then name
    // (bin_sweep --max-funcs shape), then execute in address order.
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

    let run_name = args.run_name.clone().unwrap_or_else(|| {
        format!(
            "{}_j{}",
            image_name,
            args.jobs
        )
    });
    let out_dir = args.out_dir.join(&run_name);
    if let Err(error) = fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {}", out_dir.display(), error);
        std::process::exit(2);
    }

    eprintln!(
        "[PAR] corpus={} discovered={} selected={} jobs={} workers={} out={}",
        args.binary,
        discovered,
        functions.len(),
        jobs.len(),
        args.jobs,
        out_dir.display()
    );

    let shared = Arc::new(SharedCorpus {
        image: Arc::clone(&image),
        image_name: image_name.clone(),
        functions: functions.clone(),
    });

    let t_run = Instant::now();
    let outcomes = match run_pool(&jobs, Arc::clone(&shared), args.jobs) {
        Ok(outcomes) => outcomes,
        Err(error) => {
            eprintln!("worker pool failed: {}", error);
            std::process::exit(2);
        }
    };
    let run_wall = t_run.elapsed().as_micros();

    // Deterministic collection: write per-function files in job order,
    // one manifest line per function, run record last.
    let mut manifest = match fs::File::create(out_dir.join("manifest.jsonl")) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("cannot create manifest: {}", error);
            std::process::exit(2);
        }
    };
    let mut ok_count = 0;
    let mut err_count = 0;
    let mut panic_count = 0;
    let mut preamble_seen = false;
    for (slot, &idx) in jobs.iter().enumerate() {
        let outcome = &outcomes[slot];
        let function = &functions[idx];
        // Run-level preamble extraction: strip the fixed typedef block
        // (process-wide latch artifact) off the one function that carried
        // it this run; persist it once per run below.
        let (pure_text, had_preamble) = match outcome {
            Outcome::Ok { text, .. } => strip_typedef_preamble(text),
            _ => ("", false),
        };
        if had_preamble {
            preamble_seen = true;
        }
        // Signature must use the PURE text length: the raw length of the
        // preamble carrier differs by the 215-byte run artifact, which
        // would make the carrier's signature position-dependent.
        let signature = match outcome {
            Outcome::Ok { .. } => format!("ok:{}", pure_text.len()),
            _ => outcome.signature(),
        };
        let record = FuncRecord {
            idx,
            name: function.name.clone(),
            vaddr: function.vaddr,
            size: function.size,
            status: outcome.status_name(),
            signature,
            bytes: match outcome {
                Outcome::Ok { .. } => Some(pure_text.len()),
                _ => None,
            },
            md5: match outcome {
                Outcome::Ok { .. } => Some(md5_hex(pure_text.as_bytes())),
                _ => None,
            },
            wall_us: match outcome {
                Outcome::Ok { wall_us, .. } => Some(*wall_us),
                _ => None,
            },
        };
        if let Outcome::Ok { .. } = outcome {
            let file_name = format!(
                "f{:03}_{}.c",
                idx,
                sanitize_name(&function.name)
            );
            if let Err(error) = fs::write(out_dir.join(&file_name), pure_text) {
                eprintln!("cannot write {}: {}", file_name, error);
                std::process::exit(2);
            }
        }
        match outcome {
            Outcome::Ok { .. } => ok_count += 1,
            Outcome::Err { .. } => err_count += 1,
            Outcome::Panic { .. } => panic_count += 1,
        }
        let line = serde_json::to_string(&record).expect("serialize record");
        if let Err(error) = writeln!(manifest, "{}", line) {
            eprintln!("cannot append manifest: {}", error);
            std::process::exit(2);
        }
    }

    let run = RunRecord {
        binary: args.binary.clone(),
        image_name: image_name.clone(),
        jobs: jobs.len(),
        workers: args.jobs,
        discovered,
        selected: functions.len(),
        ok: ok_count,
        err: err_count,
        panic: panic_count,
        wall_us: run_wall,
        commit: git_commit(),
    };
    // Persist the run-level typedef preamble exactly once (it was stripped
    // from the one per-function text that carried it this run). Exactly one
    // function per process hits the TYPEDEFS_EMITTED latch; if that ever
    // fails to hold, say so loudly rather than writing an empty artifact.
    if preamble_seen {
        if let Err(error) = fs::write(out_dir.join("typedef_preamble.c"), TYPEDEF_PREAMBLE) {
            eprintln!("cannot write typedef_preamble.c: {}", error);
            std::process::exit(2);
        }
    } else if ok_count > 0 {
        eprintln!("[PAR] WARNING: no function carried the typedef preamble (latch invariant broken)");
    }
    if let Err(error) =
        fs::write(out_dir.join("run.json"), serde_json::to_string_pretty(&run).expect("serialize run"))
    {
        eprintln!("cannot write run.json: {}", error);
        std::process::exit(2);
    }

    if !args.quiet {
        println!(
            "[PAR] run={} jobs={} ok/err/panic={}/{}/{} wall={:.2}s workers={}",
            run_name,
            jobs.len(),
            ok_count,
            err_count,
            panic_count,
            run_wall as f64 / 1e6,
            args.jobs,
        );
    }
    // Exit code: 0 iff every function decompiled to Ok. The determinism
    // gate (verify_parallel_determinism.sh) additionally byte-compares
    // outputs between runs; non-Ok outcomes are a corpus property, not a
    // driver failure, but they still make the exit non-zero so callers
    // notice.
    if err_count == 0 && panic_count == 0 {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
