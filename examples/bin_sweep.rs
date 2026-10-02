//! PANICSWEEP lane (BINSWEEP-0001): generic robustness sweep driver for
//! arbitrary system ELF x86-64 binaries.
//!
//! Purpose: run Rugra's decompiler over a broad corpus of NEVER-TUNED
//! system binaries (network tools / compression / crypto / interpreters /
//! lib .so) with the bare native face — the same load + decompile shape
//! `gen_decompile` established (BFD function-symbol discovery, PT_LOAD
//! memory image with import relocations applied, bare Architecture, full
//! default action pipeline, PrintC pretty face) — and classify every
//! per-function outcome: ok / panic / error / timeout / crash.
//!
//! Process model: the parent enumerates each binary's functions, selects
//! the largest `--max-funcs` of them (stress-biased, deterministic), and
//! decompiles EVERY function in an isolated child process
//! (`--sweep-one <binary> <index>`), `timeout`-wrapped. A panic, hang, or
//! segfault in one function cannot take down the sweep; panics are caught
//! in-process (big-stack thread + catch-by-join + a panic hook that
//! records file:line) and reported as one sentinel JSON line on stdout.
//!
//! Parent-side knobs (CLI flag or env, flag wins):
//!   --manifest <file>     JSONL manifest: {"path":..., "category":...}
//!                         (extra fields are copied through to the record)
//!   --max-funcs <n>       per-binary function cap (default 24; largest
//!                         first, ties by address)
//!   --func-timeout <s>    per-function child timeout (default 30)
//!   --binary-budget <s>   per-binary wall budget (default 120; remaining
//!                         functions are honestly recorded budget-skipped)
//!   --jobs <n>            concurrent binaries (default 4)
//!   --out-dir <dir>       result directory (default /tmp/opencode/binsweep)
//!   --list-only           enumerate + write the plan, run nothing
//!   env RUGRA_SWEEP_MIRROR inert (historical): worker flow always uses
//!                         the direct-runner oracle range (0, u64::MAX) —
//!                         same semantics as gen_decompile after
//!                         BINSWEEP-JTDEST-UNLINKED-0001. Formerly
//!                         toggled the driver-bounded [entry, MAX) form.
//!
//! Outputs under --out-dir:
//!   functions.jsonl  one record per attempted function (ticket evidence)
//!   results.jsonl    one record per binary (scoreboard input)
//!   run.meta.json    knobs + commit + argv for reproducibility
//!   summary.json     aggregate counts + family distribution
//!   stderr/          full worker stderr for non-ok outcomes (forensics)
//!
//! Usage (run from the repo root — sleigh_specs/ is CWD-relative):
//!   cargo run --profile fast-release --example bin_sweep -- \
//!       --manifest /dev/shm/rugra-tests/panicsweep/manifest.jsonl \
//!       --out-dir /dev/shm/rugra-tests/panicsweep/run1

use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
const SENTINEL: &str = "##BINSWEEP##";
const DEFAULT_MAX_FUNCS: usize = 24;
const DEFAULT_FUNC_TIMEOUT_SECS: u64 = 30;
const DEFAULT_BINARY_BUDGET_SECS: u64 = 120;
const DEFAULT_JOBS: usize = 4;
const SWEEP_ONE_ARG: &str = "--sweep-one";
const MSG_CLIP: usize = 240;
const STDERR_TAIL_CLIP: usize = 400;

// ===========================================================================
// Function discovery + memory image + Architecture — the gen_decompile
// bare-face contract, verbatim (GENSMOKE-0001). Same input for every
// binary; this driver adds no corpus-specific channels.
// ===========================================================================

// RUGRA-GLUE: one discovered decompilable unit (address, name, size).
#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

// RUGRA-GLUE: BFD static/dynamic FUNC symbols + PLT JUMP_SLOT stubs,
// dedup by address, (offset, name) order (golden_dump_1204.cc shape).
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
// import relocations applied (curl worker PLTSTUB-THUNKRELRO-0001 image
// contract generalized to any ELF).
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

// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): locked x86-64
// address-space facts for the spec host.
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

// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): Translate::getUniqueStart
// (Translate::INJECT) for the locked x86-64 .sla.
const SPEC_UNIQUE_INJECT_BASE: u64 = 0x364_400;

// FUNCPROTO-MODEL-BIND-0001 (sweep-driver copy): language host for the
// driver-side compiler-spec parse.
struct SweepSpecHost {
    registers: HashMap<String, rudra::fspec::VarnodeData>,
}

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
        SPEC_UNIQUE_INJECT_BASE
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

// RUGRA-GLUE: bare Architecture — gen_decompile's build_architecture
// verbatim (archid, SLEIGH register_xref, commentdb, shared TypeFactory
// with the locked cspec data_organization, inject library + userops,
// pspec context/register decode, parse_compiler_config establishing
// defaultfp, loader-backed string manager).
// PERF-DUAL-SLEIGH-INIT-0001: also returns the register-catalog engine so
// run_one's lifter adopts it (SleighLifter::from_ctx) — the oracle's ONE
// translator per Architecture (sleigh_arch.cc:174 buildTranslator reuse),
// not a second x86-64.sla deserialization.
fn build_architecture(
    loader: Option<std::sync::Arc<dyn rudra::loadimage::LoadImage>>,
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
        .map_err(|_| "compiler spec element lock poisoned".to_string())?
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
    let mut inject_lib = rudra::pcodeinject::PcodeInjectLibrary::new(SPEC_UNIQUE_INJECT_BASE);
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


// RUGRA-GLUE: hermetic single-function decompile (gen run_one shape) that
// RETURNS the produced C text length instead of printing it, so the sweep
// worker can report over the sentinel channel.
fn run_one(binary_path: &str, functions: &[GenFunction], index: usize) -> Result<usize, String> {
    use std::sync::Arc;
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("not an ELF binary".to_string()),
    };
    let target = &functions[index];
    let image = memory_image_bytes(elf, &buffer);

    let loader: Arc<dyn rudra::loadimage::LoadImage> = Arc::new(
        rudra::loadimage::RawLoadImage::from_bytes(
            binary_path.rsplit('/').next().unwrap_or("sweep"),
            0,
            image.clone(),
        ),
    );
    let (arch, sleigh_ctx) = build_architecture(Some(loader))?;

    let func_size =
        i32::try_from(target.size).map_err(|_| format!("function {} is too large", target.name))?;
    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
    fd.set_arch(arch);
    // The full BFD function-symbol face (the ONLY symbol channel: bare
    // native face — no data symbols, no strings, no seeds).
    for function in functions {
        fd.add_symbol(function.vaddr, function.name.clone());
    }

    // PERF-DUAL-SLEIGH-INIT-0001: adopt the register-catalog engine
    // (single .sla load per child; oracle sleigh_arch.cc:174 buildTranslator
    // keeps one translator per languageindex). The catalog leg was
    // read-only, so configure_x86_64 sees fresh-engine state.
    let mut sleigh = SleighLifter::from_ctx(sleigh_ctx);
    sleigh
        .configure_x86_64(&image, 0)
        .map_err(|error| format!("failed to configure SLEIGH: {error}"))?;

    let empty_protos = std::collections::BTreeMap::new();
    // Full-space flow range (0, u64::MAX) — the direct-runner oracle
    // contract (followFlow(code:0, code:highest), funcdata.cc:163
    // startProcessing). The historical bounded [entry, MAX) form rejected
    // far-away jumptable case targets as out-of-bounds
    // (BINSWEEP-JTDEST-UNLINKED-0001); RUGRA_SWEEP_MIRROR is now an
    // inert marker (still forwarded to children and recorded).
    rudra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        .map_err(|error| format!("flow generation failed for {}: {error}", target.name))?;

    let fd_arc = Arc::new(std::sync::RwLock::new(fd));
    fd_arc
        .write()
        .map_err(|_| "Funcdata write lock poisoned".to_string())?
        .set_self_ref(Arc::downgrade(&fd_arc));

    let mut db = ActionDatabase::new();
    db.set_default_actions();
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during analysis".to_string())?;
        db.perform_action("decompile", &mut fd_write)
            .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
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
    Ok(c_code.trim_end().len())
}

// ===========================================================================
// Sweep records + worker protocol
// ===========================================================================

// RUGRA-GLUE: worker -> parent result over the sentinel line.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct WorkerResult {
    status: String, // "ok" | "panic" | "error"
    ms: u64,
    c_bytes: usize,
    panic_loc: String,
    panic_msg: String,
    err_msg: String,
}

// RUGRA-GLUE: one attempted function (functions.jsonl record).
#[derive(Clone, Debug, Serialize)]
struct FuncRecord {
    binary: String,
    category: String,
    func_index: usize,
    name: String,
    vaddr: u64,
    size: usize,
    status: String, // ok|panic|error|timeout|crash|budget-skipped|worker-failure
    ms: u64,
    wall_ms: u64,
    family: String,
    panic_loc: String,
    panic_msg: String,
    err_msg: String,
    stderr_tail: String,
    c_bytes: usize,
    attempt: u8,
    stdout_noise: usize,
}

// RUGRA-GLUE: one swept binary (results.jsonl record).
#[derive(Clone, Debug, Serialize)]
struct BinaryRecord {
    path: String,
    category: String,
    sha256: String,
    manifest_sha256: String,
    elf_class: u8,
    machine: u16,
    et_type: u16,
    et_type_str: String,
    has_interp: bool,
    symtab_funcs: usize,
    dynsym_funcs: usize,
    plt_stubs: usize,
    discovered: usize,
    selected: usize,
    attempted: usize,
    ok: usize,
    panic: usize,
    error: usize,
    timeout: usize,
    crash: usize,
    budget_skipped: usize,
    worker_failure: usize,
    families: Vec<(String, usize)>,
    wall_ms: u64,
    status: String, // swept|skipped-not-elf|skipped-arch|no-functions|read-error|parse-error
    note: String,
}

// RUGRA-GLUE: manifest row (path + category + any extra provenance fields
// copied through, e.g. sha256 for cross-verification).
#[derive(Clone, Debug, Deserialize)]
struct ManifestRow {
    path: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    sha256: String,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

// RUGRA-GLUE: normalizes a panic location to the bare `file.rs:line` form
// (panic! locations carry the crate-relative `src/` prefix).
fn normalize_loc(loc: &str) -> &str {
    loc.strip_prefix("src/").unwrap_or(loc)
}

// RUGRA-GLUE: classifies one function outcome into a family key. "K:" =
// known ticket (corpus evidence for an existing TODO entry), "NEW:" =
// unregistered family (needs a ticket), "E:" = error-path family,
// "T:"/"C:" = timeout / crash classes.
fn classify_family(status: &str, loc: &str, msg: &str) -> String {
    let head: String = msg.chars().take(72).collect();
    let loc = normalize_loc(loc);
    match status {
        "panic" => {
            if loc == "prettyprint.rs:3946" || msg.contains("indentstack") {
                // SQATTR-PENDINGBRACE-IDENTITY-0001 (PRETTYFLUSH family)
                "K:PRETTYFLUSH-3946".to_string()
            } else if msg.contains("Forced merge caused intersection")
                || loc.starts_with("merge.rs:")
            {
                // GEN4-SQ-MERGE-FORCEDINTERSECT-0001
                "K:MERGE-FORCEDINTERSECT".to_string()
            } else if msg.contains("block_insert_op") || loc == "funcdata.rs:4984" {
                // GEN4-SQ-DBLHI-UNINSERT-0001 (fixed; regression signal)
                "K:DBLHI-UNINSERT-4984".to_string()
            } else if !loc.is_empty() {
                format!("NEW:PANIC:{loc}")
            } else {
                format!("NEW:PANIC:MSG:{head}")
            }
        }
        "error" => {
            if msg.contains("NULL local type") {
                // GEN4-SQ-NULLLOCALTYPE-0001
                "K:NULLLOCALTYPE".to_string()
            } else if msg.contains("flow generation failed") {
                "E:FLOWFAIL".to_string()
            } else if msg.contains("action pipeline failed") {
                let inner: String = msg
                    .split("action pipeline failed")
                    .nth(1)
                    .unwrap_or("")
                    .chars()
                    .take(56)
                    .collect();
                format!("E:PIPELINE{inner}")
            } else if !msg.is_empty() {
                format!("E:ERR:{head}")
            } else {
                "E:ERR-EMPTY".to_string()
            }
        }
        "timeout" => "T:TIMEOUT".to_string(),
        "crash" => {
            if msg.contains("has overflowed its stack") || msg.contains("stack overflow") {
                "C:STACKOVERFLOW".to_string()
            } else {
                format!("C:CRASH:{head}")
            }
        }
        "worker-failure" => "C:WORKER-FAILURE".to_string(),
        _ => String::new(),
    }
}

// RUGRA-GLUE: clips a diagnostic string to a bounded length.
fn clip(text: &str, limit: usize) -> String {
    let mut out: String = text.chars().take(limit).collect();
    if out.len() < text.len() {
        out.push('…');
    }
    out.replace('\n', "\\n")
}

// RUGRA-GLUE: last non-empty stderr lines for the record tail.
fn stderr_tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    let take: Vec<&str> = lines.iter().rev().take(4).rev().cloned().collect();
    clip(&take.join(" ⏎ "), STDERR_TAIL_CLIP)
}

fn payload_str(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

// RUGRA-GLUE: ELF header facts straight from the first 64 bytes (class,
// endian, e_type, e_machine) — no parser API surface involved.
#[derive(Default)]
struct ElfFacts {
    elf_class: u8,
    little_endian: bool,
    et_type: u16,
    machine: u16,
}

fn elf_facts(buffer: &[u8]) -> Option<ElfFacts> {
    if buffer.len() < 20 || &buffer[0..4] != b"\x7fELF" {
        return None;
    }
    Some(ElfFacts {
        elf_class: buffer[4],
        little_endian: buffer[5] == 1,
        et_type: u16::from_le_bytes([buffer[16], buffer[17]]),
        machine: u16::from_le_bytes([buffer[18], buffer[19]]),
    })
}

fn et_type_str(et_type: u16) -> String {
    match et_type {
        1 => "REL".to_string(),
        2 => "EXEC".to_string(),
        3 => "DYN".to_string(),
        4 => "CORE".to_string(),
        other => format!("0x{other:x}"),
    }
}

// RUGRA-GLUE: sha256 via coreutils (the sweep already shells out to
// `timeout`; one more deterministic subprocess keeps the driver
// dependency-free).
fn sha256_of(path: &str) -> String {
    Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .map(|digest| digest.to_string())
        })
        .unwrap_or_default()
}

// RUGRA-GLUE: sanitized file name fragment for stderr archives.
fn name_fragment(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("bin").replace('/', "_")
}

// ===========================================================================
// Worker mode: hermetic one-function decompile with panic capture.
// ===========================================================================

fn sweep_one(binary_path: &str, index: usize) -> i32 {
    let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    let hook_slot = captured.clone();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let msg = payload_str(info.payload());
        eprintln!("[SWEEP] panic at {}: {}", loc, clip(&msg, MSG_CLIP));
        let mut slot = match hook_slot.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot.is_none() {
            *slot = Some((loc, msg));
        }
    }));

    let start = Instant::now();
    let bp = binary_path.to_string();
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            let functions = match load_functions(&bp) {
                Ok(functions) => functions,
                Err(error) => return (usize::MAX, Err(format!("discovery failed: {error}"))),
            };
            if index >= functions.len() {
                return (usize::MAX, Err(format!("index {index} out of range")));
            }
            let result = run_one(&bp, &functions, index);
            (index, result)
        });
    let joined = match handle {
        Ok(handle) => handle.join(),
        Err(error) => {
            eprintln!("[SWEEP] failed to spawn stack thread: {error}");
            return 72;
        }
    };
    let ms = start.elapsed().as_millis() as u64;
    let worker_result = match joined {
        Ok((_, Ok(c_bytes))) => WorkerResult {
            status: "ok".to_string(),
            ms,
            c_bytes,
            ..Default::default()
        },
        Ok((_, Err(err_msg))) => WorkerResult {
            status: "error".to_string(),
            ms,
            err_msg: clip(&err_msg, MSG_CLIP),
            ..Default::default()
        },
        Err(payload) => {
            let (loc, msg) = captured
                .lock()
                .ok()
                .and_then(|mut slot| slot.take())
                .unwrap_or_else(|| (String::new(), payload_str(&payload)));
            WorkerResult {
                status: "panic".to_string(),
                ms,
                panic_loc: loc,
                panic_msg: clip(&msg, MSG_CLIP),
                ..Default::default()
            }
        }
    };
    println!(
        "{} {}",
        SENTINEL,
        serde_json::to_string(&worker_result).unwrap_or_else(|_| "{}".to_string())
    );
    0
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

// ===========================================================================
// Parent mode: the sweep orchestrator.
// ===========================================================================

struct SweepConfig {
    max_funcs: usize,
    func_timeout: Duration,
    binary_budget: Duration,
    jobs: usize,
    list_only: bool,
    mirror: bool,
}

struct SharedOutputs {
    functions: Mutex<std::io::BufWriter<fs::File>>,
    results: Mutex<std::io::BufWriter<fs::File>>,
    stderr_dir: String,
}

// RUGRA-GLUE: one spawn attempt outcome for a single function.
struct SpawnOutcome {
    status: String,
    worker: Option<WorkerResult>,
    stderr: Vec<u8>,
    noise: usize,
}

fn spawn_one_function(
    exe: &str,
    path: &str,
    index: usize,
    func_timeout: Duration,
    mirror: bool,
) -> Result<SpawnOutcome, String> {
    let mut command = Command::new("timeout");
    command
        .arg("-k")
        .arg("10s")
        .arg(format!("{}s", func_timeout.as_secs().max(1)))
        .arg(exe)
        .arg(SWEEP_ONE_ARG)
        .arg(path)
        .arg(index.to_string());
    if mirror {
        command.env("RUGRA_SWEEP_MIRROR", "1");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().map_err(|error| format!("spawn failed: {error}"))?;
    let stdout_text = String::from_utf8_lossy(&output.stdout).to_string();
    let sentinel_line = stdout_text
        .lines()
        .find(|line| line.starts_with(SENTINEL));
    let noise = stdout_text
        .lines()
        .filter(|line| !line.starts_with(SENTINEL) && !line.trim().is_empty())
        .count();
    let worker = sentinel_line.and_then(|line| {
        serde_json::from_str::<WorkerResult>(line.trim_start_matches(SENTINEL).trim()).ok()
    });
    let status = if let Some(worker) = worker.as_ref() {
        worker.status.clone()
    } else if output.status.code() == Some(124) || output.status.code() == Some(137) {
        "timeout".to_string()
    } else if let Some(signal) = output.status.signal() {
        format!("crash:{signal}")
    } else {
        String::new()
    };
    if status.is_empty() {
        return Ok(SpawnOutcome {
            status: "worker-failure".to_string(),
            worker: None,
            stderr: output.stderr,
            noise,
        });
    }
    Ok(SpawnOutcome {
        status,
        worker,
        stderr: output.stderr,
        noise,
    })
}

// RUGRA-GLUE: one binary's whole sweep; returns the per-binary record and
// appends per-function records to the shared outputs.
fn sweep_binary(
    exe: &str,
    row: &ManifestRow,
    config: &SweepConfig,
    outputs: &SharedOutputs,
) -> BinaryRecord {
    let started = Instant::now();
    let mut record = BinaryRecord {
        path: row.path.clone(),
        category: row.category.clone(),
        sha256: String::new(),
        manifest_sha256: row.sha256.clone(),
        elf_class: 0,
        machine: 0,
        et_type: 0,
        et_type_str: String::new(),
        has_interp: false,
        symtab_funcs: 0,
        dynsym_funcs: 0,
        plt_stubs: 0,
        discovered: 0,
        selected: 0,
        attempted: 0,
        ok: 0,
        panic: 0,
        error: 0,
        timeout: 0,
        crash: 0,
        budget_skipped: 0,
        worker_failure: 0,
        families: Vec::new(),
        wall_ms: 0,
        status: "swept".to_string(),
        note: String::new(),
    };
    let buffer = match fs::read(&row.path) {
        Ok(buffer) => buffer,
        Err(error) => {
            record.status = "read-error".to_string();
            record.note = clip(&error.to_string(), 120);
            record.wall_ms = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    let Some(facts) = elf_facts(&buffer) else {
        record.status = "skipped-not-elf".to_string();
        record.wall_ms = started.elapsed().as_millis() as u64;
        return record;
    };
    record.sha256 = sha256_of(&row.path);
    if !row.sha256.is_empty() && row.sha256 != record.sha256 {
        record.note = format!(
            "sha256 mismatch vs manifest ({} != {})",
            record.sha256, row.sha256
        );
    }
    record.elf_class = facts.elf_class;
    record.machine = facts.machine;
    record.et_type = facts.et_type;
    record.et_type_str = et_type_str(facts.et_type);
    if facts.elf_class != 2 {
        record.status = "skipped-arch".to_string();
        record.note = format!("ELF class {} (not 64-bit)", facts.elf_class);
        record.wall_ms = started.elapsed().as_millis() as u64;
        return record;
    }
    if facts.machine != 0x3e {
        record.status = "skipped-arch".to_string();
        record.note = format!("e_machine 0x{:x} (not x86-64)", facts.machine);
        record.wall_ms = started.elapsed().as_millis() as u64;
        return record;
    }
    let obj = match Object::parse(&buffer) {
        Ok(obj) => obj,
        Err(error) => {
            record.status = "parse-error".to_string();
            record.note = clip(&error.to_string(), 120);
            record.wall_ms = started.elapsed().as_millis() as u64;
            return record;
        }
    };
    let Object::Elf(elf) = &obj else {
        record.status = "skipped-not-elf".to_string();
        record.wall_ms = started.elapsed().as_millis() as u64;
        return record;
    };
    record.has_interp = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == 3 /* PT_INTERP */);
    record.symtab_funcs = elf
        .syms
        .iter()
        .filter(|sym| sym.st_shndx != 0 && sym.is_function())
        .count();
    record.dynsym_funcs = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_shndx != 0 && sym.is_function())
        .count();
    record.plt_stubs = elf
        .pltrelocs
        .iter()
        .filter(|reloc| reloc.r_type == R_X86_64_JUMP_SLOT)
        .count();
    let functions = discover_functions(elf);
    record.discovered = functions.len();
    if functions.is_empty() {
        record.status = "no-functions".to_string();
        record.wall_ms = started.elapsed().as_millis() as u64;
        return record;
    }

    // Largest-first selection (ties by address), then address order for
    // stable indices.
    let mut order: Vec<usize> = (0..functions.len()).collect();
    order.sort_by(|&a, &b| {
        functions[b]
            .size
            .cmp(&functions[a].size)
            .then_with(|| functions[a].vaddr.cmp(&functions[b].vaddr))
    });
    let mut chosen: Vec<usize> = order.into_iter().take(config.max_funcs).collect();
    chosen.sort();
    record.selected = chosen.len();

    let mut family_counts: HashMap<String, usize> = HashMap::new();
    let mut func_records: Vec<FuncRecord> = Vec::new();
    for &index in &chosen {
        let elapsed = started.elapsed();
        let mut func_record = FuncRecord {
            binary: row.path.clone(),
            category: row.category.clone(),
            func_index: index,
            name: functions[index].name.clone(),
            vaddr: functions[index].vaddr,
            size: functions[index].size,
            status: String::new(),
            ms: 0,
            wall_ms: 0,
            family: String::new(),
            panic_loc: String::new(),
            panic_msg: String::new(),
            err_msg: String::new(),
            stderr_tail: String::new(),
            c_bytes: 0,
            attempt: 0,
            stdout_noise: 0,
        };
        if config.list_only {
            func_record.status = "planned".to_string();
            func_records.push(func_record);
            continue;
        }
        if elapsed + Duration::from_secs(3) > config.binary_budget {
            func_record.status = "budget-skipped".to_string();
            record.budget_skipped += 1;
            func_records.push(func_record);
            continue;
        }
        let spawn_started = Instant::now();
        let mut outcome = spawn_one_function(exe, &row.path, index, config.func_timeout, config.mirror);
        let mut attempt: u8 = 1;
        if let Ok(first) = &outcome {
            if first.status == "worker-failure" {
                // Multi-lane discipline: worker-failure retried once before
                // attribution (transient OOM/spawn flakes vs real defect).
                attempt = 2;
                outcome = spawn_one_function(exe, &row.path, index, config.func_timeout, config.mirror);
            }
        }
        func_record.attempt = attempt;
        func_record.wall_ms = spawn_started.elapsed().as_millis() as u64;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                func_record.status = "worker-failure".to_string();
                func_record.err_msg = clip(&error, MSG_CLIP);
                record.worker_failure += 1;
                family_counts
                    .entry("C:WORKER-FAILURE".to_string())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
                func_records.push(func_record);
                continue;
            }
        };
        let status_class = if outcome.status.starts_with("crash:") {
            "crash"
        } else {
            outcome.status.as_str()
        };
        func_record.status = status_class.to_string();
        let worker = outcome.worker.clone();
        func_record.stdout_noise = outcome.noise;
        let signal_note = outcome
            .status
            .strip_prefix("crash:")
            .map(|signal| format!("signal {signal}; "))
            .unwrap_or_default();
        match (&worker, status_class) {
            (Some(result), "ok") => {
                func_record.ms = result.ms;
                func_record.c_bytes = result.c_bytes;
                record.ok += 1;
            }
            (Some(result), "panic") => {
                func_record.ms = result.ms;
                func_record.panic_loc = result.panic_loc.clone();
                func_record.panic_msg = result.panic_msg.clone();
                record.panic += 1;
            }
            (Some(result), "error") => {
                func_record.ms = result.ms;
                func_record.err_msg = result.err_msg.clone();
                record.error += 1;
            }
            (_, "timeout") => {
                record.timeout += 1;
            }
            (_, "crash") => {
                func_record.err_msg = clip(
                    &(signal_note + &String::from_utf8_lossy(&outcome.stderr)),
                    MSG_CLIP,
                );
                record.crash += 1;
            }
            (_, "worker-failure") => {
                func_record.err_msg = clip(
                    &(signal_note + &String::from_utf8_lossy(&outcome.stderr)),
                    MSG_CLIP,
                );
                record.worker_failure += 1;
            }
            _ => {}
        }
        let classify_source = if status_class == "panic" {
            (
                "panic",
                worker
                    .as_ref()
                    .map(|result| result.panic_loc.clone())
                    .unwrap_or_default(),
                worker
                    .as_ref()
                    .map(|result| result.panic_msg.clone())
                    .unwrap_or_default(),
            )
        } else if status_class == "error" {
            (
                "error",
                String::new(),
                worker
                    .as_ref()
                    .map(|result| result.err_msg.clone())
                    .unwrap_or_default(),
            )
        } else if status_class == "crash" {
            (
                "crash",
                String::new(),
                String::from_utf8_lossy(&outcome.stderr).to_string(),
            )
        } else {
            (status_class, String::new(), String::new())
        };
        func_record.family = classify_family(classify_source.0, &classify_source.1, &classify_source.2);
        if !func_record.family.is_empty() {
            family_counts
                .entry(func_record.family.clone())
                .and_modify(|count| *count += 1)
                .or_insert(1);
        }
        func_record.stderr_tail = stderr_tail(&outcome.stderr);
        // Forensic stderr archive for every non-ok outcome.
        if status_class != "ok" && !config.list_only {
            let file_name = format!(
                "{}__{:03}.log",
                name_fragment(&row.path),
                index
            );
            let _ = fs::write(
                Path::new(&outputs.stderr_dir).join(file_name),
                &outcome.stderr,
            );
        }
        func_records.push(func_record);
    }

    for func_record in &func_records {
        if let Ok(mut writer) = outputs.functions.lock() {
            let _ = writeln!(
                writer,
                "{}",
                serde_json::to_string(func_record).unwrap_or_default()
            );
        }
    }
    let mut families: Vec<(String, usize)> = family_counts.into_iter().collect();
    families.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    record.families = families;
    record.attempted = func_records
        .iter()
        .filter(|func_record| func_record.status != "planned")
        .count();
    record.wall_ms = started.elapsed().as_millis() as u64;
    record
}

// RUGRA-GLUE: numeric env knob with CLI override.
fn knob(env_key: &str, flag_value: Option<&str>, default: u64) -> u64 {
    flag_value
        .and_then(|value| value.parse().ok())
        .or_else(|| {
            std::env::var(env_key)
                .ok()
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(default)
}

// RUGRA-GLUE: flags that consume one value argument.
const VALUE_FLAGS: [&str; 6] = [
    "--manifest",
    "--out-dir",
    "--max-funcs",
    "--func-timeout",
    "--binary-budget",
    "--jobs",
];

// RUGRA-GLUE: positional binaries (skipping the program name, flags, and
// each value-taking flag's consumed argument).
fn positional_paths(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if VALUE_FLAGS.contains(&arg.as_str()) {
            index += 2; // flag + its value
            continue;
        }
        if arg.starts_with("--") {
            index += 1;
            continue;
        }
        out.push(arg.clone());
        index += 1;
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: {} --manifest <manifest.jsonl> [binaries...] [--max-funcs N] [--func-timeout S] \
             [--binary-budget S] [--jobs N] [--out-dir DIR] [--list-only]",
            args[0]
        );
        std::process::exit(1);
    }

    // Worker mode: --sweep-one <binary> <index>
    if let Some(position) = args.iter().position(|arg| arg == SWEEP_ONE_ARG) {
        let binary_path = args[position + 1].clone();
        let index: usize = args[position + 2].parse().unwrap_or(usize::MAX);
        std::process::exit(sweep_one(&binary_path, index));
    }

    let flag_value = |flag: &str| -> Option<String> {
        args.iter().position(|arg| arg == flag).map(|position| {
            args.get(position + 1)
                .cloned()
                .unwrap_or_default()
        })
    };
    let out_dir = flag_value("--out-dir").unwrap_or_else(|| "/tmp/opencode/binsweep".to_string());
    let config = SweepConfig {
        max_funcs: knob("BINSWEEP_MAX_FUNCS", flag_value("--max-funcs").as_deref(), DEFAULT_MAX_FUNCS as u64)
            as usize,
        func_timeout: Duration::from_secs(knob(
            "BINSWEEP_FUNC_TIMEOUT",
            flag_value("--func-timeout").as_deref(),
            DEFAULT_FUNC_TIMEOUT_SECS,
        )),
        binary_budget: Duration::from_secs(knob(
            "BINSWEEP_BINARY_BUDGET",
            flag_value("--binary-budget").as_deref(),
            DEFAULT_BINARY_BUDGET_SECS,
        )),
        jobs: knob("BINSWEEP_JOBS", flag_value("--jobs").as_deref(), DEFAULT_JOBS as u64) as usize,
        list_only: args.iter().any(|arg| arg == "--list-only"),
        mirror: std::env::var("RUGRA_SWEEP_MIRROR").is_ok(),
    };

    // Manifest + ad-hoc positional binaries.
    let mut rows: Vec<ManifestRow> = Vec::new();
    if let Some(manifest_path) = flag_value("--manifest") {
        let text = fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
            eprintln!("[SWEEP] cannot read manifest {manifest_path}: {error}");
            String::new()
        });
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match serde_json::from_str::<ManifestRow>(line) {
                Ok(row) => rows.push(row),
                Err(error) => eprintln!("[SWEEP] manifest line skipped: {error}"),
            }
        }
    }
    for positional in positional_paths(&args) {
        if rows.iter().any(|row| row.path == positional) {
            continue;
        }
        rows.push(ManifestRow {
            path: positional.clone(),
            category: "adhoc".to_string(),
            sha256: String::new(),
            extra: HashMap::new(),
        });
    }
    if rows.is_empty() {
        eprintln!("[SWEEP] no binaries to sweep (empty manifest and no positional paths)");
        std::process::exit(1);
    }

    fs::create_dir_all(&out_dir).expect("create out-dir");
    let stderr_dir = format!("{out_dir}/stderr");
    fs::create_dir_all(&stderr_dir).expect("create stderr dir");
    let functions_file = fs::File::create(format!("{out_dir}/functions.jsonl")).expect("functions.jsonl");
    let results_file = fs::File::create(format!("{out_dir}/results.jsonl")).expect("results.jsonl");
    let outputs = Arc::new(SharedOutputs {
        functions: Mutex::new(std::io::BufWriter::new(functions_file)),
        results: Mutex::new(std::io::BufWriter::new(results_file)),
        stderr_dir,
    });

    let exe = std::env::current_exe().expect("current_exe").to_string_lossy().to_string();
    let commit = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let meta = serde_json::json!({
        "driver": "examples/bin_sweep.rs",
        "commit": commit,
        "argv": args,
        "max_funcs": config.max_funcs,
        "func_timeout_secs": config.func_timeout.as_secs(),
        "binary_budget_secs": config.binary_budget.as_secs(),
        "jobs": config.jobs,
        "mirror": config.mirror,
        "binaries": rows.len(),
        "started": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    });
    fs::write(
        format!("{out_dir}/run.meta.json"),
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    )
    .expect("run.meta.json");

    eprintln!(
        "[SWEEP] {} binaries | max_funcs={} func_timeout={}s budget={}s jobs={} out={}",
        rows.len(),
        config.max_funcs,
        config.func_timeout.as_secs(),
        config.binary_budget.as_secs(),
        config.jobs,
        out_dir
    );

    // Simple shared work queue over binaries.
    let queue: Arc<Mutex<std::collections::VecDeque<usize>>> =
        Arc::new(Mutex::new((0..rows.len()).collect()));
    let rows = Arc::new(rows);
    let config = Arc::new(config);
    let mut handles = Vec::new();
    for _ in 0..config.jobs.max(1) {
        let queue = Arc::clone(&queue);
        let rows = Arc::clone(&rows);
        let config = Arc::clone(&config);
        let outputs = Arc::clone(&outputs);
        let exe = exe.clone();
        handles.push(std::thread::spawn(move || loop {
            let next = {
                let mut queue = match queue.lock() {
                    Ok(queue) => queue,
                    Err(poisoned) => poisoned.into_inner(),
                };
                queue.pop_front()
            };
            let Some(index) = next else { break };
            let record = sweep_binary(&exe, &rows[index], &config, &outputs);
            eprintln!(
                "[SWEEP] {:>3}/{} {} [{}] ok={} panic={} err={} to={} crash={} skip={} wf={} ({}ms)",
                index + 1,
                rows.len(),
                record.path,
                record.status,
                record.ok,
                record.panic,
                record.error,
                record.timeout,
                record.crash,
                record.budget_skipped,
                record.worker_failure,
                record.wall_ms
            );
            if let Ok(mut writer) = outputs.results.lock() {
                let _ = writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&record).unwrap_or_default()
                );
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    let mut flush_failed = false;
    for writer_lock in [&outputs.functions, &outputs.results] {
        if let Ok(mut writer) = writer_lock.lock() {
            if let Err(error) = writer.flush() {
                // ENOSPC and friends must be loud: a silently truncated
                // JSONL corrupts every downstream aggregate.
                eprintln!("[SWEEP] output flush FAILED: {error}");
                flush_failed = true;
            }
        }
    }
    if flush_failed {
        eprintln!("[SWEEP] aborting before summary aggregation (outputs incomplete)");
        std::process::exit(101);
    }

    // Aggregate summary from functions.jsonl (single source of truth).
    let mut status_counts: HashMap<String, usize> = HashMap::new();
    let mut family_counts: HashMap<String, usize> = HashMap::new();
    let mut family_binaries: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
    let functions_text = fs::read_to_string(format!("{out_dir}/functions.jsonl"))
        .unwrap_or_default();
    for line in functions_text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status != "planned" && !status.is_empty() {
            *status_counts.entry(status.to_string()).or_insert(0) += 1;
        }
        if let Some(family) = value.get("family").and_then(|v| v.as_str()) {
            if !family.is_empty() {
                *family_counts.entry(family.to_string()).or_insert(0) += 1;
                if let Some(binary) = value.get("binary").and_then(|v| v.as_str()) {
                    family_binaries
                        .entry(family.to_string())
                        .or_default()
                        .insert(binary.to_string());
                }
            }
        }
    }
    let results_text = fs::read_to_string(format!("{out_dir}/results.jsonl")).unwrap_or_default();
    let binaries_total = results_text.lines().count();
    let mut families: Vec<(&String, &usize)> = family_counts.iter().collect();
    families.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let family_table: Vec<serde_json::Value> = families
        .iter()
        .map(|(family, count)| {
            serde_json::json!({
                "family": family,
                "functions": count,
                "binaries": family_binaries.get(*family).map(|set| set.len()).unwrap_or(0),
            })
        })
        .collect();
    let summary = serde_json::json!({
        "binaries": binaries_total,
        "statuses": status_counts,
        "families": family_table,
    });
    fs::write(
        format!("{out_dir}/summary.json"),
        serde_json::to_string_pretty(&summary).unwrap_or_default(),
    )
    .expect("summary.json");

    eprintln!("[SWEEP] ==== summary ====");
    eprintln!("[SWEEP] binaries: {binaries_total}");
    let mut statuses: Vec<(&String, &usize)> = status_counts.iter().collect();
    statuses.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (status, count) in &statuses {
        eprintln!("[SWEEP]   {status:>14}: {count}");
    }
    eprintln!("[SWEEP] families:");
    for (family, count) in &families {
        eprintln!(
            "[SWEEP]   {count:>5}x {family} ({} binaries)",
            family_binaries.get(*family).map(|set| set.len()).unwrap_or(0)
        );
    }
    eprintln!("[SWEEP] outputs: {out_dir}/{{functions,results,summary,run.meta}}.jsonl|.json");
}
