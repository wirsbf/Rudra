//! GENSMOKE-0001: bare generalization driver for arbitrary ELF x86-64
//! binaries (third-binary smoke lane).
//!
//! Purpose: run Rudra's decompiler over a NEVER-TUNED binary with the bare
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
//!   cargo run --profile fast-release --example gen_decompile -- <binary> [--jobs N]
//!
//! Env:
//!   RUDRA_GEN_MIRROR         inert (historical): flow always uses the
//!                             direct-runner oracle range (0, u64::MAX) —
//!                             followFlow(code:0, code:highest),
//!                             funcdata.cc:163 startProcessing. Formerly
//!                             toggled the driver-bounded [entry, MAX) form
//!                             (BINSWEEP-JTDEST-UNLINKED-0001 root cause).
//!   RUDRA_GEN_TIMEOUT_SECS   per-function child timeout in all-mode
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
//!   RUDRA_GEN_ONLY=<name>    all-mode: decompile only the named function
//!   RUDRA_GEN_STALE_GUARD_INHERITED  internal, set by the all-mode
//!                             coordinator on its `--one` children: the
//!                             coordinator verified THIS exe against the
//!                             source tree at launch, so per-function
//!                             workers skip re-hashing the tree (see the
//!                             staleness self-check below).
//!   RUDRA_GEN_PHASE_TIMING    =1 emits per-phase wall-clock [PHASE] lines
//!                             on stderr (SPEEDPROF-FIXEDFLOOR-0001; the
//!                             gen-face counterpart of the curl driver's
//!                             [STEP] channel). Default silent — zero
//!                             effect on stdout blocks or exit codes.
//!   --jobs N (flag)          all-mode worker-pool width, default 8
//!                             (SPEEDPROF-PAR-CHILDREN-0001). `--jobs 1`
//!                             reproduces the historical serial coordinator
//!                             (index-order scheduling, no per-function
//!                             progress lines); any N still emits stdout
//!                             blocks in function index order, byte-identical
//!                             to the serial form.
//!
//! Staleness self-check (INFRA-EXAMPLES-STALELINK-0001): at startup the
//! driver compares the build-time source digest embedded by build.rs
//! (RUDRA_BUILD_SOURCE_DIGEST over every src/**/*.rs file plus this file,
//! the shared guard core, and build.rs itself) against a freshly computed
//! digest of the current tree. A mismatch — or a missing digest, or an
//! unreadable tree — fails fast with exit 2 BEFORE any corpus work: a
//! cargo-reused examples binary that predates the sources under test is
//! exactly the MB29 (r3merge mirror effect missed) and CASTFUSEB
//! (−86/−138 mis-attributed) accident shape. `--stale-guard-
//! probe` runs only this check (exit 0 fresh / 2 stale) for gate scripts
//! (tools/verify_mirror_gate.sh pre-run guard). On success the guard is
//! completely silent — zero bytes on stdout or stderr — so canon/mirror
//! outputs stay byte-identical to the unguarded driver.
//!
//! All-mode decompiles each function in an isolated child process
//! (`--one <index>`), mirroring the oracle golden generator's hermetic
//! per-function "one" mode: a panic or hang in one function cannot take
//! down the corpus run, and each function sees a fresh Architecture.
//! The all-mode coordinator runs a bounded pool of `--jobs N` worker
//! threads (default 8; SPEEDPROF-PAR-CHILDREN-0001) that supervise those
//! children concurrently — one Architecture + one DB per subprocess is the
//! proven isolation form; completion order never reaches stdout, which is
//! assembled strictly in function index order (byte-identical to the
//! historical serial coordinator).

use goblin::Object;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use std::os::fd::AsRawFd as _;

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

// RUDRA-GLUE: one discovered decompilable unit (address, name, size).
#[derive(Clone)]
struct GenFunction {
    vaddr: u64,
    name: String,
    size: usize,
}

// ---------------------------------------------------------------------------
// SPEEDPROF-FIXEDFLOOR-0001: env-gated per-phase wall-clock channel
// (RUDRA_GEN_PHASE_TIMING=1) — the gen-face counterpart of the curl driver's
// [STEP] lines (curl_decompile.rs:6612). Pure observability: stderr-only,
// default completely silent, zero effect on stdout blocks or exit codes, so
// the canon/mirror protocols are untouched (the [GEN-PAR] progress-line
// precedent: stderr is not an output-contract face). Each [PHASE] line
// carries the phase label and the wall time since the previous mark; the
// first mark also reports the time from process start, so a `--one`
// child's full fixed-floor assembly cost (discovery, parse, SLEIGH
// engine, cspec/pspec, symbol registration, flow/action/print) is
// event-level quantifiable.
// ---------------------------------------------------------------------------
static PHASE_TIMING: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

// RUDRA-GLUE: parse RUDRA_GEN_PHASE_TIMING once (any value except "0"
// enables, mirroring RUDRA_SLEIGH_LOAD_REPORT's convention).
fn phase_timing_enabled() -> bool {
    *PHASE_TIMING.get_or_init(|| {
        std::env::var("RUDRA_GEN_PHASE_TIMING").is_ok_and(|value| value != "0")
    })
}

// RUDRA-GLUE: last phase-mark instant, process-global so the coordinator
// thread's discovery mark chains into the run_one worker thread's assembly
// marks (single `--one` child, sequential phases).
static PHASE_LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

// RUDRA-GLUE: emit one [PHASE] line (if enabled). First mark reports the
// time since process start (clock origin), which for a `--one` child
// includes exec + dynamic link + stale-guard skip.
fn phase_mark(label: &str) {
    if !phase_timing_enabled() {
        return;
    }
    let now = std::time::Instant::now();
    let mut last = PHASE_LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match *last {
        Some(previous) => eprintln!("[PHASE] {label} {:.3}s", (now - previous).as_secs_f64()),
        None => eprintln!(
            "[PHASE] {label} {:.3}s (since process start)",
            now.duration_since(process_startup()).as_secs_f64()
        ),
    }
    *last = Some(now);
}

// RUDRA-GLUE: process-start anchor for the first phase mark's
// "since process start" leg (lazily initialized on first use — Instant
// is not const-constructible).
static PROCESS_STARTUP: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn process_startup() -> std::time::Instant {
    *PROCESS_STARTUP.get_or_init(std::time::Instant::now)
}

// RUDRA-GLUE: mirror of golden_dump_1204.cc registerFunctionSymbol +
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

// RUDRA-GLUE: PT_LOAD vaddr-keyed memory image with the ELF loader's
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

// MIRRORCENSUS-GEN-READONLY-STRFOLD-0001: LoadImageBfd::loadFill
// (loadimage_bfd.cc:124-179) is SECTION-based, not PT_LOAD-based: for any
// queried address it walks bfd's section chain (findSection, :99-122) and
// serves `bfd_get_section_contents(p, ..., curaddr - p->vma, ...)` from the
// FIRST section in the chain whose [vma, vma+size) contains the address —
// non-ALLOC sections included. The gen corpora expose such sections at
// their (raw) VMAs: sqlite .gnu_debuglink (vma 0, 0x34), sasquatch
// .comment (vma 0, 0x2b) + eight .debug_* PROGBITS sections (all vma 0,
// sizes up to 0x28a6a), and BFD keeps every one of them in the chain with
// SEC_READONLY (bfd/elf.c _bfd_elf_make_section_from_shdr maps !SHF_WRITE
// -> SEC_READONLY with NO SHF_ALLOC requirement — probe-verified against
// the real BFD 2.38 in the FSTRFOLDUP lane,
// /dev/shm/rudra-tests/fstrfoldup/bfd_ro_probe.c). An oracle-side fold of
// a char* constant pointing there (pushPtrCharConstant printc.cc:1698-1719
// -> StringManagerUnicode::getStringData stringmanage.cc:459 loadFill)
// reads those section bytes, which the PT_LOAD memory image alone does not
// carry. This overlay reproduces the chain service exactly: sections are
// visited in section-table order (= bfd chain order) and each writes its
// file bytes ONLY to addresses no earlier chain section claims — ALLOC
// sections merely claim (their bytes are already exact in the PT_LOAD
// image; sasquatch's .debug_info at vma 0 size 0x28a6a OVERLAPS .text
// [0x6d40,0x42bee), and findSection serves .text there because it precedes
// the debug sections in the chain — a blind copy corrupted code bytes and
// blew the sq face to 57020 in the first iteration of this lane, caught by
// the mirror gate). Claim resolution is interval arithmetic over the
// section list. BFD-absorbed sections (SHT_SYMTAB / the .strtab /
// e_shstrndx) never enter bfd's chain and are skipped here the same way;
// NOBITS sections have no file bytes to copy (they still claim their
// interval — .bss zeros stay zeros). FSTRFOLDUP-STRFOLD-COMMENTRO-0001
// precedent (examples/httpd_decompile.rs overlay_bfd_nonalloc_sections —
// httpd's single non-ALLOC section had no overlap, so the blind copy was
// equivalent there; this gen form is the general chain-faithful one).
fn overlay_bfd_nonalloc_sections(
    elf: &goblin::elf::Elf,
    buffer: &[u8],
    image: &mut [u8],
) {
    use goblin::elf::section_header::{SHT_NOBITS, SHT_STRTAB, SHT_SYMTAB, SHF_ALLOC};
    let shstrndx = elf.header.e_shstrndx as usize;
    // bfd chain membership, in chain order: every section except the
    // BFD-internal absorbed set and zero-size entries.
    let chain: Vec<usize> = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|&(index, header)| {
            header.sh_size != 0
                && index != shstrndx
                && header.sh_type != SHT_SYMTAB
                && !(header.sh_type == SHT_STRTAB
                    && elf.shdr_strtab.get_at(header.sh_name) == Some(".strtab"))
        })
        .map(|(index, _)| index)
        .collect();
    // Claimed intervals, sorted by start (overlaps possible — the walk
    // below advances a cursor so an overlapping earlier claim only ever
    // shrinks what a later section may write).
    let mut claimed: Vec<(usize, usize)> = Vec::new();
    for index in chain {
        let header = &elf.section_headers[index];
        let alloc = (header.sh_flags & SHF_ALLOC as u64) != 0;
        let start = header.sh_addr as usize;
        let end = start.saturating_add(header.sh_size as usize);
        if !alloc && header.sh_type != SHT_NOBITS {
            // Serve this section's bytes on the sub-intervals of
            // [start, end) that no earlier chain section claims —
            // findSection's first-match-wins, restricted to writes.
            let mut cursor = start;
            for &(c_start, c_end) in &claimed {
                if c_start >= end {
                    break;
                }
                if c_end > cursor {
                    let dst_lo = cursor;
                    let dst_hi = c_start.min(end);
                    if dst_lo < dst_hi {
                        overlay_copy(header, buffer, image, start, dst_lo, dst_hi);
                    }
                }
                cursor = cursor.max(c_end);
                if cursor >= end {
                    break;
                }
            }
            if cursor < end {
                overlay_copy(header, buffer, image, start, cursor, end);
            }
        }
        // Claim the whole interval for later sections.
        if let Some(position) = claimed.iter().position(|&(c_start, _)| c_start > start) {
            claimed.insert(position, (start, end));
        } else {
            claimed.push((start, end));
        }
    }
}

// Copy [dst_lo, dst_hi) of section `header` (file bytes at sh_offset +
// (dst - sh_addr)) into the image, clipped to the image bounds.
fn overlay_copy(
    header: &goblin::elf::section_header::SectionHeader,
    buffer: &[u8],
    image: &mut [u8],
    section_start: usize,
    dst_lo: usize,
    dst_hi: usize,
) {
    let src_lo = header.sh_offset as usize + (dst_lo - section_start);
    let src_hi = src_lo + (dst_hi - dst_lo);
    let Some(src) = buffer.get(src_lo..src_hi) else {
        return;
    };
    if dst_lo >= image.len() {
        return;
    }
    let dst_end = dst_hi.min(image.len());
    image[dst_lo..dst_end].copy_from_slice(&src[..dst_end - dst_lo]);
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

impl rudra::arch::SpecQuery for GenSpecHost {
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

impl rudra::pcodeparse::SleighSymbolLookup for GenSpecHost {
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

// RUDRA-GLUE: bare Architecture for the generalization lane — the same
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
    loader: Option<Arc<dyn rudra::loadimage::LoadImage>>,
) -> Result<(Arc<rudra::arch::Architecture>, rudra::sleigh_ffi::SleighCtx), String> {
    let cspec_bytes = fs::read("sleigh_specs/x86-64-gcc.cspec")
        .map_err(|error| format!("unable to read compiler spec: {error}"))?;
    phase_mark("asm_cspec_read");
    let sleigh = rudra::sleigh_ffi::SleighCtx::new()
        .ok_or_else(|| "unable to initialize SLEIGH register catalog".to_string())?;
    phase_mark("asm_sleigh_engine");
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
    phase_mark("asm_register_enum");
    let host = Arc::new(GenSpecHost { registers });
    let mut store = rudra::marshal::DocumentStorage::new();
    let doc = store
        .parse_document(&cspec_bytes)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    phase_mark("asm_cspec_parse");
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
    // architecture.cc:1398 buildTypegrp (single shared TypeFactory).
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
    // architecture.cc:635 `userops.initialize(this)` — the base user-op
    // table from the translator's .sla `userop` names (Translate::
    // getUserOpNames → UnspecializedPcodeOp per index, userop.cc:392-403).
    // Restores the CALLOTHER-name channel: unspecialized pcodeops like the
    // x86 `ud2` semantics' invalidInstructionException (CALLOTHER #77) print
    // by name instead of the CALLOTHER[index] fallback, and
    // earlyJumpTableFail's userop-type consult resolves the real descriptor.
    {
        let userops_arc = arch.userops.as_ref().expect("just installed").clone();
        let names = sleigh.user_op_names();
        let name_refs: Vec<&[u8]> = names.iter().map(|v| v.as_slice()).collect();
        userops_arc
            .write()
            .map_err(|_| "userops lock poisoned".to_string())?
            .initialize(&name_refs)
            .map_err(|e| format!("userops.initialize failed: {e}"))?;
    }
    // ARCH-CONTEXT-TRACKED-0001 (gen-driver copy): parseProcessorConfig
    // before parseCompilerConfig (architecture.cc:639->641); the locked
    // x86-64.pspec <context_data> + <register_data> children.
    let pspec_bytes = fs::read("sleigh_specs/x86-64.pspec")
        .map_err(|error| format!("unable to read processor spec: {error}"))?;
    let pspec_doc = store
        .parse_document(&pspec_bytes)
        .map_err(|error| format!("processor spec parse failed: {error}"))?;
    phase_mark("asm_pspec_read_parse");
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
                    let mut decoder =
                        rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_context_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec context_data decode failed: {error}"))?;
                }
                "register_data" => {
                    let pspec_registry =
                        Arc::new(std::sync::RwLock::new(rudra::marshal::IdRegistry::new()));
                    let mut decoder =
                        rudra::marshal::TreeDecoder::new(child, pspec_registry);
                    arch.decode_register_data(&mut decoder, host.as_ref())
                        .map_err(|error| format!("processor spec register_data decode failed: {error}"))?;
                }
                _ => {}
            }
        }
    }
    // architecture.cc:1391: `symboltab = new Database(this,true);` — the
    // Architecture owns its symbol table from init, BEFORE parseCompilerConfig,
    // so the cspec <global><range space="ram"/> ingestion
    // (Architecture::addToGlobalScope → Database::addRange) lands the ram
    // range on the global scope. S2CODESTAR-DOWNCHAIN-0001 analysis leg: the
    // global range is load-bearing for mapGlobals' discoverScope walk
    // (funcdata_varnode.cc:1701-1702 — a persist varnode in ram with no
    // containing scope range throws "Could not discover scope") and for
    // ActionConstantPtr's container queries.
    arch.symboltab = Some(std::sync::Arc::new(std::sync::RwLock::new(
        rudra::database::Database::new(false),
    )));
    // architecture.cc:1239-1351 parseCompilerConfig — establishes the
    // prototype models and defaultfp (the FUNCPROTO-MODEL-BIND-0001 chain).
    arch.parse_compiler_config(&mut store, host.as_ref(), 8)
        .map_err(|error| format!("compiler spec parse failed: {error}"))?;
    phase_mark("asm_compiler_config");
    if arch.defaultfp.is_none() {
        return Err("No default prototype specified".to_string());
    }
    // architecture.cc:1391-1414: buildLoader precedes buildStringManager.
    if let Some(loader) = loader {
        arch.loader = Some(loader);
        arch.build_string_manager();
    }
    phase_mark("asm_string_manager");
    Ok((Arc::new(arch), sleigh))
}

// RUDRA-GLUE: hermetic single-function decompile, the shape the oracle
// golden_dump_1204 "one" mode drives (BfdArchitecture init, followFlow,
// universal action, PrintC docFunction) on Rudra's side.
fn run_one(binary_path: &str, functions: &[GenFunction], index: usize) -> Result<(), String> {
    let buffer = fs::read(binary_path).map_err(|e| e.to_string())?;
    let obj = Object::parse(&buffer).map_err(|e| e.to_string())?;
    let elf = match &obj {
        Object::Elf(elf) => elf,
        _ => return Err("not an ELF binary".to_string()),
    };
    phase_mark("reparse");
    let target = &functions[index];
    let mut image = memory_image_bytes(elf, &buffer);
    // MIRRORCENSUS-GEN-READONLY-STRFOLD-0001: the oracle's loadFill is a
    // section-chain service (see overlay_bfd_nonalloc_sections) — lay the
    // exposed non-ALLOC section bytes onto their VMAs before the image is
    // cloned into the loader and handed to SLEIGH, so string reads see the
    // same bytes the oracle's BfdArchitecture would serve.
    overlay_bfd_nonalloc_sections(elf, &buffer, &mut image);
    phase_mark("image_overlay");

    let loader: Arc<dyn rudra::loadimage::LoadImage> = Arc::new(
        rudra::loadimage::RawLoadImage::from_bytes(
            binary_path.rsplit('/').next().unwrap_or("gen"),
            0,
            image.clone(),
        ),
    );
    let (arch, sleigh_ctx) = build_architecture(Some(loader))?;
    phase_mark("build_architecture");
    // GEN-CODEPTR-SYMBOLIZE-0001 analysis-side leg (S2CODESTAR-DOWNCHAIN-0001):
    // the oracle's golden harness registers every BFD function symbol into the
    // ANALYSIS Architecture's global scope before decompiling
    // (regen_ghidra_golden.py:219-231 registerFunctionSymbol ->
    // scope->addFunction; BfdArchitecture::init readLoaderSymbols is the
    // production channel of the same face). ActionConstantPtr::isPointer ->
    // Funcdata::queryContainerParentScope reads THAT scope, and a hit runs
    // Funcdata::spacebaseConstant (funcdata.cc:413-419), whose PTRSUB output
    // is typed pointer-to-the-symbol's-type — for a function symbol that is
    // TypeFactory::getTypeCode (database.cc FunctionSymbol::buildType), i.e.
    // the code* mint seed of the whole downChain family. Rudra's gen driver
    // previously installed NO analysis symboltab (query channel returned None
    // on every isPointer consult), so the seed never existed in the mirror
    // arm. build_architecture now owns the Database (with the cspec <global>
    // ram range); register the function symbols on it — address-unique
    // first-wins matching the golden's queryFunction dedup, consume size 1 =
    // glb->min_funcsymbol_size default (same content contract as the
    // print-side DB below).
    if let Some(symboltab) = arch.symboltab.clone() {
        let mut db = symboltab.write().map_err(|_| "symbol table lock poisoned".to_string())?;
        if let Some(db_scope) = db.get_global_scope_mut() {
            for function in functions {
                db_scope.add_function(Address::new(function.vaddr), &function.name, 1);
            }
        }
    }
    phase_mark("symbols_analysis_db");

    // ACTORDER-SPACEBASE-SCOPEWIRE-0001: the analysis-side TypeSpacebase
    // scope leg — the missing twin of the GEN-CODEPTR-SYMBOLIZE-0001
    // analysis leg above. The oracle's TypeSpacebase::getMap (type.cc:
    // 2935-2945) resolves the global scope LIVE through the Architecture
    // (`glb->symboltab->getGlobalScope()`), so every
    // TypeSpacebase::getSubType (type.cc:2947-2969) queryContainer hit
    // returns the symbol's type — for a FunctionSymbol that is
    // TypeFactory::getTypeCode (database.cc FunctionSymbol::buildType).
    // TypeOpPtrsub::getOutputToken (typeop.cc:2352-2365) rides this: a
    // PTRSUB whose base is a spacebase pointer and whose offset resolves
    // to a symbol yields token = pointer-to-symbol-type, which
    // ActionSetCasts::castOutput (coreaction.cc:2532-2544) then finds
    // identical to the output's high type and short-circuits with no CAST
    // (the `(code *)sqlite3WalkNoop` mirror family — S2SELECT bucket B,
    // ACTORDER lane: both-side drill pinned the same is_copy-arm
    // PTRSUB直写 stack slot on op 0xccfe2:36db; the oracle's token is
    // code* via this scope hit, Rudra's fell to the xunknown1* fallback
    // because the factory's spacebase scope snapshot was never attached
    // in the gen driver). Rudra's factory snapshots the scope at
    // TypeSpacebase construction (RUDRA-GLUE, typefactory.rs
    // get_type_spacebase) instead of resolving live, so the driver must
    // attach the source before the first get_type_spacebase call — the
    // exact CURL-CODEREF/PREGFREE precedent (curl_decompile.rs:4697,
    // httpd_decompile.rs:3696). The shared TypeFactory is the one the
    // TypeOps hold (arch.set_types at build_architecture), and the print
    // phase reuses the same factory Arc, so both phases resolve like the
    // oracle's single live scope.
    if let Some(symboltab) = arch.symboltab.clone() {
        if let Some(types) = arch.types.as_ref() {
            types
                .write()
                .map_err(|_| "type factory lock poisoned".to_string())?
                .set_spacebase_scope_source(Some(symboltab));
        }
    }

    let func_size =
        i32::try_from(target.size).map_err(|_| format!("function {} is too large", target.name))?;
    let mut fd = Funcdata::new(&target.name, Address::new(target.vaddr), func_size);
    fd.set_arch(arch);
    // The full BFD function-symbol face (this is the ONLY symbol channel:
    // bare native face — no data symbols, no strings, no seeds).
    for function in functions {
        fd.add_symbol(function.vaddr, function.name.clone());
    }
    phase_mark("fd_symbols");

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
    phase_mark("lifter_configure");

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
    rudra::flow::follow_flow_range(&mut fd, &mut sleigh, 0, u64::MAX, &empty_protos)
        .map_err(|error| format!("flow generation failed for {}: {error}", target.name))?;
    phase_mark("flow");

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
    // followFlow, funcdata.cc:157-163). Rudra's flow generation lives at
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
                rudra::Error::from("restart SLEIGH lifter lock poisoned".to_string())
            })?;
            rudra::flow::follow_flow_range(
                restart_fd,
                &mut lifter,
                0,
                u64::MAX,
                &restart_protos,
            )
        }),
    );
    // STAGE-DRILL (RUDRA_STAGE_DRILL_OUT=<path>, same env pair as the
    // curl/httpd drivers): the recorder itself lives in the library
    // (drillobserve hooks in action.rs/funcdata.rs), so the generic driver
    // only needs the start/drain bracket around perform_action.
    let drill_out = std::env::var("RUDRA_STAGE_DRILL_OUT").ok();
    if drill_out.is_some() {
        let fd_arch = fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned during drill start".to_string())?
            .arch
            .clone()
            .ok_or_else(|| "drill requires a bound Architecture".to_string())?;
        rudra::drillobserve::start(fd_arch);
    }
    // LANE CMPORIENT diagnostic (RUDRA_STAGE_DRILL precedent from the
    // curl/httpd drill arms): arm the OPACTION_DEBUG mirror recorder for
    // the --one target before the pipeline runs, then after perform drain
    // the per-application `DEBUG <n>: <leafname>` frames to <name>.dbg —
    // the exact counterpart of the oracle probe's GLM_TRACE output, for
    // event-level rule-chain comparison. Env-gated; no pipeline change.
    // (Three-arm union with the STAGE-DRILL arm above and the [PHASE]
    // timing marks: RUDRA_STAGE_DRILL alone sinks to <name>.dbg below;
    // with RUDRA_STAGE_DRILL_OUT also set the explicit path sink drains
    // first and the <name>.dbg sink skips on its empty-guard.)
    if std::env::var("RUDRA_STAGE_DRILL").is_ok() {
        let fd_arch = fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned during drill arm".to_string())?
            .arch
            .clone();
        if let Some(arch) = fd_arch {
            rudra::drillobserve::start(arch);
        }
    }
    {
        let mut fd_write = fd_arc
            .write()
            .map_err(|_| "Funcdata write lock poisoned during analysis".to_string())?;
        db.perform_action("decompile", &mut fd_write)
            .map_err(|error| format!("action pipeline failed for {}: {error}", target.name))?;
    }
    phase_mark("action");
    if let Some(path) = drill_out {
        let drained = rudra::drillobserve::drain();
        std::fs::write(&path, drained.join("\n"))
            .map_err(|e| format!("stage drill write failed for {path}: {e}"))?;
    }
    if std::env::var("RUDRA_STAGE_DRILL").is_ok() {
        let drained = rudra::drillobserve::drain();
        if !drained.is_empty() {
            std::fs::write(format!("{}.dbg", target.name), drained.join("\n"))
                .map_err(|e| format!("drill dump failed: {e}"))?;
        }
    }

    // LANE GETLONGEST diagnostic (RUDRA_DUMP_FUNC precedent from the
    // curl/httpd drivers): after the universal action and before printing,
    // dump the final structured tree (sblocks) and the final raw p-code
    // listing for the named function — the exact counterparts of the
    // oracle probe's `fd->getStructure().printTree` / `fd->printRaw`
    // (post-perform, pre-docFunction). Env-gated; CWD-relative output
    // <name>.tree / <name>.ir.
    if let Ok(dump_fn) = std::env::var("RUDRA_DUMP_FUNC") {
        if dump_fn == target.name {
            let fd_read = fd_arc
                .read()
                .map_err(|_| "Funcdata read lock poisoned during dump".to_string())?;
            let mut tree_out = String::new();
            for blk in &fd_read.sblocks.blocks {
                rudra::block::print_tree_dbg(blk, 0, &mut tree_out);
            }
            std::fs::write(format!("{}.tree", target.name), &tree_out)
                .map_err(|e| format!("tree dump failed: {e}"))?;
            match fd_read.print_raw() {
                Ok(ir) => std::fs::write(format!("{}.ir", target.name), &ir)
                    .map_err(|e| format!("IR dump failed: {e}"))?,
                Err(error) => {
                    eprintln!("[DUMP] print_raw failed for {}: {error}", target.name)
                }
            }
            // Per-op raw listing (oracle BlockBasic::printRaw face: one
            // `seqnum:\top_raw` line per op, per basic block) — Rudra's
            // print_raw currently prints only block headers for the bblocks
            // state, so the op lines are emitted here directly through the
            // drill formatter (same DrillFmt::op_raw the raw-ops arm uses).
            {
                let fmt = rudra::drillfmt::DrillFmt {
                    arch: fd_read
                        .arch
                        .clone()
                        .expect("analysis arch present at dump time"),
                };
                let mut s = String::new();
                for i in 0..fd_read.bblocks.get_size() {
                    let blk = match fd_read.bblocks.get_block(i) {
                        Some(b) => b,
                        None => continue,
                    };
                    let blk_rg = blk.read().unwrap();
                    let bank = fd_read.bblocks.bank.clone();
                    let ins: Vec<i32> = (0..blk_rg.size_in())
                        .map(|j| {
                            blk_rg
                                .get_in(j)
                                .map(|e| bank.expect_index(e.point))
                                .unwrap_or(-1)
                        })
                        .collect();
                    let outs: Vec<i32> = (0..blk_rg.size_out())
                        .map(|j| {
                            blk_rg
                                .get_out(j)
                                .map(|e| bank.expect_index(e.point))
                                .unwrap_or(-1)
                        })
                        .collect();
                    s.push_str(&format!(
                        "Basic Block {} 0x{:08x} in={:?} out={:?}\n",
                        i,
                        blk_rg.get_start_addr().as_u64(),
                        ins,
                        outs
                    ));
                    if let Some(bb) = blk_rg.as_any().downcast_ref::<rudra::block::BlockBasic>() {
                        for op_ref in &bb.ops {
                            let op = op_ref.0.read().unwrap();
                            // address.cc:32-38 `operator<<(ostream,SeqNum)`:
                            // `pc.printRaw() ':' uniq` with the uniq counter
                            // in decimal.
                            let offset = op.start.addr.as_u64();
                            s.push_str(&format!(
                                "0x{:08x}:{}:\t{}\n",
                                offset,
                                op.start.time,
                                fmt.op_raw(&op)
                            ));
                        }
                    }
                }
                std::fs::write(format!("{}.ops", target.name), &s)
                    .map_err(|e| format!("ops dump failed: {e}"))?;
            }

            eprintln!("[DUMP] wrote {}.tree / {}.ir", target.name, target.name);
        }
    }

    // GEN-CODEPTR-SYMBOLIZE-0001: the print-side function-symbol channel.
    // The oracle's golden harness registers every BFD function symbol into
    // the Architecture's symboltab before printing
    // (regen_ghidra_golden.py:219-231 registerFunctionSymbol →
    // scope->addFunction(address, basename)), so PrintC::pushPtrCodeConstant
    // (printc.cc:1730-1742) resolves pointer-to-code constants through
    // glb->symboltab->getGlobalScope()->queryFunction and prints the
    // function display name instead of the default `(code *)0xVAL` arm
    // (printc.cc:1806-1814). Rudra's mechanism pieces are all present
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
    let mut print_symbol_db = rudra::database::Database::new(false);
    {
        let db_scope = print_symbol_db
            .get_global_scope_mut()
            .ok_or_else(|| "print symbol DB has no global scope".to_string())?;
        for function in functions {
            db_scope.add_function(Address::new(function.vaddr), &function.name, 1);
        }
    }
    // MIRRORCENSUS-GEN-READONLY-STRFOLD-0001: the readonly property ranges
    // the oracle's BfdArchitecture installs at Architecture init —
    // LoadImageBfd::getReadonly (loadimage_bfd.cc:286-303) lists every BFD
    // section with SEC_READONLY and Architecture::fillinReadOnlyFromLoader
    // (architecture.cc:1371-1381) ORs Varnode::readonly over each range
    // into the symboltab flagbase. PrintC::pushPtrCharConstant's isReadOnly
    // gate (printc.cc:1709, via Scope::isReadOnly -> queryProperties ->
    // flagbase) reads exactly this channel, so without the ranges the
    // mirror can never fold a string literal — the gen driver installed
    // zero readonly code (MIRRORCENSUS2 §3-H: sqlite `unaff_R12 = "LIT"`
    // vs `(char *)LIT` 120 lines + sq 18, folding never fired). The
    // direct-runner golden (BfdArchitecture, real BFD 2.38 — provenance
    // json runner block) HAS these ranges: bare-library truth, not
    // analyzer state. BFD's ELF backend maps !SHF_WRITE -> SEC_READONLY
    // with NO SHF_ALLOC requirement, so the range list includes NON-ALLOC
    // sections at their raw VMAs (sqlite .gnu_debuglink [0,0x33];
    // sasquatch .comment + .debug_* stack at vma 0), whose bytes the
    // overlay_bfd_nonalloc_sections call above laid into the image.
    // BFD-absorbed sections (SHT_SYMTAB, the .strtab, e_shstrndx) are not
    // in bfd's chain and are excluded identically. Print-DB only: the
    // analysis symboltab above keeps the function-symbol face alone (the
    // swap below happens after perform_action), so the action pipeline
    // runs with the same channel-absent state as before — zero
    // action-phase drift. FSTRFOLDUP precedent (examples/httpd_decompile.rs
    // MIRATTR-F-STRFOLD-0001 print-db install; ro_base=0 — the gen driver
    // is the single raw-vaddr arm the golden compares at --base 0).
    {
        let mut ro_ranges = 0usize;
        use goblin::elf::section_header::{SHT_STRTAB, SHT_SYMTAB, SHF_WRITE};
        let shstrndx = elf.header.e_shstrndx as usize;
        for (index, header) in elf.section_headers.iter().enumerate() {
            if header.sh_size == 0
                || (header.sh_flags & SHF_WRITE as u64) != 0
                || index == shstrndx
            {
                continue;
            }
            if header.sh_type == SHT_SYMTAB {
                continue; // bfd-internal (symtab): not in the chain
            }
            if header.sh_type == SHT_STRTAB
                && elf.shdr_strtab.get_at(header.sh_name) == Some(".strtab")
            {
                continue; // bfd-internal (the symtab's strtab)
            }
            let first = Address::new(header.sh_addr);
            let last = Address::new(header.sh_addr + header.sh_size - 1);
            if let Some(range) = rudra::address::Range::new(first, last) {
                print_symbol_db.set_property_range(
                    rudra::varnode::varnode_flags::READONLY,
                    range,
                );
                ro_ranges += 1;
            }
        }
        eprintln!(
            "[PREPASS] MIRRORCENSUS-GEN-READONLY-STRFOLD-0001 print DB: {} readonly section ranges installed",
            ro_ranges
        );
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
    phase_mark("print_db_install");

    let mut printer = PrintC::new(Box::new(EmitPrettyPrint::new()));
    printer.set_rpn_enabled(true);
    {
        let fd_read = fd_arc
            .read()
            .map_err(|_| "Funcdata read lock poisoned during printing".to_string())?;
        printer.doc_function(&fd_read);
    }
    phase_mark("print");
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
    if std::env::var("RUDRA_SLEIGH_LOAD_REPORT").is_ok_and(|value| value != "0") {
        eprintln!(
            "[GEN] sleigh engine loads={}",
            rudra::sleigh_ffi::engine_load_count()
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
// RUDRA-GLUE: pure driver infrastructure — the oracle golden generator is a
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

// RUDRA-GLUE: one /proc snapshot of (ppid, pid) edges under `root`,
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

// RUDRA-GLUE: SIGKILL every foreign process still holding an end of one of
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

// RUDRA-GLUE: Command::output() with the same capture face (stdin null,
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

// ---------------------------------------------------------------------------
// INFRA-EXAMPLES-STALELINK-0001: startup staleness self-check.
//
// RUDRA-GLUE: pure driver/gate infrastructure — the locked Ghidra oracle's
// golden harness is a C++ build with its own artifact management; there is
// no decompiler-side counterpart to match. The guarded failure mode (a
// cargo-reused examples binary that predates the sources under test) caused
// two measured incidents: MB29 integration read "all faces identical" off a
// stale binary and missed the r3merge mirror effect (sq −86 / sqlite −138),
// and the CASTFUSEB lane attributed those same deltas to an unrelated
// commit (CR-CASTFUSEB net-baseline A/B disproved both). The guard embeds a
// content digest of src/**/*.rs + this file at build time (build.rs, shared
// core in examples/common/stale_guard_hash.rs) and recomputes it at startup:
// content-level, deliberately mtime-independent (touching a file without a
// content change is not staleness). Fail-closed on every non-Fresh verdict;
// completely silent on success so canon/mirror outputs are byte-identical
// to the unguarded driver.
// ---------------------------------------------------------------------------

// RUDRA-GLUE: digest core kept in lockstep with build.rs via one shared
// verbatim source file (see examples/common/stale_guard_hash.rs header).
#[path = "common/stale_guard_hash.rs"]
mod stale_guard_hash;

// RUDRA-GLUE: build-time digest + domain size emitted by build.rs; None
// only when the build script did not run or emit (fail-closed below).
const EMBEDDED_SOURCE_DIGEST: Option<&str> = option_env!("RUDRA_BUILD_SOURCE_DIGEST");
const EMBEDDED_SOURCE_FILE_COUNT: Option<&str> = option_env!("RUDRA_BUILD_SOURCE_FILE_COUNT");

// RUDRA-GLUE: all-mode coordinator -> child handoff marker. The coordinator
// verified this exact exe against the tree at launch; per-function children
// (810 on the sq face, 1385 on sqlite) skip re-hashing the source tree.
const STALE_GUARD_INHERITED_ENV: &str = "RUDRA_GEN_STALE_GUARD_INHERITED";

// RUDRA-GLUE: guard failure exit code — distinct from `timeout`'s 124 and
// from the usage/panic codes so gate scripts can tell staleness apart.
const STALE_GUARD_EXIT_CODE: i32 = 2;

// RUDRA-GLUE: render the fail-closed [GEN-STALE] block for a non-Fresh
// verdict (None for Fresh). The message must name 陈旧二进制 and the relink
// command — gate operators act on it directly.
fn stale_guard_report(verdict: stale_guard_hash::GuardVerdict) -> Option<String> {
    use stale_guard_hash::GuardVerdict;
    match verdict {
        GuardVerdict::Fresh { .. } => None,
        GuardVerdict::Stale { embedded, current } => Some(format!(
            "[GEN-STALE] FAIL: 陈旧二进制 (stale binary) — embedded build digest != current source digest\n\
             [GEN-STALE]   embedded={embedded:016x}  current={current:016x}\n\
             [GEN-STALE]   本二进制不含当前工作区源码（cargo 增量/缓存复用未重链的事故形态：MB29 漏检 r3merge 镜面效应、\n\
             [GEN-STALE]   CASTFUSEB 错归因两口实录——INFRA-EXAMPLES-STALELINK-0001）。拒绝继续，防止陈旧产物冒充测量。\n\
             [GEN-STALE]   重链 (relink): 在目标 worktree 内执行  cargo build --profile fast-release --examples\n\
             [GEN-STALE]   校验域: src/**/*.rs + examples/gen_decompile.rs 内容指纹（FNV-1a-64，内容级，与 mtime 无关）"
        )),
        GuardVerdict::NoEmbeddedDigest => Some(
            "[GEN-STALE] FAIL: 构建期指纹缺失 (no embedded source digest) — 本二进制未经 build.rs 指纹嵌入，\n\
             [GEN-STALE]   守卫按陈旧处理拒绝继续（fail-closed）。\n\
             [GEN-STALE]   重链 (relink): 在目标 worktree 内执行  cargo build --profile fast-release --examples"
                .to_string(),
        ),
        GuardVerdict::UnreadableSourceTree => Some(
            "[GEN-STALE] FAIL: 源码树不可读 (cannot read src/ for the staleness digest) — CWD 必须是仓库根\n\
             [GEN-STALE]   （与 sleigh_specs/ 的 CWD 相对要求同款）。守卫按陈旧处理拒绝继续（fail-closed）。\n\
             [GEN-STALE]   重链/改在仓库根运行: cd <worktree-root> && cargo build --profile fast-release --examples"
                .to_string(),
        ),
    }
}

// RUDRA-GLUE: startup enforcement — verify the embedded digest against the
// current tree unless this process is an all-mode child inheriting the
// coordinator's verified-at-launch state. Exits 2 on any non-Fresh verdict;
// returns silently (no output at all) when fresh.
fn enforce_stale_guard() {
    if std::env::var_os(STALE_GUARD_INHERITED_ENV).is_some() {
        return;
    }
    let verdict =
        stale_guard_hash::guard_verdict(EMBEDDED_SOURCE_DIGEST, std::path::Path::new("."));
    if let Some(report) = stale_guard_report(verdict) {
        eprintln!("{report}");
        std::process::exit(STALE_GUARD_EXIT_CODE);
    }
}

// RUDRA-GLUE: standalone guard mode for gate scripts (--stale-guard-probe):
// run ONLY the self-check — one stdout status line on success, the same
// [GEN-STALE] block + exit 2 on failure. Ignores the inherited marker (a
// probe must always actually probe) and needs no corpus binary argument.
fn stale_guard_probe() {
    let verdict =
        stale_guard_hash::guard_verdict(EMBEDDED_SOURCE_DIGEST, std::path::Path::new("."));
    match verdict {
        stale_guard_hash::GuardVerdict::Fresh { digest } => {
            println!(
                "STALE-GUARD OK digest={digest:016x} files={}",
                EMBEDDED_SOURCE_FILE_COUNT.unwrap_or("?")
            );
        }
        stale => {
            if let Some(report) = stale_guard_report(stale) {
                eprintln!("{report}");
            }
            std::process::exit(STALE_GUARD_EXIT_CODE);
        }
    }
}


// ---------------------------------------------------------------------------
// SPEEDPROF-PAR-CHILDREN-0001: all-mode per-function child pool.
//
// RUDRA-GLUE: pure coordinator scheduling infrastructure — the locked
// oracle's golden generator (regen_ghidra_golden.py) is a Python harness
// whose "all" mode serializes its per-function "one" children; there is no
// decompiler-side function to mirror. The lane's measured evidence
// (/dev/shm/rudra-tests/speedprof/): jobs=32 child pool on this machine ran
// sqlite 953.6s -> 165.4s (5.76x) and sq 393.7s -> 43.5s (9.05x) with a
// three-way byte-identity chain (official serial == harness serial ==
// harness parallel; sqlite 5,289,364B + sq full cmp). This in-driver pool
// adopts exactly that shape:
//   - worker isolation = one `--one <index>` SUBPROCESS per function (one
//     Architecture + one DB per child — the CR-S1-proven form; no
//     in-process sharing, PAREVAL-DETERM-HERMETICITY-0001 stays intact);
//   - output order = function index order always: blocks are collected per
//     slot and emitted after the pool drains, so stdout is byte-identical
//     to the historical serial coordinator at any --jobs;
//   - enqueue order = largest-function-first at jobs > 1 (load balancing
//     against the one giant straggler, e.g. sqlite VdbeExec ~166s; schedule
//     order never reaches the output), index order at jobs == 1;
//   - default 8 (conservative on the shared 112-core host), `--jobs N`
//     override, fail-closed: a child spawn error or a panicked worker
//     aborts the whole run with a nonzero exit and no assembled output.
// ---------------------------------------------------------------------------

// RUDRA-GLUE: conservative default pool width (shared host discipline;
// SPEEDPROF measured up to 32 safe, 8 keeps headroom under foreign load).
const DEFAULT_POOL_JOBS: usize = 8;

// RUDRA-GLUE: parse `--jobs N` / `--jobs=N` (default DEFAULT_POOL_JOBS);
// invalid usage (non-numeric, zero, or a trailing `--jobs` with no value)
// exits 1 before any corpus work (fail-closed).
fn parse_jobs(args: &[String]) -> usize {
    let mut jobs = DEFAULT_POOL_JOBS;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let value = if arg == "--jobs" {
            match iter.next() {
                Some(value) => Some(value.as_str()),
                None => {
                    eprintln!("--jobs needs a positive integer argument");
                    std::process::exit(1);
                }
            }
        } else {
            arg.strip_prefix("--jobs=")
        };
        if let Some(value) = value {
            jobs = value.parse().unwrap_or_else(|_| {
                eprintln!("--jobs needs a positive integer (got '{value}')");
                std::process::exit(1);
            });
        }
    }
    if jobs == 0 {
        eprintln!("--jobs must be >= 1");
        std::process::exit(1);
    }
    jobs
}

// RUDRA-GLUE: classify one supervised child's capture into its all-mode
// output block — the historical serial coordinator's four-way selection,
// factored out verbatim so serial and pooled emission share one code path
// (bytes identical by construction). Returns (ok-flag, block text with its
// trailing newline).
fn child_block(
    output: &std::process::Output,
    function: &GenFunction,
    timeout_secs: u64,
) -> (bool, String) {
    let status = &output.status;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if status.success() && stdout.contains("/* ----") {
        let mut text = stdout.to_string();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        (true, text)
    } else if status.code().is_some_and(|code| code == 124) {
        (
            false,
            format!(
                "/* ---- 0x{:x}: {} TIMEOUT (>{}s) ---- */\n",
                function.vaddr, function.name, timeout_secs
            ),
        )
    } else if stderr.contains("panicked") {
        let reason = stderr
            .lines()
            .rev()
            .find(|line| line.contains("panicked") || line.starts_with("Error"))
            .unwrap_or("panicked");
        (
            false,
            format!(
                "/* ---- 0x{:x}: {} PANICKED: {} ---- */\n",
                function.vaddr, function.name, reason
            ),
        )
    } else {
        let reason = stderr
            .lines()
            .rev()
            .find(|line| line.starts_with("[GEN] --one failed"))
            .map(|line| line.trim_start_matches("[GEN] --one failed: "))
            .unwrap_or("nonzero exit");
        (
            false,
            format!(
                "/* ---- 0x{:x}: {} ERROR: {} ---- */\n",
                function.vaddr, function.name, reason
            ),
        )
    }
}


fn main() {
    // SPEEDPROF-FIXEDFLOOR-0001: pin the phase-clock origin at main entry
    // (the first [PHASE] mark's "since process start" leg) before any
    // argument handling, so the anchor excludes nothing the driver runs.
    let _ = process_startup();
    let args: Vec<String> = std::env::args().collect();
    // INFRA-EXAMPLES-STALELINK-0001 standalone probe mode for gate scripts:
    // run only the staleness self-check (exit 0 fresh / 2 stale), no corpus
    // binary needed.
    if args.iter().any(|arg| arg == "--stale-guard-probe") {
        stale_guard_probe();
        return;
    }
    // INFRA-EXAMPLES-STALELINK-0001 startup staleness self-check: silent on
    // success, exit 2 before any corpus work on a stale/unverifiable binary.
    enforce_stale_guard();
    if args.len() < 2 {
        eprintln!(
            "usage: {} <binary> [--list | --one <index> | --jobs N]\n  env: RUDRA_GEN_MIRROR=1 RUDRA_GEN_TIMEOUT_SECS=<n> RUDRA_GEN_ONLY=<name>",
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
        // SPEEDPROF-FIXEDFLOOR-0001: discovery (read + goblin parse + symbol
        // table scan) is the child's first fixed-floor phase.
        phase_mark("discovery");
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
        // RUDRA-GLUE: PERF-ARENA-FLIP (f) observation probe (--one tail;
        // default off).
        rudra::block::bank_stats::report();
        return;
    }

    // all-mode: isolated child per function (hermetic "one" mirror),
    // `timeout`-wrapped when RUDRA_GEN_TIMEOUT_SECS > 0. The wrapper also
    // carries --kill-after so a SIGTERM-immune child is SIGKILLed at the
    // deadline instead of wedging `timeout` in waitpid, and the coordinator
    // supervises each child through run_capped_output (GEN-DRIVER-STALL-0001:
    // wall cap + post-exit pipe-holder kill; normal path byte-identical to
    // Command::output()). SPEEDPROF-PAR-CHILDREN-0001: a bounded pool of
    // `--jobs N` worker threads (default 8) supervises those children
    // concurrently; blocks are collected per slot and emitted in function
    // index order after the pool drains — stdout stays byte-identical to
    // the historical serial coordinator at every pool width (see the pool
    // section comment above parse_jobs).
    let timeout_secs: u64 = std::env::var("RUDRA_GEN_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let wall_cap = (timeout_secs > 0).then(|| {
        Duration::from_secs(
            timeout_secs + TIMEOUT_KILL_AFTER_SECS + WALL_CAP_SLACK_SECS,
        )
    });
    let only = std::env::var("RUDRA_GEN_ONLY").ok();
    let only_addr = only
        .as_deref()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u64::from_str_radix(value, 16).ok());
    let exe = std::env::current_exe().expect("current_exe");
    let mirror_env = std::env::var("RUDRA_GEN_MIRROR").ok();
    let jobs = parse_jobs(&args);

    // Work list: indices passing the RUDRA_GEN_ONLY filter (same predicate
    // as the historical serial loop — include when no filter is set, or
    // when either the name or the 0x-address form matches).
    let work: Vec<usize> = functions
        .iter()
        .enumerate()
        .filter(|(_, function)| {
            only.as_deref().is_none_or(|name| {
                name == function.name || only_addr == Some(function.vaddr)
            })
        })
        .map(|(index, _)| index)
        .collect();

    // Schedule over work slots: index order at jobs == 1 (exact historical
    // serial shape), largest-function-first at jobs > 1 (load balancing so
    // one giant straggler starts first — completion order never reaches
    // the output, only slot assignment does).
    let mut schedule: Vec<usize> = (0..work.len()).collect();
    if jobs > 1 {
        schedule.sort_by_key(|&slot| std::cmp::Reverse(functions[work[slot]].size));
    }
    let cursor = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::atomic::AtomicUsize::new(0);
    // One filled Option per work slot; workers never touch another slot.
    let blocks: std::sync::Mutex<Vec<Option<(bool, String)>>> =
        std::sync::Mutex::new(vec![None; work.len()]);
    // First child-spawn error aborts the run (fail-closed): workers stop
    // pulling new work and the coordinator exits nonzero before emitting
    // any assembled output.
    let spawn_failure: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    let worker_count = jobs.min(work.len());
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..worker_count)
            .map(|_| {
                scope.spawn(|| {
                    loop {
                        let position =
                            cursor.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let Some(&slot) = schedule.get(position) else {
                            return;
                        };
                        // Fail-fast drain: a sibling already hit a spawn error.
                        if spawn_failure
                            .lock()
                            .expect("pool failure flag lock")
                            .is_some()
                        {
                            return;
                        }
                        let index = work[slot];
                        let function = &functions[index];
                        let started = std::time::Instant::now();
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
                            command.env("RUDRA_GEN_MIRROR", mirror);
                        }
                        // INFRA-EXAMPLES-STALELINK-0001: children inherit the
                        // coordinator's verified-at-launch state instead of
                        // re-hashing the source tree once per function worker.
                        command.env(STALE_GUARD_INHERITED_ENV, "1");
                        let (ok, block) = match run_capped_output(command, wall_cap) {
                            Ok(output) => child_block(&output, function, timeout_secs),
                            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => (
                                false,
                                format!(
                                    "/* ---- 0x{:x}: {} STALL: child unkillable past wall cap ({error}) ---- */\n",
                                    function.vaddr, function.name
                                ),
                            ),
                            Err(error) => {
                                *spawn_failure
                                    .lock()
                                    .expect("pool failure flag lock") =
                                    Some(format!("spawn failed for {}: {error}", function.name));
                                return;
                            }
                        };
                        blocks.lock().expect("pool block store lock")[slot] = Some((ok, block));
                        // Pooled-mode progress on stderr only (serial keeps the
                        // historical per-function silence); stdout is reserved
                        // for the index-ordered C assembly.
                        if jobs > 1 {
                            let finished =
                                done.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                            eprintln!(
                                "[GEN-PAR] {}/{} idx {} {} {:.1}s {}",
                                finished,
                                work.len(),
                                index,
                                function.name,
                                started.elapsed().as_secs_f64(),
                                if ok { "ok" } else { "fail" }
                            );
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            if handle.join().is_err() {
                // Fail-closed: a panicked worker poisons the pool — no
                // partial assembled output.
                eprintln!("[GEN] FAIL: pool worker thread panicked");
                std::process::exit(1);
            }
        }
    });
    if let Some(message) = spawn_failure.into_inner().expect("pool failure flag lock") {
        eprintln!("[GEN] FAIL (fail-closed): {message}");
        std::process::exit(1);
    }

    // Ordered emission: strictly function index order, one shared code path
    // with the classification above — byte-identical to the historical
    // serial coordinator's per-function print!/println! sequence.
    let blocks = blocks.into_inner().expect("pool block store lock");
    let mut ok_count = 0usize;
    for slot in 0..work.len() {
        let Some((ok, block)) = &blocks[slot] else {
            eprintln!("[GEN] FAIL: function slot {slot} produced no block");
            std::process::exit(1);
        };
        print!("{block}");
        if *ok {
            ok_count += 1;
        }
    }
    eprintln!("[GEN] ok={}/{} functions", ok_count, functions.len());
    // RUDRA-GLUE: PERF-ARENA-FLIP (f) observation probe tail (default off).
    rudra::block::bank_stats::report();
}
