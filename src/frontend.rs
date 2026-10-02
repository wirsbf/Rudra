//! Native ELF front-end: symbol import, function discovery, memory-map
//! derivation, and C++ name demangling.
//!
//! Role: Ghidra's Java layer — the ELF loader (`ElfProgramBuilder`), the
//! ELF symbol / entry-point / demangler analyzers — populates the Program
//! database before the C++ decompiler runs; the locked decompile-cpp oracle
//! tree only consumes that Program through its transport. This module is
//! Rugra's native adapter for the same front-end boundary (the role
//! [`crate::debugproto`] plays for DWARF): it reads the ELF symbol tables
//! (`.symtab` + `.dynsym`), derives the non-stripped function universe from
//! defined `STT_FUNC` symbols and the entry point, derives the `PT_LOAD`
//! memory map, and demangles Itanium-ABI C++ names on the import path.
//!
//! ELF semantics follow the System V ABI (ELF-64) specification; the
//! per-function doc comments cite the governing spec sections. The canon
//! driver's pre-seeding channels (locked ledger corpus, PLT/EXTERNAL stub
//! projections, DWARF prototypes) remain available as overrides on top of
//! this module's auto-derived data — see `docs/api/frontend.md` for the
//! data-level differential that classifies every residue.

use anyhow::{Context, Result};
use goblin::elf::Elf;

#[cfg(test)]
use std::path::Path;

// ---------------------------------------------------------------------------
// System V ABI constants (ELF-64)
// ---------------------------------------------------------------------------

// System V ABI 4.1, ch. 4 (Object Files), "Symbol Table": st_info packs
// binding<<4 | type; st_shndx == SHN_UNDEF (0) marks an undefined (imported)
// symbol; symbol index 0 of every table is the reserved null entry.
/// `SHN_UNDEF`: the symbol table index value marking an undefined symbol.
const SHN_UNDEF: usize = 0;
/// `STT_FUNC` (2): the symbol names a function (executable code).
const STT_FUNC: u8 = 2;
/// `STB_LOCAL` (0): local binding.
const STB_LOCAL: u8 = 0;
/// `STB_GLOBAL` (1): global binding.
const STB_GLOBAL: u8 = 1;
/// `STB_WEAK` (2): weak binding.
const STB_WEAK: u8 = 2;
/// `STB_GNU_UNIQUE` (10): GNU-unique binding (GNU extension).
const STB_GNU_UNIQUE: u8 = 10;
/// `STT_OBJECT` (1): the symbol names a data object.
const STT_OBJECT: u8 = 1;
/// `STT_SECTION` (3): the symbol is associated with a section.
const STT_SECTION: u8 = 3;
/// `STT_FILE` (4): the symbol names a source file.
const STT_FILE: u8 = 4;
/// `STT_COMMON` (5): the symbol names a common block.
const STT_COMMON: u8 = 5;
/// `STT_TLS` (6): the symbol names a thread-local object.
const STT_TLS: u8 = 6;
/// `STT_GNU_IFUNC` (10): GNU indirect-function symbol (GNU extension).
const STT_GNU_IFUNC: u8 = 10;

// System V ABI 4.1, ch. 4, "Section Header": sh_flags bit SHF_EXECINSTR (0x4)
// marks a section holding executable machine instructions.
/// `SHF_EXECINSTR` (0x4): section contains executable instructions.
const SHF_EXECINSTR: u64 = 0x4;

// System V ABI 4.1, ch. 4, "Program Header": p_type PT_LOAD (1) marks a
/// loadable segment; p_flags carry PF_X (1) / PF_W (2) / PF_R (4).
const PT_LOAD: u32 = 1;
/// `PF_X` (1): segment is executable.
const PF_X: u32 = 1;
/// `PF_W` (2): segment is writable.
const PF_W: u32 = 2;
/// `PF_R` (4): segment is readable.
const PF_R: u32 = 4;

// ---------------------------------------------------------------------------
// Symbol data model
// ---------------------------------------------------------------------------

/// The ELF symbol type (`st_info & 0xf`, System V ABI 4.1 "Symbol Table").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    /// `STT_NOTYPE` (0): the symbol's type is not specified.
    NoType,
    /// `STT_OBJECT` (1): a data object.
    Object,
    /// `STT_FUNC` (2): a function or executable code symbol.
    Function,
    /// `STT_SECTION` (3): a section symbol.
    Section,
    /// `STT_FILE` (4): a source file symbol.
    File,
    /// `STT_COMMON` (5): a common block.
    Common,
    /// `STT_TLS` (6): a thread-local object.
    Tls,
    /// `STT_GNU_IFUNC` (10): GNU indirect function (GNU extension).
    GnuIfunc,
    /// Any other value (OS/processor-specific ranges).
    Other(u8),
}

// RUDRA-GLUE: ELF spec enum decoder (Ghidra's Java ElfSymbol.getType carries the
// same STT_* set; the locked decompile-cpp oracle tree has no ELF parser — its
// Program arrives pre-populated by the Java loader). System V ABI 4.1, ch. 4,
// "Symbol Table": symbol type occupies the low nibble of st_info.
impl SymbolType {
    /// Decodes the `st_info` low nibble into a symbol type.
    // RUDRA-GLUE: STT_* nibble decoder (spec-cited Java-layer equivalent; no
    // locked-tree counterpart).
    pub fn from_info(info: u8) -> SymbolType {
        match info & 0xf {
            0 => SymbolType::NoType,
            STT_OBJECT => SymbolType::Object,
            STT_FUNC => SymbolType::Function,
            STT_SECTION => SymbolType::Section,
            STT_FILE => SymbolType::File,
            STT_COMMON => SymbolType::Common,
            STT_TLS => SymbolType::Tls,
            STT_GNU_IFUNC => SymbolType::GnuIfunc,
            other => SymbolType::Other(other),
        }
    }
}

/// The ELF symbol binding (`st_info >> 4`, System V ABI 4.1 "Symbol Table").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolBinding {
    /// `STB_LOCAL` (0): local symbol, not visible outside the object.
    Local,
    /// `STB_GLOBAL` (1): global symbol, visible to all object files.
    Global,
    /// `STB_WEAK` (2): weak symbol.
    Weak,
    /// `STB_GNU_UNIQUE` (10): GNU-unique binding (GNU extension).
    GnuUnique,
    /// Any other value (OS/processor-specific ranges).
    Other(u8),
}

// RUDRA-GLUE: ELF spec enum decoder (Ghidra's Java ElfSymbol.getBind carries the
// same STB_* set; the locked decompile-cpp oracle tree has no ELF parser).
// System V ABI 4.1, ch. 4, "Symbol Table": symbol binding occupies the high
// nibble of st_info.
impl SymbolBinding {
    /// Decodes the `st_info` high nibble into a binding.
    // RUDRA-GLUE: STB_* nibble decoder (spec-cited Java-layer equivalent; no
    // locked-tree counterpart).
    pub fn from_info(info: u8) -> SymbolBinding {
        match info >> 4 {
            STB_LOCAL => SymbolBinding::Local,
            STB_GLOBAL => SymbolBinding::Global,
            STB_WEAK => SymbolBinding::Weak,
            STB_GNU_UNIQUE => SymbolBinding::GnuUnique,
            other => SymbolBinding::Other(other),
        }
    }
}

/// Which ELF symbol table an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolTable {
    /// The static linker symbol table (`.symtab`); absent in stripped
    /// binaries.
    Symtab,
    /// The dynamic symbol table (`.dynsym`); present in every dynamically
    /// linked object and the only table a stripped binary keeps.
    Dynsym,
}

/// One imported ELF symbol: the six-field data shape (name / address / size /
/// type / binding / defined-vs-import) every front-end consumer needs.
///
/// `name` carries the demangled spelling when the raw name is an Itanium-ABI
/// mangled name (the Ghidra demangler analyzer's rename); `mangled_name`
/// preserves the raw strtab spelling in that case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    /// Symbol name — demangled when the raw name was mangled.
    pub name: String,
    /// The raw strtab spelling, present only when it differed (mangled).
    pub mangled_name: Option<String>,
    /// `st_value`: the symbol's virtual address (0 for undefined imports).
    pub address: u64,
    /// `st_size`: the symbol's size in bytes (0 when unknown).
    pub size: u64,
    /// The symbol type (`st_info` low nibble).
    pub sym_type: SymbolType,
    /// The symbol binding (`st_info` high nibble).
    pub binding: SymbolBinding,
    /// `st_shndx != SHN_UNDEF`: the symbol is defined here (an export),
    /// otherwise it is an undefined import.
    pub defined: bool,
    /// Which table the entry was read from.
    pub table: SymbolTable,
}

/// The imported symbol universe: `.symtab` entries followed by `.dynsym`
/// entries, each in table order (skipping the reserved null index 0 and
/// empty-name entries, System V ABI 4.1 "Symbol Table").
#[derive(Debug, Clone, Default)]
pub struct SymbolImport {
    symbols: Vec<ElfSymbol>,
}

// RUDRA-GLUE: deterministic-order accessor set for the front-end symbol store
// (Ghidra's Java SymbolManager owns the Program-side store; the locked
// decompile-cpp oracle tree receives symbols through its transport and has no
// ELF import layer).
impl SymbolImport {
    /// Number of imported symbols.
    // RUDRA-GLUE: store-size accessor (Rust collection idiom; no locked-tree
    // counterpart).
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the import is empty (stripped binary with no `.dynsym`).
    // RUDRA-GLUE: emptiness accessor paired with len (clippy convention; no
    // locked-tree counterpart).
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// All symbols in import order (`.symtab` then `.dynsym`, table order).
    // RUDRA-GLUE: slice accessor for the import-order store (no locked-tree
    // counterpart).
    pub fn symbols(&self) -> &[ElfSymbol] {
        &self.symbols
    }

    /// Defined symbols only (exports: `st_shndx != SHN_UNDEF`).
    // RUDRA-GLUE: exports filter — the defined/import classification of the
    // System V ABI "Symbol Table" (st_shndx semantics); Java-layer equivalent.
    pub fn exports(&self) -> impl Iterator<Item = &ElfSymbol> {
        self.symbols.iter().filter(|symbol| symbol.defined)
    }

    /// Undefined symbols only (imports: `st_shndx == SHN_UNDEF`).
    // RUDRA-GLUE: imports filter — the undefined half of the System V ABI
    // st_shndx classification; Java-layer equivalent.
    pub fn imports(&self) -> impl Iterator<Item = &ElfSymbol> {
        self.symbols.iter().filter(|symbol| !symbol.defined)
    }

    /// Defined `STT_FUNC` symbols — the non-stripped function universe.
    // RUDRA-GLUE: STT_FUNC filter feeding function discovery (the
    // addFunctionsFromSymbolTable symbol class; System V ABI STT_FUNC = 2).
    pub fn function_symbols(&self) -> impl Iterator<Item = &ElfSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.defined && symbol.sym_type == SymbolType::Function)
    }

    /// First symbol registered at `address` (`.symtab` wins over `.dynsym`).
    // RUDRA-GLUE: address-keyed lookup mirroring the Program symbol query the
    // driver performs when naming call targets (Java SymbolManager lookup).
    pub fn lookup_address(&self, address: u64) -> Option<&ElfSymbol> {
        self.symbols.iter().find(|symbol| symbol.address == address)
    }
}

// ---------------------------------------------------------------------------
// Function discovery data model
// ---------------------------------------------------------------------------

/// How one discovered function was seeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionSeedKind {
    /// The ELF header's `e_entry`, when no function symbol covers it.
    EntryPoint,
    /// A defined `STT_FUNC` symbol from `.symtab`.
    SymtabFunction,
    /// A defined `STT_FUNC` symbol from `.dynsym` (the only source on a
    /// stripped binary).
    DynsymFunction,
}

/// One discovered function, in the canon driver's function-table shape
/// (entry address, size, name, origin).
///
/// `size` keeps `st_size` when it is non-zero; size-0 symbols (crt stubs,
/// `_init`/`_fini`) get a working bound — the next seed's address capped by
/// the owning executable section's end — mirroring the driver-side discovery
/// layer's rule. The bound is a working extent, not the oracle's flow-derived
/// body; padding inside it never survives an entry-seeded flow walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSeed {
    /// Entry virtual address (`st_value`, or `e_entry` for the entry seed).
    pub vaddr: u64,
    /// `st_size` when non-zero, else the working next-entry bound.
    pub size: u64,
    /// Symbol name at the entry (demangled when mangled); `"entry"` for a
    /// symbol-less entry point.
    pub name: String,
    /// Which channel seeded this function.
    pub kind: FunctionSeedKind,
}

// ---------------------------------------------------------------------------
// Memory map data model
// ---------------------------------------------------------------------------

/// One `PT_LOAD` segment of the derived memory map.
///
/// This is the data source for the driver-side `add_range` seeding (global
/// scope ownership ranges) and the read-only property ranges: the loader maps
/// every `PT_LOAD` segment at its virtual address, so the decompiler's global
/// scope spans exactly these ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySegment {
    /// `p_vaddr`: the segment's virtual address.
    pub vaddr: u64,
    /// `p_memsz`: the segment's in-memory size (`.bss` tail included).
    pub memsz: u64,
    /// `p_filesz`: the segment's file-backed size (`p_memsz >= p_filesz`).
    pub filesz: u64,
    /// `p_offset`: the segment's file offset.
    pub file_offset: u64,
    /// `PF_R`: the segment is readable.
    pub readable: bool,
    /// `PF_W`: the segment is writable.
    pub writable: bool,
    /// `PF_X`: the segment is executable.
    pub executable: bool,
}

// RUDRA-GLUE: PT_LOAD range helpers matching the canon driver's manual
// add_range loops (examples/*_decompile.rs walk the same program headers);
// Ghidra's Java ElfProgramBuilder owns the Program-side memory blocks — the
// locked decompile-cpp oracle tree receives them via BfdArchitecture's loader.
impl MemorySegment {
    /// Read-only classification (`PF_R` set, `PF_W` clear) — the driver's
    /// read-only property-range filter.
    // RUDRA-GLUE: PF_R/PF_W classification (System V ABI "Program Header"
    // p_flags; the driver's readonly range filter form).
    pub fn read_only(&self) -> bool {
        self.readable && !self.writable
    }

    /// The `(first, last)` inclusive address pair of the segment — the exact
    /// form the driver's `add_range` loop builds (`first = p_vaddr`,
    /// `last = p_vaddr + p_memsz - 1`).
    // RUDRA-GLUE: add_range bounds form (the driver's manual loop shape;
    // System V ABI p_vaddr/p_memsz semantics).
    pub fn range_bounds(&self) -> Option<(u64, u64)> {
        if self.memsz == 0 {
            return None;
        }
        Some((self.vaddr, self.vaddr + self.memsz - 1))
    }
}

// ---------------------------------------------------------------------------
// Aggregate seed
// ---------------------------------------------------------------------------

/// The complete auto-derived front-end seed for one binary: entry point,
/// function universe, memory map, and symbol import.
#[derive(Debug, Clone)]
pub struct FrontendSeed {
    /// `e_entry` from the ELF header (0 for shared libraries).
    pub entry_point: u64,
    /// Discovered functions, sorted by entry address.
    pub functions: Vec<FunctionSeed>,
    /// `PT_LOAD` segments in program-header order.
    pub segments: Vec<MemorySegment>,
    /// The imported symbol universe.
    pub symbols: SymbolImport,
}

// ---------------------------------------------------------------------------
// Demangling
// ---------------------------------------------------------------------------

/// Demangles an Itanium C++ ABI mangled name to its source-level spelling.
///
/// Only `_Z`-prefixed names are attempted (the Itanium ABI mangling prefix;
/// the same gate Ghidra's demangler analyzer applies). Returns `None` for
/// non-mangled names and for mangled names that fail to parse.
// RUDRA-GLUE: Ghidra's Java DemanglerAnalyzer (DemanglerCmd) performs this
// rename on the Program's symbols before the decompiler runs — the locked
// decompile-cpp oracle tree has no demangler. Itanium C++ ABI §5 (Mangled
// names): external names begin "_Z" followed by the encoding.
pub fn demangle(name: &str) -> Option<String> {
    if !name.starts_with("_Z") {
        return None;
    }
    let symbol = cpp_demangle::Symbol::new(name.as_bytes()).ok()?;
    symbol.demangle().ok()
}

// RUDRA-GLUE: the demangler rename applied on the symbol import path — the
// DemanglerAnalyzer equivalent that swaps a mangled symbol's display name for
// its demangled spelling while preserving the raw form.
fn demangled_symbol_name(raw: &str) -> (String, Option<String>) {
    match demangle(raw) {
        Some(demangled) => (demangled, Some(raw.to_string())),
        None => (raw.to_string(), None),
    }
}

// ---------------------------------------------------------------------------
// Symbol import
// ---------------------------------------------------------------------------

/// Imports every ELF symbol: `.symtab` entries followed by `.dynsym` entries,
/// each in table order.
///
/// Skips the reserved null entry (index 0) and empty-name entries of each
/// table (System V ABI 4.1, ch. 4, "Symbol Table": index 0 is reserved and
/// holds no name). Names are demangled on the way in when mangled. GNU
/// version tags (`@GLIBC_...`) live in `.gnu.version`, not in the strtab
/// names, and stay with the driver-side EXTERNAL-block channel.
// RUDRA-GLUE: Ghidra's Java ElfProgramBuilder.addSymbols walks the same two
// tables into the Program's symbol manager; the locked decompile-cpp oracle
// tree has no ELF parser (its Program arrives pre-populated). System V ABI
// 4.1, ch. 4, "Symbol Table" (Elf64_Sym: st_name, st_info, st_other, st_shndx,
// st_value, st_size).
pub fn import_symbols(bytes: &[u8]) -> Result<SymbolImport> {
    let elf = Elf::parse(bytes).context("ELF parse for symbol import")?;
    let mut symbols = Vec::new();
    for (index, sym) in elf.syms.iter().enumerate() {
        if index == 0 {
            continue; // reserved null entry
        }
        if let Some(symbol) = elf_symbol_from(
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            elf.strtab.get_at(sym.st_name),
            SymbolTable::Symtab,
        ) {
            symbols.push(symbol);
        }
    }
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        if index == 0 {
            continue; // reserved null entry
        }
        if let Some(symbol) = elf_symbol_from(
            sym.st_value,
            sym.st_size,
            sym.st_info,
            sym.st_shndx,
            elf.dynstrtab.get_at(sym.st_name),
            SymbolTable::Dynsym,
        ) {
            symbols.push(symbol);
        }
    }
    Ok(SymbolImport { symbols })
}

// RUDRA-GLUE: one Elf64_Sym row → ElfSymbol (the field mapping Ghidra's Java
// ElfSymbol performs); empty-name entries carry no importable identity and are
// skipped. System V ABI 4.1, ch. 4, "Symbol Table".
fn elf_symbol_from(
    value: u64,
    size: u64,
    info: u8,
    shndx: usize,
    raw_name: Option<&str>,
    table: SymbolTable,
) -> Option<ElfSymbol> {
    let raw = raw_name?;
    if raw.is_empty() {
        return None;
    }
    let (name, mangled_name) = demangled_symbol_name(raw);
    Some(ElfSymbol {
        name,
        mangled_name,
        address: value,
        size,
        sym_type: SymbolType::from_info(info),
        binding: SymbolBinding::from_info(info),
        defined: shndx != SHN_UNDEF,
        table,
    })
}

// ---------------------------------------------------------------------------
// Function discovery
// ---------------------------------------------------------------------------

/// Discovers the non-stripped function universe: defined `STT_FUNC` symbols
/// from `.symtab` ∪ `.dynsym` lying inside an executable section, plus the
/// ELF entry point when no function symbol covers it.
///
/// Mirrors the Ghidra importer semantics the canon drivers reconstruct:
/// `.symtab` wins over `.dynsym` at the same address (the static table is the
/// linker's authoritative record); the entry point merges with a covering
/// symbol (the entry analyzer marks the existing function) and otherwise
/// seeds a function named `"entry"`. Sizes keep `st_size` when non-zero;
/// size-0 symbols take the working next-entry bound capped by the owning
/// executable section's end. The result is sorted by entry address.
// RUDRA-GLUE: Ghidra's Java ElfProgramBuilder.addFunctionsFromSymbolTable +
// the entry-point analyzer own this discovery; the locked decompile-cpp
// oracle tree has no function-creation layer (it consumes the Program's
// function universe). System V ABI 4.1, ch. 4: "e_entry" (ELF header) and
// "Section Header" (SHF_EXECINSTR marks executable sections).
pub fn discover_functions(bytes: &[u8]) -> Result<Vec<FunctionSeed>> {
    let elf = Elf::parse(bytes).context("ELF parse for function discovery")?;
    let exec_ranges = executable_section_ranges(&elf);
    let in_exec = |addr: u64| exec_ranges.iter().any(|&(lo, hi)| lo <= addr && addr < hi);
    let mut seeds: Vec<FunctionSeed> = Vec::new();
    let mut seeded: std::collections::BTreeSet<u64> = Default::default();
    for (index, sym) in elf.syms.iter().enumerate() {
        if index == 0 {
            continue; // reserved null entry
        }
        let Some(name) = elf.strtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() || sym.st_value == 0 || !sym.is_function() {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF || !in_exec(sym.st_value) {
            continue;
        }
        if seeded.insert(sym.st_value) {
            let (name, _) = demangled_symbol_name(name);
            seeds.push(FunctionSeed {
                vaddr: sym.st_value,
                size: sym.st_size,
                name,
                kind: FunctionSeedKind::SymtabFunction,
            });
        }
    }
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        if index == 0 {
            continue; // reserved null entry
        }
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if name.is_empty() || sym.st_value == 0 || !sym.is_function() {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF || !in_exec(sym.st_value) {
            continue;
        }
        if seeded.insert(sym.st_value) {
            let (name, _) = demangled_symbol_name(name);
            seeds.push(FunctionSeed {
                vaddr: sym.st_value,
                size: sym.st_size,
                name,
                kind: FunctionSeedKind::DynsymFunction,
            });
        }
    }
    let entry = elf.header.e_entry;
    if entry != 0 && in_exec(entry) && !seeded.contains(&entry) {
        // The entry-point analyzer creates a function at e_entry; with no
        // symbol there, Ghidra's default entry naming is "entry".
        let name = elf
            .syms
            .iter()
            .find(|sym| sym.st_value == entry)
            .and_then(|sym| elf.strtab.get_at(sym.st_name))
            .or_else(|| {
                elf.dynsyms
                    .iter()
                    .find(|sym| sym.st_value == entry)
                    .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
            })
            .filter(|name| !name.is_empty())
            .map(|name| demangled_symbol_name(name).0)
            .unwrap_or_else(|| "entry".to_string());
        seeds.push(FunctionSeed {
            vaddr: entry,
            size: 0,
            name,
            kind: FunctionSeedKind::EntryPoint,
        });
    }
    seeds.sort_by_key(|seed| seed.vaddr);
    fill_working_bounds(&mut seeds, &exec_ranges);
    Ok(seeds)
}

/// Executable section ranges `(start, end)` — every `SHF_EXECINSTR` section
/// with a non-zero size, in section-header order.
// RUDRA-GLUE: executable-extent helper for the discovery pass (Ghidra's Java
// importer validates symbol addresses against executable memory blocks);
// System V ABI 4.1, ch. 4, "Section Header": SHF_EXECINSTR (0x4).
fn executable_section_ranges(elf: &Elf) -> Vec<(u64, u64)> {
    elf.section_headers
        .iter()
        .filter(|header| (header.sh_flags & SHF_EXECINSTR) != 0 && header.sh_size > 0)
        .map(|header| (header.sh_addr, header.sh_addr.saturating_add(header.sh_size)))
        .collect()
}

/// Fills working size bounds for size-0 seeds: the next seed's address capped
/// by the owning executable section's end.
///
/// `_init`/`_fini` (each alone in its own section) therefore take their exact
/// section extent; same-section size-0 symbols take the gap to the next seed.
/// The bound is a working extent — the oracle's flow-derived body sizes are a
/// decompile-time product this module does not reproduce.
// RUDRA-GLUE: the canon driver's discovery layer applies the same working
/// bound rule (its comment: "a working bound, not Ghidra's flow-derived
/// body"); Ghidra's Java side derives real body extents by disassembly.
fn fill_working_bounds(seeds: &mut [FunctionSeed], exec_ranges: &[(u64, u64)]) {
    for index in 0..seeds.len() {
        if seeds[index].size != 0 {
            continue;
        }
        let vaddr = seeds[index].vaddr;
        let next = seeds
            .get(index + 1)
            .map(|seed| seed.vaddr)
            .filter(|next| *next > vaddr);
        let section_end = exec_ranges
            .iter()
            .filter(|&&(lo, hi)| lo <= vaddr && vaddr < hi)
            .map(|&(_, hi)| hi)
            .min()
            .filter(|hi| *hi > vaddr);
        let bound = match (next, section_end) {
            (Some(next), Some(end)) => Some(next.min(end)),
            (Some(next), None) => Some(next),
            (None, Some(end)) => Some(end),
            (None, None) => None,
        };
        if let Some(bound) = bound {
            seeds[index].size = bound - vaddr;
        }
    }
}

// ---------------------------------------------------------------------------
// Memory map
// ---------------------------------------------------------------------------

/// Derives the memory map from the program headers: every `PT_LOAD` segment
/// with a non-zero `p_memsz`, in program-header order.
///
/// This is the add_range source set: the loader maps exactly these segments
/// at their virtual addresses, so the global scope's ownership ranges and the
/// read-only property ranges both derive from this list.
// RUDRA-GLUE: Ghidra's Java ElfProgramBuilder allocates the Program's memory
/// blocks from the same program headers; the locked decompile-cpp oracle tree
/// receives them through BfdArchitecture's loader (every PT_LOAD mapped).
// System V ABI 4.1, ch. 4, "Program Header" (Elf64_Phdr: p_type, p_flags,
// p_offset, p_vaddr, p_filesz, p_memsz).
pub fn derive_memory_map(bytes: &[u8]) -> Result<Vec<MemorySegment>> {
    let elf = Elf::parse(bytes).context("ELF parse for memory map")?;
    Ok(elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD && ph.p_memsz > 0)
        .map(|ph| MemorySegment {
            vaddr: ph.p_vaddr,
            memsz: ph.p_memsz,
            filesz: ph.p_filesz,
            file_offset: ph.p_offset,
            readable: (ph.p_flags & PF_R) != 0,
            writable: (ph.p_flags & PF_W) != 0,
            executable: (ph.p_flags & PF_X) != 0,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

/// Builds the complete front-end seed for one binary: symbol import, function
/// discovery, memory map, and the raw entry point.
// RUDRA-GLUE: aggregate of the three import channels above — the single call
// a future driver uses instead of its manual seeding loops (Ghidra's Java
// loader/analyzer stack performs the equivalent population before the
// decompiler runs).
pub fn build_seed(bytes: &[u8]) -> Result<FrontendSeed> {
    let elf = Elf::parse(bytes).context("ELF parse for front-end seed")?;
    let symbols = import_symbols(bytes)?;
    let functions = discover_functions(bytes)?;
    let segments = derive_memory_map(bytes)?;
    Ok(FrontendSeed {
        entry_point: elf.header.e_entry,
        functions,
        segments,
        symbols,
    })
}

// RUDRA-GLUE: test convenience — reads a canon fixture binary relative to the
// crate manifest (canon binaries are repo-tracked test inputs).
#[cfg(test)]
fn fixture_bytes(relative: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {}", path.display(), err))
}

// RUDRA-GLUE: test convenience — the locked-oracle provenance ledger for one
// canon corpus (the manual seed data the differential compares against).
#[cfg(test)]
fn provenance_functions(name: &str) -> Vec<(u64, String, u64)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.provenance.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {}", path.display(), err));
    let json: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("parse {}: {}", path.display(), err));
    json["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .map(|entry| {
            (
                entry["offset"].as_u64().expect("offset"),
                entry["name"].as_str().expect("name").to_string(),
                entry["size"].as_u64().expect("size"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// The canon analyzeHeadless image base both PIE corpora were imported at
    /// (provenance `offset` values are image-based; ELF vaddr = offset − base).
    const CANON_IMAGE_BASE: u64 = 0x100000;

    // ---- demangle wiring -------------------------------------------------

    #[test]
    fn demangle_resolves_itanium_names() {
        assert_eq!(
            demangle("_ZN5space3fooEibc").as_deref(),
            Some("space::foo(int, bool, char)")
        );
        assert_eq!(demangle("_ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        // Non-mangled names are not attempted (the Itanium prefix gate).
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("__libc_start_main"), None);
        // Mangled-looking but malformed input fails to parse, not panics.
        assert_eq!(demangle("_Z"), None);
        assert_eq!(demangle("_Z9notreal!!"), None);
    }

    #[test]
    fn demangled_symbol_name_feeds_the_import_path() {
        // Plain C name passes through untouched, no mangled form recorded.
        assert_eq!(
            demangled_symbol_name("main"),
            ("main".to_string(), None)
        );
        // Mangled name swaps in the demangled spelling, keeps the raw form.
        let (name, mangled) = demangled_symbol_name("_ZN3foo3barEv");
        assert_eq!(name, "foo::bar()");
        assert_eq!(mangled.as_deref(), Some("_ZN3foo3barEv"));
    }

    // ---- symbol import (real canon binary) --------------------------------

    #[test]
    fn curl_symbol_import_matches_spec_semantics() {
        let bytes = fixture_bytes("examples/curl");
        let import = import_symbols(&bytes).expect("curl symbol import");

        // .symtab (non-null, non-empty) + .dynsym (non-null, non-empty):
        // 109 named symtab entries + 51 named dynsym entries (readelf -sW).
        assert_eq!(import.len(), 160);

        // Spot checks against readelf -s output (spec field semantics):
        // main: 0x25a0, st_size 3531, FUNC, GLOBAL, defined, .symtab.
        let main = import
            .symbols()
            .iter()
            .find(|s| s.name == "main")
            .expect("main symbol");
        assert_eq!(main.address, 0x25a0);
        assert_eq!(main.size, 3531);
        assert_eq!(main.sym_type, SymbolType::Function);
        assert_eq!(main.binding, SymbolBinding::Global);
        assert!(main.defined);
        assert_eq!(main.table, SymbolTable::Symtab);

        // _init: 0x2000, st_size 0, FUNC, LOCAL, defined (size-0 crt entry).
        let init = import
            .symbols()
            .iter()
            .find(|s| s.name == "_init")
            .expect("_init symbol");
        assert_eq!(init.address, 0x2000);
        assert_eq!(init.size, 0);
        assert_eq!(init.binding, SymbolBinding::Local);

        // free: undefined .dynsym import (st_value 0, st_shndx UND).
        let free = import
            .symbols()
            .iter()
            .find(|s| s.name == "free" && s.table == SymbolTable::Dynsym)
            .expect("free dynsym import");
        assert_eq!(free.address, 0);
        assert!(!free.defined);
        assert_eq!(free.sym_type, SymbolType::Function);
        assert_eq!(free.binding, SymbolBinding::Global);

        // Exports/imports split (st_shndx == SHN_UNDEF across both tables):
        // a fully-linked PIE keeps its undefined imports in .symtab too, so
        // the import set is 96 = 48 .symtab UND + 48 .dynsym UND; the 48
        // EXTERNAL-block slots the canon ledger records are the .dynsym UND
        // subset.
        let imports: Vec<&ElfSymbol> = import.imports().collect();
        assert_eq!(imports.len(), 96);
        assert_eq!(
            imports
                .iter()
                .filter(|s| s.table == SymbolTable::Dynsym)
                .count(),
            48
        );
        // Defined STT_FUNC symbols: the 31 .symtab functions (curl's .dynsym
        // carries no defined FUNC entry).
        assert_eq!(import.function_symbols().count(), 31);
    }

    #[test]
    fn httpd_stripped_symbol_import_is_dynsym_only() {
        let bytes = fixture_bytes("examples/httpd");
        let import = import_symbols(&bytes).expect("httpd symbol import");
        // Stripped binary: no .symtab — every entry comes from .dynsym.
        assert!(import
            .symbols()
            .iter()
            .all(|s| s.table == SymbolTable::Dynsym));
        // 473 defined dynsym STT_FUNC entries (the stripped corpus's
        // symbol-backed function universe).
        assert_eq!(import.function_symbols().count(), 473);
    }

    // ---- function discovery -----------------------------------------------

    #[test]
    fn curl_function_discovery_covers_symtab_universe() {
        let bytes = fixture_bytes("examples/curl");
        let seeds = discover_functions(&bytes).expect("curl discovery");
        // 31 defined .symtab STT_FUNC symbols inside executable sections;
        // curl's .dynsym has no defined FUNC entry; e_entry (0x3370) merges
        // with the _start symbol seed.
        assert_eq!(seeds.len(), 31);
        assert!(seeds.iter().all(|s| s.kind == FunctionSeedKind::SymtabFunction));

        let by_addr: BTreeMap<u64, &FunctionSeed> =
            seeds.iter().map(|s| (s.vaddr, s)).collect();

        // _start covers the entry point and keeps its st_size.
        let start = by_addr[&0x3370];
        assert_eq!(start.name, "_start");
        assert_eq!(start.size, 47);

        // Size-0 crt entries take working bounds: _init/_fini are alone in
        // their sections, so the section extent is exact (27 / 13 — the same
        // values the locked ledger records).
        assert_eq!(by_addr[&0x2000].name, "_init");
        assert_eq!(by_addr[&0x2000].size, 27);
        assert_eq!(by_addr[&0x5478].name, "_fini");
        assert_eq!(by_addr[&0x5478].size, 13);

        // Same-section size-0 crt stubs take the gap to the next seed
        // (working bounds; the ledger's flow-derived sizes differ — see the
        // ledger differential test).
        assert_eq!(by_addr[&0x33a0].name, "deregister_tm_clones");
        assert_eq!(by_addr[&0x33a0].size, 0x33d0 - 0x33a0);
        assert_eq!(by_addr[&0x3450].name, "frame_dummy");
        assert_eq!(by_addr[&0x3450].size, 0x3460 - 0x3450);

        // st_size survives untouched for sized symbols.
        assert_eq!(by_addr[&0x25a0].name, "main");
        assert_eq!(by_addr[&0x25a0].size, 3531);

        // Sorted by entry address.
        let addrs: Vec<u64> = seeds.iter().map(|s| s.vaddr).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted);
    }

    #[test]
    fn httpd_stripped_discovery_is_dynsym_backed() {
        let bytes = fixture_bytes("examples/httpd");
        let seeds = discover_functions(&bytes).expect("httpd discovery");
        // Stripped: the 473 defined .dynsym STT_FUNC symbols; e_entry
        // (0x2c420) merges with the _start dynsym seed.
        assert_eq!(seeds.len(), 473);
        assert!(seeds.iter().all(|s| s.kind == FunctionSeedKind::DynsymFunction));
        let start = seeds.iter().find(|s| s.vaddr == 0x2c420).expect("_start");
        assert_eq!(start.name, "_start");
        assert_eq!(start.size, 47);
        // Every httpd dynsym FUNC has a non-zero st_size, so no working
        // bounds are exercised on this corpus.
        assert!(seeds.iter().all(|s| s.size > 0));
    }

    #[test]
    fn sqlite3_shared_library_discovery() {
        // System corpus (provenance input path); skip when the host lacks it.
        let path = Path::new("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6");
        if !path.exists() {
            eprintln!("[FRONTEND-TEST] libsqlite3 absent — skip");
            return;
        }
        let bytes = std::fs::read(path).expect("read libsqlite3");
        let seeds = discover_functions(&bytes).expect("sqlite3 discovery");
        // 1339 defined .dynsym STT_FUNC symbols (provenance
        // defined_dynsym_func); entry point is 0 for a shared library, so no
        // entry seed fires.
        assert_eq!(seeds.len(), 1339);
        assert!(seeds.iter().all(|s| s.kind == FunctionSeedKind::DynsymFunction));
        assert!(seeds.iter().all(|s| s.size > 0));
    }

    // ---- data-level differential vs the manual seed data -------------------

    /// curl: the module's auto-derived function table vs the locked 124-entry
    /// ledger (the canon driver's manual GOLDEN_CORPUS_LEDGER source).
    /// Coverage classes, precomputed and independently verified:
    ///   - 31 module seeds, all inside the ledger (0 extras);
    ///   - 93 ledger residue = 45 PLT stubs + 48 EXTERNAL slots (driver
    ///     discovery channels, out of this module's scope);
    ///   - covered names: 27/31 (the 4 GCC clone-suffix spellings resolve
    ///     through the DWARF channel, not ELF);
    ///   - covered sizes: 11/31 (the oracle's sizes are flow-derived bodies;
    ///     ELF st_size / working bounds differ on 20).
    #[test]
    fn curl_ledger_differential_classified() {
        let bytes = fixture_bytes("examples/curl");
        let seeds = discover_functions(&bytes).expect("curl discovery");
        let ledger: BTreeMap<u64, (String, u64)> = provenance_functions("ghidra_curl_1204")
            .into_iter()
            .map(|(offset, name, size)| (offset - CANON_IMAGE_BASE, (name, size)))
            .collect();
        assert_eq!(ledger.len(), 124);

        let mut in_ledger = 0;
        let mut name_matches = 0;
        let mut size_matches = 0;
        for seed in &seeds {
            let Some((ledger_name, ledger_size)) = ledger.get(&seed.vaddr) else {
                continue;
            };
            in_ledger += 1;
            if &seed.name == ledger_name {
                name_matches += 1;
            }
            if seed.size == *ledger_size {
                size_matches += 1;
            }
        }
        assert_eq!(in_ledger, 31, "every module seed is a ledger entry");
        assert_eq!(name_matches, 27);
        assert_eq!(size_matches, 11);

        // Residue classification: PLT stub span 0x2020..0x25a0 and the
        // EXTERNAL block at 0x19000+ account for every ledger entry the
        // module does not cover.
        let residue: Vec<u64> = ledger
            .keys()
            .copied()
            .filter(|vaddr| !seeds.iter().any(|s| s.vaddr == *vaddr))
            .collect();
        assert_eq!(residue.len(), 93);
        let plt: Vec<u64> = residue
            .iter()
            .copied()
            .filter(|v| (0x2020..0x25a0).contains(v))
            .collect();
        let external: Vec<u64> = residue
            .iter()
            .copied()
            .filter(|v| *v >= 0x19000)
            .collect();
        assert_eq!(plt.len(), 45, "PLT stubs (driver PLT channel)");
        assert_eq!(external.len(), 48, "EXTERNAL slots (driver EXTERNAL channel)");
        assert_eq!(plt.len() + external.len(), residue.len());
    }

    /// httpd: the module's discovery vs the driver's manual ELF loop form
    /// (examples/httpd_decompile.rs:3662-3708 — dynsym STT_FUNC with a
    /// resolvable file offset). On this corpus the two rules coincide
    /// exactly: same 473 addresses, names, and sizes.
    #[test]
    fn httpd_driver_manual_form_equivalence() {
        let bytes = fixture_bytes("examples/httpd");
        let seeds = discover_functions(&bytes).expect("httpd discovery");
        // The driver's manual form, verbatim rule: defined dynsym FUNC,
        // st_value != 0, address inside some section (file_off > 0), size =
        // st_size (the 512 fallback never fires — no size-0 entries).
        let elf = Elf::parse(&bytes).expect("httpd ELF");
        let mut manual: BTreeMap<u64, (String, u64)> = Default::default();
        for sym in elf.dynsyms.iter() {
            if sym.st_value == 0 || !sym.is_function() {
                continue;
            }
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let file_off = elf.section_headers.iter().any(|header| {
                sym.st_value >= header.sh_addr
                    && sym.st_value < header.sh_addr.saturating_add(header.sh_size)
            });
            if file_off {
                manual.insert(
                    sym.st_value,
                    (name.to_string(), if sym.st_size > 0 { sym.st_size } else { 512 }),
                );
            }
        }
        assert_eq!(manual.len(), 473);
        for seed in &seeds {
            let (name, size) = manual
                .get(&seed.vaddr)
                .unwrap_or_else(|| panic!("module seed 0x{:x} missing from manual form", seed.vaddr));
            assert_eq!(&seed.name, name, "name at 0x{:x}", seed.vaddr);
            assert_eq!(seed.size, *size, "size at 0x{:x}", seed.vaddr);
        }
        assert_eq!(seeds.len(), manual.len(), "no extras on either side");
    }

    /// httpd: module coverage vs the locked 2010-entry ledger. All 473
    /// symbol-backed seeds are ledger entries with exact names; the 1537
    /// residue is the stripped-discovery universe (analyzer-level function
    /// finding — the STRIPPED-DISCOVERY work package, out of scope here).
    #[test]
    fn httpd_ledger_differential_classified() {
        let bytes = fixture_bytes("examples/httpd");
        let seeds = discover_functions(&bytes).expect("httpd discovery");
        let ledger: BTreeMap<u64, (String, u64)> = provenance_functions("ghidra_httpd_1204")
            .into_iter()
            .map(|(offset, name, size)| (offset - CANON_IMAGE_BASE, (name, size)))
            .collect();
        assert_eq!(ledger.len(), 2010);
        let mut in_ledger = 0;
        let mut name_matches = 0;
        for seed in &seeds {
            let Some((ledger_name, _)) = ledger.get(&seed.vaddr) else {
                panic!("module seed 0x{:x} outside the ledger", seed.vaddr);
            };
            in_ledger += 1;
            if &seed.name == ledger_name {
                name_matches += 1;
            }
        }
        assert_eq!(in_ledger, 473);
        assert_eq!(name_matches, 473, "every covered name matches the oracle");
        let residue = ledger.len() - in_ledger;
        assert_eq!(residue, 1537, "stripped-discovery universe (out of scope)");
    }

    /// sqlite3: module coverage vs the locked 1385-entry ledger. All 1339
    /// dynsym-backed seeds are ledger entries with exact names; the 46
    /// residue is the .plt.sec jump-slot stubs (driver PLT channel).
    #[test]
    fn sqlite3_ledger_differential_classified() {
        let path = Path::new("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6");
        if !path.exists() {
            eprintln!("[FRONTEND-TEST] libsqlite3 absent — skip");
            return;
        }
        let bytes = std::fs::read(path).expect("read libsqlite3");
        let seeds = discover_functions(&bytes).expect("sqlite3 discovery");
        let ledger: BTreeMap<u64, (String, u64)> = provenance_functions("ghidra_sqlite_1204")
            .into_iter()
            .map(|(offset, name, size)| (offset, (name, size)))
            .collect();
        assert_eq!(ledger.len(), 1385);
        let mut in_ledger = 0;
        let mut name_matches = 0;
        for seed in &seeds {
            let Some((ledger_name, _)) = ledger.get(&seed.vaddr) else {
                panic!("module seed 0x{:x} outside the ledger", seed.vaddr);
            };
            in_ledger += 1;
            if &seed.name == ledger_name {
                name_matches += 1;
            }
        }
        assert_eq!(in_ledger, 1339);
        assert_eq!(name_matches, 1339);
        // Residue = the 46 .plt.sec jump-slot stubs (0x1e320..0x1e600 —
        // the driver PLT channel, not this module).
        let residue: Vec<u64> = ledger
            .keys()
            .copied()
            .filter(|vaddr| !seeds.iter().any(|s| s.vaddr == *vaddr))
            .collect();
        assert_eq!(residue.len(), 46);
        assert!(residue.iter().all(|v| (0x1e320..0x1e600).contains(v)));
    }

    // ---- memory map ---------------------------------------------------------

    /// The derived PT_LOAD map vs the drivers' manual add_range loops
    /// (identical program-header walks). curl: 4 segments, 3 read-only, the
    /// executable one at 0x2000; httpd: same shape.
    #[test]
    fn pt_load_memory_map_matches_driver_add_range_form() {
        let curl = derive_memory_map(&fixture_bytes("examples/curl")).expect("curl map");
        assert_eq!(curl.len(), 4);
        // readelf -lW: offsets/vaddrs/sizes of the four LOAD segments.
        let expected: [(u64, u64, u64, u64); 4] = [
            (0x0, 0x0, 0x1af0, 0x1af0),
            (0x2000, 0x2000, 0x3485, 0x3485),
            (0x6000, 0x6000, 0xf148, 0xf148),
            (0x15c48, 0x16c48, 0x888, 0x1a38),
        ];
        for (segment, (off, vaddr, filesz, memsz)) in curl.iter().zip(expected) {
            assert_eq!((segment.file_offset, segment.vaddr, segment.filesz, segment.memsz), (off, vaddr, filesz, memsz));
        }
        assert!(curl[0].read_only());
        assert!(curl[1].read_only() && curl[1].executable);
        assert!(curl[2].read_only());
        assert!(curl[3].writable && !curl[3].read_only());
        // add_range bounds form: first = p_vaddr, last = p_vaddr+memsz-1.
        assert_eq!(curl[1].range_bounds(), Some((0x2000, 0x2000 + 0x3485 - 1)));

        let httpd = derive_memory_map(&fixture_bytes("examples/httpd")).expect("httpd map");
        assert_eq!(httpd.len(), 4);
        assert_eq!(httpd[1].vaddr, 0x29000);
        assert!(httpd[1].read_only() && httpd[1].executable);
        assert_eq!(httpd[3].range_bounds(), Some((0x999f0, 0x999f0 + 0xa3d0 - 1)));
    }

    // ---- aggregate -----------------------------------------------------------

    #[test]
    fn build_seed_aggregates_all_channels() {
        let bytes = fixture_bytes("examples/curl");
        let seed = build_seed(&bytes).expect("curl front-end seed");
        assert_eq!(seed.entry_point, 0x3370);
        assert_eq!(seed.functions.len(), 31);
        assert_eq!(seed.segments.len(), 4);
        assert_eq!(seed.symbols.len(), 160);
        // The entry point is covered by the _start symbol seed (merged, not
        // duplicated).
        assert_eq!(
            seed.functions
                .iter()
                .filter(|f| f.vaddr == seed.entry_point)
                .count(),
            1
        );

        let httpd = build_seed(&fixture_bytes("examples/httpd")).expect("httpd seed");
        assert_eq!(httpd.entry_point, 0x2c420);
        assert_eq!(httpd.functions.len(), 473);
        assert_eq!(httpd.symbols.function_symbols().count(), 473);
    }
}
