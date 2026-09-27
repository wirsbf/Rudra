//! Import function prototypes from native debug metadata.
//!
//! Ghidra imports DWARF into its Program database before the decompiler runs.
//! The decompiler then receives a locked [`crate::fspec::FuncProto`].  This
//! module provides the same front-end boundary for Rugra: it reads concrete
//! subprogram definitions (following `DW_AT_abstract_origin` and
//! `DW_AT_specification`), materializes the declared prototype, assigns
//! parameter storage from the active compiler-spec resource order, and locks
//! the result before any Action executes.
//!
//! It also imports DWARF global variables (`DW_TAG_variable` with a static
//! `DW_OP_addr` location) so their declared types reach the global
//! symbol/type boundary the same way Ghidra's DWARF analyzer attaches them
//! to the Program's symbol table.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianRcSlice, Reader, RunTimeEndian,
    SectionId, Unit, UnitOffset,
};
use object::{Object, ObjectSection};

use crate::fspec::FuncProto;
use crate::funcdata::Funcdata;
use crate::type_system::datatype::{
    Datatype, TypeArray, TypeBase, TypeEnum, TypeField, TypeMetatype, TypePointer, TypeStruct,
    TypeUnion,
};

type DwarfReader = EndianRcSlice<RunTimeEndian>;

/// One declared function parameter, in source declaration order.
#[derive(Debug, Clone)]
pub struct DebugParameter {
    pub name: String,
    /// True only when the source record carried an explicit parameter name.
    pub name_locked: bool,
    pub data_type: Arc<Datatype>,
}

/// A concrete DWARF subprogram definition and its canonical declaration.
#[derive(Debug, Clone)]
pub struct DebugPrototype {
    pub address: u64,
    pub name: String,
    pub return_type: Arc<Datatype>,
    pub parameters: Vec<DebugParameter>,
    pub is_varargs: bool,
}

/// Function-entry address to imported prototype.
#[derive(Debug, Clone, Default)]
pub struct DebugPrototypeDatabase {
    prototypes: BTreeMap<u64, DebugPrototype>,
}

/// A DWARF global-variable definition with a static address.
///
/// Mirrors the symbol-table entry Ghidra's DWARF analyzer creates for a
/// `DW_TAG_variable` carrying `DW_AT_location = DW_OP_addr <addr>`: the
/// variable's name, storage address, and declared data type.
#[derive(Debug, Clone)]
pub struct DebugGlobalVariable {
    pub address: u64,
    pub name: String,
    pub data_type: Arc<Datatype>,
    /// Name of the nearest enclosing `DW_TAG_subprogram` when the variable
    /// DIE is nested inside a function (a C function-static). Ghidra's DWARF
    /// analyzer imports those into the function's namespace, so the symbol
    /// display name is `<parent_function>::<name>` (locked-oracle witnesses:
    /// `my_get_token::save` at 0x17510, `next_url::beenhere` at 0x17518);
    /// CU-level variables keep `None` and stay in the global scope.
    pub parent_function: Option<String>,
    /// True when this entry came from the external-declaration +
    /// R_X86_64_COPY relocation pass (stdin/stdout/stderr) rather than a
    /// located DW_AT_variable DIE. Instrumented-oracle witness (lane
    /// R3MERGE, canon analyzeHeadless 12.0.4 e40ed130): those symbols reach
    /// the decompiler as TYPELOCKED `undefined8` — the DWARF analyzer's
    /// committed types land only on located variables, never on the
    /// copy-reloc externs — so `SymbolEntry::updateType` writes
    /// `updateType(undefined8,true,true)` which `varnode.cc:476-477`
    /// demotes to UNLOCKED (TYPE_UNKNOWN is never locked), leaving the
    /// varnode's data-type free for the ActionInferTypes propagation
    /// contest (locked libc prototypes push archive-FILE\*, DWARF field
    /// edges push DWARF-FILE\*/Configurable\*; most-specific wins per
    /// `typeOrder`). The driver consults this flag to seed the oracle's
    /// `undefined8` symbol type instead of the declared DWARF type; the
    /// declared type stays on `data_type` as the parse product.
    pub extern_reloc: bool,
}

/// Static-address global variables keyed by storage address.
#[derive(Debug, Clone, Default)]
pub struct DebugGlobalDatabase {
    globals: BTreeMap<u64, DebugGlobalVariable>,
    address_size: usize,
}

impl DebugGlobalDatabase {
    // RUGRA-GLUE: reads the same DW_TAG_variable + DW_OP_addr records Ghidra's Java DWARF analyzer turns into Program symbols; native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Result<Self> {
        // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: warm the archive-FILE type cache
        // before the DWARF walk — its init interns bases and a pointer
        // through the shared TypeFactory write lock, while the unit loop
        // below holds that lock across resolve_type/intern_named, and the
        // extern-declaration remap inside the loop must stay lock-free.
        let _ = clib_file_types();
        let dwarf = load_dwarf(bytes).context("parsing object for DWARF globals")?;
        let mut globals = BTreeMap::new();
        let mut address_size = 8usize;
        // DWARF-SYMFIELD-TYPESTATE-0001: external variable declarations
        // (DW_AT_declaration + DW_AT_external, no DW_AT_location) carry the
        // declared type for data-import symbols whose storage this ELF
        // defines through an R_X86_64_COPY relocation. Ghidra's DWARF
        // analyzer applies that declared type to the defined symbol — the
        // locked-oracle witnesses are `stdout`/`stdin`/`stderr` printing
        // with bare names (ElfSymbol carries the @@GLIBC version separately)
        // and the FILE* type state behind golden main's bare
        // `__stream = stdin;` / `__stream_00 = stdout;` assignments versus
        // `(FILE *)0x0` casts (ghidra_curl_1204.c:609/894/895). First
        // declaration per name wins, matching the located-global loop's
        // first-DIE-wins insert.
        let mut external_decls: HashMap<String, Arc<Datatype>> = HashMap::new();
        let mut headers = dwarf.units();
        while let Some(header) = headers.next().context("iterating DWARF units")? {
            let unit = dwarf.unit(header).context("loading DWARF unit")?;
            address_size = unit.encoding().address_size as usize;
            let mut entries = unit.entries();
            // (depth, name, is_subprogram) stack for parent-function
            // tracking. next_dfs yields (DELTA depth, entry): the isize is
            // the depth CHANGE from the previous entry (gimli unit.rs
            // EntriesTree::next_dfs — same accumulation pattern the
            // read_prototype_children/read_struct_fields walks use), so the
            // absolute level is accumulated separately and the stack is
            // popped down to it, keeping the ancestors. Treating the delta
            // as the absolute level popped the enclosing subprogram frame
            // off the stack on every first child (a +1 child of a depth-1
            // subprogram read as "depth 1" -> pop the subprogram's own
            // frame), so every function-static (DW_TAG_variable with
            // DW_OP_addr nested in a DW_TAG_subprogram) imported with
            // parent_function = None and printed its bare ELF-stripped name;
            // the locked-oracle spellings are my_get_token::save @0x17510
            // and next_url::beenhere @0x17518 (ghidra_curl_1204.c:1226+).
            let mut scope_stack: Vec<(usize, Option<String>, bool)> = Vec::new();
            let mut absolute_depth: isize = 0;
            while let Some((delta, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
                absolute_depth += delta;
                let depth = usize::try_from(absolute_depth).unwrap_or(0);
                while scope_stack.len() > depth {
                    scope_stack.pop();
                }
                let parent_function = scope_stack
                    .iter()
                    .rev()
                    .find(|(_, _, is_subprogram)| *is_subprogram)
                    .and_then(|(_, name, _)| name.clone());
                let entry_name =
                    entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)?;
                if entry.tag() != gimli::DW_TAG_variable {
                    scope_stack.push((depth, entry_name, entry.tag() == gimli::DW_TAG_subprogram));
                    continue;
                }
                // DWARF-SYMFIELD-TYPESTATE-0001: capture the declaration's
                // type by name before the storage-address gate below
                // (declarations have no DW_AT_location and would otherwise
                // be skipped without recording anything).
                if attr_flag(entry, gimli::DW_AT_declaration)?
                    && attr_flag(entry, gimli::DW_AT_external)?
                {
                    if let Some(name) = entry_name.as_deref() {
                        if !external_decls.contains_key(name) {
                            if let Some(offset) =
                                entry_reference(&unit, entry, gimli::DW_AT_type)?
                            {
                                let data_type =
                                    resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?;
                                // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: extern
                                // FILE* declarations (stdin/stdout/stderr)
                                // enter the ARCHIVE FILE domain — the
                                // golden's bare `__stream = stdin;`/
                                // `fwrite(...,stderr)` sites (no cast,
                                // ghidra_curl_1204.c:609/1406) are the
                                // same domain as the libc prototypes'
                                // FILE, while the DWARF FILE survives in
                                // subprogram parameters and struct fields
                                // (`outs.stream = (FILE *)stdout;` at :612
                                // is the domain crossing).
                                let data_type =
                                    remap_external_clib_file_pointer(data_type);
                                external_decls.insert(name.to_string(), data_type);
                            }
                        }
                    }
                }
                let Some(address) = static_location_address(&unit, entry)? else {
                    scope_stack.push((depth, entry_name, false));
                    continue;
                };
                let Some(name) = entry_name.clone() else {
                    scope_stack.push((depth, entry_name, false));
                    continue;
                };
                let data_type = match entry_reference(&unit, entry, gimli::DW_AT_type)? {
                    Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                    None => unknown_type(address_size),
                };
                globals.insert(
                    address,
                    DebugGlobalVariable {
                        address,
                        name,
                        data_type,
                        parent_function,
                        extern_reloc: false,
                    },
                );
                scope_stack.push((depth, entry_name, false));
            }
        }
        // DWARF-SYMFIELD-TYPESTATE-0001: bind the captured declaration types
        // to their copy-relocation addresses. Located globals (real
        // DW_AT_location) stay authoritative; the copy-reloc pass only adds
        // entries at addresses nothing else claimed.
        for (address, name) in copy_reloc_object_symbols(bytes) {
            if globals.contains_key(&address) {
                continue;
            }
            if let Some(data_type) = external_decls.get(&name) {
                globals.insert(
                    address,
                    DebugGlobalVariable {
                        address,
                        name,
                        data_type: data_type.clone(),
                        parent_function: None,
                        // R3MERGE-STDMERGE-TYPESTATE-0001: copy-reloc
                        // externs seed `undefined8` symbols (see the
                        // field doc + instrumented-oracle witness).
                        extern_reloc: true,
                    },
                );
            }
        }
        Ok(Self {
            globals,
            address_size,
        })
    }

    // RUGRA-GLUE: address-keyed lookup mirroring the Program database query Rugra's driver performs when seeding global types
    pub fn get(&self, address: u64) -> Option<&DebugGlobalVariable> {
        self.globals.get(&address)
    }

    // RUGRA-GLUE: deterministic address order for diagnostics around the Program-to-Funcdata import boundary
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &DebugGlobalVariable)> {
        self.globals.iter()
    }

    // RUGRA-GLUE: count accessor for diagnostics around the Program-to-Funcdata import boundary
    pub fn len(&self) -> usize {
        self.globals.len()
    }

    // RUGRA-GLUE: builds Funcdata::global_struct_ptrs entries; each address constant referencing a global gets the C "&global" type (pointer to the variable's declared type, with array decay), which Ghidra derives from its symbol-table Datatype linkage
    pub fn address_pointer_map(&self) -> HashMap<u64, Arc<Datatype>> {
        self.globals
            .values()
            .map(|global| {
                (
                    global.address, global_address_type(global, self.address_size),
                )
            })
            .collect()
    }

    // RUGRA-GLUE: the DWARF front-end's committed-data-type semantic.
    /// Ghidra's DWARF analyzer creates Data whose imported data type is
    /// committed (locked memory); the decompiler interface exports that as
    /// ATTRIB_TYPELOCK on the symbol XML, which `Symbol::decodeHeader`
    /// folds into the Symbol's typelock flag (database.cc:439-442). Both
    /// typelock-gated consumers — `SymbolEntry::updateType`
    /// (database.cc:135-141, reached via `Varnode::setSymbolProperties`
    /// varnode.cc:413) and `ActionInferTypes::buildLocaltypes`' exact-piece
    /// branch (coreaction.cc:5021-5027) — depend on it to attach a global
    /// Symbol's DWARF type onto the address varnode RuleLoadVarnode
    /// materializes (ruleaction.cc:4293 `newVarnode` → `queryProperties` →
    /// `setSymbolProperties`). Rugra's driver seeds the query-channel
    /// Database directly, so the typelock fold lives here as the single
    /// front-end semantic.
    pub fn seed_global_locked(
        db: &mut crate::database::Database,
        scope_id: u64,
        address: u64,
        name: &str,
        dtype: Arc<Datatype>,
        size: i32,
    ) -> Option<u64> {
        let symbol_id =
            db.add_symbol_mapped(scope_id, name, Some(dtype), crate::address::Address::new(address), size);
        if let Some(symbol_id) = symbol_id {
            db.set_symbol_flag(scope_id, symbol_id, crate::database::symbol_flags::TYPELOCK, true);
        }
        symbol_id
    }
}

/// PLT thunk entries keyed by thunk entry address.
///
/// Mirrors the function symbols Ghidra's ELF front-end creates for every PLT
/// thunk: a `.plt.sec`/`.plt` slot (an `endbr64; bnd jmp *disp32(%rip)`
/// sequence jumping through a GOT slot owned by an
/// `R_X86_64_JUMP_SLOT`/`.rela.plt` relocation) or a `.plt.got` slot (whose
/// GOT slot is owned by an `R_X86_64_GLOB_DAT` relocation in `.rela.dyn`)
/// becomes a thunk Function named after the dynamic import it resolves. The
/// decompiler side then reads that name through the call-spec chain
/// (`FlowInfo::queryCall` flow.cc:656-672 → `FuncCallSpecs::setFuncdata`
/// fspec.cc:4949-4960 → `PrintC::opCall` printc.cc:601-609 `fc->getName()`),
/// which is why an undefined dynamic import (`apr_app_initialize`,
/// st_value==0, lives in libapr) still prints its name at every direct call
/// site of the thunk in the locked httpd oracle
/// (tests/golden/ghidra_httpd_1204.c: `apr_app_initialize(auStack_9c,...)`
/// for the 0x12a6d0 thunk). Without this import a call target address has no
/// symbol anywhere, `Funcdata::map_globals`'s no-symbol arm builds a
/// `uRam<offset>` data-global name for it (varmap.rs build_variable_name
/// mirroring database.cc:2455-2468), and the printer shows `uRam...()` as
/// the callee.
#[derive(Debug, Clone, Default)]
pub struct ElfPltImports {
    thunks: BTreeMap<u64, String>,
}

impl ElfPltImports {
    /// Import every PLT thunk name from the ELF image.
    ///
    /// `.plt.sec`/`.plt` slots are matched to `.rela.plt` JUMP_SLOT
    /// relocations by slot index (`i`-th relocation ↔ `base + 16*i`, with
    /// `.plt` slots starting at index 1 to skip the resolver header);
    /// `.plt.got` slots are decoded individually (the `f2 ff 25 <disp32>`
    /// tail) and matched against the R_X86_64_GLOB_DAT relocation that owns
    /// the jumped-through GOT address. Slot geometry and matching follow the
    /// locked-oracle witnesses documented with the original driver-side
    /// implementation (examples/curl_decompile.rs PLT resolution block;
    /// httpd witnesses: slot 43 = 0x2a6d0 = `apr_app_initialize`,
    /// `.plt` @0x29020, `.plt.got` @0x2a400, `.plt.sec` @0x2a420).
    // RUGRA-GLUE: reads the same .plt/.plt.sec/.plt.got + relocation records Ghidra's Java ELF/PLT analyzer turns into thunk Function symbols; native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Self {
        let obj = match goblin::Object::parse(bytes) {
            Ok(obj) => obj,
            Err(_) => return Self::default(),
        };
        let goblin::Object::Elf(elf) = obj else {
            return Self::default();
        };
        let mut thunks = BTreeMap::new();

        let mut plt_sec_base = 0u64;
        let mut plt_base = 0u64;
        let mut plt_got: Option<(u64, u64, u64)> = None; // (sh_addr, sh_offset, sh_size)
        for header in elf.section_headers.iter() {
            if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
                match name {
                    ".plt" => plt_base = header.sh_addr,
                    ".plt.sec" => plt_sec_base = header.sh_addr,
                    ".plt.got" => {
                        plt_got =
                            Some((header.sh_addr, header.sh_offset, header.sh_size))
                    }
                    _ => {}
                }
            }
        }

        // .plt.sec (or .plt) via .rela.plt JUMP_SLOT relocations.
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
                            thunks
                                .entry(plt_addr)
                                .or_insert_with(|| name.to_string());
                        }
                    }
                }
            }
        }

        // .plt.got slots: GOT owners are R_X86_64_GLOB_DAT relocations in
        // .rela.dyn (not .rela.plt), so the slot-index loop above misses
        // them; decode each slot's `f2 ff 25 <disp32>` tail directly.
        if let Some((slot_vaddr, file_off, sh_size)) = plt_got {
            for slot in 0..(sh_size as usize / 8) {
                let start = file_off as usize + slot * 8;
                let Some(insn) = bytes.get(start..start + 11) else {
                    continue;
                };
                if insn[4] != 0xf2 || insn[5] != 0xff || insn[6] != 0x25 {
                    continue;
                }
                let disp =
                    i32::from_le_bytes([insn[7], insn[8], insn[9], insn[10]]) as i64;
                let got_addr = (slot_vaddr + slot as u64 + 11) as i64 + disp;
                let name = elf
                    .dynrelas
                    .iter()
                    .chain(elf.dynrels.iter())
                    .find_map(|reloc| {
                        if reloc.r_offset != got_addr as u64 {
                            return None;
                        }
                        elf.dynsyms
                            .get(reloc.r_sym)
                            .and_then(|sym| elf.dynstrtab.get_at(sym.st_name))
                            .filter(|name| !name.is_empty())
                    });
                if let Some(name) = name {
                    thunks
                        .entry(slot_vaddr + slot as u64)
                        .or_insert_with(|| name.to_string());
                }
            }
        }

        Self { thunks }
    }

    // RUGRA-GLUE: address-keyed lookup mirroring the Program database query the driver performs when seeding call-target symbols
    pub fn get(&self, address: u64) -> Option<&String> {
        self.thunks.get(&address)
    }

    // RUGRA-GLUE: deterministic address order for the driver-side seeding loop
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &String)> {
        self.thunks.iter()
    }

    // RUGRA-GLUE: count accessor for import-boundary diagnostics
    pub fn len(&self) -> usize {
        self.thunks.len()
    }

    // RUGRA-GLUE: emptiness accessor for the clippy len-without-is_empty pair
    pub fn is_empty(&self) -> bool {
        self.thunks.is_empty()
    }

    // RUGRA-GLUE: thunk-membership test used to gate the default FUN_ naming pass (a thunk already carries its import name)
    pub fn contains(&self, address: u64) -> bool {
        self.thunks.contains_key(&address)
    }
}

/// Default name for an analysis-discovered function symbol, mirroring the
/// locked-oracle convention: Ghidra's front-end names every function the
/// analysis creates (and no ELF symbol covers) `FUN_` + the entry address in
/// 8-digit zero-padded hex — on the analyzeHeadless **image base** address,
/// not the raw ELF virtual address (the httpd oracle loads the ET_DYN image
/// at 0x100000, so the golden's shared tail chunks read `FUN_0012c520` for
/// ELF vaddr 0x2c520). The decompiler prints such names verbatim at call
/// sites through the same fspec chain as named functions
/// (`PrintC::opCall` printc.cc:601-609); Rugra's driver seeds the name into
/// its callpoint-symbol stand-in for that table.
// RUGRA-GLUE: Ghidra's Java SymbolManager owns this default-name policy (outside decompile/cpp); native front-end adapter for the boundary
pub fn analyze_headless_function_symbol_name(vaddr: u64, image_base: u64) -> String {
    format!("FUN_{:08x}", image_base.wrapping_add(vaddr))
}

// RUGRA-GLUE: index of DWARF named types (struct/union/enum/typedef spellings)
// built at the Program-import boundary. Ghidra's DWARF analyzer populates the
// program type manager with these names, and the platform signature loader
// resolves signature base spellings (e.g. `FILE`) against that manager; this
// index is the driver-side equivalent handed to `LibcSignatureTable::locked_proto`.
// First definition wins on duplicate names (Ghidra suffixes conflicts; the
// locked curl corpus has none).
pub fn parse_type_names(bytes: &[u8]) -> Result<HashMap<String, Arc<Datatype>>> {
    let dwarf = load_dwarf(bytes).context("parsing object for DWARF named types")?;
    let mut names: HashMap<String, Arc<Datatype>> = HashMap::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().context("iterating DWARF units")? {
        let unit = dwarf.unit(header).context("loading DWARF unit")?;
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
            let named = matches!(
                entry.tag(),
                gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_union_type
                    | gimli::DW_TAG_enumeration_type
                    | gimli::DW_TAG_typedef
                    | gimli::DW_TAG_base_type
            );
            if !named {
                continue;
            }
            let Some(name) = entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)? else {
                continue;
            };
            if names.contains_key(&name) {
                continue;
            }
            // DWARF-SYMFIELD-TYPESTATE-0001: a DW_TAG_typedef entry resolves
            // through the typedef DIE ITSELF, not its DW_AT_type target, so
            // the index keeps the typedef spelling the way Ghidra's DWARF
            // front end keeps a TypeTypedef (type.hh:522) — resolve_type's
            // typedef branch materializes the underlying composite renamed
            // to the typedef name (the `FILE` over `struct _IO_FILE`, golden
            // witnesses `FILE *__stream` decls / `(FILE *)0x0` casts in
            // ghidra_curl_1204.c main; resolving the raw target printed the
            // struct spelling `_IO_FILE *` in every libc signature and
            // cast). Struct/union/enum/base entries have no DW_AT_type and
            // keep resolving themselves directly.
            let data_type = if entry.tag() == gimli::DW_TAG_typedef {
                resolve_type(&dwarf, &unit, entry.offset(), 0, &mut Vec::new())?
            } else {
                match entry_reference(&unit, entry, gimli::DW_AT_type)? {
                    Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                    None => resolve_type(&dwarf, &unit, entry.offset(), 0, &mut Vec::new())?,
                }
            };
            names.insert(name, data_type);
        }
    }
    Ok(names)
}

// RUGRA-GLUE: shared DWARF section loader for the prototype and global importers
fn load_dwarf(bytes: &[u8]) -> Result<Dwarf<DwarfReader>> {    let object = object::File::parse(bytes).context("parsing object for DWARF sections")?;
    let endian = if object.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    Dwarf::load(|id: SectionId| {
        let data = match object.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?,
            None => Cow::Borrowed(&[][..]),
        };
        let owned: Rc<[u8]> = Rc::from(data.as_ref());
        Ok::<DwarfReader, object::Error>(EndianRcSlice::new(owned, endian))
    })
    .context("loading DWARF sections")
}

// RUGRA-GLUE: extracts a variable's static storage address from DW_AT_location; accepts exactly DW_OP_addr (the form Ghidra's analyzer requires for a global symbol), skipping register/complex expressions deterministically
fn static_location_address(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Option<u64>> {
    let Some(AttributeValue::Exprloc(expression)) = entry.attr_value(gimli::DW_AT_location)?
    else {
        return Ok(None);
    };
    let mut operations = expression.operations(unit.encoding());
    let Some(first) = operations.next()? else {
        return Ok(None);
    };
    let gimli::Operation::Address { address } = first else {
        return Ok(None);
    };
    if operations.next()?.is_some() {
        return Ok(None);
    }
    Ok(Some(address))
}

// RUGRA-GLUE: reads a DWARF boolean attribute accepting the flag and udata
// forms producers emit for DW_AT_declaration/DW_AT_external; absent means
// false, matching the Java analyzer's null-vs-present check
fn attr_flag(
    entry: &DebuggingInformationEntry<DwarfReader>,
    attribute: gimli::DwAt,
) -> Result<bool> {
    Ok(match entry.attr_value(attribute)? {
        Some(gimli::AttributeValue::Flag(value)) => value,
        Some(gimli::AttributeValue::Udata(value)) => value != 0,
        _ => false,
    })
}

// RUGRA-GLUE: enumerates R_X86_64_COPY relocation targets with their
// version-stripped object symbol names — the data imports (the
// stdout/stdin/stderr-class .bss copies) whose declared DWARF type Ghidra's
// analyzer applies to the locally-defined symbol. The symbol display name
// carries no @@VERSION suffix (the oracle's ElfSymbol table keeps the
// version in a separate field; golden prints bare `stdout`/`stdin`/
// `stderr`), so the ELF strtab spelling is cut at the first '@'.
fn copy_reloc_object_symbols(bytes: &[u8]) -> Vec<(u64, String)> {
    let Ok(elf) = goblin::elf::Elf::parse(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for reloc in &elf.dynrelas {
        if reloc.r_type != goblin::elf::reloc::R_X86_64_COPY {
            continue;
        }
        let Some(sym) = elf.dynsyms.get(reloc.r_sym) else {
            continue;
        };
        if goblin::elf::sym::st_type(sym.st_info) != goblin::elf::sym::STT_OBJECT {
            continue;
        }
        let Some(full) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        let Some(stripped) = full.split('@').next() else {
            continue;
        };
        if stripped.is_empty() || sym.st_value == 0 {
            continue;
        }
        out.push((sym.st_value, stripped.to_string()));
    }
    out
}

// RUGRA-GLUE: the type of an address constant that references a DWARF global; "&global" is a pointer to the variable's declared type, and arrays decay to element pointers per C address-of semantics on the IR
fn global_address_type(global: &DebugGlobalVariable, ptr_size: usize) -> Arc<Datatype> {
    if let Datatype::Array(array) = global.data_type.as_ref() {
        return pointer_type(array.array_of.clone(), ptr_size);
    }
    pointer_type(global.data_type.clone(), ptr_size)
}

impl DebugPrototypeDatabase {
    // RUGRA-GLUE: Ghidra's Java DWARF analyzer populates the Program database before the C++ decompiler; this is Rugra's native front-end adapter for that boundary
    pub fn parse_elf(bytes: &[u8]) -> Result<Self> {
        let dwarf = load_dwarf(bytes).context("parsing object for DWARF prototypes")?;

        let mut prototypes = BTreeMap::new();
        let mut headers = dwarf.units();
        while let Some(header) = headers.next().context("iterating DWARF units")? {
            let unit = dwarf.unit(header).context("loading DWARF unit")?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().context("walking DWARF DIEs")? {
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let Some(address) = subprogram_address(&dwarf, &unit, entry)? else {
                    continue;
                };
                let canonical = canonical_subprogram_offset(&unit, entry.offset())?;
                let canonical_entry = unit
                    .entry(canonical)
                    .context("reading canonical subprogram DIE")?;
                let name = entry_string(&dwarf, &unit, &canonical_entry, gimli::DW_AT_name)?
                    .or(entry_string(&dwarf, &unit, entry, gimli::DW_AT_name)?)
                    .unwrap_or_else(|| format!("FUN_{address:08x}"));
                let return_type = match entry_reference(&unit, &canonical_entry, gimli::DW_AT_type)?
                {
                    Some(offset) => resolve_type(&dwarf, &unit, offset, 0, &mut Vec::new())?,
                    None => void_type(),
                };
                let (parameters, is_varargs) = read_prototype_children(&dwarf, &unit, canonical)?;
                prototypes.insert(
                    address,
                    DebugPrototype {
                        address,
                        name,
                        return_type,
                        parameters,
                        is_varargs,
                    },
                );
            }
        }
        Ok(Self { prototypes })
    }

    // RUGRA-GLUE: address-keyed lookup mirrors the Program database query performed before Ghidra constructs Funcdata
    pub fn get(&self, address: u64) -> Option<&DebugPrototype> {
        self.prototypes.get(&address)
    }

    // RUGRA-GLUE: exposes deterministic address order for front-end prototype seeding; Ghidra's Program database iterator is outside decompile/cpp
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &DebugPrototype)> {
        self.prototypes.iter()
    }

    // RUGRA-GLUE: count accessor for diagnostics around the Program-to-Funcdata import boundary
    pub fn len(&self) -> usize {
        self.prototypes.len()
    }

    // RUGRA-GLUE: applies a Program-database prototype to Rugra Funcdata before Actions, matching Ghidra's externally locked prototype boundary
    pub fn apply(&self, fd: &mut Funcdata) -> Result<bool> {
        let Some(debug_proto) = self.get(fd.baseaddr.as_u64()) else {
            return Ok(false);
        };
        let model_carrier = fd.funcp.clone();
        fd.funcp = self.locked_proto(debug_proto, &model_carrier)?;
        Ok(true)
    }

    /// Materialize the locked call-site `FuncProto` for a callee entry
    /// address, mirroring the other half of the same Program-database
    /// boundary: `FlowInfo::queryCall` (flow.cc:656-672) resolves the callee
    /// `Funcdata` whose DWARF signature the analyzer locked, and
    /// `ActionDefaultParams` (coreaction.cc:2322-2330) copies that whole
    /// callee prototype onto the call site with
    /// `fc->copy(otherfunc->getFuncProto())` — `FuncProto::copy`
    /// (fspec.cc:3789-3804) transfers the model pointer, the flag word
    /// (every lock bit), and a clone of the parameter store, so the call
    /// site ends up with the callee's locked parameter list verbatim.
    ///
    /// `model_carrier` supplies the model exactly as the callee's own
    /// `Funcdata` would have bound it: the Architecture default model both
    /// the decompiled function and every DWARF-analyzed callee carry (the
    /// same carrier `apply` clones from `fd.funcp` after
    /// `Funcdata::set_arch`'s named-ctor binding, FUNCPROTO-MODEL-BIND-0001).
    ///
    /// Returns `Ok(None)` when the address has no DWARF definition (import
    /// thunk / non-debug function: the boundary contributes nothing and the
    /// generic_clib import table or active recovery owns the call site).
    // RUGRA-GLUE: the queryCall -> ActionDefaultParams copy boundary for DWARF-locked callees; Ghidra reaches it via the Program database, Rugra's driver hands it directly
    pub fn locked_callsite_proto(
        &self,
        entry: u64,
        model_carrier: &FuncProto,
    ) -> Result<Option<FuncProto>> {
        let Some(debug_proto) = self.get(entry) else {
            return Ok(None);
        };
        self.locked_proto(debug_proto, model_carrier).map(Some)
    }

    // RUGRA-GLUE: shared locked-signature builder behind both halves of the
    // DWARF Program-database boundary (own-function apply + call-site copy);
    // the lock recipe mirrors FuncProto::setPieces (fspec.cc:3843-3852):
    // assigned storage, DW_AT_name-gated NAME_LOCKED bits, input/output/model
    // locks, and the void-signature unknown-model pin below.
    fn locked_proto(
        &self,
        debug_proto: &DebugPrototype,
        model_carrier: &FuncProto,
    ) -> Result<FuncProto> {
        if !model_carrier.has_model() {
            bail!(
                "DWARF prototype {} has no bound ProtoModel", debug_proto.name
            );
        }
        let mut proto = FuncProto::from_model_carrier(
            model_carrier,
            debug_proto.name.clone(),
            debug_proto.return_type.clone(),
        );
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: debug_proto.name.clone(),
            out_type: Some(debug_proto.return_type.clone()),
            in_types: debug_proto
                .parameters
                .iter()
                .map(|parameter| parameter.data_type.clone())
                .collect(),
            in_names: debug_proto
                .parameters
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect(),
            first_var_arg_slot: if debug_proto.is_varargs {
                debug_proto.parameters.len() as i32
            } else {
                -1
            },
        };
        proto.name = debug_proto.name.clone();
        proto.set_pieces(&pieces);
        if proto.has_input_errors() {
            bail!(
                "compiler model cannot assign parameter storage for DWARF prototype {}",
                debug_proto.name
            );
        }
        let mut source_index = 0usize;
        for param in &mut proto.parameters {
            if param.is_hidden_return() {
                continue;
            }
            let Some(parameter) = debug_proto.parameters.get(source_index) else {
                break;
            };
            // Ghidra's DWARF import locks only real DW_AT_name parameter
            // names (ProtoStoreSymbol::setInput mirrors
            // ParameterPieces::namelock onto the symbol, fspec.cc:3158/:3180);
            // a nameless DIE stays unnamed and the decompiler's default
            // naming (buildDefaultName) owns it — so the synthesized
            // param_N stand-in is NOT name-locked (lookForFuncParamNames
            // additionally filters the param_ prefix, coreaction.cc:2831).
            if parameter.name_locked {
                param.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
            }
            source_index += 1;
        }
        // DWARF-VOID-UNKNOWN-MODEL-0001: a 0-param DWARF signature with no
        // return-location DIE takes Ghidra's StorageVerification downgrade
        // path (funcfixup/StorageVerificationDWARFFunctionFixup.java:
        // `isEmptySignature = params.isEmpty() && retval.isMissingStorage()`
        // → CommitMode.FORMAL → updateFunctionSignature runs with
        // DYNAMIC_STORAGE_ALL_PARAMS, so hasCustomVariableStorage() is
        // false), and the DWARF analyzer passes callingConventionName=null
        // (DWARFImportOptions defaultCC is blank and DW_AT_calling_convention
        // is absent) — FunctionDB.updateFunction(null,...) keeps the
        // never-assigned convention, and FunctionPrototype.grabFromFunction
        // (FunctionPrototype.java:129-141) reads it back as "unknown",
        // sending the decompiler model="unknown", which
        // FuncProto::decode routes to createUnknownModel (architecture.cc:
        // 1159-1166; "unknown" is printInDecl=false). grabFromFunction also
        // derives voidinputlock = (sigSource != DEFAULT) && paramCount == 0
        // → true (already set by set_pieces' set_input_lock on the empty
        // list). The combined observable, via ActionPrototypeWarnings
        // (coreaction.cc:4901-4908), is the golden's
        // "WARNING: Unknown calling convention -- yet parameter storage is
        // locked" on exactly the three 0-param DWARF locals (main_init,
        // main_free, hugehelp). Param'd DWARF signatures keep STORAGE commit
        // mode (custom storage, custom_storage flag suppresses the warning
        // in the oracle) and Rugra keeps the resolved default model name,
        // which suppresses the warning identically — so the pin applies to
        // the empty-signature case only.
        if debug_proto.parameters.is_empty() {
            proto.set_model_name("unknown");
        }
        Ok(proto)
    }
}

/// One locked public-libc ABI declaration for an imported symbol, kept in the
/// exact C-declaration spelling Ghidra's shipped generic_clib signature data
/// carries (glibc reserved `__`-prefixed parameter names included).
///
/// Ghidra's decompile/cpp never parses this table: the platform side loads the
/// signature data into the Program database and the locked `FuncProto` reaches
/// the decompiler already materialized (queried by `FlowInfo::queryCall`
/// flow.cc:660 and copied to call sites by `ActionDefaultParams`
/// coreaction.cc:2327). This table is Rugra's native front-end adapter for
/// that same boundary.
#[derive(Debug, Clone)]
pub struct LibcSignature {
    pub return_type: &'static str,
    pub parameters: &'static str,
}

/// Locked libc ABI signatures keyed by imported symbol name. Rugra's minimal
/// equivalent of Ghidra's generic_clib signature data: the same public glibc
/// ABI declarations verbatim. Anything not in the table keeps the unlocked
/// `void F(void)` form (matching the external-stub rendering).
#[derive(Debug, Clone)]
pub struct LibcSignatureTable {
    entries: HashMap<&'static str, LibcSignature>,
}

// GLIBC-CLIB-FILE-TYPEDOMAIN-0001 (CANON-VARNAM-NAMEREC-TIEBREAK-0001):
// the generic_clib_64 archive's own FILE, distinct from the DWARF FILE.
//
// The locked curl canon golden proves the oracle's type graph carried TWO
// FILE structures that never unified:
//   - the generic_clib_64 archive FILE behind every locked libc prototype
//     (fclose/fgets/fwrite/fputc/fileno param, fopen return) AND behind
//     the extern std-stream globals (stdin/stdout/stderr — the golden's
//     bare `__stream = stdin;` and `fwrite(...,stderr)` sites): its
//     struct layout is the glibc compat form whose slots at offsets
//     152..176 are named `__pad1..__pad4` — extracted from the locked
//     oracle tree's own
//     `Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt`
//     (field-name table, 29 fields, 216 bytes);
//   - curl's DWARF FILE (typedef FILE -> struct _IO_FILE, the same 29
//     field slots but offsets 152..176 named `_codecvt/_wide_data/
//     _freeres_list/_freeres_buf` per the binary's .debug_info), behind
//     the DWARF subprogram prototypes and struct fields.
// Both print `FILE *`, but they are different Datatype objects, and two
// observable oracle behaviors depend on that split:
//   1. ActionNameVars::lookForFuncParamNames' repeat recommendation
//      tie-break (coreaction.cc:2833-2845): parseconfig's FILE* local gets
//      `fp` (my_get_line's DWARF FILE*) recommended first (callspec order),
//      then `__stream` (fclose's archive FILE*) — TypeStruct::compare walks
//      offset/name/metatype per field and returns +1 at the FIRST name
//      difference (offset 152: `_codecvt` > `__pad1` string-wise), so the
//      archive recommendation overrides and the golden names the local
//      `__stream` (the pre-fix single-FILE model ties at typeOrder 0 and
//      keeps `fp`).
//   2. ActionSetCasts' call-argument casts: castStandard strips typedefs
//      and compares the pointee structs BY IDENTITY (cast.cc:325), so the
//      split produces exactly the golden's `(FILE *)` casts at the
//      domain-crossing call sites (ghidra_curl_1204.c:1300
//      `my_get_line((FILE *)__stream)`) and bare args where both sides
//      are in one domain (`fclose(__stream)`).
// The struct is deliberately NOT registered in the factory name tree: the
// name slot "FILE" belongs to the DWARF materialized alias, and
// intern_named's (name, shape, size, metatype) dedupe would collapse the
// two domains back into one type. It lives in this process-wide OnceLock
// together with its factory-interned pointer (ONE TypePointer object, so
// ActionMergeType's same-type grouping sees a single stable identity per
// domain). The cache MUST be warmed outside any factory lock scope —
// init takes the factory write lock briefly (base/pointer interning), and
// the DWARF walk holds that lock across its unit loop
// (DebugGlobalDatabase::parse_elf warms it first thing for this reason).
// RUGRA-GLUE: native front-end adapter for the platform-side type state —
// Ghidra's generic_clib_64.gdt owns this FILE structure on the Java side
// and hands it to the decompiler already materialized per locked
// signature; Rugra builds the same type graph once per process.
pub(crate) fn clib_file_types(
) -> &'static (Arc<Datatype>, Arc<Datatype>) {
    static CLIB_FILE: std::sync::OnceLock<(Arc<Datatype>, Arc<Datatype>)> =
        std::sync::OnceLock::new();
    CLIB_FILE.get_or_init(|| {
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let int4 = factory_named_base(&types, 4, TypeMetatype::Int, "int");
        let long8 = factory_named_base(&types, 8, TypeMetatype::Int, "long");
        let uint2 = factory_named_base(&types, 2, TypeMetatype::Uint, "ushort");
        let size8 = factory_named_base(&types, 8, TypeMetatype::Uint, "size_t");
        let char1 = {
            let factory = types
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            factory
                .find_by_name("char")
                .or_else(|| factory.get_type_char(1).ok())
                .expect("TypeFactory cannot build the char type")
        };
        let (char_ptr, shortbuf, unused2) = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let char_ptr = factory.get_type_pointer_default(char1.clone());
            let shortbuf = factory.get_array(char1.clone(), 1);
            let unused2 = factory.get_array(char1.clone(), 20);
            (char_ptr, shortbuf, unused2)
        };
        let field = |offset: usize, name: &str, type_ptr: Arc<Datatype>| TypeField {
            name: name.to_string(),
            offset,
            type_ptr,
        };
        let fields = vec![
            field(0, "_flags", int4.clone()),
            field(8, "_IO_read_ptr", char_ptr.clone()),
            field(16, "_IO_read_end", char_ptr.clone()),
            field(24, "_IO_read_base", char_ptr.clone()),
            field(32, "_IO_write_base", char_ptr.clone()),
            field(40, "_IO_write_ptr", char_ptr.clone()),
            field(48, "_IO_write_end", char_ptr.clone()),
            field(56, "_IO_buf_base", char_ptr.clone()),
            field(64, "_IO_buf_end", char_ptr.clone()),
            field(72, "_IO_save_base", char_ptr.clone()),
            field(80, "_IO_backup_base", char_ptr.clone()),
            field(88, "_IO_save_end", char_ptr.clone()),
            field(96, "_markers", char_ptr.clone()),
            field(104, "_chain", char_ptr.clone()),
            field(112, "_fileno", int4.clone()),
            field(116, "_flags2", int4.clone()),
            field(120, "_old_offset", long8.clone()),
            field(128, "_cur_column", uint2),
            field(130, "_vtable_offset", char1),
            field(131, "_shortbuf", shortbuf),
            field(136, "_lock", char_ptr.clone()),
            field(144, "_offset", long8),
            field(152, "__pad1", char_ptr.clone()),
            field(160, "__pad2", char_ptr.clone()),
            field(168, "__pad3", char_ptr.clone()),
            field(176, "__pad4", char_ptr),
            field(184, "__pad5", size8),
            field(192, "_mode", int4),
            field(196, "_unused2", unused2),
        ];
        let mut base = TypeBase::new("FILE".to_string(), 216, TypeMetatype::Struct);
        base.alignment = 8;
        base.align_size = 216;
        let structure = Arc::new(Datatype::Struct(TypeStruct { base, fields }));
        let pointer = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            factory.get_type_pointer_default(structure.clone())
        };
        (structure, pointer)
    })
}

/// The archive FILE struct (pass to a base-spelling override map).
// RUGRA-GLUE: accessor over the clib_file_types OnceLock (see above).
pub(crate) fn clib_file_struct() -> Arc<Datatype> {
    clib_file_types().0.clone()
}

// CURLCANON-CASTA-STAT-0001: the archive stat struct — the second archive
// type the generic_clib signature boundary owns (R1 of PROTOCAST43's A-族
// residual roots). The locked oracle's golden prints
// `__xstat(1,x,(stat *)&fileinfo)` (main:797/:878, getparameter:2105): the
// signature's `stat *` and the local's DWARF `stat *` are TWO type objects
// (CastStrategyC::castStandard's `curbase == reqbase` pointer-identity
// early-exit, cast.cc:304/:329, does NOT fire through the struct default
// arm :387 — distinct objects of equal 144-byte size cast). Rugra resolved
// the libc ledger's `stat` spelling through the DWARF name index, so the
// signature param and fileinfo's local shared ONE interned DWARF struct
// and the cast was suppressed (`&fileinfo`). The archive domain below is
// the same two-universe split the archive FILE holds
// (GLIBC-CLIB-FILE-TYPEDOMAIN-0001): a standalone glibc x86-64
// bits/stat.h layout (the 144-byte 15-field form curl's own DWARF
// <444> struct stat carries: st_dev..__glibc_reserved), built directly —
// never name-interned into the factory tree — so the DWARF `stat`
// (interned by struct_type) and this archive `stat` stay distinct
// objects; TypeStruct::compare (type.cc:1742-1780) then orders them by
// object id at equal field/size shape (both derive from the same glibc
// header, the tie the locked oracle's two stat objects also hold).
// RUGRA-GLUE: the platform signature loader materializes generic_clib's
// own stat from the archive data before the decompiler runs (same Java
// seam as the archive FILE); this OnceLock is Rugra's form of that graph.
pub(crate) fn clib_stat_types(
) -> &'static (Arc<Datatype>, Arc<Datatype>) {
    static CLIB_STAT: std::sync::OnceLock<(Arc<Datatype>, Arc<Datatype>)> =
        std::sync::OnceLock::new();
    CLIB_STAT.get_or_init(|| {
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let long8 = factory_named_base(&types, 8, TypeMetatype::Int, "long");
        let ulong8 = factory_named_base(&types, 8, TypeMetatype::Uint, "ulong");
        let uint4 = factory_named_base(&types, 4, TypeMetatype::Uint, "uint");
        let int4 = factory_named_base(&types, 4, TypeMetatype::Int, "int");
        // struct timespec { __time_t tv_sec; long tv_nsec; } — 16 bytes,
        // built standalone like the surrounding archive structs (never
        // name-interned; the DWARF-side timespec keeps its own object).
        let timespec = {
            let mut base = TypeBase::new("timespec".to_string(), 16, TypeMetatype::Struct);
            base.alignment = 8;
            base.align_size = 16;
            Arc::new(Datatype::Struct(TypeStruct {
                base,
                fields: vec![
                    TypeField {
                        name: "tv_sec".to_string(),
                        offset: 0,
                        type_ptr: long8.clone(),
                    },
                    TypeField {
                        name: "tv_nsec".to_string(),
                        offset: 8,
                        type_ptr: long8.clone(),
                    },
                ],
            }))
        };
        let glibc_reserved = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            factory.get_array(long8.clone(), 3)
        };
        let field = |offset: usize, name: &str, type_ptr: Arc<Datatype>| TypeField {
            name: name.to_string(),
            offset,
            type_ptr,
        };
        // glibc x86-64 bits/stat.h field order (offsets are the ABI's):
        // st_dev@0 st_ino@8 st_nlink@16 st_mode@24 st_uid@28 st_gid@32
        // __pad0@36 st_rdev@40 st_size@48 st_blksize@56 st_blocks@64
        // st_atim@72 st_mtim@88 st_ctim@104 __glibc_reserved[3]@120.
        let fields = vec![
            field(0, "st_dev", ulong8.clone()),
            field(8, "st_ino", ulong8.clone()),
            field(16, "st_nlink", ulong8.clone()),
            field(24, "st_mode", uint4.clone()),
            field(28, "st_uid", uint4.clone()),
            field(32, "st_gid", uint4),
            field(36, "__pad0", int4),
            field(40, "st_rdev", ulong8),
            field(48, "st_size", long8.clone()),
            field(56, "st_blksize", long8.clone()),
            field(64, "st_blocks", long8.clone()),
            field(72, "st_atim", timespec.clone()),
            field(88, "st_mtim", timespec.clone()),
            field(104, "st_ctim", timespec),
            field(120, "__glibc_reserved", glibc_reserved),
        ];
        let mut base = TypeBase::new("stat".to_string(), 144, TypeMetatype::Struct);
        base.alignment = 8;
        base.align_size = 144;
        let structure = Arc::new(Datatype::Struct(TypeStruct { base, fields }));
        let pointer = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            factory.get_type_pointer_default(structure.clone())
        };
        (structure, pointer)
    })
}

/// The archive stat struct (pass to a base-spelling override map).
// RUGRA-GLUE: accessor over the clib_stat_types OnceLock (see above).
pub(crate) fn clib_stat_struct() -> Arc<Datatype> {
    clib_stat_types().0.clone()
}

// GLIBC-CLIB-FILE-TYPEDOMAIN-0001: the generic_clib signature boundary's
// base-spelling index — the DWARF named-type index with the FILE spelling
// overridden to the archive domain (locked_proto parses every ledger
// spelling through exactly this map).
// CURLCANON-CASTA-STAT-0001: the same override now carries the archive
// stat — the locked oracle's __xstat signature `stat *` is the archive's
// own struct, never the CU-local DWARF stat (golden :797/:878/:2105 keep
// the `(stat *)` cast between the two domains; a name-index resolution
// collapses them to one object and castStandard cc:304 suppresses it).
// RUGRA-GLUE: the platform signature loader resolves spellings against the
// Program type manager where the archive FILE/stat already live (the Java
// side never consults the DWARF name index for a generic_clib signature);
// this map is Rugra's form of that resolution boundary.
fn libc_type_resolution_index(
    type_names: Option<&HashMap<String, Arc<Datatype>>>,
) -> HashMap<String, Arc<Datatype>> {
    let mut index = match type_names {
        Some(names) => names.clone(),
        None => HashMap::new(),
    };
    index.insert("FILE".to_string(), clib_file_struct());
    index.insert("stat".to_string(), clib_stat_struct());
    index
}

/// The factory-interned pointer to the archive FILE (the std-stream
/// globals' domain).
// RUGRA-GLUE: accessor over the clib_file_types OnceLock (see above).
pub(crate) fn clib_file_pointer() -> Arc<Datatype> {
    clib_file_types().1.clone()
}

// GLIBC-CLIB-FILE-TYPEDOMAIN-0001 helper: replace a pointer-to-FILE
// (either the DWARF materialized alias spelling `FILE` or the raw struct
// spelling `_IO_FILE`) with the factory-interned pointer to the archive
// FILE. Anything else passes through unchanged. Lock-free: the pointer
// comes from the warmed OnceLock cache, never the factory.
// RUGRA-GLUE: mirrors the platform DWARF analyzer's symbol-typing seam —
// extern FILE* declarations resolve their spelling against the Program
// type manager's archive FILE, while DIE-graph references (parameters,
// struct fields) keep the CU-local DWARF type.
fn remap_external_clib_file_pointer(dt: Arc<Datatype>) -> Arc<Datatype> {
    if let Datatype::Pointer(tp) = dt.as_ref() {
        let ptr_to = &tp.ptr_to;
        if ptr_to.get_metatype() == TypeMetatype::Struct
            && (ptr_to.get_name() == "FILE" || ptr_to.get_name() == "_IO_FILE")
        {
            return clib_file_pointer();
        }
    }
    dt
}

// GLIBC-CLIB-FILE-TYPEDOMAIN-0001 helper: replace a pointer-to-FILE
impl Default for LibcSignatureTable {
    // RUGRA-GLUE: Ghidra draws these from its shipped generic_clib signature
    // data on the platform side; Rugra encodes the same public glibc ABI
    // declarations verbatim (the 24 imports the locked curl input references)
    fn default() -> Self {
        let entries: Vec<(&'static str, &'static str, &'static str)> = vec![
            ("free", "void", "void *__ptr"),
            ("malloc", "void *", "size_t __size"),
            ("realloc", "void *", "void *__ptr,size_t __size"),
            ("memcpy", "void *", "void *__dest,void *__src,size_t __n"),
            ("strlen", "size_t", "char *__s"),
            ("strcpy", "char *", "char *__dest,char *__src"),
            ("strcat", "char *", "char *__dest,char *__src"),
            ("strdup", "char *", "char *__s"),
            ("strchr", "char *", "char *__s,int __c"),
            ("strrchr", "char *", "char *__s,int __c"),
            ("strstr", "char *", "char *__haystack,char *__needle"),
            ("strtol", "long", "char *__nptr,char **__endptr,int __base"),
            ("puts", "int", "char *__s"),
            ("isatty", "int", "int __fd"),
            ("fileno", "int", "FILE *__stream"),
            ("fclose", "int", "FILE *__stream"),
            ("fopen", "FILE *", "char *__filename,char *__modes"),
            ("fgets", "char *", "char *__s,int __n,FILE *__stream"),
            ("fputc", "int", "int __c,FILE *__stream"),
            (
                "fwrite", "size_t", "void *__ptr,size_t __size,size_t __n,FILE *__s",
            ),
            ("exit", "void", "int __status"),
            ("time", "time_t", "time_t *__timer"),
            (
                "__xstat", "int", "int __ver,char *__filename,stat *__stat_buf",
            ),
            ("__ctype_b_loc", "ushort **", ""),
        ];
        Self {
            entries: entries
                .into_iter()
                .map(|(name, return_type, parameters)| {
                    (
                        name,
                        LibcSignature {
                            return_type,
                            parameters,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl LibcSignatureTable {
    // RUGRA-GLUE: bare-load constructor (RUGRA-FLOW-MIRROR-0001 M3). The
    // oracle single-function harness loads via BfdArchitecture +
    // readLoaderSymbols only — no Java analyzer, no generic_clib signature
    // data reaches the decompiler — so every lookup misses and call sites
    // keep their unlocked prototypes. Default construction stays the full
    // locked ledger.
    pub fn empty() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    // RUGRA-GLUE: address of the Program-database signature lookup the decompiler performs via queryFunction
    pub fn lookup(&self, name: &str) -> Option<&LibcSignature> {
        self.entries.get(name)
    }

    /// Materialize the locked call-site `FuncProto` for an imported symbol,
    /// mirroring the decoded Program-database state handed to the decompiler:
    /// missing addresses are assigned through the UnknownProtoModel's cloned
    /// default resources (`ProtoStoreInternal::decode`, fspec.cc:3533-3541),
    /// source markup is restored, and input/output type locks are retained.
    /// The call site receives a copy through `ActionDefaultParams`
    /// (coreaction.cc:2327).
    ///
    /// Returns `Ok(None)` when the symbol has no locked signature (unknown
    /// import: stays unlocked, active recovery decides) and `Err` when the
    /// bound compiler model cannot assign the requested prototype. Scalar
    /// stack spill is represented by that model; aggregate/ModelRule paths
    /// remain outside the current bilateral fixture.
    // RUGRA-GLUE: generic-clib Program-database adapter; storage/markup state follows ProtoStoreInternal::decode (fspec.cc:3464-3567)
    /// Resolve the platform-side locked signature for an imported callee.
    /// `type_names` is the DWARF named-type index (`parse_type_names`): a
    /// signature base spelling that names a DWARF-known type resolves to that
    /// concrete type — the same name resolution Ghidra's signature loader
    /// performs against the program's type manager, where `FILE *` is a
    /// pointer to the real glibc `FILE` struct rather than an opaque unknown.
    /// Without it, an unknown-based `FILE *` loses the typeOrder competition
    /// against `char *` (SUB_PTR vs SUB_PTR, then pointee char vs unknown)
    /// and the decompiler's inferred `char *` overwrites the locked libc
    /// return type.
    pub fn locked_proto(
        &self,
        name: &str,
        model_carrier: &FuncProto,
        type_names: Option<&HashMap<String, Arc<Datatype>>>,
    ) -> Result<Option<FuncProto>> {
        let Some(signature) = self.lookup(name) else {
            return Ok(None);
        };
        let address_size = 8usize;
        // parse_c_type resolves through the canonical shared TypeFactory
        // (Ghidra's ONE `glb->types`, grammar.cc:2989 bases / :2402-2411
        // pointers) so the whole program shares ONE TypePointer object per
        // pointee — ActionMergeType's same-type grouping and the
        // lookForFuncParamNames merge-class gate key on that identity
        // (GLIBC-PROTO-PARAMNAME-0001).
        //
        // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: the generic_clib boundary
        // resolves the FILE spelling through the ARCHIVE's own FILE, not
        // the DWARF name index — the two type domains never unified in the
        // locked oracle (see clib_file_struct). Everything else keeps the
        // DWARF name resolution.
        let type_index = libc_type_resolution_index(type_names);
        let type_names = Some(&type_index);
        let return_type = parse_c_type(signature.return_type, address_size, type_names)?;
        let mut parameters = Vec::new();
        for declaration in split_parameter_list(signature.parameters) {
            let (type_text, parameter_name) = split_declaration(declaration)?;
            parameters.push(DebugParameter {
                name: parameter_name.to_string(),
                name_locked: true,
                data_type: parse_c_type(type_text, address_size, type_names)?,
            });
        }
        if !model_carrier.has_model() {
            bail!("libc prototype {name} has no bound ProtoModel");
        }
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: name.to_string(),
            out_type: Some(return_type),
            in_types: parameters
                .iter()
                .map(|parameter| parameter.data_type.clone())
                .collect(),
            in_names: parameters
                .iter()
                .map(|parameter| parameter.name.clone())
                .collect(),
            first_var_arg_slot: -1,
        };
        let mut proto = FuncProto::from_model_carrier(
            model_carrier,
            name.to_string(),
            pieces
                .out_type
                .clone()
                .expect("libc prototype always has output type"),
        );
        proto.name = name.to_string();
        proto.update_all_types_from_pieces(&pieces);
        if proto.has_input_errors() {
            bail!("compiler model cannot assign parameter storage for libc prototype {name}");
        }
        for param in &mut proto.parameters {
            // fspec.cc:3503-3506: the platform-side signature decode reads
            // ATTRIB_NAMELOCK into ParameterPieces::namelock, and
            // fspec.cc:3564 propagates it via curparam->setNameLock(). Every
            // parameter of a locked generic_clib signature carries a real
            // glibc reserved name (split_declaration rejects nameless
            // declarations), so each is name-locked here — the bit
            // ActionNameVars::lookForFuncParamNames gates on
            // (coreaction.cc:2818 param->isNameLocked()).
            param.flags |= crate::fspec::protoparam_flags::NAME_LOCKED;
        }
        proto.set_input_lock(true);
        proto.set_output_lock(true);
        proto.set_model_lock(true);
        // PLTSTUB-WARNLOSS-0001 (closed, CURB lane): the generic_clib
        // import path sends the decompiler the same never-assigned
        // convention the 0-param DWARF void-signature pin above documents:
        // the ELF thunk's
        // FunctionDB carries no calling convention (the importer never
        // assigns one for external thunks; FunctionPrototype.grabFromFunction
        // reads it back as "unknown" — FunctionPrototype.java:129-141), so
        // FuncProto::decode (fspec.cc:4675-4711) sees model="unknown" and
        // routes to createUnknownModel (architecture.cc:1159-1166: an
        // UnknownProtoModel cloned from defaultfp — identical paramrange/
        // localrange/stackgrowsnegative behavior, printInDecl=false), while
        // ProtoStoreInternal::decode (fspec.cc:3464-3567) still assigns
        // parameter storage through that model with the typelock bits kept.
        // The observable, via ActionPrototypeWarnings (coreaction.cc:4901-
        // 4908: isModelUnknown && !hasCustomStorage && (inputLocked ||
        // outputLocked)), is the golden's "/* WARNING: Unknown calling
        // convention -- yet parameter storage is locked */" header on
        // exactly the 24 generic_clib-locked PLT stubs (locked curl witness
        // 0x102310 strcpy / 0x102320 puts; the 21 imports outside the table
        // — curl_easy_*, __vfprintf_chk, __cxa_finalize — stay unlocked and
        // show no warning, matching the golden). Rugra pins the name string
        // only: the bound ProtoModelFull stays the defaultfp clone, so
        // every model-object consumer (hasEffect, derive_input_map,
        // varmap's name-keyed registry lookup falling back to defaultfp)
        // keeps the placeholder behavior UnknownProtoModel adopts.
        proto.set_model_name("unknown");
        Ok(Some(proto))
    }
}

// RUGRA-GLUE: splits the comma-separated parameter declaration list the signature data carries; an empty list is a void parameter list
fn split_parameter_list(parameters: &str) -> impl Iterator<Item = &str> {
    parameters
        .split(',')
        .map(str::trim)
        .filter(|declaration| !declaration.is_empty())
}

// RUGRA-GLUE: splits one "TYPE NAME" parameter declaration; the trailing
// identifier run is the name, everything before it (spaces and pointer stars
// included, e.g. "void *__ptr") is the type text
fn split_declaration(declaration: &str) -> Result<(&str, &str)> {
    let trimmed = declaration.trim();
    let name_start = trimmed
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map(|pos| pos + 1)
        .unwrap_or(0);
    let (type_text, name) = trimmed.split_at(name_start);
    if name.is_empty() {
        bail!("signature parameter declaration has no name: {declaration:?}");
    }
    let type_text = type_text.trim();
    if type_text.is_empty() {
        bail!("signature parameter declaration has no type: {declaration:?}");
    }
    Ok((type_text, name))
}

// RUGRA-GLUE: parses the signature data's C type spellings into Datatypes; only the metatype/size-bearing forms the 24-entry public libc ABI uses (void, char, int, long, size_t, time_t, ushort and pointer layers). A base spelling that names a DWARF-known type (FILE, stat) resolves to that concrete type through `type_names` — the same type-manager name resolution Ghidra's signature loader performs — and only falls back to an address-sized unknown base when the name is unknown
// RUGRA-GLUE: resolves one signature base spelling through the Architecture
// TypeFactory the way Ghidra's signature grammar does (lexer TYPE_NAME rule
// hits glb->types->findByName, grammar.cc:2989). A factory name-tree hit
// keeps the core type's identity; a miss interns a named base via
// get_base_named -> findAdd (type.cc:3412).
fn factory_named_base(
    types: &std::sync::Arc<
        std::sync::RwLock<crate::type_system::typefactory::TypeFactory>,
    >,
    size: usize,
    metatype: TypeMetatype,
    name: &str,
) -> Arc<Datatype> {
    {
        let factory = types
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = factory.find_by_name(name) {
            return existing;
        }
    }
    let mut factory = types
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    factory
        .get_base_named(size, metatype, name)
        .unwrap_or_else(|_| {
            Arc::new(Datatype::Base(TypeBase::new(
                name.to_string(),
                size,
                metatype,
            )))
        })
}

// RUGRA-GLUE: parses the signature data's C type spellings into Datatypes; only the metatype/size-bearing forms the 24-entry public libc ABI uses (void, char, int, long, size_t, time_t, ushort and pointer layers). A base spelling that names a DWARF-known type (FILE, stat) resolves to that concrete type through `type_names` — the same type-manager name resolution Ghidra's signature loader performs; any OTHER unresolvable base is a parse error, mirroring the two oracle arms (explicit transport size or findByName miss), never a minted address-sized unknown base (BRIDGE1-TYPESEED-PIDT)
// HEADLESS-BRIDGE-V1-TYPESEED extension: the committed-local seed manifest
// (C1) feeds the canon golden's own declaration spellings here, so the base
// table now also covers the analyzer-committed bases (undefined/undefinedN,
// uint/ulong/byte/short/float/double/bool with their x86-64 gcc sizes) and
// the outermost array declarator (`long[4]`, `char *[2]` -> TypeFactory::
// getTypeArray, type.cc:3902 — the mirror of TypeArray::decode's
// arraysize*alignsize reconstruction, type.cc:1330-1342).
pub(crate) fn parse_c_type(
    type_text: &str,
    address_size: usize,
    type_names: Option<&HashMap<String, Arc<Datatype>>>,
) -> Result<Arc<Datatype>> {
    let types = crate::type_system::typefactory::TypeFactory::shared_default();
    let trimmed = type_text.trim();
    // Outermost array declarator first, in C declarator order: the LEFTMOST
    // dimension is the outermost array — `long[2][4]` reads "array 2 of
    // array 4 of long" (C's `long name[2][4]` binds name[2] first), and the
    // oracle's type transport nests exactly that way: TypeArray::encode
    // wraps the element type as the sub-element, so the outer <type
    // metatype="array" arraysize="2"> holds the inner arraysize="4" (the
    // decode mirror is type.cc:1326-1347: arraysize from the attribute,
    // then `arrayof = typegrp.decodeType(decoder)` recursion). Reduction
    // therefore strips the LEFTMOST dimension and recurses on the rest of
    // the spelling: `long[2][4]` -> array(2, parse(`long[4]`)). The former
    // rightmost-strip inverted the nesting into array(4) of array(2) of
    // long (BRIDGE1-TYPESEED-MULTIDIM).
    if trimmed.ends_with(']') {
        if let Some(open) = trimmed.find('[') {
            if let Some(rel_close) = trimmed[open + 1..].find(']') {
                let close = open + 1 + rel_close;
                let count: usize = trimmed[open + 1..close].parse()?;
                let mut spelling = String::with_capacity(trimmed.len());
                spelling.push_str(&trimmed[..open]);
                spelling.push_str(&trimmed[close + 1..]);
                let base = parse_c_type(&spelling, address_size, type_names)?;
                let mut factory = types
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                return Ok(factory.get_array(base, count));
            }
        }
    }
    let (base_text, pointer_depth) = split_pointer_depth(trimmed);
    // Ghidra parses every platform signature through the ONE Architecture
    // TypeFactory: base spellings resolve via the name tree
    // (`glb->types->findByName`, grammar.cc:2989) and declarator pointers
    // via `PointerModifier::modType -> glb->types->getTypePointer(addrsize,
    // base, wordsize)` (grammar.cc:2402-2411), whose `findAdd`
    // (type.cc:3412) returns the ONE interned TypePointer object for a
    // given pointee. That type identity keys ActionMergeType's same-type
    // grouping (`ct == high->getType()` pointer equality, merge.cc:387) —
    // the speculative merges from `Merge::mergeLinear` mark multi-region
    // temps with >1 merge class, and ActionNameVars::lookForFuncParamNames
    // then declines to rename them from callee parameter names
    // (coreaction.cc:2887 `high->getNumMergeClasses() > 1`). Minting a
    // fresh Arc per call site here fragmented the same-type groups, so
    // main's pointer temps stayed single-class and inherited libc
    // parameter names the canon oracle leaves unnamed
    // (GLIBC-PROTO-PARAMNAME-0001).
    let mut datatype = match base_text {
        "void" => {
            let factory = types
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            factory.get_type_void()
        }
        // The generic_clib Program-database type named `char` is Ghidra's
        // character datatype, not a same-sized plain integer.  The C++
        // decompiler receives it as TypeChar (type.hh:348-357), whose
        // `chartype` flag drives PrintC::pushConstant.
        "char" => {
            {
                let factory = types
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(existing) = factory.find_by_name("char") {
                    existing
                } else if let Ok(core_char) = factory.get_type_char(1) {
                    core_char
                } else {
                    drop(factory);
                    let mut factory = types
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    factory
                        .get_type_char_named("char")
                        .expect("TypeFactory cannot build the char type")
                }
            }
        }
        "int" => factory_named_base(&types, 4, TypeMetatype::Int, "int"),
        "long" => factory_named_base(&types, address_size, TypeMetatype::Int, "long"),
        "size_t" | "time_t" => {
            factory_named_base(&types, address_size, TypeMetatype::Uint, base_text)
        }
        "ushort" => factory_named_base(&types, 2, TypeMetatype::Uint, "ushort"),
        // C1 seed bases (x86-64 gcc data_organization sizes): the canon
        // declaration layer's undefined/uint/byte/... spellings with their
        // committed sizes, mirroring the base core types the oracle's
        // TypeFactory already interns for the bare harness.
        "ulong" => factory_named_base(&types, address_size, TypeMetatype::Uint, "ulong"),
        "uint" => factory_named_base(&types, 4, TypeMetatype::Uint, "uint"),
        "byte" => factory_named_base(&types, 1, TypeMetatype::Uint, "byte"),
        "short" => factory_named_base(&types, 2, TypeMetatype::Int, "short"),
        "float" => factory_named_base(&types, 4, TypeMetatype::Float, "float"),
        "double" => factory_named_base(&types, 8, TypeMetatype::Float, "double"),
        "bool" => factory_named_base(&types, 1, TypeMetatype::Bool, "bool"),
        "undefined" => factory_named_base(&types, 1, TypeMetatype::Unknown, "undefined"),
        "undefined1" => factory_named_base(&types, 1, TypeMetatype::Unknown, "undefined1"),
        "undefined2" => factory_named_base(&types, 2, TypeMetatype::Unknown, "undefined2"),
        "undefined4" => factory_named_base(&types, 4, TypeMetatype::Unknown, "undefined4"),
        "undefined8" => factory_named_base(&types, 8, TypeMetatype::Unknown, "undefined8"),
        // C1 glibc typedef mirror: the httpd canon commits `__pid_t`
        // (ghidra_httpd_1204.c:24574, ap_signal_server `__pid_t local_34;`)
        // as glibc's `typedef int __pid_t` (sys/types.h) the analyzeHeadless
        // DWARF analyzer imported — 4 bytes, metatype int — the same (4,int)
        // the oracle-side <localdb> encoder table (gen_seed_xml.py BASES,
        // stage_seed_diag-validated) writes as the explicit size/metatype
        // attributes. The httpd driver builds no DWARF name index, so the
        // committed typedef resolves here exactly like the other seed
        // bases. BRIDGE1-TYPESEED-PIDT: the former address-size fallback
        // minted an 8B `__pid_t` that overlapped the neighboring committed
        // local_30(8B@-48) and tripped the forced-variable-type failure
        // (varmap.cc:280) in the restructure pass.
        "__pid_t" => factory_named_base(&types, 4, TypeMetatype::Int, "__pid_t"),
        other => match type_names.and_then(|index| index.get(other)) {
            Some(data_type) => data_type.clone(),
            // C4 STRUCT-SEED (HEADLESS-BRIDGE-V1 C3NEXT): a named composite
            // (URLGlob/OutStruct/stat/LongShort/va_list/...) resolves through
            // the ONE shared TypeFactory's name tree — the same resolution
            // Ghidra's C parser performs for a TYPE_NAME token
            // (`glb->types->findByName`, grammar.cc:2989). The factory's name
            // tree is populated by the DWARF import boundary
            // (parse_type_names -> resolve_type -> intern_named), which the
            // curl driver runs unconditionally before any request, so a
            // struct spelling seeded from the manifest finds the same interned
            // Arc<struct> the signature path's type_names index holds — one
            // type identity domain. The lookup is read-only and only fires
            // for spellings outside the core table above, so a bare-load /
            // no-DWARF run keeps the historical bail below.
            None => {
                let existing = {
                    let factory = types
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    factory.find_by_name(other)
                };
                match existing {
                    Some(data_type) => data_type,
                    // A bare name carries no size anywhere the oracle would
                    // honor: the <localdb>/<type> transport reads size only
                    // from the explicit ATTRIB_SIZE (Datatype::decodeBasic,
                    // type.cc:623-637, reached via the default arm of
                    // TypeFactory::decodeTypeNoRef, type.cc:4536-4543), and
                    // the C-signature path resolves a named base through
                    // glb->types->findByName (grammar.cc:2989) — an
                    // unresolved name lexes as a plain IDENTIFIER and the
                    // parse fails. Neither oracle path ever mints an
                    // address-sized unknown base from a spelling, so an
                    // unresolvable base here is a parse error the seed
                    // caller reports and skips (BRIDGE1-TYPESEED-PARSEFAIL
                    // downgrade; the silent 8B mint is what made
                    // BRIDGE1-TYPESEED-PIDT latent-poisonous).
                    None => bail!(
                        "unresolved base spelling `{other}`: not a committed core/seed base and no known-type entry (the oracle transports an explicit size; a bare name never mints one)"
                    ),
                }
            }
        },
    };
    for _ in 0..pointer_depth {
        // Ghidra builds parsed declarator pointers through
        // PointerModifier::modType -> glb->types->getTypePointer(addrsize,
        // base, wordsize) (grammar.cc:2402-2411), whose 3-arg overload
        // leaves the name EMPTY (type.cc:3867-3875) — the "char *" spelling
        // is syntax, not type identity, so the signature-parsed pointers
        // stay anonymous and PrintC renders them through the drilled
        // multi-layer form (`char *pcVar1`), matching the golden output.
        // The former composed display names ("char *"/"char **") made these
        // NAMED single-layer pointers and printed `char * pcVar1` (oracle
        // printc_anonymous_pointer_decl_1204 named_ptr_contrast).
        let mut factory = types
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        datatype = factory.get_type_pointer(address_size, datatype, 1);
    }
    Ok(datatype)
}

// RUGRA-GLUE: separates trailing pointer stars from the base type name in a C type spelling
fn split_pointer_depth(type_text: &str) -> (&str, usize) {
    let trimmed = type_text.trim();
    // Strip one trailing '*' at a time, along with any spaces before it, so
    // every spacing form ("char **", "char**", "char * *") reduces to the
    // same base + depth. The old `trim_end_matches(" *")` could not strip a
    // second star ("char **" does not END with the two-char pattern " *"),
    // so double pointers fell through to the unknown-name base arm and
    // produced Base("char **", TYPE_UNKNOWN) instead of a structural
    // Pointer-to-Pointer.
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    let mut depth = 0usize;
    while end > 0 && bytes[end - 1] == b'*' {
        depth += 1;
        end -= 1;
        while end > 0 && bytes[end - 1] == b' ' {
            end -= 1;
        }
    }
    (trimmed[..end].trim(), depth)
}


// RUGRA-GLUE: resolves a concrete function entry address from a DWARF DIE before handing the prototype to Funcdata
fn subprogram_address(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Option<u64>> {
    if let Some(value) = entry.attr_value(gimli::DW_AT_low_pc)? {
        if let Some(address) = dwarf.attr_address(unit, value)? {
            return Ok(Some(address));
        }
    }
    let mut ranges = dwarf.die_ranges(unit, entry)?;
    Ok(ranges.next()?.map(|range| range.begin))
}

// RUGRA-GLUE: follows DWARF declaration inheritance so optimized definitions consume the same source prototype Ghidra imports into its Program database
fn canonical_subprogram_offset(
    unit: &Unit<DwarfReader>,
    mut offset: UnitOffset<usize>,
) -> Result<UnitOffset<usize>> {
    for _ in 0..32 {
        let entry = unit.entry(offset)?;
        let next = entry_reference(unit, &entry, gimli::DW_AT_abstract_origin)?
            .or(entry_reference(unit, &entry, gimli::DW_AT_specification)?);
        let Some(next) = next else {
            return Ok(offset);
        };
        offset = next;
    }
    bail!("DWARF abstract-origin/specification chain exceeds 32 entries")
}

// RUGRA-GLUE: extracts canonical direct formal-parameter children in DIE order, which is the declaration order preserved by Ghidra's imported prototype
fn read_prototype_children(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<(Vec<DebugParameter>, bool)> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut depth = 0isize;
    let mut parameters = Vec::new();
    let mut is_varargs = false;
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        depth += delta;
        if depth <= 0 {
            break;
        }
        if depth != 1 {
            continue;
        }
        if entry.tag() == gimli::DW_TAG_unspecified_parameters {
            is_varargs = true;
            continue;
        }
        if entry.tag() != gimli::DW_TAG_formal_parameter {
            continue;
        }
        let canonical = canonical_parameter_offset(unit, entry.offset())?;
        let canonical_entry = unit.entry(canonical)?;
        let source_name = entry_string(dwarf, unit, &canonical_entry, gimli::DW_AT_name)?;
        let name_locked = source_name.is_some();
        let name = source_name
            .unwrap_or_else(|| format!("param_{}", parameters.len() + 1));
        let data_type = match entry_reference(unit, &canonical_entry, gimli::DW_AT_type)? {
            Some(type_offset) => resolve_type(dwarf, unit, type_offset, 0, &mut Vec::new())?,
            None => unknown_type(unit.encoding().address_size as usize),
        };
        parameters.push(DebugParameter { name, name_locked, data_type ,
        });
    }
    Ok((parameters, is_varargs))
}

// RUGRA-GLUE: follows optimized formal-parameter abstract origins to recover declaration name/type before FuncProto construction
fn canonical_parameter_offset(
    unit: &Unit<DwarfReader>,
    mut offset: UnitOffset<usize>,
) -> Result<UnitOffset<usize>> {
    for _ in 0..32 {
        let entry = unit.entry(offset)?;
        let Some(next) = entry_reference(unit, &entry, gimli::DW_AT_abstract_origin)? else {
            return Ok(offset);
        };
        offset = next;
    }
    bail!("DWARF formal-parameter abstract-origin chain exceeds 32 entries")
}

// RUGRA-GLUE: converts a DWARF string attribute into owned front-end state; Ghidra's Program database similarly outlives the DIE reader
fn entry_string(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    name: gimli::DwAt,
) -> Result<Option<String>> {
    let Some(value) = entry.attr_value(name)? else {
        return Ok(None);
    };
    let reader = dwarf.attr_string(unit, value)?;
    Ok(Some(reader.to_string_lossy()?.into_owned()))
}

// RUGRA-GLUE: normalizes unit-relative and same-unit debug-info references for the native DWARF importer
fn entry_reference(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    name: gimli::DwAt,
) -> Result<Option<UnitOffset<usize>>> {
    let Some(value) = entry.attr_value(name)? else {
        return Ok(None);
    };
    Ok(match value {
        AttributeValue::UnitRef(offset) => Some(offset),
        AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    })
}

// RUGRA-GLUE: materializes the DWARF type graph into Rugra Datatype objects at the Program-import boundary; Ghidra performs this in its DWARF/type-manager front end. `visiting` holds the DIE offsets currently being resolved so recursive types (FILE -> struct _IO_FILE -> _chain FILE *) break at the back edge with a shallow named projection, the same way Ghidra's two-phase type manager exposes an already-created type before its members are filled in
fn resolve_type(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Arc<Datatype>> {
    if depth >= 64 {
        bail!("DWARF type chain exceeds 64 entries")
    }
    if visiting.contains(&offset) {
        let entry = unit.entry(offset)?;
        return shallow_type(dwarf, unit, &entry, offset);
    }
    visiting.push(offset);
    let resolved = resolve_type_inner(dwarf, unit, offset, depth, visiting);
    visiting.pop();
    resolved
}

// RUGRA-GLUE: the field/chain-resolving half of resolve_type, entered with the DIE already pushed on the visiting stack
fn resolve_type_inner(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Arc<Datatype>> {
    let entry = unit.entry(offset)?;
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)?
        .and_then(|value| value.udata_value())
        .map(|value| value as usize);
    let name = entry_string(dwarf, unit, &entry, gimli::DW_AT_name)?;
    let referenced = entry_reference(unit, &entry, gimli::DW_AT_type)?;
    match entry.tag() {
        gimli::DW_TAG_base_type => dwarf_base_type(
                name.unwrap_or_else(|| "int".to_string()),
                size.unwrap_or(4),
                &entry,
        ),
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => {
            let pointee = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => void_type(),
            };
            Ok(pointer_type(
                pointee,
                size.unwrap_or(unit.encoding().address_size as usize),
            ))
        }
        gimli::DW_TAG_typedef => {
            let inner = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => unknown_type(size.unwrap_or(unit.encoding().address_size as usize)),
            };
            match name {
                // A typedef over a composite/enum keeps its fields and named
                // values under the typedef spelling (this is how the type
                // renders in decompiled C). Rugra's Datatype enum has no
                // TypeTypedef variant yet, so the typedef is materialized as
                // the renamed underlying type.
                //
                // Exception first (PRINTC-BOOLLITERAL-0001): the conventional
                // boolean typedef names resolve to the core bool type the way
                // Ghidra's DWARF front end maps `typedef bool` (curl.h line
                // 394, DW_TAG_typedef "bool" -> char) to its boolean primitive,
                // landing on the decompiler's core `bool` from
                // setCoreType("bool",1,TYPE_BOOL,false) (sleigh_arch.cc:216).
                // Type identity then drives ActionSetCasts::castInput's
                // constant absorption (coreaction.cc:2687-2691) and
                // PrintC::pushConstant's TYPE_BOOL arm (printc.cc:1769-1771),
                // printing `true`/`false` — the canonical-golden behavior for
                // every typedef-bool field (`::config.showerror = true;`).
                // Gate on the 1-byte underlying so a malformed larger "bool"
                // typedef keeps the alias path.
                Some(name) => {
                    if inner.get_size() == 1 {
                        let factory = crate::type_system::typefactory::TypeFactory::shared_default();
                        let core_bool = factory
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .dwarf_conventional_bool(&name);
                        if let Some(core_bool) = core_bool {
                            return Ok(core_bool);
                        }
                    }
                    materialized_alias(name, &inner)
                }
                None => Ok(inner),
            }
        }
        gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type => {
            // CURLCANON-CASTA-CONST-0001 (R2 of PROTOCAST43's A-族 residual
            // roots): the oracle's DWARF front end drops cv-qualifier
            // wrappers at import — the locked goldens carry ZERO
            // `const`/`volatile`/`restrict` tokens across all six corpora
            // (curl 11.3.2/1204, httpd, sq, sqlite, vsh), and
            // my_get_token's DWARF `const char *` param chain (0x3ca ptr
            // -> 0x186 const -> char, readelf-verified) prints as
            // `char * my_get_token(char *line)` with `(char *)0x0`
            // constant casts (golden :1213/:1226/:1603). Rugra's former
            // `alias_type("const char", char)` minted an independent
            // qualifier object as the prototype's req — printing
            // `const char *` signatures and `(const char *)0x0` casts.
            // Strip to the underlying type; a qualifier DIE with no
            // DW_AT_type is cv-qualified void (DW_TAG_const_type with an
            // absent type attribute denotes `const void`), which strips
            // to the canonical void.
            match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting),
                None => Ok(void_type()),
            }
        }
        gimli::DW_TAG_structure_type => {
            let fields = read_composite_fields(dwarf, unit, offset, depth, visiting)?;
            // Ghidra: DWARFProgram.java:658-675 — unnamed structure types take
            // the importer's synthesized "anon_<container>_<layout
            // fingerprint>_for_<fields>" name (after the single-inbound-
            // typedef steal, :650-656). The former struct_<offset> spelling
            // was a RUGRA-GLUE placeholder (DWARF-ANON-TYPENAME-0001);
            // golden witness `(anon_union_16_3_e2f18bb4_for_content)` casts.
            let type_name = match name {
                Some(name) => name,
                None => composite_type_name(dwarf, unit, offset)?,
            };
            Ok(struct_type(type_name, size.unwrap_or(0), fields))
        }
        gimli::DW_TAG_union_type => {
            let fields = read_composite_fields(dwarf, unit, offset, depth, visiting)?;
            // Ghidra: DWARFProgram.java:658-675 — same anonymous naming chain
            // as the structure arm (union is a structure type,
            // DWARFTag.java:200-210; container word "union", :229-250).
            let type_name = match name {
                Some(name) => name,
                None => composite_type_name(dwarf, unit, offset)?,
            };
            Ok(union_type(type_name, size.unwrap_or(0), fields))
        }
        gimli::DW_TAG_enumeration_type => {
            let values = read_enumerators(dwarf, unit, offset)?;
            // Anonymous enums keep the offset spelling — NOT the Java
            // "anon_enum_<bits>" (:684-686 -> :771-774): in Java the final
            // name comes from the :650-656 typedef steal, which is not
            // carried (see dwarf_type_leaf_name); the shared spelling would
            // merge distinct enums' value tables in the name-keyed factory
            // (observed HTTPREQ_*/TIMECOND_* corruption). Zero corpus
            // surface; restore with the steal when TypeTypedef lands.
            let type_name =
                name.unwrap_or_else(|| format!("enum_{:x}", offset.0));
            Ok(enum_type(type_name, size.unwrap_or(4), values))
        }
        gimli::DW_TAG_array_type => {
            let element = match referenced {
                Some(inner) => resolve_type(dwarf, unit, inner, depth + 1, visiting)?,
                None => unknown_type(1),
            };
            let count = read_array_count(unit, offset)?;
            let array_size = element.get_size().saturating_mul(count);
            // Ghidra's DWARF array import runs through
            // TypeFactory::getTypeArray (type.cc:3902), whose inline
            // `TypeArray` ctor leaves the name EMPTY — array identity is
            // structural (element type + count), the composed spelling was
            // diagnostic-only.
            Ok(Arc::new(Datatype::Array(TypeArray {
                base: TypeBase::new(String::new(), array_size, TypeMetatype::Array),
                array_of: element,
                num_elements: count,
            })))
        }
        gimli::DW_TAG_unspecified_type => Ok(void_type()),
        _ => {
            if let Some(inner) = referenced {
                resolve_type(dwarf, unit, inner, depth + 1, visiting)
            } else {
                Ok(unknown_type(
                    size.unwrap_or(unit.encoding().address_size as usize),
                ))
            }
        }
    }
}

// RUGRA-GLUE: shallow projection of a type DIE that is already being resolved higher in the chain: the type's name/size/metatype without fields or nested chains, breaking recursive type graphs the way Ghidra's two-phase type creation does
fn shallow_type(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<Arc<Datatype>> {
    let address_size = unit.encoding().address_size as usize;
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)?
        .and_then(|value| value.udata_value())
        .map(|value| value as usize);
    match entry.tag() {
        gimli::DW_TAG_base_type => dwarf_base_type(
            entry_string(dwarf, unit, entry, gimli::DW_AT_name)?
                .unwrap_or_else(|| "int".to_string()),
            size.unwrap_or(4),
            entry,
        ),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
            // Ghidra: DWARFProgram.java:658-675 — the two-phase importer
            // exposes the anonymous type's synthesized name even on the
            // unfinished back-edge projection, so unnamed DIEs route through
            // the same naming chain as the fully resolved type. Named
            // back-edges keep the historical placeholder spelling — every
            // corpus witness is renamed by the typedef materialization layer
            // above this projection.
            let name = entry_string(dwarf, unit, entry, gimli::DW_AT_name)?;
            match name {
                Some(_) => Ok(base_type(
                    format!("struct_{:x}", offset.0),
                    size.unwrap_or(0),
                    TypeMetatype::Struct,
                )),
                None => Ok(base_type(
                    composite_type_name(dwarf, unit, offset)?,
                    size.unwrap_or(0),
                    TypeMetatype::Struct,
                )),
            }
        }
        gimli::DW_TAG_union_type => Ok({
            // Ghidra: DWARFProgram.java:658-675 — union back-edge takes the
            // same anonymous naming chain as the structure arm above.
            let name = entry_string(dwarf, unit, entry, gimli::DW_AT_name)?;
            let type_name = match name {
                Some(_) => format!("union_{:x}", offset.0),
                None => composite_type_name(dwarf, unit, offset)?,
            };
            base_type(type_name, size.unwrap_or(0), TypeMetatype::Union)
        }),
        gimli::DW_TAG_enumeration_type => Ok(base_type(
            // Anonymous enums keep the offset spelling (see the
            // resolve_type_inner enum arm: the Java anon_enum naming and
            // its :650-656 typedef steal are not carried without a
            // TypeTypedef separation).
            format!("enum_{:x}", offset.0),
            size.unwrap_or(4),
            TypeMetatype::Enum,
        )),
        gimli::DW_TAG_pointer_type
        | gimli::DW_TAG_reference_type
        | gimli::DW_TAG_rvalue_reference_type => {
            Ok(pointer_type(void_type(), size.unwrap_or(address_size)))
        }
        _ => {
            // Typedefs and qualifiers keep their own spelling over the
            // target's shallow size/metatype (attributes only, no chain
            // recursion), matching the flattened alias this importer
            // produced before field materialization existed (a recursive
            // `FILE` still renders as `FILE *`).
            let qualifier = match entry.tag() {
                gimli::DW_TAG_const_type => Some("const"),
                gimli::DW_TAG_volatile_type => Some("volatile"),
                gimli::DW_TAG_restrict_type => Some("restrict"),
                _ => None,
            };
            let target = entry_reference(unit, entry, gimli::DW_AT_type)?
                .map(|target| unit.entry(target))
                .transpose()?;
            let (target_name, target_size, metatype) = match &target {
                Some(target_entry) => {
                    let target_size = target_entry
                        .attr_value(gimli::DW_AT_byte_size)?
                        .and_then(|value| value.udata_value())
                        .map(|value| value as usize);
                    let metatype = match target_entry.tag() {
                        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                            TypeMetatype::Struct
                        }
                        gimli::DW_TAG_union_type => TypeMetatype::Union,
                        gimli::DW_TAG_enumeration_type => TypeMetatype::Enum,
                        _ => TypeMetatype::Unknown,
                    };
                    (
                        entry_string(dwarf, unit, target_entry, gimli::DW_AT_name)?,
                        target_size,
                        metatype,
                    )
                }
                None => (None, None, TypeMetatype::Unknown),
            };
            let own_name = entry_string(dwarf, unit, entry, gimli::DW_AT_name)?;
            let base_name = own_name
                .or(target_name)
                .unwrap_or_else(|| format!("_{:x}", offset.0));
            let display = match qualifier {
                Some(qualifier) => format!("{qualifier} {base_name}"),
                None => base_name,
            };
            Ok(base_type(
                display,
                target_size
                    .or(size)
                    .unwrap_or(address_size),
                metatype,
            ))
        }
    }
}

// RUGRA-GLUE: maps DW_AT_encoding to the Rugra metatype the base-type importer assigns
fn base_metatype(entry: &DebuggingInformationEntry<DwarfReader>) -> Result<TypeMetatype> {
    let encoding = entry.attr_value(gimli::DW_AT_encoding)?;
    Ok(match encoding {
        Some(AttributeValue::Encoding(value))
            if value == gimli::DW_ATE_float || value == gimli::DW_ATE_complex_float =>
        {
            TypeMetatype::Float
        }
        Some(AttributeValue::Encoding(value))
            if value == gimli::DW_ATE_unsigned
                || value == gimli::DW_ATE_unsigned_char
                || value == gimli::DW_ATE_address =>
        {
            TypeMetatype::Uint
        }
        Some(AttributeValue::Encoding(value)) if value == gimli::DW_ATE_boolean => {
            TypeMetatype::Bool
        }
        _ => TypeMetatype::Int,
    })
}

// Ghidra's isEncodingCompatible (DWARFDataTypeManager.java:359-369): only
// the DW_ATE_signed / DW_ATE_unsigned requests constrain the alias-table
// hit — a signed request rejects unsigned-integer canonicals, an unsigned
// request rejects signed-integer canonicals. `bool` counts as an unsigned
// integer (BooleanDataType extends AbstractUnsignedIntegerDataType), while
// float/wchar_t/undefined1 canonicals are not AbstractIntegerDataType
// instances and always pass; every other encoding passes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BaseAliasSign {
    Signed,
    Unsigned,
    NonInteger,
}

// Ghidra: DWARFDataTypeManager.java:477-549 initBaseDataTypes
// (Java-side DWARF analyzer; decompile/cpp has no DWARF parser, so Rugra's
// debugproto is the native front-end adapter for that boundary).
// The standard C base-type alias table the analyzer's getBaseType consults
// FIRST (DWARFDataTypeManager.java:403 `dt = baseDataTypes.get(name)`): a
// DW_AT_name spelling one of these aliases resolves to the Program DTM's
// canonical type DIRECTLY — no typedef wrap — when the size gate and the
// encoding gate pass, so the decompiler receives (and prints) the canonical
// spelling: `long int` (8, DW_ATE_signed) IS the DTM `long` and casts print
// `(long)` (golden corpus: `(long)` 55x curl / 1165x httpd, `long int` zero
// occurrences). Canonical spellings match the C++ coretypes stream names
// (typefactory.rs init_data_org_core_types doc): uchar/longlong/ulonglong
// are Java-DTM-only names — the C++ stream's same-size longlong slot is
// overwritten by long — so they intern as named non-core types exactly as
// the database transport delivers them to TypeFactory::findAdd
// (type.cc:3412-3437). The void/nullptr table entries serve Java-only
// lookup paths (a DW_TAG_base_type never carries those names: DWARF
// expresses void by an absent DW_AT_type, handled at the pointer arm).
fn standard_base_alias(name: &str) -> Option<(&'static str, TypeMetatype, BaseAliasSign)> {
    Some(match name {
        // initBaseDataTypes :499-501
        "char" | "signed char" => ("char", TypeMetatype::Int, BaseAliasSign::Signed),
        "unsigned char" => ("uchar", TypeMetatype::Uint, BaseAliasSign::Unsigned),
        // :516-520
        "short" | "short int" | "signed short int" => ("short", TypeMetatype::Int, BaseAliasSign::Signed),
        "unsigned short int" | "short unsigned int" => {
            ("ushort", TypeMetatype::Uint, BaseAliasSign::Unsigned)
        }
        // :522-524
        "int" | "signed int" => ("int", TypeMetatype::Int, BaseAliasSign::Signed),
        "unsigned int" => ("uint", TypeMetatype::Uint, BaseAliasSign::Unsigned),
        // :526-530
        "long" | "long int" | "signed long int" => ("long", TypeMetatype::Int, BaseAliasSign::Signed),
        "unsigned long int" | "long unsigned int" => {
            ("ulong", TypeMetatype::Uint, BaseAliasSign::Unsigned)
        }
        // :532-536
        "long long" | "long long int" | "signed long long int" => {
            ("longlong", TypeMetatype::Int, BaseAliasSign::Signed)
        }
        "unsigned long long int" | "long long unsigned int" => {
            ("ulonglong", TypeMetatype::Uint, BaseAliasSign::Unsigned)
        }
        // :538-543
        "float" => ("float", TypeMetatype::Float, BaseAliasSign::NonInteger),
        "double" => ("double", TypeMetatype::Float, BaseAliasSign::NonInteger),
        "long double" => ("longdouble", TypeMetatype::Float, BaseAliasSign::NonInteger),
        // :545-548 (bool is an unsigned integer for the compatibility gate)
        "bool" => ("bool", TypeMetatype::Bool, BaseAliasSign::Unsigned),
        "wchar_t" => ("wchar_t", TypeMetatype::Int, BaseAliasSign::NonInteger),
        "undefined1" => ("undefined1", TypeMetatype::Unknown, BaseAliasSign::NonInteger),
        _ => return None,
    })
}

// Ghidra: DWARFDataTypeManager.java:397 getBaseType
// (the aligned-size gate at :404 `dt.getAlignedLength() == dwarfSize`: the
// canonical type's dataOrganization size must equal the DIE's
// DW_AT_byte_size or the alias hit is rejected, falling through to the
// original-name arm). The shared TypeFactory's core table IS the x86-64
// gcc dataOrganization mirror, so factory-present canonicals resolve their
// size through it; the three Java-DTM-only names take the same
// dataOrganization slots — uchar = charSize, longlong/ulonglong =
// longLongSize (== longSize, 8, under the locked x86-64 gcc cspec;
// AbstractIntegerDataType.java:549-566).
fn canonical_base_size(canonical: &str) -> Option<usize> {
    let factory = crate::type_system::typefactory::TypeFactory::shared_default();
    let guard = factory
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.find_by_name(canonical) {
        return Some(existing.get_size());
    }
    match canonical {
        "uchar" => guard.find_by_name("char").map(|dt| dt.get_size()),
        "longlong" | "ulonglong" => guard.find_by_name("long").map(|dt| dt.get_size()),
        _ => None,
    }
}

// Ghidra: DWARFDataTypeManager.java:359 isEncodingCompatible
// (the DW_ATE_signed / DW_ATE_unsigned arms at :362-368)
fn base_alias_encoding_compatible(
    encoding: Option<gimli::DwAte>,
    sign: BaseAliasSign,
) -> bool {
    match encoding {
        Some(value) if value == gimli::DW_ATE_signed => {
            sign != BaseAliasSign::Unsigned
        }
        Some(value) if value == gimli::DW_ATE_unsigned => {
            sign != BaseAliasSign::Signed
        }
        _ => true,
    }
}

// RUGRA-GLUE: materializes the Program database base type selected by the
// locked Ghidra DWARF analyzer before the C++ decompiler receives it.
// Resolution order mirrors DWARFDataTypeManager.getBaseType
// (DWARFDataTypeManager.java:397-449, reached from the base-type DIE at
// DWARFDataTypeImporter.java:373):
//   1. alias-table hit (size + encoding gates pass) returns the canonical
//      Program type directly (:403-407) — the type the decompiler's
//      TypeFactory::findAdd then dedups onto its same-named core entry
//      (type.cc:3412-3425), so DWARF `long int` and the cspec `long` are
//      ONE object and identical-type casts disappear;
//   2. DW_ATE_signed_char falls back to the char type (:426), keeping the
//      DWARF spelling the way the typedef wrap (:441-447) renders it;
//   3. every other name keeps its DWARF spelling (the typedef-wrap arm —
//      Rugra materializes typedefs as the renamed underlying type).
fn dwarf_base_type(
    name: String,
    size: usize,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<Arc<Datatype>> {
    let encoding = entry.attr_value(gimli::DW_AT_encoding)?;
    let metatype = base_metatype(entry)?;
    let encoding_kind = match encoding {
        Some(AttributeValue::Encoding(value)) => Some(value),
        _ => None,
    };
    if let Some((canonical, canonical_metatype, sign)) = standard_base_alias(name.as_str()) {
        if canonical_base_size(canonical) == Some(size)
            && base_alias_encoding_compatible(encoding_kind, sign)
        {
            return Ok(base_type(canonical.to_string(), size, canonical_metatype));
        }
    }
    // DWARFDataTypeManager::getBaseType resolves the core names `char` and
    // `signed char` to CharDataType before its encoding fallback.  Its
    // DW_ATE_signed_char fallback is also CharDataType, whereas
    // DW_ATE_unsigned_char resolves to the ordinary unsigned `uchar` type.
    // GLIBC-PROTO-PARAMNAME-0001: interned by name so the DWARF char is
    // the SAME type object the factory's signature/inference paths use
    // (Ghidra resolves every `char` through its one TypeFactory,
    // grammar.cc:2989); a fresh clone here fragmented same-type merge
    // grouping.
    if encoding_kind == Some(gimli::DW_ATE_signed_char) {
        return Ok(intern_named(Arc::new(Datatype::Base(
            TypeBase::new_char(name, TypeMetatype::Int),
        ))));
    }
    Ok(base_type(name, size, metatype))
}

// RUGRA-GLUE: reads direct DW_TAG_member children (DIE order = declaration order), resolving each member's DW_AT_type and DW_AT_data_member_location exactly as Ghidra's DWARF analyzer builds composite fields
fn read_composite_fields(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
    depth: usize,
    visiting: &mut Vec<UnitOffset<usize>>,
) -> Result<Vec<TypeField>> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    let mut fields = Vec::new();
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        let Some(name) = entry_string(dwarf, unit, entry, gimli::DW_AT_name)? else {
            continue;
        };
        let member_offset = member_location(unit, entry)?;
        let Some(type_reference) = entry_reference(unit, entry, gimli::DW_AT_type)? else {
            continue;
        };
        let data_type = resolve_type(dwarf, unit, type_reference, depth + 1, visiting)?;
        fields.push(TypeField {
            name,
            offset: member_offset,
            type_ptr: data_type,
        });
    }
    Ok(fields)
}

// RUGRA-GLUE: decodes DW_AT_data_member_location in the two forms producers emit for composites — a plain constant and DW_OP_plus_uconst — rejecting anything else fail-visibly
fn member_location(
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
) -> Result<usize> {
    let Some(value) = entry.attr_value(gimli::DW_AT_data_member_location)? else {
        return Ok(0);
    };
    match value {
        AttributeValue::Udata(value) => Ok(value as usize),
        AttributeValue::Exprloc(ref expression) => {
            let mut operations = expression.clone().operations(unit.encoding());
            let resolved = match operations.next()? {
                Some(gimli::Operation::PlusConstant { value }) => usize::try_from(value).ok(),
                _ => None,
            };
            let complete = resolved.is_some() && operations.next()?.is_none();
            match (resolved, complete) {
                (Some(offset), true) => Ok(offset),
                _ => bail!("unsupported DW_AT_data_member_location expression"),
            }
        }
        _ => bail!("unsupported DW_AT_data_member_location form"),
    }
}

// ---------------------------------------------------------------------------
// DWARF anonymous type naming — Java 12.0.4 build-tree oracle.
//
// The canon/mirror goldens are produced by Ghidra's *Java* DWARF importer
// (12.0.4 build tree /data/ls/DiffClip/tools/ghidra-12.0.4-build/src,
// application.version=12.0.4 verified), not by the cpp decompiler: anonymous
// composite/enum type names are synthesized at Program-import time in
// DWARFProgram/DWARFUtil (Java). Every citation in this section anchors to
// that Java tree; the basis is recorded on the DWARF-ANON-TYPENAME-0001
// ticket row. Golden witness: `(anon_union_16_3_e2f18bb4_for_content)` casts
// (ghidra_curl_1204.c:767-788), reproduced from the DIE facts
// union@0xa49: byte_size=0x10, members Set/CharRange/NumRange with no
// DW_AT_data_member_location (offset default 0, DWARFUtil.java:283-289).
// ---------------------------------------------------------------------------

/// Global DIE identity across the whole .debug_info section:
/// (unit-header section offset, unit-relative DIE offset). This is the
/// identity Java's section-wide `typeReferers` map is keyed by
/// (DWARFProgram.java:381), modulo the DW_AT_abstract_origin /
/// DW_AT_specification fragment merging into DIEAggregates
/// (DWARFProgram.java:65-66 REF_ATTRS, DIEAggregate.java:80-103
/// createFromHead) — C producers never emit those references for types
/// (curl/httpd corpora: zero hits), so every DIE is its own aggregate head
/// and getHeadFragment() (DIEAggregate.java:247-249) is the DIE itself.
type GlobalDieId = (u64, usize);

/// One .debug_info DIE projected for the anonymous-name chain: entry name
/// (DWARFProgram.java:590-602 getEntryName chain), raw DW_AT_name
/// (DIEAggregate.java:397-399 getName — no linkage fallback), DW_AT_type
/// target (DIEAggregate.java:456-458 getTypeRef), parent / all-tag child
/// position (DWARFProgram.java:1472-1490 getPositionInParent), byte size
/// (DIEAggregate.java:414-417 getUnsignedLong over DWARFNumericAttribute),
/// DW_AT_external presence (DWARFUtil.java:277) and the
/// DW_AT_data_member_location value parseDataMemberOffset yields
/// (DIEAggregate.java:613-637: numeric in [0, i32::MAX] via
/// assertValidUInt :596-600, expression evaluated, every failure caught at
/// DWARFUtil.java:287 back to 0).
#[derive(Debug, Clone)]
struct DwarfDieRecord {
    id: GlobalDieId,
    tag: gimli::DwTag,
    /// getEntryName (DWARFProgram.java:590-602): DW_AT_name, then
    /// DW_AT_linkage_name, then DW_AT_MIPS_linkage_name.
    entry_name: Option<String>,
    /// DW_AT_name only — what DIEAggregate.getName (:397-399) returns; the
    /// fingerprint (:282) and referring-member names (:804) use this, not
    /// the linkage fallback.
    name_attr: Option<String>,
    type_target: Option<GlobalDieId>,
    parent: Option<GlobalDieId>,
    /// 0-based position among ALL direct children of the parent — the
    /// getPositionInParent(head, x -> true) result (DWARFProgram.java:807).
    child_position: usize,
    byte_size: Option<u64>,
    external: bool,
    member_offset: u32,
}

/// The section-wide DIE table plus the inbound DW_AT_type reference index
/// (DWARFProgram.java:199 typeReferers, a ListValuedMap whose value lists
/// keep insertion order = .debug_info walk order per :375-385
/// indexDIEATypeRefs iterating allAggregates() in section order).
#[derive(Debug, Default)]
struct DwarfDieTable {
    records: Vec<DwarfDieRecord>,
    by_id: std::collections::HashMap<GlobalDieId, usize>,
    type_refs: std::collections::HashMap<GlobalDieId, Vec<usize>>,
}

impl DwarfDieTable {
    /// Direct children in .debug_info order — for C producers identical to
    /// iterating the head fragment's children (DWARFUtil.java:271).
    // Ghidra: DWARFUtil.java:271 getStructLayoutFingerprint — headFragment().getChildren() iteration order
    fn children(&self, id: GlobalDieId) -> impl Iterator<Item = &DwarfDieRecord> {
        self.records.iter().filter(move |record| record.parent == Some(id))
    }

    /// getTypeReferers(target, tag) (DWARFProgram.java:1393-1402): the
    /// ordered referrer list filtered by tag, .debug_info order preserved
    /// from the put() loop (:381).
    // Ghidra: DWARFProgram.java:1393 getTypeReferers — tag-filtered referrer list in typeReferers insertion order
    fn type_referers(&self, id: GlobalDieId, tag: gimli::DwTag) -> Vec<&DwarfDieRecord> {
        self.type_refs
            .get(&id)
            .map(|refs| {
                refs.iter()
                    .map(|&index| &self.records[index])
                    .filter(|record| record.tag == tag)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// DW_AT_data_member_location as parseDataMemberOffset returns it for the
/// fingerprint: the single supported producer expression form
/// (DW_OP_plus_uconst, the same form `member_location` above decodes for
/// field layout) maps to its constant; every other expression or a constant
/// outside [0, i32::MAX] throws inside Java and is caught back to 0
/// (DIEAggregate.java:624-632 + assertValidUInt :596-600, catch at
/// DWARFUtil.java:284-289).
// Ghidra: DIEAggregate.java:613 parseDataMemberOffset — blob-attribute DWARF expression evaluation with assertValidUInt range gate
fn soft_member_location(
    unit: &Unit<DwarfReader>,
    expression: &gimli::Expression<gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>>,
) -> Option<u32> {
    let mut operations = expression.clone().operations(unit.encoding());
    let resolved = match operations.next().ok()? {
        Some(gimli::Operation::PlusConstant { value }) => u64::try_from(value).ok(),
        _ => None,
    };
    let complete = resolved.is_some() && operations.next().ok()?.is_none();
    match resolved {
        Some(value) if complete && value <= i32::MAX as u64 => Some(value as u32),
        _ => None,
    }
}

// Ghidra: DWARFProgram.java:375 indexDIEATypeRefs — one ordered .debug_info walk recording
// every DIE's DW_AT_type inbound reference; the parent/child-position facts the
// anonymous-name chain needs ride along so the naming pass never re-reads entries
fn build_dwarf_die_table(dwarf: &Dwarf<DwarfReader>) -> Result<DwarfDieTable> {
    let mut table = DwarfDieTable::default();
    let mut by_section: std::collections::HashMap<u64, GlobalDieId> =
        std::collections::HashMap::new();
    // DW_FORM_ref_addr targets (section-absolute) may point forward; resolve
    // them after the walk the way diesByOffset (:460) serves every offset.
    let mut pending_section_refs: Vec<(usize, u64)> = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().context("iterating DWARF units for the type-reference index")? {
        let unit = dwarf
            .unit(header)
            .context("loading DWARF unit for the type-reference index")?;
        let unit_base = unit
            .header
            .offset()
            .as_debug_info_offset()
            .map(|offset| offset.0 as u64)
            .unwrap_or(0);
        let mut entries = unit.entries();
        // Depth accumulation mirrors the parse_elf scope walk above (same
        // gimli next_dfs delta semantics): stack frames carry
        // (id, children-seen-so-far) so child_position is the all-tag
        // 0-based sibling index getPositionInParent computes.
        let mut parent_stack: Vec<(GlobalDieId, usize)> = Vec::new();
        let mut absolute_depth: isize = 0;
        while let Some((delta, entry)) = entries
            .next_dfs()
            .context("walking DWARF DIEs for the type-reference index")?
        {
            absolute_depth += delta;
            let depth = usize::try_from(absolute_depth).unwrap_or(0);
            // Strict-ancestor pop (parse_elf's scope walk keeps sloppier
            // equal-depth frames; this walk needs the exact parent for
            // child_position). The emptiness guard terminates the depth-0
            // / negative-delta edge (root-level and malformed streams)
            // instead of popping an empty Vec forever.
            while parent_stack.len() >= depth && !parent_stack.is_empty() {
                parent_stack.pop();
            }
            let id = (unit_base, entry.offset().0);
            let (parent, child_position) = match parent_stack.last_mut() {
                Some(frame) => {
                    let position = frame.1;
                    frame.1 += 1;
                    (Some(frame.0), position)
                }
                None => (None, 0),
            };
            let name_attr = entry_string(dwarf, &unit, entry, gimli::DW_AT_name)?;
            let entry_name =
                name_arg_linkage_chain(dwarf, &unit, entry, name_attr.as_ref())?;
            let byte_size = match entry.attr_value(gimli::DW_AT_byte_size)? {
                Some(gimli::AttributeValue::Udata(value)) => Some(value),
                Some(gimli::AttributeValue::Sdata(value)) => Some(value as u64),
                _ => None,
            };
            let member_offset = match entry.attr_value(gimli::DW_AT_data_member_location)? {
                Some(gimli::AttributeValue::Udata(value)) => {
                    if value <= i32::MAX as u64 {
                        value as u32
                    } else {
                        0
                    }
                }
                Some(gimli::AttributeValue::Sdata(value)) => {
                    if (0..=i32::MAX as i64).contains(&value) {
                        value as u32
                    } else {
                        0
                    }
                }
                Some(gimli::AttributeValue::Exprloc(ref expression)) => {
                    soft_member_location(&unit, expression).unwrap_or(0)
                }
                _ => 0,
            };
            let external = entry.attr_value(gimli::DW_AT_external)?.is_some();
            let mut pending_section_target = None;
            let type_target = match entry.attr_value(gimli::DW_AT_type)? {
                Some(gimli::AttributeValue::UnitRef(offset)) => Some((unit_base, offset.0)),
                Some(gimli::AttributeValue::DebugInfoRef(offset)) => {
                    pending_section_target = Some(offset.0 as u64);
                    None
                }
                _ => None,
            };
            let record_index = table.records.len();
            let record_type_target = type_target;
            table.records.push(DwarfDieRecord {
                id,
                tag: entry.tag(),
                entry_name,
                name_attr,
                type_target: record_type_target,
                parent,
                child_position,
                byte_size,
                external,
                member_offset,
            });
            if let Some(target) = record_type_target {
                table.type_refs.entry(target).or_default().push(record_index);
            }
            if let Some(section_offset) = pending_section_target {
                pending_section_refs.push((record_index, section_offset));
            }
            table.by_id.insert(id, record_index);
            by_section.insert(unit_base + entry.offset().0 as u64, id);
            parent_stack.push((id, 0));
        }
    }
    for (record_index, section_offset) in pending_section_refs {
        if let Some(&target) = by_section.get(&section_offset) {
            table.type_refs.entry(target).or_default().push(record_index);
        }
    }
    Ok(table)
}

// RUGRA-GLUE: the getEntryName fallback chain (DWARFProgram.java:590-602) — DW_AT_name,
// then DW_AT_linkage_name, then DW_AT_MIPS_linkage_name — as a pure helper over the
// already-read DW_AT_name value
fn name_arg_linkage_chain(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    entry: &DebuggingInformationEntry<DwarfReader>,
    name_attr: Option<&String>,
) -> Result<Option<String>> {
    if let Some(name) = name_attr {
        return Ok(Some(name.clone()));
    }
    let linkage = match entry_string(dwarf, unit, entry, gimli::DW_AT_linkage_name)? {
        Some(name) => Some(name),
        None => entry_string(dwarf, unit, entry, gimli::DW_AT_MIPS_linkage_name)?,
    };
    Ok(linkage)
}

// Ghidra: DWARFTag.java:200 isStructureType — class/interface/struct/union
fn dwarf_tag_is_structure_type(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_class_type
            | gimli::DW_TAG_interface_type
            | gimli::DW_TAG_structure_type
            | gimli::DW_TAG_union_type
    )
}

// Ghidra: DWARFTag.java:229 getContainerTypeName — the container word in anon names
// (interface has no case and falls to the "unknown" default)
fn dwarf_container_type_name(tag: gimli::DwTag) -> &'static str {
    match tag {
        gimli::DW_TAG_structure_type => "struct",
        gimli::DW_TAG_class_type => "class",
        gimli::DW_TAG_enumeration_type => "enum",
        gimli::DW_TAG_union_type => "union",
        gimli::DW_TAG_lexical_block => "lexical_block",
        gimli::DW_TAG_subprogram => "subprogram",
        gimli::DW_TAG_subroutine_type => "subr",
        gimli::DW_TAG_variable => "var",
        _ => "unknown",
    }
}

// Ghidra: DWARFUtil.java:267 getStructLayoutFingerprint — "%d_%d_%08x" of struct size,
// member count and the Java List hashCode of the sorted "%04x_%s" member strings
fn struct_layout_fingerprint(table: &DwarfDieTable, id: GlobalDieId) -> String {
    // :268 structSize = getUnsignedLong(DW_AT_byte_size, 0) — numeric forms
    // only; a consistent table always carries the DIE being named.
    let struct_size = match table.by_id.get(&id) {
        Some(&index) => table.records[index].byte_size.unwrap_or(0),
        None => 0,
    };
    let mut member_names: Vec<String> = Vec::new();
    let mut member_count: usize = 0;
    for child in table.children(id) {
        // :272-275 only DW_TAG_member / DW_TAG_inheritance children enter.
        if !matches!(
            child.tag,
            gimli::DW_TAG_member | gimli::DW_TAG_inheritance
        ) {
            continue;
        }
        // :277-279 children carrying DW_AT_external are skipped (and do not
        // increment the count).
        if child.external {
            continue;
        }
        // :280 count increments after the external skip.
        member_count += 1;
        // :282,:290-292 DIEAggregate.getName = DW_AT_name only; unnamed
        // members become UNNAMED_MEMBER_<count-after-increment>.
        let member_name = child
            .name_attr
            .clone()
            .unwrap_or_else(|| format!("UNNAMED_MEMBER_{member_count}"));
        // :293 "%04x_%s" of the member offset (missing/erroring location
        // attributes already folded to 0 in the table).
        member_names.push(format!("{:04x}_{}", child.member_offset, member_name));
    }
    // :296 Collections.sort — lexicographic over the formatted strings
    // (UTF-16 unit order for Java; identical to Rust byte order for the
    // ASCII member names C producers emit).
    member_names.sort();
    // :297 "%d_%d_%08x" — size as decimal long, count as decimal, hash as
    // 8-digit lowercase hex of the 32-bit List hashCode.
    format!(
        "{}_{}_{:08x}",
        struct_size,
        member_count,
        java_list_hashcode(&member_names)
    )
}

// Ghidra: java.lang.String hashCode — 31-polynomial over UTF-16 code units with 32-bit wraparound
fn java_string_hashcode(text: &str) -> u32 {
    text.encode_utf16()
        .fold(0u32, |hash, unit| {
            hash.wrapping_mul(31).wrapping_add(u32::from(unit))
        })
}

// Ghidra: java.util.AbstractList hashCode — fold 1 = 31*fold + element.hashCode with wraparound
fn java_list_hashcode(texts: &[String]) -> u32 {
    texts.iter().fold(1u32, |hash, text| {
        hash.wrapping_mul(31)
            .wrapping_add(java_string_hashcode(text))
    })
}

// Ghidra: DWARFProgram.java:792 getReferringMemberFieldNames — "_for_" field names of the
// member DIEs whose DW_AT_type references the anon type; aborted to "" when the referring
// members do not share one parent
fn referring_member_field_names(table: &DwarfDieTable, id: GlobalDieId) -> String {
    // :663-664 + :1393-1402 getTypeReferers(target, DW_TAG_member).
    let referring_members = table.type_referers(id, gimli::DW_TAG_member);
    if referring_members.is_empty() {
        // :793-795
        return String::new();
    }
    // :796 common parent of the first referring member.
    let common_parent = referring_members[0].parent;
    let mut result = String::new();
    for member in &referring_members {
        // :799-802 any referring member from a different parent aborts the
        // whole suffix (diea.getParent identity: same head offset = same
        // aggregate object for C producers).
        if member.parent != common_parent {
            return String::new();
        }
        // :804 member name via DIEAggregate.getName (DW_AT_name only).
        let member_name = match &member.name_attr {
            Some(name) => name.clone(),
            None => {
                // :805-813 unnamed referring member -> "<parentName>_<position>"
                // with the position among ALL siblings (x -> true filter,
                // getPositionInParent :1472-1490). The -1 corrupt-index skip
                // (:808-810) cannot arise — records always carry their
                // child position; a root-level member has no parent and is
                // skipped the same way.
                let Some(parent) = common_parent else {
                    continue;
                };
                let parent_name = dwarf_type_leaf_name(table, parent, 0);
                format!("{parent_name}_{}", member.child_position)
            }
        };
        // :814-817 join with "_".
        if !result.is_empty() {
            result.push('_');
        }
        result.push_str(&member_name);
    }
    // :819
    result
}

// Ghidra: DWARFProgram.java:845 ensureSafeNameLength — 2000-char clamp (SymbolUtilities.java:35)
// with the "..."$<hash>$" tail for over-long names; applied on the generic getDWARFName
// exit (:728), i.e. to entry names and typedef-steal results, not to the anon fingerprint
// spelling which returns early at :674
fn ensure_safe_name_length(name: String) -> String {
    // Java String.length counts UTF-16 units.
    if name.encode_utf16().count() <= 2000 {
        return name;
    }
    // :849 abbrevTemplateName (C++ '<...>' sugar, :834-843) never triggers
    // for the C names this importer serves — skipped.
    // :853-855 keep 2000-3-12=1985 leading units, "..." and "$<hex>$" of the
    // full-name String hashCode.
    let prefix_keep = 2000 - "...".len() - (8 + 2 + 2);
    let hash = java_string_hashcode(&name);
    let prefix: String = String::from_utf16_lossy(
        &name.encode_utf16().take(prefix_keep).collect::<Vec<u16>>(),
    );
    format!("{prefix}...${hash:x}$")
}

// Ghidra: DWARFProgram.java:658 getDWARFName anonymous-structure branch —
// "anon_<container>_<layout-fingerprint>_for_<fields>" for an unnamed structure type
fn anon_composite_type_name(table: &DwarfDieTable, id: GlobalDieId) -> String {
    let container = table
        .by_id
        .get(&id)
        .map(|&index| dwarf_container_type_name(table.records[index].tag))
        .unwrap_or("unknown");
    // :659 layout fingerprint.
    let fingerprint = struct_layout_fingerprint(table, id);
    // :663-666 referring member field names.
    let referring_member_names = referring_member_field_names(table, id);
    // :667-672 non-empty names gain the "_for_" prefix (and the type is
    // re-homed into the referring struct's namespace at :670 — a category
    // path change only; the decompiler prints the unqualified leaf name,
    // golden witness `(anon_union_16_3_e2f18bb4_for_content)`).
    let suffix = if referring_member_names.is_empty() {
        String::new()
    } else {
        format!("_for_{referring_member_names}")
    };
    // :673-674 leaf name returned without the length clamp (early return
    // ahead of the :728 ensureSafeNameLength pass).
    format!("anon_{container}_{fingerprint}{suffix}")
}

// Ghidra: DWARFProgram.java:610 getDWARFName — leaf-name spelling for a type DIE the way
// the importer records it (DWARFName.getName, DWARFName.java:144-146); C-corpus walk:
// entry name (:590-602), single-inbound-typedef steal (:650-656), anonymous structure
// fingerprint naming (:658-675), anonymous enum size naming (:684-686 -> :771-774)
fn dwarf_type_leaf_name(table: &DwarfDieTable, id: GlobalDieId, depth: usize) -> String {
    let Some(&index) = table.by_id.get(&id) else {
        // Unreachable for tables built over the same section the id came
        // from; keep the fingerprint spelling as the defensive exit.
        return anon_composite_type_name(table, id);
    };
    let record = &table.records[index];
    // :626 getEntryName (:590-602 DW_AT_name -> linkage chain).
    // :629-638 mangled "_Z" nesting demangle and :642-648 child linkage-name
    // namespace recovery are C++-producer paths (no "_Z" names in the C
    // corpora) — not carried.
    let name = record.entry_name.clone();
    // :650-656 exactly one inbound DW_TAG_typedef referer steals the
    // typedef's own DWARFName — NOT CARRIED (conservative degradation,
    // 铁律 1.5): Rugra materializes typedefs as renamed clones of the
    // underlying type (materialized_alias/alias_type) instead of Ghidra's
    // separate TypedefDataType, so the steal's only end-to-end effect here
    // is interning the underlying DIE under the typedef name, colliding
    // with the alias layer in the name-keyed TypeFactory (observed: PARAMID
    // round-2 decompile stall on the curl corpus). The typedef-referred
    // name is already carried by the alias layer; restore when a
    // TypeTypedef variant lands (type.hh:431 TypeTypedef).
    let _ = depth;
    if name.is_none() && dwarf_tag_is_structure_type(record.tag) {
        // :658-675 anonymous structure naming (fingerprint + "_for_" fields).
        return anon_composite_type_name(table, id);
    }
    // :684-686 -> getAnonEnumName (:771-774) "anon_enum_<bits>" — NOT
    // CARRIED (conservative degradation, 铁律 1.5): in Java the anonymous
    // enum's final name comes from the :650-656 typedef steal (every
    // corpus anon enum is single-typedef'd), and the two are inseparable;
    // carrying "anon_enum_32" without the steal makes every 4-byte anon
    // enum share one name, and the name-keyed factory's same-shape merge
    // then collapses distinct enums' value tables (observed: curl
    // HTTPREQ_* constants rendering as TIMECOND_* from the merged table,
    // +40 canon lines). The offset spelling keeps tables distinct; restore
    // with the steal when TypeTypedef lands. The spelling itself has zero
    // corpus surface (no anon enum name is printed).
    match name {
        Some(name) => ensure_safe_name_length(name),
        None => {
            // :680-717 anonymous base/subroutine/lexical spellings never
            // arise for the composite/typedef DIEs this walk serves (member
            // parents and typedef targets are composites in every C
            // witness); keep the historical offset spelling as the
            // defensive exit.
            format!("{}_{:x}", dwarf_container_type_name(record.tag), record.id.1)
        }
    }
}

// Ghidra: DWARFProgram.java:626 getEntryName + :650-675 — anonymous composite DIE naming
// driver used by resolve_type_inner/shallow_type: full entry-name chain, single inbound
// typedef steal, then the layout-fingerprint anonymous name
fn composite_type_name(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<String> {
    let table = build_dwarf_die_table(dwarf)?;
    let unit_base = unit
        .header
        .offset()
        .as_debug_info_offset()
        .map(|offset| offset.0 as u64)
        .unwrap_or(0);
    Ok(dwarf_type_leaf_name(&table, (unit_base, offset.0), 0))
}

// RUGRA-GLUE: reads direct DW_TAG_enumerator children into the value→name table Ghidra keeps on its enum data types for constant-name rendering
fn read_enumerators(
    dwarf: &Dwarf<DwarfReader>,
    unit: &Unit<DwarfReader>,
    offset: UnitOffset<usize>,
) -> Result<BTreeMap<u64, String>> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    let mut values = BTreeMap::new();
    while let Some((delta, entry)) = cursor.next_dfs()? {
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() != gimli::DW_TAG_enumerator {
            continue;
        }
        let Some(name) = entry_string(dwarf, unit, entry, gimli::DW_AT_name)? else {
            continue;
        };
        let Some(value) = entry
            .attr_value(gimli::DW_AT_const_value)?
            .and_then(|value| value.udata_value())
        else {
            continue;
        };
        values.insert(value, name);
    }
    Ok(values)
}

// RUGRA-GLUE: reads the first DW_TAG_subrange child's element count (DW_AT_count, or DW_AT_upper_bound+1) which is the array length Ghidra's DWARF analyzer assigns
fn read_array_count(unit: &Unit<DwarfReader>, offset: UnitOffset<usize>) -> Result<usize> {
    let mut cursor = unit.entries_at_offset(offset)?;
    let mut first = true;
    let mut walk_depth = 0isize;
    for _ in 0..64 {
        let Some((delta, entry)) = cursor.next_dfs()? else {
            break;
        };
        if first {
            first = false;
            continue;
        }
        walk_depth += delta;
        if walk_depth <= 0 {
            break;
        }
        if walk_depth != 1 {
            continue;
        }
        if entry.tag() == gimli::DW_TAG_subrange_type {
            if let Some(value) = entry.attr_value(gimli::DW_AT_count)? {
                if let Some(count) = value.udata_value() {
                    return Ok(count as usize);
                }
            }
            if let Some(value) = entry.attr_value(gimli::DW_AT_upper_bound)? {
                if let Some(upper) = value.udata_value() {
                    return Ok(upper as usize + 1);
                }
            }
            return Ok(0);
        }
    }
    Ok(0)
}

// RUGRA-GLUE: constructs a leaf Datatype from front-end debug metadata before it enters Ghidra-aligned type analysis
fn base_type(name: String, size: usize, metatype: TypeMetatype) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Base(TypeBase::new(name, size, metatype))))
}

// RUGRA-GLUE: constructs a fielded struct Datatype from DWARF DW_TAG_member children; Ghidra builds the equivalent Structure dataType in its DWARF/type-manager front end
fn struct_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    intern_named(Arc::new(Datatype::Struct(TypeStruct {
        base: TypeBase::new(name, size, TypeMetatype::Struct),
        fields,
    })))
}

// RUGRA-GLUE: constructs a fielded union Datatype from DWARF union members (all at offset 0)
fn union_type(name: String, size: usize, fields: Vec<TypeField>) -> Arc<Datatype> {
    let mut base = TypeBase::new(name, size, TypeMetatype::Union);
    // Ghidra's TypeUnion constructor sets needs_resolution (type.hh:551);
    // the import completes the fields immediately (the ctor's
    // type_incomplete counterpart is cleared by setFields), but the
    // resolution flag survives — every decoded/imported union carries it.
    // Pointers to the union inherit the flag in TypePointer::calcSubmeta
    // (type.cc:1048-1049), which is what drives
    // ActionInferTypes::propagateTypeEdge's always-resolve arm
    // (coreaction.cc:5081-5084) and ActionSetCasts::resolveUnion
    // (coreaction.cc:2490). Without it the whole ResolvedUnion machinery
    // starves (COREACT-C3-UNIONRES-0001). Same flagging pattern as
    // enum_type's ENUMTYPE note above.
    base.flags |= crate::type_system::datatype::type_flags::NEEDS_RESOLUTION;
    intern_named(Arc::new(Datatype::Union(TypeUnion {
        base,
        fields,
    })))
}

// RUGRA-GLUE: constructs an enum Datatype with its DWARF enumerator value table for constant-name rendering
fn enum_type(name: String, size: usize, values: BTreeMap<u64, String>) -> Arc<Datatype> {
    let mut base = TypeBase::new(name, size, TypeMetatype::Enum);
    // Ghidra's TypeEnum sets the `enumtype` flag (type.hh:490-494 /
    // TypeFactory decode paths); isEnumType() is flag-based, so an enum
    // without the flag is invisible to PrintC::pushConstant's enum arm
    // (printc.cc:1756/1763) and prints as a default cast. Mirrors the
    // decode-side flagging in the factory (datatype.rs ENUMTYPE sets).
    base.flags |= crate::type_system::datatype::type_flags::ENUMTYPE;
    intern_named(Arc::new(Datatype::Enum(TypeEnum {
        base,
        values,
    })))
}

// RUGRA-GLUE: DWARF-import type-manager canonicalization. Ghidra's DWARF
// analyzer resolves every DIE type through the Architecture's ONE
// TypeFactory (type.cc findByName/setName interning), so the same-named
// structure reached from two variables — or from both the globals pass
// (DebugGlobalDatabase) and the prototype pass (DebugPrototypeDatabase) —
// is ONE interned Datatype object, and pointer-identity comparisons
// (CastStrategyC::castStandard's `curtype == reqtype`, cast.cc:299;
// ActionSetCasts' store-value cast, coreaction.cc:553-554) see equal types
// and emit no cast. Rugra's two independent DWARF passes each built fresh
// Arcs, so `*glob = glob_expand;` (URLGlob** param vs typelocked URLGlob*
// global read) gained a spurious `(URLGlob *)` cast. This soft intern
// reuses the shared factory's existing name entry when the shape (enum
// variant), size, and metatype match — the shape guard keeps a cycle-break
// shallow projection (base_type with a composite metatype) from shadowing
// the full fielded definition of the same DWARF name — and registers the
// new type otherwise. This is the cross-parse identity half of the importer
// boundary noted as untracked on alias_type.
fn intern_named(candidate: Arc<Datatype>) -> Arc<Datatype> {
    let name = candidate.get_name().to_string();
    if name.is_empty() {
        return candidate;
    }
    // Ghidra's transport decode derives the id when the name is present and
    // no explicit id traveled (type.cc:675-676 `id = hashName(name); //
    // There must be some kind of id`, Datatype::decodeBasic) — and
    // TypeFactory::findAdd rejects a zero id outright (type.cc:3417-3425
    // "Datatype must have a valid id"). Rugra's DWARF constructors
    // (base_type/struct_type/union_type/enum_type) leave the fresh
    // TypeBase id at 0, so without this derivation the findAdd below
    // errors and the candidate silently stays UNREGISTERED — invisible
    // to the HashMap-carried consumers but a None lookup for every
    // name-tree resolution (parse_c_type's findByName mirror, the C4
    // struct-seed channel's spelling resolver; OUTSTRUCT-ID0). The
    // typedef path (alias_type) already hashes explicitly, matching this
    // rule; deriving here makes every import-boundary candidate follow
    // the same decodeBasic contract.
    let candidate = if candidate.get_id() == 0 {
        let mut derived = (*candidate).clone();
        derived.base_record_mut().id = Datatype::hash_name(&name);
        Arc::new(derived)
    } else {
        candidate
    };
    // Ghidra's DWARF front end never feeds an incomplete (zero-size)
    // composite to TypeFactory::findAdd — findAdd's layout pass would hit
    // getPrimitiveAlignSize(0), a division by the default alignment map's
    // zero entry (type.cc:3429-3437); the declaration-only DIEs stay
    // unregistered stubs on the Java side. Rugra's resolve_type still
    // builds zero-size candidates for DW_AT_declaration composites (the
    // anonymous forward refs inside field graphs), so they keep the
    // historical unregistered course here too: returned as-is, invisible
    // to the name tree, harmless to the HashMap-carried consumers
    // (OUTSTRUCT-ID0 follow-up guard).
    if candidate.get_size() == 0 {
        return candidate;
    }
    let factory = crate::type_system::typefactory::TypeFactory::shared_default();
    let mut guard = factory.write().unwrap();
    if let Some(existing) = guard.find_by_name(&name) {
        let same_shape = std::mem::discriminant(existing.as_ref())
            == std::mem::discriminant(candidate.as_ref());
        if same_shape
            && existing.get_size() == candidate.get_size()
            && existing.get_metatype() == candidate.get_metatype()
        {
            return existing;
        }
        // Same name, different shape/size (shallow cycle-break projection
        // vs the full definition, or a genuine DWARF redefinition): keep the
        // fresh candidate without touching the registered slot.
        return candidate;
    }
    match guard.intern_imported((*candidate).clone()) {
        Ok(interned) => interned,
        Err(_) => candidate,
    }
}

// RUGRA-GLUE: materializes a DWARF typedef as the underlying composite/enum renamed to the typedef spelling; Rugra's Datatype enum has no TypeTypedef variant yet (Ghidra type.hh has one), so fields and enumerator names are carried on the renamed type
fn materialized_alias(name: String, inner: &Datatype) -> Result<Arc<Datatype>> {
    Ok(alias_type(name, inner ))
}

// RUGRA-GLUE: preserves a DWARF typedef/qualifier spelling by cloning the
// resolved concrete datatype and changing only its name/id/core flag, matching
// the shape/flag-preserving clone portion of TypeFactory::getTypedef
// (type.cc:3818-3840). This retains TypeChar's chartype/submeta state and the
// full pointer/array/composite shape. Architecture-owned canonical insertion
// remains a separately tracked importer boundary.
fn alias_type(name: String, inner: &Datatype) -> Arc<Datatype> {
    let mut alias = inner.clone();
    let base = alias.base_record_mut();
    base.name = name.clone();
    base.display_name = name.clone();
    base.id = Datatype::hash_name(&name);
    base.flags &= !crate::type_system::datatype::type_flags::CORETYPE;
    intern_named(Arc::new(alias))
}

// RUGRA-GLUE: constructs a pointer Datatype from a resolved DWARF pointee at the native debug-import boundary
fn pointer_type(pointee: Arc<Datatype>, size: usize) -> Arc<Datatype> {
    // Ghidra builds DWARF pointer types anonymously (the TypeFactory 3-arg
    // getTypePointer path, type.cc:3867-3875 — DW_AT_name on a pointer
    // typedef attaches via alias_type, not here); see parse_c_type's note
    // for why the former composed display name diverged from the oracle.
    // The factory pass below canonicalizes pointer identity the way the
    // oracle's single TypeFactory does for every DWARF type.
    crate::type_system::typefactory::TypeFactory::shared_default()
        .write()
        .unwrap()
        .get_type_pointer(size, pointee, 1)
}

// RUGRA-GLUE: canonical locked-void type used when DW_AT_type is absent on a subprogram or pointer target.
// GLIBC-PROTO-PARAMNAME-0001: routed through the canonical shared factory
// (Ghidra's single `void` core type) so `void *` pointee identity is the
// factory's, not a per-parse clone.
fn void_type() -> Arc<Datatype> {
    crate::type_system::typefactory::TypeFactory::shared_default()
        .read()
        .unwrap()
        .get_type_void()
}

// RUGRA-GLUE: fail-visible unknown DWARF type used only when a DIE omits a resolvable type reference
fn unknown_type(size: usize) -> Arc<Datatype> {
    base_type(format!("undefined{size}"), size, TypeMetatype::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: the archive FILE struct is the
    // generic_clib_64 layout extracted from the locked oracle tree's own
    // .gdt field-name table (29 fields, 216 bytes, `__pad1..__pad4` at
    // offsets 152..176 — the glibc compat spelling of the slots curl's
    // DWARF names `_codecvt/_wide_data/_freeres_list/_freeres_buf`).
    #[test]
    fn clib_file_struct_matches_generic_clib64_layout() {
        let file = clib_file_struct();
        assert_eq!(file.get_name(), "FILE");
        assert_eq!(file.get_size(), 216);
        assert_eq!(file.get_metatype(), TypeMetatype::Struct);
        let Datatype::Struct(st) = file.as_ref() else {
            panic!("clib FILE must be a struct");
        };
        assert_eq!(st.fields.len(), 29);
        let names: Vec<(usize, &str)> =
            st.fields.iter().map(|f| (f.offset, f.name.as_str())).collect();
        assert_eq!(names[0], (0, "_flags"));
        assert_eq!(names[21], (144, "_offset"));
        let pads: Vec<&str> = st.fields[22..26].iter().map(|f| f.name.as_str()).collect();
        assert_eq!(pads, vec!["__pad1", "__pad2", "__pad3", "__pad4"]);
        let offsets: Vec<usize> = st.fields[22..26].iter().map(|f| f.offset).collect();
        assert_eq!(offsets, vec![152, 160, 168, 176]);
        assert_eq!(names[28], (196, "_unused2"));
    }

    // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: two FILE domains never unify —
    // the archive FILE and a DWARF-shaped FILE (identical slots, DWARF
    // field spellings at 152..176) are distinct objects, and the
    // makeRec repeat tie-break direction (coreaction.cc:2833-2845) is
    // decided by the FIRST field-name difference: `_codecvt` >
    // `__pad1` string-wise, so a DWARF-FILE* recommendation held first
    // is overridden by the archive FILE* — the exact ordering that names
    // parseconfig's local `__stream` instead of `fp` in the locked
    // golden (TypeStruct::compare, type.cc:1742-1780).
    #[test]
    fn clib_file_domain_dominates_dwarf_file_in_type_order() {
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let clib_file = clib_file_struct();
        let Datatype::Struct(clib_st) = clib_file.as_ref() else {
            panic!("clib FILE must be a struct");
        };
        let dwarf_fields: Vec<TypeField> = clib_st
            .fields
            .iter()
            .map(|f| {
                let mut field = f.clone();
                match field.offset {
                    152 => field.name = "_codecvt".to_string(),
                    160 => field.name = "_wide_data".to_string(),
                    168 => field.name = "_freeres_list".to_string(),
                    176 => field.name = "_freeres_buf".to_string(),
                    _ => {}
                }
                field
            })
            .collect();
        let dwarf_file = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("FILE".to_string(), 216, TypeMetatype::Struct),
            fields: dwarf_fields,
        }));
        assert!(!Arc::ptr_eq(&clib_file, &dwarf_file));
        let (clib_ptr, dwarf_ptr) = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                factory.get_type_pointer_default(clib_file.clone()),
                factory.get_type_pointer_default(dwarf_file.clone()),
            )
        };
        assert!(!Arc::ptr_eq(&clib_ptr, &dwarf_ptr));
        // DWARF FILE* held first, archive FILE* arrives second: the
        // override fires (positive typeOrder at the field-name delta).
        assert!(dwarf_ptr.type_order(&clib_ptr) > 0);
        // Symmetric: the archive FILE* held first is NOT demoted.
        assert!(clib_ptr.type_order(&dwarf_ptr) < 0);
    }

    // GLIBC-CLIB-FILE-TYPEDOMAIN-0001: locked_proto resolves the FILE
    // spelling of the libc ledger through the archive domain even when a
    // DWARF name index offers its own FILE — the two channels stay
    // distinct exactly like the oracle's generic_clib boundary.
    // (The full locked_proto call needs the architecture's bound
    // defaultfp carrier for parameter-storage assignment; the resolution
    // seam it threads every spelling through is
    // libc_type_resolution_index, covered by the test above.)

    // GLIBC-CLIB-FILE-TYPEDOMAIN-0001 + CURLCANON-CASTA-STAT-0001: the
    // libc ledger's resolution index routes the FILE and stat spellings
    // through the archive domain even when a DWARF name index offers its
    // own FILE/stat, and leaves every other spelling on the DWARF
    // resolution — the channels stay distinct exactly like the oracle's
    // generic_clib boundary (locked_proto parses through exactly this map).
    #[test]
    fn libc_type_resolution_index_splits_file_domains() {
        let mut dwarf_index: HashMap<String, Arc<Datatype>> = HashMap::new();
        let dwarf_file = clib_file_struct();
        dwarf_index.insert("FILE".to_string(), dwarf_file.clone());
        let dwarf_stat = clib_stat_struct();
        dwarf_index.insert("stat".to_string(), dwarf_stat.clone());
        let urlglob = dwarf_file.clone();
        dwarf_index.insert("URLGlob".to_string(), urlglob.clone());
        let index = libc_type_resolution_index(Some(&dwarf_index));
        let resolved = parse_c_type("FILE *", 8, Some(&index))
            .expect("FILE * resolves through the split index");
        let Datatype::Pointer(tp) = resolved.as_ref() else {
            panic!("FILE * must resolve to a pointer");
        };
        // The pointee is the archive FILE object (the OnceLock identity),
        // and the interned pointer matches the clib domain's pointer.
        assert!(Arc::ptr_eq(&tp.ptr_to, &clib_file_types().0));
        assert!(Arc::ptr_eq(&resolved, &clib_file_types().1));
        // A non-FILE spelling keeps its DWARF resolution untouched.
        assert!(Arc::ptr_eq(index.get("URLGlob").unwrap(), &urlglob));

        // CURLCANON-CASTA-STAT-0001: `stat *` resolves through the archive
        // stat domain, never the DWARF name-index entry — the signature
        // param and a DWARF-typed local hold distinct objects so the
        // golden's `(stat *)&fileinfo` cast survives castStandard's
        // cc:304/:329 pointer-identity early-exits (cast.cc:300-392).
        let stat_resolved = parse_c_type("stat *", 8, Some(&index))
            .expect("stat * resolves through the split index");
        let Datatype::Pointer(stat_tp) = stat_resolved.as_ref() else {
            panic!("stat * must resolve to a pointer");
        };
        assert!(Arc::ptr_eq(&stat_tp.ptr_to, &clib_stat_types().0));
        assert!(Arc::ptr_eq(&stat_resolved, &clib_stat_types().1));
        // The override does not touch the DWARF index itself: the
        // caller's entry keeps its own object.
        assert!(Arc::ptr_eq(dwarf_index.get("stat").unwrap(), &dwarf_stat));
    }

    // CURLCANON-CASTA-STAT-0001: the archive stat is the generic_clib
    // glibc x86-64 bits/stat.h layout — 144 bytes, 15 fields, the ABI
    // field order/offsets curl's own DWARF struct stat carries
    // (readelf <444>: st_dev@0 .. __glibc_reserved@120).
    #[test]
    fn clib_stat_struct_matches_generic_clib64_layout() {
        let stat = clib_stat_struct();
        assert_eq!(stat.get_name(), "stat");
        assert_eq!(stat.get_size(), 144);
        assert_eq!(stat.get_metatype(), TypeMetatype::Struct);
        let Datatype::Struct(st) = stat.as_ref() else {
            panic!("clib stat must be a struct");
        };
        assert_eq!(st.fields.len(), 15);
        let layout: Vec<(usize, &str)> =
            st.fields.iter().map(|f| (f.offset, f.name.as_str())).collect();
        assert_eq!(
            layout,
            vec![
                (0, "st_dev"),
                (8, "st_ino"),
                (16, "st_nlink"),
                (24, "st_mode"),
                (28, "st_uid"),
                (32, "st_gid"),
                (36, "__pad0"),
                (40, "st_rdev"),
                (48, "st_size"),
                (56, "st_blksize"),
                (64, "st_blocks"),
                (72, "st_atim"),
                (88, "st_mtim"),
                (104, "st_ctim"),
                (120, "__glibc_reserved"),
            ]
        );
        // Field metatypes follow the ABI (__dev_t/__mode_t/__off_t
        // chains): uint64/uint32/int32/int64 tiers and the trailing
        // long[3] array.
        assert_eq!(st.fields[0].type_ptr.get_metatype(), TypeMetatype::Uint);
        assert_eq!(st.fields[0].type_ptr.get_size(), 8);
        assert_eq!(st.fields[3].type_ptr.get_size(), 4);
        assert_eq!(st.fields[6].type_ptr.get_metatype(), TypeMetatype::Int);
        assert_eq!(st.fields[8].type_ptr.get_metatype(), TypeMetatype::Int);
        assert_eq!(st.fields[8].type_ptr.get_size(), 8);
        let Datatype::Struct(timespec) = st.fields[11].type_ptr.as_ref() else {
            panic!("st_atim must be a timespec struct");
        };
        assert_eq!(st.fields[11].type_ptr.get_size(), 16);
        assert_eq!(timespec.fields.len(), 2);
        assert_eq!(st.fields[14].type_ptr.get_metatype(), TypeMetatype::Array);
        assert_eq!(st.fields[14].type_ptr.get_size(), 24);
        // Two-universe witness: an equal-shape DWARF-side stat (same
        // name/size/fields) is still a DISTINCT object, and the
        // struct-vs-struct default arm of castStandard (cast.cc:387)
        // casts between their pointers — the golden `(stat *)` form.
        let dwarf_stat = Arc::new(Datatype::Struct(TypeStruct {
            base: TypeBase::new("stat".to_string(), 144, TypeMetatype::Struct),
            fields: st.fields.clone(),
        }));
        assert!(!Arc::ptr_eq(&stat, &dwarf_stat));
        let types = crate::type_system::typefactory::TypeFactory::shared_default();
        let (archive_ptr, dwarf_ptr) = {
            let mut factory = types
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                factory.get_type_pointer_default(stat.clone()),
                factory.get_type_pointer_default(dwarf_stat.clone()),
            )
        };
        assert!(!Arc::ptr_eq(&archive_ptr, &dwarf_ptr));
    }

    // Test-only drill: the spelling of the base type a (possibly nested)
    // anonymous pointer chain points at — the identity the composed name
    // used to carry before the anonymous-pointer alignment.
    trait PtrDrillBaseName {
        fn ptr_drill_base_name(&self) -> String;
    }
    impl PtrDrillBaseName for Arc<Datatype> {
        fn ptr_drill_base_name(&self) -> String {
            let mut cur = self.as_ref();
            while let Datatype::Pointer(p) = cur {
                cur = p.ptr_to.as_ref();
            }
            cur.get_name().to_string()
        }
    }

    // BRIDGE1-TYPESEED-PIDT: `__pid_t` must carry the committed glibc
    // typedef's (4, int) — the explicit size the oracle's <localdb>
    // transport would hold (gen_seed_xml BASES mirror) — so the seeded
    // local_34@-52 cannot overlap the 8B local_30@-48 neighbor.
    #[test]
    fn typeseed_pidt_base_carries_committed_four_byte_int() {
        let dt = parse_c_type("__pid_t", 8, None).expect("committed typedef resolves");
        assert_eq!(dt.get_name(), "__pid_t");
        assert_eq!(dt.get_size(), 4);
        assert_eq!(dt.get_metatype(), TypeMetatype::Int);
    }

    // BRIDGE1-TYPESEED-PIDT (fallback removal): an unresolvable bare name
    // is a parse error — the oracle never mints an address-sized unknown
    // base from a spelling (transport carries explicit size; grammar's
    // findByName miss fails the parse).
    #[test]
    fn typeseed_unknown_base_is_parse_error_not_address_sized_mint() {
        let err = parse_c_type("__not_a_committed_type", 8, None)
            .expect_err("unknown base must not mint a base");
        assert!(
            err.to_string().contains("unresolved base spelling"),
            "unexpected error text: {err}"
        );
    }

    // BRIDGE1-TYPESEED-MULTIDIM: C declarator order — `long[2][4]` is
    // array(2) of array(4) of long (outer arraysize = leftmost dimension,
    // matching the oracle's nested TypeArray transport).
    #[test]
    fn typeseed_multidim_array_strips_leftmost_dimension() {
        let dt = parse_c_type("long[2][4]", 8, None).expect("multidim resolves");
        let Datatype::Array(outer) = dt.as_ref() else {
            panic!("outermost must be an array");
        };
        assert_eq!(outer.num_elements, 2);
        assert_eq!(outer.base.size, 64); // 2 * 4 * 8
        let Datatype::Array(inner) = outer.array_of.as_ref() else {
            panic!("element must be the inner array");
        };
        assert_eq!(inner.num_elements, 4);
        assert_eq!(inner.base.size, 32); // 4 * 8
        assert_eq!(inner.array_of.get_size(), 8);
        assert_eq!(inner.array_of.get_name(), "long");
        // Single-dim spellings keep their shape: `char *[2]` stays
        // array(2) of char*.
        let single = parse_c_type("char *[2]", 8, None).expect("single-dim resolves");
        let Datatype::Array(arr) = single.as_ref() else {
            panic!("single-dim must be an array");
        };
        assert_eq!(arr.num_elements, 2);
        assert_eq!(arr.array_of.get_metatype(), TypeMetatype::Pointer);
    }

    struct TestSpecHost {
        registers: BTreeMap<String, crate::fspec::VarnodeData>,
    }

    impl crate::arch::SpecQuery for TestSpecHost {
        fn get_register(&self, name: &str) -> Option<crate::fspec::VarnodeData> {
            self.registers.get(name).copied()
        }

        fn space_by_name(&self, name: &str) -> Option<crate::space::AddressSpace> {
            use crate::space::AddressSpace;
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

        fn space_highest(&self, space: crate::space::AddressSpace) -> u64 {
            match space {
                crate::space::AddressSpace::Unique
                | crate::space::AddressSpace::Register
                | crate::space::AddressSpace::Join => 0xffff_ffff,
                _ => u64::MAX,
            }
        }

        fn unique_inject_base(&self) -> u64 {
            0x364_400
        }
    }

    impl crate::pcodeparse::SleighSymbolLookup for TestSpecHost {
        fn find_symbol(&self, name: &str) -> Option<crate::pcodeparse::SleighSymbol> {
            self.registers
                .get(name)
                .map(|data| crate::pcodeparse::SleighSymbol {
                name: name.to_string(),
                kind: crate::pcodeparse::SleightSymbolKind::Varnode(
                    crate::varnode::VarnodeData {
                        space: data.space,
                        offset: data.offset,
                        size: data.size.max(0) as usize,
                    },
                ),
            })
        }
    }

    fn model_carrier() -> FuncProto {
        let cspec = std::fs::read("sleigh_specs/x86-64-gcc.cspec")
            .expect("locked x86-64 gcc compiler spec");
        let mut store = crate::marshal::DocumentStorage::new();
        let document = store.parse_document(&cspec).expect("parse compiler spec");
        let root = document.root.clone().expect("compiler spec root");
        store.register_tag(&root);

        let sleigh = crate::sleigh_ffi::SleighCtx::new().expect("SLEIGH register catalog");
        let mut registers = BTreeMap::new();
        for index in 0..sleigh.num_registers() {
            let Some((name, space, offset, size)) = sleigh.register_info(index) else {
                continue;
            };
            let Ok(space_id) = u8::try_from(space) else {
                continue;
            };
            registers.insert(
                name,
                crate::fspec::VarnodeData {
                    space: crate::space::AddressSpace::from_id(space_id),
                    offset,
                    size,
                },
            );
        }
        let host = Arc::new(TestSpecHost { registers });
        let mut arch = crate::arch::Architecture::new();
        arch.archid = "x86:LE:64:default".to_string();
        let mut inject = crate::pcodeinject::PcodeInjectLibrary::new(0x364_400);
        inject.set_sleigh_lookup(host.clone());
        arch.pcodeinjectlib = Some(Arc::new(std::sync::RwLock::new(inject)));
        let mut userops = crate::userop::UserOpManage::new();
        userops.register_op(
            "segment".to_string(),
            crate::userop::UserOpType::Unspecialized,
        );
        arch.userops = Some(Arc::new(std::sync::RwLock::new(userops)));
        arch.parse_compiler_config(&mut store, host.as_ref(), 8)
            .expect("decode default ProtoModel");
        let mut carrier = FuncProto::new("carrier".to_string(), void_type());
        carrier.set_model(Some(
            arch.defaultfp
                .clone()
                .expect("default x86-64 gcc ProtoModel"),
        ));
        carrier
    }


    #[test]
    fn libc_signature_table_covers_the_24_locked_imports() {
        let table = LibcSignatureTable::default();
        for name in [
            "free", "malloc", "realloc", "memcpy", "strlen", "strcpy", "strcat", "strdup",
            "strchr", "strrchr", "strstr", "strtol", "puts", "isatty", "fileno", "fclose",
            "fopen", "fgets", "fputc", "fwrite", "exit", "time", "__xstat", "__ctype_b_loc",
        ] {
            assert!(table.lookup(name).is_some(), "missing signature for {name}");
        }
        assert!(table.lookup("not_an_import").is_none());
        // The stub-section spellings ride the same table (glibc reserved
        // parameter names included).
        assert_eq!(table.lookup("free").unwrap().parameters, "void *__ptr");
        assert_eq!(table.lookup("fwrite").unwrap().return_type, "size_t");
        assert_eq!(table.lookup("__ctype_b_loc").unwrap().parameters, "");
    }

    #[test]
    fn libc_locked_proto_assigns_sysv_storage_and_locks() {
        let carrier = model_carrier();
        let table = LibcSignatureTable::default();

        // free: void return, one void* parameter at RDI (0x38), fully locked.
        let free = table
            .locked_proto("free", &carrier, None)
            .expect("free signature represents")
            .expect("free is in the table");
        assert_eq!(free.return_type.get_metatype(), TypeMetatype::Void);
        assert_eq!(free.num_params(), 1);
        assert_eq!(free.get_param(0).unwrap().name, "__ptr");
        assert_eq!(free.get_param(0).unwrap().address.as_u64(), 0x38);
        assert!(free.is_output_locked());
        assert!(free.get_param(0).unwrap().is_type_locked());

        // strdup: char * return (8-byte pointer), one char* parameter.
        let strdup = table
            .locked_proto("strdup", &carrier, None)
            .expect("strdup signature represents")
            .expect("strdup is in the table");
        assert_eq!(strdup.return_type.get_metatype(), TypeMetatype::Pointer);
        assert_eq!(strdup.return_type.get_size(), 8);
        assert_eq!(strdup.get_param(0).unwrap().address.as_u64(), 0x38);

        match strdup.get_param(0).unwrap().data_type.as_ref() {
            Datatype::Pointer(pointer) => {
                assert!(pointer.ptr_to.is_char_print());
                assert_eq!(pointer.ptr_to.get_name(), "char");
            }
            other => panic!("strdup parameter is not a pointer: {other:?}"),
        }

        // strtol: long return, (char*, char**, int) at RDI/RSI/RDX.
        let strtol = table
            .locked_proto("strtol", &carrier, None)
            .expect("strtol signature represents")
            .expect("strtol is in the table");
        assert_eq!(strtol.num_params(), 3);
        // Signature-parsed pointers are ANONYMOUS (Ghidra's
        // PointerModifier::modType -> getTypePointer 3-arg, grammar.cc:2403
        // / type.cc:3867-3875); "char **" is the spelling, not the identity.
        let strtol_p1 = strtol.get_param(1).unwrap();
        assert_eq!(strtol_p1.data_type.get_name(), "");
        assert!(matches!(strtol_p1.data_type.as_ref(), Datatype::Pointer(_)));
        assert_eq!(strtol.get_param(2).unwrap().address.as_u64(), 0x10);

        // __ctype_b_loc: zero parameters, ushort ** return; the empty
        // parameter list is a locked void input.
        let ctype = table
            .locked_proto("__ctype_b_loc", &carrier, None)
            .expect("__ctype_b_loc signature represents")
            .expect("__ctype_b_loc is in the table");
        assert_eq!(ctype.num_params(), 0);
        // Anonymous pointer (see parse_c_type's Ghidra note).
        assert_eq!(ctype.return_type.get_name(), "");
        assert!(matches!(ctype.return_type.as_ref(), Datatype::Pointer(_)));
        assert!(ctype.void_input_locked);

        // Unknown imports stay unlocked (Ok(None) — active recovery decides).
        assert!(table
            .locked_proto("not_an_import", &carrier, None)
            .expect("unknown import does not error")
            .is_none());
    }

    #[test]
    fn compiler_model_spills_seventh_scalar_to_stack() {
        let mut proto = model_carrier();
        let scalar = base_type("long".to_string(), 8, TypeMetatype::Int);
        let pieces = crate::grammar::PrototypePieces {
            model: None,
            name: "eight_scalars".to_string(),
            out_type: Some(void_type()),
            in_types: vec![scalar; 8],
            in_names: (1..=8).map(|index| format!("p{index}")).collect(),
            first_var_arg_slot: -1,
        };
        proto.set_pieces(&pieces);
        assert!(!proto.has_input_errors());
        assert_eq!(proto.num_params(), 8);
        for (index, expected_offset) in [0x38, 0x30, 0x10, 0x08, 0x80, 0x88]
            .into_iter()
            .enumerate()
        {
            let param = proto.get_param(index).expect("register parameter");
            assert_eq!(param.address_space, crate::space::AddressSpace::Register);
            assert_eq!(param.address.as_u64(), expected_offset);
        }
        for (index, expected_offset) in [(6usize, 8u64), (7, 16)] {
            let param = proto.get_param(index).expect("stack parameter");
            assert_eq!(param.address_space, crate::space::AddressSpace::Stack);
            assert_eq!(param.address.as_u64(), expected_offset);
        }
    }

    #[test]
    fn curl_dwarf_prototypes_preserve_declared_shape() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");

        let getstr = db.get(0x36d0).expect("GetStr prototype");
        assert_eq!(getstr.name, "GetStr");
        assert_eq!(getstr.parameters.len(), 2);
        assert_eq!(getstr.parameters[0].name, "string");
        assert_eq!(getstr.parameters[1].name, "value");

        match getstr.parameters[1].data_type.as_ref() {
            Datatype::Pointer(pointer) => {
                assert_eq!(pointer.ptr_to.get_name(), "char");
                assert!(pointer.ptr_to.is_char_print());
            }
            other => panic!("GetStr value parameter is not a pointer: {other:?}"),
        }

        let progress = db.get(0x34d0).expect("myprogress prototype");
        assert_eq!(progress.parameters.len(), 5);
        assert_eq!(progress.parameters[0].name, "clientp");
        assert_eq!(progress.parameters[4].name, "ulnow");

        let helpf = db.get(0x3980).expect("helpf prototype");
        assert_eq!(helpf.parameters.len(), 1);
        assert!(helpf.is_varargs);

        let constant_propagated = db.get(0x3f00).expect("getparameter definition");
        assert_eq!(constant_propagated.name, "getparameter");
        assert_eq!(constant_propagated.parameters.len(), 4);
        assert_eq!(constant_propagated.parameters[3].name, "config");
    }

    #[test]
    fn curl_dwarf_globals_import_urlglob_pointer_chain() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugGlobalDatabase::parse_elf(&bytes).expect("DWARF globals");
        // 5 located globals + the 3 copy-relocation externals
        // (stdout/stdin/stderr, DWARF-SYMFIELD-TYPESTATE-0001).
        assert_eq!(db.len(), 8);
        {
            let stdout = db.get(0x174e0).expect("stdout copy-reloc global");
            assert_eq!(stdout.name, "stdout");
            assert!(stdout.parent_function.is_none());
            match stdout.data_type.as_ref() {
                Datatype::Pointer(pointer) => {
                    // Typedef spelling preserved: FILE over struct _IO_FILE.
                    assert_eq!(pointer.ptr_to.get_name(), "FILE");
                    assert_eq!(pointer.ptr_to.get_size(), 216);
                }
                other => panic!("stdout declaration is not a pointer: {other:?}"),
            }
            let stdin = db.get(0x174f0).expect("stdin copy-reloc global");
            assert_eq!(stdin.name, "stdin");
            let stderr = db.get(0x17500).expect("stderr copy-reloc global");
            assert_eq!(stderr.name, "stderr");
            // R3MERGE-STDMERGE-TYPESTATE-0001: the three copy-reloc
            // externs carry the extern_reloc mark — the driver seeds the
            // oracle's TYPELOCKED undefined8 symbol form for them (the
            // instrumented-oracle witness in the field doc), while the
            // declared DWARF type stays on data_type as the parse
            // product.
            assert!(stdout.extern_reloc && stdin.extern_reloc && stderr.extern_reloc);
        }

        let glob_expand = db.get(0x17660).expect("glob_expand global");
        assert_eq!(glob_expand.name, "glob_expand");
        // Located DWARF variables never take the extern_reloc mark.
        assert!(!glob_expand.extern_reloc);
        // Anonymous pointer (see parse_c_type's Ghidra note); the pointee
        // structure check below carries the identity.
        assert_eq!(glob_expand.data_type.get_name(), "");
        match glob_expand.data_type.as_ref() {
            Datatype::Pointer(pointer) => match pointer.ptr_to.as_ref() {
                Datatype::Struct(composite) => {
                    assert_eq!(composite.base.size, 304);
                    let literal = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "literal")
                        .expect("URLGlob.literal field");
                    assert_eq!(literal.offset, 0);
                    // Anonymous array of anonymous char* (getTypeArray /
                    // getTypePointer both leave names empty).
                    assert_eq!(literal.type_ptr.get_name(), "");
                    match literal.type_ptr.as_ref() {
                        Datatype::Array(arr) => {
                            assert_eq!(arr.num_elements, 10);
                            assert!(matches!(
                                arr.array_of.as_ref(),
                                Datatype::Pointer(_)
                            ));
                        }
                        _ => panic!("literal field must be an array"),
                    }
                    let pattern = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "pattern")
                        .expect("URLGlob.pattern field");
                    assert_eq!(pattern.offset, 80);
                    // DW_AT_upper_bound 8 is inclusive: 9 elements of the
                    // 24-byte URLPattern occupy [80, 296) where `size` sits.
                    assert_eq!(pattern.type_ptr.get_name(), "");
                    match pattern.type_ptr.as_ref() {
                        Datatype::Array(arr) => {
                            assert_eq!(arr.num_elements, 9);
                            assert_eq!(arr.array_of.get_name(), "URLPattern");
                        }
                        _ => panic!("pattern field must be an array"),
                    }
                    let size = composite
                        .fields
                        .iter()
                        .find(|field| field.name == "size")
                        .expect("URLGlob.size field");
                    assert_eq!(size.offset, 296);
                    assert_eq!(size.type_ptr.get_name(), "int");
                }
                other => panic!("URLGlob pointee is not a struct: {other:?}"),
            },
            other => panic!("glob_expand is not a pointer: {other:?}"),
        }

        let glob_url = db.get(0x17520).expect("config global");
        assert_eq!(glob_url.name, "config");
        assert_eq!(glob_url.data_type.get_name(), "Configurable");
        assert_eq!(glob_url.data_type.get_size(), 304);

        let map = db.address_pointer_map();
        assert_eq!(map.len(), 8);
        // Address-pointer map types are anonymous pointers (see
        // pointer_type's Ghidra note); assert the pointee spelling through
        // the drill instead of the composed name.
        assert_eq!(
            map.get(&0x17660)
                .expect("glob_expand address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17660)
                .expect("glob_expand address type")
                .ptr_drill_base_name(),
            "URLGlob"
        );
        assert_eq!(
            map.get(&0x17520).expect("config address type").get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17520)
                .expect("config address type")
                .ptr_drill_base_name(),
            "Configurable"
        );
        assert_eq!(
            map.get(&0x17680)
                .expect("glob_buffer address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17680)
                .expect("glob_buffer address type")
                .ptr_drill_base_name(),
            "char"
        );
        assert_eq!(
            map.get(&0x17518)
                .expect("beenhere address type")
                .get_name(),
            ""
        );
        assert_eq!(
            map.get(&0x17518)
                .expect("beenhere address type")
                .ptr_drill_base_name(),
            "int"
        );
    }

    // GLOBWORD-C5: the DWARF front-end typelock semantic. In Ghidra, the
    // DWARF analyzer's committed Data types reach the decompiler symbol
    // table as ATTRIB_TYPELOCK (Symbol::decodeHeader database.cc:439-442);
    // without the flag, both typelock-gated consumers
    // (SymbolEntry::updateType database.cc:135-141 and buildLocaltypes'
    // exact-piece branch coreaction.cc:5021-5027) skip the global Symbol's
    // DWARF type, and glob_expand's value degrades to raw offsets in the
    // output. seed_global_locked is the single driver-side projection of
    // that semantic onto Rugra's query-channel Database.
    #[test]
    fn seed_global_locked_marks_dwarf_globals_typelocked_and_findable() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugGlobalDatabase::parse_elf(&bytes).expect("DWARF globals");
        let glob_expand = db.get(0x17660).expect("glob_expand global");

        let mut channel = crate::database::Database::new(false);
        let scope = channel.global_scope_id;
        let symbol_id = DebugGlobalDatabase::seed_global_locked(
            &mut channel,
            scope,
            glob_expand.address,
            &glob_expand.name,
            glob_expand.data_type.clone(),
            glob_expand.data_type.get_size().max(1) as i32,
        )
        .expect("seeded symbol id");

        // The typelock gate SymbolEntry::updateType checks.
        let locked = channel
            .get_global_scope()
            .and_then(|s| s.symbols.get(&symbol_id))
            .map(|sym| sym.read().unwrap().is_type_locked());
        assert_eq!(locked, Some(true));

        // The channel the pipeline queries (queryProperties/
        // queryContainer) resolves the seeded entry, and the entry carries
        // the URLGlob-pointer symbol type updateType hands to the Varnode.
        let hit = channel
            .query_container(
                scope,
                Address::new(0x17660),
                1,
                Address::new(0),
            )
            .expect("container hit at glob_expand");
        assert_eq!(hit.symbol_name, "glob_expand");
        let entry_type = channel
            .get_global_scope()
            .and_then(|s| s.symbols.get(&symbol_id))
            .map(|sym| sym.read().unwrap().get_type());
        assert!(matches!(
            entry_type,
            Some(Some(ref dt)) if matches!(dt.as_ref(), Datatype::Pointer(_))
        ));
    }

    #[test]
    fn typedef_and_qualifier_aliases_preserve_character_semantics_and_shape() {
        let character = Datatype::Base(TypeBase::new_char("char".to_string(), TypeMetatype::Int));
        let qualified = alias_type("const char".to_string(), &character);
        assert!(qualified.is_char_print());
        assert_eq!(qualified.get_name(), "const char");

        let pointer = Datatype::Pointer(TypePointer {
            base: TypeBase::new("char *".to_string(), 8, TypeMetatype::Pointer),
            ptr_to: Arc::new(character),
            wordsize: 1,
        });
        let alias = alias_type("char_ptr".to_string(), &pointer);
        match alias.as_ref() {
            Datatype::Pointer(pointer) => {
                assert_eq!(pointer.ptr_to.get_name(), "char");
                assert!(pointer.ptr_to.is_char_print());
            }
            other => panic!("pointer typedef lost its concrete shape: {other:?}"),
        }
    }

    // CURLCANON-CASTA-CONST-0001: DWARF cv-qualifiers strip at import —
    // my_get_token @0x3720's DWARF param chain (0x3ca ptr -> 0x186 const
    // -> char, readelf-verified) resolves into the plain char-pointer
    // domain: no `const char` alias object is minted, so the prototype
    // prints `char * my_get_token(char *line)` and the 0x0 literals cast
    // `(char *)` — the locked golden :1213/:1226/:1603, never `const`.
    #[test]
    fn dwarf_const_qualifier_strips_to_underlying_type() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        let proto = db.get(0x3720).expect("my_get_token prototype");
        assert_eq!(proto.name, "my_get_token");
        assert_eq!(proto.parameters.len(), 1);
        assert_eq!(proto.parameters[0].name, "line");
        let qualified_name = proto.parameters[0].data_type.get_name();
        assert_eq!(
            qualified_name, "",
            "the stripped param is the anonymous char pointer (pointer_type builds unnamed DWARF pointers)"
        );
        match proto.parameters[0].data_type.as_ref() {
            Datatype::Pointer(pointer) => {
                assert_eq!(pointer.ptr_to.get_name(), "char");
                assert!(pointer.ptr_to.is_char_print());
                assert!(!pointer.ptr_to.get_name().starts_with("const"));
            }
            other => panic!("my_get_token line parameter is not a pointer: {other:?}"),
        }
        // The static local `save` (DWARF <ed6>, same const-chain pointee)
        // strips with it — golden compares `my_get_token::save == (char *)0x0`.
    }

    // CALLSPEC-ENV-SCOPE-0001: the call-site half of the DWARF boundary —
    // queryCall resolves the DWARF-locked callee and ActionDefaultParams
    // copies its whole FuncProto to the call site (coreaction.cc:2322-2330),
    // so a caller decompiling with debug info sees the callee's locked
    // parameter list (golden main: `glob_url(&urls,pcVar12,&urlnum)` 3-arg
    // from the DWARF definition, not an experimental guess).
    #[test]
    fn locked_callsite_proto_copies_dwarf_signature() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        // glob_url @ 0x4f70: (URLGlob **glob, char *url, int *urlnum).
        let carrier = model_carrier();
        let proto = db
            .locked_callsite_proto(0x4f70, &carrier)
            .expect("glob_url callsite prototype represents")
            .expect("glob_url has a DWARF definition");
        assert_eq!(proto.num_params(), 3);
        assert!(proto.is_input_locked());
        assert!(proto.is_output_locked());
        assert!(proto.is_model_locked());
        assert!(!proto.is_model_unknown());
        assert_eq!(proto.get_param(0).unwrap().name, "glob");
        assert_eq!(proto.get_param(0).unwrap().address.as_u64(), 0x38);
        assert_eq!(proto.get_param(2).unwrap().address.as_u64(), 0x10);
        // Anonymous pointer chain (see parse_c_type's Ghidra note): the
        // "URLGlob **" spelling is not the imported type's name.
        assert_eq!(proto.get_param(0).unwrap().data_type.get_name(), "");
        assert!(matches!(
            proto.get_param(0).unwrap().data_type.as_ref(),
            Datatype::Pointer(_)
        ));

        // A thunk/import address has no DWARF definition: the boundary
        // contributes nothing (Ok(None)) and the import table owns it.
        assert!(db
            .locked_callsite_proto(0x2490, &carrier)
            .expect("thunk lookup does not error")
            .is_none());
    }

    #[test]
    fn applying_known_void_prototype_locks_shape_and_storage() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        let mut fd = Funcdata::new("GetStr", Address::new(0x36d0), 0x4a);
        fd.funcp = model_carrier();
        assert!(db
            .apply(&mut fd)
            .expect("apply prototype"));
        assert!(fd.funcp.is_input_locked());
        assert!(fd.funcp.is_output_locked());
        assert_eq!(fd.funcp.parameters.len(), 2);
        assert_eq!(fd.funcp.parameters[0].address.as_u64(), 0x38);
        assert_eq!(fd.funcp.parameters[1].address.as_u64(), 0x30);

        let mut no_args = Funcdata::new("hugehelp", Address::new(0x4a00), 0x54);
        no_args.funcp = model_carrier();
        assert!(db
            .apply(&mut no_args)
            .expect("apply void input"));
        assert!(no_args.funcp.parameters.is_empty());
        assert!(no_args.funcp.is_input_locked());
    }

    // A void input list locks the model, but does not replace a model already
    // bound by the caller. FuncProto::decode only constructs an unknown model
    // for an explicit, unresolved ATTRIB_MODEL value; voidinputlock merely
    // contributes to modellock (fspec.cc:4681-4698, 4737-4738, 4776-4777).
    // DWARF-VOID-UNKNOWN-MODEL-0001 supersedes the "keeps the bound model"
    // expectation for the 0-param DWARF locals: the headless analyzer hands
    // the decompiler model="unknown" (StorageVerification's empty-signature
    // downgrade + FunctionDB.updateFunction(null,...) keeping the never-
    // assigned convention), and the locked golden witnesses it as the
    // "WARNING: Unknown calling convention -- yet parameter storage is
    // locked" header on exactly main_init/main_free/hugehelp.
    #[test]
    fn void_signature_dwarf_prototype_pins_unknown_model() {
        let bytes = std::fs::read("examples/curl").expect("curl fixture");
        let db = DebugPrototypeDatabase::parse_elf(&bytes).expect("DWARF prototypes");
        for (name, address) in
            [
            ("main_init", 0x4960u64), ("main_free", 0x4970), ("hugehelp", 0x4a00),
        ]
        {
            let mut fd = Funcdata::new(name, Address::new(address), 8);
            // Simulate the post-set_arch default-model binding the worker
            // performs before the DWARF overlay.
            fd.funcp = model_carrier();
            assert!(db
                .apply(&mut fd)
                .expect("apply void-signature prototype"));
            assert!(
                fd.funcp.is_model_unknown(),
                "{name} pins the oracle's unknown model (golden warning witness)"
            );
            assert!(
                fd.funcp.is_model_locked(),
                "{name} void parameter list locks the bound model"
            );
            assert!(fd.funcp.void_input_locked);
        }
    }

    // UNKNOWN-PROTOMODEL-WARN-EMIT-0001 ⑤ counterpart: parameterized DWARF
    // signatures keep the resolved model binding — in the locked golden none
    // of the 18 parameterized DWARF functions warn, so the overlay must not
    // pin the unknown sentinel for them.
    // HTTPD-URAM-SYMBOLIZE-0001: the PLT thunk import boundary against the
    // locked-oracle httpd image (the binary the 12.0.4 headless golden was
    // produced from; thunk names cross-checked against the golden's function
    // headers `/* ---- 0x12aXXX: <name> (10 bytes) ---- */`).
    fn httpd_bytes() -> Vec<u8> {
        std::fs::read("examples/httpd").expect("httpd fixture")
    }

    #[test]
    fn plt_imports_resolve_sec_slots_from_jump_slot_relocs() {
        let imports = ElfPltImports::parse_elf(&httpd_bytes());
        // .plt.sec @0x2a420, slot i at +16*i ↔ .rela.plt[i].
        // Witness set = the 82 thunk call sites of the uRam family; every
        // name below matches the locked golden's callee spelling.
        for (addr, name) in [
            (0x2a6d0u64, "apr_app_initialize"),
            (0x2a7c0, "apr_pool_create_ex"),
            (0x2a6a0, "apr_pool_tag"),
            (0x2abc0, "apr_palloc"),
            (0x2a8e0, "apr_filepath_name_get"),
            (0x2a4d0, "apr_array_make"),
            (0x2a450, "apr_getopt_init"),
            (0x2b6e0, "apr_getopt"),
            (0x2b190, "apr_array_push"),
            (0x2aa50, "apr_hook_sort_all"),
            (0x2b070, "apr_dynamic_fn_retrieve"),
            (0x2a820, "apr_pool_clear"),
            (0x2b1a0, "apr_pool_destroy"),
            (0x2ab70, "apr_hook_deregister_all"),
            (0x2a540, "strcasecmp"),
            (0x2afd0, "strncasecmp"),
            (0x2acb0, "memcmp"),
            (0x2a800, "apr_table_get"),
            (0x2b790, "__ctype_b_loc"),
            (0x2b140, "apr_parse_addr_port"),
            (0x2a8d0, "apr_itoa"),
            (0x2b770, "__ctype_tolower_loc"),
            (0x2a600, "strncmp"),
            (0x2b430, "apr_sockaddr_equal"),
            (0x2a9e0, "strchr"),
            (0x2aee0, "apr_pstrdup"),
            (0x2b500, "apr_pstrndup"),
            (0x2aa30, "apr_time_exp_lt"),
            (0x2a4e0, "apr_time_exp_gmt"),
            (0x2aa90, "apr_strftime"),
            (0x2a980, "__stack_chk_fail"),
            (0x2a830, "apr_filepath_root"),
            (0x2a910, "strlen"),
            (0x2ab20, "apr_pool_cleanup_register"),
            (0x2a970, "apr_pool_cleanup_kill"),
            (0x2ab40, "memset"),
            (0x2ae60, "memcpy"),
            (0x2aa80, "strrchr"),
        ] {
            assert_eq!(
                imports.get(addr).map(String::as_str),
                Some(name),
                "PLT thunk at 0x{addr:x} must import as {name}"
            );
        }
        // JUMP_SLOT count == .plt.sec slot count: all 317 imports resolved.
        assert_eq!(imports.len(), 317, "one thunk name per .rela.plt entry");
        // Non-thunk addresses (the 5 shared tail chunks in .text) must stay
        // unnamed here — they are analysis functions, not imports.
        for addr in [0x2c520u64, 0x2c550, 0x2c8e0, 0x2c960, 0x2ce20] {
            assert!(
                imports.get(addr).is_none(),
                "0x{addr:x} is not a PLT thunk"
            );
        }
    }

    #[test]
    fn analyze_headless_function_symbol_name_uses_image_base_padding() {
        // Locked-oracle witnesses (golden headers):
        // 0x2c520 → FUN_0012c520, 0x2c960 → FUN_0012c960.
        assert_eq!(
            analyze_headless_function_symbol_name(0x2c520, 0x100000),
            "FUN_0012c520"
        );
        assert_eq!(
            analyze_headless_function_symbol_name(0x2c960, 0x100000),
            "FUN_0012c960"
        );
        assert_eq!(
            analyze_headless_function_symbol_name(0x2ce20, 0x100000),
            "FUN_0012ce20"
        );
    }

    #[test]
    fn plt_imports_reject_non_elf_payloads() {
        assert!(ElfPltImports::parse_elf(b"not an elf image at all").is_empty());
    }

}
