//! Architecture manager — faithful port of `architecture.hh` / `architecture.cc`
//! (1570 lines).
//!
//! Manager for all the major decompiler subsystems. An instantiation is tailored
//! to a specific LoadImage, processor, and compiler spec. This class is the
//! *owner* of the LoadImage, Translate, symbols (Database), PrintLanguage, etc.
//! It also holds numerous configuration parameters for the analysis process.
//!
//! Status: L1→L2. The configuration container with all fields and defaults is
//! complete. The XML decode/parse methods and virtual factory hooks
//! (buildTranslator/buildLoader/…) are documented as L3 gaps pending the
//! Translate/LoadImage/DocumentStorage infrastructure.
//!
//! Ghidra reference:
//! ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/architecture.{hh,cc}.

use crate::address::{Range, RangeList, RangeProperties};
use crate::fspec::{ProtoModelFull, VarnodeData};
use crate::override_rs::Override;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Language/space queries consumed by the compiler-spec decode chain,
/// standing in for the `Architecture`'s `AddrSpaceManager` + `Translate`
/// during `parseCompilerConfig` (space-by-name, per-space highest,
/// register lookup, overlay enumeration, SLEIGH symbols).  Ghidra reads
/// these off the Architecture itself; Rugra's `Architecture` does not own
/// an `AddrSpaceManager` yet, so the parse entry points take this trait.
pub trait SpecQuery {
    // Ghidra: sleighbase.cc:133 SleighBase::getRegister (via Translate)
    /// Resolve a named register to its varnode, or None.
    fn get_register(&self, name: &str) -> Option<VarnodeData>;

    // Ghidra: translate.cc:590 AddrSpaceManager::getSpaceByName
    /// Resolve an address space by name, or None.
    fn space_by_name(&self, name: &str) -> Option<crate::space::AddressSpace>;

    // Ghidra: space.hh:189 AddrSpace::getHighest
    /// Highest offset addressable in the given space.
    fn space_highest(&self, spc: crate::space::AddressSpace) -> u64;

    // Ghidra: translate.hh:550 AddrSpaceManager::numSpaces
    /// Number of address spaces (for the overlay duplication loop of
    /// `addToGlobalScope`/`addOtherSpace`).  Zero by default: no overlay
    /// enumeration without a wired space manager.
    fn num_spaces(&self) -> usize {
        0
    }

    // Ghidra: translate.hh:559 AddrSpaceManager::getSpace
    /// The space at the given index, or None.
    fn space_at(&self, _i: usize) -> Option<crate::space::AddressSpace> {
        None
    }

    // Ghidra: space.hh:165 AddrSpace::isOverlay
    /// Whether the space is an overlay space.
    fn is_overlay(&self, _spc: crate::space::AddressSpace) -> bool {
        false
    }

    // Ghidra: space.hh:141 AddrSpace::isOverlayBase
    /// Whether the space is the base of overlay spaces.
    fn is_overlay_base(&self, _spc: crate::space::AddressSpace) -> bool {
        false
    }

    // Ghidra: space.hh:153 AddrSpace::getContain
    /// The base space an overlay is contained in, or None.
    fn contain_space(&self, _spc: crate::space::AddressSpace) -> Option<crate::space::AddressSpace> {
        None
    }

    // Ghidra: sleigh.hh SleighBase::findSymbol (via PcodeSnippet::lex)
    /// Resolve a SLEIGH language symbol (registers etc.) by name.
    fn sleigh_symbol(&self, _name: &str) -> Option<crate::pcodeparse::SleighSymbol> {
        None
    }

    // Ghidra: translate.hh:611 Translate::getUniqueStart(Translate::INJECT)
    /// Unique-space offset where snippet temporaries start
    /// (`0x200 + unique_base`).
    fn unique_inject_base(&self) -> u64 {
        0x200
    }
}

/// Residual report produced by `Architecture::parse_compiler_config`.
/// Every child element the Rust dispatch could not fully decode, every
/// child the Ghidra oracle itself ignores, and every post-loop step that
/// depends on other domains is listed here — nothing is silently skipped.
#[derive(Debug, Default, Clone)]
pub struct CompilerConfigReport {
    /// `(child tag, reason/owning TODO)` for children whose full decode
    /// belongs to another domain.
    pub skipped_children: Vec<(String, String)>,
    /// Child tags the Ghidra oracle's own dispatch ignores (no else
    /// branch in architecture.cc:1249-1305).
    pub ignored_children: Vec<String>,
    /// Post-loop steps (initializeSegments, PreferSplitManager,
    /// setupSizes) that depend on infrastructure outside this slice.
    pub post_step_residuals: Vec<String>,
}

// Ghidra: globalcontext.hh:78 TrackedContext
/// A tracked register (Varnode storage) and the value it contains, decoded
/// from a pspec `<tracked_set>`'s `<set>` children.  Faithful to
/// `TrackedContext` (globalcontext.hh:78-83): `VarnodeData loc` (register
/// storage resolved by `name` attribute or explicit
/// `space`/`offset`/`size` attributes) + `uintb val`.
///
/// Distinct from `crate::context::TrackedContext` (offset/size/val without a
/// space dimension), which predates space-aware ingest and stays in place
/// until the ContextDatabase itself gains a space-keyed partmap
/// (SLEIGH-0002C); the ActionConstbase consumer needs the full
/// `Address(ctx.loc.space, ctx.loc.offset)` (coreaction.cc:693).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedRegister {
    /// Storage details of the register being tracked (`loc`).
    pub loc: VarnodeData,
    /// The value of the register (`val`).
    pub val: u64,
}

// Ghidra: globalcontext.hh:284 ContextInternal::trackbase (partmap<Address,TrackedSet>)
/// Space-aware partition map of tracked register sets, keyed on
/// `(space order, offset)` — the Rugra stand-in for
/// `ContextInternal::trackbase` (globalcontext.hh:284,
/// `partmap<Address,TrackedSet>`), holding the partitions fed by pspec
/// `<context_data><tracked_set>` children through the mirrored
/// `split`/`clearRange`/`getValue` step semantics (partmap.hh:81-157).
///
/// Ordering caveat (registered residual): Ghidra orders `Address` by the
/// live `AddrSpaceManager` baselist index; Rugra orders by
/// `AddressSpace::space_id()`.  The two agree for all same-space lookups —
/// the only production consumer (`ActionConstbase`,
/// coreaction.cc:692) queries the function's address in `ram`.
/// Cross-space partition interleavings stay UNTESTED until the space
/// registry carries real baselist indices (SLEIGH-0002C / ADDRESS-0001).
#[derive(Debug, Clone, Default)]
pub struct TrackedSetMap {
    /// Sorted split points `((space order, offset), tracked set)` — the
    /// `database` member of `partmap` (partmap.hh:56).  Absence of an
    /// earlier split means the (empty) `defaultvalue` applies.
    splits: Vec<((u8, u64), Vec<TrackedRegister>)>,
}

impl TrackedSetMap {
    // RUGRA-GLUE: new (C++ aggregate construction of partmap)
    /// Construct an empty partition map (empty `defaultvalue`).
    pub fn new() -> Self {
        Self {
            splits: Vec::new(),
        }
    }

    // Ghidra: partmap.hh:81 partmap::getValue
    /// Look up the first split point coming before the given point and
    /// return the tracked set it maps to; the empty default value if there
    /// is no earlier split.  Faithful to `partmap::getValue`
    /// (partmap.hh:81-112), including the `upper_bound` + `--iter`
    /// predecessor lookup.
    pub fn get_value(&self, space: crate::space::AddressSpace, offset: u64) -> &[TrackedRegister] {
        let key = (space.space_id(), offset);
        // upper_bound(key): first split with key strictly greater.
        let upper = self.splits.partition_point(|(k, _)| *k <= key);
        if upper == 0 {
            return &[];
        }
        &self.splits[upper - 1].1
    }

    // Ghidra: partmap.hh:117 partmap::split
    /// Introduce (if not already present) a split point, copying the value
    /// object of the partition it falls into (the default value when the
    /// point precedes every split).  Faithful to `partmap::split`
    /// (partmap.hh:117-136); returns the index of the split's value.
    fn split(&mut self, key: (u8, u64)) -> usize {
        let upper = self.splits.partition_point(|(k, _)| *k <= key);
        if upper > 0 {
            if self.splits[upper - 1].0 == key {
                return upper - 1; // Point matches exactly — return old ref
            }
            let value = self.splits[upper - 1].1.clone();
            self.splits.insert(upper, (key, value));
            return upper;
        }
        self.splits.insert(0, (key, Vec::new())); // Copy of defaultvalue
        0
    }

    // Ghidra: partmap.hh:144 partmap::clearRange
    /// Split at both boundary points of the given range and erase the split
    /// points strictly between them; the value object at the left boundary
    /// keeps its identity (the caller clears and refills it, mirroring
    /// `ContextInternal::createSet`, globalcontext.cc:470-475).  Faithful to
    /// `partmap::clearRange` (partmap.hh:144-157); returns the mutable
    /// value assigned to the range.
    fn clear_range(&mut self, key1: (u8, u64), key2: (u8, u64)) -> &mut Vec<TrackedRegister> {
        self.split(key1);
        self.split(key2);
        let beg = self.splits.partition_point(|(k, _)| *k < key1); // lower_bound(key1)
        let end = self.splits.partition_point(|(k, _)| *k < key2); // lower_bound(key2)
        if end > beg + 1 {
            // database.erase(beg+1, end): drop splits strictly inside.
            self.splits.drain(beg + 1..end);
        }
        &mut self.splits[beg].1
    }
}

// RUGRA-GLUE: find_body_content (Ghidra reads it via readString(ATTRIB_CONTENT))
/// Extract the character content of the `<body>` child under the LAST
/// p-code element (`pcode`/`case_pcode`/`addr_pcode`/`default_pcode`/
/// `size_pcode`) of the given element subtree.  With multiple `<pcode>`
/// children every one is decoded and the LAST body's text survives in the
/// payload parsestring (decodeBody overwrites per iteration), so the last
/// match is what the subsequent compile consumes.  Ghidra's
/// `XmlDecode::readString(ATTRIB_CONTENT)` (marshal.cc:390-395) reads the
/// element content field directly; Rugra's `TreeDecoder` cannot surface it
/// through the `Decoder` trait, so the paired DOM handle provides it.
fn find_body_content(element: &std::sync::Arc<std::sync::RwLock<crate::marshal::Element>>) -> Option<String> {
    const PCODE_TAGS: [&str; 5] = ["pcode", "case_pcode", "addr_pcode", "default_pcode", "size_pcode"];
    let el = element.read().expect("element lock poisoned");
    let mut result = None;
    for pcode in &el.children {
        let pcode_el = pcode.read().expect("element lock poisoned");
        if !PCODE_TAGS.contains(&pcode_el.name.as_str()) {
            continue;
        }
        for body in &pcode_el.children {
            let body_el = body.read().expect("element lock poisoned");
            if body_el.name == "body" {
                result = Some(body_el.content.clone());
            }
        }
    }
    result
}

/// FlowInfo option bit: error on too many instructions. Faithful to
/// `FlowInfo::error_toomanyinstructions` (used in resetDefaultsInternal).
pub const FLOWOPT_ERROR_TOOMANY: u32 = 1 << 0;

/// Data-type split configuration bits. Faithful to `OptionSplitDatatypes`
/// option flags (architecture.cc:1431).
pub mod split_datatype {
    /// Split struct accesses.
    pub const OPTION_STRUCT: u32 = 1;
    /// Split array accesses.
    pub const OPTION_ARRAY: u32 = 2;
    /// Split pointer accesses.
    pub const OPTION_POINTER: u32 = 4;
}

/// The major decompiler version. Faithful to `ArchitectureCapability::majorversion`.
pub const MAJOR_VERSION: u32 = 6;
/// The minor decompiler version. Faithful to `ArchitectureCapability::minorversion`.
pub const MINOR_VERSION: u32 = 1;

/// Abstract extension point for building Architecture objects. Faithful to
/// `ArchitectureCapability` (architecture.hh:117).
///
/// Each extension implements `build_architecture()` as the formal entry point
/// for the bootstrapping process.
pub trait ArchitectureCapability: Send + Sync {
    // RUGRA-GLUE: name (no Ghidra counterpart found)
    /// Get the capability identifier.
    fn name(&self) -> &str;

    // RUGRA-GLUE: build_architecture (no Ghidra counterpart found)
    /// Build an Architecture given a raw file or data. Faithful to
    /// `buildArchitecture`. Returns `Ok(())` on success; the built architecture
    /// is stored externally.
    fn build_architecture(
        &self,
        filename: &str,
        target: &str,
    ) -> Result<Box<dyn ArchitectureBuilder>, String>;

    // RUGRA-GLUE: is_file_match (no Ghidra counterpart found)
    /// Determine if this extension can handle this file. Faithful to
    /// `isFileMatch`.
    fn is_file_match(&self, filename: &str) -> bool;

    // RUGRA-GLUE: is_xml_match (no Ghidra counterpart found)
    /// Determine if this extension can handle this XML document. Faithful to
    /// `isXmlMatch`.
    fn is_xml_match(&self, doc: &str) -> bool;
}

/// Trait that an `ArchitectureCapability::build_architecture` returns,
/// providing the virtual factory hooks for sub-components. Faithful to the
/// protected virtual methods of `Architecture` (architecture.hh:264-348).
pub trait ArchitectureBuilder: Send + Sync {
    // RUGRA-GLUE: build_database (no Ghidra counterpart found)
    /// Build the database and global scope. Faithful to `buildDatabase`.
    fn build_database(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_translator (no Ghidra counterpart found)
    /// Build the Translator object. Faithful to `buildTranslator`.
    fn build_translator(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_loader (no Ghidra counterpart found)
    /// Build the LoadImage object and load the executable image. Faithful to
    /// `buildLoader`.
    fn build_loader(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_pcode_inject_library (no Ghidra counterpart found)
    /// Build the injection library. Faithful to `buildPcodeInjectLibrary`.
    fn build_pcode_inject_library(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_typegrp (no Ghidra counterpart found)
    /// Build the data-type factory/container. Faithful to `buildTypegrp`.
    fn build_typegrp(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_core_types (no Ghidra counterpart found)
    /// Add core primitive data-types. Faithful to `buildCoreTypes`.
    fn build_core_types(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_comment_db (no Ghidra counterpart found)
    /// Build the comment database. Faithful to `buildCommentDB`.
    fn build_comment_db(&mut self) -> Result<(), String>;
    // Ghidra: architecture.hh:308 Architecture::buildStringManager
    /// Build the string manager. Faithful to the virtual factory hook
    /// `buildStringManager` (architecture.hh:308; invoked from
    /// `Architecture::init`, architecture.cc:1401). Concrete overrides:
    /// sleigh_arch.cc:247-251 and ghidra_arch.cc:365-369.
    fn build_string_manager(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_constant_pool (no Ghidra counterpart found)
    /// Build the constant pool. Faithful to `buildConstantPool`.
    fn build_constant_pool(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_context (no Ghidra counterpart found)
    /// Build the Context database. Faithful to `buildContext`.
    fn build_context(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_symbols (no Ghidra counterpart found)
    /// Build any symbols from spec files. Faithful to `buildSymbols`.
    fn build_symbols(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: build_spec_file (no Ghidra counterpart found)
    /// Load any relevant specification files. Faithful to `buildSpecFile`.
    fn build_spec_file(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: modify_spaces (no Ghidra counterpart found)
    /// Modify address spaces as required. Faithful to `modifySpaces`.
    fn modify_spaces(&mut self) -> Result<(), String>;
    // RUGRA-GLUE: resolve_architecture (no Ghidra counterpart found)
    /// Figure out the processor and compiler. Faithful to `resolveArchitecture`.
    fn resolve_architecture(&mut self) -> Result<(), String>;
}

/// Registry of `ArchitectureCapability` extensions. Faithful to the static
/// `thelist` and static methods of `ArchitectureCapability`
/// (architecture.hh:120-156).
pub struct CapabilityRegistry {
    capabilities: Vec<Box<dyn ArchitectureCapability>>,
}

impl Default for CapabilityRegistry {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityRegistry {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
        }
    }

    // RUGRA-GLUE: register (no Ghidra counterpart found)
    /// Register a new capability.
    pub fn register(&mut self, cap: Box<dyn ArchitectureCapability>) {
        self.capabilities.push(cap);
    }

    // RUGRA-GLUE: find_capability_for_file (no Ghidra counterpart found)
    /// Find an extension to process a file. Faithful to
    /// `ArchitectureCapability::findCapability(filename)` (architecture.cc:92).
    pub fn find_capability_for_file(&self, filename: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.is_file_match(filename))
            .map(|c| c.as_ref())
    }

    // RUGRA-GLUE: find_capability_for_xml (no Ghidra counterpart found)
    /// Find an extension to process an XML document. Faithful to
    /// `ArchitectureCapability::findCapability(Document*)` (architecture.cc:106).
    pub fn find_capability_for_xml(&self, doc: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.is_xml_match(doc))
            .map(|c| c.as_ref())
    }

    // RUGRA-GLUE: get_capability (no Ghidra counterpart found)
    /// Get a capability by name. Faithful to `getCapability` (architecture.cc:120).
    pub fn get_capability(&self, name: &str) -> Option<&dyn ArchitectureCapability> {
        self.capabilities
            .iter()
            .find(|c| c.name() == name)
            .map(|c| c.as_ref())
    }

    // RUGRA-GLUE: sort_capabilities (no Ghidra counterpart found)
    /// Sort extensions so the "raw" architecture comes last. Faithful to
    /// `sortCapabilities` (architecture.cc:134).
    pub fn sort_capabilities(&mut self) {
        if let Some(raw_pos) = self.capabilities.iter().position(|c| c.name() == "raw") {
            let raw = self.capabilities.remove(raw_pos);
            self.capabilities.push(raw);
        }
    }

    // RUGRA-GLUE: major_version (no Ghidra counterpart found)
    /// Get the major decompiler version. Faithful to `getMajorVersion`.
    pub fn major_version() -> u32 {
        MAJOR_VERSION
    }

    // RUGRA-GLUE: minor_version (no Ghidra counterpart found)
    /// Get the minor decompiler version. Faithful to `getMinorVersion`.
    pub fn minor_version() -> u32 {
        MINOR_VERSION
    }
}

/// Prototype models owned by the Architecture.  Each entry is the same shared
/// model object handed to `FuncProto`, mirroring Ghidra's map of stable
/// `ProtoModel *` values.
pub type ProtoModelMap = BTreeMap<String, Arc<ProtoModelFull>>;

/// Manager for all the major decompiler subsystems. Faithful to
/// `Architecture` (architecture.hh:165).
///
/// This is the Ghidra `Architecture` class — distinct from the `types::Architecture`
/// enum (which is the target CPU). It holds all configuration parameters and
/// owns the sub-component references.
#[derive(Clone)]
pub struct Architecture {
    /// ID string uniquely describing this architecture. Faithful to `archid`.
    pub archid: String,

    // ---- Configuration data (architecture.hh:170-188) ----
    /// How many levels to let parameter trims recurse.
    pub trim_recurse_max: i32,
    /// Maximum number of references to an implied var.
    pub max_implied_ref: i32,
    /// Max terms duplicated without a new variable.
    pub max_term_duplication: i32,
    /// Maximum size of an "integer" type before creating an array type.
    pub max_basetype_size: i32,
    /// Minimum size of a function symbol.
    pub min_funcsymbol_size: i32,
    /// Maximum number of entries in a single JumpTable.
    pub max_jumptable_size: u32,
    /// Aggressively trim inputs that look like they are sign extended.
    pub aggressive_ext_trim: bool,
    /// True if readonly values should be treated as constants.
    pub readonlypropagate: bool,
    /// True if we should infer pointers from constants that are likely addresses.
    pub infer_pointers: bool,
    /// True if we should attempt conversion of while-do loops to for loops.
    pub analyze_for_loops: bool,
    /// True if we should ignore NaN operations entirely.
    pub nan_ignore_all: bool,
    /// True if we should ignore NaN operations protecting floating-point comparisons.
    pub nan_ignore_compare: bool,
    /// How many bits of alignment a function ptr has.
    pub funcptr_align: i32,
    /// Options passed to flow following engine.
    pub flowoptions: u32,
    /// Maximum instructions that can be processed in one function.
    pub max_instructions: u32,
    /// Aliases blocked by 0=none, 1=struct, 2=array, 3=all.
    pub alias_block_level: i32,
    /// Toggle for data-types splitting: Bit 0=structs, 1=arrays, 2=pointers.
    pub split_datatype_config: u32,

    // ---- Sub-component references (placeholders until integrated) ----
    /// Parsed forms of possible prototypes (name → entry).
    pub proto_models: ProtoModelMap,
    /// Name of the default prototype model.
    pub defaultfp_name: Option<String>,
    /// Shared default prototype model.  This is pointer-identical to the entry
    /// in `proto_models`, matching `Architecture::defaultfp`.
    pub defaultfp: Option<Arc<ProtoModelFull>>,
    /// Default storage location of the return address (for the current
    /// function).  Faithful to `defaultReturnAddr`
    /// (architecture.hh:194); `None` mirrors the constructor's
    /// `space == (AddrSpace *)0` sentinel (architecture.cc:159).
    pub default_return_addr: Option<VarnodeData>,
    /// Name of the model to use when evaluating the current function.
    pub evalfp_current_name: Option<String>,
    /// Name of the model to use when evaluating called functions.
    pub evalfp_called_name: Option<String>,
    /// Model used when evaluating the current function.  Faithful to
    /// `evalfp_current` (architecture.hh:195); identity-shared with the
    /// `proto_models` entry.
    pub evalfp_current: Option<Arc<ProtoModelFull>>,
    /// Model used when evaluating called functions.  Faithful to
    /// `evalfp_called` (architecture.hh:196).
    pub evalfp_called: Option<Arc<ProtoModelFull>>,
    /// Set of address spaces in which a pointer constant is inferable.
    /// Faithful to `inferPtrSpaces` (architecture.hh:182); appended by
    /// `addToGlobalScope` (architecture.cc:832).
    pub infer_ptr_spaces: Vec<crate::space::AddressSpace>,
    /// The `(space, first, last)` triples applied to the global scope by
    /// the deferred `<global>` loop and `addOtherSpace`
    /// (architecture.cc:1332-1335), in application order.  Since
    /// CSPEC-GLOBAL-APPLY-0001 the same triples also land in the
    /// constructor-built symbol table's global scope at parse time
    /// (the space-keyed `ScopeRangeTree`, `add_range_spaced` —
    /// architecture.cc:833/852 `symboltab->addRange` write-through);
    /// this record remains as the source-order projection the
    /// fixtures and drivers observe.
    pub global_scope_ranges: Vec<(crate::space::AddressSpace, u64, u64)>,
    /// Ranges for which high-level pointers are not possible. Faithful to
    /// `nohighptr`.
    pub nohighptr: RangeList,
    /// Override commands for the current function. Faithful to the Override
    /// owned by Funcdata (referenced via Architecture).
    pub overrides: Override,
    /// True if loader symbols have been read.
    pub loadersymbols_parsed: bool,

    // ---- Sub-component references (architecture.hh:190-213) ----
    /// Symbol table (Database). Faithful to `symboltab`.
    pub symboltab: Option<std::sync::Arc<std::sync::RwLock<crate::database::Database>>>,
    /// Load image. Faithful to `loader`.
    pub loader: Option<std::sync::Arc<dyn crate::loadimage::LoadImage>>,
    /// Type factory. Faithful to `types`.
    pub type_factory_name: Option<String>,
    /// Type factory instance (faithful to Architecture `types`). Optional until
    /// set via `set_types`. Used by Rules needing `getBase(size, metatype)`.
    pub types: Option<std::sync::Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>>,
    /// User-defined op manager (faithful to Architecture `userops`). Optional.
    pub userops: Option<std::sync::Arc<std::sync::RwLock<crate::userop::UserOpManage>>>,
    /// P-code injection manager.  Faithful to `pcodeinjectlib`
    /// (architecture.hh:200).
    pub pcodeinjectlib: Option<std::sync::Arc<std::sync::RwLock<crate::pcodeinject::PcodeInjectLibrary>>>,
    /// Join record database (translate.hh AddrSpaceManager joinrecords).
    pub join_db: crate::space::JoinDatabase,
    /// Comment database. Faithful to `commentdb`.
    pub commentdb: Option<std::sync::Arc<std::sync::RwLock<crate::comment::CommentDatabaseInternal>>>,
    /// String manager. Faithful to `stringManager`.
    pub string_manager: Option<std::sync::Arc<std::sync::RwLock<crate::stringmanage::StringManager>>>,
    /// Constant pool. Faithful to `cpool`.
    pub cpool: Option<std::sync::Arc<std::sync::RwLock<crate::cpool::ConstantPoolInternal>>>,
    /// Context database. Faithful to `context`.
    pub context_db: Option<std::sync::Arc<std::sync::RwLock<crate::context::ContextInternal>>>,
    /// pspec `<context_data>` tracked-register partitions — Rugra-side
    /// stand-in for the `ContextInternal::trackbase` partition map
    /// (globalcontext.hh:284) behind `Architecture::context`
    /// (architecture.hh:191), filled by the `ELEM_CONTEXT_DATA` arm of
    /// `Architecture::parseProcessorConfig` (architecture.cc:1190 ->
    /// `ContextInternal::decodeFromSpec`, globalcontext.cc:531).  Kept on
    /// the Architecture because `crate::context::ContextInternal` keys on
    /// the space-less `crate::address::Address`; merge under SLEIGH-0002C.
    pub tracked_set_map: TrackedSetMap,
    /// Count of pspec `<context_set>` children consumed by
    /// [`Architecture::decode_context_data`] but not decoded: the low-level
    /// context-variable blob (`ContextInternal::decodeContext`,
    /// globalcontext.cc:345) requires the .sla context layout registered in
    /// the Rust ContextDatabase (SLEIGH-0002C residual; Ghidra registers the
    /// variables via `SleighBase::reregisterContext`, sleighbase.cc:125-131,
    /// into the same `ContextInternal` the SLEIGH translator shares,
    /// sleigh_arch.cc:181).
    pub context_set_children_skipped: usize,
    /// Options database. Faithful to `options`.
    pub options_db: Option<std::sync::Arc<std::sync::RwLock<crate::options::OptionDatabase>>>,
    /// Identity key of this Architecture's printer registry entry (the
    /// storage channel for `printlist`/`print`, architecture.hh:206/205 —
    /// see `printlanguage`'s thread-local registry for why the list cannot
    /// live in this struct: printers are !Send while the canonical-Factory
    /// static in funcdata.rs pins this struct Send+Sync). Minted at
    /// construction; never printed or hashed into outputs.
    pub print_registry_key: u64,
    /// Root Action database. Faithful to `allacts` (architecture.hh:212).
    /// Ghidra embeds the `ActionDatabase` by value inside `Architecture`;
    /// Rugra defers instantiation to [`Architecture::build_action`] (like the
    /// other sub-components) behind a shared lock, because option appliers
    /// mutate the current root through `&mut Architecture`
    /// (options.cc:1008-1015 `glb->allacts.toggleAction(...)`) while other
    /// subsystems hold shared references to the Architecture.
    pub allacts: Option<std::sync::Arc<std::sync::RwLock<crate::action::ActionDatabase>>>,
    /// Prefer-split records. Faithful to `splitrecords`.
    pub split_records: Vec<crate::prefersplit::PreferSplitRecord>,
    /// Laned register records, ordered by whole-register size. The shared
    /// allocation preserves the pointer identity returned by Ghidra's
    /// `getLanedRegister` across lookups and Funcdata lane-map entries.
    pub lane_records: Vec<std::sync::Arc<crate::transform::LanedRegister>>,

    // ---- Stack space / spacebase configuration (cspec <stackpointer>) ----
    /// The address space that the stack pointer indexes into (IPTR_SPACEBASE).
    /// Faithful to `glb->getStackSpace()`. Defaults to AddressSpace::Stack.
    pub stack_space: crate::space::AddressSpace,
    /// The (space, offset, size) of the formal stack pointer register.
    /// Faithful to cspec `<stackpointer register="RSP" space="ram"/>` +
    /// `SpacebaseSpace::getSpacebase(0)`. Defaults to the x86-64 RSP:
    /// Register@0x20, size 8.
    pub stack_pointer_space: crate::space::AddressSpace,
    pub stack_pointer_offset: u64,
    pub stack_pointer_size: usize,
    /// True if the stack grows toward negative offsets (x86 convention).
    /// Faithful to cspec `growth="negative"`.
    pub stack_grows_negative: bool,
    /// True when the `<stackpointer>` element set `reversejustify="yes"`
    /// (the `setReverseJustified` effect of `addSpacebase`,
    /// architecture.cc:566-567).
    pub stack_reverse_justify: bool,
    /// The stack space's containing space: the cspec `<stackpointer
    /// space="...">` basespace that `Architecture::addSpacebase`
    /// (architecture.cc:559-570) hands to the `SpacebaseSpace`
    /// constructor as its `contain` link (translate.hh:174, exposed by
    /// the `getContain` override at translate.hh:187; the base
    /// `AddrSpace::getContain` null is space.hh:505). Defaults to Ram,
    /// matching every locked x86-64 gcc cspec (`space="ram"`). Powers the
    /// `assoc->getContain() != spc` check of
    /// `RuleLoadVarnode::correctSpacebase` (ruleaction.cc:4181) via
    /// [`Architecture::get_contain`].
    pub stack_base_space: crate::space::AddressSpace,

    /// The formal stack pointer's ORIGINAL (untruncated) base register —
    /// `SpacebaseSpace::baseOrig` (translate.hh:178), the value behind
    /// `getSpacebaseFull(0)` (translate.cc:118-124). Identical to the
    /// [`Self::stack_pointer_*`] triple whenever the base space is not
    /// truncated (`setBaseRegister` with `truncSize == size` leaves
    /// `baseloc == baseOrig`, translate.cc:95-101).
    pub stack_pointer_full_space: crate::space::AddressSpace,
    pub stack_pointer_full_offset: u64,
    pub stack_pointer_full_size: usize,
    /// Default space where code lives (`defaultcodespace`, translate.hh:226,
    /// read through `getDefaultCodeSpace`, translate.hh:505-507). Enum-model
    /// stand-in: the locked x86-64 production code space `ram` (the driver
    /// cspecs resolve `space="ram"` to
    /// [`crate::space::AddressSpace::Ram`]).
    pub default_code_space: crate::space::AddressSpace,
    /// Applied `<truncate_space>` commands in application order, stored as
    /// (enum space name, truncated size). Enum-model projection of the
    /// per-`AddrSpace` state that `AddrSpace::truncateSpace` mutates
    /// (space.cc:105-112): the TRUNCATED flag, `addressSize = newsize`,
    /// `minimumPointerSize = newsize`, `calcScaleMask`. Applied through the
    /// manager's by-name lookup (`AddrSpaceManager::truncateSpace`,
    /// translate.cc:776-783) during language initialization
    /// (`SleighArchitecture::modifySpaces`, sleigh_arch.cc:423-430, fed by
    /// the `.ldefs` `<language>` `<truncate_space>` records,
    /// sleigh_arch.cc:86-89).
    pub space_truncations: Vec<(String, u32)>,

    /// The SLEIGH register cross-reference, keyed exactly like
    /// `SleighBase::varnode_xref` (sleighbase.cc:91's insert key):
    /// `(space index, offset, size)` with BIG sizes first
    /// (`VarnodeData::operator<`, pcoderaw.hh:67-71). Populated from
    /// `SleighBase::getAllRegisters` (sleighbase.cc:182-186) — the
    /// `varnode_xref` copy the shim's `rugra_sleigh_register_info` walks —
    /// by the driver at architecture build time. Consumers:
    /// [`Architecture::get_register_name`] (the
    /// `SleighBase::getRegisterName` projection) and
    /// [`Architecture::get_exact_register_name`].
    pub register_xref: std::collections::BTreeMap<
        (i32, u64, i32),
        String,
    >,
}

// Manual Debug impl (the `loader` field is `Arc<dyn LoadImage>` without a
// Debug bound, so we cannot derive). Print just the archid for diagnostics.
impl std::fmt::Debug for Architecture {
    // RUGRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Architecture").field("archid", &self.archid).finish()
    }
}

impl Default for Architecture {
    // RUGRA-GLUE: default (no Ghidra counterpart found)
    fn default() -> Self {
        Self::new()
    }
}

// Ghidra: architecture.cc:211-212 ~Architecture: if (types != 0) delete types;
/// TF-SINGLETON-WIRING-0001 step 1 teardown mirror: the oracle Architecture
/// DESTROYS its TypeFactory in the destructor (architecture.cc:211-212),
/// ending the factory's cross-Architecture lifetime. Rugra's factory lives
/// behind `Arc<RwLock<..>>`, so the destruction equivalent is unpublishing
/// the thread's current-Architecture entry when it still points at OUR
/// factory — after this, `TypeFactory::shared_default` resolutions on this
/// thread fall back to the process-canonical tier instead of a dropped
/// Architecture's stale factory. A different Architecture's publication is
/// left untouched (its ownership supersedes ours).
impl Drop for Architecture {
    // RUGRA-GLUE: drop (destructor side of the ownership mirror; the
    // Rust-side field teardown follows automatically)
    fn drop(&mut self) {
        if let Some(factory) = &self.types {
            crate::type_system::typefactory::TypeFactory::unpublish_current_arch(factory);
        }
        // architecture.cc:200-201 printlist teardown half — the registry
        // entry for this architecture goes away with it (the printers stay
        // alive through their Arc handles).
        crate::printlanguage::unpublish_printlist(self.print_registry_key);
    }
}

// RUGRA-GLUE: print_registry_key minting (identity channel for the
// architecture.hh:206 printlist storage mirror — allocator-independent,
// never part of any output).
fn next_print_registry_key() -> u64 {
    static NEXT_KEY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT_KEY.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Architecture {
    // RUGRA-GLUE: new (no Ghidra counterpart found)
    /// Construct an uninitialized Architecture. Faithful to `Architecture()`
    /// (architecture.cc:150).
    pub fn new() -> Self {
        let mut arch = Self {
            archid: String::new(),
            trim_recurse_max: 0,
            max_implied_ref: 0,
            max_term_duplication: 0,
            max_basetype_size: 0,
            min_funcsymbol_size: 1,
            max_jumptable_size: 0,
            aggressive_ext_trim: false,
            readonlypropagate: false,
            infer_pointers: false,
            analyze_for_loops: false,
            nan_ignore_all: false,
            nan_ignore_compare: false,
            funcptr_align: 0,
            flowoptions: 0,
            max_instructions: 0,
            alias_block_level: 0,
            split_datatype_config: 0,
            proto_models: ProtoModelMap::new(),
            defaultfp_name: None,
            defaultfp: None,
            default_return_addr: None,
            evalfp_current_name: None,
            evalfp_called_name: None,
            evalfp_current: None,
            evalfp_called: None,
            infer_ptr_spaces: Vec::new(),
            global_scope_ranges: Vec::new(),
            nohighptr: RangeList::new(),
            overrides: Override::new(),
            loadersymbols_parsed: false,
            // Ghidra: architecture.cc:597 Architecture::buildDatabase —
            // `symboltab = new Database(this,true);` (cc:600) + the global
            // scope attach (architecture.cc:601-602). The Architecture
            // ALWAYS owns a symbol table in the oracle; the cspec `<global>`
            // ranges land in its global scope at parse time (the
            // `add_to_global_scope` write-through). Drivers that install
            // their own Program DB replace the whole handle
            // (`set_symboltab`), which drops these ranges in favor of
            // their own — the canon-face contract
            // (CSPEC-GLOBAL-APPLY-0001).
            symboltab: Some(std::sync::Arc::new(std::sync::RwLock::new(
                crate::database::Database::new(true),
            ))),
            loader: None,
            type_factory_name: None,
            types: None,
            userops: None,
            pcodeinjectlib: None,
            join_db: crate::space::JoinDatabase::new(),
            commentdb: None,
            string_manager: None,
            cpool: None,
            context_db: None,
            tracked_set_map: TrackedSetMap::new(),
            context_set_children_skipped: 0,
            options_db: None,
            print_registry_key: next_print_registry_key(),
            allacts: None,
            split_records: Vec::new(),
            lane_records: Vec::new(),
            stack_space: crate::space::AddressSpace::Stack,
            stack_pointer_space: crate::space::AddressSpace::Register,
            stack_pointer_offset: 0x20, // x86-64 RSP
            stack_pointer_size: 8,
            stack_grows_negative: true,
            stack_reverse_justify: false,
            stack_base_space: crate::space::AddressSpace::Ram,
            // baseOrig == baseloc on the untruncated default (translate.cc:95).
            stack_pointer_full_space: crate::space::AddressSpace::Register,
            stack_pointer_full_offset: 0x20, // x86-64 RSP (baseOrig)
            stack_pointer_full_size: 8,
            default_code_space: crate::space::AddressSpace::Ram,
            space_truncations: Vec::new(),
            register_xref: std::collections::BTreeMap::new(),
        };
        arch.reset_defaults_internal();
        arch
    }

    // RUGRA-GLUE: reset_defaults_internal (no Ghidra counterpart found)
    /// Reset default values for options specific to Architecture. Faithful to
    /// `resetDefaultsInternal` (architecture.cc:1416).
    pub fn reset_defaults_internal(&mut self) {
        self.trim_recurse_max = 5;
        self.max_implied_ref = 2;
        self.max_term_duplication = 2;
        self.max_basetype_size = 10;
        self.flowoptions = FLOWOPT_ERROR_TOOMANY;
        self.max_instructions = 100000;
        self.infer_pointers = true;
        self.analyze_for_loops = true;
        self.readonlypropagate = false;
        self.nan_ignore_all = false;
        self.nan_ignore_compare = true;
        self.alias_block_level = 2;
        self.split_datatype_config = split_datatype::OPTION_STRUCT
            | split_datatype::OPTION_ARRAY
            | split_datatype::OPTION_POINTER;
        self.max_jumptable_size = 1024;
    }

    // RUGRA-GLUE: reset_defaults (no Ghidra counterpart found)
    /// Reset defaults values for options owned by this Architecture. Faithful
    /// to `resetDefaults` (architecture.cc:1438).
    pub fn reset_defaults(&mut self) {
        self.reset_defaults_internal();
        // architecture.cc:1442 `allacts.resetDefaults();` — same failure class
        // as Ghidra: a database that never registered its universal root
        // aborts when the "decompile" root is rederived. A `None` database
        // (pre-`build_action` state, which the embedded Ghidra value cannot
        // represent) has no defaults to reset.
        if let Some(db) = &self.allacts {
            db.write().expect("allacts write lock").reset_defaults();
        }
        // architecture.cc:1443-1444:
        //   for(int4 i=0;i<printlist.size();++i)
        //     printlist[i]->resetDefaults();
        // — every printer registered with THIS architecture (identity-keyed
        // registry, so a second live architecture's printers are untouched,
        // exactly as the oracle's per-object vector).
        crate::printlanguage::printlist_reset_defaults(self.print_registry_key);
    }

    // Ghidra: architecture.cc:171-172 Architecture::Architecture (print =
    // buildLanguage(...); printlist.push_back(print);) +
    // architecture.cc:431 setPrintLanguage (printlist.push_back(print))
    /// Register a printer with this architecture and make it the current
    /// printer. Both oracle push sites — the constructor's default build
    /// and `setPrintLanguage`'s newly built language — push and
    /// immediately make current. Returns the shared handle: the caller
    /// keeps it for concrete printer work while option appliers reach the
    /// same object through [`Self::print_language_current`] exactly as
    /// `glb->print` does (options.cc:526).
    pub fn register_print_language(
        &mut self,
        printer: Box<dyn crate::printlanguage::PrintLanguage>,
    ) -> std::sync::Arc<
        std::sync::RwLock<Box<dyn crate::printlanguage::PrintLanguage>>,
    > {
        crate::printlanguage::register_print_language(self.print_registry_key, printer)
    }

    // Ghidra: architecture.hh:205 print — the current-printer accessor
    /// The architecture's current printer (`glb->print`). `None` before
    /// the first registration — a state the oracle's constructor-time
    /// build (architecture.cc:171-172) cannot occupy; option appliers that
    /// need a printer report it (see `OptionCommentStyle::apply`).
    pub fn print_language_current(
        &self,
    ) -> Option<
        std::sync::Arc<
            std::sync::RwLock<Box<dyn crate::printlanguage::PrintLanguage>>,
        >
    > {
        crate::printlanguage::printlist_current(self.print_registry_key)
    }

    // Ghidra: architecture.cc:585 Architecture::buildAction
    /// Build the universal Action for function transformation and
    /// instantiate the "decompile" root Action. Faithful to `buildAction`
    /// (architecture.cc:582-591). `parseExtraRules(store)` is deferred
    /// until spec-driven extra rules land (registered residual
    /// ARCH-PARSEEXTRARULES-0001); it appends user rules before the
    /// universal tree is built, which is unobservable until that input
    /// path exists.
    pub fn build_action(&mut self) {
        let db = self
            .allacts
            .get_or_insert_with(|| std::sync::Arc::new(std::sync::RwLock::new(crate::action::ActionDatabase::new())));
        let mut db = db.write().expect("allacts write lock");
        db.universal_action();
        db.reset_defaults();
    }

    // Ghidra: architecture.cc:234 Architecture::getModel
    /// Get a specific PrototypeModel by name. Faithful to `getModel`
    /// (architecture.cc:234). Returns the entry, or None.
    pub fn get_model(&self, nm: &str) -> Option<&Arc<ProtoModelFull>> {
        self.proto_models.get(nm)
    }

    // Ghidra: architecture.cc:247 Architecture::hasModel
    /// Does this Architecture have a specific PrototypeModel? Faithful to
    /// `hasModel` (architecture.cc:247).
    pub fn has_model(&self, nm: &str) -> bool {
        self.proto_models.contains_key(nm)
    }

    // Ghidra: architecture.cc:264 Architecture::getSpaceBySpacebase
    /// Get the address space associated with the indicated \e spacebase
    /// register. Faithful to `getSpaceBySpacebase`
    /// (architecture.cc:264-282): walk every space (in baselist index
    /// order) and each space's spacebase records, returning the first
    /// space whose record matches the register's size/space/offset.
    ///
    /// Registry source: Rugra's enum-space Architecture keeps the
    /// spacebase records as flat config (Ghidra stores them on the spaces
    /// via `numSpacebase`/`getSpacebase`, space.hh:155-156); the locked
    /// x86-64 oracle has exactly one record-bearing space — the stack
    /// space, whose single record is the `<stackpointer>` triple
    /// [`Self::stack_pointer_space`]/[`Self::stack_pointer_offset`]/
    /// [`Self::stack_pointer_size`] — so the iteration reduces to that
    /// one record.
    ///
    /// Deviation from the throw: Ghidra ends with
    /// `throw LowlevelError("Unable to find entry for spacebase
    /// register")`; this port returns `None` so the caller
    /// (`RuleLoadVarnode::correct_spacebase`) can take the miss branch —
    /// a pre-registered conservative degradation
    /// (PRINTC-INPUTREG-DEADSTORE-0001): the oracle throw only fires for
    /// a spacebase-flagged input at an unregistered location, which
    /// `Funcdata::spacebase` (funcdata.cc:230) never produces.
    pub fn get_space_by_spacebase(
        &self,
        loc_space: crate::space::AddressSpace,
        loc_offset: u64,
        size: usize,
    ) -> Option<crate::space::AddressSpace> {
        // (assoc space, record point (space, offset, size)) in baselist
        // order; today: the stack record only.
        let records = [(
            self.stack_space,
            self.stack_pointer_space,
            self.stack_pointer_offset,
            self.stack_pointer_size,
        )];
        for (assoc, point_space, point_offset, point_size) in records {
            if point_size != size {
                continue;
            }
            if point_space != loc_space {
                continue;
            }
            if point_offset != loc_offset {
                continue;
            }
            return Some(assoc);
        }
        None
    }

    // Ghidra: sleighbase.cc:144 SleighBase::getRegisterName
    /// Register-name lookup: faithful 1:1 port of
    /// `SleighBase::getRegisterName(base, off, size)`
    /// (sleighbase.cc:144-168). Finds the register name whose varnode
    /// contains `[off, off+size)` in `base`, walking the `varnode_xref`
    /// ordering (`VarnodeData::operator<`: space index, then offset, then
    /// BIG sizes first — pcoderaw.hh:67-71). The `upper_bound` step lands on
    /// the first entry greater than the probe `(base, off, size)`; because
    /// equal offsets sort big-size-first, `iter--` lands on the largest
    /// register starting at `off` (or an earlier offset otherwise). The
    /// back-walk then requires a covering
    /// `point.offset + point.size >= off + size`, stopping at the first
    /// base-offset change — exactly the C++ loop at cc:151-167. An empty
    /// table (no SLEIGH catalog installed) yields "" everywhere, matching a
    /// Translate with no registers.
    pub fn get_register_name(
        &self,
        base: crate::space::AddressSpace,
        off: u64,
        size: i32,
    ) -> String {
        // cc:147-150: sym = {space=base, offset=off, size=size}; the probe
        // key mirrors the C++ map ordering with (space-index, offset, size
        // DESCENDING), so a Rust BTreeMap over (index, offset, -size) with
        // the probe's `-size` reproduces the C++ ordering exactly.
        let probe = (base.space_id() as i32, off, -size);
        // cc:151-153: iter = upper_bound(sym); if (iter == begin()) return "";
        // iter--. upper_bound is the first entry STRICTLY greater than the
        // probe, so the element it steps back to is the GREATEST entry with
        // key <= probe — an inclusive end bound. (iter == begin() means no
        // entry <= probe exists at all, the empty-range case.)
        let (prev_key, prev_name) = {
            let mut walker = self.register_xref.range(..=probe);
            match walker.next_back() {
                Some(entry) => (entry.0.clone(), entry.1.clone()),
                None => return String::new(),
            }
        };
        let (prev_space, prev_off, neg_prev_size) = prev_key;
        let prev_size = -neg_prev_size;
        // cc:155: point.space != base → "".
        if crate::space::AddressSpace::from_id(prev_space as u8) != base {
            return String::new();
        }
        // cc:156: offbase = point.offset.
        let offbase = prev_off;
        // cc:157-158: point.offset+point.size >= off+size → name.
        if prev_off.wrapping_add(prev_size as u64) >= off.wrapping_add(size as u64) {
            return prev_name;
        }
        // cc:160-166: walk back ONE predecessor per step
        // (`while(iter!=begin()){ --iter; ... }`), checking each for the
        // space/base-offset break and the covering gate. `range(..current)`
        // is the RangeTo (exclusive) bound: it already excludes `current`,
        // so `next_back()` lands exactly on the immediate predecessor —
        // oracle's `--iter`. (F1 fix, R-RAWQUAR: the former extra
        // `next_back()` discard skipped every other predecessor.)
        let mut current = prev_key;
        loop {
            let mut walker = self.register_xref.range(..current);
            match walker.next_back() {
                None => return String::new(),
                Some((next_key, next_name)) => {
                    let (next_space, next_off, neg_next_size) = *next_key;
                    let next_size = -neg_next_size;
                    // cc:163: space change or base-offset change → "".
                    if crate::space::AddressSpace::from_id(next_space as u8) != base
                        || next_off != offbase
                    {
                        return String::new();
                    }
                    // cc:164-165: covering entry → name.
                    if next_off.wrapping_add(next_size as u64)
                        >= off.wrapping_add(size as u64)
                    {
                        return next_name.clone();
                    }
                    current = *next_key;
                }
            }
        }
    }

    // Ghidra: sleighbase.cc:170 SleighBase::getExactRegisterName
    /// Exact `(space, offset, size)` register-name lookup, faithful to
    /// `SleighBase::getExactRegisterName` (sleighbase.cc:170-180): the
    /// `varnode_xref.find` hit or "".
    pub fn get_exact_register_name(
        &self,
        base: crate::space::AddressSpace,
        off: u64,
        size: i32,
    ) -> String {
        self.register_xref
            .get(&(base.space_id() as i32, off, -size))
            .cloned()
            .unwrap_or_default()
    }

    // RUGRA-GLUE: set_register_xref (no Ghidra counterpart; Ghidra fills
    //   varnode_xref during SleighBase::buildXrefs (sleighbase.cc:79-96)
    //   from the live symbol table, Rugra snapshots the shim's
    //   getAllRegisters enumeration at driver time).
    /// Install the SLEIGH register cross-reference: entries are
    /// `(space index, offset, size, name)` tuples from
    /// `rugra_sleigh_register_info` (the `SleighBase::getAllRegisters`
    /// copy). The key mirrors `VarnodeData::operator<` with big sizes
    /// first (pcoderaw.hh:67-71); the value is the register name. A
    /// duplicate key keeps the FIRST insert, matching
    /// `varnode_xref.insert`'s no-overwrite semantics (sleighbase.cc:91 —
    /// the conflicting pair goes to errorPairs instead).
    pub fn set_register_xref(
        &mut self,
        entries: impl IntoIterator<Item = (i32, u64, i32, String)>,
    ) {
        self.register_xref.clear();
        for (space_index, offset, size, name) in entries {
            self.register_xref
                .entry((space_index, offset, -size))
                .or_insert(name);
        }
    }

    // Ghidra: space.hh:505 AddrSpace::getContain (stack override: translate.hh:187)
    /// Return the containing space of a virtual space, `None` otherwise.
    /// Faithful relocation of the `getContain` family: the base
    /// `AddrSpace::getContain` (space.hh:505-507) returns null for
    /// non-virtual spaces, and the `SpacebaseSpace` override
    /// (translate.hh:187) returns the space's `contain` link
    /// (translate.hh:174) — for the stack space, the cspec basespace
    /// installed by `addSpacebase` (architecture.cc:564-565). Rugra's
    /// enum-space model has no per-space record store, so the link lives
    /// on the Architecture ([`Self::stack_base_space`]) and the lookup is
    /// keyed by the associated space. Callers compare the result against
    /// the load/store space exactly as the oracle compares
    /// `assoc->getContain() != spc` (ruleaction.cc:4181).
    pub fn get_contain(
        &self,
        spc: crate::space::AddressSpace,
    ) -> Option<crate::space::AddressSpace> {
        if spc == self.stack_space {
            return Some(self.stack_base_space);
        }
        None
    }

    // Ghidra: architecture.cc:323 Architecture::setDefaultModel
    /// Set the default PrototypeModel. Faithful to `setDefaultModel`
    /// (architecture.cc:323). The previous default (if any) is reset to
    /// print-in-decl.
    pub fn set_default_model(&mut self, model_name: &str) {
        if !self.proto_models.contains_key(model_name) {
            return;
        }
        self.defaultfp_name = None;
        if let Some(previous) = self.defaultfp.take() {
            previous.set_print_in_decl(true);
        }
        let model = self
            .proto_models
            .get(model_name)
            .expect("model existence checked before default selection")
            .clone();
        model.set_print_in_decl(false);
        self.defaultfp_name = Some(model_name.to_string());
        self.defaultfp = Some(model);
    }

    // Ghidra: architecture.cc:741 Architecture::decodeProto
    /// Decode and register one `<prototype>` child.  Duplicate names fail
    /// before replacing any existing shared model.
    pub fn decode_proto(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<Arc<ProtoModelFull>, String> {
        self.decode_proto_common(decoder, addr_size, register_resolver, None)
    }

    // Ghidra: architecture.cc:741 Architecture::decodeProto
    /// The `parseCompilerConfig` path of `decodeProto`: the Architecture's
    /// `defaultReturnAddr` (set by a preceding `<returnaddress>` element)
    /// is injected into models that lack their own `<returnaddress>`
    /// (fspec.cc:2689-2691), exactly like Ghidra reading `glb` state at
    /// model-decode time.
    pub fn decode_proto_spec(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<Arc<ProtoModelFull>, String> {
        let default_return = self.default_return_addr.clone();
        self.decode_proto_common(decoder, addr_size, register_resolver, default_return.as_ref())
    }

    // Ghidra: architecture.cc:741 Architecture::decodeProto
    /// Shared decode core for both entry points.
    fn decode_proto_common(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
        default_return_addr: Option<&VarnodeData>,
    ) -> Result<Arc<ProtoModelFull>, String> {
        let sub_id = decoder.peek_element();
        let sub_name = decoder.element_name(sub_id).unwrap_or_default();
        if sub_name != "prototype" {
            return Err("Expecting <prototype> or <resolveprototype> tag".to_string());
        }
        let mut model = ProtoModelFull::new(Some(self.stack_space), addr_size);
        let name = model.decode_with_defaults(
            decoder,
            Some(self.stack_space),
            addr_size,
            self.stack_grows_negative,
            None,
            None,
            register_resolver,
            default_return_addr,
        )?;
        if self.proto_models.contains_key(&name) {
            return Err(format!("Duplicate ProtoModel name: {name}"));
        }
        let model = Arc::new(model);
        self.proto_models.insert(name, model.clone());
        Ok(model)
    }

    // Ghidra: architecture.cc:795 Architecture::decodeDefaultProto
    /// Decode the `<default_proto>` wrapper and select its single model as the
    /// Architecture default.
    pub fn decode_default_proto(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.decode_default_proto_common(decoder, addr_size, register_resolver, false)
    }

    // Ghidra: architecture.cc:795 Architecture::decodeDefaultProto
    /// The `parseCompilerConfig` path of `decodeDefaultProto`, injecting
    /// the Architecture default return address into the models.
    pub fn decode_default_proto_spec(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.decode_default_proto_common(decoder, addr_size, register_resolver, true)
    }

    // Ghidra: architecture.cc:795 Architecture::decodeDefaultProto
    /// Shared decode core for both entry points.
    fn decode_default_proto_common(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        addr_size: usize,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
        with_default_return: bool,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        while decoder.peek_element() != 0 {
            if self.defaultfp.is_some() {
                return Err("More than one default prototype model".to_string());
            }
            let model = if with_default_return {
                self.decode_proto_spec(decoder, addr_size, register_resolver)?
            } else {
                self.decode_proto(decoder, addr_size, register_resolver)?
            };
            let name = model.get_name().to_string();
            self.set_default_model(&name);
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.hh:193 Architecture::defaultfp
    /// Retrieve the selected shared default model.
    pub fn get_default_model(&self) -> Option<&Arc<ProtoModelFull>> {
        self.defaultfp.as_ref()
    }

    // Ghidra: architecture.cc:812 Architecture::decodeGlobal
    /// Parse a `<global>` element for child `<range>` elements that will be
    /// added to the global scope.  Ranges are stored in partial form so
    /// that elements can be parsed before all address spaces exist.
    /// Faithful to `decodeGlobal` (architecture.cc:812-821): children are
    /// collected in document order; a failing child aborts the collection
    /// with the partial vector handed back to the caller (the earlier
    /// directly-applied model/stack/inject state stays applied).
    pub fn decode_global(
        decoder: &mut dyn crate::marshal::Decoder,
        range_props: &mut Vec<RangeProperties>,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        while decoder.peek_element() != 0 {
            range_props.push(RangeProperties::new());
            RangeProperties::decode(range_props.last_mut().expect("just pushed"), decoder)
                .map_err(|e| e.to_string())?;
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: address.cc:236 Range::Range(const RangeProperties &,const AddrSpaceManager *)
    /// Resolve partially parsed range properties against the language.
    /// Faithful to the `Range` constructor (address.cc:236-260): a register
    /// range spans the named register varnode (`last = first-1+size`), a
    /// space range defaults `last` to the space's highest offset, and an
    /// out-of-bounds or reversed range throws `Illegal range tag`.
    fn range_from_properties(
        props: &RangeProperties,
        host: &dyn SpecQuery,
    ) -> Result<(crate::space::AddressSpace, u64, u64), String> {
        if props.is_register {
            let point = host
                .get_register(&props.space_name)
                .ok_or_else(|| format!("Unknown register name: {}", props.space_name))?;
            let first = point.offset;
            let last = (first.wrapping_sub(1)).wrapping_add(point.size as u64);
            return Ok((point.space, first, last));
        }
        let spc = host
            .space_by_name(&props.space_name)
            .ok_or_else(|| format!("Undefined space: {}", props.space_name))?;
        let highest = host.space_highest(spc);
        let first = props.first;
        let mut last = props.last;
        if !props.seen_last {
            last = highest;
        }
        if first > highest || last > highest || last < first {
            return Err("Illegal range tag".to_string());
        }
        Ok((spc, first, last))
    }

    // Ghidra: architecture.cc:826 Architecture::addToGlobalScope
    /// Add a memory range parsed from a `<global>` tag to the global scope.
    /// Varnodes in this region will be assumed to be global variables.
    /// Faithful to `addToGlobalScope` (architecture.cc:826-844): the space
    /// is appended to `inferPtrSpaces` and the range is applied to the
    /// global scope; when the space is an overlay base the range is
    /// duplicated into every overlay space contained in it.  Since
    /// CSPEC-GLOBAL-APPLY-0001 the range lands in the constructor-built
    /// symbol table's global scope at parse time (the space-keyed
    /// `ScopeRangeTree` via `add_range_spaced` — the
    /// architecture.cc:833/841/852 `symboltab->addRange` write-through);
    /// the `(space, first, last)` triples are additionally recorded in
    /// source order on the Architecture (`global_scope_ranges`) as the
    /// projection the fixtures and drivers observe.
    ///
    /// A REGISTER-space range (e.g. x86-64-gcc.cspec's
    /// `<global><register name="MXCSR"/></global>`) applies to the global
    /// scope but is NOT appended to `inferPtrSpaces`:
    /// `Architecture::cacheAddrSpaceProperties`
    /// (architecture.cc:665-683) filters the infer list with
    /// `if (spc->getDelay() == 0) continue; // Don't put in a register
    /// space` (cc:678) — register spaces (delay 0) never infer constant
    /// pointers. Pushing Register into the list made a 4-byte constant
    /// (`inferPtrSpaces=[Ram,Register]`, Register addrSize 4) pass the
    /// exact-size gate where the oracle's [Ram(+code)] list rejects it
    /// (4 != 8), so ActionConstantPtr converted the httpd main int-web
    /// constant 0x17a422 ("ptemp") into a 4-byte
    /// PTRSUB(spacebase,#0x17a422) that RulePtrsubCharConstant then
    /// collapsed into a char* constant — typing the whole
    /// apr_app_initialize-return web char* (`pcVar4 = "ptemp"` +
    /// `(char *)` casts) where the oracle keeps `int iVar3 = 0x17a422`
    /// (HTTPDMAIN-F4-WEBTYPE-0001).
    pub fn add_to_global_scope(
        &mut self,
        props: &RangeProperties,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        let (spc, first, last) = Self::range_from_properties(props, host)?;
        // architecture.cc:665-683 cacheAddrSpaceProperties: register
        // spaces (delay 0) stay out of the constant-pointer inference
        // list (cc:678 `if (spc->getDelay() == 0) continue; // Don't put
        // in a register space`); the range still applies to the global
        // scope below (HTTPDMAIN-F4-WEBTYPE-0001).
        if spc != crate::space::AddressSpace::Register {
            self.infer_ptr_spaces.push(spc);
        }
        // database.cc:833 — `symboltab->addRange(scope,spc,...)`: the
        // range lands in the global scope's space-keyed rangetree NOW
        // (the same `Database::addRange` call the C++ makes, live at
        // parse time). The `global_scope_ranges` record below keeps the
        // source-order projection the CSPEC-GLOBAL-APPLY fixture observes.
        if let Some(symboltab) = &self.symboltab {
            let global_id = symboltab.read().expect("lock poisoned").global_scope_id;
            symboltab
                .write()
                .expect("lock poisoned")
                .add_range_spaced(global_id, spc, first, last);
        }
        self.global_scope_ranges.push((spc, first, last));
        if host.is_overlay_base(spc) {
            // We need to duplicate the range being marked as global into
            // the overlay space(s)
            let num = host.num_spaces();
            for i in 0..num {
                let Some(ospc) = host.space_at(i) else { continue };
                if !host.is_overlay(ospc) {
                    continue;
                }
                if host.contain_space(ospc) != Some(spc) {
                    continue;
                }
                // database.cc:841 — the overlay duplicate addRange.
                if let Some(symboltab) = &self.symboltab {
                    let global_id =
                        symboltab.read().expect("lock poisoned").global_scope_id;
                    symboltab
                        .write()
                        .expect("lock poisoned")
                        .add_range_spaced(global_id, ospc, first, last);
                }
                self.global_scope_ranges.push((ospc, first, last));
            }
        }
        Ok(())
    }

    // Ghidra: architecture.cc:847 Architecture::addOtherSpace
    /// Explicitly add the OTHER space and any overlays to the global scope.
    /// Faithful to `addOtherSpace` (architecture.cc:847-862).
    pub fn add_other_space(&mut self, host: &dyn SpecQuery) -> Result<(), String> {
        let Some(other_space) = host.space_by_name("other") else {
            return Err("Undefined space: other".to_string());
        };
        let highest = host.space_highest(other_space);
        // database.cc:852 — `symboltab->addRange(scope,otherSpace,0,...)`.
        if let Some(symboltab) = &self.symboltab {
            let global_id = symboltab.read().expect("lock poisoned").global_scope_id;
            symboltab
                .write()
                .expect("lock poisoned")
                .add_range_spaced(global_id, other_space, 0, highest);
        }
        self.global_scope_ranges.push((other_space, 0, highest));
        if host.is_overlay_base(other_space) {
            let num = host.num_spaces();
            for i in 0..num {
                let Some(ospc) = host.space_at(i) else { continue };
                if !host.is_overlay(ospc) {
                    continue;
                }
                if host.contain_space(ospc) != Some(other_space) {
                    continue;
                }
                // database.cc:859 — the overlay duplicate addRange.
                if let Some(symboltab) = &self.symboltab {
                    let global_id =
                        symboltab.read().expect("lock poisoned").global_scope_id;
                    symboltab
                        .write()
                        .expect("lock poisoned")
                        .add_range_spaced(global_id, ospc, 0, highest);
                }
                self.global_scope_ranges.push((ospc, 0, highest));
            }
        }
        Ok(())
    }

    // ---- pspec <context_data> tracked-register ingest (ARCH-CONTEXT-TRACKED-0001) ----

    // Ghidra: globalcontext.cc:531 ContextInternal::decodeFromSpec
    /// Decode a pspec `<context_data>` element into tracked-register
    /// partitions.  Faithful to `ContextInternal::decodeFromSpec`
    /// (globalcontext.cc:531-549), which the `ELEM_CONTEXT_DATA` arm of
    /// `Architecture::parseProcessorConfig` invokes
    /// (architecture.cc:1172-1223, dispatch at :1190):
    /// - children are consumed in strict document order via
    ///   `openElement()` until exhaustion (`subId == 0`);
    /// - every child MUST carry range attributes
    ///   (`Range::decodeFromAttributes`, address.cc:316-353);
    /// - a `<tracked_set>` child installs a tracked partition over
    ///   [addr1, addr2) — `createSet` (globalcontext.cc:470) +
    ///   `decodeTracked` (globalcontext.cc:85) fill the SAME vector the
    ///   partition map returned (reference, not copy);
    /// - a `<context_set>` child targets the low-level SLEIGH context blob
    ///   (`decodeContext`, globalcontext.cc:345) — consumed and counted
    ///   here, decode residual SLEIGH-0002C;
    /// - any other child throws `Bad <context_data> tag` (verbatim oracle
    ///   text, globalcontext.cc:547).
    pub fn decode_context_data(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        let root_name = decoder.element_name(elem_id).unwrap_or_default();
        if root_name != "context_data" {
            // XmlDecode::openElement(const ElementId &) mismatch text
            // (marshal.cc:185).
            return Err(format!("Expecting <context_data> but got <{}>", root_name));
        }
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            // Range range; range.decodeFromAttributes(decoder); // There MUST be a range
            let (spc, first, last) = Self::range_from_attributes(decoder, host)?;
            let addr1 = (spc.space_id(), first);
            // Address addr2 = range.getLastAddrOpen(decoder.getAddrSpaceManager())
            let addr2 = Self::last_addr_open(spc, last, host);
            let child_name = decoder.element_name(sub_id).unwrap_or_default();
            match child_name.as_str() {
                "context_set" => {
                    // Ghidra: decodeContext(decoder,addr1,addr2) consumes the
                    // <set> children (globalcontext.cc:349-368) against the
                    // SLEIGH-registered context variables.  Residual: the
                    // .sla context layout is not registered in the Rust
                    // ContextDatabase (SLEIGH-0002C), so the children are
                    // consumed (document order, one close per child) and the
                    // occurrence is counted instead of decoded.
                    self.context_set_children_skipped += 1;
                    loop {
                        let inner = decoder.open_element();
                        if inner == 0 {
                            break;
                        }
                        decoder.close_element(inner);
                    }
                }
                "tracked_set" => {
                    // TrackedSet &res(trackbase.clearRange(addr1,addr2));
                    // res.clear(); return res;  (globalcontext.cc:470-475)
                    let slot = self.tracked_set_map.clear_range(addr1, addr2);
                    Self::decode_tracked(slot, decoder, host)?;
                }
                _ => return Err("Bad <context_data> tag".to_string()),
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:929 Architecture::decodeProcessorData (register_data arm)
    /// Decode a pspec `<register_data>` element into the architecture's
    /// laned-register records. Faithful to the `ELEM_REGISTER_DATA` arm of
    /// `Architecture::decodeProcessorData` (architecture.cc:929-977):
    /// - one `<register>` child at a time in document order; the child must
    ///   carry `vector_lane_sizes` and/or `volatile` attributes to act;
    /// - `vector_lane_sizes` (comma-separated) parses through
    ///   `LanedRegister::parseSizes` and ORs its size bitmask into
    ///   `maskList[wholeSize]` (cc:952-958);
    /// - after all children, `lanerecords` is rebuilt as one record per
    ///   non-zero mask entry, ordered by whole size (cc:970-976) —
    ///   `set_lane_records` performs the same sort+merge.
    /// The `volatile` arm (cc:960-963: `symboltab->setPropertyRange`) is a
    /// registered residual: the locked x86-64.pspec declares no volatile
    /// registers (grep-clean), so the arm is unreachable for this corpus
    /// (ARCH-REGISTERDATA-VOLATILE-0001).
    pub fn decode_register_data(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let mut mask_list: Vec<u32> = Vec::new();
        let elem_id = decoder.open_element();
        let root_name = decoder.element_name(elem_id).unwrap_or_default();
        if root_name != "register_data" {
            return Err(format!(
                "Expecting <register_data> but got <{}>",
                root_name
            ));
        }
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            let child_name = decoder.element_name(sub_id).unwrap_or_default();
            if child_name != "register" {
                return Err(format!(
                    "Expecting <register> but got <{}>",
                    child_name
                ));
            }
            // cc:936-944: first attribute pass collects the two knobs.
            let mut is_volatile = false;
            let mut lane_sizes = String::new();
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match decoder.attribute_name(attrib_id).as_deref() {
                    Some("vector_lane_sizes") => lane_sizes = decoder.read_string(),
                    Some("volatile") => is_volatile = decoder.read_bool(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            if !lane_sizes.is_empty() || is_volatile {
                // cc:945-947: rewindAttributes + storage.decodeFromAttributes
                // (pcoderaw.cc:33-52: `name` resolves through the translate's
                // register table and wins over `space`). The rewind is
                // REQUIRED: the knob loop above already consumed the
                // attribute stream.
                decoder.rewind_attributes();
                let storage = Self::varnode_data_from_attributes(decoder, host)?;
                if !lane_sizes.is_empty() {
                    let mut laned_register = crate::transform::LanedRegister::with_sizes(0, 0);
                    laned_register.parse_sizes(storage.size as i32, &lane_sizes);
                    let size_index = laned_register.get_whole_size();
                    while mask_list.len() as i32 <= size_index {
                        mask_list.push(0);
                    }
                    mask_list[size_index as usize] |= laned_register.get_size_bit_mask();
                }
                if is_volatile {
                    // ARCH-REGISTERDATA-VOLATILE-0001: symboltab
                    // setPropertyRange wiring not reachable for the locked
                    // pspec (zero volatile declarations); surface the hit
                    // loudly if a future spec exercises the arm.
                    eprintln!(
                        "[ARCH] register_data volatile arm skipped (ARCH-REGISTERDATA-VOLATILE-0001)"
                    );
                }
            }
            decoder.close_element(sub_id);
        }
        decoder.close_element(elem_id);
        // cc:970-976: lanerecords.clear(); one LanedRegister per set mask
        // bit-entry, in ascending whole-size order.
        let mut records = Vec::new();
        for (i, mask) in mask_list.iter().enumerate() {
            if *mask == 0 {
                continue;
            }
            records.push(crate::transform::LanedRegister::with_sizes(i as i32, *mask));
        }
        self.set_lane_records(records);
        Ok(())
    }

    // Ghidra: address.cc:316 Range::decodeFromAttributes
    /// Reconstruct a `Range` from the attributes of a `<context_set>`/
    /// `<tracked_set>` child.  Faithful to
    /// `Range::decodeFromAttributes` (address.cc:316-353): `space` resolves
    /// through the space manager (`XmlDecode::readSpace` error text,
    /// marshal.cc:407), `first`/`last` are unsigned integers, `name`
    /// resolves to the register extent and RETURNS EARLY ("There should be
    /// no (space,first,last) attributes"); a missing space throws
    /// `No address space indicated in range tag`; `last` defaults to the
    /// space's highest offset; bounds violations throw `Illegal range tag`.
    fn range_from_attributes(
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(crate::space::AddressSpace, u64, u64), String> {
        use crate::marshal::Decoder;
        let mut spc: Option<crate::space::AddressSpace> = None;
        let mut seen_last = false;
        let mut first = 0u64;
        let mut last = 0u64;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("space") => {
                    let space_name = decoder.read_string();
                    spc = Some(host.space_by_name(&space_name).ok_or_else(|| {
                        format!("Unknown address space name: {}", space_name)
                    })?);
                }
                Some("first") => first = decoder.read_unsigned_integer(),
                Some("last") => {
                    last = decoder.read_unsigned_integer();
                    seen_last = true;
                }
                Some("name") => {
                    // const VarnodeData &point(trans->getRegister(...));
                    // spc/first/last come from the register extent and the
                    // attribute loop RETURNS immediately.
                    let register_name = decoder.read_string();
                    let point = host
                        .get_register(&register_name)
                        .ok_or_else(|| format!("Unknown register name: {}", register_name))?;
                    let first = point.offset;
                    let last = (first.wrapping_sub(1)).wrapping_add(point.size as u64);
                    return Ok((point.space, first, last));
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        let Some(spc) = spc else {
            return Err("No address space indicated in range tag".to_string());
        };
        let highest = host.space_highest(spc);
        if !seen_last {
            last = highest;
        }
        if first > highest || last > highest || last < first {
            return Err("Illegal range tag".to_string());
        }
        Ok((spc, first, last))
    }

    // Ghidra: address.cc:265 Range::getLastAddrOpen
    /// The open right boundary of a tracked partition — the split key one
    /// past the range.  Faithful to `Range::getLastAddrOpen`
    /// (address.cc:265-281): when `last` is the space's highest offset the
    /// boundary is the NEXT SPACE IN ORDER at offset 0
    /// (`AddrSpaceManager::getNextSpaceInOrder`, translate.cc:647-667);
    /// otherwise it is `last + 1` in the same space.  Rugra orders spaces
    /// by `AddressSpace::space_id()`, so the next space in order is
    /// `(sid + 1, 0)` — strictly greater than every `(sid, off)` key, which
    /// is what makes a query at the space's highest offset still resolve to
    /// the partition (see TrackedSetMap's ordering caveat).  The
    /// maximal-address sentinel (no next space, `Address::m_maximal`) also
    /// orders after every same-space key; the `checked_add` overflow arm
    /// models it with `(sid, u64::MAX)`.
    fn last_addr_open(
        spc: crate::space::AddressSpace,
        last: u64,
        host: &dyn SpecQuery,
    ) -> (u8, u64) {
        if last == host.space_highest(spc) {
            match spc.space_id().checked_add(1) {
                Some(next) => (next, 0),
                None => (spc.space_id(), u64::MAX),
            }
        } else {
            (spc.space_id(), last + 1)
        }
    }

    // Ghidra: globalcontext.cc:91 ContextDatabase::decodeTracked
    /// Restore a sequence of tracked register values from the `<set>`
    /// children of one `<tracked_set>`.  Faithful to
    /// `ContextDatabase::decodeTracked` (globalcontext.cc:85-93): the
    /// vector is cleared first ("Clear out any old stuff"), then one
    /// `TrackedContext` per remaining child element, appended in document
    /// order (`vec.emplace_back(); vec.back().decode(decoder);`).
    fn decode_tracked(
        vec: &mut Vec<TrackedRegister>,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        vec.clear(); // Clear out any old stuff
        while decoder.peek_element() != 0 {
            let mut ctx = TrackedRegister {
                loc: VarnodeData {
                    space: crate::space::AddressSpace::Ram,
                    offset: 0,
                    size: 0,
                },
                val: 0,
            };
            Self::decode_tracked_context(&mut ctx, decoder, host)?;
            vec.push(ctx);
        }
        Ok(())
    }

    // Ghidra: globalcontext.cc:56 TrackedContext::decode
    /// Parse one `<set>` element into a tracked register.  Faithful to
    /// `TrackedContext::decode` (globalcontext.cc:56-63): the element name
    /// is checked (`XmlDecode::openElement(ELEM_SET)` mismatch text,
    /// marshal.cc:185), the storage comes from
    /// `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-53), and `val`
    /// is read by attribute id.  Divergence note: a `<set>` missing the
    /// `val` attribute indexes out of bounds in the oracle
    /// (`XmlDecode::readUnsignedInteger(attribId)`, marshal.cc:371-372);
    /// the Rust mirror yields 0 instead of undefined behavior.
    fn decode_tracked_context(
        ctx: &mut TrackedRegister,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        let name = decoder.element_name(elem_id).unwrap_or_default();
        if name != "set" {
            return Err(format!("Expecting <set> but got <{}>", name));
        }
        ctx.loc = Self::varnode_data_from_attributes(decoder, host)?;
        ctx.val =
            decoder.read_unsigned_integer_attr(&crate::marshal::AttributeId::new("val", 0));
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: pcoderaw.cc:33 VarnodeData::decodeFromAttributes
    /// Collect the storage attributes of a `<set>` element.  Faithful to
    /// `VarnodeData::decodeFromAttributes` (pcoderaw.cc:33-53): a `space`
    /// attribute rewinds and re-scans for `offset`/`size` by attribute id
    /// (`AddrSpace::decodeAttributes`, space.cc:339-356 — `size` is read
    /// SIGNED, a missing `offset` throws `Address is missing offset`) and
    /// then breaks; a `name` attribute resolves the whole storage through
    /// the translator's register map (`SleighBase::getRegister`,
    /// sleighbase.cc:133-142) and returns immediately; other attributes are
    /// skipped.  An attribute-less element decodes to Ghidra's null-space
    /// sentinel (`space = (AddrSpace*)0; size = 0`, pcoderaw.cc:35-36),
    /// which Rugra's space enum cannot represent — the default
    /// `VarnodeData` (ram/0/0) stands in for the sentinel.
    fn varnode_data_from_attributes(
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<VarnodeData, String> {
        use crate::marshal::Decoder;
        let mut space: Option<crate::space::AddressSpace> = None;
        let mut offset = 0u64;
        let mut size = 0i32;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("space") => {
                    let space_name = decoder.read_string();
                    let spc = host.space_by_name(&space_name).ok_or_else(|| {
                        format!("Unknown address space name: {}", space_name)
                    })?;
                    // decoder.rewindAttributes(); offset =
                    // space->decodeAttributes(decoder,size);
                    decoder.rewind_attributes();
                    let mut found_offset = false;
                    loop {
                        let inner = decoder.next_attribute_id();
                        if inner == 0 {
                            break;
                        }
                        match decoder.attribute_name(inner).as_deref() {
                            Some("offset") => {
                                offset = decoder.read_unsigned_integer();
                                found_offset = true;
                            }
                            Some("size") => size = decoder.read_signed_integer() as i32,
                            _ => {
                                let _ = decoder.read_string();
                            }
                        }
                    }
                    if !found_offset {
                        return Err("Address is missing offset".to_string());
                    }
                    space = Some(spc);
                    break;
                }
                Some("name") => {
                    let register_name = decoder.read_string();
                    let point = host
                        .get_register(&register_name)
                        .ok_or_else(|| format!("Unknown register name: {}", register_name))?;
                    return Ok(point); // *this = point;
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        Ok(VarnodeData {
            space: space.unwrap_or(crate::space::AddressSpace::Ram),
            offset,
            size,
        })
    }

    // Ghidra: globalcontext.hh:304 ContextInternal::getTrackedSet
    /// The tracked register set in effect at the given address — the
    /// `ActionConstbase` consumer entry point (coreaction.cc:692:
    /// `data.getArch()->context->getTrackedSet(data.getAddress())`).
    /// Faithful to `ContextInternal::getTrackedSet` (globalcontext.hh:304:
    /// `trackbase.getValue(addr)`): the partition of the last split at or
    /// before the address, or the empty default set.
    pub fn get_tracked_set(
        &self,
        space: crate::space::AddressSpace,
        offset: u64,
    ) -> &[TrackedRegister] {
        self.tracked_set_map.get_value(space, offset)
    }

    // Ghidra: globalcontext.hh:303 ContextInternal::getTrackedDefault
    /// The set of default tracked-register values — the `defaultvalue` of
    /// the partition map, returned for addresses preceding every split.
    /// Faithful to `ContextDatabase::getTrackedDefault`
    /// (globalcontext.hh:211-212 / globalcontext.hh:303).
    /// `ContextInternal::decodeFromSpec` installs partitions exclusively
    /// through `createSet` (split points) and never assigns the default
    /// value (globalcontext.cc:531-549), so the default stays the empty set
    /// on this ingest path — mirrored by the empty slice.
    pub fn get_tracked_default(&self) -> &[TrackedRegister] {
        &[]
    }

    // Ghidra: architecture.cc:898 Architecture::decodeReturnAddress
    /// Apply information from a `<returnaddress>` element and set the
    /// default storage location for the return address of a function.
    /// Faithful to `decodeReturnAddress` (architecture.cc:898-909): the
    /// child is optional but a second `<returnaddress>` tag after the
    /// default was set throws `Multiple <returnaddress> tags in .cspec`.
    pub fn decode_return_address(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        let sub_id = decoder.peek_element();
        if sub_id != 0 {
            if self.default_return_addr.is_some() {
                return Err("Multiple <returnaddress> tags in .cspec".to_string());
            }
            // VarnodeData::decode (pcoderaw.cc:23) + decodeFromAttributes
            // (pcoderaw.cc:33-55): `space` starts null and is only set by a
            // `space` or `name` attribute — an attribute-less `<varnode/>`
            // decodes to the null-space sentinel, so the member overwrite
            // leaves the default return address UNSET (the cc:904 guard and
            // the fspec.cc:2689 injection both treat it as unset).
            let child = decoder.open_element();
            let mut space: Option<crate::space::AddressSpace> = None;
            let mut offset = 0u64;
            let mut size = 0i32;
            let mut register_name: Option<String> = None;
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match decoder.attribute_name(attrib_id).as_deref() {
                    Some("space") => {
                        let space_name = decoder.read_string();
                        space = Some(
                            host.space_by_name(&space_name)
                                .ok_or_else(|| format!("Undefined space: {}", space_name))?,
                        );
                    }
                    Some("offset") => offset = decoder.read_unsigned_integer(),
                    Some("size") => size = decoder.read_unsigned_integer() as i32,
                    Some("name") => register_name = Some(decoder.read_string()),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            decoder.close_element(child);
            // The member is overwritten unconditionally, mirroring the
            // struct assignment of `defaultReturnAddr.decode(decoder)`.
            if let Some(name) = register_name {
                let point = host
                    .get_register(&name)
                    .ok_or_else(|| format!("Unknown register name: {}", name))?;
                self.default_return_addr = Some(point);
            } else if let Some(space) = space {
                self.default_return_addr = Some(VarnodeData { space, offset, size });
            } else {
                self.default_return_addr = None;
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:979 Architecture::decodeStackPointer
    /// Create a stack space and a stack-pointer register from a
    /// `<stackpointer>` element.  Faithful to `decodeStackPointer`
    /// (architecture.cc:979-1014): `reversejustify`/`growth`/`space`/
    /// `register` attributes in source order, the base space attribute is
    /// mandatory, the register is resolved via the language, and a
    /// truncated base space truncates the pointer size (cc:1007-1011) —
    /// the [`Self::stack_pointer_*`] triple is `SpacebaseSpace::baseloc`
    /// (possibly truncated) and [`Self::stack_pointer_full_*`] is
    /// `baseOrig` (translate.cc:95-101).  Rugra has no
    /// dynamic space creation: the decoded values land on the
    /// `stack_*` fields of the Architecture (the SpacebaseSpace insertion
    /// is carried by the `stack_space` enum stand-in).
    pub fn decode_stack_pointer(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();

        let mut register_name = String::new();
        let mut stack_growth = true; // Default stack growth is in negative direction
        let mut is_reverse_justify = false;
        let mut basespace: Option<crate::space::AddressSpace> = None;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("reversejustify") => is_reverse_justify = decoder.read_bool(),
                Some("growth") => stack_growth = decoder.read_string() == "negative",
                Some("space") => {
                    let space_name = decoder.read_string();
                    basespace = Some(
                        host.space_by_name(&space_name)
                            .ok_or_else(|| format!("Undefined space: {}", space_name))?,
                    );
                }
                Some("register") => register_name = decoder.read_string(),
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }

        let Some(base) = basespace else {
            // ELEM_STACKPOINTER.getName() + " element missing \"space\"
            // attribute" (architecture.cc:1002) — the element name is the
            // bare "stackpointer", without angle brackets.
            return Err("stackpointer element missing \"space\" attribute".to_string());
        };

        let point = host
            .get_register(&register_name)
            .ok_or_else(|| format!("Unknown register name: {}", register_name))?;
        decoder.close_element(elem_id);

        // cc:1007-1011: If creating a stackpointer to a truncated space,
        // make sure to truncate the stackpointer.
        //   int4 truncSize = point.size;
        //   if (basespace->isTruncated() && (point.size > basespace->getAddrSize()))
        //     truncSize = basespace->getAddrSize();
        let base_addr_size = self.space_addr_size(base);
        let trunc_size = if self.space_is_truncated(base) && (point.size as u32) > base_addr_size
        {
            base_addr_size as usize
        } else {
            point.size as usize
        };

        // addSpacebase(basespace,"stack",point,truncSize,
        //              isreversejustify,stackGrowth,true)
        // (architecture.cc:1013 → 559-570) — SpacebaseSpace(basespace,...)
        // installs basespace as the stack space's contain link, then
        // addSpacebasePointer → SpacebaseSpace::setBaseRegister
        // (translate.cc:86-102): `baseOrig` keeps the ORIGINAL register;
        // `baseloc` takes `truncSize` and, when the register's space is
        // big-endian, shifts its offset up by the truncated-away bytes
        // (translate.cc:97-100). The enum register space is little-endian,
        // so the shift arm is dormant on every representable enum-model
        // corpus (the formula stays for alignment).
        self.stack_space = crate::space::AddressSpace::Stack;
        self.stack_pointer_full_space = point.space;
        self.stack_pointer_full_offset = point.offset;
        self.stack_pointer_full_size = point.size as usize;
        let mut baseloc_offset = point.offset;
        if trunc_size != point.size as usize && point.space.is_big_endian() {
            // baseloc.offset += (baseloc.size - truncSize);
            baseloc_offset += (point.size as usize - trunc_size) as u64;
        }
        self.stack_pointer_space = point.space;
        self.stack_pointer_offset = baseloc_offset;
        self.stack_pointer_size = trunc_size;
        self.stack_base_space = base;
        self.stack_grows_negative = stack_growth;
        self.stack_reverse_justify = is_reverse_justify;
        Ok(())
    }

    // Ghidra: translate.cc:776 AddrSpaceManager::truncateSpace
    /// Mark the named space as truncated from its original size. Faithful
    /// to the manager wrapper `AddrSpaceManager::truncateSpace`
    /// (translate.cc:776-783): the name must resolve to a known space
    /// (`getSpaceByName`, translate.cc:590-597 — the enum model resolves
    /// the locked spec names through
    /// [`crate::space::AddressSpace::from_spec_name`]), otherwise the
    /// oracle `LowlevelError` text is returned; a resolved name records
    /// the truncation that `AddrSpace::truncateSpace` (space.cc:105-112)
    /// would apply to the space record (TRUNCATED flag, addressSize and
    /// minimumPointerSize = newsize, calcScaleMask). In the oracle this
    /// runs from `SleighArchitecture::modifySpaces`
    /// (sleigh_arch.cc:423-430) over the `.ldefs` `<truncate_space>`
    /// records (sleigh_arch.cc:86-89); the x86-64:LE:64 production
    /// language defines none, so the locked corpus stays untruncated.
    /// Re-truncating the same space overwrites the effective size (the
    /// oracle re-runs `AddrSpace::truncateSpace` on the same record).
    pub fn truncate_space(&mut self, space_name: &str, newsize: u32) -> Result<(), String> {
        let spc = crate::space::AddressSpace::from_spec_name(space_name);
        if spc.is_none() {
            return Err(format!(
                "Unknown space in <truncate_space> command: {}",
                space_name
            ));
        }
        // Store under the enum's canonical name so the is_truncated /
        // addr_size queries round-trip (the "OTHER" spec name canonicalizes
        // to the enum's lowercase debug form).
        let canonical = spc.map(|s| s.name().to_string()).unwrap();
        self.space_truncations.retain(|(n, _)| *n != canonical);
        self.space_truncations.push((canonical, newsize));
        Ok(())
    }

    // Ghidra: space.hh:462 AddrSpace::isTruncated
    /// Return true if this space is truncated from its original size.
    /// Enum-model projection of the TRUNCATED flag set by
    /// `AddrSpace::truncateSpace` (space.cc:105-112): a space is truncated
    /// exactly when a `<truncate_space>` command naming it was applied
    /// through [`Self::truncate_space`].
    pub fn space_is_truncated(&self, spc: crate::space::AddressSpace) -> bool {
        self.space_truncations
            .iter()
            .any(|(name, _)| *name == spc.name())
    }

    // Ghidra: space.hh:348 AddrSpace::getAddrSize
    /// Get the address size of this space in bytes, honoring truncation.
    /// Faithful to a post-`truncateSpace` read of `getAddrSize`: the
    /// truncated size when a `<truncate_space>` command named this space,
    /// otherwise the enum model's inherent size ([`Self::addr_size`] over
    /// the locked constructors).
    pub fn space_addr_size(&self, spc: crate::space::AddressSpace) -> u32 {
        match self
            .space_truncations
            .iter()
            .rev()
            .find(|(name, _)| *name == spc.name())
        {
            Some((_, truncated_size)) => *truncated_size,
            None => spc.addr_size() as u32,
        }
    }

    // Ghidra: translate.hh:505 AddrSpaceManager::getDefaultCodeSpace
    /// Get the default address space of this processor. Enum-model
    /// projection of the `defaultcodespace` quick reference
    /// (translate.hh:226): the driver's locked x86-64 production code
    /// space `ram`.
    pub fn get_default_code_space(&self) -> crate::space::AddressSpace {
        self.default_code_space
    }

    // Ghidra: translate.cc:104 SpacebaseSpace::numSpacebase
    /// Number of base registers associated with the formal stack space.
    /// The stack spacebase is always assigned: the constructor defaults
    /// project the x86-64 RSP that the cspec `<stackpointer>` decode
    /// (`decodeStackPointer` → `addSpacebase` → `setBaseRegister`,
    /// architecture.cc:1013 → translate.cc:86-102) installs, so — like the
    /// oracle after `decodeStackPointer` — `hasbaseregister` is set and
    /// the count is 1.
    pub fn stack_space_num_spacebase(&self) -> i32 {
        1
    }

    // Ghidra: translate.cc:110 SpacebaseSpace::getSpacebase
    /// Get the (possibly truncated) stack-pointer base register —
    /// `baseloc`. Faithful to `getSpacebase(int4 i)`
    /// (translate.cc:110-116): `None` stands in for the
    /// "No base register specified" `LowlevelError` on `i != 0`.
    pub fn stack_space_get_spacebase(
        &self,
        i: i32,
    ) -> Option<(crate::space::AddressSpace, u64, usize)> {
        if i != 0 {
            return None;
        }
        Some((
            self.stack_pointer_space,
            self.stack_pointer_offset,
            self.stack_pointer_size,
        ))
    }

    // Ghidra: translate.cc:118 SpacebaseSpace::getSpacebaseFull
    /// Get the original (pre-truncation) stack-pointer base register —
    /// `baseOrig` (translate.hh:178). Faithful to `getSpacebaseFull(int4
    /// i)` (translate.cc:118-124); `None` on `i != 0` as above.
    pub fn stack_space_get_spacebase_full(
        &self,
        i: i32,
    ) -> Option<(crate::space::AddressSpace, u64, usize)> {
        if i != 0 {
            return None;
        }
        Some((
            self.stack_pointer_full_space,
            self.stack_pointer_full_offset,
            self.stack_pointer_full_size,
        ))
    }

    // Ghidra: architecture.cc:769 Architecture::decodeProtoEval
    /// Decode the `<eval_called_prototype>`/`<eval_current_prototype>`
    /// elements.  Faithful to `decodeProtoEval` (architecture.cc:769-789):
    /// the named model must already exist and each tag may appear only
    /// once.
    pub fn decode_proto_eval(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder};
        let elem_id = decoder.open_element();
        let model_name = decoder.read_string_attr(&AttributeId::new("name", 0));
        let model = self
            .proto_models
            .get(&model_name)
            .cloned()
            .ok_or_else(|| format!("Unknown prototype model name: {}", model_name))?;

        if decoder.element_name(elem_id).as_deref() == Some("eval_called_prototype") {
            if self.evalfp_called.is_some() {
                return Err("Duplicate <eval_called_prototype> tag".to_string());
            }
            self.evalfp_called = Some(model.clone());
            self.evalfp_called_name = Some(model_name);
        } else {
            if self.evalfp_current.is_some() {
                return Err("Duplicate <eval_current_prototype> tag".to_string());
            }
            self.evalfp_current = Some(model.clone());
            self.evalfp_current_name = Some(model_name);
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:1086 Architecture::decodeNoHighPtr
    /// Configure memory based on a `<nohighptr>` element.  Mark specific
    /// address ranges to indicate the decompiler will not encounter
    /// pointers (aliases) into the range.  Faithful to `decodeNoHighPtr`
    /// (architecture.cc:1086-1096) with the range resolved through the
    /// same `Range(RangeProperties)` constructor.
    pub fn decode_no_high_ptr(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        while decoder.peek_element() != 0 {
            // Iterate over every range tag in the list
            let mut props = RangeProperties::new();
            RangeProperties::decode(&mut props, decoder).map_err(|e| e.to_string())?;
            let (spc, first, last) = Self::range_from_properties(&props, host)?;
            let _ = spc;
            let rng = Range::new(crate::Address::new(first), crate::Address::new(last))
                .ok_or_else(|| "Illegal range tag".to_string())?;
            self.add_no_high_ptr(rng);
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:1101 Architecture::decodePreferSplit
    /// Configure registers based on a `<prefersplit>` element.  Faithful
    /// to `decodePreferSplit` (architecture.cc:1101-1116): only the
    /// `inhalf` style is legal and each record's split offset is half its
    /// storage size.
    pub fn decode_prefer_split(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        host: &dyn SpecQuery,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder};
        let elem_id = decoder.open_element();
        let style = decoder.read_string_attr(&AttributeId::new("style", 0));
        if style != "inhalf" {
            return Err(format!("Unknown prefersplit style: {}", style));
        }

        while decoder.peek_element() != 0 {
            let child = decoder.open_element();
            let mut register_name: Option<String> = None;
            let mut space = crate::space::AddressSpace::Register;
            let mut offset = 0u64;
            let mut size = 0i32;
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match decoder.attribute_name(attrib_id).as_deref() {
                    Some("space") => {
                        let space_name = decoder.read_string();
                        space = host
                            .space_by_name(&space_name)
                            .ok_or_else(|| format!("Undefined space: {}", space_name))?;
                    }
                    Some("offset") => offset = decoder.read_unsigned_integer(),
                    Some("size") => size = decoder.read_unsigned_integer() as i32,
                    Some("name") => register_name = Some(decoder.read_string()),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            decoder.close_element(child);
            if let Some(name) = register_name {
                let point = host
                    .get_register(&name)
                    .ok_or_else(|| format!("Unknown register name: {}", name))?;
                self.split_records.push(crate::prefersplit::PreferSplitRecord::new(
                    point.offset,
                    point.space,
                    point.size as u32,
                    point.size / 2,
                ));
            } else {
                self.split_records.push(crate::prefersplit::PreferSplitRecord::new(
                    offset,
                    space,
                    size as u32,
                    size / 2,
                ));
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:1121 Architecture::decodeAggressiveTrim
    /// Configure, based on the `<aggressivetrim>` element, how aggressively
    /// the decompiler will remove extension operations.  Faithful to
    /// `decodeAggressiveTrim` (architecture.cc:1121-1133).
    pub fn decode_aggressive_trim(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        let elem_id = decoder.open_element();
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            if decoder.attribute_name(attrib_id).as_deref() == Some("signext") {
                self.aggressive_ext_trim = decoder.read_bool();
            } else {
                let _ = decoder.read_string();
            }
        }
        decoder.close_element(elem_id);
        Ok(())
    }

    // Ghidra: architecture.cc:1138 Architecture::createModelAlias
    /// Create a value-copy alias for a ProtoModel with Ghidra's exact error
    /// strings: missing parent (`Requesting non-existent prototype model`),
    /// merged parent (`Cannot make alias of merged model`), alias-of-alias
    /// (`Cannot make alias of an alias`) and duplicate name (`Duplicate
    /// ProtoModel name`).  The merged-model check is structurally
    /// unreachable until `<resolveprototype>`/ProtoModelMerged decode lands
    /// (CSPEC-PARAMMODEL-0001); the alias-of-alias check reads the copy's
    /// `compat_model` marker.
    pub fn create_model_alias_exact(
        &mut self,
        alias_name: &str,
        parent_name: &str,
    ) -> Result<(), String> {
        let Some(parent) = self.proto_models.get(parent_name) else {
            return Err(format!(
                "Requesting non-existent prototype model: {}",
                parent_name
            ));
        };
        // Ghidra: model->isMerged() — no merged model can exist before the
        // resolveprototype decode chain lands.
        if parent.get_alias_parent_marker().is_some() {
            return Err(format!("Cannot make alias of an alias: {}", parent_name));
        }
        if self.proto_models.contains_key(alias_name) {
            return Err(format!("Duplicate ProtoModel name: {}", alias_name));
        }
        let mut model = parent.as_ref().clone();
        model.name = alias_name.to_string();
        // The alias copy constructor sets compatModel to the parent
        // (fspec.cc:2359-2377); Rugra marks the copy via `compat_model`
        // (only Some/None is observable; the numeric value is a marker).
        model.set_alias_parent_marker();
        model.set_print_in_decl(true);
        self.proto_models
            .insert(alias_name.to_string(), Arc::new(model));
        Ok(())
    }

    // Ghidra: architecture.cc:1239 Architecture::parseCompilerConfig
    /// Look for the `<compiler_spec>` tag and set configuration parameters
    /// based on it.  Faithful port of `parseCompilerConfig`
    /// (architecture.cc:1239-1351):
    ///
    /// - `<global>` children are collected as partial `RangeProperties`
    ///   and only applied after the main and `specextensions` loops finish
    ///   (they need to know about all spaces);
    /// - `<callfixup>` children go through the injection library's
    ///   `decodeInject` chain (allocate → decode → register/compile);
    /// - `<callotherfixup>`/`<segmentop>` children go through the userop
    ///   manager decode chain;
    /// - after the loops: deferred global application, `addOtherSpace`,
    ///   default-model fallback (first model in map order), the
    ///   `__thiscall` alias clone, and the type-factory `setupSizes` step.
    ///
    /// Children whose full decode belongs to other domains
    /// (`data_organization`/`enum` → CSPEC-TYPEORG-STATE-0001,
    /// `spacebase`/`deadcodedelay`/`inferptrbounds` → space-manager wiring,
    /// `readonly` → Database property ranges, `context_data` → context spec
    /// decode, `resolveprototype` → CSPEC-PARAMMODEL-0001) are recorded in
    /// the returned report rather than silently dropped; children Ghidra's
    /// own dispatch ignores (unknown tags) are noted as oracle-ignored.
    pub fn parse_compiler_config(
        &mut self,
        store: &mut crate::marshal::DocumentStorage,
        host: &dyn SpecQuery,
        addr_size: usize,
    ) -> Result<CompilerConfigReport, String> {
        let mut report = CompilerConfigReport::default();
        let mut global_ranges: Vec<RangeProperties> = Vec::new();
        let root = store
            .get_tag("compiler_spec")
            .cloned()
            .ok_or_else(|| "No compiler configuration tag found".to_string())?;
        let registry = Arc::new(std::sync::RwLock::new(crate::marshal::IdRegistry::new()));
        let children: Vec<_> = root.read().expect("element lock poisoned").children.clone();
        let register_resolver = |name: &str| host.get_register(name);
        for child in children {
            let child_name = child
                .read()
                .expect("element lock poisoned")
                .name
                .clone();
            let body_content = find_body_content(&child);
            let mut decoder = crate::marshal::TreeDecoder::new(child, registry.clone());
            match child_name.as_str() {
                "default_proto" => {
                    self.decode_default_proto_spec(&mut decoder, addr_size, &register_resolver)?;
                }
                "prototype" => {
                    self.decode_proto_spec(&mut decoder, addr_size, &register_resolver)?;
                }
                "stackpointer" => {
                    self.decode_stack_pointer(&mut decoder, host)?;
                }
                "returnaddress" => {
                    self.decode_return_address(&mut decoder, host)?;
                }
                "spacebase" => {
                    report.skipped_children.push((
                        "spacebase".to_string(),
                        "SPACE domain: dynamic spacebase space creation (architecture.cc:1071)"
                            .to_string(),
                    ));
                }
                "nohighptr" => {
                    self.decode_no_high_ptr(&mut decoder, host)?;
                }
                "prefersplit" => {
                    self.decode_prefer_split(&mut decoder, host)?;
                }
                "aggressivetrim" => {
                    self.decode_aggressive_trim(&mut decoder)?;
                }
                "data_organization" => {
                    // Ghidra architecture.cc:1268-1269:
                    //   else if (subId == ELEM_DATA_ORGANIZATION)
                    //     types->decodeDataOrganization(decoder);
                    // The factory exists for the whole parse (Architecture::init
                    // builds it before parseCompilerConfig, architecture.cc:1391);
                    // Rugra's `types` is optional, so the canonical factory is
                    // installed lazily here (TYPE-WIRING-0001). This is what
                    // populates sizeOfInt/Long/Pointer/Char/WChar and the
                    // alignment map that `TypeFactory::getBase`'s findAdd
                    // requires — without it every downChain/get_type_pointer
                    // interning path panics with the uninitialized-alignment-map
                    // LowlevelError.
                    let types = self.ensure_types();
                    types
                        .write()
                        .expect("type factory lock poisoned")
                        .decode_data_organization(&mut decoder);
                }
                "enum" => {
                    report.skipped_children.push(("enum".to_string(), "CSPEC-TYPEORG-STATE-0001".to_string()));
                }
                "global" => {
                    Self::decode_global(&mut decoder, &mut global_ranges)?;
                }
                "segmentop" => {
                    self.ensure_userops();
                    self.ensure_pcodeinjectlib(host.unique_inject_base());
                    let space_by_name = |nm: &str| host.space_by_name(nm);
                    let get_register = |nm: &str| host.get_register(nm);
                    let inject_arc = self.pcodeinjectlib.as_ref().expect("just ensured").clone();
                    let userops_arc = self.userops.as_ref().expect("just ensured").clone();
                    let mut inject_lib = inject_arc.write().expect("lock poisoned");
                    let mut userops = userops_arc.write().expect("lock poisoned");
                    userops
                        .decode_segment_op(
                            &mut decoder,
                            &mut inject_lib,
                            &space_by_name,
                            &get_register,
                            body_content.as_deref(),
                        )?;
                }
                "readonly" => {
                    report.skipped_children.push((
                        "readonly".to_string(),
                        "DB property ranges: symboltab->setPropertyRange (architecture.cc:867)"
                            .to_string(),
                    ));
                }
                "context_data" => {
                    // Ghidra: architecture.cc:1278-1279 — both
                    // parseProcessorConfig (:1190) and parseCompilerConfig
                    // (:1278) route `<context_data>` to the same
                    // ContextDatabase::decodeFromSpec call.
                    self.decode_context_data(&mut decoder, host)?;
                }
                "resolveprototype" => {
                    report.skipped_children.push((
                        "resolveprototype".to_string(),
                        "CSPEC-PARAMMODEL-0001: ProtoModelMerged decode".to_string(),
                    ));
                }
                "eval_called_prototype" | "eval_current_prototype" => {
                    self.decode_proto_eval(&mut decoder)?;
                }
                "callfixup" => {
                    self.ensure_pcodeinjectlib(host.unique_inject_base());
                    let inject_arc = self.pcodeinjectlib.as_ref().expect("just ensured").clone();
                    let mut inject_lib = inject_arc.write().expect("lock poisoned");
                    let source = format!("{} : compiler spec", self.archid);
                    inject_lib.decode_inject(
                        &source,
                        "",
                        crate::pcodeinject::InjectPayloadType::CallFixup,
                        &mut decoder,
                        body_content.as_deref(),
                    )?;
                }
                "callotherfixup" => {
                    self.ensure_userops();
                    self.ensure_pcodeinjectlib(host.unique_inject_base());
                    let inject_arc = self.pcodeinjectlib.as_ref().expect("just ensured").clone();
                    let userops_arc = self.userops.as_ref().expect("just ensured").clone();
                    let mut inject_lib = inject_arc.write().expect("lock poisoned");
                    let mut userops = userops_arc.write().expect("lock poisoned");
                    userops.decode_call_other_fixup(
                        &mut decoder,
                        &mut inject_lib,
                        body_content.as_deref(),
                    )?;
                }
                "funcptr" => {
                    self.decode_funcptr_align(&mut decoder)?;
                }
                "deadcodedelay" => {
                    report.skipped_children.push((
                        "deadcodedelay".to_string(),
                        "SPACE domain: setDeadcodeDelay per-space state (architecture.cc:1019)"
                            .to_string(),
                    ));
                }
                "inferptrbounds" => {
                    report.skipped_children.push((
                        "inferptrbounds".to_string(),
                        "SPACE domain: setInferPtrBounds per-space bounds (architecture.cc:1033)"
                            .to_string(),
                    ));
                }
                "modelalias" => {
                    use crate::marshal::{AttributeId, Decoder};
                    let elem_id = decoder.open_element();
                    let alias_name = decoder.read_string_attr(&AttributeId::new("name", 0));
                    let parent_name = decoder.read_string_attr(&AttributeId::new("parent", 0));
                    decoder.close_element(elem_id);
                    self.create_model_alias_exact(&alias_name, &parent_name)?;
                }
                other => {
                    // Ghidra's compiler_spec dispatch has no else branch:
                    // unknown children are ignored by the oracle itself.
                    report
                        .ignored_children
                        .push(format!("{}", other));
                }
            }
        }

        // specextensions: look for any user-defined configuration document
        // (architecture.cc:1308-1327).
        if let Some(ext_root) = store.get_tag("specextensions").cloned() {
            let ext_children: Vec<_> = ext_root
                .read()
                .expect("element lock poisoned")
                .children
                .clone();
            for child in ext_children {
                let child_name = child
                    .read()
                    .expect("element lock poisoned")
                    .name
                    .clone();
                let body_content = find_body_content(&child);
                let mut decoder = crate::marshal::TreeDecoder::new(child, registry.clone());
                match child_name.as_str() {
                    "prototype" => {
                        self.decode_proto_spec(&mut decoder, addr_size, &register_resolver)?;
                    }
                    "callfixup" => {
                        self.ensure_pcodeinjectlib(host.unique_inject_base());
                        let inject_arc =
                            self.pcodeinjectlib.as_ref().expect("just ensured").clone();
                        let mut inject_lib = inject_arc.write().expect("lock poisoned");
                        let source = format!("{} : compiler spec", self.archid);
                        inject_lib.decode_inject(
                            &source,
                            "",
                            crate::pcodeinject::InjectPayloadType::CallFixup,
                            &mut decoder,
                            body_content.as_deref(),
                        )?;
                    }
                    "callotherfixup" => {
                        self.ensure_userops();
                        self.ensure_pcodeinjectlib(host.unique_inject_base());
                        let inject_arc =
                            self.pcodeinjectlib.as_ref().expect("just ensured").clone();
                        let userops_arc =
                            self.userops.as_ref().expect("just ensured").clone();
                        let mut inject_lib = inject_arc.write().expect("lock poisoned");
                        let mut userops = userops_arc.write().expect("lock poisoned");
                        userops.decode_call_other_fixup(
                            &mut decoder,
                            &mut inject_lib,
                            body_content.as_deref(),
                        )?;
                    }
                    "global" => {
                        Self::decode_global(&mut decoder, &mut global_ranges)?;
                    }
                    other => {
                        // Ghidra's specextensions dispatch has no else
                        // branch either.
                        report.ignored_children.push(format!("{}", other));
                    }
                }
            }
        }

        // <global> tags instantiate the base symbol table.  They need to
        // know about all spaces, so it must come after parsing of
        // <stackpointer> and <spacebase> (architecture.cc:1329-1333).
        for props in &global_ranges {
            self.add_to_global_scope(props, host)?;
        }

        self.add_other_space(host)?;

        if self.defaultfp.is_none() {
            if !self.proto_models.is_empty() {
                let first_name = self
                    .proto_models
                    .iter()
                    .next()
                    .map(|(k, _)| k.clone())
                    .expect("map non-empty");
                self.set_default_model(&first_name);
            } else {
                return Err("No default prototype specified".to_string());
            }
        }
        // We must have a __thiscall calling convention
        // (architecture.cc:1343-1347).
        if !self.proto_models.contains_key("__thiscall") {
            // If __thiscall doesn't exist we clone it off of the default
            let parent = self
                .defaultfp
                .as_ref()
                .map(|m| m.get_name().to_string())
                .ok_or_else(|| "No default prototype specified".to_string())?;
            self.create_model_alias_exact("__thiscall", &parent)?;
        }
        // initializeSegments (architecture.cc:648-658): registers
        // SegmentedResolver objects for each segment op — resolver
        // insertion requires the AddrSpaceManager resolver store.
        if self
            .userops
            .as_ref()
            .map(|u| !u.read().expect("lock poisoned").segment_ops.is_empty())
            .unwrap_or(false)
        {
            report.post_step_residuals.push(
                "initializeSegments: SegmentedResolver insertion needs the AddrSpaceManager resolver store"
                    .to_string(),
            );
        }
        // PreferSplitManager::initialize(splitrecords) installs the global
        // prefer-split map (prefersplit.cc); Rugra's PreferSplitManager is
        // per-Funcdata, so the global install step is a residual.
        if !self.split_records.is_empty() {
            report.post_step_residuals.push(
                "PreferSplitManager::initialize: global install not yet represented".to_string(),
            );
        }
        // types->setupSizes() (architecture.cc:1350): if no
        // data_organization was registered, set up default values. Ghidra's
        // setupSizes reads the Architecture for the stack spacebase size,
        // default data space address size, and default size; Rugra threads
        // the same values from the compiler-spec address size (x86-64: the
        // ram default data space and the RSP stack spacebase are both
        // addr_size wide; there is no far-pointer segment op in the locked
        // cspec, so far_pointer stays None).
        {
            let types = self.ensure_types();
            types
                .write()
                .expect("type factory lock poisoned")
                .setup_sizes(&crate::type_system::typefactory::SizeArchInputs {
                    stack_spacebase_size: Some(addr_size as i32),
                    default_data_space_addr_size: addr_size as i32,
                    default_size: addr_size as i32,
                    far_pointer: None,
                });
        }
        Ok(report)
    }

    // RUGRA-GLUE: ensure_userops (Ghidra's userops member always exists)
    /// Install an empty userop manager if none is attached, mirroring the
    /// always-present `Architecture::userops` member (userops.initialize
    /// runs earlier in restoreFromSpec, architecture.cc:635).
    fn ensure_userops(&mut self) {
        if self.userops.is_none() {
            self.userops = Some(std::sync::Arc::new(std::sync::RwLock::new(
                crate::userop::UserOpManage::new(),
            )));
        }
    }

    // RUGRA-GLUE: ensure_pcodeinjectlib (Ghidra's buildPcodeInjectLibrary)
    /// Install a fresh injection library with the given unique base if
    /// none is attached, mirroring `buildPcodeInjectLibrary` +
    /// `PcodeInjectLibrarySleigh(g)` (architecture.cc:638,
    /// inject_sleigh.cc:343-348).  The SLEIGH symbol lookup (`slgh`) must
    /// be installed by the owner for snippet compilation.
    fn ensure_pcodeinjectlib(&mut self, unique_inject_base: u64) {
        if self.pcodeinjectlib.is_none() {
            self.pcodeinjectlib = Some(std::sync::Arc::new(std::sync::RwLock::new(
                crate::pcodeinject::PcodeInjectLibrary::new(unique_inject_base),
            )));
        }
    }

    // Ghidra: architecture.cc:1049 Architecture::decodeFuncPtrAlign
    /// Pull information from a `<funcptr>` element: turn on alignment
    /// analysis of function pointers.  Faithful to `decodeFuncPtrAlign`
    /// (architecture.cc:1049-1066): alignment 0 clears the field, otherwise
    /// the field holds the position of the first 1 bit.
    pub fn decode_funcptr_align(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<(), String> {
        use crate::marshal::{AttributeId, Decoder};
        let elem_id = decoder.open_element();
        let mut align = decoder.read_signed_integer_attr(&AttributeId::new("align", 0)) as i64;
        decoder.close_element(elem_id);

        if align == 0 {
            self.funcptr_align = 0; // No alignment
            return Ok(());
        }
        let mut bits = 0i32;
        while (align & 1) == 0 {
            // Find position of first 1 bit
            bits += 1;
            align >>= 1;
        }
        self.funcptr_align = bits;
        Ok(())
    }

    // RUGRA-GLUE: high_ptr_possible (no Ghidra counterpart found)
    /// Are pointers possible to the given location? Faithful to
    /// `highPtrPossible` (architecture.hh:408). Without AddrSpace type info we
    /// conservatively check the nohighptr range list.
    pub fn high_ptr_possible(&self, loc: crate::Address, size: i32) -> bool {
        // inRange checks the whole span; Ghidra checks !nohighptr.inRange(loc, size).
        // Our RangeList::in_range takes a single address, so we check both ends.
        if self.nohighptr.in_range(loc) {
            return false;
        }
        if size > 1 {
            let end = crate::Address::new(loc.as_u64().saturating_add(size as u64 - 1));
            if self.nohighptr.in_range(end) {
                return false;
            }
        }
        true
    }

    // RUGRA-GLUE: add_no_high_ptr (no Ghidra counterpart found)
    /// Add a new region where pointers do not exist. Faithful to `addNoHighPtr`
    /// (architecture.cc:576).
    pub fn add_no_high_ptr(&mut self, rng: Range) {
        self.nohighptr.insert_range(rng);
    }

    // RUGRA-GLUE: globalify (no Ghidra counterpart found)
    /// Mark all spaces as global. Faithful to `globalify` (architecture.cc:437).
    /// Without AddrSpaceManager, this is a no-op placeholder; the global flag is
    /// a property of spaces owned externally.
    pub fn globalify(&mut self) {
        // L3 gap: requires AddrSpaceManager integration.
    }

    // Ghidra: architecture.cc:1138 Architecture::createModelAlias
    /// Create a value-copy alias for a ProtoModel.  Payload and independent
    /// print state follow the Ghidra alias copy constructor; the existing
    /// boolean API cannot represent Ghidra's merged/alias-parent exception
    /// domain, which remains outside the verified default-model slice.
    pub fn create_model_alias(&mut self, alias_name: &str, parent_name: &str) -> bool {
        if let Some(parent) = self.proto_models.get(parent_name) {
            if self.proto_models.contains_key(alias_name) {
                return false;
            }
            let mut model = parent.as_ref().clone();
            model.name = alias_name.to_string();
            model.set_print_in_decl(true);
            self.proto_models
                .insert(alias_name.to_string(), Arc::new(model));
            true
        } else {
            false
        }
    }

    // RUGRA-GLUE: decode_flow_override (no Ghidra counterpart found)
    /// Decode flow overrides from a stream. Faithful to
    /// `decodeFlowOverride` (architecture.hh:239). The actual XML parse is an
    /// L3 gap; this is the application entry point.
    pub fn decode_flow_override(&mut self) {
        // L3 gap: XML decode of <flowoverridelist>.
    }

    // RUGRA-GLUE: get_description (no Ghidra counterpart found)
    /// Get a string describing this architecture. Faithful to
    /// `getDescription` (architecture.hh:244).
    pub fn get_description(&self) -> &str {
        &self.archid
    }

    // Ghidra: sleigh_arch.hh:138 SleighArchitecture::printMessage
    /// Print an error message to console. Faithful to `printMessage`
    /// (architecture.hh:250). Default implementation prints to stderr.
    pub fn print_message(&self, message: &str) {
        eprintln!("{message}");
    }

    // RUGRA-GLUE: init (no Ghidra counterpart found)
    /// Load the image and configure architecture. Faithful to
    /// `Architecture::init` (architecture.hh:221). This method orchestrates
    /// the initialization by calling the virtual factory hooks.
    pub fn init(&mut self) -> Result<(), String> {
        // In full Ghidra, this calls the virtual factory methods:
        //   buildLoader(store)
        //   fillinReadOnlyFromLoader()
        //   buildTypegrp(store)
        //   buildCoreTypes(store)
        //   buildCommentDB(store)
        //   buildStringManager(store)
        //   buildConstantPool(store)
        //   buildContext(store)
        //   buildInstructions(store)
        //   buildAction(store)
        //   postSpecFile()
        //
        // In Rugra, sub-components are set externally via set_* methods,
        // with buildStringManager now wired for real (architecture.cc:1401
        // ordering: the loader, installed by buildLoader, precedes it).
        // This method verifies that essential components are present.
        if self.archid.is_empty() {
            return Err("Architecture ID not set".to_string());
        }
        self.build_string_manager();
        Ok(())
    }

    // RUGRA-GLUE: clear_analysis (no Ghidra counterpart found)
    /// Clear analysis specific to a function. Faithful to `clearAnalysis`
    /// (architecture.hh:232).
    pub fn clear_analysis(&self) {
        // Full: fd.clear() + commentdb.clearType. Requires Funcdata.
    }

    // RUGRA-GLUE: read_loader_symbols (no Ghidra counterpart found)
    /// Read symbols from loader into database. Faithful to
    /// `readLoaderSymbols` (architecture.hh:233).
    pub fn read_loader_symbols(&mut self, _delim: &str) {
        if self.loadersymbols_parsed {
            return;
        }
        // Full: iterate loader symbols and insert into database.
        self.loadersymbols_parsed = true;
    }

    // RUGRA-GLUE: encode (no Ghidra counterpart found)
    /// Encode this architecture to a stream. Faithful to
    /// `Architecture::encode` (architecture.hh:251).
    pub fn encode(&self, encoder: &mut dyn crate::marshal::Encoder) {
        use crate::marshal::{AttributeId, ElementId};
        let arch_elem = ElementId::new("architecture", 0);
        encoder.open_element(&arch_elem);
        encoder.write_string(&AttributeId::new("id", 0), &self.archid);
        // Encode sub-components as needed.
        encoder.close_element(&arch_elem);
    }

    // ---- Sub-component setters (virtual factory hook equivalents) ----

    // RUGRA-GLUE: set_symboltab (no Ghidra counterpart found)
    /// Set the symbol table (Database). Replaces `buildDatabase`.
    pub fn set_symboltab(&mut self, db: std::sync::Arc<std::sync::RwLock<crate::database::Database>>) {
        self.symboltab = Some(db);
    }

    // RUGRA-GLUE: set_loader (no Ghidra counterpart found)
    /// Set the load image. Replaces `buildLoader`.
    pub fn set_loader(&mut self, loader: std::sync::Arc<dyn crate::loadimage::LoadImage>) {
        self.loader = Some(loader);
    }

    // RUGRA-GLUE: set_commentdb (no Ghidra counterpart found)
    /// Set the comment database. Replaces `buildCommentDB`.
    pub fn set_commentdb(&mut self, db: std::sync::Arc<std::sync::RwLock<crate::comment::CommentDatabaseInternal>>) {
        self.commentdb = Some(db);
    }

    // RUGRA-GLUE: set_string_manager (test/driver injection point; Ghidra
    // only assigns `stringManager` from its own buildStringManager factory,
    // architecture.cc:1401 — Rugra keeps the external setter for pre-seeded
    // test managers and until the driver pipeline owns the loader lifecycle)
    /// Set the string manager. Replaces `buildStringManager` injection.
    pub fn set_string_manager(&mut self, sm: std::sync::Arc<std::sync::RwLock<crate::stringmanage::StringManager>>) {
        self.string_manager = Some(sm);
    }

    // Ghidra: architecture.hh:308 Architecture::buildStringManager
    /// Build the Architecture-owned string manager singleton. Faithful to
    /// the virtual factory hook (architecture.hh:308) invoked from
    /// `Architecture::init` (architecture.cc:1401) and overridden at
    /// ghidra_arch.cc:365-369 as `stringManager = new GhidraStringManager(this,2048)`.
    ///
    /// Declared detection contract (JAVA CONTRACT, B4): Rugra's production
    /// manager implements the `GhidraStringManager`/Java behavior — charset
    /// validity plus NUL termination with **no 2048 search bound**, with
    /// `maximumChars=2048` truncating only the returned bytes and setting
    /// `isTruncated` (the golden corpus `tests/golden/ghidra_curl_1204.c`
    /// proves the oracle walked this path). The 1:1 native
    /// `StringManagerUnicode` (sleigh_arch.cc:247-251, 2048-byte search
    /// clamp) remains available via
    /// [`crate::stringmanage::StringManager::new_unicode`]. The manager
    /// reads through this Architecture's `loader` (the LoadImage channel,
    /// loadimage.hh:80), so the loader must be attached first — matching
    /// Ghidra's init order (buildLoader precedes buildStringManager,
    /// architecture.cc:1390-1401). With no loader the manager degrades to
    /// cache-only queries.
    pub fn build_string_manager(&mut self) {
        let manager = match &self.loader {
            Some(loader) => crate::stringmanage::StringManager::new_ghidra_contract(
                loader.clone(),
                2048,
            ),
            None => crate::stringmanage::StringManager::new(2048),
        };
        self.string_manager = Some(std::sync::Arc::new(std::sync::RwLock::new(manager)));
    }

    // RUGRA-GLUE: set_cpool (no Ghidra counterpart found)
    /// Set the constant pool. Replaces `buildConstantPool`.
    pub fn set_cpool(&mut self, cp: std::sync::Arc<std::sync::RwLock<crate::cpool::ConstantPoolInternal>>) {
        self.cpool = Some(cp);
    }

    // RUGRA-GLUE: set_context_db (no Ghidra counterpart found)
    /// Set the context database. Replaces `buildContext`.
    pub fn set_context_db(&mut self, ctx: std::sync::Arc<std::sync::RwLock<crate::context::ContextInternal>>) {
        self.context_db = Some(ctx);
    }

    // RUGRA-GLUE: set_options_db (no Ghidra counterpart found)
    /// Set the options database. Replaces the OptionDatabase constructor.
    pub fn set_options_db(&mut self, opts: std::sync::Arc<std::sync::RwLock<crate::options::OptionDatabase>>) {
        self.options_db = Some(opts);
    }

    // RUGRA-GLUE: set_types (no Ghidra counterpart found)
    /// Set the TypeFactory instance. Replaces `buildTypegrp`.
    ///
    /// TF-SINGLETON-WIRING-0001 step 1: this is the Rugra moment the
    /// oracle's `SleighArchitecture::buildTypegrp` installs the factory
    /// into the Architecture (`types = new TypeFactory(this);`,
    /// sleigh_arch.cc:201; TypeFactoryGhidra twin ghidra_arch.cc:321), so
    /// the handle is simultaneously published as the thread's
    /// current-Architecture factory — the `glb->types` ownership mirror
    /// that `TypeFactory::shared_default` resolves for handle-less engine
    /// call sites.
    pub fn set_types(&mut self, tf: std::sync::Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>>) {
        crate::type_system::typefactory::TypeFactory::publish_current_arch(tf.clone());
        self.types = Some(tf);
    }

    // Ghidra: sleigh_arch.cc:201 types = new TypeFactory(this);
    // architecture.cc:1350 types->setupSizes() decode tail
    /// Install this Architecture's OWN TypeFactory if none is set, then
    /// return the active handle. Ghidra's Architecture always owns exactly
    /// one `TypeFactory` (`TypeFactory::TypeFactory(Architecture*)`,
    /// type.cc:3106; built by `buildTypegrp` sleigh_arch.cc:201 with the
    /// `architecture.cc:1350` setupSizes tail applied at decode), so the
    /// fresh path now constructs a NEW per-Architecture factory (the
    /// canonical bootstrap recipe: core types + default alignment map +
    /// no-lease unknown warmup) instead of borrowing the process-canonical
    /// singleton — closing the cross-Architecture type-state leak for
    /// drivers that never call `set_types` explicitly. The returned handle
    /// is (re)published as the thread's current-Architecture factory so
    /// every handle-less `shared_default` resolution observes the same
    /// factory the Architecture observes. TYPE-WIRING-0001 production
    /// wiring: after `fd.set_arch(arch)` (or before VarnodeBank use), call
    /// `arch.ensure_types()` and `fd.vbank.set_type_factory(handle)` so
    /// every varnode/symbol unknown type resolves the same factory the
    /// printer and varmap observe.
    pub fn ensure_types(
        &mut self,
    ) -> std::sync::Arc<std::sync::RwLock<crate::type_system::typefactory::TypeFactory>> {
        if let Some(existing) = &self.types {
            let existing = existing.clone();
            crate::type_system::typefactory::TypeFactory::publish_current_arch(existing.clone());
            return existing;
        }
        let fresh = crate::type_system::typefactory::TypeFactory::fresh_canonical();
        self.types = Some(fresh.clone());
        crate::type_system::typefactory::TypeFactory::publish_current_arch(fresh.clone());
        fresh
    }

    // RUGRA-GLUE: set_userops (no Ghidra counterpart found)
    /// Set the userop manager.
    pub fn set_userops(&mut self, uo: std::sync::Arc<std::sync::RwLock<crate::userop::UserOpManage>>) {
        self.userops = Some(uo);
    }

    // RUGRA-GLUE: get_base_type (no Ghidra counterpart found)
    /// Get a base type of `size`/`metatype` from the TypeFactory, if set.
    /// Faithful to `TypeFactory::getBase` via Architecture.
    pub fn get_base_type(&self, size: usize, m: crate::type_system::datatype::TypeMetatype) -> Option<std::sync::Arc<crate::type_system::datatype::Datatype>> {
        self.types.as_ref().and_then(|tf| tf.read().unwrap().get_base(size, m))
    }

    // RUGRA-GLUE: construct_join_address (no Ghidra counterpart found)
    /// Construct a "join" address for a multi-register value. Faithful to
    /// `Translate::constructJoinAddress` (translate.cc:817-860). Degraded:
    /// only the contiguous-same-space fast path is implemented (returns the
    /// lower address); non-contiguous returns a zero placeholder.
    pub fn construct_join_address(&self, hi_offset: u64, hi_size: usize, lo_offset: u64, lo_size: usize) -> u64 {
        // If the two pieces are contiguous in the same space, the join is
        // just the lowest address.
        if lo_offset + lo_size as u64 == hi_offset {
            return lo_offset;
        }
        if hi_offset + hi_size as u64 == lo_offset {
            return hi_offset;
        }
        0
    }

    // RUGRA-GLUE: set_split_records (no Ghidra counterpart found)
    /// Set the prefer-split records. Replaces `decodePreferSplit`.
    pub fn set_split_records(&mut self, records: Vec<crate::prefersplit::PreferSplitRecord>) {
        self.split_records = records;
    }

    // RUGRA-GLUE: configuration adapter for Architecture::decodeRegisterData
    // (architecture.cc:929); the production decoder builds the same unique,
    // whole-size-ordered vector by accumulating a size-indexed maskList.
    /// Replace the laned-register records while restoring the ordering and
    /// duplicate-size mask merge invariant established by `decodeRegisterData`.
    pub fn set_lane_records(&mut self, records: Vec<crate::transform::LanedRegister>) {
        let mut records = records;
        records.sort_by_key(crate::transform::LanedRegister::get_whole_size);
        let mut merged: Vec<crate::transform::LanedRegister> = Vec::new();
        for record in records {
            if let Some(last) = merged.last_mut() {
                if last.get_whole_size() == record.get_whole_size() {
                    last.size_bit_mask |= record.get_size_bit_mask();
                    continue;
                }
            }
            merged.push(record);
        }
        self.lane_records = merged.into_iter().map(std::sync::Arc::new).collect();
    }

    // Ghidra: architecture.cc:290 Architecture::getLanedRegister
    /// Look up the shared laned-register record for a storage size. As in the
    /// locked oracle, the address is currently ignored and the ordered vector
    /// is searched by whole-register size.
    pub fn get_laned_register(
        &self,
        _loc: crate::address::Address,
        size: usize,
    ) -> Option<std::sync::Arc<crate::transform::LanedRegister>> {
        let mut min = 0i32;
        let mut max = self.lane_records.len() as i32 - 1;
        while min <= max {
            let mid = (min + max) / 2;
            let record = &self.lane_records[mid as usize];
            let whole_size = record.get_whole_size();
            if whole_size < size as i32 {
                min = mid + 1;
            } else if (size as i32) < whole_size {
                max = mid - 1;
            } else {
                return Some(record.clone());
            }
        }
        None
    }

    // Ghidra: architecture.cc:312 Architecture::getMinimumLanedRegisterSize
    /// Return the smallest configured whole-register size, or `-1` when no
    /// laned registers are configured.
    pub fn get_minimum_laned_register_size(&self) -> i32 {
        self.lane_records
            .first()
            .map_or(-1, |record| record.get_whole_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;

    // PRINTC-PRINTLIST-WIRING-0001: architecture.cc:1443-1444 —
    // Architecture::resetDefaults resets exactly THIS architecture's
    // printers (per-object vector semantics; two live architectures on one
    // thread must not cross-reset).
    #[test]
    fn printlist_reset_is_per_architecture() {
        use crate::prettyprint::{Emit, EmitNoMarkup};
        use crate::printlanguage::PrintLanguage as _;

        fn rendered_comment(
            handle: &std::sync::Arc<
                std::sync::RwLock<Box<dyn crate::printlanguage::PrintLanguage>>,
            >,
        ) -> String {
            let mut printer = handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Slice the delta: the emitter buffer accumulates across calls.
            let before = printer
                .get_emit()
                .as_any_mut()
                .and_then(|any| any.downcast_ref::<EmitNoMarkup>())
                .map(|emit| emit.debug_get_output_ref().len())
                .unwrap_or(0);
            printer.emit_line_comment(0, "routed body");
            printer
                .get_emit()
                .as_any_mut()
                .and_then(|any| any.downcast_ref::<EmitNoMarkup>())
                .map(|emit| emit.debug_get_output_ref()[before..].to_string())
                .unwrap_or_default()
                .trim_start_matches(['\n', ' '])
                .to_string()
        }

        let mut arch_a = Architecture::new();
        let mut arch_b = Architecture::new();
        let handle_a = arch_a.register_print_language(Box::new(crate::printc::PrintC::new(
            Box::new(EmitNoMarkup::new()),
        )));
        let handle_b = arch_b.register_print_language(Box::new(crate::printc::PrintC::new(
            Box::new(EmitNoMarkup::new()),
        )));
        // Registration order: current = the newly pushed printer
        // (architecture.cc:171-172/431 push-then-point).
        assert_eq!(
            arch_a.print_language_current().unwrap().read().unwrap().get_name(),
            "c-language"
        );
        // Flip both to the C++ style, then reset ONLY arch_a.
        for handle in [&handle_a, &handle_b] {
            handle
                .write()
                .unwrap()
                .set_comment_style("cplusplus")
                .expect("valid style");
        }
        assert!(rendered_comment(&handle_a).starts_with("// "));
        arch_a.reset_defaults();
        // arch_a's printer is back to the C default (printc.cc:1594 via
        // resetDefaultsPrintC); arch_b's printer is untouched — exactly the
        // oracle's per-object printlist loop.
        assert!(rendered_comment(&handle_a).starts_with("/* "));
        assert!(rendered_comment(&handle_b).starts_with("// "));
    }

    #[test]
    fn test_defaults() {
        let arch = Architecture::new();
        assert_eq!(arch.trim_recurse_max, 5);
        assert_eq!(arch.max_implied_ref, 2);
        assert_eq!(arch.max_term_duplication, 2);
        assert_eq!(arch.max_basetype_size, 10);
        assert!(arch.infer_pointers);
        assert!(arch.analyze_for_loops);
        assert!(!arch.readonlypropagate);
        assert!(arch.nan_ignore_compare);
        assert!(!arch.nan_ignore_all);
        assert_eq!(arch.alias_block_level, 2);
        assert_eq!(arch.max_jumptable_size, 1024);
        assert_eq!(arch.max_instructions, 100000);
        assert_eq!(
            arch.split_datatype_config,
            split_datatype::OPTION_STRUCT | split_datatype::OPTION_ARRAY | split_datatype::OPTION_POINTER
        );
        assert_eq!(arch.min_funcsymbol_size, 1);
    }

    #[test]
    fn test_reset_defaults() {
        let mut arch = Architecture::new();
        arch.trim_recurse_max = 99;
        arch.infer_pointers = false;
        arch.reset_defaults();
        assert_eq!(arch.trim_recurse_max, 5);
        assert!(arch.infer_pointers);
    }

    #[test]
    fn test_proto_models() {
        let mut arch = Architecture::new();
        let mut model = ProtoModelFull::new(Some(crate::space::AddressSpace::Stack), 8);
        model.name = "__stdcall".to_string();
        let external = Arc::new(model);
        arch.proto_models
            .insert("__stdcall".to_string(), external.clone());
        assert!(arch.has_model("__stdcall"));
        assert!(!arch.has_model("__cdecl"));
        assert!(arch.get_model("__stdcall").is_some());
        arch.set_default_model("__stdcall");
        assert_eq!(arch.defaultfp_name.as_deref(), Some("__stdcall"));
        assert!(!arch.get_model("__stdcall").unwrap().print_in_decl());
        assert!(Arc::ptr_eq(
            arch.get_model("__stdcall").unwrap(),
            arch.get_default_model().unwrap(),
        ));
        assert!(Arc::ptr_eq(&external, arch.get_default_model().unwrap()));
        assert!(!external.print_in_decl());

        let mut replacement = ProtoModelFull::new(Some(crate::space::AddressSpace::Stack), 8);
        replacement.name = "replacement".to_string();
        let replacement = Arc::new(replacement);
        arch.proto_models
            .insert("replacement".to_string(), replacement.clone());
        arch.set_default_model("replacement");
        assert!(external.print_in_decl());
        assert!(!replacement.print_in_decl());
        assert!(Arc::ptr_eq(&replacement, arch.get_default_model().unwrap()));
    }

    #[test]
    fn test_model_alias() {
        let mut arch = Architecture::new();
        let mut model = ProtoModelFull::new(Some(crate::space::AddressSpace::Stack), 8);
        model.name = "parent".to_string();
        model.set_print_in_decl(false);
        arch.proto_models
            .insert("parent".to_string(), Arc::new(model));
        assert!(arch.create_model_alias("alias", "parent"));
        assert!(arch.has_model("alias"));
        assert_eq!(arch.get_model("alias").unwrap().get_name(), "alias");
        assert!(arch.get_model("alias").unwrap().print_in_decl());
        assert!(!arch.create_model_alias("alias2", "nonexistent"));
    }

    #[test]
    fn test_high_ptr_possible() {
        let mut arch = Architecture::new();
        assert!(arch.high_ptr_possible(Address::new(0x1000), 4));
        arch.add_no_high_ptr(Range::new(Address::new(0x1000), Address::new(0x1FFF)).unwrap());
        assert!(!arch.high_ptr_possible(Address::new(0x1000), 4));
        assert!(!arch.high_ptr_possible(Address::new(0x1FFC), 8)); // end in range
        assert!(arch.high_ptr_possible(Address::new(0x2000), 4));
    }

    #[test]
    fn test_version() {
        assert_eq!(CapabilityRegistry::major_version(), 6);
        assert_eq!(CapabilityRegistry::minor_version(), 1);
    }

    #[test]
    fn test_truncate_space_projection() {
        // AddrSpaceManager::truncateSpace (translate.cc:776-783) +
        // AddrSpace::truncateSpace state (space.cc:105-112), projected on
        // the architecture for the enum space model.
        let mut arch = Architecture::new();
        assert!(!arch.space_is_truncated(crate::space::AddressSpace::Ram));
        assert_eq!(
            arch.space_addr_size(crate::space::AddressSpace::Ram),
            8,
            "inherent ram addr size while untruncated"
        );
        // cc:780-781: unknown name → LowlevelError("Unknown space in
        // <truncate_space> command: ...").
        assert_eq!(
            arch.truncate_space("nosuch", 4),
            Err("Unknown space in <truncate_space> command: nosuch".to_string())
        );
        arch.truncate_space("ram", 4).unwrap();
        assert!(arch.space_is_truncated(crate::space::AddressSpace::Ram));
        assert_eq!(arch.space_addr_size(crate::space::AddressSpace::Ram), 4);
        assert!(
            !arch.space_is_truncated(crate::space::AddressSpace::Stack),
            "truncation is per-space"
        );
        assert_eq!(
            arch.space_addr_size(crate::space::AddressSpace::Stack),
            8,
            "untruncated spaces keep their inherent size"
        );
        // Re-truncation overwrites the effective size (the oracle re-runs
        // AddrSpace::truncateSpace on the same space record).
        arch.truncate_space("ram", 6).unwrap();
        assert_eq!(arch.space_addr_size(crate::space::AddressSpace::Ram), 6);
        // getDefaultCodeSpace (translate.hh:505-507): enum-model ram.
        assert_eq!(
            arch.get_default_code_space(),
            crate::space::AddressSpace::Ram
        );
    }

    #[test]
    fn test_decode_stack_pointer_truncated() {
        // decodeStackPointer cc:1007-1011 + setBaseRegister
        // translate.cc:95-101: a truncated base space splits the stack
        // pointer into baseloc (truncated) and baseOrig (full).
        let mut store = parse_store(
            "<stackpointer register=\"RSP\" space=\"ram\" growth=\"negative\"/>",
        );
        let root = store
            .get_tag("stackpointer")
            .expect("stackpointer root registered")
            .clone();

        // Untruncated: truncSize == point.size, baseloc == baseOrig.
        {
            let registry = Arc::new(std::sync::RwLock::new(
                crate::marshal::IdRegistry::new(),
            ));
            let mut decoder = crate::marshal::TreeDecoder::new(root.clone(), registry);
            let mut arch = Architecture::new();
            arch.decode_stack_pointer(&mut decoder, &TestHost)
                .expect("decode");
            assert_eq!(arch.stack_pointer_size, 8);
            assert_eq!(arch.stack_pointer_offset, 0x20);
            assert_eq!(arch.stack_pointer_full_size, 8);
            assert_eq!(arch.stack_pointer_full_offset, 0x20);
            assert_eq!(
                arch.stack_space_get_spacebase(0).unwrap(),
                (crate::space::AddressSpace::Register, 0x20, 8)
            );
            assert_eq!(
                arch.stack_space_get_spacebase_full(0).unwrap(),
                (crate::space::AddressSpace::Register, 0x20, 8)
            );
            assert!(arch.stack_space_get_spacebase(1).is_none());
            assert!(arch.stack_space_get_spacebase_full(1).is_none());
            assert_eq!(arch.stack_space_num_spacebase(), 1);
        }

        // Truncated ram → 4: truncReg size 4, fullReg stays the full 8-byte
        // RSP; the register space is little-endian so the offset is NOT
        // shifted (translate.cc:97-100 big-endian-only arm).
        {
            let registry = Arc::new(std::sync::RwLock::new(
                crate::marshal::IdRegistry::new(),
            ));
            let mut decoder = crate::marshal::TreeDecoder::new(root, registry);
            let mut arch = Architecture::new();
            arch.truncate_space("ram", 4).unwrap();
            arch.decode_stack_pointer(&mut decoder, &TestHost)
                .expect("decode");
            assert_eq!(arch.stack_pointer_size, 4, "baseloc truncated to 4");
            assert_eq!(
                arch.stack_pointer_offset, 0x20,
                "LE register space: no big-endian offset shift"
            );
            assert_eq!(arch.stack_pointer_full_size, 8, "baseOrig keeps 8");
            assert_eq!(
                arch.stack_space_get_spacebase(0).unwrap(),
                (crate::space::AddressSpace::Register, 0x20, 4)
            );
            assert_eq!(
                arch.stack_space_get_spacebase_full(0).unwrap(),
                (crate::space::AddressSpace::Register, 0x20, 8)
            );
        }
    }

    /// A tiny language host for the compiler-spec parse tests: one register
    /// (RSP@0x20 size 8), ram/stack/register spaces with 64-bit highest.
    struct TestHost;

    impl SpecQuery for TestHost {
        fn get_register(&self, name: &str) -> Option<VarnodeData> {
            match name {
                "RSP" => Some(VarnodeData {
                    space: crate::space::AddressSpace::Register,
                    offset: 0x20,
                    size: 8,
                }),
                _ => None,
            }
        }
        fn space_by_name(&self, name: &str) -> Option<crate::space::AddressSpace> {
            match name {
                "ram" => Some(crate::space::AddressSpace::Ram),
                "stack" => Some(crate::space::AddressSpace::Stack),
                "register" => Some(crate::space::AddressSpace::Register),
                "other" => Some(crate::space::AddressSpace::Other(0)),
                _ => None,
            }
        }
        fn space_highest(&self, _spc: crate::space::AddressSpace) -> u64 {
            u64::MAX
        }
    }

    fn parse_store(text: &str) -> crate::marshal::DocumentStorage {
        let mut store = crate::marshal::DocumentStorage::new();
        let doc = store.parse_document(text.as_bytes()).expect("parse");
        let root = doc.root.clone().expect("root");
        store.register_tag(&root);
        store
    }

    #[test]
    fn test_decode_global_deferred_apply() {
        // decodeGlobal collects partial ranges; the apply loop runs in
        // parse_compiler_config AFTER the child loop (architecture.cc:1329).
        // Without a <default_proto> the oracle itself throws
        // "No default prototype specified" (architecture.cc:1341).
        let mut store = parse_store(
            "<compiler_spec><global><range space=\"ram\"/></global>\
             <default_proto><prototype name=\"__stdcall\" extrapop=\"8\" stackshift=\"8\">\
             </prototype></default_proto></compiler_spec>",
        );
        let mut arch = Architecture::new();
        let report = arch
            .parse_compiler_config(&mut store, &TestHost, 8)
            .expect("parse");
        assert!(report.skipped_children.is_empty());
        // ram full range + the OTHER space range from addOtherSpace.
        assert_eq!(arch.global_scope_ranges.len(), 2);
        assert_eq!(arch.global_scope_ranges[0], (crate::space::AddressSpace::Ram, 0, u64::MAX));
        assert_eq!(arch.infer_ptr_spaces, vec![crate::space::AddressSpace::Ram]);
        // CSPEC-GLOBAL-APPLY-0001: the same ranges land in the symbol
        // table's global scope (architecture.cc:833/852
        // `symboltab->addRange`), in the space-keyed tree — ram full range
        // and OTHER full range as separate partitions.
        {
            let db = arch.symboltab.as_ref().expect("constructor DB").read().unwrap();
            let global = db.get_global_scope().expect("global scope");
            // TestHost maps "other" to Other(0) (index 0), which sorts
            // before ram (index 3) — the drivers' real host uses
            // Other(SPACEID_OTHER=1), same order.
            assert_eq!(
                global.rangetree.ranges(),
                &[
                    crate::database::ScopeRange::new(
                        crate::space::AddressSpace::Other(0),
                        0,
                        u64::MAX,
                    ),
                    crate::database::ScopeRange::new(crate::space::AddressSpace::Ram, 0, u64::MAX),
                ][..],
                "sorted by (space index, first)"
            );
            // The queryProperties fold is live: a ram offset inside the
            // global range answers mapped|addrtied|persist
            // (database.cc:1271-1276).
            let (_, flags) = db.query_properties(
                db.global_scope_id,
                crate::address::Address::new(0x1234),
                1,
                crate::address::Address::new(0),
            );
            assert_eq!(
                flags,
                crate::varnode::varnode_flags::MAPPED
                    | crate::varnode::varnode_flags::ADDRTIED
                    | crate::varnode::varnode_flags::PERSIST
            );
        }

        let mut bare = parse_store("<compiler_spec/>");
        let mut arch2 = Architecture::new();
        assert_eq!(
            arch2.parse_compiler_config(&mut bare, &TestHost, 8).unwrap_err(),
            "No default prototype specified"
        );
    }

    #[test]
    fn test_decode_return_address_multiple_tags() {
        // architecture.cc:904-905: a second <returnaddress> after the first
        // was set throws "Multiple <returnaddress> tags in .cspec".
        let mut store = parse_store(
            "<compiler_spec><returnaddress><varnode space=\"stack\" offset=\"0\" size=\"8\"/>\
             </returnaddress><returnaddress><varnode space=\"stack\" offset=\"0\" size=\"8\"/>\
             </returnaddress></compiler_spec>",
        );
        let mut arch = Architecture::new();
        let err = arch
            .parse_compiler_config(&mut store, &TestHost, 8)
            .unwrap_err();
        assert_eq!(err, "Multiple <returnaddress> tags in .cspec");
    }

    #[test]
    fn test_parse_compiler_config_minimal() {
        // Full chain on a minimal cspec: stackpointer + returnaddress +
        // default_proto; the model must pick up the default return address
        // (fspec.cc:2689) and the __thiscall alias must be cloned
        // (architecture.cc:1343-1347).
        let mut store = parse_store(
            "<compiler_spec>\
             <stackpointer register=\"RSP\" space=\"ram\"/>\
             <returnaddress><varnode space=\"stack\" offset=\"0\" size=\"8\"/></returnaddress>\
             <default_proto><prototype name=\"__stdcall\" extrapop=\"8\" stackshift=\"8\">\
             </prototype></default_proto>\
             </compiler_spec>",
        );
        let mut arch = Architecture::new();
        arch.archid = "test".to_string();
        let _report = arch
            .parse_compiler_config(&mut store, &TestHost, 8)
            .expect("parse");
        assert_eq!(arch.stack_pointer_offset, 0x20);
        assert_eq!(arch.stack_pointer_size, 8);
        assert!(arch.stack_grows_negative);
        assert_eq!(
            arch.default_return_addr,
            Some(VarnodeData {
                space: crate::space::AddressSpace::Stack,
                offset: 0,
                size: 8
            })
        );
        assert_eq!(arch.defaultfp.as_ref().unwrap().get_name(), "__stdcall");
        assert!(arch.proto_models.contains_key("__thiscall"));
        // The model decoded after <returnaddress> gets the default injected
        // as a return_address effect record.
        let effects = arch.defaultfp.as_ref().unwrap().effect_iter();
        assert!(effects
            .iter()
            .any(|e| matches!(e.get_type(), crate::fspec::EffectType::ReturnAddress)
                && e.space == crate::space::AddressSpace::Stack
                && e.offset == 0));
    }

    /// A trivial test capability for the registry.
    struct DummyCap {
        name: String,
    }
    impl ArchitectureCapability for DummyCap {
        fn name(&self) -> &str {
            &self.name
        }
        fn build_architecture(
            &self,
            _f: &str,
            _t: &str,
        ) -> Result<Box<dyn ArchitectureBuilder>, String> {
            Err("not implemented".to_string())
        }
        fn is_file_match(&self, f: &str) -> bool {
            f.ends_with(".bin")
        }
        fn is_xml_match(&self, _d: &str) -> bool {
            false
        }
    }

    /// A "raw" capability that should sort last.
    struct RawCap;
    impl ArchitectureCapability for RawCap {
        fn name(&self) -> &str {
            "raw"
        }
        fn build_architecture(
            &self,
            _f: &str,
            _t: &str,
        ) -> Result<Box<dyn ArchitectureBuilder>, String> {
            Err("not implemented".to_string())
        }
        fn is_file_match(&self, _f: &str) -> bool {
            true
        }
        fn is_xml_match(&self, _d: &str) -> bool {
            false
        }
    }

    #[test]
    fn test_capability_registry() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Box::new(RawCap));
        reg.register(Box::new(DummyCap {
            name: "elf".to_string(),
        }));
        // Before sort: raw is first.
        assert_eq!(reg.get_capability("raw").unwrap().name(), "raw");
        // Find by file.
        assert!(reg.find_capability_for_file("test.bin").is_some());
        // Sort: raw should move to the end.
        reg.sort_capabilities();
        // Still findable by name.
        assert!(reg.get_capability("raw").is_some());
        assert!(reg.get_capability("elf").is_some());
    }

    #[test]
    fn test_laned_register_lookup_minimum_order_and_identity() {
        let mut arch = Architecture::new();
        arch.set_lane_records(vec![
            crate::transform::LanedRegister::with_sizes(16, 1 << 4),
            crate::transform::LanedRegister::with_sizes(8, 1 << 2),
            crate::transform::LanedRegister::with_sizes(16, 1 << 8),
        ]);
        assert_eq!(arch.get_minimum_laned_register_size(), 8);
        assert_eq!(
            arch.lane_records
                .iter()
                .map(|record| record.get_whole_size())
                .collect::<Vec<_>>(),
            vec![8, 16]
        );
        let first = arch
            .get_laned_register(Address::new(0x10), 16)
            .unwrap();
        let second = arch
            .get_laned_register(Address::new(0xdead), 16)
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert_eq!(first.get_size_bit_mask(), (1 << 4) | (1 << 8));
        assert!(arch.get_laned_register(Address::new(0), 12).is_none());

        arch.set_lane_records(Vec::new());
        assert_eq!(arch.get_minimum_laned_register_size(), -1);
    }

    // Ghidra: sleighbase.cc:144 SleighBase::getRegisterName — boundary
    // semantics regression (upper_bound + iter-- == greatest entry <= probe).
    #[test]
    fn test_get_register_name_boundaries() {
        use crate::space::AddressSpace;
        let mut arch = Architecture::new();
        // A miniature varnode_xref in the SLEIGH ordering (big sizes first
        // per pcoderaw.hh:67-71): RAX family at 0x0, XMM0_Qa 16 bytes at
        // 0x110 with an 8-byte XMM0_Q lower half at the same offset.
        arch.set_register_xref(vec![
            (4, 0x0, 8, "RAX".to_string()),
            (4, 0x0, 4, "EAX".to_string()),
            (4, 0x0, 1, "AL".to_string()),
            (4, 0x20, 8, "RSP".to_string()),
            (4, 0x110, 16, "XMM0_Qa".to_string()),
            (4, 0x110, 8, "XMM0_Q".to_string()),
        ]);
        let reg = AddressSpace::Register;
        // Exact hits: the greatest <= probe is the probe itself.
        assert_eq!(arch.get_register_name(reg, 0x0, 8), "RAX");
        assert_eq!(arch.get_register_name(reg, 0x20, 8), "RSP");
        // 16 bytes at 0x110 covers only via the 16-byte entry (the 8-byte
        // lower half alone does not cover [0x110,0x120)).
        assert_eq!(arch.get_register_name(reg, 0x110, 16), "XMM0_Qa");
        // 8 bytes at 0x110: the -8 probe sorts before -16, so the greatest
        // <= probe is the 8-byte entry itself.
        assert_eq!(arch.get_register_name(reg, 0x110, 8), "XMM0_Q");
        // Sub-register inside RAX: probe (4,0x1,-1) — greatest <= probe is
        // (4,0x0,-1) AL (exact key ordering: -1 > -4 > -8). AL fails the
        // covering gate (0x0+1 < 0x1+1), so the walk-back visits the
        // immediate predecessor (4,0x0,-4) EAX, which covers (0x0+4 >= 0x2)
        // → "EAX" — the oracle's C++ replica answer (R-RAWQUAR F1: the
        // double-step bug skipped EAX and returned RAX here).
        assert_eq!(arch.get_register_name(reg, 0x1, 1), "EAX");
        // Full discriminating table (set_register_xref clears + rebuilds):
        arch.set_register_xref(vec![
            (4, 0x0, 8, "RAX".to_string()),
            (4, 0x0, 4, "EAX".to_string()),
            (4, 0x0, 1, "AL".to_string()),
            (4, 0x20, 8, "RSP".to_string()),
            (4, 0x110, 16, "XMM0_Qa".to_string()),
            (4, 0x110, 8, "XMM0_Q".to_string()),
            (4, 0x100, 2, "S2".to_string()),
            (4, 0x100, 4, "S4".to_string()),
            (4, 0x100, 8, "S8".to_string()),
            (4, 0x200, 4, "Q4".to_string()),
            (4, 0x200, 8, "Q8".to_string()),
        ]);
        // Two-step walk-back success: probe (0x102,4) — greatest <= is
        // (4,0x100,-2) S2 (offset 0x100 < 0x102, S2 is the largest key at
        // that offset); S2 fails (0x102 < 0x106), predecessor S4 fails
        // (0x104 < 0x106), predecessor S8 covers (0x108 >= 0x106) → "S8".
        assert_eq!(arch.get_register_name(reg, 0x102, 4), "S8");
        // False-miss discriminator: probe (0x201,4) — greatest <= is Q4
        // (0x204 < 0x205 fails), the immediate predecessor Q8 covers
        // (0x208 >= 0x205) → "Q8". The double-step bug skipped Q8 and
        // returned "" (R-RAWQUAR F1 miss-direction).
        assert_eq!(arch.get_register_name(reg, 0x201, 4), "Q8");
        // Span past RAX end: (4,0x7,-4) — greatest <= is RAX(8) but
        // 0x0+8 < 0x7+4, and the back-walk stops at the base-offset change
        // (no other entry at offset 0x0 covers) → "".
        assert_eq!(arch.get_register_name(reg, 0x7, 4), "");
        // Gap between entries: probe at 0x40 → greatest <= is RSP(0x20,8)
        // which covers [0x40,0x48)? no: 0x20+8 < 0x40+8 → back-walk hits
        // offset change → "".
        assert_eq!(arch.get_register_name(reg, 0x40, 8), "");
        // Different space: nothing in ram → "".
        assert_eq!(arch.get_register_name(AddressSpace::Ram, 0x0, 8), "");
        // Empty catalog: "" everywhere (Translate with no registers).
        let empty = Architecture::new();
        assert_eq!(empty.get_register_name(reg, 0x0, 8), "");
        // getExactRegisterName (sleighbase.cc:170-180).
        assert_eq!(arch.get_exact_register_name(reg, 0x110, 16), "XMM0_Qa");
        assert_eq!(arch.get_exact_register_name(reg, 0x110, 4), "");
    }
}
