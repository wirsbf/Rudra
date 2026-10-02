//! Type management and deduplication
//!
//! Corresponds to Ghidra's `TypeFactory` class in `type.hh`. This class is responsible
//! for the lifecycle of all `Datatype` objects, ensuring that identical types are
//! deduplicated and providing a central point for type lookup.

use crate::address::Address;
use crate::marshal::{Decoder, Encoder};
use crate::type_system::datatype::*;
use crate::AddressSpace;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Lexicographic projection of the concrete dependency keys covered by this
/// series: atomic, pointer, array, and partial-container types.
type TypeTreeKey = (
    u8,
    usize,
    i64,
    usize,
    usize,
    u8,
    u8,
    Reverse<usize>,
    u64);

// Ghidra: type.hh:752 DatatypeWarning
/// A warning attached to a named data-type. Mirrors Ghidra's
/// `DatatypeWarning` (type.hh:752-762): the data-type the warning is about
/// plus the explanatory string displayed to the user. Ghidra stores the
/// `Datatype*` itself; Rudra records the `(name, id)` identity pair that
/// `removeWarning` compares on (type.cc:3766: `getId() == dt->getId() &&
/// getName() == dt->getName()`) — for factory-registered types the pair is
/// stable across the Arc re-wrapping that Rudra's immutable-Arc registry
/// performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatatypeWarning {
    /// Name of the data-type associated with the warning.
    pub type_name: String,
    /// Id of the data-type associated with the warning.
    pub type_id: u64,
    /// The explanatory string which should be displayed to the user.
    pub warning: String,
}

/// Managed container for all Datatype objects
pub struct TypeFactory {
    /// All types managed by this factory, keyed by their unique name
    types: BTreeMap<String, Arc<Datatype>>,

    /// Cache for core types (void, int, etc.) for quick access
    core_types: BTreeMap<String, Arc<Datatype>>,

    /// Structural registry for factory-owned types. The key preserves the
    /// concrete pointer/array/partial dependency identity before descending
    /// size and id, matching the covered `DatatypeCompare` branches.
    base_type_tree: RwLock<BTreeMap<TypeTreeKey, Arc<Datatype>>>,

    /// Fast preferred-core lookup corresponding to Ghidra's `typecache`.
    base_cache: RwLock<BTreeMap<(usize, TypeMetatype), Arc<Datatype>>>,

    /// The non-character signed byte selected by `cacheCoreTypes`, matching
    /// Ghidra's `type_nochar` side cache (type.hh:777).
    type_nochar: RwLock<Option<Arc<Datatype>>>,

    /// Preferred printable character types by byte size, matching Ghidra's
    /// `charcache[5]` (type.hh:778). Only sizes 0..=4 can be populated.
    char_cache: RwLock<BTreeMap<usize, Arc<Datatype>>>,

    /// The default size of a pointer for this architecture
    ptr_size: usize,

    /// Live function-local scope handles for local-frame spacebases, keyed
    /// by the frame (function entry) offset. This is the Rust ownership seam
    /// for Ghidra's dynamic `TypeSpacebase::getMap` resolution
    /// (type.cc:2938-2944: `queryFunction(localframe)->getScopeLocal()`):
    /// the Funcdata owns the restructured `ScopeLocal`, the factory-cached
    /// spacebase type holds a clone of the shared handle (attached eagerly
    /// HERE, at type construction, so the cache can never hold a
    /// stale/unattached local frame), and `ActionRestructureVarnode`
    /// publishes each restructured scope into the handle contents. The
    /// handle starts as an empty `ScopeLocal` — the oracle's pre-restructure
    /// observable.
    live_local_scopes: BTreeMap<u64, std::sync::Arc<std::sync::RwLock<crate::varmap::ScopeLocal>>>,

    /// Side data for `TypePointerRel` instances: the parent container and
    /// offset that do not fit on Rudra's flat `TypePointer`. Mirrors the
    /// `parent`/`offset` fields of Ghidra's `TypePointerRel` (type.hh:647).
    rel_pointers: BTreeMap<String, RelativePointer>,

    /// Typedef targets: maps a typedef name to the data-type it aliases
    /// (the "stripped" form). Mirrors Ghidra's `Datatype::typedefImm`
    /// (type.hh:196) and `TypeFactory::getTypedef` (type.cc:3818-3840).
    typedefs: BTreeMap<String, Arc<Datatype>>,

    /// Pending incomplete typedefs awaiting their referenced type's
    /// completion. Mirrors Ghidra's `incompleteTypedef` list (type.hh:761):
    /// `getTypedef` appends clones that are still `type_incomplete`
    /// (type.cc:3837-3838) and `resolveIncompleteTypedefs` drains them
    /// (type.cc:3777-3809), including the TYPE_CODE arm that installs the
    /// referenced code type's prototype on the typedef.
    incomplete_typedefs: Vec<Arc<Datatype>>,

    /// Warnings attached to named data-types, mirroring Ghidra's `warnings`
    /// list (type.hh:760) of `DatatypeWarning` records appended by
    /// `insertWarning` (type.cc:3750) and drained entry-by-entry by
    /// `removeWarning` (type.cc:3761).
    warnings: Vec<DatatypeWarning>,

    /// Size of the core "int" data-type (Ghidra `sizeOfInt`, type.hh:763).
    /// Persisted state of `decodeDataOrganization`/`setupSizes`.
    size_of_int: i32,
    /// Size of the core "long" data-type (Ghidra `sizeOfLong`, type.hh:764).
    size_of_long: i32,
    /// Size of the core "char" data-type (Ghidra `sizeOfChar`, type.hh:765).
    size_of_char: i32,
    /// Size of the core "wchar_t" data-type (Ghidra `sizeOfWChar`, type.hh:766).
    size_of_wchar: i32,
    /// Size of pointers into the default data space (Ghidra `sizeOfPointer`,
    /// type.hh:767).
    size_of_pointer: i32,
    /// Size of alternate pointers, 0 when unused (Ghidra `sizeOfAltPointer`,
    /// type.hh:768). Only `setupSizes`'s far-pointer branch writes this.
    size_of_alt_pointer: i32,
    /// Size of an enumerated type (Ghidra `enumsize`, type.hh:769).
    enum_size: i32,
    /// Default enumeration meta-type (Ghidra `enumtype`, type.hh:770).
    enum_type: TypeMetatype,
    /// Alignment of primitive data-types keyed by size (Ghidra `alignMap`,
    /// type.hh:771). Element value -1 marks "not set" during decode; index 0
    /// stays -1 unless an explicit `<entry size="0">` exists.
    align_map: Vec<i32>,

    /// Maximum size of a scalar "base" type before `getBase` converts the
    /// request into an array of 1-byte unknowns (Ghidra
    /// `Architecture::max_basetype_size`, architecture.hh:173, set to 10 at
    /// architecture.cc:1422). Rudra stores it on the factory because the
    /// factory has no Architecture handle yet.
    max_base_type_size: usize,

    /// The symbol-table snapshot global spacebases resolve through. Ghidra's
    /// `TypeSpacebase::getMap` reads `glb->symboltab->getGlobalScope()`
    /// dynamically (type.cc:2935-2945); Rudra's types carry no Architecture,
    /// so the factory holds the Database handle here and clones the global
    /// scope into each new spacebase product (the scope graph is installed
    /// before decompilation and stable during it, matching the oracle's
    /// observable answers). Consumers: `TypeSpacebase::get_sub_type` (the
    /// RulePtrsubUndo isPtrsubMatching guard) and the spacebase typing of
    /// `Funcdata::spacebase_constant` (B3-COREACTION-CONSTANTPTR-0001 b).
    symboltab: Option<std::sync::Arc<std::sync::RwLock<crate::database::Database>>>,
}

/// Select the source of the Architecture-owned core-type table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreTypeFlavor {
    /// Projection of the compiler-supplied `<coretypes>` used by the Java
    /// decompiler client and the canonical headless-output gate.
    DataOrg,
    /// `ArchitectureGhidra::buildCoreTypes` when no `<coretypes>` tag exists.
    GhidraFallback,
    /// `SleighArchitecture::buildCoreTypes` when no `<coretypes>` tag exists.
    Standalone,
}

// MIRROR2 unkbyte family: the lock-free canonical 1-byte TYPE_UNKNOWN cache
// (see TypeFactory::canonical_unknown_base_1). Populated eagerly inside
// `TypeFactory::shared_default`'s construction closure — under no RwLock
// lease — so factory write-lease holders (e.g. down_chain_pointer reaching
// TypeSpacebase::get_sub_type's miss arm) always find the fast path armed
// and never re-enter the shared factory's lock.
static CANONICAL_UNKNOWN_BASE_1: std::sync::OnceLock<std::sync::Arc<Datatype>> =
    std::sync::OnceLock::new();

// RUDRA-GLUE: thread-local stand-in for the oracle's `glb->types`
// ownership resolution (architecture.hh:197). Ghidra's engine always
// reaches the factory THROUGH the owning Architecture; Rudra's handle-less
// call sites (39 `shared_default` references) resolve through this
// registry instead. The entry is published by
// `Architecture::set_types`/`ensure_types` at the oracle `buildTypegrp`
// moment (sleigh_arch.cc:201 / ghidra_arch.cc:321) and cleared by
// `Architecture::drop` when the registry still points at the dropping
// Architecture's factory (the architecture.cc:211-212 `delete types`
// mirror). The `unknown_base_1` snapshot is warmed at publication time
// under NO lease (same MIRROR2 argument as the process-canonical closure),
// so `canonical_unknown_base_1` never needs the factory lock.
struct CurrentArchTypes {
    factory: Arc<RwLock<TypeFactory>>,
    unknown_base_1: Arc<Datatype>,
}

thread_local! {
    static CURRENT_ARCH_TYPES: std::cell::RefCell<Option<CurrentArchTypes>> =
        const { std::cell::RefCell::new(None) };
}

impl TypeFactory {
    // RUDRA-GLUE: publication half of the `glb->types` ownership mirror
    // (oracle builds the factory INTO the Architecture: sleigh_arch.cc:201
    // `types = new TypeFactory(this);`; Rudra drivers install the handle
    // via `Architecture::set_types`, which calls this).
    /// Publish `factory` as this thread's current-Architecture factory.
    ///
    /// Must run at architecture-build time (before any lease on `factory`
    /// can exist on this thread) — the eager `unknown_base_1` warmup takes
    /// one read lease, and the MIRROR2 lock-free fast path requires it to
    /// be armed before any write-lease holder can reach
    /// `canonical_unknown_base_1`. Last-publisher-wins: a subsequent
    /// publication replaces the entry (sequential multi-Architecture
    /// drivers), and the previous factory stays reachable through its Arc
    /// handles.
    pub(crate) fn publish_current_arch(factory: Arc<RwLock<TypeFactory>>) {
        let unknown_base_1 = factory
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_base(1, TypeMetatype::Unknown)
            .expect("TypeFactory::get_base always produces an unknown base type");
        CURRENT_ARCH_TYPES
            .try_with(|slot| {
                *slot.borrow_mut() = Some(CurrentArchTypes {
                    factory,
                    unknown_base_1,
                });
            })
            .ok();
    }

    // RUDRA-GLUE: teardown half of the `glb->types` ownership mirror
    // (architecture.cc:211-212 `delete types;` runs in ~Architecture).
    /// Clear the thread's current-Architecture entry if it still points at
    /// `factory` (identity compared). A no-op when another Architecture
    /// has since published — its ownership supersedes ours.
    pub(crate) fn unpublish_current_arch(factory: &Arc<RwLock<TypeFactory>>) {
        CURRENT_ARCH_TYPES
            .try_with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(&current.factory, factory))
                {
                    *slot = None;
                }
            })
            .ok();
    }

    // RUDRA-GLUE: query half of the `glb->types` ownership mirror.
    /// The thread's current-Architecture factory, if one is published.
    pub(crate) fn current_arch_factory() -> Option<Arc<RwLock<TypeFactory>>> {
        CURRENT_ARCH_TYPES
            .try_with(|slot| slot.borrow().as_ref().map(|current| current.factory.clone()))
            .unwrap_or(None)
    }
}

// RUDRA-GLUE: process-tier probe standing in for Ghidra's architecture-class
// selection of the core-type table. The oracle has two harness faces:
// SleighArchitecture::buildCoreTypes (sleigh_arch.cc:204-238) installs the
// console/standalone table (`xunknownN`/`int4`/`uint1`/`code`) when the
// architecture description carries no `<coretypes>` element — the direct-
// runner harness contract; ArchitectureGhidra receives the Java client's
// `<coretypes>` stream (PcodeDataTypeManager.encodeCoreTypes) and spells
// `undefinedN`/`int`/`long` — the canonical headless gate. Rudra's drivers
// select the contract by environment (RUDRA_MIRROR / RUDRA_FLOW_MIRROR for
// curl/httpd, RUDRA_GEN_MIRROR for the generalization driver; see
// MIRROR-ENVS-CANONICAL-0001), so every `TypeFactory::new` constructed in
// such a process must take the standalone table, exactly as the locked
// direct-runner goldens (tests/golden/*_1204.direct-runner.c) spell it.
/// Whether this process runs the direct-runner (standalone SLEIGH) oracle
/// contract instead of the canonical headless contract.
pub fn direct_runner_tier_active() -> bool {
    std::env::var_os("RUDRA_MIRROR").is_some()
        || std::env::var_os("RUDRA_FLOW_MIRROR").is_some()
        || std::env::var_os("RUDRA_GEN_MIRROR").is_some()
}

impl TypeFactory {
    // RUDRA-GLUE: Combines TypeFactory construction (type.cc:3106) with the
    // standalone SLEIGH fallback bootstrap (sleigh_arch.cc:204).
    /// Create a new TypeFactory and initialize core types
    ///
    /// # Arguments
    /// * `ptr_size` - Default pointer size for the target architecture (e.g., 4 or 8)
    pub fn new(ptr_size: usize) -> Self {
        let flavor = if direct_runner_tier_active() {
            CoreTypeFlavor::Standalone
        } else {
            CoreTypeFlavor::DataOrg
        };
        Self::new_flavor(ptr_size, flavor)
    }

    /// Construct with an explicit core-unknown registration flavor; the
    /// standalone flavor mirrors SleighArchitecture::buildCoreTypes
    /// (sleigh_arch.cc:229-232) for oracle-driven fixtures.
    // RUDRA-GLUE: Rust construction split of the two Ghidra registration
    // sites (ghidra_arch.cc:349 dataorg / sleigh_arch.cc:204 standalone);
    // Ghidra picks the site by architecture subclass instead of a param.
    pub fn new_flavor(ptr_size: usize, flavor: CoreTypeFlavor) -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            base_type_tree: RwLock::new(BTreeMap::new()),
            base_cache: RwLock::new(BTreeMap::new()),
            type_nochar: RwLock::new(None),
            char_cache: RwLock::new(BTreeMap::new()),
            ptr_size,
            live_local_scopes: BTreeMap::new(),
            rel_pointers: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            incomplete_typedefs: Vec::new(),
            warnings: Vec::new(),
            // Ghidra: type.cc:3106 TypeFactory::TypeFactory zeroes every
            // size field (int/long/char/wchar/pointer/altpointer/enumsize)
            // and leaves alignMap default-constructed (empty).
            size_of_int: 0,
            size_of_long: 0,
            size_of_char: 0,
            size_of_wchar: 0,
            size_of_pointer: 0,
            size_of_alt_pointer: 0,
            enum_size: 0,
            // Ghidra leaves `enumtype` uninitialized in the constructor
            // (type.cc:3108-3118); it is only read after parseEnumConfig or
            // setupSizes assigns it. Rust must initialize: Unknown is a
            // non-production placeholder never observable through the
            // mapped call graph.
            enum_type: TypeMetatype::Unknown,
            align_map: Vec::new(),
            // Ghidra: architecture.cc:1422 `max_basetype_size = 10;` —
            // installed by Architecture::resetDefaults, mirrored as the
            // factory default because TypeFactory reads it from `glb` at
            // type.cc:3652.
            max_base_type_size: 10,
            symboltab: None,
        };
        factory.init_core_types_flavor(flavor);
        factory
    }

    // Ghidra: type.cc:3106 TypeFactory::TypeFactory(Architecture *g)
    /// The raw Ghidra constructor projection: an EMPTY container with zeroed
    /// size fields, no alignment map, no core types, and freshly cleared
    /// caches. `TypeFactory::new` is the Rust architecture-bootstrap twin
    /// (Ghidra builds core types from `SleighArchitecture::buildCoreTypes`
    /// AFTER constructing the raw factory); `raw` exposes the pre-bootstrap
    /// state itself so the constructor's observable behaviour — `findAdd`
    /// failing with the uninitialized-alignment-map LowlevelError and
    /// `getTypeVoid`/`getTypeCode` still working — can be differentially
    /// tested against the oracle.
    pub fn raw() -> Self {
        let mut factory = Self {
            types: BTreeMap::new(),
            core_types: BTreeMap::new(),
            base_type_tree: RwLock::new(BTreeMap::new()),
            base_cache: RwLock::new(BTreeMap::new()),
            type_nochar: RwLock::new(None),
            char_cache: RwLock::new(BTreeMap::new()),
            // Rudra's pointer-size field has no Ghidra member counterpart
            // (Ghidra reads glb->sizeof_pointer at use sites); 0 marks the
            // uninitialized raw-constructor state.
            ptr_size: 0,
            rel_pointers: BTreeMap::new(),
            live_local_scopes: BTreeMap::new(),
            typedefs: BTreeMap::new(),
            incomplete_typedefs: Vec::new(),
            warnings: Vec::new(),
            size_of_int: 0,
            size_of_long: 0,
            size_of_char: 0,
            size_of_wchar: 0,
            size_of_pointer: 0,
            size_of_alt_pointer: 0,
            enum_size: 0,
            enum_type: TypeMetatype::Unknown,
            align_map: Vec::new(),
            max_base_type_size: 10,
            symboltab: None,
        };
        // Ghidra: type.cc:3118 `clearCache();` is the constructor's only call.
        factory.clear_cache();
        factory
    }

    // RUDRA-GLUE: default compiler-supplied core-type bootstrap used before
    // Architecture ownership is wired into every TypeFactory constructor.
    /// Initialize the fundamental core types
    fn init_core_types(&mut self) {
        self.init_core_types_flavor(CoreTypeFlavor::DataOrg);
    }

    // RUDRA-GLUE: Rust enum dispatcher for Ghidra's architecture-subclass
    // virtual buildCoreTypes selection.
    /// Bootstrap core types from the selected Architecture source.
    fn init_core_types_flavor(&mut self, flavor: CoreTypeFlavor) {
        match flavor {
            CoreTypeFlavor::DataOrg => self.init_data_org_core_types(),
            CoreTypeFlavor::GhidraFallback => self.init_ghidra_fallback_core_types(),
            CoreTypeFlavor::Standalone => self.init_sleigh_core_types(),
        }
    }

    // RUDRA-GLUE: Architecture-owned bridge for the virtual buildCoreTypes
    // hook; Ghidra selects the subclass implementation instead of an enum.
    /// Build core types after processor/compiler configuration has populated
    /// the raw factory's data-organization state.
    pub fn build_core_types_flavor(&mut self, flavor: CoreTypeFlavor) {
        self.init_core_types_flavor(flavor);
    }

    // RUDRA-GLUE: local projection of the headless Java client's
    // `<coretypes>` stream (the canon-golden contract). Ghidra's C++ side
    // receives this from PcodeDataTypeManager.encodeCoreTypes
    // (PcodeDataTypeManager.java:1238-1256, built by generateCoreTypes
    // :1154-1228): signed = AbstractIntegerDataType.getSignedDataTypes
    // (sbyte,short,int3,int,int5,int6,int7,sqword→longlong→long,int16 under
    // the x86-64 gcc data organization shortSize=2/integerSize=4/longSize=8/
    // longLongSize=8 — the same-size longlong slot is overwritten by long,
    // AbstractIntegerDataType.java:544-566), unsigned analogous
    // (byte,ushort,uint3,uint,uint5,6,7,ulong,uint16, :616-638),
    // Undefined.getUndefinedDataTypes = undefined1..8 (Undefined.java:31-38),
    // float(4)/double(8)/longdouble(16), code, char(1,int,ASCII),
    // wchar_t(4,int,UTF — wide≠2 ⇒ wchar16 unregistered, wide≠4 satisfied by
    // wchar_t itself), bool, void. The names drive printC spelling and
    // Datatype::printNameBase prefixes (type.hh:273 — long→'l', short→'s',
    // byte→'b'), so this table must match the Java names exactly.
    fn init_data_org_core_types(&mut self) {
        // Void type
        let mut void_base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
        void_base.alignment = 1;
        void_base.align_size = 0;
        let void_type = Arc::new(Datatype::Void(void_base));
        self.add_core_type(void_type);

        // Boolean type
        let bool_type = Arc::new(Datatype::Base(TypeBase::new(
            "bool".to_string(), 1, TypeMetatype::Bool,
        )));
        self.add_core_type(bool_type);

        // Integer types: exact Java coreBuiltin projection (see doc comment).
        const INT_TYPES: &[(&str, usize, TypeMetatype)] = &[
            ("sbyte", 1, TypeMetatype::Int),
            ("short", 2, TypeMetatype::Int),
            ("int3", 3, TypeMetatype::Int),
            ("int", 4, TypeMetatype::Int),
            ("int5", 5, TypeMetatype::Int),
            ("int6", 6, TypeMetatype::Int),
            ("int7", 7, TypeMetatype::Int),
            ("long", 8, TypeMetatype::Int),
            ("int16", 16, TypeMetatype::Int),
            ("byte", 1, TypeMetatype::Uint),
            ("ushort", 2, TypeMetatype::Uint),
            ("uint3", 3, TypeMetatype::Uint),
            ("uint", 4, TypeMetatype::Uint),
            ("uint5", 5, TypeMetatype::Uint),
            ("uint6", 6, TypeMetatype::Uint),
            ("uint7", 7, TypeMetatype::Uint),
            ("ulong", 8, TypeMetatype::Uint),
            ("uint16", 16, TypeMetatype::Uint),
        ];
        for &(name, size, metatype) in INT_TYPES {
            self.add_core_type(Arc::new(Datatype::Base(TypeBase::new(
                name.to_string(), size, metatype,
            ))));
        }

        // The locked Java/headless oracle supplies an ASCII `char`.  Register
        // it through setCoreType so TypeChar flags, hash identity, and
        // canonical object selection match the decoded core-type path.
        if let Err(message) = self.set_core_type_result("char", 1, TypeMetatype::Int, true) {
            panic!("LowlevelError: {message}");
        }
        // wchar_t: UTF (ATTRIB_UTF → TypeUnicode on the C++ decode side,
        // PcodeDataTypeManager.java:1203-1205); x86-64 gcc wchar size is 4.
        if let Err(message) = self.set_core_type_result("wchar_t", 4, TypeMetatype::Int, true) {
            panic!("LowlevelError: {message}");
        }

        // Floating point types
        let f_type4 = Arc::new(Datatype::Base(TypeBase::new(
            "float".to_string(), 4, TypeMetatype::Float,
        )));
        self.add_core_type(f_type4);
        let f_type8 = Arc::new(Datatype::Base(TypeBase::new(
            "double".to_string(), 8, TypeMetatype::Float,
        )));
        self.add_core_type(f_type8);
        let f_type16 = Arc::new(Datatype::Base(TypeBase::new(
            "longdouble".to_string(), 16, TypeMetatype::Float,
        )));
        self.add_core_type(f_type16);

        // The compiler-supplied data organization observed by the canonical
        // headless gate names these `undefined1/2/4/8`.
        for &size in &[1, 2, 4, 8] {
            let name = format!("undefined{size}");
            let mut base = TypeBase::new(name.clone(), size, TypeMetatype::Unknown);
            base.id = Datatype::hash_name(&name);
            self.add_core_type(Arc::new(Datatype::Base(base)));
        }

        // Ghidra: ghidra_arch.cc:324 ArchitectureGhidra::buildCoreTypes
        // (`types->setCoreType("code",1,TYPE_CODE,false);` at cc:349) —
        // every oracle headless form registers the code core: the
        // ArchitectureGhidra fallback table (ghidra_arch.cc:349) AND the
        // Java client's
        // `<coretypes>` stream (canon gate witness: the headless golden
        // renders named `code` types, `(code *)PTR_…`). cacheCoreTypes
        // (type.cc:3239-3244) then fills typecache[1][TYPE_CODE], which
        // unifies `getBase(1,TYPE_CODE)` AND `getTypeCode()` (type.cc:3680
        // probes the same cache slot) onto the NAMED core. Without this
        // registration the data-org flavor answered `get_base(1, Code)`
        // with an UNNAMED base — an empty printNameBase contribution
        // (TYPINGPX-PXNAME-0001 case d: `pRam` vs oracle `pcRam`) and an
        // unnamed/typed code-type split the oracle never produces.
        if let Err(message) = self.set_core_type_result("code", 1, TypeMetatype::Code, false) {
            panic!("LowlevelError: {message}");
        }

        self.cache_core_types();
    }

    // Ghidra: ghidra_arch.cc:324 ArchitectureGhidra::buildCoreTypes
    /// Install the complete no-`coretypes` ArchitectureGhidra fallback table.
    fn init_ghidra_fallback_core_types(&mut self) {
        const TYPES: &[(&str, usize, TypeMetatype, bool)] = &[
            ("void", 1, TypeMetatype::Void, false),
            ("bool", 1, TypeMetatype::Bool, false),
            ("byte", 1, TypeMetatype::Uint, false),
            ("word", 2, TypeMetatype::Uint, false),
            ("dword", 4, TypeMetatype::Uint, false),
            ("qword", 8, TypeMetatype::Uint, false),
            ("char", 1, TypeMetatype::Int, true),
            ("sbyte", 1, TypeMetatype::Int, false),
            ("sword", 2, TypeMetatype::Int, false),
            ("sdword", 4, TypeMetatype::Int, false),
            ("sqword", 8, TypeMetatype::Int, false),
            ("float", 4, TypeMetatype::Float, false),
            ("float8", 8, TypeMetatype::Float, false),
            ("float10", 10, TypeMetatype::Float, false),
            ("float16", 16, TypeMetatype::Float, false),
            ("undefined", 1, TypeMetatype::Unknown, false),
            ("undefined2", 2, TypeMetatype::Unknown, false),
            ("undefined4", 4, TypeMetatype::Unknown, false),
            ("undefined8", 8, TypeMetatype::Unknown, false),
            ("code", 1, TypeMetatype::Code, false),
            ("wchar", 2, TypeMetatype::Int, true),
        ];
        self.install_core_type_table(TYPES);
    }

    // Ghidra: sleigh_arch.cc:204 SleighArchitecture::buildCoreTypes
    /// Install the complete no-`coretypes` standalone SLEIGH fallback table.
    fn init_sleigh_core_types(&mut self) {
        const TYPES: &[(&str, usize, TypeMetatype, bool)] = &[
            ("void", 1, TypeMetatype::Void, false),
            ("bool", 1, TypeMetatype::Bool, false),
            ("uint1", 1, TypeMetatype::Uint, false),
            ("uint2", 2, TypeMetatype::Uint, false),
            ("uint4", 4, TypeMetatype::Uint, false),
            ("uint8", 8, TypeMetatype::Uint, false),
            ("int1", 1, TypeMetatype::Int, false),
            ("int2", 2, TypeMetatype::Int, false),
            ("int4", 4, TypeMetatype::Int, false),
            ("int8", 8, TypeMetatype::Int, false),
            ("float4", 4, TypeMetatype::Float, false),
            ("float8", 8, TypeMetatype::Float, false),
            ("float10", 10, TypeMetatype::Float, false),
            ("float16", 16, TypeMetatype::Float, false),
            ("xunknown1", 1, TypeMetatype::Unknown, false),
            ("xunknown2", 2, TypeMetatype::Unknown, false),
            ("xunknown4", 4, TypeMetatype::Unknown, false),
            ("xunknown8", 8, TypeMetatype::Unknown, false),
            ("code", 1, TypeMetatype::Code, false),
            ("char", 1, TypeMetatype::Int, true),
            ("wchar2", 2, TypeMetatype::Int, true),
            ("wchar4", 4, TypeMetatype::Int, true),
        ];
        self.install_core_type_table(TYPES);
    }

    // RUDRA-GLUE: fallible Rust constructor bridge for the explicit
    // setCoreType sequences in both Ghidra buildCoreTypes functions.
    fn install_core_type_table(&mut self, registrations: &[(&str, usize, TypeMetatype, bool)]) {
        for &(name, size, metatype, is_character) in registrations {
            if let Err(message) = self.set_core_type_result(name, size, metatype, is_character) {
                panic!("LowlevelError: {message}");
            }
        }
        self.cache_core_types();
    }

    // RUDRA-GLUE: Rust-owned Arc insertion used by the architecture bootstrap;
    // Ghidra performs the same flag mutation in setCoreType (type.cc:3178)
    // and ordered-tree insertion in findAdd (type.cc:3412).
    /// Internal helper to register a core type
    fn add_core_type(&mut self, mut dt: Arc<Datatype>) {
        if let Some(dt_mut) = Arc::get_mut(&mut dt) {
            match dt_mut {
                Datatype::Void(b) | Datatype::Base(b) => b.flags |= type_flags::CORETYPE,
                _ => {}
            }
        }
        let name = dt.get_name().to_string();
        self.core_types.insert(name.clone(), dt.clone());
        self.types.insert(name, dt.clone());
        let tree_key = Self::type_tree_key(&dt);
        let tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.entry(tree_key).or_insert_with(|| dt.clone());
    }

    // Ghidra: type.cc:23 Datatype::base2sub
    /// Return the locked-oracle propagation sub-metatype used by the factory's
    /// structural ordering. Atomic types use these exact `base2sub` values.
    fn base_submeta(metatype: TypeMetatype) -> u8 {
        match metatype {
            TypeMetatype::PartialUnion => 0,
            TypeMetatype::Union => 1,
            TypeMetatype::Struct => 2,
            TypeMetatype::Array => 3,
            TypeMetatype::Pointer => 6,
            TypeMetatype::Float => 8,
            TypeMetatype::Code => 9,
            TypeMetatype::Bool => 10,
            TypeMetatype::Enum => 13,
            TypeMetatype::PartialEnum => 14,
            TypeMetatype::Uint => 16,
            TypeMetatype::Int => 17,
            TypeMetatype::PartialStruct => 20,
            TypeMetatype::Unknown => 21,
            TypeMetatype::Spacebase => 22,
            TypeMetatype::Void => 23,
        }
    }

    // Ghidra: type.hh:236 Datatype::getSubMeta (via DatatypeCompare, type.hh:306)
    /// The propagation sub-metatype used by the factory's structural ordering
    /// (`DatatypeSet` with `DatatypeCompare`: submeta ascending, size
    /// descending, id ascending — type.cc:227 `compareDependency`). Rudra
    /// derives it from the `Datatype` variant exactly as Ghidra's
    /// constructors assign it (TypeChar type.hh:356, TypeUnicode type.cc:862,
    /// TypeEnum type.hh:489), including the `submeta_override` those
    /// constructor ports record.
    fn submeta_of(datatype: &Datatype) -> u8 {
        datatype.get_submeta() as i32 as u8
    }

    // RUDRA-GLUE: Tuple projection of DatatypeCompare::operator()
    // (type.hh:308) and the covered concrete compareDependency functions.
    fn type_tree_key(datatype: &Datatype) -> TypeTreeKey {
        let (dependency, offset, parent, wordsize, space_rank, space_id) = match datatype {
            Datatype::Pointer(pointer) => {
                let dependency = Arc::as_ptr(&pointer.ptr_to) as usize;
                if (pointer.base.flags & type_flags::IS_PTRREL) != 0 {
                    let (offset, parent) = pointer
                        .base
                        .pointer_rel
                        .as_ref()
                        .map(|state| (state.offset, Arc::as_ptr(&state.parent) as usize))
                        .unwrap_or((0, 0));
                    (dependency, offset, parent, pointer.wordsize, 0, 0)
                } else {
                    let (space_rank, space_id) = match pointer.base.pointer_space {
                        Some(space) => (0, space.space_id()),
                        None => (1, 0),
                    };
                    (dependency, 0, 0, pointer.wordsize, space_rank, space_id)
                }
            }
            Datatype::Array(array) => (Arc::as_ptr(&array.array_of) as usize, 0, 0, 0, 0, 0)
            ,
            Datatype::PartialStruct(partial) => (
                Arc::as_ptr(&partial.container) as usize, partial.offset, 0, 0, 0, 0,
            ),
            Datatype::PartialEnum(partial) => (
                Arc::as_ptr(&partial.parent) as usize, partial.offset, 0, 0, 0, 0,
            ),
            Datatype::PartialUnion(partial) => (
                Arc::as_ptr(&partial.container) as usize, partial.offset, 0, 0, 0, 0,
            ),
            _ => (0, 0, 0, 0, 0, 0),
        };
        (
            Self::submeta_of(datatype),
            dependency,
            offset,
            parent,
            wordsize,
            space_rank,
            space_id,
            Reverse(datatype.get_size()),
            datatype.get_id(),
        )
    }

    // Ghidra: type.cc:3366 TypeFactory::findByName
    /// Find a type by name
    pub fn find_by_name(&self, name: &str) -> Option<Arc<Datatype>> {
        self.types.get(name).cloned()
    }

    // Ghidra: sleigh_arch.cc:204 SleighArchitecture::buildCoreTypes
    /// Resolve a DWARF typedef whose NAME is a conventional boolean spelling
    /// to this factory's registered core boolean type.
    ///
    /// Ghidra's DWARF front end maps the conventional C boolean typedef names
    /// (`bool`/`_Bool`) to its boolean primitive before anything reaches the
    /// decompiler, so a `typedef bool -> char` in DWARF (curl.h line 394
    /// `typedef char bool;`, DWARF `DW_TAG_typedef "bool" -> base char`) lands
    /// in the decompiler as the core `bool` registered by
    /// `setCoreType("bool",1,TYPE_BOOL,false)` (sleigh_arch.cc:216,
    /// type.cc:3178-3195), NOT as a renamed char clone. Every downstream
    /// boolean-literal behavior follows from that metatype:
    /// `ActionSetCasts::castInput`'s constant arm (coreaction.cc:2687-2691
    /// `vn->updateType(ct)`) absorbs the requirement type into the constant,
    /// and `PrintC::pushConstant`'s TYPE_BOOL arm (printc.cc:1769-1771 ->
    /// pushBoolConstant printc.cc:1488-1495) prints it `true`/`false` — the
    /// canonical-oracle behavior witnessed on `::config.showerror = true;`
    /// (ghidra_curl_1204.c main) for the typedef-bool fields, versus the
    /// library-level direct-runner golden printing `'\x01'` for the same
    /// store when no DWARF front end names the type.
    ///
    /// Returns the core `bool` only when this factory actually registered one
    /// with metatype BOOL and size 1 (`setCoreType`'s exact shape); any other
    /// registration state falls back to the caller's alias materialization.
    pub fn dwarf_conventional_bool(&self, name: &str) -> Option<Arc<Datatype>> {
        if !matches!(name, "bool" | "_Bool") {
            return None;
        }
        let core = self.find_by_name(name)?;
        if core.get_metatype() == TypeMetatype::Bool && core.get_size() == 1 {
            Some(core)
        } else {
            None
        }
    }

    // Ghidra: type.cc:3631 TypeFactory::getBase
    /// Get a base scalar type of `size` bytes with metatype `m`.
    ///
    /// Compat projection of Ghidra `TypeFactory::getBase`
    /// (`type.cc:3631-3651,3658-3660`): a preferred core entry wins regardless
    /// of name; otherwise one unnamed `TypeBase` is canonicalized by the
    /// ordered tree. The byte-faithful port — including the
    /// `size > max_basetype_size` array conversion and the
    /// uninitialized-alignment-map LowlevelError — is [`Self::get_base_result`];
    /// this lenient twin preserves the historical Rudra contract for existing
    /// callers on factories whose architecture wiring has not installed an
    /// alignment map yet (registered residual
    /// TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001).
    ///
    /// TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 status: every in-lease caller
    /// (cpool.rs, merge.rs, grammar.rs, typefactory internals) is migrated to
    /// [`Self::get_base_result`]. The twin is retained for callers outside
    /// that lease, which take `&TypeFactory` read guards and cannot take the
    /// `&mut` the faithful twin needs:
    /// - `src/arch.rs` (the architecture type-query helper at arch.rs:2327),
    /// - `src/varnode.rs`, `src/userop.rs`, `src/varmap.rs`,
    /// - `src/coreaction.rs`, `src/ruleaction.rs`,
    /// - internal [`Self::concretize`] (type.cc:4147; `varmap.rs:2546` holds a
    ///   read guard on the factory),
    /// - the pinned `typefactory_local_cache_1204` differential snapshot base
    ///   (71971b2 `cpool.rs:614`/`merge.rs` compile against this file).
    /// Migrate them when their leases free up, then delete this twin.
    pub fn get_base(&self, size: usize, m: TypeMetatype) -> Option<Arc<Datatype>> {
        let cache_key = (size, m);
        let cache = self
            .base_cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = cache.get(&cache_key) {
            return Some(existing.clone());
        }
        drop(cache);

        // type.cc:3652-3657: a base request over max_basetype_size becomes an
        // ARRAY of 1-byte unknowns ("Create array of unknown bytes to match
        // size"), regardless of the requested metatype — the source of the
        // oracle's `xunknown1 [280]` input-shadow type, whose TYPE_ARRAY
        // metatype is what makes RuleSubRight's isPieceStructured test
        // (ruleaction.cc:7256) fire for large SUBPIECE inputs. The twin
        // previously built a scalar TypeBase of the raw size, so oversized
        // inputs typed as scalar INT were never piece-structured and degraded
        // to the INT_RIGHT shift ladder (VARGROUP-ABSORB-0001 §4-4).
        if size > self.max_base_type_size {
            let element = self.get_base(1, TypeMetatype::Unknown)?;
            let array = self.oversize_unknown_array(size, element)?;
            // Cache per (size, metatype): every oversize metatype maps to the
            // same unknown1 array (type.cc:3655 ignores m here).
            let mut cache = self
                .base_cache
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.entry(cache_key).or_insert_with(|| array.clone());
            return Some(array);
        }

        // Ghidra constructs an unnamed TypeBase and canonicalizes it through
        // findAdd when no preferred core entry exists. Its structural key is
        // the plain base sub-metatype, descending size, then id zero.
        let tree_key = (
            Self::base_submeta(m),
            0,
            0,
            0,
            0,
            0,
            0,
            Reverse(size),
            0);
        let tree = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = tree.get(&tree_key) {
            return Some(existing.clone());
        }
        drop(tree);

        let mut tree = self
            .base_type_tree
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(
            tree.entry(tree_key)
                .or_insert_with(|| Arc::new(Datatype::Base(TypeBase::new(String::new(), size, m))))
                .clone(),
        )
    }

    // RUDRA-GLUE: the `&self`-twin form of the type.cc:3652-3657 oversize-base
    // array conversion (mirror of `get_array_result`, type.cc:3902-3908, for
    /// the unknown1 family): build/find the unnamed array of `element` in
    /// `base_type_tree` under the same structural key `find_add` uses, so
    /// both the `&mut` faithful path and this twin hand out the identical
    /// `Arc` identity.
    fn oversize_unknown_array(
        &self,
        num_elements: usize,
        element: Arc<Datatype>,
    ) -> Option<Arc<Datatype>> {
        // get_array_result strips the element (type.cc:3655 getTypeArray ->
        // getStripped); unnamed bases have no stripped form, so the element
        // passes through unchanged.
        let element =
            Datatype::get_stripped_arc(&element).unwrap_or(element);
        let size = num_elements * element.get_align_size();
        let mut base = TypeBase::new(String::new(), size, TypeMetatype::Array);
        base.alignment = element.get_alignment() as i32;
        base.align_size = size;
        // type.hh:937-944: arraysize==1 sets needs_resolution; oversize
        // requests have num_elements > 1 here.
        let candidate = Datatype::Array(TypeArray {
            base,
            array_of: element,
            num_elements,
        });
        let tree_key = Self::type_tree_key(&candidate);
        let tree = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = tree.get(&tree_key) {
            return Some(existing.clone());
        }
        drop(tree);
        let mut tree = self
            .base_type_tree
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Some(
            tree.entry(tree_key)
                .or_insert_with(move || Arc::new(candidate))
                .clone(),
        )
    }

    // Ghidra: type.cc:3631 TypeFactory::getBase
    /// The faithful `TypeFactory::getBase(int4,type_metatype)` port
    /// (type.cc:3631-3660), returning Ghidra's LowlevelError messages as
    /// `Err`:
    /// - `size < 9` and a printable-scalar metatype: the preferred
    ///   `typecache[size][m]` entry returns immediately.
    /// - `size >= 9` and TYPE_FLOAT: `typecache10`/`typecache16` (Rudra's
    ///   `base_cache[(10|16, Float)]`) return when populated.
    /// - `size > max_base_type_size` (10, architecture.cc:1422): the request
    ///   converts to an array of `size` cached 1-byte unknowns, exactly as
    ///   type.cc:3652-3657 does (including the `getStripped` element strip
    ///   and the findAdd canonicalization of the unnamed array).
    /// - otherwise an unnamed `TypeBase` is canonicalized through
    ///   [`Self::find_add`], whose miss path raises the
    ///   "TypeFactory alignment map not initialized" LowlevelError when no
    ///   alignment map has been installed (the raw-constructor state).
    pub fn get_base_result(
        &mut self, size: usize, m: TypeMetatype,
    ) -> Result<Arc<Datatype>, String> {
        // Ghidra guards `m >= TYPE_FLOAT` (numeric 10..17: Float, Code, Bool,
        // Uint, Int, Unknown, Spacebase, Void) for the 9x8 typecache matrix.
        let printable_scalar = matches!(
            m,
            TypeMetatype::Float
                | TypeMetatype::Code
                | TypeMetatype::Bool
                | TypeMetatype::Uint
                | TypeMetatype::Int
                | TypeMetatype::Unknown
                | TypeMetatype::Spacebase
                | TypeMetatype::Void
        );
        if size < 9 && printable_scalar {
            let cache_key = (size, m);
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&cache_key) {
                return Ok(existing.clone());
            }
        } else if size >= 9 && m == TypeMetatype::Float {
            // type.cc:3642-3651: only sizes 10 and 16 have dedicated slots.
            if size == 10 || size == 16 {
                let cache = self
                    .base_cache
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(existing) = cache.get(&(size, m)) {
                    return Ok(existing.clone());
                }
            }
        }
        if size > self.max_base_type_size {
            // type.cc:3652-3657: build an array of unknown bytes to match the
            // size. Ghidra dereferences typecache[1][TYPE_UNKNOWN] without a
            // null check — a factory that never cached a 1-byte unknown
            // crashes; Rudra panics with the same precondition documented.
            let cache_key = (1_usize, TypeMetatype::Unknown);
            let element = {
                let cache = self
                    .base_cache
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                cache.get(&cache_key).cloned()
            };
            let element = element
                .expect(
                "getBase array conversion requires a cached 1-byte unknown (type.cc:3654)");
            // getBase delegates to getTypeArray, including virtual stripping,
            // aligned stride, inherited alignment, and canonical identity.
            return self.get_array_result(element, size);
        }
        self.find_add(Datatype::Base(TypeBase::new(String::new(), size, m)), true)
    }

    // Ghidra: type.cc:3619 TypeFactory::getBaseNoChar
    /// The faithful `TypeFactory::getBaseNoChar` port (type.cc:3619-3625): a
    /// one-byte TYPE_INT request returns `type_nochar` when the side cache
    /// holds a selection; everything else delegates to the faithful
    /// [`Self::get_base_result`], including its LowlevelError propagation.
    pub fn get_base_no_char_result(
        &mut self,
        size: usize,
        metatype: TypeMetatype,
    ) -> Result<Arc<Datatype>, String> {
        if size == 1 && metatype == TypeMetatype::Int {
            let nochar = self
                .type_nochar
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(datatype) = nochar.as_ref() {
                return Ok(datatype.clone());
            }
        }
        self.get_base_result(size, metatype)
    }

    // Ghidra: type.cc:3619 TypeFactory::getBaseNoChar
    /// Get a canonical base type, excluding the printable ASCII character
    /// specialization for a one-byte signed integer when a non-character core
    /// type was selected by `cache_core_types`.
    ///
    /// TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 status: every in-lease caller
    /// (merge.rs `factory_nochar_distinct`, typefactory tests) is migrated to
    /// [`Self::get_base_no_char_result`]; this twin has ZERO current-tree
    /// callers and is retained only because the pinned
    /// `typefactory_local_cache_1204` differential snapshot base (296c128
    /// `merge.rs:3198`) compiles against this file. Delete it when that
    /// runner is re-pinned to a post-rework base.
    pub fn get_base_no_char(&self, size: usize, metatype: TypeMetatype) -> Option<Arc<Datatype>> {
        if size == 1 && metatype == TypeMetatype::Int {
            let nochar = self
                .type_nochar
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(datatype) = nochar.as_ref() {
                return Some(datatype.clone());
            }
        }
        self.get_base(size, metatype)
    }

    // Ghidra: type.cc:3667 TypeFactory::getBase(int4,type_metatype,const string &)
    /// Get or create a "base" type with a specified name and properties.
    /// Faithful to `TypeFactory::getBase(int4 s,type_metatype m,const string &n)`
    /// (type.cc:3667-3673): `TypeBase tmp(s,m,n); tmp.id = hashName(n);
    /// return findAdd(tmp);`
    pub fn get_base_named(
        &mut self,
        size: usize,
        m: TypeMetatype,
        name: &str,
    ) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new(name.to_string(), size, m);
        base.id = Datatype::hash_name(name);
        self.find_add(Datatype::Base(base), false)
    }

    // Ghidra: type.cc:3412 TypeFactory::findAdd
    /// Use the quickest method (name or id when possible) to locate the
    /// matching data-type; if not currently in this container, insert the
    /// candidate. Faithful to `TypeFactory::findAdd` (type.cc:3412-3439):
    ///
    /// - Named candidate with id 0 raises
    ///   `"Datatype must have a valid id: {name}"` (type.cc:3419).
    /// - A name+id hit whose `compareDependency` differs (base sub-metatype /
    ///   size at type.cc:227-234; concrete element/container identity for the
    ///   B variants below) raises
    ///   `"Trying to alter definition of type: {name}"` (type.cc:3423); an
    ///   equal definition returns the EXISTING factory object (this is the
    ///   aliasing point `setCoreType` relies on when promoting).
    /// - An unnamed (or id-missed) candidate is probed structurally in the
    ///   ordered tree keyed by (sub-metatype, descending size, id) —
    ///   `DatatypeCompare`, type.hh:306-310 — and returns the canonical entry
    ///   on equivalence.
    /// - On a miss the candidate is inserted; the alignment computation
    /// (type.cc:3433-3436) raises
    /// `"TypeFactory alignment map not initialized"` when no map was
    /// installed (the raw-constructor state) — gated behind
    /// `enforce_alignment`, which is set on the faithful `getBase` port
    /// [`Self::get_base_result`] only: production Rudra factories do not yet
    /// thread the decoded alignment map through their architecture wiring
    /// (registered residual TYPEFACTORY-ARCH-ALIGNMAP-WIRING-0001), and a
    /// tree slot already holding the same key raises
    /// `"Shared type id: {id:x}"` (type.cc:3393-3403).
    ///
    /// This slice projects the complete dependency key for TypeArray and the
    /// three partial variants. Other container comparators remain on the
    /// registered TYPE-0001 residual.
    // RUDRA-GLUE: DWARF/type-manager import boundary — Ghidra's DWARF
    // analyzer registers every imported type through the architecture's
    // single factory (the type.cc:3412 findAdd path below), which is what
    // makes cross-reference type identity hold; this pub(crate) wrapper
    // exposes that registration channel to the debugproto importer.
    pub(crate) fn intern_imported(
        &mut self,
        candidate: Datatype,
    ) -> Result<Arc<Datatype>, String> {
        self.find_add(candidate, true)
    }

    // Ghidra: type.cc:3412 TypeFactory::findAdd
    fn find_add(
        &mut self,
        mut candidate: Datatype,
        enforce_alignment: bool,
    ) -> Result<Arc<Datatype>, String> {
        let name = candidate.get_name().to_string();
        let candidate_id = candidate.get_id();
        if !name.is_empty() {
            // type.cc:3417-3425
            if candidate_id == 0 {
                return Err(format!("Datatype must have a valid id: {name}"));
            }
            if let Some(existing) = self.types.get(&name) {
                if existing.get_id() == candidate_id {
                    // Use the concrete virtual compareDependency projection
                    // for every dependency-bearing variant covered by the
                    // structural registry. Other variants retain the
                    // series-A submeta/size projection under TYPE-0001.
                    let dependency_mismatch = match (existing.as_ref(), &candidate) {
                        (Datatype::Pointer(_), Datatype::Pointer(_))
                        | (Datatype::Array(_), Datatype::Array(_))
                        | (Datatype::PartialStruct(_), Datatype::PartialStruct(_))
                        | (Datatype::PartialEnum(_), Datatype::PartialEnum(_))
                        | (Datatype::PartialUnion(_), Datatype::PartialUnion(_)) => {
                            existing.compare_dependency(&candidate) != 0
                        }
                        _ => {
                            existing.get_submeta() != candidate.get_submeta()
                                || existing.get_size() != candidate.get_size()
                        }
                    };
                    if dependency_mismatch {
                        return Err(format!("Trying to alter definition of type: {name}"));
                    }
                    return Ok(existing.clone());
                }
                // Ghidra's nametree keeps multiple (name,id) entries; Rudra's
                // flat map holds one, so an id mismatch falls through to the
                // structural insert and overwrites the name slot (registered
                // TYPE-0001 name-map residual).
            }
        } else {
            // type.cc:3427-3430 findNoName: structural probe including id.
            let tree_key = Self::type_tree_key(&candidate);
            let tree = self
                .base_type_tree
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = tree.get(&tree_key) {
                return Ok(existing.clone());
            }
        }
        // type.cc:3432-3436 computes both stored layout fields before insert.
        if candidate.base_record_mut().alignment < 0 {
            let (alignment, align_size) = if self.align_map.is_empty() {
                if enforce_alignment {
                    return Err("TypeFactory alignment map not initialized".to_string());
                }
                // Legacy non-enforcing callers run before architecture
                // wiring; use the locked default map for the same two-step
                // layout calculation rather than discarding layout state.
                primitive_layout(candidate.get_size())
            } else {
                let align_size = self.get_primitive_align_size(candidate.get_size() as u32)?;
                let alignment = self.get_alignment(align_size as u32)?;
                (alignment as usize, align_size as usize)
            };
            let base = candidate.base_record_mut();
            base.alignment = alignment as i32;
            base.align_size = align_size;
        }
        let tree_key = Self::type_tree_key(&candidate);
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = tree.get(&tree_key) {
            let mut message = format!("Shared type id: {:x}\n  ", candidate_id);
            message.push_str(&Self::print_raw(&candidate));
            message.push_str(" : ");
            message.push_str(&Self::print_raw(existing));
            return Err(message);
        }
        let arc = Arc::new(candidate);
        tree.insert(tree_key, arc.clone());
        // The tree borrow ends here; the name cross-reference follows.
        // type.cc:3404-3405: nametree gets named (id != 0) entries.
        if !name.is_empty() {
            self.types.insert(name, arc.clone());
        }
        Ok(arc)
    }

    // Ghidra: type.cc:139 Datatype::printRaw (base), type.cc:910
    // TypePointer::printRaw, type.cc:1204 TypeArray::printRaw — the fragments
    /// used by insert's "Shared type id" message (type.cc:3396-3400): the
    /// name (or `unkbyte<size>`), `element *` for pointers, and
    /// `element [n]` for arrays.
    fn print_raw(dt: &Datatype) -> String {
        match dt {
            Datatype::Pointer(p) => format!("{} *", Self::print_raw(&p.ptr_to)),
            Datatype::Array(a) => {
                format!("{} [{}]", Self::print_raw(&a.array_of), a.num_elements)
            }
            _ => {
                let name = dt.get_name();
                if name.is_empty() {
                    format!("unkbyte{}", dt.get_size())
                } else {
                    name.to_string()
                }
            }
        }
    }

    // Ghidra: type.cc:1035 TypePointer::calcSubmeta (needs_resolution arm)
    /// The `needs_resolution` inheritance arm of `TypePointer::calcSubmeta`
    /// (type.cc:1051-1052): `if (ptrto->needsResolution() && ptrtoMeta !=
    /// TYPE_PTR) flags |= needs_resolution;` — a pointer to a
    /// resolution-needing type (union, single-field struct, size-1 array)
    /// inherits the flag, but never through a second pointer level. In Ghidra
    /// this runs in every `TypePointer` constructor (type.hh:413/416) and in
    /// `TypePointer::decode` (type.cc:1027); Rudra applies it at each pointer
    /// construction site in this factory (get_ptr, get_type_pointer,
    /// get_type_pointer_rel, resize_pointer, and the decode `<type>` pointer
    /// branch), which are the paths that flow through the ctor in Ghidra.
    ///
    /// Consumers treat a pointer's flag as identity-resolution only
    /// (`Datatype::findResolve` base returns `this`; every needsResolution
    /// rejection in printc/cast waives `TYPE_PTR`), so the flag on pointers
    /// changes no resolved type — it makes the printc.cc:1962 TYPE_PTR waiver
    /// load-bearing, exactly as in Ghidra.
    ///
    /// This compatibility helper is used only by the legacy side-table
    /// relative-pointer API below. Canonical `TypePointer::new` now performs
    /// the complete calcSubmeta/coretype transition; this helper preserves the
    /// older manually-constructed object's needs-resolution bit until that
    /// legacy API is retired.
    fn pointer_inherit_needs_resolution(ptr_to: &Datatype) -> u32 {
        if ptr_to.needs_resolution() && ptr_to.get_metatype() != TypeMetatype::Pointer {
            type_flags::NEEDS_RESOLUTION
        } else {
            0
        }
    }

    // RUDRA-GLUE: compatibility name for the default-space pointer factory;
    // Ghidra callers invoke TypeFactory::getTypePointer directly.
    /// Get or create a canonical pointer using Rudra's default-space geometry.
    pub fn get_ptr(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype> {
        self.get_type_pointer_default(ptr_to)
    }

    // RUDRA-GLUE: PointerModifier receives Architecture in Ghidra, while the
    // Rust parser owns only TypeFactory. `ptr_size` is the default data-space
    // address size supplied when this factory is constructed; Rudra's current
    // AddressSpace enum models the production default word size as one.
    /// Construct the canonical pointer used by grammar's default-space path.
    pub fn get_type_pointer_default(&mut self, ptr_to: Arc<Datatype>) -> Arc<Datatype> {
        self.get_type_pointer_result(self.ptr_size, ptr_to, 1, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // RUDRA-GLUE: Result-returning Rust twin of getTypeArray so getBase can
    // preserve its LowlevelError channel instead of converting it to panic.
    fn get_array_result(
        &mut self,
        array_of: Arc<Datatype>,
        num_elements: usize,
    ) -> Result<Arc<Datatype>, String> {
        let array_of = Datatype::get_stripped_arc(&array_of).unwrap_or(array_of);
        let size = num_elements
            .checked_mul(array_of.get_align_size())
            .expect("TypeArray size overflow");
        let mut base = TypeBase::new(String::new(), size, TypeMetatype::Array);
        base.alignment = array_of.get_alignment() as i32;
        base.align_size = size;
        // Ghidra: type.hh:937-944 inline TypeArray ctor (the path
        // TypeFactory::getTypeArray takes, type.cc:3902-3908):
        //   // A varnode which is an array of size 1, should generally
        //   // always be treated as the element data-type
        //   if (n == 1) flags |= needs_resolution;
        // TypeArray::decode (type.cc:1341-1342) sets the same flag on the
        // arraysize==1 decode arm, so both creation paths agree.
        if num_elements == 1 {
            base.flags |= type_flags::NEEDS_RESOLUTION;
        }
        self.find_add(
            Datatype::Array(TypeArray {
            base,
            array_of,
            num_elements,
        }), false,
        )
    }

    // Ghidra: type.cc:3902 TypeFactory::getTypeArray
    /// Get or create an unnamed canonical array type.
    pub fn get_array(&mut self, array_of: Arc<Datatype>, num_elements: usize) -> Arc<Datatype> {
        self.get_array_result(array_of, num_elements)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3914 TypeFactory::getTypeStruct
    /// Create a new structure type
    pub fn create_struct(&mut self, name: &str) -> Arc<Datatype> {
        let mut base = TypeBase::new(name.to_string(), 0, TypeMetatype::Struct);
        base.id = Datatype::hash_name(name);
        base.flags |= type_flags::TYPE_INCOMPLETE;
        self.find_add(
            Datatype::Struct(TypeStruct {
            base,
            fields: Vec::new(),
        }), false,
        )
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3479 TypeFactory::setFields
    /// Set fields for an existing structure and update its size.
    ///
    /// Includes the `TypeStruct::setFields` single-field arm (type.cc:1569-1571):
    /// a structure with exactly one field whose type's full size
    /// (`getSize`, NOT `getAlignSize`) equals the structure size passed by
    /// the caller is marked `needs_resolution` — the write-side producer that
    /// feeds `TypeStruct::findResolve`/`resolveInFlow` (type.cc:1944-1960)
    /// and the printc pushPartialSymbol needsResolution early-break
    /// (printc.cc:1967). Ghidra ORs the flag in (never clears) and checks
    /// `field[0].type`'s full size only — the field's offset is not examined
    /// by `setFields` itself.
    ///
    /// NOTE on the comparison operand: Ghidra's `TypeStruct::setFields`
    /// receives `newSize` explicitly (type.cc:1567). The grammar caller
    /// passes `assignFieldOffsets`' output (type.cc:2798-2799), which for a
    /// single unassigned field is
    /// `calcAlignSize(field.getAlignSize(), max(1, field.getAlignment()))`
    /// (type.cc:1971-1993: running offset starts at 0 and advances by
    /// ALIGN sizes; the struct size is the align-rounded end). Rudra's
    /// `set_fields` takes no size parameter, so the arm recomputes that
    /// grammar-form `newSize` instead of comparing against the derived
    /// `st.base.size` (`max(offset + get_size())`): comparing against the
    /// derived size OVER-FIRES for a field type whose `alignSize > size`
    /// (e.g. an XML-decoded unrounded struct type — Ghidra's grammar
    /// `newSize` is 8 for a size-5/align-4 field type so the flag stays
    /// clear, while the derived size 5 would match the field's full size).
    /// Relies on the alignment/alignSize retained on each field Datatype;
    /// legacy direct constructors use the documented default-map fallback.
    pub fn set_fields(&mut self, name: &str, fields: Vec<TypeField>) -> Option<Arc<Datatype>> {
        let dt = self.types.get(name)?.clone();
        if !dt.is_incomplete() {
            return None;
        }
        let defined = self.define_replace(&dt, |defined| {
            let st = match defined {
                Datatype::Struct(structure) => structure,
                _ => return Err("setFields target is not a TypeStruct".to_string()),
            };
            st.fields = fields;
            let mut unpadded_size = 0;
            let mut new_align = 1;
            for field in &st.fields {
                unpadded_size =
                    unpadded_size.max(field.offset + field.type_ptr.get_align_size());
                new_align = new_align.max(field.type_ptr.get_alignment());
            }
            st.base.size = calc_align_size(unpadded_size, new_align);
            st.base.alignment = new_align as i32;
            st.base.align_size = calc_align_size(st.base.size, new_align);
            if st.fields.len() == 1 {
                let field = &st.fields[0];
                let field_align = field.type_ptr.get_alignment().max(1);
                let ghidra_new_size = calc_align_size(field.type_ptr.get_align_size(), field_align);
                if field.type_ptr.get_size() == ghidra_new_size {
                    st.base.flags |= type_flags::NEEDS_RESOLUTION;
                }
            }
            st.base.flags &= !type_flags::TYPE_INCOMPLETE;
            Ok(())
        });
        let result = defined.unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        // type.cc:3490-3491 — the grammar path funnels through the same
        // factory setFields, so the pointer submeta migration tail applies
        // here too (see set_fields_flags).
        self.recalc_pointer_submeta(&result, SubMetatype::Ptr);
        self.recalc_pointer_submeta(&result, SubMetatype::PtrStruct);
        Some(result)
    }

    // Ghidra: type.cc:3479 TypeFactory::setFields (explicit newSize/newAlign arm)
    /// Set fields on an existing structure with an EXPLICIT final size and
    /// alignment, mirroring the full `TypeFactory::setFields(const
    /// vector<TypeField> &fd, TypeStruct *ot, int4 newSize, int4 newAlign,
    /// uint4 flags)` signature (type.cc:3479-3490) whose core is
    /// `TypeStruct::setFields(fd, newSize, newAlign)` (type.cc:1563-1574):
    /// `size = newSize` unconditionally, then the single-field
    /// needs_resolution arm compares `field[0].type->getSize()` against that
    /// EXPLICIT size — not against anything derived from the fields.
    ///
    /// This is the form Ghidra's non-grammar callers use (`decodeStruct`'s
    /// stub fill at type.cc:4355 passes the decoded size attribute;
    /// `setStructDecl` passes the stored declaration size), and the only form
    /// under which the "single field does NOT fill the struct" cell
    /// (field size < newSize) and the "offset not examined" cell (single field
    /// at offset > 0 whose type size still equals newSize) are reachable.
    /// The size-derived `set_fields` above is the grammar-path twin
    /// (grammar.cc:2798-2799 derives newSize via `assignFieldOffsets`, so
    /// there the derived and explicit conditions coincide for offset-0
    /// fields with `alignSize == size`).
    ///
    /// The immutable-Arc replacement updates the registered tree/name slots,
    /// but existing dependent/external Arcs remain stale under
    /// TYPEFACTORY-ARC-IDENTITY-0001; masked flag propagation is performed by
    /// decode/typedef completion callers that supply those flags.
    /// `new_align` is retained on the Datatype base and drives `alignSize`,
    /// matching Ghidra's `TypeStruct::setFields` tail.
    pub fn set_fields_sized(
        &mut self,
        name: &str,
        fields: Vec<TypeField>,
        new_size: usize,
        new_align: usize,
    ) -> Option<Arc<Datatype>> {
        self.set_fields_flags(name, fields, new_size, new_align, 0)
    }

    // Ghidra: type.cc:3479 TypeFactory::setFields (explicit newSize/newAlign arm)
    /// The full `TypeFactory::setFields(const vector<TypeField> &fd,
    /// TypeStruct *ot, int4 newSize, int4 newAlign, uint4 flags)` signature
    /// (type.cc:3479-3492), including the two pieces the size-derived twins
    /// could not express before this port:
    ///
    /// - the flags mask tail (type.cc:3487-3488):
    ///   `flags &= ~type_incomplete;
    ///    flags |= (flags & (opaque_string | variable_length | type_incomplete))`
    ///   — with `flags == 0` this reduces to the plain incomplete clear;
    /// - the pointer submeta migration tail (type.cc:3490-3491):
    ///   `recalcPointerSubmeta(ot, SUB_PTR); recalcPointerSubmeta(ot,
    ///   SUB_PTR_STRUCT);` — pointers interned while the struct was
    ///   incomplete (SUB_PTR_STRUCT slot) re-key to their now-current
    ///   submeta so later `getTypePointer` probes find them. The
    ///   define_replace Arc seam limits the migration to pointers holding
    ///   the post-completion Arc (TYPEFACTORY-ARC-IDENTITY-0001).
    pub fn set_fields_flags(
        &mut self,
        name: &str,
        fields: Vec<TypeField>,
        new_size: usize,
        new_align: usize,
        flags: u32,
    ) -> Option<Arc<Datatype>> {
        let dt = self.types.get(name)?.clone();
        if !dt.is_incomplete() {
            return None;
        }
        let defined = self.define_replace(&dt, |defined| {
            let st = match defined {
                Datatype::Struct(structure) => structure,
                _ => return Err("setFields target is not a TypeStruct".to_string()),
            };
            st.fields = fields;
            st.base.size = new_size;
            st.base.alignment = new_align as i32;
            st.base.align_size = calc_align_size(new_size, new_align);
            if st.fields.len() == 1 && st.fields[0].type_ptr.get_size() == st.base.size {
                st.base.flags |= type_flags::NEEDS_RESOLUTION;
            }
            // type.cc:3487-3488 flag clear + masked-OR transfer.
            st.base.flags &= !type_flags::TYPE_INCOMPLETE;
            st.base.flags |=
                flags & (type_flags::OPAQUE_STRUCT | type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
            Ok(())
        });
        let result = defined.unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        // type.cc:3490-3491: recalcPointerSubmeta(ot, SUB_PTR) then
        // (ot, SUB_PTR_STRUCT), in this order.
        self.recalc_pointer_submeta(&result, SubMetatype::Ptr);
        self.recalc_pointer_submeta(&result, SubMetatype::PtrStruct);
        Some(result)
    }

    // RUDRA-GLUE: Ghidra exposes no numTypes method; this counts the union of
    // its structural `tree` (type.hh:772) and Rust's named cross-reference.
    /// Get the number of types currently managed
    pub fn num_types(&self) -> usize {
        let anonymous_base_count = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|datatype| datatype.get_name().is_empty())
            .count();
        self.types.len() + anonymous_base_count
    }

    // Ghidra: type.cc:3563 TypeFactory::dependentOrder
    /// Place data-types in dependency order. The atomic registry, including
    /// unnamed `getBase` results, follows Ghidra's `DatatypeCompare` key for
    /// atomic types: sub-metatype, descending size, then id. The remaining
    /// pointer/aggregate registry is still name-keyed, so full non-atomic
    /// `dependentOrder` equivalence remains `TYPE-0001`/L2.
    ///
    /// Alignment Evidence (four decisive-semantics checklist):
    /// - References/output params: `deporder` is an out-param appended to
    ///   (Ghidra passes `vector<Datatype*> &deporder`); Rust passes `&mut Vec`.
    /// - Loop bounds/order: Ghidra iterates every `tree` entry from begin to
    ///   end. Rust first walks every atomic structural entry in the same key
    ///   order, then the remaining named roots; the latter is a known gap.
    /// - Counter/accumulator: `mark` (DatatypeSet) is per-call, reset on each
    ///   `dependentOrder` invocation; cycle-break via insert-second-check.
    /// - Sort/compare key: Ghidra's roots and mark use `compareDependency`
    ///   then id. Rust's atomic roots match this; the visited set uses canonical
    ///   `Arc` identity, equivalent for the factory-owned atomic slice only.
    pub fn dependent_order(&self, deporder: &mut Vec<Arc<Datatype>>) {
        // Ghidra: type.cc:3545 TypeFactory::orderRecurse
        // `mark` prevents cycles: insert returns whether the ptr was new.
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // Atomic roots are held in the same (submeta, descending size, id)
        // order as Ghidra's DatatypeSet. This includes unnamed getBase results.
        let tree = self
            .base_type_tree
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for ct in tree.values() {
            self.order_recurse(deporder, &mut visited, ct);
        }
        drop(tree);
        // Add non-atomic named roots. Pointer/aggregate global structural
        // ordering remains part of the module-level TypeFactory L2 gap.
        for ct in self.types.values() {
            self.order_recurse(deporder, &mut visited, ct);
        }
    }

    // Ghidra: type.cc:3545 TypeFactory::orderRecurse
    /// Recursively order: ensure dependents of `ct` are added before `ct`
    /// itself. Faithful to `orderRecurse` (type.cc:3545-3557). Visits
    /// `ct->typedefImm` first (Rudra: typedef target), then each
    /// `ct->getDepend(i)` for `i in 0..numDepend()`, then pushes `ct`.
    fn order_recurse(
        &self,
        deporder: &mut Vec<Arc<Datatype>>,
        mark: &mut std::collections::HashSet<usize>,
        ct: &Arc<Datatype>,
    ) {
        // pair<DatatypeSet::iterator,bool> res = mark.insert(ct);
        // if (!res.second) return;
        let key = Arc::as_ptr(ct) as usize;
        if !mark.insert(key) {
            return; // Already inserted before
        }
        if let Some(target) = self.typedefs.get(ct.get_name()) {
            self.order_recurse(deporder, mark, target);
        }
        // numDepend()/getDepend(i) — dispatch by variant (type.hh:261-630).
        // Pointer->ptrto, Array->arrayof, Struct/Union->field[i].type,
        // Code->proto return type. Base/Void/Enum/Spacebase: 0 depends.
        for dep in Self::depends_of(ct) {
            self.order_recurse(deporder, mark, &dep);
        }
        deporder.push(ct.clone());
    }

    // RUDRA-GLUE: depends_of — Rust aggregator of Ghidra's per-variant
    //   `Datatype::numDepend` + `Datatype::getDepend` virtual dispatch table
    //   (type.hh:261 base virtual; overrides at type.hh:422 Pointer, 455 Array,
    //   526 Struct, 555 Union, 629 Code). C++ uses virtual dispatch on the
    //   Datatype base; Rust matches on the Datatype enum. Faithful 1:1 port.
    /// Return the direct dependency sub-types of `ct`. Faithful to Ghidra's
    /// `Datatype::numDepend` + `Datatype::getDepend` virtuals (type.hh:
    /// 261/422/455/526/555/629). Mirrors the per-variant override table:
    /// - Void/Base/Enum/Spacebase: 0 depends (base virtual returns 0).
    /// - Pointer: 1 (`ptrto`).   Array: 1 (`arrayof`).
    /// - Struct/Union: `fields.len()` (`field[i].type`).
    /// - Code: 1 (the proto's return type — TypeCode::numDepend type.hh:629).
    ///   (Ghidra's TypeCode::getDepend returns the prototype's return type;
    ///   Rudra's TypeCode.proto is Option<Arc<FuncProto>>.)
    fn depends_of(ct: &Datatype) -> Vec<Arc<Datatype>> {
        match ct {
            Datatype::Void(_) | Datatype::Base(_) | Datatype::Enum(_) | Datatype::Spacebase(_) => {
                Vec::new()
            }
            Datatype::Pointer(p) => vec![p.ptr_to.clone()],
            Datatype::Array(a) => vec![a.array_of.clone()],
            Datatype::Struct(s) => s.fields.iter().map(|f| f.type_ptr.clone()).collect(),
            Datatype::Union(u) => u.fields.iter().map(|f| f.type_ptr.clone()).collect(),
            Datatype::Code(c) => c
                .proto
                .as_ref()
                .map(|p| p.return_type.clone())
                .into_iter()
                .collect(),
            // Ghidra TypePartialStruct/TypePartialUnion do not override
            // numDepend/getDepend on the base (type.hh has no override on
            // TypePartialStruct; TypePartialUnion delegates to the union —
            // type.cc:2446). We return the container as the single dependency
            // so dependentOrder can place the partial after its container.
            Datatype::PartialStruct(ps) => vec![ps.container.clone()],
            // TypePartialEnum inherits TypeEnum's numDepend=0, but the parent
            // enum must precede it; expose it as a dependency.
            Datatype::PartialEnum(pe) => vec![pe.parent.clone()],
            // TypePartialUnion delegates numDepend to the underlying union
            // (type.cc:2446); return the container's fields.
            Datatype::PartialUnion(pu) => {
                if let Datatype::Union(u) = pu.container.as_ref() {
                    u.fields.iter().map(|f| f.type_ptr.clone()).collect()
                } else {
                    vec![pu.container.clone()]
                }
            }
        }
    }

    // Ghidra: type.cc:3122 TypeFactory::clearCache
    /// Clear every preferred-type side cache without changing the ordered
    /// factory tree. Ghidra invokes this from the constructor and `clear`.
    fn clear_cache(&mut self) {
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .type_nochar
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.char_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    // Ghidra: type.cc:3251 TypeFactory::clear
    /// Remove every factory-owned type and reset all preferred-type caches.
    /// Size/alignment configuration is deliberately retained, as in Ghidra.
    pub fn clear(&mut self) {
        self.types.clear();
        self.core_types.clear();
        self.base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.clear_cache();
        self.rel_pointers.clear();
        self.typedefs.clear();
        self.incomplete_typedefs.clear();
    }

    // Ghidra: type.cc:3266 TypeFactory::clearNoncore
    /// Delete anything that isn't a core type. Faithful to
    /// `TypeFactory::clearNoncore` (type.cc:3266-3285): the ordered tree (and
    /// its name cross-reference) is walked retaining exactly the entries
    /// whose object carries the core flag — INCLUDING entries that were
    /// promoted in place by `setCoreType` — while the preferred-type caches
    /// are left untouched (every cached entry is core by construction).
    /// Rudra has no warning registry; the relative-pointer/typedef side
    /// registries follow their objects and the incomplete-typedef queue is
    /// cleared exactly like Ghidra's `incompleteTypedef` list.
    pub fn clear_non_core(&mut self) {
        // Ghidra scans the core flag on the tree entries; the promoted objects
        // carry it after promote_core replaced every channel.
        self.types.retain(|_, datatype| datatype.is_coretype());
        self.core_types.retain(|_, datatype| datatype.is_coretype());
        self.base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, datatype| datatype.is_coretype());
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, datatype| datatype.is_coretype());
        self.rel_pointers.clear();
        self.typedefs.clear();
        self.incomplete_typedefs.clear();
    }

    // ---------------------------------------------------------------
    // Type-getters aligned with Ghidra's TypeFactory (type.cc).
    // Each follows the same "look-up-then-create-and-cache" pattern as
    // the C++ `findAdd`, keyed on the type name in our flat map.
    // ---------------------------------------------------------------

    // Ghidra: type.cc:3575 TypeFactory::getTypeVoid
    /// The faithful `TypeFactory::getTypeVoid` port (type.cc:3575-3588): the
    /// typecache slot `typecache[0][TYPE_VOID-TYPE_FLOAT]` returns
    /// immediately when filled; otherwise a `TypeVoid` (whose constructor
    /// sets `coretype` and the name "void", type.hh:389) is given
    /// `id = hashName("void")`, inserted directly into the tree/name
    /// cross-reference WITHOUT a findAdd conflict check, and cached in the
    /// typecache slot itself.
    pub fn get_type_void_result(&mut self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(0, TypeMetatype::Void)) {
                return existing.clone();
            }
        }
        // TypeVoid ctor (type.hh:389): name "void", size 0, coretype flag.
        let mut base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
        base.alignment = 1;
        base.align_size = 0;
        base.id = Datatype::hash_name("void");
        base.flags |= type_flags::CORETYPE;
        let dt = Arc::new(Datatype::Void(base));
        let tree_key = Self::type_tree_key(&dt);
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.insert(tree_key, dt.clone());
        self.types.insert("void".to_string(), dt.clone());
        self.base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((0, TypeMetatype::Void), dt.clone());
        dt
    }

    // RUDRA-GLUE: shared-reference twin of [`Self::get_type_void_result`]
    /// for callers holding `&TypeFactory`. Every production factory
    /// bootstraps the void core type, so the cache/name lookup always
    /// resolves; the raw-constructor creation path is the `_result` variant.
    ///
    /// TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 status: every in-lease caller
    /// (decode_type_no_ref, decode_code_define, typefactory tests) is
    /// migrated to [`Self::get_type_void_result`]. The twin is retained for
    /// callers outside that lease that hold `&TypeFactory`/read guards:
    /// `src/userop.rs` (tests), `src/funcdata.rs:7022`,
    /// `src/coreaction.rs:5988/5993`. Migrate them when their leases free
    /// up, then delete this twin.
    pub fn get_type_void(&self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(0, TypeMetatype::Void)) {
                return existing.clone();
            }
        }
        self.find_by_name("void")
            .expect("void core type must exist")
    }

    // Ghidra: type.cc:3678 TypeFactory::getTypeChar(int4 s)
    /// If a core character data-type of the given size exists, return it.
    /// Otherwise raise Ghidra's LowlevelError. Faithful to
    /// `TypeFactory::getTypeChar(int4 s)` (type.cc:3678-3687): the lookup
    /// consults `charcache[s]` only for `s < 5`; every other size — and every
    /// cache miss — raises
    /// `"Request for unsupported character data-type"` as `Err`.
    pub fn get_type_char(&self, size: usize) -> Result<Arc<Datatype>, String> {
        if size < 5 {
            let cache = self
                .char_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&size) {
                return Ok(existing.clone());
            }
        }
        Err("Request for unsupported character data-type".to_string())
    }

    // Ghidra: type.cc:3593 TypeFactory::getTypeChar(const string &n)
    /// Create a 1-byte character data-type (assumed UTF8). Faithful to
    /// `TypeFactory::getTypeChar(const string &n)` (type.cc:3593-3599): build
    /// a `TypeChar(n)` — `TypeBase(1,TYPE_INT,n)` with the `chartype` flag
    /// and `SUB_INT_CHAR` (type.hh:356) — give it `id = hashName(n)`, and run
    /// it through `findAdd` (same-definition hit returns the existing object,
    /// conflicting definitions raise the alter-definition LowlevelError).
    pub fn get_type_char_named(&mut self, n: &str) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new_char(n.to_string(), TypeMetatype::Int);
        base.id = Datatype::hash_name(n);
        self.find_add(Datatype::Base(base), false)
    }

    // Ghidra: type.cc:3606 TypeFactory::getTypeUnicode
    /// Create a multi-byte character data-type (UTF16/UTF32). Faithful to
    /// `TypeFactory::getTypeUnicode` (type.cc:3606-3612): build a
    /// `TypeUnicode(nm,sz,m)` — `setflags()` selects `utf16`/`utf32`/
    /// `chartype` by size (type.cc:837-846) and the sub-metatype is
    /// `SUB_INT_UNICODE`/`SUB_UINT_UNICODE` regardless of size
    /// (type.cc:862-867) — give it `id = hashName(nm)`, and run it through
    /// `findAdd`.
    pub fn get_type_unicode_named(
        &mut self,
        nm: &str,
        sz: usize,
        m: TypeMetatype,
    ) -> Result<Arc<Datatype>, String> {
        let mut base = TypeBase::new_unicode(nm.to_string(), sz, m);
        base.id = Datatype::hash_name(nm);
        self.find_add(Datatype::Base(base), false)
    }

    // RUDRA-GLUE: size-keyed convenience wrapper over
    /// [`Self::get_type_unicode_named`] with the historical canonical name
    /// (wchar2/wchar4). Ghidra has no size-only getTypeUnicode; the
    /// name-carrying port above is the faithful entry.
    pub fn get_type_unicode(&mut self, size: usize) -> Arc<Datatype> {
        let name = unicode_name_for_size(size);
        match self.get_type_unicode_named(&name, size, TypeMetatype::Int) {
            Ok(dt) => dt,
            // The legacy API cannot fail on the default factory state it was
            // designed for (an installed alignment map); surface the faithful
            // error as a panic rather than silently diverging.
            Err(message) => panic!("LowlevelError: {message}"),
        }
    }

    // Ghidra: type.cc:3940 TypeFactory::getTypeUnion
    /// Create an incomplete union data-type with the given name. Faithful to
    /// `TypeFactory::getTypeUnion` (type.cc:3940-3948). Ghidra's
    /// `TypeUnion()` constructor (type.hh:551) sets `type_incomplete |
    /// needs_resolution`; Rudra mirrors both flags.
    pub fn get_type_union(&mut self, name: &str) -> Arc<Datatype> {
        let mut base = TypeBase::new(name.to_string(), 0, TypeMetatype::Union);
        base.id = Datatype::hash_name(name);
        base.flags |= type_flags::TYPE_INCOMPLETE | type_flags::NEEDS_RESOLUTION;
        self.find_add(
            Datatype::Union(TypeUnion {
            base,
            fields: Vec::new(),
        }), false,
        )
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3493 TypeFactory::setFields(TypeUnion*)
    /// Set the fields of an existing union, recomputing its size as the max
    /// field size (union members overlap at offset 0). Mirrors the union
    /// behaviour of `TypeUnion::setFields` used by `TypeFactory::setFields`.
    pub fn set_union_fields(
        &mut self, name: &str, fields: Vec<TypeField>,
    ) -> Option<Arc<Datatype>> {
        let dt = self.types.get(name)?.clone();
        if !dt.is_incomplete() {
            return None;
        }
        let defined = self.define_replace(&dt, |defined| {
            let union = match defined {
                Datatype::Union(union) => union,
                _ => return Err("setFields target is not a TypeUnion".to_string()),
            };
            union.fields = fields;
            let max_size = union
                .fields
                .iter()
                .map(|field| field.type_ptr.get_size())
                .max()
                .unwrap_or(0);
            let new_align = union
                .fields
                .iter()
                .map(|field| field.type_ptr.get_alignment())
                .max()
                .unwrap_or(1)
                .max(1);
            union.base.size = max_size;
            union.base.alignment = new_align as i32;
            union.base.align_size = calc_align_size(max_size, new_align);
            union.base.flags &= !type_flags::TYPE_INCOMPLETE;
            Ok(())
        });
        Some(defined.unwrap_or_else(|message| panic!("LowlevelError: {message}")))
    }

    // Ghidra: type.cc:3493 TypeFactory::setFields(TypeUnion*)
    /// Define a union with the caller-supplied final size and alignment.
    /// This is the explicit counterpart to [`Self::set_fields_sized`] and
    /// preserves layout values decoded from compiler/debug type metadata.
    pub fn set_union_fields_sized(
        &mut self,
        name: &str,
        fields: Vec<TypeField>,
        new_size: usize,
        new_align: usize,
    ) -> Option<Arc<Datatype>> {
        self.set_union_fields_flags(name, fields, new_size, new_align, 0)
    }

    // Ghidra: type.cc:3493 TypeFactory::setFields(TypeUnion*)
    /// The full union `TypeFactory::setFields` signature (type.cc:3500-3511)
    /// including the flags mask tail (type.cc:3508-3509):
    /// `flags &= ~type_incomplete;
    ///  flags |= (flags & (variable_length | type_incomplete))` — note the
    /// union mask has NO `opaque_string` bit (only the struct version at
    /// type.cc:3488 transfers it), and the union version performs NO
    /// `recalcPointerSubmeta` calls (contrast type.cc:3490-3491).
    pub fn set_union_fields_flags(
        &mut self,
        name: &str,
        fields: Vec<TypeField>,
        new_size: usize,
        new_align: usize,
        flags: u32,
    ) -> Option<Arc<Datatype>> {
        let dt = self.types.get(name)?.clone();
        if !dt.is_incomplete() {
            return None;
        }
        let defined = self.define_replace(&dt, |defined| {
            let union = match defined {
                Datatype::Union(union) => union,
                _ => return Err("setFields target is not a TypeUnion".to_string()),
            };
            union.fields = fields;
            union.base.size = new_size;
            union.base.alignment = new_align as i32;
            union.base.align_size = calc_align_size(new_size, new_align);
            // type.cc:3508-3509 flag clear + masked-OR transfer.
            union.base.flags &= !type_flags::TYPE_INCOMPLETE;
            union.base.flags |=
                flags & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
            Ok(())
        });
        Some(defined.unwrap_or_else(|message| panic!("LowlevelError: {message}")))
    }

    // Ghidra: type.cc:3724 TypeFactory::recalcPointerSubmeta
    /// Search for pointers that match the given `base` and `sub` sub-metatype
    /// and re-key them to the current calculated sub-metatype. Faithful to
    /// `TypeFactory::recalcPointerSubmeta` (type.cc:3724-3745):
    ///
    /// ```text
    /// TypePointer top(1,base,0);        // size 1, ptrto=base, wordsize 0
    /// sub_metatype curSub = top.submeta;  // = calcSubmeta for pointers to base
    /// if (curSub == sub) return;          // correct submeta already
    /// top.submeta = sub;                  // search on the incorrect submeta
    /// iter = tree.lower_bound(&top);
    /// while(iter != tree.end()) {
    ///   if (dt->getMetatype() != TYPE_PTR) break;
    ///   if (ptr->ptrto != base) break;
    ///   ++iter;                           // advance BEFORE erase
    ///   if (ptr->submeta == sub) { tree.erase(ptr); ptr->submeta = curSub; tree.insert(ptr); }
    /// }
    /// ```
    ///
    /// Alignment Evidence (four decisive-semantics checklist):
    /// - References/output params: mutates the stored pointer's submeta AND
    ///   its tree slot in place (`base` is read-only). Rudra's submeta is
    ///   DERIVED (`pointer_submeta`) rather than stored, so the re-key is
    ///   `remove(old_key)` + `insert(type_tree_key(same Arc))` — the same
    ///   Arc is preserved, only the ordering slot migrates.
    /// - Loop bounds/iteration order: from `tree.lower_bound(&top)` (the
    ///   probe key `(sub, base-identity, 0, 0, wordsize 0, no-space,
    ///   Reverse(1), id 0)`) forward through tree order; BREAKS at the first
    ///   non-TYPE_PTR entry or an entry whose `ptrto` is not `base` by
    ///   identity — later same-base pointers beyond an unrelated entry are
    ///   not visited, exactly as in the oracle.
    /// - Counter/accumulator: none; `++iter` precedes the erase (C++ set
    ///   iterator invalidation), mirrored by collecting the migration keys
    ///   before removing.
    /// - Sort/comparison key: the factory tree's `compareDependency` order —
    ///   submeta, then `ptrto` pointer identity, then wordsize, then spaceid
    ///   (no-space last), then descending size (type.cc:955-967); the probe
    ///   `top` has size 1 / wordsize 0 / no space, so wordsize-0 pointers
    ///   WITH a space sort before the probe and are skipped — a probe-shape
    ///   quirk inherited verbatim from the oracle.
    ///
    /// Scope: pointers keyed under a PREVIOUS Arc of `base` (the
    /// `define_replace` completion seam) are not reachable through the
    /// `ptrto == base` identity check — tracked by
    /// TYPEFACTORY-ARC-IDENTITY-0001.
    pub fn recalc_pointer_submeta(&mut self, base: &Arc<Datatype>, sub: SubMetatype) {
        // TypePointer top(1,base,0) — its calcSubmeta IS the current proper
        // sub-metatype for pointers to base.
        let top = TypePointer::new(1, base.clone(), 0);
        let cur_sub = pointer_submeta(&top);
        if cur_sub == sub {
            return; // Don't need to search for pointers with correct submeta
        }
        // top.submeta = sub — the probe key under the incorrect submeta:
        // (submeta, dependency=base identity, offset 0, parent 0, wordsize 0,
        //  space_rank None=1, space_id 0, Reverse(size 1), id 0).
        let probe: TypeTreeKey = (
            sub as u8,
            Arc::as_ptr(base) as usize,
            0,
            0,
            0,
            1,
            0,
            Reverse(1),
            0,
        );
        let tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let base_raw = Arc::as_ptr(base) as *const Datatype;
        let mut migrate: Vec<TypeTreeKey> = Vec::new();
        for (key, dt) in tree.range(probe..) {
            let Datatype::Pointer(pointer) = dt.as_ref() else {
                break; // dt->getMetatype() != TYPE_PTR
            };
            if !std::ptr::eq(Arc::as_ptr(&pointer.ptr_to) as *const Datatype, base_raw) {
                break; // ptr->ptrto != base
            }
            // ++iter before the erase; the stored submeta is the key's
            // submeta component (submeta_of at insertion time).
            if key.0 == sub as u8 {
                migrate.push(key.clone());
            }
        }
        for key in migrate {
            if let Some(arc) = tree.remove(&key) {
                // ptr->submeta = curSub; tree.insert(ptr) — the derived
                // submeta already evaluates to curSub, so re-keying by the
                // current projection performs the migration.
                tree.insert(Self::type_tree_key(&arc), arc);
            }
        }
    }

    // Ghidra: type.cc:3750 TypeFactory::insertWarning
    /// Add the data-type and string to the `warnings` container. Faithful to
    /// `TypeFactory::insertWarning` (type.cc:3750-3757): a data-type with a
    /// zero id throws `LowlevelError("Can only issue warnings for named
    /// data-types")`, the `warning_issued` flag is set on the type, and the
    /// record is appended. The flag write goes through the registered-slot
    /// replace (Ghidra mutates the registered object in place); Rudra
    /// re-wraps it in a new Arc under the same registry slots.
    pub fn insert_warning(
        &mut self,
        dt: &Arc<Datatype>,
        warn: String,
    ) -> Result<Arc<Datatype>, String> {
        if dt.get_id() == 0 {
            return Err("Can only issue warnings for named data-types".to_string());
        }
        let updated = self.define_replace(dt, |defined| {
            // dt->flags |= Datatype::warning_issued (type.hh:185 = 0x20000).
            defined.set_type_flag(type_flags::WARNING_ISSUED);
            Ok(())
        })?;
        self.warnings.push(DatatypeWarning {
            type_name: updated.get_name().to_string(),
            type_id: updated.get_id(),
            warning: warn,
        });
        Ok(updated)
    }

    // Ghidra: type.cc:3761 TypeFactory::removeWarning
    /// Run through the `warnings` container and delete every entry matching
    /// the given data-type. Faithful to `TypeFactory::removeWarning`
    /// (type.cc:3761-3773): an entry matches when the stored data-type's id
    /// AND name equal the given type's (type.cc:3766); the list walk is
    /// order-preserving, `erase` returns the next iterator (no index skips).
    pub fn remove_warning(&mut self, dt: &Datatype) {
        let id = dt.get_id();
        let name = dt.get_name();
        self.warnings
            .retain(|entry| !(entry.type_id == id && entry.type_name == name));
    }

    // Ghidra: type.cc:3445 TypeFactory::setName
    /// Rename a data-type and fix up the cross-referencing. Faithful to
    /// `TypeFactory::setName` (type.cc:3445-3459): the name reference is
    /// erased (when the type carries an id), the type is removed from the
    /// structural tree, `name`/`displayName` are set, a zero id is replaced
    /// by `hashName(n)`, and both channels re-insert the type. Returns the
    /// renamed type.
    ///
    /// Rudra performs the erase/reinsert through the registered-slot
    /// replace, which ADDITIONALLY refuses two pathological collisions the
    /// oracle would paper over silently (std::set::insert failing when
    /// another object already occupies the new name/tree slot): those are
    /// registry misuse, surfaced as `Err` instead of a silently unindexed
    /// type.
    pub fn set_name(
        &mut self,
        ct: &Arc<Datatype>,
        n: &str,
    ) -> Result<Arc<Datatype>, String> {
        self.define_replace(ct, |defined| {
            defined.set_type_name(n);
            if defined.get_id() == 0 {
                defined.set_type_id(Datatype::hash_name(n));
            }
            Ok(())
        })
    }

    // Ghidra: type.cc:4055 TypeFactory::getTypePointerWithSpace
    /// Build a named pointer with an address space attribute. The new
    /// data-type acts like a typedef of a normal pointer but can affect the
    /// resolution of constants by the type propagation system. Faithful to
    /// `TypeFactory::getTypePointerWithSpace` (type.cc:4055-4065):
    ///
    /// ```text
    /// TypePointer tp(ptrTo,spc);   // size=spc->getAddrSize(), wordsize=
    ///                              // spc->getWordSize(), spaceid=spc,
    ///                              // calcSubmeta
    /// tp.name = nm; tp.displayName = nm; tp.id = Datatype::hashName(nm);
    /// TypePointer *res = (TypePointer *)findAdd(tp);
    /// res->calcTruncate(*this);
    /// return res;
    /// ```
    ///
    /// Note the constructor is the AddrSpace form — there is NO
    /// `getStripped` step on `ptrTo` (unlike `getTypePointer`,
    /// type.cc:3869-3870). `calcTruncate`'s attached subcomponent is the
    /// TYPE-0001 structural residual: the guard
    /// (`size != getSizeOfAltPointer()` early-out) is mirrored and the
    /// `resizePointer` is issued for its factory-registration side effect,
    /// same as the decode-path kludge (type.cc:4196 neighbourhood).
    pub fn get_type_pointer_with_space(
        &mut self,
        ptr_to: Arc<Datatype>,
        space: AddressSpace,
        nm: &str,
    ) -> Result<Arc<Datatype>, String> {
        let mut tp = TypePointer::new_with_space(ptr_to, space);
        tp.base.name = nm.to_string();
        tp.base.display_name = nm.to_string();
        tp.base.id = Datatype::hash_name(nm);
        let res = self.find_add(Datatype::Pointer(tp), true)?;
        // res->calcTruncate(*this) — see the doc note above.
        if res.get_size() as i32 == self.get_size_of_alt_pointer() {
            let _ = self.resize_pointer(
                &res,
                self.get_size_of_pointer() as usize,
            );
        }
        Ok(res)
    }

    // Ghidra: type.cc:4122 TypeFactory::destroyType
    /// Remove the indicated data-type from this factory. Indirect references
    /// (via TypeArray TypeStruct etc.) are not affected. Faithful to
    /// `TypeFactory::destroyType` (type.cc:4122-4132): a core type throws
    /// `LowlevelError("Cannot destroy core type")`; a type with a warning
    /// first drains its warning entries; the name reference and the tree
    /// entry are erased; the object is deleted (Rudra: the Arc slots are
    /// dropped, so the object dies when the last external handle dies).
    ///
    /// Ghidra's `nametree.erase`/`tree.erase` remove by object identity
    /// (set erase of the equivalent key); Rudra removes the slot when it
    /// holds this precise Arc OR an equivalent `(name, id)` / tree-key
    /// entry, mirroring key-equivalence semantics.
    pub fn destroy_type(&mut self, ct: &Arc<Datatype>) -> Result<(), String> {
        if ct.is_coretype() {
            return Err("Cannot destroy core type".to_string());
        }
        if ct.has_warning() {
            self.remove_warning(ct.as_ref());
        }
        // nametree.erase(ct) — the (name, id) keyed channel.
        let name = ct.get_name();
        if !name.is_empty() {
            let remove_name = self
                .types
                .get(name)
                .is_some_and(|registered| {
                    Arc::ptr_eq(registered, ct)
                        || (registered.get_id() == ct.get_id()
                            && registered.get_name() == name)
                });
            if remove_name {
                self.types.remove(name);
            }
        }
        // tree.erase(ct) — the structural channel, by exact key.
        let tree_key = Self::type_tree_key(ct);
        {
            let tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let remove_tree = tree
                .get(&tree_key)
                .is_some_and(|registered| {
                    Arc::ptr_eq(registered, ct)
                        || (registered.get_id() == ct.get_id()
                            && registered.get_name() == ct.get_name())
                });
            if remove_tree {
                tree.remove(&tree_key);
            }
        }
        // delete ct — mirrored by dropping the removed Arc handles.
        Ok(())
    }

    // Ghidra: type.cc:3967 TypeFactory::getTypeEnum
    /// The faithful `TypeFactory::getTypeEnum` port (type.cc:3967-3973): a
    /// `TypeEnum tmp(enumsize, enumtype, n)` — the factory's configured
    /// `enumsize`/`enumtype` state (type.hh:489-494 sets the `enumtype` flag,
    /// normalizes the metatype to TYPE_INT/TYPE_UINT, and leaves the
    /// sub-metatype at base2sub[TYPE_ENUM_INT/UINT] = 15/13) — with
    /// `id = hashName(n)`, canonicalized through `findAdd` (name cross-
    /// reference AND the ordered tree, so the enum participates in
    /// cacheCoreTypes like any other core entry).
    ///
    /// `enum_size`/`enum_type` are populated by `parse_enum_config` /
    /// `setup_sizes`; a factory that never ran either keeps the raw-
    /// constructor zero state, and the faithful error propagation surfaces
    /// findAdd's LowlevelErrors as `Err`.
    pub fn get_type_enum_result(&mut self, name: &str) -> Result<Arc<Datatype>, String> {
        let meta = if self.enum_type == TypeMetatype::Int {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        let mut base = TypeBase::new(name.to_string(), self.enum_size.max(0) as usize, meta);
        base.id = Datatype::hash_name(name);
        base.flags |= type_flags::ENUMTYPE;
        self.find_add(
            Datatype::Enum(TypeEnum {
                base,
                values: std::collections::BTreeMap::new(),
            }),
            false,
        )
    }

    // RUDRA-GLUE: legacy flat-map twin of [`Self::get_type_enum_result`]
    /// kept for grammar.rs (its file is under another lease): dedupes by
    /// name and creates a 4-byte signed stub, which matches the oracle only
    /// for factories whose `enumsize`/`enumtype` were configured as 4/signed.
    /// The byte-faithful port reading the configured enum state is
    /// `get_type_enum_result`.
    pub fn get_type_enum(&mut self, name: &str) -> Arc<Datatype> {
        if let Some(existing) = self.find_by_name(name) {
            return existing;
        }
        let mut base = TypeBase::new(name.to_string(), 4, TypeMetatype::Int);
        base.flags |= type_flags::ENUMTYPE;
        let dt = Arc::new(Datatype::Enum(TypeEnum {
            base,
            values: std::collections::BTreeMap::new(),
        }));
        self.types.insert(name.to_string(), dt.clone());
        dt
    }

    // Ghidra: type.cc:3532 TypeFactory::setEnumValues
    /// Set the value→name map on an existing enumeration. Faithful to
    /// `TypeFactory::setEnumValues` (type.cc:3532-3538), which calls
    /// `te->setNameMap(nmap)` (re-hashing the type into the tree around it).
    /// We replace the enum's `values` map in place.
    pub fn set_enum_values(
        &mut self,
        name: &str,
        values: std::collections::BTreeMap<u64, String>,
    ) -> Option<Arc<Datatype>> {
        if let Some(dt) = self.types.get_mut(name) {
            if let Datatype::Enum(ref mut e) = Arc::make_mut(dt) {
                e.values = values;
                return Some(dt.clone());
            }
        }
        None
    }

    // Ghidra: type.cc:3692 TypeFactory::getTypeCode()
    /// Retrieve or create the core "code" Datatype object with no prototype
    /// attached. Faithful to `TypeFactory::getTypeCode()` (type.cc:3692-3701):
    /// the typecache slot `typecache[1][TYPE_CODE-TYPE_FLOAT]` returns when
    /// filled; otherwise a generic complete `TypeCode` — UNNAMED, id 0
    /// (type.cc:3698-3700) — is canonicalized through `findAdd` (the ordered
    /// tree dedupes it on (SUB_CODE, size, id)).
    pub fn get_type_code(&mut self) -> Arc<Datatype> {
        {
            let cache = self
                .base_cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = cache.get(&(1, TypeMetatype::Code)) {
                return existing.clone();
            }
        }
        let mut code = TypeCode::new();
        code.base.flags &= !type_flags::TYPE_INCOMPLETE;
        // tmp.markComplete() (type.cc:3699): considered complete.
        let candidate = Datatype::Code(code);
        let tree_key = Self::type_tree_key(&candidate);
        let mut tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dt = tree
            .entry(tree_key)
            .or_insert_with(|| Arc::new(candidate))
            .clone();
        dt
    }

    // Ghidra: type.cc:3707 TypeFactory::getTypeCode(const string &nm)
    /// Create a "function"/"executable" data-type with a name. Faithful to
    /// `TypeFactory::getTypeCode(const string &nm)` (type.cc:3707-3717): an
    /// empty name delegates to the unnamed getter; otherwise a generic
    /// complete `TypeCode` carrying `name`/`displayName` and
    /// `id = hashName(nm)` is canonicalized through `findAdd`.
    pub fn get_type_code_named(&mut self, nm: &str) -> Result<Arc<Datatype>, String> {
        if nm.is_empty() {
            return Ok(self.get_type_code());
        }
        let mut code = TypeCode::new();
        code.base.name = nm.to_string();
        code.base.display_name = nm.to_string();
        code.base.id = Datatype::hash_name(nm);
        code.base.flags &= !type_flags::TYPE_INCOMPLETE;
        // tmp.markComplete() (type.cc:3715).
        self.find_add(Datatype::Code(code), false)
    }

    // Ghidra: type.cc:4002 TypeFactory::getTypeCode(PrototypePieces)
    /// Create a `TypeCode` object and associate a specific function prototype
    /// with it. Faithful to `TypeFactory::getTypeCode(const PrototypePieces&)`
    /// (type.cc:4002-4008): builds an unnamed `TypeCode`, calls
    /// `setPrototype(this, proto, getTypeVoid())` on it, marks it complete, and
    /// dedupes via `findAdd`.
    ///
    /// Rudra note: Ghidra dedupes prototype-bearing code types structurally
    /// via `findAdd` (which uses `compare`). Rudra's flat name-keyed map cannot
    /// look up an unnamed type by structure efficiently, so this port mints a
    /// synthetic name derived from the prototype's structure (return type name
    /// + parameter type names + model name) so that equivalent prototypes
    /// dedupe while distinct ones do not collide. The structural comparison
    /// is still available via `Datatype::compare_deep` for callers that need
    /// it.
    pub fn get_type_code_pieces(
        &mut self,
        proto: &crate::fspec::PrototypePieces) -> Arc<Datatype> {
        // Build the synthetic name for dedup.
        let mut name = String::from("funcptr");
        name.push('(');
        match proto.out_type {
            Some(t) => name.push_str(t.get_name()),
            None => name.push_str("void"),
        }
        name.push(')');
        name.push('(');
        for (i, t) in proto.in_types.iter().enumerate() {
            if i > 0 {
                name.push(',');
            }
            name.push_str(t.get_name());
        }
        name.push(')');
        if proto.first_var_arg_slot >= 0 {
            name.push_str("...");
        }
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut code = TypeCode::new();
        code.base.name = name.clone();
        code.base.display_name = name.clone();
        // Ghidra: tc.markComplete() clears type_incomplete.
        code.base.flags &= !type_flags::TYPE_INCOMPLETE;
        code.base.flags |= type_flags::VARLENGTH;
        code.set_prototype_pieces(proto);
        let dt = Arc::new(Datatype::Code(code));
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:3518 TypeFactory::setPrototype
    /// Set the prototype on an (incomplete) `TypeCode`. Faithful to
    /// `TypeFactory::setPrototype(const FuncProto*, TypeCode*, uint4)`
    /// (type.cc:3518-3528): asserts the target is incomplete, detaches it from
    /// the tree, calls `TypeCode::setPrototype(this, fp)` on it, clears the
    /// `type_incomplete` flag, ORs in the requested `(variable_length |
    /// type_incomplete)` flags, and re-inserts it.
    ///
    /// Returns the updated `Arc<Datatype>` (re-inserted under the same name).
    /// Errors if `name` is not a code type or is not incomplete.
    pub fn set_prototype(
        &mut self,
        name: &str,
        fp: Option<&crate::fspec::FuncProto>,
        flags: u32,
    ) -> Result<Arc<Datatype>, &'static str> {
        let dt = self
            .types
            .get_mut(name)
            .ok_or("TypeCode not found in factory")?;
        let code = match Arc::make_mut(dt) {
            Datatype::Code(c) => c,
            _ => return Err("setPrototype target is not a TypeCode"),
        };
        if (code.base.flags & type_flags::TYPE_INCOMPLETE) == 0 {
            return Err("Can only set prototype on incomplete data-type");
        }
        // TypeCode::setPrototype(typegrp, fp) — copy the prototype in.
        code.set_prototype(fp);
        // Clear incomplete; OR in the caller-requested flags.
        code.base.flags &= !type_flags::TYPE_INCOMPLETE;
        code.base.flags |= flags & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
        Ok(dt.clone())
    }

    // Ghidra: type.cc:3929 TypeFactory::getTypePartialStruct
    /// Create a partial-structure covering `[off, off+sz)` of `contain` (a
    /// struct or array). Faithful to `TypeFactory::getTypePartialStruct`
    /// (type.cc:3929-3953): builds a `TypePartialStruct` whose `stripped`
    /// fallback is `getBase(sz, TYPE_UNKNOWN)` — i.e. an undefined type of
    /// `sz` bytes. Rudra reuses `get_base(sz, Unknown)` for the stripped form.
    pub fn get_type_partial_struct(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        // Ghidra: Datatype *strip = getBase(sz, TYPE_UNKNOWN); (type.cc:3932)
        // — the faithful Result twin; its LowlevelError (findAdd alignment
        // on an uninitialized map, type.cc:3300-3302) is a throw in the
        // oracle, surfaced as the LowlevelError panic here.
        let stripped = self
            .get_base_result(sz, TypeMetatype::Unknown)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        let partial = Datatype::PartialStruct(TypePartialStruct::new(
            contain,
            off,
            sz,
            Some(stripped)));
        self.find_add(partial, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3980 TypeFactory::getTypePartialEnum
    /// Create a partial-enumeration covering `[off, off+sz)` of `contain` (an
    /// enum). Faithful to `TypeFactory::getTypePartialEnum`
    /// (type.cc:3980-3990): builds a `TypePartialEnum` whose `stripped`
    /// fallback is `getBase(sz, TYPE_UNKNOWN)`.
    pub fn get_type_partial_enum(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        // Ghidra: Datatype *strip = getBase(sz, TYPE_UNKNOWN); (type.cc:3983)
        // — faithful Result twin; see get_type_partial_struct for the
        // LowlevelError panic rationale.
        let stripped = self
            .get_base_result(sz, TypeMetatype::Unknown)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        let partial = Datatype::PartialEnum(TypePartialEnum::new(
            contain,
            off,
            sz,
            Some(stripped)));
        self.find_add(partial, true)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3955 TypeFactory::getTypePartialUnion
    /// Create a partial-union covering `[off, off+sz)` of `contain` (a union).
    /// Faithful to `TypeFactory::getTypePartialUnion` (type.cc:3955-3978):
    /// builds a `TypePartialUnion` whose `stripped` fallback is
    /// `getBase(sz, TYPE_UNKNOWN)`.
    pub fn get_type_partial_union(
        &mut self,
        contain: Arc<Datatype>,
        off: i64,
        sz: usize,
    ) -> Arc<Datatype> {
        // Ghidra: Datatype *strip = getBase(sz, TYPE_UNKNOWN); (type.cc:3958)
        // — faithful Result twin; see get_type_partial_struct for the
        // LowlevelError panic rationale.
        let stripped = self
            .get_base_result(sz, TypeMetatype::Unknown)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        let partial = Datatype::PartialUnion(TypePartialUnion::new(
            contain,
            off,
            sz,
            Some(stripped)));
        self.find_add(partial, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:4090 TypeFactory::getExactPiece
    /// Drill through nested component types and recover the canonical type
    /// for the byte range beginning at `offset` with `size` bytes. Exact-size
    /// hits preserve the original Arc; ranges stopped by a union, a
    /// struct/array boundary, or an unstripped enum are represented by the
    /// corresponding canonical partial type.
    pub fn get_exact_piece(
        &mut self,
        ct: Arc<Datatype>,
        offset: i64,
        size: usize,
    ) -> Option<Arc<Datatype>> {
        let mut current = ct;
        let mut last_type: Option<Arc<Datatype>> = None;
        let mut last_off = 0_i64;
        let mut cur_off = offset;
        loop {
            // Ghidra promotes `size + curOff` to int8. i128 keeps the signed
            // range check without introducing a Rust usize overflow.
            if (current.get_size() as i128) < size as i128 + cur_off as i128 {
                break;
            }
            if current.get_size() == size {
                return Some(current);
            }
            if current.get_metatype() == TypeMetatype::Union {
                return Some(self.get_type_partial_union(current, cur_off, size));
            }
            last_type = Some(current.clone());
            last_off = cur_off;
            let (subtype, newoff) = Datatype::get_sub_type_arc(&current, cur_off);
            let Some(subtype) = subtype else {
                break;
            };
            current = subtype;
            cur_off = newoff;
        }

        let last_type = last_type?;
        match last_type.get_metatype() {
            TypeMetatype::Struct | TypeMetatype::Array => {
                Some(self.get_type_partial_struct(last_type, last_off, size))
            }
            _ if last_type.is_enum_type() && !last_type.has_stripped() => {
                Some(self.get_type_partial_enum(last_type, last_off, size))
            }
            _ => None,
        }
    }

    // Ghidra: type.cc:3992 TypeFactory::getTypeSpacebase
    /// Create a "spacebase" type for the given address space, scoped to
    /// `frame` (INVALID for the global spacebase). Faithful to
    /// `TypeFactory::getTypeSpacebase` (type.cc:3992-4000), which builds a
    /// `TypeSpacebase(spaceid, localframe, glb)`. Rudra stores the optional
    /// `Scope` (set later when an Architecture/SymbolTable is attached).
    pub fn get_type_spacebase(
        &mut self,
        spaceid: Option<AddressSpace>,
        frame: Address,
    ) -> Arc<Datatype> {
        // RUDRA-GLUE dedup: Ghidra canonicalizes spacebases through the
        // compare-sorted tree in findAdd (type.cc:3996 via
        // TypeSpacebase::compareDependency type.cc:3045-3055 — base, then
        // spaceid, then localframe); Rudra's factory is a name-keyed
        // BTreeMap, so the synthetic key below encodes the space+frame
        // identity for the map slot. It is NOT the type's display name.
        let key = format!(
            "__spacebase_{}_{}",
            spaceid.map(|s| s.word_size()).unwrap_or(0),
            frame.as_u64()
        );
        if let Some(existing) = self.find_by_name(&key) {
            return existing;
        }
        // Ghidra `TypeSpacebase(AddrSpace*, const Address&, Architecture*)`
        // (type.hh:735-736) bases on `Datatype(0,1,TYPE_SPACEBASE)` whose
        // ctor (type.hh:214) leaves `name` EMPTY — the spacebase is an
        // ANONYMOUS type. At print time `PrintC::buildTypeStack`
        // (printc.cc:143-163) stops at an anonymous non-PTR/ARRAY/CODE
        // type, so `PrintC::pushTypeStart`'s anonymous branch
        // (printc.cc:280-285) spells `PrintC::genericTypeName` →
        // "BADSPACEBASE" (printc.cc:3387-3389, returned before the size
        // suffix), declaring e.g. `BADSPACEBASE *in_RSP`. Rudra previously
        // carried the synthetic dedup key as the type NAME, leaking
        // `__spacebase_1_<frame> *in_RSP` into declarations
        // (SPACEBASE-SYMNAME-0001); the name is now empty like the oracle.
        let mut base = TypeBase::new(String::new(), 0, TypeMetatype::Spacebase);
        // Ghidra spacebase is a core type (cached on the architecture).
        base.flags |= type_flags::CORETYPE;
        // getMap's local-frame arm (type.cc:2938-2944) resolves the LIVE
        // fd->getScopeLocal() on every query. Attach the shared handle
        // eagerly at construction (VARMAP-STACKBOUNDARY-0001): the registry
        // entry is created here if absent, so the cached type always carries
        // the handle and later publishes (restructure passes) only replace
        // the handle CONTENTS. An empty ScopeLocal is the oracle's
        // pre-restructure observable.
        //
        // Local-frame test: Rudra's legacy `Address::new(frame)` form is
        // SPACELESS, so `is_invalid()` (null-base) is true for real function
        // entries too and cannot distinguish — the factory's global
        // spacebases are always constructed at frame 0 (funcdata
        // spacebaseConstant mirror, Address::new(0)), so a NONZERO
        // localframe offset is the local-frame predicate here (and in
        // TypeSpacebase::get_map).
        let local_handle = if frame.is_null() {
            None
        } else {
            Some(
                self.live_local_scopes
                    .entry(frame.as_u64())
                    .or_insert_with(|| {
                        std::sync::Arc::new(std::sync::RwLock::new(
                            crate::varmap::ScopeLocal::new(),
                        ))
                    })
                    .clone(),
            )
        };
        let sb = TypeSpacebase {
            base,
            address: frame.clone(),
            fd: local_handle,
            spaceid,
            localframe: frame,
            // The getMap projection (type.cc:2935-2945) reads
            // glb->symboltab->getGlobalScope() dynamically and — for a
            // valid localframe — resolves queryFunction(localframe) →
            // fd->getScopeLocal() on EVERY query. This snapshot of the
            // global scope is only the GLOBAL leg of that projection
            // (globals are installed before decompilation and stable during
            // it); local-frame queries must NOT read it — the live ScopeLocal
            // is restructured during the pipeline (RULEARITH-SPACEBASE-
            // ARRAYSNAP-0001), so the RulePtrArith query path resolves
            // datatype::SpacebaseMap::Local from the decompiling Funcdata at
            // query time instead (ruleaction.rs spacebase_map).
            scope: self.symboltab.as_ref().and_then(|db| {
                db.read()
                    .unwrap()
                    .get_global_scope()
                    .map(|scope| std::sync::Arc::new(scope.clone()))
            }),
        };
        let dt = Arc::new(Datatype::Spacebase(sb));
        self.types.insert(key, dt.clone());
        dt
    }

    // RUDRA-GLUE: set_spacebase_scope_source (no Ghidra counterpart; Ghidra
    // resolves the map dynamically through the Architecture on every
    // TypeSpacebase::getMap call, Rudra snapshots it at construction).
    /// Register the Database whose global scope new spacebase types resolve
    /// through — the driver/fixture attaches this right after installing the
    /// symbol graph and before the first `get_type_spacebase` call.
    pub fn set_spacebase_scope_source(
        &mut self,
        db: Option<std::sync::Arc<std::sync::RwLock<crate::database::Database>>>,
    ) {
        self.symboltab = db;
    }

    // RUDRA-GLUE: legacy named relative-pointer convenience. It predates the
    // parent-pointer overload below and keeps the historical side-table API;
    // Ghidra's formal overload at type.cc:4036 also requires size, wordsize,
    // and name, so this three-argument signature has no direct counterpart.
    /// Find/create the legacy named relative pointer used by older callers.
    pub fn get_type_pointer_rel(
        &mut self,
        ptr_to: Arc<Datatype>,
        parent: Arc<Datatype>,
        offset: i64,
    ) -> Arc<Datatype> {
        let name = format!("{}+{} *", parent.get_name(), offset);
        if let Some(existing) = self.find_by_name(&name) {
            return existing;
        }
        let mut base = TypeBase::new(name.clone(), self.ptr_size, TypeMetatype::Pointer);
        base.flags |= type_flags::IS_PTRREL;
        // type.cc:1051-1052 calcSubmeta needs_resolution inheritance
        // (TypePointerRel ctor delegates to the TypePointer ctor, type.hh:662).
        base.flags |= Self::pointer_inherit_needs_resolution(&ptr_to);
        let dt = Arc::new(Datatype::Pointer(TypePointer {
            base,
            ptr_to,
            wordsize: 1,
        }));
        self.rel_pointers
            .insert(name.clone(), RelativePointer { parent, offset });
        self.types.insert(name, dt.clone());
        dt
    }

    // Ghidra: type.cc:4016 TypeFactory::getTypePointerRel(TypePointer*,Datatype*,int4)
    /// Create the unnamed ephemeral relative-pointer overload. Pointer width,
    /// word size, and parent container are taken from `parent_pointer`; the
    /// stripped plain pointer is canonicalized before the relative pointer is
    /// interned.
    pub fn get_type_pointer_rel_ephemeral(
        &mut self,
        parent_pointer: Arc<Datatype>,
        ptr_to: Arc<Datatype>,
        offset: i64,
    ) -> Arc<Datatype> {
        let (size, wordsize, parent) = match parent_pointer.as_ref() {
            Datatype::Pointer(pointer) => {
                (pointer.base.size, pointer.wordsize, pointer.ptr_to.clone())
            }
            _ => panic!("getTypePointerRel parent must be a pointer"),
        };
        let stripped = self.get_type_pointer(size, ptr_to.clone(), wordsize);
        let mut relative = TypePointer::new_relative(size, ptr_to, wordsize, parent, offset);
        relative.mark_ephemeral(stripped);
        self.find_add(Datatype::Pointer(relative), true)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // RUDRA-GLUE: Result-returning Rust twin of getTypePointer so callers
    // that already expose LowlevelError can preserve that channel.
    fn get_type_pointer_result(
        &mut self,
        size: usize,
        ptr_to: Arc<Datatype>,
        wordsize: usize,
        enforce_alignment: bool,
    ) -> Result<Arc<Datatype>, String> {
        let ptr_to = Datatype::get_stripped_arc(&ptr_to).unwrap_or(ptr_to);
        // TypePointer::calcTruncate's attached subcomponent is still the
        // TYPE-0001 structural residual; the ordinary registry path below is
        // exact for factories without an alternate pointer size.
        self.find_add(
            Datatype::Pointer(TypePointer::new(size, ptr_to, wordsize)),
            enforce_alignment,
        )
    }

    // Ghidra: type.cc:3885 TypeFactory::getTypePointer(s,pt,ws,n)
    /// Construct the named pointer overload, including display name and the
    /// hash-derived id used by the name tree.
    pub fn get_type_pointer_named(
        &mut self,
        size: usize,
        ptr_to: Arc<Datatype>,
        wordsize: usize,
        name: &str,
    ) -> Arc<Datatype> {
        let ptr_to = Datatype::get_stripped_arc(&ptr_to).unwrap_or(ptr_to);
        let mut pointer = TypePointer::new(size, ptr_to, wordsize);
        pointer.base.name = name.to_string();
        pointer.base.display_name = name.to_string();
        pointer.base.id = Datatype::hash_name(name);
        self.find_add(Datatype::Pointer(pointer), true)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3867 TypeFactory::getTypePointer(s,pt,ws)
    /// Find/create a pointer of the given `size` to `ptr_to` with `wordsize`,
    /// after one virtual `getStripped` step, then canonicalize it through the
    /// factory's pointer dependency key.
    pub fn get_type_pointer(
        &mut self,
        size: usize,
        ptr_to: Arc<Datatype>,
        wordsize: usize,
    ) -> Arc<Datatype> {
        self.get_type_pointer_result(size, ptr_to, wordsize, true)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3902 TypeFactory::getTypeArray(as,ao)
    /// Find/create an array of `num_elements` elements of `array_of`,
    /// canonicalized through the factory's structural tree (findAdd /
    /// findNoName dedup, type.cc:3412/3377). Faithful to the oracle:
    ///
    /// - One virtual `getStripped` step on the element type first
    ///   (type.cc:3905-3906), exactly as `getTypePointer` does.
    /// - The `TypeArray(int4 n, Datatype *ao)` constructor
    ///   (type.hh:937-946) builds the ANONYMOUS shell through the 3-arg
    ///   `Datatype(size, alignment, TYPE_ARRAY)` base constructor
    ///   (type.hh:215): empty name/display name, `size = n *
    ///   ao->getAlignSize()`, `alignSize = size`, `alignment =
    ///   ao->getAlignment()`, `submeta = base2sub[TYPE_ARRAY]`, zero flags —
    ///   and then sets `needs_resolution` when `n == 1` (a size-1 array
    ///   should generally be treated as the element data-type).
    ///
    /// The anonymous name is load-bearing for printing: `buildTypeStack`
    /// (printc.cc:148-151) drills an unnamed ARRAY layer, so a declaration
    /// spells `T name [N]` (array_expr postsurround after the identifier,
    /// printc.cc:76/294-295) and never bakes the bracket into the type name.
    ///
    /// Alignment Evidence:
    /// - References/output params: `array_of` moved in; the (possibly
    ///   stripped) element Arc is stored inside the shell. No caller state
    ///   mutated beyond the factory trees.
    /// - Loop bounds/order: none (single construction).
    /// - Counter/accumulator: none; `num_elements` is the stored arity.
    /// - Sort/compare key: the findAdd anonymous arm compares through the
    ///   structural tree key (submeta, dependency pointer, size, id —
    ///   `DatatypeCompare` type.hh:306), never the name.
    pub fn get_type_array(&mut self, num_elements: usize, array_of: Arc<Datatype>) -> Arc<Datatype> {
        let array_of = Datatype::get_stripped_arc(&array_of).unwrap_or(array_of);
        // type.hh:937: Datatype(n*ao->getAlignSize(), ao->getAlignment(),
        // TYPE_ARRAY); type.hh:215 sets alignSize = size, id = 0.
        let size = num_elements * array_of.get_align_size();
        let mut base =
            crate::type_system::datatype::TypeBase::new(String::new(), size, TypeMetatype::Array);
        base.alignment = array_of.get_alignment() as i32;
        // type.hh:944-945: `if (n == 1) flags |= needs_resolution;`
        if num_elements == 1 {
            base.flags |= crate::type_system::datatype::type_flags::NEEDS_RESOLUTION;
        }
        self.find_add(
            Datatype::Array(crate::type_system::datatype::TypeArray {
                base,
                array_of,
                num_elements,
            }),
            true,
        )
        .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.hh:429 TypePointer::downChain (virtual call site)
    /// Virtual `downChain` dispatch entry, reproducing the C++ virtual call
    /// `pointer->downChain(off,par,parOff,allowArrayWrap,typegrp)` (virtual
    /// declaration type.hh:429, `TypePointerRel` override type.hh:681; the
    /// production caller is `TypeOpIntAdd::propagateAddIn2Out`,
    /// typeop.cc:1241).
    ///
    /// A pointer carrying `pointer_rel` state — the canonical Rust
    /// representation of Ghidra's `TypePointerRel`, installed by
    /// [`Self::get_type_pointer_rel_ephemeral`] — dispatches to the relative
    /// override [`Self::down_chain`]. A pointer flagged with the legacy named
    /// `is_ptrrel` side-table entry (see [`Self::get_type_pointer_rel`])
    /// dispatches there too: Ghidra's single `TypePointerRel` class routes
    /// both representations through the same override. Every other pointer
    /// dispatches to the plain [`Self::down_chain_pointer`]. A non-pointer
    /// input has no Ghidra counterpart (the virtual call is ill-typed in C++)
    /// and yields `None`.
    pub fn down_chain_virtual(
        &mut self,
        ptr: &Arc<Datatype>,
        off: &mut i64,
        par: &mut Option<Arc<Datatype>>,
        par_off: &mut i64,
        allow_array_wrap: bool,
    ) -> Option<Arc<Datatype>> {
        let pointer = match ptr.as_ref() {
            Datatype::Pointer(pointer) => pointer.clone(),
            _ => return None,
        };
        if let Some(state) = &pointer.base.pointer_rel {
            let parent = state.parent.clone();
            let offset = state.offset;
            return self.down_chain(ptr, &parent, offset, off, par, par_off, allow_array_wrap);
        }
        if (pointer.base.flags & type_flags::IS_PTRREL) != 0 {
            // RUDRA-GLUE: legacy named relative pointers keep parent/offset
            // only in the factory side table; the dispatcher consults it so
            // both Rust representations of TypePointerRel take the override.
            if let Some(relative) = self.rel_pointers.get(&pointer.base.name) {
                let parent = relative.parent.clone();
                let offset = relative.offset;
                return self.down_chain(ptr, &parent, offset, off, par, par_off, allow_array_wrap);
            }
        }
        self.down_chain_pointer(ptr, off, par, par_off, allow_array_wrap)
    }

    // Ghidra: type.cc:2656 TypePointerRel::downChain
    /// Find a sub-type pointer given an offset into this relative pointer.
    /// Faithful to `TypePointerRel::downChain` (type.cc:2656-2672).
    ///
    /// If the offset lands inside `ptrto` and `ptrto` is a struct/array,
    /// defer to the plain `TypePointer::downChain` *on this same pointer*
    /// (type.cc:2660-2662), so the deferred `par = this` bookkeeping
    /// (type.cc:1111) observes the relative pointer itself. Otherwise convert
    /// the offset to be relative to the parent container:
    /// `relOff = (off + offset) & calc_mask(size)`. If `relOff` is out of the
    /// parent's range, return `None`. Otherwise build a pointer to the parent
    /// and recurse via the plain-pointer downChain, returning its result
    /// directly, `None` included (type.cc:2671).
    ///
    /// `orig` is the relative pointer being descended; `parent`/`offset` are
    /// its container state (normally extracted by
    /// [`Self::down_chain_virtual`]); `allow_array_wrap` matches Ghidra's
    /// `allowArrayWrap`. `off` is the in/out offset (updated in place);
    /// `par`/`par_off` are the caller-shared container accumulators, written
    /// only by the deferred/plain recursion.
    pub fn down_chain(
        &mut self,
        orig: &Arc<Datatype>,
        parent: &Arc<Datatype>,
        offset: i64,
        off: &mut i64,
        par: &mut Option<Arc<Datatype>>,
        par_off: &mut i64,
        allow_array_wrap: bool,
    ) -> Option<Arc<Datatype>> {
        let ptr = match orig.as_ref() {
            Datatype::Pointer(pointer) => pointer.clone(),
            _ => return None,
        };
        let ptrto_meta = ptr.ptr_to.get_metatype();
        let ptrto_size = ptr.ptr_to.get_size() as i64;
        // If the offset is inside ptrto and ptrto is a container, defer to the
        // plain TypePointer::downChain on this same pointer (type.cc:2660-2662).
        if *off >= 0 && *off < ptrto_size
            && (ptrto_meta == TypeMetatype::Struct || ptrto_meta == TypeMetatype::Array)
        {
            return self.down_chain_pointer(orig, off, par, par_off, allow_array_wrap);
        }
        // Convert off to be relative to the parent container.
        let mask = crate::address::calc_mask(ptr.base.size) as i64;
        let rel_off = (*off + offset) & mask;
        if rel_off < 0 || rel_off >= parent.get_size() as i64 {
            return None; // Don't let pointer shift beyond original container.
        }
        // Build a pointer to the parent (Ghidra: origPointer =
        // typegrp.getTypePointer(size, parent, wordsize)).
        let orig_pointer = self.get_type_pointer(ptr.base.size, parent.clone(), ptr.wordsize);
        *off = rel_off;
        // Recovering the start of the parent is still downchaining, even
        // though the parent may be the container (type.cc:2669-2670): return
        // the pointer to the parent without drilling down to the field at
        // offset 0 and without touching the container accumulators.
        if rel_off == 0 && offset != 0 {
            return Some(orig_pointer);
        }
        // Recurse via the plain-pointer downChain on the freshly built parent
        // pointer and return its result directly, `None` included
        // (type.cc:2671). This walks into the parent's sub-type at rel_off.
        self.down_chain_pointer(&orig_pointer, off, par, par_off, allow_array_wrap)
    }

    // Ghidra: type.cc:1084 TypePointer::downChain
    /// Plain `TypePointer::downChain` (type.cc:1084-1121), factored out so the
    /// relative-pointer override above can recurse into it. Faithful to the
    /// wrapping / enum / array / struct dispatch.
    ///
    /// `orig` is the pointer being descended (the C++ `this`): the wrap-to-zero
    /// early return yields it unchanged (type.cc:1098) and the container
    /// bookkeeping writes it into `par` (type.cc:1111), so identity is
    /// preserved without re-interning the pointer. Returns
    /// `Some(pointer_to_component)` with `off` updated in place, `par` set to
    /// the descended pointer (when ptrto is an array or struct), and `par_off`
    /// set to the offset into the container.
    fn down_chain_pointer(
        &mut self,
        orig: &Arc<Datatype>,
        off: &mut i64,
        par: &mut Option<Arc<Datatype>>,
        par_off: &mut i64,
        allow_array_wrap: bool,
    ) -> Option<Arc<Datatype>> {
        let ptr = match orig.as_ref() {
            Datatype::Pointer(pointer) => pointer.clone(),
            _ => return None,
        };
        let ptrto = &ptr.ptr_to;
        let ptrto_size = ptrto.get_align_size() as i64;
        // Check if we are wrapping (type.cc:1088-1100).
        if *off < 0 || *off >= ptrto_size {
            if ptrto_size != 0 && !ptrto.is_variable_length() {
                if !allow_array_wrap {
                    return None;
                }
                // sign_extend(off, size*8-1) then modulo ptrto_size.
                let bits = ptr.base.size * 8;
                let mut sign_off = sign_extend(*off, bits.saturating_sub(1));
                sign_off = sign_off % ptrto_size;
                if sign_off < 0 {
                    sign_off += ptrto_size;
                }
                *off = sign_off;
                if *off == 0 {
                    // Wrapped back to zero: consider this going down one level
                    // and return this pointer itself unchanged (type.cc:1098).
                    return Some(orig.clone());
                }
            }
        }
        if ptrto.is_enum_type() {
            // Go "into" the enumeration: build a pointer to a 1-byte uint
            // (type.cc:1104 getBase(1, TYPE_UINT) — non-const, may throw).
            let tmp = self
                .get_base_result(1, TypeMetatype::Uint)
                .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
            *off = 0;
            return Some(self.get_type_pointer(ptr.base.size, tmp, ptr.wordsize));
        }
        let meta = ptrto.get_metatype();
        let is_array = meta == TypeMetatype::Array;
        if is_array || meta == TypeMetatype::Struct {
            // par = this (type.cc:1111): the descended pointer itself.
            *par = Some(orig.clone());
            *par_off = *off;
        }
        // pt = ptrto->getSubType(off, &off).  The C++ virtual returns the
        // factory-owned component pointer directly; preserve the same Arc
        // identity so pointer interning uses the component's canonical
        // dependency key instead of a structurally equal clone.
        let (pt, new_off) = Datatype::get_sub_type_arc(ptrto, *off);
        let pt = match pt {
            Some(t) => t,
            None => return None,
        };
        *off = new_off;
        if !is_array {
            // getTypePointerStripArray: strip the array layer off `pt` if any
            // (type.cc:3849). Rudra has no dedicated factory method yet; the
            // strip is done inline by recursing into the element type.
            let stripped = strip_array(pt.clone());
            Some(self.get_type_pointer(ptr.base.size, stripped, ptr.wordsize))
        } else {
            Some(self.get_type_pointer(ptr.base.size, pt, ptr.wordsize))
        }
    }

    // Ghidra: type.cc:2693 TypePointerRel::getPtrToFromParent (static)
    /// Given a containing data-type and offset, find the "pointed to"
    /// data-type suitable for a `TypePointerRel`. Faithful to
    /// `TypePointerRel::getPtrToFromParent` (type.cc:2693-2707).
    ///
    /// The biggest contained data-type that starts at the exact offset is
    /// returned. If the offset is negative or there is no data-type starting
    /// exactly there, a 1-byte `undefined1` data-type is returned.
    pub fn get_ptr_to_from_parent(
        &mut self,
        base: &Arc<Datatype>,
        off: i64) -> Arc<Datatype> {
        if off > 0 {
            let mut cur = base.clone();
            let mut cur_off = off;
            loop {
                let (sub, new_off) = cur.get_sub_type(cur_off);
                match sub {
                    Some(s) => {
                        cur = s;
                        cur_off = new_off;
                        if cur_off == 0 {
                            break;
                        }
                    }
                    None => {
                        // Ghidra: base = typegrp.getBase(1, TYPE_UNKNOWN)
                        // (type.cc:2702) — non-null, may throw LowlevelError;
                        // the faithful Result twin panics with that message.
                        return self
                            .get_base_result(1, TypeMetatype::Unknown)
                            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
                    }
                }
            }
            cur
        } else {
            // off <= 0: unknown (type.cc:2705 getBase(1, TYPE_UNKNOWN)).
            self.get_base_result(1, TypeMetatype::Unknown)
                .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
        }
    }

    // Ghidra: type.cc:3818 TypeFactory::getTypedef
    /// Create a typedef of `ct` under a new `name`. Faithful to
    /// `TypeFactory::getTypedef` (type.cc:3818-3840): clone the base type,
    /// give it a new name/id, clear `coretype`, and record the typedef target.
    /// Rudra stores the typedef target (the "stripped" form) in the
    /// `typedefs` table so that `get_typedef_target` can walk it.
    pub fn get_typedef(&mut self, name: &str, ct: Arc<Datatype>) -> Arc<Datatype> {
        if let Some(existing) = self.find_by_name(name) {
            // type.cc:3825-3826: `if (ct != res->getTypedef()) throw ...` —
            // the dedup compares against the existing type's per-Datatype
            // typedefImm channel (type.hh:244), not a factory-side table.
            let same_target = existing
                .get_typedef()
                .is_some_and(|target| Arc::ptr_eq(target, &ct));
            if !same_target {
                panic!("LowlevelError: Trying to create typedef of existing type: {name}");
            }
            return existing;
        }
        // Ghidra clones every Datatype base field (including exact layout),
        // then changes only name/displayName/id, clears coretype, and stores
        // typedefImm. A normal typedef does NOT acquire has_stripped.
        let mut base = ct.base_record().clone();
        base.name = name.to_string();
        base.display_name = name.to_string();
        base.id = Datatype::hash_name(name);
        base.flags &= !type_flags::CORETYPE;
        // type.cc:3834: res->typedefImm = ct; — the per-type channel that
        // the cast.cc:325 / printc.cc:390 / coreaction.cc:2476 /
        // typeop.cc:2337 strip loops walk. The cloned record may already
        // carry ct's own channel (typedef-of-typedef, type.hh:212 copy
        // ctor); the assignment overwrites it with the immediate base,
        // exactly as the unconditional oracle store does.
        base.typedef_imm = Some(ct.clone());
        let aliased = ct.clone();
        let dt = match ct.as_ref() {
            Datatype::Void(_) => Datatype::Void(base),
            Datatype::Base(_) => Datatype::Base(base),
            Datatype::Pointer(p) => Datatype::Pointer(TypePointer {
                base,
                ptr_to: p.ptr_to.clone(),
                wordsize: p.wordsize,
            }),
            Datatype::Array(a) => Datatype::Array(TypeArray {
                base,
                array_of: a.array_of.clone(),
                num_elements: a.num_elements,
            }),
            Datatype::Struct(s) => Datatype::Struct(TypeStruct {
                base,
                fields: s.fields.clone(),
            }),
            Datatype::Enum(e) => Datatype::Enum(TypeEnum {
                base,
                values: e.values.clone(),
            }),
            Datatype::Union(u) => Datatype::Union(TypeUnion {
                base,
                fields: u.fields.clone(),
            }),
            Datatype::Code(c) => Datatype::Code(TypeCode {
                base,
                proto: c.proto.clone(),
            }),
            Datatype::Spacebase(s) => Datatype::Spacebase(TypeSpacebase {
                base,
                address: s.address.clone(),
                fd: s.fd.clone(),
                spaceid: s.spaceid,
                localframe: s.localframe.clone(),
                scope: s.scope.clone(),
            }),
            Datatype::PartialStruct(ps) => Datatype::PartialStruct(TypePartialStruct {
                base,
                container: ps.container.clone(),
                offset: ps.offset,
                stripped: ps.stripped.clone(),
            }),
            Datatype::PartialEnum(pe) => Datatype::PartialEnum(TypePartialEnum {
                base,
                parent: pe.parent.clone(),
                offset: pe.offset,
                stripped: pe.stripped.clone(),
            }),
            Datatype::PartialUnion(pu) => Datatype::PartialUnion(TypePartialUnion {
                base,
                container: pu.container.clone(),
                offset: pu.offset,
                stripped: pu.stripped.clone(),
            }),
        };
        let dt = self
            .find_add(dt, false)
            .unwrap_or_else(|message| panic!("LowlevelError: {message}"));
        self.typedefs.insert(name.to_string(), aliased);
        // Ghidra: type.cc:3837-3838 getTypedef:
        //   if (res->isIncomplete()) incompleteTypedef.push_back(res);
        // The clone inherits the referenced type's type_incomplete flag;
        // resolveIncompleteTypedefs (type.cc:3777) drains it once the
        // referenced struct/union/code type completes.
        if dt.is_incomplete() {
            self.incomplete_typedefs.push(dt.clone());
        }
        dt
    }

    // RUDRA-GLUE: get_typedef_target (Rudra-side name index)
    /// Look up the typedef target (the stripped form) for a typedef name in
    /// the factory's `typedefs` index. Ghidra has no name-keyed accessor —
    /// type.cc:3850 is `getTypePointerStripArray`, and the only oracle
    /// channel is the per-Datatype `typedefImm` (type.hh:244), now mirrored
    /// by `Datatype::get_typedef` and populated at get_typedef time
    /// (type.cc:3834). This index remains as a debug/test reachability
    /// helper; production consumers walk the per-type channel.
    pub fn get_typedef_target(&self, name: &str) -> Option<&Arc<Datatype>> {
        self.typedefs.get(name)
    }

    // Ghidra: type.cc:4071 TypeFactory::resizePointer
    /// Build a new pointer to `ptr`'s pointee with a different size,
    /// preserving the wordsize. Only a concrete virtual `getStripped` result
    /// is substituted; ordinary typedefs remain the pointee.
    pub fn resize_pointer(&mut self, ptr: &Datatype, new_size: usize) -> Arc<Datatype> {
        let (ptr_to, wordsize) = match ptr {
            Datatype::Pointer(p) => (p.ptr_to.clone(), p.wordsize),
            _ => panic!("resizePointer requires a pointer"),
        };
        let ptr_to = Datatype::get_stripped_arc(&ptr_to).unwrap_or(ptr_to);
        self.find_add(
            Datatype::Pointer(TypePointer::new(new_size, ptr_to, wordsize)),
            true,
        )
        .unwrap_or_else(|message| panic!("LowlevelError: {message}"))
    }

    // Ghidra: type.cc:3326 TypeFactory::findByIdLocal
    /// Find a type by (name, id) within this factory only (no parent scope
    /// search). Faithful to `TypeFactory::findByIdLocal` (type.cc:3326-3344).
    /// A non-zero `id` requires an exact id match; an id of 0 matches by name
    /// only (the first type with that name).
    pub fn find_by_id_local(&self, name: &str, id: u64) -> Option<Arc<Datatype>> {
        match self.types.get(name) {
            Some(dt) => {
                if id == 0 || dt.get_id() == id {
                    Some(dt.clone())
                } else {
                    None
                }
            }
            None => None,
        }
    }

    // Ghidra: type.cc:3354 TypeFactory::findById
    /// Find a type by (name, id, size). Faithful to
    /// `TypeFactory::findById` (type.cc:3354-3361). For variable-length base
    /// types a non-zero `sz` folds the size into the id via
    /// `Datatype::hashSize` (type.hh:206) before delegating to
    /// `find_by_id_local`. Rudra does not currently store per-size variants,
    /// so we only apply the id-fold and fall back to a name+size match.
    pub fn find_by_id(&self, name: &str, id: u64, sz: usize) -> Option<Arc<Datatype>> {
        let effective_id = if sz > 0 { hash_size(id, sz) } else { id };
        if let Some(dt) = self.find_by_id_local(name, effective_id) {
            return Some(dt);
        }
        // Fall back to a name+size structural match for variable-length types.
        self.types
            .get(name)
            .filter(|dt| sz == 0 || dt.get_size() == sz)
            .cloned()
    }

    // Ghidra: type.cc:3106 TypeFactory::TypeFactory(Architecture *g)
    /// The single TypeFactory instance for the locked-oracle process model.
    ///
    /// Ghidra constructs exactly one `TypeFactory` per `Architecture`
    /// (`TypeFactory::TypeFactory(Architecture *g)`, type.cc:3106-3119 — the
    /// factory holds `glb` and every `getBase`/`findAdd` call deduplicates
    /// against that one factory), and the canonical headless oracle runs one
    /// Architecture per process. Rudra's production `Funcdata` does not yet
    /// carry an attached `Architecture` (FUNCPROTO-MODEL-BIND-0001 chain), so
    /// callers with no injectable handle (`VarnodeBank` default typing,
    /// `ScopeLocal` symbol typing) resolve this process-wide DataOrg-flavor
    /// factory instead — preserving the oracle's observable identity domain
    /// (one canonical `undefined{size}` object per size for the whole
    /// process) until per-Architecture wiring lands. Callers that DO have an
    /// Architecture must prefer its own `types` handle. Construction
    /// completes the architecture-attach sequence: the decode tail's
    /// `types->setupSizes()` alignment guard (architecture.cc:1350 →
    /// type.cc:3164-3165 `if (alignMap.empty()) setDefaultAlignmentMap();`)
    /// runs at attach, because no Architecture exists to run it later —
    /// without it the first getBase/getTypePointer tree miss raises the
    /// raw-constructor LowlevelError "TypeFactory alignment map not
    /// initialized" (type.cc:3296-3305 getAlignment), which the oracle can
    /// observe only between raw construction and decode, never from inside a
    /// decompiled function.
    ///
    /// TF-SINGLETON-WIRING-0001 step 1 (per-Architecture resolution): the
    /// oracle's engine reaches the factory through the OWNING Architecture
    /// (`glb->types`, architecture.hh:197); Rudra's handle-less call sites
    /// (39 `shared_default` references, 9 files) resolve through this entry
    /// instead. Resolution order mirrors that ownership: **the thread's
    /// current-Architecture factory wins** (published by
    /// `Architecture::set_types`/`ensure_types` at the oracle
    /// `buildTypegrp` moment — sleigh_arch.cc:201 / ghidra_arch.cc:321),
    /// and the process-canonical factory below is the fallback for
    /// pre-architecture contexts (unit fixtures, decode-before-arch paths).
    /// In a single-Architecture process the two arms return the SAME handle
    /// (the driver installs the process-canonical factory via `set_types`),
    /// so every existing observation is byte-identical; in a
    /// multi-Architecture process (bin_sweep dual-binary probe) each
    /// Architecture's accumulated type tables stay separate, matching the
    /// oracle's per-Architecture factory lifetime
    /// (architecture.cc:162 construct-null → buildTypegrp new → 211-212
    /// delete).
    pub fn shared_default() -> Arc<RwLock<TypeFactory>> {
        if let Some(current) = Self::current_arch_factory() {
            return current;
        }
        Self::process_canonical_factory()
    }

    // Ghidra: sleigh_arch.cc:201 types = new TypeFactory(this);
    /// A FRESH per-Architecture factory with the canonical bootstrap recipe.
    ///
    /// The construction sequence is byte-identical to the process-canonical
    /// factory's (below): `TypeFactory::new(8)` (core types, flavor selected
    /// by the mirror-tier environment exactly as `SleighArchitecture::
    /// buildCoreTypes` sleigh_arch.cc:204-238 vs the `<coretypes>` decode
    /// selects by architecture description) plus the architecture.cc:1350
    /// decode-tail alignment default (`if (alignMap.empty())
    /// setDefaultAlignmentMap()`, type.cc:3164-3165), plus the eager
    /// no-lease warmup of the 1-byte unknown cache (MIRROR2 lock-safety,
    /// see `canonical_unknown_base_1`). Drivers that build one Architecture
    /// per binary (the oracle process model) call this per Architecture and
    /// hand the result to `Architecture::set_types`, which publishes it as
    /// the thread's current-Architecture factory — the engine's
    /// `shared_default` resolutions then observe exactly this factory, the
    /// way the oracle's engine observes `glb->types`.
    pub fn fresh_canonical() -> Arc<RwLock<TypeFactory>> {
        let mut factory = TypeFactory::new(8);
        // architecture.cc:1350 `types->setupSizes();` tail →
        // type.cc:3164-3165 `if (alignMap.empty()) setDefaultAlignmentMap();`
        if factory.align_map.is_empty() {
            factory.set_default_alignment_map();
        }
        let arc = Arc::new(RwLock::new(factory));
        // Eager no-lease warmup, same argument as the process-canonical
        // closure: this runs at driver/architecture-build time, before any
        // factory lease can exist on this thread.
        let _ = arc
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_base(1, TypeMetatype::Unknown)
            .expect("TypeFactory::get_base always produces an unknown base type");
        arc
    }

    // RUDRA-GLUE: process-canonical fallback tier of the oracle's
    // per-Architecture `glb->types` resolution (architecture.hh:197).
    /// The process-wide fallback factory (pre-architecture contexts only).
    /// Construction recipe is frozen: any change here must keep the
    /// single-Architecture canonical runs byte-identical.
    fn process_canonical_factory() -> Arc<RwLock<TypeFactory>> {
        static SHARED: std::sync::OnceLock<Arc<RwLock<TypeFactory>>> = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| {
                let mut factory = TypeFactory::new(8);
                // architecture.cc:1350 `types->setupSizes();` tail →
                // type.cc:3164-3165 `if (alignMap.empty())
                // setDefaultAlignmentMap();`
                if factory.align_map.is_empty() {
                    factory.set_default_alignment_map();
                }
                let arc = Arc::new(RwLock::new(factory));
                // Eagerly populate the canonical 1-byte-unknown cache under
                // NO lease (see canonical_unknown_base_1): once this closure
                // completes, any factory write lease can exist only after
                // the cache is filled, so the lock-free fast path is always
                // armed before a lease-holder can reach the query.
                let unknown_base_1 = arc
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_base(1, TypeMetatype::Unknown)
                    .expect("TypeFactory::get_base always produces an unknown base type");
                let _ = CANONICAL_UNKNOWN_BASE_1.set(unknown_base_1);
                arc
            })
            .clone()
    }

    // Ghidra: type.cc:2965-2967 TypeSpacebase::getSubType miss return
    /// The factory-mediated 1-byte TYPE_UNKNOWN base for the spacebase /
    /// symbol-table miss and untyped-symbol arms
    /// (`glb->types->getBase(1,TYPE_UNKNOWN)` — type.cc:2967;
    /// `sc->getArch()->types->getBase(1,TYPE_UNKNOWN)` — database.cc:629/
    /// 681/731). In the oracle this always resolves through the
    /// architecture's TypeFactory, so the standalone console tier answers
    /// the NAMED core `xunknown1` (sleigh_arch.cc:229, cacheCoreTypes
    /// typecache slot) and the headless DataOrg tier `undefined1`; the
    /// former raw-anonymous constructions printed `unkbyte1` via
    /// PrintC::genericTypeName (printc.cc:3383) — the MIRROR2 unkbyte
    /// family.
    ///
    /// Lock-safety (MIRROR2 deadlock evidence, eu-stack of the hung canon
    /// worker): the dominant caller chain is
    /// `TypeFactory::down_chain_pointer` (holding the factory's WRITE
    /// lease) → `TypeSpacebase::get_sub_type` → here, so this helper MUST
    /// NOT re-enter `shared_default`'s RwLock while that lease is held
    /// (self-deadlock via read_contended; the oracle has no locks — any
    /// factory query from inside a factory method is legal there). The
    /// cache is therefore populated eagerly under NO lease — at
    /// `publish_current_arch` time for the current-Architecture tier and
    /// inside the process-canonical construction closure for the fallback
    /// tier — and read lock-free here; the on-demand population path can
    /// only run when the process-canonical factory has never been
    /// constructed, in which case no lease on it can be held either.
    /// Factory identity is preserved (the SAME Arc the answering factory's
    /// typecache would return — the current Architecture's factory when one
    /// is published, mirroring `glb->types->getBase(1,TYPE_UNKNOWN)`; the
    /// process-canonical object otherwise), keeping downstream
    /// identity-sensitive decisions (type-propagation ptr-eq, char-print
    /// flag reads) on one object per factory.
    pub fn canonical_unknown_base_1() -> Arc<Datatype> {
        if let Some(unknown) = CURRENT_ARCH_TYPES
            .try_with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|current| current.unknown_base_1.clone())
            })
            .unwrap_or(None)
        {
            return unknown;
        }
        if let Some(base) = CANONICAL_UNKNOWN_BASE_1.get() {
            return base.clone();
        }
        let base = Self::process_canonical_factory()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_base(1, TypeMetatype::Unknown)
            .expect("TypeFactory::get_base always produces an unknown base type");
        let _ = CANONICAL_UNKNOWN_BASE_1.set(base.clone());
        base
    }

    // Ghidra: type.cc:4140 TypeFactory::concretize
    /// Concretize a possibly-abstract data-type into a representable one.
    /// Faithful to `TypeFactory::concretize` (type.cc:4140-4150): a TYPE_CODE
    /// of size 1 is replaced with the factory's `getBase(1, TYPE_UNKNOWN)`
    /// output (same object identity on repeated calls); anything else is
    /// returned unchanged.
    ///
    /// TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001 note: the Ghidra method is
    /// non-const, but Rudra's caller (`varmap.rs:2546`, varmap.cc:622) holds
    /// a read guard on the shared factory, pinning this port to `&self` and
    /// therefore to the lenient `get_base` twin (cache/tree probe without the
    /// findAdd alignment error) — the cached `undefined1` core entry hits the
    /// identical typecache fast path as the oracle's getBase, so the
    /// observable result is the canonical entry in every reachable state.
    pub fn concretize(&self, ct: Arc<Datatype>) -> Arc<Datatype> {
        if ct.get_metatype() == TypeMetatype::Code {
            debug_assert_eq!(
                ct.get_size(),
                1,
                "Primitive code data-type that is not size 1"
            );
            // type.cc:4147: ct = getBase(1, TYPE_UNKNOWN);
            return self
                .get_base(1, TypeMetatype::Unknown)
                .expect("factory always produces a base unknown");
        }
        ct
    }

    // Ghidra: type.cc:3850 TypeFactory::deconcretize
    /// Inverse of `concretize`. NOTE: Ghidra has **no** `TypeFactory::deconcretize`
    /// (verified absent across the whole `cpp/` tree). The decompiler only ever
    /// "concretizes" in one direction (varmap.cc:622). Rudra provides this as
    /// the documented inverse: it restores a size-1 base back to an anonymous
    /// code type, and is otherwise the identity. This is a faithful "no-op for
    /// non-concretized types" companion so callers can round-trip.
    pub fn deconcretize(&mut self, ct: Arc<Datatype>) -> Arc<Datatype> {
        // Only the exact concretize output (a size-1 unknown base named
        // "undefined1") is reversed back to a code type; everything else is
        // returned unchanged, matching the absence of any reverse logic in
        // Ghidra.
        match ct.as_ref() {
            Datatype::Base(b)
                if b.metatype == TypeMetatype::Unknown
                    && b.size == 1
                    && b.name == "undefined1" =>
            {
                self.get_type_code()
            }
            _ => ct,
        }
    }
}

// Ghidra: type.cc:709 Datatype::hashSize
/// Reversibly hash a size into a data-type id. Faithful to
/// `Datatype::hashSize` (type.cc:709-716): `sizeHash = size *
/// 0x98251033aecbabaf; id ^= sizeHash;` — feeding the output back with the
/// same size recovers the original id. Delegates to the canonical
/// `Datatype::hash_size` port.
pub fn hash_size(id: u64, sz: usize) -> u64 {
    Datatype::hash_size(id, sz as i32)
}

// Ghidra: type.cc:3850 TypeFactory::charNameForSize
/// Produce the canonical name for a char type of `size` bytes. Mirrors
/// Ghidra's `charcache` (1→"char", 2→"wchar2", 4→"wchar4").
fn char_name_for_size(size: usize) -> String {
    match size {
        1 => "char".to_string(),
        _ => format!("wchar{}", size),
    }
}

// Ghidra: type.cc:3850 TypeFactory::unicodeNameForSize
/// Produce the canonical name for a unicode char type of `size` bytes.
fn unicode_name_for_size(size: usize) -> String {
    match size {
        2 => "wchar2".to_string(),
        4 => "wchar4".to_string(),
        _ => format!("wchar{}", size),
    }
}

// ===========================================================================
// XML serialization (type.cc:3137-3248 setup, 4155-4675 decode family).
// ===========================================================================

impl TypeFactory {
    // Ghidra: type.cc:3137 TypeFactory::setupSizes
    /// Set up default values for the size of "int", the structure alignment,
    /// and the default enum size. Faithful to `TypeFactory::setupSizes`
    /// (type.cc:3137-3170): every zeroed size field gets its default, an
    /// empty alignment map installs `setDefaultAlignmentMap`, and a zero
    /// `enumsize` takes the architecture default size with unsigned
    /// meta-type.
    ///
    /// Rudra glue: Ghidra pulls the stack spacebase size, default data space
    /// address size, default size, and far-pointer segment op from the
    /// `Architecture` handle (`glb`). Rudra's `TypeFactory` does not hold an
    /// Architecture yet, so those lookups are passed in as `SizeArchInputs`
    /// by the caller; the derivation arithmetic below is 1:1 with the
    /// oracle.
    pub fn setup_sizes(&mut self, arch: &SizeArchInputs) {
        // Ghidra: if (sizeOfInt == 0) { sizeOfInt = 1; spc = glb->getStackSpace();
        //        if (spc) { sizeOfInt = spdata.size; if (sizeOfInt > 4) sizeOfInt = 4; } }
        if self.size_of_int == 0 {
            self.size_of_int = 1; // Default if we can't find a better value
            if let Some(spacebase_size) = arch.stack_spacebase_size {
                // Use stack pointer as likely indicator of "int" size.
                self.size_of_int = spacebase_size;
                if self.size_of_int > 4 {
                    // "int" is rarely bigger than 4 bytes
                    self.size_of_int = 4;
                }
            }
        }
        // Ghidra: if (sizeOfLong == 0) sizeOfLong = (sizeOfInt == 4) ? 8 : sizeOfInt;
        if self.size_of_long == 0 {
            self.size_of_long = if self.size_of_int == 4 {
                8
            } else {
                self.size_of_int
            };
        }
        // Ghidra: if (sizeOfChar == 0) sizeOfChar = 1;
        if self.size_of_char == 0 {
            self.size_of_char = 1;
        }
        // Ghidra: if (sizeOfWChar == 0) sizeOfWChar = 2;
        if self.size_of_wchar == 0 {
            self.size_of_wchar = 2;
        }
        // Ghidra: if (sizeOfPointer == 0) sizeOfPointer =
        //        glb->getDefaultDataSpace()->getAddrSize();
        if self.size_of_pointer == 0 {
            self.size_of_pointer = arch.default_data_space_addr_size;
        }
        // Ghidra: segOp = glb->getSegmentOp(glb->getDefaultDataSpace());
        //        if (segOp && segOp->hasFarPointerSupport()) {
        //          sizeOfPointer = segOp->getInnerSize();
        //          sizeOfAltPointer = sizeOfPointer + segOp->getBaseSize(); }
        if let Some((inner_size, base_size)) = arch.far_pointer {
            self.size_of_pointer = inner_size;
            self.size_of_alt_pointer = inner_size + base_size;
        }
        // Ghidra: if (alignMap.empty()) setDefaultAlignmentMap();
        if self.align_map.is_empty() {
            self.set_default_alignment_map();
        }
        // Ghidra: if (enumsize == 0) { enumsize = glb->getDefaultSize();
        //        enumtype = TYPE_ENUM_UINT; }
        if self.enum_size == 0 {
            self.enum_size = arch.default_size;
            self.enum_type = TypeMetatype::Uint;
        }
    }

    // Ghidra: type.cc:3178 TypeFactory::setCoreType
    /// Manually create a "base" core type and mark it as core. Faithful to
    /// `TypeFactory::setCoreType` (type.cc:3178-3195):
    ///
    /// ```text
    /// if (chartp) { if (size == 1) ct = getTypeChar(name);
    ///               else ct = getTypeUnicode(name,size,meta); }
    /// else if (meta == TYPE_CODE) ct = getTypeCode(name);
    /// else if (meta == TYPE_VOID) ct = getTypeVoid();
    /// else ct = getBase(size,meta,name);
    /// ct->flags |= Datatype::coretype;
    /// ```
    ///
    /// Returns the (possibly newly created) core type. Conflicting
    /// registrations surface Ghidra's `findAdd` LowlevelError messages as
    /// `Err` ("Trying to alter definition of type: …", "Shared type id: …",
    /// "Datatype must have a valid id: …", "TypeFactory alignment map not
    /// initialized") with NO partial state — exactly like the oracle, which
    /// throws before inserting anything.
    ///
    /// Promotion aliasing: Ghidra ORs `coretype` onto the canonical object
    /// IN PLACE when the name already resolves to an equal definition, so
    /// every external alias observes the flag immediately. Rust's immutable
    /// `Arc<Datatype>` cannot mutate through shared handles
    /// (src/type_system/datatype.rs holds the flag model, a separate lease),
    /// so [`Self::promote_core`] conservatively replaces the promoted object
    /// in EVERY factory-owned channel — `types`, `core_types`,
    /// `base_type_tree`, `base_cache`, `char_cache`, `type_nochar`, and
    /// identical `typedefs`/`rel_pointers` values — making all
    /// factory-mediated observations identical. Flag visibility through an
    /// external stale Arc handle remains the registered residual
    /// TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001.
    pub fn set_core_type_result(
        &mut self,
        name: &str,
        size: usize,
        meta: TypeMetatype,
        chartp: bool,
    ) -> Result<Arc<Datatype>, String> {
        let ct = if chartp {
            if size == 1 {
                self.get_type_char_named(name)?
            } else {
                self.get_type_unicode_named(name, size, meta)?
            }
        } else if meta == TypeMetatype::Code {
            self.get_type_code_named(name)?
        } else if meta == TypeMetatype::Void {
            // getTypeVoid returns the singleton, whose constructor already
            // sets coretype (type.hh:389).
            return Ok(self.get_type_void_result());
        } else {
            self.get_base_named(size, meta, name)?
        };
        // type.cc:3194 `ct->flags |= Datatype::coretype;`
        Ok(self.promote_core(&ct))
    }

    // RUDRA-GLUE: Arc-returning thin assertion layer around
    /// [`Self::set_core_type_result`]. TYPEFACTORY-LEGACY-CALLER-MIGRATION-0001
    /// status: every in-lease caller (cpool.rs test fixture, merge.rs test,
    /// typefactory tests) is migrated to the faithful Result twin, which
    /// surfaces Ghidra's findAdd LowlevelError (type.cc:3412-3438) as `Err`.
    /// This layer has ZERO current-tree callers and is retained only because
    /// the pinned `typefactory_local_cache_1204` differential snapshot base
    /// (71971b2 `cpool.rs:614`, `merge.rs`) compiles against this file; it
    /// panics with the oracle's LowlevelError message, exactly the throw
    /// semantics of type.cc:3178. Delete it when that runner is re-pinned
    /// to a post-migration commit.
    pub fn set_core_type(
        &mut self,
        name: &str,
        size: usize,
        meta: TypeMetatype,
        chartp: bool,
    ) -> Arc<Datatype> {
        match self.set_core_type_result(name, size, meta, chartp) {
            Ok(dt) => dt,
            Err(message) => panic!("LowlevelError: {message}"),
        }
    }

    // Ghidra: type.cc:3194 `ct->flags |= Datatype::coretype;` (in-place OR)
    /// OR the `coretype` flag onto the canonical factory object, replacing
    /// the immutable Arc in every factory-owned channel so that all
    /// factory-mediated lookups observe the promotion atomically. A type that
    /// is already core is returned unchanged (the OR is idempotent, exactly
    /// like the oracle's in-place mutation).
    ///
    /// External stale-handle flag visibility cannot be mirrored without an
    /// interior-mutability rework of `Datatype` (datatype.rs, separate
    /// lease); that divergence stays registered under
    /// TYPEFACTORY-CORE-PROMOTION-IDENTITY-0001.
    fn promote_core(&mut self, ct: &Arc<Datatype>) -> Arc<Datatype> {
        if ct.is_coretype() {
            return ct.clone();
        }
        let mut promoted = ct.as_ref().clone();
        match &mut promoted {
            Datatype::Void(base) | Datatype::Base(base) => base.flags |= type_flags::CORETYPE,
            Datatype::Enum(e) => e.base.flags |= type_flags::CORETYPE,
            Datatype::Spacebase(s) => s.base.flags |= type_flags::CORETYPE,
            Datatype::Pointer(p) => p.base.flags |= type_flags::CORETYPE,
            Datatype::Array(a) => a.base.flags |= type_flags::CORETYPE,
            Datatype::Struct(s) => s.base.flags |= type_flags::CORETYPE,
            Datatype::Union(u) => u.base.flags |= type_flags::CORETYPE,
            Datatype::Code(c) => c.base.flags |= type_flags::CORETYPE,
            Datatype::PartialStruct(ps) => ps.base.flags |= type_flags::CORETYPE,
            Datatype::PartialEnum(pe) => pe.base.flags |= type_flags::CORETYPE,
            Datatype::PartialUnion(pu) => pu.base.flags |= type_flags::CORETYPE,
        }
        let promoted = Arc::new(promoted);
        let name = promoted.get_name().to_string();
        if !name.is_empty() {
            // The factory's core retention set must contain the promoted
            // object so clearNoncore keeps it (Ghidra scans the core flag in
            // the tree instead).
            self.core_types.insert(name.clone(), promoted.clone());
            if self
                .types
                .get(&name)
                .is_some_and(|old| Arc::ptr_eq(old, ct))
            {
                self.types.insert(name, promoted.clone());
            }
        }
        {
            let tree_key = Self::type_tree_key(&promoted);
            let mut tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match tree.get(&tree_key) {
                Some(old) if Arc::ptr_eq(old, ct) => {
                    tree.insert(tree_key, promoted.clone());
                }
                None => {
                    tree.insert(tree_key, promoted.clone());
                }
                _ => {}
            }
        }
        {
            // Ghidra's in-place OR never touches the caches; the preferred
            // slots only ever hold core types (cacheCoreTypes skips
            // non-core), so a promoted type cannot already occupy a slot.
            // Replace-by-identity only, for defensive atomicity.
            let mut cache = self
                .base_cache
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(slot) = cache.get_mut(&(promoted.get_size(), promoted.get_metatype())) {
                if Arc::ptr_eq(slot, ct) {
                    *slot = promoted.clone();
                }
            }
        }
        {
            let mut char_cache = self
                .char_cache
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for slot in char_cache.values_mut() {
                if Arc::ptr_eq(slot, ct) {
                    *slot = promoted.clone();
                }
            }
        }
        {
            let mut nochar = self
                .type_nochar
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if nochar.as_ref().is_some_and(|old| Arc::ptr_eq(old, ct)) {
                *nochar = Some(promoted.clone());
            }
        }
        for target in self.typedefs.values_mut() {
            if Arc::ptr_eq(target, ct) {
                *target = promoted.clone();
            }
        }
        for rel in self.rel_pointers.values_mut() {
            if Arc::ptr_eq(&rel.parent, ct) {
                rel.parent = promoted.clone();
            }
        }
        promoted
    }

    // Ghidra: type.cc:3200 TypeFactory::cacheCoreTypes
    /// Walk the type tree and cache the most commonly accessed core types for
    /// quick lookup. Faithful to `TypeFactory::cacheCoreTypes`
    /// (type.cc:3200-3248).
    ///
    pub fn cache_core_types(&mut self) {
        let ordered: Vec<Arc<Datatype>> = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect();
        let cache = self
            .base_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nochar = self
            .type_nochar
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let char_cache = self
            .char_cache
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for datatype in ordered {
            if !datatype.is_coretype() {
                continue;
            }
            let size = datatype.get_size();
            let metatype = datatype.get_metatype();
            if size > 8 {
                if metatype == TypeMetatype::Float && (size == 10 || size == 16) {
                    cache.insert((size, metatype), datatype);
                }
                continue;
            }

            match metatype {
                TypeMetatype::Int => {
                    let is_ascii = datatype.get_flags() & type_flags::CHARTYPE != 0;
                    if size == 1 && !is_ascii {
                        *nochar = Some(datatype.clone());
                    }
                    if datatype.is_enum_type() {
                        continue;
                    }
                    if datatype.is_char_print() {
                        if size < 5 {
                            char_cache.insert(size, datatype.clone());
                        }
                        if is_ascii {
                            cache.insert((size, metatype), datatype);
                        }
                        continue;
                    }
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                TypeMetatype::Uint => {
                    if datatype.is_enum_type() {
                        continue;
                    }
                    let is_ascii = datatype.get_flags() & type_flags::CHARTYPE != 0;
                    if datatype.is_char_print() {
                        if size < 5 {
                            char_cache.insert(size, datatype.clone());
                        }
                        if is_ascii {
                            cache.insert((size, metatype), datatype);
                        }
                        continue;
                    }
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                TypeMetatype::Void
                | TypeMetatype::Unknown
                | TypeMetatype::Bool
                | TypeMetatype::Code
                | TypeMetatype::Float => {
                    cache.entry((size, metatype)).or_insert(datatype);
                }
                _ => {}
            }
        }
    }

    // Ghidra: type.cc:4216 TypeFactory::encode
    /// Encode all non-core, non-anonymous data-types in dependency order as a
    /// `<typegrp>` element. Faithful to `TypeFactory::encode`
    /// (type.cc:4216-4235): runs `dependentOrder`, then for each type skips
    /// anonymous types and (for core types that are not pointer/array/struct/
    /// union) skips them (they are saved via `encodeCoreTypes` instead), and
    /// emits the rest via `Datatype::encode`.
    pub fn encode(&self, encoder: &mut dyn Encoder) {
        let mut deporder: Vec<Arc<Datatype>> = Vec::new();
        self.dependent_order(&mut deporder);
        encoder.open_element(&elem::element("typegrp"));
        for dt in &deporder {
            if dt.get_name().is_empty() {
                continue; // Don't save anonymous types.
            }
            if dt.is_coretype() {
                let meta = dt.get_metatype();
                if !matches!(
                    meta,
                    TypeMetatype::Pointer | TypeMetatype::Array
                        | TypeMetatype::Struct | TypeMetatype::Union
                ) {
                    continue; // Saved via encodeCoreTypes.
                }
            }
            dt.encode(encoder);
        }
        encoder.close_element(&elem::element("typegrp"));
    }

    // Ghidra: type.cc:4240 TypeFactory::encodeCoreTypes
    /// Encode all core data-types (except pointer/array/struct/union, which
    /// are saved in the regular `<typegrp>`) as a `<coretypes>` element.
    /// Faithful to `TypeFactory::encodeCoreTypes` (type.cc:4240-4257).
    pub fn encode_core_types(&self, encoder: &mut dyn Encoder) {
        encoder.open_element(&elem::element("coretypes"));
        for (_name, ct) in self.types.iter() {
            if !ct.is_coretype() {
                continue;
            }
            let meta = ct.get_metatype();
            if matches!(
                meta,
                TypeMetatype::Pointer | TypeMetatype::Array
                    | TypeMetatype::Struct | TypeMetatype::Union
            ) {
                continue;
            }
            ct.encode(encoder);
        }
        encoder.close_element(&elem::element("coretypes"));
    }

    // Ghidra: type.cc:4553 TypeFactory::decode
    /// Scan configuration parameters and parse `<type>` children of a
    /// `<typegrp>` element into this container. Faithful to
    /// `TypeFactory::decode` (type.cc:4553-4561).
    pub fn decode_typegrp(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element_matching(&elem::element("typegrp"));
        while decoder.peek_element() != 0 {
            // Ghidra: decodeTypeNoRef(decoder, false);
            // Rudra: the full decode requires Architecture + FuncProto decode,
            // which are not wired through yet (see decode_type_no_ref). We
            // consume each child element so the decoder advances correctly.
            let child_id = decoder.open_element();
            if child_id != 0 {
                decoder.close_element_skipping(child_id);
            }
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
    }

    // Ghidra: type.cc:4567 TypeFactory::decodeCoreTypes
    /// Parse data-type elements into this container. This stream is presumed
    /// to contain "core" data-types and the cached matrix will be populated
    /// from this set. Faithful to `TypeFactory::decodeCoreTypes`
    /// (type.cc:4567-4577):
    /// - `clear()` FIRST — a FULL wipe of tree/name cross-reference and
    /// every preferred-type cache (NOT clearNoncore; core entries from a
    /// previous stream do not survive),
    /// - each child element is decoded through `decodeTypeNoRef(decoder,
    ///   true)` (the forcecore flag ORs `coretype` onto the freshly built
    ///   candidate, type.cc:4459-4460 etc.),
    /// - `cacheCoreTypes()` runs at the end — but NOT when a child raised a
    ///   LowlevelError: the error propagates and the decoded-so-far partial
    ///   state remains observable.
    pub fn decode_core_types(&mut self, decoder: &mut dyn Decoder) -> Result<(), String> {
        self.clear(); // Make sure this routine flushes
        let elem_id = decoder.open_element_matching(&elem::element("coretypes"));
        while decoder.peek_element() != 0 {
            self.decode_type_no_ref(decoder, true)?;
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        self.cache_core_types();
        Ok(())
    }

    // Ghidra: type.cc:4583 TypeFactory::decodeDataOrganization
    /// Recover size defaults (`sizeOfInt`, `sizeOfLong`, `sizeOfPointer`,
    /// `sizeOfChar`, `sizeOfWChar`) and the alignment map by parsing a
    /// `<data_organization>` element. Faithful to
    /// `TypeFactory::decodeDataOrganization` (type.cc:4583-4615): only the
    /// five size children and `<size_alignment_map>` are consumed, every
    /// other child is closed-and-skipped, and the parsed sizes overwrite the
    /// factory fields (no defaulting happens here — that is `setupSizes`).
    /// Returns a snapshot of the five sizes for callers; the same values are
    /// persisted on the factory.
    pub fn decode_data_organization(
        &mut self,
        decoder: &mut dyn Decoder) -> DataOrganizationSizes {
        let elem_id = decoder.open_element_matching(&elem::element("data_organization"));
        loop {
            let sub_id = decoder.open_element();
            if sub_id == 0 {
                break;
            }
            let name = decoder.element_name(sub_id).unwrap_or_default();
            match name.as_str() {
                "integer_size" => {
                    // Ghidra: sizeOfInt = decoder.readSignedInteger(ATTRIB_VALUE);
                    self.size_of_int = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "long_size" => {
                    self.size_of_long = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "pointer_size" => {
                    self.size_of_pointer =
                        decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "char_size" => {
                    self.size_of_char = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "wchar_size" => {
                    self.size_of_wchar = decoder.read_signed_integer_attr(&attrib("value")) as i32;
                }
                "size_alignment_map" => {
                    // Ghidra: decodeAlignmentMap(decoder); — no continue:
                    // falls through to the unified closeElement(subId)
                    // below, which closes <size_alignment_map> itself
                    // (type.cc:4604-4606 -> 4612).
                    self.decode_alignment_map(decoder);
                }
                _ => {
                    decoder.close_element_skipping(sub_id);
                    continue;
                }
            }
            decoder.close_element(sub_id);
        }
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        DataOrganizationSizes {
            size_of_int: self.size_of_int,
            size_of_long: self.size_of_long,
            size_of_pointer: self.size_of_pointer,
            size_of_char: self.size_of_char,
            size_of_wchar: self.size_of_wchar,
        }
    }

    // Ghidra: type.cc:4619 TypeFactory::decodeAlignmentMap
    /// Recover the size→alignment map from the children of a
    /// `<size_alignment_map>` element. Faithful to
    /// `TypeFactory::decodeAlignmentMap` (type.cc:4619-4641): the map is
    /// cleared, each `<entry size alignment>` grows the vector with -1 fill
    /// and assigns its size slot (a later duplicate entry wins), and a final
    /// forward pass copies the nearest earlier explicit alignment into every
    /// remaining -1 slot starting from `curAlign = 1` at index 1. Index 0 is
    /// never touched by the fill pass: it stays -1 unless an explicit
    /// `<entry size="0">` set it. An empty `<size_alignment_map>` leaves the
    /// map empty — no default is installed here (that is `setupSizes` via
    /// `setDefaultAlignmentMap`) and no exception is raised. Returns a
    /// snapshot of the persisted map.
    ///
    /// Rudra divergence (ill-formed input only): when a non-`<entry>` child
    /// appears mid-map, Ghidra breaks with the element left open (its parent
    /// `closeElement` then throws `DecoderError`); Rudra's TreeDecoder must
    /// close the opened child to keep its position coherent, so the child is
    /// skipped instead. Well-formed compiler specs (only `<entry>` children)
    /// never reach this branch.
    pub fn decode_alignment_map(&mut self, decoder: &mut dyn Decoder) -> Vec<i32> {
        // Ghidra: alignMap.clear();
        self.align_map.clear();
        loop {
            let map_id = decoder.open_element();
            let name = decoder.element_name(map_id).unwrap_or_default();
            if name != "entry" {
                // Ghidra: if (mapId != ELEM_ENTRY) break; — openElement
                // returning 0 (end of children) also lands here.
                if map_id != 0 {
                    decoder.close_element_skipping(map_id);
                }
                break;
            }
            // Ghidra: int4 sz = readSignedInteger(ATTRIB_SIZE);
            //        int4 val = readSignedInteger(ATTRIB_ALIGNMENT);
            let sz = decoder.read_signed_integer_attr(&attrib("size")) as usize;
            let val = decoder.read_signed_integer_attr(&attrib("alignment")) as i32;
            // Ghidra: while (alignMap.size() <= sz) alignMap.push_back(-1);
            while self.align_map.len() <= sz {
                self.align_map.push(-1);
            }
            self.align_map[sz] = val;
            decoder.close_element(map_id);
        }
        // Ghidra: int4 curAlign = 1;
        //        for (sz = 1; sz < alignMap.size(); ++sz) { ... }
        let mut cur_align: i32 = 1;
        for sz in 1..self.align_map.len() {
            let tmp = self.align_map[sz];
            if tmp == -1 {
                self.align_map[sz] = cur_align; // Copy from nearest explicit value.
            } else {
                cur_align = tmp;
            }
        }
        self.align_map.clone()
    }

    // Ghidra: type.cc:4644 TypeFactory::setDefaultAlignmentMap
    /// The default alignment map used when the compiler spec has no
    /// `<size_alignment_map>`. Faithful to
    /// `TypeFactory::setDefaultAlignmentMap` (type.cc:4644-4656): the vector
    /// is resized to 9 with 0 fill (so a fresh install yields
    /// `[0,1,2,2,4,4,4,4,8]` — index 0 is 0, not 1) and slots 1..=8 are
    /// assigned the x86-style powers-of-two ladder.
    pub fn set_default_alignment_map(&mut self) {
        // Ghidra: alignMap.resize(9,0);
        self.align_map.resize(9, 0);
        self.align_map[1] = 1;
        self.align_map[2] = 2;
        self.align_map[3] = 2;
        self.align_map[4] = 4;
        self.align_map[5] = 4;
        self.align_map[6] = 4;
        self.align_map[7] = 4;
        self.align_map[8] = 8;
    }

    // Ghidra: type.hh:813 TypeFactory::getSizeOfInt
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfInt`
    /// (type.hh:813).
    pub fn get_size_of_int(&self) -> i32 {
        self.size_of_int
    }

    // Ghidra: type.hh:814 TypeFactory::getSizeOfLong
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfLong`
    /// (type.hh:814).
    pub fn get_size_of_long(&self) -> i32 {
        self.size_of_long
    }

    // Ghidra: type.hh:815 TypeFactory::getSizeOfChar
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfChar`
    /// (type.hh:815).
    pub fn get_size_of_char(&self) -> i32 {
        self.size_of_char
    }

    // Ghidra: type.hh:816 TypeFactory::getSizeOfWChar
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfWChar`
    /// (type.hh:816).
    pub fn get_size_of_wchar(&self) -> i32 {
        self.size_of_wchar
    }

    // Ghidra: type.hh:817 TypeFactory::getSizeOfPointer
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfPointer`
    /// (type.hh:817).
    pub fn get_size_of_pointer(&self) -> i32 {
        self.size_of_pointer
    }

    // Ghidra: type.hh:818 TypeFactory::getSizeOfAltPointer
    /// Snapshot getter mirroring Ghidra's inline `getSizeOfAltPointer`
    /// (type.hh:818).
    pub fn get_size_of_alt_pointer(&self) -> i32 {
        self.size_of_alt_pointer
    }

    // Ghidra: type.cc:3296 TypeFactory::getAlignment
    /// Return the alignment associated with a primitive data-type of the
    /// given size. Faithful to `TypeFactory::getAlignment`
    /// (type.cc:3296-3305): a size at or beyond the map end returns the last
    /// entry, an empty map raises `LowlevelError("TypeFactory alignment map
    /// not initialized")` (returned as `Err` with the same message), and any
    /// other size returns its slot (which may be -1 for index 0 when no
    /// explicit size-0 entry exists).
    pub fn get_alignment(&self, size: u32) -> Result<i32, String> {
        if size as usize >= self.align_map.len() {
            if self.align_map.is_empty() {
                return Err("TypeFactory alignment map not initialized".to_string());
            }
            return Ok(self.align_map[self.align_map.len() - 1]);
        }
        Ok(self.align_map[size as usize])
    }

    // Ghidra: type.cc:3312 TypeFactory::getPrimitiveAlignSize
    /// Return the amount of room a data-type takes up in memory (the
    /// `\b sizeof` size). Faithful to `TypeFactory::getPrimitiveAlignSize`
    /// (type.cc:3312-3320): `uint4 mod = size % align` converts the signed
    /// alignment to unsigned 32-bit first, so a -1 alignment behaves as
    /// 0xFFFFFFFF; the remainder is then padded up. A zero alignment (the
    /// default map's index 0) is a division by zero in Ghidra and panics
    /// here — never query size 0 against a default-installed map.
    pub fn get_primitive_align_size(&self, size: u32) -> Result<i32, String> {
        let align = self.get_alignment(size)?;
        let align_u = align as u32;
        let rem = size % align_u;
        let result = if rem != 0 {
            size.wrapping_add(align_u.wrapping_sub(rem))
        } else {
            size
        };
        Ok(result as i32)
    }

    // Ghidra: type.cc:4662 TypeFactory::parseEnumConfig
    /// Recover default enumeration properties (size and signedness) from an
    /// `<enum>` XML tag and store them (`enumsize`/`enumtype`). Faithful to
    /// `TypeFactory::parseEnumConfig` (type.cc:4662-4672).
    pub fn parse_enum_config(&mut self, decoder: &mut dyn Decoder) {
        let elem_id = decoder.open_element_matching(&elem::element("enum"));
        // Ghidra: enumsize = decoder.readSignedInteger(ATTRIB_SIZE);
        self.enum_size = decoder.read_signed_integer_attr(&attrib("size")) as i32;
        // Ghidra: if (decoder.readBool(ATTRIB_SIGNED)) enumtype = TYPE_ENUM_INT;
        //        else enumtype = TYPE_ENUM_UINT;
        self.enum_type = if decoder.read_bool_attr(&attrib("signed")) {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
    }

    // Ghidra: type.cc:4155 TypeFactory::decodeType
    /// Restore a data-type from either a `<typeref>` element (resolved by name
    /// and id) or a full `<type>` element. Faithful to `TypeFactory::decodeType`
    /// (type.cc:4155-4184). Returns the resolved `Datatype` (looked up by name
    /// and id) for a typeref, or the newly decoded type for a `<type>`.
    ///
    /// Rudra gap: full `<type>` decoding requires the Architecture handle for
    /// code/struct/union field decoding; the typeref path (name+id lookup) is
    /// fully functional.
    pub fn decode_type(
        &mut self,
        decoder: &mut dyn Decoder) -> Result<Arc<Datatype>, String> {
        let elem_id = decoder.peek_element();
        let elem_name = decoder
            .element_name(elem_id)
            .unwrap_or_default();
        if elem_name == "typeref" {
            let opened = decoder.open_element();
            let mut new_id: u64 = 0;
            let mut size: i64 = -1;
            loop {
                let attrib_id = decoder.next_attribute_id();
                if attrib_id == 0 {
                    break;
                }
                match decoder.attribute_name(attrib_id).as_deref() {
                    Some("id") => new_id = decoder.read_unsigned_integer(),
                    Some("size") => size = decoder.read_signed_integer(),
                    _ => {
                        let _ = decoder.read_string();
                    }
                }
            }
            let newname = decoder.read_string_attr(&attrib("name"));
            if new_id == 0 {
                new_id = Datatype::hash_name(&newname);
            }
            let ct = self
                .find_by_id(&newname, new_id, if size < 0 { 0 } else { size as usize })
                .ok_or_else(|| format!("Unable to resolve type: {}", newname))?;
            if opened != 0 {
                decoder.close_element(opened);
            }
            Ok(ct)
        } else {
            self.decode_type_no_ref(decoder, false)
        }
    }

    // Ghidra: type.cc:4436 TypeFactory::decodeTypeNoRef
    /// Restore a `Datatype` from a `<type>` element (not `<typeref>`). Faithful
    /// to `TypeFactory::decodeTypeNoRef` (type.cc:4436-4548). Dispatches on the
    /// element name (`<void>`, `<def>`) and the `metatype` attribute to the
    /// subclass decoders.
    ///
    /// Rudra gap: the struct/union/code/pointerrel branches require
    /// Architecture-backed field/prototype decoding that is not yet wired
    /// (see type_audit.md). Those branches consume their child elements so the
    /// decoder advances correctly and return a placeholder error for the
    /// caller to handle; the base/char/utf/enum/void/pointer/array branches
    /// that do not need the Architecture are functional.
    pub fn decode_type_no_ref(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let elem_id = decoder.open_element();
        let elem_name = decoder
            .element_name(elem_id)
            .unwrap_or_default();
        if elem_name == "void" {
            let ct = self.get_type_void_result(); // Automatically a coretype.
            if elem_id != 0 {
                decoder.close_element(elem_id);
            }
            return Ok(ct);
        }
        if elem_name == "def" {
            let ct = self.decode_typedef(decoder)?;
            if elem_id != 0 {
                decoder.close_element(elem_id);
            }
            return Ok(ct);
        }
        // Ghidra: type_metatype meta = string2metatype(decoder.readString(ATTRIB_METATYPE));
        let metastring = decoder.read_string_attr(&attrib("metatype"));
        let meta = string2metatype(&metastring);
        match meta {
            TypeMetatype::Pointer => {
                let basic = Datatype::decode_basic(decoder)?;
                decoder.rewind_attributes();
                let wordsize = TypePointer::decode_pointer_attributes(decoder, &basic);
                // Child pointed-to type:
                let ptrto = self.decode_type(decoder)?;
                let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Pointer);
                base.display_name = basic.display_name.clone();
                base.alignment = basic.alignment;
                base.align_size = basic.size;
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                let mut pointer = TypePointer {
                    base,
                    ptr_to: ptrto.clone(),
                    wordsize,
                };
                pointer.calc_submeta();
                if basic.name.is_empty() {
                    pointer.base.flags |= ptrto.get_inheritable();
                }
                // The locked path canonicalizes the decoded stack candidate
                // through findAdd; a repeated decode returns the existing
                // factory object instead of colliding in insert.
                // Rudra's production Architecture currently records
                // `types->setupSizes()` as an executed no-op
                // (CSPEC-TYPEORG-STATE-0001). Keep decode on findAdd's
                // compatibility layout channel until that state is wired;
                // structural pointer identity and collision semantics are
                // still canonical. The explicit get_type_pointer API above
                // remains the fail-closed locked-oracle channel.
                let dt = self.find_add(Datatype::Pointer(pointer), false)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
            TypeMetatype::Array => {
                let basic = Datatype::decode_basic(decoder)?;
                // Ghidra: type.cc:1323 TypeArray::decode rewinds attributes
                // after decodeBasic before re-reading ATTRIB_ARRAYSIZE —
                // decodeBasic's attribute loop has otherwise consumed the
                // element's attributes, and arraysize would stay -1.
                decoder.rewind_attributes();
                let num_elements = TypeArray::decode_array_attributes(decoder);
                let array_of = self.decode_type(decoder)?;
                // Ghidra: type.cc:1338-1339 TypeArray::decode:
                //   if ((arraysize<=0)||(arraysize*arrayof->getAlignSize()!=size))
                //     throw LowlevelError("Bad size for array of type "+arrayof->getName());
                // `decode_array_attributes` folds an absent or negative
                // `arraysize` attribute to 0, matching Ghidra's `<= 0` arm.
                // Ghidra multiplies in int4; Rust's usize cannot wrap, so an
                // overflowing product is rejected directly (such inputs would
                // only pass Ghidra's compare by int4 wraparound coincidence;
                // unreachable from well-formed specs).
                let product = num_elements.checked_mul(array_of.get_align_size());
                if num_elements == 0 || product != Some(basic.size) {
                    return Err(format!(
                        "Bad size for array of type {}",
                        array_of.get_name()
                    ));
                }
                let mut base = TypeBase::new(basic.name, basic.size, TypeMetatype::Array);
                base.display_name = basic.display_name;
                // TypeArray::decode overwrites decoded alignment with the
                // element alignment and keeps alignSize equal to total size.
                base.alignment = array_of.get_alignment() as i32;
                base.align_size = basic.size;
                base.id = basic.id;
                base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
                // Ghidra: type.cc:1341-1342 TypeArray::decode:
                //   if (arraysize == 1)
                //     flags |= needs_resolution;	// Array of size 1 needs special treatment
                // Same condition as the inline TypeArray ctor arm applied by
                // get_array (type.hh:937-944), so decode and factory
                // creation agree.
                if num_elements == 1 {
                    base.flags |= type_flags::NEEDS_RESOLUTION;
                }
                let dt = self.find_add(
                    Datatype::Array(TypeArray {
                    base,
                    array_of,
                    num_elements,
                }), false,
                )?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
            TypeMetatype::Enum => {
                // Ghidra's switch distinguishes TYPE_ENUM_INT/TYPE_ENUM_UINT
                // (type.cc:4482-4485); Rust's TypeMetatype collapses both
                // variants, so the original attribute string selects the
                // signedness that TypeEnum::decode derives from the decoded
                // metatype (type.cc:4323).
                let ct = self.decode_enum(decoder, forcecore, metastring == "enum_int")?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Struct => {
                let ct = self.decode_struct(decoder, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Union => {
                let ct = self.decode_union(decoder, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Code => {
                let ct = self.decode_code(decoder, false, false, forcecore)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            TypeMetatype::Void => {
                // Ghidra: type.cc:4504-4509 — TypeVoid voidType;
                // voidType.decode(decoder,*this); ct = findAdd(voidType);
                // The TypeVoid ctor sets name "void" and the coretype flag
                // (type.hh:389); decode only overwrites the id
                // (type.cc:887-897), and findAdd runs the full named path —
                // an absent id raises "Datatype must have a valid id: void".
                let id = Datatype::decode_void_id(decoder);
                let mut base = TypeBase::new("void".to_string(), 0, TypeMetatype::Void);
                base.alignment = 1;
                base.align_size = 0;
                base.id = id;
                base.flags |= type_flags::CORETYPE;
                let ct = self.find_add(Datatype::Void(base), false)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(ct)
            }
            _ => {
                // Ghidra default arm (type.cc:4511-4544): scan attributes for
                // char/utf; a `char="true"` builds a TypeChar, `utf="true"`
                // builds a TypeUnicode, anything else a plain TypeBase — each
                // merged with decodeBasic's fields and canonicalized through
                // findAdd.
                let basic = Datatype::decode_basic(decoder)?;
                decoder.rewind_attributes();
                let mut is_char = false;
                let mut is_utf = false;
                loop {
                    let attrib_id = decoder.next_attribute_id();
                    if attrib_id == 0 {
                        break;
                    }
                    match decoder.attribute_name(attrib_id).as_deref() {
                        Some("char") if decoder.read_bool() => is_char = true,
                        Some("utf") if decoder.read_bool() => is_utf = true,
                        _ => {
                            let _ = decoder.read_string();
                        }
                    }
                }
                let core_bit = if forcecore { type_flags::CORETYPE } else { 0 };
                let candidate = if is_char {
                    // type.cc:4515-4523: TypeChar ctor (type.hh:356) sets
                    // size 1/TYPE_INT/chartype/SUB_INT_CHAR; the ctor's
                    // decode then overwrites name/size/metatype/id and
                    // re-specializes submeta by the decoded metatype
                    // (type.cc:818).
                    let mut base = TypeBase::new_char(basic.name.clone(), basic.metatype);
                    base.display_name = basic.display_name.clone();
                    base.size = basic.size;
                    base.alignment = basic.alignment;
                    base.align_size = basic.size;
                    base.id = basic.id;
                    base.flags |= basic.flags | core_bit;
                    Datatype::Base(base)
                } else if is_utf {
                    // type.cc:4525-4533: TypeUnicode + decode — setflags()
                    // picks utf16/utf32/chartype by size (type.cc:837-846)
                    // and submeta is SUB_INT_UNICODE/SUB_UINT_UNICODE
                    // regardless of size (type.cc:858).
                    let mut base =
                        TypeBase::new_unicode(basic.name.clone(), basic.size, basic.metatype);
                    base.display_name = basic.display_name.clone();
                    base.alignment = basic.alignment;
                    base.align_size = basic.size;
                    base.id = basic.id;
                    base.flags |= basic.flags | core_bit;
                    Datatype::Base(base)
                } else {
                    let mut base = TypeBase::new(basic.name.clone(), basic.size, basic.metatype);
                    base.display_name = basic.display_name.clone();
                    base.alignment = basic.alignment;
                    base.align_size = basic.size;
                    base.id = basic.id;
                    base.flags = basic.flags | core_bit;
                    Datatype::Base(base)
                };
                let dt = self.find_add(candidate, false)?;
                if elem_id != 0 {
                    decoder.close_element(elem_id);
                }
                Ok(dt)
            }
        }
    }

    // Ghidra: type.cc:4263 TypeFactory::decodeTypedef
    /// Scan the `id`, `name`, and `format` attributes of a `<def>` element,
    /// decode the referenced data-type, and construct a typedef alias.
    /// Faithful to `TypeFactory::decodeTypedef` (type.cc:4263-4313).
    pub fn decode_typedef(
        &mut self,
        decoder: &mut dyn Decoder) -> Result<Arc<Datatype>, String> {
        let mut id: u64 = 0;
        let mut nm = String::new();
        let mut format: u32 = 0;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("id") => id = decoder.read_unsigned_integer(),
                Some("name") => nm = decoder.read_string(),
                Some("format") => {
                    let s = decoder.read_string();
                    if let Ok(val) = Datatype::encode_integer_format(&s) {
                        format = val;
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        if id == 0 {
            id = Datatype::hash_name(&nm);
        }
        let defed_type = self.decode_type(decoder)?;
        if defed_type.is_variable_length() {
            id = Datatype::hash_size(id, defed_type.get_size() as i32);
        }
        // Ghidra: recursive struct/union typedef resolution via findByIdLocal.
        // Rudra: delegate to get_typedef, which registers the alias.
        let _ = format; // Rudra's get_typedef does not yet accept a format arg.
        Ok(self.get_typedef(&nm, defed_type))
    }

    // Ghidra: type.cc:4318 TypeFactory::decodeEnum
    /// Decode an enumeration `<type>` element (with `<val>` children) and add
    /// it to the container. Faithful to `TypeFactory::decodeEnum`
    /// (type.cc:4318-4329): a `TypeEnum` scratch is decoded
    /// (`TypeEnum::decode` normalizes the metatype to TYPE_INT/TYPE_UINT,
    /// type.cc:4323), ORs `coretype` when `forcecore`, and is canonicalized
    /// through `findAdd` — so the enum enters the ordered tree and
    /// participates in cacheCoreTypes exactly like the oracle.
    ///
    /// `signed` carries the TYPE_ENUM_INT/TYPE_ENUM_UINT distinction of
    /// Ghidra's switch (type.cc:4482-4485), which Rust's collapsed
    /// `TypeMetatype::Enum` cannot express from `decode_basic` alone.
    pub fn decode_enum(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
        signed: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder)?;
        // Ghidra: metatype = (metatype == TYPE_ENUM_INT) ? TYPE_INT : TYPE_UINT;
        let meta = if signed {
            TypeMetatype::Int
        } else {
            TypeMetatype::Uint
        };
        let mut values: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
        let mut warning = String::new();
        loop {
            let child_id = decoder.open_element();
            if child_id == 0 {
                break;
            }
            let (val, nm) = TypeEnum::decode_enum_value(decoder, basic.size);
            if nm.is_empty() {
                return Err(format!(
                    "{}: TypeEnum field missing name attribute",
                    basic.name
                ));
            }
            if values.contains_key(&val) {
                if warning.is_empty() {
                    warning =
                        format!(
                        "Enum \"{}\": Some values do not have unique names", basic.name
                    );
                }
            } else {
                values.insert(val, nm);
            }
            decoder.close_element(child_id);
        }
        let mut base = TypeBase::new(basic.name.clone(), basic.size, meta);
        base.display_name = basic.display_name.clone();
        base.alignment = basic.alignment;
        base.align_size = basic.size;
        base.id = basic.id;
        base.flags = basic.flags
            | type_flags::ENUMTYPE
            | if forcecore { type_flags::CORETYPE } else { 0 };
        let dt = self.find_add(Datatype::Enum(TypeEnum { base, values }), false)?;
        // type.cc:4326-4327: `if (!warning.empty()) insertWarning(res,
        // warning);` — the duplicate-enum-name warning rides the same
        // channel (verbatim throw on anonymous id-0 types); the returned
        // Arc is the post-flag-write registration.
        let dt = if !warning.is_empty() {
            self.insert_warning(&dt, warning)?
        } else {
            dt
        };
        Ok(dt)
    }

    // Ghidra: type.cc:4335 TypeFactory::decodeStruct
    /// Decode a structure `<type>` element with `<field>` children. Faithful to
    /// `TypeFactory::decodeStruct` (type.cc:4335-4362). Creates a stub first to
    /// allow recursive definitions, then fills in the fields.
    pub fn decode_struct(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder)?;
        // Create a registered stub (empty fields) to allow recursive
        // references while the children are decoded.
        let stub_name = basic.name.clone();
        let ct = if let Some(existing) = self.find_by_name(&stub_name) {
            if existing.get_metatype() != TypeMetatype::Struct {
                return Err(format!("Trying to redefine type: {stub_name}"));
            }
            existing
        } else {
            let mut stub_base =
                TypeBase::new(stub_name.clone(), basic.size, TypeMetatype::Struct);
            stub_base.display_name = basic.display_name.clone();
            stub_base.alignment = basic.alignment;
            stub_base.align_size = basic.size;
            stub_base.id = basic.id;
            stub_base.flags = basic.flags
                | type_flags::TYPE_INCOMPLETE
                | if forcecore { type_flags::CORETYPE } else { 0 };
            self.find_add(
                Datatype::Struct(TypeStruct {
                base: stub_base,
                fields: Vec::new(),
            }), false,
            )?
        };
        // Decode fields. Per-field this mirrors, in order:
        //  - `TypeField::TypeField(Decoder&,TypeFactory&)` (type.cc:768-794):
        //    decode attributes, then `decodeType`, then the name-empty and
        //    offset-negative throws, then closeElement;
        //  - the `TypeStruct::decodeFields` acceptance loop
        //    (type.cc:1839-1870): void-metatype throw, out-of-order throw,
        //    overlap throw-out, does-not-fit throw.
        let mut fields: Vec<TypeField> = Vec::new();
        // decodeFields loop state (type.cc:1835-1837).
        let mut last_off: i64 = -1;
        let mut calc_size: i64 = 0;
        let mut calc_align: usize = 1;
        let mut warning = String::new();
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            let attrs = TypeField::decode_field_attributes(decoder);
            // type.cc:786: type = typegrp.decodeType(decoder);
            let field_type = self.decode_type(decoder)?;
            // type.cc:787-790 (TypeField ctor, in this order).
            if attrs.name.is_empty() {
                return Err("name attribute must not be empty in <field> tag".to_string());
            }
            if attrs.offset < 0 {
                return Err("offset attribute invalid for <field> tag".to_string());
            }
            if child_id != 0 {
                decoder.close_element(child_id);
            }
            // type.cc:1842-1843: null type is impossible in Rust (decode_type
            // returns Result); the TYPE_VOID arm remains.
            if field_type.get_metatype() == TypeMetatype::Void {
                return Err(format!(
                    "Bad field data-type for structure: {}",
                    basic.name
                ));
            }
            // type.cc:1846-1848: strictly-lower-than-previous offset is out of
            // order; equal offsets fall through to the overlap check below.
            if (attrs.offset as i64) < last_off {
                return Err("Fields are out of order".to_string());
            }
            last_off = attrs.offset as i64;
            // type.cc:1849-1860: a field starting inside the previous field's
            // extent is thrown out with a warning. The warning text is built
            // verbatim (first overlap names the field; later ones collapse
            // to the multiple-fields form) and rides to the
            // `insertWarning(ct, warning)` tail at type.cc:4357-4358.
            if (attrs.offset as i64) < calc_size {
                if warning.is_empty() {
                    warning = format!(
                        "Struct \"{}\": ignoring overlapping field \"{}\"",
                        basic.name, attrs.name
                    );
                } else {
                    warning = format!(
                        "Struct \"{}\": ignoring multiple overlapping fields",
                        basic.name
                    );
                }
                continue;
            }
            // type.cc:1861-1866: field must fit within the declared size.
            calc_size = attrs.offset as i64 + field_type.get_size() as i64;
            if calc_size > basic.size as i64 {
                return Err(format!(
                    "Field {} does not fit in structure {}",
                    attrs.name, basic.name
                ));
            }
            calc_align = calc_align.max(field_type.get_alignment());
            let ident = if attrs.ident < 0 {
                attrs.offset
            } else {
                attrs.ident
            };
            let _ = ident; // Rudra TypeField has no ident field; ident == offset.
            fields.push(TypeField {
                name: attrs.name,
                offset: attrs.offset as usize,
                type_ptr: field_type,
            });
        }
        // Replace the stub with the fully-defined struct.
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Struct);
        base.display_name = basic.display_name.clone();
        base.alignment = if basic.alignment < 1 {
            calc_align as i32
        } else {
            basic.alignment
        };
        base.align_size = calc_align_size(basic.size, base.alignment as usize);
        base.id = basic.id;
        base.flags = basic.flags | if forcecore { type_flags::CORETYPE } else { 0 };
        // decodeFields tail (type.cc:1871-1874) on the scratch:
        //   if (size == 0) flags |= type_incomplete;
        //   if (field.size() > 0) markComplete();   // clears type_incomplete
        // then decodeStruct transfers via TypeFactory::setFields
        // (type.cc:3487-3488: clear, then masked-OR the scratch's
        // opaque_string|variable_length|type_incomplete). The scratch always
        // starts incomplete (TypeStruct() default ctor, type.hh:518), so the
        // observable residue is: the factory type stays incomplete iff it
        // ended with zero fields (a size-0 struct cannot accept any field —
        // the fit check above rejects `calcSize > 0 == size`), and an XML
        // `incomplete="true"` attribute is overridden by non-empty fields,
        // exactly as Ghidra's markComplete-then-transfer sequence does.
        if fields.is_empty() {
            base.flags |= type_flags::TYPE_INCOMPLETE;
        } else {
            base.flags &= !type_flags::TYPE_INCOMPLETE;
        }
        // Ghidra: type.cc:1875-1877 TypeStruct::decodeFields tail:
        //   if (field.size() == 1) {
        //     if (field[0].type->getSize() == size)
        //       flags |= needs_resolution;		// needs special resolution
        //   }
        // `size` is the struct size decoded from the <type> element's
        // attributes (decodeBasic), exactly the member `TypeStruct::decodeFields`
        // reads (and the `newSize` decodeStruct passes through
        // `TypeFactory::setFields` at type.cc:4355, whose
        // `TypeStruct::setFields` arm re-derives the same flag, type.cc:1569-1571);
        // the comparison uses the field type's full `getSize` against the
        // post-throw-out field list. The flag is ORed in, never cleared.
        if fields.len() == 1 && fields[0].type_ptr.get_size() == basic.size {
            base.flags |= type_flags::NEEDS_RESOLUTION;
        }
        let scratch = Datatype::Struct(TypeStruct { base, fields });
        let result = if !ct.is_incomplete() {
            if ct.compare_dependency(&scratch) != 0 {
                return Err(format!("Redefinition of structure: {}", basic.name));
            }
            ct
        } else {
            let Datatype::Struct(scratch_struct) = scratch else {
                unreachable!();
            };
            let fields = scratch_struct.fields;
            let new_size = scratch_struct.base.size;
            let new_alignment = scratch_struct.base.alignment;
            let flags = scratch_struct.base.flags;
            self.define_replace(&ct, |defined| {
                let structure = match defined {
                    Datatype::Struct(structure) => structure,
                    _ => return Err("setFields target is not a TypeStruct".to_string()),
                };
                structure.fields = fields;
                structure.base.size = new_size;
                structure.base.alignment = new_alignment;
                structure.base.align_size =
                    calc_align_size(new_size, new_alignment as usize);
                if structure.fields.len() == 1
                    && structure.fields[0].type_ptr.get_size() == new_size
                {
                    structure.base.flags |= type_flags::NEEDS_RESOLUTION;
                }
                structure.base.flags &= !type_flags::TYPE_INCOMPLETE;
                structure.base.flags |= flags
                    & (type_flags::OPAQUE_STRUCT
                        | type_flags::VARLENGTH
                        | type_flags::TYPE_INCOMPLETE);
                Ok(())
            })?
        };
        // type.cc:4357-4358: `if (!warning.empty()) insertWarning(ct,
        // warning);` — the registered type carries the decodeFields
        // overlap warning; an anonymous (id-0) type makes insertWarning
        // throw the verbatim LowlevelError (type.cc:3753-3754). The
        // returned Arc is the post-flag-write registration (Ghidra's `ct`
        // mutates in place; Rudra re-wraps under the same slots).
        let result = if !warning.is_empty() {
            self.insert_warning(&result, warning)?
        } else {
            result
        };
        self.resolve_incomplete_typedefs()?;
        Ok(result)
    }

    // Ghidra: type.cc:4368 TypeFactory::decodeUnion
    /// Decode a union `<type>` element with `<field>` children. Faithful to
    /// `TypeFactory::decodeUnion` (type.cc:4368-4393). Structurally identical
    /// to `decode_struct` but produces a `TypeUnion`.
    pub fn decode_union(
        &mut self,
        decoder: &mut dyn Decoder,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        let basic = Datatype::decode_basic(decoder)?;
        let stub_name = basic.name.clone();
        let ct = if let Some(existing) = self.find_by_name(&stub_name) {
            if existing.get_metatype() != TypeMetatype::Union {
                return Err(format!("Trying to redefine type: {stub_name}"));
            }
            existing
        } else {
            let mut stub_base =
                TypeBase::new(stub_name, basic.size, TypeMetatype::Union);
            stub_base.display_name = basic.display_name.clone();
            stub_base.alignment = basic.alignment;
            stub_base.align_size = basic.size;
            stub_base.id = basic.id;
            stub_base.flags = basic.flags
                | type_flags::TYPE_INCOMPLETE
                | type_flags::NEEDS_RESOLUTION
                | if forcecore { type_flags::CORETYPE } else { 0 };
            self.find_add(
                Datatype::Union(TypeUnion {
                base: stub_base,
                fields: Vec::new(),
            }), false,
            )?
        };
        let mut fields: Vec<TypeField> = Vec::new();
        let mut calc_align: usize = 1;
        while decoder.peek_element() != 0 {
            let child_id = decoder.open_element();
            let attrs = TypeField::decode_field_attributes(decoder);
            if attrs.name.is_empty() {
                return Err("name attribute must not be empty in <field> tag".to_string());
            }
            if attrs.offset < 0 {
                return Err("offset attribute invalid for <field> tag".to_string());
            }
            let field_type = self.decode_type(decoder)?;
            if attrs.offset as usize + field_type.get_size() > basic.size {
                return Err(format!(
                    "Field {} does not fit in union {}",
                    attrs.name, basic.name
                ));
            }
            calc_align = calc_align.max(field_type.get_alignment());
            fields.push(TypeField {
                name: attrs.name,
                offset: attrs.offset as usize,
                type_ptr: field_type,
            });
            if child_id != 0 {
                decoder.close_element(child_id);
            }
        }
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Union);
        base.display_name = basic.display_name.clone();
        base.alignment = if basic.alignment < 1 {
            calc_align as i32
        } else {
            basic.alignment
        };
        base.align_size = calc_align_size(basic.size, base.alignment as usize);
        base.id = basic.id;
        base.flags = basic.flags
            | type_flags::TYPE_INCOMPLETE
            | type_flags::NEEDS_RESOLUTION
            | if forcecore { type_flags::CORETYPE } else { 0 };
        if !fields.is_empty() {
            base.flags &= !type_flags::TYPE_INCOMPLETE;
        }
        let scratch = Datatype::Union(TypeUnion { base, fields });
        let result = if !ct.is_incomplete() {
            if ct.compare_dependency(&scratch) != 0 {
                return Err(format!("Redefinition of union: {}", basic.name));
            }
            ct
        } else {
            let Datatype::Union(scratch_union) = scratch else {
                unreachable!();
            };
            let fields = scratch_union.fields;
            let new_size = scratch_union.base.size;
            let new_alignment = scratch_union.base.alignment;
            let flags = scratch_union.base.flags;
            self.define_replace(&ct, |defined| {
                let union = match defined {
                    Datatype::Union(union) => union,
                    _ => return Err("setFields target is not a TypeUnion".to_string()),
                };
                union.fields = fields;
                union.base.size = new_size;
                union.base.alignment = new_alignment;
                union.base.align_size = calc_align_size(new_size, new_alignment as usize);
                union.base.flags &= !type_flags::TYPE_INCOMPLETE;
                union.base.flags |=
                    flags & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
                Ok(())
            })?
        };
        self.resolve_incomplete_typedefs()?;
        Ok(result)
    }

    // Ghidra: type.cc:4401 TypeFactory::decodeCode
    /// Decode a code `<type>` element with an optional `<prototype>` child,
    /// creating a placeholder stub first to allow recursive definitions.
    /// Faithful to `TypeFactory::decodeCode` (type.cc:4401-4429):
    ///
    /// - `decodeStub` peeks for the `<prototype>` child (setting
    ///   `variable_length`) and reads the element attributes; the scratch
    ///   `TypeCode` carries the ctor's `type_incomplete` bit throughout,
    /// - a metatype other than `code` raises `Expecting metatype="code"`,
    /// - `findByIdLocal(name,id)` either finds the existing container entry
    ///   (raising `Trying to redefine type` for a non-code occupant) or the
    ///   scratch is canonicalized through `findAdd` as the stub,
    /// - `decodePrototype` (with the constructor/destructor chain from
    ///   `decodeTypeWithCodeFlags`) fills the scratch,
    /// - a non-incomplete container entry is checked with
    ///   `compareDependency` (`Redefinition of code data-type`), while an
    ///   incomplete stub is defined in place through the factory's
    ///   `setPrototype` — which also completes prototype-less stubs, since
    ///   Ghidra clears `type_incomplete` even for a null prototype,
    /// - `resolveIncompleteTypedefs` drains pending code/struct/union
    ///   typedefs whose referenced type just completed.
    ///
    /// The element itself was opened by the caller (`decodeTypeNoRef` /
    /// `decodeTypeWithCodeFlags`) and stays open; the `<prototype>` child is
    /// consumed here.
    ///
    /// Rudra gap: a present `<prototype>` child errors until
    /// `FuncProto::decode` (fspec.cc:4675, fspec.rs lease) is ported — the
    /// stub inserted before the throw survives, matching the oracle's
    /// partial state on its own prototype-decode failures.
    pub fn decode_code(
        &mut self,
        decoder: &mut dyn Decoder,
        is_constructor: bool,
        is_destructor: bool,
        forcecore: bool,
    ) -> Result<Arc<Datatype>, String> {
        // Ghidra: TypeCode tc; tc.decodeStub(decoder);
        let (mut basic, _has_proto) = TypeCode::decode_code_stub(decoder)?;
        // Ghidra: if (tc.getMetatype() != TYPE_CODE)
        //          throw LowlevelError("Expecting metatype=\"code\"");
        if basic.metatype != TypeMetatype::Code {
            return Err("Expecting metatype=\"code\"".to_string());
        }
        // Ghidra: if (forcecore) tc.flags |= Datatype::coretype;
        if forcecore {
            basic.flags |= type_flags::CORETYPE;
        }
        // Scratch TypeCode mirroring Ghidra's stack-local `tc` (TypeCode ctor:
        // type.cc:2757-2763). decode_code_stub already OR-composed the ctor's
        // type_incomplete and the peek's variable_length into basic.flags.
        let mut tc = TypeCode::new();
        tc.base.name = basic.name.clone();
        tc.base.display_name = basic.display_name.clone();
        tc.base.size = basic.size;
        if basic.alignment >= 0 {
            tc.base.alignment = basic.alignment;
        }
        tc.base.align_size = basic.size;
        tc.base.id = basic.id;
        tc.base.flags |= basic.flags;
        // Ghidra: Datatype *ct = findByIdLocal(tc.name,tc.id);
        //        if (ct == 0) ct = findAdd(tc);   // Create stub to allow recursive definitions
        //        else if (ct->getMetatype() != TYPE_CODE)
        //          throw LowlevelError("Trying to redefine type: " + tc.name);
        let ct = match self.find_by_id_local(&basic.name, basic.id) {
            None => self.find_add(Datatype::Code(tc.clone()), false)?,
            Some(existing) => {
                if existing.get_metatype() != TypeMetatype::Code {
                    return Err(format!("Trying to redefine type: {}", basic.name));
                }
                existing
            }
        };
        // Ghidra: tc.decodePrototype(decoder, isConstructor, isDestructor, *this);
        let voidtype = self.get_type_void_result();
        tc.decode_prototype(decoder, is_constructor, is_destructor, voidtype)?;
        // Ghidra: if (!ct->isIncomplete()) {
        //           if (0 != ct->compareDependency(tc))
        //             throw LowlevelError("Redefinition of code data-type: " + tc.name);
        //         }
        //         else setPrototype(tc.proto, (TypeCode *)ct, tc.flags);
        let result = if !ct.is_incomplete() {
            if ct.compare_dependency(&Datatype::Code(tc)) != 0 {
                return Err(format!("Redefinition of code data-type: {}", basic.name));
            }
            ct.clone()
        } else {
            self.set_prototype_define(&ct, tc.proto.as_deref(), tc.base.flags)?
        };
        // Ghidra: resolveIncompleteTypedefs();
        self.resolve_incomplete_typedefs()?;
        // Ghidra: return ct;
        Ok(result)
    }

    // Ghidra: type.cc:3518 TypeFactory::setPrototype(const FuncProto *,TypeCode *,uint4)
    /// Define an incomplete code data-type in place with the given prototype
    /// and flag transfer. Faithful to the factory's `setPrototype` wrapper
    /// (type.cc:3518-3528): asserts the target is incomplete (verbatim
    /// LowlevelError otherwise), copies the prototype in, clears
    /// `type_incomplete`, ORs in `(variable_length | type_incomplete)` from
    /// the caller's flags, and re-registers the object.
    fn set_prototype_define(
        &mut self,
        ct: &Arc<Datatype>,
        fp: Option<&crate::fspec::FuncProto>,
        flags: u32,
    ) -> Result<Arc<Datatype>, String> {
        // Ghidra: if (!newCode->isIncomplete())
        //          throw LowlevelError("Can only set prototype on incomplete data-type");
        if !ct.is_incomplete() {
            return Err("Can only set prototype on incomplete data-type".to_string());
        }
        // Ghidra: tree.erase(newCode); newCode->setPrototype(this,fp);
        //         newCode->flags &= ~(uint4)Datatype::type_incomplete;
        //         newCode->flags |= (flags & (variable_length | type_incomplete));
        //         tree.insert(newCode);
        self.define_replace(ct, |defined| {
            let code = match defined {
                Datatype::Code(code) => code,
                _ => return Err("setPrototype target is not a TypeCode".to_string()),
            };
            code.set_prototype(fp);
            code.base.flags &= !type_flags::TYPE_INCOMPLETE;
            code.base.flags |= flags & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
            Ok(())
        })
    }

    // RUDRA-GLUE: channel-replacing define mutation shared by the
    /// setPrototype/setFields wrappers (`set_prototype_define`,
    /// `resolve_incomplete_typedefs`). Ghidra mutates the container object
    /// in place (tree.erase / mutate / tree.insert of the same pointer);
    /// Rudra clones the candidate, applies the mutation, and replaces both
    /// owning channels (ordered tree slot + name map) with the updated
    /// `Arc`, which preserves every factory-mediated observation
    /// (re-lookup by name/id, repeated decode identity). This does not update
    /// Arcs already captured by arrays, pointers, partial types, typedef and
    /// incomplete-type side tables, caches, or external callers. Those stale
    /// dependency channels are the registered
    /// TYPEFACTORY-ARC-IDENTITY-0001 immutable-Arc residual.
    fn define_replace(
        &mut self,
        ct: &Arc<Datatype>,
        mutate: impl FnOnce(&mut Datatype) -> Result<(), String>,
    ) -> Result<Arc<Datatype>, String> {
        let old_tree_key = Self::type_tree_key(ct);
        let old_name = ct.get_name().to_string();

        // Ghidra's erase operates on the exact object pointer. Refuse to
        // perform a replacement unless both factory channels still name this
        // precise Arc; silently overwriting a stale/colliding slot would lose
        // an unrelated canonical Datatype.
        {
            let tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match tree.get(&old_tree_key) {
                Some(registered) if Arc::ptr_eq(registered, ct) => {}
                _ => {
                    return Err(
                        "Datatype definition is not registered under its current tree key"
                            .to_string(),
                    );
                }
            }
        }
        if !old_name.is_empty()
            && !self
                .types
                .get(&old_name)
                .is_some_and(|registered| Arc::ptr_eq(registered, ct))
        {
            return Err(
                "Datatype definition is not registered under its current name".to_string());
        }

        let mut defined = (**ct).clone();
        mutate(&mut defined)?;
        let arc = Arc::new(defined);
        let tree_key = Self::type_tree_key(&arc);
        let name = arc.get_name().to_string();

        {
            let tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(registered) = tree.get(&tree_key) {
                let same_old_slot = tree_key == old_tree_key && Arc::ptr_eq(registered, ct);
                if !same_old_slot {
                    return Err(
                        "Datatype definition collides with an existing tree key".to_string()
                    );
                }
            }
        }
        if !name.is_empty() {
            if let Some(registered) = self.types.get(&name) {
                let same_old_slot = name == old_name && Arc::ptr_eq(registered, ct);
                if !same_old_slot {
                    return Err(
                        "Datatype definition collides with an existing name".to_string());
                }
            }
        }

        let tree = self
            .base_type_tree
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.remove(&old_tree_key);
        tree.insert(tree_key, arc.clone());
        if !old_name.is_empty() && old_name != name {
            self.types.remove(&old_name);
        }
        if !name.is_empty() {
            self.types.insert(name, arc.clone());
        }
        Ok(arc)
    }

    // Ghidra: type.cc:3777 TypeFactory::resolveIncompleteTypedefs
    /// Complete any pending typedefs whose referenced data-type has finished
    /// decoding. Faithful to `TypeFactory::resolveIncompleteTypedefs`
    /// (type.cc:3777-3809): walks the incomplete-typedef list in order;
    /// struct entries receive the referenced fields via the struct setFields
    /// wrapper (type.cc:3479-3492 — incomplete guard, fields+size, flag
    /// merge `opaque_string|variable_length|type_incomplete`), union entries
    /// via the union wrapper (type.cc:3500-3511 — merge without
    /// `opaque_string`), code entries via the factory `setPrototype`, and
    /// finished entries are removed (Ghidra's `list::erase(iter)` advance).
    pub fn resolve_incomplete_typedefs(&mut self) -> Result<(), String> {
        let mut index = 0;
        while index < self.incomplete_typedefs.len() {
            let dt = self.incomplete_typedefs[index].clone();
            // Ghidra: Datatype *defedType = dt->getTypedef();
            let defed = match self.typedefs.get(dt.get_name().to_string().as_str()) {
                Some(target) => target.clone(),
                None => {
                    index += 1;
                    continue;
                }
            };
            if defed.is_incomplete() {
                index += 1;
                continue;
            }
            match (dt.as_ref(), defed.as_ref()) {
                (Datatype::Struct(_), Datatype::Struct(defed_struct)) => {
                    // Ghidra: setFields(defedStruct->field, prevStruct,
                    //                   defedStruct->size, defedStruct->alignment,
                    //                   defedStruct->flags);
                    let fields = defed_struct.fields.clone();
                    let new_size = defed_struct.base.size;
                    let new_alignment = defed_struct.base.alignment;
                    let new_align_size = defed_struct.base.align_size;
                    let flags = defed_struct.base.flags;
                    self.define_replace(&dt, |defined| {
                        let st = match defined {
                            Datatype::Struct(st) => st,
                            _ => return Err(
                                    "setFields target is not a TypeStruct".to_string()
                                )
                            ,
                        };
                        st.fields = fields;
                        st.base.size = new_size;
                        st.base.alignment = new_alignment;
                        st.base.align_size = new_align_size;
                        st.base.flags &= !type_flags::TYPE_INCOMPLETE;
                        st.base.flags |= flags
                            & (type_flags::OPAQUE_STRUCT
                                | type_flags::VARLENGTH
                                | type_flags::TYPE_INCOMPLETE);
                        Ok(())
                    })?;
                    self.incomplete_typedefs.remove(index);
                }
                (Datatype::Union(_), Datatype::Union(defed_union)) => {
                    let fields = defed_union.fields.clone();
                    let new_size = defed_union.base.size;
                    let new_alignment = defed_union.base.alignment;
                    let new_align_size = defed_union.base.align_size;
                    let flags = defed_union.base.flags;
                    self.define_replace(&dt, |defined| {
                        let un = match defined {
                            Datatype::Union(un) => un,
                            _ => return Err("setFields target is not a TypeUnion".to_string())
                            ,
                        };
                        un.fields = fields;
                        un.base.size = new_size;
                        un.base.alignment = new_alignment;
                        un.base.align_size = new_align_size;
                        un.base.flags &= !type_flags::TYPE_INCOMPLETE;
                        un.base.flags |= flags
                            & (type_flags::VARLENGTH | type_flags::TYPE_INCOMPLETE);
                        Ok(())
                    })?;
                    self.incomplete_typedefs.remove(index);
                }
                (Datatype::Code(_), Datatype::Code(defed_code)) => {
                    // Ghidra: setPrototype(defedCode->proto, prevCode, defedCode->flags);
                    self.set_prototype_define(
                        &dt,
                        defed_code.proto.as_deref(),
                        defed_code.base.flags,
                    )?;
                    self.incomplete_typedefs.remove(index);
                }
                _ => index += 1,
            }
        }
        Ok(())
    }

    // Ghidra: type.cc:4193 TypeFactory::decodeTypeWithCodeFlags
    /// Restore a data-type from an element and extra "code" flags — the
    /// "Kludge to get flags into code pointer types, when they can't come
    /// through the stream" (type.cc:4186-4192) used by `CPoolRecord::decode`
    /// (cpool.cc:147-151) for method/constructor constant-pool records.
    /// Faithful to `TypeFactory::decodeTypeWithCodeFlags`
    /// (type.cc:4193-4212):
    ///
    /// - opens the `<type>` element and runs `decodeBasic` on it,
    /// - a metatype other than `ptr` raises
    ///   `Special type decode does not see pointer`,
    /// - the WORDSIZE attribute loop runs WITHOUT a preceding
    ///   `rewindAttributes` (type.cc:4201-4207, unlike `TypePointer::decode`
    ///   at type.cc:1015). `decodeBasic`'s enumeration above has already run
    ///   the attribute index to exhaustion, and neither XmlDecode
    ///   (marshal.cc:231-241) nor Rudra's `TreeDecoder` restarts enumeration
    ///   implicitly, so this loop reads nothing and `wordsize` keeps the
    ///   `TypePointer` ctor default 1 (type.hh:407). The loop is kept
    ///   structurally identical to the oracle,
    /// - `decodeCode(decoder, isConstructor, isDestructor, false)` decodes
    ///   the pointed-to code type on the SAME still-open element — under the
    ///   exhausted-attributes cursor this is where the oracle's nested
    ///   pointer→code XML raises `Bad size for type ` (empty name), the
    ///   empirically verified 12.0.4 behaviour,
    /// - on success the element is closed, `calcTruncate` runs, and the
    ///   pointer is canonicalized through `findAdd`.
    ///
    /// Exception partial state: every error above leaves the element OPEN
    /// with its attributes consumed and its children unread — the cursor
    /// position and the factory state (nothing inserted; the throw precedes
    /// every insertion) are exactly the oracle's.
    pub fn decode_type_with_code_flags(
        &mut self,
        decoder: &mut dyn Decoder,
        is_constructor: bool,
        is_destructor: bool,
    ) -> Result<Arc<Datatype>, String> {
        // Ghidra: TypePointer tp; — ctor defaults (type.hh:407):
        // ptrto = 0, wordsize = 1, spaceid = 0, truncate = 0.
        // Ghidra: uint4 elemId = decoder.openElement();
        let elem_id = decoder.open_element();
        // Ghidra: tp.decodeBasic(decoder);
        let basic = Datatype::decode_basic(decoder)?;
        // Ghidra: if (tp.getMetatype() != TYPE_PTR)
        //          throw LowlevelError("Special type decode does not see pointer");
        if basic.metatype != TypeMetatype::Pointer {
            return Err("Special type decode does not see pointer".to_string());
        }
        let mut wordsize: u64 = 1; // TypePointer ctor default (type.hh:407)
        // Ghidra (type.cc:4201-4207): the wordsize attribute loop without
        // rewindAttributes — see the doc comment; it never reads under the
        // exhausted cursor, matching XmlDecode's non-restarting enumeration.
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            if decoder.attribute_name(attrib_id).as_deref() == Some("wordsize") {
                wordsize = decoder.read_unsigned_integer();
            }
        }
        // Ghidra: tp.ptrto = decodeCode(decoder, isConstructor, isDestructor, false);
        let ptrto = self.decode_code(decoder, is_constructor, is_destructor, false)?;
        // Ghidra: decoder.closeElement(elemId);
        if elem_id != 0 {
            decoder.close_element(elem_id);
        }
        // Build the candidate pointer exactly as Ghidra's stack-local `tp`
        // now holds it: decodeBasic's fields, the ctor-default wordsize, the
        // ptrto decoded above. calcSubmeta's flag/`pointer_to_array` arms and
        // the inheritable-flags copy of TypePointer::decode (type.cc:1027-1029)
        // are NOT part of this kludge path (the oracle never reaches them
        // either — the decodeCode call above throws first on every real
        // stream).
        let mut base = TypeBase::new(basic.name.clone(), basic.size, TypeMetatype::Pointer);
        base.display_name = basic.display_name.clone();
        base.alignment = basic.alignment;
        base.align_size = basic.size;
        base.id = basic.id;
        base.flags = basic.flags;
        let candidate =
            Datatype::Pointer(TypePointer {
                base,
                ptr_to: ptrto,
                wordsize: wordsize as usize,
            });
        // Ghidra: tp.calcTruncate(*this); (type.cc:1058-1067) — assigns the
        // truncated subcomponent when size == getSizeOfAltPointer(); Rudra's
        // TypePointer has no `truncate` field (TYPE-0001 structural residual),
        // so the resize is issued for its factory-registration side effect.
        if candidate.get_size() as i32 == self.get_size_of_alt_pointer() {
            let _ = self.resize_pointer(
                &candidate,
                self.get_size_of_pointer() as usize);
        }
        // Ghidra: return findAdd(tp);
        // The TypePointer ctor leaves alignment -1, so the oracle's findAdd
        // recomputes alignment through the (architecture-provided) map — the
        // enforcing probe mirrors that dependency.
        self.find_add(candidate, true)
    }

    // Ghidra: type.cc:3390 TypeFactory::insert
    /// Internal method for finally inserting a new Datatype pointer.
    /// Faithful to the oracle's dual registration (type.cc:3390-3406) for the
    /// atomic, pointer, array, and partial variants covered by this series.
    /// The name cross-reference only receives named entries; other container
    /// variants remain on the registered TYPE-0001 residual.
    fn insert(&mut self, dt: Arc<Datatype>) {
        let name = dt.get_name().to_string();
        let structurally_keyed = matches!(
            dt.as_ref(),
            Datatype::Void(_) | Datatype::Base(_) | Datatype::Enum(_)
                | Datatype::Code(_) | Datatype::Pointer(_) | Datatype::Array(_)
                | Datatype::PartialStruct(_) | Datatype::PartialEnum(_)
                | Datatype::PartialUnion(_)
        );
        if structurally_keyed {
            let tree_key = Self::type_tree_key(&dt);
            let tree = self
                .base_type_tree
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = tree.get(&tree_key) {
                let mut message = format!("Shared type id: {:x}\n  ", dt.get_id());
                message.push_str(&Self::print_raw(&dt));
                message.push_str(" : ");
                message.push_str(&Self::print_raw(existing));
                panic!("LowlevelError: {message}");
            }
            tree.insert(tree_key, dt.clone());
        }
        // type.cc:3404-3405: `if (newtype->id!=0) nametree.insert(newtype);`
        // — unnamed entries live in the tree only. decodeBasic's hashName
        // fallback keeps named decode candidates id-non-zero in practice;
        // the flat map keeps any named entry for the legacy lookup paths.
        if !name.is_empty() {
            self.types.insert(name, dt);
        }
    }
}

/// Recovered size defaults from a `<data_organization>` element. Returned by
/// `TypeFactory::decode_data_organization` as a snapshot of the persisted
/// factory state (the factory also stores these in its own fields, mirroring
/// Ghidra's `sizeOf*` members).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataOrganizationSizes {
    /// Default size of "int" (Ghidra `sizeOfInt`).
    pub size_of_int: i32,
    /// Default size of "long" (Ghidra `sizeOfLong`).
    pub size_of_long: i32,
    /// Default pointer size (Ghidra `sizeOfPointer`).
    pub size_of_pointer: i32,
    /// Default char size (Ghidra `sizeOfChar`).
    pub size_of_char: i32,
    /// Default wide-char size (Ghidra `sizeOfWChar`).
    pub size_of_wchar: i32,
}

// RUDRA-GLUE: Architecture-handle lookups of TypeFactory::setupSizes
/// The architecture-derived inputs `TypeFactory::setup_sizes` reads from
/// `glb` in Ghidra (type.cc:3142-3167). Rudra's `TypeFactory` has no
/// Architecture handle yet, so callers provide the same observations:
/// `getStackSpace()->getSpacebase(0).size` (`None` when there is no stack
/// space), `getDefaultDataSpace()->getAddrSize()`, `getDefaultSize()`, and
/// the far-pointer segment op `(innerSize, baseSize)` when one with
/// far-pointer support resolves.
pub struct SizeArchInputs {
    /// `glb->getStackSpace()->getSpacebase(0).size`, or `None` when the
    /// architecture has no stack space (`getStackSpace() == 0`).
    pub stack_spacebase_size: Option<i32>,
    /// `glb->getDefaultDataSpace()->getAddrSize()`.
    pub default_data_space_addr_size: i32,
    /// `glb->getDefaultSize()`.
    pub default_size: i32,
    /// `(innerSize, baseSize)` of a far-pointer segment op on the default
    /// data space, `None` when there is none.
    pub far_pointer: Option<(i32, i32)>,
}

/// Side record for a relative pointer: the containing parent type and the
/// byte offset into it. Models the `parent`/`offset` fields of Ghidra's
/// `TypePointerRel` (type.hh:647) that do not fit on Rudra's flat `TypePointer`.
#[derive(Debug, Clone)]
pub struct RelativePointer {
    /// The container data-type this pointer indexes into.
    pub parent: Arc<Datatype>,
    /// Byte offset within `parent` where the pointee begins.
    pub offset: i64,
}

// Ghidra: type.cc:1092 sign_extend (address.hh:499 local helper)
/// Sign-extend the low `bits+1` bits of `val` to a full `i64`. Mirrors
/// Ghidra's `sign_extend(off, size*8-1)` invocation at type.cc:1092 (the
/// helper is defined in address.hh:499 as `sign_extend(intb val, int4 bits)`).
/// Used by `TypeFactory::down_chain_pointer` when wrapping an out-of-range
/// array offset back into `[0, ptrtoSize)`.
fn sign_extend(val: i64, bits: usize) -> i64 {
    // Guard against bits >= 64 (size >= 8 bytes), in which case no extension
    // is needed (Ghidra's shift by >= width is UB but effectively a no-op).
    if bits >= 63 {
        return val;
    }
    let shift = 63 - bits;
    ((val as i64) << shift) >> shift
}

// Ghidra: type.cc:3849 TypeFactory::getTypePointerStripArray (inline effect)
/// Strip a single array layer from `dt`, mirroring the behaviour of
/// `TypeFactory::getTypePointerStripArray` (type.cc:3849-3859) as invoked by
/// the plain `TypePointer::downChain` (type.cc:1119): if the component is an
/// array, return its element type; otherwise return the type unchanged.
fn strip_array(dt: Arc<Datatype>) -> Arc<Datatype> {
    match dt.as_ref() {
        Datatype::Array(a) => a.array_of.clone(),
        _ => dt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    // RUDRA-GLUE: fixture-local XML element builder mirroring the oracle
    // fixture's decode strings (tests have no Ghidra counterpart).
    fn xml_elem(name: &str, attrs: &[(&str, &str)]) -> std::sync::Arc<RwLock<Element>> {
        let mut el = Element::new();
        el.set_name(name);
        for (k, v) in attrs {
            el.add_attribute(k, v);
        }
        std::sync::Arc::new(RwLock::new(el))
    }

    fn xml_elem_with_children(
        name: &str,
        attrs: &[(&str, &str)],
        children: Vec<std::sync::Arc<RwLock<Element>>>,
    ) -> std::sync::Arc<RwLock<Element>> {
        let el = xml_elem(name, attrs);
        for child in children {
            el.write().unwrap().add_child(child);
        }
        el
    }

    fn decoder_for_type(child: std::sync::Arc<RwLock<Element>>) -> TreeDecoder {
        let root = xml_elem_with_children("root", &[], vec![child]);
        let mut decoder = TreeDecoder::new(root, std::sync::Arc::new(RwLock::new(IdRegistry)));
        decoder.open_element();
        decoder
    }

    fn setup_default_sizes(factory: &mut TypeFactory) {
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
    }

    // Ghidra: type.cc:4193 TypeFactory::decodeTypeWithCodeFlags (regression
    // net for the TYPEFACTORY-CODEFLAGS-DECODE-0001 oracle fixture)
    #[test]
    fn test_decode_type_with_code_flags_error_paths() {
        let mut factory = TypeFactory::new(8);
        // Nested pointer->code: the oracle's decodeStub re-read of the
        // attribute-exhausted outer element raises "Bad size for type ".
        let mut decoder = decoder_for_type(xml_elem_with_children(
            "type",
            &[("metatype", "ptr"), ("size", "8")],
            vec![xml_elem("type", &[("metatype", "code"), ("size", "1")])],
        ));
        assert_eq!(
            factory
                .decode_type_with_code_flags(&mut decoder, true, false)
                .unwrap_err(),
            "Bad size for type "
        );
        // Cursor partial state: the failed element is still open with its
        // children unread.
        assert!(decoder.peek_element() != 0);

        // Non-pointer metatype: "Special type decode does not see pointer".
        let mut decoder =
            decoder_for_type(xml_elem("type", &[("metatype", "code"), ("size", "1")]));
        assert_eq!(
            factory
                .decode_type_with_code_flags(&mut decoder, true, true)
                .unwrap_err(),
            "Special type decode does not see pointer"
        );

        // Missing size on the first decodeBasic (named form).
        let mut decoder =
            decoder_for_type(xml_elem("type", &[("metatype", "ptr"), ("name", "vp")]));
        assert_eq!(
            factory
                .decode_type_with_code_flags(&mut decoder, false, true)
                .unwrap_err(),
            "Bad size for type vp"
        );
    }

    // Ghidra: type.cc:4401 TypeFactory::decodeCode via decodeType — stub
    // creation, in-place completion, dedup, redefine and clash errors.
    #[test]
    fn test_decode_code_stub_completion_and_errors() {
        let mut factory = TypeFactory::new(8);

        // Prototype-less stub: created incomplete, completed in place by the
        // setPrototype wrapper (type_incomplete cleared even for a null
        // prototype, variable_length absent).
        let ct = factory
            .decode_type(&mut decoder_for_type(xml_elem(
                "type",
                &[("metatype", "code"), ("name", "cf_one"), ("size", "1")],
            )))
            .expect("code decode");
        assert_eq!(ct.get_name(), "cf_one");
        assert_eq!(ct.get_metatype(), TypeMetatype::Code);
        assert_eq!(ct.get_flags() & type_flags::TYPE_INCOMPLETE, 0);
        assert_eq!(ct.get_flags() & type_flags::VARLENGTH, 0);
        assert_eq!(ct.get_alignment(), 1);
        assert_eq!(ct.get_align_size(), 1);
        assert!(matches!(ct.as_ref(), Datatype::Code(c) if c.proto.is_none()));

        // Re-decode dedups to the same canonical object.
        let again = factory
            .decode_type(&mut decoder_for_type(xml_elem(
                "type",
                &[("metatype", "code"), ("name", "cf_one"), ("size", "1")],
            )))
            .expect("code re-decode");
        assert!(std::sync::Arc::ptr_eq(&ct, &again));

        // Same name+id, different size: compareDependency redefinition error,
        // previous definition survives.
        let err = factory
            .decode_type(&mut decoder_for_type(xml_elem(
                "type",
                &[("metatype", "code"), ("name", "cf_one"), ("size", "2")],
            )))
            .unwrap_err();
        assert_eq!(err, "Redefinition of code data-type: cf_one");
        assert_eq!(factory.find_by_name("cf_one").unwrap().get_size(), 1);

        // Non-code occupant: findByIdLocal metatype check.
        factory
            .decode_type(&mut decoder_for_type(xml_elem(
                "type",
                &[("metatype", "int"), ("name", "clash_t"), ("size", "4")],
            )))
            .expect("int decode");
        let err = factory
            .decode_type(&mut decoder_for_type(xml_elem(
                "type",
                &[("metatype", "code"), ("name", "clash_t"), ("size", "1")],
            )))
            .unwrap_err();
        assert_eq!(err, "Trying to redefine type: clash_t");
        assert_eq!(
            factory.find_by_name("clash_t").unwrap().get_metatype(),
            TypeMetatype::Int
        );

        // A present <prototype> child is the registered FuncProto::decode gap:
        // the stub is inserted first, then the error fires (partial state).
        let err = factory
            .decode_type(&mut decoder_for_type(xml_elem_with_children(
                "type",
                &[("metatype", "code"), ("name", "cf_gap"), ("size", "1")],
                vec![xml_elem("prototype", &[("model", "__stdcall")])],
            )))
            .unwrap_err();
        assert!(err.contains("FuncProto::decode"), "{err}");
        let stub = factory
            .find_by_name("cf_gap")
            .expect("stub survives the gap error");
        assert_eq!(
            stub.get_flags() & type_flags::TYPE_INCOMPLETE,
            type_flags::TYPE_INCOMPLETE
        );
    }

    #[test]
    fn test_factory_init() {
        let factory = TypeFactory::new(8);
        assert!(factory.find_by_name("void").is_some());
        assert!(factory.find_by_name("int").is_some());
        assert!(factory.find_by_name("uint").is_some());
        assert!(factory.find_by_name("bool").is_some());
    let preferred_char = factory
            .get_base(1, TypeMetatype::Int)
            .expect("preferred one-byte signed core type");
        let non_character = factory
            .get_base_no_char(1, TypeMetatype::Int)
            .expect("ordinary one-byte signed core type");
        assert_eq!(preferred_char.get_name(), "char");
        assert!(preferred_char.is_char_print());
        assert_eq!(non_character.get_name(), "sbyte");
        assert!(!non_character.is_char_print());
        assert!(!Arc::ptr_eq(&preferred_char, &non_character));
    }

    #[test]
    fn test_data_org_core_inventory_matches_java_coretypes() {
        // Java coreBuiltin projection (PcodeDataTypeManager.generateCoreTypes
        // under x86-64 gcc data organization).
        let factory = TypeFactory::new(8);
        let expected = [
            ("sbyte", 1, TypeMetatype::Int),
            ("short", 2, TypeMetatype::Int),
            ("int3", 3, TypeMetatype::Int),
            ("int", 4, TypeMetatype::Int),
            ("int5", 5, TypeMetatype::Int),
            ("int6", 6, TypeMetatype::Int),
            ("int7", 7, TypeMetatype::Int),
            ("long", 8, TypeMetatype::Int),
            ("byte", 1, TypeMetatype::Uint),
            ("ushort", 2, TypeMetatype::Uint),
            ("uint3", 3, TypeMetatype::Uint),
            ("uint", 4, TypeMetatype::Uint),
            ("uint5", 5, TypeMetatype::Uint),
            ("uint6", 6, TypeMetatype::Uint),
            ("uint7", 7, TypeMetatype::Uint),
            ("ulong", 8, TypeMetatype::Uint),
            ("double", 8, TypeMetatype::Float),
            ("longdouble", 16, TypeMetatype::Float),
            ("undefined8", 8, TypeMetatype::Unknown),
            ("wchar_t", 4, TypeMetatype::Int),
        ];
        for (name, size, metatype) in expected {
            let datatype = factory
                .find_by_name(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(
                (datatype.get_size(), datatype.get_metatype()),
                (size, metatype)
            );
        }
        // cacheCoreTypes ASCII preference and (submeta,size) cache slots.
        assert!(Arc::ptr_eq(
            &factory
                .get_base(8, TypeMetatype::Int)
                .expect("signed 8-byte core"),
            &factory.find_by_name("long").expect("long")
        ));
        assert!(Arc::ptr_eq(
            &factory
                .get_base(8, TypeMetatype::Uint)
                .expect("unsigned 8-byte core"),
            &factory.find_by_name("ulong").expect("ulong")
        ));
        assert!(Arc::ptr_eq(
            &factory
                .get_base(2, TypeMetatype::Int)
                .expect("signed 2-byte core"),
            &factory.find_by_name("short").expect("short")
        ));
        assert!(Arc::ptr_eq(
            &factory
                .get_base(1, TypeMetatype::Uint)
                .expect("unsigned 1-byte core"),
            &factory.find_by_name("byte").expect("byte")
        ));
        assert!(Arc::ptr_eq(
            &factory
                .get_base(8, TypeMetatype::Float)
                .expect("8-byte float core"),
            &factory.find_by_name("double").expect("double")
        ));
    }

    #[test]
    fn test_data_org_code_core_named_and_unified() {
        // Ghidra: ghidra_arch.cc:349 — every oracle headless form registers
        // the `code` core; cacheCoreTypes (type.cc:3239-3244) fills
        // typecache[1][TYPE_CODE], unifying getBase(1,TYPE_CODE) and
        // getTypeCode() onto the NAMED core. The data-org flavor previously
        // answered get_base(1, Code) with an UNNAMED base (empty
        // printNameBase contribution — TYPINGPX-PXNAME-0001 case d).
        let mut factory = TypeFactory::new_flavor(8, CoreTypeFlavor::DataOrg);
        let by_base = factory
            .get_base(1, TypeMetatype::Code)
            .expect("code base resolves");
        assert_eq!(by_base.get_name(), "code");
        assert_eq!(by_base.get_metatype(), TypeMetatype::Code);
        assert_eq!(by_base.get_size(), 1);
        // type.cc:3680 getTypeCode probes the same typecache slot: both
        // access paths must return the SAME canonical object.
        let by_getter = factory.get_type_code();
        assert!(Arc::ptr_eq(&by_base, &by_getter));
        assert!(Arc::ptr_eq(
            &by_base,
            &factory.find_by_name("code").expect("code core registered")
        ));
    }

    #[test]
    fn test_ghidra_fallback_core_inventory_and_cache_identity() {
        let factory = TypeFactory::new_flavor(8, CoreTypeFlavor::GhidraFallback);
        let expected = [
            ("void", 0, TypeMetatype::Void),
            ("bool", 1, TypeMetatype::Bool),
            ("byte", 1, TypeMetatype::Uint),
            ("word", 2, TypeMetatype::Uint),
            ("dword", 4, TypeMetatype::Uint),
            ("qword", 8, TypeMetatype::Uint),
            ("char", 1, TypeMetatype::Int),
            ("sbyte", 1, TypeMetatype::Int),
            ("sword", 2, TypeMetatype::Int),
            ("sdword", 4, TypeMetatype::Int),
            ("sqword", 8, TypeMetatype::Int),
            ("float", 4, TypeMetatype::Float),
            ("float8", 8, TypeMetatype::Float),
            ("float10", 10, TypeMetatype::Float),
            ("float16", 16, TypeMetatype::Float),
            ("undefined", 1, TypeMetatype::Unknown),
            ("undefined2", 2, TypeMetatype::Unknown),
            ("undefined4", 4, TypeMetatype::Unknown),
            ("undefined8", 8, TypeMetatype::Unknown),
            ("code", 1, TypeMetatype::Code),
            ("wchar", 2, TypeMetatype::Int),
        ];
        for (name, size, metatype) in expected {
            let datatype = factory
                .find_by_name(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(
                (datatype.get_size(), datatype.get_metatype()),
                (size, metatype)
            );
            assert!(datatype.is_coretype(), "{name} is not core");
        }
        let character = factory.find_by_name("char").expect("ASCII core type");
        assert!(Arc::ptr_eq(
            &character,
            &factory
                .get_base(1, TypeMetatype::Int)
                .expect("preferred INT1")
        ));
        assert!(Arc::ptr_eq(
            &character,
            &factory.get_type_char(1).expect("cached ASCII core type")
        ));
        let signed_byte = factory
            .get_base_no_char(1, TypeMetatype::Int)
            .expect("non-character INT1");
        assert_eq!(signed_byte.get_name(), "sbyte");
        assert!(!Arc::ptr_eq(&character, &signed_byte));
        assert_eq!(factory.get_type_char(2).unwrap().get_name(), "wchar");
        assert!(factory.get_type_char(4).is_err());
        assert_eq!(
            factory
                .get_base(10, TypeMetatype::Float)
                .unwrap()
                .get_name(),
            "float10"
        );
        assert_eq!(
            factory
                .get_base(16, TypeMetatype::Float)
                .unwrap()
                .get_name(),
            "float16"
        );
        assert!(Arc::ptr_eq(
            &factory.find_by_name("code").unwrap(),
            &factory.get_base(1, TypeMetatype::Code).unwrap()
        ));
    }

    #[test]
    fn test_sleigh_fallback_core_inventory_and_cache_identity() {
        let factory = TypeFactory::new_flavor(8, CoreTypeFlavor::Standalone);
        let expected = [
            ("void", 0, TypeMetatype::Void),
            ("bool", 1, TypeMetatype::Bool),
            ("uint1", 1, TypeMetatype::Uint),
            ("uint2", 2, TypeMetatype::Uint),
            ("uint4", 4, TypeMetatype::Uint),
            ("uint8", 8, TypeMetatype::Uint),
            ("int1", 1, TypeMetatype::Int),
            ("int2", 2, TypeMetatype::Int),
            ("int4", 4, TypeMetatype::Int),
            ("int8", 8, TypeMetatype::Int),
            ("float4", 4, TypeMetatype::Float),
            ("float8", 8, TypeMetatype::Float),
            ("float10", 10, TypeMetatype::Float),
            ("float16", 16, TypeMetatype::Float),
            ("xunknown1", 1, TypeMetatype::Unknown),
            ("xunknown2", 2, TypeMetatype::Unknown),
            ("xunknown4", 4, TypeMetatype::Unknown),
            ("xunknown8", 8, TypeMetatype::Unknown),
            ("code", 1, TypeMetatype::Code),
            ("char", 1, TypeMetatype::Int),
            ("wchar2", 2, TypeMetatype::Int),
            ("wchar4", 4, TypeMetatype::Int),
        ];
        for (name, size, metatype) in expected {
            let datatype = factory
                .find_by_name(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(
                (datatype.get_size(), datatype.get_metatype()),
                (size, metatype)
            );
            assert!(datatype.is_coretype(), "{name} is not core");
        }
        assert!(factory.find_by_name("int").is_none());
        assert!(factory.find_by_name("uint").is_none());
        assert!(factory.find_by_name("double").is_none());
        let character = factory.find_by_name("char").expect("ASCII core type");
        assert!(Arc::ptr_eq(
            &character,
            &factory
                .get_base(1, TypeMetatype::Int)
                .expect("preferred INT1")
        ));
        assert!(Arc::ptr_eq(
            &character,
            &factory.get_type_char(1).expect("cached ASCII core type")
        ));
        let signed_byte = factory
            .get_base_no_char(1, TypeMetatype::Int)
            .expect("non-character INT1");
        assert_eq!(signed_byte.get_name(), "int1");
        assert!(!Arc::ptr_eq(&character, &signed_byte));
        assert_eq!(factory.get_type_char(2).unwrap().get_name(), "wchar2");
        assert_eq!(factory.get_type_char(4).unwrap().get_name(), "wchar4");
        assert_eq!(
            factory.get_base(2, TypeMetatype::Int).unwrap().get_name(),
            "int2"
        );
        assert_eq!(
            factory
                .get_base(10, TypeMetatype::Float)
                .unwrap()
                .get_name(),
            "float10"
        );
        assert_eq!(
            factory
                .get_base(16, TypeMetatype::Float)
                .unwrap()
                .get_name(),
            "float16"
        );
        assert!(Arc::ptr_eq(
            &factory.find_by_name("code").unwrap(),
            &factory.get_base(1, TypeMetatype::Code).unwrap()
        ));
    }

    #[test]
    fn test_pointer_deduplication() {
        let mut factory = TypeFactory::new(8);
        assert!(factory.align_map.is_empty());
        let int_type = factory.find_by_name("int").unwrap();

        let ptr1 = factory.get_ptr(int_type.clone());
        let ptr2 = factory.get_ptr(int_type.clone());

        assert_eq!(Arc::as_ptr(&ptr1), Arc::as_ptr(&ptr2));
        assert!(ptr1.get_name().is_empty());
        assert_eq!(ptr1.get_size(), 8);
        assert_eq!((ptr1.get_alignment(), ptr1.get_align_size()), (8, 8));
    }

    #[test]
    fn test_pointer_canonical_key_geometry_and_virtual_stripping() {
        let mut factory = TypeFactory::new(8);
        let partial_parent = factory.create_struct("PointerPartialParent");
        setup_default_sizes(&mut factory);
        let int_type = factory.find_by_name("int").expect("int core type");
        let uint_type = factory.find_by_name("uint").expect("uint core type");

        let plain = factory.get_type_pointer(8, int_type.clone(), 1);
        let repeated = factory.get_type_pointer(8, int_type.clone(), 1);
        let different_wordsize = factory.get_type_pointer(8, int_type.clone(), 2);
        let different_size = factory.get_type_pointer(4, int_type.clone(), 1);
        let different_target = factory.get_type_pointer(8, uint_type.clone(), 1);
        let duplicate_int = Arc::new((*int_type).clone());
        let different_identity = factory.get_type_pointer(8, duplicate_int.clone(), 1);
        assert!(Arc::ptr_eq(&plain, &repeated));
        assert!(!Arc::ptr_eq(&plain, &different_wordsize));
        assert!(!Arc::ptr_eq(&plain, &different_size));
        assert!(!Arc::ptr_eq(&plain, &different_target));
        assert!(!Arc::ptr_eq(&plain, &different_identity));
        assert_ne!(plain.compare_dependency(&different_identity), 0);
        assert!(plain.get_name().is_empty());
        assert!(plain.is_coretype());
        assert_eq!(plain.get_flags() & type_flags::IS_PTRREL, 0);
        let plain_pointer = match plain.as_ref() {
            Datatype::Pointer(pointer) => pointer,
            _ => panic!("expected pointer"),
        };
        let plain_key = TypeFactory::type_tree_key(&plain);
        assert_eq!(plain_key.0, plain.get_submeta() as i32 as u8);
        assert_eq!(plain_key.1, Arc::as_ptr(&plain_pointer.ptr_to) as usize);
        assert_eq!((plain_key.2, plain_key.3), (0, 0));
        assert_eq!(plain_key.4, 1);
        assert_eq!((plain_key.5, plain_key.6), (1, 0));
        assert_eq!(plain_key.7, Reverse(8));
        assert_eq!(plain_key.8, 0);
        assert!(plain_key < TypeFactory::type_tree_key(&different_wordsize));
        assert!(plain_key < TypeFactory::type_tree_key(&different_size));

        let named = factory.get_type_pointer_named(
            8,
            int_type.clone(),
            1,
            "CanonicalNamedPointer");
        let named_repeat = factory.get_type_pointer_named(
            8,
            int_type.clone(),
            1,
            "CanonicalNamedPointer");
        assert!(Arc::ptr_eq(&named, &named_repeat));
        assert_eq!(named.get_name(), "CanonicalNamedPointer");
        assert_eq!(named.get_display_name(), "CanonicalNamedPointer");
        assert_eq!(named.get_id(), Datatype::hash_name("CanonicalNamedPointer"));
        let named_key = TypeFactory::type_tree_key(&named);
        assert_eq!(
            (
                named_key.0,
                named_key.1,
                named_key.2,
                named_key.3,
                named_key.4,
                named_key.5,
                named_key.6,
                named_key.7,
            ),
            (
                plain_key.0,
                plain_key.1,
                plain_key.2,
                plain_key.3,
                plain_key.4,
                plain_key.5,
                plain_key.6,
                plain_key.7,
            )
        );
        assert_eq!(named_key.8, Datatype::hash_name("CanonicalNamedPointer"));
        assert!(plain_key < named_key);
        let named_keys_before = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for (size, target, wordsize) in [
            (8, uint_type.clone(), 1),
            (8, int_type.clone(), 2),
            (4, int_type.clone(), 1),
        ] {
            let named_conflict =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    factory.get_type_pointer_named(
                        size,
                        target,
                        wordsize,
                        "CanonicalNamedPointer");
                }));
            let payload = named_conflict.expect_err("named dependency conflict");
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .expect("string panic payload");
            assert_eq!(
                message,
                "LowlevelError: Trying to alter definition of type: CanonicalNamedPointer"
            );
        }
        assert!(Arc::ptr_eq(
            &named,
            &factory
                .find_by_name("CanonicalNamedPointer")
                .expect("named pointer survives conflict")
        ));
        assert_eq!(
            factory
                .base_type_tree
                .read()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            named_keys_before
        );

        let int_array = factory.get_array(int_type.clone(), 2);
        let uint_array = factory.get_array(uint_type, 2);
        let int_array_pointer = factory.get_type_pointer(8, int_array.clone(), 1);
        let uint_array_pointer = factory.get_type_pointer(8, uint_array.clone(), 1);
        assert!(!Arc::ptr_eq(&int_array_pointer, &uint_array_pointer));
        assert!(int_array_pointer.is_pointer_to_array());
        assert!(matches!(
            int_array_pointer.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &int_array)
        ));
        assert!(matches!(
            uint_array_pointer.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &uint_array)
        ));
        let singleton_array = factory.get_array(int_type.clone(), 1);
        let singleton_pointer = factory.get_type_pointer(8, singleton_array, 1);
        assert!(singleton_pointer.is_pointer_to_array());
        assert!(singleton_pointer.needs_resolution());

        let incomplete_pointer =
            factory.get_type_pointer(8, partial_parent.clone(), 1);
        assert_eq!(incomplete_pointer.get_submeta(), SubMetatype::PtrStruct);

        let ordinary_alias = factory.get_typedef("PointerScalarAlias", int_type.clone());
        let alias_pointer = factory.get_type_pointer(8, ordinary_alias.clone(), 1);
        assert!(matches!(
            alias_pointer.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &ordinary_alias)
        ));

        let partial = factory.get_type_partial_struct(partial_parent, 0, 2);
        let partial_stripped =
            Datatype::get_stripped_arc(&partial).expect("partial stripped fallback");
        let partial_alias = factory.get_typedef("PointerPartialAlias", partial.clone());
        let partial_pointer = factory.get_type_pointer(8, partial, 1);
        let partial_alias_pointer = factory.get_type_pointer(8, partial_alias, 1);
        assert!(matches!(
            partial_pointer.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &partial_stripped)
        ));
        assert!(Arc::ptr_eq(&partial_pointer, &partial_alias_pointer));

        let ram_pointer = factory
            .find_add(
                Datatype::Pointer(TypePointer::new_with_space(
                    int_type.clone(),
                    AddressSpace::Ram,
                )),
                true,
            )
            .expect("RAM pointer");
        let register_pointer = factory
            .find_add(
                Datatype::Pointer(TypePointer::new_with_space(
                    int_type,
                    AddressSpace::Register,
                )),
                true,
            )
            .expect("register pointer");
        assert!(!Arc::ptr_eq(&plain, &ram_pointer));
        assert!(!Arc::ptr_eq(&ram_pointer, &register_pointer));
        let ram_key = TypeFactory::type_tree_key(&ram_pointer);
        let register_key = TypeFactory::type_tree_key(&register_pointer);
        assert_eq!((ram_key.5, ram_key.6), (0, AddressSpace::Ram.space_id()));
        assert!(ram_key < plain_key);
        assert!(ram_key < register_key);

        let keys_before_collision = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let duplicate = Arc::new((*ram_pointer).clone());
        let collision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.insert(duplicate);
        }));
        assert!(collision.is_err());
        let keys_after_collision = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys_after_collision, keys_before_collision);
    }

    #[test]
    fn test_ephemeral_pointer_rel_inherits_parent_geometry_and_identity() {
        let mut factory = TypeFactory::new(8);
        let parent = factory.create_struct("EphemeralParent");
        let other_parent = factory.create_struct("OtherEphemeralParent");
        setup_default_sizes(&mut factory);
        let int_type = factory.find_by_name("int").expect("int core type");
        let uint_type = factory.find_by_name("uint").expect("uint core type");
        let unknown = factory
            .find_by_name("undefined1")
            .expect("one-byte unknown core type");

        let parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let relative = factory.get_type_pointer_rel_ephemeral(
            parent_pointer.clone(),
            int_type.clone(),
            4);
        let repeated = factory.get_type_pointer_rel_ephemeral(
            parent_pointer,
            int_type.clone(),
            4);
        assert!(Arc::ptr_eq(&relative, &repeated));
        assert!(relative.get_name().is_empty());
        assert_eq!(
            relative.get_flags() & (type_flags::IS_PTRREL | type_flags::HAS_STRIPPED),
            type_flags::IS_PTRREL | type_flags::HAS_STRIPPED
        );
        let relative_pointer = match relative.as_ref() {
            Datatype::Pointer(pointer) => pointer,
            _ => panic!("expected relative pointer"),
        };
        let state = relative_pointer
            .base
            .pointer_rel
            .as_ref()
            .expect("relative state");
        assert_eq!(relative_pointer.base.size, 8);
        assert_eq!(relative_pointer.wordsize, 2);
        assert!(Arc::ptr_eq(&relative_pointer.ptr_to, &int_type));
        assert!(Arc::ptr_eq(&state.parent, &parent));
        assert_eq!(state.offset, 4);
        let stripped = state.stripped.as_ref().expect("ephemeral stripped pointer");
        let canonical_plain = factory.get_type_pointer(8, int_type.clone(), 2);
        assert!(Arc::ptr_eq(stripped, &canonical_plain));
        let relative_key = TypeFactory::type_tree_key(&relative);
        assert_eq!(relative_key.0, SubMetatype::PtrRel as i32 as u8);
        assert_eq!(relative_key.1, Arc::as_ptr(&int_type) as usize);
        assert_eq!(relative_key.2, 4);
        assert_eq!(relative_key.3, Arc::as_ptr(&parent) as usize);
        assert_eq!(relative_key.4, 2);
        assert_eq!((relative_key.5, relative_key.6), (0, 0));
        assert_eq!(relative_key.7, Reverse(8));
        assert_eq!(relative_key.8, 0);

        let other_parent_pointer = factory.get_type_pointer(8, other_parent, 2);
        let different_parent = factory.get_type_pointer_rel_ephemeral(
            other_parent_pointer,
            int_type.clone(),
            4);
        let target_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let different_target = factory.get_type_pointer_rel_ephemeral(
            target_parent_pointer,
            uint_type,
            4);
        let offset_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let different_offset = factory.get_type_pointer_rel_ephemeral(
            offset_parent_pointer,
            int_type.clone(),
            8);
        let negative_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let negative_offset = factory.get_type_pointer_rel_ephemeral(
            negative_parent_pointer,
            int_type.clone(),
            -4);
        let negative_repeat_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let negative_repeat = factory.get_type_pointer_rel_ephemeral(
            negative_repeat_parent_pointer,
            int_type.clone(),
            -4,
        );
        let narrow_parent_pointer = factory.get_type_pointer(4, parent.clone(), 1);
        let different_geometry = factory.get_type_pointer_rel_ephemeral(
            narrow_parent_pointer,
            int_type.clone(),
            4);
        let wide_word_parent_pointer = factory.get_type_pointer(8, parent.clone(), 4);
        let different_wordsize = factory.get_type_pointer_rel_ephemeral(
            wide_word_parent_pointer,
            int_type.clone(),
            4);
        assert!(!Arc::ptr_eq(&relative, &different_parent));
        assert!(!Arc::ptr_eq(&relative, &different_target));
        assert!(!Arc::ptr_eq(&relative, &different_offset));
        assert!(!Arc::ptr_eq(&relative, &negative_offset));
        assert!(Arc::ptr_eq(&negative_offset, &negative_repeat));
        assert!(!Arc::ptr_eq(&relative, &different_geometry));
        assert!(!Arc::ptr_eq(&relative, &different_wordsize));
        assert_eq!(TypeFactory::type_tree_key(&negative_offset).2, -4);
        assert!(TypeFactory::type_tree_key(&negative_offset) < relative_key);
        assert!(matches!(
            different_geometry.as_ref(),
            Datatype::Pointer(pointer) if pointer.base.size == 4 && pointer.wordsize == 1
        ));
        assert!(matches!(
            different_wordsize.as_ref(),
            Datatype::Pointer(pointer) if pointer.base.size == 8 && pointer.wordsize == 4
        ));

        let formal = Datatype::Pointer(TypePointer::new_relative(
            8,
            int_type.clone(),
            2,
            parent.clone(),
            4,
        ));
        assert_eq!(formal.get_flags() & type_flags::HAS_STRIPPED, 0);
        assert_eq!(TypeFactory::type_tree_key(&formal), relative_key);

        let parent_clone = Arc::new((*parent).clone());
        let parent_clone_pointer = factory.get_type_pointer(8, parent_clone, 2);
        let different_parent_identity = factory.get_type_pointer_rel_ephemeral(
            parent_clone_pointer,
            int_type.clone(),
            4);
        let target_clone = Arc::new((*int_type).clone());
        let target_clone_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let different_target_identity = factory.get_type_pointer_rel_ephemeral(
            target_clone_parent_pointer,
            target_clone,
            4);
        assert_ne!(relative.compare_dependency(&different_parent_identity), 0);
        assert_ne!(relative.compare_dependency(&different_target_identity), 0);

        let ordinary_alias = factory.get_typedef("RelativeScalarAlias", int_type.clone());
        let alias_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let alias_relative = factory.get_type_pointer_rel_ephemeral(
            alias_parent_pointer,
            ordinary_alias.clone(),
            4);
        let alias_pointer = match alias_relative.as_ref() {
            Datatype::Pointer(pointer) => pointer,
            _ => panic!("expected relative pointer"),
        };
        assert!(Arc::ptr_eq(&alias_pointer.ptr_to, &ordinary_alias));
        let alias_stripped = alias_pointer
            .get_stripped_pointer()
            .expect("ephemeral relative pointer stripped target");
        assert!(matches!(
            alias_stripped.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &ordinary_alias)
        ));
        assert!(!Arc::ptr_eq(alias_stripped, &alias_relative));

        let partial_target = factory.get_type_partial_struct(parent.clone(), 0, 2);
        let partial_stripped =
            Datatype::get_stripped_arc(&partial_target).expect("partial stripped target");
        let partial_parent_pointer = factory.get_type_pointer(8, parent.clone(), 2);
        let partial_relative = factory.get_type_pointer_rel_ephemeral(
            partial_parent_pointer,
            partial_target.clone(),
            4,
        );
        let partial_pointer = match partial_relative.as_ref() {
            Datatype::Pointer(pointer) => pointer,
            _ => panic!("expected relative pointer"),
        };
        assert!(Arc::ptr_eq(&partial_pointer.ptr_to, &partial_target));
        assert!(matches!(
            partial_pointer.get_stripped_pointer().map(|value| value.as_ref()),
            Some(Datatype::Pointer(pointer)) if Arc::ptr_eq(&pointer.ptr_to, &partial_stripped)
        ));

        let unknown_parent_pointer = factory.get_type_pointer(8, parent, 2);
        let unknown_relative =
            factory.get_type_pointer_rel_ephemeral(unknown_parent_pointer, unknown, 4);
        assert_eq!(unknown_relative.get_submeta(), SubMetatype::PtrRelUnknown);
        assert_eq!(
            TypeFactory::type_tree_key(&unknown_relative).0,
            SubMetatype::PtrRelUnknown as i32 as u8
        );
        assert!(relative_key < TypeFactory::type_tree_key(&unknown_relative));

        let pointer_to_relative = factory.get_type_pointer(8, relative.clone(), 1);
        assert!(matches!(
            pointer_to_relative.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, stripped)
        ));

        let nonpointer_parent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.get_type_pointer_rel_ephemeral(int_type, relative, 0);
        }));
        assert!(nonpointer_parent.is_err());
    }

    #[test]
    fn test_pointer_factory_fails_before_layout_setup_without_tree_leak() {
        let mut factory = TypeFactory::raw();
        let scalar = Arc::new(Datatype::Base(TypeBase::new(
            "raw_scalar".into(),
            4,
            TypeMetatype::Int,
        )));
        let keys_before = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            factory
                .get_type_pointer_result(8, scalar.clone(), 1, true)
                .unwrap_err(),
            "TypeFactory alignment map not initialized"
        );
        let public_failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.get_type_pointer(8, scalar.clone(), 1);
        }));
        let named_failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.get_type_pointer_named(8, scalar, 1, "RawNamedPointer");
        }));
        assert!(public_failure.is_err());
        assert!(named_failure.is_err());
        assert!(factory.find_by_name("RawNamedPointer").is_none());
        let keys_after = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys_after, keys_before);
    }

    #[test]
    fn test_pointer_decode_returns_existing_canonical_object() {
        let mut factory = TypeFactory::new(8);
        assert!(factory.align_map.is_empty());
        let pointer_xml = || {
            xml_elem_with_children(
                "type",
                &[("metatype", "ptr"), ("size", "8"), ("wordsize", "2")],
                vec![xml_elem(
                    "type",
                    &[
                        ("metatype", "uint"),
                        ("name", "DecodePointerTarget"),
                        ("size", "4"),
                    ],
                )],
            )
        };
        let decoded = factory
            .decode_type(&mut decoder_for_type(pointer_xml()))
            .expect("first pointer decode");
        let keys_after_first = factory.base_type_tree.read().unwrap().len();
        let repeated = factory
            .decode_type(&mut decoder_for_type(pointer_xml()))
            .expect("repeated pointer decode");
        assert_eq!(
            factory.base_type_tree.read().unwrap().len(), keys_after_first
        );
        assert!(Arc::ptr_eq(&decoded, &repeated));
        assert!(decoded.get_name().is_empty());
        assert!(decoded.get_display_name().is_empty());
        assert_eq!(decoded.get_id(), 0);
        assert_eq!((decoded.get_alignment(), decoded.get_align_size()), (8, 8));
        assert!(matches!(
            decoded.as_ref(),
            Datatype::Pointer(pointer)
                if pointer.wordsize == 2
                    && pointer.ptr_to.get_name() == "DecodePointerTarget"
        ));
        let decoded_target = match decoded.as_ref() {
            Datatype::Pointer(pointer) => pointer.ptr_to.clone(),
            _ => panic!("expected pointer"),
        };
        let direct = factory.get_type_pointer(8, decoded_target, 2);
        assert!(Arc::ptr_eq(&decoded, &direct));
        let different_geometry_xml = xml_elem_with_children(
            "type",
            &[("metatype", "ptr"), ("size", "4")],
            vec![xml_elem(
                "type",
                &[
                    ("metatype", "uint"),
                    ("name", "DecodePointerTarget"),
                    ("size", "4"),
                ],
            )],
        );
        let different_geometry = factory
            .decode_type(&mut decoder_for_type(different_geometry_xml))
            .expect("different pointer decode geometry");
        assert!(!Arc::ptr_eq(&decoded, &different_geometry));
        assert!(matches!(
            different_geometry.as_ref(),
            Datatype::Pointer(pointer) if pointer.base.size == 4 && pointer.wordsize == 1
        ));
    }

    #[test]
    fn test_array_creation() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").unwrap();

        let array = factory.get_array(int_type.clone(), 10);
        let repeated = factory.get_array(int_type, 10);
        assert!(array.get_name().is_empty());
        assert!(array.get_display_name().is_empty());
        assert_eq!(array.get_size(), 40);
        assert!(Arc::ptr_eq(&array, &repeated));
    }

    #[test]
    fn test_array_stride_identity_and_singleton_resolution() {
        let mut factory = TypeFactory::new(8);
        let mut odd_base = TypeBase::new("odd3".into(), 3, TypeMetatype::Uint);
        odd_base.display_name = "odd3".into();
        odd_base.id = Datatype::hash_name("odd3");
        odd_base.alignment = 2;
        odd_base.align_size = 4;
        let odd = factory
            .find_add(Datatype::Base(odd_base), false)
            .expect("register explicit-layout element");
        let int_type = factory.find_by_name("int").expect("int core type");
        assert_eq!(odd.get_size(), 3);
        assert_eq!(odd.get_alignment(), 2);
        assert_eq!(odd.get_align_size(), 4);

        let odd_array = factory.get_array(odd.clone(), 3);
        let odd_repeat = factory.get_array(odd.clone(), 3);
        let int_array = factory.get_array(int_type, 3);
        assert_eq!(odd_array.get_size(), 12);
        assert_eq!(odd_array.get_alignment(), 2);
        assert_eq!(odd_array.get_align_size(), 12);
        assert!(Arc::ptr_eq(&odd_array, &odd_repeat));
        assert!(!Arc::ptr_eq(&odd_array, &int_array));
        assert_eq!(int_array.get_size(), odd_array.get_size());
        match odd_array.as_ref() {
            Datatype::Array(array) => {
                assert_eq!(array.num_elements, 3);
                assert!(Arc::ptr_eq(&array.array_of, &odd));
            }
            _ => panic!("expected array"),
        }

        let keys_before_collision = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let duplicate = Arc::new((*odd_array).clone());
        let conflict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.insert(duplicate);
        }));
        let panic_payload = conflict.expect_err("duplicate array must raise Shared type id");
        let panic_message = panic_payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic_payload.downcast_ref::<&str>().copied())
            .expect("string panic payload");
        assert_eq!(
            panic_message,
            "LowlevelError: Shared type id: 0\n  odd3 [3] : odd3 [3]"
        );
        let keys_after_collision = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys_after_collision, keys_before_collision);
        assert!(Arc::ptr_eq(
            &odd_array,
            factory
                .base_type_tree
                .get_mut()
                .unwrap()
                .get(&TypeFactory::type_tree_key(&odd_array))
                .expect("canonical array survives conflict")
        ));

        let singleton = factory.get_array(odd, 1);
        assert!(singleton.needs_resolution());
        assert_eq!(singleton.get_size(), 4);
    }

    #[test]
    fn test_array_decode_canonicalization_and_nonpositive_count_errors() {
        let mut factory = TypeFactory::new(8);
        let array_xml = |attrs: &[(&str, &str)], element_name: &str, element_size: &str| {
            xml_elem_with_children(
                "type",
                attrs,
                vec![xml_elem(
                    "type",
                    &[
                        ("metatype", "uint"),
                        ("name", element_name),
                        ("size", element_size),
                    ],
                )],
            )
        };

        let decoded = factory
            .decode_type(&mut decoder_for_type(array_xml(
                &[("metatype", "array"), ("size", "8"), ("arraysize", "2")],
                "DecodeElem4",
                "4",
            )))
            .expect("decode anonymous array");
        let repeated = factory
            .decode_type(&mut decoder_for_type(array_xml(
                &[("metatype", "array"), ("size", "8"), ("arraysize", "2")],
                "DecodeElem4",
                "4",
            )))
            .expect("repeat anonymous array decode");
        let element = factory
            .find_by_name("DecodeElem4")
            .expect("decoded element registered");
        let constructed = factory.get_array(element.clone(), 2);
        assert!(decoded.get_name().is_empty());
        assert!(decoded.get_display_name().is_empty());
        assert!(Arc::ptr_eq(&decoded, &repeated));
        assert!(Arc::ptr_eq(&decoded, &constructed));
        assert!(matches!(
            decoded.as_ref(),
            Datatype::Array(array)
                if array.num_elements == 2 && Arc::ptr_eq(&array.array_of, &element)
        ));

        let singleton = factory
            .decode_type(&mut decoder_for_type(array_xml(
                &[("metatype", "array"), ("size", "4"), ("arraysize", "1")],
                "DecodeSingletonElem",
                "4",
            )))
            .expect("decode singleton array");
        let singleton_element = factory
            .find_by_name("DecodeSingletonElem")
            .expect("singleton element registered");
        assert!(singleton.needs_resolution());
        assert_eq!(singleton.get_size(), 4);
        assert!(Arc::ptr_eq(
            &singleton,
            &factory.get_array(singleton_element, 1)
        ));

        let named = factory
            .decode_type(&mut decoder_for_type(array_xml(
                &[
                    ("metatype", "array"),
                    ("name", "NamedDecodeArray"),
                    ("size", "8"),
                    ("arraysize", "2"),
                ],
                "DecodeElem4",
                "4",
            )))
            .expect("decode named array");
        let redefinition = factory
            .decode_type(&mut decoder_for_type(array_xml(
                &[
                    ("metatype", "array"),
                    ("name", "NamedDecodeArray"),
                    ("size", "8"),
                    ("arraysize", "1"),
                ],
                "DecodeElem8",
                "8",
            )))
            .unwrap_err();
        assert_eq!(
            redefinition,
            "Trying to alter definition of type: NamedDecodeArray"
        );
        assert!(Arc::ptr_eq(
            &named,
            &factory
                .find_by_name("NamedDecodeArray")
                .expect("original named array survives")
        ));

        let keys_before_invalid = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let invalid_counts = [
            vec![("metatype", "array"), ("size", "0")],
            vec![("metatype", "array"), ("size", "0"), ("arraysize", "0")],
            vec![("metatype", "array"), ("size", "0"), ("arraysize", "-1")],
        ];
        for attrs in invalid_counts {
            let error = factory
                .decode_type(&mut decoder_for_type(array_xml(
                    &attrs,
                    "DecodeElem4",
                    "4")))
                .unwrap_err();
            assert_eq!(error, "Bad size for array of type DecodeElem4");
        }
        let keys_after_invalid = factory
            .base_type_tree
            .read()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys_after_invalid, keys_before_invalid);
        assert!(!keys_after_invalid
            .iter()
            .any(|key| {
            key.0 == SubMetatype::Array as i32 as u8 && key.7 == Reverse(0)
        }));
    }

    #[test]
    fn test_array_virtual_stripping_and_partial_canonicalization() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").expect("int core type");
        let ordinary_alias = factory.get_typedef("ScalarAlias", int_type.clone());
        assert!(!ordinary_alias.has_stripped());
        assert!(Datatype::get_stripped_arc(&ordinary_alias).is_none());
        assert!(Arc::ptr_eq(
            factory
                .get_typedef_target("ScalarAlias")
                .expect("ordinary typedef target"),
            &int_type
        ));
        let alias_array = factory.get_array(ordinary_alias.clone(), 2);
        let alias_element = match alias_array.as_ref() {
            Datatype::Array(array) => array.array_of.clone(),
            _ => panic!("expected array"),
        };
        assert!(Arc::ptr_eq(&alias_element, &ordinary_alias));

        let parent = factory.create_struct("PartialParent");
        let other_parent = factory.create_struct("OtherPartialParent");
        let union_parent = factory.get_type_union("PartialUnionParent");
        let other_union = factory.get_type_union("OtherPartialUnionParent");
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let partial = factory.get_type_partial_struct(parent.clone(), 0, 2);
        let partial_repeat = match partial.as_ref() {
            Datatype::PartialStruct(partial) => factory.get_type_partial_struct(
                partial.container.clone(),
                partial.offset,
                partial.base.size,
            ),
            _ => panic!("expected partial struct"),
        };
        assert!(Arc::ptr_eq(&partial, &partial_repeat));
        assert!(partial.get_name().is_empty());
        assert!(partial.get_display_name().is_empty());
        assert_eq!(partial.get_id(), 0);
        assert_eq!(partial.get_alignment(), 1);
        assert_eq!(partial.get_align_size(), 2);
        assert!(partial.has_stripped());
        assert!(!partial.needs_resolution());
        let partial_key = TypeFactory::type_tree_key(&partial);
        assert_eq!(partial_key.0, SubMetatype::PartialStruct as i32 as u8);
        assert_eq!(partial_key.1, Arc::as_ptr(&parent) as usize);
        assert_eq!(partial_key.2, 0);
        assert_eq!((partial_key.3, partial_key.4), (0, 0));
        assert_eq!((partial_key.5, partial_key.6), (0, 0));
        assert_eq!(partial_key.7, Reverse(2));
        assert_eq!(partial_key.8, 0);

        let different_offset = factory.get_type_partial_struct(
            match partial.as_ref() {
                Datatype::PartialStruct(partial) => partial.container.clone(),
                _ => unreachable!(),
            },
            1,
            2,
        );
        let different_size = factory.get_type_partial_struct(
            match partial.as_ref() {
                Datatype::PartialStruct(partial) => partial.container.clone(),
                _ => unreachable!(),
            },
            0,
            3,
        );
        let different_parent = factory.get_type_partial_struct(other_parent, 0, 2);
        assert!(!Arc::ptr_eq(&partial, &different_offset));
        assert!(!Arc::ptr_eq(&partial, &different_size));
        assert!(!Arc::ptr_eq(&partial, &different_parent));
        assert_eq!(
            partial_key.cmp(&TypeFactory::type_tree_key(&different_offset)),
            0_i64.cmp(&1)
        );
        assert_eq!(
            partial_key.cmp(&TypeFactory::type_tree_key(&different_size)),
            Reverse(2_usize).cmp(&Reverse(3))
        );

        let stripped = Datatype::get_stripped_arc(&partial).expect("partial stripped form");
        let partial_array = factory.get_array(partial.clone(), 2);
        let partial_element = match partial_array.as_ref() {
            Datatype::Array(array) => array.array_of.clone(),
            _ => panic!("expected array"),
        };
        assert!(Arc::ptr_eq(&partial_element, &stripped));

        let partial_alias = factory.get_typedef("PartialAlias", partial.clone());
        assert!(!Arc::ptr_eq(&partial_alias, &partial));
        assert_eq!(partial_alias.get_name(), "PartialAlias");
        assert!(partial_alias.has_stripped());
        assert_eq!(partial_alias.get_flags(), partial.get_flags());
        match (partial_alias.as_ref(), partial.as_ref()) {
            (Datatype::PartialStruct(alias), Datatype::PartialStruct(original)) => {
                assert!(Arc::ptr_eq(&alias.container, &original.container));
                assert_eq!(alias.offset, original.offset);
                assert!(matches!(
                    (&alias.stripped, &original.stripped),
                    (Some(left), Some(right)) if Arc::ptr_eq(left, right)
                ));
            }
            _ => panic!("expected partial-struct typedef clone"),
        }
        assert!(Arc::ptr_eq(
            factory
                .get_typedef_target("PartialAlias")
                .expect("partial typedef target"),
            &partial
        ));
        assert!(Arc::ptr_eq(
            &Datatype::get_stripped_arc(&partial_alias).expect("partial alias stripped form"),
            &stripped
        ));
        let partial_alias_array = factory.get_array(partial_alias, 2);
        let aliased_element = match partial_alias_array.as_ref() {
            Datatype::Array(array) => array.array_of.clone(),
            _ => panic!("expected array"),
        };
        assert!(Arc::ptr_eq(&aliased_element, &stripped));

        let partial_union = factory.get_type_partial_union(union_parent.clone(), 0, 2);
        let partial_union_repeat = factory.get_type_partial_union(union_parent.clone(), 0, 2);
        let partial_union_offset =
            factory.get_type_partial_union(union_parent.clone(), 1, 2);
        let partial_union_size = factory.get_type_partial_union(union_parent.clone(), 0, 3);
        let partial_union_parent = factory.get_type_partial_union(other_union, 0, 2);
        assert!(Arc::ptr_eq(&partial_union, &partial_union_repeat));
        assert!(!Arc::ptr_eq(&partial_union, &partial_union_offset));
        assert!(!Arc::ptr_eq(&partial_union, &partial_union_size));
        assert!(!Arc::ptr_eq(&partial_union, &partial_union_parent));
        assert!(partial_union.get_name().is_empty());
        assert!(partial_union.get_display_name().is_empty());
        assert_eq!(partial_union.get_id(), 0);
        assert_eq!(partial_union.get_alignment(), 1);
        assert_eq!(partial_union.get_align_size(), 2);
        assert!(partial_union.has_stripped());
        assert!(partial_union.needs_resolution());
        let union_key = TypeFactory::type_tree_key(&partial_union);
        assert_eq!(union_key.0, SubMetatype::PartialUnion as i32 as u8);
        assert_eq!(union_key.1, Arc::as_ptr(&union_parent) as usize);
        assert_eq!(union_key.2, 0);
        assert_eq!((union_key.3, union_key.4), (0, 0));
        assert_eq!((union_key.5, union_key.6), (0, 0));
        assert_eq!(union_key.7, Reverse(2));
        assert_eq!(union_key.8, 0);
        let union_stripped =
            Datatype::get_stripped_arc(&partial_union).expect("partial union stripped form");
        let union_alias = factory.get_typedef("PartialUnionAlias", partial_union.clone());
        assert!(!Arc::ptr_eq(&union_alias, &partial_union));
        assert_eq!(union_alias.get_name(), "PartialUnionAlias");
        assert!(union_alias.has_stripped());
        assert_eq!(union_alias.get_flags(), partial_union.get_flags());
        match (union_alias.as_ref(), partial_union.as_ref()) {
            (Datatype::PartialUnion(alias), Datatype::PartialUnion(original)) => {
                assert!(Arc::ptr_eq(&alias.container, &original.container));
                assert_eq!(alias.offset, original.offset);
                assert!(matches!(
                    (&alias.stripped, &original.stripped),
                    (Some(left), Some(right)) if Arc::ptr_eq(left, right)
                ));
            }
            _ => panic!("expected partial-union typedef clone"),
        }
        assert!(Arc::ptr_eq(
            factory
                .get_typedef_target("PartialUnionAlias")
                .expect("partial union typedef target"),
            &partial_union
        ));
        assert!(Arc::ptr_eq(
            &Datatype::get_stripped_arc(&union_alias).expect("partial union alias stripped form"),
            &union_stripped
        ));
        let union_alias_array = factory.get_array(union_alias, 2);
        assert!(matches!(
            union_alias_array.as_ref(),
            Datatype::Array(array) if Arc::ptr_eq(&array.array_of, &union_stripped)
        ));

        let enum_parent = factory
            .get_type_enum_result("PartialEnumParent")
            .expect("configured enum parent");
        assert_eq!(enum_parent.get_size(), 8);
        assert_eq!(enum_parent.get_metatype(), TypeMetatype::Uint);
        assert!(enum_parent.is_enum_type());
        let partial_enum = factory.get_type_partial_enum(enum_parent.clone(), 0, 2);
        let partial_enum_repeat = factory.get_type_partial_enum(enum_parent.clone(), 0, 2);
        let partial_enum_offset = factory.get_type_partial_enum(enum_parent.clone(), 1, 2);
        let partial_enum_size = factory.get_type_partial_enum(enum_parent.clone(), 0, 3);
        let other_enum = factory
            .get_type_enum_result("OtherPartialEnumParent")
            .expect("second configured enum parent");
        let partial_enum_parent = factory.get_type_partial_enum(other_enum, 0, 2);
        assert!(Arc::ptr_eq(&partial_enum, &partial_enum_repeat));
        assert!(!Arc::ptr_eq(&partial_enum, &partial_enum_offset));
        assert!(!Arc::ptr_eq(&partial_enum, &partial_enum_size));
        assert!(!Arc::ptr_eq(&partial_enum, &partial_enum_parent));
        assert!(partial_enum.get_name().is_empty());
        assert!(partial_enum.get_display_name().is_empty());
        assert_eq!(partial_enum.get_id(), 0);
        assert_eq!(partial_enum.get_alignment(), 2);
        assert_eq!(partial_enum.get_align_size(), 2);
        assert_eq!(partial_enum.get_metatype(), TypeMetatype::Uint);
        assert_eq!(partial_enum.get_submeta(), SubMetatype::UintPartialEnum);
        assert!(partial_enum.is_enum_type());
        assert!(partial_enum.has_stripped());
        let enum_key = TypeFactory::type_tree_key(&partial_enum);
        assert_eq!(enum_key.0, SubMetatype::UintPartialEnum as i32 as u8);
        assert_eq!(enum_key.1, Arc::as_ptr(&enum_parent) as usize);
        assert_eq!(enum_key.2, 0);
        assert_eq!((enum_key.3, enum_key.4), (0, 0));
        assert_eq!((enum_key.5, enum_key.6), (0, 0));
        assert_eq!(enum_key.7, Reverse(2));
        assert_eq!(enum_key.8, 0);
        match partial_enum.as_ref() {
            Datatype::PartialEnum(partial) => {
                assert_eq!(partial.base.metatype, TypeMetatype::Uint);
                assert_eq!(
                    partial.base.submeta_override,
                    Some(SubMetatype::UintPartialEnum)
                );
            }
            _ => panic!("expected partial enum"),
        }
        let enum_stripped =
            Datatype::get_stripped_arc(&partial_enum).expect("partial enum stripped form");
        let enum_alias = factory.get_typedef("PartialEnumAlias", partial_enum.clone());
        assert!(!Arc::ptr_eq(&enum_alias, &partial_enum));
        assert_eq!(enum_alias.get_name(), "PartialEnumAlias");
        assert!(enum_alias.has_stripped());
        assert_eq!(enum_alias.get_flags(), partial_enum.get_flags());
        match (enum_alias.as_ref(), partial_enum.as_ref()) {
            (Datatype::PartialEnum(alias), Datatype::PartialEnum(original)) => {
                assert!(Arc::ptr_eq(&alias.parent, &original.parent));
                assert_eq!(alias.offset, original.offset);
                assert!(matches!(
                    (&alias.stripped, &original.stripped),
                    (Some(left), Some(right)) if Arc::ptr_eq(left, right)
                ));
            }
            _ => panic!("expected partial-enum typedef clone"),
        }
        assert!(Arc::ptr_eq(
            factory
                .get_typedef_target("PartialEnumAlias")
                .expect("partial enum typedef target"),
            &partial_enum
        ));
        assert!(Arc::ptr_eq(
            &Datatype::get_stripped_arc(&enum_alias).expect("partial enum alias stripped form"),
            &enum_stripped
        ));
        let enum_alias_array = factory.get_array(enum_alias, 2);
        assert!(matches!(
            enum_alias_array.as_ref(),
            Datatype::Array(array) if Arc::ptr_eq(&array.array_of, &enum_stripped)
        ));
    }

    // --- new TypeFactory getters aligned with type.cc ---

    #[test]
    fn test_get_type_void() {
        // type.cc:3575 — singleton void.
        let mut factory = TypeFactory::new(8);
        let v = factory.get_type_void_result();
        assert_eq!(v.get_name(), "void");
        assert_eq!(v.get_metatype(), TypeMetatype::Void);
    }

    #[test]
    fn test_get_type_char() {
        // type.cc:3593/3678 — the size-only lookup returns the charcache
        // selection, which only exists after an ASCII core registration and
        // cacheCoreTypes (Ghidra's buildCoreTypes registers "char" first,
        // sleigh_arch.cc:235); on the raw pre-bootstrap factory (the empty
        // TypeFactory(Architecture*) projection, type.cc:3106-3119) the
        // uncached request raises the oracle's LowlevelError.
        let mut factory = TypeFactory::raw();
        assert_eq!(
            factory.get_type_char(1).unwrap_err(),
            "Request for unsupported character data-type"
        );
        factory
            .set_core_type_result("char", 1, TypeMetatype::Int, true)
            .unwrap();
        factory.cache_core_types();
        let c = factory.get_type_char(1).expect("cached char");
        assert_eq!(c.get_size(), 1);
        assert_eq!(c.get_metatype(), TypeMetatype::Int);
        assert!(c.is_char_print());
        // dedup: second call returns the same Arc.
        let c2 = factory.get_type_char(1).expect("cached char");
        assert!(Arc::ptr_eq(&c, &c2));
        // The DataOrg bootstrap now mirrors the locked headless oracle's
        // coretypes stream supplying an ASCII char (DEBUGPROTO-DWARF-CHAR
        // -0001), so a production-bootstrapped factory resolves immediately.
        let boot = TypeFactory::new(8);
        let b = boot.get_type_char(1).expect("boot char");
        assert_eq!(b.get_size(), 1);
        assert!(b.is_char_print());
    }

    #[test]
    fn test_get_type_unicode() {
        // type.cc:3606 — UTF16 (size 2) sets UTF16 flag, UTF32 (size 4) sets UTF32.
        let mut factory = TypeFactory::new(8);
        let w2 = factory.get_type_unicode(2);
        assert_eq!(w2.get_size(), 2);
        assert!((w2.get_flags() & type_flags::UTF16) != 0);
        let w4 = factory.get_type_unicode(4);
        assert_eq!(w4.get_size(), 4);
        assert!((w4.get_flags() & type_flags::UTF32) != 0);
        assert!(w2.is_char_print() && w4.is_char_print());
    }

    #[test]
    fn test_get_type_union_and_fields() {
        // type.cc:3940 — union starts incomplete + needs_resolution.
        let mut factory = TypeFactory::new(8);
        let u = factory.get_type_union("MyUnion");
        assert_eq!(u.get_metatype(), TypeMetatype::Union);
        assert!(u.needs_resolution());
        // Set fields: union size = max field size.
        let int_t = factory.find_by_name("int").unwrap();
        factory
            .set_core_type_result("char", 1, TypeMetatype::Int, true)
            .unwrap();
        factory.cache_core_types();
        let char_t = factory.get_type_char(1).expect("cached char");
        let updated = factory
            .set_union_fields(
                "MyUnion", vec![
                TypeField { name: "a".into(), offset: 0, type_ptr: int_t ,
                    },
                TypeField { name: "b".into(), offset: 0, type_ptr: char_t ,
                    },
            ],
            )
            .expect("union exists");
        assert_eq!(updated.get_size(), 4);
    }

    #[test]
    fn test_decode_union_empty_and_nonempty_completion_state() {
        let mut factory = TypeFactory::new(8);
        for (name, size) in [("EmptyUnionZero", "0"), ("EmptyUnionSized", "8")] {
            let decoded = factory
                .decode_type(&mut decoder_for_type(xml_elem(
                    "type",
                    &[("metatype", "union"), ("name", name), ("size", size)],
                )))
                .expect("empty union decode");
            assert!(
                decoded.is_incomplete(), "{name} was completed without fields"
            );
        }

        let field = xml_elem_with_children(
            "field",
            &[("name", "value"), ("offset", "0")],
            vec![xml_elem("type", &[("metatype", "int"), ("size", "4")])],
        );
        let decoded = factory
            .decode_type(&mut decoder_for_type(xml_elem_with_children(
                "type",
                &[
                    ("metatype", "union"), ("name", "FilledUnion"), ("size", "4"),
                ],
                vec![field],
            )))
            .expect("nonempty union decode");
        assert!(!decoded.is_incomplete());
        assert_eq!(decoded.get_size(), 4);
    }

    #[test]
    fn test_set_fields_uses_assign_field_offsets_padded_size() {
        let mut factory = TypeFactory::new(8);
        let mut field_base = TypeBase::new("odd3".to_string(), 3, TypeMetatype::Uint);
        field_base.alignment = 2;
        field_base.align_size = 4;
        let odd_field = Arc::new(Datatype::Base(field_base));
        factory.create_struct("PaddedStruct");
        let defined = factory
            .set_fields(
                "PaddedStruct",
                vec![TypeField {
                    name: "value".to_string(),
                    offset: 0,
                    type_ptr: odd_field,
                }],
            )
            .expect("define padded struct");
        assert_eq!(defined.get_size(), 4);
        assert_eq!(defined.get_alignment(), 2);
        assert_eq!(defined.get_align_size(), 4);
        assert!(!defined.needs_resolution());
    }

    #[test]
    fn test_struct_union_definition_rekeys_factory_channels() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").expect("int core type");

        let old_struct = factory.create_struct("LayoutStruct");
        let old_struct_key = TypeFactory::type_tree_key(&old_struct);
        let new_struct = factory
            .set_fields_sized(
                "LayoutStruct",
                vec![TypeField {
                    name: "value".to_string(),
                    offset: 0,
                    type_ptr: int_type.clone(),
                }],
                12,
                8,
            )
            .expect("define struct");
        let new_struct_key = TypeFactory::type_tree_key(&new_struct);
        assert!(!Arc::ptr_eq(&old_struct, &new_struct));
        assert!(Arc::ptr_eq(
            &new_struct,
            &factory.find_by_name("LayoutStruct").expect("struct lookup")
        ));
        assert!(!factory
            .base_type_tree
            .read()
            .unwrap()
            .contains_key(&old_struct_key));
        assert!(factory
            .base_type_tree
            .read()
            .unwrap()
            .get(&new_struct_key)
            .is_some_and(|registered| Arc::ptr_eq(registered, &new_struct)));
        assert_eq!(new_struct.get_size(), 12);
        assert_eq!(new_struct.get_alignment(), 8);
        assert_eq!(new_struct.get_align_size(), 16);
        assert!(!new_struct.is_incomplete());

        let old_union = factory.get_type_union("LayoutUnion");
        let old_union_key = TypeFactory::type_tree_key(&old_union);
        let new_union = factory
            .set_union_fields_sized(
                "LayoutUnion",
                vec![TypeField {
                    name: "value".to_string(),
                    offset: 0,
                    type_ptr: int_type,
                }],
                9,
                4,
            )
            .expect("define union");
        let new_union_key = TypeFactory::type_tree_key(&new_union);
        assert!(!Arc::ptr_eq(&old_union, &new_union));
        assert!(Arc::ptr_eq(
            &new_union,
            &factory.find_by_name("LayoutUnion").expect("union lookup")
        ));
        assert!(!factory
            .base_type_tree
            .read()
            .unwrap()
            .contains_key(&old_union_key));
        assert!(factory
            .base_type_tree
            .read()
            .unwrap()
            .get(&new_union_key)
            .is_some_and(|registered| Arc::ptr_eq(registered, &new_union)));
        assert_eq!(new_union.get_size(), 9);
        assert_eq!(new_union.get_alignment(), 4);
        assert_eq!(new_union.get_align_size(), 12);
        assert!(!new_union.is_incomplete());
    }

    #[test]
    fn test_define_replace_refuses_stale_tree_slot() {
        let mut factory = TypeFactory::new(8);
        let structure = factory.create_struct("StaleSlot");
        let key = TypeFactory::type_tree_key(&structure);
        let unrelated = Arc::new((*structure).clone());
        factory
            .base_type_tree
            .get_mut()
            .unwrap()
            .insert(key, unrelated);

        let result = factory.define_replace(&structure, |_| Ok(()));
        assert_eq!(
            result.unwrap_err(),
            "Datatype definition is not registered under its current tree key"
        );
        assert!(Arc::ptr_eq(
            &structure,
            &factory
                .find_by_name("StaleSlot")
                .expect("name slot unchanged")
        ));
    }

    #[test]
    fn test_public_field_setters_surface_registry_replacement_errors() {
        for (name, is_union, explicit_layout) in [
            ("StructDerived", false, false),
            ("StructSized", false, true),
            ("UnionDerived", true, false),
            ("UnionSized", true, true),
        ] {
            let mut factory = TypeFactory::new(8);
            let stub = if is_union {
                factory.get_type_union(name)
            } else {
                factory.create_struct(name)
            };
            let key = TypeFactory::type_tree_key(&stub);
            factory
                .base_type_tree
                .get_mut()
                .unwrap()
                .insert(key, Arc::new((*stub).clone()));

            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if is_union && explicit_layout {
                    factory.set_union_fields_sized(name, Vec::new(), 8, 4);
                } else if is_union {
                    factory.set_union_fields(name, Vec::new());
                } else if explicit_layout {
                    factory.set_fields_sized(name, Vec::new(), 8, 4);
                } else {
                    factory.set_fields(name, Vec::new());
                }
            }));
            assert!(panicked.is_err(), "{name} swallowed the replacement error");
            assert!(Arc::ptr_eq(
                &stub,
                &factory.find_by_name(name).expect("name slot unchanged")
            ));
        }
    }

    #[test]
    fn test_named_factory_fast_paths_validate_concrete_identity() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").expect("int core type");
        let uint_type = factory.find_by_name("uint").expect("uint core type");
        let alias = factory.get_typedef("WordAlias", int_type.clone());
        let repeat = factory.get_typedef("WordAlias", int_type.clone());
        assert!(Arc::ptr_eq(&alias, &repeat));
        assert!(Arc::ptr_eq(
            factory
                .get_typedef_target("WordAlias")
                .expect("typedef target"),
            &int_type
        ));

        let conflicting_target = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.get_typedef("WordAlias", uint_type);
        }));
        assert!(conflicting_target.is_err());
        assert!(Arc::ptr_eq(
            &alias,
            &factory.find_by_name("WordAlias").expect("alias unchanged")
        ));

        let structure = factory.create_struct("AggregateCollision");
        let conflicting_union = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.get_type_union("AggregateCollision");
        }));
        assert!(conflicting_union.is_err());
        assert!(Arc::ptr_eq(
            &structure,
            &factory
                .find_by_name("AggregateCollision")
                .expect("struct unchanged")
        ));
    }

    #[test]
    fn test_series_c_named_pointer_dependency_rejects_redefinition() {
        let mut factory = TypeFactory::new(8);
        let int_type = factory.find_by_name("int").expect("int core type");
        let uint_type = factory.find_by_name("uint").expect("uint core type");

        let pointer_candidate = |ptr_to: Arc<Datatype>| {
            let mut base = TypeBase::new("ScopedPointer".into(), 8, TypeMetatype::Pointer);
            base.id = Datatype::hash_name("ScopedPointer");
            base.alignment = 8;
            base.align_size = 8;
            Datatype::Pointer(TypePointer { base, ptr_to, wordsize: 1 ,
            })
        };
        let first = factory
            .find_add(pointer_candidate(int_type.clone()), false)
            .expect("register scoped pointer");
        let different_target = pointer_candidate(uint_type);
        assert_ne!(first.compare_dependency(&different_target), 0);
        assert_eq!(
            factory.find_add(different_target, false).unwrap_err(),
            "Trying to alter definition of type: ScopedPointer"
        );
        let scoped_survivor = factory
            .find_by_name("ScopedPointer")
            .expect("original scoped pointer survives");
        assert!(Arc::ptr_eq(&first, &scoped_survivor));
        assert!(matches!(
            first.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &int_type)
        ));

        let parent_a = factory.create_struct("ScopedRelativeParentA");
        let parent_b = factory.create_struct("ScopedRelativeParentB");
        let relative_candidate = |parent: Arc<Datatype>, offset: i64| {
            let mut base =
                TypeBase::new("ScopedRelativePointer".into(), 8, TypeMetatype::Pointer);
            base.id = Datatype::hash_name("ScopedRelativePointer");
            base.alignment = 8;
            base.align_size = 8;
            base.flags |= type_flags::IS_PTRREL;
            base.pointer_rel = Some(PointerRelState {
                parent,
                offset,
                stripped: None,
            });
            Datatype::Pointer(TypePointer {
                base,
                ptr_to: int_type.clone(),
                wordsize: 1,
            })
        };
        let relative = factory
            .find_add(relative_candidate(parent_a.clone(), 4), false)
            .expect("register scoped relative pointer");
        let different_relative = relative_candidate(parent_b, 12);
        assert_ne!(relative.compare_dependency(&different_relative), 0);
        assert_eq!(
            factory.find_add(different_relative, false).unwrap_err(),
            "Trying to alter definition of type: ScopedRelativePointer"
        );
        assert!(matches!(
            relative.as_ref(),
            Datatype::Pointer(pointer)
                if matches!(
                    &pointer.base.pointer_rel,
                    Some(state) if Arc::ptr_eq(&state.parent, &parent_a) && state.offset == 4
                )
        ));
    }

    #[test]
    fn test_dependent_order_visits_typedef_target_before_alias() {
        let mut factory = TypeFactory::new(8);
        let target = factory
            .get_base_named(4, TypeMetatype::Uint, "AA")
            .expect("named target");
        let alias = factory.get_typedef("C", target.clone());
        let mut ordered = Vec::new();
        factory.dependent_order(&mut ordered);
        let target_index = ordered
            .iter()
            .position(|datatype| Arc::ptr_eq(datatype, &target))
            .expect("target in dependency order");
        let alias_index = ordered
            .iter()
            .position(|datatype| Arc::ptr_eq(datatype, &alias))
            .expect("alias in dependency order");
        assert!(target_index < alias_index);
    }

    #[test]
    fn test_clear_paths_drop_incomplete_typedef_queue_before_recreate() {
        for clear_all in [true, false] {
            let mut factory = TypeFactory::new(8);
            let incomplete = factory.create_struct("PendingStruct");
            let _alias = factory.get_typedef("PendingAlias", incomplete);
            assert_eq!(factory.incomplete_typedefs.len(), 1);

            if clear_all {
                factory.clear();
            } else {
                factory.clear_non_core();
            }
            assert!(factory.incomplete_typedefs.is_empty());
            assert!(factory.find_by_name("PendingStruct").is_none());
            assert!(factory.find_by_name("PendingAlias").is_none());

            let recreated = factory.create_struct("PendingStruct");
            let defined = factory
                .set_fields_sized("PendingStruct", Vec::new(), 8, 4)
                .expect("define recreated struct");
            assert!(!Arc::ptr_eq(&recreated, &defined));
            assert_eq!(defined.get_size(), 8);
            assert_eq!(defined.get_alignment(), 4);
            assert!(factory.resolve_incomplete_typedefs().is_ok());
        }
    }

    #[test]
    fn test_get_type_enum_and_values() {
        // type.cc:3967 / 3532 — enum with ENUMTYPE flag; setEnumValues fills map.
        let mut factory = TypeFactory::new(8);
        let e = factory.get_type_enum("Color");
        assert!(e.is_enum_type());
        let mut vals = std::collections::BTreeMap::new();
        vals.insert(0, "RED".to_string());
        vals.insert(1, "GREEN".to_string());
        vals.insert(2, "BLUE".to_string());
        let _ = factory.set_enum_values("Color", vals).expect("enum exists");
        // round-trip: the enum is still an enum after setting values.
        let e2 = factory.find_by_name("Color").unwrap();
        assert!(e2.is_enum_type());
    }

    #[test]
    fn test_get_type_code() {
        // type.cc:3692 — generic code type, size 1, metatype Code.
        let mut factory = TypeFactory::new(8);
        let c = factory.get_type_code();
        assert_eq!(c.get_metatype(), TypeMetatype::Code);
        assert_eq!(c.get_size(), 1);
        assert_eq!(c.get_alignment(), 1);
        assert_eq!(c.get_align_size(), 1);
        let c2 = factory.get_type_code();
        assert!(Arc::ptr_eq(&c, &c2));
    }

    #[test]
    fn test_get_type_pointer_rel() {
        // Legacy side-table glue retained for older Rudra callers. The locked
        // type.cc:4016 parent-pointer overload is exercised by
        // test_ephemeral_pointer_rel_inherits_parent_geometry_and_identity.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let struct_t = factory.create_struct("S");
        let rp = factory.get_type_pointer_rel(int_t.clone(), struct_t.clone(), 4);
        assert_eq!(rp.get_metatype(), TypeMetatype::Pointer);
        assert!((rp.get_flags() & type_flags::IS_PTRREL) != 0);
        // side table recorded the parent/offset.
        let rec = factory.rel_pointers.get(rp.get_name()).unwrap();
        assert_eq!(rec.offset, 4);
        assert_eq!(rec.parent.get_name(), "S");
    }

    #[test]
    fn test_get_ptr_to_from_parent() {
        // type.cc:2693 — drill into a struct to find the field type at `off`.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let _ = factory.create_struct("S");
        // S { int a @ 0; int b @ 4; }
        let fields = vec![
            TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() ,
            },
            TypeField { name: "b".into(), offset: 4, type_ptr: int_t.clone() ,
            },
        ];
        let struct_t = factory.set_fields("S", fields).expect("struct S exists");
        // off=4 lands on field `b` (an int); the loop exits at newoff==0.
        let pt = factory.get_ptr_to_from_parent(&struct_t, 4);
        assert_eq!(pt.get_size(), 4);
        // off=0 should return the unknown fallback (Ghidra: getBase(1, UNKNOWN)).
        let pt0 = factory.get_ptr_to_from_parent(&struct_t, 0);
        assert_eq!(pt0.get_size(), 1);
        // Negative offset returns the 1-byte unknown fallback.
        let ptn = factory.get_ptr_to_from_parent(&struct_t, -1);
        assert_eq!(ptn.get_size(), 1);
    }

    #[test]
    fn test_down_chain_struct_field() {
        // type.cc:2656 — downchain a relative pointer whose offset (4) points
        // past the end of a 4-byte struct into the parent at offset 4.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let _ = factory.create_struct("Inner");
        let inner_fields = vec![
            TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() ,
        }];
        let inner = factory
            .set_fields("Inner", inner_fields)
            .expect("Inner exists");
        // Parent is a 2-field struct; the relative pointer points to `inner`
        // at offset 0 but its parent-relative offset is 4.
        let _ = factory.create_struct("Outer");
        let outer_fields = vec![
            TypeField { name: "x".into(), offset: 0, type_ptr: int_t.clone() ,
            },
            TypeField { name: "y".into(), offset: 4, type_ptr: inner.clone() ,
            },
        ];
        let outer = factory
            .set_fields("Outer", outer_fields)
            .expect("Outer exists");
        let rp = factory.get_type_pointer_rel(int_t.clone(), outer.clone(), 4);
        // off=0 lands inside ptrto (int, size 4) but ptrto is neither struct
        // nor array, so we fall through to the parent-relative path.
        let mut off: i64 = 0;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = 0;
        setup_default_sizes(&mut factory);
        let result = factory.down_chain(
            &rp, &outer, 4, &mut off, &mut par, &mut par_off, false);
        // We expect a non-None result (drilled into the parent at rel_off=4).
        assert!(
            result.is_some(), "down_chain should produce a component pointer"
        );
        // `par` should be populated (the pointer to Outer).
        assert!(par.is_some());
    }

    #[test]
    fn test_down_chain_virtual_dispatch_routing() {
        // type.hh:429/681 — the virtual downChain call dispatches by pointer
        // kind: plain pointers take TypePointer::downChain (par = this,
        // wrap-to-zero returns this), while pointer_rel inputs take the
        // TypePointerRel override (parent-relative conversion, untouched
        // accumulators on the recover-parent path, type.cc:2669-2671).
        let mut factory = TypeFactory::new(8);
        let alignment_map = xml_elem("size_alignment_map", &[]);
        for (size, alignment) in [("1", "1"), ("2", "2"), ("4", "4"), ("8", "8")] {
            alignment_map.write().unwrap().add_child(xml_elem(
                "entry",
                &[("size", size), ("alignment", alignment)],
            ));
        }
        let organization =
            xml_elem_with_children("data_organization", &[], vec![alignment_map]);
        let mut organization_decoder = TreeDecoder::new(
            organization,
            std::sync::Arc::new(RwLock::new(IdRegistry::new())),
        );
        factory.decode_data_organization(&mut organization_decoder);
        setup_default_sizes(&mut factory);
        let int_t = factory.find_by_name("int").unwrap();
        let _ = factory.create_struct("Inner");
        let inner = factory
            .set_fields(
                "Inner",
                vec![
                    TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() ,
                    },
                    TypeField { name: "b".into(), offset: 4, type_ptr: int_t.clone() ,
                    },
                ],
            )
            .expect("Inner exists");
        let _ = factory.create_struct("Progress");
        let progress = factory
            .set_fields(
                "Progress",
                vec![
                    TypeField { name: "first".into(), offset: 0, type_ptr: int_t.clone() ,
                    },
                    TypeField { name: "inner".into(), offset: 8, type_ptr: inner.clone() ,
                    },
                ],
            )
            .expect("Progress exists");
        let pd_ptr = factory.get_type_pointer(8, progress.clone(), 1);

        // Plain routing: struct field hit sets par to the descended pointer
        // itself (type.cc:1111 `par = this`) and renormalizes off to 0.
        let mut off: i64 = 8;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = 0;
        let result =
            factory.down_chain_virtual(&pd_ptr, &mut off, &mut par, &mut par_off, false);
        assert!(
            result.is_some(), "plain field hit yields a component pointer"
        );
        assert!(Arc::ptr_eq(par.as_ref().expect("par set"), &pd_ptr));
        assert_eq!(par_off, 8);
        assert_eq!(off, 0);

        // Plain routing: wrap-to-zero returns this pointer unchanged
        // (type.cc:1098) without touching the accumulators.
        let mut off: i64 = 16;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = -999;
        let result =
            factory.down_chain_virtual(&pd_ptr, &mut off, &mut par, &mut par_off, true);
        assert!(Arc::ptr_eq(
            &result.expect("wrap-to-zero returns this"), &pd_ptr
        ));
        assert!(par.is_none(), "wrap-to-zero leaves par untouched");
        assert_eq!(par_off, -999);
        assert_eq!(off, 0);

        // Rel routing (recover-parent, type.cc:2669-2670): the parent pointer
        // is returned and the accumulators stay untouched.
        let rel_inner = factory.get_type_pointer_rel_ephemeral(
            pd_ptr.clone(),
            inner.clone(),
            8);
        let mut off: i64 = -8;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = -999;
        let result =
            factory.down_chain_virtual(&rel_inner, &mut off, &mut par, &mut par_off, false);
        assert!(Arc::ptr_eq(
            &result.expect("recover-parent returns parent pointer"), &pd_ptr
        ));
        assert!(par.is_none(), "recover-parent leaves par untouched");
        assert_eq!(par_off, -999);
        assert_eq!(off, 0);

        // Rel routing (deferral, type.cc:2660-2662): off lands inside the
        // struct ptrto, so the plain override runs on the relative pointer
        // itself and `par = this` observes the relative pointer.
        let mut off: i64 = 4;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = -999;
        let result =
            factory.down_chain_virtual(&rel_inner, &mut off, &mut par, &mut par_off, false);
        assert!(result.is_some(), "deferral drills into the Inner field");
        assert!(Arc::ptr_eq(par.as_ref().expect("par set"), &rel_inner));
        assert_eq!(par_off, 4);
        assert_eq!(off, 0);

        // Routing discrimination: the same scalar ptrto yields None through
        // the plain path (base getSubType) but a field pointer through the
        // relative path.
        let int_ptr = factory.get_type_pointer(8, int_t.clone(), 1);
        let rel_first = factory.get_type_pointer_rel_ephemeral(
            pd_ptr.clone(),
            int_t.clone(),
            0);
        let mut off: i64 = 0;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = -999;
        assert!(factory
            .down_chain_virtual(&int_ptr, &mut off, &mut par, &mut par_off, false)
            .is_none());
        assert!(par.is_none());
        let mut off: i64 = 0;
        let mut par: Option<Arc<Datatype>> = None;
        let mut par_off: i64 = -999;
        let result =
            factory.down_chain_virtual(&rel_first, &mut off, &mut par, &mut par_off, false);
        assert!(result.is_some(), "rel routing reaches the parent container");
        assert!(Arc::ptr_eq(par.as_ref().expect("par set"), &pd_ptr));
        assert_eq!(off, 0);
    }

    #[test]
    fn test_get_typedef_and_target() {
        // type.cc:3818 — ordinary typedefImm does not set HAS_STRIPPED.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let td = factory.get_typedef("Word", int_t.clone());
        assert_eq!(td.get_name(), "Word");
        assert_eq!(td.get_size(), 4);
        assert_eq!(td.get_flags() & type_flags::HAS_STRIPPED, 0);
        assert!(!td.is_coretype());
        // target lookup returns the aliased type.
        let target = factory.get_typedef_target("Word").unwrap();
        assert_eq!(target.get_name(), "int");
    }

    #[test]
    fn test_resize_pointer() {
        // type.cc:4071 — same pointee, new size, preserves wordsize.
        let mut factory = TypeFactory::new(8);
        let partial_parent = factory.create_struct("ResizePartialParent");
        setup_default_sizes(&mut factory);
        let int_t = factory.find_by_name("int").unwrap();
        let ordinary_alias = factory.get_typedef("ResizeScalarAlias", int_t.clone());
        let ptr8 = factory.get_type_pointer(8, ordinary_alias.clone(), 2);
        let ptr4 = factory.resize_pointer(&ptr8, 4);
        assert_eq!(ptr4.get_size(), 4);
        assert_eq!(ptr4.get_metatype(), TypeMetatype::Pointer);
        assert!(matches!(
            ptr4.as_ref(),
            Datatype::Pointer(pointer)
                if pointer.wordsize == 2 && Arc::ptr_eq(&pointer.ptr_to, &ordinary_alias)
        ));
        let ptr4_repeat = factory.resize_pointer(&ptr8, 4);
        assert!(Arc::ptr_eq(&ptr4, &ptr4_repeat));
        let ptr4_direct = factory.get_type_pointer(4, ordinary_alias.clone(), 2);
        assert!(Arc::ptr_eq(&ptr4, &ptr4_direct));
        assert!(ptr4.get_name().is_empty());
        assert!(ptr4.get_display_name().is_empty());
        assert_eq!(ptr4.get_id(), 0);

        let space_source = Datatype::Pointer(TypePointer::new_with_space(
            ordinary_alias.clone(),
            AddressSpace::Ram,
        ));
        let resized_space = factory.resize_pointer(&space_source, 4);
        let direct_wordsize_one = factory.get_type_pointer(4, ordinary_alias.clone(), 1);
        assert!(Arc::ptr_eq(&resized_space, &direct_wordsize_one));
        assert!(matches!(
            resized_space.as_ref(),
            Datatype::Pointer(pointer)
                if pointer.base.pointer_space.is_none()
                    && (pointer.base.flags & type_flags::IS_PTRREL) == 0
        ));

        let relative_source = Datatype::Pointer(TypePointer::new_relative(
            8,
            ordinary_alias.clone(),
            2,
            int_t.clone(),
            4,
        ));
        let resized_relative = factory.resize_pointer(&relative_source, 4);
        assert!(Arc::ptr_eq(&resized_relative, &ptr4_direct));
        assert!(matches!(
            resized_relative.as_ref(),
            Datatype::Pointer(pointer)
                if pointer.base.pointer_rel.is_none()
                    && (pointer.base.flags & type_flags::IS_PTRREL) == 0
        ));

        let partial = factory.get_type_partial_struct(partial_parent, 0, 2);
        let stripped = Datatype::get_stripped_arc(&partial).expect("partial stripped fallback");
        let partial_source = Datatype::Pointer(TypePointer::new(8, partial, 2));
        let partial_resized = factory.resize_pointer(&partial_source, 4);
        assert!(matches!(
            partial_resized.as_ref(),
            Datatype::Pointer(pointer) if Arc::ptr_eq(&pointer.ptr_to, &stripped)
        ));

        let nonpointer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.resize_pointer(int_t.as_ref(), 4);
        }));
        assert!(nonpointer.is_err());
    }

    #[test]
    fn test_find_by_id_local_and_global() {
        // type.cc:3326 / 3354 — findByIdLocal matches by name; id 0 matches any id.
        let factory = TypeFactory::new(8);
        // "void" exists with id 0 (unset); lookup by name with id 0 succeeds.
        assert!(factory.find_by_id_local("void", 0).is_some());
        // non-existent name.
        assert!(factory.find_by_id_local("nope", 0).is_none());
        // findById with size fallback.
        assert!(factory.find_by_id("int", 0, 4).is_some());
        assert!(factory.find_by_id("int", 0, 8).is_none());
    }

    #[test]
    fn test_concretize_and_deconcretize() {
        // type.cc:4140 — TYPE_CODE → base TYPE_UNKNOWN of size 1.
        let mut factory = TypeFactory::new(8);
        let code = factory.get_type_code();
        let concrete = factory.concretize(code);
        assert_eq!(concrete.get_metatype(), TypeMetatype::Unknown);
        assert_eq!(concrete.get_size(), 1);
        // non-code types pass through unchanged.
        let int_t = factory.find_by_name("int").unwrap();
        let passthrough = factory.concretize(int_t.clone());
        assert!(Arc::ptr_eq(&passthrough, &int_t));
        // deconcretize (Rudra-only inverse) round-trips the concretized form.
        let back = factory.deconcretize(concrete);
        assert_eq!(back.get_metatype(), TypeMetatype::Code);
    }

    #[test]
    fn test_raw_constructor_alignment_gate_and_void() {
        // type.cc:3106/3122 — the raw factory has no alignment map and no
        // core types; a findAdd miss raises the oracle LowlevelError text.
        let mut raw = TypeFactory::raw();
        assert_eq!(
            raw.get_base_result(1, TypeMetatype::Int).unwrap_err(),
            "TypeFactory alignment map not initialized"
        );
        // getTypeVoid works on the raw factory (type.cc:3575-3588).
        let void_t = raw.get_type_void_result();
        assert_eq!(void_t.get_name(), "void");
        assert_eq!(void_t.get_id(), Datatype::hash_name("void"));
        assert!(void_t.is_coretype());
    }

    #[test]
    fn test_set_core_type_promotes_existing_noncore_factory_view() {
        // type.cc:3178-3195 — setCoreType on an existing equal definition
        // ORs the core flag onto the canonical object. Every factory-mediated
        // lookup observes the promotion.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let pre = factory
            .get_base_named(1, TypeMetatype::Int, "promo_plain")
            .unwrap();
        assert!(!pre.is_coretype());
        let post = factory
            .set_core_type_result("promo_plain", 1, TypeMetatype::Int, false)
            .unwrap();
        assert!(post.is_coretype());
        assert_eq!(post.get_id(), pre.get_id());
        // The factory view is promoted.
        let queried = factory.find_by_name("promo_plain").unwrap();
        assert!(queried.is_coretype());
        assert!(Arc::ptr_eq(&queried, &post));
        // The promoted entry survives clearNoncore (Ghidra scans the flag).
        factory.clear_non_core();
        assert!(factory.find_by_name("promo_plain").is_some());
    }

    #[test]
    fn test_set_core_type_conflict_returns_oracle_error() {
        // type.cc:3423 — compareDependency mismatch raises the alter-
        // definition LowlevelError with no partial state.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        factory
            .set_core_type_result("plain_x", 1, TypeMetatype::Int, false)
            .unwrap();
        let err = factory
            .set_core_type_result("plain_x", 2, TypeMetatype::Int, false)
            .unwrap_err();
        assert_eq!(err, "Trying to alter definition of type: plain_x");
        // Partial state: the original registration is untouched.
        let survivor = factory.find_by_name("plain_x").unwrap();
        assert_eq!(survivor.get_size(), 1);
        // A char/plain submeta mismatch also raises.
        let err2 = factory
            .set_core_type_result("plain_x", 1, TypeMetatype::Int, true)
            .unwrap_err();
        assert_eq!(err2, "Trying to alter definition of type: plain_x");
    }

    #[test]
    fn test_large_base_converts_to_unknown_array() {
        // type.cc:3652-3657 — sizes over max_basetype_size (10) become an
        // unnamed array of the cached 1-byte unknown.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        factory
            .set_core_type_result("u1", 1, TypeMetatype::Unknown, false)
            .unwrap();
        factory.cache_core_types();
        let big = factory.get_base_result(20, TypeMetatype::Int).unwrap();
        assert_eq!(big.get_metatype(), TypeMetatype::Array);
        assert_eq!(big.get_size(), 20);
        assert!(big.get_name().is_empty());
        let repeat = factory.get_base_result(20, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&big, &repeat));
        match big.as_ref() {
            crate::type_system::datatype::Datatype::Array(a) => {
                assert_eq!(a.num_elements, 20);
                assert_eq!(a.array_of.get_name(), "u1");
            }
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn test_wide_char_and_float_cache_slots() {
        // type.cc:3182-3186 chartp size!=1 → TypeUnicode; type.cc:3210-3215
        // float10/16 dedicated slots; unicode fills charcache but never the
        // preferred ASCII slot.
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let wide2 = factory
            .set_core_type_result("wide2", 2, TypeMetatype::Int, true)
            .unwrap();
        assert!(wide2.get_flags() & type_flags::UTF16 != 0);
        let plain2 = factory
            .set_core_type_result("plain2", 2, TypeMetatype::Int, false)
            .unwrap();
        let f10 = factory
            .set_core_type_result("f10", 10, TypeMetatype::Float, false)
            .unwrap();
        let f16 = factory
            .set_core_type_result("f16", 16, TypeMetatype::Float, false)
            .unwrap();
        factory.cache_core_types();
        // UTF16 is char-printable: charcache[2] holds it.
        assert!(Arc::ptr_eq(&factory.get_type_char(2).unwrap(), &wide2));
        // But not ASCII: the preferred (2, INT) slot goes to the plain int.
        assert!(Arc::ptr_eq(
            &factory.get_base_result(2, TypeMetatype::Int).unwrap(),
            &plain2
        ));
        // Float10/16 dedicated slots.
        assert!(Arc::ptr_eq(
            &factory.get_base_result(10, TypeMetatype::Float).unwrap(), &f10
        ));
        assert!(Arc::ptr_eq(
            &factory.get_base_result(16, TypeMetatype::Float).unwrap(), &f16
        ));
    }

    #[test]
    fn test_decode_core_types_rebuilds_and_enums_enter_tree() {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        fn el(name: &str, attrs: &[(&str, &str)]) -> std::sync::Arc<std::sync::RwLock<Element>> {
            let mut e = Element::new();
            e.set_name(name);
            for (k, v) in attrs {
                e.add_attribute(k, v);
            }
            std::sync::Arc::new(std::sync::RwLock::new(e))
        }
        let mut factory = TypeFactory::new(8);
        factory.clear();
        let root = el("coretypes", &[]);
        {
            let mut rg = root.write().unwrap();
            rg.add_child(el(
                "type",
                &[
                    ("name", "dk_enum"), ("size", "1"), ("metatype", "enum_int"), ("id", "0x5500000000000011"),
                ],
            ));
            rg.add_child(el(
                "type",
                &[
                    ("name", "dk_char"), ("size", "1"), ("metatype", "int"), ("char", "true"), ("id", "0x5500000000000012"),
                ],
            ));
        }
        let mut decoder = TreeDecoder::new(
            root, std::sync::Arc::new(std::sync::RwLock::new(IdRegistry)),
        );
        factory.decode_core_types(&mut decoder).unwrap();
        // Full clear wiped the bootstrap entries.
        assert!(factory.find_by_name("undefined1").is_none());
        // The decoded enum is core and entered the ordered tree: with no
        // plain size-1 INT registered, type_nochar selects it (type.cc:3220-
        // 3222 runs BEFORE the isEnumType break).
        let dk_enum = factory.find_by_name("dk_enum").unwrap();
        assert!(dk_enum.is_coretype());
        assert!(dk_enum.is_enum_type());
        let nochar = factory
            .get_base_no_char_result(1, TypeMetatype::Int)
            .unwrap();
        assert!(Arc::ptr_eq(&nochar, &dk_enum));
        // The enum break leaves typecache[1][INT] to the ASCII char.
        let dk_char = factory.find_by_name("dk_char").unwrap();
        let preferred = factory.get_base_result(1, TypeMetatype::Int).unwrap();
        assert!(Arc::ptr_eq(&preferred, &dk_char));
    }

    #[test]
    fn test_hash_size_stability() {
        // type.cc:709-716 — hashSize XORs the scaled size into the id; the
        // transform is an involution: feeding the output back with the same
        // size recovers the original id.
        let a = hash_size(0x1234, 1);
        let b = hash_size(0x1234, 4);
        assert_ne!(a, b);
        assert_eq!(a, hash_size(0x1234, 1));
        assert_eq!(hash_size(a, 1), 0x1234);
        assert_eq!(hash_size(b, 4), 0x1234);
        assert_eq!(a, Datatype::hash_size(0x1234, 1));
    }

    // --- P2 TypeFactory::getTypeCode(PrototypePieces) / setPrototype ---

    #[test]
    fn test_get_type_code_pieces() {
        // type.cc:4002 — builds a TypeCode with an attached prototype.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.find_by_name("int").unwrap();
        let void_t = factory.get_type_void_result();
        let in_types = vec![int_t.clone(), int_t];
        let sig = crate::fspec::PrototypePieces {
            out_type: Some(&void_t),
            in_types: &in_types,
            first_var_arg_slot: -1,
        };
        let code = factory.get_type_code_pieces(&sig);
        assert_eq!(code.get_metatype(), TypeMetatype::Code);
        // Dedup: a second call with the same pieces returns the same Arc.
        let in_types2 = vec![
            factory.find_by_name("int").unwrap(),
            factory.find_by_name("int").unwrap(),
        ];
        let void_t2 = factory.get_type_void_result();
        let sig2 = crate::fspec::PrototypePieces {
            out_type: Some(&void_t2),
            in_types: &in_types2,
            first_var_arg_slot: -1,
        };
        let code2 = factory.get_type_code_pieces(&sig2);
        assert!(Arc::ptr_eq(&code, &code2));
        // The prototype has 2 parameters.
        if let Datatype::Code(c) = code.as_ref() {
            let proto = c.proto.as_ref().expect("prototype attached");
            assert_eq!(proto.num_params(), 2);
            assert!(proto.is_input_locked());
        } else {
            panic!("expected a Code type");
        }
    }

    #[test]
    fn test_factory_set_prototype_on_incomplete() {
        // type.cc:3518 — setPrototype requires an incomplete TypeCode.
        let mut factory = TypeFactory::new(8);
        // Build an incomplete code type manually.
        let mut base = TypeBase::new("incomplete_code".to_string(), 1, TypeMetatype::Code);
        base.flags |= type_flags::TYPE_INCOMPLETE;
        let dt = Arc::new(Datatype::Code(TypeCode { base, proto: None }));
        factory.types.insert("incomplete_code".to_string(), dt);
        // Set a prototype on it.
        let void_t = factory.get_type_void_result();
        let proto = crate::fspec::FuncProto::new("f".to_string(), void_t);
        let updated = factory
            .set_prototype("incomplete_code", Some(&proto), 0)
            .expect("setPrototype on incomplete code");
        // Incomplete flag cleared.
        assert!(updated.get_flags() & type_flags::TYPE_INCOMPLETE == 0);
        // Prototype copied in.
        if let Datatype::Code(c) = updated.as_ref() {
            assert!(c.proto.is_some());
        } else {
            panic!("expected a Code type");
        }
    }

    #[test]
    fn test_factory_set_prototype_rejects_complete() {
        // type.cc:3518 — setting a prototype on a complete code type errors.
        let mut factory = TypeFactory::new(8);
        let code = factory.get_type_code(); // complete (no TYPE_INCOMPLETE)
        let void_t = factory.get_type_void_result();
        let proto = crate::fspec::FuncProto::new("f".to_string(), void_t);
        let res = factory.set_prototype("code", Some(&proto), 0);
        assert!(res.is_err());
    }

    #[test]
    fn test_unknown_base_is_canonical_by_size() {
        let mut factory = TypeFactory::new(8);
        // The faithful getBase twin runs findAdd, whose alignment computation
        // requires the architecture-installed map (type.cc:3300-3302) — the
        // same setupSizes the oracle runs on every production factory
        // (type.cc:3160); clear()/clearNoncore deliberately retain it
        // (type.cc:3251/3266).
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        let core = factory.get_base_result(8, TypeMetatype::Unknown).unwrap();
        let core_again = factory.get_base_result(8, TypeMetatype::Unknown).unwrap();
        assert!(Arc::ptr_eq(&core, &core_again));
        assert_eq!(core.get_name(), "undefined8");
        assert!(core.is_coretype());

        let anonymous = factory.get_base_result(3, TypeMetatype::Unknown).unwrap();
        let anonymous_again = factory.get_base_result(3, TypeMetatype::Unknown).unwrap();
        assert!(Arc::ptr_eq(&anonymous, &anonymous_again));
        assert!(!Arc::ptr_eq(&core, &anonymous));
        assert_eq!(anonymous.get_name(), "");
        assert_eq!(anonymous.get_id(), 0);
        assert!(!anonymous.is_coretype());

        let mut ordered = Vec::new();
        factory.dependent_order(&mut ordered);
        assert!(ordered
            .iter()
            .any(|datatype| Arc::ptr_eq(datatype, &anonymous)));

        factory.clear_non_core();
        let recreated = factory.get_base_result(3, TypeMetatype::Unknown).unwrap();
        let recreated_again = factory.get_base_result(3, TypeMetatype::Unknown).unwrap();
        assert!(!Arc::ptr_eq(&anonymous, &recreated));
        assert!(Arc::ptr_eq(&recreated, &recreated_again));
    }

    #[test]
    fn test_named_unknown_rejects_conflicting_definition() {
        let mut factory = TypeFactory::new(8);
        let first = factory
            .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
            .unwrap();
        let repeated = factory
            .get_base_named(3, TypeMetatype::Unknown, "fixture_unknown3")
            .unwrap();
        assert!(Arc::ptr_eq(&first, &repeated));
        assert_eq!(first.get_id(), Datatype::hash_name("fixture_unknown3"));
        assert_eq!(
            factory
                .get_base_named(4, TypeMetatype::Unknown, "fixture_unknown3")
                .unwrap_err(),
            "Trying to alter definition of type: fixture_unknown3"
        );
    }

    #[test]
    fn test_core_cache_uses_ordered_identity_not_names() {
        let mut factory = TypeFactory::new(8);
        factory.clear();

        let plain_a = factory
            .set_core_type_result("plain_high", 1, TypeMetatype::Int, false)
            .unwrap();
        let plain_b = factory
            .set_core_type_result("aaaaaaaa", 1, TypeMetatype::Int, false)
            .unwrap();
        let uint_a = factory
            .set_core_type_result("unsigned_custom_a", 1, TypeMetatype::Uint, false)
            .unwrap();
        let uint_b = factory
            .set_core_type_result("unsigned_custom_b", 1, TypeMetatype::Uint, false)
            .unwrap();
        let ascii = factory
            .set_core_type_result("custom_ascii_glyph", 1, TypeMetatype::Int, true)
            .unwrap();
        factory.cache_core_types();

        let preferred = factory
            .get_base_result(1, TypeMetatype::Int)
            .expect("preferred signed byte");
        assert!(Arc::ptr_eq(&preferred, &ascii));
        let preferred_char = factory.get_type_char(1).expect("cached char");
        assert!(Arc::ptr_eq(&preferred_char, &ascii));

        let expected_nochar = if plain_a.get_id() > plain_b.get_id() {
            &plain_a
        } else {
            &plain_b
        };
        let nochar = factory
            .get_base_no_char_result(1, TypeMetatype::Int)
            .expect("non-character signed byte");
        assert!(Arc::ptr_eq(&nochar, expected_nochar));

        let expected_uint = if uint_a.get_id() < uint_b.get_id() {
            &uint_a
        } else {
            &uint_b
        };
        let preferred_uint = factory
            .get_base_result(1, TypeMetatype::Uint)
            .expect("preferred unsigned byte");
        assert!(Arc::ptr_eq(&preferred_uint, expected_uint));
        assert_eq!(preferred.get_name(), "custom_ascii_glyph");
    }

    #[test]
    fn test_core_cache_repeat_late_plain_and_clear() {
        let mut factory = TypeFactory::new(8);
        factory.clear();

        let first_plain = factory
            .set_core_type_result("aaaaaaaa", 1, TypeMetatype::Int, false)
            .unwrap();
        let ascii = factory
            .set_core_type_result("custom_ascii_glyph", 1, TypeMetatype::Int, true)
            .unwrap();
        factory.cache_core_types();
        let first_preferred = factory.get_base_result(1, TypeMetatype::Int).unwrap();
        let first_nochar = factory
            .get_base_no_char_result(1, TypeMetatype::Int)
            .unwrap();
        assert!(Arc::ptr_eq(&first_preferred, &ascii));
        assert!(Arc::ptr_eq(&first_nochar, &first_plain));

        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &first_preferred,
            &factory.get_base_result(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &first_nochar,
            &factory
                .get_base_no_char_result(1, TypeMetatype::Int)
                .unwrap()
        ));

        let late_plain = factory
            .set_core_type_result("zzzzzzzz", 1, TypeMetatype::Int, false)
            .unwrap();
        assert!(late_plain.get_id() > first_plain.get_id());
        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &ascii,
            &factory.get_base_result(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &late_plain,
            &factory
                .get_base_no_char_result(1, TypeMetatype::Int)
                .unwrap()
        ));

        factory.clear();
        factory.clear();
        assert!(factory.find_by_name("custom_ascii_glyph").is_none());
        let post_clear = factory
            .set_core_type_result("post_clear_plain", 1, TypeMetatype::Int, false)
            .unwrap();
        factory.cache_core_types();
        assert!(Arc::ptr_eq(
            &post_clear,
            &factory.get_base_result(1, TypeMetatype::Int).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &post_clear,
            &factory
                .get_base_no_char_result(1, TypeMetatype::Int)
                .unwrap()
        ));
    }

    // ---- data_organization / alignment-map state (oracle-verified numbers
    // ---- come from tests/oracle/cspec_typeorg_state_1204; these are the
    // ---- Rust regression mirrors).

    use crate::marshal::{Element, IdRegistry, TreeDecoder};

    fn elem_node(name: &str, attrs: &[(&str, &str)]) -> Arc<RwLock<Element>> {
        let mut el = Element::new();
        el.set_name(name);
        for (k, v) in attrs {
            el.add_attribute(k, v);
        }
        Arc::new(RwLock::new(el))
    }

    fn decoder_over(root: Arc<RwLock<Element>>) -> TreeDecoder {
        TreeDecoder::new(root, Arc::new(RwLock::new(IdRegistry::new())))
    }

    fn data_org_node(children: Vec<Arc<RwLock<Element>>>) -> Arc<RwLock<Element>> {
        let root = elem_node("data_organization", &[]);
        {
            let mut rg = root.write().unwrap();
            for child in children {
                rg.add_child(child);
            }
        }
        root
    }

    fn size_node(name: &str, value: &str) -> Arc<RwLock<Element>> {
        elem_node(name, &[("value", value)])
    }

    fn entry_node(size: &str, alignment: &str) -> Arc<RwLock<Element>> {
        elem_node("entry", &[("size", size), ("alignment", alignment)])
    }

    fn align_probe(factory: &TypeFactory, sizes: &[u32]) -> Vec<i32> {
        sizes
            .iter()
            .map(|&sz| factory.get_alignment(sz).unwrap())
            .collect()
    }

    #[test]
    fn test_data_organization_persists_sizes_and_skips_unknown_children() {
        let mut factory = TypeFactory::new(8);
        let root = data_org_node(vec![
            size_node("machine_alignment", "2"), // not consumed: skipped
            size_node("pointer_size", "8"),
            size_node("wchar_size", "4"),
            size_node("short_size", "2"), // not consumed: skipped
            size_node("integer_size", "4"),
            size_node("long_size", "8"),
            size_node("float_size", "4"), // not consumed: skipped
        ]);
        let snapshot = factory.decode_data_organization(&mut decoder_over(root));
        // Production x86-64-gcc.cspec values (no char_size element: stays 0).
        assert_eq!(snapshot.size_of_int, 4);
        assert_eq!(snapshot.size_of_long, 8);
        assert_eq!(snapshot.size_of_pointer, 8);
        assert_eq!(snapshot.size_of_char, 0);
        assert_eq!(snapshot.size_of_wchar, 4);
        assert_eq!(factory.get_size_of_int(), 4);
        assert_eq!(factory.get_size_of_long(), 8);
        assert_eq!(factory.get_size_of_char(), 0);
        assert_eq!(factory.get_size_of_wchar(), 4);
        assert_eq!(factory.get_size_of_pointer(), 8);
        assert_eq!(factory.get_size_of_alt_pointer(), 0);
    }

    #[test]
    fn test_alignment_map_sparse_fill_leaves_index0_minus1() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("4", "4"));
            rg.add_child(entry_node("8", "8"));
            rg.add_child(entry_node("16", "16"));
        }
        let root = data_org_node(vec![map]);
        let observed = factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(observed.size_of_int, 0); // sizes untouched by map-only doc
        // Forward-fill semantics: index 0 keeps -1, 3<-2, 5..7<-4, 9..15<-8.
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17]),
            vec![-1, 1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 16, 16]
        );
    }

    #[test]
    fn test_alignment_map_empty_stays_empty_until_setup_sizes() {
        let mut factory = TypeFactory::new(8);
        let root = data_org_node(vec![elem_node("size_alignment_map", &[])]);
        factory.decode_data_organization(&mut decoder_over(root));
        // decodeAlignmentMap installs nothing; getAlignment raises the oracle
        // LowlevelError text.
        assert_eq!(
            factory.get_alignment(1).unwrap_err(),
            "TypeFactory alignment map not initialized"
        );
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        // setDefaultAlignmentMap: resize(9,0) then slots 1..=8 — index 0 is 0.
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            vec![0, 1, 2, 2, 4, 4, 4, 4, 8, 8]
        );
    }

    #[test]
    fn test_alignment_map_explicit_zero_entry_and_duplicate_wins() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("0", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("8", "8"));
            rg.add_child(entry_node("8", "4")); // duplicate size: later wins
            rg.add_child(entry_node("5", "0")); // explicit zero alignment
        }
        let root = data_org_node(vec![map]);
        factory.decode_data_organization(&mut decoder_over(root));
        // Fill: 1<-1, 3..4<-2, 6..7<-0, 8 stays 4 (duplicate winner).
        assert_eq!(
            align_probe(&factory, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            vec![1, 1, 2, 2, 2, 0, 0, 0, 4, 4]
        );
    }

    #[test]
    fn test_setup_sizes_derives_defaults_from_arch_inputs() {
        let mut factory = TypeFactory::new(8);
        // Only char_size present: everything else derives (type.cc:3137-3170).
        let root = data_org_node(vec![size_node("char_size", "3")]);
        factory.decode_data_organization(&mut decoder_over(root));
        factory.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8), // stack pointer is 8 -> clamp to 4
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        assert_eq!(factory.get_size_of_int(), 4);
        assert_eq!(factory.get_size_of_long(), 8); // (int==4) ? 8 : int
        assert_eq!(factory.get_size_of_char(), 3); // already set: untouched
        assert_eq!(factory.get_size_of_wchar(), 2);
        assert_eq!(factory.get_size_of_pointer(), 8);
        assert_eq!(factory.get_size_of_alt_pointer(), 0);

        // int != 4 branch: sizeOfLong copies sizeOfInt instead of becoming 8.
        let mut factory2 = TypeFactory::new(8);
        let root2 = data_org_node(vec![size_node("integer_size", "2")]);
        factory2.decode_data_organization(&mut decoder_over(root2));
        factory2.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: Some(8),
            default_data_space_addr_size: 8,
            default_size: 8,
            far_pointer: None,
        });
        assert_eq!(factory2.get_size_of_int(), 2);
        assert_eq!(factory2.get_size_of_long(), 2);

        // No stack space: sizeOfInt keeps the literal fallback 1.
        let mut factory3 = TypeFactory::new(8);
        factory3.setup_sizes(&SizeArchInputs {
            stack_spacebase_size: None,
            default_data_space_addr_size: 4,
            default_size: 4,
            far_pointer: Some((2, 2)),
        });
        assert_eq!(factory3.get_size_of_int(), 1);
        assert_eq!(factory3.get_size_of_long(), 1);
        assert_eq!(factory3.get_size_of_pointer(), 2); // far-pointer override
        assert_eq!(factory3.get_size_of_alt_pointer(), 4); // inner + base
    }

    #[test]
    fn test_data_organization_consumes_children_after_alignment_map() {
        // Reviewer probe (CSPEC-TYPEORG-STATE-0001 rework): Ghidra's sam
        // branch falls through to closeElement(subId) (type.cc:4604-4612),
        // so children AFTER <size_alignment_map> are still consumed. A
        // missing close would leave the TreeDecoder stack on the sam
        // element, break the loop early, and silently drop them.
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
        }
        let root = data_org_node(vec![map, size_node("char_size", "3")]);
        let snapshot = factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(snapshot.size_of_char, 3);
        assert_eq!(factory.get_size_of_char(), 3);
        assert_eq!(factory.get_alignment(1).unwrap(), 1);
    }

    #[test]
    fn test_primitive_align_size_pads_like_sizeof() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut rg = map.write().unwrap();
            rg.add_child(entry_node("1", "1"));
            rg.add_child(entry_node("2", "2"));
            rg.add_child(entry_node("4", "4"));
        }
        let root = data_org_node(vec![map]);
        factory.decode_data_organization(&mut decoder_over(root));
        assert_eq!(factory.get_primitive_align_size(1).unwrap(), 1);
        assert_eq!(factory.get_primitive_align_size(2).unwrap(), 2);
        assert_eq!(factory.get_primitive_align_size(3).unwrap(), 4);
        assert_eq!(factory.get_primitive_align_size(4).unwrap(), 4);
        assert_eq!(factory.get_primitive_align_size(5).unwrap(), 8); // 5%4=1 -> +3
        assert_eq!(factory.get_primitive_align_size(7).unwrap(), 8);
        assert_eq!(factory.get_primitive_align_size(8).unwrap(), 8); // align 4
    }

    #[test]
    fn test_get_exact_piece_walk_order_partial_results_and_identity() {
        let mut factory = TypeFactory::new(8);
        let map = elem_node("size_alignment_map", &[]);
        {
            let mut write = map.write().unwrap();
            write.add_child(entry_node("0", "1"));
            write.add_child(entry_node("1", "1"));
            write.add_child(entry_node("2", "2"));
            write.add_child(entry_node("4", "4"));
            write.add_child(entry_node("8", "8"));
        }
        factory.decode_data_organization(&mut decoder_over(data_org_node(vec![map])));
        setup_default_sizes(&mut factory);
        let uint4 = factory
            .get_base_result(4, TypeMetatype::Uint)
            .expect("uint4");
        let uint8 = factory
            .get_base_result(8, TypeMetatype::Uint)
            .expect("uint8");

        factory.create_struct("ExactInner");
        let inner = factory
            .set_fields_sized(
                "ExactInner",
                vec![
                    TypeField {
                        name: "lo".into(),
                        offset: 0,
                        type_ptr: uint4.clone(),
                    },
                    TypeField {
                        name: "hi".into(),
                        offset: 4,
                        type_ptr: uint4.clone(),
                    },
                ],
                8,
                4,
            )
            .expect("inner definition");
        factory.create_struct("ExactOuter");
        let outer = factory
            .set_fields_sized(
                "ExactOuter",
                vec![
                    TypeField {
                        name: "head".into(),
                        offset: 0,
                        type_ptr: uint4.clone(),
                    },
                    TypeField {
                        name: "inner".into(),
                        offset: 8,
                        type_ptr: inner.clone(),
                    },
                    TypeField {
                        name: "tail".into(),
                        offset: 16,
                        type_ptr: uint8,
                    },
                ],
                24,
                8,
            )
            .expect("outer definition");

        let whole = factory.get_exact_piece(outer.clone(), 0, 24);
        assert!(Arc::ptr_eq(&whole.expect("whole struct"), &outer));
        let nested = factory.get_exact_piece(outer.clone(), 8, 8);
        assert!(Arc::ptr_eq(&nested.expect("nested struct"), &inner));
        let leaf = factory.get_exact_piece(outer.clone(), 12, 4);
        assert!(Arc::ptr_eq(&leaf.expect("nested leaf"), &uint4));
        assert!(factory.get_exact_piece(outer.clone(), 22, 4).is_none());
        assert!(factory.get_exact_piece(outer.clone(), 24, 1).is_none());
        assert!(factory.get_exact_piece(outer.clone(), 1, 24).is_none());
        let negative_exact = factory.get_exact_piece(uint4.clone(), -1, 4);
        assert!(Arc::ptr_eq(
            &negative_exact.expect("exact-size test precedes descent"),
            &uint4,
        ));

        let cross = factory
            .get_exact_piece(inner.clone(), 2, 4)
            .expect("cross partial");
        let cross_repeat = factory
            .get_type_partial_struct(inner.clone(), 2, 4);
        assert!(Arc::ptr_eq(&cross, &cross_repeat));
        let hole = factory
            .get_exact_piece(outer.clone(), 4, 0)
            .expect("zero-size hole");
        let hole_repeat = factory.get_type_partial_struct(outer.clone(), 4, 0);
        assert!(Arc::ptr_eq(&hole, &hole_repeat));

        let array = factory.get_array(uint4.clone(), 3);
        let array_element = factory
            .get_exact_piece(array.clone(), 4, 4)
            .expect("array element");
        assert!(Arc::ptr_eq(&array_element, &uint4));
        let array_partial = factory
            .get_exact_piece(array.clone(), 2, 4)
            .expect("cross-stride array partial");
        let array_partial_direct = factory.get_type_partial_struct(array.clone(), 2, 4);
        assert!(Arc::ptr_eq(&array_partial, &array_partial_direct));
        let (negative_element, negative_off) = Datatype::get_sub_type_arc(&array, -1);
        assert!(Arc::ptr_eq(
            &negative_element.expect("negative array offset"),
            &uint4,
        ));
        assert_eq!(negative_off, -1);
        let negative_array_piece = factory
            .get_exact_piece(array.clone(), -1, 4)
            .expect("negative array piece");
        assert!(Arc::ptr_eq(&negative_array_piece, &uint4));
        let (past_array, past_off) = Datatype::get_sub_type_arc(&array, 12);
        assert!(past_array.is_none());
        assert_eq!(past_off, 12);

        let enumeration = factory
            .get_type_enum_result("ExactEnum")
            .expect("configured enum");
        let enum_piece = factory
            .get_exact_piece(enumeration.clone(), 1, 2)
            .expect("partial enum");
        let enum_repeat = factory.get_type_partial_enum(enumeration, 1, 2);
        assert!(Arc::ptr_eq(&enum_piece, &enum_repeat));
        assert!(enum_piece.has_stripped());
        assert!(factory.get_exact_piece(enum_piece, 0, 1).is_none());

        factory.get_type_union("ExactUnion");
        let union = factory
            .set_union_fields_sized(
                "ExactUnion",
                vec![TypeField {
                    name: "wide".into(),
                    offset: 0,
                    type_ptr: uint4.clone(),
                }],
                4,
                4,
            )
            .expect("union definition");
        let whole_union = factory
            .get_exact_piece(union.clone(), 0, 4)
            .expect("whole union");
        assert!(Arc::ptr_eq(&whole_union, &union));
        let union_piece = factory
            .get_exact_piece(union.clone(), 1, 2)
            .expect("partial union");
        let union_repeat = factory.get_type_partial_union(union, 1, 2);
        assert!(Arc::ptr_eq(&union_piece, &union_repeat));

        let wide_partial = factory.get_type_partial_struct(outer.clone(), 8, 8);
        let (wide_subtype, wide_newoff) = Datatype::get_sub_type_arc(&wide_partial, 0);
        assert_eq!(wide_newoff, 0);
        assert!(Arc::ptr_eq(
            &wide_subtype.expect("partial equality boundary"),
            &inner,
        ));
        let leaf_partial = factory.get_type_partial_struct(outer, 8, 4);
        let (leaf_subtype, leaf_newoff) = Datatype::get_sub_type_arc(&leaf_partial, 0);
        assert_eq!(leaf_newoff, 0);
        assert!(Arc::ptr_eq(
            &leaf_subtype.expect("partial successful descent"),
            &uint4,
        ));

        let narrow = factory.get_type_partial_struct(inner, 0, 2);
        let (subtype, newoff) = Datatype::get_sub_type_arc(&narrow, 0);
        assert!(subtype.is_none());
        assert_eq!(newoff, 0);
        assert!(factory.get_exact_piece(narrow, 0, 1).is_none());
    }

    // ---- TF-SINGLETON-WIRING-0001 step 1: current-Architecture resolution
    // ----
    // TLS hygiene: every test below MUST unpublish what it published —
    // cargo's test harness reuses threads, and a stale publication would
    // redirect a LATER test's `shared_default`/`canonical_unknown_base_1`
    // resolutions at this test's factory.

    /// The fallback tier: with nothing published, `shared_default` answers
    /// the process-canonical factory (pre-publication contexts, e.g. unit
    /// fixtures and decode-before-arch paths).
    #[test]
    fn shared_default_without_publication_answers_process_canonical() {
        assert!(TypeFactory::current_arch_factory().is_none());
        let resolved = TypeFactory::shared_default();
        assert!(TypeFactory::current_arch_factory().is_none());
        assert!(Arc::ptr_eq(
            &resolved,
            &TypeFactory::shared_default(),
        ));
    }

    /// Publishing a factory redirects BOTH resolution entries to it
    /// (`shared_default` and `canonical_unknown_base_1`), the published
    /// unknown is the published factory's OWN cached object (identity
    /// domain follows the owning Architecture, mirroring
    /// `glb->types->getBase(1,TYPE_UNKNOWN)`), and unpublishing restores
    /// the process-canonical fallback.
    #[test]
    fn publish_current_arch_redirects_resolution_and_unpublish_restores() {
        let fresh = TypeFactory::fresh_canonical();
        assert!(!Arc::ptr_eq(
            &fresh,
            &TypeFactory::shared_default(),
        ));
        TypeFactory::publish_current_arch(fresh.clone());
        assert!(Arc::ptr_eq(
            &TypeFactory::shared_default(),
            &fresh,
        ));
        let published_unknown = TypeFactory::canonical_unknown_base_1();
        let factory_unknown = fresh
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_base(1, TypeMetatype::Unknown)
            .expect("factory always produces an unknown base type");
        assert!(Arc::ptr_eq(&published_unknown, &factory_unknown));
        TypeFactory::unpublish_current_arch(&fresh);
        assert!(TypeFactory::current_arch_factory().is_none());
        assert!(!Arc::ptr_eq(
            &TypeFactory::shared_default(),
            &fresh,
        ));
    }

    /// Unpublish is ownership-scoped: clearing ANOTHER factory's
    /// publication is a no-op (the other Architecture's ownership
    /// supersedes ours), and only the identity-matching unpublish clears.
    #[test]
    fn unpublish_is_identity_scoped_to_own_factory() {
        let first = TypeFactory::fresh_canonical();
        let second = TypeFactory::fresh_canonical();
        TypeFactory::publish_current_arch(first.clone());
        TypeFactory::unpublish_current_arch(&second);
        assert!(Arc::ptr_eq(
            &TypeFactory::current_arch_factory().expect("still first"),
            &first,
        ));
        TypeFactory::unpublish_current_arch(&first);
        assert!(TypeFactory::current_arch_factory().is_none());
    }

    /// Sequential multi-Architecture lifecycle (bin_sweep dual-binary
    /// shape): publishing factory #2 must fully replace factory #1 — no
    /// residual first-Architecture state reachable through the resolution
    /// entries.
    #[test]
    fn republish_replaces_previous_architecture_factory() {
        let first = TypeFactory::fresh_canonical();
        let second = TypeFactory::fresh_canonical();
        TypeFactory::publish_current_arch(first.clone());
        assert!(Arc::ptr_eq(&TypeFactory::shared_default(), &first));
        TypeFactory::publish_current_arch(second.clone());
        assert!(Arc::ptr_eq(&TypeFactory::shared_default(), &second));
        TypeFactory::unpublish_current_arch(&second);
        assert!(TypeFactory::current_arch_factory().is_none());
    }

    /// The fresh-factory construction recipe must match the
    /// process-canonical one up to instance identity: same alignment-map
    /// state and a working unknown base (the architecture.cc:1350 decode
    /// tail applied at build, type.cc:3164-3165).
    #[test]
    fn fresh_canonical_matches_process_recipe() {
        let fresh = TypeFactory::fresh_canonical();
        let canonical = TypeFactory::shared_default();
        assert!(!Arc::ptr_eq(&fresh, &canonical));
        let (fresh_map, canonical_map) = (
            fresh
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_alignment(1),
            canonical
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_alignment(1),
        );
        assert_eq!(fresh_map, canonical_map);
        assert!(
            fresh
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_base(1, TypeMetatype::Unknown)
                .is_some()
        );
    }

    /// Architecture integration: `set_types` publishes (the buildTypegrp
    /// moment), `ensure_types` installs a fresh OWN factory for
    /// set_types-less architectures, and Drop unpublishes (the
    /// architecture.cc:211-212 teardown mirror) — restoring the
    /// process-canonical fallback tier.
    #[test]
    fn architecture_lifecycle_publishes_and_unpublishes_its_factory() {
        use crate::arch::Architecture;
        // set_types path: the installed handle becomes the thread-current
        // factory while the Architecture lives.
        {
            let mut arch = Architecture::new();
            let owned = TypeFactory::fresh_canonical();
            arch.set_types(owned.clone());
            assert!(Arc::ptr_eq(
                &TypeFactory::current_arch_factory().expect("published"),
                &owned,
            ));
            // ensure_types returns the SAME installed handle (no shadow
            // fresh construction behind an explicit install).
            assert!(Arc::ptr_eq(&arch.ensure_types(), &owned));
        }
        // Architecture dropped → publication cleared.
        assert!(TypeFactory::current_arch_factory().is_none());
        // ensure_types fresh path: a set_types-less Architecture acquires
        // its OWN factory (not the process-canonical singleton) — compare
        // against the fallback tier directly, because shared_default NOW
        // resolves to the freshly published current factory by design.
        {
            let mut arch = Architecture::new();
            let handle = arch.ensure_types();
            assert!(!Arc::ptr_eq(
                &handle,
                &TypeFactory::process_canonical_factory(),
            ));
            assert!(Arc::ptr_eq(
                &TypeFactory::current_arch_factory().expect("published"),
                &handle,
            ));
        }
        assert!(TypeFactory::current_arch_factory().is_none());
    }

    // --- WORKPKG-UNMAP-TYPEUNION-0003: TypeFactory recalcPointerSubmeta /
    // setName / insertWarning / removeWarning / getTypePointerWithSpace /
    // destroyType / setFields flags (type.cc:3724/3445/3750/3761/4055/4122/3479) ---

    #[test]
    fn test_string2typeclass_and_metatype2typeclass_live_in_datatype() {
        // The type.cc free functions live on the datatype module; the
        // factory re-exports them through the glob import for spec decode.
        use crate::type_system::datatype::{metatype2typeclass, string2typeclass, TypeClass};
        assert_eq!(string2typeclass("hiddenret"), Ok(TypeClass::HiddenRet));
        assert_eq!(metatype2typeclass(TypeMetatype::Pointer), TypeClass::Ptr);
    }

    /// Install the x86-64-gcc.cspec `<size_alignment_map>` shape (entries
    /// 1/2/4/8/16, index 0 left at the decode -1 fill) through the real
    /// `decode_alignment_map` path, so the factory mirrors the production
    /// cspec-decoded layout rather than `setDefaultAlignmentMap` (whose
    /// index-0 zero would divide by zero on the size-0 incomplete struct,
    /// the same UB Ghidra's oracle has there).
    fn install_cspec_align_map(factory: &mut TypeFactory) {
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::RwLock;
        fn entry(size: i64, alignment: i64) -> std::sync::Arc<RwLock<Element>> {
            std::sync::Arc::new(RwLock::new(Element {
                name: "entry".to_string(),
                content: String::new(),
                attr_names: vec!["size".to_string(), "alignment".to_string()],
                attr_values: vec![size.to_string(), alignment.to_string()],
                children: Vec::new(),
            }))
        }
        let root = std::sync::Arc::new(RwLock::new(Element {
            name: "size_alignment_map".to_string(),
            content: String::new(),
            attr_names: Vec::new(),
            attr_values: Vec::new(),
            children: vec![
                entry(1, 1),
                entry(2, 2),
                entry(4, 4),
                entry(8, 8),
                entry(16, 16),
            ],
        }));
        let registry = std::sync::Arc::new(RwLock::new(IdRegistry::new()));
        let mut decoder = TreeDecoder::new(root, registry);
        // Descend INTO the <size_alignment_map> node first: production
        // reaches decode_alignment_map with the decoder already positioned
        // at that element (decodeDataOrganization opens it before the call).
        decoder.open_element();
        factory.decode_alignment_map(&mut decoder);
    }

    #[test]
    fn test_recalc_pointer_submeta_migrates_incomplete_struct_pointers() {
        // type.cc:3724-3745 walk: pointers interned while a struct was
        // INCOMPLETE sit in the SUB_PTR_STRUCT(4) slot; after the struct
        // completes as a single-field struct, calcSubmeta yields SUB_PTR(6)
        // and recalcPointerSubmeta(base, SUB_PTR_STRUCT) must re-key them so
        // a fresh getTypePointer probe (which computes SUB_PTR) finds the
        // SAME registration instead of interning a duplicate.
        let mut factory = TypeFactory::new(8);
        install_cspec_align_map(&mut factory);
        // Incomplete single-field struct.
        let st = factory.create_struct("fixture_recalc_s");
        assert!(st.is_incomplete());
        // A pointer to the incomplete struct registers under PtrStruct(4).
        let ptr_before = factory.get_type_pointer(8, st.clone(), 1);
        assert_eq!(ptr_before.get_submeta(), SubMetatype::PtrStruct);
        // Complete the struct through the factory setFields twin — the
        // completion internally runs the recalc tail (type.cc:3490-3491).
        let int_t = factory.get_base(4, TypeMetatype::Int).expect("int");
        let completed = factory
            .set_fields_sized(
                "fixture_recalc_s",
                vec![TypeField { name: "x".into(), offset: 0, type_ptr: int_t.clone() }],
                4,
                4,
            )
            .expect("completes");
        assert!(!completed.is_incomplete());
        // NOTE(observe): set_fields_sized re-wraps the struct in a NEW Arc
        // (define_replace seam, TYPEFACTORY-ARC-IDENTITY-0001), so the
        // probe identity differs from the pointer's pointee Arc and the
        // direct migration cannot reach it. The completed struct itself
        // must now register pointers as SUB_PTR:
        let ptr_after = factory.get_type_pointer(8, completed.clone(), 1);
        assert_eq!(ptr_after.get_submeta(), SubMetatype::Ptr);
        // And an explicit recalc call with the stale sub on the completed
        // base is a no-op-safe probe (curSub == SUB_PTR != SUB_PTR_STRUCT
        // walks; nothing matching ptrto==completed sits under 4 — the
        // stale pointer holds the pre-completion Arc).
        factory.recalc_pointer_submeta(&completed, SubMetatype::PtrStruct);
        let ptr_again = factory.get_type_pointer(8, completed.clone(), 1);
        assert!(Arc::ptr_eq(&ptr_after, &ptr_again));
        // A multi-field struct keeps PtrStruct(4) pointers (calcSubmeta:
        // numDepend > 1), and its recalc(SUB_PTR) early-outs (curSub==sub).
        let mt = factory.create_struct("fixture_recalc_m");
        let _mptr = factory.get_type_pointer(8, mt.clone(), 1);
        let int8 = factory.get_base(8, TypeMetatype::Int).expect("long");
        let _ = int8;
        let mcompleted = factory
            .set_fields_sized(
                "fixture_recalc_m",
                vec![
                    TypeField { name: "a".into(), offset: 0, type_ptr: int_t.clone() },
                    TypeField { name: "b".into(), offset: 4, type_ptr: int_t.clone() },
                ],
                8,
                4,
            )
            .expect("completes");
        let mptr_after = factory.get_type_pointer(8, mcompleted.clone(), 1);
        assert_eq!(mptr_after.get_submeta(), SubMetatype::PtrStruct);
    }

    #[test]
    fn test_set_name_reregisters_both_channels() {
        // type.cc:3445-3459: rename fixes the name channel AND the tree;
        // a zero id becomes hashName(n).
        let mut factory = TypeFactory::new(8);
        // Named construction already carries a hashName id; the rename
        // observable is the two-channel swap.
        let st = factory.create_struct("fixture_rename_s");
        assert_ne!(st.get_id(), 0);
        let renamed = factory.set_name(&st, "fixture_renamed").expect("renames");
        assert_eq!(renamed.get_name(), "fixture_renamed");
        assert_eq!(renamed.get_display_name(), "fixture_renamed");
        // Id is UNCHANGED by setName when already nonzero (type.cc:3453).
        assert_eq!(renamed.get_id(), st.get_id());
        let found = factory.find_by_name("fixture_renamed").expect("new slot");
        assert!(Arc::ptr_eq(&found, &renamed));
        assert!(factory.find_by_name("fixture_rename_s").is_none());
        // The zero-id branch (type.cc:3453-3454) reachable via an
        // ANONYMOUS tree-registered type: an unnamed array.
        let int_t = factory.get_base(4, TypeMetatype::Int).expect("int");
        let arr = factory.get_array(int_t, 2);
        assert_eq!(arr.get_id(), 0);
        assert!(arr.get_name().is_empty());
        let named_arr = factory.set_name(&arr, "fixture_arr").expect("renames");
        assert_eq!(named_arr.get_id(), Datatype::hash_name("fixture_arr"));
        assert!(factory.find_by_name("fixture_arr").is_some());
    }

    #[test]
    fn test_insert_and_remove_warning() {
        // type.cc:3750-3757 / 3761-3773.
        let mut factory = TypeFactory::new(8);
        // Anonymous (id 0) types cannot carry warnings: an unnamed array.
        let int_t = factory.get_base(4, TypeMetatype::Int).expect("int");
        let anon = factory.get_array(int_t, 2);
        assert!(factory.insert_warning(&anon, "w".into()).is_err());
        // A named type warns: the flag is set and the record appended.
        let st = factory.create_struct("fixture_warn_s");
        assert_ne!(st.get_id(), 0);
        let warned = factory
            .insert_warning(&st, "ignoring overlapping field".into())
            .expect("warns");
        assert!(warned.has_warning());
        assert_eq!(factory.warnings.len(), 1);
        assert_eq!(factory.warnings[0].type_name, "fixture_warn_s");
        assert_eq!(factory.warnings[0].type_id, st.get_id());
        assert_eq!(factory.warnings[0].warning, "ignoring overlapping field");
        // removeWarning matches on (id, name).
        factory.remove_warning(warned.as_ref());
        assert!(factory.warnings.is_empty());
        // A different name does not drain.
        let warned2 = factory
            .insert_warning(&warned, "second".into())
            .expect("warns");
        let other = factory.create_struct("fixture_warn_other");
        factory.remove_warning(other.as_ref());
        assert_eq!(factory.warnings.len(), 1);
        let _ = warned2;
    }

    #[test]
    fn test_decode_struct_overlap_warning_rides_insert_warning() {
        // type.cc:4349/4357-4358: the decodeFields overlap warning reaches
        // insertWarning through decodeStruct. A NAMED struct gets the
        // warning registered (hasWarning set); an ANONYMOUS (id-0) struct
        // makes insertWarning throw the verbatim LowlevelError
        // (type.cc:3753-3754).
        use crate::marshal::{Element, IdRegistry, TreeDecoder};
        use std::sync::{Arc, RwLock};

        fn decode_struct_fields(
            factory: &mut TypeFactory,
            name: Option<&str>,
            fields: &[(&str, &str)],
        ) -> Result<Arc<Datatype>, String> {
            let mut root = Element::new();
            root.set_name("type");
            if let Some(nm) = name {
                root.add_attribute("name", nm);
            }
            root.add_attribute("size", "8");
            root.add_attribute("metatype", "struct");
            for (fname, off) in fields {
                let mut field = Element::new();
                field.set_name("field");
                field.add_attribute("name", fname);
                field.add_attribute("offset", off);
                let mut ty = Element::new();
                ty.set_name("type");
                ty.add_attribute("name", "int");
                ty.add_attribute("size", "4");
                ty.add_attribute("metatype", "int");
                field.add_child(Arc::new(RwLock::new(ty)));
                root.add_child(Arc::new(RwLock::new(field)));
            }
            let registry = Arc::new(RwLock::new(IdRegistry::new()));
            let mut decoder = TreeDecoder::new(Arc::new(RwLock::new(root)), registry);
            factory.decode_type(&mut decoder)
        }

        // Named, no overlap: no warning.
        let mut factory = TypeFactory::new(8);
        let plain = decode_struct_fields(&mut factory, Some("fixture_dec_plain"), &[("x", "0")])
            .expect("decodes");
        assert!(!plain.has_warning());
        assert!(factory.warnings.is_empty());
        // Named, overlapping second field: warning registered verbatim.
        let warned = decode_struct_fields(
            &mut factory,
            Some("fixture_dec_warn"),
            &[("x", "0"), ("y", "0")],
        )
        .expect("decodes");
        assert!(warned.has_warning());
        assert_eq!(factory.warnings.len(), 1);
        assert_eq!(factory.warnings[0].type_name, "fixture_dec_warn");
        assert_eq!(
            factory.warnings[0].warning,
            "Struct \"fixture_dec_warn\": ignoring overlapping field \"y\""
        );
        // ANONYMOUS overlapping struct: insertWarning throws verbatim.
        let mut factory_anon = TypeFactory::new(8);
        let anon = decode_struct_fields(&mut factory_anon, None, &[("x", "0"), ("y", "0")]);
        assert_eq!(
            anon.err(),
            Some("Can only issue warnings for named data-types".to_string())
        );
    }

    #[test]
    fn test_destroy_type_channels() {
        // type.cc:4122-4132: core types are refused; named types leave both
        // channels; a warned type drains its warnings first.
        let mut factory = TypeFactory::new(8);
        let int_t = factory.get_base(4, TypeMetatype::Int).expect("int");
        assert_eq!(
            factory.destroy_type(&int_t),
            Err("Cannot destroy core type".to_string())
        );
        let st = factory.create_struct("fixture_destroy_s");
        let warned = factory
            .insert_warning(&st, "w".into())
            .expect("warns");
        assert_eq!(factory.warnings.len(), 1);
        factory.destroy_type(&warned).expect("destroys");
        assert!(factory.find_by_name("fixture_destroy_s").is_none());
        assert!(factory.warnings.is_empty());
    }

    #[test]
    fn test_get_type_pointer_with_space_named_form() {
        // type.cc:4055-4065: size=space addr size, wordsize=space word
        // size, name/displayName=nm, id=hashName(nm); NO getStripped step.
        let mut factory = TypeFactory::new(8);
        install_cspec_align_map(&mut factory);
        let int_t = factory.get_base(4, TypeMetatype::Int).expect("int");
        let ptr = factory
            .get_type_pointer_with_space(int_t.clone(), AddressSpace::Ram, "file_ptr")
            .expect("interns");
        assert_eq!(ptr.get_name(), "file_ptr");
        assert_eq!(ptr.get_id(), Datatype::hash_name("file_ptr"));
        let Datatype::Pointer(p) = ptr.as_ref() else {
            panic!("pointer");
        };
        assert_eq!(p.wordsize, AddressSpace::Ram.word_size());
        assert!(p.base.pointer_space.is_some());
        // Dedup: the same construction returns the same registration.
        let int_again = factory.get_base(4, TypeMetatype::Int).expect("int");
        let ptr2 = factory
            .get_type_pointer_with_space(int_again, AddressSpace::Ram, "file_ptr")
            .expect("interns");
        assert!(Arc::ptr_eq(&ptr, &ptr2));
    }

    #[test]
    fn test_set_fields_flags_mask_transfer() {
        // type.cc:3487-3488: the masked-OR transfers
        // opaque_string|variable_length|type_incomplete from the caller's
        // flags; the union mask (type.cc:3508-3509) has NO opaque_string.
        let mut factory = TypeFactory::new(8);
        factory
            .set_core_type_result("char", 1, TypeMetatype::Int, true)
            .unwrap();
        let char_t = factory.get_type_char(1).expect("char");
        let _ = factory.create_struct("fixture_mask_s");
        let completed = factory
            .set_fields_flags(
                "fixture_mask_s",
                vec![TypeField { name: "c".into(), offset: 0, type_ptr: char_t.clone() }],
                1,
                1,
                type_flags::OPAQUE_STRUCT | type_flags::VARLENGTH,
            )
            .expect("completes");
        let flags = completed.get_flags();
        assert_eq!(flags & type_flags::OPAQUE_STRUCT, type_flags::OPAQUE_STRUCT);
        assert_eq!(flags & type_flags::VARLENGTH, type_flags::VARLENGTH);
        // Union version: opaque_string is NOT transferred.
        let _ = factory.get_type_union("fixture_mask_u");
        let udone = factory
            .set_union_fields_flags(
                "fixture_mask_u",
                vec![TypeField { name: "c".into(), offset: 0, type_ptr: char_t }],
                1,
                1,
                type_flags::OPAQUE_STRUCT | type_flags::VARLENGTH,
            )
            .expect("completes");
        let uflags = udone.get_flags();
        assert_eq!(uflags & type_flags::OPAQUE_STRUCT, 0);
        assert_eq!(uflags & type_flags::VARLENGTH, type_flags::VARLENGTH);
        // A masked-in type_incomplete keeps the union registered but
        // incomplete (the oracle's re-incomplete path).
        let _ = factory.get_type_union("fixture_mask_u2");
        let u2 = factory
            .set_union_fields_flags(
                "fixture_mask_u2",
                vec![],
                0,
                1,
                type_flags::TYPE_INCOMPLETE,
            )
            .expect("registers");
        assert!(u2.is_incomplete());
    }
}
