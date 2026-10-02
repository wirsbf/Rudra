//! Address space definitions
//!
//! This module corresponds to Ghidra's `space.hh` and defines the various
//! address spaces used in the decompiler.
//!
//! # Address Spaces
//!
//! Ghidra uses multiple address spaces to represent different types of storage:
//! - **RAM**: Normal memory
//! - **Register**: CPU registers
//! - **Unique**: Temporary/intermediate values (SSA temporaries)
//! - **Const**: Constant values
//! - **Stack**: Stack space
//! - **Other**: Custom/architecture-specific spaces

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::{Rc, Weak};

/// Address space identifier
pub type SpaceId = u8;

// Space IDs matching SLEIGH .sla spec space indices (space.hh getIndex()).
// SLEIGH x86-64 spec: 0=const, 1=OTHER, 2=unique, 3=ram, 4=register.
// Rudra extends past index 4 for its own spaces (Stack, Join, Iop).
pub const SPACEID_CONST: SpaceId = 0;
pub const SPACEID_OTHER: SpaceId = 1;
pub const SPACEID_UNIQUE: SpaceId = 2;
pub const SPACEID_RAM: SpaceId = 3;
pub const SPACEID_REGISTER: SpaceId = 4;
pub const SPACEID_STACK: SpaceId = 5;
pub const SPACEID_JOIN: SpaceId = 6;
pub const SPACEID_IOP: SpaceId = 7;

/// Address space in which a varnode resides
///
/// Corresponds to Ghidra's AddrSpace hierarchy in `space.hh`
///
/// Ghidra uses multiple address spaces to represent different types of storage:
/// - RAM: Normal memory
/// - Register: CPU registers
/// - Unique: Temporary/intermediate values
/// - Const: Constant values
/// - Stack: Stack space
/// - Other: Custom address spaces
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum AddressSpace {
    /// Normal memory (RAM)
    Ram,
    /// CPU registers
    Register,
    /// Temporary/unique storage for intermediate values (SSA temporaries)
    Unique,
    /// Constant values
    Const,
    /// Stack space
    Stack,
    /// Join space (for combining multiple spaces)
    Join,
    /// Internal iop space — varnodes referencing a PcodeOp (Ghidra IPTR_IOP).
    Iop,
    /// Overlay space
    Overlay,
    /// Other/custom address space
    Other(SpaceId),
}

impl AddressSpace {
    // RUDRA-GLUE: space_id (no Ghidra counterpart found)
    /// Get the space ID
    pub fn space_id(&self) -> SpaceId {
        match self {
            AddressSpace::Ram => SPACEID_RAM,
            AddressSpace::Register => SPACEID_REGISTER,
            AddressSpace::Unique => SPACEID_UNIQUE,
            AddressSpace::Const => SPACEID_CONST,
            AddressSpace::Stack => SPACEID_STACK,
            AddressSpace::Join => SPACEID_JOIN,
            AddressSpace::Iop => SPACEID_IOP,
            AddressSpace::Overlay => SPACEID_OTHER,
            AddressSpace::Other(id) => *id,
        }
    }

    // Ghidra: space.hh:31 spacetype
    pub fn from_id(id: SpaceId) -> Self {
        match id {
            SPACEID_CONST => AddressSpace::Const,
            SPACEID_OTHER => AddressSpace::Other(id),
            SPACEID_UNIQUE => AddressSpace::Unique,
            SPACEID_RAM => AddressSpace::Ram,
            SPACEID_REGISTER => AddressSpace::Register,
            SPACEID_STACK => AddressSpace::Stack,
            SPACEID_JOIN => AddressSpace::Join,
            SPACEID_IOP => AddressSpace::Iop,
            id => AddressSpace::Other(id),
        }
    }

    // RUDRA-GLUE: is_register
    /// Check if this is a register space
    pub fn is_register(&self) -> bool {
        matches!(self, AddressSpace::Register)
    }

    // RUDRA-GLUE: is_unique (no Ghidra counterpart found)
    /// Check if this is a temporary/unique space
    pub fn is_unique(&self) -> bool {
        matches!(self, AddressSpace::Unique)
    }

    // RUDRA-GLUE: is_const (no Ghidra counterpart found)
    /// Check if this is a constant space
    pub fn is_const(&self) -> bool {
        matches!(self, AddressSpace::Const)
    }

    // RUDRA-GLUE: is_ram (no Ghidra counterpart found)
    /// Check if this is RAM space
    pub fn is_ram(&self) -> bool {
        matches!(self, AddressSpace::Ram)
    }

    // RUDRA-GLUE: is_stack (no Ghidra counterpart found)
    /// Check if this is stack space
    pub fn is_stack(&self) -> bool {
        matches!(self, AddressSpace::Stack)
    }

    // Ghidra: space.hh AddrSpace::getDelay
    /// Heritage delay for this space — number of heritage passes before
    /// this space's varnodes are first heritaged. Faithful to
    /// `AddrSpace::getDelay()` (space.hh:315). Ghidra reads this from the
    /// .sla spec space record (`delay` attribute, sleighbase.cc:292
    /// decodeSlaSpace → `new AddrSpace(..., delay, deadcodedelay)`).
    /// Locked x86-64 oracle values (sleigh_specs/x86-64.sla space table,
    /// verified byte-level: `60 a5 cc 71 83 "ram" c9 21 83 e0 a3 10
    /// e0 aa 21 81 ...` = ELEM_SPACE name="ram" index=3 delay=1):
    ///   OTHER/const=0, unique=0 (size 4), ram=1, register=0.
    /// The stack space is NOT in the .sla — it is synthesized by
    /// `Architecture::decodeStackPointer` → `addSpacebase`
    /// (architecture.cc:1013 → 559-570). The delay argument is
    /// `ptrdata.space->getDelay()+1` (architecture.cc:565), where
    /// `ptrdata` is the stack-pointer register VarnodeData returned by
    /// `translate->getRegister(registerName)` (architecture.cc:1004) —
    /// i.e. the REGISTER space (delay 0), NOT the basespace (ram, 1);
    /// basespace is only stored as `contain` (translate.cc:61).
    /// SpacebaseSpace forwards that dl to AddrSpace as both delay and
    /// deadcodedelay (translate.cc:57-59 `AddrSpace(..., ind, 0, dl, dl)`).
    /// ⇒ stack delay = register(0)+1 = **1** for x86-64 (oracle
    /// HeritageInfo dump confirms `stack:idx=8,type=IPTR_SPACEBASE,
    /// delay=1`; see RCA2_MAXPASS.md §4.3/§5).
    /// RCA-2 (sb-integration probe, 2026-09-22): an earlier note here
    /// misread `ptrdata.space` as basespace and set stack=2, pushing
    /// stack first-heritage/placeholder resolution (and thus
    /// freePlaceholderSlot→maxpass flip, ActionActiveParam build) one
    /// pass late vs oracle (build@pass3 vs pass2) and inflating
    /// ParamList::calcDelay → getMaxInputDelay (2 vs 1). Fixed to 1.
    /// MAINDIFF-UNIQLEAK-0001 history: before that, Rudra had Ram=0
    /// (wrong — ram heritaged one pass too early, fixed to 1) alongside
    /// Stack=1; the "oracle first stack pass at pass 2" observation that
    /// justified Stack=2 was counted in mainloop rounds and actually
    /// corresponds to heritage delay=1 (stack first heritaged at
    /// heritage pass 1 = mainloop round 2).
    pub fn get_delay(&self) -> i32 {
        match self {
            AddressSpace::Ram => 1,
            AddressSpace::Stack => 1,
            _ => 0,
        }
    }

    // Ghidra: space.hh AddrSpace::getDeadcodeDelay
    /// Dead-code delay — number of heritage passes before dead-code removal
    /// is allowed on this space. Faithful to `AddrSpace::getDeadcodeDelay()`
    /// (space.hh). Ghidra defaults deadcodedelay = delay if not specified
    /// (space.cc:334-335).
    pub fn get_deadcode_delay(&self) -> i32 {
        self.get_delay()
    }

    // Ghidra: space.hh:332 AddrSpace::getIndex
    /// Integer identifier of this space in the locked x86-64 corpus space
    /// table. Faithful to `AddrSpace::getIndex()` (space.hh:332) — the
    /// index `AddrSpaceManager::insertSpace` assigns at construction:
    ///   - translator spaces (`.sla` `<spaces>` order, probed from the live
    ///     locked-spec translator via `SleighCtx::space_info`):
    ///     const=0, OTHER=1, unique=2, ram=3, register=4
    ///   - `Architecture::restoreFromSpec` appends fspec=5, iop=6, join=7
    ///     (architecture.cc:632-634, `numSpaces()` at insert time)
    ///   - `parseProcessorConfig` → `addSpacebase` appends stack=8
    ///     (architecture.cc:1013 → 566-568), still within `restoreFromSpec`.
    /// Consumers: `Override::insertDeadcodeDelay`/`hasDeadcodeDelay`
    /// (override.cc:79-105, indexed by `spc->getIndex()`) and
    /// `Heritage::getInfo` (heritage.hh:257).
    /// Overlay spaces get a dynamic index at construction (space.rs
    /// `new_overlay_space` takes the index parameter); the enum carries no
    /// per-instance storage, so Overlay reports -1. No deadcode-delay or
    /// heritage consumer accepts an Overlay space in the corpus
    /// (`bumpDeadcodeDelay` gates to processor/spacebase kinds), so the
    /// hole is unobservable.
    pub fn get_index(&self) -> i32 {
        match self {
            AddressSpace::Const => 0,
            AddressSpace::Other(id) if *id == SPACEID_OTHER => 1,
            AddressSpace::Other(id) => *id as i32,
            AddressSpace::Unique => 2,
            AddressSpace::Ram => 3,
            AddressSpace::Register => 4,
            AddressSpace::Iop => 6,
            AddressSpace::Join => 7,
            AddressSpace::Stack => 8,
            AddressSpace::Overlay => -1,
        }
    }

    // RUDRA-GLUE: inverse of `AddressSpace::get_index` over the locked
    /// x86-64 corpus space table (same provenance as `get_index` above) —
    /// stands in for `AddrSpaceManager::getSpace(i)`
    /// (translate.hh:559-561), which Rudra's `Architecture` does not own
    /// yet. Used by `Funcdata::start_processing` to resolve
    /// `Override::applyDeadCodeDelay` index entries back to spaces.
    /// Index 5 (fspec) has no enum variant (Rudra models no fspec space);
    /// a deadcode-delay override can never be installed for it
    /// (`bumpDeadcodeDelay` gates to processor/spacebase kinds), so the
    /// hole is unobservable.
    pub fn from_index(index: usize) -> Option<AddressSpace> {
        match index {
            0 => Some(AddressSpace::Const),
            1 => Some(AddressSpace::Other(SPACEID_OTHER)),
            2 => Some(AddressSpace::Unique),
            3 => Some(AddressSpace::Ram),
            4 => Some(AddressSpace::Register),
            6 => Some(AddressSpace::Iop),
            7 => Some(AddressSpace::Join),
            8 => Some(AddressSpace::Stack),
            _ => None,
        }
    }

    // RUDRA-GLUE: locked x86-64 corpus space-name table indexed by
    /// `AddrSpace::getIndex` — stands in for
    /// `AddrSpaceManager::getSpace(i)->getName()` (override.cc:51-56's
    /// message path). Same provenance as `get_index`: the live translator
    /// reports the capitalized name "OTHER" (SLEIGH `.sla` name), distinct
    /// from `AddressSpace::name`'s lowercase debug form.
    pub fn spec_space_name(index: usize) -> Option<&'static str> {
        match index {
            0 => Some("const"),
            1 => Some("OTHER"),
            2 => Some("unique"),
            3 => Some("ram"),
            4 => Some("register"),
            5 => Some("fspec"),
            6 => Some("iop"),
            7 => Some("join"),
            8 => Some("stack"),
            _ => None,
        }
    }

    // Ghidra: translate.cc:590 AddrSpaceManager::getSpaceByName
    /// Reverse of [`Self::spec_space_name`] for the enum space model: resolve
    /// a spec space name (the names `AddrSpaceManager::getSpaceByName`
    /// (translate.cc:590-597) finds in the live translator's space table)
    /// to its enum variant. "fspec" has no enum variant (the fspec space is
    /// reached through `SPACEID_*` handles), and dynamic/overlay names are
    /// unknown to the model, so both return `None` (Ghidra: null).
    pub fn from_spec_name(name: &str) -> Option<AddressSpace> {
        match name {
            "const" => Some(AddressSpace::Const),
            "OTHER" => Some(AddressSpace::Other(SPACEID_OTHER)),
            "unique" => Some(AddressSpace::Unique),
            "ram" => Some(AddressSpace::Ram),
            "register" => Some(AddressSpace::Register),
            "iop" => Some(AddressSpace::Iop),
            "join" => Some(AddressSpace::Join),
            "stack" => Some(AddressSpace::Stack),
            _ => None,
        }
    }

    // Ghidra: space.hh AddrSpace::isHeritaged
    /// Is this space heritaged (subject to SSA phi-placement)? Faithful to
    /// `AddrSpace::isHeritaged()` (space.hh). Ghidra's IPTR_CONSTANT,
    /// IPTR_FSPEC, IPTR_IOP, IPTR_JOIN are not heritaged; all others are.
    /// Rudra: Const/Iop/Join/Fspec(not modeled) are not heritaged.
    pub fn is_heritaged(&self) -> bool {
        !matches!(
            self, AddressSpace::Const | AddressSpace::Iop | AddressSpace::Join
                | AddressSpace::Other(SPACEID_OTHER)
        )
    }

    // Ghidra: space.hh:415 AddrSpace::doesDeadcode
    /// Does this space participate in dead-code analysis?  The compact
    /// `AddressSpace` projection preserves the locked constructors' flags:
    /// constant, iop/fspec, and OTHER clear `does_deadcode`; Join clears only
    /// `heritaged`, so dead-code analysis remains enabled there.
    pub fn does_deadcode(&self) -> bool {
        !matches!(
            self,
            AddressSpace::Const | AddressSpace::Iop | AddressSpace::Other(SPACEID_OTHER)
        )
    }

    /// Check if this is the internal iop space (references a PcodeOp).
    /// Ghidra: `getSpaceType()==IPTR_IOP` (space.hh:35).
    pub fn is_iop(&self) -> bool {
        matches!(self, AddressSpace::Iop)
    }

    // RUDRA-GLUE: is_big_endian (no Ghidra counterpart found)
    /// Check if this is a big-endian space
    pub fn is_big_endian(&self) -> bool {
        // Default to false, can be overridden per architecture
        false
    }

    // Ghidra: space.hh:340 AddrSpace::getWordSize
    /// Get the addressable unit size (wordsize) for this space, in bytes.
    /// Faithful to `getWordSize` over the constructors that exist in the
    /// production closure: every hardwired space passes wordsize 1
    /// (ConstantSpace space.cc:357, OtherSpace space.cc:397, UniqueSpace
    /// space.cc:428, JoinSpace space.cc:447, IopSpace op.cc:36) and the
    /// x86-64 spec spaces (ram/register/stack, sleigh_specs/x86-64.sla) are
    /// all wordsize 1. Spec spaces with wordsize>1 project only through the
    /// registry handle (see [`AddrSpace::get_word_size`]).
    pub fn word_size(&self) -> usize {
        match self {
            AddressSpace::Register | AddressSpace::Ram | AddressSpace::Stack => 1,
            AddressSpace::Unique => 1,
            AddressSpace::Const => 1,
            AddressSpace::Join | AddressSpace::Iop | AddressSpace::Overlay | AddressSpace::Other(_) => 1,
        }
    }

    // Ghidra: space.hh:348 AddrSpace::getAddrSize
    /// Get the address size for this space, in bytes. Faithful to
    /// `getAddrSize` over the constructors that build each space kind:
    /// const = sizeof(uintb) = 8 (space.cc:357), OTHER = sizeof(uintb) = 8
    /// (space.cc:397), iop = sizeof(void *) = 8 (op.cc:36), unique =
    /// UniqueSpace::SIZE = 4 (space.cc:418/428), join = sizeof(uintm) = 4
    /// (types.h:27, space.cc:447). ram/stack/overlay carry the
    /// architecture spec values, modeled with the x86-64 production sizes
    /// (8/8; an overlay copies its base space, space.cc:670) until the
    /// enum migrates onto the registry handle (ADDRESS-0001), which carries
    /// the real per-spec size (see [`AddrSpace::get_addr_size`]).
    /// register = 4 on the x86-64 oracle: heritage.cc:393/445/466 build
    /// SUBPIECE offset constants via `newConstant(addr.getAddrSize(), ...)`
    /// on register-space ranges, and the locked oracle projection emits
    /// them as `c:X:4` — 2668/2668 SUBPIECE trailing constants are width 4
    /// (SUBFLOW-SUBPIECE-WIDTH-0001 census).
    pub fn addr_size(&self) -> usize {
        match self {
            AddressSpace::Ram => 8,
            AddressSpace::Register => 4,
            AddressSpace::Unique => 4, // UniqueSpace::SIZE (space.cc:418)
            AddressSpace::Const => 8, // sizeof(uintb) (space.cc:357)
            AddressSpace::Stack => 8,
            AddressSpace::Join => 4,    // sizeof(uintm) (space.cc:447)
            AddressSpace::Iop => 8,     // sizeof(void *) (op.cc:36)
            AddressSpace::Overlay => 8, // copies its base space (space.cc:670)
            AddressSpace::Other(_) => 8, // sizeof(uintb) (space.cc:397)
        }
    }

    // RUDRA-GLUE: name (no Ghidra counterpart found)
    /// Get the name of this space
    pub fn name(&self) -> &'static str {
        match self {
            AddressSpace::Ram => "ram",
            AddressSpace::Register => "register",
            AddressSpace::Unique => "unique",
            AddressSpace::Const => "const",
            AddressSpace::Stack => "stack",
            AddressSpace::Join => "join",
            AddressSpace::Iop => "iop",
            AddressSpace::Overlay => "overlay",
            AddressSpace::Other(_) => "other",
        }
    }
}

impl fmt::Display for AddressSpace {
    // RUDRA-GLUE: fmt (no Ghidra counterpart found)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressSpace::Ram => write!(f, "ram"),
            AddressSpace::Register => write!(f, "register"),
            AddressSpace::Unique => write!(f, "unique"),
            AddressSpace::Const => write!(f, "const"),
            AddressSpace::Stack => write!(f, "stack"),
            AddressSpace::Join => write!(f, "join"),
            AddressSpace::Iop => write!(f, "iop"),
            AddressSpace::Overlay => write!(f, "overlay"),
            AddressSpace::Other(id) => write!(f, "space{}", id),
        }
    }
}

/// Constant space (for constant values)
///
/// Corresponds to Ghidra's `ConstantSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantSpace {
    /// Space ID
    pub id: SpaceId,
}

impl ConstantSpace {
    // Ghidra: space.cc:356 ConstantSpace::new
    /// Create a new constant space
    pub fn new() -> Self {
        ConstantSpace {
            id: SPACEID_CONST }
    }

    // Ghidra: space.cc:356 ConstantSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Const
    }

    // Ghidra: space.cc:380 ConstantSpace::decode
    /// Decode from string
    pub fn decode(s: &str) -> Option<Self> {
        let _id = s.parse::<SpaceId>().ok()?;
        Some(ConstantSpace::new())
    }

    // Ghidra: space.cc:364 ConstantSpace::overlapJoin
    /// Check if this overlaps with a join space
    pub fn overlap_join(&self, _offset: u64, _size: usize) -> bool {
        // Constant space doesn't overlap with joins
        false
    }

    // Ghidra: space.cc:372 ConstantSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        format!("const_space[{}]", self.id)
    }
}

impl Default for ConstantSpace {
    // Ghidra: space.cc:356 ConstantSpace::default
    fn default() -> Self {
        Self::new()
    }
}

/// Unique space (for SSA temporaries)
///
/// Corresponds to Ghidra's `UniqueSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueSpace {
    /// Space ID
    pub id: SpaceId,
    /// Next available unique offset
    next_offset: u64,
}

impl UniqueSpace {
    // Ghidra: space.cc:427 UniqueSpace::new
    /// Create a new unique space
    pub fn new() -> Self {
        UniqueSpace {
            id: SPACEID_UNIQUE,
            next_offset: 0,
        }
    }

    // Ghidra: space.cc:427 UniqueSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Unique
    }

    // Ghidra: space.cc:427 UniqueSpace::allocate
    /// Allocate a new unique offset
    pub fn allocate(&mut self, size: usize) -> u64 {
        let offset = self.next_offset;
        self.next_offset += size as u64;
        offset
    }

    // Ghidra: space.cc:427 UniqueSpace::reset
    /// Reset the allocator
    pub fn reset(&mut self) {
        self.next_offset = 0;
    }
}

impl Default for UniqueSpace {
    // Ghidra: space.cc:427 UniqueSpace::default
    fn default() -> Self {
        Self::new()
    }
}

/// Other/custom address space
///
/// Corresponds to Ghidra's `OtherSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherSpace {
    /// Space ID
    pub id: SpaceId,
    /// Space name
    pub name: String,
}

impl OtherSpace {
    // Ghidra: space.cc:396 OtherSpace::new
    /// Create a new other space
    pub fn new(id: SpaceId, name: String) -> Self {
        OtherSpace { id, name }
    }

    // Ghidra: space.cc:396 OtherSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Other(self.id)
    }

    // Ghidra: space.cc:410 OtherSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        format!("other_space[{}]:'{}'", self.id, self.name)
    }
}

// Ghidra: translate.hh:196 JoinRecord
/// A record describing how a join-space address maps to physical pieces.
#[derive(Debug, Clone)]
pub struct JoinRecord {
    pub pieces: Vec<VarnodeData>,
    pub unified: VarnodeData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: usize,
}

impl JoinRecord {
    // Ghidra: translate.hh:201 JoinRecord::numPieces
    pub fn num_pieces(&self) -> usize { self.pieces.len() }
    // Ghidra: translate.hh:202 JoinRecord::isFloatExtension
    pub fn is_float_extension(&self) -> bool { self.pieces.len() == 1 }
    // Ghidra: translate.hh:203 JoinRecord::getPiece
    pub fn get_piece(&self, i: usize) -> &VarnodeData { &self.pieces[i] }
    // Ghidra: translate.hh:204 JoinRecord::getUnified
    pub fn get_unified(&self) -> &VarnodeData { &self.unified }
}

#[derive(Clone)]
pub struct JoinDatabase {
    pub records: Vec<JoinRecord>,
    /// Ghidra `AddrSpaceManager::joinallocate` (translate.hh:233) — next
    /// offset to allocate in join space; grows by `roundsize` (16-byte
    /// multiples) per new record and never resets within one
    /// Architecture (translate.cc:706-710).
    join_allocate: u64,
}

impl JoinDatabase {
    // RUDRA-GLUE: Rust Default ctor (Ghidra uses AddrSpaceManager's vector)
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            join_allocate: 0,
        }
    }
    // Ghidra: translate.hh:232 AddrSpaceManager::findJoin
    pub fn find_join(&self, offset: u64) -> Option<&JoinRecord> {
        self.records.iter().find(|r| r.unified.offset == offset)
    }
    // Ghidra: translate.hh:234 AddrSpaceManager::addJoin
    /// Legacy alias retained for existing callers; delegates to the
    /// faithful [`JoinDatabase::find_add_join`].
    pub fn add_join(&mut self, pieces: Vec<VarnodeData>) -> u64 {
        self.find_add_join(pieces)
    }
    // Ghidra: translate.cc:671 AddrSpaceManager::findAddJoin
    /// Find a pre-existing split record, or create a new one corresponding
    /// to the input pieces (most significant to least significant).
    /// Faithful to `findAddJoin` (translate.cc:671-715): `totalsize` as the
    /// piece-size sum (the float-extension single-piece/logicalsize form is
    /// not reachable through this enum-space twin — float extensions keep
    /// their own path), dedup against the existing records by piece
    /// sequence, and allocation of the unified varnode at `join_allocate`
    /// rounded up to the next multiple of 16 (`roundsize`).
    ///
    /// Ordering note: Ghidra keeps `splitset` ordered by
    /// `JoinRecord::operator<` (space index, offset, size descending) and
    /// dedups through it; the set itself is only ever queried for identity
    /// (no iteration), so a linear equality scan over `records` is
    /// observably equivalent — `unified.offset` allocation order (the
    /// splitlist order consumers see) follows creation order in both.
    pub fn find_add_join(&mut self, pieces: Vec<VarnodeData>) -> u64 {
        let totalsize: usize = {
            let mut acc: usize = 0;
            for piece in &pieces {
                acc += piece.size;
            }
            acc
        };
        // set<JoinRecord*,JoinRecordCompare>::find(&testnode) — dedup on
        // the piece sequence (testnode.unified.size == totalsize makes
        // records whose pieces match but logical size differs still equal
        // here only when the size matches too; the 2-piece integer joins
        // of this path always have size == piece sum).
        if let Some(existing) = self.records.iter().find(|r| {
            r.pieces.len() == pieces.len()
                && r.pieces
                    .iter()
                    .zip(pieces.iter())
                    .all(|(a, b)| a.space == b.space && a.offset == b.offset && a.size == b.size)
        }) {
            return existing.unified.offset;
        }
        // uint4 roundsize = (totalsize + 15) & ~((uint4)0xf);
        let roundsize = ((totalsize + 15) & !0xfusize) as u64;
        let offset = self.join_allocate;
        self.join_allocate += roundsize;
        self.records.push(JoinRecord {
            pieces,
            unified: VarnodeData { space: AddressSpace::Join, offset, size: totalsize },
        });
        offset
    }
}

/// Registry-side join-record store, the 1:1 twin of Ghidra's
/// `AddrSpaceManager` join halves (`splitset`/`splitlist`,
/// translate.hh:234-235) plus the `JoinRecord` they hold
/// (translate.hh:196) — here with registry `AddrSpace` handles in the
/// pieces, exactly like Ghidra's `VarnodeData.space` (`AddrSpace *`,
/// pcoderaw.hh:35-37). The legacy enum-based [`JoinRecord`] above stays
/// for un-migrated consumers (`arch.rs`'s `join_db`,
/// `translate.rs`'s manager); this module is the canonical placement the
/// `JoinSpace::printRaw` specialization consumes
/// (space.cc:593 `getManager()->findJoin`).
pub mod manager_join {
    use super::{AddrSpace, SpaceVarnodeData};

    // Ghidra: translate.hh:196 JoinRecord
    /// A record describing how a join-space address maps to its physical
    /// pieces (most significant to least significant).
    #[derive(Debug, Clone)]
    pub struct JoinRecord {
        // Ghidra: translate.hh:198 pieces
        /// All the physical pieces of the symbol, most significant to least.
        pub pieces: Vec<SpaceVarnodeData>,
        // Ghidra: translate.hh:199 unified
        /// Special entry representing the entire symbol in one chunk.
        pub unified: SpaceVarnodeData,
    }

    impl JoinRecord {
        // Ghidra: translate.hh:201 JoinRecord::numPieces
        pub fn num_pieces(&self) -> usize {
            self.pieces.len()
        }
        // Ghidra: translate.hh:202 JoinRecord::isFloatExtension
        pub fn is_float_extension(&self) -> bool {
            self.pieces.len() == 1
        }
        // Ghidra: translate.hh:203 JoinRecord::getPiece
        pub fn get_piece(&self, i: usize) -> &SpaceVarnodeData {
            &self.pieces[i]
        }
        // Ghidra: translate.hh:204 JoinRecord::getUnified
        pub fn get_unified(&self) -> &SpaceVarnodeData {
            &self.unified
        }

        // Ghidra: translate.cc:172 JoinRecord::operator<
        /// Lexicographic record ordering: `unified.size` first (float
        /// extensions may share pieces at different logical sizes), then the
        /// piece sequence via `VarnodeData::operator<` (pcoderaw.hh:64-68:
        /// space index, then offset, then size DESCENDING — bigger sizes
        /// first); a shorter piece list that is a prefix of a longer one is
        /// the smaller record.
        pub fn less_than(&self, op2: &JoinRecord) -> bool {
            // Some joins may have same piece but different unified size
            // (floating point)
            if self.unified.size != op2.unified.size {
                return self.unified.size < op2.unified.size;
            }
            let mut i = 0;
            loop {
                if self.pieces.len() == i {
                    // If more pieces in op2, it is bigger (return true), if
                    // same number this==op2, return false
                    return op2.pieces.len() > i;
                }
                if op2.pieces.len() == i {
                    return false; // More pieces in -this-, so it is bigger
                }
                if self.pieces[i] != op2.pieces[i] {
                    return self.pieces[i].less_than(&op2.pieces[i]);
                }
                i += 1;
            }
        }
    }

    // RUDRA-GLUE: PartialEq derived from less_than (Ghidra has no
    // JoinRecord::operator==; the splitset dedup treats records as equal
    // when neither is less than the other, which is exactly this).
    impl PartialEq for JoinRecord {
        // RUDRA-GLUE: trait method head for the impl above.
        fn eq(&self, other: &Self) -> bool {
            !self.less_than(other) && !other.less_than(self)
        }
    }

    impl SpaceVarnodeData {
        // Ghidra: pcoderaw.hh:64 VarnodeData::operator<
        /// Ordering by the space's index, then the offset, then by size
        /// DESCENDING (big sizes come first). Uses the crate-level
        /// `PartialEq for SpaceVarnodeData` (pointer-identity space +
        /// offset + size, Ghidra `VarnodeData::operator==`,
        /// pcoderaw.hh:77) for the `!=` in Ghidra's loop.
        pub fn less_than(&self, op2: &SpaceVarnodeData) -> bool {
            if self.space != op2.space {
                return self.space.get_index() < op2.space.get_index();
            }
            if self.offset != op2.offset {
                return self.offset < op2.offset;
            }
            self.size > op2.size // BIG sizes come first
        }
    }

    // Ghidra: translate.hh:233 AddrSpaceManager::joinallocate +
    //   translate.hh:234 AddrSpaceManager::splitset +
    //   translate.hh:235 AddrSpaceManager::splitlist
    /// The manager's join-record halves plus the allocation counter.
    /// `split_set` holds every distinct split ordered by
    /// `JoinRecord::operator<` (the dedup side); `split_list` indexes the
    /// records by join address in ascending allocation order
    /// (`join_allocate` only ever grows in 16-byte-aligned steps, so a
    /// plain push_back keeps the binary search in `find_join` valid —
    /// translate.cc:713).
    #[derive(Debug, Default)]
    pub struct JoinRecordTables {
        /// Ghidra `uintb joinallocate` — next offset to allocate in the
        /// join space.
        pub join_allocate: u64,
        /// Ghidra `set<JoinRecord*,JoinRecordCompare> splitset` as a Vec
        /// sorted by `JoinRecord::operator<`.
        pub split_set: Vec<JoinRecord>,
        /// Ghidra `vector<JoinRecord*> splitlist` (ascending
        /// `unified.offset`).
        pub split_list: Vec<JoinRecord>,
    }

    impl JoinRecordTables {
        // Ghidra: translate.cc:671 AddrSpaceManager::findAddJoin
        /// Find a pre-existing split record, or create a new one for
        /// `pieces` (most significant to least significant). Faithful to
        /// `findAddJoin` (translate.cc:671-715): the four LowlevelError
        /// validations with Ghidra's exact strings, `totalsize` from
        /// `logical_size` (single piece only) or the piece-size sum, dedup
        /// against `split_set` via the record ordering, and allocation of
        /// the unified varnode at `join_allocate` rounded up to the next
        /// multiple of 16 (`roundsize`).
        ///
        /// Ghidra returns the new (or found) `JoinRecord *`; Rudra returns
        /// the unified join-space offset, from which the record stays
        /// reachable via [`JoinRecordTables::find_join`].
        pub fn find_add_join(
            &mut self,
            pieces: &[SpaceVarnodeData],
            logical_size: u32,
            joinspace: &AddrSpace,
        ) -> u64 {
            if pieces.is_empty() {
                panic!("Cannot create a join without pieces");
            }
            if pieces.len() == 1 && logical_size == 0 {
                panic!("Cannot create a single piece join without a logical size");
            }
            let totalsize: u32 = if logical_size != 0 {
                if pieces.len() != 1 {
                    panic!("Cannot specify logical size for multiple piece join");
                }
                logical_size
            } else {
                let mut acc: u32 = 0;
                for piece in pieces {
                    acc += piece.size as u32;
                }
                if acc == 0 {
                    panic!("Cannot create a zero size join");
                }
                acc
            };
            // JoinRecord testnode; testnode.pieces = pieces;
            // testnode.unified.size = totalsize;
            // set<JoinRecord*,JoinRecordCompare>::find(&testnode)
            let probe = JoinRecord {
                pieces: pieces.to_vec(),
                unified: SpaceVarnodeData {
                    space: joinspace.clone(),
                    offset: 0,
                    size: totalsize as i32,
                },
            };
            if let Ok(idx) = self
                .split_set
                .binary_search_by(|rec| rec_less_than_as_ordering(rec, &probe))
            {
                // If already in the set
                return self.split_set[idx].unified.offset;
            }
            // uint4 roundsize = (totalsize + 15) & ~((uint4)0xf);
            let roundsize = (totalsize + 15) & !0xfu32;
            // newjoin->unified.space = joinspace; .offset = joinallocate;
            // joinallocate += roundsize; .size = totalsize;
            let newjoin = JoinRecord {
                pieces: pieces.to_vec(),
                unified: SpaceVarnodeData {
                    space: joinspace.clone(),
                    offset: self.join_allocate,
                    size: totalsize as i32,
                },
            };
            self.join_allocate += roundsize as u64;
            // splitset.insert(newjoin); splitlist.push_back(newjoin);
            let pos = self
                .split_set
                .binary_search_by(|rec| rec_less_than_as_ordering(rec, &newjoin))
                .unwrap_or_else(|e| e);
            self.split_set.insert(pos, newjoin);
            self.split_list.push(self.split_set[pos].clone());
            self.split_list.last().expect("just pushed").unified.offset
        }

        // Ghidra: translate.cc:746 AddrSpaceManager::findJoin
        /// Find the JoinRecord whose unified offset is exactly `offset`.
        /// Faithful to `findJoin` (translate.cc:746-762): a binary search of
        /// `split_list` on `unified.offset`, panicking with Ghidra's
        /// `LowlevelError("Unlinked join address")` message when no record
        /// matches (the offset must have come from a findAddJoin record).
        pub fn find_join(&self, offset: u64) -> &JoinRecord {
            match self
                .split_list
                .binary_search_by_key(&offset, |r| r.unified.offset)
            {
                Ok(idx) => &self.split_list[idx],
                Err(_) => panic!("Unlinked join address"),
            }
        }
    }

    // RUDRA-GLUE: rec_less_than_as_ordering — TotalOrder adapter around
    // JoinRecord::operator< for binary_search_by; Ghidra's std::set uses
    // the same operator for its red-black tree ordering.
    fn rec_less_than_as_ordering(a: &JoinRecord, b: &JoinRecord) -> std::cmp::Ordering {
        if a.less_than(b) {
            std::cmp::Ordering::Less
        } else if b.less_than(a) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    }
}

// RUDRA-GLUE: fspec_space — Ghidra's FspecSpace stores a `FuncCallSpecs *`
// as the address OFFSET (fspec.hh:344-346: "the offset is the actual value
// of the pointer"); printRaw/encodeAttributes dereference that pointer
// (fspec.cc:2125 `FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset`). Rust
// cannot dereference a raw integer, so the registry keeps the same
// offset→object association in a side table — the exact twin of the
// `manager_join_tables` backlink that stands in for
// `getManager()->findJoin` (space.cc:593). The table carries only the two
// fields the Ghidra methods read: `name` (fspec.hh:1647) and `entryaddress`
// (fspec.hh:1648). TYPEOP-FSPEC-SPACE-0001 slice 2 re-homes the
// registration at the Funcdata callspec bank; until then the fixture (and
// only the fixture) registers entries through
// [`SpaceRegistry::register_fspec_entry`].
/// The per-offset view of a FuncCallSpecs as seen by the fspec space.
#[derive(Debug, Clone)]
pub struct FspecEntry {
    // Ghidra: fspec.hh:1647 FuncCallSpecs::name
    /// Identifier (function name) associated with the call prototype.
    pub name: String,
    // Ghidra: fspec.hh:1648 FuncCallSpecs::entryaddress
    /// First executing address of the callee; `None` is the invalid
    /// (null-base) `Address` of the C++ default constructor.
    pub entry: Option<(AddrSpace, u64)>,
}

// RUDRA-GLUE: FspecEntryTable (Ghidra needs no table — the C++ offset IS a
// dereferenceable pointer; this Vec-backed map is the Rust stand-in.)
/// Registry-side offset→entry map backing fspec-space dereferences.
#[derive(Debug, Default)]
pub struct FspecEntryTable {
    entries: std::collections::BTreeMap<u64, FspecEntry>,
}

impl FspecEntryTable {
    // RUDRA-GLUE: resolve (Ghidra dereferences `(FuncCallSpecs *)(uintp)offset`.)
    /// The entry stored for `offset`, if any.
    pub fn resolve(&self, offset: u64) -> Option<&FspecEntry> {
        self.entries.get(&offset)
    }

    // RUDRA-GLUE: register (Ghidra registers implicitly by allocating the
    // FuncCallSpecs on the heap whose address becomes the offset.)
    /// Associate `offset` with a call-spec view.
    pub fn register(&mut self, offset: u64, name: &str, entry: Option<(AddrSpace, u64)>) {
        self.entries.insert(
            offset,
            FspecEntry {
                name: name.to_string(),
                entry,
            },
        );
    }
}

/// Join space (for combining multiple spaces)
///
/// Corresponds to Ghidra's `JoinSpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinSpace {
    /// Space ID
    pub id: SpaceId,
    /// Pieces that make up the join
    pub pieces: Vec<JoinPiece>,
}

/// A piece of a join
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPiece {
    /// Address space of this piece
    pub space: AddressSpace,
    /// Offset in the space
    pub offset: u64,
    /// Size of this piece
    pub size: usize,
}

impl JoinSpace {
    // Ghidra: space.cc:446 JoinSpace::new
    /// Create a new join space
    pub fn new(pieces: Vec<JoinPiece>) -> Self {
        JoinSpace {
            id: SPACEID_JOIN,
            pieces,
        }
    }

    // Ghidra: space.cc:446 JoinSpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Join
    }

    // Ghidra: space.cc:446 JoinSpace::size
    /// Get the total size of the join
    pub fn size(&self) -> usize {
        self.pieces.iter().map(|p| p.size).sum()
    }

    // Ghidra: space.cc:446 JoinSpace::numPieces
    /// Get the number of pieces
    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    // Ghidra: space.cc:646 JoinSpace::decode
    /// Decode from string format
    pub fn decode(s: &str) -> Option<Self> {
        // Format: "piece1_space:offset:size,piece2_space:offset:size,..."
        let mut pieces = Vec::new();
        for piece_str in s.split(',') {
            let parts: Vec<&str> = piece_str.split(':').collect();
            if parts.len() != 3 {
                return None;
            }
            let space_id = parts[0].parse::<SpaceId>().ok()?;
            let offset = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()?;
            let size = parts[2].parse().ok()?;
            pieces.push(JoinPiece {
                space: AddressSpace::from_id(space_id),
                offset,
                size,
            });
        }
        Some(JoinSpace::new(pieces))
    }

    // Ghidra: space.cc:539 JoinSpace::decodeAttributes
    /// Decode from attributes (XML-style)
    pub fn decode_attributes(attrs: &[(&str, &str)]) -> Option<Self> {
        let mut pieces = Vec::new();
        for (key, value) in attrs {
            if key.starts_with("piece") {
                let parts: Vec<&str> = value.split(':').collect();
                if parts.len() >= 3 {
                    if let (Ok(space_id), Ok(offset), Ok(size)) = (
                        parts[0].parse::<SpaceId>(),
                        u64::from_str_radix(parts[1].trim_start_matches("0x"), 16),
                        parts[2].parse(),
                    ) {
                        pieces.push(JoinPiece {
                            space: AddressSpace::from_id(space_id),
                            offset,
                            size,
                        });
                    }
                }
            }
        }
        if pieces.is_empty() {
            None
        } else {
            Some(JoinSpace::new(pieces))
        }
    }

    // Ghidra: space.cc:502 JoinSpace::encodeAttributes
    /// Encode to attributes (XML-style)
    pub fn encode_attributes(&self) -> Vec<(String, String)> {
        self.pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| {
                (
                    format!("piece{}", i),
                    format!(
                        "{}:{:x}:{}", piece.space.space_id(), piece.offset, piece.size
                    ),
                )
            })
            .collect()
    }

    // Ghidra: space.cc:454 JoinSpace::overlapJoin
    /// Check if this overlaps with another join
    pub fn overlap_join(&self, offset: u64, size: usize) -> bool {
        let end = offset + size as u64;
        let self_size = self.size() as u64;
        offset < self_size && end > 0
    }

    // Ghidra: space.cc:590 JoinSpace::printRaw
    /// Print raw representation
    pub fn print_raw(&self) -> String {
        let pieces_str: Vec<String> = self
            .pieces
            .iter()
            .map(|p| format!("{}:{:x}:{}", p.space, p.offset, p.size))
            .collect();
        format!("join_space[{}]", pieces_str.join(","))
    }

    // Ghidra: space.cc:611 JoinSpace::read
    /// Read value from the joined pieces
    pub fn read(&self, _offset: u64, _size: usize) -> Vec<u8> {
        // Placeholder: would need actual memory context to read
        vec![0; _size]
    }
}

/// Overlay space (for overlaying another space)
///
/// Corresponds to Ghidra's `OverlaySpace` in space.hh
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlaySpace {
    /// Space ID
    pub id: SpaceId,
    /// Base space being overlaid
    pub base_space: AddressSpace,
    /// Name of the overlay
    pub name: String,
}

impl OverlaySpace {
    // Ghidra: space.cc:654 OverlaySpace::new
    /// Create a new overlay space
    pub fn new(id: SpaceId, base_space: AddressSpace, name: String) -> Self {
        OverlaySpace {
            id,
            base_space,
            name,
        }
    }

    // Ghidra: space.cc:654 OverlaySpace::space
    /// Get the space type
    pub fn space(&self) -> AddressSpace {
        AddressSpace::Overlay
    }

    // Ghidra: space.cc:654 OverlaySpace::base
    /// Get the base space
    pub fn base(&self) -> AddressSpace {
        self.base_space
    }

    // Ghidra: space.cc:661 OverlaySpace::decode
    /// Decode from string format "id:base_space_id:name"
    pub fn decode(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        let id = parts[0].parse::<SpaceId>().ok()?;
        let base_space_id = parts[1].parse::<SpaceId>().ok()?;
        let name = parts[2].to_string();
        Some(OverlaySpace::new(
            id,
            AddressSpace::from_id(base_space_id),
            name,
        ))
    }
}

// ============================================================================
// Architecture-owned AddrSpace registry (SPACE-0001)
// ----------------------------------------------------------------------------
// The enum `AddressSpace` above is Rudra's legacy fixed-enum bridge kept only
// so un-migrated consumers keep compiling. Everything below is the 1:1 port of
// Ghidra's architecture-owned address-space model:
//   - `space.hh:30 spacetype` / `space.hh:85 AddrSpace` flag bits
//   - `AddrSpace` runtime record + derived space constructors (space.cc)
//   - `SpacebaseSpace` base-register state (translate.cc:57-133)
//   - `AddrSpaceManager` as `SpaceRegistry` (translate.cc:235-784)
// Downstream consumers (Address/Varnode/Range keys) migrate in ADDRESS-0001.
// ============================================================================

// Ghidra: space.hh:30 spacetype
/// Fundamental address space types. Faithful to the `spacetype` enum
/// (space.hh:30-38): every address space must be one of these core types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SpaceType {
    /// `IPTR_CONSTANT = 0` — special space to represent constants.
    Constant = 0,
    /// `IPTR_PROCESSOR = 1` — normal spaces modelled by processor.
    Processor = 1,
    /// `IPTR_SPACEBASE = 2` — addresses are offsets off a base register.
    SpaceBase = 2,
    /// `IPTR_INTERNAL = 3` — internally managed temporary space.
    Internal = 3,
    /// `IPTR_FSPEC = 4` — special internal FuncCallSpecs reference.
    Fspec = 4,
    /// `IPTR_IOP = 5` — special internal PcodeOp reference.
    Iop = 5,
    /// `IPTR_JOIN = 6` — special virtual space for split variables.
    Join = 6,
}

// RUDRA-GLUE: space_flags (Ghidra models these as the anonymous enum inside
// class AddrSpace, space.hh:85-98; Rust needs a free-standing const module
// because the record below is not a class namespace.)
/// Address-space attribute flags. Values are the `AddrSpace` enum constants
/// (space.hh:85-98).
pub mod space_flags {
    /// `AddrSpace::big_endian` — space is big endian if set (space.hh:86).
    pub const BIG_ENDIAN: u32 = 1;
    /// `AddrSpace::heritaged` — this space is heritaged (space.hh:87).
    pub const HERITAGED: u32 = 2;
    /// `AddrSpace::does_deadcode` — dead-code analysis is done (space.hh:88).
    pub const DOES_DEADCODE: u32 = 4;
    /// `AddrSpace::programspecific` — specific to a loadimage (space.hh:89).
    pub const PROGRAMSPECIFIC: u32 = 8;
    /// `AddrSpace::reverse_justification` (space.hh:90).
    pub const REVERSE_JUSTIFICATION: u32 = 16;
    /// `AddrSpace::formal_stackspace` (space.hh:91).
    pub const FORMAL_STACKSPACE: u32 = 0x20;
    /// `AddrSpace::overlay` — this space overlays another (space.hh:92).
    pub const OVERLAY: u32 = 0x40;
    /// `AddrSpace::overlaybase` — base of overlay space(s) (space.hh:93).
    pub const OVERLAYBASE: u32 = 0x80;
    /// `AddrSpace::truncated` (space.hh:94).
    pub const TRUNCATED: u32 = 0x100;
    /// `AddrSpace::hasphysical` (space.hh:95).
    pub const HASPHYSICAL: u32 = 0x200;
    /// `AddrSpace::is_otherspace` — quick OtherSpace check (space.hh:96).
    pub const IS_OTHERSPACE: u32 = 0x400;
    /// `AddrSpace::has_nearpointers` (space.hh:97).
    pub const HAS_NEARPOINTERS: u32 = 0x800;
}

// RUDRA-GLUE: reserved space-name/index constants (Ghidra declares these as
// static members `ConstantSpace::NAME` etc.; Rust uses free consts so the
/// handle type below stays a plain data carrier.)
// Ghidra: space.cc:347 ConstantSpace::NAME
pub const CONSTANT_SPACE_NAME: &str = "const";
// Ghidra: space.cc:349 ConstantSpace::INDEX
pub const CONSTANT_SPACE_INDEX: i32 = 0;
// Ghidra: space.cc:386 OtherSpace::NAME
pub const OTHER_SPACE_NAME: &str = "OTHER";
// Ghidra: space.cc:388 OtherSpace::INDEX
pub const OTHER_SPACE_INDEX: i32 = 1;
// Ghidra: space.cc:416 UniqueSpace::NAME
pub const UNIQUE_SPACE_NAME: &str = "unique";
// Ghidra: space.cc:418 UniqueSpace::SIZE
pub const UNIQUE_SPACE_SIZE: u32 = 4;
// Ghidra: fspec.cc:2107 FspecSpace::NAME
/// Reserved name for the \b fspec space (fspec.cc:2107).
pub const FSPEC_SPACE_NAME: &str = "fspec";
// Ghidra: op.cc:24 IopSpace::NAME
/// Reserved name for the \b iop space (op.cc:24).
pub const IOP_SPACE_NAME: &str = "iop";
// RUDRA-GLUE: reserved EXTERNAL space-name constant (Ghidra declares it on
// the platform side — Java `AddressSpace.EXTERNAL_SPACE` =
// `new GenericAddressSpace("EXTERNAL", 32, TYPE_EXTERNAL, 0)`,
// AddressSpace.java:76-81 — while the locked 12.0.4 decompiler oracle has
// no ExternalSpace counterpart: `spacetype` (space.hh:30-38) ends at
// IPTR_JOIN and no decompiler code registers a space of this name. The
// import-stub addresses themselves live in an artificial EXTERNAL *memory
// block* in the default space (ElfProgramBuilder.java:1532-1556), which is
// what the EXTERNAL-STUB-SUPPORT-0001 stub projection keys on. Rust needs
// the free const for the same reason as the other reserved names.)
/// Reserved name for the Ghidra-platform external space ("EXTERNAL",
/// AddressSpace.java:80).
pub const EXTERNAL_SPACE_NAME: &str = "EXTERNAL";

// RUDRA-GLUE: calc_mask (Ghidra's helper lives in address.hh/address.cc,
// outside space.cc; ported here because calcScaleMask depends on it.)
/// Mask covering `size` bytes, faithful to `calc_mask` (address.hh:499) with
/// the 8-byte `uintb` table `uintbmasks` (address.cc:633): sizes are clamped
/// to 8.
pub fn calc_mask(size: i32) -> u64 {
    const UINTBMASKS: [u64; 9] = [
        0,
        0xff,
        0xffff,
        0xffffff,
        0xffffffff,
        0xffffffffff,
        0xffffffffffff,
        0xffffffffffffff,
        0xffffffffffffffff,
    ];
    UINTBMASKS[if (size as u32) < 8 { size as usize } else { 8 }]
}

// RUDRA-GLUE: attrib_space/attrib_offset/attrib_size — Ghidra declares the
// marshal attribute ids once in marshal.cc's global table (ATTRIB_SPACE
// marshal.cc:1247, ATTRIB_OFFSET marshal.cc:1243, ATTRIB_SIZE
// marshal.cc:1246); Rust has no global constructor table, so the locked
// ids are minted through these per-call constructors (the same pattern as
// translate.rs's ATTRIB_SPACE and pcodeparse.rs's elem_addr).
// Ghidra: marshal.cc:1247 ATTRIB_SPACE
/// Marshaling attribute "space" (locked id 20).
pub fn attrib_space() -> crate::marshal::AttributeId {
    crate::marshal::AttributeId::new("space", 20)
}
// Ghidra: marshal.cc:1243 ATTRIB_OFFSET
/// Marshaling attribute "offset" (locked id 16).
pub fn attrib_offset() -> crate::marshal::AttributeId {
    crate::marshal::AttributeId::new("offset", 16)
}
// Ghidra: marshal.cc:1246 ATTRIB_SIZE
/// Marshaling attribute "size" (locked id 19).
pub fn attrib_size() -> crate::marshal::AttributeId {
    crate::marshal::AttributeId::new("size", 19)
}
// Ghidra: space.cc:24 ATTRIB_LOGICALSIZE
/// Marshaling attribute "logicalsize" (locked id 92) — the logical size of
/// a single-piece join (float extension).
pub fn attrib_logicalsize() -> crate::marshal::AttributeId {
    crate::marshal::AttributeId::new("logicalsize", 92)
}
// Ghidra: space.cc:30 ATTRIB_PIECE
/// Marshaling attribute "piece" (locked id 94; indexed slots 94+ hold the
/// join pieces, most significant first).
pub fn attrib_piece() -> crate::marshal::AttributeId {
    crate::marshal::AttributeId::new("piece", 94)
}

// Ghidra: space.hh:233 JoinSpace::MAX_PIECES
/// Maximum number of pieces that can be marshaled in one join address.
pub const MAX_PIECES: usize = 64;

// RUDRA-GLUE: SpaceVarnodeData (Ghidra's VarnodeData in translate.hh carries
// an `AddrSpace *`; the legacy enum-based `VarnodeData` above cannot express
// that, so the registry uses this handle-based twin until ADDRESS-0001
// unifies them.)
/// Memory location with a registry space handle, offset, and size.
#[derive(Debug, Clone)]
pub struct SpaceVarnodeData {
    /// Address space of the location (Ghidra: `AddrSpace *space`).
    pub space: AddrSpace,
    /// Offset in the space (Ghidra: `uintb offset`).
    pub offset: u64,
    /// Size in bytes (Ghidra: `int4 size`).
    pub size: i32,
}

impl PartialEq for SpaceVarnodeData {
    // RUDRA-GLUE: Ghidra compares VarnodeData members with default
    // operator== (space pointer identity, offset, size).
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space && self.offset == other.offset && self.size == other.size
    }
}
impl Eq for SpaceVarnodeData {}

// RUDRA-GLUE: SpacebaseState (Ghidra keeps these as private fields of the
// SpacebaseSpace subclass, translate.hh:173-178; the Rust record flattens the
// subclass state into an Option so one handle type covers all spaces.)
/// Base-register state carried only by `IPTR_SPACEBASE` spaces.
#[derive(Debug, Clone)]
struct SpacebaseState {
    /// Containing space (`translate.hh:174 contain`).
    contain: Option<AddrSpace>,
    /// True if a base register has been attached (`translate.hh:175`).
    has_base_register: bool,
    /// True if stack grows in negative direction (`translate.hh:176`).
    is_negative_stack: bool,
    /// Location data of the base register (`translate.hh:177 baseloc`).
    base_loc: SpaceVarnodeData,
    /// Original base register before any truncation (`translate.hh:178`).
    base_orig: SpaceVarnodeData,
}

// RUDRA-GLUE: AddrSpaceInner (Ghidra keeps this state directly in the
// AddrSpace class, space.hh:99-116 + the derived-class fields; Rust hides it
// behind a shared handle so two managers can reference one space like
// Ghidra's raw pointers with refcounting.)
/// Runtime state of one address space.
#[derive(Debug, Clone)]
struct AddrSpaceInner {
    /// Type of space (space.hh:100 `type`).
    space_type: SpaceType,
    /// Attribute flags (space.hh:104 `flags`).
    flags: u32,
    /// Highest (byte) offset into this space (space.hh:105 `highest`).
    highest: u64,
    /// Offset below which we don't search for pointers (space.hh:106).
    pointer_lower_bound: u64,
    /// Offset above which we don't search for pointers (space.hh:107).
    pointer_upper_bound: u64,
    /// Shortcut character for printing (space.hh:108 `shortcut`).
    shortcut: char,
    /// Name of this space (space.hh:110 `name`).
    name: String,
    /// Size of an address into this space in bytes (space.hh:111).
    address_size: u32,
    /// Size of unit being addressed, 1=byte (space.hh:112 `wordsize`).
    word_size: u32,
    /// Smallest size of a pointer into this space (space.hh:113).
    minimum_pointer_size: i32,
    /// An integer identifier for the space (space.hh:114 `index`).
    index: i32,
    /// Delay in heritaging this space (space.hh:115 `delay`).
    delay: i32,
    /// Delay before deadcode removal is allowed (space.hh:116).
    deadcode_delay: i32,
    /// Number of managers using this space (space.hh:103 `refcount`).
    refcount: i32,
    /// Spacebase-subclass state; `None` for non-IPTR_SPACEBASE spaces.
    spacebase: Option<SpacebaseState>,
    // Ghidra: space.hh:118 AddrSpace::manage (manager backlink, fspec half).
    /// Weak link to the owning manager's fspec-entry table, wired when the
    /// registry inserts this space (Rudra's constructors take no manager, so
    /// `insertSpace` is the association point). Only the fspec space reads
    /// it — `FspecSpace::printRaw`/`encodeAttributes` dereference the offset
    /// as a `FuncCallSpecs *` (fspec.cc:2125/2130/2145/2155); `None` on
    /// every other kind and on an fspec space that was never registered.
    fspec_table: Option<Weak<RefCell<FspecEntryTable>>>,
    // Ghidra: space.hh:118 AddrSpace::manage (manager backlink, join half).
    /// Weak link to the owning manager's join-record tables, wired when the
    /// registry inserts this space (Rudra's constructors take no manager, so
    /// `insertSpace` is the association point). Only the join space reads
    /// it — `JoinSpace::printRaw` resolves its pieces through
    /// `getManager()->findJoin` (space.cc:593); `None` on every other kind
    /// and on a join space that was never registered.
    manager_join_tables: Option<Weak<RefCell<manager_join::JoinRecordTables>>>,
}

/// Architecture-owned address-space handle. Faithful to Ghidra's `AddrSpace`
/// (space.hh:82): the handle is a shared reference to the space record, so
/// two `SpaceRegistry`s may manage the same space (Ghidra: shared `AddrSpace*`
/// with `refcount`), and flag mutations performed through one manager are
/// visible through every handle (e.g. `insertSpace` setting `overlaybase` on
/// the overlaid base space).
///
/// An absent space is represented by `Option<AddrSpace>` = `None`, matching
/// Ghidra's null `AddrSpace*` (the "invalid address" state of
/// `Address::Address()`, address.hh:262).
#[derive(Clone)]
pub struct AddrSpace(Rc<RefCell<AddrSpaceInner>>);

impl AddrSpace {
    // Ghidra: space.cc:58 AddrSpace::AddrSpace
    /// Initialize an address space with its basic attributes. Faithful to the
    /// full constructor (space.cc:58-81): only `hasphysical` is honored from
    /// `fl`, `big_endian` is set from `big_end`, `heritaged|does_deadcode`
    /// are always set, `shortcut` starts as the unassigned placeholder `' '`,
    /// and `calcScaleMask` runs at the end.
    pub fn new_space(
        space_type: SpaceType,
        name: &str,
        big_end: bool,
        size: u32,
        ws: u32,
        ind: i32,
        fl: u32,
        dl: i32,
        dead: i32,
    ) -> Self {
        let mut inner = AddrSpaceInner {
            space_type,
            flags: fl & space_flags::HASPHYSICAL,
            highest: 0,
            pointer_lower_bound: 0,
            pointer_upper_bound: 0,
            shortcut: ' ',
            name: name.to_string(),
            address_size: size,
            word_size: ws,
            minimum_pointer_size: 0,
            index: ind,
            delay: dl,
            deadcode_delay: dead,
            refcount: 0,
            spacebase: None,
            manager_join_tables: None,
            fspec_table: None,
        };
        if big_end {
            inner.flags |= space_flags::BIG_ENDIAN;
        }
        inner.flags |= space_flags::HERITAGED | space_flags::DOES_DEADCODE;
        let handle = AddrSpace(Rc::new(RefCell::new(inner)));
        handle.calc_scale_mask();
        handle
    }

    // Ghidra: space.cc:356 ConstantSpace::ConstantSpace
    /// Construct the unique constant space. Faithful to `ConstantSpace`
    /// (space.cc:356-362): name "const", index 0, address size `sizeof(uintb)`
    /// = 8 on a 64-bit host, word size 1, delay/deadcodedelay 0, then
    /// `heritaged|does_deadcode|big_endian` cleared and endianness set from
    /// the host (`HOST_ENDIAN`, types.h:43/50).
    pub fn new_constant_space(host_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Constant,
            CONSTANT_SPACE_NAME,
            false,
            8, // sizeof(uintb) on the 64-bit oracle host
            1,
            CONSTANT_SPACE_INDEX,
            0,
            0,
            0,
        );
        spc.clear_flags(
            space_flags::HERITAGED | space_flags::DOES_DEADCODE | space_flags::BIG_ENDIAN,
        );
        if host_big_endian {
            spc.set_flags(space_flags::BIG_ENDIAN);
        }
        spc
    }

    // Ghidra: space.cc:396 OtherSpace::OtherSpace
    /// Construct the \b other space. Faithful to `OtherSpace`
    /// (space.cc:396-401): name "OTHER", index 1 (`OtherSpace::INDEX`, which
    /// the C++ constructor hardcodes regardless of `ind`), address size
    /// `sizeof(uintb)` = 8, then `heritaged|does_deadcode` cleared and
    /// `is_otherspace` set.
    pub fn new_other_space() -> Self {
        let spc = Self::new_space(
            SpaceType::Processor,
            OTHER_SPACE_NAME,
            false,
            8, // sizeof(uintb) on the 64-bit oracle host
            1,
            OTHER_SPACE_INDEX,
            0,
            0,
            0,
        );
        spc.clear_flags(space_flags::HERITAGED | space_flags::DOES_DEADCODE);
        spc.set_flags(space_flags::IS_OTHERSPACE);
        spc
    }

    // Ghidra: space.cc:427 UniqueSpace::UniqueSpace
    /// Construct the \b unique space. Faithful to `UniqueSpace`
    /// (space.cc:427-431): name "unique", fixed size 4
    /// (`UniqueSpace::SIZE`), word size 1, endianness from the processor
    /// translator (`t->isBigEndian()` passed here as `target_big_endian`),
    /// delay/deadcodedelay 0, then `hasphysical` set.
    pub fn new_unique_space(ind: i32, fl: u32, target_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Internal,
            UNIQUE_SPACE_NAME,
            target_big_endian,
            UNIQUE_SPACE_SIZE,
            1,
            ind,
            fl,
            0,
            0,
        );
        spc.set_flags(space_flags::HASPHYSICAL);
        spc
    }

    // Ghidra: space.cc:446 JoinSpace::JoinSpace
    /// Construct the \b join space. Faithful to `JoinSpace`
    /// (space.cc:446-452): name "join", address size `sizeof(uintm)` = 4
    /// (types.h:27), endianness from the translator, delay/deadcodedelay 0,
    /// then `heritaged` cleared (the space is never heritaged but does
    /// dead-code analysis).
    pub fn new_join_space(ind: i32, target_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Join,
            "join",
            target_big_endian,
            4, // sizeof(uintm), types.h:26-27
            1,
            ind,
            0,
            0,
            0,
        );
        spc.clear_flags(space_flags::HERITAGED);
        spc
    }

    // Ghidra: op.cc:33 IopSpace::IopSpace
    /// Construct the \b iop space. Faithful to `IopSpace` (op.cc:33-39):
    /// name "iop", address size `sizeof(void *)` = 8, word size 1, delay 1,
    /// deadcodedelay 1, then `heritaged|does_deadcode|big_endian` cleared and
    /// endianness set from the host.
    pub fn new_iop_space(ind: i32, host_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Iop,
            "iop",
            false,
            8, // sizeof(void *) on the 64-bit oracle host
            1,
            ind,
            0,
            1,
            1,
        );
        spc.clear_flags(
            space_flags::HERITAGED | space_flags::DOES_DEADCODE | space_flags::BIG_ENDIAN,
        );
        if host_big_endian {
            spc.set_flags(space_flags::BIG_ENDIAN);
        }
        spc
    }

    // Ghidra: fspec.cc:2116 FspecSpace::FspecSpace
    /// Construct the \b fspec space. Faithful to `FspecSpace`
    /// (fspec.cc:2116-2122): name "fspec", address size `sizeof(void *)` = 8,
    /// word size 1, delay 1, deadcodedelay 1, then
    /// `heritaged|does_deadcode|big_endian` cleared and endianness set from
    /// the host.
    pub fn new_fspec_space(ind: i32, host_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Fspec,
            "fspec",
            false,
            8, // sizeof(void *) on the 64-bit oracle host
            1,
            ind,
            0,
            1,
            1,
        );
        spc.clear_flags(
            space_flags::HERITAGED | space_flags::DOES_DEADCODE | space_flags::BIG_ENDIAN,
        );
        if host_big_endian {
            spc.set_flags(space_flags::BIG_ENDIAN);
        }
        spc
    }

    // Ghidra: translate.cc:57 SpacebaseSpace::SpacebaseSpace
    /// Construct a virtual space (usually the stack). Faithful to the
    /// `SpacebaseSpace` constructor (translate.cc:57-66): word size is taken
    /// from the containing space (`base->getWordSize()`), delay and
    /// deadcodedelay are both `dl`, endianness comes from the translator
    /// (`t->isBigEndian()` passed as `target_big_endian`), `contain` is the
    /// base space, `hasbaseregister` starts false, `isNegativeStack` defaults
    /// true, and `formal_stackspace` is set when `is_formal`.
    pub fn new_spacebase_space(
        nm: &str,
        ind: i32,
        sz: u32,
        base: &AddrSpace,
        dl: i32,
        is_formal: bool,
        target_big_endian: bool,
    ) -> Self {
        let mut inner = AddrSpaceInner {
            space_type: SpaceType::SpaceBase,
            flags: 0 & space_flags::HASPHYSICAL,
            highest: 0,
            pointer_lower_bound: 0,
            pointer_upper_bound: 0,
            shortcut: ' ',
            name: nm.to_string(),
            address_size: sz,
            word_size: base.get_word_size(),
            minimum_pointer_size: 0,
            index: ind,
            delay: dl,
            deadcode_delay: dl,
            refcount: 0,
            manager_join_tables: None,
            fspec_table: None,
            spacebase: Some(SpacebaseState {
                contain: Some(base.clone()),
                has_base_register: false,
                is_negative_stack: true,
                base_loc: SpaceVarnodeData {
                    space: base.clone(),
                    offset: 0,
                    size: 0,
                },
                base_orig: SpaceVarnodeData {
                    space: base.clone(),
                    offset: 0,
                    size: 0,
                },
            }),
        };
        if target_big_endian {
            inner.flags |= space_flags::BIG_ENDIAN;
        }
        inner.flags |= space_flags::HERITAGED | space_flags::DOES_DEADCODE;
        if is_formal {
            inner.flags |= space_flags::FORMAL_STACKSPACE;
        }
        let handle = AddrSpace(Rc::new(RefCell::new(inner)));
        handle.calc_scale_mask();
        handle
    }

    // Ghidra: space.cc:661 OverlaySpace::decode
    /// Construct an overlay space over `base`. Faithful to the field flow of
    /// `OverlaySpace::decode` (space.cc:661-680): the partial constructor
    /// (space.cc:654-659) sets `baseSpace` and the `overlay` flag, then the
    /// decode body copies `addressSize`/`wordsize`/`delay`/`deadcodedelay`
    /// from the base space, reruns `calcScaleMask`, and propagates
    /// `big_endian`/`hasphysical` from the base. Name and index are supplied
    /// directly instead of decoded from XML until the marshal decoder lands
    /// (MARSHAL-XML-TEXT-0001). The contain link is stored in the shared
    /// `SpacebaseState` slot (Ghidra keeps it in the `OverlaySpace::
    /// baseSpace` subclass field) so `getContain` reports it.
    pub fn new_overlay_space(name: &str, index: i32, base: &AddrSpace) -> Self {
        let mut inner = AddrSpaceInner {
            space_type: SpaceType::Processor,
            flags: 0 & space_flags::HASPHYSICAL,
            highest: 0,
            pointer_lower_bound: 0,
            pointer_upper_bound: 0,
            shortcut: ' ',
            name: name.to_string(),
            address_size: base.get_addr_size(),
            word_size: base.get_word_size(),
            minimum_pointer_size: 0,
            index,
            delay: base.get_delay(),
            deadcode_delay: base.get_deadcode_delay(),
            refcount: 0,
            manager_join_tables: None,
            fspec_table: None,
            spacebase: Some(SpacebaseState {
                contain: Some(base.clone()),
                has_base_register: false,
                is_negative_stack: true,
                base_loc: SpaceVarnodeData {
                    space: base.clone(),
                    offset: 0,
                    size: 0,
                },
                base_orig: SpaceVarnodeData {
                    space: base.clone(),
                    offset: 0,
                    size: 0,
                },
            }),
        };
        // Partial-constructor flag (space.cc:658) plus the base-class
        // always-on flags (space.cc:95).
        inner.flags |= space_flags::OVERLAY | space_flags::HERITAGED | space_flags::DOES_DEADCODE;
        // Decode-body propagation (space.cc:676-679).
        if base.is_big_endian() {
            inner.flags |= space_flags::BIG_ENDIAN;
        }
        if base.has_physical() {
            inner.flags |= space_flags::HASPHYSICAL;
        }
        let handle = AddrSpace(Rc::new(RefCell::new(inner)));
        handle.calc_scale_mask();
        handle
    }

    // Ghidra: space.cc:87 AddrSpace::AddrSpace(m,t,tp)
    /// Partial constructor for initializing a space via decode. Faithful to
    /// the XML partial constructor (space.cc:87-98): `refcount` 0, the given
    /// type, `flags = heritaged|does_deadcode` (always on unless a derived
    /// partial constructor turns them off), `wordsize` 1,
    /// `minimumPointerSize` 0, `shortcut` the unassigned placeholder `' '`,
    /// and endianness left for the decode attributes. Ghidra leaves
    /// `name`/`addressSize`/`index`/`delay`/`deadcodedelay` unwritten until
    /// `decodeBasicAttributes` (space.cc:304) fills them; Rust zero/empty
    /// initializes those because the record has no uninitialized state.
    pub fn new_for_decode(space_type: SpaceType) -> Self {
        let inner = AddrSpaceInner {
            space_type,
            flags: space_flags::HERITAGED | space_flags::DOES_DEADCODE,
            highest: 0,
            pointer_lower_bound: 0,
            pointer_upper_bound: 0,
            shortcut: ' ',
            name: String::new(),
            address_size: 0,
            word_size: 1,
            minimum_pointer_size: 0,
            index: 0,
            delay: 0,
            deadcode_delay: 0,
            refcount: 0,
            manager_join_tables: None,
            fspec_table: None,
            spacebase: None,
        };
        AddrSpace(Rc::new(RefCell::new(inner)))
    }

    // Ghidra: space.cc:403 OtherSpace::OtherSpace(m,t)
    /// Partial \b other constructor for decode. Faithful to the decode
    /// partial constructor (space.cc:403-408): base partial space of type
    /// `IPTR_PROCESSOR`, then `heritaged|does_deadcode` cleared and
    /// `is_otherspace` set.
    pub fn new_other_space_for_decode() -> Self {
        let spc = Self::new_for_decode(SpaceType::Processor);
        spc.clear_flags(space_flags::HERITAGED | space_flags::DOES_DEADCODE);
        spc.set_flags(space_flags::IS_OTHERSPACE);
        spc
    }

    // Ghidra: space.cc:433 UniqueSpace::UniqueSpace(m,t)
    /// Partial \b unique constructor for decode. Faithful to the decode
    /// partial constructor (space.cc:433-437): base partial space of type
    /// `IPTR_INTERNAL`, then `hasphysical` set.
    pub fn new_unique_space_for_decode() -> Self {
        let spc = Self::new_for_decode(SpaceType::Internal);
        spc.set_flags(space_flags::HASPHYSICAL);
        spc
    }

    // Ghidra: space.cc:654 OverlaySpace::OverlaySpace(m,t)
    /// Partial overlay constructor for decode. Faithful to the decode
    /// partial constructor (space.cc:654-659): base partial space of type
    /// `IPTR_PROCESSOR`, `baseSpace` null, then the `overlay` flag set. The
    /// `baseSpace` link is attached by `OverlaySpace::decode`
    /// (space.cc:661-680) — see [`SpaceRegistry::decode_space`].
    pub fn new_overlay_space_for_decode() -> Self {
        let spc = Self::new_for_decode(SpaceType::Processor);
        spc.set_flags(space_flags::OVERLAY);
        spc
    }

    // Ghidra: translate.cc:73 SpacebaseSpace::SpacebaseSpace(m,t)
    /// Partial spacebase constructor for decode. Faithful to the decode
    /// partial constructor (translate.cc:73-79): base partial space of type
    /// `IPTR_SPACEBASE`, `hasbaseregister` false, `isNegativeStack` true,
    /// `contain` null, and the `programspecific` flag set
    /// (full-constructor spaces never set it — only the decode path does).
    /// The Rust record keeps `spacebase: None` until `set_contain` attaches
    /// the containing space: `numSpacebase`/`getSpacebase` (which throw
    /// without a base register), `stackGrowsNegative` (base-impl true =
    /// the partial ctor's `isNegativeStack` default), and `getContain`
    /// (null) all observe the same state as the C++ partial constructor.
    pub fn new_spacebase_space_for_decode() -> Self {
        let spc = Self::new_for_decode(SpaceType::SpaceBase);
        spc.set_flags(space_flags::PROGRAMSPECIFIC);
        spc
    }

    // Ghidra: space.cc:304 AddrSpace::decodeBasicAttributes
    /// Walk the attributes of the current element and recover all the
    /// properties defining this space. Faithful to
    /// `decodeBasicAttributes` (space.cc:304-337): `deadcodedelay` is reset
    /// to -1 first; the attribute walk reads name/index/size/wordsize/
    /// bigendian/delay/deadcodedelay/physical; a missing `deadcodedelay`
    /// falls back to the final `delay`; and `calcScaleMask` runs at the
    /// end. Dispatch is by attribute name through the decoder's id→name
    /// table (the in-tree decode pattern established by
    /// `SpacebaseSpace::decode_basic_attributes`, translate.rs).
    pub fn decode_basic_attributes(&self, decoder: &mut dyn crate::marshal::Decoder) {
        {
            let mut inner = self.0.borrow_mut();
            inner.deadcode_delay = -1;
        }
        loop {
            let id = decoder.next_attribute_id();
            if id == 0 {
                break;
            }
            let name = decoder.attribute_name(id).unwrap_or_default();
            match name.as_str() {
                "name" => {
                    let value = decoder.read_string();
                    self.0.borrow_mut().name = value;
                }
                "index" => {
                    let value = decoder.read_signed_integer() as i32;
                    self.0.borrow_mut().index = value;
                }
                "size" => {
                    let value = decoder.read_signed_integer() as u32;
                    self.0.borrow_mut().address_size = value;
                }
                "wordsize" => {
                    let value = decoder.read_unsigned_integer() as u32;
                    self.0.borrow_mut().word_size = value;
                }
                "bigendian" => {
                    if decoder.read_bool() {
                        self.set_flags(space_flags::BIG_ENDIAN);
                    }
                }
                "delay" => {
                    let value = decoder.read_signed_integer() as i32;
                    self.0.borrow_mut().delay = value;
                }
                "deadcodedelay" => {
                    let value = decoder.read_signed_integer() as i32;
                    self.0.borrow_mut().deadcode_delay = value;
                }
                "physical" => {
                    if decoder.read_bool() {
                        self.set_flags(space_flags::HASPHYSICAL);
                    }
                }
                _ => {
                    // Skip the unknown attribute's value.
                    let _ = decoder.read_string();
                }
            }
        }
        let delay = self.0.borrow().delay;
        let mut inner = self.0.borrow_mut();
        if inner.deadcode_delay == -1 {
            inner.deadcode_delay = delay; // If deadcodedelay attribute not present, set it to delay
        }
        drop(inner);
        self.calc_scale_mask();
    }

    // Ghidra: space.cc:339 AddrSpace::decode
    /// Restore the space from an open element. Faithful to the base
    /// `decode` (space.cc:339-345), which serves the `<space>`,
    /// `<space_other>`, and `<space_unique>` tags (their classes have no
    /// decode override): open the element, run `decodeBasicAttributes`, and
    /// close it. The `<space_base>` and `<space_overlay>` variants are
    /// handled by [`SpaceRegistry::decode_space`]
    /// (translate.cc:126/661) because they read extra space-reference
    /// attributes through the manager. The four never-decoded special
    /// spaces throw exactly like their C++ overrides: ConstantSpace
    /// (space.cc:380), FspecSpace (fspec.cc:2166), IopSpace (op.cc:61) and
    /// JoinSpace (space.cc:646) — mapped to the deterministic panics this
    /// file uses for LowlevelError.
    pub fn decode(&self, decoder: &mut dyn crate::marshal::Decoder) {
        match self.get_type() {
            SpaceType::Constant => panic!("Should never decode the constant space"),
            SpaceType::Fspec => panic!("Should never decode fspec space from stream"),
            SpaceType::Iop => panic!("Should never decode iop space from stream"),
            SpaceType::Join => panic!("Should never decode join space"),
            _ => {}
        }
        let elem_id = decoder.open_element();
        self.decode_basic_attributes(decoder);
        decoder.close_element(elem_id);
    }

    // Ghidra: space.cc:143 AddrSpace::encodeAttributes
    /// Write the main attributes for an address within this space.
    /// Faithful to the virtual dispatch in space.cc: the base form writes
    /// ATTRIB_SPACE + ATTRIB_OFFSET (space.cc:146-147); the IopSpace
    /// override writes only the literal space name "iop", dropping the
    /// offset (op.hh:49); the FspecSpace override projects through the
    /// offset's call spec — an invalid entry address writes only the
    /// literal "fspec", a valid one writes the ENTRY space name and ENTRY
    /// offset (fspec.cc:2124-2136), i.e. the encoded form never carries the
    /// fspec offset itself; the JoinSpace override writes the join space
    /// plus one indexed ATTRIB_PIECE per piece and ATTRIB_LOGICALSIZE for a
    /// single-piece join (space.cc:502-519).
    /// `writeSpace` is virtual on the encoder (marshal.hh:368): the XML/tree
    /// form renders the space name string (XmlEncode::writeSpace,
    /// marshal.cc:569), the packed form the special-space byte or index
    /// (PackedEncode::writeSpace, marshal.cc:1193).
    pub fn encode_attributes(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        offset: u64) {
        match self.get_type() {
            // Ghidra: op.hh:49 IopSpace::encodeAttributes override.
            SpaceType::Iop => {
                encoder.write_string(&attrib_space(), IOP_SPACE_NAME);
                return;
            }
            // Ghidra: fspec.cc:2124 FspecSpace::encodeAttributes override.
            SpaceType::Fspec => {
                self.encode_attributes_fspec(encoder, offset, None);
                return;
            }
            // Ghidra: space.cc:502 JoinSpace::encodeAttributes override.
            SpaceType::Join => {
                self.encode_attributes_join(encoder, offset);
                return;
            }
            _ => {}
        }
        // encoder.writeSpace(ATTRIB_SPACE,this);
        encoder.write_space(&attrib_space(), self);
        // encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset);
        encoder.write_unsigned_integer(&attrib_offset(), offset);
    }

    // Ghidra: space.cc:156 AddrSpace::encodeAttributes (3-arg)
    /// Write the main attributes of an address and a size. Faithful to the
    /// 3-argument virtual form (space.cc:156-162): identical dispatch to
    /// [`AddrSpace::encode_attributes`] plus ATTRIB_SIZE on the base path;
    /// the IopSpace override still writes only "iop" (op.hh:50) and the
    /// FspecSpace override adds the size only on the valid-entry path
    /// (fspec.cc:2138-2151); the JoinSpace override ignores the size
    /// entirely and delegates to the 2-argument form (space.cc:527-531).
    pub fn encode_attributes_with_size(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        offset: u64,
        size: i32,
    ) {
        match self.get_type() {
            // Ghidra: op.hh:50 IopSpace::encodeAttributes(3-arg) override.
            SpaceType::Iop => {
                encoder.write_string(&attrib_space(), IOP_SPACE_NAME);
                return;
            }
            // Ghidra: fspec.cc:2138 FspecSpace::encodeAttributes(3-arg).
            SpaceType::Fspec => {
                self.encode_attributes_fspec(encoder, offset, Some(size));
                return;
            }
            // Ghidra: space.cc:527 JoinSpace::encodeAttributes(3-arg) —
            // encodeAttributes(encoder,offset); // Ignore size
            SpaceType::Join => {
                self.encode_attributes_join(encoder, offset);
                return;
            }
            _ => {}
        }
        encoder.write_space(&attrib_space(), self);
        encoder.write_unsigned_integer(&attrib_offset(), offset);
        encoder.write_signed_integer(&attrib_size(), size as i64);
    }

    // Ghidra: fspec.cc:2124 FspecSpace::encodeAttributes /
    //   fspec.cc:2138 FspecSpace::encodeAttributes(3-arg)
    /// The fspec-space specialization shared by both encode arities:
    /// `FuncCallSpecs *fc = (FuncCallSpecs *)(uintp)offset` — an invalid
    /// entry address writes only the literal "fspec" (no offset, no size);
    /// a valid entry writes the entry space name, entry offset, and (3-arg
    /// form only) the size. An offset with no registered entry would be a
    /// wild-pointer dereference in C++ (undefined); Rust fails
    /// deterministically, the same policy as the unlinked-join panic.
    fn encode_attributes_fspec(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        offset: u64,
        size: Option<i32>,
    ) {
        let tables = self
            .get_fspec_table()
            .unwrap_or_else(|| panic!("Unresolved fspec address"));
        let fc = tables
            .borrow()
            .resolve(offset)
            .cloned()
            .unwrap_or_else(|| panic!("Unresolved fspec address"));
        match fc.entry {
            // if (fc->getEntryAddress().isInvalid())
            //   encoder.writeString(ATTRIB_SPACE, "fspec");
            None => encoder.write_string(&attrib_space(), FSPEC_SPACE_NAME),
            Some((spc, entry_off)) => {
                // AddrSpace *id = fc->getEntryAddress().getSpace();
                // encoder.writeSpace(ATTRIB_SPACE, id);
                encoder.write_space(&attrib_space(), &spc);
                // encoder.writeUnsignedInteger(ATTRIB_OFFSET,
                //   fc->getEntryAddress().getOffset());
                encoder.write_unsigned_integer(&attrib_offset(), entry_off);
                if let Some(sz) = size {
                    // encoder.writeSignedInteger(ATTRIB_SIZE, size);
                    encoder.write_signed_integer(&attrib_size(), sz as i64);
                }
            }
        }
    }

    // Ghidra: space.cc:502 JoinSpace::encodeAttributes (both arities)
    /// The join-space specialization shared by both encode arities (the
    /// 3-arg form ignores its size, space.cc:527-531). Faithful to
    /// `JoinSpace::encodeAttributes` (space.cc:502-519): the offset must
    /// resolve to an existing JoinRecord through the manager
    /// (`getManager()->findJoin(offset)` — the "Record must already exist"
    /// contract; an unlinked offset is the `findJoin` LowlevelError
    /// "Unlinked join address", translate.cc:761), then
    /// `writeSpace(ATTRIB_SPACE, this)` names the join space itself, each
    /// piece (most significant first) becomes an indexed ATTRIB_PIECE
    /// string `{space-name}:0x{offset:x}:{size}` (the ostringstream `hex`
    /// manipulator for the offset, `dec` restored for the size), a record
    /// with more than MAX_PIECES pieces throws
    /// LowlevelError("Exceeded maximum pieces in one join address"), and a
    /// single-piece join (float extension) appends ATTRIB_LOGICALSIZE
    /// holding the unified size.
    fn encode_attributes_join(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        offset: u64) {
        // JoinRecord *rec = getManager()->findJoin(offset);
        let tables = self.get_manager_join_tables();
        let tables = tables.unwrap_or_else(|| panic!("Unlinked join address"));
        let tables_ref = tables.borrow();
        let rec = tables_ref.find_join(offset);
        // encoder.writeSpace(ATTRIB_SPACE, this);
        encoder.write_space(&attrib_space(), self);
        let num = rec.num_pieces();
        if num > MAX_PIECES {
            panic!("Exceeded maximum pieces in one join address");
        }
        for i in 0..num {
            // const VarnodeData &vdata( rec->getPiece(i) );
            // ostringstream t; t << vdata.space->getName() << ":0x";
            // t << hex << vdata.offset << ':' << dec << vdata.size;
            let vdata = rec.get_piece(i);
            let t = format!(
                "{}:0x{:x}:{}",
                vdata.space.get_name(),
                vdata.offset,
                vdata.size
            );
            // encoder.writeStringIndexed(ATTRIB_PIECE, i, t.str());
            encoder.write_string_indexed(&attrib_piece(), i as u32, &t);
        }
        if num == 1 {
            // encoder.writeUnsignedInteger(ATTRIB_LOGICALSIZE,
            //   rec->getUnified().size);
            encoder.write_unsigned_integer(
                &attrib_logicalsize(),
                rec.get_unified().size as u64);
        }
    }

    // Ghidra: space.cc:169 AddrSpace::decodeAttributes
    /// Recover an offset (and possibly a size) from the attributes of an
    /// open element describing an address in this space. Faithful to
    /// `decodeAttributes` (space.cc:169-189): walk every attribute, take
    /// ATTRIB_OFFSET / ATTRIB_SIZE by name, skip the rest, and throw
    /// `LowlevelError("Address is missing offset")` (an `Err` here) when no
    /// offset attribute was seen. The JoinSpace override (space.cc:539)
    /// rebuilds a JoinRecord from the ATTRIB_PIECE attributes. Ghidra's
    /// virtual reads the manager off the space itself (`getManager()`,
    /// space.hh:118); Rust spaces carry only the join-table backlink, so
    /// the manager is the explicit `spc_manager` parameter — the same
    /// object Ghidra's space would hold.
    pub fn decode_attributes(
        &self,
        decoder: &mut dyn crate::marshal::Decoder,
        spc_manager: &SpaceRegistry,
        size: &mut u32,
    ) -> Result<u64, String> {
        if self.get_type() == SpaceType::Join {
            return self.decode_attributes_join(decoder, spc_manager, size);
        }
        let mut offset: u64 = 0;
        let mut found_offset = false;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            match decoder.attribute_name(attrib_id).as_deref() {
                Some("offset") => {
                    found_offset = true;
                    offset = decoder.read_unsigned_integer();
                }
                Some("size") => {
                    *size = decoder.read_signed_integer() as i32 as u32;
                }
                _ => {
                    // Skip the unknown attribute's value.
                    let _ = decoder.read_string();
                }
            }
        }
        if !found_offset {
            return Err("Address is missing offset".to_string());
        }
        Ok(offset)
    }

    // Ghidra: space.cc:539 JoinSpace::decodeAttributes
    /// The join-space specialization: pieces arrive as a sequence of
    /// indexed ATTRIB_PIECE attributes ("piece1" is the most significant
    /// piece; the XML decoder reinterprets the name suffix through
    /// `getIndexedAttributeId`, marshal.cc:243, while the packed decoder
    /// already carries the indexed id in its header). Faithful to
    /// `JoinSpace::decodeAttributes` (space.cc:539-588):
    /// ATTRIB_LOGICALSIZE supplies the float-extension logical size; an
    /// attribute below the ATTRIB_PIECE id, or a piece position beyond
    /// MAX_PIECES, is skipped without reading; pieces are placed by index
    /// into a grow-on-demand vector (a hole leaves a zero piece); a piece
    /// string with no `:` is a REGISTER name (`getTrans()->getRegister`,
    /// space.cc:566-569); otherwise the form is
    /// `{space-name}:{offset}:{size}` with one `:` exactly — a missing
    /// second `:` throws `LowlevelError("join address piece attribute is
    /// malformed")` — and the numbers parse with the stream auto-base
    /// (`unsetf(ios::dec|ios::hex|ios::oct)`). The pieces finally go
    /// through `getManager()->findAddJoin` (translate.cc:671), whose
    /// dedup returns the original unified offset for an exact re-decode;
    /// the size out-param receives the unified size.
    ///
    /// Two Ghidra forms fail deterministically here instead of the C++
    /// undefined behavior: a register-name piece needs the Translate
    /// register table (SPACE-0001 residual), and an unknown piece space
    /// name would leave a null `VarnodeData.space` that only survives the
    /// C++ join-record ordering because `operator<` compares unified sizes
    /// first (translate.cc:172-191) — Rust's non-optional space handle
    /// rejects it at the lookup point.
    fn decode_attributes_join(
        &self,
        decoder: &mut dyn crate::marshal::Decoder,
        spc_manager: &SpaceRegistry,
        size: &mut u32,
    ) -> Result<u64, String> {
        let tables = self.get_manager_join_tables();
        let tables = tables.unwrap_or_else(|| panic!("Unlinked join address"));
        // vector<VarnodeData> pieces;
        let mut pieces: Vec<SpaceVarnodeData> = Vec::new();
        let mut logicalsize: u32 = 0;
        loop {
            // uint4 attribId = decoder.getNextAttributeId();
            let mut attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            if attrib_id == attrib_logicalsize().id {
                // logicalsize = decoder.readUnsignedInteger();
                logicalsize = decoder.read_unsigned_integer() as u32;
                continue;
            } else if attrib_id == crate::marshal::ATTRIB_UNKNOWN {
                // attribId = decoder.getIndexedAttributeId(ATTRIB_PIECE);
                attrib_id = decoder.get_indexed_attribute_id(&attrib_piece());
            }
            // if (attribId < ATTRIB_PIECE.getId()) continue;
            if attrib_id < attrib_piece().id {
                continue;
            }
            // int4 pos = (int4)(attribId - ATTRIB_PIECE.getId());
            let pos = (attrib_id - attrib_piece().id) as usize;
            // if (pos > MAX_PIECES) continue;
            if pos > MAX_PIECES {
                continue;
            }
            // while(pieces.size() <= pos) pieces.emplace_back();
            while pieces.len() <= pos {
                pieces.push(SpaceVarnodeData {
                    space: self.clone(),
                    offset: 0,
                    size: 0,
                });
            }
            // string attrVal = decoder.readString();
            let attr_val = decoder.read_string();
            // string::size_type offpos = attrVal.find(':');
            match attr_val.find(':') {
                None => {
                    // Register-name piece form: the C++ resolves it through
                    // getTrans()->getRegister (space.cc:566-569); the
                    // register table is the SPACE-0001 residual, so the
                    // form is rejected loudly rather than mis-decoded.
                    return Err(
                        "register-name join piece requires the Translate register table"
                            .to_string(),
                    );
                }
                Some(offpos) => {
                    // string::size_type szpos = attrVal.find(':',offpos+1);
                    let szpos = attr_val[offpos + 1..].find(':').map(|i| i + offpos + 1);
                    let Some(szpos) = szpos else {
                        return Err(
                            "join address piece attribute is malformed".to_string()
                        );
                    };
                    // string spcname = attrVal.substr(0,offpos);
                    let spcname = &attr_val[..offpos];
                    // vdat.space = getManager()->getSpaceByName(spcname);
                    let Some(spc) = spc_manager.get_space_by_name(spcname) else {
                        return Err(format!(
                            "Unknown address space name: {}",
                            spcname
                        ));
                    };
                    pieces[pos].space = spc;
                    // istringstream s1(attrVal.substr(offpos+1,szpos));
                    // s1.unsetf(ios::dec|ios::hex|ios::oct); s1 >> vdat.offset;
                    pieces[pos].offset = crate::marshal::cpp_stream_unsigned(
                        &attr_val[offpos + 1..szpos]);
                    // istringstream s2(attrVal.substr(szpos+1)); ...
                    // s2 >> vdat.size;
                    pieces[pos].size = crate::marshal::cpp_stream_unsigned(
                        &attr_val[szpos + 1..]) as u32 as i32;
                }
            }
            // sizesum += vdat.size;  (accumulator unused beyond the loop)
        }
        // JoinRecord *rec = getManager()->findAddJoin(pieces,logicalsize);
        let offset = tables
            .borrow_mut()
            .find_add_join(&pieces, logicalsize, self);
        let tables_ref = tables.borrow();
        let rec = tables_ref.find_join(offset);
        // size = rec->getUnified().size;
        *size = rec.get_unified().size as u32;
        // return rec->getUnified().offset;
        Ok(rec.get_unified().offset)
    }

    // RUDRA-GLUE: set_contain (Ghidra's derived decode bodies write the
    // private `SpacebaseSpace::contain` / `OverlaySpace::baseSpace` member
    // directly; Rust needs a setter on the shared record.)
    /// Attach the containing space (`translate.cc:131 contain` /
    /// `space.cc:668 baseSpace`) after a decode-time space reference
    /// resolves. Manager use only.
    pub fn set_contain(&self, base: &AddrSpace) {
        let mut inner = self.0.borrow_mut();
        let state = inner.spacebase.get_or_insert_with(|| SpacebaseState {
            contain: None,
            has_base_register: false,
            is_negative_stack: true,
            base_loc: SpaceVarnodeData {
                space: base.clone(),
                offset: 0,
                size: 0,
            },
            base_orig: SpaceVarnodeData {
                space: base.clone(),
                offset: 0,
                size: 0,
            },
        });
        state.contain = Some(base.clone());
    }

    // RUDRA-GLUE: new_external_space (the locked 12.0.4 decompiler oracle has
    // no ExternalSpace: `spacetype` (space.hh:30-38) stops at IPTR_JOIN, the
    // C++ side never registers a space named EXTERNAL, and the packed
    // protocol refuses to marshal it — PackedEncode.writeSpace throws
    // "Cannot marshal address space" for Java TYPE_EXTERNAL=10
    // (PackedEncode.java:186-199). The EXTERNAL artifact lives on the Ghidra
    // platform side: AddressSpace.java:80 defines
    // `new GenericAddressSpace("EXTERNAL", 32, TYPE_EXTERNAL, 0)` — a flat
    // 32-bit space, not an overlay — and the ELF importer materializes the
    // import stub addresses as an artificial EXTERNAL *memory block* in the
    // default space (ElfProgramBuilder.java:1532-1556 createExternalBlock,
    // 0x1000-aligned linkage block, 8 bytes per UND import). This
    // constructor mirrors that Java definition so a Rudra SpaceRegistry can
    // name and register the EXTERNAL space alongside the decode-registered
    // spaces; the decompiler-side spacetype is Processor because the oracle
    // enum has no external member.)
    /// Construct the Ghidra-platform EXTERNAL space: name "EXTERNAL",
    /// 32-bit offsets (address size 4), word size 1, supplied index,
    /// little/big endian per the platform, and the base partial-constructor
    /// flags (`heritaged|does_deadcode`, space.cc:87-98).
    pub fn new_external_space(ind: i32, target_big_endian: bool) -> Self {
        let spc = Self::new_space(
            SpaceType::Processor,
            EXTERNAL_SPACE_NAME,
            target_big_endian,
            4, // 32-bit space: GenericAddressSpace("EXTERNAL", 32, ...)
            1,
            ind,
            0,
            0,
            0,
        );
        spc
    }

    // Ghidra: space.cc:34 AddrSpace::calcScaleMask
    /// Calculate `highest` based on `addressSize` and `wordsize`, plus the
    /// default pointer bounds. Faithful to `calcScaleMask`
    /// (space.cc:34-44) with Ghidra's unsigned wraparound arithmetic.
    fn calc_scale_mask(&self) {
        let mut inner = self.0.borrow_mut();
        // highest = calc_mask(addressSize); highest = highest*wordsize + (wordsize-1);
        inner.highest = calc_mask(inner.address_size as i32)
            .wrapping_mul(inner.word_size as u64)
            .wrapping_add(inner.word_size as u64 - 1);
        let buffer_size: u64 = if inner.address_size < 3 {
            0x100
        } else {
            0x1000
        };
        inner.pointer_lower_bound = 0u64.wrapping_add(buffer_size);
        inner.pointer_upper_bound = inner.highest.wrapping_sub(buffer_size);
    }

    // Ghidra: space.cc:105 AddrSpace::truncateSpace
    /// Truncate the logical form of the space. Faithful to `truncateSpace`
    /// (space.cc:105-112): sets `truncated`, updates `addressSize` and
    /// `minimumPointerSize` to `newsize`, and recalculates the scale mask.
    pub fn truncate_space(&self, newsize: u32) {
        {
            let mut inner = self.0.borrow_mut();
            inner.flags |= space_flags::TRUNCATED;
            inner.address_size = newsize;
            inner.minimum_pointer_size = newsize as i32;
        }
        self.calc_scale_mask();
    }

    // Ghidra: space.hh:264 AddrSpace::setFlags
    /// Set a cached attribute (Ghidra: protected; the registry and derived
    /// constructors are the intended callers).
    pub fn set_flags(&self, fl: u32) {
        self.0.borrow_mut().flags |= fl;
    }

    // Ghidra: space.hh:270 AddrSpace::clearFlags
    /// Clear a cached attribute (Ghidra: protected).
    pub fn clear_flags(&self, fl: u32) {
        self.0.borrow_mut().flags &= !fl;
    }

    // RUDRA-GLUE: set_manager_join_tables — Ghidra's AddrSpace receives its
    // `AddrSpaceManager *manage` backlink in the constructor (space.hh:118);
    // Rudra's constructors take no manager, so the registry wires the
    // join-record half (the only half any space method reads) when it
    // inserts the space. This is the injection point for
    // `JoinSpace::printRaw`'s `getManager()->findJoin` (space.cc:593).
    /// Wire the owning registry's join-record tables into this space.
    pub fn set_manager_join_tables(&self, tables: &Rc<RefCell<manager_join::JoinRecordTables>>) {
        self.0.borrow_mut().manager_join_tables = Some(Rc::downgrade(tables));
    }

    // RUDRA-GLUE: set_fspec_table — same association point as
    /// `set_manager_join_tables` above, for the fspec half of the
    /// `AddrSpace::manage` backlink (`FspecSpace::printRaw`/
    /// `encodeAttributes` dereference the offset pointer, fspec.cc:2125).
    /// Wire the owning registry's fspec-entry table into this space.
    pub fn set_fspec_table(&self, tables: &Rc<RefCell<FspecEntryTable>>) {
        self.0.borrow_mut().fspec_table = Some(Rc::downgrade(tables));
    }

    // RUDRA-GLUE: get_fspec_table — the read side of the fspec half.
    /// `None` for spaces that were never inserted into a registry.
    fn get_fspec_table(&self) -> Option<Rc<RefCell<FspecEntryTable>>> {
        self.0
            .borrow()
            .fspec_table
            .as_ref()
            .and_then(|w| w.upgrade())
    }

    // RUDRA-GLUE: get_manager_join_tables — the read side of the
    /// `AddrSpace::manage` join half. `None` for spaces that were never
    /// inserted into a registry.
    fn get_manager_join_tables(&self) -> Option<Rc<RefCell<manager_join::JoinRecordTables>>> {
        self.0
            .borrow()
            .manager_join_tables
            .as_ref()
            .and_then(|w| w.upgrade())
    }

    // Ghidra: space.hh:277 AddrSpace::getName
    /// Get the name of this space.
    pub fn get_name(&self) -> String {
        self.0.borrow().name.clone()
    }

    // Ghidra: space.hh:304 AddrSpace::getType
    /// Get the defining type of this space.
    pub fn get_type(&self) -> SpaceType {
        self.0.borrow().space_type
    }

    // Ghidra: space.hh:315 AddrSpace::getDelay
    /// Get the number of heritage passes being delayed.
    pub fn get_delay(&self) -> i32 {
        self.0.borrow().delay
    }

    // Ghidra: space.hh:325 AddrSpace::getDeadcodeDelay
    /// Get the number of passes before deadcode removal is allowed.
    pub fn get_deadcode_delay(&self) -> i32 {
        self.0.borrow().deadcode_delay
    }

    // Ghidra: space.hh:332 AddrSpace::getIndex
    /// Get the integer identifier of the space.
    pub fn get_index(&self) -> i32 {
        self.0.borrow().index
    }

    // Ghidra: space.hh:340 AddrSpace::getWordSize
    /// Get the number of bytes in an addressable unit.
    pub fn get_word_size(&self) -> u32 {
        self.0.borrow().word_size
    }

    // Ghidra: space.hh:348 AddrSpace::getAddrSize
    /// Get the number of bytes needed to represent an offset into this space.
    pub fn get_addr_size(&self) -> u32 {
        self.0.borrow().address_size
    }

    // Ghidra: space.hh:354 AddrSpace::getHighest
    /// Get the highest (byte) offset possible for this space.
    pub fn get_highest(&self) -> u64 {
        self.0.borrow().highest
    }

    // Ghidra: space.hh:361 AddrSpace::getPointerLowerBound
    /// Get the minimum offset that will be inferred as a pointer.
    pub fn get_pointer_lower_bound(&self) -> u64 {
        self.0.borrow().pointer_lower_bound
    }

    // Ghidra: space.hh:368 AddrSpace::getPointerUpperBound
    /// Get the maximum offset that will be inferred as a pointer.
    pub fn get_pointer_upper_bound(&self) -> u64 {
        self.0.borrow().pointer_upper_bound
    }

    // Ghidra: space.hh:374 AddrSpace::getMinimumPtrSize
    /// Get the minimum pointer size for this space (0 = exact match).
    pub fn get_minimum_ptr_size(&self) -> i32 {
        self.0.borrow().minimum_pointer_size
    }

    // Ghidra: space.hh:397 AddrSpace::getShortcut
    /// Get the shortcut character (`' '` while unassigned).
    pub fn get_shortcut(&self) -> char {
        self.0.borrow().shortcut
    }

    // RUDRA-GLUE: set_shortcut (Ghidra mutates the private `shortcut` field
    // directly from AddrSpaceManager::assignShortcut; Rust needs a setter.)
    /// Assign the shortcut character (manager use only).
    fn set_shortcut(&self, sc: char) {
        self.0.borrow_mut().shortcut = sc;
    }

    // RUDRA-GLUE: refcount (Ghidra's `refcount` field is private with no
    // getter; exposed read-only so the oracle fixture can observe it like the
    // C++ fixture reads it through #define private public.)
    /// Number of managers using this space.
    pub fn refcount(&self) -> i32 {
        self.0.borrow().refcount
    }

    // RUDRA-GLUE: identity_ptr (Ghidra compares raw AddrSpace pointers in
    // ordered containers; the handle exposes the shared-record address so
    // other types can build deterministic identity tiebreaks without
    // reaching into the private Rc.)
    /// Stable per-object identity (the shared record's address). Equal for
    /// two handles to the same space, mirroring pointer equality.
    pub fn identity_ptr(&self) -> usize {
        Rc::as_ptr(&self.0) as usize
    }

    // RUDRA-GLUE: increment_refcount (Ghidra does `spc->refcount += 1` inside
    // AddrSpaceManager::insertSpace on the success path only.)
    /// Register one more manager reference to this space.
    fn increment_refcount(&self) {
        self.0.borrow_mut().refcount += 1;
    }

    // Ghidra: space.hh:383 AddrSpace::wrapOffset
    /// Wrap an offset modulo the size of this address space. Faithful to
    /// `wrapOffset` (space.hh:383-391): unsigned compare against `highest`,
    /// then a signed remainder that is corrected back into `(0, mod)`.
    pub fn wrap_offset(&self, off: u64) -> u64 {
        let (highest,) = {
            let inner = self.0.borrow();
            (inner.highest,)
        };
        if off <= highest {
            return off;
        }
        let modulus = (highest as i64).wrapping_add(1);
        let mut res = (off as i64).rem_euclid(modulus);
        if res < 0 {
            res += modulus;
        }
        res as u64
    }

    // Ghidra: space.hh:407 AddrSpace::isHeritaged
    /// Return true if dataflow has been traced for this space.
    pub fn is_heritaged(&self) -> bool {
        (self.0.borrow().flags & space_flags::HERITAGED) != 0
    }

    // Ghidra: space.hh:415 AddrSpace::doesDeadcode
    /// Return true if dead-code analysis should be done on this space.
    pub fn does_deadcode(&self) -> bool {
        (self.0.borrow().flags & space_flags::DOES_DEADCODE) != 0
    }

    // Ghidra: space.hh:423 AddrSpace::hasPhysical
    /// Return true if data is physically stored in this space.
    pub fn has_physical(&self) -> bool {
        (self.0.borrow().flags & space_flags::HASPHYSICAL) != 0
    }

    // Ghidra: space.hh:430 AddrSpace::isBigEndian
    /// Return true if values in this space are big endian.
    pub fn is_big_endian(&self) -> bool {
        (self.0.borrow().flags & space_flags::BIG_ENDIAN) != 0
    }

    // Ghidra: space.hh:439 AddrSpace::isReverseJustified
    /// Return true if alignment justification does not match endianness.
    pub fn is_reverse_justified(&self) -> bool {
        (self.0.borrow().flags & space_flags::REVERSE_JUSTIFICATION) != 0
    }

    // Ghidra: space.hh:444 AddrSpace::isFormalStackSpace
    /// Return true if attached to the formal stack pointer.
    pub fn is_formal_stackspace(&self) -> bool {
        (self.0.borrow().flags & space_flags::FORMAL_STACKSPACE) != 0
    }

    // Ghidra: space.hh:448 AddrSpace::isOverlay
    /// Return true if this is an overlay space.
    pub fn is_overlay(&self) -> bool {
        (self.0.borrow().flags & space_flags::OVERLAY) != 0
    }

    // Ghidra: space.hh:452 AddrSpace::isOverlayBase
    /// Return true if other spaces overlay this space.
    pub fn is_overlay_base(&self) -> bool {
        (self.0.borrow().flags & space_flags::OVERLAYBASE) != 0
    }

    // Ghidra: space.hh:456 AddrSpace::isOtherSpace
    /// Return true if this is the \e other address space.
    pub fn is_other_space(&self) -> bool {
        (self.0.borrow().flags & space_flags::IS_OTHERSPACE) != 0
    }

    // Ghidra: space.hh:462 AddrSpace::isTruncated
    /// Return true if this space is truncated from its original size.
    pub fn is_truncated(&self) -> bool {
        (self.0.borrow().flags & space_flags::TRUNCATED) != 0
    }

    // Ghidra: space.hh:466 AddrSpace::hasNearPointers
    /// Return true if near (truncated) pointers into this space are possible.
    pub fn has_near_pointers(&self) -> bool {
        (self.0.borrow().flags & space_flags::HAS_NEARPOINTERS) != 0
    }

    // Ghidra: space.hh:474 AddrSpace::numSpacebase
    /// Number of base registers associated with this space (0 or 1; the base
    /// `AddrSpace` implementation always returns 0).
    pub fn num_spacebase(&self) -> i32 {
        match self.spacebase_state() {
            None => 0,
            Some(state) => {
                if state.has_base_register {
                    1
                } else {
                    0
                }
            }
        }
    }

    // RUDRA-GLUE: spacebase_state (Ghidra's subclass fields are accessed
    // directly by SpacebaseSpace methods; Rust reads them through the
    // flattened Option.)
    /// Borrow a snapshot of the spacebase state, if this is a virtual space.
    fn spacebase_state(&self) -> Option<SpacebaseState> {
        self.0.borrow().spacebase.clone()
    }

    // Ghidra: space.hh:482 AddrSpace::getSpacebase
    /// Get the base register location for a virtual space. Faithful to
    /// `SpacebaseSpace::getSpacebase` (translate.cc:110-116): throws
    /// (returns `Err` here) when no base register was specified or the index
    /// is non-zero.
    pub fn get_spacebase(&self, i: i32) -> Result<SpaceVarnodeData, String> {
        match self.spacebase_state() {
            Some(state) if state.has_base_register && i == 0 => Ok(state.base_loc),
            _ => Err(format!(
                "No base register specified for space: {}",
                self.get_name()
            )),
        }
    }

    // Ghidra: space.hh:490 AddrSpace::getSpacebaseFull
    /// Get the original (pre-truncation) base register. Faithful to
    /// `SpacebaseSpace::getSpacebaseFull` (translate.cc:118-124).
    pub fn get_spacebase_full(&self, i: i32) -> Result<SpaceVarnodeData, String> {
        match self.spacebase_state() {
            Some(state) if state.has_base_register && i == 0 => Ok(state.base_orig),
            _ => Err(format!(
                "No base register specified for space: {}",
                self.get_name()
            )),
        }
    }

    // Ghidra: space.hh:497 AddrSpace::stackGrowsNegative
    /// Return true if a stack in this space grows in the negative direction.
    /// The base implementation always returns true; virtual spaces report
    /// their assigned growth direction.
    pub fn stack_grows_negative(&self) -> bool {
        match self.0.borrow().spacebase.as_ref() {
            None => true,
            Some(state) => state.is_negative_stack,
        }
    }

    // Ghidra: space.hh:505 AddrSpace::getContain
    /// Return this space's containing space (virtual spaces only); `None`
    /// for regular spaces (Ghidra: null).
    pub fn get_contain(&self) -> Option<AddrSpace> {
        match self.0.borrow().spacebase.as_ref() {
            None => None,
            Some(state) => state.contain.clone(),
        }
    }

    // Ghidra: translate.cc:86 SpacebaseSpace::setBaseRegister
    /// Set the base register of a virtual space. Faithful to
    /// `setBaseRegister` (translate.cc:86-102): assigning a second, different
    /// base register (location or growth direction) is an error; the original
    /// register is preserved in `base_orig`; and a truncated size shifts the
    /// base location offset up by the lost bytes on big-endian register
    /// spaces only.
    fn set_base_register(
        &self,
        data: &SpaceVarnodeData,
        trunc_size: i32,
        stack_growth: bool,
    ) -> Result<(), String> {
        let mut inner = self.0.borrow_mut();
        let Some(state) = inner.spacebase.as_mut() else {
            // RUDRA-GLUE: Ghidra reaches this method only through
            // SpacebaseSpace; a non-virtual space here is a caller bug.
            return Err(format!(
                "No base register specified for space: {}",
                inner.name
            ));
        };
        if state.has_base_register {
            if state.base_loc != *data || state.is_negative_stack != stack_growth {
                return Err(format!(
                    "Attempt to assign more than one base register to space: {}",
                    inner.name
                ));
            }
        }
        state.has_base_register = true;
        state.is_negative_stack = stack_growth;
        state.base_orig = data.clone();
        state.base_loc = data.clone();
        if trunc_size != state.base_loc.size {
            if state.base_loc.space.is_big_endian() {
                state.base_loc.offset =
                    (state.base_loc.offset as u64)
                    .wrapping_add((state.base_loc.size - trunc_size) as u64);
            }
            state.base_loc.size = trunc_size;
        }
        Ok(())
    }

    // Ghidra: space.hh:514 AddrSpace::addressToByte
    /// Scale from addressable units to byte units.
    pub fn address_to_byte(val: u64, ws: u32) -> u64 {
        // `uintb` is a fixed-width unsigned 64-bit value in Ghidra, so the
        // multiplication is modulo 2^64.  Make that release/debug invariant
        // explicit instead of relying on profile-specific overflow checks.
        val.wrapping_mul(ws as u64)
    }

    // Ghidra: space.hh:523 AddrSpace::byteToAddress
    /// Scale from byte units to addressable units.
    pub fn byte_to_address(val: u64, ws: u32) -> u64 {
        val / ws as u64
    }

    // Ghidra: space.hh:532 AddrSpace::addressToByteInt
    /// Scale an i64 from addressable units to byte units.
    pub fn address_to_byte_int(val: i64, ws: u32) -> i64 {
        val * ws as i64
    }

    // Ghidra: space.hh:541 AddrSpace::byteToAddressInt
    /// Scale an i64 from byte units to addressable units.
    pub fn byte_to_address_int(val: i64, ws: u32) -> i64 {
        val / ws as i64
    }

    // Ghidra: space.hh:549 AddrSpace::compareByIndex
    /// Compare two spaces by their index.
    pub fn compare_by_index(a: &AddrSpace, b: &AddrSpace) -> bool {
        a.get_index() < b.get_index()
    }

    // Ghidra: space.cc:206 AddrSpace::printRaw
    /// Write an address in this space to a string, taking the wordsize into
    /// account (a `+n` suffix when the offset is off-cut). Faithful to
    /// `AddrSpace::printRaw` (space.cc:206-222): the print width shrinks for
    /// small offsets in >4-byte spaces, the offset is scaled to addressable
    /// units via `byteToAddress`, and the off-cut is the byte remainder.
    /// `ConstantSpace::printRaw` (space.cc:372) and `OtherSpace::printRaw`
    /// (space.cc:410) override with unpadded hex; the dispatch below keys on
    /// the constant type and the `is_otherspace` flag, which only production
    /// OtherSpaces set. `JoinSpace::printRaw` (space.cc:590) and
    /// `IopSpace::printRaw` (op.cc:41) override with the pieces/op forms.
    pub fn print_raw(&self, offset: u64) -> String {
        match self.get_type() {
            // Ghidra: space.cc:372 ConstantSpace::printRaw and space.cc:410
            //   OtherSpace::printRaw overrides (unpadded hex).
            SpaceType::Constant => return format!("0x{:x}", offset),
            SpaceType::Join => return self.print_raw_join(offset),
            SpaceType::Fspec => return self.print_raw_fspec(offset),
            SpaceType::Iop => {
                // Ghidra: op.cc:41 IopSpace::printRaw override — RESIDUAL
                // SPACE-IOP-PRINTRAW-0001: both terminal renders (the
                // non-branch SeqNum form via `SeqNum.addr`, the branch
                // `code_`+shortcut+block-start form via
                // `BlockBasic::start_addr`) need the address's space, which
                // the legacy spaceless model does not carry; blocked by
                // ADDRESS-0001. Until the future `IopSpace::print_raw` in
                // op.rs can render them, the base form below is the output
                // (the pre-specialization observable). Kept inline so this
                // file compiles standalone under registry-overlay runners
                // pinned to pre-op.rs-specialization bases.
            }
            _ => {}
        }
        if self.is_other_space() {
            return format!("0x{:x}", offset);
        }
        let (address_size, word_size) = {
            let inner = self.0.borrow();
            (inner.address_size, inner.word_size)
        };
        let mut sz = address_size as i32;
        if sz > 4 {
            if (offset >> 32) == 0 {
                sz = 4; // Don't print a bunch of zeroes at front of address
            } else if (offset >> 48) == 0 {
                sz = 6;
            }
        }
        let mut out = format!(
            "0x{:0width$x}",
            Self::byte_to_address(offset, word_size),
            width = (2 * sz) as usize
        );
        if word_size > 1 {
            let cut = offset % word_size as u64;
            if cut != 0 {
                out.push_str(&format!("+{}", cut));
            }
        }
        out
    }

    // Ghidra: fspec.cc:2153 FspecSpace::printRaw
    /// The fspec-space specialization: `FuncCallSpecs *fc =
    /// (FuncCallSpecs *)(uintp)offset` — a non-empty name prints directly,
    /// otherwise `func_` is followed by the entry address's own `printRaw`
    /// (an invalid entry prints `invalid_addr` through
    /// `Address::printRaw`, address.hh:305-311). An offset with no
    /// registered entry would be a wild-pointer dereference in C++
    /// (undefined); Rust fails deterministically, the same policy as the
    /// unlinked-join panic.
    fn print_raw_fspec(&self, offset: u64) -> String {
        let tables = self
            .get_fspec_table()
            .unwrap_or_else(|| panic!("Unresolved fspec address"));
        let fc = tables
            .borrow()
            .resolve(offset)
            .cloned()
            .unwrap_or_else(|| panic!("Unresolved fspec address"));
        // if (fc->getName().size() != 0) s << fc->getName();
        if !fc.name.is_empty() {
            return fc.name;
        }
        // s << "func_"; fc->getEntryAddress().printRaw(s);
        let mut out = String::from("func_");
        match fc.entry {
            Some((spc, entry_off)) => out.push_str(&spc.print_raw(entry_off)),
            None => out.push_str("invalid_addr"),
        }
        out
    }

    // Ghidra: space.cc:590 JoinSpace::printRaw
    /// The join-space specialization: `JoinRecord *rec =
    /// getManager()->findJoin(offset)` resolves the offset back to its
    /// pieces, each piece is printed by its own space's `printRaw`
    /// (`vdat.space->printRaw(s,vdat.offset)`), pieces are comma-separated
    /// inside braces, and a single-piece join (float extension) appends
    /// `:` + the unified (logical) size. Faithful to the quirk that the
    /// `szsum` accumulator from the loop is discarded and replaced by
    /// `rec->getUnified().size` when `num == 1` (space.cc:604-606).
    ///
    /// Unlinked offsets (no JoinRecord) panic with Ghidra's
    /// `LowlevelError("Unlinked join address")` from `findJoin`
    /// (translate.cc:761); a join space never registered with a registry has
    /// no manager backlink, which Ghidra cannot express (its constructor
    /// always takes the manager) — mapped to the same deterministic panic.
    fn print_raw_join(&self, offset: u64) -> String {
        // JoinRecord *rec = getManager()->findJoin(offset);
        let tables = self.get_manager_join_tables();
        let tables = tables.unwrap_or_else(|| panic!("Unlinked join address"));
        let tables_ref = tables.borrow();
        let rec = tables_ref.find_join(offset);
        let mut szsum: i32 = 0;
        let num = rec.num_pieces();
        let mut out = String::from("{");
        for i in 0..num {
            let vdat = rec.get_piece(i);
            szsum += vdat.size;
            if i != 0 {
                out.push(',');
            }
            // vdat.space->printRaw(s,vdat.offset);
            out.push_str(&vdat.space.print_raw(vdat.offset));
        }
        if num == 1 {
            szsum = rec.get_unified().size;
            out.push_str(&format!(":{}", szsum));
        }
        out.push('}');
        out
    }

    // Ghidra: space.cc:126 AddrSpace::overlapJoin
    /// Determine how a point address falls in a range of this space.
    /// Faithful to `AddrSpace::overlapJoin` (space.cc:126-136): a different
    /// space never overlaps, and the distance wraps through `wrapOffset`.
    /// `ConstantSpace::overlapJoin` (space.cc:364) always returns -1; the
    /// join-space override needs the join-record database (residual).
    pub fn overlap_join(
        &self,
        offset: u64,
        size: i32,
        point_space: &AddrSpace,
        point_off: u64,
        point_skip: i64,
    ) -> i32 {
        if self.get_type() == SpaceType::Constant {
            return -1;
        }
        if self != point_space {
            return -1;
        }
        let dist = self.wrap_offset(
            point_off
                .wrapping_add(point_skip as u64)
                .wrapping_sub(offset),
        );
        if dist >= size as u64 {
            return -1; // but must fall before op+size
        }
        dist as u32 as i32
    }
}

// RUDRA-GLUE: PartialEq/Eq/Hash for AddrSpace (Ghidra compares AddrSpace
// pointers, e.g. `this != pointSpace` in overlapJoin and `vData.space ==
// pointSpace`; Rust expresses pointer identity through Rc equality.)
impl PartialEq for AddrSpace {
    // RUDRA-GLUE: eq (Ghidra never defines operator== for AddrSpace; it
    // compares raw AddrSpace pointers, e.g. space.cc:129 `this != pointSpace`.
    // Rust models that pointer identity via Rc::ptr_eq on the shared record.)
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for AddrSpace {}

// RUDRA-GLUE: Hash for AddrSpace (Ghidra spaces are used as pointer keys; the
// handle hashes by identity to stay consistent with PartialEq.)
impl std::hash::Hash for AddrSpace {
    // RUDRA-GLUE: hash (Ghidra hashes nothing here — spaces key C++ maps by
    // raw pointer; the handle hashes by Rc address to stay consistent with
    // the ptr-equality PartialEq above.)
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (Rc::as_ptr(&self.0) as usize).hash(state);
    }
}

// RUDRA-GLUE: Debug for AddrSpace (diagnostics only; Ghidra has no Debug.)
impl std::fmt::Debug for AddrSpace {
    // RUDRA-GLUE: fmt (Rust Debug formatting has no Ghidra behavioral
    // counterpart; diagnostics only.)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.0.borrow();
        f.debug_struct("AddrSpace")
            .field("name", &inner.name)
            .field("index", &inner.index)
            .finish()
    }
}

// RUDRA-GLUE: SpaceRegistry (Ghidra's AddrSpaceManager, translate.hh:220;
// renamed because translate.rs already hosts the legacy enum-based
// AddrSpaceManager until consumers migrate in ADDRESS-0001. The resolver and
// join-record halves (resolvelist/splitset/splitlist, translate.hh:222/234/235)
// stay with that legacy manager for now.)
/// A manager for different address spaces: creation, lookup by name or
/// shortcut, and iteration over address spaces in index order.
#[derive(Default)]
pub struct SpaceRegistry {
    // Ghidra: translate.hh:221 baselist
    /// Every space we know about for this architecture, indexed by space
    /// index. Holes (`None`) may exist and are skipped by ordered iteration.
    base_list: Vec<Option<AddrSpace>>,
    // Ghidra: translate.hh:223 name2Space
    /// Map from name to space.
    name_to_space: HashMap<String, AddrSpace>,
    // Ghidra: translate.hh:224 shortcut2Space
    /// Map from shortcut character to space.
    shortcut_to_space: HashMap<char, AddrSpace>,
    // Ghidra: translate.hh:225 constantspace
    /// Quick reference to the constant space.
    constant_space: Option<AddrSpace>,
    // Ghidra: translate.hh:226 defaultcodespace
    /// Default space where code lives, generally main RAM.
    default_code_space: Option<AddrSpace>,
    // Ghidra: translate.hh:227 defaultdataspace
    /// Default space where data lives.
    default_data_space: Option<AddrSpace>,
    // Ghidra: translate.hh:228 iopspace
    /// Space for internal pcode op pointers.
    iop_space: Option<AddrSpace>,
    // Ghidra: translate.hh:229 fspecspace
    /// Space for internal callspec pointers.
    fspec_space: Option<AddrSpace>,
    // Ghidra: translate.hh:230 joinspace
    /// Space for unifying split variables.
    join_space: Option<AddrSpace>,
    // Ghidra: translate.hh:231 stackspace
    /// Stack space associated with the processor.
    stack_space: Option<AddrSpace>,
    // Ghidra: translate.hh:232 uniqspace
    /// Unique space associated with the processor.
    uniq_space: Option<AddrSpace>,
    // Ghidra: translate.hh:233 AddrSpaceManager::joinallocate +
    //   translate.hh:234 AddrSpaceManager::splitset +
    //   translate.hh:235 AddrSpaceManager::splitlist
    /// The join-record halves plus the join-space allocation counter,
    /// shared with every registered join space via the
    /// `manager_join_tables` backlink (the join half of Ghidra's
    /// `AddrSpace::manage`, space.hh:118) so `JoinSpace::printRaw`
    /// (space.cc:593) can run `getManager()->findJoin` from the space
    /// handle alone. Shared (not a plain field) precisely because the
    /// spaces hold weak links into it.
    join_tables: Rc<RefCell<manager_join::JoinRecordTables>>,
    // RUDRA-GLUE: fspec_tables (the fspec half of Ghidra's
    // `AddrSpace::manage` backlink: C++ fspec offsets ARE FuncCallSpecs
    // pointers that printRaw/encodeAttributes dereference, fspec.cc:2125;
    // Rust resolves them through this shared table instead.)
    /// The offset→call-spec view table, shared with the registered fspec
    /// space via the `fspec_table` weak backlink.
    fspec_table: Rc<RefCell<FspecEntryTable>>,
}

impl SpaceRegistry {
    // Ghidra: translate.cc:235 AddrSpaceManager::AddrSpaceManager
    /// Construct an empty address space manager: every cached space slot is
    /// null and `joinallocate` starts at 0 (translate.cc:235-247).
    pub fn new() -> Self {
        Self::default()
    }

    // Ghidra: translate.hh:244 AddrSpaceManager::insertSpace
    /// Add a new address space to the model. Faithful to `insertSpace`
    /// (translate.cc:352-437): per-type name/index validation (with the
    /// immediate throws for a mis-indexed const or OTHER space), cached-slot
    /// routing, `baselist` growth on demand, duplicate name/id detection in
    /// Ghidra's exact order, Ghidra's exact error strings, `refcount += 1`
    /// only on success, and `assignShortcut` at the end.
    pub fn insert_space(&mut self, spc: AddrSpace) -> Result<(), String> {
        let mut name_type_mismatch = false;
        let mut duplicate_name = false;
        match spc.get_type() {
            SpaceType::Constant => {
                if spc.get_name() != CONSTANT_SPACE_NAME {
                    name_type_mismatch = true;
                }
                if spc.get_index() != CONSTANT_SPACE_INDEX {
                    // translate.cc:362-363 throws before touching any slot.
                    return Err("const space must be assigned index 0".to_string());
                }
                self.constant_space = Some(spc.clone());
            }
            SpaceType::Internal => {
                if spc.get_name() != UNIQUE_SPACE_NAME {
                    name_type_mismatch = true;
                }
                if self.uniq_space.is_some() {
                    duplicate_name = true;
                }
                self.uniq_space = Some(spc.clone());
            }
            SpaceType::Fspec => {
                if spc.get_name() != FSPEC_SPACE_NAME {
                    name_type_mismatch = true;
                }
                if self.fspec_space.is_some() {
                    duplicate_name = true;
                }
                // Wire the manager backlink (Ghidra's FspecSpace receives its
                // AddrSpaceManager in the constructor, fspec.cc:2116; Rudra
                // constructors take no manager, so insertSpace is the
                // association point). Wired before validation so an insert
                // that throws still leaves the space pointing at this
                // manager, like a Ghidra-constructed space.
                spc.set_fspec_table(&self.fspec_table);
                self.fspec_space = Some(spc.clone());
            }
            SpaceType::Join => {
                if spc.get_name() != "join" {
                    name_type_mismatch = true;
                }
                if self.join_space.is_some() {
                    duplicate_name = true;
                }
                // Wire the manager backlink (Ghidra's JoinSpace receives its
                // AddrSpaceManager in the constructor, space.cc:446; Rudra
                // constructors take no manager, so insertSpace is the
                // association point). Wired before validation so an insert
                // that throws still leaves the space pointing at this
                // manager, like a Ghidra-constructed space.
                spc.set_manager_join_tables(&self.join_tables);
                self.join_space = Some(spc.clone());
            }
            SpaceType::Iop => {
                if spc.get_name() != "iop" {
                    name_type_mismatch = true;
                }
                if self.iop_space.is_some() {
                    duplicate_name = true;
                }
                self.iop_space = Some(spc.clone());
            }
            SpaceType::SpaceBase | SpaceType::Processor => {
                // translate.cc:394-399: only a SPACEBASE named "stack" is
                // cached in the stackspace slot, then falls through.
                if spc.get_type() == SpaceType::SpaceBase && spc.get_name() == "stack" {
                    if self.stack_space.is_some() {
                        duplicate_name = true;
                    }
                    self.stack_space = Some(spc.clone());
                }
                if spc.is_overlay() {
                    // Mark the base as being overlayed.
                    let contain = spc
                        .get_contain()
                        .expect("overlay space without a containing space");
                    contain.set_flags(space_flags::OVERLAYBASE);
                } else if spc.is_other_space() && spc.get_index() != OTHER_SPACE_INDEX {
                    // translate.cc:405-408 throws before touching baselist.
                    return Err("OTHER space must be assigned index 1".to_string());
                }
            }
        }

        // RUDRA-GLUE: Ghidra indexes baselist with a possibly-negative int4
        // (undefined behavior); Rust guards the conversion because Vec
        // indexing requires usize.
        let idx = usize::try_from(spc.get_index())
            .expect("address space index must be non-negative");
        if self.base_list.len() <= idx {
            self.base_list.resize(idx + 1, None);
        }
        let duplicate_id = self.base_list[idx].is_some();

        if !name_type_mismatch && !duplicate_name && !duplicate_id {
            if self
                .name_to_space
                .insert(spc.get_name(), spc.clone())
                .is_some()
            {
                duplicate_name = true;
            }
        }

        if name_type_mismatch || duplicate_name || duplicate_id {
            let mut err_msg = format!("Space {}", spc.get_name());
            if name_type_mismatch {
                err_msg.push_str(" was initialized with wrong type");
            }
            if duplicate_name {
                err_msg.push_str(" was initialized more than once");
            }
            if duplicate_id {
                let holder = self.base_list[idx]
                    .as_ref()
                    .map(|s| s.get_name())
                    .unwrap_or_default();
                err_msg.push_str(&format!(" was assigned as id duplicating: {}", holder));
            }
            // translate.cc:429-431 deletes the unreferenced space; Rust's
            // caller keeps the handle but its refcount stays 0, matching the
            // Ghidra post-throw observable.
            return Err(err_msg);
        }
        self.base_list[idx] = Some(spc.clone());
        spc.increment_refcount();
        self.assign_shortcut(&spc);
        Ok(())
    }

    // Ghidra: translate.hh:242 AddrSpaceManager::assignShortcut
    /// Select a shortcut character for a new space. Faithful to
    /// `assignShortcut` (translate.cc:517-573): an already-assigned shortcut
    /// is re-registered directly; otherwise the character is chosen by type
    /// (`'#'` const, `'%'` for a processor space named "register", first name
    /// character for other processor spaces, `'s'` spacebase, `'u'` unique,
    /// `'f'` fspec, `'j'` join, `'i'` iop), upper-case is folded to
    /// lower-case, collisions advance the character with `a`–`z` wrapping,
    /// and after 26 collisions the space reuses `'z'` WITHOUT updating the
    /// map (so `get_space_by_shortcut('z')` still returns the older space).
    fn assign_shortcut(&mut self, spc: &AddrSpace) {
        if spc.get_shortcut() != ' ' {
            self.shortcut_to_space
                .insert(spc.get_shortcut(), spc.clone());
            return;
        }
        let mut shortcut: char = match spc.get_type() {
            SpaceType::Constant => '#',
            SpaceType::Processor => {
                if spc.get_name() == "register" {
                    '%'
                } else {
                    // Ghidra reads name[0]; an empty std::string yields '\0'.
                    spc.get_name().chars().next().unwrap_or('\0')
                }
            }
            SpaceType::SpaceBase => 's',
            SpaceType::Internal => 'u',
            SpaceType::Fspec => 'f',
            SpaceType::Join => 'j',
            SpaceType::Iop => 'i',
        };

        if ('A'..='Z').contains(&shortcut) {
            shortcut = ((shortcut as u8) + 0x20) as char;
        }

        let mut collision_count = 0u32;
        loop {
            // Ghidra's map insert fails on an existing key without replacing
            // it; Rust's HashMap::insert replaces, so membership is checked
            // first to keep the losing space out of the map entirely.
            if !self.shortcut_to_space.contains_key(&shortcut) {
                self.shortcut_to_space.insert(shortcut, spc.clone());
                spc.set_shortcut(shortcut);
                return;
            }
            collision_count += 1;
            if collision_count > 26 {
                // Reuse 'z' without registering in the map (translate.cc:561-566).
                spc.set_shortcut('z');
                return;
            }
            // shortcut += 1 with the a..z wrap (translate.cc:568-570).
            let mut next = (shortcut as u8).wrapping_add(1) as char;
            if !('a'..='z').contains(&next) {
                next = 'a';
            }
            shortcut = next;
        }
    }

    // Ghidra: translate.hh:254 AddrSpaceManager::getSpaceByName
    /// Get an address space by name. Faithful to `getSpaceByName`
    /// (translate.cc:590-597).
    pub fn get_space_by_name(&self, nm: &str) -> Option<AddrSpace> {
        self.name_to_space.get(nm).cloned()
    }

    // Ghidra: translate.hh:255 AddrSpaceManager::getSpaceByShortcut
    /// Get an address space from its shortcut. Faithful to
    /// `getSpaceByShortcut` (translate.cc:604-612).
    pub fn get_space_by_shortcut(&self, sc: char) -> Option<AddrSpace> {
        self.shortcut_to_space.get(&sc).cloned()
    }

    // Ghidra: translate.hh:256 AddrSpaceManager::getIopSpace
    /// Get the internal pcode op space (translate.hh:457-459).
    pub fn get_iop_space(&self) -> Option<AddrSpace> {
        self.iop_space.clone()
    }

    // Ghidra: translate.hh:257 AddrSpaceManager::getFspecSpace
    /// Get the internal callspec space (translate.hh:466-468).
    pub fn get_fspec_space(&self) -> Option<AddrSpace> {
        self.fspec_space.clone()
    }

    // RUDRA-GLUE: register_fspec_entry — Ghidra needs no registration: a
    /// C++ fspec offset IS a live `FuncCallSpecs *` whose members
    /// printRaw/encodeAttributes read (fspec.cc:2125). The Rust registry
    /// mirrors that dereference through its fspec-entry table; TYPEOP-FSPEC-
    /// SPACE-0001 slice 2 moves the calls to the Funcdata callspec bank.
    /// Associate an fspec-space `offset` with the call-spec view
    /// (name + entry address) the C++ dereference would observe.
    pub fn register_fspec_entry(
        &mut self,
        offset: u64,
        name: &str,
        entry: Option<(&AddrSpace, u64)>,
    ) {
        self.fspec_table.borrow_mut().register(
            offset,
            name,
            entry.map(|(spc, off)| (spc.clone(), off)),
        );
    }

    // Ghidra: translate.hh:258 AddrSpaceManager::getJoinSpace
    /// Get the joining space (translate.hh:475-477).
    pub fn get_join_space(&self) -> Option<AddrSpace> {
        self.join_space.clone()
    }

    // Ghidra: translate.hh:270 AddrSpaceManager::findAddJoin
    /// Get (or create) the JoinRecord for `pieces` (most significant to
    /// least significant). Faithful to `findAddJoin`
    /// (translate.cc:671-715 — see
    /// [`manager_join::JoinRecordTables::find_add_join`]); returns the
    /// unified join-space offset of the record, from which
    /// [`SpaceRegistry::find_join`] recovers the pieces. Requires the join
    /// space to be registered (Ghidra's manager always has one when
    /// findAddJoin runs).
    pub fn find_add_join(&mut self, pieces: &[SpaceVarnodeData], logical_size: u32) -> u64 {
        let joinspace = self
            .join_space
            .clone()
            .expect("findAddJoin without a registered join space");
        self.join_tables
            .borrow_mut()
            .find_add_join(pieces, logical_size, &joinspace)
    }

    // Ghidra: translate.hh:271 AddrSpaceManager::findJoin
    /// Find the JoinRecord for join-space `offset` (translate.cc:746-762).
    /// Panics with `Unlinked join address` when no record matches, exactly
    /// like Ghidra's LowlevelError. Returns a clone so the caller does not
    /// hold the shared-table borrow.
    pub fn find_join(&self, offset: u64) -> manager_join::JoinRecord {
        self.join_tables.borrow().find_join(offset).clone()
    }

    // Ghidra: translate.hh:259 AddrSpaceManager::getStackSpace
    /// Get the stack space for this processor (translate.hh:484-486).
    pub fn get_stack_space(&self) -> Option<AddrSpace> {
        self.stack_space.clone()
    }

    // Ghidra: translate.hh:260 AddrSpaceManager::getUniqueSpace
    /// Get the temporary register space (translate.hh:496-498).
    pub fn get_unique_space(&self) -> Option<AddrSpace> {
        self.uniq_space.clone()
    }

    // Ghidra: translate.hh:261 AddrSpaceManager::getDefaultCodeSpace
    /// Get the default code space (translate.hh:505-507).
    pub fn get_default_code_space(&self) -> Option<AddrSpace> {
        self.default_code_space.clone()
    }

    // Ghidra: translate.hh:262 AddrSpaceManager::getDefaultDataSpace
    /// Get the default data space (translate.hh:514-516).
    pub fn get_default_data_space(&self) -> Option<AddrSpace> {
        self.default_data_space.clone()
    }

    // Ghidra: translate.hh:263 AddrSpaceManager::getConstantSpace
    /// Get the constant space (translate.hh:522-524).
    pub fn get_constant_space(&self) -> Option<AddrSpace> {
        self.constant_space.clone()
    }

    // Ghidra: translate.hh:253 AddrSpaceManager::getDefaultSize
    /// Get the size of addresses for the default space. Faithful to the
    /// inline `getDefaultSize` (translate.hh:448-450), which dereferences the
    /// default code space unconditionally.
    pub fn get_default_size(&self) -> u32 {
        self.default_code_space
            .as_ref()
            .expect("getDefaultSize without a default code space")
            .get_addr_size()
    }

    // Ghidra: translate.hh:267 AddrSpaceManager::numSpaces
    /// Get the number of address-space slots (including empty holes),
    /// faithful to `numSpaces` (translate.hh:550-552): `baselist.size()`.
    pub fn num_spaces(&self) -> usize {
        self.base_list.len()
    }

    // Ghidra: translate.hh:268 AddrSpaceManager::getSpace
    /// Get an address space via its index. Faithful to `getSpace`
    /// (translate.hh:559-561): returns the slot content, which is `None` for
    /// a hole or an out-of-range index (Ghidra returns a null or reads out of
    /// bounds; Rust clamps to `None`).
    pub fn get_space(&self, i: usize) -> Option<AddrSpace> {
        self.base_list.get(i).cloned().flatten()
    }

    // Ghidra: translate.hh:269 AddrSpaceManager::getNextSpaceInOrder
    /// Get the next space in the absolute order of addresses. Faithful to
    /// `getNextSpaceInOrder` (translate.cc:647-663) with Ghidra's three
    /// cursor states mapped onto `Option`: `None` as input means "start from
    /// `baselist[0]`" (Ghidra's null), a valid handle advances from
    /// `index+1` skipping holes, and `None` as output is Ghidra's
    /// `~((uintp)0)` end sentinel (also returned when the sentinel is fed
    /// back in, because a `None` input restarts from slot 0 which is empty
    /// at that point in the iteration protocol).
    pub fn get_next_space_in_order(&self, spc: Option<AddrSpace>) -> Option<AddrSpace> {
        let Some(spc) = spc else {
            return self.base_list.first().cloned().flatten();
        };
        let mut index = spc.get_index() + 1;
        while (index as usize) < self.base_list.len() {
            if let Some(res) = &self.base_list[index as usize] {
                return Some(res.clone());
            }
            index += 1;
        }
        None
    }

    // Ghidra: translate.hh:246 AddrSpaceManager::addSpacebasePointer
    /// Set the base register of a spacebase space. Faithful to
    /// `addSpacebasePointer` (translate.cc:460-464), which performs the
    /// privileged act of calling the space's `setBaseRegister`
    /// (translate.cc:86-102).
    pub fn add_spacebase_pointer(
        &self,
        basespace: &AddrSpace,
        ptrdata: &SpaceVarnodeData,
        trunc_size: i32,
        stack_growth: bool,
    ) -> Result<(), String> {
        basespace.set_base_register(ptrdata, trunc_size, stack_growth)
    }

    // Ghidra: translate.hh:239 AddrSpaceManager::setDefaultCodeSpace
    /// Set the default code space by index. Faithful to `setDefaultCodeSpace`
    /// (translate.cc:309-318): refuses a second assignment and a bad index;
    /// the default data space is set to the same space.
    pub fn set_default_code_space(&mut self, index: usize) -> Result<(), String> {
        if self.default_code_space.is_some() {
            return Err("Default space set multiple times".to_string());
        }
        let spc = match self.base_list.get(index).cloned().flatten() {
            Some(spc) => spc,
            None => return Err("Bad index for default space".to_string()),
        };
        self.default_code_space = Some(spc.clone());
        self.default_data_space = Some(spc);
        Ok(())
    }

    // Ghidra: translate.hh:240 AddrSpaceManager::setDefaultDataSpace
    /// Set the default data space by index, after the code space. Faithful to
    /// `setDefaultDataSpace` (translate.cc:323-331).
    pub fn set_default_data_space(&mut self, index: usize) -> Result<(), String> {
        if self.default_code_space.is_none() {
            return Err("Default data space must be set after the code space".to_string());
        }
        let spc = match self.base_list.get(index).cloned().flatten() {
            Some(spc) => spc,
            None => return Err("Bad index for default data space".to_string()),
        };
        self.default_data_space = Some(spc);
        Ok(())
    }

    // Ghidra: translate.hh:241 AddrSpaceManager::setReverseJustified
    /// Set the reverse-justified property on a space. Faithful to
    /// `setReverseJustified` (translate.cc:338-342).
    pub fn set_reverse_justified(&self, spc: &AddrSpace) {
        spc.set_flags(space_flags::REVERSE_JUSTIFICATION);
    }

    // Ghidra: translate.hh:243 AddrSpaceManager::markNearPointers
    /// Mark that a space can be accessed with near pointers. Faithful to
    /// `markNearPointers` (translate.cc:577-583): sets `has_nearpointers` and
    /// establishes `minimumPointerSize` when it is still 0 and the space size
    /// differs.
    pub fn mark_near_pointers(&self, spc: &AddrSpace, size: i32) {
        spc.set_flags(space_flags::HAS_NEARPOINTERS);
        let mut inner = spc.0.borrow_mut();
        if inner.minimum_pointer_size == 0 && inner.address_size != size as u32 {
            inner.minimum_pointer_size = size;
        }
    }

    // Ghidra: translate.hh:248 AddrSpaceManager::setInferPtrBounds
    /// Establish the range of constants checked as possible symbol starts
    /// for one space. Faithful to `setInferPtrBounds` (translate.cc:483-488),
    /// which writes `pointerLowerBound`/`pointerUpperBound` on the range's
    /// space. The `Range` object itself belongs to the legacy address module;
    /// its space/first/last values are passed directly.
    pub fn set_infer_ptr_bounds(&self, space: &AddrSpace, first: u64, last: u64) {
        let mut inner = space.0.borrow_mut();
        inner.pointer_lower_bound = first;
        inner.pointer_upper_bound = last;
    }

    // Ghidra: translate.hh:245 AddrSpaceManager::copySpaces
    /// Copy every space from another manager, sharing the same records.
    /// Faithful to `copySpaces` (translate.cc:443-453): insert in baselist
    /// order, then set the default code and data spaces from the source's
    /// indices.
    pub fn copy_spaces(&mut self, op2: &SpaceRegistry) -> Result<(), String> {
        for spc in &op2.base_list {
            if let Some(spc) = spc {
                self.insert_space(spc.clone())?;
            }
        }
        let code_index = op2
            .default_code_space
            .as_ref()
            .expect("copySpaces source without a default code space")
            .get_index() as usize;
        self.set_default_code_space(code_index)?;
        let data_index = op2
            .default_data_space
            .as_ref()
            .expect("copySpaces source without a default data space")
            .get_index() as usize;
        self.set_default_data_space(data_index)?;
        Ok(())
    }

    // Ghidra: translate.hh:272 AddrSpaceManager::setDeadcodeDelay
    /// Set the number of passes before deadcode removal is allowed for a
    /// space. Faithful to `setDeadcodeDelay` (translate.cc:768-773).
    pub fn set_deadcode_delay(&self, spc: &AddrSpace, delaydelta: i32) {
        spc.0.borrow_mut().deadcode_delay = delaydelta;
    }

    // Ghidra: translate.hh:273 AddrSpaceManager::truncateSpace
    /// Mark the named space as truncated. Faithful to the manager wrapper
    /// (translate.cc:776-784): unknown names are an error, otherwise the
    /// space's `truncateSpace` (space.cc:105-112) runs.
    pub fn truncate_space(&mut self, name: &str, newsize: u32) -> Result<(), String> {
        let spc = match self.get_space_by_name(name) {
            Some(spc) => spc,
            None => {
                return Err(format!(
                    "Unknown space in <truncate_space> command: {}",
                    name
                ))
            }
        };
        spc.truncate_space(newsize);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_id() {
        assert_eq!(AddressSpace::Ram.space_id(), SPACEID_RAM);
        assert_eq!(AddressSpace::Register.space_id(), SPACEID_REGISTER);
        assert_eq!(AddressSpace::Unique.space_id(), SPACEID_UNIQUE);
        assert_eq!(AddressSpace::Const.space_id(), SPACEID_CONST);
    }

    #[test]
    fn test_address_space_from_spec_name() {
        // AddrSpaceManager::getSpaceByName (translate.cc:590-597) reverse
        // table for the enum model: every locked spec name resolves, other
        // names (including dynamic/overlay names and the variant-less
        // "fspec") return None.
        assert_eq!(
            AddressSpace::from_spec_name("ram"),
            Some(AddressSpace::Ram)
        );
        assert_eq!(
            AddressSpace::from_spec_name("register"),
            Some(AddressSpace::Register)
        );
        assert_eq!(
            AddressSpace::from_spec_name("stack"),
            Some(AddressSpace::Stack)
        );
        assert_eq!(
            AddressSpace::from_spec_name("unique"),
            Some(AddressSpace::Unique)
        );
        assert_eq!(
            AddressSpace::from_spec_name("const"),
            Some(AddressSpace::Const)
        );
        assert_eq!(
            AddressSpace::from_spec_name("join"),
            Some(AddressSpace::Join)
        );
        assert_eq!(
            AddressSpace::from_spec_name("iop"),
            Some(AddressSpace::Iop)
        );
        assert_eq!(
            AddressSpace::from_spec_name("OTHER"),
            Some(AddressSpace::Other(SPACEID_OTHER))
        );
        assert_eq!(AddressSpace::from_spec_name("fspec"), None);
        assert_eq!(AddressSpace::from_spec_name("overlay"), None);
        assert_eq!(AddressSpace::from_spec_name("nosuch"), None);
    }

    #[test]
    fn test_address_space_from_id() {
        assert_eq!(AddressSpace::from_id(SPACEID_RAM), AddressSpace::Ram);
        assert_eq!(
            AddressSpace::from_id(SPACEID_REGISTER),
            AddressSpace::Register
        );
        assert_eq!(AddressSpace::from_id(SPACEID_UNIQUE), AddressSpace::Unique);
        assert_eq!(AddressSpace::from_id(SPACEID_CONST), AddressSpace::Const);
    }

    #[test]
    fn test_address_space_predicates() {
        assert!(AddressSpace::Register.is_register());
        assert!(AddressSpace::Unique.is_unique());
        assert!(AddressSpace::Const.is_const());
        assert!(AddressSpace::Ram.is_ram());
        assert!(AddressSpace::Stack.is_stack());

        assert!(!AddressSpace::Ram.is_register());
        assert!(!AddressSpace::Register.is_const());
    }

    #[test]
    fn test_address_space_display() {
        assert_eq!(AddressSpace::Ram.to_string(), "ram");
        assert_eq!(AddressSpace::Register.to_string(), "register");
        assert_eq!(AddressSpace::Unique.to_string(), "unique");
        assert_eq!(AddressSpace::Const.to_string(), "const");
    }

    #[test]
    fn test_unique_space_allocation() {
        let mut unique = UniqueSpace::new();

        let offset1 = unique.allocate(4);
        let offset2 = unique.allocate(8);
        let offset3 = unique.allocate(4);

        assert_eq!(offset1, 0);
        assert_eq!(offset2, 4);
        assert_eq!(offset3, 12);

        unique.reset();
        let offset4 = unique.allocate(4);
        assert_eq!(offset4, 0);
    }

    #[test]
    fn test_join_space() {
        let pieces = vec![
            JoinPiece {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            },
            JoinPiece {
                space: AddressSpace::Register,
                offset: 4,
                size: 4,
            },
        ];

        let join = JoinSpace::new(pieces);
        assert_eq!(join.size(), 8);
        assert_eq!(join.num_pieces(), 2);
    }

    #[test]
    fn test_overlay_space() {
        let overlay = OverlaySpace::new(10, AddressSpace::Ram, "code_overlay".to_string());
        assert_eq!(overlay.base(), AddressSpace::Ram);
        assert_eq!(overlay.space(), AddressSpace::Overlay);
    }

    #[test]
    fn test_constant_space_methods() {
        let const_space = ConstantSpace::new();
        assert_eq!(const_space.print_raw(), "const_space[0]");
        assert!(!const_space.overlap_join(0, 100));
    }

    #[test]
    fn test_other_space_print_raw() {
        let other = OtherSpace::new(10, "custom".to_string());
        assert_eq!(other.print_raw(), "other_space[10]:'custom'");
    }

    #[test]
    fn test_join_space_decode_encode() {
        let pieces = vec![
            JoinPiece {
                space: AddressSpace::Register,
                offset: 0,
                size: 4,
            },
            JoinPiece {
                space: AddressSpace::Register,
                offset: 4,
                size: 4,
            },
        ];
        let join = JoinSpace::new(pieces);

        let attrs = join.encode_attributes();
        assert_eq!(attrs.len(), 2);

        assert!(join.overlap_join(0, 4));
        assert!(!join.overlap_join(100, 4));
    }

    #[test]
    fn test_overlay_space_decode() {
        let overlay = OverlaySpace::decode("10:3:test_overlay").unwrap();
        assert_eq!(overlay.id, 10);
        assert_eq!(overlay.base(), AddressSpace::Ram);
        assert_eq!(overlay.name, "test_overlay");
    }

    // ------------------------------------------------------------------------
    // SPACE-0001 registry regression tests (Rudra-side only; oracle parity is
    // proven by tests/oracle/space_registry_1204.* + runner).
    // ------------------------------------------------------------------------

    fn canonical_registry() -> SpaceRegistry {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        m.insert_space(AddrSpace::new_other_space()).unwrap();
        m.insert_space(AddrSpace::new_unique_space(2, 0, false))
            .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "ram",
            false,
            8,
            1,
            3,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor,
            "register",
            false,
            8,
            1,
            4,
            space_flags::HASPHYSICAL,
            0,
            0,
        ))
        .unwrap();
        let ram = m.get_space_by_name("ram").unwrap();
        m.insert_space(AddrSpace::new_spacebase_space(
            "stack", 5, 8, &ram, 1, true, false,
        ))
        .unwrap();
        m.insert_space(AddrSpace::new_join_space(6, false)).unwrap();
        m.insert_space(AddrSpace::new_iop_space(7, false)).unwrap();
        m.set_default_code_space(3).unwrap();
        m
    }

    #[test]
    fn test_registry_canonical_projection() {
        let m = canonical_registry();
        assert_eq!(m.num_spaces(), 8);
        let ram = m.get_space_by_name("ram").unwrap();
        assert_eq!(ram.get_index(), 3);
        assert_eq!(ram.get_addr_size(), 8);
        assert_eq!(ram.get_word_size(), 1);
        assert!(!ram.is_big_endian());
        assert!(ram.has_physical());
        assert!(ram.is_heritaged());
        assert_eq!(ram.get_highest(), 0xffffffffffffffff);
        assert_eq!(ram.get_pointer_lower_bound(), 0x1000);
        assert_eq!(ram.get_pointer_upper_bound(), 0xffffffffffffefff);
        assert_eq!(ram.refcount(), 1);
        let stack = m.get_space_by_name("stack").unwrap();
        assert_eq!(stack.get_type(), SpaceType::SpaceBase);
        assert!(stack.is_formal_stackspace());
        assert_eq!(stack.get_delay(), 1);
        assert_eq!(stack.get_deadcode_delay(), 1);
        assert_eq!(stack.get_shortcut(), 's');
        let iop = m.get_space_by_name("iop").unwrap();
        assert!(!iop.is_heritaged());
        assert!(!iop.does_deadcode());
        assert_eq!(iop.get_delay(), 1);
        let join = m.get_space_by_name("join").unwrap();
        assert!(!join.is_heritaged());
        assert!(join.does_deadcode());
        assert_eq!(join.get_addr_size(), 4);
        assert_eq!(m.get_default_size(), 8);
    }

    #[test]
    fn test_registry_rejection_paths() {
        // Fresh manager with const/ram/register only, mirroring the locked
        // oracle fixture scenario (tests/oracle/space_registry_1204.cc).
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, space_flags::HASPHYSICAL, 0, 0,
        ))
        .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor, "register", false, 8, 1, 4, space_flags::HASPHYSICAL, 0, 0,
        ))
        .unwrap();
        // duplicate id
        let dup_id = AddrSpace::new_space(
            SpaceType::Processor, "extra", false, 8, 1, 3, 0, 0, 0);
        assert_eq!(
            m.insert_space(dup_id),
            Err("Space extra was assigned as id duplicating: ram".to_string())
        );
        // duplicate name (grows baselist to index+1 before rejecting)
        let dup_name = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 9, 0, 0, 0);
        assert_eq!(
            m.insert_space(dup_name),
            Err("Space ram was initialized more than once".to_string())
        );
        // wrong type name
        let wrong_type = AddrSpace::new_space(
            SpaceType::Internal, "tmpx", false, 8, 1, 9, 0, 0, 0);
        assert_eq!(
            m.insert_space(wrong_type),
            Err("Space tmpx was initialized with wrong type".to_string())
        );
        // const wrong index
        let bad_const = AddrSpace::new_space(
            SpaceType::Constant, "const", false, 8, 1, 5, 0, 0, 0);
        assert_eq!(
            m.insert_space(bad_const),
            Err("const space must be assigned index 0".to_string())
        );
        // OTHER wrong index
        let bad_other = AddrSpace::new_space(
            SpaceType::Processor, "OTHER", false, 8, 1, 5, 0, 0, 0);
        bad_other.set_flags(space_flags::IS_OTHERSPACE);
        assert_eq!(
            m.insert_space(bad_other),
            Err("OTHER space must be assigned index 1".to_string())
        );
        assert_eq!(m.num_spaces(), 10);
        assert!(m.get_space_by_name("extra").is_none());
        assert!(m.get_space(9).is_none());
    }

    #[test]
    fn test_registry_hole_fill_and_iteration() {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, 0, 0, 0,
        ))
        .unwrap();
        assert_eq!(m.num_spaces(), 4);
        assert!(m.get_space(1).is_none());
        let mut names = Vec::new();
        let mut cur = m.get_next_space_in_order(None);
        while let Some(spc) = cur {
            names.push(spc.get_name());
            cur = m.get_next_space_in_order(Some(spc));
        }
        assert_eq!(names, vec!["const", "ram"]);
        // Late fill of the dead hole at index 2.
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor, "extra", false, 8, 1, 2, 0, 0, 0,
        ))
        .unwrap();
        assert_eq!(m.num_spaces(), 4);
        let mut names = Vec::new();
        let mut cur = m.get_next_space_in_order(None);
        while let Some(spc) = cur {
            names.push(spc.get_name());
            cur = m.get_next_space_in_order(Some(spc));
        }
        assert_eq!(names, vec!["const", "extra", "ram"]);
    }

    #[test]
    fn test_registry_shortcut_collision() {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        m.insert_space(AddrSpace::new_spacebase_space(
            "stack",
            1,
            8,
            &AddrSpace::new_space(SpaceType::Processor, "ram", false, 8, 1, 2, 0, 0, 0),
            0,
            true,
            false,
        ))
        .unwrap();
        m.insert_space(AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 2, 0, 0, 0,
        ))
        .unwrap();
        let sram = AddrSpace::new_space(
            SpaceType::Processor, "sram", false, 8, 1, 3, 0, 0, 0);
        m.insert_space(sram.clone()).unwrap();
        assert_eq!(sram.get_shortcut(), 't');
        assert_eq!(m.get_space_by_shortcut('s').unwrap().get_name(), "stack");
        assert_eq!(m.get_space_by_shortcut('t').unwrap().get_name(), "sram");
        assert_eq!(m.get_space_by_shortcut('#').unwrap().get_name(), "const");
    }

    #[test]
    fn test_registry_shortcut_z_reuse_after_26_collisions() {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        for (i, c) in (b'a'..=b'z').enumerate() {
            let name: String = std::iter::repeat(c as char).take(2).collect();
            m.insert_space(AddrSpace::new_space(
                SpaceType::Processor, &name, false, 8, 1, i as i32 + 1, 0, 0, 0,
            ))
            .unwrap();
        }
        let apple = AddrSpace::new_space(
            SpaceType::Processor, "apple", false, 8, 1, 27, 0, 0, 0);
        m.insert_space(apple.clone()).unwrap();
        assert_eq!(apple.get_shortcut(), 'z');
        // The map still points 'z' at the earlier space (translate.cc:559-566
        // reuses 'z' without updating the map).
        assert_eq!(m.get_space_by_shortcut('z').unwrap().get_name(), "zz");
    }

    #[test]
    fn test_registry_projection_wordsize_endian() {
        let m = SpaceRegistry::new();
        let ws2 = AddrSpace::new_space(
            SpaceType::Processor, "ws2", false, 4, 2, 3, 0, 0, 0);
        assert_eq!(ws2.get_highest(), 0x1ffffffff);
        assert_eq!(ws2.get_pointer_lower_bound(), 0x1000);
        assert_eq!(ws2.get_pointer_upper_bound(), 0x1ffffefff);
        let small = AddrSpace::new_space(
            SpaceType::Processor, "small", false, 2, 3, 4, 0, 0, 0);
        assert_eq!(small.get_highest(), 0x2ffff);
        assert_eq!(small.get_pointer_lower_bound(), 0x100);
        assert_eq!(small.get_pointer_upper_bound(), 0x2feff);
        let be = AddrSpace::new_space(
            SpaceType::Processor, "be", true, 8, 1, 5, 0, 0, 0);
        assert!(be.is_big_endian());
        assert_eq!(AddrSpace::address_to_byte(5, 2), 10);
        assert_eq!(AddrSpace::byte_to_address(10, 2), 5);
        // wrapOffset
        let spc = AddrSpace::new_space(
            SpaceType::Processor, "wr", false, 4, 1, 6, 0, 0, 0);
        assert_eq!(spc.wrap_offset(0xffffffff), 0xffffffff);
        assert_eq!(spc.wrap_offset(0x100000000), 0);
        assert_eq!(spc.wrap_offset(0x100000001), 1);
        // near pointers / reverse justification / infer bounds / deadcode
        m.mark_near_pointers(&spc, 2);
        assert!(spc.has_near_pointers());
        assert_eq!(spc.get_minimum_ptr_size(), 2);
        m.set_reverse_justified(&spc);
        assert!(spc.is_reverse_justified());
        m.set_infer_ptr_bounds(&spc, 0x10, 0x20);
        assert_eq!(spc.get_pointer_lower_bound(), 0x10);
        assert_eq!(spc.get_pointer_upper_bound(), 0x20);
        m.set_deadcode_delay(&spc, 7);
        assert_eq!(spc.get_deadcode_delay(), 7);
        // truncate
        let big = AddrSpace::new_space(
            SpaceType::Processor, "big", false, 8, 1, 7, 0, 0, 0);
        big.truncate_space(4);
        assert!(big.is_truncated());
        assert_eq!(big.get_minimum_ptr_size(), 4);
        assert_eq!(big.get_highest(), 0xffffffff);
    }

    #[test]
    fn test_registry_spacebase_pointer_bridge() {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        let reg = AddrSpace::new_space(
            SpaceType::Processor, "register", false, 8, 1, 4, 0, 0, 0);
        m.insert_space(reg.clone()).unwrap();
        let ram = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, 0, 0, 0);
        m.insert_space(ram.clone()).unwrap();
        let stack = AddrSpace::new_spacebase_space(
            "stack", 5, 8, &ram, 1, true, false);
        m.insert_space(stack.clone()).unwrap();
        let ptr = SpaceVarnodeData {
            space: reg.clone(),
            offset: 0,
            size: 8,
        };
        m.add_spacebase_pointer(&stack, &ptr, 8, true).unwrap();
        assert_eq!(stack.num_spacebase(), 1);
        let base = stack.get_spacebase(0).unwrap();
        assert_eq!(base.offset, 0);
        assert_eq!(base.size, 8);
        assert_eq!(base.space, reg);
        assert!(stack.stack_grows_negative());
        assert_eq!(stack.get_contain(), Some(ram));
        // Idempotent re-assignment with identical data.
        m.add_spacebase_pointer(&stack, &ptr, 8, true).unwrap();
        // Conflicting re-assignment is rejected.
        let other = SpaceVarnodeData {
            space: reg.clone(),
            offset: 8,
            size: 8,
        };
        assert_eq!(
            m.add_spacebase_pointer(&stack, &other, 8, true),
            Err("Attempt to assign more than one base register to space: stack".to_string())
        );
        assert_eq!(
            stack.get_spacebase(1),
            Err("No base register specified for space: stack".to_string())
        );
        // Truncation on a big-endian register space shifts the offset up.
        let bereg = AddrSpace::new_space(
            SpaceType::Processor, "beregi", true, 8, 1, 6, 0, 0, 0);
        let beptr = SpaceVarnodeData {
            space: bereg.clone(),
            offset: 0x100,
            size: 8,
        };
        let bebase = AddrSpace::new_space(
            SpaceType::Processor, "beram", true, 8, 1, 7, 0, 0, 0);
        let bestack = AddrSpace::new_spacebase_space(
            "bestack", 8, 8, &bebase, 0, false, true);
        m.add_spacebase_pointer(&bestack, &beptr, 4, false).unwrap();
        let base = bestack.get_spacebase(0).unwrap();
        assert_eq!(base.offset, 0x104);
        assert_eq!(base.size, 4);
        let full = bestack.get_spacebase_full(0).unwrap();
        assert_eq!(full.offset, 0x100);
        assert_eq!(full.size, 8);
        assert!(!bestack.stack_grows_negative());
    }

    #[test]
    fn test_registry_copy_spaces_refcount() {
        let a = canonical_registry();
        let mut b = SpaceRegistry::new();
        b.copy_spaces(&a).unwrap();
        assert_eq!(b.num_spaces(), 8);
        assert_eq!(b.get_space_by_name("ram").unwrap().refcount(), 2);
        assert_eq!(a.get_space_by_name("ram").unwrap().refcount(), 2);
        assert_eq!(b.get_default_size(), 8);
        assert_eq!(b.get_default_code_space().unwrap().get_name(), "ram");
        assert!(b.get_stack_space().is_some());
        assert!(b.get_iop_space().is_some());
        assert!(b.get_join_space().is_some());
        assert!(b.get_unique_space().is_some());
        assert!(b.get_constant_space().is_some());
    }

    #[test]
    fn test_registry_overlay_marks_base() {
        let mut m = SpaceRegistry::new();
        let ram = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, space_flags::HASPHYSICAL, 0, 0,
        );
        m.insert_space(ram.clone()).unwrap();
        let ov = AddrSpace::new_overlay_space("code_overlay", 4, &ram);
        m.insert_space(ov).unwrap();
        assert!(ram.is_overlay_base());
        let ov = m.get_space_by_name("code_overlay").unwrap();
        assert!(ov.is_overlay());
        assert_eq!(ov.get_addr_size(), 8);
        assert_eq!(ov.get_word_size(), 1);
        assert_eq!(ov.get_contain().unwrap(), ram);
        // Unknown-space truncation error.
        assert_eq!(
            m.truncate_space("nosuch", 4),
            Err("Unknown space in <truncate_space> command: nosuch".to_string())
        );
        m.truncate_space("ram", 4).unwrap();
        assert!(ram.is_truncated());
        assert_eq!(ram.get_minimum_ptr_size(), 4);
    }

    // RUDRA-GLUE: test helper building the fixture-shaped registry (const=0,
    // unique=2, ram=3, register=4, join=6, iop=7) like the locked oracle
    // fixture space_printraw_special_1204.
    fn special_printraw_registry() -> (SpaceRegistry, AddrSpace, AddrSpace) {
        let mut m = SpaceRegistry::new();
        m.insert_space(AddrSpace::new_constant_space(false))
            .unwrap();
        m.insert_space(AddrSpace::new_unique_space(2, 0, false))
            .unwrap();
        let ram = AddrSpace::new_space(
            SpaceType::Processor, "ram", false, 8, 1, 3, space_flags::HASPHYSICAL, 0, 0,
        );
        m.insert_space(ram.clone()).unwrap();
        let reg = AddrSpace::new_space(
            SpaceType::Processor, "register", false, 8, 1, 4, space_flags::HASPHYSICAL, 0, 0,
        );
        m.insert_space(reg.clone()).unwrap();
        let join = AddrSpace::new_join_space(6, false);
        m.insert_space(join.clone()).unwrap();
        m.insert_space(AddrSpace::new_iop_space(7, false)).unwrap();
        (m, ram, reg)
    }

    // RUDRA-GLUE: panic payload extraction (panic!("literal") payloads are
    // &str; panic!("{}", x) payloads are String).
    fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = e.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = e.downcast_ref::<String>() {
            s.clone()
        } else {
            unreachable!("panic payload was not a string")
        }
    }

    #[test]
    fn test_join_print_raw_two_pieces() {
        // Ghidra: space.cc:590 JoinSpace::printRaw — rudra regression only;
        // the byte-exact oracle is tests/oracle/space_printraw_special_1204.
        let (mut m, ram, reg) = special_printraw_registry();
        let join = m.get_join_space().unwrap();
        let pieces = [
            SpaceVarnodeData { space: reg.clone(), offset: 0x18, size: 4 ,
            },
            SpaceVarnodeData { space: reg.clone(), offset: 0x10, size: 4 ,
            },
        ];
        let off = m.find_add_join(&pieces, 0);
        assert_eq!(off, 0);
        assert_eq!(join.print_raw(off), "{0x00000018,0x00000010}");
        // Dedup: identical pieces return the same record/offset.
        assert_eq!(m.find_add_join(&pieces, 0), 0);
    }

    #[test]
    fn test_join_print_raw_three_pieces_distinct_spaces() {
        let (mut m, ram, reg) = special_printraw_registry();
        let join = m.get_join_space().unwrap();
        let pieces = [
            SpaceVarnodeData { space: ram.clone(), offset: 0x1000, size: 4 ,
            },
            SpaceVarnodeData { space: reg.clone(), offset: 0x20, size: 2 ,
            },
            SpaceVarnodeData { space: reg.clone(), offset: 0x22, size: 2 ,
            },
        ];
        let off = m.find_add_join(&pieces, 0);
        assert_eq!(off, 0); // fresh registry: first allocation, 16-byte aligned
        assert_eq!(join.print_raw(off), "{0x00001000,0x00000020,0x00000022}");
    }

    #[test]
    fn test_join_print_raw_single_piece_float_extension() {
        let (mut m, ram, reg) = special_printraw_registry();
        let join = m.get_join_space().unwrap();
        let pieces = [SpaceVarnodeData { space: reg.clone(), offset: 0x100, size: 8 ,
        }];
        let off = m.find_add_join(&pieces, 4);
        assert_eq!(off, 0);
        // num==1: the loop's szsum is discarded and replaced by the unified
        // (logical) size (space.cc:604-606).
        assert_eq!(join.print_raw(off), "{0x00000100:4}");
    }

    #[test]
    fn test_join_print_raw_wordsize2_piece_recursion() {
        let (mut m, ram, reg) = special_printraw_registry();
        let ws2 = AddrSpace::new_space(SpaceType::Processor, "ws2", false, 4, 2, 5, 0, 0, 0);
        m.insert_space(ws2.clone()).unwrap();
        let join = m.get_join_space().unwrap();
        let pieces = [
            SpaceVarnodeData { space: ws2.clone(), offset: 0x101, size: 2 ,
            },
            SpaceVarnodeData { space: reg.clone(), offset: 0x30, size: 2 ,
            },
        ];
        let off = m.find_add_join(&pieces, 0);
        // The piece recursion goes through the piece space's own printRaw
        // (scaling + "+cut" suffix): 0x101 -> 0x80+1, 8-hex-digit field for
        // the 4-byte address size.
        assert_eq!(join.print_raw(off), "{0x00000080+1,0x00000030}");
    }

    #[test]
    fn test_join_print_raw_unlinked_panics() {
        let (m, _ram, _reg) = special_printraw_registry();
        let join = m.get_join_space().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join.print_raw(0xdeadb0)
        ));
        assert_eq!(panic_message(result.unwrap_err()), "Unlinked join address");
    }

    #[test]
    fn test_join_space_unregistered_has_no_manager_backlink() {
        // A join space never inserted into a registry cannot reach the
        // join tables; Ghidra cannot express this (its constructor always
        // takes the manager) — mapped to the same deterministic panic.
        let join = AddrSpace::new_join_space(6, false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| join.print_raw(0)
        ));
        assert_eq!(panic_message(result.unwrap_err()), "Unlinked join address");
    }

    #[test]
    fn test_iop_print_raw_residual_falls_back_to_base_form() {
        // SPACE-IOP-PRINTRAW-0001 residual: the specialization returns None
        // for both forms (spaceless SeqNum.addr / BlockBasic::start_addr),
        // so the dispatch falls back to the base AddrSpace::printRaw form.
        let (m, _ram, _reg) = special_printraw_registry();
        let iop = m.get_iop_space().unwrap();
        assert_eq!(crate::op::IopSpace::print_raw(0x1234), None);
        assert_eq!(iop.print_raw(0x1234), "0x00001234");
    }

    #[test]
    fn test_join_record_ordering_operator() {
        // Ghidra: translate.cc:172 JoinRecord::operator< — unified.size
        // first, then pieces lexicographically (space index, offset, size
        // DESCENDING), shorter-prefix-is-smaller.
        let (m, ram, reg) = special_printraw_registry();
        let piece = |sp: &AddrSpace, off: u64, sz: i32| SpaceVarnodeData {
            space: sp.clone(),
            offset: off,
            size: sz,
        };
        let rec = |sz: i32, pieces: Vec<SpaceVarnodeData>| manager_join::JoinRecord {
            pieces,
            unified: SpaceVarnodeData { space: ram.clone(), offset: 0, size: sz ,
            },
        };
        // Size dominates.
        assert!(rec(4, vec![piece(&reg, 0, 4)]).less_than(&rec(8, vec![piece(&reg, 0, 4)])));
        // Same size: piece offset decides.
        assert!(rec(4, vec![piece(&reg, 0x10, 4)]).less_than(&rec(4, vec![piece(&reg, 0x18, 4)])));
        // Same space+offset: BIG sizes come first.
        assert!(rec(4, vec![piece(&reg, 0x10, 8)]).less_than(&rec(4, vec![piece(&reg, 0x10, 4)])));
        // Prefix is smaller.
        assert!(rec(4, vec![piece(&reg, 0x10, 4)])
            .less_than(&rec(4, vec![piece(&reg, 0x10, 4), piece(&ram, 0, 4)])));
        // Equal records.
        assert!(!rec(4, vec![piece(&reg, 0x10, 4)]).less_than(&rec(4, vec![piece(&reg, 0x10, 4)])));
        let _ = m;
    }

    #[test]
    fn test_find_add_join_validations() {
        // Ghidra: translate.cc:675-691 validation strings.
        let (mut m, _ram, reg) = special_printraw_registry();
        let empty: [SpaceVarnodeData; 0] = [];
        assert_eq!(
            panic_message(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || m.find_add_join(&empty, 0)
                ))
                    .unwrap_err()
            ),
            "Cannot create a join without pieces"
        );
        assert_eq!(
            panic_message(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    m.find_add_join(
                        &[SpaceVarnodeData { space: reg.clone(), offset: 0, size: 4 ,
                        }], 0,
                    )
                }))
                .unwrap_err()
            ),
            "Cannot create a single piece join without a logical size"
        );
        assert_eq!(
            panic_message(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    m.find_add_join(
                        &[
                            SpaceVarnodeData { space: reg.clone(), offset: 0, size: 4 ,
                            },
                            SpaceVarnodeData { space: reg.clone(), offset: 4, size: 4 ,
                            },
                        ],
                        8,
                    )
                }))
                .unwrap_err()
            ),
            "Cannot specify logical size for multiple piece join"
        );
        assert_eq!(
            panic_message(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    m.find_add_join(
                        &[
                            SpaceVarnodeData { space: reg.clone(), offset: 0, size: 0 ,
                            },
                            SpaceVarnodeData { space: reg.clone(), offset: 0, size: 0 ,
                            },
                        ],
                        0,
                    )
                }))
                .unwrap_err()
            ),
            "Cannot create a zero size join"
        );
    }
}

// SQLCENSUS-STACKSLOT-GROUP-0001 第一波验收单测（space.rs 尾部 tests 模块后独立
// 模块，避免与既有 tests 模块的 use 冲突）。
/// `JoinDatabase::find_add_join` 的 findAddJoin 语义
/// （translate.cc:671-715）：dedup 同片序列回同一 offset；新记录按
/// roundsize（16 字节粒度）推进 join_allocate；find_join 反查命中。
#[cfg(test)]
mod join_db_tests {
    use super::*;

    #[test]
    fn test_find_add_join_dedup_and_granularity() {
        let mut db = JoinDatabase::new();
        // RDX:RAX pair（most-significant first，findAddJoin 片序）
        let rdx_rax = vec![
            VarnodeData { space: AddressSpace::Register, offset: 0x10, size: 8 },
            VarnodeData { space: AddressSpace::Register, offset: 0x0, size: 8 },
        ];
        let first = db.find_add_join(rdx_rax.clone());
        // 首个分配从 joinallocate=0 起（translate.cc:709）
        assert_eq!(first, 0);
        // 同片序列 dedup 回同一 join 地址（splitset 身份查询）
        let again = db.find_add_join(rdx_rax.clone());
        assert_eq!(again, 0);
        assert_eq!(db.records.len(), 1);
        // 不同片序列：roundsize=16 推进到下一个 16 字节槽
        let other = db.find_add_join(vec![
            VarnodeData { space: AddressSpace::Register, offset: 0x18, size: 8 },
            VarnodeData { space: AddressSpace::Register, offset: 0x8, size: 8 },
        ]);
        assert_eq!(other, 16);
        // findJoin 反查（translate.hh:232，process_joins 消费）
        let rec = db.find_join(0).expect("record at join:0");
        assert_eq!(rec.unified.size, 16);
        assert_eq!(rec.pieces.len(), 2);
        assert_eq!(rec.pieces[0].offset, 0x10);
        assert!(db.find_join(8).is_none());
    }
}
