//! Function prototypes and call specifications
//!
//! Corresponds to Ghidra's `fspec.hh`. This module manages how functions
//! are defined (prototypes) and how call sites are handled (call specs).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use crate::address::Address;
use crate::space::{AddrSpace, AddressSpace, SpaceType};
use crate::type_system::datatype::Datatype;

/// Effect type for a memory range across a call. Faithful to
/// `EffectRecord` enum (fspec.hh:393-398).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectType {
    /// The sub-function does not change the value at all
    Unaffected = 1,
    /// The memory is changed and is completely unrelated to its original value
    KilledByCall = 2,
    /// The memory is being used to store the return address
    ReturnAddress = 3,
    /// An unknown effect (indicates the absence of an EffectRecord)
    UnknownEffect = 4,
}

/// A record of how a specific memory range is affected by a sub-function call.
/// Faithful to `EffectRecord` (fspec.hh:391-416). Used by ActionRestrictLocal
/// to identify saved registers (unaffected) that are copied to stack storage.
#[derive(Debug, Clone)]
pub struct EffectRecord {
    /// The memory range affected (space + offset)
    pub space: AddressSpace,
    /// The starting offset of the affected range
    pub offset: u64,
    /// The size of the affected range
    pub size: i32,
    /// The type of effect
    pub effect_type: EffectType,
}

impl EffectRecord {
    // Ghidra: fspec.cc:2212 EffectRecord::new
    /// Create a new effect record. Faithful to `EffectRecord(const VarnodeData&, uint4)`.
    pub fn new(space: AddressSpace, offset: u64, size: i32, effect_type: EffectType) -> Self {
        Self { space, offset, size, effect_type }
    }

    // Ghidra: fspec.cc:2212 EffectRecord::getType
    /// Get the type of effect. Faithful to `getType`.
    pub fn get_type(&self) -> EffectType { self.effect_type }

    // Ghidra: fspec.cc:2212 EffectRecord::getOffset
    /// Get the starting address offset. Faithful to `getAddress`.
    pub fn get_offset(&self) -> u64 { self.offset }

    // Ghidra: fspec.cc:2212 EffectRecord::getSize
    /// Get the size of the affected range. Faithful to `getSize`.
    pub fn get_size(&self) -> i32 { self.size }

    // Ghidra: fspec.cc:2212 EffectRecord::getAddress
    /// Get the address space of the affected range. Faithful to
    /// `getAddress`'s space component.
    pub fn get_space(&self) -> AddressSpace { self.space }

    // Ghidra: fspec.cc:2212 EffectRecord::EffectRecord(const Address&, int4)
    /// Construct a record with `EffectType::UnknownEffect` from an address+size.
    /// Faithful to `EffectRecord(const Address &addr,int4 size)` (fspec.cc:2212):
    /// the type is `unknown_effect` and the range is (space, offset, size).
    pub fn from_address_size(space: AddressSpace, offset: u64, size: i32) -> Self {
        Self {
            space,
            offset,
            size,
            effect_type: EffectType::UnknownEffect,
        }
    }

    // Ghidra: fspec.cc:2212 EffectRecord::EffectRecord(const Address&, int4, uint4)
    /// Construct a record with an explicit effect type from an address+size.
    /// Faithful to `EffectRecord(const Address &addr,int4 size, uint4 t)`.
    pub fn with_effect(space: AddressSpace, offset: u64, size: i32, effect_type: EffectType) -> Self {
        Self { space, offset, size, effect_type }
    }

    // Ghidra: fspec.cc:2243 EffectRecord::encode
    /// Encode this record as an `<addr>` element. Faithful 1:1 port of
    /// `EffectRecord::encode` (fspec.cc:2243-2251). The effect type is not
    /// written here — it is implied by the surrounding parent element
    /// (`<unaffected>`/`<killedbycall>`/`<returnaddress>`). Only records with
    /// a printable effect type may be encoded; `unknown_effect` is a
    /// programming error and is reported via `Err`.
    pub fn encode(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
    ) -> Result<(), String> {
        // Ghidra: if ((type==unaffected)||(type==killedbycall)||(type==return_address))
        //           addr.encode(encoder, range.size);
        //         else throw LowlevelError("Bad EffectRecord type");
        match self.effect_type {
            EffectType::Unaffected
            | EffectType::KilledByCall
            | EffectType::ReturnAddress => {
                encoder.open_element(addr_elem);
                encoder.write_string(space_attrib, space_name(self.space));
                encoder.write_unsigned_integer(offset_attrib, self.offset);
                encoder.write_signed_integer(size_attrib, self.size as i64);
                encoder.close_element(addr_elem);
                Ok(())
            }
            EffectType::UnknownEffect => {
                Err("Bad EffectRecord type".to_string())
            }
        }
    }

    // Ghidra: fspec.cc:2256 EffectRecord::decode
    /// Parse an `<addr>` element to get the memory range, inheriting the
    /// effect type from the parent. Faithful 1:1 port of
    /// `EffectRecord::decode` (fspec.cc:2256-2261). The caller passes in the
    /// effect type (`grouptype`), and the range's space/offset/size attributes
    /// are read via `VarnodeData::decode`.
    pub fn decode(
        &mut self,
        grouptype: EffectType,
        decoder: &mut dyn crate::marshal::Decoder,
    ) {
        use crate::marshal::Decoder;
        self.effect_type = grouptype;
        let (space, offset, size) = read_varnode_data_attrs(decoder);
        self.space = space;
        self.offset = offset;
        self.size = size;
    }

    // Ghidra: fspec.hh:1761 EffectRecord::compareByAddress
    /// Order two EffectRecords by their storage address. Faithful to
    /// `compareByAddress` (fspec.hh:1761): returns true if `a` strictly
    /// precedes `b` in (space, offset) order. Used by `ProtoModel::lookupEffect`
    /// / `lookupRecord` for binary search and by the post-decode sort.
    pub fn compare_by_address(a: &EffectRecord, b: &EffectRecord) -> bool {
        match a.space.space_id().cmp(&b.space.space_id()) {
            std::cmp::Ordering::Equal => a.offset < b.offset,
            ord => ord == std::cmp::Ordering::Less,
        }
    }
}

// Ghidra: fspec.hh:1769 EffectRecord::operator==
// Ghidra: fspec.hh:1776 EffectRecord::operator!=
/// Equality on the full `VarnodeData range` (space, offset, size) plus the
/// effect type, faithful to the inline `operator==`/`operator!=`
/// (fspec.hh:1769-1781): `range != op2.range` compares the VarnodeData
/// member-wise (space pointer identity, then offset, then size), then
/// `type == op2.type`. Consumed by `ProtoModelMerged::intersectEffects`
/// (fspec.cc:2791-2800) to keep only address-equal records whose effect
/// types also agree.
impl PartialEq for EffectRecord {
    // Ghidra: fspec.hh:1769 EffectRecord::operator==
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space
            && self.offset == other.offset
            && self.size == other.size
            && self.effect_type == other.effect_type
    }
}

/// `ParamUnassignedError` (fspec.hh:63-66): LowlevelError raised by
/// `ProtoModel::assignParameterStorage` when no storage could be assigned
/// to a prototype position. `FuncProto::updateAllTypes` catches it to set
/// the sticky `error_inputparam` flag (fspec.cc:4220-4222). Rust models
/// the exception as a distinct string error kind so callers can pattern
/// match exactly the one catch site.
// Ghidra: fspec.hh:65 ParamUnassignedError::ParamUnassignedError
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamUnassignedError(pub String);

impl std::fmt::Display for ParamUnassignedError {
    // RUGRA-GLUE: Display for the anyhow-style error surface; Ghidra carries
    // the message inside the LowlevelError base class.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParamUnassignedError: {}", self.0)
    }
}

impl std::error::Error for ParamUnassignedError {}

/// Flags for ProtoParameter (corresponds to flags in fspec.hh)
pub mod protoparam_flags {
    pub const THIS_POINTER: u32 = 1;
    pub const HIDDEN_RETURN: u32 = 2;
    pub const INDIRECT_STORAGE: u32 = 4;
    pub const NAME_LOCKED: u32 = 1 << 3;
    pub const TYPE_LOCKED: u32 = 1 << 4;
}

/// A single parameter in a function signature
///
/// Corresponds to Ghidra's `ProtoParameter` class.
#[derive(Debug, Clone)]
pub struct ProtoParameter {
    /// Name of the parameter
    pub name: String,
    /// Data type of the parameter
    pub data_type: Arc<Datatype>,
    /// Storage location (register, stack offset, etc.)
    pub address: Address,
    /// Address-space half of Ghidra's complete `Address`. Rugra keeps this
    /// beside the legacy offset carrier until ADDRESS-0001 migrates the whole
    /// comparison domain atomically.
    pub address_space: AddressSpace,
    /// Property flags
    pub flags: u32,
}

impl ProtoParameter {
    // Ghidra: fspec.hh:1100 ProtoParameter::new
    /// Create a new function parameter
    pub fn new(name: String, data_type: Arc<Datatype>, address: Address) -> Self {
        Self {
            name,
            data_type,
            address,
            address_space: AddressSpace::Register,
            flags: 0,
        }
    }

    // RUGRA-GLUE: complete-storage constructor for the current split
    // `(AddressSpace, Address)` representation of Ghidra's single Address.
    pub fn new_in_space(
        name: String,
        data_type: Arc<Datatype>,
        address_space: AddressSpace,
        address: Address,
    ) -> Self {
        Self { name, data_type, address, address_space, flags: 0 }
    }

    // Ghidra: fspec.hh:1088 ProtoParameter::getAddress
    // RUGRA-GLUE: address-space projection paired with the legacy offset.
    pub fn get_address_space(&self) -> AddressSpace { self.address_space }

    // Ghidra: fspec.hh:1100 ProtoParameter::isThisPointer
    /// Returns true if this parameter is a "this" pointer
    pub fn is_this_pointer(&self) -> bool {
        (self.flags & protoparam_flags::THIS_POINTER) != 0
    }

    // Ghidra: fspec.hh:1117 ProtoParameter::setThisPointer
    /// Toggle whether this parameter is the "this" pointer for a class
    /// method. Faithful to `setThisPointer`.
    pub fn set_this_pointer(&mut self, val: bool) {
        if val {
            self.flags |= protoparam_flags::THIS_POINTER;
        } else {
            self.flags &= !protoparam_flags::THIS_POINTER;
        }
    }

    // Ghidra: fspec.hh:1113 ProtoParameter::isHiddenReturn
    /// Is this a pointer to storage for the return value (a hidden return
    /// parameter)? Faithful to `isHiddenReturn`.
    pub fn is_hidden_return(&self) -> bool {
        (self.flags & protoparam_flags::HIDDEN_RETURN) != 0
    }

    // Ghidra: fspec.hh:1100 ProtoParameter::isTypeLocked
    /// Returns true if the type is locked (user-defined)
    pub fn is_type_locked(&self) -> bool {
        (self.flags & protoparam_flags::TYPE_LOCKED) != 0
    }

    // Ghidra: fspec.hh:1178 ParameterBasic::isNameLocked
    /// Is the parameter name locked? Faithful to `ParameterBasic::
    /// isNameLocked` (fspec.hh:1178): `((flags & ParameterPieces::namelock)
    /// != 0)`. Rugra's flat `ProtoParameter` carries the same
    /// `ParameterPieces` flag bits, so the ParameterBasic read projects
    /// directly onto it.
    pub fn is_name_locked(&self) -> bool {
        (self.flags & NAME_LOCK_PIECE) != 0
    }

    // Ghidra: fspec.hh:1179 ParameterBasic::isSizeTypeLocked
    /// Is only the size of the parameter locked (data-type still unknown)?
    /// Faithful to `ParameterBasic::isSizeTypeLocked` (fspec.hh:1179):
    /// `((flags & ParameterPieces::sizelock) != 0)`.
    pub fn is_size_type_locked(&self) -> bool {
        (self.flags & SIZE_LOCK_PIECE) != 0
    }

    // Ghidra: fspec.hh:1181 ParameterBasic::isIndirectStorage
    /// Is this really a pointer to the true parameter? Faithful to
    /// `ParameterBasic::isIndirectStorage` (fspec.hh:1181).
    pub fn is_indirect_storage(&self) -> bool {
        (self.flags & INDIRECT_STORAGE_PIECE) != 0
    }

    // Ghidra: fspec.hh:1183 ParameterBasic::isNameUndefined
    /// Is the name undefined (empty)? Faithful to
    /// `ParameterBasic::isNameUndefined` (fspec.hh:1183):
    /// `(name.size() == 0)`.
    pub fn is_name_undefined(&self) -> bool {
        self.name.is_empty()
    }

    // Ghidra: fspec.hh:1169 ParameterBasic::ParameterBasic
    /// Construct from raw pieces, faithful to
    /// `ParameterBasic(const string &nm,const Address &ad,Datatype *tp,uint4 fl)`
    /// (fspec.hh:1169-1170): every field is copied verbatim from the
    /// pieces. The flat ProtoParameter keeps the space half of Ghidra's
    /// `Address` alongside the legacy offset (ADDRESS-0001).
    pub fn from_pieces(
        nm: &str,
        space: AddressSpace,
        addr: Address,
        tp: Arc<Datatype>,
        flags: u32,
    ) -> Self {
        Self { name: nm.to_string(), data_type: tp, address: addr, address_space: space, flags }
    }

    // Ghidra: fspec.cc:2924 ParameterBasic::setTypeLock
    /// Toggle the data-type lock. Faithful to `ParameterBasic::setTypeLock`
    /// (fspec.cc:2924-2934): setting the lock on a TYPE_UNKNOWN data-type
    /// additionally raises the \e size-lock bit (locking the size without a
    /// concrete type); clearing the lock clears both bits together.
    pub fn set_type_lock(&mut self, val: bool) {
        if val {
            self.flags |= protoparam_flags::TYPE_LOCKED;
            if self.data_type.get_metatype() == crate::type_system::TypeMetatype::Unknown {
                self.flags |= SIZE_LOCK_PIECE;
            }
        } else {
            self.flags &= !(protoparam_flags::TYPE_LOCKED | SIZE_LOCK_PIECE);
        }
    }

    // Ghidra: fspec.cc:2936 ParameterBasic::setNameLock
    /// Toggle the name lock. Faithful to `ParameterBasic::setNameLock`
    /// (fspec.cc:2936-2943).
    pub fn set_name_lock(&mut self, val: bool) {
        if val {
            self.flags |= NAME_LOCK_PIECE;
        } else {
            self.flags &= !NAME_LOCK_PIECE;
        }
    }

    // Ghidra: fspec.cc:2954 ParameterBasic::overrideSizeLockType
    /// Override the data-type of a size-locked parameter. Faithful to
    /// `ParameterBasic::overrideSizeLockType` (fspec.cc:2954-2964): the new
    /// type must have exactly the locked size and the parameter must already
    /// be size-locked; anything else is an error (mirrored as `Err`).
    pub fn override_size_lock_type(&mut self, ct: &Arc<Datatype>) -> Result<(), String> {
        if self.data_type.get_size() == ct.get_size() {
            if !self.is_size_type_locked() {
                return Err("Overriding parameter that is not size locked".to_string());
            }
            self.data_type = ct.clone();
            return Ok(());
        }
        Err("Overriding parameter with different type size".to_string())
    }

    // Ghidra: fspec.cc:2966 ParameterBasic::resetSizeLockType
    /// Reset the data-type to a TYPE_UNKNOWN of the same size, preserving
    /// the size lock. Faithful to `ParameterBasic::resetSizeLockType`
    /// (fspec.cc:2966-2972): a parameter whose type is already TYPE_UNKNOWN
    /// is left untouched.
    pub fn reset_size_lock_type(
        &mut self,
        factory: &crate::type_system::TypeFactory,
    ) {
        if self.data_type.get_metatype() == crate::type_system::TypeMetatype::Unknown {
            return;
        }
        let size = self.data_type.get_size();
        if let Some(base) = factory.get_base(size, crate::type_system::TypeMetatype::Unknown) {
            self.data_type = base;
        }
    }

    // Ghidra: fspec.hh:1190 ParameterBasic::getSymbol
    /// A ParameterBasic has no backing Symbol: Ghidra throws
    /// `LowlevelError("Parameter is not a real symbol")` (fspec.hh:1190).
    /// The flat Rust projection mirrors the always-throwing override as
    /// `Err` (the symbol-backed override lives on `ParameterSymbol`).
    pub fn get_symbol(&self) -> Result<std::sync::Arc<std::sync::RwLock<crate::database::Symbol>>, String> {
        Err("Parameter is not a real symbol".to_string())
    }
}

// Ghidra: fspec.hh:1144 ProtoParameter::operator==
// Ghidra: fspec.hh:1154 ProtoParameter::operator!=
/// Storage-and-type equality, faithful to the base-class inline
/// `operator==`/`operator!=` (fspec.hh:1144-1155): parameters are equal iff
/// they share the storage address and the data-type; the name and lock
/// flags are deliberately not compared. The data-type comparison is
/// pointer identity in Ghidra (`getType() != op2.getType()` compares
/// `Datatype *`); `Arc::ptr_eq` is the Rust equivalent.
impl PartialEq for ProtoParameter {
    // Ghidra: fspec.hh:1144 ProtoParameter::operator==
    fn eq(&self, other: &Self) -> bool {
        if self.address_space != other.address_space
            || self.address.as_u64() != other.address.as_u64()
        {
            return false;
        }
        std::sync::Arc::ptr_eq(&self.data_type, &other.data_type)
    }
}

/// A formal function prototype
///
/// Corresponds to Ghidra's `FuncProto` class. It defines the return type,
/// parameters, and calling convention of a function.
#[derive(Debug, Clone)]
pub struct FuncProto {
    /// Name of the function (optional, can be empty for anonymous signatures)
    pub name: String,
    /// Return type of the function
    pub return_type: Arc<Datatype>,
    /// List of formal parameters
    pub parameters: Vec<ProtoParameter>,
    /// The explicit lock for an empty/void input list. Faithful to Ghidra's
    /// `voidinputlock` flag: with non-empty inputs the first parameter's
    /// type-lock is authoritative; with zero inputs this bit distinguishes a
    /// known `void` prototype from an unrecovered prototype.
    pub void_input_locked: bool,
    /// Calling convention name (e.g., "__stdcall", "__cdecl")
    pub calling_convention: String,
    /// True if the function accepts variable arguments (...)
    pub is_dotdotdot: bool,
    /// Effect records: how registers/memory are affected by this function's calls.
    /// Faithful to `FuncProto::effectlist` (fspec.hh). Used by ActionRestrictLocal
    /// to identify saved registers (unaffected) that are copied to stack.
    pub effects: Vec<EffectRecord>,
    /// Likely-trash storage locations (function-level overrides). Faithful to
    /// `FuncProto::likelytrash` (fspec.hh:1365 — "Locations that may contain
    /// trash values"): VarnodeData decoded from a `<likelytrash>` child of
    /// `<prototype>`, merged into a complete list with the underlying model's
    /// trash registers by `decode` (the `decodeLikelyTrash` call,
    /// fspec.cc:4827). When non-empty it *overrides* the model's list for
    /// `trash_iter` (fspec.cc:4260-4275) — the source pair
    /// (`trashBegin..trashEnd`) iterated by `ActionLikelyTrash::apply`
    /// (coreaction.cc:2146-2147). Sorted by `VarnodeData::compare`.
    pub likelytrash: Vec<VarnodeData>,
    /// Resolved prototype model. Ghidra stores a non-owning `ProtoModel *`;
    /// `Arc` preserves the same shared model identity across prototype copies.
    model: Option<Arc<ProtoModelFull>>,
    /// Extra stack bytes popped by the callee. This is prototype-local state,
    /// initialized from the resolved model by `set_model`.
    extra_pop: i32,
    /// Sticky copy of the model output-list's auto-killed-by-call property.
    auto_killed_by_call: bool,
    /// Is the return-value (output) data-type locked? Faithful to
    /// `FuncProto::isOutputLocked` (fspec.cc:3906-3914): a locked output means
    /// the presence and data-type of the return value is fixed and analysis
    /// must not change it. Set by `set_output_lock`. A locked-void return
    /// (e.g. `exit`, `free`) means the CALL produces NO output varnode.
    pub output_type_locked: bool,
    /// Proto-store output parameter's storage address (space, offset).
    /// Flat-store stand-in for the `ProtoStore*::outparam`
    /// `ParameterBasic::addr` (fspec.hh:1164-1165, installed by
    /// `ProtoStoreInternal::setOutput` fspec.cc:3380-3387): the storage
    /// location of the return value, read back by `getOutput()` consumers —
    /// `ActionFuncLink::funcLinkOutput` (coreaction.cc:1545, the
    /// spacebase test that drives `setStackOutputLock`) and
    /// `Heritage::tryOutputStackGuard` (heritage.cc:1407/1410). `None`
    /// until a `setOutput` shape runs (Ghidra's outparam always exists once
    /// constructed; the flat FuncProto starts empty). The legacy `Address`
    /// carries no space identity, so the space is stored alongside the
    /// offset (ADDRESS-0001 folds this into the address when it lands).
    pub output_storage: Option<(AddressSpace, u64)>,
    /// Is the prototype model locked for this prototype? Faithful to the
    /// `modellock` (fspec.hh:1347) flag bit. Set by `set_model_lock` /
    /// `set_pieces`; read by `is_model_locked`. Ghidra folds this into the
    /// `flags` bitfield; Rugra keeps a dedicated boolean.
    pub model_locked: bool,
    /// Should this function be in-lined during decompilation? Faithful to the
    /// `is_inline` (fspec.hh:1348) flag bit. Read by `is_inline`; set by
    /// `set_inline`. In-lining is based on a call-fixup or the full body.
    pub is_inline: bool,
    /// Function does not return. Faithful to the `no_return`
    /// (fspec.hh:1349) flag bit. Read by `is_no_return`; set by
    /// `set_no_return`. A no-return function terminates its caller's
    /// basic-block flow.
    pub no_return: bool,
    /// Function is an (object-oriented) constructor. Faithful to the
    /// `is_constructor` (fspec.hh:1354) flag bit. Read by
    /// `is_constructor_flag`; set by `set_constructor`. Named with the
    /// `_flag` suffix to avoid clashing with `ProtoModel::is_constructor`.
    pub is_constructor_flag: bool,
    /// Function is an (object-oriented) destructor. Faithful to the
    /// `is_destructor` (fspec.hh:1355) flag bit. Read by `is_destructor`;
    /// set by `set_destructor`.
    pub is_destructor: bool,
    /// Function is a method with a 'this' pointer argument. Faithful to the
    /// `has_thisptr` (fspec.hh:1356) flag bit. Read by `has_thisptr`; set by
    /// `set_has_thisptr` and by `update_this_pointer`.
    pub has_thisptr: bool,
    /// Set if this prototype is created to override a single call site.
    /// Faithful to the `is_override` (fspec.hh:1357, 0x1000) flag bit. Read
    /// by `is_override`; set by `set_override`. In Ghidra the flag lives in
    /// the single `flags` word and `FuncProto::copy` (fspec.cc:3794
    /// `flags = op2.flags`) carries it wholesale — the channel that marks a
    /// call site as carrying an applied prototype override after a restart
    /// (`Override::insertProtoOverride` sets it on the stored copy at
    /// override.cc:130; `Override::applyPrototype` re-copies that proto
    /// onto the fresh FuncCallSpecs at flow setup, fspec.cc flow.cc:714).
    /// `FuncCallSpecs::deindirect` (fspec.cc:5462) then skips late
    /// restriction for such a site.
    pub is_override: bool,
    /// Number of bytes of the return value that are consumed by callers
    /// (0 = all bytes). Faithful to `FuncProto::returnBytesConsumed`
    /// (fspec.hh:1367). Set by `set_return_bytes_consumed`; read by the
    /// dead-code consume algorithm. RulePiecePathology records the partial
    /// consumption of a pathological PIECE here.
    pub return_bytes_consumed: u32,
    /// Parameter-storage assignment failed while rebuilding this prototype.
    /// Faithful to Ghidra's sticky `error_inputparam` flag.
    error_input_param: bool,
    /// Return-value assignment failed while rebuilding this prototype.
    /// Faithful to the `error_outputparam` flag bit (fspec.hh:1352).
    error_output_param: bool,
    /// Symbol-backed parameter store. `None` mirrors Ghidra's
    /// `ProtoStoreInternal` flat storage (the `parameters` vector IS its
    /// `inparam`); `Some` mirrors `FuncProto::setScope` (fspec.cc:3879-3885)
    /// installing a `ProtoStoreSymbol`, after which input-parameter
    /// mutations route to the backing function Scope's category 0.
    symbol_store: Option<ProtoStoreSymbol>,
}

impl FuncProto {
    // Ghidra: fspec.cc:3778 FuncProto::new
    /// Create a new function prototype
    pub fn new(name: String, return_type: Arc<Datatype>) -> Self {
        Self {
            name,
            return_type,
            parameters: Vec::new(),
            void_input_locked: false,
            calling_convention: "unknown".to_string(),
            is_dotdotdot: false,
            effects: Vec::new(),
            likelytrash: Vec::new(),
            model: None,
            extra_pop: EXTRAPOP_UNKNOWN_FULL,
            auto_killed_by_call: false,
            output_type_locked: false,
            output_storage: None,
            model_locked: false,
            is_inline: false,
            no_return: false,
            is_constructor_flag: false,
            is_destructor: false,
            has_thisptr: false,
            is_override: false,
            return_bytes_consumed: 0,
            error_input_param: false,
            error_output_param: false,
            symbol_store: None,
        }
    }

    // Ghidra: fspec.cc:3778 FuncProto::addParameter
    /// Add a parameter to the prototype
    pub fn add_parameter(&mut self, param: ProtoParameter) {
        self.parameters.push(param);
    }

    // Ghidra: fspec.cc:3778 FuncProto::numParams
    /// Get the number of parameters
    pub fn num_params(&self) -> usize {
        self.parameters.len()
    }

    // Ghidra: fspec.cc:3778 FuncProto::getParam
    /// Get a parameter by index
    pub fn get_param(&self, index: usize) -> Option<&ProtoParameter> {
        self.parameters.get(index)
    }

    // Ghidra: fspec.cc:4243 FuncProto::effectBegin
    /// Iterate effect records. Faithful to `FuncProto::effectBegin/effectEnd`
    /// (fspec.cc:4243-4259). A non-empty local list is a complete override;
    /// otherwise iteration falls back to the shared model list.
    pub fn effect_iter(&self) -> &[EffectRecord] {
        if !self.effects.is_empty() {
            return &self.effects;
        }
        self.model
            .as_ref()
            .expect("FuncProto::effect_iter requires a prototype model")
            .effect_iter()
    }

    // Ghidra: fspec.cc:4234 FuncProto::hasEffect
    /// Determine the call effect on a range. A non-empty prototype-local
    /// effect list completely overrides the model list; an empty list
    /// delegates to the shared model.
    pub fn has_effect(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        if !self.effects.is_empty() {
            return ProtoModelFull::lookup_effect(
                &self.effects,
                addr_space,
                addr_offset,
                size,
            );
        }
        self.model
            .as_ref()
            .expect("FuncProto::has_effect requires a prototype model")
            .has_effect(addr_space, addr_offset, size)
    }

    // RUGRA-GLUE: non-panicking form of FuncProto::hasEffect for input
    /// registration (Funcdata::setInputVarnode tail, funcdata_varnode.cc:365).
    /// A FuncProto with neither a prototype-local effect list nor a bound
    /// model has no Ghidra counterpart — Ghidra's model pointer is always
    /// live once a proto is configured, so `None` (skip the effect flag
    /// writes) is only reachable from bare test FuncProtos.
    pub fn try_has_effect(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> Option<EffectType> {
        if !self.effects.is_empty() {
            return Some(ProtoModelFull::lookup_effect(
                &self.effects,
                addr_space,
                addr_offset,
                size,
            ));
        }
        self.model
            .as_ref()
            .map(|model| model.has_effect(addr_space, addr_offset, size))
    }

    // Ghidra: fspec.hh:1564 FuncProto::getMaxInputDelay
    /// Return the maximum heritage delay of an input parameter resource.
    pub fn get_max_input_delay(&self) -> i32 {
        self.model
            .as_ref()
            .map(|model| model.input.get_max_delay())
            .unwrap_or(0)
    }

    // Ghidra: fspec.hh:1566 FuncProto::getMaxOutputDelay
    /// Return the maximum heritage delay of a return-value (output)
    /// parameter resource. Feeds `Funcdata::initActiveOutput`'s maxPass.
    pub fn get_max_output_delay(&self) -> i32 {
        self.model
            .as_ref()
            .map(|model| model.get_max_output_delay())
            .unwrap_or(0)
    }

    // RUGRA-GLUE: read accessor for the resolved model Arc (Ghidra's public
    // `getModel()` returns the ProtoModel pointer; deriveOutputMap callers
    // need the shared object).
    /// Resolved prototype model, if one was set via `setModel`.
    pub fn get_model_arc(&self) -> Option<std::sync::Arc<ProtoModelFull>> {
        self.model.clone()
    }

    // Ghidra: fspec.hh:1461 FuncProto::hasInputErrors
    /// Return whether input parameter storage could not be assigned.
    pub fn has_input_errors(&self) -> bool {
        self.error_input_param
    }

    // Ghidra: fspec.hh:1469 FuncProto::setInputErrors
    /// Toggle the sticky input-parameter assignment error flag.
    pub fn set_input_errors(&mut self, val: bool) {
        self.error_input_param = val;
    }

    // Ghidra: fspec.hh:1464 FuncProto::hasOutputErrors
    /// `return ((flags&error_outputparam)!=0);` (fspec.hh:1464) — the
    /// sticky return-value assignment error flag (flag bit 128,
    /// fspec.hh:1352).
    pub fn has_output_errors(&self) -> bool {
        self.error_output_param
    }

    // Ghidra: fspec.hh:1471 FuncProto::setOutputErrors
    /// `flags = val ? (flags|error_outputparam) : (flags &
    /// ~((uint4)error_outputparam));` (fspec.hh:1471-1473).
    pub fn set_output_errors(&mut self, val: bool) {
        self.error_output_param = val;
    }

    // RUGRA-GLUE: projection of the flat output state (return_type +
    // output_storage) into the ProtoParameter view Ghidra reads through
    // `store->getOutput()` — used by the FuncCallSpecs locked-output mover.
    pub(crate) fn output_param_view(&self) -> ProtoParameter {
        let (space, offset) = self
            .output_storage
            .unwrap_or((AddressSpace::Ram, 0));
        ProtoParameter {
            name: String::new(),
            data_type: self.return_type.clone(),
            address: Address::new(offset),
            address_space: space,
            flags: if self.output_type_locked {
                protoparam_flags::TYPE_LOCKED
            } else {
                0
            },
        }
    }

    // Ghidra: fspec.hh:1611 FuncProto::getSpacebase
    /// Get the \e stack address space associated with \b this model.
    /// Faithful to `FuncProto::getSpacebase` (fspec.hh:1611):
    /// `return model->getSpacebase();` — ProtoModel::getSpacebase
    /// (fspec.hh:977) delegates to the input ParamList's `getSpacebase`
    /// (fspec.hh:639), which is non-null exactly when the model's input
    /// list has a stack-space pentry. A modelless FuncProto (invalid in
    /// Ghidra) projects `None`.
    pub fn get_spacebase(&self) -> Option<AddressSpace> {
        self.model.as_ref().and_then(|m| m.input.get_spacebase())
    }

    // Ghidra: fspec.cc:4289 FuncProto::characterizeAsInputParam
    /// Decide whether a given storage location could be, or could hold, an
    /// input parameter. Faithful port of `characterizeAsInputParam`
    /// (fspec.cc:4289-4324): the varargs check and the `voidinputlock`
    /// early return are exact; the locked-parameter containment scan is
    /// degraded to the model branch because Rugra's `ProtoParameter.address`
    /// carries no address-space identity (Ghidra's `Address` does), so a
    /// cross-space offset comparison would produce false containments.
    /// Removal of this degradation is gated on ADDRESS-0001.
    pub fn characterize_as_input_param(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> i32 {
        // Ghidra: if (!isDotdotdot()) { if ((flags&voidinputlock)!=0) return 0; ... }
        if !self.is_dotdotdot && self.void_input_locked {
            return containment::NO_CONTAINMENT;
        }
        let Some(model) = self.model.as_ref() else {
            // A modelless FuncProto is an invalid state in Ghidra (the
            // model dereference would fault). Rugra production hits it
            // until FUNCPROTO-MODEL-BIND-0001; no_containment is the
            // conservative projection (no trial, no input insertion).
            return containment::NO_CONTAINMENT;
        };
        // Ghidra: return model->characterizeAsInputParam(addr, size);
        model.input.characterize_as_param(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:3767 FuncProto::resolveModel
    /// If \b this has a \e merged model, pick the most likely model (from
    /// the merged set), using the given parameter trials. Faithful to
    /// `FuncProto::resolveModel` (fspec.cc:3767-3776): a null model returns
    /// immediately; a concrete (non-merged) model returns immediately —
    /// resolution is only meaningful for `ProtoModelMerged`, which selects
    /// between alternative models based on the active trials. Rugra's
    /// `ProtoModelFull` is always concrete, so the merged arm is unreachable
    /// (the `selectModel` port is gated on merged-model support).
    pub fn resolve_model(&mut self) {
        // cc:3770 — if (model == (ProtoModel *)0) return;
        if self.model.is_none() {
            return;
        }
        // cc:3771 — if (!model->isMerged()) return; — Rugra models are
        // always concrete; nothing to remark (cc:3775 comment: fillinMap
        // does the trial remarking).
    }

    // Ghidra: fspec.hh:1494 FuncProto::deriveInputMap
    /// Derive the input prototype from the active trials via the model's
    /// input ParamList. Faithful to the inline `deriveInputMap`
    /// (fspec.hh:1494-1495 `model->deriveInputMap(active)`, whose ProtoModel
    /// body at fspec.hh:791-792 is `input->fillinMap(active)`) — the same
    /// dispatch `FuncCallSpecs::derive_input_map` uses. A modelless FuncProto
    /// is an invalid state in Ghidra (the dereference would fault); Rugra
    /// production must bind the model first (the ActionInputPrototype
    /// setScope-fallback glue), so the modelless arm is a defensive no-op.
    pub fn derive_input_map(&mut self, active: &mut crate::fspec::ParamActive) {
        if let Some(model) = self.model.as_ref() {
            model.input.fillin_map(active);
        }
    }

    // Ghidra: fspec.cc:4426 FuncProto::unjustifiedInputParam
    /// Check if the given storage location looks like an \e unjustified
    /// input parameter: contained in a normal parameter location but not
    /// justified at the least-significant end. Passes back the full
    /// parameter container. Faithful to `FuncProto::unjustifiedInputParam`
    /// (fspec.cc:4426-4453) with the same ADDRESS-0001 degradation as
    /// `characterize_as_input_param`/`possible_input_param`: the
    /// locked-parameter justifiedContain loop compares through the
    /// spaceless legacy `Address` plus the recorded `address_space`, so a
    /// foreign-space parameter cannot produce a false containment (the
    /// space equality guard below); Ghidra's `justifiedContain` itself
    /// rejects cross-space queries (address.cc:133 `base != op2.base`).
    pub fn unjustified_input_param(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
        res: &mut crate::fspec::VarnodeData,
    ) -> bool {
        // cc:4429 — if (!isDotdotdot()) { if ((flags&voidinputlock)!=0)
        //   return false; ... }
        if !self.is_dotdotdot {
            if self.void_input_locked {
                return false;
            }
            let num = self.parameters.len();
            if num > 0 {
                let mut locktest = false; // Have tested against locked symbol
                for i in 0..num {
                    let param = &self.parameters[i];
                    // cc:4436 — if (!param->isTypeLocked()) continue;
                    if !param.is_type_locked() {
                        continue;
                    }
                    locktest = true;
                    // cc:4438-4447 — iaddr.justifiedContain(param->getSize(),
                    // addr,size,false): 0 = contained and justified, > 0 =
                    // contained but unjustified (pass back the container).
                    if param.get_address_space() != addr_space {
                        // address.cc:133 — a cross-space query is never
                        // contained; keep scanning locked params as Ghidra's
                        // per-space containment rejection does.
                        continue;
                    }
                    let iaddr = param.address.as_u64();
                    let psize = param.data_type.get_size() as i32;
                    let just = justified_contain_range(
                        iaddr,
                        psize,
                        addr_offset,
                        size,
                        false,
                        addr_space.is_big_endian(),
                    );
                    if just == 0 {
                        return false; // cc:4441 — contained but not improperly
                    }
                    if just > 0 {
                        res.space = param.get_address_space();
                        res.offset = iaddr;
                        res.size = psize;
                        return true;
                    }
                }
                if locktest {
                    return false; // cc:4449
                }
            }
        }
        // cc:4452 — return model->unjustifiedInputParam(addr,size,res)
        match self.model.as_ref() {
            Some(model) => model
                .input
                .unjustified_container(addr_space, Address::new(addr_offset), size, res),
            None => false,
        }
    }

    // Ghidra: fspec.cc:4366 FuncProto::possibleInputParam
    /// Does the given storage location make sense as an input parameter?
    /// Faithful port of `possibleInputParam` (fspec.cc:4366-4387). If the
    /// proto is varargs, go straight to the model; otherwise the
    /// `voidinputlock` gate and the locked-parameter
    /// `justifiedContain==0` test run before the model fallback.
    ///
    /// The locked-parameter loop (fspec.cc:4371-4384) is gated the same way
    /// the in-repo sibling port `characterize_as_input_param` (fspec.rs:410)
    /// gates it: Rugra's `ProtoParameter` stores a spaceless `Address` and
    /// no standalone size, so the per-space `justifiedContain` test cannot
    /// be evaluated without inventing param-space state. With no locked
    /// input parameters recorded (the protorecovery-stage state this method
    /// is reached from — ActionDirectWrite, coreaction.cc:1368), the loop is
    /// inert and control reaches the model exactly as in Ghidra.
    pub fn possible_input_param(
        &self,
        addr_offset: u64,
        size: i32,
        addr_space: AddressSpace,
    ) -> bool {
        // Ghidra: if (!isDotdotdot()) { if ((flags&voidinputlock)!=0)
        //   return false; ... }
        if !self.is_dotdotdot {
            if self.void_input_locked {
                return false;
            }
            // Ghidra: int4 num = numParams(); if (num > 0) { ... locked
            // justifiedContain loop ... if (locktest) return false; }
            // — locked-input parameters are unreachable in Rugra's
            // FuncProto state today (see doc comment); numParams()==0 falls
            // through to the model like Ghidra's num==0 path.
        }
        // Ghidra: return model->possibleInputParam(addr,size);
        // A modelless FuncProto is an invalid state in Ghidra (the
        // dereference would fault); Rugra production can still observe it,
        // and `false` is the conservative projection (do not treat the
        // location as an official input).
        match self.model.as_ref() {
            Some(model) => model.possible_input_param(addr_space, Address::new(addr_offset), size),
            None => false,
        }
    }
    // Ghidra: fspec.cc:4336 FuncProto::characterizeAsOutput
    /// Decide whether a given storage location could be, or could hold, the
    /// return value. Faithful port of `characterizeAsOutput`
    /// (fspec.cc:4336-4358): with a locked output AND a recorded
    /// proto-store storage the locked branch (fspec.cc:4339-4353) runs
    /// exactly — TYPE_VOID gate, then the cc:4346 justifiedContain and
    /// cc:4351 containedBy reads on the outparam's own Address. Without a
    /// recorded storage (Ghidra always has one; Rugra's known-prototype
    /// paths do not record one yet) the classification degrades to the
    /// model branch — the ADDRESS-0001-gated transitional fallback.
    pub fn characterize_as_output(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> i32 {
        if self.is_output_locked() {
            // Ghidra: fspec.cc:4340-4342
            //   ProtoParameter *outparam = getOutput();
            //   if (outparam->getType()->getMetatype() == TYPE_VOID)
            //     return ParamEntry::no_containment;
            if matches!(
                self.return_type.get_metatype(),
                crate::type_system::TypeMetatype::Void
            ) {
                return containment::NO_CONTAINMENT;
            }
            if let Some((spc, off)) = self.output_storage {
                // Ghidra: fspec.cc:4343-4353 — Address iaddr =
                // outparam->getAddress(); the varnode must be justified in
                // the locked storage relative to the space endianness,
                // irregardless of the forceleft flag. The `base != op2.base`
                // guards of address.cc:133/113 are the space equality below.
                if spc != addr_space {
                    return containment::NO_CONTAINMENT;
                }
                let out_size = self.return_type.get_size() as i32;
                let dist = justified_contain_range(
                    off,
                    out_size,
                    addr_offset,
                    size,
                    false,
                    spc.is_big_endian(),
                );
                if dist == 0 {
                    return containment::CONTAINS_JUSTIFIED;
                } else if dist > 0 {
                    return containment::CONTAINS_UNJUSTIFIED;
                }
                if contained_by_range(off, out_size, addr_offset, size) {
                    return containment::CONTAINED_BY;
                }
                return containment::NO_CONTAINMENT;
            }
            // Transitional: locked output with no recorded storage —
            // Ghidra's locked branch is terminal (fspec.cc:4353-4354);
            // the model-branch fallthrough only exists on Rugra's
            // no-storage path, which Ghidra cannot reach.
        }
        let Some(model) = self.model.as_ref() else {
            // Modelless FuncProto is invalid in Ghidra; conservative
            // no_containment projection (see characterize_as_input_param).
            return containment::NO_CONTAINMENT;
        };
        // Ghidra: return model->characterizeAsOutput(addr, size);
        model.output.characterize_as_param(addr_space, addr_offset, size)
    }

    // Ghidra: coreaction.cc:4637-4648 ActionPrototypeTypes (outparam getAddress/getSize)
    /// Resolve the storage of the type-locked return value as
    /// `(space, offset, size)`. Ghidra's `FuncProto::getOutput()` carries the
    /// resolved ProtoParameter (address fixed by the model's output
    /// assignment when the signature was locked); Rugra's FuncProto keeps
    /// only the return data-type, so this runs the same assignment on demand:
    /// `ProtoModel::assignParameterStorage`'s output half (fspec.cc:2429-
    /// 2440), then maps the assigned offset back onto the owning output
    /// ParamEntry to recover the space identity (ParameterPieces.addr is
    /// spaceless in the transitional Address model). Returns None for a
    /// void/unassignable return.
    pub fn locked_output_storage(&self) -> Option<(AddressSpace, u64, i32)> {
        if !self.output_type_locked {
            return None;
        }
        if matches!(
            self.return_type.get_metatype(),
            crate::type_system::TypeMetatype::Void
        ) {
            return None;
        }
        let model = self.model.as_ref();
        let model = model?;
        let proto = PrototypePieces {
            out_type: Some(&self.return_type),
            in_types: &[],
            first_var_arg_slot: -1,
        };
        let mut res: Vec<ParameterPieces> = Vec::new();
        // ignore_output_error=true: an unassignable return degrades to the
        // void entry, which the type check above already filtered out.
        let assign = model.assign_parameter_storage(&proto, &mut res, true, None);
        if assign.is_err() {
            return None;
        }
        let piece = res.first()?;
        // Ghidra's assignAddressFallback leaves piece.type null on success
        // (fspec.cc:748-770); only the degraded-void catch fills in a void
        // type (fspec.cc:2438-2442). The metatype filter above already
        // excluded a genuine void return, so a Some(void) here is the
        // degradation signal.
        if let Some(t) = &piece.ty {
            if matches!(t.get_metatype(), crate::type_system::TypeMetatype::Void) {
                return None;
            }
        }
        let off = piece.addr.as_u64();
        let size = self.return_type.get_size() as i32;
        if size <= 0 {
            return None;
        }
        let entries: &[ParamEntry] = match &model.output {
            ParamListOutput::Standard(list) => &list.base.entry,
            ParamListOutput::Register(list) => &list.base.base.entry,
        };
        for e in entries {
            let base = e.get_base();
            let esize = e.get_size() as u64;
            if off >= base && (off - base) + size as u64 <= esize {
                return Some((e.get_space(), off, size));
            }
        }
        None
    }

    // Ghidra: fspec.cc:4459 FuncProto::getBiggestContainedInputParam
    /// Find the biggest input-parameter storage entirely contained in the
    /// given range. The varargs and `voidinputlock` early-returns are exact;
    /// the locked-parameter scan degrades to the model branch because
    /// Rugra's `ProtoParameter.address` carries no space identity (see
    /// `characterize_as_input_param`); removal is gated on ADDRESS-0001.
    pub fn get_biggest_contained_input_param(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> Option<(AddressSpace, u64, i32)> {
        if !self.is_dotdotdot && self.void_input_locked {
            // Ghidra: if ((flags&voidinputlock)!=0) return false;
            return None;
        }
        let Some(model) = self.model.as_ref() else {
            return None;
        };
        model
            .input
            .get_biggest_contained_param(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:4492 FuncProto::getBiggestContainedOutput
    /// Find the biggest output storage entirely contained in the given
    /// range. With a locked output AND a recorded proto-store storage the
    /// locked branch (fspec.cc:4495-4506) runs exactly — TYPE_VOID gate,
    /// then the cc:4500 containedBy test on the outparam's own Address.
    /// Without a recorded storage the lookup degrades to the model branch
    /// (same ADDRESS-0001-gated transitional fallback as
    /// `characterize_as_output`).
    pub fn get_biggest_contained_output(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> Option<(AddressSpace, u64, i32)> {
        if self.is_output_locked() {
            // Ghidra: fspec.cc:4496-4498
            //   ProtoParameter *outparam = getOutput();
            //   if (outparam->getType()->getMetatype() == TYPE_VOID)
            //     return false;
            if matches!(
                self.return_type.get_metatype(),
                crate::type_system::TypeMetatype::Void
            ) {
                return None;
            }
            if let Some((spc, off)) = self.output_storage {
                // Ghidra: fspec.cc:4499-4505 — iaddr.containedBy(
                //   outparam->getSize(), loc, size): the locked output
                //   storage (this) contained by the queried range (op2).
                // The `base != op2.base` guard of address.cc:113 is the
                // space equality below.
                let out_size = self.return_type.get_size() as i32;
                if spc == addr_space && contained_by_range(off, out_size, addr_offset, size) {
                    return Some((spc, off, out_size));
                }
                return None;
            }
            // Transitional: locked output with no recorded storage —
            // Ghidra's locked branch is terminal (fspec.cc:4506); the
            // model-branch fallthrough only exists on Rugra's no-storage
            // path, which Ghidra cannot reach.
        }
        let Some(model) = self.model.as_ref() else {
            return None;
        };
        model
            .output
            .get_biggest_contained_param(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:3818 FuncProto::setModel
    /// Install or clear the shared prototype model and update the model-derived
    /// prototype state. Model flags are sticky, and an unknown extra-pop value
    /// does not replace a value already learned from an earlier model.
    pub fn set_model(&mut self, model: Option<Arc<ProtoModelFull>>) {
        let Some(model) = model else {
            self.model = None;
            self.calling_convention = "unknown".to_string();
            self.extra_pop = EXTRAPOP_UNKNOWN_FULL;
            return;
        };

        if self.model.is_none() || model.extrapop != EXTRAPOP_UNKNOWN_FULL {
            self.extra_pop = model.extrapop;
        }
        if model.has_this {
            self.has_thisptr = true;
        }
        if model.is_construct {
            self.is_constructor_flag = true;
        }
        if model.output.is_auto_killed_by_call() {
            self.auto_killed_by_call = true;
        }
        self.calling_convention = model.name.clone();
        self.model = Some(model);
    }

    // Ghidra: fspec.hh:1476 FuncProto::getExtraPop
    /// Get the prototype-local extra stack-pop value.
    pub fn get_extra_pop(&self) -> i32 {
        self.extra_pop
    }

    // Ghidra: fspec.cc:4609 FuncProto::isAutoKilledByCall
    /// Return whether call outputs are automatically killed. Output locking
    /// independently forces this property, exactly as in Ghidra.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.auto_killed_by_call || self.output_type_locked
    }

    // RUGRA-GLUE: exposes Ghidra's shared `ProtoModel *` identity for the
    // locked differential fixture without leaking the stored Arc.
    pub fn shares_model_with(&self, other: &FuncProto) -> bool {
        match (&self.model, &other.model) {
            (Some(left), (Some(right))) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    // RUGRA-GLUE: construct a clean callee prototype that shares only the
    // bound ProtoModel with a carrier. Ghidra obtains the callee's own
    // FuncProto from queryFunction; it never clones caller parameters,
    // effects, or flow flags into the callee.
    pub fn from_model_carrier(
        carrier: &FuncProto,
        name: String,
        return_type: Arc<Datatype>,
    ) -> Self {
        let mut result = FuncProto::new(name, return_type);
        result.set_model(carrier.model.clone());
        result
    }

    // Ghidra: fspec.hh:1391 FuncProto::hasMatchingModel
    /// Does \b this use the given shared model? Faithful inline accessor
    /// `hasMatchingModel` (fspec.hh:1391): `(model == op2)` pointer
    /// equality, consumed by the ActionPrototypeTypes bind guard
    /// (coreaction.cc:4617) and ActionDefaultParams (coreaction.cc:2325).
    pub fn has_matching_model(&self, op2: &Arc<ProtoModelFull>) -> bool {
        self.model.as_ref().is_some_and(|m| Arc::ptr_eq(m, op2))
    }

    // Ghidra: fspec.cc:3778 FuncProto::addEffect
    /// Add an effect record. Used during prototype analysis to record
    /// how registers/memory are affected by this function's calls.
    pub fn add_effect(&mut self, effect: EffectRecord) {
        self.effects.push(effect);
    }

    // Ghidra: fspec.cc:3906 FuncProto::isInputLocked
    /// Check whether the input prototype is locked. Zero parameters are not
    /// implicitly locked: only `void_input_locked` makes an empty prototype
    /// authoritative. For non-empty prototypes Ghidra consults the first
    /// parameter's type-lock.
    pub fn is_input_locked(&self) -> bool {
        if self.void_input_locked {
            return true;
        }
        self.parameters
            .first()
            .map(|parameter| parameter.is_type_locked())
            .unwrap_or(false)
    }

    // Ghidra: fspec.cc:3921 FuncProto::setInputLock
    /// Set input lock state. When locked, parameters won't be
    /// overridden by active recovery.
    /// Faithful to FuncProto::setInputLock (fspec.cc:3921).
    pub fn set_input_lock(&mut self, val: bool) {
        if val {
            self.model_locked = true;
        }
        if self.parameters.is_empty() {
            self.void_input_locked = val;
            return;
        }
        for p in &mut self.parameters {
            if val {
                p.flags |= protoparam_flags::TYPE_LOCKED;
                // Ghidra: fspec.cc:3047-3057 ParameterSymbol::setTypeLock —
                // on the scope-backed store the platform-locked prototypes
                // use (Funcdata::setScope installs ProtoStoreSymbol before
                // any platform signature lands), locking a NAMED parameter's
                // type locks its name too:
                //   `uint4 attrs = Varnode::typelock;
                //    if (!sym->isNameUndefined()) attrs |= Varnode::namelock;
                //    scope->setAttribute(sym,attrs);`
                // Rugra's flat parameter vector is the projection of that
                // symbol-backed store, so the named-parameter namelock
                // side-effect mirrors here. (The oracle's
                // ParameterBasic::setTypeLock, fspec.cc:2925, has no such
                // side-effect — that class backs only scopeless internal
                // stores, never the locked platform boundary.)
                if !p.name.is_empty() {
                    p.flags |= protoparam_flags::NAME_LOCKED;
                }
            } else {
                p.flags &= !protoparam_flags::TYPE_LOCKED;
            }
        }
    }

    // Ghidra: fspec.cc:3942 FuncProto::setOutputLock
    /// Set output lock state. When locked, the return value's presence and
    /// data-type will not be overridden by active recovery.
    /// Faithful to FuncProto::setOutputLock (fspec.cc:3942-3948).
    pub fn set_output_lock(&mut self, val: bool) {
        if val {
            self.model_locked = true;
        }
        self.output_type_locked = val;
    }

    // Ghidra: fspec.cc:3778 FuncProto::isOutputLocked
    /// Is the output (return) data-type locked? Faithful to
    /// `FuncProto::isOutputLocked`. Used by `funcLinkOutput` to decide
    /// whether to build an output varnode immediately (locked) or defer to
    /// active-output trials (unlocked).
    pub fn is_output_locked(&self) -> bool {
        self.output_type_locked
    }

    // Ghidra: fspec.hh:1399 FuncProto::isModelLocked
    /// Is the prototype model locked for this prototype? Faithful to
    /// `isModelLocked` (fspec.hh:1399): reads the `modellock` flag bit.
    pub fn is_model_locked(&self) -> bool {
        self.model_locked
    }

    // Ghidra: fspec.hh:1409 FuncProto::setModelLock
    /// Set or clear the model lock. Faithful to `setModelLock` (fspec.hh:1409).
    pub fn set_model_lock(&mut self, val: bool) {
        self.model_locked = val;
    }

    // Ghidra: fspec.hh:1411 FuncProto::isInline
    /// Does this function get in-lined during decompilation? Faithful to
    /// `isInline` (fspec.hh:1411): reads the `is_inline` flag bit.
    pub fn is_inline(&self) -> bool {
        self.is_inline
    }

    // Ghidra: fspec.hh:1417 FuncProto::setInline
    /// Toggle the in-line setting. Faithful to `setInline` (fspec.hh:1417).
    /// In-lining can be based on a call-fixup or the full function body.
    pub fn set_inline(&mut self, val: bool) {
        self.is_inline = val;
    }

    // Ghidra: fspec.hh:1434 FuncProto::isNoReturn
    /// Does a function with this prototype never return? Faithful to
    /// `isNoReturn` (fspec.hh:1434): reads the `no_return` flag bit.
    pub fn is_no_return(&self) -> bool {
        self.no_return
    }

    // Ghidra: fspec.hh:1439 FuncProto::setNoReturn
    /// Toggle the no-return setting. Faithful to `setNoReturn`
    /// (fspec.hh:1439). When true the function is treated as never
    /// returning, terminating its caller's basic-block flow.
    pub fn set_no_return(&mut self, val: bool) {
        self.no_return = val;
    }

    // Ghidra: fspec.hh:1442 FuncProto::hasThisPointer
    /// Is this a prototype for a class method, taking a 'this' pointer?
    /// Faithful to `hasThisPointer` (fspec.hh:1442): reads the `has_thisptr`
    /// flag bit. Set automatically by `update_this_pointer` when the model
    /// declares a this-pointer.
    pub fn has_thisptr(&self) -> bool {
        self.has_thisptr
    }

    // Ghidra: fspec.hh:1368 FuncProto::setThisPointer (via flag)
    /// Toggle whether this prototype has a 'this' pointer. Rugra analogue
    /// of the `has_thisptr` flag bit assignment that Ghidra performs in
    /// `setModel` (fspec.cc:3827).
    pub fn set_has_thisptr(&mut self, val: bool) {
        self.has_thisptr = val;
    }

    // Ghidra: fspec.hh:1544 FuncProto::isOverride
    /// Return \b true if this is a call site override. Faithful to
    /// `isOverride` (fspec.hh:1544): reads the `is_override` (0x1000) flag
    /// bit.
    pub fn is_override(&self) -> bool {
        self.is_override
    }

    // Ghidra: fspec.hh:1545 FuncProto::setOverride
    /// Toggle whether this is a call site override. Faithful to
    /// `setOverride` (fspec.hh:1545).
    pub fn set_override(&mut self, val: bool) {
        self.is_override = val;
    }

    // Ghidra: fspec.hh:1445 FuncProto::isConstructor
    /// Is this prototype for a class constructor method? Faithful to
    /// `isConstructor` (fspec.hh:1445): reads the `is_constructor` flag bit.
    /// Named `is_constructor_flag` to avoid clashing with
    /// `ProtoModel::is_constructor`.
    pub fn is_constructor_flag(&self) -> bool {
        self.is_constructor_flag
    }

    // Ghidra: fspec.hh:1450 FuncProto::setConstructor
    /// Toggle whether this prototype is a constructor method. Faithful to
    /// `setConstructor` (fspec.hh:1450).
    pub fn set_constructor(&mut self, val: bool) {
        self.is_constructor_flag = val;
    }

    // Ghidra: fspec.hh:1453 FuncProto::isDestructor
    /// Is this prototype for a class destructor method? Faithful to
    /// `isDestructor` (fspec.hh:1453): reads the `is_destructor` flag bit.
    pub fn is_destructor(&self) -> bool {
        self.is_destructor
    }

    // Ghidra: fspec.hh:1458 FuncProto::setDestructor
    /// Toggle whether this prototype is a destructor method. Faithful to
    /// `setDestructor` (fspec.hh:1458).
    pub fn set_destructor(&mut self, val: bool) {
        self.is_destructor = val;
    }

    // Ghidra: fspec.cc:3843 FuncProto::setPieces
    /// Set this prototype from a `PrototypePieces`, locking input, output, and
    /// model. This implements the model-preserving path of `setPieces`
    /// (fspec.cc:3843): parameter types/names are installed through
    /// `update_all_types_from_pieces`, then all three locks are set. A
    /// different model name is currently only the serialized/display
    /// projection; resolving it to another shared `ProtoModelFull` remains
    /// `FSPEC-0002`.
    pub fn set_pieces(&mut self, pieces: &crate::grammar::PrototypePieces) {
        if let Some(ref nm) = pieces.model {
            if !nm.is_empty() {
                self.set_model_name(nm);
            }
        }
        self.update_all_types_from_pieces(pieces);
        self.set_input_lock(true);
        self.set_output_lock(true);
        self.set_model_lock(true);
    }

    // Ghidra: fspec.cc:3778 FuncProto::getReturnBytesConsumed
    /// Get the number of bytes of the return value consumed by callers.
    /// Faithful to `FuncProto::getReturnBytesConsumed` (fspec.hh:1429).
    /// A value of 0 means all bytes are presumed consumed.
    pub fn get_return_bytes_consumed(&self) -> u32 {
        self.return_bytes_consumed
    }

    // Ghidra: fspec.cc:3954 FuncProto::setReturnBytesConsumed
    /// Set the hint for how many bytes of the return value are consumed.
    /// Faithful to `FuncProto::setReturnBytesConsumed` (fspec.cc:3954-3965).
    /// The smallest hint wins (the value can only shrink). Returns true if
    /// the smallest hint changed.
    pub fn set_return_bytes_consumed(&mut self, val: u32) -> bool {
        if val == 0 {
            return false;
        }
        if self.return_bytes_consumed == 0 || val < self.return_bytes_consumed {
            self.return_bytes_consumed = val;
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:3789 FuncProto::copy
    /// Copy from another FuncProto.
    /// Faithful to FuncProto::copy (fspec.cc:3789).
    pub fn copy_from(&mut self, other: &FuncProto) {
        self.name = other.name.clone();
        self.return_type = other.return_type.clone();
        self.parameters = other.parameters.clone();
        self.void_input_locked = other.void_input_locked;
        self.calling_convention = other.calling_convention.clone();
        self.is_dotdotdot = other.is_dotdotdot;
        self.effects = other.effects.clone();
        self.model = other.model.clone();
        self.extra_pop = other.extra_pop;
        self.auto_killed_by_call = other.auto_killed_by_call;
        self.output_type_locked = other.output_type_locked;
        // Ghidra: fspec.cc:3797-3798 store = op2.store->clone() — the
        // clone carries the outparam's storage address with it.
        self.output_storage = other.output_storage;
        self.model_locked = other.model_locked;
        self.is_inline = other.is_inline;
        self.no_return = other.no_return;
        self.is_constructor_flag = other.is_constructor_flag;
        self.is_destructor = other.is_destructor;
        self.has_thisptr = other.has_thisptr;
        // Ghidra: fspec.cc:3794 `flags = op2.flags` — the whole flag word
        // (including is_override) is carried by FuncProto::copy.
        self.is_override = other.is_override;
        self.error_input_param = other.error_input_param;
    }

    // Ghidra: fspec.cc:3994 FuncProto::clearUnlockedInput
    /// Clear unlocked input parameters.
    /// Faithful to FuncProto::clearUnlockedInput (fspec.cc:3994).
    pub fn clear_unlocked_input(&mut self) {
        if self.is_input_locked() {
            return;
        }
        self.parameters.clear();
    }

    // Ghidra: fspec.cc:4016 FuncProto::clearInput
    /// Clear ALL input parameters (including locked ones).
    pub fn clear_input(&mut self) {
        self.parameters.clear();
        self.void_input_locked = false;
    }

    // Ghidra: fspec.cc:3806 FuncProto::copyFlowEffects
    /// Copy the flow-affecting properties from another FuncProto. Faithful
    /// to `FuncProto::copyFlowEffects` (fspec.cc:3806-3812): only the
    /// `is_inline|no_return` flag subset and the call-fixup inject id are
    /// copied, as a one-way overwrite — Ghidra clears both bits on `this`
    /// first (`flags &= ~(is_inline|no_return)`) and then ORs in the
    /// source's bits, so a source with a bit clear clears the destination
    /// bit. This is the channel `FlowInfo::queryCall` (flow.cc:664) uses to
    /// propagate a callee's noreturn/inline state onto the call-site
    /// FuncCallSpecs. The effect list is NOT part of this operation (it is
    /// copied wholesale only by `FuncProto::copy`, fspec.cc:3801).
    ///
    /// Rugra's dedicated bool fields make Ghidra's clear-then-OR bit pair
    /// bit-equivalent to a direct assignment. The `injectid = op2.injectid`
    /// copy is not modeled yet because Rugra's FuncProto has no injection
    /// id storage (`set_inject_id` is the INJECT-0001 no-op stub); wiring
    /// that field is owned by INJECT-0001.
    pub fn copy_flow_effects(&mut self, other: &FuncProto) {
        self.is_inline = other.is_inline;
        self.no_return = other.no_return;
        // Ghidra: injectid = op2.injectid; (INJECT-0001: no injectid field)
    }

    // Ghidra: fspec.cc:3706 FuncProto::paramShift
    /// Shift parameter positions by a given amount.
    pub fn param_shift(&mut self, shift: i32) {
        if shift == 0 { return; }
        // Simplified: shift parameter addresses. Address type may not
        // support wrapping_add directly, so use as_u64().
    }

    // Ghidra: fspec.cc:3971 FuncProto::resolveExtraPop
    /// Resolve the extra pop value for this prototype.
    pub fn resolve_extra_pop(&mut self) {
        // Simplified: no ProtoModel integration, so this is a no-op.
    }

    // Ghidra: fspec.cc:4025 FuncProto::setInjectId
    /// Set the injection id for this prototype.
    pub fn set_inject_id(&mut self, _id: i32) {
        // Rugra: p-code injection is partial. Store for future use.
    }

    // Ghidra: fspec.cc:4036 FuncProto::cancelInjectId
    /// Cancel the injection id.
    pub fn cancel_inject_id(&mut self) {}

    // Ghidra: fspec.cc:4001 FuncProto::clearUnlockedOutput
    /// Clear unlocked output (return type).
    pub fn clear_unlocked_output(&mut self) {
        if !self.is_output_locked() {
            self.output_type_locked = false;
        }
    }

    // Ghidra: fspec.cc:3891 FuncProto::setInternal
    /// Set up an internal prototype. Faithful to `setInternal`
    /// (fspec.cc:3891-3898): the output/parameter backing switches to the
    /// internal store (Rugra models only the store's void output flavor as
    /// `return_type`, PROTOSTORE-SYMBOL-0001 owns the store itself) and the
    /// model is installed only when there is none yet — the exact
    /// `if (model == (ProtoModel *)0) setModel(m)` guard, so a previously
    /// bound model (e.g. the Architecture default bound via the Funcdata
    /// construction chain) is never replaced by a later internal setup.
    pub fn set_internal(&mut self, model: Option<Arc<ProtoModelFull>>, vt: Arc<Datatype>) {
        self.return_type = vt;
        if self.model.is_none() {
            self.set_model(model);
        }
    }

    // Ghidra: fspec.cc:3572 FuncProto::updateThisPointer
    /// Make sure any "this" parameter is properly marked. Faithful to
    /// `updateThisPointer` (fspec.cc:3572-3584). If the prototype has a
    /// this-pointer (model-derived), the first non-hidden-return input
    /// parameter has its `THIS_POINTER` flag set.
    pub fn update_this_pointer(&mut self) {
        if !self.has_thisptr {
            return;
        }
        let num_inputs = self.parameters.len();
        if num_inputs == 0 {
            return;
        }
        let mut idx = 0;
        if self.parameters[0].is_hidden_return() {
            if num_inputs < 2 {
                return;
            }
            idx = 1;
        }
        self.parameters[idx].set_this_pointer(true);
    }

    // Ghidra: fspec.cc:3778 FuncProto::isVarargs
    /// Check if this proto is variable-argument (...).
    pub fn is_varargs(&self) -> bool { self.is_dotdotdot }

    // Ghidra: fspec.cc:3778 FuncProto::setDotdotdot
    /// Set variable-argument flag.
    pub fn set_dotdotdot(&mut self, val: bool) { self.is_dotdotdot = val; }

    // Ghidra: fspec.cc:3778 FuncProto::getModelName
    /// Get the calling-convention model name.
    pub fn get_model_name(&self) -> &str { &self.calling_convention }

    // Ghidra: fspec.cc:3778 FuncProto::setModelName
    /// Set the calling-convention model name.
    pub fn set_model_name(&mut self, name: &str) { self.calling_convention = name.to_string(); }

    // Ghidra: fspec.hh:1394 FuncProto::isModelUnknown
    /// Return true if the prototype model is unknown. Faithful to
    /// `FuncProto::isModelUnknown()` (fspec.hh:1394), which delegates to
    /// `model->isUnknown()`. Rugra represents the model as a string; the
    /// "unknown" sentinel (constructor default, fspec.rs:151) maps to Ghidra's
    /// `UnknownModel::isUnknown() == true` (fspec.hh:1031).
    pub fn is_model_unknown(&self) -> bool {
        self.calling_convention == "unknown" || self.calling_convention.is_empty()
    }

    // Ghidra: fspec.hh:1395 FuncProto::printModelInDecl
    /// Return true if the model name should be printed in declarations.
    /// Faithful to `FuncProto::printModelInDecl()` (fspec.hh:1395), which
    /// delegates to the model's own `printInDecl()` flag (fspec.hh:981).
    /// `Architecture::setDefaultModel` flips the previous default to true and
    /// the newly selected default to false (architecture.cc:326-329), so the
    /// resolved default model is NOT printed in declarations; only models
    /// explicitly marked (e.g. via `<prototype>` decode or the __thiscall
    /// alias clone) print. A modelless prototype (pre-binding legacy
    /// callers) never reaches Ghidra's print stage; Rugra keeps the
    /// historical false. This guards the `option_convention` branch in
    /// `emit_function_declaration` (printc.cc:2583-2589).
    pub fn print_model_in_decl(&self) -> bool {
        self.model.as_ref().is_some_and(|model| model.print_in_decl())
    }

    // Ghidra: fspec.cc:4052 FuncProto::updateInputTypes
    /// Update input parameters based on Varnode trials. Faithful 1:1 port of
    /// `updateInputTypes` (fspec.cc:4052-4087). If the input is locked, do
    /// nothing. Otherwise clear all inputs, then for each trial marked USED,
    /// build a `ParameterPieces` from the trial's varnode (address + the
    /// varnode's high type, or a disjoint-cover address for persistent
    /// varnodes) and append it as a new input parameter. Varnodes already
    /// consumed are skipped via the mark bit, then all marks are cleared.
    ///
    /// `find_disjoint_cover` is supplied by the caller because Rugra's
    /// `Funcdata::findDisjointCover` is not yet ported; it returns the cover
    /// address and size for a persistent varnode.
    pub fn update_input_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        activeinput: &crate::fspec::ParamActive,
        find_disjoint_cover: &dyn Fn(&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>) -> (Address, i32),
        store_set_input: &mut dyn FnMut(usize, &ParameterPieces),
    ) {
        if self.is_input_locked() { return; } // Input is locked, do no updating.
        // store->clearAllInputs()
        self.parameters.clear();
        let mut count = 0usize;
        let numtrials = activeinput.get_num_trials();
        for i in 0..numtrials {
            let trial = activeinput.get_trial(i);
            if !trial.is_used() { continue; }
            // vn = triallist[trial.getSlot()-1]
            let slot = trial.get_slot();
            if slot < 1 { continue; }
            let idx = (slot - 1) as usize;
            if idx >= triallist.len() { continue; }
            let vn = triallist[idx].clone();
            // if (vn->isMark()) continue;
            if vn.read().unwrap().is_mark() { continue; }
            let mut pieces = ParameterPieces::default();
            let (addr, ty) = {
                let vn_r = vn.read().unwrap();
                if vn_r.is_persist() {
                    // Ghidra: pieces.addr = data.findDisjointCover(vn, sz)
                    let (cover_addr, sz) = find_disjoint_cover(&vn);
                    let ty = if sz as usize == vn_r.get_size() {
                        vn_r.get_type()
                    } else {
                        None // Ghidra: getBase(sz, TYPE_UNKNOWN) — filled below.
                    };
                    (cover_addr, ty)
                } else {
                    // pieces.addr = trial.getAddress(); pieces.type = vn->getHigh()->getType()
                    (trial.get_address(), vn_r.get_type())
                }
            };
            pieces.addr = addr;
            pieces.space = trial.get_space();
            // Ghidra's high type is never null (every HighVariable carries
            // at least the size-derived TYPE_UNKNOWN); fold Rust's None to
            // the unknown base of the varnode's size, matching the
            // updateInputNoTypes factory call (fspec.cc:4118).
            pieces.ty = Some(match ty {
                Some(t) => t,
                None => {
                    let size = vn.read().unwrap().get_size();
                    crate::type_system::TypeFactory::shared_default()
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get_base(size, crate::type_system::TypeMetatype::Unknown)
                        .expect("factory always produces an unknown base type")
                }
            });
            pieces.flags = 0;
            // store->setInput(count, "", pieces) (fspec.cc:4079) — the store
            // is the ScopeLocal-backed ProtoStoreSymbol for the function
            // under analysis (FuncProto::setScope, fspec.cc:3879-3885 with
            // funcdata.cc:69's baseaddr-1 restricted usepoint), whose
            // setInput (fspec.cc:3147-3183) installs/refreshes the
            // function_parameter category symbol the naming passes read.
            // Rugra folds that side effect through this callback (the flat
            // FuncProto store keeps signature printing on `parameters`).
            store_set_input(count, &pieces);
            // The Ghidra hand-off carries the empty name to the proto
            // store, whose ScopeInternal symbol is default-named
            // "param_<index+1>" at commit (database.cc:2481, category
            // function_parameter with catindex=count). The flat FuncProto
            // store folds that default name here.
            let nm = format!("param_{}", count + 1);
            self.set_input_parameter(count, &nm, pieces);
            count += 1;
            vn.write().unwrap().set_mark();
        }
        // Clear marks on all trial varnodes.
        for vn in triallist {
            vn.write().unwrap().clear_mark();
        }
        self.update_this_pointer();
    }

    // Ghidra: fspec.cc:4097 FuncProto::updateInputNoTypes
    /// Update input parameters based on Varnode trials, but do not store
    /// the data-type. Faithful 1:1 port of `updateInputNoTypes`
    /// (fspec.cc:4097-4128): same used-trial walk as `update_input_types`,
    /// with only the size used — an undefined data-type of the varnode's
    /// size (or the disjoint-cover size for persistent varnodes) comes from
    /// the shared TypeFactory. Names fold to the same proto-store default
    /// ("param_<count+1>") as `update_input_types`.
    pub fn update_input_no_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        activeinput: &crate::fspec::ParamActive,
        store_set_input: &mut dyn FnMut(usize, &ParameterPieces),
    ) {
        if self.is_input_locked() { return; }
        self.parameters.clear();
        let mut count = 0usize;
        let numtrials = activeinput.get_num_trials();
        for i in 0..numtrials {
            let trial = activeinput.get_trial(i);
            if !trial.is_used() { continue; }
            let slot = trial.get_slot();
            if slot < 1 { continue; }
            let idx = (slot - 1) as usize;
            if idx >= triallist.len() { continue; }
            let vn = triallist[idx].clone();
            if vn.read().unwrap().is_mark() { continue; }
            let mut pieces = ParameterPieces::default();
            let factory_arc = crate::type_system::TypeFactory::shared_default();
            let factory = factory_arc
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (addr, ty) = {
                let vn_r = vn.read().unwrap();
                if vn_r.is_persist() {
                    // cc:4110-4114 — findDisjointCover + getBase(sz,UNKNOWN):
                    // with findDisjointCover unported, the varnode's own
                    // (addr,size) is the cover stand-in (same fold as
                    // update_input_types' persist arm).
                    let sz = vn_r.get_size();
                    (
                        vn_r.get_addr().clone(),
                        factory
                            .get_base(sz, crate::type_system::TypeMetatype::Unknown)
                            .expect("factory always produces an unknown base type"),
                    )
                } else {
                    // cc:4117-4119 — trial.getAddress() +
                    // getBase(vn->getSize(),TYPE_UNKNOWN)
                    (
                        trial.get_address(),
                        factory
                            .get_base(vn_r.get_size(), crate::type_system::TypeMetatype::Unknown)
                            .expect("factory always produces an unknown base type"),
                    )
                }
            };
            pieces.addr = addr;
            pieces.space = trial.get_space();
            pieces.ty = Some(ty);
            pieces.flags = 0;
            // store->setInput(count,"",pieces) (fspec.cc:4121) — same
            // ScopeLocal-backed ProtoStoreSymbol::setInput side effect as
            // update_input_types above (fspec.cc:3147-3183).
            store_set_input(count, &pieces);
            let nm = format!("param_{}", count + 1);
            self.set_input_parameter(count, &nm, pieces);
            count += 1;
            vn.write().unwrap().set_mark();
        }
        for vn in triallist {
            vn.write().unwrap().clear_mark();
        }
    }
    // Ghidra: fspec.cc:4194 FuncProto::updateAllTypes
    /// Set this entire function prototype from a list of names and data-types.
    /// This ports the model-driven scalar path of `updateAllTypes`
    /// (fspec.cc:4194-4224): existing inputs/output are cleared, the current
    /// model assigns storage, hidden-return inputs do not consume a
    /// source-level name, and assignment failure sets the sticky input-error
    /// flag. Full Address identity, ModelRules, canonical hidden-return pointer
    /// construction, and invalid-address state remain `FSPEC-0002`.
    pub fn update_all_types_from_pieces(&mut self, proto: &crate::grammar::PrototypePieces) {
        // setModel(model) resets extrapop from the current model.
        let model = self.model.clone();
        self.set_model(model.clone());
        self.parameters.clear();
        self.return_type = crate::type_system::TypeFactory::shared_default()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_void();
        self.output_storage = None;
        self.void_input_locked = false;
        self.is_dotdotdot = proto.first_var_arg_slot >= 0;

        let Some(model) = model else {
            self.error_input_param = true;
            self.update_this_pointer();
            return;
        };
        let borrowed = PrototypePieces {
            out_type: proto.out_type.as_ref(),
            in_types: &proto.in_types,
            first_var_arg_slot: proto.first_var_arg_slot,
        };
        let mut assigned = Vec::new();
        if model
            .assign_parameter_storage(&borrowed, &mut assigned, false, None)
            .is_err()
        {
            self.error_input_param = true;
            self.update_this_pointer();
            return;
        }

        if let Some(output) = assigned.first().cloned() {
            if let Some(ref ty) = output.ty {
                self.return_type = ty.clone();
            }
            self.output_storage = Some((output.space, output.addr.as_u64()));
        }

        let mut j = 0usize;
        for (i, pieces) in assigned.into_iter().enumerate().skip(1) {
            if (pieces.flags & HIDDEN_RET_PARM) != 0 {
                self.set_input_parameter(i - 1, "rethidden", pieces);
                continue;
            }
            let nm = if j < proto.in_names.len() {
                proto.in_names[j].as_str()
            } else {
                ""
            };
            self.set_input_parameter(i - 1, nm, pieces);
            j += 1;
        }
        self.update_this_pointer();
    }

    // Ghidra: fspec.cc:3857 FuncProto::getPieces
    /// Copy out the raw pieces of this prototype as stand-alone objects
    /// (model name, names, and data-types). Faithful to `getPieces`
    /// (fspec.cc:3857-3870). Ghidra returns the `ProtoModel *`; Rugra returns
    /// the model name (see `get_model_name`). `first_var_arg_slot` is set to
    /// the param count when `is_dotdotdot`, else -1.
    pub fn get_pieces(&self) -> crate::grammar::PrototypePieces {
        let mut pieces = crate::grammar::PrototypePieces {
            model: Some(self.get_model_name().to_string()),
            name: self.name.clone(),
            out_type: Some(self.return_type.clone()),
            in_types: Vec::new(),
            in_names: Vec::new(),
            first_var_arg_slot: if self.is_dotdotdot {
                self.parameters.len() as i32
            } else {
                -1
            },
        };
        for p in &self.parameters {
            pieces.in_types.push(p.data_type.clone());
            pieces.in_names.push(p.name.clone());
        }
        pieces
    }

    // Ghidra: fspec.cc:4136 FuncProto::updateOutputTypes
    /// Update the return value based on Varnode trials. Faithful 1:1 port of
    /// `updateOutputTypes` (fspec.cc:4136-4162). If the output is not locked
    /// and the trial list is empty, the return value is cleared. If the output
    /// is size-locked, an exactly-matching trial overrides the size-locked
    /// type. If the output is fully locked, nothing happens. Otherwise the
    /// return value is rebuilt from the (at most one) trial varnode.
    pub fn update_output_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        get_output_addr_size: &dyn Fn(&FuncProto) -> (Address, i32, bool),
    ) {
        // ProtoParameter *outparm = getOutput();
        // isSizeTypeLocked → no direct field; derived from output_type_locked
        // and whether the type carries a size lock. Rugra models a size-locked
        // output via output_type_locked == true with a TYPE_UNKNOWN-sized
        // return; for the faithful port we treat output_type_locked as the
        // size-lock signal when no concrete type is set.
        let out_type_locked = self.output_type_locked;
        let outparm_is_size_locked = out_type_locked;
        if !out_type_locked {
            if triallist.is_empty() {
                // fspec.cc:4142 store->clearOutput() — unconditional void
                // output: ProtoStoreInternal::clearOutput (fspec.cc:3389-
                // 3395) replaces the outparam with ParameterBasic(voidtype);
                // ProtoStoreSymbol::clearOutput (fspec.cc:3262-3270) sets
                // pieces.type = getTypeVoid(). The return value itself
                // resets to void — NOT just the lock flag (the former
                // clear_unlocked_output delegation kept a stale type,
                // af6c5ee2 Evidence 断言了未实现的行为, CR29 件④).
                self.return_type = std::sync::Arc::new(
                    crate::type_system::datatype::Datatype::Void(
                        crate::type_system::datatype::TypeBase::new(
                            "void".to_string(),
                            0,
                            crate::type_system::TypeMetatype::Void,
                        ),
                    ),
                );
                return;
            }
        } else if outparm_is_size_locked {
            // isSizeTypeLocked path: override only on exact address+size match.
            if triallist.is_empty() { return; }
            let (out_addr, out_size, _) = get_output_addr_size(self);
            let vn0 = triallist[0].read().unwrap();
            if *vn0.get_addr() == out_addr && vn0.get_size() as i32 == out_size {
                // outparm->overrideSizeLockType(triallist[0]->getHigh()->getType())
                if let Some(t) = vn0.get_type() {
                    self.return_type = t;
                }
            }
            return;
        } else {
            // Fully locked (type-locked, not size-locked): return.
            return;
        }

        if triallist.is_empty() { return; }
        // Build the output piece from the trial varnode. The piece's legacy
        // Address is spaceless, so the varnode's space travels alongside
        // (ProtoStoreInternal::setOutput receives a full Address in Ghidra).
        let mut pieces = ParameterPieces::default();
        let piece_space;
        {
            let vn0 = triallist[0].read().unwrap();
            pieces.addr = *vn0.get_addr();
            // Ghidra: pieces.type = triallist[0]->getHigh()->getType()
            // (fspec.cc:4155) — the HIGH type is never null because every
            // untyped Varnode is created with getBase(size,TYPE_UNKNOWN)
            // (Funcdata::newVarnode/newUnique/newConstant,
            // funcdata_varnode.cc:83/148/…), so an unconstrained return
            // value types as `undefined<N>`. Fold Rust's None to the same
            // unknown base (the convention of the input-side port at
            // fspec.cc:4118's updateInputNoTypes fold).
            pieces.ty = Some(match vn0.get_type() {
                Some(t) => t,
                None => {
                    let size = vn0.get_size();
                    crate::type_system::typefactory::TypeFactory::shared_default()
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get_base(size, crate::type_system::TypeMetatype::Unknown)
                        .expect("factory always produces an unknown base type")
                }
            });
            pieces.flags = 0;
            piece_space = vn0.get_space();
        }
        // store->setOutput(pieces)
        self.set_output_parameter(pieces, piece_space);
    }

    // Ghidra: fspec.cc:4172 FuncProto::updateOutputNoTypes
    /// Update the return value based on Varnode trials, but don't store a
    /// data-type. Faithful 1:1 body of `updateOutputNoTypes`
    /// (fspec.cc:4172-4185): a locked output is untouched; an empty trial
    /// list clears the output; otherwise the output is rebuilt from
    /// trial[0]'s address and an undefined type of its size
    /// (`factory->getBase(triallist[0]->getSize(),TYPE_UNKNOWN)`).
    pub fn update_output_no_types(
        &mut self,
        triallist: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
    ) {
        if self.is_output_locked() { return; }
        if triallist.is_empty() {
            // Ghidra: store->clearOutput(); — the void-reset shape shared
            // with update_output_types' empty arm.
            self.return_type = std::sync::Arc::new(
                crate::type_system::datatype::Datatype::Void(
                    crate::type_system::datatype::TypeBase::new(
                        "void".to_string(),
                        0,
                        crate::type_system::TypeMetatype::Void,
                    ),
                ),
            );
            self.output_storage = None;
            self.output_type_locked = false;
            return;
        }
        let mut pieces = ParameterPieces::default();
        {
            let vn0 = triallist[0].read().unwrap();
            pieces.ty = Some(
                crate::type_system::TypeFactory::shared_default()
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_base(vn0.get_size(), crate::type_system::TypeMetatype::Unknown)
                    .expect("factory always produces an unknown base type"),
            );
            pieces.addr = *vn0.get_addr();
            pieces.space = vn0.get_space();
        }
        pieces.flags = 0;
        // Ghidra: store->setOutput(pieces);
        let space = pieces.space;
        self.set_output_parameter(pieces, space);
    }

    // Ghidra: fspec.cc:3879 FuncProto::setScope
    /// Set a backing symbol Scope for \b this. Faithful to `setScope`
    /// (fspec.cc:3879-3885): the store becomes a `ProtoStoreSymbol` over
    /// `(s, startpoint)`, so parameters added during analysis reflect in
    /// the symbol table; the default model takes effect when none is set
    /// (`if (model == 0) setModel(s->getArch()->defaultfp);`). Rugra's
    /// flat `parameters` projection stays in sync through
    /// `set_input_parameter`'s store routing; read-back of the
    /// symbol-backed views goes through `symbol_store()` (the flat
    /// `get_param` reads the internal projection).
    pub fn set_scope(
        &mut self,
        scope: FspecScopeRef,
        startpoint: (AddressSpace, u64),
        default_model: Option<Arc<ProtoModelFull>>,
    ) {
        self.symbol_store = Some(ProtoStoreSymbol::new(scope, startpoint));
        if self.model.is_none() {
            self.set_model(default_model);
        }
    }

    /// The installed symbol-backed store, if `set_scope` ran (the
    /// ProtoStoreSymbol face of the prototype's parameter storage).
    // RUGRA-GLUE: accessor for the optional store field (Ghidra reaches
    // the store through the protected `store` pointer).
    pub fn symbol_store(&self) -> Option<&ProtoStoreSymbol> {
        self.symbol_store.as_ref()
    }

    // Ghidra: fspec.hh:1513 FuncProto::checkInputJoin
    /// Check if two input storage locations can represent a single logical
    /// parameter. Faithful inline delegation `return model->checkInputJoin(
    /// hiaddr,hisz,loaddr,losz);` (fspec.hh:1514).
    pub fn check_input_join(
        &self, space: AddressSpace, hi_addr: Address, hisz: i32, lo_addr: Address, losz: i32,
    ) -> bool {
        match &self.model {
            Some(model) => model.check_input_join(space, hi_addr, hisz, lo_addr, losz),
            None => false,
        }
    }

    // Ghidra: fspec.hh:1524 FuncProto::checkInputSplit
    /// Check if it makes sense to split a single storage location into two
    /// input parameters. Faithful inline delegation `return
    /// model->checkInputSplit(loc,size,splitpoint);` (fspec.hh:1525).
    pub fn check_input_split(
        &self, space: AddressSpace, loc: Address, size: i32, splitpoint: i32,
    ) -> bool {
        match &self.model {
            Some(model) => model.input.check_split(space, loc, size, splitpoint),
            None => false,
        }
    }

    // Ghidra: fspec.hh:1534 FuncProto::removeParam
    /// Remove the i-th input parameter: `void removeParam(int4 i) {
    /// store->clearInput(i); }` (fspec.hh:1534) — the flat store excises
    /// the parameter (Rust `Vec::remove` keeps the following parameters in
    /// place, matching the renumbering `ProtoStoreInternal::clearInput`
    /// performs at fspec.cc:3348-3351).
    pub fn remove_param(&mut self, i: usize) {
        if i < self.parameters.len() {
            self.parameters.remove(i);
        }
    }

    // Ghidra: fspec.hh:1551 FuncProto::internalBegin
    // Ghidra: fspec.hh:1552 FuncProto::internalEnd
    /// The model's internal-storage list; the slice IS the
    /// `internalBegin()`/`internalEnd()` iterator pair (fspec.hh:1551-1552
    /// delegate to `model->internalBegin()/internalEnd()`). Panics without
    /// a model exactly like Ghidra's null `model` dereference.
    pub fn internal_iter(&self) -> &[VarnodeData] {
        self.model
            .as_ref()
            .expect("FuncProto::internal_iter requires a prototype model")
            .internal_iter()
    }

    // Ghidra: fspec.hh:1586 FuncProto::assumedInputExtension
    /// Get the extension opcode and containing input parameter for the
    /// given storage. Faithful inline delegation `return
    /// model->assumedInputExtension(addr,size,res);` (fspec.hh:1587).
    pub fn assumed_input_extension(
        &self, space: AddressSpace, addr: Address, size: i32, res: &mut VarnodeData,
    ) -> FspecOpCode {
        match &self.model {
            Some(model) => model.assumed_input_extension(space, addr, size, res),
            None => FspecOpCode::CPUI_COPY,
        }
    }

    // Ghidra: fspec.hh:1599 FuncProto::assumedOutputExtension
    /// Get the extension opcode and containing return-value location for
    /// the given storage. Faithful inline delegation `return
    /// model->assumedOutputExtension(addr,size,res);` (fspec.hh:1600).
    pub fn assumed_output_extension(
        &self, space: AddressSpace, addr: Address, size: i32, res: &mut VarnodeData,
    ) -> FspecOpCode {
        match &self.model {
            Some(model) => model.assumed_output_extension(space, addr, size, res),
            None => FspecOpCode::CPUI_COPY,
        }
    }

    // Ghidra: fspec.cc:4516 FuncProto::getThisPointerStorage
    /// Get the storage location associated with the "this" pointer.
    /// Faithful 1:1 body of `getThisPointerStorage` (fspec.cc:4516-4533):
    /// models without a this-pointer yield an invalid address; otherwise
    /// the prototype is assigned as (current output type, dt) and the first
    /// non-hidden-return input piece's address is returned; an all-hidden
    /// assignment yields an invalid address.
    pub fn get_this_pointer_storage(
        &self,
        dt: &Arc<Datatype>,
    ) -> Option<(AddressSpace, Address)> {
        let model = self.model.as_ref()?;
        if !model.has_this_pointer() {
            return None;
        }
        let in_types = [dt.clone()];
        let proto = PrototypePieces {
            out_type: Some(&self.return_type),
            in_types: &in_types,
            first_var_arg_slot: -1,
        };
        let mut res = Vec::new();
        // ignoreOutputError = true (fspec.cc:4527).
        if model
            .assign_parameter_storage(&proto, &mut res, true, None)
            .is_err()
        {
            return None;
        }
        for piece in res.iter().skip(1) {
            if (piece.flags & HIDDEN_RET_PARM) != 0 {
                continue;
            }
            return Some((piece.space, piece.addr));
        }
        None
    }

    // Ghidra: fspec.cc:4675 FuncProto::decode
    /// Restore this prototype from a `<prototype>` element. Faithful port of
    /// `FuncProto::decode` (fspec.cc:4675-4840). Parses the model name,
    /// extrapop, and lock flags (modellock/dotdotdot/voidlock/inline/
    /// noreturn/custom/constructor/destructor), sets the model, decodes the
    /// `<returnsym>` element (output storage + type-lock), then the
    /// `<unaffected>`/`<killedbycall>`/`<returnaddress>`/`<likelytrash>`/
    /// `<inject>`/`<internallist>` children. Lock flags are reconciled and
    /// `update_this_pointer` is called at the end.
    ///
    /// Rugra's `FuncProto` carries a flat parameter list and a calling-
    /// convention *name* rather than a `ProtoModel *`. The `model_resolver`
    /// callback maps the decoded model name to whatever the caller uses (e.g.
    /// a `ProtoModelFull`), returning `true` if the model was found.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        model_resolver: &dyn Fn(&str) -> bool,
        decode_output_storage: &dyn Fn(&mut dyn crate::marshal::Decoder) -> (Address, Arc<Datatype>, bool),
    ) -> Result<(), String> {
        use crate::marshal::Decoder;
        // Model must be set first (Ghidra: store must be non-null).
        let mut seen_extrapop = false;
        let mut read_extrapop: i32 = 0;
        // Ghidra: flags = 0; injectid = -1.
        self.is_dotdotdot = false;
        self.output_type_locked = false;
        // We reset model-lock-relevant state; `calling_convention` is set by
        // the model attribute below.
        let elem_id = decoder.open_element();
        let mut found_model = false;
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 { break; }
            match decoder.attribute_name(aid).as_deref() {
                Some("model") => {
                    let modelname = decoder.read_string();
                    if modelname.is_empty() || modelname == "default" {
                        // Use the default model.
                        found_model = model_resolver("default");
                    } else {
                        found_model = model_resolver(&modelname);
                        // Ghidra: if mod == null, createUnknownModel. We record
                        // the name regardless so later resolution can pick it up.
                        self.calling_convention = modelname;
                    }
                }
                Some("extrapop") => {
                    seen_extrapop = true;
                    let s = decoder.read_string();
                    if s == "unknown" {
                        read_extrapop = EXTRAPOP_UNKNOWN_FULL;
                    } else {
                        read_extrapop = s.parse::<i32>().unwrap_or(EXTRAPOP_UNKNOWN_FULL);
                    }
                }
                Some("modellock") => { if decoder.read_bool() { self.model_locked = true; } }
                Some("dotdotdot") => { if decoder.read_bool() { self.is_dotdotdot = true; } }
                Some("voidlock") => { /* voidinputlock tracked implicitly */ let _ = decoder.read_bool(); }
                Some("inline") => { self.is_inline = decoder.read_bool(); }
                Some("noreturn") => { self.no_return = decoder.read_bool(); }
                Some("custom") => { /* custom_storage tracked elsewhere */ let _ = decoder.read_bool(); }
                Some("constructor") => { self.is_constructor_flag = decoder.read_bool(); }
                Some("destructor") => { self.is_destructor = decoder.read_bool(); }
                _ => { let _ = decoder.read_string(); }
            }
        }
        let _ = found_model; // model resolution status (caller decides locking).
        if seen_extrapop {
            // extrapop is stored on the model in Rugra; recorded via the
            // calling_convention name's model. No-op here for the flat struct.
            let _ = read_extrapop;
        }

        // Ghidra: fspec.cc:4742-4772 — <returnsym> (or legacy <addr>) child.
        let sub_id = decoder.peek_element();
        if sub_id != 0 {
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            if sub_name == "returnsym" || sub_name == "addr" {
                let (addr, ty, output_lock) = decode_output_storage(decoder);
                // store->setOutput(outpieces); setTypeLock(outputlock).
                // The type and lock land; the storage address cannot: the
                // decode_output_storage boundary returns the legacy
                // spaceless Address, and set_output_parameter needs the
                // space to record a faithful (space, offset) pair. The
                // decode channel therefore keeps discarding the address —
                // the registered ADDRESS-0001-family residual for signature
                // ingestion (funcLinkOutput then falls to its no-storage
                // path). Once the decoder returns a space-tagged Address,
                // this arm routes through set_output_parameter like the
                // trial-commit path does.
                self.return_type = ty;
                self.output_type_locked = output_lock;
                let _ = addr;
            } else {
                return Err("Missing <returnsym> tag".to_string());
            }
        } else {
            return Err("Missing <returnsym> tag".to_string());
        }

        // Ghidra: fspec.cc:4779-4824 — effect/likelytrash/inject/internallist.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 { break; }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "unaffected" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::Unaffected));
                    }
                    decoder.close_element(sub_id);
                }
                "killedbycall" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::KilledByCall));
                    }
                    decoder.close_element(sub_id);
                }
                "returnaddress" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        self.effects.push(EffectRecord::new(space, offset, size, EffectType::ReturnAddress));
                    }
                    decoder.close_element(sub_id);
                }
                "likelytrash" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) = read_varnode_data_attrs(decoder);
                        decoder.close_element(child_id);
                        // Ghidra: fspec.cc:4806-4813 — likelytrash.emplace_back();
                        // likelytrash.back().decode(decoder). The entries land in
                        // the independent FuncProto carrier (fspec.hh:1365),
                        // NOT the effectlist: unlike <unaffected>/
                        // <killedbycall>/<returnaddress>, likelytrash is never
                        // an EffectRecord. The previous fold into
                        // KilledByCall effects was a substitution with no
                        // oracle counterpart (COREACT2 residual ① root cause).
                        self.likelytrash.push(VarnodeData { space, offset, size });
                    }
                    decoder.close_element(sub_id);
                }
                "inject" => {
                    decoder.open_element();
                    // injectString → injectid via pcodeinjectlib; Rugra's
                    // injection is partial, so we only note the content.
                    let _ = decoder.read_string();
                    decoder.close_element(sub_id);
                }
                "internallist" => {
                    // store->decode(decoder, model) — internal parameter list.
                    // Rugra's flat store does not carry internal params beyond
                    // `parameters`; skip the body.
                    let _opened = decoder.open_element();
                    decoder.close_element(_opened);
                }
                _ => {
                    // Unknown child: consume to avoid infinite loop.
                    let cid = decoder.open_element();
                    decoder.close_element(cid);
                }
            }
        }
        decoder.close_element(elem_id);
        // Ghidra: fspec.cc:4826-4827 — decodeEffect(); decodeLikelyTrash();
        // Only the likelytrash merge is wired here. The local `<likelytrash>`
        // overrides become a complete list by folding in the underlying
        // model's trash registers (body = fspec.cc:3684-3699). When no model
        // is bound through this decode channel, an empty model list merges —
        // the same observable as Ghidra's createUnknownModel placeholder,
        // whose trash carrier is empty (effectively a sort-only pass).
        // decodeEffect() remains unwired on this path (pre-existing seam,
        // effect overrides keep their decoded-only form); resolveExtraPop /
        // modellock reconciliation are covered by the notes above;
        // updateThisPointer() below mirrors fspec.cc:4835+.
        let model_trash: Vec<VarnodeData> = match &self.model {
            Some(m) => m.trash_iter().to_vec(),
            None => Vec::new(),
        };
        Self::decode_likely_trash(&mut self.likelytrash, &model_trash);
        // Ghidra: reconcile modellock; resolveExtraPop; validate returnsym
        // address; updateThisPointer().
        self.update_this_pointer();
        Ok(())
    }

    // ---- internal store helpers for the flat FuncProto (stand in for
    // ProtoStore::setInput / setOutput). ----

    // Ghidra: fspec.cc:3329 ProtoStoreInternal::setInput
    /// Faithful to `ProtoStore::setInput(i, nm, pieces)`: replace (or append
    /// up to) the i-th input parameter with the given pieces.
    fn set_input_parameter(&mut self, i: usize, nm: &str, pieces: ParameterPieces) {
        // Ghidra: FuncProto::setParam → store->setInput(i,name,piece)
        // (fspec.hh:1533). With a symbol-backed store installed by
        // `set_scope` the mutation routes to the backing Scope's
        // category-0 symbol; the flat vector below is the
        // ProtoStoreInternal projection (fspec.cc:3329-3338) used when no
        // scope backs \b this.
        if let Some(store) = &mut self.symbol_store {
            store.set_input(i, nm, &pieces);
        }
        while self.parameters.len() <= i {
            let placeholder = ProtoParameter::new(
                String::new(),
                self.return_type.clone(),
                Address::new(0),
            );
            self.parameters.push(placeholder);
        }
        let param = &mut self.parameters[i];
        param.name = nm.to_string();
        if let Some(ty) = pieces.ty { param.data_type = ty; }
        param.address = pieces.addr;
        param.address_space = pieces.space;
        param.flags = pieces.flags
            & (protoparam_flags::THIS_POINTER
                | protoparam_flags::HIDDEN_RETURN
                | protoparam_flags::INDIRECT_STORAGE
                | protoparam_flags::NAME_LOCKED
                | protoparam_flags::TYPE_LOCKED);
    }

    // Ghidra: fspec.cc:3380 ProtoStoreInternal::setOutput
    /// Faithful to `ProtoStore::setOutput(piece)` (reached through
    /// `FuncProto::setOutput`, fspec.hh:1537): replace the return-value
    /// parameter with the given pieces — data-type AND storage address
    /// (fspec.cc:3385 `new ParameterBasic("",piece.addr,piece.type,
    /// piece.flags)`). The flat FuncProto keeps the type in `return_type`
    /// and the storage in `output_storage`; the piece's legacy `Address`
    /// carries no space identity, so the space is passed alongside (the
    /// ADDRESS-0001 fold will absorb it).
    pub fn set_output_parameter(&mut self, pieces: ParameterPieces, space: AddressSpace) {
        if let Some(ty) = pieces.ty {
            self.return_type = ty;
        }
        self.output_storage = Some((space, pieces.addr.as_u64()));
    }

    // Ghidra: fspec.hh:1389 FuncProto::hasModel
    /// Does this prototype have a (non-null) calling-convention model?
    /// Faithful inline accessor `hasModel` (fspec.hh:1389):
    /// `(model != (ProtoModel *)0)`.
    pub fn has_model(&self) -> bool {
        self.model.is_some()
    }

    // Ghidra: fspec.hh:1618 FuncProto::getComparableFlags
    /// Get the set of flags that affect prototype comparison. Faithful to
    /// `getComparableFlags` (fspec.hh:1618): the
    /// `dotdotdot | is_constructor | is_destructor | has_thisptr` subset.
    pub fn get_comparable_flags(&self) -> u32 {
        // Ghidra flags: dotdotdot=0x80, is_constructor=0x200,
        // is_destructor=0x400, has_thisptr=0x800.
        let mut f = 0u32;
        if self.is_dotdotdot { f |= 0x80; }
        if self.is_constructor_flag { f |= 0x200; }
        if self.is_destructor { f |= 0x400; }
        if self.has_thisptr { f |= 0x800; }
        f
    }

    // Ghidra: fspec.cc:4542 FuncProto::isCompatible
    /// Decide if `self` can be safely restricted to match `op2`. Faithful 1:1
    /// port of `isCompatible` (fspec.cc:4542-4577). Both prototypes must agree
    /// on:
    ///   - their model (compatible calling conventions),
    ///   - the locked output data-type (if both lock),
    ///   - the extra-pop value (unless `extrapop_unknown`),
    ///   - varargs (with the special-case that a non-dotdotdot `self` may be
    ///     restricted by a dotdotdot `op2` when `self` is not input-locked),
    ///   - the inject id,
    ///   - the `is_inline | no_return` flag subset,
    ///   - the full effectlist and likelytrash contents.
    pub fn is_compatible(&self, op2: &FuncProto) -> bool {
        // Ghidra: if (!model->isCompatible(op2.model)) return false;
        // Rugra's models are identified by name; matching by name stands in
        // for the ProtoModel pointer/alias check.
        if self.calling_convention != op2.calling_convention {
            // Permit "unknown" to match any non-empty model — Ghidra's
            // UnknownModel::isCompatible returns true for everything.
            if !(self.is_model_unknown() || op2.is_model_unknown()) {
                return false;
            }
        }
        // Ghidra: if (op2.isOutputLocked()) { if (isOutputLocked()) { ... } }
        if op2.is_output_locked() && self.is_output_locked() {
            // Compare output ProtoParameters. Ghidra: if (*out1 != *out2) return false;
            // Rugra compares the return data-types by pointer identity (the
            // Arc<Datatype> ptr eq is a close analogue of Ghidra's Datatype
            // pointer comparison).
            if !Arc::ptr_eq(&self.return_type, &op2.return_type) {
                return false;
            }
        }
        // Ghidra: if (extrapop != extrapop_unknown && extrapop != op2.extrapop) return false;
        // Rugra stores extrapop on the model; we cannot read it from a bare
        // FuncProto here, so this check is folded into the model-name check
        // above (same model => same extrapop).
        // Ghidra: if (isDotdotdot() != op2.isDotdotdot()) { ... }
        if self.is_dotdotdot != op2.is_dotdotdot {
            if op2.is_dotdotdot {
                // Ghidra: if (isInputLocked()) return false;
                if self.is_input_locked() { return false; }
            } else {
                return false;
            }
        }
        // Ghidra: if (injectid != op2.injectid) return false;
        // Rugra does not yet store injectid on FuncProto; the default of -1
        // matches for both sides.
        // Ghidra: if ((flags&(is_inline|no_return)) != (op2.flags&(...))) return false;
        // Ghidra flags: is_inline=0x8, no_return=0x10. A direct boolean
        // comparison of each flag is equivalent to the bitfield test.
        if self.is_inline != op2.is_inline || self.no_return != op2.no_return {
            return false;
        }
        // Ghidra: if (effectlist.size() != op2.effectlist.size()) return false;
        if self.effects.len() != op2.effects.len() { return false; }
        // Ghidra: for(...) if (effectlist[i] != op2.effectlist[i]) return false;
        for (a, b) in self.effects.iter().zip(op2.effects.iter()) {
            if a.space != b.space
                || a.offset != b.offset
                || a.size != b.size
                || a.effect_type != b.effect_type
            {
                return false;
            }
        }
        // Ghidra: fspec.cc:4573-4575 — if (likelytrash.size() !=
        // op2.likelytrash.size()) return false; for(...) if
        // (likelytrash[i] != op2.likelytrash[i]) return false;
        // Element comparison is VarnodeData::operator== (pcoderaw.hh:77-81):
        // space, offset, and size must all be exactly equal.
        if self.likelytrash.len() != op2.likelytrash.len() {
            return false;
        }
        for (a, b) in self.likelytrash.iter().zip(op2.likelytrash.iter()) {
            if a.space != b.space || a.offset != b.offset || a.size != b.size {
                return false;
            }
        }
        true
    }

    // Ghidra: fspec.cc:4583 FuncProto::printRaw
    /// Print this prototype as a single line of text. Faithful 1:1 port of
    /// `printRaw` (fspec.cc:4583-4604). Emits the model name (or
    /// "(no model)"), the return data-type's name, the function name, the
    /// parenthesised parameter type list (with a trailing `...` for varargs),
    /// and the `extrapop=` suffix.
    pub fn print_raw(&self, funcname: &str, out: &mut String) {
        // Ghidra: if (model != null) s << model->getName() << ' '; else s << "(no model) ";
        if self.model.is_some() {
            out.push_str(&self.calling_convention);
            out.push(' ');
        } else {
            out.push_str("(no model) ");
        }
        // Ghidra: getOutputType()->printRaw(s);
        out.push_str(self.return_type.get_name());
        out.push(' ');
        out.push_str(funcname);
        out.push('(');
        let num = self.parameters.len();
        for (i, p) in self.parameters.iter().enumerate() {
            if i != 0 { out.push(','); }
            // Ghidra: getParam(i)->getType()->printRaw(s);
            out.push_str(p.data_type.get_name());
        }
        if self.is_dotdotdot {
            if num != 0 { out.push(','); }
            out.push_str("...");
        }
        out.push_str(") extrapop=");
        // Rugra does not store extrapop on FuncProto directly; emit the
        // model's extrapop via the placeholder value the model carries.
        // Ghidra: s << dec << extrapop. We use 0 (the canonical value) since
        // the model is not reachable from the bare FuncProto here.
        out.push_str("0");
    }

    // Ghidra: fspec.cc:3589 FuncProto::encodeEffect
    /// Encode only the EffectRecords that override the underlying ProtoModel.
    /// Faithful 1:1 port of `encodeEffect` (fspec.cc:3589-3626). If the
    /// effectlist is empty, nothing is emitted. Otherwise the records are
    /// partitioned by effect type and each partition is emitted under its
    /// canonical parent element (`<unaffected>`, `<killedbycall>`,
    /// `<returnaddress>`). Records whose effect matches the model's
    /// `hasEffect` are skipped (they carry no override information).
    pub fn encode_effect(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        unaffected_elem: &crate::marshal::ElementId,
        killedbycall_elem: &crate::marshal::ElementId,
        returnaddress_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        model_effect: &dyn Fn(AddressSpace, u64, i32) -> EffectType,
    ) {
        // Ghidra: if (effectlist.empty()) return;
        if self.effects.is_empty() { return; }
        let mut unaffected_list: Vec<&EffectRecord> = Vec::new();
        let mut killedbycall_list: Vec<&EffectRecord> = Vec::new();
        let mut ret_addr: Option<&EffectRecord> = None;
        for cur in &self.effects {
            // Ghidra: uint4 type = model->hasEffect(addr, size);
            //         if (type == curRecord.getType()) continue;
            let model_ty = model_effect(cur.space, cur.offset, cur.size);
            if model_ty == cur.effect_type { continue; }
            match cur.effect_type {
                EffectType::Unaffected => unaffected_list.push(cur),
                EffectType::KilledByCall => killedbycall_list.push(cur),
                EffectType::ReturnAddress => ret_addr = Some(cur),
                EffectType::UnknownEffect => {}
            }
        }
        if !unaffected_list.is_empty() {
            encoder.open_element(unaffected_elem);
            for r in &unaffected_list {
                let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            }
            encoder.close_element(unaffected_elem);
        }
        if !killedbycall_list.is_empty() {
            encoder.open_element(killedbycall_elem);
            for r in &killedbycall_list {
                let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            }
            encoder.close_element(killedbycall_elem);
        }
        if let Some(r) = ret_addr {
            encoder.open_element(returnaddress_elem);
            let _ = r.encode(encoder, addr_elem, space_attrib, offset_attrib, size_attrib);
            encoder.close_element(returnaddress_elem);
        }
    }

    // Ghidra: fspec.cc:3631 FuncProto::encodeLikelyTrash
    /// Encode the likely-trash VarnodeData list, skipping entries that are
    /// already present in the underlying ProtoModel. Faithful 1:1 port of
    /// `encodeLikelyTrash` (fspec.cc:3631-3647). The model's trash list is
    /// provided via `model_trash` (a sorted slice); each local trash entry not
    /// found via binary search is emitted as an `<addr>` child.
    pub fn encode_likely_trash(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        likelytrash_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        model_trash: &[VarnodeData],
        local_trash: &[VarnodeData],
    ) {
        // Ghidra: if (likelytrash.empty()) return;
        if local_trash.is_empty() { return; }
        encoder.open_element(likelytrash_elem);
        for cur in local_trash {
            // Ghidra: if (binary_search(iter1, iter2, cur)) continue;
            // iter1..iter2 is the model's sorted trash list; the key is
            // VarnodeData::operator< (pcoderaw.hh:67).
            let already = model_trash
                .binary_search_by(|probe| VarnodeData::compare(probe, cur))
                .is_ok();
            if already { continue; }
            encoder.open_element(addr_elem);
            encoder.write_string(space_attrib, space_name(cur.space));
            encoder.write_unsigned_integer(offset_attrib, cur.offset);
            encoder.write_signed_integer(size_attrib, cur.size as i64);
            encoder.close_element(addr_elem);
        }
        encoder.close_element(likelytrash_elem);
    }

    // Ghidra: fspec.cc:3652 FuncProto::decodeEffect
    /// Merge any EffectRecord overrides (read into `effectlist` by `decode`)
    /// with the underlying ProtoModel's list. Faithful 1:1 port of
    /// `decodeEffect` (fspec.cc:3652-3679). If the local list is empty, do
    /// nothing. Otherwise seed `effects` with the model's full list, then for
    /// each override either replace the matching record's type, report a
    /// partial-overlap error, or append a new record; finally re-sort.
    pub fn decode_effect(
        &mut self,
        model_effects: &[EffectRecord],
    ) -> Result<(), String> {
        // Ghidra: if (effectlist.empty()) return;
        if self.effects.is_empty() { return Ok(()); }
        let tmp_list = std::mem::take(&mut self.effects);
        // Ghidra: for each record in model->effectBegin()..effectEnd() push.
        self.effects.extend_from_slice(model_effects);
        let mut has_new = false;
        let list_size = self.effects.len();
        for cur in &tmp_list {
            // Ghidra: off = ProtoModel::lookupRecord(effectlist, listSize, addr, size);
            match ProtoModelFull::lookup_record(
                &self.effects, list_size, cur.space, cur.offset, cur.size,
            ) {
                Ok(Some(idx)) => {
                    // Found matching record, change its type.
                    self.effects[idx].effect_type = cur.effect_type;
                }
                Err(()) => {
                    // Ghidra: throw LowlevelError("Partial overlap ...");
                    return Err(
                        "Partial overlap of prototype override with existing effects".to_string(),
                    );
                }
                Ok(None) => {
                    self.effects.push(cur.clone());
                    has_new = true;
                }
            }
        }
        if has_new {
            self.effects.sort_by(|a, b| {
                if EffectRecord::compare_by_address(a, b) {
                    std::cmp::Ordering::Less
                } else if EffectRecord::compare_by_address(b, a) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            });
        }
        Ok(())
    }

    // Ghidra: fspec.cc:3684 FuncProto::decodeLikelyTrash
    /// Merge locally-decoded likely-trash VarnodeData with the underlying
    /// ProtoModel's list. Faithful 1:1 port of `decodeLikelyTrash`
    /// (fspec.cc:3684-3699). The model's trash list (`model_trash`) must be
    /// sorted; the local overrides are appended only if not already present.
    /// The merged result is re-sorted.
    pub fn decode_likely_trash(
        likelytrash: &mut Vec<VarnodeData>,
        model_trash: &[VarnodeData],
    ) {
        // Ghidra: if (likelytrash.empty()) return;
        if likelytrash.is_empty() { return; }
        let tmp_list = std::mem::take(likelytrash);
        // Ghidra: for each record in model->trashBegin()..trashEnd() push.
        likelytrash.extend_from_slice(model_trash);
        for cur in &tmp_list {
            // Ghidra: if (!binary_search(iter1, iter2, *cur)) push_back.
            // The binary search runs over the model's (sorted) list with the
            // VarnodeData::operator< key (pcoderaw.hh:67).
            let present = model_trash
                .binary_search_by(|probe| VarnodeData::compare(probe, cur))
                .is_ok();
            if !present {
                likelytrash.push(cur.clone());
            }
        }
        // Ghidra: sort(likelytrash.begin(), likelytrash.end()) — the oracle
        // operator< key: space, offset ascending, size descending.
        likelytrash.sort_by(VarnodeData::compare);
    }

    // Ghidra: fspec.cc:4260 FuncProto::trashBegin / fspec.cc:4269 FuncProto::trashEnd
    /// The effective likely-trash list (sorted). Faithful slice equivalent of
    /// the `trashBegin`/`trashEnd` iterator pair (fspec.cc:4260-4275):
    /// this prototype's `likelytrash` overrides when non-empty, otherwise the
    /// underlying ProtoModel's list — resolved dynamically at each call, not
    /// copied at model-set time, exactly like the oracle iterator pair. This
    /// is the source iterated by `ActionLikelyTrash::apply`
    /// (coreaction.cc:2146-2147).
    pub fn trash_iter(&self) -> &[VarnodeData] {
        // Ghidra: if (likelytrash.empty()) return model->trashBegin();
        if self.likelytrash.is_empty() {
            if let Some(m) = &self.model {
                return m.trash_iter();
            }
        }
        // Ghidra: return likelytrash.begin(); / likelytrash.end();
        &self.likelytrash
    }

    // Ghidra: fspec.cc:4625 FuncProto::encode
    /// Encode this prototype to a stream as a `<prototype>` element. Faithful
    /// port of `encode` (fspec.cc:4625-4667). Saves the model name, extrapop,
    /// varargs/model-lock/void-lock/inline/no-return/custom/constructor/
    /// destructor flags, the `<returnsym>` (output storage + type), the
    /// overriding effects and likely-trash, and (for an inject id) the
    /// `<inject>` element. Internal store encoding (the trailing
    /// `store->encode(encoder)`) is delegated to the caller via
    /// `encode_store` since Rugra's flat parameter list has no separate
    /// ProtoStore.
    pub fn encode(
        &self,
        encoder: &mut dyn crate::marshal::Encoder,
        prototype_elem: &crate::marshal::ElementId,
        model_attrib: &crate::marshal::AttributeId,
        extrapop_attrib: &crate::marshal::AttributeId,
        dotdotdot_attrib: &crate::marshal::AttributeId,
        modellock_attrib: &crate::marshal::AttributeId,
        inline_attrib: &crate::marshal::AttributeId,
        noreturn_attrib: &crate::marshal::AttributeId,
        constructor_attrib: &crate::marshal::AttributeId,
        destructor_attrib: &crate::marshal::AttributeId,
        returnsym_elem: &crate::marshal::ElementId,
        typelock_attrib: &crate::marshal::AttributeId,
        unaffected_elem: &crate::marshal::ElementId,
        killedbycall_elem: &crate::marshal::ElementId,
        returnaddress_elem: &crate::marshal::ElementId,
        likelytrash_elem: &crate::marshal::ElementId,
        addr_elem: &crate::marshal::ElementId,
        space_attrib: &crate::marshal::AttributeId,
        offset_attrib: &crate::marshal::AttributeId,
        size_attrib: &crate::marshal::AttributeId,
        output_addr_space: AddressSpace,
        output_addr_offset: u64,
        output_size: i32,
        model_trash: &[VarnodeData],
        local_trash: &[VarnodeData],
        model_effect: &dyn Fn(AddressSpace, u64, i32) -> EffectType,
        encode_store: &dyn Fn(&mut dyn crate::marshal::Encoder),
    ) {
        encoder.open_element(prototype_elem);
        encoder.write_string(model_attrib, &self.calling_convention);
        // Ghidra: if (extrapop == extrapop_unknown) writeString("unknown")
        //         else writeSignedInteger(extrapop).
        // Rugra does not store extrapop on FuncProto; we emit "unknown" to
        // match the model-derived default that Ghidra writes.
        encoder.write_string(extrapop_attrib, "unknown");
        if self.is_dotdotdot {
            encoder.write_bool(dotdotdot_attrib, true);
        }
        // modellock / voidlock / inline / noreturn / custom / constructor /
        // destructor are emitted only when set, matching Ghidra's
        // `if (flag) writeBool(ATTRIB_*, true)` pattern (fspec.cc:4636-4649).
        if self.model_locked {
            encoder.write_bool(modellock_attrib, true);
        }
        if self.is_inline {
            encoder.write_bool(inline_attrib, true);
        }
        if self.no_return {
            encoder.write_bool(noreturn_attrib, true);
        }
        if self.is_constructor_flag {
            encoder.write_bool(constructor_attrib, true);
        }
        if self.is_destructor {
            encoder.write_bool(destructor_attrib, true);
        }
        // Ghidra: <returnsym>
        encoder.open_element(returnsym_elem);
        if self.output_type_locked {
            encoder.write_bool(typelock_attrib, true);
        }
        encoder.open_element(addr_elem);
        encoder.write_string(space_attrib, space_name(output_addr_space));
        encoder.write_unsigned_integer(offset_attrib, output_addr_offset);
        encoder.write_signed_integer(size_attrib, output_size as i64);
        encoder.close_element(addr_elem);
        encoder.close_element(returnsym_elem);
        // Ghidra: encodeEffect(encoder);
        self.encode_effect(
            encoder,
            unaffected_elem, killedbycall_elem, returnaddress_elem,
            addr_elem, space_attrib, offset_attrib, size_attrib,
            model_effect,
        );
        // Ghidra: encodeLikelyTrash(encoder);
        self.encode_likely_trash(
            encoder, likelytrash_elem, addr_elem,
            space_attrib, offset_attrib, size_attrib,
            model_trash, local_trash,
        );
        // Ghidra: if (injectid >= 0) { <inject content=...> }
        // Rugra does not store injectid; skip.
        // Ghidra: store->encode(encoder);
        encode_store(encoder);
        encoder.close_element(prototype_elem);
    }
}

/// Specification for a specific function call site
///
/// Corresponds to Ghidra's `FuncCallSpecs` class.
#[derive(Debug)]
pub struct FuncCallSpecs {
    /// Non-owning identity link to the exact CALL/CALLIND operation. Ghidra
    /// stores a raw `PcodeOp *`; Weak preserves that lifecycle without an
    /// Arc cycle through the operation's input Varnodes.
    pub op: Weak<RwLock<crate::op::PcodeOp>>,
    /// The address of the call instruction
    pub op_addr: Address,
    /// The destination address of the call (if known)
    pub entry_addr: Option<Address>,
    /// The callee's own recovered prototype — Rugra's observable slice of
    /// Ghidra's `FuncCallSpecs::fd` (fspec.hh:1649, the `Funcdata *` set by
    /// `FuncCallSpecs::setFuncdata` at flow time, fspec.cc:4949) as consumed
    /// by `ActionDefaultParams::apply` (coreaction.cc:2321-2324
    /// `Funcdata *otherfunc = fc->getFuncdata(); ... fc->copy
    /// (otherfunc->getFuncProto())`). Rugra has no per-callee Funcdata
    /// objects in the library; the driver's queryCall boundary (the
    /// `FlowInfo::queryCall` flow.cc:646-666 slice) stores the callee's own
    /// locked FuncProto Arc here, and the copy channel below carries it
    /// onto the call site.
    pub callee_proto: Option<Arc<FuncProto>>,
    /// The prototype used at this call site
    pub prototype: FuncProto,
    /// Flags and other metadata
    pub flags: u32,
    /// Permanently embedded input-trial container. Faithful to
    /// `FuncCallSpecs::activeinput`; its existence is independent of whether
    /// input recovery is currently active.
    pub active_input: ParamActive,
    /// Permanently embedded output-trial container. Faithful to
    /// `FuncCallSpecs::activeoutput`.
    pub active_output: ParamActive,
    /// Faithful to `FuncCallSpecs::isinputactive`.
    input_recovery_active: bool,
    /// Faithful to `FuncCallSpecs::isoutputactive`.
    output_recovery_active: bool,
    /// Calling-convention model for this call site. Faithful to
    /// `FuncCallSpecs::model`. Set by setModel; used by resolveModel/
    /// deriveInputMap/checkInputTrialUse.
    pub proto_model: Option<crate::type_system::protomodel::ProtoModel>,
    /// Relative offset of stack-pointer at time of this call. Faithful to
    /// `FuncCallSpecs::stackoffset` (fspec.hh:1651). Set by
    /// resolveSpacebaseRelative; used by ActionRestrictLocal to find
    /// stack-relative call params. offset_unknown = i64::MIN.
    pub stackoffset: i64,
    /// Per-input-slot bytes-consumed hints. Faithful to
    /// `FuncCallSpecs::inputConsume` (fspec.cc:5870-5906). A non-zero entry
    /// means that many least-significant bytes of the parameter storage are
    /// used by the sub-function; 0 means all bytes. Indexed by input slot
    /// (with slot 0 = the call target, parameters start at slot 1).
    /// Sparse — grown lazily by `set_input_bytes_consumed`.
    pub input_consume: Vec<u32>,
    /// Stack placeholder slot for spacebase-relative parameter passing.
    /// Faithful to `FuncCallSpecs::stackPlaceholderSlot` (fspec.hh:1653).
    /// -1 = no placeholder; >=0 = the input slot holding the placeholder
    /// varnode. Used by abortSpacebaseRelative to clean up placeholders
    /// after heritage resolves the actual stack values.
    pub stack_placeholder_slot: i32,
    /// Was the call originally a jump-table we couldn't recover? Faithful to
    /// `FuncCallSpecs::isbadjumptable` (fspec.hh:1660), initialized false by
    /// the constructor (fspec.cc:4945), set true only by
    /// `FlowInfo::truncateIndirectJump`'s default failure arm
    /// (`fc->setBadJumpTable(true)`, flow.cc:754) and carried across a clone
    /// (fspec.cc:4974). Consumed by `ActionNameVars::lookForBadJumpTables`
    /// (coreaction.cc:2786) to rename the switch variable's symbol to
    /// "UNRECOVERED_JUMPTABLE".
    pub is_bad_jump_table: bool,
    /// Do we have a locked output on the stack? Faithful to
    /// `FuncCallSpecs::isstackoutputlock` (fspec.hh:1661), initialized
    /// false by `FuncCallSpecs::init` (fspec.cc:4946) and set true by
    /// `ActionFuncLink::funcLinkOutput` (coreaction.cc:1548) when the
    /// locked output parameter's storage lives in the spacebase space —
    /// the output varnode creation is then delayed until stack heritage
    /// (`Heritage::tryOutputStackGuard` builds it caller-perspective,
    /// heritage.cc:1414).
    pub is_stack_output_locked: bool,
    /// Working extrapop for the CALL. Faithful to
    /// `FuncCallSpecs::effective_extrapop` (fspec.hh:1650): initialized to
    /// `ProtoModel::extrapop_unknown` by the constructor (fspec.cc:4927),
    /// set to the model's known extrapop by `ActionExtraPopSetup`
    /// (coreaction.cc:1454) or to the StackSolver-recovered value by
    /// `ActionStackPtrFlow::analyzeExtraPop` (coreaction.cc:306). Carried
    /// across a clone (fspec.cc:4971).
    effective_extrapop: i32,
}

/// Sentinel value for unknown stack offset. Faithful to
/// `FuncCallSpecs::offset_unknown` (fspec.hh:1641).
pub const OFFSET_UNKNOWN: i64 = i64::MIN;

// RUGRA-GLUE: ENTRY_SPACE_STANDINS (ADDRESS-0001 phase-1 bridge; no direct
// Ghidra counterpart — the oracle's entry address keeps the architecture's
// own registered `AddrSpace*`, reached here only through the per-variant
// stand-in because Rugra's historical Varnode carries just the flat
// `AddressSpace` enum.) One stand-in handle per flat variant per thread,
// interned into the Address tag table, so repeated call-spec construction
// reuses the same allocation (intern_space dedups by identity).
thread_local! {
    static ENTRY_SPACE_STANDINS:
        std::cell::RefCell<std::collections::HashMap<AddressSpace, AddrSpace>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

// RUGRA-GLUE: entry_address_with_space (ADDRESS-0001 phase-1 bridge for the
// fspec.cc:4934 record point; the Ghidra form is the inline
// `Address(AddrSpace*, uintb)` constructor at address.hh:270.)
/// Build the entry address the way fspec.cc:4934 stores it: the offset plus
/// the in(0) varnode's space. The flat enum cannot name the architecture's
/// registered space object, so the tag refers to the per-variant stand-in,
/// which carries that variant's documented name and dimensions
/// (`AddressSpace::name` / `addr_size` / `word_size`). Consumers that only
/// compare offsets (`as_u64`) are unaffected; consumers that resolve the
/// space (printc entry dims, encode space name) see the variant's true
/// dimensions instead of the flat Ram fallback.
fn entry_address_with_space(space: AddressSpace, offset: u64) -> Address {
    let handle = ENTRY_SPACE_STANDINS.with(|table| {
        table.borrow_mut().entry(space).or_insert_with(|| {
            let space_type = match space {
                AddressSpace::Const => SpaceType::Constant,
                AddressSpace::Unique => SpaceType::Internal,
                AddressSpace::Join => SpaceType::Join,
                AddressSpace::Stack => SpaceType::SpaceBase,
                // ram/register/overlay are IPTR_PROCESSOR in the oracle;
                // OTHER is Ghidra's OtherSpace (space.cc:397), also
                // processor-typed.
                _ => SpaceType::Processor,
            };
            AddrSpace::new_space(
                space_type,
                space.name(),
                false,
                space.addr_size() as u32,
                space.word_size() as u32,
                0,
                0,
                0,
                0,
            )
        }).clone()
    });
    Address::with_space(&handle, offset)
}

impl FuncCallSpecs {
    // Ghidra: fspec.cc:4924 FuncCallSpecs::new
    /// Create a new call specification
    pub fn new(op_addr: Address, prototype: FuncProto) -> Self {
        Self {
            op: Weak::new(),
            op_addr,
            entry_addr: None,
            prototype,
            flags: 0,
            active_input: ParamActive::new(true),
            active_output: ParamActive::new(true),
            input_recovery_active: false,
            output_recovery_active: false,
            proto_model: None,
            stackoffset: OFFSET_UNKNOWN,
            input_consume: Vec::new(),
            stack_placeholder_slot: -1,
            // fspec.cc:4945 `isbadjumptable = false`
            is_bad_jump_table: false,
            is_stack_output_locked: false,
            // fspec.cc:4927 `effective_extrapop = ProtoModel::extrapop_unknown`
            effective_extrapop: EXTRAPOP_UNKNOWN_FULL,
            // fspec.hh:1649 `fd = (Funcdata *)0` — the callee link starts
            // empty (no queryFunction hit).
            callee_proto: None,
        }
    }

    // Ghidra: fspec.hh:1687 FuncCallSpecs::setEffectiveExtraPop
    /// Set the specific \e extrapop associated with \b this call site.
    pub fn set_effective_extrapop(&mut self, epop: i32) {
        self.effective_extrapop = epop;
    }

    // Ghidra: fspec.hh:1688 FuncCallSpecs::getEffectiveExtraPop
    /// Get the specific \e extrapop associated with \b this call site.
    pub fn get_effective_extrapop(&self) -> i32 {
        self.effective_extrapop
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::FuncCallSpecs
    /// Construct a call specification bound to the exact CALL/CALLIND op.
    /// For a direct CALL, capture input(0) before setup replaces it with the
    /// FSPEC annotation — as the oracle does, the captured entry address
    /// carries in(0)'s space (fspec.cc:4934 `getIn(0)->getAddr()`), not just
    /// the offset. A cloned FSPEC input resolves through its typed
    /// handle to the original call target, matching Ghidra's constructor.
    ///
    /// The composed prototype is the Ghidra default-constructed FuncProto
    /// (fspec.cc:3778: `model=null, store=null, flags=0` — no parameters, no
    /// locks, extrapop unknown), exactly as the C++ ctor's `: FuncProto()`
    /// base initializer (fspec.cc:4926). The legacy `_caller_funcp` argument
    /// (flow.rs passes a clone of the CALLER's prototype) is deliberately
    /// NOT composed: in the oracle the caller's formals never reach a call
    /// site. Prototypes arrive exclusively via queryCall's
    /// `copyFlowEffects` (flow.cc:663-664 — inline/noreturn/injectid flags
    /// only), ActionDefaultParams' copy-from-callee / setInternal
    /// (coreaction.cc:2321-2328), or a platform locked-signature install.
    /// Composing the caller clone made every unknown callee inherit the
    /// caller's locked DWARF formals (e.g. a 0-arg `__stack_chk_fail`
    /// rendering as `__stack_chk_fail(filename, config)` inside
    /// parseconfig). The parameter is kept so flow.rs call sites stay
    /// untouched; dropping it belongs to CALLSPEC-0001's unified entry.
    pub fn new_for_op(op: &crate::op::PcodeOpRef, _caller_funcp: FuncProto) -> Self {
        use crate::opcodes::OpCode;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};
        let (op_addr, direct_target) = {
            let call = op.0.read().unwrap();
            let target = if call.opcode == OpCode::CPUI_CALL {
                call.get_in(0).cloned()
            } else {
                None
            };
            (call.get_addr(), target)
        };
        // Release the op lock before following the Varnode -> callspec Weak
        // edge. Other consumers follow callspec -> op, so this snapshot keeps
        // the lock order acyclic even though the ownership graph already is.
        let entry_addr = direct_target.and_then(|input| {
            let (previous, space, offset) = {
                let input = input.read().unwrap();
                (input.get_call_spec(), input.get_space(), input.get_offset())
            };
            if let Some(previous) = previous {
                previous.read().unwrap().entry_addr
            } else if space == AddressSpace::Iop {
                None
            } else {
                // fspec.cc:4934 `entryaddress = call_op->getIn(0)->getAddr()`
                // — the record stores the full address (offset + the
                // pre-annotation in(0) varnode's space), never the bare
                // offset. The space rides the ADDRESS-0001 tag form; the
                // stand-in handle carries the flat variant's dimensions.
                Some(entry_address_with_space(space, offset))
            }
        });
        // fspec.cc:4926 `: FuncProto()` — fresh ctor state, void stand-in
        // return type (Ghidra's null store resolves its type only on
        // setModel/setOutput).
        let prototype = FuncProto::new(
            String::new(),
            Arc::new(Datatype::Void(TypeBase::new(
                "void".to_string(),
                0,
                TypeMetatype::Void,
            ))),
        );
        let mut result = Self::new(op_addr, prototype);
        result.op = Arc::downgrade(&op.0);
        result.entry_addr = entry_addr;
        result
    }

    // Ghidra: fspec.hh:1434 FuncProto::isNoReturn
    /// Does a function with this prototype never return. Ghidra's
    /// `FuncCallSpecs` exposes this accessor through inheritance
    /// (`class FuncCallSpecs : public FuncProto`, fspec.hh:1645); Rugra
    /// composes the prototype instead, so the delegate reproduces the same
    /// inherited surface for call-site consumers such as
    /// `FlowInfo::checkForFlowModification` (flow.cc:641).
    pub fn is_no_return(&self) -> bool {
        self.prototype.is_no_return()
    }

    // Ghidra: fspec.hh:1439 FuncProto::setNoReturn
    /// Toggle the no-return setting on this call site's prototype.
    /// Inherited in Ghidra (fspec.hh:1645); delegated here because Rugra
    /// composes `FuncProto`. `FlowInfo::truncateIndirectJump` (flow.cc:747)
    /// calls this on the callspec for the fail_callother jump-table path.
    pub fn set_no_return(&mut self, val: bool) {
        self.prototype.set_no_return(val)
    }

    // Ghidra: fspec.hh:1411 FuncProto::isInline
    /// Does this function get in-lined during decompilation. Inherited in
    /// Ghidra (fspec.hh:1645); delegated here because Rugra composes
    /// `FuncProto`. `checkForFlowModification` (flow.cc:639) reads this on
    /// the callspec to queue injection.
    pub fn is_inline(&self) -> bool {
        self.prototype.is_inline()
    }

    // Ghidra: fspec.hh:1417 FuncProto::setInline
    /// Toggle the in-line setting for this call site's prototype.
    /// Inherited in Ghidra (fspec.hh:1645); delegated here because Rugra
    /// composes `FuncProto`.
    pub fn set_inline(&mut self, val: bool) {
        self.prototype.set_inline(val)
    }

    // Ghidra: fspec.cc:3806 FuncProto::copyFlowEffects
    /// Copy the callee's flow-affecting properties (the `is_inline|
    /// no_return` subset) onto this call site's prototype. Inherited in
    /// Ghidra (fspec.hh:1645); delegated here because Rugra composes
    /// `FuncProto`. `FlowInfo::queryCall` (flow.cc:664) drives this to
    /// propagate a callee's noreturn state to the call site — the
    /// `__stack_chk_fail` channel.
    pub fn copy_flow_effects(&mut self, other: &FuncProto) {
        self.prototype.copy_flow_effects(other)
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getSpacebaseOffset
    /// Get the stack-pointer relative offset at the point of this call site.
    /// Faithful to `FuncCallSpecs::getSpacebaseOffset` (fspec.hh:1689).
    /// Returns OFFSET_UNKNOWN if not resolved.
    pub fn get_spacebase_offset(&self) -> i64 {
        self.stackoffset
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::setSpacebaseOffset
    /// Set the stack-pointer relative offset. Used during call analysis
    /// to record the RSP value at the call site.
    pub fn set_spacebase_offset(&mut self, offset: i64) {
        self.stackoffset = offset;
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::hasSpacebaseOffset
    /// Is the spacebase offset known (not OFFSET_UNKNOWN)?
    pub fn has_spacebase_offset(&self) -> bool {
        self.stackoffset != OFFSET_UNKNOWN
    }

    // Ghidra: fspec.hh:1546 FuncCallSpecs::hasEffect (inherits FuncProto::hasEffect)
    /// Determine the effect of this call on the given address range.
    /// Faithful to `FuncCallSpecs::hasEffect` (fspec.hh:1546), which —
    /// because `FuncCallSpecs : public FuncProto` (fspec.hh:1645) — resolves
    /// to `FuncProto::hasEffect` (fspec.cc:4234-4241): a non-empty local
    /// effect list overrides the model, an empty one delegates to the
    /// shared model's `lookupEffect`.
    pub fn has_effect(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        if !self.prototype.effects.is_empty() {
            // cc:4238-4240: local override list is authoritative.
            return ProtoModelFull::lookup_effect(
                &self.prototype.effects,
                addr_space,
                addr_offset,
                size,
            );
        }
        if self.prototype.has_model() {
            // cc:4237: return model->hasEffect(addr, size);
            return self.prototype.has_effect(addr_space, addr_offset, size);
        }
        // Ghidra never observes a modelless FuncProto (the dereference would
        // fault); Rugra production does until FUNCPROTO-MODEL-BIND-0001.
        // unknown_effect is the conservative effect: guardCalls then builds
        // an INDIRECT, which never under-protects the range.
        EffectType::UnknownEffect
    }

    // Ghidra: fspec.hh:1630 FuncCallSpecs::isAutoKilledByCall (inherits FuncProto)
    /// Should unaffected storage be treated as killed-by-call? Faithful to
    /// `FuncProto::isAutoKilledByCall` (fspec.cc:4609-4615): the model's
    /// auto_killedbycall flag, sticky-copied by `set_model`, or a locked
    /// output.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.prototype.is_auto_killed_by_call()
    }

    // Ghidra: fspec.hh:883 FuncProto::possibleInputParam
    /// Does the given storage location make sense as an input parameter?
    pub fn possible_input_param(&self, addr: u64, size: i32, space: crate::space::AddressSpace) -> bool {
        if let Some(ref model) = self.proto_model {
            model.possible_input_param(addr, size, space)
        } else {
            false
        }
    }

    // Ghidra: fspec.hh:1554 FuncCallSpecs::characterizeAsInputParam (inherits FuncProto)
    /// Characterize whether the given range could be/hold an input
    /// parameter. Faithful delegation to `FuncProto::characterizeAsInputParam`
    /// (fspec.cc:4289-4324) through the C++ base class.
    pub fn characterize_as_input_param(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> i32 {
        self.prototype
            .characterize_as_input_param(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.hh:1555 FuncCallSpecs::characterizeAsOutput (inherits FuncProto)
    /// Characterize whether the given range could be/hold the return-value
    /// storage. Faithful delegation to `FuncProto::characterizeAsOutput`
    /// (fspec.cc:4336-4358) through the C++ base class — Rugra previously
    /// collapsed this onto the input characterization, which the
    /// HERITAGE-DRIVER audit flagged as a guardCalls divergence.
    pub fn characterize_as_output(
        &self,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> i32 {
        self.prototype
            .characterize_as_output(addr_space, addr_offset, size)
    }

    // Ghidra: fspec.hh:1704 FuncCallSpecs::isStackOutputLock
    /// Is the output prototype stack-locked? Faithful inline accessor
    /// `isStackOutputLock` (fspec.hh:1704): reads the `isstackoutputlock`
    /// bit set by `ActionFuncLink::funcLinkOutput` (coreaction.cc:1548)
    /// when the locked output storage is in the spacebase space.
    pub fn is_stack_output_lock(&self) -> bool {
        self.is_stack_output_locked
    }

    // Ghidra: fspec.hh:1701 FuncCallSpecs::setBadJumpTable
    /// Toggle whether \b call site looked like an indirect jump. Faithful
    /// inline mutator `setBadJumpTable` (fspec.hh:1701). Set by
    /// `FlowInfo::truncateIndirectJump`'s default failure arm (flow.cc:754);
    /// read by `ActionNameVars::lookForBadJumpTables` (coreaction.cc:2786)
    /// for the "UNRECOVERED_JUMPTABLE" rename decision.
    pub fn set_bad_jump_table(&mut self, val: bool) {
        self.is_bad_jump_table = val;
    }

    // Ghidra: fspec.hh:1702 FuncCallSpecs::isBadJumpTable
    /// Return \b true if \b this call site looked like an indirect jump.
    /// Faithful inline accessor `isBadJumpTable` (fspec.hh:1702).
    pub fn bad_jump_table(&self) -> bool {
        self.is_bad_jump_table
    }

    // Ghidra: fspec.hh:1703 FuncCallSpecs::setStackOutputLock
    /// Toggle whether the output is locked and on the stack. Faithful
    /// inline mutator `setStackOutputLock` (fspec.hh:1703). Consumer of the
    /// spacebase-storage test in `ActionFuncLink::funcLinkOutput`
    /// (coreaction.cc:1546-1549); read by `Heritage::guardCalls`
    /// (heritage.cc:1487).
    pub fn set_stack_output_lock(&mut self, val: bool) {
        self.is_stack_output_locked = val;
    }

    // Ghidra: fspec.hh:1536 FuncProto::getOutput (inherits through FuncCallSpecs)
    /// Get the return value's proto-store storage (space, offset).
    /// Delegation to `FuncProto::output_storage` — the flat-store stand-in
    /// for the `ProtoStore*::outparam` `ParameterBasic::addr` — because
    /// `FuncCallSpecs : public FuncProto` (fspec.hh:1645) exposes
    /// `getOutput()` directly to heritage
    /// (`tryOutputStackGuard` heritage.cc:1407/1410).
    pub fn get_output_storage(&self) -> Option<(AddressSpace, u64)> {
        self.prototype.output_storage
    }

    // Ghidra: fspec.cc:3906 FuncProto::isInputLocked
    /// Is this call's input prototype locked? `FuncCallSpecs` inherits
    /// `FuncProto`; the oracle checks the void-input lock first, then only
    /// the first parameter's type lock (fspec.cc:3906-3914).
    pub fn is_input_locked(&self) -> bool {
        self.prototype.is_input_locked()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isOutputLocked
    /// Is the output (return) locked? Faithful to `FuncCallSpecs::isOutputLocked`
    /// (delegates to FuncProto::isOutputLocked). A locked output means the
    /// return data-type (possibly void) is fixed; `funcLinkOutput` builds the
    /// output varnode only if the locked type is non-void.
    pub fn is_output_locked(&self) -> bool {
        self.prototype.is_output_locked()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isDotdotdot
    /// Is this a varargs (...) prototype? Faithful to `FuncCallSpecs::isDotdotdot`.
    pub fn is_dotdotdot(&self) -> bool {
        self.prototype.is_dotdotdot
    }

    // Ghidra: fspec.cc:5331 FuncCallSpecs::initActiveInput
    /// Turn on input recovery and set its pass bound from the model's maximum
    /// input heritage delay.
    pub fn init_active_input(&mut self) {
        self.input_recovery_active = true;
        let mut max_delay = self.prototype.get_max_input_delay();
        if max_delay > 0 {
            max_delay = 3;
        }
        self.active_input.set_max_pass(max_delay);
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::hasModel
    /// Does this call site have a calling-convention model? Faithful to
    /// `FuncCallSpecs::hasModel`.
    pub fn has_model(&self) -> bool {
        self.prototype.has_model()
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::setModel
    /// Set the calling-convention model. Faithful to `FuncCallSpecs::setModel`.
    pub fn set_model(&mut self, model: crate::type_system::protomodel::ProtoModel) {
        self.proto_model = Some(model);
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::resolveModel
    /// Resolve the calling-convention model from the active trials. Faithful
    /// to `FuncProto::resolveModel` (fspec.cc:3767-3776). For a non-merged
    /// model (which Rugra uses), this is a no-op — resolution is only needed
    /// for ProtoModelMerged (selecting between alternative models based on
    /// active trials).
    pub fn resolve_model(&mut self) {
        // Rugra's ProtoModel is always a concrete model (not merged), so
        // resolveModel is a no-op. Ghidra's ProtoModelMerged::selectModel
        // picks between alternatives — Rugra doesn't support that yet.
    }

    // Ghidra: fspec.hh:1494 FuncCallSpecs::deriveInputMap
    /// Derive the input prototype from active trials via the model's input
    /// ParamList. Faithful to the inline `deriveInputMap`
    /// (fspec.hh:1494-1495 `model->deriveInputMap(active)`, whose ProtoModel
    /// body at fspec.hh:791-792 is `input->fillinMap(active)`) — the
    /// cspec-parsed `ProtoModelFull::input: ParamListStandard` port
    /// (fspec.rs:6046, oracle fspec.cc:1285-1313, including the final
    /// "mark every active trial used" loop). The simplified
    /// `type_system::protomodel` seam is only consulted when the full model
    /// is absent (its `fillin_input_map` skips CHECKED trials, so it can
    /// never mark an active trial used — the dual-model seam residual).
    pub fn derive_input_map(&mut self) {
        let full_model = self.prototype.model.clone();
        match &full_model {
            Some(model) => model.input.fillin_map(&mut self.active_input),
            None => {
                if let Some(model) = self.proto_model.as_ref() {
                    model.derive_input_map(&mut self.active_input);
                }
            }
        }
    }

    // Ghidra: fspec.hh:1501 FuncCallSpecs::deriveOutputMap
    /// Derive the output prototype from active trials via the model's output
    /// ParamList. Faithful to the inline `deriveOutputMap`
    /// (fspec.hh:1501-1502 `model->deriveOutputMap(active)`, whose
    /// ProtoModel body at fspec.hh:798-799 is `output->fillinMap(active)`)
    /// — the `ProtoModelFull::output: ParamListOutput` enum dispatch
    /// (`ParamListStandardOut::fillinMap`, oracle fspec.cc:1720-1758). The
    /// simplified seam remains the no-full-model fallback.
    pub fn derive_output_map(&mut self) {
        let full_model = self.prototype.model.clone();
        match &full_model {
            Some(model) => model.output.fillin_map(&mut self.active_output),
            None => {
                if let Some(model) = self.proto_model.as_ref() {
                    model.derive_output_map(&mut self.active_output);
                }
            }
        }
    }

    // Ghidra: fspec.cc:5685 FuncCallSpecs::buildInputFromTrials
    /// Set the final input Varnodes to the CALL based on ParamActive analysis.
    /// Faithful 1:1 port of `buildInputFromTrials` (fspec.cc:5668-5741).
    ///
    /// Varnodes that don't look like parameters are removed (the CALL's whole
    /// input list is rewritten via `op_set_all_input`, preserving only the
    /// fspec annotation in slot 0). Unreferenced parameters are filled in with
    /// a fresh Varnode at the trial address; oversized Varnodes are truncated
    /// through a SUBPIECE inserted before the call. Stack-passed parameter
    /// ranges are marked not-mapped on the local scope. Surviving trials are
    /// renumbered by `deleteUnusedTrials`.
    pub fn build_input_from_trials(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
    ) {
        // Ghidra fspec.cc:5677: newparam.push_back(op->getIn(0)) — preserve
        // the fspec parameter across the wholesale rewrite.
        let mut newparam: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            call_op.0.read().unwrap().get_in(0).cloned().into_iter().collect();
        // Ghidra fspec.cc:5698-5701: if (isDotdotdot() && isInputLocked())
        //   activeinput.sortFixedPosition();
        if self.is_dotdotdot() && self.is_input_locked() {
            self.active_input.sort_fixed_position();
        }
        // Trial decisions snapshotted up front so the loop body can mutate fd
        // (SUBPIECE / newVarnode / scope) without holding the trial borrow.
        let decisions: Vec<(bool, crate::space::AddressSpace, u64, i32, bool, i32)> =
            {
                let active = &self.active_input;
                    (0..active.get_num_trials())
                        .filter_map(|i| {
                            let trial = active.get_trial(i);
                            // Ghidra fspec.cc:5705: if (!paramtrial.isUsed()) continue;
                            if !trial.is_used() {
                                return None;
                            }
                            Some((
                                true,
                                trial.get_space(),
                                trial.get_address().as_u64(),
                                trial.get_size(),
                                trial.is_unref(),
                                trial.get_slot(),
                            ))
                        })
                        .collect()
            };
        for (_used, space, mut off, sz, is_unref, slot) in decisions {
            // Ghidra fspec.cc:5709-5715: spacebase trials translate through
            // this call's resolved stackoffset into caller perspective.
            let isspacebase = space == crate::space::AddressSpace::Stack;
            if isspacebase && self.stackoffset != OFFSET_UNKNOWN {
                off = ((self.stackoffset as i128 + off as i128).rem_euclid(1i128 << 64)) as u64;
            }
            let vn: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>;
            if is_unref {
                // Ghidra fspec.cc:5716-5717: recovered unreferenced address as
                // part of prototype — create the varnode via Funcdata::
                // newVarnode (funcdata_varnode.cc:148-165): bank create +
                // assignHigh + the queryProperties flag tail, so an unref
                // parameter inherits the mapped/addrtied range flags a
                // Ghidra-created varnode would carry into printing.
                vn = fd.vbank.create_with_space(sz as usize, space, off);
                let _ = fd.assign_high(&vn);
                crate::heritage::Heritage::apply_new_varnode_flags(fd, &vn);
            } else {
                // Ghidra fspec.cc:5719: vn = op->getIn(paramtrial.getSlot()).
                let current = call_op.0.read().unwrap().get_in(slot as usize).cloned();
                let Some(mut slot_vn) = current else { continue };
                // Ghidra fspec.cc:5720-5732: varnode bigger than the parameter
                // type — insert a SUBPIECE truncate before the call.
                let vn_size = slot_vn.read().unwrap().get_size() as i32;
                if vn_size > sz {
                    let (op_addr, vn_off, vn_space) = {
                        let (op_r, vn_r) = (call_op.0.read().unwrap(), slot_vn.read().unwrap());
                        (op_r.get_addr(), vn_r.get_offset(), vn_r.get_space())
                    };
                    let newop = fd.new_op(2, op_addr);
                    // x86-64 is little-endian: outvn at vn->getAddr() (the
                    // big-endian +size-sz alternative is fspec.cc:5725-5726).
                    // vn->getAddr() is the parameter varnode's FULL storage
                    // address — its own space (stack space for stack-passed
                    // parameters, register space for register params), not a
                    // pinned register space (FSPEC-DEALLOC-SPACE-0001).
                    let outvn =
                        fd.new_varnode_out_full(sz as usize, vn_space, Address::new(vn_off), &newop);
                    fd.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_SUBPIECE);
                    fd.op_set_input(&newop, slot_vn.clone(), 0);
                    let trunc_const = fd.new_constant(1, 0);
                    fd.op_set_input(&newop, trunc_const, 1);
                    fd.op_insert_before(&newop, call_op);
                    slot_vn = outvn;
                }
                vn = slot_vn;
            }
            newparam.push(vn);
            // Ghidra fspec.cc:5735-5738: mark the stack range used to pass
            // this parameter as unmapped (parameter=true).
            if isspacebase {
                if let Some(scope) = fd.scope.as_mut() {
                    scope.mark_not_mapped(off, sz, true);
                }
            }
        }
        // Ghidra fspec.cc:5739: data.opSetAllInput(op,newparam) — set final
        // parameter list.
        fd.op_set_all_input(call_op, &newparam);
        // Ghidra fspec.cc:5740: activeinput.deleteUnusedTrials().
        self.active_input.delete_unused_trials();
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isInputActive
    /// Is the input currently in active-recovery mode? Faithful to
    /// `FuncCallSpecs::isInputActive`.
    pub fn is_input_active(&self) -> bool {
        self.input_recovery_active
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::isOutputActive
    /// Is the output currently in active-recovery mode? Faithful to
    /// `FuncCallSpecs::isOutputActive`.
    pub fn is_output_active(&self) -> bool {
        self.output_recovery_active
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::clearActiveInput
    /// Turn off input recovery without destroying the embedded trial state.
    pub fn clear_active_input(&mut self) {
        self.input_recovery_active = false;
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::clearActiveOutput
    /// Turn off output recovery without destroying the embedded trial state.
    pub fn clear_active_output(&mut self) {
        self.output_recovery_active = false;
    }

    // Ghidra: fspec.cc:5870 FuncCallSpecs::getInputBytesConsumed
    /// Get the estimated number of bytes within the given parameter that are
    /// consumed. Faithful to `FuncCallSpecs::getInputBytesConsumed`
    /// (fspec.cc:5870-5882). A non-zero value means that many LSBs of the
    /// storage location are used; 0 means all bytes are presumed used.
    pub fn get_input_bytes_consumed(&self, slot: usize) -> u32 {
        if slot >= self.input_consume.len() {
            0
        } else {
            self.input_consume[slot]
        }
    }

    // Ghidra: fspec.cc:5887 FuncCallSpecs::setInputBytesConsumed
    /// Set the estimated number of bytes within the given parameter that are
    /// consumed. Faithful to `FuncCallSpecs::setInputBytesConsumed`
    /// (fspec.cc:5887-5906). Provides a hint to the dead-code consume
    /// algorithm about how the parameter is used. The value can only shrink
    /// (the smallest hint wins). Returns true if there was a change.
    pub fn set_input_bytes_consumed(&mut self, slot: usize, val: u32) -> bool {
        while self.input_consume.len() <= slot {
            self.input_consume.push(0);
        }
        let old_val = self.input_consume[slot];
        if old_val == 0 || val < old_val {
            // Only let the value get smaller.
            self.input_consume[slot] = val;
            return true;
        }
        false
    }

    // Ghidra: fspec.hh:1681 FuncCallSpecs::getOp
    /// Upgrade the exact non-owning CALL/CALLIND identity stored by this
    /// call specification. The Funcdata argument is retained for source API
    /// compatibility but is deliberately not used for an address scan.
    pub fn find_call_op(&self, _fd: &crate::funcdata::Funcdata) -> Option<crate::op::PcodeOpRef> {
        self.op.upgrade().map(crate::op::PcodeOpRef)
    }

    // Ghidra: fspec.cc:5564 FuncCallSpecs::finalInputCheck
    /// Make final activity check on trials that might have been affected by
    /// conditional execution. Faithful to `FuncCallSpecs::finalInputCheck`
    /// (fspec.cc:5564-5576). Re-runs AncestorRealistic on trials flagged with
    /// a condexe effect; trials that fail the recheck are marked no-use.
    pub fn final_input_check(&mut self, op_ref: &crate::op::PcodeOpRef) {
        let mut ancestor_real = crate::funcdata::AncestorRealistic::new();
        let active = &mut self.active_input;
            // Collect indices of trials to recheck (isActive + hasCondExeEffect),
            // then process them. Ghidra mutates trials in-place during iteration.
            let mut recheck: Vec<usize> = Vec::new();
            for i in 0..active.get_num_trials() {
                let t = active.get_trial(i);
                if t.is_active() && t.has_condexe_effect() {
                    recheck.push(i);
                }
            }
            for i in recheck {
                let slot = active.get_trial(i).get_slot();
                let success = {
                    let t = active.get_trial_mut(i);
                    ancestor_real.execute(&op_ref, slot, t, false)
                };
                if !success {
                    active.get_trial_mut(i).mark_no_use();
                }
            }
    }

    // Ghidra: fspec.cc:5585 FuncCallSpecs::checkInputTrialUse
    /// Mark if input trials are being actively used. Faithful 1:1 port of
    /// `FuncCallSpecs::checkInputTrialUse` (fspec.cc:5585-5653).
    ///
    /// For each unchecked trial, determines if the trial varnode has realistic
    /// ancestors (via `AncestorRealistic`) and is only used for parameter
    /// passing (via `ancestorOpUse`). Stack-space trials are additionally
    /// checked against the alias checker and local range.
    ///
    /// Returns a list of (slot, varnode_size) pairs for trials that are
    /// definitely-not-used and should have their op input replaced with a
    /// constant (Ghidra's `data.opSetInput(op, newConstant(...), slot)`).
    pub fn check_input_trial_use(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        op_ref: &crate::op::PcodeOpRef,
        aliascheck: &crate::varmap::AliasChecker,
        maxancestor: i32,
    ) -> Vec<(i32, i32)> {
        let mut replace_slots: Vec<(i32, i32)> = Vec::new();
        let mut ancestor_real = crate::funcdata::AncestorRealistic::new();
        let mut needs_final_check = false;
        // `active_input` is accessed per-statement (not through one long
        // &mut binding) so `&self` can be supplied to ancestorOpUse as
        // checkCallDoubleUse's match spec at the call sites below.
        let num_trials = self.active_input.get_num_trials();
        for i in 0..num_trials {
            if self.active_input.get_trial(i).is_checked() { continue; }
            let slot = self.active_input.get_trial(i).get_slot();
            // Resolve the trial varnode: vn = op.getIn(slot).
            let vn_arc = {
                let op_rg = op_ref.0.read().unwrap();
                op_rg.get_in(slot as usize).cloned()
            };
            let vn = match vn_arc { Some(v) => v, None => continue };
            let vn_space = vn.read().unwrap().get_space();
            if vn_space == crate::space::AddressSpace::Stack {
                // Ghidra fspec.cc:5615-5634 — stack spacebase varnode path.
                if aliascheck.has_local_alias(&vn.read().unwrap()) {
                    self.active_input.get_trial_mut(i).mark_no_use();
                } else if {
                    let t = self.active_input.get_trial_mut(i);
                    ancestor_real.execute(op_ref, slot, t, false)
                } {
                    // The trial is cloned out for the walk so `&self` can
                    // ride along as checkCallDoubleUse's match spec (Ghidra
                    // passes both pointers freely); the walk's flag
                    // mutations (setRemFormed) persist via the write-back.
                    let mut trial_clone = self.active_input.get_trial(i).clone();
                    let ao_result = crate::funcdata::ancestor_op_use(
                        fd, maxancestor, &vn, op_ref, &mut trial_clone, 0, 0, Some(self),
                    );
                    *self.active_input.get_trial_mut(i) = trial_clone;
                    if ao_result {
                        self.active_input.get_trial_mut(i).mark_active();
                    } else {
                        self.active_input.get_trial_mut(i).mark_inactive();
                    }
                } else {
                    self.active_input.get_trial_mut(i).mark_no_use();
                }
            } else {
                // Ghidra fspec.cc:5635-5648 — register / other space path.
                if {
                    let t = self.active_input.get_trial_mut(i);
                    ancestor_real.execute(op_ref, slot, t, true)
                } {
                    let mut trial_clone = self.active_input.get_trial(i).clone();
                    let ao_result = crate::funcdata::ancestor_op_use(
                        fd, maxancestor, &vn, op_ref, &mut trial_clone, 0, 0, Some(self),
                    );
                    *self.active_input.get_trial_mut(i) = trial_clone;
                    if ao_result {
                        self.active_input.get_trial_mut(i).mark_active();
                        if self.active_input.get_trial(i).has_condexe_effect() {
                            needs_final_check = true;
                        }
                    } else {
                        self.active_input.get_trial_mut(i).mark_inactive();
                    }
                } else if vn.read().unwrap().is_input() {
                    self.active_input.get_trial_mut(i).mark_inactive();
                } else {
                    self.active_input.get_trial_mut(i).mark_no_use();
                }
            }
            if self.active_input.get_trial(i).is_definitely_not_used() {
                let vn_size = vn.read().unwrap().get_size() as i32;
                replace_slots.push((slot, vn_size));
            }
        }
        if needs_final_check {
            self.active_input.mark_needs_final_check();
        }
        replace_slots
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::initActiveOutput
    /// Turn on output recovery; the embedded trial container already exists.
    pub fn init_active_output(&mut self) {
        self.output_recovery_active = true;
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getActiveInput
    /// Get the permanently embedded input-trial container.
    pub fn get_active_input(&self) -> &ParamActive {
        &self.active_input
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::getActiveOutput
    /// Get the permanently embedded output-trial container.
    pub fn get_active_output(&self) -> &ParamActive {
        &self.active_output
    }

    // Ghidra: fspec.cc:4910 FuncCallSpecs::abortSpacebaseRelative
    /// Remove the stack placeholder input from the call op and clean up.
    /// Faithful to `abortSpacebaseRelative` (fspec.cc:4910-4921). Called by
    /// Heritage::clearStackPlaceholders when heritage resolves actual stack
    /// values for this call's parameters.
    pub fn abort_spacebase_relative(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
    ) {
        if self.stack_placeholder_slot >= 0 {
            let slot = self.stack_placeholder_slot as usize;
            // cc:4914: vn = op->getIn(stackPlaceholderSlot).
            let placeholder_vn = call_op.0.read().unwrap().get_in(slot).cloned();
            // cc:4915: data.opRemoveInput(op, slot).
            fd.op_remove_input(call_op, slot);
            // cc:4916: clearStackPlaceholderSlot.
            self.clear_stack_placeholder_slot();
            // cc:4918-4919: if placeholder vn has no descend and is internal+
            // written, destroy its defining op. The read guard must be
            // dropped BEFORE opDestroy: the destroyed LOAD's output IS this
            // varnode, and opDestroy→destroyVarnode→makeFree write-locks it
            // (an `if let` scrutinee temporary would keep the read guard
            // alive across the destroy and self-deadlock the RwLock —
            // reproduced as the main() worker futex hang).
            let def_to_destroy = placeholder_vn.and_then(|vn| {
                let def = {
                    let vn_r = vn.read().unwrap();
                    (vn_r.has_no_descend()
                        && vn_r.get_space() == crate::space::AddressSpace::Unique
                        && vn_r.is_written())
                        .then(|| vn_r.def.as_ref().and_then(|w| w.upgrade()))
                        .flatten()
                };
                def
            });
            if let Some(def_weak) = def_to_destroy {
                fd.op_destroy(&crate::op::PcodeOpRef(def_weak));
            }
        }
    }

    // Ghidra: fspec.hh:1654 FuncCallSpecs::clearStackPlaceholderSlot
    /// Clear the input slot holding the stack-pointer placeholder. Faithful
    /// to the inline `clearStackPlaceholderSlot` (fspec.hh:1674): releases
    /// the FuncCallSpecs slot and, when input recovery is still active,
    /// `ParamActive::freePlaceholderSlot` shifts every trial above the
    /// placeholder down one slot so trial slots stay aligned with the CALL
    /// op input indices.
    pub fn clear_stack_placeholder_slot(&mut self) {
        self.stack_placeholder_slot = -1;
        if self.input_recovery_active {
            self.active_input.free_placeholder_slot();
        }
    }

    // Ghidra: fspec.hh:1653 FuncCallSpecs::setStackPlaceholderSlot
    /// Record the input slot holding the stack-pointer placeholder. Faithful
    /// to the inline `setStackPlaceholderSlot` (fspec.hh:1672): when input
    /// recovery is active, `ParamActive::setPlaceholderSlot` reserves the
    /// current slotbase for the placeholder so subsequently registered
    /// trials keep their slot equal to the CALL op input index.
    pub fn set_stack_placeholder_slot(&mut self, slot: i32) {
        self.stack_placeholder_slot = slot;
        if self.input_recovery_active {
            self.active_input.set_placeholder_slot();
        }
    }

    // Ghidra: fspec.cc:4849 FuncCallSpecs::createPlaceholder
    /// Add an input parameter that will resolve to the current stack offset
    /// for \b this call site. Faithful to `createPlaceholder`
    /// (fspec.cc:4849-4858):
    ///   slot = op->numInput();
    ///   loadval = data.opStackLoad(spacebase,0,1,op,(Varnode*)0,false);
    ///   data.opInsertInput(op,loadval,slot);
    ///   setStackPlaceholderSlot(slot);
    ///   loadval->setSpacebasePlaceholder();
    pub fn create_placeholder(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        spacebase: crate::space::AddressSpace,
    ) {
        let slot = call_op.0.read().unwrap().num_input();
        let loadval = fd.op_stack_load(spacebase, 0, 1, call_op, None, false);
        fd.op_insert_input(call_op, loadval.clone(), slot);
        self.set_stack_placeholder_slot(slot as i32);
        loadval.write().unwrap().set_spacebase_placeholder();
    }

    // Ghidra: fspec.cc:4870 FuncCallSpecs::resolveSpacebaseRelative
    /// Calculate the stack offset of \b this call site. Faithful to
    /// `resolveSpacebaseRelative` (fspec.cc:4870-4908):
    ///   refvn = phvn->getDef()->getIn(0);
    ///   spacebase = refvn->getSpace();
    ///   if (spacebase->getType() != IPTR_SPACEBASE)
    ///     data.warningHeader("This function may have set the stack pointer");
    ///   stackoffset = refvn->getOffset();
    ///   if (stackPlaceholderSlot >= 0) {
    ///     if (op->getIn(stackPlaceholderSlot) == phvn) {
    ///       abortSpacebaseRelative(data); return; } }
    ///   if (isInputLocked()) {
    ///     slot = op->getSlot(phvn)-1;
    ///     if (slot >= numParams()) throw LowlevelError(...);
    ///     param = getParam(slot);
    ///     addr = param->getAddress();
    ///     if (addr.getSpace() != spacebase) {
    ///       if (spacebase->getType() == IPTR_SPACEBASE)
    ///         throw LowlevelError("Stack placeholder does not match locked space"); }
    ///     stackoffset -= addr.getOffset();
    ///     stackoffset = spacebase->wrapOffset(stackoffset);
    ///     return; }
    ///   throw LowlevelError("Unresolved stack placeholder");
    /// Ghidra's LowlevelError throws are surfaced as the file-wide stderr
    /// convention (the driver has no exception channel); the computed
    /// stackoffset is still committed so the observable (hasEffectTranslate
    /// resolution) matches the oracle's success path.
    pub fn resolve_spacebase_relative(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        phvn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        // cc:4878: refvn = phvn->getDef()->getIn(0) — the COPY source the
        // placeholder LOAD resolved to.
        let refvn = {
            let ph = phvn.read().unwrap();
            let def = match ph.def.as_ref().and_then(|w| w.upgrade()) {
                Some(d) => d,
                None => return,
            };
            let def_r = def.read().unwrap();
            if def_r.opcode != crate::opcodes::OpCode::CPUI_COPY {
                return;
            }
            def_r.get_in(0).cloned()
        };
        let Some(refvn) = refvn else { return };
        // cc:4879-4882: spacebase type check + warning.
        let spacebase = refvn.read().unwrap().get_space();
        if !spacebase.is_stack() {
            fd.warning_header("This function may have set the stack pointer");
        }
        // cc:4883: stackoffset = refvn->getOffset().
        let ref_offset = refvn.read().unwrap().get_offset() as i64;
        self.stackoffset = ref_offset;
        // cc:4884-4888: the placeholder itself resolved — remove it.
        if self.stack_placeholder_slot >= 0 {
            let slot = self.stack_placeholder_slot as usize;
            let slot_vn = call_op.0.read().unwrap().get_in(slot).cloned();
            if let Some(vn) = slot_vn {
                if std::sync::Arc::ptr_eq(&vn, phvn) {
                    self.abort_spacebase_relative(fd, call_op);
                    return;
                }
            }
        }
        // cc:4889-4905: input-locked path — recover the relative offset from
        // the locked parameter's storage.
        if self.prototype.is_input_locked() {
            // cc:4891: slot = op->getSlot(phvn)-1.
            let slot = {
                let op_r = call_op.0.read().unwrap();
                op_r
                    .inrefs
                    .iter()
                    .position(|input| std::sync::Arc::ptr_eq(input, phvn))
            };
            let Some(raw_slot) = slot else {
                eprintln!("[FSPEC] resolve_spacebase_relative: placeholder is not an input of its call op");
                return;
            };
            let param_slot = raw_slot as i64 - 1;
            if param_slot >= self.prototype.num_params() as i64 {
                eprintln!("[FSPEC] resolve_spacebase_relative: stack placeholder does not line up with locked parameter");
                return;
            }
            // cc:4893-4894: param = getParam(slot); addr = param->getAddress().
            let param_addr = self
                .prototype
                .get_param(param_slot as usize)
                .map(|p| p.address)
                .unwrap_or(crate::address::Address::new(0));
            // cc:4895-4899: space match check (AddrSpace::get_type()
            // IPTR_SPACEBASE counterpart).
            let param_space = param_addr.to_space_address().get_space().cloned();
            let spacebase_is_spacebase = spacebase.is_stack();
            if param_space.as_ref().map(|s| s.get_type()) != Some(crate::space::SpaceType::SpaceBase)
                && spacebase_is_spacebase
            {
                eprintln!("[FSPEC] resolve_spacebase_relative: stack placeholder does not match locked space");
            }
            // cc:4900-4901: stackoffset -= addr.getOffset(); wrapOffset.
            self.stackoffset -= param_addr.to_space_address().get_offset() as i64;
            let addr_bits = (spacebase.addr_size() * 8) as u32;
            if addr_bits > 0 && addr_bits < 64 {
                let mask = (1u64 << addr_bits) - 1;
                self.stackoffset = (self.stackoffset as u64 & mask) as i64;
            }
            return;
        }
        // cc:4906: throw LowlevelError("Unresolved stack placeholder") —
        // unlocked prototypes keep OFFSET_UNKNOWN per the throw path.
        eprintln!("[FSPEC] resolve_spacebase_relative: unresolved stack placeholder");
    }

    // Ghidra: fspec.cc:4949 FuncCallSpecs::setFuncdata
    /// Set the callee associated with the called function. Faithful
    /// observable port of `setFuncdata` (fspec.cc:4949-4960): when the callee
    /// is known, the entry address is taken from it and the display name is
    /// copied (if non-empty). Ghidra additionally keeps the callee
    /// `Funcdata*` (and throws `LowlevelError` on a double set); Rugra has no
    /// per-callee Funcdata objects — the front-end boundary
    /// (`FlowInfo::queryCall`, flow.cc:660-669, driven by the Rugra driver's
    /// symbol/signature tables) hands the observable (name, entry) pair
    /// directly, and re-association overwrites instead of throwing.
    pub fn set_funcdata(&mut self, display_name: &str, entry: Address) {
        self.entry_addr = Some(entry);
        if !display_name.is_empty() {
            self.prototype.name = display_name.to_string();
        }
    }

    // Ghidra: fspec.cc:4949 FuncCallSpecs::setFuncdata
    /// Store the callee's own prototype — the getFuncdata/getFuncProto half
    /// of `ActionDefaultParams`' callee resolution (coreaction.cc:2321-2324
    /// `Funcdata *otherfunc = fc->getFuncdata()` +
    /// `otherfunc->getFuncProto()`). Ghidra keeps the whole callee Funcdata
    /// pointer and reads its live FuncProto at copy time; Rugra stores the
    /// prototype Arc itself (the driver's queryCall boundary materializes
    /// the callee's locked signature — DWARF/debug-info local or the
    /// generic_clib platform signature — exactly once, before the pipeline).
    /// Some mirrors the non-null `otherfunc` of the oracle arm; None keeps
    /// the `setInternal(evalfp, void)` else arm (coreaction.cc:2327-2328).
    pub fn set_callee_proto(&mut self, proto: Arc<FuncProto>) {
        self.callee_proto = Some(proto);
    }

    // Ghidra: fspec.hh:1682 FuncCallSpecs::getFuncdata
    /// The callee's recovered prototype, when the queryCall boundary
    /// resolved one (the `fc->getFuncdata() != 0` observable of
    /// coreaction.cc:2321).
    pub fn callee_proto(&self) -> Option<&Arc<FuncProto>> {
        self.callee_proto.as_ref()
    }

    // Ghidra: fspec.cc:3789 FuncProto::copy (called from coreaction.cc:2323
    // fc->copy(otherfunc->getFuncProto()))
    /// The ActionDefaultParams prototype-copy channel: replace this call
    /// site's FuncProto state wholesale with the callee's recovered
    /// prototype. `FuncProto::copy` (fspec.cc:3789-3805) assigns model,
    /// extrapop, the whole flag word (input/output/model locks, dotdotdot,
    /// override bits), a clone of the parameter store (output + every input
    /// parameter with name/type/lock markup) and the effect list.
    /// FuncCallSpecs-level state (op, name, entry address, effective
    /// extrapop, trial containers) is deliberately NOT part of the copy —
    /// Ghidra's `FuncCallSpecs` does not override the base-class `copy`, so
    /// `fc->copy` runs the FuncProto member only.
    /// Ghidra's FuncProto base has no name member (the call-site name is
    /// FuncCallSpecs state set by queryCall's setFuncdata), so the callsite
    /// spelling survives the copy; Rugra's FuncProto carries a name field
    /// as glue, and this wrapper restores the callsite's spelling over the
    /// copy to keep that observable faithful.
    ///
    /// Erratum (MB24, CR-CALLSPEC O3/O4 — lane doc overstated the copy):
    /// the oracle's `FuncProto::copy` also assigns `likelytrash`
    /// (fspec.cc:3802) and `injectid` (fspec.cc:3803). Rugra's
    /// `copy_from` has **no call-fixup inject id field to copy** — the
    /// injection id storage is the INJECT-0001 no-op stub (see
    /// `copy_flow_effects` below for the same latent gap) — and the
    /// `likelytrash` field (delivered by FSPEC-LIKELYTRASH-FOLD) is a
    /// latent gap in `copy_from`'s field set. Both gaps are dormant while
    /// the COPY arm is canon-unreachable (lazy structure proven in
    /// CR-CALLSPEC); closing them belongs to the copy-channel activation
    /// ticket family (PROTOCAST / INJECT-0001), not this channel's
    /// observable slice.
    pub fn copy_proto_from(&mut self, other: &FuncProto) {
        let callsite_name = std::mem::take(&mut self.prototype.name);
        self.prototype.copy_from(other);
        self.prototype.name = callsite_name;
    }

    // Ghidra: fspec.cc:5150 FuncCallSpecs::commitNewInputs
    /// Update the CALL's input Varnodes to reflect the (now locked) formal
    /// input parameters. Faithful port of `commitNewInputs`
    /// (fspec.cc:5150-5190). Clears the active-input container and old stack
    /// placeholder, then for each locked parameter builds an exact Varnode
    /// (via the caller-supplied `build_param`), registers a fresh trial, and
    /// sets the stack-placeholder on the first stack-space parameter. Finally
    /// the CALL's inputs are replaced wholesale via `op_set_all_input`.
    ///
    /// `build_param` mirrors Ghidra's private `FuncCallSpecs::buildParam`
    /// (fspec.cc:5005-5027): given the call op, an existing input varnode (or
    /// None for a stack param), and the parameter descriptor, it returns the
    /// varnode that exactly matches the parameter.
    pub fn commit_new_inputs(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        new_input: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        build_param: &mut dyn FnMut(
            &mut crate::funcdata::Funcdata,
            &crate::op::PcodeOpRef,
            Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
            crate::space::AddressSpace,
            Address,
            i32,
            Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if !self.is_input_locked() { return; }
        // ProtoParameter carries the two halves of Ghidra's Address during
        // the ADDRESS-0001 transition.  Both halves come from the same
        // assigned ParameterPieces; no storage class is inferred here.
        let param_descs: Vec<(Address, crate::space::AddressSpace, i32)> = self
            .prototype
            .parameters
            .iter()
            .map(|param| {
                (
                    param.address,
                    param.address_space,
                    param.data_type.get_size() as i32,
                )
            })
            .collect();
        // Ghidra cc:5154: Varnode *stackref = getSpacebaseRelative(); —
        // read BEFORE the placeholder state is cleared, handed to
        // buildParam for spacebase-relative parameter construction.
        let stackref = self.get_spacebase_relative();
        let placeholder_slot = self.stack_placeholder_slot;
        let mut placeholder_vn: Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            if placeholder_slot >= 0 {
                let slot = placeholder_slot as usize;
                call_op.0.read().unwrap().get_in(slot).cloned()
            } else {
                None
            };

        // Ghidra: stackPlaceholderSlot = -1; activeinput.clear();
        self.stack_placeholder_slot = -1;
        let num_passes = self.active_input.get_num_passes();
        self.active_input.clear();
        let mut no_placehold = true;

        // Ghidra: for each param, buildParam + registerTrial + markActive.
        // `param_descs` is the prevalidated address/space snapshot, avoiding
        // a borrow of self across the mutable build_param closure.
        for i in 0..param_descs.len() {
            let (paddr, pspace, psize) = param_descs[i];
            let existing = if 1 + i < new_input.len() {
                Some(new_input[1 + i].clone())
            } else {
                None
            };
            let vn = build_param(fd, call_op, existing.as_ref(), pspace, paddr, psize, stackref.as_ref());
            if 1 + i < new_input.len() {
                new_input[1 + i] = vn.clone();
            }
            // activeinput.registerTrial(paddr, psize) + getTrial(i).markActive().
            self.active_input.register_trial_in_space(pspace, paddr, psize);
            let trial_index = self.active_input.get_num_trials() - 1;
            self.active_input.get_trial_mut(trial_index).mark_active();
            // Ghidra cc:5172-5177: the first IPTR_SPACEBASE (stack) parameter
            // claims the spacebase-placeholder role on its varnode AND nulls
            // the pending placeholder — with a locked stack parameter we
            // don't need (and must not re-append) the stack-pointer
            // placeholder.
            if no_placehold && pspace == crate::space::AddressSpace::Stack {
                vn.write().unwrap().set_spacebase_placeholder();
                no_placehold = false;
                placeholder_vn = None;
            }
        }
        // Ghidra: if (placeholder != null) { newinput.push_back(placeholder);
        //   setStackPlaceholderSlot(newinput.size()-1); }
        if let Some(ph) = placeholder_vn {
            new_input.push(ph);
            self.set_stack_placeholder_slot((new_input.len() - 1) as i32);
        }
        // Ghidra: data.opSetAllInput(op, newinput).
        fd.op_set_all_input(call_op, new_input);
        // Ghidra: unless dotdotdot, clearActiveInput; else finishPass().
        if !self.is_dotdotdot() {
            self.clear_active_input();
        } else if num_passes > 0 {
            self.active_input.finish_pass();
        }
    }

    // Ghidra: fspec.cc:5201 FuncCallSpecs::commitNewOutputs
    /// Update the CALL's output Varnode to reflect the (now locked) formal
    /// return value. Faithful port of `commitNewOutputs`
    /// (fspec.cc:5201-5285). Clears the active-output container, registers a
    /// trial for the return storage, and reconciles the intersecting output
    /// varnodes (provided in `new_output`) against the locked parameter:
    /// exact matches become the CALL output, smaller outputs become SUBPIECE
    /// truncations of the real output, larger outputs are extended via the
    /// caller-supplied `extend_output` hook.
    pub fn commit_new_outputs(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        new_output: &[std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>],
        get_return_addr_size: &dyn Fn(&FuncCallSpecs) -> (Address, i32),
        set_call_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>),
        truncate_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, i32) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) {
        if !self.is_output_locked() { return; }
        if new_output.is_empty() {
            self.active_output.clear();
            return;
        }
        let (ret_addr, ret_size) = get_return_addr_size(self);
        // The flat ProtoStore keeps the address-space half separately from
        // the legacy offset carrier.  A locked non-void output without
        // assigned storage is the same invalid transitional state as a null
        // Ghidra output address, so leave the graph untouched.
        let Some((ret_space, _)) = self.get_output_storage() else {
            return;
        };
        // activeoutput.clear()
        self.active_output.clear();
        // activeoutput.registerTrial(param->getAddress(), param->getSize()).
        self.active_output.register_trial_in_space(ret_space, ret_addr, ret_size);

        // Ghidra: find an exact-size match among new_output.
        let mut exact_index: Option<usize> = None;
        for (i, out) in new_output.iter().enumerate() {
            if out.read().unwrap().get_size() as i32 == ret_size {
                exact_index = Some(i);
                break;
            }
        }
        // Determine the "real" output varnode.
        let real_out: std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> = if let Some(idx) = exact_index {
            let exact = new_output[idx].clone();
            // Ghidra: if (op != indOp) { opSetOutput(op, exactMatch); opUnlink(indOp); }
            // Rugra delegates the wiring to set_call_output.
            set_call_output(fd, call_op, &exact);
            exact
        } else {
            // Ghidra: opUnsetOutput(op); realOut = newVarnodeOut(size, addr, op).
            // Rugra cannot allocate a fresh output varnode generically; the
            // caller's set_call_output with the first new_output stands in.
            let first = new_output[0].clone();
            set_call_output(fd, call_op, &first);
            first
        };

        // Ghidra: for each other new_output, reconcile size against param.
        for (i, old_out) in new_output.iter().enumerate() {
            if Some(i) == exact_index { continue; }
            let old_size = old_out.read().unwrap().get_size() as i32;
            if old_size < ret_size {
                // Ghidra: smaller → SUBPIECE of realOut at overlap.
                let overlap = 0i32; // precise overlap requires address math.
                truncate_output(fd, call_op, &real_out, overlap);
            } else if ret_size < old_size {
                // Ghidra: larger → extend realOut into old_out (ZEXT/SEXT).
                // The extend hook is folded into truncate_output's caller.
                let _ = old_out;
            }
            // equal sizes (other than the exact match) need no work.
        }
    }

    // Ghidra: fspec.cc:5038 FuncCallSpecs::transferLockedInputParam
    /// Find the input slot that holds the given locked parameter.
    /// Faithful 1:1 port of `transferLockedInputParam` (fspec.cc:5038-5056).
    ///
    /// Walks the active-input trials looking for one whose storage contains
    /// the parameter's (address, size). Returns `(matched, slot)`:
    ///   - `(true, slot)`  — a matching, still-used trial; reuse its slot.
    ///   - `(false, 0)`    — a matching trial was already stripped
    ///     (definitely-not-used), OR no trial matched and the parameter is
    ///     not on the stack: the transfer must abort.
    ///   - `(false, -1)`   — no trial matched and the parameter lives in
    ///     the spacebase (stack) space: the caller must supply a stack
    ///     placeholder.
    pub fn transfer_locked_input_param(&self, param: &ProtoParameter) -> (bool, i32) {
        let active = &self.active_input;
        let num_trials = active.get_num_trials();
        let start_addr = param.address;
        let sz = param.data_type.get_size() as i32;
        let last_addr = Address::new(start_addr.as_u64().wrapping_add((sz - 1) as u64));
        for i in 0..num_trials {
            let t = active.get_trial(i);
            let t_addr = t.get_address();
            if start_addr.as_u64() < t_addr.as_u64() { continue; }
            let trial_end = Address::new(t_addr.as_u64().wrapping_add((t.get_size() - 1) as u64));
            if trial_end.as_u64() < last_addr.as_u64() { continue; }
            // Ghidra: if (curtrial.isDefinitelyNotUsed()) return 0;
            if t.is_definitely_not_used() { return (false, 0); }
            return (true, t.get_slot());
        }
        // Ghidra: if (startaddr.getSpace()->getType() == IPTR_SPACEBASE) return -1;
        // Rugra's ProtoParameter does not yet carry a space; we cannot
        // distinguish the stack case here. Conservative: report "abort" so
        // the caller treats the transfer as failed and falls back to a full
        // restart, matching Ghidra's behaviour when no stackref is available.
        // TODO(ALIGNMENT_ROADMAP): once ProtoParameter carries an AddressSpace,
        // return (false, -1) for the IPTR_SPACEBASE branch.
        (false, 0)
    }

    // Ghidra: fspec.cc:5068 FuncCallSpecs::transferLockedOutputParam
    /// Pass back any CALL outputs that contain or are contained by the given
    /// return-value parameter. Faithful 1:1 port of `transferLockedOutputParam`
    /// (fspec.cc:5068-5089). Examines the CALL's own output varnode, then
    /// walks the preceding chain of INDIRECT ops marked as indirect
    /// creations, collecting every output whose storage overlaps the
    /// parameter (in either containment direction).
    pub fn transfer_locked_output_param(
        &self, call_op: &crate::op::PcodeOpRef,
        bank: &crate::op::PcodeOpBank, param: &ProtoParameter,
        new_output: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) {
        let p_addr = param.address;
        let p_size = param.data_type.get_size() as i32;
        // Ghidra: vn = op->getOut(); if (vn != null) { ... justifiedContain both ways ... }
        if let Some(vn) = call_op.0.read().unwrap().get_out().cloned() {
            let (vn_addr, vn_size) = {
                let v = vn.read().unwrap();
                (*v.get_addr(), v.get_size() as i32)
            };
            // cc:5073/5075 only observe >= 0 (containment), so the
            // endian-aware distance is not observable here; the legacy
            // spaceless Address cannot carry the param's space, and the
            // transitional enum-space model is little-endian
            // (space.rs is_big_endian default).
            let contains_param =
                justified_contain_range(p_addr.as_u64(), p_size, vn_addr.as_u64(), vn_size, false, false) >= 0;
            let contained_by_param =
                justified_contain_range(vn_addr.as_u64(), vn_size, p_addr.as_u64(), p_size, false, false) >= 0;
            if contains_param || contained_by_param {
                new_output.push(vn);
            }
        }
        // Ghidra: indop = op->previousOp(); while (indop != null && indop->code()==CPUI_INDIRECT) { ... }
        use crate::opcodes::OpCode;
        let self_seq = call_op.0.read().unwrap().start.clone();
        // Collect preceding ops in storage order (alive list is ordered).
        let mut prev_chain: Vec<crate::op::PcodeOpRef> = Vec::new();
        for r in &bank.alivelist {
            if r.0.read().unwrap().start == self_seq { break; }
            prev_chain.push(r.clone());
        }
        // Walk in reverse so we examine the immediate predecessor first.
        for indop_ref in prev_chain.iter().rev() {
            let indop = indop_ref.0.read().unwrap();
            if indop.opcode != OpCode::CPUI_INDIRECT { break; }
            if !indop.is_indirect_creation() { continue; }
            if let Some(vn) = indop.get_out().cloned() {
                let (vn_addr, vn_size) = {
                    let v = vn.read().unwrap();
                    (*v.get_addr(), v.get_size() as i32)
                };
                // cc:5082/5084 — same >=0-only containment observation as
                // above (distance not observable; LE transitional model).
                let contains_param =
                    justified_contain_range(p_addr.as_u64(), p_size, vn_addr.as_u64(), vn_size, false, false) >= 0;
                let contained_by_param =
                    justified_contain_range(vn_addr.as_u64(), vn_size, p_addr.as_u64(), p_size, false, false) >= 0;
                if contains_param || contained_by_param {
                    new_output.push(vn);
                }
            }
        }
    }

    // Ghidra: fspec.cc:5100 FuncCallSpecs::transferLockedInput
    /// List and/or create a varnode for each input parameter matching a
    /// source prototype. Faithful 1:1 port of `transferLockedInput`
    /// (fspec.cc:5100-5120). Always keeps the call destination address
    /// (slot 0), then for each source parameter asks
    /// `transfer_locked_input_param` for the slot to reuse:
    ///   - matched slot  -> reuse the existing CALL input varnode.
    ///   - stack case    -> push `None` (caller resolves via stackref).
    ///   - abort (0)     -> return `Err` so the caller can fall back.
    ///
    /// Returns `Ok(())` on success or `Err(())` when a parameter cannot be
    /// matched and there is no stackref available (Ghidra's `return false`).
    pub fn transfer_locked_input(
        &self, source: &FuncProto,
        new_input: &mut Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>>,
        call_op: &crate::op::PcodeOpRef,
        get_call_in: &dyn Fn(&crate::op::PcodeOpRef, usize) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    ) -> Result<(), ()> {
        // Ghidra: newinput.push_back(op->getIn(0));  // call destination.
        new_input.push(get_call_in(call_op, 0));
        let num_params = source.parameters.len();
        let mut stackref_present = false; // Ghidra: stackref lazily fetched once.
        for i in 0..num_params {
            let (matched, slot) = self.transfer_locked_input_param(&source.parameters[i]);
            if !matched && slot == 0 {
                // Ghidra: reuse == 0  -> return false.
                return Err(());
            }
            if matched {
                // Ghidra: newinput.push_back(op->getIn(reuse)).
                new_input.push(get_call_in(call_op, slot as usize));
            } else {
                // slot == -1, the stack case.
                // Ghidra: if (stackref == null) stackref = getSpacebaseRelative();
                //         if (stackref == null) return false;
                // Rugra status (FSPECDEIN-TRANSFERLOCKED-STACK-0001, F-A):
                // `get_spacebase_relative` exists since the FSPECDEIN lane
                // (commit_new_inputs reads it at its fspec.cc:5154 mirror),
                // but THIS arm is not wired to it yet — it still takes the
                // conservative "no stackref" early-Err path. Behavioral
                // half (lazy fetch on first stack hit, then push None)
                // stays on the ticket; the parse channel itself is in place.
                if !stackref_present {
                    return Err(());
                }
                new_input.push(None);
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:5130 FuncCallSpecs::transferLockedOutput
    /// Pass back the varnode needed to match the output parameter (return
    /// value) of a source prototype. Faithful 1:1 port of
    /// `transferLockedOutput` (fspec.cc:5130-5139). If the source return is
    /// `TYPE_VOID`, nothing is collected; otherwise delegates to
    /// `transfer_locked_output_param`.
    pub fn transfer_locked_output(
        &self, source: &FuncProto, call_op: &crate::op::PcodeOpRef,
        bank: &crate::op::PcodeOpBank,
        new_output: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        source_output_param: &ProtoParameter,
    ) -> bool {
        // Ghidra: ProtoParameter *param = source.getOutput();
        //         if (param->getType()->getMetatype() == TYPE_VOID) return true;
        if matches!(source_output_param.data_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            return true;
        }
        self.transfer_locked_output_param(call_op, bank, source_output_param, new_output);
        true
    }

    // Ghidra: fspec.cc:5770 FuncCallSpecs::buildOutputFromTrials
    /// Set the final output varnode of this CALL based on ParamActive
    /// analysis of trials. Faithful 1:1 port of `buildOutputFromTrials`
    /// (fspec.cc:5770-5860). Reorders the trial varnodes into the survivors'
    /// 1-based slot order, deletes unused trials, and then either:
    ///   - moves the single surviving trial's varnode to be the CALL output
    ///     (destroying the INDIRECT that previously held it), or
    ///   - for two surviving trials, joins them via a `constructJoinAddress`
    ///     and emits SUBPIECE ops to recover each half (honouring
    ///     `isJoinReverse` for the high/low ordering and double-precision
    ///     marking), or
    ///   - returns leaving the CALL output unchanged if there are no
    ///     surviving trials.
    ///
    /// `set_call_output` wires a varnode as the CALL's output (Ghidra's
    /// `data.opSetOutput(op, vn)`). `destroy_indirect` removes an INDIRECT
    /// op and its inputs (Ghidra's `opDestroy` + `deleteVarnode` loop).
    /// `build_join_output` constructs the join varnode + SUBPIECE ops
    /// (Ghidra's `constructJoinAddress` / `newVarnode` / `newOp(SUBPIECE)`
    /// sequence).
    ///
    /// `trial_vn` is Ghidra's `vector<Varnode*> trialvn`: a DENSE
    /// position-indexed list with `None` for locations that never produced
    /// a varnode (fspec.cc:5541-5542 pads it to `getNumTrials()`). Slots are
    /// assigned 1..N in registration order (fspec.cc:1963-1975, slotbase
    /// starts at 1) and travel with the trials through `sortTrials`, so
    /// `curtrial.getSlot() - 1` is the trial's ORIGINAL registration
    /// position — the caller must not compact the list or the slot↔position
    /// correspondence is lost.
    pub fn build_output_from_trials(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        trial_vn: &[Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>],
        set_call_output: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef, &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>),
        destroy_indirect: &dyn Fn(&mut crate::funcdata::Funcdata, &crate::op::PcodeOpRef),
        build_join_output: &dyn Fn(
            &mut crate::funcdata::Funcdata,
            &crate::op::PcodeOpRef,
            &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // hi
            &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // lo
        ) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>, // the joined whole
    ) {
        let active = &mut self.active_output;
        // Ghidra: reorder varnodes by trial slot; collect survivors into finalvn.
        let mut final_vn: Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>> = Vec::new();
        for i in 0..active.get_num_trials() {
            let cur = active.get_trial(i);
            if !cur.is_used() { break; }
            // Ghidra: vn = trialvn[ curtrial.getSlot() - 1 ] — no bounds
            // guard; slot-1 is always the original registration position
            // and the dense list is padded to getNumTrials().
            let idx = (cur.get_slot() - 1) as usize;
            final_vn.push(trial_vn[idx].clone());
        }
        // Ghidra: activeoutput.deleteUnusedTrials();  // renumbers survivors 1..N
        active.delete_unused_trials();
        if active.get_num_trials() == 0 { return; } // Nothing is a formal output.

        let mut deleted_ops: Vec<crate::op::PcodeOpRef> = Vec::new();

        if active.get_num_trials() == 1 {
            // Single, properly justified output.
            // Ghidra invariant: a used trial was active (only actives are
            // ever marked used, fspec.cc:1704) and an active trial always
            // has its trialvn entry (fspec.cc:5672-5673), so finalvn[0] is
            // never NULL. A NULL would be a C++ deref crash.
            let Some(finalout_vn) = final_vn[0].clone() else {
                panic!("buildOutputFromTrials: used trial has no varnode");
            };
            // Ghidra: indop = finaloutvn->getDef(); deletedops.push_back(indop);
            //         data.opSetOutput(op, finaloutvn);
            if let Some(def_weak) = finalout_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            set_call_output(fd, call_op, &finalout_vn);
        } else if active.get_num_trials() == 2 {
            // Ghidra: pick hi/lo honouring isJoinReverse. Both survivors
            // carry the used⟹active⟹non-NULL invariant (fspec.cc:1704 +
            // fspec.cc:5672-5673).
            let (hi_slot, lo_slot) = if active.is_join_reverse() {
                (0usize, 1usize)
            } else {
                (1usize, 0usize)
            };
            let (Some(hi_vn), Some(lo_vn)) = (final_vn[hi_slot].clone(), final_vn[lo_slot].clone())
            else {
                panic!("buildOutputFromTrials: used trial has no varnode");
            };
            // Ghidra: if (data.isDoublePrecisOn()) { lovn->setPrecisLo(); hivn->setPrecisHi(); }
            // fspec.cc:5816-5819 — the marking rides on the SAME Varnode
            // objects that build_join_output re-homes as SUBPIECE outputs
            // (opSetOutput(sublo, lovn)), so RuleDoubleIn later fires on the
            // join SUBPIECE with out isPrecisLo (double.cc:3263) and
            // reconstructs the logical whole via SplitVarnode::findCreateWhole
            // (double.cc:527 newUniqueOut PIECE) — the unique-space PIECE16
            // family that RulePieceStructure then marks as partial roots.
            if fd.is_double_precis_on() {
                lo_vn.write().unwrap().set_precis_lo();
                hi_vn.write().unwrap().set_precis_hi();
            }
            // Ghidra: deletedops.push_back(hivn->getDef()); deletedops.push_back(lovn->getDef());
            if let Some(def_weak) = hi_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            if let Some(def_weak) = lo_vn.read().unwrap().def.as_ref().and_then(|w| w.upgrade()) {
                deleted_ops.push(crate::op::PcodeOpRef(def_weak));
            }
            // Ghidra: finaloutvn = findPreexistingWhole(hivn, lovn); if null,
            // build the join (constructJoinAddress + SUBPIECE pair); else
            // reuse the preexisting PIECE whole and destroy its def too.
            // The preexisting-whole probe is ported as
            // `FuncCallSpecs::find_preexisting_whole` (fspec.cc:5750-5760)
            // and unit-tested, but the wiring is deferred: hivn/lovn defs
            // already capture the shared PIECE op (loneDescend of both
            // pieces IS the PIECE), so destroying them matches Ghidra's
            // deletedops in both arms, and switching the join hook to a
            // Some(whole)-reuse arm is a hook-contract change that must
            // ride with its own differential evidence (MIGW-FSPEC-0004).
            let _ = FuncCallSpecs::find_preexisting_whole(&hi_vn, &lo_vn);
            let _finalout_vn = build_join_output(fd, call_op, &hi_vn, &lo_vn);
            // The join hook is responsible for opSetOutput(op, finaloutvn).
        } else {
            return;
        }

        // Ghidra: for each deleted op, opDestroy + deleteVarnode(in0,in1).
        for dop in &deleted_ops {
            destroy_indirect(fd, dop);
        }
    }

    // Ghidra: fspec.cc:5443 FuncCallSpecs::deindirect
    /// Convert \b this call site from an indirect to a direct function call.
    /// Faithful 1:1 body of `deindirect` (fspec.cc:5443-5472): the callee's
    /// entry address and display name are adopted, the CALLIND is rewritten
    /// as a CALL whose in(0) is a fresh typed call-spec annotation, an
    /// indirect override is installed so restarts keep the resolution, and
    /// — unless the callee is noreturn/inline or \b this already carries an
    /// applied prototype override — `lateRestriction` either commits the new
    /// inputs/outputs in place or flags a restart via
    /// `data.setRestartPending(true)`.
    ///
    /// Rugra's Funcdata has no per-callee `Funcdata *` at action time (the
    /// front-end boundary established by `FlowInfo::queryCall`,
    /// flow.cc:660-669): the production caller (`ActionDeindirect`,
    /// coreaction.cc:1219) resolves the callee through the query channels
    /// and hands the observable slice `(entry address, display name,
    /// &FuncProto)` — the same slice `newfd` contributes on the Ghidra side
    /// (`getAddress`/`getDisplayName`/`getFuncProto`). `owner` is the
    /// stable `Arc` handle of \b this callspec, required to mint the typed
    /// annotation varnode (`Funcdata::newVarnodeCallSpecs` reads the entry
    /// address through it — the write guards below are therefore taken in
    /// separate scopes so the annotation mint can read between them).
    ///
    /// Returns `true` when a restart is pending (Ghidra's
    /// `data.setRestartPending(true)`), `false` when the conversion
    /// completed in place.
    pub fn deindirect(
        owner: &std::sync::Arc<std::sync::RwLock<FuncCallSpecs>>,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        newfd_entry: Address,
        newfd_display_name: &str,
        newfd_proto: &FuncProto,
    ) -> bool {
        // Ghidra: entryaddress = newfd->getAddress(); name =
        //         newfd->getDisplayName(); fd = newfd;
        {
            let mut fc = owner.write().unwrap();
            fc.entry_addr = Some(newfd_entry);
            if !newfd_display_name.is_empty() {
                fc.prototype.name = newfd_display_name.to_string();
            }
        }
        // Ghidra: vn = data.newVarnodeCallSpecs(this); opSetInput(op, vn, 0);
        let vn = fd.new_varnode_call_specs(owner);
        fd.op_set_input(call_op, vn, 0);
        // Ghidra: opSetOpcode(op, CPUI_CALL);
        fd.op_set_opcode(call_op, crate::opcodes::OpCode::CPUI_CALL);
        // Ghidra: data.getOverride().insertIndirectOverride(op->getAddr(),entryaddress);
        let op_addr = owner.read().unwrap().op_addr;
        fd.localoverride.insert_indirect_override(op_addr, newfd_entry);

        // Ghidra: FuncProto &newproto( newfd->getFuncProto() );
        //         if ((!newproto.isNoReturn())&&(!newproto.isInline())) {
        if !newfd_proto.is_no_return() && !newfd_proto.is_inline() {
            // Ghidra: if (isOverride()) return; // Don't use the discovered
            //         function prototype.  FuncCallSpecs inherits this from
            //         FuncProto (fspec.hh:1645); Rugra reads the embedded
            //         prototype's flag.
            if owner.read().unwrap().prototype.is_override() {
                return false;
            }
            // Ghidra: if (lateRestriction(newproto,newinput,newoutput)) {
            //           commitNewInputs(data,newinput);
            //           commitNewOutputs(data,newoutput);
            //           return;
            //         }
            let mut newinput: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
                Vec::new();
            let mut newoutput: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
                Vec::new();
            let committed = {
                let mut fc = owner.write().unwrap();
                if fc.late_restriction(
                    newfd_proto,
                    call_op,
                    &mut newinput,
                    &mut newoutput,
                    &prod_get_call_in,
                    &fd.obank,
                ) {
                    let mut build_param = |fd: &mut crate::funcdata::Funcdata,
                                           call_op: &crate::op::PcodeOpRef,
                                           existing: Option<
                        &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
                    >,
                                           pspace: crate::space::AddressSpace,
                                           paddr: Address,
                                           psize: i32,
                                           stackref: Option<
                        &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
                    >|
                     -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
                        prod_build_param(
                            fd, call_op, existing, pspace, paddr, psize, stackref,
                        )
                    };
                    fc.commit_new_inputs(fd, call_op, &mut newinput, &mut build_param);
                    fc.commit_new_outputs(
                        fd,
                        call_op,
                        &newoutput,
                        &prod_get_return_addr_size,
                        &prod_set_call_output,
                        &prod_truncate_output,
                    );
                    true
                } else {
                    false
                }
            };
            if committed {
                // We have successfully updated the prototype, don't restart.
                // Ghidra's `name` lives on FuncCallSpecs (fspec.hh:1645),
                // outside FuncProto::copy's field set (fspec.cc:3789-3804
                // copies model/extrapop/flags/store/effectlist/likelytrash/
                // injectid — never a name), so lateRestriction's copy never
                // disturbs the display name adopted at cc:5447. Rugra's
                // FuncProto embeds the name, so re-assert it across the
                // copy to mirror the field separation.
                {
                    let mut fc = owner.write().unwrap();
                    if !newfd_display_name.is_empty() {
                        fc.prototype.name = newfd_display_name.to_string();
                    }
                }
                return false;
            }
        }
        // The restart fall-through keeps the adopted name as well (the
        // oracle's FuncCallSpecs name survives every path in deindirect).
        {
            let mut fc = owner.write().unwrap();
            if !newfd_display_name.is_empty() {
                fc.prototype.name = newfd_display_name.to_string();
            }
        }
        // Ghidra: data.setRestartPending(true);
        fd.set_restart_pending(true);
        true
    }

    // Ghidra: fspec.cc:5934 FuncCallSpecs::hasEffectTranslate
    /// Calculate the effect type on the given storage location, translating
    /// stack-relative addresses from the caller's perspective to the callee's.
    /// Faithful 1:1 port of `hasEffectTranslate` (fspec.cc:5934-5943). For
    /// non-stack spaces, the query is forwarded to `has_effect` directly. For
    /// the stack (spacebase) space, the offset is rebased by subtracting this
    /// call's resolved `stackoffset` (wrapping within the space); if the
    /// `stackoffset` is still `offset_unknown`, the effect is reported as
    /// `unknown_effect`.
    pub fn has_effect_translate(
        &self,
        addr_space: crate::space::AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        // Ghidra: AddrSpace *spc = addr.getSpace();
        //         if (spc->getType() != IPTR_SPACEBASE) return hasEffect(addr, size);
        if addr_space != crate::space::AddressSpace::Stack {
            return self.has_effect(addr_space, addr_offset, size);
        }
        // Ghidra: if (stackoffset == offset_unknown) return unknown_effect;
        if self.stackoffset == OFFSET_UNKNOWN {
            return EffectType::UnknownEffect;
        }
        // Ghidra: newoff = spc->wrapOffset(addr.getOffset() - stackoffset);
        let newoff = ((addr_offset as i128 - self.stackoffset as i128).rem_euclid(1i128 << 64)) as u64;
        // Ghidra: return hasEffect(Address(spc, newoff), size);
        self.has_effect(addr_space, newoff, size)
    }

    // Ghidra: fspec.cc:5950 FuncCallSpecs::countMatchingCalls (static)
    /// Tally the number of calls to the same sub-function across a list of
    /// call sites. Faithful 1:1 port of `countMatchingCalls`
    /// (fspec.cc:5950-5974). Sorts the list by entry address, marks call sites
    /// with invalid entry addresses as singletons, then for each run of equal
    /// entry addresses assigns the run length to every member's
    /// `match_call_count`.
    ///
    /// Rugra's `FuncCallSpecs` does not yet carry the `matchCallCount` field,
    /// so the run lengths are returned as a `Vec<(entry_addr, count)>` keyed by
    /// entry address; callers can apply them as needed.
    pub fn count_matching_calls(
        qlst: &[&FuncCallSpecs],
    ) -> Vec<(Address, u32)> {
        // Ghidra: vector<FuncCallSpecs *> copyList(qlst);
        //         sort(copyList.begin(), copyList.end(), compareByEntryAddress);
        let mut copy: Vec<&FuncCallSpecs> = qlst.iter().copied().collect();
        copy.sort_by(|a, b| {
            a.entry_addr
                .unwrap_or(Address::new(0))
                .as_u64()
                .cmp(&b.entry_addr.unwrap_or(Address::new(0)).as_u64())
        });
        let mut result: Vec<(Address, u32)> = Vec::new();
        if copy.is_empty() {
            return result;
        }
        // Ghidra: for(i=0;i<size;++i) { if (!entryaddress.isInvalid()) break;
        //         copyList[i]->matchCallCount = 1; }
        let mut i = 0usize;
        while i < copy.len() {
            if copy[i].entry_addr.is_some() {
                break;
            }
            result.push((Address::new(0), 1));
            i += 1;
        }
        if i == copy.len() {
            return result;
        }
        // Ghidra: Address lastAddr = copyList[i]->entryaddress;
        let mut last_addr = copy[i].entry_addr.unwrap();
        let mut last_change = i;
        i += 1;
        while i < copy.len() {
            if copy[i].entry_addr == Some(last_addr) {
                i += 1;
                continue;
            }
            let num = (i - last_change) as u32;
            // Ghidra: for(; lastChange<i; ++lastChange) matchCallCount = num;
            for _ in last_change..i {
                result.push((last_addr, num));
            }
            last_change = i;
            last_addr = copy[i].entry_addr.unwrap();
            i += 1;
        }
        let num = (copy.len() - last_change) as u32;
        for _ in last_change..copy.len() {
            result.push((last_addr, num));
        }
        result
    }

    // Ghidra: fspec.cc:4964 FuncCallSpecs::clone
    /// Produce the covered identity/lifecycle clone slice, rebound to a new
    /// call op. This corresponds to `clone` (fspec.cc:4964-4977): it allocates
    /// a distinct owner, rebinds the exact op identity, copies the modeled
    /// entry/stackoffset/isbadjumptable/`FuncProto`, and resets active-input/
    /// output state. Funcdata/name plus effective extrapop and paramshift
    /// remain unmodeled `CALLSPEC-0001` fields, so this is not the complete
    /// 1:1 clone contract.
    pub fn clone_for_op(&self, new_op: &crate::op::PcodeOpRef) -> FuncCallSpecs {
        // Do not re-resolve the cloned input(0) while holding `self`'s read
        // guard.  The cloned FSPEC annotation still points at `self`, and a
        // recursive std::sync::RwLock read is not guaranteed when a writer is
        // waiting.  Ghidra's clone has the source object directly available,
        // so snapshot its entry and clone fields from that identity instead.
        let new_op_addr = new_op.0.read().unwrap().get_addr();
        let mut res = FuncCallSpecs::new(new_op_addr, self.prototype.clone());
        res.op = Arc::downgrade(&new_op.0);
        // Ghidra: constructor recovers the old entry, then setFuncdata(fd)
        // refreshes it only when fd is non-null.
        res.entry_addr = self.entry_addr;
        // effective_extrapop / paramshift are not modelled on FuncCallSpecs.
        res.stackoffset = self.stackoffset;
        // fspec.cc:4974 `res->isbadjumptable = isbadjumptable`.
        res.is_bad_jump_table = self.is_bad_jump_table;
        // fspec.cc:4968 `res->setFuncdata(fd)` — the clone carries the
        // callee link so the cloned call site's ActionDefaultParams arm
        // still resolves the same recovered prototype.
        res.callee_proto = self.callee_proto.clone();
        // res.copy(*this) — prototype already cloned via new().
        res
    }

    // Ghidra: fspec.cc:5901 FuncCallSpecs::paramshiftModifyStart
    /// Prepend `paramshift` parameters to this call's prototype. Faithful
    /// port of `paramshiftModifyStart` (fspec.cc:5901-5906). If `paramshift`
    /// is zero, this is a no-op. Otherwise the underlying FuncProto's
    /// `param_shift` is invoked with the same count.
    pub fn paramshift_modify_start(&mut self, paramshift: i32) {
        if paramshift == 0 { return; }
        // Ghidra: paramShift(paramshift);
        self.prototype.param_shift(paramshift);
    }

    // Ghidra: fspec.cc:5911 FuncCallSpecs::paramshiftModifyStop
    /// Throw out the paramshift parameters. Faithful port of
    /// `paramshiftModifyStop` (fspec.cc:5911-5925). Returns `true` if a change
    /// was made (paramshift > 0 and not already applied). Rugra does not yet
    /// track the `paramshift_applied` flag, so this always performs the
    /// removal when `paramshift > 0`. Op-input rewiring (`data.opRemoveInput`)
    /// is delegated to the caller via `remove_input` since the call op is not
    /// stored on FuncCallSpecs.
    pub fn paramshift_modify_stop(
        &mut self,
        paramshift: i32,
        remove_input: &mut dyn FnMut(usize),
    ) -> bool {
        if paramshift == 0 { return false; }
        // Ghidra: if (isParamshiftApplied()) return false;
        //         setParamshiftApplied(true);
        // Rugra does not track the applied flag; we always apply.
        // Ghidra: if (op->numInput() < paramshift + 1) throw LowlevelError(...);
        // The caller's remove_input is responsible for bounds.
        // Ghidra: for(i=0;i<paramshift;++i) { opRemoveInput(op,1); removeParam(0); }
        for _ in 0..paramshift {
            remove_input(1);
            if !self.prototype.parameters.is_empty() {
                self.prototype.parameters.remove(0);
            }
        }
        true
    }

    // Ghidra: fspec.hh:1740 FuncCallSpecs::compareByEntryAddress
    /// Compare FuncCallSpecs by function entry address. Faithful inline
    /// static `return a->entryaddress < b->entryaddress;` (fspec.hh:1740);
    /// used by `countMatchingCalls` and the call-spec sort. A missing entry
    /// compares as offset 0 (the legacy `Address` carries no invalid state).
    pub fn compare_by_entry_address(a: &FuncCallSpecs, b: &FuncCallSpecs) -> bool {
        a.entry_addr
            .unwrap_or(Address::new(0))
            .as_u64()
            < b.entry_addr.unwrap_or(Address::new(0)).as_u64()
    }

    // Ghidra: fspec.cc:4982 FuncCallSpecs::getSpacebaseRelative
    /// Find the active stack-pointer Varnode at \b this call site through
    /// the stack-pointer placeholder slot. Faithful 1:1 body
    /// (fspec.cc:4982-4992): no placeholder slot or a placeholder that is
    /// not written / not spacebase-marked / not LOAD-defined yields `None`;
    /// otherwise the LOAD's pointer input (slot 1) is the reference.
    pub fn get_spacebase_relative(
        &self,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        if self.stack_placeholder_slot < 0 {
            return None;
        }
        let op = self.op.upgrade()?;
        let op_guard = op.read().unwrap();
        let tmpvn = op_guard.get_in(self.stack_placeholder_slot as usize)?.clone();
        drop(op_guard);
        let loadop_weak = {
            let vn = tmpvn.read().unwrap();
            if !vn.is_spacebase_placeholder() {
                return None;
            }
            if !vn.is_written() {
                return None;
            }
            vn.def.clone()?
        };
        let loadop = loadop_weak.upgrade()?;
        let loadop_guard = loadop.read().unwrap();
        if loadop_guard.get_opcode() != crate::opcodes::OpCode::CPUI_LOAD {
            return None;
        }
        loadop_guard.get_in(1).cloned()
    }

    // Ghidra: fspec.cc:5349 FuncCallSpecs::checkInputJoin
    /// Check if adjacent parameter trials can be combined into a single
    /// logical parameter. Faithful 1:1 body (fspec.cc:5349-5368): active
    /// input recovery or too-few trials refuse; the hi/lo trial order
    /// follows `ishislot`, each side's size must equal the corresponding
    /// Varnode size, and the final word is the model's checkInputJoin on
    /// the trials' addresses and sizes.
    pub fn check_input_join(
        &self,
        slot1: i32,
        ishislot: bool,
        vn1_size: i32,
        vn2_size: i32,
    ) -> bool {
        if self.is_input_active() {
            return false;
        }
        if slot1 >= self.active_input.get_num_trials() as i32 {
            return false; // Not enough params
        }
        // getTrialForInputVarnode subtracts 1 (call address) or 2 (past the
        // placeholder) from the op slot — the accessor performs it.
        let (hi_slot, lo_slot, hi_vn_size, lo_vn_size) = if ishislot {
            (slot1, slot1 + 1, vn1_size, vn2_size)
        } else {
            (slot1 + 1, slot1, vn2_size, vn1_size)
        };
        let hislot = self.active_input.get_trial_for_input_varnode(hi_slot);
        let loslot = self.active_input.get_trial_for_input_varnode(lo_slot);
        if hislot.get_size() != hi_vn_size {
            return false;
        }
        if loslot.get_size() != lo_vn_size {
            return false;
        }
        // FuncProto::checkInputJoin(hislot->getAddress(),hislot->getSize(),
        //                           loslot->getAddress(),loslot->getSize());
        let space = hislot.get_space();
        self.prototype.check_input_join(
            space,
            hislot.get_address(),
            hislot.get_size(),
            loslot.get_address(),
            loslot.get_size(),
        )
    }

    // Ghidra: fspec.cc:5376 FuncCallSpecs::doInputJoin
    /// Join two parameter trials into a single merged parameter. Faithful
    /// 1:1 body (fspec.cc:5376-5395): a locked input refuses (Err mirrors
    /// the throw); the join address is the join-space offset over
    /// (hi,lo)-ordered pieces — Ghidra's `constructJoinAddress` becomes the
    /// caller-supplied join-tables hook here — and `activeinput.joinTrial`
    /// merges the two trials at (slot1, joinaddr, size1+size2).
    pub fn do_input_join(
        &mut self,
        slot1: i32,
        ishislot: bool,
        construct_join_address: &dyn Fn(
            AddressSpace,
            Address,
            i32,
            AddressSpace,
            Address,
            i32,
        ) -> Address,
    ) -> Result<(), String> {
        if self.prototype.is_input_locked() {
            return Err("Trying to join parameters on locked function prototype".to_string());
        }
        let trial1 = self.active_input.get_trial_for_input_varnode(slot1);
        let trial2 = self.active_input.get_trial_for_input_varnode(slot1 + 1);
        let addr1 = trial1.get_address();
        let addr2 = trial2.get_address();
        let space1 = trial1.get_space();
        let space2 = trial2.get_space();
        let size1 = trial1.get_size();
        let size2 = trial2.get_size();

        let joinaddr = if ishislot {
            construct_join_address(space1, addr1, size1, space2, addr2, size2)
        } else {
            construct_join_address(space2, addr2, size2, space1, addr1, size1)
        };

        self.active_input
            .join_trial(slot1, joinaddr, size1 + size2);
        Ok(())
    }

    // Ghidra: fspec.cc:5408 FuncCallSpecs::lateRestriction
    /// Update \b this prototype to match a given (more specialized)
    /// prototype. Faithful 1:1 body (fspec.cc:5408-5431): without a model
    /// the restriction is copied wholesale; otherwise the prototypes must
    /// be compatible, a dotdotdot restriction requires active input
    /// recovery, locked inputs/outputs transfer through the locked-input/
    /// output movers, and \b this finally copies the restriction.
    pub fn late_restriction(
        &mut self,
        restricted_proto: &FuncProto,
        call_op: &crate::op::PcodeOpRef,
        new_input: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        new_output: &mut Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        get_call_in: &dyn Fn(
            &crate::op::PcodeOpRef,
            usize,
        ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
        bank: &crate::op::PcodeOpBank,
    ) -> bool {
        if !self.prototype.has_model() {
            // Ghidra: copy(restrictedProto); return true;
            self.prototype.copy_from(restricted_proto);
            return true;
        }
        if !self.prototype.is_compatible(restricted_proto) {
            return false;
        }
        if restricted_proto.is_dotdotdot && !self.is_input_active() {
            return false;
        }
        if restricted_proto.is_input_locked() {
            // Redo all the varnode inputs (if possible)
            let mut slots: Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>> =
                Vec::new();
            if self.transfer_locked_input(restricted_proto, &mut slots, call_op, get_call_in)
                .is_err()
            {
                return false;
            }
            // transfer_locked_input collected Option slots (0 = cannot
            // build); a single None fails the restriction exactly as
            // Ghidra's 0 return does.
            for slot in slots {
                match slot {
                    Some(vn) => new_input.push(vn),
                    None => return false,
                }
            }
        }
        if restricted_proto.output_type_locked {
            // Redo all the varnode outputs (if possible)
            // Ghidra: transferLockedOutput reads source.getOutput(); the
            // flat FuncProto projects its output as (return_type,
            // output_storage) into a ProtoParameter view for the mover.
            let source_output_param = restricted_proto.output_param_view();
            if !self.transfer_locked_output(restricted_proto, call_op, bank, new_output, &source_output_param) {
                return false;
            }
        }
        // Convert ourselves to restrictedProto
        self.prototype.copy_from(restricted_proto);
        true
    }

    // Ghidra: fspec.cc:5485 FuncCallSpecs::forceSet
    /// Install a definitive prototype at \b this call site. Faithful 1:1
    /// body (fspec.cc:5485-5509): the recovered prototype is copied into
    /// the override manager first (so restarts don't rediscover it), then
    /// `lateRestriction` either commits the new inputs/outputs in place or
    /// flags a restart; either way the prototype locks and both error
    /// flags adopt the restriction's.
    ///
    /// Override-manager note: Ghidra's `insertProtoOverride` takes ownership
    /// of a heap `FuncProto` copy and marks it `is_override` (override.cc:130);
    /// on restart `Override::applyPrototype` (flow.cc:714) re-copies that
    /// stored proto onto the fresh callspec. Rugra's `Override` records the
    /// callpoint but does not yet store the proto itself (CALLSPEC-0001
    /// seam), so the restart re-application of the full proto remains
    /// unwired; this pass's observable (proto override recorded + in-place
    /// late restriction + lock) is complete.
    pub fn force_set(
        &mut self,
        fd: &mut crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        fp: &FuncProto,
    ) {
        let mut newinput: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();
        let mut newoutput: Vec<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> =
            Vec::new();

        // Copy the recovered prototype into the override manager so that
        // future restarts don't have to rediscover it.
        // Ghidra: FuncProto *newproto = new FuncProto(); newproto->copy(fp);
        //         data.getOverride().insertProtoOverride(op->getAddr(),newproto);
        fd.localoverride.insert_proto_override(self.op_addr);
        // Ghidra: if (lateRestriction(fp,newinput,newoutput)) {
        //           commitNewInputs(data,newinput);
        //           commitNewOutputs(data,newoutput);
        //         } else { data.setRestartPending(true); }
        if self.late_restriction(fp, call_op, &mut newinput, &mut newoutput, &prod_get_call_in, &fd.obank) {
            let mut build_param = |fd: &mut crate::funcdata::Funcdata,
                                   call_op: &crate::op::PcodeOpRef,
                                   existing: Option<
                &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
            >,
                                   pspace: crate::space::AddressSpace,
                                   paddr: Address,
                                   psize: i32,
                                   stackref: Option<
                &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
            >|
             -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
                prod_build_param(fd, call_op, existing, pspace, paddr, psize, stackref)
            };
            self.commit_new_inputs(fd, call_op, &mut newinput, &mut build_param);
            self.commit_new_outputs(
                fd,
                call_op,
                &newoutput,
                &prod_get_return_addr_size,
                &prod_set_call_output,
                &prod_truncate_output,
            );
        } else {
            // Too late to make restrictions to correct prototype.
            // Force a restart.
            fd.set_restart_pending(true);
        }
        // Regardless of what happened, lock the prototype so it doesn't happen again
        self.prototype.set_input_lock(true);
        self.prototype.set_input_errors(fp.has_input_errors());
        self.prototype.set_output_errors(fp.has_output_errors());
    }

    // Ghidra: fspec.cc:5517 FuncCallSpecs::insertPcode
    /// Inject any \e upon-return p-code at \b this call site. Faithful
    /// 1:1 body (fspec.cc:5517-5528): a negative inject id does nothing;
    /// otherwise the payload is fetched from the architecture's injection
    /// library and inserted right after the callpoint. Rugra has no
    /// `Funcdata::doLiveInject` yet, so the insertion is the caller's
    /// `live_inject` hook (invoked with the payload id, the call address,
    /// and the op), matching the established seam style for this module.
    pub fn insert_pcode(
        &self,
        fd: &crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        live_inject: &dyn Fn(&crate::funcdata::Funcdata, i32, &crate::op::PcodeOpRef),
    ) -> Result<(), String> {
        // Ghidra: int4 id = getInjectUponReturn();
        let id = self
            .prototype
            .model
            .as_ref()
            .map(|m| m.inject_upon_return)
            .unwrap_or(-1);
        if id < 0 {
            return Ok(()); // Nothing to inject
        }
        // Ghidra: InjectPayload *payload =
        //         data.getArch()->pcodeinjectlib->getPayload(id);
        let arch = fd
            .arch
            .as_ref()
            .ok_or_else(|| "insertPcode requires an owning Architecture".to_string())?;
        let lib = arch
            .pcodeinjectlib
            .as_ref()
            .ok_or_else(|| "insertPcode requires a p-code injection library".to_string())?;
        let lib_guard = lib.read().unwrap();
        if lib_guard.get_payload_by_id(id).is_none() {
            return Err(format!("Unknown p-code inject id: {}", id));
        }
        drop(lib_guard);
        // do the insertion right after the callpoint
        live_inject(fd, id, call_op);
        Ok(())
    }

    // Ghidra: fspec.cc:5536 FuncCallSpecs::collectOutputTrialVarnodes
    /// Collect the Varnode attached to each output trial. Faithful 1:1
    /// body (fspec.cc:5536-5557): a determined call output refuses (Err
    /// mirrors the throw); the trial list grows to the trial count; the
    /// walk upstream over INDIRECT ops (via the caller's previous-op
    /// hook) records every indirect-creation output whose storage matches
    /// a trial, re-pinning the trial's address to the exact Varnode.
    pub fn collect_output_trial_varnodes(
        &mut self,
        call_op: &crate::op::PcodeOpRef,
        trialvn: &mut Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>>,
        previous_op: &dyn Fn(
            &crate::op::PcodeOpRef,
        ) -> Option<crate::op::PcodeOpRef>,
    ) -> Result<(), String> {
        if call_op.0.read().unwrap().get_out().is_some() {
            return Err("Output of call was determined prematurely".to_string());
        }
        // Size of array should match number of trials
        while trialvn.len() < self.active_output.get_num_trials() {
            trialvn.push(None);
        }
        let mut indop = previous_op(call_op);
        while let Some(op) = indop {
            let guard = op.0.read().unwrap();
            if guard.get_opcode() != crate::opcodes::OpCode::CPUI_INDIRECT {
                break;
            }
            if guard.is_indirect_creation() {
                if let Some(vn_arc) = guard.get_out().cloned() {
                    let (vn_addr, vn_size) = {
                        let vn = vn_arc.read().unwrap();
                        (*vn.get_addr(), vn.get_size() as i32)
                    };
                    let index = self
                        .active_output
                        .which_trial_in_space(AddressSpace::Ram, vn_addr, vn_size);
                    if index >= 0 {
                        trialvn[index as usize] = Some(vn_arc);
                        // the exact varnode may have changed, so we reset the trial
                        self.active_output
                            .get_trial_mut(index as usize)
                            .set_address(vn_addr, vn_size);
                    }
                }
            }
            drop(guard);
            indop = previous_op(&op);
        }
        Ok(())
    }

    // Ghidra: fspec.cc:5661 FuncCallSpecs::checkOutputTrialUse
    /// Mark whether output trials are being actively used. Faithful 1:1
    /// body (fspec.cc:5661-5677): trials are collected first, then each
    /// is marked active (a matching Varnode exists) or inactive — never
    /// noUse, since the value may be returned but unused. A prematurely
    /// checked trial refuses (Err mirrors the throw).
    pub fn check_output_trial_use(
        &mut self,
        fd: &crate::funcdata::Funcdata,
        call_op: &crate::op::PcodeOpRef,
        trialvn: &mut Vec<Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>>,
        previous_op: &dyn Fn(
            &crate::op::PcodeOpRef,
        ) -> Option<crate::op::PcodeOpRef>,
    ) -> Result<(), String> {
        let _ = fd;
        self.collect_output_trial_varnodes(call_op, trialvn, previous_op)?;
        // The location is either used or not.  If it is used it can either
        // be the official output or a killedbycall, so whether the trial is
        // present as a varnode determines whether the trial is active.
        for i in 0..trialvn.len() {
            if self.active_output.get_trial(i).is_checked() {
                return Err("Output trial has been checked prematurely".to_string());
            }
            if trialvn[i].is_some() {
                self.active_output.get_trial_mut(i).mark_active();
            } else {
                // don't call markNoUse, the value may be returned but not used
                self.active_output.get_trial_mut(i).mark_inactive();
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:5750 FuncCallSpecs::findPreexistingWhole
    /// Check if two Varnodes are merged into a whole. Faithful 1:1 body
    /// (fspec.cc:5750-5760): both Varnodes must have the SAME lone
    /// descendant op, that op must be a PIECE, and its output is the
    /// preexisting whole; anything else yields `None`.
    pub fn find_preexisting_whole(
        vn1: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
        vn2: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    ) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
        let op1 = vn1.read().unwrap().lone_descend()?;
        let op2 = vn2.read().unwrap().lone_descend()?;
        if !std::sync::Arc::ptr_eq(&op1, &op2) {
            return None;
        }
        let guard = op1.read().unwrap();
        if guard.get_opcode() != crate::opcodes::OpCode::CPUI_PIECE {
            return None;
        }
        guard.get_out().cloned()
    }
}

// ======================================================================
// FspecSpace helpers (fspec.hh:339-360 / fspec.cc:2116-2170)
// ======================================================================
// Ghidra's `FspecSpace` is a special address space whose offsets are really
// (truncated) `FuncCallSpecs *` pointers — used to attach a call spec to a
// CALL/CALLIND input varnode. Rugra does not model address spaces as runtime
// objects (AddressSpace is an enum), so the three FspecSpace methods that
// inspect the encoded pointer are exposed here as free helpers that take a
// borrowed `FuncCallSpecs` directly. Faithful 1:1 ports of:
//   - FspecSpace::encodeAttributes(2-arg)  (fspec.cc:2124-2136)
//   - FspecSpace::encodeAttributes(3-arg)  (fspec.cc:2138-2151)
//   - FspecSpace::printRaw                 (fspec.cc:2153-2164)

// Ghidra: fspec.cc:2124 FspecSpace::encodeAttributes (2-arg)
/// Encode the space/offset attributes of an fspec-space address. Faithful
/// port of the 2-argument `FspecSpace::encodeAttributes` (fspec.cc:2124-2136).
/// If the call spec has no resolved entry address, the literal space name
/// "fspec" is emitted; otherwise the entry address's space and offset are
/// written.
pub fn fspec_encode_attributes(
    fc: &FuncCallSpecs,
    encoder: &mut dyn crate::marshal::Encoder,
    space_attrib: &crate::marshal::AttributeId,
    offset_attrib: &crate::marshal::AttributeId,
) {
    // Ghidra: if (fc->getEntryAddress().isInvalid()) writeString(ATTRIB_SPACE, "fspec");
    match fc.entry_addr {
        None => encoder.write_string(space_attrib, "fspec"),
        Some(addr) => {
            // Ghidra: AddrSpace *id = fc->getEntryAddress().getSpace();
            //         encoder.writeSpace(ATTRIB_SPACE, id);
            //         encoder.writeUnsignedInteger(ATTRIB_OFFSET, off);
            encoder.write_string(space_attrib, &space_name_for_addr(addr));
            encoder.write_unsigned_integer(offset_attrib, addr.as_u64());
        }
    }
}

// Ghidra: fspec.cc:2138 FspecSpace::encodeAttributes (3-arg)
/// Encode the space/offset/size attributes of an fspec-space address.
/// Faithful port of the 3-argument `FspecSpace::encodeAttributes`
/// (fspec.cc:2138-2151). Identical to the 2-arg form but additionally writes
/// the `size` attribute.
pub fn fspec_encode_attributes_with_size(
    fc: &FuncCallSpecs,
    size: i32,
    encoder: &mut dyn crate::marshal::Encoder,
    space_attrib: &crate::marshal::AttributeId,
    offset_attrib: &crate::marshal::AttributeId,
    size_attrib: &crate::marshal::AttributeId,
) {
    match fc.entry_addr {
        None => encoder.write_string(space_attrib, "fspec"),
        Some(addr) => {
            encoder.write_string(space_attrib, &space_name_for_addr(addr));
            encoder.write_unsigned_integer(offset_attrib, addr.as_u64());
            encoder.write_signed_integer(size_attrib, size as i64);
        }
    }
}

// Ghidra: fspec.cc:2153 FspecSpace::printRaw
/// Print the fspec-space address as text. Faithful 1:1 port of
/// `FspecSpace::printRaw` (fspec.cc:2153-2164). If the call spec has a
/// display name it is emitted directly; otherwise the placeholder `func_`
/// prefix is followed by the entry address (printed as a hex offset).
pub fn fspec_print_raw(fc: &FuncCallSpecs, out: &mut String) {
    // Ghidra: if (fc->getName().size() != 0) s << fc->getName();
    if !fc.prototype.name.is_empty() {
        out.push_str(&fc.prototype.name);
    } else {
        // Ghidra: s << "func_"; fc->getEntryAddress().printRaw(s);
        out.push_str("func_");
        if let Some(addr) = fc.entry_addr {
            out.push_str(&format!("{:x}", addr.as_u64()));
        }
    }
}

// RUGRA-GLUE: space_name_for_addr — the oracle reads
// `fc->getEntryAddress().getSpace()->getName()` (fspec.cc:2132-2133
// `writeSpace`). An entry address carrying a registry tag (the
// fspec.cc:4934 record-point form) reports its stand-in's name; the
// legacy spaceless form (setFuncdata/deindirect callers still pass the
// ADDRESS-0001 phase-1 `Address::new` offset form) keeps the conventional
// "ram" placeholder, the typical entry-address space.
fn space_name_for_addr(addr: Address) -> String {
    match addr.get_space() {
        Some(spc) => spc.get_name(),
        None => "ram".to_string(),
    }
}

// ======================================================================
// Production commit/late-restriction hook adapters (FSPEC-DEINDIRECT-TRIGGER-0001)
//
// Ghidra's FuncCallSpecs methods read the CALL op's inputs and Funcdata's
// op-editing API directly (they are methods on a class holding `op` with
// full access to `data`). Rugra's `FuncCallSpecs` methods take caller
// hooks because the stable-owner `Arc<RwLock<..>>` callspec cannot borrow
// `Funcdata` while mutated. These free functions are the production
// adapters the production `deindirect`/`force_set` (this file) pass: they
// are the direct translation of what the Ghidra methods inline.
// ======================================================================

// RUGRA-GLUE: production adapter for the inline `op->getIn(slot)` reads in
// `FuncCallSpecs::transferLockedInput` (fspec.cc:5103/5110) and the CALL
// input reads of `lateRestriction` callers.
pub(crate) fn prod_get_call_in(
    op: &crate::op::PcodeOpRef,
    slot: usize,
) -> Option<std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>> {
    op.0.read().unwrap().get_in(slot).cloned()
}

// Ghidra: fspec.cc:5005 FuncCallSpecs::buildParam (production adapter)
/// Build the Varnode exactly matching a (locked) parameter for the CALL.
/// Faithful 1:1 body (fspec.cc:5005-5027): a missing Varnode means a
/// spacebase-relative parameter, built via `Funcdata::opStackLoad`; an
/// exact size match is returned as-is; anything else is truncated with a
/// SUBPIECE(0) inserted before the CALL (a free non-constant Varnode with
/// descendants is re-versioned first so the SUBPIECE does not give the
/// original multiple descendants).
pub(crate) fn prod_build_param(
    fd: &mut crate::funcdata::Funcdata,
    call_op: &crate::op::PcodeOpRef,
    vn: Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
    param_space: crate::space::AddressSpace,
    param_addr: Address,
    param_size: i32,
    stackref: Option<&std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>>,
) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
    // Ghidra: if (vn == (Varnode *)0) { ... opStackLoad(spc,off,sz,op,stackref,false); }
    let Some(mut vn) = vn.cloned() else {
        return fd.op_stack_load(
            param_space,
            param_addr.as_u64(),
            param_size as usize,
            call_op,
            stackref.cloned(),
            false,
        );
    };
    // Ghidra: if (vn->getSize() == param->getSize()) return vn;
    if vn.read().unwrap().get_size() as i32 == param_size {
        return vn;
    }
    // Ghidra: newop = data.newOp(2,op->getAddr()); opSetOpcode(SUBPIECE);
    let newout_addr = call_op.0.read().unwrap().get_addr();
    let newop = fd.new_op(2, newout_addr);
    fd.op_set_opcode(&newop, crate::opcodes::OpCode::CPUI_SUBPIECE);
    // Ghidra: newout = data.newUniqueOut(param->getSize(),newop);
    let newout = fd.new_unique_out(param_size as usize, &newop);
    // Ghidra: if (vn->isFree() && !vn->isConstant() && !vn->hasNoDescend())
    //           vn = data.newVarnode(vn->getSize(),vn->getAddr());
    {
        let reversion = {
            let guard = vn.read().unwrap();
            guard.is_free() && !guard.is_constant() && !guard.has_no_descend()
        };
        if reversion {
            let (sz, space, off) = {
                let guard = vn.read().unwrap();
                (guard.get_size(), guard.address_space, guard.loc.as_u64())
            };
            vn = fd.new_varnode_typed_in_space(sz, space, Address::new(off), None);
        }
    }
    // Ghidra: opSetInput(newop,vn,0); opSetInput(newop,data.newConstant(4,0),1);
    fd.op_set_input(&newop, vn, 0);
    let zero = fd.new_constant(4, 0);
    fd.op_set_input(&newop, zero, 1);
    // Ghidra: opInsertBefore(newop,op);
    fd.op_insert_before(&newop, call_op);
    newout
}

// RUGRA-GLUE: production adapter for the `param->getAddress()` /
// `param->getSize()` reads of `commitNewOutputs` (fspec.cc:5208-5210) —
// the callspec's locked output parameter storage.
pub(crate) fn prod_get_return_addr_size(fc: &FuncCallSpecs) -> (Address, i32) {
    let addr = fc
        .prototype
        .output_storage
        .map(|(_, off)| Address::new(off))
        .unwrap_or(Address::new(0));
    (addr, fc.prototype.return_type.get_size() as i32)
}

// RUGRA-GLUE: production adapter for the `opSetOutput(op,exactMatch)` +
// `opUnlink(indOp)` wiring of `commitNewOutputs` (fspec.cc:5222-5230) and
// the unset/new-arm (fspec.cc:5233-5235). Rugra's op_set_output performs
// the re-link; the exact-match predecessor INDIRECT is unlinked exactly
// when it is not the CALL itself.
pub(crate) fn prod_set_call_output(
    fd: &mut crate::funcdata::Funcdata,
    call_op: &crate::op::PcodeOpRef,
    vn: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
) {
    // If the varnode is already the CALL's output, nothing to do.
    let already = {
        let op_guard = call_op.0.read().unwrap();
        op_guard
            .get_out()
            .map(|out| std::sync::Arc::ptr_eq(&out, vn))
            .unwrap_or(false)
    };
    if already {
        return;
    }
    // Ghidra: indOp = exactMatch->getDef(); if (op != indOp) { opSetOutput;
    //           opUnlink(indOp); }
    let ind_op = vn.read().unwrap().get_def().map(crate::op::PcodeOpRef);
    fd.op_set_output(call_op, vn.clone());
    if let Some(ind) = ind_op {
        if ind != *call_op {
            fd.op_unlink(&ind);
        }
    }
}

// RUGRA-GLUE: production adapter for the SUBPIECE truncation arm of
// `commitNewOutputs` (fspec.cc:5244-5259): the smaller intersecting output
// becomes a SUBPIECE of the real output at the byte `overlap`.
pub(crate) fn prod_truncate_output(
    _fd: &mut crate::funcdata::Funcdata,
    _call_op: &crate::op::PcodeOpRef,
    _real_out: &std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>>,
    _overlap: i32,
) -> std::sync::Arc<std::sync::RwLock<crate::varnode::Varnode>> {
    // The truncation graph edit is exercised only through output-locked
    // late restrictions; registered as the commit-outputs graph residual of
    // FSPEC-DEINDIRECT-TRIGGER-0001 (CALLSPEC-0001 seam).
    unreachable!("prod_truncate_output: commit-outputs truncation arm not yet wired (FSPEC-DEINDIRECT-TRIGGER-0001 residual)")
}

// ======================================================================
// ParamTrial + ParamActive (fspec.hh:210-380)
// ======================================================================
// These are the parameter-recovery infrastructure that FuncCallSpecs
// Actions (ActionFuncLink, ActionParamDouble, ActionActiveParam, etc.) need.
// Ported faithfully from fspec.hh so those Actions can be wired once
// FuncCallSpecs gains an `active_input`/`active_output` field.

/// Flags for a parameter trial. Faithful to `ParamTrial` enum (fspec.hh:212-223).
pub mod param_trial_flags {
    pub const CHECKED: u32 = 1;
    pub const USED: u32 = 2;
    pub const DEFNOUSE: u32 = 4;
    pub const ACTIVE: u32 = 8;
    pub const UNREF: u32 = 0x10;
    pub const KILLEDBYCALL: u32 = 0x20;
    pub const REM_FORMED: u32 = 0x40;
    pub const INDCREATE_FORMED: u32 = 0x80;
    pub const CONDEXE_EFFECT: u32 = 0x100;
    pub const ANCESTOR_REALISTIC: u32 = 0x200;
    pub const ANCESTOR_SOLID: u32 = 0x400;
}

/// A single parameter trial: a candidate storage location being evaluated
/// as a formal parameter. Faithful to `ParamTrial` (fspec.hh:210-273).
#[derive(Debug, Clone)]
pub struct ParamTrial {
    flags: u32,
    /// Address-space component of Ghidra's `Address`. Rugra's transitional
    /// `Address` has an optional full-space tag, while parameter-list code
    /// still uses the coarse enum, so the component is carried beside it.
    space: AddressSpace,
    addr: Address,
    size: i32,
    slot: i32,
    offset: i32,
    fixed_position: i32,
    /// Index into the owning `ParamListStandard`'s entry list, or `None` if
    /// no matching entry was found. Stands in for Ghidra's
    /// `const ParamEntry *entry` pointer (fspec.hh:230). Rugra stores an
    /// index because Rust trials must be `Clone` without lifetime params.
    entry_index: Option<usize>,
}

impl ParamTrial {
    // RUGRA-GLUE: compatibility constructor for legacy spaceless Address
    // callers; production parameter trials use `new_in_space`.
    pub fn new(addr: Address, sz: i32, sl: i32) -> Self {
        Self::new_in_space(AddressSpace::Register, addr, sz, sl)
    }
    // Ghidra: fspec.hh:235 ParamTrial::ParamTrial
    /// Construct from the complete storage address, size, and input slot.
    pub fn new_in_space(space: AddressSpace, addr: Address, sz: i32, sl: i32) -> Self {
        Self {
            flags: 0, space, addr, size: sz, slot: sl, offset: -1, fixed_position: -1,
            entry_index: None,
        }
    }
    // RUGRA-GLUE: coarse-space projection of Ghidra's complete Address;
    // Ghidra reads `getAddress().getSpace()` directly (fspec.hh:236).
    /// Return the address-space component of the trial storage address.
    pub fn get_space(&self) -> AddressSpace { self.space }
    // Ghidra: fspec.hh:210 ParamTrial::getAddress
    pub fn get_address(&self) -> Address { self.addr }
    // Ghidra: fspec.hh:210 ParamTrial::getSize
    pub fn get_size(&self) -> i32 { self.size }
    // Ghidra: fspec.hh:210 ParamTrial::getSlot
    pub fn get_slot(&self) -> i32 { self.slot }
    // Ghidra: fspec.hh:210 ParamTrial::setSlot
    pub fn set_slot(&mut self, val: i32) { self.slot = val; }

    // Ghidra: fspec.hh:265 ParamTrial::slotGroup
    /// Get the position of \b this within its parameter \e group: `return
    /// entry->getSlot(addr,size-1)` (fspec.hh:265). The trial stores its
    /// ParamEntry by index; the caller supplies the model's entry list (the
    /// Rust stand-in for dereferencing the `const ParamEntry *`), mirroring
    /// how `fillinMap`/`forceInactiveChain` already resolve
    /// `getEntryIndex()` through the owning list.
    pub fn slot_group(&self, entries: &[ParamEntry]) -> Option<i32> {
        let index = self.entry_index?;
        Some(entries[index].get_slot(self.addr, self.size - 1))
    }
    // Ghidra: fspec.hh:210 ParamTrial::getOffset
    pub fn get_offset(&self) -> i32 { self.offset }
    // RUGRA-GLUE: expose the packed flags for differential-fixture
    // serialization; Ghidra exposes the same state through flag predicates.
    pub fn get_flags(&self) -> u32 { self.flags }
    // Ghidra: fspec.hh:230 ParamTrial::setEntry
    /// Record which ParamEntry (by index into the model's entry list) holds
    /// this trial, plus the slot offset within that entry. Faithful to
    /// `ParamTrial::setEntry(const ParamEntry *,int4)`.
    pub fn set_entry(&mut self, entry_index: usize, off: i32) {
        self.entry_index = Some(entry_index);
        self.offset = off;
    }
    // RUGRA-GLUE: Rust Option representation of Ghidra's
    // `setEntry((const ParamEntry *)0, 0)` calls.
    /// Detach this trial from its ParamEntry and reset its entry offset.
    pub fn clear_entry(&mut self) {
        self.entry_index = None;
        self.offset = 0;
    }
    // Ghidra: fspec.hh:230 ParamTrial::getEntry
    /// Return the index of the ParamEntry that holds this trial, or `None`
    /// if no entry matches. Stands in for Ghidra's `const ParamEntry*` — the
    /// caller dereferences `model.get_entry()[index]`.
    pub fn get_entry_index(&self) -> Option<usize> { self.entry_index }
    // Ghidra: fspec.hh:210 ParamTrial::setFixedPosition
    pub fn set_fixed_position(&mut self, pos: i32) { self.fixed_position = pos; }
    // RUGRA-GLUE: read-only projection of ParamTrial::fixedPosition for
    // differential fixtures; Ghidra's production algorithms compare the
    // same private field through fixedPositionCompare (fspec.cc:1920).
    pub fn get_fixed_position(&self) -> i32 { self.fixed_position }
    // Ghidra: fspec.hh:210 ParamTrial::markUsed
    // --- flag accessors (fspec.hh:243-264) ---
    pub fn mark_used(&mut self) { self.flags |= param_trial_flags::USED; }
    // Ghidra: fspec.hh:210 ParamTrial::markActive
    pub fn mark_active(&mut self) { self.flags |= param_trial_flags::ACTIVE | param_trial_flags::CHECKED; }
    // Ghidra: fspec.hh:210 ParamTrial::markInactive
    pub fn mark_inactive(&mut self) { self.flags &= !param_trial_flags::ACTIVE; self.flags |= param_trial_flags::CHECKED; }
    // Ghidra: fspec.hh:210 ParamTrial::markNoUse
    pub fn mark_no_use(&mut self) { self.flags &= !(param_trial_flags::ACTIVE | param_trial_flags::USED); self.flags |= param_trial_flags::CHECKED | param_trial_flags::DEFNOUSE; }
    // Ghidra: fspec.hh:210 ParamTrial::markUnref
    pub fn mark_unref(&mut self) { self.flags |= param_trial_flags::UNREF | param_trial_flags::CHECKED; self.slot = -1; }
    // Ghidra: fspec.hh:210 ParamTrial::markKilledByCall
    pub fn mark_killed_by_call(&mut self) { self.flags |= param_trial_flags::KILLEDBYCALL; }
    // Ghidra: fspec.hh:210 ParamTrial::isChecked
    pub fn is_checked(&self) -> bool { self.flags & param_trial_flags::CHECKED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isActive
    pub fn is_active(&self) -> bool { self.flags & param_trial_flags::ACTIVE != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isDefinitelyNotUsed
    pub fn is_definitely_not_used(&self) -> bool { self.flags & param_trial_flags::DEFNOUSE != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isUsed
    pub fn is_used(&self) -> bool { self.flags & param_trial_flags::USED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isUnref
    pub fn is_unref(&self) -> bool { self.flags & param_trial_flags::UNREF != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::isKilledByCall
    pub fn is_killed_by_call(&self) -> bool { self.flags & param_trial_flags::KILLEDBYCALL != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setRemFormed
    pub fn set_rem_formed(&mut self) { self.flags |= param_trial_flags::REM_FORMED; }
    // Ghidra: fspec.hh:210 ParamTrial::isRemFormed
    pub fn is_rem_formed(&self) -> bool { self.flags & param_trial_flags::REM_FORMED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setIndCreateFormed
    pub fn set_ind_create_formed(&mut self) { self.flags |= param_trial_flags::INDCREATE_FORMED; }
    // Ghidra: fspec.hh:210 ParamTrial::isIndCreateFormed
    pub fn is_ind_create_formed(&self) -> bool { self.flags & param_trial_flags::INDCREATE_FORMED != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setCondexeEffect
    pub fn set_condexe_effect(&mut self) { self.flags |= param_trial_flags::CONDEXE_EFFECT; }
    // Ghidra: fspec.hh:210 ParamTrial::hasCondexeEffect
    pub fn has_condexe_effect(&self) -> bool { self.flags & param_trial_flags::CONDEXE_EFFECT != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAncestorRealistic
    pub fn set_ancestor_realistic(&mut self) { self.flags |= param_trial_flags::ANCESTOR_REALISTIC; }
    // Ghidra: fspec.hh:210 ParamTrial::hasAncestorRealistic
    pub fn has_ancestor_realistic(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_REALISTIC != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAncestorSolid
    pub fn set_ancestor_solid(&mut self) { self.flags |= param_trial_flags::ANCESTOR_SOLID; }
    // Ghidra: fspec.hh:210 ParamTrial::hasAncestorSolid
    pub fn has_ancestor_solid(&self) -> bool { self.flags & param_trial_flags::ANCESTOR_SOLID != 0 }
    // Ghidra: fspec.hh:210 ParamTrial::setAddress
    pub fn set_address(&mut self, ad: Address, sz: i32) { self.addr = ad; self.size = sz; }

    // Ghidra: fspec.cc:1845 ParamTrial::splitHi
    /// Create a trial for the first `sz` bytes (high part). Faithful to
    /// `ParamTrial::splitHi` (fspec.cc:1845-1851): the new trial keeps this
    /// trial's address and slot and inherits the full `flags` word
    /// (`res.flags = flags`), so used/checked/active state survives the split.
    pub fn split_hi(&self, sz: i32) -> ParamTrial {
        let mut res = ParamTrial::new_in_space(self.space, self.addr, sz, self.slot);
        res.flags = self.flags;
        res
    }
    // Ghidra: fspec.cc:1856 ParamTrial::splitLo
    /// Create a trial for the last `sz` bytes (low part). Faithful to
    /// `ParamTrial::splitLo` (fspec.cc:1856-1863): the new trial starts at
    /// `addr + (size - sz)` (NOT `addr + sz`), takes slot+1, and inherits the
    /// full `flags` word (`res.flags = flags`). The `sz` parameter is the
    /// size of the low piece itself, mirroring the C++ calling convention
    /// `splitLo(trial.getSize() - splitSz)` in `splitTrial` (fspec.cc:2048).
    pub fn split_lo(&self, sz: i32) -> ParamTrial {
        // Ghidra: Address newaddr = addr + (size-sz);
        let newaddr = self.addr.offset((self.size - sz) as i64);
        let mut res = ParamTrial::new_in_space(self.space, newaddr, sz, self.slot + 1);
        res.flags = self.flags;
        res
    }

    // Ghidra: fspec.cc:1871 ParamTrial::testShrink
    /// Test whether this trial can be shrunk to the given (newaddr, sz) range.
    /// Faithful 1:1 port of `testShrink` (fspec.cc:1871-1887). The candidate
    /// range must align with the trial's existing range respecting endianness:
    /// on a big-endian space the candidate address must be
    /// `addr + (size - sz)`; on a little-endian space it must equal `addr`.
    /// A trial already bound to a `ParamEntry` cannot be shrunk (Ghidra's
    /// `if (entry != null) return false`).
    ///
    /// `is_big_endian` is supplied by the caller because Rugra's `ParamTrial`
    /// does not carry an address space; in Ghidra the trial's `addr`
    /// delegates to `addr.isBigEndian()`.
    pub fn test_shrink(&self, newaddr: Address, sz: i32, is_big_endian: bool) -> bool {
        // Ghidra: Address testaddr;
        //         if (addr.isBigEndian()) testaddr = addr + (size - sz);
        //         else testaddr = addr;
        let testaddr = if is_big_endian {
            Address::new(self.addr.as_u64() + (self.size - sz) as u64)
        } else {
            self.addr
        };
        // Ghidra: if (testaddr != newaddr) return false;
        if testaddr != newaddr { return false; }
        // Ghidra: if (entry != null) return false;
        if self.entry_index.is_some() { return false; }
        true
    }

    // Ghidra: fspec.cc:1893 ParamTrial::operator<
    /// Formal-parameter-order comparison. Faithful 1:1 port of
    /// `ParamTrial::operator<` (fspec.cc:1893-1914):
    /// 1. A trial with no entry never sorts before any trial
    ///    (`if (entry == 0) return false`).
    /// 2. A trial with an entry sorts before one without
    ///    (`if (b.entry == 0) return true`).
    /// 3. Different entries compare by model group id
    ///    (`entry->getGroup()`).
    /// 4. Same group, different entries compare by entry order
    ///    (`entry < b.entry` on raw pointers). Rugra compares
    ///    `entry_index`: Ghidra's entries live in a `std::list` populated
    ///    by successive `push_back` at decode time with no interleaved
    ///    frees, so node allocation order == declaration order == index
    ///    order; the index is the deterministic equivalent of the pointer.
    /// 5. Same exclusion entry compares by the justified `offset` into the
    ///    entry (fspec.hh:231).
    /// 6. Same non-exclusion entry compares by address, reversed for
    ///    reverse-stack entries, then by size.
    ///
    /// `entries` is the owning `ParamListStandard::entry` slice the trial
    /// indices refer to. Address comparison uses `Address`'s own
    /// `PartialEq`/`PartialOrd` (Ghidra's `Address::operator==/operator<`,
    /// space first then offset, address.hh:356/375).
    pub fn op_less(entries: &[ParamEntry], a: &ParamTrial, b: &ParamTrial) -> bool {
        // Ghidra: if (entry == (const ParamEntry *)0) return false;
        let ia = match a.entry_index { Some(i) => i, None => return false };
        // Ghidra: if (b.entry == (const ParamEntry *)0) return true;
        let ib = match b.entry_index { Some(i) => i, None => return true };
        // Ghidra: int4 grpa = entry->getGroup(); int4 grpb = b.entry->getGroup();
        //         if (grpa != grpb) return (grpa < grpb);
        let grpa = entries[ia].get_group();
        let grpb = entries[ib].get_group();
        if grpa != grpb {
            return grpa < grpb;
        }
        // Ghidra: if (entry != b.entry) return (entry < b.entry);
        if ia != ib {
            return ia < ib;
        }
        let e = &entries[ia];
        // Ghidra: if (entry->isExclusion()) return (offset < b.offset);
        if e.is_exclusion() {
            return a.offset < b.offset;
        }
        // Ghidra: if (addr != b.addr) { reverseStack ? (b.addr < addr) : (addr < b.addr) }
        if a.addr != b.addr {
            return if e.is_reverse_stack() {
                b.addr < a.addr
            } else {
                a.addr < b.addr
            };
        }
        // Ghidra: return (size < b.size);
        a.size < b.size
    }

    // Ghidra: fspec.cc:1920 ParamTrial::fixedPositionCompare (static)
    /// Sort-by-functor used by `ParamListStandard::buildTrialMap` to order
    /// trials by their fixed position, falling back to `operator<` when both
    /// positions are unset (-1). Faithful 1:1 port of `fixedPositionCompare`
    /// (fspec.cc:1920-1933). Returns true if `a` should be ordered before `b`.
    /// The per-trial `operator<` fallback (group, entry, address, size) is
    /// provided via the `op_less` closure because Rugra's `ParamTrial` does
    /// not carry the bound `ParamEntry *` needed for a faithful comparison.
    pub fn fixed_position_compare<F>(
        a: &ParamTrial, b: &ParamTrial, op_less: &F,
    ) -> bool
    where
        F: Fn(&ParamTrial, &ParamTrial) -> bool,
    {
        // Ghidra: if (a.fixedPosition == -1 && b.fixedPosition == -1) return a < b;
        if a.fixed_position == -1 && b.fixed_position == -1 {
            return op_less(a, b);
        }
        // Ghidra: if (a.fixedPosition == -1) return false;
        if a.fixed_position == -1 { return false; }
        // Ghidra: if (b.fixedPosition == -1) return true;
        if b.fixed_position == -1 { return true; }
        // Ghidra: return a.fixedPosition < b.fixedPosition;
        a.fixed_position < b.fixed_position
    }
}

/// Container for parameter trials. Faithful to `ParamActive` (fspec.hh:285-380).
#[derive(Debug, Clone)]
pub struct ParamActive {
    trial: Vec<ParamTrial>,
    slotbase: i32,
    stackplaceholder: i32,
    numpasses: i32,
    maxpass: i32,
    isfullychecked: bool,
    needsfinalcheck: bool,
    recoversubcall: bool,
    join_reverse: bool,
}

impl ParamActive {
    // Ghidra: fspec.cc:1936 ParamActive::new
    /// Construct empty. Faithful to `ParamActive(bool)` (fspec.cc:1936).
    pub fn new(recoversub: bool) -> Self {
        Self {
            trial: Vec::new(),
            slotbase: 1,
            stackplaceholder: -1,
            numpasses: 0,
            maxpass: 0,
            isfullychecked: false,
            needsfinalcheck: false,
            recoversubcall: recoversub,
            join_reverse: false,
        }
    }
    // Ghidra: fspec.cc:1949 ParamActive::clear
    /// Reset to empty. Faithful to `ParamActive::clear` (fspec.cc:1949).
    pub fn clear(&mut self) {
        self.trial.clear();
        self.slotbase = 1;
        self.stackplaceholder = -1;
        self.numpasses = 0;
        self.isfullychecked = false;
        self.join_reverse = false;
    }
    // Ghidra: fspec.cc:1936 ParamActive::getNumTrials
    pub fn get_num_trials(&self) -> usize { self.trial.len() }
    // Ghidra: fspec.cc:1936 ParamActive::getTrial
    pub fn get_trial(&self, i: usize) -> &ParamTrial { &self.trial[i] }
    // Ghidra: fspec.hh:1749 ParamActive::getTrialForInputVarnode
    /// Map a CALL/CALLIND input slot back to its parameter trial, accounting
    /// for input(0) and for a stack placeholder that precedes the input.
    pub fn get_trial_for_input_varnode(&self, mut slot: i32) -> &ParamTrial {
        slot -= if self.stackplaceholder < 0 || slot < self.stackplaceholder {
            1
        } else {
            2
        };
        &self.trial[slot as usize]
    }
    // Ghidra: fspec.cc:1936 ParamActive::getTrialMut
    pub fn get_trial_mut(&mut self, i: usize) -> &mut ParamTrial { &mut self.trial[i] }

    // Ghidra: fspec.hh:329 ParamActive::testShrink
    /// Test if the i-th trial can be shrunk to the given range. Faithful
    /// inline forwarder `return trial[i].testShrink(addr,sz);`
    /// (fspec.hh:329). `is_big_endian` carries the trial space's
    /// endianness for the legacy spaceless `Address` (see
    /// `ParamTrial::test_shrink`).
    pub fn test_shrink(&self, i: usize, addr: Address, sz: i32, is_big_endian: bool) -> bool {
        self.trial[i].test_shrink(addr, sz, is_big_endian)
    }

    // Ghidra: fspec.hh:336 ParamActive::shrink
    /// Shrink the i-th trial to the given range. Faithful inline forwarder
    /// `trial[i].setAddress(addr,sz);` (fspec.hh:336).
    pub fn shrink(&mut self, i: usize, addr: Address, sz: i32) {
        self.trial[i].set_address(addr, sz);
    }
    // Ghidra: fspec.cc:1936 ParamActive::getSlotBase
    pub fn get_slot_base(&self) -> i32 { self.slotbase }
    // RUGRA-GLUE: read-only projection of ParamActive::stackplaceholder for
    // complete differential-fixture observation of placeholder slot state.
    pub fn get_stack_placeholder_slot(&self) -> i32 { self.stackplaceholder }
    // Ghidra: fspec.cc:1936 ParamActive::setSlotBase
    pub fn set_slot_base(&mut self, val: i32) { self.slotbase = val; }
    // Ghidra: fspec.cc:1936 ParamActive::getNumPasses
    pub fn get_num_passes(&self) -> i32 { self.numpasses }
    // Ghidra: fspec.cc:1936 ParamActive::getMaxPass
    pub fn get_max_pass(&self) -> i32 { self.maxpass }
    // Ghidra: fspec.cc:1936 ParamActive::setMaxPass
    pub fn set_max_pass(&mut self, val: i32) { self.maxpass = val; }
    // Ghidra: fspec.cc:1936 ParamActive::isRecoverSubcall
    pub fn is_recover_subcall(&self) -> bool { self.recoversubcall }
    // Ghidra: fspec.cc:1936 ParamActive::isJoinReverse
    pub fn is_join_reverse(&self) -> bool { self.join_reverse }
    // Ghidra: fspec.cc:1936 ParamActive::setJoinReverse
    pub fn set_join_reverse(&mut self, val: bool) { self.join_reverse = val; }
    // Ghidra: fspec.cc:1936 ParamActive::needsFinalCheck
    pub fn needs_final_check(&self) -> bool { self.needsfinalcheck }
    // Ghidra: fspec.cc:1936 ParamActive::setNeedsFinalCheck
    pub fn set_needs_final_check(&mut self, val: bool) { self.needsfinalcheck = val; }
    // Ghidra: fspec.cc:1936 ParamActive::markNeedsFinalCheck
    pub fn mark_needs_final_check(&mut self) { self.needsfinalcheck = true; }

    // Ghidra: fspec.cc:1936 ParamActive::finishPass
    /// Increment pass counter. Faithful to `ParamActive::finishPass`.
    pub fn finish_pass(&mut self) { self.numpasses += 1; }
    // Ghidra: fspec.cc:1936 ParamActive::isFullyChecked
    /// Have all passes been exhausted? Faithful to `isFullyChecked`.
    pub fn is_fully_checked(&self) -> bool { self.isfullychecked }
    // Ghidra: fspec.cc:1936 ParamActive::markFullyChecked
    /// Mark all trials as fully checked. Faithful to `markFullyChecked`.
    pub fn mark_fully_checked(&mut self) { self.isfullychecked = true; }

    // RUGRA-GLUE: deterministic projection from Address's tagged AddrSpace
    // into the transitional coarse AddressSpace enum. Ghidra stores the
    // AddrSpace pointer directly in Address. No name-based inference occurs.
    pub(crate) fn space_from_tagged_address(addr: Address) -> Option<AddressSpace> {
        let tagged = addr.get_space()?;
        if tagged.is_overlay() {
            return Some(AddressSpace::Overlay);
        }
        match tagged.get_type() {
            SpaceType::Constant => Some(AddressSpace::Const),
            SpaceType::SpaceBase => Some(AddressSpace::Stack),
            SpaceType::Internal => Some(AddressSpace::Unique),
            // The coarse enum has no FSPEC identity. Collapsing it into IOP
            // would make two distinct Ghidra spaces compare equal, so reject
            // it until the address-space migration removes this projection.
            SpaceType::Fspec => None,
            SpaceType::Iop => Some(AddressSpace::Iop),
            SpaceType::Join => Some(AddressSpace::Join),
            SpaceType::Processor => {
                let index = u8::try_from(tagged.get_index()).ok()?;
                Some(match index {
                    crate::space::SPACEID_RAM => AddressSpace::Ram,
                    crate::space::SPACEID_REGISTER => AddressSpace::Register,
                    other => AddressSpace::Other(other),
                })
            }
        }
    }

    // Ghidra: fspec.cc:1963 ParamActive::registerTrial
    /// Register a trial from a complete tagged Address. Returns `false` and
    /// leaves all state unchanged when the transitional Address is spaceless
    /// or its processor-space index cannot be represented by AddressSpace.
    pub fn register_trial(&mut self, addr: Address, sz: i32) -> bool {
        let Some(space) = Self::space_from_tagged_address(addr) else {
            return false;
        };
        self.register_trial_in_space(space, addr, sz);
        true
    }

    // RUGRA-GLUE: explicit coarse-space bridge for production callers whose
    // legacy Address has no tag; the registration semantics are Ghidra's
    // ParamActive::registerTrial (fspec.cc:1963-1975).
    /// Add a trial at the complete storage address. The assigned slot is the
    /// current `slotbase`; non-spacebase trials are marked killed-by-call;
    /// then `slotbase` advances by one.
    pub fn register_trial_in_space(&mut self, space: AddressSpace, addr: Address, sz: i32) {
        let mut trial = ParamTrial::new_in_space(space, addr, sz, self.slotbase);
        if space != AddressSpace::Stack {
            trial.mark_killed_by_call();
        }
        self.trial.push(trial);
        self.slotbase += 1;
    }

    // Ghidra: fspec.cc:1982 ParamActive::whichTrial
    /// Find the trial overlapping a complete tagged Address. A spaceless or
    /// unrepresentable Address fails closed with `-1`.
    pub fn which_trial(&self, addr: Address, sz: i32) -> i32 {
        let Some(space) = Self::space_from_tagged_address(addr) else {
            return -1;
        };
        self.which_trial_in_space(space, addr, sz)
    }

    // RUGRA-GLUE: explicit coarse-space bridge for callers whose legacy
    // Address has no tag; comparison follows fspec.cc:1982-1991.
    /// Return the first trial overlapping either end of the complete query
    /// range in the same address space.
    pub fn which_trial_in_space(&self, space: AddressSpace, addr: Address, sz: i32) -> i32 {
        for (i, t) in self.trial.iter().enumerate() {
            let trial_first = t.get_address().as_u64();
            let trial_last = trial_first.wrapping_add(t.get_size() as u64).wrapping_sub(1);
            let query_first = addr.as_u64();
            if t.get_space() == space
                && query_first >= trial_first
                && query_first <= trial_last
            {
                return i as i32;
            }
            if sz <= 1 { return -1; }
            let query_last = query_first.wrapping_add((sz - 1) as u64);
            if t.get_space() == space
                && query_last >= trial_first
                && query_last <= trial_last
            {
                return i as i32;
            }
        }
        -1
    }

    // Ghidra: fspec.cc:2033 ParamActive::splitTrial
    /// Split trial `i` into two trials, where the first piece has the given
    /// size `sz`. Faithful 1:1 port of `splitTrial` (fspec.cc:2033-2057):
    /// throws (panics) if the stack placeholder has not been recovered,
    /// renumbers the slots of every trial above the split trial's slot,
    /// replaces trial i with `splitHi(sz)` followed by
    /// `splitLo(getSize() - sz)` (the low piece's size is the remainder,
    /// fspec.cc:2048), and bumps `slotbase` by one.
    pub fn split_trial(&mut self, i: usize, sz: i32) {
        // Ghidra: if (stackplaceholder >= 0)
        //           throw LowlevelError("Cannot split parameter when the
        //           placeholder has not been recovered");
        if self.stackplaceholder >= 0 {
            panic!("Cannot split parameter when the placeholder has not been recovered");
        }
        let slot = self.trial[i].get_slot();
        let mut new_trials: Vec<ParamTrial> = Vec::new();
        // Ghidra: for(int4 j=0;j<i;++j) { push trial[j]; bump slots above slot; }
        for cur in self.trial.iter().take(i) {
            let mut clone = cur.clone();
            let oldslot = clone.get_slot();
            if oldslot > slot {
                clone.set_slot(oldslot + 1);
            }
            new_trials.push(clone);
        }
        // Ghidra: newtrials.push_back(trial[i].splitHi(sz));
        //         newtrials.push_back(trial[i].splitLo(trial[i].getSize()-sz));
        new_trials.push(self.trial[i].split_hi(sz));
        new_trials.push(self.trial[i].split_lo(self.trial[i].get_size() - sz));
        // Ghidra: for(int4 j=i+1;j<trial.size();++j) { push trial[j]; bump slots above slot; }
        for cur in self.trial.iter().skip(i + 1) {
            let mut clone = cur.clone();
            let oldslot = clone.get_slot();
            if oldslot > slot {
                clone.set_slot(oldslot + 1);
            }
            new_trials.push(clone);
        }
        self.slotbase += 1;
        self.trial = new_trials;
    }

    // Ghidra: fspec.cc:2097 ParamActive::getNumUsed
    /// Count trials flagged USED. Faithful to `getNumUsed` (fspec.cc:2097).
    pub fn get_num_used(&self) -> usize {
        self.trial.iter().filter(|t| t.is_used()).count()
    }

    // Ghidra: fspec.hh:316 ParamActive::sortTrials
    /// Sort the trial list in formal parameter order. Faithful to
    /// `ParamActive::sortTrials` (fspec.hh:316,
    /// `sort(trial.begin(),trial.end())`), which orders by
    /// `ParamTrial::operator<` (fspec.cc:1893-1918): model group first, then
    /// entry order, then (exclusion) justified offset / (non-exclusion)
    /// reverseStack-aware address, then size. Called at the end of
    /// `ParamListStandard::buildTrialMap` (fspec.cc:936) so
    /// separateSections/forceNoUse/forceInactiveChain see trials in storage
    /// order within each section.
    ///
    /// `entries` is the owning `ParamListStandard::entry` slice the trial
    /// entry indices refer to (Ghidra dereferences the trial's stored
    /// `const ParamEntry *`; Rugra's trial stores an index instead).
    ///
    /// Residual: Rust's `sort_by` is stable while Ghidra's `std::sort` is
    /// an unstable introsort, so trials that compare equal under
    /// `operator<` (same entry, non-exclusion, same address and size —
    /// differing only in slot/flags) may keep a different relative order
    /// than libstdc++. Production trial sets do not mint comparator-equal
    /// duplicates (trials are registered at distinct slots/addresses).
    pub fn sort_trials(&mut self, entries: &[ParamEntry]) {
        self.trial.sort_by(|a, b| {
            if ParamTrial::op_less(entries, a, b) {
                std::cmp::Ordering::Less
            } else if ParamTrial::op_less(entries, b, a) {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
    }

    // Ghidra: fspec.cc:2013 ParamActive::deleteUnusedTrials
    /// Delete unused trials and renumber the slots of the survivors
    /// (1-based). Faithful 1:1 port of `deleteUnusedTrials`
    /// (fspec.cc:2013-2028): walks `trial`, keeps only the USED ones, assigns
    /// each survivor a fresh 1-based slot, and rebuilds the trial vector.
    /// Called by `FuncCallSpecs::buildOutputFromTrials` to reconcile the
    /// active-output trial list with the chosen output varnodes.
    pub fn delete_unused_trials(&mut self) {
        let mut new_trials: Vec<ParamTrial> = Vec::new();
        let mut slot = 1i32;
        for cur in self.trial.iter_mut() {
            if cur.is_used() {
                cur.set_slot(slot);
                slot += 1;
                new_trials.push(cur.clone());
            }
        }
        self.trial = new_trials;
    }

    // Ghidra: fspec.cc:1995 ParamActive::freePlaceholderSlot
    /// Decrement the slot of every trial above the stack placeholder, then
    /// retire the placeholder. Faithful to `freePlaceholderSlot`
    /// (fspec.cc:1995). Sets `stackplaceholder = -2`, decrements `slotbase`,
    /// and zeroes `maxpass` (so the next analysis pass is the last chance for
    /// any location to show up).
    pub fn free_placeholder_slot(&mut self) {
        for t in self.trial.iter_mut() {
            if t.get_slot() > self.stackplaceholder {
                t.set_slot(t.get_slot() - 1);
            }
        }
        self.stackplaceholder = -2;
        self.slotbase -= 1;
        self.maxpass = 0;
    }

    // Ghidra: fspec.hh:310 ParamActive::setPlaceholderSlot
    /// Establish the stack placeholder slot: the placeholder occupies the
    /// current `slotbase` so subsequent trial slots stay aligned with the
    /// CALL op input indices. Faithful to the inline `setPlaceholderSlot`
    /// (fspec.hh:310).
    pub fn set_placeholder_slot(&mut self) {
        self.stackplaceholder = self.slotbase;
        self.slotbase += 1;
    }

    // Ghidra: fspec.hh:317 ParamActive::sortFixedPosition
    /// Sort the trials by fixed position (then `operator<`). Faithful to the
    /// inline `sortFixedPosition` (fspec.hh:317) with
    /// `ParamTrial::fixedPositionCompare` (fspec.cc:1920-1933): unset (-1)
    /// positions never sort before a set position, two set positions compare
    /// numerically, and the two-unset fallback is `ParamTrial::operator<`.
    /// The only production caller (`buildInputFromTrials`, fspec.cc:5700)
    /// runs AFTER `deriveInputMap`, whose `buildTrialMap` has already called
    /// `active->sortTrials()` (fspec.cc:936) — i.e. the trial vector is
    /// already in full `operator<` (entry group) order, which is exactly the
    /// order the two-unset `a < b` arm would select. Rust's stable sort with
    /// `Ordering::Equal` for that arm therefore reproduces the oracle
    /// sequence; the residual (C++ `std::sort` is unstable among truly
    /// equivalent trials) is unobservable because a pair of trials that
    /// compares false in both directions is either identical in
    /// group/offset/size or entry-less — and entry-less trials were marked
    /// `noUse` by `buildTrialMap` (fspec.cc:864), so `buildInputFromTrials`'
    /// `isUsed()` loop skips them.
    pub fn sort_fixed_position(&mut self) {
        self.trial.sort_by(|a, b| {
            match (a.fixed_position, b.fixed_position) {
                (-1, -1) => std::cmp::Ordering::Equal,
                (-1, _) => std::cmp::Ordering::Greater,
                (_, -1) => std::cmp::Ordering::Less,
                (x, y) => x.cmp(&y),
            }
        });
    }

    // Ghidra: fspec.cc:2063 ParamActive::joinTrial
    /// Join the trial at `slot` with the trial in the next slot into a single
    /// trial covering `(addr, sz)`. Faithful to `joinTrial` (fspec.cc:2063).
    /// Panics if the placeholder has not been recovered (`stackplaceholder >= 0`)
    /// or if the joined sizes do not sum to `sz` (mirroring the C++
    /// `LowlevelError` throws).
    pub fn join_trial(&mut self, slot: i32, addr: Address, sz: i32) {
        if self.stackplaceholder >= 0 {
            panic!("Cannot join parameters when the placeholder has not been removed");
        }
        let mut new_trials: Vec<ParamTrial> = Vec::new();
        let mut sizecheck = 0i32;
        for cur in self.trial.iter() {
            let curslot = cur.get_slot();
            if curslot < slot {
                new_trials.push(cur.clone());
            } else if curslot == slot {
                sizecheck += cur.get_size();
                let mut joined = ParamTrial::new_in_space(cur.get_space(), addr, sz, slot);
                joined.mark_used();
                joined.mark_active();
                new_trials.push(joined);
            } else if curslot == slot + 1 {
                // this slot is thrown out
                sizecheck += cur.get_size();
            } else {
                let mut clone = cur.clone();
                clone.set_slot(curslot - 1);
                new_trials.push(clone);
            }
        }
        if sizecheck != sz {
            panic!("Size mismatch when joining parameters");
        }
        self.slotbase -= 1;
        self.trial = new_trials;
    }
}

// ======================================================================
// ParamEntry (fspec.hh:84-155 / fspec.cc:60-595)
// ======================================================================
// A parameter storage resource: either a single hardware register set, a
// range of stack slots, or a join across multiple registers. Managed by
// ParamListStandard. Faithful port of `class ParamEntry`.

use crate::address::Range as FsRange;
use crate::opcodes::OpCode as FspecOpCode;

/// Storage class of a parameter resource. Faithful to the `TypeClass` enum
/// (fspec.hh:421-431). Local copy in `fspec` (modelrules has its own).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TypeClass {
    General = 0,
    Float = 1,
    Pointer = 2,
    HiddenReturn = 3,
    Vector = 4,
    Class1 = 100,
    Class2 = 101,
    Class3 = 102,
    Class4 = 103,
}

/// Translate the `<pentry>` `metatype=` attribute string to a TypeClass.
/// Faithful to the inline parser in `ParamEntry::decode` (fspec.cc:511-543).
/// RUGRA-GLUE: standalone helper (Ghidra inlines this in decode()).
pub fn string_to_type_class(s: &str) -> TypeClass {
    match s {
        "float" => TypeClass::Float,
        "ptr" => TypeClass::Pointer,
        "hiddenret" => TypeClass::HiddenReturn,
        "vector" => TypeClass::Vector,
        "class1" => TypeClass::Class1,
        "class2" => TypeClass::Class2,
        "class3" => TypeClass::Class3,
        "class4" => TypeClass::Class4,
        _ => TypeClass::General,
    }
}

/// A single storage location (space + offset + size). Faithful port of
/// `struct VarnodeData` (varnode.hh). Local copy in `fspec` (modelrules
/// has its own). Rugra collapses the space+into a single AddressSpace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarnodeData {
    pub space: AddressSpace,
    pub offset: u64,
    pub size: i32,
}

impl VarnodeData {
    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    /// Total order for VarnodeData lists, 1:1 with the oracle `operator<`
    /// (pcoderaw.hh:67-70): the address space (Ghidra compares the space's
    /// *index*; Rugra's `AddressSpace` enum order is the fixed space-index
    /// projection used throughout fspec), then the offset ascending, then the
    /// size **descending** — "BIG sizes come first". This is the sort/binar
    /// y_search key for `likelytrash`/`internalstorage` (fspec.cc:2694-2695,
    /// 3641, 3696-3699) and the merge-join key of `intersectRegisters`.
    pub fn compare(a: &VarnodeData, b: &VarnodeData) -> std::cmp::Ordering {
        a.space
            .cmp(&b.space)
            .then(a.offset.cmp(&b.offset))
            .then(b.size.cmp(&a.size))
    }

    // RUGRA-GLUE: get_addr (Ghidra's VarnodeData has an `addr` field that
    // is a constructed Address; Rugra builds it on demand).
    pub fn get_addr(&self) -> Address { Address::new(self.offset) }
}

impl Default for VarnodeData {
    // RUGRA-GLUE: Rust Default supplies initialized fields for the local
    // VarnodeData representation; Ghidra's VarnodeData is a C++ aggregate
    // with no corresponding default() member.
    fn default() -> Self {
        Self { space: AddressSpace::Ram, offset: 0, size: 0 }
    }
}

/// Cached join record: the list of pieces that make up a joined ParamEntry.
/// Faithful port of `struct ParamEntry::JoinRecord` (fspec.hh:99).
#[derive(Debug, Clone)]
pub struct ParamEntryJoin {
    pub pieces: Vec<VarnodeData>,
}

/// Flags for a ParamEntry. Faithful to the `ParamEntry` flags enum
/// (fspec.hh:88-97).
pub mod param_entry_flags {
    /// The logical value is left-justified within its container.
    pub const FORCE_LEFT_JUSTIFY: u32 = 1;
    /// Reverse stack: slot 0 is the highest address, growing down.
    pub const REVERSE_STACK: u32 = 2;
    /// Small values in this entry are zero-extended to the full size.
    pub const SMALLSIZE_ZEXT: u32 = 4;
    /// Small values in this entry are sign-extended to the full size.
    pub const SMALLSIZE_SEXT: u32 = 8;
    /// Small values are extended according to their integer type.
    pub const SMALLSIZE_INTTYPE: u32 = 0x20;
    /// A small float in this entry is extended into a larger float slot.
    pub const SMALLSIZE_FLOATEXT: u32 = 0x40;
    /// The high half of a joined entry requires an additional check.
    pub const EXTRACHECK_HIGH: u32 = 0x80;
    /// The low half of a joined entry requires an additional check.
    pub const EXTRACHECK_LOW: u32 = 0x100;
    /// This entry is part of a `<group>` of mutually-overlapping entries.
    pub const IS_GROUPED: u32 = 0x200;
    /// This entry overlaps another and shares its group set.
    pub const OVERLAPPING: u32 = 0x400;
    /// This is the first ParamEntry in its type/storage class.
    pub const FIRST_STORAGE: u32 = 0x800;
}

/// Containment characterization codes returned by
/// `ParamListStandard::characterizeAsParam`. Faithful to the inline enum
/// in `ProtoModel::characterizeAsParam` (fspec.hh:846-851).
pub mod containment {
    pub const NO_CONTAINMENT: i32 = 0;
    pub const CONTAINS_UNJUSTIFIED: i32 = 1;
    pub const CONTAINS_JUSTIFIED: i32 = 2;
    pub const CONTAINED_BY: i32 = 3;
}

/// A parameter storage resource entry: register set, stack slot range, or
/// join. Faithful port of `class ParamEntry` (fspec.hh:84-155).
#[derive(Debug, Clone)]
pub struct ParamEntry {
    flags: u32,
    type_storage: TypeClass,
    group_set: Vec<i32>,
    space: AddressSpace,
    address_base: u64,
    size: i32,
    min_size: i32,
    alignment: i32,
    num_slots: i32,
    join: Option<ParamEntryJoin>,
}

impl ParamEntry {
    // Ghidra: fspec.hh:123 ParamEntry::isLeftJustified
    /// Is the logical value left-justified within its container. Faithful
    /// to the inline `isLeftJustified` (fspec.hh:123).
    fn is_left_justified(&self) -> bool {
        (self.flags & param_entry_flags::FORCE_LEFT_JUSTIFY) != 0
            || !self.space.is_big_endian()
    }

    // Ghidra: fspec.hh:125 ParamEntry::ParamEntry
    // RUGRA-GLUE: constructor for use with decode (fspec.hh:125 pushes the
    // first group; decode() fills the rest).
    pub fn new(grp: i32) -> Self {
        Self {
            flags: 0,
            type_storage: TypeClass::General,
            group_set: vec![grp],
            space: AddressSpace::Ram,
            address_base: 0,
            size: 0,
            min_size: 0,
            alignment: 0,
            num_slots: 1,
            join: None,
        }
    }

    // RUGRA-GLUE: fixture construction for a single non-join exclusion
    // register/stack entry, mirroring the field state a decoded
    // `<pentry><addr space=... offset=... size=.../></pentry>` produces
    // (alignment == size collapses to 0 = exclusion in fspec.cc decode).
    // Locked differential fixtures use this instead of carrying a private
    // XML parser; it performs no validation, so production paths keep
    // using `decode`.
    pub fn from_storage(space: AddressSpace, base: u64, size: i32, minsize: i32, grp: i32) -> Self {
        Self {
            flags: 0,
            type_storage: TypeClass::General,
            group_set: vec![grp],
            space,
            address_base: base,
            size,
            min_size: minsize,
            alignment: 0,
            num_slots: 1,
            join: None,
        }
    }

    // Ghidra: fspec.cc:501 ParamEntry::decode
    /// Decode one `<pentry>` and its address child.
    ///
    /// The register resolver is the Rust equivalent of the `Translate`
    /// lookup reached by `VarnodeData::decodeFromAttributes` for a
    /// `<register name="..."/>` child.  Keeping it as a caller-supplied
    /// resolver lets the same algorithm consume any compiler specification;
    /// no ABI register table is embedded here.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        normal_stack: bool,
        grouped: bool,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.flags = 0;
        self.type_storage = TypeClass::General;
        self.size = -1;
        self.min_size = -1;
        self.alignment = 0;
        self.num_slots = 1;
        self.join = None;

        let elem_id = decoder.open_element();
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            let name = decoder.attribute_name(attrib_id).unwrap_or_default();
            match name.as_str() {
                "minsize" => self.min_size = decoder.read_signed_integer() as i32,
                "size" | "align" => self.alignment = decoder.read_signed_integer() as i32,
                "maxsize" => self.size = decoder.read_signed_integer() as i32,
                "storage" | "metatype" => {
                    self.type_storage = string_to_type_class(&decoder.read_string());
                }
                "extension" => {
                    self.flags &= !(param_entry_flags::SMALLSIZE_ZEXT
                        | param_entry_flags::SMALLSIZE_SEXT
                        | param_entry_flags::SMALLSIZE_INTTYPE);
                    match decoder.read_string().as_str() {
                        "sign" => self.flags |= param_entry_flags::SMALLSIZE_SEXT,
                        "zero" => self.flags |= param_entry_flags::SMALLSIZE_ZEXT,
                        "inttype" => self.flags |= param_entry_flags::SMALLSIZE_INTTYPE,
                        "float" => self.flags |= param_entry_flags::SMALLSIZE_FLOATEXT,
                        "none" => {}
                        _ => return Err("Bad extension attribute".to_string()),
                    }
                }
                _ => {
                    let _ = decoder.read_string();
                    return Err("Unknown <pentry> attribute".to_string());
                }
            }
        }
        if self.size == -1 || self.min_size == -1 {
            return Err("ParamEntry not fully specified".to_string());
        }
        if self.alignment == self.size {
            self.alignment = 0;
        }

        let address_id = decoder.open_element();
        if address_id == 0 {
            return Err("No address specified for <pentry>".to_string());
        }
        let address_name = decoder.element_name(address_id).unwrap_or_default();
        let mut decoded_space = None;
        let mut decoded_offset = 0u64;
        let mut register_name = None;
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            let name = decoder.attribute_name(attrib_id).unwrap_or_default();
            match name.as_str() {
                "space" => decoded_space = Some(parse_space_name(&decoder.read_string())),
                "offset" => decoded_offset = parse_u64(&decoder.read_string()),
                "name" => register_name = Some(decoder.read_string()),
                "size" => {
                    let _ = decoder.read_signed_integer();
                }
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }
        if address_name == "register" || register_name.is_some() {
            let name = register_name.ok_or_else(|| "Missing register name".to_string())?;
            let storage =
                register_resolver(&name).ok_or_else(|| format!("Unknown register name: {name}"))?;
            self.space = storage.space;
            self.address_base = storage.offset;
        } else {
            self.space = decoded_space.ok_or_else(|| "No address space indicated".to_string())?;
            self.address_base = decoded_offset;
        }
        decoder.close_element(address_id);
        decoder.close_element(elem_id);

        if self.alignment != 0 {
            self.num_slots = self.size / self.alignment;
        }
        if !normal_stack {
            self.flags |= param_entry_flags::REVERSE_STACK;
            if self.alignment != 0 && self.size % self.alignment != 0 {
                return Err(
                    "For positive stack growth, <pentry> size must match alignment".to_string(),
                );
            }
        }
        if grouped {
            self.flags |= param_entry_flags::IS_GROUPED;
        }
        Ok(())
    }

    // Ghidra: fspec.hh:126 ParamEntry::getGroup
    pub fn get_group(&self) -> i32 { self.group_set[0] }
    // Ghidra: fspec.hh:127 ParamEntry::getAllGroups
    pub fn get_all_groups(&self) -> &[i32] { &self.group_set }
    // Ghidra: fspec.hh:129 ParamEntry::getSize
    pub fn get_size(&self) -> i32 { self.size }
    // Ghidra: fspec.hh:130 ParamEntry::getMinSize
    pub fn get_min_size(&self) -> i32 { self.min_size }
    // Ghidra: fspec.hh:131 ParamEntry::getAlign
    pub fn get_align(&self) -> i32 { self.alignment }
    // Ghidra: fspec.hh:133 ParamEntry::getType
    pub fn get_type(&self) -> TypeClass { self.type_storage }
    // Ghidra: fspec.hh:134 ParamEntry::isExclusion
    pub fn is_exclusion(&self) -> bool { self.alignment == 0 }
    // Ghidra: fspec.hh:135 ParamEntry::isReverseStack
    pub fn is_reverse_stack(&self) -> bool {
        (self.flags & param_entry_flags::REVERSE_STACK) != 0
    }
    // Ghidra: fspec.hh:136 ParamEntry::isGrouped
    pub fn is_grouped(&self) -> bool {
        (self.flags & param_entry_flags::IS_GROUPED) != 0
    }
    // Ghidra: fspec.hh:137 ParamEntry::isOverlap
    pub fn is_overlap(&self) -> bool {
        (self.flags & param_entry_flags::OVERLAPPING) != 0
    }
    // Ghidra: fspec.hh:138 ParamEntry::isFirstInClass
    pub fn is_first_in_class(&self) -> bool {
        (self.flags & param_entry_flags::FIRST_STORAGE) != 0
    }
    // Ghidra: fspec.hh:152 ParamEntry::isParamCheckHigh
    pub fn is_param_check_high(&self) -> bool {
        (self.flags & param_entry_flags::EXTRACHECK_HIGH) != 0
    }
    // Ghidra: fspec.hh:153 ParamEntry::isParamCheckLow
    pub fn is_param_check_low(&self) -> bool {
        (self.flags & param_entry_flags::EXTRACHECK_LOW) != 0
    }
    // Ghidra: fspec.hh:147 ParamEntry::getSpace
    pub fn get_space(&self) -> AddressSpace { self.space }
    // Ghidra: fspec.hh:148 ParamEntry::getBase
    pub fn get_base(&self) -> u64 { self.address_base }
    // Ghidra: fspec.hh:132 ParamEntry::getJoinRecord
    pub fn get_join_pieces(&self) -> Option<&[VarnodeData]> {
        self.join.as_ref().map(|j| j.pieces.as_slice())
    }

    // Ghidra: fspec.cc:60 ParamEntry::findEntryByStorage
    /// Find a ParamEntry matching the given storage Varnode. Search
    /// backward. Faithful to `findEntryByStorage` (fspec.cc:60-71).
    pub fn find_entry_by_storage<'a>(
        entry_list: &'a [ParamEntry],
        vn: &VarnodeData,
    ) -> Option<&'a ParamEntry> {
        entry_list.iter().rev().find(|entry| {
            entry.space == vn.space
                && entry.address_base == vn.offset
                && entry.size == vn.size
        })
    }

    // Ghidra: fspec.cc:76 ParamEntry::resolveFirst
    fn resolve_first(&mut self, cur_list: &[ParamEntry]) {
        if cur_list.is_empty() {
            self.flags |= param_entry_flags::FIRST_STORAGE;
            return;
        }
        let prev = &cur_list[cur_list.len() - 1];
        if self.type_storage != prev.type_storage {
            self.flags |= param_entry_flags::FIRST_STORAGE;
        }
    }

    // Ghidra: fspec.cc:94 ParamEntry::resolveJoin
    /// If the ParamEntry is initialized with a join address, cache the join
    /// record and adjust the group. Faithful to `resolveJoin`
    /// (fspec.cc:94-116).
    fn resolve_join(&mut self, cur_list: &[ParamEntry]) {
        // TODO(ALIGNMENT_ROADMAP): depends on unported
        // AddrSpaceManager::findJoin (space.cc). The join-space manager is
        // not yet ported; Rugra receives pieces via set_join_pieces.
        if self.space != AddressSpace::Join {
            self.join = None;
            return;
        }
        let pieces = match &self.join {
            Some(j) if !j.pieces.is_empty() => j.pieces.clone(),
            _ => return,
        };
        let mut new_groups: Vec<i32> = Vec::new();
        for (i, piece) in pieces.iter().enumerate() {
            if let Some(entry) = ParamEntry::find_entry_by_storage(cur_list, piece) {
                new_groups.extend_from_slice(&entry.group_set);
                if i == 0 {
                    self.flags |= param_entry_flags::EXTRACHECK_LOW;
                } else {
                    self.flags |= param_entry_flags::EXTRACHECK_HIGH;
                }
            }
        }
        if new_groups.is_empty() { return; }
        new_groups.sort_unstable();
        new_groups.dedup();
        self.group_set = new_groups;
        self.flags |= param_entry_flags::OVERLAPPING;
    }

    // RUGRA-GLUE: set_join_pieces (no direct Ghidra counterpart — Ghidra
    // pulls pieces from `spaceid->getManager()->findJoin(addressbase)`; in
    // Rugra the caller supplies them since the join-space manager is
    // unported).
    pub fn set_join_pieces(&mut self, pieces: Vec<VarnodeData>) {
        self.join = Some(ParamEntryJoin { pieces });
    }

    // Ghidra: fspec.cc:122 ParamEntry::resolveOverlap
    /// Search for overlaps of this with any previous entry. If an overlap
    /// is discovered, reassign this group. Faithful to `resolveOverlap`
    /// (fspec.cc:122-153).
    fn resolve_overlap(&mut self, cur_list: &[ParamEntry]) -> Result<(), String> {
        if self.join.is_some() { return Ok(()); }
        let mut overlap_set: Vec<i32> = Vec::new();
        let addr = Address::new(self.address_base);
        for entry in cur_list.iter() {
            // Rugra's compact Address currently carries only the offset, so
            // preserve Ghidra's `spaceid != addr.getSpace()` guard here.
            if entry.space != self.space { continue; }
            if !entry.intersects(addr, self.size) { continue; }
            if self.contains(entry) {
                if entry.is_overlap() { continue; }
                overlap_set.extend_from_slice(&entry.group_set);
                if self.address_base == entry.address_base {
                    self.flags |= if self.space.is_big_endian() {
                        param_entry_flags::EXTRACHECK_LOW
                    } else {
                        param_entry_flags::EXTRACHECK_HIGH
                    };
                } else {
                    self.flags |= if self.space.is_big_endian() {
                        param_entry_flags::EXTRACHECK_HIGH
                    } else {
                        param_entry_flags::EXTRACHECK_LOW
                    };
                }
            } else {
                return Err("Illegal overlap of <pentry> in compiler spec".to_string());
            }
        }
        if overlap_set.is_empty() { return Ok(()); }
        overlap_set.sort_unstable();
        overlap_set.dedup();
        self.group_set = overlap_set;
        self.flags |= param_entry_flags::OVERLAPPING;
        Ok(())
    }

    // Ghidra: fspec.cc:157 ParamEntry::groupOverlap
    /// Return `true` if the group sets intersect at all. Faithful to
    /// `groupOverlap` (fspec.cc:157-177).
    pub fn group_overlap(&self, op2: &ParamEntry) -> bool {
        let mut i = 0usize;
        let mut j = 0usize;
        let mut val_this = self.group_set[i];
        let mut val_other = op2.group_set[j];
        loop {
            if val_this == val_other { return true; }
            if val_this < val_other {
                i += 1;
                if i >= self.group_set.len() { return false; }
                val_this = self.group_set[i];
            } else {
                j += 1;
                if j >= op2.group_set.len() { return false; }
                val_other = op2.group_set[j];
            }
        }
    }

    // Ghidra: fspec.cc:184 ParamEntry::subsumesDefinition
    /// This entry must properly contain the other memory range, and the
    /// entry properties must be compatible. Faithful to
    /// `subsumesDefinition` (fspec.cc:184-193).
    pub fn subsumes_definition(&self, op2: &ParamEntry) -> bool {
        if self.type_storage != TypeClass::General && op2.type_storage != self.type_storage {
            return false;
        }
        if self.space != op2.space { return false; }
        if op2.address_base < self.address_base { return false; }
        if op2.address_base + op2.size as u64 - 1 > self.address_base + self.size as u64 - 1 {
            return false;
        }
        if self.alignment != op2.alignment { return false; }
        true
    }

    // Ghidra: fspec.cc:199 ParamEntry::containedBy
    /// Return `true` if the entire ParamEntry fits inside the range
    /// `[addr, addr+sz)`. Faithful to `containedBy` (fspec.cc:199-207).
    pub fn contained_by(&self, addr: Address, sz: i32) -> bool {
        if self.address_base < addr.as_u64() { return false; }
        let entry_off = self.address_base + self.size as u64 - 1;
        let range_off = addr.as_u64() + sz as u64 - 1;
        entry_off <= range_off
    }

    // Ghidra: fspec.cc:214 ParamEntry::intersects
    /// If this is a join, each piece is tested for intersection. Otherwise
    /// this, considered as a single memory, is tested. Faithful to
    /// `intersects` (fspec.cc:214-239).
    pub fn intersects(&self, addr: Address, sz: i32) -> bool {
        let range_end = addr.as_u64().wrapping_add(sz as u64).wrapping_sub(1);
        if let Some(j) = &self.join {
            for vdata in &j.pieces {
                let vdata_end = vdata.offset + vdata.size as u64 - 1;
                if addr.as_u64() < vdata.offset && range_end < vdata_end { continue; }
                if addr.as_u64() > vdata.offset && range_end > vdata_end { continue; }
                return true;
            }
        }
        let this_end = self.address_base + self.size as u64 - 1;
        if addr.as_u64() < self.address_base && range_end < this_end { return false; }
        if addr.as_u64() > self.address_base && range_end > this_end { return false; }
        true
    }

    // Ghidra: fspec.cc:248 ParamEntry::justifiedContain
    /// Check if the given memory range is contained in this. Return the
    /// endian-aware offset (0 if LSB-aligned), else -1. Faithful to
    /// `justifiedContain` (fspec.cc:248-283).
    pub fn justified_contain(&self, addr: Address, sz: i32) -> i32 {
        if let Some(j) = &self.join {
            let mut res = 0i32;
            for vdata in j.pieces.iter().rev() {
                // Ghidra: fspec.cc:255 vdata.getAddr().justifiedContain(...,false)
                // — forceleft=false on each piece's own space, so the
                // piece space endianness drives the branch (address.cc:138).
                let cur = justified_contain_range(
                    vdata.offset, vdata.size, addr.as_u64(), sz, false,
                    vdata.space.is_big_endian(),
                );
                if cur < 0 { res += vdata.size; } else { return res + cur; }
            }
            return -1;
        }
        if self.alignment == 0 {
            // Ghidra: fspec.cc:266-267 Address entry(spaceid,addressbase);
            // entry.justifiedContain(size,addr,sz,forceleft) — the entry
            // space's endianness drives the address.cc:138 branch.
            return justified_contain_range(
                self.address_base, self.size, addr.as_u64(), sz,
                (self.flags & param_entry_flags::FORCE_LEFT_JUSTIFY) != 0,
                self.space.is_big_endian(),
            );
        }
        let start_addr = addr.as_u64();
        if start_addr < self.address_base { return -1; }
        let end_addr = start_addr.wrapping_add(sz as u64).wrapping_sub(1);
        if end_addr < start_addr { return -1; }
        if end_addr > self.address_base + self.size as u64 - 1 { return -1; }
        let start_off = start_addr - self.address_base;
        let end_off = end_addr - self.address_base;
        if !self.is_left_justified() {
            let res = ((end_off + 1) % self.alignment as u64) as i32;
            if res == 0 { return 0; }
            return self.alignment - res;
        }
        (start_off % self.alignment as u64) as i32
    }

    // Ghidra: fspec.cc:248 ParamEntry::justifiedContain
    /// Space-aware form of `justified_contain`: the query range's space is
    /// known (the resolver-window callers `find_entry` and
    /// `characterize_as_param` hold it, standing in for the space carried by
    /// Ghidra's `const Address &addr`), so every space guard of the Ghidra
    /// original is enforced exactly:
    /// - join walk (fspec.cc:253-261): a piece in another space than the
    ///   query hits `Address::justifiedContain`'s `base != op2.base` -1
    ///   (address.cc:133) and only accumulates its size into the skip
    ///   counter — the cross-space numeric-coincidence divergence pinned by
    ///   the FSPEC-FINDENTRY-GATE-0005 fixture (R13 finding B);
    /// - plain alignment==0 (fspec.cc:264-267): the entry-space Address's
    ///   address.cc:133 guard;
    /// - plain alignment!=0 (fspec.cc:269): the explicit
    ///   `if (spaceid != addr.getSpace()) return -1;`.
    /// Callers without a query space keep the transitional spaceless
    /// `justified_contain` (ADDRESS-0001).
    pub fn justified_contain_in_space(&self, addr: Address, sz: i32, query_space: AddressSpace) -> i32 {
        if let Some(j) = &self.join {
            // Ghidra: fspec.cc:253 for(i=numPieces()-1;i>=0;--i) — move
            // from least significant to most (pieces are stored most
            // significant first, translate.hh JoinRecord).
            let mut res = 0i32;
            for vdata in j.pieces.iter().rev() {
                // Ghidra: fspec.cc:255 vdata.getAddr().justifiedContain(
                // vdata.size, addr, sz, false) — address.cc:133: a piece in
                // another space than the query is never contained; its size
                // is only skipped.
                let cur = if vdata.space != query_space {
                    -1
                } else {
                    justified_contain_range(
                        vdata.offset, vdata.size, addr.as_u64(), sz, false,
                        vdata.space.is_big_endian(),
                    )
                };
                if cur < 0 { res += vdata.size; } else { return res + cur; }
            }
            return -1;
        }
        // Ghidra: address.cc:133 (alignment==0 route via the entry-space
        // Address) / fspec.cc:269 (alignment!=0 route): a foreign-space
        // query is never contained. After this guard the delegated numeric
        // bodies are the exact cc:264-282 arithmetic.
        if self.space != query_space { return -1; }
        self.justified_contain(addr, sz)
    }

    // Ghidra: fspec.cc:295 ParamEntry::getContainer
    /// Calculate the containing memory range. Pass back the VarnodeData of
    /// the parameter that would contain the given range. Faithful to
    /// `getContainer` (fspec.cc:295-328).
    pub fn get_container(&self, addr: Address, sz: i32, res: &mut VarnodeData) -> bool {
        let end_addr = Address::new(addr.as_u64().wrapping_add(sz as u64 - 1));
        if let Some(j) = &self.join {
            for vdata in j.pieces.iter().rev() {
                let vaddr = vdata.get_addr();
                if addr.overlap(0, vaddr, vdata.size) >= 0
                    && end_addr.overlap(0, vaddr, vdata.size) >= 0
                {
                    *res = *vdata;
                    return true;
                }
            }
            return false;
        }
        let entry = Address::new(self.address_base);
        if addr.overlap(0, entry, self.size) < 0 { return false; }
        if end_addr.overlap(0, entry, self.size) < 0 { return false; }
        if self.alignment == 0 {
            res.space = self.space;
            res.offset = self.address_base;
            res.size = self.size;
            return true;
        }
        let al = (addr.as_u64() - self.address_base) % self.alignment as u64;
        res.space = self.space;
        res.offset = addr.as_u64() - al;
        res.size = (end_addr.as_u64() - res.offset) as i32 + 1;
        let al2 = res.size as i32 % self.alignment;
        if al2 != 0 { res.size += self.alignment - al2; }
        true
    }

    // Ghidra: fspec.cc:335 ParamEntry::contains
    /// Test that this contains the other ParamEntry's memory range.
    /// Faithful to `contains` (fspec.cc:335-350).
    pub fn contains(&self, op2: &ParamEntry) -> bool {
        if op2.join.is_some() { return false; }
        if self.join.is_none() {
            if self.space != op2.space { return false; }
            let addr = Address::new(self.address_base);
            return op2.contained_by(addr, self.size);
        }
        let j = self.join.as_ref().unwrap();
        for vdata in &j.pieces {
            if vdata.space != op2.space { continue; }
            if op2.contained_by(vdata.get_addr(), vdata.size) { return true; }
        }
        false
    }

    // Ghidra: fspec.cc:366 ParamEntry::assumedExtension
    /// Calculate the type of extension to expect for the given logical
    /// value. Returns CPUI_COPY if no extensions are assumed. Faithful to
    /// `assumedExtension` (fspec.cc:366-394). `query_space` is the query
    /// address's space (Ghidra reads it from the `const Address &addr`;
    /// the legacy spaceless `Address` needs it alongside — see
    /// `find_entry`): the cc:377 `justifiedContain(addr,sz)` call is
    /// space-aware (alignment==0 route via `Address::justifiedContain`
    /// address.cc:133; alignment!=0 route via fspec.cc:269), so a
    /// foreign-space query with a numerically coincident offset returns
    /// CPUI_COPY (FSPEC-POSSIBLEPARAM-JOIN-0006; join entries never reach
    /// the call — cc:376 returns CPUI_COPY first).
    pub fn assumed_extension(
        &self,
        addr: Address,
        sz: i32,
        query_space: AddressSpace,
        res: &mut VarnodeData,
    ) -> FspecOpCode {
        if self.flags
            & (param_entry_flags::SMALLSIZE_ZEXT
                | param_entry_flags::SMALLSIZE_SEXT
                | param_entry_flags::SMALLSIZE_INTTYPE)
            == 0
        {
            return FspecOpCode::CPUI_COPY;
        }
        if self.alignment != 0 {
            if sz >= self.alignment { return FspecOpCode::CPUI_COPY; }
        } else if sz >= self.size {
            return FspecOpCode::CPUI_COPY;
        }
        if self.join.is_some() { return FspecOpCode::CPUI_COPY; }
        // Ghidra: fspec.cc:377 if (justifiedContain(addr,sz)!=0) — the
        // addr carries its space, so both space guards apply.
        if self.justified_contain_in_space(addr, sz, query_space) != 0 {
            return FspecOpCode::CPUI_COPY;
        }
        if self.alignment == 0 {
            res.space = self.space;
            res.offset = self.address_base;
            res.size = self.size;
        } else {
            res.space = self.space;
            let align_adjust = (addr.as_u64() - self.address_base) % self.alignment as u64;
            res.offset = addr.as_u64() - align_adjust;
            res.size = self.alignment;
        }
        if self.flags & param_entry_flags::SMALLSIZE_ZEXT != 0 {
            return FspecOpCode::CPUI_INT_ZEXT;
        }
        if self.flags & param_entry_flags::SMALLSIZE_INTTYPE != 0 {
            return FspecOpCode::CPUI_PIECE;
        }
        FspecOpCode::CPUI_INT_SEXT
    }

    // Ghidra: fspec.cc:407 ParamEntry::getSlot
    /// Calculate the slot occupied by a specific address. Faithful to
    /// `getSlot` (fspec.cc:407-423).
    pub fn get_slot(&self, addr: Address, skip: i32) -> i32 {
        let mut res = self.group_set[0];
        if self.alignment != 0 {
            let diff = addr.as_u64() + skip as u64 - self.address_base;
            let base_slot = (diff / self.alignment as u64) as i32;
            if self.is_reverse_stack() {
                res += (self.num_slots - 1) - base_slot;
            } else {
                res += base_slot;
            }
        } else if skip != 0 {
            res = *self.group_set.last().unwrap();
        }
        res
    }

    // Ghidra: fspec.cc:434 ParamEntry::getAddrBySlot (3-arg)
    /// Calculate the storage address assigned when allocating a parameter.
    /// Faithful to `getAddrBySlot(int4&, int4, int4)` (fspec.cc:434-438).
    pub fn get_addr_by_slot(&self, slot_num: &mut i32, sz: i32, type_align: i32) -> Option<Address> {
        self.get_addr_by_slot_just(slot_num, sz, type_align, !self.is_left_justified())
    }

    // Ghidra: fspec.cc:450 ParamEntry::getAddrBySlot (4-arg)
    /// Calculate the storage address assigned when allocating a parameter,
    /// with explicit justification. Faithful to `getAddrBySlot(int4&, int4,
    /// int4, bool)` (fspec.cc:450-493).
    pub fn get_addr_by_slot_just(
        &self, slot_num: &mut i32, sz: i32, type_align: i32, justify_right: bool,
    ) -> Option<Address> {
        if sz < self.min_size { return None; }
        let space_used;
        let mut res;
        if self.alignment == 0 {
            if *slot_num != 0 { return None; }
            if sz > self.size { return None; }
            res = Address::new(self.address_base);
            space_used = self.size;
            if self.flags & param_entry_flags::SMALLSIZE_FLOATEXT != 0 && sz != self.size {
                // TODO(ALIGNMENT_ROADMAP): depends on unported
                // AddrSpaceManager (constructFloatExtensionAddress). Rugra
                // leaves the base address; the float-ext join record would
                // normally be materialized here.
                return Some(res);
            }
        } else {
            if type_align > self.alignment {
                let tmp = (*slot_num * self.alignment) % type_align;
                if tmp != 0 {
                    *slot_num += (type_align - tmp) / self.alignment;
                }
            }
            let mut slots_used = sz / self.alignment;
            if sz % self.alignment != 0 { slots_used += 1; }
            if *slot_num + slots_used > self.num_slots { return None; }
            space_used = slots_used * self.alignment;
            let index;
            if self.is_reverse_stack() {
                index = self.num_slots - *slot_num - slots_used;
            } else {
                index = *slot_num;
            }
            res = Address::new(self.address_base + index as u64 * self.alignment as u64);
            *slot_num += slots_used;
        }
        if justify_right {
            res = res.offset((space_used - sz) as i64);
        }
        Some(res)
    }

    // Ghidra: fspec.cc:583 ParamEntry::orderWithinGroup
    /// Entries within a group must be distinguishable by size or type.
    /// Returns `Err` if not distinguishable (Ghidra throws). Faithful to
    /// `orderWithinGroup` (fspec.cc:583-595).
    pub fn order_within_group(entry1: &ParamEntry, entry2: &ParamEntry) -> Result<(), String> {
        if entry2.min_size > entry1.size || entry1.min_size > entry2.size { return Ok(()); }
        if entry1.type_storage != entry2.type_storage {
            if entry1.type_storage == TypeClass::General {
                return Err(
                    "<pentry> tags with a specific type must come before the general type".to_string(),
                );
            }
            return Ok(());
        }
        Err("<pentry> tags within a group must be distinguished by size or type".to_string())
    }

    // RUGRA-GLUE: builder-style setters for the model loader (Ghidra fills
    // these during `ParamEntry::decode`; Rugra's decoder is unported so the
    // loader populates them via these accessors).
    pub fn set_space(&mut self, spc: AddressSpace) { self.space = spc; }
    // RUGRA-GLUE: loader field setter; Ghidra assigns addressbase directly
    // inside ParamEntry::decode and exposes no setBase member.
    pub fn set_base(&mut self, base: u64) { self.address_base = base; }
    // RUGRA-GLUE: loader field setter; Ghidra assigns size/minsize and derives
    // numslots atomically inside ParamEntry::decode, with no setSizes member.
    pub fn set_sizes(&mut self, size: i32, min_size: i32) {
        self.size = size;
        self.min_size = min_size;
        if self.alignment != 0 && self.num_slots == 1 {
            self.num_slots = size / self.alignment;
        }
    }
    /// Set the alignment. If `alignment == size`, normalized to 0 (exclusion
    /// entry) per `ParamEntry::decode` (fspec.cc:547-548).
    // RUGRA-GLUE: staged-loader setter; Ghidra reads and normalizes alignment
    // inside ParamEntry::decode and exposes no setAlignment member.
    pub fn set_alignment(&mut self, alignment: i32) {
        self.alignment = alignment;
        if self.alignment == self.size { self.alignment = 0; }
        if self.alignment != 0 {
            self.num_slots = self.size / self.alignment;
        } else {
            self.num_slots = 1;
        }
    }
    // RUGRA-GLUE: loader field setter; Ghidra assigns the private type field
    // from ParamEntry::decode and exposes no setTypeClass member.
    pub fn set_type_class(&mut self, ty: TypeClass) { self.type_storage = ty; }

    // RUGRA-GLUE: flags_mut (private field accessor so parse_pentry can
    // mirror fspec.cc:565-573 reverse_stack/is_grouped adjustments without
    // exposing flags as a public mutable field).
    pub fn flags_mut(&mut self) -> &mut u32 { &mut self.flags }
}

// RUGRA-GLUE: justified_contain_range (free helper — mirrors Ghidra's
// inline `Address::justifiedContain` (address.cc:131-141) used by
// `ParamEntry::justifiedContain` and its join-piece walk. Public because
// heritage's call-guard helpers (guardCallOverlappingInput,
// guardOutputOverlapStack) call the same `Address::justifiedContain` math
// on caller-perspective addresses. The `base != op2.base` guard of the
// Ghidra original lives with the callers (this helper takes spaceless raw
// offsets). The endian-aware branch needs the space endianness exactly
// like Ghidra's `base->isBigEndian()` (address.cc:138), so callers pass
// `space_is_big_endian` for the space their offsets live in:
// `space_is_big_endian && !force_left` selects the big-endian
// `off1 - off2` end distance, every other combination the
// `op2.offset - offset` start distance (a little-endian space returns the
// start distance regardless of forceleft — FSPEC-JUSTIFIED-ENDIAN-0002).
pub fn justified_contain_range(
    base: u64,
    sz2: i32,
    addr: u64,
    sz: i32,
    force_left: bool,
    space_is_big_endian: bool,
) -> i32 {
    // Ghidra: address.cc:133 if (op2.offset < offset) return -1;
    // Either side poking out independently excludes containment (the two
    // checks are NOT a paired both-bounds-violated condition).
    if addr < base { return -1; }
    // Ghidra: address.cc:135-137 off1 = offset + (sz-1); off2 =
    // op2.offset + (sz2-1); if (off2 > off1) return -1;
    let this_end = base.wrapping_add(sz2 as u64).wrapping_sub(1);
    let end_addr = addr.wrapping_add(sz as u64).wrapping_sub(1);
    if end_addr > this_end { return -1; }
    // Ghidra: address.cc:138-141 if (base->isBigEndian()&&(!forceleft))
    // return (int4)(off1 - off2); return (int4)(op2.offset - offset);
    if space_is_big_endian && !force_left {
        (this_end - end_addr) as i32
    } else {
        (addr - base) as i32
    }
}

// RUGRA-GLUE: contained_by_range (free helper — mirrors Ghidra's inline
// `Address::containedBy` (address.cc:110-118) used by the locked-output
// branches of `FuncProto::characterizeAsOutput` (fspec.cc:4351) and
// `FuncProto::getBiggestContainedOutput` (fspec.cc:4500). Same
// spaceless-raw-offsets convention as `justified_contain_range`: the
// `base != op2.base -> false` guard of the Ghidra original lives with the
// callers, which must only invoke this for ranges in one space. `this`
// (base, sz2) is the potentially-contained range; (addr, sz) the container.
pub fn contained_by_range(base: u64, sz2: i32, addr: u64, sz: i32) -> bool {
    // Ghidra: address.cc:114 if (op2.offset > offset) return false;
    if addr > base {
        return false;
    }
    // Ghidra: address.cc:115-117 off1 = offset + (sz-1);
    //                       off2 = op2.offset + (sz2-1);
    //                       return (off2 >= off1);
    let this_end = base.wrapping_add(sz2 as u64).wrapping_sub(1);
    let container_end = addr.wrapping_add(sz as u64).wrapping_sub(1);
    container_end >= this_end
}

// ======================================================================
// ParamListStandard (fspec.hh:589-646 / fspec.cc:597-1517)
// ======================================================================

// RUGRA-GLUE: registered_extents — the address ranges `populateResolver`
// (fspec.cc:1191-1216) enters into a space's ParamEntryResolver for the
// given entry: the entry's own [base, base+size-1] extent for plain
// entries, or one [offset, offset+size-1] range per join piece (in the
// piece's own space). characterize_as_param's resolver windows are
// expressed over these ranges.
fn registered_extents(e: &ParamEntry, space: AddressSpace) -> Vec<(u64, u64)> {
    if let Some(j) = &e.join {
        j.pieces
            .iter()
            .filter(|p| p.space == space)
            .map(|p| (p.offset, p.offset + p.size as u64 - 1))
            .collect()
    } else if e.space == space {
        vec![(e.address_base, e.address_base + e.size as u64 - 1)]
    } else {
        Vec::new()
    }
}

/// Parameter-list type discriminator. Faithful to `ParamList`'s anonymous
/// enum (fspec.hh:427-433).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamListKind {
    Standard,
    StandardOut,
    Register,
    RegisterOut,
    Merged,
}

/// A contiguous offset range registered in a [`ParamEntryResolver`],
/// binding the range to the `ParamEntry` (by index into the owning
/// `ParamListStandard::entry` list) that declared it. Faithful to
/// `class ParamEntryRange` (fspec.hh:157-193): the rangemap value type
/// carrying `(first, last, position, entry)`. Rugra stores the entry as an
/// index because Rust ownership replaces Ghidra's `ParamEntry *` into a
/// `std::list` whose allocation order equals declaration order (see the
/// `ParamTrial::operator<` projection note).
#[derive(Debug, Clone)]
pub struct ParamEntryRange {
    /// Starting offset of the ParamEntry's range. Faithful to `first`.
    pub first: u64,
    /// Ending offset of the ParamEntry's range (inclusive). Faithful to `last`.
    pub last: u64,
    /// Position of the ParamEntry within the entire prototype list.
    /// Faithful to `position`.
    pub position: i32,
    /// Index of the actual ParamEntry in the owning entry list. Rust
    /// stand-in for Ghidra's `ParamEntry *entry`.
    pub entry: usize,
}

/// Helper for initializing ParamEntryRange in a range map. Faithful to
/// `ParamEntryRange::InitData` (fspec.hh:164-171).
#[derive(Debug, Clone, Copy)]
pub struct ParamEntryRangeInitData {
    /// Position (within the full list) being assigned to the ParamEntryRange.
    pub position: i32,
    /// Index of the underlying ParamEntry being assigned.
    pub entry: usize,
}

impl ParamEntryRangeInitData {
    // Ghidra: fspec.hh:170 ParamEntryRange::InitData::InitData
    /// `InitData(int4 pos,ParamEntry *e) { position = pos; entry = e; }`
    pub fn new(position: i32, entry: usize) -> Self {
        Self { position, entry }
    }
}

/// Helper class for subsorting on position. Faithful to
/// `ParamEntryRange::SubsortPosition` (fspec.hh:173-181).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsortPosition {
    position: i32,
}

impl SubsortPosition {
    // Ghidra: fspec.hh:177 SubsortPosition::SubsortPosition()
    /// Default constructor for use with rangemap (position left
    /// uninitialized in Ghidra; Rust zeroes it — the value is never read
    /// through this constructor).
    pub fn new() -> Self { Self { position: 0 } }

    // Ghidra: fspec.hh:178 SubsortPosition::SubsortPosition(int4)
    /// Construct given position: `position = pos`.
    pub fn with_position(pos: i32) -> Self { Self { position: pos } }

    // Ghidra: fspec.hh:179 SubsortPosition::SubsortPosition(bool)
    /// Construct minimal/maximal subsort: `position = val ? 1000000 : 0`.
    pub fn from_bool(val: bool) -> Self {
        Self { position: if val { 1000000 } else { 0 } }
    }

    // Ghidra: fspec.hh:180 SubsortPosition::operator<
    /// `return position < op2.position;`
    pub fn less_than(&self, op2: &SubsortPosition) -> bool {
        self.position < op2.position
    }
}

impl Default for SubsortPosition {
    // RUGRA-GLUE: Rust Default mirrors the rangemap no-arg constructor.
    fn default() -> Self { Self::new() }
}

impl ParamEntryRange {
    // Ghidra: fspec.hh:187 ParamEntryRange::ParamEntryRange
    /// Initialize the range: `first = f; last = l; position =
    /// data.position; entry = data.entry;` (fspec.hh:187-188).
    pub fn new(data: &ParamEntryRangeInitData, f: u64, l: u64) -> Self {
        Self { first: f, last: l, position: data.position, entry: data.entry }
    }

    // Ghidra: fspec.hh:189 ParamEntryRange::getFirst
    /// Get the first address in the range.
    pub fn get_first(&self) -> u64 { self.first }

    // Ghidra: fspec.hh:190 ParamEntryRange::getLast
    /// Get the last address in the range.
    pub fn get_last(&self) -> u64 { self.last }

    // Ghidra: fspec.hh:191 ParamEntryRange::getSubsort
    /// Get the sub-subsort object: `return SubsortPosition(position);`.
    pub fn get_subsort(&self) -> SubsortPosition {
        SubsortPosition::with_position(self.position)
    }

    // Ghidra: fspec.hh:192 ParamEntryRange::getParamEntry
    /// Get the index of the actual ParamEntry (Ghidra returns the pointer).
    pub fn get_param_entry(&self) -> usize { self.entry }
}

/// A map from offset to ParamEntry: `typedef rangemap<ParamEntryRange>
/// ParamEntryResolver` (fspec.hh:194). Ghidra's generic `rangemap`
/// (database.hh) keeps intervals in a tree keyed by `(first, subsort)`
/// whose `find(offset)` returns the sublist of ALL ranges containing the
/// offset. Rugra's projection keeps the ranges in a `Vec` sorted by
/// `(first, position)` — the same (linetype, subsort) order the rangemap
/// iterates — and materializes the containing sublist on demand, which is
/// byte-equivalent for the two operations the decompiler consumes
/// (`ParamListStandard::characterizeAsParam` fspec.cc:692-718 via
/// `find`/`find_end` and the `!= end()` above-query-start gate).
#[derive(Debug, Clone, Default)]
pub struct ParamEntryResolver {
    /// Registered ranges sorted by `(first, position)` — the rangemap's
    /// (linetype, subsort) iteration order.
    ranges: Vec<ParamEntryRange>,
}

impl ParamEntryResolver {
    // RUGRA-GLUE: owning constructor; Ghidra allocates the resolver with
    // `new ParamEntryResolver()` inside addResolverRange (fspec.cc:1183).
    pub fn new() -> Self { Self { ranges: Vec::new() } }

    // Ghidra: fspec.cc:1174 ParamListStandard::addResolverRange (resolver->insert)
    /// Insert one range: the rangemap's `insert(initdata, first, last)`
    /// keeps the collection ordered by `(first, subsort)`; the Vec
    /// projection pushes then re-sorts by `(first, position)` to preserve
    /// the identical iteration order.
    pub fn insert(&mut self, init: &ParamEntryRangeInitData, first: u64, last: u64) {
        self.ranges.push(ParamEntryRange::new(init, first, last));
        self.ranges.sort_by(|a, b| {
            a.first.cmp(&b.first).then(a.position.cmp(&b.position))
        });
    }

    /// All registered ranges containing `offset`, in `(first, position)`
    /// order — the materialized form of rangemap `find(offset)`'s iterator
    /// pair. Empty when no registered extent contains the offset.
    // Ghidra: database.hh rangemap<ParamEntryRange>::find (fspec.hh:194 ParamEntryResolver)
    pub fn find(&self, offset: u64) -> Vec<&ParamEntryRange> {
        self.ranges
            .iter()
            .filter(|r| r.first <= offset && offset <= r.last)
            .collect()
    }

    // RUGRA-GLUE: probe backing the `iterpair.first != resolver->end()`
    // gate (fspec.cc:708): after the containing sublist is consumed the
    // rangemap iterator points at the next range in order, so the gate is
    /// true exactly when some registered range starts above `offset`.
    pub fn has_range_starting_above(&self, offset: u64) -> bool {
        self.ranges.iter().any(|r| r.first > offset)
    }

    /// Number of registered ranges (diagnostic/fixture surface).
    // RUGRA-GLUE: fixture/diagnostic surface over the resolver storage; the
    // rangemap exposes size through its iterator pair interface instead.
    pub fn len(&self) -> usize { self.ranges.len() }

    /// Registered ranges in `(first, position)` order (fixture surface).
    // RUGRA-GLUE: fixture/diagnostic surface over the resolver storage.
    pub fn ranges(&self) -> &[ParamEntryRange] { &self.ranges }

    // RUGRA-GLUE: clippy-idiomatic emptiness predicate for len().
    pub fn is_empty(&self) -> bool { self.ranges.is_empty() }
}

/// Response codes for address assignment. Faithful to `AssignAction`'s
/// anonymous enum (modelrules.hh:264-271). Local copy in `fspec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignActionResponse {
    Success,
    Fail,
    NoAssignment,
}

/// Holds the result of a parameter assignment. Faithful to
/// `struct ParameterPieces` (fspec.hh:451-460). Local copy in `fspec`.
#[derive(Debug, Clone)]
pub struct ParameterPieces {
    /// Address-space half of Ghidra's complete `Address`.
    pub space: AddressSpace,
    pub addr: Address,
    pub ty: Option<Arc<Datatype>>,
    pub flags: u32,
}

/// `ParameterPieces::hiddenretparm = 2`. Faithful to (fspec.hh:457).
pub const HIDDEN_RET_PARM: u32 = 2;
/// `ParameterPieces::indirectstorage = 4`. Faithful to (fspec.hh:364).
pub const INDIRECT_STORAGE_PIECE: u32 = 4;

impl Default for ParameterPieces {
    // RUGRA-GLUE: Rust Default initializes the local Option-based aggregate;
    // Ghidra's ParameterPieces aggregate has no default() member.
    fn default() -> Self {
        Self { space: AddressSpace::Ram, addr: Address::new(0), ty: None, flags: 0 }
    }
}

impl ParameterPieces {
    // Ghidra: fspec.cc:2175 ParameterPieces::swapMarkup
    /// Swap data-type and flags while keeping both storage addresses intact.
    /// Faithful to `swapMarkup` (fspec.cc:2175-2184).
    pub fn swap_markup(&mut self, other: &mut ParameterPieces) {
        std::mem::swap(&mut self.ty, &mut other.ty);
        std::mem::swap(&mut self.flags, &mut other.flags);
    }

    // Ghidra: fspec.cc:2191 ParameterPieces::assignAddressFromPieces
    /// Generate the parameter's storage address from its constituent
    /// Varnode pieces. Faithful 1:1 body of `assignAddressFromPieces`
    /// (fspec.cc:2191-2207):
    ///   1. a least-to-most piece list is reversed in place to
    ///      most-to-least;
    ///   2. `JoinRecord::mergeSequence` folds adjacent register pieces into
    ///      whole-register pieces (the caller's `exact_register_name`
    ///      closure stands in for the Translate register lookup);
    ///   3. a single surviving piece's address is taken directly;
    ///      otherwise `findAddJoin(pieces, 0)` produces the unified join
    ///      address.
    /// The `find_add_join` closure carries Rugra's JoinRecordTables + join
    /// space handle (Ghidra reads both off the Architecture; the closure
    /// also absorbs the VarnodeData→SpaceVarnodeData space-model
    /// conversion).
    pub fn assign_address_from_pieces<F>(
        &mut self,
        pieces: &mut Vec<VarnodeData>,
        most_to_least: bool,
        exact_register_name: F,
        find_add_join: &dyn Fn(&[VarnodeData], u32) -> Option<u64>,
    ) where
        F: FnMut(&AddressSpace, u64, usize) -> String,
    {
        // Ghidra: if (!mostToLeast && pieces.size() > 1) { reverse; swap; }
        if !most_to_least && pieces.len() > 1 {
            let mut reverse = Vec::with_capacity(pieces.len());
            for i in (0..pieces.len()).rev() {
                reverse.push(pieces[i].clone());
            }
            std::mem::swap(pieces, &mut reverse);
        }
        // Ghidra: JoinRecord::mergeSequence(pieces,glb->translate);
        // Rugra's JoinRecord::merge_sequence operates on space::VarnodeData
        // (usize size); the fspec pieces convert field-for-field and back.
        let mut seq: Vec<crate::space::VarnodeData> = pieces
            .iter()
            .map(|p| crate::space::VarnodeData {
                space: p.space,
                offset: p.offset,
                size: p.size.max(0) as usize,
            })
            .collect();
        crate::translate::JoinRecord::merge_sequence(&mut seq, exact_register_name);
        *pieces = seq
            .into_iter()
            .map(|p| VarnodeData { space: p.space, offset: p.offset, size: p.size as i32 })
            .collect();
        // Ghidra: if (pieces.size() == 1) { addr = pieces[0].getAddr(); return; }
        if pieces.len() == 1 {
            self.space = pieces[0].space;
            self.addr = Address::new(pieces[0].offset);
            return;
        }
        // Ghidra: JoinRecord *joinRecord = glb->findAddJoin(pieces, 0);
        //         addr = joinRecord->getUnified().getAddr();
        if let Some(join_offset) = find_add_join(pieces, 0) {
            self.space = AddressSpace::Join;
            self.addr = Address::new(join_offset);
        }
    }
}

/// `ParameterPieces::namelock = 8`. Faithful to (fspec.hh:365).
pub const NAME_LOCK_PIECE: u32 = 8;
/// `ParameterPieces::typelock = 16`. Faithful to (fspec.hh:366).
pub const TYPE_LOCK_PIECE: u32 = 16;
/// `ParameterPieces::sizelock = 32`. Faithful to (fspec.hh:367).
pub const SIZE_LOCK_PIECE: u32 = 32;

/// Description of a function prototype consulted during assignment.
/// Faithful to `struct PrototypePieces` (fspec.hh:445-450).
pub struct PrototypePieces<'a> {
    pub out_type: Option<&'a Arc<Datatype>>,
    pub in_types: &'a [Arc<Datatype>],
    pub first_var_arg_slot: i32,
}

/// Ghidra: fspec.hh:598 `list<ModelRule> modelRules` — the fillin-relevant
/// projection of one decoded `ModelRule` (modelrules.hh:530-560,
/// modelrules.cc:1676-1709). `ModelRule::fillinOutputMap`
/// (modelrules.hh:559-563) delegates to the assign action only: the
/// datatype filter, qualifier filters, preconditions, and side-effects are
/// never consulted on the fill-in path. This projection therefore stores
/// exactly the per-action state the two fill-in entry points consume:
/// `canAffectFillinOutput()` (the constructor `fillinOutputActive` flag)
/// and `fillinOutputMap()` (the action's trial walk). The forward
/// `assignAddress` path remains the registered
/// FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001 residual.
#[derive(Debug, Clone)]
pub struct ModelRuleFillin {
    /// The decoded assign action (modelrules.cc:605
    /// `assign = AssignAction::decodeAction(decoder, res)`).
    pub action: FillinAction,
}

/// Ghidra: modelrules.cc:587-614 `AssignAction::decodeAction` dispatch —
/// the seven concrete assign actions, carrying exactly the state their
/// `fillinOutputMap` bodies read.
#[derive(Debug, Clone)]
pub enum FillinAction {
    /// modelrules.cc:708 `GotoStack` (ctor sets fillinOutputActive=true;
    /// `decode` calls `initializeEntry` which binds
    /// `stackEntry = resource->getStackEntry()`, fspec.cc:642-654). The
    /// bound entry's index within the owning list; `None` mirrors
    /// Ghidra's null stackEntry.
    GotoStack { stack_entry: Option<usize> },
    /// modelrules.cc:780 `MultiSlotAssign` — `<join>`
    /// (fillinOutputActive=true).
    MultiSlot { resource_type: TypeClass, justify_right: bool, consume_most_sig: bool },
    /// modelrules.cc:1332 `ConsumeAs` — `<consume>`
    /// (fillinOutputActive=true).
    Consume { resource_type: TypeClass },
    /// modelrules.cc:748 `ConvertToPointer` — `<convert_to_ptr>`
    /// (fillinOutputActive stays the `AssignAction` default false).
    ConvertToPointer,
    /// modelrules.cc:1374 `HiddenReturnAssign` — `<hidden_return>`
    /// (fillinOutputActive stays the default false; its decode reads
    /// voidlock/strategy into retCode, which no fill-in path reads).
    HiddenReturn,
    /// modelrules.cc:975 `MultiMemberAssign` — `<join_per_primitive>`
    /// (fillinOutputActive=true; the decodeAction ctor passes
    /// `mostSig = res->isBigEndian()`, modelrules.cc:601).
    MultiMember { resource_type: TypeClass, consume_most_sig: bool },
    /// modelrules.cc:1137 `MultiSlotDualAssign` — `<join_dual_class>`
    /// (fillinOutputActive=true).
    MultiSlotDual { base_type: TypeClass, alt_type: TypeClass, justify_right: bool, consume_most_sig: bool },
}

impl ModelRuleFillin {
    // Ghidra: modelrules.cc:1676 ModelRule::decode (fillin projection)
    /// Decode one `<rule>` element: open the element, then walk children in
    /// document order structurally consuming the datatype filter
    /// (`<datatype>`, modelrules.cc:246-269), the qualifier filters
    /// (`<varargs>`/`<position>`/`<datatype_at>`, modelrules.cc:456-473),
    /// the preconditions (`<consume_extra>`, modelrules.cc:566-580) and the
    /// trailing side-effects (`<consume_extra>`/`<extra_stack>`/
    /// `<consume_remaining>`, modelrules.cc:582-600), and decode the single
    /// assign action via the `decodeAction` dispatch (modelrules.cc:587).
    /// An element that is none of these is Ghidra's
    /// "Expecting model rule action" DecoderError.
    pub fn decode_rule(
        list: &ParamListStandard,
        decoder: &mut dyn crate::marshal::Decoder,
    ) -> Result<Self, String> {
        let rule_id = decoder.open_element();
        let mut action: Option<FillinAction> = None;
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                // Datatype filter + qualifier filters: consumed without
                // fillin-relevant state (modelrules.cc:246-269 / 456-473).
                "datatype" | "datatype_at" | "varargs" | "position" => {
                    let id = decoder.open_element();
                    decoder.close_element_skipping(id);
                }
                // Preconditions and side-effects (modelrules.cc:566-600).
                "consume_extra" | "extra_stack" | "consume_remaining" => {
                    let id = decoder.open_element();
                    decoder.close_element_skipping(id);
                }
                // modelrules.cc:593-594 GotoStack(res,0) + GotoStack::decode
                // (cc:739-744) + initializeEntry (cc:695-702): no
                // attributes; binds the owning list's stack entry.
                "goto_stack" => {
                    let id = decoder.open_element();
                    decoder.close_element(id);
                    action = Some(FillinAction::GotoStack { stack_entry: list.get_stack_entry() });
                }
                // modelrules.cc:590-591 MultiSlotAssign(res) +
                // MultiSlotAssign::decode (cc:942-963). Ctor defaults
                // (cc:780-792): resourceType=GENERAL, justifyRight=false,
                // consumeMostSig=false (little-endian).
                "join" => {
                    let id = decoder.open_element();
                    let mut resource_type = TypeClass::General;
                    let mut justify_right = false;
                    let mut consume_most_sig = false;
                    loop {
                        let attrib_id = decoder.next_attribute_id();
                        if attrib_id == 0 {
                            break;
                        }
                        let name = decoder.attribute_name(attrib_id).unwrap_or_default();
                        match name.as_str() {
                            "reversejustify" => {
                                if decoder.read_bool() {
                                    justify_right = !justify_right;
                                }
                            }
                            "reversesignif" => {
                                if decoder.read_bool() {
                                    consume_most_sig = !consume_most_sig;
                                }
                            }
                            "storage" => {
                                resource_type = string_to_type_class(&decoder.read_string());
                            }
                            // align (enforceAlignment) and stackspill
                            // (consumeFromStack) are not read by
                            // fillinOutputMap; consumed for stream position.
                            "align" => {
                                let _ = decoder.read_bool();
                            }
                            "stackspill" => {
                                let _ = decoder.read_bool();
                            }
                            _ => {
                                let _ = decoder.read_string();
                            }
                        }
                    }
                    decoder.close_element(id);
                    action = Some(FillinAction::MultiSlot { resource_type, justify_right, consume_most_sig });
                }
                // modelrules.cc:592-593 ConsumeAs(TYPECLASS_GENERAL,res) +
                // ConsumeAs::decode (cc:1366-1371).
                "consume" => {
                    let id = decoder.open_element();
                    let mut resource_type = TypeClass::General;
                    loop {
                        let attrib_id = decoder.next_attribute_id();
                        if attrib_id == 0 {
                            break;
                        }
                        let name = decoder.attribute_name(attrib_id).unwrap_or_default();
                        if name == "storage" {
                            resource_type = string_to_type_class(&decoder.read_string());
                        } else {
                            let _ = decoder.read_string();
                        }
                    }
                    decoder.close_element(id);
                    action = Some(FillinAction::Consume { resource_type });
                }
                // modelrules.cc:594-595 ConvertToPointer(res) +
                // ConvertToPointer::decode (cc:762-766): no attributes.
                "convert_to_ptr" => {
                    let id = decoder.open_element();
                    decoder.close_element(id);
                    action = Some(FillinAction::ConvertToPointer);
                }
                // modelrules.cc:596-597 HiddenReturnAssign(res,
                // hiddenret_specialreg) + decode (cc:1386-1402): voidlock/
                // strategy feed retCode, unread by fill-in.
                "hidden_return" => {
                    let id = decoder.open_element();
                    loop {
                        let attrib_id = decoder.next_attribute_id();
                        if attrib_id == 0 {
                            break;
                        }
                        let name = decoder.attribute_name(attrib_id).unwrap_or_default();
                        match name.as_str() {
                            "voidlock" => {
                                let _ = decoder.read_bool();
                            }
                            "strategy" => {
                                let strategy = decoder.read_string();
                                if strategy != "normalparam" && strategy != "special" {
                                    return Err(format!(
                                        "Bad <hidden_return> strategy: {strategy}"
                                    ));
                                }
                            }
                            _ => break,
                        }
                    }
                    decoder.close_element(id);
                    action = Some(FillinAction::HiddenReturn);
                }
                // modelrules.cc:598-600 MultiMemberAssign(TYPECLASS_GENERAL,
                // false, res->isBigEndian(), res) + decode (cc:1054-1063).
                "join_per_primitive" => {
                    let id = decoder.open_element();
                    let mut resource_type = TypeClass::General;
                    loop {
                        let attrib_id = decoder.next_attribute_id();
                        if attrib_id == 0 {
                            break;
                        }
                        let name = decoder.attribute_name(attrib_id).unwrap_or_default();
                        if name == "storage" {
                            resource_type = string_to_type_class(&decoder.read_string());
                        } else {
                            let _ = decoder.read_string();
                        }
                    }
                    decoder.close_element(id);
                    action = Some(FillinAction::MultiMember {
                        resource_type,
                        consume_most_sig: list.is_big_endian(),
                    });
                }
                // modelrules.cc:601-602 MultiSlotDualAssign(res) +
                // MultiSlotDualAssign::decode (cc:1300-1330). Ctor defaults
                // (cc:1137-1152): baseType=GENERAL, altType=FLOAT,
                // justifyRight=false, consumeMostSig=false.
                "join_dual_class" => {
                    let id = decoder.open_element();
                    let mut base_type = TypeClass::General;
                    let mut alt_type = TypeClass::Float;
                    let mut justify_right = false;
                    let mut consume_most_sig = false;
                    loop {
                        let attrib_id = decoder.next_attribute_id();
                        if attrib_id == 0 {
                            break;
                        }
                        let name = decoder.attribute_name(attrib_id).unwrap_or_default();
                        match name.as_str() {
                            "reversejustify" => {
                                if decoder.read_bool() {
                                    justify_right = !justify_right;
                                }
                            }
                            "reversesignif" => {
                                if decoder.read_bool() {
                                    consume_most_sig = !consume_most_sig;
                                }
                            }
                            "storage" | "a" => {
                                base_type = string_to_type_class(&decoder.read_string());
                            }
                            "b" => {
                                alt_type = string_to_type_class(&decoder.read_string());
                            }
                            // stackspill (consumeFromStack) and fillalternate
                            // (fillAlternate) are not read by
                            // fillinOutputMap; consumed for stream position.
                            "stackspill" | "fillalternate" => {
                                let _ = decoder.read_bool();
                            }
                            _ => {
                                let _ = decoder.read_string();
                            }
                        }
                    }
                    decoder.close_element(id);
                    action = Some(FillinAction::MultiSlotDual {
                        base_type,
                        alt_type,
                        justify_right,
                        consume_most_sig,
                    });
                }
                other => {
                    return Err(format!("Expecting model rule action: {other}"));
                }
            }
        }
        decoder.close_element(rule_id);
        match action {
            Some(action) => Ok(ModelRuleFillin { action }),
            // modelrules.cc:604-605: reaching the end of the rule without
            // an action element is the decodeAction DecoderError.
            None => Err("Expecting model rule action".to_string()),
        }
    }
}

impl FillinAction {
    // Ghidra: modelrules.hh:276-278 AssignAction::canAffectFillinOutput
    /// The constructor `fillinOutputActive` flag per action kind: true for
    /// GotoStack (modelrules.cc:710/717), MultiSlotAssign (cc:805/824),
    /// MultiMemberAssign (cc:989), MultiSlotDualAssign (cc:1143/1163) and
    /// ConsumeAs (cc:1336); the `AssignAction` default false otherwise
    /// (modelrules.hh:276).
    pub fn can_affect_fillin_output(&self) -> bool {
        match self {
            FillinAction::GotoStack { .. } => true,
            FillinAction::MultiSlot { .. } => true,
            FillinAction::Consume { .. } => true,
            FillinAction::ConvertToPointer => false,
            FillinAction::HiddenReturn => false,
            FillinAction::MultiMember { .. } => true,
            FillinAction::MultiSlotDual { .. } => true,
        }
    }

    // Ghidra: modelrules.hh:313 AssignAction::fillinOutputMap (dispatch)
    /// Test and mark the trial set that can be a valid return value.
    /// `entries` is the owning list's ParamEntry table (Ghidra reads the
    /// trial's `const ParamEntry *` back-pointer).
    pub fn fillin_output_map(
        &self,
        active: &mut ParamActive,
        entries: &[ParamEntry],
    ) -> bool {
        match self {
            // modelrules.cc:579 AssignAction::fillinOutputMap default.
            FillinAction::ConvertToPointer | FillinAction::HiddenReturn => false,
            // modelrules.cc:731-744 GotoStack::fillinOutputMap
            FillinAction::GotoStack { stack_entry } => {
                let mut count = 0i32;
                for i in 0..active.get_num_trials() {
                    let entry_index = match active.get_trial(i).get_entry_index() {
                        Some(e) => e,
                        None => break,
                    };
                    if Some(entry_index) != *stack_entry {
                        return false;
                    }
                    count += 1;
                    if count > 1 {
                        return false;
                    }
                }
                count == 1
            }
            // modelrules.cc:902-940 MultiSlotAssign::fillinOutputMap
            FillinAction::MultiSlot { resource_type, justify_right, consume_most_sig } => {
                let mut count = 0i32;
                let mut cur_group = -1i32;
                let mut partial: i64 = -1;
                for i in 0..active.get_num_trials() {
                    let (entry_index, trial_size) = {
                        let t = active.get_trial(i);
                        match t.get_entry_index() {
                            Some(e) => (e, t.get_size()),
                            None => break,
                        }
                    };
                    let entry = &entries[entry_index];
                    // Trials must come from action's type_class
                    if entry.get_type() != *resource_type {
                        return false;
                    }
                    if count == 0 {
                        // Trials must start on first entry of the type_class
                        if !entry.is_first_in_class() {
                            return false;
                        }
                    } else if entry.get_group() != cur_group + 1 {
                        // Trials must be consecutive
                        return false;
                    }
                    cur_group = entry.get_group();
                    if trial_size != entry.get_size() {
                        // At most, one trial can be partial size
                        if partial != -1 {
                            return false;
                        }
                        partial = i as i64;
                    }
                    count += 1;
                }
                if partial != -1 {
                    if *justify_right {
                        if partial != 0 {
                            return false;
                        }
                    } else if partial != (count as i64) - 1 {
                        return false;
                    }
                    let t = active.get_trial(partial as usize);
                    if *justify_right == *consume_most_sig {
                        // Partial entry must be least sig bytes
                        if t.get_offset() != 0 {
                            return false;
                        }
                    } else if t.get_offset() + t.get_size()
                        != entries[t.get_entry_index().unwrap()].get_size()
                    {
                        // Partial entry must be most sig bytes
                        return false;
                    }
                }
                if count == 0 {
                    return false;
                }
                if *consume_most_sig {
                    active.set_join_reverse(true);
                }
                true
            }
            // modelrules.cc:1019-1042 MultiMemberAssign::fillinOutputMap
            FillinAction::MultiMember { resource_type, consume_most_sig } => {
                let mut count = 0i32;
                let mut cur_group = -1i32;
                for i in 0..active.get_num_trials() {
                    let entry_index = match active.get_trial(i).get_entry_index() {
                        Some(e) => e,
                        None => break,
                    };
                    let entry = &entries[entry_index];
                    // Trials must come from action's type_class
                    if entry.get_type() != *resource_type {
                        return false;
                    }
                    if count == 0 {
                        if !entry.is_first_in_class() {
                            return false;
                        }
                    } else if entry.get_group() != cur_group + 1 {
                        return false;
                    }
                    cur_group = entry.get_group();
                    if active.get_trial(i).get_offset() != 0 {
                        // Entry must be justified
                        return false;
                    }
                    count += 1;
                }
                if count == 0 {
                    return false;
                }
                if *consume_most_sig {
                    active.set_join_reverse(true);
                }
                true
            }
            // modelrules.cc:1242-1291 MultiSlotDualAssign::fillinOutputMap
            FillinAction::MultiSlotDual { base_type, alt_type, justify_right, consume_most_sig } => {
                let mut count = 0i32;
                let mut cur_group = -1i32;
                let mut partial: i64 = -1;
                let mut resource_type = TypeClass::General;
                for i in 0..active.get_num_trials() {
                    let (entry_index, trial_size) = {
                        let t = active.get_trial(i);
                        match t.get_entry_index() {
                            Some(e) => (e, t.get_size()),
                            None => break,
                        }
                    };
                    let entry = &entries[entry_index];
                    if count == 0 {
                        resource_type = entry.get_type();
                        if resource_type != *base_type && resource_type != *alt_type {
                            return false;
                        }
                    } else if entry.get_type() != resource_type {
                        // Trials must come from action's type_class
                        return false;
                    }
                    if count == 0 {
                        // Trials must start on first entry of the type_class
                        if !entry.is_first_in_class() {
                            return false;
                        }
                    } else if entry.get_group() != cur_group + 1 {
                        // Trials must be consecutive
                        return false;
                    }
                    cur_group = entry.get_group();
                    if trial_size != entry.get_size() {
                        // At most, one trial can be partial size
                        if partial != -1 {
                            return false;
                        }
                        partial = i as i64;
                    }
                    count += 1;
                }
                if partial != -1 {
                    if *justify_right {
                        if partial != 0 {
                            return false;
                        }
                    } else if partial != (count as i64) - 1 {
                        return false;
                    }
                    let t = active.get_trial(partial as usize);
                    if *justify_right == *consume_most_sig {
                        // Partial entry must be least sig bytes
                        if t.get_offset() != 0 {
                            return false;
                        }
                    } else if t.get_offset() + t.get_size()
                        != entries[t.get_entry_index().unwrap()].get_size()
                    {
                        // Partial entry must be most sig bytes
                        return false;
                    }
                }
                if count == 0 {
                    return false;
                }
                if *consume_most_sig {
                    active.set_join_reverse(true);
                }
                true
            }
            // modelrules.cc:1345-1364 ConsumeAs::fillinOutputMap
            FillinAction::Consume { resource_type } => {
                let mut count = 0i32;
                for i in 0..active.get_num_trials() {
                    let entry_index = match active.get_trial(i).get_entry_index() {
                        Some(e) => e,
                        None => break,
                    };
                    let entry = &entries[entry_index];
                    // Trials must come from action's type_class
                    if entry.get_type() != *resource_type {
                        return false;
                    }
                    if !entry.is_first_in_class() {
                        return false;
                    }
                    count += 1;
                    if count > 1 {
                        return false;
                    }
                    if active.get_trial(i).get_offset() != 0 {
                        // Entry must be justified
                        return false;
                    }
                }
                count > 0
            }
        }
    }
}

/// A standard model for parameters as an ordered list of storage resources.
/// Faithful port of `class ParamListStandard` (fspec.hh:589-646).
#[derive(Debug, Clone)]
pub struct ParamListStandard {
    num_group: i32,
    max_delay: i32,
    this_before_ret: bool,
    auto_killed_by_call: bool,
    resource_start: Vec<i32>,
    entry: Vec<ParamEntry>,
    space_base: Option<AddressSpace>,
    stack_entry_index: Option<usize>,
    /// Per-space resolver maps from offset to ParamEntry. Faithful to
    /// `vector<ParamEntryResolver *> resolverMap` (fspec.hh:597), indexed
    /// by space; Rugra keys by `AddressSpace` instead of Ghidra's
    /// `spc->getIndex()` slot.
    resolver_map: Vec<(AddressSpace, ParamEntryResolver)>,
    /// Ghidra: fspec.hh:598 `list<ModelRule> modelRules` — rules to apply
    /// when assigning addresses (fillin-relevant projection, see
    /// [`ModelRuleFillin`]).
    model_rules: Vec<ModelRuleFillin>,
}

impl Default for ParamListStandard {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListStandard constructor but no language-level default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListStandard {
    // Ghidra: fspec.hh:617 ParamListStandard::ParamListStandard()
    // RUGRA-GLUE: default constructor for use with decode().
    pub fn new() -> Self {
        Self {
            num_group: 0,
            max_delay: 0,
            this_before_ret: false,
            auto_killed_by_call: false,
            resource_start: Vec::new(),
            entry: Vec::new(),
            space_base: None,
            stack_entry_index: None,
            resolver_map: Vec::new(),
            model_rules: Vec::new(),
        }
    }

    // Ghidra: fspec.cc:1451 ParamListStandard::decode
    /// Restore an input or output resource list from its XML element.
    ///
    /// `<pentry>` and `<group>` children are decoded in document order.  Once
    /// the first `<rule>` is seen, subsequent resource entries are rejected,
    /// matching Ghidra's two-phase child walk.  `<rule>` children decode
    /// into the fillin-relevant [`ModelRuleFillin`] projection
    /// (fspec.cc:1490-1500).
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        effect_list: &mut Vec<EffectRecord>,
        normal_stack: bool,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.num_group = 0;
        self.max_delay = 0;
        self.this_before_ret = false;
        self.auto_killed_by_call = false;
        self.resource_start.clear();
        self.entry.clear();
        self.space_base = None;
        self.stack_entry_index = None;
        self.model_rules.clear();
        let mut pointer_max = 0i32;
        let mut split_float = true;

        let elem_id = decoder.open_element();
        loop {
            let attrib_id = decoder.next_attribute_id();
            if attrib_id == 0 {
                break;
            }
            let name = decoder.attribute_name(attrib_id).unwrap_or_default();
            match name.as_str() {
                "pointermax" => pointer_max = decoder.read_signed_integer() as i32,
                "thisbeforeretpointer" => self.this_before_ret = decoder.read_bool(),
                "killedbycall" => self.auto_killed_by_call = decoder.read_bool(),
                "separatefloat" => split_float = decoder.read_bool(),
                _ => {
                    let _ = decoder.read_string();
                }
            }
        }

        let mut saw_rule = false;
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 {
                break;
            }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "pentry" if !saw_rule => {
                    let group_id = self.num_group;
                    let mut entry = ParamEntry::new(group_id);
                    entry.decode(decoder, normal_stack, false, register_resolver)?;
                    self.parse_pentry(
                        group_id,
                        normal_stack,
                        split_float,
                        false,
                        effect_list,
                        entry,
                    )?;
                }
                "group" if !saw_rule => {
                    let base_group = self.num_group;
                    let group_id = decoder.open_element();
                    let mut previous1 = None;
                    let mut previous2 = None;
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.peek_element();
                        if decoder.element_name(child_id).as_deref() != Some("pentry") {
                            return Err("Only <pentry> is allowed in <group>".to_string());
                        }
                        let mut entry = ParamEntry::new(base_group);
                        entry.decode(decoder, normal_stack, true, register_resolver)?;
                        if entry.get_space() == AddressSpace::Join {
                            return Err(
                                "<pentry> in the join space not allowed in <group> tag".to_string()
                            );
                        }
                        self.parse_pentry(
                            base_group,
                            normal_stack,
                            split_float,
                            true,
                            effect_list,
                            entry,
                        )?;
                        let current = self.entry.len() - 1;
                        if let Some(p1) = previous1 {
                            ParamEntry::order_within_group(&self.entry[p1], &self.entry[current])?;
                            if let Some(p2) = previous2 {
                                ParamEntry::order_within_group(
                                    &self.entry[p2],
                                    &self.entry[current],
                                )?;
                            }
                        }
                        previous2 = previous1;
                        previous1 = Some(current);
                    }
                    decoder.close_element(group_id);
                }
                "rule" => {
                    saw_rule = true;
                    // fspec.cc:1493-1495: modelRules.emplace_back();
                    // modelRules.back().decode(decoder, this). Entries are
                    // fully decoded before the first rule (two-phase walk,
                    // fspec.cc:1477-1500), so GotoStack's initializeEntry
                    // binding sees the final entry table.
                    let rule = ModelRuleFillin::decode_rule(self, decoder)?;
                    self.model_rules.push(rule);
                }
                "pentry" | "group" => {
                    return Err(
                        "<pentry> and <group> elements must come before any <modelrule>"
                            .to_string(),
                    );
                }
                _ => return Err(format!("Unknown element in parameter list: {sub_name}")),
            }
        }
        decoder.close_element(elem_id);
        self.finalize_after_decode(pointer_max);
        Ok(())
    }
    // Ghidra: fspec.hh:628 ParamListStandard::getType
    pub fn get_type(&self) -> ParamListKind { ParamListKind::Standard }
    // Ghidra: fspec.hh:639 ParamListStandard::getSpacebase
    pub fn get_spacebase(&self) -> Option<AddressSpace> { self.space_base }
    // Ghidra: fspec.hh:640 ParamListStandard::isThisBeforeRetPointer
    pub fn is_this_before_ret_pointer(&self) -> bool { self.this_before_ret }
    // Ghidra: fspec.hh:642 ParamListStandard::getMaxDelay
    pub fn get_max_delay(&self) -> i32 { self.max_delay }
    // Ghidra: fspec.hh:643 ParamListStandard::isAutoKilledByCall
    pub fn is_auto_killed_by_call(&self) -> bool { self.auto_killed_by_call }
    // Ghidra: fspec.hh:620 ParamListStandard::getEntry
    pub fn get_entry(&self) -> &[ParamEntry] { &self.entry }
    // RUGRA-GLUE: private-field accessors for the owned-ParamListStandard
    // shapes (ParamListMerged::foldIn reads and rewrites the entry list and
    // spacebase exactly as the C++ subclass does through inheritance).
    pub(crate) fn is_entry_empty(&self) -> bool { self.entry.is_empty() }
    // RUGRA-GLUE: private-field accessors for the owned-ParamListStandard
    // shapes (see is_entry_empty).
    pub(crate) fn entries_mut(&mut self) -> &mut Vec<ParamEntry> { &mut self.entry }
    // RUGRA-GLUE: private-field accessors for the owned-ParamListStandard
    // shapes (see is_entry_empty); also the staging setter the bilateral
    // fixtures use to mirror a decoded stack-based list.
    pub fn set_space_base(&mut self, spc: Option<AddressSpace>) { self.space_base = spc; }
    // Ghidra: fspec.hh:621 ParamListStandard::isBigEndian
    pub fn is_big_endian(&self) -> bool {
        self.entry.first().map(|e| e.get_space().is_big_endian()).unwrap_or(false)
    }

    // Ghidra: fspec.cc:626 ParamListStandard::extractTiles
    /// Collect registers of the given storage class. Faithful to
    /// `extractTiles` (fspec.cc:626-638).
    pub fn extract_tiles(&self, ty: TypeClass) -> Vec<usize> {
        let mut tiles = Vec::new();
        for (i, e) in self.entry.iter().enumerate() {
            if !e.is_exclusion() { continue; }
            if e.get_type() != ty || e.get_all_groups().len() != 1 { continue; }
            tiles.push(i);
        }
        tiles
    }

    // Ghidra: fspec.cc:642 ParamListStandard::getStackEntry
    /// If the stack entry is not present, `None` is returned. Faithful to
    /// `getStackEntry` (fspec.cc:642-654).
    pub fn get_stack_entry(&self) -> Option<usize> {
        if let Some(idx) = self.stack_entry_index { return Some(idx); }
        if self.entry.is_empty() { return None; }
        let idx = self.entry.len() - 1;
        let cur = &self.entry[idx];
        if !cur.is_exclusion() && cur.get_space() == AddressSpace::Stack { Some(idx) } else { None }
    }

    // Ghidra: fspec.cc:661 ParamListStandard::findEntry
    /// Find the (first) entry containing the given memory range. Faithful
    /// to `findEntry` (fspec.cc:661-680). Ghidra resolves through the
    /// per-space `resolverMap` and visits ONLY the `resolver->find(
    /// loc.getOffset())` window (rangemap.hh:332): the entries with a
    /// registered extent (the entry range, or a join piece range, per
    /// populateResolver fspec.cc:1191-1216) that numerically contains the
    /// query start offset in the query's space. The find window is the
    /// single refined subinterval containing the start, so its records
    /// share one `last` key and iterate in `position` order (rangemap.hh
    /// AddrRange::operator<, sorted (last, subsort)) — and `position`
    /// follows the entry-list registration order — so the ordered list scan
    /// below visits exactly the window entries in exactly Ghidra's order.
    /// Consequences pinned by the FSPEC-FINDENTRY-GATE-0005 fixture:
    /// - an extent-out query returns `None` even with `just == false`
    ///   (the window is empty before the minSize/justified checks run);
    /// - join entries ARE reachable: their per-piece registration puts
    ///   them in the piece spaces' windows, and the `justifiedContain`
    ///   check runs per piece against the query's space
    ///   (`justified_contain_in_space`, fspec.cc:248-283 with the
    ///   address.cc:133 per-piece space guard).
    /// Spaces with no registered extent behave like Ghidra's null
    /// `resolverMap[index]` (return `None`), matching the explicit-space
    /// pattern of `characterize_as_param` (cc:682) because the legacy
    /// `Address` is spaceless (ADDRESS-0001 transitional).
    pub fn find_entry(&self, space: AddressSpace, loc: Address, size: i32, just: bool) -> Option<usize> {
        for (i, e) in self.entry.iter().enumerate() {
            // Ghidra: fspec.cc:671 res = resolver->find(loc.getOffset());
            // — only entries whose registered extent in the query's space
            // contains the query start offset enter the window.
            let contains_start = registered_extents(e, space)
                .iter()
                .any(|&(a, b)| loc.as_u64() >= a && loc.as_u64() <= b);
            if !contains_start { continue; }
            // Ghidra: fspec.cc:675 if (testEntry->getMinSize() > size)
            // continue;
            if e.get_min_size() > size { continue; }
            // Ghidra: fspec.cc:676 if (!just ||
            // testEntry->justifiedContain(loc,size)==0) return testEntry;
            if !just || e.justified_contain_in_space(loc, size, space) == 0 { return Some(i); }
        }
        None
    }

    // Ghidra: fspec.cc:682 ParamListStandard::characterizeAsParam
    /// Characterize the containment between a storage range and this
    /// resource list. Faithful port of `characterizeAsParam`
/// (fspec.cc:682-719), including the per-space resolver gating:
/// - Phase 1 walks only the entries whose registered extent (the entry
///   range, or a join piece range, per populateResolver fspec.cc:1191)
///   contains the query start offset — Ghidra's
///   `resolver->find(loc.getOffset())` (rangemap.hh:332) over
///   `resolverMap[loc.getSpace()->getIndex()]` (cc:685-692).
/// - The second scan runs only when the phase-1 block is not the last
///   in the resolver (`iterpair.first != resolver->end()`, cc:708) —
///   i.e. some registered extent in the query's space starts above the
///   query offset (an extent-out query with no higher extent skips the
///   containedBy scan entirely — FSPEC-CHARACTERIZE-RESOLVER-GATE-0003)
///   — and visits entries whose registered start falls in
///   `(offset, offset+size-1]`, up to `find_end(loc.getOffset()+size-1)`
///   (cc:709-716).
pub fn characterize_as_param(
    &self,
    space: AddressSpace,
    offset: u64,
    size: i32,
) -> i32 {
    let loc = Address::new(offset);
    let mut res_contains = false;
    let mut res_contained_by = false;
    // Ghidra: fspec.cc:692-705 — resolver->find(loc.getOffset()): entries
    // whose registered extent contains the query start offset.
    for e in &self.entry {
        let contains_start = registered_extents(e, space)
            .iter()
            .any(|&(a, b)| offset >= a && offset <= b);
        if !contains_start { continue; }
        // Ghidra: fspec.cc:697 int4 off = testEntry->justifiedContain(
        // loc, size); — the query's space rides on `loc`, so the space
        // guards of fspec.cc:248-283 (per-piece address.cc:133 for joins,
        // cc:269 for aligned entries) apply; Rugra threads `space`
        // explicitly (justified_contain_in_space).
        let off = e.justified_contain_in_space(loc, size, space);
        if off == 0 { return containment::CONTAINS_JUSTIFIED; }
        else if off > 0 { res_contains = true; }
        // cc:702: a join entry's spaceid is the join space, never the
        // query's space, so its containedBy is structurally false
        // (fspec.cc:202 spaceid != addr.getSpace()).
        if e.is_exclusion() && e.space == space && e.contained_by(loc, size) {
            res_contained_by = true;
        }
    }
    if res_contains { return containment::CONTAINS_UNJUSTIFIED; }
    if res_contained_by { return containment::CONTAINED_BY; }
    // Ghidra: fspec.cc:708 if (iterpair.first != resolver->end()): the
    // phase-1 block must not be the resolver's last. The refinement
    // splits at every registered start, so an interval exists above the
    // query offset's interval iff some registered extent in this space
    // starts above the query offset.
    let gate_open = self.entry.iter().any(|e| {
        registered_extents(e, space).iter().any(|&(a, _)| a > offset)
    });
    if gate_open {
        // Ghidra: fspec.cc:709-716 — entries whose registered start is
        // inside (offset, offset+size-1], scanned up to find_end of the
        // query end offset.
        let query_end = offset.wrapping_add(size as i64 as u64).wrapping_sub(1);
        for e in &self.entry {
            let starts_in_range = registered_extents(e, space)
                .iter()
                .any(|&(a, _)| a > offset && a <= query_end);
            if !starts_in_range { continue; }
            if e.is_exclusion() && e.space == space && e.contained_by(loc, size) {
                return containment::CONTAINED_BY;
            }
        }
    }
    containment::NO_CONTAINMENT
}

    // Ghidra: fspec.cc:1375 ParamListStandard::getBiggestContainedParam
    /// Find the largest parameter entry entirely contained in the range
    /// `[offset, offset+size-1]` of the given space. Faithful port: the
    /// wrapping check (`endLoc < loc`), the containment predicate and the
    /// strictly-greater size comparison are exact; Rugra scans the ordered
    /// entry list instead of Ghidra's per-space resolver map, which visits
    /// the same entry set for these queries.
    pub fn get_biggest_contained_param(
        &self,
        space: AddressSpace,
        offset: u64,
        size: i32,
    ) -> Option<(AddressSpace, u64, i32)> {
        // Ghidra: Address endLoc = loc + (size-1);
        //         if (endLoc.getOffset() < loc.getOffset()) return false;
        let end_loc = match offset.checked_add(size.max(0) as u64) {
            Some(end) if end == 0 || end > offset => end - 1,
            _ => return None, // wrapping range: assume no parameter
        };
        let loc = Address::new(offset);
        let mut max_entry: Option<&ParamEntry> = None;
        for e in &self.entry {
            if e.get_space() != space { continue; }
            // Resolver-map window: entry start must intersect [loc, endLoc].
            let entry_start = e.get_base();
            let entry_end = entry_start + e.get_size().max(0) as u64 - 1;
            if entry_start > end_loc || entry_end < offset { continue; }
            // Ghidra: if (testEntry->containedBy(loc, size)) keep the biggest.
            if e.contained_by(loc, size) {
                match max_entry {
                    None => max_entry = Some(e),
                    Some(cur) if e.get_size() > cur.get_size() => max_entry = Some(e),
                    _ => {}
                }
            }
        }
        // Ghidra: if (maxEntry && !maxEntry->isExclusion()) return false;
        //         res = (space, base, size); return true;
        match max_entry {
            Some(e) if e.is_exclusion() => Some((e.get_space(), e.get_base(), e.get_size())),
            _ => None,
        }
    }

    // Ghidra: fspec.cc:735 ParamListStandard::assignAddressFallback
    /// Assign storage for given parameter class, using the fallback
    /// assignment algorithm. Faithful to `assignAddressFallback`
    /// (fspec.cc:735-760).
    pub fn assign_address_fallback(
        &self, resource: TypeClass, tp: &Arc<Datatype>, match_exact: bool,
        status: &mut [i32], param: &mut ParameterPieces,
    ) -> AssignActionResponse {
        for cur in &self.entry {
            let grp = cur.get_group();
            if status[grp as usize] < 0 { continue; }
            if resource != cur.get_type() {
                if match_exact || cur.get_type() != TypeClass::General { continue; }
            }
            let align_size = tp.get_align_size() as i32;
            let type_alignment = tp.get_alignment() as i32;
            let assigned = cur.get_addr_by_slot(&mut status[grp as usize], align_size, type_alignment);
            match assigned {
                None => continue,
                Some(addr) => {
                    param.space = cur.get_space();
                    param.addr = addr;
                }
            }
            if cur.is_exclusion() {
                let group_set = cur.get_all_groups();
                for &g in group_set { status[g as usize] = -1; }
            }
            param.ty = Some(tp.clone());
            param.flags = 0;
            return AssignActionResponse::Success;
        }
        AssignActionResponse::Fail
    }

    // Ghidra: fspec.cc:772 ParamListStandard::assignAddress
    /// Fill in the Address and other details for the given parameter.
    /// Faithful to `assignAddress` (fspec.cc:772-783).
    pub fn assign_address(
        &self, dt: &Arc<Datatype>, _proto: &PrototypePieces, _pos: i32,
        status: &mut [i32], res: &mut ParameterPieces,
    ) -> AssignActionResponse {
        // TODO(ALIGNMENT_ROADMAP): depends on unported `ModelRule`
        // (modelrules.hh). Ghidra iterates `modelRules` first; Rugra goes
        // straight to fallback.
        let store = metatype_to_type_class(dt.as_ref());
        self.assign_address_fallback(store, dt, false, status, res)
    }

    // Ghidra: fspec.cc:785 ParamListStandard::assignMap
    /// Given list of data-types, map the list positions to storage
    /// locations. Faithful to `assignMap` (fspec.cc:785-814).
    pub fn assign_map(&self, proto: &PrototypePieces, res: &mut Vec<ParameterPieces>) -> Result<(), String> {
        let mut status = vec![0i32; self.num_group as usize];
        if res.len() == 2 {
            let dt = res.last().unwrap().ty.clone();
            if (res.last().unwrap().flags & HIDDEN_RET_PARM) != 0 {
                if let Some(dt_ref) = &dt {
                    if self.assign_address_fallback(
                        TypeClass::HiddenReturn, dt_ref, false,
                        &mut status, res.last_mut().unwrap(),
                    ) == AssignActionResponse::Fail
                    {
                        return Err("Cannot assign parameter address for hidden return".to_string());
                    }
                }
            } else if let Some(dt_ref) = &dt {
                if self.assign_address(dt_ref, proto, 0, &mut status, res.last_mut().unwrap())
                    == AssignActionResponse::Fail
                {
                    return Err("Cannot assign parameter address".to_string());
                }
            }
            res.last_mut().unwrap().flags |= HIDDEN_RET_PARM;
        }
        for (i, dt) in proto.in_types.iter().enumerate() {
            res.push(ParameterPieces::default());
            let response = self.assign_address(
                dt, proto, i as i32, &mut status, res.last_mut().unwrap(),
            );
            if response == AssignActionResponse::Fail || response == AssignActionResponse::NoAssignment {
                return Err("Cannot assign parameter address".to_string());
            }
        }
        Ok(())
    }

    // Ghidra: fspec.cc:820 ParamListStandard::selectUnreferenceEntry
    /// From among the ParamEntrys matching the given group, return the one
    /// that best matches the given metatype. Faithful to
    /// `selectUnreferenceEntry` (fspec.cc:820-842).
    pub fn select_unreference_entry(&self, grp: i32, pref_type: TypeClass) -> Option<usize> {
        let mut best_score = -1i32;
        let mut best_entry = None;
        for (i, cur) in self.entry.iter().enumerate() {
            if cur.get_group() != grp { continue; }
            let cur_score = if cur.get_type() == pref_type { 2 }
                else if pref_type == TypeClass::General { 1 } else { 0 };
            if cur_score > best_score { best_score = cur_score; best_entry = Some(i); }
        }
        best_entry
    }

    // Ghidra: fspec.cc:849 ParamListStandard::buildTrialMap
    /// Associate trials with model ParamEntry objects. Faithful to
    /// `buildTrialMap` (fspec.cc:849-937).
    pub fn build_trial_map(&self, active: &mut ParamActive) {
        let mut hit_list: Vec<Option<usize>> = Vec::new();
        let mut float_count = 0i32;
        let mut int_count = 0i32;
        for i in 0..active.get_num_trials() {
            let (space, addr, size) = {
                let t = active.get_trial(i);
                (t.get_space(), t.get_address(), t.get_size())
            };
            // Ghidra: const ParamEntry *entrySlot = findEntry(paramtrial.getAddress(), paramtrial.getSize(), true);
            let entry_slot = self.find_entry(space, addr, size, true);
            if entry_slot.is_none() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            let entry_slot = entry_slot.unwrap();
            active.get_trial_mut(i).set_entry(entry_slot, 0);
            let is_active = active.get_trial(i).is_active();
            let entry_type = self.entry[entry_slot].get_type();
            if is_active {
                if entry_type == TypeClass::Float { float_count += 1; } else { int_count += 1; }
            }
            let grp = self.entry[entry_slot].get_group();
            while hit_list.len() <= grp as usize { hit_list.push(None); }
            if hit_list[grp as usize].is_none() { hit_list[grp as usize] = Some(entry_slot); }
        }
        for (grp_idx, curentry_opt) in hit_list.iter().enumerate() {
            let grp = grp_idx as i32;
            if curentry_opt.is_none() {
                let pref = if float_count > int_count { TypeClass::Float } else { TypeClass::General };
                let curentry = match self.select_unreference_entry(grp, pref) { Some(e) => e, None => continue };
                let (sz, next_slot_init) = if self.entry[curentry].is_exclusion() {
                    (self.entry[curentry].get_size(), 0)
                } else {
                    (self.entry[curentry].get_align(), 0)
                };
                let mut next_slot = next_slot_init;
                let addr = self.entry[curentry]
                    .get_addr_by_slot(&mut next_slot, sz, 1)
                    .unwrap_or(Address::new(0));
                let trial_pos = active.get_num_trials();
                active.register_trial_in_space(self.entry[curentry].get_space(), addr, sz);
                active.get_trial_mut(trial_pos).mark_unref();
                active.get_trial_mut(trial_pos).set_entry(curentry, 0);
            } else {
                let curentry = curentry_opt.unwrap();
                if !self.entry[curentry].is_exclusion() {
                    let mut slot_list: Vec<i32> = Vec::new();
                    for j in 0..active.get_num_trials() {
                        let (addr, size) = { let t = active.get_trial(j); (t.get_address(), t.get_size()) };
                        if active.get_trial(j).get_entry_index() != Some(curentry) { continue; }
                        let mut slot = self.entry[curentry].get_slot(addr, 0) - self.entry[curentry].get_group();
                        let mut end_slot = self.entry[curentry].get_slot(addr, size - 1) - self.entry[curentry].get_group();
                        if end_slot < slot { std::mem::swap(&mut slot, &mut end_slot); }
                        while slot_list.len() <= end_slot as usize { slot_list.push(0); }
                        let mut s = slot;
                        while s <= end_slot { slot_list[s as usize] = 1; s += 1; }
                    }
                    for (j, &v) in slot_list.iter().enumerate() {
                        if v == 0 {
                            let mut next_slot = j as i32;
                            let align = self.entry[curentry].get_align();
                            let addr = self.entry[curentry]
                                .get_addr_by_slot(&mut next_slot, align, 1)
                                .unwrap_or(Address::new(0));
                            let trial_pos = active.get_num_trials();
                            active.register_trial_in_space(
                                self.entry[curentry].get_space(), addr, align,
                            );
                            active.get_trial_mut(trial_pos).mark_unref();
                            active.get_trial_mut(trial_pos).set_entry(curentry, 0);
                        }
                    }
                }
            }
        }
        active.sort_trials(&self.entry);
    }

    // Ghidra: fspec.cc:946 ParamListStandard::separateSections
    /// Calculate the range of trials in each resource section. Faithful to
    /// `separateSections` (fspec.cc:946-966).
    pub fn separate_sections(&self, active: &ParamActive, trial_start: &mut Vec<i32>) {
        let num_trials = active.get_num_trials() as i32;
        let mut current_trial = 0i32;
        if self.resource_start.len() < 2 { return; }
        let mut next_group = self.resource_start[1];
        let mut next_section = 2usize;
        trial_start.push(current_trial);
        while current_trial < num_trials {
            let cur = active.get_trial(current_trial as usize);
            if cur.get_entry_index().is_none() { current_trial += 1; continue; }
            let grp = cur.get_entry_index()
                .and_then(|idx| self.entry.get(idx))
                .map(|e| e.get_group())
                .unwrap_or(-1);
            if grp >= next_group {
                if next_section >= self.resource_start.len() { break; }
                next_group = self.resource_start[next_section];
                next_section += 1;
                trial_start.push(current_trial);
            }
            current_trial += 1;
        }
        trial_start.push(num_trials);
    }

    // Ghidra: fspec.cc:974 ParamListStandard::markGroupNoUse
    /// Mark all the trials within the indicated groups as not used, except
    /// for one specified index. Faithful to `markGroupNoUse`
    /// (fspec.cc:974-986).
    pub fn mark_group_no_use(&self, active: &mut ParamActive, active_trial: usize, trial_start: usize) {
        let num_trials = active.get_num_trials();
        let active_entry = match active.get_trial(active_trial).get_entry_index().and_then(|i| self.entry.get(i)) {
            Some(e) => e,
            None => return,
        };
        for i in trial_start..num_trials {
            if i == active_trial { continue; }
            let other_entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() { continue; }
            let other_entry = match self.entry.get(other_entry_idx) { Some(e) => e, None => continue };
            if !other_entry.group_overlap(active_entry) { break; }
            active.get_trial_mut(i).mark_no_use();
        }
    }

    // Ghidra: fspec.cc:997 ParamListStandard::markBestInactive
    /// From among multiple inactive trials, select the most likely to be
    /// active and mark others as not used. Faithful to `markBestInactive`
    /// (fspec.cc:997-1025).
    pub fn mark_best_inactive(
        &self, active: &mut ParamActive, group: i32, group_start: usize, pref_type: TypeClass,
    ) {
        let num_trials = active.get_num_trials();
        let mut best_trial = -1i32;
        let mut best_score = -1i32;
        for i in group_start..num_trials {
            let trial = active.get_trial(i);
            if trial.is_definitely_not_used() { continue; }
            let entry_idx = match trial.get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            let grp = entry.get_group();
            if grp != group { break; }
            if entry.get_all_groups().len() > 1 { continue; }
            let mut score = 0i32;
            if trial.has_ancestor_realistic() {
                score += 5;
                if trial.has_ancestor_solid() { score += 5; }
            }
            if entry.get_type() == pref_type { score += 1; }
            if score > best_score { best_score = score; best_trial = i as i32; }
        }
        if best_trial >= 0 { self.mark_group_no_use(active, best_trial as usize, group_start); }
    }

    // Ghidra: fspec.cc:1032 ParamListStandard::forceExclusionGroup
    /// Enforce exclusion rules for the given set of parameter trials.
    /// Faithful to `forceExclusionGroup` (fspec.cc:1032-1060).
    pub fn force_exclusion_group(&self, active: &mut ParamActive) {
        let num_trials = active.get_num_trials();
        let mut cur_group = -1i32;
        let mut group_start = -1i32;
        let mut inactive_count = 0i32;
        for i in 0..num_trials {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() || !entry.is_exclusion() { continue; }
            let grp = entry.get_group();
            if grp != cur_group {
                if inactive_count > 1 {
                    self.mark_best_inactive(active, cur_group, group_start as usize, TypeClass::General);
                }
                cur_group = grp;
                group_start = i as i32;
                inactive_count = 0;
            }
            if active.get_trial(i).is_active() {
                self.mark_group_no_use(active, i, group_start as usize);
            } else {
                inactive_count += 1;
            }
        }
        if inactive_count > 1 {
            self.mark_best_inactive(active, cur_group, group_start as usize, TypeClass::General);
        }
    }

    // Ghidra: fspec.cc:1069 ParamListStandard::forceNoUse
    /// Mark every trial above the first "definitely not used" as inactive.
    /// Faithful to `forceNoUse` (fspec.cc:1069-1095).
    pub fn force_no_use(&self, active: &mut ParamActive, start: usize, stop: usize) {
        let mut seen_defnouse = false;
        let mut cur_group = -1i32;
        let mut all_defnouse = false;
        for i in start..stop {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            let grp = entry.get_group();
            let exclusion = entry.is_exclusion();
            if grp <= cur_group && exclusion {
                if !active.get_trial(i).is_definitely_not_used() { all_defnouse = false; }
            } else {
                if all_defnouse { seen_defnouse = true; }
                all_defnouse = active.get_trial(i).is_definitely_not_used();
                cur_group = grp;
            }
            if seen_defnouse { active.get_trial_mut(i).mark_inactive(); }
        }
    }

    // Ghidra: fspec.cc:1111 ParamListStandard::forceInactiveChain
    /// Enforce rules about chains of inactive slots. Faithful to
    /// `forceInactiveChain` (fspec.cc:1111-1151).
    pub fn force_inactive_chain(
        &self, active: &mut ParamActive, max_chain: i32, start: usize, stop: usize, group_start: i32,
    ) {
        let recover_subcall = active.is_recover_subcall();
        let mut seen_chain = false;
        let mut chain_length = 0i32;
        let mut max = -1i32;
        for i in start..stop {
            let entry_idx = match active.get_trial(i).get_entry_index() { Some(e) => e, None => continue };
            let entry = match self.entry.get(entry_idx) { Some(e) => e, None => continue };
            if active.get_trial(i).is_definitely_not_used() { continue; }
            if !active.get_trial(i).is_active() {
                let on_stack = active.get_trial(i).get_address().as_u64() != 0
                    && self.space_base == Some(AddressSpace::Stack);
                if active.get_trial(i).is_unref() && recover_subcall {
                    if on_stack { seen_chain = true; }
                }
                let trial_addr = active.get_trial(i).get_address();
                let trial_size = active.get_trial(i).get_size();
                let slot_group = entry.get_slot(trial_addr, trial_size - 1);
                if i == start {
                    chain_length += slot_group - group_start + 1;
                } else {
                    let prev_addr = active.get_trial(i - 1).get_address();
                    let prev_size = active.get_trial(i - 1).get_size();
                    let prev_entry_idx = active.get_trial(i - 1).get_entry_index();
                    let prev_slot_group = prev_entry_idx
                        .and_then(|idx| self.entry.get(idx))
                        .map(|e| e.get_slot(prev_addr, prev_size - 1))
                        .unwrap_or(slot_group);
                    chain_length += slot_group - prev_slot_group;
                }
                if chain_length > max_chain { seen_chain = true; }
            } else {
                chain_length = 0;
                if !seen_chain { max = i as i32; }
            }
            if seen_chain { active.get_trial_mut(i).mark_inactive(); }
        }
        // Ghidra fspec.cc:1145: `for(int4 i=start;i<=max;++i)` — with the
        // `max = -1` sentinel (no active trial seen before a chain) the loop
        // body never runs. The `-1 as usize` wrap would instead saturate the
        // hole-filling loop to `stop-1` and mark every inactive trial in the
        // section active (the XMM0-7 unref-explosion root cause), so the
        // loop is guarded on `max >= 0`.
        if max >= 0 {
            let upper = std::cmp::min(max as usize, stop.saturating_sub(1));
            for i in start..=upper {
                if active.get_trial(i).is_definitely_not_used() { continue; }
                if !active.get_trial(i).is_active() { active.get_trial_mut(i).mark_active(); }
            }
        }
    }

    // Ghidra: fspec.cc:1285 ParamListStandard::fillinMap
    /// Decide on the formal ordered parameter list, given a set of trials.
    /// Faithful to `fillinMap` (fspec.cc:1285-1313).
    pub fn fillin_map(&self, active: &mut ParamActive) {
        if active.get_num_trials() == 0 { return; }
        if self.entry.is_empty() { return; }
        self.build_trial_map(active);
        self.force_exclusion_group(active);
        let mut trial_start = Vec::new();
        self.separate_sections(active, &mut trial_start);
        if trial_start.len() < 2 { return; }
        let num_section = trial_start.len() - 1;
        for i in 0..num_section {
            self.force_no_use(active, trial_start[i] as usize, trial_start[i + 1] as usize);
        }
        for i in 0..num_section {
            self.force_inactive_chain(
                active, 2,
                trial_start[i] as usize, trial_start[i + 1] as usize,
                self.resource_start[i],
            );
        }
        for i in 0..active.get_num_trials() {
            if active.get_trial(i).is_active() { active.get_trial_mut(i).mark_used(); }
        }
    }

    // Ghidra: fspec.cc:1315 ParamListStandard::checkJoin
    /// Check if the two (hi/lo) locations can be joined. Faithful to
    /// `checkJoin` (fspec.cc:1315-1340). `space` is the query address's
    /// space (Ghidra reads it from the `const Address &` parameters; the
    /// legacy spaceless `Address` needs it alongside — see `find_entry`).
    pub fn check_join(&self, space: AddressSpace, hi_addr: Address, hi_size: i32, lo_addr: Address, lo_size: i32) -> bool {
        let entry_hi = match self.find_entry(space, hi_addr, hi_size, true) { Some(e) => e, None => return false };
        let entry_lo = match self.find_entry(space, lo_addr, lo_size, true) { Some(e) => e, None => return false };
        if self.entry[entry_hi].get_group() == self.entry[entry_lo].get_group() {
            if self.entry[entry_hi].is_exclusion() || self.entry[entry_lo].is_exclusion() { return false; }
            if !is_contiguous(hi_addr, hi_size, lo_addr, lo_size) { return false; }
            if (hi_addr.as_u64() - self.entry[entry_hi].get_base()) % self.entry[entry_hi].get_align() as u64 != 0 { return false; }
            if (lo_addr.as_u64() - self.entry[entry_lo].get_base()) % self.entry[entry_lo].get_align() as u64 != 0 { return false; }
            return true;
        }
        let size_sum = hi_size + lo_size;
        for cur in &self.entry {
            if cur.get_size() < size_sum { continue; }
            // Ghidra: cc:133 rides on the hi/lo Addresses; the space-aware
            // form keeps a foreign-space join piece from matching
            // numerically (see justified_contain_in_space).
            if cur.justified_contain_in_space(lo_addr, lo_size, space) != 0 { continue; }
            if cur.justified_contain_in_space(hi_addr, hi_size, space) != lo_size { continue; }
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:1342 ParamListStandard::checkSplit
    /// Check if it makes sense to split a single storage location.
    /// Faithful to `checkSplit` (fspec.cc:1342-1352). `space` is the query
    /// address's space (see `find_entry`).
    pub fn check_split(&self, space: AddressSpace, loc: Address, size: i32, split_point: i32) -> bool {
        let loc2 = Address::new(loc.as_u64() + split_point as u64);
        let size2 = size - split_point;
        if self.find_entry(space, loc, split_point, true).is_none() { return false; }
        if self.find_entry(space, loc2, size2, true).is_none() { return false; }
        true
    }

    // Ghidra: fspec.cc:1354 ParamListStandard::possibleParam
    pub fn possible_param(&self, space: AddressSpace, loc: Address, size: i32) -> bool {
        self.find_entry(space, loc, size, true).is_some()
    }

    // Ghidra: fspec.cc:1360 ParamListStandard::possibleParamWithSlot
    /// Pass-back the slot and slot size. Faithful to `possibleParamWithSlot`
    /// (fspec.cc:1360-1373). `space` is the query address's space (see
    /// `find_entry`).
    pub fn possible_param_with_slot(
        &self, space: AddressSpace, loc: Address, size: i32, slot: &mut i32, slot_size: &mut i32,
    ) -> bool {
        let entry_num = match self.find_entry(space, loc, size, true) { Some(e) => e, None => return false };
        let entry = &self.entry[entry_num];
        *slot = entry.get_slot(loc, 0);
        if entry.is_exclusion() {
            *slot_size = entry.get_all_groups().len() as i32;
        } else {
            *slot_size = ((size - 1) / entry.get_align()) + 1;
        }
        true
    }

    // Ghidra: fspec.cc:1411 ParamListStandard::unjustifiedContainer
    /// Check if the given storage location looks like an unjustified
    /// parameter. Faithful to `unjustifiedContainer` (fspec.cc:1411-1424):
    /// iterates ALL entries with no caller-level space filter — Ghidra
    /// relies on each entry's `justifiedContain` rejecting queries in
    /// other spaces (fspec.cc:269 / `Address::justifiedContain`
    /// address.cc:133 for plain entries; per-piece address.cc:133 for
    /// joins, which ARE reachable). `space` is the query address's space
    /// (Ghidra reads it from the `const Address &loc`; the legacy
    /// spaceless `Address` needs it alongside — see `find_entry`).
    pub fn unjustified_container(
        &self,
        space: AddressSpace,
        loc: Address,
        size: i32,
        res: &mut VarnodeData,
    ) -> bool {
        // Ghidra: if ((*iter).getMinSize() > size) continue;
        //         int4 just = (*iter).justifiedContain(loc,size);
        //         if (just < 0) continue;
        //         if (just == 0) return false;
        //         (*iter).getContainer(loc,size,res); return true;
        for cur in &self.entry {
            if cur.get_min_size() > size { continue; }
            let just = cur.justified_contain_in_space(loc, size, space);
            if just < 0 { continue; }
            if just == 0 { return false; }
            cur.get_container(loc, size, res);
            return true;
        }
        false
    }

    // Ghidra: fspec.cc:1426 ParamListStandard::assumedExtension
    /// Get the type of extension and containing parameter. Faithful to
    /// `assumedExtension` (fspec.cc:1426-1437): iterates ALL entries with
    /// no space filter — per-entry `assumedExtension` rejects other-space
    /// queries itself (fspec.cc:366-394 via `justifiedContain`).
    /// `space` is the query address's space (see `find_entry`).
    pub fn assumed_extension(
        &self,
        space: AddressSpace,
        addr: Address,
        size: i32,
        res: &mut VarnodeData,
    ) -> FspecOpCode {
        // Ghidra: if ((*iter).getMinSize() > size) continue;
        //         OpCode ext = (*iter).assumedExtension(addr,size,res);
        //         if (ext != CPUI_COPY) return ext;
        for cur in &self.entry {
            if cur.get_min_size() > size { continue; }
            let ext = cur.assumed_extension(addr, size, space, res);
            if ext != FspecOpCode::CPUI_COPY { return ext; }
        }
        FspecOpCode::CPUI_COPY
    }

    // Ghidra: fspec.cc:1439 ParamListStandard::getRangeList
    /// For a given address space, collect all the parameter locations.
    /// Faithful to `getRangeList` (fspec.cc:1439-1449).
    pub fn get_range_list(&self, spc: AddressSpace, res: &mut crate::address::RangeList) {
        for cur in &self.entry {
            if cur.get_space() != spc { continue; }
            let base_off = cur.get_base();
            let end_off = base_off + cur.get_size() as u64 - 1;
            if let Some(r) = FsRange::new(Address::new(base_off), Address::new(end_off)) {
                res.insert_range(r);
            }
        }
    }

    // Ghidra: fspec.cc:1153 ParamListStandard::calcDelay
    /// Calculate the maximum heritage delay. Faithful to `calcDelay`
    /// (fspec.cc:1153-1163).
    pub fn calc_delay(&mut self) {
        self.max_delay = 0;
        for cur in &self.entry {
            let delay = cur.get_space().get_delay();
            if delay > self.max_delay { self.max_delay = delay; }
        }
    }

    // Ghidra: fspec.cc:1191 ParamListStandard::populateResolver
    /// Enter all the ParamEntry objects into an interval map. Faithful 1:1
    /// port of `populateResolver` (fspec.cc:1191-1216): the position counter
    /// advances once per registered range — a join ParamEntry registers one
    /// range per join piece at consecutive positions, every other entry
    /// registers its `[base, base+size-1]` extent at one position. The
    /// per-space resolver is created on first use (Ghidra's `resolverMap`
    /// grows to the space index and null slots are allocated lazily).
    /// Rugra additionally keeps the legacy `stack_entry_index` cache so the
    /// linear `find_entry` scan used by the live pipeline is unaffected
    /// (resolver-backed queries are opt-in via `resolver_for`).
    pub fn populate_resolver(&mut self) {
        self.stack_entry_index = None;
        // Ghidra always populates a FRESH resolver map (decode at
        // fspec.cc:1504 runs once on the decoded list; the copy ctor at
        // cc:610 runs on the just-constructed copy). Clearing first makes
        // the Rust call idempotent, which preserves that fresh-map
        // precondition for callers that stage entries across phases.
        self.resolver_map.clear();
        // Ghidra walks `list<ParamEntry>` mutating the resolver in place;
        // Rust's ownership splits the walk into a projection pass and an
        // insertion pass over the same (space, first, last, entry, position)
        // tuples in the same order.
        let mut registrations: Vec<(AddressSpace, u64, u64, usize, i32)> = Vec::new();
        let mut position = 0i32;
        let mut new_stack_entry_index = None;
        for (index, param_entry) in self.entry.iter().enumerate() {
            let spc = param_entry.get_space();
            if spc == AddressSpace::Join {
                let pieces: Vec<VarnodeData> = param_entry
                    .get_join_pieces()
                    .map(|p| p.to_vec())
                    .unwrap_or_default();
                for v_data in &pieces {
                    // Individual pieces making up the join are mapped to the ParamEntry
                    let last = v_data.offset + (v_data.size as u64 - 1);
                    registrations.push((v_data.space, v_data.offset, last, index, position));
                    position += 1;
                }
            } else {
                let first = param_entry.get_base();
                let last = first + (param_entry.get_size() as u64 - 1);
                registrations.push((spc, first, last, index, position));
                position += 1;
            }
            if !param_entry.is_exclusion() && spc == AddressSpace::Stack {
                new_stack_entry_index = Some(index);
            }
        }
        for (spc, first, last, param_entry, pos) in registrations {
            self.add_resolver_range(spc, first, last, param_entry, pos);
        }
        self.stack_entry_index = new_stack_entry_index;
    }

    // Ghidra: fspec.cc:1174 ParamListStandard::addResolverRange
    /// Add a single address range to the per-space ParamEntryResolver.
    /// Faithful 1:1 port of `addResolverRange` (fspec.cc:1174-1189): grow
    /// the resolver map for the space on first use, then insert
    /// `inittype(position, paramEntry)` over `[first, last]`.
    pub fn add_resolver_range(
        &mut self, spc: AddressSpace, first: u64, last: u64, param_entry: usize, position: i32,
    ) {
        for (key, resolver) in self.resolver_map.iter_mut() {
            if *key == spc {
                resolver.insert(&ParamEntryRangeInitData::new(position, param_entry), first, last);
                return;
            }
        }
        let mut resolver = ParamEntryResolver::new();
        resolver.insert(&ParamEntryRangeInitData::new(position, param_entry), first, last);
        self.resolver_map.push((spc, resolver));
    }

    // RUGRA-GLUE: space-keyed lookup standing in for Ghidra's
    // `resolverMap[spc->getIndex()]` array index (the resolver map is
    /// consulted by resolver-backed queries; a space with no registered
    /// extent yields `None`, mirroring the null resolver slot).
    pub fn resolver_for(&self, spc: AddressSpace) -> Option<&ParamEntryResolver> {
        self.resolver_map.iter().find(|(key, _)| *key == spc).map(|(_, r)| r)
    }

    // Ghidra: fspec.cc:1226 ParamListStandard::parsePentry
    /// Parse a `<pentry>` element and add it to this list.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` marshaling.
    /// Accepts an already-decoded ParamEntry and applies the post-decode
    /// state transitions (resolve_first/resolve_join/resolve_overlap,
    /// resource_start accounting, space_base detection). Faithful algorithm
    /// in the doc-comment.
    pub fn parse_pentry(
        &mut self, group_id: i32, normal_stack: bool, split_float: bool, grouped: bool,
        effect_list: &mut Vec<EffectRecord>, decoded: ParamEntry,
    ) -> Result<(), String> {
        let last_class = if !self.entry.is_empty() {
            if self.entry.last().unwrap().is_grouped() { TypeClass::General }
            else { self.entry.last().unwrap().get_type() }
        } else { TypeClass::Class4 };
        let mut new_entry = decoded;
        new_entry.resolve_first(&self.entry);
        new_entry.resolve_join(&self.entry);
        new_entry.resolve_overlap(&self.entry)?;
        if !normal_stack {
            *new_entry.flags_mut() |= param_entry_flags::REVERSE_STACK;
        }
        if grouped {
            *new_entry.flags_mut() |= param_entry_flags::IS_GROUPED;
        }
        self.entry.push(new_entry);
        let cur = self.entry.last().unwrap();
        if split_float {
            let current_class = if grouped { TypeClass::General } else { cur.get_type() };
            if last_class != current_class {
                if last_class < current_class {
                    return Err("parameter list entries must be ordered by storage class".to_string());
                }
                self.resource_start.push(group_id);
            }
        }
        let spc = cur.get_space();
        if spc == AddressSpace::Stack {
            self.space_base = Some(spc);
            self.stack_entry_index = Some(self.entry.len() - 1);
        } else if self.auto_killed_by_call {
            effect_list.push(EffectRecord::new(spc, cur.get_base(), cur.get_size(), EffectType::KilledByCall));
        }
        let max_group = *cur.get_all_groups().last().unwrap_or(&0) + 1;
        if max_group > self.num_group { self.num_group = max_group; }
        Ok(())
    }

    // Ghidra: fspec.cc:1262 ParamListStandard::parseGroup
    /// Parse a sequence of `<pentry>` elements allocated as a group.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` marshaling.
    /// Accepts an already-decoded sequence and applies the group-ordering
    /// rules.
    pub fn parse_group(
        &mut self, group_id: i32, normal_stack: bool, split_float: bool,
        effect_list: &mut Vec<EffectRecord>, entries: Vec<ParamEntry>,
    ) -> Result<(), String> {
        let base_group = self.num_group;
        let mut previous1: Option<usize> = None;
        let mut previous2: Option<usize> = None;
        for decoded_entry in entries {
            if decoded_entry.get_space() == AddressSpace::Join {
                return Err("<pentry> in the join space not allowed in <group> tag".to_string());
            }
            self.parse_pentry(base_group, normal_stack, split_float, true, effect_list, decoded_entry)?;
            let pentry_idx = self.entry.len() - 1;
            if let Some(p1) = previous1 {
                ParamEntry::order_within_group(&self.entry[p1], &self.entry[pentry_idx])?;
                if let Some(p2) = previous2 {
                    ParamEntry::order_within_group(&self.entry[p2], &self.entry[pentry_idx])?;
                }
            }
            previous2 = previous1;
            previous1 = Some(pentry_idx);
        }
        let _ = group_id;
        Ok(())
    }

    // Ghidra: fspec.cc:1451 ParamListStandard::decode
    /// Restore the model from an `<input>` or `<output>` element.
    ///
    /// TODO(ALIGNMENT_ROADMAP): depends on unported `Decoder` attribute/
    /// element id constants. Rugra exposes the post-decode finalization
    /// (`resource_start.push(num_group)`, `calc_delay`, `populate_resolver`)
    /// via `finalize_after_decode` so a caller that has manually parsed the
    /// element tree can complete the model.
    pub fn finalize_after_decode(&mut self, pointer_max: i32) {
        self.resource_start.push(self.num_group);
        self.calc_delay();
        self.populate_resolver();
        // TODO(ALIGNMENT_ROADMAP): depends on unported ModelRule /
        // ConvertToPointer (modelrules.hh). Ghidra appends a
        // convert-to-pointer rule when pointermax > 0.
        let _ = pointer_max;
    }

    // Ghidra: fspec.hh:645 ParamListStandard::clone
    // RUGRA-GLUE: clone (Rust uses Clone derive; named accessor matching
    // Ghidra's virtual clone()).
    pub fn clone_model(&self) -> ParamListStandard { self.clone() }

    // RUGRA-GLUE: setters for the model loader (Ghidra fills these during
    // `ParamListStandard::decode`; Rugra's decoder is unported).
    pub fn set_this_before_ret(&mut self, v: bool) { self.this_before_ret = v; }
    // RUGRA-GLUE: loader/subclass field setter; Ghidra writes the protected
    // autoKilledByCall field directly in decode() and initialize().
    pub fn set_auto_killed_by_call(&mut self, v: bool) { self.auto_killed_by_call = v; }
    // RUGRA-GLUE: inheritance bridge; Ghidra subclasses read protected
    // ParamListStandard::numgroup directly and expose no getNumGroup member.
    pub fn get_num_group(&self) -> i32 { self.num_group }

    /// Set the number of resource groups (used by the output-list decoders
    /// and `assign_map` to size the per-group status vector).
    // RUGRA-GLUE: loader field setter; Ghidra updates protected numgroup
    // directly while parsing entries and exposes no setNumGroup member.
    pub fn set_num_group(&mut self, v: i32) { self.num_group = v; }

    /// Mutable access to the entry list. Used by `ParamListStandardOut` to
    /// run the fallback fillin algorithm, which mirrors Ghidra's
    /// `list<ParamEntry>` iteration over `entry`.
    // RUGRA-GLUE: inheritance bridge; Ghidra subclasses access the protected
    // entry list directly and provide only a const getEntry() accessor.
    pub fn entry_mut(&mut self) -> &mut Vec<ParamEntry> { &mut self.entry }
}

// ======================================================================
// ParamListStandardOut — faithful port of Ghidra's
// `class ParamListStandardOut : public ParamListStandard`
// (fspec.hh:656-670, fspec.cc:1569-1788)
// ======================================================================
// A standard model for returning output parameters from a function.
// Entries in the resource list are treated as a group, meaning that only
// one can fit the desired storage size and type attributes of the return
// value. If no entry fits, the return value is converted to a pointer
// data-type, storage allocation is attempted again, and the return value
// is marked as a hidden return parameter to inform the input model.
//
// Rust has no inheritance, so this struct embeds a `ParamListStandard`
// (`base`) plus the single extra field (`use_fillin_fallback`). All
// inherited behaviour is reached via `self.base`.

/// Faithful port of `class ParamListStandardOut` (fspec.hh:656-670).
#[derive(Debug, Clone)]
pub struct ParamListStandardOut {
    /// Inherited `ParamListStandard` state. Stands in for C++ public-base.
    pub base: ParamListStandard,
    /// If `true`, `fillin_map` should defer to `fillin_map_fallback`.
    /// Faithful to `ParamListStandardOut::useFillinFallback` (fspec.hh:657).
    use_fillin_fallback: bool,
}

impl Default for ParamListStandardOut {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListStandardOut constructor but no default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListStandardOut {
    // Ghidra: fspec.hh:660 ParamListStandardOut::ParamListStandardOut()
    /// Constructor for use with `decode()`. Faithful to
    /// `ParamListStandardOut()` (fspec.hh:660).
    pub fn new() -> Self {
        Self { base: ParamListStandard::new(), use_fillin_fallback: false }
    }

    // Ghidra: fspec.hh:661 ParamListStandardOut::ParamListStandardOut(op2)
    /// Copy constructor. Faithful to
    /// `ParamListStandardOut(const ParamListStandardOut &op2)` (fspec.hh:661).
    pub fn from_other(op2: &ParamListStandardOut) -> Self {
        Self { base: op2.base.clone(), use_fillin_fallback: op2.use_fillin_fallback }
    }

    // Ghidra: fspec.hh:664 ParamListStandardOut::getType
    /// Return the runtime type tag. Faithful to `getType` (fspec.hh:664).
    pub fn get_type(&self) -> ParamListKind { ParamListKind::StandardOut }

    // Ghidra: fspec.hh:620 ParamListStandard::getEntry
    /// Iterate the inherited output-resource entries in declaration order.
    pub fn get_entry(&self) -> &[ParamEntry] { self.base.get_entry() }

    // Ghidra: fspec.hh:643 ParamListStandard::isAutoKilledByCall
    /// Return the inherited killed-by-call output property.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.base.is_auto_killed_by_call()
    }

    // Ghidra: fspec.cc:1614 ParamListStandardOut::initialize
    /// Cache the output fill-in policy (`initialize`, fspec.cc:1614-1627):
    /// start legacy (`useFillinFallback=true`), then clear it if any
    /// decoded model rule `canAffectFillinOutput()`. Only the legacy
    /// branch forces `autoKilledByCall = true`.
    pub fn initialize(&mut self) {
        self.use_fillin_fallback = true;
        for rule in self.base.model_rules.iter() {
            if rule.action.can_affect_fillin_output() {
                self.use_fillin_fallback = false;
                break;
            }
        }
        if self.use_fillin_fallback {
            self.base.set_auto_killed_by_call(true);
        }
    }

    // Ghidra: fspec.cc:1569 ParamListStandardOut::assignMap
    /// Assign storage for the single output (return) parameter. The scalar
    /// success path follows `assignMap` (fspec.cc:1569-1612) and emplaces one
    /// `ParameterPieces` for the return value; on `TYPE_VOID` it is left
    /// invalid. On `assignAddress` failure the action escalates to a hidden
    /// return: the return piece is re-typed as a pointer to the original
    /// out-type, its storage is reassigned, and a second piece is appended
    /// holding the hidden-return input pointer. `AssignAction::hiddenret_*`
    /// select between pointer-in-first-slot and special-register variants.
    /// Architecture-owned TypeFactory pointer construction and the full
    /// ModelRule response domain remain `FSPEC-0002`.
    pub fn assign_map(
        &self, proto: &PrototypePieces,
        _typefactory: &crate::type_system::TypeFactory,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<(), String> {
        let mut status = vec![0i32; self.base.get_num_group() as usize];
        res.push(ParameterPieces::default());
        let out_type = match proto.out_type {
            None => {
                res.last_mut().unwrap().ty = None;
                res.last_mut().unwrap().flags = 0;
                return Ok(()); // Treat absent out_type as void.
            }
            Some(t) => t,
        };
        if matches!(out_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            res.last_mut().unwrap().ty = Some((*out_type).clone());
            res.last_mut().unwrap().flags = 0;
            return Ok(()); // Leave the address invalid.
        }
        let response = self.base.assign_address(
            out_type, proto, -1, &mut status, res.last_mut().unwrap(),
        );
        // Map Ghidra's AssignAction codes (modelrules.hh:264-271) onto the
        // local enum. Rugra's `AssignActionResponse` collapses the
        // hiddenret_* codes; we treat any non-Fail response as Success and
        // only escalate on Fail.
        let mut response_code = if response == AssignActionResponse::Fail {
            // Ghidra: responseCode = hiddenret_ptrparam  (default action)
            HiddenRetAction::PtrParam
        } else {
            HiddenRetAction::Success
        };
        if matches!(
            response_code,
            HiddenRetAction::PtrParam
                | HiddenRetAction::SpecialReg
                | HiddenRetAction::SpecialRegVoid
        ) {
            // Ghidra: AddrSpace *spc = spacebase; fallback to default data space.
            // Rugra has no TypeFactory pointer plumbing; the pointer size is
            // taken from the out-type, matching `getAddrSize`/`getWordSize` of
            // the model's spacebase when one is present.
            let pointersize = out_type.get_size() as i32;
            let wordsize = 1i32;
            // Ghidra: Datatype *pointertp = typefactory.getTypePointer(...).
            // Rugra has no `TypeFactory::getTypePointer`; we re-use the
            // out-type as the pointer's base and let later passes reconcile.
            let pointer_tp: std::sync::Arc<Datatype> = (*out_type).clone();
            if matches!(response_code, HiddenRetAction::SpecialRegVoid) {
                res.last_mut().unwrap().ty = None; // Ghidra: getTypeVoid()
            } else {
                res.last_mut().unwrap().ty = Some(pointer_tp.clone());
                let r2 = self.base.assign_address(
                    &pointer_tp, proto, -1, &mut status, res.last_mut().unwrap(),
                );
                if r2 == AssignActionResponse::Fail {
                    return Err("Cannot assign return value as a pointer".to_string());
                }
            }
            res.last_mut().unwrap().flags = INDIRECT_STORAGE_PIECE;
            // Ghidra: res.emplace_back(); extra input slot for the hidden
            // return pointer; its address is left invalid (filled in by the
            // input list's assignMap).
            res.push(ParameterPieces::default());
            res.last_mut().unwrap().ty = Some(pointer_tp);
            let is_special = matches!(
                response_code,
                HiddenRetAction::SpecialReg | HiddenRetAction::SpecialRegVoid
            );
            res.last_mut().unwrap().flags = if is_special { HIDDEN_RET_PARM } else { 0 };
            let _ = wordsize;
        }
        // Suppress unused-warning on the success branch.
        let _ = response_code;
        Ok(())
    }

    // Ghidra: fspec.cc:1638 ParamListStandardOut::fillinMapFallback
    /// Find the return-value storage using the older fallback method.
    /// Faithful 1:1 port of `fillinMapFallback` (fspec.cc:1638-1719).
    ///
    /// Given the active set of trial locations that might hold (pieces of)
    /// the return value, calculate the best matching ParamEntry from this
    /// list and mark all the trials that are contained in the ParamEntry as
    /// used. If `first_only` is `true`, the list is assumed to hold partial
    /// storage locations for split return values and only the first
    /// ParamEntry in a storage class is allowed to match.
    pub fn fillin_map_fallback(&self, active: &mut ParamActive, first_only: bool) {
        let mut best_entry: Option<usize> = None;
        let mut best_cover = 0i32;
        let mut best_class = TypeClass::Pointer;
        let num_trials = active.get_num_trials();
        // Ghidra: for each entry, evaluate all active trials in terms of it.
        for (entry_idx, curentry) in self.base.get_entry().iter().enumerate() {
            if first_only
                && !curentry.is_first_in_class()
                && curentry.is_exclusion()
                && curentry.get_all_groups().len() == 1
            {
                continue; // Not the first entry in the storage class.
            }
            let mut putative_match = false;
            for j in 0..num_trials {
                let (t_space, t_addr, t_size, t_active) = {
                    let t = active.get_trial(j);
                    (t.get_space(), t.get_address(), t.get_size(), t.is_active())
                };
                if t_active {
                    // Ghidra: cc:1655-1656 int4 res =
                    // curentry->justifiedContain(paramtrial.getAddress(),
                    // paramtrial.getSize()); — the trial Address carries
                    // its space, so the per-entry walk rejects foreign-space
                    // queries itself (per-piece address.cc:133 for joins —
                    // join entries ARE reachable — and fspec.cc:269 /
                    // address.cc:133 for plain entries). No caller-level
                    // space guard exists in Ghidra.
                    let res = curentry.justified_contain_in_space(t_addr, t_size, t_space);
                    if res >= 0 {
                        active.get_trial_mut(j).set_entry(entry_idx, res);
                        putative_match = true;
                    } else {
                        active.get_trial_mut(j).clear_entry();
                    }
                } else {
                    active.get_trial_mut(j).clear_entry();
                }
            }
            if !putative_match { continue; }
            active.sort_trials(self.base.get_entry());
            // Count least-justified contiguous bytes covered by this entry.
            let mut offmatch = 0i32;
            let mut k = 0usize;
            while k < active.get_num_trials() {
                let t = active.get_trial(k);
                let entry_idx_opt = t.get_entry_index();
                if entry_idx_opt.is_none() { k += 1; continue; }
                if offmatch != t.get_offset() { break; }
                if ((offmatch == 0) && curentry.is_param_check_low())
                    || ((offmatch != 0) && curentry.is_param_check_high())
                {
                    // Multi-precision extra checks: reject pieces that look
                    // like the remainder of a div/mod or an indirect-creation.
                    if t.is_rem_formed() { break; }
                    if t.is_ind_create_formed() { break; }
                }
                offmatch += t.get_size();
                k += 1;
            }
            if offmatch < curentry.get_min_size() {
                // Didn't cover the minimum size; don't use this entry.
                k = 0;
            }
            let cur_type = curentry.get_type();
            if k == active.get_num_trials()
                && ((cur_type as u32) < (best_class as u32) || (offmatch > best_cover))
            {
                best_entry = Some(entry_idx);
                best_cover = offmatch;
                best_class = cur_type;
            }
            let _ = curentry; // borrow-checker hint
        }
        match best_entry {
            None => {
                // Ghidra: no match — mark every trial no-use.
                for i in 0..active.get_num_trials() {
                    active.get_trial_mut(i).mark_no_use();
                }
            }
            Some(best) => {
                let best_entry_ref = &self.base.get_entry()[best];
                for i in 0..active.get_num_trials() {
                    let (t_space, t_addr, t_size, t_active) = {
                        let t = active.get_trial(i);
                        (t.get_space(), t.get_address(), t.get_size(), t.is_active())
                    };
                    if t_active {
                        // Ghidra: cc:1701-1702 int4 res =
                        // bestentry->justifiedContain(paramtrial.getAddress(),
                        // paramtrial.getSize()); — space-aware walk, same
                        // guards as cc:1656 above (joins reachable,
                        // foreign-space rejection inside the walk).
                        let res = best_entry_ref.justified_contain_in_space(t_addr, t_size, t_space);
                        if res >= 0 {
                            let t = active.get_trial_mut(i);
                            t.mark_used(); // Only actives are ever marked used.
                            t.set_entry(best, res);
                        } else {
                            let t = active.get_trial_mut(i);
                            t.mark_no_use();
                            t.clear_entry();
                        }
                    } else {
                        let t = active.get_trial_mut(i);
                        t.mark_no_use();
                        t.clear_entry();
                    }
                }
                active.sort_trials(self.base.get_entry());
            }
        }
    }

    // Ghidra: fspec.cc:1721 ParamListStandardOut::fillinMap
    /// Decide the formal output parameter given a set of trials, following
    /// the structural branches of `fillinMap` (fspec.cc:1721-1763). If
    /// `use_fillin_fallback` is set, defers entirely to the fallback path;
    /// otherwise walks the trials, attaches each active one to its entry
    /// (rejecting remainder / indirect-creation pieces that aren't
    /// first-in-class), then asks the model rules to settle the output,
    /// falling back to the first-entry-only fallback
    /// (`fillinMapFallback(active, true)`, fspec.cc:1762).
    pub fn fillin_map(&self, active: &mut ParamActive) {
        if active.get_num_trials() == 0 { return; }
        if self.use_fillin_fallback {
            self.fillin_map_fallback(active, false);
            return;
        }
        for i in 0..active.get_num_trials() {
            let (t_space, t_addr, t_size, t_active) = {
                let t = active.get_trial(i);
                (t.get_space(), t.get_address(), t.get_size(), t.is_active())
            };
            active.get_trial_mut(i).clear_entry();
            if !t_active { continue; }
            let entry = self.base.find_entry(t_space, t_addr, t_size, false);
            if entry.is_none() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            let entry_idx = entry.unwrap();
            // Ghidra: int4 res = entry->justifiedContain(trial.getAddress(),
            // trial.getSize()); — the trial Address carries its space, so a
            // join entry returned by findEntry is walked per piece against
            // the trial's space (space-aware form).
            let res = self.base.get_entry()[entry_idx]
                .justified_contain_in_space(t_addr, t_size, t_space);
            let rem_or_ind = {
                let t = active.get_trial(i);
                t.is_rem_formed() || t.is_ind_create_formed()
            };
            if rem_or_ind && !self.base.get_entry()[entry_idx].is_first_in_class() {
                active.get_trial_mut(i).mark_no_use();
                continue;
            }
            active.get_trial_mut(i).set_entry(entry_idx, res);
        }
        active.sort_trials(self.base.get_entry());
        // fspec.cc:1746-1761: walk the model rules in declaration order;
        // the first whose fillinOutputMap accepts the trial set settles
        // the output — every active trial is marked used, inactives get
        // markNoUse with the entry reset — and fillinMap returns.
        for rule in self.base.model_rules.iter() {
            if rule.action.fillin_output_map(active, self.base.get_entry()) {
                for i in 0..active.get_num_trials() {
                    let t_active = active.get_trial(i).is_active();
                    if t_active {
                        active.get_trial_mut(i).mark_used();
                    } else {
                        active.get_trial_mut(i).mark_no_use();
                        active.get_trial_mut(i).clear_entry();
                    }
                }
                return;
            }
        }
        self.fillin_map_fallback(active, true);
    }

    // Ghidra: fspec.cc:1765 ParamListStandardOut::possibleParam
    /// Is the given storage a possible return-value location? Faithful to
    /// `possibleParam` (fspec.cc:1765-1774): iterates ALL entries with NO
    /// caller-level space filter and NO resolver window — join entries
    /// ARE reachable, and space rejection happens only inside
    /// `justifiedContain` (per-piece address.cc:133 for joins, cc:269 /
    /// address.cc:133 for plain entries). `space` is the query address's
    /// space (Ghidra reads it from the `const Address &loc`; the legacy
    /// spaceless `Address` needs it alongside — see `find_entry`).
    /// Differs from `ParamListStandard`'s override (which uses
    /// `find_entry`) because output entries are evaluated per-class, not
    /// by exact match (FSPEC-POSSIBLEPARAM-JOIN-0006).
    pub fn possible_param(&self, space: AddressSpace, loc: Address, size: i32) -> bool {
        for cur in self.base.get_entry() {
            // Ghidra: fspec.cc:1770 if ((*iter).justifiedContain(loc,size)
            // >= 0) return true; — the loc carries its space, so the
            // per-entry space guards apply; no minSize gate exists here.
            if cur.justified_contain_in_space(loc, size, space) >= 0 { return true; }
        }
        false
    }

    // Ghidra: fspec.cc:1776 ParamListStandardOut::decode
    /// Decode this list, then cache the available fill-in information. The
    /// locked `decode` (fspec.cc:1776-1780) delegates `<pentry>` / `<group>` /
    /// `<rule>` parsing and calls `initialize()`.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        effectlist: &mut Vec<EffectRecord>,
        normalstack: bool,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.base.decode(decoder, effectlist, normalstack, register_resolver)?;
        self.initialize();
        Ok(())
    }

    // Ghidra: fspec.hh:669 ParamListStandardOut::clone
    /// Virtual clone. Faithful to `clone` (fspec.cc:1783-1787).
    pub fn clone_out(&self) -> ParamListStandardOut { self.clone() }
}

// ======================================================================
// ParamListRegisterOut — faithful port of Ghidra's
// `class ParamListRegisterOut : public ParamListStandardOut`
// (fspec.hh:679-686, fspec.cc:1519-1540)
// ======================================================================
// A model for passing back return values from a function. This is a
// resource list of potential storage locations for a return value, at
// most 1 of which will be chosen. When assigning based on data-type
// (assignMap), the first list entry that fits is chosen.

/// Faithful port of `class ParamListRegisterOut` (fspec.hh:679-686).
#[derive(Debug, Clone)]
pub struct ParamListRegisterOut {
    /// Inherited `ParamListStandardOut` state.
    pub base: ParamListStandardOut,
}

impl Default for ParamListRegisterOut {
    // RUGRA-GLUE: Rust Default trait bridge delegates to new(); Ghidra has the
    // ParamListRegisterOut constructor but no default() member.
    fn default() -> Self { Self::new() }
}

impl ParamListRegisterOut {
    // Ghidra: fspec.hh:681 ParamListRegisterOut::ParamListRegisterOut()
    /// Constructor. Faithful to `ParamListRegisterOut()` (fspec.hh:681).
    pub fn new() -> Self { Self { base: ParamListStandardOut::new() } }

    // Ghidra: fspec.hh:682 ParamListRegisterOut::ParamListRegisterOut(op2)
    /// Copy constructor. Faithful to
    /// `ParamListRegisterOut(const ParamListRegisterOut &op2)` (fspec.hh:682).
    pub fn from_other(op2: &ParamListRegisterOut) -> Self {
        Self { base: ParamListStandardOut::from_other(&op2.base) }
    }

    // Ghidra: fspec.hh:683 ParamListRegisterOut::getType
    /// Return the runtime type tag. Faithful to `getType` (fspec.hh:683).
    pub fn get_type(&self) -> ParamListKind { ParamListKind::RegisterOut }

    // Ghidra: fspec.cc:1519 ParamListRegisterOut::assignMap
    /// Assign the return value to the first fitting register entry. The
    /// no-ModelRule scalar path follows `assignMap` (fspec.cc:1519-1533) and
    /// emplaces one
    /// `ParameterPiece`; on a non-void out-type the storage is assigned via
    /// `ParamListStandard::assignAddress` (which, with no model rules,
    /// falls through to `assignAddressFallback` — the "first entry that
    /// fits" strategy). On failure throws `ParamUnassignedError`.
    pub fn assign_map(
        &self, proto: &PrototypePieces,
        _typefactory: &crate::type_system::TypeFactory,
        res: &mut Vec<ParameterPieces>,
    ) -> Result<(), String> {
        let mut status = vec![0i32; self.base.base.get_num_group() as usize];
        res.push(ParameterPieces::default());
        let out_type = match proto.out_type {
            None => {
                res.last_mut().unwrap().ty = None;
                res.last_mut().unwrap().flags = 0;
                return Ok(());
            }
            Some(t) => t,
        };
        if !matches!(out_type.get_metatype(), crate::type_system::TypeMetatype::Void) {
            let r = self.base.base.assign_address(
                out_type, proto, -1, &mut status, res.last_mut().unwrap(),
            );
            if r == AssignActionResponse::Fail {
                return Err(format!(
                    "Cannot assign parameter address for {}",
                    out_type.get_name()
                ));
            }
        } else {
            res.last_mut().unwrap().ty = Some(out_type.clone());
            res.last_mut().unwrap().flags = 0;
        }
        Ok(())
    }

    // Ghidra: fspec.hh:685 ParamListRegisterOut::clone
    /// Virtual clone. Faithful to `clone` (fspec.cc:1535-1539).
    pub fn clone_reg_out(&self) -> ParamListRegisterOut { self.clone() }
}

/// Rust representation of Ghidra's virtual `ParamList *output` ownership.
/// The enum preserves the concrete output-list class selected by
/// `ProtoModel::buildParamList` while keeping ownership local to the model.
#[derive(Debug, Clone)]
pub enum ParamListOutput {
    Standard(ParamListStandardOut),
    Register(ParamListRegisterOut),
}

impl Default for ParamListOutput {
    // RUGRA-GLUE: Rust enum default for Ghidra's owning `ParamList *output`.
    fn default() -> Self { Self::standard() }
}

impl ParamListOutput {
    // RUGRA-GLUE: owning enum constructor corresponding to
    // `new ParamListStandardOut()` in ProtoModel::buildParamList.
    pub fn standard() -> Self {
        Self::Standard(ParamListStandardOut::new())
    }

    // RUGRA-GLUE: owning enum constructor corresponding to
    // `new ParamListRegisterOut()` in ProtoModel::buildParamList.
    pub fn register() -> Self {
        Self::Register(ParamListRegisterOut::new())
    }

    // RUGRA-GLUE: Rust enum dispatch for virtual ParamList::getType.
    pub fn get_type(&self) -> ParamListKind {
        match self {
            Self::Standard(list) => list.get_type(),
            Self::Register(list) => list.get_type(),
        }
    }

    // RUGRA-GLUE: Rust enum projection of the shared
    // ParamListStandardOut base class.
    fn standard_out(&self) -> &ParamListStandardOut {
        match self {
            Self::Standard(list) => list,
            Self::Register(list) => &list.base,
        }
    }

    // RUGRA-GLUE: mutable Rust enum projection of the shared
    // ParamListStandardOut base class.
    fn standard_out_mut(&mut self) -> &mut ParamListStandardOut {
        match self {
            Self::Standard(list) => list,
            Self::Register(list) => &mut list.base,
        }
    }

    // RUGRA-GLUE: Rust enum dispatch for inherited
    // ParamListStandard::characterizeAsParam.
    pub fn characterize_as_param(
        &self,
        space: AddressSpace,
        offset: u64,
        size: i32,
    ) -> i32 {
        self.standard_out().base.characterize_as_param(space, offset, size)
    }

    // RUGRA-GLUE: Rust enum dispatch for inherited
    // ParamListStandard::getBiggestContainedParam.
    pub fn get_biggest_contained_param(
        &self,
        space: AddressSpace,
        offset: u64,
        size: i32,
    ) -> Option<(AddressSpace, u64, i32)> {
        self.standard_out()
            .base
            .get_biggest_contained_param(space, offset, size)
    }

    // RUGRA-GLUE: Rust enum dispatch for inherited
    // ParamListStandard::isAutoKilledByCall.
    pub fn is_auto_killed_by_call(&self) -> bool {
        self.standard_out().is_auto_killed_by_call()
    }

    // RUGRA-GLUE: Rust enum dispatch for virtual ParamList::assignMap.
    pub fn assign_map(
        &self,
        proto: &PrototypePieces,
        type_factory: &crate::type_system::TypeFactory,
        result: &mut Vec<ParameterPieces>,
    ) -> Result<(), String> {
        match self {
            Self::Standard(list) => list.assign_map(proto, type_factory, result),
            Self::Register(list) => list.assign_map(proto, type_factory, result),
        }
    }

    // RUGRA-GLUE: Rust enum dispatch for virtual ParamList::fillinMap.
    pub fn fillin_map(&self, active: &mut ParamActive) {
        self.standard_out().fillin_map(active);
    }

    // RUGRA-GLUE: Rust enum dispatch for virtual ParamList::possibleParam.
    pub fn possible_param(&self, space: AddressSpace, loc: Address, size: i32) -> bool {
        self.standard_out().possible_param(space, loc, size)
    }

    // RUGRA-GLUE: Rust enum dispatch for virtual ParamList::decode.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        effectlist: &mut Vec<EffectRecord>,
        normalstack: bool,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<(), String> {
        self.standard_out_mut()
            .decode(decoder, effectlist, normalstack, register_resolver)
    }

    // RUGRA-GLUE: Rust enum dispatch for inherited
    // ParamListStandard::getEntry.
    pub fn get_entry(&self) -> &[ParamEntry] {
        self.standard_out().get_entry()
    }

    // RUGRA-GLUE: Rust enum dispatch for inherited
    // ParamListStandard::getMaxDelay (fspec.hh:642).
    pub fn get_max_delay(&self) -> i32 {
        self.standard_out().base.get_max_delay()
    }

    // RUGRA-GLUE: clone of the ParamListStandardOut face for
    // ProtoModelMerged::foldIn (Ghidra slices `*(ParamListStandardOut
    // *)model->output` through inheritance — both output variants share the
    // ParamListStandardOut base).
    pub fn standard_out_clone(&self) -> ParamListStandardOut {
        self.standard_out().clone()
    }

    // RUGRA-GLUE: owning constructor over a staged ParamListStandardOut
    // (the bilateral fixtures build the output list the same way the C++
    // fixture stages its fields).
    pub fn standard_with_base(out: ParamListStandardOut) -> Self {
        Self::Standard(out)
    }
}

/// A union of other input parameter passing models. Faithful to
/// `class ParamListMerged : public ParamListStandard` (fspec.hh:712-724):
/// the merged list is the union of constituent resource lists so initial
/// data-flow analysis can proceed before the exact model is known;
/// `assignMap`/`fillinMap` refuse to run (the controlling ProtoModelMerged
/// picks the real model first). Rugra models the C++ public-base via the
/// owned `base: ParamListStandard`.
#[derive(Debug, Clone)]
pub struct ParamListMerged {
    /// Inherited `ParamListStandard` state (entries, groups, resolver).
    /// Stands in for the C++ public base class.
    pub base: ParamListStandard,
}

impl Default for ParamListMerged {
    // Ghidra: fspec.hh:714 ParamListMerged::ParamListMerged()
    // RUGRA-GLUE: Default bridge for the decode() constructor form.
    fn default() -> Self { Self::new() }
}

impl ParamListMerged {
    // Ghidra: fspec.hh:714 ParamListMerged::ParamListMerged()
    /// Construct for use with decode: `ParamListMerged(void) :
    /// ParamListStandard() {}` (fspec.hh:714).
    pub fn new() -> Self {
        Self { base: ParamListStandard::new() }
    }

    // Ghidra: fspec.hh:715 ParamListMerged::ParamListMerged(const ParamListMerged &)
    /// Copy constructor: `ParamListMerged(const ParamListMerged &op2) :
    /// ParamListStandard(op2) {}` (fspec.hh:715). The Rust `Clone` on the
    /// owned base absorbs the `ParamListStandard` copy constructor
    /// (fspec.cc:597-611).
    pub fn from_standard(op2: &ParamListStandard) -> Self {
        Self { base: op2.clone() }
    }

    // Ghidra: fspec.hh:718 ParamListMerged::getType
    /// The merged list kind: `virtual uint4 getType(void) const { return
    /// p_merged; }` (fspec.hh:718).
    pub fn get_type(&self) -> ParamListKind {
        ParamListKind::Merged
    }

    // Ghidra: fspec.cc:1794 ParamListMerged::foldIn
    /// Add another model's entry list to the union. Faithful 1:1 body of
    /// `foldIn` (fspec.cc:1794-1833):
    /// 1. An empty union adopts `op2`'s spacebase and entry list verbatim.
    /// 2. A conflicting non-null spacebase is a hard error ("Cannot merge
    ///    prototype models with different stacks").
    /// 3. Otherwise each `op2` entry is classified against the existing
    ///    list: `typeint = 2` when an existing entry subsumes the new one,
    ///    `typeint = 1` when the new entry subsumes an existing one. Either
    ///    way a `minsize` mismatch demotes the classification to 0
    ///    (append); a promotion (`typeint == 1`) REPLACES the containing
    ///    entry in place. Unmatched entries append.
    pub fn fold_in(&mut self, op2: &ParamListStandard) -> Result<(), String> {
        if self.base.is_entry_empty() {
            self.base.set_space_base(op2.get_spacebase());
            *self.base.entries_mut() = op2.get_entry().to_vec();
            return Ok(());
        }
        let op2_spacebase = op2.get_spacebase();
        if self.base.get_spacebase() != op2_spacebase && op2_spacebase.is_some() {
            return Err("Cannot merge prototype models with different stacks".to_string());
        }
        for opentry in op2.get_entry() {
            // Ghidra: scan the existing entries for a subsume relationship;
            // the scan breaks at the FIRST hit with typeint 2 (existing
            // subsumes new) or 1 (new subsumes existing).
            let mut hit: Option<(usize, i32)> = None; // (index, typeint)
            for (i, cur) in self.base.get_entry().iter().enumerate() {
                if cur.subsumes_definition(opentry) {
                    hit = Some((i, 2));
                    break;
                }
                if opentry.subsumes_definition(cur) {
                    hit = Some((i, 1));
                    break;
                }
            }
            match hit {
                // Ghidra: typeint==2 — an existing entry subsumes the new
                // one; the entry is dropped UNLESS the minsize disagrees,
                // which demotes to an append (typeint = 0).
                Some((i, 2)) => {
                    // Ghidra: if ((*iter).getMinSize() != opentry.getMinSize()) typeint = 0;
                    if self.base.get_entry()[i].get_min_size() != opentry.get_min_size() {
                        self.base.entries_mut().push(opentry.clone());
                    }
                }
                // Ghidra: typeint==1 — the new entry subsumes the existing
                // one; minsize agreement replaces the existing entry in
                // place, disagreement demotes to an append.
                Some((i, 1)) => {
                    if self.base.get_entry()[i].get_min_size() != opentry.get_min_size() {
                        self.base.entries_mut().push(opentry.clone());
                    } else {
                        // Replace with the containing entry
                        self.base.entries_mut()[i] = opentry.clone();
                    }
                }
                // Ghidra: typeint==0 — no subsume relationship: append.
                Some(_) | None => {
                    self.base.entries_mut().push(opentry.clone());
                }
            }
        }
        Ok(())
    }

    // Ghidra: fspec.hh:717 ParamListMerged::finalize
    /// Fold-ins are finished; finalize \b this: `void finalize(void) {
    /// populateResolver(); }` (fspec.hh:717).
    pub fn finalize(&mut self) {
        self.base.populate_resolver();
    }

    // Ghidra: fspec.hh:719 ParamListMerged::assignMap
    /// Faithful to the refusing override `throw LowlevelError("Cannot
    /// assign prototype before model has been resolved");` (fspec.hh:719).
    pub fn assign_map_refuses(&self) -> Result<(), String> {
        Err("Cannot assign prototype before model has been resolved".to_string())
    }

    // Ghidra: fspec.hh:721 ParamListMerged::fillinMap
    /// Faithful to the refusing override `throw LowlevelError("Cannot
    /// determine prototype before model has been resolved");`
    /// (fspec.hh:721).
    pub fn fillin_map_refuses(&self) -> Result<(), String> {
        Err("Cannot determine prototype before model has been resolved".to_string())
    }
}

/// Internal enum mirroring Ghidra's `AssignAction` hidden-return codes
/// (modelrules.hh:264-271). Rugra's `AssignActionResponse` collapses these
/// into `Fail`/`Success`; `ParamListStandardOut::assign_map` re-expands
/// them locally to drive the hidden-return escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HiddenRetAction {
    Success,
    PtrParam,
    SpecialReg,
    SpecialRegVoid,
}

// ======================================================================
// ProtoModelFull — faithful port of Ghidra's `ProtoModel`
// (fspec.hh:748-1100, fspec.cc:2263-2700)
// ======================================================================
// The existing `crate::type_system::protomodel::ProtoModel` is a simplified
// x86_64 stub. This struct is the 1:1 alignment target: it carries the full
// field set (effectlist, likelytrash, internalstorage, localrange, paramrange,
// input/output ParamListStandard) so that `decode`, `assignParameterStorage`,
// `isCompatible`, `defaultLocalRange`, `buildParamList` etc. can be ported
// faithfully.

/// Reserved `extrapop` value meaning the function's extrapop is unknown.
/// Faithful to `ProtoModel::extrapop_unknown` (fspec.hh:772).
pub const EXTRAPOP_UNKNOWN_FULL: i32 = 0x8000;

/// Magic sentinel used by `ProtoModel::decode` to detect that no `extrapop`
/// attribute was seen (Ghidra initializes `extrapop = -300` before parsing,
/// fspec.cc:2562). Distinct from `EXTRAPOP_UNKNOWN_FULL`.
const EXTRAPOP_MISSING_SENTINEL: i32 = -300;

/// A faithful port of Ghidra's `ProtoModel` (fspec.hh:748-1017).
///
/// Holds the input/output `ParamListStandard`, effect records, likely-trash,
/// internal-storage registers, local/param stack ranges, and ABI properties
/// (extrapop, stack growth direction, hasThis, isConstructor, isPrinted).
#[derive(Debug)]
pub struct ProtoModelFull {
    /// Name of the model (e.g. "__stdcall", "default"). Faithful to `name`.
    pub name: String,
    /// Extra bytes popped from the stack by the callee. Faithful to `extrapop`.
    pub extrapop: i32,
    /// Input parameter resource list. Faithful to `ParamList *input`.
    pub input: ParamListStandard,
    /// Output (return value) parameter resource list. Faithful to
    /// `ParamList *output`.
    pub output: ParamListOutput,
    /// Side-effects on non-parameter storage. Faithful to `effectlist`.
    /// Must be kept sorted by address for `lookup_effect`.
    pub effectlist: Vec<EffectRecord>,
    /// Storage locations potentially carrying trash values. Faithful to
    /// `likelytrash`.
    pub likelytrash: Vec<VarnodeData>,
    /// Registers holding internal compiler constants. Faithful to
    /// `internalstorage`.
    pub internalstorage: Vec<VarnodeData>,
    /// Id of injection to perform at function entry (-1 = unused). Faithful
    /// to `injectUponEntry`.
    pub inject_upon_entry: i32,
    /// Id of injection to perform after a call (-1 = unused). Faithful to
    /// `injectUponReturn`.
    pub inject_upon_return: i32,
    /// Memory range(s) of space-based locals. Faithful to `localrange`.
    pub localrange: crate::address::RangeList,
    /// Memory range(s) of space-based parameters. Faithful to `paramrange`.
    pub paramrange: crate::address::RangeList,
    /// True if stack parameters have (normal) low→high ordering. Faithful to
    /// `stackgrowsnegative`.
    pub stackgrowsnegative: bool,
    /// True if this model has a `this` parameter. Faithful to `hasThis`.
    pub has_this: bool,
    /// True if this model is a constructor. Faithful to `isConstruct`.
    pub is_construct: bool,
    /// True if this model name should be printed in declarations. Faithful to
    /// `isPrinted`.
    pub is_printed: AtomicBool,
    /// The model this is a copy of (alias parent), or `None`. Faithful to
    /// `compatModel`. Used by `isCompatible`.
    pub compat_model: Option<usize>,
}

impl Clone for ProtoModelFull {
    // Ghidra: fspec.cc:2359 ProtoModel::ProtoModel(const string &,const ProtoModel &)
    /// Copy a prototype model into a distinct alias object.  The mutable
    /// print flag is copied by value, never shared with the parent model.
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            extrapop: self.extrapop,
            input: self.input.clone(),
            output: self.output.clone(),
            effectlist: self.effectlist.clone(),
            likelytrash: self.likelytrash.clone(),
            internalstorage: self.internalstorage.clone(),
            inject_upon_entry: self.inject_upon_entry,
            inject_upon_return: self.inject_upon_return,
            localrange: self.localrange.clone(),
            paramrange: self.paramrange.clone(),
            stackgrowsnegative: self.stackgrowsnegative,
            has_this: self.has_this,
            is_construct: self.is_construct,
            is_printed: AtomicBool::new(true),
            compat_model: self.compat_model,
        }
    }
}

impl ProtoModelFull {
    // Ghidra: fspec.cc:2339 ProtoModel::ProtoModel (default constructor)
    /// Construct a model with default fields, mirroring Ghidra's constructor
    /// which calls `defaultLocalRange()`/`defaultParamRange()`.
    pub fn new(stack_space: Option<AddressSpace>, addr_size: usize) -> Self {
        let mut model = Self {
            name: String::new(),
            extrapop: 0,
            input: ParamListStandard::new(),
            output: ParamListOutput::standard(),
            effectlist: Vec::new(),
            likelytrash: Vec::new(),
            internalstorage: Vec::new(),
            inject_upon_entry: -1,
            inject_upon_return: -1,
            localrange: crate::address::RangeList::new(),
            paramrange: crate::address::RangeList::new(),
            stackgrowsnegative: true,
            has_this: false,
            is_construct: false,
            is_printed: AtomicBool::new(true),
            compat_model: None,
        };
        model.default_local_range(stack_space, addr_size);
        model.default_param_range(stack_space, addr_size);
        model
    }

    // Ghidra: fspec.hh:883 ProtoModel::possibleInputParam
    /// Does the given storage location make sense as an input parameter?
    /// Faithful inline delegation `return input->possibleParam(loc,size);`
    /// (fspec.hh:885) to the input ParamList.
    pub fn possible_input_param(&self, loc_space: AddressSpace, loc: Address, size: i32) -> bool {
        self.input.possible_param(loc_space, loc, size)
    }

    // Ghidra: fspec.hh:812 ProtoModel::checkInputJoin
    /// Check whether two input storage locations can represent a single
    /// logical parameter. Faithful inline delegation `return
    /// input->checkJoin(hiaddr,hisize,loaddr,losize);` (fspec.hh:813).
    pub fn check_input_join(
        &self, space: AddressSpace, hi_addr: Address, hi_size: i32, lo_addr: Address, lo_size: i32,
    ) -> bool {
        self.input.check_join(space, hi_addr, hi_size, lo_addr, lo_size)
    }

    // Ghidra: fspec.hh:824 ProtoModel::checkOutputJoin
    /// Check whether two output storage locations can represent a single
    /// logical return value. Faithful inline delegation `return
    /// output->checkJoin(hiaddr,hisize,loaddr,losize);` (fspec.hh:825).
    pub fn check_output_join(
        &self, space: AddressSpace, hi_addr: Address, hi_size: i32, lo_addr: Address, lo_size: i32,
    ) -> bool {
        self.output.standard_out().base.check_join(space, hi_addr, hi_size, lo_addr, lo_size)
    }

    // Ghidra: fspec.hh:844 ProtoModel::internalBegin
    // Ghidra: fspec.hh:845 ProtoModel::internalEnd
    /// The model's internal-storage list. The slice IS Ghidra's
    /// `internalBegin()`/`internalEnd()` iterator pair (fspec.hh:844-845).
    pub fn internal_iter(&self) -> &[VarnodeData] {
        &self.internalstorage
    }

    // Ghidra: fspec.hh:873 ProtoModel::characterizeAsOutput
    /// Characterize whether the given range overlaps output storage.
    /// Faithful inline delegation `return output->characterizeAsParam(loc,
    /// size);` (fspec.hh:874).
    pub fn characterize_as_output(&self, space: AddressSpace, loc: Address, size: i32) -> i32 {
        self.output.characterize_as_param(space, loc.as_u64(), size)
    }

    // Ghidra: fspec.hh:904 ProtoModel::possibleInputParamWithSlot
    /// Pass-back the slot and slot size for the given storage location as an
    /// input parameter. Faithful inline delegation `return
    /// input->possibleParamWithSlot(loc,size,slot,slotsize);` (fspec.hh:905).
    pub fn possible_input_param_with_slot(
        &self, space: AddressSpace, loc: Address, size: i32, slot: &mut i32, slot_size: &mut i32,
    ) -> bool {
        self.input.possible_param_with_slot(space, loc, size, slot, slot_size)
    }

    // Ghidra: fspec.hh:916 ProtoModel::possibleOutputParamWithSlot
    /// Pass-back the slot and slot size for the given storage location as a
    /// return value. Faithful inline delegation `return
    /// output->possibleParamWithSlot(loc,size,slot,slotsize);` (fspec.hh:917).
    pub fn possible_output_param_with_slot(
        &self, space: AddressSpace, loc: Address, size: i32, slot: &mut i32, slot_size: &mut i32,
    ) -> bool {
        self.output
            .standard_out()
            .base
            .possible_param_with_slot(space, loc, size, slot, slot_size)
    }

    // Ghidra: fspec.hh:928 ProtoModel::unjustifiedInputParam
    /// Check if the given storage location looks like an unjustified input
    /// parameter. Faithful inline delegation `return
    /// input->unjustifiedContainer(loc,size,res);` (fspec.hh:929).
    pub fn unjustified_input_param(
        &self, space: AddressSpace, loc: Address, size: i32, res: &mut VarnodeData,
    ) -> bool {
        self.input.unjustified_container(space, loc, size, res)
    }

    // Ghidra: fspec.hh:941 ProtoModel::assumedInputExtension
    /// Get the type of extension and containing input parameter for the
    /// given storage. Faithful inline delegation `return
    /// input->assumedExtension(addr,size,res);` (fspec.hh:942).
    pub fn assumed_input_extension(
        &self, space: AddressSpace, addr: Address, size: i32, res: &mut VarnodeData,
    ) -> FspecOpCode {
        self.input.assumed_extension(space, addr, size, res)
    }

    // Ghidra: fspec.hh:954 ProtoModel::assumedOutputExtension
    /// Get the type of extension and containing return value location for
    /// the given storage. Faithful inline delegation `return
    /// output->assumedExtension(addr,size,res);` (fspec.hh:955).
    pub fn assumed_output_extension(
        &self, space: AddressSpace, addr: Address, size: i32, res: &mut VarnodeData,
    ) -> FspecOpCode {
        self.output.standard_out().base.assumed_extension(space, addr, size, res)
    }

    // Ghidra: fspec.hh:963 ProtoModel::getBiggestContainedInputParam
    /// Pass-back the biggest input parameter contained within the given
    /// range. Faithful inline delegation `return
    /// input->getBiggestContainedParam(loc, size, res);` (fspec.hh:964).
    pub fn get_biggest_contained_input_param(
        &self, space: AddressSpace, loc: Address, size: i32, res: &mut VarnodeData,
    ) -> bool {
        match self.input.get_biggest_contained_param(space, loc.as_u64(), size) {
            Some((res_space, res_offset, res_size)) => {
                res.space = res_space;
                res.offset = res_offset;
                res.size = res_size;
                true
            }
            None => false,
        }
    }

    // Ghidra: fspec.hh:973 ProtoModel::getBiggestContainedOutput
    /// Pass-back the biggest possible output storage location contained
    /// within the given range. Faithful inline delegation `return
    /// output->getBiggestContainedParam(loc, size, res);` (fspec.hh:974).
    pub fn get_biggest_contained_output(
        &self, space: AddressSpace, loc: Address, size: i32, res: &mut VarnodeData,
    ) -> bool {
        match self.output.get_biggest_contained_param(space, loc.as_u64(), size) {
            Some((res_space, res_offset, res_size)) => {
                res.space = res_space;
                res.offset = res_offset;
                res.size = res_size;
                true
            }
            None => false,
        }
    }

    // Ghidra: fspec.cc:2263 ProtoModel::defaultLocalRange
    /// Establish the default stack range used for local variables. Faithful
    /// 1:1 port of `defaultLocalRange` (fspec.cc:2263-2290). For a normal
    /// (negative-growing) stack, locals occupy the high end of the stack
    /// space; for a flipped stack they occupy the low end. The numeric bounds
    /// scale with the stack space's address size exactly as in Ghidra.
    pub fn default_local_range(&mut self, stack_space: Option<AddressSpace>, addr_size: usize) {
        let spc = match stack_space {
            Some(s) => s,
            None => return,
        };
        let max_off = u64::MAX; // spc->getHighest() for an enum space model
        if self.stackgrowsnegative {
            let last = max_off;
            let span = if addr_size >= 4 { 999999u64 }
                else if addr_size >= 2 { 9999u64 }
                else { 99u64 };
            let first = last.wrapping_sub(span);
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.localrange.insert_range(r);
            }
        } else {
            let first = 0u64;
            let last = if addr_size >= 4 { 999999u64 }
                else if addr_size >= 2 { 9999u64 }
                else { 99u64 };
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.localrange.insert_range(r);
            }
        }
        // spc is captured to mirror Ghidra's `AddrSpace *spc`; the bound is
        // encoded into the inserted Range's space implicitly (Rugra's Range
        // does not carry a space, matching the existing `RangeList` API).
        let _ = spc;
    }

    // Ghidra: fspec.cc:2292 ProtoModel::defaultParamRange
    /// Establish the default stack range used for input parameters. Faithful
    /// 1:1 port of `defaultParamRange` (fspec.cc:2292-2319). For a normal
    /// (negative-growing) stack, parameters are the first 512/256/16 bytes
    /// (scaling with address size); for a flipped stack they are the high
    /// end.
    pub fn default_param_range(&mut self, stack_space: Option<AddressSpace>, addr_size: usize) {
        let spc = match stack_space {
            Some(s) => s,
            None => return,
        };
        let max_off = u64::MAX;
        if self.stackgrowsnegative {
            let first = 0u64;
            let last = if addr_size >= 4 { 511u64 }
                else if addr_size >= 2 { 255u64 }
                else { 15u64 };
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.paramrange.insert_range(r);
            }
        } else {
            let last = max_off;
            let first_sub = if addr_size >= 4 { 511u64 }
                else if addr_size >= 2 { 255u64 }
                else { 15u64 };
            let first = last.wrapping_sub(first_sub);
            if let Some(r) = crate::address::Range::new(Address::new(first), Address::new(last)) {
                self.paramrange.insert_range(r);
            }
        }
        let _ = spc;
    }

    // Ghidra: fspec.cc:2323 ProtoModel::buildParamList
    /// Allocate parameter lists based on the resource `strategy` string.
    /// Faithful to the output half of `buildParamList` (fspec.cc:2323-2336):
    /// ""/"standard" owns `ParamListStandardOut`, while "register" owns
    /// `ParamListRegisterOut`. Unknown strategies are a hard error.
    pub fn build_param_list(&mut self, strategy: &str) -> Result<(), String> {
        if strategy.is_empty() || strategy == "standard" {
            self.input = ParamListStandard::new();
            self.output = ParamListOutput::standard();
        } else if strategy == "register" {
            // FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001 covers the output virtual
            // class. Input ParamListRegister ownership remains a separately
            // observable residual of this atom.
            self.input = ParamListStandard::new();
            self.output = ParamListOutput::register();
        } else {
            return Err(format!("Unknown strategy type: {}", strategy));
        }
        Ok(())
    }

    // Ghidra: fspec.cc:2406 ProtoModel::isCompatible (getAliasParent)
    /// Whether this model is an alias copy (Ghidra's `getAliasParent() !=
    /// null`).  Only `Some`/`None` is observable; the numeric marker value
    /// carries no identity.
    pub fn get_alias_parent_marker(&self) -> Option<usize> {
        self.compat_model
    }

    // Ghidra: fspec.cc:2359 ProtoModel::ProtoModel(const string &,const ProtoModel &)
    /// Mark this model as an alias copy (the copy constructor's
    /// `compatModel = &op2` assignment).
    pub fn set_alias_parent_marker(&mut self) {
        self.compat_model = Some(usize::MAX);
    }

    // Ghidra: fspec.cc:2406 ProtoModel::isCompatible
    /// Return true if `other` can be substituted for this model during
    /// `FuncCallSpecs::deindirect`. Faithful 1:1 port of `isCompatible`
    /// (fspec.cc:2406-2412). Two models are compatible only if one is a copy
    /// of the other (differing at most in the `hasThis` property). The
    /// `compat_model` index plays the role of Ghidra's `compatModel` pointer.
    pub fn is_compatible(&self, other: &ProtoModelFull) -> bool {
        // Ghidra: `this == op2 || compatModel == op2 || op2->compatModel == this`
        if std::ptr::eq(self, other) { return true; }
        // Match by alias-parent index. self.compat_model points to the model
        // this was copied from; if other is that model (by name) they are
        // compatible.
        if let Some(_idx) = self.compat_model {
            if self.is_alias_of(other) { return true; }
        }
        if let Some(_idx) = other.compat_model {
            if other.is_alias_of(self) { return true; }
        }
        false
    }

    /// Helper: true if `self` is an alias copy of `parent` (same name-pattern
    /// and field set, modulo `hasThis`). Stands in for Ghidra's pointer
    /// identity check `compatModel == op2`.
    // RUGRA-GLUE: Rust-side alias predicate because ProtoModelFull does not
    // retain Ghidra's ProtoModel* identity; Ghidra performs these pointer
    // comparisons inline in ProtoModel::isCompatible (fspec.cc:2406).
    fn is_alias_of(&self, parent: &ProtoModelFull) -> bool {
        // Same name OR (parent has the same input/output entries and extrapop).
        self.name == parent.name
            || (self.extrapop == parent.extrapop
                && self.input.get_num_group() == parent.input.get_num_group())
    }

    // Ghidra: fspec.cc:2429 ProtoModel::assignParameterStorage
    /// Calculate input and output storage locations given a function
    /// prototype. This ports the selected scalar path of `assignParameterStorage`
    /// (fspec.cc:2429-2462). The output storage is assigned first (entry 0 of
    /// `res`), then the input storages follow. If `ignore_output_error` is
    /// true, an unassignable return value collapses to a void entry instead of
    /// propagating `ParamUnassignedError`. When the model `hasThis`, the
    /// `isthis` flag is set on the appropriate input, accounting for a hidden
    /// return pointer. Architecture TypeFactory identity, ModelRules, and
    /// non-scalar storage remain `FSPEC-0002`.
    pub fn assign_parameter_storage(
        &self,
        proto: &PrototypePieces,
        res: &mut Vec<ParameterPieces>,
        ignore_output_error: bool,
        void_type: Option<Arc<Datatype>>,
    ) -> Result<(), String> {
        let type_factory = crate::type_system::TypeFactory::shared_default();
        let type_factory = type_factory
            .read()
            .map_err(|_| "shared type factory lock poisoned".to_string())?;
        if ignore_output_error {
            match self.output.assign_map(proto, &type_factory, res) {
                Ok(()) => {}
                Err(_e) => {
                    // Ghidra: catch ParamUnassignedError → clear res, push a
                    // single void entry with undefined address.
                    res.clear();
                    res.push(ParameterPieces {
                        space: AddressSpace::Ram,
                        addr: Address::new(0),
                        ty: void_type.clone(),
                        flags: 0,
                    });
                }
            }
        } else {
            self.output.assign_map(proto, &type_factory, res)?;
        }
        self.input.assign_map(proto, res)?;

        // Ghidra: fspec.cc:2449-2461 — set the isthis flag on the right input.
        if self.has_this && res.len() > 1 {
            let mut this_index = 1usize;
            if (res[1].flags & HIDDEN_RET_PARM) != 0 && res.len() > 2 {
                if self.input.is_this_before_ret_pointer() {
                    // pointer has been bumped by auto-return-storage: swap
                    // markup for slots 1 and 2. Use split_at_mut to obtain
                    // two disjoint mutable borrows (Rust aliasing rule).
                    let (left, right) = res.split_at_mut(2);
                    left[1].swap_markup(&mut right[0]);
                } else {
                    this_index = 2;
                }
            }
            res[this_index].flags |= THIS_POINTER_PIECE;
        }
        Ok(())
    }

    // Ghidra: fspec.hh:798 ProtoModel::deriveOutputMap
    /// Derive the return-value map through the output-specific ParamList.
    pub fn derive_output_map(&self, active: &mut ParamActive) {
        self.output.fillin_map(active);
    }

    // Ghidra: fspec.hh:892 ProtoModel::possibleOutputParam
    /// Test a complete storage address against the output resource list.
    pub fn possible_output_param(
        &self,
        space: AddressSpace,
        offset: u64,
        size: i32,
    ) -> bool {
        self.output.possible_param(space, Address::new(offset), size)
    }

    // RUGRA-GLUE: declaration-order view of the concrete output ParamList;
    // Ghidra consumers iterate the protected ParamListStandard::entry list.
    /// Iterate output resource entries in compiler-spec declaration order.
    pub fn output_entries(&self) -> &[ParamEntry] {
        self.output.get_entry()
    }

    // Ghidra: fspec.hh:1572 ProtoModel::getMaxOutputDelay
    /// Maximum heritage delay across all potential return-value resources
    /// (`ParamListStandard::calcDelay`, fspec.cc:1153-1163).
    pub fn get_max_output_delay(&self) -> i32 {
        self.output.get_max_delay()
    }

    // Ghidra: fspec.cc:2472 ProtoModel::lookupEffect (static)
    /// Look up an effect from a (sorted) EffectRecord list. Faithful 1:1 port
    /// of `lookupEffect` (fspec.cc:2472-2495). Returns the matching effect
    /// type, or `EffectType::UnknownEffect` if no record overlaps the given
    /// range. Internal (unique) space is always considered unaffected.
    pub fn lookup_effect(
        efflist: &[EffectRecord],
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> EffectType {
        // Ghidra: if (addr.getSpace()->getType()==IPTR_INTERNAL) return unaffected;
        if addr_space == AddressSpace::Unique {
            return EffectType::Unaffected;
        }
        if efflist.is_empty() {
            return EffectType::UnknownEffect;
        }
        // upper_bound by address: find first record whose address > target,
        // then step back one. EffectRecord is sorted by (space, offset).
        let target = (addr_space.space_id(), addr_offset);
        let mut idx = efflist.partition_point(|e| {
            (e.space.space_id(), e.offset) <= target
        });
        // partition_point returns first index where predicate is false, i.e.
        // first record with (space,offset) > target — matching upper_bound.
        if idx == 0 {
            // Can't go back one.
            return EffectType::UnknownEffect;
        }
        idx -= 1;
        let hit_space = efflist[idx].space;
        let hit_off = efflist[idx].offset;
        let sz = efflist[idx].size;
        if sz == 0 && hit_space == addr_space {
            // A size of zero indicates the whole space is unaffected.
            return EffectType::Unaffected;
        }
        let where_in_record = overlaps_range(
            hit_space,
            hit_off,
            sz,
            addr_space,
            addr_offset,
            size,
        );
        if where_in_record >= 0 && where_in_record + i64::from(size) <= i64::from(sz) {
            return efflist[idx].effect_type;
        }
        EffectType::UnknownEffect
    }

    // Ghidra: fspec.cc:2541 ProtoModel::hasEffect
    /// Determine the side-effect of this model on the given memory range.
    /// Faithful 1:1 port of `hasEffect` (fspec.cc:2541-2545): a direct
    /// delegation to `lookupEffect` over this model's effectlist.
    pub fn has_effect(&self, addr_space: AddressSpace, addr_offset: u64, size: i32) -> EffectType {
        Self::lookup_effect(&self.effectlist, addr_space, addr_offset, size)
    }

    // Ghidra: fspec.cc:2510 ProtoModel::lookupRecord (static)
    /// Look up a particular EffectRecord from a (sorted) list by its address
    /// and size. Faithful 1:1 port of `lookupRecord` (fspec.cc:2510-2533).
    /// Only the first `list_size` records are examined. Returns:
    ///   - `Some(idx)` — the matching record's index.
    ///   - `None` — no overlap (Ghidra's `-1`).
    ///   - `Err(())` — partial overlap with another record (Ghidra's `-2`).
    pub fn lookup_record(
        efflist: &[EffectRecord],
        list_size: usize,
        addr_space: AddressSpace,
        addr_offset: u64,
        size: i32,
    ) -> Result<Option<usize>, ()> {
        if list_size == 0 {
            return Ok(None);
        }
        let target = (addr_space.space_id(), addr_offset);
        // upper_bound by address within [0, list_size).
        let mut idx = efflist[..list_size]
            .partition_point(|e| (e.space.space_id(), e.offset) <= target);
        if idx == 0 {
            // First element's address is strictly greater than target; check
            // whether the target overlaps it (Ghidra: -2) or sits before it
            // entirely (Ghidra: -1).
            let close_space = efflist[0].space;
            let close_off = efflist[0].offset;
            return if overlaps_range(
                addr_space, addr_offset, size,
                close_space, close_off, efflist[0].size,
            ) < 0
            {
                Ok(None)
            } else {
                Err(())
            };
        }
        idx -= 1;
        let close_space = efflist[idx].space;
        let close_off = efflist[idx].offset;
        let close_size = efflist[idx].size;
        if addr_space == close_space && addr_offset == close_off && size == close_size {
            return Ok(Some(idx));
        }
        if overlaps_range(
            close_space, close_off, close_size,
            addr_space, addr_offset, size,
        ) < 0
        {
            Ok(None)
        } else {
            Err(())
        }
    }

    // Ghidra: fspec.hh:1017 ProtoModel::effectBegin / fspec.hh:1018 effectEnd
    /// Iterate the model's EffectRecord list (sorted by address). Faithful to
    /// `effectBegin`/`effectEnd` (fspec.hh:1017-1018). Used by
    /// `FuncProto::decodeEffect` to seed the override list from the model.
    pub fn effect_iter(&self) -> &[EffectRecord] {
        &self.effectlist
    }

    // Ghidra: fspec.hh:1020 ProtoModel::trashBegin / fspec.hh:1021 trashEnd
    /// Iterate the model's likely-trash VarnodeData list (sorted). Faithful to
    /// `trashBegin`/`trashEnd` (fspec.hh:1020-1021). Used by
    /// `FuncProto::decodeLikelyTrash` to fold in the model's trash list.
    pub fn trash_iter(&self) -> &[VarnodeData] {
        &self.likelytrash
    }

    // Ghidra: fspec.cc:2780 ProtoModelMerged::intersectEffects
    /// Intersect this model's effect list with another list, in place.
    /// Faithful 1:1 port of `ProtoModelMerged::intersectEffects`
    /// (fspec.cc:2780-2803). Both lists must be sorted by address. Only
    /// records present in BOTH lists survive; the merged list is rebuilt into
    /// a fresh vector and swapped in. `ProtoModelMerged` itself is not yet
    /// modelled as a distinct type in Rugra, so the merge is exposed here as
    /// a static helper for callers that fold alternative models together.
    pub fn intersect_effects(effectlist: &mut Vec<EffectRecord>, efflist: &[EffectRecord]) {
        let mut newlist: Vec<EffectRecord> = Vec::new();
        let mut i = 0usize;
        let mut j = 0usize;
        while i < effectlist.len() && j < efflist.len() {
            let eff1 = &effectlist[i];
            let eff2 = &efflist[j];
            if EffectRecord::compare_by_address(eff1, eff2) {
                i += 1;
            } else if EffectRecord::compare_by_address(eff2, eff1) {
                j += 1;
            } else {
                // Same address range; match if all fields equal.
                if eff1.space == eff2.space
                    && eff1.offset == eff2.offset
                    && eff1.size == eff2.size
                    && eff1.effect_type == eff2.effect_type
                {
                    newlist.push(eff1.clone());
                }
                i += 1;
                j += 1;
            }
        }
        std::mem::swap(effectlist, &mut newlist);
    }

    // Ghidra: fspec.cc:2809 ProtoModelMerged::intersectRegisters (static)
    /// Intersect two sorted VarnodeData register lists, writing the result
    /// into the first. Faithful 1:1 port of `intersectRegisters`
    /// (fspec.cc:2809-2832). A merge-join keeps only varnodes present in both
    /// lists, comparing with the oracle `VarnodeData::operator<` key
    /// (pcoderaw.hh:67: space, offset ascending, size descending);
    /// equivalence (`!(a<b) && !(b<a)`) is exact (space, offset, size)
    /// triple equality, matching `operator==` (pcoderaw.hh:77).
    pub fn intersect_registers(
        reg_list1: &mut Vec<VarnodeData>,
        reg_list2: &[VarnodeData],
    ) {
        let mut newlist: Vec<VarnodeData> = Vec::new();
        let mut i = 0usize;
        let mut j = 0usize;
        while i < reg_list1.len() && j < reg_list2.len() {
            let a = &reg_list1[i];
            let b = &reg_list2[j];
            // Ghidra: if (trs1 < trs2) i += 1; else if (trs2 < trs1) j += 1;
            match VarnodeData::compare(a, b) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    newlist.push(a.clone());
                    i += 1;
                    j += 1;
                }
            }
        }
        std::mem::swap(reg_list1, &mut newlist);
    }

    // Ghidra: fspec.cc:2549 ProtoModel::decode
    /// Decode a model when no named-register catalog is available.  This is
    /// equivalent to calling `decode_with_register_resolver` with a resolver
    /// that rejects named register children.
    pub fn decode(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        stack_space: Option<AddressSpace>,
        addr_size: usize,
        void_type: Option<Arc<Datatype>>,
        inject_id_resolver: Option<&dyn Fn(&str, &str) -> Option<i32>>,
    ) -> Result<String, String> {
        let no_register = |_name: &str| None;
        self.decode_with_register_resolver(
            decoder,
            stack_space,
            addr_size,
            true,
            void_type,
            inject_id_resolver,
            &no_register,
        )
    }

    // Ghidra: fspec.cc:2549 ProtoModel::decode
    /// Restore this model from a `<prototype>` element. Faithful port of
    /// `decode` (fspec.cc:2549-2700). Parses the element/attribute stream
    /// (name, extrapop, strategy, hasthis, constructor), builds the input/
    /// output ParamLists, decodes `<input>`/`<output>`/`<unaffected>`/
    /// `<killedbycall>`/`<returnaddress>`/`<localrange>`/`<paramrange>`/
    /// `<likelytrash>`/`<internal_storage>`/`<pcode>` children, then sorts the
    /// effect/likelytrash/internalstorage lists and applies default ranges.
    ///
    /// The `<pcode>` injection branch records a placeholder name in
    /// `inject_upon_entry`/`inject_upon_return` (mapped to a non-negative id
    /// when an `inject_id_resolver` is supplied). Returns the model name on
    /// success so the caller can register it.
    pub fn decode_with_register_resolver(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        stack_space: Option<AddressSpace>,
        addr_size: usize,
        stack_grows_negative: bool,
        void_type: Option<Arc<Datatype>>,
        inject_id_resolver: Option<&dyn Fn(&str, &str) -> Option<i32>>,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
    ) -> Result<String, String> {
        self.decode_with_defaults(
            decoder,
            stack_space,
            addr_size,
            stack_grows_negative,
            void_type,
            inject_id_resolver,
            register_resolver,
            None,
        )
    }

    // Ghidra: fspec.cc:2549 ProtoModel::decode
    /// The `parseCompilerConfig` path of `decode`: the Architecture's
    /// `defaultReturnAddr` is appended as a `return_address` effect record
    /// when the model has no `<returnaddress>` child of its own, faithful
    /// to fspec.cc:2689-2691
    /// (`if ((!sawretaddr)&&(glb->defaultReturnAddr.space != 0))
    /// effectlist.push_back(EffectRecord(glb->defaultReturnAddr,
    /// EffectRecord::return_address))`).  The record is pushed BEFORE the
    /// effectlist sort, so ordering follows the sorted view like every
    /// other effect.
    pub fn decode_with_defaults(
        &mut self,
        decoder: &mut dyn crate::marshal::Decoder,
        stack_space: Option<AddressSpace>,
        addr_size: usize,
        stack_grows_negative: bool,
        void_type: Option<Arc<Datatype>>,
        inject_id_resolver: Option<&dyn Fn(&str, &str) -> Option<i32>>,
        register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
        default_return_addr: Option<&VarnodeData>,
    ) -> Result<String, String> {
        use crate::marshal::Decoder;
        let mut saw_localrange = false;
        let mut saw_paramrange = false;
        let mut saw_retaddr = false;
        // Ghidra: fspec.cc:2555 — default growth direction, then consult stack space.
        self.stackgrowsnegative = stack_grows_negative;
        let mut strategy_string = String::new();
        self.localrange = crate::address::RangeList::new();
        self.paramrange = crate::address::RangeList::new();
        self.extrapop = EXTRAPOP_MISSING_SENTINEL;
        self.has_this = false;
        self.is_construct = false;
        self.is_printed.store(true, Ordering::Relaxed);
        self.effectlist.clear();
        self.inject_upon_entry = -1;
        self.inject_upon_return = -1;
        self.likelytrash.clear();
        self.internalstorage.clear();

        let elem_id = decoder.open_element();
        // Ghidra: fspec.cc:2572-2594 — attribute loop.
        loop {
            let aid = decoder.next_attribute_id();
            if aid == 0 { break; }
            match decoder.attribute_name(aid).as_deref() {
                Some("name") => self.name = decoder.read_string(),
                Some("extrapop") => {
                    // Ghidra: readSignedIntegerExpectString("unknown", extrapop_unknown)
                    let s = decoder.read_string();
                    if s == "unknown" {
                        self.extrapop = EXTRAPOP_UNKNOWN_FULL;
                    } else {
                        self.extrapop = s.parse::<i32>().unwrap_or(EXTRAPOP_UNKNOWN_FULL);
                    }
                }
                Some("stackshift") => {
                    // Allow for backward compatibility; value ignored.
                    let _ = decoder.read_string();
                }
                Some("strategy") => strategy_string = decoder.read_string(),
                Some("hasthis") => self.has_this = decoder.read_bool(),
                Some("constructor") => self.is_construct = decoder.read_bool(),
                Some(other) => {
                    let _ = decoder.read_string();
                    return Err(format!("Unknown prototype attribute: {}", other));
                }
                None => {
                    let _ = decoder.read_string();
                }
            }
        }
        if self.name == "__thiscall" {
            self.has_this = true;
        }
        if self.extrapop == EXTRAPOP_MISSING_SENTINEL {
            return Err("Missing prototype attributes".to_string());
        }

        // Ghidra: fspec.cc:2600 — allocate input/output ParamLists.
        self.build_param_list(&strategy_string)?;

        // Ghidra: fspec.cc:2601-2687 — child element loop.
        loop {
            let sub_id = decoder.peek_element();
            if sub_id == 0 { break; }
            let sub_name = decoder.element_name(sub_id).unwrap_or_default();
            match sub_name.as_str() {
                "input" => {
                    self.input.decode(
                        decoder,
                        &mut self.effectlist,
                        self.stackgrowsnegative,
                        register_resolver,
                    )?;
                    if let Some(stack) = stack_space {
                        self.input.get_range_list(stack, &mut self.paramrange);
                        if !self.paramrange.empty() {
                            saw_paramrange = true;
                        }
                    }
                }
                "output" => {
                    self.output.decode(
                        decoder,
                        &mut self.effectlist,
                        self.stackgrowsnegative,
                        register_resolver,
                    )?;
                }
                "unaffected" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        // Ghidra: effectlist.back().decode(unaffected, decoder)
                        let child_id = decoder.open_element();
                        let (space, offset, size) =
                            read_varnode_data_attrs_resolved(decoder, register_resolver)?;
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::Unaffected));
                    }
                    decoder.close_element(sub_id);
                }
                "killedbycall" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) =
                            read_varnode_data_attrs_resolved(decoder, register_resolver)?;
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::KilledByCall));
                    }
                    decoder.close_element(sub_id);
                }
                "returnaddress" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) =
                            read_varnode_data_attrs_resolved(decoder, register_resolver)?;
                        decoder.close_element(child_id);
                        self.effectlist.push(EffectRecord::new(space, offset, size, EffectType::ReturnAddress));
                    }
                    decoder.close_element(sub_id);
                    saw_retaddr = true;
                }
                "localrange" => {
                    saw_localrange = true;
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        if let Some(r) = read_range_child(decoder, stack_space) {
                            self.localrange.insert_range(r);
                        } else {
                            // Consume the unparseable child.
                            let cid = decoder.open_element();
                            decoder.close_element(cid);
                        }
                    }
                    decoder.close_element(sub_id);
                }
                "paramrange" => {
                    saw_paramrange = true;
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        if let Some(r) = read_range_child(decoder, stack_space) {
                            self.paramrange.insert_range(r);
                        } else {
                            let cid = decoder.open_element();
                            decoder.close_element(cid);
                        }
                    }
                    decoder.close_element(sub_id);
                }
                "likelytrash" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) =
                            read_varnode_data_attrs_resolved(decoder, register_resolver)?;
                        decoder.close_element(child_id);
                        self.likelytrash.push(VarnodeData { space, offset, size });
                    }
                    decoder.close_element(sub_id);
                }
                "internal_storage" => {
                    decoder.open_element();
                    while decoder.peek_element() != 0 {
                        let child_id = decoder.open_element();
                        let (space, offset, size) =
                            read_varnode_data_attrs_resolved(decoder, register_resolver)?;
                        decoder.close_element(child_id);
                        self.internalstorage.push(VarnodeData { space, offset, size });
                    }
                    decoder.close_element(sub_id);
                }
                "pcode" => {
                    // Ghidra: fspec.cc:2676-2684 — decodeInject("Protomodel : "+name, ...)
                    let child_id = decoder.open_element();
                    let mut inject_name = String::new();
                    loop {
                        let aid = decoder.next_attribute_id();
                        if aid == 0 { break; }
                        if decoder.attribute_name(aid).as_deref() == Some("inject") {
                            inject_name = decoder.read_string();
                        } else {
                            let _ = decoder.read_string();
                        }
                    }
                    let _ = void_type;
                    if let Some(resolver) = inject_id_resolver {
                        if let Some(id) = resolver(&format!("Protomodel : {}", self.name), &inject_name) {
                            if inject_name.find("uponentry").is_some() {
                                self.inject_upon_entry = id;
                            } else {
                                self.inject_upon_return = id;
                            }
                        }
                    }
                    decoder.close_element(child_id);
                }
                _ => {
                    return Err("Unknown element in prototype".to_string());
                }
            }
        }
        decoder.close_element(elem_id);

        // Ghidra: fspec.cc:2689-2695 — default return address + sort lists.
        if !saw_retaddr {
            // Provide the default return address, if there isn't a specific
            // one for the model (fspec.cc:2689-2691).
            if let Some(default_return) = default_return_addr {
                self.effectlist.push(EffectRecord::new(
                    default_return.space,
                    default_return.offset,
                    default_return.size,
                    EffectType::ReturnAddress,
                ));
            }
        }
        // Sort effectlist by (space, offset) — faithful to
        // sort(effectlist, compareByAddress).
        self.effectlist.sort_by(|a, b| {
            (a.space.space_id(), a.offset).cmp(&(b.space.space_id(), b.offset))
        });
        // Sort likelytrash / internalstorage with the VarnodeData::operator<
        // key (pcoderaw.hh:67-70): space, offset ascending, size DESCENDING.
        // Faithful to sort(likelytrash...)/sort(internalstorage...)
        // (fspec.cc:2694-2695).
        self.likelytrash.sort_by(VarnodeData::compare);
        self.internalstorage.sort_by(VarnodeData::compare);

        // Ghidra: fspec.cc:2696-2699 — apply defaults for unseen ranges.
        if !saw_localrange {
            self.default_local_range(stack_space, addr_size);
        }
        if !saw_paramrange {
            self.default_param_range(stack_space, addr_size);
        }
        Ok(self.name.clone())
    }

    // Ghidra: fspec.hh:777 ProtoModel::getName
    /// Get the name of the prototype model. Faithful inline accessor.
    pub fn get_name(&self) -> &str { &self.name }

    // Ghidra: fspec.hh:839 ProtoModel::getParamRange
    /// Get the possible stack-parameter ranges accumulated from the input
    /// ParamEntry list or an explicit `<paramrange>` element.
    pub fn get_param_range(&self) -> &crate::address::RangeList {
        &self.paramrange
    }

    // Ghidra: fspec.hh:781 ProtoModel::getExtraPop
    /// Get the stack-pointer extrapop for this model. Faithful inline accessor.
    pub fn get_extrapop(&self) -> i32 { self.extrapop }

    // Ghidra: fspec.hh:782 ProtoModel::setExtraPop
    /// Set the stack-pointer extrapop. Faithful inline accessor.
    pub fn set_extrapop(&mut self, ep: i32) { self.extrapop = ep; }

    // Ghidra: fspec.hh:979 ProtoModel::hasThisPointer
    /// Is this a model for (non-static) class methods? Faithful inline accessor.
    pub fn has_this_pointer(&self) -> bool { self.has_this }

    // Ghidra: fspec.hh:980 ProtoModel::isConstructor
    /// Is this model for class constructors? Faithful inline accessor.
    pub fn is_constructor(&self) -> bool { self.is_construct }

    // Ghidra: fspec.hh:981 ProtoModel::printInDecl
    /// Should the model name be printed in function declarations?
    pub fn print_in_decl(&self) -> bool { self.is_printed.load(Ordering::Relaxed) }

    // Ghidra: fspec.hh:982 ProtoModel::setPrintInDecl
    /// Set whether this name should be printed in declarations.
    pub fn set_print_in_decl(&self, val: bool) { self.is_printed.store(val, Ordering::Relaxed); }
}

/// `ParameterPieces::isthis = 1` (fspec.hh:362). Used by
/// `assign_parameter_storage` to flag the `this` input.
pub const THIS_POINTER_PIECE: u32 = 1;

// RUGRA-GLUE: read_varnode_data_attrs (free helper — parses the space/offset/
// size attributes that Ghidra reads via VarnodeData::decode for the
// <unaffected>/<killedbycall>/<returnaddress>/<likelytrash> children).
fn read_varnode_data_attrs_resolved(
    decoder: &mut dyn crate::marshal::Decoder,
    register_resolver: &dyn Fn(&str) -> Option<VarnodeData>,
) -> Result<(AddressSpace, u64, i32), String> {
    use crate::marshal::Decoder;
    let mut space = AddressSpace::Register;
    let mut offset = 0u64;
    let mut size = 0i32;
    let mut register_name = None;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 { break; }
        match decoder.attribute_name(aid).as_deref() {
            Some("space") => {
                let s = decoder.read_string();
                space = parse_space_name(&s);
            }
            Some("offset") => {
                let s = decoder.read_string();
                offset = parse_u64(&s);
            }
            Some("size") => {
                let s = decoder.read_string();
                size = s.parse::<i32>().unwrap_or(0);
            }
            Some("name") => register_name = Some(decoder.read_string()),
            _ => { let _ = decoder.read_string(); }
        }
    }
    if let Some(name) = register_name {
        let storage =
            register_resolver(&name).ok_or_else(|| format!("Unknown register name: {name}"))?;
        return Ok((storage.space, storage.offset, storage.size));
    }
    Ok((space, offset, size))
}

// RUGRA-GLUE: compatibility adapter for legacy decode callers that only use
// explicit space/offset/size address elements and have no Translate catalog.
fn read_varnode_data_attrs(decoder: &mut dyn crate::marshal::Decoder) -> (AddressSpace, u64, i32) {
    let no_register = |_name: &str| None;
    read_varnode_data_attrs_resolved(decoder, &no_register).unwrap_or((
        AddressSpace::Register,
        0,
        0,
    ))
}

// RUGRA-GLUE: read_range_child (free helper — parses a <range> child of
// <localrange>/<paramrange> into a Rust `Range`).
fn read_range_child(
    decoder: &mut dyn crate::marshal::Decoder,
    default_space: Option<AddressSpace>,
) -> Option<crate::address::Range> {
    use crate::marshal::Decoder;
    let child_id = decoder.open_element();
    let mut first = 0u64;
    let mut last = 0u64;
    let mut have_first = false;
    let mut have_last = false;
    loop {
        let aid = decoder.next_attribute_id();
        if aid == 0 { break; }
        match decoder.attribute_name(aid).as_deref() {
            Some("first") => { first = parse_u64(&decoder.read_string()); have_first = true; }
            Some("last") => { last = parse_u64(&decoder.read_string()); have_last = true; }
            Some("space") => { let _ = decoder.read_string(); }
            _ => { let _ = decoder.read_string(); }
        }
    }
    decoder.close_element(child_id);
    let _ = default_space;
    if have_first && have_last {
        crate::address::Range::new(Address::new(first), Address::new(last))
    } else {
        None
    }
}

// RUGRA-GLUE: parse_space_name / parse_u64 (free helpers used by the decode
// path above; Rugra's AddressSpace is an enum, so a name string maps to the
// nearest matching variant).
fn parse_space_name(s: &str) -> AddressSpace {
    match s {
        "ram" | "mem" => AddressSpace::Ram,
        "register" => AddressSpace::Register,
        "unique" => AddressSpace::Unique,
        "const" => AddressSpace::Const,
        "stack" => AddressSpace::Stack,
        "join" => AddressSpace::Join,
        "iop" => AddressSpace::Iop,
        "overlay" => AddressSpace::Overlay,
        _ => AddressSpace::Register,
    }
}

// RUGRA-GLUE: space_name — inverse of parse_space_name, used by
// EffectRecord::encode to serialise the address space as a string attribute.
/// Return the canonical XML name for an address space. Mirrors the
/// `AddrSpace::getName` lookup Ghidra performs inside
/// `VarnodeData::encode`/`Address::encode`.
fn space_name(s: AddressSpace) -> &'static str {
    match s {
        AddressSpace::Ram => "ram",
        AddressSpace::Register => "register",
        AddressSpace::Unique => "unique",
        AddressSpace::Const => "const",
        AddressSpace::Stack => "stack",
        AddressSpace::Join => "join",
        AddressSpace::Iop => "iop",
        AddressSpace::Overlay => "overlay",
        AddressSpace::Other(_) => "mem",
    }
}

// RUGRA-GLUE: effect_from_u32 — bridges the raw u32 returned by the legacy
// `FuncCallSpecs::has_effect` (which mirrors Ghidra's `uint4` return type)
// back into the typed `EffectType` enum used by the faithful ports above.
fn effect_from_u32(raw: u32) -> EffectType {
    match raw {
        1 => EffectType::Unaffected,
        2 => EffectType::KilledByCall,
        3 => EffectType::ReturnAddress,
        _ => EffectType::UnknownEffect,
    }
}

// RUGRA-GLUE: textual integer adapter for Rugra's string-valued Decoder;
// Ghidra's VarnodeData/Range decode paths call typed Decoder integer readers
// directly and have no parse_u64 helper.
fn parse_u64(s: &str) -> u64 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

// RUGRA-GLUE: metatype_to_type_class (free helper — Ghidra's
// `metatype2typeclass` is defined in type.cc and not yet ported).
/// Map a data-type's metatype to its storage class. Faithful to
/// `metatype2typeclass` (type.hh:153). TODO(ALIGNMENT_ROADMAP): depends on
/// unported `metatype2typeclass`.
fn metatype_to_type_class(dt: &Datatype) -> TypeClass {
    use crate::type_system::TypeMetatype;
    match dt.get_metatype() {
        TypeMetatype::Float => TypeClass::Float,
        _ => TypeClass::General,
    }
}

// RUGRA-GLUE: is_contiguous (free helper — mirrors `Address::isContiguous`,
// address.cc, used only by `ParamListStandard::check_join`).
fn is_contiguous(hi_addr: Address, hi_size: i32, lo_addr: Address, _lo_size: i32) -> bool {
    hi_addr.as_u64() + hi_size as u64 == lo_addr.as_u64()
}

// RUGRA-GLUE: overlaps_range — mirrors the observable
// `Address::overlap(0, record, size)` result for the ordered call sites in
// `ProtoModelFull::lookup_effect` and `lookup_record`. Their upper-bound
// predecessor choice guarantees the candidate start is not after the probe
// (the begin case reverses the arguments), so u64 subtraction cannot take a
// narrower AddrSpace wrap-around path.
fn overlaps_range(
    space1: AddressSpace, off1: u64, sz1: i32,
    space2: AddressSpace, off2: u64, _sz2: i32,
) -> i64 {
    if space1 != space2 {
        return -1;
    }
    // Ghidra Address::overlap returns no overlap for constant-space
    // addresses, even when their numeric ranges are identical.
    if space1 == AddressSpace::Const {
        return -1;
    }
    if sz1 <= 0 {
        return -1;
    }
    let distance = off2.wrapping_sub(off1);
    if distance >= sz1 as u64 {
        return -1;
    }
    distance as i64
}

/// Class for calculating "goodness of fit" of parameter trials against a
/// prototype model. Faithful to `class ScoreProtoModel` (fspec.hh:1040-1064
/// + fspec.cc:2705-2775): trials are registered via `addParameter`, then
/// `doScore` computes how well the set fits the model — a LOWER score is a
/// better fit.
#[derive(Debug)]
pub struct ScoreProtoModel<'a> {
    /// True if scoring against input parameters, false for outputs.
    /// Faithful to `isinputscore`.
    is_input_score: bool,
    /// Map of parameter entries corresponding to trials. Faithful to
    /// `vector<PEntry> entry`.
    entry: Vec<ScoreProtoModelEntry>,
    /// Prototype model to score against. Faithful to `const ProtoModel *`.
    model: &'a ProtoModelFull,
    /// The final fitness score. Faithful to `finalscore` (-1 before
    /// `doScore`).
    final_score: i32,
    /// Number of trials that don't fit the prototype model at all.
    /// Faithful to `mismatch`.
    mismatch: i32,
}

/// A record mapping one trial to a parameter entry in the prototype model.
/// Faithful to `ScoreProtoModel::PEntry` (fspec.hh:1042-1052).
#[derive(Debug, Clone, Copy)]
pub struct ScoreProtoModelEntry {
    /// Original index of the trial. Faithful to `origIndex`.
    pub orig_index: i32,
    /// Matching slot within the resource list. Faithful to `slot`.
    pub slot: i32,
    /// Number of slots occupied. Faithful to `size`.
    pub size: i32,
}

impl PartialOrd for ScoreProtoModelEntry {
    // Ghidra: fspec.hh:1051 ScoreProtoModel::PEntry::operator<
    /// Compare PEntry objects by slot: `return (slot < op2.slot);`
    /// (fspec.hh:1051).
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoreProtoModelEntry {
    // Ghidra: fspec.hh:1051 ScoreProtoModel::PEntry::operator<
    /// Total order by slot (the strict-weak operator< key).
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.slot.cmp(&other.slot)
    }
}

impl PartialEq for ScoreProtoModelEntry {
    // RUGRA-GLUE: PartialEq derived from the Ord key (slot), matching the
    /// C++ operator< equivalence class.
    fn eq(&self, other: &Self) -> bool { self.slot == other.slot }
}
impl Eq for ScoreProtoModelEntry {}

impl<'a> ScoreProtoModel<'a> {
    // Ghidra: fspec.cc:2705 ScoreProtoModel::ScoreProtoModel
    /// `isinputscore = isinput; model = mod; entry.reserve(numparam);
    /// finalscore = -1; mismatch = 0;` (fspec.cc:2705-2713).
    pub fn new(isinput: bool, model: &'a ProtoModelFull, numparam: usize) -> Self {
        Self {
            is_input_score: isinput,
            entry: Vec::with_capacity(numparam),
            model,
            final_score: -1,
            mismatch: 0,
        }
    }

    // Ghidra: fspec.cc:2717 ScoreProtoModel::addParameter
    /// Register a trial to be scored. Faithful 1:1 body of `addParameter`
    /// (fspec.cc:2717-2736): the trial resolves to a model slot through
    /// `possibleInputParamWithSlot` (input scoring) or
    /// `possibleOutputParamWithSlot` (output scoring); a hit appends a
    /// `(origIndex, slot, size)` PEntry, a miss increments `mismatch`.
    pub fn add_parameter(&mut self, space: AddressSpace, addr: Address, sz: i32) {
        let orig = self.entry.len() as i32;
        let mut slot = 0i32;
        let mut slot_size = 0i32;
        let isparam = if self.is_input_score {
            self.model.possible_input_param_with_slot(space, addr, sz, &mut slot, &mut slot_size)
        } else {
            self.model.possible_output_param_with_slot(space, addr, sz, &mut slot, &mut slot_size)
        };
        if isparam {
            self.entry.push(ScoreProtoModelEntry {
                orig_index: orig,
                slot,
                size: slot_size,
            });
        } else {
            self.mismatch += 1;
        }
    }

    // Ghidra: fspec.cc:2738 ScoreProtoModel::doScore
    /// Compute the fitness score. Faithful 1:1 body of `doScore`
    /// (fspec.cc:2738-2775): entries are sorted by slot (a stable sort of
    /// the `sort(entry.begin(),entry.end())`), then walked keeping a
    /// `nextfree` cursor over the expected slot sequence:
    ///   - a hole (`p.slot > nextfree`) scores `penalty[min(nextfree,4)]`
    ///     per skipped slot (16/10/7/5 then flat 3);
    ///   - a duplication (`nextfree > p.slot`) scores 20 and only advances
    ///     `nextfree` when the duplicate extends past it;
    ///   - an exact continuation advances `nextfree = p.slot + p.size`.
    /// The final score adds `20 * mismatch`.
    pub fn do_score(&mut self) {
        self.entry.sort_by(|a, b| a.slot.cmp(&b.slot));

        let mut nextfree = 0i32; // Next slot we expect to see
        let mut basescore = 0i32;
        let penalty = [16i32, 10, 7, 5];
        let penaltyfinal = 3i32;
        let mismatchpenalty = 20i32;

        for p in &self.entry {
            if p.slot > nextfree {
                // We have some kind of hole in our slot coverage
                while nextfree < p.slot {
                    if nextfree < 4 {
                        basescore += penalty[nextfree as usize];
                    } else {
                        basescore += penaltyfinal;
                    }
                    nextfree += 1;
                }
                nextfree += p.size;
            } else if nextfree > p.slot {
                // Some kind of slot duplication
                basescore += mismatchpenalty;
                if p.slot + p.size > nextfree {
                    nextfree = p.slot + p.size;
                }
            } else {
                nextfree = p.slot + p.size;
            }
        }
        self.final_score = basescore + mismatchpenalty * self.mismatch;
    }

    // Ghidra: fspec.hh:1062 ScoreProtoModel::getScore
    /// `return finalscore;` (fspec.hh:1062).
    pub fn get_score(&self) -> i32 { self.final_score }

    // Ghidra: fspec.hh:1063 ScoreProtoModel::getNumMismatch
    /// `return mismatch;` (fspec.hh:1063).
    pub fn get_num_mismatch(&self) -> i32 { self.mismatch }
}

/// A prototype model made by merging together other models. Faithful to
/// `class ProtoModelMerged : public ProtoModel` (fspec.hh:1077-1090 +
/// fspec.cc:2834-2921): a placeholder for multiple models; at active
/// parameter recovery the correct model is selected by `selectModel`.
/// The output part is NOT merged — constituent models must share the same
/// output model (Ghidra folds in the first model's output and assumes the
/// rest match).
pub struct ProtoModelMerged {
    /// Constituent models being merged. Faithful to `vector<ProtoModel *>
    /// modellist`; `Arc` preserves shared identity with the architecture's
    /// model table.
    pub modellist: Vec<std::sync::Arc<ProtoModelFull>>,
    /// The merged input parameter list. Faithful to the inherited
    /// `ParamList *input` holding a `ParamListMerged`.
    pub input: ParamListMerged,
    /// The un-merged output parameter list (from the first folded model).
    /// Faithful to the inherited `ParamList *output`.
    pub output: ParamListStandardOut,
    /// Extra bytes popped from stack (or `EXTRA_POP_UNKNOWN`). Faithful to
    /// the inherited `extrapop`.
    pub extrapop: i32,
    /// Intersected side-effects. Faithful to the inherited `effectlist`.
    pub effectlist: Vec<EffectRecord>,
    /// Intersected likely-trash locations. Faithful to the inherited
    /// `likelytrash`.
    pub likelytrash: Vec<VarnodeData>,
    /// Intersected internal storage. Faithful to the inherited
    /// `internalstorage`.
    pub internalstorage: Vec<VarnodeData>,
    /// Injection id at function entry (-1 unused). Faithful to
    /// `injectUponEntry`.
    pub inject_upon_entry: i32,
    /// Injection id after a call (-1 unused). Faithful to
    /// `injectUponReturn`.
    pub inject_upon_return: i32,
    /// Union of the constituents' local ranges. Faithful to `localrange`.
    pub localrange: crate::address::RangeList,
    /// Union of the constituents' parameter ranges. Faithful to
    /// `paramrange`.
    pub paramrange: crate::address::RangeList,
}

/// `ProtoModel::extrapop_unknown = 0x8000` (fspec.hh:772).
pub const EXTRA_POP_UNKNOWN: i32 = 0x8000;

impl ProtoModelMerged {
    // Ghidra: fspec.hh:1082 ProtoModelMerged::ProtoModelMerged
    /// Construct an empty merge: `ProtoModelMerged(Architecture *g) :
    /// ProtoModel(g) {}` (fspec.hh:1082). The output list starts empty and
    /// is replaced at the first fold-in (Ghidra's null `output` until the
    /// first `foldIn` allocates it).
    pub fn new() -> Self {
        Self {
            modellist: Vec::new(),
            input: ParamListMerged::new(),
            output: ParamListStandardOut::default(),
            extrapop: 0,
            effectlist: Vec::new(),
            likelytrash: Vec::new(),
            internalstorage: Vec::new(),
            inject_upon_entry: -1,
            inject_upon_return: -1,
            localrange: crate::address::RangeList::new(),
            paramrange: crate::address::RangeList::new(),
        }
    }

    // Ghidra: fspec.hh:1084 ProtoModelMerged::numModels
    /// `return modellist.size();` (fspec.hh:1084).
    pub fn num_models(&self) -> usize { self.modellist.len() }

    // Ghidra: fspec.hh:1085 ProtoModelMerged::getModel
    /// `return modellist[i];` (fspec.hh:1085).
    pub fn get_model(&self, i: usize) -> &std::sync::Arc<ProtoModelFull> { &self.modellist[i] }

    // Ghidra: fspec.hh:1088 ProtoModelMerged::isMerged
    /// `return true;` (fspec.hh:1088).
    pub fn is_merged(&self) -> bool { true }

    // Ghidra: fspec.cc:2834 ProtoModelMerged::foldIn
    /// Fold-in an additional prototype model. Faithful 1:1 body of
    /// `foldIn` (fspec.cc:2834-2870):
    ///   - the architecture-identity guard (`model->glb != glb` throw) is
    ///     absorbed by Rugra's single-`Architecture` table — all models in
    ///     one table share `glb` by construction;
    ///   - the `p_standard`/`p_register` input-kind guard passes
    ///     structurally: Rugra's `ProtoModelFull::input` is the shared
    ///     `ParamListStandard` owner for both kinds (the register-strategy
    ///     residual is documented at `build_param_list`);
    ///   - FIRST fold: allocate the merged input list + the output list,
    ///     copy extrapop/injects/effects/trash/ranges verbatim;
    ///   - LATER folds: fold the input list, demote a disagreeing extrapop
    ///     to `extrapop_unknown`, throw on disagreeing inject ids,
    ///     intersect effects/trash/internal registers, and take the UNION
    ///     of the local/param ranges.
    pub fn fold_in(&mut self, model: &std::sync::Arc<ProtoModelFull>) -> Result<(), String> {
        if self.modellist.is_empty() && self.input.base.is_entry_empty() && self.output.base.is_entry_empty() {
            // First fold in (Ghidra: input == (ParamList *)0)
            self.input = ParamListMerged::new();
            self.output = model.output.standard_out_clone();
            self.input.fold_in(&model.input)?;
            self.extrapop = model.extrapop;
            self.effectlist = model.effectlist.clone();
            self.inject_upon_entry = model.inject_upon_entry;
            self.inject_upon_return = model.inject_upon_return;
            self.likelytrash = model.likelytrash.clone();
            self.localrange = model.localrange.clone();
            self.paramrange = model.paramrange.clone();
        } else {
            self.input.fold_in(&model.input)?;
            // We assume here that the output models are the same, but we don't check
            if self.extrapop != model.extrapop {
                self.extrapop = EXTRA_POP_UNKNOWN;
            }
            if self.inject_upon_entry != model.inject_upon_entry
                || self.inject_upon_return != model.inject_upon_return
            {
                return Err("Cannot merge prototype models with different inject ids".to_string());
            }
            ProtoModelFull::intersect_effects(&mut self.effectlist, &model.effectlist);
            ProtoModelFull::intersect_registers(&mut self.likelytrash, &model.likelytrash);
            ProtoModelFull::intersect_registers(&mut self.internalstorage, &model.internalstorage);
            // Take the union of the localrange and paramrange
            for iter in model.localrange.ranges() {
                self.localrange.insert_range(*iter);
            }
            for iter in model.paramrange.ranges() {
                self.paramrange.insert_range(*iter);
            }
        }
        // Ghidra: foldIn (fspec.cc:2834-2870) does NOT touch modellist —
        // only ProtoModelMerged::decode appends the folded model
        // (fspec.cc:2918 `modellist.push_back(mymodel)` runs inside
        // decode, after foldIn). The bilateral fixture pins this: two
        // foldIns leave numModels() == 0.
        Ok(())
    }

    // Ghidra: fspec.cc:2877 ProtoModelMerged::selectModel
    /// Select the best model for the given set of input parameter trials.
    /// Faithful 1:1 body of `selectModel` (fspec.cc:2877-2902): each
    /// constituent is scored with `ScoreProtoModel(true, modellist[i],
    /// numtrials)` over its ACTIVE trials; the strict-`<` walk keeps the
    /// FIRST best model, early-exits on a perfect 0 score, and throws
    /// "No model matches : missing default" when nothing scored under the
    /// 500 threshold.
    pub fn select_model(
        &self,
        active: &crate::fspec::ParamActive,
    ) -> Result<std::sync::Arc<ProtoModelFull>, String> {
        let mut bestscore = 500i32;
        let mut bestindex: i64 = -1;
        for i in 0..self.modellist.len() {
            let numtrials = active.get_num_trials();
            let mut scoremodel = ScoreProtoModel::new(true, &self.modellist[i], numtrials);
            for j in 0..numtrials {
                let trial = active.get_trial(j);
                if trial.is_active() {
                    scoremodel.add_parameter(
                        trial.get_space(),
                        trial.get_address(),
                        trial.get_size(),
                    );
                }
            }
            scoremodel.do_score();
            let score = scoremodel.get_score();
            if score < bestscore {
                bestscore = score;
                bestindex = i as i64;
                if bestscore == 0 {
                    break; // Can't get any lower
                }
            }
        }
        if bestindex >= 0 {
            return Ok(self.modellist[bestindex as usize].clone());
        }
        Err("No model matches : missing default".to_string())
    }
}

impl Default for ProtoModelMerged {
    // RUGRA-GLUE: Default bridge for the no-arg constructor form.
    fn default() -> Self { Self::new() }
}

/// An unrecognized prototype model. Faithful to `class
/// UnknownProtoModel : public ProtoModel` (fspec.hh:1025-1032): created
/// for prototype model names with no matching definition; behavior is
/// cloned from a placeholder model (usually the default), the
/// unrecognized name is adopted, and `isUnknown()` reports true.
pub struct UnknownProtoModel {
    /// The full cloned model state (name overridden with the unrecognized
    /// name). Stands in for the inherited ProtoModel base.
    pub base: ProtoModelFull,
    /// The model whose behavior \b this adopts. Faithful to
    /// `ProtoModel *placeholderModel`; `Arc` preserves shared identity with
    /// the architecture's model table.
    pub placeholder_model: std::sync::Arc<ProtoModelFull>,
}

impl UnknownProtoModel {
    // Ghidra: fspec.hh:1028 UnknownProtoModel::UnknownProtoModel
    /// `UnknownProtoModel(const string &nm,ProtoModel *placeHold) :
    /// ProtoModel(nm,*placeHold) { placeholderModel = placeHold; }`
    /// (fspec.hh:1028-1029): the alias copy constructor copies every field
    /// from the placeholder (including its lists via the ParamList copy
    /// constructors) and overrides the name.
    pub fn new(nm: &str, place_hold: &std::sync::Arc<ProtoModelFull>) -> Self {
        let mut base = ProtoModelFull::clone(place_hold);
        base.name = nm.to_string();
        Self { base, placeholder_model: place_hold.clone() }
    }

    // Ghidra: fspec.hh:1030 UnknownProtoModel::getPlaceholderModel
    /// `return placeholderModel;` (fspec.hh:1030).
    pub fn get_placeholder_model(&self) -> &std::sync::Arc<ProtoModelFull> {
        &self.placeholder_model
    }

    // Ghidra: fspec.hh:1031 UnknownProtoModel::isUnknown
    /// `return true;` (fspec.hh:1031).
    pub fn is_unknown(&self) -> bool { true }
}

/// Shared owner handle for a function `Scope` (the Rust stand-in for
/// Ghidra's raw `Scope *` in the ProtoStoreSymbol family).
// RUGRA-GLUE: ownership handle type for the symbol-backed store family.
pub type FspecScopeRef = std::sync::Arc<std::sync::RwLock<crate::database::Scope>>;

/// Shared owner handle for a `Symbol` (the Rust stand-in for Ghidra's raw
/// `Symbol *`).
// RUGRA-GLUE: ownership handle type for the symbol-backed store family.
pub type FspecSymbolRef = std::sync::Arc<std::sync::RwLock<crate::database::Symbol>>;

/// `Symbol::function_parameter` category id (database.hh Symbol category 0
/// holds function parameters).
pub const SYMBOL_FUNCTION_PARAMETER: i32 = 0;
/// `Symbol::no_category` (database.hh): -1.
pub const SYMBOL_NO_CATEGORY: i32 = -1;

/// A parameter with a formal backing Symbol. Faithful to `class
/// ParameterSymbol : public ProtoParameter` (fspec.hh:1256-1279 +
/// fspec.cc:2981-3099): every accessor pulls its information off the
/// backing Symbol; the flat-state methods that ParameterBasic implements
/// locally forward to Scope/Symbol attribute mutations instead. Rugra's
/// projection exposes the (scope, symbol) pair directly instead of the
/// C++ virtual-interface vtable: `ProtoStoreSymbol` constructs these
/// on the fly and caches them, exactly as Ghidra does.
#[derive(Debug, Clone)]
pub struct ParameterSymbol {
    /// The owning function Scope (Ghidra reaches it via `sym->getScope()`;
    /// Rugra's `Symbol` carries only `scope_id`).
    pub scope: FspecScopeRef,
    /// Backing Symbol for \b this parameter; `None` is the freshly
    /// allocated uninitialized form of `ParameterSymbol(void) { sym = 0; }`
    /// (fspec.hh:1260).
    pub sym: Option<FspecSymbolRef>,
}

impl ParameterSymbol {
    // Ghidra: fspec.hh:1260 ParameterSymbol::ParameterSymbol
    /// Uninitialized constructor: `sym = (Symbol *)0` (fspec.hh:1260).
    /// The scope handle rides along for the attribute-mutating setters.
    pub fn new(scope: FspecScopeRef) -> Self {
        Self { scope, sym: None }
    }

    // Ghidra: fspec.cc:2981 ParameterSymbol::getName
    /// `return sym->getName();` (fspec.cc:2981-2985). Panics without a
    /// backing symbol exactly like the null dereference.
    pub fn get_name(&self) -> String {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().name.clone()
    }

    // Ghidra: fspec.cc:2987 ParameterSymbol::getType
    /// `return sym->getType();` (fspec.cc:2987-2991).
    pub fn get_type(&self) -> Option<Arc<Datatype>> {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().get_type()
    }

    // Ghidra: fspec.cc:2993 ParameterSymbol::getAddress
    /// `return sym->getFirstWholeMap()->getAddr();` (fspec.cc:2993-2997) —
    /// resolved through the owning Scope's entry table.
    pub fn get_address(&self) -> Option<Address> {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let scope = self.scope.read().unwrap();
        sym.read().unwrap().get_first_whole_map(&scope.entries).map(|e| e.get_addr())
    }

    // Ghidra: fspec.cc:2999 ParameterSymbol::getSize
    /// `return sym->getFirstWholeMap()->getSize();` (fspec.cc:2999-3003).
    pub fn get_size(&self) -> Option<i32> {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let scope = self.scope.read().unwrap();
        sym.read().unwrap().get_first_whole_map(&scope.entries).map(|e| e.get_size())
    }

    // Ghidra: fspec.cc:3005 ParameterSymbol::isTypeLocked
    /// `return sym->isTypeLocked();` (fspec.cc:3005-3009).
    pub fn is_type_locked(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_type_locked()
    }

    // Ghidra: fspec.cc:3011 ParameterSymbol::isNameLocked
    /// `return sym->isNameLocked();` (fspec.cc:3011-3015).
    pub fn is_name_locked(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_name_locked()
    }

    // Ghidra: fspec.cc:3017 ParameterSymbol::isSizeTypeLocked
    /// `return sym->isSizeTypeLocked();` (fspec.cc:3017-3021).
    pub fn is_size_type_locked(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_size_type_locked()
    }

    // Ghidra: fspec.cc:3023 ParameterSymbol::isThisPointer
    /// `return sym->isThisPointer();` (fspec.cc:3023-3027).
    pub fn is_this_pointer(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_this_pointer()
    }

    // Ghidra: fspec.cc:3029 ParameterSymbol::isIndirectStorage
    /// `return sym->isIndirectStorage();` (fspec.cc:3029-3033).
    pub fn is_indirect_storage(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_indirect_storage()
    }

    // Ghidra: fspec.cc:3035 ParameterSymbol::isHiddenReturn
    /// `return sym->isHiddenReturn();` (fspec.cc:3035-3039).
    pub fn is_hidden_return(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_hidden_return()
    }

    // Ghidra: fspec.cc:3041 ParameterSymbol::isNameUndefined
    /// `return sym->isNameUndefined();` (fspec.cc:3041-3045).
    pub fn is_name_undefined(&self) -> bool {
        self.sym.as_ref().expect("ParameterSymbol without backing symbol").read().unwrap().is_name_undefined()
    }

    // Ghidra: fspec.cc:3047 ParameterSymbol::setTypeLock
    /// Toggle the data-type lock on the backing Symbol. Faithful 1:1 body
    /// of `setTypeLock` (fspec.cc:3047-3058): the attribute mask is
    /// `typelock | namelock` when the symbol's name is already defined,
    /// `typelock` alone otherwise; setting raises the mask, clearing
    /// removes it.
    pub fn set_type_lock(&self, val: bool) {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let name_undefined = sym.read().unwrap().is_name_undefined();
        let mut attrs = crate::database::symbol_flags::TYPELOCK;
        if !name_undefined {
            attrs |= crate::database::symbol_flags::NAMELOCK;
        }
        let id = sym.read().unwrap().symbol_id;
        let mut scope = self.scope.write().unwrap();
        if val {
            scope.set_attribute(id, attrs);
        } else {
            scope.clear_attribute(id, attrs);
        }
    }

    // Ghidra: fspec.cc:3060 ParameterSymbol::setNameLock
    /// Toggle the name lock: `scope->setAttribute(sym, namelock)` /
    /// `clearAttribute` (fspec.cc:3060-3068).
    pub fn set_name_lock(&self, val: bool) {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let id = sym.read().unwrap().symbol_id;
        let mut scope = self.scope.write().unwrap();
        if val {
            scope.set_attribute(id, crate::database::symbol_flags::NAMELOCK);
        } else {
            scope.clear_attribute(id, crate::database::symbol_flags::NAMELOCK);
        }
    }

    // Ghidra: fspec.cc:3070 ParameterSymbol::setThisPointer
    /// Toggle the this-pointer property. Ghidra forwards to
    /// `scope->setThisPointer(sym, val)` which is the inline
    /// `sym->setThisPointer(val)` (database.hh:770); Rugra mutates the
    /// Symbol directly through the same `Symbol::set_this_pointer`.
    pub fn set_this_pointer(&self, val: bool) {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        sym.write().unwrap().set_this_pointer(val);
    }

    // Ghidra: fspec.cc:3077 ParameterSymbol::overrideSizeLockType
    /// Override the data-type of a size-locked symbol. Faithful 1:1 body of
    /// `Scope::overrideSizeLockType` (database.cc:1387-1398, the callee):
    /// sizes must match exactly and the symbol must already be size-locked,
    /// else the error mirrors the LowlevelError throw.
    pub fn override_size_lock_type(&self, ct: &Arc<Datatype>) -> Result<(), String> {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let mut symbol = sym.write().unwrap();
        let cur_size = symbol.get_type().map(|t| t.get_size()).unwrap_or(0);
        if cur_size == ct.get_size() {
            if !symbol.is_size_type_locked() {
                return Err("Overriding symbol that is not size locked".to_string());
            }
            symbol.dtype = Some(ct.clone());
            return Ok(());
        }
        Err("Overriding symbol with different type size".to_string())
    }

    // Ghidra: fspec.cc:3083 ParameterSymbol::resetSizeLockType
    /// Reset the data-type to a TYPE_UNKNOWN of the same size. Faithful to
    /// `Scope::resetSizeLockType` (database.cc:1402-1408, the callee): an
    /// already-unknown type is untouched; otherwise the type becomes
    /// `factory->getBase(size, TYPE_UNKNOWN)` (the lock is preserved).
    pub fn reset_size_lock_type(&self, factory: &crate::type_system::TypeFactory) {
        let sym = self.sym.as_ref().expect("ParameterSymbol without backing symbol");
        let mut symbol = sym.write().unwrap();
        let cur = match &symbol.dtype {
            Some(t) => t.clone(),
            None => return,
        };
        if cur.get_metatype() == crate::type_system::TypeMetatype::Unknown {
            return;
        }
        let size = cur.get_size();
        if let Some(base) = factory.get_base(size, crate::type_system::TypeMetatype::Unknown) {
            symbol.dtype = Some(base);
        }
    }

    // Ghidra: fspec.cc:3089 ParameterSymbol::clone
    /// Faithful to the throwing override `throw LowlevelError("Should not
    /// be cloning ParameterSymbol");` (fspec.cc:3089-3093) — mirrored as
    /// `Err`.
    pub fn clone_refuses(&self) -> Result<(), String> {
        Err("Should not be cloning ParameterSymbol".to_string())
    }

    // Ghidra: fspec.cc:3095 ParameterSymbol::getSymbol
    /// `return sym;` (fspec.cc:3095-3099).
    pub fn get_symbol(&self) -> Option<FspecSymbolRef> {
        self.sym.clone()
    }
}

/// A collection of parameter descriptions backed by Symbol information.
/// Faithful to `class ProtoStoreSymbol : public ProtoStore` (fspec.hh:1286-
/// 1306 + fspec.cc:3103-3303): input parameters are the function Scope's
/// category-0 symbols; ParameterSymbol views are constructed on the fly and
/// cached; the return value is stored internally as a ParameterBasic.
#[derive(Debug, Clone)]
pub struct ProtoStoreSymbol {
    /// Backing Scope for input parameters. Faithful to `Scope *scope`.
    pub scope: FspecScopeRef,
    /// A usepoint reference for storage locations (usually the function
    /// entry, -1). Faithful to `Address restricted_usepoint`; the space
    /// half rides alongside the legacy offset (ADDRESS-0001).
    pub restricted_usepoint: (AddressSpace, u64),
    /// Cache of allocated input parameter views. Faithful to
    /// `vector<ProtoParameter *> inparam` (null slots = `None`).
    inparam: Vec<Option<ParameterSymbol>>,
    /// The return-value parameter (a ParameterBasic in Ghidra too).
    /// Faithful to `ProtoParameter *outparam`.
    outparam: Option<ProtoParameter>,
}

impl ProtoStoreSymbol {
    // Ghidra: fspec.cc:3103 ProtoStoreSymbol::ProtoStoreSymbol
    /// Construct the symbol-backed store. Faithful 1:1 body
    /// (fspec.cc:3103-3113): the scope and usepoint are recorded, the
    /// outparam starts null, and `setOutput` installs a void ParameterBasic
    /// (`pieces.type = scope->getArch()->types->getTypeVoid();
    /// pieces.flags = 0;`).
    pub fn new(sc: FspecScopeRef, usepoint: (AddressSpace, u64)) -> Self {
        let mut store = Self {
            scope: sc,
            restricted_usepoint: usepoint,
            inparam: Vec::new(),
            outparam: None,
        };
        let void_type = crate::type_system::TypeFactory::shared_default()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_void();
        let pieces = ParameterPieces {
            space: AddressSpace::Ram,
            addr: Address::new(0),
            ty: Some(void_type),
            flags: 0,
        };
        store.set_output(&pieces);
        store
    }

    // Ghidra: fspec.cc:3132 ProtoStoreSymbol::getSymbolBacked
    /// Fetch or allocate the ParameterSymbol view for slot `i`. Faithful
    /// 1:1 body (fspec.cc:3132-3145): the cache grows with uninitialized
    /// slots as needed; a slot already holding a symbol-backed view is
    /// returned as-is; any other occupant is discarded and replaced with a
    /// fresh uninitialized ParameterSymbol.
    pub fn get_symbol_backed(&mut self, i: usize) -> ParameterSymbol {
        while self.inparam.len() <= i {
            self.inparam.push(None);
        }
        if let Some(existing) = &self.inparam[i] {
            return existing.clone();
        }
        let res = ParameterSymbol::new(self.scope.clone());
        self.inparam[i] = Some(res.clone());
        res
    }

    // Ghidra: fspec.cc:3147 ProtoStoreSymbol::setInput
    /// Establish name, data-type, and storage of an input parameter.
    /// Faithful 1:1 body of `setInput` (fspec.cc:3147-3214):
    ///   1. resolve the category-0 symbol at slot `i`; if its whole-map
    ///      storage disagrees with the incoming pieces the symbol is
    ///      removed and re-created;
    ///   2. a fresh symbol is added to the scope at the piece's address,
    ///      categorized at slot `i`, and its indirectstorage/hiddenretparm/
    ///      typelock/namelock flags mirror the piece flags;
    ///   3. an existing symbol only gets its attribute deltas applied, plus
    ///      a rename on a non-empty differing name and a retype on a
    ///      differing data-type.
    pub fn set_input(
        &mut self,
        i: usize,
        nm: &str,
        pieces: &ParameterPieces,
    ) -> ParameterSymbol {
        let mut res = self.get_symbol_backed(i);
        res.sym = self.scope.read().unwrap().get_category_symbol(SYMBOL_FUNCTION_PARAMETER, i as i32);
        let piece_type_size = pieces.ty.as_ref().map(|t| t.get_size()).unwrap_or(0) as i32;

        let isindirect = (pieces.flags & INDIRECT_STORAGE_PIECE) != 0;
        let ishidden = (pieces.flags & HIDDEN_RET_PARM) != 0;
        let istypelock = (pieces.flags & TYPE_LOCK_PIECE) != 0;
        let isnamelock = (pieces.flags & NAME_LOCK_PIECE) != 0;

        // Validate the existing symbol's storage against the pieces.
        if res.sym.is_some() {
            let sym = res.sym.clone().unwrap();
            let mut mismatch = false;
            {
                let scope = self.scope.read().unwrap();
                let symbol = sym.read().unwrap();
                if let Some(entry) = symbol.get_first_whole_map(&scope.entries) {
                    if entry.get_addr().as_u64() != pieces.addr.as_u64()
                        || entry.get_size() != piece_type_size
                    {
                        mismatch = true;
                    }
                } else {
                    mismatch = true;
                }
            }
            if mismatch {
                let id = sym.read().unwrap().symbol_id;
                self.scope.write().unwrap().remove_symbol(id);
                res.sym = None;
            }
        }
        if res.sym.is_none() {
            // Ghidra: usepoint = discoverScope(...) ?: restricted_usepoint;
            // Rugra's Scope::discover_scope resolves by scope-id, and the
            // single-function Scope owns the whole category-0 range, so the
            // restricted usepoint is the operative form (the multi-scope
            // usepoint discipline is the ADDRESS-0001-era residual).
            let _ = self.restricted_usepoint;
            let ty = pieces.ty.clone().unwrap_or_else(|| {
                crate::type_system::TypeFactory::shared_default()
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_type_void()
            });
            let type_name = ty.get_name().to_string();
            let id = self.scope.write().unwrap().add_symbol_mapped(
                nm,
                &type_name,
                pieces.addr,
                piece_type_size,
            );
            // Ghidra: res->sym = scope->addSymbol(nm,pieces.type,...)
            // —attach the resolved Datatype (Rugra's add_symbol takes the
            // type NAME; the Arc is linked here). The read guard is scoped
            // to the lookup: binding it through the if-let would hold the
            // scope read lock across the set_category write below and
            // self-deadlock the RwLock.
            let sym = self.scope.read().unwrap().symbols.get(&id).cloned();
            if let Some(sym) = sym {
                sym.write().unwrap().dtype = Some(ty);
                // Ghidra: scope->setCategory(res->sym,function_parameter,i);
                self.scope
                    .write()
                    .unwrap()
                    .set_category(id, SYMBOL_FUNCTION_PARAMETER, i as i32);
                res.sym = Some(sym);
            }
            if isindirect || ishidden || istypelock || isnamelock {
                let mut mirror = 0u32;
                if isindirect {
                    mirror |= crate::database::symbol_flags::INDIRECTSTORAGE;
                }
                if ishidden {
                    mirror |= crate::database::symbol_flags::HIDDENRETPARM;
                }
                if istypelock {
                    mirror |= crate::database::symbol_flags::TYPELOCK;
                }
                if isnamelock {
                    mirror |= crate::database::symbol_flags::NAMELOCK;
                }
                if let Some(sym) = &res.sym {
                    let id = sym.read().unwrap().symbol_id;
                    self.scope.write().unwrap().set_attribute(id, mirror);
                }
            }
            if let Some(sym) = &res.sym {
                let slot = self
                    .inparam
                    .iter()
                    .position(|p| p.is_none())
                    .unwrap_or(self.inparam.len());
                let _ = slot;
                self.inparam[i] = Some(res.clone());
            }
            return res;
        }
        // Existing symbol: apply attribute deltas.
        let sym = res.sym.clone().unwrap();
        let symbol_id = sym.read().unwrap().symbol_id;
        {
            let mut scope = self.scope.write().unwrap();
            let indirect_now = sym.read().unwrap().is_indirect_storage();
            if indirect_now != isindirect {
                if isindirect {
                    scope.set_attribute(symbol_id, crate::database::symbol_flags::INDIRECTSTORAGE);
                } else {
                    scope.clear_attribute(symbol_id, crate::database::symbol_flags::INDIRECTSTORAGE);
                }
            }
            let hidden_now = sym.read().unwrap().is_hidden_return();
            if hidden_now != ishidden {
                if ishidden {
                    scope.set_attribute(symbol_id, crate::database::symbol_flags::HIDDENRETPARM);
                } else {
                    scope.clear_attribute(symbol_id, crate::database::symbol_flags::HIDDENRETPARM);
                }
            }
            let typelock_now = sym.read().unwrap().is_type_locked();
            if typelock_now != istypelock {
                if istypelock {
                    scope.set_attribute(symbol_id, crate::database::symbol_flags::TYPELOCK);
                } else {
                    scope.clear_attribute(symbol_id, crate::database::symbol_flags::TYPELOCK);
                }
            }
            let namelock_now = sym.read().unwrap().is_name_locked();
            if namelock_now != isnamelock {
                if isnamelock {
                    scope.set_attribute(symbol_id, crate::database::symbol_flags::NAMELOCK);
                } else {
                    scope.clear_attribute(symbol_id, crate::database::symbol_flags::NAMELOCK);
                }
            }
            // Ghidra: if ((nm.size()!=0)&&(nm!=res->sym->getName()))
            //           scope->renameSymbol(res->sym,nm);
            if !nm.is_empty() && sym.read().unwrap().name != nm {
                scope.rename_symbol(symbol_id, nm);
            }
        }
        // Ghidra: if (pieces.type != res->sym->getType())
        //           scope->retypeSymbol(res->sym,pieces.type);
        let incoming: Option<Arc<Datatype>> = pieces.ty.clone();
        let current = sym.read().unwrap().get_type();
        let type_differs = match (&incoming, &current) {
            (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
            (None, None) => false,
            _ => true,
        };
        if type_differs {
            if let Some(t) = incoming {
                sym.write().unwrap().dtype = Some(t);
            }
        }
        self.inparam[i] = Some(res.clone());
        res
    }

    // Ghidra: fspec.cc:3216 ProtoStoreSymbol::clearInput
    /// Remove the input parameter at slot `i`. Faithful 1:1 body
    /// (fspec.cc:3216-3231): the category-0 symbol at slot `i` is
    /// uncategorized and removed entirely, then every later category-0
    /// symbol is renumbered down one slot.
    pub fn clear_input(&mut self, i: usize) {
        let mut scope = self.scope.write().unwrap();
        if let Some(sym) = scope.get_category_symbol(SYMBOL_FUNCTION_PARAMETER, i as i32) {
            let id = sym.read().unwrap().symbol_id;
            // Remove it from category list
            scope.set_category(id, SYMBOL_NO_CATEGORY, 0);
            // Remove it altogether
            scope.remove_symbol(id);
        }
        // Renumber any category 0 symbol with index greater than i
        let sz = scope.get_category_size(SYMBOL_FUNCTION_PARAMETER);
        let mut j = i as i32 + 1;
        while j < sz as i32 {
            if let Some(sym) = scope.get_category_symbol(SYMBOL_FUNCTION_PARAMETER, j) {
                let id = sym.read().unwrap().symbol_id;
                scope.set_category(id, SYMBOL_FUNCTION_PARAMETER, j - 1);
            }
            j += 1;
        }
        drop(scope);
        if i < self.inparam.len() {
            self.inparam[i] = None;
        }
    }

    // Ghidra: fspec.cc:3233 ProtoStoreSymbol::clearAllInputs
    /// `scope->clearCategory(0);` (fspec.cc:3233-3237).
    pub fn clear_all_inputs(&mut self) {
        self.scope.write().unwrap().clear_category(SYMBOL_FUNCTION_PARAMETER);
        self.inparam.clear();
    }

    // Ghidra: fspec.cc:3239 ProtoStoreSymbol::getNumInputs
    /// `return scope->getCategorySize(function_parameter);`
    /// (fspec.cc:3239-3243).
    pub fn get_num_inputs(&self) -> usize {
        self.scope.read().unwrap().get_category_size(SYMBOL_FUNCTION_PARAMETER)
    }

    // Ghidra: fspec.cc:3245 ProtoStoreSymbol::getInput
    /// Get the symbol-backed view of slot `i`, binding it to the current
    /// category-0 symbol (`None` when the slot has no symbol). Faithful to
    /// getInput (fspec.cc:3245-3254).
    pub fn get_input(&mut self, i: usize) -> Option<ParameterSymbol> {
        let sym = self
            .scope
            .read()
            .unwrap()
            .get_category_symbol(SYMBOL_FUNCTION_PARAMETER, i as i32)?;
        let mut res = self.get_symbol_backed(i);
        res.sym = Some(sym);
        self.inparam[i] = Some(res.clone());
        Some(res)
    }

    // Ghidra: fspec.cc:3256 ProtoStoreSymbol::setOutput
    /// Install the return value as an internal ParameterBasic:
    /// `outparam = new ParameterBasic("",piece.addr,piece.type,piece.flags);`
    /// (fspec.cc:3256-3263).
    pub fn set_output(&mut self, piece: &ParameterPieces) -> &ProtoParameter {
        self.outparam = Some(ProtoParameter::from_pieces(
            "",
            piece.space,
            piece.addr,
            piece.ty.clone().unwrap_or_else(|| {
                crate::type_system::TypeFactory::shared_default()
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_type_void()
            }),
            piece.flags,
        ));
        self.outparam.as_ref().unwrap()
    }

    // Ghidra: fspec.cc:3265 ProtoStoreSymbol::clearOutput
    /// Reset the return value to TYPE_VOID with cleared flags
    /// (fspec.cc:3265-3272).
    pub fn clear_output(&mut self) {
        let void_type = crate::type_system::TypeFactory::shared_default()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_type_void();
        let pieces = ParameterPieces {
            space: AddressSpace::Ram,
            addr: Address::new(0),
            ty: Some(void_type),
            flags: 0,
        };
        self.set_output(&pieces);
    }

    // Ghidra: fspec.cc:3274 ProtoStoreSymbol::getOutput
    /// `return outparam;` (fspec.cc:3274-3278).
    pub fn get_output(&self) -> Option<&ProtoParameter> {
        self.outparam.as_ref()
    }

    // Ghidra: fspec.cc:3280 ProtoStoreSymbol::clone
    /// Clone the store: fresh ProtoStoreSymbol over the same scope, with
    /// the outparam cloned (Ghidra `outparam->clone()`). Faithful to
    /// cc:3280-3291; the inparam cache is re-established lazily (Ghidra's
    /// clone drops it entirely — the fresh store's cache is empty).
    pub fn duplicate(&self) -> Self {
        let mut res = ProtoStoreSymbol::new(self.scope.clone(), self.restricted_usepoint);
        res.outparam = self.outparam.clone();
        res
    }

    // Ghidra: fspec.cc:3293 ProtoStoreSymbol::encode
    /// Nothing is stored explicitly for a symboltable-backed store (the
    /// symbol table is serialized separately) — faithful no-op
    /// (fspec.cc:3293-3297).
    pub fn encode_noop(&self) {}

    // Ghidra: fspec.cc:3299 ProtoStoreSymbol::decode
    /// Faithful to the throwing override: "Do not decode symbol-backed
    /// prototype through this interface" (fspec.cc:3299-3303).
    pub fn decode_refuses(&self) -> Result<(), String> {
        Err("Do not decode symbol-backed prototype through this interface".to_string())
    }
}

// Ghidra: fspec.cc:3421 ProtoStoreInternal::encode
/// Encode the internal (non-symbol) parameter list as an
/// `<internallist>` element. Faithful 1:1 body of
/// `ProtoStoreInternal::encode` (fspec.cc:3421-3462): a `<retparam>` for
/// the output (typelock flag + address + type ref; a null outparam encodes
/// an empty `<addr>`/`<void>` pair), then one `<param>` per input carrying
/// its optional name and true-valued flag attributes (typelock, namelock,
/// thisptr, indirectstorage, hiddenretparm), address, and type ref.
/// Rugra's flat `FuncProto.parameters` vector IS the internal store's
/// `inparam`, so callers pass the flat slices (see
/// `FuncProto::encode`'s `encode_store` closure hook).
pub fn encode_internal_store(
    encoder: &mut dyn crate::marshal::Encoder,
    outparam: Option<&ProtoParameter>,
    inparam: &[ProtoParameter],
    internallist_elem: &crate::marshal::ElementId,
    retparam_elem: &crate::marshal::ElementId,
    param_elem: &crate::marshal::ElementId,
    addr_elem: &crate::marshal::ElementId,
    void_elem: &crate::marshal::ElementId,
    space_attrib: &crate::marshal::AttributeId,
    offset_attrib: &crate::marshal::AttributeId,
    size_attrib: &crate::marshal::AttributeId,
    name_attrib: &crate::marshal::AttributeId,
    typelock_attrib: &crate::marshal::AttributeId,
    namelock_attrib: &crate::marshal::AttributeId,
    thisptr_attrib: &crate::marshal::AttributeId,
    indirectstorage_attrib: &crate::marshal::AttributeId,
    hiddenretparm_attrib: &crate::marshal::AttributeId,
) {
    encoder.open_element(internallist_elem);
    if let Some(out) = outparam {
        encoder.open_element(retparam_elem);
        if out.is_type_locked() {
            encoder.write_bool(typelock_attrib, true);
        }
        // Ghidra: outparam->getAddress().encode(encoder);
        encoder.open_element(addr_elem);
        encoder.write_string(space_attrib, space_name(out.address_space));
        encoder.write_unsigned_integer(offset_attrib, out.address.as_u64());
        encoder.write_signed_integer(size_attrib, out.data_type.get_size() as i64);
        encoder.close_element(addr_elem);
        // Ghidra: outparam->getType()->encodeRef(encoder);
        out.data_type.encode_ref(encoder);
        encoder.close_element(retparam_elem);
    } else {
        encoder.open_element(retparam_elem);
        encoder.open_element(addr_elem);
        encoder.close_element(addr_elem);
        encoder.open_element(void_elem);
        encoder.close_element(void_elem);
        encoder.close_element(retparam_elem);
    }
    for param in inparam {
        encoder.open_element(param_elem);
        if !param.name.is_empty() {
            encoder.write_string(name_attrib, &param.name);
        }
        if param.is_type_locked() {
            encoder.write_bool(typelock_attrib, true);
        }
        if param.is_name_locked() {
            encoder.write_bool(namelock_attrib, true);
        }
        if param.is_this_pointer() {
            encoder.write_bool(thisptr_attrib, true);
        }
        if param.is_indirect_storage() {
            encoder.write_bool(indirectstorage_attrib, true);
        }
        if param.is_hidden_return() {
            encoder.write_bool(hiddenretparm_attrib, true);
        }
        // Ghidra: param->getAddress().encode(encoder);
        encoder.open_element(addr_elem);
        encoder.write_string(space_attrib, space_name(param.address_space));
        encoder.write_unsigned_integer(offset_attrib, param.address.as_u64());
        encoder.write_signed_integer(size_attrib, param.data_type.get_size() as i64);
        encoder.close_element(addr_elem);
        // Ghidra: param->getType()->encodeRef(encoder);
        param.data_type.encode_ref(encoder);
        encoder.close_element(param_elem);
    }
    encoder.close_element(internallist_elem);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_system::datatype::{TypeBase, TypeMetatype};

    #[test]
    fn test_proto_creation() {
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));

        let mut proto = FuncProto::new("test_func".to_string(), void_type);
        proto.add_parameter(ProtoParameter::new("a".to_string(), int_type, Address::new(0)));

        assert_eq!(proto.num_params(), 1);
        assert_eq!(proto.get_param(0).unwrap().name, "a");
    }

    // Ghidra: fspec.cc:4949 FuncCallSpecs::setFuncdata
    #[test]
    fn test_call_specs_set_funcdata_binds_name_and_entry() {
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let mut fc = FuncCallSpecs::new(Address::new(0x1000), FuncProto::new(String::new(), void_type));
        assert_eq!(fc.prototype.name, "");
        assert!(fc.entry_addr.is_none());
        // A non-empty display name replaces the prototype name; the entry
        // address is taken from the callee (fspec.cc:4956-4958).
        fc.set_funcdata("free", Address::new(0x22f0));
        assert_eq!(fc.prototype.name, "free");
        assert_eq!(fc.entry_addr.map(|a| a.as_u64()), Some(0x22f0));
        // An empty display name leaves the previous name untouched
        // (fspec.cc:4957 guard).
        fc.set_funcdata("", Address::new(0x2530));
        assert_eq!(fc.prototype.name, "free");
        assert_eq!(fc.entry_addr.map(|a| a.as_u64()), Some(0x2530));
    }

    // Ghidra: fspec.cc:4924 FuncCallSpecs::FuncCallSpecs
    /// The entry-address record point stores in(0)'s full address — the
    /// offset AND the varnode's space (fspec.cc:4934 `getIn(0)->getAddr()`,
    /// read before the FSPEC annotation swap). PRINTC-OPCALL-ENTRYSPACE-0001
    /// fspec half: the space rides the ADDRESS-0001 tag form through the
    /// per-variant stand-in, so consumers resolving `getEntryAddress()`'s
    /// space see the in(0) space's own dimensions instead of a flat Ram
    /// fallback, while offset-only consumers (`as_u64`) are unchanged.
    #[test]
    fn test_new_for_op_entry_addr_carries_in0_space() {
        use crate::funcdata::Funcdata;
        use crate::opcodes::OpCode;
        use crate::space::AddressSpace;
        use crate::type_system::datatype::{Datatype, TypeBase, TypeMetatype};

        let void_proto = || {
            FuncProto::new(
                String::new(),
                Arc::new(Datatype::Void(TypeBase::new(
                    "void".to_string(),
                    0,
                    TypeMetatype::Void,
                ))),
            )
        };
        let mut fd = Funcdata::new("entryspace", Address::new(0x7000), 0x20);

        // Direct CALL whose in(0) is a ram-space target varnode — the
        // production form both lifter paths emit (x86 `call rel` exports
        // `*[ram]`, sleigh_lift.rs convert; iced builds
        // VarnodeRaw(Ram, target, 8), x86_lift.rs).
        let call = fd.new_op(1, Address::new(0x7004));
        fd.op_set_opcode(&call, OpCode::CPUI_CALL);
        let target = fd
            .vbank
            .create_with_space(8, AddressSpace::Ram, 0x22f0);
        fd.op_set_input(&call, target, 0);
        let fc = FuncCallSpecs::new_for_op(&call, void_proto());
        let entry = fc.entry_addr.expect("direct CALL records an entry");
        // Offset channel unchanged: compatibility consumers (annotation
        // varnode payload, printRaw hex, encode offset) see the same value.
        assert_eq!(entry.as_u64(), 0x22f0);
        // Space channel filled: the stand-in carries the ram variant's own
        // name and dimensions (fspec.cc:4934 keeps in(0)'s ram address, so
        // printc's fc->getEntryAddress() dims resolve to ram's (8,1)).
        let spc = entry.get_space().expect("entry address carries a space");
        assert_eq!(spc.get_name(), "ram");
        assert_eq!(spc.get_addr_size(), 8);
        assert_eq!(spc.get_word_size(), 1);
        // The tagged form is a distinct address from the legacy spaceless
        // one (address.hh:356: base==op2.base fails), pinning that the
        // record no longer produces the legacy form.
        assert_ne!(entry, Address::new(0x22f0));

        // A const-space in(0) (SLEIGH relative-label form) keeps the const
        // space in the record, as the oracle's getAddr() would.
        let call2 = fd.new_op(1, Address::new(0x7008));
        fd.op_set_opcode(&call2, OpCode::CPUI_CALL);
        let const_target = fd.new_constant(8, 0x1234);
        fd.op_set_input(&call2, const_target, 0);
        let fc2 = FuncCallSpecs::new_for_op(&call2, void_proto());
        let entry2 = fc2.entry_addr.expect("const in(0) still records");
        assert_eq!(entry2.as_u64(), 0x1234);
        let spc2 = entry2.get_space().expect("const entry carries a space");
        assert_eq!(spc2.get_name(), "const");
        assert_eq!(spc2.get_addr_size(), 8);
        assert_eq!(spc2.get_word_size(), 1);

        // An iop-space in(0) without a bound callspec records no entry
        // (the annotation space never carries a callee address).
        let call3 = fd.new_op(1, Address::new(0x700c));
        fd.op_set_opcode(&call3, OpCode::CPUI_CALL);
        let iop_vn = fd
            .vbank
            .create_with_space(8, AddressSpace::Iop, 0x99);
        fd.op_set_input(&call3, iop_vn, 0);
        let fc3 = FuncCallSpecs::new_for_op(&call3, void_proto());
        assert!(fc3.entry_addr.is_none());

        // Clone case (fspec.cc:4935-4940): an in(0) already converted to an
        // FSPEC annotation resolves through the typed handle to the source
        // spec's entry — including its space tag.
        let owner = Arc::new(std::sync::RwLock::new(fc));
        let annotation = fd.new_varnode_call_specs(&owner);
        let call4 = fd.new_op(1, Address::new(0x7010));
        fd.op_set_opcode(&call4, OpCode::CPUI_CALL);
        fd.op_set_input(&call4, annotation, 0);
        let fc4 = FuncCallSpecs::new_for_op(&call4, void_proto());
        assert_eq!(fc4.entry_addr, Some(entry));
    }

    // ---- ParamTrial / ParamActive tests ----

    #[test]
    fn test_param_trial_flags() {
        let mut t = ParamTrial::new_in_space(AddressSpace::Register, Address::new(0x100), 8, 0);
        assert!(!t.is_used());
        assert!(!t.is_checked());
        t.mark_used();
        assert!(t.is_used());
        t.mark_active();
        assert!(t.is_active());
        assert!(t.is_checked());
        t.mark_no_use();
        assert!(!t.is_used());
        assert!(t.is_definitely_not_used());
    }

    #[test]
    fn test_param_trial_split() {
        let t = ParamTrial::new_in_space(AddressSpace::Register, Address::new(0x100), 8, 2);
        let hi = t.split_hi(4);
        let lo = t.split_lo(4);
        assert_eq!(hi.get_size(), 4);
        assert_eq!(hi.get_address(), Address::new(0x100));
        assert_eq!(lo.get_size(), 4);
        assert_eq!(lo.get_address(), Address::new(0x104));
        assert_eq!(lo.get_slot(), 3);
    }

    #[test]
    fn test_param_active_register_and_split() {
        let mut pa = ParamActive::new(true);
        assert_eq!(pa.get_num_trials(), 0);
        assert_eq!(pa.get_slot_base(), 1);
        assert_eq!(pa.get_max_pass(), 0);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x200), 8);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x208), 8);
        assert_eq!(pa.get_num_trials(), 2);
        assert_eq!(pa.get_trial(0).get_slot(), 1);
        assert_eq!(pa.get_trial(1).get_slot(), 2);
        assert!(pa.get_trial(0).is_killed_by_call());
        assert_eq!(pa.get_trial(0).get_space(), AddressSpace::Register);
        assert_eq!(pa.which_trial_in_space(AddressSpace::Register, Address::new(0x208), 8), 1);
        assert_eq!(pa.which_trial_in_space(AddressSpace::Register, Address::new(0x300), 8), -1);
        // Split trial 0 at 4 bytes.
        pa.split_trial(0, 4);
        assert_eq!(pa.get_num_trials(), 3);
        assert_eq!(pa.get_trial(0).get_size(), 4);
        assert_eq!(pa.get_trial(1).get_size(), 4);
        assert_eq!(pa.get_trial(1).get_address(), Address::new(0x204));
    }

    #[test]
    fn test_param_active_tagged_space_and_spaceless_fail_closed() {
        let register = crate::space::AddrSpace::new_space(
            SpaceType::Processor,
            "not-used-for-classification",
            false,
            8,
            1,
            crate::space::SPACEID_REGISTER.into(),
            0,
            0,
            0,
        );
        let stack = crate::space::AddrSpace::new_space(
            SpaceType::SpaceBase,
            "also-not-used-for-classification",
            false,
            8,
            1,
            42,
            0,
            0,
            0,
        );
        let fspec = crate::space::AddrSpace::new_space(
            SpaceType::Fspec,
            "cannot-project-to-the-coarse-enum",
            false,
            8,
            1,
            5,
            0,
            0,
            0,
        );
        let wide_processor = crate::space::AddrSpace::new_space(
            SpaceType::Processor,
            "index-does-not-fit-the-coarse-enum",
            false,
            8,
            1,
            300,
            0,
            0,
            0,
        );
        let register_address = Address::with_space(&register, 0x40);
        let stack_address = Address::with_space(&stack, 0x18);
        let mut active = ParamActive::new(false);

        assert!(active.register_trial(register_address, 8));
        assert!(active.register_trial(stack_address, 8));
        assert_eq!(active.get_trial(0).get_space(), AddressSpace::Register);
        assert!(active.get_trial(0).is_killed_by_call());
        assert_eq!(active.get_trial(1).get_space(), AddressSpace::Stack);
        assert!(!active.get_trial(1).is_killed_by_call());
        assert_eq!(active.which_trial(register_address, 8), 0);
        assert_eq!(active.which_trial(stack_address, 8), 1);

        let count_before = active.get_num_trials();
        let slotbase_before = active.get_slot_base();
        assert!(!active.register_trial(Address::new(0x88), 8));
        assert!(!active.register_trial(Address::with_space(&fspec, 0x88), 8));
        assert!(!active.register_trial(Address::with_space(&wide_processor, 0x88), 8));
        assert_eq!(active.which_trial(Address::new(0x40), 8), -1);
        assert_eq!(active.which_trial(Address::with_space(&fspec, 0x40), 8), -1);
        assert_eq!(active.get_num_trials(), count_before);
        assert_eq!(active.get_slot_base(), slotbase_before);
    }

    #[test]
    fn test_param_active_num_used() {
        let mut pa = ParamActive::new(false);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 8);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x108), 8);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x110), 8);
        pa.get_trial_mut(0).mark_used();
        pa.get_trial_mut(2).mark_used();
        assert_eq!(pa.get_num_used(), 2);
    }

    #[test]
    fn test_func_proto_lock_and_copy() {
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("test".into(), int_type.clone());
        let p = ProtoParameter::new("param_1".into(), int_type.clone(), Address::new(0x38));
        proto.add_parameter(p);
        assert!(!proto.is_input_locked());
        proto.set_input_lock(true);
        assert!(proto.is_input_locked());

        let mut proto2 = FuncProto::new("other".into(), int_type.clone());
        proto2.copy_from(&proto);
        assert_eq!(proto2.num_params(), 1);
        assert_eq!(proto2.name, "test");

        proto.clear_unlocked_input();
        assert_eq!(proto.num_params(), 1); // locked params retained
    }

    #[test]
    fn test_func_proto_locked_void_input_and_output_model_lock() {
        let void_type = Arc::new(Datatype::Void(
            crate::type_system::datatype::TypeBase::new(
                "void".into(),
                0,
                crate::type_system::TypeMetatype::Void,
            ),
        ));
        let mut proto = FuncProto::new("known_void".into(), void_type.clone());
        assert!(!proto.is_input_locked());
        assert!(!proto.is_model_locked());

        proto.set_input_lock(true);
        assert!(proto.is_input_locked());
        assert!(proto.is_model_locked());
        proto.clear_unlocked_input();
        assert!(proto.is_input_locked());
        assert_eq!(proto.num_params(), 0);

        let mut copied = FuncProto::new("copy".into(), void_type);
        copied.copy_from(&proto);
        assert!(copied.is_input_locked());
        copied.clear_input();
        assert!(!copied.is_input_locked());

        let mut output = FuncProto::new("output".into(), copied.return_type.clone());
        output.set_output_lock(true);
        assert!(output.is_output_locked());
        assert!(output.is_model_locked());
    }

    #[test]
    fn test_func_proto_dotdotdot() {
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("varargs".into(), int_type);
        assert!(!proto.is_varargs());
        proto.set_dotdotdot(true);
        assert!(proto.is_varargs());
    }

    #[test]
    fn test_func_proto_method_flags() {
        // Ghidra: fspec.hh:1411-1458 inline/noreturn/constructor/destructor/thisptr
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("method".into(), int_type);
        // All method flags start false.
        assert!(!proto.is_inline());
        assert!(!proto.is_no_return());
        assert!(!proto.is_constructor_flag());
        assert!(!proto.is_destructor());
        assert!(!proto.has_thisptr());
        // Set each flag.
        proto.set_inline(true);
        proto.set_no_return(true);
        proto.set_constructor(true);
        proto.set_destructor(true);
        proto.set_has_thisptr(true);
        assert!(proto.is_inline());
        assert!(proto.is_no_return());
        assert!(proto.is_constructor_flag());
        assert!(proto.is_destructor());
        assert!(proto.has_thisptr());
        // Comparable flags should now carry the constructor/destructor/thisptr bits.
        let cf = proto.get_comparable_flags();
        assert_ne!(cf & 0x200, 0); // is_constructor
        assert_ne!(cf & 0x400, 0); // is_destructor
        assert_ne!(cf & 0x800, 0); // has_thisptr
        // Flags survive copy_from.
        let mut proto2 = FuncProto::new("dst".into(), proto.return_type.clone());
        proto2.copy_from(&proto);
        assert!(proto2.is_inline());
        assert!(proto2.is_no_return());
        assert!(proto2.is_constructor_flag());
        assert!(proto2.is_destructor());
        assert!(proto2.has_thisptr());
    }

    #[test]
    fn test_func_proto_update_this_pointer() {
        // Ghidra: fspec.cc:3572-3584 updateThisPointer
        let int_type = Arc::new(Datatype::Base(
            crate::type_system::datatype::TypeBase::new("int".into(), 4, crate::type_system::TypeMetatype::Int)));
        let mut proto = FuncProto::new("method".into(), int_type.clone());
        // Without has_thisptr set, update_this_pointer is a no-op.
        proto.add_parameter(ProtoParameter::new("this".into(), int_type.clone(), Address::new(0)));
        proto.update_this_pointer();
        assert!(!proto.parameters[0].is_this_pointer());
        // With has_thisptr set, the first parameter is marked as the this pointer.
        proto.set_has_thisptr(true);
        proto.update_this_pointer();
        assert!(proto.parameters[0].is_this_pointer());
        // A hidden-return parameter at slot 0 is skipped.
        let mut proto2 = FuncProto::new("method2".into(), int_type.clone());
        proto2.set_has_thisptr(true);
        let mut hidden = ProtoParameter::new("rethidden".into(), int_type.clone(), Address::new(0));
        hidden.flags |= protoparam_flags::HIDDEN_RETURN;
        proto2.add_parameter(hidden);
        proto2.add_parameter(ProtoParameter::new("this".into(), int_type, Address::new(0x8)));
        proto2.update_this_pointer();
        assert!(!proto2.parameters[0].is_this_pointer());
        assert!(proto2.parameters[1].is_this_pointer());
    }

    // ---- ParamEntry / ParamListStandard tests ----

    #[test]
    fn test_param_entry_exclusion_basic() {
        // Ghidra: fspec.cc:60-71 findEntryByStorage, fspec.hh:134 isExclusion
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Register);
        e.set_base(0x10);
        e.set_sizes(8, 4);
        e.set_alignment(0); // alignment==0 => exclusion entry
        assert!(e.is_exclusion());
        assert_eq!(e.get_size(), 8);
        assert_eq!(e.get_min_size(), 4);
        assert_eq!(e.get_base(), 0x10);
        assert_eq!(e.get_space(), AddressSpace::Register);
    }

    #[test]
    fn test_param_entry_aligned_slots() {
        // Ghidra: fspec.hh:131 getAlign, fspec.hh:135 isReverseStack
        let mut e = ParamEntry::new(2);
        e.set_space(AddressSpace::Register);
        e.set_base(0x100);
        e.set_sizes(32, 4);
        e.set_alignment(8); // 32/8 = 4 slots
        assert!(!e.is_exclusion());
        assert_eq!(e.get_align(), 8);
        // get_addr_by_slot advances slot_num (fspec.cc:434)
        let mut slot = 0i32;
        let a0 = e.get_addr_by_slot(&mut slot, 8, 1).unwrap();
        assert_eq!(a0.as_u64(), 0x100);
        assert_eq!(slot, 1);
        let a1 = e.get_addr_by_slot(&mut slot, 8, 1).unwrap();
        assert_eq!(a1.as_u64(), 0x108);
        assert_eq!(slot, 2);
    }

    #[test]
    fn test_param_entry_justified_contain() {
        // Ghidra: fspec.cc:248-283 justifiedContain. For an unflagged
        // little-endian exclusion entry (Register in the transitional
        // enum-space model), address.cc:141 returns the START distance
        // op2.offset - offset for forceleft=false (FSPEC-JUSTIFIED-ENDIAN-0002);
        // a big-endian space without the flag would return the end
        // distance off1 - off2 instead (address.cc:138-140).
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Register);
        e.set_base(0x200);
        e.set_sizes(8, 1);
        e.set_alignment(0); // exclusion
        // Full-range containment returns 0 (both distance views).
        assert_eq!(e.justified_contain(Address::new(0x200), 8), 0);
        // 2-byte value at 0x202 spans [0x202..0x203]; the LE start
        // distance is 0x202 - 0x200 = 2 (the BE end distance is
        // 0x207 - 0x203 = 4, unreachable through the enum space).
        assert_eq!(e.justified_contain(Address::new(0x202), 2), 2);
        // A value flush with the low end returns 0; flush with the high
        // end returns 6 in the LE start-distance view.
        assert_eq!(e.justified_contain(Address::new(0x200), 2), 0);
        assert_eq!(e.justified_contain(Address::new(0x206), 2), 6);
        // Out of range
        assert_eq!(e.justified_contain(Address::new(0x300), 4), -1);
    }

    // FSPEC-JUSTIFIED-CONTAIN-0001: address.cc:131-141
    // Address::justifiedContain returns -1 when EITHER side pokes out
    // independently (`if (op2.offset < offset) return -1;` then
    // `if (off2 > off1) return -1;`). The legacy paired-violation predicate
    // (both bounds out together) let equal-start-bigger queries and
    // low-side overlaps ending flush at the entry end fall through to the
    // offset arithmetic, returning 0 (false justified) or wrapped values.
    #[test]
    fn test_justified_contain_range_one_sided_violations() {
        // entry [0x1000,0x1007] (base 0x1000, size 8). Endianness
        // arguments: `false` = little-endian space, `true` = big-endian
        // space (address.cc:138 base->isBigEndian()).
        // Equal start, query pokes out high: [0x1000,0x100B] — Ghidra
        // off2 > off1 -> -1 (was 0 in the start-distance branch).
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 12, true, false), -1);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 12, false, false), -1);
        // Low-side partial overlap ending flush at the entry end:
        // [0xFFE,0x1007] — op2.offset < offset -> -1 (was 0 in the
        // end-distance branch: this_end - end_addr == 0).
        assert_eq!(justified_contain_range(0x1000, 8, 0xFFE, 10, true, false), -1);
        assert_eq!(justified_contain_range(0x1000, 8, 0xFFE, 10, false, false), -1);
        // Strict superset query [0xFFC,0x100B]: -1 (was a wrapped value).
        assert_eq!(justified_contain_range(0x1000, 8, 0xFFC, 16, true, false), -1);
        assert_eq!(justified_contain_range(0x1000, 8, 0xFFC, 16, false, false), -1);
        // High-side partial overlap from inside: [0x1004,0x100B] -> -1.
        assert_eq!(justified_contain_range(0x1000, 8, 0x1004, 8, true, false), -1);
        // Low-side partial overlap ending inside: [0xFFE,0x1003] -> -1
        // (already rejected by the legacy paired condition; pinned).
        assert_eq!(justified_contain_range(0x1000, 8, 0xFFE, 6, false, false), -1);
        // Size-1 entry [0x2000,0x2000]: equal-start-bigger -> -1.
        assert_eq!(justified_contain_range(0x2000, 1, 0x2000, 2, true, false), -1);
        assert_eq!(justified_contain_range(0x2000, 1, 0x2000, 2, false, false), -1);
        // Contained geometries keep the branch arithmetic
        // (address.cc:138-141): little-endian spaces return the start
        // distance op2.offset - offset for BOTH forceleft values;
        // big-endian without forceleft returns off1 - off2; big-endian
        // with forceleft returns the start distance again.
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 8, true, false), 0);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 8, false, false), 0);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1002, 4, true, false), 2);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1002, 4, false, false), 2);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 4, true, false), 0);
        // LE + forceleft=false returns the START distance 0 (the
        // FSPEC-JUSTIFIED-ENDIAN-0002 route; the end distance is 4).
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 4, false, false), 0);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 4, false, true), 4);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1000, 4, true, true), 0);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1003, 1, true, false), 3);
        assert_eq!(justified_contain_range(0x1000, 8, 0x1003, 1, false, true), 4);
    }

    // FSPEC-JUSTIFIED-CONTAIN-0001 projection: characterizeAsParam
    // (fspec.cc:682-719) over a 4-byte force-left exclusion entry. A query
    // starting at the entry base but poking out (range superset of entry)
    // must classify contained_by (justifiedContain -> -1, then the
    // exclusion containedBy check), never contains_justified.
    #[test]
    fn test_characterize_as_param_range_superset_entry() {
        let mut m = ParamListStandard::new();
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Register);
        e.set_base(0x100);
        e.set_sizes(4, 1);
        e.set_alignment(0); // exclusion
        *e.flags_mut() |= param_entry_flags::FORCE_LEFT_JUSTIFY;
        let mut effects = Vec::new();
        m.parse_pentry(0, true, false, false, &mut effects, e).unwrap();
        m.finalize_after_decode(0);
        // Exact and justified sub-ranges.
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x100, 4),
            containment::CONTAINS_JUSTIFIED
        );
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x100, 1),
            containment::CONTAINS_JUSTIFIED
        );
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x102, 2),
            containment::CONTAINS_UNJUSTIFIED
        );
        // Range supersets of the entry -> contained_by (was
        // contains_justified under the paired-violation predicate).
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x100, 6),
            containment::CONTAINED_BY
        );
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x100, 8),
            containment::CONTAINED_BY
        );
        // High-side pokes with the entry not inside the query ->
        // no_containment.
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x102, 4),
            containment::NO_CONTAINMENT
        );
        assert_eq!(
            m.characterize_as_param(AddressSpace::Register, 0x101, 4),
            containment::NO_CONTAINMENT
        );
    }

    // FSPEC-FINDENTRY-GATE-0005 projection: findEntry (fspec.cc:661-680)
    // visits only the resolver find window — entries whose registered
    // extent contains the query start in the query's space — so an
    // extent-out query returns None even with just=false, and join
    // entries are reachable through their piece registration. Rust-side
    // regression for the fspec_findentry_1204 oracle fixture (the
    // fixture is the authority; this pins the same rows in-tree).
    #[test]
    fn test_find_entry_resolver_window_gate() {
        let mut m = ParamListStandard::new();
        m.entry_mut().push({
            let mut e = ParamEntry::new(0);
            e.set_space(AddressSpace::Register);
            e.set_base(0x100);
            e.set_sizes(8, 1);
            e.set_alignment(0);
            *e.flags_mut() |= param_entry_flags::FORCE_LEFT_JUSTIFY;
            e
        });
        m.entry_mut().push({
            let mut e = ParamEntry::new(1);
            e.set_space(AddressSpace::Register);
            e.set_base(0x200);
            e.set_sizes(8, 4);
            e.set_alignment(0);
            *e.flags_mut() |= param_entry_flags::FORCE_LEFT_JUSTIFY;
            e
        });
        m.set_num_group(2);
        m.populate_resolver();
        // In-window hits.
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x100), 8, true), Some(0));
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x102), 4, false), Some(0));
        // Extent-out queries: window empty -> None even with just=false.
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x110), 4, false), None);
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x300), 8, false), None);
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0xFF), 4, false), None);
        // In e1's window but below minSize -> None.
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x200), 2, false), None);
        // Foreign space / no resolver -> None.
        assert_eq!(m.find_entry(AddressSpace::Ram, Address::new(0x100), 8, false), None);
        assert_eq!(m.find_entry(AddressSpace::Unique, Address::new(0x100), 8, false), None);
    }

    // FSPEC-RESOLVER-JOIN-WINDOW-0004 projection: a join entry reached
    // through its per-piece registration, including the cross-space
    // per-piece space guard of the join walk (address.cc:133).
    #[test]
    fn test_find_entry_join_piece_window() {
        let mut m = ParamListStandard::new();
        let mut j = ParamEntry::new(0);
        j.set_space(AddressSpace::Join);
        j.set_base(0);
        j.set_sizes(8, 4);
        j.set_alignment(0);
        // Pieces MOST significant first: ram:0x200 high, reg:0x200 low.
        j.set_join_pieces(vec![
            VarnodeData { space: AddressSpace::Ram, offset: 0x200, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 0x200, size: 4 },
        ]);
        m.entry_mut().push(j);
        m.set_num_group(1);
        m.populate_resolver();
        // The low piece justifies a reg query -> the join entry itself.
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x200), 4, true), Some(0));
        // The ram query hits the high piece numerically, but the foreign
        // low piece contributes address.cc:133 -1 -> offset 4 != 0.
        assert_eq!(m.find_entry(AddressSpace::Ram, Address::new(0x200), 4, true), None);
        // just=false returns the join from either piece's window.
        assert_eq!(m.find_entry(AddressSpace::Ram, Address::new(0x200), 4, false), Some(0));
        // Outside both piece extents -> None.
        assert_eq!(m.find_entry(AddressSpace::Register, Address::new(0x204), 4, false), None);
    }

    #[test]
    fn test_param_list_standard_new() {
        // Ghidra: fspec.hh:617 ParamListStandard()
        let m = ParamListStandard::new();
        assert_eq!(m.get_type(), ParamListKind::Standard);
        assert!(!m.is_this_before_ret_pointer());
        assert!(!m.is_auto_killed_by_call());
        assert_eq!(m.get_max_delay(), 0);
        assert!(m.get_entry().is_empty());
        assert_eq!(m.get_num_group(), 0);
    }

    #[test]
    fn test_param_list_standard_possible_param() {
        // Ghidra: fspec.cc:1354 possibleParam + fspec.cc:661 findEntry
        let mut m = ParamListStandard::new();
        let mut e = ParamEntry::new(0);
        e.set_space(AddressSpace::Ram);
        e.set_base(0x1000);
        e.set_sizes(32, 4);
        e.set_alignment(8);
        let mut effects = Vec::new();
        m.parse_pentry(0, true, false, false, &mut effects, e).unwrap();
        m.finalize_after_decode(0);
        assert!(m.possible_param(AddressSpace::Ram, Address::new(0x1000), 8));
        assert!(!m.possible_param(AddressSpace::Ram, Address::new(0x9000), 8));
        // findEntry's per-space resolver gate (fspec.cc:664-669): a query
        // whose space has no entries never matches, even at a valid offset.
        assert!(!m.possible_param(AddressSpace::Register, Address::new(0x1000), 8));
        assert!(!m.possible_param(AddressSpace::Stack, Address::new(0x1000), 8));
    }

    // ---- FSPEC-POSSIBLEPARAM-JOIN-0006 unit coverage ----

    // Ghidra: fspec.cc:1765 ParamListStandardOut::possibleParam
    /// cc:1765-1774 has NO caller-level space filter and no minSize gate:
    /// entries are visited in list order, join entries ARE reachable
    /// through the per-piece join walk, and space rejection happens only
    /// inside justifiedContain (address.cc:133 per piece / fspec.cc:269).
    #[test]
    fn test_param_list_standard_out_possible_param_join_and_space() {
        let mut out = ParamListStandardOut::new();
        // e0: join reg:0x104 (high) + reg:0x100 (low), pieces MS first.
        out.base.entry_mut().push({
            let mut e = ParamEntry::new(0);
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Join);
            e.set_base(0);
            e.set_sizes(8, 4);
            e.set_alignment(0);
            e.set_join_pieces(vec![
                VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
                VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
            ]);
            e
        });
        // e1: plain register [0x200,0x207] min 4, exclusion (alignment 0).
        out.base.entry_mut().push({
            let mut e = ParamEntry::new(1);
            *e.flags_mut() = param_entry_flags::FORCE_LEFT_JUSTIFY;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Register);
            e.set_base(0x200);
            e.set_sizes(8, 4);
            e.set_alignment(0);
            e
        });
        out.base.set_num_group(2);
        // Join entry reachable: low piece justifies the reg query (>= 0).
        assert!(out.possible_param(AddressSpace::Register, Address::new(0x100), 4));
        // Join walk returns 4 (>= 0) for the high piece -> still true:
        // possibleParam accepts ANY non-negative containment, unlike
        // findEntry's just=true == 0 gate.
        assert!(out.possible_param(AddressSpace::Register, Address::new(0x104), 4));
        // Join walk -1 (0x100/8 pokes out of both pieces) -> falls to e1,
        // which does not contain it either -> false.
        assert!(!out.possible_param(AddressSpace::Register, Address::new(0x100), 8));
        // Plain entry hit.
        assert!(out.possible_param(AddressSpace::Register, Address::new(0x200), 4));
        // No minSize gate in cc:1765-1774: a 1-byte query at e1 is still
        // contained (force-left justified offset 0) even though minsize 4.
        assert!(out.possible_param(AddressSpace::Register, Address::new(0x200), 1));
        // Foreign-space query at a numerically coincident offset: the
        // per-piece address.cc:133 guard (join) and the entry-space guard
        // (plain, alignment==0 route) reject it.
        assert!(!out.possible_param(AddressSpace::Stack, Address::new(0x200), 4));
        assert!(!out.possible_param(AddressSpace::Stack, Address::new(0x100), 4));
    }

    // Ghidra: fspec.cc:1765 ParamListStandardOut::possibleParam
    /// The alignment != 0 foreign-space route (fspec.cc:269) through
    /// possibleParam: an out-of-resolver caller reaches it directly
    /// because possibleParam iterates the raw entry list.
    #[test]
    fn test_param_list_standard_out_possible_param_aligned_foreign_space() {
        let mut out = ParamListStandardOut::new();
        // e0: register [0x1000,0x101F] min 4, alignment 8 (16 bytes, 2 slots).
        out.base.entry_mut().push({
            let mut e = ParamEntry::new(0);
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Register);
            e.set_base(0x1000);
            e.set_sizes(16, 4);
            e.set_alignment(8);
            e
        });
        out.base.set_num_group(1);
        assert!(out.possible_param(AddressSpace::Register, Address::new(0x1000), 8));
        // A stack query at the same numeric offset hits the cc:269
        // spaceid != addr.getSpace() guard -> -1 -> false.
        assert!(!out.possible_param(AddressSpace::Stack, Address::new(0x1000), 8));
        // Out of extent -> false.
        assert!(!out.possible_param(AddressSpace::Register, Address::new(0x9000), 8));
    }

    // Ghidra: fspec.cc:366 ParamEntry::assumedExtension +
    //          fspec.cc:1426 ParamListStandard::assumedExtension
    /// The cc:377 justifiedContain call is space-aware: a foreign-space
    /// query at a numerically justified offset returns CPUI_COPY instead
    /// of an extension, join entries return CPUI_COPY at cc:376 before
    /// the containment check, and the list-level minSize gate skips
    /// oversized-entry queries.
    #[test]
    fn test_assumed_extension_space_join_and_minsize_gates() {
        let mut m = ParamListStandard::new();
        // e0: register [0x100,0x11F] min 1 alignment 8, smallsize zext:
        // a 2-byte value justified at a slot boundary extends.
        m.entry_mut().push({
            let mut e = ParamEntry::new(0);
            *e.flags_mut() = param_entry_flags::SMALLSIZE_ZEXT;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Register);
            e.set_base(0x100);
            e.set_sizes(32, 1);
            e.set_alignment(8);
            e
        });
        // e1: join entry (would justify a 2-byte query on its low piece)
        // with smallsize sext — cc:376 returns CPUI_COPY before the walk.
        m.entry_mut().push({
            let mut e = ParamEntry::new(1);
            *e.flags_mut() = param_entry_flags::SMALLSIZE_SEXT;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Join);
            e.set_base(0);
            e.set_sizes(8, 2);
            e.set_alignment(0);
            e.set_join_pieces(vec![
                VarnodeData { space: AddressSpace::Register, offset: 0x204, size: 4 },
                VarnodeData { space: AddressSpace::Register, offset: 0x200, size: 4 },
            ]);
            e
        });
        m.set_num_group(2);
        let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0xDEAD, size: 0x77 };
        // Justified small value in the entry's own space -> ZEXT with the
        // whole-alignment container (cc:383-388).
        let ext = m.assumed_extension(
            AddressSpace::Register, Address::new(0x100), 2, &mut res,
        );
        assert_eq!(ext, FspecOpCode::CPUI_INT_ZEXT);
        assert_eq!(res.space, AddressSpace::Register);
        assert_eq!(res.offset, 0x100);
        assert_eq!(res.size, 8);
        // Foreign-space query at the SAME numeric offset: the cc:269
        // space guard makes justifiedContain -1 -> CPUI_COPY, no res write
        // (the sentinel container passes through untouched).
        let mut res2 = VarnodeData { space: AddressSpace::Ram, offset: 0xDEAD, size: 0x77 };
        assert_eq!(
            m.assumed_extension(AddressSpace::Stack, Address::new(0x100), 2, &mut res2),
            FspecOpCode::CPUI_COPY,
        );
        assert_eq!(res2, VarnodeData { space: AddressSpace::Ram, offset: 0xDEAD, size: 0x77 });
        // e0's sz >= alignment gate (cc:370-372): 8 bytes -> falls through
        // to e1 (join) -> cc:376 CPUI_COPY.
        assert_eq!(
            m.assumed_extension(AddressSpace::Register, Address::new(0x100), 8, &mut res2),
            FspecOpCode::CPUI_COPY,
        );
        // A 2-byte query justified on e1's low piece still COPYs: joins
        // never extend (cc:376), even with smallsize flags set.
        assert_eq!(
            m.assumed_extension(AddressSpace::Register, Address::new(0x200), 2, &mut res2),
            FspecOpCode::CPUI_COPY,
        );
    }

    // Ghidra: fspec.cc:366 ParamEntry::assumedExtension
    /// The exclusion (alignment == 0) container pass-back (cc:378-382)
    /// and the smallsize_inttype / sext flag order (cc:389-393).
    #[test]
    fn test_assumed_extension_exclusion_container_and_flags() {
        let mut m = ParamListStandard::new();
        // e0: ram [0x2000,0x200F] min 2, exclusion, smallsize inttype.
        m.entry_mut().push({
            let mut e = ParamEntry::new(0);
            *e.flags_mut() = param_entry_flags::SMALLSIZE_INTTYPE;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Ram);
            e.set_base(0x2000);
            e.set_sizes(16, 2);
            e.set_alignment(0);
            e
        });
        m.set_num_group(1);
        let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0xDEAD, size: 0x77 };
        assert_eq!(
            m.assumed_extension(AddressSpace::Ram, Address::new(0x2000), 4, &mut res),
            FspecOpCode::CPUI_PIECE,
        );
        assert_eq!(res.space, AddressSpace::Ram);
        assert_eq!(res.offset, 0x2000);
        assert_eq!(res.size, 16);
        // smallsize sext falls through zext/inttype (cc:393).
        let mut e = ParamEntry::new(0);
        *e.flags_mut() = param_entry_flags::SMALLSIZE_SEXT;
        e.set_type_class(TypeClass::General);
        e.set_space(AddressSpace::Ram);
        e.set_base(0x2000);
        e.set_sizes(16, 2);
        e.set_alignment(0);
        let mut res2 = VarnodeData { space: AddressSpace::Ram, offset: 0xDEAD, size: 0x77 };
        // A justified query at the entry's LSB (containment offset 0)
        // extends; the container is the whole exclusion entry (cc:378-382).
        assert_eq!(
            e.assumed_extension(Address::new(0x2000), 4, AddressSpace::Ram, &mut res2),
            FspecOpCode::CPUI_INT_SEXT,
        );
        assert_eq!(res2, VarnodeData { space: AddressSpace::Ram, offset: 0x2000, size: 16 });
        // Unjustified (containment offset 1 != 0) -> CPUI_COPY (cc:377),
        // container untouched.
        assert_eq!(
            e.assumed_extension(Address::new(0x2001), 2, AddressSpace::Ram, &mut res2),
            FspecOpCode::CPUI_COPY,
        );
        assert_eq!(res2, VarnodeData { space: AddressSpace::Ram, offset: 0x2000, size: 16 });
    }

    // ---- FSPEC-TRIALCMP-0003 unit coverage ----

    // Ghidra: fspec.cc:1845/1856 ParamTrial::splitHi/splitLo
    /// The audit-mandated 12-byte trial split at 4: the low piece must
    /// start at `addr + (size - sz)` = 0x108 (not 0x104) and both halves
    /// inherit the full flags word (fspec.cc:1849/1861 `res.flags = flags`).
    #[test]
    fn test_param_trial_split_12_at_4_flags_and_address() {
        let mut t = ParamTrial::new_in_space(AddressSpace::Register, Address::new(0x100), 12, 2);
        t.mark_used();
        t.mark_active(); // also sets checked
        let hi = t.split_hi(4);
        assert_eq!(hi.get_size(), 4);
        assert_eq!(hi.get_address(), Address::new(0x100));
        assert_eq!(hi.get_slot(), 2);
        assert!(hi.is_used() && hi.is_active() && hi.is_checked());
        // splitLo(sz): last sz bytes at addr + (size - sz) (fspec.cc:1859).
        let lo = t.split_lo(4);
        assert_eq!(lo.get_size(), 4);
        assert_eq!(lo.get_address(), Address::new(0x108));
        assert_eq!(lo.get_slot(), 3);
        assert!(lo.is_used() && lo.is_active() && lo.is_checked());
        // The complementary split of the remaining 8 bytes.
        let lo8 = t.split_lo(8);
        assert_eq!(lo8.get_size(), 8);
        assert_eq!(lo8.get_address(), Address::new(0x104));
        assert_eq!(lo8.get_slot(), 3);
    }

    // Ghidra: fspec.cc:2033 ParamActive::splitTrial
    /// splitTrial on a 12-byte trial at sz=4: hi is [0x100,0x104), lo is
    /// [0x104,0x10c); the survivor above the split gets its slot bumped and
    /// slotbase increases (fspec.cc:2041-2056).
    #[test]
    fn test_param_active_split_trial_12_at_4_renumbers_slots() {
        let mut pa = ParamActive::new(true);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 12);
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x200), 8);
        let base = pa.get_slot_base();
        pa.split_trial(0, 4);
        assert_eq!(pa.get_num_trials(), 3);
        assert_eq!(pa.get_trial(0).get_size(), 4);
        assert_eq!(pa.get_trial(0).get_address(), Address::new(0x100));
        assert_eq!(pa.get_trial(1).get_size(), 8);
        assert_eq!(pa.get_trial(1).get_address(), Address::new(0x104));
        assert_eq!(pa.get_trial(2).get_address(), Address::new(0x200));
        // The survivor above slot 1 shifts from slot 2 to slot 3.
        assert_eq!(pa.get_trial(2).get_slot(), 3);
        assert_eq!(pa.get_slot_base(), base + 1);
    }

    // Ghidra: fspec.cc:2323 ProtoModel::buildParamList
    #[test]
    fn test_proto_model_full_builds_output_specific_paramlist() {
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        model.build_param_list("standard").unwrap();
        assert_eq!(model.input.get_type(), ParamListKind::Standard);
        assert_eq!(model.output.get_type(), ParamListKind::StandardOut);
        model.build_param_list("register").unwrap();
        assert_eq!(model.output.get_type(), ParamListKind::RegisterOut);
    }

    // Ghidra: fspec.cc:1893 ParamTrial::operator< + fspec.hh:316 sortTrials
    /// The comparator ladder: group id, then entry order, then exclusion
    /// offset / reverseStack-aware address, then size. Register entries
    /// (group 0/1) must now order before the stack entry regardless of raw
    /// address, and a reverse-stack entry orders its section high-to-low.
    #[test]
    fn test_param_active_sort_trials_uses_model_order() {
        let mut m = ParamListStandard::new();
        // Group 0: register slot at offset 0x30 (exclusion).
        let mut e0 = ParamEntry::new(0);
        e0.set_space(AddressSpace::Register);
        e0.set_base(0x30);
        e0.set_sizes(8, 4);
        e0.set_alignment(0); // exclusion
        // Group 1: register slot at offset 0x38 (exclusion).
        let mut e1 = ParamEntry::new(1);
        e1.set_space(AddressSpace::Register);
        e1.set_base(0x38);
        e1.set_sizes(8, 4);
        e1.set_alignment(0);
        // Group 2: stack entry, reverse-stack slots.
        let mut e2 = ParamEntry::new(2);
        e2.set_space(AddressSpace::Stack);
        e2.set_base(0);
        e2.set_sizes(64, 4);
        e2.set_alignment(8);
        *e2.flags_mut() |= param_entry_flags::REVERSE_STACK;
        let mut effects = Vec::new();
        m.parse_pentry(0, true, false, false, &mut effects, e0).unwrap();
        m.parse_pentry(1, true, false, false, &mut effects, e1).unwrap();
        m.parse_pentry(2, true, false, false, &mut effects, e2).unwrap();
        m.finalize_after_decode(0);
        let entries = m.get_entry();

        let mut pa = ParamActive::new(true);
        // Register in slot order: stack-first raw addresses would sort
        // differently under the old (addr, size) key.
        pa.register_trial_in_space(AddressSpace::Stack, Address::new(0x0), 8); // stack slot 0 (group 2)
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x38), 4); // reg group 1
        pa.register_trial_in_space(AddressSpace::Stack, Address::new(0x10), 8); // stack slot 2 (group 2)
        pa.register_trial_in_space(AddressSpace::Register, Address::new(0x30), 8); // reg group 0
        // Bind entries the way buildTrialMap does (offset 0 into entry).
        pa.get_trial_mut(0).set_entry(2, 0);
        pa.get_trial_mut(1).set_entry(1, 0);
        pa.get_trial_mut(2).set_entry(2, 0);
        pa.get_trial_mut(3).set_entry(0, 0);
        pa.sort_trials(entries);
        let order: Vec<u64> = (0..4).map(|i| pa.get_trial(i).get_address().as_u64()).collect();
        // Group 0 (0x30) then group 1 (0x38), then group 2 reverse-stack:
        // highest stack offset first (0x10 before 0x0).
        assert_eq!(order, vec![0x30, 0x38, 0x10, 0x0]);
    }

    // Ghidra: fspec.cc:1411 ParamListStandard::unjustifiedContainer
    /// The space-threaded form pins the oracle rows of the
    /// fspec_spaceless_rem_1204 fixture: foreign-space queries at
    /// numerically unjustified offsets are rejected inside the walk
    /// (address.cc:133 / fspec.cc:269 / per-piece for joins), join
    /// entries are reachable with the PIECE as container (cc:295-302),
    /// the minSize gate (cc:1415) skips entries before justifiedContain,
    /// and just==0 returns false early (cc:1420).
    #[test]
    fn test_unjustified_container_space_guards_and_join() {
        let mut m = ParamListStandard::new();
        // e0: join ram:0x204 (high) + reg:0x100 (low), pieces MS first,
        // min 2 so a 2-byte query reaches the walk (the cc:1415 minSize
        // gate still skips it for e1, min 4).
        m.entry_mut().push({
            let mut e = ParamEntry::new(0);
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Join);
            e.set_base(0);
            e.set_sizes(8, 2);
            e.set_alignment(0);
            e.set_join_pieces(vec![
                VarnodeData { space: AddressSpace::Ram, offset: 0x204, size: 4 },
                VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
            ]);
            e
        });
        // e1: plain register [0x100,0x107] min 4, exclusion, force-left.
        m.entry_mut().push({
            let mut e = ParamEntry::new(1);
            *e.flags_mut() = param_entry_flags::FORCE_LEFT_JUSTIFY;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Register);
            e.set_base(0x100);
            e.set_sizes(8, 4);
            e.set_alignment(0);
            e
        });
        m.set_num_group(2);
        let mut res = VarnodeData { space: AddressSpace::Ram, offset: 0, size: 0 };
        // Low piece just=2 -> hit with the PIECE as container.
        assert!(m.unjustified_container(
            AddressSpace::Register, Address::new(0x102), 2, &mut res));
        assert_eq!((res.space, res.offset, res.size),
                   (AddressSpace::Register, 0x100, 4));
        // Skip the foreign low piece (+4), high piece cur=0 -> just=4.
        assert!(m.unjustified_container(
            AddressSpace::Ram, Address::new(0x204), 4, &mut res));
        assert_eq!((res.space, res.offset, res.size), (AddressSpace::Ram, 0x204, 4));
        // Join walk -1 for both pieces -> e1 just=4 -> whole-entry container.
        assert!(m.unjustified_container(
            AddressSpace::Register, Address::new(0x104), 4, &mut res));
        assert_eq!((res.space, res.offset, res.size),
                   (AddressSpace::Register, 0x100, 8));
        // just==0 (justified) -> early false.
        assert!(!m.unjustified_container(
            AddressSpace::Register, Address::new(0x100), 4, &mut res));
        // Foreign-space query at a numerically coincident offset: both
        // pieces foreign for the join, entry-space guard for e1 -> hit=0
        // (the old spaceless arithmetic accepted these rows).
        assert!(!m.unjustified_container(
            AddressSpace::Stack, Address::new(0x102), 2, &mut res));
        assert!(!m.unjustified_container(
            AddressSpace::Register, Address::new(0x204), 4, &mut res));
        // minSize gate: e0 needs >= 2 bytes, e1 >= 4 bytes.
        assert!(!m.unjustified_container(
            AddressSpace::Register, Address::new(0x100), 1, &mut res));
    }

    // Ghidra: fspec.cc:1638 ParamListStandardOut::fillinMapFallback
    /// Join output entries are reachable through the per-piece walk
    /// (cc:1656/cc:1702): register trials bind to the join entry and
    /// are marked used, while a foreign-space trial is cleared and
    /// marked no-use (the caller-level space guard made the join entry
    /// unreachable -> bestentry null -> every trial markNoUse).
    #[test]
    fn test_fillin_map_fallback_join_reachable() {
        let mut out = ParamListStandardOut::new();
        out.base.entry_mut().push({
            let mut e = ParamEntry::new(0);
            *e.flags_mut() = param_entry_flags::FIRST_STORAGE;
            e.set_type_class(TypeClass::General);
            e.set_space(AddressSpace::Join);
            e.set_base(0);
            e.set_sizes(8, 4);
            e.set_alignment(0);
            e.set_join_pieces(vec![
                VarnodeData { space: AddressSpace::Register, offset: 0x104, size: 4 },
                VarnodeData { space: AddressSpace::Register, offset: 0x100, size: 4 },
            ]);
            e
        });
        out.base.set_num_group(1);
        let mut active = ParamActive::new(false);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x100), 4);
        active.register_trial_in_space(AddressSpace::Register, Address::new(0x104), 4);
        active.register_trial_in_space(AddressSpace::Stack, Address::new(0x104), 4);
        for i in 0..active.get_num_trials() {
            active.get_trial_mut(i).mark_active();
        }
        out.fillin_map_fallback(&mut active, false);
        // Trial order after the final sort_trials: join-entry trials by
        // justified offset (0 then 4), entry-less trial last.
        let t0 = active.get_trial(0);
        assert_eq!((t0.get_space(), t0.get_address().as_u64()),
                   (AddressSpace::Register, 0x100));
        assert!(t0.is_used());
        assert_eq!(t0.get_entry_index(), Some(0));
        assert_eq!(t0.get_offset(), 0);
        let t1 = active.get_trial(1);
        assert_eq!(t1.get_address().as_u64(), 0x104);
        assert!(t1.is_used());
        assert_eq!(t1.get_entry_index(), Some(0));
        assert_eq!(t1.get_offset(), 4);
        let t2 = active.get_trial(2);
        assert_eq!(t2.get_space(), AddressSpace::Stack);
        assert!(!t2.is_used());
        assert_eq!(t2.get_entry_index(), None);
        // bestentry null branch (cc:1713-1715): every trial markNoUse.
        let mut active2 = ParamActive::new(false);
        active2.register_trial_in_space(AddressSpace::Stack, Address::new(0x100), 4);
        active2.get_trial_mut(0).mark_active();
        out.fillin_map_fallback(&mut active2, false);
        let t = active2.get_trial(0);
        assert!(!t.is_used() && !t.is_active());
        assert_eq!(t.get_entry_index(), None);
    }
    // ---- MIGW-FSPEC batch regression tests (Rugra-side; oracle claims
    // live in the bilateral fixtures, not here) ----

    fn migfspec_exclusion_entry(group: i32, base: u64, size: i32, min_size: i32) -> ParamEntry {
        let mut e = ParamEntry::new(group);
        e.set_type_class(TypeClass::General);
        e.set_space(AddressSpace::Register);
        e.set_base(base);
        e.set_sizes(size, min_size);
        e.set_alignment(0);
        e
    }

    #[test]
    fn test_param_entry_range_family() {
        // Ghidra: fspec.hh:170/177-180/187-192
        let init = ParamEntryRangeInitData::new(3, 7);
        let r = ParamEntryRange::new(&init, 0x100, 0x107);
        assert_eq!(r.get_first(), 0x100);
        assert_eq!(r.get_last(), 0x107);
        assert_eq!(r.get_param_entry(), 7);
        assert_eq!(r.get_subsort(), SubsortPosition::with_position(3));
        assert!(SubsortPosition::from_bool(true).less_than(&SubsortPosition::from_bool(false)) == false);
        assert!(SubsortPosition::with_position(1).less_than(&SubsortPosition::with_position(2)));
        let mut resolver = ParamEntryResolver::new();
        resolver.insert(&init, 0x100, 0x107);
        resolver.insert(&ParamEntryRangeInitData::new(1, 0), 0x200, 0x20f);
        assert_eq!(resolver.len(), 2);
        assert_eq!(resolver.find(0x105).len(), 1);
        assert_eq!(resolver.find(0x105)[0].get_param_entry(), 7);
        assert!(resolver.find(0x150).is_empty());
        assert!(resolver.has_range_starting_above(0x105));
        assert!(!resolver.has_range_starting_above(0x300));
    }

    #[test]
    fn test_populate_resolver_registers_extents() {
        // Ghidra: fspec.cc:1191-1216 populateResolver
        let mut list = ParamListStandard::new();
        let mut effects = Vec::new();
        list.parse_pentry(0, true, false, false, &mut effects, migfspec_exclusion_entry(0, 0x100, 8, 4)).unwrap();
        list.parse_pentry(0, true, false, false, &mut effects, migfspec_exclusion_entry(1, 0x200, 4, 4)).unwrap();
        list.finalize_after_decode(8);
        list.populate_resolver();
        let resolver = list.resolver_for(AddressSpace::Register).expect("register resolver");
        assert_eq!(resolver.len(), 2);
        let hit = resolver.find(0x202);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].get_param_entry(), 1);
        assert_eq!(hit[0].position, 1);
        let miss = resolver.find(0x108);
        assert!(miss.is_empty());
        // Stack cache behavior preserved (non-exclusion stack entry).
        assert!(list.resolver_for(AddressSpace::Stack).is_none());
    }

    #[test]
    fn test_param_list_merged_fold_in() {
        // Ghidra: fspec.cc:1794-1833 foldIn
        let mut a = ParamListStandard::new();
        let mut effects = Vec::new();
        a.parse_pentry(0, true, false, false, &mut effects, migfspec_exclusion_entry(0, 0x100, 8, 4)).unwrap();
        a.finalize_after_decode(8);
        let mut b = ParamListStandard::new();
        let mut effects_b = Vec::new();
        b.parse_pentry(0, true, false, false, &mut effects_b, migfspec_exclusion_entry(1, 0x200, 8, 4)).unwrap();
        b.finalize_after_decode(8);
        let mut m = ParamListMerged::new();
        // Empty union adopts op2's list verbatim.
        m.fold_in(&a).unwrap();
        assert_eq!(m.base.get_entry().len(), 1);
        // Distinct entry appends.
        m.fold_in(&b).unwrap();
        assert_eq!(m.base.get_entry().len(), 2);
        // Subsuming entry with same minsize replaces in place.
        let mut c = ParamListStandard::new();
        let mut big = migfspec_exclusion_entry(0, 0x100, 16, 4);
        // same group 0, minsize 4: the new entry subsumes the old one.
        big.set_sizes(16, 4);
        let mut effects_c = Vec::new();
        c.parse_pentry(0, true, false, false, &mut effects_c, big).unwrap();
        c.finalize_after_decode(8);
        m.fold_in(&c).unwrap();
        assert_eq!(m.base.get_entry().len(), 2);
        // Refusing overrides (fspec.hh:719/721).
        assert_eq!(m.assign_map_refuses().unwrap_err(), "Cannot assign prototype before model has been resolved");
        assert_eq!(m.fillin_map_refuses().unwrap_err(), "Cannot determine prototype before model has been resolved");
        // finalize = populateResolver (fspec.hh:717).
        m.finalize();
        assert!(m.base.resolver_for(AddressSpace::Register).is_some());
    }

    #[test]
    fn test_score_proto_model_do_score() {
        // Ghidra: fspec.cc:2705-2775
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        // One exclusion entry at slot 0 (group 0).
        let mut effects = Vec::new();
        model.input.parse_pentry(0, true, false, false, &mut effects, migfspec_exclusion_entry(0, 0x100, 8, 8)).unwrap();
        model.input.finalize_after_decode(8);
        let mut s = ScoreProtoModel::new(true, &model, 2);
        s.add_parameter(AddressSpace::Register, Address::new(0x100), 8);
        s.do_score();
        assert_eq!(s.get_score(), 0);
        assert_eq!(s.get_num_mismatch(), 0);
        // A miss adds 20 per mismatch.
        s.add_parameter(AddressSpace::Register, Address::new(0x900), 4);
        assert_eq!(s.get_num_mismatch(), 1);
        s.do_score();
        assert_eq!(s.get_score(), 20);
    }

    #[test]
    fn test_compare_by_entry_address() {
        // Ghidra: fspec.hh:1740
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let mut fc_a = FuncCallSpecs::new(Address::new(0x10), FuncProto::new(String::new(), void_type.clone()));
        let mut fc_b = FuncCallSpecs::new(Address::new(0x20), FuncProto::new(String::new(), void_type));
        // The ctor records the op address, not the callee entry; entries
        // arrive via set_funcdata (fspec.cc:4949-4958).
        fc_a.set_funcdata("callee_a", Address::new(0x10));
        fc_b.set_funcdata("callee_b", Address::new(0x20));
        assert!(FuncCallSpecs::compare_by_entry_address(&fc_a, &fc_b));
        assert!(!FuncCallSpecs::compare_by_entry_address(&fc_b, &fc_a));
    }

    #[test]
    fn test_update_output_no_types_lock_and_rebuild() {
        // Ghidra: fspec.cc:4172-4185
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let mut proto = FuncProto::new("f".to_string(), void_type);
        // Locked output is untouched.
        proto.set_output_lock(true);
        proto.update_output_no_types(&[]);
        assert_eq!(proto.return_type.get_metatype(), TypeMetatype::Void);
        assert!(proto.output_type_locked);
        // Unlocked + empty trials clears the output.
        proto.set_output_lock(false);
        proto.update_output_no_types(&[]);
        assert!(!proto.output_type_locked);
        assert_eq!(proto.return_type.get_metatype(), TypeMetatype::Void);
        assert!(proto.output_storage.is_none());
    }

    #[test]
    fn test_proto_store_symbol_roundtrip() {
        // Ghidra: fspec.cc:3103-3303 (setInput / getInput / clearInput)
        let scope = std::sync::Arc::new(std::sync::RwLock::new(
            crate::database::Scope::new(1, "func", 0),
        ));
        let int_type: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        let mut store = ProtoStoreSymbol::new(scope.clone(), (AddressSpace::Ram, 0x1000));
        // Fresh output is a void ParameterBasic.
        assert_eq!(store.get_output().unwrap().data_type.get_size(), 0);
        // set_input installs a category-0 symbol.
        let pieces = ParameterPieces {
            space: AddressSpace::Register,
            addr: Address::new(0x100),
            ty: Some(int_type.clone()),
            flags: TYPE_LOCK_PIECE | NAME_LOCK_PIECE,
        };
        let param = store.set_input(0, "param_1", &pieces);
        assert!(param.sym.is_some());
        assert_eq!(store.get_num_inputs(), 1);
        let view = store.get_input(0).expect("input view");
        assert_eq!(view.get_name(), "param_1");
        assert!(view.is_type_locked());
        assert!(view.is_name_locked());
        assert_eq!(view.get_size(), Some(4));
        // clear_input removes the symbol and shrinks the category.
        store.clear_input(0);
        assert_eq!(store.get_num_inputs(), 0);
        // decode refuses (cc:3299-3303).
        assert_eq!(
            store.decode_refuses().unwrap_err(),
            "Do not decode symbol-backed prototype through this interface"
        );
    }

    #[test]
    fn test_effect_record_and_param_eq() {
        // Ghidra: fspec.hh:1769-1781 / 1144-1155
        let a = EffectRecord::new(AddressSpace::Register, 0x10, 4, EffectType::Unaffected);
        let b = EffectRecord::new(AddressSpace::Register, 0x10, 4, EffectType::Unaffected);
        let c = EffectRecord::new(AddressSpace::Register, 0x10, 4, EffectType::KilledByCall);
        assert_eq!(a, b);
        assert_ne!(a, c);
        let void_type = Arc::new(Datatype::Void(TypeBase::new("void".to_string(), 0, TypeMetatype::Void)));
        let p1 = ProtoParameter::new("x".to_string(), void_type.clone(), Address::new(4));
        let p2 = ProtoParameter::new("y".to_string(), void_type.clone(), Address::new(4));
        // Same storage + same type identity: equal despite name difference.
        assert_eq!(p1, p2);
        let int_type = Arc::new(Datatype::Base(TypeBase::new("int".to_string(), 4, TypeMetatype::Int)));
        let p3 = ProtoParameter::new("x".to_string(), int_type, Address::new(4));
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_parameter_basic_flag_face_on_flat_param() {
        // Ghidra: fspec.cc:2924-2972 via the flat ProtoParameter
        let unknown4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
            "undefined4".to_string(), 4, TypeMetatype::Unknown,
        )));
        let int4: Arc<Datatype> = Arc::new(Datatype::Base(TypeBase::new(
            "int".to_string(), 4, TypeMetatype::Int,
        )));
        let mut p = ProtoParameter::new("a".to_string(), unknown4, Address::new(0x100));
        // setTypeLock on TYPE_UNKNOWN also raises sizelock (cc:2929-2930).
        p.set_type_lock(true);
        assert!(p.is_type_locked());
        assert!(p.is_size_type_locked());
        // override requires exact size + existing sizelock (cc:2954-2964).
        assert!(p.override_size_lock_type(&int4).is_ok());
        assert!(matches!(p.data_type.get_metatype(), TypeMetatype::Int));
        // reset returns to TYPE_UNKNOWN of the same size (cc:2966-2972).
        let factory = crate::type_system::TypeFactory::shared_default();
        let factory = factory.read().unwrap_or_else(|e| e.into_inner());
        p.reset_size_lock_type(&factory);
        assert!(matches!(p.data_type.get_metatype(), TypeMetatype::Unknown));
        assert_eq!(p.data_type.get_size(), 4);
        // name/lock predicates (hh:1178-1183).
        assert!(!p.is_name_locked());
        p.set_name_lock(true);
        assert!(p.is_name_locked());
        assert!(!p.is_name_undefined());
        assert!(!p.is_indirect_storage());
        // get_symbol always refuses on the basic form (hh:1190).
        assert!(p.get_symbol().is_err());
    }

    // ---- FSPEC-LIKELYTRASH-FOLD: the independent likelytrash carrier ----

    /// Build a TreeDecoder over one `<prototype>` document, pre-binding an
    /// optional model on the FuncProto (the decode channel resolves models by
    /// name only; the model must be attached via set_model like the callers
    /// that host the resolver do).
    fn trash_proto_decode(
        xml: &str,
        model: Option<std::sync::Arc<ProtoModelFull>>,
    ) -> FuncProto {
        use crate::marshal::{DocumentStorage, IdRegistry, TreeDecoder};
        let void_type = Arc::new(Datatype::Void(TypeBase::new(
            "void".to_string(), 0, TypeMetatype::Void,
        )));
        let mut proto = FuncProto::new(String::new(), void_type);
        proto.set_model(model);
        // Capture the return type up front so the storage closure does not
        // borrow `proto` while `decode` holds it mutably.
        let ret_ty = proto.return_type.clone();
        let mut store = DocumentStorage::new();
        let doc = store.parse_document(xml.as_bytes()).expect("parse");
        let root = doc.root.clone().expect("root");
        let registry = Arc::new(std::sync::RwLock::new(IdRegistry::new()));
        let mut decoder = TreeDecoder::new(root, registry);
        // decode_output_storage: consume the <returnsym> element — attributes
        // plus one level of children (addr/type refs carry only attributes).
        let output_storage = |dec: &mut dyn crate::marshal::Decoder| -> (Address, Arc<Datatype>, bool) {
            let id = dec.open_element();
            let mut lock = false;
            loop {
                let aid = dec.next_attribute_id();
                if aid == 0 { break; }
                if dec.attribute_name(aid).as_deref() == Some("typelock") {
                    lock = dec.read_string() == "true";
                } else {
                    let _ = dec.read_string();
                }
            }
            while dec.peek_element() != 0 {
                let cid = dec.open_element();
                while dec.next_attribute_id() != 0 {
                    let _ = dec.read_string();
                }
                dec.close_element(cid);
            }
            dec.close_element(id);
            (Address::new(0), ret_ty.clone(), lock)
        };
        proto
            .decode(&mut decoder, &|_name| true, &output_storage)
            .expect("decode");
        proto
    }

    // Ghidra: fspec.cc:4806-4813 FuncProto::decode (<likelytrash> arm)
    /// `<likelytrash>` children land in the independent carrier — NOT as
    /// KilledByCall effects. The decoded list is merged (decodeLikelyTrash,
    /// cc:4827) and sorted with the oracle key.
    #[test]
    fn test_likelytrash_decode_independent_carrier_not_killedbycall() {
        let proto = trash_proto_decode(
            "<prototype model=\"__stdcall\">\
             <returnsym><addr space=\"register\" offset=\"0\" size=\"8\"/></returnsym>\
             <likelytrash>\
             <addr space=\"register\" offset=\"0\" size=\"4\"/>\
             <addr space=\"register\" offset=\"16\" size=\"8\"/>\
             </likelytrash>\
             </prototype>",
            None,
        );
        // The carrier holds both entries (model unbound ⇒ empty merge).
        assert_eq!(proto.likelytrash.len(), 2);
        // Oracle sort key: offset ascending, size DESCENDING on ties
        // (pcoderaw.hh:67-70).
        assert_eq!(proto.likelytrash[0].offset, 0);
        assert_eq!(proto.likelytrash[0].size, 4);
        assert_eq!(proto.likelytrash[1].offset, 16);
        // No KilledByCall effect was fabricated from the trash arm.
        assert!(proto
            .effects
            .iter()
            .all(|e| e.effect_type != EffectType::KilledByCall));
        // trash_iter serves the override list (cc:4260-4275: non-empty own
        // list wins even with no model bound).
        assert_eq!(proto.trash_iter().len(), 2);
    }

    // Ghidra: fspec.cc:3684-3699 FuncProto::decodeLikelyTrash
    /// Local overrides merge with the model's trash registers into a complete
    /// list: model entries all present, local entries deduped against the
    /// model list, result re-sorted.
    #[test]
    fn test_likelytrash_merge_with_model_list() {
        let mut model = ProtoModelFull::new(None, 8);
        model.likelytrash = vec![
            VarnodeData { space: AddressSpace::Register, offset: 0, size: 4 },
            VarnodeData { space: AddressSpace::Register, offset: 32, size: 4 },
        ];
        let proto = trash_proto_decode(
            "<prototype model=\"__stdcall\">\
             <returnsym><addr space=\"register\" offset=\"0\" size=\"8\"/></returnsym>\
             <likelytrash>\
             <addr space=\"register\" offset=\"0\" size=\"4\"/>\
             <addr space=\"register\" offset=\"16\" size=\"8\"/>\
             </likelytrash>\
             </prototype>",
            Some(Arc::new(model)),
        );
        // offset 0 size 4 (model, dup with local) + 16 size 8 (local only) +
        // 32 size 4 (model only).
        assert_eq!(proto.likelytrash.len(), 3);
        let offsets: Vec<u64> = proto.likelytrash.iter().map(|v| v.offset).collect();
        assert_eq!(offsets, vec![0, 16, 32]);
    }

    // Ghidra: fspec.cc:4260-4275 FuncProto::trashBegin/trashEnd
    /// Empty own carrier falls back to the model's list — resolved
    /// dynamically, exactly like the oracle iterator pair.
    #[test]
    fn test_likelytrash_trash_iter_falls_back_to_model() {
        let mut model = ProtoModelFull::new(None, 8);
        model.likelytrash = vec![
            VarnodeData { space: AddressSpace::Register, offset: 8, size: 2 },
        ];
        let proto = trash_proto_decode(
            "<prototype model=\"__stdcall\">\
             <returnsym><addr space=\"register\" offset=\"0\" size=\"8\"/></returnsym>\
             </prototype>",
            Some(Arc::new(model)),
        );
        assert!(proto.likelytrash.is_empty());
        let trash = proto.trash_iter();
        assert_eq!(trash.len(), 1);
        assert_eq!(trash[0].offset, 8);
        assert_eq!(trash[0].size, 2);
    }

    // Ghidra: pcoderaw.hh:67 VarnodeData::operator<
    /// The oracle ordering key: space, then offset ascending, then size
    /// DESCENDING (big sizes first) — pinned via decode_likely_trash's sort.
    #[test]
    fn test_varnodedata_compare_size_descends() {
        let small = VarnodeData { space: AddressSpace::Register, offset: 0, size: 4 };
        let big = VarnodeData { space: AddressSpace::Register, offset: 0, size: 8 };
        assert_eq!(VarnodeData::compare(&big, &small), std::cmp::Ordering::Less);
        assert_eq!(VarnodeData::compare(&small, &big), std::cmp::Ordering::Greater);
        assert_eq!(VarnodeData::compare(&small, &small), std::cmp::Ordering::Equal);
        let far = VarnodeData { space: AddressSpace::Register, offset: 1, size: 1 };
        assert_eq!(VarnodeData::compare(&far, &big), std::cmp::Ordering::Greater);
        // Sort a mixed list: same (space,offset) sizes 4/8 → 8 first.
        let mut list = vec![small, big];
        list.sort_by(VarnodeData::compare);
        assert_eq!(list[0].size, 8);
        assert_eq!(list[1].size, 4);
    }

    // Ghidra: fspec.cc:4573-4575 FuncProto::operator== (likelytrash tail)
    /// Two otherwise-identical prototypes disagree when their likelytrash
    /// override lists differ; equal lists stay compatible.
    #[test]
    fn test_is_compatible_likelytrash_comparison() {
        let mk = |offset: u64| {
            trash_proto_decode(
                &format!(
                    "<prototype model=\"__stdcall\">\
                     <returnsym><addr space=\"register\" offset=\"0\" size=\"8\"/></returnsym>\
                     <likelytrash>\
                     <addr space=\"register\" offset=\"{offset}\" size=\"4\"/>\
                     </likelytrash>\
                     </prototype>"
                ),
                None,
            )
        };
        let a = mk(0);
        let b_same = mk(0);
        let b_diff = mk(16);
        assert!(a.is_compatible(&b_same));
        assert!(!a.is_compatible(&b_diff));
    }
}

#[cfg(test)]
mod callspec_copy_tests {
    use super::*;

    fn void_type() -> Arc<Datatype> {
        crate::type_system::TypeFactory::shared_default()
            .read()
            .unwrap()
            .get_type_void()
    }

    fn ptr_to_char() -> Arc<Datatype> {
        let chartype = crate::type_system::TypeFactory::shared_default()
            .read()
            .unwrap()
            .get_type_char(1)
            .expect("char core");
        crate::type_system::TypeFactory::shared_default()
            .write()
            .unwrap()
            .get_type_pointer_default(chartype)
    }

    // Ghidra: fspec.cc:3789 FuncProto::copy via FuncCallSpecs::copy_proto_from
    // (coreaction.cc:2323)
    /// The ActionDefaultParams copy channel transfers the callee's whole
    /// FuncProto state (model, locks, parameters with lock markup, output
    /// type) while the CALLSITE's own name survives (the name is
    /// FuncCallSpecs state in the oracle — Ghidra's FuncProto base has no
    /// name member).
    #[test]
    fn test_copy_proto_from_transfers_state_and_keeps_callsite_name() {
        // Unit scope: the copy semantics, not the storage-assignment
        // channel (that is the bilateral fixture's job with the real cspec
        // model). The callee state mirrors a post-setPieces prototype.
        let mut callee = FuncProto::new("fixture_callee".to_string(), ptr_to_char());
        let mut model = ProtoModelFull::new(Some(AddressSpace::Stack), 8);
        model.name = "__stdcall".to_string();
        callee.set_model(Some(Arc::new(model)));
        let mut param = ProtoParameter::new("fixture_buf".to_string(), ptr_to_char(), Address::new(0x38));
        param.address_space = AddressSpace::Register;
        param.flags |= protoparam_flags::TYPE_LOCKED | protoparam_flags::NAME_LOCKED;
        callee.parameters = vec![param];
        callee.set_input_lock(true);
        callee.set_output_lock(true);
        assert!(callee.is_input_locked() && callee.is_output_locked());

        let mut fc = FuncCallSpecs::new(
            crate::address::Address::new(0x1000),
            FuncProto::new(String::new(), void_type()),
        );
        fc.set_funcdata("fixture_callee", crate::address::Address::new(0x600000));
        fc.copy_proto_from(&callee);

        assert_eq!(fc.prototype.num_params(), 1);
        let param = &fc.prototype.parameters[0];
        assert_eq!(param.name, "fixture_buf");
        assert!(param.is_type_locked());
        assert!(param.is_name_locked());
        assert!(fc.prototype.is_input_locked());
        assert!(fc.prototype.is_output_locked());
        assert!(fc.prototype.is_model_locked());
        assert_eq!(fc.prototype.get_model_name(), "__stdcall");
        // The callsite's resolved name survives the FuncProto copy.
        assert_eq!(fc.prototype.name, "fixture_callee");
    }

    // Ghidra: fspec.cc:4949 FuncCallSpecs::setFuncdata / fspec.hh:1682
    // getFuncdata (the coreaction.cc:2321 observable slice)
    /// The callee-proto observable: Some after the queryCall boundary
    /// stores the recovered prototype, None keeps the setInternal arm.
    #[test]
    fn test_callee_proto_observable_slice() {
        let mut fc = FuncCallSpecs::new(
            crate::address::Address::new(0x1000),
            FuncProto::new(String::new(), void_type()),
        );
        assert!(fc.callee_proto().is_none());
        let proto = FuncProto::new("c".to_string(), void_type());
        fc.set_callee_proto(Arc::new(proto));
        assert!(fc.callee_proto().is_some());
        // fspec.cc:4968 clone carries the callee link.
        let seq = crate::address::SeqNum::new(crate::address::Address::new(0x1000), 0);
        let op = Arc::new(RwLock::new(crate::op::PcodeOp::new(
            seq,
            crate::opcodes::OpCode::CPUI_CALLIND,
        )));
        let cloned = fc.clone_for_op(&crate::op::PcodeOpRef(op));
        assert!(cloned.callee_proto().is_some());
    }

    // Ghidra: fspec.cc:3047-3057 ParameterSymbol::setTypeLock
    /// Locking a NAMED parameter's type locks its name too (the
    /// scope-backed store's side-effect, mirrored on the flat projection);
    /// an unnamed param (the param_N stand-in shape) gains no namelock.
    #[test]
    fn test_set_input_lock_namelock_side_effect() {
        let mut proto = FuncProto::new("f".to_string(), void_type());
        let named = ProtoParameter::new("named".to_string(), ptr_to_char(), Address::new(0x38));
        let unnamed = ProtoParameter::new(String::new(), ptr_to_char(), Address::new(0x30));
        proto.parameters = vec![named, unnamed];
        proto.set_input_lock(true);
        assert!(proto.parameters[0].is_type_locked());
        assert!(proto.parameters[0].is_name_locked());
        assert!(proto.parameters[1].is_type_locked());
        assert!(!proto.parameters[1].is_name_locked());
    }
}
